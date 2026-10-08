#include "http_client.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <utility>

#include <boost/asio/ssl.hpp>

#include <openssl/ssl.h> // SSL_set_tlsext_host_name: no asio wrapper for SNI (single bare-openssl exception)

std::optional<ParsedUrl> parseUrl(const std::string& url) {
    auto r = boost::urls::parse_absolute_uri(url);
    if (!r) return std::nullopt;
    ParsedUrl u;
    u.tls = r->scheme_id() == boost::urls::scheme::https;
    u.host = std::string(r->host());
    u.target = std::string(r->path());
    if (u.target.empty()) u.target = "/";
    if (!r->params().empty()) {
        u.target += '?';
        u.target += r->params().buffer(); // already-encoded query, verbatim
    }
    if (r->has_port()) {
        u.port = std::string(r->port());
        u.hostHeader = u.host + ":" + u.port;
    } else {
        u.port = u.tls ? "443" : "80";
        u.hostHeader = u.host;
    }
    if (u.host.empty()) return std::nullopt;
    return u;
}

// Hop-by-hop/framing headers are never reused towards the client (framing is recomputed on this side)
bool hopByHop(std::string_view name) {
    auto eq = [&](const char* s) {
        return name.size() == strlen(s) &&
               std::equal(name.begin(), name.end(), s,
                          [](char a, char b) {
                              return std::tolower((unsigned char)a) == b;
                          });
    };
    return eq("connection") || eq("keep-alive") || eq("proxy-connection") ||
           eq("transfer-encoding") || eq("te") || eq("trailer") || eq("upgrade") ||
           eq("content-length");
}

namespace {

// LibreSSL's default CA paths may be baked in as relative paths by CMake,
// and it does not read SSL_CERT_*. Explicit configuration wins (file and
// hashed dir work independently); Linux/macOS fall back to system absolute
// paths. Misconfiguration must fail loudly - never degrade into skipping
// verification or silently switching trust sources. (Lazy init: the
// environment is read once on the instance's first https request.)
void configureTrust(asio::ssl::context& context) {
    const char* file = std::getenv("SSL_CERT_FILE");
    const char* dir = std::getenv("SSL_CERT_DIR");
    const bool hasFile = file != nullptr && *file != '\0';
    const bool hasDir = dir != nullptr && *dir != '\0';
    if (hasFile || hasDir) {
        if (hasFile) context.load_verify_file(file);
        if (hasDir) context.add_verify_path(dir);
        return;
    }
#ifdef __linux__
    context.load_verify_file("/etc/ssl/certs/ca-certificates.crt");
#elif defined(__APPLE__)
    context.load_verify_file("/etc/ssl/cert.pem");
#else
    // Other platforms keep the library default trust paths; override with
    // SSL_CERT_FILE/DIR
    context.set_default_verify_paths();
#endif
}

// Buffered-path internal handler: memory guard + body collection + response
// header recording (hop-by-hop/framing headers stripped). The response is
// reassembled by request(); framing is not reused (recomputed on this side)
struct BufferedHandler : HttpClient::ExchangeHandler {
    size_t maxBytes;
    int status = 200;
    int version = 11;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    explicit BufferedHandler(size_t max) : maxBytes(max) {}

    asio::awaitable<std::optional<std::chrono::milliseconds>>
    onHeader(http::response_parser<http::buffer_body>& p) override {
        status = (int)p.get().result_int(); // beast returns unsigned; narrowed to int (status-code range)
        version = (int)p.get().version();
        for (const auto& h : p.get())
            if (!hopByHop(h.name_string()))
                headers.emplace_back(std::string(h.name_string()), std::string(h.value()));
        if (auto length = p.content_length(); length && *length > maxBytes)
            throwHttp(502, "Upstream response too large");
        // No idle timeout: first-byte silence is legitimate generation time;
        // a hang is caught by the totalCap hard cap
        co_return std::nullopt;
    }

    asio::awaitable<void> onBody(const char* data, size_t n) override {
        if (n > maxBytes - body.size()) throwHttp(502, "Upstream response too large");
        body.append(data, n);
        co_return;
    }
};

} // namespace

// ---- Impl: all state and coroutine machinery (moved here from the old
// header-private section). The foundation of the PIMPL: an Impl address
// never changes during the instance lifetime (a move only carries the
// shell's unique_ptr); frames of in-flight coroutines and the references
// held by ssl::stream all land on stable addresses inside Impl ----

class HttpClient::Impl {
public:
    // ---- configuration (written by shell setters at assembly time) ----
    std::chrono::milliseconds connectTimeout{10000}; // one budget for resolve~response-header read
    std::chrono::milliseconds totalCap{60000};       // hard overall cap; <=0 disables
    size_t maxBodyBytes = 8ULL * 1024 * 1024;        // buffered-path memory guard


    // (used by the HttpStream session below; internal to this .cpp)
    // Errors from connect/request/headers/body stages -> 504/502 (beast deadline/idle timeouts -> 504)
    [[noreturn]] static void throwUpstreamError(const boost::system::system_error& e) {
        if (e.code() == beast::error::timeout)
            throwHttp(504, "Upstream request timed out");
        throwHttp(502, "Upstream request failed");
    }

    asio::ssl::context& sslContext() {
        if (!sslc_) {
            sslc_.emplace(asio::ssl::context::tls_client);
            configureTrust(*sslc_);
        }
        return *sslc_;
    }

    // SNI must carry a DNS name only (an IP literal is illegal); both the
    // certificate chain and the DNS/IP identity must be verified
    static void setupTls(asio::ssl::stream<beast::tcp_stream>& upstream, const std::string& host) {
        boost::system::error_code addressError;
        (void)asio::ip::make_address(host, addressError);
        if (addressError && !SSL_set_tlsext_host_name(upstream.native_handle(), host.c_str()))
            throwHttp(502, "Upstream request failed");
        upstream.set_verify_mode(asio::ssl::verify_peer);
        upstream.set_verify_callback(asio::ssl::host_name_verification(host));
    }

    static constexpr size_t kReadBuf = 16384;

    std::optional<asio::ssl::context> sslc_; // lazily initialized on first https, then reused read-only
};

// ---- HttpStream session. Defined at shell scope: it IS
// HttpClient::HttpStream::Session, and holds an Impl* for sslContext()/
// setupTls()/error mapping. Heap-owned via shared_ptr inside HttpStream: the
// reaper's completion handler holds a copy too, so an abandoned stream still
// gets its upstream closed when the cap fires. The coroutines are Session
// members - their frames bind this Session's shared_ptr-stable address ----
struct HttpClient::HttpStream::Session : std::enable_shared_from_this<Session> {
    Impl* client = nullptr;      // owning HttpClient's Impl; stable address (PIMPL)
    ParsedUrl url;
    http::request<http::string_body> req;
    std::function<void()> onHardCap;
    std::chrono::milliseconds connectTimeout{};
    std::chrono::milliseconds totalCap{};

    std::optional<asio::steady_timer> reaper; // emplaced in head() once the executor is known
    beast::flat_buffer left;    // bytes over-read past the headers (first body chunk)
    http::response_parser<http::buffer_body> parser;
    std::optional<beast::tcp_stream> plain;
    std::optional<asio::ssl::stream<beast::tcp_stream>> tls;
    std::optional<std::chrono::milliseconds> idle;
    bool capped = false;
    bool headDone = false;
    bool closed = false;
    bool reaperArmed = false;

    // The reaper shares ownership of the session, so it never dangles; after
    // close() both stream optionals are disengaged and the hook still fires
    // (an abandoned stream's client socket must be unblocked just the same)
    void armReaper() {
        if (totalCap <= std::chrono::milliseconds(0)) return;
        if (!reaper) return; // head() not reached: nothing to arm (plain shell misuse)
        reaperArmed = true;
        reaper->expires_after(totalCap); // NOLINT(bugprone-unchecked-optional-access) emplaced at head() entry, before any arm
        reaper->async_wait( // NOLINT(bugprone-unchecked-optional-access) emplaced at head() entry, before any arm
            [self = shared_from_this()](const boost::system::error_code& ec) {
            if (ec) return;
            self->capped = true;
            if (self->plain) beast::get_lowest_layer(*self->plain).close(); // NOLINT(bugprone-unchecked-optional-access) capped implies a live stream
            if (self->tls) beast::get_lowest_layer(*self->tls).close(); // NOLINT(bugprone-unchecked-optional-access) capped implies a live stream
            if (self->onHardCap) self->onHardCap(); // completion handler: must not throw
        });
    }

    // Best-effort teardown: called from destructors and abort paths, so it
    // must never throw - a close/cancel failure changes nothing that matters
    void closeUpstream() noexcept { // NOLINT(bugprone-exception-escape) best-effort teardown: beast close/cancel never throws in practice, and the catch above guards the signature-level possibility
        try {
            if (plain) { // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
                plain->close();
                plain.reset();
            }
            if (tls) {
                beast::get_lowest_layer(*tls).close();
                tls.reset();
            }
            // an armed reaper must always be disarmed: its handler keeps the
            // session alive and would fire later
            if (reaperArmed) reaper->cancel(); // NOLINT(bugprone-unchecked-optional-access) armed implies emplaced
        } catch (const boost::system::system_error&) { // NOLINT(bugprone-empty-catch) teardown failures are genuinely ignorable here
        }
        closed = true;
    }

    static constexpr size_t kReadBuf = 16384;
    char buf[kReadBuf]; // view-mode chunk storage (shared across chunks; see the getChunk contract)

    // The coroutines are Session members: the frame binds this Session's
    // address, never a shell. Defined below
    asio::awaitable<http::response_parser<http::buffer_body>*> head();
    asio::awaitable<std::optional<size_t>> chunk(char* out, size_t n);
};

// ---- Session coroutines (defined out of line; frames bind the Session's
// shared_ptr-stable address). System errors map to 502/504 at these single
// exits, matching the historical behavior; a reaper hit reports 504 first ----

// resolve+connect (+TLS handshake) + request write + response-header read
// under one connectTimeout budget; returns with the parser ready and the
// first-byte budget lifted (idle decides from here)
asio::awaitable<http::response_parser<http::buffer_body>*> HttpClient::HttpStream::Session::head() {
    auto ex = co_await asio::this_coro::executor;
    reaper.emplace(ex);
    try {
        asio::ip::tcp::resolver resolver(ex);
        auto [rec, endpoints] = co_await resolver.async_resolve(
            url.host, url.port, asio::as_tuple(asio::use_awaitable));
        if (rec) throw boost::system::system_error(rec);

        if (url.tls) {
            tls.emplace(ex, client->sslContext());
            Impl::setupTls(*tls, url.host);
            armReaper();
            beast::get_lowest_layer(*tls).expires_after(connectTimeout); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
            co_await beast::get_lowest_layer(*tls).async_connect(endpoints, asio::use_awaitable); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
            co_await tls->async_handshake(asio::ssl::stream_base::client, asio::use_awaitable); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
        } else {
            plain.emplace(ex);
            armReaper();
            plain->expires_after(connectTimeout); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
            co_await plain->async_connect(endpoints, asio::use_awaitable); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
        } // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here

        // head/body ops only need the lowest layer; read/write over it
        auto* lowest = tls ? &beast::get_lowest_layer(*tls) : &beast::get_lowest_layer(*plain); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
 // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
        co_await http::async_write(*lowest, req, asio::use_awaitable);
        // lift the default parser limit; body-size guards are the caller's
        // business (the buffered adapter re-applies maxBodyBytes via its handler)
        parser.body_limit(boost::none);
        co_await http::async_read_header(*lowest, left, parser, asio::use_awaitable);
        lowest->expires_never();
    } catch (const boost::system::system_error& e) {
        closeUpstream();
        if (capped) throwHttp(504, "Upstream stream timed out");
        Impl::throwUpstreamError(e);
    }
    headDone = true;
    co_return &parser;
}

// One body chunk into `out` (buffer_body incremental mode); a rolling idle
// deadline is set right before each read, so the caller's own writes between
// chunks never consume idle budget. http::error::need_buffer is the
// buffer_body handshake, not a failure; anything else travels to the exit
asio::awaitable<std::optional<size_t>>
HttpClient::HttpStream::Session::chunk(char* out, size_t n) {
    if (closed || !headDone) throwHttp(500, "HttpStream used out of order", false);
    if (parser.is_done()) co_return std::nullopt;

    auto* lowest = tls ? &beast::get_lowest_layer(*tls) : &beast::get_lowest_layer(*plain); // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
 // NOLINT(bugprone-unchecked-optional-access) plain/tls engaged is a session invariant here
    parser.get().body().data = out;
    parser.get().body().size = n;
    if (idle) lowest->expires_after(*idle);
    try {
        co_await http::async_read_some(*lowest, left, parser, asio::use_awaitable);
    } catch (const boost::system::system_error& e) {
        if (e.code() != http::error::need_buffer) {
            closeUpstream();
            if (capped) throwHttp(504, "Upstream stream timed out");
            Impl::throwUpstreamError(e);
        }
    }
    size_t got = n - parser.get().body().size;
    if (parser.is_done() && idle) lowest->expires_never();
    co_return std::optional<size_t>(got); // 0 = spurious wake (caller retries)
}

// ---- shell: plain-function forwarders (never coroutines - no frame may
// capture the shell this; this is what makes moves safe) ----

HttpClient::HttpClient() : impl_(std::make_unique<Impl>()) {}
HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;
HttpClient::~HttpClient() = default;

void HttpClient::setConnectTimeout(std::chrono::milliseconds v) { impl_->connectTimeout = v; }
void HttpClient::setTotalCap(std::chrono::milliseconds v) { impl_->totalCap = v; }
void HttpClient::setMaxBodyBytes(size_t v) { impl_->maxBodyBytes = v; }

// Streaming exchange: a thin adapter over the HttpStream session (the only
// pump implementation lives in Session::head/chunk)
asio::awaitable<void> HttpClient::exchange(const ParsedUrl& u,
                                           http::request<http::string_body> req,
                                           ExchangeHandler& handler,
                                           const std::function<void()>& onHardCap) {
    HttpStream s = open(u, std::move(req), onHardCap);
    auto* p = co_await s.getHead();
    auto idle = co_await handler.onHeader(*p);
    s.setIdle(idle ? *idle : std::chrono::milliseconds(-1));

    while (auto chunk = co_await s.getChunk())
        co_await handler.onBody(chunk->data(), chunk->size());

    co_await handler.afterBody(); // epilogue still under the cap
    s.close();                    // disarm + close; the destructor would too
}

HttpClient::HttpStream HttpClient::open(const ParsedUrl& u, http::request<http::string_body> req,
                                        const std::function<void()>& onHardCap) {
    // defined here (not inside Impl) so the session type is complete; a plain
    // function - no coroutine keywords, so no frame captures the shell this
    auto s = std::make_shared<HttpStream::Session>();
    s->client = impl_.get(); // sslContext()/setupTls/error mapping; stable Impl* (PIMPL)
    s->url = u;
    s->req = std::move(req);
    s->onHardCap = onHardCap;
    s->connectTimeout = impl_->connectTimeout;
    s->totalCap = impl_->totalCap;
    return HttpStream{std::move(s)};
}

// ---- HttpStream: plain forwarders over the shared session ----

HttpClient::HttpStream::HttpStream(std::shared_ptr<Session> s) noexcept
    : session_(std::move(s)) {}
HttpClient::HttpStream::HttpStream(HttpStream&&) noexcept = default;
HttpClient::HttpStream& HttpClient::HttpStream::operator=(HttpStream&&) noexcept = default;

HttpClient::HttpStream::~HttpStream() {
    if (session_) session_->closeUpstream(); // destruction implies close()
}

bool HttpClient::HttpStream::open_() const noexcept { return session_ != nullptr; }

asio::awaitable<http::response_parser<http::buffer_body>*> HttpClient::HttpStream::getHead() {
    if (!session_ || session_->closed || session_->headDone)
        throwHttp(500, "HttpStream used out of order", false);
    co_return co_await session_->head();
}

asio::awaitable<std::optional<std::string_view>> HttpClient::HttpStream::getChunk() {
    for (;;) {
        auto n = co_await session_->chunk(session_->buf, sizeof(session_->buf));
        if (!n) co_return std::nullopt; // body complete
        if (*n > 0) co_return std::string_view(session_->buf, *n);
        // 0 = spurious wake without bytes: read again
    }
}

asio::awaitable<std::optional<size_t>>
HttpClient::HttpStream::getChunk(char* out, size_t n) {
    if (!session_ || session_->closed) throwHttp(500, "HttpStream used out of order", false);
    if (n == 0) co_return size_t{0};
    for (;;) {
        auto got = co_await session_->chunk(out, n);
        if (got && *got == 0) continue; // spurious wake without bytes: read again
        co_return got;
    }
}

void HttpClient::HttpStream::close() {
    if (session_) {
        session_->closeUpstream(); // closes the upstream, disarms the cap, marks closed
        session_.reset();          // back to the detached state (open_() == false)
    }
}

void HttpClient::HttpStream::setIdle(std::chrono::milliseconds v) {
    if (v <= std::chrono::milliseconds(0)) session_->idle.reset();
    else session_->idle = v;
}

// ---- buffered API: assemble the request, run one session to completion ----

namespace {
asio::awaitable<http::response<http::string_body>>
bufferedRun(HttpClient::HttpStream s, size_t maxBodyBytes) {
    auto* p = co_await s.getHead();
    BufferedHandler handler{maxBodyBytes}; // buffered: the default afterBody no-op applies
    auto idle = co_await handler.onHeader(*p);
    s.setIdle(idle ? *idle : std::chrono::milliseconds(-1));

    while (auto chunk = co_await s.getChunk())
        co_await handler.onBody(chunk->data(), chunk->size());

    co_await handler.afterBody();
    s.close();

    http::response<http::string_body> res{http::status(handler.status), handler.version};
    for (const auto& [k, v] : handler.headers) res.insert(k, v);
    res.body() = std::move(handler.body);
    co_return res;
}
} // namespace

asio::awaitable<http::response<http::string_body>>
HttpClient::request(http::verb method, const std::string& url,
                    std::vector<std::pair<std::string, std::string>> extraHeaders,
                    std::string body) {
    auto u = parseUrl(url);
    if (!u) throwHttp(500, "invalid url", false);

    http::request<http::string_body> req{method, u->target, 11};
    req.set(http::field::host, u->hostHeader);
    req.set(http::field::user_agent, "http-client-cpp");
    for (const auto& [k, v] : extraHeaders) req.set(k, v);
    req.body() = std::move(body);
    req.keep_alive(false); // one request per connection (no upstream pooling)
    req.prepare_payload();

    co_return co_await bufferedRun(open(*u, std::move(req)), impl_->maxBodyBytes);
}

asio::awaitable<http::response<http::string_body>> HttpClient::get(const std::string& url) {
    co_return co_await request(http::verb::get, url, {}, "");
}

asio::awaitable<http::response<http::string_body>>
HttpClient::post(const std::string& url, std::string body, const std::string& contentType) {
    std::vector<std::pair<std::string, std::string>> headers;
    if (!contentType.empty()) headers.emplace_back("content-type", contentType);
    co_return co_await request(http::verb::post, url, std::move(headers), std::move(body));
}

asio::awaitable<http::response<http::string_body>>
HttpClient::put(const std::string& url, std::string body, const std::string& contentType) {
    std::vector<std::pair<std::string, std::string>> headers;
    if (!contentType.empty()) headers.emplace_back("content-type", contentType);
    co_return co_await request(http::verb::put, url, std::move(headers), std::move(body));
}

asio::awaitable<http::response<http::string_body>> HttpClient::del(const std::string& url) {
    co_return co_await request(http::verb::delete_, url, {}, "");
}
