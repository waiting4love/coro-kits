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

    asio::awaitable<void> exchange(const ParsedUrl& u, http::request<http::string_body> req,
                                   ExchangeHandler& handler) {
        auto ex = co_await asio::this_coro::executor;

        asio::steady_timer reaper(ex);
        bool capped = false;
        auto arm = [&](auto& upstream) {
            if (totalCap <= std::chrono::milliseconds(0)) return;
            reaper.expires_after(totalCap);
            armReaper(reaper, upstream, capped, handler);
        };

        // resolve+connect (+TLS handshake) + request write + response-header
        // read share one connectTimeout budget
        try {
            asio::ip::tcp::resolver resolver(ex);
            auto [rec, endpoints] = co_await resolver.async_resolve(
                u.host, u.port, asio::as_tuple(asio::use_awaitable));
            if (rec) throw boost::system::system_error(rec);

            if (u.tls) {
                asio::ssl::stream<beast::tcp_stream> upstream(ex, sslContext());
                setupTls(upstream, u.host);
                arm(upstream);

                beast::get_lowest_layer(upstream).expires_after(connectTimeout);
                co_await beast::get_lowest_layer(upstream).async_connect(endpoints,
                                                                         asio::use_awaitable);
                co_await upstream.async_handshake(asio::ssl::stream_base::client,
                                                  asio::use_awaitable);
                co_await requestAndRelay(upstream, req, handler, reaper);
            } else {
                beast::tcp_stream upstream(ex);
                arm(upstream);
                upstream.expires_after(connectTimeout);
                co_await upstream.async_connect(endpoints, asio::use_awaitable);
                co_await requestAndRelay(upstream, req, handler, reaper);
            }
        } catch (const boost::system::system_error& e) {
            // Single exit for system_error from every stage (connect/request/
            // headers/body). A reaper hit (force close yields
            // operation_aborted) reports as 504 first, matching idle-timeout
            // semantics
            if (capped) throwHttp(504, "Upstream stream timed out");
            throwUpstreamError(e);
        }
    }

    // ---- buffered ----

    asio::awaitable<http::response<http::string_body>> get(const std::string& url) {
        co_return co_await request(http::verb::get, url, {}, "");
    }

    asio::awaitable<http::response<http::string_body>>
    post(const std::string& url, std::string body, const std::string& contentType) {
        std::vector<std::pair<std::string, std::string>> headers;
        if (!contentType.empty()) headers.emplace_back("content-type", contentType);
        co_return co_await request(http::verb::post, url, std::move(headers), std::move(body));
    }

    asio::awaitable<http::response<http::string_body>>
    put(const std::string& url, std::string body, const std::string& contentType) {
        std::vector<std::pair<std::string, std::string>> headers;
        if (!contentType.empty()) headers.emplace_back("content-type", contentType);
        co_return co_await request(http::verb::put, url, std::move(headers), std::move(body));
    }

    asio::awaitable<http::response<http::string_body>> del(const std::string& url) {
        co_return co_await request(http::verb::delete_, url, {}, "");
    }

    asio::awaitable<http::response<http::string_body>>
    request(http::verb method, const std::string& url,
            std::vector<std::pair<std::string, std::string>> extraHeaders, std::string body) {
        auto u = parseUrl(url);
        if (!u) throwHttp(500, "invalid url", false);

        http::request<http::string_body> req{method, u->target, 11};
        req.set(http::field::host, u->hostHeader);
        req.set(http::field::user_agent, "http-client-cpp");
        for (const auto& [k, v] : extraHeaders) req.set(k, v);
        req.body() = std::move(body);
        req.keep_alive(false); // one request per connection (no upstream pooling)
        req.prepare_payload();

        BufferedHandler handler{maxBodyBytes}; // buffered: the default afterBody/onHardCap no-ops apply
        co_await exchange(*u, std::move(req), handler);

        http::response<http::string_body> res{http::status(handler.status), handler.version};
        for (const auto& [k, v] : handler.headers) res.insert(k, v);
        res.body() = std::move(handler.body);
        co_return res;
    }

private:
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

    // Hard-cap watchdog: guards against an upstream that neither closes nor
    // sends (a hang the idle timeout cannot reach) and against writes
    // stalled by a zero-window client. close() fails pending operations
    // immediately, without relying on coroutine cancellation. Handlers with
    // ec=aborted are still posted after cancel/destruction: the frame may
    // already be gone, so check ec before touching any reference
    template <class Stream>
    static void armReaper(asio::steady_timer& timer, Stream& upstream, bool& capped,
                          ExchangeHandler& handler) {
        timer.async_wait([&upstream, &capped, &handler](const boost::system::error_code& ec) {
            if (ec) return;
            capped = true;
            beast::get_lowest_layer(upstream).close();
            handler.onHardCap(); // synchronous, from a completion handler: must not throw
        });
    }

    // Reads the body to eof (buffer_body incremental mode); one virtual
    // handler.onBody call per chunk. When idle has a value it is a rolling
    // idle timeout: a beast deadline set right before each read; silence
    // between reads beyond the budget makes beast close the upstream (->
    // 504). Set before the read, not at the loop head: the sink's writes
    // do not consume idle budget
    template <class Stream>
    static asio::awaitable<void> pumpBody(Stream& upstream, beast::flat_buffer& left,
                                          http::response_parser<http::buffer_body>& p,
                                          ExchangeHandler& handler,
                                          std::optional<std::chrono::milliseconds> idle) {
        char buf[kReadBuf];
        while (!p.is_done()) {
            p.get().body().data = buf;
            p.get().body().size = sizeof(buf);
            if (idle) beast::get_lowest_layer(upstream).expires_after(*idle);
            auto [ec, n] = co_await http::async_read_some(upstream, left, p,
                                                          asio::as_tuple(asio::use_awaitable));
            (void)n;
            if (ec && ec != http::error::need_buffer)
                throw boost::system::system_error(ec); // mid-stream break/idle timeout: mapped to 502/504 at the exit
            size_t got = sizeof(buf) - p.get().body().size;
            if (got > 0) co_await handler.onBody(buf, got);
        }
        if (idle) beast::get_lowest_layer(upstream).expires_never();
    }

    // write request -> read response headers -> onHeader (decides the body
    // idle budget) -> lift the first-byte budget -> pump body -> afterBody
    // (e.g. the SSE last-chunk write) -> disarm the hard cap
    template <class Stream>
    static asio::awaitable<void> requestAndRelay(Stream& upstream,
                                                 http::request<http::string_body>& req,
                                                 ExchangeHandler& handler,
                                                 asio::steady_timer& reaper) {
        co_await http::async_write(upstream, req, asio::use_awaitable);

        beast::flat_buffer left; // bytes over-read past the headers (the first body chunk)
        http::response_parser<http::buffer_body> p;
        // lift the default limit before reading headers; the guard is the
        // handler's decision (unlimited for SSE, maxBodyBytes for buffered)
        p.body_limit(boost::none);
        co_await http::async_read_header(upstream, left, p, asio::use_awaitable);

        auto idle = co_await handler.onHeader(p);
        beast::get_lowest_layer(upstream).expires_never();
        co_await pumpBody(upstream, left, p, handler, idle);
        co_await handler.afterBody(); // no-op unless overridden
        reaper.cancel(); // normal finish disarms the cap (later aborted callbacks only check ec, touching no references)
    }

    std::optional<asio::ssl::context> sslc_; // lazily initialized on first https, then reused read-only
};

// ---- shell: plain-function forwarders (never coroutines - no frame may
// capture the shell this; this is what makes moves safe) ----

HttpClient::HttpClient() : impl_(std::make_unique<Impl>()) {}
HttpClient::HttpClient(HttpClient&&) noexcept = default;
HttpClient& HttpClient::operator=(HttpClient&&) noexcept = default;
HttpClient::~HttpClient() = default;

void HttpClient::setConnectTimeout(std::chrono::milliseconds v) { impl_->connectTimeout = v; }
void HttpClient::setTotalCap(std::chrono::milliseconds v) { impl_->totalCap = v; }
void HttpClient::setMaxBodyBytes(size_t v) { impl_->maxBodyBytes = v; }

asio::awaitable<void> HttpClient::exchange(const ParsedUrl& u,
                                           http::request<http::string_body> req,
                                           ExchangeHandler& handler) {
    return impl_->exchange(u, std::move(req), handler);
}

asio::awaitable<http::response<http::string_body>> HttpClient::get(const std::string& url) {
    return impl_->get(url);
}

asio::awaitable<http::response<http::string_body>>
HttpClient::post(const std::string& url, std::string body, const std::string& contentType) {
    return impl_->post(url, std::move(body), contentType);
}

asio::awaitable<http::response<http::string_body>>
HttpClient::put(const std::string& url, std::string body, const std::string& contentType) {
    return impl_->put(url, std::move(body), contentType);
}

asio::awaitable<http::response<http::string_body>> HttpClient::del(const std::string& url) {
    return impl_->del(url);
}

asio::awaitable<http::response<http::string_body>>
HttpClient::request(http::verb method, const std::string& url,
                    std::vector<std::pair<std::string, std::string>> extraHeaders,
                    std::string body) {
    return impl_->request(method, url, std::move(extraHeaders), std::move(body));
}
