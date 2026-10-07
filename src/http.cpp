#include "http.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>

#include <boost/beast/http/chunk_encode.hpp> // chunk_body/chunk_last: hand-written chunked frames

// ---- utilities ----

namespace {

// Two body limits: the beast parser hard cap (exceeding it drops the
// connection) and the business limit (413, the connection may continue;
// matches koa-bodyparser's 1mb jsonLimit)
constexpr std::size_t kMaxParserBodyBytes = 8ULL * 1024 * 1024;
constexpr std::size_t kMaxRequestBodyBytes = 1024ULL * 1024;

std::vector<std::string> splitPath(const std::string& path) {
    std::vector<std::string> segs;
    std::string cur;
    for (char c : path) {
        if (c == '/') {
            segs.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    segs.push_back(std::move(cur));
    return segs; // "/api/count/x" -> ["", "api", "count", "x"]
}

std::string joinPath(const std::vector<std::string>& segs, size_t from) {
    std::string out;
    for (size_t i = from; i < segs.size(); ++i) {
        out += '/';
        out += segs[i];
    }
    return out.empty() ? "/" : out;
}

// Splits "/a/b" into segments (drops the leading empty segment produced by '/')
std::vector<std::string> pathSegs(const std::string& path) {
    auto segs = splitPath(path);
    if (!segs.empty() && segs.front().empty()) segs.erase(segs.begin());
    return segs;
}

// Segment-level prefix match: the path equals prefixPath or lives below it
bool segsStartsWith(const std::vector<std::string>& segs, const std::string& prefixPath) {
    auto pre = pathSegs(prefixPath);
    return segs.size() >= pre.size() && std::equal(pre.begin(), pre.end(), segs.begin());
}

const char* mimeOf(const std::string& path) {
    auto endsWith = [&](const char* suffix) {
        size_t n = strlen(suffix);
        return path.size() >= n && path.compare(path.size() - n, n, suffix) == 0;
    };
    if (endsWith(".html")) return "text/html; charset=utf-8";
    if (endsWith(".js")) return "text/javascript";
    if (endsWith(".mjs")) return "text/javascript";
    if (endsWith(".css")) return "text/css";
    if (endsWith(".json")) return "application/json";
    if (endsWith(".txt")) return "text/plain; charset=utf-8";
    if (endsWith(".ico")) return "image/vnd.microsoft.icon";
    if (endsWith(".svg")) return "image/svg+xml";
    if (endsWith(".png")) return "image/png";
    if (endsWith(".jpg") || endsWith(".jpeg")) return "image/jpeg";
    if (endsWith(".gif")) return "image/gif";
    if (endsWith(".woff")) return "font/woff";
    if (endsWith(".woff2")) return "font/woff2";
    if (endsWith(".ttf")) return "font/ttf";
    if (endsWith(".map")) return "application/json";
    return "application/octet-stream";
}

// Rewrites an existing response in place as a JSON error (headers already set are kept)
void applyJsonError(http::response<http::string_body>& res, int status, const std::string& message) {
    json::object o;
    o["error"] = message;
    res.result(status);
    res.set(http::field::content_type, "application/json; charset=utf-8");
    res.body() = json::serialize(o);
}

http::response<http::string_body> errorResponse(int status, const std::string& message) {
    json::object o;
    o["error"] = message;
    http::response<http::string_body> res{http::status(status), 11};
    res.set(http::field::content_type, "application/json; charset=utf-8");
    res.body() = json::serialize(o);
    return res;
}

// CORS is applied to every response (405/parse errors/413 included) so
// cross-origin browsers see the real status instead of a TypeError; not
// applied when unconfigured
bool corsEnabled(const HttpConfig& config) { return !config.corsAllowOrigin.empty(); }

void applyCors(const HttpConfig& config, http::response<http::string_body>& res) {
    if (!corsEnabled(config)) return;
    res.set(http::field::access_control_allow_origin, config.corsAllowOrigin);
    res.set(http::field::access_control_allow_methods, config.corsAllowMethods);
    res.set(http::field::access_control_allow_headers, config.corsAllowHeaders);
}

// Reads a whole file. Open failure (missing/unreadable...) -> nullopt.
// With async file support (asio gates stream_file behind BOOST_ASIO_HAS_FILE,
// e.g. Windows or Linux with io_uring) the read is asynchronous; EOF arrives
// as error::eof by convention (caught via as_tuple, the bytes read are still
// valid, and truncation shortens the result). Without it, a synchronous
// ifstream read - same semantics, briefly blocking the single-threaded loop
// for a static file, matching the pre-stream_file behavior.
asio::awaitable<std::optional<std::string>> readFileAsync(const std::string& path) {
    std::error_code fec;
    if (!std::filesystem::is_regular_file(path, fec)) co_return std::nullopt;

#if defined(BOOST_ASIO_HAS_FILE)
    try {
        asio::stream_file file(co_await asio::this_coro::executor, path,
                               asio::stream_file::read_only);
        std::string content;
        if (uint64_t size = file.size(); size > 0) {
            content.resize((size_t)size);
            auto [ec, n] = co_await asio::async_read(
                file, asio::buffer(content), asio::as_tuple(asio::use_awaitable));
            if (ec && ec != asio::error::eof) co_return std::nullopt;
            if (ec == asio::error::eof) content.resize(n);
        }
        co_return content;
    } catch (const boost::system::system_error&) {
        co_return std::nullopt;
    }
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) co_return std::nullopt;
    co_return std::string{(std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()};
#endif
}

} // namespace

// ---- Ctx ----

void Ctx::json(int status, const json::value& v) {
    res.result(status);
    res.set(http::field::content_type, "application/json; charset=utf-8");
    res.body() = json::serialize(v);
}

void Ctx::setCookie(const std::string& name, const std::string& value, const std::string& path,
                    std::optional<long long> maxAgeSeconds) {
    // RFC 6265 conventional form: Max-Age over Expires (no clock math),
    // conventional attribute casing
    std::string c = name + "=" + value + "; Path=" + path;
    if (maxAgeSeconds && *maxAgeSeconds > 0) {
        c += "; Max-Age=" + std::to_string(*maxAgeSeconds);
        c += "; SameSite=Lax; HttpOnly";
    } else {
        c += "; Max-Age=0"; // clear
    }
    // Trust the protocol marker only from a loopback reverse proxy: a remote
    // client must not be able to forge X-Forwarded-Proto. Direct HTTP
    // debugging gets no Secure
    if (sock != nullptr && req["X-Forwarded-Proto"] == "https") {
        boost::system::error_code ec;
        auto peer = sock->socket().remote_endpoint(ec);
        if (!ec && peer.address().is_loopback()) c += "; Secure";
    }
    res.insert(http::field::set_cookie, c);
}

std::optional<std::string> Ctx::cookie(const std::string& name) const {
    auto it = req.find(http::field::cookie);
    if (it == req.end()) return std::nullopt;
    std::string_view header = it->value();
    size_t start = 0;
    while (start <= header.size()) {
        auto semi = header.find(';', start);
        std::string_view part = header.substr(
            start, semi == std::string_view::npos ? std::string_view::npos : semi - start);
        // trim surrounding whitespace
        while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) part.remove_prefix(1);
        while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) part.remove_suffix(1);
        auto eq = part.find('=');
        if (eq != std::string_view::npos && part.substr(0, eq) == name)
            return std::string(part.substr(eq + 1));
        if (semi == std::string_view::npos) break;
        start = semi + 1;
    }
    return std::nullopt;
}

// ---- streaming response (self-write mode) ----

asio::awaitable<void> Ctx::beginSse(int status) {
    // Self-write mode: the framework writes no response and does no error
    // fallback (errors end the connection)
    respond = false;
    res.keep_alive(req.keep_alive()); // connection lifetime follows the client's wish by default
    res.result(http::status(status));
    res.set(http::field::content_type, "text/event-stream");
    res.set(http::field::cache_control, "no-cache");
    res.chunked(true);
    http::response_serializer<http::string_body> sr{res};
    // explicit token: the implicit default is awaitable only since Boost 1.84+
    // (deferred became the default completion token); 1.81-1.83 need this
    co_await http::async_write_header(*sock, sr, asio::use_awaitable);
    // The 30s deadline set before the session read persists across
    // operations and covers all later writes; long streams must lift it
    sock->expires_never();
}

asio::awaitable<void> Ctx::writeChunk(std::string_view data) const {
    co_await asio::async_write(*sock, http::chunk_body(asio::buffer(data.data(), data.size())),
                               asio::use_awaitable);
}

asio::awaitable<void> Ctx::endStream() const {
    co_await asio::async_write(*sock, http::chunk_last(), asio::use_awaitable);
}

// ---- Router ----

void Router::add(http::verb method, const std::string& pattern, Handler handler) {
    auto segs = splitPath(pattern);
    // drop the first empty segment (patterns start with '/')
    if (!segs.empty() && segs.front().empty()) segs.erase(segs.begin());
    routes_.push_back(Route{method, std::move(segs), std::move(handler)});
}

std::optional<Router::Match> Router::match(http::verb method, const std::vector<std::string>& segsIn,
                                           std::string& allowHeader) const {
    std::span segs = segsIn;
    // tolerate a trailing slash: a trailing empty segment ("/api/count/" ->
    // ["api","count",""]) counts as none
    if (segs.size() > 1 && segs.back().empty()) segs = segs.subspan(0, segs.size() - 1);

    std::optional<Match> found;
    std::vector<std::string> allowMethods;
    bool pathMatched = false;

    for (const auto& r : routes_) {
        // a trailing "*" is a wildcard matching zero or more remaining
        // segments ("/files/*" covers "/files" and any depth below); the
        // wildcard part collects no params
        bool wildcard = !r.segments.empty() && r.segments.back() == "*";
        size_t fixed = wildcard ? r.segments.size() - 1 : r.segments.size();
        if (segs.size() < fixed) continue;
        if (!wildcard && segs.size() != r.segments.size()) continue;

        std::map<std::string, std::string> params;
        bool ok = true;
        for (size_t i = 0; i < fixed; ++i) {
            const std::string& pat = r.segments[i];
            if (!pat.empty() && pat[0] == ':') params[pat.substr(1)] = segs[i];
            else if (pat != segs[i]) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        pathMatched = true;
        allowMethods.emplace_back(http::to_string(r.method));
        if (r.method == method && !found)
            found = Match{r.handler, std::move(params)};
    }

    if (!found && pathMatched) {
        // registering GET also serves HEAD (allowedMethods behavior)
        if (std::ranges::find(allowMethods, "GET") != allowMethods.end())
            allowMethods.emplace_back("HEAD");
        // descending join (matches @koa/router's sort().reverse())
        std::ranges::sort(allowMethods, std::greater<>());
        allowMethods.erase(std::ranges::unique(allowMethods).begin(), allowMethods.end());
        allowHeader.clear();
        for (size_t i = 0; i < allowMethods.size(); ++i) {
            if (i) allowHeader += ", ";
            allowHeader += allowMethods[i];
        }
    }
    return found;
}

// ---- inner handling ----

namespace {

// Inner handling: every path fills ctx.res in place; the response object is
// never replaced (CORS headers were applied when the Ctx was created, and
// error rewrites rely on keeping them)
asio::awaitable<void> handleInner(const HttpConfig& config, const Router& router, Ctx& ctx) {
    // 1) origin-form parsing (Boost.URL: decoded path segments and query
    //    params in one step). Malformed escapes (e.g. "%zz") are rejected here
    auto parsed = boost::urls::parse_origin_form(ctx.req.target());
    if (!parsed) {
        applyJsonError(ctx.res, 400, "Bad request");
        co_return;
    }
    std::vector<std::string> segs;
    for (auto s : parsed->segments()) segs.emplace_back(s);
    for (auto p : parsed->params())
        ctx.query[std::string(p.key)] = p.has_value ? std::string(p.value) : std::string();

    // 2) base-path stripping: segment-wise compare, then drop prefix segments
    const std::string& bp = config.basePath;
    if (!bp.empty()) {
        auto bpSegs = pathSegs(bp);
        if (segs == bpSegs) { // exact hit -> canonicalize to the trailing slash (SPA-relative-path friendly)
            ctx.res.result(http::status::found);
            ctx.res.set(http::field::location, bp + "/");
            co_return;
        }
        if (!segsStartsWith(segs, bp)) {
            applyJsonError(ctx.res, 404, "Not found");
            co_return;
        }
        segs.erase(segs.begin(), segs.begin() + (std::ptrdiff_t)bpSegs.size());
    }

    // 2.5) OPTIONS preflight short-circuit: with CORS configured, any path ->
    //      204 (a preflight needs a 2xx; it cannot rely on 405+Allow, and no
    //      catch-all route is registered, keeping 404 semantics intact for
    //      other methods; CORS headers are already applied)
    if (ctx.req.method() == http::verb::options && corsEnabled(config)) {
        ctx.res.result(http::status::no_content);
        // cache the preflight result, saving repeat OPTIONS round trips
        ctx.res.set(http::field::access_control_max_age, "86400");
        co_return;
    }

    // 3) JSON body parsing (only when Content-Type contains json)
    {
        auto ct = ctx.req.find(http::field::content_type);
        bool isJson = ct != ctx.req.end() &&
                      ct->value().find("json") != std::string_view::npos;
        if (isJson && !ctx.req.body().empty()) {
            boost::system::error_code ec;
            ctx.body = json::parse(ctx.req.body(), ec);
            if (ec) throw HttpError(400, "Invalid JSON");
        }
    }

    // 4) route dispatch (CORS headers are already applied, route-independent)
    std::string allowHeader;
    auto m = router.match(ctx.req.method(), segs, allowHeader);
    if (m) {
        ctx.params = std::move(m->params);
        co_await m->handler(ctx);
        co_return;
    }
    if (!allowHeader.empty()) {
        applyJsonError(ctx.res, 405, "Method Not Allowed");
        ctx.res.set(http::field::allow, allowHeader);
        co_return;
    }

    // 5) unmatched paths under exclusion prefixes -> 404 JSON, never falling
    //    through to the SPA fallback (policy owned by the application)
    for (const auto& p : config.spaExcludePrefixes)
        if (segsStartsWith(segs, p)) {
            applyJsonError(ctx.res, 404, "Not found");
            co_return;
        }

    // 6) static files + SPA fallback (GET only; HEAD may fetch file headers)
    bool getable = ctx.req.method() == http::verb::get || ctx.req.method() == http::verb::head;
    if (getable) {
        // path traversal guard
        for (const auto& s : segs)
            if (s == "..") {
                applyJsonError(ctx.res, 404, "Not found");
                co_return;
            }

        std::string rel = joinPath(segs, 0);
        if (rel.size() > 1 && rel.back() == '/') rel += "index.html";
        if (rel == "/") rel = "/index.html";
        std::string filePath = config.staticDir + rel;

        if (auto content = co_await readFileAsync(filePath)) {
            ctx.res.result(http::status::ok);
            ctx.res.set(http::field::content_type, mimeOf(filePath));
            ctx.res.body() = std::move(*content);
            co_return;
        }

        // SPA fallback: GET and index.html exists -> serve it
        if (ctx.req.method() == http::verb::get) {
            std::string indexPath = config.staticDir + "/index.html";
            if (auto content = co_await readFileAsync(indexPath)) {
                ctx.res.result(http::status::ok);
                ctx.res.set(http::field::content_type, "text/html; charset=utf-8");
                ctx.res.body() = std::move(*content);
                co_return;
            }
        }
    }

    applyJsonError(ctx.res, 404, "Not found");
}

} // namespace

// ---- connection session ----

namespace {

// One request-response round trip: read -> dispatch -> write. Returns false =
// the connection should end (peer asked to close / 413 hard cap / the
// self-write path chose to close); I/O errors (peer disconnect, write
// timeout) propagate to doSession for silent cleanup
asio::awaitable<bool> doExchange(beast::tcp_stream& stream, const Router& router,
                                 const HttpConfig& config) {
    stream.expires_after(std::chrono::seconds(30));
    beast::flat_buffer buf;

    http::request_parser<http::string_body> parser;
    parser.body_limit(kMaxParserBodyBytes); // hard memory cap (the business limit is judged after reading)
    bool bodyLimited = false;
    {
        // as_tuple takes over error completions so the error path avoids
        // exceptions: a bare rethrow from a coroutine catch handler crashes
        // in SEH dispatch on this toolchain (clang/MSVC-ABI; 2026-10 ASAN
        // finding). Semantics unchanged: body_limit -> the 413 side path;
        // any other error -> rethrown as before, ending the connection
        auto [ec, n] = co_await http::async_read(stream, buf, parser,
                                                 asio::as_tuple(asio::use_awaitable));
        (void)n;
        if (ec == http::error::body_limit)
            bodyLimited = true;
        else if (ec)
            throw boost::system::system_error(ec);
    }
    if (bodyLimited) {
        // the request is incomplete, no usable req: answer directly and
        // close (CORS applied so cross-origin browsers can read the 413)
        http::response<http::string_body> res = errorResponse(413, "request entity too large");
        applyCors(config, res);
        res.keep_alive(false);
        res.prepare_payload();
        co_await http::async_write(stream, res, asio::use_awaitable);
        co_return false;
    }

    bool keep = parser.get().keep_alive();
    // HEAD: keep the real Content-Length but send no body. beast does not
    // strip the response body, and clearing it early would make
    // prepare_payload compute CL=0, so clear it after prepare_payload
    bool isHead = parser.get().method() == http::verb::head;

    Ctx ctx;
    ctx.req = parser.release();
    ctx.sock = &stream;
    // apply the shared CORS headers up front: every later path (error
    // rewrites, self-written headers) keeps them
    applyCors(config, ctx.res);

    // matches koa-bodyparser's 1mb jsonLimit: over the limit -> 413 (the
    // connection may continue)
    if (ctx.req.body().size() > kMaxRequestBodyBytes) {
        applyJsonError(ctx.res, 413, "request entity too large");
    } else {
        try {
            co_await handleInner(config, router, ctx);
        } catch (const HttpError& e) {
            // rewrite ctx.res in place: headers set or written before the
            // error survive. In self-write mode the header may already be
            // committed and the status cannot change -> just close
            if (!ctx.respond) ctx.res.keep_alive(false);
            else applyJsonError(ctx.res, e.status, e.expose ? e.what() : "Internal error");
            std::cerr << "[http] " << e.status << " " << e.what() << '\n';
        } catch (const std::exception& e) {
            if (!ctx.respond) ctx.res.keep_alive(false);
            else applyJsonError(ctx.res, 500, "Internal error");
            std::cerr << "[http] unhandled error: " << e.what() << '\n';
        } catch (...) {
            if (!ctx.respond) ctx.res.keep_alive(false);
            else applyJsonError(ctx.res, 500, "Internal error");
            std::cerr << "[http] unknown error" << '\n';
        }
    }

    // self-write path: the handler finished writing; connection lifetime was
    // its decision (beginSse already synced the client's wish)
    if (!ctx.respond) co_return ctx.res.keep_alive();

    ctx.res.keep_alive(keep);
    ctx.res.prepare_payload();
    if (isHead) ctx.res.body().clear();
    co_await http::async_write(stream, ctx.res, asio::use_awaitable);
    co_return keep;
}

} // namespace

asio::awaitable<void> doSession(beast::tcp_stream stream, const Router& router,
                                const HttpConfig& config) {
    try {
        for (;;) {
            bool keep = co_await doExchange(stream, router, config);
            if (!keep) break;
        }
    } catch (const std::exception& e) {
        // peer closed the connection / write timeout &c: normal silent cleanup
        (void)e;
    }
}

asio::awaitable<void> listen(asio::ip::tcp::acceptor acceptor, const Router& router,
                             const HttpConfig& config) {
    for (;;) {
        auto [ec, sock] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec == asio::error::operation_aborted) break;
            continue;
        }
        beast::tcp_stream stream(std::move(sock));
        // router/config bind by reference into the session coroutine frames;
        // the referenced objects live on the caller's stack for the whole
        // event loop
        asio::co_spawn(acceptor.get_executor(),
                       doSession(std::move(stream), router, config), asio::detached);
    }
}
