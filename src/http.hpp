#pragma once
// HTTP server layer: Boost.Beast + Asio C++20 coroutines.
// Responsibilities: listening, base-path stripping, routing, 405, static SPA
// hosting, central error handling -> JSON, cookie parse/set, streaming
// responses (SSE self-write mode).
// ctx.res is the single response object: routes, static files and errors all
// fill it in place; the framework never replaces it.

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp> // origin-form parsing: decoded path segments and query params

#include "error.hpp"
#include "http_config.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace json = boost::json;

// ---- request context ----

struct Ctx {
    http::request<http::string_body> req;
    http::response<http::string_body> res{http::status::ok, 11};

    beast::tcp_stream* sock = nullptr; // injected by the session layer (non-owning; never null while a handler runs)
    bool respond = true;               // false = handler self-writes the response: the framework writes nothing
                                       // and does no error fallback (errors end the connection; once the header is
                                       // committed the status can no longer change)

    std::map<std::string, std::string> params; // route params (:name)
    std::map<std::string, std::string> query;  // query params (decoded)
    json::value body;                          // parsed JSON body (null = none)

    std::optional<std::string> user; // JWT username (lowercase; nullopt = none)

    // JSON response with Content-Type: application/json
    void json(int status, const json::value& v);
    // Append a Set-Cookie (repeatable); adds Secure only when a loopback
    // reverse proxy marks the request HTTPS, not for direct HTTP
    void setCookie(const std::string& name, const std::string& value, const std::string& path,
                   std::optional<long long> maxAgeSeconds);
    // Read a cookie
    [[nodiscard]] std::optional<std::string> cookie(const std::string& name) const;

    // ---- streaming response (self-write mode) ----

    // Commits SSE response headers and enters self-write mode: sets
    // respond=false, the status, Content-Type: text/event-stream,
    // Cache-Control: no-cache, TE: chunked, writes the header and lifts the
    // 30s deadline (Beast deadlines persist across operations and would cap
    // all later writes; long streams must lift them)
    asio::awaitable<void> beginSse(int status = 200);
    // Writes one chunk (TE: chunked framing; a temporary string argument is
    // safe: the write completes within the co_await)
    asio::awaitable<void> writeChunk(std::string_view data) const;
    // Finishes the stream with the last-chunk. Reuses the connection by
    // default; call res.keep_alive(false) afterwards to close
    asio::awaitable<void> endStream() const;
};

using Handler = std::function<asio::awaitable<void>(Ctx&)>;

// ---- router (static segments + :param; 405 carries Allow) ----

class Router {
public:
    void add(http::verb method, const std::string& pattern, Handler handler);

    // Matching takes URL-decoded path segments (no leading empty segment; a
    // trailing empty segment = trailing slash). Returns handler+params;
    // nullopt on no match; path exists but method differs -> 405 with Allow.
    // Holds std::function/std::map by value: the implicit special members
    // are inherently throwing (std::map's move ctor is not noexcept per the
    // standard), so nothrow cannot be promised -> single-point exemption
    struct Match { // NOLINT(bugprone-exception-escape)
        Handler handler;
        std::map<std::string, std::string> params;
    };
    std::optional<Match> match(http::verb method, const std::vector<std::string>& segs,
                               std::string& allowHeader) const;

private:
    struct Route {
        http::verb method;
        std::vector<std::string> segments; // ":name" = param segment
        Handler handler;
    };
    std::vector<Route> routes_;
};

// ---- server startup ----

// Starts the listening coroutine: the framework needs only config + a
// routing table and no business types (the application context is constructed
// and captured by the user's own handlers). config/router are read-only
// after assembly and passed by const reference; the referenced objects must
// outlive the event loop (declaring them before io_context suffices).
asio::awaitable<void> listen(asio::ip::tcp::acceptor acceptor, const Router& router,
                             const HttpConfig& config);
