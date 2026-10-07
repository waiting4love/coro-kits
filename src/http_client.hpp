#pragma once
// Outbound HTTP/HTTPS client (Boost.Beast + Asio C++20 coroutines).
//
// Responsibilities: URL parsing, resolve/connect (+TLS: SNI, certificate
// chain and DNS/IP identity verification), sending the request, receiving
// response headers and body. Depends only on http.hpp/error.hpp + Boost.
//
// Two API levels:
//   - Buffered get/post/put/del/request: collects the whole body and returns
//     a response<string_body>. 4xx/5xx do not throw (the status code is
//     passed through for the caller to judge); transport/timeout failures
//     throw HttpError 502/504; redirects are not followed; the returned
//     response has hop-by-hop/framing headers stripped (safe to forward;
//     framing is recomputed on this side)
//   - Streaming exchange: an ExchangeHandler (interface) receives the
//     headers on arrival (may commit client response headers, e.g. for
//     SSE), gets body chunks one by one, plus lifecycle hooks (afterBody
//     epilogue / onHardCap abort); business exceptions propagate untouched.
//     Upstream URL and request assembly are entirely the caller's business.
//
// Timeout model (mirrors Node's AbortController plus a body-stage anti-hang
// guard):
//   connectTimeout budgets resolve+connect+TLS handshake+request write+
//   response-header read as one; the body-stage rolling idle timeout is
//   decided by the handler's onHeader return value (the buffered path
//   returns nullopt: first-byte silence is legitimate generation time);
//   totalCap is a hard overall cap - on expiry the upstream socket is force
//   closed (onHardCap decides whether the client connection goes too) -> 504.
//
// Movable (PIMPL): all state and coroutine machinery live in Impl inside
// the .cpp, and a Impl address is stable for life - a move only carries the
// shell's unique_ptr; coroutine frames of in-flight requests and TLS stream
// references all land on Impl, so moving the shell dangles nothing.
// Copying stays forbidden; a moved-from shell may only be destructed or
// re-assigned. Shell forwarders are plain functions (never coroutines), so
// no frame ever captures the shell this; with the interface-based handler,
// exchange is no longer a template either - the implementation sinks
// entirely into the .cpp and this header carries contracts only.
//
// Ownership and concurrency (single-threaded io_context rule):
//   - no io_context is held: coroutines take the executor via
//     asio::this_coro::executor at run time, binding naturally to the event
//     loop that issued the call - no cross-loop references to dangle
//   - the destruction red line is unchanged: an instance must outlive every
//     in-flight request coroutine (once Impl dies, references dangle;
//     moving is exempt - only the shell changes, Impl does not)
//   - ssl::context is lazily initialized: on the first https request it
//     reads SSL_CERT_FILE/DIR and loads CAs, then is reused read-only
//     (single-threaded SSL_CTX sharing across streams is safe; verify mode
//     and SNI live on the stream, not the context)

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "http.hpp"

// Parses an absolute URL. Anything but http/https is treated as non-tls
// (default port 80, matching the legacy upstream behavior); callers wanting
// a scheme allowlist must validate themselves
struct ParsedUrl {
    bool tls = false;
    std::string host;
    std::string port;       // service name string (the resolver accepts "443"/"8443"...)
    std::string target;     // path?query
    std::string hostHeader; // host or host:port (port included for non-default ports)
};

std::optional<ParsedUrl> parseUrl(const std::string& url);

// Hop-by-hop/framing headers that must not be reused towards the peer
// (strip them when proxying response headers)
bool hopByHop(std::string_view name);

class HttpClient {
public:
    // Streaming exchange handler: the event contract of one exchange. The
    // implementation must outlive the exchange (passed by reference,
    // non-owning). Happy-path order: onHeader -> onBody* -> afterBody;
    // onHardCap fires only on the abort path (totalCap expiry), after which
    // the exchange fails with 504 and afterBody is skipped.
    struct ExchangeHandler {
        virtual ~ExchangeHandler() = default;

        // Response headers arrived (before the body); returns the rolling
        // idle timeout for the body stage (nullopt = unlimited, totalCap is
        // the safety net). May commit client response headers here, or
        // throw a business exception to abort the exchange
        virtual asio::awaitable<std::optional<std::chrono::milliseconds>>
        onHeader(http::response_parser<http::buffer_body>& p) = 0;

        // One non-empty body chunk; may throw a business exception to abort
        // the exchange
        virtual asio::awaitable<void> onBody(const char* data, size_t n) = 0;

        // Body fully pumped, before the hard cap is disarmed (SSE: the
        // last-chunk write stays under the cap, guarding against a
        // zero-window client deadlock). Default: no-op
        virtual asio::awaitable<void> afterBody() { co_return; }

        // The hard overall cap fired: the upstream socket is already being
        // force-closed; tear down anything else that must go with it (e.g.
        // the client socket once SSE headers are committed; keep it
        // otherwise so a 504 can still be sent). Called synchronously from
        // a timer completion handler - must not throw. Default: no-op
        virtual void onHardCap() {}
    };

    HttpClient();                        // Impl assembly lives in http_client.cpp
    HttpClient(HttpClient&&) noexcept;   // carries only the unique_ptr; Impl stays put
    HttpClient& operator=(HttpClient&&) noexcept;
    ~HttpClient();                       // must happen after all in-flight request coroutines
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // ---- configuration (set once at assembly time, e.g. from Config in main) ----
    void setConnectTimeout(std::chrono::milliseconds v); // one budget for resolve~response-header read
    void setTotalCap(std::chrono::milliseconds v);       // hard overall cap; <=0 disables
    void setMaxBodyBytes(size_t v);                      // buffered-path memory guard

    // Streaming exchange (event contract: ExchangeHandler)
    asio::awaitable<void> exchange(const ParsedUrl& u, http::request<http::string_body> req,
                                   ExchangeHandler& handler);

    // ---- buffered (defined in http_client.cpp; keeps this header lean) ----

    asio::awaitable<http::response<http::string_body>> get(const std::string& url);

    asio::awaitable<http::response<http::string_body>>
    post(const std::string& url, std::string body,
         const std::string& contentType = "application/json");

    asio::awaitable<http::response<http::string_body>>
    put(const std::string& url, std::string body,
        const std::string& contentType = "application/json");

    asio::awaitable<http::response<http::string_body>> del(const std::string& url);

    asio::awaitable<http::response<http::string_body>>
    request(http::verb method, const std::string& url,
            std::vector<std::pair<std::string, std::string>> extraHeaders, std::string body);

private:
    struct Impl; // all state and coroutine machinery (.cpp); its stable address is what makes moves safe
    std::unique_ptr<Impl> impl_;
};
