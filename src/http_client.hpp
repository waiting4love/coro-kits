#pragma once
// Outbound HTTP/HTTPS client (Boost.Beast + Asio C++20 coroutines).
//
// Responsibilities: URL parsing, resolve/connect (+TLS: SNI, certificate
// chain and DNS/IP identity verification), sending the request, receiving
// response headers and body. Depends only on http_srv.hpp/error.hpp + Boost.
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

#include "http_srv.hpp"

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

    // Streaming exchange (event contract: ExchangeHandler). onHardCap fires
    // when the total cap does, before the 504 surfaces: use it to unblock
    // anything this exchange might be suspended on (e.g. a stalled
    // zero-window client socket in self-write mode)
    asio::awaitable<void> exchange(const ParsedUrl& u, http::request<http::string_body> req,
                                   ExchangeHandler& handler,
                                   const std::function<void()>& onHardCap = {});

    // ---- streaming object (pull style; the other two APIs are adapters over it) ----

    // One streamed exchange. Acquire with HttpClient::open(), then:
    //   auto& head = co_await s.getHead();   // resolve+connect(+TLS)+request+headers,
    //                                        // one connectTimeout budget; parser out-param
    //   s.setIdle(15000ms);                  // optional: body-stage rolling idle budget
    //                                        // (default: unlimited, totalCap is the net)
    //   while (auto chunk = co_await s.getChunk())
    //       use(*chunk);                     // or: s.getChunk(std::span<char>)
    //   /* epilogue writes (e.g. SSE last-chunk) here - still under the total cap */
    //   s.close();                           // disarm the cap + close the upstream; idempotent
    //
    // Abort semantics: when the total cap fires, the upstream is force-closed, the
    // onHardCap unblock hook (open() parameter) runs first, and the suspended
    // co_await throws HttpError 504. Transport/timeout failures map to 502/504 at
    // the suspended co_await; business exceptions cannot arise inside HttpStream.
    // Lifecycle: movable (the session lives on a shared state object, its address
    // is stable); must not outlive the HttpClient; close() also runs on destruction.
    // Not thread-safe: confined to the io_context thread like everything else.
    class HttpStream {
    public:
        HttpStream() = default; // an empty shell: assign a real one over it via move
        HttpStream(HttpStream&&) noexcept;
        HttpStream& operator=(HttpStream&&) noexcept;
        ~HttpStream(); // implies close()
        HttpStream(const HttpStream&) = delete;
        HttpStream& operator=(const HttpStream&) = delete;

        [[nodiscard]] bool open_() const noexcept; // test hook: whether a session is attached

        // Runs resolve+connect(+TLS)+request write+response-header read under one
        // connectTimeout budget. Returns the live parser (status, headers, and the
        // buffer_body for advanced use); the reference stays valid for the stream's
        // lifetime. Invalid without a session (shell) or after close(): throws
        // HttpError 500
        asio::awaitable<http::response_parser<http::buffer_body>*> getHead(); // never null; caller-held for the stream lifetime

        // Body-stage rolling idle budget: re-armed before every read, so silence
        // between chunks beyond it aborts via beast (-> 504). Call after getHead(),
        // before the first getChunk; values <= 0 disable (default)
        void setIdle(std::chrono::milliseconds v);

        // Next non-empty body chunk; a view into the session's internal buffer,
        // valid until the NEXT getChunk call (or close/destruction - it is
        // overwritten in place, and a stale view often still "looks right": if the
        // data must outlive the next call, use the span overload below).
        // nullopt = body complete (subsequent calls keep returning nullopt)
        asio::awaitable<std::optional<std::string_view>> getChunk();

        // Caller-buffered variant (asio idiom): reads straight into `out` - zero
        // copy, and data survives past the next call. Returns the bytes read;
        // nullopt = body complete. At most `n` bytes per call; chunking upstream
        // is not preserved (a "chunk" is whatever fits the buffer)
        asio::awaitable<std::optional<size_t>> getChunk(char* out, size_t n);

        // Disarms the total cap and closes the upstream. Idempotent; after close()
        // the object returns to the detached state (getHead/getChunk throw 500).
        // The epilogue (e.g. SSE last-chunk) belongs BEFORE this call, so it stays
        // under the cap
        void close();

    private:
        friend class HttpClient;
        struct Session; // defined inside Impl (http_client.cpp)
        explicit HttpStream(std::shared_ptr<Session> s) noexcept; // Impl-only
        std::shared_ptr<Session> session_; // empty = detached shell
    };

    // Lazily acquires a streamed exchange: nothing runs until getHead(). onHardCap
    // is the unblock hook: it fires when the total cap does, before the 504
    // surfaces - close anything the exchange might be suspended on (a stalled
    // zero-window client socket; only closing the upstream would never wake it)
    HttpStream open(const ParsedUrl& u, http::request<http::string_body> req,
                    const std::function<void()>& onHardCap = {});

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
