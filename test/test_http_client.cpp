// HttpClient unit tests: an embedded Router server (127.0.0.1, ephemeral
// port, fully offline); each case drives the io_context (poll loop) until the
// client coroutine finishes.
// Note: the closure of a coroutine lambda must stay alive by name until the
// coroutine finishes (closures are not copied into coroutine frames; an
// immediately-invoked temporary dangles its captures).
// The https handshake chain against a temporary CA and a TLS mock is covered
// by end-to-end tests elsewhere; URL parsing and the buffered/http paths are
// covered here. One opt-in live-network case (real site, real TLS) lives at
// the bottom: it is only registered when COROKIT_LIVE_TESTS=1 is set, so the
// default suite stays hermetic and network-free.

#include "http_client.hpp"

#include <chrono>
#include <cstdlib>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include "http_srv.hpp" // Router/listen: the embedded test server


namespace {

using namespace std::chrono_literals;

// Drives the ioc until the client coroutine finishes (poll loop with a 10s
// backstop); the detached listen coroutine on the ioc does not block exit.
// Exceptions inside the coroutine rethrow on the test thread via the future.
// makeClient is a coroutine-body factory (a callable returning awaitable<T>);
// it is called inside drive: the lambda closure is not copied into the
// coroutine frame (captures are reached through this), so the closure must
// outlive the coroutine - taking a factory and constructing it in this
// function's scope removes the "temporary closure dies first" trap at the
// API level
template <class MakeClient>
auto drive(asio::io_context& ioc, MakeClient&& makeClient,
           std::chrono::steady_clock::duration budget = std::chrono::seconds(10)) {
    auto client = makeClient();
    auto fut = asio::co_spawn(ioc, std::move(client), asio::use_future);
    // a poll() loop that drains all outstanding work marks the context
    // stopped; a later drive on the same ioc must restart it first (the
    // live test drives one ioc twice)
    if (ioc.stopped()) ioc.restart();
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (fut.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        if (std::chrono::steady_clock::now() > deadline) {
            ioc.stop();
            ADD_FAILURE() << "client coroutine did not finish in time";
            throw std::runtime_error("test deadline exceeded");
        }
        ioc.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return fut.get();
}

// Embedded test server: ephemeral port + Router; cases register routes
// before start()
struct TestServer {
    asio::io_context ioc; // declared first: destroyed after the cfg/router referencing it
    HttpConfig cfg;
    Router router;
    asio::ip::tcp::acceptor acceptor;
    unsigned short port;

    TestServer() : acceptor(ioc, {asio::ip::make_address("127.0.0.1"), 0}),
                   port(acceptor.local_endpoint().port()) {}

    void start() {
        asio::co_spawn(ioc, listen(std::move(acceptor), router, cfg), asio::detached);
    }

    [[nodiscard]] std::string baseUrl() const {
        return "http://127.0.0.1:" + std::to_string(port);
    }

    template <class MakeClient>
    auto run(MakeClient&& makeClient) {
        return drive(ioc, std::forward<MakeClient>(makeClient));
    }
};

// Common client coroutine: swallows HttpError, returns the status code
// (0 = did not throw as expected)
auto statusOf(HttpClient& hc, std::string url) {
    return [&hc, url = std::move(url)]() -> asio::awaitable<int> {
        try {
            co_await hc.get(url);
            co_return 0;
        } catch (const HttpError& e) {
            co_return e.status;
        }
    };
}

// Minimal GET request for open() against the test server
http::request<http::string_body> getRequest(const ParsedUrl& u) {
    http::request<http::string_body> req{http::verb::get, u.target, 11};
    req.set(http::field::host, u.hostHeader);
    req.set(http::field::user_agent, "corokit-test");
    req.prepare_payload();
    return req;
}

TEST(HttpClientParseUrlTest, HttpsAndHttp) {
    auto u = parseUrl("https://api.example.com/v1/chat?x=1");
    ASSERT_TRUE(u);
    EXPECT_TRUE(u->tls);
    EXPECT_EQ(u->host, "api.example.com");
    EXPECT_EQ(u->port, "443"); // the default port never enters hostHeader
    EXPECT_EQ(u->target, "/v1/chat?x=1");
    EXPECT_EQ(u->hostHeader, "api.example.com");

    u = parseUrl("http://127.0.0.1:8080/x");
    ASSERT_TRUE(u);
    EXPECT_FALSE(u->tls);
    EXPECT_EQ(u->port, "8080");
    EXPECT_EQ(u->hostHeader, "127.0.0.1:8080");
}

TEST(HttpClientParseUrlTest, DefaultsAndInvalid) {
    auto u = parseUrl("http://host.example");
    ASSERT_TRUE(u);
    EXPECT_EQ(u->port, "80");
    EXPECT_EQ(u->target, "/");
    EXPECT_EQ(u->hostHeader, "host.example");

    EXPECT_FALSE(parseUrl("not a url"));
    EXPECT_FALSE(parseUrl("http://")); // no host
    EXPECT_FALSE(parseUrl("/relative/path"));
}

TEST(HttpClientHopByHopTest, Names) {
    EXPECT_TRUE(hopByHop("connection"));
    EXPECT_TRUE(hopByHop("Content-Length"));
    EXPECT_TRUE(hopByHop("TRANSFER-ENCODING"));
    EXPECT_FALSE(hopByHop("x-test"));
    EXPECT_FALSE(hopByHop("content-type"));
}

TEST(HttpClientTest, GetReturnsBodyAndStatus) {
    TestServer srv;
    srv.router.add(http::verb::get, "/hello", [](Ctx& ctx) -> asio::awaitable<void> {
        json::object o;
        o["ok"] = true;
        ctx.json(200, o);
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]() -> asio::awaitable<std::string> {
        auto res = co_await hc.get(base + "/hello");
        EXPECT_EQ(res.result(), http::status::ok);
        co_return std::string(res.body());
    };
    EXPECT_EQ(srv.run(call), "{\"ok\":true}");
}

TEST(HttpClientTest, PostEchoesBodyAndContentType) {
    TestServer srv;
    srv.router.add(http::verb::post, "/echo", [](Ctx& ctx) -> asio::awaitable<void> {
        // echo the request body and content-type verbatim, verifying
        // request assembly and header passing
        ctx.res.set(http::field::content_type,
                    std::string(ctx.req[http::field::content_type]));
        ctx.res.body() = std::string(ctx.req.body());
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]()
                    -> asio::awaitable<http::response<http::string_body>> {
        co_return co_await hc.post(base + "/echo", R"({"a":1})", "application/json");
    };
    auto res = srv.run(call);
    EXPECT_EQ(res.result(), http::status::ok);
    EXPECT_EQ(res.body(), R"({"a":1})");
    auto ct = res.find(http::field::content_type);
    ASSERT_TRUE(ct != res.end());
    EXPECT_EQ(ct->value(), "application/json");
}

TEST(HttpClientTest, StatusPassthroughWithoutThrow) {
    TestServer srv;
    srv.router.add(http::verb::get, "/nope404", [](Ctx& ctx) -> asio::awaitable<void> {
        json::object o;
        o["error"] = "no";
        ctx.json(404, o);
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]() -> asio::awaitable<http::status> {
        auto res = co_await hc.get(base + "/nope404");
        co_return res.result();
    };
    EXPECT_EQ(srv.run(call), http::status::not_found); // 4xx does not throw; caller judges
}

TEST(HttpClientTest, StripsHopByHopHeaders) {
    TestServer srv;
    srv.router.add(http::verb::get, "/hop", [](Ctx& ctx) -> asio::awaitable<void> {
        ctx.res.set("x-test", "kept");
        ctx.res.set(http::field::connection, "close"); // the client sends close anyway; the server echoes it
        ctx.res.body() = "hi";
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]()
                    -> asio::awaitable<http::response<http::string_body>> {
        co_return co_await hc.get(base + "/hop");
    };
    auto res = srv.run(call);
    auto xTest = res.find("x-test");
    ASSERT_TRUE(xTest != res.end());
    EXPECT_EQ(xTest->value(), "kept");
    // hop-by-hop/framing headers are never reused (content-length is
    // recomputed; forwarding it would double-set)
    EXPECT_EQ(res.find(http::field::connection), res.end());
    EXPECT_EQ(res.find(http::field::content_length), res.end());
    EXPECT_EQ(res.body(), "hi");
}

TEST(HttpClientTest, ShellMoveDuringFlight) {
    // Core check of the PIMPL movability: the shell is moved while a request
    // is in flight (the client coroutine is necessarily suspended mid
    // exchange); in-flight coroutines hold the stable Impl* and are
    // unaffected; the destination takes over the same Impl and keeps working
    TestServer srv;
    HttpClient origin;  // source shell: emptied while the request is in flight
    HttpClient movedTo; // destination: takes over the same Impl
    srv.router.add(http::verb::get, "/move", [&](Ctx& ctx) -> asio::awaitable<void> {
        movedTo = std::move(origin); // the request has arrived => the client coroutine is suspended
        ctx.res.body() = "ok";
        co_return;
    });
    srv.router.add(http::verb::get, "/plain", [](Ctx& ctx) -> asio::awaitable<void> {
        ctx.res.body() = "again";
        co_return;
    });
    srv.start();

    auto first = srv.run([&origin, base = srv.baseUrl()]()
                             -> asio::awaitable<http::response<http::string_body>> {
        co_return co_await origin.get(base + "/move");
    });
    EXPECT_EQ(first.body(), "ok");

    auto second = srv.run([&movedTo, base = srv.baseUrl()]()
                              -> asio::awaitable<http::response<http::string_body>> {
        co_return co_await movedTo.get(base + "/plain");
    });
    EXPECT_EQ(second.body(), "again"); // the destination owns the same Impl and can keep issuing requests
}

TEST(HttpClientTest, StreamObjectHappyPath) {
    // the object API end to end: lazy open, getHead (parser visible),
    // view-mode chunks, explicit close; the hard-cap hook never fires
    TestServer srv;
    srv.router.add(http::verb::get, "/stream", [](Ctx& ctx) -> asio::awaitable<void> {
        ctx.res.set(http::field::content_type, "text/plain");
        ctx.res.body() = "hello stream object";
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]() -> asio::awaitable<std::string> {
        auto u = parseUrl(base + "/stream");
        if (!u) throwHttp(500, "bad url");
        auto s = hc.open(*u, getRequest(*u));
        EXPECT_TRUE(s.open_());
        auto* p = co_await s.getHead();
        EXPECT_EQ((int)p->get().result_int(), 200);
        std::string body;
        while (auto chunk = co_await s.getChunk())
            body.append(chunk->data(), chunk->size());
        // (an SSE relay's last-chunk write belongs here - still under the cap)
        s.close();
        EXPECT_FALSE(s.open_());
        co_return body;
    };
    EXPECT_EQ(srv.run(call), "hello stream object");
}

TEST(HttpClientTest, StreamObjectCallerBuffer) {
    // the span-style read: data lands in caller memory and survives the next
    // getChunk; also covers reassembling chunked bodies bigger than one read
    TestServer srv;
    srv.router.add(http::verb::get, "/big", [](Ctx& ctx) -> asio::awaitable<void> {
        ctx.res.set(http::field::content_type, "text/plain");
        ctx.res.body() = std::string(100'000, 'z');
        co_return;
    });
    srv.start();

    HttpClient hc;
    auto call = [&hc, base = srv.baseUrl()]() -> asio::awaitable<std::string> {
        auto u = parseUrl(base + "/big");
        if (!u) throwHttp(500, "bad url");
        auto s = hc.open(*u, getRequest(*u));
        co_await s.getHead();
        char buf[4096];
        std::string body;
        size_t calls = 0;
        while (auto n = co_await s.getChunk(buf, sizeof(buf))) {
            body.append(buf, *n);
            ++calls;
        }
        EXPECT_GT(calls, size_t{1}); // 100k through a 4k buffer takes many reads
        s.close();
        co_return body;
    };
    EXPECT_EQ(srv.run(call), std::string(100'000, 'z'));
}

TEST(HttpClientTest, StreamObjectHardCapThrows) {
    // abort path: the 504 surfaces from getChunk (getHead already returned);
    // the unblock hook fires first
    TestServer srv;
    srv.router.add(http::verb::get, "/hang", [](Ctx& ctx) -> asio::awaitable<void> {
        (void)ctx;
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(2s);
        co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        ctx.json(200, json::object{{"ok", true}});
        co_return;
    });
    srv.start();

    HttpClient hc;
    hc.setTotalCap(50ms);
    auto call = [&hc, base = srv.baseUrl()]() -> asio::awaitable<int> {
        int hardCaps = 0;
        auto u = parseUrl(base + "/hang");
        if (!u) throwHttp(500, "bad url");
        auto s = hc.open(*u, getRequest(*u), [&] { ++hardCaps; });
        try {
            // the hung upstream never answers, so the cap can fire at either
            // suspended point (headers or first chunk); both are the abort path
            co_await s.getHead();
            while (auto chunk = co_await s.getChunk()) {
                (void)chunk;
            }
            co_return 0;
        } catch (const HttpError& e) {
            EXPECT_EQ(hardCaps, 1); // fired before the 504 surfaced
            co_return e.status;
        }
    };
    EXPECT_EQ(srv.run(call), 504);
}

TEST(HttpClientTest, MaxBodyBytesGuard) {
    TestServer srv;
    srv.router.add(http::verb::get, "/big", [](Ctx& ctx) -> asio::awaitable<void> {
        ctx.res.set(http::field::content_type, "text/plain");
        ctx.res.body() = std::string(64, 'x');
        co_return;
    });
    srv.start();

    HttpClient hc;
    hc.setMaxBodyBytes(8); // far below the response size
    EXPECT_EQ(srv.run(statusOf(hc, srv.baseUrl() + "/big")), 502);
}

TEST(HttpClientTest, TotalCapTimesOut) {
    TestServer srv;
    srv.router.add(http::verb::get, "/slow", [](Ctx& ctx) -> asio::awaitable<void> {
        (void)ctx;
        asio::steady_timer timer(co_await asio::this_coro::executor);
        timer.expires_after(2s); // far beyond totalCap: the hang is force-closed by the hard cap (-> 504)
        co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
        ctx.json(200, json::object{{"ok", true}});
        co_return;
    });
    srv.start();

    HttpClient hc;
    hc.setTotalCap(50ms);
    EXPECT_EQ(srv.run(statusOf(hc, srv.baseUrl() + "/slow")), 504);
}

TEST(HttpClientTest, ConnectionRefused502) {
    asio::io_context ioc;
    asio::ip::tcp::acceptor probe(ioc, {asio::ip::make_address("127.0.0.1"), 0});
    const std::string url =
        "http://127.0.0.1:" + std::to_string(probe.local_endpoint().port()) + "/";
    probe.close(); // nothing listens: connect is refused immediately (not a timeout)

    HttpClient hc;
    try {
        EXPECT_EQ(drive(ioc, statusOf(hc, url)), 502);
    } catch (const std::exception& e) {
        FAIL() << "escaped: " << typeid(e).name() << " : " << e.what();
    }
}

TEST(HttpClientTest, InvalidUrl500) {
    asio::io_context ioc;
    HttpClient hc;
    EXPECT_EQ(drive(ioc, statusOf(hc, "not a url")), 500);
}

// ---- opt-in live-network case (real site, real TLS) ----
// Registered only when COROKIT_LIVE_TESTS=1: the default suite stays hermetic
// (repeatable, offline-safe, fast); this case is for manual runs and machines
// with internet access. The target is the TUNA mirror service: reachable from
// mainland China without a proxy (unlike, say, Google), tolerant of repeated
// handshakes (unlike cppreference, which throttles back-to-back TLS), and
// serving a stable real page. Assertions are deliberately loose - status and
// a signature substring only, never page content (the site rewrites itself).
#ifdef COROKIT_LIVE_TESTS

// Both fetches in ONE case on purpose: the site rate-limits rapid
// back-to-back TLS handshakes, so separate ctest invocations seconds apart
// flake; a single process keeps the two connections naturally spaced
TEST(HttpClientLive, HttpsHomepage) {
    asio::io_context ioc;
    HttpClient hc;
    hc.setConnectTimeout(std::chrono::seconds(10));
    hc.setTotalCap(std::chrono::seconds(30));

    // buffered fetch over real TLS (DNS, SNI, chain verification, framing)
    auto buffered = [&hc]() -> asio::awaitable<int> {
        auto res = co_await hc.get("https://mirrors.tuna.tsinghua.edu.cn");
        EXPECT_EQ(res.result(), http::status::ok);
        // a stable signature of the real page (title block), not its content
        EXPECT_NE(res.body().find("tuna"), std::string::npos);
        co_return 0;
    };
    EXPECT_EQ(drive(ioc, buffered, std::chrono::seconds(30)), 0);

    // the pull object over real TLS: parser visible, chunks reassembled,
    // the stream completes and closes cleanly
    auto pulled = [&hc]() -> asio::awaitable<int> {
        auto u = parseUrl("https://mirrors.tuna.tsinghua.edu.cn");
        if (!u) throwHttp(500, "bad url");
        http::request<http::string_body> req{http::verb::get, u->target, 11};
        req.set(http::field::host, u->hostHeader);
        req.set(http::field::user_agent, "corokit-live-test");
        req.prepare_payload();

        auto s = hc.open(*u, std::move(req));
        auto* head = co_await s.getHead();
        EXPECT_EQ(head->get().result_int(), 200);
        size_t total = 0;
        while (auto chunk = co_await s.getChunk()) total += chunk->size();
        EXPECT_GT(total, size_t{1000}); // the landing page is ~22KB
        s.close();
        co_return 0;
    };
    EXPECT_EQ(drive(ioc, pulled, std::chrono::seconds(30)), 0);
}

#endif // COROKIT_LIVE_TESTS

} // namespace
