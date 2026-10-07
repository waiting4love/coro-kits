// coro-kit all-in-one demo: Koa-style routing + JSON/cookies/SSE + central
// error handling + the outbound HTTP client.
//
// After starting (default 127.0.0.1:18080, override with the PORT env var):
//   curl "http://127.0.0.1:18080/hello/world?times=3"        route params + query + JSON response
//   curl -X POST http://127.0.0.1:18080/echo \
//        -H 'content-type: application/json' -d '{"a":1}'    JSON body parsing + echo
//   curl -i  http://127.0.0.1:18080/visit                    cookie read/write (visit counter)
//   curl -N  http://127.0.0.1:18080/events                   SSE streaming (self-written chunks)
//   curl "http://127.0.0.1:18080/fetch?path=/hello/world"    server-side outbound request (self-fetch)
//   curl -i  http://127.0.0.1:18080/fail                     HttpError -> JSON error response
//   curl -i  http://127.0.0.1:18080/nope                     404 (central error handling)
//   curl -i -X POST http://127.0.0.1:18080/hello/world       405 + Allow

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "http_srv.hpp"
#include "http_client.hpp"

namespace {

constexpr unsigned short kPort = 18080;

// Application assembly context (the usual App pattern: make_shared
// establishes shared ownership; handlers capture a copy, so detached session
// coroutines always reach the business objects)
struct DemoApp {
    HttpClient http;      // outbound client: movable via PIMPL; coroutines bind the stable Impl*
    std::string selfBase; // this server's own baseUrl (filled after the acceptor binds; used by /fetch)
};

// Reads a positive integer query param; falls back when missing, 400 on non-numeric
int positiveQuery(const Ctx& ctx, const char* key, int fallback) {
    auto it = ctx.query.find(key);
    if (it == ctx.query.end() || it->second.empty()) return fallback;
    try {
        return std::max(1, std::stoi(it->second));
    } catch (const std::exception&) {
        throwHttp(400, std::string("invalid ") + key);
    }
}

// Route param :name + query ?times= -> JSON response
asio::awaitable<void> hello(Ctx& ctx) {
    const int times = positiveQuery(ctx, "times", 1);
    json::array greets;
    for (int i = 0; i < times; ++i)
        greets.push_back(("Hello, " + ctx.params.at("name") + "!").c_str());
    ctx.json(200, json::object{{"greets", std::move(greets)}});
    co_return;
}

// JSON body echo (the framework already parsed valid JSON into ctx.body;
// invalid JSON never reaches the handler)
asio::awaitable<void> echo(Ctx& ctx) {
    if (ctx.body.is_null()) throwHttp(400, "JSON body required");
    ctx.json(200, json::object{{"you_sent", ctx.body}});
    co_return;
}

// Cookie read/write: a visit counter
asio::awaitable<void> visit(Ctx& ctx) {
    int n = 1;
    if (auto v = ctx.cookie("visits")) n = std::stoi(*v) + 1;
    ctx.setCookie("visits", std::to_string(n), "/", 3600);
    ctx.json(200, json::object{{"visit_no", n}});
    co_return;
}

// SSE: beginSse enters self-write mode (respond=false: the framework writes
// nothing back and provides no error fallback)
asio::awaitable<void> events(Ctx& ctx) {
    co_await ctx.beginSse();
    for (int i = 1; i <= 5; ++i) {
        asio::steady_timer t(co_await asio::this_coro::executor);
        t.expires_after(std::chrono::milliseconds(300));
        co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
        co_await ctx.writeChunk("data: " + json::serialize(json::object{{"tick", i}}) + "\n\n");
    }
    co_await ctx.endStream(); // last-chunk finish (keeps the connection by default)
    co_return;
}

// Business error demo: throw HttpError; the central error handler turns it
// into JSON (expose=false would show only "Internal error")
asio::awaitable<void> fail(Ctx& ctx) {
    (void)ctx;
    throwHttp(418, "I'm a teapot");
}

// Outbound request: HttpClient GET on this server's own endpoint, then
// relay (buffered API; 4xx/5xx do not throw)
asio::awaitable<void> fetch(Ctx& ctx, const std::shared_ptr<DemoApp>& app) {
    std::string path = "/hello/world";
    if (auto it = ctx.query.find("path"); it != ctx.query.end() && !it->second.empty())
        path = it->second;
    auto res = co_await app->http.get(app->selfBase + path);
    ctx.res.result(res.result()); // hop-by-hop/framing headers already stripped; safe to forward
    if (auto ct = res.find(http::field::content_type); ct != res.end())
        ctx.res.set(http::field::content_type, std::string(ct->value()));
    ctx.res.body() = std::move(res.body());
    co_return;
}

void registerDemoRoutes(Router& router, const std::shared_ptr<DemoApp>& app) {
    router.add(http::verb::get, "/hello/:name", hello);
    router.add(http::verb::post, "/echo", echo);
    router.add(http::verb::get, "/visit", visit);
    router.add(http::verb::get, "/events", events);
    router.add(http::verb::get, "/fail", fail);
    router.add(http::verb::get, "/fetch",
               [app](Ctx& ctx) -> asio::awaitable<void> { co_await fetch(ctx, app); });
}

} // namespace

int main() {
    try {
        unsigned short port = kPort;
        if (const char* env = std::getenv("PORT")) {
            int p = std::atoi(env);
            if (p > 0 && p < 65536) port = (unsigned short)p;
        }

        Router router; // routing table: read-only after registration
        auto app = std::make_shared<DemoApp>();
        registerDemoRoutes(router, app);

        asio::io_context ioc; // single-threaded event loop (Node semantics: stores need no locks)
        asio::ip::tcp::acceptor acceptor(ioc, {asio::ip::make_address("127.0.0.1"), port});
        app->selfBase = "http://127.0.0.1:" + std::to_string(acceptor.local_endpoint().port());

        // listen() takes config by reference and the awaitable is lazy: the
        // referenced object must outlive ioc.run(). A temporary (HttpConfig{})
        // dies with the co_spawn full-expression and dangles inside the
        // coroutine frame - that crashed on GCC/Linux while silently passing
        // on Windows/clang
        HttpConfig cfg;
        asio::co_spawn(ioc, listen(std::move(acceptor), router, cfg), asio::detached);

        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&ioc](const boost::system::error_code&, int sig) {
            std::cout << "received signal " << sig << ", shutting down" << '\n';
            ioc.stop();
        });

        std::cout << "corokit demo listening on " << app->selfBase << '\n'
                  << "  curl \"" << app->selfBase << "/hello/world?times=3\"" << '\n'
                  << "  curl -X POST " << app->selfBase << "/echo"
                  << " -H 'content-type: application/json' -d '{\"a\":1}'" << '\n'
                  << "  curl -i " << app->selfBase << "/visit" << '\n'
                  << "  curl -N " << app->selfBase << "/events" << '\n'
                  << "  curl \"" << app->selfBase << "/fetch?path=/hello/world\"" << '\n'
                  << "  curl -i " << app->selfBase << "/fail" << '\n';
        ioc.run();
    } catch (const std::exception& e) {
        // Exception exits must not throw again: ostream operations are
        // considered throwing (exception-escape), so use C stdio
        fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    } catch (...) {
        fputs("fatal: unknown exception\n", stderr);
        return 1;
    }
    return 0;
}
