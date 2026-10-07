// Consumer-side minimal business service: the business repo carries only
// business code - the shared modules (http framework / http client / jwt /
// sqlite / openssl / b64) all come from coro-kit, with the same includes
// and link setup as when the sources were vendored (the flat header layout
// is exposed through corokit's PUBLIC include path).
//
// curl "http://127.0.0.1:18081/hello/world"               route param + JSON
// curl "http://127.0.0.1:18081/fetch?path=/hello/world"   outbound client self-fetch
// curl -N  http://127.0.0.1:18081/events                  SSE

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "http.hpp"
#include "http_client.hpp"

namespace {

constexpr unsigned short kPort = 18081;

// Application assembly context (App pattern: make_shared shared ownership,
// handlers capture a copy)
struct ConsumerApp {
    HttpClient http;      // outbound client (a coro-kit module, movable via PIMPL)
    std::string selfBase; // self-fetch baseUrl
};

asio::awaitable<void> hello(Ctx& ctx) {
    ctx.json(200, json::object{{"hello", ctx.params.at("name")},
                               {"from", "corokit-consumer"}});
    co_return;
}

asio::awaitable<void> events(Ctx& ctx) {
    co_await ctx.beginSse();
    for (int i = 1; i <= 3; ++i) {
        asio::steady_timer t(co_await asio::this_coro::executor);
        t.expires_after(std::chrono::milliseconds(300));
        co_await t.async_wait(asio::as_tuple(asio::use_awaitable));
        co_await ctx.writeChunk("data: " + json::serialize(json::object{{"tick", i}}) + "\n\n");
    }
    co_await ctx.endStream();
    co_return;
}

asio::awaitable<void> fetch(Ctx& ctx, const std::shared_ptr<ConsumerApp>& app) {
    std::string path = "/hello/world";
    if (auto it = ctx.query.find("path"); it != ctx.query.end() && !it->second.empty())
        path = it->second;
    auto res = co_await app->http.get(app->selfBase + path);
    ctx.res.result(res.result());
    if (auto ct = res.find(http::field::content_type); ct != res.end())
        ctx.res.set(http::field::content_type, std::string(ct->value()));
    ctx.res.body() = std::move(res.body());
    co_return;
}

} // namespace

int main() {
    try {
        Router router;
        auto app = std::make_shared<ConsumerApp>();
        router.add(http::verb::get, "/hello/:name", hello);
        router.add(http::verb::get, "/events", events);
        router.add(http::verb::get, "/fetch",
                   [app](Ctx& ctx) -> asio::awaitable<void> { co_await fetch(ctx, app); });

        asio::io_context ioc;
        asio::ip::tcp::acceptor acceptor(ioc, {asio::ip::make_address("127.0.0.1"), kPort});
        app->selfBase = "http://127.0.0.1:" + std::to_string(acceptor.local_endpoint().port());
        asio::co_spawn(ioc, listen(std::move(acceptor), router, HttpConfig{}), asio::detached);

        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&ioc](const boost::system::error_code&, int sig) {
            std::cout << "received signal " << sig << ", shutting down" << '\n';
            ioc.stop();
        });

        std::cout << "consumer listening on " << app->selfBase << '\n';
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
