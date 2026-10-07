// HTTP framework unit tests: Router matching/params/405 Allow; Ctx cookies
// and JSON responses. Calls the implementation functions directly, no
// listening socket (a behavioral parity baseline against the Node original)

#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <boost/beast.hpp>

#include "http.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace json = boost::json;

namespace {

Handler noopHandler() {
    return [](Ctx&) -> asio::awaitable<void> { co_return; };
}

Router makeRouter() {
    Router r;
    r.add(http::verb::get, "/api/count", noopHandler());
    r.add(http::verb::get, "/api/user/:name", noopHandler());
    r.add(http::verb::post, "/api/user/:name/ping", noopHandler());
    return r;
}

} // namespace

TEST(Router, ExactMatch) {
    Router r = makeRouter();
    std::string allow;
    auto m = r.match(http::verb::get, {"api", "count"}, allow);
    ASSERT_TRUE(m.has_value());
    EXPECT_TRUE(m->params.empty());
}

TEST(Router, ParamExtraction) {
    Router r = makeRouter();
    std::string allow;
    auto m = r.match(http::verb::get, {"api", "user", "Alice"}, allow);
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->params.at("name"), "Alice");

    auto mp = r.match(http::verb::post, {"api", "user", "bob", "ping"}, allow);
    ASSERT_TRUE(mp.has_value());
    EXPECT_EQ(mp->params.at("name"), "bob");
}

TEST(Router, TrailingSlashTolerated) {
    // a trailing slash becomes a trailing empty segment, treated as absent
    // (see the match comment)
    Router r = makeRouter();
    std::string allow;
    auto m = r.match(http::verb::get, {"api", "count", ""}, allow);
    EXPECT_TRUE(m.has_value());
}

TEST(Router, MissReturnsNullopt) {
    Router r = makeRouter();
    std::string allow;
    auto m = r.match(http::verb::get, {"no", "such"}, allow);
    EXPECT_FALSE(m.has_value());
}

TEST(Router, MethodMismatchYieldsAllowHeader) {
    // registering GET also serves HEAD; joined in descending order (matches
    // @koa/router's sort().reverse())
    Router r = makeRouter();
    std::string allow;
    auto m = r.match(http::verb::post, {"api", "count"}, allow);
    EXPECT_FALSE(m.has_value());
    EXPECT_EQ(allow, "HEAD, GET");
}

TEST(Router, WildcardTailMatchesZeroOrMore) {
    Router r;
    r.add(http::verb::get, "/files/*", noopHandler());
    std::string allow;
    auto zero = r.match(http::verb::get, {"files"}, allow); // zero segments
    ASSERT_TRUE(zero.has_value());
    EXPECT_TRUE(zero->params.empty());
    auto deep = r.match(http::verb::get, {"files", "a", "b", "c"}, allow); // any depth
    EXPECT_TRUE(deep.has_value());
}

TEST(CtxCookie, ParseAndMissing) {
    Ctx ctx;
    ctx.req.set(http::field::cookie, "a=1; b=x=y; c=3");
    EXPECT_EQ(ctx.cookie("a"), std::optional<std::string>("1"));
    EXPECT_EQ(ctx.cookie("b"), std::optional<std::string>("x=y")); // value containing '=': split at the first '='
    EXPECT_EQ(ctx.cookie("c"), std::optional<std::string>("3"));
    EXPECT_FALSE(ctx.cookie("d").has_value());
}

TEST(CtxCookie, AbsentHeader) {
    Ctx ctx;
    EXPECT_FALSE(ctx.cookie("anything").has_value());
}

TEST(CtxSetCookie, WithMaxAge) {
    Ctx ctx;
    ctx.setCookie("sid", "S3CR3T", "/", 60);
    auto it = ctx.res.find(http::field::set_cookie);
    ASSERT_NE(it, ctx.res.end());
    EXPECT_EQ(it->value(), "sid=S3CR3T; Path=/; Max-Age=60; SameSite=Lax; HttpOnly");
}

TEST(CtxSetCookie, ClearWithoutMaxAge) {
    // a missing maxAge -> Max-Age=0, the clear semantics (matching the Node
    // cookies library contract)
    Ctx ctx;
    ctx.setCookie("sid", "", "/", std::nullopt);
    EXPECT_EQ(ctx.res.find(http::field::set_cookie)->value(), "sid=; Path=/; Max-Age=0");
}

TEST(CtxSetCookie, UntrustedForwardedHttpsDoesNotSetSecure) {
    Ctx ctx; // no trusted peer info: a forwarded header alone must not enable Secure
    ctx.req.set("X-Forwarded-Proto", "https");
    ctx.setCookie("sid", "test", "/", 60);
    EXPECT_EQ(ctx.res[http::field::set_cookie],
              "sid=test; Path=/; Max-Age=60; SameSite=Lax; HttpOnly");
}

TEST(CtxSetCookie, LoopbackProxyControlsSecureForSetAndClear) {
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor(ioc, {asio::ip::address_v4::loopback(), 0});
    asio::ip::tcp::socket client(ioc);
    client.connect(acceptor.local_endpoint());
    beast::tcp_stream stream(acceptor.accept());
    Ctx ctx;
    ctx.sock = &stream;
    ctx.req.set("X-Forwarded-Proto", "https");
    ctx.setCookie("sid", "test", "/", 60);
    EXPECT_EQ(ctx.res[http::field::set_cookie],
              "sid=test; Path=/; Max-Age=60; SameSite=Lax; HttpOnly; Secure");
    ctx.res.erase(http::field::set_cookie);
    ctx.setCookie("sid", "", "/", std::nullopt);
    EXPECT_EQ(ctx.res[http::field::set_cookie], "sid=; Path=/; Max-Age=0; Secure");
    ctx.res.erase(http::field::set_cookie);
    ctx.req.set("X-Forwarded-Proto", "http");
    ctx.setCookie("sid", "test", "/", 60);
    EXPECT_EQ(ctx.res[http::field::set_cookie],
              "sid=test; Path=/; Max-Age=60; SameSite=Lax; HttpOnly");
}

TEST(CtxSetCookie, MultipleCookies) {
    Ctx ctx;
    ctx.setCookie("a", "1", "/", std::nullopt);
    ctx.setCookie("b", "2", "/", std::nullopt);
    auto [b, e] = ctx.res.equal_range(http::field::set_cookie);
    EXPECT_EQ(std::distance(b, e), 2);
}

TEST(CtxJson, SetsStatusContentTypeBody) {
    Ctx ctx;
    json::object o;
    o["ok"] = true;
    ctx.json(201, o);
    EXPECT_EQ(ctx.res.result_int(), 201);
    EXPECT_EQ(ctx.res[http::field::content_type], "application/json; charset=utf-8");
    EXPECT_EQ(ctx.res.body(), R"({"ok":true})");
}
