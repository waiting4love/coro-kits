# coro-kit

C++20 协程 Web 工具箱：**类 Koa 的 HTTP 服务框架**、**出站 HTTP/HTTPS 客户端**，
以及 JWT 验签、SQLite / OpenSSL 的 RAII 封装。

源自三个生产服务（API 计数限流、OpenAI 代理、软件授权管理）沉淀下来的共享模块。
全部模块从 Node.js 服务重写而来，行为语义刻意与 Node 生态对齐（Koa 的
ctx/router、jsonwebtoken 的错误分类、Buffer.from 的宽容 base64）。

- 单线程 `io_context` 事件循环，业务 handler 全协程——心智模型与 Node 完全一致
- 一个模块一对文件（`xxx.hpp` + 可选 `xxx.cpp`），FetchContent 下来即可使用
- **零依赖钉死**：库本体不定死 Boost 版本、LibreSSL 还是 OpenSSL、SQLite 版本——
  依赖由使用方按自己的工程决定，库只认 CMake target 约定（见下文）

## 模块一览

| 模块 | 组件 | 文件 | 职责 |
|---|---|---|---|
| HTTP 服务框架 | `corokit::http_srv` | `http_srv.hpp/.cpp`、`http_config.hpp`、`error.hpp` | 监听、路由（静态段 / `:param` / `*` 尾通配）、405+Allow、静态资源 + SPA fallback、Cookie、SSE 流式响应、中央错误处理 → JSON、CORS 预检 |
| 出站 HTTP 客户端 | `corokit::http_client` | `http_client.hpp/.cpp` | 缓冲式 `get/post/put/del/request` + 流式 `exchange`（handler 接口）；TLS（SNI、证书链与 DNS/IP 身份验证）、两级超时（建连预算 + 总时长硬顶 + body 滚动空闲）、PIMPL 可移动 |
| JWT | `corokit::jwt` | `jwt.hpp/.cpp` | RS256 验签 / 签发；`TokenExpiredError` / `NotBeforeError` / `JsonWebTokenError` 错误名与 [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) 对齐 |
| OpenSSL RAII | `corokit::openssl` | `openssl.hpp/.cpp` | `openssl::Key`（EVP_PKEY 统一层）、`signRsaSha256/verifyRsaSha256`、PKCS#1 v1.5 分块加解密、`randomBytes`；业务代码不触碰裸 C API |
| SQLite RAII | `corokit::sqlite` | `sqlite.hpp/.cpp` | `Db` / `Statement` / `Transaction`；语句一次 prepare 长期复用、事务不显式 commit 析构即回滚、约束冲突抛 `ConstraintError` 子类 |
| .NET 密钥加载 | `corokit::key_loader` | `key_loader.hpp/.cpp` | `RSAKeyValue` XML（`RSACryptoServiceProvider.ToXmlString()` 格式）→ `openssl::Key` |
| base64 | `corokit::b64` | `b64.hpp` | 标准 / base64url 双字母表；解码宽容（忽略空白与缺失填充，对齐 Node `Buffer.from`） |

`error.hpp` / `http_config.hpp` 随 `corokit::http_srv` 提供；另有伞目标
`corokit::corokit`（等于全部选中组件）。

## 在你的工程中引入

```cmake
include(FetchContent)
# ……先按你工程自己的方式备好所选组件的依赖（版本来源完全由你定），然后：
set(COROKIT_INCLUDE_LIBRARIES "http_srv" "http_client")  # 可选：只引所需组件（缺省=全部）
FetchContent_Declare(corokit
  GIT_REPOSITORY https://github.com/<you>/coro-kit.git
  GIT_TAG        v0.2.0)
FetchContent_MakeAvailable(corokit)
target_link_libraries(your-app PRIVATE corokit::http_client)  # 按需链组件，或用伞目标
```

**组件选择对齐 Boost 的 `BOOST_INCLUDE_LIBRARIES`**：引入前设置
`COROKIT_INCLUDE_LIBRARIES` 即可，选择会自动展开到传递闭包（如 `jwt` 自带
`key_loader`、`openssl`）；未知组件名直接报错并列出合法值。各组件与额外依赖：

| 组件 | 额外依赖 |
|---|---|
| `corokit::b64` | 无（header-only） |
| `corokit::openssl` | OpenSSL/LibreSSL ≥ 1.1 |
| `corokit::sqlite` | SQLite ≥ 3.37 |
| `corokit::key_loader` | `corokit::openssl` |
| `corokit::jwt` | `corokit::key_loader`、Boost::json |
| `corokit::http_srv` | Boost（asio/beast/json/url）、Threads |
| `corokit::http_client` | `corokit::http_srv`、OpenSSL（上游 TLS） |
| `corokit::corokit` | 伞目标：全部选中组件 |

**依赖解析是懒的**：只有至少一个选中组件需要某依赖时才会探测它——只引
`corokit::sqlite` 的工程完全不需要装 Boost 与 OpenSSL，反之只引 http 组件的
工程不需要 SQLite。

**依赖约定**：库被引入时，若下列 target 已存在则直接复用；不存在才回退系统
`find_package`——所以"你工程里已有的"就是"coro-kit 用的"：

版本过低会在 configure 期得到一条说明原因与出路的 FATAL_ERROR（Boost
版本从 `Boost_VERSION` 变量、超级项目变量或 `boost/version.hpp` 三处探
测，别名/预编译场景也覆盖）；源码里另有 static_assert 兜底（`http_srv.hpp` /
`openssl.cpp` / `sqlite.cpp`），对所有供依赖方式权威。探测到版本时
configure 输出一行 `coro-kit: Boost x.y (floor 1.81)` 供确认。

| 库需要的 target | 回退解析 | 说明 |
|---|---|---|
| `OpenSSL::SSL` / `OpenSSL::Crypto` | `find_package(OpenSSL)` | **OpenSSL 与 LibreSSL 均可**（均须 ≥ 1.1，opaque RSA API）；走 LibreSSL 的工程自建这对别名即可（`examples/consumer` 有先例） |
| `Boost::json`（http 组件另需 `Boost::url`） | `find_package(Boost COMPONENTS ...)` | ≥ 1.81（Boost.URL 引入线），已测 1.83 与 1.87；url 是编译库（非 header-only），超级项目 FetchContent 与系统安装皆可 |
| `SQLite::SQLite3` 或 `sqlite3` | `find_package(SQLite3)` | ≥ 3.37（`sqlite3_changes64`）；amalgamation 自建 target（名字 `sqlite3`）或系统安装皆可 |

被 FetchContent 引入时 demo / 单测默认**不构建**（`COROKIT_BUILD_DEMO` /
`COROKIT_BUILD_TESTS` 默认 OFF，仅顶层构建为 ON），对使用方零负担。

两个跨工程注意点：

- **Linux io_uring**：若你的工程启用 `BOOST_ASIO_HAS_IO_URING`，须在引入
  coro-kit **之前**全局定义（Asio 配置宏必须全工程一致，否则 ODR 违规），并在
  最终可执行目标链接 `uring`；或把 `COROKIT_ENABLE_IO_URING` 置 ON（本库自行
  定义并链接）
- **Windows + clang/lld-link**：链接 LibreSSL 的工程需要给最终目标补
  `oldnames`（cl.exe 自动链、CMake+clang 不带）；系统 OpenSSL 无此问题

`examples/consumer` 是一个完整可编译的消费样例：自钉一套依赖版本（LibreSSL
4.1.0 / Boost 1.87.0）、`COROKIT_INCLUDE_LIBRARIES` 只选 http 组件（**本机
无需安装 SQLite**）+ FetchContent 引入 coro-kit + 一个纯业务视角的小服务
——**它同时就是"业务仓库删除公共模块后切换到 coro-kit"的迁移模板**。

### 从"仓库内携带公共模块"迁移到 FetchContent

以 public-services 三仓为例，每个仓库的切换步骤：

1. 删除本仓 `cpp/src/` 下的公共模块文件（`http_srv.*`（原 `http.*`）、
   `http_config.hpp`、`error.hpp`、`b64.hpp`、`key_loader.*`、`sqlite.*`、
   `openssl.*`、`jwt.*`、`http_client.*`）及对应测试（`test_b64/test_http_srv/
   test_key_loader/test_jwt/test_http_client` 与测试密钥）
2. `CMakeLists.txt` 里加 `set(COROKIT_INCLUDE_LIBRARIES ...)` 按需选组件 +
   `FetchContent_Declare(corokit GIT_REPOSITORY …)` + `MakeAvailable`（放在
   自备依赖块之后——库检测到 `OpenSSL::*` 别名、`Boost::json`、`sqlite3`
   已存在即直接复用，零重复构建；未选中的组件连依赖都不要求）
3. 业务目标源列表去掉公共模块的 .cpp，链接改为所用组件（如
   `corokit::http_srv corokit::http_client`，或图省事链 `corokit::corokit`）
4. 业务代码仅改 include 的模块名：`#include "http.hpp"` → `"http_srv.hpp"`，
   其余头文件名与 flat 布局经各组件的 PUBLIC include 原样透出
5. 既有依赖钉版块原样保留——版本决定权在你手里，coro-kit 不参与

## 顶层独立构建与测试

克隆本仓库直接构建时，依赖走系统 `find_package`（OpenSSL / Boost(json) /
SQLite3 需已安装，或经 vcpkg / conan 等注入）：

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

```bash
# Windows + LLVM clang（Ninja）
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
```

本机没有系统级依赖时，用 `examples/consumer` 验证 FetchContent 路径（http
组件自备依赖，无需 SQLite）：

```bash
cmake -S examples/consumer -B build/verify
cmake --build build/verify
./build/verify/consumer                  # 消费样例服务
```

组件选择本身也可以直接验证（懒依赖：未选组件不触发任何 find_package）：

```bash
cmake -S . -B build-sqliteonly -DCOROKIT_BUILD_DEMO=OFF -DCOROKIT_BUILD_TESTS=OFF \
      -DCOROKIT_INCLUDE_LIBRARIES=sqlite   # 只需系统 SQLite，无需 Boost/OpenSSL
cmake --build build-sqliteonly
```

测试框架（GoogleTest）仅 `COROKIT_BUILD_TESTS=ON` 时获取，且优先复用系统的
`find_package(GTest CONFIG)`——不影响库本身的依赖面。

## demo

`demo/main.cpp` 一站式演示全部模块能力（约 150 行，值得一读），顶层构建时产出：

```bash
cmake --build build --target demo
./build/demo            # 默认 127.0.0.1:18080，PORT 环境变量可覆盖
```

```bash
curl "http://127.0.0.1:18080/hello/world?times=3"     # 路由参数 + query + JSON 响应
curl -X POST http://127.0.0.1:18080/echo \
     -H 'content-type: application/json' -d '{"a":1}' # JSON body 解析回显
curl -i  http://127.0.0.1:18080/visit                 # Cookie 读/写（访问计数）
curl -N  http://127.0.0.1:18080/events                # SSE 流式响应
curl "http://127.0.0.1:18080/fetch?path=/hello/world" # 服务端出站请求自访
curl -i  http://127.0.0.1:18080/fail                  # HttpError → JSON（418）
curl -i  http://127.0.0.1:18080/nope                  # 404（中央错误处理）
curl -i -X POST http://127.0.0.1:18080/hello/world    # 405 + Allow: HEAD, GET
```

## 快速上手

### 服务端（类 Koa）

```cpp
#include "http_srv.hpp"   // 链接 corokit::http_srv

asio::awaitable<void> hello(Ctx& ctx) {
    ctx.json(200, json::object{{"hello", ctx.params.at("name")}});
    co_return;
}

int main() {
    Router router;
    router.add(http::verb::get, "/hello/:name", hello);

    HttpConfig cfg; // basePath / staticDir / CORS 按需填充
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor(ioc, {asio::ip::make_address("0.0.0.0"), 3000});
    asio::co_spawn(ioc, listen(std::move(acceptor), router, cfg), asio::detached);
    ioc.run();
}
```

handler 里可以：读路由参数 `ctx.params`、query `ctx.query`、解析后的 JSON body
`ctx.body`；写响应 `ctx.json(status, value)`、`ctx.setCookie(...)`；长响应走
`ctx.beginSse()` → `ctx.writeChunk(...)` → `ctx.endStream()` 自写流。抛
`throwHttp(status, msg)` 即由中央错误处理转 JSON；`respond=false` 时 handler
全权接管写回。

### 出站 HTTP 客户端

```cpp
HttpClient http; // PIMPL 可移动；协程帧持有稳定的 Impl*，实例须活过在飞请求
http.setConnectTimeout(std::chrono::seconds(10));
http.setTotalCap(std::chrono::seconds(60));

auto res = co_await http.get("https://example.com/api");
// 4xx/5xx 不抛：状态码原样，业务自判
// 传输/超时故障抛 HttpError：502（上游故障）/ 504（超时）
// 返回的响应已剥逐跳/定界头，转发复用安全
```

流式（SSE 透传等）实现 `HttpClient::ExchangeHandler` 接口——`onHeader` 在响应头
到达时调用（返回 body 阶段的滚动空闲超时），`onBody` 逐块回调：

```cpp
struct Relay : HttpClient::ExchangeHandler {
    Ctx& ctx;
    asio::awaitable<std::optional<std::chrono::milliseconds>>
    onHeader(http::response_parser<http::buffer_body>& p) override {
        co_await ctx.beginSse((int)p.get().result_int());
        co_return std::chrono::milliseconds(15000); // nullopt = 不限空闲
    }
    asio::awaitable<void> onBody(const char* data, size_t n) override {
        co_await ctx.writeChunk(std::string_view(data, n));
        co_return;
    }
};
```

### JWT 验签

```cpp
auto pub = loadPublicEvpKeyFromXml("public-key.xml");
try {
    auto payload = verifyJwt(token, pub, "my-issuer", "my-audience");
} catch (const JwtVerifyError& e) {
    // e.name == "TokenExpiredError" / "NotBeforeError" / "JsonWebTokenError"
}
```

### SQLite

```cpp
sqlite::Db db("app.db");
db.exec("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)");

sqlite::Statement put = db.prepare("INSERT OR REPLACE INTO kv VALUES (?, ?)");
put.bind(1, "lang").bind(2, "C++").run();

sqlite::Statement get = db.prepare("SELECT v FROM kv WHERE k = ?");
if (get.bind(1, "lang").step()) std::cout << get.text(0) << '\n';

sqlite::Transaction tx = db.begin(); // 不显式 commit，析构自动回滚（异常安全）
// ……多条写……
tx.commit();
```

### OpenSSL

```cpp
std::string sig = openssl::signRsaSha256(privKey, "data");
bool ok = openssl::verifyRsaSha256(pubKey, "data", sig); // 验签失败返回 false，不抛
std::string sid = openssl::randomBytes(16);              // 会话号统一走它
```

## 设计要点

- **单线程事件循环**：整个服务跑在一个 `io_context` 上（对齐 Node 事件循环语义），
  store 层直调不加锁；协程运行期经 `this_coro::executor` 取执行器，无跨 loop 引用
- **所有权即文档**：业务对象 `make_shared` 装配、handler 捕获副本；`HttpClient`
  经 PIMPL 可移动（在飞协程持有稳定的 `Impl*`）；所有 RAII 类型可移动不可拷贝
- **RAII 红线**：业务代码不出现裸 `sqlite3_*` / `EVP_*` / RSA 装配 API，全部经
  封装；错误一律抛异常（`sqlite::Error`、`openssl::Error`、`HttpError`）
- **超时模型对齐 AbortController**：建连+首字节一个预算、body 滚动空闲超时、
  总时长硬顶看门狗强拆——三种挂法（上游死挂、客户端零窗口、慢生成）都有兜底
- **对 Node 的行为对拍**：路由 405 的 Allow 排序、cookie 序列化、JWT 错误分类、
  base64 宽容解码等，均以 Node 版实现为基线写测试

## 目录结构

```
coro-kit/
├── CMakeLists.txt            # 组件化（COROKIT_INCLUDE_LIBRARIES）+ 懒依赖解析 + 版本底线
├── src/                      # 全部模块（flat 布局，按组件分组，互相以 "xxx.hpp" 引用）
├── demo/main.cpp             # 一站式演示：服务端 + SSE + Cookie + 出站客户端
├── test/                     # gtest 单测 + 仅测试用的 1024 位 RSA 密钥（keys/）
└── examples/consumer/        # 消费样例 = 迁移模板（只选 http 组件，无需 SQLite）
```

## 测试

```bash
ctest --test-dir build --output-on-failure
```

覆盖：路由匹配/参数/405、Cookie 序列化、base64 RFC 4648 向量与宽容解码、
JWT 全错误分类（含算法混淆/篡改签名）、.NET XML 密钥加载、出站客户端的
缓冲式/流式路径、TLS 链路（SNI/证书验证/失败关闭）、超时与内存护栏、
以及"请求在飞时移动 HttpClient 外壳"的可移动性验证。

## 来源与同步

本库的模块同时服务于三个生产服务：counter-services（API 计数/限流）、
ai-proxy-node（OpenAI 兼容代理）与 authman-node（软件授权管理）。当前各仓库
以字节一致（md5 相同）的方式携带同模块；后续按上文"迁移指引"逐仓切换为
FetchContent 引入后，本库成为唯一上游。

## License

MIT（见 [LICENSE](LICENSE)）——使用、修改、分发、再许可均无限制，仅保留版权与许可声明一行。
