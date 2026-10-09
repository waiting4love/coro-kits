# coro-kit — Agent Guide

coro-kit is a C++20 coroutine web toolkit extracted from three production
services: a Koa-style HTTP server framework, an outbound HTTP/HTTPS client,
JWT (RS256) verification, and RAII wrappers for SQLite and OpenSSL. It is
meant to be open-sourced on GitHub.

## Language rules (important)

- Code comments: English only, concise, only where necessary. No Chinese.
- Error messages, log/print messages: English.
- Git commit messages: English, style `type(scope): summary`
  (feat / fix / refactor / build / test / docs).
- `README.md` is currently Chinese — that is deliberate; do not translate it
  unless asked.

## Layout

```
CMakeLists.txt       # components + lazy dependency resolution + version floors
src/                 # all modules, flat layout, included as "xxx.hpp"
demo/main.cpp        # all-in-one demo (top-level builds only; http components)
test/                # gtest unit tests + test-only 1024-bit RSA keys in test/keys/
examples/consumer/   # consumer sample = migration template: pins LibreSSL + Boost,
                     # selects only the http components (no SQLite needed)
```

Components (Boost-style; consumers set `COROKIT_INCLUDE_LIBRARIES` before
pulling this project in, unset/empty = all): `b64` (header-only), `openssl`,
`sqlite`, `key_loader` (-> openssl), `jwt` (-> openssl + b64 + Boost.json;
.NET XML key loading is the consumer's concern - link key_loader and include
key_loader.hpp explicitly), `http_srv` (src/http_srv.hpp/.cpp +
http_config.hpp + error.hpp), `http_client` (-> Boost.url + OpenSSL for
upstream TLS; header-only error.hpp resolves via the shared src include dir),
plus the `corokit::corokit` umbrella.
Dependency resolution is lazy per component: a sqlite-only consumer never
triggers Boost/OpenSSL lookups. Note the module was renamed http -> http_srv
(headers included as "http_srv.hpp").

## Dependency policy (do not break this)

The library pins **no** third-party dependency. Boost / OpenSSL-or-LibreSSL
/ SQLite versions and sources are the consumer's choice. The CMake contract:
reuse `OpenSSL::SSL`/`OpenSSL::Crypto`, `Boost::json`, `Boost::headers`,
`SQLite::SQLite3` (or `sqlite3`) if those targets already exist, otherwise
fall back to `find_package`. Details and gotchas:

- Inside a Boost superproject build `Boost::headers` is an empty
  pseudo-library — include dirs live on the per-module targets (wrapped in
  BUILD_INTERFACE generator expressions; boost/version.hpp belongs to the
  config module). The CMake aggregates `Boost::asio/beast/json/url` when
  they exist. Keep this logic.
- Version floors: OpenSSL 1.1 / SQLite 3.37 as configure-time
  FATAL_ERRORs; the Boost 1.81 floor is compile-time only (static_assert in
  src/http_srv.hpp) - configure-time Boost probing was deliberately removed,
  the version sources across provisioning shapes were not worth it. The
  static_asserts in src/http_srv.hpp, src/openssl.cpp and src/sqlite.cpp are
  authoritative for every provisioning path.
- demo/tests default OFF when consumed as a subproject (`PROJECT_IS_TOP_LEVEL`).
- GoogleTest is only fetched under `COROKIT_BUILD_TESTS=ON` (system
  `find_package(GTest CONFIG)` preferred; it forces all components).

## Build & test (this machine: Windows, LLVM clang + Ninja + Git Bash)

This machine has no system OpenSSL/Boost/SQLite, so a top-level configure
cannot resolve all dependencies. Verify the FetchContent path via the
consumer example (http components only - Boost + LibreSSL redirections
suffice, no SQLite/gtest needed):

```bash
cd coro-kit
D="<abs path to some built sibling>/cpp/build/_deps"
cmake -S examples/consumer -B build/verify -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DFETCHCONTENT_SOURCE_DIR_BOOST="$D/boost-src" \
  -DFETCHCONTENT_SOURCE_DIR_LIBRESSL="$D/libressl-src"
cmake --build build/verify
./build/verify/consumer   # default port 18081
```

The full test suite runs on WSL (see below). On machines with system deps, a
plain `cmake -S . -B build && cmake --build build && ctest --test-dir build`
works (find_package path).

### WSL (Ubuntu-24) — the find_package path on this host

The Windows host has no system OpenSSL/Boost/SQLite, but WSL does after
installing packages (as root; `wsl -d Ubuntu-24 -u root` needs no password):

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake \
  ninja-build libboost-dev libboost-json-dev libboost-url-dev \
  libssl-dev libsqlite3-dev libgtest-dev pkg-config
```

Ubuntu 24.04 provides GCC 13, CMake 3.28, Boost 1.83, OpenSSL 3.0,
SQLite 3.45. Build as the default user (faster than /mnt/d):

```bash
tar --exclude=./build -cf - . | (cd ~/corokit && tar -xf -)
cd ~/corokit && cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build
# 47 tests expected (the suite forces all components)
```
The opt-in live-network case (real TLS against mirrors.tuna.tsinghua.edu.cn;
CN-reachable, handshake-friendly) runs with -DCOROKIT_LIVE_TESTS=ON; the
default suite stays hermetic. Two gotchas learned there: asio poll() marks
the context stopped once all work drains - a second drive on the same
io_context needs ioc.restart() first; and Windows+LibreSSL needs
SSL_CERT_FILE pointing at a CA bundle for live verification.

WSL also proves the lazy-dependency property of component selection: a
`-DCOROKIT_INCLUDE_LIBRARIES=sqlite` configure resolves no Boost/OpenSSL at
all.

Git Bash gotchas: prefix wsl.exe calls with `MSYS_NO_PATHCONV=1` (it rewrites
/mnt/... paths), and never `pkill -f <pattern>` where the pattern occurs in
the calling command line (it kills the caller's own shell).

## Engineering red lines (C++20 coroutines, single-threaded io_context)

- Everything runs on one `io_context` (Node event-loop semantics): stores
  are called directly without locks; coroutines take the executor via
  `this_coro::executor` — never capture/store an executor or io_context.
- No `co_await` inside a `catch` handler on this toolchain (clang/MSVC-ABI:
  a bare rethrow crashes in SEH dispatch). Use `asio::as_tuple` to receive
  errors as values, or stash an `exception_ptr` and rethrow after the catch.
- Error style for asio ops: plain `use_awaitable` already throws
  `system_error` on error completion - use it whenever the error would be
  thrown anyway. Reserve `as_tuple(use_awaitable)` for errors handled as
  VALUES (eof-with-bytes convention, http body_limit side path, acceptor
  operation_aborted shutdown, timers whose cancellation is ignored).
- Coroutine-lambda closures are not copied into frames: name them and keep
  them alive until the coroutine finishes.
- Reference arguments to lazy coroutines (anything returning asio::awaitable)
  must point at objects that outlive `ioc.run()` - never pass temporaries.
  `listen(..., HttpConfig{})` dangles inside the coroutine frame; it
  segfaulted on GCC/Linux while silently passing on Windows/clang.
- asio has no default-constructed executors: a `steady_timer` member built
  from an empty `any_io_executor` constructs "successfully" and then throws
  `bad_executor` on first use (far from the construction site). Use
  `std::optional<steady_timer>` and emplace once the executor is known
  (HttpClient's Session does this).
- `asio::awaitable<T&>` is not representable (the machinery does `new T&`).
  Coroutine results that are references must travel as pointers.
- `HttpStream` (src/http_client.hpp) is the single pump: the buffered API
  runs over Session::head/chunk. Do not add a second body-pump
  implementation. (The exchange()/ExchangeHandler callback API was removed
  on the httpstream-only branch; the pull object replaces it.) Chunk views from `getChunk()` are valid
  until the next call - data that must survive goes through the
  caller-buffer overload `getChunk(char*, size_t)`.
- `HttpClient` forwarders on the shell must stay plain functions (zero
  coroutine keywords) — a coroutine shell would capture the shell `this` and
  defeat the PIMPL movability. The stable-address rule: no frame may capture
  the shell `this`, only `Impl*`.
- Exception-exit code paths (catch handlers in `main` &c) must not be able
  to throw again: use C stdio (`fprintf`/`fputs`), not `std::cerr`.
- RAII rule: business code never touches raw `sqlite3_*` / `EVP_*` / RSA
  assembly APIs. The two accepted bare-API exceptions are commented in place
  (`SSL_set_tlsext_host_name` for SNI in http_client.cpp; the independent
  EVP signing oracle in test_jwt.cpp) — do not "clean those up".
- `RsaNumbers` members own `std::string` deliberately (a past dangling
  string_view caused intermittent verification failures) — do not switch
  back to views.

## Static analysis

`.clang-tidy` at the repo root; `clang-tidy -p build src/foo.cpp` (works
against `build/verify`'s compile_commands.json too). Single-point `NOLINT`
must carry a reason comment. Keep runs clean on files you touch.

## Before committing

`cmake --build build/verify` with 0 errors, `ctest --test-dir build/verify`
all green (45 tests), clang-tidy clean on touched files, and no Chinese
left in code paths:

```bash
grep -rP '[\x{4e00}-\x{9fff}]' src demo test examples CMakeLists.txt .clang-tidy
# (should print nothing; README.md is exempt)
```
