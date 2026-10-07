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
CMakeLists.txt       # zero pinned deps: if(NOT TARGET) contract + find_package fallback
src/                 # all modules, flat layout, included as "xxx.hpp"
demo/main.cpp        # all-in-one demo (top-level builds only)
test/                # gtest unit tests + test-only 1024-bit RSA keys in test/keys/
examples/consumer/   # consumer sample = migration template (pins its own deps,
                     # FetchContents coro-kit, builds a small business server)
```

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
- Version floors surface as explanatory FATAL_ERRORs at configure time
  (Boost 1.81 / OpenSSL 1.1 / SQLite 3.37, best-effort detection) plus
  static_asserts in src/http.hpp, src/openssl.cpp and src/sqlite.cpp as the
  authoritative backstop.
- demo/tests default OFF when consumed as a subproject (`PROJECT_IS_TOP_LEVEL`).
- GoogleTest is only fetched under `COROKIT_BUILD_TESTS=ON` (system
  `find_package(GTest CONFIG)` preferred).

## Build & test (this machine: Windows, LLVM clang + Ninja + Git Bash)

This machine has no system OpenSSL/Boost/SQLite, so a top-level configure
cannot resolve dependencies. Verify via the consumer example, redirecting
dependency sources to a sibling project's cache (no re-download):

```bash
cd coro-kit
D="<abs path to some built sibling>/cpp/build/_deps"
cmake -S examples/consumer -B build/verify -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DCOROKIT_BUILD_TESTS=ON \
  -DFETCHCONTENT_SOURCE_DIR_BOOST="$D/boost-src" \
  -DFETCHCONTENT_SOURCE_DIR_LIBRESSL="$D/libressl-src" \
  -DFETCHCONTENT_SOURCE_DIR_SQLITE3="$D/sqlite3-src" \
  -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$D/googletest-src"
cmake --build build/verify
ctest --test-dir build/verify --output-on-failure   # 45 tests expected
```

On machines with system deps, a plain `cmake -S . -B build && cmake --build
build && ctest --test-dir build` works (find_package path).

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
```

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
- Coroutine-lambda closures are not copied into frames: name them and keep
  them alive until the coroutine finishes.
- Reference arguments to lazy coroutines (anything returning asio::awaitable)
  must point at objects that outlive `ioc.run()` - never pass temporaries.
  `listen(..., HttpConfig{})` dangles inside the coroutine frame; it
  segfaulted on GCC/Linux while silently passing on Windows/clang.
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
