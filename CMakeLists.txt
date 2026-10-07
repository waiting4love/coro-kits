# coro-kit - a C++20 coroutine web toolkit: a Koa-style HTTP server
# framework, an outbound HTTP/HTTPS client, JWT verification, and RAII
# wrappers for SQLite and OpenSSL.
#
# Dependency policy: this library pins no third-party dependency versions or
# sources. Boost / OpenSSL (or LibreSSL) / SQLite are all provided by the
# consumer, per this contract - a target that already exists is reused
# directly; only when missing does the library fall back to a system
# find_package:
#   OpenSSL::SSL / OpenSSL::Crypto - the find_package(OpenSSL) result; a
#                                    consumer on LibreSSL just creates these
#                                    aliases itself (see examples/consumer)
#   Boost::json + Boost::url      - find_package(Boost COMPONENTS json url)
#                                    or a Boost superproject via FetchContent;
#                                    1.81+ required (Boost.URL line); url is
#                                    a compiled library, not header-only
#   SQLite::SQLite3 or sqlite3     - find_package(SQLite3) or a self-built
#                                    amalgamation target
#
# Consumption (FetchContent / add_subdirectory) is documented in the README;
# examples/consumer is a fully compilable sample and doubles as the
# migration template for "drop the vendored shared modules, fetch the
# library".
#
# Linux io_uring: a consumer enabling BOOST_ASIO_HAS_IO_URING must define it
# globally before pulling this library in (Asio config macros must agree
# across the whole build or layouts diverge = ODR violation); the uring
# library is linked by the consumer's final executable targets. Alternatively
# set COROKIT_ENABLE_IO_URING=ON (the library defines it and links uring
# itself).
#
# The test framework (GoogleTest) is only fetched when COROKIT_BUILD_TESTS=ON
# and does not affect the library's dependency surface: a system
# find_package(GTest CONFIG) is preferred, FetchContent is the fallback.

cmake_minimum_required(VERSION 3.21) # PROJECT_IS_TOP_LEVEL was added in 3.21
project(corokit VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # build/compile_commands.json: clang-tidy -p build works as-is

if(NOT CMAKE_BUILD_TYPE AND PROJECT_IS_TOP_LEVEL)
  set(CMAKE_BUILD_TYPE Release)
endif()

# When consumed as a subproject via FetchContent, demo/tests default to off
# (zero friction for consumers)
if(PROJECT_IS_TOP_LEVEL)
  option(COROKIT_BUILD_DEMO "Build the demo server" ON)
  option(COROKIT_BUILD_TESTS "Build unit tests" ON)
else()
  option(COROKIT_BUILD_DEMO "Build the demo server" OFF)
  option(COROKIT_BUILD_TESTS "Build unit tests" OFF)
endif()
option(COROKIT_ENABLE_IO_URING "Define BOOST_ASIO_HAS_IO_URING and link uring" OFF)

include(FetchContent)

# ---------------------------------------------------------------------------
# Dependency resolution (all can be pre-provided by the consumer; see the
# file header)
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

if(NOT TARGET OpenSSL::SSL)
  find_package(OpenSSL REQUIRED) # also provides OpenSSL::Crypto
endif()

if(NOT TARGET Boost::json)
  # url is a compiled library since Boost 1.81 (Boost.URL's iterator/params
  # implementations live in libboost_url), not header-only
  find_package(Boost REQUIRED COMPONENTS json url)
endif()
# Boost header aggregation: for an installed Boost or FindBoost,
# Boost::headers is the full include set; but inside a Boost superproject
# (in-tree FetchContent build) it is an empty pseudo-library and the include
# dirs live on the per-module targets - so aggregate them one by one where
# they exist; both shapes end up with complete header paths
set(COROKIT_BOOST_LINK Boost::headers Boost::json)
foreach(comp IN ITEMS asio beast url)
  if(TARGET Boost::${comp})
    list(APPEND COROKIT_BOOST_LINK Boost::${comp})
  endif()
endforeach()

if(TARGET SQLite::SQLite3)
  set(COROKIT_SQLITE_LINK SQLite::SQLite3)
elseif(TARGET sqlite3)
  set(COROKIT_SQLITE_LINK sqlite3)
else()
  find_package(SQLite3 REQUIRED)
  set(COROKIT_SQLITE_LINK SQLite::SQLite3)
endif()

# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------
add_library(corokit STATIC
  src/http.cpp
  src/http_client.cpp
  src/jwt.cpp
  src/key_loader.cpp
  src/openssl.cpp
  src/sqlite.cpp
)
add_library(corokit::corokit ALIAS corokit)
target_compile_features(corokit PUBLIC cxx_std_20)
target_include_directories(corokit PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
# All PUBLIC: headers expose Boost types; ssl/crypto/sqlite symbols flow from
# the static library into the final link
target_link_libraries(corokit PUBLIC
  ${COROKIT_BOOST_LINK}
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
  ${COROKIT_SQLITE_LINK}
)
if(MSVC)
  target_compile_options(corokit PRIVATE /utf-8) # sources contain non-ASCII; avoids C4819
endif()
if(WIN32)
  # Minimum target OS for Boost.Asio; PRIVATE touches only this library's
  # TUs and does not constrain the consumer
  target_compile_definitions(corokit PRIVATE _WIN32_WINNT=0x0A00)
endif()
if(COROKIT_ENABLE_IO_URING)
  target_compile_definitions(corokit PUBLIC BOOST_ASIO_HAS_IO_URING)
  target_link_libraries(corokit PUBLIC uring)
endif()
if(UNIX)
  target_compile_options(corokit PRIVATE -Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# demo: Koa-style server + SSE + cookies + outbound client self-fetch
# (top-level builds only)
# ---------------------------------------------------------------------------
if(COROKIT_BUILD_DEMO)
  add_executable(demo demo/main.cpp)
  target_link_libraries(demo PRIVATE corokit)
  if(MSVC)
    target_compile_options(demo PRIVATE /utf-8)
  endif()
  if(WIN32)
    target_compile_definitions(demo PRIVATE _WIN32_WINNT=0x0A00)
  endif()
  if(UNIX)
    target_compile_options(demo PRIVATE -Wall -Wextra)
  endif()
endif()

# ---------------------------------------------------------------------------
# Unit tests (only when COROKIT_BUILD_TESTS=ON; prefer a system GTest,
# FetchContent as fallback)
# ---------------------------------------------------------------------------
if(COROKIT_BUILD_TESTS)
  find_package(GTest CONFIG QUIET)
  if(NOT GTest_FOUND)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
      URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
      DOWNLOAD_EXTRACT_TIMESTAMP TRUE # fixed-version release tarball: keep timestamps (CMP0135)
    )
    FetchContent_MakeAvailable(googletest)
  endif()

  # Test keys: test/keys/ holds test-only 1024-bit RSA keys (.NET XML), committed to the repo
  add_executable(corokit-tests
    test/test_b64.cpp
    test/test_http.cpp
    test/test_http_client.cpp
    test/test_jwt.cpp
    test/test_key_loader.cpp
  )
  target_link_libraries(corokit-tests PRIVATE corokit GTest::gtest_main)
  target_compile_definitions(corokit-tests PRIVATE KEYS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/keys")
  if(MSVC)
    target_compile_options(corokit-tests PRIVATE /utf-8)
  endif()
  if(WIN32)
    target_compile_definitions(corokit-tests PRIVATE _WIN32_WINNT=0x0A00)
  endif()
  if(UNIX)
    target_compile_options(corokit-tests PRIVATE -Wall -Wextra)
  endif()

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(corokit-tests)
endif()
