# coro-kit - a C++20 coroutine web toolkit: a Koa-style HTTP server
# framework, an outbound HTTP/HTTPS client, JWT verification, and RAII
# wrappers for SQLite and OpenSSL.
#
# Components (Boost-style per-library model): consumers select what they
# need by setting COROKIT_INCLUDE_LIBRARIES before pulling this project in
# (unset/empty = all components; unknown names fail loudly). The selection
# expands to its transitive closure, and unselected components cost neither
# build time nor dependencies:
#
#   corokit::b64          b64.hpp (header-only)                     - no deps
#   corokit::openssl      openssl.hpp/.cpp                          - OpenSSL/LibreSSL >= 1.1 (crypto)
#   corokit::sqlite       sqlite.hpp/.cpp                           - SQLite >= 3.37
#   corokit::key_loader   key_loader.hpp/.cpp                       - corokit::openssl, b64
#   corokit::jwt          jwt.hpp/.cpp                              - corokit::openssl, b64, Boost::json
#   corokit::http_srv     http_srv.hpp/.cpp, http_config.hpp, error.hpp
#                                                                   - Boost (asio/beast/json/url), Threads
#   corokit::http_client  http_client.hpp/.cpp                      - Boost.url (asio/beast header-only), OpenSSL (TLS upstream)
#   corokit::corokit      umbrella over everything selected
#
# Dependency policy: nothing is pinned. Per-component contract - a target
# that already exists is reused directly, find_package is the fallback;
# versions and sources stay the consumer's choice:
#   OpenSSL::SSL / OpenSSL::Crypto - find_package(OpenSSL); a consumer on
#                                    LibreSSL just creates these aliases
#                                    itself (see examples/consumer)
#   Boost::json (+ Boost::url for the http components) - find_package or a
#                                    Boost superproject via FetchContent;
#                                    1.81+ required (Boost.URL line)
#   SQLite::SQLite3 or sqlite3     - find_package(SQLite3) or a self-built
#                                    amalgamation target
# Resolutions happen lazily: a dependency is only required when at least one
# selected component needs it.
#
# Linux io_uring: a consumer enabling BOOST_ASIO_HAS_IO_URING must define it
# globally before pulling this library in (Asio config macros must agree
# across the whole build or layouts diverge = ODR violation); the uring
# library is linked by the consumer's final executable targets. Alternatively
# set COROKIT_ENABLE_IO_URING=ON (the http components define it and link
# uring themselves).
#
# The test framework (GoogleTest) is only fetched when COROKIT_BUILD_TESTS=ON
# (which forces all components) and does not affect the library's dependency
# surface: a system find_package(GTest CONFIG) is preferred.

cmake_minimum_required(VERSION 3.21) # PROJECT_IS_TOP_LEVEL was added in 3.21
project(corokit VERSION 0.2.0 LANGUAGES CXX)

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
  option(COROKIT_BUILD_TESTS "Build unit tests (forces all components)" ON)
else()
  option(COROKIT_BUILD_DEMO "Build the demo server" OFF)
  option(COROKIT_BUILD_TESTS "Build unit tests (forces all components)" OFF)
endif()
option(COROKIT_ENABLE_IO_URING "Define BOOST_ASIO_HAS_IO_URING and link uring" OFF)
option(COROKIT_LIVE_TESTS "Include the live-network http_client tests (real site, real TLS; needs internet)" OFF)

include(FetchContent)

# ---------------------------------------------------------------------------
# Component selection (BOOST_INCLUDE_LIBRARIES style)
# ---------------------------------------------------------------------------
set(COROKIT_ALL_COMPONENTS "b64" "openssl" "sqlite" "key_loader" "jwt" "http_srv" "http_client")

if(COROKIT_BUILD_TESTS)
  # the suite covers every component
  set(COROKIT_INCLUDE_LIBRARIES "${COROKIT_ALL_COMPONENTS}")
elseif(NOT DEFINED COROKIT_INCLUDE_LIBRARIES OR COROKIT_INCLUDE_LIBRARIES STREQUAL "")
  set(COROKIT_INCLUDE_LIBRARIES "${COROKIT_ALL_COMPONENTS}")
endif()

foreach(_c IN LISTS COROKIT_INCLUDE_LIBRARIES)
  if(NOT "${_c}" IN_LIST COROKIT_ALL_COMPONENTS)
    message(FATAL_ERROR
      "coro-kit: unknown component '${_c}'. Valid components: ${COROKIT_ALL_COMPONENTS}")
  endif()
endforeach()

# Expand the selection to its transitive closure
set(COROKIT_COMPONENTS ${COROKIT_INCLUDE_LIBRARIES})
foreach(_c IN LISTS COROKIT_INCLUDE_LIBRARIES)
  if(_c STREQUAL "jwt")
    list(APPEND COROKIT_COMPONENTS openssl b64)   # openssl::Key + header-only base64url
  elseif(_c STREQUAL "key_loader")
    list(APPEND COROKIT_COMPONENTS openssl b64)
  endif()
  # http_client: no transitive deps - error.hpp is header-only (shared src
  # include dir), Boost.url is linked by the http_client target itself
endforeach()
list(REMOVE_DUPLICATES COROKIT_COMPONENTS)
message(STATUS "coro-kit components: ${COROKIT_COMPONENTS}")

set(COROKIT_WANT_OPENSSL OFF)
set(COROKIT_WANT_BOOST OFF)
if("openssl" IN_LIST COROKIT_COMPONENTS OR "key_loader" IN_LIST COROKIT_COMPONENTS OR
   "jwt" IN_LIST COROKIT_COMPONENTS OR "http_client" IN_LIST COROKIT_COMPONENTS)
  set(COROKIT_WANT_OPENSSL ON)
endif()
if("http_srv" IN_LIST COROKIT_COMPONENTS OR "http_client" IN_LIST COROKIT_COMPONENTS OR
   "jwt" IN_LIST COROKIT_COMPONENTS)
  set(COROKIT_WANT_BOOST ON)
endif()

# ---------------------------------------------------------------------------
# Dependency resolution - lazy, per component (see the file header)
# ---------------------------------------------------------------------------
if("http_srv" IN_LIST COROKIT_COMPONENTS OR "sqlite" IN_LIST COROKIT_COMPONENTS)
  find_package(Threads REQUIRED)
endif()

if(COROKIT_WANT_OPENSSL)
  if(NOT TARGET OpenSSL::SSL)
    find_package(OpenSSL REQUIRED) # also provides OpenSSL::Crypto
  endif()
  if(DEFINED OPENSSL_VERSION AND OPENSSL_VERSION VERSION_LESS 1.1)
    message(FATAL_ERROR
      "coro-kit requires OpenSSL/LibreSSL >= 1.1 (opaque RSA APIs), but found "
      "${OPENSSL_VERSION}. Provide a newer OpenSSL/LibreSSL to your project.")
  endif()
endif()

# Boost floor note: 1.81+ is enforced by the static_assert in
# src/http_srv.hpp (BOOST_VERSION) - no configure-time probing here, the
# version sources across provisioning shapes (find_package variable /
# superproject / pre-provided targets) are not worth the complexity
set(_boost_components "")
if(COROKIT_WANT_BOOST)
  if("http_srv" IN_LIST COROKIT_COMPONENTS OR "jwt" IN_LIST COROKIT_COMPONENTS)
    list(APPEND _boost_components json)
  endif()
  if("http_srv" IN_LIST COROKIT_COMPONENTS OR "http_client" IN_LIST COROKIT_COMPONENTS)
    list(APPEND _boost_components url)
  endif()
  list(REMOVE_DUPLICATES _boost_components)
  # url is a compiled library since Boost 1.81 (Boost.URL's iterator/params
  # implementations live in libboost_url), not header-only. Per-component
  # gate: only find_package when a needed target is still missing (e.g.
  # http_client alone needs Boost::url but not Boost::json)
  if(("json" IN_LIST _boost_components AND NOT TARGET Boost::json)
     OR ("url" IN_LIST _boost_components AND NOT TARGET Boost::url))
    find_package(Boost REQUIRED COMPONENTS ${_boost_components})
  endif()
endif()

set(COROKIT_SQLITE_LINK "")
if("sqlite" IN_LIST COROKIT_COMPONENTS)
  if(TARGET SQLite::SQLite3)
    set(COROKIT_SQLITE_LINK SQLite::SQLite3)
  elseif(TARGET sqlite3)
    set(COROKIT_SQLITE_LINK sqlite3)
  else()
    find_package(SQLite3 REQUIRED)
    set(COROKIT_SQLITE_LINK SQLite::SQLite3)
  endif()
  if(DEFINED SQLite3_VERSION AND SQLite3_VERSION VERSION_LESS 3.37)
    message(FATAL_ERROR
      "coro-kit requires SQLite >= 3.37 (sqlite3_changes64), but found "
      "${SQLite3_VERSION}. Provide a newer SQLite to your project.")
  endif()
endif()

# Boost header aggregation (after all component targets exist): for an
# installed Boost or FindBoost, Boost::headers is the full include set; but
# inside a Boost superproject (in-tree FetchContent build) it is an empty
# pseudo-library and the include dirs live on the per-module targets - so
# aggregate them one by one where they exist; both shapes end up with
# complete header paths
if(COROKIT_WANT_BOOST)
  set(COROKIT_BOOST_LINK Boost::headers Boost::json)
  foreach(comp IN ITEMS asio beast url)
    if(TARGET Boost::${comp})
      list(APPEND COROKIT_BOOST_LINK Boost::${comp})
    endif()
  endforeach()
  # http_client (decoupled from http_srv) needs url but not json: linking
  # json would hand http_client-only consumers a superfluous libboost_json
  # runtime dependency
  set(COROKIT_BOOST_CLIENT_LINK ${COROKIT_BOOST_LINK})
  list(REMOVE_ITEM COROKIT_BOOST_CLIENT_LINK Boost::json)
endif()

# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
set(COROKIT_INC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)

function(corokit_target_flags tgt)
  if(MSVC)
    target_compile_options(${tgt} PRIVATE /utf-8) # sources contain non-ASCII; avoids C4819
  endif()
  if(WIN32)
    # Minimum target OS for Boost.Asio; PRIVATE touches only this target's
    # TUs and does not constrain the consumer
    target_compile_definitions(${tgt} PRIVATE _WIN32_WINNT=0x0A00)
  endif()
  if(UNIX)
    target_compile_options(${tgt} PRIVATE -Wall -Wextra)
  endif()
endfunction()

if("b64" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_b64 INTERFACE)
  add_library(corokit::b64 ALIAS corokit_b64)
  target_compile_features(corokit_b64 INTERFACE cxx_std_20)
  target_include_directories(corokit_b64 INTERFACE ${COROKIT_INC})
endif()

if("openssl" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_openssl STATIC src/openssl.cpp)
  add_library(corokit::openssl ALIAS corokit_openssl)
  target_compile_features(corokit_openssl PUBLIC cxx_std_20)
  target_include_directories(corokit_openssl PUBLIC ${COROKIT_INC})
  target_link_libraries(corokit_openssl PUBLIC OpenSSL::Crypto)
  corokit_target_flags(corokit_openssl)
endif()

if("sqlite" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_sqlite STATIC src/sqlite.cpp)
  add_library(corokit::sqlite ALIAS corokit_sqlite)
  target_compile_features(corokit_sqlite PUBLIC cxx_std_20)
  target_include_directories(corokit_sqlite PUBLIC ${COROKIT_INC})
  target_link_libraries(corokit_sqlite PUBLIC ${COROKIT_SQLITE_LINK} Threads::Threads)
  corokit_target_flags(corokit_sqlite)
endif()

if("key_loader" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_key_loader STATIC src/key_loader.cpp)
  add_library(corokit::key_loader ALIAS corokit_key_loader)
  target_compile_features(corokit_key_loader PUBLIC cxx_std_20)
  target_include_directories(corokit_key_loader PUBLIC ${COROKIT_INC})
  # key_loader.hpp includes openssl.hpp -> consumers may use openssl::Key
  target_link_libraries(corokit_key_loader PUBLIC corokit_openssl)
  corokit_target_flags(corokit_key_loader)
endif()

if("jwt" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_jwt STATIC src/jwt.cpp)
  add_library(corokit::jwt ALIAS corokit_jwt)
  target_compile_features(corokit_jwt PUBLIC cxx_std_20)
  target_include_directories(corokit_jwt PUBLIC ${COROKIT_INC})
  # jwt.hpp exposes openssl.hpp (openssl::Key) and boost/json.hpp; .NET XML
  # key loading is the consumer's concern (corokit::key_loader + key_loader.hpp)
  target_link_libraries(corokit_jwt PUBLIC corokit_openssl Boost::headers Boost::json)
  corokit_target_flags(corokit_jwt)
endif()

if("http_srv" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_http_srv STATIC src/http_srv.cpp)
  add_library(corokit::http_srv ALIAS corokit_http_srv)
  target_compile_features(corokit_http_srv PUBLIC cxx_std_20)
  target_include_directories(corokit_http_srv PUBLIC ${COROKIT_INC})
  # http_srv.hpp exposes Boost types
  target_link_libraries(corokit_http_srv PUBLIC ${COROKIT_BOOST_LINK} Threads::Threads)
  if(COROKIT_ENABLE_IO_URING)
    target_compile_definitions(corokit_http_srv PUBLIC BOOST_ASIO_HAS_IO_URING)
    target_link_libraries(corokit_http_srv PUBLIC uring)
  endif()
  corokit_target_flags(corokit_http_srv)
endif()

if("http_client" IN_LIST COROKIT_COMPONENTS)
  add_library(corokit_http_client STATIC src/http_client.cpp)
  add_library(corokit::http_client ALIAS corokit_http_client)
  target_compile_features(corokit_http_client PUBLIC cxx_std_20)
  target_include_directories(corokit_http_client PUBLIC ${COROKIT_INC})
  # Decoupled from http_srv: header-only error.hpp resolves via the shared
  # src include dir; Boost needs only url (asio/beast are header-only).
  # TLS upstream → OpenSSL::SSL
  target_link_libraries(corokit_http_client PUBLIC
    ${COROKIT_BOOST_CLIENT_LINK}
    OpenSSL::SSL
    OpenSSL::Crypto
  )
  if(COROKIT_ENABLE_IO_URING)
    target_compile_definitions(corokit_http_client PUBLIC BOOST_ASIO_HAS_IO_URING)
  endif()
  corokit_target_flags(corokit_http_client)
endif()

# Umbrella over the selected components (link everything with one target)
add_library(corokit_corokit INTERFACE)
add_library(corokit::corokit ALIAS corokit_corokit)
foreach(_c IN LISTS COROKIT_COMPONENTS)
  target_link_libraries(corokit_corokit INTERFACE corokit::${_c})
endforeach()

# ---------------------------------------------------------------------------
# demo: Koa-style server + SSE + cookies + outbound client self-fetch
# (top-level builds only; needs the http components)
# ---------------------------------------------------------------------------
if(COROKIT_BUILD_DEMO)
  if(NOT ("http_srv" IN_LIST COROKIT_COMPONENTS AND "http_client" IN_LIST COROKIT_COMPONENTS))
    message(FATAL_ERROR "the coro-kit demo requires the http_srv and http_client components")
  endif()
  add_executable(demo demo/main.cpp)
  target_link_libraries(demo PRIVATE corokit::http_srv corokit::http_client)
  corokit_target_flags(demo)
endif()

# ---------------------------------------------------------------------------
# Unit tests (only when COROKIT_BUILD_TESTS=ON; forces all components.
# Prefer a system GTest, FetchContent as fallback)
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
    test/test_http_srv.cpp
    test/test_http_client.cpp
    test/test_jwt.cpp
    test/test_key_loader.cpp
  )
  target_link_libraries(corokit-tests PRIVATE corokit::corokit GTest::gtest_main)
  target_compile_definitions(corokit-tests PRIVATE KEYS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/test/keys")
  if(COROKIT_LIVE_TESTS)
    # opt-in live-network cases (see the bottom of test/test_http_client.cpp);
    # the default suite stays hermetic and network-free
    target_compile_definitions(corokit-tests PRIVATE COROKIT_LIVE_TESTS=1)
  endif()
  corokit_target_flags(corokit-tests)

  enable_testing()
  include(GoogleTest)
  gtest_discover_tests(corokit-tests)
endif()
