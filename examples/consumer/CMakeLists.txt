# coro-kit consumer example: simulates the full shape of "a business repo
# dropped its vendored shared modules and now FetchContents coro-kit".
#
# Dependency versions are this example's own choice (pinning here is the
# example's decision, not a requirement of coro-kit):
#   LibreSSL 4.1.0 / Boost 1.87.0 / SQLite 3.46.1 - the set used by the
#   originating services. The OpenSSL::* aliases and the sqlite3 target are
#   self-provided; coro-kit detects them and reuses them directly.
#
# During local development coro-kit is pulled in via SOURCE_DIR pointing at
# the repo root; once published to GitHub switch to the commented
# GIT_REPOSITORY / GIT_TAG (no difference to consumers).

cmake_minimum_required(VERSION 3.28)
project(corokit-consumer LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
  add_compile_definitions(_WIN32_WINNT=0x0A00)
endif()
if(MSVC)
  add_compile_options(/utf-8)
endif()

include(FetchContent)

# ---------------------------------------------------------------------------
# LibreSSL (an example of the consumer choosing the crypto library: coro-kit
# only knows the OpenSSL::* convention)
# ---------------------------------------------------------------------------
set(LIBRESSL_APPS OFF CACHE BOOL "" FORCE)
set(LIBRESSL_TESTS OFF CACHE BOOL "" FORCE)
set(ENABLE_ASM OFF CACHE BOOL "" FORCE)   # avoids perl/nasm dependencies, keeps builds portable
set(ENABLE_NC OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MSVC_RUNTIMES OFF CACHE BOOL "" FORCE)
# clang ships an <endian.h> in its LLVM resource dir, making
# check_include_files(endian.h) a false positive; real Windows has no system
# <endian.h>, so preset the probe result to force the compat shim.
if(WIN32)
  set(HAVE_ENDIAN_H 0 CACHE INTERNAL "no system <endian.h> on Windows" FORCE)
endif()
FetchContent_Declare(
  libressl
  URL https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.1.0.tar.gz
  URL_HASH SHA256=0f71c16bd34bdaaccdcb96a5d94a4921bfb612ec6e0eba7a80d8854eefd8bb61
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE # fixed-version release tarball: keep timestamps (CMP0135)
)
FetchContent_MakeAvailable(libressl)

# Wrap LibreSSL's ssl/crypto into the OpenSSL::* names coro-kit expects
add_library(OpenSSL::SSL INTERFACE IMPORTED GLOBAL)
target_link_libraries(OpenSSL::SSL INTERFACE ssl)
add_library(OpenSSL::Crypto INTERFACE IMPORTED GLOBAL)
target_link_libraries(OpenSSL::Crypto INTERFACE crypto)

# ---------------------------------------------------------------------------
# Boost superproject (only asio/beast/json/url and their dependencies)
# ---------------------------------------------------------------------------
set(BOOST_INCLUDE_LIBRARIES "asio;beast;json;url" CACHE STRING "" FORCE)
set(BOOST_ENABLE_PYTHON OFF CACHE BOOL "" FORCE)
set(BOOST_ENABLE_MPI OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  Boost
  URL https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz
  URL_HASH SHA256=7da75f171837577a52bbf217e17f8ea576c7c246e4594d617bfde7fafd408be5
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE # fixed-version release tarball: keep timestamps (CMP0135)
)
FetchContent_MakeAvailable(Boost)

# ---------------------------------------------------------------------------
# SQLite amalgamation (the zip has no CMakeLists.txt: wrap it in our own target)
# ---------------------------------------------------------------------------
FetchContent_Declare(
  sqlite3
  URL https://sqlite.org/2024/sqlite-amalgamation-3460100.zip
  URL_HASH SHA256=77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE # fixed-version release tarball: keep timestamps (CMP0135)
)
FetchContent_MakeAvailable(sqlite3)
add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
find_package(Threads REQUIRED)
target_link_libraries(sqlite3 PRIVATE Threads::Threads)
if(UNIX)
  target_link_libraries(sqlite3 PRIVATE m ${CMAKE_DL_LIBS})
endif()

# ---------------------------------------------------------------------------
# coro-kit (the shared modules come from the library now; the business repo
# no longer carries their sources)
# ---------------------------------------------------------------------------
FetchContent_Declare(corokit
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.."
  # GIT_REPOSITORY https://github.com/<you>/coro-kit.git
  # GIT_TAG        v0.1.0
)
FetchContent_MakeAvailable(corokit)

# ---------------------------------------------------------------------------
# The business itself: only includes coro-kit headers, only links corokit::corokit
# ---------------------------------------------------------------------------
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE corokit::corokit)
if(UNIX)
  target_compile_options(consumer PRIVATE -Wall -Wextra)
endif()
if(WIN32)
  # CMake+clang+lld-link does not auto-link oldnames.lib (LibreSSL needs it)
  target_link_libraries(consumer PRIVATE oldnames)
endif()
# When enabling io_uring on Linux: add_compile_definitions(BOOST_ASIO_HAS_IO_URING)
# globally before pulling in coro-kit, and link uring on the final target
# (or use COROKIT_ENABLE_IO_URING)

enable_testing()
