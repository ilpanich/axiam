#!/usr/bin/env bash
# Run the C SDK bench. Wired to the sibling C SDK (ilpanich/axiam-c-sdk) via
# CMake add_subdirectory() (see CMakeLists.txt). Builds bench.c against it and
# execs the resulting binary, which prints one axiam.sdk-bench/v1 JSON record
# to stdout.
#
# Degrades gracefully to a 'pending' record (not a hard failure) if cmake/a C
# compiler is missing, or if configure/build fails for any reason (e.g. the
# sibling axiam-c-sdk checkout or its libcurl/OpenSSL dev headers are
# missing) — the collector still gets a well-formed row. A build that
# succeeds always runs the binary, which itself degrades to an 'error'
# record (not a crash) if the target is unreachable or login fails.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

pending() {
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending c
  exit 0
}

command -v cmake >/dev/null || pending
{ command -v cc >/dev/null || command -v gcc >/dev/null; } || pending

mkdir -p build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >build/.configure.log 2>&1 || pending
cmake --build build -j >build/.build.log 2>&1 || pending

exec ./build/axiam-bench
