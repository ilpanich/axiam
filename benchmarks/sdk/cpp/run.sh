#!/usr/bin/env bash
# Run the C++ SDK bench (wired to axiam::Client via a CMake add_subdirectory
# on the sibling axiam-cplusplus-sdk checkout — see TODO.md). Configures +
# builds the bench into ./build, then execs the binary, which prints exactly
# one axiam.sdk-bench/v1 record to stdout. Falls back to a 'pending' record
# if the toolchain, the sibling SDK checkout, or the build itself is
# unavailable — a build failure here must never break the aggregator run.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# The SDK version this bench reports is READ from the sibling checkout it
# builds against, not declared as a literal in the harness — see
# ../_sdkversion.sh for why eight of these literals had gone stale at once.
# Sourced before any `cd`, like _tlspaths.sh, and a no-op when the checkout
# is absent (the bench then keeps its own fallback literal).
# shellcheck disable=SC1091
source "$HERE/../_sdkversion.sh"; export_sdk_version cpp
cd "$HERE"
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"

command -v cmake >/dev/null 2>&1 || { emit_pending cpp; exit 0; }

BUILD_DIR="$HERE/build"
# Build output goes to our stderr (fd 2), never stdout: stdout must carry
# exactly the one JSON record the exec'd binary prints below.
if cmake -S "$HERE" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release 1>&2 \
   && cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 2)" 1>&2; then
  exec "$BUILD_DIR/axiam-bench"
else
  emit_pending cpp
fi
