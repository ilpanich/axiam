#!/usr/bin/env bash
# Run the C++ SDK bench. The C++ SDK (ilpanich/axiam-cplusplus-sdk) is implemented; the bench
# glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with a CMake build + run of the bench binary.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build && exec ./build/axiam-bench
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending cpp
