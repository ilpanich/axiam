#!/usr/bin/env bash
# Run the Rust SDK bench. The Rust SDK (sdks/rust) is implemented; the bench
# glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: cargo run --release
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec cargo run --release
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending rust
