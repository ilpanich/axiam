#!/usr/bin/env bash
# Run the Rust SDK bench. The Rust SDK is still under development
# (feature/phase-17, T17.1); until it is wired this emits a 'pending'
# record. Replace the body below with: cargo run --release
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# When the SDK lands, implement bench in this directory and exec it here, e.g.:
#   exec cargo run --release
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending rust
