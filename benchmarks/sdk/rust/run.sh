#!/usr/bin/env bash
# Run the Rust SDK bench (wired to axiam-sdk via a path dep on the sibling
# axiam-rust-sdk checkout). Builds and runs the bench entrypoint in this
# directory, which prints exactly one axiam.sdk-bench/v1 JSON record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
# If the toolchain isn't installed, emit a valid 'pending' record (the collector
# still gets a well-formed row) instead of failing the whole run.
command -v cargo >/dev/null || { source "$HERE/../_pending.sh"; emit_pending rust; exit 0; }
exec cargo run --release --quiet
