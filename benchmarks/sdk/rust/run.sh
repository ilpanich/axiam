#!/usr/bin/env bash
# Run the Rust SDK bench (wired to axiam-sdk via a path dep on the sibling
# axiam-rust-sdk checkout). Builds and runs the bench entrypoint in this
# directory, which prints exactly one axiam.sdk-bench/v1 JSON record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# H8: the TLS input paths (BENCH_CA_CERT and, for p3-mtls, BENCH_CLIENT_CERT/
# BENCH_CLIENT_KEY) are set relative to benchmarks/ by profiles/*.env, so they
# must be resolved to absolute paths BEFORE the `cd "$HERE"` below — the bench
# binary reads them with its own cwd now sdk/rust/.
# shellcheck disable=SC1091
source "$HERE/../_tlspaths.sh"; absolutize_tls_paths
cd "$HERE"
# H8: defense-in-depth if this script is invoked directly (bypassing both
# `just sdk-bench` and `sdk-bench-all`'s run-all.sh, which already source the
# seed env) — source .seed/<target>.seed.env ourselves so BENCH_RESOURCE_ID
# isn't silently empty, and fail fast naming the var if it still is.
if [ -z "${BENCH_RESOURCE_ID:-}" ]; then
  SEED_ENV="${BENCH_SEED_DIR:-$HERE/../../.seed}/${BENCH_TARGET:-axiam}.seed.env"
  if [ -f "$SEED_ENV" ]; then
    # shellcheck disable=SC1090
    source "$SEED_ENV"
  fi
fi
if [ -z "${BENCH_RESOURCE_ID:-}" ]; then
  echo "[rust] FATAL: BENCH_RESOURCE_ID is empty — run 'just target=${BENCH_TARGET:-axiam} bench-seed' first (see ../.seed/<target>.seed.env)." >&2
  exit 1
fi
# If the toolchain isn't installed, emit a valid 'pending' record (the collector
# still gets a well-formed row) instead of failing the whole run.
command -v cargo >/dev/null || { source "$HERE/../_pending.sh"; emit_pending rust; exit 0; }
exec cargo run --release --quiet
