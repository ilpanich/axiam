#!/usr/bin/env bash
# Run the Go SDK bench. The bench glue in this directory is wired to the SDK
# (ilpanich/axiam-go-sdk); it emits an axiam.sdk-bench/v1 record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# H8: resolve BENCH_CA_CERT to an absolute path before `cd "$HERE"` below —
# profiles/*.env sets it relative to benchmarks/ (the caller's cwd), which
# no longer resolves once this script cds into sdk/go/.
if [ -n "${BENCH_CA_CERT:-}" ] && [ -f "$BENCH_CA_CERT" ]; then
  export BENCH_CA_CERT="$(cd "$(dirname "$BENCH_CA_CERT")" && pwd)/$(basename "$BENCH_CA_CERT")"
fi
cd "$HERE"
command -v go >/dev/null || { source "$HERE/../_pending.sh"; emit_pending go; exit 0; }
# H8: go.sum is committed and normally already tidy, but run it defensively
# here too — a stale go.sum (e.g. the sibling axiam-go-sdk's own deps moved)
# otherwise fails hard with "go: updates to go.mod needed; go mod tidy"
# instead of self-healing when network access is available.
go mod tidy >&2 || echo "[go] 'go mod tidy' failed (offline?) — continuing with the committed go.sum" >&2
exec go run .
