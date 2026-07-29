#!/usr/bin/env bash
# Run the Go SDK bench. The bench glue in this directory is wired to the SDK
# (ilpanich/axiam-go-sdk); it emits an axiam.sdk-bench/v1 record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
command -v go >/dev/null || { source "$HERE/../_pending.sh"; emit_pending go; exit 0; }
# H8: go.sum is committed and normally already tidy, but run it defensively
# here too — a stale go.sum (e.g. the sibling axiam-go-sdk's own deps moved)
# otherwise fails hard with "go: updates to go.mod needed; go mod tidy"
# instead of self-healing when network access is available.
go mod tidy >&2 || echo "[go] 'go mod tidy' failed (offline?) — continuing with the committed go.sum" >&2
exec go run .
