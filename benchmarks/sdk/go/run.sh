#!/usr/bin/env bash
# Run the Go SDK bench. The bench glue in this directory is wired to the SDK
# (ilpanich/axiam-go-sdk); it emits an axiam.sdk-bench/v1 record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
command -v go >/dev/null || { source "$HERE/../_pending.sh"; emit_pending go; exit 0; }
exec go run .
