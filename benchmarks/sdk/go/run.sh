#!/usr/bin/env bash
# Run the Go SDK bench. The Go SDK is still under development
# (feature/phase-17, T17.7); until it is wired this emits a 'pending'
# record. Replace the body below with: go run .
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# When the SDK lands, implement bench in this directory and exec it here, e.g.:
#   exec go run .
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending go
