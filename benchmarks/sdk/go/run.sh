#!/usr/bin/env bash
# Run the Go SDK bench. The Go SDK (ilpanich/axiam-go-sdk) is implemented; the bench glue
# in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: go run .
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec go run .
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending go
