#!/usr/bin/env bash
# Run the Swift SDK bench. The Swift SDK (ilpanich/axiam-swift-sdk) is implemented; the
# bench glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: swift run -c release axiam-bench
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec swift run -c release axiam-bench
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending swift
