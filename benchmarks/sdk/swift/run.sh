#!/usr/bin/env bash
# Run the Swift SDK bench (wired to AxiamSDK via a path dependency on the sibling
# axiam-swift-sdk checkout). Builds and runs the bench entrypoint in this directory,
# which prints exactly one axiam.sdk-bench/v1 JSON record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
# shellcheck disable=SC1091
# If the toolchain isn't installed, or the release build fails (e.g. the sibling
# axiam-swift-sdk checkout is missing/unbuildable), emit a valid 'pending' record
# (the collector still gets a well-formed row) instead of failing the whole run.
command -v swift >/dev/null || { source "$HERE/../_pending.sh"; emit_pending swift; exit 0; }
swift build -c release --product axiam-bench >/dev/null 2>&1 || {
  source "$HERE/../_pending.sh"; emit_pending swift; exit 0;
}
exec swift run -c release axiam-bench
