#!/usr/bin/env bash
# Run the Swift SDK bench (wired to AxiamSDK via a path dependency on the sibling
# axiam-swift-sdk checkout). Builds and runs the bench entrypoint in this directory,
# which prints exactly one axiam.sdk-bench/v1 JSON record to stdout.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# The SDK version this bench reports is READ from the sibling checkout it
# builds against, not declared as a literal in the harness — see
# ../_sdkversion.sh for why eight of these literals had gone stale at once.
# Sourced before any `cd`, like _tlspaths.sh, and a no-op when the checkout
# is absent (the bench then keeps its own fallback literal).
# shellcheck disable=SC1091
source "$HERE/../_sdkversion.sh"; export_sdk_version swift
cd "$HERE"
# shellcheck disable=SC1091
# If the toolchain isn't installed, or the release build fails (e.g. the sibling
# axiam-swift-sdk checkout is missing/unbuildable), emit a valid 'pending' record
# (the collector still gets a well-formed row) instead of failing the whole run.
command -v swift >/dev/null || { source "$HERE/../_pending.sh"; emit_pending swift; exit 0; }

# Build output goes to stderr (dry-run.sh keeps it in swift.dryrun.log); stdout
# carries only the JSON record. It used to go to /dev/null, which made a failed
# build indistinguishable from a missing toolchain.
#
# Swift 6.4 made swift-build the default backend, and on some Linux toolchain
# layouts it fails before compiling anything: it parses the localized
# `ld --version` text (a non-English locale prints e.g. "ld di GNU" and it then
# probes ld64's `-version_details`), and it looks for helpers such as
# swift-autolink-extract next to /usr/sbin instead of in the toolchain. The
# legacy native build system is still supported, so retry with it.
build_flags=(-c release)
if ! swift build "${build_flags[@]}" --product axiam-bench >&2; then
  echo "[swift bench] default build system failed; retrying with --build-system native" >&2
  build_flags+=(--build-system native)
  swift build "${build_flags[@]}" --product axiam-bench >&2 || {
    source "$HERE/../_pending.sh"
    emit_pending swift "swift release build failed (toolchain present) — the build log is on stderr, kept in swift.dryrun.log by the dry run."
    exit 0
  }
fi
# Run the binary just built rather than `swift run`, which would rebuild with
# the default build system and hit the same failure.
exec "$(swift build "${build_flags[@]}" --show-bin-path)/axiam-bench"
