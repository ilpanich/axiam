#!/usr/bin/env bash
# Run the Kotlin SDK bench. The Kotlin SDK (ilpanich/axiam-kotlin-sdk) is implemented; the
# bench glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: ./gradlew -q run
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec ./gradlew -q --console=plain run
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending kotlin
