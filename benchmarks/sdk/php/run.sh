#!/usr/bin/env bash
# Run the Php SDK bench. The Php SDK is still under development
# (feature/phase-17, T17.6); until it is wired this emits a 'pending'
# record. Replace the body below with: php bench.php
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# When the SDK lands, implement bench in this directory and exec it here, e.g.:
#   exec php bench.php
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending php
