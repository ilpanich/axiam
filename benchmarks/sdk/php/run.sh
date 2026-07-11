#!/usr/bin/env bash
# Run the Php SDK bench. The PHP SDK (sdks/php) is implemented; the bench
# glue in this directory is not yet wired, so this emits a 'pending' record.
# Replace the body below with: php bench.php
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Once wired, implement bench in this directory and exec it here, e.g.:
#   exec php bench.php
# shellcheck disable=SC1091
source "$HERE/../_pending.sh"; emit_pending php
