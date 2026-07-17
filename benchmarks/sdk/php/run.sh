#!/usr/bin/env bash
# Run the Php SDK bench. The PHP SDK (ilpanich/axiam-php-sdk) is implemented and the
# bench glue in this directory is now wired: bench.php times the four canonical ops
# and prints an axiam.sdk-bench/v1 record (or a 'pending' record if vendor/ is absent —
# run `composer install` here first).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v php >/dev/null || { source "$HERE/../_pending.sh"; emit_pending php; exit 0; }
exec php "$HERE/bench.php"
