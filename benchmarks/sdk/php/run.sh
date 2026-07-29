#!/usr/bin/env bash
# Run the Php SDK bench. The PHP SDK (ilpanich/axiam-php-sdk) is implemented and the
# bench glue in this directory is now wired: bench.php times the four canonical ops
# and prints an axiam.sdk-bench/v1 record (or a 'pending' record if vendor/ is absent —
# run `composer install` here first).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
command -v php >/dev/null || { source "$HERE/../_pending.sh"; emit_pending php; exit 0; }

# H8 fix: run `composer install` automatically when vendor/ is missing (php +
# composer are both available on this host) instead of relying on a
# by-hand step; bench.php itself still degrades to a `pending` record if
# vendor/autoload.php ends up absent for any reason (e.g. composer missing,
# or the sibling axiam-php-sdk checkout/path repo not resolvable).
if [ ! -f "$HERE/vendor/autoload.php" ] && command -v composer >/dev/null 2>&1; then
  echo "[php] vendor/ missing — running 'composer install' (path-repo to the sibling axiam-php-sdk checkout)" >&2
  ( cd "$HERE" && composer install --no-interaction --quiet ) >&2 || \
    echo "[php] composer install failed — bench.php will emit a 'pending' record" >&2
fi

exec php "$HERE/bench.php"
