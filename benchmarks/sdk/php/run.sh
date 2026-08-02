#!/usr/bin/env bash
# Run the Php SDK bench. The PHP SDK (ilpanich/axiam-php-sdk) is implemented and the
# bench glue in this directory is now wired: bench.php times the four canonical ops
# and prints an axiam.sdk-bench/v1 record (or a 'pending' record if vendor/ is absent —
# run `composer install` here first).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Resolve the TLS input paths (BENCH_CA_CERT and, for p3-mtls,
# BENCH_CLIENT_CERT/BENCH_CLIENT_KEY) to absolute paths. php runs with the
# caller's cwd so the benchmarks-relative paths from profiles/*.env would
# usually resolve anyway — this makes it independent of who invoked us, the
# same way every other language's run.sh is.
# shellcheck disable=SC1091
source "$HERE/../_tlspaths.sh"; absolutize_tls_paths
command -v php >/dev/null || { source "$HERE/../_pending.sh"; emit_pending php; exit 0; }

# H8 fix: run `composer install` automatically when vendor/ is missing (php +
# composer are both available on this host) instead of relying on a
# by-hand step; bench.php itself still degrades to a `pending` record if
# vendor/autoload.php ends up absent for any reason (e.g. composer missing,
# or the sibling axiam-php-sdk checkout/path repo not resolvable).
# The SDK depends on php-amqplib, which declares `ext-sockets`. Composer
# refuses to resolve the dependency graph without it ("it is missing from your
# system"), so on a distro that ships sockets.so but leaves it commented out in
# php.ini — Arch, among others — `composer install` fails and this bench
# degrades to a 'pending' record even though php, composer and the SDK are all
# present. The extension is loadable per-invocation with `-d`, which needs no
# root and edits no system file, so prefer that over failing.
#
# Nothing in this bench actually opens a socket through it: the four measured
# ops are REST-only, and the SDK gates every AMQP code path behind an
# extension_loaded() check. This satisfies composer's platform requirement,
# nothing more. To make it permanent instead, uncomment `extension=sockets` in
# your php.ini (`php --ini` shows which file that is).
PHP_ARGS=()
if ! php -m | grep -qix sockets && php -d extension=sockets -m 2>/dev/null | grep -qix sockets; then
  echo "[php] ext-sockets is available but not enabled in php.ini — loading it for this run only (-d extension=sockets)" >&2
  PHP_ARGS+=(-d extension=sockets)
fi

if [ ! -f "$HERE/vendor/autoload.php" ] && command -v composer >/dev/null 2>&1; then
  echo "[php] vendor/ missing — running 'composer install' (path-repo to the sibling axiam-php-sdk checkout)" >&2
  ( cd "$HERE" && php "${PHP_ARGS[@]}" "$(command -v composer)" install --no-interaction --quiet ) >&2 || \
    echo "[php] composer install failed — bench.php will emit a 'pending' record" >&2
fi

exec php "${PHP_ARGS[@]}" "$HERE/bench.php"
