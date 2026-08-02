# Php SDK benchmark — now wired

The PHP SDK bench is wired to the real SDK (`ilpanich/axiam-php-sdk`, Composer
package `axiam/axiam-sdk`). `bench.php` times the four canonical CONTRACT.md §1
ops (`login`, `refresh`, `check_access`, `batch_check`) and prints one
`axiam.sdk-bench/v1` record to stdout; `run.sh` execs it.

## Running it
1. `run.sh` now runs `composer install` itself when `vendor/` is missing (php +
   composer are both available in this environment), so a bare
   `cd benchmarks && just sdk=php sdk-bench` is enough. `composer.json`
   resolves `axiam/axiam-sdk` from the sibling `../../../../axiam-php-sdk`
   checkout via a `path` repository (the Packagist tag may not exist yet);
   `vendor/` is still not committed (gitignored). If composer itself is
   missing or the install fails, `bench.php` degrades gracefully and emits a
   `status: "pending"` record instead of crashing.
2. `cd benchmarks && just sdk=php sdk-bench` prints the record against a running,
   seeded target.

## H8 fix — `minimum-stability`

`composer install` used to fail outright with "found
axiam/axiam-sdk[dev-<branch>, dev-main, 0.x-dev] but it does not match your
minimum-stability" — a `path` repository with no tagged release resolves as a
`dev-*` version, which composer's default `minimum-stability: stable` rejects.
Fixed by adding `"minimum-stability": "dev"` + `"prefer-stable": true` to this
directory's `composer.json` (the latter keeps any *other* dependency that does
have stable tags from being pulled in as unstable). Verified in this
environment: `composer install` resolves and mirrors the sibling checkout
into `vendor/axiam/axiam-sdk`, and `php bench.php` emits a real `status:
"error"` record against a target it can't reach (as expected pre-seed) rather
than a `pending` one.

## H8 fix — CSRF token never captured after login

`Session::captureCsrfTokenFromResponse()` (in the sibling `axiam-php-sdk`)
existed as a public method but had no caller anywhere — `login()`/
`verifyMfa()` never invoked it, so every state-changing call after login
(`refresh()`, `checkAccess()`, `batchCheck()`) omitted `X-CSRF-Token` and got
403 "CSRF validation failed". Fixed in the sibling repo (see its own commit
log); required re-mirroring the path-repo here (`composer update
axiam/axiam-sdk` or a fresh `composer install` after deleting
`vendor/axiam/axiam-sdk`) to pick it up.

## H8 fix — `BENCH_CA_CERT` not wired

HARNESS-SPEC.md documents `BENCH_CA_CERT` (a CA bundle file path) as an
input every SDK bench should honor under the TLS profiles (p2) — `bench.php`
never read it, so every p2 run failed at the first HTTPS call. Fixed:
`$cfg['custom_ca']` reads it and is passed as `AxiamClient`'s `$customCa`
constructor parameter (a file path — this SDK's own docs confirm that's the
one and only shape it accepts, unlike e.g. the Rust/Go/Java SDKs which want
raw PEM content/bytes). Verified `ok`, double-run-clean at both
p0-plaintext and p2-tls13 against a live seeded target.

## Notes
- The PHP SDK is synchronous (no async client), so this bench is single-process
  and runs every iteration serially — `concurrency` is always `1` and
  `SDK_BENCH_CONCURRENCY` is ignored.

## p3-mtls (CONTRACT.md §6.1) — wired and verified

`build_ops()` reads `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` **once** (not per
`login` iteration) and passes them as the `$clientCert`/`$clientKey`
constructor arguments through a single `$newClient` factory used by both
construction sites.

Note the asymmetry in the SDK's own signature, which the bench has to respect:
`$customCa` is a CA-bundle **file path** (Guzzle `verify`), while
`$clientCert`/`$clientKey` are PEM **strings** (Guzzle `cert`/`ssl_key`, which
the SDK materialises into `0600` temp files internally). All three env vars are
paths, so only the latter two are read.

The pair is all-or-nothing (§6.1 rule 1), and both the validation and the file
reads happen inside `build_ops()` so a misconfiguration surfaces as the
contractual `status:"error"` record.

### ext-sockets

`run.sh` now detects the case where `sockets.so` exists but is commented out in
`php.ini` — the default on Arch and some other distros — and loads it for the
run only (`php -d extension=sockets`). Without it `composer install` refuses to
resolve at all, because the SDK depends on php-amqplib which declares
`ext-sockets`, and this bench degraded to a `pending` record despite php,
composer and the SDK all being present. Nothing here opens a socket through it
(the four measured ops are REST-only and the SDK gates AMQP behind
`extension_loaded()`); it satisfies composer's platform check. Uncomment
`extension=sockets` in your `php.ini` to make it permanent.

```
cd benchmarks && just target=axiam profile=p3-mtls sdk=php sdk-bench
just sdk-bench-test php     # proves the cert reaches the wire, no stack needed
```

Verified: phase A (half-configured pair -> `status:"error"` naming both vars)
and phase B (stub mTLS server observes `CN=bench-client`) both pass.
