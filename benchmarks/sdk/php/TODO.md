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

## Notes
- The PHP SDK is synchronous (no async client), so this bench is single-process
  and runs every iteration serially — `concurrency` is always `1` and
  `SDK_BENCH_CONCURRENCY` is ignored.
