# Php SDK benchmark — now wired

The PHP SDK bench is wired to the real SDK (`ilpanich/axiam-php-sdk`, Composer
package `axiam/axiam-sdk`). `bench.php` times the four canonical CONTRACT.md §1
ops (`login`, `refresh`, `check_access`, `batch_check`) and prints one
`axiam.sdk-bench/v1` record to stdout; `run.sh` execs it.

## Running it
1. `composer install` in this directory first. `composer.json` resolves
   `axiam/axiam-sdk` from the sibling `../../../../axiam-php-sdk` checkout via a
   `path` repository (the Packagist tag may not exist yet); `vendor/` is not
   committed. Until `composer install` is run, `bench.php` degrades gracefully and
   emits a `status: "pending"` record.
2. `cd benchmarks && just sdk=php sdk-bench` prints the record against a running,
   seeded target.

## Notes
- The PHP SDK is synchronous (no async client), so this bench is single-process
  and runs every iteration serially — `concurrency` is always `1` and
  `SDK_BENCH_CONCURRENCY` is ignored.
