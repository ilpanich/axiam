# Rust SDK benchmark — wired

The Rust SDK bench is now wired to the real SDK (`ilpanich/axiam-rust-sdk`,
crate `axiam-sdk`). `src/main.rs` builds an `AxiamClient` and times the four
canonical CONTRACT.md §1 ops — `login`, `refresh`, `check_access`,
`batch_check` — with a warm-up + measured loop, then prints one
`axiam.sdk-bench/v1` JSON record to stdout (see `../HARNESS-SPEC.md`).

## How it's wired
- `Cargo.toml` depends on `axiam-sdk` via a **path dep** on the sibling
  checkout (`../../../../axiam-rust-sdk`), `default-features = false,
  features = ["rest"]` (only the REST transport is exercised). An empty
  `[workspace]` table keeps this crate a standalone workspace so the parent
  `axiam/` workspace never absorbs it.
- For a reproducible published build, swap the path dep for the crates.io
  release pinned to **`=1.0.0-alpha7`** (the first alpha that builds under
  edition 2024):
  `axiam-sdk = { version = "=1.0.0-alpha7", default-features = false, features = ["rest"] }`
- `refresh` is timed serially (concurrency 1) because the SDK single-flight-
  guards refresh; the other three ops run at `SDK_BENCH_CONCURRENCY`.
- On setup failure (server down / bad creds / non-UUID `BENCH_RESOURCE_ID`) it
  emits a zeroed `status: "error"` record and exits 0.

## Run
```
cd benchmarks && just sdk=rust sdk-bench
```
`BENCH_RESOURCE_ID` must be a valid UUID (the AXIAM authz endpoints reject
non-UUID resource ids).

## H8 fix — `BENCH_RESOURCE_ID must be a valid UUID (got "")`

`bash sdk/rust/run.sh` invoked directly (bypassing both `just sdk-bench`'s
seed sourcing and `sdk-bench-all`'s `run-all.sh`, which already sourced the
seed env) never saw `.seed/<target>.seed.env`, so `BENCH_RESOURCE_ID` arrived
empty and the bench's own UUID-format check failed fast with an empty value.
Fixed at the source: `just sdk-bench` now sources `.seed/<target>.seed.env`
itself before invoking any `run.sh` and fails fast (naming the exact missing
var) if `BENCH_RESOURCE_ID`/`BENCH_SUBJECT_ID`/etc. are still empty
afterwards (see `../../justfile`'s `sdk-bench` recipe). `run.sh` in this
directory also sources the seed env directly as a second line of defense for
callers that invoke it without `just`. Verified: `cargo run --release` builds
and runs cleanly with a real seeded `BENCH_RESOURCE_ID`, and fails fast with a
clear message (not a Rust panic) when no seed env is reachable at all.
