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
cd benchmarks && just sdk-bench sdk=rust
```
`BENCH_RESOURCE_ID` must be a valid UUID (the AXIAM authz endpoints reject
non-UUID resource ids).
