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

## H8 fix — `BENCH_CA_CERT` not wired (p2 blocked at the first HTTPS call)

`main.rs` never read `BENCH_CA_CERT` (HARNESS-SPEC.md's documented input for
trusting a TLS profile's throwaway CA), so every p2 run failed at the first
HTTPS call with a certificate-verification error. Fixed: `Cfg` now reads
`BENCH_CA_CERT`, reads the PEM bytes, and `build_client` calls
`AxiamClient::builder().with_custom_ca(pem)` when set. `run.sh` also resolves
the (relative) path to absolute before its `cd "$HERE"`, since
`profiles/*.env` sets it relative to `benchmarks/` and this script changes
directory before the bench ever reads it. Verified `ok`, double-run-clean at
both p0-plaintext and p2-tls13 against a live seeded target. This also
required a companion fix in the sibling `axiam-rust-sdk` (the
`REFRESH_PATH`-scoped-cookie bug — see that repo's own commit log — without
it every `refresh()` failed regardless of TLS profile).

## p3-mtls (CONTRACT.md §6.1)

Wired: `Cfg::from_env` reads `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` (file
paths) into `client_identity_pem`, and `build_client` — the single constructor
behind both the shared client and `Op::Login`'s throwaway one — applies
`builder.with_client_cert(cert_pem, key_pem)`.

```
cd benchmarks && just target=axiam profile=p3-mtls sdk=rust sdk-bench
just sdk-bench-test rust   # proves the cert reaches the wire, no stack needed
```

Verified: phase A (half-configured pair -> `status:"error"` naming both vars)
and phase B (stub mTLS server observes `CN=bench-client`) both pass.
