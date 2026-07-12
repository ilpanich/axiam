# Rust SDK benchmark — wiring TODO

The Rust SDK is implemented (`ilpanich/axiam-rust-sdk`, crate `axiam-sdk`, Phase 16). This
directory is the bench-glue scaffold: it currently emits a `pending` record
conforming to `../HARNESS-SPEC.md` because the bench entrypoint has not been
wired to the SDK yet.

## To wire it up
1. Add the SDK dependency: **Cargo.toml (add axiam-sdk dep)**.
2. Implement a bench entrypoint in this directory that:
   - reads the `BENCH_*` / `SDK_BENCH_*` env (see HARNESS-SPEC.md),
   - times the four ops (`login`, `refresh`, `check_access`, `batch_check`)
     with a warm-up + measured loop,
   - prints exactly one `axiam.sdk-bench/v1` JSON object to stdout with
     `status: "ok"`.
3. Point `run.sh` at it (replace the `emit_pending` fallback with `cargo run --release`).
4. Verify: `cd benchmarks && just sdk-bench sdk=rust` prints a valid record.

See `../typescript/bench.mjs` and `../python/bench.py` for complete reference
harnesses (timing loop, percentile math, JSON contract) to mirror.
