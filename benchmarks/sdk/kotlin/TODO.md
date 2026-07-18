# Kotlin SDK benchmark — wiring TODO

The Kotlin SDK is implemented (`ilpanich/axiam-kotlin-sdk`). This directory is the bench-glue
scaffold: it currently emits a `pending` record conforming to `../HARNESS-SPEC.md`
because the bench entrypoint has not been wired to the SDK yet.

## To wire it up
1. Add the SDK dependency: **build.gradle.kts (add io.github.ilpanich:axiam-sdk-kotlin dep)**.
2. Implement a bench entrypoint in this directory that:
   - reads the `BENCH_*` / `SDK_BENCH_*` env (see HARNESS-SPEC.md), including the
     `BENCH_CLIENT_CERT` / `BENCH_CLIENT_KEY` / `BENCH_CA_CERT` triple for the
     `p3-mtls` profile (the Kotlin SDK exposes client-cert mTLS per CONTRACT §6.1),
   - times the four ops (`login`, `refresh`, `check_access`, `batch_check`)
     with a warm-up + measured loop,
   - prints exactly one `axiam.sdk-bench/v1` JSON object to stdout with
     `status: "ok"`.
3. Point `run.sh` at it (replace the `emit_pending` fallback with `./gradlew -q --console=plain run`).
4. Verify: `cd benchmarks && just sdk-bench sdk=kotlin` prints a valid record.

See `../typescript/bench.mjs` and `../python/bench.py` for complete reference
harnesses (timing loop, percentile math, JSON contract) to mirror.
