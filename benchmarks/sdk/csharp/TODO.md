# Csharp SDK benchmark — wiring TODO

The Csharp SDK is planned in `claude_dev/roadmap.md` (Phase 17, T17.5) and
not yet implemented. This directory is a scaffold that currently emits a
`pending` record conforming to `../HARNESS-SPEC.md`.

## To wire it up
1. Add the SDK dependency: ***.csproj (dotnet add package Axiam.Sdk)**.
2. Implement a bench entrypoint in this directory that:
   - reads the `BENCH_*` / `SDK_BENCH_*` env (see HARNESS-SPEC.md),
   - times the four ops (`client_credentials`, `introspect`, `userinfo`,
     `authz_check`) with a warm-up + measured loop,
   - prints exactly one `axiam.sdk-bench/v1` JSON object to stdout with
     `status: "ok"`.
3. Point `run.sh` at it (replace the `emit_pending` fallback with `dotnet run -c Release`).
4. Verify: `cd benchmarks && just sdk-bench sdk=csharp` prints a valid record.

See `../typescript/bench.mjs` and `../python/bench.py` for complete reference
harnesses (timing loop, percentile math, JSON contract) to mirror.
