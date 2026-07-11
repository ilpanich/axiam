# Go SDK benchmark — wiring TODO

The Go SDK is planned in `claude_dev/roadmap.md` (Phase 17, T17.7) and
not yet implemented. This directory is a scaffold that currently emits a
`pending` record conforming to `../HARNESS-SPEC.md`.

## To wire it up
1. Add the SDK dependency: **go.mod (go get github.com/axiam/axiam-go)**.
2. Implement a bench entrypoint in this directory that:
   - reads the `BENCH_*` / `SDK_BENCH_*` env (see HARNESS-SPEC.md),
   - times the four ops (`client_credentials`, `introspect`, `userinfo`,
     `authz_check`) with a warm-up + measured loop,
   - prints exactly one `axiam.sdk-bench/v1` JSON object to stdout with
     `status: "ok"`.
3. Point `run.sh` at it (replace the `emit_pending` fallback with `go run .`).
4. Verify: `cd benchmarks && just sdk-bench sdk=go` prints a valid record.

See `../typescript/bench.mjs` and `../python/bench.py` for complete reference
harnesses (timing loop, percentile math, JSON contract) to mirror.
