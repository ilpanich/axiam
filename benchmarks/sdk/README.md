# SDK Client Benchmarks

Measures the **client-side** overhead each official AXIAM SDK adds on top of the
raw protocol calls, so users can choose an SDK with eyes open.

- The contract every SDK bench emits is defined in [`HARNESS-SPEC.md`](HARNESS-SPEC.md).
- `typescript/` and `python/` contain complete reference harnesses (timing loop,
  percentiles, JSON output) with the SDK call left as a clearly-marked TODO.
- `rust/`, `go/`, `java/`, `csharp/`, `php/` are pending stubs with a per-language
  `TODO.md`; each currently emits a valid `pending` record.

The SDKs themselves are under development on `feature/phase-17` (see
`claude_dev/roadmap.md` Phase 17). As each lands, wire its bench per its `TODO.md`
and flip its status to `ok`.

## Run

```bash
cd benchmarks
just sdk-bench      sdk=python      # one SDK
just sdk-bench-all                  # every SDK with a run.sh
# then fold into the report:
python3 sdk/collect.py --results results
```

SDK benches read the same `BENCH_*` env (and seed env) as the server harness, so
they hit the same provisioned tenant/client on a running target.
