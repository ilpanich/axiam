# SDK Client Benchmarks

Measures the **client-side** overhead each official AXIAM SDK adds on top of the
raw protocol calls, so users can choose an SDK with eyes open.

- The contract every SDK bench emits is defined in [`HARNESS-SPEC.md`](HARNESS-SPEC.md).
- `typescript/` and `python/` are wired to the real SDKs (`axiam-sdk` npm package,
  `axiam-sdk` PyPI package) and emit `status: "ok"` records.
- `rust/`, `go/`, `java/`, `csharp/`, `php/` are pending stubs with a per-language
  `TODO.md`; each currently emits a valid `pending` record.

All 7 SDKs (`ilpanich/axiam-{rust,typescript,python,java,csharp,php,go}-sdk`) are
implemented and conform to `sdks/CONTRACT.md`. The five stubs above are missing only their
bench glue, not the SDK itself — wire each per its `TODO.md` and flip its status
to `ok`.

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
