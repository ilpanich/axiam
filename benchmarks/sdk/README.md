# SDK Client Benchmarks

Measures the **client-side** overhead each official AXIAM SDK adds on top of the
raw protocol calls, so users can choose an SDK with eyes open.

- The contract every SDK bench emits is defined in [`HARNESS-SPEC.md`](HARNESS-SPEC.md).
- **All 7 benches are wired** to their real SDK: `python/` and `typescript/` against
  the `axiam-sdk` PyPI/npm packages, and `rust/`, `go/`, `java/`, `csharp/`, `php/`
  against their sibling `ilpanich/axiam-<lang>-sdk` checkout via a local
  path/replace/project reference (so they build before the alpha package is on the
  public registry — swap to the published package when available, per each
  `TODO.md`).
- Each emits `status: "ok"` when its toolchain + SDK are installed and a seeded
  target is reachable; otherwise a `pending` (toolchain/package missing) or `error`
  (server unreachable / missing grant) record.

All 7 SDKs (`ilpanich/axiam-{rust,typescript,python,java,csharp,php,go}-sdk`) are
implemented and conform to `sdks/CONTRACT.md`.

## Run

```bash
cd benchmarks
# `just` overrides (sdk=…) must precede the recipe name, else `just` reads them
# as another recipe ("does not contain recipe `sdk=python`").
just sdk=python sdk-bench           # one SDK
just sdk-bench-all                  # every SDK with a run.sh
# then fold into the report:
python3 sdk/collect.py --results results
```

SDK benches read the same `BENCH_*` env (and seed env) as the server harness, so
they hit the same provisioned tenant/client on a running target.
