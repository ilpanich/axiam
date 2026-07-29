# SDK Client Benchmarks

Measures the **client-side** overhead each official AXIAM SDK adds on top of the
raw protocol calls, so users can choose an SDK with eyes open.

- The contract every SDK bench emits is defined in [`HARNESS-SPEC.md`](HARNESS-SPEC.md).
- **All 7 primary-language benches are wired** to their real SDK: `python/` and
  `typescript/` against the `axiam-sdk` PyPI/npm packages (a local install/link
  step in `run.sh` when the published package isn't resolvable yet), and
  `rust/`, `go/`, `java/`, `csharp/`, `php/` against their sibling
  `ilpanich/axiam-<lang>-sdk` checkout via a local path/replace/project
  reference (so they build before the alpha package is on the public registry —
  swap to the published package when available, per each `TODO.md`). Four more
  scaffolds (`kotlin/`, `c/`, `cpp/`, `swift/`) exist beyond the 7 primary
  languages; `kotlin/` has validated `ok` records here too, the other three are
  wired but unverified on this host (no toolchain).
- Each emits `status: "ok"` when its toolchain + SDK are installed and a seeded
  target is reachable; otherwise a `pending` (toolchain/package missing) or `error`
  (server unreachable / missing grant) record.

All 7 SDKs (`ilpanich/axiam-{rust,typescript,python,java,csharp,php,go}-sdk`) are
implemented and conform to `sdks/CONTRACT.md`.

## H8 status (measured on this host, not aspirational)

| lang | status | notes |
|---|---|---|
| rust | **validated** | `ok`, double-run-clean against a live p0 **and** p2-tls13 target |
| python | **validated** | `ok`, double-run-clean against a live p0 **and** p2-tls13 target |
| typescript | **validated (p0)** | `ok`, double-run-clean at p0; p2 blocked by an unrelated pre-existing SDK bug (`require('node:https')` inside ESM output — see `TODO.md`) |
| go | **validated** | `ok`, double-run-clean against a live p0 **and** p2-tls13 target |
| java | **validated (p0)** | `ok`, double-run-clean at p0; p2 blocked by an unrelated pre-existing OkHttp hostname-verification bug (rejects a certificate `curl` independently verifies as valid) — see `TODO.md` |
| php | **validated** | `ok`, double-run-clean against a live p0 **and** p2-tls13 target |
| csharp | **honest pending** | `dotnet` is not installed on this host; `run.sh` preflights and prints the exact install commands (see `csharp/TODO.md`) |
| kotlin | bonus — validated (p0) | not one of the 7 primary languages, but its toolchain happened to be available here too |
| c / cpp / swift | pending (untested) | wired against their sibling SDKs but not compiled/run on this host (no toolchain) |

Getting here required two upstream fixes beyond the harness itself, both found
by running these benches against a real, seeded AXIAM server for the first
time: the server never echoed the CSRF token as a response header for
non-browser SDKs to capture (`crates/axiam-api-rest`, fixed on this branch),
and the Rust SDK read the path-scoped `axiam_refresh` cookie from the wrong
URL (fixed in the sibling `axiam-rust-sdk` repo). Three more per-SDK bugs were
found and fixed in the sibling repos along the way (PHP never captured the
post-login CSRF token; the TypeScript SDK never resynced CSRF after a REST
refresh). See `../../claude_dev/improvement-after-g-benchmark.md` §4 "H8" for
the full account.

## Run

```bash
cd benchmarks
# `just` overrides (sdk=…) must precede the recipe name, else `just` reads them
# as another recipe ("does not contain recipe `sdk=python`").
just sdk=python sdk-bench           # one SDK (sources .seed/<target>.seed.env itself — H8)
just sdk-bench-all                  # every SDK with a run.sh
# then fold into the report:
python3 sdk/collect.py --results results
# or generate the full report (server matrix + this SDK section together):
python3 runner/report.py --results results
```

SDK benches read the same `BENCH_*` env (and seed env) as the server harness, so
they hit the same provisioned tenant/client on a running target.
`sdk-bench-all` now writes records under `results/sdk/<profile>/<lang>.json`
(profile-scoped, so a p0 run and a p2 run can coexist instead of the later
one clobbering the earlier one's file — H8).
