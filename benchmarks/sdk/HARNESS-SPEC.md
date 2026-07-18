# SDK Benchmark Harness Specification

The protocol-level scenarios (`benchmarks/scenarios/`) measure the **server**. The
SDK harness measures the **client**: how much latency/CPU each official AXIAM SDK
adds on top of the raw wire calls, so users can pick an SDK knowing its overhead.

All 7 SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go — the `ilpanich/axiam-<lang>-sdk`
repositories) are implemented and conform to `sdks/CONTRACT.md`, and **all seven
bench directories are now wired** against their real SDK (`python/`, `typescript/`,
`rust/`, `go/`, `java/`, `csharp/`, `php/`). Each emits an `ok` record when its
SDK package/toolchain is installed and a seeded target is reachable, and degrades
to a `pending` (toolchain/package missing) or `error` (server unreachable / grant
missing) record otherwise. The compiled-language benches depend on their SDK via a
local path/replace/project reference (see each `sdk/<lang>/TODO.md`) so they build
against the sibling `axiam-<lang>-sdk` checkout when the package is not yet on the
public registry.

## What each SDK bench must do

Exercise the canonical SDK operations locked in `sdks/CONTRACT.md` §1, **through
the SDK** (not raw HTTP):

| op key         | SDK call it should make (canonical name, per-language spelling in CONTRACT.md §1) |
|-----------------|-------------------------------------------------------------------------------|
| `login`         | `login(email, password)` — `POST /api/v1/auth/login`                          |
| `refresh`       | `refresh()` — `POST /api/v1/auth/refresh`                                     |
| `check_access`  | `check_access(action, resource_id[, scope])` (or its `can` alias)             |
| `batch_check`   | `batch_check(checks)` — results in input order                                |

For each op: run a warm-up, then N timed iterations against a running, seeded
target (default AXIAM at `$BENCH_HOST:$BENCH_PORT`), and record per-op latency.

**Measure `refresh` serially (concurrency 1).** Every SDK guards `refresh()` with
a single-flight lock, so under `SDK_BENCH_CONCURRENCY` concurrent callers N
refreshes coalesce into ~1 wire call — concurrent refresh throughput would not
reflect wire cost. The reference harnesses (and all wired benches) run `login`,
`check_access` and `batch_check` at `SDK_BENCH_CONCURRENCY` but `refresh` at
concurrency 1. `refresh()` also requires a prior successful `login()` on the same
client instance.

**Out of SDK-harness scope.** `oauth2_token` (client-credentials grant),
`introspect`, and `userinfo` are real AXIAM server endpoints (`/oauth2/token`,
`/oauth2/introspect`, `/oauth2/userinfo`) and are measured at the protocol level
by the k6 scenarios (`scenarios/oauth2_client_credentials.js`,
`scenarios/token_introspection.js`, `scenarios/userinfo.js`). No SDK wraps them
by contract — CONTRACT.md §1 locks the SDK method vocabulary to `login`,
`verify_mfa`, `refresh`, `logout`, `check_access`/`can`, and `batch_check` only —
so there is no SDK client call to time for these three ops. Do not add them to
an SDK bench's `ops`.

## Inputs (environment)

The same env the server harness uses, so `runner/*.sh` can drive both:

```
BENCH_TARGET, BENCH_SCHEME, BENCH_HOST, BENCH_PORT, BENCH_GRPC_ADDR
BENCH_TENANT_ID, BENCH_TENANT_SLUG, BENCH_CLIENT_ID, BENCH_CLIENT_SECRET, BENCH_USERNAME, BENCH_PASSWORD
BENCH_ACTION          (default "read")      # action for check_access/batch_check
BENCH_RESOURCE_ID     (seeded resource UUID) # subject of the authz checks
BENCH_SUBJECT_ID      (seeded user UUID)      # the bench user's id
BENCH_CA_CERT         # custom CA for server verification under TLS profiles
SDK_BENCH_ITERATIONS  (default 2000)
SDK_BENCH_WARMUP      (default 200)
SDK_BENCH_CONCURRENCY (default 16)
```

SDK clients authenticate with `tenant_slug` (`BENCH_TENANT_SLUG`, default
`"default"`), not the tenant UUID — the tenant UUID (`BENCH_TENANT_ID`) is still
needed for scenarios/adapters that address the tenant by id.

`BENCH_RESOURCE_ID` and `BENCH_SUBJECT_ID` are written by `runner/seed.sh`, which
provisions a resource plus a role holding a `read` permission grant assigned to
the bench user — so `check_access(read, BENCH_RESOURCE_ID)` returns `allowed=true`.
The server rejects a non-UUID `resource_id` (400), so a bench that batches checks
must reuse this UUID, not synthesize per-index ids.

**Security-profile limitation.** No AXIAM SDK currently exposes an mTLS
client-certificate option (only a custom-CA-for-server-verification escape hatch),
so the SDK benches run the p0–p2 profiles only; the `p3-mtls` profile is exercised
by the k6 protocol scenarios (`scenarios/lib/config.js` `tlsAuth`), not by the SDK
harness. `BENCH_CLIENT_CERT`/`BENCH_CLIENT_KEY` therefore apply to the k6
scenarios, not to SDK benches, until the SDKs grow a client-cert option.

## Output (stdout, single JSON object) — the stable contract

Each SDK bench prints exactly one JSON object matching this schema to stdout. The
aggregator (`sdk/collect.py`) reads them and folds them into the main report's
"SDK client overhead" section.

```json
{
  "schema": "axiam.sdk-bench/v1",
  "sdk": "typescript",
  "sdk_version": "0.1.0",
  "language_runtime": "node 22.3.0",
  "target": "axiam",
  "profile": "p2-tls13",
  "status": "ok",                       // "ok" | "pending" | "error"
  "iterations": 2000,
  "concurrency": 16,
  "ops": {
    "login":         { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "refresh":        { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "check_access":   { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "batch_check":    { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 }
  },
  "client_cpu_ms_total": 0,             // optional: CPU consumed by the client process
  "client_rss_mib_peak": 0,             // optional: peak client memory
  "notes": ""
}
```

`status: "pending"` (the current state of the five unwired scaffolds) means "SDK
bench glue not yet wired"; the report lists these as not-yet-measured rather than
failures.

## Comparing SDK overhead to the wire baseline

For a given op + profile, the **SDK overhead** is:

```
overhead_p95_ms = sdk.ops[op].p95_ms - server_scenario.p95(op, profile)
```

`sdk/collect.py` computes this delta where a directly comparable k6 scenario
exists:
- `login` → `oauth2_password_login` (both hit `POST /api/v1/auth/login`).
- `check_access` → `authz_check_rest` and `batch_check` → `authz_batch_rest`
  (both hit `POST /api/v1/authz/check[/batch]`, the same wire path the SDKs use),
  so these deltas are now genuinely comparable. The gRPC authz scenarios
  (`authz_check_grpc.js`, `authz_batch_grpc.js`) remain a separate AXIAM
  capability metric and are NOT used for SDK-overhead deltas.
- `refresh` has no exact wire counterpart: `scenarios/token_refresh.js` exercises
  the OAuth2 `refresh_token` grant (`/oauth2/token`), while the SDK's `refresh()`
  calls the session endpoint (`/api/v1/auth/refresh`) — different wire paths, so
  no overhead delta is computed for it.

A well-built SDK adds only serialization + connection-pooling overhead (typically
sub-millisecond p95 on localhost). Large positive overhead points at a per-call
cost the SDK should amortize (e.g. re-creating TLS connections, re-parsing JWKS,
no keep-alive).

## Running a wired SDK bench

All seven benches are wired. To run one you need its toolchain and the SDK
package resolvable:

1. Each compiled-language manifest (`Cargo.toml` / `go.mod` / `pom.xml` /
   `*.csproj` / `composer.json`) references its SDK via a local path/replace/
   project reference to the sibling `axiam-<lang>-sdk` checkout, so it builds even
   before the alpha package is published to the public registry. Swap that for the
   published package reference once available (see each `sdk/<lang>/TODO.md`).
2. `cd benchmarks && just sdk=<lang> sdk-bench` prints one `axiam.sdk-bench/v1`
   record. `just sdk-bench-all` runs every language and folds the results in.
3. The stdout JSON contract is fixed — do not add or rename fields the aggregator
   depends on (`schema`, `sdk`, `status`, `ops.*`). Op keys stay snake_case
   (`check_access`, `batch_check`) even where the SDK method is camel/Pascal-case.
4. `python/bench.py` and `typescript/bench.mjs` remain the reference
   implementations for the timing loop, percentile math, and JSON contract.
