# SDK Benchmark Harness Specification

The protocol-level scenarios (`benchmarks/scenarios/`) measure the **server**. The
SDK harness measures the **client**: how much latency/CPU each official AXIAM SDK
adds on top of the raw wire calls, so users can pick an SDK knowing its overhead.

All 7 SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go — the `ilpanich/axiam-<lang>-sdk`
repositories) are implemented and conform to `sdks/CONTRACT.md`.
The `python/` and `typescript/` bench directories are wired against the real SDKs
(`SDK_WIRED = True`/`true`). The remaining five (`rust/`, `go/`, `java/`, `csharp/`,
`php/`) are scaffolds with a per-language `TODO.md`: the SDK itself exists, only
the bench glue is pending. Each unwired scaffold documents the contract and emits
a `pending` result until wired.

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
BENCH_CA_CERT, BENCH_CLIENT_CERT, BENCH_CLIENT_KEY   # for TLS/mTLS profiles
SDK_BENCH_ITERATIONS  (default 2000)
SDK_BENCH_WARMUP      (default 200)
SDK_BENCH_CONCURRENCY (default 16)
```

SDK clients authenticate with `tenant_slug` (`BENCH_TENANT_SLUG`, default
`"default"`), not the tenant UUID — the tenant UUID (`BENCH_TENANT_ID`) is still
needed for scenarios/adapters that address the tenant by id.

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

`sdk/collect.py` computes this delta only where a directly comparable k6 scenario
exists (`login` → `oauth2_password_login`, since both hit
`POST /api/v1/auth/login`). `refresh` has no exact wire counterpart:
`scenarios/token_refresh.js` exercises the OAuth2 `refresh_token` grant
(`/oauth2/token`), while the SDK's `refresh()` calls the session endpoint
(`/api/v1/auth/refresh`) — different wire paths, so no overhead delta is
computed for it. `check_access`/`batch_check` are REST calls
(`POST /api/v1/authz/check[/batch]`) in every SDK; the closest k6 scenarios
(`authz_check_grpc.js`, `authz_batch_grpc.js`) measure the gRPC
`AuthorizationService`, which those scenarios' own comments already flag as
NON-COMPARATIVE — so overhead for those two ops is approximate at best until a
REST-based k6 authz scenario exists.

A well-built SDK adds only serialization + connection-pooling overhead (typically
sub-millisecond p95 on localhost). Large positive overhead points at a per-call
cost the SDK should amortize (e.g. re-creating TLS connections, re-parsing JWKS,
no keep-alive).

## How to wire the remaining SDKs (rust/go/java/csharp/php)

1. Add the SDK as a dependency in that directory's manifest
   (`Cargo.toml` / `go.mod` / `pom.xml` / `*.csproj` / `composer.json`).
2. Replace the TODO block in the bench entrypoint with real SDK calls for the
   four ops (`login`, `refresh`, `check_access`, `batch_check`), timing each
   iteration. See `python/bench.py` and `typescript/bench.mjs` for the complete
   reference implementations (timing loop, percentile math, JSON contract).
3. Keep the stdout JSON exactly as specified — do not add or rename fields the
   aggregator depends on (`schema`, `sdk`, `status`, `ops.*`).
4. `cd benchmarks && just sdk-bench sdk=<lang>` should print a valid record.
