# SDK Benchmark Harness Specification

The protocol-level scenarios (`benchmarks/scenarios/`) measure the **server**. The
SDK harness measures the **client**: how much latency/CPU each official AXIAM SDK
adds on top of the raw wire calls, so users can pick an SDK knowing its overhead.

The SDKs are still under development on `feature/phase-17` (Rust, TypeScript,
Python, Java, C#, PHP, Go — see `claude_dev/roadmap.md` Phase 17). Each directory
here is a **scaffold**: it documents the contract and emits a `pending` result
until the corresponding SDK lands, at which point you replace the TODO body with
real SDK calls. The contract below is stable, so wiring a finished SDK in is a
drop-in.

## What each SDK bench must do

Exercise the same logical operations as the server scenarios, **through the SDK**:

| op key            | SDK call it should make                                  |
|-------------------|----------------------------------------------------------|
| `client_credentials` | obtain a token via the client-credentials grant        |
| `introspect`      | validate/introspect a token                              |
| `userinfo`        | fetch the current identity                               |
| `authz_check`     | perform an authorization check (gRPC where the SDK supports it) |

For each op: run a warm-up, then N timed iterations against a running, seeded
target (default AXIAM at `$BENCH_HOST:$BENCH_PORT`), and record per-op latency.

## Inputs (environment)

The same env the server harness uses, so `runner/*.sh` can drive both:

```
BENCH_TARGET, BENCH_SCHEME, BENCH_HOST, BENCH_PORT, BENCH_GRPC_ADDR
BENCH_TENANT_ID, BENCH_CLIENT_ID, BENCH_CLIENT_SECRET, BENCH_USERNAME, BENCH_PASSWORD
BENCH_CA_CERT, BENCH_CLIENT_CERT, BENCH_CLIENT_KEY   # for TLS/mTLS profiles
SDK_BENCH_ITERATIONS  (default 2000)
SDK_BENCH_WARMUP      (default 200)
SDK_BENCH_CONCURRENCY (default 16)
```

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
    "client_credentials": { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "introspect":         { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "userinfo":           { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 },
    "authz_check":        { "p50_ms": 0, "p95_ms": 0, "p99_ms": 0, "throughput_rps": 0, "errors": 0 }
  },
  "client_cpu_ms_total": 0,             // optional: CPU consumed by the client process
  "client_rss_mib_peak": 0,             // optional: peak client memory
  "notes": ""
}
```

`status: "pending"` (the current scaffold state) means "SDK not yet wired";
the report lists these as not-yet-measured rather than failures.

## Comparing SDK overhead to the wire baseline

For a given op + profile, the **SDK overhead** is:

```
overhead_p95_ms = sdk.ops[op].p95_ms - server_scenario.p95(op, profile)
```

A well-built SDK adds only serialization + connection-pooling overhead (typically
sub-millisecond p95 on localhost). Large positive overhead points at a per-call
cost the SDK should amortize (e.g. re-creating TLS connections, re-parsing JWKS,
no keep-alive). `sdk/collect.py` computes this delta when both numbers exist.

## How to wire a real SDK (per directory)

1. Add the SDK as a dependency in that directory's manifest
   (`Cargo.toml` / `package.json` / `requirements.txt` / `go.mod` / `pom.xml` /
   `*.csproj` / `composer.json`).
2. Replace the TODO block in the bench entrypoint with real SDK calls for the four
   ops, timing each iteration.
3. Keep the stdout JSON exactly as specified — do not add or rename fields the
   aggregator depends on (`schema`, `sdk`, `status`, `ops.*`).
4. `cd benchmarks && just sdk-bench sdk=<lang>` should print a valid record.
