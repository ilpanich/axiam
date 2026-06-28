# Benchmark Methodology

The value of a benchmark is entirely in its fairness. This document defines the
rules that make an AXIAM-vs-competitor run *comparable*, and the exact meaning of
every metric we report.

## 1. Principles

1. **Identical logical workload.** Every target receives the same sequence of
   logical operations (login, issue token, introspect, refresh, authz-check, …).
   Only the wire encoding differs, isolated in `scenarios/lib/targets.js`.
2. **Standard protocols only.** We exercise OAuth2 (RFC 6749), OIDC, token
   introspection (RFC 7662), and JWKS (RFC 7517). No proprietary endpoints in the
   cross-target comparison. AXIAM-only extras (e.g. the gRPC `AuthorizationService`)
   are measured separately and clearly labelled as non-comparative.
3. **Equal resource envelope.** Every target runs with the *same* CPU and memory
   caps (`--cpus`, `mem_limit`) so that "performance per resource" is meaningful.
   The caps are set in each `targets/<name>/docker-compose.yml` and overridable via
   `BENCH_CPUS` / `BENCH_MEM`.
4. **Same host, back-to-back.** Targets are benchmarked sequentially on the same
   machine, never concurrently, so neither steals CPU/cache/IO from the other.
5. **Warm before measure.** Each scenario runs a warm-up stage (excluded from
   metrics) before the measured stage, so JIT/connection-pool/cache effects do not
   pollute results.
6. **The load generator must not be the bottleneck.** k6 runs on the host (not in
   the capped network), and we assert generator CPU headroom. If k6 saturates,
   the run is flagged invalid in the report.

## 2. The comparison matrix

```
result = f(target, security_profile, scenario)
```

* **target** ∈ { axiam, keycloak, zitadel, … }
* **security_profile** ∈ { p0-plaintext, p1-tls12, p2-tls13, p3-mtls } (see
  `docs/security-profiles.md`)
* **scenario** ∈ the k6 scripts under `scenarios/`

Each cell produces one **result record** (JSON) under `results/`.

## 3. Scenarios

| Scenario file                   | Logical operation                              | Protocol      | Comparative? |
|---------------------------------|------------------------------------------------|---------------|--------------|
| `oauth2_password_login.js`      | Resource-owner login → token (or session)      | HTTP/OAuth2   | Yes          |
| `oauth2_client_credentials.js`  | Machine-to-machine token issuance              | HTTP/OAuth2   | Yes          |
| `token_introspection.js`        | Validate an opaque/JWT token (RFC 7662)        | HTTP/OAuth2   | Yes          |
| `token_refresh.js`              | Refresh-token rotation                          | HTTP/OAuth2   | Yes          |
| `jwks_fetch.js`                 | Fetch signing keys (RFC 7517)                  | HTTP          | Yes          |
| `userinfo.js`                   | OIDC `/userinfo`                                | HTTP/OIDC     | Yes          |
| `authz_check_grpc.js`           | Low-latency authorization decision             | gRPC          | AXIAM-only*  |

\* Most competitors do not expose a directly equivalent low-latency gRPC authz
decision; this scenario is reported separately as an AXIAM capability metric, not
a head-to-head number.

## 4. Load model

Each scenario uses a **closed-loop ramping-VU model** with three stages:

| Stage    | Duration (default) | Counted? | Purpose                         |
|----------|--------------------|----------|---------------------------------|
| warm-up  | `BENCH_WARMUP` 30s | No       | Fill caches/pools, hit steady state |
| measure  | `BENCH_DURATION` 120s | **Yes** | The reported numbers            |
| cool-down| 10s                | No       | Drain in-flight requests        |

VU count, ramp shape, and durations are environment-overridable (see
`scenarios/lib/config.js`). The default targets a *moderate sustained* load; for
saturation/sizing studies, raise `BENCH_VUS` until latency thresholds break and
record the last passing point.

## 5. Metrics

### Performance (from k6)
* **throughput** — successful iterations per second over the measure stage
  (`iterations` rate, 2xx/expected-status only).
* **latency p50 / p95 / p99** — end-to-end request duration (`http_req_duration`,
  or `grpc_req_duration`), in milliseconds.
* **error_rate** — fraction of iterations that failed a check or returned an
  unexpected status. A run with `error_rate > BENCH_MAX_ERROR` (default 1%) is
  marked **invalid**.

### Resource (from the sampler)
Sampled every `BENCH_SAMPLE_INTERVAL` (default 1s) over the measure stage via
`docker stats` on the target's containers (server + datastore + broker):
* **cpu_cores_avg / cpu_cores_p95** — CPU cores consumed (1.0 = one full core).
* **mem_mib_avg / mem_mib_p95** — resident memory in MiB.

### Efficiency (derived, the headline numbers)
* **throughput_per_core** = `throughput / cpu_cores_avg`
  → *requests per second per CPU core.* Higher is better.
* **throughput_per_gib** = `throughput / (mem_mib_avg / 1024)`
  → *requests per second per GiB of RAM.* Higher is better.
* **cpu_ms_per_request** = `(cpu_cores_avg * 1000) / throughput`
  → *CPU-milliseconds spent per request.* Lower is better.

These derived numbers are the answer to *"can AXIAM deliver competitor-level
performance at a lower resource cost?"* — compare `throughput_per_core` and
`cpu_ms_per_request` across targets at equal latency.

### Security cost (derived across profiles)
For a fixed (target, scenario), the report computes the **relative cost** of each
profile vs the `p0-plaintext` baseline:
* **tls_throughput_penalty** = `1 - throughput(profile)/throughput(p0)`
* **tls_latency_overhead_ms** = `p95(profile) - p95(p0)`

This quantifies what each security tier *costs*, so an operator can choose a
posture with eyes open.

## 6. Validity gates

A result record is flagged `valid: false` (and excluded from headline comparisons)
if any hold:
* `error_rate > BENCH_MAX_ERROR`
* generator CPU saturation detected (k6 dropped iterations)
* fewer than `BENCH_MIN_SAMPLES` resource samples captured
* target health check failed during the measure stage

Invalid cells are still written to `results/` (for debugging) but the report lists
them in a separate "excluded" section.

## 7. Reproducibility

Every result record embeds: target image digest, security profile, resource caps,
k6 version, scenario file hash, VU/duration config, and host CPU/RAM. Two runs with
the same embedded config on the same hardware should agree within run-to-run noise
(typically <5% on throughput). Always report the **median of N≥3 runs** for any
published figure; the report's `--repeat` summarization does this for you.
