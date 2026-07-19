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
| `authz_check_rest.js`           | Authorization decision (REST)                  | HTTP/REST     | AXIAM-only*  |
| `authz_batch_rest.js`           | Batch authorization decision (REST)            | HTTP/REST     | AXIAM-only*  |
| `authz_check_grpc.js`           | Low-latency authorization decision             | gRPC          | AXIAM-only*  |
| `authz_batch_grpc.js`           | Batch authorization decision                    | gRPC          | AXIAM-only*  |

\* Most competitors do not expose a directly equivalent authorization-decision
endpoint (REST or gRPC, single or batch); these scenarios are reported separately
as AXIAM capability metrics, not head-to-head numbers. The REST authz scenarios
also serve as the wire baseline for SDK `check_access`/`batch_check` overhead
(see `sdk/HARNESS-SPEC.md`). All four require a seeded resource + role grant and a
logged-in user token; the authz scenarios log in as the bench user in `setup()`.

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

`report.py` also keeps a **per-container** breakdown of `cpu_avg`/`mem_avg`
(not just the whole-stack sum) and computes, per cell, a **bottleneck**
column: the container(s) whose `cpu_avg ≥ 0.95 ×` their configured CPU cap
(read from `meta.json`'s `containers[].cpu_cap`, falling back to the
`docker-compose.yml` default for that role — server 2 CPU, DB 2 CPU, broker
1 CPU, TLS edge 1 CPU — if the meta predates that field), or `none` if nothing
in the stack saturated. `none` is itself informative: it means the client, the
network, or an un-pegged serialization point is the limiter, not raw CPU — see
the "Appendix: per-container resource breakdown" section of the generated
report for the full per-container table.

### Host telemetry — CPU frequency, temperature, generator headroom
`docker stats` measures *time-based core utilization*: it cannot distinguish a
core spinning at 3.9 GHz from one throttled to 2.2 GHz. On laptop hardware
(see "Running on a laptop" in `docs/security-profiles.md` / the runbook) that
gap matters, so `resource/host-sampler.sh` runs alongside the container
sampler at the same cadence and writes `<scenario>.host.csv`
(`epoch_ms, cpu_mhz_avg, cpu_mhz_min, temp_c_max, host_cpu_util_pct,
k6_cpu_cores`), all from no-sudo `/sys`/`/proc` reads:
* **mhz_avg** — mean, over the window, of the per-sample mean CPU frequency
  across all online cores (`/sys/…/cpufreq/scaling_cur_freq`).
* **mhz_min / mhz_max ratio** — the lowest single-core frequency seen anywhere
  in the window, divided by the window's peak mean frequency. A number near
  1.0 means the clock stayed flat; a low number means at least one core spent
  time markedly slower than the pack.
* **temp_max** — the hottest thermal zone's peak reading in the window (°C).
* **k6_cores_avg** — CPU cores (not %) consumed by the `k6` process(es)
  themselves during the window.

**Interpretation rule** (from the re-examination of the first full run,
2026-07-19): if repeated CPU-bound cells ~30 min apart agree closely (e.g.
AXIAM introspection p0 vs p2: 2199 vs 2192 req/s) **and** `mhz_avg` stays flat
across the run, cross-target/cross-profile comparisons are not distorted by
throttling — a *constant* sustained-clock reduction depresses all absolute
numbers uniformly, which is invisible to `docker stats` alone but would make
every cell in the run conservative by the same factor, not selectively unfair
to one target. `report.py` flags two conditions automatically:
* **clock_variance** — this cell's `mhz_avg` sagged more than 15% below its
  own window's peak `mhz_avg` — the clock was *not* flat during this specific
  measurement, so treat its absolute numbers with more caution than a
  flagged-clean cell.
* **generator_saturated** — `k6_cores_avg > 0.8 × (host_cpus − stack_cap_cpus)`,
  i.e. k6 itself was eating most of the CPU headroom left after the target
  stack's caps — the load generator may be the bottleneck, not the target.

Both flags appear in the `host_flags` column of the "All results" table.

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

`report.py`'s efficiency tables also render a **server-container-only**
variant of both numbers, computed against just the primary server/app
container's CPU+mem (excluding the database, broker, and TLS edge
containers). AXIAM's stack includes a broker (RabbitMQ) that Keycloak and
Zitadel don't; the whole-stack numbers above fold that cost in silently, while
the server-only variant isolates it so it stays visible rather than
understating AXIAM's per-request server cost relative to a single-process
competitor.

### Comparability flags (fallback operations)
Some logical ops can't always be measured for real on every target — e.g.
Zitadel generally ships ROPC disabled, so its `login()` adapter falls back to
`client_credentials` (see `scenarios/lib/targets.js`); `token_refresh.js`
falls back the same way when a target issues no refresh token to rotate; and
`userinfo.js`'s `setup()` falls back to a client_credentials token only if
minting a real user token fails. Every fallback increments the `bench_fallback`
k6 counter for that iteration. A cell with `bench_fallback > 0` is still
**valid** (it passed the normal validity gates) but is annotated
`comparability: fallback-op`, shown with `fallback: yes` in the full results
table, and **excluded from head-to-head efficiency/winner tables** — a
fallback op measures a different (usually cheaper) operation than its label,
so ranking it against a real login/refresh would be comparing different
things under the same name.

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

Every result record's `meta.json` embeds, per cell: `target`/`profile`/`scenario`,
security profile (`scheme`, `tls_min`, `client_auth`), resource caps (`caps`),
rate-limit posture, VU/duration config, and host CPU/RAM (`host`). It also
records, for full reproducibility of *what actually ran*:
* **containers** — for every container in the target's stack: `name`, `role`
  (server/db/mq/edge), `image`, `image_digest` (from
  `docker inspect --format '{{.Config.Image}} {{index .RepoDigests 0}}'`), and
  the `cpu_cap` it was measured against.
* **scenario_sha256** — hash of the exact `scenarios/<name>.js` file executed
  (`sha256sum`), so a report can be traced back to the harness code that
  produced it even after the scenario file later changes.
* **batch_size** — `BENCH_BATCH_SIZE` (default 5), the batch-authz request size.
* **host_kernel**, **docker_version**, **cpu_model**, **cpu_governor** — host
  facts (`uname -r`, `docker version`, `/proc/cpuinfo`,
  `/sys/…/cpufreq/scaling_governor`).
* **k6_cpu_cores_avg** — the generator's own CPU consumption over the measure
  window (from the A6 host sampler), the basis for `generator_saturated`.

`report.py` tolerates older `meta.json` files that predate any of the above —
missing fields degrade to sensible defaults (e.g. compose-file CPU cap
defaults instead of a recorded `cpu_cap`) rather than crashing the report.

Two runs with the same embedded config on the same hardware should agree within
run-to-run noise (typically <5% on throughput). Always report the **median of
N≥3 runs** for any published figure; the report's `--repeat` summarization does
this for you.

**Sharing results.** `runner/seed.sh` writes client secrets and the bench
user's password to `.seed/<target>.seed.env`, which is gitignored and lives
outside `results/`. `results/` itself holds nothing secret. To hand off or
publish a run, use `just bench-pack`: it archives only `*.k6.json`,
`*.res.csv`, `*.host.csv`, `*.meta.json`, and `report.md` into
`results-<date>.tar.xz`, and verifies (grepping the packed content for
`SECRET`/`PASSWORD`) that nothing sensitive made it in before leaving the
archive on disk.
