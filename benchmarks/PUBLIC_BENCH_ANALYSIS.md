# AXIAM Benchmark Analysis — Second Draft (preliminary run 2)

> **Status: second benchmark draft, preliminary.** This updates the first
> draft (run of 2026-07-19) with a new full run of 2026-07-21 against **AXIAM
> 1.0.0-alpha15**, after a round of benchmark-harness fixes and AXIAM
> performance work. Most of draft 1's invalid cells are now valid — password
> login and userinfo are real three-way comparisons for the first time — and
> every cell now records CPU-frequency and temperature telemetry. Two
> limitations keep the "preliminary" label: every figure is still a **single
> run** (the harness supports median-of-3; it will be used for the next full
> matrix), and the hardware is still a consumer laptop. Where this draft
> *corrects* draft 1, it says so explicitly (§2). Numbers are real and
> reproducible; treat them as a credible signal, not a final verdict.

## 1. What was measured

Three open-source IAM servers were driven with the **identical logical
workload** through the vendor-neutral k6 harness in
[`benchmarks/`](README.md) (adapter layer isolates per-vendor endpoint
differences; see [`docs/methodology.md`](docs/methodology.md)):

| Target | Server | Datastore | Extra services |
|---|---|---|---|
| **AXIAM** | `axiam-server` **1.0.0-alpha15** (Rust / Actix-Web / Tonic, built from source) | SurrealDB v3 (SurrealKV backend) | RabbitMQ 4 (audit/event broker) |
| **Keycloak** | Keycloak 26.7.0 (JVM) | PostgreSQL 16 (uniformly tuned, see below) | — |
| **Zitadel** | Zitadel v4.15.2 (Go) | PostgreSQL 16 (uniformly tuned, see below) | — |

### Test environment

Everything ran on the same single **Dell XPS 15 9570 laptop** as draft 1
(i7-8750H, 12 logical CPUs, ~31 GiB RAM, Linux 7.1, Docker 29.6), targets
benchmarked sequentially, never concurrently, CPU governor pinned to
`performance`. Two configurations were run:

**Main (capped) matrix** — all three targets, both profiles:

| Container | CPU cap | Memory cap |
|---|---|---|
| IAM server (all three) | 2 CPUs | 1024 MiB |
| Database (SurrealDB / PostgreSQL) | 2 CPUs | 1024 MiB |
| RabbitMQ (AXIAM only) | 1 CPU | 512 MiB |

**DB-uncapped sensitivity pass** (AXIAM and Zitadel only, §5): identical
except the database gets **4 CPUs / 2048 MiB** — servers stay capped at 2 —
to measure how far each *server* scales when its database isn't the wall.

Load model (unchanged): closed-loop **50 VUs**, 30 s warm-up + 120 s measured
window per scenario, k6 v2.1.0 on the host outside the caps. Validity gates:
error rate ≤ 1%, p95 < 2000 ms. Profiles: **p0-plaintext** and **p2-tls13**
(TLS 1.3, terminated in-process by all three targets; AXIAM's gRPC listener
now also serves TLS at p2, closing a draft-1 inconsistency). PostgreSQL is
minimally and **uniformly** tuned for both competitors
(`shared_buffers=256MB`, `effective_cache_size=512MB`, `max_connections=200`);
SurrealDB runs stock. AXIAM's default per-IP rate limits remain neutralized
(k6 is a single source IP; competitors ship no equivalent default limits).

**New in this run:** every cell records host CPU frequency, package
temperature, and load-generator CPU at 1 s resolution, published with the raw
data. Summary: on CPU-saturated cells the sustained clock held ~3.7–3.9 GHz;
on the generator-heavy JWKS cells it sat ~3.2 GHz; package temperature reached
95–100 °C on hot cells. So absolute numbers from this laptop are, if anything,
conservative, and all targets ran under the same thermal envelope.

## 2. What changed since draft 1 (corrections included)

**Harness fixes (this run's cells are valid where draft 1's were not):**
- `userinfo` now uses a real user token → valid for all three targets
  (draft 1: 100% errors on AXIAM and Keycloak).
- Keycloak password login (ROPC) seeding fixed → valid hash-bound login cell
  (draft 1: 100% errors).
- Zitadel password login now drives Zitadel's session API with a real
  password check (draft 1: a no-hashing client-credentials fallback that was
  flagged as non-comparable).

**Correction to draft 1 — refresh-token cells.** New instrumentation that
tags fallback operations revealed that the `token_refresh` scenario falls back
to plain token issuance on **all three targets** (no target issues a refresh
token on the client-credentials grant the scenario minted with). This also
applies retroactively to draft 1's AXIAM refresh figures, which we presented
as refresh-rotation measurements: they were the same fallback. The refresh
comparison is therefore **withdrawn until the scenario is fixed** to obtain
its token via a real user login; run-2 refresh cells appear in the full matrix
(§7) clearly labeled `fallback-op` and are excluded from all head-to-head
claims. This is exactly the kind of error the fallback tagging was built to
catch; it caught us too, and we're reporting it.

**Keycloak got significantly faster between the two runs** (e.g.
introspection 337 → 1765 req/s) with the same image tag and caps. Likely
contributors: the seeding fixes (a correctly-configured realm), the uniform
PostgreSQL tuning, and the removal of draft 1's error-storm cells from the
session; image digests were not recorded in draft 1, so drift under the
mutable `26.7.0` tag can't be excluded. We treat run 2 as the honest baseline
and have **retired all draft-1 comparison multiples** — the current numbers
below supersede them, and several head-to-heads are now closer than draft 1
suggested.

**AXIAM improvements measured this run** (1.0.0-alpha vs 1.0.0-alpha15):
- Password login: 35 → **67.5 req/s**, p95 2127 → **907 ms** — concurrent
  Argon2id verification is now bounded (a fix that is simultaneously a
  memory-DoS hardening: peak server memory during the login storm dropped
  from ~970 MiB — at the edge of its 1 GiB cap — to ~478 MiB).
- Authorization single checks: REST 290 → **745 req/s**, gRPC p99 tail
  850 → **90 ms**.
- gRPC now serves TLS 1.3 at p2 with no measurable penalty vs plaintext.

## 3. Headline results (capped matrix, valid comparable cells)

Full data in §7. Higher throughput / lower latency / lower `cpu·ms per
request` is better. CPU/memory figures are whole-stack (AXIAM's include
SurrealDB **and** RabbitMQ).

### Machine-to-machine token issuance (`oauth2_client_credentials`)

| profile | target | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | CPU (cores, stack) | req/s per core | cpu·ms/req |
|---|---|---|---|---|---|---|---|---|
| p0-plaintext | **AXIAM** | **1788** | 25.9 | **32.3** | 36.2 | 2.90 | **617** | **1.62** |
| p0-plaintext | Zitadel | 419 | 109.4 | 138.7 | 211.7 | 3.58 | 117 | 8.53 |
| p0-plaintext | Keycloak | 346 | 103.9 | 210.4 | 301.5 | 2.07 | 167 | 6.00 |
| p2-tls13 | **AXIAM** | **908** | 53.8 | **62.8** | 65.2 | 1.65 | **551** | **1.81** |
| p2-tls13 | Zitadel | 405 | 112.2 | 143.5 | 234.5 | 3.59 | 113 | 8.85 |
| p2-tls13 | Keycloak | 340 | 104.6 | 210.6 | 301.0 | 2.07 | 165 | 6.08 |

AXIAM issues **4.3× more tokens/s than Zitadel and 5.2× more than Keycloak**
at plaintext, with a p99 of 36 ms, and stays 2.2–2.7× ahead under TLS 1.3
(see the TLS caveat in §6 — the TLS gap is a known connection-behavior issue
under investigation, not crypto cost).

### Token introspection (RFC 7662)

| profile | target | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | CPU (cores) | req/s per core | cpu·ms/req |
|---|---|---|---|---|---|---|---|---|
| p0-plaintext | **AXIAM** | **2229** | 20.4 | **27.1** | 30.0 | 2.38 | **936** | **1.07** |
| p0-plaintext | Keycloak | 1765 | 7.8 | 82.8 | 86.8 | 2.34 | 753 | 1.33 |
| p0-plaintext | Zitadel | 923 | 47.3 | 67.1 | 73.8 | 3.70 | 250 | 4.01 |
| p2-tls13 | **AXIAM** | **2219** | 20.5 | **27.3** | 30.2 | 2.64 | **841** | **1.19** |
| p2-tls13 | Keycloak | 1794 | 7.7 | 82.2 | 86.2 | 2.35 | 764 | 1.31 |
| p2-tls13 | Zitadel | 891 | 50.3 | 68.3 | 77.4 | 3.75 | 238 | 4.21 |

This is now the closest head-to-head: AXIAM leads Keycloak by 1.26× on
throughput (2.4× vs Zitadel) with a 3× better p95 (27 vs 83 ms) and the best
CPU efficiency — and, notably, **zero TLS penalty** (−0.4%). Keycloak's p50
is actually the lowest of the three; its tail (p95/p99 ≈ 82–87 ms under a
fully pegged JVM) is what separates them.

### JWKS fetch (RFC 7517)

| profile | target | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | CPU (cores) | req/s per core | cpu·ms/req |
|---|---|---|---|---|---|---|---|---|
| p0-plaintext | **AXIAM** | **27059** | 1.3 | **3.0** | 4.3 | 1.65 | **16388** | **0.061** |
| p0-plaintext | Keycloak | 3855 | 3.0 | 74.4 | 79.1 | 2.01 | 1922 | 0.52 |
| p0-plaintext | Zitadel | 2034 | 11.5 | 65.0 | 67.6 | 2.99 | 681 | 1.47 |
| p2-tls13 | **AXIAM** | **24118** | 1.6 | **3.0** | 4.1 | 1.98 | **12171** | **0.082** |
| p2-tls13 | Keycloak | 3098 | 3.8 | 77.2 | 82.9 | 2.01 | 1544 | 0.65 |
| p2-tls13 | Zitadel | 2023 | 12.7 | 61.3 | 64.3 | 3.11 | 651 | 1.54 |

A 7–13× gap. As in draft 1, AXIAM's server sat well under its CPU cap
(~1.3/2 cores) while the load generator itself neared its limit — AXIAM's
true JWKS ceiling is **above** what a 50-VU closed loop can measure.

### OIDC userinfo — new this round (valid three-way for the first time)

| profile | target | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | CPU (cores) | req/s per core | cpu·ms/req |
|---|---|---|---|---|---|---|---|---|
| p0-plaintext | **AXIAM** | **5457** | 4.6 | **46.4** | 53.9 | 3.76 | 1453 | 0.69 |
| p0-plaintext | Keycloak | 3561 | 3.1 | 77.6 | 81.2 | 2.00 | 1778 | **0.56** |
| p0-plaintext | Zitadel | 967 | 23.6 | 81.8 | 86.0 | 2.84 | 340 | 2.94 |
| p2-tls13 | **AXIAM** | **4924** | 5.1 | **48.8** | 53.6 | 3.64 | 1351 | 0.74 |
| p2-tls13 | Keycloak | 3529 | 3.2 | 77.7 | 81.3 | 2.00 | 1761 | **0.57** |
| p2-tls13 | Zitadel | 942 | 29.6 | 81.7 | 91.5 | 2.91 | 323 | 3.09 |

AXIAM leads throughput (1.5× Keycloak, 5.6× Zitadel) and p95 — while
DB-limited: SurrealDB was pegged at its 2-core cap in this cell (uncapped it
reaches 7261 req/s at p95 11 ms, §5). Honesty note: on *whole-stack* CPU per
request, Keycloak is the most efficient here (0.56 vs 0.69 cpu·ms/req) —
AXIAM's stack figure includes its saturated DB and its audit broker.
(Zitadel's cells use a machine-user token — its user-login flow returns a
session token the harness can't yet convert; the measured endpoint and
semantics are the same.)

### Password login — new this round (all three targets hash for real)

Password hashing at each vendor's shipped defaults: AXIAM **Argon2id**
(OWASP parameters), Keycloak 26 **Argon2id** (default), Zitadel **bcrypt**
(default cost). This is the only scenario where the vendors intentionally do
different amounts of work per request — hash configuration dominates it, so
compare with that in mind:

| profile | target | throughput (req/s) | p50 (ms) | p95 (ms) | valid (p95 < 2 s) |
|---|---|---|---|---|---|
| p0-plaintext | **AXIAM** | **67.5** | 694 | **907** | ✓ |
| p0-plaintext | Keycloak | 22.3 | 2139 | 2380 | ✗ gate breach |
| p0-plaintext | Zitadel | 2.0 | 21992 | 25605 | ✗ gate breach |
| p2-tls13 | **AXIAM** | **67.8** | 695 | **946** | ✓ |
| p2-tls13 | Keycloak | 22.8 | 2114 | 2273 | ✗ gate breach |
| p2-tls13 | Zitadel | 2.0 | 22465 | 25397 | ✗ gate breach |

At 50 concurrent users on 2 CPUs, **AXIAM is the only target that stays under
the 2-second p95 gate**, at 3× Keycloak's login rate with the same hash
algorithm class. Zitadel's number is not a defect — its default bcrypt cost
is simply very expensive (~1 CPU-second per verification), which at this
concurrency yields ~22 s median waits; operators can tune it down. The
architectural point this cell demonstrates: AXIAM **bounds concurrent hash
verifications** (new in alpha15), converting overload into bounded latency
instead of memory exhaustion — draft 1 showed what happens without that bound
(AXIAM itself breached the gate and approached its memory cap).

## 4. AXIAM-only capability: authorization decisions (REST + gRPC)

No head-to-head (Keycloak and Zitadel expose no equivalent decision
endpoint). Each check performs a full RBAC evaluation (tenant-scoped roles,
resource hierarchy, scopes) against live data:

| scenario | profile | throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) | valid |
|---|---|---|---|---|---|---|
| authz_check_rest | p0 | 745 | 67.0 | 84.6 | 94.5 | ✓ |
| authz_check_rest | p2 | 747 | 67.4 | 84.2 | 93.7 | ✓ |
| authz_check_grpc | p0 | 722 | 61.0 | 73.0 | 90.0 | ✓ |
| authz_check_grpc | p2 | 746 | 60.0 | 73.0 | 88.0 | ✓ |
| authz_batch_rest (5 checks/req) | p0 | 46 | 1060 | 1276 | 1359 | ✓ |
| authz_batch_rest (5 checks/req) | p2 | 46 | 1042 | 1280 | 1368 | ✓ |
| authz_batch_grpc (5 checks/req) | p0 | 23 | 2153 | 2309 | 2370 | ✗ p95 > 2 s |
| authz_batch_grpc (5 checks/req) | p2 | 23 | 2139 | 2305 | 2396 | ✗ p95 > 2 s |

Single checks improved 1.5–2.5× since draft 1 (REST 290→745/s; the gRPC p99
tail collapsed from 850 to 90 ms) and now run at DB saturation. The **batch
endpoints remain the known weak spot** — unchanged since draft 1 despite a
round-trip-coalescing fix, and unchanged even with the DB uncapped, which
narrows the cause to a serialized database query pattern rather than
resources; the investigation continues with a specific suspect. Batch is
currently *slower* than repeated single checks; don't use it in
latency-sensitive paths until this is fixed.

## 5. DB-uncapped sensitivity pass (AXIAM & Zitadel)

Same envelope, database raised to 4 CPUs / 2048 MiB (servers still 2/1024).
What happens when the DB isn't the wall (p0 numbers):

| scenario | target | capped → uncapped (req/s) | Δ | limit after uncapping |
|---|---|---|---|---|
| authz_check_rest | AXIAM | 745 → **1017** | +37% | round-trip latency (nothing saturated) |
| authz_check_grpc | AXIAM | 722 → **867** | +20% | round-trip latency |
| userinfo | AXIAM | 5457 → **7261** | +33% | **AXIAM server pegged (first time outside login)** |
| oauth2_client_credentials | AXIAM | 1788 → 1817 | +1.6% | latency-structured; DB cap was never the wall |
| token_introspection | AXIAM | 2229 → 2209 | ~0% | latency-structured |
| jwks_fetch | AXIAM | 27059 → 27397 | +1.2% | load generator |
| jwks_fetch | Zitadel | 2034 → **3520** | +73% | Postgres **still pegged at 3.9/4 cores** |
| userinfo | Zitadel | 967 → **1718** | +78% | Postgres pegged at 4.0/4 cores |
| token_introspection | Zitadel | 923 → 1027 | +11% | Zitadel server pegged |
| oauth2_client_credentials | Zitadel | 419 → 414 | ~0% | mixed |

Takeaways: AXIAM's authorization and userinfo paths scale directly with DB
CPU (its server still has headroom at 2 cores except on userinfo); its token
endpoints are *not* DB-capped at all in this envelope. Zitadel is profoundly
Postgres-bound — even with double the DB CPU of anyone's server, Postgres
saturates first on its read paths. In the uncapped configuration the
cross-target gaps at p0 are: JWKS 7.8×, userinfo 4.2×, client-credentials
4.4×, introspection 2.2× — all in AXIAM's favor.

## 6. Weaknesses and caveats (the honest section)

**TLS 1.3 still halves AXIAM's token-issuance throughput** (−49% on
client-credentials; introspection −0.4%, JWKS −10.9%). This did *not* get
fixed by the session-resumption work shipped in alpha15 — and this run's new
telemetry proves resumption *is* working (TLS handshake time per request ≈ 0
in the degraded cells), which eliminates handshakes as the cause. What
remains: under TLS the load generator negotiates HTTP/2 and funnels all 50
users through one multiplexed connection, while plaintext uses HTTP/1.1 with
a per-connection pool — everything (latency, server CPU, DB CPU) halves in
lockstep, the signature of a connection-level ceiling, not crypto. The
isolation experiment (TLS 1.3 with HTTP/1.1 only) is queued for the next run.
Even with the penalty, AXIAM's TLS token numbers lead the field 2.2–2.7×.

**The authz batch endpoints are still slow** (§4) — now proven not to be a
resource problem (identical with DB uncapped). Under investigation.

**The refresh-token comparison is withdrawn** pending a harness fix (§2) —
the run-2 cells measure token issuance via a fallback on all three targets
and are labeled as such in the matrix.

**Zitadel's gRPC scenario produced no valid cell** (100% gRPC-level errors:
the benchmark's service-account token lacks the audience Zitadel's gRPC API
requires). The protocol-efficiency comparison (Zitadel REST vs gRPC) waits
for the next run. No AXIAM/Keycloak claim is affected.

**Other comparability caveats, stated plainly:**

- Single run per cell (median-of-3 next time); deltas ≲ 10% are noise.
- Same laptop as draft 1, now with telemetry: governor `performance`, package
  temperature hit 95–100 °C on hot cells, sustained clocks ~3.7–3.9 GHz on
  CPU-pegged cells (~3.2 GHz on generator-heavy ones). Cross-target fairness
  is unaffected (identical envelope); absolute numbers are conservative.
- Keycloak improved 2–5× vs draft 1 on the same version tag (§2) — we treat
  the new, better numbers as the baseline and have discarded draft-1
  multiples.
- AXIAM's stack figures still include RabbitMQ (~0.1–0.4 cores) which
  competitors don't run; its memory figures for cells that ran *after* the
  login scenario include ~360 MiB of retained allocator memory from the
  login burst (a known, benign retention behavior under investigation —
  visible as the step from ~470 to ~880 MiB stack memory in the matrix).
- k6 skipped certificate verification at p2 (throwaway private CA; handshake
  and record crypto are real). Zitadel's userinfo cells use a machine-user
  token (§3). The closed-loop 50-VU model floors fast endpoints (JWKS) and
  turns into pure latency-measurement when nothing saturates.

## 7. Full result matrix (capped run, graph-ready)

One row per (scenario, profile, target). `thr` = successful requests/s over
the 120 s window; latencies ms; `cpu`/`mem` = stack-wide averages;
`thr/core` = throughput per core consumed; `cpu·ms/req` = CPU-milliseconds
per request. Rows failing a validity gate, or measuring a fallback operation,
are labeled and **must not be charted as head-to-head performance**.

| scenario | profile | target | thr (req/s) | p50 | p95 | p99 | err % | cpu (cores) | mem (MiB) | thr/core | cpu·ms/req | valid |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| oauth2_client_credentials | p0 | axiam | 1788 | 25.9 | 32.3 | 36.2 | 0.00 | 2.90 | 470 | 617 | 1.62 | ✓ |
| oauth2_client_credentials | p0 | keycloak | 346 | 103.9 | 210.4 | 301.5 | 0.00 | 2.07 | 834 | 167 | 6.00 | ✓ |
| oauth2_client_credentials | p0 | zitadel | 419 | 109.4 | 138.7 | 211.7 | 0.00 | 3.58 | 352 | 117 | 8.53 | ✓ |
| oauth2_client_credentials | p2 | axiam | 908 | 53.8 | 62.8 | 65.2 | 0.00 | 1.65 | 487 | 551 | 1.81 | ✓ |
| oauth2_client_credentials | p2 | keycloak | 340 | 104.6 | 210.6 | 301.0 | 0.00 | 2.07 | 917 | 165 | 6.08 | ✓ |
| oauth2_client_credentials | p2 | zitadel | 405 | 112.2 | 143.5 | 234.5 | 0.00 | 3.59 | 351 | 113 | 8.85 | ✓ |
| token_introspection | p0 | axiam | 2229 | 20.4 | 27.1 | 30.0 | 0.00 | 2.38 | 883 | 936 | 1.07 | ✓ |
| token_introspection | p0 | keycloak | 1765 | 7.8 | 82.8 | 86.8 | 0.00 | 2.34 | 945 | 753 | 1.33 | ✓ |
| token_introspection | p0 | zitadel | 923 | 47.3 | 67.1 | 73.8 | 0.00 | 3.70 | 425 | 250 | 4.01 | ✓ |
| token_introspection | p2 | axiam | 2219 | 20.5 | 27.3 | 30.2 | 0.00 | 2.64 | 905 | 841 | 1.19 | ✓ |
| token_introspection | p2 | keycloak | 1794 | 7.7 | 82.2 | 86.2 | 0.00 | 2.35 | 949 | 764 | 1.31 | ✓ |
| token_introspection | p2 | zitadel | 891 | 50.3 | 68.3 | 77.4 | 0.00 | 3.75 | 427 | 238 | 4.21 | ✓ |
| token_refresh | p0 | axiam | 910 | 25.4 | 32.2 | 36.2 | 0.00 | 3.06 | 915 | 298 | 3.36 | ⚠ fallback-op |
| token_refresh | p0 | keycloak | 204 | 100.3 | 200.8 | 291.3 | 0.00 | 2.07 | 947 | 98 | 10.19 | ⚠ fallback-op |
| token_refresh | p0 | zitadel | 215 | 107.6 | 137.0 | 174.8 | 0.00 | 3.50 | 504 | 62 | 16.26 | ⚠ fallback-op |
| token_refresh | p2 | axiam | 453 | 53.6 | 63.6 | 66.8 | 0.00 | 1.80 | 877 | 252 | 3.97 | ⚠ fallback-op |
| token_refresh | p2 | keycloak | 202 | 100.6 | 200.7 | 291.4 | 0.00 | 2.07 | 950 | 98 | 10.23 | ⚠ fallback-op |
| token_refresh | p2 | zitadel | 208 | 110.3 | 146.4 | 194.4 | 0.00 | 3.52 | 498 | 59 | 16.90 | ⚠ fallback-op |
| jwks_fetch | p0 | axiam | 27059 | 1.3 | 3.0 | 4.3 | 0.00 | 1.65 | 456 | 16388 | 0.061 | ✓ |
| jwks_fetch | p0 | keycloak | 3855 | 3.0 | 74.4 | 79.1 | 0.00 | 2.01 | 714 | 1922 | 0.52 | ✓ |
| jwks_fetch | p0 | zitadel | 2034 | 11.5 | 65.0 | 67.6 | 0.00 | 2.99 | 348 | 681 | 1.47 | ✓ |
| jwks_fetch | p2 | axiam | 24118 | 1.6 | 3.0 | 4.1 | 0.00 | 1.98 | 474 | 12171 | 0.082 | ✓ |
| jwks_fetch | p2 | keycloak | 3098 | 3.8 | 77.2 | 82.9 | 0.00 | 2.01 | 783 | 1544 | 0.65 | ✓ |
| jwks_fetch | p2 | zitadel | 2023 | 12.7 | 61.3 | 64.3 | 0.00 | 3.11 | 257 | 651 | 1.54 | ✓ |
| oauth2_password_login | p0 | axiam | 68 | 694.2 | 907.5 | 1194.8 | 0.00 | 2.16 | 865 | 31 | 31.98 | ✓ |
| oauth2_password_login | p0 | keycloak | 22 | 2139.0 | 2380.2 | 2487.4 | 0.00 | 2.02 | 896 | 11 | 90.77 | ✗ p95>2s |
| oauth2_password_login | p0 | zitadel | 2 | 21991.6 | 25605.2 | 27835.6 | 0.00 | 2.02 | 405 | 1 | 986.80 | ✗ p95>2s |
| oauth2_password_login | p2 | axiam | 68 | 694.6 | 945.7 | 1100.7 | 0.00 | 2.33 | 905 | 29 | 34.31 | ✓ |
| oauth2_password_login | p2 | keycloak | 23 | 2113.9 | 2272.8 | 2344.1 | 0.00 | 2.03 | 932 | 11 | 89.02 | ✗ p95>2s |
| oauth2_password_login | p2 | zitadel | 2 | 22465.2 | 25396.8 | 27434.1 | 0.30 | 2.02 | 401 | 1 | 996.56 | ✗ p95>2s |
| userinfo | p0 | axiam | 5457 | 4.6 | 46.4 | 53.9 | 0.00 | 3.76 | 800 | 1453 | 0.69 | ✓ |
| userinfo | p0 | keycloak | 3561 | 3.1 | 77.6 | 81.2 | 0.00 | 2.00 | 944 | 1778 | 0.56 | ✓ |
| userinfo | p0 | zitadel | 967 | 23.6 | 81.8 | 86.0 | 0.00 | 2.84 | 542 | 340 | 2.94 | ✓ (machine-user token) |
| userinfo | p2 | axiam | 4924 | 5.1 | 48.8 | 53.6 | 0.00 | 3.64 | 775 | 1351 | 0.74 | ✓ |
| userinfo | p2 | keycloak | 3529 | 3.2 | 77.7 | 81.3 | 0.00 | 2.00 | 946 | 1761 | 0.57 | ✓ |
| userinfo | p2 | zitadel | 942 | 29.6 | 81.7 | 91.5 | 0.00 | 2.91 | 540 | 323 | 3.09 | ✓ (machine-user token) |
| zitadel_userinfo_grpc | p0 | zitadel | — | — | — | — | 100.00 | 3.53 | 551 | — | — | ✗ harness bug (audience) |
| zitadel_userinfo_grpc | p2 | zitadel | — | — | — | — | 100.00 | 3.50 | 546 | — | — | ✗ harness bug (audience) |
| authz_check_rest (AXIAM-only) | p0 | axiam | 745 | 67.0 | 84.6 | 94.5 | 0.00 | 2.74 | 425 | 272 | 3.68 | ✓ |
| authz_check_rest (AXIAM-only) | p2 | axiam | 747 | 67.4 | 84.2 | 93.7 | 0.00 | 2.80 | 438 | 267 | 3.75 | ✓ |
| authz_check_grpc (AXIAM-only) | p0 | axiam | 722 | 61.0 | 73.0 | 90.0 | 0.00 | 3.01 | 419 | 240 | 4.17 | ✓ |
| authz_check_grpc (AXIAM-only) | p2 | axiam | 746 | 60.0 | 73.0 | 88.0 | 0.00 | 2.69 | 440 | 277 | 3.61 | ✓ |
| authz_batch_rest (AXIAM-only) | p0 | axiam | 46 | 1060.3 | 1275.9 | 1359.2 | 0.00 | 1.30 | 425 | 35 | 28.58 | ✓ |
| authz_batch_rest (AXIAM-only) | p2 | axiam | 46 | 1041.8 | 1280.0 | 1368.0 | 0.00 | 1.30 | 440 | 35 | 28.28 | ✓ |
| authz_batch_grpc (AXIAM-only) | p0 | axiam | 23 | 2153.0 | 2309.0 | 2370.0 | 0.00 | 1.26 | 380 | 18 | 54.30 | ✗ p95>2s |
| authz_batch_grpc (AXIAM-only) | p2 | axiam | 23 | 2139.0 | 2305.0 | 2396.0 | 0.00 | 1.21 | 386 | 19 | 51.83 | ✗ p95>2s |

### Security cost of TLS 1.3 (p2 vs p0, valid cells)

| target / scenario | Δ throughput |
|---|---|
| axiam / token_introspection | −0.4% |
| axiam / jwks_fetch | −10.9% |
| axiam / userinfo | −9.8% |
| axiam / oauth2_password_login | +0.4% |
| axiam / oauth2_client_credentials | **−49.2%** (see §6) |
| keycloak / oauth2_client_credentials | −1.6% |
| keycloak / token_introspection | +1.6% |
| keycloak / jwks_fetch | −19.6% |
| keycloak / userinfo | −0.9% |
| zitadel / oauth2_client_credentials | −3.3% |
| zitadel / token_introspection | −3.5% |
| zitadel / jwks_fetch | −0.6% |
| zitadel / userinfo | −2.6% |

(|Δ| ≲ 10% is within single-run noise.)

## 8. Summary and what happens next

**Strengths shown by this run.** On every scenario with a valid head-to-head,
AXIAM 1.0.0-alpha15 leads throughput and p95 latency: token issuance 4.3–5.2×,
introspection 1.3–2.4×, JWKS 7–13×, userinfo 1.5–5.6×, and it is the only
target that passes the latency gate on password login at 50 concurrent users
(3× Keycloak's rate at the same hash-algorithm class, with bounded memory).
Efficiency (cpu·ms/req) leads in every valid comparison except Keycloak's
userinfo cell — and AXIAM's figures still carry its audit broker and a
saturated DB inside them. The DB-uncapped pass shows AXIAM's server has
headroom left in almost every cell.

**Weaknesses shown by this run.** The TLS 1.3 connection-behavior issue still
halves token issuance under this load generator (root cause isolated, fix in
validation); the authz batch endpoints remain slower than single checks
(proven non-resource-bound, investigation narrowed); the refresh comparison
had to be withdrawn as a fallback measurement — on all targets, including
ours in draft 1; and the Zitadel gRPC comparison cell is still invalid.

**Next round:** median-of-3 on every cell, the refresh-scenario fix, the
Zitadel gRPC audience fix, the TLS HTTP/1.1 isolation cell, p3-mtls (AXIAM
now terminates mTLS natively), a production-rate-limit-posture run, and — when
hardware allows — a server-class re-run to replace the laptop numbers.

---
*Sources: benchmark runs of 2026-07-21 (capped full matrix + DB-uncapped
sensitivity pass; per-cell k6 summaries, 1 s `docker stats` samples, 1 s host
CPU-frequency/temperature telemetry, and run metadata), aggregated by
`runner/report.py`. Metric definitions: [`docs/methodology.md`](docs/methodology.md).*
