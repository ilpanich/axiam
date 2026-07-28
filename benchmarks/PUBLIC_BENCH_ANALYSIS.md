# AXIAM Benchmark Analysis — Third Draft (run 3, median-of-3)

> **Status: third benchmark draft — the first statistically grounded one.**
> This updates draft 2 (single-run, 2026-07-21) with a full run of 2026-07-25/26
> against the released **AXIAM 1.0.0-alpha19** container image (digest-pinned,
> pulled from the public registry — not a local build), with **every matrix
> cell measured three times and reported as the median**, plus seven labeled
> sensitivity passes (DB-uncapped for all targets, decision-cache ON, DB-pool
> A/B, native mTLS, production rate-limit posture, batch-strategy A/B, and a
> TLS/HTTP-version isolation cell). Observed run-to-run throughput spread was
> **±0.1–2.8%** per cell, so differences above ~5% are signal on this
> hardware. The remaining limitation is the hardware itself: a consumer
> laptop. Where this draft *corrects* earlier drafts it says so explicitly
> (§2) — including one correction in AXIAM's favor that we held ourselves to
> the same standard on. Numbers are reproducible from the published raw data.

## 1. What was measured

Three open-source IAM servers were driven with the **identical logical
workload** through the vendor-neutral k6 harness in
[`benchmarks/`](README.md) (adapter layer isolates per-vendor endpoint
differences; see [`docs/methodology.md`](docs/methodology.md)):

| Target | Server | Datastore | Extra services |
|---|---|---|---|
| **AXIAM** | `axiam-server` **1.0.0-alpha19** (Rust / Actix-Web / Tonic; pulled ghcr image, digest recorded) | SurrealDB v3 (SurrealKV backend) | RabbitMQ 4 (audit/event broker) |
| **Keycloak** | Keycloak 26.7.0 (JVM) | PostgreSQL 16 (uniformly tuned) | — |
| **Zitadel** | Zitadel v4.15.2 (Go) | PostgreSQL 16 (uniformly tuned) | — |

### Test environment

Same single **Dell XPS 15 9570** (i7-8750H, 12 logical CPUs, ~31 GiB RAM,
Linux 7.1, Docker 29.6) as previous drafts; targets benchmarked sequentially;
CPU governor `performance`; per-cell CPU-frequency/temperature/generator
telemetry recorded and published (hot cells sustained ~3.7–3.9 GHz at
95–100 °C; a few competitor cells carry a `clock_variance` flag in the raw
data where clocks sagged — none of the headline AXIAM cells do).

Caps (main matrix): every IAM server 2 CPUs / 1024 MiB; every database
2 CPUs / 1024 MiB; RabbitMQ (AXIAM only) 1 CPU / 512 MiB. Load model:
closed-loop **50 VUs**, 30 s warm-up + 120 s measured window, **×3 repeats,
median reported**. Validity gates: error rate ≤ 1%, p95 < 2 s, ≥ 2 valid
runs per cell. Profiles: **p0-plaintext** and **p2-tls13** (TLS 1.3
terminated in-process by all three targets, gRPC included). AXIAM's default
per-IP rate limits are neutralized in head-to-head cells (k6 is a single
source IP; competitors ship no equivalent defaults) — the *production*
posture gets its own labeled pass and a tuning guide in §6.

## 2. What changed since draft 2 (corrections included)

**Correction in AXIAM's favor — the "slow batch endpoint" caveat is
withdrawn as unproven.** Drafts 1 and 2 reported AXIAM's authorization
*batch* endpoints as a known weak spot (~46 batches/s, slower than single
checks). Run 3's expanded sensitivity set revealed a **measurement-order
artifact**: for roughly 5–7 minutes after a stack is seeded, the database
serves queries through what appears to be a serialization bottleneck
(~45 req/s regardless of scenario), and the batch cells had *always* run
first in the matrix order. When a batch cell runs on a settled stack it
measures **852 batches/s (≈ 4 260 checks/s, p50 49 ms)** — i.e. batch is
*more* efficient than single checks, as designed. We are re-measuring all
batch cells under a corrected protocol before publishing final batch
numbers; the same artifact also invalidated one TLS-diagnosis cell (§5).
The transient itself is under investigation (it may affect cold-start
behavior, which is why we're publishing it rather than quietly fixing the
cell order).

**Refresh-token comparison — partially restored.** Keycloak's refresh cells
now measure real single-use rotation (the draft-2 fallback is fixed:
379 req/s at p0). AXIAM's own refresh cells **still measure a fallback** (a
harness cookie-handling bug, being fixed) and remain excluded. Zitadel's
refresh needs an `offline_access` flow the harness doesn't implement yet.

**Zitadel gRPC is now measured for real** (draft 2: 100% auth errors): its
gRPC userinfo runs at 183 req/s vs 943 req/s for its REST equivalent.

**Provenance is now airtight:** every container in every cell records an
image digest; AXIAM ran from the published, digest-pinned release image.
The draft-2 "Keycloak got faster between runs" ambiguity can't recur.

## 3. Headline results (capped matrix, median-of-3, valid cells)

Full matrix in §7. CPU/memory figures are whole-stack (AXIAM's include
SurrealDB **and** RabbitMQ); `server-only` efficiency is also published in
the raw report.

### Machine-to-machine token issuance (`oauth2_client_credentials`)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | server-only req/s per core |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **1823** | 25.4 | **31.9** | **637** | **1880** |
| p0 | Zitadel | 423 | 110.0 | 134.2 | 115 | 235 |
| p0 | Keycloak | 351 | 103.6 | 208.1 | 170 | 176 |
| p2 | **AXIAM** | **903** | 54.2 | **62.8** | 567 | 1624 |
| p2 | Zitadel | 415 | 113.1 | 137.5 | 111 | 226 |
| p2 | Keycloak | 346 | 104.0 | 209.1 | 167 | 173 |

AXIAM issues **5.2× more tokens/s than Keycloak and 4.3× more than
Zitadel** at plaintext and stays 2.2–2.6× ahead under TLS 1.3 (the TLS gap
is a connection-behavior issue under investigation, §5 — not crypto cost).

### Token introspection (RFC 7662)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | cpu·ms/req |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **2230** | 20.4 | **27.1** | **907** | **1.10** |
| p0 | Keycloak | 1908 | 7.2 | 81.7 | 807 | 1.24 |
| p0 | Zitadel | 910 | 47.8 | 68.7 | 248 | 4.04 |
| p2 | **AXIAM** | **2225** | 20.4 | **27.2** | 839 | 1.19 |
| p2 | Keycloak | 1758 | 7.9 | 82.5 | 748 | 1.34 |
| p2 | Zitadel | 899 | 50.1 | 67.7 | 238 | 4.19 |

The closest head-to-head: AXIAM leads Keycloak 1.17× on throughput with a
3× better p95 and **zero TLS penalty** (−0.2%). Keycloak's p50 is the
lowest of the field; its JVM tail is what separates them.

### JWKS fetch (RFC 7517)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **27 784** | 1.3 | **2.9** | **16 850** |
| p0 | Keycloak | 3764 | 3.1 | 75.2 | 1881 |
| p0 | Zitadel | 2071 | 11.2 | 65.1 | 698 |
| p2 | **AXIAM** | **24 309** | 1.6 | **2.9** | 12 349 |
| p2 | Keycloak | 3042 | 3.8 | 77.6 | 1514 |
| p2 | Zitadel | 2023 | 12.8 | 61.1 | 650 |

A 7–13× gap, still limited by the load generator, not by AXIAM (server at
~1.3/2 cores while k6 neared its own budget).

### OIDC userinfo

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | server-only cpu·ms/req |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **5008** | 4.8 | **50.2** | 1452 | **0.25** |
| p0 | Keycloak | 3742 | 3.0 | 77.0 | **1873** | 0.53 |
| p0 | Zitadel* | 943 | 25.7 | 82.6 | 333 | 0.87 |
| p2 | **AXIAM** | **4822** | 5.2 | **49.2** | 1345 | 0.28 |
| p2 | Keycloak | 3489 | 3.2 | 77.9 | **1740** | 0.57 |
| p2 | Zitadel* | 950 | 27.4 | 80.8 | 324 | 0.96 |

*\* Zitadel's cells use a machine-user token (its user-login flow returns a
session token the harness can't yet convert); measured endpoint and
semantics are the same.*

AXIAM leads throughput (1.34× Keycloak, 5.3× Zitadel) while its DB is
saturated (uncapped it reaches **7457 req/s**, §4). On whole-stack req/s
per core Keycloak wins this cell (AXIAM's figure carries a pegged SurrealDB
plus RabbitMQ); on the **server-only** measure AXIAM's server is 2.1×
cheaper per request — both facts published.

### Password login (all targets hash for real)

AXIAM **Argon2id** (OWASP params), Keycloak 26 **Argon2id** (default),
Zitadel **bcrypt** (default cost — much more expensive per verification;
tunable). Hash configuration dominates this scenario; compare accordingly.

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | valid (p95 < 2 s) |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **69** | 695 | **774** | ✓ (3/3 runs) |
| p0 | Keycloak | 52 | 919 | 1070 | ✓ (2/3 runs) |
| p0 | Zitadel | 2 | 22 605 | 25 388 | ✗ gate breach |
| p2 | **AXIAM** | **69** | 692 | **816** | ✓ (3/3 runs) |
| p2 | Keycloak | 23 | 2115 | 2249 | ✗ gate breach |
| p2 | Zitadel | 2 | 21 823 | 25 529 | ✗ gate breach |

Keycloak's plaintext login cell is valid for the first time (52 req/s —
notably better than its own draft-2 number; its TLS login cell still
breaches the gate, an asymmetry we can't yet explain and therefore flag).
AXIAM remains the fastest and the only target valid at both profiles,
with **bounded memory** during the burst (the alpha15 concurrency bound).

### AXIAM-only: authorization decisions

No head-to-head exists (competitors expose no equivalent decision
endpoint). Full RBAC evaluation (tenant-scoped roles, resource hierarchy,
scopes) against live data, median-of-3:

| scenario | profile | thr (req/s) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| authz_check_rest | p0 | 737 | 68.4 | 85.2 | 94.1 |
| authz_check_rest | p2 | 747 | 67.1 | 84.5 | 94.1 |
| authz_check_grpc | p0 | 603 | 62.0 | 75.0 | 217.0 |
| authz_check_grpc | p2 | 622 | 61.0 | 74.0 | 112.0 |

Single checks are DB-saturated at ~740/s on a 2-core DB and scale to
1013/s with 4 DB cores (§4). **Batch numbers are intentionally absent**:
see the §2 correction — the only clean batch cell so far measured
852 batches/s (≈4 260 checks/s), and full re-measured batch tables will
ship in the next draft rather than repeating an artifact. With the
**decision cache** enabled (§4) single checks reach **2322 req/s REST /
1822 gRPC** on the same capped hardware.

## 4. Sensitivity passes (labeled, never mixed into head-to-heads)

**DB-uncapped (4 CPUs / 2 GiB for every DB; servers stay at 2):**

| cell | capped → uncapped | what limits it now |
|---|---|---|
| AXIAM authz_check_rest | 737 → **1013** (+37%) | round-trip latency; nothing saturated |
| AXIAM userinfo | 5008 → **7457** (+49%) | **AXIAM server itself, for the first time** |
| AXIAM tokens/jwks | ±1% | not DB-bound at all |
| Keycloak (every cell) | ±2% | Keycloak server (pegged in every cell) |
| Zitadel jwks / userinfo | +70% / +85% | Postgres, even at 4 cores |
| Zitadel introspection | +13% | Zitadel server |

**Decision cache ON** (`AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`,
TTL 5 s): authz checks **3.0–3.15×** (REST 2322/s, gRPC 1822/s), DB no
longer saturated, all non-authz cells unchanged. Caveat: the benchmark's
cache hit rate is favorable (small key space); revocations are bounded by
the 5 s TTL plus event-driven invalidation (integration-tested).

**DB connection pool** (`AXIAM__DB__POOL_SIZE=4`): token issuance +7%
(1823→1955); everything else within noise at this concurrency. A further
in-flight cap (64) changes nothing. Default stays 1.

**Native mTLS (p3)** — AXIAM terminates **client-certificate TLS 1.3
in-process** (no proxy in front; the verified peer certificate is the
identity source). Result: **parity with plain TLS 1.3 across the entire
matrix** (CC 903.6 vs 903, introspection 2201 vs 2225, userinfo 4826 vs
4822, jwks 24 146 vs 24 309…). For IoT/mTLS fleets: client-cert
verification is free on top of TLS.

**Production rate-limit posture:** with AXIAM's shipped per-IP limits
active (token 20/min/IP, introspect 10/min/IP, …) a 50-VU single-IP
generator is throttled to near-zero on every limited endpoint — the
defaults do exactly what they're for (blunt single-source abuse), and this
pass is the measured evidence that AXIAM ships enforcing limits by default
while the competitors ship none. It is **not** a performance measurement,
and it shows the shipped defaults are sized for internet-facing human
traffic, not machine fleets — see §6 for what to set instead.

## 5. Weaknesses and caveats (the honest section)

**TLS 1.3 still halves token issuance** (−50.5% on client_credentials;
introspection −0.2%, userinfo −3.7%, jwks −12.5%, login ~0%). Everything
still points at HTTP/2 single-connection multiplexing in the load path
rather than crypto (handshake time per request ≈ 0; server and DB CPU halve
in lockstep with throughput). The HTTP/1.1-over-TLS isolation cell we
queued for this run was unfortunately invalidated by the §2 measurement
artifact (it ran inside the post-seed window) — it is re-queued under the
corrected protocol. Even with the penalty, AXIAM's TLS token numbers lead
the field 2.2–2.6×.

**A post-seed database transient exists** (§2): for ~5–7 minutes after bulk
seeding, throughput on the AXIAM stack is clamped at ~45 req/s. We found it
because it corrupted our own cells; we're investigating whether it can
affect production cold-starts or bulk imports, and the harness now gets a
settle gate + randomized cell order. Numbers in this draft come from cells
outside that window except where explicitly withdrawn (batch, TLS-h1).

**AXIAM's refresh-token cells are still excluded** (harness cookie bug —
the fallback tagging keeps catching it, including on us). Keycloak's
refresh is now measured for real (379/s). Zitadel refresh/login cells
remain gate-invalid at its default bcrypt cost.

**Other caveats, stated plainly:** consumer-laptop hardware (server-class
re-run still pending budget); AXIAM stack figures include RabbitMQ
(~0.1–0.3 cores) and, for cells after the login burst, ~360 MiB of retained
allocator memory (reproduced on alpha19; an allocator A/B experiment is
scripted and scheduled — it inflates AXIAM's memory column, not its
latency); k6 skips cert verification at p2/p3 (throwaway CA; handshake and
record crypto are real); closed-loop 50 VUs floors the fastest endpoints
(JWKS) and measures latency, not capacity, when nothing saturates; SDK
client-side overhead benchmarks exist in the harness but have not yet
produced validated runs — client-side numbers will come in a future draft.

## 6. Recommended settings by deployment (measured, not guessed)

The production-posture pass (§4) showed the shipped defaults are tuned for
one thing: stopping single-source abuse on a small internet-facing
deployment. Every knob below is a runtime environment variable; the
recommendations derive directly from this run's measurements on
2-core/1-GiB-per-container hardware — scale linearly with your envelope
where the data says the path scales (authz/userinfo with DB CPU; login
with server CPU; token issuance with neither until ~1.8k/s per 2 cores).

### Sizing quick reference (what a given envelope measured)

| Envelope (server / DB) | Token issuance | Introspection | Authz checks (cache off / on) | Userinfo | Logins (Argon2id, OWASP) |
|---|---|---|---|---|---|
| 2 cores / 2 cores | ~1 800/s | ~2 200/s | ~740 / ~2 300/s | ~5 000/s | ~69/s |
| 2 cores / 4 cores | ~1 800/s | ~2 200/s | ~1 000 / higher | ~7 500/s (server-bound) | ~69/s |

### Knob-by-knob

| Setting (env var) | Shipped default | Small internet-facing (2c/1GiB) | M2M / microservices / IoT fleet | Large multi-tenant (8c+) |
|---|---|---|---|---|
| `AXIAM__RATE_LIMIT__PROFILE` | `internet` | `internet` | **`gateway`** — moves the whole machine-traffic family coherently from one variable | `mesh` |
| `AXIAM__RATE_LIMIT__KEY` | `ip` | `ip` | **`client_id`** (or `ip_client_id`) — per-IP buckets collide behind NAT/gateways — **but read the security caveat below first** | `ip_client_id` |
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | 20 | 60–120 | **per-client peak × 60 × 2** (a 2-core server sustains ~108k issuances/min total) | budget per tenant SLA |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | 10 | 60 | 10–20× your token limit (resource servers introspect per request) | same rule |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | 300 | 600 | **6 000–60 000** per client (checks are cheap reads; 300/min starves any real service) | size to cache-on ceiling |
| `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` | 10 (per IP) | keep 10 | 60+ if users arrive through a shared NAT/proxy (always per-IP by design) | 60+, front with WAF |
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` | `false` | `true` | **`true`** — measured 3× on checks, DB load −40–75% | `true` |
| `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` | 5 | 5 | 5 (raise only if a ≤TTL revocation delay is acceptable) | 5 |
| `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` | 10 000/tenant | default | default | raise with RAM (entries are small) |
| `AXIAM__AUTHZ__BATCH_STRATEGY` | `concurrent` | default | default for now — re-measurement in progress; `coalesced` showed 852 batches/s on a settled stack | follow next draft |
| `AXIAM__DB__POOL_SIZE` | 1 | 1 | **4** if token-issuance-heavy (+7% measured); otherwise 1 | 4 |
| `AXIAM__DB__POOL_MAX_IN_FLIGHT` | 0 (off) | 0 | 0 (never bound in tests at 50 VUs) | set only with evidence |
| `AXIAM__AUTH__MAX_CONCURRENT_HASHES` | 0 = auto (min(cpus, 4)) | auto | auto | ≈ physical cores reserved for auth; keeps login RAM bounded (~19 MiB per concurrent hash) |
| DB CPU allocation | — | DB ≥ server cores | DB ≥ server cores if authz/userinfo-heavy (they scale with DB CPU; tokens don't) | 2× server cores for read-heavy |

**Security caveat on `client_id` keying — read before changing the key mode.**
The `client_id` a request is bucketed by is read from the request body
*before* the client credential is verified (that is what the OAuth2 spec puts
there). So an attacker who simply varies the `client_id` string gets a fresh
bucket each time and is effectively unlimited on the token, revoke and
introspect endpoints. **`client_id` keying is a fairness control between
well-behaved clients, not an abuse control.** `ip` is the only mode whose key
an attacker cannot mint at will, which is why it stays the shipped default.
Use `client_id`/`ip_client_id` only where something else is already
authenticating callers at the edge — mTLS, an API gateway, a WAF, or an IP
allow-list — which is exactly the topology the M2M column assumes.

Two rules of thumb the data supports: (1) if your traffic is
authorization-check-heavy, spend hardware on the **database** and turn the
**decision cache on** before anything else; (2) if it's token-heavy, the
limits — not the hardware — are what you'll hit first: raise
`TOKEN_PER_MIN` from your real per-client peak and, *if and only if* you have
edge authentication per the caveat above, switch the key mode; keep the
defaults on genuinely internet-exposed endpoints (login, register,
password-reset, MFA), which stay per-IP in every configuration.

## 7. Full result matrix (capped run, median-of-3, graph-ready)

One row per (scenario, profile, target); `±` is the throughput spread
across the three runs. Rows failing a validity gate or measuring a
fallback are labeled and **must not be charted as head-to-head**.

| scenario | profile | target | thr (req/s) | ± | p50 | p95 | p99 | cpu (cores) | mem (MiB) | valid |
|---|---|---|---|---|---|---|---|---|---|---|
| oauth2_client_credentials | p0 | axiam | 1823 | 0.1% | 25.4 | 31.9 | 35.8 | 2.86 | 516 | ✓ |
| oauth2_client_credentials | p0 | keycloak | 351 | 1.4% | 103.6 | 208.1 | 301.4 | 2.07 | 764 | ✓ |
| oauth2_client_credentials | p0 | zitadel | 423 | 0.3% | 110.0 | 134.2 | 171.3 | 3.68 | 362 | ✓ |
| oauth2_client_credentials | p2 | axiam | 903 | 0.1% | 54.2 | 62.8 | 65.0 | 1.59 | 523 | ✓ |
| oauth2_client_credentials | p2 | keycloak | 346 | 0.9% | 104.0 | 209.1 | 300.4 | 2.07 | 804 | ✓ |
| oauth2_client_credentials | p2 | zitadel | 415 | 0.6% | 113.1 | 137.5 | 168.7 | 3.73 | 356 | ✓ |
| token_introspection | p0 | axiam | 2230 | 0.3% | 20.4 | 27.1 | 29.8 | 2.46 | 922 | ✓ |
| token_introspection | p0 | keycloak | 1908 | 2.0% | 7.2 | 81.7 | 85.5 | 2.36 | 973 | ✓ |
| token_introspection | p0 | zitadel | 910 | 1.2% | 47.8 | 68.7 | 76.2 | 3.67 | 441 | ✓ |
| token_introspection | p2 | axiam | 2225 | 0.5% | 20.4 | 27.2 | 30.2 | 2.65 | 927 | ✓ |
| token_introspection | p2 | keycloak | 1758 | 2.4% | 7.9 | 82.5 | 86.8 | 2.35 | 873 | ✓ |
| token_introspection | p2 | zitadel | 899 | 0.9% | 50.1 | 67.7 | 76.8 | 3.77 | 424 | ✓ |
| token_refresh | p0 | keycloak | 379 | 2.0% | 101.5 | 204.6 | 299.5 | 2.05 | 983 | ✓ real rotation |
| token_refresh | p2 | keycloak | 367 | 1.1% | 102.3 | 205.2 | 298.5 | 2.05 | 881 | ✓ real rotation |
| token_refresh | p0/p2 | axiam | — | — | — | — | — | — | — | ⚠ fallback-op (harness bug, excluded) |
| token_refresh | p0/p2 | zitadel | — | — | — | — | — | — | — | ✗ fallback + gate |
| jwks_fetch | p0 | axiam | 27784 | 0.3% | 1.3 | 2.9 | 4.2 | 1.65 | 503 | ✓ |
| jwks_fetch | p0 | keycloak | 3764 | 2.0% | 3.1 | 75.2 | 79.9 | 2.00 | 631 | ✓ |
| jwks_fetch | p0 | zitadel | 2071 | 0.6% | 11.2 | 65.1 | 67.4 | 2.97 | 261 | ✓ |
| jwks_fetch | p2 | axiam | 24309 | 0.9% | 1.6 | 2.9 | 4.0 | 1.97 | 502 | ✓ |
| jwks_fetch | p2 | keycloak | 3042 | 1.5% | 3.8 | 77.6 | 82.9 | 2.01 | 681 | ✓ |
| jwks_fetch | p2 | zitadel | 2023 | 0.8% | 12.8 | 61.1 | 64.1 | 3.11 | 258 | ✓ |
| oauth2_password_login | p0 | axiam | 69 | 1.0% | 694.7 | 774.1 | 1055.5 | 2.09 | 897 | ✓ |
| oauth2_password_login | p0 | keycloak | 52 | 7.8% | 919.3 | 1069.7 | 1161.6 | 2.05 | 911 | ✓ (2/3 runs) |
| oauth2_password_login | p0 | zitadel | 2 | 1.0% | 22604.7 | 25388.0 | 27052.2 | 2.02 | 418 | ✗ p95>2s |
| oauth2_password_login | p2 | axiam | 69 | 0.6% | 691.5 | 815.8 | 1116.5 | 2.30 | 918 | ✓ |
| oauth2_password_login | p2 | keycloak | 23 | 0.4% | 2115.1 | 2248.6 | 2315.0 | 2.03 | 854 | ✗ p95>2s |
| oauth2_password_login | p2 | zitadel | 2 | 1.5% | 21822.6 | 25529.0 | 27744.6 | 2.02 | 411 | ✗ p95>2s |
| userinfo | p0 | axiam | 5008 | 0.6% | 4.8 | 50.2 | 54.4 | 3.45 | 765 | ✓ |
| userinfo | p0 | keycloak | 3742 | 1.9% | 3.0 | 77.0 | 80.6 | 2.00 | 961 | ✓ |
| userinfo | p0 | zitadel | 943 | 1.4% | 25.7 | 82.6 | 88.7 | 2.83 | 451 | ✓ (machine-user token) |
| userinfo | p2 | axiam | 4822 | 0.2% | 5.2 | 49.2 | 54.0 | 3.59 | 638 | ✓ |
| userinfo | p2 | keycloak | 3489 | 1.1% | 3.2 | 77.9 | 81.4 | 2.01 | 858 | ✓ |
| userinfo | p2 | zitadel | 950 | 1.8% | 27.4 | 80.8 | 89.0 | 2.93 | 443 | ✓ (machine-user token) |
| userinfo_grpc (AXIAM-only) | p0 | axiam | 3294 | 0.2% | 14.0 | 22.0 | 25.0 | 1.61 | 757 | ✓ |
| userinfo_grpc (AXIAM-only) | p2 | axiam | 3254 | 0.3% | 14.0 | 22.0 | 25.0 | 1.51 | 606 | ✓ |
| zitadel_userinfo_grpc | p0 | zitadel | 183 | 1.2% | 233.0 | 503.0 | 887.0 | 1.16 | 445 | ✓ (machine-user token) |
| zitadel_userinfo_grpc | p2 | zitadel | 187 | 1.7% | 232.0 | 328.0 | 843.0 | 1.19 | 440 | ✓ (machine-user token) |
| authz_check_rest (AXIAM-only) | p0 | axiam | 737 | 0.9% | 68.4 | 85.2 | 94.1 | 2.92 | 481 | ✓ |
| authz_check_rest (AXIAM-only) | p2 | axiam | 747 | 0.0% | 67.1 | 84.5 | 94.1 | 2.86 | 474 | ✓ |
| authz_check_grpc (AXIAM-only) | p0 | axiam | 603 | 2.8% | 62.0 | 75.0 | 217.0 | 2.55 | 468 | ✓ |
| authz_check_grpc (AXIAM-only) | p2 | axiam | 622 | 1.1% | 61.0 | 74.0 | 112.0 | 2.47 | 465 | ✓ |
| authz_batch_* (AXIAM-only) | p0/p2 | axiam | — | — | — | — | — | — | — | ⚠ withdrawn — order artifact (§2); re-measurement in progress |

### Security cost of TLS 1.3 (p2 vs p0, valid cells, median-of-3)

| target / scenario | Δ throughput |
|---|---|
| axiam / token_introspection | −0.2% |
| axiam / userinfo | −3.7% |
| axiam / userinfo_grpc | −1.2% |
| axiam / authz_check_rest / _grpc | +1.3% / +3.1% |
| axiam / oauth2_password_login | −0.5% |
| axiam / jwks_fetch | −12.5% |
| axiam / oauth2_client_credentials | **−50.5%** (see §5) |
| keycloak / oauth2_client_credentials | −1.5% |
| keycloak / token_introspection | −7.9% |
| keycloak / jwks_fetch | −19.2% |
| keycloak / userinfo | −6.8% |
| keycloak / token_refresh | −3.3% |
| zitadel / all scenarios | −2.3% … +2.0% |

And the p3 result in one line: **mTLS (client certificates, verified
in-process) ≈ p2 within noise on every scenario.**

## 8. Summary and what happens next

**Strengths.** Median-of-3 confirms every draft-2 lead on the pinned
release binary: token issuance 4.3–5.2×, introspection 1.17–2.45×, JWKS
7–13×, userinfo 1.34–5.3×; the only login that stays under 2 s p95 at both
profiles; native mTLS at zero measured cost (unique in this field —
Zitadel's built-in listener has no client-cert mode, Keycloak's typical
deployments front it with a proxy); a decision cache worth 3× on
authorization checks; and run-to-run spreads tight enough (±0.1–2.8%) to
trust the deltas.

**Weaknesses.** The TLS token-issuance halving persists (isolation cell
re-queued after being invalidated by the measurement artifact); AXIAM's
refresh cell is still harness-blocked; batch numbers are withdrawn pending
re-measurement under the corrected protocol — with early evidence they'll
come back *better* than singles; memory retention after login bursts
(~360 MiB) awaits the scripted allocator experiment; and everything is
still laptop-hosted.

**Next round:** corrected cell ordering + post-seed settle gate; clean
batch A/B and TLS-h1 cells; the refresh harness fix; the allocator A/B;
SDK client-overhead tables; and — when hardware allows — the server-class
re-run.

---
*Sources: benchmark runs of 2026-07-25/26 (median-of-3 capped matrix ×
p0/p2 × 3 targets; labeled sensitivity passes: DB-uncapped ×3 targets,
decision-cache ON, pool A/B ×2, native-mTLS p3, prod rate-limit posture,
batch-strategy A/B, TLS-h1 isolation; per-cell k6 summaries, 1 s container
+ host telemetry, digest-recorded metadata), aggregated by
`runner/report.py`. Metric definitions: [`docs/methodology.md`](docs/methodology.md).*
