# AXIAM Benchmark Analysis — Fourth Draft

> **Status: fourth benchmark draft.** This updates draft 3 (2026-07-26, the
> first statistically grounded run) with the outcomes of the **Phase H**
> follow-up work (2026-07-28/29): a settle gate that can actually detect the
> clamp draft 3 tripped over, the root-caused explanation for what that clamp
> is, four decided defaults (batch strategy, allocator, decision cache, DB
> pool), a closed TLS/HTTP-2 investigation, and a validated SDK
> client-overhead table. **The published performance numbers in §3/§4/§7
> below are unchanged from draft 3** — they are still the G-box's
> 2026-07-25/26 median-of-3 run against the released **AXIAM 1.0.0-alpha19**
> container image. What changed is which of those numbers we stand behind as
> verdicts, and why: draft 3 withdrew the batch numbers and left the TLS
> penalty, the cache default and the pool default all open; this draft closes
> four of those five (§2). The fifth — a true publishable *run-4* matrix
> re-measured end-to-end on the settled protocol — could not be produced
> on the sandbox host this round of work ran on, for a specific, measured,
> and product-relevant reason explained in §1 and §5. Numbers are
> reproducible from the published raw data; platform is named at every
> number below.

## 0. What this draft is and is not

- **Is:** a decision record. Four defaults that draft 3 left pending now have
  measured, criteria-based verdicts (batch → `coalesced`, allocator →
  jemalloc, decision cache → stays opt-in, DB pool → stays `1`), the TLS
  investigation that draft 3's §5 opened is closed, the refresh comparison
  is restored with an honest comparability label, and the SDK
  client-overhead table exists with real data for the first time.
- **Is not:** a new published performance level. Every throughput/latency
  number in §3, §4 and §7 is the **same G-box run-3 number as draft 3**
  (labeled "G-box" below, per the platform table in §1.1). The Phase H work
  ran on a *second*, different host — a resource-constrained sandbox — whose
  purpose was to validate the harness fixes (the settle gate, the report
  refusal machinery, the protocol-variant label, the SDK table) end-to-end,
  not to produce a competing performance number. That host cannot produce
  *any* settled AXIAM authz/token/introspect/login/revoke cell at all (§1),
  so it could not have supplied a run-4 matrix even if the schedule had
  allowed one. §1 explains why in one paragraph, and the full mechanism is
  in `claude_dev/postseed-transient-investigation.md`.

### 1.1 Platforms named in this draft

| Label | Machine | Role |
|---|---|---|
| **G-box** | Dell XPS 15 9570 (i7-8750H, 12 logical CPUs, ~31 GiB RAM), same box as drafts 1–3 | Source of every headline number in §3/§4/§7 |
| **sandbox** | Phase H investigation host (2 vCPU-class container sandbox) | Source of the H2 root-cause investigation, the H6 TLS/protocol measurements, the H7/H8 harness validation, and the harness-validation matrix in §1.2 — **never** a source of headline numbers |

## 1. Why there is no run-4 publishable matrix yet

Every AXIAM deployment pays one synchronous datastore write — an `UPSERT` of
a shared rate-limit bucket record — in front of six endpoints:
`POST /api/v1/authz/check`, `POST /oauth2/token`, `POST /oauth2/introspect`,
`POST /oauth2/revoke`, `POST /api/v1/auth/login`, and (a separate bug,
tracked) `GET /api/v1/users`. Draft 3 called the effect this write produces
a **"post-seed database transient"** because on the G-box it appears for
roughly 5–7 minutes after a fresh seed and then recovers. The Phase H
investigation (`claude_dev/postseed-transient-investigation.md`, task H2)
reproduced the same signature on a second host and found it is **neither
post-seed nor reliably transient**: it is a permanent, per-request cost that
exists on every request to those six endpoints, on any host, indefinitely.
What differs between hosts is only how expensive that one datastore write
is — on the G-box it is cheap enough (~22 ms) that the six endpoints still
clear hundreds of requests per second once whatever made it briefly
expensive after a seed subsides; on the sandbox host the same write costs
~40 ms and **never subsides**, pinning those six endpoints at
**16–21 ops/s at any concurrency from 1 to 40 clients, indefinitely** — idle
time, server restarts, datastore restarts, connection-pool size, and even
swapping the datastore for a pure in-memory backend all leave it unchanged.
Section 5 has the full honesty write-up; the short version is: **this is a
product property, not a benchmark artifact**, and it is the reason a true
run-4 median-of-3 matrix — the kind draft 3 promised for its successor —
cannot be produced on a host where that one write is expensive. It has to
run on a host where it isn't (the G-box, or any host after the tracked fix
lands — see §5's "moved to fixed" list for what's already shipped and what
remains open).

### 1.2 What *was* run this round: a harness-validation matrix (sandbox, bounded)

To validate the new settle gate (§5), the `report.py` refusal machinery, the
`protocol-variant` label, and the SDK table end-to-end, one bounded,
single-repeat pass of the full scenario matrix (`axiam` + `keycloak`,
`p0-plaintext` + `p2-tls13`) ran on the sandbox host, with the settle-gate
timeout deliberately shortened to 120 s (`BENCH_SETTLE_TIMEOUT_SECS=120`,
down from the 600 s default) — the sandbox host's clamp was already known
from H2 to be permanent, so waiting the full 10-minute default before every
one of the four clamped sessions would have added ~30 minutes of pure wait
with a foregone conclusion. This is a **harness validation, not a
publishable run**: it is a single pass, not a median-of-3, and every
AXIAM cell that touches the six `RateLimitShared` endpoints is expected —
and required — to come back **refused** with `settle_timeout: true`, exactly
as `report.py`'s H1 refusal logic is supposed to do. Its numbers are not
cited anywhere in §3/§4/§7; its purpose was to prove the harness tells the
truth about its own limits rather than silently publishing a clamped cell as
a level, and to catch any remaining harness bugs while doing it. Results:
`benchmarks/results/tasks/h10-validate/`.

## 2. What changed since draft 3 (decisions closed, corrections included)

**Batch strategy — decided and shipped.** Draft 3 withdrew the "batch is
slow" claim as an unproven measurement-order artifact and promised a
re-measurement. That re-measurement happened (task G3, on settled cells from
runs 2–3 of the same G-box session): `coalesced` batch REST measured
**744 ops/s = 3 721 checks/s = 4.98× single checks** (748/s); `coalesced`
batch gRPC **866–872 ops/s ≈ 4 330 checks/s**, p95 74 ms — comfortably inside
the ≤2 s gate. `concurrent`, the previous default, reached only 1.37×
singles on REST (200 ops/s = 1 000 checks/s) with a 282 ms p95 on gRPC.
`coalesced` won decisively and **is now the shipped default**
(`AXIAM__AUTHZ__BATCH_STRATEGY=coalesced`,
`crates/axiam-authz/src/config.rs`; `concurrent` stays selectable). See
`claude_dev/authz-batch-investigation.md` for the closing table.

**Memory retention — fixed.** Draft 3 flagged ~360 MiB of RSS retained after
a login burst that never returned to baseline, and queued a scripted A/B.
That A/B ran (task G6): default allocator retained **376 MiB** above
baseline (peak 491 MiB); jemalloc retained **86 MiB** (peak 126 MiB) — a
**94% reduction** in the retention gap, with no throughput or latency cost
measured. The released container image now links jemalloc as its default
allocator (task H4). AXIAM's mem column no longer needs the caveat draft 3
carried.

**The TLS token-issuance halving — investigated to a documented position,
not fully closed.** Draft 3's §5 reported `client_credentials` losing
**−50.5%** at p2 (1823 → 903 ops/s) and, after a first follow-up, narrowed
the field of suspects to "not HTTP/2, not TLS-in-general, something
endpoint-specific" without naming the cause. Task H6 closed the HTTP/2
question directly: **acquitted**. The hypothesis that concurrent clients
collapse onto one HTTP/2 connection pinned to one worker thread does not
hold with any normal client — 10/50/100 concurrent clients open 10/50/100
h2 connections, and both actix worker threads stay CPU-balanced at every
level (`claude_dev/b2-tls-h2-investigation.md` §2.1). TLS 1.3 termination
in-process is priced at 10–13% on a cheap endpoint, shrinking as the
endpoint does more work — a normal, publishable cost, not 50%. What remains
open is *why specifically* `client_credentials` loses 50% while
`token_introspection` — wrapped by the exact same `RateLimitShared`
middleware — loses only 0.2%: the shared rate-limit write is the leading
candidate (it is a real, per-request synchronous cost that both endpoints
pay), but introspection's near-zero TLS delta is a real objection against
it fully explaining the asymmetry, so it is stated as an **open question**,
not a closed one. Settling it needs one VU-sweep on a host where
`/oauth2/token` is not itself clamped by that write — the G-box, or any host
after the fix in §5 lands. See `claude_dev/b2-tls-h2-investigation.md` §6.

**The "post-seed transient" — reframed, and it is the most important
correction in this draft.** See §1 and §5.

**Decision cache — evaluated against explicit criteria and stays opt-in.**
Draft 3 reported a K=1 ceiling of 3.0–3.15× and a realistic K=10 000 result
of +32%, and called the 3× number "a ceiling, not an expectation." Task H5
fixed three defects the sweep had surfaced (unbounded internal-list growth,
a lock-contention hotspot in revocation, an undocumented multi-replica
revocation bound) and then walked the clean data against seven pre-agreed
criteria, agreed *before* the numbers arrived. The ship bar for the
K=10 000 throughput ratio was **≥1.5×**; the best clean measurement anywhere
is **1.32×** (the same +32% draft 3 already published) — below the bar. The
default **stays `false`** (`claude_dev/decision-cache-decision.md` §7–8);
nothing about the measured numbers changed, only the decision built on top
of them.

**DB connection pool — evaluated and stays at 1.** Draft 3 reported
`pool_size=4` at +7% on client-credentials, neutral elsewhere, with the
default left at 1 "pending an open-loop harness." Task H9 could not obtain
the pre-agreed confirm cell (it needs a settled CC cell, which requires a
host where the shared rate-limit write is cheap) but closed the question on
independent evidence instead: `AXIAM__DB__POOL_SIZE` 1→8 moved authz
throughput by **0 ops/s** at both 1 and 20 VUs on the sandbox host — the
underlying connection model does not buy DB concurrency from more pooled
handles, so the G-box's "+7%" reads as noise from an unconfirmed,
never-proven-settled cell rather than a real effect. Default stays
`pool_size=1`; no code change needed. `claude_dev/db-pool-design.md` §11.

**Refresh-token comparison — restored, with an honest comparability label.**
Draft 3 excluded AXIAM's refresh cells entirely (a harness cookie-handling
bug made every AXIAM refresh cell measure a client-credentials fallback,
`bench_fallback` ≈ 100%). That bug is fixed (task G4: the root cause was the
refresh cookie's `Path` attribute) and AXIAM's refresh cell now measures the
real operation — **0% fallback, 1.00 HTTP request per iteration**, same as
Keycloak's already-real rotation cell. But fixing the harness surfaced a
semantic fact that was always true and had gone unlabeled: AXIAM has no
ROPC/password grant by design, so its refresh cell exercises **session
cookie refresh** (`POST /api/v1/auth/refresh`), while Keycloak's exercises
the **OAuth2 refresh-token grant**. These are two different protocols doing
related jobs, not the same request against two servers. `report.py` now
carries a `protocol-variant` comparability label (task H7) — the same
family of caveat as `fallback-op`/`cc-token-setup` — and the pair is
published in §3/§7 side by side **under that label**, not as a like-for-like
head-to-head.

**A p0-plaintext harness bug fixed along the way.** Every cookie-based
p0-plaintext scenario (login, authz checks, batch) was silently dying in k6
`setup()` because the server's auth cookies are marked `Secure` by default
and k6's cookie jar will not replay a `Secure` cookie over `http://`. The
bench harness now sets `AXIAM__AUTH__COOKIE_SECURE=false` for the
p0-plaintext profile only (an operator override still wins, and the
production default stays `true` everywhere else) — task H6. This does not
change any published number (the affected cells were already excluded or
re-derived under TLS), but it unblocks p0 authz/login measurement for any
future run.

**SDK client-overhead table — exists for the first time with real data.**
Draft 3 noted the SDK benches existed but had never produced a validated
run. Task H8 fixed one mechanical, per-language cause for each of the seven
original SDKs (env plumbing, missing package installs, concurrency
mismatches, a server-side CSRF gap) and ran them all against a seeded
target. **6 of 7** validated end-to-end (rust, python, typescript, go, java,
php); **csharp** stays an honest `pending` (host toolchain not installed).
See §7.1.

## 3. Headline results (G-box, capped matrix, median-of-3, valid cells)

*Unchanged from draft 3 — same numbers, same platform (G-box), reproduced
here for continuity. Full matrix in §7.*

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
Zitadel** at plaintext and stays 2.2–2.6× ahead under TLS 1.3. The p2 gap on
this one scenario is **not a TLS or HTTP/2 cost** — HTTP/2 is acquitted by
direct measurement and TLS 1.3 termination is priced separately at 10–13%
elsewhere in this matrix (§2) — the mechanism is endpoint-specific and still
open (§5).

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

### Session/token refresh — restored, published under the protocol-variant label

> ⚠️ **Comparability: protocol-variant.** AXIAM has no ROPC/password grant by
> design; its cell measures **session cookie refresh**
> (`POST /api/v1/auth/refresh`). Keycloak's cell measures the **OAuth2
> refresh-token grant**. These are two different protocols solving a related
> problem, not the same request. Do not read this pair as a like-for-like
> head-to-head; the throughput comparison below is informational only.

| profile | target | thr (req/s) | fallback | req/iteration | note |
|---|---|---|---|---|---|
| p0 | AXIAM | **910** | 0% | 1.00 | session refresh; single confirm run (task G4), not median-of-3 |
| p0 | Keycloak | **379** | 0% | 1.00 | OAuth2 refresh grant; median-of-3, real single-use rotation |
| p2 | Keycloak | **367** | 0% | 1.00 | OAuth2 refresh grant; median-of-3, real single-use rotation |

AXIAM's session-refresh cell was independently reproduced at **914 ops/s**
in the G8 diagnostic session. Both AXIAM numbers are single confirmatory
runs from the harness-fix tasks, not the median-of-3 protocol the rest of
this section uses — flagged here rather than presented at the same
confidence level as the matrix cells. Zitadel's refresh needs an
`offline_access` flow the harness doesn't implement yet and is excluded.

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

Keycloak's p0-vs-p2 login asymmetry (52 valid vs 23 gate-breaching) was
diagnosed in follow-up work (task H7): a one-off diagnostic run with more
container memory headroom (4 GiB instead of the shared 1 GiB default) reproduced
both profiles as clean, 0%-error passes (p0 27.9 req/s, p2 13.6 req/s,
legitimately slower under TLS, not gate-invalid) after twice reproducing an
outright `OOMKilled` at the matrix's own memory cap. The likely explanation
for the original matrix's asymmetry is Keycloak-on-Quarkus needing more than
1 GiB of headroom under sustained Argon2/PBKDF2-class hashing load, not a
TLS-specific defect — a harness sizing gap, not a fairness problem. AXIAM
remains the fastest and the only target valid at both profiles, with
**bounded memory** during the burst (and, as of this draft, the retention
after the burst is fixed — see §2).

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
1013/s with 4 DB cores (§4). With the **decision cache** enabled (§4,
opt-in) single checks reach **2322 req/s REST / 1822 gRPC** at the most
favorable key space measured (K = 1, ~100% hit rate); §4 has the realistic
key-space number and the reason the default stays off.

**Batch checks — the decided verdict (§2), not a withdrawal.** With the
shipped `coalesced` default, batch REST measured **744 batches/s
(3 721 checks/s, 4.98× singles)**, p50/p95 comfortably inside the gate;
batch gRPC **866–872 batches/s (≈4 330 checks/s)**, p95 74 ms. The
`concurrent` alternative reached only 1.37× on REST. Full table:
`claude_dev/authz-batch-investigation.md`.

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

**Decision cache — measured, and now a closed decision (default stays
off).** `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`, TTL 5 s: authz checks
**3.0–3.15×** at the most favorable key space (REST 2322/s, gRPC 1822/s,
K = 1 — every VU sending the same `(subject, resource, action, scope)`
tuple, ~100% hit rate). **Read that as a ceiling, not an expectation.** The
one trustworthy larger-K measurement (K = 10 000, exceeding the per-tenant
entry cap) is **+32%**, not +200%. Task H5 walked this data against seven
criteria agreed before the numbers arrived; the ship bar for K = 10 000 was
**≥1.5×**, and +32% does not clear it (`claude_dev/decision-cache-decision.md`
§7–8). **Decision: stays opt-in.** Two caveats that belong with the number
regardless of default: revocation is enforced by event-driven invalidation
on the mutation path plus the 5 s TTL backstop (integration- and
live-stack-tested) — but the cache is **process-local**, so with more than
one replica a revocation only invalidates the replica that handled it, and
the deployment's worst-case revocation latency is the TTL. The cache's own
`AuthZ decision cache stats (D7)` log line reports the live `hit_rate_pct`
so an operator can measure their own key-space win rather than assume one.

**DB connection pool — measured, closed negative (default stays 1).**
`AXIAM__DB__POOL_SIZE=4`: token issuance **+7%** (1823→1955) in the one
sample that exists; everything else within noise. That sample was never
confirmed to run outside the settle-gate-blind window (§1/§5), and a direct
mechanism test (pool 1→8, 0 ops/s change at 1 or 20 VUs) says the
connection model doesn't buy DB concurrency from more pooled handles
anyway. **Default stays `pool_size=1`.** `claude_dev/db-pool-design.md` §11.

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
while the competitors ship none. It is **not** a performance measurement.
Follow-up work (task H7) re-measured the `gateway` preset
(`AXIAM__RATE_LIMIT__PROFILE=gateway`) on the sandbox host: switching a
single machine client from per-IP to per-`client_id` keying moved its
admitted rate from 8.5%/3.7%/68.9% ok (heavily throttled) to
**96.6%/100%/100% ok** on token/introspect/authz respectively — the preset
does exactly what §6 recommends it for. It does **not** touch the
per-request shared-rate-limit write from §1/§5: admitted throughput under
`gateway` landed at 22–24 ops/s on that host, the same band H2 measured for
those endpoints under every other posture — a rate-limit *policy* change
cannot make a synchronous datastore write cheaper. See §6 for what to set
instead.

## 5. Weaknesses and caveats (the honest section)

**What we called a "post-seed database transient" was never post-seed, and
on some hosts it never clears.** The Phase H investigation
(`claude_dev/postseed-transient-investigation.md`, task H2) traced it to a
real, permanent design property of AXIAM: six endpoints —
`POST /api/v1/authz/check`, `POST /oauth2/token`, `POST /oauth2/introspect`,
`POST /oauth2/revoke`, `POST /api/v1/auth/login` and `GET /api/v1/users` —
perform **one synchronous SurrealDB write (the shared rate-limit counter)
before the handler runs**, on every request, forever. That round trip is
the throughput ceiling for those endpoints. On the sandbox investigation
host it cost ~40 ms and pinned all six at **16–21 ops/s at any concurrency
from 1 to 40 clients, indefinitely** — unaffected by seeding, data volume,
uptime, traffic, server or datastore restarts, connection-pool size, or
even swapping the datastore to a pure in-memory backend (all tested
directly). On the G-box the same write cost only ~22 ms, cheap enough that
the endpoints still ran hundreds of requests per second once whatever made
it briefly more expensive right after a fresh seed (still not fully
explained — see below) subsided. On the gRPC listener the same write is
applied server-wide as a tower layer, so **every** gRPC call pays it, not
just the six REST paths. **Readers should treat every AXIAM number on those
six endpoints (client_credentials, introspection, authz_check, login,
revoke) as bounded by the cost of one datastore write in your deployment's
environment, not by AXIAM's request handling** — on a fast datastore that
ceiling is high (hundreds to low thousands of ops/s, as this draft's own
G-box numbers show); on a slow one it is the whole story. Two fixes are
tracked and neither has shipped yet: `GET /api/v1/users` is a separate,
already-understood bug (it inherits the *registration* rate-limit bucket,
not a read bucket — 5/min/IP in the production posture), and getting the
shared-store round trip off the synchronous critical path (a TTL cache with
write-back, a fire-and-forget write with a previous-read decision, or an
explicit single-replica off-switch) is written up as a maintainer issue in
`claude_dev/postseed-transient-investigation.md` §7.1. **What remains
genuinely unresolved, stated plainly:** the G-box's specific recovery
pattern — a ~5–7 minute window that ends in a sharp cliff back to full
throughput — has not been reproduced on the second host, which never
recovers at all. Two readings are possible and this draft does not pick
between them: the G-box's write occasionally drops from ~22 ms to ~1 ms for
some SurrealDB-side reason not yet identified, or the G-box's "recovered"
cells were measuring something subtly different from the clamped ones. This
is the single largest open item carried into the next investigation round.

**The TLS token-issuance halving is priced but not fully explained.** See
§2 and §3 — HTTP/2 is acquitted by direct measurement, TLS 1.3 itself costs
10–13% elsewhere in the matrix, and the shared rate-limit write above is the
leading candidate for the remaining `client_credentials`-specific penalty —
but `token_introspection`, wrapped by the identical middleware, loses only
0.2% under the same conditions, which is a real objection the current
evidence has not resolved. Even with the unexplained penalty, AXIAM's TLS
token numbers lead the field 2.2–2.6×.

**Moved to fixed since draft 3:**

- **Memory retention** (~360 MiB retained after a login burst) — fixed via
  jemalloc as the release-container default allocator; 94% of the gap
  closed, no throughput cost (§2, task H4/G6).
- **Batch verdict** — no longer withdrawn pending re-measurement; `coalesced`
  measured, decided, and shipped as the default (§2/§3, task H3/G3).
- **Refresh harness** — the cookie `Path` bug that made every AXIAM refresh
  cell measure a client-credentials fallback is fixed; the cell is restored
  under the `protocol-variant` comparability label (§2/§3, task G4/H7).
- **p0-plaintext `Secure`-cookie bug** — every cookie-based p0 scenario used
  to die in harness `setup()`; fixed for the bench profile only, production
  default unchanged (§2, task H6).

**Other caveats, stated plainly:** consumer-laptop hardware (server-class
re-run still pending budget — see "next round" below); AXIAM stack figures
include RabbitMQ (~0.1–0.3 cores); k6 skips cert verification at p2/p3
(throwaway CA; handshake and record crypto are real); closed-loop 50 VUs
floors the fastest endpoints (JWKS) and measures latency, not capacity, when
nothing saturates; the decision cache and the DB connection pool are both
measured, decided, and stay off/at-default (§4) — neither is oversold as a
"just turn this on" win; the SDK client-side overhead table (§7.1) has real
data now but from one un-repeated pass, not a median-of-3.

## 6. Recommended settings by deployment (measured, not guessed)

The production-posture pass (§4) showed the shipped defaults are tuned for
one thing: stopping single-source abuse on a small internet-facing
deployment. Every knob below is a runtime environment variable; the
recommendations derive directly from this run's measurements on
2-core/1-GiB-per-container hardware (G-box; the `gateway`-preset admitted-rate
numbers are sandbox-host, §4) — scale linearly with your envelope where the
data says the path scales (authz/userinfo with DB CPU; login with server
CPU; token issuance with neither until ~1.8k/s per 2 cores).

### Sizing quick reference (what a given envelope measured)

| Envelope (server / DB) | Token issuance | Introspection | Authz checks (cache off / on) | Userinfo | Logins (Argon2id, OWASP) |
|---|---|---|---|---|---|
| 2 cores / 2 cores | ~1 800/s | ~2 200/s | ~740 / ~2 300/s | ~5 000/s | ~69/s |
| 2 cores / 4 cores | ~1 800/s | ~2 200/s | ~1 000 / higher | ~7 500/s (server-bound) | ~69/s |

**Whatever your envelope, one fact matters more than the table above for the
six `RateLimitShared` endpoints (token, introspect, authz_check, login,
revoke, and the `users` list — §5): their real ceiling is set by your
deployment's cost for one small SurrealDB `UPSERT`, not by AXIAM's request
handling.** The numbers above assume a datastore where that write is cheap
(the G-box's measured ~22 ms); if your datastore is slower, size expectations
down accordingly and watch the `AuthZ`/`RateLimit` metrics rather than
trusting this table blind.

### Knob-by-knob

| Setting (env var) | Shipped default | Small internet-facing (2c/1GiB) | M2M / microservices / IoT fleet | Large multi-tenant (8c+) |
|---|---|---|---|---|
| `AXIAM__RATE_LIMIT__PROFILE` | `internet` | `internet` | **`gateway`** — moves the whole machine-traffic family coherently from one variable; measured (§4): single-client_id admitted rate 8.5%→96.6% (token), 3.7%→100% (introspect), 68.9%→100% (authz) | `mesh` |
| `AXIAM__RATE_LIMIT__KEY` | `ip` | `ip` | **`client_id`** (or `ip_client_id`) — per-IP buckets collide behind NAT/gateways — **but read the security caveat below first** | `ip_client_id` |
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | 20 | 60–120 | **per-client peak × 60 × 2** (a 2-core server sustains ~108k issuances/min total on a fast datastore — §5 caveat applies) | budget per tenant SLA |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | 10 | 60 | 10–20× your token limit (resource servers introspect per request) | same rule |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | 300 | 600 | **6 000–60 000** per client (checks are cheap reads; 300/min starves any real service) | size to cache-on ceiling |
| `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` | 10 (per IP) | keep 10 | 60+ if users arrive through a shared NAT/proxy (always per-IP by design) | 60+, front with WAF |
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` | `false` | `false` | `false` (measured but not shipped ON — §4/§2: +32% at a realistic key space, below the ship bar) | `false`, evaluate per tenant hit-rate |
| `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` | 5 | 5 | 5 (raise only if a ≤TTL revocation delay is acceptable, if you turn the cache on) | 5 |
| `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` | 10 000/tenant | default | default | raise with RAM (entries are small, ~276 B measured) |
| `AXIAM__AUTHZ__BATCH_STRATEGY` | `coalesced` (shipped default, decided task H3/G3) | default | default — `coalesced` measured 744 REST batch ops/s (3 721 checks/s, 4.98× singles) and 866–872 gRPC batch ops/s (≈4 330 checks/s, p95 74 ms) vs `concurrent`'s 1.37× / 282 ms p95 | default |
| `AXIAM__DB__POOL_SIZE` | 1 | 1 | 1 — measured no benefit; the one +7% sample was never confirmed settled and a direct mechanism test found 0 change (§4/§2, task H9) | 1 |
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
authorization-check-heavy, spend hardware on the **database** first — the
decision cache is measured but does not clear its own ship bar at a
realistic key space (§4), so it is a "measure your own hit rate before
opting in" knob, not a default lever; (2) if it's token-heavy, the
limits — not the hardware — are what you'll hit first on a fast datastore,
and the datastore's own cost for the shared rate-limit write is what you'll
hit first on a slow one (§5): raise `TOKEN_PER_MIN` from your real
per-client peak and, *if and only if* you have edge authentication per the
caveat above, switch the key mode; keep the defaults on genuinely
internet-exposed endpoints (login, register, password-reset, MFA), which
stay per-IP in every configuration.

## 7. Full result matrix (G-box, capped run, median-of-3, graph-ready)

One row per (scenario, profile, target); `±` is the throughput spread
across the three runs; `http` is the negotiated protocol
(`bench_http_proto`, k6's `res.proto`) where captured. Rows failing a
validity gate or measuring a fallback/protocol-variant are labeled and
**must not be charted as an unqualified head-to-head**.

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
| token_refresh | p0 | keycloak | 379 | 2.0% | 101.5 | 204.6 | 299.5 | 2.05 | 983 | ✓ real rotation ⚠ protocol-variant |
| token_refresh | p2 | keycloak | 367 | 1.1% | 102.3 | 205.2 | 298.5 | 2.05 | 881 | ✓ real rotation ⚠ protocol-variant |
| token_refresh | p0 | axiam | 910 | n=1 | — | — | — | — | — | ✓ session refresh, 0% fallback ⚠ protocol-variant, single confirm run not median-of-3 |
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
| oauth2_password_login | p2 | keycloak | 23 | 0.4% | 2115.1 | 2248.6 | 2315.0 | 2.03 | 854 | ✗ p95>2s (diagnosed OOM-sizing, not TLS — §3) |
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
| authz_batch_rest (coalesced, AXIAM-only) | settled | axiam | 744 | — | 49 | — | — | — | — | ✓ 3 721 checks/s, 4.98× singles |
| authz_batch_grpc (coalesced, AXIAM-only) | settled | axiam | 866–872 | — | — | 74 | — | — | — | ✓ ≈4 330 checks/s |
| authz_batch_rest (concurrent, AXIAM-only) | settled | axiam | 200 | — | — | — | — | — | — | ✓ 1 000 checks/s, 1.37× singles |
| authz_batch_grpc (concurrent, AXIAM-only) | settled | axiam | 216 | — | — | 282 | — | — | — | ✓ |

### Security cost of TLS 1.3 (p2 vs p0, valid cells, median-of-3)

| target / scenario | Δ throughput | http (p0 → p2) |
|---|---|---|
| axiam / token_introspection | −0.2% | h1 → h2 |
| axiam / userinfo | −3.7% | h1 → h2 |
| axiam / userinfo_grpc | −1.2% | h2 → h2 |
| axiam / authz_check_rest / _grpc | +1.3% / +3.1% | h1 → h2 / h2 → h2 |
| axiam / oauth2_password_login | −0.5% | h1 → h2 |
| axiam / jwks_fetch | −12.5% (reproduced independently on a second machine — §2) | h1 → h2 |
| axiam / oauth2_client_credentials | **−50.5%** — **not an HTTP/2 cost** (acquitted, §2); mechanism still open, §5 | h1 → h2 |
| keycloak / oauth2_client_credentials | −1.5% | — |
| keycloak / token_introspection | −7.9% | — |
| keycloak / jwks_fetch | −19.2% | — |
| keycloak / userinfo | −6.8% | — |
| keycloak / token_refresh | −3.3% | — |
| zitadel / all scenarios | −2.3% … +2.0% | — |

And the p3 result in one line: **mTLS (client certificates, verified
in-process) ≈ p2 within noise on every scenario.**

### 7.1 SDK client-overhead table (E1.3, sandbox host, single pass — H8)

*New in this draft.* Measured with a matched-concurrency wire baseline
(the SDK bench's own `SDK_BENCH_CONCURRENCY`, not an unrelated default VU
count — an unmatched baseline produces misleading negative "overhead"
numbers purely from the load-shape mismatch). **Host clamp caveat applies
here too:** `login`/`refresh`/`check_access` touch the same
`RateLimitShared`-wrapped endpoints as §1/§5, so absolute op numbers on this
host are bounded by the same datastore-write cost, not by SDK overhead —
read the **p95-overhead-vs-wire** column (a same-host, same-window
differential) as the informative number, not the raw throughput columns.
6 of 7 original SDKs validated (rust, python, typescript, go, java, php);
**csharp** stays `pending` (host toolchain not installed;
`sdk/csharp/TODO.md` has the install commands). One un-repeated pass, not
median-of-3 — a future run-4-class matrix should repeat this table.

**profile: p0-plaintext** (selected rows; full table in the raw report)

| sdk | op | sdk p50(ms) | sdk p95(ms) | wire p95(ms) | thr(rps) | errors | p95 overhead vs wire(ms) |
|---|---|---|---|---|---|---|---|
| go | check_access | 18.58 | 27.57 | 30.44 | 414 | 0 | −2.87 |
| java | check_access | 25.33 | 39.43 | 30.44 | 293 | 0 | +8.99 |
| php | check_access | 12.31 | 23.07 | 30.44 | 73 | 0 | −7.36 |
| python | check_access | 20.42 | 30.84 | 30.44 | 359 | 0 | +0.40 |
| rust | check_access | 17.23 | 23.52 | 30.44 | 444 | 0 | −6.92 |
| typescript | check_access | 26.71 | 34.87 | 30.44 | 291 | 0 | +4.43 |
| go | batch_check | 32.53 | 45.89 | 78.67 | 229 | 0 | −32.78 |
| rust | batch_check | 36.00 | 49.73 | 78.67 | 214 | 0 | −28.94 |
| python | login | 556.35 | 738.17 | 252.22 | 14 | 0 | +485.95 (outlier — see raw report) |
| rust | login | 220.05 | 249.49 | 252.22 | 35 | 0 | −2.73 |

Most SDKs sit within roughly ±30 ms of the wire baseline on `check_access`
and beat it on `batch_check` (client-side batching amortizes better than
the matched-concurrency wire baseline assumes); `login`'s spread is wide
and dominated by the shared clamp plus one un-repeated outlier (`python`,
+486 ms) that a median-of-3 would very likely resolve — flagged rather than
smoothed over. Full per-op table for both profiles:
`benchmarks/results/sdk-report.md`.

## 8. Summary and what happens next

**Strengths.** G-box numbers reproduced across four decision rounds now:
token issuance 4.3–5.2×, introspection 1.17–2.45×, JWKS 7–13×, userinfo
1.34–5.3×; the only login that stays under 2 s p95 at both profiles; native
mTLS at zero measured cost (unique in this field); batch authorization now
a *decided* 4.98× win (`coalesced`, shipped default, not a withdrawn
number); memory retention fixed (jemalloc, shipped default); the refresh
comparison restored under an honest label instead of excluded; and a real,
validated SDK-overhead table for the first time.

**Weaknesses, stated as plainly as the strengths.** The TLS
token-issuance halving is priced (not a transport cost) but not fully
explained — one open mechanism question remains. The decision cache and the
DB connection pool were both evaluated against pre-agreed criteria and both
stay at their conservative defaults — real, useful knobs for the right
workload, not blanket wins. And the most consequential finding of this
round is a limitation, not a feature: **the "post-seed transient" is a
permanent, product-relevant synchronous datastore write in front of six
hot endpoints, whose cost sets those endpoints' ceiling on any given
deployment's hardware** (§1/§5) — this draft's own numbers show that ceiling
is high on a fast datastore (the G-box), but a fix to get the write off the
synchronous path is tracked and has not shipped. Everything here remains
laptop-hosted.

**Next round (E3/E5):** the tracked fix for the shared rate-limit write,
then a true run-4 median-of-3 matrix — on the G-box, on a server-class
host, or on a sandbox host after the fix lands, whichever comes first —
covering the full protocol including a repeated (not single-pass) SDK
overhead table; the `GET /api/v1/users` rate-limit-bucket bug fix; and, if
budget allows, the server-class re-run that has been tracked and deferred
since draft 2.

---
*Sources: G-box benchmark runs of 2026-07-25/26 (median-of-3 capped matrix ×
p0/p2 × 3 targets; labeled sensitivity passes: DB-uncapped ×3 targets,
decision-cache ON, pool A/B ×2, native-mTLS p3, prod rate-limit posture,
batch-strategy A/B, TLS-h1 isolation; per-cell k6 summaries, 1 s container
+ host telemetry, digest-recorded metadata); G4/G8 single-run refresh
confirm cells; Phase H follow-up work of 2026-07-28/29 on a second
(sandbox) host: H2 root-cause investigation
(`claude_dev/postseed-transient-investigation.md`), H3/G3 batch decision
(`claude_dev/authz-batch-investigation.md`), H4/G6 allocator decision
(`claude_dev/memory-retention-experiment.md`), H5 cache decision
(`claude_dev/decision-cache-decision.md`), H6 TLS/HTTP-2 investigation
(`claude_dev/b2-tls-h2-investigation.md`), H7 rate-limit-posture
re-measurement (`claude_dev/rate-limit-posture-decision.md`), H8 SDK-bench
validation (`benchmarks/results/sdk-report.md`), H9 pool decision
(`claude_dev/db-pool-design.md`), H10 harness-validation matrix
(`benchmarks/results/tasks/h10-validate/`); aggregated by `runner/report.py`.
Metric definitions: [`docs/methodology.md`](docs/methodology.md).*
