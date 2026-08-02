# AXIAM Benchmark Analysis — Fifth Draft (Run 4: the first clean matrix)

> **Status: fifth benchmark draft, and the first whose headline numbers come
> from an uncontaminated end-to-end run.** Draft 4 (2026-07-29) explained why
> no publishable "run 4" existed yet: every prior AXIAM number on the six
> hottest endpoints was bounded by one synchronous datastore write (the
> shared rate-limit counter), a product defect we found, root-caused, and
> fixed in the open. **Run 4 (2026-08-01/02) is the re-measurement on the
> fixed build** — full median-of-3 matrix, three targets, two TLS profiles,
> five labeled sensitivity passes, and the first complete 11-language SDK
> pass. The fix is confirmed at matrix scale: the affected endpoints gained
> +47% to +284% with no regression anywhere else (§2). This draft also adds
> a first-class **resource usage** section (§5) — memory and CPU during the
> tests, per container, graph-ready — and updated **production rate-limit
> guidance** (§7) derived from the measured capacity of each endpoint.
> Numbers are reproducible from the published raw data; the platform is
> named at every number.

## 0. Setup at a glance

| | |
|---|---|
| Hardware | Dell XPS 15 9570 ("G-box": i7-8750H, 12 logical CPUs, ~31 GiB RAM) — same box as every prior draft; consumer laptop, server-class re-run still pending |
| Load | k6 v2.1.0, 50 VUs closed-loop, 30 s warmup + 120 s measure, median-of-3 repeats per cell |
| Caps | every *server* container: 2 CPUs / **2048 MiB**; every DB container: 2 CPUs / 1024 MiB; brokers 1 CPU / 512 MiB |
| Targets | AXIAM (post-fix build, SurrealDB + RabbitMQ) vs Keycloak 26 (Postgres) vs Zitadel v4 (Postgres) |
| Profiles | p0-plaintext, p2-tls13 (in-process TLS 1.3); p3-mtls as a labeled sensitivity pass |
| Validity | 42/48 matrix cells valid; every invalid cell listed with its reason (§8); settle gate cleared first-probe on every session, zero refused cells — a first |

**Why the memory cap changed since draft 4** (was 1024 MiB): Keycloak
could not reliably survive sustained password-login load at 1 GiB (it was
OOM-killed in diagnostics, and its container **peaked at 1 070 MiB in this
run** — above the old cap). We raised the cap to 2 GiB *for all three
targets equally* so Keycloak competes at its best. AXIAM's server peaked at
**172 MiB** — 8% of the same allowance (§5).

## 1. Headline results (median-of-3, valid cells, whole numbers rounded)

### Machine-to-machine token issuance (`oauth2_client_credentials`)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | cpu·ms per request |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **2 727** | 9.1 | **58.1** | **835** | **1.20** |
| p0 | Zitadel | 425 | 108.7 | 139.9 | 122 | 8.20 |
| p0 | Keycloak | 354 | 103.0 | 208.4 | 171 | 5.84 |
| p2 | **AXIAM** | **1 180** | 42.6 | **43.9** | 571 | 1.75 |
| p2 | Zitadel | 419 | 110.9 | 138.7 | 118 | 8.46 |
| p2 | Keycloak | 346 | 104.1 | 208.5 | 168 | 5.97 |

AXIAM issues **7.7× more tokens/s than Keycloak and 6.4× more than
Zitadel** at plaintext (up from 5.2×/4.3× in draft 4 — the rate-limit fix,
§2), and stays **2.8–3.4× ahead under TLS 1.3**. AXIAM's p2 drop on this
one endpoint (−57%) is a known open question — not a TLS/HTTP-2 cost in
general (introspection loses 1.6% under identical TLS) — see §6.

### Token introspection (RFC 7662)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | cpu·ms per request |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **4 387** | 5.9 | **48.5** | **1 288** | **0.78** |
| p0 | Keycloak | 1 860 | 7.5 | 81.9 | 786 | 1.27 |
| p0 | Zitadel | 932 | 48.2 | 66.1 | 250 | 4.00 |
| p2 | **AXIAM** | **4 316** | 6.2 | **45.6** | 1 232 | 0.81 |
| p2 | Keycloak | 1 715 | 8.1 | 83.0 | 733 | 1.36 |
| p2 | Zitadel | 909 | 50.4 | 67.8 | 239 | 4.19 |

Draft 4's closest head-to-head is no longer close: **2.4× Keycloak, 4.7×
Zitadel**, with a 1.7–1.8× better p95 than Keycloak and a near-zero TLS
penalty (−1.6%).

### JWKS fetch (RFC 7517)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **26 371** | 1.3 | **3.1** | **16 184** |
| p0 | Keycloak | 4 565 | 2.7 | 72.5 | 2 278 |
| p0 | Zitadel | 2 096 | 11.2 | 64.7 | 703 |
| p2 | **AXIAM** | **23 716** | 1.6 | **3.2** | 12 219 |
| p2 | Keycloak | 4 261 | 3.1 | 72.0 | 2 125 |
| p2 | Zitadel | 2 057 | 12.9 | 59.9 | 655 |

A 5.8–12.6× gap, still limited by the load generator rather than AXIAM
(k6 itself burned ~5 CPU cores; the AXIAM server sat at 1.6/2).

### OIDC userinfo — REST and gRPC

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | server-only cpu·ms/req |
|---|---|---|---|---|---|---|
| p0 | **AXIAM (gRPC)** | **12 665** | 3.0 | **6.0** | **6 067** | — |
| p0 | **AXIAM (REST)** | **4 547** | 5.4 | 51.4 | 1 376 | **0.25** |
| p0 | Keycloak | 3 783 | 3.0 | 76.8 | **1 891** | 0.53 |
| p0 | Zitadel* | 1 000 | 24.8 | 80.0 | 348 | 0.86 |
| p2 | **AXIAM (gRPC)** | **12 148** | 4.0 | **6.0** | 5 828 | — |
| p2 | **AXIAM (REST)** | **4 439** | 5.6 | 50.7 | 1 252 | 0.27 |
| p2 | Keycloak | 3 499 | 3.3 | 77.5 | **1 747** | 0.57 |
| p2 | Zitadel* | 998 | 26.6 | 78.3 | 336 | 0.96 |

*\* Zitadel authenticated with a machine-user token minted once in setup
(its user-login flow returns a session token the harness can't convert);
the measured endpoint and semantics are the same.*

On REST, AXIAM leads 1.2× Keycloak / 4.5× Zitadel while its DB is pegged
(uncapped: 7 215/s, §4). On whole-stack req/s-per-core Keycloak wins the
REST cell; on server-only CPU per request AXIAM is 2.1× cheaper — both
published. The real story is gRPC: **12.7 k identity reads/s at p95 6 ms**
— 2.8× AXIAM's own REST and 3.3× Keycloak's best number — where draft 4
measured 3.3 k/s (§2). Zitadel's own gRPC userinfo measured 180–185/s
(−82% vs its REST) on the same harness.

### Session/token refresh — published under the protocol-variant label

> ⚠️ **Comparability: protocol-variant.** AXIAM has no ROPC/password grant by
> design; its cell measures **session cookie refresh**
> (`POST /api/v1/auth/refresh`, CSRF double-submit, single-use rotation).
> Keycloak's cell measures the **OAuth2 refresh-token grant**. Two different
> protocols doing a related job — informational, not a like-for-like race.

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | fallback |
|---|---|---|---|---|---|
| p0 | AXIAM | **839** | 47.5 | 80.6 | 0% |
| p0 | Keycloak | 377 | 101.5 | 204.9 | 0% |
| p2 | AXIAM | **834** | 48.0 | 80.6 | 0% |
| p2 | Keycloak | 370 | 102.3 | 203.8 | 0% |

New since draft 4: AXIAM's refresh is now a full **median-of-3** cell (the
draft-4 number was a single confirm run). Zitadel's refresh needs an
`offline_access` flow the harness doesn't implement and stays excluded.

### Password login (all targets hash for real)

AXIAM **Argon2id** (OWASP params), Keycloak 26 **Argon2id** (default),
Zitadel **bcrypt** (default cost — far more expensive per verification;
tunable). Hash configuration dominates this scenario.

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | valid (p95 < 2 s, ≥2/3 runs) |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **69** | 698 | **774** | ✓ 3/3 |
| p0 | Keycloak | (44) | (1 031) | (1 301) | ✗ 1/3 runs valid |
| p0 | Zitadel | (2) | (22 079) | (25 533) | ✗ 0/3 |
| p2 | **AXIAM** | **67** | 706 | **850** | ✓ 3/3 |
| p2 | Keycloak | (53) | (856) | (1 010) | ✗ 1/3 runs valid |
| p2 | Zitadel | (2) | (22 197) | (25 314) | ✗ 0/3 |

AXIAM is the only target valid at both profiles, at **≤ 140 MiB of server
memory** during the burst (§5). Keycloak's cells are excluded by our own
validity gate, not by failure to function: even at the raised 2 GiB cap it
completed only 1 of 3 runs cleanly per profile (parenthesized numbers are
that single run, shown for transparency). Prior diagnostics showed
Keycloak wants ~3.5–4 GiB under sustained hashing load; the next run will
give its login cells exactly that, labeled. Zitadel's exclusion is its
default bcrypt cost (~22 s p50 at 50 VUs) — expected and tunable.

### Authorization decisions (AXIAM-only — no competitor equivalent)

Full RBAC evaluation (tenant-scoped roles, resource hierarchy, scopes)
against live data:

| scenario | profile | thr | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| authz_check_grpc | p0 | **887** | 38 | 86 | 92 |
| authz_check_grpc | p2 | **892** | 37 | 86 | 92 |
| authz_check_rest | p0 | 753 | 74 | 93 | 99 |
| authz_check_rest | p2 | 760 | 73 | 92 | 99 |

gRPC now leads REST by **+18% throughput at half the p50** (draft 4 had
gRPC 18% *behind* — that deficit was the fixed rate-limit write, §2). Both
are DB-saturated at the 2-core DB cap and scale to 1 434–1 678/s with 4 DB
cores (§4).

**Batch checks — an honest labeling note.** This run's batch cells
accidentally measured the *non-default* `concurrent` strategy (a benchmark
compose file still pinned the pre-decision default; now fixed): 199 batch
ops/s REST = 995 checks/s, ~1.3× singles. The shipped default is
`coalesced`, whose settled measurement remains the draft-4 verdict —
**744 batch ops/s = 3 721 checks/s = 4.98× singles (REST), 866–872 ops/s
≈ 4 330 checks/s (gRPC)**. Run 5 will re-measure `coalesced` at full
matrix scale; until then, treat 4.98× as the default's number and this
run's batch cells as the labeled alternative strategy.

## 2. The fix this run verifies (and what it changed)

Draft 4's most important finding was a defect, published openly: six hot
endpoints (token, introspect, revoke, authz check, login, users-list) paid
**one synchronous datastore write** (the shared rate-limit counter) before
the handler ran — and on the gRPC listener *every* call paid it. The fix
(a write-behind counter: decisions in-memory, one coalesced write per
bucket per interval) shipped after draft 4. Run 4 measures it end-to-end:

| endpoint (p0) | draft 4 (pre-fix) | **run 4 (post-fix)** | Δ |
|---|---|---|---|
| oauth2_client_credentials | 1 823 | **2 727** | +50% |
| token_introspection | 2 230 | **4 387** | +97% |
| authz_check_grpc | 603 | **887** | +47% |
| userinfo_grpc | 3 294 | **12 665** | **+284%** |
| authz_check_rest | 737 | 753 | +2% (DB-bound either way) |
| userinfo / jwks / login | ~flat | ~flat | unaffected paths, as expected |

The trade, restated from draft 4: cross-replica rate-limit enforcement is
now eventual rather than synchronous — bounded overshoot
`(replicas − 1) × arrival_rate_per_replica × sync_interval`, zero on a
single replica. The settle-gate machinery built to detect the old clamp
found nothing to refuse in this entire run — the first time that has ever
been true.

## 3. Security cost of TLS 1.3 (p2 vs p0, valid cells)

| target / scenario | Δ throughput |
|---|---|
| axiam / token_introspection | −1.6% |
| axiam / userinfo (REST) | −2.4% |
| axiam / userinfo (gRPC) | −4.1% |
| axiam / authz_check REST / gRPC | +0.9% / +0.6% |
| axiam / token_refresh | −0.6% |
| axiam / oauth2_password_login | −2.6% |
| axiam / jwks_fetch | −10.1% |
| axiam / oauth2_client_credentials | **−56.7%** — endpoint-specific, mechanism still open (§6) |
| keycloak (all valid cells) | −1.6% … −7.8% |
| zitadel (all valid cells) | −2.5% … +2.4% |

Most rows measure TLS 1.3 *plus* an HTTP/1.1→2 protocol change together
(the plaintext profile negotiates h1, the TLS profile h2); they are
labeled as such in the raw report. **Native mTLS (p3, client certificates
verified in-process, no proxy) again measured at parity with plain TLS 1.3
on every scenario** — client-cert verification is free on top of TLS,
which remains unique in this field and is the IoT headline.

## 4. Sensitivity passes (labeled, never mixed into head-to-heads)

**DB-uncapped (DB 2→4 cores; servers stay at 2).** Post-fix, DB CPU is the
product's main ceiling:

| cell (p0) | capped → uncapped | Δ |
|---|---|---|
| authz_check_rest / _grpc | 753 → **1 434** / 887 → **1 678** | +90% / +89% |
| oauth2_client_credentials | 2 727 → **4 484** | +64% |
| token_introspection | 4 387 → **6 249** | +42% |
| userinfo (REST) | 4 547 → **7 215** | +59% |
| token_refresh | 839 → 1 089 | +30% |
| jwks / login / userinfo_grpc | ±1% | not DB-bound |

Rule of thumb, confirmed harder than ever: **if your workload is
authz/identity-read heavy, give the database cores first.**

**Decision cache (opt-in, TTL 5 s) — measured at its best case.** With the
rate-limit fix in place, cache-ON at the bench's favorable keyspace lifts
gRPC checks to **11 598/s (13.1×)** and batch to ~26 000–45 000 checks/s —
but REST checks only +5% (791/s): the REST path's per-request session-
cookie validation (a DB read the decision cache deliberately does not
cover) becomes its own limiter. Read 13× as a ceiling at ~100% hit rate,
not an expectation — the realistic-keyspace measurement from draft 4
(+32% at K=10 000) still stands, the default **stays off**, and the server
logs its live hit rate so you can measure your own workload before opting
in. The REST-path session cost is now a tracked optimization target.

**Production rate-limit posture.** With the `internet` limits as they
shipped *at the time of this run* (token 20/min, introspect 10/min, authz
300/min, login 10/min), a single-IP 50-VU flood is throttled to the
configured trickle on every limited REST endpoint — all enforced within
measurement error — while unlimited paths run at full speed beside it
(userinfo 4 572/s, jwks 26 324/s — the 429 path is cheap). Two findings
from this pass, **both since acted on**:

1. The defaults did their abuse-stopping job and were far too strict for
   real machine fleets. The machine-endpoint defaults have been revised as
   a result (token 120/min, introspect 600/min, authz 1 800/min, revoke
   60/min; human endpoints unchanged) — §7.2. The measurements above
   describe the pre-revision numbers, which is what makes them the
   evidence for the change.
2. **It caught a real bug: the gRPC limiter admitted ~1/60th of its
   configured rate** (a per-second limit enforced against a per-minute
   window by one of the two cooperating limiter layers). Found by this
   benchmark, root-caused in code, and **fixed** —
   `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100` now really admits 100/s. The same
   fix scoped the gRPC ceilings per method family, so an identity read is
   no longer throttled by the authz limit (§7.2).

## 5. Resource usage during the tests (new in this draft — graph-ready)

Same load, same 2-CPU / 2-GiB envelope for every server. Two ways to look
at it, both worth a chart on the site:

### 5.1 Server memory (MiB, p0 matrix, median-of-3)

| scenario | AXIAM avg | AXIAM peak | Keycloak avg | Keycloak peak | Zitadel avg | Zitadel peak |
|---|---|---|---|---|---|---|
| jwks_fetch | 97 | 98 | 726 | 973 | 158 | 163 |
| oauth2_client_credentials | 99 | 106 | 900 | 979 | 143 | 147 |
| token_introspection | 103 | 104 | 794 | 795 | 157 | 161 |
| token_refresh | 104 | 106 | 797 | 804 | — | — |
| userinfo | 104 | 105 | 798 | 806 | 157 | 162 |
| oauth2_password_login | 131 | 140 | 969 | 796* | 157 | 131* |
| **worst case, whole run** | — | **172** | — | **1 070** | — | **216** |

*\* peak medians differ from avg medians across runs on the partially
valid login cells; the whole-run worst case row is the honest summary.*

**AXIAM's server never exceeded 172 MiB — 8% of its allowance — while
delivering the throughput numbers in §1. Keycloak needed the cap raised to
2 GiB just to run (peak 1 070 MiB, above the old 1 GiB cap), and was still
excluded on login validity.** Zitadel's Go server is respectably small
(≤ 216 MiB) — its costs show up in CPU-per-request and its Postgres
instead. Whole-stack memory (server + DB + broker): AXIAM 415–590 MiB
(includes SurrealDB and RabbitMQ), Keycloak 814–1 129 MiB, Zitadel
293–443 MiB — Zitadel's stack is the smallest, AXIAM's the most
throughput per byte (below).

### 5.2 CPU efficiency (p0, whole stack, median-of-3)

| scenario | metric | AXIAM | Keycloak | Zitadel |
|---|---|---|---|---|
| oauth2_client_credentials | cpu·ms per request | **1.20** | 5.84 | 8.20 |
| token_introspection | 〃 | **0.78** | 1.27 | 4.00 |
| jwks_fetch | 〃 | **0.06** | 0.44 | 1.42 |
| userinfo (REST) | 〃 | 0.73 | **0.53** | 2.88 |
| userinfo (server-only) | 〃 | **0.25** | 0.53 | 0.86 |
| oauth2_client_credentials | req/s per GiB of stack RAM | **5 988** | 338 | 1 218 |
| token_introspection | 〃 | **8 709** | 1 939 | 2 199 |
| userinfo | 〃 | **8 948** | 3 999 | 2 312 |
| jwks_fetch | 〃 | **60 723** | 5 741 | 7 330 |

One asterisk kept in the open: whole-stack userinfo CPU-per-request is the
single efficiency cell Keycloak wins (AXIAM's figure carries a pegged
SurrealDB plus RabbitMQ; server-only, AXIAM is 2.1× cheaper). Every other
cell, both axes, AXIAM leads by 1.6× to 17×.

Suggested site charts from this section: (a) grouped bars of server RSS
peak per scenario (log scale not needed — 172 vs 1 070 speaks), (b)
cpu·ms/request grouped bars, (c) a scatter of throughput vs stack RAM
(req/s per GiB). All values above are final medians, chartable as-is.

## 6. Weaknesses and caveats (the honest section)

- **The TLS client-credentials drop (−57%) is still unexplained.** New
  post-fix evidence narrows it: under TLS the endpoint shows a flat ~43 ms
  per request with *nothing saturated* — a serialization plateau, not a
  crypto cost — and the old prime suspect (the rate-limit write) is gone.
  A dedicated VU-sweep is the next-round task. Even with the penalty,
  AXIAM's TLS token issuance leads the field 2.8–3.4×.
- **Batch cells this run measured the non-default strategy** due to a
  benchmark-harness pin (now fixed); the shipped default's number remains
  draft 4's 4.98× table until run 5 re-measures it (§1).
- **The gRPC production rate limiter under-admitted ×60** (units bug,
  found by this run's posture pass) — **fixed since this run**, along with
  the server-wide scope that made the authz ceiling throttle identity
  reads; the measurements in this draft predate both fixes — §4/§7.2.
- **Keycloak's login cells are excluded by our validity gate at 2 GiB**;
  next run gives them 4 GiB, labeled. Zitadel's login/refresh exclusions
  are its default bcrypt cost / a missing harness flow — stated, not
  hidden.
- **Consumer-laptop hardware**, package temperatures hit 96–100 °C on hot
  cells and clock varied 3.2–3.9 GHz — medians-of-3 keep spreads at
  ±0.2–2.8% on AXIAM cells, but a server-class re-run remains the standing
  caveat on absolute numbers.
- AXIAM stack figures include RabbitMQ (~0.1–0.3 cores, ~110–130 MiB) and
  SurrealDB; k6 skips cert verification at p2/p3 (handshake and record
  crypto are real); closed-loop 50 VUs floors the fastest endpoints (JWKS)
  — those cells measure latency, not capacity.
- **SDK table caveats**: single pass (not median-of-3); no wire-baseline
  was captured this run, so SDK-vs-wire overhead is not published; the C
  and PHP harnesses run at concurrency 1 (their numbers are not comparable
  with the concurrency-16 SDKs); the C# `refresh` row measures a cached
  no-op (1 µs — its auth helper correctly skips the network when the token
  is still valid; the harness must force expiry next run) and one C++ tail
  anomaly is under investigation (§9).

## 7. Production rate limits: measured capacity, and what to set

AXIAM ships enforcing abuse limits by default; the competitors ship none.
This run measured both the enforcement (§4) and — for the first time on a
clean build — the actual capacity headroom behind those limits on a modest
2-core envelope:

| endpoint | shipped default (`internet`, per-IP) | previous default | measured capacity (this run, 2c server / 2c DB) | default as % of capacity |
|---|---|---|---|---|
| `POST /oauth2/token` | 120/min | 20/min | ~2 727/s ≈ 163 000/min | 0.07% |
| `POST /oauth2/introspect` | 600/min | 10/min | ~4 387/s ≈ 263 000/min | 0.23% |
| `POST /oauth2/revoke` | 60/min | 10/min | (tracks issuance) | — |
| `POST /api/v1/authz/check` | 1 800/min | 300/min | ~753/s ≈ 45 000/min (REST) | 4% |
| gRPC authz | 100/s | 100/s | ~887/s (checks), 12 665/s (reads) | 11% |
| `POST /api/v1/auth/login` | 10/min | 10/min | ~69/s ≈ 4 100/min (Argon2id-bound) | 0.2% |

The "shipped default" column is the **current** shipped value; the
"previous default" column is what shipped before this run's revision
(§7.2). The gap to capacity is still deliberate on an internet edge — but
note that even after the revision a NAT'd fleet shares one IP bucket, so
the posture advice below is unchanged. Recommendations, updated for run 4:

### 7.1 Pick a posture first (one variable)

| Deployment | Set | What it does |
|---|---|---|
| Small internet-facing | *(nothing — defaults)* | strict per-IP limits on everything |
| M2M / microservices / IoT behind NAT or gateway | `AXIAM__RATE_LIMIT__PROFILE=gateway` | per-`client_id` buckets; token 600/min, introspect 6 000/min, authz 6 000/min per client — measured (draft 4): admitted rate for a single well-behaved client 8.5% → 96.6% (token), 3.7% → 100% (introspect), 68.9% → 100% (authz) |
| Private network / service mesh | `AXIAM__RATE_LIMIT__PROFILE=mesh` | ceilings as runaway-loop guards: token 6 000/min, introspect/authz 60 000/min per client |

Human endpoints (login, register, password-reset, MFA) stay at their
strict per-IP defaults in **every** profile, by design — raise those
individually and deliberately or not at all.

### 7.2 The revised machine-endpoint defaults (shipped, sized from this run)

This run's measurements were used to raise the machine-endpoint `internet`
defaults. **These numbers are now shipped**, not a proposal — the "was"
column records what shipped before. Each value stays far below measured
capacity (25× at the tightest, authz; 400–2 700× on the rest), so the
abuse posture is intact while no longer breaking a single healthy
integration:

| knob | shipped default | was | why (measured) |
|---|---|---|---|
| `TOKEN_PER_MIN` | **120** | 20 | one service refreshing a 15-min token for a handful of workers exhausts 20/min behind NAT; 120/min is 0.07% of measured capacity |
| `INTROSPECT_PER_MIN` | **600** | 10 | resource servers introspect per *request*; 10/min breaks the first real API behind AXIAM; 600/min = 10/s = 0.23% of capacity |
| `AUTHZ_CHECK_PER_MIN` | **1 800** | 300 | 300/min = 5/s starves a single modest service; 1 800/min = 30/s = 4% of a 2-core envelope |
| `REVOKE_PER_MIN` | **60** | 10 | logout bursts from one gateway IP hit 10/min immediately |
| `GRPC_AUTHZ_PER_SEC` | 100/s | 100/s | value kept; the ×60 units bug (§4) is **fixed** — 100/s now really admits 100/s — and the ceiling is now scoped to the authz methods instead of every gRPC surface (new: `GRPC_IDENTITY_PER_SEC` 500/s, `GRPC_ADMIN_PER_SEC` 100/s) |
| login / register / password-reset / MFA | 10 / 5 / 3 / 5 per min | 10 / 5 / 3 / 5 per min | **unchanged** — these gate credential-guessing; capacity is irrelevant to their sizing |

If you pinned any of these with an env var, nothing changes for you:
explicit env always beats both the preset and the shipped default. When the
shipped `internet` numbers are what a deployment is actually enforcing, the
server now also watches the sustained 429 ratio on the four machine
endpoints and logs one advisory per 5-minute interval if more than half of
that traffic is being rejected — "your limits are throttling what looks
like legitimate machine traffic; see rate-limit-sizing". Human endpoints
are excluded from that ratio by construction.

Sizing rule for your own values: take your real per-key peak (per IP or
per client_id, whichever mode you run), double it, and check it against
the capacity column scaled to your hardware (authz/introspect/userinfo
scale with DB cores — +42–90% from 2→4 DB cores, §4; login scales with
server cores; token issuance is ahead of both until ~2.7 k/s per 2 cores).
And the standing security caveat: `client_id`-keyed modes are fairness
controls between authenticated well-behaved clients, not abuse controls —
the client_id is attacker-mintable before authentication — so use them
only behind an edge that authenticates callers (mTLS, gateway, WAF,
allow-list). `ip` remains the only attacker-resistant key and stays the
default.

## 8. Full result matrix (graph-ready)

One row per (scenario, profile, target); `±` is the throughput spread
across the three runs; cpu = whole-stack cores avg; mem = whole-stack MiB
avg. Rows failing a validity gate or carrying a comparability label say
so and **must not be charted as an unqualified head-to-head**.

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|
| oauth2_client_credentials | p0 | axiam | 2727 | 0.4% | 9.1 | 58.1 | 62.5 | 3.26 | 466 | ✓ |
| oauth2_client_credentials | p0 | keycloak | 354 | 11.5% | 103.0 | 208.4 | 301.3 | 2.07 | 1074 | ✓ |
| oauth2_client_credentials | p0 | zitadel | 425 | 2.8% | 108.7 | 139.9 | 169.2 | 3.48 | 357 | ✓ |
| oauth2_client_credentials | p2 | axiam | 1180 | 0.0% | 42.6 | 43.9 | 44.8 | 2.07 | 471 | ✓ |
| oauth2_client_credentials | p2 | keycloak | 346 | 14.5% | 104.1 | 208.5 | 300.4 | 2.07 | 910 | ✓ |
| oauth2_client_credentials | p2 | zitadel | 419 | 1.6% | 110.9 | 138.7 | 164.5 | 3.54 | 353 | ✓ |
| token_introspection | p0 | axiam | 4387 | 0.6% | 5.9 | 48.5 | 53.4 | 3.41 | 516 | ✓ |
| token_introspection | p0 | keycloak | 1860 | 2.6% | 7.5 | 81.9 | 85.7 | 2.37 | 982 | ✓ |
| token_introspection | p0 | zitadel | 932 | 1.6% | 48.2 | 66.1 | 73.7 | 3.73 | 434 | ✓ |
| token_introspection | p2 | axiam | 4316 | 0.7% | 6.2 | 45.6 | 51.3 | 3.50 | 539 | ✓ |
| token_introspection | p2 | keycloak | 1715 | 7.1% | 8.1 | 83.0 | 87.7 | 2.34 | 976 | ✓ |
| token_introspection | p2 | zitadel | 909 | 2.0% | 50.4 | 67.8 | 76.0 | 3.81 | 437 | ✓ |
| jwks_fetch | p0 | axiam | 26371 | 1.2% | 1.3 | 3.1 | 4.5 | 1.63 | 445 | ✓ |
| jwks_fetch | p0 | keycloak | 4565 | 4.8% | 2.7 | 72.5 | 76.7 | 2.00 | 814 | ✓ |
| jwks_fetch | p0 | zitadel | 2096 | 1.9% | 11.2 | 64.7 | 66.8 | 2.98 | 293 | ✓ |
| jwks_fetch | p2 | axiam | 23716 | 0.8% | 1.6 | 3.2 | 4.4 | 1.94 | 455 | ✓ |
| jwks_fetch | p2 | keycloak | 4261 | 10.8% | 3.1 | 72.0 | 76.2 | 2.01 | 869 | ✓ |
| jwks_fetch | p2 | zitadel | 2057 | 0.8% | 12.9 | 59.9 | 62.8 | 3.14 | 295 | ✓ |
| userinfo | p0 | axiam | 4547 | 0.3% | 5.4 | 51.4 | 55.8 | 3.30 | 520 | ✓ |
| userinfo | p0 | keycloak | 3783 | 0.8% | 3.0 | 76.8 | 80.5 | 2.00 | 969 | ✓ |
| userinfo | p0 | zitadel | 1000 | 2.3% | 24.8 | 80.0 | 82.6 | 2.87 | 443 | ✓ machine-user token |
| userinfo | p2 | axiam | 4439 | 0.2% | 5.6 | 50.7 | 55.5 | 3.55 | 545 | ✓ |
| userinfo | p2 | keycloak | 3499 | 1.1% | 3.3 | 77.5 | 81.3 | 2.00 | 989 | ✓ |
| userinfo | p2 | zitadel | 998 | 2.5% | 26.6 | 78.3 | 82.6 | 2.97 | 438 | ✓ machine-user token |
| userinfo_grpc (AXIAM-only) | p0 | axiam | 12665 | 0.4% | 3.0 | 6.0 | 7.0 | 2.09 | 516 | ✓ |
| userinfo_grpc (AXIAM-only) | p2 | axiam | 12148 | 0.6% | 4.0 | 6.0 | 7.0 | 2.08 | 532 | ✓ |
| zitadel_userinfo_grpc | p0 | zitadel | 180 | 4.6% | 233.0 | 645.0 | 831.0 | 1.13 | 438 | ✓ machine-user token |
| zitadel_userinfo_grpc | p2 | zitadel | 185 | 6.3% | 233.0 | 379.0 | 803.0 | 1.23 | 437 | ✓ machine-user token |
| oauth2_password_login | p0 | axiam | 69 | 1.8% | 698.4 | 774.3 | 1155.9 | 2.06 | 507 | ✓ |
| oauth2_password_login | p0 | keycloak | 44 | n=1 | 1031.2 | 1300.6 | 1447.4 | 2.04 | 969 | ✗ 1/3 runs valid |
| oauth2_password_login | p0 | zitadel | 2 | — | 22079 | 25533 | 27185 | 2.02 | 410 | ✗ p95>2s (bcrypt) |
| oauth2_password_login | p2 | axiam | 67 | 0.6% | 705.8 | 850.1 | 1173.9 | 2.01 | 532 | ✓ |
| oauth2_password_login | p2 | keycloak | 53 | n=1 | 856.0 | 1009.7 | 1119.2 | 2.06 | 1129 | ✗ 1/3 runs valid |
| oauth2_password_login | p2 | zitadel | 2 | — | 22197 | 25314 | 26897 | 2.02 | 411 | ✗ p95>2s (bcrypt) |
| token_refresh | p0 | axiam | 839 | 0.4% | 47.5 | 80.6 | 93.2 | 2.74 | 509 | ✓ ⚠ protocol-variant (session refresh) |
| token_refresh | p0 | keycloak | 377 | 1.1% | 101.5 | 204.9 | 298.9 | 2.05 | 991 | ✓ ⚠ protocol-variant (OAuth2 grant) |
| token_refresh | p2 | axiam | 834 | 0.7% | 48.0 | 80.6 | 94.2 | 2.90 | 510 | ✓ ⚠ protocol-variant |
| token_refresh | p2 | keycloak | 370 | 2.0% | 102.3 | 203.8 | 296.6 | 2.04 | 987 | ✓ ⚠ protocol-variant |
| token_refresh | p0/p2 | zitadel | — | — | — | — | — | — | — | ✗ fallback-op (no offline_access flow) |
| authz_check_rest (AXIAM-only) | p0 | axiam | 753 | 1.0% | 73.6 | 92.5 | 98.7 | 2.75 | 416 | ✓ |
| authz_check_rest (AXIAM-only) | p2 | axiam | 760 | 0.8% | 73.2 | 92.1 | 98.5 | 2.72 | 425 | ✓ |
| authz_check_grpc (AXIAM-only) | p0 | axiam | 887 | 0.3% | 38.0 | 86.0 | 92.0 | 2.57 | 415 | ✓ |
| authz_check_grpc (AXIAM-only) | p2 | axiam | 892 | 0.7% | 37.0 | 86.0 | 92.0 | 2.70 | 422 | ✓ |
| authz_batch_rest (AXIAM-only) | p0 | axiam | 199 (=995 checks/s) | 9.7% | 219.9 | 323.4 | 387.0 | 2.51 | 472 | ✓ ⚠ `concurrent` strategy, NOT the shipped default |
| authz_batch_rest (AXIAM-only) | p2 | axiam | 199 | 10.8% | 219.7 | 323.9 | 387.6 | 2.65 | 460 | ✓ ⚠ 〃 |
| authz_batch_grpc (AXIAM-only) | p0 | axiam | 175 | 12.2% | 273.0 | 400.0 | 475.0 | 2.38 | 556 | ✓ ⚠ 〃 |
| authz_batch_grpc (AXIAM-only) | p2 | axiam | 176 | 13.5% | 271.0 | 398.0 | 468.0 | 2.55 | 590 | ✓ ⚠ 〃 |
| authz_batch_rest (`coalesced`, shipped default) | settled | axiam | 744 (=3 721 checks/s) | — | 49 | — | — | — | — | ✓ from the draft-4 decision run; re-measure in run 5 |
| authz_batch_grpc (`coalesced`, shipped default) | settled | axiam | 866–872 | — | — | 74 | — | — | — | ✓ 〃 |

## 9. SDK client benchmarks (first full 11-language pass)

All eleven SDKs — Rust, TypeScript, Python, Java, Kotlin, C#, Go, PHP,
Swift, C, C++ — ran the same four ops (login, refresh, check_access,
batch_check) against the same seeded AXIAM at p0, p2 **and p3 (mTLS)**,
zero errors in 132 op-cells. Selected p0 rows (concurrency 16 unless
noted; single pass, not median-of-3):

| sdk | login p50 (ms) | refresh p50 (ms) | check p50 (ms) | check p95 (ms) | check thr (rps) |
|---|---|---|---|---|---|
| rust | 247.9 | 17.5 | 10.0 | 59.7 | 868 |
| go | 254.4 | 17.4 | 10.9 | 61.1 | 779 |
| csharp | 228.2 | *(cached no-op)* | 10.6 | 61.6 | 786 |
| java | 243.0 | 17.3 | 11.1 | 61.8 | 767 |
| kotlin | 228.6 | 17.3 | 11.4 | 61.9 | 738 |
| swift | 229.1 | 17.6 | 13.3 | 63.2 | 634 |
| typescript | 256.2 | 16.8 | 17.8 | 55.6 | 638 |
| python | 231.0 | 17.3 | 30.3 | 76.1 | 444 |
| cpp | 230.0 | 17.4 | 3.3 | 283.2* | 312 |
| c *(concurrency 1)* | 36.0 | 17.4 | 3.1 | 3.8 | 317 |
| php *(concurrency 1)* | 31.2 | 17.3 | 3.5 | 4.4 | 273 |

What the table shows: **the server, not the SDKs, sets the floor** — ten
of eleven SDKs measure refresh at 17.3 ± 0.3 ms p50 and the concurrency-16
SDKs measure login at 228–256 ms (server-side Argon2id dominates,
identically from every language). TLS (p2) and mTLS (p3) added no
measurable client-side cost in any SDK — matching the server-side p2/p3
parity. Honest flags, kept visible: the C# refresh row measures its auth
helper's (correct) token cache, not the wire, until the harness forces
expiry; C++ shows a reconnect-shaped p95 tail under investigation; C and
PHP run serially, so their rows aren't comparable with the rest; and no
matched-concurrency wire baseline was captured this run, so the
"SDK overhead vs raw HTTP" column returns in run 5.

## 10. Summary and what happens next

**Strengths.** The first clean, median-of-3, fully labeled matrix:
token issuance **7.7×/6.4×** (Keycloak/Zitadel), introspection
**2.4×/4.7×**, JWKS **5.8–12.6×**, userinfo **1.2×/4.5×** REST and
**12.7 k/s** over gRPC; the only valid login at both profiles; refresh
restored as a full median-of-3 cell (labeled); native mTLS still free;
and a resource profile to match — **≤ 172 MiB server RSS at peak, 1.2–17×
less CPU per request** on the envelope where Keycloak needed its memory
cap doubled.

**Weaknesses, stated as plainly.** The TLS client-credentials plateau
(−57%) remains the one open performance mystery; batch cells this run
measured the non-default strategy through a harness slip (default's
verdict unchanged, re-measurement queued); the gRPC prod rate limiter had
a ×60 units bug (found by this run, fixed since); Keycloak's login cells
need a 4 GiB labeled envelope to be fair; everything is still
laptop-hosted.

**Next round:** run 5 with the batch default actually exercised, the fixed
and per-method-scoped gRPC limiter re-measured, the revised `internet`
machine defaults confirmed, a 4 GiB Keycloak login cell, the SDK wire-baseline and
median-of-3 SDK repeats — and, budget permitting, the long-promised
server-class hardware re-run.

---
*Sources: G-box run-4 of 2026-08-01/02 (median-of-3 capped matrix × p0/p2 ×
3 targets; labeled sensitivity passes: DB-uncapped, decision-cache ON,
native-mTLS p3, prod rate-limit posture, batch-strategy; 11-SDK pass at
p0/p2/p3; per-cell k6 summaries, 1 s container + host telemetry,
digest-recorded metadata), aggregated by `runner/report.py`; draft-4
carry-overs where labeled (batch `coalesced` decision run; gateway-preset
admitted-rate measurements). Metric definitions:
[`docs/methodology.md`](docs/methodology.md).*
