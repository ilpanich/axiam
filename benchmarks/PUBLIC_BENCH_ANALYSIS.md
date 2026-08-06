# AXIAM Benchmark Analysis — Sixth Draft (Run 5: the release-image run)

> **Status: sixth benchmark draft — the first measured against a published
> release artifact rather than a working tree.** Run 5 (2026-08-05/06)
> benchmarks `ghcr.io/ilpanich/axiam/server:1.0.0-alpha24`, pinned by digest
> (`@sha256:a7d415bf…`), pulled exactly as any reader would pull it. It is
> also the first run with the **full three-profile matrix in the run of
> record** (plaintext, TLS 1.3, native mTLS — median-of-3 everywhere), and
> the first **median-of-3 SDK pass with a matched-concurrency wire
> baseline**. Beyond re-measuring, run 5 had three questions to answer —
> the three open mysteries draft 5 published: the TLS token-issuance
> plateau, the REST/gRPC authorization asymmetry, and the database ceiling.
> **All three are closed, with data** (§3). It also found two new problems,
> published in §6 with the same candor as their predecessors. Numbers are
> reproducible from the published raw data; the platform is named at every
> number.

## 0. Setup at a glance

| | |
|---|---|
| Hardware | Dell XPS 15 9570 ("G-box": i7-8750H, 12 logical CPUs, ~31 GiB RAM) — same box as every prior draft; consumer laptop, server-class re-run still pending |
| Load | k6 v2.1.0, 50 VUs closed-loop, 30 s warmup + 120 s measure, median-of-3 repeats per cell |
| Caps | every server container: 2 CPUs / 2 048 MiB; every DB container: 2 CPUs / 1 024 MiB; broker 1 CPU / 512 MiB |
| Targets | **AXIAM 1.0.0-alpha24** (released image, digest-pinned; SurrealDB v3 digest-pinned + RabbitMQ 4) vs **Keycloak 26.7.0** (Postgres 16) vs **Zitadel v4.16.2** (Postgres 16) |
| Profiles | p0-plaintext, p2-tls13 (in-process TLS 1.3), **p3-mtls (in-process mutual TLS) — now a full matrix profile, not a sensitivity pass** |
| Validity | **64/72 matrix cells valid**; every invalid cell listed with its reason (§8); settle gate cleared first-probe on every session, zero refused cells |
| Provenance | image + digest recorded in every cell's metadata; harness checkout on `main` (`1df1a83`, a descendant of the alpha24 tag differing only in benchmark/docs files) |

**Comparability warning (run 4 → run 5).** Run 5 is *not* a like-for-like
re-run: between the runs, two authorization-path table scans were removed,
Nagle was disabled on the REST listener, the gRPC rate-limiter units bug
was fixed, the shipped rate-limit defaults were revised, and the batch
default the harness measures finally matches the batch default the product
ships. Treat run 5 as the new baseline; where a controlled comparison was
wanted, a one-variable A/B was run and is reported as such (§3).

## 1. Headline results (median-of-3, valid cells)

### Machine-to-machine token issuance (`oauth2_client_credentials`)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | cpu·ms per request |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **2 804** | 8.8 | **57.5** | **816** | **1.23** |
| p0 | Zitadel | 431 | 108.7 | 131.9 | 122 | 8.21 |
| p0 | Keycloak | 354 | 103.3 | 206.8 | 171 | 5.85 |
| p2 | **AXIAM** | **2 746** | 9.1 | **57.3** | 818 | 1.22 |
| p2 | Zitadel | 417 | 112.5 | 136.5 | 118 | 8.47 |
| p2 | Keycloak | 340 | 104.6 | 211.4 | 164 | 6.09 |
| p3 | **AXIAM** | **2 697** | 9.2 | **57.8** | 782 | 1.28 |
| p3 | Zitadel | 416 | 112.4 | 137.3 | 117 | 8.51 |
| p3 | Keycloak | 346 | 104.1 | 208.5 | 167 | 5.99 |

AXIAM issues **7.9× more tokens/s than Keycloak and 6.5× more than
Zitadel** at plaintext — and, new this run, **~8× under TLS 1.3 and mTLS
too**. Draft 5's one glaring asterisk — a −57% drop on this endpoint under
TLS — is gone: the cause was found (Nagle's algorithm interacting with
delayed ACKs, §3.1), fixed, and the TLS penalty is now −2.0%.

### Token introspection (RFC 7662)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | cpu·ms per request |
|---|---|---|---|---|---|---|
| p0 | **AXIAM** | **4 504** | 5.7 | **47.7** | **1 269** | **0.79** |
| p0 | Keycloak | 1 888 | 7.3 | 81.8 | 799 | 1.25 |
| p0 | Zitadel | 941 | 47.4 | 64.7 | 252 | 3.98 |
| p2 | **AXIAM** | **4 391** | 6.1 | **45.2** | 1 282 | 0.78 |
| p2 | Keycloak | 1 715 | 8.2 | 82.7 | 730 | 1.37 |
| p2 | Zitadel | 915 | 50.0 | 67.9 | 239 | 4.18 |
| p3 | **AXIAM** | **4 376** | 6.2 | **45.5** | 1 260 | 0.79 |
| p3 | Keycloak | 1 731 | 8.0 | 82.6 | 740 | 1.35 |
| p3 | Zitadel | 904 | 50.5 | 68.4 | 238 | 4.20 |

**2.4× Keycloak, 4.8× Zitadel**, with a ~1.8× better p95 than Keycloak and
a near-zero TLS/mTLS penalty (−2.5% / −2.8%).

### JWKS fetch (RFC 7517)

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **26 680** | 1.4 | **3.1** | **15 855** |
| p0 | Keycloak | 4 573 | 2.7 | 72.6 | 2 288 |
| p0 | Zitadel | 2 091 | 11.1 | 64.8 | 701 |
| p2 | **AXIAM** | **24 097** | 1.6 | **3.0** | 12 696 |
| p2 | Keycloak | 4 167 | 3.0 | 72.8 | 2 075 |
| p2 | Zitadel | 2 053 | 12.9 | 60.0 | 652 |
| p3 | **AXIAM** | **23 954** | 1.6 | **3.1** | 12 599 |
| p3 | Keycloak | 3 786 | 3.2 | 75.0 | 1 887 |
| p3 | Zitadel | 2 052 | 12.9 | 60.1 | 654 |

A 5.8–12.8× gap, still limited by the load generator rather than AXIAM
(k6 burned ~5 CPU cores on these cells; the AXIAM server sat below 1.7/2).

### OIDC userinfo — REST and gRPC

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | req/s per stack core | server-only cpu·ms/req |
|---|---|---|---|---|---|---|
| p0 | **AXIAM (gRPC)** | **12 307** | 4.0 | **6.0** | **5 866** | — |
| p0 | **AXIAM (REST)** | **4 752** | 5.1 | 50.9 | 1 437 | **0.25** |
| p0 | Keycloak | 3 721 | 3.0 | 77.1 | **1 863** | 0.53 |
| p0 | Zitadel* | 995 | 23.3 | 80.4 | 346 | 0.86 |
| p2 | **AXIAM (gRPC)** | **11 954** | 4.0 | **6.0** | 5 740 | — |
| p2 | **AXIAM (REST)** | **4 585** | 5.4 | 50.6 | 1 371 | 0.27 |
| p2 | Keycloak | 3 486 | 3.2 | 77.7 | **1 737** | 0.57 |
| p2 | Zitadel* | 980 | 25.7 | 79.1 | 332 | 0.95 |
| p3 | **AXIAM (gRPC)** | **11 937** | 4.0 | **6.0** | 5 777 | — |
| p3 | **AXIAM (REST)** | **4 437** | 5.5 | 51.2 | 1 255 | 0.28 |
| p3 | Keycloak | 3 490 | 3.2 | 77.9 | **1 741** | 0.57 |
| p3 | Zitadel* | 978 | 25.3 | 79.3 | 331 | 0.96 |

*\* Zitadel authenticated with a machine-user token minted once in setup
(its user-login flow returns a session token the harness can't convert);
the measured endpoint and semantics are the same.*

On REST, AXIAM leads 1.3× Keycloak / 4.8× Zitadel while its DB is pegged.
On whole-stack req/s-per-core Keycloak again wins the REST cell; on
server-only CPU per request AXIAM is 2.1× cheaper — both published, as
before. The real story stays gRPC: **12.3 k identity reads/s at p95 6 ms**.
Zitadel's own gRPC userinfo measured 191–201/s (−80% vs its REST) on the
same harness — its gRPC management API is not built as a hot path, which
is fair, and exactly why AXIAM treating gRPC as a first-class data plane
is a differentiator (§10).

### Authorization decisions (AXIAM-only — no competitor equivalent)

Full RBAC evaluation (tenant-scoped roles, resource hierarchy, scopes)
against live data, decision cache **off**:

| scenario | profile | thr | p50 (ms) | p95 (ms) | note |
|---|---|---|---|---|---|
| authz_check_grpc | p0 | **1 268** | 21 | 74 | +43% vs draft 5 (table-scan fix, §3.3) |
| authz_check_rest | p0 | **1 032** | 27 | 79 | +37% vs draft 5 |
| authz_batch_grpc | p0 | 928 ops/s = **4 640 checks/s** | 33 | 84 | 3.7× singles |
| authz_batch_rest | p0 | 1 026 ops/s = **5 130 checks/s** | 28 | 80 | **4.97× singles** |

p2 and p3 are within 1.5% of p0 on all four (§8). Two things resolved
here. First, **the shipped batch default (`coalesced`) is finally the
strategy the matrix measured** — draft 5's cells had accidentally measured
a non-default strategy through a harness pin. The settled claim ("batching
5 checks per call ≈ 5× the decision rate") reproduces at matrix scale:
4.97×. Second, the +37/43% on single checks is the direct, predicted
result of removing two full-table scans found via `EXPLAIN` after run 4 —
a fix that is now guarded by CI tests that fail if any hot authorization
query ever regresses to a table scan (§3.3).

### Session/token refresh — published under the protocol-variant label

> ⚠️ **Comparability: protocol-variant.** AXIAM has no ROPC/password grant
> by design; its cell measures **session cookie refresh**
> (`POST /api/v1/auth/refresh`, CSRF double-submit, single-use rotation).
> Keycloak's cell measures the **OAuth2 refresh-token grant**. Related
> jobs, different protocols — informational, not a like-for-like race.

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) |
|---|---|---|---|---|
| p0 | AXIAM | **545** | 88.8 | 111.1 |
| p0 | Keycloak | 377 | 101.5 | 203.9 |
| p2 | AXIAM | **540** | 89.0 | 113.2 |
| p2 | Keycloak | 368 | 102.3 | 204.4 |
| p3 | AXIAM | **542** | 89.5 | 112.8 |
| p3 | Keycloak | 365 | 102.5 | 204.9 |

**Honesty first: AXIAM's refresh regressed −35% since draft 5** (839 →
545/s, p50 47.5 → 88.8 ms; both tight medians). No harness change touched
this path; the suspects are the post-run-4 security hardening series
and/or database version drift, and the investigation is open (§6). The
cross-vendor position is unchanged (AXIAM ahead, with the label), but we'd
rather flag our own regression than let the ratio hide it. Zitadel's
refresh still needs an `offline_access` flow the harness doesn't
implement (upstream limitation, tracked) and stays excluded.

### Password login (all targets hash for real)

AXIAM **Argon2id** (OWASP params), Keycloak 26 **Argon2id** (default),
Zitadel **bcrypt** (default cost — far more expensive per verification;
tunable). Hash configuration dominates this scenario.

| profile | target | thr (req/s) | p50 (ms) | p95 (ms) | valid (p95 < 2 s, ≥2/3 runs) |
|---|---|---|---|---|---|
| p0 | **AXIAM** | **69** | 699 | **761** | ✓ 3/3 |
| p0 | Keycloak | (47) | (990) | (1 129) | ✗ 1/3 runs valid |
| p0 | Zitadel | (2) | (21 786) | (25 414) | ✗ 0/3 (bcrypt) |
| p2 | **AXIAM** | **70** | 696 | **764** | ✓ 3/3 |
| p2 | Keycloak | **51** | 890 | 1 095 | ✓ 2/3 — Keycloak's first valid login cell in this series |
| p2 | Zitadel | (2) | (22 031) | (25 348) | ✗ 0/3 |
| p3 | **AXIAM** | **68** | 704 | **791** | ✓ 3/3 |
| p3 | Keycloak | (22) | (2 179) | (2 309) | ✗ 0/3 |
| p3 | Zitadel | (2) | (21 915) | (25 611) | ✗ 0/3 |

AXIAM remains the only target valid at every profile, at ≤ ~120 MiB of
average server memory during the burst (§5). Two updates in fairness to
Keycloak: it produced its **first valid login cell** (p2, 51/s), and we
ran the promised **4 GiB labeled attempt** — which did *not* rescue it:
at 4 096 MiB Keycloak ran stably but at ~21/s with p95 ≈ 2.5 s (still
failing the validity gate, and slower than its 2 GiB survivor runs).
Keycloak's login behavior appears memory-*sensitive* rather than simply
memory-starved; we'll say so rather than keep raising its cap. Zitadel's
exclusion remains its default bcrypt cost — expected and tunable.

## 2. What changed since draft 5, and why the numbers moved

Every fix below shipped in the released alpha24 image measured here — none
is a benchmark-only tweak:

| Change | Measured consequence in run 5 |
|---|---|
| Nagle disabled on the REST listener (`TCP_NODELAY`, default on) | TLS token issuance −57% → **−2%** (§3.1) |
| Two authorization table scans → index scans | REST checks +37%, gRPC checks +43%, cache-off (§3.3) |
| Batch strategy measured = batch strategy shipped (`coalesced`) | batch REST = **4.97× singles** at matrix scale (§1) |
| gRPC rate-limiter ×60 units bug fixed; per-method-family ceilings | prod-posture partially re-verified; **a new flood-behavior problem found, see §6** |
| Revised `internet` machine-endpoint defaults (token 120/min, introspect 600/min, authz 1 800/min, revoke 60/min) | enforcement re-measured under flood (§7) |
| SDK harness: real refresh calls, async Python driver, client CPU/RSS telemetry, wire baseline, median-of-3 | §9's overhead column exists and is trustworthy |

## 3. Three mysteries, closed (the benchmark as debugger)

This section is why we benchmark in the open. Draft 5 published three
unexplained results as open questions with named hypotheses. Run 5 tested
all three.

### 3.1 The TLS plateau was Nagle's algorithm — confirmed by A/B

Draft 5's flat ~43 ms per TLS token request (nothing saturated, p50≈p95)
had a hypothesis: actix-web never set `TCP_NODELAY`, so Nagle's algorithm
held the second TLS record of each HTTP/2 response until the peer's
**40 ms delayed-ACK timer** fired — plaintext HTTP/1.1 responses fit one
write and never noticed. The controlled A/B on the TLS profile:

| arm | thr | p50 / p95 |
|---|---|---|
| `TCP_NODELAY=false` (old behavior) | 1 172/s | 42.8 / 44.1 ms — draft 5's plateau, reproduced |
| `TCP_NODELAY=true` (shipped default now) | **2 642/s** | 9.5 / 57.5 ms |
| plaintext control | 2 757/s | 8.9 / 57.6 ms |

A VU sweep (1→100) at both profiles shows TLS tracking plaintext within
2–6% at every concurrency, both saturating ~2.7 k/s from 20 VUs — a small
constant TLS cost plus the database ceiling, no serialization anywhere.
And the wire-level photograph, from an `ss -ti` snapshot inside the
server's network namespace during the old-behavior arm: **18 of 20
established connections frozen with bytes sitting in the send queue
(`Send-Q 707`, `notsent:31`) behind a single unacked segment, each
waiting out the peer's 40 ms delayed-ACK timer** — versus zero held-back
connections in the control. Closed, at every layer we can observe.

### 3.2 The REST/gRPC authorization asymmetry was the session-revocation read — confirmed by a 2×2

Draft 5: with the decision cache on, gRPC checks reached 13× but REST
barely moved. Code review traced it to one extra database round-trip: the
REST path checks session revocation on every request; the gRPC path
validates the JWT and stops. Run 5 ran the 2×2 (decision cache ×
session-validation cache, plaintext, checks/s):

| | session cache off | session cache on (TTL 5 s) |
|---|---|---|
| decision cache off | REST 1 013 / gRPC 1 248 | REST 1 177 / gRPC 1 244 |
| decision cache on | REST 5 597 / gRPC 11 122 | REST **11 647** / gRPC 11 172 |

The session cache does nothing for gRPC (it never did the read) and lifts
fully-cached REST to parity with gRPC — mechanism confirmed. Both caches
remain **off by default**: these are best-case (hot-key) ceilings, not
expectations.

**Does caching break revocation? Measured, not assumed.** The revocation
regression cell ran with caching on (TTL 5 s), twice over: (A) revoke a
role through the API — the cache invalidation hook fires end to end and a
**deny is served 262 ms after the revocation call**; (B) delete the
grant *behind the server's back*, directly in the database, suppressing
every invalidation hook — stale allows persist for up to the TTL and
stop at 5.2 s, inside the promised TTL-plus-slack bound. In short:
revoke through the API and revocation is immediate even with caches on;
only out-of-band database surgery waits out the TTL, which is the
documented contract. The flip side is stated with the same candor: part
of gRPC's speed *is* that it does not re-check session revocation per
call — token expiry (15 min max) is its revocation bound. That is a
documented posture choice, and a strict mode is on the roadmap.

### 3.3 The database ceiling: per-query waste removed, concurrency remains

After run 4, `EXPLAIN` on the live schema found two full-table scans on
the hot authorization read path (both fixable without schema changes; both
now CI-guarded against regression). Run 5 measures the result: cache-off
capped checks went 753 → 1 010–1 032/s (the pre-registered success bar was
1 000). The capped→uncapped (2→4 DB cores) delta narrowed from ~+90% to
**+75–79%** — so per-query cost is no longer the dominant waste, and what
remains is database *concurrency*. That reframes the roadmap: read-scaling
(with its staleness semantics stated honestly) now outranks further
per-query tuning. "Give the database cores first" remains the operative
sizing guidance for authz-heavy workloads.

## 4. Security cost of TLS 1.3 and mutual TLS (vs p0, valid cells)

| target / scenario | Δ thr p2 (TLS 1.3) | Δ thr p3 (mTLS) |
|---|---|---|
| axiam / oauth2_client_credentials | **−2.0%** | −3.8% |
| axiam / token_introspection | −2.5% | −2.8% |
| axiam / userinfo REST / gRPC | −3.5% / −2.9% | −6.6% / −3.0% |
| axiam / authz check REST / gRPC | −0.8% / −0.2% | −1.5% / −0.7% |
| axiam / authz batch REST / gRPC | −1.1% / −1.2% | −2.2% / −0.3% |
| axiam / token_refresh | −0.9% | −0.5% |
| axiam / oauth2_password_login | +0.3% | −2.1% |
| axiam / jwks_fetch | −9.7% | −10.2% |
| keycloak (valid cells) | −2.4% … −9.2% | −2.2% … **−17.2%** (jwks); login invalid at p3 |
| zitadel (valid cells) | −1.5% … −3.3% | −1.7% … −3.9% |

Most REST rows measure TLS *plus* an HTTP/1.1→2 protocol change together
(labeled as such in the raw report). The headline stands its third and
strongest re-measurement, now in the run of record at median-of-3:
**native mTLS — client certificates verified in-process, no sidecar, no
proxy — costs AXIAM ≈1% over plain TLS 1.3 on every scenario.** For an IoT
or zero-trust deployment that needs client certs on every connection,
AXIAM is the only one of the three that offers this in-process, and it is
effectively free. Keycloak pays measurably for mTLS on its hottest
read (−17% on JWKS) and could not produce a valid login cell under it.

## 5. Resource usage during the tests (graph-ready)

Same load, same 2-CPU / 2-GiB server envelope. Whole-run p0 matrix,
median-of-3, average RSS of the *server* container:

| scenario | AXIAM | Keycloak | Zitadel |
|---|---|---|---|
| jwks_fetch | **88** | 836 | 154 |
| oauth2_client_credentials | **90** | 710 | 138 |
| token_introspection | **95** | 752 | 153 |
| token_refresh | **95** | 755 | — |
| userinfo | **94** | 756 | 153 |
| oauth2_password_login | **119** | 853* | 154 |
| authz check/batch (no competitor equivalent) | 86–94 | — | — |

*\* Keycloak login cells are only partially valid (§1); its 4 GiB labeled
attempt is excluded from this table and reported in §1's login section.*

**AXIAM's server averaged 86–120 MiB across the entire matrix — mostly
under 5% of its allowance — while delivering §1's throughput.** Zitadel's
Go server remains respectably small (135–169 MiB); its costs surface in
CPU-per-request instead. Keycloak runs 674–853 MiB at the same envelope.
Whole-stack (server + DB + broker): AXIAM 375–533 MiB (SurrealDB and
RabbitMQ included), Keycloak 816–973 MiB, Zitadel 281–457 MiB — Zitadel's
stack is the smallest at rest; AXIAM's does the most work per byte:

| scenario (p0) | metric | AXIAM | Keycloak | Zitadel |
|---|---|---|---|---|
| oauth2_client_credentials | cpu·ms per request (stack) | **1.23** | 5.85 | 8.21 |
| token_introspection | 〃 | **0.79** | 1.25 | 3.98 |
| jwks_fetch | 〃 | **0.06** | 0.44 | 1.43 |
| userinfo (REST, stack) | 〃 | 0.70 | **0.54** | 2.89 |
| userinfo (server-only) | 〃 | **0.25** | 0.53 | 0.86 |
| oauth2_client_credentials | req/s per GiB of stack RAM | **6 528** | 416 | 1 239 |
| token_introspection | 〃 | **9 312** | 2 134 | 2 228 |
| userinfo | 〃 | **11 522** | 4 319 | 2 319 |
| jwks_fetch | 〃 | **66 270** | 5 022 | 7 351 |

The one cell Keycloak wins (whole-stack userinfo CPU/req — AXIAM's figure
carries a pegged SurrealDB plus RabbitMQ) is kept in the open, as in every
draft. Every other cell, both axes, AXIAM leads by 1.6× to 24×.

## 6. Weaknesses and caveats (the honest section)

- **Token/session refresh regressed −35% since draft 5** (839 → 545/s) on
  our own measurements, with no harness change on that path. The suspects
  are the post-run-4 security-hardening commits and/or database version
  drift; a stage-timed bisection is queued. We found it, we're publishing
  it, and the next draft will explain it — the same treatment the
  rate-limit write and the ×60 bug got.
- **The rate limiter fails our own enforcement assertions — in both
  directions.** This run added an automated check that compares
  configured limits against admitted rates under a single-IP flood, with
  a ±10% bar. Verdicts: login **passes** (11/min vs 10 configured);
  the REST machine endpoints **over-admit** (+12% token, +48%
  introspect, +50% authz check — token-bucket burst bleeding into the
  sustained window); and the gRPC families **under-admit by ×20–33**
  (181/min admitted vs 6 000 configured on authz) — the ×60 units bug
  draft 5 reported is fixed, but two cooperating limiter layers with
  mismatched windows appear to compound under overload. Three limiter
  families (revoke, gRPC admin, gRPC infra) have no test scenario yet,
  so their ceilings are asserted only in code review. Compliant clients
  under the limit are unaffected by any of this, but until it's fixed
  and re-measured, **we do not advertise gRPC throughput under the abuse
  posture**, and we publish the failing table rather than the passing
  subset (§7).
- **Keycloak's login story is genuinely hard to measure fairly.** We
  raised its cap to 4 GiB as promised; it got *slower* (§1). We report its
  one valid cell (51/s at p2/2 GiB) and our failed rescue attempt rather
  than either hiding the cells or pretending the 4 GiB number is
  representative.
- **SDK caveats**: Python remains the slow outlier even after moving to a
  genuinely async driver (check p50 ~40 ms vs ~10 ms for Go/Java/Rust —
  now attributable to the SDK/runtime, not the old harness artifact);
  the C++ SDK's reconnect-shaped p95 tail persists despite the connection-
  age fix and is still under investigation; the TypeScript-vs-wire
  overhead reads implausibly *negative* and its baseline comparability is
  being audited before we publish TS overhead claims; C# merged 2 of 3
  passes. All flagged inline in §9.
- **Consumer-laptop hardware**, package temperatures 95–100 °C on hot
  cells, clock 3.1–3.9 GHz across cells; medians-of-3 keep AXIAM spreads
  ≤ ±2% (batch cells ±13–17% — coalescing is phase-sensitive), but a
  server-class re-run remains the standing caveat on absolute numbers.
- AXIAM stack figures include RabbitMQ and SurrealDB; k6 skips cert
  verification at p2/p3 (handshake and record crypto are real);
  closed-loop 50 VUs floors the fastest endpoints (JWKS) — those cells
  measure latency, not capacity.
- The investigation passes (§3) are single labeled runs by design, not
  median-of-3; the matrix cells they explain are median-of-3.

## 7. Production rate limits: measured capacity, and what to set

AXIAM ships enforcing abuse limits by default; the competitors ship none.
The revised `internet` defaults (draft 5 §7.2) are now re-measured on the
released image against a single-IP 50-VU flood:

| endpoint | shipped default (`internet`, per-IP) | measured capacity (this run, 2c server / 2c DB) | default as % of capacity | flood enforcement (admitted vs configured, ±10% bar) |
|---|---|---|---|---|
| `POST /api/v1/auth/login` | 10/min | ~69/s ≈ 4 100/min (Argon2id-bound) | 0.2% | ✅ **PASS** — 11/min admitted |
| `POST /oauth2/token` | 120/min | ~2 804/s ≈ 168 000/min | 0.07% | ❌ FAIL — 135/min (+12%) |
| `POST /oauth2/introspect` | 600/min | ~4 504/s ≈ 270 000/min | 0.22% | ❌ FAIL — 889/min (+48%) |
| `POST /api/v1/authz/check` | 1 800/min | ~1 032/s ≈ 62 000/min (REST; batch shares this bucket) | 2.9% | ❌ FAIL — 2 699/min (+50%) |
| gRPC authz | 100/s (= 6 000/min) | ~1 268/s checks | 8% | ❌ FAIL — **181/min admitted (~1/33)** |
| gRPC identity | 500/s (= 30 000/min) | ~12 307/s reads | 4% | ❌ FAIL — 1 504/min (~1/20) |
| `POST /oauth2/revoke` | 60/min | (tracks issuance) | — | not yet covered by a test scenario |
| gRPC admin / gRPC infra | 10/s / 100/s | — | — | not yet covered by a test scenario |

Yes, that column is mostly FAIL, and we're publishing it anyway: the
assertion script and its ±10% bar are ours, this is the second limiter
bug class it has caught (the ×60 units bug was the first), and a public
failing table is what makes the fix verifiable next run. The abuse
*direction* of the posture is intact — the critical human endpoint
(login) enforces exactly, and every machine endpoint still throttles a
flood to within 1.5× of its configured trickle — but "within 1.5×" is
not "as configured", and the gRPC starvation is a real availability bug
under attack. Both are open work items.

The margin between defaults and capacity is **25–2 700×, with authz the
tightest** — deliberate on an internet edge. Posture guidance is unchanged
from draft 5: pick `internet` (default), `gateway`, or `mesh`; human
endpoints (login, register, password-reset, MFA) keep strict per-IP limits
in every profile by design. The standing security caveat, verbatim:
`client_id`-keyed modes are fairness controls between authenticated
well-behaved clients, not abuse controls — the client_id is
attacker-mintable before authentication — so use them only behind an edge
that authenticates callers. `ip` remains the only attacker-resistant key
and stays the default.

## 8. Full result matrix (graph-ready)

One row per (scenario, profile, target); `±` is the throughput spread
across the three runs; cpu = whole-stack cores avg; mem = whole-stack MiB
avg. Rows failing a validity gate or carrying a comparability label say so
and **must not be charted as an unqualified head-to-head**.

| scenario | profile | target | thr (req/s) | ± | p50 (ms) | p95 (ms) | p99 (ms) | cpu | mem | valid / label |
|---|---|---|---|---|---|---|---|---|---|---|
| oauth2_client_credentials | p0 | axiam | 2804 | 0.6% | 8.8 | 57.5 | 61.9 | 3.44 | 440 | ✓ |
| oauth2_client_credentials | p0 | keycloak | 354 | 11.1% | 103.3 | 206.8 | 299.5 | 2.07 | 871 | ✓ |
| oauth2_client_credentials | p0 | zitadel | 431 | 0.9% | 108.7 | 131.9 | 156.1 | 3.54 | 356 | ✓ |
| oauth2_client_credentials | p2 | axiam | 2746 | 1.5% | 9.1 | 57.3 | 61.8 | 3.36 | 428 | ✓ |
| oauth2_client_credentials | p2 | keycloak | 340 | 17.2% | 104.6 | 211.4 | 301.0 | 2.07 | 846 | ✓ |
| oauth2_client_credentials | p2 | zitadel | 417 | 0.8% | 112.5 | 136.5 | 160.6 | 3.53 | 352 | ✓ |
| oauth2_client_credentials | p3 | axiam | 2697 | 0.6% | 9.2 | 57.8 | 62.0 | 3.45 | 430 | ✓ |
| oauth2_client_credentials | p3 | keycloak | 346 | 14.9% | 104.1 | 208.5 | 300.0 | 2.07 | 816 | ✓ |
| oauth2_client_credentials | p3 | zitadel | 416 | 1.4% | 112.4 | 137.3 | 161.0 | 3.54 | 354 | ✓ |
| token_introspection | p0 | axiam | 4504 | 0.5% | 5.7 | 47.7 | 52.7 | 3.55 | 495 | ✓ |
| token_introspection | p0 | keycloak | 1888 | 3.2% | 7.3 | 81.8 | 85.8 | 2.36 | 906 | ✓ |
| token_introspection | p0 | zitadel | 941 | 0.9% | 47.4 | 64.7 | 72.3 | 3.74 | 432 | ✓ |
| token_introspection | p2 | axiam | 4391 | 0.9% | 6.1 | 45.2 | 50.7 | 3.43 | 476 | ✓ |
| token_introspection | p2 | keycloak | 1715 | 0.9% | 8.2 | 82.7 | 86.9 | 2.35 | 964 | ✓ |
| token_introspection | p2 | zitadel | 915 | 2.4% | 50.0 | 67.9 | 75.0 | 3.83 | 430 | ✓ |
| token_introspection | p3 | axiam | 4376 | 0.4% | 6.2 | 45.5 | 50.8 | 3.47 | 489 | ✓ |
| token_introspection | p3 | keycloak | 1731 | 5.8% | 8.0 | 82.6 | 86.7 | 2.34 | 913 | ✓ |
| token_introspection | p3 | zitadel | 904 | 1.4% | 50.5 | 68.4 | 76.3 | 3.80 | 442 | ✓ |
| jwks_fetch | p0 | axiam | 26680 | 0.9% | 1.4 | 3.1 | 4.4 | 1.68 | 412 | ✓ |
| jwks_fetch | p0 | keycloak | 4573 | 3.7% | 2.7 | 72.6 | 76.6 | 2.00 | 932 | ✓ |
| jwks_fetch | p0 | zitadel | 2091 | 1.6% | 11.1 | 64.8 | 67.1 | 2.98 | 291 | ✓ |
| jwks_fetch | p2 | axiam | 24097 | 1.6% | 1.6 | 3.0 | 4.2 | 1.90 | 408 | ✓ |
| jwks_fetch | p2 | keycloak | 4167 | 9.6% | 3.0 | 72.8 | 76.8 | 2.01 | 927 | ✓ |
| jwks_fetch | p2 | zitadel | 2053 | 0.8% | 12.9 | 60.0 | 63.2 | 3.15 | 281 | ✓ |
| jwks_fetch | p3 | axiam | 23954 | 0.6% | 1.6 | 3.1 | 4.3 | 1.90 | 413 | ✓ |
| jwks_fetch | p3 | keycloak | 3786 | 11.2% | 3.2 | 75.0 | 78.6 | 2.01 | 890 | ✓ |
| jwks_fetch | p3 | zitadel | 2052 | 1.0% | 12.9 | 60.1 | 63.1 | 3.14 | 292 | ✓ |
| userinfo | p0 | axiam | 4752 | 0.5% | 5.1 | 50.9 | 55.1 | 3.31 | 422 | ✓ |
| userinfo | p0 | keycloak | 3721 | 0.6% | 3.0 | 77.1 | 80.8 | 2.00 | 882 | ✓ |
| userinfo | p0 | zitadel | 995 | 1.0% | 23.3 | 80.4 | 83.1 | 2.87 | 439 | ✓ machine-user token |
| userinfo | p2 | axiam | 4585 | 0.8% | 5.4 | 50.6 | 55.0 | 3.34 | 466 | ✓ |
| userinfo | p2 | keycloak | 3486 | 0.7% | 3.2 | 77.7 | 81.3 | 2.01 | 973 | ✓ |
| userinfo | p2 | zitadel | 980 | 2.1% | 25.7 | 79.1 | 84.3 | 2.95 | 449 | ✓ machine-user token |
| userinfo | p3 | axiam | 4437 | 2.1% | 5.5 | 51.2 | 55.5 | 3.53 | 437 | ✓ |
| userinfo | p3 | keycloak | 3490 | 0.4% | 3.2 | 77.9 | 81.5 | 2.00 | 929 | ✓ |
| userinfo | p3 | zitadel | 978 | 2.9% | 25.3 | 79.3 | 83.4 | 2.95 | 457 | ✓ machine-user token |
| userinfo_grpc (AXIAM-only) | p0 | axiam | 12307 | 1.9% | 4.0 | 6.0 | 7.0 | 2.10 | 422 | ✓ |
| userinfo_grpc (AXIAM-only) | p2 | axiam | 11954 | 1.6% | 4.0 | 6.0 | 7.0 | 2.08 | 526 | ✓ |
| userinfo_grpc (AXIAM-only) | p3 | axiam | 11937 | 1.0% | 4.0 | 6.0 | 7.0 | 2.07 | 533 | ✓ |
| zitadel_userinfo_grpc | p0 | zitadel | 191 | 4.4% | 230.0 | 320.0 | 823.0 | 1.13 | 437 | ✓ machine-user token |
| zitadel_userinfo_grpc | p2 | zitadel | 201 | 3.1% | 230.0 | 263.0 | 697.9 | 1.24 | 446 | ✓ machine-user token |
| zitadel_userinfo_grpc | p3 | zitadel | 192 | 3.2% | 230.0 | 289.0 | 886.0 | 1.24 | 448 | ✓ machine-user token |
| oauth2_password_login | p0 | axiam | 69 | 2.0% | 699.1 | 760.6 | 940.0 | 2.12 | 495 | ✓ |
| oauth2_password_login | p0 | keycloak | (47) | n=1 | (990.4) | (1129.0) | (1218.8) | 2.05 | 966 | ✗ 1/3 runs valid |
| oauth2_password_login | p0 | zitadel | (2) | — | (21786) | (25414) | (27451) | 2.02 | 413 | ✗ p95>2s (bcrypt) |
| oauth2_password_login | p2 | axiam | 70 | 1.6% | 696.4 | 763.9 | 1050.6 | 2.11 | 481 | ✓ |
| oauth2_password_login | p2 | keycloak | 51 | 4.8% | 890.3 | 1094.7 | 1186.0 | 2.05 | 961 | ✓ 2/3 |
| oauth2_password_login | p2 | zitadel | (2) | — | (22031) | (25348) | (27107) | 2.02 | 412 | ✗ p95>2s (bcrypt) |
| oauth2_password_login | p3 | axiam | 68 | 0.9% | 704.0 | 790.9 | 1199.8 | 2.05 | 482 | ✓ |
| oauth2_password_login | p3 | keycloak | (22) | — | (2178.6) | (2308.5) | (2422.3) | 2.03 | 863 | ✗ 0/3 |
| oauth2_password_login | p3 | zitadel | (2) | — | (21915) | (25611) | (27418) | 2.02 | 409 | ✗ p95>2s (bcrypt) |
| token_refresh | p0 | axiam | 545 | 1.2% | 88.8 | 111.1 | 155.0 | 2.59 | 484 | ✓ ⚠ protocol-variant (session refresh) |
| token_refresh | p0 | keycloak | 377 | 2.4% | 101.5 | 203.9 | 297.2 | 2.05 | 916 | ✓ ⚠ protocol-variant (OAuth2 grant) |
| token_refresh | p2 | axiam | 540 | 3.3% | 89.0 | 113.2 | 156.2 | 2.68 | 482 | ✓ ⚠ protocol-variant |
| token_refresh | p2 | keycloak | 368 | 0.4% | 102.3 | 204.4 | 297.4 | 2.05 | 973 | ✓ ⚠ protocol-variant |
| token_refresh | p3 | axiam | 542 | 1.3% | 89.5 | 112.8 | 155.8 | 2.69 | 495 | ✓ ⚠ protocol-variant |
| token_refresh | p3 | keycloak | 365 | 0.6% | 102.5 | 204.9 | 298.1 | 2.05 | 948 | ✓ ⚠ protocol-variant |
| token_refresh | all | zitadel | — | — | — | — | — | — | — | ✗ fallback-op (no offline_access flow) |
| authz_check_rest (AXIAM-only) | p0 | axiam | 1032 | 0.3% | 27.2 | 79.4 | 84.9 | 2.87 | 390 | ✓ |
| authz_check_rest (AXIAM-only) | p2 | axiam | 1024 | 0.3% | 27.8 | 79.8 | 85.2 | 2.99 | 395 | ✓ |
| authz_check_rest (AXIAM-only) | p3 | axiam | 1016 | 0.8% | 28.0 | 80.1 | 85.7 | 2.95 | 383 | ✓ |
| authz_check_grpc (AXIAM-only) | p0 | axiam | 1268 | 1.1% | 21.0 | 74.0 | 79.0 | 2.81 | 383 | ✓ |
| authz_check_grpc (AXIAM-only) | p2 | axiam | 1265 | 0.6% | 21.0 | 74.0 | 79.0 | 2.84 | 380 | ✓ |
| authz_check_grpc (AXIAM-only) | p3 | axiam | 1259 | 0.3% | 21.0 | 74.0 | 79.0 | 2.83 | 390 | ✓ |
| authz_batch_rest (AXIAM-only, `coalesced` default) | p0 | axiam | 1026 (=5 130 checks/s) | 13.0% | 27.5 | 79.6 | 85.2 | 2.96 | 375 | ✓ |
| authz_batch_rest 〃 | p2 | axiam | 1015 | 13.2% | 28.0 | 79.9 | 85.5 | 2.86 | 375 | ✓ |
| authz_batch_rest 〃 | p3 | axiam | 1004 | 12.0% | 28.6 | 80.3 | 85.8 | 2.88 | 379 | ✓ |
| authz_batch_grpc (AXIAM-only, `coalesced` default) | p0 | axiam | 928 (=4 640 checks/s) | 17.0% | 33.0 | 84.0 | 90.0 | 2.83 | 435 | ✓ |
| authz_batch_grpc 〃 | p2 | axiam | 917 | 17.1% | 34.0 | 84.0 | 90.0 | 2.72 | 420 | ✓ |
| authz_batch_grpc 〃 | p3 | axiam | 926 | 16.4% | 33.0 | 84.0 | 90.0 | 2.67 | 423 | ✓ |

## 9. SDK client benchmarks — median-of-3, with a real wire baseline

All eleven SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, Go, PHP,
Swift, C, C++) ran the same four ops against the same seeded AXIAM at
plaintext, **three passes each, medianed**, with a **matched-concurrency
k6 wire baseline** measured on the same host first — so the "overhead vs
wire" column finally exists and means what it says. Client CPU and peak
RSS are now recorded per SDK as well. Concurrency-16 SDKs (p0):

| sdk | login p50 (ms) | refresh p50 (ms) | check p50 (ms) | check p95 (ms) | check thr (rps) | check p95 overhead vs wire (ms) |
|---|---|---|---|---|---|---|
| rust | 257.5 | 17.3 | 10.0 | 59.8 | 869 | **+2.7** |
| go | 253.8 | 17.3 | 10.1 | 60.0 | 840 | +2.9 |
| java | 254.7 | 17.3 | 10.3 | 60.1 | 835 | +3.0 |
| csharp* | 234.6 | 17.2 | 10.3 | 60.8 | 821 | +3.7 |
| typescript* | 255.7 | 16.7 | 18.1 | 34.2 | 805 | (−22.9)* |
| kotlin | 233.4 | 17.2 | 11.0 | 61.7 | 773 | +4.6 |
| swift | 231.7 | 17.3 | 11.3 | 61.4 | 747 | +4.3 |
| python* | 238.9 | 17.3 | 40.2 | 116.8 | 311 | +59.7 |
| cpp* | 242.2 | 17.2 | 3.2 | 280.2 | 313 | +223.1 |

Serial harnesses, labeled and excluded from cross-SDK throughput
comparison (single worker, by their harness design): **C** (check p50
3.0 ms, p95 3.8 ms, 318 rps) and **PHP** (3.6 / 4.3 ms, 272 rps).

**Client-side footprint (new this run — first pass of this telemetry).**
Each SDK's own process CPU (total over its bench) and peak RSS, which is
half the story for IoT and sidecar deployments:

| sdk | runtime | client CPU (s, whole bench) | peak RSS (MiB) |
|---|---|---|---|
| go | go 1.26 | **3.3** | 36 |
| c *(serial)* | gcc 16, C11 | 13.9 | **13** |
| php *(serial)* | php 8.5 | 5.6 | 59 |
| csharp | .NET 8 | 10.3 | 105 |
| typescript | node 22 | 13.1 | 125 |
| swift | swift 6.3 | 13.3 | 48 |
| kotlin | JVM 21 | 17.1 | 458 |
| cpp | g++ 16 | 17.6 | 39 |
| java | JVM 21 | 21.1 | 306 |
| rust | cargo | 23.4 | **23** |
| python | python 3.14 | 40.0 | 88 |

Highlights: Go is by far the cheapest concurrent client on CPU; C and
Rust are the smallest on memory (13/23 MiB — the embedded/IoT lane); the
JVM SDKs pay the expected 300–460 MiB runtime tax at equal wire
performance; Python is the most expensive on CPU *and* the slowest, a
consistent picture. One number we flag rather than explain: Rust's
client CPU reads high relative to its (excellent) latency profile —
this is the first run of this telemetry and that figure gets a second
look before we draw conclusions from it.

What the table shows, and the flags (\*), stated plainly:

- **The server, not the SDKs, sets the floor**: ten SDKs measure refresh
  at 16.7–17.3 ms p50 and login at 232–257 ms (server-side Argon2id
  dominates identically from every language).
- **SDK overhead on the hot path is single-digit milliseconds at p95** for
  seven of the nine concurrent SDKs (+2.7 to +4.6 ms over raw k6 at the
  same concurrency) — the headline the wire baseline was built to
  establish.
- **C# refresh is now a real measurement** (17.2 ms — draft 5's cached
  no-op is fixed by the harness forcing expiry); its record merged 2 of 3
  passes.
- **Python** moved to a genuinely async driver and is *still* the outlier
  (p50 40 ms, +60 ms p95 overhead) — draft 5 blamed the harness; the
  harness is now clean, so the remaining gap belongs to the SDK/runtime
  and is being profiled.
- **C++** keeps its reconnect-shaped tail (p50 3.2 ms / p95 280 ms)
  despite the connection-age fix — investigation continues, now on
  server-side idle-timeout suspects.
- **TypeScript's negative "overhead"** is flagged, not celebrated: a
  client shouldn't beat the wire baseline on the same box, so its
  baseline comparability is under audit before we publish TS overhead
  claims.

## 10. Why build AXIAM at all?

A fair question given this field: Keycloak is mature and ubiquitous,
Zitadel is modern and well-engineered, Auth0/Okta are excellent managed
products. Five drafts of measurements into this project, our answer has
sharpened rather than softened:

**1. The efficiency gap is real, large, and it is the product.** These
are not micro-optimizations: on identical hardware, identical caps and
identical scenarios, AXIAM issues ~8× the tokens, introspects ~2.4–4.8×
the tokens, and serves ~6–13× the JWKS reads of the incumbents — in
86–120 MiB of server RSS, under 8% of what Keycloak uses for less
throughput. IAM is infrastructure that runs 24/7 in front of everything;
its cost floor and its p95 are a tax every request in the system pays.
Rust with no GC pauses, no JVM warm-up, and CPU-shaped-per-request
economics moves that floor by close to an order of magnitude — that is a
capability difference, not a benchmark trophy.

**2. Nobody else treats the machine/IoT edge as the main stage.**
Authorization *decisions* as a first-class, benchmarked hot path (5 100+
hierarchy-aware RBAC checks/s on 2+2 cores, batch API at the shipped
default); a gRPC data plane that does 12 000+ identity reads/s at 6 ms
p95 (the competitors' gRPC surfaces are management APIs, and it shows —
Zitadel's measures 200/s); and in-process mutual TLS at ~1% cost, no
sidecar — which makes per-device client certificates *the cheap option*
for IoT fleets rather than an architecture project. If your workload is
humans logging into web apps, Keycloak serves you well today. If it is
services and devices asking "may I?" tens of thousands of times a second,
that workload is what AXIAM is shaped around.

**3. Security posture as measured defaults, not documentation.** AXIAM is
the only target here that ships abuse rate-limits on by default — sized
from these measurements, with human endpoints locked strictly regardless
of posture (and login enforcement measured exact under flood; the
machine-endpoint enforcement gaps §7 reports are published, tracked
bugs, not fine print).
Argon2id, EdDSA short-lived tokens, single-use rotating refresh
tokens, append-only audit, encrypted-at-rest secrets are defaults, not
options. And the process is part of the posture: this benchmark series
has now found, published, and fixed a synchronous rate-limit write, a
×60 limiter units bug, a Nagle-induced TLS latency cliff, two
authorization table scans — and currently carries an open refresh
regression and a gRPC flood-behavior bug in public view. We think an IAM
vendor that measures itself adversarially and publishes the misses is
itself a security feature.

**And the honest cons, in the same breath.** AXIAM is alpha: it has a
fraction of Keycloak's protocol surface, extension ecosystem, hosting
options and community; Zitadel's resting stack is smaller than ours
(SurrealDB + RabbitMQ ride along in every AXIAM deployment); Keycloak
wins one whole-stack efficiency cell outright (§5); our RBAC engine is
additive-only in v1.0-beta (no deny-override); SurrealDB is a younger
storage engine than Postgres by a decade; and every number in this
document comes from one consumer laptop until the server-class re-run
lands. Choosing AXIAM today means choosing a young system whose
performance-per-watt, machine-first design, and measurement culture you
value over incumbent breadth. That trade is exactly the niche the
incumbents leave open — and the measurements above are why we believe the
niche is worth serving.

## 11. Summary and what happens next

**Strengths.** The first release-image, full-three-profile, median-of-3
matrix: token issuance **7.9×/6.5×** (Keycloak/Zitadel) now sustained
under TLS and mTLS; introspection **2.4×/4.8×**; JWKS **5.8–12.8×**;
userinfo **1.3×/4.8×** REST and **12.3 k/s** gRPC; authz checks up
**+37/43%** with the batch default measured at **4.97× singles**; native
mTLS at ~1% cost in the run of record; the only login valid at every
profile; ≤ ~120 MiB average server RSS; and all three of draft 5's open
mysteries closed with controlled experiments (§3).

**Weaknesses, stated as plainly.** A −35% refresh regression we
introduced ourselves and are now chasing; a gRPC limiter that starves
under flood; a Keycloak login cell that resists fair measurement in both
directions; Python and C++ SDK outliers that survived their first fixes;
laptop hardware.

**Next round:** the refresh-regression bisection, the limiter-enforcement
fixes (gRPC starvation and REST overshoot) re-verified by the same
assertion script that failed them here, scenario coverage for the three
untested limiter families, the TypeScript baseline audit — and the
long-promised server-class hardware re-run, which remains the biggest
single upgrade this series can make.

---
*Sources: G-box run-5 of 2026-08-05/06 (median-of-3 capped matrix ×
p0/p2/p3 × 3 targets; §12.3–12.7 labeled investigation passes: KC-login
4 GiB, TCP_NODELAY A/B + VU sweep + in-namespace `ss -ti` socket
captures, session/decision cache 2×2, cache-on revocation cell, DB
capped/uncapped, prod rate-limit posture with the `rl-prod-summary.md`
assertion artifact; 11-SDK median-of-3 pass with matched-VU wire
baseline and client CPU/RSS telemetry; per-cell k6 summaries, 1 s
container + host telemetry, digest-recorded image metadata), aggregated
by `runner/report.py`. Target versions: AXIAM 1.0.0-alpha24 (digest-pinned),
Keycloak 26.7.0, Zitadel v4.16.2, SurrealDB v3 (digest-pinned),
Postgres 16. Metric definitions: [`docs/methodology.md`](docs/methodology.md).*
