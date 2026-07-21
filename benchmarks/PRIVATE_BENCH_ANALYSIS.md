# PRIVATE — Benchmark Post-Mortem & Improvement Plan

> Internal working document. Companion to `PUBLIC_BENCH_ANALYSIS.md`.
> **Updated 2026-07-21** for the second (preliminary) run: one full "DB-capped"
> matrix (AXIAM 1.0.0-alpha15 source build vs Keycloak 26.7.0 vs Zitadel
> v4.15.2, p0-plaintext + p2-tls13, 50 VUs, 2 CPU / 1024 MiB caps) plus one
> "DB-uncapped" sensitivity pass (AXIAM + Zitadel only, DB at 4 CPU / 2048 MiB,
> servers still capped). Same Dell XPS 15 9570 host as run 1; the A6 host
> telemetry (CPU MHz, temperature, k6 cores) and the A4 metadata are present in
> every cell this time. Still **single-run** cells (the C1 median-of-3
> machinery exists but was not used for this preliminary pass). This file
> collects everything we should NOT publish as-is: harness bugs, unexplained
> anomalies, tuning hypotheses, and AXIAM work items derived from the raw data.
> Run-1 (2026-07-19) findings that are now resolved are kept, compressed, for
> the record.

## 0. Run-2 executive summary (what moved, what didn't)

Measured on the capped matrix, p0, vs run 1:

| Area | Run 1 | Run 2 | Verdict |
|---|---|---|---|
| B1 login (Argon2 semaphore) | 35 req/s, p95 2127 ms, RSS→970 MiB | **67.5 req/s, p95 907 ms, RSS peak ~478 MiB** | ✅ fixed (2×, gate passes) |
| authz single check REST | 290 req/s, p50 139 ms | **745 req/s, p50 67 ms** | ✅ 2.5× (attribution below, §4.6) |
| authz single check gRPC p99 | 850 ms tail | **90 ms** | ✅ tail gone |
| A1 userinfo | 100% errors | **valid on all 3 targets; AXIAM fastest (5457/s)** | ✅ fixed |
| A2 Keycloak ROPC | 100% errors | **works (22.3/s, hash-bound)** | ✅ fixed |
| D5 Zitadel real login | CC fallback (405/s, no hash) | **real session-API login: 2.0/s, p50 ~22 s (bcrypt)** | ✅ harness fixed; cell gate-invalid |
| B2 TLS 1.3 on token endpoints | CC −55% | **CC −49% — still halved** | ❌ NOT fixed; resumption hypothesis refuted (§4.3) |
| D1 authz batch | 41/22 req/s, p50 1.1/2.3 s | **46/23 req/s, p50 1.05/2.15 s** | ❌ unchanged; new root-cause lead (§4.2) |
| token_refresh | "real rotation" (so we thought) | **`bench_fallback` fired on 100% of iterations on ALL THREE targets** | ❌ new harness finding (§1.6) |
| D4 Zitadel gRPC | not covered | **runs, but 100% gRPC errors** (§1.7) | ❌ needs audience fix |
| Keycloak overall | CC 143, intro 337, jwks 644 | **CC 346, intro 1765, jwks 3855** | ⚠ 2–5× better, same image tag (§2.0) |

Uncapping the DB (4 CPU): AXIAM authz single +37% (→1017 REST), userinfo +33%
(→7261, server pegs for the first time), CC +1.6% (DB cap was NOT the token
wall), batch unchanged (not resource-bound). Zitadel: jwks +73%, userinfo +78%
with Postgres pegging even 4 cores — Zitadel is deeply DB-bound.

## 1. Harness bugs & data-validity issues

### 1.1 ✅ FIXED+VERIFIED — `userinfo` used a client-credentials token

Run 2 confirms the A1 fix: `mintUserToken()` (login-first) produces valid
userinfo cells on AXIAM and Keycloak; 0% errors everywhere. Bonus realized:
userinfo is now a real 3-way comparison and AXIAM wins it (5457 vs 3561 KC vs
967 Zitadel, capped p0). Note AXIAM's cell is DB-pegged (2.04 cores) with a
bimodal latency shape (p50 4.6 ms, p95 46 ms) — see §3.1; uncapped it does
7261/s and the *server* saturates for the first time outside login.

### 1.2 ✅ FIXED+VERIFIED — Keycloak ROPC

Fail-closed seeding (A2) + the follow-up seed fix (commit `8e72ca1`) work:
ROPC produces a valid hash-bound login cell (22.3 req/s, KC server pegged at
2.0 cores). Note KC's login p95 (2273–2380 ms) **breaches the 2 s validity
gate** — flag it in the report rather than dropping it; it's a real measure of
Argon2id-under-JVM at this concurrency.

### 1.3 ✅ MOSTLY FIXED — password-login comparability

All three targets now hash for real: AXIAM Argon2id (OWASP), Keycloak 26
Argon2id (default), Zitadel **bcrypt at its default cost** via the D5
session-API flow. Zitadel's cell is honest but extreme: 2.0 req/s, p50 ~22 s
at 50 VUs — its server pegs 2 cores doing ~1 CPU-second of bcrypt per login.
Publish with care: state hash algorithms + defaults explicitly, keep the
gate-invalid flag on the KC/Zitadel cells, and don't present 34× as if
Zitadel were doing the same work as AXIAM — it's doing *more expensive* work
per login at its shipped defaults. The p95 gate (2 s) makes AXIAM the only
target with a *valid* login cell at 50 VUs; that's the defensible headline.

### 1.6 ❌ NEW — `token_refresh` is a fallback op on ALL THREE targets (and retroactively was in run 1 for AXIAM too)

The A3 `bench_fallback` counter fired on **100% of iterations for every
target** (AXIAM 145 555, KC 32 566, Zitadel 34 408 — each ≈ iterations).
Cause: `token_refresh.js` still mints via `mintToken()` → client-credentials
first → **no target issues a refresh token on the CC grant** (spec-correct),
so every VU permanently takes the `clientCredentials` fallback branch. The
cell therefore measures "CC issuance with an extra untimed mint per
iteration" everywhere.

Retroactive correction for run 1: AXIAM's celebrated 886/373 req/s "refresh
rotation" cells were the **same fallback** — 886 ≈ exactly half of CC 1743,
the two-requests-per-iteration signature we spotted on Zitadel but missed on
ourselves. The instrumentation did its job. Run 2's ratios all match
(AXIAM 910 ≈ ½×1788; 453 ≈ ½×908).

Fix (**A8**): `token_refresh.js` setup must obtain the token via
`mintUserToken()` (login-first — AXIAM's login sets `axiam_refresh`; KC ROPC
returns `refresh_token`; Zitadel needs an OIDC flow or `offline_access` via
its session/OIDC bridge — investigate; keep the fallback tag for targets where
it's genuinely impossible). Until then, `report.py` already excludes these
cells from head-to-head winner tables (verified working — keep it that way)
and the public doc §4 carries the correction.

### 1.7 ❌ NEW — Zitadel gRPC scenario: 100% gRPC errors

`zitadel_userinfo_grpc` ran (proto loads, 1725 req/s of *responses* at ~20 ms)
but **every call returned a non-OK gRPC status** in both profiles. Two stacked
causes, both visible in the data:

1. `bench_fallback=1` in setup: `mintUserToken()` fell back to
   client-credentials because Zitadel's D5 `login()` returns a **session
   token** in the body (`sessionToken`), which `readAccessFromLogin()` doesn't
   recognize (it looks for `access_token`/cookies) → no user token.
2. The CC machine-user token it used instead lacks the **Zitadel-project
   audience** — Zitadel's own APIs (auth.v1 included) reject tokens minted
   without `urn:zitadel:iam:org:project:id:zitadel:aud` scope. REST
   `/oidc/v1/userinfo` accepts the plain CC token (hence REST userinfo works,
   966/s) but the gRPC Auth API does not.

Fix (**D11**): add the `urn:zitadel:iam:org:project:id:zitadel:aud` scope to
the Zitadel `clientCredentials()` body used for gRPC setup (or exchange the
session token properly), and record the k6 gRPC error *status* in a counter so
the next failure of this shape is diagnosable from the summary alone. The
res.csv shows Postgres pegged (2.03 cores) even on the error path — the
requests were doing real DB work before failing, so a valid cell should land in
the same order of magnitude (~1.7–2 k/s), which would make a genuinely
interesting protocol-efficiency pairing vs Zitadel REST userinfo (967/s).

### 1.8 ⚠ PARTIAL — provenance fields: digests unknown, stale tag, floating DB tag

A4 landed and every meta.json now has kernel/docker/CPU/governor/k6-cores —
good. But all `image_digest` fields read `"unknown"` (locally-built images
have no RepoDigests; pulled ones should have been inspected before the run)
and the AXIAM tag string says `1.0.0-alpha12` while the binary is a local
build of merged main (released as **1.0.0-alpha15**). Also
`surrealdb/surrealdb:v3` is a **floating tag** — we cannot prove the DB
version was identical between runs 1 and 2 (relevant to §4.6 attribution).

Fix (**A9**): (a) stamp the real built version into the image tag (or a
`build_ref` meta field with `git rev-parse HEAD`); (b) fall back to
`docker images --digests` / image ID when RepoDigests is empty, and record
the image *ID* always; (c) pin `surrealdb` (and postgres) by digest in the
bench composes.

### 1.9 ✅ VERIFIED — secrets hygiene (A7)

The shared run-2 archive contains no secret material (checked: the only
`SECRET|PASSWORD` grep hits are scenario filenames in meta.json). `bench-pack`
does its job.

## 2. Cross-target observations that need internal follow-up

### 2.0 ⚠ Keycloak improved 2–5× vs run 1 on the SAME image tag

KC 26.7.0 / postgres:16-alpine in both runs, yet: CC 143→346, introspection
337→1765, jwks 644→3855, userinfo (error path)→3561. Its latency *shape*
changed too (run 1: p50 ~90–300 ms; run 2: p50 3–8 ms with an ~80 ms p95
mode — classic JVM fast-path + GC/queueing tail). Plausible contributors, none
proven: C2's uniform Postgres tuning (though KC's DB is nearly idle), the A2
seed rebuild (a correctly-configured realm/client), no 1.66 M-error userinfo/
ROPC storms polluting the same session, and possible image drift under the
mutable `26.7.0` tag (digest unrecorded in run 1 — see §1.8). **Action:** treat
run 2 as the honest baseline going forward, say so in the public doc (done),
and let A9 digest-pinning prevent this ambiguity from recurring. Do NOT quote
run-1 Keycloak multiples (12×, 6.5×…) anywhere anymore; the current honest
multiples are CC 5.2×, introspection 1.3×, jwks 7.0×, userinfo 1.5×.

Two uncomfortable, publish-with-care facts from the new KC numbers:
- **Introspection is now close** (2229 vs 1765 = 1.26×). AXIAM still wins
  throughput, p95 (27 vs 83 ms) and cpu·ms/req (1.07 vs 1.33), but the "6.5×"
  era is over.
- **KC beats AXIAM on cpu·ms/req for userinfo** (0.56 vs 0.69) — driven by
  AXIAM's stack including a pegged SurrealDB + RabbitMQ. Whole-stack
  efficiency is the metric we chose; keep it, but the server-only breakdown
  (A5) should be surfaced next time to show AXIAM's server itself is cheaper.

### 2.1 Zitadel is even more DB-bound than we thought

Uncapped (PG 4 CPU/2 GiB): jwks 2034→3520 with PG at **3.9/4 cores**; userinfo
967→1718 with PG at **4.01/4**; introspection 923→1027 (its server becomes the
wall at 1.9/2). Zitadel's ceiling in any small envelope is Postgres. For
fairness we already tuned PG uniformly (C2) — mention in methodology that the
uncapped pass gave Zitadel's DB 2× the CPU AXIAM's server had.

### 2.2 Benchmark-coverage gaps still open

1. **p3-mtls / p1-tls12** — still not run (D3 native mTLS code is merged and
   waiting for its no-nginx p3 pass).
2. **Median-of-3** (C1) — machinery merged, not exercised; next full run must
   use it. All run-2 deltas < ~10% should be treated as noise until then.
3. **Saturation / open-loop** — closed-loop 50 VUs still caps jwks (k6 ~5.4
   cores, borderline against the generator-headroom gate) and now visibly
   floors authz/token cells in the uncapped pass (§3.2): nothing saturated,
   throughput = 50 / round-trip-latency. A `constant-arrival-rate` variant is
   the only way to measure the real knee.
4. **rl=prod posture run** (C4) — still pending.
5. **SDK benches (E1) and AMQP harness (E2)** — unchanged.
6. **D7 decision-cache ON pass** — not in this archive; run the labeled
   sensitivity cell next time.

## 3. Bottleneck attribution (run-2 data)

### 3.1 Capped matrix — the three regimes still hold, with better resolution

- **AXIAM:** DB-pegged on authz single checks (2.01–2.02/2) and userinfo
  (2.04/2); DB-heavy but unpegged on CC/refresh (1.76); server-heavy only on
  login (1.66, by design) and jwks (1.24–1.56, generator-limited). Batch
  cells: **nothing** is loaded (server 0.03–0.06, DB 1.03–1.09) — see §4.2.
- **Keycloak:** server pegged at 2.00 in *every* cell, DB ≤ 0.35. Unchanged.
- **Zitadel:** PG pegged or near-pegged everywhere except login (server-pegged
  doing bcrypt).

### 3.2 Uncapped sensitivity — what it taught us

- **authz single checks:** +37% REST (745→1017), DB now 2.84/4 (unpegged),
  server 0.88/2 (unpegged) → the remaining limit is **round-trip latency**
  (p50 46.5 ms ⇒ 50 VUs / 0.0465 s ≈ 1075/s — exactly what we measured).
  Cutting per-check latency (D7 cache, or fewer round-trips) is now worth
  more than CPU. The 3-round-trip structure at ~15 ms each is the floor.
- **client_credentials: the DB cap was NOT the wall** (+1.6%, DB plateaus at
  1.76 cores regardless of cap). Token issuance is latency-structured too
  (p50 25.6 ms ⇒ ~1950/s closed-loop ceiling; we sit at 1817). To move this
  number: shave round-trips per issuance (§4.5), not DB CPU.
- **userinfo: first non-login AXIAM server saturation** (2.01/2 cores at
  7261/s, DB 3.33). This is the cell to profile server-side CPU on next —
  it's our highest-rate authenticated read path.
- **batch: identical uncapped** — definitive proof it's not resource-bound.

### 3.3 SurrealDB tuning (D6) — sharpened by the uncapped data

The DB pegging on authz/userinfo is real work, not cap artifact (it happily
eats 2.8–3.3 cores when allowed). Next D6 steps, in order of expected value:
profile the 3 coalesced authz queries and the userinfo read with SurrealDB
slow-query logging; check `get_role_permission_grants_for_roles` for the §4.2
serialization; then the durability-parity statement (C2.3) before publishing
any tuned numbers. RabbitMQ still shows the periodic ~1-core p95 spikes
(avg 0.01–0.41) — unchanged, same batching recommendation as run 1.

## 4. AXIAM product work items (evidence-ranked, updated)

### 4.1 ✅ B1 Argon2id semaphore — CONFIRMED, with a residual

Measured: 67.5 req/s (was 35), p95 907 ms (was 2127), server peak ~478 MiB
(was ~970), 0% errors, gate passes, at unchanged OWASP parameters. The
acceptance target "RSS under ~350 MiB" was missed on paper but the miss is the
**D9 retention effect**, not concurrency: baseline RSS before the login cell
is ~115 MiB, peak during is ~478, and RSS then stays ~478 for every subsequent
scenario in the session (run 1: retained ~646). So: semaphore works; allocator
retention (D9) is still worth the jemalloc A/B, since it inflates AXIAM's
published memory column for every post-login cell (visible in run 2's mem
figures: cells that ran after login report ~880–950 MiB stack vs ~420–490
before).

### 4.2 ❌ [HIGH] Batch authz — D1 coalescing landed, numbers did not move; NEW root-cause hypothesis

Run 2 (capped or uncapped, p0 or p2 — all identical): REST batch 46/s at p50
~1.05 s; gRPC batch 23/s at p50 ~2.15 s; server 0.03–0.06 cores; **DB pinned
at 1.03–1.09 cores in every configuration, including with 4 cores available**.
That last fact is the tell: the batch path consumes almost exactly ONE core's
worth of DB no matter what — i.e. its work is **serialized on a single
DB-side thread**. Closed-loop arithmetic then explains everything:
50 VUs / 46 per-s ≈ 1.09 s queueing delay = the observed p50; throughput is
pinned at 1/(per-batch serialized CPU time ≈ 22 ms).

So the D1 coalescing was correct but aimed at the wrong cost: it removed
round-trips (15→3), while the dominant cost is (hypothesis) **one of the
coalesced queries executing serially inside SurrealDB** — prime suspect the
batched `get_role_permission_grants_for_roles` (IN-across-roles), possibly
unindexed/table-scanning, and (for gRPC ≈ 2× REST) the per-item
subject_id/T-27-12 validation path issuing a second heavy query. Note the
single-check path improved 2.5× in the same release — whatever serializes is
specific to the batch's query shape.

Next steps (**D10**, supersedes the D1 re-run):
1. Reproduce one batch call against the bench stack with SurrealDB query
   logging; time each of the 3 queries; `EXPLAIN` the grants query.
2. If the grants query is the serial cost: index it, or split it back into
   per-role queries issued **concurrently** (ironic but plausible win), or
   pre-join role→grants in one round-trip per role set.
3. Control experiment: implement the batch handler as `join_all` of N
   single-check evaluations and benchmark both shapes — if 5 concurrent
   singles beat the coalesced batch (745/5 ≈ 149 batches/s equivalent vs
   measured 46), ship that while the query is investigated.
4. Explain gRPC's exact 2× and eliminate it.

### 4.3 ❌ [HIGH] TLS 1.3 halving persists — resumption hypothesis REFUTED, h2 is the surviving lead

Run 2 p2 vs p0 (capped): CC −49.2%, refresh-fallback −50.2%, introspection
−0.4%, jwks −10.9%, userinfo −9.8%, login +0.4%. New, decisive evidence from
the A6/k6 data: in the degraded p2 token cells `http_req_tls_handshaking` avg
≈ **0.001 ms** and `http_req_connecting` ≈ 0 — the B2 session-resumption +
keep-alive work is functioning, handshakes are simply not happening per
request, and yet p50 still exactly doubles (25.9→53.8 ms) with **everything**
(server CPU 0.98→0.56, DB 1.76→1.00 cores) halving in lockstep. That is a
concurrency ceiling upstream of the server, precisely the
**h2-single-connection multiplexing** signature (hypothesis 1 in the B2
analysis below): k6 negotiates h2 over TLS and funnels all 50 VUs through one
multiplexed connection, while p0 http/1.1 uses a per-VU connection pool.

Why introspection/userinfo/jwks barely move: their per-request latencies
(1.3–20 ms) sit under the single-connection ceiling; the POST token grants
(26 ms+) don't.

**Next actions (zero server code until measured):**
1. Run the p2 cell through the already-merged h1-only edge
   (`targets/axiam/tls/tls13-h1.conf`) for `oauth2_client_credentials` — if
   p2-h1 ≈ p0, h2 is convicted. (This was the one B2 acceptance step not run
   in this round.)
2. Confirm from the raw k6 JSON (laptop) that p2 cells carry
   `http_version=2` tags.
3. If convicted, decide the *product* stance: k6-specific artifact vs real
   client behavior. Real SDKs/service-mesh clients open connection pools;
   single-conn h2 serialization mostly punishes benchmark-style single-host
   clients. Options: tune h2 stream/flow-control windows on the actix
   listener; document `AXIAM__SERVER__TLS__HTTP2=false` + edge guidance; or
   accept and document. The honest public position meanwhile (published in
   run-2 doc): "TLS 1.3 halves AXIAM's token-endpoint throughput *under this
   load generator*; root cause isolated to connection behavior, not crypto —
   fix in validation."

The 4.3.1 root-cause analysis from run 1 (hypotheses, code landed: ALPN knob,
ticketer+session cache, 0-RTT declined, tls13-h1 edge) remains accurate;
run 2 upgraded hypothesis 2 (resumption) from "secondary" to "refuted as
dominant term" and left hypothesis 1 (h2) as the only live suspect.

### 4.4 [MEDIUM] Native mTLS — merged, still unmeasured

No p3 cells in this archive. The p3 no-nginx run stays on the next-run list.
(gRPC-over-TLS *did* get validated this round — see §4.7.)

### 4.5 [MEDIUM] Feed the DB-bound flows — now with uncapped guidance

Post-uncapped picture (§3.2): authz checks and userinfo scale with DB CPU;
token issuance does NOT (latency-structured). Priorities: (a) D7 decision
cache ON sensitivity cell — with checks now at 745–1017/s and DB-bound, the
cache's expected win is large and measurable; (b) count round-trips per CC
issuance and remove redundant client/tenant reads (the 25.6 ms p50 at ~1
server-core is mostly waiting); (c) userinfo server-side profile (first
server-saturating read path, §3.2).

### 4.6 ⚠ Attribute the 2.5× single-check improvement honestly

authz_check_rest went 290→745 req/s and the gRPC p99 tail (850 ms) vanished
between runs, but *which* change did it (D1 handler work? F2 pool lifecycle?
SurrealDB drift under the floating `v3` tag? seed shape?) is **not
attributable** with digests unrecorded (§1.8). Before quoting "2.5× faster
authz" in marketing: pin images (A9), re-run once on the pinned stack, and
bisect only if the number doesn't reproduce. The public doc currently states
the improvement with the harness/server changes as joint attribution — keep
that phrasing until proven.

### 4.7 ✅ Quick wins landed this round

- **gRPC over TLS (D2 + #218 crypto-provider fix): validated live** — p2 gRPC
  cells ran over TLS (per-VU handshakes visible: `tls_handshaking` avg
  1.9 ms on authz_check_grpc p2) with **no throughput penalty** (746 vs 722
  p0; batch identical). The p2 matrix is no longer internally inconsistent.
- **JWKS (B3):** flat at 24.1–27.4 k/s, still generator-limited; ETag/304
  behavior not exercised by the bench (k6 sends no If-None-Match) — fine.
- **userinfo endpoint semantics:** AXIAM cleanly accepts the user token and
  is the fastest target — the run-1 "make sure it 403s cleanly" note is moot.

### 4.8 [LOW] Report/labeling polish for run 3

- `report.py` treats `bench_fallback` in *setup* (Zitadel userinfo mints a CC
  token once) identically to per-iteration fallback — distinguish
  `fallback-op` (cell measures the wrong op) from `cc-token-setup` (op is
  right, token provenance is a caveat). Zitadel's REST userinfo cell is
  currently over-penalized by the label.
- Blank the throughput column for the 100%-error zitadel_userinfo_grpc cell
  (1725/s of errors invites misquoting — the run-1 lesson, new instance).
- Surface the A5 server-only efficiency table in the public doc next time
  (see §2.0, KC userinfo cpu·ms).

## 5. Security-hardening notes (updated)

1. **Login memory-DoS (B1): closed and verified** — peak RSS bounded (~478
   MiB incl. retention, was ~970 at the cap edge), backpressure instead of
   OOM. Residual: D9 retention keeps ~360 MiB of allocator arena after the
   burst; not a DoS, but run the experiment.
2. **Rate limiter posture** — unchanged stance; C4 prod-posture run still
   pending. The competitors' new numbers don't change the argument: neither
   KC nor Zitadel ships default per-IP limits.
3. **TLS 0-RTT stays off** (reaffirmed; resumption tickets active and now
   proven effective in-bench).
4. **mTLS in-process** — merged, needs the p3 run for the proxy-headers
   surface to be retired in the bench too.
5. **Zitadel bcrypt observation** (from D5): at Zitadel defaults a single
   laptop core sustains ~1 login/s — worth a neutral doc note on hash-cost
   tradeoffs (AXIAM's Argon2id at OWASP params + semaphore gives 67/s on 2
   cores with bounded memory; the *combination* of strong hashing and
   concurrency bounding is the differentiator).

## 6. Reporting/presentation for the site (run-2 deliverables)

- Public doc rewritten (second draft) with: real 3-way login and userinfo
  tables, the refresh-cell correction (prominent, it corrects draft 1), TLS
  status honesty, KC-improvement note, uncapped sensitivity section, and the
  host-telemetry summary (temps hit 95–100 °C; clocks held 3.7–3.9 GHz on
  CPU-pegged cells, ~3.2 GHz on the k6-heavy jwks cells; governor
  `performance`; per-cell mhz/temp columns now in the raw data).
- Charts unchanged from the run-1 plan (grouped bars, p95 dots, TLS-delta) —
  all derivable from the §5 matrix of the public doc.
- Do NOT chart: token_refresh (fallback everywhere), zitadel_userinfo_grpc
  (invalid), any run-1 Keycloak multiple.

## 7. Suggested order of execution (updated for run 3)

1. **A8** refresh-token user-mint + **D11** Zitadel gRPC audience + **A9**
   digest/version stamping + §4.8 label polish — all small harness diffs,
   they unblock the last invalid/ambiguous cells.
2. **B2 conviction cell**: p2 CC via `tls13-h1.conf` (one cell, minutes) —
   then fix or document per §4.3.3.
3. **D10** batch serialization investigation (query profiling + concurrent
   control experiment).
4. **Run 3 on the laptop**: full capped matrix, median-of-3 (C1), incl.
   p3-mtls (D3), D7-cache-ON cell, C4 prod posture, and the uncapped pass
   for Keycloak too (completes the sensitivity set).
5. E4 public refresh from run 3; then the deferred E1/E2/E3 ladder.
