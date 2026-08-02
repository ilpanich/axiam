# PRIVATE — Benchmark Post-Mortem & Improvement Plan

> Internal working document. Companion to `PUBLIC_BENCH_ANALYSIS.md`.
> **Updated 2026-08-02 for run 4** — the first run executed *after* the shared
> rate-limit write-behind fix, on the post-fix image (build_ref `6875e4b`),
> G-box (Dell XPS 15 9570, i7-8750H, 12 logical CPUs, ~31 GiB), Docker 29.6.2,
> k6 v2.1.0. Full median-of-3 capped matrix (AXIAM vs Keycloak vs Zitadel;
> p0-plaintext + p2-tls13; 50 VUs; 2 CPU per server container, **2048 MiB**
> per server container — raised from 1024, see §2.3 — DBs at 2 CPU / 1024 MiB),
> plus sensitivity passes (`sens-db-uncapped`, `sens-cache-on`, `sens-p3-mtls`,
> `sens-rl-prod`, `sens-batch-concurrent`) and the **first full 11-language SDK
> pass at three profiles (p0/p2/p3)**. Run-3 findings that are resolved are
> compressed; everything still open is carried forward. The executable
> follow-up plan derived from this document is
> [`claude_dev/improvement-after-run4-benchmark.md`](../claude_dev/improvement-after-run4-benchmark.md).

## 0. Run-4 executive summary

**The headline: the H2 write-behind rate-limit fix is verified at matrix
scale.** Run 4 is the re-measurement that `rate-limit-fix-verification.md`
promised, and it is unambiguous — every endpoint the synchronous
`rate_limit_bucket` UPSERT used to clamp is now dramatically faster, the
settle gate cleared in 15–16 s on every session (no timeouts, **zero refused
cells** — first run ever), and 42/48 matrix cells are valid with every
invalid cell explained (§2).

Median-of-3, capped, p0, vs run 3 (also median-of-3):

| Scenario | Run 3 | **Run 4** | Δ | Note |
|---|---|---|---|---|
| oauth2_client_credentials | 1823 | **2727** (±0.4%) | **+50%** | 7.7× KC, 6.4× Zitadel |
| token_introspection | 2230 | **4387** (±0.6%) | **+97%** | 2.4× KC, 4.7× Zitadel |
| authz_check_rest | 737 | **753** (±1.0%) | +2% | DB-pegged, as before |
| authz_check_grpc | 603 | **887** (±0.3%) | **+47%** | gRPC now BEATS REST +17.8% — G8 inverted (§3.2) |
| userinfo (REST) | 5008 | 4547 (±0.3%) | −9% | see §2.5 (mem-cap change, run variance) |
| userinfo_grpc | 3294 | **12665** (±0.4%) | **+284%** | tower-layer write removed from EVERY gRPC call |
| jwks_fetch | 27784 | 26371 (±1.2%) | −5% | generator-limited, unchanged story |
| oauth2_password_login | 69 | **69** (±1.8%) | 0% | Argon2id-bound by design — the right result |
| token_refresh (AXIAM) | fallback-op | **839 real** (±0.4%) | n/a | G4 fix holds at matrix scale, protocol-variant label |
| authz_batch_rest | invalid | 199 ops/s | — | ⚠ ran `concurrent`, NOT the shipped default (§1) |

Everything that improved is exactly the set of endpoints the H2 fix
targeted; everything else is flat within noise. The fix costs nothing
anywhere. **`rate-limit-fix-verification.md` can be closed as CONFIRMED at
matrix scale.**

Three new discoveries this run, in descending order of importance:

1. **The gRPC production rate limiter over-throttles ×60 — a real product
   bug found by `sens-rl-prod`** (§1.2). Root-caused to a units mismatch in
   code, not just observed.
2. **The bench compose still pins `AXIAM__AUTHZ__BATCH_STRATEGY=concurrent`**,
   so every run-4 batch cell measured the non-default strategy; the shipped
   `coalesced` default was never exercised this run (§1.1).
3. **Decision cache post-fix asymmetry**: with the clamp gone, cache-ON now
   lifts gRPC checks **13.1×** (887 → 11 598/s) but REST checks only +5%
   (753 → 791) — the REST authz path has its own non-cache serialization,
   almost certainly per-request session validation (§3.3).

## 1. ⚠ Run-4 discoveries

### 1.1 Batch cells measured `concurrent`, not the shipped `coalesced` default

`benchmarks/targets/axiam/docker-compose.yml:90` still reads:

```yaml
AXIAM__AUTHZ__BATCH_STRATEGY: "${AXIAM__AUTHZ__BATCH_STRATEGY:-concurrent}"
```

That `:-concurrent` fallback predates the H3 decision that made `coalesced`
the product default, and the runbook
(`claude_dev/run-4-benchmark-instructions.md` §1) explicitly predicted batch
"should be ~5× singles, not ~1.4×". It came out at ~1.3× (batch REST 199
ops/s = 995 checks/s vs 753 singles) — because the harness silently
overrode the product default back to `concurrent`. Confirmation: the
`sens-batch-concurrent` pass is **numerically identical to the matrix**
(198.7 vs 199 REST, 214 vs 175 gRPC — the intended A/B had no B).

Consequences:

- **No run-4 cell measures the shipped batch default.** The G3 settled
  numbers (`coalesced`: 744 REST ops/s = 3 721 checks/s = 4.98× singles;
  866–872 gRPC ops/s) remain the only valid coalesced measurements and stay
  the published verdict for the default.
- The run-4 matrix batch cells are still *valid measurements of
  `concurrent`* (0% err, 3/3 runs, DB pegged at 2.0) — publish them only as
  the labeled non-default strategy.
- **Fixed in this branch**: the compose fallback is now `coalesced` so run 5
  measures the real default (and the sensitivity pass becomes a true A/B).

### 1.2 gRPC prod rate limiter admits 1/60th of its configured limit — units-mismatch bug (root-caused)

`sens-rl-prod` (shipped `internet` posture, single-IP 50-VU generator) shows
the REST limits enforcing **exactly** as configured — and the gRPC limit
enforcing at 1/60th of configured:

| Scenario | Configured limit | Admitted (bench_ok over the whole session) | Verdict |
|---|---|---|---|
| authz_check_rest | 300/min/IP | 1200 ≈ 300/min | ✅ as configured |
| oauth2_client_credentials | 20/min/IP | 75 | ✅ as configured (incl. ramp) |
| token_introspection | 10/min/IP | 27 | ✅ |
| oauth2_password_login | 10/min/IP | 39 | ✅ |
| authz_check_grpc | **100/s** (`GRPC_AUTHZ_PER_SEC`) | **400 ≈ 100/min** | ❌ ×60 too strict |
| authz_batch_grpc | 100/s | 300 ≈ 100/min | ❌ |
| userinfo_grpc | 100/s (server-wide layer) | 400 ≈ 100/min | ❌ (and see below) |

Root cause, found in code while writing this document
(`crates/axiam-api-grpc/src/middleware/rate_limit.rs`): the server wires
**two** cooperating layers —

1. `build_grpc_governor_layer(authz_per_sec)` — the in-memory governor,
   correctly quota'd at `Quota::per_second(authz_per_sec)` (this one was
   already fixed once, see the module's own comments);
2. `GrpcSharedRateLimitLayer::new(db, "grpc_authz", grpc_config.grpc_authz_per_sec, …)`
   — the cross-replica write-behind pre-check, which enforces its `limit`
   over `WINDOW_SECS = 60` (the REST per-**minute** window) but is handed
   the per-**second** number verbatim.

So the shared pre-check clamps to `100 per 60 s` before the correctly
configured governor ever sees the request. The observed ~100 admitted per
60-s window across all three gRPC scenarios matches exactly. Fix is a
one-liner conceptually (`limit × 60` at the call site, or a per-second
window for this layer) plus a regression test asserting admitted ≈
configured under sustained overload. **Task I1 — this blocks advertising
any gRPC prod posture.** Note also the pre-existing design smell it
re-confirms: the layer is server-wide, so `userinfo_grpc` (not an authz
call) is throttled by the *authz* limit even at correct units (I2).

### 1.3 Prod-posture refresh errors (minor)

`token_refresh` under prod limits: 111 045 ok / 2 833 failed (2.4%) at
694/s vs 839 neutralized. Refresh itself is not in the limited set; the
failures are consistent with the harness's periodic re-login hitting the
10/min login bucket mid-run and the affected VUs erroring until re-seeded.
Harness-side follow-up (I13): make the refresh scenario's re-login budget
fit inside the login limit, or label the cell.

## 2. Data-validity notes

### 2.1 Settle gate & refusals — clean across the board

Every session's gate cleared on the first probe (15–16 s wait, threshold
400 ops/s); `settle_timeout` false everywhere; zero refused cells. The H1/H10
machinery finally had nothing to do — consistent with the H2 fix being real.

### 2.2 Invalid cells — 6/48, all explained, none AXIAM's

- KC login p0 **and** p2: only 1/3 valid runs each (single valid runs: 44/s
  p0, 53/s p2). Still memory-instability at the raised 2048 MiB cap — the H7
  diagnosis stands: KC needs ~3.5–4 GiB for sustained hashing load (§2.3).
- Zitadel login p0+p2 (0/3): bcrypt at default cost, p50 ≈ 22 s — known,
  expected, kept-with-label.
- Zitadel refresh p0+p2 (0/3): no `offline_access` flow in the harness —
  known `fallback-op`, excluded from head-to-heads.

AXIAM: **24/24 valid cells** including, for the first time, refresh
(protocol-variant-labeled) and both batch cells (labeled `concurrent`, §1.1).

### 2.3 The 1024→2048 MiB server-cap raise — why, and what it did

Run-3's KC login instability was diagnosed (H7) as OOM-driven. For run 4 the
per-server-container memory cap was raised 1024 → 2048 MiB **for all three
targets equally** (DBs stay at 1024). Measured effect:

- Keycloak's container peaked at **1070 MiB** during the run — i.e. above
  the old 1024 cap; the raise was necessary for KC to survive at all.
  KC p2 login went from 0/3 to 1/3 valid; p0 stayed 1/3. **2048 is still
  not enough for sustained-login KC** — run 5 should use 4096 for login
  cells only (per H7's measured 3.28 GiB peak), labeled.
- AXIAM's server peaked at **172 MiB** (8.4% of its cap) across the entire
  run — the jemalloc fix (H4) is confirmed at matrix scale; the old ~490 MiB
  post-login retention is gone (login cell avg 131 MiB, later cells ~100–110).
- Zitadel peaked at 216 MiB.

Comparability note: run-4 vs run-3 mem columns are not cap-identical;
throughput comparisons are unaffected (no target was memory-starved in
valid run-3 cells except KC login, which was invalid there anyway).

### 2.4 Provenance gap: `build_ref 6875e4b` is not on `main`

Every AXIAM cell records `build_ref 6875e4be733e…`, which is **not an
ancestor of current `origin/main`** (checked 2026-08-02). The run
presumably used an image built from the merged fix branch before a
rebase/squash. Nothing suggests the binary differs materially from main's
content, but A9 provenance discipline says: run 5 must use an image whose
build_ref is a real main commit (I14).

### 2.5 userinfo REST −9% vs run 3

4547 vs 5008 (both tight medians). Not investigated; plausibly the
different mem-cap envelope, image differences, thermal variance (this run
recorded temp_max 96–100 °C on hot cells), or SurrealDB version drift.
Since the cell is DB-pegged in both runs, park unless run 5 confirms a
trend (I15). Its gRPC sibling tripled, so nothing product-alarming.

### 2.6 SDK pass — 33/33 records, but the overhead column is empty

All 11 SDKs (rust, python, typescript, go, java, csharp, php, c, cpp,
kotlin, swift) produced ok records at all three profiles — first time ever,
including first-ever c/cpp/kotlin/swift data. But:

- **No wire-baseline was captured** (`wire p95 = —` everywhere), so the E1.3
  headline metric — p95 overhead vs matched-concurrency wire — could not be
  computed. The SDK table is real but only intra-SDK comparable (I8).
- **csharp `refresh` is a no-op measurement**: p50 1.2 µs, "752 361 rps" —
  the .NET auth helper returns the still-valid cached token without a
  network call; the bench never forces expiry. Data quirk, not an SDK
  defect per se — but the harness must force a real refresh (I9).
- **c and php run at concurrency 1** (single-threaded harnesses; all others
  16) — their lower latencies AND lower throughputs are load-shape, not SDK
  quality. Label or fix (I10).
- **cpp has a bimodal tail**: check p50 3.3 ms / p95 283–336 ms at every
  profile. Signature of a connection being re-established on a subset of
  iterations (curl handle churn / no keep-alive on some path). Worth an SDK
  fix (I11).
- **python check_access p50 ~30 ms** vs 10–11 ms for go/java/rust/etc. at
  the same concurrency — asyncio/GIL overhead, worth a look (I12).
- Client RSS/CPU columns recorded 0.0 — sampler not wired (I8).

Otherwise the cross-language picture is remarkably consistent: login p50
228–256 ms across all concurrency-16 SDKs (server Argon2 dominates),
refresh p50 17.3±0.2 ms across ten SDKs — the server, not the SDKs, sets
the floor. TLS and mTLS profiles cost the SDKs nothing measurable (matches
the server-side p2/p3 parity).

## 3. What the sensitivity passes taught (run-4 edition)

### 3.1 DB-uncapped: the DB is now *the* bottleneck almost everywhere

With the rate-limit write gone, uncapping the DB (2→4 cores) buys much more
than it did in run 3:

| cell (p0) | capped → uncapped | Δ | limiter after |
|---|---|---|---|
| authz_check_rest | 753 → **1434** | **+90%** | still DB-side latency |
| authz_check_grpc | 887 → **1678** | **+89%** | 〃 |
| oauth2_client_credentials | 2727 → **4484** | **+64%** | 〃 |
| token_introspection | 4387 → **6249** | **+42%** | 〃 |
| userinfo | 4547 → **7215** | **+59%** | server approaching cap |
| token_refresh | 839 → **1089** | +30% | 〃 |
| authz_batch_rest/grpc (`concurrent`) | 199/175 → 379/400 | +91–129% | DB |
| jwks / login / userinfo_grpc | ±1% | — | generator / Argon2 / server |

Run-3's headline ratios were ~+37/+18% on checks; post-fix they are ~+90%.
The product message: **AXIAM's ceiling now scales with DB CPU on every
DB-bound path** — good for the "spend hardware on the DB first" guidance,
and it sharpens the case for SurrealDB tuning / read-scaling work (I5).

### 3.2 gRPC vs REST inverted (G8 closed in the right direction)

Run 3: gRPC checks −18% vs REST (603 vs 737). Run 4: **+17.8%** (887 vs
753) with p50 38 vs 74 ms. The old deficit was mostly the tower-wide
rate-limit write (paid by every gRPC call, amortized differently on REST).
userinfo gRPC vs REST: **+179%** (12 665 vs 4 547) at less CPU — gRPC is
now unambiguously the low-latency recommendation for service-mesh authz.
G8 closed.

### 3.3 Decision cache post-fix: gRPC 13.1×, REST +5% — new asymmetry

`sens-cache-on` (K=1-ish bench keyspace, TTL 5 s, `concurrent` batch):

- authz_check_grpc 887 → **11 598/s** (13.1×), DB freed.
- authz_batch_grpc 175 → 8 956 ops/s; batch_rest 199 → 5 240 ops/s
  (~26 000 checks/s) — cache mostly bypasses the batch-strategy question.
- **authz_check_rest 753 → 791 (+5%)** despite p50 halving (73.6 → 31.5).
- token_introspection read −21% in this pass (3 438 vs 4 387) — cache does
  not touch introspection; treat as run-order/DB variance but re-check (I15).

The REST asymmetry hypothesis: the REST authz path authenticates via
**session cookie + CSRF**, which costs a per-request session lookup in
SurrealDB that the decision cache does not (and should not) cover; the gRPC
path authenticates via JWT (no DB). With the decision read cached, REST's
remaining ~1.25 ms/req of serialized DB work is the session read. If
confirmed, a session-validation cache (or JWT-auth parity for the REST
check endpoint) is worth ~10× on REST checks for cache users (I4).
**H5's stays-opt-in decision is unchanged** — the K=1 bench keyspace is
still a ceiling, not an expectation — but the post-fix ceiling is now 13×,
so the "measure your own hit rate" guidance got more valuable, and the
K-sweep should be re-run post-fix before v1.0 (I4).

### 3.4 Native mTLS (p3): parity again, now post-fix

CC 1177 (p2: 1180), check_rest 755 (760), check_grpc 894 (892),
introspection 4313 (4316), userinfo 4421 (4439), userinfo_grpc 12 266
(12 148), jwks 23 333 (23 716), login 67.3 (67), refresh 828 (834).
Client-cert verification remains free on top of TLS 1.3 — the IoT headline
survives the fix. (This pass also validated the two p3 harness fixes on
main: gRPC-over-TLS dialing and CWD-independent cert paths.)

### 3.5 TLS on client_credentials — the plateau narrows the B2 question

Post-fix: p0 2727 → p2 1180 (**−57%**), while introspection loses 1.6%,
refresh 0.6%, checks ±1%, jwks −10%, userinfo −2.4%. New and diagnostic:
the p2 CC cell shows **bottleneck: none** with an eerily flat latency
distribution — p50 42.6 / p95 43.9 / p99 44.8 ms — i.e. every request pays
a near-constant ~43 ms, nothing saturates, and throughput is exactly
50 VUs / 43 ms. That is a *serialization/latency plateau*, not a CPU cost —
and the rate-limit write can no longer be the suspect (it's gone, and p0 CC
runs 2 727/s through the same middleware). Something on the CC-under-TLS
path serializes at ~40 ms. Suspects, in order: per-request client-secret
Argon2/bcrypt verification interacting with TLS-session-bound connection
behavior (are p2 connections being torn down and re-handshaked per token?
`http 2.0` is recorded, but k6's connection reuse per VU under h2 with
short responses deserves a direct look); a lock around the TLS session
cache; the token-persist write path batching differently under h2 framing.
The B2/H6 VU-sweep is finally runnable on this host since nothing else
clamps: sweep VUs 1→100 at p0 and p2 (I3). A constant-per-request cost will
scale throughput linearly with VUs; a serialization point will pin it.

### 3.6 Prod-limit posture (beyond the gRPC bug)

REST enforcement is exact (§1.2 table). Unlimited paths are unaffected
(userinfo 4 572/s, jwks 26 324/s — matrix-identical while the limited
endpoints 429 at ~28 k attempts/s: the 429 path is cheap, no collateral
damage). The maintainer's run-3 observation still stands and now has
sharper numbers behind it: shipped machine-endpoint defaults are 3–5
orders of magnitude below measured capacity (token 20/min vs ~163 000/min
measured; authz 300/min vs ~45 000/min). The public doc's §6 now carries
concrete revised guidance and a proposed-defaults table (see
`claude_dev/improvement-after-run4-benchmark.md` I6/I7 for the code-side
proposal).

## 4. Memory & CPU (run-4, now a first-class publishable story)

Server-container medians across the p0 matrix (avg during measure window;
peak = median across runs of per-run peak):

| target | server avg RSS | server peak RSS | server avg CPU | cap use (mem) |
|---|---|---|---|---|
| **AXIAM** | 97–132 MiB | **≤ 140 MiB** (worst cell: login) | 0.33–1.80 cores | ≤ 7% of 2 GiB |
| Keycloak | 726–900 MiB | **up to 1 070 MiB** | pegged 2.00 in every valid cell | 52% |
| Zitadel | 131–165 MiB | 216 MiB | 0.41–2.00 | 11% |

Whole-stack (server+DB+broker) mem: AXIAM 415–590 MiB (SurrealDB 202–356 +
RabbitMQ ~105–128), Keycloak 814–1129, Zitadel 293–443. Per-request CPU
(whole stack, p0): CC 1.20 vs KC 5.84 vs Zit 8.20 cpu·ms/req; introspection
0.78/1.27/4.00; jwks 0.06/0.44/1.42; userinfo 0.73/0.53/2.88 (KC wins that
one whole-stack; server-only AXIAM 0.25 vs 0.53 — publish both).
Throughput per stack-GiB (p0): jwks 60 723 vs 5 741 vs 7 330; CC 5 988 vs
338 vs 1 218; userinfo 8 948 vs 3 999 vs 2 312.

Honesty notes for the public doc: AXIAM's whole-stack RAM sits between
Zitadel's (smaller) and Keycloak's (larger) because SurrealDB+RabbitMQ ride
along; the *server* comparison and the per-request/thr-per-GiB measures are
where AXIAM's efficiency story is unambiguous, so publish per-container
bars, not just stack totals. Also publish the thermal caveat: laptop hit
96–100 °C on hot cells; mhz_avg varied 3.16–3.87 GHz across cells.

## 5. Work items (evidence-ranked, post-run-4)

Full specs in
[`claude_dev/improvement-after-run4-benchmark.md`](../claude_dev/improvement-after-run4-benchmark.md).

1. **I1 — Fix gRPC shared-limiter ×60 units bug** (§1.2). Product bug,
   blocks gRPC prod posture. + regression test.
2. **I2 — Scope gRPC limiter per-method** (server-wide authz limit throttles
   userinfo/reflection too).
3. **I3 — CC-under-TLS plateau VU sweep** (§3.5) — last open perf mystery.
4. **I4 — REST-check session-read serialization** (§3.3) + post-fix cache
   K-sweep re-run.
5. **I5 — SurrealDB scaling work** (uncapped +42–90% says DB CPU is the
   product's ceiling).
6. **I6/I7 — Rate-limit default revision + sizing docs** (public §6;
   proposed internet-profile machine-endpoint raises).
7. **I8–I12 — SDK harness/SDK fixes**: wire baseline, csharp forced
   refresh, c/php concurrency parity, cpp tail, python asyncio look.
8. **I13 — refresh-under-prod re-login budget** (§1.3).
9. **I14 — provenance: build from main** (§2.4).
10. **I15 — watch items**: userinfo REST −9%, cache-pass introspection −21%.
11. **Harness (done this branch)**: compose batch default → `coalesced`.

## 6. Publishing guidance for the site (run-4 deliverables)

- Publish the run-4 matrix as **the** headline numbers (first uncontaminated
  run): CC 7.7×/6.4×, introspection 2.4×/4.7×, jwks 5.8×/12.6×, userinfo
  1.2×/4.5× (+ AXIAM gRPC userinfo 12.7 k/s), login only-valid-at-both-
  profiles, refresh under protocol-variant label.
- Publish the **resource-usage story with graphs** (server RSS bars, peak
  RSS, cpu·ms/req, thr/GiB) — it is now AXIAM's cleanest differentiator
  (≤140 MiB server vs 1 070 MiB KC at higher throughput).
- Publish batch ONLY as: matrix = labeled `concurrent` (non-default,
  harness pin, now fixed); default's verdict remains G3's coalesced
  4.98× table. Do not chart run-4 batch as the default.
- Publish the gRPC prod-limiter bug openly (found by our own bench, fix
  tracked) — same honesty pattern as the H2 write.
- Do NOT chart: Zitadel login/refresh (gate/fallback), KC login (1/3 valid;
  say why + the 4 GiB plan), cache-ON in head-to-heads (labeled pass only).
- Refresh comparability, cc-token-setup, and protocol-confound (h1→h2)
  labels: carry over verbatim from draft-4 practice.
