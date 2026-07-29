# G9 small investigations — written answers

Covers all three G9 sub-items from `claude_dev/improvement-after-serious-benchmark.md`
§G9. Item 1 (gRPC-vs-REST authz gap) is the deep dive; item 2 (Keycloak
p0/p2 login asymmetry) is diagnostic-procedure-only per the plan (no
Keycloak changes); item 3 (`sens-rl-prod` metric coherence) documents the
root cause and the code fix already landed in
`benchmarks/scenarios/lib/metrics.js`.

No live stack/docker/k6 was available while writing this — every claim below
is either **proven by source** (cites a `file:line`) or explicitly flagged
**hypothesis** with the cheapest experiment that would settle it on the
maintainer's laptop. No benchmark number below is fabricated; all of them are
quoted from `claude_dev/improvement-after-serious-benchmark.md` §G9 or
`benchmarks/PRIVATE_BENCH_ANALYSIS.md` (run 3).

---

## 1. gRPC single-check −18% vs REST, despite better latency

### 1.1 The numbers and the arithmetic

Run 3, clean cells (median-of-3, both p0-plaintext and p2-tls13 profiles —
i.e. not the post-seed transient documented in §1 of
`PRIVATE_BENCH_ANALYSIS.md`, and not a TLS artifact since the gap is
identical at p2):

| | REST (`authz_check_rest`) | gRPC (`authz_check_grpc`) |
|---|---|---|
| throughput | **737 req/s** | **603 req/s** (−18%) |
| p50 latency | 68 ms | **62 ms** (better) |
| p95 latency | 85 ms | **75 ms** (better) |

Both handlers route through the identical
`AuthorizationEngine::check_access` path (D-08; see 1.3 below), at 50 VUs,
`ramping-vus` closed-loop executor, in both scenario files
(`benchmarks/scenarios/authz_check_rest.js`,
`benchmarks/scenarios/authz_check_grpc.js`).

In a closed-loop model with `N` VUs each doing one blocking call per
iteration, throughput ≈ `N / mean_latency` — so the *lower* a cell's latency,
the *higher* its throughput should be, all else equal. Checking that
explicitly (per-VU latency, not p50/p95, but p50 is the closest proxy
available from the summary):

- REST: `50 / 0.068 s ≈ 735.3 req/s` — measured **737**. Fully explained by
  latency alone (within noise).
- gRPC: `50 / 0.062 s ≈ 806.5 req/s` — measured **603**. A **~203 req/s
  (≈25%) shortfall** the latency number does not explain.

This is the strongest clue in the dataset: REST's closed loop is behaving
exactly as the arithmetic predicts (the server has enough headroom that 50
VUs simply queue up behind REST's own service time), while gRPC's *achieved*
concurrency is behaving as if something is holding it below 50 effective
VUs, even though its per-call service time is the better of the two.

A second, independent data point corroborates this pattern on a completely
different gRPC code path. `PRIVATE_BENCH_ANALYSIS.md` §1.3 records the one
clean batch cell in the whole run-3 archive: `authz_batch_grpc` (coalesced
strategy) at **852.7 batches/s, p50 49 ms, p95 75 ms**. Arithmetic:
`50 / 0.049 s ≈ 1020.4` predicted vs **852.7** measured — a **~16%
shortfall**, same direction as the single-check gap, on a scenario whose
per-item server-side cost (5 items/batch, engine-coalesced lookups) is
structurally unrelated to `check_access`'s per-call UUID-parsing/validation
cost (see 1.3). No clean REST-batch cell exists to cross-check against (§1.3:
"no clean cell at all for: batch REST"), so this is corroborating, not
conclusive — but the fact that *two* independent gRPC scenarios both
under-realize their own latency-implied throughput, while the one clean REST
cell (single-check) does not, points at something systemic to the gRPC path
through the harness rather than something specific to `check_access`'s body.

A third data point, from `PRIVATE_BENCH_ANALYSIS.md` §3.1 (DB-uncapped
sensitivity pass — same scenarios, SurrealDB's CPU cap raised from 2 to 4
cores):

| cell | capped → uncapped | limiter after uncapping |
|---|---|---|
| `authz_check_rest` | 737 → **1013** (+37%) | "nothing pegged; round-trip latency" |
| `authz_check_grpc` | 603 → **712** (+18%) | "same" |

If the capped-run ceiling for both cells were *purely* SurrealDB-CPU-bound
(SurrealDB is pegged at ~2.0/2 cores in both, per §3.2), giving both more DB
capacity should relieve both proportionally. REST gets +37%, gRPC only
+18%, and the *relative* gap actually widens (gRPC/REST = 81.8% capped vs
70.3% uncapped). That is consistent with gRPC's capped-run ceiling having an
extra, non-DB-CPU component that additional database capacity does not
relieve — again pointing away from a purely server-CPU/DB explanation and
toward something in the gRPC call path (server-side concurrency plumbing, or
harness-side) that caps effective parallelism independent of backend
capacity.

### 1.2 What's proven vs what's a hypothesis

**Proven by source** (read, not run):

- **Both handlers hit the same core logic.** `check_access` (REST:
  `crates/axiam-api-rest/src/handlers/authz_check.rs:151-193`; gRPC:
  `crates/axiam-api-grpc/src/services/authorization.rs:79-126`) both end in
  `engine.check_access(&access_req)` / `authz.check_access(&access_req)` —
  same `AuthorizationEngine`, same SurrealDB queries. The per-call *body*
  work differs, but the DB work does not.
- **gRPC does strictly more per-call CPU work than REST for identity
  handling.** `check_access` in
  `crates/axiam-api-grpc/src/services/authorization.rs:85-109` performs
  **five** `Uuid::parse_str`-style parses (`claims_tenant_id`,
  `claims_subject_id`, `body_tenant_id`, `body_subject_id`, `resource_id` —
  lines 91, 92, 97, 98, 115) plus two `if` cross-validation branches
  (SEC-003/T-27-12, lines 100-109) comparing body-supplied
  `tenant_id`/`subject_id` against the verified JWT claims. REST's
  `CheckAccessBody` (`crates/axiam-api-rest/src/handlers/authz_check.rs:36-49`)
  declares `resource_id: Uuid` and `subject_id: Option<Uuid>` as *typed*
  fields — serde/actix's JSON extractor parses them directly, and REST does
  not even accept a body `tenant_id` (it is always `user.tenant_id` from the
  auth extractor, per the module doc at lines 8-10), so there is no
  cross-validation branch to run at all. This is real, but it is in-process,
  synchronous, sub-microsecond-scale CPU work on UUIDs — implausible as the
  source of a ~25% throughput gap when both paths are dominated by
  millisecond-scale DB round trips, and **it argues the wrong direction for
  latency**: gRPC does more of this work per call yet still shows the lower
  p50/p95. If this were the dominant cost, gRPC's latency should be *worse*,
  not better. Ranked low.
- **REST pays an extra async DB round trip per call that gRPC does not.**
  `AuthenticatedUser::from_request`
  (`crates/axiam-api-rest/src/extractors/auth.rs:87-113`) calls
  `validator.is_session_active(user.tenant_id, user.session_id).await`
  (lines 106-109) — a `SurrealSessionRepository::get_by_id` lookup
  (`crates/axiam-api-rest/src/extractors/auth.rs:47-58`) on **every**
  REST request, to support session revocation (REQ-7/D-15). gRPC's
  `AuthInterceptor::call` (`crates/axiam-api-grpc/src/middleware/auth.rs:33-47`)
  only runs `validate_access_token` (signature/expiry check, no DB call) —
  it never checks session liveness. This is a real, proven asymmetry and a
  plausible, sufficient explanation for REST's *higher* latency (68 vs
  62 ms p50) — but it makes gRPC's *lower* throughput more surprising, not
  less: gRPC does less server-side work per call (no session DB round trip)
  and still achieves fewer requests/second than the closed-loop arithmetic
  predicts.
- **The shared rate-limit DB round trip is symmetric, not a cause.** Both
  protocols pay one DB round trip here: REST's
  `/api/v1/authz/check` route is wrapped with `RateLimitShared` (
  `crates/axiam-api-rest/src/server.rs:770-777`); gRPC's
  `GrpcSharedRateLimitLayer` is applied server-wide, unconditionally, to
  every gRPC call (`crates/axiam-api-grpc/src/server.rs:153`,
  `.layer(shared_rate_limit_layer)`, backed by
  `SurrealRateLimitBucketRepository::increment` —
  `crates/axiam-api-grpc/src/middleware/rate_limit.rs:369-406`). Checked
  and ruled out as an asymmetry.
- **No gRPC-specific concurrency cap found in the transport config.**
  `crates/axiam-api-grpc/src/server.rs:152` sets
  `.concurrency_limit_per_connection(256)` — 50 VUs each hold one
  connection (`authz_check_grpc.js` connects once per VU, `__ITER === 0`
  guard), so this cap is nowhere near binding.
- **The one shared mutex in the authz path (`axiam-authz`'s decision
  cache, `crates/axiam-authz/src/decision_cache.rs:119`,
  `Mutex<HashMap<Uuid, TenantShard>>`) is identical for both protocols.**
  `crates/axiam-server/src/main.rs` constructs the engine (and clones the
  same `Arc`-wrapped decision cache into it) separately for REST, gRPC, and
  the AMQP consumer (three `AuthorizationEngine::new` call sites, lines
  ~745, ~769, ~935), but all clone the *same* underlying cache instance —
  so lock contention, if any, is shared equally and cannot explain a
  REST-vs-gRPC asymmetry. (Also: this run predates G5's cache-ON
  ship-decision, §3.2 of the private doc, so the cache was very likely off
  for this cell regardless.)
- **The rate limiters were not binding during this measurement.** The
  default (`RateLimitProfile::Internet`, which presets nothing —
  `crates/axiam-api-rest/src/config/rate_limit.rs:182`)
  caps `authz_check_per_min` at 300/min = 5 req/s per IP (default value,
  `crates/axiam-api-rest/src/config/rate_limit.rs:295`) — far below 603-737
  req/s, so this cell's profile must have used a raised limit (matching
  §3.7 of the private doc, which separately documents the *default* posture
  clamping both protocols to near-zero — that is item 3 of this note, not
  item 1). Confirms the 603/737 numbers reflect real capacity, not a rate
  limiter.

**Hypothesis, not proven** (needs the live discriminator experiment below):

- **The k6 gRPC client (`k6/net/grpc`) achieves less effective concurrency
  than its 50 configured VUs, for reasons internal to the harness rather
  than the server.** I read `benchmarks/scenarios/authz_check_grpc.js`
  closely for a timing-window bug (the obvious "hidden overhead" story: some
  JS-side cost happening *outside* the `Date.now()` window used for
  `bench_op_latency_ms`) and did **not** find one: `start = Date.now()` is
  captured immediately before `client.invoke(...)`, and the request-object
  literal, `check()`, and `m.grpcStatus.add()` (lines in
  `authz_check_grpc.js`'s `default()`) all execute *before*
  `m.latency.add(Date.now() - start)` is called — so all of that JS-side
  work is *inside* the timed window, not hidden from it. That rules out the
  simplest version of "the harness undercounts gRPC latency." What remains
  unruled-out is a *structural* difference between k6's `http` module (whose
  `res.timings.duration` is computed natively in k6's Go core, purely for
  the wire round trip) and k6's `grpc` module (whose `invoke()` does
  protobuf marshal/unmarshal and Go↔JS value-boundary crossing — evidenced
  by the D11 comments already in the file about `res.status` arriving as "a
  wrapped Go value" needing `Number()` coercion) possibly costing real
  wall-clock time on the k6 process itself (CPU competing with the other 49
  VUs) in a way that raises the *iteration* cycle time without raising the
  *invoke()* time proportionally as much as it raises REST's simpler
  JSON-string-building iteration cycle. This is plausible but **not
  established** — it would need to show up as elevated k6-generator CPU
  usage during the gRPC cell relative to the REST cell, which was not
  captured in run 3.

### 1.3 Cheapest discriminator experiment (laptop)

In order of cost, cheapest first:

1. **Free — re-read existing k6 summaries, if the raw JSON from run 3 is
   still on disk.** k6 always emits `iteration_duration` (built-in, no code
   change) alongside `bench_op_latency_ms` (custom). If
   `iteration_duration`'s p50 on the gRPC cell is meaningfully larger than
   `bench_op_latency_ms`'s p50 (while REST's `iteration_duration` ≈
   `bench_op_latency_ms`), that proves per-iteration harness overhead is
   inflating gRPC's *effective* per-VU cycle time beyond what
   `bench_op_latency_ms` reports — confirming the harness-side hypothesis
   without touching any code. (Not checked here: no raw run-3 `.k6.json`
   files exist in this checkout — `benchmarks/results/` is empty except for
   `.gitkeep`.)
2. **Cheap — re-run `authz_check_grpc.js` and `authz_check_rest.js` at 2×
   VUs (100) on the same target.** If the server is the ceiling, gRPC's
   throughput should barely move (queueing would show up as materially
   worse p50/p95). If the harness/client is the ceiling, gRPC throughput
   should scale up noticeably toward the 2× line while REST, already
   latency-bound, scales closer to linearly too (both should move — the
   diagnostic signal is *relative* movement, not absolute).
3. **Cheap — watch server-side CPU (`docker stats`) during each cell at the
   same 50 VUs.** If the AXIAM server / SurrealDB containers are visibly
   *less* utilized during the gRPC cell than the REST cell (both cells run
   the same core `check_access`, so utilization should track req/s if the
   server is the bottleneck), that is direct evidence of spare server
   capacity going unused — i.e. the ceiling is upstream of the server.
4. **Moderate — instrument k6-generator CPU** (`k6 run --out ...` or OS-level
   `top`/`pidstat` on the k6 process) during both cells. If the k6 process's
   own CPU is pegged during the gRPC cell but not the REST cell at the same
   VU count, that directly confirms the load generator itself (not the
   server) is the effective bottleneck for gRPC.

### 1.4 Recommendation

**Document as accepted overhead; no server-side code change.** No candidate
found by reading `axiam-api-grpc`/`axiam-api-rest` source explains a
throughput deficit that: (a) is not visible in latency, (b) recurs on an
unrelated gRPC scenario (batch) with a different per-item cost profile, and
(c) does not scale proportionally with database capacity the way the REST
ceiling does. Everything server-side that *is* proven true (gRPC's extra
UUID parsing/cross-validation, REST's extra session-revocation DB call)
points the wrong direction for explaining the gap, or is already fully
accounted for by the (favorable, for gRPC) latency numbers. The private
doc's original guess — "suspect per-call UUID-parse/validation or tonic
service overhead" (`PRIVATE_BENCH_ANALYSIS.md` §3.6) — is not well
supported once the arithmetic is checked explicitly: that overhead would
have to show up in the *timed* portion of the request and make gRPC's
latency *worse*, and it doesn't.

There is no ≤20-line fix here because there is no *proven* single cause to
fix — the strongest lead (harness/client-side effective concurrency) is a
hypothesis that needs the live discriminator experiments in §1.3 to become
actionable, and none of them are code changes to the two lib files this
task owns. **gRPC still wins on the metric that matters more for a
service-mesh authz check under load — p95 latency (75 vs 85 ms) — so this
does not block anything; carry it forward as a documented, low-priority
open item** (as `PRIVATE_BENCH_ANALYSIS.md` §3.6 already does), now with the
closed-loop arithmetic and the batch/DB-uncapped corroboration recorded so a
future pass has a concrete starting point instead of re-deriving it.

---

## 2. Keycloak p0-vs-p2 login asymmetry (diagnostic procedure only — no KC changes)

**The numbers** (`PRIVATE_BENCH_ANALYSIS.md` §2.4, same image digest both
profiles): p0 (plaintext) login **52 req/s, p50 919 ms, p95 1070 ms**, 2/3
runs valid, ±7.8% spread (the widest in the matrix). p2 (TLS 1.3) login
**stuck at 23 req/s, p95 2249 ms, 0/3 runs valid.** This is fairness
hygiene, not an AXIAM defect — Keycloak is not code this repo owns or ships,
and the task explicitly scopes this to "note the finding," not fix it.

### Diagnostic procedure for the laptop

1. **Rule out run-order / warm-up interaction first.** §2.4 already floats
   "possibly KC hashing-iteration warm-up interacting with run order." Run
   the p0 and p2 Keycloak login cells **back-to-back, twice, in both
   orders** (p0→p2 then p2→p0), each preceded by an explicit idle/settle
   window (mirrors G1/G2's post-seed-transient countermeasure — same
   family of "first cell after some event is unrepresentative" bug). If p2
   recovers when it's *not* first, or degrades when p0 runs right before
   it, that points at a KC-internal warm-up/JIT/hashing-cache effect keyed
   off request order, not TLS itself.
2. **Isolate TLS overhead from Keycloak's own request handling.** Capture
   `docker stats` for the Keycloak container during both cells. If KC's CPU
   is pegged in p2 but not p0 at the same 50 VUs, TLS handshake/cipher cost
   on Keycloak's own listener is plausible (Keycloak terminates its own TLS
   in this profile, per the target's compose config — confirm which
   listener p2 actually points at before concluding this). If KC's CPU is
   *not* pegged in p2, the bottleneck is elsewhere (network path, bench
   client TLS overhead, or the "0/3 valid" gate itself masking a
   measurement problem rather than a real slowdown).
3. **Check what "0/3 valid" actually means for p2.** A run being
   gate-invalid (per `report.py`'s validity gate) is a different finding
   than "p2 is 2.3× slower" — confirm whether the p2 cell fails the
   error-rate/p95 threshold gate outright (making the 23 req/s / p95 2249 ms
   figures themselves suspect, e.g. built on a smaller effective sample)
   or passes the gate but is legitimately slower. This changes whether the
   right next step is "investigate KC+TLS performance" or "fix the p2
   Keycloak login cell's validity first."
4. **One repro run each way is sufficient per the G9 spec** ("one
   diagnostic run each way") — this is bounded, not an open-ended KC
   performance investigation. Record whatever the run shows (even
   inconclusive) in the private doc under §2.4 and move on; G9's
   acceptance criterion for this item is the written note, not a fix.

No Keycloak configuration, Dockerfile, or benchmark target file was touched
for this item, per the task's "no KC fixes" instruction.

---

## 3. `sens-rl-prod` metric coherence (fixed in `benchmarks/scenarios/lib/metrics.js`)

### 3.1 The incoherence

Run 3's production-rate-limit pass (`sens-rl-prod`) showed, e.g.,
`authz_check_rest` at **`bench_ok` rate 13.6/s while `bench_error_rate` was
1.00**, and `authz_check_grpc` at **84/s while `bench_error_rate` was
0.95**. Read at face value this looks contradictory: a cell that is
"~100% errors" advertising a double-digit "ops/s" of apparent success.

### 3.2 Root cause (traced by reading `doOp()` and every scenario that
produced these numbers)

**`doOp()` was not the bug.** `benchmarks/scenarios/lib/metrics.js`'s
`doOp()` only ever calls `m.ok.add(1)` when `check()` reports the response
status equals `built.expect` (200/201 in every scenario/adapter — verified
by grepping every `expect:` in `benchmarks/scenarios/lib/targets.js` and
every scenario file; none sets `expect: 429`, so a 429 can never be
misclassified as a pass via `built.expect`). `authz_check_rest.js` and the
two REST scenarios the `g9-rlprod` harness task exercises
(`oauth2_client_credentials.js`, `token_introspection.js`) all call `doOp()`
normally with `expect: 200`. Ruled out: "a scenario counting a 429 as a
success because `built.expect` matched" (candidate cause from the task
brief) — does not happen anywhere in this codebase.

**The gRPC scenarios (`authz_check_grpc.js`, `authz_batch_grpc.js`,
`userinfo_grpc.js`, `zitadel_userinfo_grpc.js`) do bypass `doOp()`** and
hand-roll their own `ok`/`failed`/`errorRate`/`latency` recording (they
must — k6's `grpc.Client.invoke()` has a different response shape and
timing model than `http.request()`, there is no way to feed it through the
HTTP-shaped `doOp()`). This is a real maintenance smell (confirmed by
reading all four files), but their hand-rolled logic mirrors `doOp()`'s
classify-then-count semantics correctly: `ok` is only ever incremented when
`res.status === grpc.StatusOK`, matching REST's behavior. It is not, by
itself, the source of the incoherence.

**The actual mechanism (established by reading `crates/axiam-api-rest`'s
and `crates/axiam-api-grpc`'s rate limiters, both `governor`-based token
buckets):** the default (`RateLimitProfile::Internet`) posture's
`authz_check_per_min = 300` (5 req/s per IP,
`crates/axiam-api-rest/src/config/rate_limit.rs:295`) and the analogous
gRPC `grpc_authz_per_sec` default both use `governor::Quota::per_second`
with `burst_size` equal to the configured rate
(`crates/axiam-api-grpc/src/middleware/rate_limit.rs:183-184`) — meaning
the bucket starts **full** and admits a burst of real, legitimate successes
at test start (during k6's ramp-up), before settling into steady-state
rejections once the burst is drained. Those burst successes are genuine
200s/OK responses — `bench_ok` is correct to count them. Meanwhile, k6's
`ramping-vus` executor is a **closed loop with no backoff**: every VU that
gets a 429/`RESOURCE_EXHAUSTED` retries again immediately on its next
iteration, so the *total* iteration volume over the test's duration becomes
very large (thousands of near-instant rejections), while the real successes
stay small and roughly bounded by the configured rate. `bench_error_rate`
(a `Rate` = failures / total iterations) correctly reflects that the vast
majority of that huge iteration count failed — round to "1.00" at 2 decimal
places even when not exactly 100%. `bench_ok`'s reported "rate" (a k6
`Counter`'s built-in `count / total_test_duration_seconds`, which is what
`run-improvement-tasks.sh`'s `k6_stat()` reads via `m["bench_ok"]["rate"]`)
is *also* correct — it is the small burst-phase success count spread over
the whole test's wall-clock duration, which is a genuine (if small)
admitted-throughput number, not noise. **Both numbers are individually
correct; the incoherence is a legibility gap, not a counting bug**: nothing
in the summary told a reader whether "1.00 error rate" meant "some other
bug, unrelated to rate limiting, is also broken" or "this is entirely
expected 429 rejection." (This reading is corroborated by
`PRIVATE_BENCH_ANALYSIS.md` §3.7, which independently describes the same
posture pass in aggregate terms — "CC 0.9/s, introspection 0.4/s, ~100%
429s" — the same shape of number, at the same order of magnitude, for a
sibling endpoint.)

### 3.3 The fix

`benchmarks/scenarios/lib/metrics.js`:

- Added `m.throttled = new Counter('bench_throttled')`. `doOp()` now adds to
  it (in addition to, not instead of, `m.failed`/`bench_error_rate` — this
  is additive, changes no existing metric's semantics or any downstream
  consumer) whenever a failed check's response status is exactly `429`.
- Added an exported `recordGrpcResult(res, latencyMs, ok)` helper that
  centralizes the *same* classify-and-count logic (including the
  `bench_throttled` split, keyed off gRPC status `8` =
  `RESOURCE_EXHAUSTED`, the status `too_many_requests_response()` in
  `crates/axiam-api-grpc/src/middleware/rate_limit.rs:222-224` returns) so
  the gRPC scenarios can adopt it with a one-line change instead of
  re-diverging their hand-rolled copy further.

With this in place, a `sens-rl-prod`-style summary shows, per scenario:
`bench_ok` (genuine successes), `bench_throttled` (expected control-plane
rejections), and `bench_failed - bench_throttled` (anything else) — so a
100%-ish-error cell where `bench_failed ≈ bench_throttled` reads as "the
posture is working as configured," and a cell where `bench_failed` is
larger than `bench_throttled` reads as "something else is also broken,"
without requiring the reader to reconcile a `Counter`-rate against a
`Rate`-fraction computed over different denominators in their head.

**`node --check` passed** on both owned files
(`benchmarks/scenarios/lib/metrics.js`, `benchmarks/scenarios/lib/targets.js`
— the latter required no change for this task).

### 3.4 Remaining edit needed (NOT made — outside this task's file ownership)

> **Update (H7, 2026-07-29):** this edit has since landed —
> `authz_check_grpc.js`, `authz_batch_grpc.js`, and `userinfo_grpc.js` all
> call `recordGrpcResult()` today (confirmed by reading each file's
> `default()`), so `bench_throttled` is present on the gRPC cells too, per
> §3.5's acceptance line. H7's task brief (re)stated this edit as still
> outstanding for the **REST** side (`token_introspection.js`/
> `authz_check_rest.js`) — but per §3.5 below, those two scenarios already go
> through `doOp()`, which already classifies `bench_throttled`, so no source
> edit was needed there either; H7 confirmed this live instead (a `rl=prod`
> mini-pass, `p0-plaintext`, single source IP, 20–70 s windows):
> `oauth2_client_credentials` 58 ok / **627 throttled** / 0 other,
> `token_introspection` 28 ok / **726 throttled** / 0 other,
> `authz_check_rest` 471 ok / **213 throttled** / 0 other — all three read
> "purely rate-limited" (`other failures ≈ 0`), the exact acceptance bar
> `run-improvement-tasks.sh`'s `g9-rlprod` table checks for. The paragraph
> below is kept as the historical record of what this edit looked like when
> it was still open.

`recordGrpcResult()` is exported and ready, but **not wired into any
scenario** — `authz_check_grpc.js`, `authz_batch_grpc.js`, and
`userinfo_grpc.js` are not owned by this change (only
`benchmarks/scenarios/lib/metrics.js`, `benchmarks/scenarios/lib/targets.js`,
and this document are). The exact remaining edit, per file, is to replace
the final six lines of each scenario's `default()` with a single call.
For example, in `authz_check_grpc.js`:

```diff
- const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
- m.grpcStatus.add(res && res.status != null ? Number(res.status) : -1);
- m.latency.add(Date.now() - start);
- m.errorRate.add(!ok);
- if (ok) m.ok.add(1); else m.failed.add(1);
+ const ok = check(res, { 'grpc status OK': (r) => r && r.status === grpc.StatusOK });
+ recordGrpcResult(res, Date.now() - start, ok);
```

(plus `import { m, recordGrpcResult } from './lib/metrics.js';` — currently
`import { m } from './lib/metrics.js';`). The same substitution applies to
`authz_batch_grpc.js` and `userinfo_grpc.js`. `zitadel_userinfo_grpc.js`
targets Zitadel, not AXIAM's rate limiter, so wiring it in is optional
(harmless either way — `bench_throttled` would simply stay at 0 for that
scenario, matching today's behavior of `bench_failed` alone).

### 3.5 Acceptance harness alignment

`g9-rlprod` (`benchmarks/run-improvement-tasks.sh:697-727`) exercises
`oauth2_client_credentials`, `token_introspection`, `authz_check_rest` — all
three go through `doOp()`, so this task's `bench_throttled` fix is live for
all three without any further edit. It reads `thr = m["bench_ok"]["rate"]`
and `err = m["bench_error_rate"]["value"]` from the k6 summary and prints
✅ when `err < 0.99 or thr < 1.0`. That check is unaffected by this change
(it does not read `bench_throttled`) — this task did not touch
`run-improvement-tasks.sh` (not owned) — but the underlying numbers it reads
were already correct per the trace above; whether a given cell's `thr`
lands under `1.0` depends on the configured rate limit and load profile
(G7's territory), not on anything fixed here. What this task adds is the
diagnostic signal (`bench_throttled`) that makes *why* a cell landed where
it did legible from the summary, which was the actual ask ("so a posture
pass is diagnosable").
