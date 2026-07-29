# Improvements After the G-Task Run (2026-07-28) — Phase H Plan

**Created 2026-07-28** from the full G1–G10 task-run results
(`results-20260728.tar.xz`: `results/tasks/g*`, the median-of-3 matrix in
`results/run-*` + `results/report.md`, and the `sens-*` labeled passes).
Every verdict number in §1 was **re-verified against the raw archive**
(each task's `results/tasks/<task>/SUMMARY.md`, the underlying `*.k6.json`
metrics and `*.meta.json` cell metadata) before this plan was finalized.
This document is the executable task list that follows
[`improvement-after-serious-benchmark.md`](improvement-after-serious-benchmark.md)
(the G plan). Task IDs continue as **H1…H10**.

Each task states **which model to use**, chosen as the *cheapest model that
can reliably do the job*: **Sonnet 5** for well-specified, mechanical,
harness/config/docs work with crisp acceptance criteria; **Opus 5** only for
open-ended debugging, design judgment, or security-relevant default changes.
Same discipline as before: feature branch, signed commits, PR per phase,
every Opus task ends by writing its findings into `claude_dev/`.

> **Where the code is (H0 — merge first).** The entire G implementation is
> **not on `main`**. This plan lives on branch
> **`claude/benchmark-results-analysis-hynzr8`**, which carries everything
> in one mergeable unit: the task driver
> (`benchmarks/run-improvement-tasks.sh`) with its four runner fixes
> (telemetry sampler, interrupt-safe teardown, g1-dbdirect credentials +
> probe), the G2 settle gate + rotation + env dump, the G4 refresh fix
> (cookie `Path` root cause), the G5 K-sweep scenario +
> `decision-cache-decision.md` (decision left OPEN behind seven pre-agreed
> criteria), the G7 rate-limit posture presets
> (`AXIAM__RATE_LIMIT__PROFILE`, defaults unchanged) + decision record, the
> G8 ALPN analysis (`HTTP2=false` proven a no-op and turned into a hard
> startup error), the G9 `bench_throttled` classifier — **and** this plan,
> already merged with current `main` (UUIDv7 ids, SDK OIDC/SSO contract
> 1.5). The 2026-07-28 results were collected with this branch's harness.
> **H0: PR and merge this branch before starting any H task**; all file
> references below are to its state. Branches
> `claude/g1-timeline-hanging-l0mqd0` (same code, no plan) and
> `claude/benchmark-results-analysis-f1xn2k` (same plan, no code) are
> **superseded by this one** and should be closed without merging.

---

## §1 What the G run established (verdicts)

| Task | Verdict | Evidence |
|---|---|---|
| G1 transient | **Partially resolved** | Window reproduced: **~6.0 min** at ~44 ops/s (p50 ~1.0 s), DB pinned ~1.05 cores, server idle; sharp cliff recovery to ~715 ops/s between minute 5.4 and 6.0. **8 min of idle does NOT cure it** (first cell after idle: 44.5 ops/s) ⇒ warm-up is **traffic-driven**, not wall-clock. **Survives a server restart** (44.3 ops/s after) ⇒ state is not in the AXIAM process. **RabbitMQ queue depth is 0 for the whole window** ⇒ audit-backlog hypothesis **refuted**. The two remaining probes were faulty: the datastore-restart cell recorded only **1 request** (server needed pool re-signin after the DB restart; cell unusable — its SUMMARY row reads `NA`), and the db-direct probe has per-row container-start overhead (~500 ms flat, 31 rows, no post-window baseline) — inconclusive. |
| G2 settle gate + rotation + meta | **Implemented and working — but the gate does not work against THIS transient** | `settle_wait_secs` (34/35 s), `settle_timeout:false`, `cell_order_index` rotates between runs, `axiam_env` dumped with secrets `<redacted>` — all present in `tasks/g2-verify/run-*` meta.json. The SUMMARY's "❌ no meta.json" is a **checker bug** (it looked in the un-redirected default results dir). Critically: the gate passed in ~34 s while the clamp lasts ~6 min — a 1 rps serial canary sees the ~22 ms serialized unit as a *fast* response; the clamp is only visible **under concurrency** (closed-loop queueing: 50 VUs / 45 ops/s ≈ 1 s p50). Consequence: G3 run-1 cells, G5's K=1/K=100 cells, G8's CC cells and both G4/G8 CC comparison cells all ran inside the window despite gate + warm-up cell. |
| G3 batch A/B | **DECIDED — `coalesced` wins, ship it as default** | On settled cells (runs 2–3): coalesced batch REST 744 ops/s = **3 721 checks/s = 4.98×** singles (748/s); coalesced batch gRPC 866–872 ops/s ≈ **4 330 checks/s**, p95 74 ms (gate ≤2 s ✅). Concurrent: batch REST 200 ops/s = 1 000 checks/s = 1.37× singles, gRPC batch 216 ops/s p95 282 ms. Both beat singles, coalesced wins by 3.7×. |
| G4 refresh harness | **PASS — with a comparability caveat** | AXIAM 910 ops/s, Keycloak 323 ops/s, `bench_fallback == 0`, **1.00 HTTP req/iteration** on both. (AXIAM refresh ≈ ½ × its CC cell — but with 1 req/iter and rotation doing revoke+issue writes, that is real work, not the fallback signature. The in-task CC comparison cell was clamped (46 ops/s) and unusable.) ⚠ Per `refresh-harness-diagnosis.md`: AXIAM deliberately has no ROPC/password grant, so its cell measures **session refresh**, Keycloak's the **OAuth2 refresh grant** — `report.py` needs a `protocol-variant` label and the pair must not be published as a like-for-like head-to-head (→ H7). |
| G5 cache K-sweep | **Contaminated — decision stays OPEN** | Only K=10 000 is trustworthy: cache ON 712 vs OFF 541 ops/s = **+32%**, memory cost ≈ 0 (196 vs 207 MiB). K=1 rows (both 45 ops/s, p50 >1 s) and the K=100 OFF row (60 ops/s, p50 954 ms) ran inside the transient. K=1 truth from run-3 `sens-cache-on`: **3.0–3.15×** (authz REST 2322 vs 737; gRPC 1822 vs 603). The revocation live test was not run. The branch's `decision-cache-decision.md` gates the flip behind seven criteria and surfaced **three cache defects** that must be fixed before any default change (unbounded `order` growth below the cap; process-local cache ⇒ multi-replica revocation ≤ TTL; `invalidate_subject` O(shard) under the global mutex) — all folded into H5. |
| G6 memory retention | **PASS — jemalloc convincingly** | Default malloc: 68 → peak 491 → retained **376 MiB** (+309 over baseline). jemalloc: 69 → peak **126** → retained **86 MiB** (+17). Closes **94%** of the gap (threshold ≥30%) with no throughput caveat recorded. Go: make jemalloc the release default. |
| G8 TLS h1 vs h2 | **Inconclusive for CC — all three CC cells clamped (~45 ops/s)**; valuable side-signal from refresh | The SUMMARY table's "p2-h1 within 15% of p0 ⇒ h2 convicted" reading is wrong — all three cells measured the transient, not TLS. The **refresh** cells in the same session escaped the window and say something new: p0 914 ops/s, **p2-native 893 (−2.3% — no native-TLS penalty)**, p2-h1 (nginx) 443 (−51%, plus **1 059 `bench_failed` ops**). Also: negotiated-protocol capture never landed (column reads `?`). B2 remains open. |
| G7 rate-limit posture | **Implemented on the branch — two residuals** | Shipped defaults byte-for-byte unchanged; relaxation is an opt-in `AXIAM__RATE_LIMIT__PROFILE` = `internet`\|`gateway`\|`mesh` preset touching only machine-to-machine buckets (switches them to `client_id` keying); human endpoints strict per-IP by construction. Residuals per `rate-limit-posture-decision.md`: §7.1 maintainer sign-off, §7.2 a laptop re-measurement of the gateway preset (→ H7). |
| G9 metric coherence | **Mostly done; REST wiring missing** | Root cause written up (`grpc-vs-rest-authz-analysis.md`): the run-3 incoherence was burst-then-storm, not a counting bug. `bench_throttled` + the shared `recordGrpcResult()` classifier are wired into the **gRPC** scenarios and the CC path (145 ok vs 7 145 throttled — legible), but the REST scenarios `token_introspection` and `authz_check_rest` still lack it (confirmed by the g9 run). G9.1 (gRPC −16%) is documented as **accepted overhead** (no cheap fix; gRPC still wins p95). G9.2 (Keycloak login asymmetry) has a written procedure but no diagnostic run yet. |
| G10 SDK benches | **0 / 7 validated — every failure now has a known, small cause** | rust: bench runs but `BENCH_RESOURCE_ID` arrived empty (env plumbing). python: `axiam_sdk` not installed (no local-path install step). typescript: `axiam-sdk` package unresolved (sibling repo not linked). go: `go.mod` needs `go mod tidy`. java: `ClassNotFoundException: io.axiam.bench.Bench` (bench not compiled before `exec:java`). csharp/php: host toolchain missing (honest `pending` records). |
| Pool sensitivity (run-3 leftover, new `inflight-64` pass) | **pool_size=4 = +7% on CC only; in-flight cap 64 changes nothing** | CC 1955 (pool 4) and 1954 (pool 4 + inflight 64) vs 1823 matrix baseline; every other scenario within noise. |

**Cross-cutting finding — the single biggest data-quality fact:** the G2
settle gate as implemented (serial canary, p50 < 100 ms) **cannot detect the
post-seed clamp** and passed ~34 s into a ~6-minute window. Every "first
cell(s) after seed" in the G run is still corrupted, exactly like run 3. The
matrix batch rows (`authz_batch_rest` 41/s, `authz_batch_grpc` invalid 0/3) and
the report's batch verdicts are artifacts of the same contamination and must
not be published as-is.

**Stray data — root cause found in the harness:** the `bench-matrix` recipe
unconditionally re-exports `BENCH_RESULTS_DIR="$PWD/results/run-$i"`
(`benchmarks/justfile:364`, repeat loop), clobbering any redirect a caller
set — which is why `g2-verify`'s mini matrix wrote into the default results
root (its SUMMARY "❌ no meta.json" is that leak, not a missing
implementation) and had to be moved by hand. `results/axiam/p2-tls13/` at
the results root (CC 44.7/s clamped; refresh with the old 2-req/iter
fallback signature) is a stale pre-G4 leftover of the same class — delete
it; it must not enter any report. Fixed by H1.

---

## §2 Phase H0 — data integrity first (in order)

### H1. A settle gate that actually detects the clamp + runner-fault fixes — **Sonnet 5**

*Why Sonnet:* every fix is precisely specified below with a reproducible
failure in hand and the offending lines identified; no open-ended judgment.

*Files (all on this branch):* `benchmarks/justfile` (`bench-matrix`),
`benchmarks/runner/run-benchmark.sh` (`settle_gate()` / `canary_probe()`,
`BENCH_SETTLE_*` tunables), `benchmarks/run-improvement-tasks.sh`,
`benchmarks/docs/methodology.md`, `benchmarks/runner/report.py`.

1. **Settle gate v2 (concurrent canary).** `settle_gate()` today is a
   serial 1 rps `canary_probe()` requiring `BENCH_SETTLE_STABLE_SECS=30`
   consecutive seconds under `BENCH_SETTLE_MAX_MS=100` — measured result:
   it passes ~34 s into the ~6-min clamp, because a lone request against
   the ~22 ms serialized unit *is* fast; the clamp only exists under
   concurrency. Replace the probe with a short concurrent burst (k6,
   `authz_check_rest`, 20 VUs, 15 s — or a curl-parallel equivalent to keep
   k6 out of the gate) and require **probe throughput ≥ 400 ops/s**
   (in-window ~44, settled ~730 — the threshold is far from both) OR p50
   < 150 ms *under those 20 VUs*. Repeat every 30 s until pass; keep the
   existing hard-timeout/`settle_timeout` machinery and meta fields, add
   `settle_probe_thr`. Update methodology §"post-seed settle" with why the
   serial canary was blind.
2. **Fix the `bench-matrix` results-dir clobber (the wrong-directory
   fault):** the repeat loop unconditionally
   `export BENCH_RESULTS_DIR="$PWD/results/run-$i"`, discarding any
   redirect the caller set — this is exactly why `g2-verify`'s mini matrix
   wrote to the results root and its SUMMARY checker (which globs under the
   task's own dir, correctly) reported "no meta.json". Change it to nest:
   `RUN_DIR="${BENCH_RESULTS_DIR:-$PWD/results}/run-$i"`. Then audit every
   `run-improvement-tasks.sh` step for the same pattern and make the script
   fail fast if a cell would write outside `results/tasks/<task-id>/`.
   Re-run `g2-verify` afterwards to get a green SUMMARY (the fields
   themselves are already proven present: `settle_wait_secs` 34/35 s,
   `cell_order_index` rotated, `axiam_env` redacted). Delete the stale
   stray `results/axiam/p2-tls13/` tree.
3. **Fix the g1-isolate datastore-restart probe:** after restarting the DB
   container, wait for the server's pool to re-sign-in (poll `/health` or
   one authenticated request until 200, with a timeout) before measuring,
   and run a full-length cell. The current data point is n=1 request and
   unusable.
4. **Fix the g1-dbdirect probe:** keep one long-lived client (exec into a
   persistent container or a single process with a session), not one
   `docker run` per query; timestamp every row; run the *same* query the
   authz path issues (take it from the D6 report); and always collect a
   post-window baseline segment so in-window vs settled is a within-file
   comparison.
5. `report.py`: refuse (or loudly flag) cells whose meta records
   `settle_timeout: true`.

*Acceptance:* a deliberately-immediate cell after a fresh seed is held by
the gate and, when released, measures ≥ 600 ops/s on `authz_check_rest`;
`settle_wait_secs` lands ≈ the observed window (~5–7 min), not ~34 s; a dry
run of the task script writes nothing outside `results/tasks/`.

### H2. G1 endgame: locate the clamp, rule product defect in or out — **Opus 5**

*Why Opus:* the remaining space is genuinely open-ended (SurrealDB
internals vs data shape), and the outcome is a product-risk verdict the
public doc must carry honestly.

*Files:* `claude_dev/postseed-transient-investigation.md` (extend/finish),
possible follow-ups in `crates/axiam-db` / `benchmarks/targets/axiam/*`.

Evidence inherited (do not re-litigate): traffic-cured ~6-min window with a
sharp cliff (44 → 572 → 715 ops/s in one 36 s step); idle does not cure;
server restart does not cure; AMQP queues flat 0; DB pinned at ~1.0 core;
~22 ms serialized unit. New discriminator from G8: in the same session,
**`token_refresh` ran at 914 ops/s while CC and authz sat clamped at ~45** —
the clamp appears to be *per-table/per-query*, not global.

1. **Per-operation clamp map (cheapest, most informative):** inside a fresh
   window run 20 s micro-cells of authz_check, CC, introspection, userinfo,
   jwks, refresh, login; tabulate which are clamped. Cross-reference each
   op's tables/queries (from the D6 query-pattern report) — the clamped set
   should name the table(s)/index(es) whose post-ingest state is the cause.
2. **Fixed db-direct probe (H1.5)** with the actual clamped query: if a raw
   SurrealDB session shows the same ~22 ms serialized unit in-window,
   AXIAM is exonerated entirely; if not, instrument `axiam-db` (pool
   checkout wait vs query time — the F1 metrics exist) during the window.
3. **Seed-volume dependence:** seed at 10% → does the window scale down?
   (Index/compaction work scales with ingest; a fixed-length warmup does
   not.)
4. **SurrealDB-side observation:** debug logs + `docker stats` of the DB
   during the window; look for compaction/index messages coinciding with
   the recovery cliff; repeat the datastore-restart probe with H1.4's fix —
   if a DB restart *clears* the clamp, the state is rebuilt DB-side memory;
   if it *resets* the 6-min clock, it is recovery/replay work.
5. **Verdict + action.** Traffic-cured means a production instance after a
   bulk import serves degraded traffic until warmed — that is
   **product-relevant** unless the probes prove the trigger is unique to
   the bench's seed shape. If product-relevant: open the issue with the
   reproduction, evaluate mitigations (post-import warm-up driver in the
   server, staged ingest, SurrealDB tuning/version bump — measure, don't
   speculate), and add the honesty line to the public doc. Either way the
   ~22 ms serialized unit must be named, not hand-waved.

*Acceptance:* investigation note finished with a demonstrated trigger
(turning the suspected cause off/down measurably shortens or removes the
window), the per-op clamp map, and a bench-only vs product-relevant verdict
with the follow-up issue/PR filed if product-relevant.

---

## §3 Phase H-A — ship the decided wins (parallel, after H1)

### H3. Flip the batch default to `coalesced` (executes the G3 decision) — **Sonnet 5**

*Files:* `crates/axiam-authz/src/config.rs` (default), config docs +
deployment docs + `benchmarks/PUBLIC_BENCH_ANALYSIS.md` §6 row,
`claude_dev/authz-batch-investigation.md` (append the verdict + G3 table).

The G3 criterion was met by both strategies and `coalesced` wins decisively
(4.98× vs 1.37×; gRPC batch p95 74 ms vs 282 ms). Change the default,
keep `concurrent` selectable, update every doc location that names the
default (config reference, tuning table, public §6), paste the G3 table
into the investigation doc as the closing verdict, and update the config
unit test asserting the default.

*Acceptance:* default is `coalesced`; both strategies still selectable and
tested; all four doc locations agree; investigation doc closed with data.

### H4. jemalloc as the release default (executes the G6 PASS) — **Sonnet 5**

*Files:* `docker/` server Dockerfile, release CI workflow,
`crates/axiam-server/Cargo.toml` (feature default for release profile or
build arg), deployment docs, `claude_dev/memory-retention-experiment.md` §6,
public doc retained-memory caveat.

G6 measured jemalloc closing **94%** of the 309 MiB retention gap (peak also
491 → 126 MiB) at default decay settings. Make the `jemalloc` feature the
default for release container builds (keep a `--no-default-features` escape
hatch documented for musl/platform edge cases), add `MALLOC_CONF` guidance
(explicitly: defaults sufficed; `dirty_decay_ms` tuning not needed), paste
the numbers into the experiment note §6 and the G6 placeholder, and rewrite
the public doc's retained-memory caveat to "fixed since draft 3 (allocator)".

*Acceptance:* released image runs with jemalloc (verifiable via
`MALLOC_CONF=stats_print:true` smoke or the binary's feature list); docs and
both notes updated; CI green.

### H5. Decision-cache ship decision on clean data — **Opus 5**

*Why Opus:* flipping a security-relevant default (authorization staleness)
on evidence that is currently one-third contaminated needs the adversarial
read; the re-measurement itself is prescribed.

*Files:* `crates/axiam-authz` (`decision_cache.rs`, default + docs),
`benchmarks/scenarios/authz_check_rest.js` (`BENCH_AUTHZ_KEYSPACE` exists),
`docs/` security notes, `claude_dev/decision-cache-decision.md` (**exists on
this branch, decision OPEN behind seven pre-agreed criteria — fill it, do
not fork a new note**).

1. **Fix the three cache defects the G5 analysis surfaced — before any
   measurement counts toward the flip** (criterion C5): (a) the `order`
   vector grows unbounded while the working set stays *below*
   `max_entries_per_tenant` (TTL-expired keys leave `entries` but stay in
   `order`; re-access pushes a duplicate) — fix + a regression test for the
   expired-then-reaccessed path; (b) `invalidate_subject` is O(shard) under
   the single global mutex every check needs — bound or shard the lock;
   (c) the cache is process-local: document "revocation immediate" as a
   single-process property and the multi-replica worst case ≤ TTL, next to
   the default.
2. Re-run the K-sweep **on the H1 settled protocol**: cache ON/OFF at
   K ∈ {1, 100, 10 000}, median-of-3, warm-up + gate before every pass.
   Anchors to reconcile: K=1 → 3.0–3.15× (run-3 sens), K=10 000 → +32%
   (G5), K=100 → unknown (contaminated).
3. Add the missing **live-stack revocation test** (the existing integration
   test drives mocks; the decision note carries a manual curl procedure —
   automate it): immediate invalidation on the live stack, and the
   suppressed-event worst case (stale-allow ≤ TTL).
4. Memory bound at K=10 000 with the real entry count inspected (G5's
   server-RSS delta was ≈ 0 — verify the cache actually held 10 000
   entries rather than silently evicting).
5. Walk the note's seven criteria with the clean data and decide default ON
   (TTL 5 s) vs opt-in; if ON: config default, deployment docs, public §6,
   and the ≤TTL staleness statement in the security docs next to the
   default. One combined cache+pool4 labeled cell.

*Acceptance:* cache defects fixed with tests; clean K-sweep table; live
revocation tests pass; the decision note's criteria table is filled and the
verdict recorded; if the default flips, all four doc locations updated.

### H6. B2 endgame v2: settled CC cells + protocol capture — **Opus 5**

*Why Opus:* third attempt at the last-hypothesis TLS debugging; the G8 run
added a genuinely confusing new fact that needs careful discrimination.

*Files:* `benchmarks/scenarios/lib/*` (protocol capture),
`crates/axiam-server/src/tls.rs` (per `b2-tls-h2-investigation.md`),
`docs/security-profiles.md`, `benchmarks/PRIVATE_BENCH_ANALYSIS.md`.

Constraints already proven by this branch's source analysis — do not re-try
them: `AXIAM__SERVER__TLS__HTTP2=false` was a no-op (actix-http
unconditionally prepends `h2` to ALPN) and is now a **hard startup error**;
actix-http exposes **no** `max_concurrent_streams`/window knobs, so "tune
the native h2 listener" is not an available move. If h2 is convicted, the
outcome is the documented-position path (topology artifact: one client
host = few h2 connections; real clients pool connections) unless a
listener-level fix exists outside actix's h2 surface.

1. **Protocol capture first (the `?` column):** record each response's
   negotiated protocol (k6 `res.proto`) into a `bench_http_proto` metric
   and surface it in `report.py`; without it no conviction is valid.
   Optionally log ALPN server-side at debug for cross-checking.
2. **Re-run the three CC cells mid-session on the settled protocol** (p0,
   p2-native, p2-h1), plus refresh at the same three points. Never first
   after seed (H1 gate + a warm-up cell).
3. **Discriminate with the new facts:** matrix CC p2-native = −50%
   (903 vs 1823) but G8 refresh p2-native = **−2.3%** (893 vs 914) — and
   both p2 numbers sit ≈ 900/s. Test the "p2 POST ceiling ≈ 900/s"
   hypothesis directly: run CC at p2 with halved/doubled VUs — a fixed
   per-request TLS cost scales p50 linearly and leaves the ceiling; a
   serialization point holds throughput at ~900 regardless. Compare CPU
   split (server vs k6) between CC-p0 and CC-p2 at equal load.
4. **Make the h1 control trustworthy before using it:** G8's p2-h1 refresh
   lost 51% *and* recorded **1 059 failed ops** — tune the nginx overlay
   (worker count, keepalive_requests, proxy buffering) until its error
   rate is 0 and its p0-equivalent overhead is characterized; only then
   does "h1-over-TLS ≈ p0?" convict or acquit h2.
5. Fix what is found, or write the documented position
   (`docs/security-profiles.md` + public §5) with the evidence. CC and
   refresh must both be re-measured at p2 for the final table;
   introspection/jwks must not regress.

*Acceptance:* p2 CC within ~15% of p0, **or** an evidence-backed accepted
position published; the protocol column renders in the report; the h1
control cell is error-free.

---

## §4 Phase H-B — harness completeness (anytime)

### H7. Metric & small-investigation batch — **Sonnet 5**

*Files:* `benchmarks/scenarios/lib/metrics.js` + the REST scenarios,
`benchmarks/runner/report.py`, `claude_dev/rate-limit-posture-decision.md`,
notes in `claude_dev/` / private doc.

1. **Finish the G9 classifier wiring for REST:** the shared classifier
   (`recordGrpcResult()` + the CC path) exists but `token_introspection`
   and `authz_check_rest` still bypass it (confirmed live by the g9 run:
   `bench_throttled` absent) — add the REST-side equivalent so
   `bench_throttled` exists in every scenario. Acceptance: a `rl=prod`
   mini-pass shows all three probed scenarios reading "purely
   rate-limited" or naming the real failure.
2. **`protocol-variant` comparability label in `report.py`** (G4 caveat):
   AXIAM's refresh cell measures session refresh, Keycloak's the OAuth2
   refresh grant — label the pair so head-to-head tables carry the caveat
   the same way `fallback-op`/`cc-token-setup` are carried today.
3. **G7 residuals:** surface `rate-limit-posture-decision.md` §7.1 to the
   maintainer for sign-off, and run the §7.2 laptop re-measurement of the
   `gateway` preset (one labeled pass), pasting the numbers into the
   decision record and the sizing docs.
4. **G9.2 Keycloak p0-vs-p2 login asymmetry** (52/s valid vs 23/s invalid
   0/3 in the matrix): one diagnostic run each way per the written
   procedure in `grpc-vs-rest-authz-analysis.md`; note the finding in the
   private doc; fairness hygiene only, no KC fixes. (G9.1 is closed —
   documented as accepted overhead.)

### H8. SDK benches round 2 — one fix per language, then the overhead table — **Sonnet 5**

*Why Sonnet:* every failure has a named, mechanical cause from the G10
attempt logs; the spec, harness and TODOs all exist.

*Files:* `benchmarks/sdk/<lang>/*`, `benchmarks/justfile` (recipe line 387
area), sibling `ilpanich/axiam-<lang>-sdk` checkouts, `sdk/collect.py`,
`benchmarks/runner/report.py`, `sdk/README.md`.

Per-language fixes (from `tasks/g10-sdk/*/attempt-*.log`):

| lang | observed failure | fix |
|---|---|---|
| rust | ran, `status:error`: `BENCH_RESOURCE_ID must be a valid UUID (got "")` | the seed env is not reaching the bench: source `benchmarks/.seed/<target>.seed.env` in the sdk-bench recipe/run.sh and assert the UUID non-empty before starting; fail fast with the exact missing var named |
| python | `No module named 'axiam_sdk'` | `run.sh`: create a venv and `pip install -e ../../../../axiam-python-sdk` (sibling checkout) when the module is missing |
| typescript | `Cannot find package 'axiam-sdk'` | `run.sh`: `npm install ../../../../axiam-typescript-sdk` (file: dependency) before running `bench.mjs`; verify the sibling checkout name matches the TODO |
| go | `go: updates to go.mod needed; go mod tidy` | commit the tidied `go.mod`/`go.sum` with the local `replace` to the sibling repo; make `run.sh` run `go mod tidy` defensively |
| java | `ClassNotFoundException: io.axiam.bench.Bench` | build before exec: `mvn -q package` (or `compile`) ahead of `exec:java`, or run `exec:java` with the correct module/classpath per the TODO |
| csharp | honest `pending`: toolchain not installed | preflight that prints the exact host install commands (dotnet SDK version per TODO); document in `sdk/csharp/TODO.md`; optionally provide a container fallback |
| php | honest `pending`: toolchain not installed | same pattern (php + composer, composer path-repo to the sibling SDK) |

Then: each language emits a `status:"ok"` `axiam.sdk-bench/v1` record twice
in a row against a seeded p0 target; `collect.py` ingests all without
warnings; run `just sdk-bench-all` at p0 + p2 and build the E1.3
**overhead-vs-wire-baseline table** into the published report; fix
`sdk/README.md` claims to measured reality (pending languages listed as
pending).

*Acceptance:* ≥ 7 SDKs with validated OK records; the overhead table
renders from real records; README truthful.

### H9. DB-pool default decision (small) — **Sonnet 5**

*Files:* `crates/axiam-db` (default), `claude_dev/db-pool-design.md`
(verdict §), deployment docs.

Evidence: `pool_size=4` = **+7% on client-credentials** (1955 vs 1823),
neutral on everything else; `POOL_MAX_IN_FLIGHT=64` adds nothing on top;
expiry soak already PASSED (run 3). Criterion (pre-agreed): one settled
confirm cell reproduces ≥ +5% on CC with nothing regressed → ship
`pool_size=4` as default (in-flight cap stays 0/unlimited-semantics as
today); otherwise keep 1 and close with the negative result. Update the
design doc's verdict section and the deployment docs either way.

*Acceptance:* confirm cell recorded; default matches the criterion outcome;
docs consistent.

### H10. Run 4 — the publishable matrix + public-doc refresh (E4) — **Sonnet 5**

*Precondition:* H1 (gate), H3 (batch default), H4 (jemalloc image), H5/H6
outcomes landed; H9 decided.

1. Full median-of-3 matrix (all targets, p0 + p2) on the settled protocol
   with cell rotation active — the first matrix whose batch rows are
   trustworthy. Expect: `authz_batch_rest`/`_grpc` valid and ~5× singles
   (coalesced default); AXIAM `token_refresh` valid with 0 fallback,
   published next to Keycloak's cell under the H7 `protocol-variant` label
   (session refresh vs OAuth2 refresh grant — not like-for-like); no
   `fallback-op` rows for AXIAM.
2. Sensitivity passes per the standing list (uncapped DB, rl=prod, p3-mtls
   spot-check, cache/pool per H5/H9 defaults — a labeled OFF pass for
   whichever default flipped, so the delta stays visible).
3. E4: regenerate `PUBLIC_BENCH_ANALYSIS.md` from run-4 medians. Contents
   that must change: batch rows (previously artifacts), refresh row
   (real rotation), B2 verdict per H6, the transient note per H2's verdict
   (honesty section), the SDK overhead table (H8), moved-to-fixed list
   (memory retention, batch, refresh). Keep the honest tone; label the
   laptop as the platform; keep E3 (server-class re-run) tracked.

*Acceptance:* report renders with zero invalid AXIAM cells outside
known-labeled ones; public doc fourth draft published from run-4 medians.

---

## §5 Execution order & model summary

```
H0: PR + merge claude/benchmark-results-analysis-hynzr8 (G implementation + harness + this plan)
H1 (Sonnet) ─→ H2 (Opus)                       # gate first, then the transient verdict
H3, H4 (Sonnet, parallel — no new data needed) # decided wins, ship now
H5 (Opus, needs H1), H6 (Opus, needs H1)       # the two open performance verdicts
H7, H8 (Sonnet, anytime), H9 (Sonnet, needs H1)
H10 run 4 + E4 last (needs H1, H3, H4; folds in H5/H6/H9 outcomes)
```

| Task | Model | Rationale for the cheaper/costlier choice |
|---|---|---|
| H1 settle gate v2 + runner faults | **Sonnet 5** | every fix specified against a reproduced failure |
| H2 transient endgame | **Opus 5** | open-ended DB-internals debugging + product-risk verdict |
| H3 batch default → coalesced | **Sonnet 5** | pre-agreed criterion already met by the data |
| H4 jemalloc release default | **Sonnet 5** | threshold met 94% vs 30%; mechanical build/CI/docs |
| H5 cache ship decision | **Opus 5** | security-default flip on partially-contaminated evidence |
| H6 B2 endgame v2 | **Opus 5** | last-hypothesis TLS debugging, new confounding fact |
| H7 metrics + small investigations | **Sonnet 5** | bounded diagnostics with written-answer deliverables |
| H8 SDK benches round 2 | **Sonnet 5** | per-language causes identified; recipe-driven repair |
| H9 pool default | **Sonnet 5** | one confirm cell + pre-agreed ≥5% criterion |
| H10 run 4 + E4 | **Sonnet 5** | protocol execution + doc regeneration |

**MVP gate:** H1–H6 (H6 may close as a documented position). H7–H9
non-blocking. H10 required for the public page, not the server MVP.

---

## §6 Execution record (2026-07-29)

All ten H tasks are closed. One line per task, outcome as recorded when the
task closed:

| Task | Outcome |
|---|---|
| H0 | Pre-merged — the plan's own branch (code + harness + this plan) merged to `main` before H1 started, per this document's header. |
| H1 | Done — settle gate v2 (concurrent burst probe) ships; the `bench-matrix` results-dir clobber and both g1-isolate/g1-dbdirect probe faults fixed; `report.py` refuses `settle_timeout: true` cells. |
| H2 | Root cause found — **product-relevant**. The "post-seed transient" is a permanent synchronous `RateLimitShared` datastore write in front of six endpoints, not a seeding effect; reproduced on a second host at a different (higher) unit cost; a maintainer issue is written up (`postseed-transient-investigation.md` §7.1) and not yet fixed. |
| H3 | Shipped — `AXIAM__AUTHZ__BATCH_STRATEGY` default flipped to `coalesced` (4.98× singles on settled REST, ≈4 330 checks/s on gRPC); `concurrent` stays selectable; all four doc locations updated. |
| H4 | Shipped — jemalloc is the release-container default allocator; closes 94% of the measured memory-retention gap with no throughput cost. |
| H5 | Opt-in verdict — decision cache stays `false` by default. Three surfaced defects fixed first; the clean K=10 000 measurement (+32%, 1.32×) does not clear the seven-criteria ship bar (≥1.5×); recorded with full criteria table in `decision-cache-decision.md`. |
| H6 | Closed — acquitted. HTTP/2 exonerated by direct connection-census measurement; TLS 1.3 priced at 10–13%, not 50%; the h1 control made trustworthy (nginx upstream keepalive fix); `bench_http_proto` column ships in `report.py`; the p0 `Secure`-cookie harness bug fixed along the way. The `client_credentials`-specific penalty itself stays an open question (documented, not hand-waved). |
| H7 | Done — REST-side `bench_throttled` classifier wired (parity with gRPC/CC); `protocol-variant` comparability label ships in `report.py`; the `gateway` rate-limit preset measured live (single-client_id admitted rate 8.5%→96.6%/3.7%→100%/68.9%→100% on token/introspect/authz); the Keycloak p0-vs-p2 login asymmetry diagnosed as an OOM-sizing artifact, not a TLS defect. |
| H8 | 6/7 validated — rust, python, typescript, go, java, php SDK benches run end-to-end against a seeded target with real `ok` records; csharp stays an honest `pending` (host toolchain not installed); the E1.3 overhead table renders from real data in `report.py`. |
| H9 | Negative-closed. The pre-agreed confirm cell was unsatisfiable on a clamped host (needs a settled CC cell); closed on independent mechanism evidence instead (`pool_size` 1→8 moved authz throughput by 0 ops/s at 1 or 20 VUs) — default stays `pool_size=1`, no code change needed. |
| H10 | This run — **harness validated (with one real bug found and fixed), publishable matrix deferred to a fast-datastore host (E3/the G-box) with reasons.** A bounded, single-repeat matrix (not median-of-3), `BENCH_SETTLE_TIMEOUT_SECS=120`, ran on the sandbox host for axiam+keycloak × p0/p2 (34 cells; `results/tasks/h10-validate/`). Found and fixed a real `report.py` bug along the way: the settle gate stamps `settle_timeout` session-wide (by design), so `report.py` was refusing every AXIAM cell in a clamped session outright — including `jwks_fetch`/`userinfo`/`userinfo_grpc`/`token_refresh`, none of which touch the `RateLimitShared` endpoints H2 mapped, and none of which H2 ever measured as slow. Added `CLAMP_SENSITIVE_SCENARIOS` + `settle_timeout_applies()` so the refusal (and its host_flags badge) applies only to the seven scenarios that actually route through a wrapped endpoint. After the fix: those seven AXIAM cells (+batch) are refused loudly with `settle_timeout: true`; the other AXIAM cells render valid data with the `http` protocol column populated (excluded only for the separate, expected `repeat=1` "need >=2 valid runs" reason); the refresh row carries the `protocol-variant` label for both AXIAM and Keycloak; the SDK section renders from H8's records; no AXIAM row reads `fallback-op`. Separately, Keycloak OOM'd at the harness's standard 1024m cap on this more resource-constrained sandbox (known mechanism, per H7); worked around with a labeled `BENCH_MEM=4096m` override for Keycloak only, not a tracked-default change. `benchmarks/PUBLIC_BENCH_ANALYSIS.md` was rewritten as the fourth draft on the G-box's existing run-3 numbers (labeled by platform throughout), since the sandbox host cannot itself produce a publishable level for any `RateLimitShared`-wrapped endpoint (H2). A consistency pass reconciled `PRIVATE_BENCH_ANALYSIS.md` and `docs/methodology.md` with the H2–H9 verdicts that had not yet been folded back into either document.

**Carried forward, not closed by Phase H:** the maintainer issue from H2 §7.1
(get the shared rate-limit write off the synchronous path; fix
`GET /api/v1/users`'s rate-limit bucket); the open `client_credentials`-vs-`token_introspection`
TLS-penalty asymmetry from H6; the G-box recovery-cliff mechanism from H2 §6;
a true run-4 median-of-3 matrix on a host where the shared write is cheap
(E3); a repeated (median-of-3) SDK overhead table; the csharp SDK bench;
`sdk/collect.py`'s `server_p95()` wire-baseline lookup doesn't know about a
task's `results/tasks/<id>/run-N/` nesting, so an SDK overhead render
against a nested tree (as H10's validation run did) degrades every
overhead-vs-wire cell to `—` instead of computing it — cosmetic only (H8's
own flat-root render, `benchmarks/results/sdk-report.md`, is unaffected),
but worth fixing before a run-4-class matrix repeats the SDK table under
the same nested layout.
