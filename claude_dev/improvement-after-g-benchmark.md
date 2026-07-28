# Improvements After the G-Task Run (2026-07-28) — Phase H Plan

**Created 2026-07-28** from the full G1–G10 task-run results
(`results-20260728.tar.xz`: `results/tasks/g*`, the median-of-3 matrix in
`results/run-*` + `results/report.md`, and the `sens-*` labeled passes).
This document is the executable task list that follows
[`improvement-after-serious-benchmark.md`](improvement-after-serious-benchmark.md)
(the G plan). Task IDs continue as **H1…H10**.

Each task states **which model to use**, chosen as the *cheapest model that
can reliably do the job*: **Sonnet 5** for well-specified, mechanical,
harness/config/docs work with crisp acceptance criteria; **Opus 5** only for
open-ended debugging, design judgment, or security-relevant default changes.
Same discipline as before: feature branch, signed commits, PR per phase,
every Opus task ends by writing its findings into `claude_dev/`.

---

## §1 What the G run established (verdicts)

| Task | Verdict | Evidence |
|---|---|---|
| G1 transient | **Partially resolved** | Window reproduced: **~6.0 min** at ~44 ops/s (p50 ~1.0 s), DB pinned ~1.05 cores, server idle; sharp cliff recovery to ~715 ops/s between minute 5.4 and 6.0. **8 min of idle does NOT cure it** (first cell after idle: 44.5 ops/s) ⇒ warm-up is **traffic-driven**, not wall-clock. **Survives a server restart** (44.3 ops/s after) ⇒ state is not in the AXIAM process. **RabbitMQ queue depth is 0 for the whole window** ⇒ audit-backlog hypothesis **refuted**. The two remaining probes were faulty: the datastore-restart cell recorded only **1 request** (server needed pool re-signin after the DB restart; cell unusable), and the db-direct probe has per-row container-start overhead (~500 ms flat, 31 rows, no post-window baseline) — inconclusive. |
| G2 settle gate + rotation + meta | **Implemented and working — but the gate does not work against THIS transient** | `settle_wait_secs` (34/35 s), `settle_timeout:false`, `cell_order_index` rotates between runs, `axiam_env` dumped with secrets `<redacted>` — all present in `tasks/g2-verify/run-*` meta.json. The SUMMARY's "❌ no meta.json" is a **checker bug** (it looked in the un-redirected default results dir). Critically: the gate passed in ~34 s while the clamp lasts ~6 min — a 1 rps serial canary sees the ~22 ms serialized unit as a *fast* response; the clamp is only visible **under concurrency** (closed-loop queueing: 50 VUs / 45 ops/s ≈ 1 s p50). Consequence: G3 run-1 cells, G5's K=1/K=100 cells, G8's CC cells and both G4/G8 CC comparison cells all ran inside the window despite gate + warm-up cell. |
| G3 batch A/B | **DECIDED — `coalesced` wins, ship it as default** | On settled cells (runs 2–3): coalesced batch REST 744 ops/s = **3 721 checks/s = 4.98×** singles (748/s); coalesced batch gRPC 866–872 ops/s ≈ **4 330 checks/s**, p95 74 ms (gate ≤2 s ✅). Concurrent: batch REST 200 ops/s = 1 000 checks/s = 1.37× singles, gRPC batch 216 ops/s p95 282 ms. Both beat singles, coalesced wins by 3.7×. |
| G4 refresh harness | **PASS** | AXIAM 910 ops/s, Keycloak 323 ops/s, `bench_fallback == 0`, **1.00 HTTP req/iteration** on both. (AXIAM refresh ≈ ½ × its CC cell — but with 1 req/iter and rotation doing revoke+issue writes, that is real work, not the fallback signature. The in-task CC comparison cell was clamped (46 ops/s) and unusable; compare against the matrix CC 1823/s.) |
| G5 cache K-sweep | **Contaminated — decision deferred** | Only K=10 000 is trustworthy: cache ON 712 vs OFF 541 ops/s = **+32%**, memory cost ≈ 0 (196 vs 207 MiB). K=1 rows (both 45 ops/s, p50 >1 s) and the K=100 OFF row (60 ops/s, p50 954 ms) ran inside the transient. K=1 truth from run-3 `sens-cache-on`: **3.0–3.15×** (authz REST 2322 vs 737; gRPC 1822 vs 603). The revocation live test was not run. |
| G6 memory retention | **PASS — jemalloc convincingly** | Default malloc: 68 → peak 491 → retained **376 MiB** (+309 over baseline). jemalloc: 69 → peak **126** → retained **86 MiB** (+17). Closes **94%** of the gap (threshold ≥30%) with no throughput caveat recorded. Go: make jemalloc the release default. |
| G8 TLS h1 vs h2 | **Inconclusive for CC — all three CC cells clamped (~45 ops/s)**; valuable side-signal from refresh | The SUMMARY table's "p2-h1 within 15% of p0 ⇒ h2 convicted" reading is wrong — all three cells measured the transient, not TLS. The **refresh** cells in the same session escaped the window and say something new: p0 914 ops/s, **p2-native 893 (−2.3% — no native-TLS penalty)**, p2-h1 (nginx) 443 (−51%, plus ~2 100 request failures). Also: negotiated-protocol capture never landed (column reads `?`). B2 remains open. |
| G9 metric coherence | **1 of 3 sub-tasks done** | `bench_throttled` verdict landed for `oauth2_client_credentials` (145 ok vs 7 145 throttled — "purely rate-limited" now legible); `token_introspection` and `authz_check_rest` are **not wired** to the shared classifier. G9.1 (gRPC −16%) and G9.2 (Keycloak p2 login asymmetry) were not attempted. |
| G10 SDK benches | **0 / 7 validated — every failure now has a known, small cause** | rust: bench runs but `BENCH_RESOURCE_ID` arrived empty (env plumbing). python: `axiam_sdk` not installed (no local-path install step). typescript: `axiam-sdk` package unresolved (sibling repo not linked). go: `go.mod` needs `go mod tidy`. java: `ClassNotFoundException: io.axiam.bench.Bench` (bench not compiled before `exec:java`). csharp/php: host toolchain missing (honest `pending` records). |
| Pool sensitivity (run-3 leftover, new `inflight-64` pass) | **pool_size=4 = +7% on CC only; in-flight cap 64 changes nothing** | CC 1955 (pool 4) and 1954 (pool 4 + inflight 64) vs 1823 matrix baseline; every other scenario within noise. |

**Cross-cutting finding — the single biggest data-quality fact:** the G2
settle gate as implemented (serial canary, p50 < 100 ms) **cannot detect the
post-seed clamp** and passed ~34 s into a ~6-minute window. Every "first
cell(s) after seed" in the G run is still corrupted, exactly like run 3. The
matrix batch rows (`authz_batch_rest` 41/s, `authz_batch_grpc` invalid 0/3) and
the report's batch verdicts are artifacts of the same contamination and must
not be published as-is.

**Stray data:** `results/axiam/p2-tls13/` at the results root (CC 44.7/s
clamped; refresh with the old 2-req/iter fallback signature) is a stale
pre-G4 leftover that leaked to the default results dir — delete it; it must
not enter any report.

---

## §2 Phase H0 — data integrity first (in order)

### H1. A settle gate that actually detects the clamp + runner-fault fixes — **Sonnet 5**

*Why Sonnet:* every fix is precisely specified below with a reproducible
failure in hand; no open-ended judgment.

*Files:* `benchmarks/run-improvement-tasks.sh` (**note: this script exists
only on the laptop today — commit it to `benchmarks/` first, it is the
artifact several of these fixes patch**), `benchmarks/runner/run-benchmark.sh`,
`benchmarks/runner/seed.sh`, `benchmarks/docs/methodology.md`,
`benchmarks/runner/report.py`.

1. **Settle gate v2 (concurrent canary).** Replace the 1 rps serial canary:
   after seed, run a short concurrent probe (k6, `authz_check_rest`, 20 VUs,
   15 s) and require **probe throughput ≥ 400 ops/s** (in-window it reads
   ~44; settled it reads ~730 — the threshold sits far from both) OR p50
   < 150 ms *under those 20 VUs*. Repeat every 30 s until pass; hard timeout
   12 min → warn + `settle_timeout: true` in meta. Record
   `settle_probe_thr` and total `settle_wait_secs` in every cell's meta.
   Keep the old fields. Document in methodology §"post-seed settle" why the
   serial canary was blind (the ~22 ms serialized unit is only visible under
   concurrency).
2. **Fix the g2-verify SUMMARY checker** to look for meta.json under the
   task's own `BENCH_RESULTS_DIR` (it declared "mini matrix did not run"
   while `tasks/g2-verify/run-*/…/meta.json` exist and carry all three new
   fields).
3. **Fix the results-dir leak** that produced `results/axiam/p2-tls13/` at
   the results root: audit every step of `run-improvement-tasks.sh` for
   cells that run without `BENCH_RESULTS_DIR` exported (the G8 step-3 CC/
   refresh re-measure is the known offender pattern); make the script fail
   fast if a cell would write outside `results/tasks/<task-id>/`. Delete the
   stale stray tree.
4. **Fix the g1-isolate datastore-restart probe:** after restarting the DB
   container, wait for the server's pool to re-sign-in (poll `/health` or
   one authenticated request until 200, with a timeout) before measuring,
   and run a full-length cell. The current data point is n=1 request and
   unusable.
5. **Fix the g1-dbdirect probe:** keep one long-lived client (exec into a
   persistent container or a single process with a session), not one
   `docker run` per query; timestamp every row; run the *same* query the
   authz path issues (take it from the D6 report); and always collect a
   post-window baseline segment so in-window vs settled is a within-file
   comparison.
6. `report.py`: refuse (or loudly flag) cells whose meta records
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

*Files:* `crates/axiam-authz` (default + docs), `benchmarks/scenarios/`
(K-sweep variant already exists), `docs/` security notes,
`claude_dev/decision-cache-decision.md` (new).

1. Re-run the K-sweep **on the H1 settled protocol**: cache ON/OFF at
   K ∈ {1, 100, 10 000}, median-of-3, warm-up + gate before every pass.
   Current anchors to reconcile: K=1 → 3.0–3.15× (run-3 sens), K=10 000 →
   +32% (G5), K=100 → unknown (contaminated).
2. Run the revocation integration test against the live stack (immediate
   invalidation) and the suppressed-event worst case (stale-allow ≤ TTL).
3. Memory bound at K=10 000 with the real entry count inspected (G5's
   server-RSS delta was ≈ 0 — verify the cache actually held 10 000
   entries rather than silently evicting).
4. Decide default ON (TTL 5 s) vs opt-in; write the decision note with the
   full sweep table and the security rationale; if ON: config default,
   deployment docs, public §6, and the ≤TTL staleness statement in the
   security docs next to the default. One combined cache+pool4 labeled cell.

*Acceptance:* clean K-sweep table; revocation tests pass against the live
stack; decision note committed; if the default flips, all four doc
locations updated.

### H6. B2 endgame v2: settled CC cells + protocol capture — **Opus 5**

*Why Opus:* third attempt at the last-hypothesis TLS debugging; the G8 run
added a genuinely confusing new fact that needs careful discrimination.

*Files:* `benchmarks/scenarios/lib/*` (protocol capture),
`crates/axiam-server` (listener/h2 tuning if convicted),
`docs/security-profiles.md`, `benchmarks/PRIVATE_BENCH_ANALYSIS.md`.

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
   lost 51% *and* threw ~2 100 request errors — tune the nginx overlay
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

*Files:* `benchmarks/scenarios/lib/metrics.js` + the two scenarios,
`benchmarks/runner/report.py`, notes in `claude_dev/` / private doc.

1. **Finish the G9 classifier wiring:** `token_introspection` and
   `authz_check_rest` must route failures through the shared
   ok/throttled/other classifier so `bench_throttled` exists in every
   scenario (audit all scenarios while there — the fix is one shared
   helper). Acceptance: a `rl=prod` mini-pass shows all three probed
   scenarios reading "purely rate-limited" or naming the real failure.
2. **G9.1 gRPC single-check −16% vs REST:** one profiling pass over the
   tonic path (UUID parse, metadata auth, per-call span); fix if ≤ ~20
   lines, else document as accepted overhead (gRPC still wins p95).
3. **G9.2 Keycloak p0-vs-p2 login asymmetry** (52/s valid vs 23/s invalid
   0/3 in the matrix): one diagnostic run each way, note the finding in
   the private doc; fairness hygiene only, no KC fixes.

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
   (coalesced default); AXIAM `token_refresh` a real head-to-head vs
   Keycloak's 379/s (G4); no `fallback-op` rows for AXIAM.
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
