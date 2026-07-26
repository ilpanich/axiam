# Improvements After the Serious Benchmark (run 3) — Pre-MVP Plan

**Created 2026-07-26** from the run-3 analysis
([`benchmarks/PRIVATE_BENCH_ANALYSIS.md`](../benchmarks/PRIVATE_BENCH_ANALYSIS.md),
run-3 rewrite). This document is the executable task list for the **final
performance/correctness improvements before the MVP**. It is intentionally
incomplete in one place: **§G6 will be integrated with the output of the
memory-allocation experiment** (`benchmarks/run-memory-experiment.sh`, the
B1/D9 A/B) once the maintainer runs it on the laptop — fill in the numbers
and the jemalloc go/no-go there, then finalize the plan.

Each task states **which model to use** — chosen as the *cheapest model that
can reliably do the job*: **Sonnet 5** for well-specified, mechanical,
harness/config/docs work with crisp acceptance criteria; **Opus 5** only for
open-ended debugging, design judgment, or security-sensitive server
internals. Same discipline as previous plans: feature branch, signed
commits, PR per phase, every Opus task ends by writing its findings into
`claude_dev/` so the next agent inherits evidence, not just a diff.

**Context recap (what run 3 established):**

- A **post-seed serialized-DB transient** (~5–7 min, ~45 req/s clamp,
  SurrealDB pinned at ~1 core, ~22 ms serialized unit) corrupted every
  "first cell after seed" in every run so far — including **all batch
  cells** ever measured and the run-3 **B2 h1-isolation cell**. The one
  clean batch cell (coalesced, gRPC, cell 4 of its pass) measured
  **852 batches/s ≈ 4 264 checks/s** — batch is *fine*, the data was bad.
- **B2 (TLS −50.5% on client_credentials)** is still unexplained; h2
  multiplexing remains the only live hypothesis; the conviction cell must
  be re-run on a settled stack.
- **A8 residual:** AXIAM's own `token_refresh` cell still measures a CC
  fallback (100% `bench_fallback`; Keycloak's fix works, ours doesn't).
- **D7 decision cache** measured **3.0–3.15×** on authz checks; default
  is still `false`.
- **F2/F3 pool:** +7% on token issuance at `pool_size=4`, neutral
  elsewhere; expiry soak PASSED.
- **D3 native mTLS:** parity with p2 across the board — done, publishable.
- **rl=prod pass:** shipped per-IP defaults flatten any single-IP fleet —
  by design, but the defaults are wrong for M2M topologies (maintainer
  confirmed); public doc §6 now carries recommended values that must stay
  in sync with code.
- **SDK benches (E1):** still zero validated runs — the harness exists.
- Memory retention after login bursts (~360 MiB) reproduced on alpha19;
  experiment script now exists.

---

## Phase G0 — Unblock the data (do these first, in order)

### G1. Root-cause the post-seed serialized-DB transient — **Opus 5**

*Why Opus:* open-ended systems debugging across SurrealDB internals, the
AMQP audit pipeline, and the DB pool — no recipe exists, and the outcome
decides whether this is a **product cold-start defect** or a bench-only
artifact.

*Files:* investigation note `claude_dev/postseed-transient-investigation.md`
(new, required); possible changes in `crates/axiam-db`, `crates/axiam-amqp`,
`benchmarks/targets/axiam/*`; no speculative server changes without data.

1. **Reproduce on the laptop:** `just target=axiam bench-up bench-seed`,
   then immediately drive `authz_check_rest` in a loop while sampling
   `docker stats` for SurrealDB/server/RabbitMQ at 1 s cadence for 10 min.
   Expected: ~45 req/s and DB ~1.0 core for ~5–7 min, then recovery to
   ~740 req/s / 2.0 cores. Record exact duration and the recovery shape.
2. Bisect the trigger, cheapest probes first:
   - **Seed-volume dependence:** seed with 10% of the data — does the
     window shrink? (compaction/index hypothesis scales with ingest).
   - **Audit-backlog hypothesis:** watch RabbitMQ queue depths
     (`rabbitmqctl list_queues`) during the window; if the audit consumer
     is draining a seed backlog with serialized DB writes, the queue depth
     curve will match the window. Also try `AXIAM__AMQP` audit consumer
     disabled for one probe run.
   - **DB-side hypothesis:** run the same seed against a standalone
     SurrealDB (no AXIAM) and issue the authz queries directly (surreal
     sql) — if the clamp reproduces without AXIAM, it's SurrealKV
     background work; check SurrealDB debug logs for
     compaction/index-build messages during the window.
   - **Server-side hypothesis:** restart only `bench-axiam-server` (not
     the DB) mid-window — if the clamp survives a server restart it's not
     the server's warm-up/pool.
3. Classify the outcome, and act accordingly:
   - **Bench-only** (e.g. seed-shaped ingest burst): fix belongs in G2
     (settle gate) + a documented explanation. Done.
   - **Product-relevant** (cold-start / bulk-import serialization): open a
     dedicated issue with the reproduction, decide mitigation (e.g.
     post-import settle, SurrealDB tuning, staged audit-drain rate) as its
     own PR, and add a line to the public doc's honesty section.
4. Whatever the outcome: write the note with the measured window duration,
   trigger, and mechanism. The ~22 ms serialized unit must be explained,
   not hand-waved.

*Acceptance:* the note exists with a demonstrated trigger (turning the
suspected cause off/down measurably shortens or removes the window), and a
bench-only vs product-relevant verdict with evidence.

### G2. Harness countermeasures + re-measure the corrupted cells — **Sonnet 5**

*Why Sonnet:* well-specified runner/report edits plus a prescribed set of
re-runs; G1 supplies the understanding.

*Files:* `benchmarks/runner/run-benchmark.sh`, `benchmarks/runner/seed.sh`,
`benchmarks/runner/report.py`, `benchmarks/justfile`,
`benchmarks/docs/methodology.md`.

1. **Settle gate:** after `bench-seed`, before the first cell, poll a cheap
   canary (one `authz_check_rest` request/s): require N consecutive seconds
   (default 30) of p50 under a threshold (default 100 ms) OR a hard settle
   timeout (default 10 min, then warn + proceed with a
   `settle_timeout: true` meta flag). Record `settle_wait_secs` in every
   cell's meta.json.
2. **Cell-order rotation:** rotate the scenario list per run index
   (run-1 starts at scenario 1, run-2 at scenario 2, …) so no scenario is
   systematically first; record `cell_order_index` in meta. (Median-of-3
   then also averages out any residual position effect.)
3. **Self-describing labeled passes:** dump every `AXIAM__*` env var the
   compose received (values of the pass-through knobs: pool, batch
   strategy, cache, rl posture, hashes) into meta.json per cell. report.py
   shows them in the labeled-pass sections.
4. **Re-measure the corrupted cells** on the settled protocol
   (median-of-3): the four authz batch/single cells × both
   `AXIAM__AUTHZ__BATCH_STRATEGY` values (the D10 A/B, finally clean), and
   the **B2 h1 cell** (`BENCH_NGINX_CONF=tls13-h1.conf`, p2,
   client_credentials + token_refresh) run **mid-session, never first**.
5. Update methodology.md (§ new: "post-seed settle"), and re-generate the
   report.

*Acceptance:* a deliberately-immediate first cell shows the settle gate
delaying it; meta.json carries `settle_wait_secs`, `cell_order_index`, and
the `AXIAM__*` knob dump; clean batch A/B and h1 numbers exist in
`results/`; report renders them.

### G3. Decide D10 from clean data (batch default) — **Sonnet 5**

*Why Sonnet:* once G2's A/B exists this is a config-default decision with a
pre-agreed criterion, plus doc updates. (If the clean data contradicts
itself — e.g. coalesced wins gRPC but loses REST — escalate to Opus 5 for
the judgment call instead of guessing.)

*Files:* `crates/axiam-authz/src/config.rs` (default), docs,
`claude_dev/authz-batch-investigation.md` (append the verdict).

Criterion (from the original D1/D10 acceptance): batch checks/s must
exceed single checks/s on the same protocol; `authz_batch_grpc` must pass
the 2 s p95 gate. Ship whichever strategy wins as the default (early
evidence: `coalesced` at 852 batches/s), keep the other selectable, update
the config docs + the public doc §6 row, and record before/after cells in
the PR.

*Acceptance:* clean-cell table in the PR; default matches the winner;
docs/tuning table updated consistently.

---

## Phase G-A — Product fixes (parallel after G0)

### G4. AXIAM `token_refresh` harness fix (A8 residual) — **Sonnet 5**

*Why Sonnet:* scoped harness debugging with a working reference
implementation (Keycloak's path) beside it.

*Files:* `benchmarks/scenarios/lib/auth.js`, `lib/targets.js`,
`scenarios/token_refresh.js`; seed if needed.

1. Against a live seeded AXIAM (alpha19+), execute `mintUserToken()`'s
   login-first path manually (curl) and find where the refresh credential
   is lost: is `axiam_refresh` still the cookie name? Is it `HttpOnly` +
   `Secure` such that the k6 cookie-jar read misses it at p0? Does the
   `/oauth2/token` refresh grant expect the cookie or a body param?
2. Fix the extraction (shared helper with `loginSession()`), keep the
   fallback tag for genuinely impossible targets, and confirm on one local
   cell that `bench_fallback == 0` and iterations do **one** HTTP request.
3. While in there: implement Zitadel `offline_access` refresh if its OIDC
   bridge allows it in ≤ ~50 lines; otherwise document why not (one
   paragraph in methodology) and keep the tag.

*Acceptance:* AXIAM refresh cell valid (0 fallback, single-request
iterations, throughput NOT ≈ ½ × CC); report includes it in head-to-heads
against Keycloak's 379/s.

### G5. Decision cache: ship-decision + realistic-hit-rate evidence — **Opus 5**

*Why Opus:* flipping a security-relevant default (authorization staleness)
needs the risk analysis written by the model that can weigh it, and the
bench evidence needs an adversarial eye (the 3× was measured at a
bench-friendly hit rate).

*Files:* `crates/axiam-authz` (default + docs), `benchmarks/scenarios/`
(one new variant), `docs/` security notes,
`claude_dev/decision-cache-decision.md` (new).

1. Add a **low-hit-rate bench variant**: parameterize `authz_check_rest`
   to spread checks across K distinct (subject, resource) pairs (seed
   supports multiple resources; extend minimally if not). Measure cache-ON
   at K ∈ {1 (today's cell), 100, 10 000} to bound the win as hit rate
   drops, and measure the memory cost at 10 000 entries.
2. Re-verify the two safety properties on the live stack: revocation
   enforced immediately via invalidation event (existing integration test,
   run against the bench stack), and worst-case stale-allow ≤ TTL when the
   event is suppressed.
3. Decide: default ON (proposed: `true`, TTL 5 s) or stay opt-in. Write
   the decision note with the K-sweep numbers and the security rationale;
   if ON, update the config default, deployment docs, public doc §6, and
   add the ≤TTL staleness statement to the security docs *next to the
   default*, not in a footnote.
4. One combined cell: cache ON + `pool_size=4` (the F3 leftover), labeled.

*Acceptance:* K-sweep table exists; decision note committed; if default
flips, all four doc locations updated and the revocation test passes
against the live stack.

### G6. Memory retention: run the experiment, decide jemalloc — **Sonnet 5** *(⚠ to be integrated with the experiment output)*

*Why Sonnet:* the experiment is fully scripted
(`benchmarks/run-memory-experiment.sh`); this task is running it and
acting on a pre-agreed threshold. **Escalate to Opus 5 only if the data is
confusing** (e.g. jemalloc changes throughput > 5%, or variant A's
retention doesn't reproduce).

1. On the laptop: `cd benchmarks && ./run-memory-experiment.sh` (defaults:
   both variants, 10-min post-burst watch). If variant B's default decay
   doesn't close the gap, one more run with
   `D9_MALLOC_CONF="dirty_decay_ms:1000,muzzy_decay_ms:0"` per the
   experiment note §5.
2. Paste `results/d9-summary.md` into
   `claude_dev/memory-retention-experiment.md` §6 **and into this section**,
   replacing this placeholder.
3. On PASS (≥30% of the ~360 MiB gap closed, throughput within ±5%):
   follow-up PR making `jemalloc` a default feature of the release build
   (Dockerfile + CI), with `MALLOC_CONF` guidance in deploy docs. On FAIL:
   documented negative result, close D9, and open a scoped issue to find
   the in-process retainer instead (that outcome would mean the memory is
   *held*, not fragmented — a different bug class).

> **⟨PLACEHOLDER — integrate `results/d9-summary.md` here when the
> experiment has run.⟩**

*Acceptance:* numbers in both docs; a PR or a documented "not worth it";
public doc's retained-memory caveat updated either way.

### G7. Rate-limit defaults & the published tuning guide — **Opus 5**

*Why Opus:* changing shipped security defaults (anti-abuse limits) is a
security decision with real abuse-vector tradeoffs; the mechanical parts
are small.

*Files:* `crates/axiam-api-rest/src/config/rate_limit.rs`, docs,
`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §6 (keep in sync),
`docs/` deployment guide.

1. Evaluate, per endpoint class, whether the shipped default should move
   for MVP given the run-3 evidence (a 2-core server sustains ~1 800
   issuances/s; the default caps a *client* at 20/min): proposal to
   assess — token/introspect/revoke default `key=client_id` with higher
   per-client defaults (e.g. token 600/min/client), keeping strict per-IP
   defaults on the human endpoints (login/register/reset/MFA) unchanged.
   Consider a documented "gateway/mesh" profile (env preset) instead of
   changing defaults, if changing them weakens the internet-facing
   posture.
2. Whatever is decided: the deployment docs gain a "sizing your limits"
   page whose numbers are generated from the same table as the public doc
   §6 (single source of truth — a small shared markdown include or a
   lint that diffs them).
3. Add a startup log line summarizing the active rate-limit posture
   (key mode + per-min values) so operators can see what they shipped.

*Acceptance:* decision recorded (changed defaults or a preset + rationale);
docs and public §6 agree; unit tests updated for any new defaults; startup
log shows the posture.

---

## Phase G-B — Instrumentation-grade leftovers

### G8. B2 endgame: convict or acquit h2 — **Opus 5**

*Why Opus:* two runs of fixes haven't moved it; this is the last
hypothesis, and the fix (if any) touches the TLS/actix listener.

*Files:* `crates/axiam-server` (listener/h2 settings),
`benchmarks/scenarios/lib/*`, `docs/security-profiles.md`,
`benchmarks/PRIVATE_BENCH_ANALYSIS.md` (root-cause note).

Precondition: G2's clean h1 cell. Then:
1. If h1-over-TLS ≈ p0 (within ~15%): h2 convicted. Measure the k6-side
   `http_version` tag to confirm, then tune the native listener —
   `max_concurrent_streams`, initial stream/connection window sizes on
   actix's h2 — and re-measure; if no setting recovers the throughput,
   write the documented position: benchmark-topology artifact (one client
   host = few h2 connections), real SDK/mesh clients pool connections;
   include an `AXIAM__SERVER__TLS__HTTP2=false`-equivalent guidance only
   if it actually works (run 2 showed actix re-adds h2 — verify or remove
   that knob from docs).
2. If h1-over-TLS is ALSO −50%: h2 acquitted; instrument per-request
   server-side timing at p2 vs p0 (span around TLS read/write vs handler)
   and follow the data; check kTLS/record-size/buffer sizing.
3. Either way: CC and refresh (fixed by G4) re-measured at p2; the public
   doc §5 TLS paragraph rewritten with the verdict.

*Acceptance:* p2 client_credentials within ~15% of p0, **or** a written,
evidence-backed acceptance note in `docs/security-profiles.md` + public
doc; introspection/jwks/authz not regressed.

### G9. Small investigations (batch of three) — **Sonnet 5**

*Why Sonnet:* each is a bounded diagnostic with a written-answer
deliverable; none blocks MVP.

1. **gRPC single-check −16% vs REST** (603 vs 737 at p0, reproduced at
   p2): profile the tonic path per-call (UUID parse, metadata auth,
   per-call span); if the cause is found and the fix is ≤ ~20 lines, do
   it; else document as accepted overhead (gRPC still wins p95: 75 vs
   85 ms).
2. **Keycloak p0-vs-p2 login asymmetry** (52/s valid vs 23/s invalid):
   one diagnostic run each way; note the finding in the private doc; no KC
   fixes — this is fairness hygiene only.
3. **`sens-rl-prod` metric coherence:** the prod-posture pass showed
   `bench_ok`-rate > 0 with `bench_error_rate = 1.0` on some cells
   (e.g. authz 13.6/s at 100% err) — make the metrics unambiguous under
   429-storms (count OK ops only in `bench_ok`) so the posture pass reads
   cleanly next time.

*Acceptance:* three short written answers (private doc or `claude_dev/`),
plus merged micro-fixes where found.

### G10. SDK benches: first validated cross-SDK run (E1.1 + E1.3) — **Sonnet 5**

*Why Sonnet:* the harness, spec, and per-language TODOs already exist;
this is execution + repair per a written recipe (one agent per language,
exactly as plan E1.1 specified). The maintainer explicitly wants SDK
coverage in the benchmark set.

*Files:* `benchmarks/sdk/*`, sibling `ilpanich/axiam-<lang>-sdk` checkouts,
`benchmarks/runner/report.py` or `sdk/collect.py`.

1. Per language (rust, python, typescript, go, java, csharp, php): checkout
   sibling SDK repo, `just target=axiam bench-up bench-seed`, `just
   sdk=<lang> sdk-bench`; fix build/env/contract drift until it emits one
   spec-conformant `axiam.sdk-bench/v1` record with `status:"ok"` twice in
   a row; `collect.py` ingests it without warnings; update the language's
   `TODO.md`.
2. Then the overhead table (E1.3): each SDK's `check_access`/`batch_check`/
   `login`/`refresh` p50/p95 + throughput next to the same-cell k6 wire
   baselines; wire into the published report; fix `sdk/README.md` claims
   to measured reality. The 4 stub languages (kotlin/swift/c/cpp) follow
   only after the 7 primary ones pass.

*Acceptance:* ≥7 SDKs with validated OK records against a seeded p0
target; the SDK-overhead table renders in the report from real records;
pending languages listed as pending.

---

## Execution order & model summary

```
G1 (Opus)  → G2 (Sonnet) → G3 (Sonnet)        # unblock + clean batch/B2 data
G4 (Sonnet), G5 (Opus), G6 (Sonnet), G7 (Opus)   # parallel after G2
G8 (Opus, needs G2's h1 cell + G4 for refresh re-measure)
G9 (Sonnet), G10 (Sonnet)                      # anytime; G10 before run 4
→ run 4: settled protocol, median-of-3, full sensitivity + SDK tables
→ E4: public doc fourth draft (MVP-ready numbers)
```

| Task | Model | Rationale for the cheaper/costlier choice |
|---|---|---|
| G1 transient root-cause | **Opus 5** | open-ended, cross-system, product-risk verdict |
| G2 harness countermeasures | **Sonnet 5** | fully specified edits + prescribed re-runs |
| G3 batch default decision | **Sonnet 5** | pre-agreed criterion (escalate if data conflicts) |
| G4 refresh harness fix | **Sonnet 5** | scoped debug with a working reference |
| G5 cache ship-decision | **Opus 5** | security default flip + adversarial bench design |
| G6 allocator experiment | **Sonnet 5** | scripted; threshold pre-agreed (escalate if confusing) |
| G7 rate-limit defaults | **Opus 5** | shipped security-default change |
| G8 B2 endgame | **Opus 5** | last-hypothesis debugging in the TLS listener |
| G9 small investigations | **Sonnet 5** | bounded diagnostics |
| G10 SDK bench validation | **Sonnet 5** | recipe-driven execution & repair |

MVP gate: G1–G7 done (G8 may land as a documented position rather than a
fix; G9 is non-blocking; G10 required only for the SDK section of the
public page, not for the server MVP itself).

---

## Implementation status (updated 2026-07-26)

Implemented on branch `claude/benchmark-analysis-reporting-yo7gh5`, **each task
with the model this plan assigns it** (G5/G7/G8 via Opus 5 agents; G2/G4/G9 via
Sonnet 5 agents).

**One environment constraint governs the whole table:** this sandbox has
`cargo`, `node` and `python3` but **no `k6`, no Docker target stacks, and no
live server** — and container-image egress is blocked, so no stack can be
brought up. Every acceptance criterion that is a *measured benchmark number* is
therefore collected on the maintainer's laptop via the new driver script rather
than here. No benchmark number was fabricated.

### The data-collection driver

`benchmarks/run-improvement-tasks.sh` — one subcommand per task that needs a
live run, each independently runnable in a spare slot, each writing
`results/tasks/<task>/SUMMARY.md` with the measured numbers **and** this plan's
acceptance criterion so the task can be closed from its summary alone:

| Subcommand | Task | Answers |
|---|---|---|
| `g1-timeline` | G1 | When does the post-seed window end? (**run this first**) |
| `g1-idle` | G1 | Time-based background work, or traffic-driven warm-up? |
| `g1-isolate` | G1 | Does the state live in the server or the datastore? |
| `g1-dbdirect` | G1 | Is the clamp visible with AXIAM out of the path? |
| `g2-verify` | G2 | Do settle gate + rotation + env dump work live (incl. a secret-leak check)? |
| `g3-batch` | G3 | Clean batch A/B — does batch finally beat single checks? |
| `g4-refresh` | G4 | Is the refresh cell a real rotation now (`bench_fallback == 0`)? |
| `g5-cache-sweep` | G5 | Does the cache's 3× survive a realistic key space? |
| `g6-memory` | G6 | Does jemalloc fix the post-burst retention? (wraps `run-memory-experiment.sh`) |
| `g8-tls-h1` | G8 | Is HTTP/2 multiplexing the TLS token-issuance penalty? |
| `g9-rlprod` | G9 | Are rate-limited cells legible (`bench_failed ≈ bench_throttled`)? |
| `g10-sdk` | G10 | Do the SDK benches emit valid records? |

### Per-task status

| Task | Model | Status | Notes |
|------|-------|--------|-------|
| G1 transient root-cause | Opus 5 | ⛔ laptop | Four probes scripted. The `g1-idle` probe is the decisive one: it splits "background work on a timer" from "warm-up that needs traffic" in a single cell. |
| G2 harness countermeasures | Sonnet 5 | ✅ / ⏳ | Settle gate (`BENCH_SETTLE*`, canary-probes the target's real endpoint), per-run scenario rotation (`cell_order_index`), `axiam_env` knob dump with secret redaction. Found and fixed a real `bench-pack` bug: the leak grep false-positived on redacted key *names*. Live verification ⏳ `g2-verify`. |
| G3 batch default | Sonnet 5 | ⛔ laptop | Blocked on G2's settle gate — this is the A/B run 3 could not do. |
| G4 refresh fix | Sonnet 5 | ✅ / ⏳ | Root-caused from source: the `axiam_refresh` cookie is scoped `Path=/api/v1/auth/refresh` (jar read at the login URL could never see it), **and** login-issued refresh tokens live in `axiam-auth`'s `SessionRepository`, so they can never validate at the OAuth2 token endpoint. See `refresh-harness-diagnosis.md`. ⚠ **Comparability**: AXIAM has no password grant (deliberately — OAuth 2.1 drops ROPC), so this cell measures *session refresh* while Keycloak's measures the *OAuth2 refresh grant*. The two need a `protocol-variant` label in `report.py`; do not publish as a like-for-like head-to-head. |
| G5 cache sweep | Opus 5 | ✅ / ⏳ | `BENCH_AUTHZ_KEYSPACE=K` spreads checks over K distinct cache keys; K=1 byte-identical to before; `setup()` self-provisions and fails closed if a key yields the wrong decision. Decision left **open** behind seven pre-agreed criteria. Surfaced three `axiam-authz` findings — see below. |
| G6 allocator | Sonnet 5 | ⛔ laptop | Fully scripted (`run-memory-experiment.sh`); §G6's placeholder awaits the numbers. |
| G7 rate-limit posture | Opus 5 | ✅ / ⏳ | Shipped defaults **unchanged** (login 10/min, token 20, introspect 10, authz 300, key `ip`); relaxation is an opt-in `Internet`/`Gateway`/`Mesh` posture that touches only machine-to-machine buckets and switches them to `client_id` keying. Human endpoints stay strict per-IP under every posture. Preset values justified against measured ceilings; where a value sits *above* the measured ceiling (Mesh authz) it is documented as a runaway-loop guard, not an attacker guard. |
| G8 B2 endgame | Opus 5 | ✅ / ⏳ | **`AXIAM__SERVER__TLS__HTTP2=false` was a proven no-op** — actix-http's `rustls_0_23_with_config` unconditionally prepends `h2` to ALPN and rustls selects by server preference, so h2 always won regardless of the setting. Now a hard startup error (`ErrorKind::Unsupported`) rather than a silent lie — an operator relying on it was previously wrong without knowing, and it also made faking an h1 cell via the env var impossible. G8 deliberately did NOT ship an h2 `max_concurrent_streams` knob: actix-http never exposes it, so the knob could not have affected the outcome, and shipping it would repeat the exact mistake this task existed to correct. Conviction cell ⏳ `g8-tls-h1`. See `b2-tls-h2-investigation.md`. |
| G9 small investigations | Sonnet 5 | ✅ / ⏳ | The rate-limit "metric incoherence" was **not** a counting bug: limiters start with a full burst, so genuine successes land at test start while the retry storm drives the *fraction* to ~1.00. Both metrics were correct and jointly illegible. Fixed with `bench_throttled` + a shared `recordGrpcResult()` classifier now wired into all three gRPC scenarios. gRPC-vs-REST authz gap documented as accepted overhead (no cheap fix found; gRPC still wins p95). |
| G10 SDK benches | Sonnet 5 | ⛔ laptop | Needs a live seeded target; `g10-sdk` validates two consecutive `status: "ok"` records per language. |

### Findings that became new work (not in the original plan)

1. **Decision-cache `order` vector grows unbounded** when the working set stays
   *below* `max_entries_per_tenant` — the FIFO trim only runs when the cap is
   exceeded, while TTL-expired keys are removed from `entries` but left in
   `order`, so a re-access pushes a duplicate. Growth tracks the miss rate. The
   existing test only covers a *live* re-insert, so this is untested. This
   matters precisely because it is the code G5 may default to ON — **fix before
   any default flip** (it is criterion C5 in the cache decision note).
2. **The decision cache is process-local with no cross-replica invalidation**,
   so "revocation is immediate" is a single-process property; a multi-replica
   deployment's actual revocation latency is ≤ TTL. This must appear next to the
   default wherever the default is documented, not in a footnote.
3. **`invalidate_subject` is O(shard) under the single global mutex** — a role
   unassignment scans up to 10 000 entries while holding the lock every authz
   check needs.
4. **No live-stack revocation test exists.** The "existing integration test"
   G5 was to run against the live stack drives the engine with mock
   repositories; there is no REST-level or live-DB invalidation test anywhere.
   The cache note carries a manual curl procedure and recommends two issues.
5. **`report.py` needs a `protocol-variant` comparability label** for the G4
   refresh cell (see the G4 row above).
