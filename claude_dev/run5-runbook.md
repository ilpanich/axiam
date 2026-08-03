# Benchmark run 5 — execution runbook

- **Date written**: 2026-08-02
- **Branch this describes**: `claude/axiam-fixes-optimization-4qymzu`
  (commits `a15b78d`, `421e3e2`, `cedbc64`, `d35fa65`)
- **Predecessor**: [`improvement-after-run4-benchmark.md`](improvement-after-run4-benchmark.md)
  (I-tasks) — run 5 is item 6 of its *Suggested order of execution*
- **Audience**: whoever executes the matrix. Run 5 is executed **off this
  sandbox**, on the operator's own machine.

Run 5 has two jobs. It **re-measures** the matrix now that the run-4 fixes have
landed, and it **collects the data three open investigations need** — I5 (the
TLS client-credentials plateau), I6 (the REST/gRPC authz asymmetry) and I7 (the
SurrealDB ceiling). Those three shipped as *mechanism + instrumentation*, not as
measured wins: the code changes are in, the hypotheses are stated, and run 5 is
what confirms or refutes them. **Sections 4–6 are therefore not optional
extras — they are the point of this run.**

Read §0 and §1 before touching anything. Several cells need a non-default
envelope, and two of the new knobs default to *off* — if run 5 is executed with
last run's command lines, §5's data will silently not exist.

> **Just want the commands?** [**§12 is a complete copy-paste script**](#12-exact-commands--the-copy-paste-reference)
> for the whole run, in order, with every environment variable and parameter
> spelled out. §0–§11 explain *why*; §12 is what you actually type. If you
> follow §12 top to bottom you cannot collect the wrong data.

---

## 0. What changed since run 4 (and what that means for the numbers)

Everything below is already in the image if you build from this branch. It is
listed because each item moves a number you will be comparing against run 4.

| Change | Commit | Effect on run-5 numbers |
|---|---|---|
| **gRPC rate limiter ×60 units bug fixed** (I1) | `a15b78d` | gRPC now admits `configured × 60` per minute instead of `configured` per minute. Every run-4 gRPC cell under prod posture was throttled to 1/60th. **Do not compare run-4 gRPC prod cells to run-5 ones as like-for-like.** |
| **gRPC limiter scoped per method family** (I2) | `a15b78d` | `GetUserInfo` is no longer throttled by the *authz* bucket. New knobs `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` (default 5× authz) and `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (default 1× authz). Reflection and health are unlimited; **unknown paths fail into the strictest bucket**. |
| **`internet` defaults revised** (I3) | `a15b78d` | token 20→**120**/min, introspect 10→**600**/min, authz_check 300→**1800**/min, revoke 10→**60**/min. Human endpoints unchanged. `gateway`/`mesh` unchanged. |
| **Nagle disabled on the REST listener** (I5) | `421e3e2` | New `AXIAM__SERVER__TCP_NODELAY`, **default `true`**. This is the I5 candidate fix and it is *on by default*, so a plain run-5 matrix already measures the post-fix world. §4 tells you how to A/B it. |
| **Session-validation cache** (I6) | `421e3e2` | New `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`, **default `0` = OFF**. Run 5 must set it explicitly or §5 produces nothing. |
| **Two authz table scans removed** (I7) | `421e3e2` | `grants` batched read and group-inherited `has_role` were full `TableScan`s on *every uncached check on every surface*; both are now `IndexScan`. Unconditional — no flag. Expect authz numbers to move, and the capped-vs-uncapped DB gap to narrow. |
| **Batch strategy pinned to `coalesced`** (I14) | pre-existing | Run 4's compose file forced `concurrent`, silently overriding the shipped default. Run 5 finally measures the real default, and `sens-batch-concurrent` becomes a genuine A/B instead of a duplicate. Expect batch REST ≈ 4–5× singles (G3). |
| **SDK bench correctness + telemetry** (I9, I10, I13) | `d35fa65` | C# `refresh` no longer measures a cached no-op; all 11 runners now assert a real HTTP call per refresh iteration and record real client CPU/RSS; Python drives the async client; C/PHP are labelled `conc=1` and excluded from throughput comparison. |
| **Wire baseline + median-of-3** (I15) | `d35fa65` | `sdk-bench-all` runs a matched-VU k6 baseline first, so the `p95 overhead vs wire` column is populated this time. |
| **Provenance preflight** (I18) | `d35fa65` | `run-benchmark.sh` now fails fast unless the image's `build_ref` is an ancestor of `origin/main`. |
| **`rl-prod` assertions** (I19) | `d35fa65` | `just rl-prod-check` compares configured vs admitted per endpoint and writes `rl-prod-summary.md`. This is the check that caught I1 by hand. |

> **Comparability warning.** Run 5 is **not** a like-for-like re-run of run 4.
> The rate-limit defaults changed, a gRPC units bug was fixed, the batch default
> changed, and two table scans were removed. Treat run 5 as a new baseline.
> Where you do want a controlled comparison, use the A/B procedures in §4–§6,
> which toggle exactly one variable at a time.

---

## 1. Preflight — do not skip

### 1.1 Provenance (I18)

Run 4's `build_ref 6875e4b` was **not an ancestor of `origin/main`** — the image
had been built from a fix branch pre-merge. There was no material doubt about
content that time, but it is exactly the discipline that stops a run being
thrown away later. This is now enforced in `run-benchmark.sh`, but check it by
hand first:

```bash
git fetch origin main
git merge-base --is-ancestor <build_ref> origin/main \
  && echo "OK: image built from main" \
  || echo "STOP: image is not built from main"
```

`BENCH_ALLOW_UNMERGED_BUILD_REF=1` exists as an escape hatch for deliberate
pre-merge validation. **If you use it, say so in `meta.json` and in the writeup**
— an unlabelled unmerged run is how run 4's provenance footnote happened.

### 1.2 Environment sanity

- Confirm the 2-core server / 2-core DB envelope matches run 4, or record the
  difference. Capacity figures in `PUBLIC_BENCH_ANALYSIS.md` §7 are stated for
  that envelope.
- **Thermals (I8).** Run 4's hot cells hit 96–100 °C with `mhz_avg` spread
  3.16–3.87 GHz. Consider an inter-cell cooldown, and record `mhz_avg` per cell
  so a thermally-throttled cell can be identified rather than silently averaged
  in. If you can, run one cell-order-shuffle sensitivity pass to check ordering
  is not confounding results.
- Confirm `just` and `docker compose` resolve, and that `docker compose config`
  renders the target compose files without error.

### 1.3 Watch items carried from run 4 (I8) — cheap, no work, just record

- userinfo REST 5 008 (run 3) → 4 547 (run 4), −9% on a DB-pegged cell.
  Confirm or dismiss as environment drift.
- `sens-cache-on` introspection 3 438 vs matrix 4 387 (−21%) on a
  cache-irrelevant endpoint. Run-order/DB variance suspect.

---

## 2. Standard matrix

Invocation is unchanged from run 4:

```bash
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just target=axiam profile=p0-plaintext bench-run
# ... repeat per target/profile, or use bench-matrix for the full sweep
```

Run the full matrix across targets (axiam, keycloak, zitadel) and profiles
(p0-plaintext, p2-tls13, p3-mtls) as in run 4, **except** the Keycloak login
cells, which need §3.

---

## 3. Keycloak login cells — 4 GiB, run separately (I16)

Run 4 gave Keycloak 2 048 MiB. That was *necessary* (KC peaked at 1 070 MiB) but
**not sufficient** — login cells were still only 1/3 valid per profile, and the
H7 diagnosis observed a 3.28 GiB peak. Run the login cells alone at 4 096 MiB
and leave every other cell at the shared 2 048 cap, so the envelope change is
confined to the cells that need it and is visible in `meta.json` (the C2
cap-recording machinery already records `BENCH_MEM`).

```bash
# KC login cells only, 4 GiB:
BENCH_MEM=4096m just target=keycloak profile=p0-plaintext bench-up
just target=keycloak bench-seed
just target=keycloak profile=p0-plaintext scenario=oauth2_password_login.js bench-run
just target=keycloak bench-down

# The rest of Keycloak's matrix at the default 2048m, login excluded:
BENCH_SCENARIO_EXCLUDE="oauth2_password_login.js" \
  just target=keycloak profile=p0-plaintext bench-up
# ... bench-seed / bench-run as usual
```

`BENCH_SCENARIO_EXCLUDE` is new in `d35fa65` precisely so a cell needing a
different envelope can be split out without hand-editing the matrix.

---

## 4. I5 — the TLS client-credentials plateau

**What run 4 showed.** p2 (TLS) client-credentials = 1 180/s with
`bottleneck: none` and a flat p50/p95/p99 of **42.6 / 43.9 / 44.8 ms** — every
request paying a near-constant ~43 ms with nothing saturated. p0 CC = 2 727/s
through the same middleware.

**What the code review established (statically, `421e3e2`).** Two things are now
*settled* and need no measurement:

- **Client-credentials is not Argon2-bound.** `hash_client_secret` is plain
  SHA-256 + constant-time compare (`crates/axiam-db/src/repository/service_account.rs:36-40`,
  consumed at `crates/axiam-oauth2/src/token.rs:408-412`), and nothing on that
  path touches `crypto_semaphore`. This closes the analysis's open question about
  whether CC shares the login hasher pool. It does not.
- **No lock is held across an await on the CC path**, and the rustls session
  cache is not implicated (a `Ticketer` is configured, so TLS 1.3 resumption is
  stateless and the store is off the hot path).

**The live hypothesis: Nagle + delayed ACK.** `actix-web` defaults
`tcp_nodelay: None`, which actix-http reads as *never call `set_nodelay`* — so
Nagle was on for the REST listener. `tonic` defaults it to `true`, and the gRPC
surface shows no plateau. Linux's delayed-ACK timer is **40 ms**; 42.6 − 40 ≈
2.6 ms of real work, the right order for this handler. It is TLS-only because
the plaintext bind is HTTP/1.1 (a single write, immune to Nagle) while the TLS
bind is h2, where HEADERS and DATA reach the socket as separate writes and hence
separate TLS records.

**Known gap in the hypothesis:** it does not by itself explain why CC is affected
and `token_refresh` is not (also a POST returning a JWT, p0 839 → p2 834).
Whether Nagle fires depends on the exact byte layout relative to path MSS, which
is why `response_body_bytes` is instrumented. **Closing this gap is part of the
job.**

### 4.1 Enable instrumentation

```bash
RUST_LOG=axiam_oauth2=debug,axiam_api_rest=debug
```

No feature flag, no rebuild. Measurement is always on (five `Instant::now()`
reads, ~20 ns each, against a ~370 µs handler — under 0.1%); only *reporting* is
gated by the tracing level.

### 4.2 The A/B

On the **p2-tls13** `oauth2_client_credentials` cell, with p0 as control:

| Arm | Setting |
|---|---|
| A (post-fix, new default) | `AXIAM__SERVER__TCP_NODELAY=true` |
| B (pre-I5 behaviour) | `AXIAM__SERVER__TCP_NODELAY=false` |

Also run the **H6 §6 VU sweep**, 1 → 100 VUs at p0 and p2 on CC. This has been
blocked since H6 because something else always clamped it; nothing does now.
Constant per-request cost ⇒ throughput scales with VUs. A serialization point ⇒
throughput pins.

### 4.3 Artifacts

DEBUG events on target `axiam::perf`:

- `stage="oauth2.client_credentials"` → `client_lookup_us`, `secret_verify_us`,
  `tenant_lookup_us`, `token_mint_us`, `handler_total_us`
- `stage="oauth2.token_endpoint"` → `exchange_us`, `serialize_us`,
  `response_body_bytes`

Plus k6's `bench_http_proto`, connection-reuse counters, and `tls_handshakes`.
Capture `ss -ti` against the container during the run — a Nagle stall shows
unacked bytes with an idle congestion window.

> There is deliberately **no** "token persist" stage: client-credentials issues
> no refresh token and writes nothing. If you see a DB write on this path,
> that is itself a finding.

### 4.4 Decision rule

| Outcome | Reading |
|---|---|
| **Confirms Nagle** | `handler_total_us` stays ~2–4 ms while k6 p50 is ~43 ms (the 40 ms is *outside* the handler), **and** arm B reproduces 43 ms / ~1 180 rps while arm A's p50 collapses toward p0 with throughput rising. |
| **Refutes Nagle** | 43 ms persists in arm A, **or** the stage timings already sum to ~43 ms — in which case the cost is in-handler after all, and the stage breakdown tells you which one. |
| **Closes the "why only CC" gap** | Compare `response_body_bytes` against path MSS (1448 on a 1500-MTU veth) *after* adding h2 HEADERS and TLS record overhead. If the CC body lands just over one segment and `token_refresh`'s does not, that is the explanation. |

---

## 5. I6 — the REST/gRPC authz asymmetry

**What run 4 showed.** With the decision cache on, gRPC checks went
887 → 11 598/s (**13.1×**) but REST checks only 753 → 791 (**+5%**), despite p50
halving.

**What the code review established (`421e3e2`) — the run-4 hypothesis was right
about the cost and wrong about the cause.** The analysis attributed the REST
cost to "session cookie + CSRF" authentication. But
`benchmarks/scenarios/authz_check_rest.js:106` already sends
`Authorization: Bearer` — it is **already a JWT caller**. The session read happens
regardless of credential source, because `AuthenticatedUser::from_request` calls
`is_session_active()` unconditionally
(`crates/axiam-api-rest/src/extractors/auth.rs:105-115`).

Exact DB round-trips on a **cache-hit** authz check:

| Surface | Round-trips | Why |
|---|---|---|
| REST | **1** | the session read (D-15 revocation check), not covered by the decision cache |
| gRPC | **0** | `crates/axiam-api-grpc/src/middleware/auth.rs:42` validates the token and stops — it does **not** enforce the session-revocation check at all |

That asymmetry, not the credential type, is the 13.1× vs +5%.

> **Consequence worth stating plainly:** offering Bearer-JWT auth on
> `/api/v1/authz/check` — option (b) in the I6 write-up — **cannot** fix this
> cell, because it is already in use. Option (a), a session-validation cache,
> was implemented instead.

### 5.1 Enable — this defaults to OFF

```bash
AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5
```

**If run 5 is executed without setting this, §5 produces no data.** Startup emits
a `WARN` naming the active TTL; its absence means the cache is off. Check the log
line before trusting a cell.

> **Set it before `bench-up`, not before `bench-run`.** The compose file
> forwards an explicit allow-list of variable names into the container, and the
> server reads its config at start — so exporting this against an
> already-running stack changes nothing. `bench-down` then `bench-up` to change
> it. (This knob and `AXIAM__SERVER__TCP_NODELAY` were added to that allow-list
> alongside this runbook; they were not forwarded before.) §12.5 has the exact
> loop, including the `docker exec … env` check that proves the value landed.

Cache semantics, for interpreting results: **positive answers only** are cached
(a revoked session is never cached, so it cannot be resurrected; a new session is
usable instantly), entries carry the row's own `expires_at` so expiry is exact,
and invalidation lives inside the repository itself. Single replica ⇒ revocation
is immediate. Multi-replica ⇒ bounded by the TTL, the same contract as the
decision cache.

### 5.2 The matrix — a 2×2, replacing the 1-D H5 sweep

Over `authz_check_rest` and `authz_check_grpc`:

| | `SESSION_VALIDATION_CACHE_TTL_SECS=0` | `=5` |
|---|---|---|
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false` | baseline | session cache only |
| `=true` | decision cache only (= run 4) | both |

The H5 K-sweep's ship-bar arithmetic predates the rate-limit fix and the ceiling
moved from 3× to 13.1×, so it needs re-running regardless — and it should now be
this 2×2 rather than a 1-D sweep, because **the two caches cover disjoint
round-trips**.

### 5.3 Decision rule

| Outcome | Reading |
|---|---|
| **Confirms** | REST `authz_check` with **both** caches on approaches the gRPC both-on number (order 10 k/s, up from 791). Decision-cache-only stays ~791. |
| **Refutes** | REST stays near 791 with both on ⇒ the remaining cost is not the session read. Look at the actix middleware chain and HTTP framing next. |

### 5.4 Revocation regression cell — mandatory

Re-run `h5-revocation-check.sh` with the session cache **on**. Expected:
revocation still immediate on a single replica; ≤ 5 s if the cell runs 2+
replicas. A cache that speeds up authz by breaking revocation is not a win —
this cell is what proves it did not.

---

## 6. I7 — the SurrealDB ceiling

**What run 4 showed.** DB-uncapped deltas post-fix: checks +89/90%, CC +64%,
userinfo +59%, introspection +42%, refresh +30% — i.e. the DB had become the
product's ceiling.

**What changed (`421e3e2`).** Two genuine full table scans on the authz read path
were found via `EXPLAIN` against the real migrated schema, and fixed:

| Query | Before | After |
|---|---|---|
| `grants` batched read | `TableScan` (`pre_decode_filter: "no (unsupported predicate)"`) | `IndexScan idx_grants_unique` |
| `has_role` group-inherited | `TableScan` | `IndexScan idx_has_role_unique` |

Causes were `WHERE meta::id(in) IN $role_ids` (a function call wrapping the
indexed field) and a correlated sub-select on the RHS. **No schema change and no
new index were needed** — the composite `(in, out)` indexes from schema v19
already covered it. Both tables were scanned on *every uncached check on every
surface*; the cost is invisible on a small seed and grows with total DB size.

### 6.1 Run

Nothing to enable — the fixes are unconditional and already in the image.

Matrix `authz_check_rest`, `authz_check_grpc` and `authz_batch_*` at both
`dbcaps=capped` and `dbcaps=uncapped`, with **both caches off**, so the plan fix
is measured in isolation rather than masked by caching.

### 6.2 Decision rule

| Signal | Reading |
|---|---|
| **Success metric** | Capped-envelope `authz_check` REST **≥ 1 000/s without cache** (run-4 baseline: 753). |
| **Strong confirmation** | The DB-uncapped delta **shrinks** (was checks +89/90%). Removing a table scan cuts per-query cost, so the capped↔uncapped gap should narrow. If it stays near +90%, the ceiling is *concurrency*, not per-query cost — and read replicas (§6.4) move up the priority list. |

### 6.3 Seed-size sensitivity — desirable, but NOT runnable as the harness stands

The idea: one labelled cell at ~10× the seed volume. Pre-fix, scan cost scaled
with total row count; post-fix it should be flat — the most direct evidence the
fix is real rather than noise.

**The harness cannot do this today.** `runner/seed.sh` provisions a single
fixture (one org/tenant/user/client) and exposes no volume knob; there is no
`BENCH_SEED_SCALE` or equivalent anywhere in `benchmarks/`. Building it means a
bulk loader that inserts ~10× the `grants` and `has_role` edge rows **across
many tenants** — both tables grow with the whole database, which is exactly why
the scans mattered — run between `bench-seed` and `bench-run`.

Treat this as follow-up tooling, not a run-5 step. See §12.6 for the same note
at the point of use. Without it, I7's evidence rests on the §6.2 decision rule
plus the `EXPLAIN` plan pins already enforced in CI.

### 6.4 Not in scope for run 5

- **Batch/pipelining** — `coalesced` already collapses 15 round-trips to 3 for
  the 5-item shape. Further pipelining should wait until run 5 shows where the
  ceiling sits *after* the scans are gone.
- **Read replicas** — design note only, `docs/deployment/authz-read-path.md` §4.
  The blocker is not plumbing but staleness semantics: a replica reintroduces a
  stale-allow window at the storage layer, where the decision cache's
  invalidation hooks cannot reach, bounded by replication lag rather than a TTL —
  and lag can degrade silently.
- **CP-3 (DB container tuning)** — now actionable, but **re-measure first**. Its
  premise ("if throughput barely moves, the wall is the connection, not DB
  capacity") was formed when the run-4 deltas partly measured per-query scan
  cost, not capacity.

### 6.5 CI guard

`cargo test -p axiam-db --test authz_query_plan_test` fails if any hot query
regresses to `TableScan`. It includes *witness* tests asserting the old query
forms genuinely do scan, so the assertions cannot quietly become tautologies.

---

## 7. Prod-posture pass and the I19 assertions

```bash
just rl=prod target=axiam profile=p0-plaintext bench-run
just target=axiam profile=p0-plaintext rl-prod-check
# artifact: results/rl-prod-summary.md — exit 1 on any endpoint outside ±10% of configured
```

`runner/rl_prod_check.py` reads the current defaults **read-only** out of
`crates/axiam-api-rest/src/config/rate_limit.rs` and
`crates/axiam-api-grpc/src/{config.rs,middleware/rate_limit.rs}`, so it cannot
drift from the code. Expected values on this branch:

| Endpoint | Configured |
|---|---|
| token | 120/min |
| introspect | 600/min |
| authz_check | 1 800/min |
| revoke | 60/min |
| gRPC authz | 6 000/min (100/s × 60) |
| gRPC identity | 30 000/min (5× authz) |
| gRPC admin | 6 000/min (1× authz) |
| login / register / password-reset / MFA | 10 / 5 / 3 / 5 per min (unchanged) |

This is the check that caught the I1 units bug by hand last time; it has been
live-tested against a synthetic failure reproducing that exact bug (100/min
admitted vs 6 000/min configured). **The three gRPC families must be asserted
separately** — a server-wide assertion would not have caught I2.

### 7.1 I4 — refresh-under-prod errors

Run 4 saw `token_refresh` under prod posture at 2 833 failures (2.4%) at 694/s.
Refresh is unlimited; the failures line up with the harness's periodic re-login
tripping the 10/min login bucket mid-run. Either budget re-logins inside the
login limit or pre-mint a session pool in setup, then confirm the failure count
drops. If it does, that also confirms the product-docs note that session-refresh
capacity is effectively coupled to the login limit for short-session
deployments.

---

## 8. SDK pass

```bash
just target=axiam profile=p0-plaintext repeat=3 SDK_BENCH_CONCURRENCY=16 sdk-bench-all
# artifacts: results/sdk-run-{1,2,3}/ → merged into results/sdk/p0-plaintext/*.json
#            results/sdk/sdk-report.md
```

The matched-VU k6 wire baseline now runs automatically before the SDK pass
(`BENCH_VUS = SDK_BENCH_CONCURRENCY`), so the `p95 overhead vs wire` column will
be populated this time. An *unmatched* baseline produces bogus negative
overheads — that was the draft-4 lesson; do not override the VU coupling.

What to check in the output:

- **I9 guard.** Every runner now asserts a real HTTP call per refresh iteration
  (exact call counts for C via `axiam_client_refresh_count()`; a plausible-wire
  latency floor for the other ten, since none expose a counter). A tripped guard
  exits non-zero and `run-all.sh` reports FAILED rather than publishing a fake
  number. **C# `refresh` should now read ~1.2 ms, not 1.2 µs.**
- **I13 telemetry.** `client_cpu_ms_total` and `client_rss_mib_peak` were 0.0 for
  every SDK in run 4. They should now be real. Client-side efficiency is half the
  E1.3 story — an SDK burning 2× CPU at equal latency matters for IoT.
- **I10 labelling.** C and PHP run at concurrency 1 and are now rendered in a
  separate "serial benches — excluded from cross-SDK throughput comparison"
  table. Do not re-merge them into the throughput chart.
- **Python is now an async driver.** Run 4's Python `check_access` gap (p50
  30.3 ms vs 10–11 ms for Go/Java/Rust) was profiled and found to be
  **substantially a harness artifact**: a synchronous GIL-bound client driven
  through `ThreadPoolExecutor(max_workers=16)` sharing one `httpx.Client`, with
  per-call latency scaling ~linearly with thread count while aggregate throughput
  stayed flat — the Little's-Law fingerprint of a fixed-capacity queueing point
  (GIL scheduling plus httpcore's single per-pool lock), not extra per-call work.
  All four originally-suspected causes were ruled out with direct evidence. The
  runner now uses `AsyncAxiamClient` with an `asyncio.Semaphore`. **Expect the
  Python number to move substantially, and treat it as a new baseline rather than
  an SDK improvement.**
- **C++ tail (I11).** Root-caused and fixed in the C++ SDK repo — and *not* the
  `Expect: 100-continue` cause the analysis speculated (libcurl 8.5's threshold
  is 1 MiB, not 1 KiB, so check/batch bodies never trigger it). The real cause was
  `CURLOPT_MAXAGE_CONN` (libcurl default 118 s, so a long-lived worker silently
  reconnects) compounding with `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` (default
  200 ms, burned on every fresh connection where AAAA resolves but IPv6 is
  unroutable). **Acceptance: p95 within 3× p50 at p0.** A residual tail would
  point at server-side idle timeouts or `Connection: close`, not connection age.

`SDK_BENCH_SKIP_WIRE=1` skips the baseline on a quick re-run. Do not use it for
the run of record.

---

## 9. Zitadel (I17) — known gaps, carried

- **(a) refresh** still needs an `offline_access` device/PKCE seed flow. Zitadel's
  session-token-exchange is confirmed unimplemented upstream
  (`zitadel/zitadel#7900`, "investigating") and ROPC is unsupported; the one
  plausible HTTP-only path (Custom Login UI callback-linking) is documented in
  `token_refresh.js` but **not implemented**, because it could not be verified
  against a live Zitadel. Keep the exclusion label.
- **(b) login is bcrypt-dominated.** An opt-in, default-neutral
  `ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_COST` override is now wired into
  the compose file (verified via `docker compose config` to resolve to Zitadel's
  own default of 14 when unset, so default runs are unaffected). If you want a
  latency-comparable row, run **one** cell with a reduced cost and label it
  clearly as non-default; otherwise keep excluding.
- **(c)** `zitadel_userinfo_grpc` now emits `bench_http_proto` — fixed.

---

## 10. Reporting

```bash
just bench-report   # folds the SDK section (with conc=1 labelling) into results/report.md
```

When writing up:

1. **State the comparability break.** §0's warning belongs in the run-5
   document's opening, not a footnote. Four separate changes moved numbers.
2. **Record provenance explicitly** — `build_ref`, and whether the merge-base
   check passed or was overridden.
3. **Report I5/I6/I7 as confirmed or refuted**, using the decision rules in
   §4.4, §5.3 and §6.2. A hypothesis that survives an honest attempt to refute it
   is worth far more than one that was never tested; and a refuted one is a
   result, not a failure — record it either way.
4. **Do not propagate the "≥500× below capacity" claim.** Run 4's docs asserted
   every revised default stays ≥500× below measured capacity. That is false:
   authz_check is ~25× (1 800/min vs ~45 000/min) and introspect ~438×. The
   corrected range is **25–2 700×, with authz the tightest**. This is already
   fixed in code, tests and `PUBLIC_BENCH_ANALYSIS.md`; do not reintroduce it.
5. **Keep the D8 caveat verbatim** wherever rate-limit numbers appear:
   `client_id`-keyed modes are fairness controls between authenticated
   well-behaved clients, not abuse controls, because the client_id is
   attacker-mintable before authentication. `ip` remains the only
   attacker-resistant key and stays the default.

---

## 11. Quick checklist

- [ ] `git merge-base --is-ancestor <build_ref> origin/main` passes (§1.1)
- [ ] Envelope matches run 4, or the difference is recorded (§1.2)
- [ ] Full matrix run, KC login cells split out at `BENCH_MEM=4096m` (§2, §3)
- [ ] `RUST_LOG=axiam_oauth2=debug,axiam_api_rest=debug` set for the I5 cells (§4.1)
- [ ] `TCP_NODELAY` A/B run on p2 CC, with p0 control (§4.2)
- [ ] H6 VU sweep 1→100 at p0 and p2 on CC (§4.2)
- [ ] **`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5` set** — startup WARN confirms it (§5.1)
- [ ] I6 2×2 cache matrix run on REST and gRPC (§5.2)
- [ ] `h5-revocation-check.sh` re-run with the session cache on (§5.4)
- [ ] I7 cells run with **both caches off**, capped and uncapped (§6.1)
- [ ] ~~10× seed-size sensitivity cell~~ — **not runnable**, harness has no bulk-seed tooling (§6.3)
- [ ] `rl-prod-check` passes, `rl-prod-summary.md` archived (§7)
- [ ] SDK pass with `repeat=3` and the wire baseline enabled (§8)
- [ ] C# refresh reads ~1.2 ms, not 1.2 µs (§8)
- [ ] `client_cpu_ms_total` / `client_rss_mib_peak` are non-zero (§8)
- [ ] Thermals and `mhz_avg` recorded per cell (§1.2)

> Every command in §12 was checked against the harness as it exists on this
> branch: `just` recipes and variables, the scenario filenames, the runner
> scripts, and — critically — that each `AXIAM__…` variable is actually
> forwarded into the container by `targets/axiam/docker-compose.yml`. Compose
> uses an explicit allow-list, so a variable that is merely exported in your
> shell but absent from that list reaches nothing. The I5 and I6 knobs were
> **added to that list** in the same commit as this section; before it, the
> §5.1 instruction would have been silently ignored.

---

## 12. Exact commands — the copy-paste reference

Everything below is literal. Run it from `benchmarks/` unless a block says
otherwise. Blocks are in execution order; do not reorder them.

### 12.0 The one rule that matters

**Server-side environment variables are baked into the container at
`bench-up`, not at `bench-run`.**

`benchmarks/targets/axiam/docker-compose.yml` forwards an *explicit allow-list*
of variable names into the container. Exporting a variable and then running
`bench-run` against an already-running stack does nothing — the process was
started with the old value. So:

- put every `AXIAM__…` / `RUST_LOG` export **on the same line as, or before,
  `bench-up`**;
- to change any of them, **`bench-down` first, then `bench-up` again**. That is
  why the A/B blocks below always tear down between arms.

`just` variables (`target=`, `profile=`, `rl=`, `dbcaps=`, `repeat=`,
`scenario=`, `targets=`, `profiles=`) are a different mechanism — they go
**before the recipe name**, never after, and are not environment variables:

```bash
just target=axiam profile=p2-tls13 bench-run     # correct
just bench-run target=axiam                      # WRONG — silently ignored
```

### 12.1 Preflight (once, before anything else)

```bash
cd /path/to/axiam/benchmarks

# 1. Provenance (I18). Replace <build_ref> with the image's build_ref.
#    run-benchmark.sh now enforces this too, but check it by hand first.
git fetch origin main
git merge-base --is-ancestor <build_ref> origin/main \
  && echo "OK: image built from main" \
  || echo "STOP: image is NOT built from main — do not start run 5"

# 2. Toolchain sanity.
just --version && docker compose version
docker compose -f targets/axiam/docker-compose.yml config >/dev/null && echo "compose OK"

# 3. Throwaway TLS/mTLS certs for the security profiles (idempotent).
just bench-certs
```

If step 1 fails and you are *deliberately* validating a pre-merge image, and
only then:

```bash
export BENCH_ALLOW_UNMERGED_BUILD_REF=1   # and SAY SO in the writeup + meta.json
```

### 12.2 The standard matrix (median-of-3)

This is the bulk of the run and needs no special environment.

```bash
cd /path/to/axiam/benchmarks

just targets="axiam keycloak zitadel" \
     profiles="p0-plaintext p2-tls13 p3-mtls" \
     repeat=3 \
     bench-matrix
```

`bench-matrix` handles up/seed/run/down per cell and writes each pass to
`results/run-<i>/`. `bench-report` medians across them later.

> Keycloak's **login** cells are excluded from this pass and run separately in
> §12.3 — they need a 4 GiB envelope. If you would rather run the matrix
> per-target by hand, use this shape:
>
> ```bash
> just target=axiam profile=p0-plaintext bench-up
> just target=axiam bench-seed
> just target=axiam profile=p0-plaintext bench-run
> just target=axiam bench-down
> ```

### 12.3 Keycloak login cells — 4 GiB, separately (I16)

Run 4 gave Keycloak 2 048 MiB; that was necessary but not sufficient (H7
observed a 3.28 GiB peak) and login cells were still 1/3 valid.

```bash
cd /path/to/axiam/benchmarks

for P in p0-plaintext p2-tls13; do
  BENCH_MEM=4096m just target=keycloak profile="$P" bench-up
  just target=keycloak bench-seed
  just target=keycloak profile="$P" scenario=oauth2_password_login.js bench-run
  just target=keycloak bench-down
done
```

And, if you ran §12.2 per-target by hand rather than via `bench-matrix`, the
rest of Keycloak's matrix at the default cap with login excluded:

```bash
export BENCH_SCENARIO_EXCLUDE="oauth2_password_login.js"
just target=keycloak profile=p0-plaintext bench-up
just target=keycloak bench-seed
just target=keycloak profile=p0-plaintext bench-run
just target=keycloak bench-down
unset BENCH_SCENARIO_EXCLUDE
```

`BENCH_MEM` is recorded into `meta.json` automatically by the C2 machinery, so
the 4 GiB cells are self-labelling.

### 12.4 I5 — the TLS client-credentials plateau

Two arms plus a control. **Tear down between arms** — `TCP_NODELAY` is read at
container start.

```bash
cd /path/to/axiam/benchmarks

# ---- Arm A: post-fix (the new shipped default) --------------------------
export RUST_LOG="axiam=warn,axiam_oauth2=debug,axiam_api_rest=debug"
export AXIAM__SERVER__TCP_NODELAY=true

just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
just target=axiam profile=p2-tls13 scenario=oauth2_client_credentials.js bench-run
docker logs axiam-bench-app > ../i5-armA-tls-nodelay-on.log 2>&1   # capture stage timings
just target=axiam bench-down

# ---- Arm B: pre-I5 behaviour (Nagle left on) ----------------------------
export AXIAM__SERVER__TCP_NODELAY=false

just target=axiam profile=p2-tls13 bench-up
just target=axiam bench-seed
just target=axiam profile=p2-tls13 scenario=oauth2_client_credentials.js bench-run
docker logs axiam-bench-app > ../i5-armB-tls-nodelay-off.log 2>&1
just target=axiam bench-down

# ---- Control: same two arms at p0 (plaintext) ---------------------------
for N in true false; do
  export AXIAM__SERVER__TCP_NODELAY=$N
  just target=axiam profile=p0-plaintext bench-up
  just target=axiam bench-seed
  just target=axiam profile=p0-plaintext scenario=oauth2_client_credentials.js bench-run
  docker logs axiam-bench-app > "../i5-p0-nodelay-$N.log" 2>&1
  just target=axiam bench-down
done

unset AXIAM__SERVER__TCP_NODELAY
export RUST_LOG="axiam=warn"
```

> Confirm the container name first with `docker ps --format '{{.Names}}'` if
> `docker logs axiam-bench-app` errors — the compose project prefix can vary.

**What to pull out of those logs** — DEBUG events on target `axiam::perf`:

```bash
grep -o 'stage="oauth2.client_credentials".*' ../i5-armA-tls-nodelay-on.log | head
grep -o 'stage="oauth2.token_endpoint".*'     ../i5-armA-tls-nodelay-on.log | head
```

Fields: `client_lookup_us`, `secret_verify_us`, `tenant_lookup_us`,
`token_mint_us`, `handler_total_us`; and `exchange_us`, `serialize_us`,
`response_body_bytes`.

**The VU sweep** (H6 §6 — blocked since H6, finally runnable):

```bash
for VUS in 1 2 5 10 20 50 100; do
  for PROF in p0-plaintext p2-tls13; do
    just target=axiam profile="$PROF" bench-up
    just target=axiam bench-seed
    BENCH_VUS=$VUS just target=axiam profile="$PROF" \
      scenario=oauth2_client_credentials.js bench-run
    just target=axiam bench-down
  done
done
```

**Kernel-level confirmation**, while an arm-B run is in flight (separate shell):

```bash
docker exec axiam-bench-app sh -c 'ss -ti' | head -40
# A Nagle stall shows unacked bytes sitting with an idle congestion window.
```

Decision rule is §4.4.

### 12.5 I6 — REST/gRPC authz asymmetry (the 2×2)

**`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` defaults to `0` (OFF). If
you skip these exports, this section produces nothing new.**

```bash
cd /path/to/axiam/benchmarks

for DEC in false true; do
  for SESS in 0 5; do
    export AXIAM__AUTHZ__DECISION_CACHE_ENABLED=$DEC
    export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=$SESS

    just target=axiam profile=p0-plaintext bench-up

    # Verify the knobs actually took effect BEFORE spending a cell on it:
    docker exec axiam-bench-app env | grep -E 'DECISION_CACHE_ENABLED|SESSION_VALIDATION_CACHE_TTL'
    docker logs axiam-bench-app 2>&1 | grep -i 'session.validation' | head -3
    # With SESS=5 you MUST see a startup WARN naming the TTL.
    # No WARN => the cache is off => the cell is worthless. Stop and fix.

    just target=axiam bench-seed
    just target=axiam profile=p0-plaintext scenario=authz_check_rest.js bench-run
    just target=axiam profile=p0-plaintext scenario=authz_check_grpc.js bench-run
    just target=axiam bench-down
  done
done

unset AXIAM__AUTHZ__DECISION_CACHE_ENABLED AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
```

This 2×2 **replaces** the 1-D H5 K-sweep — the two caches cover disjoint
round-trips, so a single-variable sweep cannot separate them.

**Revocation regression cell — mandatory, not optional.** A cache that speeds
up authz by breaking revocation is not a win:

```bash
export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5
just target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
bash runner/h5-revocation-check.sh
just target=axiam bench-down
unset AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
# Expect: revocation still immediate on a single replica (<= 5s if 2+ replicas).
```

Decision rule is §5.3.

### 12.6 I7 — SurrealDB ceiling (both caches OFF)

The table-scan fixes are unconditional, so nothing to enable — but the caches
must be **off** or they mask the effect being measured.

```bash
cd /path/to/axiam/benchmarks

export AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false
export AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=0

for CAPS in capped uncapped; do
  just target=axiam profile=p0-plaintext dbcaps="$CAPS" bench-up
  just target=axiam bench-seed
  for S in authz_check_rest.js authz_check_grpc.js authz_batch_rest.js; do
    just target=axiam profile=p0-plaintext dbcaps="$CAPS" scenario="$S" bench-run
  done
  just target=axiam bench-down
done

unset AXIAM__AUTHZ__DECISION_CACHE_ENABLED AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS
```

> Scenario filenames verified present: `authz_check_rest.js`,
> `authz_check_grpc.js`, `authz_batch_rest.js`, `authz_batch_grpc.js`,
> `oauth2_client_credentials.js`, `oauth2_password_login.js`,
> `token_refresh.js`. Add `authz_batch_grpc.js` to the inner loop if you want
> the gRPC batch surface too.

**Seed-size sensitivity — NOT RUNNABLE with the current harness. Skip it, or
build the tooling first.**

§6.3 describes this as the cleanest single demonstration that the I7 fix is
real, and that reasoning still holds: pre-fix, the scan cost scaled with total
row count, so post-fix it should be flat. But **the harness cannot do it
today**, and this was verified rather than assumed:

- `runner/seed.sh` provisions a *fixture* — one org, one tenant, one user, one
  client — not a bulk dataset. It exposes no volume knob (`BENCH_SEED_DIR` is a
  path, not a size).
- There is no `BENCH_SEED_SCALE`, `SEED_USERS` or equivalent anywhere in the
  harness. Do not invent one and expect it to be honoured; it will be silently
  ignored and you will measure the normal seed twice.

If you want this cell, it needs new tooling first: a bulk loader that inserts
~10x the `grants` and `has_role` edge rows **across many tenants** (the whole
point is that both tables grow with the entire database, not with one tenant),
run after `bench-seed` and before `bench-run`. Label the resulting cell
explicitly so it is never averaged in with normal-seed cells.

Without it, the I7 evidence for run 5 rests on the §6.2 decision rule — the
capped-envelope ≥ 1 000/s target and the narrowing of the DB-uncapped delta —
which is weaker but still decisive, plus the `EXPLAIN` plan pins that already
run in CI.

Decision rule is §6.2. CI guard:
`cargo test -p axiam-db --test authz_query_plan_test`.

### 12.7 Prod-posture pass + the I19 assertions

```bash
cd /path/to/axiam/benchmarks

just rl=prod target=axiam profile=p0-plaintext bench-up
just target=axiam bench-seed
just rl=prod target=axiam profile=p0-plaintext bench-run
just target=axiam bench-down

# I19: configured-vs-admitted per endpoint. Exit 1 on any endpoint outside +/-10%.
just rl-prod-check
# artifact: results/rl-prod-summary.md
```

`rl=prod` sets the real shipped limits, and `rl_prod_check.py` re-extracts them
**read-only from the Rust source** — so if the two ever drift, the check fails
loudly instead of publishing a wrong comparison. Expected configured values on
this branch:

| endpoint | configured |
|---|---|
| token | 120/min |
| introspect | 600/min |
| authz_check | 1 800/min |
| revoke | 60/min |
| gRPC authz | 6 000/min (100/s x 60) |
| gRPC identity | 30 000/min (500/s x 60) |
| gRPC admin | 6 000/min (100/s x 60) |
| login / register / reset / MFA | 10 / 5 / 3 / 5 per min |

**I4 — refresh-under-prod errors.** Run 4 saw 2 833 failures (2.4%) on
`token_refresh` under prod posture, which line up with the harness's periodic
re-login tripping the 10/min login bucket. After the pass above, check:

```bash
grep -h "token_refresh" results/run-*/axiam/p0-plaintext/*/summary.json 2>/dev/null | head
# Expect the failure count to have dropped. If it has not, the re-login budget
# still needs fixing (or a pre-minted session pool in setup).
```

### 12.8 SDK pass (median-of-3, with the wire baseline)

```bash
cd /path/to/axiam/benchmarks

just target=axiam profile=p0-plaintext repeat=3 SDK_BENCH_CONCURRENCY=16 sdk-bench-all
```

The matched-VU k6 wire baseline now runs automatically first
(`BENCH_VUS = SDK_BENCH_CONCURRENCY`) so the `p95 overhead vs wire` column is
populated. **Do not override that coupling** — an unmatched baseline produces
bogus negative overheads (the draft-4 lesson). `SDK_BENCH_SKIP_WIRE=1` exists
for quick re-runs; never use it for the run of record.

Then verify the three things run 4 got wrong:

```bash
# I9 — C# refresh must now be a REAL call: expect ~1.2 ms, NOT 1.2 us.
grep -h '"op": *"refresh"' results/sdk/p0-plaintext/*.json | grep -i csharp

# I13 — client telemetry must be non-zero (it was 0.0 for every SDK in run 4).
grep -ho '"client_cpu_ms_total": *[0-9.]*' results/sdk/p0-plaintext/*.json | sort -u | head
grep -ho '"client_rss_mib_peak": *[0-9.]*' results/sdk/p0-plaintext/*.json | sort -u | head

# I10 — C and PHP must render under the separate serial-bench table.
grep -n "conc=1\|serial benches" results/sdk/sdk-report.md
```

If any refresh row still reads in microseconds, the I9 guard should already
have failed the run — treat a microsecond row plus a passing run as a harness
bug, not a fast SDK.

### 12.9 Report

```bash
cd /path/to/axiam/benchmarks
just bench-report        # -> results/report.md, SDK section with conc=1 labelling
```

### 12.10 If something goes wrong

```bash
# Tear everything down and start the cell again:
just target=axiam bench-down

# Wipe accumulated results (DESTRUCTIVE — archive first if you care):
just bench-clean

# Archive a completed run:
just bench-pack

# Prove a cell can connect/seed/answer without spending a real measurement:
just target=axiam profile=p0-plaintext dry=1 bench-run     # -> results/dry-run/
just targets="axiam keycloak zitadel" profiles="p0-plaintext p2-tls13" bench-dry-run
```

A dry run is the cheapest way to validate a whole matrix invocation before
committing hours to it. **If you change any command in this section, dry-run it
first.**
