# Improvement plan after benchmark run 4 (2026-08-02)

Derived from `benchmarks/PRIVATE_BENCH_ANALYSIS.md` (run-4 edition) and the
raw archive `results20260802` (matrix run-1..3, sens-*, sdk/). Companion to
the published `benchmarks/PUBLIC_BENCH_ANALYSIS.md` fifth draft. This is the
run-4 successor to `improvement-after-serious-benchmark.md` (G-tasks) and
`improvement-after-g-benchmark.md` (H-tasks); task IDs here are **I-tasks**.

Context in one line: run 4 confirmed the H2 write-behind rate-limit fix at
matrix scale (+47%…+284% on the previously clamped endpoints, zero refused
cells), so the remaining work splits into (A) production rate-limit posture
fixes, (B) product performance levers, (C) SDK fixes, (D) benchmark-harness
fixes for run 5.

---

## A. Production rate limits (the user-facing posture)

### I1 — Fix the gRPC shared-limiter ×60 units bug ⚠ product bug, highest priority

**Evidence (sens-rl-prod):** with `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC=100`, all
three gRPC scenarios admitted ~100 ops per **60 s** window (bench_ok totals:
check 400, batch 300, userinfo 400 over the session) — 1/60th of the
configured per-second rate. REST limits enforced exactly as configured in
the same pass (authz 300/min ✓, token 20/min ✓, introspect 10/min ✓,
login 10/min ✓).

**Root cause (found in code):**
`crates/axiam-api-grpc/src/middleware/rate_limit.rs` wires two layers; the
in-memory `build_grpc_governor_layer(authz_per_sec)` is correctly quota'd
(`Quota::per_second`), but the cross-replica pre-check
`GrpcSharedRateLimitLayer::new(db, "grpc_authz", grpc_config.grpc_authz_per_sec, …)`
enforces its `limit` against `WINDOW_SECS = 60` (the REST per-minute
window) while being handed the per-**second** number verbatim. The stricter
layer wins, so the effective limit is `per_sec` requests **per minute**.

**Fix:** convert units at the boundary (`limit = grpc_authz_per_sec * 60`
for the 60-s shared window — saturating mul), or give the gRPC layer a
per-second shared window. Prefer the ×60 conversion: it keeps one shared
bucket schema and the write-behind flusher cadence unchanged.

**Acceptance:** integration test driving sustained overload through the
full layered stack asserts admitted-per-minute ≈ configured×60 (±10%);
`sens-rl-prod` re-run shows gRPC check admitted ≈ 100/s. Unit test pinning
the call-site units so a refactor can't reintroduce it.

### I2 — Scope the gRPC limiter per-method (design fix)

The shared layer + governor apply **server-wide**, so `GetUserInfo` (an
identity read measured at 12.7 k/s) is throttled by the *authz* limit.
Under prod posture, gRPC userinfo collapsed to the same ~100/min as authz.
Fix: split buckets per service/method family (authz-check vs identity-read
vs admin), with an explicit unlimited/neutral default for reflection and
health. Sizing per family can then follow §7.2 of the public doc.

### I3 — Revise the shipped `internet` machine-endpoint defaults (proposal)

Run-4 measured capacity vs shipped defaults (2-core envelope): token
20/min vs ~163 k/min capacity; introspect 10/min vs ~263 k/min; authz
300/min vs ~45 k/min. Proposal published in PUBLIC doc §7.2 —
**token 20→120/min, introspect 10→600/min, authz_check 300→1 800/min,
revoke 10→60/min; human endpoints (login/register/reset/MFA) unchanged.**
Each suggested value stays ≥500× below measured capacity, preserving the
abuse posture while no longer breaking a single healthy integration behind
NAT. Implementation notes:

- Change only `RateLimitConfig::default()`; the `gateway`/`mesh` presets
  are already sized (600/6 000/6 000 and 6 000/60 000/60 000) and validated
  (H7: admitted rate 96.6–100% for a single client under `gateway`).
- Update `docs/deployment/rate-limit-sizing.md` and the config-reference
  table generator/tests that assert the defaults
  (`rate_limit.rs` has default-pinning tests around lines 500–550).
- Keep the D8 security caveat (client_id is attacker-mintable) verbatim
  wherever the new numbers appear.
- Consider a startup log line when `internet` defaults are active and
  sustained 429 ratio on machine endpoints exceeds ~50% over 5 min —
  "your limits are throttling what looks like legitimate machine traffic;
  see rate-limit-sizing" — cheap to add on top of the write-behind
  counter's existing stats.

### I4 — Refresh-under-prod errors (harness or product ergonomics)

`token_refresh` under prod posture: 2 833 failures (2.4%) at 694/s vs 839
neutralized. Refresh is unlimited; the failures line up with the harness's
periodic re-login tripping the 10/min login bucket mid-run. Action:
(a) harness — budget re-logins inside the login limit or pre-mint session
pools in setup; (b) product docs — note that session-refresh capacity is
effectively coupled to the login limit for short-session deployments.

---

## B. AXIAM product performance levers (post-fix priorities)

### I5 — The TLS client-credentials plateau (−57%) — final open perf mystery

New run-4 evidence: p2 CC = 1 180/s with **bottleneck: none** and a flat
p50/p95/p99 of 42.6/43.9/44.8 ms — every request pays a near-constant
~43 ms with nothing saturated; p0 CC = 2 727/s through the same middleware
(rate-limit write exonerated — it no longer exists). This is a
serialization/latency plateau specific to CC-over-TLS.

Plan (the H6 §6 VU-sweep, finally runnable since nothing else clamps):
1. Sweep VUs 1→100 at p0 and p2 on CC. Constant per-request cost ⇒
   throughput scales with VUs; serialization point ⇒ pinned throughput.
2. Instrument the CC handler path with per-stage timings (client-secret
   verify, token mint/sign, token persist, response) under both profiles.
3. Check connection behavior under h2: are token responses closing
   streams/connections (`Connection`/GOAWAY behavior, k6 conn-reuse
   counters — `bench_http_proto` already recorded)?
Prime suspects: client-secret Argon2 verification queueing on the
`MAX_CONCURRENT_HASHES` semaphore (login shows 69/s ≈ hash-bound; CC
verifies a secret per request too — at p0 why is it 2 727/s then? check
whether CC uses the same hasher pool or a cheaper compare), and TLS
session-cache locking.

### I6 — REST authz-check session-read serialization (cache asymmetry)

`sens-cache-on`: gRPC checks 887 → 11 598/s (13.1×) but REST checks only
753 → 791 (+5%) despite p50 halving. Hypothesis: the REST path
authenticates via session cookie + CSRF ⇒ one SurrealDB session read per
request that the decision cache doesn't cover; gRPC authenticates via JWT
(no DB). Actions:
1. Confirm with a JWT-authenticated REST check variant (or trace).
2. If confirmed, add a short-TTL process-local session-validation cache
   (same invalidation discipline as the decision cache: logout/rotation
   events + TTL backstop; document the ≤TTL staleness bound), or support
   Bearer-JWT auth on `/api/v1/authz/check` for service callers — likely
   the cleaner fix and consistent with the gRPC surface.
3. Re-run the post-fix decision-cache K-sweep (the H5 evaluation predates
   the rate-limit fix; the ceiling moved from 3× to 13×, so the ship-bar
   arithmetic deserves a re-check even if the default stays opt-in).

### I7 — SurrealDB is now the product's ceiling — invest there

DB-uncapped deltas post-fix: checks +89/90%, CC +64%, userinfo +59%,
introspection +42%, refresh +30%. Candidate work, in order of expected
value: (a) profile the per-check query plan (the authz read path) for
index-only satisfaction; (b) batch/pipeline the hot reads already known to
coalesce well (the `coalesced` batch result shows the DB rewards it);
(c) evaluate SurrealDB read-replica topology for authz reads;
(d) revisit `surrealdb-tuning-report.md` items against the current
SurrealDB release. Success metric: capped-envelope authz_check ≥ 1 000/s
REST without cache.

### I8 — Watch items (cheap re-checks in run 5, no work now)

- userinfo REST 5 008 (run 3) → 4 547 (run 4): −9% between runs on a
  DB-pegged cell; confirm or dismiss as env drift.
- `sens-cache-on` introspection 3 438 vs matrix 4 387 (−21%) on a
  cache-irrelevant endpoint: run-order/DB variance suspect.
- Thermal: hot cells hit 96–100 °C, mhz_avg spread 3.16–3.87 GHz.
  Consider inter-cell cooldown or a cell-order shuffle sensitivity check.

---

## C. SDK work (from the first full 11-language pass)

### I9 — C# `refresh` measures a cached no-op (harness + contract clarification)

p50 1.2 µs / "752 k rps": the .NET auth helper correctly returns the
still-valid token without a network call; the bench never forces expiry.
Fix in the SDK bench harness (`axiam-csharp-sdk` bench runner): force
refresh via an explicit `ForceRefreshAsync`/expiry override, or mint a
token with ~1 s TTL for the refresh loop. Audit the other ten SDK bench
runners for the same trap (their ~17.3 ms p50s indicate they do hit the
wire today — add an assertion: refresh op must record ≥1 HTTP call per
iteration, mirroring the k6 `bench_fallback` lesson from G4).

### I10 — C and PHP benches run at concurrency 1 — parity or explicit labels

Their records honestly say so (`notes` field), but the report table
renders them beside concurrency-16 rows. Either implement multi-process
drivers (PHP: `pcntl_fork` N workers; C: pthreads) or make `report.py`
render a `conc=1` label in the SDK table and exclude them from any
cross-SDK throughput chart. Labeling is the cheap correct first step.

### I11 — C++ bimodal tail (p95 ~264–336 ms on check/batch at every profile)

p50 is excellent (3.3 ms — libcurl, same class as the C SDK), but a subset
of iterations pays ~280 ms. Signature: connection re-establishment (handle
churn / no keep-alive reuse on some code path), possibly one reconnect per
worker per interval. Investigate `axiam-cplusplus-sdk`'s transport: shared
`CURLM`/handle pool reuse, `CURLOPT_FORBID_REUSE`/`FRESH_CONNECT` flags,
and Expect:100-continue behavior on POST bodies (a classic ~200 ms+ curl
tail: disable `Expect` header). Acceptance: p95 within 3× p50 at p0.

### I12 — Python check_access ~3× slower than peer SDKs at equal concurrency

p50 30.3 ms vs 10–11 ms (go/java/rust/…), thr 444 vs ~770–870. Profile the
async client: event-loop-per-thread setup, JSON (de)serialization, or
sync-over-async bridging in `check_access`. Not a correctness issue;
medium priority.

### I13 — SDK bench telemetry gaps

`client_rss_mib_peak` and `client_cpu_ms_total` recorded 0.0 for every
SDK — the sampler isn't wired. Client-side efficiency is half the E1.3
story (an SDK that burns 2× CPU at equal latency matters for IoT); fix the
collector in the shared SDK-bench driver.

---

## D. Benchmark harness (for run 5)

### I14 — Batch strategy pin — **fixed on this branch**

`benchmarks/targets/axiam/docker-compose.yml` defaulted
`AXIAM__AUTHZ__BATCH_STRATEGY` to `concurrent`, silently overriding the
shipped `coalesced` default for the whole matrix (and making
`sens-batch-concurrent` a duplicate of the matrix instead of an A/B).
Changed to `coalesced`. Run 5 therefore measures the real default; keep
`sens-batch-concurrent` as the labeled alternative (it will finally
differ). Expectation to verify: batch REST ≈ 4–5× singles per G3.

### I15 — SDK wire baseline

The E1.3 overhead column (`p95 overhead vs wire`) was empty this run — no
matched-concurrency k6 wire baseline was captured. Wire the baseline step
back into `just sdk-bench-all` (BENCH_VUS = SDK_BENCH_CONCURRENCY, per the
draft-4 lesson that an unmatched baseline produces bogus negative
overheads), and repeat the SDK pass median-of-3.

### I16 — Keycloak login envelope

2 048 MiB was necessary (KC peaked at 1 070 MiB) but not sufficient: login
cells still 1/3 valid per profile. Per the H7 diagnosis (3.28 GiB peak
observed), run 5 should run KC login cells at `BENCH_MEM=4096m`, labeled
as such in meta.json (the C2 cap-recording machinery already supports it).
Keep all other cells at the shared 2 048 cap.

### I17 — Zitadel gaps (unchanged, carried)

(a) refresh needs an `offline_access` device/PKCE seed flow in the
harness; (b) login is bcrypt-dominated — consider one labeled
sensitivity cell with a reduced-cost Zitadel hash config for a
latency-comparable row, clearly marked non-default, or keep excluding
with the current label. (c) `zitadel_userinfo_grpc` records no
`bench_http_proto` — cosmetic, fix the scenario's metric emission.

### I18 — Provenance

Run-4's `build_ref 6875e4b` is not an ancestor of `origin/main` (image was
built from the fix branch pre-merge). No material doubt about content, but
A9 discipline: run 5 must pull an image whose build_ref resolves on main
(add a preflight check to the runbook — `git merge-base --is-ancestor`).

### I19 — Prod-posture pass ergonomics

Add per-endpoint expected-admission assertions to `sens-rl-prod` (the
"admitted ≈ configured" check that caught I1 was done by hand this time);
emit a small `rl-prod-summary.md` with configured-vs-admitted per endpoint
so the next units bug is caught by the harness, not the analyst.

---

## Suggested order of execution

1. **I1 + I2** (gRPC limiter correctness) — product bug, small diff, big
   trust win; unblocks advertising gRPC prod posture.
2. **I3** (defaults revision + docs) — pairs naturally with I1 in one PR
   ("rate-limit posture v2"); public §7.2 already states the proposal.
3. **I5** (CC/TLS plateau sweep) and **I6** (REST session read) — the two
   remaining perf unknowns; both are measurement-first tasks.
4. **C-block SDK fixes** (I9–I13) — independent, parallelizable per repo.
5. **D-block harness items** (I15–I19; I14 done) — before run 5.
6. **Run 5**: full matrix + fixed batch default + KC-login 4 GiB cell +
   SDK median-of-3 with wire baseline + re-run `sens-rl-prod` post-I1.
7. **I7** (SurrealDB ceiling) — the long-pole product investment, start
   after the quick wins land.
