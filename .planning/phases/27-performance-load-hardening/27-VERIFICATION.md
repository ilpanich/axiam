---
phase: 27-performance-load-hardening
verified: 2026-07-05T16:20:00Z
status: human_needed
score: 4/5 must-haves verified
behavior_unverified: 1
overrides_applied: 0
human_verification:
  - test: "PERF-01's ROADMAP success criterion #1 bundles three claims: (a) breaker trips/fails-open/cooldown [VERIFIED — see below], (b) 'does not starve legitimate auth flows' under actual burst load, and (c) 'hot-path vectors are pre-sized'. REQUIREMENTS.md's own acceptance-criteria checklist (updated by 27-01's own commit) leaves (b) and part of (c) explicitly UNCHECKED: 'Load test: a credential-stuffing burst does not starve legitimate flows' has no checkbox ticked at all, and the pre-sizing line is annotated 'no authz-middleware path-segment Vec exists ... SDK serialization maps not yet addressed'."
    expected: "Either confirm this is an accepted, deliberate scope reduction (the phase's own CONTEXT.md/RESEARCH.md/DISCUSSION-LOG.md document a locked decision to defer k6/HTTP-level load testing to 'a future performance milestone' and to treat 'SDK serialization maps' pre-sizing as never-investigated/out-of-scope), or require a follow-up plan/phase to close the literal REQUIREMENTS.md checkboxes before shipping this phase as fully done."
    why_human: "This is a scope/acceptance-criteria judgment call, not something grep can resolve: the underlying breaker MECHANISM is proven correct by 9/9 passing unit tests plus direct source read (should_attempt() gate precedes the 5s-timeout HTTP call in check_hibp), but no load/burst test exists anywhere in the repo that exercises real concurrent HTTP traffic against a login/registration endpoint to empirically prove 'legitimate flows are not starved.' A human must decide whether the unit-level proof is sufficient to close ROADMAP SC#1 as written, given REQUIREMENTS.md's own tracking still shows these sub-items unchecked."
gaps: []
deferred: []
---

# Phase 27: Performance & Load Hardening Verification Report

**Phase Goal:** Hot paths withstand load — HIBP failures degrade gracefully, batch authz parallelizes, JWKS fetches coalesce, DB reconnects back off with jitter, and critical paths are profiled with documented numbers
**Verified:** 2026-07-05T16:20:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria, PERF-01..05)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1a | A credential-stuffing burst trips `check_hibp`'s circuit breaker, which fails open (`Ok(None)`) for a cooldown window (PERF-01) | VERIFIED | `crates/axiam-auth/src/hibp_breaker.rs` state machine; independently re-ran `cargo test -p axiam-auth --lib hibp_breaker` → 9/9 pass (`trips_after_exactly_threshold_failures`, `short_circuits_within_cooldown`, `allows_one_probe_after_cooldown_elapsed`, `record_success_recloses_breaker`, `record_failure_while_open_resets_opened_at`, etc.). Source read of `policy.rs:185-191` confirms `should_attempt()` gate precedes the `.send()` HTTP call, so the network request (and its 5s timeout) is genuinely skipped once open. |
| 1b | "...does not starve legitimate auth flows"; "hot-path vectors are pre-sized" (PERF-01) | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Mechanism present + wired (see 1a) but no load/burst test exists anywhere in the repo exercising real concurrent traffic to empirically prove no starvation. REQUIREMENTS.md's own PERF-01 acceptance criteria (as last edited by 27-01's own commit `639a4d0`) leave "Load test: a credential-stuffing burst does not starve legitimate flows" unchecked, and note pre-sizing is only 1 of 3 originally-scoped targets (`check_complexity` done; "authz-middleware path-segment Vec" confirmed by 27-RESEARCH.md Pitfall 1 to not exist in the codebase, so nothing to size there; "SDK serialization maps" explicitly "not yet addressed"/never investigated). Routed to human verification below. |
| 2 | `BatchCheckAccess` (gRPC + REST) evaluates with bounded concurrency, preserves order, matches per-item results, and benchmarks faster than sequential (PERF-02) | VERIFIED | `crates/axiam-authz/src/config.rs` (`AuthzConfig.batch_max_concurrency`, default 16, unit-tested); `buffer_unordered`+`sort_by_key` confirmed in both `crates/axiam-api-grpc/src/services/authorization.rs` and `crates/axiam-api-rest/src/handlers/authz_check.rs`. Independently re-ran both correctness tests: `cargo test -p axiam-api-grpc --lib batch_check_access` → 1/1 pass; `cargo test -p axiam-api-rest --lib batch_check_access` (with `SWAGGER_UI_DOWNLOAD_URL` workaround) → 1/1 pass. Benchmark evidence: `claude_dev/performance-report.md` §4 records a real, non-fabricated criterion run — sequential 95.9ms vs. `buffer_unordered(16)` 11.4ms (≈8.4× speedup). |
| 3 | A burst of concurrent invalid-`kid` JWKS lookups triggers exactly one network fetch, across Python/Go/Rust/Java/C#/TypeScript/PHP SDKs (PERF-03) | VERIFIED | Grep-confirmed synchronization primitives wired in all 7 SDKs: Rust `fetch_lock: tokio::sync::Mutex<()>` (jwks.rs:99,180,206), Go `refreshMu sync.Mutex` (verifier.go:44,124-132), Java `ReentrantLock refreshLock` (JwksVerifier.java:91), C# `SemaphoreSlim(1,1) _fetchLock` (JwksVerifier.cs:67), Python `_refetch_lock` widened around `_get_signing_key` (_jwks.py:64,99), TypeScript documented+proven native `jose` `pendingFetch` coalescing (jwks.ts:61-64), PHP `?PromiseInterface $inFlightFetch` guard (JwksVerifier.php:67,173-184). Each SDK's own burst test is documented pass in its SUMMARY (per-SDK toolchains, not re-run here per build-hygiene scoping — Rust/Go/Java/C#/Python/TS/PHP each use independent runners outside the Rust workspace disk budget). |
| 4 | A poisoned/failed SurrealDB connection is dropped and never recycled; reconnect loop uses full-jitter exponential backoff with a ceiling and bounded retry (PERF-04) | VERIFIED | `crates/axiam-db/src/connection.rs`: `reconnect_backoff_delay` (full jitter, `rand::rng().random`), `DbConfig.reconnect_base_ms/_ceiling_ms/_max_retries` (250/30000/10 defaults), `DbManager.db: Arc<RwLock<Surreal<Client>>>`, `spawn_reconnect_loop`. Independently re-ran `cargo test -p axiam-db --lib reconnect_backoff_delay` → 3/3 pass, and `cargo test -p axiam-db --lib poisoned` → 1/1 pass (`poisoned_handle_is_evicted_and_never_returned_after_swap`). Source read of the exhaustion branch (`connection.rs:445-462`) confirms it falls into an inner `loop` sleeping the ceiling interval forever — never `break`/`return`s out of the task, matching D-11. The two `#[ignore]`d live-SurrealDB integration tests (exhaustion-stays-alive, recovery-without-restart) require `just dev-up`, unavailable in this sandbox — correctly routed to manual/CI verification, not counted as a gap per this phase's own documented scope. |
| 5 | `claude_dev/performance-report.md` records baseline-vs-optimized numbers for auth, authz-check, cert-validation from criterion benches (PERF-05) | VERIFIED | `crates/axiam-auth/benches/auth_bench.rs`, `crates/axiam-authz/benches/authz_bench.rs`, `crates/axiam-pki/benches/cert_bench.rs` all exist (confirmed on disk). `claude_dev/performance-report.md` contains real numbers (not placeholders): Argon2id hash/verify ~18.3ms, EdDSA mint ~22.2µs, single check_access ~1.45ms, batch sequential-vs-concurrent 95.9ms→11.4ms (8.4x), X.509 verify ~49.3µs. Explicitly states benches are manual/local, not CI-gated (D-15/D-16), and documents the `cargo-flamegraph` invocation as a deferred manual step (neither `perf` nor `cargo-flamegraph` installed in-sandbox, confirmed by the report's own captured command output). |

**Score:** 4/5 truths verified (1 present-but-behavior-unverified, routed to human review)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-auth/src/hibp_breaker.rs` | HibpBreaker state machine | VERIFIED | 228 lines; `pub struct HibpBreaker`, `should_attempt`/`record_success`/`record_failure`/`init_global`/`global`; 9 unit tests pass |
| `crates/axiam-auth/src/config.rs` | `hibp_breaker_threshold`/`_cooldown_secs` | VERIFIED | Fields present with documented env keys |
| `crates/axiam-authz/src/config.rs` | `AuthzConfig.batch_max_concurrency` (default 16) | VERIFIED | Full content read; default 16, 3 unit tests pass |
| `crates/axiam-api-grpc/src/services/authorization.rs` | Concurrent batch_check_access | VERIFIED | `buffer_unordered`+`sort_by_key`, correctness test passes |
| `crates/axiam-api-rest/src/handlers/authz_check.rs` | Concurrent batch_check_access | VERIFIED | `buffer_unordered`+`sort_by_key`, correctness test passes |
| `crates/axiam-db/src/connection.rs` | Full-jitter reconnect loop + RwLock handle | VERIFIED | `reconnect_backoff_delay`, `spawn_reconnect_loop`, `Arc<RwLock<Surreal<Client>>>`, `client_cloned` — all confirmed present and tested |
| `crates/axiam-server/src/main.rs` | `client_cloned().await` migration | VERIFIED | 44 occurrences of `client_cloned`; 0 remaining bare `.client()` calls |
| `crates/axiam-auth/benches/auth_bench.rs`, `axiam-authz/benches/authz_bench.rs`, `axiam-pki/benches/cert_bench.rs` | criterion benches | VERIFIED | All 3 exist on disk |
| `claude_dev/performance-report.md` | Baseline-vs-optimized report | VERIFIED | Real numbers, not placeholder text |
| 7 SDK JWKS verifiers (rust/python/go/java/csharp/typescript/php) | Single-flight guard per SDK | VERIFIED | Grep-confirmed lock/semaphore/promise primitives in all 7 files |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `check_hibp` (policy.rs) | `hibp_breaker::global()` | `should_attempt()` before `.send()`, `record_success`/`record_failure` on outcome | WIRED | Confirmed by direct source read, lines 185-236 |
| `main.rs` | `hibp_breaker::init_global` | startup call from `auth_config` | WIRED | Confirmed present (per 27-01-SUMMARY + acceptance-criteria grep) |
| gRPC/REST batch handlers | `AuthzConfig.batch_max_concurrency` | `web::Data<AuthzConfig>` / constructor param | WIRED | Confirmed field threading in `authorization.rs`/`authz_check.rs` |
| `connect_with_ttl` | `spawn_reconnect_loop` | spawned alongside `spawn_proactive_resignin` | WIRED | Confirmed via source read of `connection.rs` |
| `health_check` | current DB handle | `self.db.read().await` | WIRED | Confirmed — reads through the lock, so a swap is immediately visible |
| Each SDK's `verify()` | its single-flight guard | double-checked lock/semaphore/promise around the fetch | WIRED | Confirmed in all 7 SDKs via grep |

### Behavioral Spot-Checks (independently re-run, not trusting SUMMARY claims)

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| HibpBreaker state transitions (trip/cooldown/half-open/re-close) | `cargo test -p axiam-auth --lib hibp_breaker` | 9 passed; 0 failed | PASS |
| Reconnect backoff full-jitter bounds + ceiling clamp + variance | `cargo test -p axiam-db --lib reconnect_backoff_delay` | 3 passed; 0 failed | PASS |
| Poisoned-handle eviction (never returned post-swap) | `cargo test -p axiam-db --lib poisoned` | 1 passed; 0 failed | PASS |
| gRPC batch == sequential per-item correctness | `cargo test -p axiam-api-grpc --lib batch_check_access` | 1 passed; 0 failed | PASS |
| REST batch == sequential per-item correctness | `SWAGGER_UI_DOWNLOAD_URL=... cargo test -p axiam-api-rest --lib batch_check_access` | 1 passed; 0 failed | PASS |
| grpc_auth_test.rs compile gap (introduced by 27-01, fixed by orchestrator) | grep confirms `hibp_breaker_threshold`/`_cooldown_secs` present in `test_auth_config()` | fields present | PASS |
| Debt-marker scan across all phase-touched files (TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER) | grep across 22 key files | 0 hits | PASS (no unresolved markers) |

Per-SDK burst tests (Go/Java/C#/Python/TypeScript/PHP) were NOT independently re-run in this verification pass — each requires its own toolchain/runner outside the Rust workspace's disk budget, and each SUMMARY documents a specific pass result with commit-level evidence. This is a reasonable scoping given build-hygiene constraints; flagged here for transparency, not as a gap (source-level wiring for all 7 was independently grep-confirmed above).

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| PERF-01 | 27-01 | HIBP circuit breaker + hot-path pre-sizing | ⚠️ PARTIAL | Breaker mechanism VERIFIED; "does not starve legitimate flows" (load test) and full pre-sizing scope not completed — REQUIREMENTS.md's own tracking (updated by the phase itself) shows these unchecked. See Human Verification. |
| PERF-02 | 27-05, 27-07 | Concurrent bounded BatchCheckAccess | VERIFIED | All 3 ROADMAP sub-clauses met, including the benchmark (27-07's authz_bench, 8.4x). **Documentation inconsistency noted**: REQUIREMENTS.md's PERF-02 "Benchmark shows improvement" checkbox is still `[ ]` and the summary table still lists PERF-02 as "Pending" — this is stale bookkeeping (27-07 supplies exactly this evidence but never updated PERF-02's line back), not a functional gap. Recommend a trivial docs fix. |
| PERF-03 | 27-02, 27-03, 27-04 | JWKS single-flight across 7 SDKs | VERIFIED | All 7 SDKs wired and tested per-SDK |
| PERF-04 | 27-06 | SurrealDB reconnect resilience | VERIFIED | Full-jitter backoff, poisoned-handle eviction, exhaustion-stays-Unhealthy-forever all independently re-tested |
| PERF-05 | 27-07 | Load testing & critical-path profiling (criterion) | VERIFIED | 3 benches + populated report with real numbers |

No orphaned requirements found — all 5 PERF-01..05 IDs appear in plan frontmatter and are accounted for above.

### Anti-Patterns Found

None. Debt-marker scan (TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER/"not yet implemented"/"coming soon") across all 22 files touched by this phase's plans returned zero hits.

### Deferred Items (out of phase-27 scope, confirmed pre-existing / not phase-27 regressions)

Per `deferred-items.md` (read and cross-checked against this verification):
- Four pre-existing, unrelated C# build/test failures (`GrpcAuthzClientTests.cs`, `AmqpConsumerTests.cs`, `SensitiveRedactionTests.cs`, `Axiam.Sdk.AspNetCore` namespace typo) predate Phase 27 (confirmed via `git show HEAD:...` in the deferred-items log) — not phase-27 regressions, correctly excluded from this verification's gap list.
- The `grpc_auth_test.rs` missing `hibp_breaker_*` fields compile gap (introduced by 27-01) was already fixed by the orchestrator (commit `bbbd996`) — independently re-confirmed present in the working tree above.
- PERF-04's two `#[ignore]`d live-SurrealDB integration tests require `just dev-up` (unavailable in this sandbox) — correctly treated as manual/CI verification items, not counted as gaps.

No ROADMAP later-phase text was found addressing k6/HTTP-level load testing or "SDK serialization maps" pre-sizing (checked Phase 28/29 goals and success criteria) — these are NOT deferred-to-a-later-phase per Step 9b's matching rule; they remain open items under PERF-01's literal REQUIREMENTS.md acceptance criteria, hence routed to human verification rather than silently dropped.

### Human Verification Required

#### 1. PERF-01 scope closure: load-test + full pre-sizing scope

**Test:** Review whether the project accepts the HibpBreaker's unit-level proof (9/9 passing state-machine tests + confirmed correct call-site ordering in `check_hibp`) as sufficient evidence for ROADMAP SC#1's "does not starve legitimate auth flows" claim, in lieu of an actual k6/HTTP-level burst test against a running server. Also confirm whether "SDK serialization maps" pre-sizing (never investigated per 27-RESEARCH.md) needs a follow-up task, or whether it's accepted as out-of-scope busy-work with no measurable benefit.

**Expected:** A decision either (a) accepts the current unit-level evidence as closing PERF-01 in full (matching this phase's own locked CONTEXT.md/DISCUSSION-LOG.md decision to defer k6 load-testing to "a future performance milestone" — which would make this a documented, deliberate deferral rather than a gap), or (b) requests a small follow-up plan/phase to add the missing load-test and/or SDK-serialization pre-sizing before treating PERF-01 as done.

**Why human:** This is a judgment call about whether a state-machine unit test is an acceptable substitute for an end-to-end load/burst proof of "no starvation" — the mechanism is demonstrably correct by code inspection and unit tests (not a gap in wiring), but REQUIREMENTS.md's own literal acceptance-criteria checklist (last touched by this very phase's commits) still shows these items unchecked. A verifier cannot unilaterally decide whether the project's bar for "done" requires the literal load test or accepts the mechanism-level proof.

#### 2. Documentation bookkeeping fix for PERF-02 (low severity, not a functional gap)

**Test:** Update `.planning/REQUIREMENTS.md`'s PERF-02 "Benchmark shows improvement over the sequential implementation" line from `[ ] ... deferred to 27-07` to `[x] ... 27-07: authz_bench shows 95.9ms→11.4ms (8.4x)`, and update the summary table's PERF-02 row from "Pending" to "Complete".

**Expected:** REQUIREMENTS.md accurately reflects that 27-07 (committed after 27-05) closed this exact benchmark evidence, since the file is otherwise treated as authoritative per-requirement tracking.

**Why human:** Trivial to fix but flagged for completeness — a verifier should not silently edit REQUIREMENTS.md on the project's behalf without confirmation this is desired, since it's a planning-doc change outside this phase's own plan scope.

### Gaps Summary

No BLOCKER-level gaps found: every artifact claimed by the 7 plans exists, is substantive, and is wired; every independently re-run test (12 total across auth/db/grpc/rest) passed; no debt markers were introduced; the concurrent-batch benchmark evidence is real (not fabricated numbers). The single WARNING-level item is a scope/acceptance-criteria judgment call around PERF-01's "load test" and "full pre-sizing" sub-clauses, which the phase's own planning documents (CONTEXT.md, RESEARCH.md, DISCUSSION-LOG.md) show were deliberately narrowed to unit-level proof rather than silently dropped — but REQUIREMENTS.md's own checklist has not been updated to reflect an accepted narrower scope, so it currently reads as incomplete. A secondary, purely cosmetic bookkeeping gap exists in REQUIREMENTS.md's stale PERF-02 status line.

---

*Verified: 2026-07-05T16:20:00Z*
*Verifier: Claude (gsd-verifier)*
