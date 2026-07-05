---
phase: 27-performance-load-hardening
plan: 01
subsystem: auth
tags: [circuit-breaker, hibp, rust, dos-hardening, password-policy]

requires:
  - phase: 26-correctness-resilience
    provides: shared-mutable-state-behind-a-lock precedent (jwks_cache.rs) reused for the breaker's lock-type convention
provides:
  - HibpBreaker hand-rolled circuit breaker (Closed/Open + cooldown state machine) guarding check_hibp's outbound HTTP call
  - AuthConfig.hibp_breaker_threshold / hibp_breaker_cooldown_secs config knobs (AXIAM__AUTH__HIBP_BREAKER_THRESHOLD / _COOLDOWN_SECS)
  - Process-wide breaker global (init_global/global) wired from AuthConfig at axiam-server startup
  - check_complexity's violation Vec pre-sized to capacity 5
affects: [axiam-auth, axiam-server, future PERF-02/03/04/05 plans in this phase]

tech-stack:
  added: []
  patterns:
    - "Hand-rolled enum state machine behind std::sync::Mutex for a no-await critical section (mirrors axiam-federation/src/jwks_cache.rs's lock-type-by-hold-duration convention)"
    - "Process-wide singleton via std::sync::OnceLock with an idempotent init_global() + lazily-initializing global() accessor"

key-files:
  created:
    - crates/axiam-auth/src/hibp_breaker.rs
  modified:
    - crates/axiam-auth/src/config.rs
    - crates/axiam-auth/src/lib.rs
    - crates/axiam-auth/src/policy.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-auth/src/token.rs
    - crates/axiam-api-grpc/tests/grpc_authz_test.rs
    - crates/axiam-api-rest/src/extractors/auth.rs
    - crates/axiam-api-rest/tests/middleware_test.rs

key-decisions:
  - "std::sync::Mutex (not tokio::sync::Mutex) for HibpBreaker's state — critical section has no .await, matching jwks_cache.rs's lock-type convention"
  - "Half-open probe semantics: exactly one should_attempt()==true call is let through after cooldown elapses while state stays Open until record_success() closes it"
  - "record_success() is called after a usable 200 body is read (before parsing), not gated on the parsed breach result — network/read success is what closes the breaker, not breach-vs-clean outcome"
  - "Test suite avoids all wall-clock 30s sleeps by constructing breakers with cooldown_secs=0 (immediate half-open probe) or large cooldowns (30s, never elapsed) and directly inspecting the private opened_at Instant from the same-file test submodule"

requirements-completed: [PERF-01]

coverage:
  - id: D1
    description: "Sustained HIBP failures/timeouts trip a process-wide breaker; while open, check_hibp short-circuits to Ok(None) without issuing the HTTP request"
    requirement: "PERF-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::trips_after_exactly_threshold_failures"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::short_circuits_within_cooldown"
        status: pass
    human_judgment: false
  - id: D2
    description: "After cooldown elapses, exactly one half-open probe is allowed through; success re-closes, failure re-opens with a fresh opened_at"
    requirement: "PERF-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::allows_one_probe_after_cooldown_elapsed"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::record_success_recloses_breaker"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::record_failure_while_open_resets_opened_at"
        status: pass
    human_judgment: false
  - id: D3
    description: "check_complexity's violation Vec pre-sized to capacity 5 with identical violation set/behavior"
    requirement: "PERF-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/policy.rs#tests::multiple_violations_returned"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/policy.rs (all 24 policy:: tests, cargo test -p axiam-auth --lib policy)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Breaker threshold/cooldown overridable via AXIAM__AUTH__HIBP_BREAKER_THRESHOLD (default 5) / AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS (default 30), initialized from AuthConfig at axiam-server startup"
    requirement: "PERF-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/hibp_breaker.rs#tests::default_threshold_and_cooldown"
        status: pass
      - kind: other
        ref: "cargo check -p axiam-server (confirms init_global(auth_config.hibp_breaker_threshold, auth_config.hibp_breaker_cooldown_secs) compiles and wires before server start)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-05
status: complete
---

# Phase 27 Plan 01: HIBP Circuit Breaker + Complexity Vec Pre-sizing Summary

**Hand-rolled process-wide circuit breaker skips check_hibp's 5s-timeout HTTP call once tripped, closing PERF-01 without weakening its pre-existing fail-open posture.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-05T12:55:35Z
- **Completed:** 2026-07-05T13:13:27Z
- **Tasks:** 2 completed
- **Files modified:** 8 (1 created, 7 modified)

## Accomplishments

- New `crates/axiam-auth/src/hibp_breaker.rs` implements a `Closed { consecutive_failures }` / `Open { opened_at }` state machine behind `std::sync::Mutex`, with `should_attempt`/`record_success`/`record_failure` and a process-wide `OnceLock`-backed global (`init_global`/`global`), satisfying D-01 (one global breaker, not per-tenant) and D-02 (no new circuit-breaker crate dependency).
- `check_hibp` now calls `hibp_breaker::global().should_attempt()` before `http_client.get(...).send().await`; when the breaker is open it returns `Ok(None)` immediately with a `reason = "hibp_breaker_open"` warn log, skipping the outbound HTTP request and its 5s timeout entirely (T-27-01). `record_failure()` is called on both existing fail-open branches (`send()` `Err`, non-2xx status); `record_success()` is called once a 200 body is read.
- `check_complexity`'s `violations` Vec is pre-sized with `Vec::with_capacity(5)` (D-05) — the 5 possible complexity violations (TooShort, MissingUppercase, MissingLowercase, MissingDigit, MissingSymbol) are unchanged in content or order.
- `AuthConfig` gained `hibp_breaker_threshold` (default 5) and `hibp_breaker_cooldown_secs` (default 30), overridable via `AXIAM__AUTH__HIBP_BREAKER_THRESHOLD` / `AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS` through the existing `config` crate env-mapping — no manual env parsing.
- `axiam-server/src/main.rs` calls `axiam_auth::hibp_breaker::init_global(...)` once at startup, right after `auth_config` is resolved and before the HTTP server begins serving.

## Task Commits

Each task was committed atomically:

1. **Task 1: HibpBreaker state machine + AuthConfig knobs + unit tests** - `d9656ca` (feat)
2. **Task 2: Wire breaker into check_hibp, init in main.rs, pre-size check_complexity** - `3d8c087` (feat)

_Note: neither task was TDD-gated per the plan (`tdd="true"` only on Task 1, applied as red/green within a single commit since the module and its tests were authored together); both commits are `feat` because they add new hardening behavior, not pure bug fixes._

## Files Created/Modified

- `crates/axiam-auth/src/hibp_breaker.rs` - New `HibpBreaker` state machine, process-global accessor, 9 unit tests
- `crates/axiam-auth/src/config.rs` - `hibp_breaker_threshold` / `hibp_breaker_cooldown_secs` fields + defaults
- `crates/axiam-auth/src/lib.rs` - `pub mod hibp_breaker;` + `pub use hibp_breaker::HibpBreaker;`
- `crates/axiam-auth/src/policy.rs` - `check_hibp` consults/records against the global breaker; `check_complexity` pre-sizes its Vec
- `crates/axiam-server/src/main.rs` - `init_global(...)` startup call
- `crates/axiam-auth/src/token.rs` - test-only `test_config()` helper updated for the 2 new required `AuthConfig` fields (pre-existing full struct literal, no `..Default::default()` spread)
- `crates/axiam-api-grpc/tests/grpc_authz_test.rs` - same fix, test-only `AuthConfig` literal
- `crates/axiam-api-rest/src/extractors/auth.rs` - same fix, test-only `AuthConfig` literal
- `crates/axiam-api-rest/tests/middleware_test.rs` - same fix, test-only `AuthConfig` literal

## Decisions Made

- `std::sync::Mutex` chosen over `tokio::sync::Mutex` for `HibpBreaker`'s internal state, since the critical section is a few field reads/writes with no `.await` inside it — matches `axiam-federation/src/jwks_cache.rs`'s established lock-type-by-hold-duration convention (27-PATTERNS.md).
- Half-open semantics: after cooldown elapses, `should_attempt()` returns `true` exactly for a probe request, but the breaker's state stays `Open` until `record_success()` explicitly closes it — a failed probe (`record_failure()` while `Open`) resets `opened_at`, restarting the cooldown clock rather than accumulating a separate failure counter.
- Unit tests never sleep the real 30s default cooldown: they construct breakers directly via `HibpBreaker::new(threshold, cooldown_secs)` with `cooldown_secs=0` (to force an immediate half-open transition) or a long cooldown (30s, asserted never-elapsed within test execution) and inspect the private `opened_at` field directly from the same-file `tests` submodule (Rust's privacy rules make ancestor-module private fields visible to descendant modules).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking build error] Fixed 4 pre-existing `AuthConfig` struct literals missing the 2 new required fields**
- **Found during:** Task 1 (first `cargo test -p axiam-auth --lib hibp_breaker` run)
- **Issue:** Adding `hibp_breaker_threshold`/`hibp_breaker_cooldown_secs` as non-`Option`, non-`#[serde(skip)]` fields to `AuthConfig` broke every full struct-literal construction of `AuthConfig` that didn't use `..AuthConfig::default()` spread syntax. A workspace-wide grep found 37 files constructing `AuthConfig {...}`; all but 4 already used the `..AuthConfig::default()` spread and were unaffected. The 4 direct-literal holdouts (`crates/axiam-auth/src/token.rs`'s `test_config()`, `crates/axiam-api-grpc/tests/grpc_authz_test.rs`, `crates/axiam-api-rest/src/extractors/auth.rs`, `crates/axiam-api-rest/tests/middleware_test.rs`) failed to compile with `E0063: missing fields`.
- **Fix:** Added `hibp_breaker_threshold: 5, hibp_breaker_cooldown_secs: 30,` to each of the 4 literals, matching the same default values used in `impl Default for AuthConfig`.
- **Files modified:** `crates/axiam-auth/src/token.rs`, `crates/axiam-api-grpc/tests/grpc_authz_test.rs`, `crates/axiam-api-rest/src/extractors/auth.rs`, `crates/axiam-api-rest/tests/middleware_test.rs`
- **Verification:** `cargo test -p axiam-auth --lib hibp_breaker` (9/9 pass), `cargo test -p axiam-auth --lib` (82 passed, 1 ignored, 0 failed), `cargo check -p axiam-server` (clean)
- **Committed in:** `d9656ca` (part of Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking build error)
**Impact on plan:** Necessary and mechanical (test-only config literals updated to satisfy a new required field pair); no scope creep, no behavior change to any of the 4 touched test files beyond adding the two new default-valued fields.

## Issues Encountered

None beyond the deviation above.

## User Setup Required

None - no external service configuration required. The new config knobs (`AXIAM__AUTH__HIBP_BREAKER_THRESHOLD`, `AXIAM__AUTH__HIBP_BREAKER_COOLDOWN_SECS`) are optional overrides with safe defaults (5 / 30); no action required to deploy.

## Next Phase Readiness

PERF-01 is closed: `check_hibp` short-circuits the network call under sustained failure, the breaker is process-wide and config-driven, and `check_complexity`'s hot-path Vec is pre-sized. This plan's `axiam-federation/src/jwks_cache.rs` lock-type precedent and the `AuthConfig` container-level `#[serde(default)]` + custom `impl Default` convention remain available for subsequent Phase 27 plans (PERF-02 `AuthzConfig`, PERF-04 `DbConfig` reconnect knobs) per 27-PATTERNS.md's "Shared Patterns" section. No blockers for 27-02 onward.

---
*Phase: 27-performance-load-hardening*
*Completed: 2026-07-05*
