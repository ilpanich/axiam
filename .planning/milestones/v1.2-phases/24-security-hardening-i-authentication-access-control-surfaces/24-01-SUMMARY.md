---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 01
subsystem: auth
tags: [totp, mfa, surrealdb, cas, replay-protection, axiam-auth, axiam-db]

# Dependency graph
requires:
  - phase: 10-high-remediation
    provides: totp_last_used_step field on User, verify_code_with_replay_check step-based replay check (10-05)
provides:
  - "Atomic CAS in SurrealUserRepository::update_totp_step (Repository::update_totp_step now returns AxiamResult<bool>)"
  - "verify_code_with_replay_check returns the actual matched TOTP step (incl. -1 skew), not always current_step"
  - "AuthService::verify_mfa and AuthService::confirm_mfa both persist the matched step via the CAS and reject on a lost CAS"
  - "totp_last_used_step now seeded at MFA enrollment-confirm time, not just at first login"
affects: [25-security-hardening-ii-federation-pki-data-infra, 26-correctness-resilience]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "SurrealDB CAS via SELECT ... FROM (UPDATE ... WHERE guard) subquery, reused from oauth2_auth_code.rs::consume, applied to update_totp_step"
    - "matched-step probing: verify HMAC across the ±1 skew window via totp.check_current(), then re-derive which candidate step (current_step-1/current_step/current_step+1) matched via totp.generate(step*30) == code"

key-files:
  created:
    - crates/axiam-db/tests/totp_step_cas_test.rs
  modified:
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/user.rs
    - crates/axiam-auth/src/totp.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-federation/src/saml.rs
    - crates/axiam-auth/tests/auth_service_test.rs

key-decisions:
  - "Fix applied in AuthService::verify_mfa/confirm_mfa (axiam-auth/src/service.rs), not handlers/auth.rs — the REST handler is a thin wrapper with no MFA-specific logic; the plan's <files> listing named the wrong file for the actual call site"
  - "Reversed a prior Phase 10 decision (10-05) that kept confirm_mfa on plain verify_code specifically to avoid a same-step collision with a subsequent verify_mfa call; SECHRD-01 supersedes that by handling the collision correctly (reject as replay) instead of not seeding the step at all"

requirements-completed: [SECHRD-01]

coverage:
  - id: D1
    description: "update_totp_step is an atomic DB compare-and-set: N concurrent submissions of one valid TOTP step succeed at most once"
    requirement: "SECHRD-01"
    verification:
      - kind: integration
        ref: "crates/axiam-db/tests/totp_step_cas_test.rs#totp_step_cas_concurrent"
        status: pass
    human_judgment: false
  - id: D2
    description: "verify_code_with_replay_check records the actual matched step (incl. -1 skew), so a skew-accepted code cannot be replayed once the wall clock advances past current_step"
    requirement: "SECHRD-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/totp.rs#totp::tests::totp_skew_step_recorded"
        status: pass
    human_judgment: false
  - id: D3
    description: "AuthService::verify_mfa treats a lost update_totp_step CAS (Ok(false)) as MfaInvalidCode, indistinguishable from an invalid code"
    requirement: "SECHRD-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/tests/auth_service_test.rs#mfa_login_challenge_flow"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/tests/auth_service_test.rs#reset_mfa_clears_state_and_revokes_sessions"
        status: pass
    human_judgment: false
  - id: D4
    description: "totp_last_used_step is seeded at MFA enrollment-confirm time via the same matched-step + CAS path as login, closing the enrollment-code replay gap"
    requirement: "SECHRD-01"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/tests/auth_service_test.rs#mfa_enroll_and_confirm"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/auth_test.rs#mfa_setup_full_flow_sets_cookies"
        status: pass
    human_judgment: false

duration: 65min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 01: TOTP Replay-Window Closure Summary

**Atomic SurrealDB compare-and-set on `update_totp_step` plus actual-matched-step recording (incl. -1 skew) close the TOTP replay window across concurrent submissions, skew-tolerated codes, and MFA enrollment.**

## Performance

- **Duration:** ~65 min
- **Completed:** 2026-07-04
- **Tasks:** 3 (all `type="auto" tdd="true"`, one `tdd` implicit via test additions)
- **Files modified:** 6 (1 new test file)

## Accomplishments

- `SurrealUserRepository::update_totp_step` rewritten as an atomic CAS (`SELECT ... FROM (UPDATE ... WHERE tenant_id = $tenant_id AND (totp_last_used_step = NONE OR totp_last_used_step < $step))`), mirroring `oauth2_auth_code.rs::consume`'s proven shape. `Repository::update_totp_step` now returns `AxiamResult<bool>` instead of `AxiamResult<()>` so callers can detect a lost CAS.
- New concurrency test `totp_step_cas_test.rs` proves exactly one of 20 concurrent submissions of the same step wins the CAS, and that a subsequent replay at the same step also loses.
- `verify_code_with_replay_check` (axiam-auth) now determines WHICH candidate step in the ±1 skew window actually matched the submitted code (`current_step - 1`, `current_step`, or `current_step + 1`) instead of always reporting `current_step`, and rejects unless that matched step is strictly greater than `last_used_step`. New unit test `totp_skew_step_recorded` proves a -1-skew-accepted code cannot be replayed once the wall clock advances.
- `AuthService::verify_mfa` and `AuthService::confirm_mfa` both persist the matched step via the atomic CAS and treat `Ok(false)` (lost CAS) as `AuthError::MfaInvalidCode` — a replay or concurrent-winner CAS-miss is now indistinguishable from a wrong code.
- `totp_last_used_step` is now seeded at MFA enrollment-confirm time (not just at first login), closing the gap where the enrollment code itself could be replayed before the user's first login.

## Task Commits

1. **Task 1: Convert update_totp_step to an atomic compare-and-set + concurrency test** - `8b6a9fa` (feat)
2. **Task 2: Record the actual matched step (incl. -1 skew) and reject CAS-miss at the MFA verify handler** - `1473894` (feat)
3. **Task 3: Seed totp_last_used_step at enrollment-confirm time** - `8979cac` (feat)

**Plan metadata:** pending (this commit)

## Files Created/Modified

- `crates/axiam-core/src/repository.rs` - `Repository::update_totp_step` trait signature changed to `AxiamResult<bool>`, with doc comments explaining the CAS contract
- `crates/axiam-db/src/repository/user.rs` - `update_totp_step` rewritten as an atomic CAS subquery; new `TotpStepCasRow` minimal row struct
- `crates/axiam-db/tests/totp_step_cas_test.rs` - new concurrency test (20 parallel tasks racing one step; exactly one wins)
- `crates/axiam-auth/src/totp.rs` - `verify_code_with_replay_check` now probes and returns the actual matched step; new `totp_skew_step_recorded` unit test; extracted `TOTP_STEP_SECS`/`TOTP_SKEW` constants
- `crates/axiam-auth/src/service.rs` - `verify_mfa` and `confirm_mfa` both persist the matched step via the CAS and reject on `Ok(false)`; `confirm_mfa` switched from plain `verify_code` to `verify_code_with_replay_check`
- `crates/axiam-federation/src/saml.rs` - `NoopUserRepo` test mock's `update_totp_step` signature updated to match the new trait return type
- `crates/axiam-auth/tests/auth_service_test.rs` - fixed two tests (`mfa_login_challenge_flow`, `reset_mfa_clears_state_and_revokes_sessions`) that generated a "new" TOTP code via `generate_current()` immediately after `confirm_mfa`/`enable_mfa_for_alice`, which — now that enrollment seeds the step — collided with the just-consumed step; added a `generate_next_step_code` helper using the ±1 skew tolerance to simulate a later-step code without sleeping

## Decisions Made

- **File location correction (Task 2):** The plan's `<files>` for Task 2 named `crates/axiam-api-rest/src/handlers/auth.rs` as the MFA verify handler, but the actual `verify_mfa`/`update_totp_step` call site is `AuthService::verify_mfa` in `crates/axiam-auth/src/service.rs` — the REST handler (`handlers/auth.rs:481`) is a thin wrapper with no MFA-specific branching logic of its own (it just calls `svc.verify_mfa(input).await?`). The fix was applied at the real call site.
- **Reversed a prior Phase 10 decision (10-05-SUMMARY.md):** that summary documented "confirm_mfa uses plain verify_code for enrollment; replay tracking begins at first login" specifically because seeding the step at enrollment caused an immediate same-step `verify_mfa` call in tests to fail. SECHRD-01 explicitly requires seeding at enrollment (T-24-03), so this plan reinstates it and instead treats the same-step collision as the CORRECT rejection (a replay), fixing the two tests that encoded the old assumption rather than reverting the security fix.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed two pre-existing tests that assumed the (now closed) enrollment-replay gap**
- **Found during:** Task 3 — running `cargo test -p axiam-auth` after seeding `totp_last_used_step` at `confirm_mfa` time
- **Issue:** `mfa_login_challenge_flow` and `reset_mfa_clears_state_and_revokes_sessions` called `confirm_mfa`/`enable_mfa_for_alice` (which now seeds the step) and then generated a "new" code via `totp.generate_current()` within the same test execution (same 30s TOTP step), which the CAS correctly now rejects as a replay of the just-seeded step.
- **Fix:** Added a `generate_next_step_code` test helper that generates a code for `current_step + 1` (accepted via the existing ±1 skew tolerance, no real sleep needed) and used it at both call sites so the test models a genuinely later TOTP submission.
- **Files modified:** `crates/axiam-auth/tests/auth_service_test.rs`
- **Verification:** `cargo test -p axiam-auth --test auth_service_test` — 33/33 pass (was 31/33 before the fix)
- **Committed in:** `8979cac` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — pre-existing test bug surfaced by the correct security fix), plus 2 documented file-location/decision notes above.
**Impact on plan:** The test fix is a direct, in-scope consequence of Task 3's intended behavior change (SECHRD-01/T-24-03) — no scope creep. No production code outside the plan's stated targets was touched.

## Issues Encountered

- **Sandbox disk-space exhaustion during `cargo test -p axiam-api-rest mfa`:** this workspace's `axiam-api-rest` crate links ~15 separate integration-test binaries, each ~800MB (debug symbols across the full SAML/PKI/webauthn/crypto/SurrealDB dependency tree). Running the plan's literal verification command (`cargo test -p axiam-api-rest mfa`, which builds every test target in the crate before filtering by name) twice exhausted all available disk (`ld terminated with signal 7 [Bus error]`, then hard `ENOSPC`) even after clearing `target/debug/incremental` and pruning stale >50MB binaries. This is a pre-existing environment constraint unrelated to this plan's code changes. **Resolution:** verified the actually-affected tests via a narrower, equivalent target — `cargo test -p axiam-api-rest --test auth_test mfa` (the only test file in the crate with MFA-confirm/verify integration coverage; confirmed via grep that no other test file in the crate references `confirm_mfa`/`verify_mfa`/`totp_code`) — which built and passed cleanly (6/6 tests) both before and after the Task 3 change.
- **`utoipa-swagger-ui` build script cannot reach GitHub** (proxy returns 403 for the release zip) in this sandbox. Worked around locally via `SWAGGER_UI_DOWNLOAD_URL=file://...` pointing at a minimal hand-built stub zip (not committed; a build-time env var only, no source change). This is a pre-existing environment limitation, not a plan deviation — flagging for awareness since any future `cargo test -p axiam-api-rest` run in this sandbox will need the same workaround or network access to GitHub.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SECHRD-01 (SEC-008 TOTP replay window) fully closed: concurrent-submission race, -1-skew replay, and enrollment-code replay all now rejected.
- `Repository::update_totp_step`'s signature change (`AxiamResult<()>` → `AxiamResult<bool>`) is now the established pattern for any future CAS-based repository method in this phase (e.g. SECHRD-04's bootstrap-lock/setup-token-consumed CREATE-based uniqueness, which uses a related but distinct pattern per `24-PATTERNS.md`).
- No blockers for subsequent 24-xx plans in this phase.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

All 7 created/modified files verified present on disk; all 3 task commits (`8b6a9fa`, `1473894`, `8979cac`) verified present in git log.
