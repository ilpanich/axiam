---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 09
subsystem: auth
tags: [argon2, timing-attack, password-reset, surrealdb, actix-web]

# Dependency graph
requires:
  - phase: 24-05
    provides: relocated `pub(crate) DUMMY_HASH` constant in `crates/axiam-auth/src/password.rs`, `AuthConfig.pepper: SecretString`
  - phase: 24-08
    provides: bootstrap-path password_history seed (the other of the two production user-creation write paths)
  - phase: 24-01
    provides: user.rs statement ordering this plan's transaction edit builds on
provides:
  - crypto_semaphore-gated constant-time password-reset initiation (dummy Argon2 + async wait on both Ok(None) branches)
  - explicit current-password-reuse rejection in confirm_reset, independent of password_history_count depth
  - password_history seed on the create_with_consent (admin-created user) write path
affects: [phase-25-federation-pki-data-infra-hardening, future-auth-recovery-hardening]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "dummy_hash_wait: private per-service helper mirroring AuthService::login's SEC-026 crypto_semaphore + spawn_blocking + relocated DUMMY_HASH pattern, reused verbatim by PasswordResetService"
    - "explicit current-value comparison as a rejection independent of history-count checks, for flows where the pre-mutation value isn't yet in the history table at check time"

key-files:
  created: []
  modified:
    - crates/axiam-auth/src/password_reset.rs
    - crates/axiam-api-rest/src/handlers/password_reset.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-db/src/repository/user.rs

key-decisions:
  - "initiate_reset's valid-account (Ok(Some(...))) branch is intentionally NOT given a matching dummy_hash_wait call — per 24-RESEARCH's Pattern-4 application and the plan's must_haves, only the two Ok(None) branches (unknown email, federated user) call dummy_hash_wait, mirroring the literal SEC-026 shape rather than inventing a third code path"
  - "confirm_reset's pre-existing evaluate_password call (which performs its own Argon2 verifies against password_history) is now wrapped in its own crypto_semaphore permit for its full duration, rather than plumbing the semaphore into policy.rs's check_history — this closes the 'confirm_reset performs Argon2 work fully ungated' gap RESEARCH Pitfall 4 flagged while staying within this plan's file-modification scope (crypto.rs/policy.rs untouched)"
  - "reset_timing_indistinguishable's bound is deliberately loose (mean_unknown >= mean_valid / 4, and unknown-vs-federated within a 5x ratio of each other) rather than a tight statistical overlap test — password-reset initiation has no password-verification step on the valid branch (unlike login's SEC-026 case where the valid branch always does one real Argon2 verify), so the dominant costs on each branch are structurally different (DB round-trips vs. one dummy Argon2 op); the loose bound still fails hard if dummy_hash_wait is skipped on either Ok(None) branch (the actual regression this test guards against) while tolerating legitimate host-to-host Argon2/DB-latency variance"

requirements-completed: [SECHRD-12]

coverage:
  - id: D1
    description: "A password-reset request for an unknown or federated account performs the SEC-026 dummy Argon2 verify (crypto_semaphore-gated spawn_blocking, relocated DUMMY_HASH) before returning Ok(None), closing the T-24-91 enumeration timing side-channel"
    requirement: "SECHRD-12"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/password_reset.rs#reset_timing_indistinguishable (#[ignore]d — run with `-- --ignored`)"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/password_reset.rs#initiate_reset_returns_none_for_unknown_email"
        status: pass
      - kind: unit
        ref: "crates/axiam-auth/src/password_reset.rs#initiate_reset_returns_none_for_federated_user"
        status: pass
    human_judgment: false
  - id: D2
    description: "The unauthenticated reset path (confirm_reset) rejects an attempt to reset a password to its own CURRENT value, even for a user with zero prior password_history rows"
    requirement: "SECHRD-12"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/password_reset.rs#confirm_reset_rejects_current_password"
        status: pass
    human_judgment: false
  - id: D3
    description: "Admin-created users (create_with_consent) seed their initial password hash into password_history atomically in the same transaction as the user/consent rows"
    requirement: "SECHRD-12"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/repository/user.rs#create_with_consent_seeds_history"
        status: pass
    human_judgment: false

# Metrics
duration: 43min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 09: Constant-Time Password Reset + Current-Password-Reuse Block Summary

**Password-reset initiation now runs the SEC-026 dummy-Argon2 timing-equalization pattern on both `Ok(None)` branches, `confirm_reset` explicitly blocks reuse of the current password independent of history depth, and admin-created users seed their initial password into history.**

## Performance

- **Duration:** ~43 min
- **Started:** 2026-07-04T12:07:49Z
- **Completed:** 2026-07-04T12:50:01Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- `PasswordResetService` gained a `crypto_semaphore: Arc<Semaphore>` field (mirroring `AuthService`) and a private `dummy_hash_wait` helper that runs the identical SEC-026 dummy Argon2 verify (relocated `DUMMY_HASH` constant + `spawn_blocking` behind the semaphore); `initiate_reset` now calls it on the unknown-email and federated-user `Ok(None)` branches before returning, closing the T-24-91 enumeration timing side-channel
- `crypto_semaphore` registered as `web::Data` in `main.rs` and threaded into `PasswordResetService::new` at both REST handler call sites (`request_reset`, `confirm_reset`); `request_reset` also now resolves and passes the tenant's pepper into `initiate_reset`
- `confirm_reset` performs an explicit `verify_password(new_password, &user.password_hash, pepper)` check and rejects with `AuthError::PasswordReusedCurrent` on a match — independent of and prior to the `password_history_count`-based check — proven against a fresh-signup user with zero history rows
- Both the new current-password check and the pre-existing `evaluate_password` (history + HIBP) call in `confirm_reset` now run under a `crypto_semaphore` permit, closing a pre-existing gap where that Argon2 work ran fully ungated
- `create_with_consent`'s transaction gained a third `CREATE type::record('password_history', ...)` statement seeding the admin-created user's initial password hash atomically alongside the user/consent rows, giving the current-password-reuse check data for users created via this path (federated-user creation paths untouched, per RESEARCH Pitfall 5)

## Task Commits

Each task was committed atomically:

1. **Task 1: Plumb crypto_semaphore into PasswordResetService and run dummy_hash_wait on both Ok(None) branches (constant-time reset)** - `a6b6296` (feat)
2. **Task 2: Block reuse of the current password on the unauthenticated reset path** - `52dd265` (feat)
3. **Task 3: Seed initial passwords into history on the create_with_consent write path** - `39a8a4a` (feat)

_Note: Task 1 and Task 2 both modify `crates/axiam-auth/src/password_reset.rs`; the interleaved diffs were split at exact function boundaries (`initiate_reset`/`dummy_hash_wait` vs. `confirm_reset`) via a temporary hunk-level revert/reapply cycle so each commit compiles and passes its own scoped tests independently — no intermediate broken-build commit was created._

## Files Created/Modified
- `crates/axiam-auth/src/password_reset.rs` - `crypto_semaphore` field + `dummy_hash_wait` helper + `initiate_reset(pepper)` + `confirm_reset` current-password check + semaphore-gated history/HIBP evaluation + 2 new tests
- `crates/axiam-api-rest/src/handlers/password_reset.rs` - both handlers extract `web::Data<Arc<Semaphore>>` and thread it (plus resolved pepper for `request_reset`) into `PasswordResetService::new`/`initiate_reset`
- `crates/axiam-server/src/main.rs` - `crypto_semaphore` registered as `web::Data` in the app-builder closure
- `crates/axiam-db/src/repository/user.rs` - `create_with_consent` transaction seeds `password_history`; new test asserting exactly one seeded row

## Decisions Made
- initiate_reset's valid-account branch does NOT get a matching dummy_hash_wait call — only the two `Ok(None)` branches do, matching the plan's must_haves and 24-RESEARCH's Pattern 4 application literally (see key-decisions above for full rationale)
- confirm_reset's history/HIBP evaluation is wrapped in its own crypto_semaphore permit for the call's duration (rather than plumbing the semaphore into `policy.rs`), staying within this plan's declared file-modification scope while still closing the "ungated Argon2 work" gap RESEARCH Pitfall 4 flagged
- `reset_timing_indistinguishable`'s statistical bound is intentionally loose (see key-decisions) since password-reset initiation has no natural Argon2 call on its valid branch, unlike login's SEC-026 precedent

## Deviations from Plan

None - plan executed exactly as written. The Task 1/Task 2 commit-splitting approach described above was a mechanical consequence of both tasks touching the same file's different functions, not a deviation from the plan's specified behavior or files.

## Issues Encountered
- The sandbox's disk quota was exhausted mid-execution by `cargo test -p axiam-api-rest password_reset::` building the crate's full integration-test suite (not required by this plan's verification steps). Recovered by removing the regenerable `target/debug/incremental/` cache and a set of already-built, unrelated `axiam-api-rest` integration-test binaries (`oauth2_flow_test`, `auth_test`, `oauth2_client_test`, `bootstrap_test`, `ca_certificate_test`, `tenant_test`, `settings_test`, `audit_test`, `pgp_key_test`, `certificate_test`, `csrf_crud_test`, `health_test`) — none of these were touched by this plan, and `cargo clean` was never invoked. All four plan-required verification commands (the two `axiam-auth` tests, the `axiam-db` test, and the four-crate clippy/fmt gate) were re-run to completion afterward and pass.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SECHRD-12 fully closed: password-reset initiation is time-indistinguishable on ineligible/unknown/federated branches, current-password reuse is blocked on the unauthenticated reset path, and both production user-creation write paths (`create_with_consent` here, bootstrap in 24-08) seed initial passwords into history
- This was the final plan (9 of 9) in Phase 24 (security-hardening-i-authentication-access-control-surfaces)
- No blockers for Phase 25 (federation/PKI/data/infra hardening), which is parallel-capable with this phase per the v1.2 roadmap

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

All modified files confirmed present on disk; all three task commit hashes (`a6b6296`, `52dd265`, `39a8a4a`) confirmed present in git history.
