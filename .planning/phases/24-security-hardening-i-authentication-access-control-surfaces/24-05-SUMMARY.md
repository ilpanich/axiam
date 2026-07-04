---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 05
subsystem: auth
tags: [zeroize, secrecy, argon2, secret-hygiene, password-hashing]

# Dependency graph
requires:
  - phase: 24-security-hardening-i-authentication-access-control-surfaces
    provides: SEC-026 dummy-Argon2 timing-equalization pattern (AuthService::login) that this plan relocates DUMMY_HASH out of
provides:
  - "zeroize::Zeroizing<String> wrapping of the peppered-password buffer in hash_password/verify_password (drop-based wipe on every exit path)"
  - "AuthConfig.pepper: Option<secrecy::SecretString> — redacting Debug, exposed only via .expose_secret() at the &str boundary"
  - "pub(crate) DUMMY_HASH relocated to crates/axiam-auth/src/password.rs, single source of truth for future 24-09 constant-time reset"
affects: [24-09 (constant-time password-reset — reuses password::DUMMY_HASH)]

# Tech tracking
tech-stack:
  added: ["zeroize 1.9.0 (workspace dependency, axiam-auth)", "secrecy 0.10.3 with serde feature (workspace dependency, axiam-auth/axiam-api-grpc/axiam-api-rest/axiam-server)"]
  patterns: ["expose_secret() called exactly once at the &str boundary consumed by hash_password/verify_password; never inside spawn_blocking closures ahead of the call, never inside tracing/log macros"]

key-files:
  created: []
  modified:
    - crates/axiam-auth/src/password.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-auth/src/config.rs
    - crates/axiam-api-rest/src/handlers/password_reset.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-grpc/src/services/user.rs
    - crates/axiam-api-rest/tests/req14_pepper_test.rs
    - Cargo.toml
    - crates/axiam-auth/Cargo.toml
    - crates/axiam-api-grpc/Cargo.toml
    - crates/axiam-api-rest/Cargo.toml
    - crates/axiam-server/Cargo.toml

key-decisions:
  - "DUMMY_HASH relocated to pub(crate) const in crates/axiam-auth/src/password.rs (was private in service.rs) so AuthService and the future PasswordResetService constant-time reset (24-09) share the identical constant"
  - "secrecy added with the serde feature (not default) so SecretString gets a Deserialize impl for AuthConfig's #[derive(Deserialize)]"
  - "Fixed two AuthConfig.pepper call sites the plan's files_modified list missed (axiam-api-grpc UserServiceImpl and the req14_pepper_test.rs integration test) — Rule 3 blocking-compile-error auto-fix, same expose_secret-at-boundary pattern"

patterns-established:
  - "Zeroizing<String> for any password+pepper concatenation buffer that is fed to Argon2 (drop-based wipe fires on ?-propagated error paths, unlike a manual trailing .zeroize() call)"
  - "SecretString for any secret value carried in a config struct across function boundaries; .expose_secret() called once, exactly where the &str is consumed"

requirements-completed: [SECHRD-12]

coverage:
  - id: D1
    description: "Peppered-password buffer in hash_password/verify_password wrapped in zeroize::Zeroizing<String>, wiped on drop including ?-propagated Argon2 error paths"
    requirement: "SECHRD-12"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/password.rs — password::tests::correct_password_matches, wrong_password_does_not_match, pepper_is_applied, malformed_hash_returns_error"
        status: pass
      - kind: other
        ref: "grep 'Zeroizing' crates/axiam-auth/src/password.rs (grep-gate per plan verification block)"
        status: pass
    human_judgment: false
  - id: D2
    description: "AuthConfig.pepper changed to Option<secrecy::SecretString> (redacting Debug); every reader across axiam-auth, axiam-api-rest, axiam-api-grpc, and axiam-server exposes the secret only at the &str boundary; Argon2id params (19456, 2, 1) unchanged"
    requirement: "SECHRD-12"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/req14_pepper_test.rs#test_user_login_with_pepper, test_user_login_pepper_mismatch_fails"
        status: pass
      - kind: unit
        ref: "cargo check -p axiam-auth -p axiam-api-rest -p axiam-server -p axiam-api-grpc"
        status: pass
      - kind: other
        ref: "cargo clippy -p axiam-auth -p axiam-api-rest -p axiam-server -p axiam-api-grpc --all-targets -- -D warnings; cargo fmt --check"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 05: Zeroize/Secrecy Secret Hygiene Summary

**Peppered-password buffer wrapped in `zeroize::Zeroizing<String>` and `AuthConfig.pepper` wrapped in `secrecy::SecretString`, closing the SECHRD-12 memory-dump/log-leak side-channel with Argon2id params unchanged.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-07-04
- **Tasks:** 2
- **Files modified:** 12 (2 task commits + docs commit)

## Accomplishments
- `hash_password`/`verify_password` now build the peppered concatenation as `zeroize::Zeroizing<String>` — the buffer is drop-wiped on every exit path, including the `?`-propagated Argon2 error path (a manual trailing `.zeroize()` would have been skipped there).
- `DUMMY_HASH` (SEC-026 timing-equalization constant) relocated from a private const in `service.rs` to `pub(crate) const DUMMY_HASH` in the password module — single source of truth for `AuthService` today and the future `PasswordResetService` constant-time reset (plan 24-09).
- `AuthConfig.pepper` changed from `Option<String>` to `Option<secrecy::SecretString>` — `Debug`/log output now redacts the pepper by default; every call site across `axiam-auth`, `axiam-api-rest`, `axiam-api-grpc`, and `axiam-server` exposes the secret exactly once, at the `&str` boundary consumed by `hash_password`/`verify_password`/`with_pepper`.
- `hash_password`/`verify_password`'s own `pepper: Option<&str>` parameter signatures are unchanged, as required — only the config-level storage type changed.
- Argon2id parameters `(19456, 2, 1)` remain untouched; no second parameter set introduced.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add zeroize/secrecy deps, wrap peppered buffer in Zeroizing, relocate DUMMY_HASH** - `68d5280` (feat)
2. **Task 2: Change AuthConfig.pepper to SecretString, fix every call site** - `a0d67be` (feat)

**Plan metadata:** committed separately (see final commit below)

## Files Created/Modified
- `crates/axiam-auth/src/password.rs` - `Zeroizing<String>` peppered buffer in `hash_password`/`verify_password`; relocated `pub(crate) const DUMMY_HASH`
- `crates/axiam-auth/src/service.rs` - Removed local `DUMMY_HASH`, references `password::DUMMY_HASH`; all `self.config.pepper` readers now call `.expose_secret()` at the `&str` boundary
- `crates/axiam-auth/src/config.rs` - `AuthConfig.pepper: Option<secrecy::SecretString>`
- `crates/axiam-api-rest/src/handlers/password_reset.rs` - `auth_config.pepper.as_ref().map(|p| p.expose_secret())` at `confirm_reset` call site
- `crates/axiam-server/src/main.rs` - Wraps the env-loaded pepper in `SecretString::from`; exposes at the `SurrealUserRepository::with_pepper` boundary
- `crates/axiam-api-grpc/src/services/user.rs` - (deviation) fixed `UserServiceImpl::validate_credentials`'s pepper read, missed by the plan's files_modified list
- `crates/axiam-api-rest/tests/req14_pepper_test.rs` - (deviation) fixed `make_auth_config`'s pepper construction, missed by the plan's files_modified list
- `Cargo.toml`, `crates/axiam-auth/Cargo.toml`, `crates/axiam-api-grpc/Cargo.toml`, `crates/axiam-api-rest/Cargo.toml`, `crates/axiam-server/Cargo.toml` - Added `zeroize`/`secrecy` workspace dependencies

## Decisions Made
- `secrecy` added with the `serde` feature (not the crate default) so `SecretString` receives a `Deserialize` impl compatible with `AuthConfig`'s `#[derive(Deserialize)]` — without it, `AuthConfig` would fail to compile once `pepper`'s type changed.
- `DUMMY_HASH` relocated to `crate::password` rather than a new shared module — RESEARCH.md's recommended location, and the natural home since the constant is itself an Argon2 PHC hash string consumed by `password::verify_password`.
- Kept `hash_password`/`verify_password`'s `pepper: Option<&str>` signatures unchanged per the plan's explicit constraint — every caller exposes the secret at its own boundary rather than pushing `SecretString` deeper into the password module's API.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed `axiam-api-grpc`'s missed `AuthConfig.pepper` call site**
- **Found during:** Task 2 (workspace-wide grep for `.pepper` after the config type change)
- **Issue:** The plan's `files_modified` list for Task 2 did not include `crates/axiam-api-grpc/src/services/user.rs`, but `UserServiceImpl::validate_credentials` reads `self.auth_config.pepper.as_deref()` directly — the `AuthConfig.pepper` type change breaks this compile site too (and `axiam-server` depends on `axiam-api-grpc`, so this was on the plan's own `cargo check -p axiam-server` verification path regardless).
- **Fix:** Added `secrecy = { workspace = true }` to `crates/axiam-api-grpc/Cargo.toml`, imported `secrecy::ExposeSecret`, and changed the call site to `self.auth_config.pepper.as_ref().map(|p| p.expose_secret())`.
- **Files modified:** `crates/axiam-api-grpc/Cargo.toml`, `crates/axiam-api-grpc/src/services/user.rs`
- **Verification:** `cargo check -p axiam-api-grpc` (and transitively `-p axiam-server`) passes; `cargo clippy -p axiam-api-grpc --lib --tests -- -D warnings` clean.
- **Committed in:** `a0d67be` (Task 2 commit)

**2. [Rule 3 - Blocking] Fixed `req14_pepper_test.rs`'s `AuthConfig` construction**
- **Found during:** Task 2 (same grep sweep)
- **Issue:** `crates/axiam-api-rest/tests/req14_pepper_test.rs::make_auth_config` constructs `AuthConfig { pepper: pepper.map(|p| p.to_owned()), .. }` — `.to_owned()` on `&str` produces a `String`, which no longer matches the `Option<SecretString>` field type.
- **Fix:** Changed to `pepper.map(secrecy::SecretString::from)`.
- **Files modified:** `crates/axiam-api-rest/tests/req14_pepper_test.rs`
- **Verification:** `cargo test -p axiam-api-rest --test req14_pepper_test` — both REQ-14 AC-1 pepper round-trip tests pass (matching pepper succeeds, mismatched pepper returns 401 not 500).
- **Committed in:** `a0d67be` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 3 — blocking compile fixes for call sites the plan's files_modified list missed)
**Impact on plan:** Both fixes are mechanical applications of the same expose_secret-at-boundary pattern used throughout the plan's named files. No scope creep, no architectural change, no new secret-handling pattern introduced.

## Issues Encountered
- To keep the two task commits properly atomic (Task 1's `cargo test -p axiam-auth password` must pass on ONLY Task 1's files, before `AuthConfig.pepper`'s type change lands in Task 2), `crates/axiam-auth/src/config.rs` and the three downstream `Cargo.toml` files were temporarily set aside (`git stash push -- <files>`, main working tree — not a linked worktree, so this is safe per the destructive-git-prohibition's worktree-only scope) while Task 1's intermediate state was verified and committed, then restored before Task 2 was verified and committed. Both intermediate and final states were independently `cargo test`/`cargo check`/`clippy`/`fmt` verified.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SECHRD-12 (T19.24) fully closed: peppered buffer zeroized, pepper redacted via `SecretString`, Argon2 params unchanged.
- `password::DUMMY_HASH` is now `pub(crate)` and ready for plan 24-09 (`PasswordResetService` constant-time reset) to reuse without introducing a second copy of the constant.
- No blockers for subsequent 24-06..24-09 plans.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

All modified files confirmed present on disk; both task commits (`68d5280`, `a0d67be`) confirmed in git log.
