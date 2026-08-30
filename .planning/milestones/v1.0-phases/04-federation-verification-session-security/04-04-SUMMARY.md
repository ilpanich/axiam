---
phase: 04-federation-verification-session-security
plan: 04
subsystem: auth-session-security
tags: [session-revocation, password-change, password-reset, mfa-reset, oauth2-refresh, audience-narrowing, REQ-7]
requires:
  - "04-01: jti = session.id plumbing; AuthConfig.allow_missing_aud_as_user; AUD_USER/AUD_M2M"
  - "04-03: settings/policy resolution"
provides:
  - "POST /api/v1/auth/password/change (authenticated, current-password re-verify, selective session revocation)"
  - "AuthService::change_password / revoke_all_sessions_except"
  - "SessionRepository::invalidate_user_sessions_except (DB-level)"
  - "RefreshTokenRepository::revoke_all_for_user (OAuth2-flow user-wide revoke)"
  - "AuthenticatedUser.session_id; aud narrowed to axiam:user; AuthenticatedServiceAccount extractor"
  - "PasswordResetService extended with SessionRepository + RefreshTokenRepository (6 generic params)"
affects:
  - crates/axiam-api-rest
  - crates/axiam-server
  - crates/axiam-auth
  - crates/axiam-core
  - crates/axiam-db
tech-stack:
  added: []
  patterns:
    - "Selective session invalidation preserving current session (jti == session.id)"
    - "Dual-chokepoint refresh-token revocation (session-flow + OAuth2-flow)"
    - "Per-route JWT audience narrowing (axiam:user vs axiam:m2m)"
key-files:
  created:
    - crates/axiam-api-rest/tests/password_change.rs
    - crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs
    - crates/axiam-api-rest/tests/mfa_reset_still_revokes.rs
  modified:
    - crates/axiam-api-rest/src/extractors/auth.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/src/handlers/password_reset.rs
    - crates/axiam-api-rest/src/handlers/webauthn.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-auth/src/password_reset.rs
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/session.rs
    - crates/axiam-db/src/repository/oauth2_refresh_token.rs
    - crates/axiam-api-rest/tests/auth_test.rs
    - crates/axiam-api-rest/tests/rbac_test.rs
    - crates/axiam-api-rest/tests/bootstrap_test.rs
decisions:
  - "PasswordResetService extended with two generic params (S: SessionRepository, T: RefreshTokenRepository) calling repos directly — no AuthService dependency cycle (D-16/D-18)"
  - "change_password preserves the caller's current session (jti==session.id) while revoking all others + all OAuth2 refresh tokens (D-14/D-15)"
  - "password reset confirm revokes ALL sessions (no current session — caller unauthenticated, D-16)"
  - "DoS guard rejects new_password > 1024 bytes BEFORE Argon2id (T-04-21)"
  - "aud back-compat warn is unconditional (no in-process rate limit); operator log-side dedup handles burst noise (T-04-27)"
metrics:
  duration: continuation-session
  completed: 2026-05-29
---

# Phase 04 Plan 04: Federation/Verification — Session Security Summary

Authenticated `POST /api/v1/auth/password/change` with current-password re-verify and selective session invalidation; password-reset and MFA-reset now revoke all sessions; both session-flow AND OAuth2-flow refresh tokens are revoked; REST extractor audience narrowed to `axiam:user`.

## What Shipped (by task)

### Task 1 — `AuthenticatedUser.session_id` + audience narrowing (commit 8aa40c6)
- Added `pub session_id: Uuid` to `AuthenticatedUser` (parsed from `jti`, which equals `session.id` per 04-01).
- Audience narrowing on user-facing routes: `axiam:user` accepted; `axiam:m2m` rejected (401); missing `aud` accepted only when `allow_missing_aud_as_user` is true (unconditional WARN log).
- New sibling extractor `AuthenticatedServiceAccount` (inverse narrowing — accepts only `axiam:m2m`).
- Shared `parse_validated_claims` helper.
- 7 unit tests in `extractors/auth.rs`.

### Task 2 — DB-level revocation primitives (commit d0972d2)
- `SessionRepository::invalidate_user_sessions_except(tenant, user, current_session)` (trait + Surreal impl, `id != type::record('session', $current)` filter, returns count).
- `RefreshTokenRepository::revoke_all_for_user(tenant, user)` (trait + Surreal impl on `oauth2_refresh_token`, returns count, idempotent).
- Integration tests in axiam-db (`session_invalidate_except.rs`, `oauth2_refresh_revoke_all.rs`).

### Task 3a — axiam-auth service/reset wiring (commit 01628aa)
- `AuthService` gained a 4th generic param `T: RefreshTokenRepository`.
- `AuthService::change_password(tenant, user, current_session, current_pw, new_pw, policy, history_repo)` — verify current pw → policy check → hash → history → update → `revoke_all_sessions_except`.
- `AuthService::revoke_all_sessions_except` (preserve current) and `revoke_all_sessions` (revoke all) both now also call `revoke_all_for_user` (OAuth2 chokepoint).
- `PasswordResetService<U,R,F,H,S,T>` extended with `session_repo: S`, `refresh_token_repo: T`; `confirm_reset` now invalidates all sessions + OAuth2 refresh tokens; `TODO(T19)` removed.
- All in-file unit-test call sites updated to the 6-arg `PasswordResetService::new`.

### Task 3b — axiam-api-rest wiring + tests (this continuation session — commits below)
- **handlers/auth.rs:** `ChangePasswordRequest` struct + `change_password<C>` handler (DoS guard `new_password.len() > 1024` → 422-mapped Validation; resolve tenant→effective policy; call `svc.change_password(...)`; return 204). Fixed `AuthSvc<C>` type alias to 4 generic params (added `SurrealRefreshTokenRepository<C>`).
- **handlers/password_reset.rs:** both production `PasswordResetService::new(...)` call sites (`request_reset`, `confirm_reset`) now pass `SurrealSessionRepository<C>` + `SurrealRefreshTokenRepository<C>` injected via `web::Data`.
- **handlers/webauthn.rs:** `AuthSvc<C>` type alias updated to 4 generic params (compile fix — `AuthService` now requires `RefreshTokenRepository`).
- **server.rs:** registered `POST /api/v1/auth/password/change` under `/auth` scope, wrapped with `build_governor(rate_limit_cfg.password_reset_per_min)`, authenticated (NOT in `PUBLIC_PATHS`).
- **main.rs:** fixed `AuthService::new` call (added 4th `refresh_token_repo` arg); registered `SurrealSessionRepository`, `SurrealRefreshTokenRepository`, and `SurrealPasswordHistoryRepository` as `web::Data` so the password-change/reset handlers resolve their extractors.
- **3 integration tests** (`password_change.rs`, `password_reset_revokes_sessions.rs`, `mfa_reset_still_revokes.rs`).
- **Shared test fixtures** (`auth_test.rs`, `rbac_test.rs`, `bootstrap_test.rs`): `make_auth_service` passes the new `SurrealRefreshTokenRepository`; `test_app` macros register `SurrealRefreshTokenRepository` + `SurrealPasswordHistoryRepository`.

## Commits (this session)

| Hash | Description |
|------|-------------|
| 7bbdef3 | feat(04-04): change_password endpoint + route + reset handler 6-arg call sites (api-rest) |
| 67184ab | test(04-04): update shared test fixtures for 4-arg AuthService::new |
| 3aabcb7 | test(04-04): add password-change/reset/mfa-reset session-revocation integration tests |
| 54f73a4 | style(04-04): cargo fmt on changed api-rest files |

Prior-task commits: 8aa40c6 (Task 1), d0972d2 (Task 2), 01628aa (Task 3 auth-crate).

## Local-Compile Limitation (IMPORTANT — CI/Docker authoritative)

**`axiam-api-rest` and `axiam-server` CANNOT be compiled on this Arch host.** `axiam-federation` enables samael's `xmlsec` feature; the system `xmlsec1` is 1.3.x while samael's `-sys` bindings target 1.2.x. The build dies inside the `samael` dependency with ~80 `error[E0080]: attempt to compute 1_usize - N_usize, which would overflow` (libxml/xmlsec `-sys` const-eval skew) BEFORE the compiler ever reaches `axiam-api-rest`.

Verified during this session:
- `cargo check -p axiam-api-rest` → `error: could not compile samael (lib) due to 80 previous errors`.
- Grep for `axiam-api-rest/src|axiam-api-rest/tests|axiam-server/src` in the error output → **zero matches**. No error is attributable to code written in this plan.
- `cargo check -p axiam-auth` → **clean** (no api-rest changes leaked into the compilable crates).

**Therefore the api-rest + server changes were written by exact pattern-matching against the existing handlers/extractors/test harness, and are NOT locally compiled. CI/Docker (Debian Bookworm, xmlsec 1.2.x) is authoritative.** All changed files for CI failure tracing:
- `crates/axiam-api-rest/src/handlers/auth.rs`
- `crates/axiam-api-rest/src/handlers/password_reset.rs`
- `crates/axiam-api-rest/src/handlers/webauthn.rs`
- `crates/axiam-api-rest/src/server.rs`
- `crates/axiam-api-rest/src/extractors/auth.rs` (fmt only this session; logic from 8aa40c6)
- `crates/axiam-server/src/main.rs`
- `crates/axiam-api-rest/tests/password_change.rs`
- `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs`
- `crates/axiam-api-rest/tests/mfa_reset_still_revokes.rs`
- `crates/axiam-api-rest/tests/auth_test.rs`
- `crates/axiam-api-rest/tests/rbac_test.rs`
- `crates/axiam-api-rest/tests/bootstrap_test.rs`

## Pre-existing Compile-Error Fixes (deviation — Rule 3)

Commit 01628aa changed `AuthService` to require a 4th generic param (`T: RefreshTokenRepository`) and `PasswordResetService::new` to 6 args, but left the api-rest call sites at the old arities — these would NOT compile in CI. Fixed as part of this plan's api-rest wiring:
- `AuthSvc<C>` type alias (handlers/auth.rs, handlers/webauthn.rs) → added `SurrealRefreshTokenRepository<C>`.
- `AuthService::new` in `main.rs` → added the missing `refresh_token_repo` arg.
- `make_auth_service` in `auth_test.rs`, `rbac_test.rs`, `bootstrap_test.rs` → 4-arg form.

## Deviations from Plan

- **[Rule 3 — blocking compile fix] webauthn.rs `AuthSvc<C>` alias:** Not listed in the plan's `files_modified`, but `AuthService`'s new generic made it a hard compile error. Updated to 4 params. No behavior change.
- **[Rule 3 — blocking compile fix] main.rs + 3 test fixtures:** Same root cause (4-arg `AuthService::new`). Updated; registered new `web::Data` repos required by the new handlers.
- **change_password handler injects `SurrealPasswordHistoryRepository` + `SurrealSettingsRepository` + `SurrealTenantRepository` via `web::Data`** rather than the service owning them — the auth-crate `change_password` signature (from 01628aa) takes `policy` and `history_repo` as explicit args, so the REST layer resolves them. Matches the existing `confirm_reset` handler pattern.

## Verification Status

- axiam-auth: `cargo check -p axiam-auth` clean (verified this session).
- axiam-api-rest / axiam-server: **cannot compile locally** (xmlsec skew, documented above). CI authoritative.
- `cargo fmt` run on changed crates.
- Acceptance criteria (REQ-7 truths) covered by the 3 new integration tests + Task 1/2 unit/integration tests — to be confirmed green in CI.

## Self-Check: PASSED

Files (all FOUND):
- crates/axiam-api-rest/tests/password_change.rs
- crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs
- crates/axiam-api-rest/tests/mfa_reset_still_revokes.rs

Grep acceptance criteria (all pass):
- `pub struct ChangePasswordRequest` in handlers/auth.rs → 1
- `pub async fn change_password` in handlers/auth.rs → 1
- `/password/change` in server.rs → 1
- `refresh_token_repo.as_ref().clone()` in handlers/password_reset.rs → 2 (both call sites)

Commits (all FOUND in git log):
- 7bbdef3, 67184ab, 3aabcb7, 54f73a4

Caveat: api-rest/server compilation is CI-only (xmlsec 1.3 vs 1.2 skew). Local
self-check is limited to file/commit/grep presence — runtime test pass is
deferred to CI.
