---
phase: 23-security-regressions-high-findings
plan: 01
subsystem: auth
tags: [grpc, tonic, authentication, tenant-isolation, lockout, jwt, security]

# Dependency graph
requires: []
provides:
  - "axiam_auth::lockout::record_failed_login — shared failed-login/lockout accrual helper (D-06 single source of truth)"
  - "gRPC UserService and TokenService authenticated via AuthInterceptor (mirrors AuthorizationService)"
  - "gRPC GetUser/ValidateCredentials cross-validate tenant_id against verified JWT claims (fail-closed)"
  - "gRPC ValidateCredentials accrues lockout state on wrong password (SEC-026b closed on the gRPC path)"
affects: [23-security-regressions-high-findings, future-grpc-service-additions]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Shared crate-level helper (axiam_auth::lockout) as single source of truth for security-sensitive accrual logic, called from both REST and gRPC entrypoints"
    - "gRPC claims-cross-validation: identity derived from ValidatedClaims in request.extensions(), body fields cross-validated and rejected on mismatch (already established by AuthorizationServiceImpl, now replicated for UserService)"

key-files:
  created:
    - crates/axiam-auth/src/lockout.rs
  modified:
    - crates/axiam-auth/src/lib.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-api-grpc/src/server.rs
    - crates/axiam-api-grpc/src/services/user.rs
    - crates/axiam-api-grpc/tests/grpc_auth_test.rs

key-decisions:
  - "Used per-service with_interceptor (mirroring the existing AuthorizationService pattern) instead of a shared tower Layer via tonic::service::interceptor — the free-function's exact 0.14.6 signature was flagged [ASSUMED/unverified] in 23-RESEARCH.md, and with_interceptor is the proven-working primitive already in this codebase."
  - "TokenService received interceptor-only wiring (no body cross-validation) — ValidateTokenRequest/IntrospectTokenRequest carry no tenant_id/user_id field to compare against claims, per 23-RESEARCH.md Pattern 2."
  - "gRPC ValidateCredentials cross-validates tenant_id against claims before any user lookup (fail-closed, no cross-tenant credential oracle), locked per 23-RESEARCH.md Assumption A1."

requirements-completed: [SECFIX-01]

coverage:
  - id: D1
    description: "Shared axiam-auth lockout helper factored out of AuthService::record_failed_login; REST login path is behavior-preserving"
    requirement: "SECFIX-01"
    verification:
      - kind: unit
        ref: "cargo test -p axiam-auth (33 tests, incl. login_wrong_password, successful_login_resets_counter)"
        status: pass
    human_judgment: false
  - id: D2
    description: "UserService and TokenService reject calls with no bearer token (UNAUTHENTICATED)"
    requirement: "SECFIX-01"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/grpc_auth_test.rs#grpc_user_service_get_user_rejects_without_bearer_token"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/grpc_auth_test.rs#grpc_user_service_validate_credentials_rejects_without_bearer_token"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/grpc_auth_test.rs#grpc_token_service_introspect_rejects_without_bearer_token"
        status: pass
    human_judgment: false
  - id: D3
    description: "Cross-tenant GetUser (tenant-A caller token, tenant-B tenant_id/user_id in body) returns PERMISSION_DENIED"
    requirement: "SECFIX-01"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/grpc_auth_test.rs#grpc_get_user_cross_tenant_denied"
        status: pass
    human_judgment: false
  - id: D4
    description: "gRPC ValidateCredentials accrues failed-login/lockout state on wrong password via the shared helper (SEC-026b)"
    requirement: "SECFIX-01"
    verification:
      - kind: integration
        ref: "crates/axiam-api-grpc/tests/grpc_auth_test.rs#grpc_validate_credentials_wrong_password_accrues_lockout"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 01: gRPC UserService/TokenService Authentication + Shared Lockout Helper Summary

**Attached AuthInterceptor to gRPC UserService/TokenService, cross-validated tenant_id from verified JWT claims on GetUser/ValidateCredentials, and unified failed-login lockout accrual into a shared axiam_auth::lockout helper called by both REST login and gRPC ValidateCredentials.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-03
- **Tasks:** 3/3
- **Files modified:** 6 (1 created, 5 modified)

## Accomplishments
- Factored the failed-login/lockout increment logic (SEC-032 exponential backoff) out of `AuthService::record_failed_login` into a new standalone `axiam_auth::lockout::record_failed_login` helper, generic over `UserRepository`. The REST login path now delegates to it (behavior-preserving — all 33 existing `axiam-auth` tests remain green).
- Wrapped `UserServiceServer` and `TokenServiceServer` with `AuthInterceptor` in `server.rs`, closing the SEC-003 gap where any unauthenticated mesh peer could call `GetUser`, `ValidateCredentials`, or `IntrospectToken`.
- `UserServiceImpl::get_user` and `validate_credentials` now read `ValidatedClaims` from request extensions, cross-validate the body `tenant_id` against the verified claims (reject `PERMISSION_DENIED` on mismatch), and use the claims-derived `tenant_id` for the downstream repository query — never the client-supplied body value.
- `validate_credentials` now calls the shared lockout helper on an invalid password, closing the unmetered gRPC credential-check oracle (SEC-026b / D-06).
- Added 5 new negative tests to `grpc_auth_test.rs`: reject-without-token for `GetUser`, `ValidateCredentials`, and `IntrospectToken`; a cross-tenant `GetUser` test asserting `PERMISSION_DENIED`; and a lockout-accrual test driving 5 consecutive wrong-password `ValidateCredentials` calls to prove `failed_login_attempts`/`locked_until` accrue via the shared helper.

## Task Commits

Each task was committed atomically:

1. **Task 1: Factor the failed-login/lockout accrual into a shared axiam-auth helper (D-06)** - `d902c69` (feat)
2. **Task 2: Attach AuthInterceptor to User/Token services + claims cross-validation + gRPC lockout accrual** - `d545963` (feat)
3. **Task 3: Negative tests — reject-without-token, cross-tenant GetUser, gRPC lockout accrual** - `c9002f1` (test)

## Files Created/Modified
- `crates/axiam-auth/src/lockout.rs` - New shared `record_failed_login` helper (single source of truth for D-06)
- `crates/axiam-auth/src/lib.rs` - Added `pub mod lockout;`
- `crates/axiam-auth/src/service.rs` - `AuthService::record_failed_login` now delegates to the shared helper
- `crates/axiam-api-grpc/src/server.rs` - `UserServiceServer`/`TokenServiceServer` now built with `with_interceptor(AuthInterceptor)`
- `crates/axiam-api-grpc/src/services/user.rs` - `get_user`/`validate_credentials` read `ValidatedClaims`, cross-validate `tenant_id`, and call the shared lockout helper on invalid password
- `crates/axiam-api-grpc/tests/grpc_auth_test.rs` - Extended test harness to register User/Token services; added 5 new SECFIX-01 negative tests

## Decisions Made
- **Per-service `with_interceptor` over a shared tower `Layer`:** 23-RESEARCH.md flagged the `tonic::service::interceptor(...)` free-function pattern as `[ASSUMED — not independently re-verified against 0.14.6]`. Since `with_interceptor` is the proven-working pattern already used for `AuthorizationService` in this exact file, I used it for `UserService`/`TokenService` too rather than introduce an unverified API. This satisfies the plan's discretion note ("prefer a single shared tower Layer... if it stays clean, otherwise per-service `with_interceptor`") by choosing the safer, already-working option.
- **TokenService gets interceptor-only wiring:** confirmed via `proto/axiam/v1/token.proto` that `ValidateTokenRequest`/`IntrospectTokenRequest` carry only `access_token` — no tenant/user field exists to cross-validate, so no body-vs-claims comparison was added there (matches 23-RESEARCH.md Pattern 2 / Pitfall 1 guidance exactly).
- **gRPC test user must be `Active` for the lockout test to reach password verification:** `UserServiceImpl::validate_credentials`'s pre-existing account-status check runs *before* password verification (unlike the REST login flow, which checks status *after*). New users default to `PendingVerification` in `SurrealUserRepository::create`. The lockout test explicitly activates the test user via `UpdateUser { status: Some(UserStatus::Active), .. }` before driving wrong-password attempts, so the test exercises the real accrual path rather than short-circuiting on account status. This is a test-setup adjustment only — no production code path was reordered (out of scope for this plan).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Installed missing `protoc` system dependency**
- **Found during:** Task 1 (initial build verification before any code changes)
- **Issue:** `cargo build -p axiam-api-grpc` failed with `Could not find protoc` — the build.rs invokes `tonic_prost_build`/`prost-build`, which requires the `protoc` binary on `PATH`. This is a system build tool, not a project dependency (no `Cargo.toml`/`package.json` entry), so it falls outside the package-manager-install exclusion in Rule 3.
- **Fix:** Ran `apt-get install -y protobuf-compiler` (installs `protoc` 3.21.12 from the distro's package repository — a well-known, official Debian/Ubuntu package, not a third-party/unverified source).
- **Files modified:** none (system package only, no repo files changed)
- **Verification:** `cargo build -p axiam-api-grpc` and `cargo build -p axiam-api-grpc --features client` both succeed afterward.

---

**Total deviations:** 1 auto-fixed (1 blocking — missing system build tool)
**Impact on plan:** Necessary for any compilation/testing in this crate; no scope creep, no project dependency changes.

## Issues Encountered
- Initial version of the lockout-accrual test (`grpc_validate_credentials_wrong_password_accrues_lockout`) failed because the test user defaulted to `UserStatus::PendingVerification`, and `validate_credentials`'s pre-existing status check short-circuits before password verification for non-Active accounts — so the wrong-password branch (and thus the lockout accrual call) was never reached. Resolved by explicitly activating the test user via `UpdateUser` before driving the wrong-password attempts (see Decisions Made above).

## Next Phase Readiness
- SECFIX-01 fully closed: all three gRPC services require a verified bearer token, `GetUser`/`ValidateCredentials` trust claims over body, and `ValidateCredentials` meters every failed credential check via the single-source-of-truth `axiam_auth::lockout` helper.
- The `axiam_auth::lockout::record_failed_login` helper is now available for any future credential-check path that needs lockout accrual (per 23-CONTEXT.md Integration Points).
- No blockers for subsequent Phase 23 plans (23-02 through 23-06 address SECFIX-02..06, independent subsystems).

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

All created/modified files verified present on disk; all 3 task commits (`d902c69`, `d545963`, `c9002f1`) verified present in `git log`.
