---
phase: 28-functional-completeness
plan: 02
subsystem: auth
tags: [jwt, sub_kind, rbac, service-account, oauth2, axiam-auth, axiam-api-rest]

# Dependency graph
requires:
  - phase: 28-functional-completeness (plan 01)
    provides: email-config secret hygiene groundwork (unrelated subsystem, sequential wave-1 sibling)
provides:
  - SubjectKind enum (User/ServiceAccount/OAuth2Client) on JWT access tokens
  - issue_service_account_token minting function for the SA cert-auth (device-auth) path
  - Proof (integration test) that GET /api/v1/users is RBAC-gated by users:list
  - Documented confirmation that MFA list/delete are gated by users:admin (self-service otherwise)
affects: [sdk-modeling, audit-attribution, future-phase-subject-kind-gating]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Dedicated mint function per subject shape (issue_service_account_token) instead of parameterizing the shared 49-call-site issue_access_token"
    - "#[serde(default)] claim-tolerance convention (already used for aud/scope) extended to sub_kind for backward-compat decode"

key-files:
  created: []
  modified:
    - crates/axiam-auth/src/token.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/tests/device_auth_test.rs
    - crates/axiam-api-rest/tests/user_test.rs

key-decisions:
  - "issue_service_account_token mirrors device_auth's prior aud (AUD_USER) and scope (None) values verbatim — only sub_kind differs; validate_access_token's audience allowlist already accepts AUD_USER, so no validation-path change (D-10)"
  - "Task 3 test added to user_test.rs constructs a real AuthorizationEngine (mirroring rbac_test.rs's setup) rather than reusing that file's AllowAllAuthzChecker harness, since the AllowAll harness cannot prove RBAC denial"
  - "Confirmed (no test written) that MFA list/delete gating via users:admin was already correct in mfa_methods.rs — Task 3 is documentation-only for that half"

requirements-completed: [FUNC-04]

coverage:
  - id: D1
    description: "SubjectKind enum + sub_kind claim on AccessTokenClaims; issue_access_token stamps User, issue_client_credentials_token stamps OAuth2Client, new issue_service_account_token stamps ServiceAccount"
    requirement: "FUNC-04"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/token.rs#issue_access_token_stamps_user_sub_kind, issue_client_credentials_token_stamps_oauth2_client_sub_kind, issue_service_account_token_stamps_service_account_sub_kind"
        status: pass
    human_judgment: false
  - id: D2
    description: "Pre-phase tokens without sub_kind still decode successfully and default to User; validate_access_token accepts a ServiceAccount-kinded token unchanged"
    requirement: "FUNC-04"
    verification:
      - kind: unit
        ref: "crates/axiam-auth/src/token.rs#missing_sub_kind_defaults_to_user, validate_access_token_accepts_service_account_token"
        status: pass
    human_judgment: false
  - id: D3
    description: "device_auth's SA cert-auth path mints via issue_service_account_token (TODO(T15) resolved); minted token's sub_kind decodes to service_account"
    requirement: "FUNC-04"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/device_auth_test.rs#device_auth_mints_service_account_sub_kind"
        status: pass
    human_judgment: false
  - id: D4
    description: "A non-privileged caller (no role, lacks users:list) is RBAC-denied (403) on GET /api/v1/users"
    requirement: "FUNC-04"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/user_test.rs#list_users_non_privileged_caller_returns_403"
        status: pass
    human_judgment: false
  - id: D5
    description: "MFA list/delete endpoints gate cross-user access via users:admin, self-service otherwise (verify-only, no code change)"
    requirement: "FUNC-04"
    verification: []
    human_judgment: true
    rationale: "Confirmed by direct code reading (mfa_methods.rs is_own_resource + RequirePermission::new(\"users:admin\", ...) at list_mfa_methods ~66-83 and delete_mfa_method ~107-124) per the plan's explicit no-reimplementation instruction; no new automated test was required or added for this half of Task 3, so there is no test artifact to cite."

duration: 20min
completed: 2026-07-05
status: complete
---

# Phase 28 Plan 02: Service-Account Token `sub_kind` + Admin RBAC Verification Summary

**Service-account cert-auth tokens now self-describe via a `sub_kind: "service_account"` JWT claim (new `SubjectKind` enum, informational-only per D-10), and a new integration test proves `GET /api/v1/users` genuinely 403s a non-privileged caller.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-05T18:45:36Z
- **Completed:** 2026-07-05T19:01:14Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- Added `SubjectKind` enum (`User`/`ServiceAccount`/`OAuth2Client`, snake_case serde, `Default = User`) and a `sub_kind: SubjectKind` field (`#[serde(default)]`) on `AccessTokenClaims` in `axiam-auth/src/token.rs`.
- `issue_access_token` now stamps `User`, `issue_client_credentials_token` now stamps `OAuth2Client` — both signatures unchanged, so their combined 59 call sites needed zero edits.
- Added `issue_service_account_token(user_id, tenant_id, org_id, jti, config)`, structurally cloned from `issue_client_credentials_token`, stamping `ServiceAccount` and mirroring the `aud`/`scope` values device-auth previously passed to `issue_access_token` (`AUD_USER`, no scopes).
- Replaced the `device_auth` handler's SA cert-auth call to `issue_access_token` with `issue_service_account_token`, resolving the `TODO(T15)` comment — the only mint-path call-site change outside `token.rs`.
- Added a `device_auth_test.rs` case that completes the full SA cert-auth flow and asserts the minted token's decoded `sub_kind` is `ServiceAccount`.
- Verified (code reading, no reimplementation) that `GET /api/v1/users` is gated by `users:list` and that MFA list/delete gate cross-user access via `users:admin` (self-service otherwise); added a new `user_test.rs` integration test using a real `AuthorizationEngine` (not `AllowAllAuthzChecker`) proving a no-role caller gets 403 on `GET /api/v1/users`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add SubjectKind + sub_kind claim + issue_service_account_token (D-09/D-10/D-11)** - `e02499d` (feat)
2. **Task 2: Mint ServiceAccount at the SA cert-auth call-site (resolve TODO(T15)) + assert the claim** - `d67b307` (feat)
3. **Task 3: Verify admin user-listing + MFA management are RBAC-gated (no reimplementation)** - `d300527` (test)

**Plan metadata:** (this commit) `docs: complete 28-02 plan`

## Files Created/Modified
- `crates/axiam-auth/src/token.rs` - `SubjectKind` enum, `sub_kind` claim, `issue_service_account_token`, 5 new unit tests
- `crates/axiam-api-rest/src/handlers/auth.rs` - `device_auth` SA path calls `issue_service_account_token`; `TODO(T15)` removed
- `crates/axiam-api-rest/tests/device_auth_test.rs` - new `device_auth_mints_service_account_sub_kind` test
- `crates/axiam-api-rest/tests/user_test.rs` - new real-RBAC harness (`setup_db_with_rbac`, `make_real_authz`, `create_user_no_role`, `test_app_real_authz!`) + `list_users_non_privileged_caller_returns_403` test

## Decisions Made
- `issue_service_account_token`'s `aud`/`scope` values mirror exactly what `device_auth` previously passed to `issue_access_token` (`AUD_USER`, no scopes) — only `sub_kind` differs. `validate_access_token`'s audience allowlist already accepts `AUD_USER`, so no validation-path change was needed (D-10 preserved).
- The Task 3 RBAC-denial test could not reuse `user_test.rs`'s existing `AllowAllAuthzChecker`-based `test_app!` macro (it bypasses all permission checks by design), so a parallel real-RBAC harness (mirroring `rbac_test.rs`'s `setup_db`/`make_authz`/`test_app!` pattern) was added to `user_test.rs` for this one test.
- MFA admin-gating confirmation (list/delete via `users:admin`, self-service otherwise) required no new test — the plan explicitly scoped Task 3's MFA half to code-reading verification only, to avoid reimplementing already-correct gating.

## Deviations from Plan

None — plan executed exactly as written. `issue_access_token` import in `auth.rs` was removed (it became unused after the device_auth call-site swap) as a direct, minimal consequence of Task 2's specified change, not a separate deviation.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- FUNC-04 fully closed: `sub_kind` is self-describing and backward-compatible; admin user-listing and MFA management are proven RBAC-gated.
- `sub_kind` remains informational-only per D-10 — any future phase that wants to gate endpoints by subject kind (explicitly deferred in CONTEXT.md) will need a new authz branch; none was added here.
- No blockers for subsequent phase-28 plans.

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*

## Self-Check: PASSED

All created/modified files exist on disk; all three task commit hashes (e02499d, d67b307, d300527) found in git log.
