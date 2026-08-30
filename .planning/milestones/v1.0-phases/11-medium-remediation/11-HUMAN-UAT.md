---
status: partial
phase: 11-medium-remediation
source: [11-VERIFICATION.md]
started: 2026-06-13T18:55:00Z
updated: 2026-06-13T18:55:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Route guard renders ForbiddenPage
expected: Logged in as a low-privilege user, navigating to a route the user lacks permission for (e.g. `/users`) renders the friendly "Access Denied" ForbiddenPage — not a blank screen, not a redirect loop. Source wired at `frontend/src/components/ProtectedRoute.tsx:30` (`<ForbiddenPage />` on `!can(permission)`).
result: [pending]

### 2. Login MFA branch routing
expected: A login response of `mfa_required` navigates to the MFA verification flow; a response of `mfa_setup_required` navigates to the MFA setup flow. Source wired at `frontend/src/pages/LoginPage.tsx:107` (handles `mfa_setup_required`).
result: [pending]

### 3. Tenant/org slug restore on hard reload
expected: After a hard browser reload of an authenticated page, the tenant/org slugs are restored from the `/auth/me` response (not fabricated client-side); sidebar and routes use the correct slug. Source wired at `frontend/src/hooks/useAuthInit.ts:46-47` (`setTenantContext` from `/auth/me`).
result: [pending]

### 4. Dummy-Argon2 timing parity (optional)
expected: Login latency for a known-but-wrong-password user is comparable to a non-existent user (no user-enumeration timing side channel). Source wired at `crates/axiam-auth/src/service.rs:218-223` (`spawn_blocking(verify_password("dummy", DUMMY_HASH, ...))` on user-not-found). Primary proof is the source assertion; this manual timing check is optional corroboration.
result: [pending]

## Summary

total: 4
passed: 0
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps
