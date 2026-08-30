---
phase: 09-critical-remediation
plan: "03"
subsystem: frontend
tags: [sec-remediation, typescript, react, playwright, auth, sec-044, cq-f27]
dependency_graph:
  requires: []
  provides: [authService-typed-endpoints, auth-contract-e2e-spec]
  affects: [frontend-auth-flows, e2e-contract-gates]
tech_stack:
  added: []
  patterns: [typed-service-object, playwright-route-intercept-contract]
key_files:
  created:
    - frontend/src/services/auth.ts
    - frontend/e2e/auth-contract.spec.ts
  modified:
    - frontend/src/pages/auth/ForgotPasswordPage.tsx
    - frontend/src/pages/auth/ResetPasswordPage.tsx
    - frontend/src/pages/auth/VerifyEmailPage.tsx
    - frontend/src/pages/profile/ChangePasswordPage.tsx
    - frontend/src/pages/profile/ProfilePage.tsx
    - frontend/src/pages/profile/MfaManagementPage.tsx
decisions:
  - "Keep local TotpSetupResponse interface in MfaManagementPage to preserve component structure; not replaced with imported MfaEnrollResponse (plan: 'only the network call changes')"
  - "ProfilePage retains api import for getCurrentUser/updateProfile/getMfaMethods (correct /api/v1/ calls); only resendVerification swapped to authService"
  - "Pre-existing react-hooks/set-state-in-effect lint error in MfaManagementPage deferred (out of scope — existed before 09-03)"
metrics:
  duration: "44m"
  completed: "2026-06-12T19:21:11Z"
  tasks_completed: 3
  files_changed: 8
requirements: [REQ-13]
---

# Phase 09 Plan 03: Auth Endpoint Fix (SEC-044/CQ-F27) Summary

**One-liner:** Typed authService centralising all auth routes at `/api/v1/auth/*` with Playwright contract spec gating CI.

## What Was Built

Created `frontend/src/services/auth.ts` exporting `authService` with 7 typed methods, all routing through the project's `api` axios instance (CSRF + `withCredentials`). Rewired six auth pages to call `authService.*` instead of inline `api.post("/auth/...")` calls that silently hit 404. Added `frontend/e2e/auth-contract.spec.ts` with Playwright route-intercept tests asserting each correct endpoint URL.

## Tasks Completed

| # | Task | Commit | Key Files |
|---|------|--------|-----------|
| 1 | Create typed authService | `55dd1bc` | `frontend/src/services/auth.ts` |
| 2 | Rewire six auth pages | `b4be9d3` | 6 page files |
| 3 | Playwright auth-contract spec | `5cbb7b6` | `frontend/e2e/auth-contract.spec.ts` |

## Endpoint Corrections

| Page | Was (wrong, 404) | Now (correct) |
|------|-----------------|---------------|
| ForgotPasswordPage | POST `/auth/forgot-password` | POST `/api/v1/auth/reset` |
| ResetPasswordPage | POST `/auth/reset-password` | POST `/api/v1/auth/reset/confirm` |
| VerifyEmailPage | GET `/auth/verify-email?token=` | GET `/api/v1/auth/verify-email?token=` |
| ProfilePage (resend) | POST `/auth/resend-verification` | POST `/api/v1/auth/resend-verification` |
| ChangePasswordPage | POST `/auth/change-password` | POST `/api/v1/auth/password/change` |
| MfaManagementPage (enroll) | POST `/auth/mfa/setup` | POST `/api/v1/auth/mfa/setup/enroll` |
| MfaManagementPage (confirm) | POST `/auth/mfa/confirm` | POST `/api/v1/auth/mfa/setup/confirm` |

## Deviations from Plan

### Pre-existing Issues (Not Introduced, Not Fixed)

**1. [Pre-existing] tsconfig.app.json baseUrl deprecation**
- `TS5101: Option 'baseUrl' is deprecated` — existed before 09-03, outside scope.
- `npx tsc -b` produces this warning; my files add zero TypeScript errors.

**2. [Pre-existing] react-hooks/set-state-in-effect in MfaManagementPage**
- The `setCopied(false)` inside `useEffect` in the TOTP dialog existed before this plan.
- Deferred to deferred-items.md per scope boundary rule.

### Plan-Driven Adjustments (Not Deviations)

- ProfilePage retained its `api` import because `getCurrentUser`, `updateProfile`, and `getMfaMethods` are correct `/api/v1/` calls — only `resendVerification` needed replacement.
- `TotpSetupResponse` local interface kept in MfaManagementPage for component prop/state types; plan said "preserve component structure."

## Verification

- `npx tsc -b`: Only pre-existing `TS5101` deprecation; zero new errors.
- Lint on all plan-created/modified files: **no issues** (only pre-existing MfaManagementPage issue).
- `npx playwright test --list e2e/auth-contract.spec.ts`: 7 tests enumerated (skipped = no server; spec parses and compiles correctly).
- Stale URL grep (`/auth/forgot-password`, `/auth/reset-password`, etc. in `src/pages`): returns only router `to=` navigation links, no API calls.
- `authService.` pattern: present in all 6 pages.

## Contract Test Structure (09-04 Append-Friendly)

`auth-contract.spec.ts` uses one `test.describe("Auth endpoint contract")` outer block with per-flow inner `test.describe` blocks (ForgotPasswordPage, ResetPasswordPage, VerifyEmailPage, ProfilePage, ChangePasswordPage, MfaManagementPage). Phase 09-04 can append additional `test.describe` blocks at the end of the outer describe without conflict.

## Known Stubs

None — authService methods call real endpoints; no hardcoded data flows to UI rendering.

## Threat Flags

No new trust-boundary surfaces introduced. This plan only corrects existing frontend network paths.

## Self-Check: PASSED

- `frontend/src/services/auth.ts`: EXISTS
- `frontend/e2e/auth-contract.spec.ts`: EXISTS
- `git log --oneline | grep 55dd1bc`: FOUND (`feat(09-03): create typed authService...`)
- `git log --oneline | grep b4be9d3`: FOUND (`feat(09-03): rewire six auth pages...`)
- `git log --oneline | grep 5cbb7b6`: FOUND (`test(09-03): add Playwright auth-contract spec...`)
- `grep "/api/v1/auth/reset" frontend/src/services/auth.ts`: FOUND
- `grep "authService\." frontend/src/pages/auth/ForgotPasswordPage.tsx`: FOUND
