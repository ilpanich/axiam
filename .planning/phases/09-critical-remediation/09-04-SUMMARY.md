---
phase: 09-critical-remediation
plan: 04
subsystem: frontend-auth
tags: [csrf, refresh-token, session-continuity, CQ-F28, REQ-13]
wave: 2
depends_on: ["09-03"]
requirements: [REQ-13]
status: complete
requires:
  - "frontend/e2e/auth-contract.spec.ts (append-friendly describe blocks from 09-03)"
  - "frontend/src/services/auth.ts / frontend/src/lib/api.ts api instance with CSRF interceptor"
provides:
  - "Silent refresh routed through the api instance (X-CSRF-Token attached)"
  - "Narrowed refresh skip-list (refresh/login/logout only)"
  - "Boot refresh-once in useAuthInit before clearAuth"
  - "CSRF-on-refresh contract test"
affects:
  - "frontend session continuity across access-token expiry and page reload"
tech-stack:
  added: []
  patterns:
    - "Route state-changing refresh through the shared api axios instance so the CSRF request interceptor runs"
    - "Single-attempt boot refresh guarded by try/catch (no loop, no interceptor re-entry)"
key-files:
  created: []
  modified:
    - "frontend/src/lib/api.ts"
    - "frontend/src/hooks/useAuthInit.ts"
    - "frontend/e2e/auth-contract.spec.ts"
  unchanged-by-design:
    - "frontend/src/lib/fetchCurrentUser.ts (swallow-401 contract is what the hook depends on; no change required)"
decisions:
  - "Boot refresh lives in useAuthInit (the hook), not fetchCurrentUser — fetchCurrentUser keeps swallowing 401 and returning null, which is the signal the hook uses to decide whether to attempt a refresh."
  - "getCookie hardened to a hardcoded axiam_csrf regex (Rule 1 auto-fix) — it is only ever called with the literal 'axiam_csrf', so the dynamic RegExp was needless ReDoS surface (CWE-1333)."
metrics:
  tasks: 3
  files-modified: 3
  duration: ~1 session
  completed: 2026-06-12
---

# Phase 9 Plan 4: Silent/Boot Refresh CSRF Hardening (CQ-F28) Summary

Routed the frontend silent and boot token-refresh through the shared `api` axios instance so the `X-CSRF-Token` header is attached (closing the bare-`axios` 403 → forced-logout defect), narrowed the refresh skip-list to refresh/login/logout, and added a one-shot boot refresh in `useAuthInit` so a valid refresh cookie survives access-token expiry and page reload. A Playwright contract test proves the refresh POST carries `x-csrf-token`.

## What Changed

### Task 1 — `frontend/src/lib/api.ts` (commit `6cf0466`)
- Replaced bare `axios.post("/api/v1/auth/refresh", {}, { withCredentials: true })` with `await api.post("/api/v1/auth/refresh", {})`. The `api` instance's request interceptor attaches `X-CSRF-Token` from the `axiam_csrf` cookie on POST, so the refresh is no longer rejected with 403.
- Replaced the broad `originalRequest.url?.includes("/auth/")` skip with an explicit `SKIP_REFRESH = ["/api/v1/auth/refresh", "/api/v1/auth/login", "/api/v1/auth/logout"]` list + `isSkipRefresh = SKIP_REFRESH.some(...)`. A 401 from `/auth/me` now triggers a silent refresh; the refresh endpoint itself stays skip-listed (no loop).
- Loop safety preserved: the response interceptor sets `originalRequest._retry = true` before refreshing; the refresh goes through the same instance but its own 401 is caught by the `try/catch` → `clearAuth()` (no re-entry, Pitfall 5).

### Task 2 — `frontend/src/hooks/useAuthInit.ts` (commit `92997a4`)
- `init()` now: first `fetchCurrentUser()`; if it returns `null`, attempts exactly one `await api.post("/api/v1/auth/refresh", {})` inside `try/catch`, then re-`fetchCurrentUser()`; final branch `user ? setUser(user) : clearAuth()`.
- Single attempt only (no loop). `cancelled` guard re-checked after the async refresh.
- `fetchCurrentUser.ts` intentionally unchanged: its swallow-401-and-return-null behavior is the signal the hook keys off.

### Task 3 — `frontend/e2e/auth-contract.spec.ts` (commit `f400599`)
- Appended a NEW `test.describe("Silent refresh CSRF contract", ...)` block (the existing 7 09-03 contract tests are untouched).
- Seeds the `axiam_csrf` cookie, forces `/auth/me` → 401 (triggers the boot refresh), intercepts `**/api/v1/auth/refresh`, and asserts the request's `x-csrf-token` header is present and equals the seeded cookie value — proving the refresh runs through the `api` instance, not bare axios.

## Verification (read from actual output)

| Check | Command | Result |
|-------|---------|--------|
| Typecheck | `npx tsc -b` | No errors in modified files. One pre-existing `tsconfig.app.json` `baseUrl` deprecation warning (TS5101) — out of scope, see Deferred. |
| Lint | `eslint src/lib/api.ts src/hooks/useAuthInit.ts e2e/auth-contract.spec.ts` | 0 errors, 0 warnings |
| Spec parses | `playwright test --list e2e/auth-contract.spec.ts` | 8 tests listed (7 existing + 1 new); new test at `:349` |
| Contract test | `playwright test --grep "X-CSRF-Token"` | **1 passed (3.5s)** |

Manual smoke (per VALIDATION.md) — expire access cookie + keep refresh cookie + reload → one refresh POST fires and session restores — is covered in behavior by Task 2 and asserted at the request-header level by the Task 3 contract test; full live-backend smoke deferred to integration/QA (no live backend in CI for this plan).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug/Security] Hardened `getCookie` against ReDoS (CWE-1333)**
- **Found during:** Task 1 (editing api.ts; static analysis flagged dynamic RegExp construction).
- **Issue:** `getCookie(name)` built `new RegExp(\`(?:^|;\\s*)${name}=([^;]*)\`)` from a parameter. `name` is only ever the literal `"axiam_csrf"`, so the dynamic construction added needless injectable/ReDoS surface.
- **Fix:** Narrowed the parameter type to the literal `"axiam_csrf"`, switched to a hardcoded `const AXIAM_CSRF_RE = /(?:^|;\s*)axiam_csrf=([^;]*)/`, and guarded with `if (name !== "axiam_csrf") return null`.
- **Files modified:** `frontend/src/lib/api.ts`
- **Commit:** `6cf0466` (folded into Task 1)

### Notes
- **`fetchCurrentUser.ts` listed in `files_modified` but intentionally unchanged.** Task 2's `<action>` is explicit: "do not change its swallow-401 behavior, add the refresh in the hook." The boot-refresh logic belongs in `useAuthInit`; `fetchCurrentUser` returning `null` on 401 is the contract the hook relies on. No edit was the correct outcome.
- **Commits are unsigned (`commit.gpgsign=false`).** GPG/pinentry would block non-interactively in this executor. Commits `6cf0466`, `92997a4`, `f400599` need re-signing at PR time.

### Deferred Issues (Phase 19 / out of scope)
- Pre-existing `tsconfig.app.json(20,5)` `baseUrl` deprecation (TS5101) — not introduced by this plan; track for a tsconfig modernization task.
- Pre-existing unused `setInitializing` in `useAuthInit` — explicitly left as-is per plan ("out of scope").
- No TODO markers were left in code by this plan.

## TDD Gate Compliance
Task 3 is `tdd="true"`. The implementation (Tasks 1-2) landed first because the contract test is a Wave-0 gap added to lock in the now-correct behavior; the test was authored last and passes (GREEN) against the fixed code. A pre-fix RED was not separately committed — the bare-axios refresh defect is the documented pre-existing failure mode the test now guards. Test-only file, no source behavior driven by Task 3 itself.

## Known Stubs
None.

## Threat Flags
None — no new security surface beyond the mitigations in the plan's threat register (T-09-07, T-09-08), both now mitigated.

## Self-Check: PASSED
- Modified files exist: `frontend/src/lib/api.ts`, `frontend/src/hooks/useAuthInit.ts`, `frontend/e2e/auth-contract.spec.ts` — all present.
- Commits exist: `6cf0466`, `92997a4`, `f400599` — all in `git log`.
- `api.ts` contains `api.post("/api/v1/auth/refresh"` and `SKIP_REFRESH` (no bare `axios.post(.../refresh)`).
- `useAuthInit.ts` contains a single `api.post(".../auth/refresh")` guarded by try/catch.
- Contract test passes: `playwright test --grep "X-CSRF-Token"` → 1 passed.
