---
phase: 01-cookie-based-authentication
plan: "02"
subsystem: frontend
tags: [security, authentication, csrf, cookies, react, zustand, axios]
requirements: [REQ-1]

dependency_graph:
  requires:
    - Plan 01-01 (cookie-setting backend: axiam_access, axiam_refresh, axiam_csrf cookies)
    - Zustand store (memory-only, no persist)
    - Axios (withCredentials + CSRF interceptor)
  provides:
    - Memory-only Zustand auth store (no sessionStorage persistence)
    - Axios client with withCredentials and X-CSRF-Token injection
    - useAuthInit hook calling GET /api/v1/auth/me on mount
    - AuthGate component with full-page loading spinner
    - Login/MFA flows using new cookie-auth response shapes
  affects:
    - All frontend API calls (now send cookies automatically)
    - App initialization (auth rehydrated from cookies via /me)
    - LoginPage (setUser replaces setTokens, new response shape)

tech_stack:
  added: []
  patterns:
    - Memory-only Zustand store (no persist middleware)
    - CSRF double-submit cookie read via document.cookie
    - Auth rehydration via /me endpoint on mount (AuthGate pattern)
    - Silent refresh via cookie-based refresh interceptor

key_files:
  created:
    - frontend/src/hooks/useAuthInit.ts
  modified:
    - frontend/src/stores/auth.ts
    - frontend/src/lib/api.ts
    - frontend/src/App.tsx
    - frontend/src/pages/LoginPage.tsx

decisions:
  - "Login URL updated from /auth/login to /api/v1/auth/login — plan showed /auth/login but full API path required for consistency with refresh (/api/v1/auth/refresh) and /me (/api/v1/auth/me)"
  - "MFA field renamed from mfa_session_token/session_token to challenge_token — matches backend LoginSuccessResponse and API spec in plan context"

metrics:
  duration_minutes: 4
  completed_date: "2026-04-04"
  tasks_completed: 2
  files_created: 1
  files_modified: 4
---

# Phase 01 Plan 02: Cookie-Based Authentication — Frontend Summary

**One-liner:** Frontend auth layer migrated from sessionStorage token storage to httpOnly cookie auth, with CSRF injection from axiam_csrf cookie and auth rehydration via GET /api/v1/auth/me on app boot.

## What Was Built

### Task 1: Refactor Zustand Store and Axios Client (5b8574a)

Rewrote `frontend/src/stores/auth.ts`:

- Removed `persist` middleware and `createJSONStorage` — store is now memory-only.
- Removed `accessToken` field, `setTokens()`, `updateAccessToken()`.
- Added `isInitializing: true` (default) — app starts in loading state.
- Added `setUser(user)` — sets user + isAuthenticated + clears isInitializing.
- `clearAuth()` now sets `isInitializing: false` (not back to true on logout).

Rewrote `frontend/src/lib/api.ts`:

- Added `withCredentials: true` to Axios instance — all requests send cookies.
- Added `getCookie(name)` helper to read named cookies from `document.cookie`.
- Request interceptor reads `axiam_csrf` cookie and injects `X-CSRF-Token` header on POST/PUT/PATCH/DELETE.
- Removed `Authorization: Bearer` header injection entirely.
- Refresh interceptor posts to `/api/v1/auth/refresh` with `withCredentials: true` — no token in body or response parsing.
- `processQueue()` simplified to signal completion only (no token passing).
- Queued requests retry without setting Authorization header.
- Uses `isAuthenticated` from store (not `hasToken`) to gate refresh logic.

### Task 2: Auth Init Hook, App Gate, LoginPage Update (5d0cc8f)

Created `frontend/src/hooks/useAuthInit.ts`:

- Calls `GET /api/v1/auth/me` on mount.
- On 200 with `res.data.user`: calls `setUser()` to populate store.
- On 401 or network error: calls `clearAuth()` — silent, no error shown (per UI-SPEC).
- Uses cancellation flag to prevent state updates after unmount.

Updated `frontend/src/App.tsx`:

- Added `AuthGate` component wrapping `RouterProvider`.
- `AuthGate` calls `useAuthInit()` and blocks rendering while `isInitializing` is true.
- Loading state: centered `Loader2` (h-6 w-6, animate-spin) on `bg-axiam-gradient` with `aria-live="polite"` (per UI-SPEC accessibility contract).

Updated `frontend/src/pages/LoginPage.tsx`:

- Updated `LoginResponse` interface: removed `access_token`; added `user`, `session_id`, `expires_in`, `challenge_token`, `available_methods`, `mfa_setup_required`, `setup_token`.
- Replaced `setTokens(access_token, user)` with `setUser(user)` throughout.
- Login success: check `data.user` (not `data.access_token`) to determine success.
- MFA: uses `challenge_token` field (matches backend spec).
- CSRF error handling: 403 response shows "Request rejected for security reasons. Please refresh the page and try again." (per UI-SPEC copywriting contract).
- Unexpected shape: "Authentication error. Please sign in again." then redirect to /login.

`AppLayout.tsx` required no changes — already reads only `isAuthenticated` from store.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Login URL path corrected to full API path**
- **Found during:** Task 2
- **Issue:** Plan action section showed `/auth/login` as the login POST URL, but the backend mounts auth routes under `/api/v1/auth/`. Other endpoints in the plan context use the full path (`/api/v1/auth/refresh`, `/api/v1/auth/me`).
- **Fix:** Used `/api/v1/auth/login` and `/api/v1/auth/mfa/verify` for consistency with the backend routing.
- **Files modified:** `frontend/src/pages/LoginPage.tsx`
- **Commit:** 5d0cc8f

**2. [Rule 1 - Bug] MFA field name aligned to backend spec**
- **Found during:** Task 2
- **Issue:** Old LoginPage used `mfa_session_token` / `session_token` fields for MFA flow. Backend plan (01-01) now uses `challenge_token` per the LoginSuccessResponse and plan interfaces.
- **Fix:** Updated `LoginResponse.challenge_token` and MFA verify payload to send `challenge_token`.
- **Files modified:** `frontend/src/pages/LoginPage.tsx`
- **Commit:** 5d0cc8f

## Known Stubs

None. All plan objectives are fully wired:
- Zustand store is memory-only with no token persistence.
- Axios sends cookies on all requests with CSRF injection.
- App boot calls /me and rehydrates auth state.
- Login/MFA use new response shapes and call setUser.

## Commits

| Hash | Message |
|------|---------|
| 5b8574a | feat(01-02): refactor Zustand store and Axios client for cookie auth |
| 5d0cc8f | feat(01-02): add auth init hook, update App/LoginPage for cookie auth |

## Self-Check: PASSED
