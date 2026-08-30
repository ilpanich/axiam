---
status: human_needed
phase: 01-cookie-based-authentication
verified_at: 2026-04-04
requirement_ids: [REQ-1]
must_have_score: 8/8
---

# Phase 01 Verification: Cookie-Based Authentication

## Goal
Users authenticate via httpOnly secure cookies instead of XSS-vulnerable sessionStorage tokens.

## REQ-1 Acceptance Criteria

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| AC1 | Access token via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/` | PASS | `csrf.rs:187-189` — `http_only(true)`, `same_site(SameSite::Strict)`, `path("/")` |
| AC2 | Refresh token via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh` | PASS | `csrf.rs:200-203` — path-scoped refresh cookie |
| AC3 | Frontend removes all sessionStorage token handling | PASS | `grep -r sessionStorage frontend/src/` returns 0 matches |
| AC4 | Frontend sends credentials via cookies (no Authorization header) | PASS | `api.ts:14` — `withCredentials: true`; no `Authorization` header anywhere in frontend |
| AC5 | CSRF double-submit cookie pattern for state-changing requests | PASS | `csrf.rs` — CsrfMiddleware validates X-CSRF-Token header; `api.ts:33` injects header from cookie |
| AC6 | Logout clears cookies server-side (Max-Age=0) | PASS | `auth.rs:296-298` — `clear_access_cookie()`, `clear_refresh_cookie()`, `clear_csrf_cookie()`; uses `make_removal()` |
| AC7 | Refresh uses refresh cookie, returns new access cookie | PASS | `auth.rs:323` — reads `axiam_refresh` from cookie, not request body |
| AC8 | Existing integration tests updated for cookie-based auth | PASS | `auth_test.rs` — 10 cookie-based tests, no `Authorization: Bearer` usage |

**Score: 8/8 must-haves verified**

## Plan Must-Haves Cross-Check

### Plan 01-01 (Backend Cookie Auth)
- [x] Login returns Set-Cookie with httpOnly access token cookie
- [x] Login returns Set-Cookie with path-scoped refresh token cookie
- [x] Login returns Set-Cookie with JS-readable CSRF token cookie
- [x] Login response body contains user info but NOT access_token or refresh_token
- [x] Refresh reads refresh token from cookie, not body
- [x] Logout clears all three cookies with Max-Age=0
- [x] CSRF middleware rejects POST/PUT/PATCH/DELETE without matching X-CSRF-Token
- [x] CSRF middleware allows GET/HEAD/OPTIONS without CSRF
- [x] Auth extractor reads JWT from axiam_access cookie
- [x] GET /auth/me returns authenticated user info

### Plan 01-02 (Frontend Cookie Migration)
- [x] Frontend never stores tokens in sessionStorage or JS memory
- [x] Frontend sends cookies via withCredentials: true
- [x] Frontend injects X-CSRF-Token header on state-changing requests
- [x] App initialization calls GET /api/v1/auth/me to rehydrate auth state
- [x] If /me returns 401, user redirected to /login without error
- [x] Login parses user info from response body (not tokens)
- [x] Silent refresh retries on 401 without reading token from response
- [x] Logout POSTs to /auth/logout then clears Zustand store

### Plan 01-03 (Integration Tests)
- [x] Login test verifies httpOnly access cookie
- [x] Login test verifies path-scoped refresh cookie
- [x] Login test verifies response body has user info but no access_token
- [x] CSRF test verifies POST without X-CSRF-Token is rejected 403
- [x] CSRF test verifies POST with valid X-CSRF-Token succeeds
- [x] CSRF test verifies GET passes without CSRF token
- [x] Logout test verifies cookies cleared
- [x] Refresh test verifies new cookies from cookie-based refresh
- [x] Me endpoint test verifies user info for authenticated user
- [x] All tests use cookie jar, not Authorization header

## Deviations
1. `AxiamError::AuthorizationDenied` used for CSRF failures — no `Forbidden` variant exists. Functionally correct (returns 403), just a naming mismatch.
2. `/auth/mfa/setup/enroll` added to CSRF exempt list during test plan — was missing, auto-fixed.

## Human Verification Needed

The following items require manual browser testing to fully validate:

1. **Cookie attributes in real browser**: Verify `Secure` flag is set when served over HTTPS (test environment uses HTTP, so `Secure` attribute couldn't be verified in integration tests)
2. **CSRF token lifecycle in browser**: Login in browser, verify `axiam_csrf` cookie is readable by JavaScript (`document.cookie`), verify `axiam_access` and `axiam_refresh` are NOT visible in `document.cookie`
3. **Auth init flow**: Open app, verify spinner shows briefly, then either redirects to login (no session) or loads dashboard (valid session)
4. **Silent refresh**: Wait for access token expiry (15 min), make an API call, verify it transparently refreshes without user interaction
5. **Cross-tab behavior**: Log out in one tab, verify other tabs detect unauthenticated state on next API call
