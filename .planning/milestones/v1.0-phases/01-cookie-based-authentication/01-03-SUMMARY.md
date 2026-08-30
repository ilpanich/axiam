---
phase: 01-cookie-based-authentication
plan: "03"
subsystem: axiam-api-rest
tags: [security, authentication, csrf, cookies, jwt, testing]
requirements: [REQ-1]

dependency_graph:
  requires:
    - axiam-api-rest plan 01 (CsrfMiddleware, cookie helpers, /me endpoint)
    - axiam-auth (AuthService, AuthConfig)
    - axiam-db (SurrealUserRepository, SurrealSessionRepository)
  provides:
    - Cookie-based auth integration test suite
    - CSRF middleware validation tests
    - Cookie attribute verification tests
    - /me endpoint tests
  affects:
    - crates/axiam-api-rest/tests/auth_test.rs (full rewrite)
    - crates/axiam-api-rest/src/middleware/csrf.rs (exempt list fix)

tech_stack:
  added: []
  patterns:
    - actix-web ServiceResponse cookie extraction via response().cookies()
    - Set-Cookie header string inspection for attribute verification (httpOnly, SameSite, Path, Max-Age)
    - Cookie jar simulation via Cookie header forwarding in test requests
    - CSRF double-submit pattern in tests (send axiam_csrf cookie + X-CSRF-Token header)

key_files:
  created: []
  modified:
    - crates/axiam-api-rest/tests/auth_test.rs
    - crates/axiam-api-rest/src/middleware/csrf.rs

decisions:
  - "Inspect Set-Cookie header string for cookie attributes (httpOnly, SameSite, Path) rather than Cookie object — actix-web Cookie::http_only() returns false unless parsed from Set-Cookie with attributes"
  - "Test cookie jar via manual Cookie header forwarding — actix-web test utilities have no built-in cookie jar"
  - "CSRF token flows: tests send both axiam_csrf cookie AND X-CSRF-Token header on state-changing requests"

metrics:
  duration_minutes: 23
  completed_date: "2026-04-04"
  tasks_completed: 1
  files_created: 0
  files_modified: 2
---

# Phase 01 Plan 03: Cookie-Based Auth Integration Tests — Summary

**One-liner:** Auth integration tests fully rewritten to cookie jar pattern with CSRF double-submit verification, cookie attribute assertions, /me endpoint tests, and logout cookie clearing — all 18 tests pass.

## What Was Built

### Task 1: Rewrite auth integration tests for cookie-based flow (7c96e67)

Rewrote `crates/axiam-api-rest/tests/auth_test.rs` from scratch, removing all `Authorization: Bearer` header usage and implementing the full cookie-based test flow.

**New cookie jar helpers:**

- `extract_cookie_value<B>()` — extracts a cookie value from response `Set-Cookie` headers by name
- `extract_set_cookie_header<B>()` — extracts the full `Set-Cookie` header string for attribute inspection
- `cookie_header()` — builds a `Cookie` request header from (name, value) pairs to simulate a browser cookie jar

**New test functions (11 new tests, 7 updated):**

| Test | What it validates |
|------|------------------|
| `login_sets_httponly_access_cookie` | axiam_access has HttpOnly, SameSite=Strict, Path=/; body has user info but no access_token |
| `login_sets_pathscoped_refresh_cookie` | axiam_refresh has HttpOnly, SameSite=Strict, Path=/api/v1/auth/refresh |
| `login_sets_csrf_cookie` | axiam_csrf is NOT httpOnly (JS-readable), Path=/ |
| `csrf_missing_header_returns_403` | POST without X-CSRF-Token header → 403 |
| `csrf_valid_header_allows_request` | POST with matching X-CSRF-Token and cookie → not 403 |
| `csrf_get_request_passes_without_token` | GET /auth/me without CSRF token → 200 |
| `logout_clears_cookies` | All three cookies have Max-Age=0 in Set-Cookie headers after logout |
| `refresh_uses_cookie_returns_new_access_cookie` | Refresh via axiam_refresh cookie; new axiam_access set; body has expires_in not access_token |
| `me_returns_user_info` | GET /auth/me with cookie → 200 with user info |
| `me_returns_401_without_cookie` | GET /auth/me with no cookie → 401 |
| `mfa_setup_full_flow_sets_cookies` | MFA confirm sets axiam_access and axiam_csrf; no access_token in body |

Also updated: `login_with_invalid_password_returns_401`, `login_with_nonexistent_user_returns_401`, `refresh_with_invalid_token_returns_401`, `mfa_enforcement_login_returns_403_with_setup_token`, `mfa_setup_enroll_with_setup_token_returns_200`, `reset_mfa_requires_authentication`, `reset_mfa_returns_403_until_rbac`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Missing SurrealUserRepository in test_app! macro**
- **Found during:** Task 1
- **Issue:** All login-related tests returned 500 because `SurrealUserRepository<C>` was not registered as app data in the `test_app!` macro. The `login` handler requires it (Plan 01-01 added it as a parameter for `cookie_response_from_output`), but the test setup was not updated.
- **Fix:** Added `.app_data(web::Data::new(SurrealUserRepository::new($db.clone())))` to the macro.
- **Files modified:** `crates/axiam-api-rest/tests/auth_test.rs`
- **Commit:** 7c96e67

**2. [Rule 1 - Bug] `/auth/mfa/setup/enroll` not in CSRF exempt list**
- **Found during:** Task 1
- **Issue:** `mfa_setup_enroll_with_setup_token_returns_200` and `mfa_setup_full_flow_sets_cookies` returned 403 because POST `/auth/mfa/setup/enroll` was not in `CSRF_EXEMPT_SUFFIXES`. During MFA setup, the user has no session cookie (they received a `setup_token` from the login 403 response) and therefore no `axiam_csrf` cookie exists yet. The `setup_token` in the request body serves as the authentication/authorization mechanism — CSRF protection is redundant here.
- **Fix:** Added `"/auth/mfa/setup/enroll"` to `CSRF_EXEMPT_SUFFIXES` in `crates/axiam-api-rest/src/middleware/csrf.rs`.
- **Files modified:** `crates/axiam-api-rest/src/middleware/csrf.rs`
- **Commit:** 7c96e67

### Implementation Notes

**Cookie attribute inspection approach:** Actix-web's `Cookie` object returned from `response().cookies()` does not expose httpOnly/Secure/SameSite attributes (those are not stored on the parsed Cookie object). To verify these attributes, tests inspect the raw `Set-Cookie` header string via `extract_set_cookie_header()` and perform case-insensitive string contains checks. This is the pragmatic approach described in the plan (option b).

**Secure flag:** The `Secure` attribute is set on cookies in the source code (`access_cookie`, `refresh_cookie`, `csrf_cookie` all call `.secure(true)`). Tests do not assert on the `Secure` flag because actix-web test server runs over HTTP, and Secure cookies behave differently in that context. The Secure flag is verified by code review of `csrf.rs` rather than the integration test.

## Known Stubs

None — all test scenarios are fully implemented and passing.

## Commits

| Hash | Message |
|------|---------|
| 7c96e67 | test(01-03): rewrite auth tests to cookie-based flow, add CSRF/me/logout tests |

## Self-Check: PASSED
