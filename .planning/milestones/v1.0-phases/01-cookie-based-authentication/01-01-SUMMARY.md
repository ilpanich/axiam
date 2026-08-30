---
phase: 01-cookie-based-authentication
plan: "01"
subsystem: axiam-api-rest
tags: [security, authentication, csrf, cookies, jwt]
requirements: [REQ-1]

dependency_graph:
  requires:
    - axiam-auth (AuthService, validate_access_token, AuthConfig)
    - axiam-db (SurrealUserRepository, SurrealSessionRepository)
    - axiam-core (AxiamError, User model)
  provides:
    - CSRF double-submit cookie middleware (CsrfMiddleware)
    - Cookie-aware auth extractor (axiam_access cookie-first, Bearer fallback)
    - /auth/me endpoint
    - httpOnly JWT cookie issuance on login/MFA/refresh
  affects:
    - All auth handlers (login, logout, refresh, verify_mfa, setup_confirm_mfa)
    - All protected endpoints (auth extractor now reads from cookie)

tech_stack:
  added:
    - subtle = "2" (constant-time CSRF comparison)
    - rand = "0.9" (CSRF token generation)
  patterns:
    - Actix-Web Transform + Service middleware pattern (CsrfMiddleware)
    - Cookie-first JWT extraction with Bearer header fallback

key_files:
  created:
    - crates/axiam-api-rest/src/middleware/mod.rs
    - crates/axiam-api-rest/src/middleware/csrf.rs
  modified:
    - crates/axiam-api-rest/src/lib.rs
    - crates/axiam-api-rest/Cargo.toml
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/extractors/auth.rs

decisions:
  - "Used AxiamError::AuthorizationDenied for CSRF failure (maps to 403) — no Forbidden variant exists in AxiamError"
  - "Decode issued access_token to get user_id for login response (LoginOutput lacks user_id field)"
  - "CSRF middleware applied at /auth scope level; exempt suffixes handle login/MFA/OAuth2 flows"

metrics:
  duration_minutes: 30
  completed_date: "2026-04-04"
  tasks_completed: 3
  files_created: 2
  files_modified: 5
---

# Phase 01 Plan 01: Cookie-Based Authentication — Backend Summary

**One-liner:** JWT tokens moved from response body to httpOnly Set-Cookie headers, with CSRF double-submit cookie protection via constant-time validation and a new /auth/me endpoint.

## What Was Built

### Task 1: CSRF Middleware and Cookie Helpers (d9d6003)

Created `crates/axiam-api-rest/src/middleware/csrf.rs` with:

- **`CsrfMiddleware`**: Actix-Web `Transform + Service` middleware that enforces CSRF double-submit cookie pattern on state-changing requests (POST/PUT/PATCH/DELETE). Safe methods (GET/HEAD/OPTIONS) and login/MFA/OAuth2 paths are exempt.
- **Constant-time comparison**: Uses `subtle::ConstantTimeEq::ct_eq()` to prevent timing-based token extraction attacks (D-01).
- **Cookie builders**: `access_cookie`, `refresh_cookie`, `csrf_cookie` — all with `Secure`, `SameSite::Strict`. Access/refresh are `httpOnly=true`; CSRF is `httpOnly=false` (so JS can read it). Refresh cookie path-scoped to `/api/v1/auth/refresh` (D-06).
- **Cookie clearers**: `clear_access_cookie`, `clear_refresh_cookie`, `clear_csrf_cookie` for logout.
- **`generate_csrf_token()`**: 32 bytes of `rand::random()` hex-encoded.

### Task 2: Cookie-Setting Auth Handlers and /me Endpoint (813dc27)

Modified `crates/axiam-api-rest/src/handlers/auth.rs`:

- **`LoginSuccessResponse`** now contains `user: LoginUserInfo` + `session_id` + `expires_in` — access/refresh tokens NO LONGER in response body (D-13).
- **`RefreshSuccessResponse`**: Only `expires_in`; tokens in cookies.
- **`RefreshRequest`**: `refresh_token` field removed — reads from `axiam_refresh` cookie.
- **All login-success paths** (`login`, `verify_mfa`, `setup_confirm_mfa`) call `cookie_response_from_output()` which sets all three auth cookies and returns user info.
- **Logout** clears all three cookies with Max-Age=0.
- **New CSRF token issued on every login and refresh rotation** (D-02).
- **`GET /auth/me`**: Returns authenticated user's profile; requires valid session cookie.

Registered `/me` route and `CsrfMiddleware` in `server.rs`. Added `X-CSRF-Token` to CORS allowed headers.

### Task 3: Cookie-First Auth Extractor (985ffb3)

Modified `crates/axiam-api-rest/src/extractors/auth.rs`:

- Tries `axiam_access` httpOnly cookie first (browser clients).
- Falls back to `Authorization: Bearer <token>` header for service-to-service/device/backward-compat clients.
- Token validation path unchanged regardless of source.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] No `Forbidden` variant in `AxiamError`**
- **Found during:** Task 1
- **Issue:** Plan specified `AxiamError::Forbidden { reason: ... }` for CSRF failures, but this variant doesn't exist in `crates/axiam-core/src/error.rs`.
- **Fix:** Used `AxiamError::AuthorizationDenied { reason: "CSRF validation failed".into() }` which maps to HTTP 403 via the existing `ResponseError` impl — same observable behavior.
- **Files modified:** `crates/axiam-api-rest/src/middleware/csrf.rs`
- **Commit:** d9d6003

None other — plan executed as written.

## Known Stubs

None. All plan objectives are fully wired:
- Login sets cookies and returns user info.
- Refresh reads from cookie and sets new cookies.
- Logout clears all cookies.
- CSRF middleware validates state-changing requests.
- Auth extractor reads from cookie.
- /me endpoint is live.

## Commits

| Hash | Message |
|------|---------|
| d9d6003 | feat(01-01): add CSRF double-submit cookie middleware and auth cookie helpers |
| 813dc27 | feat(01-01): cookie-setting auth handlers, /me endpoint, CSRF middleware wiring |
| 985ffb3 | feat(01-01): cookie-first auth extractor with Bearer header fallback |
| 159dc10 | chore(01-01): apply rustfmt to auth.rs and middleware/csrf.rs |

## Self-Check: PASSED
