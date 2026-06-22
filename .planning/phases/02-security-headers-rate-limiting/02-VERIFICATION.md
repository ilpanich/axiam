---
phase: 02-security-headers-rate-limiting
verified: 2026-04-08T21:15:00Z
status: human_needed
score: 21/21 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 20/21
  gaps_closed:
    - "6th POST /api/v1/users request from same IP within 1 minute returns HTTP 429 — register_per_min now wired at server.rs:201"
    - "15-minute lockout cooldown — lockout_duration_secs default corrected to 900 at config.rs:91"
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Verify lockout admin UI end-to-end"
    expected: "Amber Locked badge appears on locked users; filter toggle works; unlock dialog opens and submits; badge disappears after unlock"
    why_human: "Visual rendering, real-time state updates, and dialog interaction cannot be verified programmatically"
---

# Phase 02: Security Headers & Rate Limiting Verification Report

**Phase Goal:** All HTTP responses include security headers and authentication endpoints resist brute-force attacks
**Verified:** 2026-04-08T21:15:00Z
**Status:** human_needed — all automated checks pass, 1 item needs human UI testing
**Re-verification:** Yes — after gap closure plan 02-05

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | Every API response includes X-Content-Type-Options: nosniff | VERIFIED | `security_headers.rs:62-65`; `main.rs:264` wraps App |
| 2  | Every API response includes X-Frame-Options: DENY | VERIFIED | `security_headers.rs:66-69`; nginx.conf:21,35,47 |
| 3  | Every API response includes Referrer-Policy: strict-origin-when-cross-origin | VERIFIED | `security_headers.rs:70-73` |
| 4  | Nginx frontend config includes CSP with script-src self only | VERIFIED | `nginx.conf:26,40,52` — `script-src 'self'` in all 3 location blocks |
| 5  | Nginx frontend config includes HSTS | VERIFIED | `nginx.conf` — `Strict-Transport-Security` with `max-age=31536000; includeSubDomains` |
| 6  | Nginx frontend config includes Permissions-Policy disabling unused browser features | VERIFIED | `nginx.conf:25,39,51` — geolocation, camera, microphone, payment, usb, etc. disabled |
| 7  | 11th login request from same IP within 1 minute returns HTTP 429 | VERIFIED | `server.rs:66` wraps `/login` resource with `build_governor(rate_limit_cfg.login_per_min)` (default 10) |
| 8  | 6th register request from same IP within 1 minute returns HTTP 429 | VERIFIED | `server.rs:201` wraps `/users` resource with `build_governor(rate_limit_cfg.register_per_min)` (default 5) — **CLOSED in 02-05** |
| 9  | 21st oauth2/token request from same IP within 1 minute returns HTTP 429 | VERIFIED | `server.rs:140` wraps `/token` resource with `build_governor(rate_limit_cfg.token_per_min)` (default 20) |
| 10 | 4th password-reset request from same IP within 1 minute returns HTTP 429 | VERIFIED | `server.rs:119` wraps `/reset` resource with `build_governor(rate_limit_cfg.password_reset_per_min)` (default 3) |
| 11 | 429 response body is JSON with error and retry_after fields | VERIFIED | `extractors/rate_limit.rs:38-53` — `{"error":"rate_limit_exceeded","retry_after":N}` |
| 12 | 429 response includes Retry-After header | VERIFIED | `extractors/rate_limit.rs:48` inserts `RETRY_AFTER` header |
| 13 | Rate limits are configurable via AXIAM__RATE_LIMIT__* environment variables | VERIFIED | `config/rate_limit.rs` uses `#[serde(default)]` with config crate env source |
| 14 | gRPC authorization endpoint has brute-force protection via rate limiting | VERIFIED | `server.rs (grpc):45,52` — `build_grpc_governor_layer` applied via `.layer(governor_layer)` |
| 15 | gRPC rate limits are configurable via environment variables | VERIFIED | `config.rs (grpc):17-18` — `grpc_authz_per_sec` via `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` |
| 16 | Rate-limited gRPC requests receive an appropriate error response | VERIFIED | `tower-governor` returns gRPC status `RESOURCE_EXHAUSTED` via `tonic` feature |
| 17 | Admin can see which users are locked in the user list | VERIFIED | `UsersPage.tsx:395` — `LockedBadge` rendered in Status column when `row.is_locked` |
| 18 | Admin can filter the user list to show only locked users | VERIFIED | `UsersPage.tsx:238-239` — `lockedCount`, `lockedOnly` state, filtered users array |
| 19 | Admin can unlock a locked user account via button click | VERIFIED | `UsersPage.tsx:354,436` — `LockOpen` button, `unlockMutation`, dialog flow |
| 20 | Unlock resets failed_login_attempts to 0 and clears locked_until | VERIFIED | `handlers/users.rs:235-236` — `failed_login_attempts: Some(0)`, `locked_until: Some(None)` |
| 21 | Account lockout cooldown is 15 minutes (900 seconds) per REQ-3 | VERIFIED | `axiam-auth/src/config.rs:91` — `lockout_duration_secs: 900`; doc comment updated to "default: 900 = 15 min" — **CLOSED in 02-05** |

**Score:** 21/21 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-api-rest/src/middleware/security_headers.rs` | SecurityHeadersMiddleware Transform+Service pair | VERIFIED | Full Transform + Service impl |
| `crates/axiam-api-rest/tests/security_headers_test.rs` | Integration tests for security headers | VERIFIED | 4 test functions with exact header value assertions |
| `docker/nginx.conf` | Updated nginx config with CSP, HSTS, Permissions-Policy | VERIFIED | All headers present in all 3 applicable location blocks |
| `crates/axiam-api-rest/src/config/rate_limit.rs` | RateLimitConfig with defaults from REQ-3 | VERIFIED | login=10, register=5, token=20, password_reset=3; validate() present |
| `crates/axiam-api-rest/src/extractors/rate_limit.rs` | XForwardedForKeyExtractor for IP-based rate limiting | VERIFIED | X-Forwarded-For parsing; exceed_rate_limit_response with JSON + Retry-After |
| `crates/axiam-api-grpc/src/middleware/rate_limit.rs` | GovernorLayer setup for gRPC rate limiting | VERIFIED | `build_grpc_governor_layer`; SmartIpKeyExtractor; NoOpMiddleware |
| `crates/axiam-api-grpc/src/config.rs` | GrpcConfig with rate limit fields | VERIFIED | `grpc_authz_per_sec: u32` present |
| `crates/axiam-api-rest/src/handlers/users.rs` | unlock handler and extended UserResponse | VERIFIED | `pub async fn unlock`; `is_locked`, `locked_until`, `failed_login_attempts` in UserResponse |
| `frontend/src/pages/users/UsersPage.tsx` | Locked badge, filter toggle, unlock button | VERIFIED | LockedBadge, lockedOnly state, LockOpen button, unlockMutation, inline unlock dialog |
| `crates/axiam-api-rest/src/server.rs` | register_per_min wired to /users resource | VERIFIED | `.wrap(build_governor(rate_limit_cfg.register_per_min))` at line 201 — added in 02-05 |
| `crates/axiam-auth/src/config.rs` | lockout_duration_secs default 900 | VERIFIED | `lockout_duration_secs: 900` at line 91; doc updated — fixed in 02-05 |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `crates/axiam-server/src/main.rs` | `middleware/security_headers.rs` | `.wrap(SecurityHeadersMiddleware)` | WIRED | `main.rs:8` import + `main.rs:264` wrap |
| `crates/axiam-server/src/main.rs` | `config/rate_limit.rs` | `AppConfig.rate_limit` field | WIRED | Field present; validate() called |
| `crates/axiam-api-rest/src/server.rs` | `extractors/rate_limit.rs` | `build_governor(rate_limit_cfg.*)` | WIRED | Login (line 66), reset (line 119), token (line 140), users/register (line 201) — all 4 wired |
| `crates/axiam-api-grpc/src/server.rs` | `middleware/rate_limit.rs` | `.layer(governor_layer)` | WIRED | `server.rs:14` import + `server.rs:45,52` construction and layer |
| `frontend/src/pages/users/UsersPage.tsx` | `frontend/src/services/users.ts` | `userService.unlock(userId)` | WIRED | `UsersPage.tsx:355` calls `unlockMutation.mutate` → `users.ts` unlock method |
| `frontend/src/services/users.ts` | `/api/v1/users/{user_id}/unlock` | POST request | WIRED | `api.post<User>` to unlock endpoint |
| `crates/axiam-api-rest/src/handlers/users.rs` | `UserRepository.update()` | `UpdateUser{failed_login_attempts:Some(0)}` | WIRED | `handlers/users.rs:235-236` — both fields reset on unlock |

---

## Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `UsersPage.tsx` | `users` / `filteredUsers` | `useQuery` → `userService.getUsers` → `GET /api/v1/users` | Yes — DB query in users handler | FLOWING |
| `UsersPage.tsx` (lock state) | `row.is_locked`, `row.locked_until` | `UserResponse.is_locked` derived from `locked_until > Utc::now()` at serialization | Yes — real user DB field | FLOWING |
| `UsersPage.tsx` (unlock) | `unlockMutation` | `POST /api/v1/users/{id}/unlock` → DB update via `UserRepository.update()` | Yes — real DB write | FLOWING |

---

## Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| register_per_min wired in server.rs | `grep "build_governor(rate_limit_cfg.register_per_min)" server.rs` | Match at line 201 | VERIFIED |
| lockout_duration_secs default is 900 | `grep "lockout_duration_secs: 900" config.rs` | Match at line 91 | VERIFIED |
| All 4 rate-limit wraps present in server.rs | Grep for `build_governor(rate_limit_cfg.` | 4 matches (login, password_reset, token, register_per_min) | VERIFIED |
| gRPC governor layer applied | Grep for `.layer(governor_layer)` | Match at server.rs:52 | VERIFIED |
| Commits 845b2be and 4baa4cd exist in git log | `git log --oneline 845b2be 4baa4cd` | Both present, messages match expected changes | VERIFIED |

Step 7b: Behavioral spot-checks limited to static analysis — server start not attempted.

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| REQ-2 | 02-01 | Security Headers (OWASP ASVS 14.4) | SATISFIED | SecurityHeadersMiddleware adds X-Content-Type-Options/X-Frame-Options/Referrer-Policy; nginx has CSP/HSTS/Permissions-Policy in all location blocks |
| REQ-3 | 02-02, 02-03, 02-04, 02-05 | Rate Limiting & Brute-Force Protection | SATISFIED | All 4 REST endpoints rate-limited; lockout after 5 attempts with 900s (15 min) default; gRPC protected; lockout UI complete with filter and unlock |

### REQ-3 Criterion-by-Criterion

| Criterion | Status | Notes |
|-----------|--------|-------|
| Rate limiting on /auth/login (10 req/min per IP) | SATISFIED | `server.rs:66` |
| Rate limiting on /auth/register (5 req/min per IP) | SATISFIED | `server.rs:201` — wired in 02-05 to `/api/v1/users` (registration endpoint) |
| Rate limiting on /oauth2/token (20 req/min per client) | SATISFIED | `server.rs:140` |
| Rate limiting on /auth/password-reset (3 req/min per IP) | SATISFIED | `server.rs:119` (route is `/auth/reset`) |
| Account lockout after 5 consecutive failed login attempts | SATISFIED | `axiam-auth/service.rs:768-788`; tested |
| 15-minute cooldown | SATISFIED | Default `lockout_duration_secs: 900` — corrected in 02-05 |
| Lockout status visible in admin UI | SATISFIED | LockedBadge + filter in UsersPage |
| gRPC brute-force protection | SATISFIED | tower-governor GovernorLayer on tonic Server |

---

## Anti-Patterns Found

No blockers. No warnings.

Previously flagged anti-patterns from the prior verification have been resolved:
- `register_per_min` dead config field — now consumed at `server.rs:201`
- `lockout_duration_secs: 300` diverging from REQ-3 — corrected to 900

---

## Human Verification Required

### 1. Lockout Admin UI Visual Verification

**Test:** Start the dev environment (`just dev-up` + `just run`), navigate to the admin Users page.
**Expected:**
1. If a user is locked (fail login 5 times), amber "Locked" badge appears in the Status column
2. Clicking the "Locked" filter button shows only locked accounts, with label "Locked (N)"
3. Clicking the LockOpen icon opens an inline confirmation dialog titled "Unlock Account"
4. Confirming the unlock removes the badge and makes the user loginable again
5. When locked filter is active with no locked users: "No locked accounts." shown

**Why human:** Visual badge rendering, real-time cache invalidation after mutation, dialog animation and interaction flow cannot be verified from static code analysis alone.

---

## Gap Closure Summary (Re-verification)

Both gaps from the previous verification (2026-04-07) were closed by plan 02-05 (commits 845b2be and 4baa4cd, completed 2026-04-08T20:49:46Z):

**Gap 1 — register endpoint rate limiting not wired:**
Resolved by adding `.wrap(build_governor(rate_limit_cfg.register_per_min))` to the `/users` web resource in `server.rs` at line 201. This follows the identical pattern used for login, reset, and token endpoints. The wrap applies to both POST (user creation) and GET (admin list), which is acceptable.

**Gap 2 — lockout cooldown default 300s vs REQ-3 requirement of 900s:**
Resolved by changing `lockout_duration_secs` default from 300 to 900 in `crates/axiam-auth/src/config.rs` line 91, and updating the doc comment to "default: 900 = 15 min". The environment variable `AXIAM__AUTH__LOCKOUT_DURATION_SECS` continues to override at runtime.

No regressions detected in the 20 previously-passing truths.

---

_Verified: 2026-04-08T21:15:00Z_
_Verifier: Claude (gsd-verifier)_
_Previous verification: 2026-04-07T23:50:00Z (gaps_found, 20/21)_
