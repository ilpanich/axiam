---
phase: 02-security-headers-rate-limiting
plan: 02
subsystem: api
tags: [actix-governor, rate-limiting, brute-force, x-forwarded-for]

requires:
  - phase: 01-cookie-auth
    provides: Auth endpoints (login, refresh, password reset)
provides:
  - RateLimitConfig with per-endpoint configurable limits
  - XForwardedForKeyExtractor for IP-based rate limiting
  - Per-resource Governor middleware on login, token, password-reset endpoints
  - JSON 429 response with Retry-After header
affects: [admin-ui, lockout]

tech-stack:
  added: [actix-governor 0.10]
  patterns: [per-endpoint rate limiting via web::resource().wrap(Governor)]

key-files:
  created:
    - crates/axiam-api-rest/src/config/rate_limit.rs
    - crates/axiam-api-rest/src/extractors/rate_limit.rs
  modified:
    - crates/axiam-api-rest/src/config/mod.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-server/src/main.rs

key-decisions:
  - "Rate limiters on individual web::resource(), not on scope — avoids interfering with CsrfMiddleware ordering"
  - "Config module converted from single file to directory to accommodate rate_limit submodule"
  - "XForwardedForKeyExtractor reads leftmost IP from X-Forwarded-For, falls back to peer addr"
  - "exceed_rate_limit_response returns JSON body with error and retry_after fields per D-03"

patterns-established:
  - "Per-endpoint Governor: build_governor(requests_per_min) creates independent stores"
  - "register_api_v1_routes takes &RateLimitConfig parameter for testability"
  - "Rate limits configurable via AXIAM__RATE_LIMIT__* env vars"

requirements-completed: [REQ-3]

duration: 15min
completed: 2026-04-06
---

# Plan 02-02: REST Rate Limiting Summary

**Per-endpoint rate limiting on auth endpoints (login=10, token=20, reset=3/min) with JSON 429 + Retry-After**

## Performance

- **Duration:** 15 min (inline execution)
- **Tasks:** 2
- **Files modified:** 26

## Accomplishments
- RateLimitConfig with defaults matching REQ-3 (login=10, register=5, token=20, reset=3 per min)
- XForwardedForKeyExtractor with custom 429 JSON response and Retry-After header
- Per-resource Governor wrapping login, oauth2/token, and password-reset endpoints
- Config validated at startup (fail-fast on zero values)
- All 18 existing test files updated for new register_api_v1_routes signature

## Task Commits

1. **Task 1: Dependencies + RateLimitConfig + XForwardedForKeyExtractor** - `721e135` (feat)
2. **Task 2: Wire rate limiters in server.rs + AppConfig** - `721e135` (feat, combined)

## Files Created/Modified
- `crates/axiam-api-rest/src/config/rate_limit.rs` - RateLimitConfig struct
- `crates/axiam-api-rest/src/extractors/rate_limit.rs` - XForwardedForKeyExtractor
- `crates/axiam-api-rest/src/server.rs` - build_governor + per-resource wrapping
- `crates/axiam-server/src/main.rs` - AppConfig.rate_limit + validate()
- 18 test files - Updated configure() calls for new signature

## Decisions Made
- Used `requests_per_minute()` API (not deprecated `per_second()`) for clarity
- actix-governor `NoOpMiddleware` for rate-limiting middleware type (no extra response headers)

## Deviations from Plan
None — plan executed as specified.

## Issues Encountered
- Clippy required collapsing nested if-let chains (Rust 2024 edition let-chains)

## Next Phase Readiness
- Rate limiting infrastructure ready for admin UI lockout visibility (Plan 02-04)
- register endpoint not rate-limited yet (no /auth/register route exists — user creation is /api/v1/users)

---
*Phase: 02-security-headers-rate-limiting*
*Completed: 2026-04-06*
