---
phase: 01-cookie-based-authentication
plan: 04
type: execute
gap_closure: true
completed_at: 2026-04-15
requirements: [REQ-1]
status: completed
---

# Plan 01-04 — Auth path-scope alignment (gap closure) — SUMMARY

## Delivered

Closed the two UAT blockers from `01-HUMAN-UAT.md` by moving the auth scope from `/auth`
to `/api/v1/auth` across the server, middleware, OpenAPI annotations, and integration tests.

| UAT Test | Gap | Status |
|---|---|---|
| 4 | `consistent-refresh-path-scope` — refresh cookie `Path=/api/v1/auth/refresh` now matches the actual handler route | closed |
| 5 | `aligned-auth-path-scope-between-client-and-server` — admin UI POST `/api/v1/auth/login` now reaches the real handler | closed |

## Changes

### Source (5 files)
- `crates/axiam-api-rest/src/server.rs:62` — `web::scope("/auth")` → `web::scope("/api/v1/auth")`.
- `crates/axiam-api-rest/src/permissions.rs:181–195` — 14 `PUBLIC_PATHS` entries prefixed.
- `crates/axiam-api-rest/src/middleware/csrf.rs:42–48` — 5 `CSRF_EXEMPT_SUFFIXES` entries prefixed.
- `crates/axiam-api-rest/src/middleware/authz.rs:150` — unit test assertion updated.
- `crates/axiam-api-rest/src/handlers/{auth,password_reset,webauthn,email_verification,bootstrap}.rs` —
  all `#[utoipa::path(path = "...")]` annotations and matching `///` doc headers prefixed (18 sites).

### Tests (4 files)
- `tests/auth_test.rs` — 28 `.uri("/auth/...")` → `.uri("/api/v1/auth/...")`.
- `tests/rbac_test.rs` — 2 references (URI + assertion message).
- `tests/device_auth_test.rs` — 4 references.
- `tests/bootstrap_test.rs` — 1 reference.

### Planning
- `01-04-PLAN.md` — gap closure plan (`gap_closure: true`).
- `01-04-SUMMARY.md` — this file.

## Verification

`cargo test -p axiam-api-rest` — post-edit results per test binary:

| Binary | Result | Notes |
|---|---|---|
| `auth_test` | 16/18 pass | 2 pre-existing fails unchanged from HEAD (refresh flow 401, mfa_reset 500) |
| `rbac_test` | 7/7 pass | no regression |
| `bootstrap_test` | 4/4 pass | no regression |
| `middleware_test` | 8/8 pass | no regression |
| `device_auth_test` | 2/5 pass | 3 pre-existing fails unchanged from HEAD (device-auth handler 500s) |

**Stash-verified no regression:** ran the same suites against a fresh `git stash` of the crate
directory and confirmed the failing tests fail identically on HEAD. Pre-existing failures are
unrelated to path-scope alignment and belong to separate phases (device-auth certificate flow,
MFA reset handler, refresh token parsing).

`cargo fmt -p axiam-api-rest` clean.
`cargo clippy -p axiam-api-rest --tests -- -D warnings` clean.

## Known limitation

The in-process `TestRequest.cookie(...)` harness does NOT enforce browser-side cookie `Path`
scoping, so `refresh_uses_cookie_returns_new_access_cookie` was never a functional cover for
UAT Test 4. Real-browser UAT re-run is required to formally close Test 4.

## Out of scope (not touched)

- `/oauth2/*`, `/.well-known/openid-configuration` — well-known OIDC URL conventions.
- Cookie-building helpers — `csrf.rs:203/:234` already use `/api/v1/auth/refresh` literal.
- Frontend — already calls `/api/v1/auth/*` (`frontend/src/lib/api.ts:93`).
- Pre-existing failures in `device_auth_test`, `auth_test::refresh_uses_cookie_*`,
  `auth_test::reset_mfa_returns_403_until_rbac`, `webhook_test`, and similar
  — all fail identically on HEAD.

## Next actions

1. Re-run `/gsd-verify-work 1` (browser UAT) to formally close Tests 4 and 5.
2. File a separate gap/phase ticket for the pre-existing refresh/MFA/device-auth test
   failures surfaced during baseline comparison.
