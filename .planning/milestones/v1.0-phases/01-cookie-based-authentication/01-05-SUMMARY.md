---
phase: 01-cookie-based-authentication
plan: 05
type: execute
gap_closure: true
completed_at: 2026-04-15
requirements: [REQ-1]
status: completed
---

# Plan 01-05 — Login contract drift (gap closure) — SUMMARY

## Delivered

Backend login endpoint now accepts either the ID-based or the slug-based form of
the login body, closing the contract drift between the admin UI (sends slugs) and
the backend (previously required UUIDs).

## Evidence

### Protocol level
```
$ curl -sk -X POST https://localhost/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"org_slug":"testorg","tenant_slug":"testtenant","username":"admin","password":"AdminPass123!Admin"}'
HTTP/2 200
set-cookie: axiam_access=…; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=900
set-cookie: axiam_refresh=…; HttpOnly; SameSite=Strict; Secure; Path=/api/v1/auth/refresh; Max-Age=2592000
set-cookie: axiam_csrf=…; SameSite=Strict; Secure; Path=/; Max-Age=900
{"user":{...},"session_id":"…","expires_in":900}
```

### UI level
Playwright drove https://localhost → Continue with workspace slugs → Sign in with
admin credentials → redirect to `/dashboard` → navigation to `/users` renders the
three test users. Evidence screenshots are under phase 02 UAT (where the lockout
UI test was the precipitating driver):
- `.planning/phases/02-security-headers-rate-limiting/uat-evidence/uat-02-01-locked-badge.png`

### Backend integration tests
`cargo test -p axiam-api-rest --test auth_test` — 16/18 pass (same baseline as
before 01-05; unchanged by this change). The 2 failures
(`refresh_uses_cookie_returns_new_access_cookie`, `reset_mfa_returns_403_until_rbac`)
are pre-existing and outside scope.

## Known limitations / follow-ups

1. Slug resolution costs one extra DB round-trip when slugs are used; IDs remain
   the fast path.
2. No new integration test for the slug path was added in this plan — the
   Playwright end-to-end run is the verification. A Rust-level integration test
   covering the slug branch should be filed as a follow-up (T19-class task).
3. Error path `NotFound` → `AuthenticationFailed` remap avoids org/tenant enumeration
   but does disclose existence indirectly via timing (single DB round-trip for the
   not-found case vs two for the wrong-password case). Acceptable for now;
   constant-time behavior is a hardening task for a later phase.

## Out of scope (filed as follow-ups)

- `web::Data::new` vs `from` for `rest_authz` — separate commit (5949609) landed
  alongside 01-05 to unblock all RBAC-protected admin endpoints.
- `PaginatedUsers` shape drift — separate commit (8a8589a) fixes the users list
  shape; broader admin pagination audit still needed.
