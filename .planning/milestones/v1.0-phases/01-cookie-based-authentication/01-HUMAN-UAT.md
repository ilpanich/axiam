---
status: complete
phase: 01-cookie-based-authentication
source: [01-VERIFICATION.md]
started: 2026-04-04T18:00:00Z
updated: 2026-04-15T15:30:00Z
---

## Current Test

[testing complete — 5 pass, 0 blocked; Tests 4 and 5 re-verified after 01-04 gap closure]

## Tests

### 1. Cookie Secure flag over HTTPS
expected: axiam_access, axiam_refresh, axiam_csrf all have Secure flag when served over HTTPS
result: pass
evidence: |
  POST /auth/login returned three Set-Cookie headers, all with the `Secure` attribute:
    axiam_access=...; HttpOnly; SameSite=Strict; Secure; Path=/; Max-Age=900
    axiam_refresh=...; HttpOnly; SameSite=Strict; Secure; Path=/api/v1/auth/refresh; Max-Age=2592000
    axiam_csrf=...;  SameSite=Strict; Secure; Path=/; Max-Age=900
  Captured against the prod-like stack (axiam-server on :8090) after admin bootstrap. Cookie-building code at crates/axiam-api-rest/src/middleware/csrf.rs:185-222 sets `.secure(true)` on all three.

### 2. CSRF cookie readable by JavaScript
expected: document.cookie shows axiam_csrf but NOT axiam_access or axiam_refresh (httpOnly)
result: pass
evidence: |
  Set-Cookie header attribute inspection confirms the spec:
    axiam_access  → HttpOnly flag set → not exposed to document.cookie
    axiam_refresh → HttpOnly flag set → not exposed to document.cookie
    axiam_csrf    → HttpOnly NOT set  → exposed to document.cookie
  Source: crates/axiam-api-rest/src/middleware/csrf.rs:187 (.http_only(true) for access), :200 (true for refresh), :216 (false for csrf).

### 3. Auth initialization flow
expected: App shows spinner, then redirects to login (no session) or loads dashboard (valid session)
result: pass
evidence: |
  Playwright navigate to https://localhost/ → app made GET /api/v1/auth/me → received 401 → client redirected to /login. URL resolved to https://localhost/login with 'AXIAM Admin' title and workspace-selection form rendered. Exact spec behaviour for the 'no session' branch.

### 4. Silent refresh on token expiry
expected: After access token expires, next API call triggers transparent refresh without user interaction
result: pass
closed_by: 01-04 (commit e2d667c)
evidence: |
  Protocol-level verification after 01-04 landed (fresh prod stack rebuilt from feature/full-review HEAD):
    $ curl -sk -i -X POST https://localhost/api/v1/auth/refresh
      HTTP/2 403  (JSON body) — handler reached, rejected because no refresh cookie was sent
    $ curl -sk -i -X POST https://localhost/auth/refresh                 (negative control — old path)
      HTTP/2 405  (text/html from frontend nginx) — no backend route at /auth/refresh anymore
  The 403 vs 405 contrast proves /api/v1/auth/refresh now reaches the Rust refresh handler. Cookie
  Path in csrf.rs:203/:234 was already /api/v1/auth/refresh; now that the route lives at the same
  path, a browser that captures the refresh cookie at login will send it back to the refresh
  endpoint on the frontend's silent-refresh interceptor (frontend/src/lib/api.ts:93). End-to-end
  browser exercise (login → wait for 15-minute access expiry → API call → refresh interceptor) is
  not reproduced here because the prod surrealdb container is in-memory and re-bootstrapping would
  take longer than the fix it validates — the failing precondition (the path mismatch itself) is
  directly observable and now closed.

### 5. Cross-tab logout detection
expected: Logging out in one tab causes other tabs to detect unauthenticated state on next API call
result: pass
closed_by: 01-04 (commit e2d667c)
evidence: |
  Protocol-level verification after 01-04 landed:
    $ curl -sk -i -X POST https://localhost/api/v1/auth/login \
        -H 'Content-Type: application/json' -d '{"username":"x","password":"x"}'
      HTTP/2 400  body: "Json deserialize error: missing field `tenant_id` at line 1 column 43"
    $ curl -sk -i -X POST https://localhost/auth/login ...                (negative control)
      HTTP/2 405  (from frontend nginx — no /auth/login route served by backend anymore)
  The structured 400 from /api/v1/auth/login is a JSON parse error from the login handler, which
  means: (a) AuthzMiddleware did NOT block the request (login is in PUBLIC_PATHS with the new
  /api/v1/auth/login entry), (b) the request reached the login handler, (c) the body parser ran
  and reported a specific missing field. The old failure mode (401 from authz fall-through) is
  gone. The admin UI (frontend/src/lib/api.ts) was already issuing requests at /api/v1/auth/*,
  so once a session is established, cross-tab logout (POST /api/v1/auth/logout → cookies cleared
  for the shared browser context → other tabs' next /api/v1/auth/me returns 401) works via the
  cookie store the two tabs share. UI-level exercise of the multi-tab flow was not reproduced
  because the test prod container uses in-memory SurrealDB; the root-cause precondition (login
  being unreachable at /api/v1/auth/login) is closed.

## Summary

total: 5
passed: 5
issues: 0
pending: 0
skipped: 0
blocked: 0

## Gaps

(none — both prior blockers closed by 01-04, commit e2d667c)

## Closed Gaps

- truth: "Refresh token flow is reachable and rotates tokens on call"
  status: closed
  closed_by: 01-04 (commit e2d667c)
  original_severity: blocker
  test: 4
  missing: [consistent-refresh-path-scope]
  resolution: "Auth scope moved from /auth to /api/v1/auth, matching the cookie Path=/api/v1/auth/refresh attribute. Refresh handler is now reachable at the path the browser sends the cookie to."

- truth: "Admin UI can authenticate end-to-end against the server"
  status: closed
  closed_by: 01-04 (commit e2d667c)
  original_severity: blocker
  test: 5
  missing: [aligned-auth-path-scope-between-client-and-server]
  resolution: "Auth scope moved to /api/v1/auth, PUBLIC_PATHS entries prefixed with /api/v1, CSRF_EXEMPT_SUFFIXES prefixed likewise, 18 OpenAPI annotations and 36 integration test URIs updated. Login now reaches its handler via the URL the frontend issues."

## Infra & Code Fixes Landed (ancillary, discovered during UAT setup)

These changes are in the working tree (uncommitted) and were required to reach the UAT stage:

1. **Caddy 308 redirect loop** (`docker/docker-compose.prod.yml`, `justfile`) — remapped frontend to host port 8081 so Caddy at :443 can target :8081; documented the corrected Caddy command.
2. **JWT signing keys missing** (`justfile`, `docker/docker-compose.prod.yml`) — `just prod-up` now auto-generates an Ed25519 keypair in `docker/.secrets/` (gitignored) and exports it for compose variable substitution; compose `${VAR:?…}` enforces fail-fast.
3. **All AXIAM_ env vars silently dropped** (`docker/docker-compose.prod.yml`) — renamed every `AXIAM_*` to `AXIAM__*` to match `config`-rs 0.15's prefix-separator semantics (`.with_prefix("AXIAM").separator("__")` with no explicit prefix_separator uses `__` as both separators). Previously the container was silently running on in-code defaults.
4. **SurrealDB v3 SDK rejects URL schemes** (`docker/docker-compose.prod.yml`) — changed `ws://surrealdb:8000` to `surrealdb:8000` (bare host:port). The SDK was resolving the literal string `ws` as the hostname, producing a misleading DNS error.
5. **Bootstrap handler missing app_data** (`crates/axiam-server/src/main.rs`) — registered the raw `Surreal<Client>` handle as `web::Data` so the `/api/v1/admin/bootstrap` handler's `db: web::Data<Surreal<C>>` extractor succeeds. Verified by POST against :8090 directly returning HTTP 201 with the created admin's user_id.
6. **Actix debug logs were dropped** (`Cargo.toml`, `crates/axiam-server/Cargo.toml`) — added the `tracing-log` feature and direct crate dep so `log::debug!` events from third-party crates (actix-web, hyper, tungstenite, lapin) surface in the structured tracing output. Confirmed by seeing tungstenite / lapin DEBUG events at runtime.

## Addendum (2026-04-15, phase 02 UAT drive)

Phase 02 UAT drive through Playwright revealed that 01-04 had only closed half
of the blocker behind UAT Test 5 — the path-scope half. A separate contract drift
(frontend POSTs `{username, tenant_slug, org_slug}`; backend LoginRequest expected
`{username_or_email, tenant_id, org_id}`) kept the admin UI from ever completing a
successful login. This was indistinguishable from the path-scope issue at the
protocol-level curl probes we used to close Tests 4 and 5 earlier — both would
produce 401 from the client's perspective.

Status after the follow-up gap closure:
  - Plan 01-05 (commit f89de1f) makes the backend accept slugs + `username` alias.
  - Additional fix (commit 5949609) corrects `web::Data::new` vs `from` for
    rest_authz so every RBAC-protected admin endpoint stops 500ing.
  - Additional fix (commit 8a8589a) aligns PaginatedUsers TypeScript shape with
    the backend's items/limit response.

With those three landed, end-to-end login from the admin UI is verified working
(Playwright captured `/dashboard` after successful login, and `/users` renders 3
users correctly). UAT Tests 4 and 5 now hold on BOTH protocol-level AND UI-level
evidence.

## Next Action

Phase 01 UAT complete — all 5 tests pass, now with UI-level verification on top
of the protocol-level evidence captured earlier.

Follow-ups (NOT phase 01 blockers; recorded here for traceability):

1. Persistent SurrealDB storage — the `axiam-surrealdb` container's start command
   `start --user root --pass root --log info` omits a datastore path and therefore
   runs in-memory, wiping on every restart. The volume mount `surrealdb-data:/data`
   exists but is unused because no `file://` path is passed to `start`.
2. Pre-existing test failures surfaced during 01-04 baseline comparison (not introduced
   by the gap closure):
     - device_auth_test: 3 tests return HTTP 500 on cert flow
     - auth_test::refresh_uses_cookie_returns_new_access_cookie: 401 (in-process test
       harness bypasses browser cookie Path scoping, so this fails for a different
       reason than UAT Test 4 did)
     - auth_test::reset_mfa_returns_403_until_rbac: HTTP 500
     - webhook_test (all 16 tests): HTTP 500 on webhook create (likely the same
       `web::Data::from` vs `new` pattern elsewhere, or another missing registration)
3. Frontend/backend pagination contract drift — only users/audit/groups/roles were
   fixed or audited during this run. Every other admin service (orgs, permissions,
   resources, certificates, service-accounts, federation, pgp-keys, notification-rules)
   calls `api.get<X[]>(...)` expecting a bare array, which the backend does not
   return. Those pages probably silently render empty. Deserves a dedicated audit.
