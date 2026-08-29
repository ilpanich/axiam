# E2E findings — full RBAC / PKI matrix against a working-tree prod stack

Run started 2026-08-29 on branch `claude/full-e2e-tests-and-fixes`.
Method: `E2E-TESTS.md` §5 — waves. Discover everything, triage, fix the whole
batch, rebuild once, re-run.

Stack under test: `docker/docker-compose.prod.yml` built from the working tree,
fronted by `caddy reverse-proxy --from https://localhost --to :8081`.
Playwright `E2E_BASE_URL=https://localhost`.

## Status

| Wave | Started | Findings | Fixed | Re-run result |
|------|---------|----------|-------|---------------|
| 1    | 2026-08-29 | (in progress) | — | — |

---

## Wave 1

### F-01 — "Audit Logs" nav item is ungated while its route is not
**Layer:** frontend
**Found by:** static comparison of `frontend/src/components/layout/navSections.tsx`
against `frontend/src/router.tsx` (to be confirmed in-browser as the `viewer`
principal).

- **Did:** compared every sidebar item's `requiredPermission` with the
  `<ProtectedRoute permission=...>` guarding the route it links to.
- **Expected:** they agree, so the sidebar never offers a destination the route
  will refuse.
- **Happened:** `/audit-logs` is declared `requiredPermission: null` in
  `navSections.tsx` (always enabled) but its route is wrapped in
  `<ProtectedRoute permission="audit_logs:list">`. Every other one of the 22
  entries agrees with its route.
- **Root cause:** the nav entry was never given the permission its route
  acquired.
- **Impact:** a principal without `audit_logs:list` gets a live, clickable
  "Audit Logs" link that dead-ends in the route guard. This is the
  "renders a control the server would refuse" class from E2E-TESTS.md §2.
- **Fix:** _pending_

### B-01 — empty `AXIAM_BOOTSTRAP_ADMIN_EMAIL` closes the bootstrap gate entirely
**Layer:** backend
**Found by:** reading `crates/axiam-api-rest/src/handlers/bootstrap.rs:269`
while preparing the stack.

- **Did:** traced what happens when the env gate variable is *present but
  empty* — the shape Docker Compose produces for
  `AXIAM_BOOTSTRAP_ADMIN_EMAIL: "${AXIAM_BOOTSTRAP_ADMIN_EMAIL:-}"`.
- **Expected:** an empty gate is no gate; fall through to the setup-token path.
- **Happened:** `std::env::var` returns `Ok("")`, the handler takes the
  env-gate branch, compares `req.email != ""`, and answers 403 *"email does not
  match AXIAM_BOOTSTRAP_ADMIN_EMAIL"* — with the setup-token path unreachable.
  A valid one-time setup token cannot bootstrap the system.
- **Root cause:** `match std::env::var(...)` treats `Ok("")` as "gate set".
- **Fix:** _pending_

### B-02 — re-creating an existing tenant answers 500, not 409
**Layer:** backend
**Severity:** medium — it makes every provisioning script non-idempotent.

- **Did:** `POST /api/v1/organizations/{org_id}/tenants` with a `slug` that
  already exists in that organization (the matrix fixture's second wave).
- **Expected:** `409 Conflict`, the answer `POST /api/v1/users` gives for the
  same situation, and the answer `scripts/e2e-bootstrap.sh` is written against:
  `409) echo "Tenant ${TENANT_SLUG} already exists (409) — skipping."`.
- **Happened:** `500 {"error":"internal_error","message":"An internal error occurred"}`.
  Server log:
  `Database error: Migration failed: Database index 'idx_tenant_org_slug' already contains ['<org>', 'mx-tenant-b'] ...`
- **Root cause:** the tenant-create handler does not pre-check the (org, slug)
  uniqueness and does not translate the SurrealDB unique-index violation into
  `AxiamError::AlreadyExists`; it falls through to the generic
  `Internal` mapping. Every other create path in the API that has a natural key
  does one or the other.
- **Impact:** the documented idempotent branch of `e2e-bootstrap.sh` is dead
  code, and an operator re-running a provisioning script sees an opaque 500
  where the system is in fact fine.
- **Fix:** _pending_

### B-03 — bootstrap on an already-bootstrapped system answers 403, not 409, whenever the gate is a setup token
**Layer:** backend (behaviour) / tooling (the claim that depends on it)
**Severity:** low-medium — operationally confusing, not a security hole.

- **Did:** ran `scripts/e2e-bootstrap.sh` a second time against the prod-shaped
  stack, whose gate is the one-time setup token the server mints at first boot.
- **Expected:** `409` — "already initialized" — which is what the script
  handles and what the handler does return when the gate is
  `AXIAM_BOOTSTRAP_ADMIN_EMAIL`.
- **Happened:** `403 {"message":"...bootstrap gate not satisfied: set
  AXIAM_BOOTSTRAP_ADMIN_EMAIL or provide a valid setup_token"}` — the token was
  consumed by the first successful call, so the gate refuses before anything
  looks at whether the system is bootstrapped at all.
- **Root cause:** ordering in `crates/axiam-api-rest/src/handlers/bootstrap.rs`
  — step 1 is the gate, step 3 is the `bootstrap_lock:global` check. On the
  env-gate path the caller passes step 1 and reaches the 409; on the
  token path the (correctly) single-use token makes step 1 terminal.
- **Assessment:** the ordering is *defensible as security posture* —
  `/admin/bootstrap` is public, and answering 409 tells an unauthenticated
  caller the deployment is initialised. It is not obviously a bug to fix in the
  handler. What is wrong is `scripts/e2e-bootstrap.sh`'s claim that "both steps
  are idempotent, so re-running against an already-seeded stack is a no-op":
  that is false for every stack whose gate is a token, i.e. every
  production-shaped one.
- **Fix:** _pending_ — make the script establish idempotence by probing
  (org-level sign-in succeeds ⇒ already bootstrapped ⇒ skip), rather than by
  depending on a status code the server only produces on one of two gate paths.

### O-01 — `POST /api/v1/users` is capped at 5/min per IP (observation, not a defect)
**Layer:** backend, by design

Creating the fixture's sixth user answered `429 rate_limit_exceeded`. This is
deliberate: `POST /users` shares the `register_per_min` bucket (5/min in the
shipped `internet` posture), and the comment above the two `/users` resources in
`crates/axiam-api-rest/src/server.rs` shows the `GET` was already split off this
bucket for exactly this reason. Recorded because it shapes tooling — a fixture,
a bulk import or a SCIM backfill must expect it — not because it is wrong.
The matrix client now waits out a 429 (honouring `Retry-After`) instead of
reporting it as a broken step.


### F-02 — `/oauth2-clients` is a blank 404 for every principal in the production image
**Layer:** frontend (reverse-proxy configuration)
**Severity:** high — one admin page is completely unreachable in the shipped image.

- **Did:** walked all 22 sidebar destinations as each of the eight matrix
  principals against the production-like stack behind Caddy.
- **Expected:** `/oauth2-clients` renders the OAuth2 Clients page for a
  principal holding `oauth2_clients:list`, and `Access Denied` for one that does
  not.
- **Happened:** an empty document body and no `<h1>` at all, for **every**
  principal including the organization super-admin (who holds `*`).
  `curl -o /dev/null -w '%{http_code}' https://localhost/oauth2-clients` → `404`
  with no content type. Every one of the other 29 SPA routes → `200 text/html`.
- **Root cause:** `docker/nginx.conf` contained

  ```nginx
  location /oauth2 {          # prefix match
      proxy_pass http://axiam-server:8090;
  ```

  nginx `location /oauth2` is a **prefix** match, so it captures
  `/oauth2-clients` as well as `/oauth2/authorize`, and forwards the SPA route
  to a backend that has no such endpoint. React is never reached, so
  `ProtectedRoute` never runs and there is nothing to render.
- **Why nothing caught it:** `frontend/vite.config.ts` already guards exactly
  this case — `"^/oauth2(/|\\?|$)"`, with the comment *"match /oauth2/ and
  /oauth2? but NOT /oauth2-clients (frontend route)"*. The fix was made in the
  dev/preview proxy and never mirrored into the nginx config the image ships.
  CI runs the E2E suite against `vite preview`, which uses the corrected proxy,
  so the suite was green while the shipped image was broken. This is precisely
  the class of defect the "test the production image" instruction exists for.
- **Fix:** `location /oauth2/` — narrowed to the trailing slash. Every backend
  OAuth2 endpoint is under `/oauth2/` (`authorize`, `token`, `introspect`,
  `revoke`, `jwks`, `userinfo`, `par`, `device_authorization`, `end_session`),
  so nothing is lost, and `/oauth2-clients` falls through to the SPA fallback in
  `location /`.
- **Regression test:** `frontend/e2e/matrix/spa-routing.spec.ts` — asserts every
  registered SPA route is answered `200 text/html`, unauthenticated, so any
  future proxy prefix that captures any future SPA route fails immediately.
  Fails before the fix on `/oauth2-clients`, passes after.

### O-02 — the sidebar's landmark is labelled but is not a navigation landmark (observation)
**Layer:** frontend, accessibility, minor

`frontend/src/components/layout/Sidebar.tsx` puts `aria-label="Main navigation"`
on the `<aside>`, whose implicit ARIA role is `complementary`; the `<nav>`
inside it carries no accessible name. A screen-reader user listing navigation
landmarks finds an unnamed one, and the named landmark is filed under
"complementary". Not a permission defect and not what this run is for — recorded
because the matrix had to work around it to locate nav entries at all.
