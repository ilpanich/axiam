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

### B-04 — a TENANT-level super-admin can act at ORGANIZATION level, including installing an org-wide mTLS trust anchor
**Layer:** backend (authorization)
**Severity:** high — it crosses the tenant isolation boundary the product is built on.

**What the system says the principal is.** `GET /api/v1/auth/me` for
`tenant-admin`:

```json
{"username":"tenant-admin","organization_level":false,
 "principal_tenant_slug":"default","tenant_slug":"default",
 "org_id":"01a04c95-…"}
```

`scripts/e2e-bootstrap.sh` states the intent in its own words: the tenant admin
holds the tenant's seeded `super-admin` role "with no resource_id, which makes
it a global grant *within this tenant* — the tenant admin administers all of
`default` and nothing outside it."

**What it can actually do.** Signed in as `tenant-admin` (tenant `default`),
against its own organization:

| request | result |
|---|---|
| `POST /organizations/{org}/ca-certificates` | **201** — minted an organization root CA |
| `PUT  /organizations/{org}/ca-certificates/{id}/mtls-trust-anchor` `{"enabled":true}` | **200** `{"mtls_trust_anchor":true,"restart_required":true}` |
| `POST /organizations/{org}/tenants` | **201** — created a new tenant `mx-escalation-probe` |
| `POST /organizations` | **201** — created a new organization `mx-escalation-probe-org` |

The second row is the serious one. An mTLS trust anchor is organization-wide:
once installed, a certificate chaining to it authenticates against the
deployment, and the tenant admin holds the CA's private key. A tenant
administrator can therefore mint client certificates that authenticate as
principals **outside its own tenant** — which is the isolation guarantee the
whole product rests on.

**Root cause — two things compounding.**

1. The `super-admin` role seeded into an ordinary tenant is granted the *entire*
   permission registry, organization-level actions included:
   `organizations:create`, `organizations:delete`, `organizations:update`,
   `tenants:create`, `tenants:delete`, `ca_certificates:generate`,
   `ca_certificates:manage`, `ca_certificates:revoke`. Confirmed in the
   `permissions` array `/auth/me` returns for `tenant-admin`.
2. The organization-level handlers check *permission* plus *same organization*,
   and nothing else. From `crates/axiam-api-rest/src/handlers/ca_certificates.rs`:

   ```rust
   RequirePermission::new("ca_certificates:generate", Uuid::nil())
       .check(&user, authz.get_ref().as_ref()).await?;
   let org_id = path.into_inner();
   // Authorization: only allow access to certificates in the caller's own org.
   if org_id != user.org_id { /* denied */ }
   ```

   `user.org_id` is the organization the caller's *tenant* belongs to, so the
   guard passes for every principal in the organization. Nothing consults
   `organization_level`. `POST /api/v1/organizations` has no organization
   binding to check at all.

**Why nothing caught it:** the two halves are individually reasonable. A
tenant's super-admin *should* hold everything that applies to its tenant, and an
organization endpoint *should* refuse a caller from a different organization.
The gap is the case neither addresses — a caller from the *same* organization
but the *wrong scope within it*.

**Fix:** _pending_ — the shape wanted is a scope predicate on the
organization-level handlers ("the caller's own record lives in the organization
scope"), not a new permission, since a permission can be granted to a tenant
role again by the same route. The seeded tenant `super-admin` role should also
stop carrying organization-level actions, so the two layers agree.

**Probe artifacts left in the test stack** (throwaway, but named so they can be
found): CA `CN=mx-escalation-probe`, CA `CN=mx-escalation-probe-2` (its trust
anchor re-disabled), tenant `mx-escalation-probe`, organization
`mx-escalation-probe-org`.

### B-05 — CSRF middleware makes the machine-facing REST surface unreachable for machine tokens
**Layer:** backend (middleware)
**Severity:** high (functional) — the one REST surface built for machine
identities cannot be called by one.

- **Did:** obtained a `client_credentials` token for the service account
  `mx-sa-direct`
  (`POST /oauth2/token?tenant_id=<A>`, → 200, `aud = axiam:m2m`), then called
  the authorization check it exists to make:

  ```
  POST /api/v1/authz/check
  Authorization: Bearer <m2m token>
  {"action":"users:list","resource_id":"<mx-root>"}
  ```
- **Expected:** an authorization decision. `AuthenticatedPrincipal` — the
  extractor this route uses — was introduced precisely so a machine audience
  could reach it. Its own doc-comment: *"It is used only on the
  authorization-check endpoints, which are the machine-facing read-only
  surface."* `sdks/CONTRACT.md` describes the same route for SDK clients.
- **Happened:** `403 {"error":"authorization_denied","message":"Authorization
  denied: CSRF validation failed"}`.
- **Root cause:** `crates/axiam-api-rest/src/middleware/csrf.rs` requires, for
  every non-safe method on every non-exempt path, an `axiam_csrf` cookie whose
  value matches the `X-CSRF-Token` header:

  ```rust
  let valid = match (cookie_value, header_value) {
      (Some(cookie), Some(header)) => cookie.as_bytes().ct_eq(header.as_bytes()).into(),
      _ => false,
  };
  ```

  A bearer-authenticated machine client has no cookie and therefore cannot
  satisfy it. The exemption list covers unauthenticated flows (login, MFA,
  OPAQUE, OAuth2 prefixes) but has no notion of "authenticated by an
  `Authorization` header rather than by a cookie".
- **Why the check is not protecting anything here:** CSRF is an attack on
  *ambient* credentials — a cookie the browser attaches on its own. A request
  authenticated solely by an `Authorization` header carries no ambient
  credential, and a cross-site attacker cannot set that header on a victim's
  behalf. Demanding a double-submit cookie from a caller that has none is
  unsatisfiable rather than protective.
- **Effect:** `POST /api/v1/authz/check` and `/authz/check/batch` — and any
  future machine-facing POST — are dead to machine tokens. The audience
  widening that `AuthenticatedPrincipal` exists to provide is entirely defeated
  by a middleware that runs before it.
- **Fix:** _pending_ — skip CSRF validation when the request carries no session
  cookie **and** authenticates via `Authorization: Bearer`. The precise
  condition matters: a request that has *both* a session cookie and a bearer
  header must still be validated, or the exemption becomes the bypass.
- **Regression test:** to be added alongside the fix — a service account gets a
  token and makes an authorization check with it.

### O-03 — `/oauth2/token` requires `tenant_id` as a query parameter (observation)
Not a defect: it is declared `required` in `sdks/openapi.json` and the server
answers `400 "Query deserialize error: missing field tenant_id"` without it.
Recorded because it is unusual for an OAuth2 token endpoint and is the first
thing a client written from the RFC rather than from the spec will get wrong —
the error text at least names the field.

### F-03 — the selected tenant does not survive a page reload
**Layer:** frontend
**Severity:** medium — usability and deep-linking, not correctness.

- **Did:** as the organization super-admin, switched to `E2E Default Tenant`
  with the topbar tenant selector, then (a) navigated to Users by clicking the
  sidebar link, and (b) reloaded the page.
- **Expected:** the selection survives both.
- **Happened:**
  - (a) **correct.** `X-Axiam-Tenant: <tenant A>` is sent, and tenant A's six
    users are listed. The switcher works.
  - (b) after `reload()`, the header is **absent**, the list falls back to the
    organization scope (only `admin`), and the topbar label resets to
    `test-org / Organization`.
- **Root cause:** the selection lives in module state —
  `let activeTenantId: string | null = null` in
  `frontend/src/lib/activeTenant.ts`, mirrored into a non-persisted zustand
  field. Nothing writes it to `sessionStorage` or to the URL, so a full document
  load starts over.
- **Assessment:** the UI stays *self-consistent* — the label resets with the
  scope, so nothing is silently mislabelled, and no data crosses a boundary.
  What breaks is continuity: an operator who reloads mid-task, or who opens a
  bookmark or a shared deep link to a child tenant's page, silently lands in the
  organization scope instead.
- **Fix:** _pending_ — persist to `sessionStorage` (per tab, so two tabs can
  administer two tenants), restore it in the same place the auth store hydrates,
  and keep the existing `logout` clear.

**Correction to an earlier reading of this run.** A first probe navigated with
`page.goto()` — a full document load — and reported the switcher as entirely
cosmetic. It is not; that probe was measuring (b) while believing it measured
(a). The matrix spec now navigates in-app after switching, which is what an
operator does and what the assertion is about.

### O-04 — revocation records no timestamp and no reason; there is no CRL or OCSP
**Layer:** backend, PKI. Recorded as a gap, not a defect.

Revoking a certificate twice answers `200` both times. That is *correct*: the
repository does `UPDATE certificate SET status = 'Revoked'` and nothing else, so
the second call is a genuine no-op and X.509 revocation is monotonic anyway. An
assertion in this run that expected a `4xx` was wrong and has been changed.

What the same code shows is worth recording separately: `Certificate` carries no
`revoked_at` and no revocation reason — `POST /certificates/{id}/revoke` accepts
no reason and stores no time — and there is no CRL or OCSP responder anywhere in
`axiam-pki` or `axiam-api-rest`. Revocation is a status flag readable only
through this API. A relying party outside AXIAM has no standard way to learn a
certificate was revoked, and a CRL entry needs a `revocationDate` that is not
being recorded. No roadmap or requirements entry mentions CRL or OCSP, so this
is flagged rather than assumed to be planned.

## Email — verified, at the log (E2E-TESTS.md §3)

`scripts/e2e-mail-check.sh`, run against the working-tree prod stack with an
SMTP provider configured for the organization. **11 checks, all passing.**

| assertion | result |
|---|---|
| `Mail consumer spawned` at boot (not "NOT spawned") | pass |
| **org-level** reset for a real principal → one `sending email` line, `provider: smtp` | **pass** |
| tenant-level reset for a real principal → one `sending email` line | pass |
| reset for an address that does not exist → `{"sent": true}` and **no** mail | pass |
| reset naming an organization that does not exist → `{"sent": true}` and **no** mail | pass |

**The reported organization-level reset bug does not reproduce on this build.**
A reset carrying an org slug and no tenant resolves the principal, queues a
`PasswordReset` message, and the consumer attempts delivery. The enumeration-safe
silences behave correctly in the other direction, which is the half a
response-body test cannot see — both answer the identical `{"sent": true}`.

Three things the script had to get right before any of that meant anything, each
of which produced a false result first:

- **`docker logs --since` reads a bare timestamp as LOCAL time.** A UTC instant
  emitted without a `Z` opened every window two hours early on a UTC+2 host, so
  every probe counted every earlier message's retries and the consumer appeared
  never to go quiet. RFC 3339 with the zone suffix.
- **`MAX_RESETS_PER_DAY = 3` per user**, and a request over the cap funnels into
  the same `{"sent": true}` with no mail — correct, and indistinguishable from
  the broken case. The script now mints a throwaway probe user per scope on
  every run rather than reusing a fixed address.
- **The consumer retries at 10s then 20s before dead-lettering**, so a "quiet"
  stretch shorter than 20s is not quiet; the settle window is 25s.

### Not verified, and why

**Rendered subjects and bodies.** Catching a template that renders
`{{tenant_name}}` literally needs the message itself, and a local catcher cannot
receive one from this stack: `SmtpProvider` uses lettre's `relay()` (implicit
TLS) when `starttls` is false and `starttls_relay()` when it is true —
*"Neither falls back to cleartext; both enforce TLS"* — and the client verifies
against compiled-in roots with no skip-verification option. Mailpit on the
compose network was reached and refused the connection at the TLS layer
(`received corrupt message of type InvalidContentType` on AXIAM's side,
`500 5.5.2 Syntax error, command unrecognized` on Mailpit's — a ClientHello
being parsed as SMTP). That is the product behaving as designed, not a defect,
so template rendering is recorded as **unverified**, needing either a
publicly-trusted catcher or a trust-store change in the server image.
