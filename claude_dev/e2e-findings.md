# E2E findings — full RBAC / PKI matrix against a working-tree prod stack

Run started 2026-08-29 on branch `claude/full-e2e-tests-and-fixes`.
Method: `E2E-TESTS.md` §5 — waves. Discover everything, triage, fix the whole
batch, rebuild once, re-run.

Stack under test: `docker/docker-compose.prod.yml` built from the working tree,
fronted by `caddy reverse-proxy --from https://localhost --to :8081`.
Playwright `E2E_BASE_URL=https://localhost`.

## Status

| Wave | Findings | Fixed | Re-run result |
|------|----------|-------|---------------|
| 1 | 5 defects (F-01, F-02, F-03, B-01…B-05) + 4 observations | all 5 defects + 3 tooling gaps | see "Wave 2" |

Severity at a glance:

| id | layer | severity | what |
|----|-------|----------|------|
| B-04 | backend | **high** | a tenant admin could install an organization-wide mTLS trust anchor |
| F-02 | frontend | **high** | `/oauth2-clients` was a blank 404 for everyone in the shipped image |
| B-05 | backend | high (functional) | the machine-facing REST surface was unreachable by a machine |
| B-02 | backend | medium | duplicate tenant answered 500, not 409 |
| F-03 | frontend | medium | the selected tenant did not survive a reload |
| B-01 | backend | medium | an empty env gate made the setup-token path unreachable |
| B-03 | tooling | low-medium | a bootstrap script that claimed an idempotence it lacked |

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
- **Fix:** `frontend/src/components/layout/navSections.tsx` — the entry now
  declares `requiredPermission: "audit_logs:list"`, matching its route guard.
  All 22 entries now agree with their routes.
- **Regression test:** `frontend/e2e/matrix/nav-reach.spec.ts` asserts, per
  principal, that a nav entry is enabled exactly when the permission is held —
  and, structurally, that no entry's declared permission differs from the one
  guarding the route it links to.

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
- **Fix:** `.ok().filter(|s| !s.trim().is_empty()).ok_or(())` — an empty gate is
  no gate, and the request falls through to the setup token, which still has to
  be valid and unconsumed.

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
- **Fix:** the tenant repository translates the `idx_tenant_org_slug` unique-index
  violation into `DbError::AlreadyExists`, which the API layer already maps to
  `409 {"error":"already_exists"}`. Done in the repository rather than the
  handler so every caller benefits and the race a pre-check cannot close is
  covered too.

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
- **Fix:** the script now establishes idempotence by probing — if the
  super-admin can sign in, the bootstrap that created it has already happened
  and the call is skipped — rather than by depending on a status code the server
  produces on only one of two gate paths. The handler's ordering is left alone:
  gate-before-lock is a defensible posture for a public endpoint.

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

**Fix:** `crates/axiam-api-rest/src/handlers/org_scope.rs` —
`require_organization_principal`, applied to all sixteen organization-level
handlers. A scope predicate rather than a new permission, because a permission
can be granted to a tenant role again by the very route that created this gap,
whereas where a principal *lives* is a row it cannot edit. See "On B-04,
precisely what was and was not changed" at the end of this document, including
the half deliberately left as a follow-up.

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
- **Fix:** CSRF validation is skipped when the request carries **no** session
  cookie **and** authenticates via `Authorization: Bearer`. The condition is
  extracted as the pure `is_bearer_only(...)` precisely because the case that
  matters is the one where BOTH are present: the browser supplies the cookie,
  an attacker supplies the header, and that request stays subject to validation.
- **Regression tests:** three unit tests on `is_bearer_only` pinning all three
  cases, plus `matrix/service-account-authz.spec.ts`, where a service account
  obtains a `client_credentials` token and makes a real authorization check
  with it.

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
- **Fix:** persisted to `sessionStorage` — per tab, so two tabs can administer
  two tenants without fighting over one value — and restored both into the HTTP
  client's module state and into the auth store, so the topbar label and the
  header it sends cannot disagree. Every access is wrapped: `sessionStorage`
  *throws* in a private window or with site data blocked, and an unreadable
  store must mean "no selection", which is the caller's own scope. The existing
  clear on logout is kept.

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

## Fixes applied in this wave

| # | fix | layer | verified by |
|---|---|---|---|
| F-01 | `navSections.tsx` declares `audit_logs:list` for the Audit Logs entry | frontend | `matrix/nav-reach.spec.ts` |
| F-02 | `location /oauth2/` in `docker/nginx.conf` — trailing slash | frontend | `matrix/spa-routing.spec.ts` |
| F-03 | the selected tenant persists in `sessionStorage`, per tab | frontend | manual reload probe; `matrix/tenancy.spec.ts` |
| B-01 | an empty `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is treated as unset | backend | reasoning + the bootstrap path itself |
| B-02 | duplicate `(org, slug)` on tenant create answers 409, not 500 | backend | `scripts/e2e-bootstrap.sh` re-run |
| B-03 | `e2e-bootstrap.sh` establishes idempotence by probing sign-in | tooling | re-run against a bootstrapped stack |
| B-04 | organization-level handlers require an organization-scoped principal | backend | `matrix/pki.spec.ts` |
| B-05 | CSRF is not demanded of a bearer-only caller | backend | `middleware::csrf` unit tests + `matrix/service-account-authz.spec.ts` |

### On B-04, precisely what was and was not changed

**Changed:** a new guard, `crates/axiam-api-rest/src/handlers/org_scope.rs`,
refuses a caller whose own record does not live in the organization's reserved
scope. It is applied to the sixteen organization-level handlers — every CA
certificate operation (generate, import, revoke, migrate custody, set mTLS
trust anchor, generate/sign intermediates), organization create/update/delete,
tenant create/update/delete, and the organization's email configuration.

The predicate is `principal_tenant_id` → `Tenant::is_organization_scope()`,
which comes from a row the caller cannot edit. Deliberately **not**
`AuthenticatedUser::organization_level`: that flag is set only when a request
names *another* tenant via `X-Axiam-Tenant`, so it is `false` for exactly the
calls that needed guarding. Reads (`GET /organizations`, `GET .../tenants`) are
left alone — the tenant switcher needs them, and they leak nothing across the
boundary.

**Not changed, and why:** an ordinary tenant's seeded `super-admin` role is
still granted the *entire* permission registry, organization-level actions
included (`crates/axiam-db/src/seeder.rs`: "super-admin gets ALL permissions").
Withholding them would be defence in depth, and the two layers would then agree
— but it is a data change to every existing tenant, the `reconcile` path only
ever grants and would need to learn to revoke, and the scope guard already makes
those grants unusable at organization level. **Recommended as a follow-up**,
deliberately not bundled into a fix that is already an authorization-boundary
change.

**Deployment note:** this tightens a boundary. A deployment where a
tenant-level administrator currently creates tenants, or manages CA material,
will start receiving 403 with a message naming the reason. That is the intent —
`scripts/e2e-bootstrap.sh` has always described a tenant admin as administering
"all of `default` and nothing outside it" — but it is a behaviour change, not
only a bug fix, and should be called out in release notes.

### T-01 — a unit test that only passes in an en-US locale
**Layer:** frontend tests
**Severity:** low, but it breaks `npm test` for a whole class of developers.

- **Did:** ran the frontend unit suite while validating the wave-1 fixes.
  1150 of 1151 passed.
- **Happened:** `AttestationPolicyPage.test.tsx` asserted
  `screen.getByText("1,200")`, while the component renders
  `status.entry_count.toLocaleString()` — a bare call, which follows the **host**
  locale. On this machine (it-IT) it renders `1.200`, and the test fails. The
  same run shows the effect elsewhere in the UI: dates render as `29 ago 2026`.
- **Assessment:** the component is right — a number in an admin UI should follow
  the operator's locale. The test is what was wrong, hard-coding one locale's
  grouping separator. CI runs somewhere the literal happens to hold, so this
  only ever broke locally, for anyone outside en-US.
- **Fix:** the expectation is now `(1200).toLocaleString()` — formatted by the
  same rule the component uses, so it holds in every locale.
- **Not touched:** nothing was changed in the component, and no other test was
  audited for the same pattern. Worth a sweep for hard-coded
  locale-formatted literals as a follow-up.

## Wave 2 — result

`E2E_BASE_URL=https://localhost npx playwright test --project=matrix`

**40 passed, 0 failing, 0 unverified.** Every wave-1 fix confirmed against the
rebuilt working-tree images: the escalation probe now answers 403 on all four
paths, `/oauth2-clients` serves `200 text/html`, a service account's own token
makes an authorization check, and the Audit Logs entry is gated.
`scripts/e2e-mail-check.sh`: **11 passed, 0 failed**.

Two failures in that run were bugs in the tests, not the product, and are fixed:

- `NAV_DESTINATIONS` still recorded `/audit-logs` as `navPermission: null` —
  the state it was *found* in. After F-01 the app was right and the table was
  stale, so the matrix reported "a control the server would allow, hidden".
- The tenancy spec read `body.username` from `/auth/me`, which answers
  `{ user: {...}, opaque: {...} }`. `undefined !== "admin"` looked exactly like
  the defect it was asserting against.

One harness gap also fixed: `Api.login` bypassed the 429 retry, so running
`--project=matrix-setup` and `--project=matrix` back to back (the latter re-runs
the former as a dependency) put two rounds of sign-ins inside one
`login_per_min` window and took the whole wave with it.

---

## Wave 2 — new finding

### B-06 — `mtls_trust_anchor` had no effect on the proxy-terminated path
**Layer:** backend (PKI)
**Severity:** medium-high — the documented control for "what may authenticate"
was decorative on the path the shipped deployments actually use.

- **Did:** issued a certificate under an organization CA that was **never**
  flagged as an mTLS trust anchor (`anchor=false`, confirmed against
  `GET /organizations/{id}/ca-certificates`), bound it to a service account, and
  presented it to `POST /api/v1/auth/device` via `X-Client-Certificate`.
- **Expected:** refused. Un-flagging a CA is the documented way to stop trusting
  it.
- **Happened:** authenticated, HTTP 200, and the token's `sub` was the bound
  service account.
- **Root cause:** `crates/axiam-pki/src/mtls.rs` checked the leaf's status and
  validity, verified its signature against the **immediate** issuer, and
  resolved the binding — but never consulted `mtls_trust_anchor`. On the native
  path rustls enforces it, because the client-CA bundle is built from exactly
  the flagged anchors; on the proxy-terminated path — what
  `docker-compose.prod.yml` and the Kubernetes manifests use — nothing did. Any
  CA in the organization was as good as any other.

  The code names the assumption it outgrew: *"Full chain-walk beyond the
  immediate issuer is out of scope (D-02 — flat org/tenant-CA -> device
  hierarchy)."* That was true before tenant **signing CAs** existed. They are
  intermediates, so the hierarchy is no longer flat.
- **How it was nearly missed:** the first version of this assertion used an
  *unbound* certificate under the unflagged CA, and it was refused — for the
  missing binding. It read as a pass. Binding the certificate removed the other
  explanation and the gap appeared immediately. An assertion with two possible
  reasons to succeed tests neither.
- **Fix:** `require_trust_anchor` — a walk from the issuing CA up `parent_ca_id`
  until a CA flagged `mtls_trust_anchor` is reached. A **walk**, not a test of
  the immediate issuer, because a tenant signing CA is an intermediate and is
  deliberately not itself an anchor; requiring the immediate issuer to be
  flagged would refuse every legitimately intermediate-issued certificate. Each
  CA on the way must be `Active` and in date — an anchor reached through a
  revoked intermediate is not reached. The walk is bounded (depth 8):
  `parent_ca_id` is data, and data can describe a cycle.
- **Regression tests:**
  `mtls_chain_reject_leaf_from_ca_that_is_not_a_trust_anchor` — everything valid
  except the flag, and the certificate is **bound**, so the refusal can only be
  about trust. Two existing fixtures now enable the flag explicitly, which is
  the behaviour change stated in test form. `axiam-pki`: 10/10 mTLS tests pass.
- **Deployment note:** like B-04, this tightens a boundary. A deployment
  authenticating devices through a proxy with CAs that were never flagged will
  start being refused, with a message naming the reason. Flag the CA.

### mTLS — what §4 measured, and what it did not

`scripts/e2e-mtls-check.sh`, proxy-terminated path:

| assertion | result |
|---|---|
| a bound certificate authenticates as the account it is bound to (token `sub`) | pass |
| ...and the token carries `aud=axiam:m2m`, not a user audience | pass |
| a certificate bound to no service account is refused | pass |
| a revoked certificate is refused | pass |
| a certificate under a CA that is not a trust anchor is refused | **was the finding; passes after the fix** |
| deleting the service account stops its certificate authenticating | pass |

**Unverified, and stated as such:** the TLS-handshake half. The stack terminates
TLS at Caddy/nginx, so `AXIAM__SERVER__TLS__ENABLED` is not set and rustls never
sees a client certificate. The server says so at boot: *"CA certificates are
flagged as mTLS trust anchors but there is nowhere to write the bundle … Client-
certificate authentication is NOT enabled."* Measuring it needs
`AXIAM__SERVER__TLS__ENABLED=true` with `CERT_PATH`, `KEY_PATH`,
`CLIENT_AUTH=optional|required` and a published TLS port.
