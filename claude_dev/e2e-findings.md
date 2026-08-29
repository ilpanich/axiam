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

---

# Wave 3 — closing the unverified half, and what it turned up

Wave 2 ended with two areas recorded **unverified** rather than passed: the
TLS-handshake half of mTLS, and rendered mail templates. Both are now measured.
Closing the first one is what surfaced B-07, which is the most serious defect
found in the whole exercise and was invisible to every wave before it, because
no wave had ever run two AXIAM processes at once.

## Precondition — the running image was older than the fix it was meant to carry

Before anything else: the `axiam-server` image in the running stack was built at
12:08 and the B-06 mTLS trust-anchor fix was committed at 12:39. Wave 2's
green mTLS result for "a certificate under a CA that is not a trust anchor is
refused" was therefore taken from `cargo test`, not from the stack. The image
was rebuilt and the container recreated before any assertion below was made.

Worth stating plainly because it is a cheap mistake to repeat: `docker compose
up -d` does not rebuild, and a container that is already running is not
restarted by a build. Compare `docker image inspect --format '{{.Created}}'`
against `git log -1 --format=%cI -- crates/` before trusting a wave.

## B-07 — a second AXIAM process logs out every one already running, permanently

**Layer:** backend (`axiam-db`)
**Severity:** high. Two replicas cannot coexist, a rolling deployment wedges
every old pod, and nothing recovers without a restart.

- **Did:** started a second server container from the same image against the
  same SurrealDB — which is all a second replica, or the overlap window of a
  rolling deploy, is. Polled `POST /api/v1/auth/login` every five seconds for
  350 seconds.
- **Expected:** no effect on the first server; two replicas against one
  datastore is the deployment `k8s/` describes.
- **Happened:** the first server went from `200` to `401` **five seconds** after
  the second one booted, stayed `401` for the entire 350-second window, and was
  **still** `401` after the second container was removed. Its own log carried
  one line per second:

  ```
  Failed to write audit log entry
    error: Database error: SurrealDB error: HTTP status client error
           (401 Unauthorized) for url (http://surrealdb:8000/rpc)
  ```

  Only a restart fixed it. Meanwhile the container reported **healthy** and
  `docker ps` showed nothing wrong — the healthcheck subcommand does not touch
  the datastore, so it measures liveness, not usefulness.

- **Root cause, first half — the trigger.** `DbManager::extend_root_token_duration`
  runs at every boot:

  ```sql
  DEFINE USER OVERWRITE axiam ON ROOT PASSWORD '…' ROLES OWNER
    DURATION FOR TOKEN 2419200s, FOR SESSION NONE
  ```

  Its doc comment called this "**Idempotent** — safe to run on every startup".
  It is idempotent in the state it leaves behind and emphatically not in its
  effect: `PASSWORD` re-hashes with a fresh salt, and SurrealDB signs root
  tokens against that hash, so the statement invalidates every token already
  issued for that user. The comment states exactly the belief that caused the
  bug.

  Note the asymmetry that made this so hard to see: SurrealDB **basic** auth
  keeps working throughout, because the password *string* is unchanged. A
  `curl -u axiam:… /sql` probe answers `200` and returns real rows from a
  datastore the server can no longer read a single row from. Any diagnosis that
  reaches for that probe concludes the database is fine.

- **Root cause, second half — why it never recovered.** There *is* machinery for
  this: `health_check` classifies auth failures as `DbError::Unhealthy`, and a
  reconnect loop polls every 5 seconds and rebuilds the handle. It never ran.
  `classify_query_error` recognised only

  ```rust
  matches!(err.not_allowed_details(), Some(NotAllowedError::Auth(_)))
  ```

  which is the shape the **WebSocket** engine produces. AXIAM has run the
  **HTTP** engine since Phase 13. There, the server answers `401` at the
  transport, before any SurrealQL response exists — and the SDK maps *every*
  `reqwest::Error` to `ErrorDetails::Connection(ConnectionFailed)`, flattening
  the status into the message and discarding `reqwest::Error::status()`
  (`surrealdb-types-3.2.4/src/error.rs:1080`). So the one error that had to
  reach the reconnect loop arrived looking like an ordinary query failure. Zero
  `Unhealthy` and zero reconnect attempts appear in five minutes of logs.

  The engine switch and the classifier were each correct when written. The
  classifier was simply never revisited for the engine that replaced the one it
  was written against.

- **Fix, both halves:**
  1. `is_transport_auth_rejection` — an error carrying reqwest's
     `HTTP status client error (401 Unauthorized)` (or `403 Forbidden`) now
     classifies as `Unhealthy`, so the reconnect loop fires and the handle is
     rebuilt. Deliberately narrow: a timeout or a refused connection says
     nothing about whether *this handle's* credentials are still accepted, and
     treating those as `Unhealthy` would rebuild every pooled connection on any
     network blip — the thundering herd the backoff exists to prevent.

     **The first version of this fix did not work, and its unit test passed.**
     The SDK's `From<reqwest::Error>` builds
     `ErrorDetails::Connection(ConnectionFailed)`, so the predicate keyed on
     `connection_details().is_some()` — reasonable, unit-tested against an
     error constructed that way, green. It changed nothing on the running
     stack. The error that actually arrives does not come through that
     conversion:

     ```text
     Error { code: -32000,
             message: "HTTP status client error (401 Unauthorized) for url (…/rpc)",
             details: Internal, cause: None }
     ```

     `Internal` is the enum's forward-compatibility catch-all, so
     `connection_details()` returns `None` and the predicate was false for
     exactly the error it was written for. The match is now on the message
     alone — the full reqwest phrase, not a bare `401`, so a query error that
     happens to mention the number cannot be mistaken for one.

     This was caught by *making a live server produce the error* rather than
     writing down what it was assumed to be:
     `a_redefined_root_user_classifies_as_unhealthy_on_the_http_engine`
     connects over the HTTP engine, redefines the root user from a second
     connection, and asserts the classification of whatever comes back. It is
     `#[ignore]`d like the other live tests and runs against any SurrealDB:
     `AXIAM_TEST_DB_URL=127.0.0.1:8001 cargo test -p axiam-db --test
     connection_resilience_test -- --ignored`.

     The general lesson, since it cost a full image rebuild: a unit test that
     constructs the error it is testing tests the construction, not the system.
     Where the shape of a third-party error is load-bearing, one live test that
     provokes it is worth more than any number of hand-built ones.
  2. `extend_root_token_duration` now **asks before overwriting**: it reads the
     user's current `DURATION FOR TOKEN` from `INFO FOR ROOT` and skips the
     redefine when it is already at least the configured TTL. Every unreadable
     case — failed query, unrecognised shape, unparseable literal — falls
     through to the redefine, i.e. the previous behaviour. Being wrong in that
     direction costs a redefine; being wrong in the other direction would leave
     the TTL at SurrealDB's ~1h default while the re-signin task waits weeks,
     which is the original Phase-14 expiry bug.

     This needed a duration parser, which the module had deliberately avoided
     ("no duration-string parser is needed — the literal is derived FROM the
     `Duration`, never the reverse"). That held while nothing read the value
     back. It does now, and SurrealDB does not answer in the units it was
     given: a TTL written as `2419200s` comes back as `4w`.

- **Regression tests** (`axiam-db`, 8 + 3 passing):
  `health_classification_maps_the_http_engines_401_to_unhealthy` uses the error
  string verbatim from the wedged server;
  `health_classification_leaves_an_ordinary_connection_failure_alone` pins the
  narrowness; `a_duration_survives_the_round_trip_surrealdb_actually_performs`
  asserts `4w` parses to the TTL written as `2419200s` — if those stop agreeing
  the pre-check silently stops working and the redefine returns on every boot.
  `anything_unrecognised_is_none_so_the_caller_redefines` covers eight
  malformed literals, because a plausible-looking wrong number is the dangerous
  failure here, not a `None`.

- **How it was found:** entirely by accident. The native-mTLS sidecar (below) is
  a second server process, and it knocked the main one over. No wave before this
  one had ever run two AXIAM processes against one datastore, which is why four
  waves of a deliberately exhaustive matrix never came near it.

## mTLS §4 — the handshake half, now measured

`scripts/e2e-mtls-native-check.sh` is new. It starts a **second server container
from the same image**, on the same network and database, with
`AXIAM__SERVER__TLS__ENABLED=true` and a self-signed listener certificate, and
lets the server derive client trust the way an operator would: from the
organization CAs flagged `mtls_trust_anchor`, which it collects at boot, writes
as a PEM bundle, and — since `client_auth` is left `off` — points a
`WebPkiClientVerifier` at in `optional` mode. The running stack is not disturbed.

**22 passed, 0 failed, 0 unverified.**

| assertion | result |
|---|---|
| the server logs `Direct TLS enabled — negotiating TLS 1.3 only` | pass |
| a TLS 1.2 handshake is refused, and a 1.3 handshake succeeds | pass |
| the client-CA bundle is built from the flagged anchors (`anchors: 7`) and client auth turns itself on | pass |
| a certificate under a flagged anchor authenticates **with no `X-Client-Certificate` header sent at all** | pass |
| ...as the service account it is bound to, with `aud=axiam:m2m` | pass |
| a certificate under a CA that was never flagged is refused **by rustls**, before any HTTP status exists | pass |
| a revoked, bound, chain-valid certificate completes the handshake and is refused by `axiam-pki` (401) | pass |
| an `X-Client-Certificate` header **cannot** override the rustls-verified peer certificate | pass |
| un-flagging an anchor stops the certificate authenticating; re-flagging restores it | pass |

`scripts/e2e-mtls-check.sh` no longer reports those two as UNVERIFIED. They are
not unverified any more — they are simply not measurable on the proxy path, and
it now says so and names the script that does measure them. Running only one of
the two leaves half of §4 untested, which is exactly the state wave 2 ended in.

The header-precedence assertion is the one worth keeping. `cert_auth.rs` claims
the verified certificate "cannot be spoofed by a header", and its own tests note
that path is "unreachable" from a unit test — there is no TLS connection in one.
The probe presents a valid bound certificate over TLS *and* a different, equally
valid, equally bound certificate in the header, so "the header was ignored" and
"the header's certificate was unusable" cannot be confused.

Two things about the harness, both of which cost a run before they were right:

- **Not port 8443, and not 8080.** A SAGE node holds both on this host. The
  sidecar failed to bind and `docker run` reported it as a container failure,
  which reads like an image problem. The script defaults to `9443` and the
  failure path now prints the `docker run` error rather than only container logs.
- **Not `%{ssl_version}`.** Not every `curl` build exposes that write-out
  variable, and one that does not returns an empty string — which reads as
  "negotiated nothing", a failure report about the probe. "TLS 1.3 only" is now
  asserted by showing a TLS 1.2 offer is refused *and* a 1.3 offer is accepted,
  which every curl can do.

## §3 mail templates — closed at the source, not through a catcher

Wave 2 recorded rendered subjects and bodies as unverified because a local SMTP
catcher cannot receive from this stack: `SmtpProvider` enforces TLS on both code
paths and verifies against compiled-in roots, so Mailpit is refused at the TLS
layer. That is the product behaving as designed.

The transport was never the interesting part. "A template that renders
`{{tenant_name}}` literally" is a property of a *(template, context)* pair, and
both halves are in this repository: the identity keys the consumer always
inserts, and the keys each publisher puts in `template_context`. So the pair is
asserted directly, in `crates/axiam-amqp/tests/mail_consumer_test.rs`:

`every_mail_type_renders_with_no_placeholder_left_standing` walks
`MailType::ALL` (a new const, so a sixth mail type cannot be added without the
test noticing), builds the identity context from the real `identity_context`
against a database where **nothing resolves** — the worst case, which proves the
four keys are unconditional rather than incidental to a seeded fixture — overlays
the publisher's declared keys, and renders subject, text body and HTML body of
that type's built-in template. Nothing may contain `{{`.

This is stronger than one observation through a catcher: it holds for all six
templates, runs in CI, and fails the moment a template grows a placeholder
nobody supplies. **Verified by mutation** — injecting `{{support_email}}` into
the `ExportReady` subject fails it with the offending text quoted; reverting
passes.

The `match` in `publisher_context_keys` is exhaustive on `MailType`, so a new
variant does not compile until someone says what its publisher supplies. What it
does not cover, stated rather than implied: that each publisher still *sends*
those keys. The table is a declaration quoted from the five call sites, not a
reading of them. It closes the direction the bug actually travels — a template
asking for more than it is given.

## The matrix was not measuring everything it appeared to

Two gaps in the harness itself, found by comparing it against the application
rather than against its own last run.

### `/settings/webauthn-attestation-policy` was never visited

`NAV_DESTINATIONS` had 22 entries and the application declares 23 permission-
gated pages. The missing one is gated by `webauthn_policy:read`, a permission no
other destination uses — so that boundary was unmeasured in **both** directions
for as long as the table has existed, and every wave reported clean over it.

It is reached from the Settings page rather than the sidebar, which is why it
was missed. Recording it as `navPermission: null` would have claimed there *is*
a sidebar gate, declared ungated — the exact shape of the F-01 finding — so
`NavDestination` gained an `inNav` flag: "not offered" is a different statement
from "offered to everyone". The route gate is still asserted both ways, because
a page nobody links to is still reachable by typing its URL.

A hand-maintained table of what to measure goes stale in the one direction that
is invisible, so `nav-reach.spec.ts` now also carries
**`every route the application declares is in the matrix`**: it reads
`router.tsx` and fails on any declared path no destination covers. Public/auth
routes, parameterised paths and the not-found fallback are exempt, each with a
reason. It reads the file as text rather than importing it — `router.tsx` pulls
in every page component, and a Playwright worker is not a place to evaluate
React modules that expect a DOM — and asserts it found more than ten paths, so
a rename that made it read nothing fails loudly instead of passing vacuously.

### In-page controls were not checked in either direction

Twelve pages gate controls one level below the route, with
`usePermissions().can(...)`: the "New Token" button on SCIM provisioning, the
tenant/system switch on audit logs, the act-on-behalf-of fields on the privacy
page, and more. §2 is explicit that both directions of such a gate are defects,
and **none of it was being measured**. A `can("scim_tokens:create")` that
inverted, or that named a permission the registry does not issue, would surface
as an operator who "just cannot find the button" while every page-level
assertion stayed green.

`frontend/e2e/matrix/in-page-controls.spec.ts` is new. For each principal it
asserts each gated control is rendered exactly when its permission allows it,
skipping controls on pages that principal cannot open — that refusal is
`nav-reach`'s to make — and failing loudly if a page did not render, so "the
control is absent" can never pass as a measurement of an error page.

It also carries a typo guard: every permission named by a gate must be one the
super-admin actually holds. A misspelt permission string is invisible from
inside the UI — it simply never matches, so the control is hidden from everyone
and the page still works for the people who were going to be refused anyway. The
guard skips itself, loudly, if the super-admin turns out to hold `*`, since a
wildcard matches typos too.

Gates that only appear after selecting a row (`ScopesPanel`,
`EffectiveAccessPanel`, the per-row bind-certificate action on service accounts)
are **not** covered: reaching them needs fixture data whose absence would read as
"the control is correctly hidden", which is the one answer that file must never
produce by accident. Named here as still unmeasured rather than quietly dropped.

## T-01 follow-up — the locale sweep is clean

Wave 2 fixed one test that asserted en-US number grouping and recommended a
sweep for others. Done: three components use locale-sensitive formatting
(`lib/utils.ts`'s `formatDate`/`formatDateTime`, `MfaManagementPage`'s
`toLocaleDateString`, `AttestationPolicyPage`'s `toLocaleString`), and no test
asserts a literal against any of them — `utils.test.ts` matches on `/2026/` and
on relative lengths. Nothing further to fix.

## B-07 — verified fixed on the running stack

Both halves, against the rebuilt image:

**The trigger is gone.** The server now logs at boot:

```
SurrealDB root token duration is already at least the configured TTL — not
redefining the user (a redefine would invalidate every other replica's token)
  duration_secs: 2419200
```

Re-running the replica probe — the same experiment that produced 60 consecutive
`401`s — with a second server container up for the whole window:

```
T+0   baseline login=200
      second replica started
T+5   login=200      T+31  login=200      T+56  login=200
...   (200 throughout)              T+66  login=200
replica removed; login=200
```

The one non-200 in that run was a `429` at T+61: the probe logs in every five
seconds and `login_per_min` is 10, so the probe outran the rate limiter. It
recovered on the next sample.

**The safety net works too.** The pre-check means AXIAM no longer triggers this
itself, but an operator rotating credentials, or an older replica during an
upgrade, still can — so the reconnect path was tested directly by issuing
`DEFINE USER OVERWRITE` against SurrealDB from outside AXIAM entirely:

```
WARN  DbManager: connection detected Unhealthy — entering bounded
      full-jitter reconnect retry loop
INFO  DbManager reconnect succeeded — handle swapped   attempt=1
```

62 milliseconds apart, and no caller saw a failure — `login` never left `200` at
an 8-second sampling interval. On the previous image the identical provocation
produced `401` for as long as it was watched, with **zero** `Unhealthy` or
reconnect lines in the log.

## H-01 — the matrix was flaky against its own parallelism

**Layer:** harness
**Severity:** low for the product, high for the suite. A permission matrix that
goes intermittently red teaches people to re-run it instead of reading it.

- **Did:** ran the full matrix (56 tests after this wave's additions, up from
  40) rather than a single spec.
- **Happened:** two or three tests failed per run — never the same set — each
  with a bare `Test timeout of 30000ms exceeded` and no assertion. All of them
  passed when their spec file was run alone.
- **Root cause:** `pki.spec.ts` and `service-account-authz.spec.ts` built their
  API client by **signing in again**, inside the test, as a principal whose
  session `matrix-setup` had already captured. `login_per_min` is 10 per IP and
  the whole suite shares one: setup spends eight of those on the sessions it
  captures, so the specs were competing for the remaining two. `Api.login`
  handles a 429 by waiting it out "to the top of the next minute-ish window" —
  correct, and longer than a 30-second test timeout. Whichever tests happened to
  be scheduled once the window filled sat in that backoff and died there.

  Wave 2 saw the same mechanism from the other side and treated the symptom:
  `Api.login` gained the 429 retry precisely because running `matrix-setup` and
  `matrix` back to back put two rounds of sign-ins in one window. The retry made
  the fixture survive; it could not make a test that *waits* finish inside its
  timeout.

- **Fix:** `Api.fromStorageState(path)` builds the request context on a
  principal's already-captured session, so the two specs spend **no** logins at
  all. The CSRF token is read out of the captured `axiam_csrf` cookie, because
  the middleware is double-submit and a client without it would 403 on every
  mutating request.

  This removes the failure rather than retrying around it — there is no window
  to exhaust if nothing signs in.

- **Verified:** three consecutive full runs, **56 passed / 0 failed** each
  (47.5s, 47.6s, 2.4m). The third is slow because `matrix-setup`'s own eight
  sign-ins — which genuinely must happen — waited out the limiter, which is the
  429 retry doing its job. Before the fix, back-to-back runs produced two or
  three timeouts every time.

- **Worth keeping in mind:** the first two green runs after the fix looked like
  proof, and were not. A flake needs to be re-provoked under the conditions that
  produced it — here, consecutive runs — before it can be called fixed.

## Wave 3 — results

| suite | result |
|---|---|
| `scripts/e2e-mtls-native-check.sh` (new — §4 handshake) | **22 passed, 0 failed, 0 unverified** |
| `scripts/e2e-mtls-check.sh` (§4 proxy path) | **17 passed, 0 failed** |
| `scripts/e2e-mail-check.sh` (§3) | **11 passed, 0 failed** |
| `axiam-db` classification + duration parser | 6 + 3 passed, incl. one live-server reproduction |
| `axiam-amqp` mail consumer | 11 passed |
| frontend unit suite | 84 files, 1153 tests, **lines 92.44%** against a 92.4% floor |
| `--project=matrix` (RBAC / PKI matrix) | **56 passed, 0 failed, 0 unverified**, three runs in a row |

A note on the frontend number, because a first attempt at it was misleading:
running `vitest run --coverage` while a Rust image build had the machine gave
**11 failures**, all `userEvent`/`findByRole` timeouts (test time 814s against
243s unloaded). None reproduced on a quiet machine. They were contention, not
defects — but a run in that state should be discarded and repeated, not reported
either way.


## Wave 4 — closing the four open items, and the two defects that surfaced

Wave 3 ended with five items listed as decisions rather than omissions. Four
are now closed; the fifth (wiring the native-mTLS sidecar into CI) is out of
scope for this pass and is restated at the end.

Closing the first one turned up **two live authorization defects** that four
waves of the matrix had not, both for the same reason: the matrix measured
what the system *does* and these were disagreements between two layers that
each, on its own, behaved correctly.

---

### Item 1 — `seeder.rs` no longer grants organization-level actions to a tenant

B-04's scope guard makes an organization-level action unusable by a tenant
principal whatever its role carries. What it left standing was the reason the
guard was needed: every tenant's seeded `super-admin` still *held*
`ca_certificates:manage`, `organizations:create`, `tenants:delete` and the
rest. Two layers, one of them saying no.

`ORGANIZATION_LEVEL_ACTIONS` (`crates/axiam-core/src/permission_scope.rs`) is
now the single list both read. `seed_default_roles` withholds those actions
from an ordinary tenant's super-admin and admin; the organization's own scope
keeps them. `viewer` is unaffected by construction — every entry is a mutation
and viewer is seeded only with `:list`/`:get`, which a test pins rather than a
comment.

**`reconcile_default_role_grants` learned to revoke**, which the wave-3 note
said it would need. Withholding alone fixes new tenants only:
`seed_default_roles` runs once at bootstrap and never again, so every existing
deployment would have kept the old grants forever. The revocation is narrow on
purpose — only the three seeded default roles (a role an operator created is
theirs), only the listed actions, only outside the organization scope. It is
not a "make grants match the seeding rules" pass: an operator who granted
`users:delete` to `viewer` keeps it. The function now returns
`ReconcileOutcome { granted, revoked }`, and `revoked` gets its own WARN line
naming the tenant, because it means a capability is being taken away.

**The rule that decides membership, and why it is not a comment.** An action
can only be withheld if *every* handler requiring it carries the scope guard.
`email_config:write` guards both `/organizations/{id}/email-config` and
`/tenants/{id}/email-config`, so withholding it would take a tenant
administrator's own mail configuration with it; it stays granted and the
organization half rests on the guard alone.
`crates/axiam-api-rest/tests/organization_scope_consistency_test.rs` reads the
handler sources and fails in both directions:

- a guarded action **missing** from the list — a hole that stays silent
  precisely because the guard covers it, so nobody notices the second layer
  stopped covering that action;
- a listed action some **unguarded** handler still needs — which would quietly
  strip a capability from every deployment on the next boot.

Mutation-verified both ways; each failure names the offending call sites.

### B-08 — `POST /api/v1/mds/refresh` was reachable from inside a tenant

**Layer:** backend (authorization). **Severity:** medium-high.
Found while establishing that rule, not by a probe.

The route was guarded by `ca_certificates:generate` alone — which every tenant
super-admin held. `mds_entry` and `mds_blob_meta` are, in the schema's own
words, *"FIDO MDS3 metadata (server-global, NOT tenant-scoped)"*. So a tenant
administrator could refresh or roll back the FIDO attestation trust picture for
**every tenant in the deployment** — the same shape as B-04's mTLS trust
anchor, one layer over.

The module's own docs already contained the argument: MDS ingestion *"is the
same class of privilege as CA certificate management"*. That class is now
organization-level, so this followed it. `GET /status` is left alone; it is a
read, as is everything else this change does not touch.

### B-09 — `/auth/me` told a tenant super-admin it could do everything

**Layer:** backend (authorization hint) / frontend (what it renders).
**Severity:** medium — no privilege is gained, but the UI offers controls the
server refuses, which is §2's first defect class.

Found by a mutation that **should have failed and did not**. A probe pointed a
matrix control at a misspelt permission and every principal still passed. The
reason was not the gate: `holds()` honours `*`, and three principals had it —
including tenant-level ones. The mutation was measuring the wildcard.

`GET /auth/me` prefixes `"*"` to the permissions array for any principal
holding a role *named* `super-admin`, and `usePermissions().can()` reads that as
yes to everything. True for the organization's own super-admin. Not true for an
ordinary tenant's, and not since B-04. So the admin UI was rendering "New
Organization", the CA-management actions and the tenant lifecycle controls to a
principal the server answers 403 to.

The comment directly above the wildcard already stated the rule it was
breaking: *"a hint that disagrees with the enforcement is worse than none"*.
The wildcard is now emitted only for a principal whose own record lives in the
organization scope — the same predicate the scope guard uses. For everyone else
the explicit action list is the honest answer *and* a complete one, since a
tenant super-admin still holds every permission that applies to its tenant. An
unresolvable tenant drops the wildcard: a control hidden from someone who could
have used it is the cheaper mistake.

Both directions are pinned and they check each other — without the fix the
withhold test fails; had it over-applied, the keep test would.

### Item 2 — the selection-gated in-page controls are measured

`ScopesPanel`'s "New Scope" (`scopes:create`), `EffectiveAccessPanel`'s act-as
subject picker (`authz:check_as`) and the per-row bind-certificate action on
service accounts (`certificates:bind`) are now in
`frontend/e2e/matrix/in-page-controls.spec.ts`.

The wave-3 reason for leaving them out was sound and is what shaped the fix:
"the control is absent" is also what you see when there was no row to select,
when the selection did not take, and when the panel half-rendered. So every
selection-gated entry carries a **landmark** — an element the panel renders
regardless of the permission (`Scopes — <name>`, `Previewing access to`, the
ungated `Rotate secret for …` beside the bind action). Nothing is selected
without first asserting there was something to select; no gate is asserted
before the landmark proves the panel is on screen. Each failure is its own
sentence, so "a control the server would allow, hidden" can never be printed
about a page that never rendered. `EffectiveAccessPanel` substitutes an
explanation when the permission is absent, so that is asserted too — "replaced
by a refusal" rules out a half-rendered panel in a way "absent" cannot.

Two gaps surfaced by that design, both reported as themselves rather than as
hidden controls:

- **the fixture had no service account in tenant B**, so `mx-b-admin` — the
  only principal that could exercise `certificates:bind` there — had no row.
  Fixed in `matrix-fixture.ts`.
- **an organization-level principal has no rows in its own scope**, correctly.
  `admin` saw nothing on either page, which would have left the whole
  "allowed" side unmeasured for the principal holding every permission. It is
  now put into tenant A first by seeding the selection `lib/activeTenant.ts`
  itself persists — the state a reload restores since F-03. Driving the
  switcher through the UI is `tenancy.spec.ts`'s assertion; this file only
  needs to arrive.

Mutation-verified in both directions: a locator that cannot find a rendered
control fails with "a control the server would allow, hidden"; a landmark that
cannot be found fails with "the selection did not take, so its absence proves
nothing".

### Item 3 — the mail publishers are read, not quoted

`every_mail_type_renders_with_no_placeholder_left_standing` builds its context
from a table of what each publisher supplies, and that table was a quote from
the five call sites. A publisher that stopped sending `action_url` would have
left the render test green while every real message rendered `{{action_url}}`
to a user — the test asserted a property of a context nobody had checked was
the context.

`every_publisher_still_sends_the_keys_it_is_credited_with` reads the call
sites. The publishers live in `axiam-api-rest`, `axiam-audit` and
`axiam-server`, all above `axiam-amqp` in the layering, so the crate cannot
call them — it reads their source, the same technique the org-scope
consistency test uses on the handlers.

Both context shapes are covered, because the two that matter are written
differently: four build a `serde_json::json!` literal inline, while
`axiam-audit`'s dispatcher assembles a map first (the event name is only known
per rule). Mutation-verified on one of each.

Two guards on the crude parts. `production_source` strips `#[cfg(test)]`
first — necessary, not tidy: `password_reset.rs` builds a message in its own
tests with a deliberately partial context, and a scan that read it would report
the production publisher as having dropped a key.
`each_mail_type_has_exactly_one_production_publisher` pins the assumption the
reader rests on.

Subset rather than equality, deliberately: a publisher may supply more than it
is credited with (`axiam-audit` adds `username` only for an unauthenticated
actor). The other direction was already closed — a key the template uses and
the table omits leaves a `{{…}}` standing.

### Item 4 — the e2e specs typecheck, and now they have to

The nine `Property 'email' does not exist on type 'never'` errors in
`auth-contract.spec.ts` are fixed, and the cause is worth naming because the
obvious fix reproduces it. TypeScript does not track assignments made inside a
callback, so `let body: T | null = null` is still narrowed to `null` at the
assertion; `expect(body).not.toBeNull()` does not widen it back (it is not a
type predicate); and handing the narrowed variable to a generic helper infers
`T = never` all over again. `Capture<T>` holds the value in an object, so the
type comes from the `captured<T>()` call rather than from flow analysis of a
variable.

The bodies are typed against the backend structs they pin, restated locally
rather than imported from `src/services/auth.ts`: a contract test that reuses
the application's own idea of the payload agrees with the application even when
the application is wrong.

**The real defect was that nothing typechecked that directory.** CI's
`npx tsc -b` builds only `tsconfig.app.json` and `tsconfig.node.json`, and
Playwright transpiles without typechecking — which is how nine errors
accumulated unseen. `npm run typecheck:e2e` now runs in the same CI step, so
there is no tenth.

---

## Still open after wave 4

Nothing here is a wave-4 failure. These are the things this exercise has
deliberately not done, listed so they are decisions rather than omissions.

1. **Publisher-side mail context is read, but the *identity* half still is
   not.** `every_publisher_still_sends_the_keys_it_is_credited_with` reads the
   five publishers. The four identity keys the consumer inserts come from
   `identity_context`, which the render test exercises directly against a
   database where nothing resolves — so that half is measured by execution
   rather than by reading, which is stronger. Nothing outstanding; recorded so
   the asymmetry is not mistaken for a gap.

2. **`nav-reach.spec.ts` has one oxlint error** (an unused `page` parameter).
   Pre-existing and untouched here. `npm run lint` also reports several
   hundred errors from `frontend/ds-bundle/`, an untracked local
   design-system artifact directory that CI never sees — worth either
   gitignoring or excluding from the lint glob, because it currently makes
   the local lint output useless for spotting a real one.

3. **The wildcard's blind spot is closed for tenant principals but remains for
   the organization's.** B-09 stops `*` reaching a tenant super-admin, so the
   matrix can now measure permission strings for those principals. The
   organization super-admin still holds `*` legitimately, so a misspelt
   permission is still invisible from inside the UI for it — which is why the
   typo guard lives in `frontend/src/lib/permissionStrings.test.ts`, comparing
   the UI's strings against `crates/axiam-api-rest/src/permissions.rs` with no
   server involved.

4. **B-08 and B-09 tighten boundaries and are behaviour changes, not only bug
   fixes.** A tenant administrator that currently refreshes the FIDO MDS blob
   will start getting 403, and a tenant super-admin's UI will stop showing
   organization-level controls it was showing (and being refused on). Both
   belong in release notes alongside B-04 and B-06.

5. **The native-mTLS sidecar is a script, not CI.** It needs Docker and a
   running stack, so it is a local verification tool. Wiring it into CI would
   mean giving the workflow a stack to point at.
