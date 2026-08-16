# SCIM 2.0 provisioning

AXIAM exposes a SCIM 2.0 (RFC 7643/7644) endpoint under `/scim/v2` so an
identity provider — Okta, Microsoft Entra ID, or any other SCIM-compliant
IdP — can create, update, and deactivate AXIAM users and groups directly,
instead of an admin doing it by hand in the AXIAM UI.

This page covers the endpoints, the supported subset (filtering and PATCH),
how authentication and tenant scoping work, and walkthroughs for wiring up
Okta and Entra. The crate implementing all of this is `axiam-scim`.

## What's implemented

| Area | Support |
|---|---|
| `Users` | Full CRUD + PATCH |
| `Groups` | Full CRUD + PATCH (including membership) |
| Filtering | `userName eq "..."` (Users), `externalId eq "..."` (Users + Groups), paging (`startIndex`, `count`) |
| PATCH ops | `add`/`replace`/`remove` on the standard attribute paths Okta/Entra send — see [PATCH support](#patch-support) below |
| Discovery | `GET /Schemas`, `GET /ServiceProviderConfig`, `GET /ResourceTypes` |
| Bulk operations | **Not supported** — `POST /Bulk` returns `501` with a SCIM error body |
| Complex filters | **Not supported** — anything but `<attr> eq "<value>"` returns `400 invalidFilter` |
| ETag / conditional requests | **Not implemented** (`ServiceProviderConfig` advertises `etag.supported: false`) — see the note in `crates/axiam-scim/src/users.rs` module docs |

This mirrors `improvement-after-run5-benchmark.md` §B4's scope exactly —
enterprise IdP-driven provisioning is "mostly CRUD," and the parts that
aren't (bulk, complex filters) are the two the spec explicitly carved out.

## Endpoints

```
GET    /scim/v2/ServiceProviderConfig
GET    /scim/v2/ResourceTypes
GET    /scim/v2/ResourceTypes/{name}
GET    /scim/v2/Schemas
GET    /scim/v2/Schemas/{id}

GET    /scim/v2/Users?filter=...&startIndex=1&count=50
POST   /scim/v2/Users
GET    /scim/v2/Users/{id}
PUT    /scim/v2/Users/{id}
PATCH  /scim/v2/Users/{id}
DELETE /scim/v2/Users/{id}

GET    /scim/v2/Groups?filter=...&startIndex=1&count=50
POST   /scim/v2/Groups
GET    /scim/v2/Groups/{id}
PUT    /scim/v2/Groups/{id}
PATCH  /scim/v2/Groups/{id}
DELETE /scim/v2/Groups/{id}

POST   /scim/v2/Bulk   -> 501, {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"], ...}
```

## Field mapping

AXIAM's `User`/`Group` models predate SCIM and don't carry every SCIM
attribute as its own column. Rather than adding parallel storage, the SCIM
crate maps onto the **existing** `UserRepository`/`GroupRepository` and
stores the handful of SCIM-only fields (`externalId`, `name.givenName`,
`name.familyName`, `name.formatted`) inside the generic `metadata` JSON
column both models already have, under a `"scim"` sub-key that never
collides with metadata some other feature writes.

| SCIM attribute | AXIAM field |
|---|---|
| `User.userName` | `User.username` |
| `User.emails` (primary) | `User.email` |
| `User.active` | `User.status == Active` (any other status — `Inactive`, `Locked`, `PendingVerification`, `Anonymized` — reads back as `active: false`) |
| `User.externalId`, `User.name.*` | `User.metadata.scim.{externalId,givenName,familyName,formatted}` |
| `User.password` (write-only, optional) | Hashed with the same Argon2id path (`axiam_auth::password::hash_password`) `create_with_consent` uses. If a SCIM create omits it, AXIAM generates a random one — SCIM-provisioned accounts are expected to authenticate via SSO/federation, not this password. |
| `Group.displayName` | `Group.name` |
| `Group.externalId` | `Group.metadata.scim.externalId` |
| `Group.members` | The existing `member_of` graph edge (`add_member`/`remove_member`/`get_members`) |

A `POST /scim/v2/Users` also writes the same GDPR Art. 7 proof-of-consent
row a native `POST /api/v1/users` does (`create_with_consent`) — a
SCIM-provisioned user is never missing that record either.

## PATCH support

`PATCH` is restricted to `add`/`replace`/`remove` on this fixed set of
paths — the op subset Okta and Entra actually send, not a general
RFC 7644 §3.5.2 implementation:

**Users:** `active`, `userName`, `externalId`, `name.givenName`,
`name.familyName`, `name.formatted`, `emails`, `password`. `userName`,
`emails`, and `password` cannot be `remove`d (they back required AXIAM
columns); `active`'s `remove` reverts to its RFC-default `true`. Entra's
path-less multi-attribute shape
(`{"op":"replace","value":{"active":false}}`) is also accepted.

**Groups:** `displayName`, `externalId`, `members`. `displayName` cannot be
`remove`d. `members` supports `add`/`replace`/`remove` with a
`[{"value":"<user-id>"}, ...]` value, a value-less `remove` (clears every
member), **and** the Okta/Entra single-member-removal shape
`members[value eq "<user-id>"]`, `remove`, no value — the one filtered
PATCH path this implementation special-cases, because both vendors rely on
it for deprovisioning a user out of a group.

Anything outside these paths — a complex `emails[type eq "work"].value`
path, an unrecognized op — returns `400` with `scimType: invalidPath` or
`invalidValue`.

## Authentication and tenant scoping

`/scim/v2/*` uses the same bearer-token authentication as every other
AXIAM REST endpoint: `Authorization: Bearer <access token>`, validated by
the identical `AuthenticatedUser` extractor `/api/v1/users` uses. There is
**no separate SCIM token type** — a SCIM caller is just an AXIAM principal
whose token carries the dedicated `scim:provision` permission (declared in
`axiam_api_rest::permissions::PERMISSION_REGISTRY`, seeded per-tenant
exactly like `users:create`).

**Tenant scoping is enforced by construction, not by an extra check**: the
tenant id on every repository call this crate makes comes *only* from the
bearer token's own `tenant_id` claim, never from anything in the SCIM
request path or body. A token minted for tenant A cannot even *name* tenant
B's users or groups in a query — every generated SurrealDB statement
filters on the token's tenant id. See `crates/axiam-scim/src/auth.rs`'s
module docs for the full statement of this property, and
`crates/axiam-scim/tests/contract_test.rs`'s tenant-isolation tests for the
adversarial cases it's checked against (cross-tenant GET/PUT/PATCH/DELETE
and list-by-token, not merely "no token at all").

### What `scim:provision` confers — read this before granting it

> **A holder of `scim:provision` can set any user's password in this tenant,
> including a tenant administrator's, and then log in as them.**

RFC 7643 §4.1.1 defines `password` as a writable `User` attribute, and
`PATCH /scim/v2/Users/{id}` honours it. The native admin API has **no**
equivalent: `PUT /api/v1/users/{id}` never writes a password hash, and the
only native password writes are self-service change and reset. So this one
permission is strictly more powerful than `users:create` + `users:update`
combined, and step 2 of the setup below — "grant it to your provisioning
identity" — is therefore granting tenant-wide account takeover to whatever
external system holds that bearer token.

That is the correct reading of the RFC; what matters is that you know it
before you grant it. Two practical consequences:

- Treat the SCIM bearer token as an **administrator credential**, not as an
  integration credential. Rotate it on the same schedule and store it in the
  same place you store an admin password.
- Most Okta/Entra deployments federate and never push a password. If yours is
  one of them, nothing is lost by the IdP never exercising this capability —
  but AXIAM does not yet let you take it away, because `password` writes are
  not behind a second permission. If that matters to your threat model, say
  so on the issue tracker; splitting it is a small change.

**Deprovisioning is immediate.** A SCIM `password` write, an `active: false`
(via `PUT` or `PATCH`), and `DELETE /scim/v2/Users/{id}` each revoke every
live session **and** every OAuth2 refresh token the target holds, in addition
to flushing the authorization decision cache. Before this was fixed
(SEC-098), only the decision cache was flushed, so an account deactivated by
an IdP's offboarding job kept a spendable refresh token.

### Rate limiting

The whole `/scim/v2` scope sits behind **one** rate-limit bucket,
`AXIAM__RATE_LIMIT__SCIM_PER_MIN` (shipped default **600/min per IP**) —
Users, Groups and the discovery endpoints, reads and writes alike. Past the
limit, requests get the standard AXIAM `429` with `Retry-After: 60`; a
well-behaved SCIM client retries.

600/min is the REST twin of `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (10/s), the
other fully-privileged machine-driven administrative surface: creating a
SCIM user generates and Argon2id-hashes an initial password, and a
`password` PATCH re-hashes one, so this ceiling is a CPU guard rather than a
throughput number. No `AXIAM__RATE_LIMIT__PROFILE` preset moves it
(SEC-079: a service-mesh capacity decision must not silently widen an
administrative surface).

For scale: at a typical IdP page size of 200, a full import of a
100 000-user directory is roughly 500 `GET /scim/v2/Users` calls, well
inside one minute's budget. Pin the env var if a very large tenant's
reconciliation sweep needs more. See
[`../deployment/rate-limit-sizing.md`](../deployment/rate-limit-sizing.md).

### Provisioning tokens — the credential to actually use

`/scim/v2/*` accepts a **provisioning token**: a long-lived, revocable bearer
handle designed for exactly this workflow — paste once into an IdP, forget.
Manage them under **SCIM Provisioning** in the admin UI, or through
`/api/v1/scim-tokens` (`scim_tokens:create` / `:list` / `:revoke`).

A provisioning token:

- is accepted on `/scim/v2/*` and **nowhere else** — not `/api/v1/*`, not
  `/oauth2/*`. That containment is why a year-long credential is defensible in
  a system whose other access tokens live 15 minutes;
- **carries no permissions of its own.** It authenticates *as* a tenant user,
  and that user's `scim:provision` grant decides everything. Unassign the role
  or deactivate the user and every token bound to them stops working — you do
  not have to revoke them separately;
- is stored only as a SHA-256 hash. The value is shown once, at creation;
- carries the fixed prefix `axiam_scim_`, so a secret scanner or a `grep` can
  find it if it is ever pasted somewhere it should not be;
- expires. There is no never-expires option — the ceiling is
  `AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS` (default 365).

This replaces the refresh-job workaround described below for new deployments.
The access-token route still works and is documented because an existing
integration may be using it.

See `claude_dev/scim-provisioning-token-design.md` for the design reasoning.

### A known limitation: the bearer principal is a user, not a service account

AXIAM has a `service_account` concept explicitly for machine-to-machine
auth, and it would be the natural fit for a SCIM bearer principal. It
doesn't work yet: AXIAM's RBAC role-assignment edge
(`RoleRepository::assign_to_user` / `get_user_role_assignments`) is
hard-scoped to the `user` table today, so a `service_account` subject
cannot hold **any** RBAC permission, `scim:provision` included. That gap
predates this crate and touches `axiam-db`/`axiam-authz`, both outside this
task's scope — it's flagged here so a follow-on (the planned SCIM
token-management UI, or a dedicated RBAC fix) has a precise pointer.

Until then, the bearer principal is a **dedicated tenant user** — see the
setup steps below. Its access token is a normal 15-minute AXIAM access
token (Security Standards: short-lived access tokens), which is short for a
"paste once into an IdP" workflow; the setup steps note the operational
trade-off and a mitigation.

### Setup (either IdP)

1. Create a dedicated, non-interactive tenant user for provisioning, e.g.
   `POST /api/v1/users` with `username: "scim-provisioner"`.
2. Create a role that holds **only** `scim:provision` — least privilege,
   not the `admin` role (which also gets `scim:provision`, since the
   default-role seeder grants admin every permission except
   `admin:bootstrap`, but carries everything else too):
   `POST /api/v1/roles`, then `POST /api/v1/roles/{role_id}/permissions`
   with `scim:provision`.
3. Assign the role to the user: `POST /api/v1/roles/{role_id}/users`.
4. Obtain a bearer token: `POST /api/v1/auth/login` with that user's
   credentials, returning a 15-minute access token and a refresh token.
   Configure your IdP's SCIM app with that access token as the bearer
   credential (Okta: "HTTP Header" auth mode; Entra: the static/long-lived
   token field).
5. **Rotation**: because the token is short-lived, run a small scheduled
   job (cron / Kubernetes `CronJob`) that calls `POST /api/v1/auth/refresh`
   and pushes the new access token into the IdP via its own management API
   before the old one expires. This is a real operational cost worth
   stating plainly rather than glossing over — see the limitation above for
   why a long-lived machine credential isn't available yet.

## Okta walkthrough

1. In the Okta Admin Console, create (or edit) an app integration with
   **SCIM provisioning**.
2. **SCIM connector base URL**: `https://<your-axiam-host>/scim/v2`
3. **Unique identifier field for users**: `userName`
4. **Supported provisioning actions**: check "Push New Users", "Push
   Profile Updates", "Push Groups" (all standard CRUD + PATCH, all
   supported).
5. **Authentication mode**: HTTP Header. Paste the bearer token from setup
   step 4 above.
6. Okta's own test ("Test API Credentials") drives exactly the request
   shapes this crate's Okta contract fixtures
   (`crates/axiam-scim/tests/fixtures/okta/`) are built from: a `userName
   eq "..."` filtered `GET /Users`, a `POST /Users` create, and — on
   deactivation — a `PATCH /Users/{id}` with `{"op":"replace","path":
   "active","value":false}`.
7. Group push sends `POST /Groups` with a `displayName` and (if members
   are already assigned) a `members` array, and later
   `PATCH /Groups/{id}` with `members[value eq "<uuid>"]`, `remove` when a
   single user leaves the Okta group.

## Entra ID (Azure AD) walkthrough

1. In the Entra admin center, go to **Enterprise applications** → your app
   → **Provisioning** → set mode to **Automatic**.
2. **Tenant URL**: `https://<your-axiam-host>/scim/v2`
3. **Secret Token**: the bearer token from setup step 4 above.
4. Click **Test Connection** — Entra probes `GET /Users?startIndex=1&count=1`
   as a validity check.
5. Under **Mappings**, the default Entra → SCIM attribute mappings for
   `userPrincipalName` → `userName`, `mail`/`otherMails` → `emails`,
   `givenName`/`surname` → `name.givenName`/`name.familyName`, and
   `accountEnabled` → `active` all match this crate's supported subset.
   Group mappings default `displayName` → `displayName` and `members` → the
   membership diff.
6. Entra deactivates a user with the path-less shape
   `{"op":"replace","value":{"active":false}}` (no `path`) rather than
   Okta's `path:"active"` form — both are handled (see
   [PATCH support](#patch-support) above), and the Entra contract fixtures
   in `crates/axiam-scim/tests/fixtures/entra/` are built from exactly this
   shape.

## Fixtures are hand-constructed, not captured

Neither Okta nor Entra traffic was actually recorded to build the contract
tests — this sandbox has no network access to either vendor. The fixtures
under `crates/axiam-scim/tests/fixtures/{okta,entra}/` are hand-constructed
from each vendor's own published SCIM implementation notes (Okta's SCIM
protocol reference, Microsoft's Entra provisioning reference) and RFC
7644's own examples. This is stated in each fixture file's header comment
and in the test file that consumes them — treat these as "the request
shapes these vendors are documented to send," not as a captured-traffic
compatibility guarantee.

## See also

- [`../README.md`](../README.md) — top-level documentation index
- [`../../claude_dev/remediation-plan-2026-08-15.md`](../../claude_dev/remediation-plan-2026-08-15.md) — task R3.1
- [`../../claude_dev/improvement-after-run5-benchmark.md`](../../claude_dev/improvement-after-run5-benchmark.md) §B4 — the verbatim scope this page implements
