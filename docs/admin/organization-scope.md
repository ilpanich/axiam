# Organization-level users, roles and service accounts

AXIAM has two levels of principal.

- A **tenant** principal belongs to one tenant. Its grants apply there and
  nowhere else. This is every user, group, role and service account AXIAM had
  before 1.0.0.
- An **organization** principal lives in the organization's own reserved
  tenant. Its *global* grants apply to every tenant in that organization —
  including tenants created long after the grant.

The super-admin created at bootstrap is an organization principal. That is what
makes it an administrator of every tenant the organization ever has.

---

## Why this exists

Creating a tenant used to leave it unreachable by everybody, the bootstrap
super-admin included.

Tenant creation seeded the new tenant's permissions and stopped there — no
roles, no grants, no assignments. Meanwhile the authorization engine filters
every lookup by tenant, and the super-admin's `super-admin` role was a row in
the *bootstrap* tenant. Ask about the new tenant and the query returned
nothing, so the answer was `no roles assigned` for everyone.

Two things fix it, and both are needed. Tenant creation now seeds the default
role set, so the tenant can be administered at all. And organization principals
reach it without anyone granting them anything.

## The organization tenant

Every organization has exactly one, created with the organization, flagged
`kind: "organization"` and slugged `organization`. It is an ordinary tenant row
in every other respect, which is deliberate: organization-level users, groups,
roles, permissions and service accounts are ordinary rows in it, evaluated by
the same RBAC engine, audited the same way.

You cannot create a second one — `organization_scope:<org_id>` is a marker row
whose record id *is* the constraint — and `POST .../tenants` refuses the
reserved slug.

### Uniqueness falls out of this

> Organization-level users are unique at organization level and across all
> tenants; tenant-level users must be unique per tenant.

That is exactly what the existing indexes already say, once organization users
live in the organization tenant:

```sql
DEFINE INDEX idx_user_tenant_username ON TABLE user COLUMNS tenant_id, username UNIQUE;
DEFINE INDEX idx_user_tenant_email    ON TABLE user COLUMNS tenant_id, email    UNIQUE;
```

`user1` can register in `tenant1` and `tenant2` as two separate accounts, and
cannot register twice in `tenant1` without deleting the first. An
organization-level `user1` is unique across the whole organization.

## The one rule

When a subject's grants are read across a tenant boundary, **only global grants
carry**.

| Assignment | Lives in | Applies to |
| --- | --- | --- |
| Global (`is_global`, no resource) | organization tenant | every resource in every tenant of the organization |
| Resource-scoped | organization tenant | that resource, in the organization tenant only |
| Global | an ordinary tenant | every resource in that tenant |
| Resource-scoped | an ordinary tenant | that resource and its descendants |

A resource-scoped assignment names a resource id in the organization tenant. No
resource with that id exists in `tenant-a`, and one that happened to share a
*name* would be an unrelated thing — carrying the assignment across would turn
a narrow grant into a grant on something else entirely, across an isolation
boundary.

Everything else is unchanged: deny-override still wins at any depth, scopes
still narrow, group membership still inherits.

An organization principal acting on the organization tenant itself is not
crossing anything and gets ordinary resource-scoped evaluation there.

Living in the organization tenant grants nothing by itself. An organization
user with no roles is denied exactly like anyone else.

## Signing in

The tenant is optional at login. Omitting it signs you in at organization
level:

```http
POST /api/v1/auth/login
{ "org_slug": "acme", "username_or_email": "root", "password": "…" }
```

A tenant user who omits the tenant is not found in the organization tenant and
gets the same enumeration-safe 401 as a wrong password — so a tenant user must
name their tenant, and learns nothing by failing to.

OPAQUE, passkeys and MFA work exactly as they do for tenant users; nothing on
those paths knows or cares which kind of tenant it is authenticating against.

The login response carries `organization_level: true` for an organization
principal.

## Acting on a tenant

An organization principal switches tenant with a header, and **without signing
in again** — it is already a principal of every tenant in its organization:

```http
GET /api/v1/users
X-Axiam-Tenant: 0193f2a1-…      # any tenant in your organization
```

The header is honoured only for a principal whose own tenant is the
organization scope, and only for a tenant in that principal's own organization.
Anything else is a 403 rather than a silent fallback — including a request with
no tenant resolver configured, which fails closed.

Without the header, an organization principal acts on the organization tenant.

In the admin UI this is the top-right selector. It lists **Organization** plus
the organization's tenants, and switching takes effect immediately. A
tenant-level principal sees the same selector but switching signs it out and
back in, because for it the premise is false: a principal of one tenant is not
a principal of another, and no server-side operation could make it one.

## Creating tenants

```http
POST /api/v1/organizations/{org_id}/tenants
{ "name": "Production", "slug": "production" }
```

Seeds the tenant's permissions **and** its default roles (`super-admin`,
`admin`, `viewer`), so it is administrable immediately.

It assigns those roles to nobody, deliberately. Organization principals already
reach the tenant by the rule above, so writing assignments at creation time
would grant nothing new, would miss every organization principal created
*afterwards*, and would have to be undone in every tenant to revoke. Deriving
access at check time has none of those properties: a tenant created ten months
later is reachable by the same rule with no write of any kind.

Grant a *tenant* user access by assigning it one of those roles in the usual
way. Provisioning a new tenant's first administrator is the same three calls,
all made from the organization session that just created the tenant — which is
the thing organization scope makes possible, and the thing whose absence left a
new tenant unreachable by everybody:

```http
POST /api/v1/users                 X-Axiam-Tenant: <new tenant>
PUT  /api/v1/users/{id}            X-Axiam-Tenant: <new tenant>   # {"status":"Active"}
POST /api/v1/roles/{role}/users    X-Axiam-Tenant: <new tenant>   # role = super-admin
```

`scripts/e2e-bootstrap.sh` does exactly this, and
[`examples/b6-organization-scope`](../../examples/b6-organization-scope/README.md)
walks the whole flow with assertions.

The `X-Axiam-Tenant` header is only as good as the resolver behind it. The
server registers one at startup (`axiam-server`'s composition root, alongside
the session validator); without it the extractor refuses every switch, so an
organization administrator would be unable to act on any tenant at all.

## What an organization principal's own account does

`X-Axiam-Tenant` says which tenant a request **acts on**. It says nothing about
where the caller *lives*, and for the caller's own account that second tenant is
the one that matters:

| Operation | Tenant used |
|---|---|
| `POST /auth/password/change` | the principal's own — its password, and its OPAQUE record, live there |
| `GET /auth/me` (the account, and the permission array) | the principal's own — grants live in the organization tenant |
| Everything else | the tenant named by the header |

Reading the acting tenant for the first two is a bug with a distinctive
symptom: an organization administrator selects a child tenant and is
immediately unable to change its own password (404) or stay signed in (401),
with nothing on screen having changed but the tenant switcher.

`GET /auth/me` therefore returns both, and a client that switches tenants should
use them accordingly:

```jsonc
{
  "user": {
    "tenant_id": "…",             // the tenant being acted on
    "principal_tenant_id": "…",   // the tenant this principal lives in
    "principal_tenant_slug": "organization",
    "org_id": "…",                // the caller's organization, addressable directly
    "organization_level": true
  },
  "permissions": ["*"]
}
```

`permissions` is the caller's effective actions in the scope it is acting on.
Across a tenant boundary it carries only **global** grants, mirroring what the
authorization engine does — a resource-scoped grant names a resource in the
organization tenant, and a resource with that id does not exist in the target.
It is a UI hint; the server enforces every action independently.

`org_id` is there so a client never has to reach `GET /api/v1/organizations` to
turn a slug into an id. That endpoint is restricted to `super-admin` and returns
only the caller's own organization.

## What tenants inherit from the organization

Three things flow downwards, and each keeps flowing after the fact — a change to
the organization reaches the tenants that **already exist**, not only the ones
created afterwards.

### Security settings

Tenant settings are stored as a sparse override mask, so any field a tenant has
not overridden tracks the organization's value for it, permanently.

A tenant may only ever **tighten**. That rule is enforced when an override is
written *and* when the baseline moves: an override the organization has since
overtaken is dropped, so the tenant returns to tracking the baseline. An
override that is still stricter is left exactly as it is.

```
org  min_length 8  → 16
tenant override 12          ⇒ cleared; the tenant is now 16 and tracks further changes
tenant override 24          ⇒ kept;    the tenant chose to go further
```

The same applies to `opaque_mode`: switching the organization from `disabled` to
`optional` or `required` reaches every tenant beneath it, including tenants that
had explicitly recorded `disabled`. Each tenant's OPAQUE key material is
provisioned at the moment of the change rather than lazily on first use, so
"did enabling it do anything?" is answerable immediately.

The overtaken field is **cleared**, not rewritten to the new value. An absent
override keeps tracking; a value written in would freeze at today's level and
need the same repair after the next change.

### The OPAQUE `required` gate

`required` refuses password login for a whole tenant before any credential is
examined, and **nobody can be enrolled retroactively** — a registration record
is built by a client holding the plaintext password, which the server never has.

So switching to `required` is refused while any active user in scope has no
record, and the error names the tenants and the counts:

```
opaque_mode `required` would lock out active users who have no OPAQUE
registration record… Uncovered users by tenant: production (14), staging (2).
```

The way through is the migration `OpaqueMode::Required`'s own documentation
describes: run `optional` until coverage is complete — user creation,
change-password and reset completion each enrol one — then switch.

### Certificate authorities

A CA is an organization-scoped asset (`ca_certificate.organization_id`), and
every tenant in the organization issues under it. A tenant adds its own layer
with a **tenant signing CA** — an intermediate created beneath an organization
CA, constrained to a path length of zero, which is what
`POST /api/v1/certificates` names as `issuer_ca_id` for that tenant. Revoking it
revokes exactly one tenant's issuance.

The admin UI reaches the organization's CAs by `org_id` from `/auth/me`. It used
to resolve that id by listing organizations, which only a `super-admin` may do —
so for any tenant administrator below that role the list came back empty and the
certificates page reported that the organization had no CA at all.

## Upgrading an existing deployment

Migration 50 adds `kind`, defaulting to `standard`. Every tenant you have is an
ordinary tenant and reads back as one; every grant keeps meaning what it meant.

The migration creates each organization's reserved tenant and **moves nobody
into it**. Your users stay where they are with the access they have, and
nothing about who can reach what changes on upgrade.

Promoting an existing administrator to organization level is a deliberate act:
create an account in the organization tenant and assign it `super-admin` there.
Relocating accounts between tenants is not something a version upgrade should
decide on your behalf, and the deployment that most needs the promotion is
exactly the one where a human should look at it first.

## See also

- [`claude_dev/organization-scope-design.md`](../../claude_dev/organization-scope-design.md)
  — why the organization scope is a tenant rather than an `Option<Uuid>`, and
  why access is derived rather than fanned out.
