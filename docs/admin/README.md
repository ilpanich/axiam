# AXIAM Admin Guide

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

Task-oriented walkthroughs for the first-run admin bootstrap and the common
day-to-day admin operations: creating organizations/tenants, users, roles,
and permissions, and assigning roles. See also:
[Deployment Guide](../deployment/README.md) (env/secrets),
[PKI Guide](../pki/README.md) (certificates), [API docs](../api/README.md).

All endpoints below require a bearer JWT (`Authorization: Bearer <token>`,
obtained via `POST /api/v1/auth/login`) except the bootstrap endpoint itself.
AXIAM's RBAC engine is **additive-only** (allow-wins, default-deny) — there is
no explicit deny-override in v1.0-beta; a caller needs an explicit permission
grant (directly or via role/group) to perform any action.

## First-run admin bootstrap

On a fresh tenant with zero admins, `POST /api/v1/admin/bootstrap` creates the
first super-admin user and seeds the default permission set and roles. The
endpoint is fail-closed (SECHRD-04): it is refused unless **one** of two
mandatory gates is satisfied — no admin can ever be created "unconditionally".

**Gate 1 — `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var.** If this environment
variable is set on the `axiam-server` process, the bootstrap request's
`email` field must match it exactly, or the request is rejected with `403`.
This is a deploy-time env var — it is **not** part of the
[deployment guide's required-secrets table](../deployment/README.md#required-secrets--environment)
(`k8s/server/secret.yml`), since it is optional and low-sensitivity; add it
to your `axiam-server` container's environment (e.g. a ConfigMap or a
deployment-manifest override) if you want to lock first-run bootstrap to a
known email address ahead of time.

**Gate 2 — one-time setup token (fallback).** If `AXIAM_BOOTSTRAP_ADMIN_EMAIL`
is not set, `axiam-server` mints a single-use setup token on first boot
(only when no admin has ever been bootstrapped) and logs it once at `info`
level:

```
AXIAM first-run bootstrap setup token minted. Use this token ONCE to
complete first-admin bootstrap (POST /api/v1/admin/bootstrap, `setup_token`
field) ...
```

Capture that token from the server logs and pass it in the bootstrap
request's `setup_token` field. It is consumed atomically on first successful
use — a replay of the same token is rejected.

If **neither** gate is satisfied (env var unset AND no/invalid/already-used
setup token), bootstrap is refused with `403` — an unset gate never allows
an arbitrary caller to create the first admin.

**Request:**

```
POST /api/v1/admin/bootstrap
{
  "org_id": "<uuid>",
  "tenant_id": "<uuid>",
  "email": "admin@example.com",
  "username": "admin",
  "password": "<strong password>",
  "setup_token": "<only if AXIAM_BOOTSTRAP_ADMIN_EMAIL is unset>"
}
```

The organization and tenant referenced by `org_id`/`tenant_id` must already
exist (see **Creating an organization and tenant** below — bootstrapping a
brand-new deployment therefore means creating the org/tenant first via a
super-admin-privileged path appropriate to your environment, then bootstrapping
the tenant's first admin against them).

On success (`201`), no token is issued — log in via `POST
/api/v1/auth/login` with the new admin's credentials to obtain a session.
Bootstrapping the same tenant again always returns `409 Conflict` (at most
one super-admin can ever be created per tenant via this endpoint, even under
concurrent first-run requests).

## Creating an organization and tenant

Organizations are top-level entities; tenants nest under an organization and
provide full data isolation (users, roles, permissions, resources are all
tenant-scoped).

To create an organization (restricted to an existing super-admin — this is
the one action not scoped by the caller's own tenant):

```
POST /api/v1/organizations
{ "name": "Acme Corp", "slug": "acme", "metadata": {} }
```

To create a tenant under that organization:

```
POST /api/v1/organizations/{org_id}/tenants
{ "name": "Production", "slug": "prod", "metadata": {} }
```

Creating a tenant automatically seeds its default permission registry so RBAC
works immediately — you do not need to manually create the baseline
permission set before assigning roles in a new tenant.

## Creating users

To create a user in your tenant (requires the `users:create` permission):

```
POST /api/v1/users
{ "username": "jdoe", "email": "jdoe@example.com", "password": "<strong password>", "metadata": {} }
```

Passwords must satisfy a minimum complexity policy (at least 8 characters)
enforced at creation time; the tenant's full password policy (HIBP breach
check, history) is enforced separately at login. Creating a user also
atomically records a `terms_of_service` consent row (GDPR Art. 7 proof of
consent) — user creation fails closed if the consent record cannot be
written, so a user can never exist without a consent record.

## Defining roles and permissions

Roles are named collections of permissions; permissions represent an action
(optionally scoped to specific resources via scopes). To create a role:

```
POST /api/v1/roles
{ "name": "billing-admin", "description": "Manage billing settings", "is_global": false }
```

To create a permission:

```
POST /api/v1/permissions
{ "action": "billing:manage", "description": "Manage billing configuration" }
```

To grant a permission to a role (optionally scoped to specific resources via
`scope_ids`):

```
POST /api/v1/roles/{role_id}/permissions
{ "permission_id": "<uuid>", "scope_ids": [] }
```

A role's `is_global` flag controls whether it applies tenant-wide or must be
assigned per-resource; resource-scoped roles cascade to child resources in
the hierarchy unless overridden.

## Assigning roles

To assign a role directly to a user (optionally scoped to a specific
resource via `resource_id`; omit for a tenant-wide/global assignment):

```
POST /api/v1/roles/{role_id}/users
{ "user_id": "<uuid>", "resource_id": null }
```

To assign a role to a group instead — every member of the group inherits the
role:

```
POST /api/v1/roles/{role_id}/groups
{ "group_id": "<uuid>", "resource_id": null }
```

Groups themselves are created via `POST /api/v1/groups` and populated via
`POST /api/v1/groups/{group_id}/members`. Assigning a role to a group is the
recommended pattern for managing access for a team rather than granting
roles to individual users one at a time.
