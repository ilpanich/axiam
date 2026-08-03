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

## Authorization decision cache (optional, D7)

AXIAM can cache effective-permission decisions per tenant to cut the 3–4
SurrealDB round-trips each authorization check would otherwise make. It is
**off by default** and controlled entirely by configuration — enabling it
changes performance, never the decision an endpoint returns.

| Env var | Default | Meaning |
| --- | --- | --- |
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` | `false` | Master switch. When `false`, the authorization path is byte-for-byte identical to a build without the cache. |
| `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` | `5` | Time-to-live for a cached decision, in seconds. Also the **bound on worst-case revocation latency** if an invalidation event is ever missed (see below). Keep it short. |
| `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` | `10000` | Maximum cached decisions retained **per tenant** before FIFO eviction (memory bound). |
| `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` | `false` | Fan invalidations out to **every replica** over RabbitMQ (§4.2). Requires the master switch above. See [below](#cross-replica-invalidation-optional-42). |
| `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS` | `30` | Freshness window for an inbound invalidation broadcast. Only used when the broadcast channel is on. |

The cache key is `(tenant, subject, resource, action, scope)` and it stores the
**full** decision — an allow, or a deny *with its exact reason* — so a cache
hit is indistinguishable from a fresh evaluation.

### Why it is safe: immediate invalidation on revocation

AXIAM's RBAC is **additive, allow-wins, default-deny** (no deny-override). That
makes the two staleness directions asymmetric:

- A **stale deny** is harmless — it only forces a redundant re-check; the
  subject is briefly under-privileged, never over-privileged.
- A **stale allow after a revocation** is the *only* dangerous case — a subject
  keeping access they no longer have.

So the cache is not left to expire on its own for security. Every mutation that
can narrow access **invalidates the affected cache entries immediately**, wired
directly into the mutation handlers:

| Mutation | Invalidation |
| --- | --- |
| Unassign role from user; remove user from group | Targeted — that one subject |
| Assign role to user; add user to group (widening) | Targeted — that one subject |
| Unassign role from group; revoke grant from role; delete/update role or permission; assign role to group or grant to role; create/update/delete resource; rename/delete scope; delete group | Per-tenant flush (affected-subject set not known without a query) |

A per-tenant flush is the conservative fallback for coarse mutations; it can
never leave a stale allow. **The security guarantee is: on the replica that
handled the mutation, no revocation leaves a stale allow** — the cache entry is
dropped in the same request that performs the revocation, before the response
returns. Whether that guarantee extends to the *other* replicas depends on the
broadcast switch; read the next two sections before enabling this in a scaled
deployment.

### Without the broadcast channel, the cache is process-local

With `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=false` (the default) the
cache lives in the server process and there is **no cross-replica
invalidation** (no AMQP fan-out, no shared store, no webhook). So:

| Deployment | Revocation latency for the decision cache |
| --- | --- |
| **Single replica** | **Immediate** — the invalidation hook drops the entry in the revoking request. The TTL is only the backstop for a missed hook. |
| **Two or more replicas** | **Up to `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5 s).** The revocation is handled by one replica and invalidates only that replica's cache; the others keep serving their cached decision until it expires. |

Three consequences worth stating plainly:

- It applies to **every** read path — REST `/api/v1/authz/check`, gRPC
  `CheckAccess`, AMQP async authz, *and* the internal `RequirePermission` guard
  on the admin endpoints — because one cache instance is shared by all engines
  in the process. Revoking an **administrator's** own privileges is subject to
  the same window on the other replicas.
- The window is **silent and unobservable**: a hit is byte-identical to a miss
  and the audit log records the decision, not its provenance. After an incident
  you cannot tell from the logs whether a given allow came from cache.
- Therefore: enable the broadcast channel below, enable the cache on a single
  replica, or accept a ≤ TTL revocation window.

### Cross-replica invalidation (optional, §4.2)

Setting `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true` (on top of
`DECISION_CACHE_ENABLED=true`) closes that window. Every invalidation from the
table above is *also* published, HMAC-signed, to the **fanout** exchange
`axiam.authz.cache.invalidate`; each replica binds its own exclusive
auto-delete queue and applies what it receives. Revocation then reaches all
replicas in broker-latency time. The table's granularity is unchanged — a
broadcast carries exactly "flush this tenant" or "flush this subject in this
tenant", nothing finer.

It needs no new infrastructure: RabbitMQ is already required, and the messages
are signed with the same mandatory `AXIAM__AMQP__SIGNING_KEY` (per-tenant
HKDF-SHA256 subkey, `key_version >= 2`, per-message nonce, `issued_at`
freshness) that the authz and audit consumers use. All replicas must share that
key.

**Two operational behaviours to know before enabling it:**

1. **A mutation whose broadcast the broker does not confirm returns 503.** The
   database write is durable, but the other replicas were not told, so the
   revocation has not fully taken effect and the API says so rather than
   reporting success. The response body contains *"could not be broadcast to
   other replicas"*. Every such mutation is idempotent in the narrowing
   direction — **retry it**.
2. **A replica whose invalidation consumer is disconnected stops using its
   cache.** It falls back to full database evaluation — correct, just slower —
   rather than serving allows it can no longer invalidate. This also covers the
   startup window: a replica does not serve a single cached decision until its
   consumer has subscribed.

Neither mode is silent — see *Observing what the cache is doing* below.

**What this does not change:** the TTL is still the backstop; the audit log
still records the decision, not its provenance; and a *rejected* broadcast
(bad signature, stale, replayed) is logged and counted but can never disable a
replica's cache — trust follows the consumer's connection state only, so a
captured message cannot be used as a cache-disabling lever.

### Observing what the cache is doing

With the cache enabled the server logs a
`AuthZ decision cache stats (D7)` line every 60 s
(`AXIAM__AUTHZ__DECISION_CACHE_STATS_SECS=0` disables it, any other positive
value changes the period) carrying `entries`, `tenants`, `queue_slots`, `hits`,
`misses`, `hit_rate_pct`, `trusted` and `bypassed`. Use `entries` to check
whether the working set is actually hitting `DECISION_CACHE_MAX_ENTRIES` (i.e.
whether FIFO eviction is running and depressing the hit rate) and
`hit_rate_pct` to decide whether the cache is earning its staleness window at
all — a low hit rate means a large key space and no benefit.

**With cross-replica invalidation enabled, `trusted` and `bypassed` are the
alert conditions:**

| Signal | Meaning | Action |
| --- | --- | --- |
| `trusted=false`, or `bypassed` rising | This replica cannot hear invalidations and is evaluating every check against the database. Correct, but at uncached latency. | Check broker connectivity from that pod. It recovers on its own once the consumer reconnects. |
| `AuthZ decision cache UNTRUSTED …` at **ERROR** | The moment it lost the invalidation stream. | As above. |
| `AuthZ decision cache TRUSTED again …` at INFO | Recovered; the cache restarts from empty. | None. |
| 503 with *"could not be broadcast to other replicas"* on a mutation | The broker, not the database, refused. The write landed; the fan-out did not. | Retry the mutation. |

### Bounded-staleness backstop

The TTL is a second line of defence, not the primary one. Even if an
invalidation were somehow missed (a bug, an out-of-band write straight to the
database), a stale allow can persist for **at most
`AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS`** before it is force-evicted and
re-evaluated. The short default (5 s) keeps that worst case small. Operators who
want a tighter bound can lower the TTL; those who never mutate roles out-of-band
can safely raise it.
