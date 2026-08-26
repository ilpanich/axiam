# Organization-level principals

Status: implemented in `claude/multi-tenant-access-control-uripsd`.

## The report

> If I create a new tenant, nobody can access — neither the super-admin created
> at bootstrap.

That is exactly what happens, and the cause is one line of omission rather than
anything subtle. `handlers::tenants::create` seeds the new tenant's
**permissions** and stops there:

```rust
let tenant = state.tenant_repo.create(input).await?;
seed_permissions(&state.db.current(), tenant.id, PERMISSION_REGISTRY).await?;
Ok(HttpResponse::Created().json(tenant))
```

No roles, no grants, no assignments. Meanwhile every lookup the authorization
engine performs is filtered by tenant:

```rust
let assignments = self.role_repo
    .get_user_role_assignments(request.tenant_id, request.subject_id).await?;
if assignments.is_empty() {
    return Ok(AccessDecision::Deny("no roles assigned".into()));
}
```

The bootstrap super-admin's `super-admin` role is a row in the *bootstrap*
tenant. Ask about the new tenant and the query returns nothing, so the answer is
`no roles assigned` for everyone, including the person who created it. The
tenant is not misconfigured; it is unreachable.

## Two fixes, and why both

The obvious repair is to seed the default roles in the new tenant too, and that
is necessary — a tenant with permissions and no roles cannot be administered by
anyone. But on its own it does not make the super-admin an administrator of the
new tenant: it creates an unassigned `super-admin` role that somebody with
existing access would have to grant, and nobody has existing access.

The second fix is the one the report actually asks for:

> some of them can operate at org level (i.e.: at least the super-admin) […]
> Users with organization level permission can operate on all tenants

So: principals that live above tenants, whose grants apply to every tenant in
the organization.

## The shape: an organization is a tenant

The tempting model is `User.tenant_id: Option<Uuid>`, with `None` meaning
"organization-level". It is also unshippable. `tenant_id` appears **7,849
times** across the workspace and is a non-optional `Uuid` in every repository
signature, every handler, every claim, every index. Making it optional is a
mechanical change to several thousand call sites, each of which has to answer
"and what does this do when there is no tenant?" — and the great majority of
them would answer it wrong by defaulting.

Instead: **every organization gets exactly one reserved tenant**, flagged
`kind: organization`, created with the organization itself. Organization-level
users, groups, roles, permissions and service accounts are ordinary rows in it.

Nothing about the storage model changes. What changes is one question the
authorization engine asks.

### What this buys, for free

**Uniqueness comes out exactly as specified.** The report asks:

> Organization-level users are unique at organization level and across all
> tenants; tenant level users must be unique for tenant.

The schema already has:

```sql
DEFINE INDEX idx_user_tenant_username ON TABLE user COLUMNS tenant_id, username UNIQUE;
DEFINE INDEX idx_user_tenant_email    ON TABLE user COLUMNS tenant_id, email    UNIQUE;
```

An organization-level user lives in the organization tenant, so it is unique
across the organization. A tenant user lives in its own tenant, so `user1` in
`tenant1` and `user1` in `tenant2` are two rows that cannot collide, and
registering twice in `tenant1` violates the index. That is the requirement,
verbatim, with **no schema change**.

**Everything else already works.** Organization-level roles, groups, service
accounts, sessions, audit entries, certificates — each is tenant-scoped today,
and each becomes organization-scoped by living in the organization tenant. No
new tables, no parallel code paths, no second RBAC engine.

## The one rule that is new

`AccessRequest` gains `subject_tenant_id`: where the subject's role assignments
live, as distinct from `tenant_id`, the tenant being acted upon. They are equal
for an ordinary tenant user, and the engine behaves exactly as before.

When they differ — an organization-level principal acting on a tenant — the
engine resolves assignments from the subject's home tenant and applies this
rule:

> Across a tenant boundary, only **global** grants carry.

A grant is global when its role assignment names no resource (`resource_id` is
the nil UUID). Resource-scoped assignments do not cross, and cannot: a role
assigned on resource `X` in the organization tenant says nothing about a
same-named resource in `tenant1`, and treating it as if it did would be a
silent privilege escalation across an isolation boundary. Scope names resolve
against the *target* tenant, because that is where the resource being narrowed
lives.

This is the whole of the new semantics. It is stated once, in
`AuthorizationEngine::evaluate`, and tested directly.

### Why not fan out grants instead

The alternative reading of

> each time a tenant is created, super-admin and "global" organization-level
> users gains immediately the required roles to operate also on it

is to write role assignments into the new tenant for every organization-level
principal at creation time. It produces the same access and is worse in three
ways:

- **It is not atomic.** Creating a tenant becomes a write whose size is the
  number of organization-level principals. A partial failure leaves a tenant
  some administrators can reach and others cannot.
- **It drifts.** An organization-level user created *after* the tenant gets
  nothing, so the fan-out has to run again on every principal creation too —
  now it is O(principals x tenants) writes maintained by two code paths that
  must agree forever.
- **It cannot be revoked coherently.** Removing organization-level access means
  finding and deleting every copy.

Deriving the answer at check time has none of these properties. An
organization-level principal has access to a tenant created ten seconds ago or
ten months ago by the same rule, and loses it the moment its organization role
is revoked.

## Login and tenant selection

> it becomes optional in the login page in such a way organization-level user
> could login at org level; for tenants user is mandatory

Login already accepts an optional `tenant_id`/`tenant_slug`. Omitting it now
resolves to the organization tenant, which is where organization-level users
live — so the credential lookup finds them and finds nobody else. A tenant user
who omits the tenant is not found, which is the correct outcome and the same
constant-time failure as a wrong password.

The active tenant for a request is carried by `X-Axiam-Tenant`. It is honoured
only for a principal whose home tenant is the organization tenant, and only for
tenants in that organization; anything else is refused rather than ignored.
`AuthenticatedUser` therefore carries two ids:

- `tenant_id` — the tenant being acted upon. Every existing handler keeps using
  this and none of them change.
- `principal_tenant_id` — where the caller's own record and grants live.

For a tenant user they are equal, which is why ~100 call sites need no edit.

## Bootstrap

> I will remove the tenant creation from the bootstrap page

Bootstrap creates the organization, its organization tenant, the
organization-level role set, and the first super-admin in it. It creates no
ordinary tenant, because there is nothing left that needs one: the super-admin
is organization-level and reaches every tenant created afterwards by the rule
above.

## Migration

`kind` defaults to `standard`, so existing tenant rows are unchanged and every
existing grant keeps meaning what it meant.

For each existing organization the migration creates the organization tenant if
absent. It does **not** move anyone into it: an existing deployment's users stay
where they are, with the access they have. Promoting an existing super-admin to
organization level is a deliberate act — moving accounts between tenants without
being asked is not something a version upgrade should do, and the deployment
that most needs the promotion is the one where an administrator should look at
it first.

The one-organization-tenant-per-organization invariant is a unique index, not a
convention.
