# B6 — one administrator, every tenant

**What this demonstrates.** An organization-level administrator creating a
tenant and administering it immediately, with no grant written into that tenant
and no second sign-in — and then the boundary that keeps the arrangement safe:
a *tenant* administrator with an identically-named global role that reaches
nothing outside its own tenant.

This is the scenario behind the defect that motivated organization scope:
creating a tenant left it unreachable by everybody, including the super-admin
who had just created it. See
[`docs/admin/organization-scope.md`](../../docs/admin/organization-scope.md)
for the model and
[`claude_dev/organization-scope-design.md`](../../claude_dev/organization-scope-design.md)
for why it is built this way.

**What it requires.**

- A running AXIAM instance, already bootstrapped — see
  [`scripts/e2e-bootstrap.sh`](../../scripts/e2e-bootstrap.sh). Bootstrap
  creates the organization, its reserved organization tenant, and the
  super-admin **inside that tenant**, which is the whole starting point here.
- `curl` and `jq` on `PATH`. Plain REST, no SDK dependency, so it cannot drift
  from what the wire actually does.

**What it does NOT cover.** Deny-override, scope narrowing and group
inheritance all behave identically for organization principals and are covered
by [`b1-deny-override/`](../b1-deny-override/README.md) and the engine's own
suite. This example is scoped to the one thing that is new: which tenants a
principal's grants reach.

## Run it

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --wait
./scripts/e2e-bootstrap.sh
./examples/b6-organization-scope/walkthrough.sh
```

## What it shows, step by step

1. **Sign in with no tenant.** The super-admin belongs to the organization
   tenant, so it names no tenant at all:

   ```json
   { "org_slug": "acme", "username_or_email": "admin", "password": "…" }
   ```

   The response carries `"organization_level": true`.

2. **Create a tenant.** `POST /organizations/{org}/tenants` seeds the new
   tenant's permissions *and* its default roles, and assigns them to nobody.

3. **Administer it immediately.** The same token, plus one header:

   ```
   X-Axiam-Tenant: <the new tenant id>
   ```

   Listing users in that tenant succeeds. Nothing was granted to anybody in
   step 2 — the super-admin's global role lives in the organization tenant and
   carries across by the one rule organization scope adds.

4. **Create a second tenant and reach that too.** No new grant, no restart, no
   sign-in. This is the property that makes deriving access at check time
   better than fanning grants out: a tenant created ten months from now is
   reachable by the same rule.

5. **The boundary.** A tenant administrator is created in tenant A with a
   *global* role — `is_global`, no resource — which reaches every resource in
   tenant A and nothing in tenant B. The header does not help it: the server
   refuses `X-Axiam-Tenant` for a principal that is not organization-level,
   with a 403 rather than a silent fallback.

6. **Same name, different reach.** Both roles are called `operations` and both
   are global. The one in the organization tenant is *organization-wide*; the
   one in tenant A is *tenant-wide*. That is why the admin UI stopped labelling
   both "Global".

7. **The middle ground.** Steps 1–4 gave one administrator every tenant; step 5
   gave another exactly one, permanently, by where its account lives. Neither
   expresses the case operators actually ask for: an organization-level
   operator who should administer *some* of the organization's tenants.

   A `tenant_scope` on the role assignment expresses it:

   ```json
   POST /api/v1/roles/{role_id}/users
   { "user_id": "…", "tenant_scope": ["<tenant-a>"] }
   ```

   The account is created in the organization scope and holds the
   organization's own `super-admin` role — so nothing below is about a missing
   permission. The walkthrough asserts all five consequences:

   | | |
   |---|---|
   | `/auth/me` | reports `reachable_tenant_ids: ["<tenant-a>"]`, and **no** `*` wildcard |
   | tenant A | works normally |
   | tenant B | `403` at the `X-Axiam-Tenant` header, not one denial per request |
   | `GET …/tenants` | lists tenant A only |
   | `POST …/tenants` | `403` — an account confined to particular tenants is not an organization administrator |

   The last one is the half the authorization engine structurally cannot
   enforce: creating a tenant names no tenant, so there is nothing for a scope
   to be compared against. That is why it is an explicit guard, and why the
   walkthrough asserts it rather than assuming it.

## The rule, stated once

> When a subject's grants are read across a tenant boundary, only **global**
> grants carry.

A resource-scoped assignment names a resource id in the organization tenant. No
resource with that id exists in another tenant, and one that shared a *name*
would be an unrelated thing — so carrying it across would turn a narrow grant
into a grant on something else entirely, across an isolation boundary. Step 5
of the walkthrough asserts exactly that.
