#!/usr/bin/env python3
"""Emit SurrealQL that inflates an already-seeded AXIAM bench fixture to N x scale.

Why this exists (E3 / J12)
--------------------------
The run-5 matrix measured a fixture of ~1 tenant, ~2 users, 1 resource and ~100
registry permissions. Every authz number in the report is therefore a number for
a *tiny* dataset, and the honest question a reader asks -- "does the 12 k/s
check path hold when the tenant has 100 000 users and a four-deep resource
tree?" -- has no answer in the archive. The seed-size sensitivity cell needs a
10x (or 100x) fixture, and it needs it in minutes, not hours.

`runner/seed.sh` provisions through the REST API, which is correct for the
*functional* fixture (it exercises the same handlers a real operator would) and
hopeless for volume: one HTTP round trip, one Argon2id hash and several indexed
writes per user, times 100 000.

So this generator writes SurrealQL directly, in transactions of
`--batch` statements, to be piped into the datastore. It is a *load-test data
generator*, not a provisioning tool, and the difference is deliberate:

  * **Bulk users cannot authenticate, by construction.** Their `password_hash`
    is the literal sentinel below -- not an Argon2id encoded hash at all, so
    verification fails to parse and the login is denied. Generating real hashes
    would mean either 100 000 Argon2id runs (defeating the point) or one shared
    hash for a known password (a fixture that ships a usable credential for
    every synthetic account, which is not a thing to leave lying in a
    datastore). Volume is the goal; authentication is not.
  * **The functional fixture is never touched.** `runner/seed.sh`'s
    `benchuser` / `bench-resource` / `bench-reader` objects keep their ids, so
    an authz cell run against a 10x fixture measures the SAME logical query
    against a bigger index -- which is the only way the before/after comparison
    means anything.
  * **Deterministic ids.** Every generated record's UUID is derived from
    (entity kind, index), so re-running is an UPSERT no-op rather than a second
    100 000 records, and a scenario can address the bulk set without reading it
    back.

Usage:
    bulk-seed.py --tenant-id <uuid> [--scale 10] [...] > bulk.surql

The companion `bulk-seed.sh` pipes this into the running SurrealDB container
and reports timings and row counts.
"""

from __future__ import annotations

import argparse
import sys

# Not an Argon2id encoded hash: `$argon2id$...` is the only shape the verifier
# accepts, so this fails to parse and every login against a bulk user is denied
# before any password comparison happens. Written in full words so that anyone
# who greps a datastore dump and finds it knows immediately what it is.
NON_AUTHENTICATABLE = "!axiam-bulk-seed-fixture-not-authenticatable!"

# UUID namespaces per entity kind. Each is a syntactically valid UUIDv4
# (version nibble 4, variant nibble 8) whose last 12 hex digits are the record
# index, so ids are stable across runs and trivially recognisable in a dump as
# generated rather than organic.
NS = {
    "tenant": "be000001",
    "user": "be000002",
    "role": "be000003",
    "resource": "be000004",
    "permission": "be000005",
    "group": "be000006",
    # Edge tables get namespaces too. `RELATE` always creates a NEW edge, so a
    # re-run would either duplicate `child_of` or violate the UNIQUE(in,out)
    # indexes on `has_role`/`grants` and abort the transaction. Addressing each
    # edge by a deterministic id and UPSERTing it makes the whole load
    # re-runnable, which matters because a bulk seed is exactly the thing an
    # operator interrupts halfway and restarts.
    "e_has_tenant": "bf000001",
    "e_child_of": "bf000002",
    "e_grants": "bf000003",
    "e_has_role": "bf000004",
}


def rid(kind: str, index: int) -> str:
    """Deterministic, valid UUID for the index-th record of `kind`."""
    return f"{NS[kind]}-0000-4000-8000-{index:012x}"


def esc(s: str) -> str:
    """Escape a Python string for a single-quoted SurrealQL string literal."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


class Batcher:
    """Emits statements wrapped in BEGIN/COMMIT transactions of `size`.

    One transaction per 1 000 records (the default) is the point of the whole
    exercise: SurrealDB commits each bare statement individually otherwise, and
    the fsync-per-statement cost is what makes a naive bulk load take hours.
    Batching too aggressively is the opposite failure -- a single 100 000
    statement transaction holds locks for its whole duration and can exhaust
    memory -- so the size stays a knob with a sane default.
    """

    def __init__(self, out, size: int) -> None:
        self.out = out
        self.size = size
        self.n = 0
        self.open = False
        self.total = 0

    def add(self, stmt: str) -> None:
        if not self.open:
            self.out.write("BEGIN TRANSACTION;\n")
            self.open = True
            self.n = 0
        self.out.write(stmt + "\n")
        self.n += 1
        self.total += 1
        if self.n >= self.size:
            self.flush()

    def flush(self) -> None:
        if self.open:
            self.out.write("COMMIT TRANSACTION;\n")
            self.open = False
            self.n = 0


def emit_tenants(b: Batcher, org_id: str, base_tenant: str, count: int) -> list[str]:
    """Extra tenants alongside the seeded one. Returns every tenant id in play.

    Multi-tenancy is the dimension a single-tenant fixture cannot measure at
    all: every hot authz query filters on `tenant_id`, so an index holding one
    tenant's rows and an index holding fifty tenants' rows are different
    physical objects even at the same total row count.
    """
    ids = [base_tenant]
    for i in range(count):
        tid = rid("tenant", i)
        ids.append(tid)
        b.add(
            f"UPSERT tenant:`{tid}` SET "
            f"organization_id = '{esc(org_id)}', "
            f"name = 'Bulk Tenant {i}', "
            f"slug = 'bulk-t{i}', "
            f"status = 'Active', "
            f"settings = {{}};"
        )
        eid = rid("e_has_tenant", i)
        b.add(
            f"UPSERT has_tenant:`{eid}` SET "
            f"in = organization:`{esc(org_id)}`, out = tenant:`{tid}`;"
        )
    return ids


def emit_users(b: Batcher, tenant_id: str, offset: int, count: int) -> None:
    for i in range(count):
        idx = offset + i
        uid = rid("user", idx)
        b.add(
            f"UPSERT user:`{uid}` SET "
            f"tenant_id = '{esc(tenant_id)}', "
            f"username = 'bulk-u{idx}', "
            f"email = 'bulk-u{idx}@bulk.invalid', "
            f"password_hash = '{esc(NON_AUTHENTICATABLE)}', "
            f"status = 'Active', "
            f"mfa_enabled = false, "
            f"failed_login_attempts = 0, "
            f"metadata = {{ bulk_seed: true }};"
        )


def emit_resource_tree(
    b: Batcher, tenant_id: str, offset: int, count: int, depth: int, fanout: int
) -> list[str]:
    """A `depth`-deep tree of `count` resources. Returns the generated ids.

    Depth matters more than count for the authz engine: a check against a leaf
    walks its ancestor chain, so a flat 10 000-resource fixture exercises the
    hierarchy code exactly as hard as a 1-resource one (i.e. not at all). Both
    `parent_id` and the `child_of` edge are written because the repository
    layer maintains both and different queries read different ones -- a fixture
    that set only one would make some queries fast for the wrong reason.
    """
    ids: list[str] = []
    # Size the root level so that growing by `fanout` for `depth` levels lands
    # on roughly `count` nodes: count / (1 + f + f^2 + ... + f^(depth-1)).
    # Getting this wrong in the obvious direction (too many roots) produces a
    # wide, shallow tree that looks like the requested size and exercises none
    # of the ancestor-walk code the cell exists to stress.
    widths = [fanout ** level for level in range(depth)]
    roots = max(1, count // max(1, sum(widths)))
    prev_level: list[str] = []
    made = 0
    for level in range(depth):
        if made >= count:
            break
        want = roots if level == 0 else len(prev_level) * fanout
        want = max(1, min(want, count - made))
        this_level: list[str] = []
        for i in range(want):
            idx = offset + made + i
            rrid = rid("resource", idx)
            this_level.append(rrid)
            ids.append(rrid)
            if level == 0:
                b.add(
                    f"UPSERT resource:`{rrid}` SET "
                    f"tenant_id = '{esc(tenant_id)}', "
                    f"name = 'bulk-res-{idx}', "
                    f"resource_type = 'bulk', "
                    f"parent_id = NONE, "
                    f"metadata = {{ bulk_seed: true, depth: {level} }};"
                )
            else:
                parent = prev_level[i % len(prev_level)]
                b.add(
                    f"UPSERT resource:`{rrid}` SET "
                    f"tenant_id = '{esc(tenant_id)}', "
                    f"name = 'bulk-res-{idx}', "
                    f"resource_type = 'bulk', "
                    f"parent_id = '{parent}', "
                    f"metadata = {{ bulk_seed: true, depth: {level} }};"
                )
                eid = rid("e_child_of", idx)
                b.add(
                    f"UPSERT child_of:`{eid}` SET "
                    f"in = resource:`{rrid}`, out = resource:`{parent}`;"
                )
        made += want
        prev_level = this_level
    # The geometric sizing leaves a remainder when count is not a clean
    # multiple; hang it off the deepest level so the requested count is met
    # exactly rather than approximately.
    while made < count and prev_level:
        idx = offset + made
        rrid = rid("resource", idx)
        parent = prev_level[made % len(prev_level)]
        ids.append(rrid)
        b.add(
            f"UPSERT resource:`{rrid}` SET "
            f"tenant_id = '{esc(tenant_id)}', "
            f"name = 'bulk-res-{idx}', "
            f"resource_type = 'bulk', "
            f"parent_id = '{parent}', "
            f"metadata = {{ bulk_seed: true, depth: {depth} }};"
        )
        b.add(
            f"UPSERT child_of:`{rid('e_child_of', idx)}` SET "
            f"in = resource:`{rrid}`, out = resource:`{parent}`;"
        )
        made += 1
    return ids


def emit_roles_and_grants(
    b: Batcher,
    tenant_id: str,
    offset: int,
    count: int,
    resources: list[str],
    users_offset: int,
    users_count: int,
    deny_ratio: float,
) -> None:
    """Roles, their permission grants, and role assignments onto the tree.

    `deny_ratio` writes a proportion of the grants as `effect = 'deny'`. This
    is not decoration: B1's deny-override path only runs its second indexed
    query for tenants that actually hold deny rules, so a fixture with zero
    denies measures the cheap path exclusively and would let a deny-path
    regression ship unmeasured.
    """
    if not resources:
        return
    for i in range(count):
        idx = offset + i
        role_id = rid("role", idx)
        perm_id = rid("permission", idx)
        b.add(
            f"UPSERT role:`{role_id}` SET "
            f"tenant_id = '{esc(tenant_id)}', "
            f"name = 'bulk-role-{idx}', "
            f"description = 'Bulk seed role', "
            f"is_global = false;"
        )
        b.add(
            f"UPSERT permission:`{perm_id}` SET "
            f"tenant_id = '{esc(tenant_id)}', "
            f"action = 'bulk:act{idx}', "
            f"description = 'Bulk seed permission';"
        )
        effect = "deny" if (deny_ratio > 0 and (i % max(1, int(1 / deny_ratio))) == 0) else "allow"
        b.add(
            f"UPSERT grants:`{rid('e_grants', idx)}` SET "
            f"in = role:`{role_id}`, out = permission:`{perm_id}`, "
            f"scope_ids = NONE, effect = '{effect}';"
        )
        # Assign the role to a user, scoped to a resource in the tree. Spread
        # across the tree rather than all on one node so ancestor walks differ
        # in length between checks, as they do in a real deployment.
        if users_count > 0:
            uid = rid("user", users_offset + (i % users_count))
            res = resources[i % len(resources)]
            b.add(
                f"UPSERT has_role:`{rid('e_has_role', idx)}` SET "
                f"in = user:`{uid}`, out = role:`{role_id}`, "
                f"resource_id = '{res}';"
            )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tenant-id", required=True,
                   help="the seeded tenant (BENCH_TENANT_ID) the bulk rows join")
    p.add_argument("--org-id", default="",
                   help="the seeded organization (BENCH_ORG_ID); required when --tenants > 0")
    p.add_argument("--scale", type=int, default=10,
                   help="multiplier applied to every base count (default 10)")
    p.add_argument("--users", type=int, default=1000,
                   help="base users per tenant, before --scale (default 1000)")
    p.add_argument("--resources", type=int, default=200,
                   help="base resources per tenant, before --scale (default 200)")
    p.add_argument("--roles", type=int, default=50,
                   help="base roles per tenant, before --scale (default 50)")
    p.add_argument("--tenants", type=int, default=0,
                   help="EXTRA tenants beyond the seeded one (default 0; not scaled)")
    p.add_argument("--depth", type=int, default=4,
                   help="resource-tree depth (default 4)")
    p.add_argument("--fanout", type=int, default=6,
                   help="children per resource node (default 6)")
    p.add_argument("--deny-ratio", type=float, default=0.05,
                   help="fraction of grants written as effect='deny' (default 0.05); "
                        "0 disables, which measures ONLY B1's cheap no-denies path")
    p.add_argument("--batch", type=int, default=1000,
                   help="statements per BEGIN/COMMIT transaction (default 1000)")
    args = p.parse_args()

    if args.tenants > 0 and not args.org_id:
        print("bulk-seed: --org-id is required when --tenants > 0", file=sys.stderr)
        return 2
    if args.scale < 1:
        print("bulk-seed: --scale must be >= 1", file=sys.stderr)
        return 2

    users = args.users * args.scale
    resources = args.resources * args.scale
    roles = args.roles * args.scale

    b = Batcher(sys.stdout, args.batch)
    tenants = emit_tenants(b, args.org_id, args.tenant_id, args.tenants)

    # Offsets keep every tenant's records in a disjoint id range, so a re-run
    # with a different --tenants count does not renumber (and thus duplicate)
    # an existing tenant's rows.
    for t_index, tid in enumerate(tenants):
        u_off = t_index * users
        r_off = t_index * resources
        ro_off = t_index * roles
        emit_users(b, tid, u_off, users)
        res_ids = emit_resource_tree(b, tid, r_off, resources, args.depth, args.fanout)
        emit_roles_and_grants(b, tid, ro_off, roles, res_ids, u_off, users, args.deny_ratio)

    b.flush()

    print(
        f"-- bulk-seed: {b.total} statements across {len(tenants)} tenant(s): "
        f"{users} users, {resources} resources (depth {args.depth}, fanout {args.fanout}), "
        f"{roles} roles/permissions/grants each; deny_ratio={args.deny_ratio}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
