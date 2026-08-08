# Deny-override design — explicit deny in the AXIAM RBAC engine

> B1 from `claude_dev/improvement-after-run5-benchmark.md`. Closes SEC-040,
> which deferred deny-override past v1.0-beta, and the "no explicit deny" entry
> in the public comparison page's cons list.

## 1. What exists today, and why it is not enough

The engine is **additive-only**: default-deny, and any matching grant allows.
There is no way to express "…except this one resource" or "…but never this
action", so the only way to carve an exception out of a broad grant is to stop
making the broad grant — which in practice means enumerating every resource a
role should reach, forever, as the tree grows.

Keycloak and Zitadel both ship a negative-permission mechanism, and it is the
single most-cited gap in comparisons against them. It is also cited in our own
public analysis. This closes it.

## 2. Semantics (normative)

**Precedence, in order:**

1. Default deny.
2. An applicable **allow** grant permits the action.
3. An applicable **deny** grant refuses it — **and beats every allow**,
   wherever either sits in the hierarchy.

Deny wins. Always. Not "most specific wins".

### 2.1 Why deny-override and not most-specific-wins

Most-specific-wins reads as more expressive and is a security footgun. Under
it, the meaning of a deny depends on where every *other* rule sits, so:

- adding an allow deeper in the tree silently re-opens something a deny closed,
- a security reviewer cannot answer "is X denied?" by looking at the deny — they
  must enumerate every rule that might out-specify it,
- moving a resource in the hierarchy can change access without any rule changing.

Deny-override gives one property that is worth more than the expressiveness:
**adding a deny rule can never widen access, and can never be undone by adding
allows.** That is checkable, and it is asserted as a property test.

The cost is real and should be stated: you cannot express "deny the subtree,
except this one leaf". The answer is to narrow the deny, not to widen the
allow. If that turns out to be too restrictive in practice, the escape hatch is
a future scoped-exception mechanism with its own review — not a quiet switch to
most-specific-wins.

### 2.2 Hierarchy cascade — worked table

Resources: `/fleet` → `/fleet/decommissioned` → `/fleet/decommissioned/unit-7`.

| # | Rules | Check on `/fleet/decommissioned/unit-7` | Result | Why |
|---|---|---|---|---|
| 1 | allow `read` on `/fleet` | read | **allow** | allow cascades to descendants (unchanged) |
| 2 | *(nothing)* | read | **deny** (`no_grant`) | default deny (unchanged) |
| 3 | allow `read` on `/fleet`, deny `read` on `/fleet/decommissioned` | read | **deny** (`denied_by_rule`) | deny cascades down, and beats the ancestor allow |
| 4 | deny `read` on `/fleet`, allow `read` on `/fleet/decommissioned` | read | **deny** (`denied_by_rule`) | **a child allow does NOT override an inherited deny** — this is the deny-override rule, and the row a reviewer should read twice |
| 5 | allow `read` on `/fleet`, deny `write` on `/fleet` | read | **allow** | denies are per action; `write` says nothing about `read` |
| 6 | allow + deny of the same action on the same node | read | **deny** (`denied_by_rule`) | deny wins at equal specificity too — there is no tie to break |
| 7 | allow via a directly assigned role, deny via a group-inherited role | read | **deny** (`denied_by_rule`) | denies inherit through groups exactly as allows do |
| 8 | allow via a global role, deny on a resource-scoped role | read | **deny** (`denied_by_rule`) | global vs resource-scoped changes applicability, not precedence |

Row 4 is the one that surprises people. It is also the one that makes the
property in §2.1 true.

### 2.3 Scope interaction

A grant carries `scope_ids`; empty means "all scopes" (wildcard). Deny follows
the same shape, which gives:

| Deny rule | Effect |
|---|---|
| deny action `read`, **no scopes** (wildcard) | masks `read` entirely on that node and its descendants — every scope, and unscoped checks too |
| deny action `read`, **scopes = [`pii`]** | masks only `read`+`pii`; `read`+`billing` and unscoped `read` are unaffected |

Read the wildcard rule carefully: a resource-level deny is *stronger* than a
scope-level one, because it matches every request for that action regardless of
what scope the request names. That is the intended reading of "deny at resource
level masks all scopes".

### 2.4 Evaluation order and the hot path

The requirement is that the **common case pays nothing**. The overwhelming
majority of tenants will have zero deny rules, and the authorization check is
the hottest path in the product (measured at ~12 700 reads/s on gRPC).

The evaluation is therefore a **single pass over grants already fetched**:

```
for each applicable role:
  for each grant of that role matching (action, scope):
    if grant.effect == Deny  -> return Deny(denied_by_rule)   // short-circuit
    if grant.effect == Allow -> remember "saw an allow"
return saw_allow ? Allow : Deny(no_grant)
```

Note what this does **not** do:

- **no second query.** Denies live on the same `grants` edge as allows and
  arrive in the same batched fetch that already happens. There is no
  deny-specific round trip, so there is no need for a per-tenant `has_denies`
  flag to gate one. (The improvement plan floated that flag as a way to keep
  the no-denies path at one query; putting `effect` on the existing edge
  achieves the same thing without a second source of truth that could go
  stale.)
- **no ordering dependence.** Deny short-circuits, and allows are only
  remembered, so the result does not depend on the order grants come back in.
  A rule set has one answer, not one answer per query plan.

Incremental cost when no denies exist: one enum comparison per grant already
being examined. The `±2 %` perf gate in the improvement plan is expected to
pass trivially; the with-denies cost is published as its own labelled cell
rather than folded into the headline.

### 2.5 Cache correctness

Decision-cache entries key on `(tenant, subject, resource, action, scope)` and
store the **full decision**. A deny outcome is cached exactly like an allow —
same key space, same TTL, same shape.

**Caching denies symmetrically is deliberate.** Asymmetric caching (cache
allows, always re-read denies) leaks a timing signal that distinguishes the two
outcomes, and it surprises operators who reason about one TTL. The cost of
symmetry is that a *removed* deny rule takes up to the TTL to widen access —
which is the safe direction, and is anyway covered by invalidation.

Every deny-rule create/update/delete fires the existing invalidation hooks, on
the same event path as any other grant mutation, with the same measured 262 ms
contract. Deny rules are not special to the cache; they are grants.

## 3. API surface

`effect: "allow" | "deny"`, defaulting to `"allow"`, on:

- role→permission grant create/update (REST, gRPC, AMQP),
- role assignment on a resource node.

**Backward compatible by construction.** Existing data has no `effect` field
and reads back as `allow`; existing clients send no `effect` and get `allow`.
There is no migration beyond the schema default.

Check responses gain a machine-readable reason:

| Reason | Meaning |
|---|---|
| `allowed` | an allow grant matched and no deny did |
| `no_grant` | nothing matched — default deny |
| `denied_by_rule` | an explicit deny matched |

The distinction matters to callers: `no_grant` means "ask an admin for
access", `denied_by_rule` means "an admin has already decided". Collapsing both
into a bare `false` — which is what an SDK would do without this — loses the
only information that tells a user which of those two situations they are in.
SDK contract §11 is updated accordingly; middleware behaviour is unchanged
(both are still 403).

## 4. Migration

None required. `effect` is absent on every existing grant edge and absent
reads as `allow`, so a deployment that upgrades and changes nothing behaves
identically. The first deny rule a tenant creates is the first behavioural
change, and it is one they made deliberately.

SEC-040 moves from "deferred" to "closed" in the threat model.

## 5. Test plan

Engine table tests, one per row of §2.2, plus:

- deny at scope level vs resource level (§2.3, both directions),
- deny via a group-inherited role,
- deny in a global role vs a resource-specific role,
- a cached deny returns byte-identically to an uncached one,
- invalidation on deny-rule delete re-opens access.

**Property test:** for any rule set and any request, adding a deny rule never
turns a `Deny` into an `Allow`. This is §2.1's guarantee stated executably, and
it is the test that would catch a future "most-specific-wins" refactor.

`EXPLAIN` guard: the grants query keeps its `IndexScan` plan — `effect` is a
projected column, never a filter, so it cannot make the predicate opaque to the
planner (which is exactly how I7(a) went wrong before).

## 6. Explicitly out of scope

- **Deny on a permission itself** (as opposed to on a grant). A permission is a
  vocabulary entry; making the vocabulary carry polarity would mean `read`
  could be a "deny-read" permission, which is incoherent.
- **Conditional / attribute-based denies.** That is ABAC, not RBAC deny-override.
- **Deny exceptions** ("deny the subtree except this leaf") — see §2.1.
