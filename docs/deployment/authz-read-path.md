# The authorization read path — what it costs and how to tune it

Operator-facing companion to the
[decision cache](README.md#authorization-decision-cache-optional-d7) and
[session-validation cache](README.md#session-validation-cache-optional-i6)
sections of the deployment guide. It documents what an authorization check
actually does against SurrealDB, which of those round-trips each cache removes,
and which tuning levers exist.

## 1. What one uncached check costs

`POST /api/v1/authz/check` (and the gRPC `CheckAccess`) resolve a decision with
these **sequential** SurrealDB round-trips:

| # | Operation | Query shape | Plan |
|---|---|---|---|
| 0 | Session-revocation check (**REST only**) | `SELECT * FROM session:<jti> WHERE tenant_id = …` | Direct record fetch |
| 1a | Direct role assignments | `SELECT … FROM has_role WHERE in = user:<subject> AND out.tenant_id = …` | `IndexScan idx_has_role_unique` |
| 1b | Group-inherited role assignments | `LET $group_records = (SELECT VALUE out FROM member_of WHERE in = user:<subject>); SELECT … FROM has_role WHERE in IN $group_records AND …` | `IndexScan idx_member_of_unique` + `IndexScan idx_has_role_unique` |
| 2 | Resource ancestors | `…->child_of->(resource WHERE tenant_id = …)` recursive walk | Graph traversal (index-free by construction) |
| 3 | Scope resolution (**only when a scope is requested**) | `SELECT … FROM scope WHERE resource_id = …` | `idx_scope_resource_name` |
| 4 | Permission grants for every applicable role | `SELECT … FROM grants WHERE in IN $role_records AND out.tenant_id = …` | `IndexScan idx_grants_unique` |

Row 0 is the asymmetry between the REST and gRPC surfaces: the gRPC
interceptor validates the JWT signature and stops, while REST additionally
enforces session revocation (D-15 / REQ-7). Enabling only the decision cache
therefore helps gRPC far more than REST — the session-validation cache is what
closes that gap.

## 2. Index-satisfaction is pinned by tests, not by hope

Two of the queries above used to be **full table scans**, and neither was
visible in functional tests or in a small-seed benchmark:

* `grants` was filtered with `WHERE meta::id(in) IN $role_ids`. Wrapping the
  indexed field in a function call makes the predicate opaque to the planner
  (`TableScan { pre_decode_filter: "no (unsupported predicate)" }`), so every
  authorization check walked **every role→permission grant of every tenant**.
* the group-inherited half of the role-assignment lookup inlined its membership
  sub-select (`WHERE in IN (SELECT VALUE out FROM member_of WHERE …)`), which
  the planner also cannot fold into an index seek — so every check additionally
  walked **every role assignment of every user of every tenant**.

Both now compare against bound record ids / a pre-resolved `LET` binding and
plan as `IndexScan`. `crates/axiam-db/tests/authz_query_plan_test.rs` runs
`EXPLAIN` against the real migrated schema and fails if either regresses — it
also keeps a witness test proving the old forms really do scan, so the
assertions cannot silently become tautologies.

**If you extend the authz read path**, the rule is: never wrap an indexed field
in a function inside a `WHERE`, and never leave a correlated sub-select on the
right-hand side of `IN`. Add an `EXPLAIN` assertion to that test file for any
new hot query.

## 3. Which cache removes which round-trip

| Round-trip | Removed by |
|---|---|
| 0 (session) | `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` |
| 1a/1b, 2, 3, 4 | `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` |

Both caches are process-local *by default*, and both then carry the same
multi-replica caveat: a revocation handled by one replica is not seen by the
others until their entries expire. If you enable one, enable both at the same
TTL — a deployment that has accepted a 5-second decision-staleness window gains
nothing by keeping a 5-second session-staleness window at zero, and vice versa.

The **decision** cache can now escape that caveat:
`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true` fans every invalidation
out to all replicas over RabbitMQ
([details](README.md#cross-replica-invalidation-42)). The **session**
validation cache has no equivalent channel, so its multi-replica window is
still bounded only by its TTL — if you enable the broadcast channel, keep
`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` at a value you are still
willing to accept as a session-revocation window, because that is now the
looser of the two.

Two throughput notes for capacity planning with the broadcast channel on:

* A replica whose invalidation consumer is disconnected serves **none** of the
  round-trips in the table from cache — it drops back to the §1 uncached cost
  for the duration. Size for that, or alert on `trusted=false` /
  `bypassed` in the `AuthZ decision cache stats (D7)` line.
* Every access-narrowing mutation now waits for a broker publisher-confirm
  before responding. That is on the *administrative* mutation path, never on
  the authorization read path measured above.

Batch checks additionally benefit from `AXIAM__AUTHZ__BATCH_STRATEGY=coalesced`
(the shipped default), which resolves the shared subject/resource lookups once
per batch instead of once per item.

## 4. Design note — read replicas for authorization reads (not implemented)

Every query in §1 is a **read**. Authorization is by far the most read-heavy
surface AXIAM exposes, so routing it to a read replica is the obvious next
scaling step once index-satisfaction and caching are exhausted. This section
records the analysis; **no replica support is implemented today** and the
configuration surface below does not exist.

**Shape.** `axiam-db`'s `DbPool` already hands each repository a `DbHandle`, so
a read-replica topology does not need a new abstraction — it needs a second
pool and a policy for which handle a repository gets. The natural split is
per-repository rather than per-query: the role, permission, resource, scope and
group repositories used by `AuthorizationEngine::evaluate` are read-only on
that path and could be constructed against a replica pool, while every
write-carrying repository keeps the primary.

**The blocking problem is not plumbing, it is staleness semantics.** AXIAM's
RBAC is additive/allow-wins/default-deny, so the dangerous direction is a
*stale allow after a revocation* — exactly the property the decision cache's
invalidation hooks exist to protect. A read replica reintroduces that window at
the storage layer, where the invalidation hooks cannot reach it: unassigning a
role commits to the primary and the replica serves the pre-unassign row until
it catches up. Unlike the caches, that window is **not** bounded by a
configured TTL; it is bounded by replication lag, which is an operational
property that can degrade without any signal in AXIAM.

**Therefore, if this is ever built, it must:**

1. be **opt-in per deployment**, defaulting to primary-only reads;
2. expose measured replication lag as a health signal, and **fail closed** —
   fall back to the primary — when lag exceeds a configured bound, rather than
   silently serving stale authorization data;
3. route the **session-revocation read (row 0) to the primary regardless**;
   session revocation is a security control with a hard immediacy expectation,
   and it is a single point read, so it is cheap to exempt;
4. be documented next to the decision cache's multi-replica caveat with the
   combined worst-case revocation window (cache TTL + replication lag), not
   each in isolation;
5. carry a benchmark cell showing the win is real. The measured DB-uncapped
   deltas after the run-4 fixes (checks +89/90%, client-credentials +64%,
   userinfo +59%) say the database is the ceiling, but they do not say the
   ceiling is *read concurrency* rather than per-query cost — §2's two removed
   table scans are the reminder that per-query cost was, in fact, part of it.
   Re-measure before assuming replicas are the answer.

**Cheaper things to exhaust first:** the two caches in §3; the `coalesced`
batch strategy; the connection pool size; and confirming after the §2 fixes
whether the DB is still the ceiling at all.
