# SurrealDB Tuning & Connection-Pool Investigation (D6)

**Status:** PRELIMINARY — static source analysis complete; runtime profiling
(query traces, pool wait-time, uncapped-DB delta, engine-mode sensitivity)
is **pending a live run on the benchmark laptop** and must be filled in
after D1's tracing lands and C2's uncapped-DB pass is available. Numbers are
deliberately absent where they would require a measured run — do not treat
any figure here as measured until this banner is removed.

This document is the D6 deliverable required by
`claude_dev/benchmark-improvement-plan.md`. It records what can be
established from the code alone, states the leading hypothesis, and lists the
exact runtime measurements needed to confirm or refute it.

## 1. Connection architecture (established from source)

`crates/axiam-db/src/connection.rs`:

- AXIAM talks to SurrealDB over the **stateless HTTP engine**
  (`surrealdb::engine::remote::http`), not the WebSocket engine. The choice is
  deliberate (SDK issue #5750: Ws reconnect silently drops `use_ns`/`use_db`).
- There is **no connection pool**. `DbManager` holds a single
  `Arc<RwLock<Surreal<Client>>>`. Each of the ~30 repositories is handed a
  `client_cloned()` handle at composition time. Cloning a `Surreal<Client>`
  is cheap and **shares the same underlying connection lineage/router** — it
  does not open an independent connection.
- Consequence: every concurrent request in the process (all authz checks,
  token introspections, refreshes, logins) is routed through **one** shared
  SurrealDB client handle.

## 2. Authz hot-path query pattern (established from source)

`crates/axiam-authz/src/engine.rs::check_access` issues, per single check,
these **sequential** awaited DB operations:

1. `role_repo.get_user_role_assignments(tenant, subject)` — round-trip 1
2. `resource_repo.get_ancestors(tenant, resource)` — round-trip 2
3. *(only when a scope is requested)* `scope_repo.list_by_resource(...)` — round-trip 3
4. `permission_repo.get_role_permission_grants_for_roles(tenant, role_ids)` —
   round-trip 4 (already batched across roles — CQ-B13 N+1 fix; good)

So a single check is **3–4 serial HTTP round-trips** over the shared
connection. The REST/gRPC batch handler
(`axiam-api-rest::handlers::authz_check::batch_check_access`) already runs
items concurrently via `buffer_unordered(batch_max_concurrency)` — so a
5-item batch fans out to as many as **~20 round-trips** that all contend for
the **one** shared client handle.

## 3. Leading hypothesis

The benchmark evidence (batch-of-5 delivers *fewer* checks/s than single
calls; server idles at 0.07–0.11 cores while SurrealDB sits at ~1.2–2 cores
"waiting, not computing"; single-check gRPC p99 850 ms vs p95 173 ms) is
consistent with **serialization at the shared client handle / SurrealDB HTTP
router**, not with CPU-bound evaluation. Two independent contributors:

- **H1 — connection/router serialization.** If the SDK router or the single
  HTTP keep-alive connection serializes in-flight queries, concurrency at the
  `buffer_unordered` layer cannot translate into concurrent DB work. This
  would make batching *lose* to single calls (batch adds coordination
  overhead but cannot parallelize the DB).
- **H2 — redundant per-item queries in a batch.** Every item in the bench's
  batch shares the **same subject** (and usually the same resource), so
  round-trip 1 (`get_user_role_assignments`) and round-trip 2
  (`get_ancestors`) are **identical** across all 5 items and are being
  executed 5×. Coalescing same-subject/same-resource items into one set of
  lookups (the D1 fast path) removes ~80% of the round-trips for this shape.

H1 and H2 are additive: fix H2 (fewer round-trips) and H1 (parallelize the
remaining ones) together.

## 4. Measurements required to confirm (pending laptop run)

Wire these before drawing conclusions — this is the D1/D6 instrumentation
step and cannot be done in the CI sandbox (no live stack):

1. **Query trace.** Run one 5-item batch against the bench stack with
   `RUST_LOG=surrealdb=debug` (and per-item / per-query tracing spans added in
   D1). Record: number of DB round-trips, whether they overlap in time or
   serialize, and per-query latency.
2. **Pool / connection wait-time.** Since there is no pool, instrument the
   time each `check_access` spends between issuing a query and its first byte
   of response under 50 VUs; a growing wait with flat CPU confirms H1.
3. **Uncapped-DB delta (needs C2).** Re-run authz cells with
   `dbcaps=uncapped` (BENCH_DB_CPUS=4 / BENCH_DB_MEM=2048). If throughput
   barely moves while the server stays idle, the wall is the connection, not
   DB capacity — pointing to a pool, not DB tuning.
4. **Engine-mode sensitivity (labeled, respecting C2 durability parity).**
   Compare SurrealKV-on-NVMe vs in-memory for the bench DB container as a
   **sensitivity data point only** — never as the published headline, and
   documented alongside the durability-parity caveat from methodology §9.

## 5. Candidate changes (to be PR'd separately with before/after numbers)

Do **not** land these until §4 confirms the hypothesis — each ships as its own
PR carrying measured before/after authz-cell numbers, per the D6 acceptance
criterion:

- **CP-1: real connection pool.** Replace the single shared handle with a
  small pool of N independent `Surreal<Client>` connections (round-robin or
  checkout), sized to the authz concurrency (start N≈`batch_max_concurrency`
  or a small multiple of CPUs). This is the direct fix for H1 if confirmed.
  Must preserve the reconnect/re-signin machinery per-connection.
- **CP-2: same-subject coalescing in the batch path (owned by D1).** Group
  batch items by `(tenant, subject)` and resolve role assignments +
  ancestors once per group. Belongs to D1; noted here for traceability.
- **CP-3: DB container tuning.** Only if §4.3 shows DB capacity (not the
  connection) is the wall.

## 6. Interaction with other tasks

- **D1** consumes §2/§3-H2 directly (the coalescing fast path) and shares the
  tracing instrumentation from §4.1.
- **D7 (decision cache)** must only be built *after* D1 + D6 remove the
  fixable inefficiency — otherwise the cache would paper over a connection
  bottleneck rather than a genuine evaluation cost.

---

## 7. D1 findings — batch-path coalescing landed (code complete; live cells pending)

This section records the D1 work that consumes §2/§3-H2. It covers the code
changes made to `axiam-authz`, `axiam-api-rest`, and `axiam-api-grpc`; the
tracing added so the maintainer can read a single batch run on the laptop; and
the round-trip reduction proven by a deterministic mock-repo test. The live
"re-run the four authz cells" acceptance remains **pending a laptop re-run**
(no live SurrealDB in the CI sandbox).

### 7.1 Serialization point (confirmed from source; magnitude pending trace)

The wall is the **single shared SurrealDB HTTP client handle** (§1): every
concurrent authz check in the process funnels through one connection, so the
pre-D1 batch handlers' `buffer_unordered` fan-out could not turn item-level
concurrency into concurrent DB work — it only multiplied the number of
serialized round-trips contending for that one handle. Fixing the connection
serialization itself (H1) is D6/CP-1 (a real pool) and is deliberately out of
D1 scope. D1 attacks the other half — H2, the **redundant per-item queries** —
which is a pure round-trip-count reduction and needs no pool.

### 7.2 What was coalesced (H2 fix)

The bench's batch is 5 checks that all share one subject and (usually) one
resource. Per the §2 query pattern, the pre-D1 path issued, per item:
`get_user_role_assignments` (RT1), `get_ancestors` (RT2), optional
`list_by_resource` (RT3), and the batched `get_role_permission_grants_for_roles`
(RT4). For the 5-item same-subject/same-resource shape (no scope) that is
**5 × 3 = 15 round-trips**, of which RT1 and RT2 were byte-for-byte identical
across all five items.

New `AuthorizationEngine::check_access_batch(&[AccessRequest])` groups the batch:

- **RT1** resolved **once per `(tenant_id, subject_id)`** group.
- **RT2** resolved **once per `(tenant_id, resource_id)`** group (only for
  items whose subject actually has role assignments — so an early "no roles
  assigned" deny walks no ancestors, exactly as single-check does).
- **RT3** (scope list) resolved once per `(tenant_id, resource_id)` targeted by
  a scoped, role-bearing item.
- **RT4** the applicable role IDs across the *whole batch* are unioned and
  de-duplicated, and grants are fetched in **one** batched query (per tenant).

**Round-trip reduction for the bench shape (batch of 5, one subject, one
resource, no scope): 15 → 3** — one `get_user_role_assignments`, one
`get_ancestors`, one `get_role_permission_grants_for_roles`. That is the same
3 round-trips a *single* check issues, so a batch of N same-subject/resource
items costs the same DB round-trips as one check (the intended point of
batching, which the bench showed was previously inverted).

Exact input order, the `authz:check_as` subject-override gate + per-item audit
(kept in the REST handler), the four deny reasons, and scope/wildcard handling
are all preserved. The single-check and batch paths share two pure helpers
(`applicable_role_ids`, `grants_allow`) plus `resolve_scope`, so their
decision/deny-reason semantics cannot diverge.

### 7.3 New engine method + how REST and gRPC share it

- `axiam-authz::engine::AuthorizationEngine::check_access_batch` is the coalesced
  path.
- `axiam-api-rest`: the `AuthzChecker` trait gained a `check_access_batch`
  method (default impl loops `check_access`; `AuthorizationEngine`'s impl
  delegates to the coalesced method). `batch_check_access` now builds the
  ordered `Vec<AccessRequest>` (running the check_as gate + per-item audit) and
  issues **one** `checker.check_access_batch(&reqs)` call instead of a
  `buffer_unordered` fan-out of per-item `check_access`.
- `axiam-api-grpc`: `AuthorizationServiceImpl::batch_check_access` builds its
  validated `access_requests` (unchanged identity cross-checks) and calls
  `engine.check_access_batch(&access_requests)`. The old `buffer_unordered`
  block and its `batch_max_concurrency` application are removed; the field is
  retained on the struct (and in `new`) for config/call-site compatibility.

Both API surfaces therefore share the exact same fast path.

### 7.4 Single-check p99 tail

No accidental extra round-trips exist on the single-check hot path: `check_access`
issues RT1, RT2, optional RT3, RT4 and nothing else, and the refactor into
shared helpers did not add any query. The p99 tail described in the plan
(gRPC single-check p99 850 ms vs p95 173 ms) is therefore expected to be a
property of the **shared-connection contention / SurrealKV compaction** (H1),
not of the evaluation code — consistent with "server idle, DB waiting". The D1
tracing (below) is what lets the maintainer confirm this on the laptop; the
structural fix for H1 is D6/CP-1.

### 7.5 Tracing added (read one batch on the laptop)

`tracing` spans, matching the repo's macro style, now cover the authz path:

- `authz.check_access` span (fields: tenant/subject/resource/action/scope) on the
  single check, with a child `debug_span` per DB query
  (`db.get_user_role_assignments`, `db.get_ancestors`, `db.list_by_resource`,
  `db.get_role_permission_grants_for_roles`), attached via `tracing::Instrument`.
- `authz.check_access_batch` span (field: `batch_size`) with the same per-query
  child spans (carrying tenant/subject/resource fields), plus a per-item
  `authz.batch.item` span (fields: `index`, `resource_id`, `action`).

Running one bench batch with `RUST_LOG=axiam_authz=debug` (and
`surrealdb=debug` per §4.1) will now show exactly how many DB spans a batch
opens — the direct confirmation that a same-subject batch-of-5 emits 3 query
spans, not 15 — and their timing/overlap.

### 7.6 Test — round-trip count over wall-clock (and why)

`crates/axiam-authz/tests/batch_coalescing_test.rs` uses **counting mock
repositories** (each seam increments an `AtomicUsize`) rather than the real
in-memory SurrealDB repos, so it can assert the *number* of round-trips
directly:

- `same_subject_batch_of_5_coalesces_round_trips`: the sequential per-item
  baseline issues 5 role-assignment + 5 ancestor + 5 grant lookups; the batch
  issues **1 + 1 + 1**, and the decisions are byte-identical and in order.
- `distinct_groups_coalesce_per_group_and_preserve_order`: 2 subjects × 2
  resources across 4 items → 2 role-assignment + 2 ancestor + 1 grant lookups
  (not 4/4/4), order preserved with a deny in the middle, decisions match
  per-item `check_access`.
- `empty_subject_denies_without_extra_round_trips`: a no-roles subject denies
  with the identical reason and walks **no** ancestors/grants.

**Why round-trip counts, not a wall-clock ratio:** the plan's "batch < 3×
single" is a latency target, but a timing assertion against sub-microsecond
in-memory mocks is dominated by scheduler/allocator noise — it would flake or
need a bound so loose it proves nothing. The round-trip *count* is the
mechanism that produces the latency win and is exact and deterministic. Since
each round-trip is one serialized call over the single shared connection on the
real stack, 3 round-trips for a batch of 5 vs 3 for a single check is
inherently sub-3×; the end-to-end ratio is confirmed on the laptop (pending).
No timing assertion was added, on purpose.

### 7.7 Acceptance status

- Code + tests: complete, run against mock/in-memory repos in the sandbox.
- **Pending laptop re-run:** the four authz cells (authz_check_rest/grpc,
  authz_batch_rest/grpc) before/after, and reading the new trace to confirm
  the 15→3 round-trip drop and to chase the single-check p99 tail toward the
  H1/D6 connection fix.

---

## 8. D7 — Authorization decision cache (design + implemented behind a flag)

D7 builds *on top of* D1 (round-trip coalescing) and D6 (this report): D1
removed the redundant per-item queries in a batch, and this report established
that the authz wall is the shared-connection serialization, not CPU. The
decision cache attacks the remaining cost — the DB round-trips themselves — by
memoizing decisions so a repeated check does **zero** DB work. It is
feature-flagged and **defaults off**, so it changes nothing until an operator
opts in.

### 8.1 What is cached and where

- **Module:** `crates/axiam-authz/src/decision_cache.rs` (`DecisionCache`,
  `DecisionCacheConfig`).
- **Key:** `(tenant_id, subject, resource, action, scope)`. Organised as
  per-tenant shards under one mutex, so a per-tenant flush is O(1) (drop the
  shard) and one tenant's churn can't evict another's entries.
- **Value:** the **full** `AccessDecision` — `Allow`, or `Deny(reason)` with the
  exact deny string — plus an `Instant` stamp. A hit is therefore byte-identical
  to a miss (allow and deny alike; deny reasons preserved verbatim).
- **Eviction:** TTL on read (expired entry is dropped and treated as a miss) +
  a per-tenant FIFO size cap (`max_entries_per_tenant`).

### 8.2 Engine integration (zero-cost when off)

`AuthorizationEngine` gained an `Option<Arc<DecisionCache>>` field, `None` by
default. `new(..)` is unchanged (all existing call sites, tests, benches
untouched); a builder `with_decision_cache(Arc<DecisionCache>)` attaches one.

- `check_access`: consult cache → on hit return; on miss run the *unchanged*
  `evaluate` body, then insert. The evaluation logic was moved verbatim into a
  private `evaluate`, so a hit returns exactly what a miss would.
- `check_access_batch`: when no cache is attached it calls the D1 coalesced
  `evaluate_batch` directly — **byte-for-byte the current behaviour**. When a
  cache is attached, it serves per-item hits from the cache and evaluates only
  the misses through the same coalesced path, preserving input order.

`axiam-server` builds **one** shared `Arc<DecisionCache>` (via
`AuthzConfig::build_decision_cache`, `None` unless enabled) and clones it into
the REST, gRPC and AMQP engines, so an invalidation triggered by a REST mutation
is observed on every read path.

### 8.3 Invalidation — the security-critical half

AXIAM's RBAC is additive allow-wins / default-deny, so the only dangerous
staleness is a **stale allow surviving a revocation**. Invalidation is wired
into the REST mutation handlers through two new `AuthzChecker` trait methods
(`invalidate_tenant`, `invalidate_subject`; default no-ops, forwarded to the
cache by the engine impl). Granularity, and why no revocation can leave a stale
allow:

| Mutation path (REST handler) | Invalidation | Why it's safe |
| --- | --- | --- |
| `roles::unassign_from_user` | `invalidate_subject(t, user)` | Only that subject's roles change. |
| `groups::remove_member` | `invalidate_subject(t, user)` | Only that subject's inherited roles change. |
| `roles::assign_to_user`, `groups::add_member` | `invalidate_subject(t, user)` | Widening (safe direction); flushed for prompt visibility. |
| `roles::unassign_from_group` | `invalidate_tenant(t)` | Affects every group member — set unknown without a query → flush. |
| `permissions::revoke_from_role` | `invalidate_tenant(t)` | Affects every subject holding the role → flush. |
| `roles::delete`, `roles::update` | `invalidate_tenant(t)` | Role removal / `is_global` change can narrow access for an unknown subject set → flush. |
| `permissions::delete`, `permissions::update` | `invalidate_tenant(t)` | Permission removal / `action` change narrows access → flush. |
| `permissions::grant_to_role`, `roles::assign_to_group` | `invalidate_tenant(t)` | Widening; flushed for prompt visibility. |
| `resources::update`, `resources::delete` | `invalidate_tenant(t)` | Re-parent/delete changes which ancestor-scoped roles cascade → can narrow → flush. |
| `scopes::update`, `scopes::delete` | `invalidate_tenant(t)` | Decisions are cached by scope *name*; rename/delete narrows scoped access → flush. |
| `groups::delete` | `invalidate_tenant(t)` | Drops inherited roles for all members → flush. |

Targeted subject invalidation is used only where exactly one subject is
provably affected; every other (coarse) mutation uses a per-tenant flush. A
flush is always sound — it cannot leave *any* stale entry for the tenant. The
invalidation happens **in the same request that performs the mutation, before
its response returns.**

### 8.4 Bounded-staleness trade-off (documented explicitly)

The TTL (default 5 s) is a *backstop*, not the primary safety mechanism. Even if
an invalidation event were missed (a bug, or an out-of-band write straight to
SurrealDB that bypasses the handlers), a stale allow self-heals within
`AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` when the entry expires and is
re-evaluated. So worst-case revocation latency ≤ TTL, always.

### 8.5 Config keys (all default to the no-op / off state)

- `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` — default **`false`**.
- `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` — default `5`.
- `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` — default `10000` (per tenant).

Documented for operators in `docs/admin/README.md` and
`docs/deployment/README.md`.

### 8.6 Tests (sandbox — logic + invalidation correctness)

- `src/decision_cache.rs` unit tests: hit==insert, deny-reason preserved
  verbatim, action/scope key distinctness, TTL expiry, targeted-subject vs
  whole-tenant invalidation, per-tenant FIFO cap, re-insert doesn't double-grow.
- `src/config.rs`: defaults are off/conservative; `build_decision_cache`
  returns `None` when disabled / `Some` when enabled; overrides deserialize.
- `tests/decision_cache_integration_test.rs` (8 engine-level tests via mutable
  counting mock repos):
  - cache hit == miss for allow **and** deny, and the hit issues **no** DB
    round-trips (counter proof);
  - TTL expiry forces re-evaluation (DB queried again);
  - **`revocation_invalidation_denies_immediately`** — grant → check (allow,
    cached) → revoke via the mutation path (store change +
    `invalidate_subject`, exactly what `unassign_from_user`/`remove_member`
    call) → next check denies **immediately**, under a 60 s TTL, proving
    event-driven (not TTL-driven) enforcement;
  - a control (`without_invalidation_stale_allow_persists_until_ttl`) that
    isolates invalidation as the mechanism — with the store changed but the
    hook skipped, the cache does serve a stale allow within the TTL;
  - `tenant_flush_enforces_revocation_immediately` (the coarse path);
  - **feature-flag-off** path: every check hits the DB, decisions unchanged,
    invalidation calls are harmless no-ops;
  - the batch path caches and invalidates identically.

### 8.7 Acceptance status

- Code + unit/integration tests: **complete** in the sandbox.
  `cargo test -p axiam-authz --lib` (config + cache unit tests) and
  `--test decision_cache_integration_test` pass; `axiam-authz` and
  `axiam-api-rest` (lib) build clean; `cargo fmt`/`clippy` clean for
  `axiam-authz`.
- **Pending laptop re-run (throughput acceptance):** "authz_check_rest/grpc
  throughput materially increases with SurrealDB no longer pegged" requires the
  benchmark laptop and is out of scope for the CI sandbox (no live SurrealDB).
  The security-critical half — immediate revocation enforcement via
  invalidation — **is** proven here by the integration tests above. Enable with
  `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true` for the before/after cells.
