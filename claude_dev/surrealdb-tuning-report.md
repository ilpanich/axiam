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

*Prepared from static analysis of `axiam-db` and `axiam-authz` at branch
`claude/benchmark-improvement-plan-9yxx7g`. Runtime sections to be completed
after the laptop re-run with D1 tracing in place.*
