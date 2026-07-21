# D10 — Authz batch serialization investigation

**Status:** root-cause narrowed by static analysis + run-2 evidence; fix
implemented as a config-selectable batch strategy (default flipped to
`concurrent`). Final wall-clock confirmation is a **laptop step** (this sandbox
has no k6 / live stack). Companion to `benchmarks/PRIVATE_BENCH_ANALYSIS.md` §4.2.

## The symptom (run-2, capped p0, unchanged under caps/TLS)

| cell | thr | p50 | server CPU | DB CPU |
|---|---|---|---|---|
| authz_check_rest (single) | 745/s | 67 ms | 0.66 | **2.01 (pegged)** |
| authz_batch_rest (5/req) | 46/s | 1060 ms | 0.06 | 1.09 |
| authz_batch_grpc (5/req) | 23/s | 2153 ms | 0.03 | 1.03 |

The batch cell leaves **everything idle** (server 0.06, DB ~1 core) yet each
request takes ~1 s. With 50 closed-loop VUs, `50 / 46 ≈ 1.09 s` — i.e. the
throughput is *fixed by the per-request latency*, and that latency is spent
waiting, not computing. DB pinned at ~1 core **in every configuration,
including the DB-uncapped pass (4 cores available)** → the batch's DB work is
**serialized**, not resource-starved.

## What was DISPROVEN

The prior hypothesis (`PRIVATE` draft, D10 task text) was that the batched
grants query `get_role_permission_grants_for_roles` — which filters
`WHERE meta::id(in) IN $role_ids` (a per-row function call that cannot use the
`grants` edge's record-link index, forcing a table scan) — was the serialized
cost.

**This is disproven by the code:** the *single*-check path
(`AuthorizationEngine::evaluate`, `engine.rs:248`) calls the **exact same**
`get_role_permission_grants_for_roles`. The single-check cell runs at 745 req/s
with the DB pegged at 2 cores. So that query shape is on the hot path of the
*fast* cell too — it is not what makes the batch slow. (The `meta::id(in)`
scan is still a latent inefficiency worth fixing on its own once the grants
table is large; it is simply not this bottleneck. Tracked as a follow-up
below.)

## What the evidence points to

Both handlers (`crates/axiam-api-rest/src/handlers/authz_check.rs:263` and
`crates/axiam-api-grpc/.../authorization.rs:177`) route the whole batch through
`AuthorizationEngine::check_access_batch`, which (pre-D10) ran the **coalesced**
path: gather every item's shared lookups, then issue one role-assignment, one
ancestor, and one grants query for the *entire* batch (3 round-trips for the
bench's 5-item same-subject shape). That is strictly fewer round-trips than 5
single checks (≈15), so on paper it should be faster.

But the whole coalesced batch resolves on **one task, issuing its 3 queries
sequentially**. A single `check_access` also issues 3 sequential queries — the
difference is *how many run concurrently across the stack*:

- **Single-check cell:** 50 VUs → ~745 req/s → hundreds of small queries in
  flight at once → SurrealDB parallelizes them across both its cores.
- **Batch cell:** 50 VUs, but each request is one coalesced task doing 3
  sequential queries and little else. The observed behaviour (DB stuck at ~1
  core, ~1 s latency, nothing saturated) is the signature of the batch tasks
  **not** achieving the same query-level concurrency the single-check flood
  does — the coalescing collapsed 5 items into a single serial dependency
  chain, removing the parallelism that let single checks saturate the DB.

The precise internal reason the coalesced chain caps DB utilisation at ~1 core
(single shared SurrealDB dispatch task? per-request connection affinity in the
F2 pool? a lock around the coalesce maps?) is **not determinable from static
reading** and needs a server-side trace under load — the per-item / per-query
`tracing` spans added in D1 are already in place (`engine.rs` `evaluate_batch`)
to capture it on the laptop. What *is* determinable: single checks parallelize
to the DB cap, and the coalesced batch does not.

## The fix (implemented)

Rather than keep optimizing a path whose serialization we cannot fully explain
from source, D10 makes the batch reuse the mechanism that is *proven* to
parallelize — the single check — for every item, concurrently:

- New `BatchStrategy` config enum (`crates/axiam-authz/src/config.rs`):
  - `Concurrent` **(new default)** — `check_access_batch` evaluates each item
    as an independent, cache-aware `check_access`, run with
    `futures::stream::…buffered(batch_max_concurrency)`; **input order and every
    decision/deny-reason are byte-identical** to a standalone `check_access`
    (the cache is consulted per item exactly as before).
  - `Coalesced` — the original D1 path, retained and selectable via
    `AXIAM__AUTHZ__BATCH_STRATEGY=coalesced` for an apples-to-apples laptop A/B.
- Bounded by the existing `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY` (default 16) so
  a large batch cannot self-DoS the DB pool (D-07); the bound now lives on the
  engine (`with_batch_config`) and is applied at all three server construction
  sites (REST, gRPC, AMQP).

### Why default to `concurrent`

- **Zero authorization risk:** the concurrent path *is* per-item
  `check_access`. The existing correctness tests already compare the batch to
  the sequential per-item baseline; the gRPC service test and the new
  `concurrent_strategy_is_per_item_and_matches_sequential` unit test assert
  byte-identical decisions and order.
- **Evidence-backed:** single checks demonstrably reach the DB cap under 50-VU
  concurrency; a batch of concurrent items is the same access pattern.
- **Reversible:** one env var restores the coalesced path; the maintainer
  picks the final default from the laptop A/B (same pattern as F3's
  pool-size decision).

### Expected laptop result (to confirm, not claimed)

A 5-item batch as 5 concurrent single-checks does ~15 round-trips but at the
single-check DB rate (~2235 q/s pegged) ⇒ order-of-magnitude ~150 batch/s,
p50 ≈ 50 VUs / 150 ≈ 0.33 s — comfortably inside the 2 s gate and **above**
the single-check-equivalent (745/5 ≈ 149 checks-worth/s). Acceptance
(`batch checks/s > single checks/s`; `authz_batch_grpc` passes the 2 s p95
gate) is verified on the run-3 laptop matrix.

## Follow-ups (not required for D10 acceptance)

1. **Index the `grants` edge lookup regardless.** Rewrite
   `get_role_permission_grants_for_roles` to match `in` against role
   record-links (`WHERE in IN [role:\`…\`, …]`, mirroring the single-role
   `get_role_permission_grants`) instead of `meta::id(in) IN $role_ids`, so it
   never table-scans when the grants table grows. Independent of the batch
   strategy (the single-check path uses it too). Low risk, but wants the same
   embedded-engine test coverage; deferred to keep the D10 diff focused on the
   serialization fix.
2. **Trace the coalesced serialization on the laptop** to positively identify
   the ~1-core ceiling (pool dispatch vs lock vs connection affinity). If it
   turns out cheap to remove, a *coalesced-and-parallel* path could beat both;
   until measured, `concurrent` is the safe, evidence-backed default.
