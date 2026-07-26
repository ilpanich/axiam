# Decision note — should the authorization decision cache (D7) default to ON?

**Task:** G5 of [`improvement-after-serious-benchmark.md`](improvement-after-serious-benchmark.md)
**Status: OPEN — blocked on measurement.** No default is being changed by this note.
**Scope of the flag:** `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` (today `false`),
`AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (`5`),
`AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` (`10000`, per tenant).

This note states the security argument, defines exactly what the K-sweep must
show for the default to flip, and leaves a table to fill in with measured
numbers. It deliberately does **not** pre-commit to a decision: the only
throughput evidence that exists today (run 3) was collected at the single most
favourable cache-key cardinality that can exist, and flipping a
security-relevant default on that evidence would be unjustified.

---

## 1. What the cache actually is

Source of truth read for this note (not the design doc):

| Fact | Where |
|---|---|
| Cache key is `(tenant_id, subject_id, resource_id, action, scope)` | `crates/axiam-authz/src/decision_cache.rs` — `SubKey` + per-tenant shard map |
| The **full** decision is cached — `Allow` *and* `Deny(reason)` verbatim | `crates/axiam-authz/src/engine.rs::check_access`, `cache.insert(request, decision.clone())` |
| A hit skips the whole `evaluate()` (3–4 sequential SurrealDB round-trips) | `engine.rs::check_access` early return |
| TTL is checked on read; expired entries are evicted in passing | `decision_cache.rs::get` |
| Size cap is **per tenant**, FIFO, enforced only on insert of a *new* key | `decision_cache.rs::insert` |
| The whole cache sits behind **one** `Mutex<HashMap<Uuid, TenantShard>>` | `decision_cache.rs` — `shards` |
| Attached only when the flag is on; otherwise the code path is byte-identical to a build without the cache | `crates/axiam-server/src/main.rs` ~L734–947, `AuthzConfig::build_decision_cache` |

A hit is indistinguishable from a miss to the caller: same decision, same deny
reason string. There is no "cached" marker in the response.

## 2. The security argument

### 2.1 Why a cache is defensible here at all

AXIAM's RBAC is additive, allow-wins, default-deny (CLAUDE.md / SEC-040). The
two staleness directions are therefore **not** symmetric:

- A **stale deny** is safe. The subject is momentarily under-privileged. Cost is
  a redundant re-evaluation, never an authorization bypass.
- A **stale allow after a revocation** is the entire risk. It is a subject
  retaining access they no longer have.

So only one direction needs defending, and it is defended in two layers.

### 2.2 Layer 1 — event-driven invalidation on access-narrowing mutations

Every REST mutation that can narrow access calls `invalidate_subject` (targeted)
or `invalidate_tenant` (conservative flush) through the `AuthzChecker` trait
before returning. Verified call sites:

| Handler file | Invalidation |
|---|---|
| `handlers/roles.rs` (role update/delete, role↔permission grant/revoke) | `invalidate_tenant` |
| `handlers/roles.rs` (user role assign/unassign) | `invalidate_subject` |
| `handlers/groups.rs` (group role assign/unassign) | `invalidate_tenant` |
| `handlers/groups.rs` (member add/remove) | `invalidate_subject` |
| `handlers/permissions.rs` (permission create/update/delete, grant changes) | `invalidate_tenant` |
| `handlers/resources.rs` (resource update — incl. reparent — and delete) | `invalidate_tenant` |
| `handlers/scopes.rs` (scope create/delete) | `invalidate_tenant` |

Coverage looks complete for the mutation surface. This is the layer that makes
revocation *immediate* rather than TTL-bounded.

### 2.3 Layer 2 — bounded staleness ≤ TTL

If an invalidation is ever missed — a new mutation path that forgets the hook, an
out-of-band write straight to SurrealDB, an `AuthzChecker` implementation that
takes the trait's default no-op — the damage is bounded: `get()` treats an entry
older than `ttl` as a miss, so a stale allow cannot outlive the revocation by
more than `decision_cache_ttl_secs` (default **5 s**). Within a single process
this bound is unconditional; it does not depend on any hook firing.

### 2.4 What the operator actually loses if an invalidation event is dropped

Concretely, for up to 5 seconds after the revocation:

- The revoked subject continues to receive `allowed: true` for the exact
  `(subject, resource, action, scope)` tuples already in cache — and only those.
  A tuple never evaluated before the revocation is a miss and evaluates fresh.
- It applies to **every** read path uniformly (REST `/authz/check`, gRPC
  `CheckAccess`, AMQP async authz, and the internal `RequirePermission` guard on
  every admin endpoint), because `main.rs` shares one `Arc<DecisionCache>` across
  all engines. A dropped invalidation therefore also delays revoking an
  *administrator's* own privileges for up to the TTL.
- There is no audit signal distinguishing a stale allow from a fresh one. The
  audit log records the decision, not its provenance. Post-incident, an operator
  cannot tell from the logs whether a given allow was served from cache.

That last point is the one worth weighing: the failure is silent and
unobservable, even though it is short.

### 2.5 Three findings that count against ON, discovered while reading the code

These are code observations from this task, not measurements. All are in
`crates/`, which G5's implementation half does not own; they need their own
issues.

**(a) `TenantShard.order` grows without bound when the working set is smaller
than the cap — a slow memory leak in the *default* configuration.**
`order` is pushed on every insert of a key not currently in `entries`, and popped
**only** inside `if is_new { while entries.len() > max_entries_per_tenant { … } }`.
When a key TTL-expires, `get()` removes it from `entries` but leaves its `SubKey`
in `order`; the next access re-inserts it as `is_new`, pushing a *second* copy.
With a working set below `max_entries_per_tenant` (10 000 by default — i.e. the
normal case) `entries.len()` never exceeds the cap, the `while` never runs, and
`order` is append-only. Growth rate equals the **miss rate**: ~20 entries/s at
the modelled K=100 point, ~1 000/s for a busy tenant, at roughly 100 bytes per
`SubKey`. A tenant that receives access-narrowing mutations self-heals
(`invalidate_tenant` drops the whole shard); a quiet-but-busy tenant does not.
The existing test `reinsert_same_key_does_not_grow_or_double_count_fifo` only
covers re-insert of a *live* key (`is_new == false`), so this path is untested.
**The K=10000 memory column in the sweep will not reveal this** — at K > cap the
`while` loop runs and drains stragglers. It is the K=100 cell, run long, that
would show it.

**(b) The cache is process-local; there is no cross-replica invalidation.**
`main.rs` builds one in-process `Arc<DecisionCache>`. No AMQP/webhook broadcast
of invalidation events exists (`grep invalidate crates/axiam-amqp/src` → nothing).
In the multi-replica Kubernetes deployment AXIAM targets, a revocation handled by
replica A invalidates only replica A. Replicas B…N keep serving the stale allow
until TTL. **So §2.2's "immediate" is a single-process property, and any
horizontally scaled deployment gets §2.3's ≤ 5 s bound as its *actual* revocation
latency, not its worst case.** If the default flips, this must be stated next to
the default, not in a footnote — an operator running 3 replicas would otherwise
reasonably believe revocation is immediate.

**(c) `invalidate_subject` is O(shard) under the global lock.** It does
`entries.retain(…)` over the whole tenant shard — up to 10 000 entries — while
holding the single mutex that every authz check needs. Every role unassignment
therefore stalls all authz evaluation briefly. Small, but it grows with
`DECISION_CACHE_MAX_ENTRIES`, which is exactly the knob the K=10000 memory
measurement is meant to inform.

## 3. Why run 3's 3× cannot decide this

Run 3 measured (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §4/§6):

| Op | cache OFF | cache ON | ratio |
|---|---|---|---|
| `authz_check_rest` p0 | 737 ops/s | 2322 ops/s | 3.15× |
| `authz_check_grpc` p0 | 603 ops/s | 1822 ops/s | 3.02× |

Every one of the 50 VUs sent the **same** `(subject, resource, action, scope)`
tuple for the whole cell. Effective cardinality K = 1, steady-state hit rate
≈ 100%. That is the upper bound of the cache's value, not an estimate of it.

### 3.1 What the hit rate should do as K grows (model, not data)

Entries are stamped at **insert** and inserts happen only on a miss — a hit does
not refresh the timestamp (`decision_cache.rs::get` returns without touching
`inserted_at`). So each key runs a fixed cycle: one miss, then every access for
the next `T` seconds is a hit. With K keys drawn uniformly at rate R:

> **h = R·T / (K + R·T)**  and  **R = 1 / ( h·c_hit + (1−h)·c_miss )**

with `c_miss = 1/737 s`, `c_hit = 1/2322 s` from run 3 and `T = 5 s`. Solving the
fixed point:

| K | modelled hit rate | modelled thr | modelled ratio |
|---|---|---|---|
| 1 | ~100% | 2322 | 3.15× (= measured run 3) |
| 100 | ~99% | ~2280 | ~3.1× |
| 10 000 | ~33% | ~945 | ~1.28× |

**This table is a prediction to be falsified, not evidence.** Two reasons it may
be optimistic: (i) the miss path takes the global mutex **twice** (`get` then
`insert`) versus once for a hit, so at a low hit rate the single
`Mutex<HashMap<…>>` becomes a serialization point that run 3 never exercised —
the measured K=10000 ratio could land **below 1.0×**, i.e. a net regression;
(ii) at K = 10 000 the per-tenant cap is exactly reached, so FIFO eviction runs
on the insert path and the live set is slightly smaller than K, pushing the hit
rate below the modelled 33%.

## 4. Measurement — what the laptop must run

### 4.1 The K-sweep (throughput + memory)

```bash
cd benchmarks
./run-improvement-tasks.sh g5-cache-sweep
```

Defaults are already correct: `G5_SCENARIO=authz_check_rest.js`,
`G5_KEYSPACES="1 100 10000"`, cache OFF then ON, one warm-up cell per stack.
Output: `benchmarks/results/tasks/g5-cache-sweep/SUMMARY.md`.

The scenario knob (implemented in this task):

- **`BENCH_AUTHZ_KEYSPACE=K`** — each request picks 1 of K distinct cache keys.
  `K=1` is the default and reproduces run 3 byte-for-byte (no provisioning, same
  request body), so the sweep's first point is directly comparable.
- **`BENCH_AUTHZ_KEYSPACE_MODE=resource`** (default) — `setup()` provisions K−1
  **child resources** of the seeded `bench-resource` through the admin REST API
  and varies `resource_id`. Children inherit the seeded `bench-reader`
  assignment via hierarchy (`engine.rs::applicable_role_ids` accepts an
  assignment scoped to any ancestor), so **every key yields a real `Allow`** on
  the same 3-round-trip evaluation path as K=1.
- **`BENCH_AUTHZ_KEYSPACE_MODE=action`** — zero-provisioning fallback that keeps
  the seeded resource and varies the `action` string. Index 0 is literally
  `read` (`Allow`); every other index is an action no grant covers, so the engine
  runs the **full** assignments → ancestors → grants path and returns
  `Deny("no permission grants action '…'")`. Denies are cached verbatim, so the
  cache is exercised identically. Useful as a control: it varies *only* key
  cardinality, with zero change in DB row diversity.

Neither mode ever hits an error path — `setup()` probes the last key before the
measured window and aborts the cell if the response is not a 200 carrying the
expected decision.

Worth also running, off the critical path, to test finding (a): one long
`K=100`, cache-ON cell (≥ 30 min) watching server RSS. The model says
`order` should grow ~20 entries/s ≈ 2 KB/s there while `entries` stays flat at
100. The standard 20 s cells are far too short to see it.

### 4.2 The safety re-verification

The existing test is:

```bash
cargo test -p axiam-authz --test decision_cache_integration_test
```

`crates/axiam-authz/tests/decision_cache_integration_test.rs`, specifically:

| Test fn | Property |
|---|---|
| `revocation_invalidation_denies_immediately` | revocation enforced immediately via the invalidation hook, not after TTL |
| `without_invalidation_stale_allow_persists_until_ttl` | the control: worst-case stale allow is bounded by TTL when the event is suppressed |
| `tenant_flush_enforces_revocation_immediately` | coarse `invalidate_tenant` path |
| `cache_hit_matches_miss_allow_and_skips_db` / `…_deny_with_reason` | a hit is byte-identical to a miss, and skips the DB |
| `cache_disabled_behaves_exactly_as_today` | flag-off is a no-op |

**Gap to record against plan G5 step 2.** That step says to run "the existing
integration test … against the bench stack". It cannot be done as written: this
suite drives the engine with **mutable counting mock repositories**, not a live
server or database. It proves the *engine's* invalidation contract; it proves
nothing about whether the REST mutation handlers reach it over the wire, and it
cannot see finding (b) at all. Until a real end-to-end test exists, the live-stack
check has to be manual against the running bench stack (cache ON):

1. `just target=axiam bench-up && just target=axiam bench-seed`, with
   `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`.
2. As `benchuser`: `POST /api/v1/authz/check` with the seeded resource → expect
   `allowed: true`. Repeat once to guarantee the entry is cached.
3. As admin: `DELETE /api/v1/roles/{bench-reader}/users/{benchuser}` (the
   `invalidate_subject` path).
4. Immediately (< 1 s) re-issue step 2 → **must** be `allowed: false`. An
   `allowed: true` here means the invalidation hook did not fire end-to-end.
5. Control for the ≤ TTL bound: restore the assignment, re-warm the entry, then
   revoke by a path that only flushes coarsely and confirm the deny appears
   within 5 s regardless.

A follow-up issue should be opened for a REST-level integration test covering
steps 2–4, and one for a multi-replica variant covering finding (b).

## 5. Decision criteria — agreed **before** the numbers arrive

The default flips to `true` only if **all** of these hold:

| # | Criterion | Rationale |
|---|---|---|
| C1 | Cache-ON/OFF throughput ratio **at K = 10 000** is ≥ **1.5×** | The ship-decision must rest on the worst realistic key space, not the best. Below this the win does not pay for silent, unobservable staleness. |
| C2 | The ratio at K = 10 000 is **> 1.0× with margin** — no regression from lock contention | If the cache can make the server *slower* under a realistic key space, ON-by-default is indefensible at any hit rate. |
| C3 | Server RSS at K = 10 000, cache ON, is within **+150 MiB** of cache OFF | Bounds `DECISION_CACHE_MAX_ENTRIES` guidance and keeps the D9 retention work interpretable. |
| C4 | `p95` at every K is **no worse** than cache OFF | A cache that improves the mean while lengthening the tail (lock convoy) is a bad trade for an authz hot path. |
| C5 | The `order`-growth leak (finding **a**) is **fixed and regression-tested** | Shipping a default-ON unbounded allocator in the authorization path is not acceptable regardless of the throughput win. |
| C6 | The multi-replica staleness caveat (finding **b**) is documented **next to the default** in the config docstring, the deployment guide, `PUBLIC_BENCH_ANALYSIS.md` §6 and the security docs | Per plan G5 step 3: not a footnote. |
| C7 | The live-stack revocation check in §4.2 passes | Layer 1 must be shown to work over the wire, not only against mocks. |

If C1 or C2 fails: **default stays `false`**, and the public doc's "3.0–3.15×"
must be relabelled as a best-case, K=1, small-key-space figure — the wording
change is required either way, since the current text does not say what key space
produced it.

If C1/C2 pass but C5 fails: default stays `false` **pending the leak fix**, then
re-evaluate — do not ship the flip and the fix as one change.

## 6. Results table — TO BE FILLED FROM THE LAPTOP RUN

Paste from `benchmarks/results/tasks/g5-cache-sweep/SUMMARY.md`. Do not
interpolate or estimate any cell.

| cache | K | thr (ops/s) | p50 (ms) | p95 (ms) | server mem (MiB) | ratio vs OFF at same K |
|---|---|---|---|---|---|---|
| false | 1 | | | | | — |
| false | 100 | | | | | — |
| false | 10000 | | | | | — |
| true | 1 | | | | | |
| true | 100 | | | | | |
| true | 10000 | | | | | |

Long-soak cell for finding (a):

| cell | duration | entries (K) | server RSS start | RSS end | ΔRSS/hour |
|---|---|---|---|---|---|
| cache ON, K=100 | | 100 | | | |

Criteria check:

| Criterion | Threshold | Measured | Pass? |
|---|---|---|---|
| C1 ratio @ K=10000 | ≥ 1.5× | | |
| C2 no regression @ K=10000 | > 1.0× | | |
| C3 ΔRSS @ K=10000 | ≤ +150 MiB | | |
| C4 p95 @ every K | ≤ cache-OFF p95 | | |
| C5 `order` leak fixed | issue closed | | |
| C6 docs updated in 4 places | yes/no | | |
| C7 live-stack revocation | pass | | |

**DECISION: _open_.** Fill §6, then record the outcome here with a one-line
rationale and, if the default flips, the four doc locations updated.

## 7. If the decision is to keep it opt-in

That is a legitimate outcome, not a failure. The cache would remain a documented
tuning knob for deployments that (i) run a single replica or accept ≤ TTL
cross-replica staleness, (ii) have a measured hot key space small relative to
their request rate, and (iii) have read the staleness statement. In that case
the deliverables are: the relabelled public-doc figure, a "when to enable the
decision cache" section in the deployment guide carrying the K-sweep table
verbatim, and issues for findings (a), (b), (c).
