# Decision note — should the authorization decision cache (D7) default to ON?

**Task:** G5 of [`improvement-after-serious-benchmark.md`](improvement-after-serious-benchmark.md),
completed by **H5** of [`improvement-after-g-benchmark.md`](improvement-after-g-benchmark.md)
**Status: DECIDED — the default stays `false` (opt-in).** See §8.
**Scope of the flag:** `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` (today `false`),
`AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (`5`),
`AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` (`10000`, per tenant).

This note states the security argument, defines exactly what the K-sweep must
show for the default to flip, and records the measured numbers. It deliberately
did **not** pre-commit to a decision: the only throughput evidence that existed
when §1–§5 were written (run 3) was collected at the single most favourable
cache-key cardinality that can exist, and flipping a security-relevant default
on that evidence would have been unjustified.

> **Reading order.** §1–§5 are the pre-measurement analysis and the criteria,
> agreed **before** any number arrived — unchanged except where a finding is now
> marked FIXED. §6 records what H5 measured and what this host could not
> measure. §7 walks the criteria. §8 is the verdict.

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
| ~~The whole cache sits behind **one** `Mutex<HashMap<Uuid, TenantShard>>`~~ **(fixed in H5 — now striped over 16 mutexes by tenant)** | `decision_cache.rs` — `stripes` |
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
revocation *immediate* — **within one process**; see finding (b) and §6.3.
**H5 verified this end to end on a live stack, not only against mocks** (§6.3).

### 2.3 Layer 2 — bounded staleness ≤ TTL

If an invalidation is ever missed — a new mutation path that forgets the hook, an
out-of-band write straight to SurrealDB, an `AuthzChecker` implementation that
takes the trait's default no-op — the damage is bounded: `get()` treats an entry
older than `ttl` as a miss, so a stale allow cannot outlive the revocation by
more than `decision_cache_ttl_secs` (default **5 s**). Within a single process
this bound is unconditional; it does not depend on any hook firing.
**H5 measured this bound on a live stack: 5 037–5 053 ms** (§6.3).

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

These were code observations, not measurements. **All three are now fixed or
documented — commit `e01061d` (H5 item 1).** The original text is kept because
the criteria in §5 refer to it.

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

> **FIXED (`e01061d`).** Entries carry a monotonic per-tenant `seq` and queue
> slots carry the `seq` they were pushed for, so a superseded slot is
> recognisable; `compact_if_needed()` rebuilds the queue (and reaps expired
> entries) once it exceeds `max(2 × live entries, 64)`. Amortised O(1); bounds
> the queue at ~2× the live set. Two regression tests cover it —
> `expired_then_reaccessed_key_does_not_grow_the_fifo_queue` (the exact reported
> path) and `churn_behind_a_pinned_front_entry_stays_bounded` (the same leak
> behind a long-lived front entry, which defeats any front-only cleanup).
> **Both were confirmed to fail against the pre-fix behaviour: 200
> expire/re-access cycles left exactly 200 queue slots, one per cycle.** The
> long K=100 soak proposed in §4.1 is therefore *superseded* — the leak is now
> demonstrated deterministically in 0.2 s instead of inferred from a 30-minute
> RSS trend, and the soak could only re-confirm it on a pre-fix image.

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

> **DOCUMENTED (`e01061d`) in all four required locations** — the
> `decision_cache` module docs, the `AuthzConfig` docstrings, the admin guide
> (new "The cache is process-local" subsection, plus the previously absolute
> "no revocation leaves a stale allow" claim corrected), and the deployment
> guide (call-out box naming the `k8s/` manifests). The server also emits the
> caveat on the very log line that announces the cache is enabled, and the
> public analysis carries it too. Still **not** fixed as a *behaviour* — there
> is no cross-replica invalidation channel, and building one is out of scope
> here; it is a precondition for any future flip on a scaled deployment.

**(c) `invalidate_subject` is O(shard) under the global lock.** It does
`entries.retain(…)` over the whole tenant shard — up to 10 000 entries — while
holding the single mutex that every authz check needs. Every role unassignment
therefore stalls all authz evaluation briefly. Small, but it grows with
`DECISION_CACHE_MAX_ENTRIES`, which is exactly the knob the K=10000 memory
measurement is meant to inform.

> **FIXED (`e01061d`), two parts.** A per-tenant `by_subject` index
> (`subject_id → its keys`) makes the operation proportional to *that subject's*
> entries instead of the shard; the index shares its keys with `entries` through
> `Arc<SubKey>`, so it costs one pointer per entry rather than a second copy of
> the key (it also removes the `SubKey` clone the FIFO queue used to hold — the
> fix is close to memory-neutral). Separately the tenant map is now striped over
> 16 independent mutexes keyed by `tenant_id`, so one tenant's invalidation or
> eviction no longer blocks every other tenant's checks. A tenant's shard stays
> wholly inside one stripe, which keeps the per-tenant FIFO cap exact.
> **Intra-tenant contention is unchanged** and is documented in the module docs
> as the honest remaining limit of the design.

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

> **Post-hoc (H5).** The model's *shape* has now been corroborated from two
> independent hosts: the G run measured **+32%** at K=10 000 against the
> modelled +28%, and this host measured a small **regression** at K=10 000
> (§6.2) — the direction reason (i) predicted. Nothing on any host has measured
> the ≥1.5× that criterion C1 requires at K=10 000.

## 4. Measurement — what was run

### 4.1 The K-sweep (throughput + memory)

```bash
cd benchmarks
G5_PROFILE=p2-tls13 BENCH_SETTLE_TIMEOUT_SECS=60 ./run-improvement-tasks.sh g5-cache-sweep
```

Defaults are already correct: `G5_SCENARIO=authz_check_rest.js`,
`G5_KEYSPACES="1 100 10000"`, cache OFF then ON, one warm-up cell per stack.
Output: `benchmarks/results/tasks/g5-cache-sweep/SUMMARY.md`.

Two harness bugs had to be fixed before the sweep could produce a single valid
cell (both in `b27da91`):

- the task hardcoded **p0-plaintext**, where k6's cookie jar refuses to replay
  the `Secure` session cookies over `http://` and every cell of this scenario
  dies in `setup()` (`postseed-transient-investigation.md` §8.3) — it now takes
  `G5_PROFILE`, defaulting to **p2-tls13**;
- the profile was passed to the *cells* but not to `bench_up_seed`, so the stack
  came up as p0 while the cells dialled `:8443` — one refused connection per
  cell and a silently empty result file. That is exactly what the first attempt
  produced, and it is only visible if you open the `.k6.json` (`http_reqs: 1`).

The scenario knob (implemented in task G5):

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
  cache is exercised identically.

Neither mode ever hits an error path — `setup()` probes the last key before the
measured window and aborts the cell if the response is not a 200 carrying the
expected decision.

### 4.2 The safety re-verification

```bash
cargo test -p axiam-authz --test decision_cache_integration_test   # 9 passed
cargo test -p axiam-authz --lib                                    # 39 passed
```

`crates/axiam-authz/tests/decision_cache_integration_test.rs`, specifically:

| Test fn | Property |
|---|---|
| `revocation_invalidation_denies_immediately` | revocation enforced immediately via the invalidation hook, not after TTL |
| `without_invalidation_stale_allow_persists_until_ttl` | the control: worst-case stale allow is bounded by TTL when the event is suppressed |
| `tenant_flush_enforces_revocation_immediately` | coarse `invalidate_tenant` path |
| `cache_hit_matches_miss_allow_and_skips_db` / `…_deny_with_reason` | a hit is byte-identical to a miss, and skips the DB |
| `cache_disabled_behaves_exactly_as_today` | flag-off is a no-op |

**Gap recorded against plan G5 step 2 — now closed.** That step said to run "the
existing integration test … against the bench stack". It could not be done as
written: this suite drives the engine with **mutable counting mock
repositories**, not a live server or database. It proves the *engine's*
invalidation contract; it proves nothing about whether the REST mutation
handlers reach it over the wire. H5 therefore automated the note's manual curl
procedure as **`benchmarks/runner/h5-revocation-check.sh`** (`b27da91`), which
runs both halves against a live stack and is re-runnable. Results in §6.3.

A follow-up issue is still worth opening for a **multi-replica** variant
covering finding (b) — the one thing neither the mock suite nor the live script
can see with a single server process.

### 4.3 What this host can and cannot measure (read before §6)

`claude_dev/postseed-transient-investigation.md` (H2, commit `35173cc`) proved
that on this machine every authz/token endpoint is clamped to **~20 ops/s** by a
synchronous ~40–50 ms SurrealDB write of a shared rate-limit counter that runs
**before** the handler. Consequences for this note, all of them load-bearing:

1. The clamp is **upstream of and outside** the decision cache. The cache can
   only remove the 3–4 evaluation round-trips *behind* it, worth a few ms against
   a ~40–50 ms serialized pre-check that it cannot touch.
2. The G-box levels (737 → 2322 ops/s) are unreachable here **by construction**.
   Any cache-ON/OFF ratio measured on this host is damped toward 1.0×, so a
   ratio near 1.0 is evidence about *the host*, not about the cache.
3. The H1 settle gate can never pass on `authz_check`, so **every cell below
   carries `settle_timeout: true` and is REFUSED by `runner/report.py`**
   (H1.5 — `collect_dir()`/`aggregate_cell()` exclude such cells from `valid`).
   The cells are reported here as *ratios with the clamp documented*, exactly as
   H2 §8.2 item 3 prescribes, and they are **not** eligible to satisfy C1/C2/C4.
4. The live server is the pinned published image `1.0.0-alpha19`, which predates
   the H5 fixes. The sweep therefore measures the **pre-fix** cache. That does
   not affect hit/miss semantics (the fixes change bookkeeping, not what hits),
   but it does mean the new `AuthZ decision cache stats (D7)` log line — the
   direct entry-count observation — does not exist in the running binary. See
   §6.4 for how the entry count was established instead.

## 5. Decision criteria — agreed **before** the numbers arrived

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

## 6. Results

### 6.1 The K-sweep, as measured (2026-07-28/29, H5)

Stack: `ghcr.io/ilpanich/axiam/server:1.0.0-alpha19` + `surrealdb/surrealdb:v3`
(3.2.3), server and datastore each capped at 2 CPU / 1 GiB, rate limits
`neutralized`, profile **p2-tls13**, 50 VUs, 30 s warm-up + 120 s measured,
one warm-up cell per stack, stack torn down and re-seeded between the OFF and ON
passes. **Every cell carries `settle_timeout: true`** (§4.3 item 3).

| cache | K | thr (ops/s) | ops | avg (ms) | p50 (ms) | p95 (ms) | p99 (ms) | server mem (MiB) | db mem (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| false | 1 | 20.01 | 3205 | 2189 | 2349 | 3002 | 3333 | 109 | 57 |
| false | 100 | 19.62 | 3160 | 2223 | 2383 | 3082 | 3380 | 110 | 69 |
| false | 10000 | 14.72 † | 3298 | 2127 | 2271 | 2949 | 3262 | 110 | 95 |
| true | 1 | 20.32 | 3255 | 2157 | 2353 | 3075 | 3880 | 109 | 58 |
| true | 100 | 20.87 | 3356 | 2091 | 1702 | 3645 | 3922 | 110 | 70 |
| true | 100 ‡ | 19.72 | 3173 | 2210 | 1890 | 3730 | 4000 | 71 | 57 |
| true | 10000 ‡ | 14.37 † | 3016 | 2320 | 2510 | 3230 | 3590 | 73 | 88 |

† **The K=10 000 ops/s figures are deflated and not comparable to the other
rows**: `setup()` provisions 9 999 child resources over REST *inside* the k6 run
window (~13 000 HTTP requests for ~3 000 measured ops), and k6's rate divides by
the whole run. Use the latency columns, which are per-op and setup-independent,
for any K = 10 000 comparison.

‡ The sandbox lost its Docker daemon overnight, which killed the ON pass after
K=100. The two ‡ cells were re-run afterwards on a **freshly seeded stack** with
identical settings (warm-up cell → K=100 → K=10 000, mirroring the pass order).
Their absolute server-RSS column is therefore not comparable with the rows above
(a fresh server process starts around 71 MiB and grows with cumulative traffic,
independent of the cache — itself worth knowing); their *within-pass* deltas are.

### 6.2 Ratios — and why they say nothing about the cache

| K | thr OFF | thr ON | thr ratio | avg lat OFF | avg lat ON | lat ratio (OFF/ON) | p95 OFF | p95 ON | p95 ratio | anchor to reconcile |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 20.01 | 20.32 | **1.016×** | 2189 | 2157 | 1.015× | 3002 | 3075 | 1.024× worse | run-3 sens: **3.0–3.15×** |
| 100 | 19.62 | 20.87 / 19.72 ‡ | **1.064× / 1.005×** | 2223 | 2091 / 2210 ‡ | 1.063× / 1.006× | 3082 | 3645 / 3730 | 1.18–1.21× worse | none (G5 cell contaminated) |
| 10000 | (14.72 †) | (14.37 †) | — † | 2127 | 2320 | **0.917×** (a regression) | 2949 | 3230 | 1.095× worse | G5: **+32%** |

Read adversarially, this is what the table says:

- **The anchors are missed by a wide margin and in both directions.** K = 1
  should have been 3.0–3.15× and measured **1.016×**. K = 10 000 should have
  been +32% and measured **−8%**. A host that cannot reproduce either anchor is
  not measuring the quantity the anchors describe.
- **The one "win" is inside run-to-run noise.** The K=100 ON cell was measured
  twice: 20.87 ops/s / 2091 ms avg and 19.72 ops/s / 2210 ms avg — a 5.7% spread
  between two runs of the *same* configuration, which is larger than the 6.3%
  "gain" over cache-OFF that the first of them shows. With n = 1 per cell (the
  median-of-3 the plan asks for was not affordable at this cell cost) no
  difference of this size is real.
- **The one thing that does move is exactly what theory predicts.** At K = 100
  cache-ON the **p50 drops 21–29%** (2383 → 1702/1890 ms) while the mean barely
  moves and p95 gets *worse*. That is the signature of a bimodal population —
  hits skip the evaluation round-trips and return quickly, misses pay
  everything — sitting behind a serialized ~40–50 ms pre-check that fixes total
  throughput regardless. The cache is demonstrably doing its job; the job is
  worth ~0 here because the bottleneck is upstream of it.
- **The tail is worse with the cache ON at every single K** (1.024×, 1.18–1.21×,
  1.095×). The sign is consistent across all three key spaces and both ON runs
  at K = 100. It is contaminated evidence, but it is contaminated evidence
  pointing the wrong way for C4, and there is no clean evidence pointing the
  other way.

**Memory.** Within one stack, going from K = 100 to K = 10 000:

| pass | server RSS at K=100 | at K=10 000 | Δ |
|---|---|---|---|
| cache OFF | 110 MiB | 110 MiB | **+0 MiB** |
| cache ON ‡ | 71.3 MiB | 73.0 MiB | **+1.7 MiB** |

The +1.7 MiB is the cache's own growth from ~100 to ~10 000 entries, and it
agrees with the in-process measurement in §6.4 (9 900 extra entries × 276 B
≈ 2.7 MiB, part of which the allocator already held). The datastore's RSS grows
far more with K (57 → 95 MiB) than the server's does — that is the 9 999
provisioned resources, not the cache.

### 6.3 Live-stack revocation — `runner/h5-revocation-check.sh` (C7)

Automated (`b27da91`), run against a live p2-tls13 stack. Three runs, two stack
configurations:

| run | test A — REST revocation (Layer 1) | test B — suppressed event (Layer 2) |
|---|---|---|
| cache **ON**, stack #1 | **PASS** — deny on the first check, 349 ms after the `DELETE` | **PASS** — 15 stale allows, first deny at entry-age **5 053 ms** |
| cache **ON**, stack #2 (fresh seed) | **PASS** — deny 494 ms after the `DELETE` | **PASS** — 14 stale allows, first deny at entry-age **5 037 ms** |
| cache **OFF** (control) | **PASS** — deny 405 ms after the `DELETE` | **PASS** — **0 stale allows**; deny 104 ms after the out-of-band DB delete |

Test B suppresses the invalidation event the only way that is honest on a live
system: it deletes the `has_role` edge **directly in SurrealDB** via
`docker exec … /surreal sql`, so no handler runs and no hook fires. The
cache-ON runs then serve the pre-revocation allow for ~4.4 s and flip to deny
at 5.04–5.05 s after the entry was **inserted** (a hit does not refresh the
timestamp, so that is the correct reference point — the TTL bound holds to
within 40–50 ms of its nominal 5 s). The cache-OFF control denies immediately
with zero stale allows, which is what makes the 5 s window attributable to the
decision cache and to nothing else in the stack.

Two traps found while writing the script, both of which produced a *false* C7
failure on the first run:

- `DELETE /api/v1/roles/{role}/users/{user}` **without** `?resource_id=` deletes
  only the *global* assignment (`resource_id = NONE`, see
  `axiam-db/src/repository/role.rs::unassign_from_user`) yet still answers
  **204**. Against the resource-scoped bench fixture the revocation is a silent
  no-op, and the "stale allow" that follows is a *correct* allow. The script now
  passes the query parameter *and* asserts the edge is really gone from the
  datastore before drawing any conclusion about the cache. **Worth a
  maintainer's attention on its own:** a resource-scoped assignment survives an
  unscoped unassign, and the API reports success.
- jq's `.allowed // empty` treats `false` as empty, so a deny read as a
  malformed body.

### 6.4 Memory bound and the real entry count at K = 10 000 (plan item 4)

The G5 K = 10 000 memory column ("≈ 0 cost, 196 vs 207 MiB") could not have
detected silent eviction. That is now quantified rather than asserted:

```
cargo test -p axiam-authz --lib \
  decision_cache::tests::memory_footprint_at_the_default_cap_is_bounded -- --exact --nocapture

decision cache @ cap=10000: RSS +2704 KiB (~276 bytes/entry), entries=10000, queue_slots=10000
```

- **The cache really holds its full cap** — `entries == 10 000` exactly, every
  key still readable, and one FIFO slot per entry with no duplicates. This is
  the entry-count verification plan item 4 asks for; it is asserted, so it stays
  verified on every test run.
- **A full 10 000-entry tenant costs ~2.7 MiB.** That is *below the resolution
  of a container-RSS column* on a 110 MiB process, which is the real reason both
  the G run and this run saw "≈ 0": not that the cache was empty, but that a
  full cache is too small to see that way. Any future attempt to infer cache
  occupancy from server RSS should be abandoned rather than repeated.
- On a **live** server the same numbers are now directly observable: `e01061d`
  adds an `AuthZ decision cache stats (D7)` log line every 60 s carrying
  `entries`, `tenants`, `queue_slots`, `hits`, `misses`, `hit_rate_pct`
  (`AXIAM__AUTHZ__DECISION_CACHE_STATS_SECS=0` disables it). It could not be
  used in this run because the bench stack is pinned to the published
  `1.0.0-alpha19` image, which predates it — the first source-built image gets
  it for free.

### 6.5 Long-soak cell for finding (a)

**Not run — deliberately superseded.** The soak existed to *detect* a leak that
is now proven deterministically (200 expire/re-access cycles → exactly 200 queue
slots before the fix, ≤ 128 after) and fixed. On the pinned pre-fix image a soak
could only re-confirm the leak; on a post-fix image it would have to re-confirm
a bound that two regression tests already assert. Rerun it only if the
compaction policy is ever changed.

## 7. Criteria check

| Criterion | Threshold | Measured | Pass? |
|---|---|---|---|
| **C1** ratio @ K=10000 | ≥ 1.5× | Best clean datum on any host: **1.32×** (G5, +32%). This host: **0.92×** by per-op latency (clamped, inadmissible). No measurement anywhere has reached 1.5×. | **FAIL** |
| **C2** no regression @ K=10000 | > 1.0× with margin | G5 1.32× (one cell) vs this host 0.92×, p95 1.095× worse. The two hosts disagree on the **sign**. | **NOT ESTABLISHED** |
| **C3** ΔRSS @ K=10000 | ≤ +150 MiB | **+1.7 MiB** within-stack (K=100 → K=10 000, cache ON); **+2.7 MiB** for a full 10 000-entry tenant measured in-process at ~276 B/entry. | **PASS** |
| **C4** p95 @ every K | ≤ cache-OFF p95 | ON was worse at **every** K: 1.024× (K=1), 1.18–1.21× (K=100, both runs), 1.095× (K=10 000). Clamped data, but consistent in sign and uncontradicted. | **FAIL on available evidence** |
| **C5** `order` leak fixed | fixed + regression-tested | Fixed in `e01061d`; two regression tests, both verified to fail against the pre-fix code. | **PASS** |
| **C6** docs updated in 4 places | yes/no | Module docs, `AuthzConfig` docstrings, admin guide, deployment guide — plus the enable-time log line and `PUBLIC_BENCH_ANALYSIS.md`. | **PASS** |
| **C7** live-stack revocation | pass | Automated `runner/h5-revocation-check.sh`; A and B pass on two ON stacks, and the OFF control shows 0 stale allows. | **PASS** |

Four of seven pass. The three that do not are precisely the three that decide
the flip, and the note's own rule — "*If C1 or C2 fails: default stays
`false`*" — applies without needing to weigh anything further.

## 8. DECISION

**DECISION: the default stays `false`. The decision cache remains an opt-in
tuning knob. Recorded 2026-07-29 (H5).**

*Rationale, in one line:* **C1 fails on the only clean evidence that exists
(+32% at K = 10 000, against a 1.5× bar), C2 and C4 are unestablished or
failing, and no host available to this task can produce data able to overturn
that — so there is no basis on which to trade a silent, unobservable ≤ 5 s
revocation window for a throughput win nobody has measured at a realistic key
space.**

Three things this decision explicitly does **not** rest on:

- It does not rest on this host's numbers. Those cells are refused by
  `report.py` and are reported as ratios only. Had they shown a 3× win they
  would still not have been usable to flip the default.
- It does not rest on the cache being useless. At K = 100 it measurably cut the
  median latency by 21–29% even here; on a host without the rate-limit clamp it
  is worth 3× at K = 1. The point is that a *ship default* has to be justified
  at the worst realistic key space, and there it is worth at most ~1.3×.
- It does not rest on the defects. Those are fixed (C5) or documented (C6). The
  flip is blocked by evidence, not by code quality.

### 8.1 What would unblock a flip, and where the data must come from

| Blocker | What must be shown | Where it can be measured |
|---|---|---|
| **C1 / C2** | ON/OFF ≥ 1.5× at K = 10 000, median-of-3, on **settled** cells (`settle_timeout: false`) | Any host where the shared rate-limit counter write costs ~1 ms rather than ~40 ms — i.e. the G box, or this host **after** the H2 §7 item 2 fix (get the shared-store round-trip off the synchronous path). Not this host as it stands. |
| **C4** | p95 no worse than cache-OFF at every K, on the same settled cells | Same |
| **finding (b)** | Cross-replica invalidation, or a deployment-scoped default (e.g. ON only for `replicas: 1`) | Needs an AMQP/webhook invalidation channel that does not exist today. Until then a multi-replica default-ON is indefensible regardless of what C1 says. |

Note the ordering: even a clean 2× at K = 10 000 would only license flipping the
default for **single-replica** deployments, because finding (b) is a correctness
caveat rather than a performance one.

## 9. Deliverables for keeping it opt-in (§7 of the original note) — done

Keeping it opt-in was always a legitimate outcome, not a failure. The cache
remains a documented tuning knob for deployments that (i) run a single replica
or accept ≤ TTL cross-replica staleness, (ii) have a measured hot key space
small relative to their request rate, and (iii) have read the staleness
statement. Status of the three deliverables the original §7 named:

- **Relabelled public-doc figure — done** (`e01061d`). `PUBLIC_BENCH_ANALYSIS.md`
  §3/§4/§6 now state that the 3.0–3.15× was measured at cache-key cardinality
  K = 1 with a ~100% hit rate, quote the +32% at K = 10 000 beside it, and carry
  the process-local caveat.
- **"When to enable the decision cache" guidance — done** (`e01061d`), as the
  multi-replica call-out in `docs/deployment/README.md` plus the process-local
  subsection and the new "Observing what the cache is doing" section in
  `docs/admin/README.md` — operators can now read their own `hit_rate_pct`
  instead of extrapolating from a benchmark run on someone else's hardware,
  which is the only honest way to size this knob given how strongly the win
  depends on the key space.
- **Issues for findings (a), (b), (c) — (a) and (c) are fixed rather than
  filed** (`e01061d`); **(b) still needs an issue** for a cross-replica
  invalidation channel, plus a second one for the multi-replica revocation test
  that neither the mock suite nor the live script can perform against a single
  process. A third is worth filing for the unscoped-unassign behaviour in §6.3.
  Per CLAUDE.md these are for the maintainer to file, not for this task.
