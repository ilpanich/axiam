# DB Connection Pool — Design (F1)

**Status:** design-only; implementation is F2. Instrumentation (F1 deliverable 2)
is merged with this doc.
**Scope:** `crates/axiam-db` (`connection.rs`, new `pool.rs`, `metrics.rs`),
repository constructors, `axiam-server` composition.
**Author context:** grounded in the pinned `surrealdb` 3.2.1 HTTP-engine source
(`src/engine/remote/http/native.rs`, `src/lib.rs`) and the existing
`DbManager` (`crates/axiam-db/src/connection.rs`).

---

## 1. Problem statement (verified, not assumed)

The vendored `surrealdb` 3.2.1 HTTP engine:

- Offers **no native connection pool** and no tuning surface — you cannot inject
  a custom `reqwest::Client`, set pool limits, or cap concurrency.
- Is **not** a serial single connection: `run_router` spawns a tokio task **per
  request** over one shared `reqwest::Client`, which keeps its own implicit
  per-host HTTP/1.1 connection pool (connections opened on demand, effectively
  unbounded).
- Shares **one** `Arc<inner>` across every `Surreal::clone()` — so one router
  dispatch task and one `reqwest::Client` serve the entire process. A clone only
  mints a new session id; it does **not** get its own dispatcher, its own TCP
  pool, or its own future re-signin/reconnect lifecycle.

AXIAM builds ~30 repositories at startup via `db.client_cloned().await` (48
`client_cloned().await` + 5 `db_handle.clone()` call sites in
`axiam-server/src/main.rs`). Consequences today:

1. **Single funnel.** All repository traffic dispatches through one router task
   and one `reqwest::Client`. DB concurrency has **no upper bound** (stampede
   risk — the same class of problem B1 fixed for Argon2id).
2. **CQ-B48 session-expiry gap.** Each startup clone is a value-snapshot of the
   auth state at composition time. `DbManager`'s proactive re-signin and
   reconnect loop keep only the manager's OWN handle alive; the ~30 repo
   sessions each expire independently on the ~4-week root-token TTL, and the
   only recovery is a process restart. `health_check` deliberately probes a
   startup-generation clone (`health_probe`) so the readiness gate at least
   *trips* when the repos' tokens expire — but recovery is still restart-only.

**Honest framing (D6 evidence).** The benchmark showed the SurrealDB
container's CPU cap was the wall on authz cells (server idle, DB pegged). So the
pool is a **correctness/robustness win first** — bounded concurrency, owned
session lifecycle, no single funnel — and a **throughput win to be MEASURED in
F3, not presumed.** N independent reqwest pools give the OS more concurrent TCP
sockets to the DB, which *may* raise the ceiling, but only a laptop re-run
(§9) decides whether `pool_size > 1` becomes the default.

---

## 2. Architecture: N independent handles (not clones)

`DbPool` holds **N fully independent `Surreal<Client>` handles**, each built via
the existing `DbManager` connect/auth path — **not** `.clone()` of one handle.

```
DbPool
├── handle[0] : PooledHandle { db: Arc<RwLock<Surreal<Client>>>, refresh_task, reconnect_task }
├── handle[1] : PooledHandle { ... }               each its OWN:
├── ...                                              • router dispatch task
└── handle[N-1]: PooledHandle { ... }               • reqwest::Client (⇒ own implicit TCP pool)
                                                     • signin session + renewal lifecycle
semaphore : Arc<Semaphore>   ← process-wide in-flight cap (AXIAM__DB__POOL_MAX_IN_FLIGHT)
in_flight : per-handle AtomicUsize (checkout policy input)
```

**Why independent handles and not clones — this is the entire point:**

| Property | 30 clones of one handle (today) | N independent handles (DbPool) |
|---|---|---|
| Router dispatch task | 1 shared | N — dispatch parallelism, no single funnel |
| `reqwest::Client` / TCP pool | 1 shared implicit pool | N independent implicit pools ⇒ more concurrent sockets to the DB |
| Session renewal | only manager's handle renews; clones expire (CQ-B48) | every handle independently re-signed-in + reconnected |
| Poisoned-handle recovery | restart-only for clones | per-handle evict-and-swap (D-12 pattern) |

Because a clone shares `Arc<inner>`, cloning can never buy any of the right-hand
column — the only way to get a second router task + second reqwest pool +
independently-renewable session is a second `Surreal::new::<Http>(...)` with its
own `signin`. That is exactly what `DbManager::connect_with_ttl` /
`DbManager::reconnect` already do, so each pooled handle is constructed through
that same proven path.

### 2.1 `PooledHandle`

Each pooled handle reuses the manager's existing D-12 machinery **per handle**:

```rust
struct PooledHandle {
    /// Swappable so the per-handle reconnect loop can evict a poisoned handle
    /// (D-12) — identical to DbManager::db today.
    db: Arc<RwLock<Surreal<Client>>>,
    /// In-flight count for THIS handle — least-in-flight checkout input.
    in_flight: Arc<AtomicUsize>,
    refresh_handle: JoinHandle<()>,   // spawn_proactive_resignin, per handle
    reconnect_handle: JoinHandle<()>, // spawn_reconnect_loop, per handle
}
```

The three lifecycle functions in `connection.rs`
(`spawn_proactive_resignin`, `spawn_reconnect_loop`, `reconnect`) are already
written against `Arc<RwLock<Surreal<Client>>>` + `&DbConfig` and are engine-
neutral — F2 lifts them (or makes them `pub(crate)` associated fns callable
from `pool.rs`) and spawns one pair **per handle**. No new resilience logic is
invented; the pool is N replicas of the manager's own already-tested lifecycle.

---

## 3. Checkout policy: least-in-flight + a semaphore cap

**Two independent mechanisms, both required:**

### 3.1 Which handle — least-in-flight (chosen)

On checkout, pick the handle with the smallest current `in_flight` count
(ties broken by index). Rationale over round-robin:

- Round-robin distributes *checkouts* evenly but not *load*: a slow query on
  handle 2 leaves it congested while round-robin keeps assigning it its turn.
- Least-in-flight is load-aware — it steers new work to the least-busy router,
  which is exactly the property we want when one handle's implicit TCP pool is
  momentarily saturated. It is O(N) over a tiny N (default 1, expected ≤ 8), so
  the scan cost is negligible.
- It degrades to identical behavior as round-robin when all handles are equally
  loaded, and to a **no-op** at `pool_size = 1` (there is only one handle) —
  preserving the "pool_size=1 ≡ today" invariant.

Selection reads each `in_flight` with `Ordering::Relaxed`; exactness is not
required (it is a hint), so no lock is taken on the hot path.

### 3.2 How much concurrency — process-wide semaphore cap

A single process-wide `tokio::sync::Semaphore` (permits =
`AXIAM__DB__POOL_MAX_IN_FLIGHT`) bounds total concurrent in-flight DB ops across
**all** handles — this is the stampede fix (analogous to B1's Argon2id gate).
Checkout acquires a permit with a timeout of
`AXIAM__DB__POOL_ACQUIRE_TIMEOUT_SECS`; on timeout it returns the **existing**
overload error — reusing B1's taxonomy exactly, no new error shape:

> **B1 mapping (verified in `crates/axiam-auth/src/crypto_gate.rs`):**
> `acquire_hash_permit` returns `AxiamError::ServiceUnavailable(String)` on
> acquire-timeout, which the REST layer maps to **HTTP 503** ("service
> unavailable / overloaded"; a transient server-capacity condition, not a
> per-client rate-limit). A closed semaphore → `AxiamError::Internal`.

The pool mirrors this precisely. Since `axiam-db` errors are `DbError` and the
crate does not depend on the REST layer, the acquire helper lives at the
`axiam-db` boundary and surfaces the overload as **`AxiamError::ServiceUnavailable`**
(which `DbError`/the repos already convert into via
`impl From<DbError> for AxiamError` — see below) so the same 503 is produced.
Concretely, F2 adds a small helper mirroring `acquire_hash_permit`:

```rust
// crates/axiam-db/src/pool.rs
async fn acquire_db_permit(
    sem: &Semaphore,
    timeout: Duration,
) -> Result<OwnedSemaphorePermit, AxiamError> {
    match tokio::time::timeout(timeout, sem.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(AxiamError::Internal("db pool semaphore closed".into())),
        Err(_elapsed) => Err(AxiamError::ServiceUnavailable(
            "database is at capacity; please retry shortly".into(),
        )),
    }
}
```

> **Error-shape note.** B1 returns `AxiamError` directly (the auth crate speaks
> `AxiamError`). `DbError` has no `ServiceUnavailable` variant, and it should not
> grow one: adding it would drift from B1's single overload shape. The pool
> therefore returns `AxiamError::ServiceUnavailable` from the checkout path
> (the repos already surface `AxiamError`), keeping **one** overload taxonomy
> across Argon2id (B1) and the DB pool (F2). No new error shape is invented.

### 3.3 The checkout guard

A checkout returns an RAII guard that:

1. Holds the `OwnedSemaphorePermit` (released on drop).
2. Incremented the chosen handle's `in_flight` on creation; **decrements it on
   drop**.
3. `Deref`s to `Surreal<Client>` so call sites use it exactly like the owned
   handle they hold today (see §6).

```rust
pub struct DbCheckout {
    handle: Arc<RwLock<Surreal<Client>>>, // the chosen handle
    _permit: OwnedSemaphorePermit,
    in_flight: Arc<AtomicUsize>,          // decremented on drop
}
// Deref target is the current Surreal<Client> read out of the handle's RwLock.
```

Drop order (permit + in_flight decrement) is guaranteed by struct field drop
order; both are infallible non-blocking ops.

---

## 4. Config keys (extend `DbConfig` in `connection.rs`)

Exact new fields appended to the existing `DbConfig` struct (which already
derives `Deserialize`, `#[serde(default)]`, and has a hand-written `Default`):

```rust
pub struct DbConfig {
    // ... existing fields (url, namespace, database, username, password,
    //     token_refresh_fraction, reconnect_base_ms, reconnect_ceiling_ms,
    //     reconnect_max_retries) unchanged ...

    /// Number of INDEPENDENT `Surreal<Client>` handles in the pool — each its
    /// own router task + reqwest client + renewable session (NOT clones).
    /// Overridable via `AXIAM__DB__POOL_SIZE`.
    /// DEFAULT `1` — byte-for-byte today's behavior (one handle, one funnel),
    /// the safe first-release default. `>1` is opt-in until F3 laptop data
    /// justifies a new default.
    pub pool_size: usize,

    /// Process-wide cap on concurrent in-flight DB ops across ALL handles
    /// (the stampede bound, analogous to B1's MAX_CONCURRENT_HASHES).
    /// Overridable via `AXIAM__DB__POOL_MAX_IN_FLIGHT`.
    /// DEFAULT: see rationale below.
    pub pool_max_in_flight: usize,

    /// How long a checkout waits for a semaphore permit before returning the
    /// existing overload error (HTTP 503, B1 taxonomy). Overridable via
    /// `AXIAM__DB__POOL_ACQUIRE_TIMEOUT_SECS`. DEFAULT `5` (matches B1's
    /// `hash_acquire_timeout_secs` default for a consistent backpressure feel).
    pub pool_acquire_timeout_secs: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            // ... existing defaults unchanged ...
            pool_size: 1,
            pool_max_in_flight: 256,
            pool_acquire_timeout_secs: 5,
        }
    }
}
```

**Default rationale:**

- `pool_size = 1` — **mandatory** safe default: with one handle the pool is
  observably identical to today (one router, one reqwest pool, one session), so
  the migration is provably a no-op behavior change. This is the F2 acceptance
  gate ("`pool_size=1` must behave byte-for-byte like today").
- `pool_max_in_flight = 256` — high enough to be a **safety ceiling, not a
  throttle** at `pool_size = 1` (today's concurrency is unbounded; 256 in-flight
  DB ops is far above the ~50-VU bench load yet caps a genuine stampede). It is
  the guardrail B1 established for hashing, applied to DB ops. F3 tunes it
  against real load; it must never be set below expected steady-state
  concurrency or it becomes a latency source (documented for operators).
- `pool_acquire_timeout_secs = 5` — identical to B1's default so overload
  backpressure feels the same across the Argon2id gate and the DB pool.

> All three keys follow the existing `AXIAM__DB__*` env convention (see the
> `token_refresh_fraction` / `reconnect_*` fields already wired that way).

---

## 5. Session lifecycle — closing CQ-B48

The pool **owns** proactive re-signin + health/reconnect **per pooled handle**,
reusing `spawn_proactive_resignin` / `spawn_reconnect_loop` / `reconnect`
verbatim, one pair of background tasks per handle. Because repositories now hold
`Arc<DbPool>` (or check out from it) instead of a frozen startup snapshot, there
are **no** un-renewed snapshot sessions left in the process — every session a
request can touch belongs to a pooled handle whose proactive re-signin keeps it
inside the root-token TTL and whose reconnect loop rebuilds it on expiry/poison.
**This closes CQ-B48:** the ~4-week TTL is no longer a restart-only outage.

### 5.1 The module-doc "Known residual gap" paragraph must change

`connection.rs`'s current module doc says (paraphrased): *"every repository is
constructed via `db.client_cloned().await` … those startup repo clones are NOT
re-signed-in … there is no connection pool, and threading a shared/swappable
handle into the repositories is explicitly out of scope."*

F2 **rewrites** that paragraph to state the opposite now holds:

> **Session lifecycle (CQ-B48 closed by the DbPool, F2).** Repositories no
> longer hold frozen `client_cloned()` snapshots. They check out from
> [`DbPool`], which holds N independent handles, each with its OWN proactive
> re-signin and reconnect loop (the same D-04/PERF-04 machinery previously
> applied only to the manager's own handle). Every session a request can reach
> is therefore kept alive inside the root-token TTL and rebuilt on
> expiry/poison — the former restart-only ~4-week outage is gone. `health_probe`
> and its startup-snapshot rationale are removed; `health_check` probes the
> pooled handles.

`health_probe` (the deliberately-un-renewed CQ-B48 detector) is **deleted** in
F2 — its only purpose was to alarm on the gap this design closes.

---

## 6. Repository seam — least churn

**Today:** 36 repository constructors take an owned `Surreal<C>` at construction
(`pub fn new(db: Surreal<C>) -> Self`, one exception: `SurrealEmailConfigRepository::new(db, key)`),
store it as `db: Surreal<C>`, and call `self.db.query(...)` directly. They are
generic over `C: Connection` and `#[derive(Clone)]`. Composition clones a handle
per repo (48 + 5 call sites in `main.rs`).

Two candidate seams were evaluated:

### Option A — repos hold `Arc<DbPool>`, check out per call (rejected as primary)

Change `db: Surreal<C>` → `pool: Arc<DbPool>` and every `self.db.query(...)` →
`self.pool.checkout().await?.query(...)`. **Churn:** every query call site in
every repo (hundreds), plus the generic `<C: Connection>` bound has to go (the
pool is concrete `Surreal<Client>`). High risk, defeats "least churn," and
breaks the `kv-mem` unit tests that construct repos over `Surreal<Db>`.

### Option B — construction-only swap: repos hold a checkout provider (CHOSEN)

Keep repos calling `self.db.query(...)` **unchanged**. Change only what `self.db`
*is* and how it is **constructed**:

- Introduce `DbHandle` — the type repos store. It `Deref`s to `Surreal<Client>`
  so `self.db.query(...)` compiles untouched. In the simplest correct form
  `DbHandle` is produced by the pool and each repo is bound to one pooled handle
  at construction (checkout-at-construction, release-never — matching today's
  "own a handle for the repo's life" semantics but now a *pooled, renewable*
  handle instead of a frozen snapshot).
- `DbManager`/`DbPool` grows `pub async fn checkout(&self) -> DbCheckout` (per-op)
  **and** `pub async fn handle_for_repo(&self) -> Surreal<Client>` (construction-
  time binding). For F2's first release, repositories bind one pooled handle at
  construction via the latter — this is the **lowest-risk** option: it is a
  pure construction-site change, identical call-site count to today, and every
  `self.db.query` body is untouched.

**Call-site change count (Option B, construction-only):** the 48
`client_cloned().await` + 5 `db_handle.clone()` sites in `main.rs` change from
`db.client_cloned().await` to `pool.handle_for_repo().await` (or the composition
holds `Arc<DbPool>` and hands each repo a bound handle). **~53 mechanical
one-line construction-site edits, zero changes inside any repository query
body.** The `<C: Connection>` generic is retained (unit tests keep using
`Surreal<Db>` / `kv-mem`); production binds `C = Client`.

**Why this is provably safe at `pool_size = 1`:** with one handle,
`handle_for_repo()` hands out the single pooled handle exactly as
`client_cloned()` handed out the single manager handle today — same router, same
reqwest pool — so behavior is byte-for-byte identical. The only *added* behavior
(per-handle renewal) strictly improves on the snapshot it replaces.

> **Per-op checkout (`DbCheckout` + semaphore) — where it applies.** The
> semaphore cap and least-in-flight selection (§3) bite when there are ≥ 2
> handles OR when the operator sets `pool_max_in_flight` below steady-state
> load. F2 ships the per-op `checkout()` guard and routes the query path
> through it (via the `instrument_query` seam, §7/§8) so the cap is real; at
> `pool_size = 1` with the default high cap this is a transparent
> increment/permit that never blocks — preserving the no-op invariant. The
> construction-time binding (above) is what keeps repo *bodies* unchanged; the
> per-op guard is what enforces the bound. F2 chooses whether the bound is
> enforced by wrapping the bound handle's queries or by a true per-op checkout,
> guided by the churn budget — both satisfy the pool_size=1 invariant.

---

## 7. Instrumentation (F1 deliverable 2 — MERGED, zero behavior change)

`crates/axiam-db/src/metrics.rs` (new, wired into `lib.rs` as `pub mod metrics`).
Because the surrealdb router channel is opaque, instrumentation sits at **our**
call path — the boundary a `DbPool` will own:

- `db_in_flight() -> i64` — process-wide gauge of DB requests in flight through
  the `axiam-db` boundary. Today: requests contending for the single dispatcher.
  Post-F2: the pool's aggregate in-flight count the semaphore bounds.
- `db_handle_checkouts() -> u64` — monotonic counter of handles handed out by
  `client_cloned()`. Directly quantifies the single-funnel fan-in (~30 at
  startup) that F2 replaces.
- `instrument_query(op, fut)` — **transparent passthrough** wrapper: RAII gauge
  guard (inc on entry, dec on drop — correct on cancel/panic/error) + a
  `tracing` TRACE event carrying `op` and `latency_us` on completion. It awaits
  exactly `fut` and returns its output unchanged: no new await points, no
  reordering, no altered error semantics. The TRACE event is free when no
  subscriber is attached.

**Choke points wired in F1** (the only ones that exist today; F2 routes the
repository query path through `instrument_query`):

1. `DbManager::client_cloned()` → `metrics::record_handle_checkout()`.
2. `DbManager::health_check()` → both `RETURN 1` probes wrapped in
   `instrument_query("health_check.manager" / ".probe", ...)`.

There is **no single query choke point across the repos today** (each repo calls
`self.db.query` directly), so F1 adds the wrapper and documents that **F2 routes
the repository/pool query path through `instrument_query`** — at which point the
gauge reflects true whole-process DB concurrency.

### 7.1 Emission

Uses `tracing` (already a crate dependency; no `metrics`/`prometheus` facade
exists in `axiam-db` — grep confirmed). Structured fields
(`op`, `latency_us`, `in_flight_at_entry`, `handle_checkouts_total`) under
`target: "axiam_db::metrics"` so an operator can enable just this target.

---

## 8. Testing plan for F2

1. **Checkout distribution.** Construct a `DbPool` with `pool_size = 3` over
   `kv-mem` handles; issue K concurrent checkouts holding briefly; assert each
   handle's `in_flight` peak is ≈ K/3 (least-in-flight spreads load) and no
   handle is starved. At `pool_size = 1` assert all checkouts map to the one
   handle (no-op invariant).
2. **Bounded concurrency + acquire-timeout → overload error.** `pool_size = 1`,
   `pool_max_in_flight = 2`; saturate with 2 held checkouts; a 3rd checkout with
   a tiny acquire timeout must return `AxiamError::ServiceUnavailable` (HTTP 503,
   B1 taxonomy) — mirrors `crypto_gate::times_out_to_service_unavailable_when_saturated`.
   Also assert peak concurrency never exceeds the permit count (mirrors B1's
   `concurrency_is_bounded_to_permit_count`).
3. **Short-TTL session renewal (CQ-B48 proof).** Reuse
   `DbManager::connect_with_ttl` per pooled handle with a short TTL (as
   `connection_resilience_test.rs::recovers_from_token_expiry_without_restart`
   does for the manager); drive queries through pooled handles past the TTL and
   assert **no 401 outage** — proving the pooled sessions re-sign-in where the
   old `client_cloned()` snapshots would have 401'd. Requires a live SurrealDB
   (gated the same way the existing resilience tests are).
4. **Per-handle poisoned-handle eviction.** Mirror
   `connection.rs::poisoned_handle_is_evicted_and_never_returned_after_swap`
   (D-12) but per pooled handle: swap one handle's `Arc<RwLock<Surreal<C>>>`
   under the write guard with two marked `kv-mem` instances and assert readers
   observe only the new handle afterwards, and that the OTHER handles in the
   pool are unaffected by the swap.
5. **`pool_size=1` ≡ today.** Assert a single-handle pool routes exactly as
   `client_cloned()` did (same handle identity semantics), so the migration is a
   proven no-op behavior change.

---

## 9. Deferred to the laptop (no live stack here)

This sandbox has `cargo` but **no live SurrealDB and no `k6`/target stacks**, so
the *measured* funnel numbers are pending the maintainer's laptop re-run. Mark
these PENDING in F3:

- **TCP-connection count during one authz bench cell (single-funnel cost).**
  While an authz cell runs against native AXIAM, on the laptop run:

  ```bash
  # Count established TCP connections from the AXIAM server to SurrealDB (port 8000).
  # Run repeatedly during the measure window; expect ~1 host's worth of reqwest
  # HTTP/1.1 sockets at pool_size=1, and ~N× that at pool_size=N.
  ss -tan | grep ':8000' | grep ESTAB | wc -l
  # or, scoped to the server container's PID/netns:
  nsenter -t "$(docker inspect -f '{{.State.Pid}}' axiam-server)" -n ss -tan state established '( dport = :8000 )' | wc -l
  ```

  Record the count at `pool_size=1` vs `pool_size=N` to quantify that N handles
  really open N independent reqwest pools.
- **In-flight gauge + query latency under load.** Enable
  `RUST_LOG=axiam_db::metrics=trace` (or wire the gauge into `/metrics`) during
  an authz cell; record peak `db_in_flight` and `latency_us` distribution — the
  boundary funnel cost before/after the pool.
- **F3 throughput before/after (pool 1 vs N)** on the four authz + token cells,
  median-of-3, D7 cache off — the honest measured verdict on whether
  `pool_size>1` ships as default (per F3 acceptance).

---

## 10. Summary

`DbPool` = N independent `Surreal<Client>` handles (own router + reqwest pool +
renewable session each), least-in-flight checkout, a process-wide semaphore cap
returning B1's existing `ServiceUnavailable`/503 overload error on acquire
timeout, per-handle re-signin/reconnect closing CQ-B48, and a construction-only
repository seam (~53 one-line composition edits, repo query bodies untouched,
`pool_size=1` provably identical to today). Correctness/robustness win is
certain; the throughput win is F3's to measure, not this doc's to claim.
