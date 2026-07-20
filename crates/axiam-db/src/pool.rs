//! Database connection pool (F2) — N independent `Surreal<Client>` handles.
//!
//! See `claude_dev/db-pool-design.md` for the full design rationale. In short:
//!
//! * The pinned `surrealdb` 3.2.1 HTTP engine offers **no** native connection
//!   pool, and every `Surreal::clone()` shares one `Arc<inner>` (one router
//!   task + one `reqwest` client). So the only way to get genuine dispatch
//!   parallelism, N independent TCP pools, and independently-renewable sessions
//!   is N separate `Surreal::new::<Http>(..) + signin` connections — exactly
//!   what [`DbManager::connect_handle`] builds. [`DbPool`] holds N of them.
//! * Each pooled handle carries its OWN proactive re-signin + reconnect loop
//!   (the D-04/PERF-04 machinery previously applied only to the manager's
//!   handle), so **CQ-B48 is closed**: no request can reach an un-renewed
//!   snapshot session, and the former restart-only ~4-week token outage is gone.
//! * A process-wide `tokio::sync::Semaphore` optionally bounds total concurrent
//!   in-flight DB ops (the stampede fix, analogous to B1's Argon2id gate). On
//!   acquire-timeout the checkout returns the **existing** overload error,
//!   [`AxiamError::ServiceUnavailable`] → HTTP 503 — reusing B1's taxonomy
//!   exactly (see [`acquire_db_permit`]).
//!
//! ## Safe-rollout invariant (`pool_size = 1`, cap disabled — the default)
//!
//! With the default [`DbConfig`] (`pool_size = 1`, `pool_max_in_flight = 0`)
//! the pool is observably identical to today: exactly one handle (so
//! least-in-flight selection and round-robin are no-ops), and **no** semaphore
//! is built — [`DbPool::checkout`] never acquires a permit and the
//! acquire-timeout path can never fire, preserving today's unbounded DB
//! concurrency byte-for-byte. `pool_size > 1` / a positive cap is opt-in.

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axiam_core::error::AxiamError;
use surrealdb::engine::remote::http::Client;
use surrealdb::{Connection, Surreal};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;

use crate::connection::{DbConfig, DbManager, ROOT_TOKEN_DURATION};
use crate::error::DbError;
use crate::metrics;

/// One pooled handle: an independent `Surreal<C>` connection behind the same
/// swappable `Arc<RwLock<..>>` [`DbManager`] uses (D-12, so its own reconnect
/// loop can evict a poisoned handle), plus this handle's in-flight count
/// (least-in-flight checkout input) and its two owned background tasks.
struct PooledHandle<C: Connection> {
    /// Swappable so the per-handle reconnect loop can atomically evict a
    /// poisoned handle (D-12) — identical to `DbManager::db`.
    db: Arc<RwLock<Surreal<C>>>,
    /// In-flight count for THIS handle — the least-in-flight selection input.
    /// Incremented by [`DbPool::checkout`], decremented when the returned
    /// [`DbCheckout`] guard drops.
    in_flight: Arc<AtomicUsize>,
    /// Proactive re-signin task (D-04) for this handle. `None` for test-only
    /// pools built over the embedded `kv-mem` engine, whose tokens never expire.
    refresh_handle: Option<JoinHandle<()>>,
    /// Reconnect loop (PERF-04) for this handle. `None` for `kv-mem` test pools.
    reconnect_handle: Option<JoinHandle<()>>,
}

/// A pool of N independent, individually-renewable SurrealDB handles.
///
/// Generic over the connection type so the checkout/selection logic can be
/// unit-tested against the embedded `kv-mem` engine (`DbPool<Db>`) where a live
/// server would otherwise be required; production always uses the default
/// `DbPool<Client>` (the HTTP engine) built via [`DbPool::connect`].
pub struct DbPool<C: Connection = Client> {
    handles: Vec<PooledHandle<C>>,
    /// `None` when the in-flight cap is disabled (`pool_max_in_flight == 0`,
    /// the default) — checkout then never acquires a permit, so today's
    /// unbounded concurrency is preserved exactly.
    semaphore: Option<Arc<Semaphore>>,
    /// How long [`DbPool::checkout`] waits for a permit before returning the
    /// overload error. Only consulted when `semaphore` is `Some`.
    acquire_timeout: Duration,
    /// Round-robin cursor for [`DbPool::handle_for_repo`] construction-time
    /// binding (spreads repositories evenly across handles at startup).
    rr: AtomicUsize,
}

impl DbPool<Client> {
    /// Connect and build the pool using the fixed production
    /// [`ROOT_TOKEN_DURATION`]. Mirrors [`DbManager::connect`].
    pub async fn connect(config: &DbConfig) -> Result<Self, surrealdb::Error> {
        Self::connect_with_ttl(config, ROOT_TOKEN_DURATION).await
    }

    /// Build a pool of `config.pool_size` INDEPENDENT handles (each via the
    /// shared [`DbManager::connect_handle`] path — its own router task, its own
    /// `reqwest` client, its own proactive re-signin + reconnect loop). The
    /// root-token duration is extended once up-front (the DEFINE USER is
    /// idempotent), then each handle signs in fresh and minting its own
    /// long-lived token.
    ///
    /// `ttl` is a test hook (short TTLs prove per-handle session renewal without
    /// waiting four weeks); production passes [`ROOT_TOKEN_DURATION`] via
    /// [`connect`](Self::connect).
    pub async fn connect_with_ttl(
        config: &DbConfig,
        ttl: Duration,
    ) -> Result<Self, surrealdb::Error> {
        // Guard against a misconfigured `pool_size = 0`: at least one handle.
        let size = config.pool_size.max(1);
        tracing::info!(
            pool_size = size,
            pool_max_in_flight = config.pool_max_in_flight,
            "Building SurrealDB connection pool"
        );

        // Idempotent, once per process even for N handles (D-04/CORR-02).
        DbManager::extend_root_token_duration(config, ttl).await;

        let mut handles = Vec::with_capacity(size);
        for _ in 0..size {
            let (db, refresh, reconnect) = DbManager::connect_handle(config, ttl).await?;
            handles.push(PooledHandle {
                db,
                in_flight: Arc::new(AtomicUsize::new(0)),
                refresh_handle: Some(refresh),
                reconnect_handle: Some(reconnect),
            });
        }

        tracing::info!(pool_size = size, "SurrealDB connection pool ready");
        Ok(Self::assemble(
            handles,
            config.pool_max_in_flight,
            Duration::from_secs(config.pool_acquire_timeout_secs),
        ))
    }

    /// Assemble the pool struct from already-built handles. The semaphore is
    /// built ONLY when `max_in_flight > 0` — a `0` (default) cap means no
    /// semaphore at all, so the acquire path is entirely bypassed.
    fn assemble(
        handles: Vec<PooledHandle<Client>>,
        max_in_flight: usize,
        acquire_timeout: Duration,
    ) -> Self {
        Self {
            handles,
            semaphore: (max_in_flight > 0).then(|| Arc::new(Semaphore::new(max_in_flight))),
            acquire_timeout,
            rr: AtomicUsize::new(0),
        }
    }
}

impl<C: Connection> DbPool<C> {
    /// Number of pooled handles.
    pub fn size(&self) -> usize {
        self.handles.len()
    }

    /// Bind a handle to a repository at CONSTRUCTION time — the minimal-churn
    /// repo seam (design §6, Option B). Returns an owned `Surreal<C>` bound to
    /// one pooled handle, chosen round-robin so repositories spread evenly
    /// across handles at startup. The repository then calls `self.db.query(..)`
    /// exactly as before — repo bodies are untouched.
    ///
    /// This replaces the ~48 `db.client_cloned().await` composition sites. At
    /// `pool_size = 1` it hands out clones of the single pooled handle exactly
    /// as `DbManager::client_cloned()` did — byte-for-byte identical routing —
    /// the only difference being that the handle is now proactively re-signed-in
    /// (a strict improvement over the frozen snapshot it replaces).
    pub async fn handle_for_repo(&self) -> Surreal<C> {
        // Preserve the F1 checkout counter semantics (handles handed to repos).
        metrics::record_handle_checkout();
        let idx = self.rr.fetch_add(1, Ordering::Relaxed) % self.handles.len();
        self.handles[idx].db.read().await.clone()
    }

    /// Per-operation checkout with least-in-flight handle selection and, when
    /// the cap is enabled, a process-wide concurrency bound.
    ///
    /// 1. If the in-flight cap is enabled, acquire a semaphore permit within
    ///    `acquire_timeout`; on timeout return [`AxiamError::ServiceUnavailable`]
    ///    (HTTP 503, B1's overload taxonomy — see [`acquire_db_permit`]). When
    ///    the cap is disabled (default) this step is skipped entirely.
    /// 2. Pick the handle with the smallest current in-flight count (ties → the
    ///    lowest index); this is load-aware and steers work away from a
    ///    momentarily-congested handle. It is a no-op at `pool_size = 1`.
    /// 3. Increment that handle's in-flight count and return a [`DbCheckout`]
    ///    RAII guard that holds the permit and decrements the count on drop.
    pub async fn checkout(&self) -> Result<DbCheckout<C>, AxiamError> {
        let permit = match &self.semaphore {
            Some(sem) => Some(acquire_db_permit(sem, self.acquire_timeout).await?),
            None => None,
        };

        let idx = self.select_least_in_flight();
        let slot = &self.handles[idx];
        slot.in_flight.fetch_add(1, Ordering::Relaxed);
        let handle = slot.db.read().await.clone();

        Ok(DbCheckout {
            handle,
            in_flight: Arc::clone(&slot.in_flight),
            _permit: permit,
        })
    }

    /// Index of the least-in-flight handle (ties broken by lowest index).
    /// Reads each count `Relaxed` — an approximate hint is fine, so no lock is
    /// taken on the hot path (design §3.1).
    fn select_least_in_flight(&self) -> usize {
        let mut best = 0usize;
        let mut best_load = usize::MAX;
        for (i, h) in self.handles.iter().enumerate() {
            let load = h.in_flight.load(Ordering::Relaxed);
            if load < best_load {
                best_load = load;
                best = i;
            }
        }
        best
    }

    /// Readiness probe: query EVERY pooled handle so readiness reflects the
    /// whole pool (an auth-expired or poisoned handle anywhere trips the gate).
    /// Each probe is routed through the F1 [`metrics::instrument_query`] gauge.
    /// An auth failure classifies as [`DbError::Unhealthy`] (D-05) so `/ready`
    /// alarms rather than treating it as a transient query error.
    pub async fn health_check(&self) -> Result<(), DbError> {
        for slot in &self.handles {
            let guard = slot.db.read().await;
            let result = metrics::instrument_query("health_check.pool", guard.query("RETURN 1"))
                .await
                .map_err(DbManager::classify_query_error)?;
            result.check().map_err(DbManager::classify_query_error)?;
        }
        Ok(())
    }

    /// Test-only constructor: build a pool directly over already-open handles
    /// (e.g. embedded `kv-mem` instances) with no background renewal tasks, so
    /// the checkout/selection/cap logic can be exercised without a live server.
    #[cfg(test)]
    fn from_handles(raw: Vec<Surreal<C>>, max_in_flight: usize, acquire_timeout: Duration) -> Self {
        let handles = raw
            .into_iter()
            .map(|db| PooledHandle {
                db: Arc::new(RwLock::new(db)),
                in_flight: Arc::new(AtomicUsize::new(0)),
                refresh_handle: None,
                reconnect_handle: None,
            })
            .collect();
        Self {
            handles,
            semaphore: (max_in_flight > 0).then(|| Arc::new(Semaphore::new(max_in_flight))),
            acquire_timeout,
            rr: AtomicUsize::new(0),
        }
    }
}

impl<C: Connection> Drop for DbPool<C> {
    fn drop(&mut self) {
        // Explicitly stop each handle's background tasks (mirrors
        // `DbManager::drop`) so a dropped pool never leaks detached tasks.
        for slot in &self.handles {
            if let Some(t) = &slot.refresh_handle {
                t.abort();
            }
            if let Some(t) = &slot.reconnect_handle {
                t.abort();
            }
        }
    }
}

/// RAII checkout guard. `Deref`s to the chosen `Surreal<C>` so callers use it
/// exactly like the owned handle they hold today (`checkout().query(..)`).
/// Holds the semaphore permit (released on drop) and decrements the chosen
/// handle's in-flight count on drop.
pub struct DbCheckout<C: Connection = Client> {
    /// Owned clone of the chosen pooled handle, read once out of its `RwLock`
    /// at checkout time (a later reconnect-loop swap is observed by the NEXT
    /// checkout, not this in-flight one).
    handle: Surreal<C>,
    in_flight: Arc<AtomicUsize>,
    /// `None` when the cap is disabled; `Some` holds a permit released on drop.
    _permit: Option<OwnedSemaphorePermit>,
}

impl<C: Connection> Deref for DbCheckout<C> {
    type Target = Surreal<C>;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<C: Connection> Drop for DbCheckout<C> {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        // `_permit` (if any) is released as the field drops.
    }
}

/// Acquire a permit from the pool's in-flight semaphore, bounded by `timeout`.
///
/// Mirrors `axiam_auth::crypto_gate::acquire_hash_permit` EXACTLY so the DB
/// pool and the Argon2id gate (B1) share ONE overload taxonomy:
///
/// * success → the held [`OwnedSemaphorePermit`] (drop to release),
/// * acquire-timeout → [`AxiamError::ServiceUnavailable`] (the REST layer maps
///   this to **HTTP 503** — a transient server-capacity condition, not a
///   per-client rate-limit),
/// * a closed semaphore (never happens — the pool never closes it) →
///   [`AxiamError::Internal`].
///
/// `DbError` intentionally grows NO `ServiceUnavailable` variant — surfacing the
/// existing `AxiamError` here keeps a single overload shape across B1 and F2
/// (design §3.2).
async fn acquire_db_permit(
    sem: &Arc<Semaphore>,
    timeout: Duration,
) -> Result<OwnedSemaphorePermit, AxiamError> {
    match tokio::time::timeout(timeout, Arc::clone(sem).acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(AxiamError::Internal("db pool semaphore closed".into())),
        Err(_elapsed) => Err(AxiamError::ServiceUnavailable(
            "database is at capacity; please retry shortly".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::engine::local::{Db, Mem};

    /// A fresh embedded `kv-mem` handle with ns/db selected.
    async fn new_mem() -> Surreal<Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
        db.use_ns("test").use_db("test").await.expect("use ns/db");
        db
    }

    /// A `kv-mem` handle carrying a distinguishing marker row, so a handle swap
    /// (D-12) is observable across handles.
    async fn new_marked(marker: &str) -> Surreal<Db> {
        let db = new_mem().await;
        db.query(format!("CREATE marker SET value = '{marker}'"))
            .await
            .and_then(|r| r.check())
            .expect("seed marker row");
        db
    }

    async fn read_marker(db: &Surreal<Db>) -> Vec<String> {
        let mut result = db
            .query("SELECT VALUE value FROM marker")
            .await
            .and_then(|r| r.check())
            .expect("read marker rows");
        result.take(0).expect("deserialize marker values")
    }

    /// Safe-rollout invariant: `pool_size = 1` with the DISABLED cap (the
    /// default) builds no semaphore, routes every checkout/handle to the single
    /// handle, and NEVER trips the acquire-timeout path no matter how many
    /// checkouts are held concurrently.
    #[tokio::test]
    async fn pool_size_one_default_is_a_single_uncapped_handle() {
        let pool = DbPool::from_handles(vec![new_mem().await], 0, Duration::from_millis(20));
        assert_eq!(pool.size(), 1);
        assert!(
            pool.semaphore.is_none(),
            "disabled cap (0) must build NO semaphore — today's unbounded behavior"
        );

        // Hold several checkouts at once; with the cap disabled none blocks or
        // times out — the acquire-timeout path cannot fire under the default.
        let a = pool.checkout().await.expect("checkout 1");
        let b = pool.checkout().await.expect("checkout 2");
        let c = pool
            .checkout()
            .await
            .expect("checkout 3 (never caps when disabled)");
        assert_eq!(
            pool.handles[0].in_flight.load(Ordering::Relaxed),
            3,
            "all checkouts map to the one handle"
        );
        drop((a, b, c));
        assert_eq!(
            pool.handles[0].in_flight.load(Ordering::Relaxed),
            0,
            "in-flight returns to zero once guards drop"
        );

        // handle_for_repo always hands out the single handle.
        let _h = pool.handle_for_repo().await;
    }

    /// Least-in-flight spreads concurrent load evenly across handles and starves
    /// none; releasing the guards returns every handle to zero in-flight.
    #[tokio::test]
    async fn checkout_spreads_load_least_in_flight_across_handles() {
        let pool = DbPool::from_handles(
            vec![new_mem().await, new_mem().await, new_mem().await],
            0,
            Duration::from_millis(20),
        );

        // 9 simultaneously-held checkouts over 3 handles → 3 each (least-in-flight).
        let mut held = Vec::new();
        for _ in 0..9 {
            held.push(pool.checkout().await.expect("checkout"));
        }
        let counts: Vec<usize> = pool
            .handles
            .iter()
            .map(|h| h.in_flight.load(Ordering::Relaxed))
            .collect();
        assert_eq!(
            counts,
            vec![3, 3, 3],
            "least-in-flight must spread load evenly"
        );
        assert!(counts.iter().all(|c| *c > 0), "no handle may be starved");

        drop(held);
        for h in &pool.handles {
            assert_eq!(h.in_flight.load(Ordering::Relaxed), 0, "all released");
        }
    }

    /// Bounded concurrency + acquire-timeout → the reused overload error.
    /// Mirrors `crypto_gate::times_out_to_service_unavailable_when_saturated`.
    #[tokio::test]
    async fn saturated_pool_times_out_to_service_unavailable() {
        let pool = DbPool::from_handles(vec![new_mem().await], 2, Duration::from_millis(20));
        assert!(
            pool.semaphore.is_some(),
            "a positive cap must build a semaphore"
        );

        // Saturate the 2 permits.
        let _a = pool.checkout().await.expect("1st permit");
        let _b = pool.checkout().await.expect("2nd permit");

        // A 3rd checkout with a tiny timeout must return the 503 overload error.
        match pool.checkout().await {
            Err(AxiamError::ServiceUnavailable(_)) => {}
            Err(other) => panic!("expected ServiceUnavailable backpressure error, got {other:?}"),
            Ok(_) => panic!("expected ServiceUnavailable backpressure error, got a checkout"),
        }
    }

    /// Peak concurrency never exceeds the permit count (memory/stampede bound).
    /// Mirrors `crypto_gate::concurrency_is_bounded_to_permit_count`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_is_bounded_to_permit_count() {
        const PERMITS: usize = 2;
        const TASKS: usize = 8;
        let pool = Arc::new(DbPool::from_handles(
            vec![new_mem().await],
            PERMITS,
            Duration::from_secs(5),
        ));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..TASKS {
            let pool = Arc::clone(&pool);
            let in_flight = Arc::clone(&in_flight);
            let max_observed = Arc::clone(&max_observed);
            tasks.push(tokio::spawn(async move {
                let _guard = pool.checkout().await.expect("checkout within timeout");
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_observed.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(25)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert!(
            max_observed.load(Ordering::SeqCst) <= PERMITS,
            "observed concurrency {} exceeded permit bound {PERMITS}",
            max_observed.load(Ordering::SeqCst)
        );
    }

    /// Per-handle poisoned-handle eviction (D-12) — mirrors
    /// `connection.rs::poisoned_handle_is_evicted_and_never_returned_after_swap`
    /// but proves the swap is isolated to ONE pooled handle: swapping handle 0's
    /// `Arc<RwLock<Surreal<C>>>` under the write guard leaves the OTHER pooled
    /// handles untouched.
    #[tokio::test]
    async fn poisoned_handle_evicted_per_handle_others_unaffected() {
        let pool = DbPool::from_handles(
            vec![new_marked("old-0").await, new_marked("keep-1").await],
            0,
            Duration::from_millis(20),
        );

        // Pre-swap: handle 0 is the "old" (poisoned) one.
        {
            let pre = pool.handles[0].db.read().await.clone();
            assert_eq!(read_marker(&pre).await, vec!["old-0".to_string()]);
        }

        // Evict handle 0 by swapping a fresh handle in under the write guard,
        // exactly as spawn_reconnect_loop does (`*db.write().await = fresh`).
        let fresh = new_marked("new-0").await;
        *pool.handles[0].db.write().await = fresh;

        // Handle 0 now observes ONLY the new handle...
        let post0 = pool.handles[0].db.read().await.clone();
        assert_eq!(
            read_marker(&post0).await,
            vec!["new-0".to_string()],
            "the poisoned handle must never be observed after the swap (D-12)"
        );
        // ...and the sibling handle is entirely unaffected by that swap.
        let post1 = pool.handles[1].db.read().await.clone();
        assert_eq!(
            read_marker(&post1).await,
            vec!["keep-1".to_string()],
            "swapping one pooled handle must not disturb the others"
        );
    }
}
