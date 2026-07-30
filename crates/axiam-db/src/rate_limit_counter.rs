//! Write-behind shared rate-limit counter (SECHRD-03 / D-01a, D-01b —
//! performance fix for the H2 finding).
//!
//! # What this replaces, and why
//!
//! Until this module existed, both shared-store rate-limit layers
//! (`axiam-api-rest::middleware::rate_limit_shared::RateLimitShared` and
//! `axiam-api-grpc::middleware::rate_limit::GrpcSharedRateLimitLayer`)
//! performed ONE synchronous
//! [`SurrealRateLimitBucketRepository::increment`] UPSERT against a single
//! `rate_limit_bucket:<endpoint>:<ip>` record **before** the handler ran, on
//! the request's critical path.
//!
//! That write is a deliberate global hot spot: one record per
//! `(endpoint, key)` pair, written by every request. Measured on
//! 2026-07-28 (`server:1.0.0-alpha19` + SurrealDB 3.2.3, 2 CPU / 1 GiB each,
//! rate limits neutralized — full data in
//! `claude_dev/postseed-transient-investigation.md` §2, §3, §7):
//!
//! - The six wrapped endpoints (`POST /api/v1/authz/check`,
//!   `POST /oauth2/token`, `POST /oauth2/introspect`, `POST /oauth2/revoke`,
//!   `POST /api/v1/auth/login`, and — unintentionally, see §7 ask 1 —
//!   `GET /api/v1/users`) were pinned at **16–21 ops/s at any concurrency
//!   from 1 to 40 VUs**, with p50 ≈ 55–65 ms at 1 VU and ≈ 1 s at 20 VUs.
//! - Structurally identical endpoints WITHOUT the wrap ran at
//!   **68–4 248 ops/s**. The cleanest pair: `GET /api/v1/users` at 60–65 ms
//!   vs `GET /api/v1/resources` at 11–12 ms — same handler shape, same
//!   session, same datastore; the only difference was the wrap.
//! - The datastore's own tracer attributed ~39–46 ms of each such request to
//!   a **single** RPC that only the wrapped endpoints issue; every other RPC
//!   in the same request was 0–6 ms. The same UPSERT issued directly
//!   (`surreal sql` / raw HTTP `/sql`) ran at 6–9 ms and scaled to 487 ops/s
//!   at 20 concurrent writers on the same hot key — so the *ordering*, not
//!   the datastore, was the ceiling. The ceiling is set by the slowest
//!   datastore write in the deployment and does not improve with
//!   concurrency, app replicas, or connection pooling.
//!
//! [`SharedRateLimitCounter`] keeps the security purpose of the layer while
//! removing that synchronous write: the per-request path is now a single
//! in-process sharded-map increment (no datastore round trip, no task spawn,
//! no `await`), and a background flusher coalesces the accumulated
//! increments into **one** [`SurrealRateLimitBucketRepository::increment_by`]
//! write per `(key, window)` per sync interval.
//!
//! # What the layer is for (do not remove it)
//!
//! The per-replica in-memory `governor`/`GovernorLayer` still runs on exactly
//! the same endpoints and still makes a full per-replica decision — it is
//! untouched by this module. The shared store exists for a different reason:
//! with N replicas behind an HPA, N independent in-memory buckets multiply
//! the effective rate limit by N. The shared counter is what makes the
//! configured limit hold *across* replicas. Deleting it would silently
//! restore that N× multiplication.
//!
//! # Staleness / overshoot bound (quotable in the security docs)
//!
//! With write-behind, cross-replica enforcement becomes **eventual** rather
//! than immediate. Precisely:
//!
//! > A replica's local view of a bucket is `shared_count + pending`, where
//! > `shared_count` is the authoritative store count as of that replica's
//! > last successful flush and `pending` is its own unflushed increments.
//! > A replica therefore always counts **all** of its own traffic
//! > immediately, and *other* replicas' traffic only as of its last flush —
//! > which is at most `sync_interval` old (`AXIAM__RATE_LIMIT__SHARED_SYNC_MS`,
//! > default 1000 ms). Consequently, for a bucket receiving aggregate
//! > arrival rate `R` spread over `replicas` replicas, the worst-case
//! > overshoot beyond the configured limit before the counts converge is
//! > bounded by approximately
//! >
//! > ```text
//! > (replicas - 1) × (R / replicas) × sync_interval
//! > ```
//! >
//! > i.e. at most `(replicas − 1) × arrival_rate_per_replica × sync_interval`
//! > extra admitted requests, and **zero** on a single replica (where
//! > `replicas - 1 = 0`, so local counting is exact and this layer is as
//! > strict as the previous synchronous implementation). With the previous
//! > per-request-synchronous write the bound was zero for any replica count,
//! > at the cost of the ~20 ops/s per-endpoint ceiling documented above.
//! > Overshoot is also capped by the in-memory `governor` on the same
//! > endpoint, which independently enforces the limit per replica; the
//! > shared layer's job is to stop the aggregate from reaching
//! > `replicas × limit`, and after one `sync_interval` it does.
//!
//! Example: limit 100/min, 4 replicas, `sync_interval` 1 s, aggregate
//! arrival 40 req/s ⇒ worst case ≈ `3 × 10 × 1 s` = ~30 requests of
//! overshoot inside a 60 s window before convergence (≈ 30 % of the limit,
//! and shrinking linearly with `sync_interval`).
//!
//! # Fail-open posture (D-01b, T-24-42 accepted risk)
//!
//! This layer keeps the ONE deliberate fail-open exception in the codebase;
//! every other control fails closed. It allows the request and logs a
//! `warn`-level alarm WITHOUT the raw bucket key (T-24-43 — the key embeds a
//! client IP / `client_id`) when:
//!
//! - the shared layer is disabled (`AXIAM__RATE_LIMIT__SHARED=off`),
//! - the caller has no key part (no client IP could be derived),
//! - no datastore handle / no counter is registered,
//! - the flusher's wake channel is full or closed,
//! - the store errors during a flush.
//!
//! In the last three cases the counter **keeps serving decisions from local
//! counts** — a store outage degrades cross-replica strictness to
//! per-replica strictness (exactly the in-memory `governor`'s posture), it
//! never hard-blocks auth traffic and never surfaces a 5xx.
//!
//! Note the one behavioral difference from the pre-write-behind layer: a
//! store outage is now discovered by the *flusher*, not by the request, so a
//! request is no longer blanket-allowed just because the store is down — it
//! is still evaluated against the (perfectly valid) local count. A limit of
//! `0` therefore denies locally even with an unreachable store, where the
//! old code would have allowed. That is strictly a correctness improvement:
//! "the store is unreachable" must not become "the limit is disabled".
//!
//! # Concurrency rules obeyed here
//!
//! - State is a fixed [`SHARD_COUNT`]-way sharded map of `std::sync::Mutex`
//!   (NOT a tokio mutex): critical sections are a few field updates and are
//!   **never** held across an `await`. The flusher collects work under the
//!   lock, drops it, awaits the store, then re-locks to write back.
//! - [`SharedRateLimitCounter::check`] is fully synchronous and allocation-
//!   free on the hot path apart from the map probe, so it can be called from
//!   any executor (actix worker, tonic/tower task) without `block_on`.
//! - Poisoned mutexes are recovered from (`into_inner`) rather than
//!   panicking: a panic elsewhere must not take the rate limiter down.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use surrealdb::Connection;

use crate::error::DbError;
use crate::repository::SurrealRateLimitBucketRepository;

/// Number of independent shards in the in-process bucket map. Sized so that
/// unrelated hot keys (one per rate-limited endpoint per client IP) rarely
/// contend on the same `Mutex`, while keeping a flush pass to 16 cheap lock
/// acquisitions.
pub const SHARD_COUNT: usize = 16;

/// Default write-behind flush interval, in milliseconds
/// (`AXIAM__RATE_LIMIT__SHARED_SYNC_MS`).
pub const DEFAULT_SYNC_INTERVAL_MS: u64 = 1_000;

/// Lower clamp for `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`. Below this the
/// flusher would approach the per-request write storm this module exists to
/// remove.
pub const MIN_SYNC_INTERVAL_MS: u64 = 50;

/// Upper clamp for `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`. Above this the
/// cross-replica overshoot bound (see module docs) grows past anything
/// defensible for a security control.
pub const MAX_SYNC_INTERVAL_MS: u64 = 60_000;

/// Fixed-window length assumed by both callers' `window_start()` helpers
/// (`axiam-api-rest::middleware::rate_limit_shared::WINDOW_SECS` and
/// `axiam-api-grpc::middleware::rate_limit::WINDOW_SECS`). Used ONLY to
/// decide when an idle bucket is stale enough to prune — the window itself is
/// always supplied by the caller, never computed here.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// A bucket whose window is older than `STALE_WINDOW_MULTIPLE` windows and
/// which has nothing pending is dropped by the flusher, bounding memory to
/// "keys seen in the last two windows".
const STALE_WINDOW_MULTIPLE: u32 = 2;

/// Capacity of the bounded wake channel feeding the flusher. Notifications
/// are pure hints (the shard maps are the source of truth), so a full
/// channel only ever delays a flush to the next interval tick — it can never
/// lose a pending delta.
const WAKE_CHANNEL_CAPACITY: usize = 1_024;

/// A bucket with pending work that has not been flushed for this many sync
/// intervals means the flusher is starved (blocked store, saturated runtime).
/// The stated overshoot bound scales with the ACTUAL flush period, so this is
/// worth exactly one `warn` to an operator.
const OVERDUE_SYNC_MULTIPLE: i32 = 5;

// ---------------------------------------------------------------------------
// Store abstraction
// ---------------------------------------------------------------------------

/// Boxed future returned by [`SharedRateLimitStore::increment_by`].
pub type StoreIncrementFuture<'a> = Pin<Box<dyn Future<Output = Result<u64, DbError>> + Send + 'a>>;

/// The single write primitive the write-behind flusher needs.
///
/// Object-safe on purpose (hence the boxed future rather than an
/// `async fn`): [`SharedRateLimitCounter`] is deliberately NOT generic over
/// the SurrealDB connection type, so one non-generic counter type can be held
/// by `axiam-api-rest`'s `AppState<C>` and by `axiam-api-grpc`'s tower layer
/// alike, and so tests can substitute a failing or call-counting store.
///
/// Implemented for [`SurrealRateLimitBucketRepository`] for every
/// `C: Connection`.
pub trait SharedRateLimitStore: Send + Sync + 'static {
    /// Adds `delta` to the bucket `key` for the fixed window starting at
    /// `window_start`, returning the authoritative POST-update count.
    fn increment_by<'a>(
        &'a self,
        key: &'a str,
        window_start: DateTime<Utc>,
        delta: u64,
    ) -> StoreIncrementFuture<'a>;
}

impl<C: Connection> SharedRateLimitStore for SurrealRateLimitBucketRepository<C> {
    fn increment_by<'a>(
        &'a self,
        key: &'a str,
        window_start: DateTime<Utc>,
        delta: u64,
    ) -> StoreIncrementFuture<'a> {
        Box::pin(SurrealRateLimitBucketRepository::increment_by(
            self,
            key,
            window_start,
            delta,
        ))
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for [`SharedRateLimitCounter`], read once via
/// [`SharedRateLimitConfig::from_env`] so the REST and gRPC layers always
/// behave identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRateLimitConfig {
    /// `AXIAM__RATE_LIMIT__SHARED` — `on` (default) or `off`.
    ///
    /// `off` skips the shared layer *entirely* (no state, no store call, no
    /// flusher) for single-replica deployments, leaving the per-replica
    /// in-memory `governor` as the sole limiter. It does NOT change any
    /// configured limit.
    pub enabled: bool,
    /// `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` — write-behind flush interval,
    /// clamped to [`MIN_SYNC_INTERVAL_MS`]..=[`MAX_SYNC_INTERVAL_MS`].
    /// Directly scales the cross-replica overshoot bound (module docs).
    pub sync_interval: Duration,
    /// Fixed-window length used only for staleness pruning; must match the
    /// callers' `window_start()` truncation (60 s in both).
    pub window: Duration,
}

impl Default for SharedRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_interval: Duration::from_millis(DEFAULT_SYNC_INTERVAL_MS),
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
        }
    }
}

impl SharedRateLimitConfig {
    /// Reads `AXIAM__RATE_LIMIT__SHARED` and
    /// `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`.
    ///
    /// - `AXIAM__RATE_LIMIT__SHARED`: `off`/`false`/`0`/`no` disable the
    ///   shared layer; anything else (including unset) leaves it **on** —
    ///   the secure default, since disabling it re-opens the multi-replica
    ///   limit multiplication.
    /// - `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`: parsed as `u64` milliseconds,
    ///   clamped to [`MIN_SYNC_INTERVAL_MS`]..=[`MAX_SYNC_INTERVAL_MS`];
    ///   unparseable or absent falls back to [`DEFAULT_SYNC_INTERVAL_MS`].
    pub fn from_env() -> Self {
        let enabled = match std::env::var("AXIAM__RATE_LIMIT__SHARED") {
            Ok(raw) => !matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "off" | "false" | "0" | "no"
            ),
            Err(_) => true,
        };

        let sync_interval_ms = std::env::var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_SYNC_INTERVAL_MS)
            .clamp(MIN_SYNC_INTERVAL_MS, MAX_SYNC_INTERVAL_MS);

        Self {
            enabled,
            sync_interval: Duration::from_millis(sync_interval_ms),
            window: Duration::from_secs(DEFAULT_WINDOW_SECS),
        }
    }
}

// ---------------------------------------------------------------------------
// Bucket state
// ---------------------------------------------------------------------------

/// One in-process fixed-window bucket.
///
/// The effective count a decision is made on is `shared_count + pending`:
/// the authoritative cross-replica count as of the last successful flush,
/// plus this replica's own not-yet-flushed increments.
#[derive(Debug, Clone)]
struct Bucket {
    /// Start of the fixed window this bucket's counts belong to. A `check`
    /// for a different window rolls the bucket over (both counts reset).
    window_start: DateTime<Utc>,
    /// Authoritative store count as of the last successful flush of this
    /// bucket in this window (already includes this replica's flushed
    /// increments).
    shared_count: u64,
    /// Local increments accepted since the last successful flush and not yet
    /// written to the store.
    pending: u64,
    /// When this bucket was last successfully flushed (`None` = never in this
    /// window). Read by the flusher purely for starvation detection: if a
    /// bucket with pending work has not been flushed for
    /// [`OVERDUE_SYNC_MULTIPLE`] sync intervals, the write-behind loop is not
    /// keeping up and the cross-replica overshoot bound documented in the
    /// module docs no longer holds, which is worth one `warn`.
    last_flush: Option<DateTime<Utc>>,
}

impl Bucket {
    fn new(window_start: DateTime<Utc>) -> Self {
        Self {
            window_start,
            shared_count: 0,
            pending: 0,
            last_flush: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

/// Shared, write-behind rate-limit counter used by BOTH the REST
/// (`RateLimitShared`) and gRPC (`GrpcSharedRateLimitLayer`) shared-store
/// layers.
///
/// Cheap to clone (`Arc` inside) and MUST be shared process-wide: one
/// instance per process, cloned into every worker. Per-worker instances would
/// fragment the local count and weaken the limit by the worker count — this
/// is why `axiam-api-rest` holds it in `AppState` (registered once as
/// `web::Data`) rather than constructing one per resource.
///
/// See the module docs for the overshoot bound and the fail-open posture.
#[derive(Clone)]
pub struct SharedRateLimitCounter {
    inner: Arc<Inner>,
    /// Wake hint for the flusher. `None` when the counter is disabled or no
    /// tokio runtime was available at construction (local-only mode). Held
    /// here rather than in [`Inner`] so that dropping every clone of the
    /// counter closes the channel and lets the flusher task exit instead of
    /// leaking.
    wake: Option<tokio::sync::mpsc::Sender<()>>,
}

struct Inner {
    config: SharedRateLimitConfig,
    /// `None` when the shared layer is disabled — no store is ever touched.
    store: Option<Arc<dyn SharedRateLimitStore>>,
    shards: Vec<Mutex<HashMap<String, Bucket>>>,
    /// Latch so a persistent wake-channel problem logs once instead of once
    /// per request (a warn per request would itself be a performance bug).
    wake_warned: AtomicBool,
    /// Latch for the "flusher is starved" alarm (see
    /// [`OVERDUE_SYNC_MULTIPLE`]), for the same reason.
    starvation_warned: AtomicBool,
}

impl SharedRateLimitCounter {
    /// Builds a counter over `store` and starts its single background
    /// flusher task.
    ///
    /// Must be called from within a tokio runtime (it is: both callers
    /// construct it during async server startup). If no runtime handle is
    /// available, construction still succeeds but logs a `warn` and the
    /// counter runs **local-only** — decisions keep working from local
    /// counts, they just never converge across replicas. That is the same
    /// fail-open degradation as a store outage, never a hard failure.
    ///
    /// When `config.enabled` is `false` the store is dropped on the spot, no
    /// task is spawned, and [`Self::check`] short-circuits to "allow".
    pub fn new(config: SharedRateLimitConfig, store: Arc<dyn SharedRateLimitStore>) -> Self {
        if !config.enabled {
            tracing::info!(
                "shared rate-limit counter DISABLED (AXIAM__RATE_LIMIT__SHARED=off); \
                 the per-replica in-memory governor is the sole rate limiter"
            );
            return Self::disabled(config);
        }

        let inner = Arc::new(Inner::new(config, Some(store)));

        // A bounded channel of increment notifications: `check` hints that
        // work exists, the flusher coalesces every `sync_interval`.
        let (tx, rx) = tokio::sync::mpsc::channel(WAKE_CHANNEL_CAPACITY);

        let wake = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let flusher_inner = Arc::clone(&inner);
                handle.spawn(flusher_loop(flusher_inner, rx));
                tracing::info!(
                    sync_interval_ms = inner.config.sync_interval.as_millis() as u64,
                    shards = SHARD_COUNT,
                    "shared rate-limit counter ACTIVE (write-behind); one datastore write \
                     per bucket per sync interval instead of one per request"
                );
                Some(tx)
            }
            Err(_) => {
                tracing::warn!(
                    "shared rate-limit counter started outside a tokio runtime; running \
                     local-only (no cross-replica convergence) — decisions continue from \
                     local counts"
                );
                None
            }
        };

        Self { inner, wake }
    }

    /// Convenience constructor reading [`SharedRateLimitConfig::from_env`].
    pub fn from_env(store: Arc<dyn SharedRateLimitStore>) -> Self {
        Self::new(SharedRateLimitConfig::from_env(), store)
    }

    /// A counter that holds no store, spawns nothing, and always allows —
    /// the `AXIAM__RATE_LIMIT__SHARED=off` shape, also used wherever a
    /// counter is structurally required but the shared layer is not wanted.
    pub fn disabled(config: SharedRateLimitConfig) -> Self {
        Self {
            inner: Arc::new(Inner::new(
                SharedRateLimitConfig {
                    enabled: false,
                    ..config
                },
                None,
            )),
            wake: None,
        }
    }

    /// Builds an enabled counter WITHOUT spawning the background flusher.
    ///
    /// For tests (and any caller that wants to drive flushing itself via
    /// [`Self::flush_once`]) — production code should use [`Self::new`].
    pub fn without_flusher(
        config: SharedRateLimitConfig,
        store: Arc<dyn SharedRateLimitStore>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner::new(config, Some(store))),
            wake: None,
        }
    }

    /// `true` when the shared layer is active (i.e. not
    /// `AXIAM__RATE_LIMIT__SHARED=off`).
    pub fn is_enabled(&self) -> bool {
        self.inner.config.enabled
    }

    /// The effective configuration (post-clamping).
    pub fn config(&self) -> &SharedRateLimitConfig {
        &self.inner.config
    }

    /// The per-request decision: `true` = allow, `false` = deny (HTTP 429 /
    /// gRPC `RESOURCE_EXHAUSTED`).
    ///
    /// Fully synchronous: one hash, one `Mutex` acquisition, a few field
    /// updates, and a non-blocking wake hint. No datastore round trip, no
    /// `await`, no task spawn — this is the whole point of the module.
    ///
    /// Semantics:
    /// - The bucket rolls over (both counts reset to zero) whenever
    ///   `window_start` differs from the stored one, so a caller that
    ///   truncates `now` to its fixed window gets exact fixed-window
    ///   behavior.
    /// - `pending` is incremented for every call, including denied ones, so
    ///   sustained over-limit traffic is reported to the store and thus to
    ///   the other replicas (mirrors the previous behavior, where the
    ///   UPSERT also ran before the limit test).
    /// - Denies when `shared_count + pending > limit`.
    ///
    /// Always allows (and never touches any state) when the counter is
    /// disabled.
    pub fn check(&self, key: &str, window_start: DateTime<Utc>, limit: u32) -> bool {
        if !self.inner.config.enabled {
            return true;
        }

        let allow = {
            let shard = self.inner.shard_for(key);
            let mut guard = lock_shard(shard);
            let bucket = guard
                .entry(key.to_string())
                .or_insert_with(|| Bucket::new(window_start));

            // Window rollover: a new fixed window is a brand-new bucket.
            // Any `pending` from the previous window is intentionally
            // discarded — that window is closed, so its count can no longer
            // influence a decision, and re-sending it would corrupt the new
            // window's count.
            if bucket.window_start != window_start {
                *bucket = Bucket::new(window_start);
            }

            bucket.pending = bucket.pending.saturating_add(1);
            bucket.shared_count.saturating_add(bucket.pending) <= u64::from(limit)
        };

        self.notify_flusher();
        allow
    }

    /// Non-blocking wake hint for the flusher.
    ///
    /// A full channel is benign — a flush is already queued and the shard
    /// maps (not the messages) carry the pending deltas, so the worst case is
    /// that this delta waits for the flusher's next interval tick. A closed
    /// channel means the flusher is gone; both are logged once at `warn`
    /// (never per request, and never with the key — T-24-43) and the decision
    /// already returned above stands.
    fn notify_flusher(&self) {
        let Some(tx) = &self.wake else { return };
        if let Err(err) = tx.try_send(())
            && !self.inner.wake_warned.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                reason = %match err {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => "wake channel full",
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => "flusher stopped",
                },
                "shared rate-limit flusher could not be woken; continuing to serve \
                 decisions from local counts (logged once)"
            );
        }
    }

    /// Runs ONE write-behind flush pass: coalesce each bucket's accumulated
    /// `pending` into a single store write, adopt the returned authoritative
    /// count, and prune stale buckets.
    ///
    /// Public so tests (and a future graceful-shutdown hook) can force
    /// convergence deterministically instead of sleeping. Idempotent and
    /// safe to call concurrently with `check`.
    pub async fn flush_once(&self) {
        self.inner.flush_once().await;
    }

    /// Number of buckets currently held in memory, across all shards.
    /// Exposed for tests and for a future gauge metric — bounded by the
    /// number of distinct `(endpoint, key_part)` pairs seen in the last two
    /// windows thanks to flush-time pruning.
    pub fn bucket_count(&self) -> usize {
        self.inner
            .shards
            .iter()
            .map(|shard| lock_shard(shard).len())
            .sum()
    }
}

impl std::fmt::Debug for SharedRateLimitCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedRateLimitCounter")
            .field("enabled", &self.inner.config.enabled)
            .field("sync_interval", &self.inner.config.sync_interval)
            .field("flusher", &self.wake.is_some())
            .field("buckets", &self.bucket_count())
            .finish()
    }
}

impl Inner {
    fn new(config: SharedRateLimitConfig, store: Option<Arc<dyn SharedRateLimitStore>>) -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }
        // A disabled counter drops the store here, so there is no way for any
        // later code path to reach the datastore.
        let store = if config.enabled { store } else { None };
        Self {
            config,
            store,
            shards,
            wake_warned: AtomicBool::new(false),
            starvation_warned: AtomicBool::new(false),
        }
    }

    fn shard_for(&self, key: &str) -> &Mutex<HashMap<String, Bucket>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % SHARD_COUNT]
    }

    /// See [`SharedRateLimitCounter::flush_once`].
    ///
    /// Three phases, so that the `std::sync::Mutex` is NEVER held across the
    /// store `await`:
    /// 1. Under each shard lock: prune stale buckets and collect
    ///    `(shard, key, window, delta)` for every bucket with pending work
    ///    that has not already been flushed within this `sync_interval`.
    /// 2. Lock-free: one [`SharedRateLimitStore::increment_by`] per key.
    /// 3. Re-lock briefly: adopt the authoritative count and subtract the
    ///    flushed delta from `pending` (increments that arrived during the
    ///    await stay pending for the next pass).
    async fn flush_once(&self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };

        let now = Utc::now();
        let work = self.collect_pending(now);

        for (shard_idx, key, window, delta) in work {
            match store.increment_by(&key, window, delta).await {
                Ok(authoritative) => {
                    let mut guard = lock_shard(&self.shards[shard_idx]);
                    if let Some(bucket) = guard.get_mut(&key) {
                        // Ignore the result if the bucket rolled over into a
                        // new window while the write was in flight — that
                        // count belongs to the window we just left.
                        if bucket.window_start == window {
                            bucket.shared_count = authoritative;
                            bucket.pending = bucket.pending.saturating_sub(delta);
                            bucket.last_flush = Some(now);
                        }
                    }
                }
                Err(err) => {
                    // Fail OPEN (D-01b): a counter-store outage must never
                    // hard-block auth traffic. `pending` is deliberately left
                    // in place so the delta is retried on the next pass; a
                    // retry that double-counts an UPSERT which actually
                    // landed errs toward *stricter* limiting, which is the
                    // safe direction for a security control.
                    // T-24-43: never log the raw key (it embeds a client IP /
                    // client_id).
                    tracing::warn!(
                        delta,
                        error = %err,
                        "shared rate-limit store unreachable during write-behind flush; \
                         cross-replica convergence paused, still enforcing local counts"
                    );
                }
            }
        }
    }

    /// Phase 1 of [`Self::flush_once`]: prune + collect, one short lock per
    /// shard, nothing awaited.
    ///
    /// Only buckets with `pending > 0` are collected, so an idle bucket costs
    /// zero store writes no matter how many passes run. Since the flusher
    /// loop itself runs at most once per `sync_interval`, "one write per
    /// bucket per interval" follows from the loop, not from any per-bucket
    /// suppression here — a bucket must never be skipped while it has
    /// unflushed increments, or its replica's contribution would stay
    /// invisible to the other replicas for an unbounded time.
    fn collect_pending(&self, now: DateTime<Utc>) -> Vec<(usize, String, DateTime<Utc>, u64)> {
        let stale_after = self.config.window * STALE_WINDOW_MULTIPLE;
        let stale_cutoff = chrono::Duration::from_std(stale_after)
            .ok()
            .and_then(|d| now.checked_sub_signed(d));
        let overdue_after = chrono::Duration::from_std(self.config.sync_interval)
            .ok()
            .map(|gap| gap * OVERDUE_SYNC_MULTIPLE);

        let mut work = Vec::new();
        let mut overdue = false;
        for (shard_idx, shard) in self.shards.iter().enumerate() {
            let mut guard = lock_shard(shard);

            // Pruning (bounded memory): drop buckets older than
            // STALE_WINDOW_MULTIPLE windows that have nothing left to flush.
            if let Some(cutoff) = stale_cutoff {
                guard.retain(|_, bucket| bucket.pending > 0 || bucket.window_start >= cutoff);
            }

            for (key, bucket) in guard.iter() {
                if bucket.pending == 0 {
                    continue;
                }
                // Starvation detection only — never suppresses a write.
                if let (Some(last), Some(threshold)) = (bucket.last_flush, overdue_after)
                    && now.signed_duration_since(last) > threshold
                {
                    overdue = true;
                }
                work.push((shard_idx, key.clone(), bucket.window_start, bucket.pending));
            }
        }

        if overdue && !self.starvation_warned.swap(true, Ordering::Relaxed) {
            // T-24-43: no raw key in the alarm.
            tracing::warn!(
                sync_interval_ms = self.config.sync_interval.as_millis() as u64,
                overdue_multiple = OVERDUE_SYNC_MULTIPLE,
                "shared rate-limit write-behind flusher is falling behind its sync \
                 interval; cross-replica overshoot may exceed the documented bound \
                 (logged once)"
            );
        }

        work
    }
}

/// Acquires a shard lock, recovering from poisoning instead of panicking: a
/// panic in an unrelated task must not disable the rate limiter.
fn lock_shard(shard: &Mutex<HashMap<String, Bucket>>) -> MutexGuard<'_, HashMap<String, Bucket>> {
    shard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The single background flusher task.
///
/// Wakes on an increment notification OR on a `sync_interval` backstop tick
/// (so a delta whose wake hint was dropped by a full channel is still
/// flushed), drains any further queued hints, then runs one coalesced pass.
/// Exits when every [`SharedRateLimitCounter`] clone has been dropped, so it
/// never outlives the counter it serves.
async fn flusher_loop(inner: Arc<Inner>, mut rx: tokio::sync::mpsc::Receiver<()>) {
    let interval = inner.config.sync_interval;
    loop {
        tokio::select! {
            hint = rx.recv() => {
                if hint.is_none() {
                    // All senders dropped: the counter is gone.
                    break;
                }
                // Coalescing window: let further increments accumulate
                // before paying for a store round trip.
                tokio::time::sleep(interval).await;
            }
            _ = tokio::time::sleep(interval) => {}
        }

        // Drain queued hints so they don't each trigger a redundant pass.
        while rx.try_recv().is_ok() {}

        inner.flush_once().await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Call-recording in-memory store: proves the flusher coalesces (one
    /// call per key per pass, carrying the summed delta) and lets a test
    /// assert "no store interaction at all".
    #[derive(Default)]
    struct RecordingStore {
        calls: Mutex<Vec<(String, DateTime<Utc>, u64)>>,
        counts: Mutex<HashMap<(String, DateTime<Utc>), u64>>,
        /// When set, every `increment_by` errors — simulates a store outage.
        fail: AtomicBool,
        call_count: AtomicUsize,
    }

    impl RecordingStore {
        fn calls(&self) -> Vec<(String, DateTime<Utc>, u64)> {
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }

        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }

        /// Simulates another replica having already written `count` into the
        /// shared bucket.
        fn preload(&self, key: &str, window: DateTime<Utc>, count: u64) {
            self.counts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((key.to_string(), window), count);
        }
    }

    impl SharedRateLimitStore for RecordingStore {
        fn increment_by<'a>(
            &'a self,
            key: &'a str,
            window_start: DateTime<Utc>,
            delta: u64,
        ) -> StoreIncrementFuture<'a> {
            Box::pin(async move {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                self.calls.lock().unwrap_or_else(|p| p.into_inner()).push((
                    key.to_string(),
                    window_start,
                    delta,
                ));
                if self.fail.load(Ordering::SeqCst) {
                    return Err(DbError::Migration("simulated store outage".into()));
                }
                let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
                let entry = counts.entry((key.to_string(), window_start)).or_insert(0);
                *entry += delta;
                Ok(*entry)
            })
        }
    }

    fn counter_with(store: Arc<RecordingStore>) -> SharedRateLimitCounter {
        SharedRateLimitCounter::without_flusher(SharedRateLimitConfig::default(), store)
    }

    /// Requirement 1: under the limit allows, crossing it denies — with no
    /// flush at all (purely local counting, the hot path).
    #[test]
    fn under_limit_allows_and_crossing_limit_denies_locally() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(Arc::clone(&store));
        let window = Utc::now();

        for i in 1..=3 {
            assert!(
                counter.check("login:203.0.113.5", window, 3),
                "request {i} is within the limit"
            );
        }
        assert!(
            !counter.check("login:203.0.113.5", window, 3),
            "the 4th request crosses limit=3 and must be denied"
        );
        // Still denied while over budget.
        assert!(!counter.check("login:203.0.113.5", window, 3));

        // Decisions required ZERO store round trips (the whole point).
        assert_eq!(store.call_count(), 0);

        // A different key has its own bucket.
        assert!(counter.check("login:198.51.100.1", window, 3));
    }

    /// Requirement 2: a new window resets the count and re-allows.
    #[test]
    fn window_rollover_resets_and_reallows() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(store);
        let window1 = Utc::now();
        let window2 = window1 + chrono::Duration::seconds(60);

        for _ in 0..2 {
            assert!(counter.check("k", window1, 2));
        }
        assert!(!counter.check("k", window1, 2));

        // New window ⇒ fresh budget.
        assert!(counter.check("k", window2, 2));
        assert!(counter.check("k", window2, 2));
        assert!(!counter.check("k", window2, 2));
    }

    /// Requirement 3: N local increments coalesce into ONE store write
    /// carrying delta N, and the authoritative count is adopted afterwards.
    #[tokio::test]
    async fn flush_coalesces_increments_into_one_write_and_adopts_the_count() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(Arc::clone(&store));
        let window = Utc::now();

        for _ in 0..5 {
            assert!(counter.check("authz_check:10.0.0.1", window, 100));
        }
        assert_eq!(store.call_count(), 0, "nothing written before the flush");

        counter.flush_once().await;

        let calls = store.calls();
        assert_eq!(calls.len(), 1, "5 increments ⇒ exactly ONE store write");
        assert_eq!(calls[0].0, "authz_check:10.0.0.1");
        assert_eq!(calls[0].1, window);
        assert_eq!(calls[0].2, 5, "the write carries the summed delta");

        // `shared_count` was adopted and `pending` drained: the next 95
        // requests fit under limit=100, the 101st does not.
        for _ in 0..95 {
            assert!(counter.check("authz_check:10.0.0.1", window, 100));
        }
        assert!(!counter.check("authz_check:10.0.0.1", window, 100));

        // A second flush writes the NEW delta only (95 + 1 denied = 96),
        // never re-sends the already-flushed 5.
        counter.flush_once().await;
        let calls = store.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].2, 96, "only the new delta is written");
    }

    /// Requirement 3b: an IDLE bucket produces no write at all — the "one
    /// write per bucket per interval" ceiling comes from the flusher loop's
    /// interval, and a bucket with nothing pending costs nothing even if the
    /// loop is woken repeatedly.
    #[tokio::test]
    async fn flush_is_a_noop_without_pending_work() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(Arc::clone(&store));

        counter.flush_once().await;
        assert_eq!(store.call_count(), 0, "no buckets ⇒ no writes");

        let window = Utc::now();
        assert!(counter.check("k", window, 10));
        counter.flush_once().await;
        assert_eq!(store.call_count(), 1);

        // Repeated passes with nothing new pending must NOT write again.
        for _ in 0..5 {
            counter.flush_once().await;
        }
        assert_eq!(
            store.call_count(),
            1,
            "an idle bucket is never re-written, however often the flusher runs"
        );

        // New traffic ⇒ exactly one more write, carrying only the new delta.
        assert!(counter.check("k", window, 10));
        assert!(counter.check("k", window, 10));
        counter.flush_once().await;
        let calls = store.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].2, 2, "only the new delta is written");
    }

    /// Requirement 4 — THE property this whole layer exists for: two counter
    /// instances ("replicas") over ONE store converge, and the COMBINED limit
    /// is enforced. An in-memory-only baseline would allow `2 × LIMIT`.
    ///
    /// This test also pins the documented staleness/overshoot bound: a replica
    /// counts all of its OWN traffic immediately, but only sees the other
    /// replica's traffic as of its last flush, so it may admit a bounded
    /// number of extra requests before converging.
    #[tokio::test]
    async fn cross_replica_convergence_enforces_the_combined_limit() {
        let store = Arc::new(RecordingStore::default());
        let replica_a = counter_with(Arc::clone(&store));
        let replica_b = counter_with(Arc::clone(&store));
        let window = Utc::now();
        let key = "oauth2_token:203.0.113.9";
        const LIMIT: u32 = 4;

        // Each replica admits 2 requests: 4 total, exactly the limit, and
        // neither replica has seen the other's traffic yet.
        let mut admitted = 0;
        for _ in 0..2 {
            assert!(replica_a.check(key, window, LIMIT));
            assert!(replica_b.check(key, window, LIMIT));
            admitted += 2;
        }
        assert_eq!(admitted, 4);

        // One flush pass on each replica: A writes its delta (2), then B
        // writes its delta and reads back the combined authoritative count
        // (4). Exactly two coalesced writes for four requests.
        replica_a.flush_once().await;
        replica_b.flush_once().await;
        let deltas: Vec<u64> = store.calls().iter().map(|c| c.2).collect();
        assert_eq!(
            deltas,
            vec![2, 2],
            "one coalesced write per replica, never one per request"
        );

        // B flushed last, so it holds the full picture and denies at once.
        assert!(
            !replica_b.check(key, window, LIMIT),
            "replica B must observe replica A's contribution after convergence"
        );

        // A adopted `shared_count = 2` (the store's value at ITS flush, before
        // B wrote), so it still admits ONE more request. This IS the
        // documented overshoot: bounded by what arrives at a replica within
        // one sync interval, and it converges on A's next flush.
        assert!(
            replica_a.check(key, window, LIMIT),
            "replica A has not yet seen B's contribution — the bounded overshoot"
        );
        admitted += 1;

        // A's next flush writes its 1 pending increment and adopts 5.
        replica_a.flush_once().await;
        assert!(
            !replica_a.check(key, window, LIMIT),
            "replica A must observe replica B's contribution after convergence"
        );
        assert!(!replica_b.check(key, window, LIMIT));

        // Aggregate admitted (5) exceeded the limit by exactly the bounded
        // overshoot and stayed FAR below the `2 × LIMIT = 8` an in-memory-only
        // per-replica baseline would have allowed.
        assert_eq!(admitted, 5);
        assert!(admitted < 2 * LIMIT as usize);
    }

    /// Requirement 4b: a count already in the store (written by another
    /// replica before this one ever saw the key) is adopted on first flush.
    #[tokio::test]
    async fn adopts_a_preexisting_shared_count_from_another_replica() {
        let store = Arc::new(RecordingStore::default());
        let window = Utc::now();
        let key = "login:198.51.100.77";
        store.preload(key, window, 9);

        let counter = counter_with(Arc::clone(&store));
        assert!(
            counter.check(key, window, 10),
            "locally this is only the 1st request, so it is admitted"
        );
        counter.flush_once().await;

        assert!(
            !counter.check(key, window, 10),
            "after convergence the store's 9 + this replica's 1 fills limit=10"
        );
    }

    /// Requirement 5: a store error during flush fails open — no panic, the
    /// delta is retained for retry, and local counting keeps working.
    #[tokio::test]
    async fn store_error_during_flush_fails_open_and_keeps_counting_locally() {
        let store = Arc::new(RecordingStore::default());
        store.fail.store(true, Ordering::SeqCst);
        let counter = counter_with(Arc::clone(&store));
        let window = Utc::now();

        for _ in 0..2 {
            assert!(counter.check("k", window, 3));
        }

        // Does not panic, does not poison anything.
        counter.flush_once().await;
        assert_eq!(store.call_count(), 1, "the flush was attempted");

        // Local counting is unaffected: the 3rd is admitted, the 4th denied.
        assert!(counter.check("k", window, 3));
        assert!(!counter.check("k", window, 3));

        // The unflushed delta was retained, so once the store recovers it is
        // written in full (4 local increments, none lost).
        store.fail.store(false, Ordering::SeqCst);
        counter.flush_once().await;
        let calls = store.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].2, 4, "the retained delta is retried in full");
    }

    /// Requirement 6: `AXIAM__RATE_LIMIT__SHARED=off` ⇒ no store interaction
    /// at all, and every request is allowed by this layer (the in-memory
    /// governor remains the sole limiter).
    #[tokio::test]
    async fn disabled_counter_never_touches_the_store() {
        let store = Arc::new(RecordingStore::default());
        let counter = SharedRateLimitCounter::new(
            SharedRateLimitConfig {
                enabled: false,
                ..SharedRateLimitConfig::default()
            },
            Arc::clone(&store) as Arc<dyn SharedRateLimitStore>,
        );

        assert!(!counter.is_enabled());
        let window = Utc::now();
        for _ in 0..50 {
            assert!(
                counter.check("k", window, 1),
                "a disabled shared layer never denies"
            );
        }
        counter.flush_once().await;

        assert_eq!(store.call_count(), 0, "no store interaction whatsoever");
        assert_eq!(store.calls().len(), 0);
        assert_eq!(counter.bucket_count(), 0, "no state is even allocated");
    }

    /// Requirement 7: memory is bounded — buckets whose window is older than
    /// two windows and which have nothing pending are pruned by the flusher.
    #[tokio::test]
    async fn flush_prunes_stale_windows_to_bound_memory() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(Arc::clone(&store));

        let now = Utc::now();
        let stale = now - chrono::Duration::seconds(10 * DEFAULT_WINDOW_SECS as i64);
        let current = now;

        // 40 distinct stale keys + 3 current keys.
        for i in 0..40 {
            assert!(counter.check(&format!("stale:{i}"), stale, 100));
        }
        for i in 0..3 {
            assert!(counter.check(&format!("live:{i}"), current, 100));
        }
        assert_eq!(counter.bucket_count(), 43);

        // First pass flushes everything (nothing is pruned yet, because all
        // 43 buckets still have pending deltas).
        counter.flush_once().await;
        assert_eq!(counter.bucket_count(), 43);
        assert_eq!(store.call_count(), 43, "one write per key, not per request");

        // Second pass: the stale keys have pending == 0 and a window older
        // than 2 windows ⇒ dropped. The live keys survive.
        counter.flush_once().await;
        assert_eq!(
            counter.bucket_count(),
            3,
            "stale buckets are pruned; memory is bounded by the last two windows"
        );
        assert_eq!(
            store.call_count(),
            43,
            "pruning issues no additional writes"
        );

        // A stale key seen again simply starts a fresh bucket.
        assert!(counter.check("stale:0", current, 100));
        assert_eq!(counter.bucket_count(), 4);
    }

    /// The background flusher actually runs and converges without any manual
    /// `flush_once` — exercising `SharedRateLimitCounter::new`'s spawn path,
    /// the wake channel and the interval backstop.
    #[tokio::test]
    async fn background_flusher_converges_without_manual_flush() {
        let store = Arc::new(RecordingStore::default());
        let counter = SharedRateLimitCounter::new(
            SharedRateLimitConfig {
                enabled: true,
                sync_interval: Duration::from_millis(MIN_SYNC_INTERVAL_MS),
                ..SharedRateLimitConfig::default()
            },
            Arc::clone(&store) as Arc<dyn SharedRateLimitStore>,
        );
        let window = Utc::now();

        for _ in 0..6 {
            assert!(counter.check("bg:1.2.3.4", window, 100));
        }

        // Wait (generously) for the flusher to coalesce and write once.
        for _ in 0..100 {
            if store.call_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let calls = store.calls();
        assert!(
            !calls.is_empty(),
            "the background flusher must write without any manual flush"
        );
        assert_eq!(
            calls[0].2, 6,
            "the single write carries the coalesced delta"
        );
        assert_eq!(
            calls.len(),
            1,
            "6 requests produced exactly one datastore write"
        );
    }

    /// `from_env` defaults and clamping. Env vars are process-global, so this
    /// single test owns all of them (no parallel test may touch them).
    #[test]
    fn from_env_defaults_on_and_clamps_the_sync_interval() {
        // SAFETY: single-threaded test that owns these two env vars; no
        // other test in this module reads them.
        unsafe {
            std::env::remove_var("AXIAM__RATE_LIMIT__SHARED");
            std::env::remove_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS");
        }
        let cfg = SharedRateLimitConfig::from_env();
        assert!(cfg.enabled, "the shared layer defaults to ON");
        assert_eq!(
            cfg.sync_interval,
            Duration::from_millis(DEFAULT_SYNC_INTERVAL_MS)
        );

        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED", "off");
        }
        assert!(!SharedRateLimitConfig::from_env().enabled);
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED", "OFF");
        }
        assert!(!SharedRateLimitConfig::from_env().enabled);
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED", "on");
        }
        assert!(SharedRateLimitConfig::from_env().enabled);
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED", "garbage");
        }
        assert!(
            SharedRateLimitConfig::from_env().enabled,
            "an unrecognized value must not silently disable a security control"
        );

        // Clamping.
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS", "1");
        }
        assert_eq!(
            SharedRateLimitConfig::from_env().sync_interval,
            Duration::from_millis(MIN_SYNC_INTERVAL_MS)
        );
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS", "999999");
        }
        assert_eq!(
            SharedRateLimitConfig::from_env().sync_interval,
            Duration::from_millis(MAX_SYNC_INTERVAL_MS)
        );
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS", "not-a-number");
        }
        assert_eq!(
            SharedRateLimitConfig::from_env().sync_interval,
            Duration::from_millis(DEFAULT_SYNC_INTERVAL_MS)
        );
        unsafe {
            std::env::set_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS", "250");
        }
        assert_eq!(
            SharedRateLimitConfig::from_env().sync_interval,
            Duration::from_millis(250)
        );

        unsafe {
            std::env::remove_var("AXIAM__RATE_LIMIT__SHARED");
            std::env::remove_var("AXIAM__RATE_LIMIT__SHARED_SYNC_MS");
        }
    }

    /// Keys are spread across shards (a single-shard map would serialize
    /// every endpoint behind one mutex).
    #[test]
    fn keys_spread_across_shards() {
        let store = Arc::new(RecordingStore::default());
        let counter = counter_with(store);
        let window = Utc::now();
        for i in 0..256 {
            assert!(counter.check(&format!("endpoint:{i}"), window, 1000));
        }
        let occupied = counter
            .inner
            .shards
            .iter()
            .filter(|s| !lock_shard(s).is_empty())
            .count();
        assert!(
            occupied > SHARD_COUNT / 2,
            "256 keys should occupy most of the {SHARD_COUNT} shards, occupied={occupied}"
        );
        assert_eq!(counter.bucket_count(), 256);
    }

    /// A real `SurrealRateLimitBucketRepository` satisfies the store trait
    /// and drives the counter end to end — this is the wiring both callers
    /// use, and the cross-replica test with a REAL in-memory SurrealDB.
    #[tokio::test]
    async fn two_counters_over_one_surrealdb_converge() {
        use surrealdb::Surreal;
        use surrealdb::engine::local::Mem;

        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();

        let store_a: Arc<dyn SharedRateLimitStore> =
            Arc::new(SurrealRateLimitBucketRepository::new(db.clone()));
        let store_b: Arc<dyn SharedRateLimitStore> =
            Arc::new(SurrealRateLimitBucketRepository::new(db.clone()));

        let replica_a =
            SharedRateLimitCounter::without_flusher(SharedRateLimitConfig::default(), store_a);
        let replica_b =
            SharedRateLimitCounter::without_flusher(SharedRateLimitConfig::default(), store_b);

        let window = Utc::now();
        let key = "authz_check:203.0.113.42";
        const LIMIT: u32 = 6;

        // 3 requests per replica: 6 total = exactly the limit.
        for _ in 0..3 {
            assert!(replica_a.check(key, window, LIMIT));
            assert!(replica_b.check(key, window, LIMIT));
        }

        replica_a.flush_once().await;
        replica_b.flush_once().await;

        // B flushed last and therefore holds the combined count (6/6).
        assert!(
            !replica_b.check(key, window, LIMIT),
            "replica B must see replica A's 3 requests"
        );

        // A adopted the store value as of ITS flush (3), so it admits the
        // bounded overshoot before converging on its next pass.
        assert!(replica_a.check(key, window, LIMIT));
        replica_a.flush_once().await;
        assert!(
            !replica_a.check(key, window, LIMIT),
            "replica A must see replica B's 3 requests after its next flush"
        );

        // ONE shared row holds the combined count (3 + 3 + A's 1 overshoot),
        // not two independent per-replica counts of 3.
        let repo = SurrealRateLimitBucketRepository::new(db);
        assert_eq!(
            repo.increment_by(key, window, 0).await.unwrap(),
            7,
            "one shared row holds the combined count"
        );
    }
}
