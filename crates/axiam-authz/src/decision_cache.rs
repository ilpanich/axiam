//! Per-tenant cache of effective-permission evaluations (D7).
//!
//! # What this caches
//!
//! A [`DecisionCache`] memoizes the full [`AccessDecision`] (Allow, or Deny
//! *with its exact reason*) for a `(tenant_id, subject, resource, action,
//! scope)` tuple, so a repeated check can skip the 3–4 sequential SurrealDB
//! round-trips the engine would otherwise issue (see the D6 tuning report).
//!
//! The cache is **opt-in** and feature-flagged: [`AuthorizationEngine`] only
//! consults it when one has been attached via
//! [`AuthorizationEngine::with_decision_cache`], which `axiam-server` does only
//! when `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`. When absent, the engine's
//! code path is byte-for-byte identical to today (zero behaviour change).
//!
//! [`AuthorizationEngine`]: crate::engine::AuthorizationEngine
//! [`AuthorizationEngine::with_decision_cache`]: crate::engine::AuthorizationEngine::with_decision_cache
//!
//! # Security property (CRITICAL — read before changing invalidation)
//!
//! AXIAM's RBAC is **default-deny with deny-override**: an absent grant
//! refuses, an `effect: Allow` grant permits, and an `effect: Deny` grant
//! refuses and **beats every allow**, at any depth of the hierarchy (CLAUDE.md;
//! SEC-040 closed by B1; precedence table in
//! `claude_dev/deny-override-design.md`).
//!
//! The two staleness directions are still NOT equally dangerous, but note *why*
//! — the reason changed when B1 landed and the distinction matters below:
//!
//! - A **stale DENY** is *safe* because a deny is the restrictive outcome: the
//!   subject is momentarily under-privileged, never over-privileged. (Before
//!   B1 this was phrased as a consequence of the engine being allow-wins. It is
//!   not — it follows from deny being restrictive, which is why it survived
//!   the change.)
//! - A **stale ALLOW** is *dangerous*: a subject keeps access they no longer
//!   have. This is the direction we must protect against, and TTL alone is not
//!   enough.
//!
//! ## What B1 changed about which mutations need a hook
//!
//! Under the pre-B1 additive model, "narrowing" and "removing" were the same
//! set: **adding** a grant could only ever widen, so an addition was safe to
//! leave stale. That is no longer true. Granting a role an `effect: Deny`
//! permission is an *addition* that **narrows**, and a cached allow that
//! outlives it is a subject exercising access an administrator has explicitly
//! forbidden.
//!
//! **Do not reintroduce the "additions are safe, skip the flush" optimisation.**
//! It was sound under allow-wins and is a privilege bug under deny-override.
//! `permissions::grant_to_role` flushes the tenant for exactly this reason and
//! says so at the call site.
//!
//! Every mutation that can narrow access — role unassignment, grant removal,
//! role/permission deletion, group membership removal, resource
//! reparent/delete, **and any grant whose effect is `Deny`** — MUST invalidate
//! the affected entries **immediately** via
//! [`DecisionCache::invalidate_subject`] or [`DecisionCache::invalidate_tenant`]
//! — wired to the mutation path, not left to TTL. The REST handlers in
//! `axiam-api-rest` do exactly this through the `AuthzChecker` trait, and in
//! practice they invalidate on widening mutations too, which is what keeps the
//! deny case covered rather than depending on every author classifying their
//! mutation correctly.
//!
//! # Bounded staleness fallback
//!
//! Even if an invalidation event were somehow missed (a bug, a mutation path
//! that forgot to call invalidate, an out-of-band DB write), the damage is
//! **bounded by the TTL**: a stale allow can persist at most
//! `decision_cache_ttl_secs` (default 5 s) before TTL eviction forces a fresh
//! evaluation. The short default TTL is the belt to the invalidation hooks'
//! braces.
//!
//! # SCOPE OF "IMMEDIATE": process-local by default, cross-replica when enabled
//!
//! `axiam-server` builds **one in-process** `Arc<DecisionCache>` and shares it
//! across the REST, gRPC and AMQP engines of *that process*. Whether an
//! invalidation reaches the *other* replicas depends on one switch:
//!
//! ## (a) `decision_cache_broadcast_enabled = false` — the default
//!
//! There is no cross-replica invalidation channel. Consequently:
//!
//! - **Single replica:** the invalidation hooks above make revocation
//!   *immediate*; the TTL is only the fallback for a missed event.
//! - **Two or more replicas** (the Kubernetes deployment AXIAM targets): a
//!   revocation handled by replica A invalidates **only replica A**. Replicas
//!   B…N keep serving the pre-revocation decision from their own caches until
//!   their entry TTL-expires. The **worst-case revocation latency for the
//!   deployment is therefore `decision_cache_ttl_secs` (default 5 s)**, not
//!   zero — and it applies uniformly to `/api/v1/authz/check`, the gRPC
//!   `CheckAccess`, AMQP async authz *and* the internal `RequirePermission`
//!   guard on every admin endpoint, so an administrator's own privileges can
//!   also outlive their revocation by up to the TTL on other replicas.
//! - The failure is **silent**: a hit is byte-identical to a miss (same
//!   decision, same deny reason) and the audit log records the decision, not
//!   its provenance. Post-incident it is not possible to tell from the logs
//!   whether a given allow was served from cache.
//!
//! Operators running more than one replica must either enable the broadcast
//! channel below, accept a ≤ TTL revocation window, or leave the cache off.
//!
//! ## (b) `decision_cache_broadcast_enabled = true` — cross-replica fan-out
//!
//! Every [`DecisionCache::invalidate_tenant`] /
//! [`DecisionCache::invalidate_subject`] triggered by a mutation is *also*
//! published, HMAC-signed, to a **RabbitMQ fanout exchange**; every replica
//! binds its own exclusive auto-delete queue to that exchange and applies what
//! it receives. Revocation then propagates in broker-latency time on **every**
//! replica, not just the one that handled the mutation. See
//! [`crate::invalidation`] for the contract and
//! `axiam-amqp::cache_invalidation` for the shipped transport.
//!
//! Two properties of that mode are load-bearing and live in *this* type:
//!
//! 1. **The trust gate** ([`DecisionCache::set_trusted`]). A replica may only
//!    serve from this cache while it is actually receiving invalidations. If
//!    its consumer is not subscribed — at startup, or after the broker
//!    connection drops — the cache is marked **untrusted**: it is flushed,
//!    every read returns a miss and every write is discarded, so the replica
//!    silently falls back to full (correct, slower) DB evaluation instead of
//!    serving allows it can no longer invalidate. This is a deliberate
//!    availability/correctness trade: throughput degrades, decisions do not.
//!    The transition is logged at ERROR and counted in
//!    [`DecisionCacheStats::bypassed`] — the degraded mode is loud.
//! 2. **Trust follows connection liveness only.** Nothing an inbound *message*
//!    says can revoke trust (a stale or replayed but validly-signed capture
//!    must not become a lever for disabling every replica's cache). Only the
//!    consumer's own subscribe/stream state moves the flag.
//!
//! The publish side fails the other way: if the broadcast cannot be confirmed
//! by the broker, the mutation handler returns 503 rather than reporting a
//! revocation that only took effect on one replica.
//!
//! This split is stated next to the default in `docs/deployment/README.md`,
//! `docs/admin/README.md`, the [`crate::config::AuthzConfig`] docstrings and
//! `benchmarks/PUBLIC_BENCH_ANALYSIS.md`.
//!
//! # Internal structure (and why)
//!
//! ```text
//! stripes: [Mutex<HashMap<TenantId, TenantShard>>; STRIPE_COUNT]   // lock striping
//!                                     │
//!                                     ├── entries:    HashMap<Arc<SubKey>, Entry>
//!                                     ├── order:      VecDeque<(seq, Arc<SubKey>)>  // FIFO cap
//!                                     └── by_subject: HashMap<SubjectId, HashSet<Arc<SubKey>>>
//! ```
//!
//! Three properties this layout buys, each fixing a defect found in the G5
//! decision review (`claude_dev/decision-cache-decision.md` §2.5):
//!
//! 1. **`order` is bounded** (§2.5 finding *a*). A TTL-expired key is removed
//!    from `entries` on read but its `order` slot cannot be found and removed
//!    in O(1); the pre-fix code therefore appended a *second* slot when the key
//!    was re-inserted, and only ever popped slots when `entries.len()` exceeded
//!    the per-tenant cap — so a working set *below* the cap grew `order`
//!    without limit at the miss rate. Each slot now carries the entry's
//!    monotonic `seq`, which makes a superseded slot recognisable, and
//!    [`TenantShard::compact_if_needed`] rebuilds the queue whenever it exceeds
//!    `max(2 × entries.len(), COMPACT_FLOOR)`. That bounds `order` at ~2× the
//!    live set (and ≤ ~2× `max_entries_per_tenant`) while staying O(1)
//!    amortised: each compaction halves the queue, so the O(n) pass is paid at
//!    most once per n inserts.
//! 2. **`invalidate_subject` is O(entries for that subject)** (§2.5 finding
//!    *c*), not O(shard). The `by_subject` index gives the affected keys
//!    directly, so a role unassignment no longer scans up to
//!    `max_entries_per_tenant` entries while holding a lock the authz hot path
//!    needs. The index shares its keys with `entries` via `Arc<SubKey>`, so it
//!    costs one pointer per entry, not a second copy of the key.
//! 3. **Lock striping**: the map of tenants is split over `STRIPE_COUNT`
//!    independent mutexes keyed by `tenant_id`, so one tenant's invalidation or
//!    eviction no longer blocks *every* other tenant's checks — the pre-fix
//!    code took a single global mutex on every `get`/`insert`. A tenant's shard
//!    lives entirely within one stripe, which keeps the per-tenant FIFO cap
//!    exact (an intra-tenant striping would only be able to enforce the cap
//!    approximately). Contention *within* one tenant is therefore unchanged and
//!    remains the honest limit of this design: a single-tenant deployment still
//!    serialises its cache accesses, which is why the K-sweep in the decision
//!    note measures cache-ON/OFF rather than assuming a win.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::types::{AccessDecision, AccessRequest};

/// Number of independent tenant-map mutexes. Fixed (not CPU-derived) so the
/// structure is deterministic across hosts and reproducible in benchmarks.
const STRIPE_COUNT: usize = 16;

/// Minimum queue length below which compaction is not worth its O(n) pass.
/// Keeps tiny tenants from compacting on every other insert.
const COMPACT_FLOOR: usize = 64;

/// Runtime configuration for the decision cache.
#[derive(Debug, Clone)]
pub struct DecisionCacheConfig {
    /// Time-to-live for a cached decision. After this elapses the entry is
    /// treated as a miss and re-evaluated. Bounds worst-case revocation
    /// latency if an invalidation event is ever missed — and, in a
    /// multi-replica deployment, bounds it on every replica that did not
    /// handle the mutation (see the module docs).
    pub ttl: Duration,
    /// Maximum number of live entries retained **per tenant**. When exceeded,
    /// the oldest entry (FIFO) for that tenant is evicted. Bounds memory so a
    /// hot tenant cannot grow the map without limit.
    pub max_entries_per_tenant: usize,
}

impl Default for DecisionCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(5),
            max_entries_per_tenant: 10_000,
        }
    }
}

/// The intra-tenant portion of the cache key: everything except `tenant_id`
/// (which selects the shard). Ordering mirrors the design-doc key
/// `(subject, resource, action, scope)`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct SubKey {
    subject_id: Uuid,
    resource_id: Uuid,
    action: String,
    scope: Option<String>,
}

impl SubKey {
    fn from_request(request: &AccessRequest) -> Self {
        Self {
            subject_id: request.subject_id,
            resource_id: request.resource_id,
            action: request.action.clone(),
            scope: request.scope.clone(),
        }
    }
}

/// A cached decision plus the metadata needed for TTL and FIFO bookkeeping.
struct Entry {
    decision: AccessDecision,
    inserted_at: Instant,
    /// Monotonic per-tenant insertion sequence. A queue slot is *live* only if
    /// its `seq` still matches the entry's; anything else is a superseded slot
    /// left behind by TTL expiry or invalidation and is dropped on compaction.
    seq: u64,
}

/// Observable counters for one point in time. Cheap to produce; intended for a
/// periodic log line or a metrics gauge, and used by the tests that assert the
/// cache really holds `max_entries_per_tenant` entries rather than silently
/// evicting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionCacheStats {
    /// Cumulative hits since construction.
    pub hits: u64,
    /// Cumulative misses since construction (includes TTL-expired reads).
    pub misses: u64,
    /// Live entries across every tenant (counts expired-but-not-yet-reaped
    /// entries, which are never *returned*).
    pub entries: usize,
    /// Tenants with at least one shard allocated.
    pub tenants: usize,
    /// Total FIFO queue slots across every tenant — the quantity that used to
    /// grow without bound. Expect ≤ ~2× `entries` (or `COMPACT_FLOOR`).
    pub queue_slots: usize,
    /// Cumulative reads short-circuited because the cache was **untrusted**
    /// (cross-replica invalidation enabled but this replica's consumer is not
    /// subscribed — see [`DecisionCache::set_trusted`]). These are also counted
    /// in `misses`, so `hits + misses` still equals total reads; `bypassed` is
    /// the subset that was refused rather than looked up. A non-zero and
    /// *rising* value means this replica is evaluating everything against the
    /// database because it cannot hear invalidations — the degraded mode is
    /// correct but slow, and this is the counter that says so.
    pub bypassed: u64,
    /// Whether the cache is currently trusted (i.e. actually serving). Always
    /// `true` when cross-replica invalidation is disabled.
    pub trusted: bool,
}

/// Per-tenant shard: the entry map, the FIFO order queue used for the size-cap
/// eviction, and the subject index used for targeted invalidation. Keeping
/// tenants in separate shards makes a per-tenant flush O(1) (drop the shard)
/// and keeps one tenant's churn from evicting another tenant's entries.
#[derive(Default)]
struct TenantShard {
    entries: HashMap<Arc<SubKey>, Entry>,
    /// Insertion order of *new* keys, for the bounded-size FIFO eviction. May
    /// hold superseded slots (TTL-expired or invalidated keys); those are
    /// recognised by a `seq` mismatch and dropped when popping or compacting.
    order: VecDeque<(u64, Arc<SubKey>)>,
    /// subject_id → its keys. Makes `invalidate_subject` proportional to the
    /// subject's own entries instead of the whole shard.
    by_subject: HashMap<Uuid, HashSet<Arc<SubKey>>>,
    next_seq: u64,
}

impl TenantShard {
    /// Read, honouring TTL. An expired entry is reaped in passing so it cannot
    /// be returned again.
    fn get(&mut self, key: &SubKey, now: Instant, ttl: Duration) -> Option<AccessDecision> {
        match self.entries.get(key) {
            Some(entry) if now.duration_since(entry.inserted_at) < ttl => {
                Some(entry.decision.clone())
            }
            Some(_) => {
                self.remove_entry(key);
                None
            }
            None => None,
        }
    }

    /// Remove a key from `entries` and the subject index. Its FIFO slot is left
    /// behind (it cannot be located in O(1)) and is reclaimed by compaction.
    fn remove_entry(&mut self, key: &SubKey) {
        if let Some((arc, _)) = self.entries.remove_entry(key) {
            self.unindex(&arc);
        }
    }

    fn unindex(&mut self, key: &Arc<SubKey>) {
        if let Some(set) = self.by_subject.get_mut(&key.subject_id) {
            set.remove(key);
            if set.is_empty() {
                self.by_subject.remove(&key.subject_id);
            }
        }
    }

    fn insert(
        &mut self,
        key: &SubKey,
        decision: AccessDecision,
        now: Instant,
        cfg: &DecisionCacheConfig,
    ) {
        // Re-insert of a still-present key: refresh value and timestamp in
        // place. It keeps its FIFO slot and `seq`, so no new slot is pushed —
        // this is the case the pre-fix code already handled correctly.
        if let Some(entry) = self.entries.get_mut(key) {
            entry.decision = decision;
            entry.inserted_at = now;
            return;
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let arc: Arc<SubKey> = Arc::new(key.clone());
        self.entries.insert(
            Arc::clone(&arc),
            Entry {
                decision,
                inserted_at: now,
                seq,
            },
        );
        self.by_subject
            .entry(arc.subject_id)
            .or_default()
            .insert(Arc::clone(&arc));
        self.order.push_back((seq, arc));

        // Enforce the per-tenant size cap: pop FIFO, skipping superseded slots,
        // until one *live* entry has been dropped or the queue drains.
        while self.entries.len() > cfg.max_entries_per_tenant {
            match self.order.pop_front() {
                Some((slot_seq, victim)) => {
                    if self.entries.get(&*victim).map(|e| e.seq) == Some(slot_seq) {
                        self.entries.remove(&*victim);
                        self.unindex(&victim);
                        break;
                    }
                    // else: superseded slot, keep popping.
                }
                None => break,
            }
        }

        self.compact_if_needed(now, cfg);
    }

    /// Reclaim superseded FIFO slots (and TTL-expired entries) once the queue
    /// has grown past ~2× the live set. Amortised O(1) per insert: a compaction
    /// leaves `order.len() == entries.len()`, so the next one cannot trigger
    /// until roughly `entries.len()` further inserts.
    ///
    /// This is the fix for the unbounded-`order` growth described in the module
    /// docs; without it a working set below `max_entries_per_tenant` never runs
    /// the cap loop and the queue grows at the miss rate, forever.
    fn compact_if_needed(&mut self, now: Instant, cfg: &DecisionCacheConfig) {
        let threshold = COMPACT_FLOOR.max(self.entries.len().saturating_mul(2));
        if self.order.len() <= threshold {
            return;
        }

        // Expired entries are already logically absent (a read would reap
        // them); drop them here so the live set — and therefore the queue
        // bound — reflects reality even for keys never read again.
        let expired: Vec<Arc<SubKey>> = self
            .entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.inserted_at) >= cfg.ttl)
            .map(|(k, _)| Arc::clone(k))
            .collect();
        for key in expired {
            self.entries.remove(&*key);
            self.unindex(&key);
        }

        let Self { entries, order, .. } = self;
        order.retain(|(slot_seq, key)| entries.get(&**key).map(|e| e.seq) == Some(*slot_seq));
    }

    /// Drop every entry for one subject. O(that subject's entries).
    fn invalidate_subject(&mut self, subject_id: Uuid) {
        if let Some(keys) = self.by_subject.remove(&subject_id) {
            for key in keys {
                self.entries.remove(&*key);
                // FIFO slots become superseded; compaction reclaims them.
            }
        }
    }
}

/// A concurrent, per-tenant, TTL + size-bounded cache of authorization
/// decisions. Cheap to clone-share behind an `Arc`.
///
/// See the [module docs](self) for the security rationale, the multi-replica
/// caveat and the internal structure.
pub struct DecisionCache {
    config: DecisionCacheConfig,
    /// Tenants split over independent mutexes; a tenant always lives in
    /// `stripes[stripe_index(tenant_id)]`.
    stripes: Vec<Mutex<HashMap<Uuid, TenantShard>>>,
    hits: AtomicU64,
    misses: AtomicU64,
    bypassed: AtomicU64,
    /// Whether this replica may serve from the cache at all. See
    /// [`Self::set_trusted`]; always `true` unless cross-replica invalidation
    /// is enabled and its consumer is disconnected.
    trusted: AtomicBool,
}

impl DecisionCache {
    /// Build a cache with the given configuration, **trusted** (the
    /// single-process behaviour: nothing else has to happen for it to serve).
    ///
    /// When cross-replica invalidation is enabled, `axiam-server` immediately
    /// calls `set_trusted(false)` on the fresh cache so it stays inert until
    /// the invalidation consumer has actually subscribed — see
    /// [`crate::config::AuthzConfig::build_decision_cache`].
    pub fn new(config: DecisionCacheConfig) -> Self {
        Self {
            config,
            stripes: (0..STRIPE_COUNT)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            bypassed: AtomicU64::new(0),
            trusted: AtomicBool::new(true),
        }
    }

    /// Whether the cache is currently allowed to serve.
    pub fn is_trusted(&self) -> bool {
        self.trusted.load(Ordering::Acquire)
    }

    /// Mark the cache trusted / untrusted, returning the **previous** value.
    ///
    /// This is the cross-replica degraded-mode switch (see the module docs).
    /// Only the invalidation consumer's own connection state may call it:
    /// `true` once it is subscribed and receiving, `false` the moment it is
    /// not (startup, subscribe failure, stream end, task drop).
    ///
    /// While untrusted:
    /// * [`Self::get`] returns `None` for every request and counts a
    ///   [`DecisionCacheStats::bypassed`] read, so the engine falls back to a
    ///   full database evaluation — correct, just slower. It never serves an
    ///   allow it can no longer invalidate.
    /// * [`Self::insert`] discards, so nothing accumulates during the outage
    ///   that would have to be reasoned about on recovery.
    ///
    /// **Every transition flushes the cache**, in both directions: entering
    /// the untrusted state drops decisions that may already be stale, and
    /// leaving it drops anything that could have been invalidated by a
    /// broadcast we were not there to receive. Recovery therefore starts from
    /// an empty, provably-fresh cache rather than from whatever survived.
    ///
    /// Transitions are logged (ERROR on losing trust, INFO on regaining it) —
    /// a silently-degraded cache would be exactly the failure this whole
    /// mechanism exists to prevent.
    pub fn set_trusted(&self, trusted: bool) -> bool {
        let previous = self.trusted.swap(trusted, Ordering::AcqRel);
        if previous == trusted {
            return previous;
        }
        // Flush on BOTH edges — see the doc comment.
        self.invalidate_all();
        if trusted {
            tracing::info!(
                "AuthZ decision cache TRUSTED again — cross-replica invalidation stream is live; \
                 cache flushed and re-enabled"
            );
        } else {
            tracing::error!(
                "AuthZ decision cache UNTRUSTED — cross-replica invalidation stream is NOT live; \
                 cache flushed and every check now falls back to full database evaluation \
                 (correct but slower) until the stream recovers"
            );
        }
        previous
    }

    /// Which mutex owns a tenant. UUIDv4 bytes are already uniformly
    /// distributed, so folding the halves is sufficient dispersion and costs
    /// nothing on the hot path.
    fn stripe_index(&self, tenant_id: Uuid) -> usize {
        let bits = tenant_id.as_u128();
        let folded = (bits as u64) ^ ((bits >> 64) as u64);
        (folded % STRIPE_COUNT as u64) as usize
    }

    fn stripe(&self, tenant_id: Uuid) -> std::sync::MutexGuard<'_, HashMap<Uuid, TenantShard>> {
        self.stripes[self.stripe_index(tenant_id)]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Look up a cached decision for `request`. Returns `None` on a miss or an
    /// expired entry (which is evicted in passing). Records a hit/miss.
    ///
    /// Returns `None` unconditionally while the cache is **untrusted** (see
    /// [`Self::set_trusted`]), counting the read as both a miss and a
    /// [`DecisionCacheStats::bypassed`].
    pub fn get(&self, request: &AccessRequest) -> Option<AccessDecision> {
        if !self.is_trusted() {
            self.bypassed.fetch_add(1, Ordering::Relaxed);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let key = SubKey::from_request(request);
        let now = Instant::now();
        let decision = {
            let mut stripe = self.stripe(request.tenant_id);
            stripe
                .get_mut(&request.tenant_id)
                .and_then(|shard| shard.get(&key, now, self.config.ttl))
        };
        if decision.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        decision
    }

    /// Insert (or refresh) the decision for `request`, stamping it `now`.
    ///
    /// Discarded while the cache is **untrusted** (see [`Self::set_trusted`]),
    /// so an outage cannot accumulate entries whose freshness nobody can
    /// vouch for.
    pub fn insert(&self, request: &AccessRequest, decision: AccessDecision) {
        if !self.is_trusted() {
            return;
        }
        let key = SubKey::from_request(request);
        let now = Instant::now();
        let mut stripe = self.stripe(request.tenant_id);
        stripe
            .entry(request.tenant_id)
            .or_default()
            .insert(&key, decision, now, &self.config);
    }

    /// Drop **every** cached decision for a tenant. The conservative,
    /// always-correct invalidation: after this, no decision for `tenant_id`
    /// can be served stale. Used for coarse mutations whose affected-subject
    /// set is not known without a DB query (grant revoke, role/permission
    /// delete, role/permission update, group-role unassignment, resource
    /// reparent/delete).
    pub fn invalidate_tenant(&self, tenant_id: Uuid) {
        let mut stripe = self.stripe(tenant_id);
        stripe.remove(&tenant_id);
    }

    /// Drop every cached decision for a single subject within a tenant. The
    /// targeted invalidation used when a mutation changes exactly one
    /// subject's effective permissions (user role unassignment, group
    /// membership removal) — see the module security note.
    ///
    /// Cost is proportional to **that subject's** cached entries (via the
    /// `by_subject` index), not to the tenant shard, and it holds only the
    /// stripe that owns `tenant_id` — other tenants' checks are unaffected.
    pub fn invalidate_subject(&self, tenant_id: Uuid, subject_id: Uuid) {
        let mut stripe = self.stripe(tenant_id);
        if let Some(shard) = stripe.get_mut(&tenant_id) {
            shard.invalidate_subject(subject_id);
        }
    }

    /// Drop the entire cache (all tenants). Provided for completeness /
    /// administrative flush; not on any hot path.
    pub fn invalidate_all(&self) {
        for stripe in &self.stripes {
            stripe.lock().unwrap_or_else(|p| p.into_inner()).clear();
        }
    }

    /// Cumulative (hits, misses) since construction — for observability/tests.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// A full counter snapshot, including the live entry count and the FIFO
    /// queue length. `axiam-server` logs this periodically when the cache is
    /// enabled so an operator (or a benchmark) can verify how many entries the
    /// cache actually holds — the pre-fix code exposed no way to tell a full
    /// cache from one that was silently evicting.
    pub fn snapshot(&self) -> DecisionCacheStats {
        let (hits, misses) = self.stats();
        let mut entries = 0usize;
        let mut tenants = 0usize;
        let mut queue_slots = 0usize;
        for stripe in &self.stripes {
            let guard = stripe.lock().unwrap_or_else(|p| p.into_inner());
            tenants += guard.len();
            for shard in guard.values() {
                entries += shard.entries.len();
                queue_slots += shard.order.len();
            }
        }
        DecisionCacheStats {
            hits,
            misses,
            entries,
            tenants,
            queue_slots,
            bypassed: self.bypassed.load(Ordering::Relaxed),
            trusted: self.is_trusted(),
        }
    }

    /// Total live entries across all tenants (test/observability helper; also
    /// counts not-yet-reaped expired entries).
    pub fn len(&self) -> usize {
        self.snapshot().entries
    }

    /// Live entries for one tenant.
    pub fn tenant_len(&self, tenant_id: Uuid) -> usize {
        self.stripe(tenant_id)
            .get(&tenant_id)
            .map(|s| s.entries.len())
            .unwrap_or(0)
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(tenant: Uuid, subject: Uuid, resource: Uuid, action: &str) -> AccessRequest {
        AccessRequest {
            tenant_id: tenant,
            subject_id: subject,
            action: action.to_string(),
            resource_id: resource,
            scope: None,
        }
    }

    fn cfg(ttl: Duration, max_entries_per_tenant: usize) -> DecisionCacheConfig {
        DecisionCacheConfig {
            ttl,
            max_entries_per_tenant,
        }
    }

    #[test]
    fn hit_returns_inserted_decision() {
        let cache = DecisionCache::new(DecisionCacheConfig::default());
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let r = Uuid::new_v4();
        let request = req(t, s, r, "read");

        assert!(cache.get(&request).is_none());
        cache.insert(&request, AccessDecision::Allow);
        assert_eq!(cache.get(&request), Some(AccessDecision::Allow));

        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn deny_reason_is_preserved_verbatim() {
        let cache = DecisionCache::new(DecisionCacheConfig::default());
        let request = req(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "read");
        let deny = AccessDecision::Deny("no permission grants action 'read'".into());
        cache.insert(&request, deny.clone());
        assert_eq!(cache.get(&request), Some(deny));
    }

    #[test]
    fn distinct_actions_and_scopes_are_distinct_keys() {
        let cache = DecisionCache::new(DecisionCacheConfig::default());
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let r = Uuid::new_v4();
        let read = req(t, s, r, "read");
        let write = req(t, s, r, "write");
        let mut scoped = read.clone();
        scoped.scope = Some("field:email".into());

        cache.insert(&read, AccessDecision::Allow);
        cache.insert(&write, AccessDecision::Deny("nope".into()));
        assert_eq!(cache.get(&read), Some(AccessDecision::Allow));
        assert_eq!(cache.get(&write), Some(AccessDecision::Deny("nope".into())));
        // A scoped variant of the same action/resource is a different key.
        assert!(cache.get(&scoped).is_none());
    }

    #[test]
    fn ttl_expiry_forces_miss() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_millis(30),
            max_entries_per_tenant: 100,
        });
        let request = req(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "read");
        cache.insert(&request, AccessDecision::Allow);
        assert_eq!(cache.get(&request), Some(AccessDecision::Allow));
        std::thread::sleep(Duration::from_millis(45));
        assert!(cache.get(&request).is_none(), "entry must expire after TTL");
    }

    #[test]
    fn invalidate_subject_drops_only_that_subject() {
        let cache = DecisionCache::new(DecisionCacheConfig::default());
        let t = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let r = Uuid::new_v4();
        let r1 = req(t, s1, r, "read");
        let r2 = req(t, s2, r, "read");
        cache.insert(&r1, AccessDecision::Allow);
        cache.insert(&r2, AccessDecision::Allow);

        cache.invalidate_subject(t, s1);
        assert!(cache.get(&r1).is_none(), "revoked subject must miss");
        assert_eq!(
            cache.get(&r2),
            Some(AccessDecision::Allow),
            "other subject must be untouched"
        );
    }

    #[test]
    fn invalidate_tenant_drops_whole_tenant_only() {
        let cache = DecisionCache::new(DecisionCacheConfig::default());
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let a = req(t1, Uuid::new_v4(), Uuid::new_v4(), "read");
        let b = req(t1, Uuid::new_v4(), Uuid::new_v4(), "read");
        let c = req(t2, Uuid::new_v4(), Uuid::new_v4(), "read");
        cache.insert(&a, AccessDecision::Allow);
        cache.insert(&b, AccessDecision::Allow);
        cache.insert(&c, AccessDecision::Allow);

        cache.invalidate_tenant(t1);
        assert!(cache.get(&a).is_none());
        assert!(cache.get(&b).is_none());
        assert_eq!(cache.get(&c), Some(AccessDecision::Allow));
    }

    #[test]
    fn per_tenant_size_cap_evicts_fifo() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries_per_tenant: 2,
        });
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let r1 = req(t, s, Uuid::new_v4(), "read");
        let r2 = req(t, s, Uuid::new_v4(), "read");
        let r3 = req(t, s, Uuid::new_v4(), "read");
        cache.insert(&r1, AccessDecision::Allow);
        cache.insert(&r2, AccessDecision::Allow);
        cache.insert(&r3, AccessDecision::Allow); // evicts r1 (oldest)

        assert!(cache.get(&r1).is_none(), "oldest entry evicted by cap");
        assert_eq!(cache.get(&r2), Some(AccessDecision::Allow));
        assert_eq!(cache.get(&r3), Some(AccessDecision::Allow));
        assert!(cache.len() <= 2);
    }

    #[test]
    fn reinsert_same_key_does_not_grow_or_double_count_fifo() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries_per_tenant: 2,
        });
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let r1 = req(t, s, Uuid::new_v4(), "read");
        let r2 = req(t, s, Uuid::new_v4(), "read");
        cache.insert(&r1, AccessDecision::Allow);
        cache.insert(&r1, AccessDecision::Deny("changed".into())); // update in place
        cache.insert(&r2, AccessDecision::Allow);

        // r1 refreshed, r2 present, cap respected, r1 not evicted by its own re-insert.
        assert_eq!(cache.get(&r1), Some(AccessDecision::Deny("changed".into())));
        assert_eq!(cache.get(&r2), Some(AccessDecision::Allow));
        assert!(cache.len() <= 2);
        assert_eq!(cache.snapshot().queue_slots, 2, "no duplicate FIFO slots");
    }

    // ---------------------------------------------------------------------
    // Regression tests for the three G5 defects
    // (claude_dev/decision-cache-decision.md §2.5)
    // ---------------------------------------------------------------------

    /// Defect (a), the exact reported path: a key that TTL-expires, is read
    /// (which reaps it from `entries`) and is then re-inserted used to push a
    /// **second** FIFO slot, and the cap loop never ran because the working set
    /// stayed below `max_entries_per_tenant`. `order` therefore grew at the
    /// miss rate forever. It must now stay bounded.
    #[test]
    fn expired_then_reaccessed_key_does_not_grow_the_fifo_queue() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_millis(2),
            max_entries_per_tenant: 10_000, // the DEFAULT: far above the working set
        });
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let request = req(t, s, Uuid::new_v4(), "read");

        for _ in 0..200 {
            cache.insert(&request, AccessDecision::Allow);
            std::thread::sleep(Duration::from_millis(3));
            // Read after expiry: reaps the entry, leaving a superseded slot.
            assert!(cache.get(&request).is_none());
        }

        let snap = cache.snapshot();
        assert!(
            snap.entries <= 1,
            "working set is one key; got {} entries",
            snap.entries
        );
        assert!(
            snap.queue_slots <= COMPACT_FLOOR * 2,
            "FIFO queue must stay bounded for a working set below the cap \
             (200 expire/re-insert cycles left {} slots)",
            snap.queue_slots
        );
    }

    /// The same leak reached by a second route: a long-lived key pins the front
    /// of the queue (so front-only cleanup could never make progress) while a
    /// small working set churns behind it. Compaction must still bound the
    /// queue.
    #[test]
    fn churn_behind_a_pinned_front_entry_stays_bounded() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_millis(50),
            max_entries_per_tenant: 10_000,
        });
        let t = Uuid::new_v4();
        let pinned_subject = Uuid::new_v4();
        let churn_subject = Uuid::new_v4();
        // Inserted first, refreshed forever: never expires, never leaves the
        // front of the queue.
        let pinned = req(t, pinned_subject, Uuid::new_v4(), "pinned");
        cache.insert(&pinned, AccessDecision::Allow);

        // 40 keys, each re-inserted 20 times after being invalidated — every
        // re-insert is a fresh slot, exactly like a TTL-expiry cycle.
        let churn: Vec<AccessRequest> = (0..40)
            .map(|i| req(t, churn_subject, Uuid::new_v4(), &format!("act-{i}")))
            .collect();
        for _ in 0..20 {
            for r in &churn {
                cache.insert(r, AccessDecision::Allow);
            }
            cache.insert(&pinned, AccessDecision::Allow); // refresh, keeps it live
            cache.invalidate_subject(t, churn_subject); // leaves 40 slots behind
        }

        let snap = cache.snapshot();
        // 800 pushes happened; without compaction the queue would hold them all.
        assert!(
            snap.queue_slots <= 2 * COMPACT_FLOOR,
            "queue ({} slots) must stay bounded after 800 re-insert cycles \
             (live set: {} entries)",
            snap.queue_slots,
            snap.entries
        );
        assert_eq!(
            cache.get(&pinned),
            Some(AccessDecision::Allow),
            "the pinned entry must survive the churn"
        );
    }

    /// Defect (c): `invalidate_subject` must touch only the target subject's
    /// entries. The index is the mechanism; the observable proof is that a
    /// large shard survives intact apart from that subject, and that the
    /// operation is fast enough to be obviously not-O(shard).
    #[test]
    fn invalidate_subject_is_proportional_to_that_subject_only() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries_per_tenant: 20_000,
        });
        let t = Uuid::new_v4();
        let victim = Uuid::new_v4();
        let others: Vec<Uuid> = (0..99).map(|_| Uuid::new_v4()).collect();

        for i in 0..100 {
            cache.insert(
                &req(t, victim, Uuid::new_v4(), &format!("a{i}")),
                AccessDecision::Allow,
            );
        }
        for s in &others {
            for i in 0..100 {
                cache.insert(
                    &req(t, *s, Uuid::new_v4(), &format!("a{i}")),
                    AccessDecision::Allow,
                );
            }
        }
        assert_eq!(cache.tenant_len(t), 10_000);

        let started = Instant::now();
        cache.invalidate_subject(t, victim);
        let elapsed = started.elapsed();

        assert_eq!(
            cache.tenant_len(t),
            9_900,
            "exactly the victim's 100 entries must go"
        );
        // Generous bound: a full 10k-entry retain() scan is orders of magnitude
        // slower than removing 100 indexed keys, but the assertion stays loose
        // so it cannot flake on a loaded CI box.
        assert!(
            elapsed < Duration::from_millis(50),
            "invalidate_subject took {elapsed:?} — expected O(subject entries)"
        );
    }

    /// Memory bound, measured (plan H5 item 4): what a full cache actually
    /// costs in RSS, isolated from any server-level noise.
    ///
    /// The RSS figure is only meaningful when this test runs **alone** —
    /// `cargo test -p axiam-authz --lib
    /// decision_cache::tests::memory_footprint_at_the_default_cap_is_bounded
    /// -- --exact --nocapture` — because RSS never shrinks when an earlier
    /// test frees its heap, so a shared run reports a near-zero delta against
    /// an already-grown heap. The assertions below are order-independent; only
    /// the printed number needs isolation. Measured 2026-07-29:
    /// **+2 704 KiB for 10 000 entries ≈ 276 bytes/entry**.
    #[test]
    fn memory_footprint_at_the_default_cap_is_bounded() {
        // Plan H5 item 4, the in-process half: the K=10 000 server-RSS column
        // of a benchmark cannot separate the cache's own footprint from the
        // request path's, and on a rate-limit-clamped host it never reaches a
        // steady state at all. This measures the cache alone: RSS delta across
        // filling one tenant to the default 10 000-entry cap, with the request
        // objects created and dropped inside the loop so only what the cache
        // retains is counted.
        fn rss_kib() -> Option<u64> {
            let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
            let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
            Some(resident_pages * 4) // 4 KiB pages on every supported target
        }
        let Some(before) = rss_kib() else {
            eprintln!("skipping: /proc/self/statm unavailable on this platform");
            return;
        };

        let cfg = DecisionCacheConfig::default();
        let cap = cfg.max_entries_per_tenant;
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(600),
            ..cfg
        });
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        for i in 0..cap {
            cache.insert(
                &req(t, s, Uuid::new_v4(), &format!("action-{i}")),
                AccessDecision::Allow,
            );
        }
        let after = rss_kib().expect("statm readable a second time");
        let snap = cache.snapshot();
        // Order-independent invariants — these are what the K=10 000 memory
        // column was supposed to establish and could not: the cache really
        // holds its full cap (no silent eviction), and the FIFO queue carries
        // no duplicate slots.
        assert_eq!(snap.entries, cap, "the cap must be genuinely held");
        assert_eq!(
            snap.queue_slots, cap,
            "one queue slot per live entry, no duplicates"
        );

        let delta_kib = after.saturating_sub(before);
        eprintln!(
            "decision cache @ cap={cap}: RSS +{} KiB (~{} bytes/entry), \
             entries={}, queue_slots={}",
            delta_kib,
            (delta_kib * 1024) / cap as u64,
            snap.entries,
            snap.queue_slots
        );
        // Loose ceiling — this is a measurement, not a micro-benchmark; it only
        // has to refute "10 000 cached decisions cost hundreds of MiB". The
        // observed value is ~2-4 MiB.
        assert!(
            delta_kib < 32 * 1024,
            "10 000 cached decisions must not cost 32 MiB (measured {delta_kib} KiB)"
        );
    }

    /// Memory bound (plan H5 item 4): at the default cap the cache must really
    /// hold `max_entries_per_tenant` entries — a silent eviction would make the
    /// K=10 000 memory column meaningless.
    #[test]
    fn holds_the_full_default_cap_without_silent_eviction() {
        let cfg = DecisionCacheConfig::default();
        let cap = cfg.max_entries_per_tenant;
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(600), // no expiry during the test
            ..cfg
        });
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let keys: Vec<AccessRequest> = (0..cap)
            .map(|i| req(t, s, Uuid::new_v4(), &format!("act-{i}")))
            .collect();
        for k in &keys {
            cache.insert(k, AccessDecision::Allow);
        }

        let snap = cache.snapshot();
        assert_eq!(snap.entries, cap, "cache must hold the full cap");
        assert_eq!(cache.tenant_len(t), cap);
        assert!(
            snap.queue_slots <= 2 * cap,
            "queue slots {} exceed the 2x bound",
            snap.queue_slots
        );
        // Every key still readable — i.e. nothing was evicted behind our back.
        for k in &keys {
            assert_eq!(cache.get(k), Some(AccessDecision::Allow));
        }

        // One more distinct key must now evict exactly one (FIFO), never grow.
        cache.insert(
            &req(t, s, Uuid::new_v4(), "overflow"),
            AccessDecision::Allow,
        );
        assert_eq!(cache.tenant_len(t), cap, "cap must hold at cap+1 inserts");
    }

    /// Tenants must not collide across the lock stripes: distinct tenants keep
    /// independent entries and independent caps.
    #[test]
    fn tenants_are_isolated_across_stripes() {
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries_per_tenant: 2,
        });
        let subject = Uuid::new_v4();
        let resource = Uuid::new_v4();
        let tenants: Vec<Uuid> = (0..64).map(|_| Uuid::new_v4()).collect();
        for t in &tenants {
            cache.insert(&req(*t, subject, resource, "read"), AccessDecision::Allow);
        }
        for t in &tenants {
            assert_eq!(
                cache.get(&req(*t, subject, resource, "read")),
                Some(AccessDecision::Allow),
                "every tenant keeps its own entry"
            );
            assert_eq!(cache.tenant_len(*t), 1);
        }
        assert_eq!(cache.len(), tenants.len());

        // A flush of one tenant leaves the others alone even when they share a
        // stripe.
        cache.invalidate_tenant(tenants[0]);
        assert_eq!(cache.len(), tenants.len() - 1);
    }

    /// Concurrency smoke test: the striped structure must stay consistent under
    /// simultaneous readers, writers and invalidators.
    #[test]
    fn concurrent_access_is_consistent() {
        let cache = Arc::new(DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_millis(20),
            max_entries_per_tenant: 500,
        }));
        let tenants: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        let subjects: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();

        let handles: Vec<_> = (0..8)
            .map(|worker| {
                let cache = Arc::clone(&cache);
                let tenants = tenants.clone();
                let subjects = subjects.clone();
                std::thread::spawn(move || {
                    for i in 0..500 {
                        let t = tenants[i % tenants.len()];
                        let s = subjects[(i + worker) % subjects.len()];
                        let r = req(t, s, Uuid::new_v4(), "read");
                        cache.insert(&r, AccessDecision::Allow);
                        let _ = cache.get(&r);
                        if i % 97 == 0 {
                            cache.invalidate_subject(t, s);
                        }
                        if i % 251 == 0 {
                            cache.invalidate_tenant(t);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("worker panicked");
        }

        let snap = cache.snapshot();
        for t in &tenants {
            assert!(cache.tenant_len(*t) <= 500, "per-tenant cap must hold");
        }
        // Per tenant the queue is bounded by ~2x the cap (plus the floor);
        // 8 workers x 500 iterations = 4 000 inserts would otherwise pile up.
        assert!(
            snap.queue_slots <= tenants.len() * (2 * 500 + COMPACT_FLOOR),
            "queue slots {} unbounded relative to {} entries",
            snap.queue_slots,
            snap.entries
        );
    }

    // -----------------------------------------------------------------------
    // §4.2 — the cross-replica trust gate (degraded mode when the invalidation
    // stream is not live). These tests are the guarantee that a replica which
    // can no longer *hear* invalidations stops serving allows it can no longer
    // invalidate — the failure mode this whole mechanism exists to prevent.
    // -----------------------------------------------------------------------

    #[test]
    fn new_cache_is_trusted_by_default() {
        // Single-process behaviour is unchanged: nothing has to happen for a
        // freshly built cache to serve.
        let cache = DecisionCache::new(cfg(Duration::from_secs(60), 100));
        assert!(cache.is_trusted());
        assert!(cache.snapshot().trusted);
    }

    #[test]
    fn untrusted_cache_never_serves_a_previously_cached_allow() {
        let cache = DecisionCache::new(cfg(Duration::from_secs(600), 100));
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let r = req(t, s, Uuid::new_v4(), "read");
        cache.insert(&r, AccessDecision::Allow);
        assert!(
            matches!(cache.get(&r), Some(AccessDecision::Allow)),
            "precondition: a trusted cache serves the allow"
        );

        // Broker gone: the consumer flips the gate.
        cache.set_trusted(false);

        assert!(
            cache.get(&r).is_none(),
            "an untrusted replica must NOT serve a cached allow it can no longer invalidate"
        );
        assert!(
            cache.is_empty(),
            "losing trust flushes: entries that may already be stale are dropped"
        );
        let snap = cache.snapshot();
        assert!(!snap.trusted);
        assert_eq!(snap.bypassed, 1, "the degraded read is counted, not silent");
    }

    #[test]
    fn untrusted_cache_discards_inserts_so_nothing_accumulates() {
        let cache = DecisionCache::new(cfg(Duration::from_secs(600), 100));
        cache.set_trusted(false);
        let t = Uuid::new_v4();
        for i in 0..10 {
            cache.insert(
                &req(t, Uuid::new_v4(), Uuid::new_v4(), &format!("a{i}")),
                AccessDecision::Allow,
            );
        }
        assert!(
            cache.is_empty(),
            "an untrusted cache must not accumulate entries during the outage"
        );
        assert_eq!(cache.snapshot().bypassed, 0, "inserts are not reads");
    }

    #[test]
    fn regaining_trust_starts_from_an_empty_cache_and_serves_again() {
        let cache = DecisionCache::new(cfg(Duration::from_secs(600), 100));
        let t = Uuid::new_v4();
        let r = req(t, Uuid::new_v4(), Uuid::new_v4(), "read");

        cache.set_trusted(false);
        // Force an entry in behind the gate's back so we can prove the
        // trust-regained edge flushes too (belt and braces: the insert path
        // already refuses, so this is the only way to plant one).
        cache.set_trusted(true);
        cache.insert(&r, AccessDecision::Allow);
        assert!(cache.get(&r).is_some());
        cache.set_trusted(false);
        cache.set_trusted(true);
        assert!(
            cache.get(&r).is_none(),
            "recovery must start from a provably-fresh (empty) cache"
        );

        cache.insert(&r, AccessDecision::Allow);
        assert!(
            matches!(cache.get(&r), Some(AccessDecision::Allow)),
            "a re-trusted cache serves normally again"
        );
    }

    #[test]
    fn set_trusted_reports_the_previous_value_and_is_idempotent() {
        let cache = DecisionCache::new(cfg(Duration::from_secs(60), 100));
        let r = req(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "read");
        cache.insert(&r, AccessDecision::Allow);

        assert!(cache.set_trusted(true), "previous value was trusted");
        assert!(
            cache.get(&r).is_some(),
            "a no-op transition must not flush the cache"
        );
        assert!(cache.set_trusted(false), "previous value was trusted");
        assert!(!cache.set_trusted(false), "previous value was untrusted");
    }

    #[test]
    fn invalidation_still_applies_while_untrusted() {
        // Applying an invalidation to an untrusted cache is always safe and
        // must never panic or be refused — the consumer keeps draining.
        let cache = DecisionCache::new(cfg(Duration::from_secs(60), 100));
        cache.set_trusted(false);
        let t = Uuid::new_v4();
        cache.invalidate_tenant(t);
        cache.invalidate_subject(t, Uuid::new_v4());
        cache.invalidate_all();
        assert!(cache.is_empty());
    }
}
