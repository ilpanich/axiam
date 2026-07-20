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
//! AXIAM's RBAC is **additive, allow-wins, default-deny** (CLAUDE.md /
//! SEC-040). There is no deny-override. That asymmetry means the two staleness
//! directions are NOT equally dangerous:
//!
//! - A **stale DENY** is *safe*: it only costs a redundant re-evaluation; the
//!   subject is momentarily under-privileged, never over-privileged.
//! - A **stale ALLOW after a revocation** is *dangerous*: a subject keeps
//!   access they no longer have. This is the only direction we must protect
//!   against, and TTL alone is not enough.
//!
//! Therefore every mutation that can *narrow* access (role unassignment, grant
//! removal, role/permission deletion, group membership removal, resource
//! reparent/delete) MUST invalidate the affected entries **immediately** via
//! [`DecisionCache::invalidate_subject`] or [`DecisionCache::invalidate_tenant`]
//! — wired to the mutation path, not left to TTL. The REST handlers in
//! `axiam-api-rest` do exactly this through the `AuthzChecker` trait.
//!
//! # Bounded staleness fallback
//!
//! Even if an invalidation event were somehow missed (a bug, a mutation path
//! that forgot to call invalidate, an out-of-band DB write), the damage is
//! **bounded by the TTL**: a stale allow can persist at most
//! `decision_cache_ttl_secs` (default 5 s) before TTL eviction forces a fresh
//! evaluation. The short default TTL is the belt to the invalidation hooks'
//! braces.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::types::{AccessDecision, AccessRequest};

/// Runtime configuration for the decision cache.
#[derive(Debug, Clone)]
pub struct DecisionCacheConfig {
    /// Time-to-live for a cached decision. After this elapses the entry is
    /// treated as a miss and re-evaluated. Bounds worst-case revocation
    /// latency if an invalidation event is ever missed.
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
#[derive(Clone, PartialEq, Eq, Hash)]
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

/// Per-tenant shard: the entry map plus a FIFO order queue used only for
/// the size-cap eviction. Keeping tenants in separate shards makes a
/// per-tenant flush O(1) (drop the shard) and keeps one tenant's churn from
/// evicting another tenant's entries.
#[derive(Default)]
struct TenantShard {
    entries: HashMap<SubKey, (AccessDecision, Instant)>,
    /// Insertion order of *new* keys, for the bounded-size FIFO eviction. May
    /// contain keys already removed by TTL/invalidation; such stragglers are
    /// skipped when popping (they're simply absent from `entries`).
    order: VecDeque<SubKey>,
}

/// A concurrent, per-tenant, TTL + size-bounded cache of authorization
/// decisions. Cheap to clone-share behind an `Arc`.
///
/// See the [module docs](self) for the security rationale.
pub struct DecisionCache {
    config: DecisionCacheConfig,
    shards: Mutex<HashMap<Uuid, TenantShard>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DecisionCache {
    /// Build a cache with the given configuration.
    pub fn new(config: DecisionCacheConfig) -> Self {
        Self {
            config,
            shards: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached decision for `request`. Returns `None` on a miss or an
    /// expired entry (which is evicted in passing). Records a hit/miss.
    pub fn get(&self, request: &AccessRequest) -> Option<AccessDecision> {
        let key = SubKey::from_request(request);
        let now = Instant::now();
        let mut shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        let decision = shards.get_mut(&request.tenant_id).and_then(|shard| {
            match shard.entries.get(&key) {
                Some((decision, inserted_at)) => {
                    if now.duration_since(*inserted_at) >= self.config.ttl {
                        // Expired: evict now so we don't keep returning it.
                        shard.entries.remove(&key);
                        None
                    } else {
                        Some(decision.clone())
                    }
                }
                None => None,
            }
        });
        if decision.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        decision
    }

    /// Insert (or refresh) the decision for `request`, stamping it `now`.
    pub fn insert(&self, request: &AccessRequest, decision: AccessDecision) {
        let key = SubKey::from_request(request);
        let now = Instant::now();
        let mut shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        let shard = shards.entry(request.tenant_id).or_default();
        let is_new = !shard.entries.contains_key(&key);
        shard.entries.insert(key.clone(), (decision, now));
        if is_new {
            shard.order.push_back(key);
            // Enforce the per-tenant size cap. Pop FIFO, skipping keys already
            // gone (expired/invalidated), until we've dropped one live entry
            // or the queue drains.
            while shard.entries.len() > self.config.max_entries_per_tenant {
                match shard.order.pop_front() {
                    Some(old) => {
                        if shard.entries.remove(&old).is_some() {
                            break;
                        }
                        // else: stale order entry, keep popping.
                    }
                    None => break,
                }
            }
        }
    }

    /// Drop **every** cached decision for a tenant. The conservative,
    /// always-correct invalidation: after this, no decision for `tenant_id`
    /// can be served stale. Used for coarse mutations whose affected-subject
    /// set is not known without a DB query (grant revoke, role/permission
    /// delete, role/permission update, group-role unassignment, resource
    /// reparent/delete).
    pub fn invalidate_tenant(&self, tenant_id: Uuid) {
        let mut shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        shards.remove(&tenant_id);
    }

    /// Drop every cached decision for a single subject within a tenant. The
    /// targeted invalidation used when a mutation changes exactly one
    /// subject's effective permissions (user role unassignment, group
    /// membership removal) — see the module security note.
    pub fn invalidate_subject(&self, tenant_id: Uuid, subject_id: Uuid) {
        let mut shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(shard) = shards.get_mut(&tenant_id) {
            shard.entries.retain(|k, _| k.subject_id != subject_id);
            // `order` may now hold stragglers; they're skipped on pop.
        }
    }

    /// Drop the entire cache (all tenants). Provided for completeness /
    /// administrative flush; not on any hot path.
    pub fn invalidate_all(&self) {
        let mut shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        shards.clear();
    }

    /// Cumulative (hits, misses) since construction — for observability/tests.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    /// Total live entries across all tenants (test/observability helper; also
    /// counts not-yet-evicted expired entries).
    pub fn len(&self) -> usize {
        let shards = self.shards.lock().unwrap_or_else(|p| p.into_inner());
        shards.values().map(|s| s.entries.len()).sum()
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
    }
}
