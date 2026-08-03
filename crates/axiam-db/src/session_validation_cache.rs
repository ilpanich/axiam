//! Short-TTL, process-local cache of session-validity checks (I6).
//!
//! # The problem this solves
//!
//! Access tokens are stateless EdDSA JWTs, so revoking a session (deleting its
//! `session` row) has no effect unless every authenticated request re-checks
//! that the session behind the token's `jti` still exists and has not expired
//! (D-15 / REQ-7). `axiam-api-rest`'s `AuthenticatedUser` extractor does exactly
//! that, which costs **one SurrealDB read per authenticated request** —
//! including on `POST /api/v1/authz/check`, the hottest authorization route.
//!
//! That read is what made the D7 decision cache look asymmetric in benchmark
//! run 4: turning the cache on took gRPC checks from 887 to 11 598 req/s
//! (13.1×) but REST checks only from 753 to 791 (+5%). The decision cache
//! removes the *authorization* round-trips; it cannot remove the
//! *authentication* one, and the gRPC surface has no equivalent read (its
//! interceptor validates the JWT signature and stops — see
//! `crates/axiam-api-grpc/src/middleware/auth.rs`).
//!
//! # What is cached, and the staleness bound
//!
//! Only **positive** results are cached: "session `(tenant, id)` existed and was
//! unexpired at time `t`, and belongs to user `u`". A negative result is never
//! cached — a missing session must stay a DB read, so a freshly created session
//! is usable immediately and a revoked one can never be resurrected by a stale
//! negative entry.
//!
//! Entries carry the session's own `expires_at`, so an entry can never outlive
//! the session it describes: expiry is enforced exactly, not approximated by the
//! TTL. The TTL bounds the *other* direction — how long a **revoked** session
//! can still be served as valid.
//!
//! # Invalidation discipline (read before changing anything)
//!
//! This cache lives **inside** [`crate::repository::SurrealSessionRepository`],
//! not beside it, precisely so invalidation cannot be forgotten: every write
//! path that can remove a session (`invalidate`, `consume`,
//! `invalidate_user_sessions`, `invalidate_user_sessions_except`,
//! `cleanup_expired`) drops the affected entries in the same call. There is no
//! second place a session row can be deleted from.
//!
//! Consequently, on a **single replica** revocation is immediate and the TTL is
//! only a backstop for an out-of-band DB write. On **two or more replicas** a
//! logout handled by replica A does not reach replicas B…N, whose entries stay
//! valid for at most `ttl`. The worst-case revocation latency for a
//! multi-replica deployment is therefore `ttl`, exactly like the D7 decision
//! cache — and for the same reason (no cross-replica invalidation channel
//! exists).
//!
//! This is why the cache is **opt-in and disabled by default**
//! (`AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`, default `0` = off). A
//! deployment that has already accepted the decision cache's ≤TTL revocation
//! window loses nothing by enabling it; a deployment that has not must decide
//! deliberately.
//!
//! # Structure
//!
//! A fixed array of independently-locked stripes keyed by `session_id`, each
//! holding a `HashMap<(tenant, session), Entry>` plus a `by_user` index so a
//! whole-user invalidation is O(that user's cached sessions) rather than
//! O(stripe). Capacity is bounded per stripe with FIFO eviction; the cache is a
//! latency optimisation, so dropping entries under pressure is always safe.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Number of independently-locked stripes.
///
/// Sessions spread evenly over stripes by `session_id`, so unrelated users
/// never contend. Sixteen matches the D7 decision cache's striping.
const STRIPE_COUNT: usize = 16;

/// Maximum live entries per stripe (≈ `STRIPE_COUNT × this` overall) before
/// FIFO eviction kicks in. 4 096 × 16 ≈ 65 k cached sessions ≈ a few MiB.
const MAX_ENTRIES_PER_STRIPE: usize = 4_096;

/// Cache key — a session is only ever looked up together with its tenant, and
/// including the tenant makes cross-tenant confusion impossible by construction.
type Key = (Uuid, Uuid);

#[derive(Debug, Clone)]
struct Entry {
    /// The owning user, so `invalidate_user` can find this entry.
    user_id: Uuid,
    /// The session's own expiry, copied from the row. Enforced exactly.
    expires_at: DateTime<Utc>,
    /// When this entry was written, for the TTL backstop.
    inserted_at: Instant,
}

#[derive(Default)]
struct Stripe {
    entries: HashMap<Key, Entry>,
    by_user: HashMap<(Uuid, Uuid), HashSet<Key>>,
    order: VecDeque<Key>,
}

impl Stripe {
    fn insert(&mut self, key: Key, entry: Entry) {
        let user_key = (key.0, entry.user_id);
        if let Some(previous) = self.entries.insert(key, entry) {
            // Re-insert of a live key: drop the stale by_user link if the row
            // somehow changed owner (it cannot today, but the map must not leak).
            let previous_user_key = (key.0, previous.user_id);
            if previous_user_key != user_key
                && let Some(set) = self.by_user.get_mut(&previous_user_key)
            {
                set.remove(&key);
                if set.is_empty() {
                    self.by_user.remove(&previous_user_key);
                }
            }
        } else {
            self.order.push_back(key);
        }
        self.by_user.entry(user_key).or_default().insert(key);

        while self.entries.len() > MAX_ENTRIES_PER_STRIPE {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.remove(oldest);
        }
    }

    fn remove(&mut self, key: Key) {
        if let Some(entry) = self.entries.remove(&key) {
            let user_key = (key.0, entry.user_id);
            if let Some(set) = self.by_user.get_mut(&user_key) {
                set.remove(&key);
                if set.is_empty() {
                    self.by_user.remove(&user_key);
                }
            }
        }
    }
}

/// Positive-only, TTL-bounded cache of session-validity checks.
///
/// See the module docs for the invalidation contract and the staleness bound.
pub struct SessionValidationCache {
    stripes: Vec<Mutex<Stripe>>,
    ttl: Duration,
}

impl std::fmt::Debug for SessionValidationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionValidationCache")
            .field("ttl", &self.ttl)
            .field("stripes", &self.stripes.len())
            .finish()
    }
}

impl SessionValidationCache {
    /// Build a cache whose entries are honoured for at most `ttl`.
    ///
    /// A zero `ttl` produces a cache that never returns a hit — callers should
    /// prefer not attaching a cache at all, but this keeps a misconfiguration
    /// harmless rather than silently long-lived.
    pub fn new(ttl: Duration) -> Self {
        Self {
            stripes: (0..STRIPE_COUNT)
                .map(|_| Mutex::new(Stripe::default()))
                .collect(),
            ttl,
        }
    }

    /// The configured staleness bound for revocations that this process did not
    /// itself perform.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn stripe(&self, session_id: Uuid) -> &Mutex<Stripe> {
        let idx = (session_id.as_u128() as usize) % STRIPE_COUNT;
        &self.stripes[idx]
    }

    /// Look up a previously-recorded *positive* validity result.
    ///
    /// Returns `Some(true)` only when the entry is younger than the TTL **and**
    /// the session's own `expires_at` is still in the future. Never returns
    /// `Some(false)`: negatives are not cached, so a miss always means "ask the
    /// database".
    pub fn get(&self, tenant_id: Uuid, session_id: Uuid) -> Option<bool> {
        if self.ttl.is_zero() {
            return None;
        }
        let key = (tenant_id, session_id);
        let mut stripe = self.stripe(session_id).lock().ok()?;
        let entry = stripe.entries.get(&key)?;

        if entry.inserted_at.elapsed() >= self.ttl || entry.expires_at <= Utc::now() {
            stripe.remove(key);
            return None;
        }
        Some(true)
    }

    /// Record that `session_id` was observed alive, owned by `user_id` and
    /// expiring at `expires_at`.
    ///
    /// Callers must only call this for a session they just read as valid.
    pub fn insert_valid(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) {
        if self.ttl.is_zero() || expires_at <= Utc::now() {
            return;
        }
        let key = (tenant_id, session_id);
        if let Ok(mut stripe) = self.stripe(session_id).lock() {
            stripe.insert(
                key,
                Entry {
                    user_id,
                    expires_at,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    /// Drop one session's entry — called from every single-session delete path.
    pub fn invalidate(&self, tenant_id: Uuid, session_id: Uuid) {
        if let Ok(mut stripe) = self.stripe(session_id).lock() {
            stripe.remove((tenant_id, session_id));
        }
    }

    /// Drop every cached session of one user — called from the bulk delete
    /// paths (password change, password reset, MFA reset, admin revoke).
    ///
    /// `except` keeps a single session alive, mirroring
    /// `invalidate_user_sessions_except`.
    pub fn invalidate_user(&self, tenant_id: Uuid, user_id: Uuid, except: Option<Uuid>) {
        let user_key = (tenant_id, user_id);
        for stripe in &self.stripes {
            let Ok(mut stripe) = stripe.lock() else {
                continue;
            };
            let Some(keys) = stripe.by_user.get(&user_key).cloned() else {
                continue;
            };
            for key in keys {
                if except == Some(key.1) {
                    continue;
                }
                stripe.remove(key);
            }
        }
    }

    /// Drop every cached session of one tenant — the blunt fallback used by
    /// `cleanup_expired`, which deletes by predicate rather than by id.
    pub fn invalidate_tenant(&self, tenant_id: Uuid) {
        for stripe in &self.stripes {
            let Ok(mut stripe) = stripe.lock() else {
                continue;
            };
            let doomed: Vec<Key> = stripe
                .entries
                .keys()
                .copied()
                .filter(|(t, _)| *t == tenant_id)
                .collect();
            for key in doomed {
                stripe.remove(key);
            }
        }
    }

    /// Number of live entries — test/observability helper.
    pub fn len(&self) -> usize {
        self.stripes
            .iter()
            .filter_map(|s| s.lock().ok())
            .map(|s| s.entries.len())
            .sum()
    }

    /// Whether the cache currently holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::hours(1)
    }

    #[test]
    fn a_hit_requires_an_insert() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t, s, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(cache.get(t, s), None, "an unseen session must miss");
        cache.insert_valid(t, s, u, future());
        assert_eq!(cache.get(t, s), Some(true));
    }

    #[test]
    fn a_zero_ttl_cache_never_hits() {
        let cache = SessionValidationCache::new(Duration::ZERO);
        let (t, s, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, s, u, future());
        assert_eq!(cache.get(t, s), None);
        assert!(cache.is_empty(), "a zero-TTL cache must not even store");
    }

    #[test]
    fn an_already_expired_session_is_never_stored() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t, s, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, s, u, Utc::now() - chrono::Duration::seconds(1));
        assert_eq!(cache.get(t, s), None);
    }

    #[test]
    fn the_sessions_own_expiry_beats_the_ttl() {
        // TTL is long, but the session expires in the past → must not hit.
        let cache = SessionValidationCache::new(Duration::from_secs(3600));
        let (t, s, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, s, u, future());
        // Force the stored expiry into the past, simulating time passing.
        {
            let mut stripe = cache.stripe(s).lock().unwrap();
            stripe.entries.get_mut(&(t, s)).unwrap().expires_at =
                Utc::now() - chrono::Duration::seconds(1);
        }
        assert_eq!(cache.get(t, s), None);
        assert!(
            cache.is_empty(),
            "the expired entry must be evicted on read"
        );
    }

    #[test]
    fn ttl_expiry_evicts() {
        let cache = SessionValidationCache::new(Duration::from_millis(1));
        let (t, s, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, s, u, future());
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get(t, s), None);
    }

    #[test]
    fn invalidate_drops_exactly_one_session() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t, u) = (Uuid::new_v4(), Uuid::new_v4());
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, a, u, future());
        cache.insert_valid(t, b, u, future());
        cache.invalidate(t, a);
        assert_eq!(cache.get(t, a), None);
        assert_eq!(cache.get(t, b), Some(true));
    }

    #[test]
    fn invalidate_user_drops_all_that_users_sessions() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let t = Uuid::new_v4();
        let (u1, u2) = (Uuid::new_v4(), Uuid::new_v4());
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, a, u1, future());
        cache.insert_valid(t, b, u1, future());
        cache.insert_valid(t, c, u2, future());
        cache.invalidate_user(t, u1, None);
        assert_eq!(cache.get(t, a), None);
        assert_eq!(cache.get(t, b), None);
        assert_eq!(cache.get(t, c), Some(true), "another user is untouched");
    }

    #[test]
    fn invalidate_user_honours_the_except_session() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t, u) = (Uuid::new_v4(), Uuid::new_v4());
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t, a, u, future());
        cache.insert_valid(t, b, u, future());
        cache.invalidate_user(t, u, Some(b));
        assert_eq!(cache.get(t, a), None);
        assert_eq!(cache.get(t, b), Some(true));
    }

    /// Tenant isolation: the same session UUID under a different tenant is a
    /// different key and must not be served from another tenant's entry.
    #[test]
    fn entries_are_tenant_scoped() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t1, t2) = (Uuid::new_v4(), Uuid::new_v4());
        let (s, u) = (Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t1, s, u, future());
        assert_eq!(cache.get(t1, s), Some(true));
        assert_eq!(
            cache.get(t2, s),
            None,
            "a session id must never resolve under a foreign tenant"
        );
    }

    #[test]
    fn invalidate_tenant_drops_only_that_tenant() {
        let cache = SessionValidationCache::new(Duration::from_secs(5));
        let (t1, t2) = (Uuid::new_v4(), Uuid::new_v4());
        let (a, b, u) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        cache.insert_valid(t1, a, u, future());
        cache.insert_valid(t2, b, u, future());
        cache.invalidate_tenant(t1);
        assert_eq!(cache.get(t1, a), None);
        assert_eq!(cache.get(t2, b), Some(true));
    }

    #[test]
    fn a_stripe_is_capacity_bounded() {
        let cache = SessionValidationCache::new(Duration::from_secs(60));
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        // Fill one stripe well past its cap by forcing the stripe index.
        let mut inserted = 0usize;
        let mut candidate = 0u128;
        while inserted < MAX_ENTRIES_PER_STRIPE + 64 {
            let s = Uuid::from_u128(candidate);
            candidate += 1;
            if !(s.as_u128() as usize).is_multiple_of(STRIPE_COUNT) {
                continue;
            }
            cache.insert_valid(t, s, u, future());
            inserted += 1;
        }
        let live = cache
            .stripe(Uuid::from_u128(0))
            .lock()
            .unwrap()
            .entries
            .len();
        assert!(
            live <= MAX_ENTRIES_PER_STRIPE,
            "stripe must stay bounded, held {live}"
        );
    }
}
