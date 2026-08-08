//! Tiny TTL cache for the `tenant_id -> organization_id` mapping (A2/J2).
//!
//! # Why this exists
//!
//! `POST /api/v1/auth/refresh` reads the tenant record on **every** request,
//! for exactly one field. That read is a security fix, not an accident: NEW-1
//! found `org_id` being stamped into the rotated access token straight from
//! the client-supplied request body, so a valid refresh could mint a token
//! scoped to a foreign organization. Deriving `org_id` authoritatively from
//! the tenant record closed it — at the cost of one serialized datastore round
//! trip on the hottest rotation path in the product.
//!
//! Run 5 measured refresh at 545/s, p50 88.8 ms, against run 4's 839/s and
//! 47.5 ms: the entire distribution shifted right with tight medians in both
//! runs, which is what added serialized work looks like
//! (`claude_dev/improvement-after-run5-benchmark.md` A2/J2).
//!
//! This cache keeps the security property and drops the round trip. It caches
//! only the mapping, never authorization state.
//!
//! # Why caching *this* is safe
//!
//! A tenant's owning organization is set when the tenant is created and is not
//! re-parentable — there is no API that moves a tenant between organizations,
//! because doing so would silently re-scope every token, role grant and
//! certificate under it. So the cached value is not merely slow-changing, it
//! is immutable for the lifetime of the tenant.
//!
//! The TTL therefore is not a correctness mechanism for staleness; it exists
//! so that a **deleted** tenant stops being served from memory within a bounded
//! time, and so the map cannot grow without bound in a deployment that churns
//! tenants. Deletion is the only transition that matters here, and a rotated
//! access token for a deleted tenant fails at the next authorization check
//! regardless — the tenant's rows are gone.
//!
//! What this cache deliberately does **not** do: it never answers "does this
//! tenant exist" for anything except this mapping, and it is never consulted
//! on a path that decides access. A miss costs one read; a hit costs one hash.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::collections::HashMap;
use uuid::Uuid;

/// How long a mapping is served from memory before it is re-read.
///
/// Sized against the only transition that matters (tenant deletion): 60 s is
/// short enough that a deleted tenant stops being served promptly, and long
/// enough that a sustained refresh flood pays the tenant read once per minute
/// per tenant instead of once per request.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Upper bound on distinct tenants held in memory.
///
/// The map is bounded rather than merely TTL'd so that a caller enumerating
/// tenant ids cannot use this as a memory-growth primitive. At the cap the
/// cache stops accepting *new* entries until the next expiry sweep, which
/// degrades to today's behaviour (one read per request) rather than to
/// unbounded growth — a bounded cache that fails to a correct-but-slower path
/// is the right failure mode for something on an auth hot path.
const MAX_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    organization_id: Uuid,
    inserted_at: Instant,
}

/// Process-wide `tenant_id -> organization_id` cache.
///
/// Cheap to clone conceptually (held behind an `Arc` in `AppState`); a plain
/// `Mutex<HashMap<..>>` is deliberate over a sharded map: the critical section
/// is a hash lookup and a `Copy` read, and the entry count is bounded by the
/// tenant count, so contention here is orders of magnitude below the round
/// trip it replaces.
#[derive(Debug)]
pub struct TenantOrgCache {
    ttl: Duration,
    entries: Mutex<HashMap<Uuid, Entry>>,
}

impl Default for TenantOrgCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl TenantOrgCache {
    /// Build a cache with an explicit TTL (tests pin a short or zero one).
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cached organization for `tenant_id`, if present and not expired.
    pub fn get(&self, tenant_id: Uuid) -> Option<Uuid> {
        let mut guard = self.lock();
        let entry = guard.get(&tenant_id).copied()?;
        if entry.inserted_at.elapsed() >= self.ttl {
            guard.remove(&tenant_id);
            return None;
        }
        Some(entry.organization_id)
    }

    /// Record `tenant_id -> organization_id`.
    pub fn insert(&self, tenant_id: Uuid, organization_id: Uuid) {
        let mut guard = self.lock();
        if guard.len() >= MAX_ENTRIES && !guard.contains_key(&tenant_id) {
            // Sweep expired entries before refusing — a full map is usually a
            // stale map, not a genuinely 4 096-tenant one.
            let ttl = self.ttl;
            guard.retain(|_, e| e.inserted_at.elapsed() < ttl);
            if guard.len() >= MAX_ENTRIES {
                return;
            }
        }
        guard.insert(
            tenant_id,
            Entry {
                organization_id,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Drop a mapping (tenant deleted or re-read forced).
    pub fn invalidate(&self, tenant_id: Uuid) {
        self.lock().remove(&tenant_id);
    }

    /// Entries currently held — for tests and a future gauge.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock here means another thread panicked *while holding a
    /// hash map of tenant ids*. There is no invariant to protect: recovering
    /// the map is strictly better than propagating a panic onto an auth path.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_and_returns_the_mapping() {
        let cache = TenantOrgCache::default();
        let tenant = Uuid::new_v4();
        let org = Uuid::new_v4();

        assert_eq!(cache.get(tenant), None, "cold cache misses");
        cache.insert(tenant, org);
        assert_eq!(cache.get(tenant), Some(org));
    }

    #[test]
    fn expired_entries_are_not_served() {
        let cache = TenantOrgCache::new(Duration::from_nanos(1));
        let tenant = Uuid::new_v4();
        cache.insert(tenant, Uuid::new_v4());

        std::thread::sleep(Duration::from_millis(2));

        assert_eq!(cache.get(tenant), None, "expired entry must not be served");
        assert!(
            cache.is_empty(),
            "and must be dropped on the read that saw it"
        );
    }

    #[test]
    fn invalidate_drops_the_entry() {
        let cache = TenantOrgCache::default();
        let tenant = Uuid::new_v4();
        cache.insert(tenant, Uuid::new_v4());

        cache.invalidate(tenant);

        assert_eq!(cache.get(tenant), None);
    }

    #[test]
    fn tenants_do_not_share_entries() {
        let cache = TenantOrgCache::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let (org_a, org_b) = (Uuid::new_v4(), Uuid::new_v4());

        cache.insert(a, org_a);
        cache.insert(b, org_b);

        assert_eq!(cache.get(a), Some(org_a));
        assert_eq!(cache.get(b), Some(org_b));
    }

    /// A full cache must degrade to "always miss" — one extra read per
    /// request — never to unbounded growth.
    #[test]
    fn insert_is_bounded() {
        let cache = TenantOrgCache::default();
        for _ in 0..(MAX_ENTRIES + 500) {
            cache.insert(Uuid::new_v4(), Uuid::new_v4());
        }
        assert!(cache.len() <= MAX_ENTRIES, "cache must stay bounded");
    }
}
