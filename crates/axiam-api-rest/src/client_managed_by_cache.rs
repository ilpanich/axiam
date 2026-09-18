//! Tiny TTL cache for the `(tenant_id, client_id) -> managed_by` mapping.
//!
//! # Why this exists
//!
//! T21.4 made `/oauth2/authorize` ask one question before it authorizes:
//! is this client externally registered (DCR or CIMD), so that the end user's
//! consent must be on record? Answering it costs a `client_id`-indexed read of
//! the client row — a read `AuthorizeService` repeats a moment later for its
//! own validation, and whose answer is discarded for every client an
//! administrator created, which is every client in most deployments.
//!
//! `resolve_external_consent` (`handlers/oauth2.rs`) argued that read was
//! affordable and named this cache as the remedy "if a future profile shows
//! otherwise". The 2026-09-18 A/B did: `oauth2_authorize` fell from 609/s to
//! 495/s (p95 113 ms → 156 ms) between the pre-T21 image and `main`, with the
//! dependency update ruled out by a third image. On the HTTP engine one extra
//! serialized round trip per authorization is exactly that shape.
//!
//! # Why caching *this* is safe
//!
//! `managed_by` is absent from the client update API on purpose, so it cannot
//! change for a row. It also cannot change **across** rows for one
//! `(tenant_id, client_id)`, which is the stronger property a cache keyed by
//! `client_id` needs:
//!
//! * `admin` and `dcr` rows get a server-generated, 128-bit random
//!   `client_id` — never chosen by a caller, never reused.
//! * `cimd` rows are keyed by the metadata document URL, and
//!   `upsert_cimd_client` refuses to take over a `client_id` that already
//!   names a row it does not own.
//!
//! So a `client_id` that once named an `admin` client can never later name an
//! external one — the direction that would matter, since a stale `admin`
//! answer would skip the consent gate. Deletion is the only transition, and a
//! deleted client fails inside `AuthorizeService` whatever this cache says.
//! The TTL is therefore not a staleness mechanism; like `tenant_org_cache`'s,
//! it bounds how long a deleted client is remembered and keeps churn from
//! growing the map.
//!
//! What this cache deliberately does **not** hold: negative answers. A lookup
//! that finds no client is never recorded, so the map only ever contains
//! `client_id`s that exist in the datastore, and a caller cannot grow it by
//! inventing identifiers. It never holds the client itself either — secrets,
//! redirect URIs and grant types are validated from a fresh read, every time.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axiam_core::models::oauth2_client::ManagedBy;
use uuid::Uuid;

/// How long an answer is served from memory before it is re-read.
///
/// Matches `tenant_org_cache`: long enough that a sustained sign-in flood pays
/// the read once per minute per client, short enough that a deleted client
/// leaves memory promptly.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Upper bound on distinct clients held in memory.
///
/// At the cap the cache stops accepting new entries until an expiry sweep
/// frees room, which degrades to the uncached behaviour — one read per
/// authorization — rather than to unbounded growth.
const MAX_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, Copy)]
struct Entry {
    managed_by: ManagedBy,
    inserted_at: Instant,
}

type Key = (Uuid, String);

/// Process-wide `(tenant_id, client_id) -> managed_by` cache.
///
/// A plain `Mutex<HashMap<..>>`, for the same reason `TenantOrgCache` is one:
/// the critical section is a hash lookup and a `Copy` read, orders of
/// magnitude below the round trip it replaces.
#[derive(Debug)]
pub struct ClientManagedByCache {
    ttl: Duration,
    entries: Mutex<HashMap<Key, Entry>>,
}

impl Default for ClientManagedByCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

impl ClientManagedByCache {
    /// Build a cache with an explicit TTL (tests pin a short one).
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cached `managed_by` for this tenant's `client_id`, if present and
    /// not expired.
    pub fn get(&self, tenant_id: Uuid, client_id: &str) -> Option<ManagedBy> {
        let key = (tenant_id, client_id.to_owned());
        let mut guard = self.lock();
        let entry = guard.get(&key).copied()?;
        if entry.inserted_at.elapsed() >= self.ttl {
            guard.remove(&key);
            return None;
        }
        Some(entry.managed_by)
    }

    /// Record the `managed_by` of a client that was just read from the
    /// datastore. Only call this with a row that exists — see the module docs
    /// on negative answers.
    pub fn insert(&self, tenant_id: Uuid, client_id: &str, managed_by: ManagedBy) {
        let key = (tenant_id, client_id.to_owned());
        let mut guard = self.lock();
        if guard.len() >= MAX_ENTRIES && !guard.contains_key(&key) {
            let ttl = self.ttl;
            guard.retain(|_, e| e.inserted_at.elapsed() < ttl);
            if guard.len() >= MAX_ENTRIES {
                return;
            }
        }
        guard.insert(
            key,
            Entry {
                managed_by,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Entries currently held — for tests and a future gauge.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A poisoned lock means another thread panicked while holding a map of
    /// client identifiers; there is no invariant to protect, and recovering
    /// the map beats propagating a panic onto an authorization path.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_and_returns_the_answer() {
        let cache = ClientManagedByCache::default();
        let tenant = Uuid::new_v4();

        assert_eq!(cache.get(tenant, "c1"), None, "cold cache misses");
        cache.insert(tenant, "c1", ManagedBy::Dcr);
        assert_eq!(cache.get(tenant, "c1"), Some(ManagedBy::Dcr));
    }

    #[test]
    fn expired_entries_are_not_served() {
        let cache = ClientManagedByCache::new(Duration::from_nanos(1));
        let tenant = Uuid::new_v4();
        cache.insert(tenant, "c1", ManagedBy::Admin);

        std::thread::sleep(Duration::from_millis(2));

        assert_eq!(cache.get(tenant, "c1"), None);
        assert!(cache.is_empty(), "the read that saw it expired drops it");
    }

    /// `client_id` is unique per tenant, not globally: the same string in two
    /// tenants names two clients, and one must never answer for the other.
    #[test]
    fn tenants_do_not_share_entries() {
        let cache = ClientManagedByCache::default();
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());

        cache.insert(a, "same-id", ManagedBy::Admin);

        assert_eq!(cache.get(b, "same-id"), None);
        cache.insert(b, "same-id", ManagedBy::Cimd);
        assert_eq!(cache.get(a, "same-id"), Some(ManagedBy::Admin));
        assert_eq!(cache.get(b, "same-id"), Some(ManagedBy::Cimd));
    }

    #[test]
    fn insert_is_bounded() {
        let cache = ClientManagedByCache::default();
        let tenant = Uuid::new_v4();
        for i in 0..(MAX_ENTRIES + 500) {
            cache.insert(tenant, &format!("c{i}"), ManagedBy::Admin);
        }
        assert!(cache.len() <= MAX_ENTRIES, "cache must stay bounded");
    }
}
