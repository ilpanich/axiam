//! Short-TTL, process-local caches of the records a token endpoint re-reads on
//! every request: a tenant's liveness, an OAuth2 client, a user account.
//!
//! # What is cached, and for whom
//!
//! Only reads that **decide nothing they write back** use these caches:
//!
//! - `TenantRepository::get_by_id_cached` — the tenant liveness every client
//!   authentication checks (R1W1-03);
//! - `OAuth2ClientRepository::get_by_client_id_with_context` — the client a
//!   token endpoint authenticates, with its tenant and the token's account;
//! - `UserRepository::get_by_id_cached` — the account an already authenticated
//!   principal's request is checked against (`account_may_act`) or describes
//!   (UserInfo claims).
//!
//! The plain `get_by_id`, which read-modify-write code relies on (lockout
//! counters, TOTP replay steps, settings updates), is never served from here.
//!
//! A cached user never carries credential material: its `password_hash` and
//! `mfa_secret` are blanked before it is stored, so a cached read can never be
//! the input to a credential check, whatever a future caller does with it.
//!
//! # The staleness bound
//!
//! Only positive answers are cached, each for at most the TTL (5 s by default,
//! `AXIAM__DB__RECORD_CACHE_TTL_SECS`; `0` turns the caches off). Every write
//! method of the repository that owns a record drops it from the cache in the
//! same call, so on a **single replica** a suspension, a deactivation or a
//! secret rotation through the API takes effect on the next request. A write
//! made on **another replica**, or outside the owning repository, reaches this
//! one within the TTL — the same bound, and the same decision
//! (`claude_dev/db-query-optimization.md` §8.5), as the session-validation and
//! authorization decision caches.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axiam_core::models::oauth2_client::OAuth2Client;
use axiam_core::models::tenant::Tenant;
use axiam_core::models::user::User;
use uuid::Uuid;

/// Default TTL of every record cache (`AXIAM__DB__RECORD_CACHE_TTL_SECS`).
pub const DEFAULT_RECORD_CACHE_TTL_SECS: u64 = 5;

/// Default bound on the entries of each record cache
/// (`AXIAM__DB__RECORD_CACHE_MAX_ENTRIES`).
pub const DEFAULT_RECORD_CACHE_MAX_ENTRIES: usize = 10_000;

const STRIPES: usize = 16;

/// A striped, TTL-bounded, size-bounded map.
struct TtlMap<K, V> {
    stripes: Vec<Mutex<HashMap<K, (V, Instant)>>>,
    ttl: Duration,
    per_stripe: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> TtlMap<K, V> {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            stripes: (0..STRIPES).map(|_| Mutex::new(HashMap::new())).collect(),
            ttl,
            per_stripe: (max_entries / STRIPES).max(1),
        }
    }

    fn stripe(&self, key: &K) -> &Mutex<HashMap<K, (V, Instant)>> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        &self.stripes[(h.finish() as usize) % STRIPES]
    }

    fn get(&self, key: &K) -> Option<V> {
        let stripe = self.stripe(key).lock().unwrap_or_else(|p| p.into_inner());
        match stripe.get(key) {
            Some((value, at)) if at.elapsed() < self.ttl => Some(value.clone()),
            _ => None,
        }
    }

    fn insert(&self, key: K, value: V) {
        let mut stripe = self.stripe(&key).lock().unwrap_or_else(|p| p.into_inner());
        if stripe.len() >= self.per_stripe && !stripe.contains_key(&key) {
            let ttl = self.ttl;
            stripe.retain(|_, (_, at)| at.elapsed() < ttl);
            if stripe.len() >= self.per_stripe {
                // Full of live entries: start the stripe over rather than grow.
                stripe.clear();
            }
        }
        stripe.insert(key, (value, Instant::now()));
    }

    fn remove(&self, key: &K) {
        self.stripe(key)
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
    }

    fn retain(&self, mut keep: impl FnMut(&K, &V) -> bool) {
        for stripe in &self.stripes {
            stripe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|k, (v, _)| keep(k, v));
        }
    }
}

/// The record caches one process shares between its tenant, OAuth2 client and
/// user repositories. Build one at the composition root and attach the same
/// `Arc` to each (`with_record_caches`), so a write through any of them drops
/// the entry every reader would have served.
pub struct RecordCaches {
    ttl: Duration,
    tenants: TtlMap<Uuid, Tenant>,
    clients: TtlMap<(Uuid, String), OAuth2Client>,
    users: TtlMap<(Uuid, Uuid), User>,
}

impl std::fmt::Debug for RecordCaches {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordCaches")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl RecordCaches {
    /// Caches whose entries are served for at most `ttl`, each holding at most
    /// about `max_entries` records.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            tenants: TtlMap::new(ttl, max_entries),
            clients: TtlMap::new(ttl, max_entries),
            users: TtlMap::new(ttl, max_entries),
        }
    }

    /// The staleness bound of every entry.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) fn tenant(&self, id: Uuid) -> Option<Tenant> {
        self.tenants.get(&id)
    }

    pub(crate) fn put_tenant(&self, tenant: &Tenant) {
        self.tenants.insert(tenant.id, tenant.clone());
    }

    pub(crate) fn forget_tenant(&self, id: Uuid) {
        self.tenants.remove(&id);
    }

    pub(crate) fn client(&self, tenant_id: Uuid, client_id: &str) -> Option<OAuth2Client> {
        self.clients.get(&(tenant_id, client_id.to_owned()))
    }

    pub(crate) fn put_client(&self, client: &OAuth2Client) {
        self.clients
            .insert((client.tenant_id, client.client_id.clone()), client.clone());
    }

    /// Drop the client whose record id is `id` — a write that names the record
    /// rather than its `client_id`.
    pub(crate) fn forget_client_record(&self, tenant_id: Uuid, id: Uuid) {
        self.clients
            .retain(|(t, _), client| !(*t == tenant_id && client.id == id));
    }

    pub(crate) fn user(&self, tenant_id: Uuid, id: Uuid) -> Option<User> {
        self.users.get(&(tenant_id, id))
    }

    /// Cache `user` with its credential material blanked.
    pub(crate) fn put_user(&self, user: &User) {
        let mut user = user.clone();
        user.password_hash = String::new();
        user.mfa_secret = None;
        self.users.insert((user.tenant_id, user.id), user);
    }

    pub(crate) fn forget_user(&self, tenant_id: Uuid, id: Uuid) {
        self.users.remove(&(tenant_id, id));
    }

    /// Drop every cached account of `tenant_id` — a write whose subject is not
    /// known by id (an anonymisation by marker, a bulk change).
    pub(crate) fn forget_users_of(&self, tenant_id: Uuid) {
        self.users.retain(|(t, _), _| *t != tenant_id);
    }
}

/// Drops a record from the caches now and again when it goes out of scope.
///
/// Placed first in a write method: the first drop covers a read that would
/// otherwise be served the pre-write record while the write runs, the second —
/// on every way out of the method, error and early return included — covers a
/// read that fetched the old row and cached it during the write.
#[must_use = "the record is forgotten again when the guard drops; bind it to a named variable"]
pub(crate) struct ForgetGuard<'a> {
    caches: Option<&'a RecordCaches>,
    forget: fn(&RecordCaches, Uuid, Uuid),
    a: Uuid,
    b: Uuid,
}

impl<'a> ForgetGuard<'a> {
    pub(crate) fn new(
        caches: Option<&'a RecordCaches>,
        forget: fn(&RecordCaches, Uuid, Uuid),
        a: Uuid,
        b: Uuid,
    ) -> Self {
        if let Some(c) = caches {
            forget(c, a, b);
        }
        Self {
            caches,
            forget,
            a,
            b,
        }
    }
}

impl Drop for ForgetGuard<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.caches {
            (self.forget)(c, self.a, self.b);
        }
    }
}

impl RecordCaches {
    /// Guard for a write to tenant `id`.
    pub(crate) fn tenant_write(caches: Option<&RecordCaches>, id: Uuid) -> ForgetGuard<'_> {
        ForgetGuard::new(caches, |c, id, _| c.forget_tenant(id), id, Uuid::nil())
    }

    /// Guard for a write to the client record `id` of `tenant_id`.
    pub(crate) fn client_write(
        caches: Option<&RecordCaches>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> ForgetGuard<'_> {
        ForgetGuard::new(caches, RecordCaches::forget_client_record, tenant_id, id)
    }

    /// Guard for a write to every client of `tenant_id` (a write that names a
    /// client by something other than its record id).
    pub(crate) fn clients_of_tenant_write(
        caches: Option<&RecordCaches>,
        tenant_id: Uuid,
    ) -> ForgetGuard<'_> {
        ForgetGuard::new(
            caches,
            |c, t, _| c.clients.retain(|(tenant, _), _| *tenant != t),
            tenant_id,
            Uuid::nil(),
        )
    }

    /// Guard for a write to user `id` of `tenant_id`.
    pub(crate) fn user_write(
        caches: Option<&RecordCaches>,
        tenant_id: Uuid,
        id: Uuid,
    ) -> ForgetGuard<'_> {
        ForgetGuard::new(caches, RecordCaches::forget_user, tenant_id, id)
    }

    /// Guard for a write to some user of `tenant_id` not known by id.
    pub(crate) fn users_of_tenant_write(
        caches: Option<&RecordCaches>,
        tenant_id: Uuid,
    ) -> ForgetGuard<'_> {
        ForgetGuard::new(
            caches,
            |c, t, _| c.forget_users_of(t),
            tenant_id,
            Uuid::nil(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_expire_after_the_ttl() {
        let map = TtlMap::new(Duration::from_millis(20), 100);
        map.insert(1u8, "a");
        assert_eq!(map.get(&1), Some("a"));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(map.get(&1), None);
    }

    #[test]
    fn a_full_stripe_never_grows_past_its_bound() {
        let map = TtlMap::new(Duration::from_secs(60), STRIPES * 2);
        for i in 0..10_000u32 {
            map.insert(i, i);
        }
        let total: usize = map.stripes.iter().map(|s| s.lock().unwrap().len()).sum();
        assert!(total <= STRIPES * 2, "{total}");
    }

    #[test]
    fn remove_and_retain_drop_entries() {
        let map = TtlMap::new(Duration::from_secs(60), 100);
        map.insert((1u8, 1u8), 'a');
        map.insert((1, 2), 'b');
        map.insert((2, 1), 'c');
        map.remove(&(1, 1));
        assert_eq!(map.get(&(1, 1)), None);
        map.retain(|(t, _), _| *t != 1);
        assert_eq!(map.get(&(1, 2)), None);
        assert_eq!(map.get(&(2, 1)), Some('c'));
    }
}
