//! [`DbHandle`] — a **live** reference to one pooled SurrealDB connection.
//!
//! ## The bug this type exists to close
//!
//! Before this type, every repository was constructed from a one-time
//! `pool.handle_for_repo().await` **clone** of the pooled `Surreal<C>` — a
//! snapshot taken once at boot and then held for the process lifetime. That is
//! fine right up until the pool's reconnect loop
//! (`DbManager::spawn_reconnect_loop`, PERF-04/D-12) decides the pooled
//! connection is poisoned and swaps a brand-new one into the pool slot.
//!
//! The swap replaced what the *pool* pointed at, but every repository was still
//! holding its own clone of the **evicted** connection. Those clones share the
//! old `Arc<inner>` — the old router task and the old `reqwest` client with the
//! old (now-rejected) cached auth token — so from that moment on every
//! repository query 401s, permanently, until the process restarts. Observed
//! ~7 minutes into a sustained load run during the rate-limit verification: a
//! cell starts clean and then produces a wall of 401s with the server otherwise
//! reporting healthy, cleared instantly by `docker restart`.
//!
//! Readiness did not catch it either: `DbPool::health_check` probes through the
//! pool slot, so it observes the *fresh* handle and reports healthy while the
//! repositories are all talking to the dead one.
//!
//! ## The fix
//!
//! [`DbHandle`] holds the pool **slot** (`Arc<ArcSwap<Surreal<C>>>`) rather than
//! a connection cloned out of it, and resolves the current connection at every
//! call via [`DbHandle::current`]. A reconnect-loop swap is therefore observed
//! by the very next query on every repository already built from that slot —
//! no restart, no permanent 401 wall.
//!
//! ## Why `ArcSwap` and not `RwLock`
//!
//! The slot is read on every single database call and written essentially never
//! (only by a reconnect). `ArcSwap::load_full` is a lock-free atomic read, so
//! the hot path takes no lock, cannot be delayed behind a queued writer, and —
//! importantly for the ~250 repository call sites — stays **synchronous**, so
//! resolving the current handle adds no `.await` point to any query path.

use std::sync::Arc;

use arc_swap::ArcSwap;
use surrealdb::engine::remote::http::Client;
use surrealdb::{Connection, Surreal};

use crate::read_preference::ReadPreference;

/// The swappable pool slot shared between a pooled handle, its background
/// refresh/reconnect tasks, and every [`DbHandle`] bound to it.
///
/// Writing this slot (a reconnect-loop eviction) is atomically visible to every
/// holder's next [`DbHandle::current`] call — that visibility *is* the fix.
pub(crate) type DbSlot<C> = Arc<ArcSwap<Surreal<C>>>;

/// Build a fresh slot around an already-connected handle.
pub(crate) fn new_slot<C: Connection>(db: Surreal<C>) -> DbSlot<C> {
    Arc::new(ArcSwap::from_pointee(db))
}

/// A live reference to one pooled SurrealDB connection.
///
/// Repositories hold this instead of an owned `Surreal<C>` so that a
/// reconnect-loop handle swap is picked up on their next query rather than
/// leaving them pinned to an evicted connection forever (see the module docs).
///
/// Cloning is cheap — clones share the same slot, so they all observe the same
/// swaps. `Surreal<C>` converts into a `DbHandle<C>` via [`From`], which keeps
/// tests (and any caller that legitimately owns a standalone connection, such
/// as an embedded `kv-mem` instance) able to construct repositories exactly as
/// before; such a handle simply has a slot that nothing ever swaps.
pub struct DbHandle<C: Connection = Client> {
    slot: DbSlot<C>,
    /// A3/J11: optional read-replica slots. Empty (the default) means every
    /// read resolves to `slot` and replica routing is entirely inert.
    ///
    /// Each replica gets its own slot so a replica connection can be evicted
    /// and re-established by the same reconnect machinery as the primary, and
    /// so a caller holding a `DbHandle` observes replica swaps on its next
    /// query exactly as it observes primary swaps.
    replicas: Arc<Vec<DbSlot<C>>>,
    /// Round-robin cursor across `replicas`. Shared by every clone of this
    /// handle so the spread is process-wide rather than per-repository.
    ///
    /// `Relaxed` is correct: this selects a replica, and any replica is a
    /// valid answer. Nothing downstream depends on the ordering of these
    /// increments, so paying for stronger ordering on a per-read atomic would
    /// buy nothing.
    replica_cursor: Arc<std::sync::atomic::AtomicUsize>,
}

impl<C: Connection> DbHandle<C> {
    /// Wrap an existing pool slot. Crate-internal: outside this crate a
    /// `DbHandle` is obtained from [`crate::DbPool::handle_for_repo`] (live) or
    /// via `From<Surreal<C>>` (standalone).
    pub(crate) fn from_slot(slot: DbSlot<C>) -> Self {
        Self {
            slot,
            replicas: Arc::new(Vec::new()),
            replica_cursor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// The connection to use for **this** operation.
    ///
    /// Resolves the slot on every call, so a reconnect-loop swap is observed
    /// immediately. The returned `Arc<Surreal<C>>` derefs to the connection, so
    /// call sites read as `self.db.current().query(..)`.
    ///
    /// Lock-free (a single atomic load), so this is safe and cheap to call on
    /// every query and never blocks behind the reconnect loop.
    pub fn current(&self) -> Arc<Surreal<C>> {
        self.slot.load_full()
    }

    /// The connection to use for a read of the given [`ReadPreference`]
    /// (A3/J11).
    ///
    /// Falls back to the primary whenever no replica may serve the read —
    /// because the preference pins it, or because no replicas are configured.
    /// A read path must never fail merely because a *performance*
    /// optimisation is unavailable, so there is deliberately no error case
    /// here: the worst a missing replica costs is the throughput it was
    /// adding. See [`crate::read_preference`] for the staleness contract and
    /// for which query classes are pinned.
    pub fn current_for(&self, preference: ReadPreference) -> Arc<Surreal<C>> {
        if !preference.allows_replica() || self.replicas.is_empty() {
            return self.current();
        }

        let idx = self
            .replica_cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.replicas.len();
        self.replicas[idx].load_full()
    }

    /// Attach read replicas to this handle.
    ///
    /// Returns a NEW handle rather than mutating: repositories already built
    /// from a replica-less handle keep their (correct, primary-only) routing,
    /// and enabling replicas is therefore always an additive wiring decision
    /// made at the composition root.
    pub fn with_replicas(self, replicas: Vec<Surreal<C>>) -> Self {
        Self {
            slot: self.slot,
            replicas: Arc::new(replicas.into_iter().map(new_slot).collect()),
            replica_cursor: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// How many read replicas this handle can route to.
    pub fn replica_count(&self) -> usize {
        self.replicas.len()
    }
}

impl<C: Connection> Clone for DbHandle<C> {
    /// Clones share the SAME slot — every clone observes every swap. (Derived
    /// `Clone` would demand `C: Clone`, which `Connection` does not imply.)
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
            replicas: Arc::clone(&self.replicas),
            replica_cursor: Arc::clone(&self.replica_cursor),
        }
    }
}

impl<C: Connection> From<Surreal<C>> for DbHandle<C> {
    /// Wrap a standalone connection in its own slot. Nothing swaps this slot,
    /// so the result behaves exactly like holding the connection directly —
    /// this is the path tests and embedded `kv-mem` callers take.
    fn from(db: Surreal<C>) -> Self {
        Self::from_slot(new_slot(db))
    }
}

impl<C: Connection> std::fmt::Debug for DbHandle<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbHandle").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::engine::local::{Db, Mem};

    async fn marked(marker: &str) -> Surreal<Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
        db.use_ns("test").use_db("test").await.expect("use ns/db");
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

    /// THE regression test for the stale-handle bug: a handle taken *before* a
    /// slot swap must observe the new connection on its next `current()`, not
    /// stay pinned to the evicted one.
    #[tokio::test]
    async fn current_observes_a_swap_made_after_the_handle_was_taken() {
        let slot = new_slot(marked("old").await);
        // Bound once, up-front — exactly how a repository binds at boot.
        let handle = DbHandle::from_slot(Arc::clone(&slot));
        assert_eq!(
            read_marker(&handle.current()).await,
            vec!["old".to_string()]
        );

        // The reconnect loop evicts the poisoned connection.
        slot.store(Arc::new(marked("new").await));

        assert_eq!(
            read_marker(&handle.current()).await,
            vec!["new".to_string()],
            "a handle bound before the swap must follow the slot, not stay \
             pinned to the evicted connection"
        );
    }

    /// Clones share the slot, so a swap reaches every repository built from it
    /// (repositories are `.clone()`d liberally into per-worker app state).
    #[tokio::test]
    async fn clones_share_the_slot_and_all_observe_the_swap() {
        let slot = new_slot(marked("old").await);
        let a = DbHandle::from_slot(Arc::clone(&slot));
        let b = a.clone();
        let c = b.clone();

        slot.store(Arc::new(marked("new").await));

        for (name, h) in [("a", &a), ("b", &b), ("c", &c)] {
            assert_eq!(
                read_marker(&h.current()).await,
                vec!["new".to_string()],
                "clone {name} must observe the swap"
            );
        }
    }

    /// `From<Surreal<C>>` yields a working, never-swapped handle — the shape
    /// tests and embedded callers rely on.
    #[tokio::test]
    async fn from_surreal_yields_a_usable_standalone_handle() {
        let handle: DbHandle<Db> = marked("standalone").await.into();
        assert_eq!(
            read_marker(&handle.current()).await,
            vec!["standalone".to_string()]
        );
    }
}

#[cfg(test)]
mod replica_routing_tests {
    use super::*;
    use surrealdb::engine::local::{Db, Mem};

    async fn marked(marker: &str) -> Surreal<Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory connect");
        db.use_ns("test").use_db("test").await.expect("use ns/db");
        db.query(format!("CREATE marker SET value = '{marker}'"))
            .await
            .and_then(|r| r.check())
            .expect("seed marker row");
        db
    }

    async fn read_marker(db: &Surreal<Db>) -> String {
        let mut result = db
            .query("SELECT VALUE value FROM marker")
            .await
            .and_then(|r| r.check())
            .expect("read marker rows");
        let rows: Vec<String> = result.take(0).expect("take marker rows");
        rows.into_iter().next().expect("one marker row")
    }

    /// With no replicas configured, every preference resolves to the primary.
    /// This is the shipped default, so it is the case that must not break.
    #[tokio::test]
    async fn without_replicas_every_read_goes_to_the_primary() {
        let handle = DbHandle::from(marked("primary").await);

        for pref in [ReadPreference::Primary, ReadPreference::PreferReplica] {
            assert_eq!(
                read_marker(&handle.current_for(pref)).await,
                "primary",
                "{} must resolve to the primary when no replica exists",
                pref.as_str()
            );
        }
        assert_eq!(handle.replica_count(), 0);
    }

    /// A pinned read must reach the primary even when replicas ARE available
    /// — this is the property `QueryClass::SessionRevocation` depends on.
    #[tokio::test]
    async fn primary_pinned_reads_never_route_to_a_replica() {
        let handle = DbHandle::from(marked("primary").await)
            .with_replicas(vec![marked("replica-a").await, marked("replica-b").await]);

        for _ in 0..10 {
            assert_eq!(
                read_marker(&handle.current_for(ReadPreference::Primary)).await,
                "primary",
                "a pinned read must never be served by a replica"
            );
        }
    }

    /// Replica-eligible reads spread across every configured replica, and
    /// never land on the primary.
    #[tokio::test]
    async fn replica_eligible_reads_round_robin_across_replicas() {
        let handle = DbHandle::from(marked("primary").await)
            .with_replicas(vec![marked("replica-a").await, marked("replica-b").await]);

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let value = read_marker(&handle.current_for(ReadPreference::PreferReplica)).await;
            assert_ne!(
                value, "primary",
                "an eligible read must not fall back needlessly"
            );
            seen.insert(value);
        }

        assert_eq!(
            seen,
            ["replica-a".to_string(), "replica-b".to_string()]
                .into_iter()
                .collect(),
            "both replicas must take a share of the load"
        );
    }

    /// Clones share the replica set AND the cursor, so spreading is
    /// process-wide rather than per-repository (every repository holds its own
    /// clone of one handle).
    #[tokio::test]
    async fn clones_share_replicas_and_the_round_robin_cursor() {
        let handle = DbHandle::from(marked("primary").await)
            .with_replicas(vec![marked("replica-a").await, marked("replica-b").await]);
        let clone = handle.clone();

        assert_eq!(clone.replica_count(), 2);

        let first = read_marker(&handle.current_for(ReadPreference::PreferReplica)).await;
        let second = read_marker(&clone.current_for(ReadPreference::PreferReplica)).await;

        assert_ne!(
            first, second,
            "a clone must continue the shared cursor, not restart it"
        );
    }
}
