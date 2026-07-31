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
}

impl<C: Connection> DbHandle<C> {
    /// Wrap an existing pool slot. Crate-internal: outside this crate a
    /// `DbHandle` is obtained from [`crate::DbPool::handle_for_repo`] (live) or
    /// via `From<Surreal<C>>` (standalone).
    pub(crate) fn from_slot(slot: DbSlot<C>) -> Self {
        Self { slot }
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
}

impl<C: Connection> Clone for DbHandle<C> {
    /// Clones share the SAME slot — every clone observes every swap. (Derived
    /// `Clone` would demand `C: Clone`, which `Connection` does not imply.)
    fn clone(&self) -> Self {
        Self {
            slot: Arc::clone(&self.slot),
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
