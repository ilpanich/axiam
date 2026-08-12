//! Shared datastore fixtures for `axiam-db`'s integration tests.
//!
//! # Why a test may not just open `Mem`
//!
//! Most of this crate's ~40 test binaries open `Surreal::new::<Mem>(())`, and
//! that is the right choice for them: they assert what a query *does*, `kv-mem`
//! needs no filesystem, and it is markedly faster.
//!
//! It is the wrong choice for any test whose assertion is **"exactly one
//! concurrent caller wins"**. Measured on SurrealDB 3.2.3 with
//! `tools/surreal-race-probe` (rounds of 8 racers released through a barrier,
//! one guarded `UPDATE … WHERE consumed = false RETURN BEFORE` each):
//!
//! | Datastore      | Rounds admitting two winners   | Attempts the engine aborted |
//! |----------------|--------------------------------|-----------------------------|
//! | `kv-mem`       | 23 of 1200, and 10 on a re-run | 5229 of 9600 (54%)          |
//! | `kv-surrealkv` | 0 of 5000                      | 21613 of 40000 (54%)        |
//! | `kv-rocksdb`   | 0 of 1200                      | 8154 of 9600 (85%)          |
//!
//! `kv-mem` is not failing to arbitrate — it aborts contended attempts at the
//! same rate `surrealkv` does — it arbitrates and then occasionally misses,
//! silently, with both callers seeing the pre-transition row. The persistent
//! engines did not miss once.
//!
//! Production runs `surrealkv` (`docker/docker-compose.prod.yml` and the k8s
//! StatefulSet). So a serialisation test on `kv-mem` measures an engine AXIAM
//! never deploys, and measures it to be weaker than the one it does — which is
//! how issue #302 came to record a 1-in-640 residual as a property of the
//! system rather than of the test harness.
//!
//! Use [`serialising_db`] for those tests. Everything else should keep using
//! `Mem` and stay fast.

// Each test binary that includes this module uses a different subset of it.
#![allow(dead_code)]

use surrealdb::Surreal;
use surrealdb::engine::local::{Db, SurrealKv};
use tempfile::TempDir;

/// A migrated datastore on the engine production runs, plus the temporary
/// directory backing it.
///
/// The `TempDir` is held for the fixture's whole life so it is removed when the
/// test ends; dropping it earlier would pull the datastore's files out from
/// under it.
pub struct SerialisingDb {
    db: Surreal<Db>,
    _dir: TempDir,
}

impl SerialisingDb {
    /// The underlying handle, cloned — repositories take ownership of one.
    pub fn handle(&self) -> Surreal<Db> {
        self.db.clone()
    }
}

impl std::ops::Deref for SerialisingDb {
    type Target = Surreal<Db>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

/// Opens a migrated `surrealkv` datastore in a fresh temporary directory.
///
/// Every call gets its own directory, so tests stay independent and can run in
/// parallel the way the `Mem` ones do.
pub async fn serialising_db() -> SerialisingDb {
    let dir = TempDir::new().expect("create temp dir for the surrealkv datastore");
    let path = dir.path().join("axiam-test.db");
    let db = Surreal::new::<SurrealKv>(path.to_string_lossy().into_owned())
        .await
        .expect("open surrealkv datastore");
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    SerialisingDb { db, _dir: dir }
}
