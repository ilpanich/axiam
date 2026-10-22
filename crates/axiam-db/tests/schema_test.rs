//! Integration tests for schema initialization using in-memory SurrealDB.

mod common;

use std::time::Duration;

use axiam_db::MigrationLease;
use surrealdb::engine::local::Mem;
use surrealdb::{Connection, Surreal};

#[tokio::test]
async fn schema_migration_applies_successfully() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    axiam_db::run_migrations(&db).await.unwrap();

    // Verify that key tables exist by querying INFO FOR DB.
    let mut result = db.query("INFO FOR DB").await.unwrap();
    let info: Option<surrealdb_types::Value> = result.take(0).unwrap();
    let info = info.expect("INFO FOR DB should return a value");
    let info_str = format!("{:?}", info);

    // Spot-check representative tables from each category.
    assert!(
        info_str.contains("organization"),
        "missing organization table"
    );
    assert!(info_str.contains("tenant"), "missing tenant table");
    assert!(info_str.contains("user"), "missing user table");
    assert!(info_str.contains("role"), "missing role table");
    assert!(info_str.contains("permission"), "missing permission table");
    assert!(info_str.contains("resource"), "missing resource table");
    assert!(info_str.contains("session"), "missing session table");
    assert!(info_str.contains("audit_log"), "missing audit_log table");
    assert!(
        info_str.contains("ca_certificate"),
        "missing ca_certificate table"
    );
    assert!(
        info_str.contains("certificate"),
        "missing certificate table"
    );
    assert!(info_str.contains("webhook"), "missing webhook table");
    assert!(
        info_str.contains("oauth2_client"),
        "missing oauth2_client table"
    );
    assert!(
        info_str.contains("federation_config"),
        "missing federation_config table"
    );
    assert!(
        info_str.contains("service_account"),
        "missing service_account table"
    );
    assert!(info_str.contains("scope"), "missing scope table");
    assert!(info_str.contains("group"), "missing group table");

    // Verify edge tables.
    assert!(info_str.contains("has_tenant"), "missing has_tenant edge");
    assert!(info_str.contains("has_role"), "missing has_role edge");
    assert!(info_str.contains("grants"), "missing grants edge");
    assert!(info_str.contains("child_of"), "missing child_of edge");
    assert!(info_str.contains("signed_by"), "missing signed_by edge");
    assert!(info_str.contains("member_of"), "missing member_of edge");

    // Verify migration was recorded.
    assert!(info_str.contains("_migration"), "missing _migration table");
}

#[tokio::test]
async fn migration_is_idempotent() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    // Run once and capture migration count.
    axiam_db::run_migrations(&db).await.unwrap();
    let mut result = db.query("SELECT * FROM _migration").await.unwrap();
    let first_run: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    let count_after_first = first_run.len();
    assert!(count_after_first > 0, "should have at least one migration");

    // Run again — should not fail or add new records.
    axiam_db::run_migrations(&db).await.unwrap();
    let mut result = db.query("SELECT * FROM _migration").await.unwrap();
    let second_run: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    assert_eq!(
        second_run.len(),
        count_after_first,
        "second run should not create additional migration records"
    );
}

#[tokio::test]
async fn can_create_record_after_migration() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    axiam_db::run_migrations(&db).await.unwrap();

    // Create an organization record to verify schema works.
    db.query(
        "CREATE organization SET \
         name = 'ACME Corp', \
         slug = 'acme-corp', \
         metadata = {}",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    let mut result = db
        .query("SELECT * FROM organization WHERE slug = 'acme-corp'")
        .await
        .unwrap();
    let records: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn unique_index_prevents_duplicate_slugs() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    axiam_db::run_migrations(&db).await.unwrap();

    // Create first organization.
    db.query(
        "CREATE organization SET \
         name = 'ACME Corp', \
         slug = 'acme', \
         metadata = {}",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    // Attempt duplicate slug — should fail.
    let result = db
        .query(
            "CREATE organization SET \
             name = 'Another Corp', \
             slug = 'acme', \
             metadata = {}",
        )
        .await
        .unwrap()
        .check();

    assert!(result.is_err(), "duplicate slug should be rejected");
}

/// #704 (R110W6-07) — a datastore that recorded 1 … 98 and 100 (it ran a build
/// that carried v100 but not v99) applies v99 on its next start. The runner
/// used to apply only versions above the highest recorded one, so v99 — the
/// certificate serial column and its issuer-unique index (#653) — was skipped
/// for ever.
#[tokio::test]
async fn a_version_below_the_highest_recorded_is_still_applied() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let mut all: Vec<u32> = result.take(0).unwrap();
    all.sort_unstable();

    // Un-apply v99 (its DDL and its record) and forget every version above
    // 100, leaving exactly 1 … 98 and 100 recorded (86 … 89 were never
    // claimed, so "1 … 98" is every listed version up to 98).
    db.query(
        "REMOVE INDEX idx_certificate_issuer_serial ON TABLE certificate; \
         REMOVE INDEX idx_ca_certificate_parent_serial ON TABLE ca_certificate; \
         REMOVE FIELD serial ON TABLE certificate; \
         REMOVE FIELD serial ON TABLE ca_certificate; \
         DELETE _migration WHERE version = 99 OR version > 100;",
    )
    .await
    .unwrap()
    .check()
    .unwrap();
    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let mut before: Vec<u32> = result.take(0).unwrap();
    before.sort_unstable();
    let expected_before: Vec<u32> = all
        .iter()
        .copied()
        .filter(|&v| v <= 98 || v == 100)
        .collect();
    assert!(expected_before.contains(&98) && !expected_before.contains(&99));
    assert_eq!(before, expected_before);

    axiam_db::run_migrations(&db)
        .await
        .expect("a migration below the highest recorded must apply");

    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let mut after: Vec<u32> = result.take(0).unwrap();
    after.sort_unstable();
    assert_eq!(after, all, "every listed migration is recorded once");

    let mut result = db.query("INFO FOR TABLE certificate").await.unwrap();
    let info: Option<surrealdb_types::Value> = result.take(0).unwrap();
    let info = format!("{:?}", info.expect("INFO FOR TABLE should return a value"));
    assert!(
        info.contains("idx_certificate_issuer_serial"),
        "v99 must have applied: idx_certificate_issuer_serial is missing"
    );
}

// ---------------------------------------------------------------------------
// #755 (R111-05) — the startup lease on `_migration_lock:startup`
// ---------------------------------------------------------------------------

/// Lease timings for tests: a TTL long enough that no test outlives it by
/// accident, and a poll short enough that a waiter notices a release at once.
const FAST: MigrationLease = MigrationLease {
    ttl: Duration::from_secs(30),
    refresh_every: Duration::from_millis(200),
    poll_every: Duration::from_millis(20),
};

/// The highest listed migration, read from a fully migrated datastore.
async fn newest_version<C: Connection>(db: &Surreal<C>) -> u32 {
    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let versions: Vec<u32> = result.take(0).unwrap();
    versions
        .into_iter()
        .max()
        .expect("a migrated datastore records versions")
}

/// How many `_migration` rows record `version`.
async fn records_of<C: Connection>(db: &Surreal<C>, version: u32) -> usize {
    let mut result = db
        .query("SELECT VALUE version FROM _migration WHERE version = $v")
        .bind(("v", version))
        .await
        .unwrap();
    result.take::<Vec<u32>>(0).unwrap().len()
}

/// The lease row's holder, if there is a row.
async fn lease_holder<C: Connection>(db: &Surreal<C>) -> Option<Option<String>> {
    let mut result = db
        .query("SELECT VALUE holder FROM _migration_lock:`startup`")
        .await
        .unwrap();
    result
        .take::<Vec<Option<String>>>(0)
        .unwrap()
        .into_iter()
        .next()
}

/// Forget the newest version's record, so that it is pending again. Every
/// migration above the newest released one is additive, so re-applying its
/// DDL over the objects it already defined is a no-op.
async fn make_newest_pending<C: Connection>(db: &Surreal<C>) -> u32 {
    let newest = newest_version(db).await;
    db.query("DELETE _migration WHERE version = $v")
        .bind(("v", newest))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(records_of(db, newest).await, 0);
    newest
}

/// The issue's test: two replicas start together against one datastore with
/// a migration pending. Both boots succeed and the version is recorded once.
/// On `surrealkv`, the engine production runs, because the assertion is about
/// concurrent writers (see `tests/common`).
#[tokio::test]
async fn two_concurrent_starters_both_succeed_and_record_the_version_once() {
    let db = common::serialising_db().await;
    let pending = make_newest_pending(&db).await;

    let (a, b) = (db.handle(), db.handle());
    let (first, second) = tokio::join!(
        axiam_db::run_migrations_with_lease(&a, FAST),
        axiam_db::run_migrations_with_lease(&b, FAST),
    );
    first.expect("the first starter boots");
    second.expect("the second starter boots");

    assert_eq!(records_of(&*db, pending).await, 1, "recorded exactly once");
    assert_eq!(lease_holder(&*db).await, None, "the lease is released");
}

/// The fallback behind the lease: with a lease that expires as soon as it is
/// written, two starters migrate at the same time — the case of a holder that
/// stalls past its TTL. The loser of each version's unique index reads the
/// winner's record and continues, so both still boot, nothing is recorded
/// twice, and every listed version is recorded.
#[tokio::test]
async fn starters_without_mutual_exclusion_tolerate_each_others_record() {
    let db = common::serialising_db().await;
    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let mut all: Vec<u32> = result.take(0).unwrap();
    all.sort_unstable();
    // Every version from 100 up pending: additive migrations above the
    // highest recorded, so both starters apply them in order, together.
    db.query("DELETE _migration WHERE version >= 100")
        .await
        .unwrap()
        .check()
        .unwrap();

    let no_exclusion = MigrationLease {
        ttl: Duration::from_millis(1),
        refresh_every: Duration::from_secs(3600),
        poll_every: Duration::from_millis(5),
    };
    let (a, b) = (db.handle(), db.handle());
    let (first, second) = tokio::join!(
        axiam_db::run_migrations_with_lease(&a, no_exclusion),
        axiam_db::run_migrations_with_lease(&b, no_exclusion),
    );
    first.expect("the first starter boots");
    second.expect("the second starter boots");

    let mut result = db
        .query("SELECT VALUE version FROM _migration")
        .await
        .unwrap();
    let mut after: Vec<u32> = result.take(0).unwrap();
    after.sort_unstable();
    assert_eq!(after, all, "every version recorded, none twice");
}

/// A holder that died leaves a lease that expires; the next starter takes it
/// over, migrates, and releases it.
#[tokio::test]
async fn an_expired_lease_is_taken_over() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let pending = make_newest_pending(&db).await;

    db.query(
        "CREATE _migration_lock:`startup` SET holder = 'dead-replica', \
         expires = time::now() - 1s",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    tokio::time::timeout(
        Duration::from_secs(10),
        axiam_db::run_migrations_with_lease(&db, FAST),
    )
    .await
    .expect("an expired lease is not waited on")
    .expect("the starter boots");

    assert_eq!(records_of(&db, pending).await, 1);
    assert_eq!(lease_holder(&db).await, None, "the lease is released");
}

/// The row a 1.1.1 binary leaves when it dies mid-migration: `locked_at` only,
/// no holder, no expiry. It is stale, not a lease, and is taken over.
#[tokio::test]
async fn a_lock_row_left_by_a_1_1_1_binary_is_taken_over() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    db.query("UPSERT _migration_lock:`startup` SET locked_at = time::now()")
        .await
        .unwrap()
        .check()
        .unwrap();

    tokio::time::timeout(
        Duration::from_secs(10),
        axiam_db::run_migrations_with_lease(&db, FAST),
    )
    .await
    .expect("a 1.1.1 lock row is not waited on")
    .expect("the starter boots");
    assert_eq!(lease_holder(&db).await, None, "the lease is released");
}

/// A live lease is waited on: the starter applies nothing while another
/// instance holds it, and proceeds as soon as that instance releases it. The
/// held lease is minutes from expiry, so "has not finished" is not a race
/// against the clock.
#[tokio::test]
async fn a_live_lease_is_waited_on() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let pending = make_newest_pending(&db).await;

    db.query(
        "CREATE _migration_lock:`startup` SET holder = 'other-replica', \
         expires = time::now() + 5m",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    let starter = {
        let db = db.clone();
        tokio::spawn(async move { axiam_db::run_migrations_with_lease(&db, FAST).await })
    };

    // Many polls' worth of waiting: the starter is still blocked, and has
    // applied nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!starter.is_finished(), "a live lease must be waited on");
    assert_eq!(
        records_of(&db, pending).await,
        0,
        "nothing applied while waiting"
    );
    assert_eq!(
        lease_holder(&db).await,
        Some(Some("other-replica".to_owned())),
        "the other instance's lease is untouched"
    );

    // The other instance finishes and releases its lease.
    db.query("DELETE _migration_lock:`startup`")
        .await
        .unwrap()
        .check()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(10), starter)
        .await
        .expect("the starter proceeds once the lease is released")
        .unwrap()
        .expect("the starter boots");
    assert_eq!(records_of(&db, pending).await, 1);
    assert_eq!(lease_holder(&db).await, None, "the lease is released");
}
