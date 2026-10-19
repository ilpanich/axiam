//! Integration tests for schema initialization using in-memory SurrealDB.

use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

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
