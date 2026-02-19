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

    // Verify edge tables.
    assert!(info_str.contains("has_tenant"), "missing has_tenant edge");
    assert!(info_str.contains("has_role"), "missing has_role edge");
    assert!(info_str.contains("grants"), "missing grants edge");
    assert!(info_str.contains("child_of"), "missing child_of edge");
    assert!(info_str.contains("signed_by"), "missing signed_by edge");

    // Verify migration was recorded.
    assert!(info_str.contains("_migration"), "missing _migration table");
}

#[tokio::test]
async fn migration_is_idempotent() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    // Run twice — should not fail.
    axiam_db::run_migrations(&db).await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    // Verify only one migration record exists.
    let mut result = db.query("SELECT * FROM _migration").await.unwrap();
    let records: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    assert_eq!(records.len(), 1, "expected exactly one migration record");
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
