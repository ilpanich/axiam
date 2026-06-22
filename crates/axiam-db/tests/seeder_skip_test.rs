//! Integration test proving the permission seeder skips the UPSERT storm
//! when the registry hash is unchanged (CQ-B42).
//!
//! Uses in-memory SurrealDB (`kv-mem` feature) — no auth required for the
//! local engine.  Pattern matches existing tests in this directory.

use axiam_db::seeder::seed_permissions;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Sample registry — two permissions, deterministic content.
const REGISTRY: &[(&str, &str)] = &[
    ("users:list", "List users in the tenant"),
    ("users:get", "Get a single user by ID"),
];

/// A different registry — triggers a re-seed.
const REGISTRY_CHANGED: &[(&str, &str)] = &[
    ("users:list", "List users in the tenant"),
    ("users:get", "Get a single user by ID"),
    ("users:create", "Create a new user"),
];

/// Helper: count permission rows for the given tenant.
async fn count_permissions(db: &Surreal<impl surrealdb::Connection>, tenant_id: Uuid) -> usize {
    let tenant_str = tenant_id.to_string();
    let mut result = db
        .query("SELECT * FROM permission WHERE tenant_id = $tid")
        .bind(("tid", tenant_str))
        .await
        .expect("count query failed");
    let rows: Vec<surrealdb_types::Value> = result.take(0).expect("take failed");
    rows.len()
}

/// Helper: read the stored seeder_state hash for the given tenant.
async fn read_seeder_hash(
    db: &Surreal<impl surrealdb::Connection>,
    tenant_id: Uuid,
) -> Option<String> {
    let state_id = uuid::Uuid::new_v5(&tenant_id, b"seeder_state").to_string();
    let mut result = db
        .query("SELECT hash FROM type::record('seeder_state', $id)")
        .bind(("id", state_id))
        .await
        .expect("seeder_state read failed");
    let rows: Vec<axiam_db::seeder::SeederStateRow> = result.take(0).expect("take failed");
    rows.into_iter().next().map(|r| r.hash)
}

/// Core test: seeding twice with the same registry must not produce extra
/// permission rows and must not change the stored hash.
#[tokio::test]
async fn seeder_skip_when_hash_unchanged() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    // Run migrations so all tables exist (including seeder_state added in v20).
    axiam_db::run_migrations(&db).await.unwrap();

    let tenant_id = Uuid::new_v4();

    // ---- First seed ----
    seed_permissions(&db, tenant_id, REGISTRY)
        .await
        .expect("first seed failed");

    let count_after_first = count_permissions(&db, tenant_id).await;
    assert_eq!(
        count_after_first,
        REGISTRY.len(),
        "first seed: expected {} permissions, got {count_after_first}",
        REGISTRY.len()
    );

    let hash_after_first = read_seeder_hash(&db, tenant_id)
        .await
        .expect("seeder_state hash not persisted after first seed");

    // ---- Second seed (same registry — must skip) ----
    seed_permissions(&db, tenant_id, REGISTRY)
        .await
        .expect("second seed failed");

    let count_after_second = count_permissions(&db, tenant_id).await;
    assert_eq!(
        count_after_second, count_after_first,
        "second seed with same registry must not add new rows"
    );

    let hash_after_second = read_seeder_hash(&db, tenant_id)
        .await
        .expect("seeder_state hash missing after second seed");
    assert_eq!(
        hash_after_second, hash_after_first,
        "hash must be unchanged after skip"
    );
}

/// Re-seeding with a changed registry must update the hash and create new rows.
#[tokio::test]
async fn seeder_re_seeds_when_registry_changed() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let tenant_id = Uuid::new_v4();

    seed_permissions(&db, tenant_id, REGISTRY)
        .await
        .expect("first seed failed");

    let hash_v1 = read_seeder_hash(&db, tenant_id)
        .await
        .expect("hash missing after first seed");

    seed_permissions(&db, tenant_id, REGISTRY_CHANGED)
        .await
        .expect("re-seed with changed registry failed");

    let count = count_permissions(&db, tenant_id).await;
    assert_eq!(
        count,
        REGISTRY_CHANGED.len(),
        "after re-seed: expected {} permissions",
        REGISTRY_CHANGED.len()
    );

    let hash_v2 = read_seeder_hash(&db, tenant_id)
        .await
        .expect("hash missing after re-seed");
    assert_ne!(hash_v1, hash_v2, "hash must change when registry changes");
}
