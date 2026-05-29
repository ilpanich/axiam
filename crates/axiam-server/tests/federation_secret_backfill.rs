//! Integration test: federation client-secret boot backfill (D-12).
//!
//! Verifies that `migrate_plaintext_federation_secrets` correctly:
//!
//! 1. Detects rows with a plaintext `client_secret` and no ciphertext.
//! 2. Encrypts each secret with AES-256-GCM split-column storage (D-11).
//! 3. Clears the legacy `client_secret` column.
//! 4. Is idempotent — second invocation returns 0 migrations.
//! 5. Decryption round-trips correctly.

use axiam_db::{SurrealAuditLogRepository, SurrealFederationConfigRepository, run_migrations};
use axiam_federation::secrets::{
    current_key_version, decrypt_client_secret, migrate_plaintext_federation_secrets,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use surrealdb_types::SurrealValue;

/// A 32-byte AES key for testing (not secret — test-only).
const TEST_KEY: [u8; 32] = [0x42u8; 32];

/// Set up an in-memory DB, run migrations, and seed test data.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
    uuid::Uuid, // config_id
) {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");

    // Create a minimal org and tenant to satisfy FK-style relationships.
    let tenant_id = uuid::Uuid::new_v4();
    let config_id = uuid::Uuid::new_v4();

    // Insert a federation_config row with a plaintext client_secret and
    // all three encrypted columns NULL (the pre-Phase-4 state).
    let _ = db
        .query(
            "CREATE type::record('federation_config', $id) SET \
             tenant_id = $tenant_id, \
             provider = 'test-idp', \
             protocol = 'OidcConnect', \
             metadata_url = 'https://idp.example.com/.well-known/openid-configuration', \
             client_id = 'client-abc', \
             client_secret = 'supersecret', \
             attribute_map = {}, \
             enabled = true, \
             allowed_algorithms = ['RS256'], \
             created_at = time::now(), \
             updated_at = time::now()",
        )
        .bind(("id", config_id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .expect("insert federation_config");

    (db, tenant_id, config_id)
}

#[derive(Debug, SurrealValue)]
struct SecretRow {
    client_secret: Option<String>,
    client_secret_nonce: Option<String>,
    client_secret_ciphertext: Option<String>,
    client_secret_key_version: Option<i64>,
}

/// Re-select the federation_config row to inspect encrypted columns.
///
/// Scoped by both `tenant_id` and `config_id` — this confirms the
/// tenant-scoped `set_encrypted_secret` UPDATE (which carries a
/// `WHERE tenant_id = $tenant_id` clause) actually persisted the encrypted
/// columns under the correct tenant.
async fn read_secret_row(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: uuid::Uuid,
    config_id: uuid::Uuid,
) -> SecretRow {
    let result = db
        .query(
            "SELECT client_secret, client_secret_nonce, \
             client_secret_ciphertext, client_secret_key_version \
             FROM federation_config \
             WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
        )
        .bind(("id", config_id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .expect("select");

    let mut result = result.check().expect("check");
    let rows: Vec<SecretRow> = result.take(0).expect("take");
    rows.into_iter().next().expect("row must exist")
}

#[tokio::test]
async fn backfill_encrypts_plaintext_secret_and_is_idempotent() {
    let (db, tenant_id, config_id) = setup().await;
    let fed_repo = SurrealFederationConfigRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());

    // --- Pre-condition: plaintext secret is present, encrypted columns are absent ---
    let before = read_secret_row(&db, tenant_id, config_id).await;
    assert_eq!(before.client_secret.as_deref(), Some("supersecret"));
    assert!(before.client_secret_nonce.is_none());
    assert!(before.client_secret_ciphertext.is_none());
    assert!(before.client_secret_key_version.is_none());

    // --- Run the migration ---
    let migrated = migrate_plaintext_federation_secrets(&fed_repo, &audit_repo, &TEST_KEY)
        .await
        .expect("migration must succeed");
    assert_eq!(migrated, 1, "exactly 1 row should be migrated");

    // --- Post-condition assertions ---
    let after = read_secret_row(&db, tenant_id, config_id).await;

    // Legacy plaintext column must be cleared (set to empty string to avoid
    // violating the TYPE string schema constraint).
    let legacy = after.client_secret.as_deref().unwrap_or("");
    assert!(
        legacy.is_empty(),
        "client_secret must be empty after backfill, got: {:?}",
        after.client_secret
    );

    // Nonce and ciphertext must be non-empty base64.
    let nonce = after
        .client_secret_nonce
        .as_deref()
        .expect("nonce must be present");
    let ciphertext = after
        .client_secret_ciphertext
        .as_deref()
        .expect("ciphertext must be present");

    assert!(!nonce.is_empty(), "nonce must be non-empty");
    assert!(!ciphertext.is_empty(), "ciphertext must be non-empty");
    assert_ne!(
        nonce, ciphertext,
        "nonce and ciphertext must be distinct values"
    );

    // Key version must be set.
    assert_eq!(
        after.client_secret_key_version,
        Some(current_key_version()),
        "key version must match current_key_version()"
    );

    // Decryption must round-trip correctly.
    let decrypted =
        decrypt_client_secret(&TEST_KEY, nonce, ciphertext).expect("decryption must succeed");
    assert_eq!(
        decrypted, "supersecret",
        "decrypted value must match original"
    );

    // --- Idempotency: second run returns 0 ---
    let migrated_again = migrate_plaintext_federation_secrets(&fed_repo, &audit_repo, &TEST_KEY)
        .await
        .expect("second migration must succeed");
    assert_eq!(migrated_again, 0, "second run must be a no-op");
}
