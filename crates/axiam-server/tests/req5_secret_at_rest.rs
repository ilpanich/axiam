//! REQ-5 federation client-secret at-rest encryption tests.
//!
//! Verifies D-11 split-column storage and the boot backfill (D-12):
//! - New row created via the repo: `client_secret_ciphertext` and
//!   `client_secret_nonce` populated; `client_secret` (legacy) empty.
//! - Legacy plaintext row: migrated to encrypted split-column storage.
//!
//! These tests are identical in scope to `federation_secret_backfill.rs`
//! but are named per the REQ-5 traceability requirement (one test file per
//! acceptance criterion).

use axiam_db::{SurrealAuditLogRepository, SurrealFederationConfigRepository, run_migrations};
use axiam_federation::secrets::{
    current_key_version, decrypt_client_secret, migrate_plaintext_federation_secrets,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

const TEST_KEY: [u8; 32] = [0xABu8; 32];

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");
    db
}

#[derive(Debug, SurrealValue)]
struct SecretRow {
    client_secret: Option<String>,
    client_secret_nonce: Option<String>,
    client_secret_ciphertext: Option<String>,
    client_secret_key_version: Option<i64>,
}

async fn read_secret_row(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    config_id: Uuid,
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
    let result = result.check().expect("check");
    let mut result = result;
    let rows: Vec<SecretRow> = result.take(0).expect("take");
    rows.into_iter().next().expect("row must exist")
}

/// Base64 pattern: all characters from the base64 alphabet (standard + padding).
fn is_valid_base64(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

// ---------------------------------------------------------------------------
// Test 1: legacy plaintext row is migrated (D-12 backfill)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn req5_secret_backfill_encrypts_plaintext_and_is_idempotent() {
    let db = setup().await;
    let tenant_id = Uuid::new_v4();
    let config_id = Uuid::new_v4();

    // Insert a legacy row with plaintext client_secret and no encrypted columns.
    db.query(
        "CREATE type::record('federation_config', $id) SET \
         tenant_id = $tenant_id, \
         provider = 'legacy-idp', \
         protocol = 'OidcConnect', \
         metadata_url = 'https://legacy-idp.example.com/.well-known/openid-configuration', \
         client_id = 'legacy-client', \
         client_secret = 'my-plaintext-secret', \
         attribute_map = {}, \
         enabled = true, \
         allowed_algorithms = ['RS256'], \
         created_at = time::now(), \
         updated_at = time::now()",
    )
    .bind(("id", config_id.to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .await
    .expect("insert legacy row")
    .check()
    .expect("check insert");

    let fed_repo = SurrealFederationConfigRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());

    // Pre-condition: plaintext present, encrypted columns absent.
    let before = read_secret_row(&db, tenant_id, config_id).await;
    assert_eq!(before.client_secret.as_deref(), Some("my-plaintext-secret"));
    assert!(before.client_secret_nonce.is_none());
    assert!(before.client_secret_ciphertext.is_none());
    assert!(before.client_secret_key_version.is_none());

    // Run migration.
    let count = migrate_plaintext_federation_secrets(&fed_repo, &audit_repo, &TEST_KEY)
        .await
        .expect("migration");
    assert_eq!(count, 1, "exactly 1 row migrated");

    let after = read_secret_row(&db, tenant_id, config_id).await;

    // Legacy column cleared.
    let legacy = after.client_secret.as_deref().unwrap_or("");
    assert!(
        legacy.is_empty(),
        "client_secret must be empty after backfill; got: {legacy:?}"
    );

    // Split-column storage populated (D-11).
    let nonce = after.client_secret_nonce.as_deref().expect("nonce present");
    let ciphertext = after
        .client_secret_ciphertext
        .as_deref()
        .expect("ciphertext present");

    assert!(is_valid_base64(nonce), "nonce must be base64; got: {nonce}");
    assert!(
        is_valid_base64(ciphertext),
        "ciphertext must be base64; got: {ciphertext}"
    );
    assert_ne!(nonce, ciphertext, "nonce and ciphertext must be distinct");
    assert_ne!(
        ciphertext, "my-plaintext-secret",
        "ciphertext must NOT be the plaintext"
    );

    // Key version set.
    assert_eq!(
        after.client_secret_key_version,
        Some(current_key_version()),
        "key version must be current"
    );

    // Decryption round-trips correctly.
    let decrypted =
        decrypt_client_secret(&TEST_KEY, nonce, ciphertext).expect("decryption must succeed");
    assert_eq!(decrypted, "my-plaintext-secret");

    // Idempotency.
    let count2 = migrate_plaintext_federation_secrets(&fed_repo, &audit_repo, &TEST_KEY)
        .await
        .expect("second migration");
    assert_eq!(count2, 0, "second run must be a no-op");
}

// ---------------------------------------------------------------------------
// Test 2: encryption helpers produce valid split-column values (D-11)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn req5_encrypt_client_secret_produces_split_column_storage() {
    use axiam_federation::secrets::encrypt_client_secret;

    let plaintext = "new-secret-value";
    let (nonce_b64, ciphertext_b64) = encrypt_client_secret(&TEST_KEY, plaintext).expect("encrypt");

    // Both values are valid base64.
    assert!(
        is_valid_base64(&nonce_b64),
        "nonce must be base64; got: {nonce_b64}"
    );
    assert!(
        is_valid_base64(&ciphertext_b64),
        "ciphertext must be base64; got: {ciphertext_b64}"
    );

    // Columns are distinct (nonce != ciphertext — D-11 split storage).
    assert_ne!(
        nonce_b64, ciphertext_b64,
        "nonce and ciphertext must be distinct"
    );

    // Ciphertext is NOT the plaintext.
    assert_ne!(
        ciphertext_b64, plaintext,
        "ciphertext must NOT equal plaintext"
    );

    // Round-trip decryption.
    let decrypted = decrypt_client_secret(&TEST_KEY, &nonce_b64, &ciphertext_b64)
        .expect("decryption must succeed");
    assert_eq!(decrypted, plaintext, "decrypted value must match original");

    // Key version is set.
    assert_eq!(current_key_version(), 1, "current key version must be 1");

    // Different encryption calls produce different nonces (probabilistic — both columns differ).
    let (nonce2, ct2) = encrypt_client_secret(&TEST_KEY, plaintext).expect("encrypt again");
    // Nonces should differ (IVs are random) — this could theoretically fail with astronomically
    // low probability, but with a 12-byte random nonce it's ~2^(-96).
    assert_ne!(nonce_b64, nonce2, "each encryption must use a fresh nonce");
    // Decryption of second ciphertext also works.
    let decrypted2 = decrypt_client_secret(&TEST_KEY, &nonce2, &ct2).expect("second decrypt");
    assert_eq!(decrypted2, plaintext);
}
