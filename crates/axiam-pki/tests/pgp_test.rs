//! Integration tests for PgpService — key generation, audit signing, and encryption.
//!
//! Validated threats:
//!   T-07-03: Ed25519 key rejected for encryption (pgp.rs:173)
//!   T-07-04: PGP sign+verify roundtrip (CA key material recoverable from encrypted store)

use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome};
use axiam_core::models::pgp_key::{CreatePgpKey, PgpKeyAlgorithm, PgpKeyPurpose};
use axiam_db::repository::SurrealPgpKeyRepository;
use axiam_pki::ca::PkiConfig;
use axiam_pki::pgp::PgpService;
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn test_pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: [0u8; 32],
    }
}

fn make_audit_entries(tenant_id: uuid::Uuid) -> Vec<AuditLogEntry> {
    vec![AuditLogEntry {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        actor_id: uuid::Uuid::new_v4(),
        actor_type: ActorType::System,
        action: "test.action".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: serde_json::json!({}),
        timestamp: Utc::now(),
    }]
}

// ---------------------------------------------------------------------------
// PGP sign + verify roundtrip (T-07-04)
// ---------------------------------------------------------------------------

/// Generate an Ed25519Legacy AuditSigning key, sign a batch, then verify the
/// signature parses back and verifies against the public key.
#[tokio::test]
async fn pgp_sign_audit_batch_and_verify_roundtrip() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(repo, test_pki_config());

    // Generate an AuditSigning key (Ed25519Legacy — signing only)
    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Test Auditor".into(),
            email: "audit@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::AuditSigning,
        })
        .await
        .expect("AuditSigning key generation must succeed");

    // The private key is NOT returned for AuditSigning keys — it is server-side only.
    assert!(
        generated.private_key_armored.is_none(),
        "private key must not be returned for AuditSigning keys"
    );

    // Sign a batch of audit entries
    let entries = make_audit_entries(tenant_id);
    let batch = svc
        .sign_audit_batch(tenant_id, entries)
        .await
        .expect("sign_audit_batch must succeed");

    assert!(
        !batch.signature_armored.is_empty(),
        "signature_armored must be non-empty"
    );
    assert!(
        batch.signature_armored.contains("BEGIN PGP MESSAGE"),
        "signature must be an armored PGP message"
    );

    // Verify roundtrip: parse the signed message and verify against the public key.
    // The public key is stored in the DB and retrieved via the generated key record.
    use pgp::composed::{Deserializable, Message, SignedPublicKey};

    let (pub_key, _) = SignedPublicKey::from_string(&generated.key.public_key_armored)
        .expect("public key must parse");

    // Parse the signed message — the armored data
    let (mut msg, _headers) =
        Message::from_string(&batch.signature_armored).expect("signed message must parse");

    // verify_read reads the message content and then verifies
    msg.verify_read(&pub_key)
        .expect("signature must verify against the public key");
}

// ---------------------------------------------------------------------------
// Ed25519 encryption reject (T-07-03 — ASVS V6)
// ---------------------------------------------------------------------------

/// Ed25519 keys must be rejected for encryption (pgp.rs:173).
/// Only Rsa4096 Export keys support encryption.
#[tokio::test]
async fn pgp_rejects_ed25519_for_encryption() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(repo, test_pki_config());

    // Generate an Ed25519 Export key
    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Ed25519 Export Key".into(),
            email: "export@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::Export,
        })
        .await
        .expect("Ed25519 Export key generation must succeed");

    // Encryption attempt must fail — Ed25519 is signing-only
    let result = svc
        .encrypt_for_export(tenant_id, generated.key.id, b"secret data")
        .await;

    assert!(
        result.is_err(),
        "Ed25519 key must be rejected for encryption"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("Ed25519") || err_msg.contains("encryption"),
        "error must mention Ed25519 / encryption, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// RSA-4096 Export key: encrypt succeeds
// ---------------------------------------------------------------------------

/// RSA-4096 Export keys must support encryption and return non-empty ciphertext.
#[tokio::test]
async fn pgp_rsa4096_export_key_encrypts_successfully() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(repo, test_pki_config());

    // Generate an Rsa4096 Export key
    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "RSA Export Key".into(),
            email: "rsa-export@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Rsa4096,
            purpose: PgpKeyPurpose::Export,
        })
        .await
        .expect("Rsa4096 Export key generation must succeed");

    // Encrypt some plaintext
    let export = svc
        .encrypt_for_export(tenant_id, generated.key.id, b"secret payload")
        .await
        .expect("Rsa4096 Export key must support encryption");

    assert!(
        !export.ciphertext_armored.is_empty(),
        "ciphertext must be non-empty"
    );
    assert!(
        export.ciphertext_armored.contains("BEGIN PGP MESSAGE"),
        "ciphertext must be an armored PGP message"
    );
}
