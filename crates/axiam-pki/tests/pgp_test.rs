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
        encryption_key: Some([0u8; 32]), // gitleaks:allow
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
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

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

// ---------------------------------------------------------------------------
// encrypt_for_export: status/purpose validation branches
// ---------------------------------------------------------------------------

/// A revoked (non-Active) key must be rejected for encryption, regardless
/// of algorithm/purpose (pgp.rs `encrypt_for_export`, status check).
#[tokio::test]
async fn pgp_encrypt_rejects_revoked_key() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Revoked Export Key".into(),
            email: "revoked@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Rsa4096,
            purpose: PgpKeyPurpose::Export,
        })
        .await
        .expect("Rsa4096 Export key generation must succeed");

    svc.revoke(tenant_id, generated.key.id)
        .await
        .expect("revoke must succeed");

    let result = svc
        .encrypt_for_export(tenant_id, generated.key.id, b"secret data")
        .await;

    assert!(result.is_err(), "revoked key must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("not active"),
        "error must mention the key is not active, got: {err_msg}"
    );
}

/// A key generated for AuditSigning (not Export) must be rejected by
/// `encrypt_for_export` even when the algorithm supports encryption
/// (pgp.rs `encrypt_for_export`, purpose check).
#[tokio::test]
async fn pgp_encrypt_rejects_non_export_purpose() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // AuditSigning keys can only be Ed25519 in practice, but the purpose
    // check runs before the algorithm check, so any AuditSigning key must
    // be rejected here regardless.
    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Signing Key".into(),
            email: "signer@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::AuditSigning,
        })
        .await
        .expect("AuditSigning key generation must succeed");

    let result = svc
        .encrypt_for_export(tenant_id, generated.key.id, b"secret data")
        .await;

    assert!(result.is_err(), "non-Export key must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("Export"),
        "error must mention Export keys, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// generate(): missing encryption key configuration (SEC-012)
// ---------------------------------------------------------------------------

/// Generating a non-Export (i.e. server-stored) key without
/// `PkiConfig::encryption_key` configured must fail fast rather than
/// storing an unencrypted private key (pgp.rs `generate`, SEC-012).
#[tokio::test]
async fn pgp_generate_audit_signing_without_encryption_key_errors() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(
        repo,
        PkiConfig {
            encryption_key: None,
        },
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "No Key Config".into(),
            email: "nokey@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::AuditSigning,
        })
        .await;

    assert!(
        result.is_err(),
        "AuditSigning key generation without an encryption key must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("ENCRYPTION_KEY"),
        "error must mention the missing encryption key config, got: {err_msg}"
    );
}

/// Export keys are never stored encrypted (private key is returned once,
/// never persisted), so generating one must succeed even with no
/// encryption key configured.
#[tokio::test]
async fn pgp_generate_export_key_without_encryption_key_succeeds() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(
        repo,
        PkiConfig {
            encryption_key: None,
        },
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Export No Key Config".into(),
            email: "exportnokey@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Rsa4096,
            purpose: PgpKeyPurpose::Export,
        })
        .await
        .expect("Export key generation must not require an encryption key");

    assert!(
        result.private_key_armored.is_some(),
        "Export key must return its private key"
    );
}

// ---------------------------------------------------------------------------
// sign_audit_batch: missing signing key / missing encryption key
// ---------------------------------------------------------------------------

/// Signing a batch for a tenant with no AuditSigning key at all must
/// surface a not-found error from `get_signing_key`, not panic.
#[tokio::test]
async fn pgp_sign_audit_batch_without_signing_key_errors() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    let repo = SurrealPgpKeyRepository::new(db);
    let svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let entries = make_audit_entries(tenant_id);
    let result = svc.sign_audit_batch(tenant_id, entries).await;

    assert!(
        result.is_err(),
        "signing with no AuditSigning key for the tenant must fail"
    );
}

/// A service configured with no `PkiConfig::encryption_key` cannot decrypt
/// a stored signing key's private key material, so `sign_audit_batch` must
/// fail even though a valid signing key exists.
#[tokio::test]
async fn pgp_sign_audit_batch_without_encryption_key_errors() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();

    // Generate the signing key with a properly configured service.
    let repo = SurrealPgpKeyRepository::new(db.clone());
    let setup_svc = PgpService::new(
        repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );
    setup_svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Auditor".into(),
            email: "audit2@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::AuditSigning,
        })
        .await
        .expect("AuditSigning key generation must succeed");

    // Now build a second service pointed at the same DB but with no
    // encryption key configured, and try to sign with it.
    let repo2 = SurrealPgpKeyRepository::new(db);
    let svc_no_key = PgpService::new(
        repo2,
        PkiConfig {
            encryption_key: None,
        },
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let entries = make_audit_entries(tenant_id);
    let result = svc_no_key.sign_audit_batch(tenant_id, entries).await;

    assert!(
        result.is_err(),
        "signing without a configured encryption key must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("ENCRYPTION_KEY"),
        "error must mention the missing encryption key config, got: {err_msg}"
    );
}
