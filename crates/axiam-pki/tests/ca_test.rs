//! Integration tests for CaService — CA keypair generation and validation.

use axiam_core::models::certificate::{CreateCaCertificate, KeyAlgorithm};
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::ca::{CaService, PkiConfig};
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

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ca_generate_ed25519_returns_valid_pem_and_fingerprint() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let svc = CaService::new(repo, test_pki_config());

    let result = svc
        .generate(CreateCaCertificate {
            organization_id: uuid::Uuid::new_v4(),
            subject: "Test CA Ed25519".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    assert!(
        !result.private_key_pem.is_empty(),
        "private key PEM must be non-empty"
    );
    assert!(
        result.certificate.public_cert_pem.contains("CERTIFICATE"),
        "public cert PEM must contain CERTIFICATE header"
    );
    assert!(
        !result.certificate.fingerprint.is_empty(),
        "fingerprint must be non-empty"
    );
}

// ---------------------------------------------------------------------------
// Reject cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ca_generate_rejects_zero_validity() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let svc = CaService::new(repo, test_pki_config());

    let result = svc
        .generate(CreateCaCertificate {
            organization_id: uuid::Uuid::new_v4(),
            subject: "Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 0,
        })
        .await;

    assert!(result.is_err(), "validity_days=0 must be rejected");
}

#[tokio::test]
async fn ca_generate_rejects_validity_above_max() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let svc = CaService::new(repo, test_pki_config());

    let result = svc
        .generate(CreateCaCertificate {
            organization_id: uuid::Uuid::new_v4(),
            subject: "Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 99_999,
        })
        .await;

    assert!(result.is_err(), "validity_days above MAX must be rejected");
}
