//! REQ-14 AC-5 — PKI fail-fast tests (SEC-012).
//!
//! Verifies that CA generation refuses to operate when no encryption key is
//! configured, instead of silently encrypting CA private keys with an all-zero
//! key (the previous insecure fallback).

use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{CreateCaCertificate, KeyAlgorithm};
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::{CaService, PkiConfig};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// SEC-012: generate with no encryption key must return an error, never Ok.
#[tokio::test]
async fn ca_generate_without_key_errors() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let config = PkiConfig {
        encryption_key: None,
    };
    let svc = CaService::new(
        repo,
        config,
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .generate(CreateCaCertificate {
            organization_id: uuid::Uuid::new_v4(),
            subject: "Test CA no-key".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await;

    assert!(result.is_err(), "generate without encryption key must fail");
    match result.unwrap_err() {
        AxiamError::Internal(msg) => {
            assert!(
                msg.contains("AXIAM__PKI__ENCRYPTION_KEY"),
                "error must name the missing env var, got: {msg}"
            );
        }
        other => panic!("expected AxiamError::Internal, got {other:?}"),
    }
}

/// SEC-012: generate with a real key must succeed (regression guard).
#[tokio::test]
async fn ca_generate_with_key_ok() {
    let db = setup_db().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let config = PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
    };
    let svc = CaService::new(
        repo,
        config,
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .generate(CreateCaCertificate {
            organization_id: uuid::Uuid::new_v4(),
            subject: "Test CA with-key".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await;

    assert!(result.is_ok(), "generate with a real key must succeed");
}
