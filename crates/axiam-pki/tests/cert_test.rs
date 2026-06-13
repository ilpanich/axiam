//! Integration tests for CertService — leaf cert issuance and CA validation.

use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm, StoreCaCertificate,
};
use axiam_core::repository::CaCertificateRepository;
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use chrono::{Duration, Utc};
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

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

/// Generate a CA, then issue a leaf cert against it — happy path.
#[tokio::test]
async fn cert_generate_against_active_ca_succeeds() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config());

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let generated = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("Leaf cert generation must succeed");

    assert!(
        generated
            .certificate
            .public_cert_pem
            .contains("CERTIFICATE"),
        "leaf cert PEM must contain CERTIFICATE header"
    );
    assert!(
        !generated.private_key_pem.is_empty(),
        "leaf private key must be returned"
    );
}

// ---------------------------------------------------------------------------
// Reject cases
// ---------------------------------------------------------------------------

/// Revoking the CA must prevent leaf cert issuance (inactive CA reject).
#[tokio::test]
async fn cert_generate_rejects_revoked_ca() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config());
    let svc_cert = CertService::new(ca_repo.clone(), cert_repo, test_pki_config());

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Revoked CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    svc_ca
        .revoke(org_id, ca.certificate.id)
        .await
        .expect("revoke must succeed");

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-002".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf cert issuance against a revoked CA must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("not active"),
        "error must mention 'not active', got: {err_msg}"
    );
}

/// Storing a CA with `not_after` in the past must block leaf cert issuance (expired CA reject).
#[tokio::test]
async fn cert_generate_rejects_expired_ca() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let now = Utc::now();

    // Build an expired CA row directly via StoreCaCertificate so not_after is in the past.
    // The CA is generated with normal rcgen to produce real cert PEM and key data,
    // then stored with a backdated not_after so CertService sees it as expired.
    use axiam_pki::ca::PkiConfig as Cfg;
    let temp_config = Cfg {
        encryption_key: [0u8; 32],
    };
    let svc_ca_temp = CaService::new(ca_repo.clone(), temp_config);
    let real_ca = svc_ca_temp
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Expired CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 1,
        })
        .await
        .expect("CA generation must succeed");

    // Now insert a second, manipulated CA row with not_after in the past.
    // We use the real generated key material so rcgen can reconstruct and sign with it,
    // but override the validity window to be expired.
    let expired_ca = ca_repo
        .create(StoreCaCertificate {
            organization_id: org_id,
            subject: "Expired CA Clone".into(),
            public_cert_pem: real_ca.certificate.public_cert_pem.clone(),
            fingerprint: format!("expired-{}", real_ca.certificate.fingerprint),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now - Duration::days(10),
            not_after: now - Duration::days(1), // expired yesterday
            encrypted_private_key: real_ca.certificate.encrypted_private_key.clone(),
        })
        .await
        .expect("direct CA row creation must succeed");

    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config());

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: expired_ca.id,
                subject: "CN=device-003".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf cert issuance against an expired CA must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    // Assert the specific reject reason. A `|| contains("valid")` fallback was too
    // broad ("valid" appears in many unrelated messages); the CA-expiry path must
    // explicitly mention expiry.
    assert!(
        err_msg.contains("expired"),
        "error must mention expiry, got: {err_msg}"
    );
}
