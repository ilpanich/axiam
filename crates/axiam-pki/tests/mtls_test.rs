//! Integration tests for DeviceAuthService — mTLS device certificate authentication.
//!
//! Validated threat: T-07-01 (ASVS V2.9) — unknown-fingerprint, expired, and
//! inactive certificates must be rejected.

use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm, StoreCertificate,
};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::repository::CertificateRepository;
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealServiceAccountRepository,
};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use axiam_pki::mtls::DeviceAuthService;
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
        encryption_key: [0u8; 32],
    }
}

// ---------------------------------------------------------------------------
// Happy path: valid cert bound to a service account → DeviceIdentity returned
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_authenticate_valid_cert_returns_device_identity() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    // 1. Generate a CA
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config());
    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "mTLS Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    // 2. Issue a leaf cert
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo.clone(), test_pki_config());
    let leaf = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-mtls-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation must succeed");

    // 3. Create a service account and bind the cert to it
    let sa_repo = SurrealServiceAccountRepository::new(db.clone());
    use axiam_core::repository::ServiceAccountRepository;
    let (sa, _secret) = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "mTLS Device SA".into(),
        })
        .await
        .expect("service account creation must succeed");

    cert_repo
        .bind_to_service_account(tenant_id, leaf.certificate.id, sa.id)
        .await
        .expect("cert binding must succeed");

    // 4. Authenticate
    let svc_auth = DeviceAuthService::new(cert_repo);
    let identity = svc_auth
        .authenticate(&leaf.certificate.public_cert_pem)
        .await
        .expect("valid cert must authenticate successfully");

    assert_eq!(identity.service_account_id, sa.id);
    assert_eq!(identity.tenant_id, tenant_id);
    assert_eq!(identity.certificate_id, leaf.certificate.id);
}

// ---------------------------------------------------------------------------
// Reject: unknown fingerprint (cert not in DB)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_rejects_unknown_fingerprint() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();

    // Generate a CA and a cert — but do NOT register the leaf cert in the DB.
    // We generate a cert locally, get its PEM, then authenticate against an empty cert table.
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config());
    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Unknown FP CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    // Issue a cert but store it in a DIFFERENT DB — so the auth DB has no matching fingerprint.
    let other_db = Surreal::new::<Mem>(()).await.unwrap();
    other_db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&other_db).await.unwrap();
    let other_ca_repo = SurrealCaCertificateRepository::new(other_db.clone());
    let svc_ca2 = CaService::new(other_ca_repo.clone(), test_pki_config());
    let ca2 = svc_ca2
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "mTLS Test CA 2".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("second CA generation must succeed");

    let other_cert_repo = SurrealCertificateRepository::new(other_db);
    let svc_cert2 = CertService::new(other_ca_repo, other_cert_repo, test_pki_config());
    let leaf_not_registered = svc_cert2
        .generate(
            org_id,
            CreateCertificate {
                tenant_id: uuid::Uuid::new_v4(),
                issuer_ca_id: ca2.certificate.id,
                subject: "CN=unregistered-device".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation in other DB must succeed");

    // Use the main (empty-cert-table) DB to authenticate
    let cert_repo_main = SurrealCertificateRepository::new(db.clone());
    let svc_auth = DeviceAuthService::new(cert_repo_main);

    // The fingerprint is unknown in the main DB — must reject
    let result = svc_auth
        .authenticate(&leaf_not_registered.certificate.public_cert_pem)
        .await;

    assert!(
        result.is_err(),
        "cert with unknown fingerprint must be rejected"
    );
    // DeviceAuthService calls get_by_fingerprint_global which returns NotFound
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("NotFound") || err_msg.contains("not found"),
        "error must be NotFound, got: {err_msg}"
    );

    // Suppress unused warning — ca is used to set org_id context
    let _ = ca;
}

// ---------------------------------------------------------------------------
// Reject: expired cert (Active status, not_after in the past)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_rejects_expired_cert() {
    let db = setup_db().await;

    let tenant_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    // We need a real X.509 PEM whose fingerprint matches what's in the DB.
    // Strategy: generate a real cert via CertService (active + future dates),
    // then MANUALLY insert a duplicate row with a past not_after date and
    // a slightly-modified fingerprint so it looks like a different cert.
    //
    // Simpler approach: generate a real cert normally, then update its not_after
    // in the DB directly via raw SurrealQL. However, the repository does not expose
    // an UPDATE for dates. So we use StoreCertificate directly with the real PEM
    // and a forged fingerprint that matches a self-computed SHA-256.
    //
    // Actual implementation: use rcgen directly to generate a cert whose PEM
    // we know, compute its fingerprint ourselves, store with past dates, authenticate.

    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use sha2::{Digest, Sha256};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "expired-device");
    params.is_ca = IsCa::NoCa;
    // Set validity to be entirely in the past using time::OffsetDateTime
    params.not_before =
        time::OffsetDateTime::from_unix_timestamp(now.timestamp() - 86_400 * 10).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(now.timestamp() - 86_400).unwrap();

    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let fingerprint = hex::encode(Sha256::digest(cert.der()));

    // We need a CA ID for issuer_ca_id — create a placeholder CA in the DB
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    use axiam_core::repository::CaCertificateRepository;
    let fake_ca_org = uuid::Uuid::new_v4();
    let fake_ca = ca_repo
        .create(axiam_core::models::certificate::StoreCaCertificate {
            organization_id: fake_ca_org,
            subject: "Fake CA for expired test".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                .into(),
            fingerprint: "fake-fingerprint".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now - Duration::days(2),
            not_after: now + Duration::days(100),
            encrypted_private_key: None,
        })
        .await
        .unwrap();

    // Store the expired cert directly via the cert repo
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    cert_repo
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: fake_ca.id,
            subject: "CN=expired-device".into(),
            public_cert_pem: cert_pem.clone(),
            fingerprint: fingerprint.clone(),
            cert_type: CertificateType::Device,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now - Duration::days(10),
            not_after: now - Duration::days(1),
            metadata: serde_json::json!({}),
        })
        .await
        .expect("storing expired cert must succeed");

    // Authenticate — DeviceAuthService checks status (Active ✓) then not_after
    let svc_auth = DeviceAuthService::new(cert_repo);
    let result = svc_auth.authenticate(&cert_pem).await;

    assert!(result.is_err(), "expired cert must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    // mtls.rs returns AxiamError::Certificate("certificate is expired or not yet valid")
    // Assert the specific reject reason — a bare `|| contains("Certificate")` fallback
    // would pass even if the expiry check were swapped for any other Certificate error.
    assert!(
        err_msg.contains("expired"),
        "error must mention expiry, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Reject: revoked (inactive) cert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_rejects_revoked_cert() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    // Generate a CA and a leaf cert
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config());
    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Revoked Cert CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA must be created");

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo.clone(), test_pki_config());
    let leaf = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-to-revoke".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert must be created");

    // Revoke the leaf cert
    cert_repo
        .revoke(tenant_id, leaf.certificate.id)
        .await
        .expect("revoke must succeed");

    let svc_auth = DeviceAuthService::new(cert_repo);
    let result = svc_auth
        .authenticate(&leaf.certificate.public_cert_pem)
        .await;

    assert!(result.is_err(), "revoked cert must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    // mtls.rs: AxiamError::Certificate("certificate is not active")
    // Assert the specific reject reason — not just the Certificate error variant.
    assert!(
        err_msg.contains("not active"),
        "error must mention inactive status, got: {err_msg}"
    );
}
