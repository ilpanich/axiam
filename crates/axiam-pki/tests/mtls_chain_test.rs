//! mTLS chain verification tests (SEC-024).
//!
//! Validates that `DeviceAuthService::authenticate` cryptographically verifies
//! the client certificate chain to the tenant/org CA — not just the stored
//! fingerprint — so a forged leaf with a matching fingerprint is rejected.
//!
//! Three cases:
//!   1. Accept: leaf signed by the tenant CA → authentication succeeds
//!   2. Reject: self-signed leaf with a matching stored fingerprint (forged) → chain error
//!   3. Reject: issuer CA not found (no-CA case) → fails closed

use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm, StoreCertificate,
};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::repository::{
    CaCertificateRepository, CertificateRepository, ServiceAccountRepository,
};
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealServiceAccountRepository,
};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use axiam_pki::mtls::DeviceAuthService;
use chrono::{Duration, Utc};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
use sha2::{Digest, Sha256};
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
// Case 1: Accept — leaf cert properly signed by the tenant CA
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_chain_accept_leaf_signed_by_tenant_ca() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));

    // Generate a real CA via CaService (stored in DB)
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let ca_svc = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let ca = ca_svc
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Chain Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    // Issue a leaf cert via CertService (signed by the CA, stored in DB)
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let cert_svc = CertService::new(
        ca_repo.clone(),
        cert_repo.clone(),
        test_pki_config(),
        sem.clone(),
    );
    let leaf = cert_svc
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=chain-test-device-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation must succeed");

    // Bind leaf to a service account
    let sa_repo = SurrealServiceAccountRepository::new(db.clone());
    let (sa, _secret) = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "Chain Test SA".into(),
            description: None,
        })
        .await
        .expect("service account creation must succeed");
    cert_repo
        .bind_to_service_account(tenant_id, leaf.certificate.id, sa.id)
        .await
        .expect("cert bind must succeed");

    // Authenticate — the leaf is signed by the CA in the DB → must succeed
    let svc_auth = DeviceAuthService::new(cert_repo, ca_repo);
    let identity = svc_auth
        .authenticate(&leaf.certificate.public_cert_pem)
        .await
        .expect("leaf signed by tenant CA must authenticate successfully");

    assert_eq!(identity.service_account_id, sa.id);
    assert_eq!(identity.tenant_id, tenant_id);
}

// ---------------------------------------------------------------------------
// Case 2: Reject — self-signed (forged) leaf with matching stored fingerprint
// ---------------------------------------------------------------------------
//
// Attack: an attacker generates a self-signed cert, submits it for registration
// (or exploits a race), and authenticates. The fingerprint matches the DB
// record but the cert was not signed by the tenant CA.
//
// The chain verify in DeviceAuthService::authenticate must catch this.

#[tokio::test]
async fn mtls_chain_reject_forged_leaf_with_matching_fingerprint() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();
    let org_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    // 1. Generate a self-signed "forged" leaf cert using rcgen directly
    //    (NOT signed by any CA stored in the DB).
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keygen must succeed");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params must build");
    params
        .distinguished_name
        .push(DnType::CommonName, "forged-device");
    params.is_ca = IsCa::NoCa;
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now.timestamp()).unwrap();
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(now.timestamp() + 86_400 * 30).unwrap();
    let forged_cert = params
        .self_signed(&key_pair)
        .expect("self-sign must succeed");
    let forged_pem = forged_cert.pem();
    let forged_der = forged_cert.der().to_vec();
    let fingerprint = hex::encode(Sha256::digest(&forged_der));

    // 2. Store a real CA in the DB (so the CA lookup succeeds, but the cert
    //    was NOT signed by this CA — the signature verify must fail).
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let ca_svc = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let real_ca = ca_svc
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Real CA (forged-leaf test)".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("real CA must be created");

    // 3. Register the forged cert in the DB with `issuer_ca_id` pointing to the
    //    real CA. The fingerprint matches what authenticate() will compute from the PEM.
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let _stored = cert_repo
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: real_ca.certificate.id,
            subject: "CN=forged-device".into(),
            public_cert_pem: forged_pem.clone(),
            fingerprint,
            cert_type: CertificateType::Device,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now,
            not_after: now + Duration::days(30),
            metadata: serde_json::json!({}),
        })
        .await
        .expect("storing forged cert in DB must succeed");

    // 4. Authenticate — fingerprint matches (passes step 2), status/expiry pass,
    //    but chain verify must FAIL because the cert is self-signed, not by real_ca.
    let svc_auth = DeviceAuthService::new(cert_repo, ca_repo);
    let result = svc_auth.authenticate(&forged_pem).await;

    assert!(result.is_err(), "forged self-signed leaf must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("chain verify failed") || err_msg.contains("verify"),
        "error must mention chain/signature verify failure, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Case 3: Reject — no active CA cert (fail-closed when CA is missing)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_chain_reject_when_no_ca_cert_found() {
    let db = setup_db().await;
    let tenant_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    // Generate a self-signed leaf cert (rcgen) and store it in DB with a
    // random issuer_ca_id that does NOT exist in the ca_certificate table.
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "no-ca-device");
    params.is_ca = IsCa::NoCa;
    params.not_before = time::OffsetDateTime::from_unix_timestamp(now.timestamp()).unwrap();
    params.not_after =
        time::OffsetDateTime::from_unix_timestamp(now.timestamp() + 86_400 * 30).unwrap();
    let leaf_cert = params.self_signed(&key_pair).unwrap();
    let leaf_pem = leaf_cert.pem();
    let leaf_der = leaf_cert.der().to_vec();
    let fingerprint = hex::encode(Sha256::digest(&leaf_der));

    let nonexistent_ca_id = uuid::Uuid::new_v4();

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());

    cert_repo
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: nonexistent_ca_id,
            subject: "CN=no-ca-device".into(),
            public_cert_pem: leaf_pem.clone(),
            fingerprint,
            cert_type: CertificateType::Device,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now,
            not_after: now + Duration::days(30),
            metadata: serde_json::json!({}),
        })
        .await
        .expect("storing cert with missing CA must succeed");

    // Authenticate — CA lookup fails → must fail closed
    let svc_auth = DeviceAuthService::new(cert_repo, ca_repo);
    let result = svc_auth.authenticate(&leaf_pem).await;

    assert!(result.is_err(), "no-CA case must fail closed");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("no CA certificate")
            || err_msg.contains("Certificate")
            || err_msg.contains("chain verify"),
        "error must indicate CA lookup failure, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Case 4: Reject — issuing CA has been revoked (SECHRD-05)
// ---------------------------------------------------------------------------
//
// The leaf cert is genuinely signed by the CA and would otherwise pass chain
// verification, but the issuing CA itself has since been revoked. Device
// auth must fail closed before `verify_signature` runs.

#[tokio::test]
async fn mtls_rejects_revoked_issuing_ca() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));

    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let ca_svc = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let ca = ca_svc
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Revoked CA Test".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let cert_svc = CertService::new(
        ca_repo.clone(),
        cert_repo.clone(),
        test_pki_config(),
        sem.clone(),
    );
    let leaf = cert_svc
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=revoked-ca-device".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation must succeed");

    let sa_repo = SurrealServiceAccountRepository::new(db.clone());
    let (sa, _secret) = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "Revoked CA Test SA".into(),
            description: None,
        })
        .await
        .expect("service account creation must succeed");
    cert_repo
        .bind_to_service_account(tenant_id, leaf.certificate.id, sa.id)
        .await
        .expect("cert bind must succeed");

    // Revoke the issuing CA via the repository's own revoke method (no direct
    // SurrealDB escape hatch needed here — a real production path exists).
    ca_repo
        .revoke(org_id, ca.certificate.id)
        .await
        .expect("CA revoke must succeed");

    let svc_auth = DeviceAuthService::new(cert_repo, ca_repo);
    let result = svc_auth
        .authenticate(&leaf.certificate.public_cert_pem)
        .await;

    assert!(
        result.is_err(),
        "device auth against a revoked issuing CA must fail closed"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("issuing CA is not active") || err_msg.contains("Certificate"),
        "error must indicate the issuing CA is not active, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Case 5: Reject — issuing CA is outside its validity window (SECHRD-05)
// ---------------------------------------------------------------------------
//
// The leaf cert is genuinely signed by the CA and would otherwise pass chain
// verification, but the issuing CA's own `not_after` has passed. Device auth
// must fail closed before `verify_signature` runs.

#[tokio::test]
async fn mtls_rejects_expired_issuing_ca() {
    let db = setup_db().await;

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));

    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let ca_svc = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let ca = ca_svc
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Expired CA Test".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let cert_svc = CertService::new(
        ca_repo.clone(),
        cert_repo.clone(),
        test_pki_config(),
        sem.clone(),
    );
    let leaf = cert_svc
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=expired-ca-device".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation must succeed");

    let sa_repo = SurrealServiceAccountRepository::new(db.clone());
    let (sa, _secret) = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "Expired CA Test SA".into(),
            description: None,
        })
        .await
        .expect("service account creation must succeed");
    cert_repo
        .bind_to_service_account(tenant_id, leaf.certificate.id, sa.id)
        .await
        .expect("cert bind must succeed");

    // Test-only escape hatch: no repo method sets an arbitrary validity
    // window, so backdate the CA's `not_after` via a direct SurrealDB
    // UPDATE. This is NOT a new production API — it exists solely to
    // simulate an issuing CA that has aged out of its validity window.
    let past = Utc::now() - Duration::days(1);
    db.query("UPDATE type::record('ca_certificate', $id) SET not_after = $not_after")
        .bind(("id", ca.certificate.id.to_string()))
        .bind(("not_after", past))
        .await
        .expect("test-only backdate query must succeed")
        .check()
        .expect("test-only backdate update must succeed");

    let svc_auth = DeviceAuthService::new(cert_repo, ca_repo);
    let result = svc_auth
        .authenticate(&leaf.certificate.public_cert_pem)
        .await;

    assert!(
        result.is_err(),
        "device auth against an expired issuing CA must fail closed"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("issuing CA certificate is expired") || err_msg.contains("Certificate"),
        "error must indicate the issuing CA is expired, got: {err_msg}"
    );
}
