//! CRUD-path coverage for the PKI services: `get`, `get_by_fingerprint`,
//! `list`, and `revoke` on CA certs, leaf certs, and PGP keys. Uses the
//! in-memory SurrealDB engine (`kv-mem`) — no external services required.

use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm,
};
use axiam_core::models::pgp_key::{CreatePgpKey, PgpKeyAlgorithm, PgpKeyPurpose};
use axiam_core::repository::Pagination;
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealPgpKeyRepository,
};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use axiam_pki::pgp::PgpService;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

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

fn sem() -> std::sync::Arc<tokio::sync::Semaphore> {
    std::sync::Arc::new(tokio::sync::Semaphore::new(4))
}

// ---------------------------------------------------------------------------
// CaService CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ca_get_list_revoke_lifecycle() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let org_id = Uuid::new_v4();
    let svc = CaService::new(ca_repo, test_pki_config(), sem());

    let ca = svc
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Root CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .unwrap();
    let ca_id = ca.certificate.id;

    // get
    let fetched = svc.get(org_id, ca_id).await.unwrap();
    assert_eq!(fetched.id, ca_id);
    assert_eq!(fetched.status, CertificateStatus::Active);

    // list
    let page = svc.list(org_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == ca_id));

    // revoke → status flips
    svc.revoke(org_id, ca_id).await.unwrap();
    let after = svc.get(org_id, ca_id).await.unwrap();
    assert_eq!(after.status, CertificateStatus::Revoked);
}

#[tokio::test]
async fn ca_get_unknown_is_not_found() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let svc = CaService::new(ca_repo, test_pki_config(), sem());
    let res = svc.get(Uuid::new_v4(), Uuid::new_v4()).await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// CertService CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cert_get_by_id_fingerprint_list_revoke() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem());
    let svc = CertService::new(ca_repo, cert_repo, test_pki_config(), sem());

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Root CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .unwrap();

    let leaf = svc
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-1".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .unwrap();
    let cert_id = leaf.certificate.id;
    let fingerprint = leaf.certificate.fingerprint.clone();

    // get by id
    let by_id = svc.get(tenant_id, cert_id).await.unwrap();
    assert_eq!(by_id.id, cert_id);

    // get by fingerprint
    let by_fp = svc
        .get_by_fingerprint(tenant_id, &fingerprint)
        .await
        .unwrap();
    assert_eq!(by_fp.id, cert_id);

    // list
    let page = svc.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == cert_id));

    // revoke
    svc.revoke(tenant_id, cert_id).await.unwrap();
    let after = svc.get(tenant_id, cert_id).await.unwrap();
    assert_eq!(after.status, CertificateStatus::Revoked);
}

#[tokio::test]
async fn cert_get_by_unknown_fingerprint_is_not_found() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let svc = CertService::new(ca_repo, cert_repo, test_pki_config(), sem());
    let res = svc.get_by_fingerprint(Uuid::new_v4(), "de:ad:be:ef").await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// PgpService CRUD
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pgp_get_list_revoke_lifecycle() {
    let db = setup_db().await;
    let repo = SurrealPgpKeyRepository::new(db.clone());
    let tenant_id = Uuid::new_v4();
    let svc = PgpService::new(repo, test_pki_config(), sem());

    let generated = svc
        .generate(CreatePgpKey {
            tenant_id,
            name: "Auditor".into(),
            email: "audit@axiam.dev".into(),
            algorithm: PgpKeyAlgorithm::Ed25519,
            purpose: PgpKeyPurpose::AuditSigning,
        })
        .await
        .unwrap();
    let key_id = generated.key.id;

    // get
    let fetched = svc.get(tenant_id, key_id).await.unwrap();
    assert_eq!(fetched.id, key_id);

    // list
    let page = svc.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|k| k.id == key_id));

    // revoke
    svc.revoke(tenant_id, key_id).await.unwrap();
}

#[tokio::test]
async fn pgp_get_unknown_is_not_found() {
    let db = setup_db().await;
    let repo = SurrealPgpKeyRepository::new(db.clone());
    let svc = PgpService::new(repo, test_pki_config(), sem());
    let res = svc.get(Uuid::new_v4(), Uuid::new_v4()).await;
    assert!(res.is_err());
}
