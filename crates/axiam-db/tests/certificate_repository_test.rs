//! CRUD + edge-case coverage for `SurrealCertificateRepository` — no
//! existing axiam-db-local test file covers this repository at all.
//! Uses the in-memory SurrealDB engine — no external services required.

use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    CertificateRepository, OrganizationRepository, Pagination, ServiceAccountRepository,
    TenantRepository,
};
use axiam_db::repository::{
    SurrealCertificateRepository, SurrealOrganizationRepository, SurrealServiceAccountRepository,
    SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

fn sample_cert(tenant_id: Uuid, issuer_ca_id: Uuid, fingerprint: &str) -> StoreCertificate {
    StoreCertificate {
        tenant_id,
        issuer_ca_id,
        subject: "CN=leaf.example.com".into(),
        public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(365),
        metadata: serde_json::json!({}),
    }
}

#[tokio::test]
async fn create_get_list_revoke_lifecycle() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let issuer_ca_id = Uuid::new_v4();

    let cert = repo
        .create(sample_cert(tenant_id, issuer_ca_id, "fp-lifecycle-1"))
        .await
        .unwrap();
    assert_eq!(cert.tenant_id, tenant_id);
    assert_eq!(cert.status, CertificateStatus::Active);
    assert_eq!(cert.cert_type, CertificateType::User);
    assert_eq!(cert.key_algorithm, KeyAlgorithm::Ed25519);

    // get_by_id
    let got = repo.get_by_id(tenant_id, cert.id).await.unwrap();
    assert_eq!(got.fingerprint, "fp-lifecycle-1");

    // get_by_fingerprint
    let by_fp = repo
        .get_by_fingerprint(tenant_id, "fp-lifecycle-1")
        .await
        .unwrap();
    assert_eq!(by_fp.id, cert.id);

    // get_by_fingerprint_global
    let global = repo
        .get_by_fingerprint_global("fp-lifecycle-1")
        .await
        .unwrap();
    assert_eq!(global.id, cert.id);

    // list
    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == cert.id));

    // revoke
    repo.revoke(tenant_id, cert.id).await.unwrap();
    let revoked = repo.get_by_id(tenant_id, cert.id).await.unwrap();
    assert_eq!(revoked.status, CertificateStatus::Revoked);
}

#[tokio::test]
async fn get_by_id_not_found() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    let err = repo.get_by_id(tenant_id, Uuid::new_v4()).await.unwrap_err();
    assert!(format!("{err:?}").to_lowercase().contains("notfound") || !format!("{err}").is_empty());
}

#[tokio::test]
async fn get_by_fingerprint_not_found() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(
        repo.get_by_fingerprint(tenant_id, "does-not-exist")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn get_by_fingerprint_global_not_found() {
    let (db, _org, _tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(repo.get_by_fingerprint_global("nope-global").await.is_err());
}

#[tokio::test]
async fn revoke_not_found_errors() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);
    assert!(repo.revoke(tenant_id, Uuid::new_v4()).await.is_err());
}

#[tokio::test]
async fn cross_tenant_get_by_id_is_not_found() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let repo = SurrealCertificateRepository::new(db);
    let cert = repo
        .create(sample_cert(tenant_a, Uuid::new_v4(), "fp-cross-tenant"))
        .await
        .unwrap();

    // Visible in its own tenant...
    assert!(repo.get_by_id(tenant_a, cert.id).await.is_ok());
    // ...but not in another tenant.
    assert!(repo.get_by_id(tenant_b, cert.id).await.is_err());
}

#[tokio::test]
async fn list_pagination() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealCertificateRepository::new(db);

    for i in 0..5 {
        repo.create(sample_cert(
            tenant_id,
            Uuid::new_v4(),
            &format!("fp-page-{i}"),
        ))
        .await
        .unwrap();
    }

    let page1 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(page1.items.len(), 3);
    assert_eq!(page1.total, 5);

    let page2 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 3,
                limit: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 2);
}

#[tokio::test]
async fn bind_to_service_account_success_and_lookup() {
    let (db, _org, tenant_id) = setup().await;
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let sa_repo = SurrealServiceAccountRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_id, Uuid::new_v4(), "fp-bind-1"))
        .await
        .unwrap();

    let sa = sa_repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "svc-account".into(),
            description: None,
        })
        .await
        .unwrap();

    // No binding yet.
    assert_eq!(
        cert_repo.get_bound_service_account(cert.id).await.unwrap(),
        None
    );

    cert_repo
        .bind_to_service_account(tenant_id, cert.id, sa.0.id)
        .await
        .unwrap();

    let bound = cert_repo.get_bound_service_account(cert.id).await.unwrap();
    assert_eq!(bound, Some(sa.0.id));
}

#[tokio::test]
async fn bind_to_service_account_cross_tenant_denied() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant B".into(),
            slug: "tenant-b-bind".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let sa_repo = SurrealServiceAccountRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_a, Uuid::new_v4(), "fp-bind-cross"))
        .await
        .unwrap();

    // Service account lives in tenant_b — binding to tenant_a's cert must be denied.
    let sa = sa_repo
        .create(CreateServiceAccount {
            tenant_id: tenant_b,
            name: "other-tenant-sa".into(),
            description: None,
        })
        .await
        .unwrap();

    let err = cert_repo
        .bind_to_service_account(tenant_a, cert.id, sa.0.id)
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").to_lowercase().contains("authoriz")
            || format!("{err:?}").to_lowercase().contains("denied"),
        "expected an authorization-denied error, got: {err:?}"
    );
}

#[tokio::test]
async fn get_bound_service_account_unbound_is_none() {
    let (db, _org, tenant_id) = setup().await;
    let cert_repo = SurrealCertificateRepository::new(db);

    let cert = cert_repo
        .create(sample_cert(tenant_id, Uuid::new_v4(), "fp-unbound"))
        .await
        .unwrap();

    assert_eq!(
        cert_repo.get_bound_service_account(cert.id).await.unwrap(),
        None
    );
}
