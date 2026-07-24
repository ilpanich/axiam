//! CRUD + edge-case coverage for `SurrealCaCertificateRepository` — this
//! repository carried NO tests at all (0% coverage) before this file.
//! Uses the in-memory SurrealDB engine — no external services required.

use axiam_core::models::certificate::{CertificateStatus, KeyAlgorithm, StoreCaCertificate};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::repository::{CaCertificateRepository, OrganizationRepository, Pagination};
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealOrganizationRepository};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid) {
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
    (db, org.id)
}

fn sample_ca(organization_id: Uuid) -> StoreCaCertificate {
    StoreCaCertificate {
        organization_id,
        subject: "CN=ACME Root CA".into(),
        public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".into(),
        fingerprint: "sha256:deadbeef".into(),
        key_algorithm: KeyAlgorithm::Rsa4096,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(3650),
        encrypted_private_key: Some(vec![1, 2, 3, 4, 5]),
    }
}

#[tokio::test]
async fn create_and_get_by_id() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let ca = repo.create(sample_ca(org_id)).await.unwrap();
    assert_eq!(ca.organization_id, org_id);
    assert_eq!(ca.subject, "CN=ACME Root CA");
    assert_eq!(ca.key_algorithm, KeyAlgorithm::Rsa4096);
    assert_eq!(ca.status, CertificateStatus::Active);
    assert_eq!(ca.encrypted_private_key, Some(vec![1, 2, 3, 4, 5]));

    let fetched = repo.get_by_id(org_id, ca.id).await.unwrap();
    assert_eq!(fetched.id, ca.id);
    assert_eq!(fetched.fingerprint, "sha256:deadbeef");
}

#[tokio::test]
async fn create_with_ed25519_and_no_private_key() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let mut input = sample_ca(org_id);
    input.key_algorithm = KeyAlgorithm::Ed25519;
    input.encrypted_private_key = None;

    let ca = repo.create(input).await.unwrap();
    assert_eq!(ca.key_algorithm, KeyAlgorithm::Ed25519);
    assert!(ca.encrypted_private_key.is_none());
}

#[tokio::test]
async fn get_by_id_wrong_org_not_found() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let ca = repo.create(sample_ca(org_id)).await.unwrap();
    let other_org = Uuid::new_v4();

    let result = repo.get_by_id(other_org, ca.id).await;
    assert!(result.is_err(), "cross-org lookup must not find the CA");
}

#[tokio::test]
async fn get_by_id_missing_returns_not_found() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_id(org_id, missing).await.is_err());
}

#[tokio::test]
async fn revoke_transitions_status() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let ca = repo.create(sample_ca(org_id)).await.unwrap();
    repo.revoke(org_id, ca.id).await.unwrap();

    let fetched = repo.get_by_id(org_id, ca.id).await.unwrap();
    assert_eq!(fetched.status, CertificateStatus::Revoked);
}

#[tokio::test]
async fn revoke_missing_returns_not_found() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.revoke(org_id, missing).await.is_err());
}

#[tokio::test]
async fn revoke_wrong_org_returns_not_found() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let ca = repo.create(sample_ca(org_id)).await.unwrap();
    let other_org = Uuid::new_v4();

    assert!(repo.revoke(other_org, ca.id).await.is_err());
    // Original remains Active — the revoke never applied cross-org.
    let fetched = repo.get_by_id(org_id, ca.id).await.unwrap();
    assert_eq!(fetched.status, CertificateStatus::Active);
}

#[tokio::test]
async fn list_by_organization_paginates_and_isolates() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let other_org = SurrealOrganizationRepository::new(db)
        .create(CreateOrganization {
            name: "Other Org".into(),
            slug: "other-org".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    for i in 0..5 {
        let mut input = sample_ca(org_id);
        input.fingerprint = format!("sha256:fp-{i}");
        repo.create(input).await.unwrap();
    }
    // A CA belonging to a different organization must not leak into org_id's list.
    let mut foreign = sample_ca(other_org);
    foreign.fingerprint = "sha256:foreign".into();
    repo.create(foreign).await.unwrap();

    let page1 = repo
        .list_by_organization(
            org_id,
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
        .list_by_organization(
            org_id,
            Pagination {
                offset: 3,
                limit: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(page2.items.len(), 2);

    let other_list = repo
        .list_by_organization(other_org, Pagination::default())
        .await
        .unwrap();
    assert_eq!(other_list.total, 1);
}

#[tokio::test]
async fn get_by_issuer_id_finds_regardless_of_organization() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);

    let ca = repo.create(sample_ca(org_id)).await.unwrap();

    let found = repo.get_by_issuer_id(ca.id).await.unwrap();
    assert_eq!(found.id, ca.id);
    assert_eq!(found.organization_id, org_id);
}

#[tokio::test]
async fn get_by_issuer_id_missing_returns_not_found() {
    let (db, _org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_issuer_id(missing).await.is_err());
}
