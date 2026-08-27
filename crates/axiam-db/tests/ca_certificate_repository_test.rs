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
        id: Uuid::new_v4(),
        organization_id,
        tenant_id: None,
        parent_ca_id: None,
        subject: "CN=ACME Root CA".into(),
        public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".into(),
        chain_pem: None,
        fingerprint: "sha256:deadbeef".into(),
        key_algorithm: KeyAlgorithm::Rsa4096,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(3650),
        encrypted_private_key: Some(vec![1, 2, 3, 4, 5]),
        key_custody: axiam_core::ca_keys::CaKeyCustody::Database,
        key_locator: None,
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
                search: None,
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
                search: None,
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

// ---------------------------------------------------------------------------
// mTLS trust anchors (schema v49)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_new_ca_is_not_an_mtls_trust_anchor() {
    // The compatibility property the whole feature rests on: flagging is opt-in,
    // so every CA a deployment already has leaves its TLS posture unchanged.
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let created = repo.create(sample_ca(org_id)).await.unwrap();
    assert!(!created.mtls_trust_anchor);
    assert!(repo.list_mtls_trust_anchors().await.unwrap().is_empty());
}

#[tokio::test]
async fn flagging_a_ca_makes_it_an_anchor_and_unflagging_removes_it() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let ca = repo.create(sample_ca(org_id)).await.unwrap();

    let on = repo
        .set_mtls_trust_anchor(org_id, ca.id, true)
        .await
        .unwrap();
    assert!(on.mtls_trust_anchor);
    let anchors = repo.list_mtls_trust_anchors().await.unwrap();
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].id, ca.id);
    // The certificate travels with it — it is what gets written to the bundle.
    assert!(anchors[0].public_cert_pem.contains("BEGIN CERTIFICATE"));

    let off = repo
        .set_mtls_trust_anchor(org_id, ca.id, false)
        .await
        .unwrap();
    assert!(!off.mtls_trust_anchor);
    assert!(repo.list_mtls_trust_anchors().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_revoked_ca_is_dropped_from_the_trust_store() {
    // Security-relevant: a revoked CA left in the client trust store would let a
    // certificate the operator has already disowned authenticate a client —
    // the one outcome revocation exists to prevent.
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let ca = repo.create(sample_ca(org_id)).await.unwrap();
    repo.set_mtls_trust_anchor(org_id, ca.id, true)
        .await
        .unwrap();
    assert_eq!(repo.list_mtls_trust_anchors().await.unwrap().len(), 1);

    repo.revoke(org_id, ca.id).await.unwrap();
    assert!(
        repo.list_mtls_trust_anchors().await.unwrap().is_empty(),
        "a revoked CA must not remain in the client trust store"
    );
}

#[tokio::test]
async fn an_expired_ca_is_dropped_from_the_trust_store() {
    // An expired root's own chain no longer validates, so trusting it buys
    // nothing and hides the fact that it needs replacing.
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    let mut expired = sample_ca(org_id);
    expired.not_before = Utc::now() - Duration::days(400);
    expired.not_after = Utc::now() - Duration::days(1);
    let ca = repo.create(expired).await.unwrap();
    repo.set_mtls_trust_anchor(org_id, ca.id, true)
        .await
        .unwrap();

    assert!(repo.list_mtls_trust_anchors().await.unwrap().is_empty());
}

#[tokio::test]
async fn anchors_span_every_organization() {
    // There is one TLS listener per process presenting one trust store, so the
    // question this answers is "what does this server trust", not "what does
    // this organization trust". Scoping it per organization would silently drop
    // every anchor but one deployment's.
    let (db, org_a) = setup().await;
    let org_b = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Other".into(),
            slug: "other".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let repo = SurrealCaCertificateRepository::new(db);
    let a = repo.create(sample_ca(org_a)).await.unwrap();
    let b = repo.create(sample_ca(org_b)).await.unwrap();
    repo.set_mtls_trust_anchor(org_a, a.id, true).await.unwrap();
    repo.set_mtls_trust_anchor(org_b, b.id, true).await.unwrap();

    let anchors = repo.list_mtls_trust_anchors().await.unwrap();
    assert_eq!(anchors.len(), 2);
}

#[tokio::test]
async fn flagging_a_foreign_organizations_ca_is_not_found() {
    // The guard is on the UPDATE, not a read-then-write: a caller naming
    // another organization's CA must match zero rows rather than flip a flag on
    // a CA they cannot see.
    let (db, org_a) = setup().await;
    let org_b = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Other".into(),
            slug: "other".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let repo = SurrealCaCertificateRepository::new(db);
    let ca = repo.create(sample_ca(org_a)).await.unwrap();

    assert!(
        repo.set_mtls_trust_anchor(org_b, ca.id, true)
            .await
            .is_err(),
        "another organization must not be able to flag this CA"
    );
    assert!(repo.list_mtls_trust_anchors().await.unwrap().is_empty());
}

#[tokio::test]
async fn flagging_a_missing_ca_is_not_found() {
    let (db, org_id) = setup().await;
    let repo = SurrealCaCertificateRepository::new(db);
    assert!(
        repo.set_mtls_trust_anchor(org_id, Uuid::new_v4(), true)
            .await
            .is_err()
    );
}
