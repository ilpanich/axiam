//! CRUD + edge-case coverage for `SurrealPgpKeyRepository` — this
//! repository carried NO tests at all (0% coverage) before this file.
//! Uses the in-memory SurrealDB engine — no external services required.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::pgp_key::{PgpKeyAlgorithm, PgpKeyPurpose, PgpKeyStatus, StorePgpKey};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    OrganizationRepository, Pagination, PgpKeyRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPgpKeyRepository, SurrealTenantRepository,
};
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
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

fn sample_key(tenant_id: Uuid, purpose: PgpKeyPurpose) -> StorePgpKey {
    StorePgpKey {
        tenant_id,
        name: "audit-signing-key".into(),
        purpose,
        public_key_armored:
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----".into(),
        fingerprint: "ABCD1234EF567890".into(),
        algorithm: PgpKeyAlgorithm::Ed25519,
        encrypted_private_key: Some(vec![9, 8, 7, 6]),
    }
}

#[tokio::test]
async fn create_and_get_by_id() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let key = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();
    assert_eq!(key.tenant_id, tenant_id);
    assert_eq!(key.purpose, PgpKeyPurpose::AuditSigning);
    assert_eq!(key.algorithm, PgpKeyAlgorithm::Ed25519);
    assert_eq!(key.status, PgpKeyStatus::Active);
    assert_eq!(key.encrypted_private_key, Some(vec![9, 8, 7, 6]));

    let fetched = repo.get_by_id(tenant_id, key.id).await.unwrap();
    assert_eq!(fetched.id, key.id);
    assert_eq!(fetched.fingerprint, "ABCD1234EF567890");
}

#[tokio::test]
async fn create_export_key_rsa4096_no_private_key() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let mut input = sample_key(tenant_id, PgpKeyPurpose::Export);
    input.algorithm = PgpKeyAlgorithm::Rsa4096;
    input.encrypted_private_key = None;

    let key = repo.create(input).await.unwrap();
    assert_eq!(key.purpose, PgpKeyPurpose::Export);
    assert_eq!(key.algorithm, PgpKeyAlgorithm::Rsa4096);
    assert!(key.encrypted_private_key.is_none());
}

#[tokio::test]
async fn get_by_id_wrong_tenant_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let key = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();
    let other_tenant = Uuid::new_v4();

    assert!(repo.get_by_id(other_tenant, key.id).await.is_err());
}

#[tokio::test]
async fn get_by_id_missing_returns_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_id(tenant_id, missing).await.is_err());
}

#[tokio::test]
async fn get_signing_key_returns_most_recent_active_audit_signing_key() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    // An Export-purpose key must never be returned as the signing key.
    let mut export_input = sample_key(tenant_id, PgpKeyPurpose::Export);
    export_input.fingerprint = "EXPORT-FP".into();
    repo.create(export_input).await.unwrap();

    let signing = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();

    let found = repo.get_signing_key(tenant_id).await.unwrap();
    assert_eq!(found.id, signing.id);
    assert_eq!(found.purpose, PgpKeyPurpose::AuditSigning);
}

#[tokio::test]
async fn get_signing_key_ignores_revoked_keys() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let key = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();
    repo.revoke(tenant_id, key.id).await.unwrap();

    let result = repo.get_signing_key(tenant_id).await;
    assert!(
        result.is_err(),
        "a revoked signing key must not be returned"
    );
}

#[tokio::test]
async fn get_signing_key_not_found_when_none_exists() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    assert!(repo.get_signing_key(tenant_id).await.is_err());
}

#[tokio::test]
async fn revoke_transitions_status() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let key = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();
    repo.revoke(tenant_id, key.id).await.unwrap();

    let fetched = repo.get_by_id(tenant_id, key.id).await.unwrap();
    assert_eq!(fetched.status, PgpKeyStatus::Revoked);
}

#[tokio::test]
async fn revoke_missing_returns_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.revoke(tenant_id, missing).await.is_err());
}

#[tokio::test]
async fn revoke_wrong_tenant_returns_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db);

    let key = repo
        .create(sample_key(tenant_id, PgpKeyPurpose::AuditSigning))
        .await
        .unwrap();
    let other_tenant = Uuid::new_v4();

    assert!(repo.revoke(other_tenant, key.id).await.is_err());
    let fetched = repo.get_by_id(tenant_id, key.id).await.unwrap();
    assert_eq!(fetched.status, PgpKeyStatus::Active);
}

#[tokio::test]
async fn list_paginates_and_isolates_by_tenant() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealPgpKeyRepository::new(db.clone());
    let (_db2, other_tenant) = {
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Other Org".into(),
                slug: "other-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                name: "Other Tenant".into(),
                slug: "other-tenant".into(),
                metadata: None,
            })
            .await
            .unwrap();
        (db.clone(), tenant.id)
    };

    for i in 0..5 {
        let mut input = sample_key(tenant_id, PgpKeyPurpose::Export);
        input.fingerprint = format!("FP-{i}");
        repo.create(input).await.unwrap();
    }
    let mut foreign = sample_key(other_tenant, PgpKeyPurpose::Export);
    foreign.fingerprint = "FOREIGN".into();
    repo.create(foreign).await.unwrap();

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

    let other_list = repo
        .list(other_tenant, Pagination::default())
        .await
        .unwrap();
    assert_eq!(other_list.total, 1);
}
