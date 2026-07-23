//! Integration tests for `SurrealPasswordHistoryRepository`: create/list
//! ordering, tenant/user scoping, and the `prune` keep-N and keep-0
//! branches, using in-memory SurrealDB.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_history::CreatePasswordHistoryEntry;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PasswordHistoryRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
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
            slug: "org-ph".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant-ph".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "ph-user".into(),
            email: "ph-user@example.com".into(),
            password: "pass123!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

async fn add_entry(
    repo: &SurrealPasswordHistoryRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
    hash: &str,
) {
    repo.create(CreatePasswordHistoryEntry {
        tenant_id,
        user_id,
        password_hash: hash.into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn create_then_get_recent_returns_it() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    add_entry(&repo, tenant_id, user_id, "hash-1").await;

    let recent = repo.get_recent(tenant_id, user_id, 10).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].password_hash, "hash-1");
}

#[tokio::test]
async fn get_recent_respects_limit_and_newest_first() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    for i in 0..5 {
        add_entry(&repo, tenant_id, user_id, &format!("hash-{i}")).await;
    }

    let recent = repo.get_recent(tenant_id, user_id, 3).await.unwrap();
    assert_eq!(recent.len(), 3);
    // Most recently created entries should come back first.
    assert_eq!(recent[0].password_hash, "hash-4");
}

#[tokio::test]
async fn get_recent_scoped_to_user_and_tenant() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    let other_user = Uuid::new_v4();
    add_entry(&repo, tenant_id, user_id, "mine").await;
    add_entry(&repo, tenant_id, other_user, "not-mine").await;

    let recent = repo.get_recent(tenant_id, user_id, 10).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].password_hash, "mine");
}

#[tokio::test]
async fn prune_keep_count_zero_deletes_all() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    for i in 0..3 {
        add_entry(&repo, tenant_id, user_id, &format!("hash-{i}")).await;
    }

    let deleted = repo.prune(tenant_id, user_id, 0).await.unwrap();
    assert_eq!(deleted, 3);

    let remaining = repo.get_recent(tenant_id, user_id, 10).await.unwrap();
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn prune_keeps_n_most_recent_and_deletes_the_rest() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    for i in 0..5 {
        add_entry(&repo, tenant_id, user_id, &format!("hash-{i}")).await;
    }

    let deleted = repo.prune(tenant_id, user_id, 2).await.unwrap();
    assert_eq!(deleted, 3, "should delete all but the 2 newest");

    let remaining = repo.get_recent(tenant_id, user_id, 10).await.unwrap();
    assert_eq!(remaining.len(), 2);
    let hashes: Vec<&str> = remaining.iter().map(|e| e.password_hash.as_str()).collect();
    assert!(hashes.contains(&"hash-4"));
    assert!(hashes.contains(&"hash-3"));
}

#[tokio::test]
async fn prune_with_no_entries_returns_zero() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    let deleted = repo.prune(tenant_id, user_id, 5).await.unwrap();
    assert_eq!(deleted, 0);
}

#[tokio::test]
async fn prune_keep_count_greater_than_entries_deletes_nothing() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealPasswordHistoryRepository::new(db);

    add_entry(&repo, tenant_id, user_id, "only-one").await;

    let deleted = repo.prune(tenant_id, user_id, 10).await.unwrap();
    assert_eq!(deleted, 0);

    let remaining = repo.get_recent(tenant_id, user_id, 10).await.unwrap();
    assert_eq!(remaining.len(), 1);
}
