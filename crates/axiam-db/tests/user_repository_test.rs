//! Integration tests for User repository using in-memory SurrealDB.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::verify_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB, run migrations, create org + tenant.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

#[tokio::test]
async fn create_and_get_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "SuperSecret123!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(user.tenant_id, tenant_id);
    assert_eq!(user.username, "alice");
    assert_eq!(user.email, "alice@example.com");
    assert_eq!(user.status, UserStatus::PendingVerification);
    assert!(!user.mfa_enabled);

    // Password should be hashed, not stored in plaintext.
    assert_ne!(user.password_hash, "SuperSecret123!");
    assert!(user.password_hash.starts_with("$argon2id$"));

    // Get by ID should return the same user.
    let fetched = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(fetched.id, user.id);
    assert_eq!(fetched.username, "alice");
}

#[tokio::test]
async fn password_verification() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: "MyPassword42!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Correct password should verify.
    assert!(verify_password("MyPassword42!", &user.password_hash, None).unwrap());

    // Wrong password should not verify.
    assert!(!verify_password("WrongPassword", &user.password_hash, None).unwrap());
}

#[tokio::test]
async fn password_with_pepper() {
    let (db, tenant_id) = setup().await;
    let pepper = "server-secret-pepper".to_string();
    let repo = SurrealUserRepository::with_pepper(db, pepper.clone());

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "carol".into(),
            email: "carol@example.com".into(),
            password: "PepperedPass!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Verify with pepper should succeed.
    assert!(verify_password("PepperedPass!", &user.password_hash, Some(&pepper)).unwrap());

    // Verify without pepper should fail.
    assert!(!verify_password("PepperedPass!", &user.password_hash, None).unwrap());
}

#[tokio::test]
async fn get_user_by_username() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "dave".into(),
            email: "dave@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = repo.get_by_username(tenant_id, "dave").await.unwrap();
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn get_user_by_email() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "eve".into(),
            email: "eve@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = repo
        .get_by_email(tenant_id, "eve@example.com")
        .await
        .unwrap();
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn update_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "frank".into(),
            email: "frank@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            user.id,
            axiam_core::models::user::UpdateUser {
                username: Some("franklin".into()),
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.username, "franklin");
    assert_eq!(updated.status, UserStatus::Active);
    assert_eq!(updated.email, "frank@example.com"); // unchanged
}

#[tokio::test]
async fn soft_delete_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "grace".into(),
            email: "grace@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, user.id).await.unwrap();

    // User should still exist but with Inactive status.
    let fetched = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(fetched.status, UserStatus::Inactive);
}

#[tokio::test]
async fn list_users_with_pagination() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    for i in 0..5 {
        repo.create(CreateUser {
            tenant_id,
            username: format!("user-{i}"),
            email: format!("user-{i}@example.com"),
            password: "pass123".into(),
            metadata: None,
        })
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
async fn duplicate_username_rejected() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    repo.create(CreateUser {
        tenant_id,
        username: "unique-user".into(),
        email: "first@example.com".into(),
        password: "pass123".into(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateUser {
            tenant_id,
            username: "unique-user".into(),
            email: "second@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate username should be rejected");
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    repo.create(CreateUser {
        tenant_id,
        username: "user-a".into(),
        email: "same@example.com".into(),
        password: "pass123".into(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateUser {
            tenant_id,
            username: "user-b".into(),
            email: "same@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate email should be rejected");
}

#[tokio::test]
async fn tenant_isolation() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Iso Org".into(),
            slug: "iso-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant_a = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant A".into(),
            slug: "tenant-a".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db);

    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant_a.id,
            username: "isolated".into(),
            email: "isolated@example.com".into(),
            password: "pass".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // User should be findable under tenant_a.
    let found = user_repo.get_by_id(tenant_a.id, user.id).await;
    assert!(found.is_ok());

    // User should NOT be findable under tenant_b.
    let not_found = user_repo.get_by_id(tenant_b.id, user.id).await;
    assert!(
        not_found.is_err(),
        "user should not be visible in other tenant"
    );
}
