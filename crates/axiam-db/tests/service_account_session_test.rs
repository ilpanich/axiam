//! Integration tests for ServiceAccount and Session repositories.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::service_account::{CreateServiceAccount, UpdateServiceAccount};
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, ServiceAccountRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::hash_client_secret;
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealServiceAccountRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB, run migrations, create org + tenant + 1 user.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
    uuid::Uuid, // user_id
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

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

// ---------------------------------------------------------------------------
// ServiceAccount tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_service_account() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, raw_secret) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "my-service".into(),
        })
        .await
        .unwrap();

    assert_eq!(sa.tenant_id, tenant_id);
    assert_eq!(sa.name, "my-service");
    assert!(sa.client_id.starts_with("sa_"));
    assert!(!raw_secret.is_empty());
    assert_eq!(sa.status, UserStatus::Active);

    let fetched = repo.get_by_id(tenant_id, sa.id).await.unwrap();
    assert_eq!(fetched.id, sa.id);
    assert_eq!(fetched.client_id, sa.client_id);
}

#[tokio::test]
async fn get_by_client_id() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, _) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "lookup-test".into(),
        })
        .await
        .unwrap();

    let fetched = repo
        .get_by_client_id(tenant_id, &sa.client_id)
        .await
        .unwrap();
    assert_eq!(fetched.id, sa.id);
}

#[tokio::test]
async fn update_service_account() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, _) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "original".into(),
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            sa.id,
            UpdateServiceAccount {
                name: Some("renamed".into()),
                status: Some(UserStatus::Inactive),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "renamed");
    assert_eq!(updated.status, UserStatus::Inactive);
}

#[tokio::test]
async fn delete_service_account() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, _) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "to-delete".into(),
        })
        .await
        .unwrap();

    repo.delete(tenant_id, sa.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, sa.id).await;
    assert!(result.is_err(), "deleted SA should not be found");
}

#[tokio::test]
async fn list_service_accounts_with_pagination() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    for i in 0..5 {
        repo.create(CreateServiceAccount {
            tenant_id,
            name: format!("sa-{i}"),
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
}

#[tokio::test]
async fn rotate_secret() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, original_secret) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "rotate-test".into(),
        })
        .await
        .unwrap();

    let new_secret = repo.rotate_secret(tenant_id, sa.id).await.unwrap();
    assert_ne!(new_secret, original_secret);

    // Verify the new hash matches the new secret.
    let fetched = repo.get_by_id(tenant_id, sa.id).await.unwrap();
    assert_eq!(fetched.client_secret_hash, hash_client_secret(&new_secret));

    // Old secret should no longer match.
    assert_ne!(
        fetched.client_secret_hash,
        hash_client_secret(&original_secret)
    );
}

#[tokio::test]
async fn verify_client_secret_hash() {
    let (db, tenant_id, _) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, raw_secret) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "hash-test".into(),
        })
        .await
        .unwrap();

    // The stored hash should match hashing the raw secret.
    assert_eq!(sa.client_secret_hash, hash_client_secret(&raw_secret));
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_session() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let expires = Utc::now() + Duration::hours(1);
    let session = repo
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "abc123hash".into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("TestAgent/1.0".into()),
            expires_at: expires,
        })
        .await
        .unwrap();

    assert_eq!(session.tenant_id, tenant_id);
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.token_hash, "abc123hash");
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));

    let fetched = repo.get_by_id(tenant_id, session.id).await.unwrap();
    assert_eq!(fetched.id, session.id);
}

#[tokio::test]
async fn get_by_token_hash() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let expires = Utc::now() + Duration::hours(1);
    let session = repo
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "unique_token_hash".into(),
            ip_address: None,
            user_agent: None,
            expires_at: expires,
        })
        .await
        .unwrap();

    let fetched = repo
        .get_by_token_hash(tenant_id, "unique_token_hash")
        .await
        .unwrap();
    assert_eq!(fetched.id, session.id);
}

#[tokio::test]
async fn invalidate_session() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let expires = Utc::now() + Duration::hours(1);
    let session = repo
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "to_invalidate".into(),
            ip_address: None,
            user_agent: None,
            expires_at: expires,
        })
        .await
        .unwrap();

    repo.invalidate(tenant_id, session.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, session.id).await;
    assert!(result.is_err(), "invalidated session should not be found");
}

#[tokio::test]
async fn invalidate_user_sessions() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let expires = Utc::now() + Duration::hours(1);
    for i in 0..3 {
        repo.create(CreateSession {
            tenant_id,
            user_id,
            token_hash: format!("session_{i}"),
            ip_address: None,
            user_agent: None,
            expires_at: expires,
        })
        .await
        .unwrap();
    }

    repo.invalidate_user_sessions(tenant_id, user_id)
        .await
        .unwrap();

    // All sessions for this user should be gone.
    let result = repo.get_by_token_hash(tenant_id, "session_0").await;
    assert!(result.is_err());
    let result = repo.get_by_token_hash(tenant_id, "session_1").await;
    assert!(result.is_err());
    let result = repo.get_by_token_hash(tenant_id, "session_2").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn cleanup_expired() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    // Create 2 expired sessions and 1 valid session.
    let past = Utc::now() - Duration::hours(1);
    let future = Utc::now() + Duration::hours(1);

    for i in 0..2 {
        repo.create(CreateSession {
            tenant_id,
            user_id,
            token_hash: format!("expired_{i}"),
            ip_address: None,
            user_agent: None,
            expires_at: past,
        })
        .await
        .unwrap();
    }

    let valid = repo
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "valid_session".into(),
            ip_address: None,
            user_agent: None,
            expires_at: future,
        })
        .await
        .unwrap();

    let deleted = repo.cleanup_expired(tenant_id).await.unwrap();
    assert_eq!(deleted, 2);

    // The valid session should still exist.
    let fetched = repo.get_by_id(tenant_id, valid.id).await.unwrap();
    assert_eq!(fetched.token_hash, "valid_session");
}
