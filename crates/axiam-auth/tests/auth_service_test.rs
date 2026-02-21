//! Integration tests for the authentication service.

use axiam_auth::config::AuthConfig;
use axiam_auth::service::{AuthService, LoginInput, RefreshInput};
use axiam_auth::token;
use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Pre-generated Ed25519 test key pair (PEM).
const TEST_PRIVATE_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";

const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        pepper: None,
        min_password_length: 12,
    }
}

/// Spin up in-memory DB, run migrations, create org + tenant + user.
async fn setup() -> (
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    Uuid,                                  // org_id
    Uuid,                                  // tenant_id
    Uuid,                                  // user_id
    Surreal<surrealdb::engine::local::Db>, // raw db handle
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
            password: "correct-horse-battery".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate user (new users default to PendingVerification).
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let session_repo = SurrealSessionRepository::new(db.clone());

    (user_repo, session_repo, org.id, tenant.id, user.id, db)
}

#[tokio::test]
async fn login_happy_path() {
    let (user_repo, session_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, config.clone());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("TestAgent".into()),
        })
        .await
        .unwrap();

    assert!(!result.access_token.is_empty());
    assert!(!result.refresh_token.is_empty());
    assert_eq!(result.expires_in, 900);

    // Verify JWT decodes correctly.
    let claims = token::decode_access_token(&result.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
    assert_eq!(claims.org_id, org_id.to_string());
    assert_eq!(claims.iss, "axiam-test");
}

#[tokio::test]
async fn login_by_email() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice@example.com".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn login_wrong_password() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "wrong-password".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, AxiamError::AuthenticationFailed { .. }),
        "expected AuthenticationFailed, got: {err:?}"
    );
}

#[tokio::test]
async fn login_user_not_found() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "nobody".into(),
            password: "irrelevant".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn login_locked_user() {
    let (user_repo, session_repo, org_id, tenant_id, user_id, _db) = setup().await;

    // Lock the user.
    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::Locked),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let svc = AuthService::new(user_repo, session_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    match &err {
        AxiamError::AuthenticationFailed { reason } => {
            assert!(
                reason.contains("locked"),
                "expected 'locked' in reason: {reason}"
            );
        }
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn login_inactive_user() {
    let (user_repo, session_repo, org_id, tenant_id, user_id, _db) = setup().await;

    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::Inactive),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let svc = AuthService::new(user_repo, session_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    match &err {
        AxiamError::AuthenticationFailed { reason } => {
            assert!(
                reason.contains("inactive"),
                "expected 'inactive' in reason: {reason}"
            );
        }
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn logout_invalidates_session() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let login_result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    // Logout should succeed.
    svc.logout(tenant_id, login_result.session_id)
        .await
        .unwrap();
}

// -----------------------------------------------------------------------
// T2.2 — Token refresh, validation, and revocation tests
// -----------------------------------------------------------------------

/// Helper: login alice and return the service + login output.
async fn login_alice(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
) -> axiam_auth::LoginOutput {
    svc.login(LoginInput {
        tenant_id,
        org_id,
        username_or_email: "alice".into(),
        password: "correct-horse-battery".into(),
        ip_address: None,
        user_agent: None,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn refresh_happy_path() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, config.clone());

    let login_out = login_alice(&svc, tenant_id, org_id).await;

    let refresh_out = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: login_out.refresh_token.clone(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    // New tokens issued.
    assert!(!refresh_out.access_token.is_empty());
    assert!(!refresh_out.refresh_token.is_empty());
    assert_ne!(refresh_out.refresh_token, login_out.refresh_token);
    assert_ne!(refresh_out.session_id, login_out.session_id);

    // New JWT is valid.
    let claims = token::decode_access_token(&refresh_out.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
    assert_eq!(claims.org_id, org_id.to_string());
}

#[tokio::test]
async fn refresh_replay_attack_fails() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let login_out = login_alice(&svc, tenant_id, org_id).await;
    let old_token = login_out.refresh_token.clone();

    // First refresh succeeds.
    svc.refresh(RefreshInput {
        tenant_id,
        org_id,
        raw_refresh_token: old_token.clone(),
        ip_address: None,
        user_agent: None,
    })
    .await
    .unwrap();

    // Second use of same token fails (single-use).
    let err = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: old_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn refresh_invalid_token_fails() {
    let (user_repo, session_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let err = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: "totally-bogus-token".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn refresh_locked_user_fails() {
    let (user_repo, session_repo, org_id, tenant_id, user_id, db) = setup().await;

    // Create a second user_repo handle to lock the user after login.
    let lock_repo = SurrealUserRepository::new(db);
    let svc = AuthService::new(user_repo, session_repo, test_config());

    let login_out = login_alice(&svc, tenant_id, org_id).await;

    // Lock user after login.
    lock_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::Locked),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let err = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: login_out.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    match &err {
        AxiamError::AuthenticationFailed { reason } => {
            assert!(reason.contains("locked"), "expected 'locked': {reason}");
        }
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn validate_access_token_works() {
    let config = test_config();
    let uid = Uuid::new_v4();
    let tid = Uuid::new_v4();
    let oid = Uuid::new_v4();

    let jwt = token::issue_access_token(uid, tid, oid, &config).unwrap();
    let validated = token::validate_access_token(&jwt, &config).unwrap();
    assert_eq!(validated.0.sub, uid.to_string());

    // Tampered token fails.
    let tampered = format!("{jwt}x");
    assert!(token::validate_access_token(&tampered, &config).is_err());
}

#[tokio::test]
async fn revoke_all_sessions() {
    let (user_repo, session_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, test_config());

    // Login twice to create two sessions.
    let login1 = login_alice(&svc, tenant_id, org_id).await;
    let login2 = login_alice(&svc, tenant_id, org_id).await;

    // Revoke all.
    svc.revoke_all_sessions(tenant_id, user_id).await.unwrap();

    // Both refresh tokens should fail.
    let err1 = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: login1.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err1, AxiamError::AuthenticationFailed { .. }));

    let err2 = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: login2.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err2, AxiamError::AuthenticationFailed { .. }));
}
