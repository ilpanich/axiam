//! Integration tests for the authentication service.

use axiam_auth::config::AuthConfig;
use axiam_auth::service::{AuthService, LoginInput, LoginResult, RefreshInput, VerifyMfaInput};
use axiam_auth::token;
use axiam_core::error::AxiamError;
use axiam_core::models::federation::{
    CreateFederationConfig, CreateFederationLink, FederationProtocol,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::MfaPolicy;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, OrganizationRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
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

/// Test AES-256-GCM key for MFA secret encryption.
const TEST_MFA_KEY: [u8; 32] = [42u8; 32];

fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        pepper: None,
        min_password_length: 12,
        mfa_encryption_key: Some(TEST_MFA_KEY),
        mfa_challenge_lifetime_secs: 300,
        totp_issuer: "AXIAM-Test".into(),
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        auth_code_lifetime_secs: 600,
        oauth2_issuer_url: String::new(),
        email_verification_grace_period_hours: 24,
        password_reset_token_expiry_hours: 1,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8080".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
    }
}

/// Spin up in-memory DB, run migrations, create org + tenant + user.
async fn setup() -> (
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
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
    let federation_repo = SurrealFederationLinkRepository::new(db.clone());

    (
        user_repo,
        session_repo,
        federation_repo,
        org.id,
        tenant.id,
        user.id,
        db,
    )
}

/// Helper: login alice (expects Success variant).
async fn login_alice(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
) -> axiam_auth::LoginOutput {
    match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::Success(out) => out,
        other => panic!("expected Success, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// T2.1 — Login / logout tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn login_happy_path() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config.clone());

    let result = login_alice(&svc, tenant_id, org_id).await;

    assert!(!result.access_token.is_empty());
    assert!(!result.refresh_token.is_empty());
    assert_eq!(result.expires_in, 900);

    let claims = token::decode_access_token(&result.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
    assert_eq!(claims.org_id, org_id.to_string());
    assert_eq!(claims.iss, "axiam-test");
}

#[tokio::test]
async fn login_by_email() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice@example.com".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn login_wrong_password() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "wrong-password".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
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
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "nobody".into(),
            password: "irrelevant".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn login_locked_user() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;

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

    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
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
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;

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

    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
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
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let login_out = login_alice(&svc, tenant_id, org_id).await;
    svc.logout(tenant_id, login_out.session_id).await.unwrap();
}

// -----------------------------------------------------------------------
// T2.2 — Token refresh, validation, and revocation tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn refresh_happy_path() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config.clone());

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

    assert!(!refresh_out.access_token.is_empty());
    assert_ne!(refresh_out.refresh_token, login_out.refresh_token);
    assert_ne!(refresh_out.session_id, login_out.session_id);

    let claims = token::decode_access_token(&refresh_out.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
}

#[tokio::test]
async fn refresh_replay_attack_fails() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let login_out = login_alice(&svc, tenant_id, org_id).await;
    let old_token = login_out.refresh_token.clone();

    svc.refresh(RefreshInput {
        tenant_id,
        org_id,
        raw_refresh_token: old_token.clone(),
        ip_address: None,
        user_agent: None,
    })
    .await
    .unwrap();

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
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

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
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;

    let lock_repo = SurrealUserRepository::new(db);
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let login_out = login_alice(&svc, tenant_id, org_id).await;

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

    let jwt = token::issue_access_token(uid, tid, oid, &[], &config).unwrap();
    let validated = token::validate_access_token(&jwt, &config).unwrap();
    assert_eq!(validated.0.sub, uid.to_string());

    let tampered = format!("{jwt}x");
    assert!(token::validate_access_token(&tampered, &config).is_err());
}

#[tokio::test]
async fn revoke_all_sessions() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let login1 = login_alice(&svc, tenant_id, org_id).await;
    let login2 = login_alice(&svc, tenant_id, org_id).await;

    svc.revoke_all_sessions(tenant_id, user_id).await.unwrap();

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

// -----------------------------------------------------------------------
// T2.3 — MFA (TOTP) tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn mfa_enroll_and_confirm() {
    let (user_repo, session_repo, fed_repo, _org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Step 1: enroll — get secret + URI.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    assert!(!enrollment.secret_base32.is_empty());
    assert!(enrollment.totp_uri.starts_with("otpauth://totp/"));

    // Step 2: generate a valid TOTP code from the secret.
    let secret = totp_rs::Secret::Encoded(enrollment.secret_base32.clone());
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        "alice@example.com".into(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();

    // Step 3: confirm with valid code.
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();
}

#[tokio::test]
async fn mfa_login_challenge_flow() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config.clone());

    // Enroll and confirm MFA.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let secret = totp_rs::Secret::Encoded(enrollment.secret_base32.clone());
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        "alice@example.com".into(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();

    // Login should now return MfaRequired.
    let login_result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap();

    let challenge_token = match login_result {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        other => panic!("expected MfaRequired, got {other:?}"),
    };

    // Verify MFA with a valid code.
    let new_code = totp.generate_current().unwrap();
    let output = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: new_code,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    assert!(!output.access_token.is_empty());
    assert!(!output.refresh_token.is_empty());

    let claims = token::decode_access_token(&output.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
    assert_eq!(claims.org_id, org_id.to_string());
}

#[tokio::test]
async fn mfa_wrong_code_rejected() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Enroll + confirm.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let secret = totp_rs::Secret::Encoded(enrollment.secret_base32);
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        "alice@example.com".into(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();

    // Login → get challenge.
    let login_result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap();

    let challenge_token = match login_result {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        _ => panic!("expected MfaRequired"),
    };

    // Verify with wrong code.
    let err = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: "000000".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn mfa_confirm_wrong_code_rejected() {
    let (user_repo, session_repo, fed_repo, _org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    svc.enroll_mfa(tenant_id, user_id).await.unwrap();

    let err = svc
        .confirm_mfa(tenant_id, user_id, "000000")
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn login_without_mfa_still_returns_success() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap();

    assert!(matches!(result, LoginResult::Success(_)));
}

// -----------------------------------------------------------------------
// T2.4 — Brute force protection tests
// -----------------------------------------------------------------------

/// Helper: attempt a bad login.
async fn bad_login(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
) {
    let _ = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "wrong-password".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await;
}

#[tokio::test]
async fn failed_login_increments_counter() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    bad_login(&svc, tenant_id, org_id).await;
    bad_login(&svc, tenant_id, org_id).await;

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.failed_login_attempts, 2);
    assert!(user.last_failed_login_at.is_some());
    assert!(user.locked_until.is_none()); // below threshold
}

#[tokio::test]
async fn account_locks_after_max_attempts() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3; // lower threshold for test
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config);

    for _ in 0..3 {
        bad_login(&svc, tenant_id, org_id).await;
    }

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.failed_login_attempts, 3);
    assert!(user.locked_until.is_some());
    assert!(user.locked_until.unwrap() > Utc::now());

    // Even correct password should fail while locked.
    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn lockout_expires_allows_login() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Manually set locked_until in the past.
    let lock_repo = SurrealUserRepository::new(db);
    lock_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                failed_login_attempts: Some(5),
                locked_until: Some(Some(Utc::now() - Duration::seconds(10))),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Login should succeed (lockout expired).
    let result = login_alice(&svc, tenant_id, org_id).await;
    assert!(!result.access_token.is_empty());
}

#[tokio::test]
async fn successful_login_resets_counter() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Fail twice.
    bad_login(&svc, tenant_id, org_id).await;
    bad_login(&svc, tenant_id, org_id).await;

    // Succeed.
    login_alice(&svc, tenant_id, org_id).await;

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.failed_login_attempts, 0);
    assert!(user.last_failed_login_at.is_none());
    assert!(user.locked_until.is_none());
}

#[tokio::test]
async fn exponential_backoff_increases_lockout() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3;
    config.lockout_duration_secs = 60;
    config.lockout_backoff_multiplier = 2.0;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config);

    // 3 failures → first lockout (60s * 2^0 = 60s).
    for _ in 0..3 {
        bad_login(&svc, tenant_id, org_id).await;
    }

    let check_repo = SurrealUserRepository::new(db.clone());
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    let first_lockout = user.locked_until.unwrap();
    let expected_min = Utc::now() + Duration::seconds(55); // allow some slack
    assert!(first_lockout > expected_min);

    // Clear lockout to simulate expiry, keep the counter at 3.
    let reset_repo = SurrealUserRepository::new(db.clone());
    reset_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                locked_until: Some(Some(Utc::now() - Duration::seconds(1))),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // 4th failure → lockout with backoff (60s * 2^1 = 120s).
    bad_login(&svc, tenant_id, org_id).await;

    let check_repo2 = SurrealUserRepository::new(db);
    let user2 = check_repo2.get_by_id(tenant_id, user_id).await.unwrap();
    let second_lockout = user2.locked_until.unwrap();
    assert!(second_lockout > first_lockout);
    let expected_min2 = Utc::now() + Duration::seconds(115);
    assert!(second_lockout > expected_min2);
}

// -----------------------------------------------------------------------
// T14.1 — MFA Enforcement
// -----------------------------------------------------------------------

/// Helper: build a TOTP verifier from a base32 secret returned by enrollment.
fn totp_from_secret(secret_base32: &str, email: &str) -> totp_rs::TOTP {
    let secret = totp_rs::Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret.to_bytes().unwrap();
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        email.into(),
    )
    .unwrap()
}

/// Helper: enroll + confirm MFA for user alice, returning the TOTP verifier.
async fn enable_mfa_for_alice(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    user_id: Uuid,
) -> totp_rs::TOTP {
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let totp = totp_from_secret(&enrollment.secret_base32, "alice@example.com");
    let code = totp.generate_current().unwrap();
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();
    totp
}

fn mfa_enforced_policy() -> Option<MfaPolicy> {
    Some(MfaPolicy {
        mfa_enforced: true,
        mfa_challenge_lifetime_secs: 300,
    })
}

fn mfa_not_enforced_policy() -> Option<MfaPolicy> {
    Some(MfaPolicy {
        mfa_enforced: false,
        mfa_challenge_lifetime_secs: 300,
    })
}

#[tokio::test]
async fn login_mfa_enforced_no_mfa_configured_returns_setup_required() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap();

    match result {
        LoginResult::MfaSetupRequired(setup) => {
            assert!(
                !setup.setup_token.is_empty(),
                "setup_token should be non-empty"
            );
        }
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn login_mfa_enforced_mfa_already_configured_returns_mfa_challenge() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Enable MFA first.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap();

    match result {
        LoginResult::MfaRequired(challenge) => {
            assert!(
                !challenge.challenge_token.is_empty(),
                "challenge_token should be non-empty"
            );
        }
        other => panic!("expected MfaRequired, got {other:?}"),
    }
}

#[tokio::test]
async fn login_mfa_not_enforced_no_mfa_returns_success() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_not_enforced_policy(),
        })
        .await
        .unwrap();

    assert!(
        matches!(result, LoginResult::Success(_)),
        "expected Success, got {result:?}"
    );
}

#[tokio::test]
async fn login_mfa_enforced_federated_user_skips_enforcement() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Create a federation config + link so the user is "federated".
    let fed_config_repo = SurrealFederationConfigRepository::new(db.clone());
    let fed_config = fed_config_repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "Google".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: None,
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            attribute_map: None,
        })
        .await
        .unwrap();

    let fed_link_repo = SurrealFederationLinkRepository::new(db);
    fed_link_repo
        .create(CreateFederationLink {
            tenant_id,
            user_id,
            federation_config_id: fed_config.id,
            external_subject: "google-subject-123".into(),
            external_email: Some("alice@gmail.com".into()),
        })
        .await
        .unwrap();

    // Login with MFA enforced — federated user should skip enforcement.
    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap();

    assert!(
        matches!(result, LoginResult::Success(_)),
        "expected Success for federated user, got {result:?}"
    );
}

#[tokio::test]
async fn enroll_mfa_with_setup_token_succeeds() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Login with MFA enforced to get a setup_token.
    let setup_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap()
    {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };

    let enrollment = svc.enroll_mfa_with_setup_token(&setup_token).await.unwrap();

    assert!(!enrollment.secret_base32.is_empty());
    assert!(enrollment.totp_uri.starts_with("otpauth://totp/"));
}

#[tokio::test]
async fn confirm_mfa_with_setup_token_returns_login_tokens() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, _user_id, _db) = setup().await;
    let config = test_config();
    let svc = AuthService::new(user_repo, session_repo, fed_repo, config.clone());

    // Step 1: Login with enforcement → get setup_token.
    let setup_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap()
    {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };

    // Step 2: Enroll with setup_token → get secret.
    let enrollment = svc.enroll_mfa_with_setup_token(&setup_token).await.unwrap();

    // Step 3: Generate TOTP code and confirm.
    let totp = totp_from_secret(&enrollment.secret_base32, "alice@example.com");
    let code = totp.generate_current().unwrap();

    let output = svc
        .confirm_mfa_with_setup_token(&setup_token, &code, None, None)
        .await
        .unwrap();

    assert!(!output.access_token.is_empty());
    assert!(!output.refresh_token.is_empty());

    // Verify the access token is valid.
    let claims = token::decode_access_token(&output.access_token, &config).unwrap();
    assert_eq!(claims.tenant_id, tenant_id.to_string());
    assert_eq!(claims.org_id, org_id.to_string());
}

#[tokio::test]
async fn reset_mfa_clears_state_and_revokes_sessions() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Enable MFA and create a session.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;

    // Login (will require MFA challenge). Complete it to get a session.
    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
        })
        .await
        .unwrap();

    let challenge_token = match result {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        other => panic!("expected MfaRequired, got {other:?}"),
    };

    // Re-fetch user to get the encrypted secret for TOTP generation.
    let check_repo = SurrealUserRepository::new(db.clone());
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(user.mfa_enabled);

    // Generate code from the stored secret (use the enrollment approach).
    // We need the raw secret — re-enroll is not possible since MFA is
    // already enabled, so we use the service's MFA infrastructure:
    // decode the encryption key, decrypt the stored secret.
    let encryption_key = test_config().mfa_encryption_key.unwrap();
    let encrypted = user.mfa_secret.as_ref().unwrap();
    let secret_bytes = axiam_auth::totp::decrypt_secret(&encryption_key, encrypted).unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        "alice@example.com".into(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();

    let login_out = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: code,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    // Now reset MFA.
    svc.reset_mfa(tenant_id, user_id).await.unwrap();

    // Verify: user no longer has MFA enabled.
    let user_after = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(
        !user_after.mfa_enabled,
        "MFA should be disabled after reset"
    );
    assert!(
        user_after.mfa_secret.is_none(),
        "MFA secret should be cleared after reset"
    );

    // Verify: sessions are invalidated (refresh should fail).
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
    assert!(
        matches!(err, AxiamError::AuthenticationFailed { .. }),
        "expected AuthenticationFailed after session revocation, got {err:?}"
    );
}

#[tokio::test]
async fn login_after_reset_requires_setup_again() {
    let (user_repo, session_repo, fed_repo, org_id, tenant_id, user_id, _db) = setup().await;
    let svc = AuthService::new(user_repo, session_repo, fed_repo, test_config());

    // Enable MFA, then reset it.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    svc.reset_mfa(tenant_id, user_id).await.unwrap();

    // Login with MFA enforced — should require setup again.
    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "correct-horse-battery".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
        })
        .await
        .unwrap();

    assert!(
        matches!(result, LoginResult::MfaSetupRequired(_)),
        "expected MfaSetupRequired after reset, got {result:?}"
    );
}
