//! Integration tests for the authentication service.

use axiam_auth::config::AuthConfig;
use axiam_auth::error::AuthError;
use axiam_auth::mfa_methods::MfaMethodService;
use axiam_auth::service::{AuthService, LoginInput, LoginResult, RefreshInput, VerifyMfaInput};
use axiam_auth::token;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::federation::{
    CreateFederationConfig, CreateFederationLink, FederationProtocol,
};
use axiam_core::models::oauth2_client::{CreateRefreshToken, RefreshToken};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{CreateSession, Session};
use axiam_core::models::settings::MfaPolicy;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, OrganizationRepository,
    RefreshTokenRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealRefreshTokenRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use axiam_test_support::{other_password, test_password};
use chrono::{Duration, Utc};
#[path = "read_then_bump_support/mod.rs"]
mod read_then_bump_support;
use read_then_bump_support::ReadThenBumpUserRepo;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Pre-generated Ed25519 test key pair (PEM).
const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key

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
        trust_forwarded_client_cert: false,
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        pepper: None,
        pepper_previous: None,
        min_password_length: 12,
        hibp_breaker_threshold: 5,
        hibp_breaker_cooldown_secs: 30,
        max_concurrent_hashes: 0,
        hash_acquire_timeout_secs: 5,
        session_validation_cache_ttl_secs: 0,
        mfa_encryption_key: Some(TEST_MFA_KEY),
        opaque_session_key: None,
        opaque_setup_key: None,
        federation_encryption_key: None,
        allow_missing_aud_as_user: true,
        cookie_secure: true,
        mfa_challenge_lifetime_secs: 300,
        totp_issuer: "AXIAM-Test".into(),
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        auth_code_lifetime_secs: 600,
        oauth2_issuer_url: String::new(),
        oauth2_mtls_base_url: String::new(),
        oauth2_default_tenant_id: String::new(),
        revocation_feed_enabled: false,
        sso_spa_origins: Vec::new(),
        email_verification_grace_period_hours: 24,
        password_reset_token_expiry_hours: 1,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        jwt_encoding_key: None,
        jwt_decoding_key: None,
        // T21.5: the spread. T21.6 added `tenant_issuer_paths` and
        // `request_issuer` to `AuthConfig` without updating this initializer,
        // so this test has not compiled since; both take their `Default`
        // value, which is the one that reproduces the behaviour this test was
        // written against.
        ..AuthConfig::default()
    }
}

/// Spin up in-memory DB, run migrations, create org + tenant + user.
async fn setup() -> (
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
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
            kind: TenantKind::Standard,
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
            password: test_password(),
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
    let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());

    (
        user_repo,
        session_repo,
        federation_repo,
        refresh_token_repo,
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
        SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
) -> axiam_auth::LoginOutput {
    match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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

/// The MFA reset moved off `AuthService` to
/// [`MfaMethodService`], which holds the WebAuthn credential repository the
/// reset must evict from (T-34). These tests still drive it through the same
/// database the service under test uses, so what they assert about the user
/// row and the sessions is unchanged.
fn mfa_methods(
    db: &Surreal<surrealdb::engine::local::Db>,
) -> MfaMethodService<
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealWebauthnCredentialRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
> {
    MfaMethodService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealWebauthnCredentialRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
    )
}

#[tokio::test]
async fn login_happy_path() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice@example.com".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn login_wrong_password() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: "wrong-password".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "nobody".into(),
            password: "irrelevant".into(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn login_locked_user() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;

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

    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;

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

    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let err = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let login_out = login_alice(&svc, tenant_id, org_id).await;
    svc.logout(tenant_id, login_out.session_id).await.unwrap();
}

// -----------------------------------------------------------------------
// F4-R12-07 (D-N43) — a half-failed logout is retryable with its credential
// -----------------------------------------------------------------------

type MemDb = surrealdb::engine::local::Db;

/// A real session repository whose `invalidate` fails while `fail` is set.
#[derive(Clone)]
struct FlakySessionRepo {
    inner: SurrealSessionRepository<MemDb>,
    fail: Arc<AtomicBool>,
}

impl SessionRepository for FlakySessionRepo {
    async fn create(&self, input: CreateSession) -> AxiamResult<Session> {
        self.inner.create(input).await
    }
    async fn create_if_credential_version(
        &self,
        input: CreateSession,
        expected_credential_version: i64,
    ) -> AxiamResult<Session> {
        self.inner
            .create_if_credential_version(input, expected_credential_version)
            .await
    }
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Session> {
        self.inner.get_by_id(tenant_id, id).await
    }
    async fn get_by_token_hash(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<Session> {
        self.inner.get_by_token_hash(tenant_id, token_hash).await
    }
    async fn get_by_browser_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<Session>> {
        self.inner
            .get_by_browser_token_hash(tenant_id, token_hash)
            .await
    }
    async fn invalidate(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AxiamError::Database("injected: session delete".into()));
        }
        self.inner.invalidate(tenant_id, id).await
    }
    async fn lineage_of(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> AxiamResult<Option<axiam_core::models::session::SessionLineage>> {
        self.inner.lineage_of(tenant_id, session_id).await
    }
    async fn invalidate_lineage(
        &self,
        tenant_id: Uuid,
        lineage_id: Uuid,
        user_id: Uuid,
        except: Option<Uuid>,
    ) -> AxiamResult<u64> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AxiamError::Database("injected: session delete".into()));
        }
        self.inner
            .invalidate_lineage(tenant_id, lineage_id, user_id, except)
            .await
    }
    async fn consume(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<bool> {
        self.inner.consume(tenant_id, id).await
    }
    async fn consume_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<Session>> {
        self.inner
            .consume_by_token_hash(tenant_id, token_hash)
            .await
    }
    async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.inner
            .invalidate_user_sessions(tenant_id, user_id)
            .await
    }
    async fn invalidate_user_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        keep: Uuid,
    ) -> AxiamResult<u64> {
        self.inner
            .invalidate_user_sessions_except(tenant_id, user_id, keep)
            .await
    }
    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        self.inner.cleanup_expired(tenant_id).await
    }
    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Session>> {
        self.inner.list_by_user(tenant_id, user_id).await
    }
    async fn mark_refresh_replay(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        accepted_under_grace: bool,
    ) -> AxiamResult<()> {
        self.inner
            .mark_refresh_replay(tenant_id, session_id, accepted_under_grace)
            .await
    }
}

/// A real refresh-token repository whose `revoke_all_for_session` fails while
/// `fail` is set.
#[derive(Clone)]
struct FlakyRefreshTokenRepo {
    inner: SurrealRefreshTokenRepository<MemDb>,
    fail: Arc<AtomicBool>,
}

impl RefreshTokenRepository for FlakyRefreshTokenRepo {
    async fn create(&self, input: CreateRefreshToken) -> AxiamResult<RefreshToken> {
        self.inner.create(input).await
    }
    async fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<RefreshToken> {
        self.inner.get_by_token_hash(tenant_id, token_hash).await
    }
    async fn revoke(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<()> {
        self.inner.revoke(tenant_id, token_hash).await
    }
    async fn supersede(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
        grace_until: chrono::DateTime<Utc>,
    ) -> AxiamResult<()> {
        self.inner
            .supersede(tenant_id, token_hash, grace_until)
            .await
    }
    async fn revoke_rotated(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<()> {
        self.inner.revoke_rotated(tenant_id, token_hash).await
    }
    async fn find_rotated(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<RefreshToken>> {
        self.inner.find_rotated(tenant_id, token_hash).await
    }
    async fn revoke_all_for_client(&self, tenant_id: Uuid, client_id: &str) -> AxiamResult<u64> {
        self.inner.revoke_all_for_client(tenant_id, client_id).await
    }
    async fn revoke_all_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        self.inner.revoke_all_for_user(tenant_id, user_id).await
    }
    async fn revoke_all_for_session(&self, tenant_id: Uuid, session_id: Uuid) -> AxiamResult<u64> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AxiamError::Database("injected: refresh revocation".into()));
        }
        self.inner
            .revoke_all_for_session(tenant_id, session_id)
            .await
    }
    async fn revoke_all_for_lineage(
        &self,
        tenant_id: Uuid,
        lineage_id: Uuid,
        session_id: Uuid,
    ) -> AxiamResult<u64> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AxiamError::Database("injected: refresh revocation".into()));
        }
        self.inner
            .revoke_all_for_lineage(tenant_id, lineage_id, session_id)
            .await
    }
    async fn delete_all_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        self.inner.delete_all_for_user(tenant_id, user_id).await
    }
    async fn delete_expired(&self, before: chrono::DateTime<Utc>, limit: u32) -> AxiamResult<u64> {
        self.inner.delete_expired(before, limit).await
    }
}

/// Alice signed in through `svc`, plus an OAuth2 refresh token (a code grant's
/// or a native sign-in's) issued under that session. Returns the access
/// token the caller logs out with and the refresh token's hash.
async fn sign_in_with_a_grant(
    svc: &AuthService<
        SurrealUserRepository<MemDb>,
        FlakySessionRepo,
        SurrealFederationLinkRepository<MemDb>,
        FlakyRefreshTokenRepo,
    >,
    refresh_repo: &SurrealRefreshTokenRepository<MemDb>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> (String, String) {
    let out = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::Success(out) => out,
        // Name the variant only: a `{:?}` of the result is a cleartext-logging sink.
        _ => panic!("expected Success, got an MFA variant"),
    };
    let token_hash = token::hash_refresh_token(&token::generate_refresh_token());
    refresh_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: token_hash.clone(),
            client_id: "native-app".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            session_id: Some(out.session_id),
            requested_userinfo_claims: vec![],
            resource: None,
            auth_time: None,
            acr: None,
            amr: vec![],
            dpop_jkt: None,
            expires_at: Utc::now() + Duration::days(30),
            lineage_id: None,
        })
        .await
        .unwrap();
    (out.access_token, token_hash)
}

/// Whether the refresh grant would still find the token: the lookup it makes
/// skips a revoked row, which is how a revoked token is refused.
async fn refresh_is_live(
    repo: &SurrealRefreshTokenRepository<MemDb>,
    tenant_id: Uuid,
    token_hash: &str,
) -> bool {
    match repo.get_by_token_hash(tenant_id, token_hash).await {
        Ok(row) => !row.revoked,
        Err(AxiamError::NotFound { .. }) => false,
        Err(e) => panic!("unexpected lookup error: {e}"),
    }
}

/// What the REST layer derives from a bearer token: the session it names.
fn session_of(access_token: &str) -> Uuid {
    let claims = token::validate_access_token(access_token, &test_config()).unwrap();
    claims
        .0
        .sid
        .as_deref()
        .unwrap_or(&claims.0.jti)
        .parse()
        .unwrap()
}

type FlakySetup = (
    AuthService<
        SurrealUserRepository<MemDb>,
        FlakySessionRepo,
        SurrealFederationLinkRepository<MemDb>,
        FlakyRefreshTokenRepo,
    >,
    SurrealSessionRepository<MemDb>,
    SurrealRefreshTokenRepository<MemDb>,
    Arc<AtomicBool>, // fail the session delete
    Arc<AtomicBool>, // fail the refresh-token revocation
    Uuid,
    Uuid,
    Uuid,
    Surreal<MemDb>,
);

async fn flaky_setup() -> FlakySetup {
    let (user_repo, session_repo, fed_repo, refresh_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let (fail_session, fail_refresh) = (Arc::new(AtomicBool::new(false)), Arc::default());
    let svc = AuthService::new(
        user_repo,
        FlakySessionRepo {
            inner: session_repo.clone(),
            fail: Arc::clone(&fail_session),
        },
        fed_repo,
        FlakyRefreshTokenRepo {
            inner: refresh_repo.clone(),
            fail: Arc::clone(&fail_refresh),
        },
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    (
        svc,
        session_repo,
        refresh_repo,
        fail_session,
        fail_refresh,
        org_id,
        tenant_id,
        user_id,
        db,
    )
}

/// A failed revocation fails the logout **before** the session is touched, so
/// the caller's own credential still names a live session and repeating the
/// logout with it completes the logout: the session ends and the refresh
/// token is refused.
#[tokio::test]
async fn a_failed_revocation_leaves_the_session_for_a_retry_with_the_same_credential() {
    let (svc, sessions, refresh_tokens, _, fail_refresh, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (bearer, refresh_hash) =
        sign_in_with_a_grant(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    fail_refresh.store(true, Ordering::SeqCst);
    assert!(
        svc.logout(tenant_id, session_of(&bearer)).await.is_err(),
        "a failed revocation is a failed logout"
    );
    sessions
        .get_by_id(tenant_id, session_of(&bearer))
        .await
        .expect("the session is still live, so the bearer token still reaches it");
    assert!(
        refresh_is_live(&refresh_tokens, tenant_id, &refresh_hash).await,
        "the refresh token is untouched until the retry"
    );

    fail_refresh.store(false, Ordering::SeqCst);
    svc.logout(tenant_id, session_of(&bearer))
        .await
        .expect("the retry with the same credential completes the logout");
    assert!(matches!(
        sessions.get_by_id(tenant_id, session_of(&bearer)).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(
        !refresh_is_live(&refresh_tokens, tenant_id, &refresh_hash).await,
        "the session's refresh token is refused from now on"
    );
}

/// A session delete that fails after the revocation succeeded is also a failed
/// logout, retryable the same way: the revocation's second pass is a no-op and
/// the delete then runs.
#[tokio::test]
async fn a_failed_session_delete_after_the_revocation_is_retryable() {
    let (svc, sessions, refresh_tokens, fail_session, _, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (bearer, refresh_hash) =
        sign_in_with_a_grant(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    fail_session.store(true, Ordering::SeqCst);
    assert!(svc.logout(tenant_id, session_of(&bearer)).await.is_err());
    assert!(
        !refresh_is_live(&refresh_tokens, tenant_id, &refresh_hash).await,
        "the revocation ran first"
    );
    sessions
        .get_by_id(tenant_id, session_of(&bearer))
        .await
        .expect("the session is still live for the retry");

    fail_session.store(false, Ordering::SeqCst);
    svc.logout(tenant_id, session_of(&bearer))
        .await
        .expect("the retry completes the logout");
    assert!(matches!(
        sessions.get_by_id(tenant_id, session_of(&bearer)).await,
        Err(AxiamError::NotFound { .. })
    ));
}

// -----------------------------------------------------------------------
// #844 (D-N43) — logout reaches grants issued before a console refresh
// -----------------------------------------------------------------------

/// A console sign-in, an OAuth2 grant issued under it, then a console
/// refresh: the access token the caller now holds names the *new* session,
/// while the grant still names the old one. Returns (old session, new
/// session, the grant's hash).
async fn grant_then_console_refresh(
    svc: &AuthService<
        SurrealUserRepository<MemDb>,
        FlakySessionRepo,
        SurrealFederationLinkRepository<MemDb>,
        FlakyRefreshTokenRepo,
    >,
    refresh_repo: &SurrealRefreshTokenRepository<MemDb>,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> (Uuid, Uuid, String) {
    let out = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::Success(out) => out,
        _ => panic!("expected Success, got an MFA variant"),
    };
    let grant_hash = token::hash_refresh_token(&token::generate_refresh_token());
    refresh_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: grant_hash.clone(),
            client_id: "rp".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            session_id: Some(out.session_id),
            requested_userinfo_claims: vec![],
            resource: None,
            auth_time: None,
            acr: None,
            amr: vec![],
            dpop_jkt: None,
            expires_at: Utc::now() + Duration::days(30),
            lineage_id: None,
        })
        .await
        .unwrap();
    let refreshed = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: out.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    assert_ne!(
        refreshed.session_id, out.session_id,
        "rotation replaced the row"
    );
    (out.session_id, refreshed.session_id, grant_hash)
}

/// #844 (d) — the console refresh copies the lineage, and the lineage of a
/// sign-in is the id of its first session.
#[tokio::test]
async fn a_console_refresh_keeps_the_session_lineage() {
    let (svc, sessions, refresh_tokens, _, _, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (first, current, grant_hash) =
        grant_then_console_refresh(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    let row = sessions.get_by_id(tenant_id, current).await.unwrap();
    assert_eq!(
        row.lineage_id, first,
        "the lineage is keyed by the first session"
    );
    let grant = refresh_tokens
        .get_by_token_hash(tenant_id, &grant_hash)
        .await
        .unwrap();
    assert_eq!(grant.session_id, Some(first), "the grant keeps its sid");
    assert_eq!(grant.lineage_id, Some(first), "and records the lineage");
    assert_eq!(
        sessions
            .lineage_of(tenant_id, first)
            .await
            .unwrap()
            .map(|l| l.lineage_id),
        Some(first),
        "the rotated-away id still resolves, through the grant that recorded it"
    );
}

/// #844 (a) — `POST /auth/logout` with the post-refresh credential revokes the
/// grant issued before the refresh. Before the lineage it was missed: the
/// grant named a session id the refresh had already replaced.
#[tokio::test]
async fn logout_after_a_console_refresh_revokes_a_grant_issued_before_it() {
    let (svc, sessions, refresh_tokens, _, _, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (_, current, grant_hash) =
        grant_then_console_refresh(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    svc.logout(tenant_id, current).await.unwrap();
    assert!(
        !refresh_is_live(&refresh_tokens, tenant_id, &grant_hash).await,
        "the grant of the lineage is revoked"
    );
    assert!(matches!(
        sessions.get_by_id(tenant_id, current).await,
        Err(AxiamError::NotFound { .. })
    ));
}

/// #844, the mirror case — a logout handed the rotated-away id (an
/// `id_token_hint`'s `sid` from before the refresh) ends the live session of
/// the lineage, so the SSO session does not survive the relying party's
/// logout.
#[tokio::test]
async fn logout_by_a_rotated_away_id_ends_the_live_session_of_its_lineage() {
    let (svc, sessions, refresh_tokens, _, _, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (first, current, grant_hash) =
        grant_then_console_refresh(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    svc.logout(tenant_id, first).await.unwrap();
    assert!(
        matches!(
            sessions.get_by_id(tenant_id, current).await,
            Err(AxiamError::NotFound { .. })
        ),
        "the live row of the lineage is ended"
    );
    assert!(!refresh_is_live(&refresh_tokens, tenant_id, &grant_hash).await);
}

/// #844 — the lineage never reaches another sign-in: a second login of the
/// same user is a second lineage, and logging the first out leaves it and its
/// grant alone.
#[tokio::test]
async fn a_lineage_logout_leaves_the_users_other_sign_ins_alone() {
    let (svc, sessions, refresh_tokens, _, _, org_id, tenant_id, user_id, _db) =
        flaky_setup().await;
    let (_, current, _) =
        grant_then_console_refresh(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;
    let (_, other, other_grant) =
        grant_then_console_refresh(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;

    svc.logout(tenant_id, current).await.unwrap();
    sessions
        .get_by_id(tenant_id, other)
        .await
        .expect("the other sign-in is untouched");
    assert!(refresh_is_live(&refresh_tokens, tenant_id, &other_grant).await);
}

/// #844 (c) — rows written before schema v115 carry no lineage. A session
/// without one is its own lineage, a grant without one is its session's, and
/// a logout of that session still revokes the grant, as it did before.
#[tokio::test]
async fn rows_without_a_lineage_keep_the_pre_v115_logout() {
    let (svc, sessions, refresh_tokens, _, _, org_id, tenant_id, user_id, db) = flaky_setup().await;
    let (bearer, grant_hash) =
        sign_in_with_a_grant(&svc, &refresh_tokens, tenant_id, org_id, user_id).await;
    let sid = session_of(&bearer);
    // Strip what v115 writes, exactly as an older binary would have left it.
    db.query(
        "UPDATE type::record('session', $sid) SET lineage_id = NONE; \
         UPDATE oauth2_refresh_token SET lineage_id = NONE WHERE session_id = $sid",
    )
    .bind(("sid", sid.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();

    let row = sessions.get_by_id(tenant_id, sid).await.unwrap();
    assert_eq!(
        row.lineage_id, sid,
        "an absent lineage reads as the session's own id"
    );
    let grant = refresh_tokens
        .get_by_token_hash(tenant_id, &grant_hash)
        .await
        .unwrap();
    assert_eq!(
        grant.lineage_id,
        Some(sid),
        "and a grant's as its session's"
    );

    svc.logout(tenant_id, sid).await.unwrap();
    assert!(!refresh_is_live(&refresh_tokens, tenant_id, &grant_hash).await);
    assert!(matches!(
        sessions.get_by_id(tenant_id, sid).await,
        Err(AxiamError::NotFound { .. })
    ));
}

// -----------------------------------------------------------------------
// T2.2 — Token refresh, validation, and revocation tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn refresh_happy_path() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;

    let lock_repo = SurrealUserRepository::new(db);
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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

/// #519 (P23W1-07) — a session refresh asks whether the account may act, not
/// whether a password sign-in would pass. A `PendingVerification` account
/// older than the email-verification grace window (24 h here) is every
/// federated account a day after it was provisioned; its session must keep
/// refreshing. Before the fix this was refused `AccountPendingVerification`.
#[tokio::test]
async fn refresh_of_a_pending_account_past_the_grace_window_succeeds() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let raw_repo = SurrealUserRepository::new(db.clone());
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let login_out = login_alice(&svc, tenant_id, org_id).await;

    // The account is pending verification and was created before the window.
    raw_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::PendingVerification),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    db.query("UPDATE type::record('user', $id) SET created_at = time::now() - 48h")
        .bind(("id", user_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let user = raw_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.status, UserStatus::PendingVerification);
    assert!(
        user.created_at < Utc::now() - Duration::hours(24),
        "the account must predate the grace window"
    );

    let refreshed = svc
        .refresh(RefreshInput {
            tenant_id,
            org_id,
            raw_refresh_token: login_out.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .expect("a pending account's session keeps refreshing past the grace window");
    assert!(!refreshed.access_token.is_empty());
    assert_ne!(refreshed.session_id, login_out.session_id);
}

/// #519's other half: `account_may_act` still refuses an inactive account, as
/// `refresh_locked_user_fails` pins for a locked one.
#[tokio::test]
async fn refresh_inactive_user_fails() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let raw_repo = SurrealUserRepository::new(db);
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let login_out = login_alice(&svc, tenant_id, org_id).await;

    raw_repo
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
            assert!(reason.contains("inactive"), "expected 'inactive': {reason}");
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

    let jwt = token::issue_access_token(
        uid,
        tid,
        oid,
        &[],
        &config,
        Uuid::new_v4().to_string(),
        token::AUD_USER,
    )
    .unwrap();
    let validated = token::validate_access_token(&jwt, &config).unwrap();
    assert_eq!(validated.0.sub, uid.to_string());

    let tampered = format!("{jwt}x");
    assert!(token::validate_access_token(&tampered, &config).is_err());
}

/// QR12-3: a failed session delete must not leave the OAuth2 refresh tokens
/// live. Both revocations are attempted, then the first error is reported.
async fn session_delete_failure_world() -> (
    AuthService<
        SurrealUserRepository<MemDb>,
        SurrealSessionRepository<MemDb>,
        SurrealFederationLinkRepository<MemDb>,
        SurrealRefreshTokenRepository<MemDb>,
    >,
    SurrealRefreshTokenRepository<MemDb>,
    Uuid,
    Uuid,
    String,
    Uuid,
) {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let oauth2_tokens = refresh_token_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let kept = login_alice(&svc, tenant_id, org_id).await;
    let token_hash = token::hash_refresh_token(&token::generate_refresh_token());
    oauth2_tokens
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: token_hash.clone(),
            client_id: "native-app".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            session_id: None,
            requested_userinfo_claims: vec![],
            resource: None,
            auth_time: None,
            acr: None,
            amr: vec![],
            dpop_jkt: None,
            expires_at: Utc::now() + Duration::days(30),
            lineage_id: None,
        })
        .await
        .unwrap();
    login_alice(&svc, tenant_id, org_id).await;
    db.query(
        "DEFINE EVENT session_delete_poison ON TABLE session \
         WHEN $event = 'DELETE' THEN { THROW 'poisoned delete' }",
    )
    .await
    .unwrap()
    .check()
    .unwrap();
    (
        svc,
        oauth2_tokens,
        tenant_id,
        user_id,
        token_hash,
        kept.session_id,
    )
}

#[tokio::test]
async fn qr12_3_revoke_all_sessions_revokes_oauth2_tokens_when_the_session_delete_fails() {
    let (svc, oauth2_tokens, tenant_id, user_id, token_hash, _kept) =
        session_delete_failure_world().await;
    svc.revoke_all_sessions(tenant_id, user_id)
        .await
        .expect_err("the failed session delete is reported");
    assert!(
        matches!(
            oauth2_tokens
                .get_by_token_hash(tenant_id, &token_hash)
                .await,
            Err(AxiamError::NotFound { .. })
        ),
        "the OAuth2 refresh token must be revoked although the session delete failed"
    );
}

#[tokio::test]
async fn qr12_3_revoke_all_sessions_except_revokes_oauth2_tokens_when_the_session_delete_fails() {
    let (svc, oauth2_tokens, tenant_id, user_id, token_hash, kept) =
        session_delete_failure_world().await;
    svc.revoke_all_sessions_except(tenant_id, user_id, kept)
        .await
        .expect_err("the failed session delete is reported");
    assert!(
        matches!(
            oauth2_tokens
                .get_by_token_hash(tenant_id, &token_hash)
                .await,
            Err(AxiamError::NotFound { .. })
        ),
        "the OAuth2 refresh token must be revoked although the session delete failed"
    );
}

#[tokio::test]
async fn revoke_all_sessions() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Step 1: enroll — get secret + URI.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    assert!(!enrollment.secret_base32.is_empty());
    assert!(enrollment.totp_uri.starts_with("otpauth://totp/"));

    // Step 2: generate a valid TOTP code from the secret.
    let secret = totp_rs::Secret::try_from_base32(&enrollment.secret_base32).unwrap();
    let secret_bytes = secret.as_bytes().to_vec();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name("alice@example.com")
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();

    // Step 3: confirm with valid code.
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();
}

#[tokio::test]
async fn mfa_login_challenge_flow() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Enroll and confirm MFA.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let secret = totp_rs::Secret::try_from_base32(&enrollment.secret_base32).unwrap();
    let secret_bytes = secret.as_bytes().to_vec();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name("alice@example.com")
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();

    // Login should now return MfaRequired.
    let login_result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap();

    let challenge_token = match login_result {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        other => panic!("expected MfaRequired, got {other:?}"),
    };

    // Verify MFA with a valid code from a LATER step — SECHRD-01 now seeds
    // totp_last_used_step at confirm_mfa time, so reusing `code`'s step
    // here would be correctly rejected as a replay.
    let new_code = generate_next_step_code(&totp);
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Enroll + confirm.
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let secret = totp_rs::Secret::try_from_base32(enrollment.secret_base32).unwrap();
    let secret_bytes = secret.as_bytes().to_vec();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name("alice@example.com")
        .build()
        .unwrap();
    let code = totp.generate_current().to_string();
    svc.confirm_mfa(tenant_id, user_id, &code).await.unwrap();

    // Login → get challenge.
    let login_result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    svc.enroll_mfa(tenant_id, user_id).await.unwrap();

    let err = svc
        .confirm_mfa(tenant_id, user_id, "000000")
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

#[tokio::test]
async fn login_without_mfa_still_returns_success() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap();

    assert!(matches!(result, LoginResult::Success(_)));
}

// -----------------------------------------------------------------------
// T2.4 — Brute force protection tests
// -----------------------------------------------------------------------

/// Helper: attempt a bad login carrying an explicit tenant lockout policy.
///
/// The policy is the whole point of these tests: it is what an administrator
/// sets on the organization, and until it was threaded into `LoginInput` the
/// login path metered against the deployment-wide `AuthConfig` instead — so a
/// threshold lowered in the admin UI changed nothing.
async fn bad_login_with_policy(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
        SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
    policy: Option<axiam_core::models::settings::LockoutPolicy>,
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
            lockout_policy: policy,
        })
        .await;
}

/// Helper: attempt a bad login.
async fn bad_login(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
        SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
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
            lockout_policy: None,
        })
        .await;
}

#[tokio::test]
async fn failed_login_increments_counter() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3; // lower threshold for test
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config,
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

/// The reported bug: a threshold lowered in the admin UI changed nothing.
///
/// The deployment default here is 10 — high enough that three failures come
/// nowhere near it — while the tenant's own policy says 3. Before
/// `LoginInput::lockout_policy` existed the login path metered against
/// `AuthConfig` and this account would still be unlocked; the tenant's setting
/// was stored, merged org→tenant, returned by the settings API, and read by
/// nothing.
#[tokio::test]
async fn a_tenants_own_threshold_locks_sooner_than_the_deployment_default() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 10;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config,
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Spelled out rather than derived from a default: the three fields beyond
    // the threshold are what the lockout WINDOW is, and a test that inherited
    // them would not say which value it was actually exercising.
    let policy = axiam_core::models::settings::LockoutPolicy {
        max_failed_login_attempts: 3,
        lockout_duration_secs: 60,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 900,
    };

    for _ in 0..3 {
        bad_login_with_policy(&svc, tenant_id, org_id, Some(policy.clone())).await;
    }

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.failed_login_attempts, 3);
    assert!(
        user.locked_until.is_some(),
        "the tenant's threshold of 3 must lock the account, not the deployment default of 10"
    );
}

/// And the converse: a tenant asking for a HIGHER threshold is honoured too.
///
/// Without this, a fix that simply always locked at three would pass the test
/// above. What the setting means is "use my number", in both directions.
#[tokio::test]
async fn a_tenants_higher_threshold_holds_the_account_open() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config,
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let policy = axiam_core::models::settings::LockoutPolicy {
        max_failed_login_attempts: 8,
        lockout_duration_secs: 60,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 900,
    };

    for _ in 0..3 {
        bad_login_with_policy(&svc, tenant_id, org_id, Some(policy.clone())).await;
    }

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(user.failed_login_attempts, 3);
    assert!(
        user.locked_until.is_none(),
        "the deployment default of 3 must not lock an account whose tenant allows 8"
    );
}

/// No tenant policy falls back to the deployment default.
///
/// The safety property behind the fallback: a settings lookup that fails must
/// not become an open brute-force window.
#[tokio::test]
async fn no_tenant_policy_falls_back_to_the_deployment_default() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config,
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    for _ in 0..3 {
        bad_login_with_policy(&svc, tenant_id, org_id, None).await;
    }

    let check_repo = SurrealUserRepository::new(db);
    let user = check_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(user.locked_until.is_some());
}

#[tokio::test]
async fn lockout_expires_allows_login() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let mut config = test_config();
    config.max_failed_login_attempts = 3;
    config.lockout_duration_secs = 60;
    config.lockout_backoff_multiplier = 2.0;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config,
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
fn totp_from_secret(secret_base32: &str, email: &str) -> totp_rs::Totp {
    let secret = totp_rs::Secret::try_from_base32(secret_base32).unwrap();
    let secret_bytes = secret.as_bytes().to_vec();
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name(email)
        .build()
        .unwrap()
}

/// Generate a TOTP code for the step AFTER the current wall-clock step.
///
/// SECHRD-01: `confirm_mfa` now seeds `totp_last_used_step` at
/// enrollment-confirm time (not just at first login), so a second
/// `verify_code_with_replay_check` call in the SAME step is correctly
/// rejected as a replay. Tests that call `confirm_mfa`/`enable_mfa_for_alice`
/// and then immediately `verify_mfa` must use a code from a LATER step —
/// this generates one without needing to sleep past a real 30s boundary
/// (the code is still accepted via the ±1 skew tolerance, since the real
/// current step hasn't advanced yet).
fn generate_next_step_code(totp: &totp_rs::Totp) -> String {
    let current_step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    // 6.0's `generate` answers a `Token`; this helper's contract is the
    // string a client would submit.
    totp.generate((current_step + 1) * 30).to_string()
}

/// Helper: enroll + confirm MFA for user alice, returning the TOTP verifier.
async fn enable_mfa_for_alice(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
        SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    user_id: Uuid,
) -> totp_rs::Totp {
    let enrollment = svc.enroll_mfa(tenant_id, user_id).await.unwrap();
    let totp = totp_from_secret(&enrollment.secret_base32, "alice@example.com");
    let code = totp.generate_current().to_string();
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Enable MFA first.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_not_enforced_policy(),
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

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
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            native_login: None,
            token_exchange: None,
            provider_kind: None,
            provider_slug: None,
            allow_tenant_inheritance: None,
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: None,
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: None,
            button_icon: None,
            allow_sha1_signatures: None,
            idp_metadata_signing_cert_pem: None,
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
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Login with MFA enforced to get a setup_token.
    let setup_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Step 1: Login with enforcement → get setup_token.
    let setup_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
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
    let code = totp.generate_current().to_string();

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Enable MFA and create a session.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;

    // Login (will require MFA challenge). Complete it to get a session.
    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
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
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret_bytes)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name("alice@example.com")
        .build()
        .unwrap();
    // SECHRD-01: enable_mfa_for_alice's confirm_mfa already seeded
    // totp_last_used_step at the current step, so use a code from the
    // NEXT step here (still accepted via ±1 skew) rather than the same
    // step, which would be correctly rejected as a replay.
    let code = generate_next_step_code(&totp);

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
    mfa_methods(&db)
        .reset_mfa(tenant_id, user_id)
        .await
        .unwrap();

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
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Enable MFA, then reset it.
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    mfa_methods(&db)
        .reset_mfa(tenant_id, user_id)
        .await
        .unwrap();

    // Login with MFA enforced — should require setup again.
    let result = svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
        })
        .await
        .unwrap();

    assert!(
        matches!(result, LoginResult::MfaSetupRequired(_)),
        "expected MfaSetupRequired after reset, got {result:?}"
    );
}

// -----------------------------------------------------------------------
// T2.x — change_password: reset-to-current rejected (SEC-028)
// -----------------------------------------------------------------------

/// SEC-028: changing to the same password is rejected with Validation error.
#[tokio::test]
async fn change_password_rejects_reuse_of_current() {
    use axiam_core::models::settings::PasswordPolicy;
    use axiam_db::repository::SurrealPasswordHistoryRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Get a valid session so we have a session_id for change_password.
    let out = login_alice(&svc, tenant_id, org_id).await;
    let policy = PasswordPolicy {
        min_length: 12,
        require_uppercase: false,
        require_lowercase: false,
        require_digits: false,
        require_symbols: false,
        password_history_count: 0,
        hibp_check_enabled: false,
    };
    let history_repo = SurrealPasswordHistoryRepository::new(db.clone());

    // Attempting to change to the *same* password must fail.
    let err = svc
        .change_password(
            tenant_id,
            user_id,
            out.session_id,
            &test_password(),
            &test_password(),
            &policy,
            &history_repo,
            None, // no HIBP client in tests
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, AxiamError::Validation { .. }),
        "reset-to-current must return Validation error, got: {err:?}"
    );
}

/// Changing to a *new* password succeeds (baseline, regression guard).
#[tokio::test]
async fn change_password_new_password_succeeds() {
    use axiam_core::models::settings::PasswordPolicy;
    use axiam_db::repository::SurrealPasswordHistoryRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let config = test_config();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        config.clone(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let out = login_alice(&svc, tenant_id, org_id).await;
    let policy = PasswordPolicy {
        min_length: 12,
        require_uppercase: false,
        require_lowercase: false,
        require_digits: false,
        require_symbols: false,
        password_history_count: 0,
        hibp_check_enabled: false,
    };
    let history_repo = SurrealPasswordHistoryRepository::new(db.clone());

    // A different, policy-compliant password must succeed.
    svc.change_password(
        tenant_id,
        user_id,
        out.session_id,
        &test_password(),
        &other_password(),
        &policy,
        &history_repo,
        None, // no HIBP client in tests
    )
    .await
    .expect("changing to a new password should succeed");
}

// ---------------------------------------------------------------------------
// ensure_can_sign_in — the account-status gate for credential-only sign-in
// ---------------------------------------------------------------------------
//
// Usernameless passkey sign-in authenticates from a credential alone, so it
// never passes through `login` or `verify_mfa` and never reaches their status
// checks. These assert the gate that stands in for them: a passkey enrolled
// while an account was healthy keeps verifying after the account is disabled,
// so "the assertion is valid" must not be allowed to mean "this user may sign
// in".

#[tokio::test]
async fn ensure_can_sign_in_admits_an_active_user() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, _db) =
        setup().await;
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();

    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    svc.ensure_can_sign_in(&user)
        .expect("an active user may sign in");
}

#[tokio::test]
async fn ensure_can_sign_in_refuses_a_deactivated_user() {
    for status in [
        UserStatus::Inactive,
        UserStatus::Locked,
        UserStatus::Anonymized,
    ] {
        let (
            user_repo,
            session_repo,
            fed_repo,
            refresh_token_repo,
            _org_id,
            tenant_id,
            user_id,
            _db,
        ) = setup().await;

        user_repo
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    status: Some(status.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();

        let svc = AuthService::new(
            user_repo,
            session_repo,
            fed_repo,
            refresh_token_repo,
            test_config(),
            Arc::new(tokio::sync::Semaphore::new(4)),
        );

        assert!(
            svc.ensure_can_sign_in(&user).is_err(),
            "a {status:?} user must not be able to sign in with a passkey alone"
        );
    }
}

#[tokio::test]
async fn ensure_can_sign_in_refuses_a_user_inside_a_lockout_window() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, _db) =
        setup().await;

    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                locked_until: Some(Some(Utc::now() + Duration::seconds(300))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();

    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // Brute-force lockout must not be walkable by switching to the passkey
    // button, and the refusal is the generic one `login` gives so that which
    // of the two reasons applies is not disclosed.
    assert!(matches!(
        svc.ensure_can_sign_in(&user),
        Err(AuthError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn ensure_can_sign_in_admits_a_user_whose_lockout_has_expired() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, _db) =
        setup().await;

    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                locked_until: Some(Some(Utc::now() - Duration::seconds(10))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();

    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    svc.ensure_can_sign_in(&user)
        .expect("an elapsed lockout must not keep locking the account out");
}

// -----------------------------------------------------------------------
// The lockout threshold is the ORGANIZATION's, not the deployment default
// -----------------------------------------------------------------------
//
// `LoginInput::lockout_policy` exists because it did not. `AuthService::login`
// metered every failed attempt against `A

// -----------------------------------------------------------------------
// X7.2 — what each sign-in path records as the authentication event
// (basic-op-gap-plan.md §4.3; T23.1.2 audit)
// -----------------------------------------------------------------------
//
// `session_evidence_rotation_test` pins the password path and what rotation
// does to the record. These pin the other paths that reach
// `create_session_and_tokens` through `axiam-auth` itself: the TOTP second
// step, the forced first-login enrolment, the OPAQUE tail, and the choke
// point's own contract (the evidence it is handed is the evidence stored, and
// the browser-session credential is stored only as a digest). The WebAuthn
// and federation call sites live in `axiam-api-rest` and are pinned there.

/// The password-then-TOTP path records `pwd`, `otp` **and** `mfa`, dated at the
/// second factor — and the password step on its own mints no session at all,
/// so there is no earlier, weaker record for it to be confused with.
#[tokio::test]
async fn x7_2_a_totp_second_step_records_pwd_otp_and_mfa() {
    use axiam_core::models::session::Amr;
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let totp = enable_mfa_for_alice(&svc, tenant_id, user_id).await;

    let challenge_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        _ => panic!("expected MfaRequired, got another login result"),
    };
    assert!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .is_empty(),
        "the password step of an MFA login must not create a session: the only \
         authentication event is the completed one"
    );

    let before = Utc::now() - Duration::seconds(1);
    let out = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: generate_next_step_code(&totp),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();

    let session = sessions.get_by_id(tenant_id, out.session_id).await.unwrap();
    assert_eq!(
        session.amr,
        vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
        "TOTP after a password is two factors: pwd + otp, with mfa alongside"
    );
    assert!(
        session.authenticated_at >= before
            && session.authenticated_at <= Utc::now() + Duration::seconds(1),
        "the event is dated when the second factor verified, not at epoch or \
         at the password step's expense: {}",
        session.authenticated_at
    );
}

/// The forced first-login enrolment (a setup token, then a TOTP confirmation)
/// records exactly what the ordinary TOTP path records: a session issued by
/// one route is worth the same to every reader of `amr` as one issued by the
/// other.
#[tokio::test]
async fn x7_2_a_forced_totp_enrolment_records_the_same_evidence_as_the_totp_step() {
    use axiam_core::models::session::Amr;
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, _user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let setup_token = match svc
        .login(LoginInput {
            tenant_id,
            org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        _ => panic!("expected MfaSetupRequired, got another login result"),
    };
    let enrollment = svc.enroll_mfa_with_setup_token(&setup_token).await.unwrap();
    let totp = totp_from_secret(&enrollment.secret_base32, "alice@example.com");
    let out = svc
        .confirm_mfa_with_setup_token(
            &setup_token,
            &totp.generate_current().to_string(),
            None,
            None,
        )
        .await
        .unwrap();

    let session = sessions
        .get_by_id(tenant_id, out.session_id)
        .await
        .expect("the enrolment's session");
    assert_eq!(session.amr, vec![Amr::Pwd, Amr::Otp, Amr::Mfa]);
    assert!(
        (Utc::now() - session.authenticated_at).num_seconds().abs() < 30,
        "dated now, not at epoch: {}",
        session.authenticated_at
    );
}

/// `complete_authenticated_login` is the tail shared by the password path and
/// the OPAQUE path (`handlers/opaque.rs` calls it after `login_finish`), so
/// asserting it here is asserting what an OPAQUE sign-in records: `pwd`, the
/// RFC 8176 value for "a password-authenticated key exchange proved knowledge
/// of the password", and nothing stronger.
#[tokio::test]
async fn x7_2_the_opaque_tail_records_pwd_and_no_second_factor() {
    use axiam_core::models::session::Amr;
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    let sessions = session_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let out = match svc
        .complete_authenticated_login(user, tenant_id, org_id, None, None, None)
        .await
        .unwrap()
    {
        LoginResult::Success(out) => out,
        LoginResult::MfaRequired(_) => panic!("expected Success, got MfaRequired"),
        LoginResult::MfaSetupRequired(_) => panic!("expected Success, got MfaSetupRequired"),
    };

    let session = sessions.get_by_id(tenant_id, out.session_id).await.unwrap();
    assert_eq!(session.amr, vec![Amr::Pwd]);
}

/// D-10 (T23.1.2): a provider that dates its authentication in AXIAM's future
/// is recorded as having authenticated when AXIAM verified the assertion — the
/// stored `authenticated_at` is what `max_age` and the ID token's `auth_time`
/// read, so it must never run ahead of the verification instant.
#[tokio::test]
async fn d10_a_far_future_upstream_instant_is_stored_as_the_verification_instant() {
    use axiam_core::models::session::{Amr, AuthenticationEvidence};
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let verified_at = Utc::now();
    let far_future = verified_at + Duration::days(365 * 70);
    let out = svc
        .create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            None,
            None,
            AuthenticationEvidence::upstream(Some(far_future), verified_at, vec![Amr::Fed]),
            None,
        )
        .await
        .unwrap();

    let session = sessions.get_by_id(tenant_id, out.session_id).await.unwrap();
    assert_eq!(
        session.authenticated_at.timestamp(),
        verified_at.timestamp(),
        "the provider's future is not AXIAM's evidence"
    );
}

/// The choke point records the evidence it is **given**, not a clock read and
/// not a constant — which is the whole reason a federated login can be dated
/// by the upstream provider — and it stores the OP browser-session credential
/// as a SHA-256 digest only.
#[tokio::test]
async fn x7_2_create_session_and_tokens_stores_the_evidence_given_and_only_a_digest_of_the_cookie()
{
    use axiam_core::models::session::{Amr, AuthenticationEvidence};
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // An upstream IdP replaying an SSO session it established nine hours ago.
    let nine_hours_ago = Utc::now() - Duration::hours(9);
    let out = svc
        .create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            None,
            None,
            AuthenticationEvidence::upstream(Some(nine_hours_ago), Utc::now(), vec![Amr::Fed]),
            None,
        )
        .await
        .unwrap();

    let session = sessions.get_by_id(tenant_id, out.session_id).await.unwrap();
    assert_eq!(
        session.authenticated_at.timestamp(),
        nine_hours_ago.timestamp(),
        "a federated login is dated by the upstream, not by AXIAM's clock"
    );
    assert_eq!(
        session.amr,
        vec![Amr::Fed],
        "`fed` and nothing else: AXIAM did not verify a password or a factor"
    );

    // h. The browser-session credential: a digest at rest, never the value.
    let stored = session
        .browser_token_hash
        .as_deref()
        .expect("every browser sign-in records an OP browser-session digest");
    assert_ne!(
        stored, out.browser_session_token,
        "the raw cookie value must never be what is stored"
    );
    assert_eq!(
        stored,
        token::hash_browser_session_token(&out.browser_session_token),
        "what is stored is the digest the authorization endpoint will compute \
         from the cookie it receives"
    );
    assert_eq!(stored.len(), 64, "a hex-encoded SHA-256");
    assert!(stored.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(
        stored,
        token::hash_refresh_token(&out.refresh_token),
        "the two credentials are independent: one is not derived from the other"
    );
    assert!(
        sessions
            .get_by_browser_token_hash(
                tenant_id,
                &token::hash_browser_session_token(&out.browser_session_token)
            )
            .await
            .unwrap()
            .is_some_and(|s| s.id == session.id),
        "the digest resolves back to this session, and only by digest"
    );
    assert!(
        sessions
            .get_by_browser_token_hash(tenant_id, &out.browser_session_token)
            .await
            .unwrap()
            .is_none(),
        "presenting the raw value in place of its digest resolves nothing"
    );
}

// -----------------------------------------------------------------------
// SA-03 (N10, N14 server side): purpose tokens and access tokens are typed
// -----------------------------------------------------------------------

/// Log in as alice under `policy` and return whatever the login produced.
async fn login_alice_with(
    svc: &AuthService<
        SurrealUserRepository<surrealdb::engine::local::Db>,
        SurrealSessionRepository<surrealdb::engine::local::Db>,
        SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
        SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
    policy: Option<MfaPolicy>,
) -> LoginResult {
    svc.login(LoginInput {
        tenant_id,
        org_id,
        username_or_email: "alice".into(),
        password: test_password(),
        ip_address: None,
        user_agent: None,
        mfa_policy: policy,
        lockout_policy: None,
    })
    .await
    .unwrap()
}

/// The MFA setup and MFA challenge tokens are signed with the access-token
/// key. Each carries its own `typ`, neither is admitted by the access-token
/// decoders, and neither is accepted where the other is expected.
#[tokio::test]
async fn sa03_mfa_purpose_tokens_are_typed_and_are_not_access_tokens() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let setup_token = match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };
    enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    let challenge_token =
        match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
            LoginResult::MfaRequired(c) => c.challenge_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };

    for (token, typ) in [
        (&setup_token, "axiam-mfa-setup+jwt"),
        (&challenge_token, "axiam-mfa-challenge+jwt"),
    ] {
        let header = jsonwebtoken::decode_header(token).unwrap();
        assert_eq!(header.typ.as_deref(), Some(typ));
        // S-8: a purpose token names no JWKS key, so a verifier that selects
        // keys strictly by `kid` finds none for it.
        assert_eq!(header.kid, None, "{typ} token must carry no kid");
        assert!(token::validate_access_token(token, &test_config()).is_err());
        assert!(token::decode_access_token_any_audience(token, &test_config()).is_err());
    }

    // Each verifier accepts its own token and refuses the other one.
    assert!(svc.decode_setup_token(&setup_token).await.is_ok());
    assert!(svc.decode_mfa_challenge_ids(&challenge_token).await.is_ok());
    assert!(svc.decode_setup_token(&challenge_token).await.is_err());
    assert!(svc.decode_mfa_challenge_ids(&setup_token).await.is_err());
}

type TestSvc = AuthService<
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
>;

/// Whether the verifier for `purpose` admits `token`.
async fn purpose_token_accepted(svc: &TestSvc, purpose: &str, token: &str) -> bool {
    match purpose {
        "mfa_challenge" => svc.decode_mfa_challenge_ids(token).await.is_ok(),
        _ => svc.decode_setup_token(token).await.is_ok(),
    }
}

/// Sign `claims` with the test key under a header whose `typ` the test picks.
fn sign_with_typ(claims: &serde_json::Value, typ: Option<&str>) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = typ.map(str::to_owned);
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// A token typed as an access token is refused by both MFA verifiers (SA-03
/// rule 6), and so is a token with an MFA token's claims under any `typ` other
/// than the verifier's own.
///
/// A real access token carries no `purpose`, so `MfaChallengeClaims` already
/// refuses it at deserialisation; what only the `typ` check refuses is a token
/// whose claims are an MFA token's and whose header is an access token's.
/// Both halves below sign exactly that.
#[tokio::test]
async fn sa03_an_access_token_is_refused_by_the_mfa_verifiers() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let access = login_alice(&svc, tenant_id, org_id).await.access_token;
    let header = jsonwebtoken::decode_header(&access).unwrap();
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert!(header.kid.is_some(), "an access token names its key");

    // The access token's own claims, made MFA-shaped — `purpose` added, and
    // `aud` removed, since the MFA verifiers set no audience and so already
    // refuse any token that carries one — re-signed under the access token's
    // own header (`at+jwt` and its `kid`).
    let payload = access.split('.').nth(1).unwrap();
    let mut access_claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
            .unwrap(),
    )
    .unwrap();
    access_claims.as_object_mut().unwrap().remove("aud");
    for purpose in ["mfa_challenge", "mfa_setup"] {
        access_claims["purpose"] = purpose.into();
        let forged = jsonwebtoken::encode(
            &header,
            &access_claims,
            &jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let accepted = purpose_token_accepted(&svc, purpose, &forged).await;
        assert!(
            !accepted,
            "{purpose} verifier accepted an at+jwt access token carrying purpose"
        );
    }

    let now = Utc::now().timestamp();
    for (purpose, own_typ) in [
        ("mfa_challenge", "axiam-mfa-challenge+jwt"),
        ("mfa_setup", "axiam-mfa-setup+jwt"),
    ] {
        let claims = serde_json::json!({
            "sub": user_id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "org_id": org_id.to_string(),
            "purpose": purpose,
            "iss": "axiam-test",
            "iat": now,
            "exp": now + 300,
        });
        for typ in [Some("at+jwt"), Some("JWT"), None] {
            assert!(
                !purpose_token_accepted(&svc, purpose, &sign_with_typ(&claims, typ)).await,
                "{purpose} verifier accepted typ {typ:?}"
            );
        }
        assert!(
            purpose_token_accepted(&svc, purpose, &sign_with_typ(&claims, Some(own_typ))).await
        );
    }
}

// -----------------------------------------------------------------------
// SA-06 (N7; S-6): MFA purpose tokens do not survive a credential change
// -----------------------------------------------------------------------

/// A reset: the same write `PasswordResetService::confirm_reset` makes.
async fn reset_alices_password(
    users: &SurrealUserRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
) {
    users
        .update(
            tenant_id,
            user_id,
            axiam_core::models::user::UpdateUser {
                password_hash: Some(
                    axiam_auth::password::hash_password("A-brand-new-Passw0rd!", None).unwrap(),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// S-6: an MFA setup token issued before a reset is refused after it, by every
/// path that takes one, with the answer an invalid token gets.
#[tokio::test]
async fn s6_an_mfa_setup_token_issued_before_a_reset_is_refused_after_it() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let setup_token = match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };
    // Control: before any reset the token is good (and a user with no epoch is
    // unaffected).
    assert!(svc.decode_setup_token(&setup_token).await.is_ok());

    reset_alices_password(&users, tenant_id, user_id).await;

    let invalid = |e: axiam_core::error::AxiamError| {
        assert!(
            matches!(
                &e,
                axiam_core::error::AxiamError::AuthenticationFailed { .. }
            ),
            "expected the invalid-token answer, got {e:?}"
        );
    };
    invalid(svc.decode_setup_token(&setup_token).await.unwrap_err());
    invalid(
        svc.enroll_mfa_with_setup_token(&setup_token)
            .await
            .unwrap_err(),
    );
    invalid(
        svc.confirm_mfa_with_setup_token(&setup_token, "000000", None, None)
            .await
            .unwrap_err(),
    );
    // Nothing was enrolled behind the refusal.
    assert!(
        !users
            .get_by_id(tenant_id, user_id)
            .await
            .unwrap()
            .mfa_enabled
    );
}

/// S-6: the same for an MFA challenge token, at verification and at the
/// WebAuthn entry that reads its ids.
#[tokio::test]
async fn s6_an_mfa_challenge_token_issued_before_a_reset_is_refused_after_it() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let totp = enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    let challenge_token =
        match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
            LoginResult::MfaRequired(c) => c.challenge_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };
    assert!(svc.decode_mfa_challenge_ids(&challenge_token).await.is_ok());

    reset_alices_password(&users, tenant_id, user_id).await;

    assert!(
        svc.decode_mfa_challenge_ids(&challenge_token)
            .await
            .is_err()
    );
    let code = totp.generate_current().to_string();
    let err = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token: challenge_token.clone(),
            totp_code: code,
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(
            &err,
            axiam_core::error::AxiamError::AuthenticationFailed { .. }
        ),
        "expected the invalid-token answer, got {err:?}"
    );
}

/// SR3-1: put the user's credential epoch an hour in the past, leaving the
/// credential version where the reset moved it. This is the state the race
/// leaves behind: the epoch the reset stamped (bound before its transaction
/// committed) is *older* than an artefact that was nonetheless built from the
/// credential the reset replaced, so the timestamp comparison alone accepts it.
async fn rewind_the_epoch_before_the_artefact(
    db: &Surreal<surrealdb::engine::local::Db>,
    users: &SurrealUserRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
) {
    db.query("UPDATE type::record('user', $id) SET credential_changed_at = time::now() - 1h")
        .bind(("id", user_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let epoch = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_changed_at
        .expect("the reset stamped an epoch");
    assert!(
        epoch < Utc::now() - Duration::minutes(30),
        "the timestamp check alone must now accept every artefact"
    );
}

/// SR3-1: an MFA challenge built from the credential a reset replaced is
/// refused even though its issue time is after the epoch — the case the
/// timestamp comparison alone cannot see.
#[tokio::test]
async fn sr3_1_a_challenge_built_from_the_replaced_credential_is_refused() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let totp = enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    // The login reads the old credential and mints its challenge...
    let challenge_token =
        match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
            LoginResult::MfaRequired(c) => c.challenge_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };
    // ...and the reset commits afterwards, its epoch stamped before the token.
    reset_alices_password(&users, tenant_id, user_id).await;
    rewind_the_epoch_before_the_artefact(&db, &users, tenant_id, user_id).await;

    assert!(
        svc.decode_mfa_challenge_ids(&challenge_token)
            .await
            .is_err(),
        "the challenge entry for WebAuthn must refuse it"
    );
    let err = svc
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: totp.generate_current().to_string(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .expect_err("a challenge built from the replaced credential must not verify");
    assert!(matches!(err, AxiamError::AuthenticationFailed { .. }));
}

/// SR3-1: the same for an MFA setup token.
#[tokio::test]
async fn sr3_1_a_setup_token_built_from_the_replaced_credential_is_refused() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let setup_token = match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };
    reset_alices_password(&users, tenant_id, user_id).await;
    rewind_the_epoch_before_the_artefact(&db, &users, tenant_id, user_id).await;

    assert!(svc.decode_setup_token(&setup_token).await.is_err());
    assert!(
        svc.enroll_mfa_with_setup_token(&setup_token).await.is_err(),
        "no enrolment may start from a setup token of the replaced credential"
    );
}

/// SR3-1 rolling upgrade: a challenge minted by a release that carried no
/// credential version is judged by the timestamp alone, so it survives a
/// credential change whose epoch predates it, as before.
#[tokio::test]
async fn sr3_1_a_challenge_without_a_version_falls_back_to_the_timestamp_check() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    reset_alices_password(&users, tenant_id, user_id).await;
    rewind_the_epoch_before_the_artefact(&db, &users, tenant_id, user_id).await;
    let now = Utc::now();
    let claims = serde_json::json!({
        "sub": user_id.to_string(),
        "tenant_id": tenant_id.to_string(),
        "org_id": org_id.to_string(),
        "purpose": "mfa_challenge",
        "iss": "axiam-test",
        "iat": now.timestamp(),
        "iat_ns": now.timestamp_nanos_opt().unwrap(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_with_typ(&claims, Some("axiam-mfa-challenge+jwt"));
    assert!(
        svc.decode_mfa_challenge_ids(&token).await.is_ok(),
        "an unversioned challenge issued after the epoch is accepted"
    );
}

/// SR3-2 / QR3-1: a stale MFA challenge, and one for an account that is gone,
/// are refused with exactly the answer a challenge that is not one gets: the
/// client-visible reason names no cause.
#[tokio::test]
async fn sr3_2_a_stale_challenge_is_refused_with_the_uniform_answer() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let totp = enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    let challenge_token =
        match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
            LoginResult::MfaRequired(c) => c.challenge_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };

    // The answer a forged challenge gets: a signed token that is not a
    // challenge (here, one with the wrong purpose).
    let now = Utc::now();
    let forged = sign_with_typ(
        &serde_json::json!({
            "sub": user_id.to_string(),
            "tenant_id": tenant_id.to_string(),
            "org_id": org_id.to_string(),
            "purpose": "something_else",
            "iss": "axiam-test",
            "iat": now.timestamp(),
            "exp": now.timestamp() + 300,
        }),
        Some("axiam-mfa-challenge+jwt"),
    );
    let reason_of = |e: AxiamError| match e {
        AxiamError::AuthenticationFailed { reason } => reason,
        other => panic!("expected AuthenticationFailed, got {other:?}"),
    };
    let verify = |token: String, code: String| {
        svc.verify_mfa(VerifyMfaInput {
            challenge_token: token,
            totp_code: code,
            ip_address: None,
            user_agent: None,
        })
    };
    let forged_reason = reason_of(verify(forged.clone(), "000000".into()).await.unwrap_err());
    let forged_ids_reason = reason_of(
        svc.decode_mfa_challenge_ids(&forged)
            .await
            .unwrap_err()
            .into(),
    );

    reset_alices_password(&users, tenant_id, user_id).await;

    let stale_verify = reason_of(
        verify(challenge_token.clone(), totp.generate_current().to_string())
            .await
            .unwrap_err(),
    );
    let stale_ids = reason_of(
        svc.decode_mfa_challenge_ids(&challenge_token)
            .await
            .unwrap_err()
            .into(),
    );
    assert_eq!(stale_verify, forged_reason, "verify_mfa");
    assert_eq!(stale_ids, forged_ids_reason, "decode_mfa_challenge_ids");

    // An account that is gone answers the same, not "unknown user".
    let ghost = sign_with_typ(
        &serde_json::json!({
            "sub": Uuid::new_v4().to_string(),
            "tenant_id": tenant_id.to_string(),
            "org_id": org_id.to_string(),
            "purpose": "mfa_challenge",
            "iss": "axiam-test",
            "iat": now.timestamp(),
            "iat_ns": now.timestamp_nanos_opt().unwrap(),
            "exp": now.timestamp() + 300,
        }),
        Some("axiam-mfa-challenge+jwt"),
    );
    let ghost_ids = reason_of(
        svc.decode_mfa_challenge_ids(&ghost)
            .await
            .unwrap_err()
            .into(),
    );
    assert_eq!(ghost_ids, forged_ids_reason, "unknown user");
}

/// S-6 controls: a token issued after the change (a second later, so past the
/// whole-second `iat`) is accepted, and so is a user who never had a change.
#[tokio::test]
async fn s6_a_token_issued_after_the_reset_is_accepted() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    assert!(
        users
            .get_by_id(tenant_id, user_id)
            .await
            .unwrap()
            .credential_changed_at
            .is_none(),
        "a user nobody has changed has no epoch"
    );
    reset_alices_password(&users, tenant_id, user_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;

    let setup_token = match login_alice_with_password(
        &svc,
        tenant_id,
        org_id,
        "A-brand-new-Passw0rd!",
        mfa_enforced_policy(),
    )
    .await
    {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };
    assert!(svc.decode_setup_token(&setup_token).await.is_ok());
}

/// Log in as alice with an explicit password.
async fn login_alice_with_password(
    svc: &TestSvc,
    tenant_id: Uuid,
    org_id: Uuid,
    password: &str,
    policy: Option<MfaPolicy>,
) -> LoginResult {
    svc.login(LoginInput {
        tenant_id,
        org_id,
        username_or_email: "alice".into(),
        password: password.into(),
        ip_address: None,
        user_agent: None,
        mfa_policy: policy,
        lockout_policy: None,
    })
    .await
    .unwrap()
}

// ---------------------------------------------------------------------
// QR2-6 — an MFA token minted after a credential change, within the same
// whole second, is not "issued before it".
// ---------------------------------------------------------------------

/// Set alice's stored credential epoch directly, so the comparison is
/// deterministic instead of depending on how long a login took.
async fn set_alices_epoch(
    db: &Surreal<surrealdb::engine::local::Db>,
    user_id: Uuid,
    epoch: chrono::DateTime<chrono::Utc>,
) {
    db.query("UPDATE type::record('user', $id) SET credential_changed_at = $epoch")
        .bind(("id", user_id.to_string()))
        .bind(("epoch", epoch))
        .await
        .unwrap()
        .check()
        .unwrap();
}

/// The `iat` (whole seconds) and, if the token carries it, the sub-second issue
/// time in nanoseconds (`iat_ns`) of a purpose token.
fn token_issue_time(token: &str) -> (i64, Option<i64>) {
    use base64::Engine;
    let payload = token.split('.').nth(1).unwrap();
    let json: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    (
        json["iat"].as_i64().unwrap(),
        json.get("iat_ns").and_then(serde_json::Value::as_i64),
    )
}

/// QR2-6: a challenge and a setup token issued after the epoch but in the same
/// second as it are accepted; one issued before it, in that second, is refused.
#[tokio::test]
async fn qr2_6_a_token_issued_after_the_epoch_in_the_same_second_is_accepted() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let _totp = enable_mfa_for_alice(&svc, tenant_id, user_id).await;
    let challenge_token =
        match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
            LoginResult::MfaRequired(c) => c.challenge_token,
            other => panic!("expected MfaRequired, got {other:?}"),
        };

    // The epoch is the start of the second the challenge was minted in: before
    // the token, and in its whole second.
    let (iat, iat_ns) = token_issue_time(&challenge_token);
    let epoch = chrono::DateTime::from_timestamp(iat, 0).unwrap();
    if let Some(ns) = iat_ns {
        assert!(ns > iat * 1_000_000_000, "the claim is sub-second");
    }
    set_alices_epoch(&db, user_id, epoch).await;
    assert!(
        svc.decode_mfa_challenge_ids(&challenge_token).await.is_ok(),
        "a challenge issued after the epoch, in the same second, is not stale"
    );

    // A token issued *before* the epoch, in that same second, is still refused.
    let before = match iat_ns {
        Some(ns) => chrono::DateTime::from_timestamp_nanos(ns + 1_000),
        None => chrono::DateTime::from_timestamp(iat + 1, 0).unwrap(),
    };
    set_alices_epoch(&db, user_id, before).await;
    assert!(
        svc.decode_mfa_challenge_ids(&challenge_token)
            .await
            .is_err(),
        "a challenge issued before the epoch is refused"
    );
}

/// QR2-6, the setup token: the same property.
#[tokio::test]
async fn qr2_6_a_setup_token_issued_after_the_epoch_in_the_same_second_is_accepted() {
    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, db) =
        setup().await;
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let setup_token = match login_alice_with(&svc, tenant_id, org_id, mfa_enforced_policy()).await {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };
    let (iat, iat_ns) = token_issue_time(&setup_token);
    set_alices_epoch(
        &db,
        user_id,
        chrono::DateTime::from_timestamp(iat, 0).unwrap(),
    )
    .await;
    assert!(
        svc.decode_setup_token(&setup_token).await.is_ok(),
        "a setup token issued after the epoch, in the same second, is not stale"
    );
    let before = match iat_ns {
        Some(ns) => chrono::DateTime::from_timestamp_nanos(ns + 1_000),
        None => chrono::DateTime::from_timestamp(iat + 1, 0).unwrap(),
    };
    set_alices_epoch(&db, user_id, before).await;
    assert!(svc.decode_setup_token(&setup_token).await.is_err());
}

// -----------------------------------------------------------------------
// SA-06 (N7, SR10-1) — the session write checks the credential version
// -----------------------------------------------------------------------
//
// A sign-in that verified the old credential and reaches the session write
// after a reset or change must not leave a live session and refresh token
// behind. The version read with the credential is carried into the session
// write, which refuses inside its own transaction when it is no longer the
// user's.

/// A password write between the credential read and the session write
/// (what a reset or change does) leaves no session behind, and the sign-in is
/// answered as a wrong password is.
#[tokio::test]
async fn sr10_1_a_credential_change_after_the_read_leaves_no_session() {
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    // The snapshot a login holds after it verified the (old) password.
    let snapshot = users.get_by_id(tenant_id, user_id).await.unwrap();

    // The reset lands: new hash, version bumped in the same write.
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$replaced".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let err = svc
        .complete_authenticated_login(snapshot, tenant_id, org_id, None, None, None)
        .await
        .expect_err("a sign-in built on a superseded credential must not mint a session");
    assert!(
        matches!(err, AxiamError::AuthenticationFailed { ref reason } if reason == "invalid credentials"),
        "answered exactly like a wrong password, got {err:?}"
    );
    assert!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .is_empty(),
        "no session (and so no refresh token) may exist"
    );
}

/// Control: an undisturbed sign-in still creates its session.
#[tokio::test]
async fn sr10_1_an_undisturbed_sign_in_still_creates_its_session() {
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    // A user whose version has moved before the read is still current.
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$replaced".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let snapshot = users.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(snapshot.credential_version > 0);

    let out = svc
        .complete_authenticated_login(snapshot, tenant_id, org_id, None, None, None)
        .await
        .unwrap();
    assert!(matches!(out, LoginResult::Success(_)));
    assert_eq!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The choke point itself: a stale carried version refuses, a current one (and
/// `None`, for a federated sign-in) is admitted.
#[tokio::test]
async fn sr10_1_create_session_and_tokens_refuses_only_a_stale_version() {
    use axiam_core::models::session::{Amr, AuthenticationEvidence};
    use axiam_core::repository::SessionRepository;

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let sessions = session_repo.clone();
    let users = user_repo.clone();
    let svc = AuthService::new(
        user_repo,
        session_repo,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let stale = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version;
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$replaced".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let current = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version;
    assert_ne!(stale, current);

    let mint = |v: Option<i64>| {
        svc.create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            None,
            None,
            AuthenticationEvidence::now(vec![Amr::Pwd]),
            v,
        )
    };
    let err = mint(Some(stale)).await.expect_err("stale version");
    assert!(
        matches!(err, AxiamError::AuthenticationFailed { ref reason } if reason == "invalid credentials"),
        "{err:?}"
    );
    assert!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .is_empty()
    );
    mint(Some(current)).await.expect("current version");
    mint(None).await.expect("no AXIAM credential carried");
    assert_eq!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .len(),
        2
    );
}

// -----------------------------------------------------------------------
// SA-06 (N7, SR11-1) — a reset writes the credential BEFORE it revokes
// -----------------------------------------------------------------------

/// A real session repository with two race hooks.
///
/// * `pending`: right after `invalidate_user_sessions`, lets one in-flight
///   sign-in that verified the OLD password land its session write (carrying
///   the version it read), as a concurrent login would between the reset's two
///   steps. Its outcome is recorded in `landed`.
/// * `bump_before_mint`: just before the next `create_if_credential_version`,
///   writes a new password hash for the user (what a reset or change does), so
///   the credential changes after the path's own check and before its session
///   write (SR10-1 / QR11-2).
#[derive(Clone)]
struct HookedSessionRepo {
    inner: SurrealSessionRepository<MemDb>,
    bump_before_mint: Arc<std::sync::Mutex<Option<SurrealUserRepository<MemDb>>>>,
    /// `(tenant_id, user_id, version read with the old credential)`.
    pending: Arc<std::sync::Mutex<Option<(Uuid, Uuid, i64)>>>,
    landed: Arc<std::sync::Mutex<Option<Result<(), String>>>>,
    /// SR13-1: models a SNAPSHOT read. When set, the next
    /// `create_if_credential_version` first lets a full reset commit (the
    /// credential write, then both revocations, which find nothing), and then
    /// writes the row with the unchecked `create`, which is what a transaction
    /// that read the old version would commit.
    snapshot_commit: Arc<std::sync::atomic::AtomicBool>,
}

impl SessionRepository for HookedSessionRepo {
    async fn create(&self, input: CreateSession) -> AxiamResult<Session> {
        self.inner.create(input).await
    }
    async fn create_if_credential_version(
        &self,
        input: CreateSession,
        expected_credential_version: i64,
    ) -> AxiamResult<Session> {
        let users = self.bump_before_mint.lock().unwrap().take();
        if let Some(users) = users {
            users
                .update(
                    input.tenant_id,
                    input.user_id,
                    UpdateUser {
                        password_hash: Some("$argon2id$raced".into()),
                        ..Default::default()
                    },
                )
                .await?;
            if self
                .snapshot_commit
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.inner
                    .invalidate_user_sessions(input.tenant_id, input.user_id)
                    .await?;
                return self.inner.create(input).await;
            }
        }
        self.inner
            .create_if_credential_version(input, expected_credential_version)
            .await
    }
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Session> {
        self.inner.get_by_id(tenant_id, id).await
    }
    async fn get_by_token_hash(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<Session> {
        self.inner.get_by_token_hash(tenant_id, token_hash).await
    }
    async fn get_by_browser_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<Session>> {
        self.inner
            .get_by_browser_token_hash(tenant_id, token_hash)
            .await
    }
    async fn invalidate(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.inner.invalidate(tenant_id, id).await
    }
    async fn lineage_of(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> AxiamResult<Option<axiam_core::models::session::SessionLineage>> {
        self.inner.lineage_of(tenant_id, session_id).await
    }
    async fn invalidate_lineage(
        &self,
        tenant_id: Uuid,
        lineage_id: Uuid,
        user_id: Uuid,
        except: Option<Uuid>,
    ) -> AxiamResult<u64> {
        self.inner
            .invalidate_lineage(tenant_id, lineage_id, user_id, except)
            .await
    }
    async fn consume(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<bool> {
        self.inner.consume(tenant_id, id).await
    }
    async fn consume_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<Session>> {
        self.inner
            .consume_by_token_hash(tenant_id, token_hash)
            .await
    }
    async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.inner
            .invalidate_user_sessions(tenant_id, user_id)
            .await?;
        let pending = self.pending.lock().unwrap().take();
        if let Some((t, u, version)) = pending {
            let outcome = self
                .inner
                .create_if_credential_version(
                    CreateSession {
                        tenant_id: t,
                        user_id: u,
                        token_hash: "interleaved-sign-in".into(),
                        ip_address: None,
                        user_agent: None,
                        expires_at: Utc::now() + Duration::hours(1),
                        authenticated_at: Utc::now(),
                        amr: vec![axiam_core::models::session::Amr::Pwd],
                        browser_token_hash: None,
                        lineage_id: None,
                    },
                    version,
                )
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            *self.landed.lock().unwrap() = Some(outcome);
        }
        Ok(())
    }
    async fn invalidate_user_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        keep: Uuid,
    ) -> AxiamResult<u64> {
        self.inner
            .invalidate_user_sessions_except(tenant_id, user_id, keep)
            .await
    }
    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        self.inner.cleanup_expired(tenant_id).await
    }
    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Session>> {
        self.inner.list_by_user(tenant_id, user_id).await
    }
    async fn mark_refresh_replay(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        accepted_under_grace: bool,
    ) -> AxiamResult<()> {
        self.inner
            .mark_refresh_replay(tenant_id, session_id, accepted_under_grace)
            .await
    }
}

/// A sign-in that verified the old password and reaches its session write
/// right after the reset's session revocation must not leave a live session:
/// the reset writes the credential (bumping the version) BEFORE it revokes, so
/// that write is refused; revoking first lets it through and nothing removes
/// it afterwards.
#[tokio::test]
async fn sr11_1_a_sign_in_landing_during_a_reset_leaves_no_session() {
    use axiam_auth::password_reset::PasswordResetService;
    use axiam_core::models::settings::PasswordPolicy;
    use axiam_db::repository::{
        SurrealPasswordHistoryRepository, SurrealPasswordResetTokenRepository,
    };

    let (user_repo, session_repo, fed_repo, refresh_token_repo, _org_id, tenant_id, user_id, db) =
        setup().await;
    let users = user_repo.clone();
    let sessions = session_repo.clone();
    let hook = HookedSessionRepo {
        inner: session_repo,
        bump_before_mint: Arc::new(std::sync::Mutex::new(None)),
        pending: Arc::new(std::sync::Mutex::new(None)),
        landed: Arc::new(std::sync::Mutex::new(None)),
        snapshot_commit: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let svc = PasswordResetService::new(
        user_repo,
        SurrealPasswordResetTokenRepository::new(db.clone()),
        fed_repo,
        SurrealPasswordHistoryRepository::new(db.clone()),
        hook.clone(),
        refresh_token_repo,
        Arc::new(tokio::sync::Semaphore::new(4)),
        5,
    );

    let email = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .email
        .clone();
    let (raw_token, _, _) = svc
        .initiate_reset(tenant_id, &email, 1, None)
        .await
        .unwrap()
        .unwrap();

    // The sign-in has verified the old password and holds the version it read.
    let old_version = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version;
    *hook.pending.lock().unwrap() = Some((tenant_id, user_id, old_version));

    let policy = PasswordPolicy {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_digits: true,
        require_symbols: false,
        password_history_count: 5,
        hibp_check_enabled: false,
    };
    svc.confirm_reset(
        tenant_id,
        &raw_token,
        "NewStr0ngPassword",
        &policy,
        None,
        None,
    )
    .await
    .unwrap();

    assert!(
        hook.landed.lock().unwrap().is_some(),
        "the interleaving must have been exercised"
    );
    assert!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .is_empty(),
        "no session may outlive the reset: a sign-in on the old password landed after the \
         revocation and survived (landed: {:?})",
        hook.landed.lock().unwrap()
    );
}

/// SR13-1: SurrealDB's transaction is SNAPSHOT isolation, so the in-transaction
/// version check does not abort against a concurrent credential write. Model
/// the interleaving: the sign-in read version N, a full reset (credential
/// write, then both revocations, which find no session yet) commits, and only
/// then does the session row commit. The re-check after the commit must
/// delete the row and answer as a wrong password, before any token is
/// returned; an undisturbed sign-in still gets its session.
#[tokio::test]
async fn sr13_1_a_session_committed_after_a_reset_and_its_revocations_does_not_survive() {
    use axiam_core::models::session::{Amr, AuthenticationEvidence};

    let (user_repo, session_repo, fed_repo, refresh_token_repo, org_id, tenant_id, user_id, _db) =
        setup().await;
    let users = user_repo.clone();
    let sessions = session_repo.clone();
    let hook = HookedSessionRepo {
        inner: session_repo,
        bump_before_mint: Arc::new(std::sync::Mutex::new(Some(users.clone()))),
        pending: Arc::new(std::sync::Mutex::new(None)),
        landed: Arc::new(std::sync::Mutex::new(None)),
        snapshot_commit: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let svc = AuthService::new(
        user_repo,
        hook,
        fed_repo,
        refresh_token_repo,
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let read_version = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version;
    let mint = |v: i64| {
        svc.create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            None,
            None,
            AuthenticationEvidence::now(vec![Amr::Pwd]),
            Some(v),
        )
    };

    let err = mint(read_version)
        .await
        .expect_err("a sign-in that read the old version must not get tokens");
    assert!(
        matches!(err, AxiamError::AuthenticationFailed { ref reason } if reason == "invalid credentials"),
        "{err:?}"
    );
    assert!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .is_empty(),
        "the session row (also the refresh token) must not outlive the reset"
    );

    // Control: undisturbed, a sign-in at the now-current version still lands.
    let current = users
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version;
    mint(current).await.expect("undisturbed sign-in");
    assert_eq!(
        sessions
            .list_by_user(tenant_id, user_id)
            .await
            .unwrap()
            .len(),
        1
    );
}

// -----------------------------------------------------------------------
// SA-06 (N7, QR11-2 / QR12-1) — each path's own wiring of the session-write check
// -----------------------------------------------------------------------
//
// `sr10_1_a_credential_change_after_the_read_leaves_no_session` covers the
// password path and the choke point. These cover the two second-factor paths
// this service owns (TOTP `verify_mfa`, setup-token completion): the
// credential changes right after the path's OWN check read of the user and
// before its session write, which must be refused as a wrong password is,
// leaving no session.
//
// The race is armed in the USER repository: the password is replaced right
// after the first `get_by_id` returns (the old row is what the path holds).
// A path that re-read the user just before the session write would then see
// the NEW version and pass `Some(new)`, minting a session, and fail these; a
// path that passed `None` would do the same. (The previous version bumped the
// password inside the session write, which a re-read would not have noticed.)
//
// WebAuthn second factor: the REST handler delegates the finish and the session
// write to `AuthService::complete_webauthn_second_factor`, which a ceremony
// needs an authenticator to reach from here;
// `webauthn_single_use_test.rs::
// qr11_2_webauthn_second_factor_refuses_a_credential_change_after_the_finish`
// covers it.

/// A service whose user repository changes the user's password right after
/// the path's own check read, plus the handles the tests need.
struct RaceWorld {
    /// The same database, with plain repositories (for set-up).
    plain: AuthService<
        SurrealUserRepository<MemDb>,
        SurrealSessionRepository<MemDb>,
        SurrealFederationLinkRepository<MemDb>,
        SurrealRefreshTokenRepository<MemDb>,
    >,
    /// The service under test.
    raced: AuthService<
        ReadThenBumpUserRepo<SurrealUserRepository<MemDb>>,
        SurrealSessionRepository<MemDb>,
        SurrealFederationLinkRepository<MemDb>,
        SurrealRefreshTokenRepository<MemDb>,
    >,
    sessions: SurrealSessionRepository<MemDb>,
    armed: Arc<AtomicBool>,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

impl RaceWorld {
    async fn new() -> Self {
        let (
            user_repo,
            session_repo,
            fed_repo,
            refresh_token_repo,
            org_id,
            tenant_id,
            user_id,
            _db,
        ) = setup().await;
        let sessions = session_repo.clone();
        let armed = Arc::new(AtomicBool::new(false));
        let plain = AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            fed_repo.clone(),
            refresh_token_repo.clone(),
            test_config(),
            Arc::new(tokio::sync::Semaphore::new(4)),
        );
        let raced = AuthService::new(
            ReadThenBumpUserRepo {
                inner: user_repo,
                armed: armed.clone(),
            },
            session_repo,
            fed_repo,
            refresh_token_repo,
            test_config(),
            Arc::new(tokio::sync::Semaphore::new(4)),
        );
        Self {
            plain,
            raced,
            sessions,
            armed,
            org_id,
            tenant_id,
            user_id,
        }
    }

    /// The password is replaced right after the next user read.
    fn arm_the_race(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    async fn assert_refused_as_a_wrong_password_with_no_session<T: std::fmt::Debug>(
        &self,
        outcome: AxiamResult<T>,
    ) {
        let err = outcome.expect_err("a superseded credential must not mint a session");
        assert!(
            matches!(err, AxiamError::AuthenticationFailed { ref reason } if reason == "invalid credentials"),
            "answered exactly like a wrong password, got {err:?}"
        );
        assert!(
            !self.armed.load(Ordering::SeqCst),
            "the race must have been exercised"
        );
        assert!(
            self.sessions
                .list_by_user(self.tenant_id, self.user_id)
                .await
                .unwrap()
                .is_empty(),
            "no session (and so no refresh token) may exist"
        );
    }
}

/// TOTP second step (`verify_mfa`).
#[tokio::test]
async fn qr11_2_totp_verify_mfa_refuses_a_credential_change_after_its_check() {
    let w = RaceWorld::new().await;
    let totp = enable_mfa_for_alice(&w.plain, w.tenant_id, w.user_id).await;
    let challenge_token = match w
        .plain
        .login(LoginInput {
            tenant_id: w.tenant_id,
            org_id: w.org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::MfaRequired(mfa) => mfa.challenge_token,
        other => panic!("expected MfaRequired, got {other:?}"),
    };

    w.arm_the_race();
    let outcome = w
        .raced
        .verify_mfa(VerifyMfaInput {
            challenge_token,
            totp_code: generate_next_step_code(&totp),
            ip_address: None,
            user_agent: None,
        })
        .await;
    w.assert_refused_as_a_wrong_password_with_no_session(outcome)
        .await;
}

/// Setup-token completion (`complete_setup_token_login`).
#[tokio::test]
async fn qr11_2_setup_token_completion_refuses_a_credential_change_after_its_check() {
    use axiam_core::models::session::{Amr, AuthenticationEvidence};

    let w = RaceWorld::new().await;
    let setup_token = match w
        .plain
        .login(LoginInput {
            tenant_id: w.tenant_id,
            org_id: w.org_id,
            username_or_email: "alice".into(),
            password: test_password(),
            ip_address: None,
            user_agent: None,
            mfa_policy: mfa_enforced_policy(),
            lockout_policy: None,
        })
        .await
        .unwrap()
    {
        LoginResult::MfaSetupRequired(s) => s.setup_token,
        other => panic!("expected MfaSetupRequired, got {other:?}"),
    };

    w.arm_the_race();
    let outcome = w
        .raced
        .complete_setup_token_login(
            &setup_token,
            AuthenticationEvidence::now(vec![Amr::Pwd, Amr::Otp, Amr::Mfa]),
            None,
            None,
        )
        .await;
    w.assert_refused_as_a_wrong_password_with_no_session(outcome)
        .await;
}
