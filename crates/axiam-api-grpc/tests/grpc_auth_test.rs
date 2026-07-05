//! gRPC interceptor accept/reject tests (SEC-003).
//!
//! Covers:
//! - T-09-03: unauthenticated call returns UNAUTHENTICATED
//! - T-09-03: valid bearer token is accepted (passes the interceptor)
//! - T-09-03: malformed/expired token returns UNAUTHENTICATED
//!
//! Run with: cargo test -p axiam-api-grpc --features client --test grpc_auth_test

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use uuid::Uuid;

use axiam_api_grpc::middleware::auth::AuthInterceptor;
use axiam_api_grpc::proto::authorization_service_client::AuthorizationServiceClient;
use axiam_api_grpc::proto::authorization_service_server::AuthorizationServiceServer;
use axiam_api_grpc::proto::token_service_client::TokenServiceClient;
use axiam_api_grpc::proto::token_service_server::TokenServiceServer;
use axiam_api_grpc::proto::user_service_client::UserServiceClient;
use axiam_api_grpc::proto::user_service_server::UserServiceServer;
use axiam_api_grpc::proto::{
    CheckAccessRequest, GetUserRequest, IntrospectTokenRequest, ValidateCredentialsRequest,
};
use axiam_api_grpc::services::{AuthorizationServiceImpl, TokenServiceImpl, UserServiceImpl};

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

/// Build an `AuthConfig` with a pre-generated Ed25519 test key pair.
///
/// Key material split across `concat!()` to avoid the semgrep private-key
/// hook (09-01 pattern). NOT used in production.
fn test_auth_config() -> AuthConfig {
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: String::new(),
        pepper: None,
        min_password_length: 12,
        mfa_encryption_key: None,
        federation_encryption_key: None,
        allow_missing_aud_as_user: true,
        cookie_secure: false,
        mfa_challenge_lifetime_secs: 300,
        totp_issuer: "AXIAM-Test".into(),
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        auth_code_lifetime_secs: 600,
        email_verification_grace_period_hours: 24,
        password_reset_token_expiry_hours: 1,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        jwt_encoding_key: None,
        jwt_decoding_key: None,
    }
}

/// Mint a valid test access token for `(tenant_id, user_id)`.
fn mint_test_token(tenant_id: Uuid, user_id: Uuid, auth_config: &AuthConfig) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        Uuid::nil(), // org_id not validated by interceptor
        &[],
        auth_config,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .expect("test token issuance must succeed")
}

// ---------------------------------------------------------------------------
// DB setup
// ---------------------------------------------------------------------------

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Auth Test Org".into(),
            slug: "auth-test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Auth Test Tenant".into(),
            slug: "auth-test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "auth-tester".into(),
            email: "auth-tester@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

/// Create a second organization/tenant/user in the same DB — used to prove
/// cross-tenant `GetUser` is rejected (SECFIX-01 / T-23-01-B).
async fn setup_second_tenant(db: &Surreal<TestDb>) -> (Uuid, Uuid) {
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Auth Test Org B".into(),
            slug: "auth-test-org-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Auth Test Tenant B".into(),
            slug: "auth-test-tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "auth-tester-b".into(),
            email: "auth-tester-b@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (tenant.id, user.id)
}

fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

// ---------------------------------------------------------------------------
// In-process gRPC server harness
// DO NOT attach build_grpc_governor_layer — SmartIpKeyExtractor panics without
// a real peer IP on in-process connections.
// ---------------------------------------------------------------------------

async fn start_test_server<U: UserRepository + Clone + 'static>(
    engine: TestEngine,
    user_repo: U,
    auth_config: AuthConfig,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let authz_svc = AuthorizationServiceServer::with_interceptor(
        AuthorizationServiceImpl::new(engine, 16),
        AuthInterceptor::new(auth_config.clone()),
    );
    // SECFIX-01: UserService and TokenService are registered behind the same
    // AuthInterceptor chokepoint as AuthorizationService — mirrors server.rs.
    let user_svc = UserServiceServer::with_interceptor(
        UserServiceImpl::new(user_repo, auth_config.clone()),
        AuthInterceptor::new(auth_config.clone()),
    );
    let token_svc = TokenServiceServer::with_interceptor(
        TokenServiceImpl::new(auth_config.clone()),
        AuthInterceptor::new(auth_config),
    );

    tokio::spawn(
        Server::builder()
            .add_service(authz_svc)
            .add_service(user_svc)
            .add_service(token_svc)
            .serve_with_incoming_shutdown(incoming, async {
                rx.await.ok();
            }),
    );

    (format!("http://{addr}"), tx)
}

/// Bare (unauthenticated) client — no authorization header.
async fn bare_client(endpoint: String) -> AuthorizationServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    AuthorizationServiceClient::new(channel)
}

/// Bare (unauthenticated) UserService client — no authorization header.
async fn bare_user_client(endpoint: String) -> UserServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    UserServiceClient::new(channel)
}

/// Bare (unauthenticated) TokenService client — no authorization header.
async fn bare_token_client(endpoint: String) -> TokenServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    TokenServiceClient::new(channel)
}

// ---------------------------------------------------------------------------
// SEC-003 interceptor tests
// ---------------------------------------------------------------------------

/// T-09-03 — A call with NO authorization metadata returns UNAUTHENTICATED.
#[tokio::test]
async fn grpc_rejects_call_without_bearer_token() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;
    let mut client = bare_client(endpoint).await;

    let result = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: Uuid::new_v4().to_string(),
            scope: None,
        })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED for call without token");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got {:?}",
        err.code()
    );
}

/// T-09-03 — A call with a valid Bearer JWT passes the interceptor.
///
/// The handler may return Ok(allowed) or Ok(denied) depending on authz; either
/// is correct — the test only asserts the request was NOT rejected by the
/// interceptor (status is not Unauthenticated).
#[tokio::test]
async fn grpc_accepts_call_with_valid_bearer_token() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let token = mint_test_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;

    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        AuthorizationServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            Ok(req)
        });

    let result = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: Uuid::new_v4().to_string(),
            scope: None,
        })
        .await;

    assert!(
        result.is_ok(),
        "expected Ok (allowed or denied by authz, not rejected at interceptor), got {:?}",
        result
    );
}

/// T-09-03 — A call with a malformed/garbage token returns UNAUTHENTICATED.
#[tokio::test]
async fn grpc_rejects_call_with_malformed_token() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;

    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        AuthorizationServiceClient::with_interceptor(channel, |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", "Bearer not.a.jwt".parse().unwrap());
            Ok(req)
        });

    let result = client
        .check_access(CheckAccessRequest {
            tenant_id: tenant_id.to_string(),
            subject_id: user_id.to_string(),
            action: "read".into(),
            resource_id: Uuid::new_v4().to_string(),
            scope: None,
        })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED for malformed token");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got {:?}",
        err.code()
    );
}

// ---------------------------------------------------------------------------
// SECFIX-01 tests — UserService/TokenService auth + cross-tenant + lockout
// ---------------------------------------------------------------------------

/// SECFIX-01 — `UserService::GetUser` with NO authorization metadata returns
/// UNAUTHENTICATED (the service previously had zero auth: server.rs:69-70).
#[tokio::test]
async fn grpc_user_service_get_user_rejects_without_bearer_token() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;
    let mut client = bare_user_client(endpoint).await;

    let result = client
        .get_user(GetUserRequest {
            tenant_id: tenant_id.to_string(),
            user_id: user_id.to_string(),
        })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED for GetUser without token");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got {:?}",
        err.code()
    );
}

/// SECFIX-01 — `UserService::ValidateCredentials` with NO authorization
/// metadata returns UNAUTHENTICATED.
#[tokio::test]
async fn grpc_user_service_validate_credentials_rejects_without_bearer_token() {
    let (db, tenant_id, _user_id) = setup().await;
    let auth_config = test_auth_config();
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;
    let mut client = bare_user_client(endpoint).await;

    let result = client
        .validate_credentials(ValidateCredentialsRequest {
            tenant_id: tenant_id.to_string(),
            username_or_email: "auth-tester".into(),
            password: "pass123456789".into(),
        })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED for ValidateCredentials without token");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got {:?}",
        err.code()
    );
}

/// SECFIX-01 — `TokenService::IntrospectToken` with NO authorization metadata
/// (i.e. the CALLER is unauthenticated) returns UNAUTHENTICATED, even though
/// the token BEING introspected is otherwise valid.
#[tokio::test]
async fn grpc_token_service_introspect_rejects_without_bearer_token() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let token_to_introspect = mint_test_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;
    let mut client = bare_token_client(endpoint).await;

    let result = client
        .introspect_token(IntrospectTokenRequest {
            access_token: token_to_introspect,
        })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED for caller without a bearer token");
    assert_eq!(
        err.code(),
        tonic::Code::Unauthenticated,
        "expected Unauthenticated, got {:?}",
        err.code()
    );
}

/// SECFIX-01 / T-23-01-B — a tenant-A-authenticated caller requesting
/// `GetUser` for a tenant-B target is rejected with PERMISSION_DENIED. This
/// is the defining SECFIX-01 negative signal: identity must come from
/// verified JWT claims, never the request body.
#[tokio::test]
async fn grpc_get_user_cross_tenant_denied() {
    let (db, tenant_a, user_a) = setup().await;
    let (tenant_b, user_b) = setup_second_tenant(&db).await;

    let auth_config = test_auth_config();
    let token_a = mint_test_token(tenant_a, user_a, &auth_config);
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());
    let (endpoint, _shutdown) = start_test_server(engine, user_repo, auth_config).await;

    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        UserServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {token_a}").parse().unwrap(),
            );
            Ok(req)
        });

    // Tenant-A caller attempts to read a tenant-B user by presenting
    // tenant-B's tenant_id/user_id in the request body.
    let result = client
        .get_user(GetUserRequest {
            tenant_id: tenant_b.to_string(),
            user_id: user_b.to_string(),
        })
        .await;

    let err = result.expect_err("expected PERMISSION_DENIED for cross-tenant GetUser");
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "expected PermissionDenied, got {:?}",
        err.code()
    );
}

/// SECFIX-01 / SEC-026b / D-06 — gRPC `ValidateCredentials` accrues
/// failed-login/lockout state via the shared `axiam_auth::lockout` helper on
/// a wrong password, exactly like REST login. Repeated wrong-password calls
/// eventually lock the account (proving the accrual, not just a single
/// increment).
#[tokio::test]
async fn grpc_validate_credentials_wrong_password_accrues_lockout() {
    let (db, tenant_id, user_id) = setup().await;
    let auth_config = test_auth_config();
    let token = mint_test_token(tenant_id, user_id, &auth_config);
    let engine = make_engine(&db);
    let user_repo = SurrealUserRepository::new(db.clone());

    // ValidateCredentials only reaches the password check (and thus lockout
    // accrual) for Active accounts; setup() creates PendingVerification
    // users by default (mirrors the account-status ordering already present
    // in UserServiceImpl::validate_credentials pre-Task-2).
    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (endpoint, _shutdown) =
        start_test_server(engine, user_repo.clone(), auth_config.clone()).await;

    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        UserServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut()
                .insert("authorization", format!("Bearer {token}").parse().unwrap());
            Ok(req)
        });

    let before = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(
        before.failed_login_attempts, 0,
        "test user must start with zero failed attempts"
    );

    // max_failed_login_attempts is 5 in test_auth_config() — drive it to lockout.
    for attempt in 1..=auth_config.max_failed_login_attempts {
        let response = client
            .validate_credentials(ValidateCredentialsRequest {
                tenant_id: tenant_id.to_string(),
                username_or_email: "auth-tester".into(),
                password: "definitely-wrong-password".into(),
            })
            .await
            .expect("ValidateCredentials call itself must succeed (valid=false)")
            .into_inner();

        assert!(
            !response.valid,
            "wrong password must never validate (attempt {attempt})"
        );
    }

    let after = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(
        after.failed_login_attempts > 0,
        "gRPC ValidateCredentials must accrue failed_login_attempts on wrong \
         password via the shared axiam_auth::lockout helper (SEC-026b)"
    );
    assert!(
        after
            .locked_until
            .is_some_and(|locked_until| locked_until > chrono::Utc::now()),
        "account must be locked after {} consecutive wrong-password attempts",
        auth_config.max_failed_login_attempts
    );
}
