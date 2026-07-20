//! Integration tests for the OAuth2 `TokenService` — exercises the
//! authorization_code, client_credentials, and refresh_token grants plus
//! revocation (RFC 7009) and introspection (RFC 7662).
//!
//! All repository dependencies are replaced with in-memory mocks whose
//! behaviour is configured per-test, so no database is required.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, generate_refresh_token, hash_refresh_token, issue_access_token};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::oauth2_client::{
    AuthorizationCode, CreateAuthorizationCode, CreateOAuth2Client, CreateRefreshToken,
    OAuth2Client, RefreshToken, UpdateOAuth2Client,
};
use axiam_core::models::tenant::{CreateTenant, Tenant, TenantStatus, UpdateTenant};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    AuthorizationCodeRepository, OAuth2ClientRepository, PaginatedResult, Pagination,
    RefreshTokenRepository, TenantRepository, UserRepository,
};
use axiam_db::hash_client_secret;
use axiam_oauth2::token::{IntrospectRequest, RevokeRequest, TokenRequest, TokenService};
use chrono::Utc;
use uuid::Uuid;

const SECRET: &str = "correct-client-secret";
// RFC 7636 Appendix B PKCE test vector.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn not_found() -> AxiamError {
    AxiamError::NotFound {
        entity: "x".into(),
        id: "y".into(),
    }
}

// ---------------------------------------------------------------------------
// AuthConfig
// ---------------------------------------------------------------------------

fn test_config() -> AuthConfig {
    let private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
    let public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        pepper: None,
        min_password_length: 12,
        mfa_encryption_key: None,
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
        email_verification_grace_period_hours: 24,
        password_reset_token_expiry_hours: 1,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        jwt_encoding_key: None,
        jwt_decoding_key: None,
        hibp_breaker_threshold: 5,
        hibp_breaker_cooldown_secs: 30,
        max_concurrent_hashes: 0,
        hash_acquire_timeout_secs: 5,
    }
}

// ---------------------------------------------------------------------------
// Mock: OAuth2ClientRepository
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum ClientOutcome {
    Found(OAuth2Client),
    NotFound,
    Db,
}

#[derive(Clone)]
struct MockClientRepo(ClientOutcome);

impl OAuth2ClientRepository for MockClientRepo {
    async fn create(&self, _i: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<OAuth2Client> {
        unimplemented!()
    }
    async fn get_by_client_id(&self, _t: Uuid, _c: &str) -> AxiamResult<OAuth2Client> {
        match &self.0 {
            ClientOutcome::Found(c) => Ok(c.clone()),
            ClientOutcome::NotFound => Err(not_found()),
            ClientOutcome::Db => Err(AxiamError::Database("outage".into())),
        }
    }
    async fn update(
        &self,
        _t: Uuid,
        _i: Uuid,
        _u: UpdateOAuth2Client,
    ) -> AxiamResult<OAuth2Client> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<OAuth2Client>> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Mock: AuthorizationCodeRepository
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockCodeRepo {
    get: Option<AuthorizationCode>,
    consume_ok: bool,
}

impl MockCodeRepo {
    fn ok(code: AuthorizationCode) -> Self {
        Self {
            get: Some(code),
            consume_ok: true,
        }
    }
}

impl AuthorizationCodeRepository for MockCodeRepo {
    async fn create(&self, _i: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
        unimplemented!()
    }
    async fn get_by_hash(
        &self,
        _t: Uuid,
        _h: &str,
        _c: &str,
        _r: &str,
    ) -> AxiamResult<AuthorizationCode> {
        self.get.clone().ok_or_else(not_found)
    }
    async fn consume(
        &self,
        _t: Uuid,
        _h: &str,
        _c: &str,
        _r: &str,
    ) -> AxiamResult<AuthorizationCode> {
        if self.consume_ok {
            self.get.clone().ok_or_else(not_found)
        } else {
            Err(not_found())
        }
    }
    async fn delete_expired(&self) -> AxiamResult<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Mock: TenantRepository
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum TenantOutcome {
    Found,
    NotFound,
    Db,
}

#[derive(Clone)]
struct MockTenantRepo(TenantOutcome);

impl TenantRepository for MockTenantRepo {
    async fn create(&self, _i: CreateTenant) -> AxiamResult<Tenant> {
        unimplemented!()
    }
    async fn get_by_id(&self, id: Uuid) -> AxiamResult<Tenant> {
        match self.0 {
            TenantOutcome::Found => Ok(Tenant {
                id,
                organization_id: Uuid::new_v4(),
                name: "T".into(),
                slug: "t".into(),
                status: TenantStatus::Active,
                metadata: serde_json::Value::Null,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }),
            TenantOutcome::NotFound => Err(not_found()),
            TenantOutcome::Db => Err(AxiamError::Database("outage".into())),
        }
    }
    async fn get_by_slug(&self, _o: Uuid, _s: &str) -> AxiamResult<Tenant> {
        unimplemented!()
    }
    async fn update(&self, _i: Uuid, _u: UpdateTenant) -> AxiamResult<Tenant> {
        unimplemented!()
    }
    async fn delete(&self, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list_by_organization(
        &self,
        _o: Uuid,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<Tenant>> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Mock: RefreshTokenRepository
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Get {
    Found(RefreshToken),
    NotFound,
}

#[derive(Clone)]
enum RevokeMode {
    Ok,
    NotFound,
    Db,
}

#[derive(Clone)]
struct MockRefreshRepo {
    get: Get,
    create_ok: bool,
    revoke: RevokeMode,
}

impl MockRefreshRepo {
    fn new() -> Self {
        Self {
            get: Get::NotFound,
            create_ok: true,
            revoke: RevokeMode::Ok,
        }
    }
    fn with_get(mut self, rt: RefreshToken) -> Self {
        self.get = Get::Found(rt);
        self
    }
}

impl RefreshTokenRepository for MockRefreshRepo {
    async fn create(&self, i: CreateRefreshToken) -> AxiamResult<RefreshToken> {
        if self.create_ok {
            Ok(RefreshToken {
                id: Uuid::new_v4(),
                tenant_id: i.tenant_id,
                token_hash: i.token_hash,
                client_id: i.client_id,
                user_id: i.user_id,
                scopes: i.scopes,
                expires_at: i.expires_at,
                revoked: false,
                created_at: Utc::now(),
            })
        } else {
            Err(AxiamError::Database("create failed".into()))
        }
    }
    async fn get_by_token_hash(&self, _t: Uuid, _h: &str) -> AxiamResult<RefreshToken> {
        match &self.get {
            Get::Found(rt) => Ok(rt.clone()),
            Get::NotFound => Err(not_found()),
        }
    }
    async fn revoke(&self, _t: Uuid, _h: &str) -> AxiamResult<()> {
        match self.revoke {
            RevokeMode::Ok => Ok(()),
            RevokeMode::NotFound => Err(not_found()),
            RevokeMode::Db => Err(AxiamError::Database("revoke failed".into())),
        }
    }
    async fn revoke_all_for_client(&self, _t: Uuid, _c: &str) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn revoke_all_for_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn delete_expired(&self) -> AxiamResult<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Mock: UserRepository (only get_by_id is exercised)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockUserRepo;

impl UserRepository for MockUserRepo {
    async fn create(&self, _i: CreateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<User> {
        Ok(User {
            id,
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password_hash: "x".into(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
    async fn get_by_username(&self, _t: Uuid, _u: &str) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_email(&self, _t: Uuid, _e: &str) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _i: Uuid, _u: UpdateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn update_totp_step(&self, _t: Uuid, _i: Uuid, _s: u64) -> AxiamResult<bool> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<User>> {
        unimplemented!()
    }
    async fn increment_failed_logins(
        &self,
        _t: Uuid,
        _u: Uuid,
        _lt: u32,
        _b: i64,
        _bm: f64,
        _m: i64,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn anonymize_user(&self, _t: Uuid, _u: Uuid, _e: &str, _p: &str) -> AxiamResult<()> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn make_client(grants: &[&str], scopes: &[&str]) -> OAuth2Client {
    OAuth2Client {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        client_id: "client-1".into(),
        client_secret_hash: hash_client_secret(SECRET),
        name: "Client".into(),
        redirect_uris: vec!["https://app.example.com/cb".into()],
        grant_types: grants.iter().map(|s| s.to_string()).collect(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_auth_code(scopes: &[&str], challenge: Option<&str>) -> AuthorizationCode {
    AuthorizationCode {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        client_id: "client-1".into(),
        user_id: Uuid::new_v4(),
        code_hash: "hash".into(),
        redirect_uri: "https://app.example.com/cb".into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        code_challenge: challenge.map(String::from),
        code_challenge_method: challenge.map(|_| "S256".into()),
        nonce: None,
        expires_at: Utc::now() + chrono::Duration::minutes(10),
        used: false,
        created_at: Utc::now(),
    }
}

fn make_refresh(user_id: Option<Uuid>, client_id: &str, scopes: &[&str]) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        token_hash: "h".into(),
        client_id: client_id.into(),
        user_id,
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        expires_at: Utc::now() + chrono::Duration::days(30),
        revoked: false,
        created_at: Utc::now(),
    }
}

type Svc =
    TokenService<MockClientRepo, MockCodeRepo, MockTenantRepo, MockRefreshRepo, MockUserRepo>;

fn build(
    client: ClientOutcome,
    code: MockCodeRepo,
    tenant: TenantOutcome,
    refresh: MockRefreshRepo,
) -> Svc {
    TokenService::new(
        MockClientRepo(client),
        code,
        MockTenantRepo(tenant),
        refresh,
        MockUserRepo,
        test_config(),
        2_592_000,
    )
}

fn base_req(grant: &str) -> TokenRequest {
    TokenRequest {
        grant_type: grant.into(),
        code: None,
        redirect_uri: None,
        client_id: Some("client-1".into()),
        client_secret: Some(SECRET.into()),
        code_verifier: None,
        refresh_token: None,
        scope: None,
    }
}

fn dummy_code_repo() -> MockCodeRepo {
    MockCodeRepo {
        get: None,
        consume_ok: true,
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exchange_unsupported_grant_type() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let err = svc
        .exchange(Uuid::new_v4(), base_req("password"))
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "unsupported_grant_type");
}

// ---------------------------------------------------------------------------
// authorization_code
// ---------------------------------------------------------------------------

fn auth_code_req(verifier: Option<&str>) -> TokenRequest {
    let mut r = base_req("authorization_code");
    r.code = Some("the-code".into());
    r.redirect_uri = Some("https://app.example.com/cb".into());
    r.code_verifier = verifier.map(String::from);
    r
}

#[tokio::test]
async fn auth_code_missing_code() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = auth_code_req(None);
    req.code = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn auth_code_missing_redirect_uri() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = auth_code_req(None);
    req.redirect_uri = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn auth_code_missing_client_id() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = auth_code_req(None);
    req.client_id = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn auth_code_client_not_found() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn auth_code_client_db_outage_is_server_error() {
    let svc = build(
        ClientOutcome::Db,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

#[tokio::test]
async fn auth_code_client_not_authorized_for_grant() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "unauthorized_client"
    );
}

#[tokio::test]
async fn auth_code_missing_client_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = auth_code_req(None);
    req.client_secret = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn auth_code_wrong_client_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = auth_code_req(None);
    req.client_secret = Some("wrong".into());
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn auth_code_code_lookup_fails() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(), // get=None -> NotFound
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn auth_code_pkce_missing_verifier() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        MockCodeRepo::ok(make_auth_code(&[], Some(PKCE_CHALLENGE))),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn auth_code_pkce_wrong_verifier() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        MockCodeRepo::ok(make_auth_code(&[], Some(PKCE_CHALLENGE))),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let bad = "wrong-verifier-padded-to-forty-three-characters";
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(Some(bad)))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn auth_code_consume_fails() {
    let mut code = MockCodeRepo::ok(make_auth_code(&[], None));
    code.consume_ok = false;
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        code,
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn auth_code_tenant_not_found() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        MockCodeRepo::ok(make_auth_code(&[], None)),
        TenantOutcome::NotFound,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn auth_code_tenant_db_outage_server_error() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        MockCodeRepo::ok(make_auth_code(&[], None)),
        TenantOutcome::Db,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

#[tokio::test]
async fn auth_code_success_no_refresh_no_openid() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &["profile"])),
        MockCodeRepo::ok(make_auth_code(&["profile"], None)),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .exchange(Uuid::new_v4(), auth_code_req(None))
        .await
        .unwrap();
    assert_eq!(resp.token_type, "Bearer");
    assert!(resp.refresh_token.is_none());
    assert!(resp.id_token.is_none());
    assert_eq!(resp.scope.as_deref(), Some("profile"));
}

#[tokio::test]
async fn auth_code_success_with_pkce_refresh_and_openid() {
    let svc = build(
        ClientOutcome::Found(make_client(
            &["authorization_code", "refresh_token"],
            &["openid"],
        )),
        MockCodeRepo::ok(make_auth_code(&["openid"], Some(PKCE_CHALLENGE))),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .exchange(Uuid::new_v4(), auth_code_req(Some(PKCE_VERIFIER)))
        .await
        .unwrap();
    assert!(resp.refresh_token.is_some());
    assert!(resp.id_token.is_some());
    assert_eq!(resp.scope.as_deref(), Some("openid"));
}

#[tokio::test]
async fn auth_code_refresh_create_failure_is_server_error() {
    let mut refresh = MockRefreshRepo::new();
    refresh.create_ok = false;
    let svc = build(
        ClientOutcome::Found(make_client(
            &["authorization_code", "refresh_token"],
            &["profile"],
        )),
        MockCodeRepo::ok(make_auth_code(&["profile"], None)),
        TenantOutcome::Found,
        refresh,
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), auth_code_req(None))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

// ---------------------------------------------------------------------------
// client_credentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cc_missing_client_id() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("client_credentials");
    req.client_id = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn cc_missing_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("client_credentials");
    req.client_secret = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn cc_client_not_found() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn cc_wrong_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("client_credentials");
    req.client_secret = Some("nope".into());
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn cc_not_authorized_for_grant() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .unwrap_err()
            .error_code(),
        "unauthorized_client"
    );
}

#[tokio::test]
async fn cc_invalid_requested_scope() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("client_credentials");
    req.scope = Some("api forbidden".into());
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_scope"
    );
}

#[tokio::test]
async fn cc_tenant_not_found() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::NotFound,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn cc_success_with_requested_scope_subset() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api", "read"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("client_credentials");
    req.scope = Some("read".into());
    let resp = svc.exchange(Uuid::new_v4(), req).await.unwrap();
    assert_eq!(resp.scope.as_deref(), Some("read"));
    assert!(resp.refresh_token.is_none());
    assert!(resp.id_token.is_none());
}

#[tokio::test]
async fn cc_success_defaults_to_client_scopes() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api", "read"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .exchange(Uuid::new_v4(), base_req("client_credentials"))
        .await
        .unwrap();
    assert_eq!(resp.scope.as_deref(), Some("api read"));
}

#[tokio::test]
async fn cc_success_empty_scopes_yields_none() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .exchange(Uuid::new_v4(), base_req("client_credentials"))
        .await
        .unwrap();
    assert!(resp.scope.is_none());
}

// ---------------------------------------------------------------------------
// refresh_token
// ---------------------------------------------------------------------------

fn refresh_req(raw: &str) -> TokenRequest {
    let mut r = base_req("refresh_token");
    r.refresh_token = Some(raw.into());
    r
}

#[tokio::test]
async fn refresh_missing_token() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = base_req("refresh_token");
    req.refresh_token = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn refresh_missing_client_id() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = refresh_req("tok");
    req.client_id = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn refresh_missing_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = refresh_req("tok");
    req.client_secret = None;
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn refresh_client_not_found() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn refresh_wrong_secret() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = refresh_req("tok");
    req.client_secret = Some("bad".into());
    assert_eq!(
        svc.exchange(Uuid::new_v4(), req)
            .await
            .unwrap_err()
            .error_code(),
        "invalid_client"
    );
}

#[tokio::test]
async fn refresh_not_authorized_for_grant() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "unauthorized_client"
    );
}

#[tokio::test]
async fn refresh_token_lookup_fails() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(), // get = NotFound
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn refresh_token_client_mismatch() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(
        Some(Uuid::new_v4()),
        "other-client",
        &["openid"],
    ));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn refresh_success_user_token_with_openid() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(
        Some(Uuid::new_v4()),
        "client-1",
        &["openid"],
    ));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    let resp = svc
        .exchange(Uuid::new_v4(), refresh_req("tok"))
        .await
        .unwrap();
    assert!(resp.refresh_token.is_some());
    assert!(resp.id_token.is_some());
    assert_eq!(resp.scope.as_deref(), Some("openid"));
}

#[tokio::test]
async fn refresh_success_machine_token_no_user() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(None, "client-1", &["api"]));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    let resp = svc
        .exchange(Uuid::new_v4(), refresh_req("tok"))
        .await
        .unwrap();
    assert!(resp.refresh_token.is_some());
    assert!(resp.id_token.is_none());
    assert_eq!(resp.scope.as_deref(), Some("api"));
}

#[tokio::test]
async fn refresh_revoke_old_not_found_is_invalid_grant() {
    let mut refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
    refresh.revoke = RevokeMode::NotFound;
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_grant"
    );
}

#[tokio::test]
async fn refresh_revoke_old_db_error_is_server_error() {
    let mut refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
    refresh.revoke = RevokeMode::Db;
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

// ---------------------------------------------------------------------------
// revoke_token (RFC 7009)
// ---------------------------------------------------------------------------

fn revoke_req(token: &str) -> RevokeRequest {
    RevokeRequest {
        token: token.into(),
        token_type_hint: None,
        client_id: "client-1".into(),
        client_secret: SECRET.into(),
    }
}

#[tokio::test]
async fn revoke_client_auth_fails() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert!(
        svc.revoke_token(Uuid::new_v4(), revoke_req("t"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revoke_unknown_token_is_ok() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert!(
        svc.revoke_token(Uuid::new_v4(), revoke_req("t"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn revoke_owned_token_succeeds() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(None, "client-1", &[]));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    assert!(
        svc.revoke_token(Uuid::new_v4(), revoke_req("t"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn revoke_other_client_token_is_noop_ok() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(None, "someone-else", &[]));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    assert!(
        svc.revoke_token(Uuid::new_v4(), revoke_req("t"))
            .await
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// introspect_token (RFC 7662)
// ---------------------------------------------------------------------------

fn introspect_req(token: &str) -> IntrospectRequest {
    IntrospectRequest {
        token: token.into(),
        token_type_hint: None,
        client_id: "client-1".into(),
        client_secret: SECRET.into(),
    }
}

#[tokio::test]
async fn introspect_client_auth_fails() {
    let svc = build(
        ClientOutcome::NotFound,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert!(
        svc.introspect_token(Uuid::new_v4(), introspect_req("t"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn introspect_valid_access_token_same_tenant_active() {
    let tenant_id = Uuid::new_v4();
    let cfg = test_config();
    let token = issue_access_token(
        Uuid::new_v4(),
        tenant_id,
        Uuid::new_v4(),
        &["profile".to_string()],
        &cfg,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .introspect_token(tenant_id, introspect_req(&token))
        .await
        .unwrap();
    assert!(resp.active);
    assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
    assert!(resp.sub.is_some());
}

#[tokio::test]
async fn introspect_access_token_other_tenant_inactive() {
    let cfg = test_config();
    let token = issue_access_token(
        Uuid::new_v4(),
        Uuid::new_v4(), // token's tenant
        Uuid::new_v4(),
        &["profile".to_string()],
        &cfg,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    // Introspect under a *different* tenant.
    let resp = svc
        .introspect_token(Uuid::new_v4(), introspect_req(&token))
        .await
        .unwrap();
    assert!(!resp.active);
}

#[tokio::test]
async fn introspect_refresh_token_active() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(
        Some(Uuid::new_v4()),
        "client-1",
        &["openid"],
    ));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    // Use a non-JWT token so JWT decode fails and refresh lookup runs.
    let raw = generate_refresh_token();
    let resp = svc
        .introspect_token(Uuid::new_v4(), introspect_req(&raw))
        .await
        .unwrap();
    assert!(resp.active);
    assert_eq!(resp.token_type.as_deref(), Some("refresh_token"));
    assert_eq!(resp.scope.as_deref(), Some("openid"));
}

#[tokio::test]
async fn introspect_refresh_token_other_client_inactive() {
    let refresh = MockRefreshRepo::new().with_get(make_refresh(
        Some(Uuid::new_v4()),
        "another-client",
        &["openid"],
    ));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        refresh,
    );
    let raw = generate_refresh_token();
    let resp = svc
        .introspect_token(Uuid::new_v4(), introspect_req(&raw))
        .await
        .unwrap();
    assert!(!resp.active);
}

#[tokio::test]
async fn introspect_unknown_token_inactive() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let raw = generate_refresh_token();
    let resp = svc
        .introspect_token(Uuid::new_v4(), introspect_req(&raw))
        .await
        .unwrap();
    assert!(!resp.active);
}

// ---------------------------------------------------------------------------
// OAuth2Error helpers (error.rs)
// ---------------------------------------------------------------------------

#[test]
fn error_codes_and_descriptions() {
    use axiam_oauth2::error::OAuth2Error;
    let cases = [
        (OAuth2Error::InvalidRequest("m".into()), "invalid_request"),
        (
            OAuth2Error::UnauthorizedClient("m".into()),
            "unauthorized_client",
        ),
        (OAuth2Error::AccessDenied("m".into()), "access_denied"),
        (
            OAuth2Error::UnsupportedResponseType,
            "unsupported_response_type",
        ),
        (OAuth2Error::InvalidScope("m".into()), "invalid_scope"),
        (OAuth2Error::InvalidGrant("m".into()), "invalid_grant"),
        (OAuth2Error::InvalidClient("m".into()), "invalid_client"),
        (
            OAuth2Error::InvalidRedirectUri("m".into()),
            "invalid_request",
        ),
        (OAuth2Error::UnsupportedGrantType, "unsupported_grant_type"),
        (OAuth2Error::ServerError("m".into()), "server_error"),
    ];
    for (err, code) in cases {
        assert_eq!(err.error_code(), code);
        // description must never be empty and must strip the code prefix.
        let desc = err.error_description();
        assert!(!desc.is_empty());
        assert!(!desc.starts_with(&format!("{code}: ")));
    }
}

#[test]
fn error_hash_refresh_and_client_secret_are_stable() {
    // Sanity: helper hashing used across the service is deterministic.
    assert_eq!(hash_refresh_token("abc"), hash_refresh_token("abc"));
    assert_eq!(hash_client_secret("abc"), hash_client_secret("abc"));
}
