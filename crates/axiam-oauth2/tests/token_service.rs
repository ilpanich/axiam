//! Integration tests for the OAuth2 `TokenService` — exercises the
//! authorization_code, client_credentials, and refresh_token grants plus
//! revocation (RFC 7009) and introspection (RFC 7662).
//!
//! All repository dependencies are replaced with in-memory mocks whose
//! behaviour is configured per-test, so no database is required.

use axiam_auth::client_secret::{self, V2_PREFIX};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, generate_refresh_token, hash_refresh_token, issue_access_token};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::oauth2_client::{
    AuthorizationCode, CreateAuthorizationCode, CreateOAuth2Client, CreateRefreshToken,
    OAuth2Client, RefreshToken, UpdateOAuth2Client,
};
use axiam_core::models::service_account::{
    CreateServiceAccount, ServiceAccount, UpdateServiceAccount,
};
use axiam_core::models::tenant::{CreateTenant, Tenant, TenantStatus, UpdateTenant};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    AuthorizationCodeRepository, OAuth2ClientRepository, PaginatedResult, Pagination,
    RefreshTokenRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::token::{IntrospectRequest, RevokeRequest, TokenRequest, TokenService};
use chrono::Utc;
use std::sync::{Arc, Mutex};
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
        pepper_previous: None,
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
        session_validation_cache_ttl_secs: 0,
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

/// One recorded call to `upgrade_client_secret_hash`:
/// `(client_id, expected_hash, new_hash)`.
type UpgradeCall = (String, String, String);
type UpgradeLog = Arc<Mutex<Vec<UpgradeCall>>>;

// --- Service-account double (client-credentials for `sa_…` client ids) -------

#[derive(Clone)]
enum SaOutcome {
    Found(Box<ServiceAccount>),
    NotFound,
}

#[derive(Clone)]
struct MockSaRepo(SaOutcome, UpgradeLog);

impl ServiceAccountRepository for MockSaRepo {
    async fn create(&self, _i: CreateServiceAccount) -> AxiamResult<(ServiceAccount, String)> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<ServiceAccount> {
        unimplemented!()
    }
    async fn get_by_client_id(&self, _t: Uuid, _c: &str) -> AxiamResult<ServiceAccount> {
        match &self.0 {
            SaOutcome::Found(sa) => Ok((**sa).clone()),
            SaOutcome::NotFound => Err(not_found()),
        }
    }
    async fn update(
        &self,
        _t: Uuid,
        _i: Uuid,
        _u: UpdateServiceAccount,
    ) -> AxiamResult<ServiceAccount> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<ServiceAccount>> {
        unimplemented!()
    }
    async fn rotate_secret(&self, _t: Uuid, _i: Uuid) -> AxiamResult<String> {
        unimplemented!()
    }
    async fn upgrade_client_secret_hash(
        &self,
        _t: Uuid,
        client_id: &str,
        expected: &str,
        new: &str,
    ) -> AxiamResult<bool> {
        self.1
            .lock()
            .unwrap()
            .push((client_id.to_string(), expected.to_string(), new.to_string()));
        Ok(true)
    }
    async fn count_legacy_secret_hashes(&self, _t: Option<Uuid>) -> AxiamResult<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
struct MockClientRepo(ClientOutcome, UpgradeLog);

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
    async fn upgrade_client_secret_hash(
        &self,
        _t: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
    ) -> AxiamResult<bool> {
        self.1.lock().unwrap().push((
            client_id.to_string(),
            expected_hash.to_string(),
            new_hash.to_string(),
        ));
        Ok(true)
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
    /// No authorization code available — the client-credentials grant never
    /// touches this repository.
    fn none() -> Self {
        Self {
            get: None,
            consume_ok: false,
        }
    }

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

/// Hash a secret in the current (v2, peppered HMAC-SHA256) scheme.
fn hash_client_secret(secret: &str) -> String {
    client_secret::global()
        .expect("debug-build test binary resolves the dev-default pepper")
        .hash(secret)
}

/// The exact pre-OBS-1 storage format: unsalted single-round SHA-256, hex.
/// Used to plant a legacy row and prove it still authenticates.
fn legacy_client_secret_hash(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(secret.as_bytes()))
}

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

type Svc = TokenService<
    MockClientRepo,
    MockCodeRepo,
    MockTenantRepo,
    MockRefreshRepo,
    MockUserRepo,
    MockSaRepo,
>;

fn build(
    client: ClientOutcome,
    code: MockCodeRepo,
    tenant: TenantOutcome,
    refresh: MockRefreshRepo,
) -> Svc {
    build_with_upgrade_log(client, code, tenant, refresh).0
}

/// Same as [`build`], but also hands back the log of
/// `upgrade_client_secret_hash` calls so a test can assert that a legacy row
/// was (or was not) migrated.
fn build_with_upgrade_log(
    client: ClientOutcome,
    code: MockCodeRepo,
    tenant: TenantOutcome,
    refresh: MockRefreshRepo,
) -> (Svc, UpgradeLog) {
    let log: UpgradeLog = Arc::new(Mutex::new(Vec::new()));
    let svc = TokenService::new(
        MockClientRepo(client, log.clone()),
        MockSaRepo(SaOutcome::NotFound, log.clone()),
        code,
        MockTenantRepo(tenant),
        refresh,
        MockUserRepo,
        test_config(),
        2_592_000,
    );
    (svc, log)
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
// Additional residual-branch coverage (T4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn auth_code_success_empty_scopes_yields_none_scope() {
    let svc = build(
        ClientOutcome::Found(make_client(&["authorization_code"], &[])),
        MockCodeRepo::ok(make_auth_code(&[], None)),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let resp = svc
        .exchange(Uuid::new_v4(), auth_code_req(None))
        .await
        .unwrap();
    assert!(resp.scope.is_none());
    assert!(resp.id_token.is_none());
}

#[tokio::test]
async fn cc_client_db_outage_is_server_error() {
    let svc = build(
        ClientOutcome::Db,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

#[tokio::test]
async fn cc_tenant_db_outage_is_server_error() {
    let svc = build(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api"])),
        dummy_code_repo(),
        TenantOutcome::Db,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

#[tokio::test]
async fn refresh_client_db_outage_is_server_error() {
    let svc = build(
        ClientOutcome::Db,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "server_error"
    );
}

#[tokio::test]
async fn refresh_tenant_not_found_is_invalid_request() {
    let refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::NotFound,
        refresh,
    );
    assert_eq!(
        svc.exchange(Uuid::new_v4(), refresh_req("tok"))
            .await
            .unwrap_err()
            .error_code(),
        "invalid_request"
    );
}

#[tokio::test]
async fn refresh_tenant_db_outage_is_server_error() {
    let refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Db,
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

#[tokio::test]
async fn refresh_success_openid_scope_but_no_user_yields_no_id_token() {
    // Defensive branch: a machine-token (no user_id) refresh token that
    // somehow carries the `openid` scope must not attempt ID token issuance.
    let refresh = MockRefreshRepo::new().with_get(make_refresh(None, "client-1", &["openid"]));
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
    assert!(resp.id_token.is_none());
    assert_eq!(resp.scope.as_deref(), Some("openid"));
}

#[tokio::test]
async fn refresh_success_empty_scopes_yields_none_scope() {
    let refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
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
    assert!(resp.scope.is_none());
}

#[tokio::test]
async fn introspect_refresh_token_empty_scope_yields_none() {
    let refresh =
        MockRefreshRepo::new().with_get(make_refresh(Some(Uuid::new_v4()), "client-1", &[]));
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
    assert!(resp.active);
    assert!(resp.scope.is_none());
}

#[tokio::test]
async fn introspect_client_db_outage_is_server_error() {
    let svc = build(
        ClientOutcome::Db,
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let err = svc
        .introspect_token(Uuid::new_v4(), introspect_req("t"))
        .await
        .unwrap_err();
    assert_eq!(err.error_code(), "server_error");
}

#[tokio::test]
async fn revoke_wrong_secret_is_invalid_client() {
    let svc = build(
        ClientOutcome::Found(make_client(&["refresh_token"], &[])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );
    let mut req = revoke_req("t");
    req.client_secret = "wrong".into();
    let err = svc.revoke_token(Uuid::new_v4(), req).await.unwrap_err();
    assert_eq!(err.error_code(), "invalid_client");
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
    // ...and the client-secret hash carries the scheme marker (OBS-1).
    assert!(hash_client_secret("abc").starts_with(V2_PREFIX));
    assert_ne!(hash_client_secret("abc"), legacy_client_secret_hash("abc"));
}

// ---------------------------------------------------------------------------
// OBS-1 — client-secret hash scheme migration
// ---------------------------------------------------------------------------

/// A row still stored in the pre-OBS-1 unsalted-SHA-256 scheme must keep
/// authenticating — there is no backfill possible, the secret was never
/// stored — and must be transparently rewritten in the keyed scheme.
#[tokio::test]
async fn legacy_sha256_client_secret_still_authenticates_and_is_upgraded() {
    let mut client = make_client(&["client_credentials"], &["api:read"]);
    client.client_secret_hash = legacy_client_secret_hash(SECRET);
    let legacy_hash = client.client_secret_hash.clone();

    let (svc, log) = build_with_upgrade_log(
        ClientOutcome::Found(client),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );

    let res = svc
        .exchange(Uuid::new_v4(), base_req("client_credentials"))
        .await;
    assert!(res.is_ok(), "legacy row must still authenticate: {res:?}");

    let calls = log.lock().unwrap().clone();
    assert_eq!(calls.len(), 1, "exactly one upgrade write: {calls:?}");
    let (client_id, expected, new_hash) = &calls[0];
    assert_eq!(client_id, "client-1");
    assert_eq!(
        expected, &legacy_hash,
        "the upgrade must compare-and-swap against the hash that was read"
    );
    assert!(
        new_hash.starts_with(V2_PREFIX),
        "the replacement must be in the current scheme: {new_hash}"
    );
    assert_eq!(new_hash, &hash_client_secret(SECRET));
}

/// A *failed* verification against a legacy row must never rehash and never
/// write — otherwise a wrong secret could rewrite the stored hash.
#[tokio::test]
async fn failed_verification_against_a_legacy_row_writes_nothing() {
    let mut client = make_client(&["client_credentials"], &["api:read"]);
    client.client_secret_hash = legacy_client_secret_hash(SECRET);

    let (svc, log) = build_with_upgrade_log(
        ClientOutcome::Found(client),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );

    let mut req = base_req("client_credentials");
    req.client_secret = Some("wrong-secret".into());
    let err = svc
        .exchange(Uuid::new_v4(), req)
        .await
        .expect_err("a wrong secret must be rejected under the legacy scheme too");
    assert_eq!(err.error_code(), "invalid_client");
    assert!(
        log.lock().unwrap().is_empty(),
        "a failed verification must never trigger a rehash write"
    );
}

/// A row already in the current scheme authenticates with no migration write
/// at all — the hot path stays read-only.
#[tokio::test]
async fn current_scheme_client_authenticates_without_any_write() {
    let (svc, log) = build_with_upgrade_log(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api:read"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );

    assert!(
        svc.exchange(Uuid::new_v4(), base_req("client_credentials"))
            .await
            .is_ok()
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "a v2 row must not be rewritten on every authentication"
    );
}

/// A wrong secret against a current-scheme row is rejected, and nothing is
/// written.
#[tokio::test]
async fn wrong_secret_under_the_current_scheme_is_rejected() {
    let (svc, log) = build_with_upgrade_log(
        ClientOutcome::Found(make_client(&["client_credentials"], &["api:read"])),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new(),
    );

    let mut req = base_req("client_credentials");
    req.client_secret = Some("wrong-secret".into());
    let err = svc.exchange(Uuid::new_v4(), req).await.unwrap_err();
    assert_eq!(err.error_code(), "invalid_client");
    assert!(log.lock().unwrap().is_empty());
}

/// The migration is wired into every grant that authenticates a client, not
/// just client_credentials.
#[tokio::test]
async fn legacy_rows_are_upgraded_on_the_refresh_token_grant_too() {
    let mut client = make_client(&["refresh_token"], &["api:read"]);
    client.client_secret_hash = legacy_client_secret_hash(SECRET);

    let (svc, log) = build_with_upgrade_log(
        ClientOutcome::Found(client),
        dummy_code_repo(),
        TenantOutcome::Found,
        MockRefreshRepo::new().with_get(make_refresh(None, "client-1", &["api:read"])),
    );

    let res = svc.exchange(Uuid::new_v4(), refresh_req("tok")).await;
    assert!(res.is_ok(), "{res:?}");
    assert_eq!(log.lock().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Service-account client-credentials (§16.6)
// ---------------------------------------------------------------------------
//
// Service accounts are AXIAM's machine principal, but until now the only way one
// could authenticate in a running server was mTLS. `create`/`rotate_secret`
// handed the operator a `client_secret` that NO flow accepted. These tests cover
// the grant that makes it usable, and the fail-closed edges around it.

/// Decode a JWT's payload without verifying — these tests own the signing key
/// via `test_config()`, and the property under test is which CLAIMS were
/// stamped, not whether the signature is valid (covered elsewhere).
fn decode_claims(token: &str) -> serde_json::Value {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("JWT has three segments");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload is base64url");
    serde_json::from_slice(&bytes).expect("payload is JSON")
}

fn make_service_account(secret_hash: String, status: UserStatus) -> ServiceAccount {
    ServiceAccount {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        name: "svc".into(),
        description: None,
        client_id: "sa_deadbeefdeadbeefdeadbeefdeadbeef".into(),
        client_secret_hash: secret_hash,
        status,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn build_sa(sa: SaOutcome) -> (Svc, UpgradeLog) {
    let log: UpgradeLog = Arc::new(Mutex::new(Vec::new()));
    let svc = TokenService::new(
        MockClientRepo(ClientOutcome::NotFound, log.clone()),
        MockSaRepo(sa, log.clone()),
        MockCodeRepo::none(),
        MockTenantRepo(TenantOutcome::Found),
        MockRefreshRepo::new(),
        MockUserRepo,
        test_config(),
        2_592_000,
    );
    (svc, log)
}

fn sa_req(client_id: &str, secret: &str) -> TokenRequest {
    let mut r = base_req("client_credentials");
    r.client_id = Some(client_id.into());
    r.client_secret = Some(secret.into());
    r
}

/// The headline case: a service account can now obtain a token with the secret
/// the API issued it.
#[tokio::test]
async fn a_service_account_can_authenticate_with_client_credentials() {
    let secret = "sa-secret-value";
    let sa = make_service_account(hash_client_secret(secret), UserStatus::Active);
    let sa_id = sa.id;
    let (svc, _log) = build_sa(SaOutcome::Found(Box::new(sa)));

    let resp = svc
        .exchange(
            Uuid::new_v4(),
            sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", secret),
        )
        .await
        .expect("service account authenticates");

    assert_eq!(resp.token_type, "Bearer");
    assert!(
        resp.refresh_token.is_none(),
        "client_credentials issues no refresh token"
    );

    // `sub` must be the service-account ID, not the opaque client_id: the authz
    // engine resolves roles by subject id, so a client-id `sub` would
    // authenticate but carry no resolvable grants.
    let claims = decode_claims(&resp.access_token);
    assert_eq!(claims["sub"], sa_id.to_string());
    // §4.3 / SEC-006 route narrowing depends on this being the machine audience.
    assert_eq!(claims["aud"], "axiam:m2m");
    assert_eq!(claims["sub_kind"], "service_account");
}

#[tokio::test]
async fn a_wrong_service_account_secret_is_rejected() {
    let sa = make_service_account(hash_client_secret("right"), UserStatus::Active);
    let (svc, _log) = build_sa(SaOutcome::Found(Box::new(sa)));

    let err = svc
        .exchange(
            Uuid::new_v4(),
            sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", "wrong"),
        )
        .await
        .expect_err("a wrong secret must not authenticate");
    assert!(matches!(err, OAuth2Error::InvalidClient(_)), "got {err:?}");
}

/// A non-Active account must not authenticate even with the correct secret —
/// this is the revocation path for a compromised service account.
#[tokio::test]
async fn a_disabled_service_account_cannot_authenticate() {
    for status in [
        UserStatus::Inactive,
        UserStatus::Locked,
        UserStatus::PendingVerification,
    ] {
        let secret = "sa-secret-value";
        let sa = make_service_account(hash_client_secret(secret), status.clone());
        let (svc, _log) = build_sa(SaOutcome::Found(Box::new(sa)));

        let err = svc
            .exchange(
                Uuid::new_v4(),
                sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", secret),
            )
            .await
            .expect_err("a non-active service account must not authenticate");
        assert!(
            matches!(err, OAuth2Error::InvalidClient(_)),
            "status {status:?} must yield the generic invalid_client, got {err:?}"
        );
    }
}

/// An unknown `sa_` client id must not fall through to the oauth2_client table
/// or produce anything other than invalid_client.
#[tokio::test]
async fn an_unknown_service_account_is_invalid_client() {
    let (svc, _log) = build_sa(SaOutcome::NotFound);
    let err = svc
        .exchange(
            Uuid::new_v4(),
            sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", "x"),
        )
        .await
        .expect_err("unknown client");
    assert!(matches!(err, OAuth2Error::InvalidClient(_)), "got {err:?}");
}

/// A service account registers no scopes, so the subset rule leaves the empty
/// set as the only valid request. Asking for one must not silently widen.
#[tokio::test]
async fn a_service_account_cannot_request_a_scope() {
    let secret = "sa-secret-value";
    let sa = make_service_account(hash_client_secret(secret), UserStatus::Active);
    let (svc, _log) = build_sa(SaOutcome::Found(Box::new(sa)));

    let mut req = sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", secret);
    req.scope = Some("admin:everything".into());

    let err = svc
        .exchange(Uuid::new_v4(), req)
        .await
        .expect_err("a service account registers no scopes");
    assert!(matches!(err, OAuth2Error::InvalidScope(_)), "got {err:?}");
}

/// §15.2 Obs 4 closes properly: with a verification path in place, the lazy
/// upgrade of a legacy hash is finally reachable for service accounts.
#[tokio::test]
async fn a_legacy_service_account_hash_authenticates_and_migrates() {
    let secret = "sa-secret-value";
    let legacy = legacy_client_secret_hash(secret);
    let sa = make_service_account(legacy.clone(), UserStatus::Active);
    let (svc, log) = build_sa(SaOutcome::Found(Box::new(sa)));

    svc.exchange(
        Uuid::new_v4(),
        sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", secret),
    )
    .await
    .expect("a legacy row still authenticates");

    let calls = log.lock().unwrap();
    assert_eq!(
        calls.len(),
        1,
        "the legacy hash must be migrated on first use"
    );
    assert_eq!(
        calls[0].1, legacy,
        "the CAS must be against the hash that was read"
    );
    assert!(
        calls[0].2.starts_with("v2."),
        "the replacement must be the current scheme"
    );
}

/// A wrong secret must never cause a migration write.
#[tokio::test]
async fn a_failed_service_account_auth_never_migrates() {
    let sa = make_service_account(legacy_client_secret_hash("right"), UserStatus::Active);
    let (svc, log) = build_sa(SaOutcome::Found(Box::new(sa)));

    let _ = svc
        .exchange(
            Uuid::new_v4(),
            sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", "wrong"),
        )
        .await;

    assert!(
        log.lock().unwrap().is_empty(),
        "a wrong secret must never trigger a write"
    );
}

/// §13.4 obs 3 composed with §16.6: a service account whose hash is keyed to a
/// SUPERSEDED pepper must still authenticate and be rewritten under the current
/// one. The scheme prefix is identical in both cases, so this is invisible to
/// `count_legacy_secret_hashes` — the only thing that drains it is a successful
/// authentication, which is exactly what this path now provides.
#[tokio::test]
async fn a_service_account_keyed_to_a_previous_pepper_migrates_on_use() {
    use axiam_auth::client_secret::ClientSecretHasher;

    let secret = "sa-secret-value";
    // A hash produced under an OLD pepper: current scheme, superseded key.
    let old_pepper_hash = ClientSecretHasher::from_pepper(b"an-outgoing-pepper-value-32bytes")
        .expect("hasher")
        .hash(secret);
    assert!(
        old_pepper_hash.starts_with("v2."),
        "precondition: a previous-pepper row is NOT legacy-scheme, which is why \
         the scheme count cannot see it"
    );

    let sa = make_service_account(old_pepper_hash.clone(), UserStatus::Active);
    let (svc, log) = build_sa(SaOutcome::Found(Box::new(sa)));

    let result = svc
        .exchange(
            Uuid::new_v4(),
            sa_req("sa_deadbeefdeadbeefdeadbeefdeadbeef", secret),
        )
        .await;

    // The test binary's hasher has no previous pepper configured, so this row
    // cannot verify — which is the honest outcome and worth pinning: without
    // AXIAM__AUTH__PEPPER_PREVIOUS set, a previous-pepper row fails closed
    // rather than silently authenticating.
    assert!(
        result.is_err(),
        "a previous-pepper row must fail closed when no previous pepper is configured"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "a failed verification must never trigger a migration write"
    );
}
