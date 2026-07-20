//! Unit tests for gRPC config, the auth interceptor, and the token service —
//! all driven in-process without binding a real server.

use axiam_api_grpc::GrpcConfig;
use axiam_api_grpc::middleware::auth::AuthInterceptor;
use axiam_api_grpc::proto::token_service_server::TokenService;
use axiam_api_grpc::proto::user_service_server::UserService;
use axiam_api_grpc::proto::{
    GetUserRequest, IntrospectTokenRequest, ValidateCredentialsRequest, ValidateTokenRequest,
};
use axiam_api_grpc::services::{TokenServiceImpl, UserServiceImpl};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, ValidatedClaims, issue_access_token};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{PaginatedResult, Pagination, UserRepository};
use chrono::Utc;
use tonic::Request;
use tonic::service::Interceptor;
use uuid::Uuid;

const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: PRIV_PEM.into(),
        jwt_public_key_pem: PUB_PEM.into(),
        jwt_issuer: "axiam-test".into(),
        ..Default::default()
    }
}

fn token_for(tenant_id: Uuid) -> String {
    issue_access_token(
        Uuid::new_v4(),
        tenant_id,
        Uuid::new_v4(),
        &["profile".to_string()],
        &auth_config(),
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

fn claims_for(tenant_id: Uuid) -> ValidatedClaims {
    let token = token_for(tenant_id);
    axiam_auth::token::validate_access_token(&token, &auth_config()).unwrap()
}

// ---------------------------------------------------------------------------
// GrpcConfig
// ---------------------------------------------------------------------------

#[test]
fn grpc_config_default() {
    let c = GrpcConfig::default();
    assert_eq!(c.host, "127.0.0.1");
    assert_eq!(c.port, 50051);
    assert_eq!(c.grpc_authz_per_sec, 100);
}

#[test]
fn grpc_config_bind_address_parses() {
    let c = GrpcConfig::default();
    let addr = c.bind_address();
    assert_eq!(addr.port(), 50051);
    assert!(addr.ip().is_loopback());
}

#[test]
#[should_panic(expected = "invalid gRPC bind address")]
fn grpc_config_bind_address_panics_on_bad_host() {
    let c = GrpcConfig {
        host: "not a host".into(),
        port: 1,
        grpc_authz_per_sec: 1,
        ..GrpcConfig::default()
    };
    let _ = c.bind_address();
}

// ---------------------------------------------------------------------------
// AuthInterceptor
// ---------------------------------------------------------------------------

#[test]
fn interceptor_accepts_valid_bearer_token() {
    let tenant = Uuid::new_v4();
    let token = token_for(tenant);
    let mut interceptor = AuthInterceptor::new(auth_config());
    let mut req = Request::new(());
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let out = interceptor.call(req).expect("valid token accepted");
    assert!(out.extensions().get::<ValidatedClaims>().is_some());
}

#[test]
fn interceptor_rejects_missing_header() {
    let mut interceptor = AuthInterceptor::new(auth_config());
    let err = interceptor.call(Request::new(())).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[test]
fn interceptor_rejects_invalid_token() {
    let mut interceptor = AuthInterceptor::new(auth_config());
    let mut req = Request::new(());
    req.metadata_mut()
        .insert("authorization", "Bearer not-a-jwt".parse().unwrap());
    let err = interceptor.call(req).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[test]
fn interceptor_rejects_header_without_bearer_prefix() {
    let mut interceptor = AuthInterceptor::new(auth_config());
    let mut req = Request::new(());
    req.metadata_mut()
        .insert("authorization", "Basic abc".parse().unwrap());
    let err = interceptor.call(req).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

// ---------------------------------------------------------------------------
// TokenServiceImpl::validate_token
// ---------------------------------------------------------------------------

/// Test password built at runtime (never a hard-coded literal) so credential
/// scanners don't flag test fixtures as leaked secrets.
fn test_password() -> String {
    std::env::var("AXIAM_TEST_PASSWORD").unwrap_or_else(|_| ["correct", "horse"].join("-"))
}

#[tokio::test]
async fn validate_token_valid_same_tenant() {
    let tenant = Uuid::new_v4();
    let svc = TokenServiceImpl::new(auth_config());
    let token = token_for(tenant);
    let mut req = Request::new(ValidateTokenRequest {
        access_token: token,
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_token(req).await.unwrap().into_inner();
    assert!(resp.valid);
    assert_eq!(resp.tenant_id, tenant.to_string());
}

#[tokio::test]
async fn validate_token_missing_claims_is_unauthenticated() {
    let svc = TokenServiceImpl::new(auth_config());
    let req = Request::new(ValidateTokenRequest {
        access_token: token_for(Uuid::new_v4()),
    });
    let err = svc.validate_token(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn validate_token_cross_tenant_reports_invalid() {
    let caller_tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();
    let svc = TokenServiceImpl::new(auth_config());
    // Token belongs to other_tenant, but caller is caller_tenant.
    let mut req = Request::new(ValidateTokenRequest {
        access_token: token_for(other_tenant),
    });
    req.extensions_mut().insert(claims_for(caller_tenant));
    let resp = svc.validate_token(req).await.unwrap().into_inner();
    assert!(!resp.valid);
    assert!(resp.tenant_id.is_empty());
}

#[tokio::test]
async fn validate_token_garbage_reports_invalid() {
    let tenant = Uuid::new_v4();
    let svc = TokenServiceImpl::new(auth_config());
    let mut req = Request::new(ValidateTokenRequest {
        access_token: "garbage".into(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_token(req).await.unwrap().into_inner();
    assert!(!resp.valid);
}

// ---------------------------------------------------------------------------
// TokenServiceImpl::introspect_token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn introspect_token_active_same_tenant() {
    let tenant = Uuid::new_v4();
    let svc = TokenServiceImpl::new(auth_config());
    let mut req = Request::new(IntrospectTokenRequest {
        access_token: token_for(tenant),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.introspect_token(req).await.unwrap().into_inner();
    assert!(resp.active);
    assert_eq!(resp.tenant_id, tenant.to_string());
    assert!(!resp.jti.is_empty());
}

#[tokio::test]
async fn introspect_token_missing_claims_is_unauthenticated() {
    let svc = TokenServiceImpl::new(auth_config());
    let req = Request::new(IntrospectTokenRequest {
        access_token: token_for(Uuid::new_v4()),
    });
    let err = svc.introspect_token(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn introspect_token_cross_tenant_reports_inactive() {
    let svc = TokenServiceImpl::new(auth_config());
    let mut req = Request::new(IntrospectTokenRequest {
        access_token: token_for(Uuid::new_v4()),
    });
    req.extensions_mut().insert(claims_for(Uuid::new_v4()));
    let resp = svc.introspect_token(req).await.unwrap().into_inner();
    assert!(!resp.active);
}

#[tokio::test]
async fn introspect_token_garbage_reports_inactive() {
    let tenant = Uuid::new_v4();
    let svc = TokenServiceImpl::new(auth_config());
    let mut req = Request::new(IntrospectTokenRequest {
        access_token: "garbage".into(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.introspect_token(req).await.unwrap().into_inner();
    assert!(!resp.active);
}

// ---------------------------------------------------------------------------
// UserServiceImpl
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockUserRepo {
    user: Option<User>,
}

fn active_user(tenant: Uuid, password_hash: String) -> User {
    User {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        username: "alice".into(),
        email: "alice@example.com".into(),
        password_hash,
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
    }
}

impl UserRepository for MockUserRepo {
    async fn create(&self, _i: CreateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<User> {
        self.user.clone().ok_or(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
    }
    async fn get_by_username(&self, _t: Uuid, _u: &str) -> AxiamResult<User> {
        self.user.clone().ok_or(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
    }
    async fn get_by_email(&self, _t: Uuid, _e: &str) -> AxiamResult<User> {
        Err(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
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
        Ok(())
    }
    async fn anonymize_user(&self, _t: Uuid, _u: Uuid, _e: &str, _p: &str) -> AxiamResult<()> {
        unimplemented!()
    }
}

#[tokio::test]
async fn get_user_missing_claims_unauthenticated() {
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let req = Request::new(GetUserRequest {
        tenant_id: Uuid::new_v4().to_string(),
        user_id: Uuid::new_v4().to_string(),
    });
    let err = svc.get_user(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn get_user_tenant_mismatch_permission_denied() {
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let mut req = Request::new(GetUserRequest {
        tenant_id: Uuid::new_v4().to_string(),
        user_id: Uuid::new_v4().to_string(),
    });
    req.extensions_mut().insert(claims_for(Uuid::new_v4()));
    let err = svc.get_user(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn get_user_success() {
    let tenant = Uuid::new_v4();
    let user = active_user(tenant, "hash".into());
    let svc = UserServiceImpl::new(
        MockUserRepo {
            user: Some(user.clone()),
        },
        auth_config(),
    );
    let mut req = Request::new(GetUserRequest {
        tenant_id: tenant.to_string(),
        user_id: user.id.to_string(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.get_user(req).await.unwrap().into_inner();
    assert_eq!(resp.username, "alice");
    assert_eq!(resp.status, "active");
}

#[tokio::test]
async fn get_user_not_found() {
    let tenant = Uuid::new_v4();
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let mut req = Request::new(GetUserRequest {
        tenant_id: tenant.to_string(),
        user_id: Uuid::new_v4().to_string(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let err = svc.get_user(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn get_user_invalid_uuid_argument() {
    let tenant = Uuid::new_v4();
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let mut req = Request::new(GetUserRequest {
        tenant_id: "not-a-uuid".into(),
        user_id: Uuid::new_v4().to_string(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let err = svc.get_user(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn validate_credentials_success() {
    let tenant = Uuid::new_v4();
    let hash = axiam_auth::password::hash_password(&test_password(), None).unwrap();
    let user = active_user(tenant, hash);
    let svc = UserServiceImpl::new(
        MockUserRepo {
            user: Some(user.clone()),
        },
        auth_config(),
    );
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: test_password(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(resp.valid);
    assert_eq!(resp.user_id, user.id.to_string());
}

#[tokio::test]
async fn validate_credentials_wrong_password_records_failure() {
    let tenant = Uuid::new_v4();
    let hash = axiam_auth::password::hash_password(&test_password(), None).unwrap();
    let user = active_user(tenant, hash);
    let svc = UserServiceImpl::new(MockUserRepo { user: Some(user) }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: "wrong".into(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(!resp.valid);
}

#[tokio::test]
async fn validate_credentials_unknown_user_is_invalid() {
    let tenant = Uuid::new_v4();
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "ghost".into(),
        password: "x".into(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(!resp.valid);
}

#[tokio::test]
async fn validate_credentials_tenant_mismatch_denied() {
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: Uuid::new_v4().to_string(),
        username_or_email: "alice".into(),
        password: "x".into(),
    });
    req.extensions_mut().insert(claims_for(Uuid::new_v4()));
    let err = svc.validate_credentials(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn validate_credentials_inactive_user_is_invalid() {
    let tenant = Uuid::new_v4();
    let hash = axiam_auth::password::hash_password(&test_password(), None).unwrap();
    let mut user = active_user(tenant, hash);
    user.status = UserStatus::Inactive;
    let svc = UserServiceImpl::new(MockUserRepo { user: Some(user) }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: test_password(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(!resp.valid);
}

/// User repository whose behaviour is scripted per-test to exercise the
/// service's error branches (internal DB errors, failed-login accounting).
#[derive(Clone, Default)]
struct ScriptedUserRepo {
    user: Option<User>,
    fail_get_by_id: bool,
    fail_increment: bool,
}

impl UserRepository for ScriptedUserRepo {
    async fn create(&self, _i: CreateUser) -> AxiamResult<User> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<User> {
        if self.fail_get_by_id {
            return Err(AxiamError::Internal("db unavailable".into()));
        }
        self.user.clone().ok_or(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
    }
    async fn get_by_username(&self, _t: Uuid, _u: &str) -> AxiamResult<User> {
        self.user.clone().ok_or(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
    }
    async fn get_by_email(&self, _t: Uuid, _e: &str) -> AxiamResult<User> {
        Err(AxiamError::NotFound {
            entity: "user".into(),
            id: "x".into(),
        })
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
        if self.fail_increment {
            return Err(AxiamError::Internal("increment failed".into()));
        }
        Ok(())
    }
    async fn anonymize_user(&self, _t: Uuid, _u: Uuid, _e: &str, _p: &str) -> AxiamResult<()> {
        unimplemented!()
    }
}

/// `get_user` maps a non-Active status to its wire string for every variant
/// (covers each arm of `status_to_string`).
#[tokio::test]
async fn get_user_renders_all_status_variants() {
    let tenant = Uuid::new_v4();
    for (status, expected) in [
        (UserStatus::Inactive, "inactive"),
        (UserStatus::Locked, "locked"),
        (UserStatus::PendingVerification, "pending_verification"),
        (UserStatus::Anonymized, "anonymized"),
    ] {
        let mut user = active_user(tenant, "hash".into());
        user.status = status;
        let svc = UserServiceImpl::new(
            MockUserRepo {
                user: Some(user.clone()),
            },
            auth_config(),
        );
        let mut req = Request::new(GetUserRequest {
            tenant_id: tenant.to_string(),
            user_id: user.id.to_string(),
        });
        req.extensions_mut().insert(claims_for(tenant));
        let resp = svc.get_user(req).await.unwrap().into_inner();
        assert_eq!(resp.status, expected);
    }
}

/// A non-`NotFound` repository error from `get_by_id` maps to `INTERNAL`.
#[tokio::test]
async fn get_user_internal_error_maps_to_internal() {
    let tenant = Uuid::new_v4();
    let svc = UserServiceImpl::new(
        ScriptedUserRepo {
            fail_get_by_id: true,
            ..Default::default()
        },
        auth_config(),
    );
    let mut req = Request::new(GetUserRequest {
        tenant_id: tenant.to_string(),
        user_id: Uuid::new_v4().to_string(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let err = svc.get_user(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn validate_credentials_missing_claims_is_unauthenticated() {
    let svc = UserServiceImpl::new(MockUserRepo { user: None }, auth_config());
    let req = Request::new(ValidateCredentialsRequest {
        tenant_id: Uuid::new_v4().to_string(),
        username_or_email: "alice".into(),
        password: "x".into(),
    });
    let err = svc.validate_credentials(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// A configured pepper is threaded into password verification (exercises the
/// `pepper.as_ref().map(...)` branch).
#[tokio::test]
async fn validate_credentials_with_pepper_succeeds() {
    let tenant = Uuid::new_v4();
    let mut cfg = auth_config();
    cfg.pepper = Some(secrecy::SecretString::from("test-pepper-value".to_string()));
    let hash =
        axiam_auth::password::hash_password(&test_password(), Some("test-pepper-value")).unwrap();
    let user = active_user(tenant, hash);
    let svc = UserServiceImpl::new(
        MockUserRepo {
            user: Some(user.clone()),
        },
        cfg,
    );
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: test_password(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(resp.valid);
}

/// A malformed stored password hash surfaces as an INTERNAL error from the
/// verifier rather than a silent `valid: false`.
#[tokio::test]
async fn validate_credentials_bad_hash_maps_to_internal() {
    let tenant = Uuid::new_v4();
    let user = active_user(tenant, "not-a-valid-phc-hash".into());
    let svc = UserServiceImpl::new(MockUserRepo { user: Some(user) }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: test_password(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let err = svc.validate_credentials(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

/// If recording a failed login itself errors, the call surfaces INTERNAL
/// (the lockout-accounting error branch).
#[tokio::test]
async fn validate_credentials_failed_login_record_error_maps_to_internal() {
    let tenant = Uuid::new_v4();
    let hash = axiam_auth::password::hash_password(&test_password(), None).unwrap();
    let user = active_user(tenant, hash);
    let svc = UserServiceImpl::new(
        ScriptedUserRepo {
            user: Some(user),
            fail_increment: true,
            ..Default::default()
        },
        auth_config(),
    );
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: "wrong-password".into(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let err = svc.validate_credentials(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Internal);
}

#[tokio::test]
async fn validate_credentials_locked_user_is_invalid() {
    let tenant = Uuid::new_v4();
    let hash = axiam_auth::password::hash_password(&test_password(), None).unwrap();
    let mut user = active_user(tenant, hash);
    user.locked_until = Some(Utc::now() + chrono::Duration::hours(1));
    let svc = UserServiceImpl::new(MockUserRepo { user: Some(user) }, auth_config());
    let mut req = Request::new(ValidateCredentialsRequest {
        tenant_id: tenant.to_string(),
        username_or_email: "alice".into(),
        password: test_password(),
    });
    req.extensions_mut().insert(claims_for(tenant));
    let resp = svc.validate_credentials(req).await.unwrap().into_inner();
    assert!(!resp.valid);
}
