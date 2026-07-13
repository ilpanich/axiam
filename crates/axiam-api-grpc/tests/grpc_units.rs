//! Unit tests for gRPC config, the auth interceptor, and the token service —
//! all driven in-process without binding a real server.

use axiam_api_grpc::GrpcConfig;
use axiam_api_grpc::middleware::auth::AuthInterceptor;
use axiam_api_grpc::proto::token_service_server::TokenService;
use axiam_api_grpc::proto::{IntrospectTokenRequest, ValidateTokenRequest};
use axiam_api_grpc::services::TokenServiceImpl;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, ValidatedClaims, issue_access_token};
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
