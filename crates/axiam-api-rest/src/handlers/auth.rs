//! Authentication endpoints — login, logout, refresh, and MFA.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::AuthService;
use axiam_auth::service::{LoginInput, RefreshInput, VerifyMfaInput};
use axiam_db::{SurrealSessionRepository, SurrealUserRepository};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

type AuthSvc<C> = AuthService<SurrealUserRepository<C>, SurrealSessionRepository<C>>;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub username_or_email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginSuccessResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

#[derive(Debug, Serialize)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
    pub challenge_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct MfaConfirmRequest {
    pub totp_code: String,
}

#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub challenge_token: String,
    pub totp_code: String,
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
}

fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /auth/login`
pub async fn login<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let input = LoginInput {
        tenant_id: b.tenant_id,
        org_id: b.org_id,
        username_or_email: b.username_or_email,
        password: b.password,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
    };

    let result = svc.login(input).await?;

    match result {
        axiam_auth::LoginResult::Success(out) => {
            Ok(HttpResponse::Ok().json(LoginSuccessResponse {
                access_token: out.access_token,
                refresh_token: out.refresh_token,
                session_id: out.session_id,
                expires_in: out.expires_in,
            }))
        }
        axiam_auth::LoginResult::MfaRequired(challenge) => {
            Ok(HttpResponse::Ok().json(MfaRequiredResponse {
                mfa_required: true,
                challenge_token: challenge.challenge_token,
            }))
        }
    }
}

/// `POST /auth/logout`
pub async fn logout<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<LogoutRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    svc.logout(user.tenant_id, body.session_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /auth/refresh`
pub async fn refresh<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<RefreshRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let input = RefreshInput {
        tenant_id: b.tenant_id,
        org_id: b.org_id,
        raw_refresh_token: b.refresh_token,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
    };

    let out = svc.refresh(input).await?;

    Ok(HttpResponse::Ok().json(LoginSuccessResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        session_id: out.session_id,
        expires_in: out.expires_in,
    }))
}

/// `POST /auth/mfa/enroll`
pub async fn enroll_mfa<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let out = svc.enroll_mfa(user.tenant_id, user.user_id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "secret_base32": out.secret_base32,
        "totp_uri": out.totp_uri,
    })))
}

/// `POST /auth/mfa/confirm`
pub async fn confirm_mfa<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<MfaConfirmRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    svc.confirm_mfa(user.tenant_id, user.user_id, &body.totp_code)
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "mfa_enabled": true })))
}

/// `POST /auth/mfa/verify`
pub async fn verify_mfa<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<MfaVerifyRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let input = VerifyMfaInput {
        challenge_token: b.challenge_token,
        totp_code: b.totp_code,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
    };

    let out = svc.verify_mfa(input).await?;

    Ok(HttpResponse::Ok().json(LoginSuccessResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        session_id: out.session_id,
        expires_in: out.expires_in,
    }))
}
