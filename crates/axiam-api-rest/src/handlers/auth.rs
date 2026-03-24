//! Authentication endpoints — login, logout, refresh, and MFA.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_auth::service::{LoginInput, RefreshInput, VerifyMfaInput};
use axiam_auth::token::issue_access_token;
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::models::certificate::DeviceAuthResponse;
use axiam_core::repository::{SettingsRepository, TenantRepository};
use axiam_db::{
    SurrealFederationLinkRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::cert_auth::CertificateAuthenticated;

type AuthSvc<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
>;

type MfaMethodSvc<C> =
    MfaMethodService<SurrealUserRepository<C>, SurrealWebauthnCredentialRepository<C>>;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub username_or_email: String,
    pub password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginSuccessResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
    pub challenge_token: String,
    pub available_methods: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RefreshRequest {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LogoutRequest {
    pub session_id: Uuid,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MfaConfirmRequest {
    pub totp_code: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MfaVerifyRequest {
    pub challenge_token: String,
    pub totp_code: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaEnrollResponse {
    pub secret_base32: String,
    pub totp_uri: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaConfirmResponse {
    pub mfa_enabled: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaSetupRequiredResponse {
    pub mfa_setup_required: bool,
    pub setup_token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MfaSetupEnrollRequest {
    pub setup_token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MfaSetupConfirmRequest {
    pub setup_token: String,
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
#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginSuccessResponse),
        (status = 202, description = "MFA challenge required", body = MfaRequiredResponse),
        (status = 403, description = "MFA setup required", body = MfaSetupRequiredResponse),
        (status = 401, description = "Invalid credentials"),
    )
)]
pub async fn login<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    mfa_svc: web::Data<MfaMethodSvc<C>>,
    settings_repo: web::Data<SurrealSettingsRepository<C>>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    // Fetch the effective MFA policy for the tenant.
    let mfa_policy = settings_repo
        .get_effective_settings(b.org_id, b.tenant_id)
        .await
        .ok()
        .map(|s| s.mfa);

    let input = LoginInput {
        tenant_id: b.tenant_id,
        org_id: b.org_id,
        username_or_email: b.username_or_email,
        password: b.password,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
        mfa_policy,
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
        axiam_auth::LoginResult::MfaRequired(mut challenge) => {
            // Decode user/tenant from challenge to look up available methods.
            if let Ok((user_id, tenant_id, _org_id)) =
                svc.decode_mfa_challenge_ids(&challenge.challenge_token)
                && let Ok(types) = mfa_svc.available_method_types(tenant_id, user_id).await
            {
                challenge.available_methods = types;
            }
            Ok(HttpResponse::Accepted().json(MfaRequiredResponse {
                mfa_required: true,
                challenge_token: challenge.challenge_token,
                available_methods: challenge.available_methods,
            }))
        }
        axiam_auth::LoginResult::MfaSetupRequired(setup) => {
            Ok(HttpResponse::Forbidden().json(MfaSetupRequiredResponse {
                mfa_setup_required: true,
                setup_token: setup.setup_token,
            }))
        }
    }
}

/// `POST /auth/logout`
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    request_body = LogoutRequest,
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn logout<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<LogoutRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    svc.logout(user.tenant_id, body.session_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /auth/refresh`
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens refreshed", body = LoginSuccessResponse),
        (status = 401, description = "Invalid refresh token"),
    )
)]
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
#[utoipa::path(
    post,
    path = "/auth/mfa/enroll",
    tag = "auth",
    responses(
        (status = 200, description = "MFA enrollment initiated", body = MfaEnrollResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn enroll_mfa<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let out = svc.enroll_mfa(user.tenant_id, user.user_id).await?;
    Ok(HttpResponse::Ok().json(MfaEnrollResponse {
        secret_base32: out.secret_base32,
        totp_uri: out.totp_uri,
    }))
}

/// `POST /auth/mfa/confirm`
#[utoipa::path(
    post,
    path = "/auth/mfa/confirm",
    tag = "auth",
    request_body = MfaConfirmRequest,
    responses(
        (status = 200, description = "MFA confirmed", body = MfaConfirmResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn confirm_mfa<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<MfaConfirmRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    svc.confirm_mfa(user.tenant_id, user.user_id, &body.totp_code)
        .await?;
    Ok(HttpResponse::Ok().json(MfaConfirmResponse { mfa_enabled: true }))
}

/// `POST /auth/mfa/verify`
#[utoipa::path(
    post,
    path = "/auth/mfa/verify",
    tag = "auth",
    request_body = MfaVerifyRequest,
    responses(
        (status = 200, description = "MFA verified", body = LoginSuccessResponse),
        (status = 401, description = "Invalid TOTP code"),
    )
)]
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

/// `POST /auth/device`
///
/// Authenticate a device via its client certificate (mTLS).
/// The certificate must be bound to a service account.
#[utoipa::path(
    post,
    path = "/auth/device",
    tag = "auth",
    responses(
        (status = 200, description = "Device authenticated", body = DeviceAuthResponse),
        (status = 401, description = "Invalid or missing certificate"),
        (status = 403, description = "Certificate not bound to a service account"),
    )
)]
pub async fn device_auth<C: Connection>(
    req: HttpRequest,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    auth_config: web::Data<AuthConfig>,
) -> Result<HttpResponse, AxiamApiError> {
    let cert_auth = CertificateAuthenticated::extract::<C>(&req).await?;

    // Resolve org_id from the tenant
    let tenant = tenant_repo.get_by_id(cert_auth.tenant_id).await?;

    // TODO(T15): Introduce a dedicated service-account token with `sub_kind: "ServiceAccount"`
    // so downstream handlers/audit can distinguish SA tokens from user tokens.
    // For now, reuse the user token shape; `sub` contains the service_account_id.
    let access_token = issue_access_token(
        cert_auth.service_account_id,
        cert_auth.tenant_id,
        tenant.organization_id,
        &[],
        &auth_config,
    )
    .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok().json(DeviceAuthResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: auth_config.access_token_lifetime_secs,
    }))
}

/// `POST /auth/mfa/setup/enroll`
///
/// Start MFA enrollment using a setup token (issued during login when
/// MFA is enforced but not yet configured).
#[utoipa::path(
    post,
    path = "/auth/mfa/setup/enroll",
    tag = "auth",
    request_body = MfaSetupEnrollRequest,
    responses(
        (status = 200, description = "MFA enrollment initiated", body = MfaEnrollResponse),
        (status = 403, description = "Invalid or expired setup token"),
    )
)]
pub async fn setup_enroll_mfa<C: Connection>(
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<MfaSetupEnrollRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let out = svc.enroll_mfa_with_setup_token(&body.setup_token).await?;
    Ok(HttpResponse::Ok().json(MfaEnrollResponse {
        secret_base32: out.secret_base32,
        totp_uri: out.totp_uri,
    }))
}

/// `POST /auth/mfa/setup/confirm`
///
/// Confirm MFA enrollment and complete login using a setup token.
#[utoipa::path(
    post,
    path = "/auth/mfa/setup/confirm",
    tag = "auth",
    request_body = MfaSetupConfirmRequest,
    responses(
        (status = 200, description = "MFA confirmed, login complete",
         body = LoginSuccessResponse),
        (status = 403, description = "Invalid or expired setup token"),
        (status = 401, description = "Invalid TOTP code"),
    )
)]
pub async fn setup_confirm_mfa<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    body: web::Json<MfaSetupConfirmRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let out = svc
        .confirm_mfa_with_setup_token(
            &b.setup_token,
            &b.totp_code,
            client_ip(&req),
            user_agent(&req),
        )
        .await?;

    Ok(HttpResponse::Ok().json(LoginSuccessResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        session_id: out.session_id,
        expires_in: out.expires_in,
    }))
}

/// `POST /api/v1/users/{user_id}/reset-mfa`
///
/// Reset MFA for a user — disables MFA, clears the secret, and
/// revokes all existing sessions. Requires admin access (caller must
/// be in the same tenant).
#[utoipa::path(
    post,
    path = "/api/v1/users/{user_id}/reset-mfa",
    tag = "users",
    params(
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses(
        (status = 204, description = "MFA reset successful"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden — cross-tenant access"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn reset_mfa<C: Connection>(
    caller: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_user_id = path.into_inner();

    // Prevent users from resetting their own MFA through the admin
    // endpoint — self-service MFA management uses the regular
    // enroll/confirm flow.
    if target_user_id == caller.user_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "use the self-service MFA flow to manage your own MFA".into(),
            },
        ));
    }

    svc.reset_mfa(caller.tenant_id, target_user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
