//! Authentication endpoints — login, logout, refresh, and MFA.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_auth::service::{LoginInput, LoginOutput, RefreshInput, VerifyMfaInput};
use axiam_auth::token::{issue_access_token, validate_access_token};
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::DeviceAuthResponse;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, RoleRepository, SettingsRepository,
    TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository,
    SurrealPasswordHistoryRepository, SurrealPermissionRepository, SurrealRefreshTokenRepository,
    SurrealRoleRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::cert_auth::CertificateAuthenticated;
use crate::middleware::csrf::{
    access_cookie, clear_access_cookie, clear_csrf_cookie, clear_refresh_cookie, csrf_cookie,
    generate_csrf_token, refresh_cookie,
};

type AuthSvc<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealRefreshTokenRepository<C>,
>;

type MfaMethodSvc<C> =
    MfaMethodService<SurrealUserRepository<C>, SurrealWebauthnCredentialRepository<C>>;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub org_id: Option<Uuid>,
    #[serde(default)]
    pub tenant_slug: Option<String>,
    #[serde(default)]
    pub org_slug: Option<String>,
    #[serde(alias = "username")]
    pub username_or_email: String,
    pub password: String,
}

/// User info included in login/me responses.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginUserInfo {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

/// Login success response body.
///
/// Tokens are delivered via `Set-Cookie` headers — not in this body.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginSuccessResponse {
    pub user: LoginUserInfo,
    pub session_id: Uuid,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaRequiredResponse {
    pub mfa_required: bool,
    pub challenge_token: String,
    pub available_methods: Vec<String>,
}

/// Refresh success response body.
///
/// The new access token is delivered via `Set-Cookie` headers.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RefreshSuccessResponse {
    pub expires_in: u64,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RefreshRequest {
    pub tenant_id: Uuid,
    pub org_id: Uuid,
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

/// GET /api/v1/auth/me response body.
///
/// `permissions` contains the caller's effective permission action strings
/// (deduplicated, sorted). If the caller has the `super-admin` role, the
/// array is prefixed with `"*"` so clients can short-circuit fine-grained
/// checks. Empty array means the user has no assigned roles.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeResponse {
    pub user: LoginUserInfo,
    pub permissions: Vec<String>,
}

/// Request body for `POST /api/v1/auth/password/change`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
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

/// Build an `HttpResponse` that sets all three auth cookies and returns
/// the `LoginSuccessResponse` body. A fresh CSRF token is generated on
/// every call (D-02 — new CSRF token on login and refresh rotation).
async fn cookie_response_from_output<C: Connection>(
    out: &LoginOutput,
    config: &AuthConfig,
    user_repo: &SurrealUserRepository<C>,
) -> Result<HttpResponse, AxiamApiError> {
    // Decode the just-issued access token to get user_id.
    let claims = validate_access_token(&out.access_token, config).map_err(AxiamError::from)?;
    let user_id = Uuid::parse_str(&claims.0.sub).map_err(|_| AxiamError::AuthenticationFailed {
        reason: "invalid sub in issued token".into(),
    })?;
    let tenant_id =
        Uuid::parse_str(&claims.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id in issued token".into(),
        })?;

    let user = user_repo.get_by_id(tenant_id, user_id).await.map_err(|_| {
        AxiamError::AuthenticationFailed {
            reason: "user not found after login".into(),
        }
    })?;

    let csrf_token = generate_csrf_token();
    Ok(HttpResponse::Ok()
        .cookie(access_cookie(
            &out.access_token,
            config.access_token_lifetime_secs,
        ))
        .cookie(refresh_cookie(
            &out.refresh_token,
            config.refresh_token_lifetime_secs,
        ))
        .cookie(csrf_cookie(&csrf_token, config.access_token_lifetime_secs))
        .json(LoginSuccessResponse {
            user: LoginUserInfo {
                id: user.id,
                username: user.username,
                email: user.email,
            },
            session_id: out.session_id,
            expires_in: out.expires_in,
        }))
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/auth/login`
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginSuccessResponse),
        (status = 202, description = "MFA challenge required", body = MfaRequiredResponse),
        (status = 403, description = "MFA setup required", body = MfaSetupRequiredResponse),
        (status = 401, description = "Invalid credentials"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn login<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    mfa_svc: web::Data<MfaMethodSvc<C>>,
    settings_repo: web::Data<SurrealSettingsRepository<C>>,
    user_repo: web::Data<SurrealUserRepository<C>>,
    org_repo: web::Data<SurrealOrganizationRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    auth_config: web::Data<AuthConfig>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    // Resolve workspace identity — accept either UUIDs or slugs. Slug-resolution
    // failures are deliberately mapped to AuthenticationFailed (401) to avoid
    // disclosing whether an organization or tenant with a given slug exists.
    let org_id = match (b.org_id, b.org_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid credentials".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide org_id or org_slug".into(),
            }));
        }
    };
    let tenant_id = match (b.tenant_id, b.tenant_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid credentials".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide tenant_id or tenant_slug".into(),
            }));
        }
    };

    // Fetch the effective MFA policy for the tenant.
    // Propagate errors instead of silently falling back to no-enforcement,
    // which could bypass MFA during DB outages.
    let mfa_policy = Some(
        settings_repo
            .get_effective_settings(org_id, tenant_id)
            .await
            .map(|s| s.mfa)?,
    );

    let input = LoginInput {
        tenant_id,
        org_id,
        username_or_email: b.username_or_email,
        password: b.password,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
        mfa_policy,
    };

    let result = svc.login(input).await?;

    match result {
        axiam_auth::LoginResult::Success(out) => {
            cookie_response_from_output(&out, &auth_config, &user_repo).await
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

/// `POST /api/v1/auth/logout`
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
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
    Ok(HttpResponse::NoContent()
        .cookie(clear_access_cookie())
        .cookie(clear_refresh_cookie())
        .cookie(clear_csrf_cookie())
        .finish())
}

/// `POST /api/v1/auth/refresh`
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens refreshed", body = RefreshSuccessResponse),
        (status = 401, description = "Invalid refresh token"),
    )
)]
pub async fn refresh<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    auth_config: web::Data<AuthConfig>,
    body: web::Json<RefreshRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    // Refresh token must come from the httpOnly cookie.
    let raw_refresh_token = req
        .cookie("axiam_refresh")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| AxiamError::AuthenticationFailed {
            reason: "missing refresh token cookie".into(),
        })?;

    let input = RefreshInput {
        tenant_id: b.tenant_id,
        org_id: b.org_id,
        raw_refresh_token,
        ip_address: client_ip(&req),
        user_agent: user_agent(&req),
    };

    let out = svc.refresh(input).await?;

    // Issue a new CSRF token on every refresh rotation (D-02).
    let csrf_token = generate_csrf_token();
    Ok(HttpResponse::Ok()
        .cookie(access_cookie(
            &out.access_token,
            auth_config.access_token_lifetime_secs,
        ))
        .cookie(refresh_cookie(
            &out.refresh_token,
            auth_config.refresh_token_lifetime_secs,
        ))
        .cookie(csrf_cookie(
            &csrf_token,
            auth_config.access_token_lifetime_secs,
        ))
        .json(RefreshSuccessResponse {
            expires_in: out.expires_in,
        }))
}

/// `POST /api/v1/auth/mfa/enroll`
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/enroll",
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

/// `POST /api/v1/auth/mfa/confirm`
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/confirm",
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

/// `POST /api/v1/auth/mfa/verify`
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/verify",
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
    user_repo: web::Data<SurrealUserRepository<C>>,
    auth_config: web::Data<AuthConfig>,
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
    cookie_response_from_output(&out, &auth_config, &user_repo).await
}

/// `POST /api/v1/auth/device`
///
/// Authenticate a device via its client certificate (mTLS).
/// The certificate must be bound to a service account.
#[utoipa::path(
    post,
    path = "/api/v1/auth/device",
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
    // Service-account/device auth has no session row — use random jti.
    let access_token = issue_access_token(
        cert_auth.service_account_id,
        cert_auth.tenant_id,
        tenant.organization_id,
        &[],
        &auth_config,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok().json(DeviceAuthResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: auth_config.access_token_lifetime_secs,
    }))
}

/// `POST /api/v1/auth/mfa/setup/enroll`
///
/// Start MFA enrollment using a setup token (issued during login when
/// MFA is enforced but not yet configured).
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/setup/enroll",
    tag = "auth",
    request_body = MfaSetupEnrollRequest,
    responses(
        (status = 200, description = "MFA enrollment initiated", body = MfaEnrollResponse),
        (status = 401, description = "Invalid or expired setup token"),
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

/// `POST /api/v1/auth/mfa/setup/confirm`
///
/// Confirm MFA enrollment and complete login using a setup token.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/setup/confirm",
    tag = "auth",
    request_body = MfaSetupConfirmRequest,
    responses(
        (status = 200, description = "MFA confirmed, login complete",
         body = LoginSuccessResponse),
        (status = 401, description = "Invalid or expired setup token / TOTP code"),
    )
)]
pub async fn setup_confirm_mfa<C: Connection>(
    req: HttpRequest,
    svc: web::Data<AuthSvc<C>>,
    user_repo: web::Data<SurrealUserRepository<C>>,
    auth_config: web::Data<AuthConfig>,
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

    cookie_response_from_output(&out, &auth_config, &user_repo).await
}

/// `GET /api/v1/auth/me`
///
/// Returns the authenticated user's profile. Requires a valid session cookie.
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Authenticated user info", body = MeResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn me<C: Connection>(
    user: AuthenticatedUser,
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    permission_repo: web::Data<SurrealPermissionRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let u = user_repo
        .get_by_id(user.tenant_id, user.user_id)
        .await
        .map_err(|_| AxiamError::AuthenticationFailed {
            reason: "user not found".into(),
        })?;

    // Effective permissions = union of action strings across every role
    // assigned to the user (direct + via group membership). `get_user_roles`
    // handles both sources, so we don't need a separate group lookup here.
    let roles = role_repo
        .get_user_roles(user.tenant_id, user.user_id)
        .await?;

    let mut actions: BTreeSet<String> = BTreeSet::new();
    let mut is_super_admin = false;
    for role in &roles {
        if role.name == "super-admin" {
            is_super_admin = true;
        }
        let perms = permission_repo
            .get_role_permissions(user.tenant_id, role.id)
            .await?;
        for p in perms {
            actions.insert(p.action);
        }
    }

    let mut permissions: Vec<String> = actions.into_iter().collect();
    if is_super_admin {
        // Wildcard short-circuits client-side `can()` checks (per UI-SPEC).
        permissions.insert(0, "*".to_string());
    }

    Ok(HttpResponse::Ok().json(MeResponse {
        user: LoginUserInfo {
            id: user.user_id,
            username: u.username,
            email: u.email,
        },
        permissions,
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
    authz: AuthzData,
    svc: web::Data<AuthSvc<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_user_id = path.into_inner();
    if !is_own_resource(&caller, target_user_id) {
        RequirePermission::new("users:admin", Uuid::nil())
            .check(&caller, authz.get_ref().as_ref())
            .await?;
    }
    svc.reset_mfa(caller.tenant_id, target_user_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/auth/password/change`
///
/// Change the authenticated user's password. Requires the current password for
/// re-verification (T-04-21: guards against session-hijack pivot). On success,
/// all other sessions and OAuth2 refresh tokens are revoked; the caller's
/// current session is preserved (D-14, D-15).
///
/// Returns 204 on success, 401 on wrong current password, 422 on policy
/// violation.
#[utoipa::path(
    post,
    path = "/api/v1/auth/password/change",
    tag = "auth",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed; other sessions revoked"),
        (status = 401, description = "Wrong current password or unauthenticated"),
        (status = 422, description = "New password violates policy"),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)] // Actix DI extractors
pub async fn change_password<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
    settings_repo: web::Data<SurrealSettingsRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    history_repo: web::Data<SurrealPasswordHistoryRepository<C>>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    use axiam_core::repository::{SettingsRepository, TenantRepository};

    // DoS guard: reject oversized new-password before any crypto work.
    if body.new_password.len() > 1024 {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "new_password exceeds maximum length of 1024 bytes".into(),
        }
        .into());
    }

    // Resolve tenant to look up org_id for effective settings.
    let tenant = tenant_repo.get_by_id(user.tenant_id).await?;
    let settings = settings_repo
        .get_effective_settings(tenant.organization_id, user.tenant_id)
        .await?;

    svc.change_password(
        user.tenant_id,
        user.user_id,
        user.session_id,
        &body.current_password,
        &body.new_password,
        &settings.password,
        history_repo.as_ref(),
    )
    .await?;

    Ok(HttpResponse::NoContent().finish())
}
