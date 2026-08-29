//! Admin email-config endpoints for organizations and tenants (FUNC-03 / D-13).
//!
//! Six scope-nested singleton handlers (GET/PUT/DELETE for org and tenant
//! scopes), gated by `email_config:read` (GET) and `email_config:write`
//! (PUT/DELETE) per D-03, each enforcing an org/tenant ownership check
//! before touching the repository (T-28-01 IDOR mitigation).
//!
//! GET always returns the raw own-scope row (`get_org_config` /
//! `get_tenant_override`) — never the merged `get_effective_config` (D-14).
//! Secrets (`SmtpConfig.password` / `ApiProviderConfig.api_key`) never
//! appear in any response body: both `EmailConfig` and `EmailConfigOverride`
//! carry `#[serde(skip_serializing)]` secrets end-to-end (D-01, 28-01).
//!
//! PUT performs structural validation only (D-15) — no live SMTP/API
//! connectivity check is ever made at write time.

use actix_web::{HttpResponse, web};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::{
    EmailConfig, EmailConfigOverride, ProviderConfig, SetOrgEmailConfig, SetTenantEmailOverride,
    validate_email_config,
};
use axiam_core::repository::{EmailConfigRepository, UserRepository};
use axiam_db::SurrealEmailConfigRepository;
use axiam_email::message::EmailMessage;
use axiam_email::service::EmailService;
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

/// D-02 fail-closed guard: `email_config_repo` is `None` when
/// `AXIAM__EMAIL_ENCRYPTION_KEY` is unset. Every email-config handler must
/// go through this instead of unwrapping directly, preserving the
/// pre-AppState "App data is not configured" 500 behavior with a clearer
/// error path.
fn require_email_config_repo<C: Connection + Clone>(
    state: &AppState<C>,
) -> Result<&SurrealEmailConfigRepository<C>, AxiamApiError> {
    state.mail.email_config_repo.as_ref().ok_or_else(|| {
        AxiamApiError(AxiamError::Internal(
            "email configuration is disabled (AXIAM__EMAIL_ENCRYPTION_KEY not set)".into(),
        ))
    })
}

/// Structural-only validation for a tenant email-config override (D-15).
///
/// Mirrors [`validate_email_config`]'s checks but only applies them to
/// fields the caller actually supplied — `None` fields inherit from the
/// org baseline and are not validated here. No live SMTP/API connectivity
/// check is ever performed.
fn validate_email_config_override(input: &EmailConfigOverride) -> AxiamResult<()> {
    let mut violations = Vec::new();

    if let Some(ref from_email) = input.from_email
        && (from_email.is_empty() || !from_email.contains('@'))
    {
        violations.push("from_email must be a valid email address".to_string());
    }

    if let Some(ref from_name) = input.from_name
        && from_name.is_empty()
    {
        violations.push("from_name must not be empty".to_string());
    }

    if let Some(Some(ref reply_to)) = input.reply_to
        && (reply_to.is_empty() || !reply_to.contains('@'))
    {
        violations.push("reply_to must be a valid email address if provided".to_string());
    }

    if let Some(ref provider) = input.provider
        && let ProviderConfig::Smtp(smtp) = provider
    {
        if smtp.host.is_empty() {
            violations.push("SMTP host must not be empty".to_string());
        }
        if smtp.port == 0 {
            violations.push("SMTP port must be > 0".to_string());
        }
    }
    // API-provider kinds: an empty api_key is the D-02 "omit — preserve
    // stored value" sentinel, not a structural violation (mirrors
    // validate_email_config's org-level handling).

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AxiamError::Validation {
            message: format!("Invalid email config override: {}", violations.join("; ")),
        })
    }
}

// ---------------------------------------------------------------------------
// Organization scope
// ---------------------------------------------------------------------------

/// `GET /api/v1/organizations/{org_id}/email-config`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/email-config",
    tag = "email-config",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    responses(
        (status = 200, description = "Organization email configuration (secrets omitted)",
         body = EmailConfig),
        (status = 404, description = "No email configuration set for this organization"),
    ),
    security(("bearer" = []))
)]
pub async fn get_org_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot read email configuration for a different organization".into(),
            action: None,
            resource_id: None,
        }));
    }

    let repo = require_email_config_repo(&state)?;
    match repo.get_org_config(org_id).await? {
        Some(config) => Ok(HttpResponse::Ok().json(config)),
        None => Err(AxiamApiError(AxiamError::NotFound {
            entity: "email_config".into(),
            id: org_id.to_string(),
        })),
    }
}

/// `PUT /api/v1/organizations/{org_id}/email-config`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/email-config",
    tag = "email-config",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    request_body = SetOrgEmailConfig,
    responses(
        (status = 200, description = "Organization email configuration updated (secrets omitted)",
         body = EmailConfig),
    ),
    security(("bearer" = []))
)]
pub async fn set_org_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<SetOrgEmailConfig>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot modify email configuration for a different organization".into(),
            action: None,
            resource_id: None,
        }));
    }

    let input = body.into_inner();
    validate_email_config(&input)?;
    let repo = require_email_config_repo(&state)?;
    let config = repo.set_org_config(org_id, input).await?;
    Ok(HttpResponse::Ok().json(config))
}

/// `DELETE /api/v1/organizations/{org_id}/email-config`
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_id}/email-config",
    tag = "email-config",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    responses(
        (status = 204, description = "Organization email configuration deleted"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_org_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot delete email configuration for a different organization".into(),
            action: None,
            resource_id: None,
        }));
    }

    let repo = require_email_config_repo(&state)?;
    repo.delete_org_config(org_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// Tenant scope
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/email-config`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/email-config",
    tag = "email-config",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Tenant email configuration override (secrets omitted)",
         body = EmailConfigOverride),
        (status = 404, description = "No email configuration override set for this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot read email configuration for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    let repo = require_email_config_repo(&state)?;
    match repo.get_tenant_override(tenant_id).await? {
        Some(config) => Ok(HttpResponse::Ok().json(config)),
        None => Err(AxiamApiError(AxiamError::NotFound {
            entity: "email_config_override".into(),
            id: tenant_id.to_string(),
        })),
    }
}

/// `PUT /api/v1/tenants/{tenant_id}/email-config`
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/email-config",
    tag = "email-config",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = EmailConfigOverride,
    responses(
        (status = 200, description = "Tenant email configuration override updated (secrets omitted)",
         body = EmailConfigOverride),
        (status = 400, description = "Validation error"),
    ),
    security(("bearer" = []))
)]
pub async fn set_tenant_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<SetTenantEmailOverride>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot modify email configuration for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    let input = body.into_inner();
    validate_email_config_override(&input)?;
    let repo = require_email_config_repo(&state)?;
    let overrides = repo.set_tenant_override(tenant_id, input).await?;
    Ok(HttpResponse::Ok().json(overrides))
}

/// `DELETE /api/v1/tenants/{tenant_id}/email-config`
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{tenant_id}/email-config",
    tag = "email-config",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 204, description = "Tenant email configuration override deleted"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_tenant_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot delete email configuration for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    let repo = require_email_config_repo(&state)?;
    repo.delete_tenant_override(tenant_id).await?;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// Delivery self-test
// ---------------------------------------------------------------------------

/// What a test send did.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct EmailTestResult {
    /// Which provider the effective configuration resolved to.
    pub provider: String,
    /// Where the message went — always the caller's own address.
    pub to: String,
    /// The provider's message id, when it returns one.
    pub message_id: Option<String>,
}

/// Send one message through the effective configuration and report what happened.
///
/// Everything about a mail misconfiguration is otherwise invisible from the
/// admin UI. `PUT` validates structure only (D-15), delivery happens on an AMQP
/// consumer in another process, and a rejection — an unverified sender domain,
/// a revoked API key — surfaces only as a dead-letter three retries later, in a
/// log the operator configuring email is not watching. This runs the same
/// resolve → build → send path inline and hands back the provider's own words.
///
/// Two things keep it from being an open relay. The recipient is read from the
/// authenticated caller's own user record and is not a request parameter, so
/// the endpoint can only mail the person invoking it; and it is gated on
/// `email_config:write`, the permission that could change the sender identity
/// anyway.
async fn run_email_test<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
) -> Result<HttpResponse, AxiamApiError> {
    let repo = require_email_config_repo(state)?;
    let config = repo
        .get_effective_config(user.org_id, user.tenant_id)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::EmailConfig(
                "no email configuration applies to this tenant: set one on the \
                 organization, or override it on the tenant"
                    .into(),
            ))
        })?;

    // The recipient is the caller's own address, from the database — never
    // anything the request supplied.
    let recipient = state
        .user_repo
        .get_by_id(user.tenant_id, user.user_id)
        .await?
        .email;

    let service = EmailService::from_config(&config).map_err(AxiamApiError)?;
    let provider = service.provider_name().to_string();

    let sender = format!("{} <{}>", config.from_name, config.from_email);
    let message = EmailMessage {
        to: recipient.clone(),
        subject: "AXIAM email configuration test".into(),
        text_body: Some(format!(
            "This is a test message from AXIAM.\n\n\
             If you are reading it, the {provider} configuration works and mail \
             sent from {sender} reaches you.\n"
        )),
        html_body: None,
    };

    let result = service.send(&message).await.map_err(AxiamApiError)?;

    Ok(HttpResponse::Ok().json(EmailTestResult {
        provider,
        to: recipient,
        message_id: result.message_id,
    }))
}

/// `POST /api/v1/organizations/{org_id}/email-config/test`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/email-config/test",
    tag = "email-config",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    responses(
        (status = 200, description = "The provider accepted the message",
         body = EmailTestResult),
        (status = 400, description = "The provider rejected it, or no configuration applies"),
    ),
    security(("bearer" = []))
)]
pub async fn test_org_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot test email configuration for a different organization".into(),
            action: None,
            resource_id: None,
        }));
    }

    run_email_test(&user, &state).await
}

/// `POST /api/v1/tenants/{tenant_id}/email-config/test`
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/email-config/test",
    tag = "email-config",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "The provider accepted the message",
         body = EmailTestResult),
        (status = 400, description = "The provider rejected it, or no configuration applies"),
    ),
    security(("bearer" = []))
)]
pub async fn test_tenant_email_config<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot test email configuration for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }

    run_email_test(&user, &state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_smtp_override() -> ProviderConfig {
        ProviderConfig::Smtp(axiam_core::models::email::SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "user".to_string(),
            password: String::new(),
            starttls: true,
        })
    }

    #[test]
    fn empty_override_passes_validation() {
        assert!(validate_email_config_override(&EmailConfigOverride::default()).is_ok());
    }

    #[test]
    fn invalid_from_email_override_fails() {
        let input = EmailConfigOverride {
            from_email: Some("not-an-email".to_string()),
            ..Default::default()
        };
        let err = validate_email_config_override(&input).unwrap_err();
        assert!(err.to_string().contains("from_email"));
    }

    #[test]
    fn empty_from_name_override_fails() {
        let input = EmailConfigOverride {
            from_name: Some(String::new()),
            ..Default::default()
        };
        let err = validate_email_config_override(&input).unwrap_err();
        assert!(err.to_string().contains("from_name"));
    }

    #[test]
    fn invalid_reply_to_override_fails() {
        let input = EmailConfigOverride {
            reply_to: Some(Some("bad".to_string())),
            ..Default::default()
        };
        let err = validate_email_config_override(&input).unwrap_err();
        assert!(err.to_string().contains("reply_to"));
    }

    #[test]
    fn reply_to_clear_passes_validation() {
        let input = EmailConfigOverride {
            reply_to: Some(None),
            ..Default::default()
        };
        assert!(validate_email_config_override(&input).is_ok());
    }

    #[test]
    fn smtp_provider_override_with_empty_host_fails() {
        let mut provider = sample_smtp_override();
        if let ProviderConfig::Smtp(ref mut smtp) = provider {
            smtp.host = String::new();
        }
        let input = EmailConfigOverride {
            provider: Some(provider),
            ..Default::default()
        };
        let err = validate_email_config_override(&input).unwrap_err();
        assert!(err.to_string().contains("SMTP host"));
    }

    #[test]
    fn smtp_provider_override_with_zero_port_fails() {
        let mut provider = sample_smtp_override();
        if let ProviderConfig::Smtp(ref mut smtp) = provider {
            smtp.port = 0;
        }
        let input = EmailConfigOverride {
            provider: Some(provider),
            ..Default::default()
        };
        let err = validate_email_config_override(&input).unwrap_err();
        assert!(err.to_string().contains("SMTP port"));
    }

    #[test]
    fn valid_smtp_provider_override_passes() {
        let input = EmailConfigOverride {
            provider: Some(sample_smtp_override()),
            ..Default::default()
        };
        assert!(validate_email_config_override(&input).is_ok());
    }

    #[test]
    fn empty_api_key_override_is_treated_as_omit_and_passes() {
        let input = EmailConfigOverride {
            provider: Some(ProviderConfig::SendGrid(
                axiam_core::models::email::ApiProviderConfig {
                    api_key: String::new(),
                    api_url: None,
                },
            )),
            ..Default::default()
        };
        assert!(validate_email_config_override(&input).is_ok());
    }
}
