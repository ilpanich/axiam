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
use axiam_core::repository::EmailConfigRepository;
use axiam_db::SurrealEmailConfigRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

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
pub async fn get_org_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot read email configuration for a different organization".into(),
        }));
    }

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
pub async fn set_org_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<SetOrgEmailConfig>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot modify email configuration for a different organization".into(),
        }));
    }

    let input = body.into_inner();
    validate_email_config(&input)?;
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
pub async fn delete_org_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot delete email configuration for a different organization".into(),
        }));
    }

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
pub async fn get_tenant_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot read email configuration for a different tenant".into(),
        }));
    }

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
pub async fn set_tenant_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
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
        }));
    }

    let input = body.into_inner();
    validate_email_config_override(&input)?;
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
pub async fn delete_tenant_email_config<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealEmailConfigRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("email_config:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();

    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot delete email configuration for a different tenant".into(),
        }));
    }

    repo.delete_tenant_override(tenant_id).await?;
    Ok(HttpResponse::NoContent().finish())
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
