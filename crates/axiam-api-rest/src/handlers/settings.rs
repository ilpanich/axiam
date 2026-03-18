//! Security settings endpoints for organizations and tenants.

use actix_web::{HttpResponse, web};
use axiam_core::models::settings::{
    SecuritySettings, SetOrgSettings, TenantSettingsOverride, effective_settings,
    validate_tenant_override,
};
use axiam_core::repository::SettingsRepository;
use axiam_db::SurrealSettingsRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

/// `GET /api/v1/organizations/{org_id}/settings`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/settings",
    tag = "settings",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    responses(
        (status = 200, description = "Organization security settings",
         body = SecuritySettings),
    ),
    security(("bearer" = []))
)]
pub async fn get_org_settings<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealSettingsRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let settings = repo.get_org_settings(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(settings))
}

/// `PUT /api/v1/organizations/{org_id}/settings`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/settings",
    tag = "settings",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
    ),
    request_body = SetOrgSettings,
    responses(
        (status = 200, description = "Organization settings updated",
         body = SecuritySettings),
    ),
    security(("bearer" = []))
)]
pub async fn set_org_settings<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealSettingsRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<SetOrgSettings>,
) -> Result<HttpResponse, AxiamApiError> {
    let settings = repo
        .set_org_settings(path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(settings))
}

/// `GET /api/v1/settings`
///
/// Returns the effective (merged) security settings for the
/// authenticated user's tenant. Org baseline + tenant overrides.
#[utoipa::path(
    get,
    path = "/api/v1/settings",
    tag = "settings",
    responses(
        (status = 200, description = "Effective tenant security settings",
         body = SecuritySettings),
    ),
    security(("bearer" = []))
)]
pub async fn get_tenant_settings<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealSettingsRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let settings = repo
        .get_effective_settings(user.org_id, user.tenant_id)
        .await?;
    Ok(HttpResponse::Ok().json(settings))
}

/// `PUT /api/v1/settings`
///
/// Set tenant-level overrides. Only fields that are **more restrictive**
/// than the org baseline are accepted. Omit a field (set to `null`) to
/// inherit from the org.
#[utoipa::path(
    put,
    path = "/api/v1/settings",
    tag = "settings",
    request_body = TenantSettingsOverride,
    responses(
        (status = 200, description = "Tenant settings updated",
         body = SecuritySettings),
        (status = 400, description = "Override violates org baseline"),
    ),
    security(("bearer" = []))
)]
pub async fn set_tenant_settings<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealSettingsRepository<C>>,
    body: web::Json<TenantSettingsOverride>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.get_org_settings(user.org_id).await?;
    let overrides = body.into_inner();

    // Validate: tenant can only be more restrictive than org
    validate_tenant_override(&org, &overrides)?;

    // Merge org baseline + overrides into a complete settings row
    let merged = effective_settings(&org, &overrides, user.tenant_id, Uuid::new_v4());

    let result = repo
        .store_effective_tenant_settings(user.tenant_id, merged)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}
