//! Tenant management endpoints (nested under organizations).

use actix_web::{HttpResponse, web};
use axiam_core::models::tenant::{CreateTenant, Tenant, UpdateTenant};
use axiam_core::repository::{PaginatedResult, Pagination, TenantRepository};
use axiam_db::seed_permissions;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use axiam_core::error::AxiamError;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::permissions::PERMISSION_REGISTRY;
use crate::state::AppState;

/// Request body for tenant creation (organization_id comes from the URL path).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
    pub metadata: Option<serde_json::Value>,
}

/// Path parameters for tenant collection endpoints.
#[derive(Debug, Deserialize)]
pub struct OrgPath {
    pub org_id: Uuid,
}

/// Path parameters for single-tenant endpoints.
#[derive(Debug, Deserialize)]
pub struct TenantPath {
    pub org_id: Uuid,
    pub tenant_id: Uuid,
}

/// `POST /api/v1/organizations/{org_id}/tenants`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/tenants",
    tag = "tenants",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = Tenant),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<OrgPath>,
    body: web::Json<CreateTenantRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: only allow creating tenants under the caller's own org.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let req = body.into_inner();
    let input = CreateTenant {
        organization_id: path.org_id,
        name: req.name,
        slug: req.slug,
        metadata: req.metadata,
    };
    let tenant = state.tenant_repo.create(input).await?;

    // Auto-seed permissions for the new tenant so RBAC works immediately.
    seed_permissions(&state.db, tenant.id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to seed permissions for new tenant {}: {}",
                tenant.id,
                e
            );
            AxiamApiError(AxiamError::Internal(
                "Failed to seed permissions for tenant".into(),
            ))
        })?;

    Ok(HttpResponse::Created().json(tenant))
}

/// `GET /api/v1/organizations/{org_id}/tenants`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/tenants",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        Pagination,
    ),
    responses(
        (status = 200, description = "List of tenants", body = inline(PaginatedResult<Tenant>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<OrgPath>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: only allow listing tenants under the caller's own org.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let result = state
        .tenant_repo
        .list_by_organization(path.org_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Tenant found", body = Tenant),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let tenant = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if tenant.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }
    Ok(HttpResponse::Ok().json(tenant))
}

/// `PUT /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = UpdateTenant,
    responses(
        (status = 200, description = "Tenant updated", body = Tenant),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
    body: web::Json<UpdateTenant>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let existing = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if existing.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }
    let tenant = state
        .tenant_repo
        .update(path.tenant_id, body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(tenant))
}

/// `DELETE /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 204, description = "Tenant deleted"),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let existing = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if existing.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }
    state.tenant_repo.delete(path.tenant_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
