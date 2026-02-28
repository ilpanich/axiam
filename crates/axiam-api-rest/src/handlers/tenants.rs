//! Tenant management endpoints (nested under organizations).

use actix_web::{HttpResponse, web};
use axiam_core::models::tenant::{CreateTenant, Tenant, UpdateTenant};
use axiam_core::repository::{PaginatedResult, Pagination, TenantRepository};
use axiam_db::SurrealTenantRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

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
pub async fn create<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<OrgPath>,
    body: web::Json<CreateTenantRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = CreateTenant {
        organization_id: path.org_id,
        name: req.name,
        slug: req.slug,
        metadata: req.metadata,
    };
    let tenant = repo.create(input).await?;
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
pub async fn list<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<OrgPath>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo
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
pub async fn get<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let tenant = repo.get_by_id(path.tenant_id).await?;
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
pub async fn update<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<TenantPath>,
    body: web::Json<UpdateTenant>,
) -> Result<HttpResponse, AxiamApiError> {
    let tenant = repo.update(path.tenant_id, body.into_inner()).await?;
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
pub async fn delete<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(path.tenant_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
