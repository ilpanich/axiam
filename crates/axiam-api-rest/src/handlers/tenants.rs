//! Tenant management endpoints (nested under organizations).

use actix_web::{HttpResponse, web};
use axiam_core::models::tenant::{CreateTenant, UpdateTenant};
use axiam_core::repository::{Pagination, TenantRepository};
use axiam_db::SurrealTenantRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

/// Request body for tenant creation (organization_id comes from the URL path).
#[derive(Debug, Deserialize)]
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
pub async fn get<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let tenant = repo.get_by_id(path.tenant_id).await?;
    Ok(HttpResponse::Ok().json(tenant))
}

/// `PUT /api/v1/organizations/{org_id}/tenants/{tenant_id}`
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
pub async fn delete<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealTenantRepository<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(path.tenant_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
