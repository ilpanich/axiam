//! Organization management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::organization::{CreateOrganization, Organization, UpdateOrganization};
use axiam_core::repository::{OrganizationRepository, PaginatedResult, Pagination};
use axiam_db::SurrealOrganizationRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

/// `POST /api/v1/organizations`
#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    tag = "organizations",
    request_body = CreateOrganization,
    responses(
        (status = 201, description = "Organization created", body = Organization),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    body: web::Json<CreateOrganization>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.create(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(org))
}

/// `GET /api/v1/organizations`
#[utoipa::path(
    get,
    path = "/api/v1/organizations",
    tag = "organizations",
    params(Pagination),
    responses(
        (status = 200, description = "List of organizations", body = inline(PaginatedResult<Organization>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/organizations/{org_id}`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}",
    tag = "organizations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 200, description = "Organization found", body = Organization),
        (status = 404, description = "Organization not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.get_by_id(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(org))
}

/// `PUT /api/v1/organizations/{org_id}`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}",
    tag = "organizations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = UpdateOrganization,
    responses(
        (status = 200, description = "Organization updated", body = Organization),
        (status = 404, description = "Organization not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateOrganization>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.update(path.into_inner(), body.into_inner()).await?;
    Ok(HttpResponse::Ok().json(org))
}

/// `DELETE /api/v1/organizations/{org_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_id}",
    tag = "organizations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    responses(
        (status = 204, description = "Organization deleted"),
        (status = 404, description = "Organization not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}
