//! Organization management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::organization::{CreateOrganization, UpdateOrganization};
use axiam_core::repository::{OrganizationRepository, Pagination};
use axiam_db::SurrealOrganizationRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

/// `POST /api/v1/organizations`
pub async fn create<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    body: web::Json<CreateOrganization>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.create(body.into_inner()).await?;
    Ok(HttpResponse::Created().json(org))
}

/// `GET /api/v1/organizations`
pub async fn list<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/organizations/{org_id}`
pub async fn get<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let org = repo.get_by_id(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(org))
}

/// `PUT /api/v1/organizations/{org_id}`
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
pub async fn delete<C: Connection>(
    _user: AuthenticatedUser,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}
