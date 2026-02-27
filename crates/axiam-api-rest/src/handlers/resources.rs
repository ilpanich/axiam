//! Resource management endpoints with hierarchy support (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::resource::{CreateResource, UpdateResource};
use axiam_core::repository::{Pagination, ResourceRepository};
use axiam_db::SurrealResourceRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateResourceRequest {
    pub name: String,
    pub resource_type: String,
    pub parent_id: Option<Uuid>,
    pub metadata: Option<serde_json::Value>,
}

// -----------------------------------------------------------------------
// Handlers — CRUD
// -----------------------------------------------------------------------

/// `POST /api/v1/resources`
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    body: web::Json<CreateResourceRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = CreateResource {
        tenant_id: user.tenant_id,
        name: req.name,
        resource_type: req.resource_type,
        parent_id: req.parent_id,
        metadata: req.metadata,
    };
    let resource = repo.create(input).await?;
    Ok(HttpResponse::Created().json(resource))
}

/// `GET /api/v1/resources`
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/resources/{resource_id}`
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let resource = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(resource))
}

/// `PUT /api/v1/resources/{resource_id}`
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateResource>,
) -> Result<HttpResponse, AxiamApiError> {
    let resource = repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(resource))
}

/// `DELETE /api/v1/resources/{resource_id}`
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Hierarchy
// -----------------------------------------------------------------------

/// `GET /api/v1/resources/{resource_id}/children`
pub async fn list_children<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let children = repo.get_children(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(children))
}

/// `GET /api/v1/resources/{resource_id}/ancestors`
pub async fn list_ancestors<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealResourceRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let ancestors = repo
        .get_ancestors(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(ancestors))
}
