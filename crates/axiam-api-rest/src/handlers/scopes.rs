//! Scope management endpoints (nested under resources, tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::scope::{CreateScope, Scope, UpdateScope};
use axiam_core::repository::ScopeRepository;
use axiam_db::SurrealScopeRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Path extractors
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ResourcePath {
    pub resource_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ScopePath {
    pub resource_id: Uuid,
    pub scope_id: Uuid,
}

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateScopeRequest {
    pub name: String,
    pub description: String,
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/resources/{resource_id}/scopes`
#[utoipa::path(
    post,
    path = "/api/v1/resources/{resource_id}/scopes",
    tag = "scopes",
    params(("resource_id" = Uuid, Path, description = "Resource ID")),
    request_body = CreateScopeRequest,
    responses(
        (status = 201, description = "Scope created", body = Scope),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealScopeRepository<C>>,
    path: web::Path<ResourcePath>,
    body: web::Json<CreateScopeRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = CreateScope {
        tenant_id: user.tenant_id,
        resource_id: path.resource_id,
        name: req.name,
        description: req.description,
    };
    let scope = repo.create(input).await?;
    Ok(HttpResponse::Created().json(scope))
}

/// `GET /api/v1/resources/{resource_id}/scopes`
#[utoipa::path(
    get,
    path = "/api/v1/resources/{resource_id}/scopes",
    tag = "scopes",
    params(("resource_id" = Uuid, Path, description = "Resource ID")),
    responses(
        (status = 200, description = "List of scopes", body = Vec<Scope>),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealScopeRepository<C>>,
    path: web::Path<ResourcePath>,
) -> Result<HttpResponse, AxiamApiError> {
    let scopes = repo
        .list_by_resource(user.tenant_id, path.resource_id)
        .await?;
    Ok(HttpResponse::Ok().json(scopes))
}

/// `GET /api/v1/resources/{resource_id}/scopes/{scope_id}`
#[utoipa::path(
    get,
    path = "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    tag = "scopes",
    params(
        ("resource_id" = Uuid, Path, description = "Resource ID"),
        ("scope_id" = Uuid, Path, description = "Scope ID"),
    ),
    responses(
        (status = 200, description = "Scope found", body = Scope),
        (status = 404, description = "Scope not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealScopeRepository<C>>,
    path: web::Path<ScopePath>,
) -> Result<HttpResponse, AxiamApiError> {
    let scope = repo.get_by_id(user.tenant_id, path.scope_id).await?;
    if scope.resource_id != path.resource_id {
        return Err(AxiamError::NotFound {
            entity: "Scope".into(),
            id: path.scope_id.to_string(),
        }
        .into());
    }
    Ok(HttpResponse::Ok().json(scope))
}

/// `PUT /api/v1/resources/{resource_id}/scopes/{scope_id}`
#[utoipa::path(
    put,
    path = "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    tag = "scopes",
    params(
        ("resource_id" = Uuid, Path, description = "Resource ID"),
        ("scope_id" = Uuid, Path, description = "Scope ID"),
    ),
    request_body = UpdateScope,
    responses(
        (status = 200, description = "Scope updated", body = Scope),
        (status = 404, description = "Scope not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealScopeRepository<C>>,
    path: web::Path<ScopePath>,
    body: web::Json<UpdateScope>,
) -> Result<HttpResponse, AxiamApiError> {
    let existing = repo.get_by_id(user.tenant_id, path.scope_id).await?;
    if existing.resource_id != path.resource_id {
        return Err(AxiamError::NotFound {
            entity: "Scope".into(),
            id: path.scope_id.to_string(),
        }
        .into());
    }
    let scope = repo
        .update(user.tenant_id, path.scope_id, body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(scope))
}

/// `DELETE /api/v1/resources/{resource_id}/scopes/{scope_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/resources/{resource_id}/scopes/{scope_id}",
    tag = "scopes",
    params(
        ("resource_id" = Uuid, Path, description = "Resource ID"),
        ("scope_id" = Uuid, Path, description = "Scope ID"),
    ),
    responses(
        (status = 204, description = "Scope deleted"),
        (status = 404, description = "Scope not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealScopeRepository<C>>,
    path: web::Path<ScopePath>,
) -> Result<HttpResponse, AxiamApiError> {
    let existing = repo.get_by_id(user.tenant_id, path.scope_id).await?;
    if existing.resource_id != path.resource_id {
        return Err(AxiamError::NotFound {
            entity: "Scope".into(),
            id: path.scope_id.to_string(),
        }
        .into());
    }
    repo.delete(user.tenant_id, path.scope_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
