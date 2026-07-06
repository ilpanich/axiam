//! Scope management endpoints (nested under resources, tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::scope::{CreateScope, Scope, UpdateScope};
use axiam_core::repository::ScopeRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateScopeRequest {
    pub name: Option<String>,
    pub description: Option<String>,
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
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<ResourcePath>,
    body: web::Json<CreateScopeRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scopes:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateScope {
        tenant_id: user.tenant_id,
        resource_id: path.resource_id,
        name: req.name,
        description: req.description,
    };
    let scope = state.scope_repo.create(input).await?;
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
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<ResourcePath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scopes:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let scopes = state
        .scope_repo
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
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<ScopePath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scopes:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let scope = state
        .scope_repo
        .get_by_id(user.tenant_id, path.scope_id)
        .await?;
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
    request_body = UpdateScopeRequest,
    responses(
        (status = 200, description = "Scope updated", body = Scope),
        (status = 404, description = "Scope not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<ScopePath>,
    body: web::Json<UpdateScopeRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scopes:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let existing = state
        .scope_repo
        .get_by_id(user.tenant_id, path.scope_id)
        .await?;
    if existing.resource_id != path.resource_id {
        return Err(AxiamError::NotFound {
            entity: "Scope".into(),
            id: path.scope_id.to_string(),
        }
        .into());
    }
    let req = body.into_inner();
    let input = UpdateScope {
        name: req.name,
        description: req.description,
    };
    let scope = state
        .scope_repo
        .update(user.tenant_id, path.scope_id, input)
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
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<ScopePath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scopes:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let existing = state
        .scope_repo
        .get_by_id(user.tenant_id, path.scope_id)
        .await?;
    if existing.resource_id != path.resource_id {
        return Err(AxiamError::NotFound {
            entity: "Scope".into(),
            id: path.scope_id.to_string(),
        }
        .into());
    }
    state
        .scope_repo
        .delete(user.tenant_id, path.scope_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}
