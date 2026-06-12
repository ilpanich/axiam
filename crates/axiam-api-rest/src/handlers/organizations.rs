//! Organization management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::organization::{CreateOrganization, Organization, UpdateOrganization};
use axiam_core::repository::{OrganizationRepository, PaginatedResult, Pagination, RoleRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealRoleRepository};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
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
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    body: web::Json<CreateOrganization>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Restrict organization creation to system-wide super-admin only.
    let roles = role_repo
        .get_user_roles(user.tenant_id, user.user_id)
        .await?;
    let is_super_admin = roles.iter().any(|r| r.name == "super-admin");
    if !is_super_admin {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "organization creation is restricted to super-admin".into(),
            },
        ));
    }

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
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Restrict organization listing to system-wide super-admin only.
    let roles = role_repo
        .get_user_roles(user.tenant_id, user.user_id)
        .await?;
    let is_super_admin = roles.iter().any(|r| r.name == "super-admin");
    if !is_super_admin {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "organization listing is restricted to super-admin".into(),
            },
        ));
    }

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
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow access to the caller's own organization.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
            },
        ));
    }

    let org = repo.get_by_id(org_id).await?;
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
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateOrganization>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow updates on the caller's own organization.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
            },
        ));
    }

    let org = repo.update(org_id, body.into_inner()).await?;
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
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealOrganizationRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow deletion of the caller's own organization.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
            },
        ));
    }

    repo.delete(org_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
