//! Organization management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::organization::{CreateOrganization, Organization, UpdateOrganization};
use axiam_core::repository::{OrganizationRepository, PaginatedResult, Pagination, RoleRepository};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// -----------------------------------------------------------------------
// Request types (CQ-B25)
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub slug: Option<String>,
    /// Free-form metadata (the admin UI stores `description` here).
    pub metadata: Option<serde_json::Value>,
}

/// `POST /api/v1/organizations`
#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    tag = "organizations",
    request_body = CreateOrganizationRequest,
    responses(
        (status = 201, description = "Organization created", body = Organization),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateOrganizationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Restrict organization creation to system-wide super-admin only.
    if !caller_is_super_admin(&state, &user).await? {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "organization creation is restricted to super-admin".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let req = body.into_inner();
    let input = CreateOrganization {
        name: req.name,
        slug: req.slug,
        metadata: req.metadata,
    };
    let org = state.org_repo.create(input).await?;
    Ok(HttpResponse::Created().json(org))
}

/// Whether the caller holds the `super-admin` role.
///
/// Read from the tenant the caller **lives in**, never the one it is acting on.
/// The two differ only for an organization-level principal that has selected a
/// child tenant with `X-Axiam-Tenant`, and its grants live in the organization's
/// reserved scope — so looking them up in the selected tenant returned nothing
/// and refused an organization administrator the very operations organization
/// scope exists to give it. Same rule as
/// `axiam_authz::types::AccessRequest::assignment_tenant_id`.
async fn caller_is_super_admin<C: Connection + Clone>(
    state: &AppState<C>,
    user: &AuthenticatedUser,
) -> Result<bool, AxiamApiError> {
    let roles = state
        .role_repo
        .get_user_roles(user.principal_tenant_id, user.user_id)
        .await?;
    Ok(roles.iter().any(|r| r.name == "super-admin"))
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
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("organizations:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Restrict organization listing to super-admin only.
    if !caller_is_super_admin(&state, &user).await? {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "organization listing is restricted to super-admin".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    // The caller's OWN organization, and only it.
    //
    // This used to return `org_repo.list(..)` — every organization in the
    // deployment — to any principal holding a `super-admin` role. That role is
    // seeded per tenant, so the super-admin of one customer's tenant could
    // enumerate the name and slug of every other customer in the same
    // installation. It is also the one endpoint `GET .../{org_id}` is careful
    // about, refusing any organization but the caller's own two functions below;
    // the list simply did not apply the same rule.
    //
    // Cross-organization enumeration is a deployment-operator concern, not a
    // tenant one, and nothing in the admin UI wants it: the certificates page
    // calls this endpoint solely to turn the caller's org slug into its UUID.
    let pagination = query.into_inner();
    let items = match state.org_repo.get_by_id(user.org_id).await {
        Ok(org) => vec![org],
        Err(_) => vec![],
    };
    let total = items.len() as u64;
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
    }))
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
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
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
                action: None,
                resource_id: None,
            },
        ));
    }

    let org = state.org_repo.get_by_id(org_id).await?;
    Ok(HttpResponse::Ok().json(org))
}

/// `PUT /api/v1/organizations/{org_id}`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}",
    tag = "organizations",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = UpdateOrganizationRequest,
    responses(
        (status = 200, description = "Organization updated", body = Organization),
        (status = 404, description = "Organization not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateOrganizationRequest>,
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
                action: None,
                resource_id: None,
            },
        ));
    }

    let req = body.into_inner();
    let input = UpdateOrganization {
        name: req.name,
        slug: req.slug,
        metadata: req.metadata,
    };
    let org = state.org_repo.update(org_id, input).await?;
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
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
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
                action: None,
                resource_id: None,
            },
        ));
    }

    state.org_repo.delete(org_id).await?;
    Ok(HttpResponse::NoContent().finish())
}
