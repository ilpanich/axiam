//! Admin bootstrap endpoint — first-run setup.
//!
//! Creates the initial admin user and seeds default roles when no admin exists.
//! After the first admin is created, this endpoint returns 404 (per D-09).

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealOrganizationRepository, SurrealRoleRepository,
    SurrealTenantRepository, SurrealUserRepository, seed_default_roles, seed_permissions,
};
use serde::{Deserialize, Serialize};
use surrealdb::{Connection, Surreal};
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::permissions::PERMISSION_REGISTRY;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BootstrapRequest {
    pub org_id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BootstrapResponse {
    pub message: String,
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Handler
// -----------------------------------------------------------------------

/// `POST /api/v1/admin/bootstrap` — first-run admin setup.
///
/// Creates the initial admin user with the super-admin role and seeds the
/// default permission set. Returns 404 once an admin already exists (D-09).
/// No token is issued — the user must authenticate via `/auth/login` (D-11).
///
/// Guarded by the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` environment variable (D-10):
/// if set, requests with a non-matching email are rejected with 403.
#[utoipa::path(
    post,
    path = "/api/v1/admin/bootstrap",
    tag = "admin",
    request_body = BootstrapRequest,
    responses(
        (status = 201, description = "Admin user created", body = BootstrapResponse),
        (status = 403, description = "Email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL"),
        (status = 404, description = "Bootstrap already completed"),
        (status = 400, description = "Organization or tenant not found"),
    )
)]
pub async fn bootstrap<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    org_repo: web::Data<SurrealOrganizationRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    db: web::Data<Surreal<C>>,
    body: web::Json<BootstrapRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // 1. Check AXIAM_BOOTSTRAP_ADMIN_EMAIL env gate (D-10).
    if let Ok(expected) = std::env::var("AXIAM_BOOTSTRAP_ADMIN_EMAIL")
        && req.email != expected
    {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL".into(),
        }));
    }

    // 2. Verify org and tenant exist.
    org_repo.get_by_id(req.org_id).await.map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "organization not found".into(),
        })
    })?;
    tenant_repo.get_by_id(req.tenant_id).await.map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "tenant not found".into(),
        })
    })?;

    // 3. Check if bootstrap has already been completed (D-09).
    //    Look for any role named "super-admin" in this tenant; if one exists and
    //    any user has been assigned to it, the bootstrap endpoint is disabled.
    let existing_roles = role_repo
        .list(
            req.tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await?;

    let super_admin_role = existing_roles
        .items
        .into_iter()
        .find(|r| r.name == "super-admin");

    if let Some(sa_role) = super_admin_role {
        // Check if any user has this role assigned.
        let existing_users = user_repo
            .list(
                req.tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1,
                },
            )
            .await?;

        // If users exist in the tenant, bootstrap is already done.
        // (The first user created via bootstrap always has super-admin.)
        // We use a more precise check: attempt get_user_roles for any user.
        // Simpler and sufficient: if any users exist with super-admin role assigned.
        // Use role's get_user_roles indirectly: check if super-admin role exists
        // and users exist — if both, bootstrap is completed.
        let _ = sa_role; // role exists — now check if any users exist
        if existing_users.total > 0 {
            return Err(AxiamApiError(AxiamError::NotFound {
                entity: "bootstrap".into(),
                id: "already initialized".into(),
            }));
        }
    }

    // 4. Seed permissions (idempotent).
    seed_permissions(db.get_ref(), req.tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 5. Seed default roles and get their IDs.
    let seed_result = seed_default_roles(db.get_ref(), req.tenant_id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| AxiamApiError(AxiamError::Internal(e.to_string())))?;

    // 6. Create the admin user (password is hashed by the repository).
    let user = user_repo
        .create(CreateUser {
            tenant_id: req.tenant_id,
            username: req.username,
            email: req.email,
            password: req.password,
            metadata: None,
        })
        .await?;

    // 7. Assign super-admin role to the new user.
    role_repo
        .assign_to_user(req.tenant_id, user.id, seed_result.super_admin_role_id, None)
        .await?;

    // 8. Return 201 — no token (user must login via /auth/login, per D-11).
    Ok(HttpResponse::Created().json(BootstrapResponse {
        message: "Admin user created. Login via /auth/login.".into(),
        user_id: user.id,
    }))
}
