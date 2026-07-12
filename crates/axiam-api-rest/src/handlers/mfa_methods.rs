//! MFA method management endpoints — list and delete.

use actix_web::{HttpResponse, web};
use axiam_core::models::mfa_method::{MfaMethod, MfaMethodType};
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// -------------------------------------------------------------------
// Response types
// -------------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MfaMethodResponse {
    pub method_id: String,
    pub method_type: MfaMethodType,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl From<MfaMethod> for MfaMethodResponse {
    fn from(m: MfaMethod) -> Self {
        Self {
            method_id: m.method_id,
            method_type: m.method_type,
            name: m.name,
            created_at: m.created_at.to_rfc3339(),
            last_used_at: m.last_used_at.map(|t| t.to_rfc3339()),
        }
    }
}

// -------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------

/// `GET /api/v1/users/{user_id}/mfa-methods`
///
/// List all MFA methods registered for a user.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/mfa-methods",
    tag = "users",
    params(
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses(
        (status = 200, description = "MFA methods list",
         body = Vec<MfaMethodResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot view another user's MFA methods"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn list_mfa_methods<C: Connection + Clone>(
    caller: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let user_id = path.into_inner();

    if !is_own_resource(&caller, user_id) {
        RequirePermission::new("users:admin", Uuid::nil())
            .check(&caller, authz.get_ref().as_ref())
            .await?;
    }

    let methods = state
        .mfa_method_service
        .list_methods(caller.tenant_id, user_id)
        .await?;
    let response: Vec<MfaMethodResponse> = methods.into_iter().map(Into::into).collect();
    Ok(HttpResponse::Ok().json(response))
}

/// `DELETE /api/v1/users/{user_id}/mfa-methods/{method_id}`
///
/// Remove a specific MFA method. Returns 400 if it is the last
/// method and MFA is enabled.
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}/mfa-methods/{method_id}",
    tag = "users",
    params(
        ("user_id" = Uuid, Path, description = "Target user ID"),
        ("method_id" = String, Path,
         description = "Method ID (\"totp\" or credential UUID)"),
    ),
    responses(
        (status = 204, description = "Method removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Method not found"),
        (status = 400, description = "Cannot remove last MFA method"),
        (status = 403, description = "Cannot delete another user's MFA methods"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_mfa_method<C: Connection + Clone>(
    caller: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AxiamApiError> {
    let (user_id, method_id) = path.into_inner();

    if !is_own_resource(&caller, user_id) {
        RequirePermission::new("users:admin", Uuid::nil())
            .check(&caller, authz.get_ref().as_ref())
            .await?;
    }

    state
        .mfa_method_service
        .delete_method(caller.tenant_id, user_id, &method_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}
