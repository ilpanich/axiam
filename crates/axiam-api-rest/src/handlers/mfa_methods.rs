//! MFA method management endpoints — list and delete.

use actix_web::{HttpResponse, web};
use axiam_auth::MfaMethodService;
use axiam_core::models::mfa_method::{MfaMethod, MfaMethodType};
use axiam_db::{SurrealUserRepository, SurrealWebauthnCredentialRepository};
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

type MfaMethodSvc<C> =
    MfaMethodService<SurrealUserRepository<C>, SurrealWebauthnCredentialRepository<C>>;

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
pub async fn list_mfa_methods<C: Connection>(
    caller: AuthenticatedUser,
    svc: web::Data<MfaMethodSvc<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let user_id = path.into_inner();

    // TODO(T19): allow admin users to list MFA methods for other users
    // once RBAC middleware is available.
    if user_id != caller.user_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "can only view your own MFA methods".into(),
            },
        ));
    }

    let methods = svc.list_methods(caller.tenant_id, user_id).await?;
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
pub async fn delete_mfa_method<C: Connection>(
    caller: AuthenticatedUser,
    svc: web::Data<MfaMethodSvc<C>>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AxiamApiError> {
    let (user_id, method_id) = path.into_inner();

    // TODO(T19): allow admin users to delete MFA methods for other users
    // once RBAC middleware is available.
    if user_id != caller.user_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "can only delete your own MFA methods".into(),
            },
        ));
    }

    svc.delete_method(caller.tenant_id, user_id, &method_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}
