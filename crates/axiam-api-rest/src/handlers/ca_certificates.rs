//! CA certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, GeneratedCaCertificate, KeyAlgorithm,
};
use axiam_core::repository::{PaginatedResult, Pagination};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::state::AppState;

// -----------------------------------------------------------------------
// Request types (CQ-B25)
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateCaCertificateRequest {
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
}

/// `POST /api/v1/organizations/{org_id}/ca-certificates`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/ca-certificates",
    tag = "ca-certificates",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = CreateCaCertificateRequest,
    responses(
        (status = 201, description = "CA certificate generated",
         body = GeneratedCaCertificate),
    ),
    security(("bearer" = []))
)]
pub async fn generate<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateCaCertificateRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow access to certificates in the caller's own org.
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
    let input = CreateCaCertificate {
        organization_id: org_id,
        subject: req.subject,
        key_algorithm: req.key_algorithm,
        validity_days: req.validity_days,
    };
    let result = state.ca_service.generate(input).await?;
    Ok(HttpResponse::Created().json(result))
}

/// `GET /api/v1/organizations/{org_id}/ca-certificates`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/ca-certificates",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        Pagination,
    ),
    responses(
        (status = 200, description = "List of CA certificates",
         body = inline(PaginatedResult<CaCertificate>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow access to certificates in the caller's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let result = state
        .ca_service
        .list(org_id, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/organizations/{org_id}/ca-certificates/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/ca-certificates/{id}",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("id" = Uuid, Path, description = "CA certificate ID"),
    ),
    responses(
        (status = 200, description = "CA certificate found", body = CaCertificate),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (org_id, id) = path.into_inner();

    // Authorization: only allow access to certificates in the caller's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let result = state.ca_service.get(org_id, id).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `POST /api/v1/organizations/{org_id}/ca-certificates/{id}/revoke`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/ca-certificates/{id}/revoke",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("id" = Uuid, Path, description = "CA certificate ID"),
    ),
    responses(
        (status = 200, description = "CA certificate revoked"),
    ),
    security(("bearer" = []))
)]
pub async fn revoke<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:revoke", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (org_id, id) = path.into_inner();

    // Authorization: only allow revoking certificates in the caller's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    state.ca_service.revoke(org_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}
