//! CA certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{CaCertificate, CreateCaCertificate, GeneratedCaCertificate};
use axiam_core::repository::{PaginatedResult, Pagination};
use axiam_db::SurrealCaCertificateRepository;
use axiam_pki::CaService;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::error::AxiamApiError;

/// `POST /api/v1/organizations/{org_id}/ca-certificates`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/ca-certificates",
    tag = "ca-certificates",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = CreateCaCertificate,
    responses(
        (status = 201, description = "CA certificate generated",
         body = GeneratedCaCertificate),
    ),
    security(("bearer" = []))
)]
pub async fn generate<C: Connection>(
    _user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<CaService<SurrealCaCertificateRepository<C>>>,
    body: web::Json<CreateCaCertificate>,
) -> Result<HttpResponse, AxiamApiError> {
    let org_id = path.into_inner();
    let mut input = body.into_inner();
    input.organization_id = org_id;
    let result = service.generate(input).await?;
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
pub async fn list<C: Connection>(
    _user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<CaService<SurrealCaCertificateRepository<C>>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let org_id = path.into_inner();
    let result = service.list(org_id, pagination.into_inner()).await?;
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
pub async fn get<C: Connection>(
    _user: AuthenticatedUser,
    path: web::Path<(Uuid, Uuid)>,
    service: web::Data<CaService<SurrealCaCertificateRepository<C>>>,
) -> Result<HttpResponse, AxiamApiError> {
    let (org_id, id) = path.into_inner();
    let result = service.get(org_id, id).await?;
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
pub async fn revoke<C: Connection>(
    _user: AuthenticatedUser,
    path: web::Path<(Uuid, Uuid)>,
    service: web::Data<CaService<SurrealCaCertificateRepository<C>>>,
) -> Result<HttpResponse, AxiamApiError> {
    let (org_id, id) = path.into_inner();
    service.revoke(org_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}
