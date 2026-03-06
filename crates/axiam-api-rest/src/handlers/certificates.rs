//! Tenant certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{Certificate, CreateCertificate, GeneratedCertificate};
use axiam_core::repository::{PaginatedResult, Pagination};
use axiam_db::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::CertService;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::error::AxiamApiError;

/// `POST /api/v1/certificates`
#[utoipa::path(
    post,
    path = "/api/v1/certificates",
    tag = "certificates",
    request_body = CreateCertificate,
    responses(
        (status = 201, description = "Certificate generated",
         body = GeneratedCertificate),
    ),
    security(("bearer" = []))
)]
pub async fn generate<C: Connection>(
    user: AuthenticatedUser,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
    body: web::Json<CreateCertificate>,
) -> Result<HttpResponse, AxiamApiError> {
    let mut input = body.into_inner();
    input.tenant_id = user.tenant_id;
    let result = service.generate(user.org_id, input).await?;
    Ok(HttpResponse::Created().json(result))
}

/// `GET /api/v1/certificates`
#[utoipa::path(
    get,
    path = "/api/v1/certificates",
    tag = "certificates",
    params(Pagination),
    responses(
        (status = 200, description = "List of certificates",
         body = inline(PaginatedResult<Certificate>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = service
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/certificates/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/certificates/{id}",
    tag = "certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, description = "Certificate found", body = Certificate),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let result = service.get(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `POST /api/v1/certificates/{id}/revoke`
#[utoipa::path(
    post,
    path = "/api/v1/certificates/{id}/revoke",
    tag = "certificates",
    params(("id" = Uuid, Path, description = "Certificate ID")),
    responses(
        (status = 200, description = "Certificate revoked"),
    ),
    security(("bearer" = []))
)]
pub async fn revoke<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    service.revoke(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}
