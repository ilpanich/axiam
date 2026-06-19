//! Tenant certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{
    BindCertificate, Certificate, CertificateType, CreateCertificate, GeneratedCertificate,
    KeyAlgorithm,
};
use axiam_core::repository::{
    CertificateRepository, PaginatedResult, Pagination, TenantRepository,
};
use axiam_db::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealTenantRepository,
};
use axiam_pki::CertService;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;

// -----------------------------------------------------------------------
// Request / response types (CQ-B25)
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateCertificateRequest {
    pub issuer_ca_id: Uuid,
    pub subject: String,
    pub cert_type: CertificateType,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days.
    pub validity_days: u32,
    pub metadata: Option<serde_json::Value>,
}

/// `POST /api/v1/certificates`
#[utoipa::path(
    post,
    path = "/api/v1/certificates",
    tag = "certificates",
    request_body = CreateCertificateRequest,
    responses(
        (status = 201, description = "Certificate generated",
         body = GeneratedCertificate),
    ),
    security(("bearer" = []))
)]
pub async fn generate<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    body: web::Json<CreateCertificateRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateCertificate {
        tenant_id: user.tenant_id,
        issuer_ca_id: req.issuer_ca_id,
        subject: req.subject,
        cert_type: req.cert_type,
        key_algorithm: req.key_algorithm,
        validity_days: req.validity_days,
        metadata: req.metadata,
    };

    // Read tenant-level max_certificate_validity_days from metadata
    let tenant = tenant_repo.get_by_id(user.tenant_id).await?;
    let max_validity = tenant
        .metadata
        .get("max_certificate_validity_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let result = service.generate(user.org_id, input, max_validity).await?;
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
    authz: AuthzData,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
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
    authz: AuthzData,
    path: web::Path<Uuid>,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
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
    authz: AuthzData,
    path: web::Path<Uuid>,
    service: web::Data<
        CertService<SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>,
    >,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:revoke", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    service.revoke(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}

/// `POST /api/v1/service-accounts/{sa_id}/bind-certificate`
#[utoipa::path(
    post,
    path = "/api/v1/service-accounts/{sa_id}/bind-certificate",
    tag = "certificates",
    request_body = BindCertificate,
    params(("sa_id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Certificate bound to service account"),
    ),
    security(("bearer" = []))
)]
pub async fn bind<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    cert_repo: web::Data<SurrealCertificateRepository<C>>,
    sa_repo: web::Data<axiam_db::SurrealServiceAccountRepository<C>>,
    body: web::Json<BindCertificate>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:bind", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let sa_id = path.into_inner();
    let input = body.into_inner();

    // Verify the certificate belongs to the same tenant.
    let cert = cert_repo
        .get_by_id(user.tenant_id, input.certificate_id)
        .await?;

    // Verify the service account belongs to the same tenant.
    use axiam_core::repository::ServiceAccountRepository;
    sa_repo.get_by_id(user.tenant_id, sa_id).await?;

    cert_repo
        .bind_to_service_account(user.tenant_id, cert.id, sa_id)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "certificate_id": cert.id,
        "service_account_id": sa_id,
        "status": "bound"
    })))
}
