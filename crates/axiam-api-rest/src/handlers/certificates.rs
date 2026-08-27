//! Tenant certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{
    BindCertificate, Certificate, CertificateStatus, CertificateType, CreateCertificate,
    GeneratedCertificate, KeyAlgorithm,
};
use axiam_core::repository::{
    CertificateRepository, PaginatedResult, Pagination, TenantRepository,
};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::state::AppState;

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
pub async fn generate<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
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
    let tenant = state.tenant_repo.get_by_id(user.tenant_id).await?;
    let max_validity = tenant
        .metadata
        .get("max_certificate_validity_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let result = state
        .pki
        .cert_service
        .generate(user.org_id, input, max_validity)
        .await?;
    Ok(HttpResponse::Created().json(result))
}

/// `GET /api/v1/certificates`
/// A certificate plus the service account it authenticates, if any.
///
/// The binding is a `cert_bound_to` graph edge, so it appeared on neither the
/// certificate row nor the service account row and the admin UI had nothing to
/// render — which is why it was "almost impossible to understand if a
/// certificate was bound to the service account or not". You could perform the
/// binding and then find no trace of it anywhere in the product.
///
/// A response wrapper rather than a field on
/// [`axiam_core::models::certificate::Certificate`]: the domain type describes
/// what a certificate *is*, and what it happens to be attached to is a fact
/// about the graph. Flattened on the wire, so a client that already parses a
/// certificate keeps working and simply gains a field.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct CertificateWithBinding {
    #[serde(flatten)]
    pub certificate: Certificate,
    /// The service account this certificate authenticates, or `null`.
    pub bound_service_account_id: Option<Uuid>,
}

impl CertificateWithBinding {
    fn attach(
        certificates: Vec<Certificate>,
        bindings: &std::collections::HashMap<Uuid, Uuid>,
    ) -> Vec<Self> {
        certificates
            .into_iter()
            .map(|certificate| Self {
                bound_service_account_id: bindings.get(&certificate.id).copied(),
                certificate,
            })
            .collect()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/certificates",
    tag = "certificates",
    params(Pagination),
    responses(
        (status = 200, description = "List of certificates",
         body = inline(PaginatedResult<CertificateWithBinding>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .pki
        .cert_service
        .list(user.tenant_id, pagination.into_inner())
        .await?;

    // One extra query for the whole page, not one per row — see
    // `CertificateRepository::bound_service_accounts` for why the per-row form
    // is what kept this off the page in the first place.
    let ids: Vec<Uuid> = result.items.iter().map(|c| c.id).collect();
    let bindings = {
        use axiam_core::repository::CertificateRepository as _;
        state.pki.cert_repo.bound_service_accounts(&ids).await?
    };

    Ok(HttpResponse::Ok().json(PaginatedResult {
        items: CertificateWithBinding::attach(result.items, &bindings),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
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
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let result = state.pki.cert_service.get(user.tenant_id, id).await?;
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
pub async fn revoke<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:revoke", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state.pki.cert_service.revoke(user.tenant_id, id).await?;
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
pub async fn bind<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<BindCertificate>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:bind", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let sa_id = path.into_inner();
    let input = body.into_inner();

    // Verify the certificate belongs to the same tenant.
    let cert = state
        .pki
        .cert_repo
        .get_by_id(user.tenant_id, input.certificate_id)
        .await?;

    // And that it can actually authenticate anything. A revoked or expired
    // certificate binds happily and then fails every handshake, so the operator
    // sees a service account that is configured for mTLS and cannot connect,
    // with nothing on either record saying why. The admin UI already filters
    // its picker to Active certificates; this is the same rule where it is
    // enforceable, for the API clients that do not go through that picker.
    if cert.status != CertificateStatus::Active {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "certificate is {:?} and cannot authenticate a service account",
                cert.status
            ),
        }));
    }
    if cert.not_after <= chrono::Utc::now() {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "certificate expired on {} and cannot authenticate a service account",
                cert.not_after.format("%Y-%m-%d")
            ),
        }));
    }

    // Verify the service account belongs to the same tenant.
    use axiam_core::repository::ServiceAccountRepository;
    state
        .service_account_repo
        .get_by_id(user.tenant_id, sa_id)
        .await?;

    state
        .pki
        .cert_repo
        .bind_to_service_account(user.tenant_id, cert.id, sa_id)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "certificate_id": cert.id,
        "service_account_id": sa_id,
        "status": "bound"
    })))
}
