//! Tenant certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{
    BindCertificate, Certificate, CertificateStatus, CertificateType, CreateCertificate,
    GeneratedCertificate, KeyAlgorithm, SignCertificateCsr, SubjectAltName,
};
use axiam_core::repository::{
    CertificateRepository, PaginatedResult, Pagination, TenantRepository,
};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedPrincipal;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::handlers::org_scope::is_organization_principal;
use crate::state::AppState;
use axiam_pki::IssuingScope;

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
    /// The names a `Server` certificate is issued for, as
    /// `[{"dns": "api.lakeside.internal"}, {"ip": "10.0.0.5"}]`. Required for
    /// `cert_type: Server` and refused for every other type. Each name, and
    /// the common name, must be admitted by the tenant's effective
    /// `server_cert_allowed_names`, which is empty — refusing every `Server`
    /// request — until an organization administrator lists names.
    #[serde(default)]
    pub subject_alt_names: Option<Vec<SubjectAltName>>,
}

/// The acting tenant's effective `server_cert_allowed_names` — read only for a
/// `Server` request, so every other request makes exactly the calls it made
/// before S-7 (I1). A failed read is an error, never an empty list read as
/// "nothing is allowed" or a missing one read as "anything is": the fence has
/// to be answered from the stored policy or not at all.
async fn server_names_for<C: Connection + Clone>(
    cert_type: &CertificateType,
    principal: &AuthenticatedPrincipal,
    state: &AppState<C>,
) -> Result<Vec<String>, AxiamApiError> {
    if *cert_type != CertificateType::Server {
        return Ok(Vec::new());
    }
    let settings = axiam_core::repository::SettingsRepository::get_effective_settings(
        &state.settings_repo,
        principal.org_id,
        principal.tenant_id,
    )
    .await?;
    Ok(settings.certificate.server_cert_allowed_names)
}

/// The issuing scope this caller acts with on both leaf paths.
///
/// [`IssuingScope::Organization`] only for a human principal whose own record
/// lives in the organization's reserved scope; everyone else — every service
/// account included — is [`IssuingScope::Tenant`] and is confined to the
/// signing CA of the tenant being acted on. The tenant being acted on is
/// `principal.tenant_id`, which is the caller's own tenant unless it named
/// another through `X-Axiam-Tenant` and was allowed to — which only an
/// organization-level principal, person or machine, can be.
async fn issuing_scope<C: Connection + Clone>(
    principal: &AuthenticatedPrincipal,
    state: &AppState<C>,
) -> IssuingScope {
    if is_organization_principal(principal, state).await {
        IssuingScope::Organization
    } else {
        IssuingScope::Tenant
    }
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
        (status = 400, description = "Invalid request: the subject is not a common name, the \
                                      validity exceeds a cap, or the names are refused — \
                                      `subject_alt_names` on a type other than `Server`, a \
                                      `Server` request with none, or a SAN or common name not \
                                      admitted by the tenant's `server_cert_allowed_names` \
                                      (empty by default, which refuses every `Server` request)"),
        (status = 404, description = "No such issuing CA within this caller's reach: it \
                                      belongs to another organization, to another tenant, \
                                      or is the organization CA and the caller is not an \
                                      organization principal"),
    ),
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn generate<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateCertificateRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:generate", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateCertificate {
        tenant_id: principal.tenant_id,
        issuer_ca_id: req.issuer_ca_id,
        subject: req.subject,
        cert_type: req.cert_type,
        key_algorithm: req.key_algorithm,
        validity_days: req.validity_days,
        metadata: req.metadata,
        subject_alt_names: req.subject_alt_names.unwrap_or_default(),
    };
    let server_names = server_names_for(&input.cert_type, &principal, state.get_ref()).await?;

    // Read tenant-level max_certificate_validity_days from metadata
    let tenant = state.tenant_repo.get_by_id(principal.tenant_id).await?;
    let max_validity = tenant
        .metadata
        .get("max_certificate_validity_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    // Which CAs of the organization this call can reach: its own tenant's
    // signing CA always, the organization CA only for a principal that lives in
    // the organization scope. Resolved from the caller's own record, never from
    // the body (DF-017).
    let scope = issuing_scope(&principal, state.get_ref()).await;

    let result = state
        .pki
        .cert_service
        .generate(principal.org_id, scope, input, max_validity, &server_names)
        .await?;
    Ok(HttpResponse::Created().json(result))
}

/// Body of `POST /api/v1/certificates/sign-csr`.
///
/// No `subject` and no `key_algorithm`: both are read out of the CSR, which is
/// the only place they can be stated without the row and the certificate being
/// able to disagree. No key is returned, so there is no key field anywhere on
/// this exchange.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SignCertificateCsrRequest {
    pub issuer_ca_id: Uuid,
    /// PEM-encoded PKCS#10 request — a `BEGIN CERTIFICATE REQUEST` block. The
    /// legacy OpenSSL `BEGIN NEW CERTIFICATE REQUEST` header is not accepted.
    pub csr_pem: String,
    pub cert_type: CertificateType,
    /// Validity duration in days.
    pub validity_days: u32,
    pub metadata: Option<serde_json::Value>,
    /// See [`CreateCertificateRequest::subject_alt_names`]. Stated here and
    /// never in the CSR, which is still refused if it requests a
    /// `subjectAltName`. Under a CA whose key is held by `vault_pki` a `Server`
    /// request on this path is refused; use `POST /api/v1/certificates`.
    #[serde(default)]
    pub subject_alt_names: Option<Vec<SubjectAltName>>,
}

/// `POST /api/v1/certificates/sign-csr`
///
/// Issue an end-entity certificate for a key AXIAM never sees. The subscriber's
/// private key is generated by whoever made the CSR — an offline ceremony, an
/// HSM, a device's secure element — and crosses the wire in neither direction.
///
/// `certificates:generate`, and not a permission of its own: a caller allowed
/// to mint a certificate under a CA is allowed to mint one for a key they
/// already hold, and this path is strictly the less powerful of the two
/// because no key material is produced or returned. The signing-CA twin,
/// `signing-cas/sign-csr`, sets the same precedent with
/// `ca_certificates:generate`.
///
/// Responds `201` with a [`Certificate`] — not a `GeneratedCertificate`, whose
/// `private_key_pem` would be a field that is always absent.
#[utoipa::path(
    post,
    path = "/api/v1/certificates/sign-csr",
    tag = "certificates",
    request_body = SignCertificateCsrRequest,
    responses(
        (status = 201, description = "Certificate issued from the request. Carries no \
                                      private key: there is none, which is the point.",
         body = Certificate),
        (status = 400, description = "The request is not a PEM PKCS#10 CSR, its signature \
                                      does not verify against the public key it carries, its \
                                      key is outside AXIAM's policy (Ed25519, or RSA with a \
                                      modulus of at least 4096 bits), it asks for a \
                                      `subjectAltName`, `keyUsage` or `extendedKeyUsage` \
                                      extension, the validity exceeds the tenant cap, the \
                                      825-day hard cap, or the issuer's own expiry, or the \
                                      names are refused (see `POST /api/v1/certificates`; a \
                                      `Server` request is also refused under a `vault_pki` CA)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden — `certificates:generate` required"),
        (status = 404, description = "No such issuing CA within this caller's reach: it \
                                      belongs to another organization, to another tenant, \
                                      or is the organization CA and the caller is not an \
                                      organization principal"),
    ),
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn sign_csr<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<SignCertificateCsrRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:generate", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = SignCertificateCsr {
        // From the authenticated context, never from the body (T-98).
        tenant_id: principal.tenant_id,
        issuer_ca_id: req.issuer_ca_id,
        csr_pem: req.csr_pem,
        cert_type: req.cert_type,
        validity_days: req.validity_days,
        metadata: req.metadata,
        subject_alt_names: req.subject_alt_names.unwrap_or_default(),
    };
    let server_names = server_names_for(&input.cert_type, &principal, state.get_ref()).await?;

    // The same tenant cap `generate` reads, from the same place.
    let tenant = state.tenant_repo.get_by_id(principal.tenant_id).await?;
    let max_validity = tenant
        .metadata
        .get("max_certificate_validity_days")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);

    let scope = issuing_scope(&principal, state.get_ref()).await;

    let certificate = state
        .pki
        .cert_service
        .sign_csr(principal.org_id, scope, input, max_validity, &server_names)
        .await?;
    Ok(HttpResponse::Created().json(certificate))
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
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn list<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:list", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let result = state
        .pki
        .cert_service
        .list(principal.tenant_id, pagination.into_inner())
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
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn get<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:get", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let result = state.pki.cert_service.get(principal.tenant_id, id).await?;
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
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn revoke<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:revoke", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state
        .pki
        .cert_service
        .revoke(principal.tenant_id, id)
        .await?;
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
        (status = 400, description = "The certificate cannot authenticate anything: it is not \
                                      Active, it has expired, or it is a `Server` certificate"),
    ),
    security(("bearer" = []), ("service_account" = []))
)]
pub async fn bind<C: Connection + Clone>(
    principal: AuthenticatedPrincipal,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<BindCertificate>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("certificates:bind", Uuid::nil())
        .check(&principal, authz.get_ref().as_ref())
        .await?;
    let sa_id = path.into_inner();
    let input = body.into_inner();

    // Verify the certificate belongs to the same tenant.
    let cert = state
        .pki
        .cert_repo
        .get_by_id(principal.tenant_id, input.certificate_id)
        .await?;

    // S-7 — a server certificate authenticates nobody, and binding one would
    // make a certificate for a *host name* the credential of a principal. The
    // device-login path refuses it as well; this is the refusal an operator
    // sees, at the moment the mistake is made.
    if cert.cert_type == CertificateType::Server {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "a Server certificate cannot be bound to a service account: it identifies \
                      a host, carries serverAuth only, and cannot authenticate a client"
                .into(),
        }));
    }

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
        .get_by_id(principal.tenant_id, sa_id)
        .await?;

    state
        .pki
        .cert_repo
        .bind_to_service_account(principal.tenant_id, cert.id, sa_id)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "certificate_id": cert.id,
        "service_account_id": sa_id,
        "status": "bound"
    })))
}
