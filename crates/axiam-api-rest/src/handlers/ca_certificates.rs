//! CA certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, GeneratedCaCertificate, ImportCaCertificate, KeyAlgorithm,
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
    /// Common name for the signing intermediate — `vault_pki` custody only.
    ///
    /// Under that custodian Vault generates a root and an intermediate beneath
    /// it, and this names the second. Defaults to the root's subject with
    /// `Intermediate Authority` appended. Ignored by every other custodian,
    /// which produces one self-signed CA and has no second certificate to name.
    #[serde(default)]
    pub intermediate_subject: Option<String>,
    /// Validity of the signing intermediate, in days. Defaults to the root's.
    #[serde(default)]
    pub intermediate_validity_days: Option<u32>,
    /// Issue leaves straight from the generated root instead of creating an
    /// intermediate. `vault_pki` custody only, and off by default.
    ///
    /// The default is the safer one: a root that signs only an intermediate can
    /// have that intermediate revoked and replaced without redistributing the
    /// trust anchor, and a root that signs leaves cannot.
    #[serde(default)]
    pub issue_from_root: bool,
}

/// `POST /api/v1/organizations/{org_id}/ca-certificates`
///
/// Generate a CA. What that means depends on the configured key custodian, and
/// deliberately not on the request:
///
/// * Under `database` or `vault` custody, AXIAM generates a self-signed root
///   and returns its private key once, in `private_key_pem`.
/// * Under `vault_pki` custody, Vault generates a root and a signing
///   intermediate beneath it, and the response has **no** `private_key_pem`
///   because the key never existed outside Vault. The root's certificate comes
///   back in `chain_pem`, which is the only copy anything outside Vault will
///   see.
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
        // An empty string is not a subject; it would produce an intermediate
        // with a blank CN rather than the documented default.
        intermediate_subject: req.intermediate_subject.filter(|s| !s.trim().is_empty()),
        intermediate_validity_days: req.intermediate_validity_days,
        issue_from_root: req.issue_from_root,
    };
    let result = state.pki.ca_service.generate(input).await?;
    Ok(HttpResponse::Created().json(result))
}

/// Body of `POST /api/v1/organizations/{org_id}/ca-certificates/import`.
///
/// Deliberately carries no subject, validity window or key algorithm: all
/// three are read out of the certificate itself. A caller that could name them
/// separately could name a subject the certificate does not have, and AXIAM
/// would enforce the claim while every relying party read the certificate.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct ImportCaCertificateRequest {
    /// PEM-encoded CA certificate.
    pub public_cert_pem: String,
    /// PEM-encoded private key, if AXIAM is to take custody of it.
    ///
    /// Omit it to register the certificate as a trust anchor only. Write-only:
    /// it goes to the configured custodian on the way in and no endpoint
    /// returns it.
    #[serde(default)]
    pub private_key_pem: Option<String>,
}

/// Manual `Debug` (SECHRD-09 / D-06): actix's error and tracing paths format
/// extractor payloads, and `#[serde(skip_serializing)]` governs `Serialize`
/// only.
impl std::fmt::Debug for ImportCaCertificateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportCaCertificateRequest")
            .field("public_cert_pem", &self.public_cert_pem)
            .field(
                "private_key_pem",
                &self.private_key_pem.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// `POST /api/v1/organizations/{org_id}/ca-certificates/import`
///
/// Register a CA an organization already has, instead of generating one.
///
/// The case this exists for: an organization whose root lives offline, in an
/// HSM, or in an existing internal PKI, and which wants AXIAM in the chain
/// rather than at the top of it. Without it, the only CA AXIAM could use was
/// one it generated, which means every AXIAM-issued certificate chains to a
/// root nothing else in the estate trusts.
///
/// With a private key, AXIAM takes custody of it and can issue against the CA.
/// Where it goes is the configured custodian's business: sealed into the row,
/// written to Vault's KV engine, or — under `vault_pki` — imported into Vault's
/// PKI engine as an issuer, after which AXIAM signs through Vault and holds
/// nothing. That last one is the BYOK counterpart to generating in Vault: the
/// key does pass through AXIAM's memory on the way in, because AXIAM is what
/// received the request, but it is never stored here and every later use of it
/// is Vault's.
///
/// Without a private key, the certificate is a trust anchor and
/// `/api/v1/certificates` says so rather than failing at the point of use.
///
/// Gated on `ca_certificates:generate`: importing a CA is the same act as
/// generating one from every relying party's point of view — it decides what
/// this organization's certificates chain to.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/ca-certificates/import",
    tag = "ca-certificates",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = ImportCaCertificateRequest,
    responses(
        (status = 201, description = "CA certificate imported", body = CaCertificate),
        (status = 400, description = "Not a CA certificate, already expired, or the \
                                      supplied key does not match it"),
    ),
    security(("bearer" = []))
)]
pub async fn import<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<ImportCaCertificateRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

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
    let certificate = state
        .pki
        .ca_service
        .import(ImportCaCertificate {
            organization_id: org_id,
            public_cert_pem: req.public_cert_pem,
            // An empty string is not a key; treating it as one would send the
            // custodian something to store and produce a CA that lists as
            // issuable and fails at the first signature.
            private_key_pem: req.private_key_pem.filter(|k| !k.trim().is_empty()),
        })
        .await?;

    Ok(HttpResponse::Created().json(certificate))
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
        .pki
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

    let result = state.pki.ca_service.get(org_id, id).await?;
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

    state.pki.ca_service.revoke(org_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}
