//! CA certificate management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, CreateIntermediateCa, GeneratedCaCertificate,
    ImportCaCertificate, KeyAlgorithm, SignIntermediateCsr,
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
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

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
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

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
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

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

// ---------------------------------------------------------------------------
// Key custody migration
// ---------------------------------------------------------------------------

/// What a custody migration did.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct MigrateCustodyResponse {
    /// The CA whose key moved.
    pub ca_certificate_id: Uuid,
    /// Where the key was.
    #[schema(example = "database")]
    pub previous_custody: String,
    /// Where it is now.
    #[schema(example = "vault")]
    pub key_custody: String,
    /// Where the new custodian filed it, when the custodian has a path.
    pub key_locator: Option<String>,
}

/// `POST /api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody`
///
/// Move this CA's signing key to the custodian the deployment is configured for.
///
/// Custody is recorded per CA rather than read from configuration, so adopting
/// Vault does not move the CAs that already exist — their keys stay sealed in
/// their rows until something moves them. This is that something, and without
/// it the only route out of database custody is to generate a new CA and
/// re-issue every leaf beneath it, which for a trust anchor means touching every
/// relying party.
///
/// Takes effect immediately; no restart. The row is the authority on where a key
/// lives, and the signing path reads it per request.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/ca-certificates/{id}/migrate-custody",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("id" = Uuid, Path, description = "CA certificate ID"),
    ),
    responses(
        (status = 200, description = "Key moved to the configured custodian",
         body = MigrateCustodyResponse),
        (status = 400, description = "Already there, nothing to move, or a custodian \
                                      that will not hand its key over"),
        (status = 403, description = "Different organization"),
        (status = 404, description = "CA certificate not found"),
    ),
    security(("bearer" = []))
)]
pub async fn migrate_custody<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:manage", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    let (org_id, id) = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    // Read the previous custody before the move, so the response can say what
    // actually changed rather than only where the key ended up.
    let before = state.pki.ca_service.get(org_id, id).await?;
    let updated = state.pki.ca_service.migrate_key_custody(org_id, id).await?;

    Ok(HttpResponse::Ok().json(MigrateCustodyResponse {
        ca_certificate_id: updated.id,
        previous_custody: before.key_custody.to_string(),
        key_custody: updated.key_custody.to_string(),
        key_locator: updated.key_locator.clone(),
    }))
}

// ---------------------------------------------------------------------------
// mTLS trust anchor
// ---------------------------------------------------------------------------

/// Body for `PUT .../ca-certificates/{id}/mtls-trust-anchor`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct SetMtlsTrustAnchor {
    /// Whether this CA should be trusted for client-certificate authentication.
    pub enabled: bool,
}

/// The acknowledgement, which is mostly about the restart.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct MtlsTrustAnchorResponse {
    /// The CA this is about.
    pub ca_certificate_id: Uuid,
    /// The flag as now stored.
    pub mtls_trust_anchor: bool,
    /// Whether the change still needs a restart to take effect.
    ///
    /// `false` when the live listener accepted the new anchor set — the
    /// ordinary case on a TLS deployment. `true` only when there was no
    /// listener to reload into (plaintext, or `client_auth = off`), where the
    /// flag is stored and applies at the next start.
    pub restart_required: bool,
    /// How many CAs the listener now trusts for client authentication, when it
    /// was reloaded. `None` when nothing was reloaded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_anchors: Option<usize>,
    /// A sentence an operator can act on, rather than a bare boolean.
    pub message: String,
}

/// `PUT /api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor`
///
/// Offer this CA — or stop offering it — as a trust anchor for mutual TLS.
///
/// When enabled, this CA's **public** certificate is exported into the
/// client-CA bundle and client-certificate verification is turned on in
/// `optional` mode, unless the operator has configured
/// `AXIAM__SERVER__TLS__CLIENT_AUTH` / `CLIENT_CA_PATH` themselves, which is
/// never overridden. The signing key is not copied and stays with its custodian.
///
/// The change applies to the **running listener**. rustls consults its client
/// certificate verifier per handshake rather than only at construction, so a
/// verifier that delegates to a swappable anchor set can be updated in place;
/// see `axiam_server::tls::ReloadableClientCertVerifier`. Connections already
/// established keep the verifier they handshook with, which is correct — a
/// certificate accepted a moment ago does not become invalid mid-connection.
///
/// `restart_required` is therefore `false` on a TLS deployment, and `true` only
/// when there is no listener to reload into.
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor",
    tag = "ca-certificates",
    request_body = SetMtlsTrustAnchor,
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("id" = Uuid, Path, description = "CA certificate ID"),
    ),
    responses(
        (status = 200, description = "Flag updated; takes effect at the next server start",
         body = MtlsTrustAnchorResponse),
        (status = 403, description = "Different organization"),
        (status = 404, description = "CA certificate not found"),
    ),
    security(("bearer" = []))
)]
pub async fn set_mtls_trust_anchor<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
    body: web::Json<SetMtlsTrustAnchor>,
) -> Result<HttpResponse, AxiamApiError> {
    // Gated on `ca_certificates:manage` rather than `:read`: this changes what
    // the deployment's TLS listener will trust, which is a stronger act than
    // reading a CA and a different one from issuing under it.
    RequirePermission::new("ca_certificates:manage", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    let (org_id, id) = path.into_inner();

    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let enabled = body.into_inner().enabled;
    use axiam_core::repository::CaCertificateRepository as _;
    let updated = state
        .pki
        .ca_cert_repo
        .set_mtls_trust_anchor(org_id, id, enabled)
        .await?;

    // Apply it to the listener that is serving this very request.
    //
    // Deliberately after the row is written and deliberately fallible-but-not-
    // fatal: the stored flag is the source of truth that the next boot reads,
    // so a reload failure must not roll it back. What it must do is *say so*,
    // rather than reporting success for a change that did not take effect —
    // that is the difference between "restart to apply" and "applied".
    let reload = match state.pki.trust_anchor_reloader.as_ref() {
        Some(reloader) => reloader.reload().await,
        None => Ok(None),
    };

    let (restart_required, trusted_anchors, applied) = match reload {
        Ok(Some(count)) => (false, Some(count), true),
        Ok(None) => (true, None, false),
        Err(e) => {
            // The anchor set on the listener is unchanged — the replacement is
            // built completely before anything is swapped — so the deployment
            // is still verifying clients exactly as it was a moment ago.
            tracing::error!(
                ca_certificate_id = %updated.id,
                error = %e,
                "trust anchor flag saved but the live reload failed; the listener \
                 is unchanged and the flag applies at the next start"
            );
            (true, None, false)
        }
    };

    let message = match (updated.mtls_trust_anchor, applied) {
        (true, true) => format!(
            "This CA is now in the mTLS client trust store. Clients presenting a \
             certificate it issued are verified by TLS itself, on connections \
             opened from now on. {} CA(s) are trusted.",
            trusted_anchors.unwrap_or_default()
        ),
        (true, false) => "This CA will be added to the mTLS client trust store when the \
             server next starts. Clients presenting a certificate it issued will \
             then be verified by TLS itself."
            .to_string(),
        (false, true) => format!(
            "This CA is no longer in the mTLS client trust store. Certificates it \
             issued no longer authenticate a client on connections opened from \
             now on; established connections keep the verifier they handshook \
             with. {} CA(s) remain trusted.",
            trusted_anchors.unwrap_or_default()
        ),
        (false, false) => "This CA will be removed from the mTLS client trust store when \
             the server next starts. Certificates it issued will no longer \
             authenticate a client."
            .to_string(),
    };

    Ok(HttpResponse::Ok().json(MtlsTrustAnchorResponse {
        ca_certificate_id: updated.id,
        mtls_trust_anchor: updated.mtls_trust_anchor,
        restart_required,
        trusted_anchors,
        message,
    }))
}

// ---------------------------------------------------------------------------
// Tenant signing CAs
// ---------------------------------------------------------------------------
//
// An organization CA is a trust anchor: long-lived, widely distributed, and
// painful to replace. Issuing every tenant's leaves straight from it means one
// tenant's compromised issuance is the whole estate's problem, and rotating it
// is a co-ordinated change at every relying party.
//
// A tenant signing CA is the intermediate that fixes that. It is created
// beneath an organization CA, constrained to a path length of zero, and is what
// `POST /api/v1/certificates` names as its `issuer_ca_id` for that tenant's
// users, services and devices. Revoking it revokes exactly one tenant's
// issuance and touches nothing else.
//
// Two ways to get one, and they differ in where the private key is:
//
// * **Generate** — AXIAM (or, under `vault_pki`, Vault) makes the key. It goes
//   to the configured custodian: Vault's PKI engine, Vault's KV engine, or
//   encrypted into the row. The key is returned once, if there is one to
//   return, and AXIAM can issue against the CA thereafter.
// * **Sign a CSR** — the tenant makes the key elsewhere and sends only a
//   PKCS#10 request. Nothing is returned once, because nothing was generated
//   here, and the row records custody `External`: AXIAM has issued a
//   certificate and holds no means of using it.

/// Body of `POST .../tenants/{tenant_id}/signing-cas`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateIntermediateCaRequest {
    /// The organization CA that signs it.
    pub parent_ca_id: Uuid,
    /// Subject for the signing CA, e.g. `CN=ACME R&D Signing CA`.
    pub subject: String,
    pub key_algorithm: KeyAlgorithm,
    /// Validity duration in days, capped to the parent's own expiry.
    pub validity_days: u32,
}

/// Body of `POST .../tenants/{tenant_id}/signing-cas/sign-csr`.
///
/// Deliberately carries no key algorithm: it is the CSR's, read out of the
/// request, because a caller who could state it separately could state one the
/// key does not have.
#[derive(Deserialize, utoipa::ToSchema)]
pub struct SignIntermediateCsrRequest {
    /// The organization CA that signs it.
    pub parent_ca_id: Uuid,
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
    /// Validity duration in days, capped to the parent's own expiry.
    pub validity_days: u32,
}

/// A CSR discloses nothing secret, but it is bulky enough to bury a tracing
/// span; elided rather than printed.
impl std::fmt::Debug for SignIntermediateCsrRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIntermediateCsrRequest")
            .field("parent_ca_id", &self.parent_ca_id)
            .field("csr_pem", &format_args!("[{} bytes]", self.csr_pem.len()))
            .field("validity_days", &self.validity_days)
            .finish()
    }
}

/// `POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`
///
/// Create a tenant signing CA beneath one of the organization's CAs, with the
/// key generated by whoever the deployment's custodian is. The private key is
/// returned exactly once — and not at all under `vault_pki`, where it was born
/// inside Vault and no API exports it.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = CreateIntermediateCaRequest,
    responses(
        (status = 201, description = "Tenant signing CA created",
         body = GeneratedCaCertificate),
        (status = 400, description = "The parent CA is revoked, expired, holds no key, \
                                      or is itself a tenant signing CA"),
    ),
    security(("bearer" = []))
)]
pub async fn generate_intermediate<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateIntermediateCaRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (org_id, tenant_id) = path.into_inner();
    require_own_org(&user, org_id)?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    //
    // The per-TENANT form, because this one names a tenant. The organization's
    // CA does the signing, but what comes out belongs to `tenant_id` alone — so
    // an organization-level account restricted to that tenant is exactly who
    // should be able to do it, and the unrestricted form would refuse the
    // administrator the tenant was given one for.
    crate::handlers::org_scope::require_organization_principal_for_tenant(
        &user,
        state.get_ref(),
        tenant_id,
    )
    .await?;

    let req = body.into_inner();
    let result = state
        .pki
        .ca_service
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id,
            parent_ca_id: req.parent_ca_id,
            subject: req.subject,
            key_algorithm: req.key_algorithm,
            validity_days: req.validity_days,
        })
        .await?;
    Ok(HttpResponse::Created().json(result))
}

/// `POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr`
///
/// Sign a certificate signing request the tenant produced elsewhere. The
/// response has no `private_key_pem` because the key never reached AXIAM: it is
/// wherever the CSR was made, and that is the point of this endpoint rather
/// than a shortcoming of it.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = SignIntermediateCsrRequest,
    responses(
        (status = 201, description = "CSR signed as a tenant signing CA", body = CaCertificate),
        (status = 400, description = "The request is not a valid PKCS#10 CSR, its signature \
                                      does not verify, or the parent CA cannot sign"),
    ),
    security(("bearer" = []))
)]
pub async fn sign_intermediate_csr<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
    body: web::Json<SignIntermediateCsrRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (org_id, tenant_id) = path.into_inner();
    require_own_org(&user, org_id)?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    //
    // The per-TENANT form, because this one names a tenant. The organization's
    // CA does the signing, but what comes out belongs to `tenant_id` alone — so
    // an organization-level account restricted to that tenant is exactly who
    // should be able to do it, and the unrestricted form would refuse the
    // administrator the tenant was given one for.
    crate::handlers::org_scope::require_organization_principal_for_tenant(
        &user,
        state.get_ref(),
        tenant_id,
    )
    .await?;

    let req = body.into_inner();
    let certificate = state
        .pki
        .ca_service
        .sign_intermediate_csr(SignIntermediateCsr {
            organization_id: org_id,
            tenant_id,
            parent_ca_id: req.parent_ca_id,
            csr_pem: req.csr_pem,
            validity_days: req.validity_days,
        })
        .await?;
    Ok(HttpResponse::Created().json(certificate))
}

/// `GET /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
    tag = "ca-certificates",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        Pagination,
    ),
    responses(
        (status = 200, description = "List of tenant signing CAs",
         body = inline(PaginatedResult<CaCertificate>)),
    ),
    security(("bearer" = []))
)]
pub async fn list_intermediates<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<(Uuid, Uuid)>,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (org_id, tenant_id) = path.into_inner();
    require_own_org(&user, org_id)?;

    let result = state
        .pki
        .ca_service
        .list_by_tenant(org_id, tenant_id, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// Refuse a path that names an organization other than the caller's own.
///
/// The same check the four older handlers in this module each spell out inline.
/// Extracted here rather than restated a fifth, sixth and seventh time: this is
/// the whole of the tenancy boundary on these routes, and a copy that drifted
/// would be a copy that let one organization read another's CAs.
fn require_own_org(user: &AuthenticatedUser, org_id: Uuid) -> Result<(), AxiamApiError> {
    if org_id == user.org_id {
        return Ok(());
    }
    Err(AxiamApiError(
        axiam_core::error::AxiamError::AuthorizationDenied {
            reason: "cannot access a different organization".into(),
            action: None,
            resource_id: None,
        },
    ))
}
