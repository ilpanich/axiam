//! SAML service-provider registry and IdP signing-credential management
//! (G-2, T23.2.5, contract §29).
//!
//! Eleven routes under `/api/v1/tenants/{tenant_id}/saml`, in the `saml` OpenAPI
//! tag. **Compiled into every build** (D-42), with or without the `saml` Cargo
//! feature: the registry is plain data, its validator is outside the feature and
//! the credential service is `axiam-pki`'s, so an SDK can reach them from the
//! committed `openapi.json`. Only [`parse_sp_metadata`] needs `samael` and
//! answers `503` in a build without it. **They do not depend on the tenant's
//! `saml_idp_enabled`**: an administrator registers SPs and issues the
//! credential *before* switching the IdP on (D-20's own reasoning); the setting
//! governs the browser routes only.
//!
//! The routes are thin. What a registration may be is decided by
//! `axiam_federation::saml_sp` (the validator and the D-42 refusals), what a
//! credential is by `axiam_pki::SamlIdpCredentialService`, and what a metadata
//! document means by `axiam_federation::saml_idp::sp_metadata`; this module
//! **calls** them on every write and turns the answers into the statuses §29.3
//! pins.
//!
//! # What every write does, in this order
//!
//! 1. the **permission** — `saml_sp:read` for the reads, `saml_sp:write` for the
//!    SP writes and `parse_sp_metadata`, `saml_idp:credential` for the three
//!    credential writes, kept apart because one of them can stop sign-on at
//!    every SP of the tenant (T-364) — and the **tenant fence**: the path tenant
//!    must be the caller's (`403`, T-357). A service-account token never gets
//!    this far: the extractor takes human principals only (`saml_sp` and
//!    `saml_idp` are human-only permission families), so it is refused with the
//!    same `401` as on every other human-only route;
//! 2. the validator, then the four D-42 refusals (`400`, each naming its rule);
//! 3. the write, with the datastore's uniqueness answers as `409 conflict`;
//! 4. one audit row, with the actor, the ids and the **names** of what changed —
//!    never a certificate, a document or a key (T-362).
//!
//! # No key, ever
//!
//! [`SamlIdpCredential`] is a response type of its own — certificate, serial,
//! fingerprint, dates, status, issuer CA — built from
//! `axiam_core::models::saml_idp_credential::SamlIdpCredential`, which carries no
//! key field, and never from the sealed type (T-365). The core type derives no
//! `Serialize`, so a route cannot expose the row by accident.

use actix_web::error::JsonPayloadError;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredential as StoredCredential, SamlIdpCredentialStatus as StoredStatus,
};
use axiam_core::models::saml_sp::{SamlServiceProvider, SamlServiceProviderInput};
use axiam_core::repository::{
    AuditLogRepository, PaginatedResult, Pagination, SamlServiceProviderRepository,
    SettingsRepository, TenantRepository,
};
use axiam_federation::saml_idp_urls::{idp_entity_id, idp_slo_url, idp_sso_url};
use axiam_federation::saml_sp::validate_saml_service_provider_write;
use axiam_pki::IssuingScope;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// Audit action: a service provider was registered.
pub const AUDIT_SP_CREATED: &str = "saml_sp.created";
/// Audit action: a service provider's registration was replaced.
pub const AUDIT_SP_UPDATED: &str = "saml_sp.updated";
/// Audit action: a service provider was deleted.
pub const AUDIT_SP_DELETED: &str = "saml_sp.deleted";
/// Audit action: SP metadata was parsed into a draft (or refused).
pub const AUDIT_SP_METADATA_PARSED: &str = "saml_sp.metadata_parsed";
/// Audit action: an IdP signing credential was issued.
pub const AUDIT_CREDENTIAL_ISSUED: &str = "saml_idp.credential_issued";
/// Audit action: the `next` credential was promoted to `active`.
pub const AUDIT_CREDENTIAL_PROMOTED: &str = "saml_idp.credential_promoted";
/// Audit action: an IdP signing credential was retired.
pub const AUDIT_CREDENTIAL_RETIRED: &str = "saml_idp.credential_retired";

/// The default and the largest `validity_days` of an issued credential.
const DEFAULT_VALIDITY_DAYS: i64 = 365;
const MAX_VALIDITY_DAYS: i64 = axiam_pki::MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS as i64;

// ---------------------------------------------------------------------------
// Response and request shapes (CONTRACT §29.2)
// ---------------------------------------------------------------------------

/// Where a signing credential is in its life. An open set: an SDK decodes a
/// value it does not know without failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamlIdpCredentialStatus {
    /// Signs the assertions the tenant issues now.
    Active,
    /// Published in metadata, not yet signing.
    Next,
    /// Out of metadata and out of use; its key is destroyed.
    Retired,
}

impl From<StoredStatus> for SamlIdpCredentialStatus {
    fn from(status: StoredStatus) -> Self {
        match status {
            StoredStatus::Active => Self::Active,
            StoredStatus::Next => Self::Next,
            StoredStatus::Retired => Self::Retired,
        }
    }
}

/// The tenant's IdP signing credential, **public facts only**.
///
/// There is no key on it and no field a key could be put in: the private key is
/// generated by the server, sealed at rest, never returned by any route and
/// destroyed on retirement (D-21).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlIdpCredential {
    /// Credential id.
    pub id: Uuid,
    /// The tenant it signs for.
    pub tenant_id: Uuid,
    /// The signing CA that issued the leaf.
    pub issuer_ca_id: Uuid,
    /// The leaf certificate, PEM. Public: it is what the metadata publishes.
    pub certificate_pem: String,
    /// The certificate's serial, lower-case hex.
    pub serial: String,
    /// Lower-case hex SHA-256 of the certificate's DER — what an SP
    /// administrator compares out of band.
    pub fingerprint: String,
    /// Start of the certificate's validity.
    pub not_before: DateTime<Utc>,
    /// End of the certificate's validity (at most 730 days after the start).
    pub not_after: DateTime<Utc>,
    /// `active`, `next` or `retired`. At most one `active` and one `next` per
    /// tenant.
    pub status: SamlIdpCredentialStatus,
    /// When the credential was issued.
    pub created_at: DateTime<Utc>,
    /// When it was retired, or null.
    pub retired_at: Option<DateTime<Utc>>,
}

impl From<StoredCredential> for SamlIdpCredential {
    fn from(c: StoredCredential) -> Self {
        // Field by field, so that a field added to the stored type is not on the
        // wire until someone decides it should be.
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            issuer_ca_id: c.issuer_ca_id,
            certificate_pem: c.certificate_pem,
            serial: c.serial,
            fingerprint: c.fingerprint,
            not_before: c.not_before,
            not_after: c.not_after,
            status: c.status.into(),
            created_at: c.created_at,
            retired_at: c.retired_at,
        }
    }
}

/// What promoting the `next` credential did.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlIdpCredentialPromotion {
    /// The credential that is now `active`.
    pub active: SamlIdpCredential,
    /// The one it replaced, now `retired`, or null when there was none.
    pub retired: Option<SamlIdpCredential>,
}

/// The tenant's SAML IdP, as the administrator needs to see it before and while
/// switching it on: what an SP will be given, and whether it answers yet.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlIdpInfo {
    /// The tenant.
    pub tenant_id: Uuid,
    /// Whether this server build serves SAML at all (it was built with the
    /// `saml` feature).
    pub saml_available: bool,
    /// The tenant's **effective** `saml_idp_enabled` setting (D-20). Written
    /// through the `settings` operations, not here.
    pub saml_idp_enabled: bool,
    /// Whether `metadata_url` answers now: SAML is available, enabled for the
    /// tenant, and an `active` or `next` credential exists (D-40).
    pub metadata_served: bool,
    /// The IdP's entity id (the metadata URL itself).
    pub entity_id: String,
    /// Where the IdP metadata is served.
    pub metadata_url: String,
    /// The single-sign-on endpoint.
    pub sso_url: String,
    /// The single-logout endpoint.
    pub slo_url: String,
    /// The `active` credential, or null.
    pub active_credential_id: Option<Uuid>,
    /// The `next` credential, or null.
    pub next_credential_id: Option<Uuid>,
}

/// Which slot a credential is issued into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamlIdpSlot {
    /// Signs at once. The usual choice for a tenant's first credential.
    Active,
    /// Published in metadata first; promoted later (the safe rotation).
    Next,
}

/// `POST …/saml/idp-credentials` body.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct IssueSamlIdpCredential {
    /// An active signing CA the caller may issue from.
    pub issuer_ca_id: Uuid,
    /// The slot to fill; it must be empty.
    pub slot: SamlIdpSlot,
    /// 1 to 730, default 365; never beyond the CA's own expiry.
    #[serde(default)]
    #[schema(minimum = 1, maximum = 730, default = 365)]
    pub validity_days: Option<i64>,
}

/// `POST …/saml/parse-sp-metadata` body: **exactly one** of the two members.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ParseSamlSpMetadata {
    /// A metadata document, at most 512 KiB.
    #[serde(default)]
    pub metadata_xml: Option<String>,
    /// An `https` URL the server fetches the document from, once, through its
    /// SSRF guard.
    #[serde(default)]
    pub metadata_url: Option<String>,
}

/// A parse of SP metadata: **a draft, not a registration**. Nothing is stored
/// until the caller submits `service_provider` to `create_service_provider` or
/// `update_service_provider`, and nothing in it is trusted because it came from
/// a document (D-41).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlSpMetadataDraft {
    /// A body `create_service_provider` accepts unchanged (bar the rules that
    /// need the datastore). `encrypt_assertions` is never set.
    pub service_provider: SamlServiceProviderInput,
    /// Lower-case hex SHA-256 of the signing certificate's DER the draft
    /// carries, or null.
    pub signing_certificate_fingerprint: Option<String>,
    /// Lower-case hex SHA-256 of the encryption certificate's DER the draft
    /// carries, or null.
    pub encryption_certificate_fingerprint: Option<String>,
    /// What to know before submitting it. Human text; do not parse it.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// JSON extractor configuration
// ---------------------------------------------------------------------------

/// The ordinary request-size limit of the registry routes. A registration with
/// 32 ACS endpoints, 64 mappings, 256 groups and two 16 KiB certificates fits
/// with room to spare.
const REGISTRY_BODY_LIMIT: usize = 131_072;
/// The limit of the metadata-parse route: a 512 KiB document, JSON-escaped.
const PARSE_BODY_LIMIT: usize = 1_048_576;

fn json_error(err: &JsonPayloadError, what: &str, scrub: bool) -> AxiamApiError {
    let message = match err {
        JsonPayloadError::Deserialize(inner) if scrub => format!(
            "the request body is not a valid {what}: {}",
            super::directory::scrub_serde_message(&inner.to_string())
        ),
        JsonPayloadError::Deserialize(_) => format!("the request body is not a valid {what}"),
        JsonPayloadError::ContentType => "the request body must be application/json".to_string(),
        JsonPayloadError::Overflow { .. } | JsonPayloadError::OverflowKnownLength { .. } => {
            "the request body is too large".to_string()
        }
        _ => "the request body could not be read".to_string(),
    };
    AxiamApiError(AxiamError::Validation { message })
}

/// The JSON configuration of the registry and credential routes: a body limit
/// and a `400 validation_error` for a body that cannot be read, never serde's
/// text with a quoted value.
pub fn registry_json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(REGISTRY_BODY_LIMIT)
        .error_handler(|err: JsonPayloadError, _req: &HttpRequest| {
            json_error(&err, "SAML registry request", true).into()
        })
}

/// The JSON configuration of `parse_sp_metadata`: a 512 KiB document fits, and
/// the answer to a body that cannot be read says nothing about it.
pub fn parse_json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(PARSE_BODY_LIMIT)
        .error_handler(|err: JsonPayloadError, _req: &HttpRequest| {
            json_error(&err, "metadata import request", false).into()
        })
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `{tenant_id}` must be the caller's tenant, as for `directory` and
/// `email_config`.
fn require_own_tenant(
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    what: &str,
) -> Result<(), AxiamApiError> {
    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: format!("cannot {what} for a different tenant"),
            action: None,
            resource_id: None,
        }));
    }
    Ok(())
}

fn conflict(reason: &str) -> AxiamApiError {
    AxiamApiError(AxiamError::Conflict {
        reason: reason.to_owned(),
    })
}

fn validation(message: impl Into<String>) -> AxiamApiError {
    AxiamApiError(AxiamError::Validation {
        message: message.into(),
    })
}

/// Lower-case hex SHA-256 of the DER of a PEM certificate, or `None`.
fn certificate_fingerprint(pem: &str) -> Option<String> {
    let der = axiam_federation::cert::pem_cert_to_der(pem).ok()?;
    Some(hex::encode(Sha256::digest(der)))
}

/// One audit row, never failing the request: the write it describes has been
/// done, or refused, already.
#[allow(clippy::too_many_arguments)] // an audit row is this wide
async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    action: &str,
    resource_id: Option<Uuid>,
    outcome: AuditOutcome,
    metadata: serde_json::Value,
) {
    if let Err(error) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user.user_id,
            actor_type: ActorType::User,
            action: action.to_string(),
            resource_id,
            outcome,
            ip_address: client_ip(http_req),
            metadata: Some(metadata),
        })
        .await
    {
        tracing::error!(
            target: "axiam::saml_admin",
            %tenant_id,
            action,
            %error,
            "a SAML registry audit row could not be written"
        );
    }
}

/// What the registry's write-time rules that need the datastore say: every
/// `allowed_groups` entry must be a group of this tenant (D-42).
async fn check_allowed_groups<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    input: &SamlServiceProviderInput,
) -> Result<(), AxiamApiError> {
    if input.allowed_groups.is_empty() {
        return Ok(());
    }
    let outside = state
        .saml_idp
        .sp_repo
        .groups_outside_tenant(tenant_id, &input.allowed_groups)
        .await?;
    if outside.is_empty() {
        return Ok(());
    }
    Err(validation(format!(
        "allowed_groups names {} group(s) that are not groups of this tenant",
        outside.len()
    )))
}

/// The names of the registration's members that `new` changes relative to `old`.
/// Names only: never a value, so no certificate, URL or mapping reaches the
/// audit log through this list.
fn changed_fields(old: &SamlServiceProvider, new: &SamlServiceProviderInput) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut note = |differs: bool, name: &'static str| {
        if differs {
            out.push(name);
        }
    };
    note(old.enabled != new.enabled, "enabled");
    note(old.display_name != new.display_name, "display_name");
    note(old.entity_id != new.entity_id, "entity_id");
    note(old.acs_urls != new.acs_urls, "acs_urls");
    note(old.slo_url != new.slo_url, "slo_url");
    note(old.slo_binding != new.slo_binding, "slo_binding");
    note(old.name_id_format != new.name_id_format, "name_id_format");
    note(old.sign_responses != new.sign_responses, "sign_responses");
    note(
        old.encrypt_assertions != new.encrypt_assertions,
        "encrypt_assertions",
    );
    note(
        old.sp_signing_cert_pem != new.sp_signing_cert_pem,
        "sp_signing_cert_pem",
    );
    note(
        old.sp_encryption_cert_pem != new.sp_encryption_cert_pem,
        "sp_encryption_cert_pem",
    );
    note(
        old.want_authn_requests_signed != new.want_authn_requests_signed,
        "want_authn_requests_signed",
    );
    note(
        old.allow_idp_initiated != new.allow_idp_initiated,
        "allow_idp_initiated",
    );
    note(
        old.attribute_mappings != new.attribute_mappings,
        "attribute_mappings",
    );
    note(old.allowed_groups != new.allowed_groups, "allowed_groups");
    out
}

/// The issuing scope this caller acts with: [`IssuingScope::Organization`] only
/// for a principal whose own record lives in the organization's reserved scope
/// (resolved from the caller's own tenant, never from the request); everyone
/// else is confined to the signing CA of the tenant being acted on. This route
/// takes human principals only, so the machine exclusion of
/// `org_scope::is_organization_principal` is already the extractor's.
async fn issuing_scope<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
) -> IssuingScope {
    match state.tenant_repo.get_by_id(user.principal_tenant_id).await {
        Ok(home) if home.is_organization_scope() => IssuingScope::Organization,
        _ => IssuingScope::Tenant,
    }
}

/// A repeated `entity_id` and an occupied slot are `409 conflict` (§29.3 rules 3
/// and 7), whatever datastore message they came from.
fn conflict_from_already_exists(error: AxiamError, reason: &str) -> AxiamApiError {
    match error {
        AxiamError::AlreadyExists { .. } => conflict(reason),
        other => AxiamApiError(other),
    }
}

// ---------------------------------------------------------------------------
// GET …/saml/idp
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/saml/idp`
///
/// The tenant's IdP as an SP will meet it, and whether it answers yet:
/// readiness is visible only here, never on the unauthenticated metadata route
/// (T-368).
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/saml/idp",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    responses(
        (status = 200, description = "The tenant's SAML IdP: its URLs, whether SAML is available \
                                      in this build and enabled for the tenant, and its \
                                      credential slots", body = SamlIdpInfo),
        (status = 403, description = "Another tenant's IdP"),
    ),
    security(("bearer" = []))
)]
pub async fn get_idp<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "read the SAML IdP")?;

    let settings = state
        .settings_repo
        .get_effective_settings(user.org_id, tenant_id)
        .await?;
    let credentials = state.saml_idp.credential_service.list(tenant_id).await?;
    let slot = |wanted: StoredStatus| {
        credentials
            .iter()
            .find(|c| c.status == wanted)
            .map(|c| c.id)
    };
    let active_credential_id = slot(StoredStatus::Active);
    let next_credential_id = slot(StoredStatus::Next);

    let base = state.auth_config.root_issuer();
    let saml_available = cfg!(feature = "saml");
    let saml_idp_enabled = settings.oidc.saml_idp_enabled;
    let entity_id = idp_entity_id(base, tenant_id);
    Ok(HttpResponse::Ok().json(SamlIdpInfo {
        tenant_id,
        saml_available,
        saml_idp_enabled,
        metadata_served: saml_available
            && saml_idp_enabled
            && (active_credential_id.is_some() || next_credential_id.is_some()),
        metadata_url: entity_id.clone(),
        entity_id,
        sso_url: idp_sso_url(base, tenant_id),
        slo_url: idp_slo_url(base, tenant_id),
        active_credential_id,
        next_credential_id,
    }))
}

// ---------------------------------------------------------------------------
// Service providers
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/saml/service-providers`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/saml/service-providers",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID"), Pagination),
    responses(
        (status = 200, description = "A page of the tenant's service providers, oldest first; \
                                      `search` matches display name, entity id and id, before \
                                      paging",
         body = inline(PaginatedResult<SamlServiceProvider>)),
        (status = 403, description = "Another tenant's registry"),
    ),
    security(("bearer" = []))
)]
pub async fn list_service_providers<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "list service providers")?;
    let page = state
        .saml_idp
        .sp_repo
        .list_page(tenant_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(page))
}

/// `POST /api/v1/tenants/{tenant_id}/saml/service-providers`
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/saml/service-providers",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = SamlServiceProviderInput,
    responses(
        (status = 201, description = "The service provider was registered", body = SamlServiceProvider),
        (status = 400, description = "A validator refusal, `encrypt_assertions: true`, a signing \
                                      certificate the SSO endpoint cannot use, or an \
                                      `allowed_groups` entry outside the tenant — the message \
                                      names the rule"),
        (status = 403, description = "Another tenant's registry"),
        (status = 409, description = "The tenant already has a service provider with this entity id"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn create_service_provider<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<SamlServiceProviderInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "register a service provider")?;

    let input = body.into_inner();
    validate_saml_service_provider_write(&input)?;
    check_allowed_groups(&state, tenant_id, &input).await?;

    let created = state
        .saml_idp
        .sp_repo
        .create(tenant_id, input)
        .await
        .map_err(|e| {
            conflict_from_already_exists(
                e,
                "a service provider with this entity_id is already registered in this tenant",
            )
        })?;

    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_SP_CREATED,
        Some(created.id),
        AuditOutcome::Success,
        serde_json::json!({
            "entity_id": created.entity_id,
            "enabled": created.enabled,
            "acs_count": created.acs_urls.len(),
            "signing_certificate_fingerprint":
                created.sp_signing_cert_pem.as_deref().and_then(certificate_fingerprint),
        }),
    )
    .await;
    Ok(HttpResponse::Created().json(created))
}

/// `GET /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}",
    tag = "saml",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("sp_id" = Uuid, Path, description = "Service provider ID"),
    ),
    responses(
        (status = 200, description = "The service provider", body = SamlServiceProvider),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such service provider in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn get_service_provider<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, sp_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "read a service provider")?;
    let found = state.saml_idp.sp_repo.get(tenant_id, sp_id).await?;
    Ok(HttpResponse::Ok().json(found))
}

/// `PUT /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}` — a
/// **replacement**: every member the body omits takes its default, it is not
/// kept. `entity_id` is immutable.
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}",
    tag = "saml",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("sp_id" = Uuid, Path, description = "Service provider ID"),
    ),
    request_body = SamlServiceProviderInput,
    responses(
        (status = 200, description = "The registration after the replacement", body = SamlServiceProvider),
        (status = 400, description = "A validator refusal, one of the write-time refusals, or a \
                                      changed `entity_id` (register a new service provider)"),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such service provider in this tenant"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn update_service_provider<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<SamlServiceProviderInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, sp_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "replace a service provider")?;

    let stored = state.saml_idp.sp_repo.get(tenant_id, sp_id).await?;
    let input = body.into_inner();
    // The pairwise `NameID` of every user is keyed on the entity id (D-22), so a
    // change would give every user a new, unknown account at that SP.
    if input.entity_id != stored.entity_id {
        return Err(validation(
            "entity_id cannot be changed: register a new service provider \
             (the pairwise NameID of every user is keyed on it)",
        ));
    }
    validate_saml_service_provider_write(&input)?;
    check_allowed_groups(&state, tenant_id, &input).await?;

    let changed = changed_fields(&stored, &input);
    let updated = state
        .saml_idp
        .sp_repo
        .update(tenant_id, sp_id, input)
        .await
        .map_err(|e| {
            conflict_from_already_exists(
                e,
                "a service provider with this entity_id is already registered in this tenant",
            )
        })?;

    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_SP_UPDATED,
        Some(updated.id),
        AuditOutcome::Success,
        serde_json::json!({
            "entity_id": updated.entity_id,
            "changed_fields": changed,
            "acs_changed": changed.contains(&"acs_urls"),
            "certificate_changed":
                changed.contains(&"sp_signing_cert_pem") || changed.contains(&"sp_encryption_cert_pem"),
        }),
    )
    .await;
    Ok(HttpResponse::Ok().json(updated))
}

/// `DELETE /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}`
///
/// Removes the registration and what the datastore holds for it, in one
/// transaction. Ends no session: users already signed in to the SP stay signed
/// in there until their SP session ends.
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}",
    tag = "saml",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("sp_id" = Uuid, Path, description = "Service provider ID"),
    ),
    responses(
        (status = 204, description = "The registration and its records are gone"),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such service provider in this tenant"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_service_provider<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, sp_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "delete a service provider")?;

    let stored = state.saml_idp.sp_repo.get(tenant_id, sp_id).await?;
    state.saml_idp.sp_repo.delete(tenant_id, sp_id).await?;
    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_SP_DELETED,
        Some(stored.id),
        AuditOutcome::Success,
        serde_json::json!({ "entity_id": stored.entity_id }),
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// SP metadata import (D-41)
// ---------------------------------------------------------------------------

/// The host of a URL the administrator supplied, for the audit row — the host
/// only: no path, no query, no credentials.
fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.chars().take(255).collect()))
}

/// `POST /api/v1/tenants/{tenant_id}/saml/parse-sp-metadata`
///
/// **A parse to a draft, never a write.** Takes exactly one of `metadata_xml`
/// and `metadata_url` and returns what a registration of that SP could look
/// like, the fingerprints of the certificates it carries and warnings. A URL is
/// fetched once, through the SSRF guard (`https` only; loopback, private,
/// link-local and cloud-metadata addresses refused; every redirect hop checked);
/// a document is refused if it holds a DTD or entity declaration, is not UTF-8,
/// is over 512 KiB, or is not exactly one `EntityDescriptor` with one SAML 2.0
/// `SPSSODescriptor`. Every refusal is a generic message that never carries the
/// document, a status line or an address. The document's own signature is not
/// evaluated.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/saml/parse-sp-metadata",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = ParseSamlSpMetadata,
    responses(
        (status = 200, description = "A draft registration; nothing was stored", body = SamlSpMetadataDraft),
        (status = 400, description = "Not exactly one of `metadata_xml` and `metadata_url`, or \
                                      one of the generic refusals: `metadata_url refused`, \
                                      `metadata fetch failed`, `not SAML service-provider \
                                      metadata`"),
        (status = 403, description = "Another tenant's registry"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "This server was built without SAML support"),
    ),
    security(("bearer" = []))
)]
pub async fn parse_sp_metadata<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<ParseSamlSpMetadata>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "import SP metadata")?;

    let ParseSamlSpMetadata {
        metadata_xml,
        metadata_url,
    } = body.into_inner();
    let (source, url_host_for_audit) = match (&metadata_xml, &metadata_url) {
        (Some(_), None) => ("upload", None),
        (None, Some(url)) => ("url", url_host(url)),
        _ => {
            return Err(validation(
                "exactly one of metadata_xml and metadata_url is required",
            ));
        }
    };

    match import_metadata(metadata_xml, metadata_url).await {
        Ok(draft) => {
            audit(
                &state,
                &http_req,
                &user,
                tenant_id,
                AUDIT_SP_METADATA_PARSED,
                None,
                AuditOutcome::Success,
                serde_json::json!({
                    "source": source,
                    "url_host": url_host_for_audit,
                    "outcome": "parsed",
                    "warnings": draft.warnings.len(),
                }),
            )
            .await;
            Ok(HttpResponse::Ok().json(draft))
        }
        Err(failure) => {
            audit(
                &state,
                &http_req,
                &user,
                tenant_id,
                AUDIT_SP_METADATA_PARSED,
                None,
                AuditOutcome::Failure,
                serde_json::json!({
                    "source": source,
                    "url_host": url_host_for_audit,
                    "outcome": failure.category(),
                }),
            )
            .await;
            Err(failure.into_api_error())
        }
    }
}

/// Why an import produced no draft. A refusal carries one of the three generic
/// messages and its audit category; nothing else about the document or the
/// response ever reaches the answer.
enum ImportFailure {
    // Only a build with `saml` has a parser to refuse a document.
    #[cfg_attr(not(feature = "saml"), allow(dead_code))]
    Refused {
        message: &'static str,
        category: &'static str,
    },
    /// The build has no SAML support.
    #[cfg(not(feature = "saml"))]
    Unavailable,
}

impl ImportFailure {
    /// The answer: a `400` carrying the generic message, or the `503` of a build
    /// without SAML.
    fn into_api_error(self) -> AxiamApiError {
        match self {
            Self::Refused { message, .. } => validation(message),
            #[cfg(not(feature = "saml"))]
            Self::Unavailable => AxiamApiError(AxiamError::ServiceUnavailable(
                "this server was built without SAML support".into(),
            )),
        }
    }

    const fn category(&self) -> &'static str {
        match self {
            Self::Refused { category, .. } => category,
            #[cfg(not(feature = "saml"))]
            Self::Unavailable => "saml_unavailable",
        }
    }
}

/// Fetch (for a URL) and parse the metadata. The parser is `samael`'s, so a build
/// without `saml` has none and answers [`ImportFailure::Unavailable`].
#[cfg(feature = "saml")]
async fn import_metadata(
    xml: Option<String>,
    url: Option<String>,
) -> Result<SamlSpMetadataDraft, ImportFailure> {
    use axiam_federation::saml_idp::sp_metadata::{
        MAX_SP_METADATA_BYTES, MetadataError, fetch_sp_metadata, parse_sp_metadata,
    };
    let refused = |error: MetadataError| ImportFailure::Refused {
        message: error.message(),
        category: error.category(),
    };
    let document = match (xml, url) {
        (Some(xml), _) => {
            if xml.len() > MAX_SP_METADATA_BYTES {
                return Err(refused(MetadataError::NotSpMetadata));
            }
            xml.into_bytes()
        }
        // `false`: the guard's address and scheme rules in full. The `true` of its
        // test seam is never passed by a route.
        (None, Some(url)) => fetch_sp_metadata(&url, false).await.map_err(refused)?,
        (None, None) => return Err(refused(MetadataError::NotSpMetadata)),
    };
    let draft = parse_sp_metadata(&document).map_err(refused)?;
    Ok(SamlSpMetadataDraft {
        service_provider: draft.service_provider,
        signing_certificate_fingerprint: draft.signing_certificate_fingerprint,
        encryption_certificate_fingerprint: draft.encryption_certificate_fingerprint,
        warnings: draft.warnings,
    })
}

/// A build without `saml` has no metadata parser (`samael` is behind the feature).
#[cfg(not(feature = "saml"))]
async fn import_metadata(
    _xml: Option<String>,
    _url: Option<String>,
) -> Result<SamlSpMetadataDraft, ImportFailure> {
    Err(ImportFailure::Unavailable)
}

// ---------------------------------------------------------------------------
// IdP signing credentials (D-21, D-42)
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/saml/idp-credentials`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/saml/idp-credentials",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    responses(
        (status = 200, description = "Every credential of the tenant, newest first — public facts \
                                      only, never a key", body = Vec<SamlIdpCredential>),
        (status = 403, description = "Another tenant's credentials"),
    ),
    security(("bearer" = []))
)]
pub async fn list_idp_credentials<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_sp:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "list IdP credentials")?;
    let mut credentials = state.saml_idp.credential_service.list(tenant_id).await?;
    credentials.reverse();
    Ok(HttpResponse::Ok().json(
        credentials
            .into_iter()
            .map(SamlIdpCredential::from)
            .collect::<Vec<_>>(),
    ))
}

/// `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials`
///
/// Generates an RSA-4096 key and a leaf under `issuer_ca_id` into an **empty**
/// slot. Takes seconds. The key is sealed at rest and never returned.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/saml/idp-credentials",
    tag = "saml",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = IssueSamlIdpCredential,
    responses(
        (status = 201, description = "The credential was issued; the key is not returned", body = SamlIdpCredential),
        (status = 400, description = "`validity_days` outside 1 to 730, or a CA that cannot sign \
                                      (revoked, expired, imported or externally held)"),
        (status = 403, description = "Another tenant's credentials"),
        (status = 404, description = "No such CA within this caller's reach (another \
                                      organization's or another tenant's)"),
        (status = 409, description = "The slot is occupied"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn issue_idp_credential<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<IssueSamlIdpCredential>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_idp:credential", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "issue an IdP credential")?;

    let request = body.into_inner();
    let validity_days = request.validity_days.unwrap_or(DEFAULT_VALIDITY_DAYS);
    if !(1..=MAX_VALIDITY_DAYS).contains(&validity_days) {
        return Err(validation(format!(
            "validity_days must be between 1 and {MAX_VALIDITY_DAYS}"
        )));
    }
    let status = match request.slot {
        SamlIdpSlot::Active => StoredStatus::Active,
        SamlIdpSlot::Next => StoredStatus::Next,
    };
    // The scope comes from the principal, never the body (DF-017).
    let scope = issuing_scope(&user, &state).await;

    // The service checks the slot first, so an occupied one is a `409` that costs
    // no RSA-4096 key generation (T-363).
    let issued = state
        .saml_idp
        .credential_service
        .issue(
            user.org_id,
            tenant_id,
            scope,
            request.issuer_ca_id,
            u32::try_from(validity_days).unwrap_or(u32::MAX),
            status,
        )
        .await
        .map_err(|e| {
            conflict_from_already_exists(
                e,
                "the slot is occupied: retire the credential in it, or promote the next one",
            )
        })?;

    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_CREDENTIAL_ISSUED,
        Some(issued.id),
        AuditOutcome::Success,
        serde_json::json!({
            "credential_id": issued.id,
            "issuer_ca_id": issued.issuer_ca_id,
            "slot": issued.status.as_str(),
            "fingerprint": issued.fingerprint,
            "validity_days": validity_days,
        }),
    )
    .await;
    Ok(HttpResponse::Created().json(SamlIdpCredential::from(issued)))
}

/// `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/promote`
///
/// In **one transaction**, retires the `active` credential (its key destroyed)
/// and makes the `next` one `active`. The id must be the tenant's current `next`
/// credential and inside its validity window.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/promote",
    tag = "saml",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("credential_id" = Uuid, Path, description = "The tenant's current `next` credential"),
    ),
    responses(
        (status = 200, description = "The credential now active, and the one it replaced", body = SamlIdpCredentialPromotion),
        (status = 403, description = "Another tenant's credentials"),
        (status = 404, description = "No such credential in this tenant"),
        (status = 409, description = "The credential is not the current `next`, or is outside its \
                                      validity window"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn promote_idp_credential<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_idp:credential", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, credential_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "promote an IdP credential")?;

    let promotion = state
        .saml_idp
        .credential_service
        .promote(tenant_id, credential_id)
        .await?;
    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_CREDENTIAL_PROMOTED,
        Some(promotion.active.id),
        AuditOutcome::Success,
        serde_json::json!({
            "credential_id": promotion.active.id,
            "slot_from": "next",
            "slot_to": "active",
            "fingerprint": promotion.active.fingerprint,
            "retired_credential_id": promotion.retired.as_ref().map(|c| c.id),
            "retired_fingerprint": promotion.retired.as_ref().map(|c| c.fingerprint.clone()),
        }),
    )
    .await;
    Ok(HttpResponse::Ok().json(SamlIdpCredentialPromotion {
        active: promotion.active.into(),
        retired: promotion.retired.map(Into::into),
    }))
}

/// `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/retire`
///
/// Retires a `next` or an `active` credential and destroys its key. Retiring the
/// **`active`** one with no successor stops SAML sign-on for the whole tenant at
/// once — the incident response to a leaked key. Retiring a retired credential
/// returns it unchanged and writes no audit row.
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/retire",
    tag = "saml",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("credential_id" = Uuid, Path, description = "Credential ID"),
    ),
    responses(
        (status = 200, description = "The credential, retired (or as it already was)", body = SamlIdpCredential),
        (status = 403, description = "Another tenant's credentials"),
        (status = 404, description = "No such credential in this tenant"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn retire_idp_credential<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("saml_idp:credential", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, credential_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "retire an IdP credential")?;

    let service = &state.saml_idp.credential_service;
    // Read first: an unknown id is `404`, and a credential that is already retired
    // is answered as it is, with nothing written and nothing audited.
    let before = service
        .list(tenant_id)
        .await?
        .into_iter()
        .find(|c| c.id == credential_id)
        .ok_or_else(|| {
            AxiamApiError(AxiamError::NotFound {
                entity: "saml_idp_credential".into(),
                id: credential_id.to_string(),
            })
        })?;
    if before.status == StoredStatus::Retired {
        return Ok(HttpResponse::Ok().json(SamlIdpCredential::from(before)));
    }

    let retired = service.retire(tenant_id, credential_id).await?;
    let still_active = service.get_active(tenant_id).await?.is_some();
    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_CREDENTIAL_RETIRED,
        Some(retired.id),
        AuditOutcome::Success,
        serde_json::json!({
            "credential_id": retired.id,
            "slot": before.status.as_str(),
            "fingerprint": retired.fingerprint,
            "tenant_has_active_credential": still_active,
        }),
    )
    .await;
    Ok(HttpResponse::Ok().json(SamlIdpCredential::from(retired)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::ca_keys::CaKeyCustody;

    fn stored(status: StoredStatus) -> StoredCredential {
        StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            issuer_ca_id: Uuid::new_v4(),
            certificate_pem: "cert".into(),
            serial: "01".into(),
            fingerprint: "ab".into(),
            not_before: Utc::now(),
            not_after: Utc::now(),
            status,
            key_custody: CaKeyCustody::Database,
            created_at: Utc::now(),
            retired_at: None,
        }
    }

    #[test]
    fn the_credential_response_has_exactly_the_contract_members_and_no_custody() {
        let json = serde_json::to_value(SamlIdpCredential::from(stored(StoredStatus::Next)))
            .expect("serialise");
        let mut members: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        members.sort_unstable();
        assert_eq!(
            members,
            [
                "certificate_pem",
                "created_at",
                "fingerprint",
                "id",
                "issuer_ca_id",
                "not_after",
                "not_before",
                "retired_at",
                "serial",
                "status",
                "tenant_id"
            ]
        );
        assert_eq!(json["status"], "next");
        assert!(json["retired_at"].is_null(), "present, as null");
    }

    #[test]
    fn a_url_host_is_the_host_only() {
        assert_eq!(
            url_host("https://user:pw@sp.example.test:8443/path?q=1#f").as_deref(),
            Some("sp.example.test")
        );
        assert_eq!(url_host("not a url"), None);
    }
}
