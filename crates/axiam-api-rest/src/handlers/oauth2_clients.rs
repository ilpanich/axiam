//! OAuth2 client management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::oauth2_client::{
    ClientAuthMethod, ClientProfile, CreateOAuth2Client, OAuth2Client, UpdateOAuth2Client,
};
use axiam_core::repository::{OAuth2ClientRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOAuth2ClientRequest {
    /// Human-readable name for the client.
    pub name: String,
    /// Allowed redirect URIs (must be HTTPS, except localhost for dev).
    /// SEC-089: this list doubles as the token-exchange audience allow-list
    /// — adding a URI here also authorises it as a token audience for this
    /// client, so review additions on exchange-capable clients with that in
    /// mind (see `docs/api/token-exchange.md#audience`).
    pub redirect_uris: Vec<String>,
    /// Grant types this client is authorized to use.
    pub grant_types: Vec<String>,
    /// Scopes the client may request.
    pub scopes: Vec<String>,
    /// B5 — allow-list for RP-initiated logout's `post_logout_redirect_uri`.
    /// Separate from `redirect_uris` on purpose: that list receives
    /// authorization codes, this one receives a browser after logout.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// B5 — where OIDC back-channel logout tokens are delivered. Omit for a
    /// client that does not participate.
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// B5 — require this client to push its authorization parameters to
    /// `/oauth2/par` (RFC 9126) rather than sending them through the browser.
    #[serde(default)]
    pub require_par: bool,
    /// X5.1 — the security posture this client is registered under.
    ///
    /// `"standard"` (the default) is every AXIAM client that has ever existed.
    /// `"fapi2"` turns on the whole FAPI 2.0 constraint bundle at once, and
    /// the registration is refused unless it also sets `require_par`, a strong
    /// `token_endpoint_auth_method` (either mTLS method or `private_key_jwt`),
    /// and at least one sender-constraining mechanism
    /// (`tls_client_certificate_bound_access_tokens` or
    /// `dpop_bound_access_tokens`). See the FAPI operator guide.
    #[serde(default)]
    pub profile: ClientProfile,
    /// X5.1 — how this client authenticates at the token endpoint
    /// (RFC 8705 §2). Defaults to `client_secret_post`.
    #[serde(default)]
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// RFC 8705 §2.1.2 — expected certificate subject DN, RFC 4514 form.
    /// Exactly one of the three `tls_client_auth_*` parameters may be set.
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    /// RFC 8705 §2.1.2 — expected `dNSName` SAN.
    #[serde(default)]
    pub tls_client_auth_san_dns: Option<String>,
    /// RFC 8705 §2.1.2 — expected `uniformResourceIdentifier` SAN.
    #[serde(default)]
    pub tls_client_auth_san_uri: Option<String>,
    /// Accepted certificate thumbprints for `self_signed_tls_client_auth`,
    /// as base64url-unpadded SHA-256 digests of the DER certificate (the same
    /// `x5t#S256` encoding as the `cnf` claim). More than one permits an
    /// overlapping rotation.
    #[serde(default)]
    pub self_signed_tls_client_auth_thumbprints: Vec<String>,
    /// RFC 8705 §3.4 — issue certificate-bound (sender-constrained) access
    /// tokens to this client. Independent of the authentication method.
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    /// RFC 7591 §2 — the client's public key set, inline, for
    /// `private_key_jwt`. Exactly one of `jwks` and `jwks_uri` may be set.
    #[serde(default)]
    pub jwks: Option<String>,
    /// RFC 7591 §2 — where the client publishes its public key set. Must be an
    /// absolute `https` URL, and is fetched through the SSRF-guarded JWKS
    /// cache, which refuses private and loopback addresses.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// RFC 9449 §5.2 — issue DPoP-bound (sender-constrained) access tokens to
    /// this client. Independent of both the authentication method and
    /// `tls_client_certificate_bound_access_tokens`; a client may ask for both
    /// constraints, and a token carrying both must satisfy both.
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    /// RFC 9449 §8 — require this client's DPoP proofs to carry a
    /// server-issued nonce.
    ///
    /// **Not implemented in this build (SEC-097).** `true` is refused with
    /// `400`; only `false` (the default) is accepted. Nothing reads the stored
    /// value, so accepting `true` would persist and echo back a security
    /// switch that does nothing. DPoP proofs are made single-use at the token
    /// endpoint by `jti` replay detection instead — see
    /// `docs/security-profiles.md`.
    #[serde(default)]
    pub dpop_require_nonce: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOAuth2ClientRequest {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Pass an empty string to clear a previously registered URI — the one
    /// edit an operator makes when an RP is decommissioned.
    pub backchannel_logout_uri: Option<String>,
    pub require_par: Option<bool>,
    /// X5.1 — see [`CreateOAuth2ClientRequest::profile`].
    pub profile: Option<ClientProfile>,
    pub token_endpoint_auth_method: Option<ClientAuthMethod>,
    /// Pass an empty string to clear, as with `backchannel_logout_uri`.
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_san_dns: Option<String>,
    pub tls_client_auth_san_uri: Option<String>,
    pub self_signed_tls_client_auth_thumbprints: Option<Vec<String>>,
    pub tls_client_certificate_bound_access_tokens: Option<bool>,
    /// X5.1 — see the create DTO. `Some("")` clears, so a client can be
    /// migrated from an inline key set to a published one.
    pub jwks: Option<String>,
    /// X5.1 — see the create DTO. `Some("")` clears.
    pub jwks_uri: Option<String>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub dpop_require_nonce: Option<bool>,
}

/// OAuth2 client response -- omits client_secret_hash.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2ClientResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    /// X5.1 — the registered posture and mTLS credentials. Read-back matters:
    /// an operator auditing which clients are financial-grade should be able
    /// to answer it from this endpoint rather than from the database.
    pub profile: ClientProfile,
    pub token_endpoint_auth_method: ClientAuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_auth_san_uri: Option<String>,
    pub self_signed_tls_client_auth_thumbprints: Vec<String>,
    pub tls_client_certificate_bound_access_tokens: bool,
    /// X5.1 — echoed so an operator can confirm which key source is registered.
    /// The document itself is public key material, so returning it leaks
    /// nothing; a `jwks_uri` is likewise public by construction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub dpop_bound_access_tokens: bool,
    pub dpop_require_nonce: bool,
    pub require_par: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<OAuth2Client> for OAuth2ClientResponse {
    fn from(c: OAuth2Client) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            client_id: c.client_id,
            name: c.name,
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            profile: c.profile,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            tls_client_auth_subject_dn: c.tls_client_auth_subject_dn,
            tls_client_auth_san_dns: c.tls_client_auth_san_dns,
            tls_client_auth_san_uri: c.tls_client_auth_san_uri,
            self_signed_tls_client_auth_thumbprints: c.self_signed_tls_client_auth_thumbprints,
            tls_client_certificate_bound_access_tokens: c
                .tls_client_certificate_bound_access_tokens,
            jwks: c.jwks,
            jwks_uri: c.jwks_uri,
            dpop_bound_access_tokens: c.dpop_bound_access_tokens,
            dpop_require_nonce: c.dpop_require_nonce,
            require_par: c.require_par,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Response for client creation -- includes the one-time plaintext secret.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2ClientCreatedResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// SEC-097 — refuse `dpop_require_nonce: true` while nothing reads it.
///
/// The field is persisted, echoed back by `GET`, and documented in the OpenAPI
/// schema, and **no code path consults it**: the token endpoint passes
/// `require_nonce: false` unconditionally because this deployment stores no
/// per-client nonce to compare an echoed one against, so a challenge would
/// prove liveness and nothing else.
///
/// An operator who sets a security switch, sees it persisted and echoed back,
/// and gets nothing has been told a lie by the API. Refusing at the point of
/// action is the same shape as SEC-101's transport check and is the only
/// answer that does not require the operator to read `handlers/oauth2.rs` to
/// discover the truth. The field itself is kept — removing it would be a wire
/// break across seven SDKs for a value that is always `false` anyway — and
/// this check is what a future nonce implementation deletes.
fn reject_unimplemented_dpop_nonce(requested: Option<bool>) -> Result<(), AxiamApiError> {
    if requested == Some(true) {
        return Err(validation_err(
            "dpop_require_nonce is not implemented in this build: nothing reads the stored \
             value, so setting it would persist a security switch that does nothing. DPoP \
             proofs are already made single-use at the token endpoint by jti replay \
             detection (RFC 9449 §11.1). See docs/security-profiles.md.",
        ));
    }
    Ok(())
}

/// Grant types a client may be registered for through this API.
///
/// This list MUST stay in step with what the token endpoint actually honours.
/// Until 2026-08-15 it omitted the device-code and token-exchange grants, so
/// `device_service::DEVICE_CODE_GRANT_TYPE` and
/// `token_exchange::TOKEN_EXCHANGE_GRANT_TYPE` — both required by their
/// respective flows, and both shipped — were rejected here as
/// "unknown grant_type". That made B2 (device flow) and B3 (token exchange)
/// unreachable through the admin API: their tests pass only because they build
/// `OAuth2Client` values directly and never cross this validator.
///
/// `device_code` (the bare form) is accepted alongside the URN because
/// `device_service` honours both.
///
/// Deliberately NOT included: `urn:axiam:params:oauth:grant-type:may-impersonate`.
/// It is a capability marker, not a grant, and whether an admin-API caller may
/// confer impersonation is a security decision that has not been taken. Leaving
/// it out preserves the existing posture — impersonation stays settable only
/// out-of-band.
const KNOWN_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    axiam_oauth2::device_service::DEVICE_CODE_GRANT_TYPE,
    "device_code",
    axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE,
];

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

fn validate_redirect_uris(uris: &[String]) -> Result<(), AxiamApiError> {
    if uris.is_empty() {
        return Err(validation_err("redirect_uris must not be empty"));
    }
    for uri in uris {
        let parsed: url::Url = uri
            .parse()
            .map_err(|_| validation_err(format!("invalid redirect_uri: {uri}")))?;
        // Redirect URIs must be absolute with an authority (host)
        let host = parsed.host_str().ok_or_else(|| {
            validation_err(format!(
                "redirect_uri must be an absolute URL with a host: {uri}"
            ))
        })?;
        // Allow http for localhost/loopback only, require HTTPS otherwise
        let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_localhost) {
            return Err(validation_err(format!(
                "redirect_uri must use https (http is only allowed for localhost/127.0.0.1/::1): {uri}"
            )));
        }
        // RFC 6749 §3.1.2: redirect URIs must not include a fragment
        if parsed.fragment().is_some() {
            return Err(validation_err(format!(
                "redirect_uri must not contain a fragment: {uri}"
            )));
        }
    }
    Ok(())
}

fn validate_grant_types(grant_types: &[String]) -> Result<(), AxiamApiError> {
    if grant_types.is_empty() {
        return Err(validation_err("grant_types must not be empty"));
    }
    for gt in grant_types {
        if !KNOWN_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(validation_err(format!(
                "unknown grant_type: {gt} (allowed: {})",
                KNOWN_GRANT_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/oauth2-clients`
#[utoipa::path(
    post,
    path = "/api/v1/oauth2-clients",
    tag = "oauth2-clients",
    request_body = CreateOAuth2ClientRequest,
    responses(
        (status = 201, description = "OAuth2 client created (secret shown once)",
         body = OAuth2ClientCreatedResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateOAuth2ClientRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();

    if req.name.is_empty() {
        return Err(validation_err("name must not be empty"));
    }
    validate_grant_types(&req.grant_types)?;
    reject_unimplemented_dpop_nonce(Some(req.dpop_require_nonce))?;
    // redirect_uris are only required when the client uses
    // authorization_code (which involves user-agent redirects).
    // M2M clients (client_credentials only) don't need them.
    let needs_redirects = req.grant_types.iter().any(|g| g == "authorization_code");
    if needs_redirects {
        validate_redirect_uris(&req.redirect_uris)?;
    }

    let create = CreateOAuth2Client {
        tenant_id: user.tenant_id,
        name: req.name,
        redirect_uris: req.redirect_uris,
        grant_types: req.grant_types,
        scopes: req.scopes,
        post_logout_redirect_uris: req.post_logout_redirect_uris,
        backchannel_logout_uri: req.backchannel_logout_uri,
        require_par: req.require_par,
        profile: req.profile,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        tls_client_auth_subject_dn: req.tls_client_auth_subject_dn,
        tls_client_auth_san_dns: req.tls_client_auth_san_dns,
        tls_client_auth_san_uri: req.tls_client_auth_san_uri,
        self_signed_tls_client_auth_thumbprints: req.self_signed_tls_client_auth_thumbprints,
        tls_client_certificate_bound_access_tokens: req.tls_client_certificate_bound_access_tokens,
        jwks: req.jwks,
        jwks_uri: req.jwks_uri,
        dpop_bound_access_tokens: req.dpop_bound_access_tokens,
        dpop_require_nonce: req.dpop_require_nonce,
    };

    // X5.1 — refuse a registration that could not satisfy the profile it
    // declares, BEFORE it is written. A `fapi2` client missing PAR or mTLS
    // would otherwise be created and then fail every request it ever made,
    // which is a configuration error discovered by the client's users rather
    // than by the operator making it. A `standard` client with a secret — every
    // client that predates X5.1 — passes without a check running.
    axiam_oauth2::fapi::validate_registration(&create)
        .map_err(|e| validation_err(e.to_string()))?;

    let (client, raw_secret) = state.oauth2_client_repo.create(create).await?;

    Ok(HttpResponse::Created().json(OAuth2ClientCreatedResponse {
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.client_id,
        client_secret: raw_secret,
        name: client.name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.scopes,
        created_at: client.created_at,
        updated_at: client.updated_at,
    }))
}

/// `GET /api/v1/oauth2-clients`
#[utoipa::path(
    get,
    path = "/api/v1/oauth2-clients",
    tag = "oauth2-clients",
    params(Pagination),
    responses(
        (status = 200, description = "List of OAuth2 clients",
         body = inline(PaginatedResult<OAuth2ClientResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .oauth2_client_repo
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    let response = PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(OAuth2ClientResponse::from)
            .collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `GET /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    responses(
        (status = 200, description = "OAuth2 client found",
         body = OAuth2ClientResponse),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let client = state
        .oauth2_client_repo
        .get_by_id(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::Ok().json(OAuth2ClientResponse::from(client)))
}

/// `PUT /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    request_body = UpdateOAuth2ClientRequest,
    responses(
        (status = 200, description = "OAuth2 client updated",
         body = OAuth2ClientResponse),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<UpdateOAuth2ClientRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let req = body.into_inner();

    if let Some(ref name) = req.name
        && name.is_empty()
    {
        return Err(validation_err("name must not be empty"));
    }
    if let Some(ref gts) = req.grant_types {
        validate_grant_types(gts)?;
    }
    reject_unimplemented_dpop_nonce(req.dpop_require_nonce)?;
    if let Some(ref uris) = req.redirect_uris {
        let needs_redirects = req
            .grant_types
            .as_ref()
            .map(|gts| gts.iter().any(|g| g == "authorization_code"))
            .unwrap_or(true);
        if needs_redirects {
            validate_redirect_uris(uris)?;
        }
    }

    // When adding authorization_code to grant_types, ensure the
    // client will have valid redirect_uris (either supplied in this
    // request or already stored).
    let adding_auth_code = req
        .grant_types
        .as_ref()
        .is_some_and(|gts| gts.iter().any(|g| g == "authorization_code"));
    if adding_auth_code && req.redirect_uris.is_none() {
        let existing = state
            .oauth2_client_repo
            .get_by_id(user.tenant_id, id)
            .await?;
        if existing.redirect_uris.is_empty() {
            return Err(validation_err(
                "redirect_uris are required when enabling \
                 authorization_code grant",
            ));
        }
        validate_redirect_uris(&existing.redirect_uris)?;
    }

    let update = UpdateOAuth2Client {
        name: req.name,
        redirect_uris: req.redirect_uris,
        grant_types: req.grant_types,
        scopes: req.scopes,
        post_logout_redirect_uris: req.post_logout_redirect_uris,
        backchannel_logout_uri: req.backchannel_logout_uri,
        require_par: req.require_par,
        profile: req.profile,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        tls_client_auth_subject_dn: req.tls_client_auth_subject_dn,
        tls_client_auth_san_dns: req.tls_client_auth_san_dns,
        tls_client_auth_san_uri: req.tls_client_auth_san_uri,
        self_signed_tls_client_auth_thumbprints: req.self_signed_tls_client_auth_thumbprints,
        tls_client_certificate_bound_access_tokens: req.tls_client_certificate_bound_access_tokens,
        jwks: req.jwks,
        jwks_uri: req.jwks_uri,
        dpop_bound_access_tokens: req.dpop_bound_access_tokens,
        dpop_require_nonce: req.dpop_require_nonce,
    };

    // X5.1 — validate the MERGED result, not the patch. Flipping `profile` to
    // `fapi2` on a client that has none of the rest is a perfectly well-formed
    // patch and a completely broken client; validating the patch alone would
    // wave it through. The extra read happens only when the patch touches a
    // profile-relevant field, so an ordinary rename still costs one write.
    if update.touches_security_profile() {
        let merged = state
            .oauth2_client_repo
            .get_by_id(user.tenant_id, id)
            .await?
            .with_update_applied(&update);
        axiam_oauth2::fapi::validate_registration(&merged)
            .map_err(|e| validation_err(e.to_string()))?;
    }

    let client = state
        .oauth2_client_repo
        .update(user.tenant_id, id, update)
        .await?;
    Ok(HttpResponse::Ok().json(OAuth2ClientResponse::from(client)))
}

/// `DELETE /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    responses(
        (status = 204, description = "OAuth2 client deleted"),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state.oauth2_client_repo.delete(user.tenant_id, id).await?;
    Ok(HttpResponse::NoContent().finish())
}
