//! OIDC federation management endpoints (tenant-scoped via JWT).
//!
//! Provides CRUD for federation configurations, the OIDC authorization
//! and callback flow, and federation link management.

use actix_web::{HttpResponse, web};
use axiam_core::models::federation::{
    CreateFederationConfig, FederationConfig, FederationLink, FederationProtocol, SubjectMapping,
    TokenExchangeTrust, UpdateFederationConfig,
};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, PaginatedResult, Pagination,
    UserRepository,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_core::error::AxiamError;
use axiam_core::repository::{
    FederationLoginStateRepository, OrganizationRepository, TenantRepository,
};
use axiam_federation::secrets::{current_key_version, encrypt_client_secret};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

/// X4 trust for exchanging this provider's tokens (RFC 8693, external issuer).
///
/// Mirrors [`TokenExchangeTrust`] on the wire rather than reusing it directly
/// so the API surface can carry its own defaults: an admin PUTting a partial
/// block gets the documented default for anything they omitted, instead of a
/// deserialization error listing fields they have never heard of.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct TokenExchangeTrustRequest {
    /// Off unless explicitly enabled. Configuring a provider for *login* is
    /// not agreement to accept its tokens as API credentials.
    #[serde(default)]
    pub enabled: bool,
    /// Audiences an incoming subject token may name. Required (non-empty)
    /// when `enabled`; there is deliberately no accept-all value.
    #[serde(default)]
    pub accepted_audiences: Vec<String>,
    /// `linked_only` (default) or `jit_provision`.
    #[serde(default)]
    pub subject_mapping: Option<String>,
    /// External asserted value -> AXIAM scopes. Deny-by-default: an external
    /// value with no entry contributes nothing.
    #[serde(default)]
    pub scope_map: std::collections::BTreeMap<String, Vec<String>>,
    /// Bound on `now - iat`, independent of the token's own `exp`.
    #[serde(default)]
    pub max_token_age_secs: Option<i64>,
    /// Per-provider ceiling on the issued AXIAM token's lifetime.
    #[serde(default)]
    pub max_lifetime_secs: Option<i64>,
}

impl TokenExchangeTrustRequest {
    /// Convert and validate in one step.
    ///
    /// Validation happens **here**, at the edge, rather than in the
    /// repository: this is the only layer that can tell an operator *which*
    /// field they got wrong, and a trust block that reaches storage malformed
    /// is one an admin later enables without being told.
    fn into_domain(self) -> Result<TokenExchangeTrust, AxiamApiError> {
        let subject_mapping = match self.subject_mapping.as_deref() {
            None => SubjectMapping::default(),
            Some(raw) => SubjectMapping::from_wire(raw).ok_or_else(|| {
                validation_err(
                    "token_exchange.subject_mapping must be 'linked_only' or 'jit_provision'",
                )
            })?,
        };
        let trust = TokenExchangeTrust {
            enabled: self.enabled,
            accepted_audiences: self.accepted_audiences,
            subject_mapping,
            scope_map: self.scope_map,
            max_token_age_secs: self
                .max_token_age_secs
                .unwrap_or(axiam_core::models::federation::DEFAULT_MAX_TOKEN_AGE_SECS),
            max_lifetime_secs: self.max_lifetime_secs,
        };
        trust
            .validate()
            .map_err(|e| validation_err(e.to_string()))?;
        Ok(trust)
    }
}

/// X4 trust as returned. Same shape as the request; nothing here is secret —
/// an operator reading a provider needs to see exactly what it trusts.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenExchangeTrustResponse {
    pub enabled: bool,
    pub accepted_audiences: Vec<String>,
    pub subject_mapping: String,
    pub scope_map: std::collections::BTreeMap<String, Vec<String>>,
    pub max_token_age_secs: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_lifetime_secs: Option<i64>,
}

impl From<TokenExchangeTrust> for TokenExchangeTrustResponse {
    fn from(t: TokenExchangeTrust) -> Self {
        Self {
            enabled: t.enabled,
            accepted_audiences: t.accepted_audiences,
            subject_mapping: t.subject_mapping.as_str().to_owned(),
            scope_map: t.scope_map,
            max_token_age_secs: t.max_token_age_secs,
            max_lifetime_secs: t.max_lifetime_secs,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateFederationConfigRequest {
    /// Display name for the identity provider (e.g., "Google", "Okta").
    pub provider: String,
    /// Federation protocol: "OidcConnect" or "Saml".
    pub protocol: String,
    /// OIDC discovery URL or SAML metadata URL.
    pub metadata_url: Option<String>,
    /// OAuth2 client ID registered with the external IdP.
    pub client_id: String,
    /// OAuth2 client secret registered with the external IdP.
    pub client_secret: String,
    /// Maps external IdP attributes to AXIAM user fields.
    pub attribute_map: Option<serde_json::Value>,
    /// PEM-encoded X.509 certificate for verifying SAML assertions or
    /// OIDC signatures (CQ-B40/REQ-14 AC-5).  Required for SAML configs.
    pub idp_signing_cert_pem: Option<String>,
    /// Accepted JWT signing algorithms (OIDC) or signature algorithms (SAML).
    /// Defaults to `["RS256"]` when not provided (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
    /// X4 external token-exchange trust. Omitted means disabled.
    pub token_exchange: Option<TokenExchangeTrustRequest>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateFederationConfigRequest {
    pub provider: Option<String>,
    pub metadata_url: Option<Option<String>>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub attribute_map: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    /// PEM-encoded X.509 certificate for verifying SAML assertions
    /// (CQ-B40/REQ-14 AC-5).  `Some(None)` clears the stored cert.
    pub idp_signing_cert_pem: Option<Option<String>>,
    /// Accepted signature algorithms (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
    /// X4 external token-exchange trust. Replaced **wholesale** when present:
    /// a partial merge of a trust configuration is how an operator ends up
    /// keeping an `accepted_audiences` entry they believed they had removed.
    pub token_exchange: Option<TokenExchangeTrustRequest>,
}

/// Federation config response -- omits client_secret.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FederationConfigResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider: String,
    pub protocol: String,
    pub metadata_url: Option<String>,
    pub client_id: String,
    pub attribute_map: serde_json::Value,
    pub enabled: bool,
    /// X4 external token-exchange trust.
    pub token_exchange: TokenExchangeTrustResponse,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<FederationConfig> for FederationConfigResponse {
    fn from(c: FederationConfig) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            provider: c.provider,
            protocol: protocol_to_string(&c.protocol).to_owned(),
            metadata_url: c.metadata_url,
            client_id: c.client_id,
            attribute_map: c.attribute_map,
            enabled: c.enabled,
            token_exchange: c.token_exchange.into(),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OidcAuthorizeRequest {
    /// ID of the federation config to use.
    pub config_id: Uuid,
    /// Redirect URI the external IdP should return the user to.
    pub redirect_uri: String,
    /// CSRF state value (generated by the caller).
    pub state: String,
    /// Nonce for replay protection (generated by the caller).
    pub nonce: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OidcCallbackRequest {
    /// ID of the federation config used in the authorization request.
    pub config_id: Uuid,
    /// Authorization code returned by the external IdP.
    pub code: String,
    /// Redirect URI that was used in the authorization request.
    pub redirect_uri: String,
    /// CSRF state value from the authorization request. Used to look up the
    /// server-side `FederationLoginState` row that holds the real nonce
    /// (SECHRD-07/D-04) — required so the callback can find its login state.
    pub state: String,
    /// Client-supplied nonce (SECHRD-07/D-04: retained for backward
    /// compatibility with older callers, but IGNORED for verification —
    /// `expected_nonce` always comes from the server-side `FederationLoginState`
    /// row looked up via `state`, never from this field).
    pub nonce: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OidcAuthorizeResponse {
    /// The full authorization URL to redirect the user to.
    pub url: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OidcCallbackResponse {
    pub user_id: Uuid,
    pub federation_link_id: Uuid,
    pub newly_provisioned: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FederationLinkResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub federation_config_id: Uuid,
    pub external_subject: String,
    pub external_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<FederationLink> for FederationLinkResponse {
    fn from(l: FederationLink) -> Self {
        Self {
            id: l.id,
            tenant_id: l.tenant_id,
            user_id: l.user_id,
            federation_config_id: l.federation_config_id,
            external_subject: l.external_subject,
            external_email: l.external_email,
            created_at: l.created_at,
            updated_at: l.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

fn protocol_to_string(p: &FederationProtocol) -> &'static str {
    match p {
        FederationProtocol::OidcConnect => "OidcConnect",
        FederationProtocol::Saml => "Saml",
    }
}

// ---------------------------------------------------------------------------
// Federation Config CRUD
// ---------------------------------------------------------------------------

/// `POST /api/v1/federation-configs`
#[utoipa::path(
    post,
    path = "/api/v1/federation-configs",
    tag = "federation",
    request_body = CreateFederationConfigRequest,
    responses(
        (status = 201, description = "Federation config created",
         body = FederationConfigResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateFederationConfigRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();

    if req.provider.is_empty() {
        return Err(validation_err("provider must not be empty"));
    }
    if req.client_id.is_empty() {
        return Err(validation_err("client_id must not be empty"));
    }
    if req.client_secret.is_empty() {
        return Err(validation_err("client_secret must not be empty"));
    }
    if let Some(ref url) = req.metadata_url
        && url.is_empty()
    {
        return Err(validation_err("metadata_url must not be empty"));
    }

    let protocol = match req.protocol.as_str() {
        "OidcConnect" => FederationProtocol::OidcConnect,
        "Saml" => FederationProtocol::Saml,
        _ => return Err(validation_err("protocol must be 'OidcConnect' or 'Saml'")),
    };

    // X4: validated before anything is written, and refused outright on SAML.
    // A SAML provider has no issuer to match and no JWKS to verify against, so
    // an enabled trust block on one is not a harmless no-op — it is a claim in
    // the admin UI that tokens are being accepted when nothing could accept
    // them.
    let token_exchange = req.token_exchange.map(|t| t.into_domain()).transpose()?;
    if let Some(ref t) = token_exchange
        && t.enabled
        && protocol != FederationProtocol::OidcConnect
    {
        return Err(validation_err(
            "token_exchange is only supported for OidcConnect providers",
        ));
    }

    // Validate IdP signing cert PEM before storage so garbage certs are
    // rejected at upload rather than at assertion-verification time (CQ-B40).
    if let Some(ref pem) = req.idp_signing_cert_pem {
        axiam_federation::cert::validate_pem_cert(pem)
            .map_err(|e| validation_err(format!("idp_signing_cert_pem is invalid: {e}")))?;
    }

    let enc_key = state.auth_config.federation_encryption_key.ok_or_else(|| {
        AxiamApiError(AxiamError::Validation {
            message: "federation encryption key not configured".into(),
        })
    })?;

    // Encrypt the client_secret before any DB write (SEC-045).
    // Plaintext never reaches the DB layer.
    let (nonce_b64, ciphertext_b64) =
        encrypt_client_secret(&enc_key, &req.client_secret).map_err(|e| {
            AxiamApiError(AxiamError::Internal(format!(
                "failed to encrypt federation secret: {e}"
            )))
        })?;

    // Store with empty legacy plaintext (field required by schema; nulled by set_encrypted_secret).
    let config = state
        .federation
        .federation_config_repo
        .create(CreateFederationConfig {
            tenant_id: user.tenant_id,
            provider: req.provider,
            protocol,
            metadata_url: req.metadata_url,
            client_id: req.client_id,
            client_secret: String::new(), // plaintext never stored
            attribute_map: req.attribute_map,
            idp_signing_cert_pem: req.idp_signing_cert_pem,
            allowed_algorithms: req.allowed_algorithms,
            token_exchange,
        })
        .await?;

    // Write the encrypted secret columns (overwrites the empty plaintext row).
    state
        .federation
        .federation_config_repo
        .set_encrypted_secret(
            user.tenant_id,
            config.id,
            nonce_b64,
            ciphertext_b64,
            current_key_version(),
        )
        .await?;

    // Reload to return the canonical state (with ciphertext set, plaintext empty).
    let config = state
        .federation
        .federation_config_repo
        .get_by_id(user.tenant_id, config.id)
        .await?;

    Ok(HttpResponse::Created().json(FederationConfigResponse::from(config)))
}

/// `GET /api/v1/federation-configs`
#[utoipa::path(
    get,
    path = "/api/v1/federation-configs",
    tag = "federation",
    params(Pagination),
    responses(
        (status = 200, description = "List of federation configs",
         body = inline(PaginatedResult<FederationConfigResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .federation
        .federation_config_repo
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    let response = PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(FederationConfigResponse::from)
            .collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `GET /api/v1/federation-configs/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/federation-configs/{id}",
    tag = "federation",
    params(("id" = Uuid, Path, description = "Federation config ID")),
    responses(
        (status = 200, description = "Federation config found",
         body = FederationConfigResponse),
        (status = 404, description = "Federation config not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let config = state
        .federation
        .federation_config_repo
        .get_by_id(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::Ok().json(FederationConfigResponse::from(config)))
}

/// `PUT /api/v1/federation-configs/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/federation-configs/{id}",
    tag = "federation",
    params(("id" = Uuid, Path, description = "Federation config ID")),
    request_body = UpdateFederationConfigRequest,
    responses(
        (status = 200, description = "Federation config updated",
         body = FederationConfigResponse),
        (status = 404, description = "Federation config not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<UpdateFederationConfigRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let req = body.into_inner();

    if let Some(ref provider) = req.provider
        && provider.is_empty()
    {
        return Err(validation_err("provider must not be empty"));
    }
    if let Some(ref client_id) = req.client_id
        && client_id.is_empty()
    {
        return Err(validation_err("client_id must not be empty"));
    }
    if let Some(ref client_secret) = req.client_secret
        && client_secret.is_empty()
    {
        return Err(validation_err("client_secret must not be empty"));
    }
    if let Some(Some(ref url)) = req.metadata_url
        && url.is_empty()
    {
        return Err(validation_err("metadata_url must not be empty"));
    }

    // Validate new IdP signing cert PEM if provided (CQ-B40).
    if let Some(Some(ref pem)) = req.idp_signing_cert_pem {
        axiam_federation::cert::validate_pem_cert(pem)
            .map_err(|e| validation_err(format!("idp_signing_cert_pem is invalid: {e}")))?;
    }

    // X4: validated before the write, and refused on a SAML row for the same
    // reason `create` refuses it — the protocol is immutable after creation,
    // so the existing row's protocol is the one that matters.
    let token_exchange = req.token_exchange.map(|t| t.into_domain()).transpose()?;
    if let Some(ref t) = token_exchange
        && t.enabled
    {
        let existing = state
            .federation
            .federation_config_repo
            .get_by_id(user.tenant_id, id)
            .await?;
        if existing.protocol != FederationProtocol::OidcConnect {
            return Err(validation_err(
                "token_exchange is only supported for OidcConnect providers",
            ));
        }
    }

    // If the caller is rotating the client_secret, encrypt it before storage
    // (SEC-045). Plaintext never reaches the DB layer.
    let new_secret_plaintext = req.client_secret.clone();

    // Update non-secret fields via the standard update path (client_secret = None means
    // "no change to secret columns").
    let config = state
        .federation
        .federation_config_repo
        .update(
            user.tenant_id,
            id,
            UpdateFederationConfig {
                provider: req.provider,
                metadata_url: req.metadata_url,
                client_id: req.client_id,
                client_secret: None, // handled separately below
                attribute_map: req.attribute_map,
                enabled: req.enabled,
                idp_signing_cert_pem: req.idp_signing_cert_pem,
                allowed_algorithms: req.allowed_algorithms,
                token_exchange,
            },
        )
        .await?;

    // If a new secret was provided, encrypt and store it now.
    if let Some(ref plaintext) = new_secret_plaintext {
        let enc_key = state.auth_config.federation_encryption_key.ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })?;
        let (nonce_b64, ciphertext_b64) =
            encrypt_client_secret(&enc_key, plaintext).map_err(|e| {
                AxiamApiError(AxiamError::Internal(format!(
                    "failed to encrypt federation secret: {e}"
                )))
            })?;
        state
            .federation
            .federation_config_repo
            .set_encrypted_secret(
                user.tenant_id,
                config.id,
                nonce_b64,
                ciphertext_b64,
                current_key_version(),
            )
            .await?;
    }

    // Reload to return canonical state.
    let config = state
        .federation
        .federation_config_repo
        .get_by_id(user.tenant_id, config.id)
        .await?;
    Ok(HttpResponse::Ok().json(FederationConfigResponse::from(config)))
}

/// `DELETE /api/v1/federation-configs/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/federation-configs/{id}",
    tag = "federation",
    params(("id" = Uuid, Path, description = "Federation config ID")),
    responses(
        (status = 204, description = "Federation config deleted"),
        (status = 404, description = "Federation config not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state
        .federation
        .federation_config_repo
        .delete(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// OIDC Flow
// ---------------------------------------------------------------------------

/// `POST /api/v1/federation/oidc/authorize`
///
/// Builds the authorization URL for the external OIDC provider. The caller
/// is responsible for generating and storing `state` and `nonce` values
/// for CSRF and replay protection.
///
/// TODO(T19.9): This endpoint currently requires authentication, making it
/// usable only for account-linking (already-authenticated users). Add
/// separate unauthenticated federation login endpoints that complete the
/// external flow and return access/refresh tokens for first-time login.
#[utoipa::path(
    post,
    path = "/api/v1/federation/oidc/authorize",
    tag = "federation",
    request_body = OidcAuthorizeRequest,
    responses(
        (status = 200, description = "Authorization URL built successfully",
         body = OidcAuthorizeResponse),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn oidc_authorize<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    body: web::Json<OidcAuthorizeRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    if req.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }
    if req.nonce.is_empty() {
        return Err(validation_err("nonce must not be empty"));
    }

    // QUAL-07: OidcFederationService is now a hoisted AppState singleton
    // (Option — None when the federation encryption key is unconfigured,
    // resolved once at startup instead of per-request).
    let service = state
        .federation
        .oidc_federation_service
        .as_ref()
        .ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })?;

    // SECHRD-07/D-04: generate a server-side nonce and persist it in
    // FederationLoginState keyed by `req.state`. `req.nonce` (client-supplied)
    // is never stored or used for verification — mirrors
    // `oidc_start_public` (:1160-1211).
    let server_nonce = random_base64url();
    let expires_at = Utc::now() + chrono::Duration::minutes(10);

    let auth_url = service
        .build_authorization_url(
            user.tenant_id,
            req.config_id,
            &req.redirect_uri,
            &req.state,
            &server_nonce,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    state
        .federation
        .federation_login_state_repo
        .insert(&axiam_core::repository::FederationLoginState {
            state: req.state,
            nonce: server_nonce,
            tenant_id: user.tenant_id,
            federation_config_id: req.config_id,
            redirect_uri: req.redirect_uri,
            expires_at,
            request_id: String::new(), // OIDC — no request ID
        })
        .await?;

    Ok(HttpResponse::Ok().json(OidcAuthorizeResponse { url: auth_url.url }))
}

/// `POST /api/v1/federation/oidc/callback`
///
/// Handles the callback from the external OIDC provider after user
/// authentication. Exchanges the authorization code for tokens,
/// validates the ID token, and provisions or links the local user.
#[utoipa::path(
    post,
    path = "/api/v1/federation/oidc/callback",
    tag = "federation",
    request_body = OidcCallbackRequest,
    responses(
        (status = 200, description = "OIDC callback processed",
         body = OidcCallbackResponse),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn oidc_callback<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    body: web::Json<OidcCallbackRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.code.is_empty() {
        return Err(validation_err("code must not be empty"));
    }
    if req.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    if req.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }

    // QUAL-07: OidcFederationService is now a hoisted AppState singleton.
    let service = state
        .federation
        .oidc_federation_service
        .as_ref()
        .ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })?;

    // SECHRD-07/D-04: consume the server-side login state and derive
    // expected_nonce from it — req.nonce (client/attacker-supplied) is
    // IGNORED entirely for verification. Mirrors `oidc_callback_public`
    // (:1254-1267).
    let login_state = state
        .federation
        .federation_login_state_repo
        .consume_by_state(&req.state)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "state not found or expired".into(),
            })
        })?;
    let expected_nonce = login_state.nonce.clone();

    let result = service
        .handle_callback(
            user.tenant_id,
            req.config_id,
            &req.code,
            &req.redirect_uri,
            &expected_nonce,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok().json(OidcCallbackResponse {
        user_id: result.user.id,
        federation_link_id: result.federation_link.id,
        newly_provisioned: result.newly_provisioned,
    }))
}

// ---------------------------------------------------------------------------
// Federation Links
// ---------------------------------------------------------------------------

/// `GET /api/v1/federation-links/user/{user_id}`
#[utoipa::path(
    get,
    path = "/api/v1/federation-links/user/{user_id}",
    tag = "federation",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "Federation links for the user",
         body = Vec<FederationLinkResponse>),
    ),
    security(("bearer" = []))
)]
pub async fn list_user_links<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let target_user_id = path.into_inner();
    let links = state
        .federation
        .federation_link_repo
        .get_by_user_id(user.tenant_id, target_user_id)
        .await?;
    let response: Vec<FederationLinkResponse> = links
        .into_iter()
        .map(FederationLinkResponse::from)
        .collect();
    Ok(HttpResponse::Ok().json(response))
}

/// `DELETE /api/v1/federation-links/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/federation-links/{id}",
    tag = "federation",
    params(("id" = Uuid, Path, description = "Federation link ID")),
    responses(
        (status = 204, description = "Federation link deleted"),
        (status = 404, description = "Federation link not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_link<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("federation:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    state
        .federation
        .federation_link_repo
        .delete(user.tenant_id, id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// SAML SP Flow — DTOs
// ---------------------------------------------------------------------------

/// Request to build a SAML AuthnRequest.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlAuthnRequestRequest {
    /// ID of the SAML federation config.
    pub config_id: Uuid,
    /// Assertion Consumer Service URL where the IdP will POST the
    /// response.
    pub acs_url: String,
    /// Optional relay state to pass through the SSO flow.
    pub relay_state: Option<String>,
}

/// Response containing the SAML AuthnRequest details.
#[cfg(feature = "saml")]
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlAuthnRequestResponse {
    /// Full redirect URL (HTTP-Redirect) or IdP SSO URL (HTTP-POST).
    pub url: String,
    /// Base64-encoded AuthnRequest XML.
    pub saml_request: String,
    /// SAML binding URI (e.g.,
    /// `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`).
    pub binding: String,
    /// Relay state, if provided.
    pub relay_state: Option<String>,
}

/// Request to handle a SAML Response at the ACS endpoint.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlAcsRequest {
    /// ID of the SAML federation config.
    pub config_id: Uuid,
    /// Base64-encoded SAML Response XML from the IdP.
    pub saml_response: String,
    /// Relay state returned by the IdP.
    pub relay_state: Option<String>,
    /// The real Assertion Consumer Service URL this response was posted to.
    ///
    /// Required so the handler can validate `Response.Destination` against it
    /// (SECFIX-04/SEC-005) instead of skipping the check, and — since R1.5 —
    /// also the signed
    /// `SubjectConfirmationData/@Recipient` inside the assertion. This field is
    /// the single source of truth for both checks: `Destination` sits on the
    /// unsigned `<samlp:Response>` root and is attacker-rewritable, so the
    /// signed `@Recipient` is what actually proves the assertion was minted for
    /// *this* SP rather than relayed from another one.
    pub acs_url: String,
}

/// Query parameters for SP metadata generation.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlMetadataQuery {
    /// ID of the SAML federation config.
    pub config_id: Uuid,
    /// Assertion Consumer Service URL for the generated metadata.
    /// Must match the actual ACS endpoint URL for the deployment.
    pub acs_url: String,
}

// ---------------------------------------------------------------------------
// SAML SP Flow — Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/federation/saml/authn-request`
///
/// Builds a SAML AuthnRequest for the specified federation config.
/// Returns the SSO URL, encoded request, and binding type for the
/// caller to initiate the redirect or POST to the IdP.
#[cfg(feature = "saml")]
#[utoipa::path(
    post,
    path = "/api/v1/federation/saml/authn-request",
    tag = "federation",
    request_body = SamlAuthnRequestRequest,
    responses(
        (status = 200, description = "SAML AuthnRequest built",
         body = SamlAuthnRequestResponse),
    ),
    security(("bearer" = []))
)]
pub async fn saml_authn_request<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    body: web::Json<SamlAuthnRequestRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.acs_url.is_empty() {
        return Err(validation_err("acs_url must not be empty"));
    }

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    let result = state
        .federation
        .saml_federation_service
        .build_authn_request(user.tenant_id, req.config_id, &req.acs_url, req.relay_state)
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok().json(SamlAuthnRequestResponse {
        url: result.url,
        saml_request: result.saml_request,
        binding: result.binding,
        relay_state: result.relay_state,
    }))
}

/// `POST /api/v1/federation/saml/acs`
///
/// Handles the SAML Response received from the external IdP after
/// user authentication. Validates the assertion, extracts claims,
/// and provisions or links the local user.
#[cfg(feature = "saml")]
#[utoipa::path(
    post,
    path = "/api/v1/federation/saml/acs",
    tag = "federation",
    request_body = SamlAcsRequest,
    responses(
        (status = 200, description = "SAML ACS processed",
         body = OidcCallbackResponse),
    ),
    security(("bearer" = []))
)]
pub async fn saml_acs<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    body: web::Json<SamlAcsRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.saml_response.is_empty() {
        return Err(validation_err("saml_response must not be empty"));
    }
    if req.acs_url.is_empty() {
        return Err(validation_err("acs_url must not be empty"));
    }

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    let result = state
        .federation
        .saml_federation_service
        .handle_saml_response(
            user.tenant_id,
            req.config_id,
            &req.saml_response,
            req.relay_state.as_deref(),
            None, // no stored request ID on the authenticated ACS path
            // SECFIX-04 + R1.5/SEC-005: the ONE source of truth for "which ACS
            // endpoint is this?". Checked against the unsigned
            // `Response@Destination` AND against the signed
            // `SubjectConfirmationData@Recipient` inside the assertion, so a
            // relayed assertion minted for another SP is rejected even though
            // the attacker can rewrite `Destination` freely.
            Some(&req.acs_url),
            // SECFIX-04: require InResponseTo presence (reject unsolicited).
            // R1.5 note: this flag is also what makes the signed
            // `SubjectConfirmationData@InResponseTo` mandatory on this path —
            // AXIAM does not support IdP-initiated SSO.
            true,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok().json(OidcCallbackResponse {
        user_id: result.user.id,
        federation_link_id: result.federation_link.id,
        newly_provisioned: result.newly_provisioned,
    }))
}

/// `GET /api/v1/federation/saml/metadata`
///
/// Generates the SP metadata XML for the specified SAML federation
/// config. Returns XML with content type `application/samlmetadata+xml`.
#[cfg(feature = "saml")]
#[utoipa::path(
    get,
    path = "/api/v1/federation/saml/metadata",
    tag = "federation",
    params(
        ("config_id" = Uuid, Query, description = "SAML federation config ID"),
        ("acs_url" = String, Query, description = "ACS URL for the SP metadata"),
    ),
    responses(
        (status = 200, description = "SP metadata XML",
         content_type = "application/samlmetadata+xml"),
    ),
    security(("bearer" = []))
)]
pub async fn saml_metadata<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    query: web::Query<SamlMetadataQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    if query.acs_url.is_empty() {
        return Err(validation_err("acs_url must not be empty"));
    }

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    let xml = state
        .federation
        .saml_federation_service
        .generate_sp_metadata(user.tenant_id, query.config_id, &query.acs_url)
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    Ok(HttpResponse::Ok()
        .content_type("application/samlmetadata+xml")
        .body(xml))
}

// ---------------------------------------------------------------------------
// First-time SSO — PUBLIC endpoints (D-22)
//
// These four handlers are reachable WITHOUT a valid JWT (listed in
// PUBLIC_PATHS).  They are DISTINCT from the authenticated link-account
// endpoints above (/api/v1/federation/*), which continue to work unchanged.
//
// redirect_uri note: there are two kinds of redirect URI in this flow —
//   1. The IdP callback URL (server-side AXIAM endpoint): hard-coded from
//      the request Host header.  Not stored in the state row.
//   2. The SPA post-login destination: supplied by the caller and stored in
//      the state row so the callback can return it in the response body.
//      The SPA reads this field and routes the user after receiving cookies.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AuthSvc type alias (mirrors the one in handlers/auth.rs)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Request / response DTOs for the public SSO flow
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/auth/federation/oidc/start`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OidcStartRequest {
    pub org_id: Option<Uuid>,
    pub org_slug: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub tenant_slug: Option<String>,
    pub federation_config_id: Uuid,
    /// SPA post-login destination (stored server-side; returned in callback
    /// response body so the SPA can route after receiving cookies).
    pub redirect_uri: String,
}

/// Response body for `POST /api/v1/auth/federation/oidc/start`.
/// The nonce is intentionally omitted — it stays server-side (T-04-31).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OidcStartResponse {
    /// The IdP authorization URL to redirect the user to.
    pub authorize_url: String,
    /// CSRF state value (must be round-tripped through the IdP).
    pub state: String,
    /// Remaining TTL in seconds (10 min = 600).
    pub expires_in_secs: i64,
}

/// Request body for `POST /api/v1/auth/federation/oidc/callback`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OidcPublicCallbackRequest {
    pub state: String,
    pub code: String,
}

/// Request body for `POST /api/v1/auth/federation/saml/login`.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlLoginRequest {
    pub org_id: Option<Uuid>,
    pub org_slug: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub tenant_slug: Option<String>,
    pub federation_config_id: Uuid,
    /// SPA post-login destination (stored server-side).
    pub redirect_uri: String,
}

/// Response body for `POST /api/v1/auth/federation/saml/login`.
#[cfg(feature = "saml")]
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SamlLoginResponse {
    /// SAML binding URI.
    pub binding: String,
    /// IdP SSO URL to POST to.
    pub sso_url: String,
    /// Base64-encoded SAML AuthnRequest XML.
    pub saml_request_b64: String,
    /// RelayState carries our `state` value through the IdP round-trip.
    pub relay_state: String,
}

/// Request body for `POST /api/v1/auth/federation/saml/acs`.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SamlAcsPublicRequest {
    pub saml_response_b64: String,
    pub relay_state: String,
}

/// Returned by both OIDC callback and SAML ACS on success (alongside
/// Set-Cookie headers). The `redirect_uri` field allows the SPA to route
/// the user to the originally requested destination.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SsoLoginSuccessResponse {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub expires_in: u64,
    /// SPA destination URL stored during start/login.
    pub redirect_uri: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate 32 random bytes encoded as base64url (no padding).
fn random_base64url() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate that a redirect_uri is a well-formed absolute HTTPS (or HTTP
/// localhost) URL.  This is a minimal open-redirect guard — a full
/// per-config allowlist would require a schema change (deferred).
// TODO(T19.14): tighten open-redirect protection — add a per-FederationConfig
// registered redirect_uri allowlist (needs a schema column) instead of the
// current scheme/host-only guard. Tracked for Phase 19.
fn validate_redirect_uri(uri: &str) -> Result<(), AxiamApiError> {
    let parsed = url::Url::parse(uri).map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "redirect_uri is not a valid URL".into(),
        })
    })?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");
    let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if scheme == "https" || (scheme == "http" && is_localhost) {
        Ok(())
    } else {
        Err(AxiamApiError(AxiamError::Validation {
            message: "redirect_uri must use HTTPS (or HTTP for localhost)".into(),
        }))
    }
}

/// Fire `login.post_auth` on a federated sign-in (SEC-095).
///
/// # Why this exists
///
/// The reactor gate was wired into `AuthService::login` and nowhere else, so
/// the two public SSO handlers below — SAML ACS and the OIDC callback — issued
/// a full session plus access/refresh tokens without the gate ever being
/// consulted. Nothing in the event registry
/// (`axiam_core::models::reactor::events`) or in `sdks/CONTRACT.md` §22.5
/// scoped `login.post_auth` to password authentication; both describe it as
/// "After credentials verify, before session issuance". An operator who
/// registered the feature's own worked example — an embargoed-region login
/// veto — got a control that "Sign in with Okta" walked straight past.
///
/// It was latent at the time it was found only because
/// `UnavailableReactorTransport` meant no reactor reply could be produced at
/// all. R2.4 merged the lapin transport, so it is live now — closing it before
/// then is why it was closed at all rather than filed against the transport.
///
/// # What it is not
///
/// It is not a second implementation of the verdict logic. The payload and the
/// `ReactorOutcome` match live once, in
/// `AuthService::intercept_login_post_auth`, so all three sign-in paths get a
/// byte-identical payload and a new outcome variant is a compile error at one
/// site rather than a silent no-op at three. This function is only the
/// call-site adapter: it pulls the client IP and user agent off the request —
/// which the SSO handlers did not previously look at, and which a
/// region-based veto needs — and delegates.
///
/// `require_mfa` is refused rather than dropped, because a federated sign-in
/// has no step-up branch to route it into. See
/// `AuthService::intercept_federated_login_post_auth`.
async fn sso_login_post_auth<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    http_req: &actix_web::HttpRequest,
    tenant_id: Uuid,
    user: &axiam_core::models::user::User,
) -> Result<(), AxiamApiError> {
    use crate::extractors::client_info::{client_ip, user_agent};
    state
        .auth_service
        .intercept_federated_login_post_auth(
            tenant_id,
            // Nil for the same reason `create_session_and_tokens` is called
            // with a nil org below — see the T19.15 TODO at each call site.
            Uuid::nil(),
            user,
            client_ip(http_req).as_deref(),
            user_agent(http_req).as_deref(),
        )
        .await
        .map_err(AxiamApiError)
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/federation/oidc/start  (public)
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/federation/oidc/start`
///
/// Generates a server-side state+nonce pair, persists it in
/// `federation_login_state` (10-min TTL), and returns the IdP authorization
/// URL.  No JWT required — this is the first step of first-time SSO (D-22).
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/oidc/start",
    tag = "federation-sso",
    request_body = OidcStartRequest,
    responses(
        (status = 200, description = "OIDC start: authorize URL returned",
         body = OidcStartResponse),
        (status = 401, description = "Unknown org/tenant slug"),
        (status = 400, description = "Validation error"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn oidc_start_public<C: Connection + Clone>(
    // Named `app_state` (not `state`) — this handler already has a local
    // `state` variable (the OAuth2 CSRF state value).
    app_state: web::Data<AppState<C>>,
    body: web::Json<OidcStartRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    if b.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    validate_redirect_uri(&b.redirect_uri)?;

    // Resolve workspace identity (mirrors Phase 1 login — 401 on slug miss).
    let org_id = match (b.org_id, b.org_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            app_state
                .org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid federation request".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide org_id or org_slug".into(),
            }));
        }
    };
    let tenant_id = match (b.tenant_id, b.tenant_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            app_state
                .tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid federation request".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide tenant_id or tenant_slug".into(),
            }));
        }
    };

    // Generate server-side state + nonce (256 bits each).
    let state = random_base64url();
    let nonce = random_base64url();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // QUAL-07: OidcFederationService is now a hoisted AppState singleton.
    let service = app_state
        .federation
        .oidc_federation_service
        .as_ref()
        .ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })?;

    let auth_url = service
        .build_authorization_url(
            tenant_id,
            b.federation_config_id,
            &b.redirect_uri,
            &state,
            &nonce,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    // Persist the state row (single-use, 10-min TTL).
    app_state
        .federation
        .federation_login_state_repo
        .insert(&axiam_core::repository::FederationLoginState {
            state: state.clone(),
            nonce,
            tenant_id,
            federation_config_id: b.federation_config_id,
            redirect_uri: b.redirect_uri,
            expires_at,
            request_id: String::new(), // OIDC — no request ID
        })
        .await?;

    Ok(HttpResponse::Ok().json(OidcStartResponse {
        authorize_url: auth_url.url,
        state,
        expires_in_secs: 600,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/federation/oidc/callback  (public)
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/federation/oidc/callback`
///
/// Consumes the state row (single-use), runs the verified OIDC flow from
/// plan 04-02 (nonce from DB — not caller-supplied), provisions or links the
/// user, and returns Set-Cookie response (no token in body).
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/oidc/callback",
    tag = "federation-sso",
    request_body = OidcPublicCallbackRequest,
    responses(
        (status = 200, description = "OIDC callback: cookies set",
         body = SsoLoginSuccessResponse),
        (status = 401, description = "State not found or expired"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn oidc_callback_public<C: Connection + Clone>(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<OidcPublicCallbackRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    if b.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }
    if b.code.is_empty() {
        return Err(validation_err("code must not be empty"));
    }

    // Atomically consume the state row (single-use; expired → None → 401).
    let login_state = state
        .federation
        .federation_login_state_repo
        .consume_by_state(&b.state)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "state not found or expired".into(),
            })
        })?;

    let tenant_id = login_state.tenant_id;
    let config_id = login_state.federation_config_id;
    // Nonce comes from the state row — NOT from the HTTP body (T-04-30).
    let expected_nonce = login_state.nonce.clone();
    let spa_redirect_uri = login_state.redirect_uri.clone();

    // QUAL-07: OidcFederationService is now a hoisted AppState singleton.
    let service = state
        .federation
        .oidc_federation_service
        .as_ref()
        .ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })?;

    // The redirect_uri we pass to the IdP token endpoint is the AXIAM ACS
    // URL.  Since we built the authorize URL using the SPA redirect_uri as
    // the redirect_uri query param, we must echo the same value here.
    let callback_result = service
        .handle_callback(
            tenant_id,
            config_id,
            &b.code,
            &spa_redirect_uri,
            &expected_nonce,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    let user = callback_result.user;

    // SEC-095: `login.post_auth` fires here too, not only on the password
    // path. The IdP has just verified the credentials and no session exists
    // yet, which is exactly the contract the event's registry entry states —
    // "After credentials verify, before session issuance". Before this, a
    // reactor registered to veto logins (the feature's own worked example is
    // an embargoed-region veto) was bypassed by clicking "Sign in with Okta".
    //
    // `org_id` is `Uuid::nil()` for the same reason the token below carries a
    // nil `org_id` — see the TODO. A reactor keying on `org_id` on this path
    // therefore sees nil rather than a wrong value.
    sso_login_post_auth(&state, &http_req, tenant_id, &user).await?;

    // TODO(T19.15): resolve real org_id from the tenant instead of Uuid::nil().
    // SSO-provisioned access tokens currently carry an empty org_id claim.
    // Wire a tenant->org_id lookup here (and at the OIDC callback below). Phase 19.
    let auth_out = state
        .auth_service
        .create_session_and_tokens(user.id, tenant_id, Uuid::nil(), None, None)
        .await?;

    let csrf_token = crate::middleware::csrf::generate_csrf_token();
    let user_detail = state
        .user_repo
        .get_by_id(tenant_id, user.id)
        .await
        .map_err(|_| AxiamError::AuthenticationFailed {
            reason: "user not found after federation login".into(),
        })?;

    Ok(actix_web::HttpResponse::Ok()
        .cookie(crate::middleware::csrf::access_cookie(
            &auth_out.access_token,
            state.auth_config.access_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        .cookie(crate::middleware::csrf::refresh_cookie(
            &auth_out.refresh_token,
            state.auth_config.refresh_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        .cookie(crate::middleware::csrf::csrf_cookie(
            &csrf_token,
            state.auth_config.access_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        // See the matching comment on handlers/auth.rs's login handler —
        // non-browser SDKs capture the CSRF token from this header (the
        // same value already exposed via the non-httpOnly cookie above).
        .insert_header((crate::middleware::csrf::HEADER_CSRF, csrf_token.clone()))
        .json(SsoLoginSuccessResponse {
            user_id: user_detail.id,
            session_id: auth_out.session_id,
            expires_in: auth_out.expires_in,
            redirect_uri: spa_redirect_uri,
        }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/federation/saml/login  (public)
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/federation/saml/login`
///
/// Builds a SAML AuthnRequest, persists state, and returns the POST-binding
/// payload for the client to submit to the IdP.
#[cfg(feature = "saml")]
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/saml/login",
    tag = "federation-sso",
    request_body = SamlLoginRequest,
    responses(
        (status = 200, description = "SAML login: AuthnRequest payload",
         body = SamlLoginResponse),
        (status = 401, description = "Unknown org/tenant slug"),
        (status = 400, description = "Validation error"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn saml_login_public<C: Connection + Clone>(
    // Named `app_state` (not `state`) — this handler already has a local
    // `state` variable (the RelayState CSRF value).
    app_state: web::Data<AppState<C>>,
    body: web::Json<SamlLoginRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    if b.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    validate_redirect_uri(&b.redirect_uri)?;

    // Resolve workspace identity (mirrors Phase 1 login — 401 on slug miss).
    let org_id = match (b.org_id, b.org_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            app_state
                .org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid federation request".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide org_id or org_slug".into(),
            }));
        }
    };
    let tenant_id = match (b.tenant_id, b.tenant_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            app_state
                .tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid federation request".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide tenant_id or tenant_slug".into(),
            }));
        }
    };

    // Generate state (SAML uses RelayState; nonce is unused for SAML).
    let state = random_base64url();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    // Pass state as RelayState so the IdP echoes it back in the SAML response.
    let result = app_state
        .federation
        .saml_federation_service
        .build_authn_request(tenant_id, b.federation_config_id, "", Some(state.clone()))
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    // Persist state row (nonce = "" for SAML — unused but required by schema).
    // Store the AuthnRequest ID for InResponseTo verification (SEC-005/REQ-14 AC-5).
    app_state
        .federation
        .federation_login_state_repo
        .insert(&axiam_core::repository::FederationLoginState {
            state: state.clone(),
            nonce: String::new(),
            tenant_id,
            federation_config_id: b.federation_config_id,
            redirect_uri: b.redirect_uri,
            expires_at,
            request_id: result.request_id.clone(),
        })
        .await?;

    Ok(HttpResponse::Ok().json(SamlLoginResponse {
        binding: result.binding,
        sso_url: result.url,
        saml_request_b64: result.saml_request,
        relay_state: state,
    }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/federation/saml/acs  (public)
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/federation/saml/acs`
///
/// Assertion Consumer Service endpoint for first-time SSO.  Consumes the
/// RelayState (maps to our state row), runs the verified SAML flow from
/// plan 04-03, provisions or links the user, and returns Set-Cookie response.
#[cfg(feature = "saml")]
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/saml/acs",
    tag = "federation-sso",
    request_body = SamlAcsPublicRequest,
    responses(
        (status = 200, description = "SAML ACS: cookies set",
         body = SsoLoginSuccessResponse),
        (status = 401, description = "State not found or expired"),
    )
)]
#[allow(clippy::too_many_arguments)]
pub async fn saml_acs_public<C: Connection + Clone>(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<SamlAcsPublicRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    if b.relay_state.is_empty() {
        return Err(validation_err("relay_state must not be empty"));
    }
    if b.saml_response_b64.is_empty() {
        return Err(validation_err("saml_response_b64 must not be empty"));
    }

    // Atomically consume the state row (single-use; expired → 401).
    let login_state = state
        .federation
        .federation_login_state_repo
        .consume_by_state(&b.relay_state)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "state not found or expired".into(),
            })
        })?;

    let tenant_id = login_state.tenant_id;
    let config_id = login_state.federation_config_id;
    let spa_redirect_uri = login_state.redirect_uri.clone();

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    // Run the verified SAML flow (04-03): signature verify + replay check.
    let callback_result = state
        .federation
        .saml_federation_service
        .handle_saml_response(
            tenant_id,
            config_id,
            &b.saml_response_b64,
            Some(&b.relay_state),
            // Pass stored request_id for InResponseTo check (SEC-005/REQ-14 AC-5).
            Some(login_state.request_id.as_str()),
            // Destination / SubjectConfirmationData@Recipient check: no ACS URL
            // is available on this path — `saml_login_public` builds its
            // AuthnRequest with an empty AssertionConsumerServiceURL and
            // `FederationLoginState` has no column to store one. The bearer
            // `<SubjectConfirmationData>` is still REQUIRED and its
            // `@Recipient`/`@NotOnOrAfter`/`@InResponseTo` are still validated
            // (the last against the stored `request_id` above); only the
            // `@Recipient` *value* comparison is skipped. Closing that needs a
            // schema addition — tracked as the SEC-005 residual, SAML-01 in
            // claude_dev/security-audit.md §7.
            None,
            // require_in_response_to has no effect when expected_request_id is
            // Some (this path already enforces presence-and-equality above) —
            // pass false for clarity; this call site is unchanged (out of
            // SECFIX-04 scope per 23-04-PLAN.md Task 2).
            false,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    let user = callback_result.user;

    // SEC-095 — see the identical call in `oidc_callback_public`.
    sso_login_post_auth(&state, &http_req, tenant_id, &user).await?;

    // TODO(T19.15): resolve real org_id from the tenant instead of Uuid::nil()
    // (see the SAML callback above) — SSO tokens carry an empty org_id claim. Phase 19.
    let auth_out = state
        .auth_service
        .create_session_and_tokens(user.id, tenant_id, Uuid::nil(), None, None)
        .await?;

    let csrf_token = crate::middleware::csrf::generate_csrf_token();
    let user_detail = state
        .user_repo
        .get_by_id(tenant_id, user.id)
        .await
        .map_err(|_| AxiamError::AuthenticationFailed {
            reason: "user not found after SAML login".into(),
        })?;

    Ok(actix_web::HttpResponse::Ok()
        .cookie(crate::middleware::csrf::access_cookie(
            &auth_out.access_token,
            state.auth_config.access_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        .cookie(crate::middleware::csrf::refresh_cookie(
            &auth_out.refresh_token,
            state.auth_config.refresh_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        .cookie(crate::middleware::csrf::csrf_cookie(
            &csrf_token,
            state.auth_config.access_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        // See the matching comment on handlers/auth.rs's login handler —
        // non-browser SDKs capture the CSRF token from this header (the
        // same value already exposed via the non-httpOnly cookie above).
        .insert_header((crate::middleware::csrf::HEADER_CSRF, csrf_token.clone()))
        .json(SsoLoginSuccessResponse {
            user_id: user_detail.id,
            session_id: auth_out.session_id,
            expires_in: auth_out.expires_in,
            redirect_uri: spa_redirect_uri,
        }))
}
