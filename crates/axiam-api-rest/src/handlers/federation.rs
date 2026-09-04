//! OIDC federation management endpoints (tenant-scoped via JWT).
//!
//! Provides CRUD for federation configurations, the OIDC authorization
//! and callback flow, and federation link management.

use actix_web::{HttpResponse, web};
use axiam_core::models::federation::{
    CreateFederationConfig, FederationConfig, FederationLink, FederationProtocol, ProviderKind,
    SubjectMapping, TokenExchangeTrust, UpdateFederationConfig,
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
use axiam_core::repository::FederationLoginStateRepository;
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
    // --- login-provider fields ---
    /// Which provider this is: `google`, `github`, `facebook`, `apple`,
    /// `microsoft`, `generic_oidc`, `generic_oauth2` or `generic_saml`.
    ///
    /// Selects the sign-in button's branding, the per-kind defaults, and the
    /// key on which a tenant config overrides an inherited organization one.
    /// Omitted ⇒ derived from `protocol`, which is what every config written
    /// before this field existed means.
    pub provider_kind: Option<String>,
    /// Operator-chosen identifier, **required** for the `generic_*` kinds and
    /// refused for the branded ones.
    pub provider_slug: Option<String>,
    /// Whether tenants of this organization may inherit this provider. Only
    /// meaningful on a config in the organization-scope tenant.
    pub allow_tenant_inheritance: Option<bool>,
    /// Scopes to request. Omitted or empty ⇒ the per-kind default.
    pub scopes: Option<Vec<String>>,
    /// OAuth2-variant authorization endpoint. Required for `OAuth2`.
    pub authorization_endpoint: Option<String>,
    /// OAuth2-variant token endpoint. Required for `OAuth2`.
    pub token_endpoint: Option<String>,
    /// OAuth2-variant userinfo endpoint. Required for `OAuth2`.
    pub userinfo_endpoint: Option<String>,
    /// External IdP tenant identifiers accepted when the provider publishes a
    /// templated issuer (Entra ID's `{tenantid}`).
    pub allowed_issuer_tenants: Option<Vec<String>>,
    /// Apple Team ID (10 characters).
    pub apple_team_id: Option<String>,
    /// Apple Key ID of the `.p8` signing key (10 characters). With both Apple
    /// identifiers set, `client_secret` is the `.p8` key itself and AXIAM mints
    /// a fresh five-minute client secret per token exchange.
    pub apple_key_id: Option<String>,
    /// Send PKCE on the authorization request. Forced on for `OAuth2`.
    pub require_pkce: Option<bool>,
    /// Sign-in-button icon for a **generic** provider, as a base64 raster data
    /// URL (`data:image/png;base64,…`), already cropped to
    /// `PROVIDER_ICON_SIZE_PX` square by the client.
    ///
    /// Refused for the branded kinds: Google, Apple and Microsoft all publish
    /// sign-in-button rules that require their own mark, so substituting a
    /// picture would produce a button that breaks the guidelines it exists to
    /// follow.
    pub button_icon: Option<String>,
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
    // --- login-provider fields ---
    //
    // `provider_kind` is deliberately absent: it selects the protocol and the
    // override key, and changing it on a live config would silently re-point
    // which inherited provider a tenant is shadowing. Delete and recreate.
    /// Operator-chosen identifier for a `generic_*` kind. `Some(None)` clears it.
    pub provider_slug: Option<Option<String>>,
    /// Whether tenants may inherit this organization-level provider.
    pub allow_tenant_inheritance: Option<bool>,
    /// Scopes to request. Replaced wholesale; empty restores the per-kind default.
    pub scopes: Option<Vec<String>>,
    /// OAuth2-variant authorization endpoint. `Some(None)` clears it.
    pub authorization_endpoint: Option<Option<String>>,
    /// OAuth2-variant token endpoint. `Some(None)` clears it.
    pub token_endpoint: Option<Option<String>>,
    /// OAuth2-variant userinfo endpoint. `Some(None)` clears it.
    pub userinfo_endpoint: Option<Option<String>>,
    /// Accepted external IdP tenants for a templated issuer. Replaced wholesale.
    pub allowed_issuer_tenants: Option<Vec<String>>,
    /// Apple Team ID. `Some(None)` clears it.
    pub apple_team_id: Option<Option<String>>,
    /// Apple Key ID. `Some(None)` clears it.
    pub apple_key_id: Option<Option<String>>,
    /// Send PKCE on the authorization request.
    pub require_pkce: Option<bool>,
    /// Sign-in-button icon for a generic provider. `Some(None)` clears it.
    pub button_icon: Option<Option<String>>,
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
    // --- login-provider fields ---
    /// Which provider this is. Derived from `protocol` for a config written
    /// before the field existed.
    pub provider_kind: String,
    /// Operator-chosen identifier for a `generic_*` kind.
    pub provider_slug: Option<String>,
    /// Whether tenants of this organization may inherit this provider.
    pub allow_tenant_inheritance: bool,
    /// Scopes as stored. Empty means "use the per-kind default"; see
    /// `effective_scopes`.
    pub scopes: Vec<String>,
    /// The per-kind default that an empty `scopes` resolves to. Returned so the
    /// admin UI can show what will actually be requested without duplicating
    /// the table.
    pub effective_scopes: Vec<String>,
    /// OAuth2-variant authorization endpoint.
    pub authorization_endpoint: Option<String>,
    /// OAuth2-variant token endpoint.
    pub token_endpoint: Option<String>,
    /// OAuth2-variant userinfo endpoint.
    pub userinfo_endpoint: Option<String>,
    /// Accepted external IdP tenants for a templated issuer.
    pub allowed_issuer_tenants: Vec<String>,
    /// Accepted signing algorithms. Returned for OIDC and SAML; meaningless,
    /// and therefore empty, for the OAuth2 variant.
    pub allowed_algorithms: Vec<String>,
    /// Apple Team ID. Not secret — the `.p8` key is, and it is never returned.
    pub apple_team_id: Option<String>,
    /// Apple Key ID.
    pub apple_key_id: Option<String>,
    /// Whether AXIAM mints this provider's client secret itself, per exchange,
    /// rather than sending a stored one. True only for an Apple config with
    /// both identifiers set.
    pub mints_client_secret: bool,
    /// Whether PKCE is sent on the authorization request. Always true for the
    /// OAuth2 variant regardless of the stored flag.
    pub pkce_required: bool,
    /// Custom sign-in-button icon, when one is set.
    pub button_icon: Option<String>,
    /// Whether AXIAM ships this provider's own mark. When true the button uses
    /// it and `button_icon` is refused; when false the button reads
    /// "Sign in with <provider>" and may carry a custom icon.
    pub has_bundled_mark: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<FederationConfig> for FederationConfigResponse {
    fn from(c: FederationConfig) -> Self {
        // Derived values first: they read the whole struct, and the field moves
        // below would otherwise leave it partially consumed.
        let effective_scopes = c.effective_scopes();
        let mints_client_secret = c.mints_client_secret();
        let pkce_required = c.pkce_required();
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            provider: c.provider,
            protocol: protocol_to_string(&c.protocol).to_owned(),
            metadata_url: c.metadata_url,
            client_id: c.client_id,
            attribute_map: c.attribute_map,
            enabled: c.enabled,
            provider_kind: c.provider_kind.as_str().to_owned(),
            provider_slug: c.provider_slug.clone(),
            allow_tenant_inheritance: c.allow_tenant_inheritance,
            effective_scopes,
            scopes: c.scopes.clone(),
            authorization_endpoint: c.authorization_endpoint.clone(),
            token_endpoint: c.token_endpoint.clone(),
            userinfo_endpoint: c.userinfo_endpoint.clone(),
            allowed_issuer_tenants: c.allowed_issuer_tenants.clone(),
            allowed_algorithms: c.allowed_algorithms.clone(),
            apple_team_id: c.apple_team_id.clone(),
            apple_key_id: c.apple_key_id.clone(),
            mints_client_secret,
            pkce_required,
            has_bundled_mark: c.provider_kind.has_bundled_mark(),
            button_icon: c.button_icon.clone(),
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

pub(crate) fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

fn protocol_to_string(p: &FederationProtocol) -> &'static str {
    p.as_str()
}

/// The login-provider fields, validated together.
///
/// One function because the rules are *relational* — a slug is required for one
/// set of kinds and refused for the others, the OAuth2 endpoints are required
/// for one protocol and meaningless for the rest — and rules like that stop
/// agreeing with each other the moment they are written twice, once in `create`
/// and once in `update`.
struct LoginProviderFields {
    provider_kind: ProviderKind,
    provider_slug: Option<String>,
    scopes: Option<Vec<String>>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    allowed_issuer_tenants: Option<Vec<String>>,
    apple_team_id: Option<String>,
    apple_key_id: Option<String>,
    button_icon: Option<String>,
}

/// Bound on how many scopes or accepted issuer tenants a config may carry.
///
/// Both are read on every login and one of them ends up in a URL, so an
/// unbounded list is an unbounded per-login cost — and an authorize URL long
/// enough to be rejected by the provider — that an admin can set.
const MAX_LIST_ENTRIES: usize = 64;

fn validate_login_provider_fields(
    protocol: FederationProtocol,
    fields: &LoginProviderFields,
) -> Result<(), AxiamApiError> {
    axiam_core::models::federation::validate_protocol_for_kind(fields.provider_kind, protocol)
        .map_err(|e| validation_err(e.to_string()))?;

    // A slug is what distinguishes two generic providers of the same kind. It
    // is **optional**, not required: a request that omits `provider_kind`
    // altogether — which every client written before this change does — derives
    // a generic kind, and demanding a slug there would turn a working create
    // call into a 400. A slug-less generic config simply keys on its kind, the
    // same way a branded one does.
    //
    // It stays refused for a branded kind, where the kind is already the key and
    // a slug would only create the illusion that a tenant could hold two Googles.
    match (
        fields.provider_kind.uses_slug(),
        fields.provider_slug.as_deref().filter(|s| !s.is_empty()),
    ) {
        (true, Some(slug)) => {
            axiam_core::models::federation::validate_provider_slug(slug).map_err(validation_err)?;
        }
        (false, Some(_)) => {
            return Err(validation_err(
                "provider_slug applies only to the generic provider kinds; a branded \
                 kind is already its own key",
            ));
        }
        (true, None) | (false, None) => {}
    }

    if let Some(scopes) = &fields.scopes {
        if scopes.len() > MAX_LIST_ENTRIES {
            return Err(validation_err(format!(
                "scopes has {} entries; the maximum is {MAX_LIST_ENTRIES}",
                scopes.len()
            )));
        }
        if scopes.iter().any(|s| s.trim().is_empty()) {
            return Err(validation_err("scopes must not contain blank entries"));
        }
    }

    if let Some(tenants) = &fields.allowed_issuer_tenants {
        if tenants.len() > MAX_LIST_ENTRIES {
            return Err(validation_err(format!(
                "allowed_issuer_tenants has {} entries; the maximum is {MAX_LIST_ENTRIES}",
                tenants.len()
            )));
        }
        if tenants.iter().any(|t| t.trim().is_empty()) {
            return Err(validation_err(
                "allowed_issuer_tenants must not contain blank entries",
            ));
        }
    }

    // The OAuth2 variant has no discovery document, so the three endpoints are
    // the config. Each is checked for HTTPS here rather than at first login: an
    // operator finds out while looking at the form, not from a failed sign-in.
    if protocol == FederationProtocol::OAuth2 {
        for (name, value) in [
            ("authorization_endpoint", &fields.authorization_endpoint),
            ("token_endpoint", &fields.token_endpoint),
            ("userinfo_endpoint", &fields.userinfo_endpoint),
        ] {
            let Some(url) = value.as_deref().filter(|u| !u.trim().is_empty()) else {
                return Err(validation_err(format!(
                    "{name} is required for an OAuth2 provider — there is no discovery \
                     document to derive it from"
                )));
            };
            require_https_endpoint(name, url)?;
        }
        // The userinfo call *is* the authentication here, so scopes that reach
        // it have to be stated: guessing a provider's scope names produces an
        // authorize URL that fails at the provider.
        let effective_empty = fields.scopes.as_ref().map(|s| s.is_empty()).unwrap_or(true)
            && fields.provider_kind.default_scopes().is_empty();
        if effective_empty {
            return Err(validation_err(
                "scopes are required for a generic OAuth2 provider — a provider's scope \
                 names are its own",
            ));
        }
    } else {
        for (name, value) in [
            ("authorization_endpoint", &fields.authorization_endpoint),
            ("token_endpoint", &fields.token_endpoint),
            ("userinfo_endpoint", &fields.userinfo_endpoint),
        ] {
            if value.as_deref().is_some_and(|u| !u.trim().is_empty()) {
                return Err(validation_err(format!(
                    "{name} applies only to the OAuth2 protocol; an OIDC provider's \
                     endpoints come from its discovery document"
                )));
            }
        }
    }

    // Apple's identifiers come as a pair or not at all: one alone produces a
    // config that looks configured and mints nothing.
    match (
        fields.apple_team_id.as_deref(),
        fields.apple_key_id.as_deref(),
    ) {
        (Some(team), Some(key)) => {
            if fields.provider_kind != ProviderKind::Apple {
                return Err(validation_err(
                    "apple_team_id and apple_key_id apply only to the `apple` provider kind",
                ));
            }
            axiam_federation::apple::validate_apple_identifier("apple_team_id", team)
                .map_err(validation_err)?;
            axiam_federation::apple::validate_apple_identifier("apple_key_id", key)
                .map_err(validation_err)?;
        }
        (None, None) => {}
        _ => {
            return Err(validation_err(
                "apple_team_id and apple_key_id must be set together — with both, the \
                 stored secret is the .p8 key and AXIAM mints a client secret per \
                 exchange; with neither, the stored secret is sent verbatim",
            ));
        }
    }

    // A custom mark belongs only where AXIAM ships none. Google, Apple and
    // Microsoft publish sign-in-button rules that require their own logo,
    // wording and colours; accepting a replacement here would let an operator
    // build a button that breaks the guidelines it is meant to follow, on a
    // page their users are asked to trust.
    if let Some(icon) = fields.button_icon.as_deref().filter(|i| !i.is_empty()) {
        if fields.provider_kind.has_bundled_mark() {
            return Err(validation_err(format!(
                "button_icon applies only to the generic provider kinds; '{}' ships \
                 its own mark, and its sign-in button must use it",
                fields.provider_kind.as_str()
            )));
        }
        axiam_core::models::federation::validate_provider_icon(icon).map_err(validation_err)?;
    }

    Ok(())
}

/// Absolute HTTPS, or plain HTTP for loopback.
///
/// The same rule `validate_metadata_url` applies to the OIDC discovery URL, and
/// for the same reason: these endpoints carry the decrypted client secret and
/// the access token that stands in for the whole authentication.
fn require_https_endpoint(name: &str, url: &str) -> Result<(), AxiamApiError> {
    let parsed =
        url::Url::parse(url).map_err(|_| validation_err(format!("{name} is not a valid URL")))?;
    let host = parsed.host_str().unwrap_or("");
    let is_loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback) {
        Ok(())
    } else {
        Err(validation_err(format!(
            "{name} must use HTTPS (or HTTP for localhost)"
        )))
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

    let protocol = FederationProtocol::from_wire(&req.protocol)
        .ok_or_else(|| validation_err("protocol must be 'OidcConnect', 'Saml' or 'OAuth2'"))?;

    // Omitted `provider_kind` derives from the protocol, which is what every
    // config written before the field existed means.
    let provider_kind = match req.provider_kind.as_deref() {
        None => ProviderKind::from_legacy_protocol(protocol),
        Some(raw) => ProviderKind::from_wire(raw).ok_or_else(|| {
            validation_err(
                "provider_kind must be one of google, github, facebook, apple, microsoft, \
                 generic_oidc, generic_oauth2, generic_saml",
            )
        })?,
    };

    let login_fields = LoginProviderFields {
        provider_kind,
        provider_slug: req.provider_slug.clone(),
        scopes: req.scopes.clone(),
        authorization_endpoint: req.authorization_endpoint.clone(),
        token_endpoint: req.token_endpoint.clone(),
        userinfo_endpoint: req.userinfo_endpoint.clone(),
        allowed_issuer_tenants: req.allowed_issuer_tenants.clone(),
        apple_team_id: req.apple_team_id.clone(),
        apple_key_id: req.apple_key_id.clone(),
        button_icon: req.button_icon.clone(),
    };
    validate_login_provider_fields(protocol, &login_fields)?;

    // The attribute map is validated now that something reads it. Before this
    // change it was stored unchecked and consulted by nothing, so a typo was
    // invisible in both directions.
    if let Some(ref map) = req.attribute_map {
        axiam_core::models::federation_claims::validate_attribute_map(map)
            .map_err(|e| validation_err(e.to_string()))?;
    }

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
            provider_kind: Some(provider_kind),
            provider_slug: req.provider_slug,
            allow_tenant_inheritance: req.allow_tenant_inheritance,
            scopes: req.scopes,
            authorization_endpoint: req.authorization_endpoint,
            token_endpoint: req.token_endpoint,
            userinfo_endpoint: req.userinfo_endpoint,
            allowed_issuer_tenants: req.allowed_issuer_tenants,
            apple_team_id: req.apple_team_id,
            apple_key_id: req.apple_key_id,
            require_pkce: req.require_pkce,
            button_icon: req.button_icon,
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

    if let Some(ref map) = req.attribute_map {
        axiam_core::models::federation_claims::validate_attribute_map(map)
            .map_err(|e| validation_err(e.to_string()))?;
    }

    // The existing row is the authority for protocol and kind — both are
    // immutable after creation — so it is loaded once here and every relational
    // rule is checked against the row as it *will* be, not as it was submitted.
    let existing = state
        .federation
        .federation_config_repo
        .get_by_id(user.tenant_id, id)
        .await?;

    let token_exchange = req.token_exchange.map(|t| t.into_domain()).transpose()?;
    if let Some(ref t) = token_exchange
        && t.enabled
        && existing.protocol != FederationProtocol::OidcConnect
    {
        return Err(validation_err(
            "token_exchange is only supported for OidcConnect providers",
        ));
    }

    /// Fold an `Option<Option<T>>` patch over the current value.
    fn patched<T: Clone>(patch: &Option<Option<T>>, current: &Option<T>) -> Option<T> {
        match patch {
            Some(v) => v.clone(),
            None => current.clone(),
        }
    }

    let login_fields = LoginProviderFields {
        provider_kind: existing.provider_kind,
        provider_slug: patched(&req.provider_slug, &existing.provider_slug),
        scopes: Some(
            req.scopes
                .clone()
                .unwrap_or_else(|| existing.scopes.clone()),
        ),
        authorization_endpoint: patched(
            &req.authorization_endpoint,
            &existing.authorization_endpoint,
        ),
        token_endpoint: patched(&req.token_endpoint, &existing.token_endpoint),
        userinfo_endpoint: patched(&req.userinfo_endpoint, &existing.userinfo_endpoint),
        allowed_issuer_tenants: Some(
            req.allowed_issuer_tenants
                .clone()
                .unwrap_or_else(|| existing.allowed_issuer_tenants.clone()),
        ),
        apple_team_id: patched(&req.apple_team_id, &existing.apple_team_id),
        apple_key_id: patched(&req.apple_key_id, &existing.apple_key_id),
        button_icon: patched(&req.button_icon, &existing.button_icon),
    };
    validate_login_provider_fields(existing.protocol, &login_fields)?;

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
                provider_slug: req.provider_slug,
                allow_tenant_inheritance: req.allow_tenant_inheritance,
                scopes: req.scopes,
                authorization_endpoint: req.authorization_endpoint,
                token_endpoint: req.token_endpoint,
                userinfo_endpoint: req.userinfo_endpoint,
                allowed_issuer_tenants: req.allowed_issuer_tenants,
                apple_team_id: req.apple_team_id,
                apple_key_id: req.apple_key_id,
                require_pkce: req.require_pkce,
                button_icon: req.button_icon,
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
            code_verifier: None,
            idp_redirect_uri: None,
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
pub(crate) fn random_base64url() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Validate that a `redirect_uri` is a well-formed absolute HTTPS (or HTTP
/// localhost) URL.
///
/// This is the **first, cheap** check, not the whole rule. It answers "is this
/// a URL a browser could be sent to at all", which is worth saying separately
/// because the message a caller gets for `not-a-url` should not be the message
/// they get for `wrong-origin`.
///
/// The rule that decides *where* a browser may be sent is
/// [`federation_login::require_deployment_spa_origin`], and since R-3 every one
/// of the four federated start operations applies it — SAML, Apple, OIDC and
/// OAuth2 alike. The `TODO(T19.14)` that used to sit here proposed a
/// per-`FederationConfig` registered-redirect allowlist instead; that is
/// deliberately **not** what landed. A second list to keep in sync with the
/// deployment-origin rule is a second place to get wrong, and the origin rule
/// already answers the question the allowlist was for. See
/// `claude_dev/remediation-plan-2026-09-04.md` §4.
pub(crate) fn validate_redirect_uri(uri: &str) -> Result<(), AxiamApiError> {
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
pub(crate) async fn sso_login_post_auth<C: Connection + Clone>(
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

/// Issue a session for a federated sign-in and return the `Set-Cookie`
/// response.
///
/// Factored out because three public paths end this way — the OIDC callback,
/// the OAuth2 callback and the handoff exchange — and a fourth copy is how one
/// of them ends up with a differently-scoped cookie or a missing CSRF header.
///
/// It deliberately does **not** fire `login.post_auth`. That gate belongs where
/// the credentials were verified, which for the handoff path is minutes earlier
/// and on a different request; firing it here as well would ask a reactor to
/// adjudicate one sign-in twice.
pub(crate) async fn issue_sso_session<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    tenant_id: Uuid,
    user: &axiam_core::models::user::User,
    spa_redirect_uri: String,
) -> Result<HttpResponse, AxiamApiError> {
    // R-3: checked again here, not only at login start — the same reason
    // `mint_handoff_and_redirect` re-checks. This is the single point every
    // OIDC and OAuth2 sign-in passes through, and a `federation_login_state`
    // row written by an older binary, before the start-path check existed, must
    // not be honoured by this one. It costs one URL parse per federated login.
    super::federation_login::require_deployment_spa_origin(state, &spa_redirect_uri)?;

    // TODO(T19.15): resolve real org_id from the tenant instead of Uuid::nil().
    // SSO-provisioned access tokens currently carry an empty org_id claim.
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

    Ok(HttpResponse::Ok()
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
            // Session lifetime, not access-token lifetime — see the note in
            // `handlers::auth`'s login response.
            state.auth_config.refresh_token_lifetime_secs,
            state.auth_config.cookie_secure,
        ))
        // See the matching comment on handlers/auth.rs's login handler —
        // non-browser SDKs capture the CSRF token from this header (the same
        // value already exposed via the non-httpOnly cookie above).
        .insert_header((crate::middleware::csrf::HEADER_CSRF, csrf_token.clone()))
        .json(SsoLoginSuccessResponse {
            user_id: user_detail.id,
            session_id: auth_out.session_id,
            expires_in: auth_out.expires_in,
            redirect_uri: spa_redirect_uri,
        }))
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
    use super::federation_login::{
        idp_redirect_uri_for, oidc_service, require_deployment_spa_origin,
        resolve_config_for_login, resolve_workspace,
    };

    let b = body.into_inner();

    if b.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    validate_redirect_uri(&b.redirect_uri)?;

    // 401 on a slug miss, deliberately, so the endpoint does not enumerate
    // organizations or tenants (D-22).
    let workspace = resolve_workspace(
        &app_state,
        b.org_id,
        b.org_slug.as_deref(),
        b.tenant_id,
        b.tenant_slug.as_deref(),
    )
    .await
    .map_err(super::federation_login::workspace_error)?;

    // Resolution honours org→tenant inheritance, so a tenant can start a login
    // through a provider its organization configured. The user and the link are
    // still created in `workspace.tenant_id` — see `handle_callback_for`.
    let resolved = resolve_config_for_login(&app_state, workspace, b.federation_config_id).await?;
    if resolved.config.protocol != FederationProtocol::OidcConnect {
        return Err(validation_err(
            "this provider does not use the OpenID Connect protocol; \
             start the flow at the endpoint its protocol names",
        ));
    }

    // R-3: the same deployment-origin rule the SAML and Apple paths apply.
    //
    // Until now this path relied on the provider's own registered-redirect
    // check, which does see this URI and does compare it — but that backstop is
    // only ever as strict as each provider's registration hygiene, and several
    // accept wildcard or prefix registrations. It is also a control AXIAM does
    // not own: nothing here can tell whether it was configured well. The rule
    // the server *does* own should be uniform across all four start operations,
    // and the provider's check remains as a second, independent layer.
    //
    // Placed after workspace and config resolution so that an unknown slug
    // still answers the uniform 401 rather than being told which check it
    // failed (D-22).
    require_deployment_spa_origin(&app_state, &b.redirect_uri)?;

    // Generate server-side state + nonce (256 bits each).
    let state = random_base64url();
    let nonce = random_base64url();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // PKCE is opt-in on this path (the server-side nonce already binds the
    // code), so a config written before the column existed behaves unchanged.
    let pkce = resolved
        .config
        .pkce_required()
        .then(axiam_federation::pkce::generate);

    // Apple posts its response cross-site instead of redirecting the browser,
    // so the URI it is given is an AXIAM server endpoint rather than the SPA
    // route. The value is stored because the token exchange must echo the exact
    // string the authorize request carried.
    let (idp_redirect_uri, stored_idp_redirect_uri) =
        idp_redirect_uri_for(&app_state, &resolved.config, &b.redirect_uri)?;

    let service = oidc_service(&app_state)?;

    let auth_url = service
        .build_authorization_url_for(
            &resolved.config,
            &idp_redirect_uri,
            &state,
            &nonce,
            pkce.as_ref().map(|p| p.challenge.as_str()),
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
            tenant_id: workspace.tenant_id,
            federation_config_id: b.federation_config_id,
            redirect_uri: b.redirect_uri,
            expires_at,
            request_id: String::new(), // OIDC — no request ID
            code_verifier: pkce.map(|p| p.verifier),
            idp_redirect_uri: stored_idp_redirect_uri,
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
    use super::federation_login::{
        consume_login_state, oidc_service, resolve_config_for_login, workspace_for_tenant,
    };

    let b = body.into_inner();

    if b.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }
    if b.code.is_empty() {
        return Err(validation_err("code must not be empty"));
    }

    // Atomically consume the state row (single-use; expired → None → 401).
    let login_state = consume_login_state(&state, &b.state).await?;

    let tenant_id = login_state.tenant_id;
    // Nonce comes from the state row — NOT from the HTTP body (T-04-30).
    let expected_nonce = login_state.nonce.clone();
    let spa_redirect_uri = login_state.redirect_uri.clone();

    // Re-resolved rather than loaded by id alone: the config may be inherited
    // from the organization, and the same visibility rules that let the login
    // start must decide whether it may finish.
    let workspace = workspace_for_tenant(&state, tenant_id).await?;
    let resolved =
        resolve_config_for_login(&state, workspace, login_state.federation_config_id).await?;

    let service = oidc_service(&state)?;

    let callback_result = service
        .handle_callback_for(
            &resolved.config,
            tenant_id,
            &b.code,
            // The exact string the authorize request carried. For every
            // provider but Apple that is the SPA redirect_uri; for Apple it is
            // the server form-post endpoint, recorded at start time.
            login_state.token_exchange_redirect_uri(),
            &expected_nonce,
            login_state.code_verifier.as_deref(),
            None,
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
    sso_login_post_auth(&state, &http_req, tenant_id, &user).await?;

    issue_sso_session(&state, tenant_id, &user, spa_redirect_uri).await
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
    use super::federation_login::{
        require_deployment_spa_origin, resolve_config_for_login, resolve_workspace, saml_acs_url,
    };

    let b = body.into_inner();

    if b.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    validate_redirect_uri(&b.redirect_uri)?;

    // 401 on a slug miss (mirrors Phase 1 login and `oidc_start_public`).
    let workspace = resolve_workspace(
        &app_state,
        b.org_id,
        b.org_slug.as_deref(),
        b.tenant_id,
        b.tenant_slug.as_deref(),
    )
    .await
    .map_err(super::federation_login::workspace_error)?;

    let resolved = resolve_config_for_login(&app_state, workspace, b.federation_config_id).await?;
    if resolved.config.protocol != FederationProtocol::Saml {
        return Err(validation_err(
            "this provider does not use the SAML protocol; \
             start the flow at the endpoint its protocol names",
        ));
    }

    // Generate state (SAML uses RelayState; nonce is unused for SAML).
    let state = random_base64url();
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // The AuthnRequest now names this deployment's real ACS URL — the
    // form-encoded one an IdP can actually post to. It was previously empty,
    // which is why `handle_saml_response` had no Recipient value to compare.
    // A SAML IdP posts its assertion to AXIAM's ACS — the URL built on the next
    // line — and never sees `redirect_uri`, so its own registered-redirect
    // allowlist cannot reject an attacker's host. This check is the only one
    // there is; see `require_deployment_spa_origin`. It runs after the
    // workspace and config have resolved so that an unknown slug still answers
    // the uniform 401 rather than being told which check it failed.
    require_deployment_spa_origin(&app_state, &b.redirect_uri)?;

    let acs_url = saml_acs_url(&app_state)?;

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    // Pass state as RelayState so the IdP echoes it back in the SAML response.
    let result = app_state
        .federation
        .saml_federation_service
        .build_authn_request(
            resolved.config.tenant_id,
            b.federation_config_id,
            &acs_url,
            Some(state.clone()),
        )
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
            tenant_id: workspace.tenant_id,
            federation_config_id: b.federation_config_id,
            redirect_uri: b.redirect_uri,
            expires_at,
            request_id: result.request_id.clone(),
            code_verifier: None,
            idp_redirect_uri: Some(acs_url),
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
    use super::federation_login::{
        consume_login_state, resolve_config_for_login, workspace_for_tenant,
    };

    let b = body.into_inner();

    if b.relay_state.is_empty() {
        return Err(validation_err("relay_state must not be empty"));
    }
    if b.saml_response_b64.is_empty() {
        return Err(validation_err("saml_response_b64 must not be empty"));
    }

    // Atomically consume the state row (single-use; expired → 401).
    let login_state = consume_login_state(&state, &b.relay_state).await?;

    let tenant_id = login_state.tenant_id;
    let spa_redirect_uri = login_state.redirect_uri.clone();

    // Re-resolved rather than loaded by id alone, exactly as
    // `oidc_callback_public` does: an organization-level config with
    // `allow_tenant_inheritance` is not found by a `get_by_id` scoped to the
    // requesting tenant, so a login that *started* would fail here. The same
    // visibility rules that let it start decide whether it may finish.
    let workspace = workspace_for_tenant(&state, tenant_id).await?;
    let resolved =
        resolve_config_for_login(&state, workspace, login_state.federation_config_id).await?;

    // QUAL-07: SamlFederationService is now a hoisted AppState singleton.
    // Run the verified SAML flow (04-03): signature verify + replay check.
    let callback_result = state
        .federation
        .saml_federation_service
        .handle_saml_response_for(
            &resolved.config,
            tenant_id,
            &b.saml_response_b64,
            Some(&b.relay_state),
            // Pass stored request_id for InResponseTo check (SEC-005/REQ-14 AC-5).
            Some(login_state.request_id.as_str()),
            // Destination / SubjectConfirmationData@Recipient check: the ACS URL
            // this deployment publishes is now recorded on the state row
            // (`idp_redirect_uri`), so a row written after that change is
            // checked against it. A row written before carries `None`, which
            // preserves the previous behaviour — the bearer
            // `<SubjectConfirmationData>` is still REQUIRED and its
            // `@NotOnOrAfter`/`@InResponseTo` are still validated; only the
            // `@Recipient` *value* comparison is skipped there. SEC-005
            // residual SAML-01 in claude_dev/security-audit.md §7.
            login_state.idp_redirect_uri.as_deref(),
            // require_in_response_to has no effect when expected_request_id is
            // Some (this path already enforces presence-and-equality above) —
            // pass false for clarity.
            false,
        )
        .await
        .map_err(axiam_core::error::AxiamError::from)?;

    let user = callback_result.user;

    // SEC-095 — see the identical call in `oidc_callback_public`.
    sso_login_post_auth(&state, &http_req, tenant_id, &user).await?;

    issue_sso_session(&state, tenant_id, &user, spa_redirect_uri).await
}
