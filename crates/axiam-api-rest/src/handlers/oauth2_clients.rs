//! OAuth2 client management endpoints (tenant-scoped via JWT).

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaClientMetadata, CibaDeliveryMode, CibaRequestSigningAlg,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    OAuth2Client, UpdateOAuth2Client,
};
use axiam_core::repository::{
    AuditLogRepository, DeviceGrantRepository, OAuth2ClientRepository, PaginatedResult, Pagination,
    RefreshTokenRepository,
};
use axiam_oauth2::client_grants::ClientGrantStores;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOAuth2ClientRequest {
    /// Human-readable name for the client.
    pub name: String,
    /// Allowed redirect URIs (must be HTTPS, except localhost for dev).
    ///
    /// SEC-089 / T21.3: this list **also** authorises token-exchange
    /// audiences, and that coupling is now deprecated — `allowed_resources`
    /// is the field that means "audiences this client may address". The
    /// redirect-URI branch survives one release so that no deployment's
    /// working exchange breaks on upgrade, and it logs a deprecation warning
    /// when it is the branch that matched. Register exchange targets in
    /// `allowed_resources` (see `docs/api/token-exchange.md#audience`).
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
    /// client that does not participate. Must be an absolute `https` URL with
    /// no credentials and no fragment, naming a public host: an IP literal that
    /// is loopback, private, link-local or the cloud metadata address, and the
    /// names `localhost`, `*.localhost`, `*.local` and `*.internal`, are refused
    /// with `400`. Delivery is one request that does not follow redirects, and a
    /// name that resolves to a non-public address is refused when it is sent.
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
    /// X7.1 — whether this client's authorization requests may carry the
    /// OpenID Connect authentication-request parameters (`prompt`, `max_age`,
    /// `acr_values`, `claims`, `id_token_hint`, `login_hint`, `display`,
    /// `ui_locales`, `claims_locales`).
    ///
    /// `"ignore"` (the default) is what every AXIAM client has always done:
    /// they are dropped and reach no decision. `"honour"` opts in, and is
    /// **refused on a `fapi2` client** at both this gate and the authorization
    /// endpoint — the two are different answers to the same question about
    /// what a request from this client means.
    #[serde(default)]
    pub authn_request_params: AuthnRequestParamsMode,
    /// X7.3 — whether an unauthenticated authorization request from this
    /// client may be answered with a redirect to the login page rather than
    /// the `401` AXIAM answers today.
    ///
    /// Accepted and stored, but **nothing reads it yet**: the login hop it
    /// gates is a later wave. Unlike `authn_request_params` it is permitted on
    /// a `fapi2` client, because it relaxes nothing — it decides only how an
    /// anonymous browser is answered.
    #[serde(default)]
    pub browser_sso: bool,
    /// T21.3 / RFC 8707 — the target services this client may name in a
    /// `resource` parameter, at `/oauth2/authorize`, `/oauth2/par`,
    /// `/oauth2/device_authorization` and `/oauth2/token`.
    ///
    /// Each entry must be an absolute URI without a fragment (RFC 8707 §2).
    /// Entries are stored in their RFC 3986 §6.2.2 normalised form, which is
    /// what the read-back shows and what every comparison uses; matching is by
    /// equivalence and **never by prefix**.
    ///
    /// Empty (the default) means the client may name no resource, so every
    /// token it obtains carries `axiam:user` or `axiam:m2m` exactly as before
    /// RFC 8707 support existed. This is also the list the RFC 8693 token
    /// exchange consults for its `audience`/`resource` target.
    #[serde(default)]
    pub allowed_resources: Vec<String>,
    /// G-7 — CIBA Core §4 `backchannel_token_delivery_mode`: `poll` or
    /// `ping`. Required when `grant_types` holds
    /// `urn:openid:params:grant-type:ciba`, refused otherwise; `push` is not
    /// offered. A CIBA client must be confidential; a `fapi2` one must also
    /// register `backchannel_authentication_request_signing_alg`.
    #[serde(default)]
    pub backchannel_token_delivery_mode: Option<String>,
    /// G-7 — CIBA Core §4: where a ping-mode client is notified. Required in
    /// ping mode and refused in poll mode; an absolute `https` URL held to the
    /// webhook address policy (no credentials, no fragment, no private,
    /// loopback or internal host).
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    /// G-7 — CIBA Core §4: `PS256`, `ES256` or `EdDSA`. When set, every
    /// backchannel authentication request must be a signed `request` JWT under
    /// this algorithm, verified against `jwks` or `jwks_uri` (exactly one is
    /// required; an inline `jwks` must hold a key of the algorithm). Required
    /// for a `fapi2` client holding the CIBA grant.
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg: Option<String>,
    /// G-7 — CIBA Core §4. `true` is **refused**: this server holds no user
    /// code to verify.
    #[serde(default)]
    pub backchannel_user_code_parameter: Option<bool>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOAuth2ClientRequest {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    /// Replace the client's scopes. On a `managed_by: dcr | cimd` client a scope
    /// the request adds that is outside the tenant's effective
    /// `dcr_allowed_scopes` is refused with `422` (#636); an
    /// administrator-managed client is not bounded.
    pub scopes: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// Pass an empty string to clear a previously registered URI — the one
    /// edit an operator makes when an RP is decommissioned. Any other value
    /// is held to the same rule as on create.
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
    /// X7.1 — see [`CreateOAuth2ClientRequest::authn_request_params`].
    pub authn_request_params: Option<AuthnRequestParamsMode>,
    /// X7.3 — see [`CreateOAuth2ClientRequest::browser_sso`].
    pub browser_sso: Option<bool>,
    /// T21.3 — see [`CreateOAuth2ClientRequest::allowed_resources`]. A
    /// whole-list replacement; `[]` withdraws every target.
    pub allowed_resources: Option<Vec<String>>,
    /// G-7 — see the create DTO. `""` clears.
    pub backchannel_token_delivery_mode: Option<String>,
    /// G-7 — see the create DTO. `""` clears.
    pub backchannel_client_notification_endpoint: Option<String>,
    /// G-7 — see the create DTO. `""` clears.
    pub backchannel_authentication_request_signing_alg: Option<String>,
    /// G-7 — `true` refused, as on create.
    pub backchannel_user_code_parameter: Option<bool>,
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
    /// X7.1 — echoed so an operator can audit which clients act on the OIDC
    /// authentication-request parameters, from this endpoint rather than from
    /// the database.
    pub authn_request_params: AuthnRequestParamsMode,
    /// X7.3 — echoed for the same reason.
    pub browser_sso: bool,
    /// T21.3 — echoed in its stored, normalised form, so an operator auditing
    /// which audiences a client may mint tokens for reads the strings the
    /// server actually compares rather than the ones they typed.
    pub allowed_resources: Vec<String>,
    /// T21.4 / D5 — who created this registration: `admin`, `dcr` or `cimd`.
    ///
    /// Echoed because an operator auditing a tenant needs to answer "which of
    /// these did we create?" from this endpoint rather than from the database,
    /// and because three behaviours hang off it: a non-`admin` client may
    /// never carry the FAPI profile, is always consent-gated, and is the only
    /// kind the unused-client sweeper touches.
    ///
    /// Read-only. There is no corresponding member on the update DTO: a
    /// registration's provenance is a fact about how it came to exist, and a
    /// field that could be edited to `admin` would be a field that launders
    /// one.
    pub managed_by: ManagedBy,
    /// T21.4 — when this client was last issued an authorization code, for the
    /// sweeper that deletes self-registered clients nobody uses.
    ///
    /// Always absent for an `admin` client: the stamp is written only for a
    /// non-`admin` one, so that an administrator's client takes exactly the
    /// path it took before T21.4 (I1). `null` on a self-registered client
    /// means it has never been authorized, and the sweeper reads `created_at`
    /// instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_authorized_at: Option<DateTime<Utc>>,
    /// G-7 — the CIBA delivery mode; absent for a client without the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_token_delivery_mode: Option<CibaDeliveryMode>,
    /// G-7 — the ping-mode notification endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_client_notification_endpoint: Option<String>,
    /// G-7 / D-61 — the algorithm this client signs its authentication
    /// requests with; absent for a client sending plain requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_authentication_request_signing_alg: Option<CibaRequestSigningAlg>,
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
            authn_request_params: c.authn_request_params,
            browser_sso: c.browser_sso,
            allowed_resources: c.allowed_resources,
            managed_by: c.managed_by,
            last_authorized_at: c.last_authorized_at,
            backchannel_token_delivery_mode: c.ciba.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: c
                .ciba
                .backchannel_client_notification_endpoint,
            backchannel_authentication_request_signing_alg: c
                .ciba
                .backchannel_authentication_request_signing_alg,
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
    /// The plaintext client secret, shown exactly once.
    ///
    /// T21.2 — **absent** for a client registered with
    /// `token_endpoint_auth_method: none`. A public client is created with no
    /// secret, so there is nothing to show; the member is omitted rather than
    /// sent as `""`, which an operator (or an SDK) would reasonably read as a
    /// secret that happens to be empty. Every confidential registration — that
    /// is, every registration that existed before T21.2 — carries it exactly
    /// as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
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
    // G-7 — CIBA; its metadata is validated by `validate_ciba`.
    CIBA_GRANT_TYPE,
];

/// G-7 — validate a registration's CIBA metadata (the rules are
/// `axiam_oauth2::ciba::validate_client_registration`'s, shared with
/// `POST /oauth2/register`) and return what to store.
fn validate_ciba(
    view: axiam_oauth2::ciba::CibaRegistrationView<'_>,
) -> Result<CibaClientMetadata, AxiamApiError> {
    axiam_oauth2::ciba::validate_client_registration(view)
        .map_err(|e| validation_err(e.to_string()))
}

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

/// Structural rules for a redirect URI, shared by the admin registration API
/// and by `POST /oauth2/register` (T21.4).
///
/// `pub(crate)` rather than private since T21.4: dynamic registration applies
/// the same rules and must not grow a second copy of them. What the DCR path
/// adds on top is the tenant's host allow-list, which has no admin-API
/// equivalent because an administrator registering a URI has already decided
/// it is acceptable.
pub(crate) fn validate_redirect_uris(uris: &[String]) -> Result<(), AxiamApiError> {
    if uris.is_empty() {
        return Err(validation_err("redirect_uris must not be empty"));
    }
    // The per-URI rule (absolute, https except loopback, no fragment) is the
    // one copy in `axiam_federation::saml_sp`, shared with the SAML ACS
    // allow-list (G-2, T23.2.1) so the two registrations can never disagree
    // about what a registrable redirect is.
    for uri in uris {
        axiam_federation::saml_sp::check_redirect_uri_registration(uri).map_err(validation_err)?;
    }
    Ok(())
}

/// Registration rule for `backchannel_logout_uri` (R101W2-04).
///
/// The URI receives a signed logout token naming a user's session, so it is
/// held to the outbound-endpoint policy every other credential-bearing target
/// uses (D-49, `axiam_oauth2::ssf::validate_push_endpoint`, also CIBA's ping
/// endpoint): absolute `https` with a host, no credentials, no fragment, no IP
/// literal that is not globally routable (loopback, private, link-local, the
/// cloud metadata address) and no `localhost`, `*.local` or `*.internal` name.
///
/// That is the redirect-URI rule (absolute, host, `https`, no fragment) plus
/// the address policy, and **without** the redirect-URI rule's `http` exception
/// for loopback: delivery goes through `guarded_fetch_no_redirect`, which
/// requires `https` and refuses loopback at connect time, so a loopback `http`
/// URI would be accepted here and could never be delivered. A name that
/// *resolves* to a non-public address passes this check and is refused at
/// delivery, which pins the address it validated.
///
/// An empty string is the "clear it" sentinel of the update request and is
/// never validated; callers filter it first.
pub(crate) fn validate_backchannel_logout_uri(uri: &str) -> Result<(), AxiamApiError> {
    axiam_oauth2::ssf::validate_push_endpoint(uri)
        .map(|_| ())
        .map_err(|reason| {
            validation_err(format!(
                "backchannel_logout_uri: {}",
                reason.replace("endpoint_url", "the URI")
            ))
        })
}

/// Validate and normalise `allowed_resources` (T21.3 / RFC 8707 §2).
///
/// Returns the list to store, which is the **normalised** form rather than
/// what the operator typed. Two reasons, and the second is the one that
/// matters: the read-back then shows the strings the server actually compares,
/// so an operator auditing a client sees the allow-list as the request path
/// sees it; and a duplicate that differs only in case or default port shows up
/// as a duplicate rather than hiding as a second entry.
///
/// A malformed entry is a `400` naming that entry. The alternative — storing
/// it and refusing it at request time — would give the operator a registration
/// that looks complete and a client that gets `invalid_target` from a value
/// the admin API accepted.
fn validate_allowed_resources(entries: &[String]) -> Result<Vec<String>, AxiamApiError> {
    axiam_oauth2::resource::normalise_registration(entries).map_err(|(entry, err)| {
        validation_err(format!(
            "invalid allowed_resources entry {entry:?}: {}",
            err.message()
        ))
    })
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

/// Refuse a registration that names a GDPR-sensitive scope while the tenant's
/// capability is off (W7 / X7 G8, plan §4.8, test T8.1).
///
/// `axiam_oauth2::fapi::validate_registration` cannot make this check — it is
/// a pure function of the registration, it lives four layers below this crate,
/// and the answer depends on a settings row. So this is a second gate rather
/// than a widening of the first, and the two refuse different things: that one
/// refuses `address` on a `fapi2` row whatever the tenant says, this one
/// refuses it on **any** row whose tenant has not enabled the capability.
///
/// Refusing at registration rather than only at the authorization endpoint is
/// what makes the switch a switch. Without it, an operator could register the
/// scope on a client while the capability was off and discover the refusal
/// only when a user tried to sign in — and the request-time gate would be
/// carrying the whole policy on its own.
///
/// It is *not* the only gate, and deliberately so: an operator who enables the
/// capability, registers clients, and then disables it again leaves rows this
/// check has already passed. `axiam_oauth2::sensitive::decide` refuses those at
/// request time, and `release_sensitive_claims` refuses them again at UserInfo.
async fn reject_sensitive_scopes_when_disabled<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    scopes: &[String],
) -> Result<(), AxiamApiError> {
    let wanted = axiam_oauth2::sensitive::requested(scopes);
    if wanted.is_empty() {
        return Ok(());
    }
    let tenant =
        axiam_core::repository::TenantRepository::get_by_id(&state.tenant_repo, tenant_id).await?;
    let settings = axiam_core::repository::SettingsRepository::get_effective_settings(
        &state.settings_repo,
        tenant.organization_id,
        tenant_id,
    )
    .await?;
    if settings.oidc.sensitive_scopes_enabled {
        return Ok(());
    }
    Err(validation_err(format!(
        "the scope(s) {} release personal data and are not enabled for this tenant; \
         an organization administrator must set sensitive_scopes_enabled before a \
         client may register them",
        wanted.join(", ")
    )))
}

/// #636 (R101W3-02) — the scopes `requested` would **newly** put on a
/// `managed_by: dcr | cimd` client that lie outside the tenant's effective
/// `dcr_allowed_scopes`.
///
/// The ceiling (#613) withholds such a scope at every read point, so letting
/// the administrator API write one is accepting what will never be served.
/// Shares [`axiam_oauth2::scope_ceiling::applies_to`] with the read points (an
/// administrator's client is not bounded) and the same
/// [`SettingsScopePolicy`](crate::scope_policy::SettingsScopePolicy) that
/// resolves organization baseline and tenant override for them, so the
/// write-time and grant-time answers cannot disagree.
///
/// Only scopes the row does **not already hold** count. A scope the stored row
/// holds beyond a ceiling that has since narrowed is already withheld at grant
/// time — the row keeps working with the scopes inside the ceiling — so a
/// request that merely re-sends it (a form posting the whole record back) adds
/// nothing, and refusing it would strand an otherwise editable row. An edit
/// that does not send `scopes` never reaches this function.
///
/// A failed read of the policy is an error, never "no ceiling": fail closed.
async fn scopes_outside_ceiling<C: Connection + Clone>(
    state: &AppState<C>,
    stored: &OAuth2Client,
    requested: &[String],
) -> Result<Vec<String>, AxiamApiError> {
    if !axiam_oauth2::scope_ceiling::applies_to(stored.managed_by) {
        return Ok(Vec::new());
    }
    let policy = crate::scope_policy::SettingsScopePolicy::new(
        state.tenant_repo.clone(),
        state.settings_repo.clone(),
        std::sync::Arc::clone(&state.tenant_org_cache),
    );
    let ceiling = axiam_oauth2::scope_ceiling::ExternalClientScopePolicy::allowed_scopes(
        &policy,
        stored.tenant_id,
    )
    .await?;
    let mut outside: Vec<String> = Vec::new();
    for scope in requested {
        if !ceiling.contains(scope) && !stored.scopes.contains(scope) && !outside.contains(scope) {
            outside.push(scope.clone());
        }
    }
    Ok(outside)
}

/// #680 (R110W3-07) — the grants `requested` would **newly** put on a
/// `managed_by: dcr | cimd` client that a self-registration would refuse, each
/// with the reason.
///
/// Asks [`axiam_oauth2::dcr::grant_refusal`], the predicate `dcr::validate`
/// itself runs and the one `cimd::validate` shares its grant list with, so the
/// admin `PUT` and the registration endpoints cannot disagree. Same
/// held-grant exemption as [`scopes_outside_ceiling`]: a grant the stored row
/// already holds is never counted, so a form posting the whole record back
/// still saves; the exemption keeps a grant and never adds one. An
/// administrator's own client is not bounded. A failed read of the tenant's
/// policy is an error, never "no policy": fail closed.
async fn grants_refused_by_registration_policy<C: Connection + Clone>(
    state: &AppState<C>,
    stored: &OAuth2Client,
    requested: &[String],
) -> Result<Vec<String>, AxiamApiError> {
    use axiam_core::models::oauth2_client::ManagedBy;
    if !axiam_oauth2::scope_ceiling::applies_to(stored.managed_by) {
        return Ok(Vec::new());
    }
    let mode = if stored.managed_by == ManagedBy::Dcr {
        let tenant = axiam_core::repository::TenantRepository::get_by_id(
            &state.tenant_repo,
            stored.tenant_id,
        )
        .await?;
        let settings = axiam_core::repository::SettingsRepository::get_effective_settings(
            &state.settings_repo,
            tenant.organization_id,
            stored.tenant_id,
        )
        .await?;
        Some(settings.oidc.dynamic_registration)
    } else {
        None
    };
    let mut refused: Vec<String> = Vec::new();
    for grant in requested {
        if stored.grant_types.contains(grant) {
            continue;
        }
        if let Some(reason) = axiam_oauth2::dcr::grant_refusal(grant, mode) {
            refused.push(reason);
        }
    }
    Ok(refused)
}

/// #746 (R111W3-03) — what `requested` would **newly** put on a
/// `managed_by: dcr | cimd` client that its tenant's registration policy
/// bounds: `(resources, redirect_uris)`, each with the reason it is refused.
///
/// `allowed_resources` is bounded by `external_client_allowed_resources` and
/// `redirect_uris` by `dcr_allowed_redirect_hosts` (a `dcr` row) or by the CIMD
/// policy (`cimd.trusted_redirect_domains`, `restrict_same_domain`; a `cimd` row,
/// #768), through the helpers `dcr::validate` and `cimd::validate` themselves
/// call, so the admin `PUT` and the registration
/// endpoints cannot disagree. Same held-value exemption as
/// [`scopes_outside_ceiling`]: a resource or redirect URI the stored row already
/// holds is never counted, so a form posting the whole record back still saves.
/// An administrator's own client is not bounded. A failed read of the policy is
/// an error, never "no policy": fail closed. The policy is read only when the
/// request carries a member the check looks at.
async fn registration_policy_refusals<C: Connection + Clone>(
    state: &AppState<C>,
    stored: &OAuth2Client,
    resources: Option<&[String]>,
    redirect_uris: Option<&[String]>,
) -> Result<(Vec<String>, Vec<String>), AxiamApiError> {
    if !axiam_oauth2::scope_ceiling::applies_to(stored.managed_by)
        || (resources.is_none() && redirect_uris.is_none())
    {
        return Ok((Vec::new(), Vec::new()));
    }
    let tenant =
        axiam_core::repository::TenantRepository::get_by_id(&state.tenant_repo, stored.tenant_id)
            .await?;
    let settings = axiam_core::repository::SettingsRepository::get_effective_settings(
        &state.settings_repo,
        tenant.organization_id,
        stored.tenant_id,
    )
    .await?;
    let mut outside_resources = Vec::new();
    if let Some(requested) = resources {
        let fresh: Vec<String> = requested
            .iter()
            .filter(|r| !stored.allowed_resources.contains(r))
            .cloned()
            .collect();
        outside_resources = axiam_oauth2::dcr::resources_outside_policy(
            &settings.oidc.external_client_allowed_resources,
            &fresh,
        );
    }
    let mut refused_redirects = Vec::new();
    if let Some(requested) = redirect_uris {
        use axiam_core::models::oauth2_client::ManagedBy;
        for uri in requested {
            if stored.redirect_uris.contains(uri) {
                continue;
            }
            let refusal = if stored.managed_by == ManagedBy::Cimd {
                // A CIMD `client_id` is the document's URL; a row whose
                // `client_id` is not one has no host to hold a redirect to,
                // so fail closed.
                match url::Url::parse(&stored.client_id)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                {
                    Some(client_host) => axiam_oauth2::cimd::redirect_uri_refusal(
                        &settings.oidc.cimd,
                        &client_host,
                        uri,
                    ),
                    None => Some(format!(
                        "redirect_uri {uri:?}: the client_id is not a URL with a host"
                    )),
                }
            } else {
                axiam_oauth2::dcr::redirect_uri_refusal(
                    &settings.oidc.dcr_allowed_redirect_hosts,
                    uri,
                )
            };
            if let Some(reason) = refusal {
                refused_redirects.push(reason);
            }
        }
    }
    Ok((outside_resources, refused_redirects))
}

/// Grants a public client may never be registered for (T21.2).
///
/// Both mint a token on the strength of the client's own credential, and a
/// public client's credential is its `client_id` — a value that travels in
/// every authorization request it makes, in the clear, through a browser.
/// `client_credentials` would turn that into a machine token; the RFC 8693
/// exchange would turn it into somebody else's.
const GRANTS_FORBIDDEN_TO_PUBLIC_CLIENTS: &[&str] = &[
    "client_credentials",
    axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE,
    // G-7 — CIBA Core §7.1: the client authenticates at `bc-authorize`.
    CIBA_GRANT_TYPE,
];

/// Refuse a registration that says `none` and something else at the same time
/// (T21.2).
///
/// The refusals that are *about the registration's own consistency* — a
/// credential registered alongside `none` — live in
/// `axiam_oauth2::fapi::validate_registration` beside the other methods'
/// consistency rules, and the FAPI refusal needs no code at all (`none` is not
/// `is_strong()`, so a `fapi2` profile rejects it through the gate that has
/// always rejected `client_secret_post`, I5). What is left here is the one
/// question that is about this API's grant vocabulary rather than about the
/// client: which grants a public client may hold.
fn reject_public_client_grants(
    method: ClientAuthMethod,
    grant_types: &[String],
) -> Result<(), AxiamApiError> {
    if !method.is_public() {
        return Ok(());
    }
    for gt in grant_types {
        if GRANTS_FORBIDDEN_TO_PUBLIC_CLIENTS.contains(&gt.as_str()) {
            return Err(validation_err(format!(
                "a public client (token_endpoint_auth_method: none) may not be registered for \
                 the {gt} grant: it authenticates with nothing, so the only thing that grant \
                 could rest on is a client_id that travels in every authorization request this \
                 client makes. Register a confidential client for it instead"
            )));
        }
    }
    Ok(())
}

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
    reject_public_client_grants(req.token_endpoint_auth_method, &req.grant_types)?;
    let allowed_resources = validate_allowed_resources(&req.allowed_resources)?;
    reject_unimplemented_dpop_nonce(Some(req.dpop_require_nonce))?;
    // R101W2-04 — an empty string on create is "none", as it is on update.
    let backchannel_logout_uri = req.backchannel_logout_uri.filter(|u| !u.is_empty());
    if let Some(ref uri) = backchannel_logout_uri {
        validate_backchannel_logout_uri(uri)?;
    }
    // redirect_uris are only required when the client uses
    // authorization_code (which involves user-agent redirects).
    // M2M clients (client_credentials only) don't need them.
    let needs_redirects = req.grant_types.iter().any(|g| g == "authorization_code");
    if needs_redirects {
        validate_redirect_uris(&req.redirect_uris)?;
    }
    let ciba = validate_ciba(axiam_oauth2::ciba::CibaRegistrationView {
        grant_types: &req.grant_types,
        token_endpoint_auth_method: req.token_endpoint_auth_method,
        profile: req.profile,
        delivery_mode: req.backchannel_token_delivery_mode.as_deref(),
        notification_endpoint: req.backchannel_client_notification_endpoint.as_deref(),
        signing_alg: req
            .backchannel_authentication_request_signing_alg
            .as_deref(),
        user_code_parameter: req.backchannel_user_code_parameter,
        jwks: req.jwks.as_deref(),
        jwks_uri: req.jwks_uri.as_deref(),
    })?;

    let create = CreateOAuth2Client {
        tenant_id: user.tenant_id,
        name: req.name,
        redirect_uris: req.redirect_uris,
        grant_types: req.grant_types,
        scopes: req.scopes,
        post_logout_redirect_uris: req.post_logout_redirect_uris,
        backchannel_logout_uri,
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
        authn_request_params: req.authn_request_params,
        browser_sso: req.browser_sso,
        allowed_resources,
        // T21.4 / D5 — this endpoint is the definition of an administrator's
        // client. Not read from the request body: `CreateOAuth2ClientRequest`
        // has no such member, so an API caller cannot claim a provenance, and
        // this is the one handler entitled to assert `admin`.
        managed_by: axiam_core::models::oauth2_client::ManagedBy::Admin,
        ciba,
    };

    // X5.1 — refuse a registration that could not satisfy the profile it
    // declares, BEFORE it is written. A `fapi2` client missing PAR or mTLS
    // would otherwise be created and then fail every request it ever made,
    // which is a configuration error discovered by the client's users rather
    // than by the operator making it. A `standard` client with a secret — every
    // client that predates X5.1 — passes without a check running.
    axiam_oauth2::fapi::validate_registration(&create)
        .map_err(|e| validation_err(e.to_string()))?;
    // W7 — the tenant switch's registration half.
    reject_sensitive_scopes_when_disabled(&state, user.tenant_id, &create.scopes).await?;

    let (client, raw_secret) = state.oauth2_client_repo.create(create).await?;

    // T21.2 — a public client has no secret to show. The decision is read off
    // the stored method rather than off `raw_secret.is_empty()`: the two agree
    // by construction (the repository mints nothing for `none`), and asking
    // the registration means a future bug in the repository surfaces as an
    // operator who cannot find their secret, not as a client silently treated
    // as public.
    let client_secret = (!client.token_endpoint_auth_method.is_public()).then_some(raw_secret);

    Ok(HttpResponse::Created().json(OAuth2ClientCreatedResponse {
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.client_id,
        client_secret,
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
        (status = 409, description = "The client was written by another request after this one read it; the patch was validated against the row it read, so nothing is written. Read the client again and retry."),
        (status = 422, description = "The client is managed_by dcr or cimd and the request adds a scope outside the tenant's effective dcr_allowed_scopes (`scope_exceeds_ceiling`), a grant its registration endpoint would refuse (`grant_exceeds_registration_policy`), an allowed_resources entry outside the tenant's external_client_allowed_resources (`resource_exceeds_registration_policy`), or a redirect URI its registration would refuse: a host outside dcr_allowed_redirect_hosts for a dcr client, or one the tenant's CIMD policy (cimd.trusted_redirect_domains, restrict_same_domain, https or loopback, no fragment) does not admit for a cimd client (`redirect_exceeds_registration_policy`); the message names each, and the client is unchanged. A scope, grant, resource or redirect URI the row already holds is not counted. An administrator-managed client is not bounded."),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    http: HttpRequest,
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
    // R101W2-04 — an empty string clears the URI and is not validated; any
    // other value is held to the same rule as on create.
    if let Some(ref uri) = req.backchannel_logout_uri
        && !uri.is_empty()
    {
        validate_backchannel_logout_uri(uri)?;
    }
    let allowed_resources = req
        .allowed_resources
        .as_deref()
        .map(validate_allowed_resources)
        .transpose()?;

    // Item 9 of the 1.1.0 atomicity audit: every rule below is checked against
    // ONE read of the row, and the write is conditional on that read
    // (`update_if_unchanged`). Each rule used to read the row again and the
    // write set only the patch's own fields, so two patches each validated
    // against the row before the other could both land, leaving a merged row
    // neither had validated. A row written since this read now answers `409`,
    // and the caller reads it again. The version is the one read here, so the
    // request carries nothing new.
    let stored = state
        .oauth2_client_repo
        .get_by_id(user.tenant_id, id)
        .await?;

    // #680 (R110W3-07) — a self-registered (`dcr`) or CIMD client holds no grant a
    // registration would refuse. Asked first, before the structural rules below, so
    // the answer is the policy's rather than a `400` about the grant's own shape.
    // It composes with the #675 public-conversion rule: that rule needs a
    // device-only stored row. A self-registration never gives a row the device
    // grant; an older admin edit may have.
    if let Some(ref requested) = req.grant_types {
        let refused = grants_refused_by_registration_policy(&state, &stored, requested).await?;
        if !refused.is_empty() {
            return Ok(crate::error::unprocessable_entity(
                "grant_exceeds_registration_policy",
                format!(
                    "this client is managed_by {} and the administrator API may not give it \
                     a grant its registration would be refused: {}; register an \
                     administrator-managed client for it instead",
                    stored.managed_by,
                    refused.join("; "),
                ),
            ));
        }
    }

    // T21.2 — `none` is a registration decision, and it stays one (I4).
    //
    // A PATCH may not move a client across the public/confidential line,
    // because the secret cannot follow it. Going public would leave a live
    // secret hash on a row whose token-endpoint arm never reads it — a
    // credential an operator believes they revoked by changing the method, and
    // SEC-093's exact shape. Going confidential would leave a row with no hash
    // at all, so every authentication attempt fails on a secret that was never
    // minted and cannot be minted by this endpoint, which only ever shows one
    // at creation.
    //
    // One exception (#675, D-4): a confidential client whose grants are only
    // the device grant and `refresh_token` may become public. Since #635 both
    // device endpoints authenticate the client by its registered method, so a
    // 1.0.x device client registered with the default `client_secret_post`
    // is refused at the upgrade while its devices — built to CONTRACT §14.1 —
    // send `client_id` alone. The conversion lets those devices keep their
    // `client_id`, and the objection above does not apply to it: the
    // repository clears `client_secret_hash` in the same write that sets
    // `none`, so no stale secret survives. Both the stored and the patched
    // grants must be device-only, so the conversion never lands on a client
    // that holds `client_credentials`, token exchange or CIBA, and the
    // operator cannot strip such a grant and go public in one request.
    // Every other conversion, and every conversion to confidential, is still
    // refused with a message that names the remedy: register the client the
    // operator actually wants.
    let mut converted_from = None;
    if let Some(requested_method) = req.token_endpoint_auth_method {
        let existing_method = stored.token_endpoint_auth_method;
        if requested_method.is_public() != existing_method.is_public() {
            let patched_grants = req.grant_types.as_deref().unwrap_or(&stored.grant_types);
            if requested_method.is_public()
                && holds_only_device_grants(&stored.grant_types)
                && holds_only_device_grants(patched_grants)
            {
                converted_from = Some(existing_method);
            } else {
                return Err(validation_err(format!(
                    "token_endpoint_auth_method cannot be changed from {} to {}: whether a \
                     client is public is decided at registration, because the client secret \
                     cannot follow the change — this endpoint mints one only at creation, and a \
                     stale one on a public row would be a credential AXIAM never checks. The one \
                     exception is a confidential client whose grant_types are only the device \
                     grant and refresh_token, which may be made public (its secret is cleared). \
                     Register a new client with the method you want",
                    existing_method.as_str(),
                    requested_method.as_str(),
                )));
            }
        }
    }
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
        if stored.redirect_uris.is_empty() {
            return Err(validation_err(
                "redirect_uris are required when enabling \
                 authorization_code grant",
            ));
        }
        validate_redirect_uris(&stored.redirect_uris)?;
    }

    // G-7 — the CIBA metadata is validated against the row the patch will
    // produce whenever the patch touches anything the rules read: the grants,
    // the method, the profile or the metadata itself. Untouched metadata is
    // carried only while the merged grants still hold CIBA; a patch that
    // removes the grant drops it rather than leaving it unread on the row.
    let ciba_touched = req.backchannel_token_delivery_mode.is_some()
        || req.backchannel_client_notification_endpoint.is_some()
        || req.backchannel_authentication_request_signing_alg.is_some()
        || req.backchannel_user_code_parameter.is_some();
    // D-61: the key source is read too — removing the keys a signing
    // algorithm is verified against must not leave the algorithm stranded.
    let ciba = if ciba_touched
        || req.grant_types.is_some()
        || req.profile.is_some()
        || req.token_endpoint_auth_method.is_some()
        || req.jwks.is_some()
        || req.jwks_uri.is_some()
    {
        let grants = req.grant_types.as_deref().unwrap_or(&stored.grant_types);
        let keep_stored = axiam_oauth2::ciba::holds_ciba_grant(grants);
        let stored_mode = stored
            .ciba
            .backchannel_token_delivery_mode
            .filter(|_| keep_stored)
            .map(|m| m.as_str().to_owned());
        let stored_endpoint = stored
            .ciba
            .backchannel_client_notification_endpoint
            .clone()
            .filter(|_| keep_stored);
        let stored_signing_alg = stored
            .ciba
            .backchannel_authentication_request_signing_alg
            .filter(|_| keep_stored)
            .map(|a| a.as_str().to_owned());
        let mode = req.backchannel_token_delivery_mode.clone().or(stored_mode);
        let endpoint = req
            .backchannel_client_notification_endpoint
            .clone()
            .or(stored_endpoint);
        let signing_alg = req
            .backchannel_authentication_request_signing_alg
            .clone()
            .or(stored_signing_alg);
        // `Some("")` clears, as the repository will store it.
        let jwks = req.jwks.clone().or(stored.jwks.clone());
        let jwks_uri = req.jwks_uri.clone().or(stored.jwks_uri.clone());
        Some(validate_ciba(axiam_oauth2::ciba::CibaRegistrationView {
            grant_types: grants,
            token_endpoint_auth_method: req
                .token_endpoint_auth_method
                .unwrap_or(stored.token_endpoint_auth_method),
            profile: req.profile.unwrap_or(stored.profile),
            delivery_mode: mode.as_deref(),
            notification_endpoint: endpoint.as_deref(),
            signing_alg: signing_alg.as_deref(),
            user_code_parameter: req.backchannel_user_code_parameter,
            jwks: jwks.as_deref(),
            jwks_uri: jwks_uri.as_deref(),
        })?)
    } else {
        None
    };

    // #636 (R101W3-02) — a self-registered (`dcr`) or CIMD client holds no scope
    // the tenant's `dcr_allowed_scopes` does not offer. Checked before anything
    // is written, so a refusal leaves the row as it was.
    if let Some(ref requested) = req.scopes {
        let outside = scopes_outside_ceiling(&state, &stored, requested).await?;
        if !outside.is_empty() {
            return Ok(crate::error::unprocessable_entity(
                "scope_exceeds_ceiling",
                format!(
                    "the scope(s) {} are outside the tenant's dcr_allowed_scopes, and this \
                     client is managed_by {} so it can never be served them; add them to \
                     dcr_allowed_scopes first, or register an administrator-managed client",
                    outside.join(", "),
                    stored.managed_by,
                ),
            ));
        }
    }

    // #746 (R111W3-03) — nor an audience or a redirect host its registration
    // would refuse: `allowed_resources` is the tenant's list and nothing else (D3),
    // and `redirect_uris` stay within `dcr_allowed_redirect_hosts` (a `dcr` row) or
    // the CIMD policy (a `cimd` row).
    let (outside_resources, refused_redirects) = registration_policy_refusals(
        &state,
        &stored,
        allowed_resources.as_deref(),
        req.redirect_uris.as_deref(),
    )
    .await?;
    if !outside_resources.is_empty() {
        return Ok(crate::error::unprocessable_entity(
            "resource_exceeds_registration_policy",
            format!(
                "the allowed_resources {} are outside the tenant's \
                 external_client_allowed_resources, and this client is managed_by {} so its \
                 audiences are the tenant's list; add them there first, or register an \
                 administrator-managed client",
                outside_resources.join(", "),
                stored.managed_by,
            ),
        ));
    }
    if !refused_redirects.is_empty() {
        return Ok(crate::error::unprocessable_entity(
            "redirect_exceeds_registration_policy",
            format!(
                "this client is managed_by {} and the administrator API may not give it a \
                 redirect its registration would be refused: {}; change the tenant's \
                 dcr_allowed_redirect_hosts (dcr) or cimd.trusted_redirect_domains and \
                 restrict_same_domain (cimd) first, or register an administrator-managed client",
                stored.managed_by,
                refused_redirects.join("; "),
            ),
        ));
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
        authn_request_params: req.authn_request_params,
        browser_sso: req.browser_sso,
        allowed_resources,
        ciba,
    };

    // X5.1 — validate the MERGED result, not the patch. Flipping `profile` to
    // `fapi2` on a client that has none of the rest is a perfectly well-formed
    // patch and a completely broken client; validating the patch alone would
    // wave it through. The merge is onto the row read above, the one the write
    // is conditional on, so what is validated here is what will be stored.
    if update.touches_security_profile() {
        let merged = stored.clone().with_update_applied(&update);
        axiam_oauth2::fapi::validate_registration(&merged)
            .map_err(|e| validation_err(e.to_string()))?;
        // W7 — and on the update path too, on the **merged** row, so a patch
        // that adds `address` to a client registered without it is refused by
        // the same rule that would have refused it at creation. A gate that
        // only ran on create is a gate with an `PATCH` around it.
        reject_sensitive_scopes_when_disabled(&state, user.tenant_id, &merged.scopes).await?;
    }

    // #749 (R111W3-01) — a conversion revokes what the client was issued while
    // confidential. Its refresh tokens and device grants could be redeemed only
    // with the secret; once the client is public the same ones redeem on
    // `client_id` alone. First pass before the write, and its failure refuses
    // the request: nothing is converted, and the retry is the whole request.
    // The other order could not be retried, because the repeat `PUT` finds the
    // client already public and is no conversion.
    let mut revoked = if converted_from.is_some() {
        revoke_confidential_era_grants(&state, user.tenant_id, &stored.client_id).await?
    } else {
        RevokedGrants::default()
    };

    let client = state
        .oauth2_client_repo
        .update_if_unchanged(user.tenant_id, id, update, stored.updated_at)
        .await?;
    if let Some(from) = converted_from {
        // Second pass: a refresh or a device request that read the
        // confidential row before the write may have issued a grant since the
        // first. Logged and recorded rather than returned, as `delete` does:
        // the conversion is durable, and a `5xx` for it would be retried as a
        // no-op that answers `200`.
        let complete = match revoke_confidential_era_grants(
            &state,
            user.tenant_id,
            &client.client_id,
        )
        .await
        {
            Ok(again) => {
                revoked.refresh_tokens += again.refresh_tokens;
                revoked.device_grants += again.device_grants;
                true
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    tenant_id = %user.tenant_id,
                    client_id = %client.client_id,
                    "a client converted to public could not have its grants revoked a second time"
                );
                false
            }
        };
        audit_conversion_to_public(&state, &http, &user, &client, from, revoked, complete).await;
    }
    Ok(HttpResponse::Ok().json(OAuth2ClientResponse::from(client)))
}

/// What [`revoke_confidential_era_grants`] revoked (#749).
#[derive(Debug, Default, Clone, Copy)]
struct RevokedGrants {
    refresh_tokens: u64,
    device_grants: u64,
}

/// #749 (R111W3-01) — revoke the refresh tokens and delete the device grants
/// of a client made public. A device-only client holds no other grant (no code,
/// pushed request or CIBA request), so [`revoke_client_grants`]'s other stores
/// are not visited. Idempotent, so it runs before and again after the write.
async fn revoke_confidential_era_grants<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<RevokedGrants, axiam_core::error::AxiamError> {
    let refresh_tokens = state
        .refresh_token_repo
        .revoke_all_for_client(tenant_id, client_id)
        .await?;
    let device_grants = axiam_db::SurrealDeviceGrantRepository::new(state.db.clone())
        .delete_all_for_client(tenant_id, client_id)
        .await?;
    Ok(RevokedGrants {
        refresh_tokens,
        device_grants,
    })
}

/// #675 (D-4) — the grants a confidential client may hold and still be made
/// public by `PUT`: the device grant, in either spelling, and `refresh_token`.
const GRANTS_CONVERTIBLE_TO_PUBLIC: &[&str] = &[
    axiam_oauth2::device_service::DEVICE_CODE_GRANT_SPELLINGS[0],
    axiam_oauth2::device_service::DEVICE_CODE_GRANT_SPELLINGS[1],
    "refresh_token",
];

/// Whether `grant_types` holds the device grant and nothing but
/// [`GRANTS_CONVERTIBLE_TO_PUBLIC`].
fn holds_only_device_grants(grant_types: &[String]) -> bool {
    grant_types
        .iter()
        .any(|g| axiam_oauth2::device_service::DEVICE_CODE_GRANT_SPELLINGS.contains(&g.as_str()))
        && grant_types
            .iter()
            .all(|g| GRANTS_CONVERTIBLE_TO_PUBLIC.contains(&g.as_str()))
}

/// The audit action of a confidential device client made public (#675).
pub const CLIENT_CONVERTED_TO_PUBLIC_ACTION: &str = "oauth2.client_converted_to_public";

/// The one audit row of a conversion to public (#675, D-4), with what the
/// conversion revoked (#749) and whether the second revocation pass completed.
/// Awaited, not detached; the conversion is already durable, so a failed append
/// is logged rather than undoing it.
async fn audit_conversion_to_public<C: Connection + Clone>(
    state: &AppState<C>,
    http: &HttpRequest,
    user: &AuthenticatedUser,
    client: &OAuth2Client,
    from: ClientAuthMethod,
    revoked: RevokedGrants,
    revocation_complete: bool,
) {
    let entry = CreateAuditLogEntry {
        tenant_id: client.tenant_id,
        actor_id: user.user_id,
        actor_type: ActorType::User,
        action: CLIENT_CONVERTED_TO_PUBLIC_ACTION.into(),
        resource_id: Some(client.id),
        outcome: AuditOutcome::Success,
        ip_address: client_ip(http),
        metadata: Some(serde_json::json!({
            "client_id": client.client_id,
            "from": from.as_str(),
            "to": client.token_endpoint_auth_method.as_str(),
            "grant_types": client.grant_types,
            "client_secret_cleared": true,
            "refresh_tokens_revoked": revoked.refresh_tokens,
            "device_grants_deleted": revoked.device_grants,
            "revocation_complete": revocation_complete,
        })),
    };
    if let Err(e) = state.audit_repo.append(entry).await {
        tracing::error!(
            error = %e,
            client_id = %client.client_id,
            "failed to write the audit row of a client converted to public"
        );
    }
}

/// `DELETE /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    responses(
        (status = 204, description = "OAuth2 client deleted; its refresh tokens, authorization codes, pushed requests, device grants and CIBA requests are revoked or deleted first"),
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
    let client = state
        .oauth2_client_repo
        .get_by_id(user.tenant_id, id)
        .await?;

    // #517 — revoke first, and refuse the delete if that fails. The other
    // order would leave a row-less client whose grants are still live, and a
    // retry would answer `404`: for a `managed_by: cimd` client the next
    // request re-materialises the row under the same `client_id` and every one
    // of those refresh tokens, codes and pushed requests works again.
    revoke_client_grants(&state, user.tenant_id, &client.client_id).await?;
    state.oauth2_client_repo.delete(user.tenant_id, id).await?;

    // A refresh or an authorization that read the row before the delete can
    // still have written a token or a code between the two writes above; one
    // more pass leaves nothing live.
    // Logged rather than returned, because the client is already gone.
    if let Err(e) = revoke_client_grants(&state, user.tenant_id, &client.client_id).await {
        tracing::error!(
            error = %e,
            tenant_id = %user.tenant_id,
            client_id = %client.client_id,
            "a deleted client's grants could not be revoked a second time"
        );
    }
    Ok(HttpResponse::NoContent().finish())
}

/// Revoke what deleting a client must revoke: its refresh tokens, its
/// authorization codes, its pushed requests, and (#610 (d)) its device grants
/// and CIBA requests (#517). Both deletion paths
/// call it — `DELETE /api/v1/oauth2-clients/{id}` (an administrator) and RFC
/// 7592's `DELETE /oauth2/register/{client_id}` (the client itself) — and the
/// unused-client sweep calls the same [`ClientGrantStores::revoke`]. What is
/// revoked, what is not, and why, is written once on
/// [`axiam_oauth2::client_grants`].
pub(crate) async fn revoke_client_grants<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<(), axiam_core::error::AxiamError> {
    ClientGrantStores::new(
        state.refresh_token_repo.clone(),
        axiam_db::SurrealAuthorizationCodeRepository::new(state.db.clone()),
        axiam_db::SurrealPushedAuthRequestRepository::new(state.db.clone()),
        axiam_db::SurrealDeviceGrantRepository::new(state.db.clone()),
        // Only `delete_all_for_client` is called, which needs no sealing key.
        axiam_db::SurrealCibaRequestRepository::new(state.db.clone(), None),
    )
    .revoke(tenant_id, client_id)
    .await
}

#[cfg(test)]
mod redirect_registration_pin {
    use super::validate_redirect_uris;

    /// G-2 / T23.2.1 — the SAML ACS allow-list shares this registration rule
    /// (`axiam_federation::saml_sp::check_redirect_uri_registration`, which
    /// this endpoint now calls). The same accept/refuse list is pinned in that
    /// crate against the ACS validator; pinning it here against the admin API's
    /// own entry point means a change to either surface fails a test.
    #[test]
    fn the_admin_api_accepts_and_refuses_the_pinned_redirect_list() {
        for uri in [
            "https://app.example.com/cb",
            "https://app.example.com:8443/cb?x=1",
            "http://localhost/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1/cb",
            "http://127.0.0.1:8080/cb",
            "http://[::1]/cb",
            "http://[::1]:9000/cb",
        ] {
            assert!(
                validate_redirect_uris(&[uri.to_owned()]).is_ok(),
                "{uri} must be registrable"
            );
        }
        for uri in [
            "",
            "not a url",
            "/relative/path",
            "https://app.example.com/cb#frag",
            "http://app.example.com/cb",
            "http://localhost.example.com/cb",
            "ftp://app.example.com/cb",
            "javascript:alert(1)",
            "myapp://callback",
            "mailto:a@example.com",
        ] {
            assert!(
                validate_redirect_uris(&[uri.to_owned()]).is_err(),
                "{uri} must not be registrable"
            );
        }
        assert!(
            validate_redirect_uris(&[]).is_err(),
            "an empty list is refused"
        );
    }
}
