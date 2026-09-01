//! The public "Sign in with X" surface.
//!
//! Everything an unauthenticated browser touches during a federated login that
//! is not already in [`super::federation`]: which providers to render, the
//! OAuth2 variant's two halves, the two cross-site form-POST returns, and the
//! handoff exchange those returns need.
//!
//! It is a separate module from `federation.rs` because the two have different
//! audiences. `federation.rs` is the tenant-admin CRUD surface, gated on
//! `federation:*` permissions. Everything here is reachable with no credential
//! at all, and every one of these routes therefore appears in **both**
//! `PUBLIC_PATHS` and `CSRF_EXEMPT_SUFFIXES` and carries a rate limit.
//!
//! See `claude_dev/federation-sso-login-design.md` §5.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::federation::{FederationConfig, FederationProtocol};
use axiam_core::models::tenant::TenantKind;
use axiam_core::repository::{
    FederationConfigRepository, FederationLoginState, FederationLoginStateRepository,
    OrganizationRepository, SSO_HANDOFF_TTL_SECS, SsoHandoffCode, SsoHandoffCodeRepository,
    TenantRepository, UserRepository,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use tracing::{info, warn};
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::state::AppState;

use super::federation::{
    SsoLoginSuccessResponse, random_base64url, sso_login_post_auth, validate_redirect_uri,
    validation_err,
};

/// How long a federation login state row lives.
///
/// Ten minutes, unchanged: a human is reading an IdP consent screen in the
/// middle of it.
const LOGIN_STATE_TTL_MINUTES: i64 = 10;

/// Server-side path Apple posts its authorization response to.
const OIDC_FORM_CALLBACK_PATH: &str = "/api/v1/auth/federation/oidc/callback/form";

/// Server-side path a SAML IdP posts its assertion to.
#[cfg(feature = "saml")]
const SAML_FORM_ACS_PATH: &str = "/api/v1/auth/federation/saml/acs/form";

/// Query parameter carrying a handoff code back into the SPA.
const HANDOFF_QUERY_PARAM: &str = "axiam_handoff";

// ---------------------------------------------------------------------------
// Workspace resolution
// ---------------------------------------------------------------------------

/// Which organization and tenant a public federation request is for.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Workspace {
    pub organization_id: Uuid,
    pub tenant_id: Uuid,
}

/// Resolve `(org, tenant)` from slugs or ids.
///
/// An omitted tenant means the **organization scope**, matching the login
/// page's "leave blank to sign in at organization level". That is a real tenant
/// row (`TenantKind::Organization`), so everything downstream treats it
/// uniformly.
///
/// Two failure modes, kept apart because they are different mistakes:
///
/// * [`WorkspaceError::Missing`] — the request named no organization at all.
///   That is a malformed request, and answering `401` would tell a client with
///   a bug that their credentials were wrong.
/// * [`WorkspaceError::Unresolved`] — an organization or tenant that does not
///   resolve. The caller decides what that means: `401` on the start endpoints,
///   which must not become a slug oracle, or an empty list on the providers
///   endpoint (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceError {
    /// No `org_id` and no `org_slug`.
    Missing,
    /// A slug or id that names nothing.
    Unresolved,
}

pub(crate) async fn resolve_workspace<C: Connection + Clone>(
    state: &AppState<C>,
    org_id: Option<Uuid>,
    org_slug: Option<&str>,
    tenant_id: Option<Uuid>,
    tenant_slug: Option<&str>,
) -> Result<Workspace, WorkspaceError> {
    let organization_id = match (org_id, org_slug.map(str::trim).filter(|s| !s.is_empty())) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| WorkspaceError::Unresolved)?
                .id
        }
        (None, None) => return Err(WorkspaceError::Missing),
    };

    let tenant_id = match (
        tenant_id,
        tenant_slug.map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .tenant_repo
                .get_by_slug(organization_id, slug)
                .await
                .map_err(|_| WorkspaceError::Unresolved)?
                .id
        }
        // No tenant named ⇒ the organization's own scope. This is what the
        // login page's blank tenant field means, and the providers endpoint
        // resolves it the same way — if `start` demanded a tenant here, the
        // buttons an organization-level user sees could not be clicked.
        (None, None) => {
            state
                .tenant_repo
                .get_organization_tenant(organization_id)
                .await
                .map_err(|_| WorkspaceError::Unresolved)?
                .id
        }
    };

    Ok(Workspace {
        organization_id,
        tenant_id,
    })
}

// ---------------------------------------------------------------------------
// Inheritance resolution
// ---------------------------------------------------------------------------

/// A provider that is effective for a tenant, and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct EffectiveProvider {
    pub config: FederationConfig,
    /// `true` when the config lives in the organization-scope tenant and this
    /// tenant is using it by inheritance.
    pub inherited: bool,
}

/// Every provider a tenant may sign in with.
///
/// The rule, restated from the design doc because this function is the only
/// place it exists in code:
///
/// * the tenant's own **enabled** configs, plus
/// * the organization tenant's **enabled** configs with
///   `allow_tenant_inheritance`, minus any whose override key the tenant
///   already uses.
///
/// The subtraction deliberately uses the tenant's configs **including disabled
/// ones**. A tenant administrator who created a Google config and disabled it
/// has said something about Google in this tenant, and the something is "no";
/// falling back to the inherited config there would make "disable" mean
/// "re-enable the organization's".
pub(crate) async fn effective_providers<C: Connection + Clone>(
    state: &AppState<C>,
    workspace: Workspace,
) -> Result<Vec<EffectiveProvider>, AxiamApiError> {
    let own_all = state
        .federation
        .federation_config_repo
        .list_all(workspace.tenant_id)
        .await?;

    let mut effective: Vec<EffectiveProvider> = own_all
        .iter()
        .filter(|c| c.enabled)
        .cloned()
        .map(|config| EffectiveProvider {
            config,
            inherited: false,
        })
        .collect();

    // An organization-scope tenant has nothing to inherit *from*; it is the
    // thing others inherit from.
    let org_tenant = match state
        .tenant_repo
        .get_organization_tenant(workspace.organization_id)
        .await
    {
        Ok(t) => t,
        // A deployment that predates organization scope has no organization
        // tenant, and therefore no inheritance. That is what such a deployment
        // has always had, so it is not an error.
        Err(_) => return Ok(effective),
    };
    if org_tenant.id == workspace.tenant_id || org_tenant.kind != TenantKind::Organization {
        return Ok(effective);
    }

    let shadowed: Vec<String> = own_all.iter().map(FederationConfig::override_key).collect();

    let inherited = state
        .federation
        .federation_config_repo
        .list_all(org_tenant.id)
        .await?;

    for config in inherited {
        if !config.enabled || !config.allow_tenant_inheritance {
            continue;
        }
        if shadowed.contains(&config.override_key()) {
            continue;
        }
        effective.push(EffectiveProvider {
            config,
            inherited: true,
        });
    }

    Ok(effective)
}

/// Resolve one config id for a login, honouring inheritance.
///
/// Two steps on purpose. Visibility is decided by [`effective_providers`], so
/// the set of providers a login can use is *exactly* the set the buttons were
/// rendered from — a config that is disabled, not inheritable, or shadowed
/// cannot be reached by posting its id. Only then is the full row loaded, from
/// the tenant that owns it, because the callback needs the encrypted secret
/// columns that the listing projection deliberately omits.
pub(crate) async fn resolve_config_for_login<C: Connection + Clone>(
    state: &AppState<C>,
    workspace: Workspace,
    config_id: Uuid,
) -> Result<EffectiveProvider, AxiamApiError> {
    let effective = effective_providers(state, workspace).await?;
    let Some(found) = effective.into_iter().find(|p| p.config.id == config_id) else {
        // Uniform with `oidc_start_public`'s slug miss: a caller learns that
        // the request failed, not whether the config exists somewhere they
        // cannot use it.
        return Err(AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid federation request".into(),
        }));
    };

    let full = state
        .federation
        .federation_config_repo
        .get_by_id(found.config.tenant_id, config_id)
        .await?;

    Ok(EffectiveProvider {
        config: full,
        inherited: found.inherited,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/auth/federation/providers
// ---------------------------------------------------------------------------

/// Query for the public providers listing.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ProvidersQuery {
    /// Organization UUID. Alternative to `org_slug`.
    pub org_id: Option<Uuid>,
    /// Organization slug, as typed on the login page.
    pub org_slug: Option<String>,
    /// Tenant UUID. Alternative to `tenant_slug`.
    pub tenant_id: Option<Uuid>,
    /// Tenant slug. Omitted or blank means the organization's own scope.
    pub tenant_slug: Option<String>,
}

/// One sign-in button.
///
/// A dedicated struct rather than a narrowed [`super::federation::FederationConfigResponse`]:
/// this is an **unauthenticated** response, and a field added to the admin
/// response must not be able to reach it by inheritance. What is here is what a
/// button needs and nothing else; `client_id`, `metadata_url`, the OAuth2
/// endpoints and every secret column are absent by construction, not by
/// filtering.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicFederationProvider {
    /// Config id, to be echoed back to the matching start endpoint.
    pub id: Uuid,
    /// Which provider this is, for the button's branding.
    pub provider_kind: String,
    /// The operator's display name for the provider.
    pub display_name: String,
    /// `OidcConnect`, `Saml` or `OAuth2` — selects which start endpoint the
    /// client calls.
    pub protocol: String,
    /// Whether AXIAM ships this provider's own sign-in mark.
    ///
    /// `true` for the branded kinds, whose buttons must use it. `false` for the
    /// generic kinds, whose buttons read "Sign in with <display_name>" and use
    /// `button_icon` when the operator uploaded one.
    pub has_bundled_mark: bool,
    /// The operator's uploaded button icon, as a bounded raster data URL.
    ///
    /// Present only for generic providers that have one. It is branding rather
    /// than configuration — nothing about the provider's identity, endpoints or
    /// credentials is derivable from a picture — which is why it is the one
    /// additional field this unauthenticated response carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button_icon: Option<String>,
    /// `true` when the provider is inherited from the organization.
    ///
    /// Not needed to sign in, and returned because the admin UI reuses this
    /// endpoint's shape and a tenant administrator must be able to see that a
    /// provider is not theirs to edit.
    pub inherited: bool,
}

/// Response body for the public providers listing.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PublicFederationProvidersResponse {
    /// Providers to offer, in a stable order.
    pub providers: Vec<PublicFederationProvider>,
}

/// `GET /api/v1/auth/federation/providers`
///
/// Which "Sign in with X" buttons to render for a workspace.
///
/// # Why an unknown organization gets `200 []` and not `401`
///
/// `oidc_start_public` answers `401` for a slug miss, deliberately, so it does
/// not enumerate tenants — and there that works, because *every* failure on
/// that endpoint is a `401` and the answer carries no information.
///
/// This endpoint's answer is a **list**, so the two shapes are distinguishable:
/// `401` for an unknown organization against `200 []` for a known one with no
/// providers would be a two-valued oracle and a perfect organization-slug
/// enumerator. `200 []` for both leaks nothing, and it is also the only shape
/// the login page can render without a special case. What bounds the guessing
/// rate is the rate limit, which is the same login budget the start endpoints
/// use.
#[utoipa::path(
    get,
    path = "/api/v1/auth/federation/providers",
    tag = "federation-sso",
    params(ProvidersQuery),
    responses(
        (status = 200, description = "Providers configured for this workspace \
            (empty for an unknown organization or tenant)",
         body = PublicFederationProvidersResponse),
    )
)]
pub async fn list_providers_public<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    query: web::Query<ProvidersQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    let q = query.into_inner();

    let Ok(workspace) = resolve_workspace(
        &state,
        q.org_id,
        q.org_slug.as_deref(),
        q.tenant_id,
        q.tenant_slug.as_deref(),
    )
    .await
    else {
        // Both failure modes answer the same way here. A malformed query and an
        // unknown organization must be indistinguishable, or the difference is
        // itself the oracle this endpoint is shaped to avoid.
        return Ok(HttpResponse::Ok().json(PublicFederationProvidersResponse {
            providers: Vec::new(),
        }));
    };

    let providers = effective_providers(&state, workspace)
        .await?
        .into_iter()
        .map(|p| PublicFederationProvider {
            id: p.config.id,
            provider_kind: p.config.provider_kind.as_str().to_owned(),
            display_name: p.config.provider,
            protocol: p.config.protocol.as_str().to_owned(),
            has_bundled_mark: p.config.provider_kind.has_bundled_mark(),
            button_icon: p.config.button_icon.clone(),
            inherited: p.inherited,
        })
        .collect();

    Ok(HttpResponse::Ok().json(PublicFederationProvidersResponse { providers }))
}

// ---------------------------------------------------------------------------
// Handoff codes
// ---------------------------------------------------------------------------

/// The origin part of a URL — scheme, host and port — or `None` if it has none.
///
/// `url::Origin::ascii_serialization` is what makes the comparison total: it
/// normalises the default port away, so `https://app.example.com` and
/// `https://app.example.com:443/` are the same origin, and a path or query
/// cannot smuggle a second host past a string compare.
fn origin_of(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// Refuse a handoff redirect target that is not an origin this deployment owns.
///
/// # Why this is not `validate_redirect_uri`
///
/// [`validate_redirect_uri`] checks the *scheme* only — any `https://` host on
/// the internet passes it, and its own `TODO(T19.14)` says so. On the OIDC and
/// OAuth2 flows that is backstopped by the identity provider, which is handed
/// the same `redirect_uri` and compares it against its registered set before it
/// will redirect anything anywhere.
///
/// The two cross-site flows have no such backstop **by construction**: a SAML
/// IdP is pointed at [`saml_acs_url`] and Apple at
/// [`server_form_callback_url`], both AXIAM's own endpoints, so the provider
/// never sees the SPA URI and never validates it. AXIAM alone decides where the
/// browser goes next — and it goes there carrying a handoff code, which
/// [`sso_handoff_public`] will exchange for session cookies for whoever
/// presents it.
///
/// Without this check, anyone could call the unauthenticated login-start
/// endpoint with `redirect_uri = https://attacker.example/`, lure a victim
/// through their own real IdP, and read a working session credential out of
/// their access log. The 60-second TTL, the single use, the hash-only storage
/// and `Referrer-Policy: no-referrer` are all irrelevant when the attacker *is*
/// the redirect destination. This is the same rule the OAuth2 authorization
/// server already applies to its own `redirect_uri` (threat model T-52), and
/// threat model T-164 for the handoff mechanism.
///
/// The allowed set is the origin of `AuthConfig::effective_issuer()` — which
/// the ACS and form-callback URLs are themselves built from, so it cannot be
/// wrong in a deployment where these flows work at all — plus anything the
/// operator adds in [`AuthConfig::sso_spa_origins`], for a deployment that
/// serves the SPA from a different host than the API.
pub(crate) fn require_deployment_spa_origin<C: Connection + Clone>(
    state: &AppState<C>,
    redirect_uri: &str,
) -> Result<(), AxiamApiError> {
    require_spa_origin(
        state.auth_config.effective_issuer(),
        &state.auth_config.sso_spa_origins,
        redirect_uri,
    )
}

/// The decision [`require_deployment_spa_origin`] makes, over the two
/// configuration values it reads and nothing else — so it can be tested without
/// standing up an `AppState`.
fn require_spa_origin(
    issuer: &str,
    extra_origins: &[String],
    redirect_uri: &str,
) -> Result<(), AxiamApiError> {
    let Some(target) = origin_of(redirect_uri) else {
        return Err(validation_err("redirect_uri is not a valid absolute URL"));
    };

    if origin_of(issuer).as_deref() == Some(target.as_str())
        || extra_origins
            .iter()
            .filter_map(|o| origin_of(o))
            .any(|o| o == target)
    {
        return Ok(());
    }

    // Named in the message because the operator, not the caller, is the one who
    // can fix it — and because the alternative is a sign-in that fails at its
    // last hop with nothing to go on.
    Err(validation_err(
        "redirect_uri must be on this deployment's own origin for SAML and Apple \
         sign-in; add the SPA's origin to AXIAM__AUTH__SSO_SPA_ORIGINS if it is \
         served from a different host than the API",
    ))
}

/// SHA-256, lowercase hex. The stored form of a handoff code.
pub(crate) fn hash_handoff_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Mint a handoff code and `303` the browser back into the SPA with it.
///
/// Used by the two **cross-site** returns — a SAML IdP's form POST, and Apple's
/// `response_mode=form_post`. Setting `SameSite=Strict` session cookies on
/// those responses is permitted but useless: the browser will not send them on
/// the navigation that follows, so the user lands in the SPA signed out.
///
/// So no cookies are set here. A single-use, 60-second code goes into the URL,
/// the SPA posts it back **same-origin**, and that response sets the cookies.
///
/// The residual risk is stated rather than hidden: the code is in a URL, and
/// URLs reach history and `Referer`. That is why the TTL is sixty seconds, why
/// it is single-use, why only its hash is stored, why the SPA strips it on
/// arrival, and why the redirect target is confined to an origin this
/// deployment owns — see [`require_deployment_spa_origin`], which is the check
/// that makes the target trustworthy at all.
pub(crate) async fn mint_handoff_and_redirect<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    http_req: &actix_web::HttpRequest,
    tenant_id: Uuid,
    user: &axiam_core::models::user::User,
    spa_redirect_uri: &str,
) -> Result<HttpResponse, AxiamApiError> {
    // Checked again here, not only at login start: this is the single point
    // every handoff passes through, and a state row written before the check
    // existed must not be honoured by a newer binary.
    require_deployment_spa_origin(state, spa_redirect_uri)?;

    // The reactor gate fires here, where the IdP has just verified the
    // credentials and no session exists — the contract `login.post_auth`
    // states. A veto therefore prevents the code from being minted at all,
    // rather than being asked about a session that already exists.
    sso_login_post_auth(state, http_req, tenant_id, user).await?;

    let code = random_base64url();
    let row = SsoHandoffCode {
        code_hash: hash_handoff_code(&code),
        tenant_id,
        user_id: user.id,
        redirect_uri: spa_redirect_uri.to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(SSO_HANDOFF_TTL_SECS),
    };
    state.federation.sso_handoff_code_repo.insert(&row).await?;

    let mut target = url::Url::parse(spa_redirect_uri).map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "stored redirect_uri is not a valid URL".into(),
        })
    })?;
    target
        .query_pairs_mut()
        .append_pair(HANDOFF_QUERY_PARAM, &code);

    info!(
        tenant_id = %tenant_id,
        user_id = %user.id,
        "minted an SSO handoff code for a cross-site federation return"
    );

    Ok(HttpResponse::SeeOther()
        .insert_header((actix_web::http::header::LOCATION, target.to_string()))
        // A URL carrying a credential must not be cached anywhere, and must not
        // travel onward as a referrer.
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .finish())
}

/// Request body for `POST /api/v1/auth/federation/handoff`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SsoHandoffRequest {
    /// The single-use code the SPA received on its callback route.
    pub code: String,
}

/// `POST /api/v1/auth/federation/handoff`
///
/// Exchange a handoff code for session cookies.
///
/// This is the same-origin half of the mechanism described on
/// [`mint_handoff_and_redirect`]: the SPA posts the code it was redirected
/// with, and *this* response is the one that carries `Set-Cookie`, on a
/// same-site request, where `SameSite=Strict` behaves as intended.
///
/// The session is created **here**, from the row's `user_id` and `tenant_id` —
/// no token material was ever stored — so a code that is never redeemed leaves
/// no session behind.
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/handoff",
    tag = "federation-sso",
    request_body = SsoHandoffRequest,
    responses(
        (status = 200, description = "Session issued; cookies set",
         body = SsoLoginSuccessResponse),
        (status = 401, description = "Code not found, expired, or already used"),
    )
)]
pub async fn sso_handoff_public<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<SsoHandoffRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let code = body.into_inner().code;
    if code.trim().is_empty() {
        return Err(validation_err("code must not be empty"));
    }

    let row = state
        .federation
        .sso_handoff_code_repo
        .consume_by_hash(&hash_handoff_code(&code))
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::AuthenticationFailed {
                // One message for "unknown", "expired" and "already used".
                // Distinguishing them would tell a holder of a stolen code
                // whether they were merely too late.
                reason: "handoff code not found or expired".into(),
            })
        })?;

    let user = state
        .user_repo
        .get_by_id(row.tenant_id, row.user_id)
        .await
        .map_err(|_| AxiamError::AuthenticationFailed {
            reason: "user not found after federation login".into(),
        })?;

    // The `login.post_auth` gate already fired when the code was minted — the
    // moment the IdP verified the credentials. Firing it again here would ask
    // a reactor to adjudicate the same sign-in twice.
    super::federation::issue_sso_session(&state, row.tenant_id, &user, row.redirect_uri).await
}

// ---------------------------------------------------------------------------
// OAuth2 variant
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/auth/federation/oauth2/start`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OAuth2StartRequest {
    /// Organization UUID. Alternative to `org_slug`.
    pub org_id: Option<Uuid>,
    /// Organization slug.
    pub org_slug: Option<String>,
    /// Tenant UUID. Alternative to `tenant_slug`.
    pub tenant_id: Option<Uuid>,
    /// Tenant slug. Omitted means the organization's own scope.
    pub tenant_slug: Option<String>,
    /// Which provider to use, from the providers endpoint.
    pub federation_config_id: Uuid,
    /// The SPA callback route. Sent to the provider verbatim, so it must match
    /// what is registered there byte for byte.
    pub redirect_uri: String,
}

/// Response body for `POST /api/v1/auth/federation/oauth2/start`.
///
/// The PKCE verifier is **not** here. It stays server-side in the login state
/// row for the same reason the OIDC `nonce` does: a value the client can supply
/// is a value an attacker can supply.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2StartResponse {
    /// The provider's authorization URL to navigate to.
    pub authorize_url: String,
    /// CSRF state, round-tripped through the provider.
    pub state: String,
    /// Remaining TTL in seconds.
    pub expires_in_secs: i64,
}

/// Request body for `POST /api/v1/auth/federation/oauth2/callback`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct OAuth2CallbackRequest {
    /// The `state` returned by the provider.
    pub state: String,
    /// The authorization code returned by the provider.
    pub code: String,
}

/// `POST /api/v1/auth/federation/oauth2/start`
///
/// Begin a login through a plain-OAuth2 provider (GitHub, Facebook, or any
/// configured `generic_oauth2`).
///
/// PKCE is generated unconditionally here — on this path there is no ID token
/// and therefore no `nonce`, so the verifier is what binds the code to this
/// browser. See `axiam_federation::pkce`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/oauth2/start",
    tag = "federation-sso",
    request_body = OAuth2StartRequest,
    responses(
        (status = 200, description = "Authorize URL returned", body = OAuth2StartResponse),
        (status = 401, description = "Unknown workspace or provider"),
        (status = 400, description = "Validation error"),
    )
)]
pub async fn oauth2_start_public<C: Connection + Clone>(
    app_state: web::Data<AppState<C>>,
    body: web::Json<OAuth2StartRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    if b.redirect_uri.is_empty() {
        return Err(validation_err("redirect_uri must not be empty"));
    }
    validate_redirect_uri(&b.redirect_uri)?;

    let workspace = resolve_workspace(
        &app_state,
        b.org_id,
        b.org_slug.as_deref(),
        b.tenant_id,
        b.tenant_slug.as_deref(),
    )
    .await
    .map_err(workspace_error)?;

    let resolved = resolve_config_for_login(&app_state, workspace, b.federation_config_id).await?;
    if resolved.config.protocol != FederationProtocol::OAuth2 {
        return Err(validation_err(
            "this provider does not use the OAuth2 protocol; \
             start the flow at the endpoint its protocol names",
        ));
    }

    let service = oidc_service(&app_state)?;
    let state = random_base64url();
    let pkce = axiam_federation::pkce::generate();

    let auth_url = service
        .build_oauth2_authorization_url(&resolved.config, &b.redirect_uri, &state, &pkce.challenge)
        .await
        .map_err(AxiamError::from)?;

    app_state
        .federation
        .federation_login_state_repo
        .insert(&FederationLoginState {
            state: state.clone(),
            // No ID token on this path, so no nonce to store.
            nonce: String::new(),
            tenant_id: workspace.tenant_id,
            federation_config_id: b.federation_config_id,
            redirect_uri: b.redirect_uri,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(LOGIN_STATE_TTL_MINUTES),
            request_id: String::new(),
            code_verifier: Some(pkce.verifier),
            // The SPA's redirect_uri went to the provider verbatim.
            idp_redirect_uri: None,
        })
        .await?;

    Ok(HttpResponse::Ok().json(OAuth2StartResponse {
        authorize_url: auth_url.url,
        state,
        expires_in_secs: LOGIN_STATE_TTL_MINUTES * 60,
    }))
}

/// `POST /api/v1/auth/federation/oauth2/callback`
///
/// Complete a plain-OAuth2 login. Called by the SPA, same-origin, so the
/// session cookies are set directly rather than through a handoff code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/oauth2/callback",
    tag = "federation-sso",
    request_body = OAuth2CallbackRequest,
    responses(
        (status = 200, description = "Session issued; cookies set",
         body = SsoLoginSuccessResponse),
        (status = 401, description = "State not found or expired, or the provider \
            returned no verified email"),
    )
)]
pub async fn oauth2_callback_public<C: Connection + Clone>(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<OAuth2CallbackRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    if b.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }
    if b.code.is_empty() {
        return Err(validation_err("code must not be empty"));
    }

    let login_state = consume_login_state(&state, &b.state).await?;
    let workspace = workspace_for_tenant(&state, login_state.tenant_id).await?;
    let resolved =
        resolve_config_for_login(&state, workspace, login_state.federation_config_id).await?;

    let service = oidc_service(&state)?;
    let result = service
        .handle_oauth2_callback(
            &resolved.config,
            login_state.tenant_id,
            &b.code,
            login_state.token_exchange_redirect_uri(),
            login_state.code_verifier.as_deref().unwrap_or_default(),
        )
        .await
        .map_err(AxiamError::from)?;

    sso_login_post_auth(&state, &http_req, login_state.tenant_id, &result.user).await?;
    super::federation::issue_sso_session(
        &state,
        login_state.tenant_id,
        &result.user,
        login_state.redirect_uri,
    )
    .await
}

// ---------------------------------------------------------------------------
// Cross-site form-POST returns
// ---------------------------------------------------------------------------

/// Form body Apple posts to the OIDC form callback.
///
/// `application/x-www-form-urlencoded`, not JSON: this is a browser form
/// submission performed by the IdP, not an API call.
#[derive(Debug, Deserialize)]
pub struct OidcFormCallbackForm {
    /// The `state` AXIAM generated at start.
    pub state: String,
    /// The authorization code, when the user approved.
    pub code: Option<String>,
    /// Apple's one-shot user record, a JSON string. Sent on the **first**
    /// authorization only, and never again.
    pub user: Option<String>,
    /// Present instead of `code` when the user cancelled or the provider
    /// refused.
    pub error: Option<String>,
}

/// `POST /api/v1/auth/federation/oidc/callback/form`
///
/// The `response_mode=form_post` return, which Apple uses whenever `name` or
/// `email` is requested.
///
/// This is a **cross-site** POST performed by the IdP, so it answers `303` with
/// a handoff code rather than setting cookies — see
/// [`mint_handoff_and_redirect`]. It is also where Apple's `user` field is
/// read: the display name arrives there once, in an unsigned form field, and
/// never in the ID token.
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/oidc/callback/form",
    tag = "federation-sso",
    request_body(content = String, description = "application/x-www-form-urlencoded \
        with `state`, `code`, and optionally Apple's `user`",
        content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 303, description = "Redirect to the SPA with a single-use handoff code"),
        (status = 401, description = "State not found or expired"),
    )
)]
pub async fn oidc_form_callback_public<C: Connection + Clone>(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState<C>>,
    form: web::Form<OidcFormCallbackForm>,
) -> Result<HttpResponse, AxiamApiError> {
    let f = form.into_inner();
    if f.state.is_empty() {
        return Err(validation_err("state must not be empty"));
    }

    // The state row is consumed whatever the outcome. A cancelled sign-in must
    // not leave a live state row behind for someone else to complete.
    let login_state = consume_login_state(&state, &f.state).await?;

    if let Some(err) = f.error.as_deref().filter(|e| !e.is_empty()) {
        // The user cancelled, or the provider refused. Route them back to the
        // SPA with the reason rather than rendering an API error page at a URL
        // they did not navigate to.
        warn!(idp_error = %err, "federation form-post callback carried an error");
        return redirect_with_error(&state, &login_state.redirect_uri, err);
    }

    let code = f
        .code
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| validation_err("code must not be empty"))?;

    let workspace = workspace_for_tenant(&state, login_state.tenant_id).await?;
    let resolved =
        resolve_config_for_login(&state, workspace, login_state.federation_config_id).await?;

    let extra = f.user.as_deref().and_then(parse_apple_user_field);

    let service = oidc_service(&state)?;
    let result = service
        .handle_callback_for(
            &resolved.config,
            login_state.tenant_id,
            code,
            login_state.token_exchange_redirect_uri(),
            &login_state.nonce,
            login_state.code_verifier.as_deref(),
            extra.as_ref(),
        )
        .await
        .map_err(AxiamError::from)?;

    mint_handoff_and_redirect(
        &state,
        &http_req,
        login_state.tenant_id,
        &result.user,
        &login_state.redirect_uri,
    )
    .await
}

/// Flatten Apple's one-shot `user` form field into claim-shaped values.
///
/// Apple sends `{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"…"}`
/// as a **JSON string** inside a form field. Returns `None` for anything that
/// does not parse: this is unsigned, provider-supplied text on an unauthenticated
/// endpoint, so it is best-effort by construction. Nothing it contains can
/// override a signed ID-token claim — the merge only fills absent keys.
fn parse_apple_user_field(raw: &str) -> Option<serde_json::Value> {
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let mut out = serde_json::Map::new();

    if let Some(name) = parsed.get("name") {
        let first = name.get("firstName").and_then(|v| v.as_str()).unwrap_or("");
        let last = name.get("lastName").and_then(|v| v.as_str()).unwrap_or("");
        let full = format!("{first} {last}");
        let full = full.trim();
        if !full.is_empty() {
            out.insert(
                "name".to_string(),
                serde_json::Value::String(full.to_string()),
            );
        }
    }
    if let Some(email) = parsed.get("email").and_then(|v| v.as_str())
        && !email.is_empty()
    {
        // Contributed only if the ID token carried none. Apple's ID token does
        // carry `email` when the scope was granted, so in practice the signed
        // value wins — which is the point of merging rather than overwriting.
        out.insert(
            "email".to_string(),
            serde_json::Value::String(email.to_string()),
        );
    }

    (!out.is_empty()).then_some(serde_json::Value::Object(out))
}

/// Form body a SAML IdP posts to the ACS.
#[cfg(feature = "saml")]
#[derive(Debug, Deserialize)]
pub struct SamlAcsForm {
    /// Base64-encoded `<samlp:Response>`, per the HTTP-POST binding.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// The `RelayState` AXIAM set at login start.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// `POST /api/v1/auth/federation/saml/acs/form`
///
/// The Assertion Consumer Service a real SAML IdP posts to.
///
/// The JSON sibling (`/saml/acs`) is kept and unchanged — it is published SDK
/// surface and it is how a non-browser client drives the flow — but no IdP can
/// call it: the HTTP-POST binding is `application/x-www-form-urlencoded` with
/// `SAMLResponse` and `RelayState`. A deployment points its IdP at this path.
///
/// Answers `303` with a handoff code, because the IdP's POST is cross-site and
/// `SameSite=Strict` cookies set on it would not be sent afterwards.
#[cfg(feature = "saml")]
#[utoipa::path(
    post,
    path = "/api/v1/auth/federation/saml/acs/form",
    tag = "federation-sso",
    request_body(content = String, description = "application/x-www-form-urlencoded \
        with `SAMLResponse` and `RelayState`",
        content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 303, description = "Redirect to the SPA with a single-use handoff code"),
        (status = 401, description = "RelayState not found or expired"),
    )
)]
pub async fn saml_acs_form_public<C: Connection + Clone>(
    http_req: actix_web::HttpRequest,
    state: web::Data<AppState<C>>,
    form: web::Form<SamlAcsForm>,
) -> Result<HttpResponse, AxiamApiError> {
    let f = form.into_inner();
    let relay_state = f
        .relay_state
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| validation_err("RelayState must not be empty"))?;
    if f.saml_response.is_empty() {
        return Err(validation_err("SAMLResponse must not be empty"));
    }

    let login_state = consume_login_state(&state, relay_state).await?;

    // The config may be inherited from the organization, in which case it is
    // not reachable by a `get_by_id` scoped to `login_state.tenant_id`. Resolve
    // it the same way the start endpoint did, and hand the resolved config to
    // the service: the assertion-replay row is recorded under the config's
    // tenant and the user is provisioned under the requesting one (T-169).
    let workspace = workspace_for_tenant(&state, login_state.tenant_id).await?;
    let resolved =
        resolve_config_for_login(&state, workspace, login_state.federation_config_id).await?;

    let callback_result = state
        .federation
        .saml_federation_service
        .handle_saml_response_for(
            &resolved.config,
            login_state.tenant_id,
            &f.saml_response,
            Some(relay_state),
            Some(login_state.request_id.as_str()),
            // Same SEC-005 residual as the JSON ACS: no ACS URL is stored, so
            // the bearer SubjectConfirmationData's @Recipient *value* is not
            // compared. Its presence, @NotOnOrAfter and @InResponseTo still are.
            None,
            false,
        )
        .await
        .map_err(AxiamError::from)?;

    mint_handoff_and_redirect(
        &state,
        &http_req,
        login_state.tenant_id,
        &callback_result.user,
        &login_state.redirect_uri,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The hoisted OIDC/OAuth2 federation service, or the one error its absence
/// produces.
pub(crate) fn oidc_service<C: Connection + Clone>(
    state: &AppState<C>,
) -> Result<&crate::state::OidcFederationServiceT<C>, AxiamApiError> {
    state
        .federation
        .oidc_federation_service
        .as_ref()
        .ok_or_else(|| {
            AxiamApiError(AxiamError::Validation {
                message: "federation encryption key not configured".into(),
            })
        })
}

/// Atomically consume a login state row, mapping both "missing" and "expired"
/// onto the same `401`.
pub(crate) async fn consume_login_state<C: Connection + Clone>(
    state: &AppState<C>,
    value: &str,
) -> Result<FederationLoginState, AxiamApiError> {
    state
        .federation
        .federation_login_state_repo
        .consume_by_state(value)
        .await?
        .ok_or_else(|| {
            AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "state not found or expired".into(),
            })
        })
}

/// Recover the `(organization, tenant)` pair for a stored login state row.
///
/// The state row records the tenant the login is for; inheritance resolution
/// needs the organization it belongs to as well, and looking it up here keeps
/// the row's shape unchanged.
pub(crate) async fn workspace_for_tenant<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Result<Workspace, AxiamApiError> {
    let tenant = state.tenant_repo.get_by_id(tenant_id).await.map_err(|_| {
        AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid federation request".into(),
        })
    })?;
    Ok(Workspace {
        organization_id: tenant.organization_id,
        tenant_id,
    })
}

/// Map a workspace-resolution failure onto the answer a *start* endpoint gives.
///
/// A missing organization identifier is a malformed request and says so; an
/// unresolvable one is a uniform `401`, so the endpoint cannot be used to
/// enumerate organizations or tenants (D-22).
pub(crate) fn workspace_error(e: WorkspaceError) -> AxiamApiError {
    match e {
        WorkspaceError::Missing => AxiamApiError(AxiamError::Validation {
            message: "must provide org_id or org_slug".into(),
        }),
        WorkspaceError::Unresolved => AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid federation request".into(),
        }),
    }
}

/// Send the browser back to the SPA with an error code in the query string.
///
/// Used only on the form-POST paths, where the IdP navigated the browser to an
/// AXIAM endpoint: rendering a JSON error there leaves the person staring at a
/// payload on a URL they never chose. The SPA's callback route has real error
/// UI for each case.
fn redirect_with_error<C: Connection + Clone>(
    state: &AppState<C>,
    redirect_uri: &str,
    error: &str,
) -> Result<HttpResponse, AxiamApiError> {
    // Same confinement as the success path: this is still AXIAM navigating a
    // browser to a caller-supplied URL on an unauthenticated endpoint, and an
    // open redirect on the API origin is worth closing even when it carries no
    // credential.
    require_deployment_spa_origin(state, redirect_uri)?;

    let mut target = url::Url::parse(redirect_uri).map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "stored redirect_uri is not a valid URL".into(),
        })
    })?;
    // Bounded and sanitised: the value comes from the IdP, and it is going into
    // a URL the browser will follow. Only the OAuth error-code shape is passed
    // through; anything else becomes a generic code the SPA can still render.
    let safe = if error.len() <= 64
        && error
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        error
    } else {
        "provider_error"
    };
    target.query_pairs_mut().append_pair("error", safe);
    Ok(HttpResponse::SeeOther()
        .insert_header((actix_web::http::header::LOCATION, target.to_string()))
        .insert_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .finish())
}

/// The absolute URL an IdP that uses `response_mode=form_post` must be pointed
/// at.
///
/// Derived from `AuthConfig::effective_issuer()` rather than a new
/// configuration key: that value already has to be the deployment's public
/// origin for OIDC discovery to be correct, and it is already validated as a
/// URL at startup. A deployment that has it wrong has a broken OIDC provider
/// already — this adds a second thing that notices, not a new way to be wrong.
pub(crate) fn server_form_callback_url<C: Connection + Clone>(
    state: &AppState<C>,
    path: &str,
) -> Result<String, AxiamApiError> {
    let issuer = state.auth_config.effective_issuer().trim_end_matches('/');
    let url = format!("{issuer}{path}");
    validate_redirect_uri(&url).map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: format!(
                "AXIAM__AUTH__OAUTH2_ISSUER_URL must be this deployment's public HTTPS \
                 origin for form-post providers; '{issuer}' does not yield a usable \
                 callback URL"
            ),
        })
    })?;
    Ok(url)
}

/// Which callback URL to register with the IdP for a config.
///
/// Apple posts its response cross-site rather than redirecting the browser to
/// it, so the URI it is given must be an AXIAM **server** endpoint. Everyone
/// else gets the SPA route the caller asked for.
pub(crate) fn idp_redirect_uri_for<C: Connection + Clone>(
    state: &AppState<C>,
    config: &FederationConfig,
    spa_redirect_uri: &str,
) -> Result<(String, Option<String>), AxiamApiError> {
    if config.provider_kind == axiam_core::models::federation::ProviderKind::Apple {
        // Apple posts its response to AXIAM rather than redirecting the browser
        // to `spa_redirect_uri`, so Apple never validates that URI and AXIAM
        // must. Refusing at start, rather than only at the handoff mint, is the
        // difference between a 400 the caller can read and a sign-in that dies
        // at its last hop.
        require_deployment_spa_origin(state, spa_redirect_uri)?;
        let server = server_form_callback_url(state, OIDC_FORM_CALLBACK_PATH)?;
        // Returned as `Some` so the state row records it: the token exchange
        // must echo the exact string the authorize request carried, and
        // reconstructing it later is how the two drift apart.
        return Ok((server.clone(), Some(server)));
    }
    Ok((spa_redirect_uri.to_string(), None))
}

/// The ACS URL a SAML IdP should be pointed at for this deployment.
#[cfg(feature = "saml")]
pub(crate) fn saml_acs_url<C: Connection + Clone>(
    state: &AppState<C>,
) -> Result<String, AxiamApiError> {
    server_form_callback_url(state, SAML_FORM_ACS_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handoff_code_is_stored_only_as_a_hash() {
        let code = "a-code-nobody-should-find-in-the-database";
        let hashed = hash_handoff_code(code);
        assert_ne!(hashed, code);
        assert_eq!(hashed.len(), 64, "SHA-256, lowercase hex");
        assert!(hashed.bytes().all(|b| b.is_ascii_hexdigit()));
        // Deterministic, or redemption could never find the row.
        assert_eq!(hashed, hash_handoff_code(code));
        assert_ne!(hashed, hash_handoff_code("a-different-code"));
    }

    #[test]
    fn apples_one_shot_user_field_becomes_a_name_claim() {
        let raw = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}"#;
        let got = parse_apple_user_field(raw).unwrap();
        assert_eq!(got["name"], "Ada Lovelace");
        assert_eq!(got["email"], "ada@example.com");
    }

    #[test]
    fn a_partial_apple_user_field_contributes_what_it_has() {
        let got = parse_apple_user_field(r#"{"name":{"firstName":"Ada"}}"#).unwrap();
        assert_eq!(got["name"], "Ada");
        assert!(got.get("email").is_none());
    }

    /// Unsigned, provider-supplied text on an unauthenticated endpoint: it must
    /// never be able to fail the request, only to contribute nothing.
    #[test]
    fn a_malformed_apple_user_field_contributes_nothing() {
        for raw in ["", "not json", "[]", "{}", r#"{"name":{}}"#, "null"] {
            assert!(parse_apple_user_field(raw).is_none(), "{raw}");
        }
    }

    const ISSUER: &str = "https://axiam.example.com";

    /// The whole point: a handoff code is a bearer credential for a session,
    /// and the SAML and Apple flows are the two where no identity provider ever
    /// sees — or validates — the SPA `redirect_uri`. If an attacker could name
    /// the redirect target on the unauthenticated start endpoint, they could
    /// lure a victim through the victim's own real IdP and read a working
    /// session credential out of their own access log.
    #[test]
    fn a_foreign_origin_may_not_receive_a_handoff_code() {
        for uri in [
            "https://attacker.example/catch",
            "https://axiam.example.com.attacker.example/catch",
            "https://evil.example.com",
            // A userinfo prefix is the classic way to make a URL *look* like it
            // is on the right host. `Url::origin` is not fooled; a string
            // `starts_with` would have been.
            "https://axiam.example.com@attacker.example/catch",
            // Same host, different scheme and port: still a different origin,
            // and http would put the code on the wire in clear.
            "http://axiam.example.com/cb",
            "https://axiam.example.com:8443/cb",
        ] {
            assert!(
                require_spa_origin(ISSUER, &[], uri).is_err(),
                "must refuse {uri}"
            );
        }
    }

    #[test]
    fn the_deployments_own_origin_is_allowed_without_configuration() {
        // The default: no `sso_spa_origins` at all, because the endpoint the
        // IdP posts to is built from this same issuer, so a same-origin SPA —
        // the only shape in which SameSite=Strict cookies work — needs no
        // entry.
        for uri in [
            "https://axiam.example.com/auth/sso/callback",
            "https://axiam.example.com",
            // The default port, spelled out, is the same origin.
            "https://axiam.example.com:443/auth/sso/callback",
        ] {
            assert!(require_spa_origin(ISSUER, &[], uri).is_ok(), "{uri}");
        }
    }

    #[test]
    fn an_operator_may_name_a_separately_hosted_spa() {
        let extra = vec!["https://app.example.com".to_string()];
        assert!(
            require_spa_origin(ISSUER, &extra, "https://app.example.com/auth/sso/callback").is_ok()
        );
        // Configuring one origin does not open the next one along.
        assert!(require_spa_origin(ISSUER, &extra, "https://other.example.com/cb").is_err());
    }

    /// A configured value is compared as an origin, so a trailing slash or a
    /// path on it neither breaks the match nor widens it.
    #[test]
    fn a_configured_origin_is_compared_as_an_origin() {
        let extra = vec!["https://app.example.com/ignored/path/".to_string()];
        assert!(
            require_spa_origin(ISSUER, &extra, "https://app.example.com/auth/sso/callback").is_ok()
        );
    }

    /// An issuer that is a bare identifier rather than a URL has no origin, so
    /// nothing matches it. That is not a new deployment requirement: the ACS
    /// and form-callback URLs are built from the same value, and
    /// `server_form_callback_url` already refuses when it does not yield a
    /// usable HTTPS URL.
    #[test]
    fn an_issuer_that_is_not_a_url_allows_nothing() {
        assert!(require_spa_origin("axiam-test", &[], "https://anything.example/cb").is_err());
    }

    #[test]
    fn a_redirect_uri_that_is_not_a_url_is_refused() {
        for uri in [
            "",
            "not a url at all",
            "/relative/only",
            "javascript:alert(1)",
        ] {
            assert!(require_spa_origin(ISSUER, &[], uri).is_err(), "{uri}");
        }
    }
}
