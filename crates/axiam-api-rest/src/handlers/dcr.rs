//! RFC 7591 dynamic client registration — the two endpoints (T21.4).
//!
//! * `POST /oauth2/register` — **unauthenticated**, in `PUBLIC_PATHS`, and the
//!   first write endpoint in AXIAM that anybody can reach without a
//!   credential.
//! * `POST /api/v1/oauth2-clients/registration-tokens` — the admin endpoint
//!   that mints the single-use initial access token the *protected*
//!   registration profile (RFC 7591 §1.2) requires.
//!
//! The validation rules live in `axiam_oauth2::dcr`, which is a pure function
//! of the request and the tenant's policy. What lives here is everything that
//! needs state: the policy read, the quota, the single-use token, the audit
//! event and the response shape.
//!
//! # The order the unauthenticated endpoint does things in
//!
//! Each step is chosen so that the cheapest refusal comes first and so that
//! nothing a caller can see depends on state they should not be able to
//! probe:
//!
//! 1. **Resolve the tenant's policy.** A tenant that has not enabled
//!    registration is refused here, before any metadata is parsed, so the
//!    endpoint cannot be used to discover what the metadata rules are.
//! 2. **Apply the mode gate.** `initial_access_token` without a bearer is
//!    refused with the same body shape as `disabled`, so the two modes are
//!    indistinguishable to a caller holding nothing.
//! 3. **Validate the metadata** (`axiam_oauth2::dcr::validate`) — pure, no
//!    reads.
//! 4. **Check the quota**, which is one indexed count.
//! 5. **Spend the initial access token**, atomically, if the mode needs one.
//!    Last of the checks, so a token is not burned by a request that was
//!    going to be refused anyway.
//! 6. **Write the client**, then audit.
//!
//! The per-IP rate limit is applied by the route wrap in `server.rs`, before
//! any of this runs.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::oauth2_client::ManagedBy;
use axiam_core::models::oauth2_registration_token::{
    CreateOAuth2RegistrationToken, DEFAULT_REGISTRATION_TOKEN_TTL_HOURS,
    MAX_REGISTRATION_TOKEN_TTL_HOURS, OAuth2RegistrationToken, REGISTRATION_TOKEN_PREFIX,
};
use axiam_core::models::settings::{DynamicRegistrationMode, OidcPolicy};
use axiam_core::repository::{
    AuditLogRepository, OAuth2ClientRepository, OAuth2RegistrationTokenRepository,
    SettingsRepository, TenantRepository,
};
use axiam_oauth2::dcr::{self, DcrError, RegistrationRequest, RegistrationResponse};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::oauth2::TenantQuery;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// The unauthenticated registration endpoint
// ---------------------------------------------------------------------------

/// An RFC 7591 §3.2.2 error body.
///
/// The same two members the OAuth2 error responses elsewhere in this crate
/// carry, declared separately because RFC 7591 §3.2.2 defines its own code
/// vocabulary (`invalid_redirect_uri`, `invalid_client_metadata`,
/// `invalid_software_statement`) that has nothing to do with RFC 6749 §5.2's.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DcrErrorResponse {
    /// RFC 7591 §3.2.2 error code.
    pub error: String,
    /// Human-readable explanation.
    pub error_description: String,
}

fn error_response(err: &DcrError) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(err.http_status())
        .unwrap_or(actix_web::http::StatusCode::BAD_REQUEST);
    HttpResponse::build(status)
        // RFC 7591 §3.2 asks for the same no-store posture the token endpoint
        // has: a registration response carries a client secret, and an error
        // response carries the fact that a tenant runs registration at all.
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"))
        .json(DcrErrorResponse {
            error: err.error_code().to_owned(),
            error_description: err.description(),
        })
}

/// Read the tenant's effective OIDC policy, or refuse.
///
/// An unknown tenant, an unreadable settings row and a tenant whose
/// organization cannot be resolved all answer
/// [`DcrError::RegistrationDisabled`] — the same answer a tenant that simply
/// turned registration off gets. That is deliberate on two counts. It fails
/// closed: a settings read that failed must never open an unauthenticated
/// write endpoint. And it refuses to be an oracle: `404` for an unknown tenant
/// would make this endpoint a tenant-enumeration probe, which is exactly the
/// argument the discovery handler already makes for answering an unknown
/// tenant with the deployment-wide document.
async fn effective_policy<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Result<OidcPolicy, DcrError> {
    let tenant = state
        .tenant_repo
        .get_by_id(tenant_id)
        .await
        .map_err(|_| DcrError::RegistrationDisabled)?;
    let settings = SettingsRepository::get_effective_settings(
        &state.settings_repo,
        tenant.organization_id,
        tenant_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not read a tenant's effective settings while answering a registration \
             request; treating dynamic registration as disabled"
        );
        DcrError::RegistrationDisabled
    })?;
    Ok(settings.oidc)
}

/// The bearer an `initial_access_token` registration presents, if any.
///
/// Only the `Bearer` scheme, and only a non-empty value. A malformed header is
/// read as *absent* rather than as an error, so every way of failing to
/// present a usable token produces the one refusal
/// [`DcrError::InitialAccessTokenRequired`] describes.
fn bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// `POST /oauth2/register` — RFC 7591 §3.1 dynamic client registration.
#[utoipa::path(
    post,
    path = "/oauth2/register",
    tag = "oauth2",
    params(TenantQuery),
    request_body = RegistrationRequest,
    responses(
        (status = 201, description = "Client registered (secret, if any, shown once)",
         body = RegistrationResponse),
        (status = 400, description = "The metadata is not one this server will register",
         body = DcrErrorResponse),
        (status = 403, description = "Dynamic registration is not enabled for this tenant, \
                                      the initial access token was missing or unusable, or \
                                      the tenant's client limit is reached",
         body = DcrErrorResponse),
    ),
)]
pub async fn register<C: Connection + Clone>(
    http_req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    body: web::Json<RegistrationRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let req = body.into_inner();

    match register_inner(&http_req, tenant_id, req, &state).await {
        Ok(response) => HttpResponse::Created()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(response),
        Err(err) => {
            audit_registration(&state, &http_req, tenant_id, None, Some(&err)).await;
            error_response(&err)
        }
    }
}

/// See [`register`]. Split so that every refusal path is one `?` and the
/// audit event is written in one place.
async fn register_inner<C: Connection + Clone>(
    http_req: &HttpRequest,
    tenant_id: Uuid,
    req: RegistrationRequest,
    state: &AppState<C>,
) -> Result<RegistrationResponse, DcrError> {
    // 1 & 2 — policy, then the mode gate, before any metadata is looked at.
    let policy = effective_policy(state, tenant_id).await?;
    let bearer = bearer_token(http_req);
    dcr::gate(policy.dynamic_registration, bearer.is_some())?;

    // 3 — the pure validation, plus the redirect-URI rules the admin API
    // already applies. `validate_redirect_uris` is reused rather than
    // reimplemented (the plan's item 3) so that "what is a usable redirect
    // URI" has one answer in this server; its message is carried into the RFC
    // 7591 error shape rather than answered as the admin API's `400`.
    crate::handlers::oauth2_clients::validate_redirect_uris(&req.redirect_uris)
        .map_err(|e| DcrError::InvalidRedirectUri(e.0.to_string()))?;
    let validated = dcr::validate(tenant_id, &req, &policy)?;

    // 4 — the per-tenant ceiling. After validation so that a malformed
    // request is told what is wrong with it rather than being turned away at
    // a quota it was never going to reach.
    let existing = state
        .oauth2_client_repo
        .count_by_managed_by(tenant_id, ManagedBy::Dcr)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %tenant_id, "could not count self-registered clients");
            // Fail closed: an unreadable count must not be read as room.
            DcrError::ClientQuotaExhausted {
                limit: policy.dcr_max_clients,
            }
        })?;
    if existing >= u64::from(policy.dcr_max_clients) {
        return Err(DcrError::ClientQuotaExhausted {
            limit: policy.dcr_max_clients,
        });
    }

    // 5 — spend the initial access token, if the mode needs one. Last,
    // because a single-use credential must not be burned by a request that
    // was going to be refused for some other reason.
    //
    // Spent **before** the client is written, and that order is the
    // single-use guarantee: a two-phase "create, then spend" would leave a
    // window in which two concurrent registrations on one handle both create
    // a client. The cost is that a handle is burned if the write then fails,
    // which is recoverable by minting another; the alternative is not
    // recoverable at all.
    //
    // The row records that it was spent and when, not which client it
    // produced — the `client_id` does not exist yet. See the repository trait
    // for why a placeholder is not written instead.
    if policy.dynamic_registration == DynamicRegistrationMode::InitialAccessToken {
        let presented = bearer.ok_or(DcrError::InitialAccessTokenRequired)?;
        let hash = axiam_auth::token::hash_refresh_token(&presented);
        let spent = state
            .oauth2_registration_token_repo
            .consume_by_token_hash(tenant_id, &hash, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, %tenant_id, "could not spend an initial access token");
                DcrError::InitialAccessTokenRequired
            })?;
        if spent.is_none() {
            return Err(DcrError::InitialAccessTokenRequired);
        }
    }

    // 6 — write, then audit.
    //
    // `fapi::validate_registration` runs here for the same reason the admin
    // handler runs it: it is where a registration that could never be served
    // is refused. For a `dcr` row it also enforces I5 — a FAPI profile on an
    // externally registered client — which `dcr::validate` has already made
    // unreachable by forcing `standard`. Two gates, as everywhere else in this
    // file, because the forcing is one line and the invariant should not
    // depend on it staying written.
    axiam_oauth2::fapi::validate_registration(&validated.create)
        .map_err(|e| DcrError::InvalidClientMetadata(e.to_string()))?;

    let (client, raw_secret) = state
        .oauth2_client_repo
        .create(validated.create)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %tenant_id, "could not write a registered client");
            DcrError::InvalidClientMetadata(
                "the registration could not be stored; try again".into(),
            )
        })?;

    audit_registration(state, http_req, tenant_id, Some(&client.client_id), None).await;

    let is_public = client.token_endpoint_auth_method.is_public();
    Ok(RegistrationResponse {
        client_id: client.client_id,
        // A public client has no secret to show — not one nobody is told
        // about: none was minted. Omitted rather than `""`, which an MCP
        // client would read as a secret that happens to be empty.
        client_secret: (!is_public).then_some(raw_secret),
        client_id_issued_at: client.created_at.timestamp(),
        // RFC 7591 §3.2.1: REQUIRED if a secret was issued, and `0` means it
        // does not expire. Absent when no secret was issued, because there is
        // nothing for the member to describe.
        client_secret_expires_at: (!is_public).then_some(0),
        client_name: client.name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        response_types: vec!["code".to_owned()],
        token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_owned(),
        scope: client.scopes.join(" "),
    })
}

/// Record every registration attempt, successful or not.
///
/// Every one, and this is the plan's item 5: the endpoint is unauthenticated,
/// so the audit log is the only record that a stranger reached it. The
/// metadata deliberately carries no client-supplied string beyond the
/// `client_id` AXIAM itself minted — a refused registration's `client_name`
/// and `redirect_uris` are attacker-controlled, and an audit viewer is a place
/// where attacker-controlled strings are read by people.
async fn audit_registration<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    tenant_id: Uuid,
    client_id: Option<&str>,
    refusal: Option<&DcrError>,
) {
    let (action, outcome) = match refusal {
        None => ("oauth2.client_registered", AuditOutcome::Success),
        Some(_) => ("oauth2.client_registration_refused", AuditOutcome::Failure),
    };
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.into(),
            // The audit row's `resource_id` is a `Uuid` and a `client_id` is
            // not one, so the identifier travels in the metadata below. The
            // row is about an act, not about a record that may not exist: a
            // refused registration created nothing to point at.
            resource_id: None,
            outcome,
            ip_address: crate::extractors::client_info::client_ip(http_req),
            metadata: Some(serde_json::json!({
                "managed_by": ManagedBy::Dcr.as_str(),
                "client_id": client_id,
                "error": refusal.map(DcrError::error_code),
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not record a dynamic client registration; the request is unaffected"
        );
    }
}

// ---------------------------------------------------------------------------
// The admin endpoint that mints initial access tokens
// ---------------------------------------------------------------------------

/// Request body for [`create_registration_token`].
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateRegistrationTokenRequest {
    /// Operator-facing label, e.g. `"mcp-inspector-demo"`, so a tenant with
    /// several outstanding tokens can tell them apart.
    pub name: String,
    /// Lifetime in hours. Defaults to 24 and is refused above 168 (a week) —
    /// see `axiam_core::models::oauth2_registration_token`.
    #[serde(default)]
    pub expires_in_hours: Option<u32>,
}

/// Metadata only. The handle exists in plaintext exactly once, in
/// [`CreateRegistrationTokenResponse`].
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegistrationTokenResponse {
    /// Row identity.
    pub id: Uuid,
    /// The tenant a registration on this token lands in.
    pub tenant_id: Uuid,
    /// The operator-facing label.
    pub name: String,
    /// The administrator who minted it.
    pub created_by: Uuid,
    /// When it stops being usable.
    pub expires_at: DateTime<Utc>,
    /// When it was spent, if it was.
    pub used_at: Option<DateTime<Utc>>,
    /// Reserved; always absent in this build. See
    /// `axiam_core::models::oauth2_registration_token::OAuth2RegistrationToken::used_by_client_id`
    /// — the registration a token produced is recorded in the audit log, not
    /// here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_by_client_id: Option<String>,
    /// Row creation time.
    pub created_at: DateTime<Utc>,
}

impl From<OAuth2RegistrationToken> for RegistrationTokenResponse {
    fn from(t: OAuth2RegistrationToken) -> Self {
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            name: t.name,
            created_by: t.created_by,
            expires_at: t.expires_at,
            used_at: t.used_at,
            used_by_client_id: t.used_by_client_id,
            created_at: t.created_at,
        }
    }
}

/// The one response that carries the handle.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateRegistrationTokenResponse {
    /// The token's metadata.
    pub token: RegistrationTokenResponse,
    /// The plaintext handle, shown exactly once. Presented by the registering
    /// client as `Authorization: Bearer <this>`.
    pub initial_access_token: String,
}

/// `POST /api/v1/oauth2-clients/registration-tokens`
///
/// Mints the single-use credential RFC 7591 §1.2's protected registration
/// profile requires. Gated on `oauth2_clients:create` rather than a permission
/// of its own: a token minted here authorises exactly one registration, and a
/// registration is strictly less than what that permission already confers
/// (an administrator holding it can create any client directly, with any
/// scopes, any audiences and any profile). A separate permission would suggest
/// this is the more dangerous of the two, which it is not.
#[utoipa::path(
    post,
    path = "/api/v1/oauth2-clients/registration-tokens",
    tag = "oauth2-clients",
    request_body = CreateRegistrationTokenRequest,
    responses(
        (status = 201, description = "Token minted; the handle is returned once",
         body = CreateRegistrationTokenResponse),
        (status = 400, description = "Invalid lifetime or name, or this tenant is not in \
                                      initial_access_token mode"),
    ),
    security(("bearer" = []))
)]
pub async fn create_registration_token<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateRegistrationTokenRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let input = body.into_inner();
    let name = input.name.trim().to_owned();
    if name.is_empty() {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "name must not be empty".into(),
        }));
    }
    let hours = input
        .expires_in_hours
        .unwrap_or(DEFAULT_REGISTRATION_TOKEN_TTL_HOURS);
    if hours == 0 || hours > MAX_REGISTRATION_TOKEN_TTL_HOURS {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "expires_in_hours must be between 1 and {MAX_REGISTRATION_TOKEN_TTL_HOURS}"
            ),
        }));
    }

    // Refuse to mint a credential for a tenant that will not honour it.
    //
    // The same argument `reject_unimplemented_dpop_nonce` makes next door: an
    // operator who mints a token, hands it to somebody and watches them be
    // refused has been told a lie by the API. `anonymous` is refused too,
    // because there the token buys nothing — registration is already open, and
    // a credential that authorises what was already permitted is one an
    // operator will believe is doing something.
    let tenant = state.tenant_repo.get_by_id(user.tenant_id).await?;
    let settings = SettingsRepository::get_effective_settings(
        &state.settings_repo,
        tenant.organization_id,
        user.tenant_id,
    )
    .await?;
    if settings.oidc.dynamic_registration != DynamicRegistrationMode::InitialAccessToken {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "this tenant's dynamic_registration is {}, so an initial access token would \
                 authorise nothing: set it to initial_access_token first",
                settings.oidc.dynamic_registration
            ),
        }));
    }

    let raw = format!(
        "{REGISTRATION_TOKEN_PREFIX}{}",
        axiam_auth::token::generate_refresh_token()
    );
    let token_hash = axiam_auth::token::hash_refresh_token(&raw);

    let created = state
        .oauth2_registration_token_repo
        .create(CreateOAuth2RegistrationToken {
            tenant_id: user.tenant_id,
            name,
            token_hash,
            created_by: user.user_id,
            expires_at: Utc::now() + Duration::hours(i64::from(hours)),
        })
        .await?;

    tracing::info!(
        target: "axiam::audit",
        event = "oauth2.registration_token_created",
        tenant_id = %user.tenant_id,
        token_id = %created.id,
        created_by = %user.user_id,
        expires_at = %created.expires_at,
        "RFC 7591 initial access token minted"
    );

    Ok(
        HttpResponse::Created().json(CreateRegistrationTokenResponse {
            token: RegistrationTokenResponse::from(created),
            initial_access_token: raw,
        }),
    )
}

/// `GET /api/v1/oauth2-clients/registration-tokens`
///
/// Metadata only — the handle is not stored, so it cannot be listed.
#[utoipa::path(
    get,
    path = "/api/v1/oauth2-clients/registration-tokens",
    tag = "oauth2-clients",
    responses(
        (status = 200, description = "Outstanding and spent initial access tokens",
         body = Vec<RegistrationTokenResponse>),
    ),
    security(("bearer" = []))
)]
pub async fn list_registration_tokens<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("oauth2_clients:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tokens = state
        .oauth2_registration_token_repo
        .list_for_tenant(user.tenant_id)
        .await?;
    Ok(HttpResponse::Ok().json(
        tokens
            .into_iter()
            .map(RegistrationTokenResponse::from)
            .collect::<Vec<_>>(),
    ))
}
