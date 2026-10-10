//! RFC 7591 dynamic client registration — the two endpoints (T21.4).
//!
//! * `POST /oauth2/register` — **unauthenticated**, in `PUBLIC_PATHS`, and the
//!   first write endpoint in AXIAM that anybody can reach without a
//!   credential.
//! * `GET` / `PUT` / `DELETE /oauth2/register/{client_id}` — RFC 7592's client
//!   configuration endpoint (T23.4.1), authenticated by the registration
//!   access token `POST /oauth2/register` returns and by nothing else.
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
use axiam_core::models::oauth2_client::{DcrRegistrationReplacement, ManagedBy};
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
///
/// The scheme is matched case-insensitively (RFC 9110 §11.1, which RFC 6750
/// §2.1 inherits): `bearer` read as *no token* would answer a good credential
/// with the bare challenge, which a client follows by discarding it (F4
/// P23W1-02). Shared by `POST /oauth2/register`'s initial access token and the
/// RFC 7592 registration access token.
fn bearer_token(req: &HttpRequest) -> Option<String> {
    let value = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token.trim())
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
    //
    // G-7: a registration naming no browser-driven grant (a CIBA-only client)
    // may name no redirect URI, and is then not held to the "must not be
    // empty" rule; any URI it does name is still checked.
    let browser_driven = req
        .grant_types
        .as_ref()
        .is_none_or(|g| g.iter().any(|x| x.trim() == "authorization_code"));
    if browser_driven || !req.redirect_uris.is_empty() {
        crate::handlers::oauth2_clients::validate_redirect_uris(&req.redirect_uris)
            .map_err(|e| DcrError::InvalidRedirectUri(e.0.to_string()))?;
    }
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

    // T23.4.1 / RFC 7592 — the management token, minted here and written in
    // the same statement as the client, so the client never exists without
    // the credential its registrant is about to be given. Only the digest is
    // stored; the plaintext leaves in this response and nowhere else — it is
    // in no log line and no audit row.
    let (registration_access_token, token_digest) = dcr::mint_registration_access_token();
    let (client, raw_secret) = state
        .oauth2_client_repo
        .create_with_registration_access_token(validated.create, &token_digest)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %tenant_id, "could not write a registered client");
            DcrError::InvalidClientMetadata(
                "the registration could not be stored; try again".into(),
            )
        })?;

    audit_registration(state, http_req, tenant_id, Some(&client.client_id), None).await;

    let uri = configuration_uri(http_req, state, tenant_id, &client.client_id);
    Ok(dcr::client_information(
        &client,
        uri,
        Some(raw_secret),
        Some(registration_access_token),
    ))
}

/// RFC 7592 §3 `registration_client_uri` for a client, under the issuer this
/// request arrived under.
///
/// On a T21.6 tenant path the issuer is `{root}/t/{tenant_id}` and the URI
/// needs nothing else; at the root the tenant travels as `?tenant_id=`, the
/// way the discovery document's `registration_endpoint` carries it. Either
/// way the URI is the one a client following the same discovery document
/// would have built, which is what makes it usable without being told
/// anything out of band.
fn configuration_uri<C: Connection + Clone>(
    http_req: &HttpRequest,
    state: &AppState<C>,
    tenant_id: Uuid,
    client_id: &str,
) -> String {
    match crate::middleware::tenant_path::binding_of(http_req) {
        Some(binding) => dcr::registration_client_uri(binding.issuer(), client_id, None),
        None => dcr::registration_client_uri(
            state.auth_config.effective_issuer(),
            client_id,
            Some(tenant_id),
        ),
    }
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
// RFC 7592 — the client configuration endpoint (T23.4.1)
// ---------------------------------------------------------------------------
//
// `GET`, `PUT` and `DELETE /oauth2/register/{client_id}`, authenticated by the
// registration access token `register` minted and by nothing else.
//
// # Who can authenticate here
//
// Exactly one credential: `Authorization: Bearer <registration_access_token>`,
// whose SHA-256 must equal the digest stored on the `managed_by: dcr` row the
// path's `client_id` names **in the tenant this request resolved** — the
// `?tenant_id=` at the root, the path segment under `/t/{tenant_id}`. The
// comparison is the repository's: one `WHERE` holding the tenant, the
// `client_id`, `managed_by = 'dcr'` and the digest, located by the
// `(tenant_id, client_id)` unique index — the "digest looked up by index"
// pattern refresh tokens and initial access tokens use, so the plaintext is
// never compared at all and there is no early-exit string comparison on
// anything an attacker chose. A user's access token, a service account's, a
// client secret presented as a bearer and another client's management token
// all hash to something that row does not hold.
//
// The route is public to `AuthzMiddleware` (`/oauth2/register/*` in
// `PUBLIC_PATHS`) so that every refusal is this module's: an RFC 6750 `401`
// with a `WWW-Authenticate: Bearer` challenge, not the middleware's generic
// body.
//
// # One answer for four failures
//
// RFC 7592 §2.1: when the client does not exist the server answers `401` and
// "MUST NOT" reveal whether it does. An unknown `client_id`, a wrong token,
// another tenant's client and a client that was never issued a token (an
// administrator's client, a CIMD shadow row, a `dcr` row older than schema
// v69) are therefore the same `401 invalid_token`, produced by the same
// `None`. `404` is never used.
//
// # What it deliberately does not consult
//
// The tenant's `dynamic_registration` mode is read by `PUT` only. A client
// may always read its own registration, and may always delete it — deletion
// only ever reduces what exists, and a tenant that turned registration off is
// the tenant most likely to want its self-registered clients gone. A `PUT`
// under `disabled` is refused `403`, exactly as a registration would be: a
// replacement re-decides the client's posture, and a tenant that has stopped
// accepting self-service registrations has stopped accepting that too.

/// The `{client_id}` path segment.
///
/// A struct rather than `web::Path<String>`: under the T21.6 `/t/{tenant_id}`
/// scope the match info holds **two** segments, and a bare `String` extractor
/// refuses that with a `404` — which would make the configuration endpoint
/// unreachable on a path issuer. Named, the `tenant_id` segment is ignored here
/// (the tenant arrives through `TenantQuery`, which `TenantPathScope` fills).
#[derive(Debug, Deserialize)]
pub struct ClientIdPath {
    /// The client's issued `client_id`.
    pub client_id: String,
}

/// The `www-authenticate` challenge on a refused management request.
///
/// RFC 6750 §3.1: no `error` when the request carried no token at all, and
/// `invalid_token` when it carried one that is not good. Nothing derived from
/// the presented value is ever echoed.
const CHALLENGE_NO_TOKEN: &str = "Bearer";
const CHALLENGE_INVALID_TOKEN: &str = "Bearer error=\"invalid_token\"";

/// Why a client configuration request was refused, before it could be served.
#[derive(Debug)]
enum ConfigRefusal {
    /// No usable `Authorization: Bearer` header.
    NoToken,
    /// A token was presented and names no registration it may manage — or the
    /// registration does not exist. Indistinguishable by design.
    InvalidToken,
    /// The token was carried somewhere RFC 6750 permits and AXIAM does not:
    /// the query string. Refused even beside a good header, because a token in
    /// a URL has already been written to every access log on the way here.
    TokenInQuery,
    /// A metadata or policy refusal, in RFC 7591 §3.2.2's shape.
    Metadata(DcrError),
    /// The datastore could not answer. Not a `401`: a client told its token
    /// is invalid will discard it, and an outage is not a reason to.
    Unavailable,
}

impl ConfigRefusal {
    /// The stable code the audit row records.
    fn code(&self) -> &'static str {
        match self {
            Self::NoToken | Self::InvalidToken => "invalid_token",
            Self::TokenInQuery => "invalid_request",
            Self::Metadata(e) => e.error_code(),
            Self::Unavailable => "server_error",
        }
    }

    fn response(&self) -> HttpResponse {
        let body = |error: &str, description: &str| DcrErrorResponse {
            error: error.to_owned(),
            error_description: description.to_owned(),
        };
        match self {
            Self::NoToken | Self::InvalidToken => {
                let challenge = if matches!(self, Self::NoToken) {
                    CHALLENGE_NO_TOKEN
                } else {
                    CHALLENGE_INVALID_TOKEN
                };
                HttpResponse::Unauthorized()
                    .append_header(("WWW-Authenticate", challenge))
                    .append_header(("Cache-Control", "no-store"))
                    .append_header(("Pragma", "no-cache"))
                    .json(body(
                        "invalid_token",
                        "present this client's registration access token as \
                         `Authorization: Bearer <token>` (RFC 7592 section 2)",
                    ))
            }
            Self::TokenInQuery => HttpResponse::BadRequest()
                .append_header(("Cache-Control", "no-store"))
                .append_header(("Pragma", "no-cache"))
                .json(body(
                    "invalid_request",
                    "the registration access token is accepted only in the Authorization \
                     header; a token sent in a URL must be treated as disclosed",
                )),
            Self::Metadata(e) => error_response(e),
            Self::Unavailable => HttpResponse::InternalServerError()
                .append_header(("Cache-Control", "no-store"))
                .json(body(
                    "server_error",
                    "the registration could not be read; try again",
                )),
        }
    }
}

/// Whether the query string carries an `access_token` (RFC 6750 §2.3).
fn token_in_query(req: &HttpRequest) -> bool {
    url::form_urlencoded::parse(req.query_string().as_bytes()).any(|(k, _)| k == "access_token")
}

/// The digest of the presented registration access token, or the refusal.
///
/// Header only. A form body is never read for a token — `PUT` takes JSON, and
/// `GET` and `DELETE` take no body — and the query string is refused outright.
fn presented_digest(req: &HttpRequest) -> Result<String, ConfigRefusal> {
    if token_in_query(req) {
        return Err(ConfigRefusal::TokenInQuery);
    }
    let presented = bearer_token(req).ok_or(ConfigRefusal::NoToken)?;
    Ok(dcr::registration_access_token_digest(&presented))
}

/// Authenticate a management request: the `dcr` client the token belongs to.
async fn authenticate_management<C: Connection + Clone>(
    req: &HttpRequest,
    state: &AppState<C>,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<(axiam_core::models::oauth2_client::OAuth2Client, String), ConfigRefusal> {
    let digest = presented_digest(req)?;
    match state
        .oauth2_client_repo
        .get_by_registration_access_token(tenant_id, client_id, &digest)
        .await
    {
        Ok(Some(client)) => Ok((client, digest)),
        Ok(None) => Err(ConfigRefusal::InvalidToken),
        Err(e) => {
            tracing::error!(
                error = %e,
                %tenant_id,
                "could not read a registration while authenticating an RFC 7592 request"
            );
            Err(ConfigRefusal::Unavailable)
        }
    }
}

/// The three operations, as the audit log names them.
#[derive(Clone, Copy)]
enum ConfigOperation {
    Read,
    Update,
    Delete,
}

impl ConfigOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    const fn success_action(self) -> &'static str {
        match self {
            Self::Read => "oauth2.client_configuration_read",
            Self::Update => "oauth2.client_configuration_updated",
            Self::Delete => "oauth2.client_configuration_deleted",
        }
    }
}

/// Whether `client_id` has the shape AXIAM mints (`oa_` + 32 lowercase hex).
///
/// A refused request's path segment is attacker-controlled, and the audit
/// viewer is a place where attacker-controlled strings are read by people —
/// the argument `audit_registration` makes for leaving a refused
/// registration's metadata out. A value of exactly this shape cannot carry
/// anything but an identifier, so it is recorded; any other value is not.
fn is_minted_client_id(client_id: &str) -> bool {
    client_id.strip_prefix("oa_").is_some_and(|hex| {
        hex.len() == 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Record every client configuration request, served or refused (the DCR
/// audit style: `managed_by`, the minted `client_id`, the error code).
///
/// **Never the token**, in any form — not the value, not a prefix, not its
/// digest. The digest is not a secret in the cryptographic sense, but it is
/// the row's lookup key, and an audit export is not where a lookup key for a
/// live credential belongs.
async fn audit_configuration<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    tenant_id: Uuid,
    operation: ConfigOperation,
    client_id: &str,
    refusal: Option<&ConfigRefusal>,
) {
    let (action, outcome) = match refusal {
        None => (operation.success_action(), AuditOutcome::Success),
        Some(_) => ("oauth2.client_configuration_refused", AuditOutcome::Failure),
    };
    let recorded_client_id = is_minted_client_id(client_id).then_some(client_id);
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.into(),
            resource_id: None,
            outcome,
            ip_address: crate::extractors::client_info::client_ip(http_req),
            metadata: Some(serde_json::json!({
                "managed_by": ManagedBy::Dcr.as_str(),
                "operation": operation.as_str(),
                "client_id": recorded_client_id,
                "error": refusal.map(ConfigRefusal::code),
                "token_rotated": matches!(operation, ConfigOperation::Update) && refusal.is_none(),
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not record an RFC 7592 client configuration request; the request is \
             unaffected"
        );
    }
}

fn no_store_json(status: actix_web::http::StatusCode, body: &RegistrationResponse) -> HttpResponse {
    HttpResponse::build(status)
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"))
        .json(body)
}

/// `GET /oauth2/register/{client_id}` — RFC 7592 §2.1 client read.
///
/// Returns the client information response without the token: only its
/// digest is stored, and the token is rotated on `PUT`, never on read.
#[utoipa::path(
    get,
    path = "/oauth2/register/{client_id}",
    tag = "oauth2",
    params(
        ("client_id" = String, Path, description = "The client's issued `client_id`"),
        TenantQuery,
    ),
    responses(
        (status = 200, description = "The client's current registration \
                                      (no `registration_access_token`, no `client_secret`)",
         body = RegistrationResponse),
        (status = 400, description = "The token was sent in the query string",
         body = DcrErrorResponse),
        (status = 401, description = "No token, a token that does not belong to this client \
                                      in this tenant, or no such client (indistinguishable)",
         body = DcrErrorResponse),
        (status = 429, description = "Rate-limited (the registration limiter's preset)"),
    ),
    security(("registration_access_token" = [])),
)]
pub async fn read_registration<C: Connection + Clone>(
    http_req: HttpRequest,
    path: web::Path<ClientIdPath>,
    tenant_query: web::Query<TenantQuery>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let client_id = path.into_inner().client_id;
    match authenticate_management(&http_req, &state, tenant_id, &client_id).await {
        Ok((client, _)) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Read,
                &client.client_id,
                None,
            )
            .await;
            let uri = configuration_uri(&http_req, &state, tenant_id, &client.client_id);
            no_store_json(
                actix_web::http::StatusCode::OK,
                &dcr::client_information(&client, uri, None, None),
            )
        }
        Err(refusal) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Read,
                &client_id,
                Some(&refusal),
            )
            .await;
            refusal.response()
        }
    }
}

/// `PUT /oauth2/register/{client_id}` — RFC 7592 §2.2 client update.
///
/// A full replacement, held to the same `validate` a registration is under
/// the tenant's current policy, and the management token rotates: the response
/// carries the new one, once, and the presented one is dead.
#[utoipa::path(
    put,
    path = "/oauth2/register/{client_id}",
    tag = "oauth2",
    params(
        ("client_id" = String, Path, description = "The client's issued `client_id`"),
        TenantQuery,
    ),
    request_body = RegistrationRequest,
    responses(
        (status = 200, description = "Registration replaced; the rotated \
                                      `registration_access_token` is returned once",
         body = RegistrationResponse),
        (status = 400, description = "The metadata is not one this tenant would register, \
                                      names a server-stated member, or names another client",
         body = DcrErrorResponse),
        (status = 401, description = "No token, a token that does not belong to this client \
                                      in this tenant (including one a concurrent update \
                                      rotated away), or no such client",
         body = DcrErrorResponse),
        (status = 403, description = "Dynamic registration is no longer enabled for this \
                                      tenant", body = DcrErrorResponse),
        (status = 429, description = "Rate-limited (the registration limiter's preset)"),
    ),
    security(("registration_access_token" = [])),
)]
pub async fn update_registration<C: Connection + Clone>(
    http_req: HttpRequest,
    path: web::Path<ClientIdPath>,
    tenant_query: web::Query<TenantQuery>,
    body: web::Bytes,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let client_id = path.into_inner().client_id;
    match update_inner(&http_req, tenant_id, &client_id, &body, &state).await {
        Ok(response) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Update,
                &response.client_id,
                None,
            )
            .await;
            no_store_json(actix_web::http::StatusCode::OK, &response)
        }
        Err(refusal) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Update,
                &client_id,
                Some(&refusal),
            )
            .await;
            refusal.response()
        }
    }
}

/// See [`update_registration`]. Authentication strictly first: nothing about
/// the body — not whether it parses — is reported to a caller who has not
/// proved it holds the token.
async fn update_inner<C: Connection + Clone>(
    http_req: &HttpRequest,
    tenant_id: Uuid,
    client_id: &str,
    body: &[u8],
    state: &AppState<C>,
) -> Result<RegistrationResponse, ConfigRefusal> {
    let (stored, presented_digest) =
        authenticate_management(http_req, state, tenant_id, client_id).await?;

    let json: serde_json::Value = serde_json::from_slice(body).map_err(|_| {
        ConfigRefusal::Metadata(DcrError::InvalidClientMetadata(
            "the request body is not a JSON client metadata document".into(),
        ))
    })?;

    // The tenant's policy as it is now, and its mode gate. `disabled` is the
    // same `403` a registration gets.
    let policy = effective_policy(state, tenant_id)
        .await
        .map_err(ConfigRefusal::Metadata)?;
    if policy.dynamic_registration == DynamicRegistrationMode::Disabled {
        return Err(ConfigRefusal::Metadata(DcrError::RegistrationDisabled));
    }

    let validated = dcr::validate_update(tenant_id, client_id, &json, &stored, &policy)
        .map_err(ConfigRefusal::Metadata)?;

    // RFC 7592 §2.2: a `client_secret` in the body MUST match the issued one,
    // and a client may never choose its own. Compared by the same keyed
    // verifier the token endpoint uses (HMAC, constant-time). A public client
    // holds no secret, so any value it sends is a mismatch.
    if let Some(presented) = json.get("client_secret") {
        let matches = match (
            presented.as_str(),
            stored.token_endpoint_auth_method.is_public(),
        ) {
            (Some(secret), false) => axiam_auth::client_secret::global()
                .map(|hasher| hasher.verify(secret, &stored.client_secret_hash).is_match())
                .unwrap_or(false),
            _ => false,
        };
        if !matches {
            return Err(ConfigRefusal::Metadata(DcrError::InvalidRequest(
                "client_secret does not match the secret issued to this client; a client \
                 cannot choose its own secret (RFC 7592 section 2.2)"
                    .into(),
            )));
        }
    }

    // The same two structural gates a registration passes.
    // G-7: as at registration, a CIBA-only client may name no redirect URI.
    let browser_driven = validated
        .create
        .grant_types
        .iter()
        .any(|g| g == "authorization_code");
    if browser_driven || !validated.create.redirect_uris.is_empty() {
        crate::handlers::oauth2_clients::validate_redirect_uris(&validated.create.redirect_uris)
            .map_err(|e| ConfigRefusal::Metadata(DcrError::InvalidRedirectUri(e.0.to_string())))?;
    }
    axiam_oauth2::fapi::validate_registration(&validated.create)
        .map_err(|e| ConfigRefusal::Metadata(DcrError::InvalidClientMetadata(e.to_string())))?;

    // Replace and rotate, as one compare-and-swap on the presented digest. A
    // `None` here is a concurrent update that rotated the token first (or a
    // concurrent delete): this caller's token is dead, which is the `401`
    // RFC 7592 gives a token that is not valid.
    let (new_token, new_digest) = dcr::mint_registration_access_token();
    let replaced = state
        .oauth2_client_repo
        .replace_dcr_registration(
            tenant_id,
            client_id,
            &presented_digest,
            &new_digest,
            DcrRegistrationReplacement::from_validated(&validated.create),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %tenant_id, "could not replace a registration");
            ConfigRefusal::Unavailable
        })?
        .ok_or(ConfigRefusal::InvalidToken)?;

    let uri = configuration_uri(http_req, state, tenant_id, &replaced.client_id);
    Ok(dcr::client_information(
        &replaced,
        uri,
        None,
        Some(new_token),
    ))
}

/// `DELETE /oauth2/register/{client_id}` — RFC 7592 §2.3 client delete.
///
/// Deletes the row through a delete conditional on the token, so the
/// management token dies with it and a second `DELETE` is `401`; then revokes
/// every refresh token issued to the client. The deleted row no longer counts
/// against `dcr_max_clients`.
#[utoipa::path(
    delete,
    path = "/oauth2/register/{client_id}",
    tag = "oauth2",
    params(
        ("client_id" = String, Path, description = "The client's issued `client_id`"),
        TenantQuery,
    ),
    responses(
        (status = 204, description = "Client deregistered; its refresh tokens are revoked"),
        (status = 400, description = "The token was sent in the query string",
         body = DcrErrorResponse),
        (status = 401, description = "No token, a token that does not belong to this client \
                                      in this tenant, or no such client",
         body = DcrErrorResponse),
        (status = 429, description = "Rate-limited (the registration limiter's preset)"),
    ),
    security(("registration_access_token" = [])),
)]
pub async fn delete_registration<C: Connection + Clone>(
    http_req: HttpRequest,
    path: web::Path<ClientIdPath>,
    tenant_query: web::Query<TenantQuery>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let client_id = path.into_inner().client_id;
    match delete_inner(&http_req, tenant_id, &client_id, &state).await {
        Ok(()) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Delete,
                &client_id,
                None,
            )
            .await;
            HttpResponse::NoContent()
                .append_header(("Cache-Control", "no-store"))
                .append_header(("Pragma", "no-cache"))
                .finish()
        }
        Err(refusal) => {
            audit_configuration(
                &state,
                &http_req,
                tenant_id,
                ConfigOperation::Delete,
                &client_id,
                Some(&refusal),
            )
            .await;
            refusal.response()
        }
    }
}

/// See [`delete_registration`]. What deletion revokes, and why the rest need
/// not be, is written once on
/// [`revoke_client_grants`](crate::handlers::oauth2_clients::revoke_client_grants),
/// which the administrator's `DELETE /api/v1/oauth2-clients/{id}` calls too.
///
/// The revocation follows the delete here rather than preceding it, because
/// the delete *is* the credential check — conditional on the presented
/// token's digest — and revoking first would let anybody naming a
/// `client_id` revoke its tokens.
async fn delete_inner<C: Connection + Clone>(
    http_req: &HttpRequest,
    tenant_id: Uuid,
    client_id: &str,
    state: &AppState<C>,
) -> Result<(), ConfigRefusal> {
    let digest = presented_digest(http_req)?;
    let deleted = state
        .oauth2_client_repo
        .delete_by_registration_access_token(tenant_id, client_id, &digest)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, %tenant_id, "could not delete a registration");
            ConfigRefusal::Unavailable
        })?
        .ok_or(ConfigRefusal::InvalidToken)?;

    if let Err(e) =
        crate::handlers::oauth2_clients::revoke_client_grants(state, tenant_id, &deleted.client_id)
            .await
    {
        // The client is gone, so its refresh tokens are already unusable at
        // the token endpoint; this is logged rather than turned into an error
        // that would tell the client its deletion failed when it did not.
        tracing::error!(
            error = %e,
            %tenant_id,
            client_id = %deleted.client_id,
            "a deregistered client's refresh tokens could not be marked revoked"
        );
    }
    Ok(())
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
