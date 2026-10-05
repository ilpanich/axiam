//! The Shared Signals Framework transmitter's protocol surface (G-5, T23.5.2,
//! SSF 1.0 §7 and §8, contract §32.6): transmitter metadata and the stream
//! management API a receiver calls.
//!
//! # Discovery (D-45)
//!
//! `GET /.well-known/ssf-configuration?tenant_id={t}` everywhere, and
//! `GET /.well-known/ssf-configuration/t/{t}` — SSF §7.2's insertion of the
//! well-known segment into the issuer `{root}/t/{t}` — where the deployment
//! serves tenant issuers (T21.6). Unauthenticated, as the specification
//! requires. **An empty `404`** for an unknown tenant, a tenant whose effective
//! `ssf_enabled` is off, a missing or malformed tenant id — one answer for every
//! way of having nothing to say, so the route tells nobody which tenants exist
//! or transmit (the D-20 shape).
//!
//! # The stream management API (D-50)
//!
//! `/ssf/v1/stream`, `/ssf/v1/status`, `/ssf/v1/verify`, authenticated by a
//! **receiver token**: an access token issued to an OAuth2 client by the
//! client-credentials grant with the `ssf.manage` scope ([`SsfReceiverToken`]).
//! A user token, a service-account token or a client token without the scope is
//! `403`. The tenant is the token's; a stream is the receiver's only when its
//! `receiver_client_id` is the token's `client_id`, and any other stream —
//! another receiver's, another tenant's, or one in a tenant whose transmitter
//! is switched off — is the same `404` as one that does not exist (SSF §8.1.1:
//! "no Event Stream with the given stream_id for this Event Receiver").
//!
//! Streams are registered and deleted by an administrator (`handlers::
//! ssf_admin`); `POST` and `DELETE` on the configuration endpoint are `403`.
//! What a receiver may change is `axiam_oauth2::ssf::apply_receiver_update`'s
//! rule: its requested events (never beyond the administrator's ceiling), its
//! description, its push endpoint under the outbound address policy, and the
//! push `Authorization` header. The status it may set unless an administrator
//! set something other than `enabled`. Verification is limited per stream by
//! `min_verification_interval` (`429`) besides the route's bucket.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::token::SubjectKind;
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::ssf::{
    MIN_VERIFICATION_INTERVAL_SECS, POLL_MAX_EVENTS_PER_RESPONSE, SHARED_ISSUER_INACTIVE_REASON,
    SSF_MANAGE_SCOPE, SecretChange, SsfDeliveryMethod, SsfStatusActor, SsfStream, SsfStreamStatus,
    SsfStreamUpdate,
};
use axiam_core::repository::{
    AuditLogRepository, SettingsRepository, SsfEventBufferRepository, SsfStreamRepository,
    TenantRepository,
};
use axiam_oauth2::ssf::{
    ReceiverStreamUpdate, ReceiverUpdateMode, SsfConfiguration, SsfError, SsfStreamConfiguration,
    apply_receiver_update, build_ssf_configuration, prepare_verification, sign_set,
    stream_configuration, validate_status_reason,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// Audit action: a receiver changed its stream's configuration.
pub const AUDIT_RECEIVER_UPDATED: &str = "ssf_stream.receiver_updated";
/// Audit action: a receiver changed its stream's status.
pub const AUDIT_RECEIVER_STATUS: &str = "ssf_stream.receiver_status_changed";
/// Audit action: a receiver asked for a verification event.
pub const AUDIT_VERIFICATION: &str = "ssf_stream.verification_requested";

/// Audit action: a receiver reported, in a poll request's `setErrs`, that it
/// could not accept a SET (RFC 8936 §2.4). `metadata.err` is one of RFC 8935
/// §2.4's codes (or `unrecognized`); a receiver's free-text description is never
/// stored.
pub const AUDIT_POLL_SET_ERROR: &str = "ssf_stream.poll_set_error";

/// Longest verification `state`, in bytes.
const MAX_STATE_BYTES: usize = 1024;

/// The longest a poll request waits for an event when it does not ask to return
/// immediately (D-48: a long poll is at most 30 s).
pub const POLL_LONG_POLL_MAX: std::time::Duration = std::time::Duration::from_secs(30);
/// How often a waiting poll looks at the buffer again.
const POLL_WAIT_STEP: std::time::Duration = std::time::Duration::from_millis(500);
/// Largest request body a poll takes, in bytes.
pub const POLL_MAX_BODY_BYTES: usize = 32_768;
/// Most `ack` entries one poll request may carry.
const POLL_MAX_ACKS: usize = 1_000;
/// Most `setErrs` entries one poll request may carry.
const POLL_MAX_SET_ERRS: usize = 100;
/// A `jti` longer than this names nothing (they are 32 characters).
const MAX_JTI_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// The tenant switch
// ---------------------------------------------------------------------------

/// Whether `tenant_id` exists, its effective `ssf_enabled` is on **and** the
/// D-55 gate does not hold. An unknown tenant is `false`, never an error a
/// caller could tell apart. Discovery, the receiver API, verification and the
/// stream-updated announcement all ask this, so the gate makes SSF behave
/// exactly as `ssf_enabled` off for every tenant.
pub(crate) async fn ssf_enabled_for<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Result<bool, AxiamError> {
    Ok(transmitter_status(state, tenant_id).await?.is_none())
}

/// Why the tenant's transmitter is inactive, or `None` when it is active: the
/// tenant does not exist, its `ssf_enabled` is off, or the D-55 gate holds.
pub(crate) async fn transmitter_status<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Result<Option<&'static str>, AxiamError> {
    let tenant = match state.tenant_repo.get_by_id(tenant_id).await {
        Ok(tenant) => tenant,
        Err(AxiamError::NotFound { .. }) => return Ok(Some(NO_SUCH_TENANT)),
        Err(other) => return Err(other),
    };
    let settings = state
        .settings_repo
        .get_effective_settings(tenant.organization_id, tenant_id)
        .await?;
    if !settings.oidc.ssf_enabled {
        return Ok(Some(SWITCH_OFF));
    }
    if state.ssf.gate.check().await?.holds() {
        return Ok(Some(SHARED_ISSUER_INACTIVE_REASON));
    }
    Ok(None)
}

/// [`transmitter_status`]'s answer for a tenant that does not exist.
const NO_SUCH_TENANT: &str = "the tenant does not exist";
/// [`transmitter_status`]'s answer for a tenant whose switch is off.
pub(crate) const SWITCH_OFF: &str = "ssf_enabled is off for this tenant";

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// `?tenant_id=` of the root discovery form.
#[derive(Debug, Deserialize)]
pub struct SsfDiscoveryQuery {
    /// The tenant whose transmitter metadata is asked for.
    pub tenant_id: Option<String>,
}

async fn discovery_for<C: Connection + Clone>(
    state: &AppState<C>,
    tenant: Option<&str>,
) -> HttpResponse {
    let Some(tenant_id) = tenant.and_then(|raw| Uuid::parse_str(raw).ok()) else {
        return HttpResponse::NotFound().finish();
    };
    match ssf_enabled_for(state, tenant_id).await {
        Ok(true) => HttpResponse::Ok()
            .append_header(("Cache-Control", "public, max-age=300"))
            .json(build_ssf_configuration(&state.auth_config, tenant_id)),
        Ok(false) => HttpResponse::NotFound().finish(),
        Err(error) => {
            tracing::error!(target: "axiam::ssf", %error, "SSF discovery could not read the tenant");
            HttpResponse::ServiceUnavailable().finish()
        }
    }
}

/// `GET /.well-known/ssf-configuration` — SSF 1.0 §7 transmitter metadata.
#[utoipa::path(
    get,
    path = "/.well-known/ssf-configuration",
    tag = "ssf-receiver",
    params(("tenant_id" = Uuid, Query, description = "The tenant whose transmitter metadata is asked for")),
    responses(
        (status = 200, description = "SSF transmitter metadata", body = SsfConfiguration),
        (status = 404, description = "Nothing to describe: an unknown tenant, or one whose \
                                      transmitter is off or inactive — `ssf_enabled` off, or a \
                                      deployment of several tenants without per-tenant issuers \
                                      (D-55) — (indistinguishable)"),
        (status = 429, description = "Rate limit"),
    ),
)]
pub async fn ssf_configuration<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    query: web::Query<SsfDiscoveryQuery>,
) -> HttpResponse {
    discovery_for(&state, query.tenant_id.as_deref()).await
}

/// `GET /.well-known/ssf-configuration/t/{tenant_id}` — the same metadata at
/// the SSF §7.2 insertion form of the tenant issuer `{root}/t/{tenant_id}`.
/// Mounted only where the deployment serves tenant issuers.
#[utoipa::path(
    get,
    path = "/.well-known/ssf-configuration/t/{tenant_id}",
    tag = "ssf-receiver",
    params(("tenant_id" = Uuid, Path, description = "The tenant this issuer names")),
    responses(
        (status = 200, description = "SSF transmitter metadata", body = SsfConfiguration),
        (status = 404, description = "Nothing to describe: an unknown tenant, or one whose \
                                      transmitter is off (indistinguishable)"),
        (status = 429, description = "Rate limit"),
    ),
)]
pub async fn ssf_configuration_tenant_path<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
) -> HttpResponse {
    discovery_for(&state, req.match_info().get("tenant_id")).await
}

// ---------------------------------------------------------------------------
// The receiver token
// ---------------------------------------------------------------------------

/// A validated receiver token: an access token issued to an OAuth2 client by
/// the client-credentials grant, carrying `ssf.manage`. Its own extractor for
/// the reason `ProtectionApiToken` is: the subject is a `client_id`, not a
/// principal in the RBAC graph, and the scope **is** the gate.
pub struct SsfReceiverToken {
    /// The receiver's `client_id` — the token's `sub`.
    pub client_id: String,
    /// The token's tenant.
    pub tenant_id: Uuid,
}

fn forbidden(reason: &str) -> AxiamApiError {
    AxiamApiError(AxiamError::AuthorizationDenied {
        reason: reason.to_owned(),
        action: None,
        resource_id: None,
    })
}

fn extract_receiver(req: &HttpRequest) -> Result<SsfReceiverToken, AxiamApiError> {
    let claims = crate::extractors::auth::parse_validated_claims(req)?.0;
    if claims.sub_kind != SubjectKind::OAuth2Client {
        return Err(forbidden(
            "the SSF stream management API takes an OAuth2 client's client-credentials token",
        ));
        ciba: Default::default(),
    }
    if !claims
        .scope
        .as_deref()
        .is_some_and(|s| s.split(' ').any(|granted| granted == SSF_MANAGE_SCOPE))
    {
        return Err(forbidden(&format!(
            "the SSF stream management API requires the '{SSF_MANAGE_SCOPE}' scope"
        )));
    }
    let tenant_id = Uuid::parse_str(&claims.tenant_id).map_err(|_| {
        AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })
    })?;
    Ok(SsfReceiverToken {
        client_id: claims.sub,
        tenant_id,
    })
}

impl actix_web::FromRequest for SsfReceiverToken {
    type Error = AxiamApiError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        std::future::ready(extract_receiver(req))
    }
}

fn no_such_stream() -> AxiamApiError {
    AxiamApiError(AxiamError::NotFound {
        entity: "ssf_stream".into(),
        id: "for this receiver".into(),
    })
}

/// The receiver's stream `raw_id`, or the one `404` for every other case.
async fn owned_stream<C: Connection + Clone>(
    state: &AppState<C>,
    receiver: &SsfReceiverToken,
    raw_id: Option<&str>,
) -> Result<SsfStream, AxiamApiError> {
    let Some(stream_id) = raw_id.and_then(|raw| Uuid::parse_str(raw).ok()) else {
        return Err(no_such_stream());
    };
    if !ssf_enabled_for(state, receiver.tenant_id).await? {
        return Err(no_such_stream());
    }
    let stream = match state
        .ssf
        .stream_repo
        .get(receiver.tenant_id, stream_id)
        .await
    {
        Ok(stream) => stream,
        Err(AxiamError::NotFound { .. }) => return Err(no_such_stream()),
        Err(other) => return Err(AxiamApiError(other)),
    };
    if stream.receiver_client_id != receiver.client_id {
        return Err(no_such_stream());
    }
    Ok(stream)
}

async fn audit_receiver<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    receiver: &SsfReceiverToken,
    action: &str,
    stream_id: Uuid,
    metadata: serde_json::Value,
) {
    let mut metadata = metadata;
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "receiver_client_id".into(),
            serde_json::json!(receiver.client_id),
        );
    }
    if let Err(error) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id: receiver.tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.to_string(),
            resource_id: Some(stream_id),
            outcome: AuditOutcome::Success,
            ip_address: client_ip(http_req),
            metadata: Some(metadata),
        })
        .await
    {
        tracing::error!(target: "axiam::ssf", action, %error, "an SSF audit row could not be written");
    }
}

/// A paused push stream was enabled again: enqueue what it held, oldest first
/// (D-48). Best effort and bounded — the held events stay buffered if the
/// broker is down, and the next resume (or a status write) takes them.
pub(crate) async fn release_held<C: Connection + Clone>(state: &AppState<C>, stream: &SsfStream) {
    let Some(outbox) = state.ssf.outbox.as_ref() else {
        return;
    };
    match outbox.resume(stream).await {
        Ok(0) => {}
        Ok(released) => {
            tracing::info!(target: "axiam::ssf", stream_id = %stream.id, released, "held SSF events released");
        }
        Err(error) => {
            tracing::warn!(target: "axiam::ssf", stream_id = %stream.id, %error, "held SSF events could not be released");
        }
    }
}

fn no_store(mut builder: actix_web::HttpResponseBuilder) -> actix_web::HttpResponseBuilder {
    builder.append_header(("Cache-Control", "no-store"));
    builder
}

// ---------------------------------------------------------------------------
// The configuration endpoint
// ---------------------------------------------------------------------------

/// `?stream_id=` of the configuration and status endpoints.
#[derive(Debug, Deserialize)]
pub struct StreamIdQuery {
    /// The stream.
    pub stream_id: Option<String>,
}

/// `GET /ssf/v1/stream` — the receiver's stream, or all of them.
#[utoipa::path(
    get,
    path = "/ssf/v1/stream",
    tag = "ssf-receiver",
    params(("stream_id" = Option<String>, Query, description = "One stream; omit for every stream of this receiver")),
    responses(
        (status = 200, description = "The stream configuration, or an array of them", body = SsfStreamConfiguration),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn get_stream_configuration<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    query: web::Query<StreamIdQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    if let Some(raw) = query.stream_id.as_deref() {
        let stream = owned_stream(&state, &receiver, Some(raw)).await?;
        return Ok(
            no_store(HttpResponse::Ok()).json(stream_configuration(&state.auth_config, &stream))
        );
    }
    let streams = if ssf_enabled_for(&state, receiver.tenant_id).await? {
        state
            .ssf
            .stream_repo
            .list_for_receiver(receiver.tenant_id, &receiver.client_id)
            .await?
    } else {
        Vec::new()
    };
    let views: Vec<SsfStreamConfiguration> = streams
        .iter()
        .map(|s| stream_configuration(&state.auth_config, s))
        .collect();
    Ok(no_store(HttpResponse::Ok()).json(views))
}

/// `POST /ssf/v1/stream` — refused: streams are registered by an
/// administrator (SSF §8.1.1.1 allows `403`).
#[utoipa::path(
    post,
    path = "/ssf/v1/stream",
    tag = "ssf-receiver",
    responses(
        (status = 401, description = "No valid token"),
        (status = 403, description = "Always: streams are registered by a tenant administrator"),
    ),
    security(("bearer" = []))
)]
pub async fn create_stream_refused(
    _receiver: SsfReceiverToken,
) -> Result<HttpResponse, AxiamApiError> {
    Err(forbidden(
        "SSF streams are registered by a tenant administrator, not by the receiver",
    ))
}

/// How many times a receiver's write is prepared again from a fresh read when
/// another write overtook the read it was prepared from (F4 W4 P23W4-01). Past
/// that the answer is `409`.
const RECEIVER_WRITE_ATTEMPTS: usize = 3;

/// Whether a failed write lost a race to another write of the same stream and
/// should be prepared again from a fresh read.
fn overtaken(error: &AxiamError, attempt: usize) -> bool {
    matches!(error, AxiamError::Conflict { .. }) && attempt + 1 < RECEIVER_WRITE_ATTEMPTS
}

async fn update_with<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: ReceiverStreamUpdate,
    mode: ReceiverUpdateMode,
) -> Result<HttpResponse, AxiamApiError> {
    let Some(raw_id) = body.stream_id.clone() else {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "stream_id is required".into(),
        }));
    };
    // Read, decide, write — and if another write (an administrator's) landed
    // between the read and the write, decide again against what it left: the
    // update carries the version it was prepared from, so it never puts back
    // what that write changed (D-51, T-406).
    let mut attempt = 0;
    let (stream, updated, changed) = loop {
        let stream = owned_stream(&state, &receiver, Some(&raw_id)).await?;
        let update = apply_receiver_update(&state.auth_config, &stream, &body, mode)
            .map_err(|message| AxiamApiError(AxiamError::Validation { message }))?;
        if matches!(update.authorization_header, SecretChange::Set(_))
            && !state.ssf.stream_repo.has_encryption_key()
        {
            return Err(AxiamApiError(AxiamError::ServiceUnavailable(
                "the push authorization header cannot be stored on this deployment".into(),
            )));
        }
        let mut changed: Vec<&str> = Vec::new();
        if update.events_requested != stream.events_requested {
            changed.push("events_requested");
        }
        if update.description != stream.description {
            changed.push("description");
        }
        if update.endpoint_url != stream.endpoint_url {
            changed.push("endpoint_url");
        }
        if !matches!(update.authorization_header, SecretChange::Keep) {
            changed.push("authorization_header");
        }
        match state
            .ssf
            .stream_repo
            .update(receiver.tenant_id, stream.id, update)
            .await
        {
            Ok(updated) => break (stream, updated, changed),
            Err(error) if overtaken(&error, attempt) => attempt += 1,
            Err(error) => return Err(AxiamApiError(error)),
        }
    };
    audit_receiver(
        &state,
        &http_req,
        &receiver,
        AUDIT_RECEIVER_UPDATED,
        stream.id,
        serde_json::json!({ "changed": changed }),
    )
    .await;
    Ok(no_store(HttpResponse::Ok()).json(stream_configuration(&state.auth_config, &updated)))
}

/// `PATCH /ssf/v1/stream` — change the receiver-supplied members present.
#[utoipa::path(
    patch,
    path = "/ssf/v1/stream",
    tag = "ssf-receiver",
    request_body = ReceiverStreamUpdate,
    responses(
        (status = 200, description = "The updated configuration", body = SsfStreamConfiguration),
        (status = 400, description = "A transmitter-supplied member that does not match, an event \
                                      beyond the administrator's allowance, a delivery method \
                                      change, a refused endpoint, or a move to another origin \
                                      without the authorization header"),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 409, description = "The stream kept changing under this write; read it again and retry"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "The header cannot be stored on this deployment"),
    ),
    security(("bearer" = []))
)]
pub async fn patch_stream_configuration<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<ReceiverStreamUpdate>,
) -> Result<HttpResponse, AxiamApiError> {
    update_with(
        receiver,
        state,
        http_req,
        body.into_inner(),
        ReceiverUpdateMode::Patch,
    )
    .await
}

/// `PUT /ssf/v1/stream` — replace the receiver-supplied members; an absent
/// one is deleted.
#[utoipa::path(
    put,
    path = "/ssf/v1/stream",
    tag = "ssf-receiver",
    request_body = ReceiverStreamUpdate,
    responses(
        (status = 200, description = "The replaced configuration", body = SsfStreamConfiguration),
        (status = 400, description = "As for PATCH, or no delivery"),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 409, description = "The stream kept changing under this write; read it again and retry"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "The header cannot be stored on this deployment"),
    ),
    security(("bearer" = []))
)]
pub async fn replace_stream_configuration<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<ReceiverStreamUpdate>,
) -> Result<HttpResponse, AxiamApiError> {
    update_with(
        receiver,
        state,
        http_req,
        body.into_inner(),
        ReceiverUpdateMode::Replace,
    )
    .await
}

/// `DELETE /ssf/v1/stream` — refused for the receiver's own stream (an
/// administrator deletes streams); `404` for any other.
#[utoipa::path(
    delete,
    path = "/ssf/v1/stream",
    tag = "ssf-receiver",
    params(("stream_id" = String, Query, description = "The stream")),
    responses(
        (status = 401, description = "No valid token"),
        (status = 403, description = "Streams are deleted by a tenant administrator"),
        (status = 404, description = "No such stream for this receiver"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_stream_refused<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    query: web::Query<StreamIdQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    owned_stream(&state, &receiver, query.stream_id.as_deref()).await?;
    Err(forbidden(
        "SSF streams are deleted by a tenant administrator; set the status to disabled instead",
    ))
}

// ---------------------------------------------------------------------------
// The status endpoint
// ---------------------------------------------------------------------------

/// A stream's status (SSF §8.1.2.1).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SsfStreamStatusView {
    /// The stream.
    pub stream_id: String,
    /// `enabled`, `paused` or `disabled`.
    pub status: SsfStreamStatus,
    /// Why, if anyone said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&SsfStream> for SsfStreamStatusView {
    fn from(s: &SsfStream) -> Self {
        Self {
            stream_id: s.id.to_string(),
            status: s.status,
            reason: s.status_reason.clone(),
        }
    }
}

/// `POST /ssf/v1/status` body (SSF §8.1.2.2).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SsfStatusUpdate {
    /// The stream.
    pub stream_id: String,
    /// `enabled`, `paused` or `disabled`.
    pub status: String,
    /// Why; at most 256 bytes.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `GET /ssf/v1/status`
#[utoipa::path(
    get,
    path = "/ssf/v1/status",
    tag = "ssf-receiver",
    params(("stream_id" = String, Query, description = "The stream")),
    responses(
        (status = 200, description = "The stream's status", body = SsfStreamStatusView),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn get_stream_status<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    query: web::Query<StreamIdQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    let stream = owned_stream(&state, &receiver, query.stream_id.as_deref()).await?;
    Ok(no_store(HttpResponse::Ok()).json(SsfStreamStatusView::from(&stream)))
}

/// `POST /ssf/v1/status`
#[utoipa::path(
    post,
    path = "/ssf/v1/status",
    tag = "ssf-receiver",
    request_body = SsfStatusUpdate,
    responses(
        (status = 200, description = "The stream's new status", body = SsfStreamStatusView),
        (status = 400, description = "An unknown status or an over-long reason"),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not a receiver token, or an administrator set this status"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 409, description = "The stream kept changing under this write; read it again and retry"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn update_stream_status<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<SsfStatusUpdate>,
) -> Result<HttpResponse, AxiamApiError> {
    let body = body.into_inner();
    let status = SsfStreamStatus::from_wire(&body.status).ok_or_else(|| {
        AxiamApiError(AxiamError::Validation {
            message: "status must be enabled, paused or disabled".into(),
        })
    })?;
    if let Some(reason) = &body.reason {
        validate_status_reason(reason)
            .map_err(|message| AxiamApiError(AxiamError::Validation { message }))?;
    }
    let reason = body.reason.filter(|r| !r.is_empty());
    // Read, decide, write; decided again from a fresh read when an
    // administrator's write landed in between (F4 W4 P23W4-01, T-406), so the
    // D-51 check below always judges the status the write would replace.
    let mut attempt = 0;
    let (stream, updated) = loop {
        let stream = owned_stream(&state, &receiver, Some(&body.stream_id)).await?;
        // D-51: what an administrator stopped, only an administrator restarts.
        if stream.status_actor == SsfStatusActor::Admin && stream.status != SsfStreamStatus::Enabled
        {
            return Err(forbidden(
                "an administrator set this stream's status; only an administrator can change it",
            ));
        }
        let mut update = SsfStreamUpdate::from_stream(&stream);
        update.status = status;
        update.status_reason = reason.clone();
        update.status_actor = SsfStatusActor::Receiver;
        match state
            .ssf
            .stream_repo
            .update(receiver.tenant_id, stream.id, update)
            .await
        {
            Ok(updated) => break (stream, updated),
            Err(error) if overtaken(&error, attempt) => attempt += 1,
            Err(error) => return Err(AxiamApiError(error)),
        }
    };
    let previous = stream.status;
    audit_receiver(
        &state,
        &http_req,
        &receiver,
        AUDIT_RECEIVER_STATUS,
        stream.id,
        serde_json::json!({ "from": previous.as_str(), "to": updated.status.as_str() }),
    )
    .await;
    if previous == SsfStreamStatus::Paused && updated.status == SsfStreamStatus::Enabled {
        release_held(&state, &updated).await;
    }
    Ok(no_store(HttpResponse::Ok()).json(SsfStreamStatusView::from(&updated)))
}

// ---------------------------------------------------------------------------
// The verification endpoint
// ---------------------------------------------------------------------------

/// `POST /ssf/v1/verify` body (SSF §8.1.4.2).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SsfVerificationRequest {
    /// The stream.
    pub stream_id: String,
    /// Echoed in the verification event; at most 1 024 bytes.
    #[serde(default)]
    pub state: Option<String>,
}

/// `POST /ssf/v1/verify` — have a verification event transmitted.
#[utoipa::path(
    post,
    path = "/ssf/v1/verify",
    tag = "ssf-receiver",
    request_body = SsfVerificationRequest,
    responses(
        (status = 204, description = "The verification event was submitted for delivery"),
        (status = 400, description = "An over-long state, or a disabled stream"),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 429, description = "Sooner than min_verification_interval, or the route's limit"),
        (status = 503, description = "Event delivery is not available on this deployment"),
    ),
    security(("bearer" = []))
)]
pub async fn request_verification<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<SsfVerificationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let body = body.into_inner();
    let stream = owned_stream(&state, &receiver, Some(&body.stream_id)).await?;
    if body
        .state
        .as_ref()
        .is_some_and(|s| s.len() > MAX_STATE_BYTES)
    {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!("state must be at most {MAX_STATE_BYTES} bytes"),
        }));
    }
    if stream.status == SsfStreamStatus::Disabled {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "the stream is disabled: nothing is transmitted on it".into(),
        }));
    }
    let Some(outbox) = state.ssf.outbox.clone() else {
        return Err(AxiamApiError(AxiamError::ServiceUnavailable(
            "SSF event delivery is not available on this deployment".into(),
        )));
    };
    let now = Utc::now();
    if !state
        .ssf
        .stream_repo
        .claim_verification(
            receiver.tenant_id,
            stream.id,
            now,
            MIN_VERIFICATION_INTERVAL_SECS,
        )
        .await?
    {
        return Err(AxiamApiError(AxiamError::RateLimited));
    }
    let event = prepare_verification(&stream, body.state.as_deref(), now).map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "the stream is disabled: nothing is transmitted on it".into(),
        })
    })?;
    outbox.submit(&stream, &event).await.map_err(|error| {
        tracing::warn!(target: "axiam::ssf", stream_id = %stream.id, %error, "verification event not submitted");
        AxiamApiError(AxiamError::ServiceUnavailable(
            "the verification event could not be submitted".into(),
        ))
    })?;
    audit_receiver(
        &state,
        &http_req,
        &receiver,
        AUDIT_VERIFICATION,
        stream.id,
        serde_json::json!({ "jti": event.jti }),
    )
    .await;
    Ok(no_store(HttpResponse::NoContent()).finish())
}

// ---------------------------------------------------------------------------
// The poll endpoint (RFC 8936)
// ---------------------------------------------------------------------------

/// One `setErrs` entry (RFC 8936 §2.4).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SsfSetError {
    /// An RFC 8935 §2.4 error code.
    pub err: String,
    /// Free text from the receiver. Accepted and **not stored**.
    #[serde(default)]
    pub description: Option<String>,
}

/// `POST /ssf/v1/poll/{stream_id}` body (RFC 8936 §2.2). Every member is
/// optional; an empty body is `{}`.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct SsfPollRequest {
    /// The most SETs to return, clamped to 100. `0` acknowledges only.
    #[serde(rename = "maxEvents", default)]
    pub max_events: Option<i64>,
    /// `true` answers at once, possibly with no SETs; `false` (the default)
    /// waits up to 30 s for one.
    #[serde(rename = "returnImmediately", default)]
    pub return_immediately: Option<bool>,
    /// The `jti`s of SETs the receiver processed: exactly those rows of this
    /// stream are deleted.
    #[serde(default)]
    pub ack: Vec<String>,
    /// SETs the receiver could not accept: each is deleted and audited.
    #[serde(rename = "setErrs", default)]
    pub set_errs: std::collections::HashMap<String, SsfSetError>,
}

/// `POST /ssf/v1/poll/{stream_id}` answer (RFC 8936 §2.3).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SsfPollResponse {
    /// The compact SETs by `jti`: the oldest held events, up to `maxEvents`,
    /// signed now, against the stream as it is now.
    #[schema(value_type = std::collections::HashMap<String, String>)]
    pub sets: serde_json::Map<String, serde_json::Value>,
    /// Whether more are held than were returned.
    #[serde(rename = "moreAvailable")]
    pub more_available: bool,
}

/// The audit-safe reading of a receiver's `err`: one of RFC 8935 §2.4's codes,
/// else a fixed word. Free text from a third party is not written to the audit
/// log.
fn audited_err_code(raw: &str) -> &'static str {
    axiam_oauth2::ssf_delivery::RFC_8935_ERROR_CODES
        .into_iter()
        .find(|known| *known == raw)
        .unwrap_or("unrecognized")
}

fn empty_poll_response() -> HttpResponse {
    no_store(HttpResponse::Ok()).json(SsfPollResponse {
        sets: serde_json::Map::new(),
        more_available: false,
    })
}

/// `POST /ssf/v1/poll/{stream_id}` — RFC 8936 poll delivery (D-48).
///
/// The receiver's token, as on the stream API, and the same single `404` for a
/// stream that is not its own. In this order: the acknowledgements, then the
/// reported errors, then the next SETs — so an event acknowledged here is not
/// returned by this same call. An unacknowledged event comes back on the next
/// poll (at-least-once); a SET is **signed now**, against the stream as it is
/// now, so a stream paused or disabled meanwhile answers an empty `sets`.
///
/// Without `returnImmediately` the call long-polls for up to 30 seconds; at most
/// one long poll waits per stream per server instance, and a second concurrent
/// request on the same stream is answered at once as if `returnImmediately` were
/// true (D-53).
#[utoipa::path(
    post,
    path = "/ssf/v1/poll/{stream_id}",
    tag = "ssf-receiver",
    params(("stream_id" = String, Path, description = "The poll stream")),
    request_body = Option<SsfPollRequest>,
    responses(
        (status = 200, description = "The oldest held SETs, up to maxEvents, and whether more are held", body = SsfPollResponse),
        (status = 400, description = "A malformed body, a negative maxEvents, too many ack or \
                                      setErrs entries, or a push stream"),
        (status = 401, description = "No valid token"),
        (status = 403, description = "Not an OAuth2 client token with the ssf.manage scope"),
        (status = 404, description = "No such stream for this receiver"),
        (status = 413, description = "The body is over 32 KiB"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn poll_events<C: Connection + Clone>(
    receiver: SsfReceiverToken,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<String>,
    body: web::Bytes,
) -> Result<HttpResponse, AxiamApiError> {
    let raw_id = path.into_inner();
    let mut stream = owned_stream(&state, &receiver, Some(&raw_id)).await?;
    if stream.delivery_method != SsfDeliveryMethod::Poll {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "this stream delivers by push; there is nothing to poll".into(),
        }));
    }
    if body.len() > POLL_MAX_BODY_BYTES {
        return Ok(HttpResponse::PayloadTooLarge().finish());
    }
    let request: SsfPollRequest = if body.iter().all(u8::is_ascii_whitespace) {
        SsfPollRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            AxiamApiError(AxiamError::Validation {
                message: "the poll request is not a valid RFC 8936 JSON body".into(),
            })
        })?
    };
    let max_events = match request.max_events {
        None => POLL_MAX_EVENTS_PER_RESPONSE,
        Some(n) if n < 0 => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "maxEvents must not be negative".into(),
            }));
        }
        Some(n) => usize::try_from(n)
            .unwrap_or(POLL_MAX_EVENTS_PER_RESPONSE)
            .min(POLL_MAX_EVENTS_PER_RESPONSE),
    };
    if request.ack.len() > POLL_MAX_ACKS || request.set_errs.len() > POLL_MAX_SET_ERRS {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "a poll request carries at most {POLL_MAX_ACKS} ack and {POLL_MAX_SET_ERRS} \
                 setErrs entries"
            ),
        }));
    }

    // 1. Acknowledgements: exactly the named rows of this stream.
    let acked: Vec<String> = request
        .ack
        .into_iter()
        .filter(|jti| jti.len() <= MAX_JTI_BYTES)
        .collect();
    state
        .ssf
        .buffer_repo
        .delete_by_jti(receiver.tenant_id, stream.id, &acked)
        .await?;

    // 2. Errors the receiver reports: each row is deleted (the receiver will not
    //    accept that SET, so offering it again is pointless) and audited.
    for (jti, reported) in request.set_errs {
        if jti.len() > MAX_JTI_BYTES {
            continue;
        }
        let removed = state
            .ssf
            .buffer_repo
            .delete_by_jti(receiver.tenant_id, stream.id, std::slice::from_ref(&jti))
            .await?;
        audit_receiver(
            &state,
            &http_req,
            &receiver,
            AUDIT_POLL_SET_ERROR,
            stream.id,
            serde_json::json!({
                "jti": jti,
                "err": audited_err_code(&reported.err),
                "held": removed > 0,
            }),
        )
        .await;
    }

    // 3. The next SETs. Nothing from a stream that is not enabled; max 0 asks
    //    for acknowledgements only.
    if stream.status != SsfStreamStatus::Enabled || max_events == 0 {
        return Ok(empty_poll_response());
    }
    let return_immediately = request.return_immediately.unwrap_or(false);
    let started = std::time::Instant::now();
    // D-53 (11): one waiting long poll per stream per instance. The slot is
    // taken the first time this request would wait, and released when it
    // returns or is dropped; a request that finds it taken answers at once.
    let mut wait_slot: Option<crate::state::bundles::PollWaitGuard> = None;
    // A key that cannot sign stays unusable for the rest of a long poll, which
    // looks at the buffer every half second: it is reported once per request,
    // not once per look (F4 W4 P23W4-03).
    let mut signing_failure_logged = false;
    loop {
        // D-55 at signing, on every look: a gate that started to hold while
        // this poll waited signs nothing.
        let issuer = state.ssf.gate.check().await?;
        let held = state
            .ssf
            .buffer_repo
            .list_oldest(receiver.tenant_id, stream.id, max_events + 1, Utc::now())
            .await?;
        if !held.is_empty() {
            let more_available = held.len() > max_events;
            let mut sets = serde_json::Map::new();
            let mut unsignable: Vec<String> = Vec::new();
            for pending in held.iter().take(max_events) {
                match sign_set(&state.auth_config, issuer, &stream, pending) {
                    Ok(set) => {
                        sets.insert(pending.jti.clone(), serde_json::Value::String(set));
                    }
                    // A key that cannot sign is the operator's to fix; the event
                    // stays for the next poll.
                    Err(SsfError::Signing(_)) => {
                        if !signing_failure_logged {
                            signing_failure_logged = true;
                            tracing::error!(target: "axiam::ssf", stream_id = %stream.id, "a held SSF event could not be signed");
                        }
                    }
                    // D-55 started to hold while this poll waited: nothing is
                    // signed, and the poll answers as a switched-off stream.
                    Err(SsfError::SharedIssuer) => return Err(no_such_stream()),
                    // The stream no longer carries it (narrowed meanwhile) or it
                    // can never be signed for this stream: drop it.
                    Err(_) => unsignable.push(pending.jti.clone()),
                }
            }
            if !unsignable.is_empty() {
                state
                    .ssf
                    .buffer_repo
                    .delete_by_jti(receiver.tenant_id, stream.id, &unsignable)
                    .await?;
            }
            if !sets.is_empty() || return_immediately {
                return Ok(no_store(HttpResponse::Ok()).json(SsfPollResponse {
                    sets,
                    more_available,
                }));
            }
        }
        if return_immediately || started.elapsed() >= POLL_LONG_POLL_MAX {
            return Ok(empty_poll_response());
        }
        if wait_slot.is_none() {
            wait_slot = state.ssf.poll_waiters.try_enter(stream.id);
            if wait_slot.is_none() {
                return Ok(empty_poll_response());
            }
        }
        // `saturating_sub`: the 30 s may have run out since the check above, and
        // a `Duration` subtraction that underflows panics.
        tokio::time::sleep(
            POLL_WAIT_STEP.min(POLL_LONG_POLL_MAX.saturating_sub(started.elapsed())),
        )
        .await;
        // The stream as it is now: paused, disabled or gone while waiting.
        stream = owned_stream(&state, &receiver, Some(&raw_id)).await?;
        if stream.status != SsfStreamStatus::Enabled {
            return Ok(empty_poll_response());
        }
    }
}
