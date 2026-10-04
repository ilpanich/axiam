//! The SSF stream registry's management routes (G-5, T23.5.2, contract §31).
//!
//! Five routes under `/api/v1/tenants/{tenant_id}/ssf/streams`, in the `ssf`
//! OpenAPI tag and the management registry. A stream is **registered by an
//! administrator**, never by a receiver: this is where the receiver binding,
//! the audience, the event ceiling, the subject format and the delivery method
//! are decided — everything a receiver cannot change on the SSF stream
//! management API (`handlers::ssf`). The routes work whatever the tenant's
//! `ssf_enabled` says: an administrator registers streams before switching the
//! transmitter on (D-45, the D-42 reasoning).
//!
//! # What every write does, in this order
//!
//! 1. the permission (`ssf_streams:read` / `ssf_streams:write`, a human-only
//!    family, so a service-account token is `401` at the extractor) and the
//!    tenant fence (`403`);
//! 2. the value rules (`400`, each naming its rule, never echoing a header or a
//!    URL): audience, description, the delivery method and its endpoint under
//!    the outbound address policy, the push header, the events ceiling and the
//!    receiver's subset, the status reason; then the binding: the receiver
//!    client must exist in the tenant, hold the `client_credentials` grant and
//!    be registered with the `ssf.manage` scope;
//! 3. `503` when a push header is to be stored and `pki_encryption_key` is not
//!    configured;
//! 4. the write, with a reused audience — in **any** tenant — as `409` (D-47);
//! 5. one audit row with the **names** of what changed, never the header;
//! 6. on a status change, a stream-updated event to the receiver (SSF §8.1.5),
//!    when the outbox is wired.

use actix_web::error::JsonPayloadError;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::ssf::{
    NewSsfStream, SSF_MANAGE_SCOPE, SecretChange, SsfDeliveryMethod, SsfEventType, SsfStatusActor,
    SsfStream as StoredStream, SsfStreamStatus, SsfStreamUpdate, SsfSubjectFormat, canonical,
};
use axiam_core::repository::{
    AuditLogRepository, OAuth2ClientRepository, PaginatedResult, Pagination, SsfStreamRepository,
};
use axiam_oauth2::ssf::{
    prepare_stream_updated, validate_audience, validate_authorization_header, validate_description,
    validate_push_endpoint, validate_status_reason,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// Audit action: a stream was registered.
pub const AUDIT_STREAM_CREATED: &str = "ssf_stream.created";
/// Audit action: an administrator replaced a stream's configuration.
pub const AUDIT_STREAM_UPDATED: &str = "ssf_stream.updated";
/// Audit action: a stream was deleted.
pub const AUDIT_STREAM_DELETED: &str = "ssf_stream.deleted";

const BODY_LIMIT: usize = 32_768;

// ---------------------------------------------------------------------------
// Shapes (CONTRACT §31.2)
// ---------------------------------------------------------------------------

/// A registered SSF stream, as the management API returns it. **The push
/// `Authorization` header is never returned**; `authorization_header_set` says
/// whether one is stored.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SsfStream {
    /// The stream id, also the SSF `stream_id`.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The OAuth2 `client_id` whose client-credentials token (scope
    /// `ssf.manage`) is this stream's receiver on the stream management API.
    pub receiver_client_id: String,
    /// The SET `aud`. Unique across the deployment.
    pub audience: String,
    /// A description.
    pub description: Option<String>,
    /// `push` (RFC 8935) or `poll` (RFC 8936).
    pub delivery_method: SsfDeliveryMethod,
    /// The push endpoint, or null for a poll stream.
    pub endpoint_url: Option<String>,
    /// Whether a push `Authorization` header is stored.
    pub authorization_header_set: bool,
    /// The event types the receiver may have.
    pub events_allowed: Vec<SsfEventType>,
    /// The event types the receiver asked for (a subset of `events_allowed`).
    pub events_requested: Vec<SsfEventType>,
    /// What the stream carries: the intersection of the two.
    pub events_delivered: Vec<SsfEventType>,
    /// `iss_sub` (default) or `email`.
    pub subject_format: SsfSubjectFormat,
    /// `enabled`, `paused` or `disabled`.
    pub status: SsfStreamStatus,
    /// Why, if anyone said.
    pub status_reason: Option<String>,
    /// Who set the status: `admin` or `receiver`.
    pub status_actor: SsfStatusActor,
    /// When the receiver last asked for a verification event, or null.
    pub last_verification_at: Option<DateTime<Utc>>,
    /// When the stream was registered.
    pub created_at: DateTime<Utc>,
    /// When it was last written.
    pub updated_at: DateTime<Utc>,
}

impl From<StoredStream> for SsfStream {
    fn from(s: StoredStream) -> Self {
        let events_delivered = s.events_delivered();
        Self {
            id: s.id,
            tenant_id: s.tenant_id,
            receiver_client_id: s.receiver_client_id,
            audience: s.audience,
            description: s.description,
            delivery_method: s.delivery_method,
            endpoint_url: s.endpoint_url,
            authorization_header_set: s.authorization_header_set,
            events_allowed: s.events_allowed,
            events_requested: s.events_requested,
            events_delivered,
            subject_format: s.subject_format,
            status: s.status,
            status_reason: s.status_reason,
            status_actor: s.status_actor,
            last_verification_at: s.last_verification_at,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

fn default_status() -> SsfStreamStatus {
    SsfStreamStatus::Enabled
}

/// `create_stream` and `update_stream` (a **replacement**) body.
#[derive(Clone, Deserialize, utoipa::ToSchema)]
pub struct SsfStreamInput {
    /// An OAuth2 client of the tenant with the `client_credentials` grant and
    /// the `ssf.manage` scope.
    pub receiver_client_id: String,
    /// 1–512 bytes; unique across the deployment.
    pub audience: String,
    /// At most 256 bytes.
    #[serde(default)]
    pub description: Option<String>,
    /// `push` or `poll`.
    pub delivery_method: SsfDeliveryMethod,
    /// Required for `push` (an `https` URL under the outbound address policy),
    /// refused for `poll`.
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// **Write-only.** The `Authorization` header value AXIAM sends to a push
    /// endpoint. On update, absent keeps the stored one — except that moving
    /// the endpoint to another origin requires it again.
    #[serde(default)]
    pub authorization_header: Option<String>,
    /// On update: remove the stored header. Refused together with
    /// `authorization_header`.
    #[serde(default)]
    pub clear_authorization_header: bool,
    /// 1–6 event types.
    pub events_allowed: Vec<SsfEventType>,
    /// A subset of `events_allowed`; absent means all of them. The receiver may
    /// narrow it later, never widen it.
    #[serde(default)]
    pub events_requested: Option<Vec<SsfEventType>>,
    /// `iss_sub` by default.
    #[serde(default)]
    pub subject_format: SsfSubjectFormat,
    /// `enabled` by default.
    #[serde(default = "default_status")]
    pub status: SsfStreamStatus,
    /// At most 256 bytes.
    #[serde(default)]
    pub status_reason: Option<String>,
}

/// `Debug` names the header's presence and nothing else.
impl std::fmt::Debug for SsfStreamInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfStreamInput")
            .field("receiver_client_id", &self.receiver_client_id)
            .field("audience", &self.audience)
            .field("delivery_method", &self.delivery_method)
            .field("endpoint_url", &self.endpoint_url)
            .field(
                "authorization_header",
                &self.authorization_header.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "clear_authorization_header",
                &self.clear_authorization_header,
            )
            .field("events_allowed", &self.events_allowed)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validation(message: impl Into<String>) -> AxiamApiError {
    AxiamApiError(AxiamError::Validation {
        message: message.into(),
    })
}

/// The JSON configuration of the routes: a body limit and a `400` that never
/// quotes the body (it may hold the header).
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().limit(BODY_LIMIT).error_handler(
        |err: JsonPayloadError, _req: &HttpRequest| {
            let message = match err {
                JsonPayloadError::Deserialize(inner) => format!(
                    "the request body is not a valid SSF stream: {}",
                    super::directory::scrub_serde_message(&inner.to_string())
                ),
                JsonPayloadError::ContentType => {
                    "the request body must be application/json".to_string()
                }
                JsonPayloadError::Overflow { .. }
                | JsonPayloadError::OverflowKnownLength { .. } => {
                    "the request body is too large".to_string()
                }
                _ => "the request body could not be read".to_string(),
            };
            AxiamApiError(AxiamError::Validation { message }).into()
        },
    )
}

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

/// The input's values, checked; the events in canonical order.
struct Checked {
    events_allowed: Vec<SsfEventType>,
    events_requested: Vec<SsfEventType>,
    header: Option<Zeroizing<String>>,
}

fn check_values(input: &SsfStreamInput) -> Result<Checked, AxiamApiError> {
    if input.receiver_client_id.trim().is_empty() {
        return Err(validation("receiver_client_id is required"));
    }
    validate_audience(&input.audience).map_err(validation)?;
    if let Some(text) = &input.description {
        validate_description(text).map_err(validation)?;
    }
    if let Some(reason) = &input.status_reason {
        validate_status_reason(reason).map_err(validation)?;
    }
    match input.delivery_method {
        SsfDeliveryMethod::Push => {
            let url = input
                .endpoint_url
                .as_deref()
                .ok_or_else(|| validation("a push stream needs an endpoint_url"))?;
            validate_push_endpoint(url).map_err(validation)?;
        }
        SsfDeliveryMethod::Poll => {
            if input.endpoint_url.is_some() {
                return Err(validation(
                    "a poll stream has no endpoint_url: AXIAM serves its poll endpoint",
                ));
            }
            if input.authorization_header.is_some() {
                return Err(validation("a poll stream has no authorization_header"));
            }
        }
    }
    if input.authorization_header.is_some() && input.clear_authorization_header {
        return Err(validation(
            "authorization_header and clear_authorization_header cannot be sent together",
        ));
    }
    let header = match &input.authorization_header {
        Some(value) => {
            validate_authorization_header(value).map_err(validation)?;
            Some(Zeroizing::new(value.clone()))
        }
        None => None,
    };
    if input.events_allowed.is_empty() {
        return Err(validation(
            "events_allowed must name at least one event type",
        ));
    }
    let events_allowed = canonical(&input.events_allowed);
    let events_requested = match &input.events_requested {
        None => events_allowed.clone(),
        Some(requested) => {
            if requested.iter().any(|e| !events_allowed.contains(e)) {
                return Err(validation(
                    "events_requested must be a subset of events_allowed",
                ));
            }
            canonical(requested)
        }
    };
    Ok(Checked {
        events_allowed,
        events_requested,
        header,
    })
}

/// The receiver binding (D-50): a client of this tenant that can obtain a
/// client-credentials token carrying `ssf.manage`.
async fn check_receiver_client<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    client_id: &str,
) -> Result<(), AxiamApiError> {
    let client = match state
        .oauth2_client_repo
        .get_by_client_id(tenant_id, client_id)
        .await
    {
        Ok(client) => client,
        Err(AxiamError::NotFound { .. }) => {
            return Err(validation(
                "receiver_client_id is not an OAuth2 client of this tenant",
            ));
        }
        Err(other) => return Err(AxiamApiError(other)),
    };
    if !client.grant_types.iter().any(|g| g == "client_credentials") {
        return Err(validation(
            "the receiver client must be registered for the client_credentials grant",
        ));
    }
    if !client.scopes.iter().any(|s| s == SSF_MANAGE_SCOPE) {
        return Err(validation(format!(
            "the receiver client must be registered with the '{SSF_MANAGE_SCOPE}' scope"
        )));
    }
    Ok(())
}

fn audience_conflict(error: AxiamError) -> AxiamApiError {
    match error {
        AxiamError::AlreadyExists { .. } => AxiamApiError(AxiamError::Conflict {
            reason: "this audience is already used by an SSF stream".into(),
        }),
        other => AxiamApiError(other),
    }
}

fn need_sealing<C: Connection + Clone>(
    state: &AppState<C>,
    sets_header: bool,
) -> Result<(), AxiamApiError> {
    if sets_header && !state.ssf.stream_repo.has_encryption_key() {
        return Err(AxiamApiError(AxiamError::ServiceUnavailable(
            "a push authorization header cannot be stored: pki_encryption_key \
             (AXIAM__AUTH__PKI_ENCRYPTION_KEY) is not configured"
                .into(),
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // an audit row is this wide
async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    user: &AuthenticatedUser,
    tenant_id: Uuid,
    action: &str,
    resource_id: Option<Uuid>,
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
            outcome: AuditOutcome::Success,
            ip_address: client_ip(http_req),
            metadata: Some(metadata),
        })
        .await
    {
        tracing::error!(
            target: "axiam::ssf_admin",
            %tenant_id,
            action,
            %error,
            "an SSF registry audit row could not be written"
        );
    }
}

/// The names of the members an administrator's update changes. Names only.
fn changed_fields(old: &StoredStream, new: &SsfStreamUpdate) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut note = |differs: bool, name: &'static str| {
        if differs {
            out.push(name);
        }
    };
    note(
        old.receiver_client_id != new.receiver_client_id,
        "receiver_client_id",
    );
    note(old.audience != new.audience, "audience");
    note(old.description != new.description, "description");
    note(
        old.delivery_method != new.delivery_method,
        "delivery_method",
    );
    note(old.endpoint_url != new.endpoint_url, "endpoint_url");
    note(
        !matches!(new.authorization_header, SecretChange::Keep),
        "authorization_header",
    );
    note(old.events_allowed != new.events_allowed, "events_allowed");
    note(
        old.events_requested != new.events_requested,
        "events_requested",
    );
    note(old.subject_format != new.subject_format, "subject_format");
    note(old.status != new.status, "status");
    note(old.status_reason != new.status_reason, "status_reason");
    out
}

/// SSF §8.1.5: a transmitter that changes a stream's status tells the
/// receiver. Best effort: the change is made whether or not the event can be
/// submitted, and a missing outbox (delivery not wired) is not an error here.
pub(crate) async fn announce_status<C: Connection + Clone>(
    state: &AppState<C>,
    stream: &StoredStream,
) {
    let Some(outbox) = state.ssf.outbox.as_ref() else {
        return;
    };
    let event = prepare_stream_updated(stream, Utc::now());
    if let Err(error) = outbox.submit(stream, &event).await {
        tracing::warn!(
            target: "axiam::ssf_admin",
            tenant_id = %stream.tenant_id,
            stream_id = %stream.id,
            %error,
            "the stream-updated event could not be submitted"
        );
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/ssf/streams`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/ssf/streams",
    tag = "ssf",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID"), Pagination),
    responses(
        (status = 200, description = "A page of the tenant's SSF streams, oldest first; `search` \
                                      matches audience, receiver client id, description and id, \
                                      before paging",
         body = inline(PaginatedResult<SsfStream>)),
        (status = 403, description = "Another tenant's registry"),
    ),
    security(("bearer" = []))
)]
pub async fn list_streams<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ssf_streams:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "list SSF streams")?;
    let page = state
        .ssf
        .stream_repo
        .list_page(tenant_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items: page.items.into_iter().map(SsfStream::from).collect(),
        total: page.total,
        offset: page.offset,
        limit: page.limit,
    }))
}

/// `POST /api/v1/tenants/{tenant_id}/ssf/streams`
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/ssf/streams",
    tag = "ssf",
    params(("tenant_id" = Uuid, Path, description = "Tenant ID")),
    request_body = SsfStreamInput,
    responses(
        (status = 201, description = "The stream was registered", body = SsfStream),
        (status = 400, description = "A value rule or the receiver binding — the message names the \
                                      rule"),
        (status = 403, description = "Another tenant's registry"),
        (status = 409, description = "The audience is already used by an SSF stream"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "A push authorization header was given and the deployment \
                                      cannot seal it"),
    ),
    security(("bearer" = []))
)]
pub async fn create_stream<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<SsfStreamInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ssf_streams:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    require_own_tenant(&user, tenant_id, "register an SSF stream")?;
    let input = body.into_inner();
    if input.clear_authorization_header {
        return Err(validation(
            "clear_authorization_header applies to an update only",
        ));
    }
    let checked = check_values(&input)?;
    check_receiver_client(&state, tenant_id, &input.receiver_client_id).await?;
    need_sealing(&state, checked.header.is_some())?;

    let created = state
        .ssf
        .stream_repo
        .create(NewSsfStream {
            tenant_id,
            receiver_client_id: input.receiver_client_id,
            audience: input.audience,
            description: input.description.filter(|d| !d.is_empty()),
            delivery_method: input.delivery_method,
            endpoint_url: input.endpoint_url,
            authorization_header: checked.header,
            events_allowed: checked.events_allowed,
            events_requested: checked.events_requested,
            subject_format: input.subject_format,
            status: input.status,
            status_reason: input.status_reason,
        })
        .await
        .map_err(audience_conflict)?;

    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_STREAM_CREATED,
        Some(created.id),
        serde_json::json!({
            "receiver_client_id": created.receiver_client_id,
            "delivery_method": created.delivery_method.as_str(),
            "subject_format": created.subject_format.as_str(),
            "status": created.status.as_str(),
            "events_allowed": SsfEventType::uris(&created.events_allowed),
            "authorization_header_set": created.authorization_header_set,
        }),
    )
    .await;
    Ok(HttpResponse::Created().json(SsfStream::from(created)))
}

/// `GET /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}",
    tag = "ssf",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("stream_id" = Uuid, Path, description = "Stream ID"),
    ),
    responses(
        (status = 200, description = "The stream", body = SsfStream),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such stream in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn get_stream<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ssf_streams:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, stream_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "read an SSF stream")?;
    let stream = state.ssf.stream_repo.get(tenant_id, stream_id).await?;
    Ok(HttpResponse::Ok().json(SsfStream::from(stream)))
}

/// `PUT /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}` — a
/// **replacement**: an omitted optional member takes its default, except the
/// header, which absent keeps.
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}",
    tag = "ssf",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("stream_id" = Uuid, Path, description = "Stream ID"),
    ),
    request_body = SsfStreamInput,
    responses(
        (status = 200, description = "The stream's new configuration", body = SsfStream),
        (status = 400, description = "A value rule, the receiver binding, or a move of the push \
                                      endpoint to another origin without the authorization header"),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such stream in this tenant"),
        (status = 409, description = "The audience is already used by another SSF stream"),
        (status = 429, description = "Rate limit"),
        (status = 503, description = "A push authorization header was given and the deployment \
                                      cannot seal it"),
    ),
    security(("bearer" = []))
)]
pub async fn update_stream<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
    body: web::Json<SsfStreamInput>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ssf_streams:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, stream_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "replace an SSF stream")?;
    let input = body.into_inner();
    let checked = check_values(&input)?;
    let old = state.ssf.stream_repo.get(tenant_id, stream_id).await?;
    if input.receiver_client_id != old.receiver_client_id {
        check_receiver_client(&state, tenant_id, &input.receiver_client_id).await?;
    }

    let header = match (checked.header, input.clear_authorization_header) {
        (Some(value), _) => SecretChange::Set(value),
        (None, true) => SecretChange::Clear,
        (None, false) if input.delivery_method == SsfDeliveryMethod::Poll => SecretChange::Clear,
        (None, false) => SecretChange::Keep,
    };
    // D-49: a stored credential never follows the endpoint to another origin
    // unless it is supplied again (or explicitly cleared).
    if old.authorization_header_set && matches!(header, SecretChange::Keep) {
        let previous = old.endpoint_url.as_deref().unwrap_or_default();
        let next = input.endpoint_url.as_deref().unwrap_or_default();
        if !axiam_oauth2::ssf::same_origin(previous, next) {
            return Err(validation(
                "moving the push endpoint to another origin requires the authorization_header \
                 again (or clear_authorization_header)",
            ));
        }
    }
    need_sealing(&state, matches!(header, SecretChange::Set(_)))?;

    let status_actor = if input.status == old.status {
        old.status_actor
    } else {
        SsfStatusActor::Admin
    };
    let update = SsfStreamUpdate {
        receiver_client_id: input.receiver_client_id,
        audience: input.audience,
        description: input.description.filter(|d| !d.is_empty()),
        delivery_method: input.delivery_method,
        endpoint_url: input.endpoint_url,
        authorization_header: header,
        events_allowed: checked.events_allowed,
        events_requested: checked.events_requested,
        subject_format: input.subject_format,
        status: input.status,
        status_reason: input.status_reason,
        status_actor,
    };
    let changed = changed_fields(&old, &update);
    let updated = state
        .ssf
        .stream_repo
        .update(tenant_id, stream_id, update)
        .await
        .map_err(audience_conflict)?;

    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_STREAM_UPDATED,
        Some(stream_id),
        serde_json::json!({ "changed": changed, "status": updated.status.as_str() }),
    )
    .await;
    if updated.status != old.status {
        announce_status(&state, &updated).await;
    }
    Ok(HttpResponse::Ok().json(SsfStream::from(updated)))
}

/// `DELETE /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}` — the stream
/// and its buffered events.
#[utoipa::path(
    delete,
    path = "/api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}",
    tag = "ssf",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("stream_id" = Uuid, Path, description = "Stream ID"),
    ),
    responses(
        (status = 204, description = "The stream and its buffered events were deleted"),
        (status = 403, description = "Another tenant's registry"),
        (status = 404, description = "No such stream in this tenant"),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_stream<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ssf_streams:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let (tenant_id, stream_id) = path.into_inner();
    require_own_tenant(&user, tenant_id, "delete an SSF stream")?;
    state.ssf.stream_repo.delete(tenant_id, stream_id).await?;
    audit(
        &state,
        &http_req,
        &user,
        tenant_id,
        AUDIT_STREAM_DELETED,
        Some(stream_id),
        serde_json::json!({}),
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}
