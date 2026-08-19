//! Reactor management endpoints (X1).
//!
//! A registration decides whether third-party code can veto a login or add a
//! claim to a token, so every write goes through
//! [`axiam_core::models::reactor::validate_registration`] against the same
//! `EVENT_REGISTRY` the dispatcher reads. Restating the valid event set here
//! would create a second source of truth, and the one that drifted would be
//! whichever nobody was looking at.

use actix_web::{HttpResponse, web};
use axiam_amqp::reactor::gate::{
    DEFAULT_HEALTH_FAILURE_SAMPLE_LIMIT, DEFAULT_HEALTH_LOOKBACK_HOURS, ReactorHealth,
    recent_health,
};
use axiam_core::models::reactor::{
    CreateReactor, DEFAULT_TIMEOUT_MS, EVENT_REGISTRY, FailurePolicy, Reactor, ReactorMode,
    UpdateReactor, default_failure_policy_for, validate_registration,
};
use axiam_core::repository::{PaginatedResult, Pagination, ReactorRepository};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Per-reactor health (R2.3)
// ---------------------------------------------------------------------------
//
// R2.2 started writing `ChainResult.failures` and a chain-level deny to the
// audit trail; `axiam_amqp::reactor::gate::recent_health` is where that
// finally becomes visible to an operator, in the same response the admin
// console already renders `last_seen_at` from. It is shared with the gRPC
// admin service (`axiam-api-grpc`'s `ReactorAdminServiceImpl`) rather than
// duplicated, so the two transports report the same numbers from the same
// query.

/// Read one reactor's health using this handler's fixed lookback + sample
/// size — a thin wrapper so call sites below read `reactor_health(..)`
/// rather than the longer shared-function call with its two tuning
/// parameters repeated at every site.
async fn reactor_health<A: axiam_core::repository::AuditLogRepository>(
    audit_repo: &A,
    tenant_id: Uuid,
    reactor_id: Uuid,
) -> ReactorHealth {
    recent_health(
        audit_repo,
        tenant_id,
        reactor_id,
        chrono::Duration::hours(DEFAULT_HEALTH_LOOKBACK_HOURS),
        DEFAULT_HEALTH_FAILURE_SAMPLE_LIMIT,
    )
    .await
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateReactorRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Event names from the registry (`GET /api/v1/reactors/events`).
    pub events: Vec<String>,
    pub mode: ReactorMode,
    #[serde(default)]
    pub priority: i32,
    /// Omit to take the 500 ms default. Capped at 5 000 ms.
    pub timeout_ms: Option<u32>,
    /// Omit to take the strictest default among `events`.
    pub failure_policy: Option<FailurePolicy>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub struct UpdateReactorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub events: Option<Vec<String>>,
    pub mode: Option<ReactorMode>,
    pub priority: Option<i32>,
    pub timeout_ms: Option<u32>,
    pub failure_policy: Option<FailurePolicy>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ReactorResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: String,
    pub events: Vec<String>,
    pub mode: ReactorMode,
    pub priority: i32,
    pub timeout_ms: u32,
    pub failure_policy: FailurePolicy,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When this reactor last consumed from its queue. `null` means it has
    /// never connected — which the admin UI shows differently from "connected
    /// once, silent since".
    pub last_seen_at: Option<DateTime<Utc>>,
    /// R2.3: dispatch failures against this registration in the last 24h
    /// whose cause was a timeout (as opposed to a rejected reply, a transport
    /// failure, or overload), capped at 100 — a health signal read from the
    /// audit trail R2.2 started writing, not a replacement for the audit log
    /// itself (`GET /api/v1/audit-log` is that).
    pub recent_timeout_count: u32,
    /// R2.3: operations this reactor's own reply *denied* in the last 24h,
    /// capped at 100. Distinct from `recent_timeout_count`: a veto is the
    /// reactor working as designed; a timeout is the reactor not answering.
    pub recent_veto_count: u32,
}

impl From<Reactor> for ReactorResponse {
    /// Health defaults to zero. Call sites that have an audit repository in
    /// scope (`list`, `get`) overwrite it via [`ReactorResponse::with_health`]
    /// — a freshly created or just-updated reactor has nothing in the
    /// lookback window to report anyway, so `create`/`update`/`delete` do not
    /// pay the extra audit-trail round trips.
    fn from(r: Reactor) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            description: r.description,
            events: r.events,
            mode: r.mode,
            priority: r.priority,
            timeout_ms: r.timeout_ms,
            failure_policy: r.failure_policy,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
            last_seen_at: r.last_seen_at,
            recent_timeout_count: 0,
            recent_veto_count: 0,
        }
    }
}

impl ReactorResponse {
    fn with_health(mut self, health: ReactorHealth) -> Self {
        self.recent_timeout_count = health.recent_timeout_count;
        self.recent_veto_count = health.recent_veto_count;
        self
    }
}

/// One hookable event, as the registry describes it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ReactorEventDescriptor {
    pub name: String,
    pub interceptable: bool,
    pub mutable: bool,
    /// Exact field names, or a namespace prefix ending in `.` — `ext.` admits
    /// `ext.department` and nothing outside the namespace.
    pub mutable_fields: Vec<String>,
    pub default_failure_policy: FailurePolicy,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// SEC-101 — refuse a registration that could never be delivered to.
///
/// Two independent reasons, both of which make an accepted registration a
/// lie, and both of which are checked before anything is validated or written.
///
/// # 1. The composed transport cannot dispatch at all
///
/// Registering a reactor against a transport that fails every dispatch is a
/// **self-service, tenant-wide, complete login outage**: `login.post_auth`,
/// `user.pre_create`, `user.pre_update` and `grant.pre_assign` all default to
/// `fail_closed`, so the first login after the registration is denied and so
/// is every one after that. The only thing standing between an operator and
/// that would be one `tracing::warn!` emitted once at boot — for every
/// deployment, including the overwhelming majority that will never register a
/// reactor, which is how a warning becomes a line that is filtered out. The
/// action that causes the outage happens hours or weeks later, in an admin UI
/// that gives no indication anything is wrong.
///
/// The fail-closed posture itself is correct and is not changed here: a
/// registered fail-closed fraud check that silently did nothing would be
/// worse, and is the failure mode reactors exist to prevent. What changes is
/// *when* the operator is told — at the point of the action, in the response
/// to it, instead of in a boot log.
///
/// Since R2.4 merged the lapin transport this arm no longer fires for
/// `axiam-server`, which composes a transport that reports `can_dispatch()`.
/// It is **not** dead: `can_dispatch` reports the transport's capability, and
/// a build that composes `UnavailableReactorTransport` (or `NoopReactorGate`)
/// still answers `false`. It deliberately does **not** fire on a broker
/// outage — see `ReactorTransport::can_dispatch`'s doc for why a blip must not
/// become a registration outage.
///
/// # 2. The registration is `listen`, whose fan-out has no caller
///
/// `ReactorTransport::publish_listen` is implemented by the lapin transport,
/// but nothing calls it: `run_chain` filters listeners out and
/// `DispatchingReactorGate::intercept` returns early once the interceptor list
/// is empty. A `listen` registration would therefore receive nothing at all —
/// the inverse of its contract, and a silent one, since a listener produces no
/// outcome to notice its absence in. Refusing is the honest answer until the
/// gate grows the fan-out.
///
/// # Why 503, and why only enabled registrations
///
/// 503 rather than 400: nothing is wrong with the request. The dependency the
/// resource needs is absent from this build, which is exactly what
/// `AxiamError::ServiceUnavailable` means everywhere else in AXIAM.
/// `would_be_enabled` is the merged result, not the request: an operator must
/// always be able to **disable** or delete a registration, especially when the
/// transport is missing, so only a write that would leave an enabled
/// registration in place is refused. `DELETE` is never refused for the same
/// reason.
fn require_dispatchable_transport<C: Connection + Clone>(
    state: &AppState<C>,
    would_be_enabled: bool,
    mode: ReactorMode,
) -> Result<(), AxiamApiError> {
    use axiam_core::models::reactor::ReactorGate;

    if !would_be_enabled {
        return Ok(());
    }

    if !state.events.reactor_gate.can_dispatch() {
        return Err(axiam_core::error::AxiamError::ServiceUnavailable(
            "the AMQP reactor transport is not available in this build, so a registered \
             reactor could never be reached. Registering one would apply its failure_policy \
             to every dispatch instead — and login.post_auth, user.pre_create, \
             user.pre_update and grant.pre_assign all default to fail_closed, so the \
             registration would deny those operations for this tenant. Refusing rather than \
             accepting a registration that causes an outage."
                .into(),
        )
        .into());
    }

    if mode == ReactorMode::Listen {
        return Err(axiam_core::error::AxiamError::ServiceUnavailable(
            "listen-mode reactors are not dispatched to yet: the transport can publish a \
             listen event, but no hook site fans out to listeners, so this registration \
             would receive nothing and — being a listener — would produce no outcome in \
             which you could notice. Register the reactor with mode 'intercept', or create \
             it with enabled: false until the listener fan-out ships."
                .into(),
        )
        .into());
    }

    Ok(())
}

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

/// `GET /api/v1/reactors/events` — the registry, verbatim.
///
/// Served rather than documented so an admin UI, an SDK generator and an
/// operator all read the same list the dispatcher enforces. A hand-maintained
/// copy in the docs is a copy that goes stale on the next hook added.
#[utoipa::path(
    get,
    path = "/api/v1/reactors/events",
    tag = "reactors",
    responses(
        (status = 200, description = "Hookable events", body = Vec<ReactorEventDescriptor>),
    ),
    security(("bearer" = []))
)]
pub async fn list_events<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    _state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let events: Vec<ReactorEventDescriptor> = EVENT_REGISTRY
        .iter()
        .map(|spec| ReactorEventDescriptor {
            name: spec.name.to_string(),
            interceptable: spec.interceptable,
            mutable: spec.mutable,
            mutable_fields: spec.mutable_fields.iter().map(|f| f.to_string()).collect(),
            default_failure_policy: spec.default_failure_policy,
            description: spec.description.to_string(),
        })
        .collect();

    Ok(HttpResponse::Ok().json(events))
}

/// `POST /api/v1/reactors`
#[utoipa::path(
    post,
    path = "/api/v1/reactors",
    tag = "reactors",
    request_body = CreateReactorRequest,
    responses(
        (status = 201, description = "Reactor registered", body = ReactorResponse),
        (status = 400, description = "Unknown event, non-interceptable event, or out-of-range timeout"),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateReactorRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();

    // SEC-101: before anything is validated or written.
    require_dispatchable_transport(state.get_ref(), req.enabled, req.mode)?;

    // Validate the timeout that will actually be stored, not the one the
    // request happened to carry — an omitted value still has to be in range,
    // and a default that was not is a bug worth catching here.
    let timeout_ms = req.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    validate_registration(&req.name, &req.events, req.mode, timeout_ms)
        .map_err(|e| validation_err(e.to_string()))?;

    let reactor = state
        .events
        .reactor_repo
        .create(CreateReactor {
            tenant_id: user.tenant_id,
            name: req.name,
            description: req.description,
            events: req.events,
            mode: req.mode,
            priority: req.priority,
            timeout_ms: Some(timeout_ms),
            failure_policy: req.failure_policy,
            enabled: req.enabled,
        })
        .await?;

    // X1 — the routing table this replica dispatches from is a TTL cache, so a
    // new registration would otherwise not fire for up to the TTL. Invalidate
    // the tenant's entries here so it is live at once; the TTL remains the
    // guarantee for every OTHER replica, which did not serve this request.
    state.invalidate_reactor_routing(user.tenant_id);

    Ok(HttpResponse::Created().json(ReactorResponse::from(reactor)))
}

/// `GET /api/v1/reactors`
#[utoipa::path(
    get,
    path = "/api/v1/reactors",
    tag = "reactors",
    params(Pagination),
    responses(
        (status = 200, description = "Registered reactors",
         body = inline(PaginatedResult<ReactorResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .events
        .reactor_repo
        .list(user.tenant_id, pagination.into_inner())
        .await?;

    // R2.3: one page of reactors is small (an admin console's page size, not
    // the event-path scale reactors themselves dispatch at), so a sequential
    // per-reactor health read is the honest cost of "current health" — the
    // alternative is a stale cached number a fail_closed veto going quiet
    // would not show up in promptly.
    let mut items = Vec::with_capacity(result.items.len());
    for reactor in result.items {
        let health = reactor_health(&state.audit_repo, user.tenant_id, reactor.id).await;
        items.push(ReactorResponse::from(reactor).with_health(health));
    }

    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

/// `GET /api/v1/reactors/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/reactors/{id}",
    tag = "reactors",
    params(("id" = Uuid, Path, description = "Reactor ID")),
    responses((status = 200, description = "Reactor found", body = ReactorResponse)),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let reactor = state
        .events
        .reactor_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
    let health = reactor_health(&state.audit_repo, user.tenant_id, reactor.id).await;
    Ok(HttpResponse::Ok().json(ReactorResponse::from(reactor).with_health(health)))
}

/// `PUT /api/v1/reactors/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/reactors/{id}",
    tag = "reactors",
    params(("id" = Uuid, Path, description = "Reactor ID")),
    request_body = UpdateReactorRequest,
    responses(
        (status = 200, description = "Reactor updated", body = ReactorResponse),
        (status = 400, description = "The merged registration is invalid"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
    body: web::Json<UpdateReactorRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let id = path.into_inner();
    let req = body.into_inner();

    // Validate the MERGED registration, not the request.
    //
    // A PUT that only sets `mode: intercept` is valid in isolation and
    // invalid against a stored `events` list containing a listen-only event.
    // Validating the request alone would let exactly that combination through
    // — the request names one field and the violation is in the pair.
    let current = state
        .events
        .reactor_repo
        .get_by_id(user.tenant_id, id)
        .await?;
    let merged_name = req.name.clone().unwrap_or_else(|| current.name.clone());
    let merged_events = req.events.clone().unwrap_or_else(|| current.events.clone());
    let merged_mode = req.mode.unwrap_or(current.mode);
    let merged_timeout = req.timeout_ms.unwrap_or(current.timeout_ms);
    let merged_enabled = req.enabled.unwrap_or(current.enabled);

    // SEC-101, on the merged result: an update that leaves the registration
    // enabled is refused while the transport cannot deliver, and one that
    // disables it is always allowed — that is the operator's way out.
    require_dispatchable_transport(state.get_ref(), merged_enabled, merged_mode)?;

    validate_registration(&merged_name, &merged_events, merged_mode, merged_timeout)
        .map_err(|e| validation_err(e.to_string()))?;

    // Changing the event set can change what the STORED failure_policy means.
    // If the caller replaces the events and does not name a policy, re-derive
    // it: a reactor that was enrichment-only (fail_open) and is now also
    // registered for `login.post_auth` must not keep passing when unreachable.
    let failure_policy = match (req.failure_policy, req.events.is_some()) {
        (Some(explicit), _) => Some(explicit),
        (None, true) => Some(default_failure_policy_for(&merged_events)),
        (None, false) => None,
    };

    let reactor = state
        .events
        .reactor_repo
        .update(
            user.tenant_id,
            id,
            UpdateReactor {
                name: req.name,
                description: req.description,
                events: req.events,
                mode: req.mode,
                priority: req.priority,
                timeout_ms: req.timeout_ms,
                failure_policy,
                enabled: req.enabled,
            },
        )
        .await?;

    state.invalidate_reactor_routing(user.tenant_id);

    Ok(HttpResponse::Ok().json(ReactorResponse::from(reactor)))
}

/// `DELETE /api/v1/reactors/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/reactors/{id}",
    tag = "reactors",
    params(("id" = Uuid, Path, description = "Reactor ID")),
    responses((status = 204, description = "Reactor deleted")),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("reactors:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    state
        .events
        .reactor_repo
        .delete(user.tenant_id, path.into_inner())
        .await?;

    // Deleting matters most of the three: an interceptor that no longer exists
    // must stop being dispatched to, and a `fail_closed` one that is still in
    // the routing table would deny every login it was registered for until the
    // TTL expired.
    state.invalidate_reactor_routing(user.tenant_id);

    Ok(HttpResponse::NoContent().finish())
}
