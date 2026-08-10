//! Reactor management endpoints (X1).
//!
//! A registration decides whether third-party code can veto a login or add a
//! claim to a token, so every write goes through
//! [`axiam_core::models::reactor::validate_registration`] against the same
//! `EVENT_REGISTRY` the dispatcher reads. Restating the valid event set here
//! would create a second source of truth, and the one that drifted would be
//! whichever nobody was looking at.

use actix_web::{HttpResponse, web};
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
}

impl From<Reactor> for ReactorResponse {
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
        }
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

    // Validate the timeout that will actually be stored, not the one the
    // request happened to carry — an omitted value still has to be in range,
    // and a default that was not is a bug worth catching here.
    let timeout_ms = req.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    validate_registration(&req.name, &req.events, req.mode, timeout_ms)
        .map_err(|e| validation_err(e.to_string()))?;

    let reactor = state
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
        .reactor_repo
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(ReactorResponse::from)
            .collect(),
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
        .reactor_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(ReactorResponse::from(reactor)))
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
    let current = state.reactor_repo.get_by_id(user.tenant_id, id).await?;
    let merged_name = req.name.clone().unwrap_or_else(|| current.name.clone());
    let merged_events = req.events.clone().unwrap_or_else(|| current.events.clone());
    let merged_mode = req.mode.unwrap_or(current.mode);
    let merged_timeout = req.timeout_ms.unwrap_or(current.timeout_ms);

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
        .reactor_repo
        .delete(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}
