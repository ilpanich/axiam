//! `ReactorAdminService` gRPC implementation (X1 / R2.3).
//!
//! Mirrors `crates/axiam-api-rest/src/handlers/reactors.rs` field-for-field
//! and rule-for-rule: the same [`validate_registration`] against the same
//! `EVENT_REGISTRY`, the same merged-registration validation on update, the
//! same routing-table invalidation on every write, and the same
//! [`axiam_amqp::reactor::gate::recent_health`] call the REST handler uses —
//! so the two transports report identical numbers rather than each growing
//! its own copy of the health query that can drift from the other.
//!
//! Permission checks use the same action strings as the REST guard
//! (`reactors:list` / `reactors:create` / `reactors:get` / `reactors:update`
//! / `reactors:delete`, resource-scoped to the nil UUID — "global" reactor
//! management, same as REST's `RequirePermission::new(action, Uuid::nil())`)
//! against the same `AuthorizationEngine`, so a permission granted or denied
//! on one transport is granted or denied identically on the other.

use std::sync::Arc;

use axiam_amqp::reactor::gate::{
    DEFAULT_HEALTH_FAILURE_SAMPLE_LIMIT, DEFAULT_HEALTH_LOOKBACK_HOURS, ReactorHealth,
    recent_health,
};
use axiam_auth::token::ValidatedClaims;
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::AccessRequest;
use axiam_core::models::reactor::{
    CreateReactor, DEFAULT_TIMEOUT_MS, EVENT_REGISTRY, FailurePolicy, Reactor, ReactorMode,
    UpdateReactor, default_failure_policy_for, validate_registration,
};
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, Pagination, PermissionRepository, ReactorRepository,
    ResourceRepository, RoleRepository, ScopeRepository,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::proto::reactor_admin_service_server::ReactorAdminService;
use crate::proto::{
    CreateReactorRequest, CreateReactorResponse, DeleteReactorRequest, DeleteReactorResponse,
    GetReactorRequest, GetReactorResponse, ListReactorEventsRequest, ListReactorEventsResponse,
    ListReactorsRequest, ListReactorsResponse, ReactorEventDescriptor, ReactorResponse,
    UpdateReactorRequest, UpdateReactorResponse,
};

pub struct ReactorAdminServiceImpl<Rr, Rl, P, Res, S, G, A>
where
    Rr: ReactorRepository,
    Rl: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
    A: AuditLogRepository,
{
    reactor_repo: Rr,
    engine: AuthorizationEngine<Rl, P, Res, S, G>,
    audit_repo: A,
    /// The same TTL-cache invalidation hook the REST handlers call
    /// (`AppState::invalidate_reactor_routing`) — so a registration written
    /// through gRPC is live on this replica's dispatch gate at once rather
    /// than only after the routing table's TTL expires, exactly as R2.2
    /// requires for the REST path.
    routing_invalidator: Arc<dyn Fn(Uuid) + Send + Sync>,
    /// SEC-101 — whether the composed reactor transport can deliver at all.
    ///
    /// A plain `bool` rather than the gate itself: this service needs the
    /// answer, not the ability to dispatch, and `axiam-api-grpc` has no other
    /// reason to know a gate exists. `axiam-server` reads it off the same
    /// gate the REST layer holds, so the two admin surfaces cannot disagree
    /// — which is the whole point. Without this, refusing the registration in
    /// `axiam-api-rest` alone would leave a second, unguarded door onto the
    /// same outage.
    dispatch_available: bool,
}

impl<Rr, Rl, P, Res, S, G, A> ReactorAdminServiceImpl<Rr, Rl, P, Res, S, G, A>
where
    Rr: ReactorRepository,
    Rl: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
    A: AuditLogRepository,
{
    pub fn new(
        reactor_repo: Rr,
        engine: AuthorizationEngine<Rl, P, Res, S, G>,
        audit_repo: A,
        routing_invalidator: Arc<dyn Fn(Uuid) + Send + Sync>,
        dispatch_available: bool,
    ) -> Self {
        Self {
            reactor_repo,
            engine,
            audit_repo,
            routing_invalidator,
            dispatch_available,
        }
    }

    /// SEC-101 — refuse to leave an ENABLED registration in place while the
    /// transport cannot deliver to it.
    ///
    /// Mirrors `axiam_api_rest::handlers::reactors::require_dispatchable_transport`
    /// exactly, including the "only when it would be enabled" rule that keeps
    /// disable and delete available as the operator's way out. See that
    /// function for the full reasoning.
    ///
    /// `UNAVAILABLE` is the gRPC status for "the dependency this call needs is
    /// not present", and is what `AxiamError::ServiceUnavailable` maps to on
    /// the REST side (503).
    fn require_dispatchable_transport(&self, would_be_enabled: bool) -> Result<(), Status> {
        if !would_be_enabled || self.dispatch_available {
            return Ok(());
        }
        Err(Status::unavailable(
            "the AMQP reactor transport is not implemented in this build, so a registered \
             reactor could never be reached. Registering one would apply its failure_policy \
             to every dispatch instead — and login.post_auth, user.pre_create, \
             user.pre_update and grant.pre_assign all default to fail_closed, so the \
             registration would deny those operations for this tenant.",
        ))
    }

    async fn require_permission(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
        action: &str,
    ) -> Result<(), Status> {
        let decision = self
            .engine
            .check_access(&AccessRequest {
                tenant_id,
                subject_id,
                action: action.to_string(),
                resource_id: Uuid::nil(),
                scope: None,
            })
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if decision.is_allowed() {
            Ok(())
        } else {
            Err(Status::permission_denied(decision.reason().to_string()))
        }
    }

    async fn health(&self, tenant_id: Uuid, reactor_id: Uuid) -> ReactorHealth {
        recent_health(
            &self.audit_repo,
            tenant_id,
            reactor_id,
            chrono::Duration::hours(DEFAULT_HEALTH_LOOKBACK_HOURS),
            DEFAULT_HEALTH_FAILURE_SAMPLE_LIMIT,
        )
        .await
    }

    async fn to_response(&self, r: Reactor) -> ReactorResponse {
        let health = self.health(r.tenant_id, r.id).await;
        to_reactor_response(r, health)
    }
}

// ---------------------------------------------------------------------------
// Wire <-> domain conversions
// ---------------------------------------------------------------------------

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

fn validation_status(e: impl std::fmt::Display) -> Status {
    Status::invalid_argument(e.to_string())
}

fn axiam_err_to_status(err: axiam_core::error::AxiamError) -> Status {
    match &err {
        axiam_core::error::AxiamError::NotFound { .. } => Status::not_found(err.to_string()),
        axiam_core::error::AxiamError::Validation { .. } => {
            Status::invalid_argument(err.to_string())
        }
        _ => Status::internal(err.to_string()),
    }
}

fn parse_mode(raw: &str) -> Result<ReactorMode, Status> {
    ReactorMode::from_wire(raw)
        .ok_or_else(|| Status::invalid_argument(format!("unknown mode '{raw}'")))
}

fn parse_failure_policy(raw: &str) -> Result<FailurePolicy, Status> {
    FailurePolicy::from_wire(raw)
        .ok_or_else(|| Status::invalid_argument(format!("unknown failure_policy '{raw}'")))
}

fn to_reactor_response(r: Reactor, health: ReactorHealth) -> ReactorResponse {
    ReactorResponse {
        id: r.id.to_string(),
        tenant_id: r.tenant_id.to_string(),
        name: r.name,
        description: r.description,
        events: r.events,
        mode: r.mode.as_str().to_string(),
        priority: r.priority,
        timeout_ms: r.timeout_ms,
        failure_policy: r.failure_policy.as_str().to_string(),
        enabled: r.enabled,
        created_at: r.created_at.to_rfc3339(),
        updated_at: r.updated_at.to_rfc3339(),
        last_seen_at: r.last_seen_at.map(|t| t.to_rfc3339()),
        recent_timeout_count: health.recent_timeout_count,
        recent_veto_count: health.recent_veto_count,
    }
}

fn to_event_descriptor(
    spec: &axiam_core::models::reactor::ReactorEventSpec,
) -> ReactorEventDescriptor {
    ReactorEventDescriptor {
        name: spec.name.to_string(),
        interceptable: spec.interceptable,
        mutable: spec.mutable,
        mutable_fields: spec.mutable_fields.iter().map(|f| f.to_string()).collect(),
        default_failure_policy: spec.default_failure_policy.as_str().to_string(),
        description: spec.description.to_string(),
    }
}

/// The verified `(tenant_id, subject_id)` pair a request is authorized as —
/// identical in shape and intent to every other gRPC service's SEC-003
/// pattern (derive identity from the interceptor-verified JWT, never from
/// the request body).
fn claims_identity<T>(request: &Request<T>) -> Result<(Uuid, Uuid), Status> {
    let claims = request
        .extensions()
        .get::<ValidatedClaims>()
        .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
        .clone();
    Ok((
        parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?,
        parse_uuid(&claims.0.sub, "claims.sub")?,
    ))
}

#[tonic::async_trait]
impl<Rr, Rl, P, Res, S, G, A> ReactorAdminService
    for ReactorAdminServiceImpl<Rr, Rl, P, Res, S, G, A>
where
    Rr: ReactorRepository + 'static,
    Rl: RoleRepository + 'static,
    P: PermissionRepository + 'static,
    Res: ResourceRepository + 'static,
    S: ScopeRepository + 'static,
    G: GroupRepository + 'static,
    A: AuditLogRepository + 'static,
{
    async fn list_reactor_events(
        &self,
        request: Request<ListReactorEventsRequest>,
    ) -> Result<Response<ListReactorEventsResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:list")
            .await?;

        Ok(Response::new(ListReactorEventsResponse {
            events: EVENT_REGISTRY.iter().map(to_event_descriptor).collect(),
        }))
    }

    async fn create_reactor(
        &self,
        request: Request<CreateReactorRequest>,
    ) -> Result<Response<CreateReactorResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:create")
            .await?;

        let req = request.into_inner();
        let mode = parse_mode(&req.mode)?;
        let failure_policy = req
            .failure_policy
            .as_deref()
            .map(parse_failure_policy)
            .transpose()?;
        let timeout_ms = req.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        let enabled = req.enabled.unwrap_or(true);

        // SEC-101 — the same refusal the REST create path makes.
        self.require_dispatchable_transport(enabled)?;

        validate_registration(&req.name, &req.events, mode, timeout_ms)
            .map_err(validation_status)?;

        let reactor = self
            .reactor_repo
            .create(CreateReactor {
                tenant_id,
                name: req.name,
                description: req.description,
                events: req.events,
                mode,
                priority: req.priority,
                timeout_ms: Some(timeout_ms),
                failure_policy,
                enabled,
            })
            .await
            .map_err(axiam_err_to_status)?;

        // R2.2: live on this replica's dispatch gate at once, same as REST.
        (self.routing_invalidator)(tenant_id);

        Ok(Response::new(CreateReactorResponse {
            reactor: Some(self.to_response(reactor).await),
        }))
    }

    async fn list_reactors(
        &self,
        request: Request<ListReactorsRequest>,
    ) -> Result<Response<ListReactorsResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:list")
            .await?;

        let req = request.into_inner();
        let result = self
            .reactor_repo
            .list(
                tenant_id,
                Pagination {
                    offset: req.offset,
                    limit: req.limit,
                },
            )
            .await
            .map_err(axiam_err_to_status)?;

        let mut items = Vec::with_capacity(result.items.len());
        for reactor in result.items {
            items.push(self.to_response(reactor).await);
        }

        Ok(Response::new(ListReactorsResponse {
            items,
            total: result.total,
            offset: result.offset,
            limit: result.limit,
        }))
    }

    async fn get_reactor(
        &self,
        request: Request<GetReactorRequest>,
    ) -> Result<Response<GetReactorResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:get")
            .await?;

        let req = request.into_inner();
        let id = parse_uuid(&req.id, "id")?;
        let reactor = self
            .reactor_repo
            .get_by_id(tenant_id, id)
            .await
            .map_err(axiam_err_to_status)?;

        Ok(Response::new(GetReactorResponse {
            reactor: Some(self.to_response(reactor).await),
        }))
    }

    async fn update_reactor(
        &self,
        request: Request<UpdateReactorRequest>,
    ) -> Result<Response<UpdateReactorResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:update")
            .await?;

        let req = request.into_inner();
        let id = parse_uuid(&req.id, "id")?;

        // Validate the MERGED registration, exactly as REST's `PUT` does —
        // see that handler's docs for why a partial update cannot be
        // validated against itself alone.
        let current = self
            .reactor_repo
            .get_by_id(tenant_id, id)
            .await
            .map_err(axiam_err_to_status)?;

        let mode = req
            .mode
            .as_deref()
            .map(parse_mode)
            .transpose()?
            .unwrap_or(current.mode);
        let merged_name = req.name.clone().unwrap_or_else(|| current.name.clone());
        let merged_events = if req.events_set {
            req.events.clone()
        } else {
            current.events.clone()
        };
        let merged_timeout = req.timeout_ms.unwrap_or(current.timeout_ms);
        let merged_enabled = req.enabled.unwrap_or(current.enabled);

        // SEC-101, on the merged result — disabling is always allowed.
        self.require_dispatchable_transport(merged_enabled)?;

        validate_registration(&merged_name, &merged_events, mode, merged_timeout)
            .map_err(validation_status)?;

        let requested_failure_policy = req
            .failure_policy
            .as_deref()
            .map(parse_failure_policy)
            .transpose()?;

        // Changing the event set can change what the STORED failure_policy
        // means — re-derive it when the caller replaced `events` without
        // naming an explicit policy, exactly as REST does.
        let failure_policy = match (requested_failure_policy, req.events_set) {
            (Some(explicit), _) => Some(explicit),
            (None, true) => Some(default_failure_policy_for(&merged_events)),
            (None, false) => None,
        };

        let reactor = self
            .reactor_repo
            .update(
                tenant_id,
                id,
                UpdateReactor {
                    name: req.name,
                    description: req.description,
                    events: req.events_set.then_some(req.events),
                    mode: req.mode.as_deref().map(parse_mode).transpose()?,
                    priority: req.priority,
                    timeout_ms: req.timeout_ms,
                    failure_policy,
                    enabled: req.enabled,
                },
            )
            .await
            .map_err(axiam_err_to_status)?;

        (self.routing_invalidator)(tenant_id);

        Ok(Response::new(UpdateReactorResponse {
            reactor: Some(self.to_response(reactor).await),
        }))
    }

    async fn delete_reactor(
        &self,
        request: Request<DeleteReactorRequest>,
    ) -> Result<Response<DeleteReactorResponse>, Status> {
        let (tenant_id, subject_id) = claims_identity(&request)?;
        self.require_permission(tenant_id, subject_id, "reactors:delete")
            .await?;

        let req = request.into_inner();
        let id = parse_uuid(&req.id, "id")?;

        self.reactor_repo
            .delete(tenant_id, id)
            .await
            .map_err(axiam_err_to_status)?;

        // Deleting matters most of the three writes: an interceptor that no
        // longer exists must stop being dispatched to at once, same as REST.
        (self.routing_invalidator)(tenant_id);

        Ok(Response::new(DeleteReactorResponse {}))
    }
}
