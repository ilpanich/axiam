//! The reactor gate (X1.4 / R2.2) — what the five hook sites actually call.
//!
//! `dispatcher.rs` decides what a chain of reactors *means*; this module is the
//! thing that has a routing table, a concurrency bound, an audit trail and a
//! set of counters, and that presents all of it to `axiam-auth`,
//! `axiam-oauth2` and the REST handlers as one method on
//! [`axiam_core::models::reactor::ReactorGate`].
//!
//! # The seam, and why it is shaped this way
//!
//! The five call sites are in crates that must not link a broker. They hold
//! [`SharedReactorGate`] — `Arc<dyn DynReactorGate>` — and a deployment without
//! AMQP puts [`NoopReactorGate`] behind it. That is the *whole* conditional:
//! there is no `if reactors_enabled` at any hook, because a branch at the hook
//! is a branch that can be wrong in only one build.
//!
//! # Zero cost when nothing is hooked
//!
//! [`DispatchingReactorGate::intercept`] returns `Allow` before touching the
//! limiter, the clock or the audit sink when either
//!
//! * the event is not in the registry (`authz.check` and friends — the
//!   structural half of §22.7's hot-path exclusion), or
//! * the tenant has no enabled interceptor for it.
//!
//! The second case is a hit on an in-process TTL map, which is what lets the
//! plan promise that hot-path cells show zero delta with reactors registered on
//! *other* events.
//!
//! # Back-pressure on the in-flight cap
//!
//! The per-tenant cap ([`DEFAULT_MAX_IN_FLIGHT`], 64) is acquired with
//! `try_acquire`, never `acquire`. Breaching it fails the interception
//! immediately and applies **each registered reactor's own failure policy**,
//! exactly as a timeout would. Queueing behind the cap would convert a
//! concurrency bound into an unbounded latency bound — the login path would
//! stop being slow and start being unavailable, which is the failure the cap
//! exists to prevent. A `fail_closed` reactor therefore denies under overload,
//! and that is the intended reading: an overloaded fraud check has not passed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use uuid::Uuid;

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::reactor::{
    FailurePolicy, Reactor, ReactorGate, ReactorMode, ReactorOutcome, event_spec,
};

use super::dispatcher::{
    ChainResult, DEFAULT_MAX_IN_FLIGHT, DispatchFailure, InFlightLimiter, ReactorTransport,
    resolve_failure, run_chain,
};
use super::metrics;

/// How long a tenant's routing table entry is served before it is re-read.
///
/// Five seconds is the same order as the authorization decision cache's TTL and
/// is the bound the "registry update visible ≤ TTL" acceptance test asserts
/// against. It is a *ceiling*, not a schedule: an administrative change also
/// calls [`ReactorRoutingTable::invalidate_tenant`], so the normal case is
/// immediate and the TTL is what covers a replica that did not serve the
/// mutation.
pub const DEFAULT_ROUTING_TTL: Duration = Duration::from_secs(5);

/// How long "this tenant has (no) reactor registrations" stays believed
/// (SEC-100).
///
/// Deliberately much longer than [`DEFAULT_ROUTING_TTL`]: it is consulted only
/// when the per-event registry read has already failed, and it decides only
/// whether a tenant with provably zero registrations is exempt from the
/// resulting deny. An administrative change calls
/// [`ReactorRoutingTable::invalidate_tenant`], which clears it on the replica
/// that served the change, so this is the ceiling for the replicas that did
/// not.
pub const REGISTRATION_PRESENCE_TTL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Where registrations come from
// ---------------------------------------------------------------------------

/// The registration store, as the gate needs to see it.
///
/// Object-safe and deliberately narrower than `ReactorRepository`: the gate
/// reads one query and must never be able to write a registration. An adapter
/// over the real repository lives in [`RepositoryReactorSource`]; tests supply
/// a vector.
pub trait ReactorSource: Send + Sync {
    /// Every **enabled** reactor in `tenant_id` subscribed to `event`, ordered
    /// by `priority` ascending then `id` — the order interceptors run in.
    fn enabled_for_event<'a>(
        &'a self,
        tenant_id: Uuid,
        event: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Reactor>, String>> + Send + 'a>,
    >;

    /// Whether this tenant has **any** reactor registration at all, enabled or
    /// not (SEC-100).
    ///
    /// Consulted only when [`Self::enabled_for_event`] has failed and there is
    /// no cached list to fall back on. The unreadable-registry rule — *a
    /// registry that cannot be read is not evidence that no veto was
    /// registered* — is right, and must stay: if an unreadable registry meant
    /// "no reactors", anyone who can degrade the reactor table's availability
    /// could disable every `fail_closed` fraud check in the deployment. But
    /// the rule was being applied to the population it does not protect. The
    /// overwhelming majority of tenants have never registered a reactor, and
    /// for them the correct answer is provably "there is nothing to consult",
    /// not "deny every login". On a cold replica — before any successful
    /// resolve has cached the empty list — the old code denied `login.post_auth`
    /// for all of them.
    ///
    /// This is a *different, broader query* than the per-event one, which is
    /// why it is worth asking: a per-table timeout, a bad plan on the event
    /// index or a partial failure can take out one and not the other. When it
    /// also fails, the deny stands — that is the honest answer when there is
    /// genuinely no evidence.
    ///
    /// The default is `Ok(true)`: "assume this tenant has registrations",
    /// which preserves the deny. An implementation that can answer cheaply
    /// should override it; one that cannot must not guess `false`.
    fn tenant_has_registrations<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
    {
        let _ = tenant_id;
        Box::pin(std::future::ready(Ok(true)))
    }
}

/// Adapter from the real `ReactorRepository` to [`ReactorSource`].
#[derive(Debug, Clone)]
pub struct RepositoryReactorSource<R>(pub R);

impl<R: axiam_core::repository::ReactorRepository> ReactorSource for RepositoryReactorSource<R> {
    fn enabled_for_event<'a>(
        &'a self,
        tenant_id: Uuid,
        event: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Reactor>, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            self.0
                .get_enabled_by_event(tenant_id, event)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn tenant_has_registrations<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
    {
        Box::pin(async move {
            // One row is enough to answer the question, so ask for one. This
            // runs only on the failure path, and its result is cached by
            // `ReactorRoutingTable` for `REGISTRATION_PRESENCE_TTL`, so a
            // sustained registry outage costs one such query per tenant per
            // minute rather than one per login.
            self.0
                .list(
                    tenant_id,
                    axiam_core::repository::Pagination {
                        offset: 0,
                        limit: 1,
                    },
                )
                .await
                .map(|page| page.total > 0)
                .map_err(|e| e.to_string())
        })
    }
}

/// A source with no registrations — the routing table a deployment gets when
/// reactors are configured off but the plumbing is still composed.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyReactorSource;

impl ReactorSource for EmptyReactorSource {
    fn enabled_for_event<'a>(
        &'a self,
        _tenant_id: Uuid,
        _event: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<Reactor>, String>> + Send + 'a>,
    > {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }

    fn tenant_has_registrations<'a>(
        &'a self,
        _tenant_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
    {
        Box::pin(std::future::ready(Ok(false)))
    }
}

// ---------------------------------------------------------------------------
// Routing table
// ---------------------------------------------------------------------------

struct RoutingEntry {
    loaded_at: Instant,
    reactors: Arc<Vec<Reactor>>,
}

/// Which reactors to call for `(tenant, event)`, cached with a TTL.
///
/// Without this the token path would pay a database round trip per issuance to
/// discover that no reactor is registered, which is the cost the feature is
/// explicitly not allowed to impose (X1.6: hot-path cells show zero delta).
pub struct ReactorRoutingTable<S> {
    source: S,
    ttl: Duration,
    entries: Mutex<HashMap<(Uuid, &'static str), RoutingEntry>>,
    /// SEC-100: "does this tenant have any registration at all", cached
    /// separately and for much longer than the routing entries.
    ///
    /// A different TTL because it answers a different question. The routing
    /// entries must be fresh — five seconds is the bound the "registry update
    /// visible ≤ TTL" acceptance test asserts — because they decide *which*
    /// reactor runs. This one only ever decides whether a tenant with
    /// provably zero reactors is exempt from the unreadable-registry deny, and
    /// it is consulted only when the registry is already unreadable, so a
    /// minute-old answer is exactly as useful as a fresh one and costs one
    /// query per tenant per minute instead of one per login.
    ///
    /// Cleared by [`Self::invalidate_tenant`] along with everything else, so a
    /// tenant that registers its first reactor stops being exempt at once on
    /// the replica that served the registration, and within
    /// [`REGISTRATION_PRESENCE_TTL`] everywhere else.
    presence: Mutex<HashMap<Uuid, (bool, Instant)>>,
}

impl<S: ReactorSource> ReactorRoutingTable<S> {
    pub fn new(source: S, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            entries: Mutex::new(HashMap::new()),
            presence: Mutex::new(HashMap::new()),
        }
    }

    /// Drop every cached entry for a tenant.
    ///
    /// Called by the reactor CRUD handlers so a registration change is visible
    /// on the mutating replica at once rather than at the end of the TTL. The
    /// TTL remains the guarantee — this is the optimisation on top of it, and
    /// the acceptance test asserts the guarantee, not the optimisation.
    pub fn invalidate_tenant(&self, tenant_id: Uuid) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|(t, _), _| *t != tenant_id);
        }
        if let Ok(mut presence) = self.presence.lock() {
            presence.remove(&tenant_id);
        }
    }

    /// Drop everything. Used when a change's tenant is not known.
    pub fn invalidate_all(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
        if let Ok(mut presence) = self.presence.lock() {
            presence.clear();
        }
    }

    /// SEC-100 — whether `tenant_id` has any reactor registration at all.
    ///
    /// `Ok(false)` is the only answer that exempts a tenant from the
    /// unreadable-registry deny, and it is only ever produced by an actual
    /// successful query that found nothing. An error here is **not** folded
    /// into `false`: that would rebuild the very bypass the rule exists to
    /// prevent, one layer down.
    async fn tenant_has_registrations(&self, tenant_id: Uuid) -> Result<bool, String> {
        if let Ok(presence) = self.presence.lock()
            && let Some((known, at)) = presence.get(&tenant_id)
            && at.elapsed() < REGISTRATION_PRESENCE_TTL
        {
            return Ok(*known);
        }
        let answer = self.source.tenant_has_registrations(tenant_id).await?;
        if let Ok(mut presence) = self.presence.lock() {
            presence.insert(tenant_id, (answer, Instant::now()));
        }
        Ok(answer)
    }

    /// Number of live cache entries — for tests and a health panel.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn cached(&self, tenant_id: Uuid, event: &'static str) -> Option<Arc<Vec<Reactor>>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&(tenant_id, event))?;
        (entry.loaded_at.elapsed() < self.ttl).then(|| Arc::clone(&entry.reactors))
    }

    fn stale(&self, tenant_id: Uuid, event: &'static str) -> Option<Arc<Vec<Reactor>>> {
        let entries = self.entries.lock().ok()?;
        entries
            .get(&(tenant_id, event))
            .map(|e| Arc::clone(&e.reactors))
    }

    /// The interceptor list for one dispatch, or the reason it is unknown.
    ///
    /// A store that cannot be read is **not** treated as "no reactors": that
    /// would make an unreachable database a way to bypass every `fail_closed`
    /// veto in the deployment. When a stale entry exists it is served (with a
    /// counter and a warning) because a slightly old list is strictly better
    /// evidence than none; when there is none, the caller applies the event's
    /// default failure policy.
    async fn resolve(
        &self,
        tenant_id: Uuid,
        event: &'static str,
    ) -> Result<Arc<Vec<Reactor>>, String> {
        if let Some(hit) = self.cached(tenant_id, event) {
            return Ok(hit);
        }

        match self.source.enabled_for_event(tenant_id, event).await {
            Ok(list) => {
                let reactors = Arc::new(list);
                if let Ok(mut entries) = self.entries.lock() {
                    entries.insert(
                        (tenant_id, event),
                        RoutingEntry {
                            loaded_at: Instant::now(),
                            reactors: Arc::clone(&reactors),
                        },
                    );
                }
                Ok(reactors)
            }
            Err(e) => {
                metrics::record_registry_error();
                if let Some(stale) = self.stale(tenant_id, event) {
                    metrics::record_registry_stale_serve();
                    tracing::warn!(
                        target: "axiam::reactor",
                        tenant_id = %tenant_id,
                        event,
                        error = %e,
                        "reactor registry unreadable; serving the expired routing entry"
                    );
                    return Ok(stale);
                }
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit sink
// ---------------------------------------------------------------------------

/// Where the gate writes what it saw.
///
/// Object-safe and one method wide, so `axiam-amqp` depends on the audit
/// *shape* rather than on a repository generic. `axiam-server` composes the
/// SurrealDB-backed one; tests collect into a vector.
pub trait ReactorAuditSink: Send + Sync {
    fn record<'a>(
        &'a self,
        entry: CreateAuditLogEntry,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

/// Drops audit records. Only for tests and for a deployment that has no audit
/// repository at all — never the production composition.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAuditSink;

impl ReactorAuditSink for NoopAuditSink {
    fn record<'a>(
        &'a self,
        _entry: CreateAuditLogEntry,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(std::future::ready(()))
    }
}

/// Writes through an `AuditLogRepository`.
///
/// A failed audit write is logged at ERROR and does **not** fail the
/// interception. That is a deliberate trade in one direction only: the outcome
/// the gate computed is already the safe one (a `fail_closed` reactor has
/// already produced a deny by the time this runs), so refusing the operation a
/// second time because the audit table was unavailable would convert an
/// observability outage into an authentication outage without making anything
/// safer.
#[derive(Debug, Clone)]
pub struct RepositoryAuditSink<A>(pub A);

impl<A: axiam_core::repository::AuditLogRepository> ReactorAuditSink for RepositoryAuditSink<A> {
    fn record<'a>(
        &'a self,
        entry: CreateAuditLogEntry,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let action = entry.action.clone();
            if let Err(e) = self.0.append(entry).await {
                tracing::error!(
                    target: "axiam::reactor",
                    action = %action,
                    error = %e,
                    "failed to write a reactor audit record — the decision stands, \
                     but the reactor-health panel will under-report"
                );
            }
        })
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Audit action for one reactor that produced no usable answer.
pub const AUDIT_ACTION_FAILURE: &str = "reactor.dispatch_failed";
/// Audit action for a chain that refused the underlying operation.
pub const AUDIT_ACTION_DENIED: &str = "reactor.denied";
/// Audit action for a chain that changed something.
pub const AUDIT_ACTION_MUTATED: &str = "reactor.mutated";

// ---------------------------------------------------------------------------
// Per-reactor health (R2.3)
// ---------------------------------------------------------------------------
//
// One function, called from both the REST handler and the gRPC admin
// service, so the two transports report the same numbers from the same
// query rather than each growing its own copy that can silently drift.

/// How far back a health count looks by default. A ceiling on what counts as
/// "recent" for a health panel, not a retention policy — the audit log
/// itself is append-only and this reads it, never prunes it.
pub const DEFAULT_HEALTH_LOOKBACK_HOURS: i64 = 24;

/// How many of a reactor's most recent [`AUDIT_ACTION_FAILURE`] records are
/// inspected by default to split out the timeout count. A page, not a full
/// scan: a reactor that has failed more than this many times in the lookback
/// window is already the worst-behaved reactor in the tenant by a wide
/// margin, and "at least this many in the window" is what a health panel
/// needs to say past that point, not an exact count.
pub const DEFAULT_HEALTH_FAILURE_SAMPLE_LIMIT: u64 = 100;

/// Recent-failure counts for one reactor, read from the audit trail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReactorHealth {
    /// [`AUDIT_ACTION_FAILURE`] records in the lookback window whose
    /// `failure_kind` metadata is `"timeout"` — the reactor did not answer in
    /// time, as opposed to answering with something the server refused.
    pub recent_timeout_count: u32,
    /// [`AUDIT_ACTION_DENIED`] records in the lookback window resource-scoped
    /// to this reactor — a genuine `decision: "deny"` reply, not a failure
    /// resolved through `failure_policy` (those are counted above, not here;
    /// see [`ChainResult::denied_by`]'s doc comment for why the two must not
    /// be conflated).
    pub recent_veto_count: u32,
}

/// Read one reactor's recent-failure health from the audit trail.
///
/// Two bounded queries, not a full-table scan: the timeout count inspects at
/// most `failure_sample_limit` records (`failure_kind` lives in the metadata
/// JSON, which [`axiam_core::repository::AuditLogFilter`] cannot filter on
/// server-side, so it is read and counted client-side); the veto count only
/// needs [`axiam_core::repository::PaginatedResult::total`] from a
/// `resource_id`+`action`-filtered query, which the repository can answer
/// without transferring the matching rows.
///
/// An audit-store error degrades to zero on both counts rather than
/// propagating — a health panel that cannot be computed this instant is not a
/// reason to hide the registration itself, and the failure is logged here so
/// it is not silent.
pub async fn recent_health<A: axiam_core::repository::AuditLogRepository>(
    audit_repo: &A,
    tenant_id: Uuid,
    reactor_id: Uuid,
    lookback: chrono::Duration,
    failure_sample_limit: u64,
) -> ReactorHealth {
    use axiam_core::repository::{AuditLogFilter, Pagination};

    let since = Utc::now() - lookback;

    let recent_timeout_count = audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                resource_id: Some(reactor_id),
                action: Some(AUDIT_ACTION_FAILURE.to_string()),
                from: Some(since),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: failure_sample_limit,
            },
        )
        .await
        .map(|page| {
            page.items
                .iter()
                .filter(|entry| {
                    entry.metadata.get("failure_kind").and_then(|v| v.as_str()) == Some("timeout")
                })
                .count() as u32
        })
        .unwrap_or_else(|e| {
            tracing::warn!(
                target: "axiam::reactor",
                tenant_id = %tenant_id,
                reactor_id = %reactor_id,
                error = %e,
                "could not read reactor timeout health from the audit trail"
            );
            0
        });

    let recent_veto_count = audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                resource_id: Some(reactor_id),
                action: Some(AUDIT_ACTION_DENIED.to_string()),
                from: Some(since),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 1,
            },
        )
        .await
        .map(|page| page.total as u32)
        .unwrap_or_else(|e| {
            tracing::warn!(
                target: "axiam::reactor",
                tenant_id = %tenant_id,
                reactor_id = %reactor_id,
                error = %e,
                "could not read reactor veto health from the audit trail"
            );
            0
        });

    ReactorHealth {
        recent_timeout_count,
        recent_veto_count,
    }
}

/// Knobs an operator can turn.
#[derive(Debug, Clone, Copy)]
pub struct ReactorGateConfig {
    /// Concurrent interceptions allowed per tenant before back-pressure.
    pub max_in_flight_per_tenant: usize,
    /// How long a routing-table entry is served before it is re-read.
    pub routing_ttl: Duration,
}

impl Default for ReactorGateConfig {
    fn default() -> Self {
        Self {
            max_in_flight_per_tenant: DEFAULT_MAX_IN_FLIGHT,
            routing_ttl: DEFAULT_ROUTING_TTL,
        }
    }
}

/// The production [`ReactorGate`]: routing table + concurrency bound + chain +
/// audit + metrics.
pub struct DispatchingReactorGate<S, T, A> {
    routing: Arc<ReactorRoutingTable<S>>,
    transport: T,
    audit: A,
    master_key: Vec<u8>,
    config: ReactorGateConfig,
    limiters: Mutex<HashMap<Uuid, InFlightLimiter>>,
}

impl<S, T, A> DispatchingReactorGate<S, T, A>
where
    S: ReactorSource,
    T: ReactorTransport,
    A: ReactorAuditSink,
{
    pub fn new(
        routing: Arc<ReactorRoutingTable<S>>,
        transport: T,
        audit: A,
        master_key: Vec<u8>,
        config: ReactorGateConfig,
    ) -> Self {
        Self {
            routing,
            transport,
            audit,
            master_key,
            config,
            limiters: Mutex::new(HashMap::new()),
        }
    }

    /// The routing table, so the admin CRUD path can invalidate it.
    pub fn routing(&self) -> &Arc<ReactorRoutingTable<S>> {
        &self.routing
    }

    fn limiter(&self, tenant_id: Uuid) -> InFlightLimiter {
        let mut limiters = match self.limiters.lock() {
            Ok(l) => l,
            // A poisoned mutex here means a panic happened while a map entry
            // was being inserted. Refusing to dispatch would be worse than
            // building a fresh limiter for this call: the cap is a bound on
            // concurrency, and a one-off extra permit set cannot exceed it by
            // more than one dispatch.
            Err(poisoned) => poisoned.into_inner(),
        };
        limiters
            .entry(tenant_id)
            .or_insert_with(|| InFlightLimiter::new(self.config.max_in_flight_per_tenant))
            .clone()
    }

    /// Resolve one failure that applies to every **interceptor** in the chain
    /// (the cap breach), and audit each.
    ///
    /// SEC-099: takes the already-filtered interceptor list, not the whole
    /// registration list. `run_chain` filters to `ReactorMode::Intercept`
    /// before it dispatches anything, and this out-of-chain path must agree
    /// with it — passing the unfiltered slice meant a `listen`-mode
    /// registration's `failure_policy` was resolved, and since
    /// `default_failure_policy_for` gives a `login.post_auth` registration
    /// `fail_closed` whatever its mode, a listener **denied the login** when
    /// the per-tenant in-flight cap was breached. `ReactorMode::Listen`'s own
    /// contract is the opposite: "a listener cannot affect any outcome".
    async fn fail_whole_chain(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        reactors: &[&Reactor],
        failure: DispatchFailure,
    ) -> ReactorOutcome {
        let mut outcome = ReactorOutcome::Allow;
        for reactor in reactors {
            metrics::record_failure(&failure);
            self.audit_failure(tenant_id, event, reactor.id, &failure)
                .await;
            if let ReactorOutcome::Deny { reason } =
                resolve_failure(reactor.failure_policy, &failure)
            {
                outcome = ReactorOutcome::Deny { reason };
            }
        }
        outcome
    }

    async fn audit_failure(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        reactor_id: Uuid,
        failure: &DispatchFailure,
    ) {
        let kind = metrics::failure_kind(failure);
        tracing::warn!(
            target: "axiam::reactor",
            tenant_id = %tenant_id,
            event,
            reactor_id = %reactor_id,
            failure_kind = kind,
            failure = %failure,
            "reactor produced no usable reply"
        );
        self.audit
            .record(CreateAuditLogEntry {
                tenant_id,
                // The reactor is the actor here — it is the party that failed
                // to answer — and it is a machine, so `System`.
                actor_id: reactor_id,
                actor_type: ActorType::System,
                action: AUDIT_ACTION_FAILURE.to_string(),
                resource_id: Some(reactor_id),
                outcome: AuditOutcome::Failure,
                ip_address: None,
                metadata: Some(serde_json::json!({
                    "event": event,
                    "reactor_id": reactor_id,
                    "failure_kind": kind,
                    "detail": failure.to_string(),
                })),
            })
            .await;
    }

    /// Everything the chain produced, written down.
    ///
    /// `ChainResult.failures` is the half that used to be dropped on the floor.
    /// A `fail_open` timeout is invisible in the outcome by design, and the
    /// audit record is the only thing that distinguishes "no reactor was
    /// configured" from "the reactor never answered" — which is precisely what
    /// the frontend health panel reads.
    async fn audit_chain(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        result: &ChainResult,
        reactor_ids: &[Uuid],
    ) {
        for (reactor_id, failure) in &result.failures {
            metrics::record_failure(failure);
            self.audit_failure(tenant_id, event, *reactor_id, failure)
                .await;
        }

        match &result.outcome {
            ReactorOutcome::Deny { reason } => {
                metrics::record_denial();
                self.audit
                    .record(CreateAuditLogEntry {
                        tenant_id,
                        actor_id: Uuid::nil(),
                        actor_type: ActorType::System,
                        action: AUDIT_ACTION_DENIED.to_string(),
                        // R2.3: `denied_by` is `Some` exactly when a reply
                        // (not a resolved failure) caused this deny — see its
                        // doc comment on `ChainResult`. Recording it as the
                        // audit resource_id is what lets the admin health
                        // surface attribute a "recent veto" to one reactor
                        // rather than only to the chain. A failure-resolved
                        // deny is already attributed via the per-reactor
                        // `reactor.dispatch_failed` records written above, so
                        // leaving this `None` in that case avoids
                        // double-counting one denial as both a veto and a
                        // failure.
                        resource_id: result.denied_by,
                        outcome: AuditOutcome::Denied,
                        ip_address: None,
                        metadata: Some(serde_json::json!({
                            "event": event,
                            "reason": reason,
                            "chain": reactor_ids,
                            "denied_by": result.denied_by,
                        })),
                    })
                    .await;
            }
            ReactorOutcome::Mutate { patch } => {
                metrics::record_mutation();
                self.audit
                    .record(CreateAuditLogEntry {
                        tenant_id,
                        actor_id: Uuid::nil(),
                        actor_type: ActorType::System,
                        action: AUDIT_ACTION_MUTATED.to_string(),
                        resource_id: None,
                        outcome: AuditOutcome::Success,
                        ip_address: None,
                        metadata: Some(serde_json::json!({
                            "event": event,
                            // Field names only. The values are tenant business
                            // data and the audit trail is read by more people
                            // than the token is.
                            "fields": patch.keys().collect::<Vec<_>>(),
                            "chain": reactor_ids,
                        })),
                    })
                    .await;
            }
            ReactorOutcome::RequireMfa => metrics::record_step_up(),
            ReactorOutcome::Allow => {}
        }
    }

    /// Re-check the merged patch against the event's allow-list.
    ///
    /// `ReactorReply::into_outcome` already refuses a forbidden key per reply,
    /// so this is unreachable through the wire path — which is exactly why it
    /// is here. The gate is the last thing between a third party and a token
    /// claim, and "the layer below already checks it" is the sentence that
    /// precedes every allow-list bypass. A merged patch cannot be attributed to
    /// one registration, so there is no per-registration policy to apply and
    /// the whole mutation is refused rather than filtered — §22.4 rule 1
    /// forbids partial application in the other direction for the same reason.
    fn enforce_allow_list(event: &'static str, outcome: ReactorOutcome) -> ReactorOutcome {
        let ReactorOutcome::Mutate { patch } = &outcome else {
            return outcome;
        };
        let Some(spec) = event_spec(event) else {
            return ReactorOutcome::Allow;
        };
        for key in patch.keys() {
            if !spec.patch_field_allowed(key) {
                metrics::record_gate_patch_rejection();
                tracing::error!(
                    target: "axiam::reactor",
                    event,
                    field = %key,
                    "a merged reactor patch reached the gate carrying a field outside \
                     the event's allow-list — the reply validator has a hole; refusing \
                     the whole operation"
                );
                return ReactorOutcome::Deny {
                    reason: format!(
                        "reactor patch field '{key}' is outside the allow-list for {event}"
                    ),
                };
            }
        }
        outcome
    }
}

impl<S, T, A> ReactorGate for DispatchingReactorGate<S, T, A>
where
    S: ReactorSource,
    T: ReactorTransport,
    A: ReactorAuditSink,
{
    async fn intercept(
        &self,
        tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> ReactorOutcome {
        // 1. Not in the registry — nothing could have been validly registered,
        //    so there is nothing to wait for. This is the structural half of
        //    the hot-path exclusion: `authz.check` returns here without
        //    touching a lock.
        let Some(spec) = event_spec(event) else {
            return ReactorOutcome::Allow;
        };

        // 2. Who is listening.
        let reactors = match self.routing.resolve(tenant_id, event).await {
            Ok(list) => list,
            Err(e) => {
                // SEC-100: before applying the unreadable-registry rule, ask
                // the one question that can exempt a tenant from it —
                // "does this tenant have any registration at all?" — through
                // a broader query with its own cache. A tenant that has never
                // registered a reactor is not a tenant whose veto we might be
                // skipping; there is provably nothing to consult, and denying
                // its logins protects nobody. This is the population the old
                // code hurt: on a cold replica during a partial registry
                // failure, EVERY tenant took the deny.
                //
                // An error from the probe is not folded into "no
                // registrations" — that would rebuild the availability-shaped
                // off switch the rule exists to remove.
                match self.routing.tenant_has_registrations(tenant_id).await {
                    Ok(false) => {
                        tracing::warn!(
                            target: "axiam::reactor",
                            tenant_id = %tenant_id,
                            event,
                            error = %e,
                            "reactor registry unreadable, but this tenant has no reactor \
                             registrations at all; allowing"
                        );
                        return ReactorOutcome::Allow;
                    }
                    Ok(true) => {}
                    Err(probe_error) => {
                        tracing::error!(
                            target: "axiam::reactor",
                            tenant_id = %tenant_id,
                            event,
                            error = %probe_error,
                            "could not establish whether this tenant has any reactor \
                             registration; falling through to the unreadable-registry rule"
                        );
                    }
                }

                // The registry is unreadable, there is no stale entry, and
                // this tenant is not known to be reactor-free, so we cannot
                // know whether a veto was registered. Falling back to the
                // event's own default is the only honest answer left: an
                // unreadable database must not become a way to skip
                // `login.post_auth`.
                //
                // Note what this deliberately does NOT do: resolve the
                // registrations' own failure policies. It cannot — the whole
                // premise of this arm is that the registration list is
                // unknown. When a *stale* list exists, `resolve` serves it and
                // the per-registration policies are applied one screen below,
                // which is the case that matters in a warm process.
                tracing::error!(
                    target: "axiam::reactor",
                    tenant_id = %tenant_id,
                    event,
                    error = %e,
                    default_policy = spec.default_failure_policy.as_str(),
                    "reactor registry unreadable and nothing cached; applying the \
                     event's default failure policy"
                );
                let failure = DispatchFailure::Transport(format!("registry unreadable: {e}"));
                metrics::record_failure(&failure);
                self.audit_failure(tenant_id, event, Uuid::nil(), &failure)
                    .await;
                return match spec.default_failure_policy {
                    FailurePolicy::FailOpen => ReactorOutcome::Allow,
                    FailurePolicy::FailClosed => ReactorOutcome::Deny {
                        reason: format!("reactor registry unavailable for {event}"),
                    },
                };
            }
        };

        // 3. Nobody is. The common case, and it must cost a map lookup.
        let interceptors: Vec<&Reactor> = reactors
            .iter()
            .filter(|r| r.mode == ReactorMode::Intercept)
            .collect();
        if interceptors.is_empty() {
            return ReactorOutcome::Allow;
        }
        let reactor_ids: Vec<Uuid> = interceptors.iter().map(|r| r.id).collect();

        // 4. Back-pressure. Immediate, never queued — see the module docs.
        let _permit = match self.limiter(tenant_id).try_enter_owned() {
            Ok(permit) => permit,
            Err(failure) => {
                tracing::warn!(
                    target: "axiam::reactor",
                    tenant_id = %tenant_id,
                    event,
                    cap = self.config.max_in_flight_per_tenant,
                    "per-tenant reactor in-flight cap reached; applying each \
                     registration's failure policy without waiting"
                );
                // SEC-099: `&interceptors`, never `&reactors` — a listener
                // must not be able to deny.
                return self
                    .fail_whole_chain(tenant_id, event, &interceptors, failure)
                    .await;
            }
        };

        // 5. Run the chain against a wall clock that starts now, so
        //    `min(timeout_ms, 5000 - elapsed)` is measured against real time
        //    rather than a sum of configured timeouts.
        let started = Instant::now();
        let result = run_chain(
            &self.transport,
            &self.master_key,
            &reactors,
            event,
            payload,
            Utc::now,
            || started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
        )
        .await;
        metrics::record_dispatch(started.elapsed().as_millis() as u64);

        self.audit_chain(tenant_id, event, &result, &reactor_ids)
            .await;

        Self::enforce_allow_list(event, result.outcome)
    }

    /// SEC-101: forwarded verbatim from the composed transport. The gate has
    /// no opinion of its own here — the question is entirely "can the thing
    /// that would carry the message carry it".
    fn can_dispatch(&self) -> bool {
        self.transport.can_dispatch()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::CURRENT_KEY_VERSION;
    use crate::reactor::protocol::{ReactorReply, ReplyDecision};
    use axiam_core::models::reactor::{DynReactorGate, SharedReactorGate, noop_reactor_gate};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const MASTER: &[u8] = b"master-key-for-reactor-gate-tests";

    // -- doubles ----------------------------------------------------------

    #[derive(Default)]
    struct VecSource {
        reactors: Mutex<Vec<Reactor>>,
        loads: AtomicUsize,
        fail: Mutex<Option<String>>,
        /// SEC-100: the presence probe is a *different, broader* query, so it
        /// is broken separately. `break_store` models the partial failure the
        /// review names (a per-table timeout, a bad plan on the event index);
        /// `break_presence` models a total one.
        fail_presence: Mutex<Option<String>>,
    }

    impl VecSource {
        fn with(reactors: Vec<Reactor>) -> Arc<Self> {
            Arc::new(Self {
                reactors: Mutex::new(reactors),
                ..Default::default()
            })
        }
        fn set(&self, reactors: Vec<Reactor>) {
            *self.reactors.lock().unwrap() = reactors;
        }
        fn break_store(&self, why: &str) {
            *self.fail.lock().unwrap() = Some(why.to_string());
        }
        #[allow(dead_code)]
        fn break_presence(&self, why: &str) {
            *self.fail_presence.lock().unwrap() = Some(why.to_string());
        }
        fn loads(&self) -> usize {
            self.loads.load(Ordering::Relaxed)
        }
    }

    impl ReactorSource for Arc<VecSource> {
        fn enabled_for_event<'a>(
            &'a self,
            _tenant_id: Uuid,
            event: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<Reactor>, String>> + Send + 'a>,
        > {
            Box::pin(async move {
                self.loads.fetch_add(1, Ordering::Relaxed);
                if let Some(why) = self.fail.lock().unwrap().clone() {
                    return Err(why);
                }
                Ok(self
                    .reactors
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.enabled && r.events.iter().any(|e| e == event))
                    .cloned()
                    .collect())
            })
        }

        fn tenant_has_registrations<'a>(
            &'a self,
            _tenant_id: Uuid,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>>
        {
            Box::pin(async move {
                if let Some(why) = self.fail_presence.lock().unwrap().clone() {
                    return Err(why);
                }
                Ok(!self.reactors.lock().unwrap().is_empty())
            })
        }
    }

    /// What the scripted transport answers with.
    #[derive(Clone)]
    enum Answer {
        Allow,
        Deny(&'static str),
        Mutate(Vec<(&'static str, &'static str)>),
        RequireMfa,
        Timeout,
        /// A signed, in-window reply whose patch the *reply validator* would
        /// refuse — used to prove the failure-policy path.
        ForbiddenPatch(&'static str),
    }

    struct Scripted {
        answer: Answer,
        calls: AtomicUsize,
        hold: Option<Duration>,
    }

    impl Scripted {
        fn new(answer: Answer) -> Self {
            Self {
                answer,
                calls: AtomicUsize::new(0),
                hold: None,
            }
        }
        fn holding(answer: Answer, hold: Duration) -> Self {
            Self {
                answer,
                calls: AtomicUsize::new(0),
                hold: Some(hold),
            }
        }
    }

    impl ReactorTransport for Scripted {
        async fn round_trip(
            &self,
            reactor: &Reactor,
            event: &'static str,
            correlation_id: Uuid,
            _payload: serde_json::Value,
            _timeout_ms: u32,
        ) -> Result<ReactorReply, DispatchFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if let Some(hold) = self.hold {
                tokio::time::sleep(hold).await;
            }
            let (decision, patch, require_mfa) = match &self.answer {
                Answer::Timeout => return Err(DispatchFailure::Timeout),
                Answer::Allow => (ReplyDecision::Allow, None, false),
                Answer::RequireMfa => (ReplyDecision::Allow, None, true),
                Answer::Deny(_) => (ReplyDecision::Deny, None, false),
                Answer::Mutate(pairs) => (
                    ReplyDecision::Mutate,
                    Some(
                        pairs
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect::<BTreeMap<_, _>>(),
                    ),
                    false,
                ),
                Answer::ForbiddenPatch(field) => (
                    ReplyDecision::Mutate,
                    Some(BTreeMap::from([(field.to_string(), "x".to_string())])),
                    false,
                ),
            };
            let reason = match &self.answer {
                Answer::Deny(r) => Some((*r).to_string()),
                _ => None,
            };
            let mut reply = ReactorReply {
                correlation_id,
                tenant_id: reactor.tenant_id,
                event: event.to_string(),
                decision,
                reason,
                patch,
                require_mfa,
                key_version: CURRENT_KEY_VERSION,
                nonce: Uuid::new_v4(),
                issued_at: Utc::now(),
                hmac_signature: None,
            };
            reply.sign(MASTER).unwrap();
            Ok(reply)
        }

        async fn publish_listen(
            &self,
            _reactor: &Reactor,
            _event: &'static str,
            _payload: serde_json::Value,
        ) -> Result<(), DispatchFailure> {
            Ok(())
        }
    }

    #[derive(Default, Clone)]
    struct CollectingAudit(Arc<Mutex<Vec<CreateAuditLogEntry>>>);

    impl CollectingAudit {
        fn entries(&self) -> Vec<CreateAuditLogEntry> {
            self.0.lock().unwrap().clone()
        }
        fn actions(&self) -> Vec<String> {
            self.entries().into_iter().map(|e| e.action).collect()
        }
    }

    impl ReactorAuditSink for CollectingAudit {
        fn record<'a>(
            &'a self,
            entry: CreateAuditLogEntry,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            self.0.lock().unwrap().push(entry);
            Box::pin(std::future::ready(()))
        }
    }

    // -- fixtures ---------------------------------------------------------

    fn reactor(tenant: Uuid, event: &str, policy: FailurePolicy) -> Reactor {
        Reactor {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            name: "r".into(),
            description: String::new(),
            events: vec![event.to_string()],
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: 500,
            failure_policy: policy,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_seen_at: None,
        }
    }

    #[allow(clippy::type_complexity)]
    fn gate(
        source: Arc<VecSource>,
        transport: Scripted,
        audit: CollectingAudit,
        config: ReactorGateConfig,
    ) -> DispatchingReactorGate<Arc<VecSource>, Scripted, CollectingAudit> {
        DispatchingReactorGate::new(
            Arc::new(ReactorRoutingTable::new(source, config.routing_ttl)),
            transport,
            audit,
            MASTER.to_vec(),
            config,
        )
    }

    // -- tests ------------------------------------------------------------

    #[tokio::test]
    async fn an_unregistered_event_never_touches_the_routing_table() {
        let source = VecSource::with(vec![]);
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Deny("no")),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(Uuid::new_v4(), "authz.check", serde_json::json!({}))
            .await;

        assert_eq!(outcome, ReactorOutcome::Allow);
        assert_eq!(
            source.loads(),
            0,
            "the hot path must not even ask which reactors are registered"
        );
    }

    #[tokio::test]
    async fn no_registered_reactor_means_allow_without_dispatching() {
        let source = VecSource::with(vec![]);
        let transport = Scripted::new(Answer::Deny("no"));
        let audit = CollectingAudit::default();
        let g = gate(
            Arc::clone(&source),
            transport,
            audit.clone(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(Uuid::new_v4(), "login.post_auth", serde_json::json!({}))
            .await;

        assert_eq!(outcome, ReactorOutcome::Allow);
        assert!(audit.entries().is_empty());
    }

    #[tokio::test]
    async fn a_deny_is_returned_and_audited() {
        let tenant = Uuid::new_v4();
        let denying_reactor = reactor(tenant, "login.post_auth", FailurePolicy::FailClosed);
        let denying_reactor_id = denying_reactor.id;
        let source = VecSource::with(vec![denying_reactor]);
        let audit = CollectingAudit::default();
        let g = gate(
            source,
            Scripted::new(Answer::Deny("embargoed region")),
            audit.clone(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(
                tenant,
                "login.post_auth",
                serde_json::json!({"sub":"alice"}),
            )
            .await;

        assert_eq!(
            outcome,
            ReactorOutcome::Deny {
                reason: "embargoed region".into()
            }
        );
        let entry = audit
            .entries()
            .into_iter()
            .find(|e| e.action == AUDIT_ACTION_DENIED)
            .expect("a deny must be audited");
        // R2.3: the audit record's resource_id is the specific reactor whose
        // reply caused the veto, so the admin health surface can attribute a
        // "recent veto" to one reactor rather than only to the chain.
        assert_eq!(entry.resource_id, Some(denying_reactor_id));
    }

    #[tokio::test]
    async fn a_mutation_is_returned_and_audited_by_field_name_only() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "token.pre_issue",
            FailurePolicy::FailOpen,
        )]);
        let audit = CollectingAudit::default();
        let g = gate(
            source,
            Scripted::new(Answer::Mutate(vec![("ext.department", "eng")])),
            audit.clone(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(tenant, "token.pre_issue", serde_json::json!({}))
            .await;

        match outcome {
            ReactorOutcome::Mutate { patch } => assert_eq!(patch["ext.department"], "eng"),
            other => panic!("expected a mutation, got {other:?}"),
        }

        let entry = audit
            .entries()
            .into_iter()
            .find(|e| e.action == AUDIT_ACTION_MUTATED)
            .expect("a mutation must be audited");
        let metadata = entry.metadata.unwrap().to_string();
        assert!(metadata.contains("ext.department"));
        assert!(
            !metadata.contains("eng"),
            "the audit record names the fields, not the tenant's values"
        );
    }

    /// The X1.2 requirement in one test: a `fail_open` timeout is invisible in
    /// the outcome, visible in the audit trail, and counted.
    #[tokio::test]
    async fn a_fail_open_timeout_allows_but_is_audited_and_counted() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "token.pre_issue",
            FailurePolicy::FailOpen,
        )]);
        let audit = CollectingAudit::default();
        let before = metrics::timeouts();
        let g = gate(
            source,
            Scripted::new(Answer::Timeout),
            audit.clone(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(tenant, "token.pre_issue", serde_json::json!({}))
            .await;

        assert_eq!(outcome, ReactorOutcome::Allow);
        // `>` rather than `== before + 1`: process-wide counter, concurrent
        // tests in the same binary.
        assert!(metrics::timeouts() > before);
        let entry = audit
            .entries()
            .into_iter()
            .find(|e| e.action == AUDIT_ACTION_FAILURE)
            .expect("a timeout must be audited even when it allows");
        assert!(entry.metadata.unwrap().to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn a_fail_closed_timeout_denies() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        let g = gate(
            source,
            Scripted::new(Answer::Timeout),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(tenant, "login.post_auth", serde_json::json!({}))
            .await;

        assert!(!outcome.permits());
    }

    /// A signed reply carrying a field outside the allow-list is a *failure*,
    /// not a smaller mutation — and on a `fail_closed` registration it denies.
    #[tokio::test]
    async fn a_forbidden_patch_field_is_refused_and_takes_the_failure_path() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "token.pre_issue",
            FailurePolicy::FailClosed,
        )]);
        let audit = CollectingAudit::default();
        let g = gate(
            source,
            Scripted::new(Answer::ForbiddenPatch("sub")),
            audit.clone(),
            ReactorGateConfig::default(),
        );

        let outcome = g
            .intercept(tenant, "token.pre_issue", serde_json::json!({}))
            .await;

        assert!(
            !outcome.permits(),
            "a reactor must not be able to set `sub`"
        );
        let failure = audit
            .entries()
            .into_iter()
            .find(|e| e.action == AUDIT_ACTION_FAILURE)
            .expect("the rejection must be audited");
        let metadata = failure.metadata.unwrap().to_string();
        assert!(metadata.contains("reply_rejected"));
        assert!(metadata.contains("sub"), "the offending key must be named");
    }

    /// Defence in depth: even if a patch reached the gate carrying a forbidden
    /// key (it cannot through the wire path — the reply validator refuses it
    /// first), the gate refuses the whole operation rather than applying part
    /// of it.
    #[test]
    fn the_gate_re_checks_the_merged_patch_against_the_allow_list() {
        type G = DispatchingReactorGate<Arc<VecSource>, Scripted, CollectingAudit>;

        let smuggled = ReactorOutcome::Mutate {
            patch: BTreeMap::from([
                ("ext.ok".to_string(), "1".to_string()),
                ("sub".to_string(), "root".to_string()),
            ]),
        };
        let out = G::enforce_allow_list("token.pre_issue", smuggled);
        assert!(
            !out.permits(),
            "a forbidden key must refuse the whole mutation, not be filtered out"
        );

        let clean = ReactorOutcome::Mutate {
            patch: BTreeMap::from([("ext.ok".to_string(), "1".to_string())]),
        };
        assert!(matches!(
            G::enforce_allow_list("token.pre_issue", clean),
            ReactorOutcome::Mutate { .. }
        ));

        // A veto-only event admits no field at all.
        let on_veto_event = ReactorOutcome::Mutate {
            patch: BTreeMap::from([("ext.ok".to_string(), "1".to_string())]),
        };
        assert!(!G::enforce_allow_list("grant.pre_assign", on_veto_event).permits());
    }

    /// Back-pressure: the cap fails the interception immediately and applies
    /// the registration's policy, rather than queueing behind the bound.
    #[tokio::test]
    async fn breaching_the_in_flight_cap_applies_the_failure_policy_without_waiting() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        let audit = CollectingAudit::default();
        let before = metrics::overloads();
        let config = ReactorGateConfig {
            max_in_flight_per_tenant: 1,
            ..Default::default()
        };
        let g = Arc::new(gate(
            source,
            // Hold the single permit long enough for the second call to find
            // the cap breached.
            Scripted::holding(Answer::Allow, Duration::from_millis(200)),
            audit.clone(),
            config,
        ));

        let first = {
            let g = Arc::clone(&g);
            tokio::spawn(async move {
                g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                    .await
            })
        };
        // Let the first dispatch take the permit.
        tokio::time::sleep(Duration::from_millis(40)).await;

        let started = Instant::now();
        let second = g
            .intercept(tenant, "login.post_auth", serde_json::json!({}))
            .await;
        let waited = started.elapsed();

        assert!(
            !second.permits(),
            "a fail_closed reactor denies under overload"
        );
        assert!(
            waited < Duration::from_millis(150),
            "the cap must reject immediately, not queue: waited {waited:?}"
        );
        // `>` rather than `== before + 1`: the counter is process-wide and the
        // other cap tests run concurrently in this binary.
        assert!(metrics::overloads() > before);
        assert!(audit.entries().iter().any(|e| {
            e.action == AUDIT_ACTION_FAILURE
                && e.metadata
                    .as_ref()
                    .is_some_and(|m| m.to_string().contains("overloaded"))
        }));
        assert_eq!(first.await.unwrap(), ReactorOutcome::Allow);
    }

    #[tokio::test]
    async fn a_fail_open_registration_survives_the_cap_breach() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "token.pre_issue",
            FailurePolicy::FailOpen,
        )]);
        let config = ReactorGateConfig {
            max_in_flight_per_tenant: 1,
            ..Default::default()
        };
        let g = Arc::new(gate(
            source,
            Scripted::holding(Answer::Allow, Duration::from_millis(200)),
            CollectingAudit::default(),
            config,
        ));

        let first = {
            let g = Arc::clone(&g);
            tokio::spawn(async move {
                g.intercept(tenant, "token.pre_issue", serde_json::json!({}))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            g.intercept(tenant, "token.pre_issue", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow
        );
        first.await.unwrap();
    }

    /// The cap is per tenant: one tenant's slow reactor must not make another
    /// tenant's logins fail.
    #[tokio::test]
    async fn the_cap_is_per_tenant() {
        let noisy = Uuid::new_v4();
        let quiet = Uuid::new_v4();
        let source = VecSource::with(vec![
            reactor(noisy, "login.post_auth", FailurePolicy::FailClosed),
            reactor(quiet, "login.post_auth", FailurePolicy::FailClosed),
        ]);
        let config = ReactorGateConfig {
            max_in_flight_per_tenant: 1,
            ..Default::default()
        };
        let g = Arc::new(gate(
            source,
            Scripted::holding(Answer::Allow, Duration::from_millis(200)),
            CollectingAudit::default(),
            config,
        ));

        let busy = {
            let g = Arc::clone(&g);
            tokio::spawn(async move {
                g.intercept(noisy, "login.post_auth", serde_json::json!({}))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(40)).await;

        assert_eq!(
            g.intercept(quiet, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "the other tenant has its own permit set"
        );
        busy.await.unwrap();
    }

    /// The invalidation acceptance test: a registration written after the gate
    /// has already cached "nobody is listening" takes effect within the TTL,
    /// and immediately when the CRUD path invalidates.
    #[tokio::test]
    async fn a_registry_update_becomes_visible_within_the_ttl() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![]);
        let config = ReactorGateConfig {
            routing_ttl: Duration::from_millis(150),
            ..Default::default()
        };
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Deny("newly registered veto")),
            CollectingAudit::default(),
            config,
        );

        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "nothing registered yet"
        );

        source.set(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);

        // Still inside the TTL: the cached empty list is served, which is the
        // documented staleness bound rather than a bug.
        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow
        );

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits(),
            "the new registration must be live once the TTL has passed"
        );
    }

    #[tokio::test]
    async fn invalidating_a_tenant_makes_a_registry_update_visible_at_once() {
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        let source = VecSource::with(vec![]);
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Deny("veto")),
            CollectingAudit::default(),
            // A long TTL, so a pass can only come from the invalidation.
            ReactorGateConfig {
                routing_ttl: Duration::from_secs(3_600),
                ..Default::default()
            },
        );

        g.intercept(tenant, "login.post_auth", serde_json::json!({}))
            .await;
        g.intercept(other, "login.post_auth", serde_json::json!({}))
            .await;
        assert_eq!(g.routing().len(), 2);

        source.set(vec![
            reactor(tenant, "login.post_auth", FailurePolicy::FailClosed),
            reactor(other, "login.post_auth", FailurePolicy::FailClosed),
        ]);
        g.routing().invalidate_tenant(tenant);
        assert_eq!(
            g.routing().len(),
            1,
            "invalidating one tenant must not flush another's entry"
        );

        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits()
        );
        assert_eq!(
            g.intercept(other, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "the untouched tenant still serves its cached entry"
        );
    }

    #[tokio::test]
    async fn the_routing_table_is_read_once_per_ttl_not_once_per_dispatch() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "token.pre_issue",
            FailurePolicy::FailOpen,
        )]);
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Allow),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        for _ in 0..5 {
            g.intercept(tenant, "token.pre_issue", serde_json::json!({}))
                .await;
        }
        assert_eq!(source.loads(), 1);
    }

    /// An unreadable registry must not become a way to skip a `fail_closed`
    /// hook — and must not break a `fail_open` one either.
    ///
    /// SEC-100 narrowed the population this applies to: the tenant must be
    /// *known to have* at least one registration, because a tenant with none
    /// has provably nothing to consult. The registration below is what makes
    /// the presence probe answer `true`; with an empty source this now
    /// correctly allows, which
    /// `an_unreadable_registry_allows_a_tenant_with_no_registrations` asserts.
    /// The per-event read still fails, so the event-default rule is what is
    /// under test here, exactly as before.
    #[tokio::test]
    async fn an_unreadable_registry_falls_back_to_the_events_default_policy() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        source.break_store("connection refused");
        let audit = CollectingAudit::default();
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Allow),
            audit.clone(),
            ReactorGateConfig::default(),
        );

        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits(),
            "login.post_auth defaults fail_closed"
        );
        assert_eq!(
            g.intercept(tenant, "token.pre_issue", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "token.pre_issue defaults fail_open"
        );
        assert_eq!(
            audit
                .actions()
                .iter()
                .filter(|a| *a == AUDIT_ACTION_FAILURE)
                .count(),
            2,
            "both registry failures are audited"
        );
    }

    #[tokio::test]
    async fn a_stale_entry_is_served_when_the_registry_goes_away() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Deny("still vetoing")),
            CollectingAudit::default(),
            ReactorGateConfig {
                routing_ttl: Duration::from_millis(50),
                ..Default::default()
            },
        );

        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits()
        );

        source.break_store("db down");
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits(),
            "the expired-but-known veto is better evidence than none"
        );
    }

    #[tokio::test]
    async fn a_listener_is_never_waited_on() {
        let tenant = Uuid::new_v4();
        let mut listener = reactor(tenant, "login.post_auth", FailurePolicy::FailClosed);
        listener.mode = ReactorMode::Listen;
        let source = VecSource::with(vec![listener]);
        let g = gate(
            source,
            Scripted::new(Answer::Deny("should never be asked")),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow
        );
    }

    #[tokio::test]
    async fn require_mfa_survives_the_gate() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        let g = gate(
            source,
            Scripted::new(Answer::RequireMfa),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::RequireMfa
        );
    }

    /// Every one of the five wired events, against a real chain, for each of
    /// the four things a reactor can do to it.
    ///
    /// The per-*site* half of this matrix lives with the sites
    /// (`axiam-auth`'s `reactor_login_gate_test`, `axiam-oauth2`'s
    /// `token_service` tests, `axiam-api-rest`'s `reactor_hooks` tests), which
    /// assert what each caller *does* with an outcome. This asserts what the
    /// gate hands them, so the two halves meet at a documented value rather
    /// than at an assumption.
    #[tokio::test]
    async fn every_wired_event_resolves_all_four_outcomes() {
        use axiam_core::models::reactor::{EVENT_REGISTRY, event_spec};

        for spec in EVENT_REGISTRY {
            let event: &'static str = spec.name;
            let tenant = Uuid::new_v4();

            // allow
            let g = gate(
                VecSource::with(vec![reactor(tenant, event, FailurePolicy::FailOpen)]),
                Scripted::new(Answer::Allow),
                CollectingAudit::default(),
                ReactorGateConfig::default(),
            );
            assert_eq!(
                g.intercept(tenant, event, serde_json::json!({})).await,
                ReactorOutcome::Allow,
                "{event}: allow"
            );

            // deny — every event is veto-capable; that is what makes them
            // interceptable at all.
            let g = gate(
                VecSource::with(vec![reactor(tenant, event, FailurePolicy::FailOpen)]),
                Scripted::new(Answer::Deny("no")),
                CollectingAudit::default(),
                ReactorGateConfig::default(),
            );
            assert_eq!(
                g.intercept(tenant, event, serde_json::json!({})).await,
                ReactorOutcome::Deny {
                    reason: "no".into()
                },
                "{event}: deny"
            );

            // mutate — the mutable events apply the patch; the veto-only ones
            // refuse the reply and fall to the failure policy.
            let field = match event {
                "token.pre_issue" => "ext.department",
                _ => "email",
            };
            let g = gate(
                VecSource::with(vec![reactor(tenant, event, FailurePolicy::FailClosed)]),
                Scripted::new(Answer::Mutate(vec![(field, "value")])),
                CollectingAudit::default(),
                ReactorGateConfig::default(),
            );
            let outcome = g.intercept(tenant, event, serde_json::json!({})).await;
            if spec.mutable {
                match outcome {
                    ReactorOutcome::Mutate { patch } => {
                        assert_eq!(patch[field], "value", "{event}: mutate")
                    }
                    other => panic!("{event}: expected a mutation, got {other:?}"),
                }
            } else {
                assert!(
                    !outcome.permits(),
                    "{event} is veto-only: a mutate reply is a failure, and this \
                     registration is fail_closed"
                );
            }

            // timeout, under both policies.
            for (policy, permits) in [
                (FailurePolicy::FailOpen, true),
                (FailurePolicy::FailClosed, false),
            ] {
                let audit = CollectingAudit::default();
                let g = gate(
                    VecSource::with(vec![reactor(tenant, event, policy)]),
                    Scripted::new(Answer::Timeout),
                    audit.clone(),
                    ReactorGateConfig::default(),
                );
                let outcome = g.intercept(tenant, event, serde_json::json!({})).await;
                assert_eq!(
                    outcome.permits(),
                    permits,
                    "{event}: timeout under {}",
                    policy.as_str()
                );
                assert!(
                    audit.actions().contains(&AUDIT_ACTION_FAILURE.to_string()),
                    "{event}: every timeout is audited, including the fail_open one"
                );
            }

            // The registry is the source of truth the matrix reads from, so
            // pin that the event is one the gate can actually reach.
            assert!(event_spec(event).is_some());
        }
    }

    /// The erased gate is what every call site actually holds; it must behave
    /// identically to the concrete one.
    #[tokio::test]
    async fn the_erased_gate_behaves_like_the_concrete_one() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        let concrete = gate(
            source,
            Scripted::new(Answer::Deny("nope")),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );
        let erased: SharedReactorGate = Arc::new(concrete);

        assert!(
            !erased
                .intercept_dyn(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits()
        );
        assert_eq!(
            noop_reactor_gate()
                .intercept_dyn(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow
        );
    }

    // -- SEC-099 / SEC-100 / SEC-101 regressions --------------------------

    fn listener(tenant: Uuid, event: &str, policy: FailurePolicy) -> Reactor {
        Reactor {
            mode: ReactorMode::Listen,
            ..reactor(tenant, event, policy)
        }
    }

    /// SEC-099. A `listen`-mode registration cannot deny, and the in-flight
    /// cap is the path where it used to.
    ///
    /// `default_failure_policy_for` gives any `login.post_auth` registration
    /// `fail_closed` regardless of mode, and `fail_whole_chain` was handed the
    /// **unfiltered** registration list — so a listener denied the login the
    /// moment the per-tenant cap was breached, which is the exact inverse of
    /// `ReactorMode::Listen`'s contract ("a listener cannot affect any
    /// outcome"). Before the fix this asserts `Deny`.
    #[tokio::test]
    async fn a_listen_registration_cannot_deny_when_the_in_flight_cap_is_breached() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![
            // One interceptor, so the chain is entered at all …
            reactor(tenant, "login.post_auth", FailurePolicy::FailOpen),
            // … and one listener whose fail_closed policy must not be read.
            listener(tenant, "login.post_auth", FailurePolicy::FailClosed),
        ]);
        let config = ReactorGateConfig {
            max_in_flight_per_tenant: 1,
            ..Default::default()
        };
        let g = Arc::new(gate(
            source,
            Scripted::holding(Answer::Allow, Duration::from_millis(200)),
            CollectingAudit::default(),
            config,
        ));

        let first = {
            let g = Arc::clone(&g);
            tokio::spawn(async move {
                g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(40)).await;

        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "only the fail_open INTERCEPTOR's policy may be resolved under the cap; \
             the fail_closed listener must not be able to deny a login"
        );
        first.await.unwrap();
    }

    /// SEC-100. An unreadable registry must not deny a tenant that provably
    /// has no reactors at all.
    ///
    /// Before the fix the `Err` arm returned the event's default failure
    /// policy — `fail_closed` for `login.post_auth` — before ever reaching the
    /// "nobody is listening" check, so on a cold replica during a partial
    /// registry failure EVERY tenant's logins were denied, including the
    /// overwhelming majority that had never registered a reactor.
    #[tokio::test]
    async fn an_unreadable_registry_allows_a_tenant_with_no_registrations() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![]);
        // Nothing cached: the failure happens on the very first resolve, which
        // is the cold-replica case.
        source.break_store("permission denied on table reactor");
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Deny("unreachable")),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        assert_eq!(
            g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await,
            ReactorOutcome::Allow,
            "a tenant with zero registrations has nothing to consult; denying its \
             logins because the registry is unreadable protects nobody"
        );
    }

    /// SEC-100, the other half: the rule itself must survive. A tenant that
    /// DOES have registrations still takes the deny when the registry cannot
    /// be read and nothing is cached — otherwise anyone who can degrade the
    /// reactor table's availability could disable every `fail_closed` check in
    /// the deployment.
    #[tokio::test]
    async fn an_unreadable_registry_still_denies_a_tenant_that_has_registrations() {
        let tenant = Uuid::new_v4();
        let source = VecSource::with(vec![reactor(
            tenant,
            "login.post_auth",
            FailurePolicy::FailClosed,
        )]);
        source.break_store("per-table timeout");
        let g = gate(
            Arc::clone(&source),
            Scripted::new(Answer::Allow),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );

        assert!(
            !g.intercept(tenant, "login.post_auth", serde_json::json!({}))
                .await
                .permits(),
            "an unreadable registry is not evidence that no veto was registered"
        );
    }

    /// SEC-100: an errored presence probe is NOT folded into "no
    /// registrations". Folding it would rebuild the availability-shaped off
    /// switch one layer down.
    #[tokio::test]
    async fn a_failing_presence_probe_does_not_exempt_a_tenant() {
        struct AllBroken;
        impl ReactorSource for AllBroken {
            fn enabled_for_event<'a>(
                &'a self,
                _tenant_id: Uuid,
                _event: &'a str,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Vec<Reactor>, String>> + Send + 'a>,
            > {
                Box::pin(std::future::ready(Err("registry down".to_string())))
            }
            fn tenant_has_registrations<'a>(
                &'a self,
                _tenant_id: Uuid,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<bool, String>> + Send + 'a>,
            > {
                Box::pin(std::future::ready(Err("registry down".to_string())))
            }
        }

        let g = DispatchingReactorGate::new(
            Arc::new(ReactorRoutingTable::new(AllBroken, DEFAULT_ROUTING_TTL)),
            Scripted::new(Answer::Allow),
            CollectingAudit::default(),
            MASTER.to_vec(),
            ReactorGateConfig::default(),
        );

        assert!(
            !g.intercept(Uuid::new_v4(), "login.post_auth", serde_json::json!({}))
                .await
                .permits()
        );
    }

    /// SEC-101. The gate reports its transport's dispatch capability, and
    /// `UnavailableReactorTransport` — the one composed in production today —
    /// answers `false`. The REST and gRPC reactor-admin handlers refuse an
    /// enabled registration on that answer.
    #[test]
    fn the_gate_reports_whether_its_transport_can_dispatch() {
        use crate::reactor::dispatcher::UnavailableReactorTransport;

        let unavailable = DispatchingReactorGate::new(
            Arc::new(ReactorRoutingTable::new(
                EmptyReactorSource,
                DEFAULT_ROUTING_TTL,
            )),
            UnavailableReactorTransport,
            CollectingAudit::default(),
            MASTER.to_vec(),
            ReactorGateConfig::default(),
        );
        assert!(
            !unavailable.can_dispatch(),
            "registering an interceptor against this transport is a login outage"
        );

        let working = gate(
            VecSource::with(vec![]),
            Scripted::new(Answer::Allow),
            CollectingAudit::default(),
            ReactorGateConfig::default(),
        );
        assert!(working.can_dispatch());

        // And it survives type erasure, which is how the REST layer sees it.
        let erased: SharedReactorGate = Arc::new(unavailable);
        assert!(!erased.can_dispatch_dyn());
        assert!(
            noop_reactor_gate().can_dispatch_dyn(),
            "the no-op gate runs no reactors at all, so a registration under it is \
             inert rather than dangerous"
        );
    }
}
