//! Core authorization engine implementing RBAC with resource hierarchy.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axiam_core::error::AxiamResult;
use axiam_core::models::permission::PermissionGrant;
use axiam_core::models::role::RoleAssignment;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
};
use tracing::Instrument;
use uuid::Uuid;

use crate::config::BatchStrategy;
use crate::decision_cache::DecisionCache;
use crate::invalidation::{InvalidationBroadcaster, InvalidationEvent};
use crate::types::{AccessDecision, AccessRequest};

/// Permission evaluation engine.
///
/// Implements the design-doc algorithm:
/// 1. Fetch subject's role assignments (direct + group, with resource scope)
/// 2. Filter applicable roles (global, scoped to target resource, or ancestor)
/// 3. Collect permissions from applicable roles
/// 4. Check if requested action matches any permission
/// 5. Validate scope if specified
/// 6. Default deny
pub struct AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    role_repo: R,
    permission_repo: P,
    resource_repo: Res,
    scope_repo: S,
    #[allow(dead_code)]
    group_repo: G,
    /// Optional per-tenant decision cache (D7). `None` unless
    /// `with_decision_cache` was called (feature-flagged in `axiam-server`).
    /// When `None`, `check_access` / `check_access_batch` behave exactly as a
    /// build without the cache.
    decision_cache: Option<Arc<DecisionCache>>,
    /// Optional cross-replica invalidation transport (§4.2). `None` unless
    /// `with_invalidation_broadcaster` was called — which `axiam-server` does
    /// only when the decision cache *and* the broadcast channel are both
    /// enabled. When `None`, `invalidate_*` is local-only and infallible,
    /// exactly as before.
    invalidation_broadcaster: Option<Arc<dyn InvalidationBroadcaster>>,
    /// How `check_access_batch` schedules its work (D10). Defaults to
    /// [`BatchStrategy::Concurrent`] when an engine is constructed directly via
    /// `new()`; `axiam-server` always overrides this from `AuthzConfig` via
    /// `with_batch_config` (see `AXIAM__AUTHZ__BATCH_STRATEGY`), whose own
    /// default is [`BatchStrategy::Coalesced`] as of H3/G3 — that is the
    /// shipped default in production. Never affects decisions or their order.
    batch_strategy: BatchStrategy,
    /// Bound on in-flight per-item evaluations under
    /// [`BatchStrategy::Concurrent`] (D-07 pool-safety). Ignored by
    /// `Coalesced`. Defaults to 16.
    batch_max_concurrency: usize,
}

// ---------------------------------------------------------------------------
// Pure evaluation helpers (no I/O) — shared by the single-check and coalesced
// batch paths so their decision/deny-reason semantics can never diverge.
// ---------------------------------------------------------------------------

/// Filter a subject's role assignments down to those applicable to
/// `resource_id`, returning the deduplicated list of applicable role IDs in
/// first-seen order.
///
/// A role applies when it is global, scoped directly to the target resource,
/// or scoped to any ancestor of the target resource (hierarchy inheritance).
fn applicable_role_ids(
    assignments: &[RoleAssignment],
    resource_id: Uuid,
    ancestor_ids: &HashSet<Uuid>,
) -> Vec<Uuid> {
    let mut seen = HashSet::new();
    assignments
        .iter()
        .filter(|a| {
            a.role.is_global
                || a.resource_id == Some(resource_id)
                || a.resource_id
                    .map(|rid| ancestor_ids.contains(&rid))
                    .unwrap_or(false)
        })
        .map(|a| a.role.id)
        .filter(|role_id| seen.insert(*role_id))
        .collect()
}

/// Whether a single grant applies to `action` under `requested_scope_id`.
///
/// Wildcard grants (empty `scope_ids`) match any requested scope; otherwise the
/// requested scope must be present in the grant's scope list. When no scope is
/// requested, an action match is sufficient.
///
/// **The wildcard rule is what makes a resource-level deny stronger than a
/// scope-level one** (B1 design §2.3): a deny with no scopes matches every
/// request for that action regardless of the scope named, so it masks the
/// action entirely. A scoped deny masks only the scopes it names.
fn grant_applies(grant: &PermissionGrant, action: &str, requested_scope_id: Option<Uuid>) -> bool {
    if grant.permission.action != action {
        return false;
    }
    match requested_scope_id {
        Some(scope_id) => grant.scope_ids.is_empty() || grant.scope_ids.contains(&scope_id),
        None => true,
    }
}

/// Outcome of evaluating the applicable grants (B1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantOutcome {
    /// At least one allow matched and no deny did.
    Allowed,
    /// An explicit deny matched. Beats any allow, matched or not.
    DeniedByRule,
    /// Nothing matched — default deny.
    NoGrant,
}

/// Given the applicable role IDs and the (shared) grants-by-role map, decide
/// the outcome for `action` under the optional `requested_scope_id`.
///
/// # Deny-override, in one pass (B1)
///
/// A matched deny **short-circuits**; a matched allow is only remembered. Two
/// consequences worth naming:
///
/// 1. **The common case pays one enum comparison per grant already being
///    examined.** Denies live on the same `grants` edge as allows and arrive in
///    the same batched fetch that already happens, so a tenant with no deny
///    rules issues exactly the queries it issued before. There is no
///    deny-specific round trip, and therefore no need for a per-tenant
///    `has_denies` flag to gate one — which would have been a second source of
///    truth able to go stale.
/// 2. **The result does not depend on grant order.** Because deny
///    short-circuits and allow only accumulates, a rule set has one answer, not
///    one answer per query plan.
fn evaluate_grants(
    unique_role_ids: &[Uuid],
    grants_by_role: &HashMap<Uuid, Vec<PermissionGrant>>,
    action: &str,
    requested_scope_id: Option<Uuid>,
) -> GrantOutcome {
    let mut saw_allow = false;
    for role_id in unique_role_ids {
        let Some(grants) = grants_by_role.get(role_id) else {
            continue;
        };
        for grant in grants {
            if !grant_applies(grant, action, requested_scope_id) {
                continue;
            }
            if grant.effect.is_deny() {
                // Deny wins over every allow, matched or not, at any depth of
                // the hierarchy and at equal specificity. There is nothing
                // later in the scan that could overturn this.
                return GrantOutcome::DeniedByRule;
            }
            saw_allow = true;
        }
    }
    if saw_allow {
        GrantOutcome::Allowed
    } else {
        GrantOutcome::NoGrant
    }
}

/// Turn a [`GrantOutcome`] into the engine's public decision, with the deny
/// reason text the single-check and coalesced-batch paths must share.
fn decision_for(outcome: GrantOutcome, action: &str) -> AccessDecision {
    match outcome {
        GrantOutcome::Allowed => AccessDecision::Allow,
        GrantOutcome::DeniedByRule => {
            AccessDecision::DeniedByRule(format!("an explicit deny rule refuses action '{action}'"))
        }
        GrantOutcome::NoGrant => {
            AccessDecision::Deny(format!("no permission grants action '{action}'"))
        }
    }
}

impl<R, P, Res, S, G> AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    pub fn new(
        role_repo: R,
        permission_repo: P,
        resource_repo: Res,
        scope_repo: S,
        group_repo: G,
    ) -> Self {
        Self {
            role_repo,
            permission_repo,
            resource_repo,
            scope_repo,
            group_repo,
            decision_cache: None,
            invalidation_broadcaster: None,
            batch_strategy: BatchStrategy::Concurrent,
            batch_max_concurrency: 16,
        }
    }

    /// Set the batch-evaluation strategy and its concurrency bound (D10).
    /// Consumed builder style so existing `new(..)` call sites are unaffected;
    /// `axiam-server` calls this once per engine from `AuthzConfig`. Neither
    /// value changes decisions or result order — only DB scheduling.
    #[must_use]
    pub fn with_batch_config(
        mut self,
        strategy: BatchStrategy,
        batch_max_concurrency: usize,
    ) -> Self {
        self.batch_strategy = strategy;
        self.batch_max_concurrency = batch_max_concurrency.max(1);
        self
    }

    /// Attach a shared [`DecisionCache`] to this engine (D7). Consumed builder
    /// style so existing `new(..)` call sites are unaffected. `axiam-server`
    /// calls this only when `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`, and
    /// passes the **same** `Arc<DecisionCache>` to every engine (REST, gRPC,
    /// AMQP) so a REST-triggered invalidation is seen by all read paths.
    #[must_use]
    pub fn with_decision_cache(mut self, cache: Arc<DecisionCache>) -> Self {
        self.decision_cache = Some(cache);
        self
    }

    /// Attach a cross-replica [`InvalidationBroadcaster`] (§4.2). Consumed
    /// builder style, like [`Self::with_decision_cache`]. `axiam-server`
    /// calls this only when **both**
    /// `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true` and
    /// `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`; when it is not
    /// called, [`Self::invalidate_tenant`] / [`Self::invalidate_subject`]
    /// behave exactly as before (local-only, infallible) and the documented
    /// TTL-bounded multi-replica staleness applies unchanged.
    #[must_use]
    pub fn with_invalidation_broadcaster(
        mut self,
        broadcaster: Arc<dyn InvalidationBroadcaster>,
    ) -> Self {
        self.invalidation_broadcaster = Some(broadcaster);
        self
    }

    /// Immediately drop every cached decision for `tenant_id`, **locally and
    /// on every other replica**. No local effect when no cache is attached.
    /// Called by the REST mutation handlers for coarse, access-narrowing
    /// changes whose affected-subject set isn't known without a query (grant
    /// revoke, role/permission delete or update, group-role unassignment,
    /// resource reparent/delete).
    ///
    /// # Errors
    ///
    /// Only when a broadcaster is attached and the broadcast could **not** be
    /// confirmed by the broker — see [`Self::broadcast`]. With no broadcaster
    /// (the default) this is infallible.
    pub async fn invalidate_tenant(&self, tenant_id: Uuid) -> AxiamResult<()> {
        self.invalidate(InvalidationEvent::Tenant { tenant_id })
            .await
    }

    /// Immediately drop every cached decision for a single `subject_id` within
    /// `tenant_id`, **locally and on every other replica**. No local effect
    /// when no cache is attached. Called by the REST mutation handlers when
    /// exactly one subject's effective permissions change (user role
    /// unassign/assign, group membership add/remove).
    ///
    /// # Errors
    ///
    /// As [`Self::invalidate_tenant`].
    pub async fn invalidate_subject(&self, tenant_id: Uuid, subject_id: Uuid) -> AxiamResult<()> {
        self.invalidate(InvalidationEvent::Subject {
            tenant_id,
            subject_id,
        })
        .await
    }

    /// Local-then-remote invalidation.
    ///
    /// Order is deliberate: the **local** cache is dropped first and
    /// unconditionally, so a broadcast failure can never leave the replica
    /// that handled the mutation serving its own stale decision. Only then is
    /// the fan-out attempted.
    async fn invalidate(&self, event: InvalidationEvent) -> AxiamResult<()> {
        if let Some(cache) = self.decision_cache.as_ref() {
            event.apply(cache);
        }
        self.broadcast(event).await
    }

    /// Fan the event out to the other replicas, if a broadcaster is attached.
    ///
    /// # Errors
    ///
    /// Propagates the broadcaster's error, which the REST mutation handlers
    /// turn into a **503**. That is the deliberate posture for §4.2: the
    /// operator asked for a revocation, the database write is durable, but the
    /// invalidation did **not** reach the other replicas — so it is reported as
    /// a failure rather than silently degrading to the TTL-bounded window the
    /// operator opted out of by enabling this channel. Retrying the mutation is
    /// safe (all of these handlers are idempotent in the narrowing direction).
    async fn broadcast(&self, event: InvalidationEvent) -> AxiamResult<()> {
        match self.invalidation_broadcaster.as_ref() {
            Some(b) => b.broadcast(event).await,
            None => Ok(()),
        }
    }

    /// Evaluate whether the subject can perform the requested action.
    ///
    /// Issues 3–4 sequential DB round-trips (role assignments, ancestors,
    /// optional scope lookup, batched grants). For batches that repeat the same
    /// subject/resource, prefer [`Self::check_access_batch`], which resolves the
    /// shared lookups once.
    #[tracing::instrument(
        name = "authz.check_access",
        skip(self, request),
        fields(
            tenant_id = %request.tenant_id,
            subject_id = %request.subject_id,
            resource_id = %request.resource_id,
            action = %request.action,
            scope = request.scope.as_deref().unwrap_or("")
        )
    )]
    pub async fn check_access(&self, request: &AccessRequest) -> AxiamResult<AccessDecision> {
        // D7 fast path: when a decision cache is attached (feature-flagged),
        // a fresh cached decision skips the DB round-trips entirely. When no
        // cache is attached this whole block is absent and the call is
        // identical to a build without the cache.
        if let Some(cache) = self.decision_cache.as_ref()
            && let Some(decision) = cache.get(request)
        {
            return Ok(decision);
        }
        let decision = self.evaluate(request).await?;
        if let Some(cache) = self.decision_cache.as_ref() {
            // Cache the FULL decision (allow *or* deny-with-reason), so a hit
            // is byte-identical to a miss.
            cache.insert(request, decision.clone());
        }
        Ok(decision)
    }

    /// Uncached RBAC evaluation — the actual algorithm (3–4 sequential DB
    /// round-trips). Kept as a separate method so the [`Self::check_access`]
    /// cache wrapper can never alter decision or deny-reason semantics: a cache
    /// hit returns exactly what this would have produced.
    async fn evaluate(&self, request: &AccessRequest) -> AxiamResult<AccessDecision> {
        // 1. Fetch all role assignments (direct + group) with resource scope.
        let assignments = self
            .role_repo
            .get_user_role_assignments(request.tenant_id, request.subject_id)
            .instrument(tracing::debug_span!("db.get_user_role_assignments"))
            .await?;

        if assignments.is_empty() {
            return Ok(AccessDecision::Deny("no roles assigned".into()));
        }

        // 2. Build the set of ancestor resource IDs for hierarchy inheritance.
        let ancestors = self
            .resource_repo
            .get_ancestors(request.tenant_id, request.resource_id)
            .instrument(tracing::debug_span!("db.get_ancestors"))
            .await?;
        let ancestor_ids: HashSet<Uuid> = ancestors.iter().map(|r| r.id).collect();

        // 3. Filter applicable roles (global / target-scoped / ancestor-scoped),
        //    deduplicated in first-seen order.
        let unique_role_ids = applicable_role_ids(&assignments, request.resource_id, &ancestor_ids);

        if unique_role_ids.is_empty() {
            return Ok(AccessDecision::Deny(
                "no applicable roles for this resource".into(),
            ));
        }

        // 4. Resolve the requested scope to an ID (if specified).
        let requested_scope_id = match self.resolve_scope(request).await? {
            ScopeResolution::None => None,
            ScopeResolution::Resolved(id) => Some(id),
            ScopeResolution::NotFound(deny) => return Ok(deny),
        };

        // 5. Fetch every applicable role's grants in a SINGLE batched query
        //    (CQ-B13 N+1 fix), then evaluate action + scope constraints.
        let grants_by_role = self
            .permission_repo
            .get_role_permission_grants_for_roles(request.tenant_id, &unique_role_ids)
            .instrument(tracing::debug_span!(
                "db.get_role_permission_grants_for_roles"
            ))
            .await?;

        Ok(decision_for(
            evaluate_grants(
                &unique_role_ids,
                &grants_by_role,
                &request.action,
                requested_scope_id,
            ),
            &request.action,
        ))
    }

    /// Resolve the request's optional scope name to a scope ID on the target
    /// resource. Shared by [`Self::check_access`] and the batch path.
    async fn resolve_scope(&self, request: &AccessRequest) -> AxiamResult<ScopeResolution> {
        let Some(ref scope_name) = request.scope else {
            return Ok(ScopeResolution::None);
        };
        let scopes = self
            .scope_repo
            .list_by_resource(request.tenant_id, request.resource_id)
            .instrument(tracing::debug_span!("db.list_by_resource"))
            .await?;
        match scopes.iter().find(|s| s.name == *scope_name) {
            Some(s) => Ok(ScopeResolution::Resolved(s.id)),
            None => Ok(ScopeResolution::NotFound(AccessDecision::Deny(format!(
                "scope '{}' not found on resource",
                scope_name
            )))),
        }
    }

    /// Evaluate an ordered batch of authorization checks.
    ///
    /// The returned `Vec` has the same length and order as `requests`; result
    /// `i` is the decision for `requests[i]` and is byte-identical to what
    /// [`Self::check_access`] would return for that request in isolation — this
    /// holds for **both** [`BatchStrategy`] variants, which differ only in how
    /// the DB work is scheduled:
    ///
    /// - [`BatchStrategy::Coalesced`] (default since H3/G3, D1) — shared
    ///   role-assignment/ancestor/grant lookups resolved once per (tenant,
    ///   subject|resource): 15 round-trips → 3 for the benchmark's 5-item
    ///   shape. On the G3 settled-protocol re-measurement this wins decisively
    ///   (4.98× repeated single checks over REST; gRPC batch p95 74 ms) —
    ///   the run-2 serialization concern only applied to the contaminated
    ///   cells (see `claude_dev/authz-batch-investigation.md`).
    /// - [`BatchStrategy::Concurrent`] (D10) — each item is an independent
    ///   cache-aware [`Self::check_access`], run concurrently (bounded by
    ///   `batch_max_concurrency`). Recovers per-item DB parallelism; still
    ///   beats repeated single checks (1.37×) but by a smaller margin than
    ///   `Coalesced`. Retained as a selectable opt-in strategy.
    pub async fn check_access_batch(
        &self,
        requests: &[AccessRequest],
    ) -> AxiamResult<Vec<AccessDecision>> {
        match self.batch_strategy {
            BatchStrategy::Concurrent => self.evaluate_concurrent(requests).await,
            BatchStrategy::Coalesced => self.evaluate_coalesced_cached(requests).await,
        }
    }

    /// **D10 opt-in strategy** — evaluate each item as an independent,
    /// cache-aware [`Self::check_access`], run **concurrently** with a bound of
    /// `batch_max_concurrency` in-flight, preserving input order.
    ///
    /// This was the run-2-era default (run-2 evidence): the coalesced path
    /// ([`Self::evaluate_batch`]) minimizes round-trips but resolves the whole
    /// batch on a single task, which appeared to serialize on the database (DB
    /// pinned at ~1 core, ~1 s p50, everything else idle) and did not beat
    /// repeated single checks. Single `check_access` calls, by contrast,
    /// saturated the DB (2 cores, 745 req/s) precisely because 50 of them ran
    /// concurrently. Evaluating a batch's items the same way recovers that
    /// parallelism. **G3 re-measured both strategies on the settled protocol**
    /// and found the run-2 coalesced numbers were contaminated by the post-seed
    /// clamp: `Coalesced` in fact wins decisively (4.98× vs this strategy's
    /// 1.37×), so `Coalesced` is the default as of H3 and this strategy is now
    /// opt-in. `check_access` is reused verbatim, so every item's decision,
    /// deny reason, cache lookup and cache insert are identical to a standalone
    /// call — `buffered` keeps results in request order.
    async fn evaluate_concurrent(
        &self,
        requests: &[AccessRequest],
    ) -> AxiamResult<Vec<AccessDecision>> {
        use futures::stream::{StreamExt, TryStreamExt};

        // Build the per-item futures EAGERLY into a Vec before handing them to
        // the stream. Mapping `requests.iter()` lazily inside `stream::iter`
        // would store the `|req| self.check_access(req)` closure in the stream
        // adapter, and when the whole `check_access_batch` future is erased
        // behind the `AuthzChecker` trait object (`Pin<Box<dyn Future + Send>>`
        // in axiam-api-rest / the gRPC async-trait), the borrow checker cannot
        // prove that closure is `for<'a> FnMut(&'a AccessRequest) -> …`
        // ("implementation of `FnOnce` is not general enough"). Collecting
        // first applies the closure in this concrete-lifetime scope, so the
        // boxed future holds only already-built item futures — no HRTB closure.
        let item_futures: Vec<_> = requests.iter().map(|req| self.check_access(req)).collect();

        futures::stream::iter(item_futures)
            .buffered(self.batch_max_concurrency.max(1))
            .try_collect()
            .await
    }

    /// **D1 path** (default since H3/G3; `AXIAM__AUTHZ__BATCH_STRATEGY=coalesced`,
    /// or the unset default) — coalesced evaluation with the D7 decision cache
    /// layered on top: serve hits from the cache, evaluate only the misses
    /// through the shared-lookup batch path, then backfill. Input order is
    /// preserved.
    async fn evaluate_coalesced_cached(
        &self,
        requests: &[AccessRequest],
    ) -> AxiamResult<Vec<AccessDecision>> {
        // With no cache attached, this is exactly the D1 coalesced path —
        // zero behaviour change.
        let Some(cache) = self.decision_cache.as_ref() else {
            return self.evaluate_batch(requests).await;
        };

        // Cache-enabled path: serve hits from the cache, evaluate only the
        // misses (still via the coalesced batch path so shared lookups are
        // resolved once), then backfill the cache. Input order is preserved.
        let mut results: Vec<Option<AccessDecision>> =
            requests.iter().map(|r| cache.get(r)).collect();

        let miss_indices: Vec<usize> = results
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.is_none().then_some(i))
            .collect();

        if !miss_indices.is_empty() {
            let miss_requests: Vec<AccessRequest> =
                miss_indices.iter().map(|&i| requests[i].clone()).collect();
            let miss_decisions = self.evaluate_batch(&miss_requests).await?;
            for (slot, &i) in miss_indices.iter().enumerate() {
                let decision = miss_decisions[slot].clone();
                cache.insert(&requests[i], decision.clone());
                results[i] = Some(decision);
            }
        }

        // Every slot is now filled (hit or freshly evaluated).
        Ok(results.into_iter().map(|d| d.expect("filled")).collect())
    }

    /// Uncached coalesced batch evaluation (the D1 fast path). Separated from
    /// [`Self::check_access_batch`] so the D7 cache wrapper cannot alter
    /// decision/deny-reason semantics.
    #[tracing::instrument(
        name = "authz.check_access_batch",
        skip(self, requests),
        fields(batch_size = requests.len())
    )]
    async fn evaluate_batch(&self, requests: &[AccessRequest]) -> AxiamResult<Vec<AccessDecision>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        // --- Coalesce round-trip 1: role assignments, once per (tenant, subject).
        let mut assignments_by_subject: HashMap<(Uuid, Uuid), Vec<RoleAssignment>> = HashMap::new();
        for req in requests {
            let key = (req.tenant_id, req.subject_id);
            if let std::collections::hash_map::Entry::Vacant(slot) =
                assignments_by_subject.entry(key)
            {
                let assignments = self
                    .role_repo
                    .get_user_role_assignments(req.tenant_id, req.subject_id)
                    .instrument(tracing::debug_span!(
                        "db.get_user_role_assignments",
                        tenant_id = %req.tenant_id,
                        subject_id = %req.subject_id
                    ))
                    .await?;
                slot.insert(assignments);
            }
        }

        // Only items whose subject actually has role assignments proceed past
        // the first gate — so ancestors/scopes/grants are fetched ONLY for
        // resources those items target. This keeps the batch's round-trip
        // profile identical to per-item `check_access` (no wasted ancestor walk
        // for a subject that would deny at "no roles assigned").
        let has_roles = |req: &AccessRequest| {
            assignments_by_subject
                .get(&(req.tenant_id, req.subject_id))
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        };

        // --- Coalesce round-trip 2: ancestors, once per (tenant, resource).
        let mut ancestors_by_resource: HashMap<(Uuid, Uuid), HashSet<Uuid>> = HashMap::new();
        for req in requests.iter().filter(|r| has_roles(r)) {
            let key = (req.tenant_id, req.resource_id);
            if let std::collections::hash_map::Entry::Vacant(slot) =
                ancestors_by_resource.entry(key)
            {
                let ancestors = self
                    .resource_repo
                    .get_ancestors(req.tenant_id, req.resource_id)
                    .instrument(tracing::debug_span!(
                        "db.get_ancestors",
                        tenant_id = %req.tenant_id,
                        resource_id = %req.resource_id
                    ))
                    .await?;
                slot.insert(ancestors.iter().map(|r| r.id).collect());
            }
        }

        // --- Coalesce round-trip 3: scope lists, once per (tenant, resource)
        //     that any scoped, role-bearing item targets.
        let mut scopes_by_resource: HashMap<(Uuid, Uuid), Vec<axiam_core::models::scope::Scope>> =
            HashMap::new();
        for req in requests
            .iter()
            .filter(|r| r.scope.is_some() && has_roles(r))
        {
            let key = (req.tenant_id, req.resource_id);
            if let std::collections::hash_map::Entry::Vacant(slot) = scopes_by_resource.entry(key) {
                let scopes = self
                    .scope_repo
                    .list_by_resource(req.tenant_id, req.resource_id)
                    .instrument(tracing::debug_span!(
                        "db.list_by_resource",
                        tenant_id = %req.tenant_id,
                        resource_id = %req.resource_id
                    ))
                    .await?;
                slot.insert(scopes);
            }
        }

        // --- Per-item: compute applicable roles from the shared lookups, and
        //     accumulate the union of role IDs so grants can be fetched ONCE.
        //     `PreDecision` short-circuits (deny) are recorded here so the final
        //     pass need not re-derive them.
        enum PreDecision {
            Decided(AccessDecision),
            NeedsGrants {
                unique_role_ids: Vec<Uuid>,
                requested_scope_id: Option<Uuid>,
            },
        }

        let mut pre: Vec<PreDecision> = Vec::with_capacity(requests.len());
        // Union of (tenant, role_id) that we must fetch grants for, deduped.
        let mut grant_role_ids: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        let mut grant_role_seen: HashSet<(Uuid, Uuid)> = HashSet::new();

        for (i, req) in requests.iter().enumerate() {
            let _item_span = tracing::debug_span!(
                "authz.batch.item",
                index = i,
                resource_id = %req.resource_id,
                action = %req.action
            )
            .entered();

            let assignments = assignments_by_subject
                .get(&(req.tenant_id, req.subject_id))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if assignments.is_empty() {
                pre.push(PreDecision::Decided(AccessDecision::Deny(
                    "no roles assigned".into(),
                )));
                continue;
            }

            // WIDENING fallback: a miss here silently yields "no ancestors",
            // which can only ever *shrink* `applicable_role_ids` below —
            // dropping an ancestor-scoped grant. If that dropped grant was a
            // DENY, this would silently widen access (an ancestor-scoped deny
            // would fail to apply). It is unreachable today only because this
            // lookup key, `(req.tenant_id, req.resource_id)`, is populated by
            // the round-trip-2 loop above under the exact same gate that
            // guards this call site: the round-trip-2 loop runs over
            // `requests.iter().filter(|r| has_roles(r))` (the `has_roles`
            // closure defined above, keyed off `assignments_by_subject`), and
            // this call site is reached only when the `assignments.is_empty()`
            // check just above did NOT `continue` — i.e. only when
            // `assignments_by_subject.get(&(req.tenant_id, req.subject_id))`
            // is non-empty for this same `req`, which is exactly `has_roles`'s
            // condition. So every `req` that reaches this line already had its
            // `(tenant_id, resource_id)` key inserted into `ancestors_by_resource`
            // by round-trip 2, and `.unwrap_or(&empty_ancestors)` never actually
            // fires. If that population gate (`has_roles`) and this consumption
            // gate (`assignments.is_empty()`) are ever allowed to diverge —
            // e.g. by filtering round-trip 2 on something other than
            // `has_roles`, or by reordering this block above the
            // `assignments.is_empty()` check — a missed lookup here would
            // silently drop an ancestor-scoped DENY instead of failing loudly.
            let empty_ancestors = HashSet::new();
            let ancestor_ids = ancestors_by_resource
                .get(&(req.tenant_id, req.resource_id))
                .unwrap_or(&empty_ancestors);

            let unique_role_ids = applicable_role_ids(assignments, req.resource_id, ancestor_ids);
            if unique_role_ids.is_empty() {
                pre.push(PreDecision::Decided(AccessDecision::Deny(
                    "no applicable roles for this resource".into(),
                )));
                continue;
            }

            // Resolve scope against the coalesced scope list (no I/O here).
            let requested_scope_id = if let Some(ref scope_name) = req.scope {
                let scopes = scopes_by_resource
                    .get(&(req.tenant_id, req.resource_id))
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                match scopes.iter().find(|s| s.name == *scope_name) {
                    Some(s) => Some(s.id),
                    None => {
                        pre.push(PreDecision::Decided(AccessDecision::Deny(format!(
                            "scope '{}' not found on resource",
                            scope_name
                        ))));
                        continue;
                    }
                }
            } else {
                None
            };

            for rid in &unique_role_ids {
                if grant_role_seen.insert((req.tenant_id, *rid)) {
                    grant_role_ids.entry(req.tenant_id).or_default().push(*rid);
                }
            }

            pre.push(PreDecision::NeedsGrants {
                unique_role_ids,
                requested_scope_id,
            });
        }

        // --- Coalesce round-trip 4: fetch grants for every applicable role in
        //     the batch, one batched query per tenant.
        //
        // Keyed per-tenant (outer map keyed by `tenant_id`, inner by
        // `role_id`) rather than by bare `role_id` across the whole batch —
        // isomorphic to keying the flat map by `(tenant_id, role_id)`, and
        // mirrors the `(Uuid, Uuid)` key `grant_role_seen` already uses a few
        // lines above. `get_role_permission_grants_for_roles` returns a
        // `role_id`-keyed map for a *single* tenant per call (it is invoked
        // once per `tenant_id` in `grant_role_ids`), so a bare
        // `grants_by_role.extend(map)` here would merge those per-tenant maps
        // into one flat `role_id`-keyed map, and a `role_id` collision across
        // two tenants in the same batch would silently overwrite one tenant's
        // grants with another's. Nesting under `tenant_id` removes that
        // reliance on UUIDv4 role-id uniqueness for cross-tenant batch
        // isolation — a same-named `role_id` in two tenants' `Vec<Uuid>` below
        // simply lands in two different inner maps and can never collide.
        let mut grants_by_role: HashMap<Uuid, HashMap<Uuid, Vec<PermissionGrant>>> =
            HashMap::new();
        for (tenant_id, role_ids) in &grant_role_ids {
            let map = self
                .permission_repo
                .get_role_permission_grants_for_roles(*tenant_id, role_ids)
                .instrument(tracing::debug_span!(
                    "db.get_role_permission_grants_for_roles",
                    tenant_id = %tenant_id,
                    role_count = role_ids.len()
                ))
                .await?;
            grants_by_role.entry(*tenant_id).or_default().extend(map);
        }
        let empty_role_grants: HashMap<Uuid, Vec<PermissionGrant>> = HashMap::new();

        // --- Final pass: evaluate each item against the shared grants map,
        //     preserving input order.
        let mut decisions = Vec::with_capacity(requests.len());
        for (item, req) in pre.into_iter().zip(requests.iter()) {
            match item {
                PreDecision::Decided(d) => decisions.push(d),
                PreDecision::NeedsGrants {
                    unique_role_ids,
                    requested_scope_id,
                } => {
                    // Same two helpers the single-check path uses, so the
                    // batch path's deny-override semantics and reason codes
                    // cannot diverge from it. Scoped to this item's tenant
                    // before handing off, so `evaluate_grants` (shared with
                    // the single-check path, which is inherently
                    // single-tenant) never sees another tenant's role ids.
                    let tenant_grants = grants_by_role
                        .get(&req.tenant_id)
                        .unwrap_or(&empty_role_grants);
                    decisions.push(decision_for(
                        evaluate_grants(
                            &unique_role_ids,
                            tenant_grants,
                            &req.action,
                            requested_scope_id,
                        ),
                        &req.action,
                    ));
                }
            }
        }

        Ok(decisions)
    }
}

/// Outcome of resolving an optional scope name to a scope ID.
enum ScopeResolution {
    /// No scope was requested.
    None,
    /// Scope name resolved to this ID.
    Resolved(Uuid),
    /// Scope name was requested but does not exist on the resource — carries
    /// the ready-made deny decision.
    NotFound(AccessDecision),
}

#[cfg(test)]
mod tests {
    use super::{GrantOutcome, decision_for, evaluate_grants};
    use crate::types::AccessDecision;
    use axiam_core::models::permission::{PermissionEffect, PermissionGrant};
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn grant_with(action: &str, effect: PermissionEffect, scope_ids: Vec<Uuid>) -> PermissionGrant {
        PermissionGrant {
            permission: axiam_core::models::permission::Permission {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                action: action.into(),
                description: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            scope_ids,
            effect,
        }
    }

    fn allow(action: &str) -> PermissionGrant {
        grant_with(action, PermissionEffect::Allow, vec![])
    }

    fn deny(action: &str) -> PermissionGrant {
        grant_with(action, PermissionEffect::Deny, vec![])
    }

    /// Build a `(role_ids, grants_by_role)` pair from `(role, grants)` groups,
    /// preserving the order the roles are listed in — which is how these tests
    /// control whether a deny is scanned before or after an allow.
    fn roles(
        groups: Vec<Vec<PermissionGrant>>,
    ) -> (Vec<Uuid>, HashMap<Uuid, Vec<PermissionGrant>>) {
        let mut ids = Vec::new();
        let mut map = HashMap::new();
        for grants in groups {
            let id = Uuid::new_v4();
            ids.push(id);
            map.insert(id, grants);
        }
        (ids, map)
    }

    // -----------------------------------------------------------------
    // Pre-B1 behaviour, unchanged
    // -----------------------------------------------------------------

    /// A role with NO entry at all in the grants-by-role map must be skipped
    /// (the `grants_by_role.get(role_id)` lookup misses) rather than stopping
    /// the scan, so a later applicable role still matches. Order is controlled
    /// here so the grants-less role is scanned first.
    #[test]
    fn skips_a_role_with_no_grants_entry_and_checks_the_next() {
        let matching = Uuid::new_v4();
        let mut map = HashMap::new();
        map.insert(matching, vec![allow("read")]);
        let ids = vec![Uuid::new_v4(), matching];

        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::Allowed
        );
    }

    #[test]
    fn no_role_granting_the_action_is_no_grant_not_denied_by_rule() {
        let (ids, map) = roles(vec![vec![allow("write")]]);

        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::NoGrant,
            "absence of a grant must not masquerade as an explicit deny — the \
             two mean opposite things to the caller"
        );
    }

    // -----------------------------------------------------------------
    // B1 — the deny-override precedence table
    // (claude_dev/deny-override-design.md §2.2)
    // -----------------------------------------------------------------

    /// Row 6: allow and deny of the same action at equal specificity. Deny
    /// wins — there is no tie to break.
    #[test]
    fn deny_beats_allow_on_the_same_role() {
        let (ids, map) = roles(vec![vec![allow("read"), deny("read")]]);
        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::DeniedByRule
        );
    }

    /// The result must not depend on the order grants are scanned in — a rule
    /// set has one answer, not one answer per query plan.
    #[test]
    fn deny_wins_regardless_of_scan_order() {
        let deny_first = roles(vec![vec![deny("read")], vec![allow("read")]]);
        let allow_first = roles(vec![vec![allow("read")], vec![deny("read")]]);

        assert_eq!(
            evaluate_grants(&deny_first.0, &deny_first.1, "read", None),
            GrantOutcome::DeniedByRule
        );
        assert_eq!(
            evaluate_grants(&allow_first.0, &allow_first.1, "read", None),
            GrantOutcome::DeniedByRule,
            "an allow scanned before a deny must still lose to it"
        );
    }

    /// Rows 3 and 4: hierarchy direction does not matter. Both an
    /// ancestor-scoped and a descendant-scoped role reach this function as
    /// applicable roles, so "deny on the parent, allow on the child" and its
    /// mirror both reduce to the same set here — and both deny.
    ///
    /// Row 4 is the one to read twice: **a child allow does not override an
    /// inherited deny.**
    #[test]
    fn a_child_allow_does_not_override_an_inherited_deny() {
        // The ancestor-scoped role carries the deny; the target-scoped role
        // carries the allow.
        let (ids, map) = roles(vec![vec![deny("read")], vec![allow("read")]]);
        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::DeniedByRule
        );
    }

    /// Row 7/8: a deny arriving via a group-inherited or global role is still
    /// a deny. Applicability decides which roles are in the set; it does not
    /// decide precedence within it.
    #[test]
    fn deny_from_any_applicable_role_wins() {
        let (ids, map) = roles(vec![
            vec![allow("read")], // directly assigned
            vec![allow("read")], // global
            vec![deny("read")],  // group-inherited
        ]);
        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::DeniedByRule
        );
    }

    /// Row 5: denies are per action. A deny on `write` says nothing about
    /// `read`.
    #[test]
    fn a_deny_on_another_action_does_not_leak() {
        let (ids, map) = roles(vec![vec![allow("read"), deny("write")]]);
        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::Allowed
        );
        assert_eq!(
            evaluate_grants(&ids, &map, "write", None),
            GrantOutcome::DeniedByRule
        );
    }

    // -----------------------------------------------------------------
    // B1 §2.3 — scope interaction
    // -----------------------------------------------------------------

    /// A deny with NO scopes is a wildcard: it masks the action for every
    /// scope, and for unscoped checks too.
    #[test]
    fn an_unscoped_deny_masks_every_scope() {
        let pii = Uuid::new_v4();
        let billing = Uuid::new_v4();
        let (ids, map) = roles(vec![vec![
            grant_with("read", PermissionEffect::Allow, vec![pii, billing]),
            deny("read"),
        ]]);

        for scope in [None, Some(pii), Some(billing)] {
            assert_eq!(
                evaluate_grants(&ids, &map, "read", scope),
                GrantOutcome::DeniedByRule,
                "a resource-level deny is stronger than any scope-level allow"
            );
        }
    }

    /// A scoped deny masks only the scopes it names.
    #[test]
    fn a_scoped_deny_masks_only_that_scope() {
        let pii = Uuid::new_v4();
        let billing = Uuid::new_v4();
        let (ids, map) = roles(vec![vec![
            allow("read"), // wildcard allow
            grant_with("read", PermissionEffect::Deny, vec![pii]),
        ]]);

        assert_eq!(
            evaluate_grants(&ids, &map, "read", Some(pii)),
            GrantOutcome::DeniedByRule
        );
        assert_eq!(
            evaluate_grants(&ids, &map, "read", Some(billing)),
            GrantOutcome::Allowed,
            "a deny scoped to `pii` must not touch `billing`"
        );
    }

    /// An unscoped *request* against a scoped deny: the deny's scope list does
    /// not contain "no scope", but the request names no scope either, so the
    /// grant applies. This is the same rule allows have always followed —
    /// stated as a test because getting it wrong in the deny direction is a
    /// silent privilege escalation.
    #[test]
    fn an_unscoped_request_matches_a_scoped_deny() {
        let pii = Uuid::new_v4();
        let (ids, map) = roles(vec![vec![
            allow("read"),
            grant_with("read", PermissionEffect::Deny, vec![pii]),
        ]]);

        assert_eq!(
            evaluate_grants(&ids, &map, "read", None),
            GrantOutcome::DeniedByRule
        );
    }

    // -----------------------------------------------------------------
    // B1 §5 — the property that motivates deny-override
    // -----------------------------------------------------------------

    /// **Adding a deny rule can never widen access.**
    ///
    /// This is the one guarantee deny-override buys over most-specific-wins,
    /// and it is what a future "most-specific-wins" refactor would break. The
    /// search is exhaustive over a small rule space rather than randomised, so
    /// it fails deterministically.
    #[test]
    fn adding_a_deny_can_never_widen_access() {
        let scope_a = Uuid::new_v4();
        let scope_b = Uuid::new_v4();

        let candidate_grants = [
            allow("read"),
            allow("write"),
            grant_with("read", PermissionEffect::Allow, vec![scope_a]),
            deny("read"),
            grant_with("read", PermissionEffect::Deny, vec![scope_a]),
            grant_with("write", PermissionEffect::Deny, vec![scope_b]),
        ];
        let requests = [
            ("read", None),
            ("read", Some(scope_a)),
            ("read", Some(scope_b)),
            ("write", None),
            ("write", Some(scope_b)),
        ];

        // Every subset of the candidate grants, as a base rule set.
        for mask in 0u32..(1 << candidate_grants.len()) {
            let base: Vec<PermissionGrant> = candidate_grants
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, g)| g.clone())
                .collect();

            // Every possible additional DENY rule.
            for extra in candidate_grants.iter().filter(|g| g.effect.is_deny()) {
                let mut widened = base.clone();
                widened.push(extra.clone());

                let (base_ids, base_map) = roles(vec![base.clone()]);
                let (wide_ids, wide_map) = roles(vec![widened]);

                for (action, scope) in requests {
                    let before = evaluate_grants(&base_ids, &base_map, action, scope);
                    let after = evaluate_grants(&wide_ids, &wide_map, action, scope);

                    if before != GrantOutcome::Allowed {
                        assert_ne!(
                            after,
                            GrantOutcome::Allowed,
                            "adding a deny turned a non-allow into an allow for \
                             ({action}, {scope:?}) — deny-override is broken"
                        );
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Reason codes (SDK contract §11)
    // -----------------------------------------------------------------

    #[test]
    fn reason_codes_distinguish_the_two_denials() {
        assert_eq!(
            decision_for(GrantOutcome::Allowed, "read").reason_code(),
            "allowed"
        );
        assert_eq!(
            decision_for(GrantOutcome::NoGrant, "read").reason_code(),
            "no_grant"
        );
        assert_eq!(
            decision_for(GrantOutcome::DeniedByRule, "read").reason_code(),
            "denied_by_rule"
        );
    }

    #[test]
    fn both_denials_refuse_access() {
        for outcome in [GrantOutcome::NoGrant, GrantOutcome::DeniedByRule] {
            assert!(!decision_for(outcome, "read").is_allowed());
        }
        assert!(decision_for(GrantOutcome::Allowed, "read").is_allowed());
    }

    #[test]
    fn deny_reasons_name_the_action() {
        for outcome in [GrantOutcome::NoGrant, GrantOutcome::DeniedByRule] {
            assert!(
                decision_for(outcome, "publish")
                    .reason()
                    .contains("publish"),
                "a deny reason must name the action it refused"
            );
        }
        assert_eq!(AccessDecision::Allow.reason(), "");
    }
}
