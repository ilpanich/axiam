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

use crate::decision_cache::DecisionCache;
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

/// Given the applicable role IDs and the (shared) grants-by-role map, decide
/// whether any grant matches `action` under the optional `requested_scope_id`.
///
/// Wildcard grants (empty `scope_ids`) match any requested scope; otherwise the
/// requested scope must be present in the grant's scope list. When no scope is
/// requested, an action match is sufficient.
fn grants_allow(
    unique_role_ids: &[Uuid],
    grants_by_role: &HashMap<Uuid, Vec<PermissionGrant>>,
    action: &str,
    requested_scope_id: Option<Uuid>,
) -> bool {
    for role_id in unique_role_ids {
        let Some(grants) = grants_by_role.get(role_id) else {
            continue;
        };
        for grant in grants {
            if grant.permission.action != action {
                continue;
            }
            match requested_scope_id {
                Some(scope_id) => {
                    if grant.scope_ids.is_empty() || grant.scope_ids.contains(&scope_id) {
                        return true;
                    }
                }
                None => return true,
            }
        }
    }
    false
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
        }
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

    /// Immediately drop every cached decision for `tenant_id`. No-op when no
    /// cache is attached. Called by the REST mutation handlers for coarse,
    /// access-narrowing changes whose affected-subject set isn't known without
    /// a query (grant revoke, role/permission delete or update, group-role
    /// unassignment, resource reparent/delete).
    pub fn invalidate_tenant(&self, tenant_id: Uuid) {
        if let Some(cache) = self.decision_cache.as_ref() {
            cache.invalidate_tenant(tenant_id);
        }
    }

    /// Immediately drop every cached decision for a single `subject_id` within
    /// `tenant_id`. No-op when no cache is attached. Called by the REST mutation
    /// handlers when exactly one subject's effective permissions change (user
    /// role unassign/assign, group membership add/remove).
    pub fn invalidate_subject(&self, tenant_id: Uuid, subject_id: Uuid) {
        if let Some(cache) = self.decision_cache.as_ref() {
            cache.invalidate_subject(tenant_id, subject_id);
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

        if grants_allow(
            &unique_role_ids,
            &grants_by_role,
            &request.action,
            requested_scope_id,
        ) {
            Ok(AccessDecision::Allow)
        } else {
            Ok(AccessDecision::Deny(format!(
                "no permission grants action '{}'",
                request.action
            )))
        }
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

    /// Evaluate an ordered batch of authorization checks, coalescing the shared
    /// DB lookups so that items repeating the same subject or resource resolve
    /// each lookup **once** instead of once per item.
    ///
    /// The returned `Vec` has the same length and order as `requests`; result
    /// `i` is the decision for `requests[i]` and is byte-identical to what
    /// [`Self::check_access`] would return for that request in isolation.
    ///
    /// Round-trip reduction for the benchmark shape (5 items, one shared subject
    /// and resource, no scope): **15 round-trips → 3** — one
    /// `get_user_role_assignments`, one `get_ancestors`, and one batched
    /// `get_role_permission_grants_for_roles` across every applicable role in
    /// the batch.
    pub async fn check_access_batch(
        &self,
        requests: &[AccessRequest],
    ) -> AxiamResult<Vec<AccessDecision>> {
        // D7: with no cache attached, this is exactly the D1 coalesced path —
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
        let mut grants_by_role: HashMap<Uuid, Vec<PermissionGrant>> = HashMap::new();
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
            grants_by_role.extend(map);
        }

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
                    if grants_allow(
                        &unique_role_ids,
                        &grants_by_role,
                        &req.action,
                        requested_scope_id,
                    ) {
                        decisions.push(AccessDecision::Allow);
                    } else {
                        decisions.push(AccessDecision::Deny(format!(
                            "no permission grants action '{}'",
                            req.action
                        )));
                    }
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
