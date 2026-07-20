//! D7: authorization decision cache — integration + security tests.
//!
//! These tests exercise the [`AuthorizationEngine`] with a [`DecisionCache`]
//! attached (the feature-flagged fast path) against **mutable counting mock
//! repositories**: the mocks both (a) count DB round-trips so we can prove a
//! cache hit skips the DB, and (b) let a test mutate the seeded data at runtime
//! to simulate a revocation landing in the store.
//!
//! The headline test is [`revocation_invalidation_denies_immediately`]: it
//! proves that a removed grant is enforced **immediately** via the engine's
//! event-driven invalidation hook (`invalidate_subject`, which is exactly what
//! the REST `unassign_from_user` / group `remove_member` handlers call through
//! the `AuthzChecker` trait) — NOT after waiting for the TTL. A control case
//! (mutate the store but skip invalidation) shows the cache *would* otherwise
//! serve a stale allow within the TTL, isolating invalidation as the mechanism
//! that enforces the revocation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_authz::{AuthorizationEngine, DecisionCache, DecisionCacheConfig};
use axiam_core::error::AxiamResult;
use axiam_core::models::group::{CreateGroup, Group, UpdateGroup};
use axiam_core::models::permission::{
    CreatePermission, Permission, PermissionGrant, UpdatePermission,
};
use axiam_core::models::resource::{CreateResource, Resource, UpdateResource};
use axiam_core::models::role::{CreateRole, Role, RoleAssignment, UpdateRole};
use axiam_core::models::scope::{CreateScope, Scope, UpdateScope};
use axiam_core::models::user::User;
use axiam_core::repository::{
    GroupRepository, PaginatedResult, Pagination, PermissionRepository, ResourceRepository,
    RoleRepository, ScopeRepository,
};
use chrono::Utc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Model builders
// ---------------------------------------------------------------------------

fn role(id: Uuid, tenant: Uuid) -> Role {
    Role {
        id,
        tenant_id: tenant,
        name: "r".into(),
        description: String::new(),
        is_global: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn permission(action: &str, tenant: Uuid) -> Permission {
    Permission {
        id: Uuid::new_v4(),
        tenant_id: tenant,
        action: action.into(),
        description: String::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Mutable, counting mock repositories
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Counters {
    role_assignments: Arc<AtomicUsize>,
    ancestors: Arc<AtomicUsize>,
    grants: Arc<AtomicUsize>,
}

impl Counters {
    fn get(a: &Arc<AtomicUsize>) -> usize {
        a.load(Ordering::SeqCst)
    }
}

/// Role repo whose per-subject assignments can be mutated at runtime (to
/// simulate a role unassignment landing in the store), counting each lookup.
#[derive(Clone)]
struct MockRoleRepo {
    counter: Arc<AtomicUsize>,
    by_subject: Arc<Mutex<HashMap<Uuid, Vec<RoleAssignment>>>>,
}

impl MockRoleRepo {
    /// Simulate the DB effect of unassigning every role from `subject`.
    fn revoke_all_roles(&self, subject: Uuid) {
        self.by_subject.lock().unwrap().remove(&subject);
    }
}

impl RoleRepository for MockRoleRepo {
    async fn get_user_role_assignments(
        &self,
        _tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .by_subject
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn create(&self, _input: CreateRole) -> AxiamResult<Role> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _id: Uuid) -> AxiamResult<Role> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _id: Uuid, _input: UpdateRole) -> AxiamResult<Role> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _id: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<Role>> {
        unimplemented!()
    }
    async fn assign_to_user(
        &self,
        _t: Uuid,
        _u: Uuid,
        _r: Uuid,
        _res: Option<Uuid>,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn unassign_from_user(
        &self,
        _t: Uuid,
        _u: Uuid,
        _r: Uuid,
        _res: Option<Uuid>,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_user_roles(&self, _t: Uuid, _u: Uuid) -> AxiamResult<Vec<Role>> {
        unimplemented!()
    }
    async fn assign_to_group(
        &self,
        _t: Uuid,
        _g: Uuid,
        _r: Uuid,
        _res: Option<Uuid>,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn unassign_from_group(
        &self,
        _t: Uuid,
        _g: Uuid,
        _r: Uuid,
        _res: Option<Uuid>,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_group_roles(&self, _t: Uuid, _g: Uuid) -> AxiamResult<Vec<Role>> {
        unimplemented!()
    }
    async fn get_role_user_ids(&self, _t: Uuid, _r: Uuid) -> AxiamResult<Vec<Uuid>> {
        unimplemented!()
    }
    async fn get_role_group_ids(&self, _t: Uuid, _r: Uuid) -> AxiamResult<Vec<Uuid>> {
        unimplemented!()
    }
}

struct MockPermissionRepo {
    counter: Arc<AtomicUsize>,
    by_role: HashMap<Uuid, Vec<PermissionGrant>>,
}

impl PermissionRepository for MockPermissionRepo {
    async fn get_role_permission_grants_for_roles(
        &self,
        _tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> AxiamResult<HashMap<Uuid, Vec<PermissionGrant>>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let mut out = HashMap::new();
        for rid in role_ids {
            if let Some(grants) = self.by_role.get(rid) {
                out.insert(*rid, grants.clone());
            }
        }
        Ok(out)
    }

    async fn create(&self, _input: CreatePermission) -> AxiamResult<Permission> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _id: Uuid) -> AxiamResult<Permission> {
        unimplemented!()
    }
    async fn update(
        &self,
        _t: Uuid,
        _id: Uuid,
        _input: UpdatePermission,
    ) -> AxiamResult<Permission> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _id: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<Permission>> {
        unimplemented!()
    }
    async fn grant_to_role(&self, _t: Uuid, _r: Uuid, _p: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn revoke_from_role(&self, _t: Uuid, _r: Uuid, _p: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_role_permissions(&self, _t: Uuid, _r: Uuid) -> AxiamResult<Vec<Permission>> {
        unimplemented!()
    }
    async fn grant_to_role_with_scopes(
        &self,
        _t: Uuid,
        _r: Uuid,
        _p: Uuid,
        _s: Vec<Uuid>,
    ) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_role_permission_grants(
        &self,
        _t: Uuid,
        _r: Uuid,
    ) -> AxiamResult<Vec<PermissionGrant>> {
        unimplemented!()
    }
}

struct MockResourceRepo {
    counter: Arc<AtomicUsize>,
}

impl ResourceRepository for MockResourceRepo {
    async fn get_ancestors(&self, _tenant_id: Uuid, _id: Uuid) -> AxiamResult<Vec<Resource>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }

    async fn create(&self, _input: CreateResource) -> AxiamResult<Resource> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _id: Uuid) -> AxiamResult<Resource> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _id: Uuid, _input: UpdateResource) -> AxiamResult<Resource> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _id: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<Resource>> {
        unimplemented!()
    }
    async fn get_children(&self, _t: Uuid, _parent: Uuid) -> AxiamResult<Vec<Resource>> {
        unimplemented!()
    }
}

struct MockScopeRepo;

impl ScopeRepository for MockScopeRepo {
    async fn list_by_resource(&self, _t: Uuid, _r: Uuid) -> AxiamResult<Vec<Scope>> {
        Ok(Vec::new())
    }
    async fn create(&self, _input: CreateScope) -> AxiamResult<Scope> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _id: Uuid) -> AxiamResult<Scope> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _id: Uuid, _input: UpdateScope) -> AxiamResult<Scope> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _id: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
}

struct MockGroupRepo;

impl GroupRepository for MockGroupRepo {
    async fn create(&self, _input: CreateGroup) -> AxiamResult<Group> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _id: Uuid) -> AxiamResult<Group> {
        unimplemented!()
    }
    async fn update(&self, _t: Uuid, _id: Uuid, _input: UpdateGroup) -> AxiamResult<Group> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _id: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(&self, _t: Uuid, _p: Pagination) -> AxiamResult<PaginatedResult<Group>> {
        unimplemented!()
    }
    async fn add_member(&self, _t: Uuid, _u: Uuid, _g: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn remove_member(&self, _t: Uuid, _u: Uuid, _g: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn get_members(
        &self,
        _t: Uuid,
        _g: Uuid,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<User>> {
        unimplemented!()
    }
    async fn get_user_groups(&self, _t: Uuid, _u: Uuid) -> AxiamResult<Vec<Group>> {
        unimplemented!()
    }
}

type MockEngine = AuthorizationEngine<
    MockRoleRepo,
    MockPermissionRepo,
    MockResourceRepo,
    MockScopeRepo,
    MockGroupRepo,
>;

/// Build an engine (NO cache attached) where `subject` has a role granting
/// `action` on `resource`. Returns the engine, the mutable role repo handle
/// (to simulate revocation), and the DB counters.
fn build_engine(
    tenant: Uuid,
    subject: Uuid,
    resource_id: Uuid,
    action: &str,
) -> (MockEngine, MockRoleRepo, Counters) {
    let counters = Counters::default();
    let role_id = Uuid::new_v4();

    let mut by_subject = HashMap::new();
    by_subject.insert(
        subject,
        vec![RoleAssignment {
            role: role(role_id, tenant),
            resource_id: Some(resource_id),
        }],
    );

    let role_repo = MockRoleRepo {
        counter: counters.role_assignments.clone(),
        by_subject: Arc::new(Mutex::new(by_subject)),
    };

    let mut by_role = HashMap::new();
    by_role.insert(
        role_id,
        vec![PermissionGrant {
            permission: permission(action, tenant),
            scope_ids: vec![],
        }],
    );

    let engine = AuthorizationEngine::new(
        role_repo.clone(),
        MockPermissionRepo {
            counter: counters.grants.clone(),
            by_role,
        },
        MockResourceRepo {
            counter: counters.ancestors.clone(),
        },
        MockScopeRepo,
        MockGroupRepo,
    );

    (engine, role_repo, counters)
}

fn cache(ttl: Duration) -> Arc<DecisionCache> {
    Arc::new(DecisionCache::new(DecisionCacheConfig {
        ttl,
        max_entries_per_tenant: 10_000,
    }))
}

fn req(tenant: Uuid, subject: Uuid, resource: Uuid, action: &str) -> AccessRequest {
    AccessRequest {
        tenant_id: tenant,
        subject_id: subject,
        action: action.into(),
        resource_id: resource,
        scope: None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A cache hit returns the SAME decision as a miss, for an allow — and skips
/// the DB round-trips on the second call.
#[tokio::test]
async fn cache_hit_matches_miss_allow_and_skips_db() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, _repo, counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));
    let request = req(tenant, subject, resource, "read");

    let miss = engine.check_access(&request).await.unwrap();
    assert_eq!(miss, AccessDecision::Allow);
    assert_eq!(Counters::get(&counters.role_assignments), 1, "miss hits DB");

    let hit = engine.check_access(&request).await.unwrap();
    assert_eq!(hit, miss, "hit must equal miss");
    assert_eq!(
        Counters::get(&counters.role_assignments),
        1,
        "hit must NOT re-query the DB"
    );
}

/// A cache hit returns the SAME decision as a miss, for a deny (with its exact
/// reason preserved).
#[tokio::test]
async fn cache_hit_matches_miss_deny_with_reason() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, _repo, counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));
    // Ask for an action the subject's role does NOT grant → deny.
    let request = req(tenant, subject, resource, "delete");

    let miss = engine.check_access(&request).await.unwrap();
    assert_eq!(
        miss,
        AccessDecision::Deny("no permission grants action 'delete'".into())
    );
    let grants_after_miss = Counters::get(&counters.grants);

    let hit = engine.check_access(&request).await.unwrap();
    assert_eq!(hit, miss, "deny decision + reason must be cached verbatim");
    assert_eq!(
        Counters::get(&counters.grants),
        grants_after_miss,
        "deny hit must not re-query"
    );
}

/// TTL expiry forces a re-evaluation (the DB is queried again after the TTL).
#[tokio::test]
async fn ttl_expiry_forces_reevaluation() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, _repo, counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_millis(40)));
    let request = req(tenant, subject, resource, "read");

    engine.check_access(&request).await.unwrap();
    assert_eq!(Counters::get(&counters.role_assignments), 1);
    // Immediate second call: served from cache.
    engine.check_access(&request).await.unwrap();
    assert_eq!(Counters::get(&counters.role_assignments), 1);

    tokio::time::sleep(Duration::from_millis(60)).await;

    engine.check_access(&request).await.unwrap();
    assert_eq!(
        Counters::get(&counters.role_assignments),
        2,
        "after TTL the decision is re-evaluated against the DB"
    );
}

/// THE KEY TEST. Grant → check (allow, cached) → revoke through the mutation
/// path (store change + `invalidate_subject`) → check MUST deny immediately,
/// even though the TTL is long (60 s). Proves event-driven invalidation, not
/// TTL expiry.
#[tokio::test]
async fn revocation_invalidation_denies_immediately() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, repo, _counters) = build_engine(tenant, subject, resource, "read");
    // Long TTL: if enforcement relied on TTL this test would (wrongly) still
    // see an allow. Only event-driven invalidation can make it deny now.
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));
    let request = req(tenant, subject, resource, "read");

    // 1. Granted → allow, now cached.
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );
    // Confirm it is genuinely cached (a second call would be served without DB).
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );

    // 2. Revoke through the mutation path: the store now denies AND the handler
    //    fires the invalidation hook (this is exactly what the REST
    //    `unassign_from_user` handler calls via `AuthzChecker::invalidate_subject`).
    repo.revoke_all_roles(subject);
    engine.invalidate_subject(tenant, subject);

    // 3. The very next check must be denied — immediately, not after the TTL.
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Deny("no roles assigned".into()),
        "a revoked grant must be enforced immediately via invalidation"
    );
}

/// Control for the test above: WITHOUT the invalidation hook, the cache serves
/// a stale allow within the TTL. This isolates invalidation (not the store
/// change alone) as the mechanism that enforces a revocation before TTL —
/// exactly why the mutation-path hooks are security-critical.
#[tokio::test]
async fn without_invalidation_stale_allow_persists_until_ttl() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, repo, _counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));
    let request = req(tenant, subject, resource, "read");

    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );

    // Store change only — NO invalidation call.
    repo.revoke_all_roles(subject);

    // The cache still (dangerously) returns the stale allow — demonstrating why
    // the immediate invalidation hooks are required, and that a missed event is
    // only bounded by the TTL.
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow,
        "without invalidation the stale allow persists until TTL"
    );
}

/// `invalidate_tenant` (the conservative flush used for coarse revocations like
/// grant revoke / role delete) also enforces a revocation immediately.
#[tokio::test]
async fn tenant_flush_enforces_revocation_immediately() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, repo, _counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));
    let request = req(tenant, subject, resource, "read");

    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );

    repo.revoke_all_roles(subject);
    engine.invalidate_tenant(tenant); // e.g. revoke_from_role / role delete path

    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Deny("no roles assigned".into())
    );
}

/// Feature-flag-OFF path: with no cache attached, every check hits the DB
/// (nothing is cached) and decisions are exactly as today. Also proves a
/// revocation is enforced with zero invalidation calls (there's no cache to go
/// stale).
#[tokio::test]
async fn cache_disabled_behaves_exactly_as_today() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, repo, counters) = build_engine(tenant, subject, resource, "read");
    // NOTE: no `.with_decision_cache(..)` — this is the default-off path.
    let request = req(tenant, subject, resource, "read");

    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Allow
    );
    // Both calls hit the DB — no caching happened.
    assert_eq!(
        Counters::get(&counters.role_assignments),
        2,
        "with the flag off every check re-queries the DB"
    );

    // A revocation is enforced on the next call with NO invalidation call,
    // because there is no cache.
    repo.revoke_all_roles(subject);
    assert_eq!(
        engine.check_access(&request).await.unwrap(),
        AccessDecision::Deny("no roles assigned".into())
    );

    // Invalidation calls are harmless no-ops when no cache is attached.
    engine.invalidate_subject(tenant, subject);
    engine.invalidate_tenant(tenant);
}

/// The batch path is cached too: identical decisions on a second batch, DB
/// skipped, and a revocation via invalidation flips the cached allow to deny.
#[tokio::test]
async fn batch_path_caches_and_invalidates() {
    let (tenant, subject, resource) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (engine, repo, counters) = build_engine(tenant, subject, resource, "read");
    let engine = engine.with_decision_cache(cache(Duration::from_secs(60)));

    let batch: Vec<AccessRequest> = vec![
        req(tenant, subject, resource, "read"),
        req(tenant, subject, resource, "read"),
        req(tenant, subject, resource, "delete"), // deny
    ];

    let first = engine.check_access_batch(&batch).await.unwrap();
    assert_eq!(
        first,
        vec![
            AccessDecision::Allow,
            AccessDecision::Allow,
            AccessDecision::Deny("no permission grants action 'delete'".into()),
        ]
    );
    let ra_after_first = Counters::get(&counters.role_assignments);

    // Second identical batch: fully served from cache, no new DB round-trips.
    let second = engine.check_access_batch(&batch).await.unwrap();
    assert_eq!(second, first, "cached batch decisions identical + in order");
    assert_eq!(
        Counters::get(&counters.role_assignments),
        ra_after_first,
        "a fully-cached batch issues no DB round-trips"
    );

    // Revoke + invalidate → the previously-allowed items now deny immediately.
    repo.revoke_all_roles(subject);
    engine.invalidate_subject(tenant, subject);
    let third = engine.check_access_batch(&batch).await.unwrap();
    assert_eq!(
        third,
        vec![
            AccessDecision::Deny("no roles assigned".into()),
            AccessDecision::Deny("no roles assigned".into()),
            AccessDecision::Deny("no roles assigned".into()),
        ]
    );
}
