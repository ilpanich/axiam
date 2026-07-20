//! D1: round-trip-count tests for the coalesced batch authorization path.
//!
//! These tests use **counting mock repositories** rather than the real
//! SurrealDB in-memory repos so we can assert *how many* DB round-trips the
//! engine issues — the core D1 win. The benchmark's batch shape is 5 checks
//! that all share one subject and one resource; the pre-D1 path issued the
//! role-assignment and ancestor lookups once **per item** (5× each), while the
//! coalesced [`AuthorizationEngine::check_access_batch`] resolves each shared
//! lookup exactly **once**.
//!
//! ## Why round-trip counts, not wall-clock ratios
//!
//! The plan's acceptance target ("batch < 3× single") is a *latency* ratio, but
//! a wall-clock assertion in CI is flaky: against an in-memory mock every query
//! is sub-microsecond, so the ratio is dominated by scheduler/allocator noise
//! and would either false-fail or need such a loose bound it proves nothing.
//! The *mechanism* that produces the latency win is the round-trip reduction,
//! and that is exactly and deterministically countable. We therefore assert the
//! round-trip counts directly (robust, precise) and derive the latency claim
//! from them: on the real stack each round-trip is one serialized HTTP call
//! over the single shared SurrealDB connection, so 3 round-trips for a batch of
//! 5 vs 3 for a single check is inherently sub-3×. The end-to-end latency ratio
//! is confirmed on the benchmark laptop (pending laptop re-run).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
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

fn role(id: Uuid, tenant: Uuid, is_global: bool) -> Role {
    Role {
        id,
        tenant_id: tenant,
        name: "r".into(),
        description: String::new(),
        is_global,
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

fn resource(id: Uuid, tenant: Uuid) -> Resource {
    Resource {
        id,
        tenant_id: tenant,
        name: "res".into(),
        resource_type: "service".into(),
        parent_id: None,
        metadata: serde_json::Value::Null,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Counting mock repositories
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Counters {
    role_assignments: Arc<AtomicUsize>,
    ancestors: Arc<AtomicUsize>,
    grants: Arc<AtomicUsize>,
    scopes: Arc<AtomicUsize>,
}

impl Counters {
    fn reset(&self) {
        self.role_assignments.store(0, Ordering::SeqCst);
        self.ancestors.store(0, Ordering::SeqCst);
        self.grants.store(0, Ordering::SeqCst);
        self.scopes.store(0, Ordering::SeqCst);
    }
    fn get(a: &Arc<AtomicUsize>) -> usize {
        a.load(Ordering::SeqCst)
    }
}

/// Role repo: returns seeded assignments per subject, counting each lookup.
struct MockRoleRepo {
    counter: Arc<AtomicUsize>,
    by_subject: HashMap<Uuid, Vec<RoleAssignment>>,
}

impl RoleRepository for MockRoleRepo {
    async fn get_user_role_assignments(
        &self,
        _tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(self.by_subject.get(&user_id).cloned().unwrap_or_default())
    }

    // --- unused by the engine hot path ---
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

/// Permission repo: returns seeded grants per role, counting the batched lookup.
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

    // --- unused ---
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

/// Resource repo: returns seeded ancestors per resource, counting each lookup.
struct MockResourceRepo {
    counter: Arc<AtomicUsize>,
    ancestors: HashMap<Uuid, Vec<Resource>>,
}

impl ResourceRepository for MockResourceRepo {
    async fn get_ancestors(&self, _tenant_id: Uuid, id: Uuid) -> AxiamResult<Vec<Resource>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(self.ancestors.get(&id).cloned().unwrap_or_default())
    }

    // --- unused ---
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

/// Scope repo: returns seeded scopes per resource, counting each lookup.
struct MockScopeRepo {
    counter: Arc<AtomicUsize>,
    by_resource: HashMap<Uuid, Vec<Scope>>,
}

impl ScopeRepository for MockScopeRepo {
    async fn list_by_resource(
        &self,
        _tenant_id: Uuid,
        resource_id: Uuid,
    ) -> AxiamResult<Vec<Scope>> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .by_resource
            .get(&resource_id)
            .cloned()
            .unwrap_or_default())
    }

    // --- unused ---
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

/// Group repo: never touched by the engine hot path (group expansion happens
/// inside the role repo's `get_user_role_assignments`).
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

/// Build an engine where `subject` has a role granting `action` on `resource`.
fn build_engine(
    tenant: Uuid,
    subject: Uuid,
    resource_id: Uuid,
    action: &str,
) -> (MockEngine, Counters) {
    let counters = Counters::default();
    let role_id = Uuid::new_v4();

    let mut by_subject = HashMap::new();
    by_subject.insert(
        subject,
        vec![RoleAssignment {
            role: role(role_id, tenant, false),
            resource_id: Some(resource_id),
        }],
    );

    let mut by_role = HashMap::new();
    by_role.insert(
        role_id,
        vec![PermissionGrant {
            permission: permission(action, tenant),
            scope_ids: vec![],
        }],
    );

    let engine = AuthorizationEngine::new(
        MockRoleRepo {
            counter: counters.role_assignments.clone(),
            by_subject,
        },
        MockPermissionRepo {
            counter: counters.grants.clone(),
            by_role,
        },
        MockResourceRepo {
            counter: counters.ancestors.clone(),
            ancestors: HashMap::new(),
        },
        MockScopeRepo {
            counter: counters.scopes.clone(),
            by_resource: HashMap::new(),
        },
        MockGroupRepo,
    );

    (engine, counters)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The core D1 assertion: a same-subject / same-resource batch of 5 must NOT
/// issue 5× the role-assignment and ancestor lookups. It coalesces to exactly
/// one of each (plus one batched grants query) — vs 5 of each for the
/// sequential per-item path.
#[tokio::test]
async fn same_subject_batch_of_5_coalesces_round_trips() {
    let tenant = Uuid::new_v4();
    let subject = Uuid::new_v4();
    let resource_id = Uuid::new_v4();
    let (engine, counters) = build_engine(tenant, subject, resource_id, "read");

    let requests: Vec<AccessRequest> = (0..5)
        .map(|_| AccessRequest {
            tenant_id: tenant,
            subject_id: subject,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .collect();

    // --- Baseline: sequential per-item check_access issues 5× each lookup.
    counters.reset();
    let mut sequential = Vec::new();
    for req in &requests {
        sequential.push(engine.check_access(req).await.unwrap());
    }
    assert_eq!(
        Counters::get(&counters.role_assignments),
        5,
        "sequential path issues one role-assignment lookup per item"
    );
    assert_eq!(Counters::get(&counters.ancestors), 5);
    assert_eq!(Counters::get(&counters.grants), 5);

    // --- Coalesced batch: exactly ONE of each shared lookup.
    counters.reset();
    let batched = engine.check_access_batch(&requests).await.unwrap();

    assert_eq!(
        Counters::get(&counters.role_assignments),
        1,
        "batch coalesces the role-assignment lookup to once per (tenant, subject)"
    );
    assert_eq!(
        Counters::get(&counters.ancestors),
        1,
        "batch coalesces the ancestor lookup to once per (tenant, resource)"
    );
    assert_eq!(
        Counters::get(&counters.grants),
        1,
        "batch fetches grants for the whole batch in a single query"
    );

    // --- Decisions must be byte-identical to the sequential path, in order.
    assert_eq!(batched, sequential);
    assert!(batched.iter().all(|d| *d == AccessDecision::Allow));
}

/// Distinct subjects/resources still coalesce per *group*: two subjects across
/// four items issue two role-assignment lookups (one per subject), not four,
/// and decisions match the per-item engine exactly (order preserved incl. a
/// deny in the middle).
#[tokio::test]
async fn distinct_groups_coalesce_per_group_and_preserve_order() {
    let tenant = Uuid::new_v4();
    let subject_a = Uuid::new_v4();
    let subject_b = Uuid::new_v4();
    let resource_x = Uuid::new_v4();
    let resource_y = Uuid::new_v4();
    let counters = Counters::default();

    let role_a = Uuid::new_v4();
    let role_b = Uuid::new_v4();

    // subject_a: read on resource_x. subject_b: write on resource_y.
    let mut by_subject = HashMap::new();
    by_subject.insert(
        subject_a,
        vec![RoleAssignment {
            role: role(role_a, tenant, false),
            resource_id: Some(resource_x),
        }],
    );
    by_subject.insert(
        subject_b,
        vec![RoleAssignment {
            role: role(role_b, tenant, false),
            resource_id: Some(resource_y),
        }],
    );

    let mut by_role = HashMap::new();
    by_role.insert(
        role_a,
        vec![PermissionGrant {
            permission: permission("read", tenant),
            scope_ids: vec![],
        }],
    );
    by_role.insert(
        role_b,
        vec![PermissionGrant {
            permission: permission("write", tenant),
            scope_ids: vec![],
        }],
    );

    let mut ancestors = HashMap::new();
    ancestors.insert(resource_x, vec![resource(resource_x, tenant)]);
    ancestors.insert(resource_y, vec![resource(resource_y, tenant)]);

    let engine = AuthorizationEngine::new(
        MockRoleRepo {
            counter: counters.role_assignments.clone(),
            by_subject,
        },
        MockPermissionRepo {
            counter: counters.grants.clone(),
            by_role,
        },
        MockResourceRepo {
            counter: counters.ancestors.clone(),
            ancestors,
        },
        MockScopeRepo {
            counter: counters.scopes.clone(),
            by_resource: HashMap::new(),
        },
        MockGroupRepo,
    );

    // Order: A/read/x (allow), A/write/x (deny — no grant), B/write/y (allow),
    // A/read/x (allow again — same group as item 0).
    let requests = vec![
        AccessRequest {
            tenant_id: tenant,
            subject_id: subject_a,
            action: "read".into(),
            resource_id: resource_x,
            scope: None,
        },
        AccessRequest {
            tenant_id: tenant,
            subject_id: subject_a,
            action: "write".into(),
            resource_id: resource_x,
            scope: None,
        },
        AccessRequest {
            tenant_id: tenant,
            subject_id: subject_b,
            action: "write".into(),
            resource_id: resource_y,
            scope: None,
        },
        AccessRequest {
            tenant_id: tenant,
            subject_id: subject_a,
            action: "read".into(),
            resource_id: resource_x,
            scope: None,
        },
    ];

    // Sequential per-item baseline for the decisions.
    counters.reset();
    let mut sequential = Vec::new();
    for req in &requests {
        sequential.push(engine.check_access(req).await.unwrap());
    }

    counters.reset();
    let batched = engine.check_access_batch(&requests).await.unwrap();

    // Two distinct subjects -> 2 role-assignment lookups (not 4).
    assert_eq!(Counters::get(&counters.role_assignments), 2);
    // Two distinct resources -> 2 ancestor lookups (not 4).
    assert_eq!(Counters::get(&counters.ancestors), 2);
    // One batched grants query for the whole batch.
    assert_eq!(Counters::get(&counters.grants), 1);

    assert_eq!(batched, sequential);
    assert_eq!(batched[0], AccessDecision::Allow);
    assert!(matches!(batched[1], AccessDecision::Deny(_)));
    assert_eq!(batched[2], AccessDecision::Allow);
    assert_eq!(batched[3], AccessDecision::Allow);
}

/// A subject with no roles short-circuits to the same deny reason as the
/// single-check path, and issues no ancestor/grants lookups for that item.
#[tokio::test]
async fn empty_subject_denies_without_extra_round_trips() {
    let tenant = Uuid::new_v4();
    let known = Uuid::new_v4();
    let resource_id = Uuid::new_v4();
    let (engine, counters) = build_engine(tenant, known, resource_id, "read");

    let unknown = Uuid::new_v4(); // no assignments seeded
    let requests = vec![AccessRequest {
        tenant_id: tenant,
        subject_id: unknown,
        action: "read".into(),
        resource_id,
        scope: None,
    }];

    counters.reset();
    let batched = engine.check_access_batch(&requests).await.unwrap();

    assert_eq!(Counters::get(&counters.role_assignments), 1);
    // No applicable subject -> engine must not walk ancestors or fetch grants.
    assert_eq!(Counters::get(&counters.ancestors), 0);
    assert_eq!(Counters::get(&counters.grants), 0);
    assert_eq!(batched[0], AccessDecision::Deny("no roles assigned".into()));
}
