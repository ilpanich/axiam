//! I7(a) — query-plan pins for the authorization hot path.
//!
//! `AuthorizationEngine::evaluate` issues three logical SurrealDB round-trips
//! per uncached check:
//!
//! 1. `RoleRepository::get_user_role_assignments` — two `has_role` reads
//!    (direct + group-inherited),
//! 2. `ResourceRepository::get_ancestors` — a `->child_of->` graph walk,
//! 3. `PermissionRepository::get_role_permission_grants_for_roles` — one
//!    `grants` read covering every applicable role.
//!
//! Each of those touches an **edge table that grows with the whole database**
//! (`grants` holds every role→permission grant of every tenant), so a plan that
//! degrades to `TableScan` turns an O(1) authorization decision into an
//! O(total grants) scan. That is invisible in a unit test and invisible in a
//! small-seed benchmark; it only surfaces as the DB becoming the product's
//! throughput ceiling (benchmark run 4, task I7).
//!
//! These tests run `EXPLAIN` against an in-memory SurrealDB with the real
//! migrated schema and assert the *plan*, not a timing — so a future rewrite
//! that reintroduces a scan fails here rather than in production.
//!
//! Vocabulary (SurrealDB 3 `EXPLAIN` output): the `operator` field is
//! `TableScan` when the engine walks a whole table, `IndexScan` when it can
//! seek into a `DEFINE INDEX`, and `GraphScan`/`Graph…` for a `->edge->`
//! traversal, which is index-free *by construction* (edge pointers live under
//! the source record's own key prefix) and therefore also acceptable.

use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealRoleRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::Value as Json;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use surrealdb_types::RecordId;
use uuid::Uuid;

use axiam_core::models::role::AssignmentScope;
use axiam_test_support::test_password;

/// Boot an in-memory SurrealDB with the production schema applied.
async fn fresh_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// A migrated DB with one org/tenant/user/group and a role assigned **to the
/// group** — the shape the group-inherited half of the assignment lookup needs.
///
/// Returns `(db, tenant_id, user_id)`.
async fn seeded_db() -> (Surreal<Db>, Uuid, Uuid) {
    let db = fresh_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Plan Org".into(),
            slug: "plan-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Plan Tenant".into(),
            slug: "plan-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "planner".into(),
            email: "planner@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let group_repo = SurrealGroupRepository::new(db.clone());
    let group = group_repo
        .create(CreateGroup {
            tenant_id: tenant.id,
            name: "Planners".into(),
            description: "plan team".into(),
            metadata: None,
        })
        .await
        .unwrap();
    group_repo
        .add_member(tenant.id, user.id, group.id)
        .await
        .unwrap();
    let role_repo = SurrealRoleRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant.id,
            name: "inherited-role".into(),
            description: "assigned to the group".into(),
            is_global: true,
        })
        .await
        .unwrap();
    role_repo
        .assign_to_group(tenant.id, group.id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

/// Recursively collect every `operator` value in an `EXPLAIN` plan tree.
fn operators(plan: &[Json]) -> Vec<String> {
    fn walk(node: &Json, out: &mut Vec<String>) {
        if let Some(op) = node.get("operator").and_then(|o| o.as_str()) {
            out.push(op.to_owned());
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    for row in plan {
        walk(row, &mut out);
    }
    out
}

/// Recursively collect every `index` name referenced by an `IndexScan`.
fn indexes(plan: &[Json]) -> Vec<String> {
    fn walk(node: &Json, out: &mut Vec<String>) {
        if let Some(idx) = node
            .get("attributes")
            .and_then(|a| a.get("index"))
            .and_then(|i| i.as_str())
        {
            out.push(idx.to_owned());
        }
        if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
            for child in children {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    for row in plan {
        walk(row, &mut out);
    }
    out
}

fn assert_no_table_scan(plan: &[Json], what: &str) {
    let ops = operators(plan);
    assert!(
        !ops.iter().any(|o| o == "TableScan"),
        "{what} must not fall back to a full table scan; operators were {ops:?}, plan {plan:#?}"
    );
}

fn assert_uses_index(plan: &[Json], index: &str, what: &str) {
    let found = indexes(plan);
    assert!(
        found.iter().any(|i| i == index),
        "{what} must be served by index `{index}`; indexes used were {found:?}, plan {plan:#?}"
    );
}

// ---------------------------------------------------------------------------
// 1. has_role — direct role assignments (RoleRepository::get_user_role_assignments)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_role_assignment_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let mut res = db
        .query(
            "SELECT meta::id(out.id) AS record_id, out.tenant_id AS tenant_id, resource_id \
             FROM has_role \
             WHERE in = type::record('user', $user_id) AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind((
            "user_id",
            "11111111-1111-1111-1111-111111111111".to_string(),
        ))
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "direct has_role lookup");
    assert_uses_index(&plan, "idx_has_role_unique", "direct has_role lookup");
}

// ---------------------------------------------------------------------------
// 2. member_of — the group-membership sub-select
// ---------------------------------------------------------------------------

/// The shipped form carries the read-time tenant predicate added for
/// residual 1 (`AND out.tenant_id = $tenant_id`). That predicate must remain
/// free: `in =` still selects the row set through `idx_member_of_unique` and
/// the tenant comparison is a post-filter, so the plan must stay an
/// `IndexScan`, not degrade to a `TableScan`.
#[tokio::test]
async fn group_membership_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let mut res = db
        .query(
            "SELECT VALUE out FROM member_of \
             WHERE in = type::record('user', $user_id) \
             AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind((
            "user_id",
            "11111111-1111-1111-1111-111111111111".to_string(),
        ))
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "member_of lookup");
    assert_uses_index(&plan, "idx_member_of_unique", "member_of lookup");
}

// ---------------------------------------------------------------------------
// 2b. has_role — group-inherited role assignments
// ---------------------------------------------------------------------------

/// The inherited half of `get_user_role_assignments` must resolve the group set
/// **first** (`LET $group_records = …`) so the outer predicate sees a constant.
///
/// This needs real rows: an empty `$group_records` constant-folds to
/// `EmptyScan`, which would make the assertion vacuous.
#[tokio::test]
async fn inherited_role_assignment_lookup_is_index_satisfied() {
    let (db, tenant_id, user_id) = seeded_db().await;

    let mut res = db
        .query(
            "LET $group_records = (\
                 SELECT VALUE out FROM member_of \
                 WHERE in = type::record('user', $user_id) \
                 AND out.tenant_id = $tenant_id\
             );",
        )
        .query(
            "SELECT meta::id(out.id) AS record_id, resource_id FROM has_role \
             WHERE in IN $group_records AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind(("user_id", user_id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(1).unwrap();

    assert_no_table_scan(&plan, "group-inherited has_role lookup");
    assert_uses_index(
        &plan,
        "idx_has_role_unique",
        "group-inherited has_role lookup",
    );
}

/// Regression witness for the inherited half: inlining the membership
/// sub-select really does scan `has_role`.
#[tokio::test]
async fn inlined_membership_subselect_would_be_a_full_table_scan() {
    let (db, tenant_id, user_id) = seeded_db().await;

    let mut res = db
        .query(
            "SELECT resource_id FROM has_role \
             WHERE in IN (\
                 SELECT VALUE out FROM member_of \
                 WHERE in = type::record('user', $user_id) \
                 AND out.tenant_id = $tenant_id\
             ) AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind(("user_id", user_id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    let ops = operators(&plan);
    assert!(
        ops.iter().any(|o| o == "TableScan"),
        "the inlined sub-select form is expected to scan — if SurrealDB has \
         since learned to plan it, relax the LET-hoisting in \
         `SurrealRoleRepository::get_user_role_assignments` accordingly. \
         Operators were {ops:?}"
    );
}

/// The repository method itself still returns the group-inherited assignment
/// after the LET hoist — the plan change must not change the rows.
#[tokio::test]
async fn inherited_assignment_is_still_returned_after_the_let_hoist() {
    let (db, tenant_id, user_id) = seeded_db().await;
    let repo = SurrealRoleRepository::new(db);
    let assignments = repo
        .get_user_role_assignments(tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(
        assignments.len(),
        1,
        "the seeded user inherits exactly one role through its group: {assignments:?}"
    );
    assert_eq!(assignments[0].role.name, "inherited-role");
}

// ---------------------------------------------------------------------------
// 3. grants — the batched per-role permission read (the I7(a) regression)
// ---------------------------------------------------------------------------

/// The **shipped** predicate must be index-satisfied.
///
/// Before I7(a) this query read `WHERE meta::id(in) IN $role_ids`, which the
/// planner cannot use an index for (see the companion test below). Comparing
/// `in` against real record ids lets `idx_grants_unique` serve it.
#[tokio::test]
async fn batched_grant_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let role_records = vec![RecordId::new(
        "role",
        "33333333-3333-3333-3333-333333333333".to_string(),
    )];
    let mut res = db
        .query(
            "SELECT meta::id(in) AS role_id, out.action AS action, scope_ids \
             FROM grants \
             WHERE in IN $role_records AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind(("role_records", role_records))
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "batched grants lookup");
    assert_uses_index(&plan, "idx_grants_unique", "batched grants lookup");
}

/// Regression witness: the pre-I7(a) form really is a full table scan, so the
/// test above is pinning something real and not a tautology.
#[tokio::test]
async fn meta_id_predicate_would_be_a_full_table_scan() {
    let db = fresh_db().await;
    let mut res = db
        .query(
            "SELECT scope_ids FROM grants \
             WHERE meta::id(in) IN $role_ids AND out.tenant_id = $tenant_id EXPLAIN",
        )
        .bind((
            "role_ids",
            vec!["33333333-3333-3333-3333-333333333333".to_string()],
        ))
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    let ops = operators(&plan);
    assert!(
        ops.iter().any(|o| o == "TableScan"),
        "the meta::id(in) form is expected to scan — if SurrealDB has since \
         learned to plan it, relax `batched_grant_lookup_is_index_satisfied` \
         accordingly. Operators were {ops:?}"
    );
}

// ---------------------------------------------------------------------------
// 4. child_of — the resource-ancestor graph walk
// ---------------------------------------------------------------------------

/// `get_ancestors` climbs `->child_of->resource`. A graph traversal never
/// consults a secondary index (the edge pointers are stored under the source
/// record's key prefix), so the property to hold is simply that it does not
/// degrade into a scan of the `child_of` or `resource` tables.
#[tokio::test]
async fn ancestor_walk_does_not_scan() {
    let db = fresh_db().await;
    let mut res = db
        .query(
            "SELECT meta::id(id) AS record_id, tenant_id, name \
             FROM array::flatten(\
                 type::record('resource', $id).{..8+path}(\
                     ->child_of->(resource WHERE tenant_id = $tenant_id))) EXPLAIN",
        )
        .bind(("id", "44444444-4444-4444-4444-444444444444".to_string()))
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "resource ancestor walk");
}

// ---------------------------------------------------------------------------
// 5. scope — the lineage read behind scope inheritance
// ---------------------------------------------------------------------------

/// Every scoped authorization check now reads the scopes of the target
/// resource **and its ancestors**, because a scope grant inherits down the
/// hierarchy. That is one more query on the hottest path in the system, so it
/// gets the same treatment as the `has_role` and `grants` reads above: `IN`
/// over a bound array of ids, kept as a plain field comparison the composite
/// index can serve.
///
/// The alternative — one `list_by_resource` per hierarchy level — would put a
/// query per level on the same path, which is the N+1 shape I7(a) removed
/// elsewhere.
#[tokio::test]
async fn lineage_scope_lookup_is_index_satisfied() {
    let db = fresh_db().await;
    let mut res = db
        .query(
            "SELECT meta::id(id) AS record_id, * FROM scope \
             WHERE tenant_id = $tenant_id AND resource_id IN $resource_ids \
             ORDER BY created_at ASC EXPLAIN",
        )
        .bind((
            "tenant_id",
            "22222222-2222-2222-2222-222222222222".to_string(),
        ))
        .bind((
            "resource_ids",
            vec![
                "44444444-4444-4444-4444-444444444444".to_string(),
                "55555555-5555-5555-5555-555555555555".to_string(),
            ],
        ))
        .await
        .unwrap();
    let plan: Vec<Json> = res.take(0).unwrap();

    assert_no_table_scan(&plan, "lineage scope lookup");
    assert_uses_index(&plan, "idx_scope_resource_name", "lineage scope lookup");
}
