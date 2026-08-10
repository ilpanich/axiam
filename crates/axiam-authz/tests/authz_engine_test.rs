//! Integration tests for the authorization engine.

use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, PermissionRepository, ResourceRepository,
    RoleRepository, ScopeRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;
type TestEngine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

/// Spin up in-memory DB, run migrations, create org + tenant + user.
async fn setup() -> (
    Surreal<TestDb>,
    Uuid, // tenant_id
    Uuid, // user_id
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

/// Build an AuthorizationEngine from a db handle.
fn make_engine(db: &Surreal<TestDb>) -> TestEngine {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// Helper: create a resource.
async fn create_resource(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    name: &str,
    parent_id: Option<Uuid>,
) -> Uuid {
    let repo = SurrealResourceRepository::new(db.clone());
    let res = repo
        .create(CreateResource {
            tenant_id,
            name: name.into(),
            resource_type: "service".into(),
            parent_id,
            metadata: None,
        })
        .await
        .unwrap();
    res.id
}

/// Helper: create a role, permission, grant permission to role, and assign role to user.
async fn grant_user_role_permission(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    role_name: &str,
    is_global: bool,
    action: &str,
    resource_id: Option<Uuid>,
) -> (Uuid, Uuid) {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: role_name.into(),
            description: format!("Role: {role_name}"),
            is_global,
        })
        .await
        .unwrap();

    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: format!("Can {action}"),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, resource_id)
        .await
        .unwrap();

    (role.id, perm.id)
}

/// Helper: create role + permission, grant with scope constraints, assign to user.
async fn grant_user_role_permission_with_scopes(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    role_name: &str,
    action: &str,
    resource_id: Uuid,
    scope_ids: Vec<Uuid>,
) -> (Uuid, Uuid) {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: role_name.into(),
            description: format!("Role: {role_name}"),
            is_global: false,
        })
        .await
        .unwrap();

    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: format!("Can {action}"),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role_with_scopes(tenant_id, role.id, perm.id, scope_ids)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, Some(resource_id))
        .await
        .unwrap();

    (role.id, perm.id)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn direct_role_grants_access() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn default_deny_no_role() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert!(matches!(decision, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn default_deny_wrong_action() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "write".into(), // user only has "read"
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert!(matches!(decision, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn group_membership_inherits_roles() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    let group_repo = SurrealGroupRepository::new(db.clone());
    let group = group_repo
        .create(CreateGroup {
            tenant_id,
            name: "devs".into(),
            description: "developers".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Add user to group.
    group_repo
        .add_member(tenant_id, user_id, group.id)
        .await
        .unwrap();

    // Assign role to group (not user directly).
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "group-reader".into(),
            description: "read via group".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "read".into(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    role_repo
        .assign_to_group(tenant_id, group.id, role.id, Some(resource_id))
        .await
        .unwrap();

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn global_role_applies_to_any_resource() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    // Assign a global role (no resource scope).
    grant_user_role_permission(
        &db, tenant_id, user_id, "admin", true, "read", None, // global assignment
    )
    .await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn resource_scoped_role_denied_on_unrelated_resource() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_a = create_resource(&db, tenant_id, "svc-a", None).await;
    let resource_b = create_resource(&db, tenant_id, "svc-b", None).await;

    // Role scoped to resource_a only.
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_a),
    )
    .await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id: resource_b, // different resource
            scope: None,
        })
        .await
        .unwrap();

    assert!(matches!(decision, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn hierarchy_inheritance() {
    let (db, tenant_id, user_id) = setup().await;

    // Create: parent -> child
    let parent_id = create_resource(&db, tenant_id, "project-a", None).await;
    let child_id = create_resource(&db, tenant_id, "service-x", Some(parent_id)).await;

    // Assign role scoped to parent.
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "project-admin",
        false,
        "deploy",
        Some(parent_id),
    )
    .await;

    let engine = make_engine(&db);

    // Access child → should be allowed (inherits from parent).
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "deploy".into(),
            resource_id: child_id,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn hierarchy_does_not_go_up() {
    let (db, tenant_id, user_id) = setup().await;

    let parent_id = create_resource(&db, tenant_id, "project-a", None).await;
    let child_id = create_resource(&db, tenant_id, "service-x", Some(parent_id)).await;

    // Assign role scoped to child only.
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "svc-viewer",
        false,
        "read",
        Some(child_id),
    )
    .await;

    let engine = make_engine(&db);

    // Access parent → should be denied (child role doesn't propagate up).
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id: parent_id,
            scope: None,
        })
        .await
        .unwrap();

    assert!(matches!(decision, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn scope_validation() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "api-user",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    // Define a scope on the resource.
    let scope_repo = SurrealScopeRepository::new(db.clone());
    scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "users:list".into(),
            description: "list users".into(),
        })
        .await
        .unwrap();

    let engine = make_engine(&db);

    // Valid scope.
    let allowed = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("users:list".into()),
        })
        .await
        .unwrap();
    assert_eq!(allowed, AccessDecision::Allow);

    // Invalid scope.
    let denied = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("admin:nuke".into()),
        })
        .await
        .unwrap();
    assert!(matches!(denied, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn scoped_permission_grants_matching_scope() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    // Define two scopes on the resource.
    let scope_repo = SurrealScopeRepository::new(db.clone());
    let scope_a = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "users:list".into(),
            description: "list users".into(),
        })
        .await
        .unwrap();
    let _scope_b = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "users:write".into(),
            description: "write users".into(),
        })
        .await
        .unwrap();

    // Grant with scope constraint: only scope_a.
    grant_user_role_permission_with_scopes(
        &db,
        tenant_id,
        user_id,
        "scoped-reader",
        "read",
        resource_id,
        vec![scope_a.id],
    )
    .await;

    let engine = make_engine(&db);

    // Request matching scope → Allow.
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("users:list".into()),
        })
        .await
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn scoped_permission_denies_wrong_scope() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    let scope_repo = SurrealScopeRepository::new(db.clone());
    let scope_a = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "users:list".into(),
            description: "list users".into(),
        })
        .await
        .unwrap();
    let _scope_b = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "users:write".into(),
            description: "write users".into(),
        })
        .await
        .unwrap();

    // Grant limited to scope_a only.
    grant_user_role_permission_with_scopes(
        &db,
        tenant_id,
        user_id,
        "scoped-reader-2",
        "read",
        resource_id,
        vec![scope_a.id],
    )
    .await;

    let engine = make_engine(&db);

    // Request different scope → Deny.
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("users:write".into()),
        })
        .await
        .unwrap();
    assert!(matches!(decision, AccessDecision::Deny(_)));
}

#[tokio::test]
async fn wildcard_permission_grants_any_scope() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    let scope_repo = SurrealScopeRepository::new(db.clone());
    scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "anything".into(),
            description: "any scope".into(),
        })
        .await
        .unwrap();

    // Grant with empty scope_ids (wildcard).
    grant_user_role_permission_with_scopes(
        &db,
        tenant_id,
        user_id,
        "wildcard-reader",
        "read",
        resource_id,
        vec![], // wildcard
    )
    .await;

    let engine = make_engine(&db);

    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("anything".into()),
        })
        .await
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn multiple_scopes_in_grant() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    let scope_repo = SurrealScopeRepository::new(db.clone());
    let scope_x = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "scope-x".into(),
            description: "x".into(),
        })
        .await
        .unwrap();
    let scope_y = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "scope-y".into(),
            description: "y".into(),
        })
        .await
        .unwrap();

    // Grant with both scope_x and scope_y.
    grant_user_role_permission_with_scopes(
        &db,
        tenant_id,
        user_id,
        "multi-scoped",
        "read",
        resource_id,
        vec![scope_x.id, scope_y.id],
    )
    .await;

    let engine = make_engine(&db);

    // Access scope-y → Allow.
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("scope-y".into()),
        })
        .await
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);

    // Access scope-x → Allow.
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: Some("scope-x".into()),
        })
        .await
        .unwrap();
    assert_eq!(decision, AccessDecision::Allow);
}

#[tokio::test]
async fn tenant_isolation() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);

    // Query with a different tenant_id → should deny.
    let other_tenant = Uuid::new_v4();
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id: other_tenant,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert!(matches!(decision, AccessDecision::Deny(_)));
}

/// A subject can have two applicable roles where one has NO permissions
/// granted at all (so it has no entry in the batched grants map) and the
/// other grants the requested action. `grants_allow` must skip the
/// grants-less role (its `grants_by_role.get` lookup misses) and still find
/// the match on the second role, rather than short-circuiting on the first.
#[tokio::test]
async fn one_of_two_applicable_roles_has_no_grants_still_allows() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    // Role #1: assigned to the user on this resource, but never granted any
    // permission — absent from `get_role_permission_grants_for_roles`'s map.
    let role_repo = SurrealRoleRepository::new(db.clone());
    let empty_role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "empty".into(),
            description: "no grants".into(),
            is_global: false,
        })
        .await
        .unwrap();
    role_repo
        .assign_to_user(tenant_id, user_id, empty_role.id, Some(resource_id))
        .await
        .unwrap();

    // Role #2: same resource, grants "read".
    grant_user_role_permission(
        &db,
        tenant_id,
        user_id,
        "viewer",
        false,
        "read",
        Some(resource_id),
    )
    .await;

    let engine = make_engine(&db);
    let decision = engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id,
            scope: None,
        })
        .await
        .unwrap();

    assert_eq!(decision, AccessDecision::Allow);
}

// -----------------------------------------------------------------------
// B1 deny-override — the precedence table, END TO END
// (claude_dev/deny-override-design.md §2.2)
//
// The unit tests in `engine.rs` assert this table against `evaluate_grants`,
// which takes the applicable role IDs as an argument. That is the right place
// to pin the precedence rule, but it assumes away the layer the table's most
// important rows are actually *about*: rows 3, 4, 7 and 8 are claims that a
// deny arriving through the hierarchy, through a group, or through a global
// role survives `applicable_role_ids` and reaches the evaluator at all. A
// regression there would silently invert row 4 from deny to allow — a
// privilege escalation — while every unit test stayed green, because each one
// hands the evaluator two role IDs that are applicable by construction.
//
// These go through the real repositories, the real hierarchy walk and the real
// group/global applicability filter. They are the tests that would fail.
// -----------------------------------------------------------------------

/// Create the permission for `action`, or return the existing one.
///
/// Permissions are unique per (tenant, action), and every one of these tests
/// needs two *grants* of the same action with opposite effects — which is the
/// whole point of the table. So the permission is shared and the two grant
/// edges differ, which is also how a real tenant would express it.
async fn ensure_permission(db: &Surreal<TestDb>, tenant_id: Uuid, action: &str) -> Uuid {
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    match perm_repo
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: format!("Can {action}"),
        })
        .await
    {
        Ok(perm) => perm.id,
        Err(_) => {
            perm_repo
                .list(tenant_id, Default::default())
                .await
                .unwrap()
                .items
                .into_iter()
                .find(|p| p.action == action)
                .expect("permission exists after AlreadyExists")
                .id
        }
    }
}

/// One role's worth of grant: what it permits or refuses, and where it applies.
struct RoleSpec<'a> {
    name: &'a str,
    action: &'a str,
    effect: PermissionEffect,
    /// Empty means wildcard — see `deny-override-design.md` §2.3.
    scope_ids: Vec<Uuid>,
    /// `None` assigns the role globally (§2.2 row 8).
    resource_id: Option<Uuid>,
}

impl<'a> RoleSpec<'a> {
    fn allow(name: &'a str, action: &'a str, resource_id: Uuid) -> Self {
        Self {
            name,
            action,
            effect: PermissionEffect::Allow,
            scope_ids: Vec::new(),
            resource_id: Some(resource_id),
        }
    }

    fn deny(name: &'a str, action: &'a str, resource_id: Uuid) -> Self {
        Self {
            name,
            action,
            effect: PermissionEffect::Deny,
            scope_ids: Vec::new(),
            resource_id: Some(resource_id),
        }
    }

    fn global(mut self) -> Self {
        self.resource_id = None;
        self
    }

    fn scoped(mut self, scope_ids: Vec<Uuid>) -> Self {
        self.scope_ids = scope_ids;
        self
    }
}

/// Create a role carrying a single grant with an explicit effect, and assign it
/// to `user_id` where `spec` says.
async fn assign_role_with_effect(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    spec: RoleSpec<'_>,
) -> Uuid {
    let RoleSpec {
        name: role_name,
        action,
        effect,
        scope_ids,
        resource_id,
    } = spec;
    let is_global = resource_id.is_none();
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: role_name.into(),
            description: format!("Role: {role_name}"),
            is_global,
        })
        .await
        .unwrap();

    let permission_id = ensure_permission(db, tenant_id, action).await;

    perm_repo
        .grant_to_role_with_effect(tenant_id, role.id, permission_id, scope_ids, effect)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, resource_id)
        .await
        .unwrap();

    role.id
}

async fn check(
    engine: &TestEngine,
    tenant_id: Uuid,
    user_id: Uuid,
    action: &str,
    resource_id: Uuid,
    scope: Option<&str>,
) -> AccessDecision {
    engine
        .check_access(&AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: action.into(),
            resource_id,
            scope: scope.map(Into::into),
        })
        .await
        .unwrap()
}

/// Row 3: allow on `/fleet`, deny on `/fleet/decommissioned`. The deny cascades
/// down to `unit-7` and beats the ancestor allow.
#[tokio::test]
async fn deny_on_an_ancestor_cascades_down_and_beats_a_higher_allow() {
    let (db, tenant_id, user_id) = setup().await;
    let fleet = create_resource(&db, tenant_id, "fleet", None).await;
    let decommissioned = create_resource(&db, tenant_id, "decommissioned", Some(fleet)).await;
    let unit7 = create_resource(&db, tenant_id, "unit-7", Some(decommissioned)).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("fleet-reader", "read", fleet),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("decom-blocked", "read", decommissioned),
    )
    .await;

    let engine = make_engine(&db);

    // The allow alone still works one level up, which is what makes the deny
    // below a *change* rather than an absence.
    assert_eq!(
        check(&engine, tenant_id, user_id, "read", fleet, None).await,
        AccessDecision::Allow
    );
    assert!(matches!(
        check(&engine, tenant_id, user_id, "read", unit7, None).await,
        AccessDecision::DeniedByRule(_)
    ));
}

/// Row 4 — **the row to read twice.** Deny on `/fleet`, allow on
/// `/fleet/decommissioned`. A child allow does NOT override an inherited deny.
///
/// This is the row that distinguishes deny-override from most-specific-wins:
/// under most-specific-wins the nearer allow would win and the check would
/// return Allow. If this test ever goes green with `AccessDecision::Allow`, the
/// engine has silently switched semantics.
#[tokio::test]
async fn a_child_allow_does_not_override_an_inherited_deny_end_to_end() {
    let (db, tenant_id, user_id) = setup().await;
    let fleet = create_resource(&db, tenant_id, "fleet", None).await;
    let decommissioned = create_resource(&db, tenant_id, "decommissioned", Some(fleet)).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("fleet-blocked", "read", fleet),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("decom-reader", "read", decommissioned),
    )
    .await;

    let engine = make_engine(&db);

    assert!(
        matches!(
            check(&engine, tenant_id, user_id, "read", decommissioned, None).await,
            AccessDecision::DeniedByRule(_)
        ),
        "a nearer allow must not overturn an inherited deny — that is \
         most-specific-wins, which this engine deliberately does not implement"
    );
}

/// Row 7: the deny arrives through a group-inherited role while the allow is
/// assigned directly. Denies inherit through groups exactly as allows do.
#[tokio::test]
async fn a_group_inherited_deny_beats_a_directly_assigned_allow() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("direct-reader", "read", resource_id),
    )
    .await;

    let group_repo = SurrealGroupRepository::new(db.clone());
    let group = group_repo
        .create(CreateGroup {
            tenant_id,
            name: "quarantined".into(),
            description: "membership refuses read".into(),
            metadata: None,
        })
        .await
        .unwrap();
    group_repo
        .add_member(tenant_id, user_id, group.id)
        .await
        .unwrap();

    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "quarantine".into(),
            description: "deny read".into(),
            is_global: false,
        })
        .await
        .unwrap();
    let perm_id = ensure_permission(&db, tenant_id, "read").await;
    perm_repo
        .grant_to_role_with_effect(tenant_id, role.id, perm_id, vec![], PermissionEffect::Deny)
        .await
        .unwrap();
    role_repo
        .assign_to_group(tenant_id, group.id, role.id, Some(resource_id))
        .await
        .unwrap();

    let engine = make_engine(&db);

    assert!(matches!(
        check(&engine, tenant_id, user_id, "read", resource_id, None).await,
        AccessDecision::DeniedByRule(_)
    ));
}

/// Row 8: a global deny against a resource-scoped allow. Global vs
/// resource-scoped changes applicability, not precedence — and a global role is
/// applicable to *every* resource, so the deny reaches a resource the allow was
/// scoped to.
#[tokio::test]
async fn a_global_deny_beats_a_resource_scoped_allow() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("svc-a-reader", "read", resource_id),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("org-wide-block", "read", Uuid::nil()).global(),
    )
    .await;

    let engine = make_engine(&db);

    assert!(matches!(
        check(&engine, tenant_id, user_id, "read", resource_id, None).await,
        AccessDecision::DeniedByRule(_)
    ));
}

/// Row 5, end to end: denies are per action. A deny on `write` says nothing
/// about `read`, even when it sits on the same node.
#[tokio::test]
async fn a_deny_on_one_action_does_not_mask_another_end_to_end() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "svc-a", None).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("reader", "read", resource_id),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("no-write", "write", resource_id),
    )
    .await;

    let engine = make_engine(&db);

    assert_eq!(
        check(&engine, tenant_id, user_id, "read", resource_id, None).await,
        AccessDecision::Allow
    );
    assert!(matches!(
        check(&engine, tenant_id, user_id, "write", resource_id, None).await,
        AccessDecision::DeniedByRule(_)
    ));
}

/// §2.3, end to end: an unscoped deny is a wildcard that masks the action for
/// every scope, while a scoped deny masks only the scope it names.
///
/// Both halves run against real `Scope` rows, so the scope-name → scope-id
/// resolution the engine does before evaluating is exercised rather than
/// assumed.
#[tokio::test]
async fn scope_interaction_end_to_end() {
    let (db, tenant_id, user_id) = setup().await;
    let resource_id = create_resource(&db, tenant_id, "api", None).await;

    let scope_repo = SurrealScopeRepository::new(db.clone());
    let pii = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "pii".into(),
            description: "personal data".into(),
        })
        .await
        .unwrap();
    let billing = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id,
            name: "billing".into(),
            description: "billing data".into(),
        })
        .await
        .unwrap();

    // Wildcard allow (no scopes) + a deny scoped to `pii` only.
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("reader", "read", resource_id),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("no-pii", "read", resource_id).scoped(vec![pii.id]),
    )
    .await;

    let engine = make_engine(&db);

    assert!(matches!(
        check(
            &engine,
            tenant_id,
            user_id,
            "read",
            resource_id,
            Some("pii")
        )
        .await,
        AccessDecision::DeniedByRule(_)
    ));
    assert_eq!(
        check(
            &engine,
            tenant_id,
            user_id,
            "read",
            resource_id,
            Some("billing")
        )
        .await,
        AccessDecision::Allow,
        "a deny scoped to `pii` must not touch `billing`"
    );
    // An unscoped request against a scoped deny still matches it: the request
    // names no scope, so the grant applies. Getting this wrong in the deny
    // direction is a silent privilege escalation.
    assert!(matches!(
        check(&engine, tenant_id, user_id, "read", resource_id, None).await,
        AccessDecision::DeniedByRule(_)
    ));

    let _ = billing;
}

/// The batch path must produce byte-identical decisions to the single path,
/// including deny-override and its reason. `evaluate_batch` re-derives
/// applicability from its own coalesced lookups rather than calling
/// `check_access`, so this is a genuinely separate code path through the same
/// precedence table — the one place the two could drift.
#[tokio::test]
async fn the_batch_path_applies_deny_override_identically() {
    let (db, tenant_id, user_id) = setup().await;
    let fleet = create_resource(&db, tenant_id, "fleet", None).await;
    let unit7 = create_resource(&db, tenant_id, "unit-7", Some(fleet)).await;

    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::allow("fleet-reader", "read", fleet),
    )
    .await;
    assign_role_with_effect(
        &db,
        tenant_id,
        user_id,
        RoleSpec::deny("unit7-blocked", "read", unit7),
    )
    .await;

    let engine = make_engine(&db);

    let requests = vec![
        AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id: fleet,
            scope: None,
        },
        AccessRequest {
            tenant_id,
            subject_id: user_id,
            action: "read".into(),
            resource_id: unit7,
            scope: None,
        },
    ];

    let batched = engine.check_access_batch(&requests).await.unwrap();
    let mut singly = Vec::new();
    for req in &requests {
        singly.push(engine.check_access(req).await.unwrap());
    }

    assert_eq!(batched, singly, "batch and single paths must not diverge");
    assert_eq!(batched[0], AccessDecision::Allow);
    assert!(matches!(batched[1], AccessDecision::DeniedByRule(_)));
}
