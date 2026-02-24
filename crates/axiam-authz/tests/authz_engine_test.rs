//! Integration tests for the authorization engine.

use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
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

/// Spin up in-memory DB, run migrations, create org + tenant + user.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
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
fn make_engine(
    db: &Surreal<surrealdb::engine::local::Db>,
) -> AuthorizationEngine<
    SurrealRoleRepository<surrealdb::engine::local::Db>,
    SurrealPermissionRepository<surrealdb::engine::local::Db>,
    SurrealResourceRepository<surrealdb::engine::local::Db>,
    SurrealScopeRepository<surrealdb::engine::local::Db>,
    SurrealGroupRepository<surrealdb::engine::local::Db>,
> {
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
    db: &Surreal<surrealdb::engine::local::Db>,
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
    db: &Surreal<surrealdb::engine::local::Db>,
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
