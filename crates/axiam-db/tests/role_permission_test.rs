//! Integration tests for Role and Permission repositories using in-memory SurrealDB.

use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{CreateRole, UpdateRole};
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, Pagination, PermissionRepository, ResourceRepository,
    RoleRepository, ScopeRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB, run migrations, create org + tenant + 2 users + 1 group.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
    uuid::Uuid, // user_a_id
    uuid::Uuid, // user_b_id
    uuid::Uuid, // group_id
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
    let user_a = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_b = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let group_repo = SurrealGroupRepository::new(db.clone());
    let group = group_repo
        .create(CreateGroup {
            tenant_id: tenant.id,
            name: "Developers".into(),
            description: "Dev team".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Add alice to the group.
    group_repo
        .add_member(tenant.id, user_a.id, group.id)
        .await
        .unwrap();

    (db, tenant.id, user_a.id, user_b.id, group.id)
}

// ---------------------------------------------------------------------------
// Role tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_role() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "admin".into(),
            description: "Administrator".into(),
            is_global: true,
        })
        .await
        .unwrap();

    assert_eq!(role.tenant_id, tenant_id);
    assert_eq!(role.name, "admin");
    assert!(role.is_global);

    let fetched = repo.get_by_id(tenant_id, role.id).await.unwrap();
    assert_eq!(fetched.id, role.id);
    assert_eq!(fetched.name, "admin");
}

#[tokio::test]
async fn update_role() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "editor".into(),
            description: "Can edit".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            role.id,
            UpdateRole {
                name: Some("super-editor".into()),
                is_global: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "super-editor");
    assert!(updated.is_global);
    assert_eq!(updated.description, "Can edit"); // unchanged
}

#[tokio::test]
async fn delete_role() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "to-delete".into(),
            description: "temp".into(),
            is_global: false,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, role.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, role.id).await;
    assert!(result.is_err(), "deleted role should not be found");
}

/// D-13/CQ-B07/SEC-058 lock-in: deleting a role via a foreign-tenant id must
/// never strip that other tenant's has_role edge. `role.rs::delete` now
/// guards the `has_role`/`grants` DELETEs with a node-tenant subquery
/// (`out.tenant_id = $tenant_id`) since those edge tables carry no
/// `tenant_id` field of their own — this proves a caller in tenant A cannot
/// use tenant B's role id to strip tenant B's own (legitimate, same-tenant)
/// has_role edge.
#[tokio::test]
async fn delete_role_does_not_strip_foreign_tenant_edge() {
    let (db, tenant_a, _, _, _) = setup().await;

    // Second, independent tenant sharing the same in-memory DB.
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user_b = user_repo
        .create(CreateUser {
            tenant_id: tenant_b.id,
            username: "carol".into(),
            email: "carol@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let repo = SurrealRoleRepository::new(db);

    // A role + has_role edge that legitimately belongs to tenant B.
    let role_b = repo
        .create(CreateRole {
            tenant_id: tenant_b.id,
            name: "b-role".into(),
            description: "tenant b role".into(),
            is_global: false,
        })
        .await
        .unwrap();
    repo.assign_to_user(tenant_b.id, user_b.id, role_b.id, None)
        .await
        .unwrap();

    // Tenant A attempts to delete tenant B's role, supplying its foreign id
    // while claiming tenant A as the caller's tenant (foreign-id delete
    // attempt). This must be a no-op, not an error — every statement in the
    // transaction is tenant-predicated and simply matches zero rows.
    repo.delete(tenant_a, role_b.id)
        .await
        .expect("foreign-tenant delete must no-op, not error");

    // Tenant B's has_role edge must survive.
    let roles_b_after = repo.get_user_roles(tenant_b.id, user_b.id).await.unwrap();
    assert_eq!(
        roles_b_after.len(),
        1,
        "tenant B's has_role edge must survive a foreign-tenant-A delete attempt"
    );
    assert_eq!(roles_b_after[0].id, role_b.id);

    // The role record itself must also survive (the final DELETE already
    // carried a flat tenant_id predicate pre-fix; this confirms it still
    // does post-fix).
    let role_still_exists = repo.get_by_id(tenant_b.id, role_b.id).await;
    assert!(
        role_still_exists.is_ok(),
        "tenant B's role record must survive a foreign-tenant-A delete attempt"
    );
}

/// Regression: a legitimate same-tenant delete must still remove the role's
/// has_role edge (the transactional rewrite must not silently stop deleting
/// edges it's supposed to delete).
#[tokio::test]
async fn delete_role_removes_own_tenant_edges() {
    let (db, tenant_id, user_a, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "own-tenant-role".into(),
            description: "temp".into(),
            is_global: false,
        })
        .await
        .unwrap();
    repo.assign_to_user(tenant_id, user_a, role.id, None)
        .await
        .unwrap();

    repo.delete(tenant_id, role.id).await.unwrap();

    let roles_after = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    assert!(
        roles_after.is_empty(),
        "same-tenant delete must still remove the has_role edge"
    );
    let result = repo.get_by_id(tenant_id, role.id).await;
    assert!(result.is_err(), "deleted role should not be found");
}

#[tokio::test]
async fn list_roles_with_pagination() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    for i in 0..5 {
        repo.create(CreateRole {
            tenant_id,
            name: format!("role-{i}"),
            description: format!("Role {i}"),
            is_global: false,
        })
        .await
        .unwrap();
    }

    let page1 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 3,
            },
        )
        .await
        .unwrap();

    assert_eq!(page1.items.len(), 3);
    assert_eq!(page1.total, 5);

    let page2 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 3,
                limit: 3,
            },
        )
        .await
        .unwrap();

    assert_eq!(page2.items.len(), 2);
}

#[tokio::test]
async fn duplicate_role_name_rejected() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    repo.create(CreateRole {
        tenant_id,
        name: "unique-role".into(),
        description: "first".into(),
        is_global: false,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateRole {
            tenant_id,
            name: "unique-role".into(),
            description: "second".into(),
            is_global: false,
        })
        .await;

    assert!(result.is_err(), "duplicate role name should be rejected");
}

#[tokio::test]
async fn assign_and_get_user_roles() {
    let (db, tenant_id, user_a, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "viewer".into(),
            description: "Can view".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_user(tenant_id, user_a, role.id, None)
        .await
        .unwrap();

    let roles = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "viewer");

    // Unassign and verify.
    repo.unassign_from_user(tenant_id, user_a, role.id, None)
        .await
        .unwrap();

    let roles = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    assert!(roles.is_empty());
}

#[tokio::test]
async fn assign_and_get_group_roles() {
    let (db, tenant_id, _, _, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "deployer".into(),
            description: "Can deploy".into(),
            is_global: false,
        })
        .await
        .unwrap();

    repo.assign_to_group(tenant_id, group_id, role.id, None)
        .await
        .unwrap();

    let roles = repo.get_group_roles(tenant_id, group_id).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "deployer");

    // Unassign and verify.
    repo.unassign_from_group(tenant_id, group_id, role.id, None)
        .await
        .unwrap();

    let roles = repo.get_group_roles(tenant_id, group_id).await.unwrap();
    assert!(roles.is_empty());
}

#[tokio::test]
async fn get_user_roles_includes_group_roles() {
    let (db, tenant_id, user_a, _, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    // Create two roles: one assigned directly to user, one to the group.
    let direct_role = repo
        .create(CreateRole {
            tenant_id,
            name: "direct-role".into(),
            description: "Directly assigned".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let group_role = repo
        .create(CreateRole {
            tenant_id,
            name: "group-role".into(),
            description: "Via group".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_user(tenant_id, user_a, direct_role.id, None)
        .await
        .unwrap();
    repo.assign_to_group(tenant_id, group_id, group_role.id, None)
        .await
        .unwrap();

    // user_a is a member of the group (set up in setup()), so should get both roles.
    let roles = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"direct-role"));
    assert!(names.contains(&"group-role"));
}

#[tokio::test]
async fn resource_scoped_role_assignment() {
    let (db, tenant_id, user_a, _, _) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "resource-editor".into(),
            description: "Can edit resource".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let resource_id = uuid::Uuid::new_v4();

    // Assign with resource scope.
    repo.assign_to_user(tenant_id, user_a, role.id, Some(resource_id))
        .await
        .unwrap();

    let roles = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "resource-editor");

    // Unassign with matching resource_id.
    repo.unassign_from_user(tenant_id, user_a, role.id, Some(resource_id))
        .await
        .unwrap();

    let roles = repo.get_user_roles(tenant_id, user_a).await.unwrap();
    assert!(roles.is_empty());
}

// ---------------------------------------------------------------------------
// Permission tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_permission() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealPermissionRepository::new(db);

    let perm = repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "Can read".into(),
        })
        .await
        .unwrap();

    assert_eq!(perm.action, "read");
    assert_eq!(perm.tenant_id, tenant_id);

    let fetched = repo.get_by_id(tenant_id, perm.id).await.unwrap();
    assert_eq!(fetched.id, perm.id);
}

#[tokio::test]
async fn update_permission() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealPermissionRepository::new(db);

    let perm = repo
        .create(CreatePermission {
            tenant_id,
            action: "write".into(),
            description: "Can write".into(),
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            perm.id,
            axiam_core::models::permission::UpdatePermission {
                action: Some("write-all".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.action, "write-all");
    assert_eq!(updated.description, "Can write"); // unchanged
}

#[tokio::test]
async fn delete_permission() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealPermissionRepository::new(db);

    let perm = repo
        .create(CreatePermission {
            tenant_id,
            action: "temp-action".into(),
            description: "temp".into(),
        })
        .await
        .unwrap();

    repo.delete(tenant_id, perm.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, perm.id).await;
    assert!(result.is_err(), "deleted permission should not be found");
}

#[tokio::test]
async fn duplicate_action_rejected() {
    let (db, tenant_id, _, _, _) = setup().await;
    let repo = SurrealPermissionRepository::new(db);

    repo.create(CreatePermission {
        tenant_id,
        action: "unique-action".into(),
        description: "first".into(),
    })
    .await
    .unwrap();

    let result = repo
        .create(CreatePermission {
            tenant_id,
            action: "unique-action".into(),
            description: "second".into(),
        })
        .await;

    // A duplicate `action` violates the unique index and must surface as a
    // Conflict (AxiamError::AlreadyExists -> HTTP 409), routed through
    // classify_write_error — not a generic Database error (HTTP 500).
    let err = result.unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("AlreadyExists"),
        "duplicate action must map to AlreadyExists (409 Conflict), not a 500; got: {dbg}"
    );
}

#[tokio::test]
async fn grant_and_get_role_permissions() {
    let (db, tenant_id, _, _, _) = setup().await;
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db);

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "editor".into(),
            description: "Editor role".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let perm_read = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "Can read".into(),
        })
        .await
        .unwrap();

    let perm_write = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "write".into(),
            description: "Can write".into(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm_read.id)
        .await
        .unwrap();
    perm_repo
        .grant_to_role(tenant_id, role.id, perm_write.id)
        .await
        .unwrap();

    let perms = perm_repo
        .get_role_permissions(tenant_id, role.id)
        .await
        .unwrap();
    assert_eq!(perms.len(), 2);

    let actions: Vec<&str> = perms.iter().map(|p| p.action.as_str()).collect();
    assert!(actions.contains(&"read"));
    assert!(actions.contains(&"write"));
}

/// CQ-B13: the batched grant lookup groups grants per role in a SINGLE query,
/// preserves scope constraints, omits roles with no grants, and stays
/// tenant-scoped (a foreign-tenant role id leaks nothing).
#[tokio::test]
async fn batched_grants_group_by_role() {
    let (db, tenant_id, _, _, _) = setup().await;
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db.clone());

    let new_global_role = |name: &str| CreateRole {
        tenant_id,
        name: name.to_string(),
        description: name.to_string(),
        is_global: true,
    };
    let role1 = role_repo.create(new_global_role("role1")).await.unwrap();
    let role2 = role_repo.create(new_global_role("role2")).await.unwrap();
    let role3 = role_repo
        .create(new_global_role("role3-empty"))
        .await
        .unwrap(); // no grants

    let perm_read = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "r".into(),
        })
        .await
        .unwrap();
    let perm_write = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "write".into(),
            description: "w".into(),
        })
        .await
        .unwrap();

    // A resource + scope so role1's write grant carries a scope constraint.
    let resource = res_repo
        .create(CreateResource {
            tenant_id,
            name: "api".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    let scope = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id: resource.id,
            name: "s1".into(),
            description: "s".into(),
        })
        .await
        .unwrap();

    // role1: wildcard read + scoped write. role2: wildcard read. role3: none.
    perm_repo
        .grant_to_role(tenant_id, role1.id, perm_read.id)
        .await
        .unwrap();
    perm_repo
        .grant_to_role_with_scopes(tenant_id, role1.id, perm_write.id, vec![scope.id])
        .await
        .unwrap();
    perm_repo
        .grant_to_role(tenant_id, role2.id, perm_read.id)
        .await
        .unwrap();

    // Foreign tenant with its own role+grant — must never appear in tenant_id's batch.
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "OrgB".into(),
            slug: "org-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "TenantB".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let role_b = role_repo
        .create(CreateRole {
            tenant_id: tenant_b.id,
            name: "roleB".into(),
            description: "b".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let perm_b = perm_repo
        .create(CreatePermission {
            tenant_id: tenant_b.id,
            action: "read".into(),
            description: "b".into(),
        })
        .await
        .unwrap();
    perm_repo
        .grant_to_role(tenant_b.id, role_b.id, perm_b.id)
        .await
        .unwrap();

    // Single batched call across all applicable role ids (including the empty
    // role3 and the cross-tenant role_b).
    let grouped = perm_repo
        .get_role_permission_grants_for_roles(tenant_id, &[role1.id, role2.id, role3.id, role_b.id])
        .await
        .unwrap();

    // role3 (no grants) and role_b (other tenant) are absent.
    assert_eq!(
        grouped.len(),
        2,
        "only role1 and role2 have in-tenant grants"
    );
    assert!(!grouped.contains_key(&role3.id));
    assert!(!grouped.contains_key(&role_b.id));

    let r1 = grouped.get(&role1.id).expect("role1 present");
    assert_eq!(r1.len(), 2);
    let write_grant = r1
        .iter()
        .find(|g| g.permission.action == "write")
        .expect("write grant");
    assert_eq!(
        write_grant.scope_ids,
        vec![scope.id],
        "scope constraint preserved"
    );
    let read_grant = r1
        .iter()
        .find(|g| g.permission.action == "read")
        .expect("read grant");
    assert!(
        read_grant.scope_ids.is_empty(),
        "wildcard grant has empty scope_ids"
    );

    let r2 = grouped.get(&role2.id).expect("role2 present");
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0].permission.action, "read");

    // The batched result matches the per-role method exactly (parity check).
    let single1 = perm_repo
        .get_role_permission_grants(tenant_id, role1.id)
        .await
        .unwrap();
    assert_eq!(single1.len(), r1.len());

    // Empty input short-circuits to an empty map.
    let empty = perm_repo
        .get_role_permission_grants_for_roles(tenant_id, &[])
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn revoke_permission_from_role() {
    let (db, tenant_id, _, _, _) = setup().await;
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db);

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "temp-role".into(),
            description: "Temp".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "delete".into(),
            description: "Can delete".into(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    // Verify granted.
    let perms = perm_repo
        .get_role_permissions(tenant_id, role.id)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1);

    // Revoke.
    perm_repo
        .revoke_from_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    let perms = perm_repo
        .get_role_permissions(tenant_id, role.id)
        .await
        .unwrap();
    assert!(perms.is_empty());
}
