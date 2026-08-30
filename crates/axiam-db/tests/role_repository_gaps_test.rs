//! Additional coverage for `SurrealRoleRepository` branches not exercised by
//! `role_permission_test.rs`: `get_by_name`, `get_user_role_assignments`,
//! `get_role_user_ids`/`get_role_group_ids`, and the cross-tenant /
//! duplicate-edge error paths of `assign_to_user`/`assign_to_group`.

use axiam_core::error::AxiamError;
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
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
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

/// Spin up in-memory DB with one org/tenant, one user and one group.
async fn setup() -> (Db, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org-rrg".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant-rrg".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "gaps-user".into(),
            email: "gaps-user@example.com".into(),
            password: "pass123!".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let group = SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id: tenant.id,
            name: "Gaps Group".into(),
            description: "d".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id, group.id)
}

/// A second, isolated tenant (org + tenant only) for cross-tenant checks.
async fn other_tenant(db: &Db) -> Uuid {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Other Org".into(),
            slug: format!("other-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: format!("other-tenant-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

// ---------------------------------------------------------------------------
// get_by_name
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_name_finds_existing_role() {
    let (db, tenant_id, _user, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "named-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let found = repo.get_by_name(tenant_id, "named-role").await.unwrap();
    assert_eq!(found.map(|r| r.id), Some(role.id));
}

#[tokio::test]
async fn get_by_name_returns_none_when_missing() {
    let (db, tenant_id, _user, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let found = repo.get_by_name(tenant_id, "nonexistent").await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn get_by_name_is_scoped_to_tenant() {
    let (db, tenant_id, _user, _group) = setup().await;
    let other_tid = other_tenant(&db).await;
    let repo = SurrealRoleRepository::new(db);

    repo.create(CreateRole {
        tenant_id,
        name: "scoped-role".into(),
        description: "d".into(),
        is_global: true,
    })
    .await
    .unwrap();

    let found = repo.get_by_name(other_tid, "scoped-role").await.unwrap();
    assert!(
        found.is_none(),
        "a role from another tenant must not be visible"
    );
}

// ---------------------------------------------------------------------------
// get_user_role_assignments
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_user_role_assignments_includes_direct_and_group_with_resource_scoping() {
    let (db, tenant_id, user_id, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());

    let direct_role = repo
        .create(CreateRole {
            tenant_id,
            name: "direct".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let group_role = repo
        .create(CreateRole {
            tenant_id,
            name: "via-group".into(),
            description: "d".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let resource_id = Uuid::new_v4();
    repo.assign_to_user(
        tenant_id,
        user_id,
        direct_role.id,
        AssignmentScope::resource(resource_id),
    )
    .await
    .unwrap();
    SurrealGroupRepository::new(db)
        .add_member(tenant_id, user_id, group_id)
        .await
        .unwrap();
    repo.assign_to_group(
        tenant_id,
        group_id,
        group_role.id,
        AssignmentScope::global(),
    )
    .await
    .unwrap();

    let assignments = repo
        .get_user_role_assignments(tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(assignments.len(), 2);

    let direct = assignments
        .iter()
        .find(|a| a.role.name == "direct")
        .expect("direct assignment present");
    assert_eq!(direct.resource_id, Some(resource_id));

    let via_group = assignments
        .iter()
        .find(|a| a.role.name == "via-group")
        .expect("group-inherited assignment present");
    assert_eq!(via_group.resource_id, None);
}

#[tokio::test]
async fn get_user_role_assignments_empty_when_no_roles() {
    let (db, tenant_id, user_id, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let assignments = repo
        .get_user_role_assignments(tenant_id, user_id)
        .await
        .unwrap();
    assert!(assignments.is_empty());
}

// ---------------------------------------------------------------------------
// get_role_user_ids / get_role_group_ids
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_role_user_ids_returns_only_directly_assigned_users() {
    let (db, tenant_id, user_id, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "role-with-users".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    // Also assign the same role to the group; get_role_user_ids should NOT
    // pick up members through the group edge (it selects FROM `user`
    // filtered on has_role edges whose `in` is a user record directly).
    repo.assign_to_group(tenant_id, group_id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    let user_ids = repo.get_role_user_ids(tenant_id, role.id).await.unwrap();
    assert_eq!(user_ids, vec![user_id]);
}

#[tokio::test]
async fn get_role_group_ids_returns_assigned_groups() {
    let (db, tenant_id, _user, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "role-with-groups".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_group(tenant_id, group_id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    let group_ids = repo.get_role_group_ids(tenant_id, role.id).await.unwrap();
    assert_eq!(group_ids, vec![group_id]);
}

#[tokio::test]
async fn get_role_user_ids_and_group_ids_empty_for_unassigned_role() {
    let (db, tenant_id, _user, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "unassigned-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    assert!(
        repo.get_role_user_ids(tenant_id, role.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.get_role_group_ids(tenant_id, role.id)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Cross-tenant assign guards (CQ-B07)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assign_to_user_cross_tenant_role_is_denied() {
    let (db, tenant_id, user_id, _group) = setup().await;
    let other_tid = other_tenant(&db).await;
    let repo = SurrealRoleRepository::new(db);

    // Role belongs to `other_tid`, user belongs to `tenant_id`.
    let foreign_role = repo
        .create(CreateRole {
            tenant_id: other_tid,
            name: "foreign-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let result = repo
        .assign_to_user(
            tenant_id,
            user_id,
            foreign_role.id,
            AssignmentScope::global(),
        )
        .await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), AxiamError::AuthorizationDenied { .. }),
        "cross-tenant role assignment must be denied"
    );
}

#[tokio::test]
async fn assign_to_group_cross_tenant_role_is_denied() {
    let (db, tenant_id, _user, group_id) = setup().await;
    let other_tid = other_tenant(&db).await;
    let repo = SurrealRoleRepository::new(db);

    let foreign_role = repo
        .create(CreateRole {
            tenant_id: other_tid,
            name: "foreign-group-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let result = repo
        .assign_to_group(
            tenant_id,
            group_id,
            foreign_role.id,
            AssignmentScope::global(),
        )
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AxiamError::AuthorizationDenied { .. }
    ));
}

#[tokio::test]
async fn unassign_from_user_cross_tenant_is_denied() {
    let (db, tenant_id, user_id, _group) = setup().await;
    let other_tid = other_tenant(&db).await;
    let repo = SurrealRoleRepository::new(db);

    let foreign_role = repo
        .create(CreateRole {
            tenant_id: other_tid,
            name: "foreign-unassign-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let result = repo
        .unassign_from_user(tenant_id, user_id, foreign_role.id, None)
        .await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        AxiamError::AuthorizationDenied { .. }
    ));
}

// ---------------------------------------------------------------------------
// Duplicate assignment (idx_has_role_unique) -> conflict
// ---------------------------------------------------------------------------

#[tokio::test]
async fn assign_to_user_duplicate_edge_is_rejected() {
    let (db, tenant_id, user_id, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "dup-assign-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    // Assigning the exact same (user, role, no resource) edge again must
    // fail — it hits idx_has_role_unique.
    let result = repo
        .assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await;
    assert!(
        result.is_err(),
        "duplicate has_role edge must be rejected, not silently ignored"
    );
}

// ---------------------------------------------------------------------------
// get_role_user_assignments / get_role_group_assignments /
// get_group_role_assignments — the `resource_id`-carrying counterparts
// ---------------------------------------------------------------------------

/// A resource to scope an assignment to. The role repository never validates
/// the target, so an id is enough — but a real row keeps the fixture honest.
async fn create_resource(db: &Db, tenant_id: Uuid, name: &str) -> Uuid {
    use axiam_core::models::resource::CreateResource;
    use axiam_core::repository::ResourceRepository;
    axiam_db::repository::SurrealResourceRepository::new(db.clone())
        .create(CreateResource {
            tenant_id,
            name: name.into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn get_role_user_assignments_carries_the_resource_scope() {
    let (db, tenant_id, user_id, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());
    let resource_id = create_resource(&db, tenant_id, "scoped-res-users").await;

    let scoped = repo
        .create(CreateRole {
            tenant_id,
            name: "scoped-user-role".into(),
            description: "d".into(),
            is_global: false,
        })
        .await
        .unwrap();
    let global = repo
        .create(CreateRole {
            tenant_id,
            name: "global-user-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_user(
        tenant_id,
        user_id,
        scoped.id,
        AssignmentScope::resource(resource_id),
    )
    .await
    .unwrap();
    repo.assign_to_user(tenant_id, user_id, global.id, AssignmentScope::global())
        .await
        .unwrap();
    // A group edge on the scoped role must not surface in the *user* listing:
    // `has_role` holds both kinds of edge and only `in` tells them apart.
    repo.assign_to_group(
        tenant_id,
        group_id,
        scoped.id,
        AssignmentScope::resource(resource_id),
    )
    .await
    .unwrap();

    let scoped_rows = repo
        .get_role_user_assignments(tenant_id, scoped.id)
        .await
        .unwrap();
    assert_eq!(scoped_rows.len(), 1, "{scoped_rows:?}");
    assert_eq!(scoped_rows[0].subject_id, user_id);
    assert_eq!(scoped_rows[0].resource_id, Some(resource_id));

    let global_rows = repo
        .get_role_user_assignments(tenant_id, global.id)
        .await
        .unwrap();
    assert_eq!(global_rows.len(), 1);
    assert_eq!(global_rows[0].subject_id, user_id);
    assert_eq!(
        global_rows[0].resource_id, None,
        "a global assignment carries no scope"
    );
}

#[tokio::test]
async fn get_role_group_assignments_carries_the_resource_scope() {
    let (db, tenant_id, user_id, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());
    let resource_id = create_resource(&db, tenant_id, "scoped-res-groups").await;

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "scoped-group-role".into(),
            description: "d".into(),
            is_global: false,
        })
        .await
        .unwrap();

    repo.assign_to_group(
        tenant_id,
        group_id,
        role.id,
        AssignmentScope::resource(resource_id),
    )
    .await
    .unwrap();
    // The mirror of the check above: a user edge must not surface in the
    // *group* listing.
    repo.assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    let rows = repo
        .get_role_group_assignments(tenant_id, role.id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].subject_id, group_id);
    assert_eq!(rows[0].resource_id, Some(resource_id));
}

#[tokio::test]
async fn role_subject_assignments_are_scoped_to_the_tenant() {
    let (db, tenant_id, user_id, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());
    let foreign = other_tenant(&db).await;

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "tenant-scoped-role".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();
    repo.assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    repo.assign_to_group(tenant_id, group_id, role.id, AssignmentScope::global())
        .await
        .unwrap();

    // Asking as another tenant must return nothing, not the owning tenant's
    // assignments.
    assert!(
        repo.get_role_user_assignments(foreign, role.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.get_role_group_assignments(foreign, role.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn role_subject_assignments_empty_for_an_unassigned_role() {
    let (db, tenant_id, _user, _group) = setup().await;
    let repo = SurrealRoleRepository::new(db);

    let role = repo
        .create(CreateRole {
            tenant_id,
            name: "nobody-holds-this".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    assert!(
        repo.get_role_user_assignments(tenant_id, role.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.get_role_group_assignments(tenant_id, role.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn get_group_role_assignments_carries_the_resource_scope() {
    let (db, tenant_id, _user, group_id) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());
    let resource_id = create_resource(&db, tenant_id, "group-roles-res").await;

    let scoped = repo
        .create(CreateRole {
            tenant_id,
            name: "group-scoped".into(),
            description: "d".into(),
            is_global: false,
        })
        .await
        .unwrap();
    let global = repo
        .create(CreateRole {
            tenant_id,
            name: "group-global".into(),
            description: "d".into(),
            is_global: true,
        })
        .await
        .unwrap();

    repo.assign_to_group(
        tenant_id,
        group_id,
        scoped.id,
        AssignmentScope::resource(resource_id),
    )
    .await
    .unwrap();
    repo.assign_to_group(tenant_id, group_id, global.id, AssignmentScope::global())
        .await
        .unwrap();

    let rows = repo
        .get_group_role_assignments(tenant_id, group_id)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");

    let scoped_row = rows.iter().find(|r| r.role.id == scoped.id).unwrap();
    assert_eq!(scoped_row.resource_id, Some(resource_id));
    let global_row = rows.iter().find(|r| r.role.id == global.id).unwrap();
    assert_eq!(global_row.resource_id, None);

    // Same tenant confinement as the role-side listings.
    let foreign = other_tenant(&db).await;
    assert!(
        repo.get_group_role_assignments(foreign, group_id)
            .await
            .unwrap()
            .is_empty()
    );
}
