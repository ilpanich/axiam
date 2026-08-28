//! A service account is a principal, and RBAC has to reach it.
//!
//! `has_role` has always been declared `User/ServiceAccount/Group -> Role`, and
//! the authorization engine has always applied RBAC identically to a machine and
//! a person — `RequirePermission::check_subject` says so, and deliberately takes
//! no `is_machine` flag to branch on. But the write paths were user- and
//! group-only, and `get_user_role_assignments` matched
//! `type::record('user', $id)` literally, so even an edge written by hand
//! resolved to nothing. A service account could authenticate and then do
//! nothing at all.
//!
//! These tests pin both halves: the edges can be created, and the query the
//! engine actually calls returns them — directly and through group membership.

use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::CreateRole;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, Pagination, RoleRepository, ServiceAccountRepository,
    TenantRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealRoleRepository,
    SurrealServiceAccountRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

struct Fixture {
    db: Db,
    tenant_id: Uuid,
    /// A second tenant in the same organization, for the isolation cases.
    other_tenant_id: Uuid,
    service_account_id: Uuid,
    role_id: Uuid,
    group_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SA RBAC Org".into(),
            slug: "sa-rbac-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SA RBAC Tenant".into(),
            slug: "sa-rbac-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Other Tenant".into(),
            slug: "sa-rbac-other".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // `create` returns the account and its plaintext client secret — the one
    // time that value exists. Nothing here needs it.
    let (service_account, _client_secret) = SurrealServiceAccountRepository::new(db.clone())
        .create(CreateServiceAccount {
            tenant_id: tenant.id,
            name: "ingest-worker".into(),
            description: Some("Machine identity under test".into()),
        })
        .await
        .unwrap();

    let role = SurrealRoleRepository::new(db.clone())
        .create(CreateRole {
            tenant_id: tenant.id,
            name: "ingest".into(),
            description: "May ingest".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let group = SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id: tenant.id,
            name: "workers".into(),
            description: "The device fleet".into(),
            metadata: None,
        })
        .await
        .unwrap();

    Fixture {
        db,
        tenant_id: tenant.id,
        other_tenant_id: other_tenant.id,
        service_account_id: service_account.id,
        role_id: role.id,
        group_id: group.id,
    }
}

/// The core of it: a role assigned to a service account is resolved by the very
/// query the authorization engine calls.
#[tokio::test]
async fn a_role_assigned_to_a_service_account_reaches_the_engine() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());

    roles
        .assign_to_service_account(f.tenant_id, f.service_account_id, f.role_id, None)
        .await
        .unwrap();

    // `get_user_role_assignments` is what `AuthorizationEngine::check` calls,
    // with the subject id and no notion of which table it came from. Before this
    // it matched `user:` records literally and a machine resolved nothing.
    let assignments = roles
        .get_user_role_assignments(f.tenant_id, f.service_account_id)
        .await
        .unwrap();

    assert_eq!(assignments.len(), 1, "the engine must see the grant");
    assert_eq!(assignments[0].role.id, f.role_id);
    assert_eq!(assignments[0].resource_id, None, "a global grant");
}

/// The convenience listing agrees with the engine's view.
#[tokio::test]
async fn get_service_account_roles_lists_the_assignment() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());

    roles
        .assign_to_service_account(f.tenant_id, f.service_account_id, f.role_id, None)
        .await
        .unwrap();

    let listed = roles
        .get_service_account_roles(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, f.role_id);

    let inverse = roles
        .get_role_service_account_assignments(f.tenant_id, f.role_id)
        .await
        .unwrap();
    assert_eq!(inverse.len(), 1);
    assert_eq!(inverse[0].subject_id, f.service_account_id);
}

/// Unassigning removes it again — and removes the *global* grant specifically.
#[tokio::test]
async fn unassigning_removes_the_grant() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());

    roles
        .assign_to_service_account(f.tenant_id, f.service_account_id, f.role_id, None)
        .await
        .unwrap();
    roles
        .unassign_from_service_account(f.tenant_id, f.service_account_id, f.role_id, None)
        .await
        .unwrap();

    let assignments = roles
        .get_user_role_assignments(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert!(assignments.is_empty());
}

/// The reason to put machines in a group at all: grant once, and every member
/// has it.
#[tokio::test]
async fn a_service_account_inherits_its_group_s_roles() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());
    let groups = SurrealGroupRepository::new(f.db.clone());

    groups
        .add_service_account_member(f.tenant_id, f.service_account_id, f.group_id)
        .await
        .unwrap();
    roles
        .assign_to_group(f.tenant_id, f.group_id, f.role_id, None)
        .await
        .unwrap();

    let assignments = roles
        .get_user_role_assignments(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert_eq!(
        assignments.len(),
        1,
        "a machine inherits a group's roles exactly as a person does — which is \
         the whole reason to grant a fleet of devices as one thing"
    );
    assert_eq!(assignments[0].role.id, f.role_id);

    // And the same through the convenience listing, which traverses `member_of`.
    let listed = roles
        .get_service_account_roles(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
}

/// Removing the membership removes the inherited grant with it.
#[tokio::test]
async fn removing_a_service_account_from_a_group_revokes_what_it_inherited() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());
    let groups = SurrealGroupRepository::new(f.db.clone());

    groups
        .add_service_account_member(f.tenant_id, f.service_account_id, f.group_id)
        .await
        .unwrap();
    roles
        .assign_to_group(f.tenant_id, f.group_id, f.role_id, None)
        .await
        .unwrap();
    groups
        .remove_service_account_member(f.tenant_id, f.service_account_id, f.group_id)
        .await
        .unwrap();

    let assignments = roles
        .get_user_role_assignments(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert!(assignments.is_empty());
}

/// Membership listings distinguish machines from people.
#[tokio::test]
async fn group_membership_listings_are_typed() {
    let f = setup().await;
    let groups = SurrealGroupRepository::new(f.db.clone());

    groups
        .add_service_account_member(f.tenant_id, f.service_account_id, f.group_id)
        .await
        .unwrap();

    let machines = groups
        .get_service_account_members(f.tenant_id, f.group_id, Pagination::default())
        .await
        .unwrap();
    assert_eq!(machines.items.len(), 1);
    assert_eq!(machines.items[0].id, f.service_account_id);
    assert_eq!(machines.total, 1);

    // A page listing "members" must not promise rows it cannot show: the user
    // listing counts user edges only, so a group holding one service account and
    // no people reports zero members rather than one it cannot render.
    let people = groups
        .get_members(f.tenant_id, f.group_id, Pagination::default())
        .await
        .unwrap();
    assert!(people.items.is_empty());
    assert_eq!(people.total, 0);

    let its_groups = groups
        .get_service_account_groups(f.tenant_id, f.service_account_id)
        .await
        .unwrap();
    assert_eq!(its_groups.len(), 1);
    assert_eq!(its_groups[0].id, f.group_id);
}

/// Tenant isolation holds for machine grants exactly as it does for human ones.
#[tokio::test]
async fn a_role_cannot_be_assigned_across_a_tenant_boundary() {
    let f = setup().await;
    let roles = SurrealRoleRepository::new(f.db.clone());

    // A role belonging to another tenant, and this tenant's service account.
    let foreign_role = roles
        .create(CreateRole {
            tenant_id: f.other_tenant_id,
            name: "foreign".into(),
            description: "Belongs elsewhere".into(),
            is_global: true,
        })
        .await
        .unwrap();

    let err = roles
        .assign_to_service_account(f.tenant_id, f.service_account_id, foreign_role.id, None)
        .await
        .expect_err("a cross-tenant grant must be refused, not silently written");
    assert!(
        format!("{err}").contains("cross-tenant"),
        "unexpected error: {err}"
    );
}

/// And a service account cannot be dropped into another tenant's group.
#[tokio::test]
async fn a_service_account_cannot_join_another_tenants_group() {
    let f = setup().await;
    let groups = SurrealGroupRepository::new(f.db.clone());

    let foreign_group = groups
        .create(CreateGroup {
            tenant_id: f.other_tenant_id,
            name: "foreign-workers".into(),
            description: "Belongs elsewhere".into(),
            metadata: None,
        })
        .await
        .unwrap();

    groups
        .add_service_account_member(f.tenant_id, f.service_account_id, foreign_group.id)
        .await
        .expect_err("a cross-tenant membership must be refused");
}
