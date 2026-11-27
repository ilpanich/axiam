//! `SurrealRoleRepository::authorization_inputs` — the one-round-trip read of an
//! uncached authorization check — answers exactly what the three reads it
//! replaces answer: the same role assignments, the same ancestors (error
//! included), and, for every assigned role, the same grants.
//!
//! The authorization engine's own suites (`axiam-authz/tests`) run over these
//! repositories and therefore over this read; this file pins the read itself,
//! against the methods it stands in for, on the real migrated schema.

use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, PermissionRepository, ResourceRepository,
    RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_test_support::test_password;
use serde_json::Value as Json;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

struct World {
    db: Surreal<Db>,
    tenant: Uuid,
    other_tenant: Uuid,
    user: Uuid,
    leaf: Uuid,
    roles: Vec<Uuid>,
}

async fn tenant(db: &Surreal<Db>, org: Uuid, slug: &str) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// A user with a global role, a role on the leaf's parent, a role on an
/// unrelated resource (with a deny grant), a role through a group, and a
/// role with no grant at all; a three-level hierarchy root → mid → leaf.
async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let t = tenant(&db, org, "t1").await;
    let other_tenant = tenant(&db, org, "t2").await;
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: t,
            username: "u".into(),
            email: "u@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let res = SurrealResourceRepository::new(db.clone());
    let mk = |name: &str, parent: Option<Uuid>, tenant_id: Uuid| CreateResource {
        tenant_id,
        name: name.into(),
        resource_type: "service".into(),
        parent_id: parent,
        metadata: None,
    };
    let root = res.create(mk("root", None, t)).await.unwrap().id;
    let mid = res.create(mk("mid", Some(root), t)).await.unwrap().id;
    let leaf = res.create(mk("leaf", Some(mid), t)).await.unwrap().id;
    let unrelated = res.create(mk("unrelated", None, t)).await.unwrap().id;

    let perms = SurrealPermissionRepository::new(db.clone());
    let mut actions = Vec::new();
    for a in ["read", "write", "delete"] {
        actions.push(
            perms
                .create(CreatePermission {
                    tenant_id: t,
                    action: a.into(),
                    description: String::new(),
                })
                .await
                .unwrap()
                .id,
        );
    }

    let role_repo = SurrealRoleRepository::new(db.clone());
    let mut roles = Vec::new();
    for (i, global) in [true, false, false, true, false].into_iter().enumerate() {
        roles.push(
            role_repo
                .create(CreateRole {
                    tenant_id: t,
                    name: format!("r{i}"),
                    description: String::new(),
                    is_global: global,
                })
                .await
                .unwrap()
                .id,
        );
    }
    perms.grant_to_role(t, roles[0], actions[0]).await.unwrap();
    perms.grant_to_role(t, roles[1], actions[1]).await.unwrap();
    perms
        .grant_to_role_with_effect(t, roles[2], actions[2], vec![], PermissionEffect::Deny)
        .await
        .unwrap();
    perms.grant_to_role(t, roles[3], actions[0]).await.unwrap();
    perms.grant_to_role(t, roles[3], actions[1]).await.unwrap();
    // roles[4]: no grant.

    role_repo
        .assign_to_user(t, user, roles[0], AssignmentScope::global())
        .await
        .unwrap();
    role_repo
        .assign_to_user(t, user, roles[1], AssignmentScope::resource(mid))
        .await
        .unwrap();
    role_repo
        .assign_to_user(t, user, roles[2], AssignmentScope::resource(unrelated))
        .await
        .unwrap();
    role_repo
        .assign_to_user(t, user, roles[4], AssignmentScope::resource_only(leaf))
        .await
        .unwrap();
    let groups = SurrealGroupRepository::new(db.clone());
    let group = groups
        .create(CreateGroup {
            tenant_id: t,
            name: "g".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    groups.add_member(t, user, group).await.unwrap();
    role_repo
        .assign_to_group(t, group, roles[3], AssignmentScope::global())
        .await
        .unwrap();

    World {
        db,
        tenant: t,
        other_tenant,
        user,
        leaf,
        roles,
    }
}

fn json<T: serde::Serialize>(v: &T) -> Json {
    serde_json::to_value(v).unwrap()
}

/// Compare `authorization_inputs` with the three reads it replaces.
async fn assert_same_as_three_reads(
    w: &World,
    assignment_tenant: Uuid,
    tenant: Uuid,
    resource: Uuid,
) {
    let roles = SurrealRoleRepository::new(w.db.clone());
    let resources = SurrealResourceRepository::new(w.db.clone());
    let perms = SurrealPermissionRepository::new(w.db.clone());

    let one = roles
        .authorization_inputs(assignment_tenant, w.user, tenant, resource)
        .await
        .unwrap()
        .expect("the SurrealDB repository offers the one-round-trip read");

    let assignments = roles
        .get_user_role_assignments(assignment_tenant, w.user)
        .await
        .unwrap();
    assert_eq!(json(&one.assignments), json(&assignments), "assignments");

    match (
        &one.ancestors,
        resources.get_ancestors(tenant, resource).await,
    ) {
        (Ok(a), Ok(b)) => assert_eq!(json(a), json(&b), "ancestors"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "ancestor error"),
        (a, b) => panic!("ancestors differ: {a:?} vs {b:?}"),
    }

    let assigned: Vec<Uuid> = assignments.iter().map(|a| a.role.id).collect();
    for role in &assigned {
        let three = perms
            .get_role_permission_grants_for_roles(assignment_tenant, &[*role])
            .await
            .unwrap();
        match (one.grants_by_role.get(role), three.get(role)) {
            (None, None) => {}
            (Some(Ok(a)), Some(b)) => assert_eq!(json(a), json(b), "grants of {role}"),
            (a, b) => panic!("grants of {role} differ: {a:?} vs {b:?}"),
        }
    }
    // Nothing for a role that is not assigned.
    assert!(
        one.grants_by_role.keys().all(|r| assigned.contains(r)),
        "grants only for assigned roles"
    );
}

#[tokio::test]
async fn matches_the_three_reads_on_a_resource_with_ancestors() {
    let w = world().await;
    assert_same_as_three_reads(&w, w.tenant, w.tenant, w.leaf).await;
    // Every assigned role with a grant is present: direct, scoped, group.
    let one = SurrealRoleRepository::new(w.db.clone())
        .authorization_inputs(w.tenant, w.user, w.tenant, w.leaf)
        .await
        .unwrap()
        .unwrap();
    for r in [w.roles[0], w.roles[1], w.roles[2], w.roles[3]] {
        assert!(one.grants_by_role.contains_key(&r), "role {r}");
    }
    assert!(
        !one.grants_by_role.contains_key(&w.roles[4]),
        "no grant, no entry"
    );
    assert_eq!(one.ancestors.as_ref().unwrap().len(), 2, "mid, root");
}

#[tokio::test]
async fn matches_the_three_reads_on_an_unknown_resource_and_subject() {
    let w = world().await;
    assert_same_as_three_reads(&w, w.tenant, w.tenant, Uuid::new_v4()).await;
    let one = SurrealRoleRepository::new(w.db.clone())
        .authorization_inputs(w.tenant, Uuid::new_v4(), w.tenant, w.leaf)
        .await
        .unwrap()
        .unwrap();
    assert!(one.assignments.is_empty());
    assert!(one.grants_by_role.is_empty());
}

/// Assignments and grants come from the subject's tenant, ancestors from the
/// tenant being acted on — never mixed up.
#[tokio::test]
async fn reads_each_part_in_its_own_tenant() {
    let w = world().await;
    assert_same_as_three_reads(&w, w.tenant, w.other_tenant, w.leaf).await;
    let one = SurrealRoleRepository::new(w.db.clone())
        .authorization_inputs(w.tenant, w.user, w.other_tenant, w.leaf)
        .await
        .unwrap()
        .unwrap();
    assert!(!one.assignments.is_empty(), "the subject's tenant");
    assert!(
        one.ancestors.as_ref().unwrap().is_empty(),
        "the leaf is not in the acted-on tenant"
    );
    // And the other way round: a subject read in a tenant it is not in.
    assert_same_as_three_reads(&w, w.other_tenant, w.tenant, w.leaf).await;
}

/// A hierarchy past the depth cap is refused as a possible cycle by both — as
/// the ancestors' own outcome, not as a failure of the whole read.
#[tokio::test]
async fn an_over_deep_hierarchy_is_the_ancestors_error_alone() {
    let w = world().await;
    let res = SurrealResourceRepository::new(w.db.clone());
    let mut parent = None;
    let mut last = Uuid::nil();
    for i in 0..60 {
        last = res
            .create(CreateResource {
                tenant_id: w.tenant,
                name: format!("deep-{i}"),
                resource_type: "service".into(),
                parent_id: parent,
                metadata: None,
            })
            .await
            .unwrap()
            .id;
        parent = Some(last);
    }
    assert_same_as_three_reads(&w, w.tenant, w.tenant, last).await;
    let one = SurrealRoleRepository::new(w.db.clone())
        .authorization_inputs(w.tenant, w.user, w.tenant, last)
        .await
        .unwrap()
        .unwrap();
    assert!(one.ancestors.is_err());
    assert!(!one.assignments.is_empty(), "the rest of the read stands");
}

/// A grant row that cannot be read fails its own role, not the read: the
/// engine surfaces it only if that role applies, which is when the three-read
/// path would have read it.
#[tokio::test]
async fn an_unreadable_grant_fails_only_its_role() {
    let w = world().await;
    // roles[2]'s grant gets a scope id that is not a UUID.
    w.db.query("UPDATE grants SET scope_ids = ['not-a-uuid'] WHERE in = type::record('role', $r)")
        .bind(("r", w.roles[2].to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    let one = SurrealRoleRepository::new(w.db.clone())
        .authorization_inputs(w.tenant, w.user, w.tenant, w.leaf)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(one.grants_by_role.get(&w.roles[2]), Some(Err(_))));
    assert!(matches!(one.grants_by_role.get(&w.roles[0]), Some(Ok(_))));
    // The three-read path fails on the same role when it reads it.
    assert!(
        SurrealPermissionRepository::new(w.db.clone())
            .get_role_permission_grants_for_roles(w.tenant, &[w.roles[2]])
            .await
            .is_err()
    );
}
