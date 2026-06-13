//! REQ-14 AC-4 integration tests: tenant isolation for role/permission edge mutations
//! and resource hierarchy safety (cycle, orphan, depth-overflow).
//!
//! Validated threats:
//!   T-10-05 (CQ-B07): cross-tenant RELATE must be rejected → AuthorizationDenied
//!   T-10-06 (CQ-B08): cycles rejected, children block delete, depth overflow errors

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::{CreateResource, UpdateResource};
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, ResourceRepository, RoleRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type Db = surrealdb::engine::local::Db;

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Create org + two tenants. Returns (org_id, tenant_a_id, tenant_b_id).
async fn setup_two_tenants(db: &Surreal<Db>) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db.clone());

    let org = org_repo
        .create(CreateOrganization {
            name: "Isolation Org".into(),
            slug: "isolation-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let ta = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant A".into(),
            slug: "tenant-a".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tb = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (org.id, ta.id, tb.id)
}

// ---------------------------------------------------------------------------
// T-10-05 (CQ-B07): cross-tenant role edge mutations rejected
// ---------------------------------------------------------------------------

/// role_assign_cross_tenant_rejected: user in tenant A, role in tenant B
/// → assign_to_user(tenant_a, user_a, role_b) returns AuthorizationDenied.
#[tokio::test]
async fn role_assign_cross_tenant_rejected() {
    let db = setup_db().await;
    let (_org_id, tenant_a, tenant_b) = setup_two_tenants(&db).await;

    let user_repo = SurrealUserRepository::new(db.clone());
    let role_repo = SurrealRoleRepository::new(db.clone());

    let user_a = user_repo
        .create(CreateUser {
            tenant_id: tenant_a,
            username: "user-a-cross".into(),
            email: "user-a-cross@example.com".into(),
            password: "password12345678".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let role_b = role_repo
        .create(CreateRole {
            tenant_id: tenant_b,
            name: "role-b-cross".into(),
            description: "Role in tenant B".into(),
            is_global: false,
        })
        .await
        .unwrap();

    // Cross-tenant assign: user in A, role in B — must be rejected.
    let result = role_repo
        .assign_to_user(tenant_a, user_a.id, role_b.id, None)
        .await;

    assert!(result.is_err(), "cross-tenant assign must fail");
    match result.unwrap_err() {
        AxiamError::AuthorizationDenied { .. } => {}
        other => panic!("expected AuthorizationDenied, got {other:?}"),
    }
}

/// role_assign_same_tenant_ok: same-tenant assign succeeds.
#[tokio::test]
async fn role_assign_same_tenant_ok() {
    let db = setup_db().await;
    let (_org_id, tenant_a, _tenant_b) = setup_two_tenants(&db).await;

    let user_repo = SurrealUserRepository::new(db.clone());
    let role_repo = SurrealRoleRepository::new(db.clone());

    let user_a = user_repo
        .create(CreateUser {
            tenant_id: tenant_a,
            username: "user-a-same".into(),
            email: "user-a-same@example.com".into(),
            password: "password12345678".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let role_a = role_repo
        .create(CreateRole {
            tenant_id: tenant_a,
            name: "role-a-same".into(),
            description: "Role in tenant A".into(),
            is_global: false,
        })
        .await
        .unwrap();

    // Same-tenant assign must succeed.
    role_repo
        .assign_to_user(tenant_a, user_a.id, role_a.id, None)
        .await
        .expect("same-tenant assign must succeed");
}

/// permission_grant_cross_tenant_rejected: role in tenant A, permission in tenant B
/// → grant_to_role(tenant_a, role_a, perm_b) returns AuthorizationDenied.
#[tokio::test]
async fn permission_grant_cross_tenant_rejected() {
    let db = setup_db().await;
    let (_org_id, tenant_a, tenant_b) = setup_two_tenants(&db).await;

    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role_a = role_repo
        .create(CreateRole {
            tenant_id: tenant_a,
            name: "role-a-perm-cross".into(),
            description: "Role A".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let perm_b = perm_repo
        .create(CreatePermission {
            tenant_id: tenant_b,
            action: "resource:read-cross".into(),
            description: "Perm in tenant B".into(),
        })
        .await
        .unwrap();

    // Cross-tenant grant: role in A, permission in B — must be rejected.
    let result = perm_repo
        .grant_to_role(tenant_a, role_a.id, perm_b.id)
        .await;

    assert!(result.is_err(), "cross-tenant permission grant must fail");
    match result.unwrap_err() {
        AxiamError::AuthorizationDenied { .. } => {}
        other => panic!("expected AuthorizationDenied, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// T-10-06 (CQ-B08): resource hierarchy — cycle, orphan, depth overflow
// ---------------------------------------------------------------------------

/// resource_cycle_rejected: chain A→B→C; re-parent A under C → cycle rejected.
#[tokio::test]
async fn resource_cycle_rejected() {
    let db = setup_db().await;
    let (_org_id, tenant_a, _) = setup_two_tenants(&db).await;

    let res_repo = SurrealResourceRepository::new(db.clone());

    // Create root A
    let res_a = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Resource A".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    // Create B as child of A
    let res_b = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Resource B".into(),
            resource_type: "service".into(),
            parent_id: Some(res_a.id),
            metadata: None,
        })
        .await
        .unwrap();

    // Create C as child of B
    let res_c = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Resource C".into(),
            resource_type: "service".into(),
            parent_id: Some(res_b.id),
            metadata: None,
        })
        .await
        .unwrap();

    // Re-parent A under C → would form a cycle A→B→C→A
    let result = res_repo
        .update(
            tenant_a,
            res_a.id,
            UpdateResource {
                name: None,
                resource_type: None,
                parent_id: Some(Some(res_c.id)),
                metadata: None,
            },
        )
        .await;

    assert!(result.is_err(), "cycle re-parent must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("cycle"),
        "error must mention cycle, got: {err_msg}"
    );
}

/// resource_delete_with_children_rejected: delete a parent that has children must fail.
#[tokio::test]
async fn resource_delete_with_children_rejected() {
    let db = setup_db().await;
    let (_org_id, tenant_a, _) = setup_two_tenants(&db).await;

    let res_repo = SurrealResourceRepository::new(db.clone());

    let parent = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Parent Resource".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let _child = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Child Resource".into(),
            resource_type: "service".into(),
            parent_id: Some(parent.id),
            metadata: None,
        })
        .await
        .unwrap();

    // Deleting a resource with children must be rejected.
    let result = res_repo.delete(tenant_a, parent.id).await;

    assert!(
        result.is_err(),
        "delete of resource with children must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("children"),
        "error must mention children, got: {err_msg}"
    );
}

/// resource_depth_overflow_errors: MAX_ANCESTOR_DEPTH chain returns Err, not truncated Ok.
#[tokio::test]
async fn resource_depth_overflow_errors() {
    let db = setup_db().await;
    let (_org_id, tenant_a, _) = setup_two_tenants(&db).await;

    let res_repo = SurrealResourceRepository::new(db.clone());

    // Build a chain of 52 resources (> MAX_ANCESTOR_DEPTH=50).
    let root = res_repo
        .create(CreateResource {
            tenant_id: tenant_a,
            name: "Depth root".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let mut current_id = root.id;
    for i in 1..=52usize {
        let r = res_repo
            .create(CreateResource {
                tenant_id: tenant_a,
                name: format!("Depth {i}"),
                resource_type: "service".into(),
                parent_id: Some(current_id),
                metadata: None,
            })
            .await
            .unwrap();
        current_id = r.id;
    }

    // Ancestor walk on the deepest leaf must return Err (not a partial Ok list).
    let result = res_repo.get_ancestors(tenant_a, current_id).await;
    assert!(
        result.is_err(),
        "get_ancestors on a chain deeper than MAX_ANCESTOR_DEPTH must return Err"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.to_lowercase().contains("depth")
            || err_msg.to_lowercase().contains("cycle")
            || err_msg.to_lowercase().contains("maximum"),
        "error must mention depth/cycle/maximum, got: {err_msg}"
    );
}
