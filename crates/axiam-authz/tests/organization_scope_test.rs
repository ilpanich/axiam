//! Authorization for organization-level principals.
//!
//! One rule separates these from ordinary tenant principals: their role
//! assignments live in the organization tenant, and when those are read across
//! a tenant boundary only **global** grants carry. Everything else — deny
//! override, scope narrowing, group inheritance — is the same engine behaving
//! the same way.
//!
//! The bug that motivated all of this: creating a tenant left it unreachable by
//! everyone, the bootstrap super-admin included, because every role assignment
//! the super-admin had was a row in a different tenant and the engine filters
//! every lookup by tenant. See `claude_dev/organization-scope-design.md`.

use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, ResourceRepository, RoleRepository,
    TenantRepository, UserRepository,
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

/// An organization with its organization tenant, one ordinary tenant, and an
/// organization-level user holding a global role.
struct Fixture {
    db: Surreal<TestDb>,
    org_tenant: Uuid,
    tenant_a: Uuid,
    tenant_b: Uuid,
    /// Lives in the organization tenant.
    org_admin: Uuid,
    /// Lives in `tenant_a`.
    tenant_user: Uuid,
}

async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Acme".into(),
            slug: "acme".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenants = SurrealTenantRepository::new(db.clone());
    let org_tenant = tenants
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
    assert_eq!(org_tenant.kind, TenantKind::Organization);

    let mk = |slug: &'static str, name: &'static str| {
        let tenants = SurrealTenantRepository::new(db.clone());
        async move {
            tenants
                .create(CreateTenant {
                    organization_id: org.id,
                    name: name.into(),
                    slug: slug.into(),
                    kind: TenantKind::Standard,
                    metadata: None,
                })
                .await
                .unwrap()
        }
    };
    let tenant_a = mk("tenant-a", "Tenant A").await;
    let tenant_b = mk("tenant-b", "Tenant B").await;

    let users = SurrealUserRepository::new(db.clone());
    let org_admin = users
        .create(CreateUser {
            tenant_id: org_tenant.id,
            username: "root".into(),
            email: "root@acme.test".into(),
            password: "correct horse battery staple".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_user = users
        .create(CreateUser {
            tenant_id: tenant_a.id,
            username: "alice".into(),
            email: "alice@acme.test".into(),
            password: "correct horse battery staple".into(),
            metadata: None,
        })
        .await
        .unwrap();

    Fixture {
        db,
        org_tenant: org_tenant.id,
        tenant_a: tenant_a.id,
        tenant_b: tenant_b.id,
        org_admin: org_admin.id,
        tenant_user: tenant_user.id,
    }
}

fn engine(
    db: &Surreal<TestDb>,
) -> AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
> {
    AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    )
}

/// Create a role in `tenant`, grant it `action`, and assign it to `subject`
/// either globally or on `resource_id`.
async fn grant(
    db: &Surreal<TestDb>,
    tenant: Uuid,
    subject: Uuid,
    role_name: &str,
    is_global: bool,
    action: &str,
    resource_id: Option<Uuid>,
) {
    let roles = SurrealRoleRepository::new(db.clone());
    let perms = SurrealPermissionRepository::new(db.clone());

    let role = roles
        .create(CreateRole {
            tenant_id: tenant,
            name: role_name.into(),
            description: format!("Role: {role_name}"),
            is_global,
        })
        .await
        .unwrap();
    let perm = perms
        .create(CreatePermission {
            tenant_id: tenant,
            action: action.into(),
            description: format!("Can {action}"),
        })
        .await
        .unwrap();
    perms.grant_to_role(tenant, role.id, perm.id).await.unwrap();
    roles
        .assign_to_user(tenant, subject, role.id, resource_id)
        .await
        .unwrap();
}

async fn resource(db: &Surreal<TestDb>, tenant: Uuid, name: &str) -> Uuid {
    SurrealResourceRepository::new(db.clone())
        .create(CreateResource {
            tenant_id: tenant,
            name: name.into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// `subject` in `subject_tenant` asking about `tenant`.
fn request(tenant: Uuid, subject_tenant: Uuid, subject: Uuid, action: &str) -> AccessRequest {
    AccessRequest {
        tenant_id: tenant,
        subject_tenant_id: Some(subject_tenant),
        subject_id: subject,
        action: action.into(),
        resource_id: Uuid::nil(),
        scope: None,
    }
}

// ---------------------------------------------------------------------------

/// The reported bug, as a test.
///
/// Before organization scope, this denied with `no roles assigned`: the
/// super-admin's grants were rows in another tenant, and every lookup the
/// engine performs is filtered by tenant.
#[tokio::test]
async fn an_organization_level_global_grant_reaches_every_tenant() {
    let f = fixture().await;
    grant(
        &f.db,
        f.org_tenant,
        f.org_admin,
        "super-admin",
        true,
        "users:list",
        None,
    )
    .await;
    let e = engine(&f.db);

    for (label, tenant) in [
        ("its own organization tenant", f.org_tenant),
        ("a tenant that existed", f.tenant_a),
        ("another tenant", f.tenant_b),
    ] {
        let d = e
            .check_access(&request(tenant, f.org_tenant, f.org_admin, "users:list"))
            .await
            .unwrap();
        assert!(
            matches!(d, AccessDecision::Allow),
            "organization-level grant must reach {label}, got {d:?}"
        );
    }
}

/// A tenant created *after* the grant is reachable by the same rule, with no
/// write of any kind at creation time.
///
/// This is the property that makes deriving access at check time better than
/// fanning grants out into each tenant: there is nothing to keep in sync.
#[tokio::test]
async fn a_tenant_created_later_is_reachable_without_any_new_grant() {
    let f = fixture().await;
    grant(
        &f.db,
        f.org_tenant,
        f.org_admin,
        "super-admin",
        true,
        "tenants:get",
        None,
    )
    .await;

    let latecomer = SurrealTenantRepository::new(f.db.clone())
        .create(CreateTenant {
            organization_id: SurrealTenantRepository::new(f.db.clone())
                .get_by_id(f.tenant_a)
                .await
                .unwrap()
                .organization_id,
            name: "Tenant C".into(),
            slug: "tenant-c".into(),
            kind: TenantKind::Standard,
            metadata: None,
        })
        .await
        .unwrap();

    let d = engine(&f.db)
        .check_access(&request(
            latecomer.id,
            f.org_tenant,
            f.org_admin,
            "tenants:get",
        ))
        .await
        .unwrap();
    assert!(
        matches!(d, AccessDecision::Allow),
        "a tenant created after the grant must be reachable by it, got {d:?}"
    );
}

/// The rule that keeps tenants isolated from each other.
///
/// A resource-scoped assignment names a resource in the organization tenant. A
/// resource with that id does not exist in the target tenant, and one that
/// happened to share a *name* would be an unrelated thing. Carrying such an
/// assignment across would turn a narrow grant into a grant on something else
/// entirely.
#[tokio::test]
async fn a_resource_scoped_organization_grant_does_not_cross_into_a_tenant() {
    let f = fixture().await;
    let org_resource = resource(&f.db, f.org_tenant, "billing").await;
    grant(
        &f.db,
        f.org_tenant,
        f.org_admin,
        "billing-admin",
        false,
        "reports:read",
        Some(org_resource),
    )
    .await;
    let e = engine(&f.db);

    // It applies where it was granted...
    let mut own = request(f.org_tenant, f.org_tenant, f.org_admin, "reports:read");
    own.resource_id = org_resource;
    assert!(
        matches!(e.check_access(&own).await.unwrap(), AccessDecision::Allow),
        "the grant must still work in the tenant it names"
    );

    // ...and nowhere else, not even on a resource of the same name.
    let twin = resource(&f.db, f.tenant_a, "billing").await;
    let mut across = request(f.tenant_a, f.org_tenant, f.org_admin, "reports:read");
    across.resource_id = twin;
    let d = e.check_access(&across).await.unwrap();
    assert!(
        !d.is_allowed(),
        "a resource-scoped organization grant must not reach a same-named \
         resource in another tenant, got {d:?}"
    );
}

/// Tenant principals stay inside their tenant.
///
/// The feature adds a way *up*; it must not add a way sideways.
#[tokio::test]
async fn a_tenant_users_grant_does_not_reach_another_tenant() {
    let f = fixture().await;
    grant(
        &f.db,
        f.tenant_a,
        f.tenant_user,
        "admin",
        true,
        "users:list",
        None,
    )
    .await;
    let e = engine(&f.db);

    assert!(
        matches!(
            e.check_access(&request(
                f.tenant_a,
                f.tenant_a,
                f.tenant_user,
                "users:list"
            ))
            .await
            .unwrap(),
            AccessDecision::Allow
        ),
        "a tenant user must still be allowed in its own tenant"
    );

    let d = e
        .check_access(&request(
            f.tenant_b,
            f.tenant_a,
            f.tenant_user,
            "users:list",
        ))
        .await
        .unwrap();
    assert!(
        !d.is_allowed(),
        "a tenant user's grant must not reach another tenant, got {d:?}"
    );
}

/// An organization-level principal with no grants is denied like anyone else.
#[tokio::test]
async fn organization_scope_is_not_itself_a_permission() {
    let f = fixture().await;
    let d = engine(&f.db)
        .check_access(&request(
            f.tenant_a,
            f.org_tenant,
            f.org_admin,
            "users:list",
        ))
        .await
        .unwrap();
    assert!(
        !d.is_allowed(),
        "living in the organization tenant grants nothing on its own, got {d:?}"
    );
}

/// `subject_tenant_id: None` must behave exactly as before the field existed.
#[tokio::test]
async fn an_absent_subject_tenant_means_the_same_tenant() {
    let f = fixture().await;
    grant(
        &f.db,
        f.tenant_a,
        f.tenant_user,
        "admin",
        true,
        "users:list",
        None,
    )
    .await;

    let explicit = request(f.tenant_a, f.tenant_a, f.tenant_user, "users:list");
    let implicit = AccessRequest {
        subject_tenant_id: None,
        ..explicit.clone()
    };
    let e = engine(&f.db);
    assert_eq!(
        e.check_access(&explicit).await.unwrap().is_allowed(),
        e.check_access(&implicit).await.unwrap().is_allowed(),
        "naming the subject's own tenant must not change the answer"
    );
}

/// The batch path promises decisions byte-identical to the per-item path. That
/// promise has to survive a batch that mixes principals of both kinds and
/// targets more than one tenant.
#[tokio::test]
async fn batched_decisions_match_per_item_decisions_across_scopes() {
    let f = fixture().await;
    grant(
        &f.db,
        f.org_tenant,
        f.org_admin,
        "super-admin",
        true,
        "users:list",
        None,
    )
    .await;
    grant(
        &f.db,
        f.tenant_a,
        f.tenant_user,
        "admin",
        true,
        "users:list",
        None,
    )
    .await;

    let requests = vec![
        request(f.tenant_a, f.org_tenant, f.org_admin, "users:list"),
        request(f.tenant_b, f.org_tenant, f.org_admin, "users:list"),
        request(f.tenant_a, f.tenant_a, f.tenant_user, "users:list"),
        request(f.tenant_b, f.tenant_a, f.tenant_user, "users:list"),
        request(f.org_tenant, f.org_tenant, f.org_admin, "users:list"),
    ];

    let e = engine(&f.db);
    let batched = e.check_access_batch(&requests).await.unwrap();
    assert_eq!(batched.len(), requests.len());

    for (i, req) in requests.iter().enumerate() {
        let single = e.check_access(req).await.unwrap();
        assert_eq!(
            batched[i].is_allowed(),
            single.is_allowed(),
            "batch item {i} disagreed with the per-item decision"
        );
    }

    // And the answers are the ones the rule predicts.
    assert!(batched[0].is_allowed(), "org admin reaches tenant A");
    assert!(batched[1].is_allowed(), "org admin reaches tenant B");
    assert!(batched[2].is_allowed(), "tenant user in its own tenant");
    assert!(!batched[3].is_allowed(), "tenant user must not reach B");
    assert!(batched[4].is_allowed(), "org admin in the org tenant");
}
