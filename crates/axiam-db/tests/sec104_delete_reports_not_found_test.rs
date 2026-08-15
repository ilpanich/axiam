//! SEC-104 — `delete` must not answer success for a foreign or unknown id.
//!
//! Five repositories (`group`, `role`, `resource`, `permission`,
//! `service_account`) deleted a record plus its edges inside one transaction
//! and returned `Ok(())` without looking at whether anything matched. The
//! `WHERE tenant_id = $tenant_id` predicate was — and is — correct, so no other
//! tenant's data was ever touched, and because the answer was a uniform 204 for
//! a foreign id, a nonexistent id and a real one, it was not an existence
//! oracle either.
//!
//! What it cost is an administrator who deletes the wrong id, is told it
//! worked, and believes the group is gone. `user` and `webhook` already got
//! this right; these tests pin the other five to the same shape, in the
//! repository, so `axiam-scim`'s hand-written pre-check could be deleted rather
//! than recopied for every future resource type.
//!
//! Every assertion below fails before the fix (the call returns `Ok(())`).

use axiam_core::error::AxiamError;
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, PermissionRepository, ResourceRepository,
    RoleRepository, ServiceAccountRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealServiceAccountRepository,
    SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = surrealdb::engine::local::Db;

/// Org + two tenants: `(tenant_a, tenant_b)`.
async fn setup() -> (Surreal<Db>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SEC-104 Org".into(),
            slug: "sec104-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenants = SurrealTenantRepository::new(db.clone());
    let a = tenants
        .create(CreateTenant {
            organization_id: org.id,
            name: "A".into(),
            slug: "sec104-a".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let b = tenants
        .create(CreateTenant {
            organization_id: org.id,
            name: "B".into(),
            slug: "sec104-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, a.id, b.id)
}

fn assert_not_found(result: Result<(), AxiamError>, what: &str) {
    match result {
        Err(AxiamError::NotFound { .. }) => {}
        other => panic!("{what}: expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn group_delete_reports_not_found_for_unknown_and_foreign_ids() {
    let (db, a, b) = setup().await;
    let repo = SurrealGroupRepository::new(db.clone());

    assert_not_found(repo.delete(a, Uuid::new_v4()).await, "unknown group id");

    let owned = repo
        .create(CreateGroup {
            tenant_id: a,
            name: "engineering".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap();

    // Tenant B may not delete it, and must be told so rather than told it
    // worked. The row survives, which is the property that always held.
    assert_not_found(repo.delete(b, owned.id).await, "foreign group id");
    assert!(repo.get_by_id(a, owned.id).await.is_ok());

    // The owner still succeeds, once.
    repo.delete(a, owned.id).await.expect("owner may delete");
    assert_not_found(repo.delete(a, owned.id).await, "second delete");
}

#[tokio::test]
async fn role_delete_reports_not_found_for_unknown_and_foreign_ids() {
    let (db, a, b) = setup().await;
    let repo = SurrealRoleRepository::new(db.clone());

    assert_not_found(repo.delete(a, Uuid::new_v4()).await, "unknown role id");

    let owned = repo
        .create(CreateRole {
            tenant_id: a,
            name: "auditor".into(),
            description: String::new(),
            is_global: true,
        })
        .await
        .unwrap();

    assert_not_found(repo.delete(b, owned.id).await, "foreign role id");
    assert!(repo.get_by_id(a, owned.id).await.is_ok());
    repo.delete(a, owned.id).await.expect("owner may delete");
}

#[tokio::test]
async fn permission_delete_reports_not_found_for_unknown_and_foreign_ids() {
    let (db, a, b) = setup().await;
    let repo = SurrealPermissionRepository::new(db.clone());

    assert_not_found(
        repo.delete(a, Uuid::new_v4()).await,
        "unknown permission id",
    );

    let owned = repo
        .create(CreatePermission {
            tenant_id: a,
            action: "orders:read".into(),
            description: String::new(),
        })
        .await
        .unwrap();

    assert_not_found(repo.delete(b, owned.id).await, "foreign permission id");
    assert!(repo.get_by_id(a, owned.id).await.is_ok());
    repo.delete(a, owned.id).await.expect("owner may delete");
}

#[tokio::test]
async fn service_account_delete_reports_not_found_for_unknown_and_foreign_ids() {
    let (db, a, b) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db.clone());

    assert_not_found(
        repo.delete(a, Uuid::new_v4()).await,
        "unknown service account id",
    );

    let (owned, _secret) = repo
        .create(CreateServiceAccount {
            tenant_id: a,
            name: "ci-runner".into(),
            description: None,
        })
        .await
        .unwrap();

    assert_not_found(repo.delete(b, owned.id).await, "foreign service account id");
    assert!(repo.get_by_id(a, owned.id).await.is_ok());
    repo.delete(a, owned.id).await.expect("owner may delete");
}

#[tokio::test]
async fn resource_delete_reports_not_found_for_unknown_and_foreign_ids() {
    let (db, a, b) = setup().await;
    let repo = SurrealResourceRepository::new(db.clone());

    assert_not_found(repo.delete(a, Uuid::new_v4()).await, "unknown resource id");

    let owned = repo
        .create(CreateResource {
            tenant_id: a,
            name: "warehouse".into(),
            resource_type: "folder".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    assert_not_found(repo.delete(b, owned.id).await, "foreign resource id");
    assert!(repo.get_by_id(a, owned.id).await.is_ok());
    repo.delete(a, owned.id).await.expect("owner may delete");
}
