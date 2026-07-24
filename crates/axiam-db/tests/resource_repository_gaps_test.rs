//! Coverage for `SurrealResourceRepository` branches not exercised by
//! `resource_scope_test.rs` / `req14_tenant_isolation_test.rs`: `get_by_id`
//! not-found, the self-parent cycle-rejection short-circuit (distinct from
//! the ancestor-walk cycle check), and `update` against a nonexistent
//! resource.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::resource::{CreateResource, UpdateResource};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, ResourceRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealResourceRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> (Surreal<surrealdb::engine::local::Db>, Uuid) {
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
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

#[tokio::test]
async fn get_by_id_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);
    assert!(repo.get_by_id(tenant_id, Uuid::new_v4()).await.is_err());
}

#[tokio::test]
async fn update_nonexistent_resource_is_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);
    let result = repo
        .update(
            tenant_id,
            Uuid::new_v4(),
            UpdateResource {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn self_parent_is_rejected_as_a_cycle() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let resource = repo
        .create(CreateResource {
            tenant_id,
            name: "Self-Parenting Resource".into(),
            resource_type: "generic".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let result = repo
        .update(
            tenant_id,
            resource.id,
            UpdateResource {
                parent_id: Some(Some(resource.id)),
                ..Default::default()
            },
        )
        .await;
    assert!(result.is_err(), "a resource cannot be its own parent");
}

#[tokio::test]
async fn get_children_and_ancestors_empty_for_root_leaf() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let root = repo
        .create(CreateResource {
            tenant_id,
            name: "Root".into(),
            resource_type: "generic".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let children = repo.get_children(tenant_id, root.id).await.unwrap();
    assert!(children.is_empty());

    let ancestors = repo.get_ancestors(tenant_id, root.id).await.unwrap();
    assert!(ancestors.is_empty());
}

#[tokio::test]
async fn reparent_to_nonexistent_parent_is_not_found() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let resource = repo
        .create(CreateResource {
            tenant_id,
            name: "Orphan Candidate".into(),
            resource_type: "generic".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let result = repo
        .update(
            tenant_id,
            resource.id,
            UpdateResource {
                parent_id: Some(Some(Uuid::new_v4())),
                ..Default::default()
            },
        )
        .await;
    assert!(
        result.is_err(),
        "re-parenting to a parent that doesn't exist must fail"
    );
}
