//! Integration tests for Resource and Scope repositories using in-memory SurrealDB.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{
    OrganizationRepository, Pagination, ResourceRepository, ScopeRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealResourceRepository, SurrealScopeRepository,
    SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB, run migrations, create org + tenant.
async fn setup() -> (Surreal<surrealdb::engine::local::Db>, uuid::Uuid) {
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

    (db, tenant.id)
}

// ---------------------------------------------------------------------------
// Resource tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_resource() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let res = repo
        .create(CreateResource {
            tenant_id,
            name: "my-service".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(res.tenant_id, tenant_id);
    assert_eq!(res.name, "my-service");
    assert_eq!(res.resource_type, "service");
    assert!(res.parent_id.is_none());

    let fetched = repo.get_by_id(tenant_id, res.id).await.unwrap();
    assert_eq!(fetched.id, res.id);
}

#[tokio::test]
async fn create_with_parent() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "parent-service".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let child = repo
        .create(CreateResource {
            tenant_id,
            name: "child-endpoint".into(),
            resource_type: "endpoint".into(),
            parent_id: Some(parent.id),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(child.parent_id, Some(parent.id));
}

#[tokio::test]
async fn update_resource() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let res = repo
        .create(CreateResource {
            tenant_id,
            name: "original".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            res.id,
            axiam_core::models::resource::UpdateResource {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "renamed");
    assert_eq!(updated.resource_type, "service"); // unchanged
}

#[tokio::test]
async fn delete_resource() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let res = repo
        .create(CreateResource {
            tenant_id,
            name: "to-delete".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, res.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, res.id).await;
    assert!(result.is_err(), "deleted resource should not be found");
}

#[tokio::test]
async fn list_resources_with_pagination() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    for i in 0..5 {
        repo.create(CreateResource {
            tenant_id,
            name: format!("resource-{i}"),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
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
async fn get_children() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "parent".into(),
            resource_type: "project".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    repo.create(CreateResource {
        tenant_id,
        name: "child-a".into(),
        resource_type: "service".into(),
        parent_id: Some(parent.id),
        metadata: None,
    })
    .await
    .unwrap();

    repo.create(CreateResource {
        tenant_id,
        name: "child-b".into(),
        resource_type: "service".into(),
        parent_id: Some(parent.id),
        metadata: None,
    })
    .await
    .unwrap();

    let children = repo.get_children(tenant_id, parent.id).await.unwrap();
    assert_eq!(children.len(), 2);

    let names: Vec<&str> = children.iter().map(|r| r.name.as_str()).collect();
    assert!(names.contains(&"child-a"));
    assert!(names.contains(&"child-b"));
}

#[tokio::test]
async fn get_ancestors() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    // Create a 3-level hierarchy: grandparent -> parent -> child.
    let grandparent = repo
        .create(CreateResource {
            tenant_id,
            name: "grandparent".into(),
            resource_type: "org".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "parent".into(),
            resource_type: "project".into(),
            parent_id: Some(grandparent.id),
            metadata: None,
        })
        .await
        .unwrap();

    let child = repo
        .create(CreateResource {
            tenant_id,
            name: "child".into(),
            resource_type: "service".into(),
            parent_id: Some(parent.id),
            metadata: None,
        })
        .await
        .unwrap();

    let ancestors = repo.get_ancestors(tenant_id, child.id).await.unwrap();
    assert_eq!(ancestors.len(), 2);
    assert_eq!(ancestors[0].name, "parent");
    assert_eq!(ancestors[1].name, "grandparent");
}

// ---------------------------------------------------------------------------
// Scope tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_scope() {
    let (db, tenant_id) = setup().await;
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db);

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
            name: "read".into(),
            description: "Read access".into(),
        })
        .await
        .unwrap();

    assert_eq!(scope.tenant_id, tenant_id);
    assert_eq!(scope.resource_id, resource.id);
    assert_eq!(scope.name, "read");

    let fetched = scope_repo.get_by_id(tenant_id, scope.id).await.unwrap();
    assert_eq!(fetched.id, scope.id);
}

#[tokio::test]
async fn update_scope() {
    let (db, tenant_id) = setup().await;
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db);

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
            name: "write".into(),
            description: "Write access".into(),
        })
        .await
        .unwrap();

    let updated = scope_repo
        .update(
            tenant_id,
            scope.id,
            axiam_core::models::scope::UpdateScope {
                description: Some("Full write access".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.description, "Full write access");
    assert_eq!(updated.name, "write"); // unchanged
}

#[tokio::test]
async fn delete_scope() {
    let (db, tenant_id) = setup().await;
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db);

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
            name: "admin".into(),
            description: "Admin scope".into(),
        })
        .await
        .unwrap();

    scope_repo.delete(tenant_id, scope.id).await.unwrap();

    let result = scope_repo.get_by_id(tenant_id, scope.id).await;
    assert!(result.is_err(), "deleted scope should not be found");
}

#[tokio::test]
async fn list_scopes_by_resource() {
    let (db, tenant_id) = setup().await;
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db);

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

    for name in ["read", "write", "admin"] {
        scope_repo
            .create(CreateScope {
                tenant_id,
                resource_id: resource.id,
                name: name.into(),
                description: format!("{name} scope"),
            })
            .await
            .unwrap();
    }

    let scopes = scope_repo
        .list_by_resource(tenant_id, resource.id)
        .await
        .unwrap();
    assert_eq!(scopes.len(), 3);
}

#[tokio::test]
async fn duplicate_scope_name_rejected() {
    let (db, tenant_id) = setup().await;
    let res_repo = SurrealResourceRepository::new(db.clone());
    let scope_repo = SurrealScopeRepository::new(db);

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

    scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id: resource.id,
            name: "unique-scope".into(),
            description: "first".into(),
        })
        .await
        .unwrap();

    let result = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id: resource.id,
            name: "unique-scope".into(),
            description: "second".into(),
        })
        .await;

    assert!(result.is_err(), "duplicate scope name should be rejected");
}
