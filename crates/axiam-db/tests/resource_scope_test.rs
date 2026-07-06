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

/// Regression: the child-count guard must still block a delete when a child
/// exists (the transactional/LET-capture rewrite must preserve this
/// pre-existing behavior).
#[tokio::test]
async fn delete_resource_blocked_by_existing_child() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db);

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "parent-with-child".into(),
            resource_type: "project".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    repo.create(CreateResource {
        tenant_id,
        name: "child".into(),
        resource_type: "service".into(),
        parent_id: Some(parent.id),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo.delete(tenant_id, parent.id).await;
    assert!(result.is_err(), "delete must fail when children exist");

    // No partial mutation: the parent must still exist.
    let still_there = repo.get_by_id(tenant_id, parent.id).await;
    assert!(
        still_there.is_ok(),
        "parent must survive a delete blocked by the child guard"
    );
}

/// D-13/CQ-B46 lock-in: a concurrent child-create racing a parent delete
/// must never produce BOTH a successful parent delete AND a surviving
/// `child_of` edge pointing at the now-deleted parent (an orphan). Before
/// this fix, the child-count guard ran as a separate `.query()` round-trip
/// before the delete's own query — a classic TOCTOU window. The fix folds
/// the guard into the SAME transaction as the deletes via a LET-capture, so
/// the read-then-decide-then-delete is atomic.
///
/// Run several trials with real concurrent tasks (mirrors
/// `totp_step_cas_test.rs`'s proven `tokio::spawn` + race pattern) to
/// exercise both possible interleavings against the in-memory engine's
/// actual transaction isolation.
#[tokio::test]
async fn concurrent_child_create_never_orphans_after_parent_delete() {
    const TRIALS: usize = 15;

    for trial in 0..TRIALS {
        let (db, tenant_id) = setup().await;
        let repo = std::sync::Arc::new(SurrealResourceRepository::new(db.clone()));

        let parent = repo
            .create(CreateResource {
                tenant_id,
                name: format!("race-parent-{trial}"),
                resource_type: "project".into(),
                parent_id: None,
                metadata: None,
            })
            .await
            .unwrap();
        let parent_id = parent.id;

        let repo_create = repo.clone();
        let create_handle = tokio::spawn(async move {
            repo_create
                .create(CreateResource {
                    tenant_id,
                    name: format!("race-child-{trial}"),
                    resource_type: "service".into(),
                    parent_id: Some(parent_id),
                    metadata: None,
                })
                .await
        });

        let repo_delete = repo.clone();
        let delete_handle =
            tokio::spawn(async move { repo_delete.delete(tenant_id, parent_id).await });

        let (create_result, delete_result) = tokio::join!(create_handle, delete_handle);
        let create_result = create_result.expect("create task panicked");
        let delete_result = delete_result.expect("delete task panicked");

        // Query the child_of table directly (bypassing the repository,
        // which only ever projects the resource.parent_id column) to
        // observe the exact invariant this transaction guards: a live
        // `child_of` edge pointing at a resource the delete call reports
        // as removed.
        let mut edge_check = db
            .query(format!(
                "SELECT * FROM child_of WHERE out = resource:`{parent_id}`"
            ))
            .await
            .unwrap();
        let remaining_edges: Vec<surrealdb_types::Value> = edge_check.take(0).unwrap();

        if delete_result.is_ok() {
            assert!(
                remaining_edges.is_empty(),
                "trial {trial}: delete succeeded but a child_of edge to the \
                 deleted parent still exists — orphan"
            );
        } else {
            // The guard tripped (it saw the child before the delete could
            // proceed) — the parent must still be present, i.e. no partial
            // mutation ran.
            assert!(
                repo.get_by_id(tenant_id, parent_id).await.is_ok(),
                "trial {trial}: a blocked delete must never partially remove the parent"
            );
        }

        // The create's own success/failure is incidental to this
        // invariant — it either won the race (child exists, delete must
        // have seen it and aborted) or lost it (delete already committed).
        // Both are covered by the branch above; just avoid an unused-var
        // warning.
        let _ = &create_result;
    }
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
