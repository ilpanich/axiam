//! Integration tests for Resource and Scope repositories using in-memory SurrealDB.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, Pagination, ResourceRepository, ScopeRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealResourceRepository, SurrealScopeRepository,
    SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

mod common;

/// Helper: spin up in-memory DB, run migrations, create org + tenant.
///
/// `Mem` is right for every test here that asserts what a query does. It is NOT
/// right for `concurrent_child_create_never_orphans_after_parent_delete`, which
/// asserts how the engine isolates two overlapping callers — see
/// [`serialising_setup`].
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
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

/// The same fixture on the storage engine production deploys.
///
/// Isolation is a property of the engine, not of the query, and `kv-mem` was
/// measured in 2026-08 to provide less of it than `surrealkv`: it lets two
/// racers both commit a guarded read-modify-write in ~1% of contended rounds,
/// where `surrealkv` and `rocksdb` let none. `tests/common/mod.rs` carries the
/// numbers. A TOCTOU test that runs on `Mem` is measuring an engine AXIAM does
/// not ship, so the one race test in this file uses this instead.
///
/// The returned fixture must be held for the test's duration — it owns the
/// temporary directory the datastore lives in.
async fn serialising_setup() -> (common::SerialisingDb, uuid::Uuid) {
    let db = common::serialising_db().await;

    let org_repo = SurrealOrganizationRepository::new(db.handle());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.handle());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
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
/// exercise both possible interleavings against the engine's actual
/// transaction isolation.
///
/// # The shape of the fix, and why the guard alone was not it (#308)
///
/// This passed for as long as it ran on `Mem`, and failed on **trial 0 of every
/// run** the moment it moved to `surrealkv` — the engine
/// `docker-compose.prod.yml` and the k8s StatefulSet actually run. The delete
/// committed and a `child_of` edge to the deleted parent survived: exactly the
/// orphan D-13/CQ-B46 was written to make impossible.
///
/// Folding the guard into one transaction makes the statements atomic, which is
/// not the property needed. The guard is a **range read** (`SELECT … FROM
/// child_of WHERE out = resource:<id>`) and the racing create **inserts into
/// that range** — a phantom, and excluding phantoms takes serialisable
/// isolation. These engines give snapshot isolation: they detect write-write
/// conflicts on the same key, and the two transactions had no key in common.
///
/// So the fix is not a better query. `create`, `create_uma_registered` and
/// `update`'s re-parent now bump `child_epoch` on the parent inside the same
/// transaction as the `RELATE` (schema v34), which is a write to the very row
/// `delete` removes. One of the two must now lose: if the create commits first
/// the delete conflicts and aborts, and if the delete commits first the create's
/// claim matches nothing and throws. Neither order leaves an orphan.
///
/// This is the acceptance test for that fix, and it was checked both ways
/// before being trusted: with the repository change reverted it fails on trial
/// 0 of every run, and with it applied it survived 200 trials × the same race.
/// TRIALS is 15 because the old code never got past the first one; the margin
/// is for scheduling luck, not for hunting a rare event.
///
/// One thing it does NOT prove, said here rather than left to be assumed. In
/// the observed runs the create always commits first and `delete` then refuses
/// through the ordinary child guard — so this exercises the fix's *atomicity*
/// (the edge is never visible without the parent write beside it) rather than
/// the conflict itself. `create_rejects_a_parent_that_does_not_exist` covers
/// the other half deterministically: the branch where the claim matches nothing
/// and must throw instead of writing a dangling edge.
#[tokio::test]
async fn concurrent_child_create_never_orphans_after_parent_delete() {
    const TRIALS: usize = 15;

    for trial in 0..TRIALS {
        let (db, tenant_id) = serialising_setup().await;
        let repo = std::sync::Arc::new(SurrealResourceRepository::new(db.handle()));

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

/// The other half of the #308 fix, and the half that is deterministic.
///
/// `claim_parent` throws when its `UPDATE` of the parent matches no row, and
/// that `THROW` is load-bearing rather than a friendlier error message. If the
/// parent has already been deleted, the claim matches nothing — and *nothing
/// matching is not a conflict*, so without the throw the create would sail past
/// and `RELATE` an edge to a record that no longer exists. That is the very
/// orphan the concurrent test above is about, reached by a slower route.
///
/// Deleting the parent first makes the losing side of the race reproducible
/// without needing to win a scheduling coin flip.
#[tokio::test]
async fn create_rejects_a_parent_that_does_not_exist() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db.clone());

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "doomed-parent".into(),
            resource_type: "project".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();
    let parent_id = parent.id;
    repo.delete(tenant_id, parent_id).await.unwrap();

    let result = repo
        .create(CreateResource {
            tenant_id,
            name: "would-be-orphan".into(),
            resource_type: "service".into(),
            parent_id: Some(parent_id),
            metadata: None,
        })
        .await;

    assert!(
        result.is_err(),
        "attaching a child to a deleted parent must fail — before #308 this \
         silently wrote a child_of edge to a record that no longer existed"
    );

    // And it must fail without leaving anything behind: no dangling edge, and
    // no half-created resource. A rolled-back transaction is the point.
    let mut edges = db
        .query(format!(
            "SELECT * FROM child_of WHERE out = resource:`{parent_id}`"
        ))
        .await
        .unwrap();
    let remaining: Vec<surrealdb_types::Value> = edges.take(0).unwrap();
    assert!(
        remaining.is_empty(),
        "a refused create must not leave a child_of edge behind"
    );
}

/// The same guard on the re-parent path. `update` already validated the new
/// parent with `get_by_id`, but that is a READ outside the transaction and
/// cannot conflict with a concurrent delete — so the claim has to hold here
/// too, and it has to refuse the same way.
#[tokio::test]
async fn reparent_rejects_a_parent_that_does_not_exist() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db.clone());

    let child = repo
        .create(CreateResource {
            tenant_id,
            name: "mover".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let result = repo
        .update(
            tenant_id,
            child.id,
            axiam_core::models::resource::UpdateResource {
                parent_id: Some(Some(uuid::Uuid::new_v4())),
                ..Default::default()
            },
        )
        .await;

    assert!(
        result.is_err(),
        "re-parenting onto a resource that does not exist must fail"
    );

    // The old parent edge state must be untouched: the re-parent transaction
    // deletes the old edge before claiming the new parent, so a failed claim
    // that did not roll back would leave the child detached from everything.
    let unchanged = repo.get_by_id(tenant_id, child.id).await.unwrap();
    assert!(
        unchanged.parent_id.is_none(),
        "a refused re-parent must leave the resource as it was"
    );
}

/// A child may not be attached across a tenant boundary. `claim_parent` carries
/// `WHERE tenant_id = $tenant_id`, so a parent in another tenant matches
/// nothing and the create is refused — the same code path as a parent that does
/// not exist, which is the correct answer: from this tenant's side, it does not.
#[tokio::test]
async fn create_rejects_a_parent_in_another_tenant() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealResourceRepository::new(db.clone());

    let parent = repo
        .create(CreateResource {
            tenant_id,
            name: "other-tenants-parent".into(),
            resource_type: "project".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let intruder_tenant = uuid::Uuid::new_v4();
    let result = repo
        .create(CreateResource {
            tenant_id: intruder_tenant,
            name: "cross-tenant-child".into(),
            resource_type: "service".into(),
            parent_id: Some(parent.id),
            metadata: None,
        })
        .await;

    assert!(
        result.is_err(),
        "a resource in one tenant must not be attachable under another tenant's node"
    );
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
                search: None,
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
                search: None,
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
