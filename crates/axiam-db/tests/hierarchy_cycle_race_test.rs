//! Item 8 of the 1.1.0 atomicity audit: two re-parents that each close half
//! of a loop never both land.
//!
//! The cycle check walked the new parent's ancestors before the write, in
//! statements of its own, and the write claimed only the new parent. Two
//! re-parents X→Y and Z→W, where Z is above Y and X is above W, each walked a
//! hierarchy without the other's edge and both committed: X → Y → Z → W → X.
//! Each re-parent now walks inside its own transaction and claims the tenant's
//! hierarchy row there (`tenant.hierarchy_epoch`, schema v105).
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs.
//! Each round builds two two-node chains, holds both movers at a barrier, then
//! releases them together. Exactly one move may land; the other is refused as
//! a cycle, and the hierarchy stays walkable from every node.

mod common;

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::resource::{CreateResource, UpdateResource};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OrganizationRepository, ResourceRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealResourceRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

async fn tenant(db: &Surreal<Db>, n: usize) -> Uuid {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {n}"),
            slug: format!("org-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {n}"),
            slug: format!("tenant-{n}"),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn node(
    repo: &SurrealResourceRepository<Db>,
    tenant_id: Uuid,
    name: &str,
    parent_id: Option<Uuid>,
) -> Uuid {
    repo.create(CreateResource {
        tenant_id,
        name: name.into(),
        resource_type: "folder".into(),
        parent_id,
        metadata: None,
    })
    .await
    .unwrap()
    .id
}

fn move_under(parent: Uuid) -> UpdateResource {
    UpdateResource {
        parent_id: Some(Some(parent)),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_re_parents_that_close_a_loop_never_both_land() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let tenant_id = tenant(&db, round).await;
        let repo = SurrealResourceRepository::new(db.handle());
        // Z is above Y, and X is above W.
        let z = node(&repo, tenant_id, "z", None).await;
        let y = node(&repo, tenant_id, "y", Some(z)).await;
        let x = node(&repo, tenant_id, "x", None).await;
        let w = node(&repo, tenant_id, "w", Some(x)).await;

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut racers = Vec::new();
        for (moved, parent) in [(x, y), (z, w)] {
            let (repo, barrier) = (SurrealResourceRepository::new(db.handle()), barrier.clone());
            racers.push(tokio::spawn(async move {
                // What the handler sees first: on its own, each move is legal.
                let above = repo.get_ancestors(tenant_id, parent).await.unwrap();
                assert!(
                    above.iter().all(|a| a.id != moved),
                    "round {round}: the read"
                );
                barrier.wait().await;
                repo.update(tenant_id, moved, move_under(parent)).await
            }));
        }
        let mut landed = 0;
        for racer in racers {
            match racer.await.unwrap() {
                Ok(_) => landed += 1,
                Err(AxiamError::Validation { message }) => assert_eq!(
                    message, "cycle detected in resource hierarchy",
                    "round {round}: the loser is refused as a cycle"
                ),
                Err(other) => panic!("round {round}: unexpected refusal {other:?}"),
            }
        }
        assert_eq!(landed, 1, "round {round}: exactly one move lands");
        for id in [x, y, z, w] {
            let chain = repo.get_ancestors(tenant_id, id).await;
            assert!(
                chain.is_ok(),
                "round {round}: the hierarchy has no cycle through {id}: {chain:?}"
            );
        }
    }
}

/// The sequential half: a move whose new parent already sits below it is
/// refused by the walk inside the transaction, and writes nothing — not even
/// the claim.
#[tokio::test]
async fn a_re_parent_under_its_own_descendant_is_refused_and_writes_nothing() {
    let db = common::serialising_db().await;
    let tenant_id = tenant(&db, 0).await;
    let repo = SurrealResourceRepository::new(db.handle());
    let a = node(&repo, tenant_id, "a", None).await;
    let b = node(&repo, tenant_id, "b", Some(a)).await;
    let c = node(&repo, tenant_id, "c", Some(b)).await;

    let refused = repo.update(tenant_id, a, move_under(c)).await;
    assert!(
        matches!(refused, Err(AxiamError::Validation { ref message }) if message == "cycle detected in resource hierarchy"),
        "{refused:?}"
    );
    assert_eq!(repo.get_by_id(tenant_id, a).await.unwrap().parent_id, None);
    let epoch: Option<i64> = db
        .query("SELECT VALUE hierarchy_epoch FROM type::record('tenant', $t)")
        .bind(("t", tenant_id.to_string()))
        .await
        .unwrap()
        .take::<Vec<Option<i64>>>(0)
        .unwrap()
        .into_iter()
        .next()
        .flatten();
    assert_eq!(epoch, None, "a refused move rolls its claim back");

    // A legal move claims the row once.
    let d = node(&repo, tenant_id, "d", None).await;
    repo.update(tenant_id, d, move_under(c)).await.unwrap();
    let epoch: Option<i64> = db
        .query("SELECT VALUE hierarchy_epoch FROM type::record('tenant', $t)")
        .bind(("t", tenant_id.to_string()))
        .await
        .unwrap()
        .take::<Vec<Option<i64>>>(0)
        .unwrap()
        .into_iter()
        .next()
        .flatten();
    assert_eq!(epoch, Some(1));
}
