//! Pending SAML `AuthnRequest`s against the real datastore (T23.2.3, G-2,
//! schema v73).
//!
//! What lives in the datastore rather than in plain Rust: the request-id replay
//! guard (a unique index that must outlive consumption), tenant isolation on
//! every verb, expiry, the single-use consume on the X6 arbiter (raced on
//! `surrealkv`, the engine production runs — see `tests/common`), and the rows
//! going with their tenant.
//!
//! No assertion message in this file formats a handle, a digest or a request id.

mod common;

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_authn_request::NewPendingSamlRequest;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, PendingSamlRequestRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPendingSamlRequestRepository, SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>) -> SurrealPendingSamlRequestRepository<Db> {
    SurrealPendingSamlRequestRepository::new(db.clone())
}

/// A fresh 64-hex digest, as the endpoint writes one.
fn digest() -> String {
    hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()))
}

fn pending(
    tenant_id: Uuid,
    sp_id: Uuid,
    request_id: Option<&str>,
    handle_hash: &str,
    ttl_secs: i64,
) -> NewPendingSamlRequest {
    let now = Utc::now();
    NewPendingSamlRequest {
        tenant_id,
        sp_id,
        request_id: request_id.map(str::to_owned),
        acs_url: "https://sp.example.com/saml/acs".into(),
        relay_state: Some("relay-1".into()),
        force_authn: true,
        is_passive: false,
        handle_hash: handle_hash.to_owned(),
        binding_hash: digest(),
        created_at: now,
        expires_at: now + Duration::seconds(ttl_secs),
    }
}

#[tokio::test]
async fn a_pending_request_round_trips_and_is_consumed_once() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, sp) = (Uuid::new_v4(), Uuid::new_v4());
    let handle = digest();
    let input = pending(tenant, sp, Some("_req1"), &handle, 600);
    repo.create(input.clone()).await.unwrap();

    let got = repo
        .get_pending(tenant, &handle)
        .await
        .unwrap()
        .expect("the pending row");
    assert_eq!(got.sp_id, sp);
    assert_eq!(got.request_id.as_deref(), Some("_req1"));
    assert_eq!(got.acs_url, input.acs_url);
    assert_eq!(got.relay_state, input.relay_state);
    assert!(got.force_authn && !got.is_passive);
    assert!(got.binding_hash == input.binding_hash);
    // Stored at full precision: the ForceAuthn comparison relies on it.
    assert_eq!(got.created_at, input.created_at);

    // A read consumes nothing.
    assert!(repo.get_pending(tenant, &handle).await.unwrap().is_some());

    let consumed = repo.consume(tenant, &handle).await.unwrap();
    assert!(consumed.is_some(), "the first consume wins");
    assert!(
        repo.consume(tenant, &handle).await.unwrap().is_none(),
        "the second consume of one handle must lose"
    );
    assert!(
        repo.get_pending(tenant, &handle).await.unwrap().is_none(),
        "a consumed row is no longer pending"
    );
}

/// **The replay guard.** A second `AuthnRequest` with an `ID` the SP already
/// used is refused — and still refused after the first was consumed, because
/// consumed rows are kept until they expire.
#[tokio::test]
async fn a_request_id_is_single_use_per_service_provider_even_after_consumption() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, sp) = (Uuid::new_v4(), Uuid::new_v4());
    let first = digest();
    repo.create(pending(tenant, sp, Some("_dup"), &first, 600))
        .await
        .unwrap();

    let replay = repo
        .create(pending(tenant, sp, Some("_dup"), &digest(), 600))
        .await;
    assert!(
        matches!(replay, Err(AxiamError::ReplayDetected)),
        "a replayed request id must be ReplayDetected"
    );

    repo.consume(tenant, &first)
        .await
        .unwrap()
        .expect("consumed");
    let after = repo
        .create(pending(tenant, sp, Some("_dup"), &digest(), 600))
        .await;
    assert!(
        matches!(after, Err(AxiamError::ReplayDetected)),
        "the guard outlives consumption"
    );

    // The same id from another SP, or in another tenant, is another request.
    repo.create(pending(
        tenant,
        Uuid::new_v4(),
        Some("_dup"),
        &digest(),
        600,
    ))
    .await
    .expect("another SP may use the same id");
    repo.create(pending(Uuid::new_v4(), sp, Some("_dup"), &digest(), 600))
        .await
        .expect("another tenant may use the same id");
}

/// IdP-initiated rows answer no request and never collide with one another.
#[tokio::test]
async fn idp_initiated_rows_do_not_collide() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, sp) = (Uuid::new_v4(), Uuid::new_v4());
    for _ in 0..3 {
        repo.create(pending(tenant, sp, None, &digest(), 600))
            .await
            .expect("an IdP-initiated row");
    }
}

#[tokio::test]
async fn another_tenant_can_neither_read_nor_consume_a_handle() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, other, sp) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let handle = digest();
    repo.create(pending(tenant, sp, Some("_x"), &handle, 600))
        .await
        .unwrap();
    assert!(repo.get_pending(other, &handle).await.unwrap().is_none());
    assert!(repo.consume(other, &handle).await.unwrap().is_none());
    // …and the failed attempt burned nothing.
    assert!(repo.consume(tenant, &handle).await.unwrap().is_some());
}

#[tokio::test]
async fn an_expired_request_is_neither_pending_nor_consumable_and_is_swept() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, sp) = (Uuid::new_v4(), Uuid::new_v4());
    let dead = digest();
    let live = digest();
    repo.create(pending(tenant, sp, Some("_dead"), &dead, -5))
        .await
        .unwrap();
    repo.create(pending(tenant, sp, Some("_live"), &live, 600))
        .await
        .unwrap();
    assert!(repo.get_pending(tenant, &dead).await.unwrap().is_none());
    assert!(repo.consume(tenant, &dead).await.unwrap().is_none());

    assert_eq!(repo.cleanup_expired().await.unwrap(), 1);
    assert!(repo.get_pending(tenant, &live).await.unwrap().is_some());
}

#[tokio::test]
async fn the_rows_go_with_their_tenant() {
    let db = setup().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SAML pending".into(),
            slug: "saml-pending".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenants = SurrealTenantRepository::new(db.clone());
    let tenant = tenants
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SAML pending".into(),
            slug: "saml-pending-t".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let repo = repo(&db);
    let handle = digest();
    repo.create(pending(tenant.id, Uuid::new_v4(), Some("_t"), &handle, 600))
        .await
        .unwrap();

    tenants.delete(tenant.id).await.unwrap();
    assert!(
        repo.get_pending(tenant.id, &handle)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.cleanup_expired().await.unwrap(),
        0,
        "nothing left over"
    );
}

/// **Exactly one concurrent continue wins**, on the engine production runs. A
/// failure here is a regression in the arbiter, not flakiness: see
/// `permission_ticket_test::concurrent_redemptions_yield_exactly_one_winner`
/// for the diagnosis order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_consumes_yield_exactly_one_winner() {
    const ROUNDS: usize = 100;
    const RACERS: usize = 8;

    let db = common::serialising_db().await;
    let repo = SurrealPendingSamlRequestRepository::new(db.handle());
    let (tenant, sp) = (Uuid::new_v4(), Uuid::new_v4());

    for round in 0..ROUNDS {
        let handle = digest();
        repo.create(pending(
            tenant,
            sp,
            Some(&format!("_r{round}")),
            &handle,
            600,
        ))
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let handle = handle.clone();
            set.spawn(async move {
                barrier.wait().await;
                repo.consume(tenant, &handle).await.unwrap()
            });
        }
        let mut winners = 0;
        while let Some(result) = set.join_next().await {
            if result.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one consume may win (round {round})");
    }
}
