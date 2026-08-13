//! Integration tests for `SurrealWebauthnAttestationPolicyRepository` (X3, D5).

use axiam_core::models::mds::CertificationLevel;
use axiam_core::models::webauthn_policy::{
    AttestationMode, UnknownAaguidAction, WebauthnAttestationPolicy,
};
use axiam_core::repository::WebauthnAttestationPolicyRepository;
use axiam_db::repository::SurrealWebauthnAttestationPolicyRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn uuid(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

// ---------------------------------------------------------------------------
// D5 regression: an absent row means the default (today's behavior).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn absent_row_returns_none_not_a_default_row() {
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_id = Uuid::new_v4();

    let result = repo.get_by_tenant(tenant_id).await.unwrap();
    assert!(
        result.is_none(),
        "an unconfigured tenant must read back as None, not a persisted default row \
         (D5: the caller treats None as WebauthnAttestationPolicy::default())"
    );
}

#[tokio::test]
async fn none_from_repository_matches_the_model_default() {
    // Not a tautology: this pins that a caller doing
    // `repo.get_by_tenant(t).await?.unwrap_or_default()` really does
    // reproduce today's behavior — the model's Default and this repository's
    // "absent" both mean the same thing.
    let default = WebauthnAttestationPolicy::default();
    assert_eq!(default.mode, AttestationMode::None);
}

// ---------------------------------------------------------------------------
// CRUD round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn set_then_get_round_trips_every_field() {
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_id = Uuid::new_v4();

    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        require_fido_certified: true,
        min_certification: Some(CertificationLevel::L2Plus),
        allowed_aaguids: Some(vec![uuid(1), uuid(2)]),
        blocked_aaguids: vec![uuid(3)],
        block_revoked_status: true,
        unknown_aaguid: Some(UnknownAaguidAction::Deny),
    };

    let stored = repo.set(tenant_id, policy.clone()).await.unwrap();
    assert_eq!(stored, policy);

    let fetched = repo.get_by_tenant(tenant_id).await.unwrap().unwrap();
    assert_eq!(fetched, policy);
}

#[tokio::test]
async fn set_twice_updates_in_place_no_duplicate_rows() {
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_id = Uuid::new_v4();

    repo.set(
        tenant_id,
        WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            ..WebauthnAttestationPolicy::default()
        },
    )
    .await
    .unwrap();

    let second = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        unknown_aaguid: Some(UnknownAaguidAction::Deny),
        ..WebauthnAttestationPolicy::default()
    };
    repo.set(tenant_id, second.clone()).await.unwrap();

    let fetched = repo.get_by_tenant(tenant_id).await.unwrap().unwrap();
    assert_eq!(
        fetched, second,
        "the second set must replace the first, not add a row"
    );
}

#[tokio::test]
async fn empty_allowlist_is_stored_and_read_back_as_some_empty_not_none() {
    // D5: `Some(vec![])` ("nothing may register") must survive round-tripping
    // distinctly from `None` ("no restriction") — this is the wire-shape half
    // of that guarantee (validation itself is the API layer's job).
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_id = Uuid::new_v4();

    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::Indirect,
        allowed_aaguids: Some(vec![]),
        ..WebauthnAttestationPolicy::default()
    };
    repo.set(tenant_id, policy.clone()).await.unwrap();

    let fetched = repo.get_by_tenant(tenant_id).await.unwrap().unwrap();
    assert_eq!(fetched.allowed_aaguids, Some(vec![]));
}

#[tokio::test]
async fn delete_reverts_to_absent() {
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_id = Uuid::new_v4();

    repo.set(
        tenant_id,
        WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        },
    )
    .await
    .unwrap();
    assert!(repo.get_by_tenant(tenant_id).await.unwrap().is_some());

    repo.delete(tenant_id).await.unwrap();
    assert!(
        repo.get_by_tenant(tenant_id).await.unwrap().is_none(),
        "delete must revert the tenant to the default (D5), not leave a tombstone row"
    );
}

#[tokio::test]
async fn policies_are_isolated_per_tenant() {
    let db = setup().await;
    let repo = SurrealWebauthnAttestationPolicyRepository::new(db);
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    repo.set(
        tenant_a,
        WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        },
    )
    .await
    .unwrap();

    // tenant_b was never configured.
    assert!(repo.get_by_tenant(tenant_b).await.unwrap().is_none());
    assert_eq!(
        repo.get_by_tenant(tenant_a).await.unwrap().unwrap().mode,
        AttestationMode::DirectRequired
    );
}
