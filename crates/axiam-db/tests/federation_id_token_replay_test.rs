//! Integration tests for `SurrealProviderIdTokenReplayRepository` (G-A, #816,
//! D-N10): the native sign-in replay store. A repeated
//! `(tenant_id, provider_id, token_hash)` is `ReplayDetected`; the same hash
//! under another provider or tenant is a different tuple; concurrent inserts
//! of one tuple have exactly one winner; the sweep removes only expired rows.

use axiam_core::error::AxiamError;
use axiam_core::repository::ProviderIdTokenReplayRepository;
use axiam_db::SurrealProviderIdTokenReplayRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

mod common;

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// A hex digest-shaped value; the store never sees a token.
fn hash(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

#[tokio::test]
async fn a_second_insert_of_the_same_token_hash_is_a_replay() {
    let repo = SurrealProviderIdTokenReplayRepository::new(setup().await);
    let (tenant, provider) = (Uuid::new_v4(), Uuid::new_v4());
    let exp = Utc::now() + Duration::minutes(5);

    repo.insert_id_token(tenant, provider, &hash(1), exp)
        .await
        .expect("first sighting is recorded");
    let err = repo
        .insert_id_token(tenant, provider, &hash(1), exp)
        .await
        .expect_err("second sighting is refused");
    assert!(matches!(err, AxiamError::ReplayDetected), "{err:?}");
}

#[tokio::test]
async fn the_key_is_tenant_provider_and_hash_together() {
    let repo = SurrealProviderIdTokenReplayRepository::new(setup().await);
    let (tenant, provider) = (Uuid::new_v4(), Uuid::new_v4());
    let exp = Utc::now() + Duration::minutes(5);

    repo.insert_id_token(tenant, provider, &hash(2), exp)
        .await
        .unwrap();
    repo.insert_id_token(tenant, Uuid::new_v4(), &hash(2), exp)
        .await
        .expect("another provider is another tuple");
    repo.insert_id_token(Uuid::new_v4(), provider, &hash(2), exp)
        .await
        .expect("another tenant is another tuple");
    repo.insert_id_token(tenant, provider, &hash(3), exp)
        .await
        .expect("another token is another tuple");
}

/// On `surrealkv`, the engine production runs (see `tests/common`).
#[tokio::test]
async fn concurrent_inserts_of_one_token_have_exactly_one_winner() {
    const RACERS: usize = 8;
    let db = common::serialising_db().await;
    let repo = SurrealProviderIdTokenReplayRepository::new(db.handle());
    let (tenant, provider) = (Uuid::new_v4(), Uuid::new_v4());
    let exp = Utc::now() + Duration::minutes(5);

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let repo = repo.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        set.spawn(async move {
            barrier.wait().await;
            repo.insert_id_token(tenant, provider, &hash(4), exp).await
        });
    }
    let mut wins = 0;
    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(()) => wins += 1,
            Err(AxiamError::ReplayDetected) => {}
            Err(other) => panic!("a loser is a replay, not an error: {other:?}"),
        }
    }
    assert_eq!(wins, 1, "one presentation wins, every other is refused");
}

#[tokio::test]
async fn the_sweep_removes_only_expired_rows() {
    let repo = SurrealProviderIdTokenReplayRepository::new(setup().await);
    let (tenant, provider) = (Uuid::new_v4(), Uuid::new_v4());

    repo.insert_id_token(tenant, provider, &hash(5), Utc::now() - Duration::hours(1))
        .await
        .unwrap();
    repo.insert_id_token(
        tenant,
        provider,
        &hash(6),
        Utc::now() + Duration::minutes(5),
    )
    .await
    .unwrap();

    assert_eq!(repo.cleanup_expired().await.unwrap(), 1);
    assert!(matches!(
        repo.insert_id_token(
            tenant,
            provider,
            &hash(6),
            Utc::now() + Duration::minutes(5)
        )
        .await,
        Err(AxiamError::ReplayDetected)
    ));
    repo.insert_id_token(
        tenant,
        provider,
        &hash(5),
        Utc::now() + Duration::minutes(5),
    )
    .await
    .expect("the expired row is gone");
    assert_eq!(repo.cleanup_expired().await.unwrap(), 0);
}
