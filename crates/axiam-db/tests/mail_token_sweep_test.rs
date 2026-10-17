//! The expiry sweep never gives an account its daily mail cap back.
//!
//! A password reset link (three a day) and a resent verification link (two a
//! day) are capped by counting the account's tokens minted since UTC midnight.
//! `delete_expired` deleted every consumed or expired token, so a sweep run
//! during the day lowered that count: an account that had used its three reset
//! links got three more once they were consumed or had expired and the cleanup
//! task had run. Tokens minted today are now kept until the day is over;
//! older dead tokens are still deleted.

use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::repository::{EmailVerificationTokenRepository, PasswordResetTokenRepository};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealPasswordResetTokenRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Backdate a token so it was minted before today.
async fn mint_yesterday(db: &Surreal<Db>, table: &str, hash: &str) {
    db.query(format!(
        "UPDATE {table} SET created_at = time::now() - 2d WHERE token_hash = $h"
    ))
    .bind(("h", hash.to_owned()))
    .await
    .unwrap()
    .check()
    .unwrap();
}

#[tokio::test]
async fn the_sweep_keeps_todays_reset_tokens_so_the_cap_still_counts_them() {
    let db = setup().await;
    let repo = SurrealPasswordResetTokenRepository::new(db.clone());
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let mint = |hash: &str, expires_in: Duration| CreatePasswordResetToken {
        tenant_id,
        user_id,
        token_hash: hash.into(),
        expires_at: Utc::now() + expires_in,
    };

    // Today: one consumed, one expired, one live.
    repo.create(mint("today-consumed", Duration::hours(1)))
        .await
        .unwrap();
    repo.consume(tenant_id, "today-consumed").await.unwrap();
    repo.create(mint("today-expired", Duration::seconds(-1)))
        .await
        .unwrap();
    repo.create(mint("today-live", Duration::hours(1)))
        .await
        .unwrap();
    // Before today: one consumed, one expired — both garbage.
    repo.create(mint("old-consumed", Duration::hours(1)))
        .await
        .unwrap();
    repo.consume(tenant_id, "old-consumed").await.unwrap();
    mint_yesterday(&db, "password_reset_token", "old-consumed").await;
    repo.create(mint("old-expired", Duration::seconds(-1)))
        .await
        .unwrap();
    mint_yesterday(&db, "password_reset_token", "old-expired").await;

    assert_eq!(repo.count_today(tenant_id, user_id).await.unwrap(), 3);
    assert_eq!(repo.delete_expired().await.unwrap(), 2, "only the old ones");
    assert_eq!(
        repo.count_today(tenant_id, user_id).await.unwrap(),
        3,
        "the day's count is what it was before the sweep"
    );
    assert!(
        repo.get_by_token_hash(tenant_id, "today-live")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_sweep_keeps_todays_verification_tokens_so_the_cap_still_counts_them() {
    let db = setup().await;
    let repo = SurrealEmailVerificationTokenRepository::new(db.clone());
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let mint = |hash: &str, expires_in: Duration| CreateEmailVerificationToken {
        tenant_id,
        user_id,
        token_hash: hash.into(),
        email: "someone@example.com".into(),
        expires_at: Utc::now() + expires_in,
    };

    repo.create(mint("today-consumed", Duration::hours(24)))
        .await
        .unwrap();
    repo.consume(tenant_id, "today-consumed").await.unwrap();
    repo.create(mint("today-expired", Duration::seconds(-1)))
        .await
        .unwrap();
    repo.create(mint("old-expired", Duration::seconds(-1)))
        .await
        .unwrap();
    mint_yesterday(&db, "email_verification_token", "old-expired").await;

    assert_eq!(repo.count_today(tenant_id, user_id).await.unwrap(), 2);
    assert_eq!(repo.delete_expired().await.unwrap(), 1, "only the old one");
    assert_eq!(repo.count_today(tenant_id, user_id).await.unwrap(), 2);
}
