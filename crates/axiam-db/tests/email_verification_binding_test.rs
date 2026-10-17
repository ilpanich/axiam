//! Item A of the 1.1.0 atomicity audit: an email-verification token is bound to
//! the address it was minted for, and an address change spends the links
//! mailed to the old one.
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs:
//! a redemption and a self-service address change, each having made the read
//! its caller makes first (the token's lookup; the handler's read of the
//! current address), wait at a barrier and then write at once. Whichever
//! commits first, the new address must never end up verified by the old
//! address's token.

mod common;

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::email_verification::{
    CreateEmailVerificationToken, EmailVerificationRedemption,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    EmailVerificationTokenRepository, OrganizationRepository, PasswordResetTokenRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealOrganizationRepository,
    SurrealPasswordResetTokenRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

const OLD: &str = "owner@a.example";
const NEW: &str = "victim@b.example";

/// An org, a tenant and a `PendingVerification` user at [`OLD`].
async fn account(db: &Surreal<Db>, n: usize) -> (Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {n}"),
            slug: format!("org-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {n}"),
            slug: format!("tenant-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("owner-{n}"),
            email: OLD.into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    (tenant.id, user.id)
}

async fn mint(db: &Surreal<Db>, tenant_id: Uuid, user_id: Uuid, email: &str, hash: &str) {
    SurrealEmailVerificationTokenRepository::new(db.clone())
        .create(CreateEmailVerificationToken {
            tenant_id,
            user_id,
            token_hash: hash.into(),
            email: email.into(),
            expires_at: Utc::now() + Duration::hours(24),
        })
        .await
        .unwrap();
}

/// The address change the self-service handler writes (SEC-050).
fn move_to_new_address() -> UpdateUser {
    UpdateUser {
        email: Some(NEW.into()),
        email_verified_at: Some(None),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_token_redeems_for_its_own_address_once() {
    let db = common::serialising_db().await;
    let (tenant_id, user_id) = account(&db, 0).await;
    mint(&db, tenant_id, user_id, OLD, "h-own").await;
    let users = SurrealUserRepository::new(db.handle());

    assert_eq!(
        users
            .redeem_email_verification(tenant_id, "h-own")
            .await
            .unwrap(),
        EmailVerificationRedemption::Verified { user_id }
    );
    let user = users.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(user.email_verified_at.is_some());
    assert_eq!(user.status, UserStatus::Active);
    assert!(matches!(
        users.redeem_email_verification(tenant_id, "h-own").await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_token_for_another_address_is_spent_and_verifies_nothing() {
    let db = common::serialising_db().await;
    let (tenant_id, user_id) = account(&db, 0).await;
    mint(&db, tenant_id, user_id, NEW, "h-other").await;
    let users = SurrealUserRepository::new(db.handle());

    assert_eq!(
        users
            .redeem_email_verification(tenant_id, "h-other")
            .await
            .unwrap(),
        EmailVerificationRedemption::AddressMismatch
    );
    let user = users.get_by_id(tenant_id, user_id).await.unwrap();
    assert!(user.email_verified_at.is_none());
    assert_eq!(user.status, UserStatus::PendingVerification);
    assert!(
        SurrealEmailVerificationTokenRepository::new(db.handle())
            .get_by_token_hash(tenant_id, "h-other")
            .await
            .is_err(),
        "spent"
    );
}

/// Every writer of the address spends the old address's links, an
/// administrator's change as much as the account's own — and only the
/// unconsumed ones of that account.
#[tokio::test]
async fn an_address_change_deletes_the_accounts_unconsumed_links_only() {
    let db = common::serialising_db().await;
    let (tenant_id, user_id) = account(&db, 0).await;
    let users = SurrealUserRepository::new(db.handle());
    let verify = SurrealEmailVerificationTokenRepository::new(db.handle());
    let reset = SurrealPasswordResetTokenRepository::new(db.handle());

    mint(&db, tenant_id, user_id, OLD, "h-live").await;
    mint(&db, tenant_id, user_id, OLD, "h-spent").await;
    verify.consume(tenant_id, "h-spent").await.unwrap();
    reset
        .create(CreatePasswordResetToken {
            tenant_id,
            user_id,
            token_hash: "r-live".into(),
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    // A second account in the tenant, whose links are not this change's.
    let bystander = users
        .create(CreateUser {
            tenant_id,
            username: "bystander".into(),
            email: "bystander@a.example".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    mint(
        &db,
        tenant_id,
        bystander.id,
        "bystander@a.example",
        "h-bystander",
    )
    .await;

    // An administrator's change: no `email_verified_at` in the write.
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                email: Some(NEW.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(verify.get_by_token_hash(tenant_id, "h-live").await.is_err());
    assert!(reset.get_by_token_hash(tenant_id, "r-live").await.is_err());
    assert!(
        verify
            .get_by_token_hash(tenant_id, "h-bystander")
            .await
            .is_ok()
    );
    let spent: Vec<String> = db
        .query("SELECT VALUE token_hash FROM email_verification_token WHERE token_hash = 'h-spent'")
        .await
        .unwrap()
        .take(0)
        .unwrap();
    assert_eq!(
        spent,
        ["h-spent"],
        "a consumed row is not this write's to delete"
    );
}

/// Rounds per race run; the whole test was also run 20 times in a row.
const ROUNDS: usize = 8;

/// The race: redeem `OLD`'s token while the account moves to `NEW`.
#[tokio::test]
async fn a_redemption_racing_an_address_change_never_verifies_the_new_address() {
    let db = common::serialising_db().await;
    let mut verified_first = 0;
    let mut changed_first = 0;
    for round in 0..ROUNDS {
        let (tenant_id, user_id) = account(&db, round).await;
        let hash = format!("h-race-{round}");
        mint(&db, tenant_id, user_id, OLD, &hash).await;

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let redeem = {
            let (db, barrier, hash) = (db.handle(), barrier.clone(), hash.clone());
            tokio::spawn(async move {
                // The read the redemption's caller makes: the link is live.
                SurrealEmailVerificationTokenRepository::new(db.clone())
                    .get_by_token_hash(tenant_id, &hash)
                    .await
                    .unwrap();
                barrier.wait().await;
                SurrealUserRepository::new(db)
                    .redeem_email_verification(tenant_id, &hash)
                    .await
            })
        };
        let change = {
            let (db, barrier) = (db.handle(), barrier.clone());
            tokio::spawn(async move {
                let users = SurrealUserRepository::new(db);
                // The read the handler makes: is this an address change?
                let current = users.get_by_id(tenant_id, user_id).await.unwrap();
                assert_eq!(current.email, OLD);
                barrier.wait().await;
                users
                    .update(tenant_id, user_id, move_to_new_address())
                    .await
            })
        };
        let redeemed = redeem.await.unwrap();
        change.await.unwrap().expect("the address change commits");

        let user = SurrealUserRepository::new(db.handle())
            .get_by_id(tenant_id, user_id)
            .await
            .unwrap();
        assert_eq!(user.email, NEW, "round {round}");
        assert!(
            user.email_verified_at.is_none(),
            "round {round}: the new address was verified by the old address's token \
             ({redeemed:?})"
        );
        match redeemed {
            Ok(EmailVerificationRedemption::Verified { .. }) => verified_first += 1,
            Err(AxiamError::NotFound { .. }) | Ok(EmailVerificationRedemption::AddressMismatch) => {
                changed_first += 1;
            }
            other => panic!("round {round}: unexpected redemption {other:?}"),
        }
        assert!(
            SurrealEmailVerificationTokenRepository::new(db.handle())
                .get_by_token_hash(tenant_id, &hash)
                .await
                .is_err(),
            "round {round}: no live link for the old address remains"
        );
    }
    assert_eq!(verified_first + changed_first, ROUNDS);
    eprintln!("redemption first: {verified_first}, address change first: {changed_first}");
}
