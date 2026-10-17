//! Item 7 of the 1.1.0 atomicity audit: a mailed token's daily cap holds
//! against requests sent together, and a burst of reset requests leaves one
//! live link.
//!
//! `initiate_reset` and `resend_verification` counted the account's tokens
//! minted today, and minted in later statements. Parallel requests each read
//! a count under the cap and all minted: the cap was exceeded, and for a
//! reset — whose mint invalidates the account's earlier links — every racer's
//! invalidation ran before the others' tokens existed, so several links were
//! live at once. The mint now counts again inside its own transaction, which
//! claims the user row.
//!
//! The race runs on `surrealkv`, the engine production runs, through the real
//! services and repositories. A wrapper holds the N requests at a barrier once
//! each has made the service's count (every one sees room under the cap),
//! then lets them mint at once — the interleaving the audit describes, made
//! certain rather than likely.

use std::sync::Arc;

use axiam_auth::password_reset::PasswordResetService;
use axiam_auth::verification::EmailVerificationService;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email_verification::{
    CreateEmailVerificationToken, EmailVerificationToken,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::{CreatePasswordResetToken, PasswordResetToken};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    EmailVerificationTokenRepository, OrganizationRepository, PasswordResetTokenRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository,
    SurrealPasswordResetTokenRepository, SurrealRefreshTokenRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, SurrealKv};
use tokio::sync::Barrier;
use uuid::Uuid;

/// Requests sent together.
const N: usize = 6;
/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;
/// `password_reset::MAX_RESETS_PER_DAY`.
const RESET_CAP: u64 = 3;
/// `verification::MAX_RESENDS_PER_DAY`.
const RESEND_CAP: u64 = 2;

/// The reset-token repository, holding each caller at the barrier once its
/// count has been read.
#[derive(Clone)]
struct RacingResets {
    inner: SurrealPasswordResetTokenRepository<Db>,
    read: Arc<Barrier>,
}

impl PasswordResetTokenRepository for RacingResets {
    async fn create(&self, input: CreatePasswordResetToken) -> AxiamResult<PasswordResetToken> {
        self.inner.create(input).await
    }
    async fn get_by_token_hash(&self, t: Uuid, h: &str) -> AxiamResult<PasswordResetToken> {
        self.inner.get_by_token_hash(t, h).await
    }
    async fn consume(&self, t: Uuid, h: &str) -> AxiamResult<PasswordResetToken> {
        self.inner.consume(t, h).await
    }
    async fn count_today(&self, t: Uuid, u: Uuid) -> AxiamResult<u64> {
        let count = self.inner.count_today(t, u).await;
        self.read.wait().await;
        count
    }
    async fn delete_expired(&self) -> AxiamResult<u64> {
        self.inner.delete_expired().await
    }
    async fn delete_unconsumed_for_user(&self, t: Uuid, u: Uuid) -> AxiamResult<u64> {
        self.inner.delete_unconsumed_for_user(t, u).await
    }
    async fn replace_within_daily_cap(
        &self,
        input: CreatePasswordResetToken,
        cap: u64,
    ) -> AxiamResult<Option<PasswordResetToken>> {
        self.inner.replace_within_daily_cap(input, cap).await
    }
}

/// The verification-token repository, holding each caller at the barrier
/// once its count has been read.
#[derive(Clone)]
struct RacingResends {
    inner: SurrealEmailVerificationTokenRepository<Db>,
    read: Arc<Barrier>,
}

impl EmailVerificationTokenRepository for RacingResends {
    async fn create(
        &self,
        input: CreateEmailVerificationToken,
    ) -> AxiamResult<EmailVerificationToken> {
        self.inner.create(input).await
    }
    async fn get_by_token_hash(&self, t: Uuid, h: &str) -> AxiamResult<EmailVerificationToken> {
        self.inner.get_by_token_hash(t, h).await
    }
    async fn consume(&self, t: Uuid, h: &str) -> AxiamResult<EmailVerificationToken> {
        self.inner.consume(t, h).await
    }
    async fn count_today(&self, t: Uuid, u: Uuid) -> AxiamResult<u64> {
        let count = self.inner.count_today(t, u).await;
        self.read.wait().await;
        count
    }
    async fn create_within_daily_cap(
        &self,
        input: CreateEmailVerificationToken,
        cap: u64,
    ) -> AxiamResult<Option<EmailVerificationToken>> {
        self.inner.create_within_daily_cap(input, cap).await
    }
    async fn delete_expired(&self) -> AxiamResult<u64> {
        self.inner.delete_expired().await
    }
}

struct World {
    db: Surreal<Db>,
    _dir: tempfile::TempDir,
    tenant_id: Uuid,
}

async fn world() -> World {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Surreal::new::<SurrealKv>(dir.path().join("race.db").to_string_lossy().into_owned())
        .await
        .unwrap();
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
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    World {
        db,
        _dir: dir,
        tenant_id: tenant.id,
    }
}

/// A fresh account (`PendingVerification`, unverified) at `email`.
async fn account(w: &World, email: &str) -> Uuid {
    SurrealUserRepository::new(w.db.clone())
        .create(CreateUser {
            tenant_id: w.tenant_id,
            username: email.replace('@', "-"),
            email: email.into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// `(minted today, still unconsumed)` in `table` for `user_id`.
async fn tokens(w: &World, table: &str, user_id: Uuid) -> (usize, usize) {
    let consumed: Vec<bool> =
        w.db.query(format!(
            "SELECT VALUE consumed_at != NONE FROM {table} WHERE user_id = $user_id"
        ))
        .bind(("user_id", user_id.to_string()))
        .await
        .unwrap()
        .take(0)
        .unwrap();
    let live = consumed.iter().filter(|c| !**c).count();
    (consumed.len(), live)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reset_requests_sent_together_never_exceed_the_cap_and_leave_one_live_link() {
    let w = world().await;
    for round in 0..ROUNDS {
        let email = format!("reset-{round}@example.com");
        let user_id = account(&w, &email).await;
        let svc = Arc::new(PasswordResetService::new(
            SurrealUserRepository::new(w.db.clone()),
            RacingResets {
                inner: SurrealPasswordResetTokenRepository::new(w.db.clone()),
                read: Arc::new(Barrier::new(N)),
            },
            SurrealFederationLinkRepository::new(w.db.clone()),
            SurrealPasswordHistoryRepository::new(w.db.clone()),
            SurrealSessionRepository::new(w.db.clone()),
            SurrealRefreshTokenRepository::new(w.db.clone()),
            Arc::new(tokio::sync::Semaphore::new(N)),
            30,
        ));

        let mut racers = Vec::new();
        for _ in 0..N {
            let (svc, tenant_id, email) = (svc.clone(), w.tenant_id, email.clone());
            racers.push(tokio::spawn(async move {
                svc.initiate_reset(tenant_id, &email, 1, None).await
            }));
        }
        let (mut minted, mut refused) = (0, 0);
        for racer in racers {
            match racer.await.unwrap() {
                Ok(Some(_)) => minted += 1,
                Err(AxiamError::RateLimited) => refused += 1,
                other => panic!("round {round}: unexpected outcome {other:?}"),
            }
        }
        assert_eq!(
            (minted, refused),
            (RESET_CAP as usize, N - RESET_CAP as usize),
            "round {round}: the cap's worth mint, the rest are refused"
        );
        assert_eq!(
            tokens(&w, "password_reset_token", user_id).await,
            (RESET_CAP as usize, 1),
            "round {round}: never above the cap, and one live link"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verification_resends_sent_together_never_exceed_the_cap() {
    let w = world().await;
    for round in 0..ROUNDS {
        let email = format!("resend-{round}@example.com");
        let user_id = account(&w, &email).await;
        let svc = Arc::new(EmailVerificationService::new(
            SurrealUserRepository::new(w.db.clone()),
            RacingResends {
                inner: SurrealEmailVerificationTokenRepository::new(w.db.clone()),
                read: Arc::new(Barrier::new(N)),
            },
            SurrealFederationLinkRepository::new(w.db.clone()),
        ));

        let mut racers = Vec::new();
        for _ in 0..N {
            let (svc, tenant_id, email) = (svc.clone(), w.tenant_id, email.clone());
            racers.push(tokio::spawn(async move {
                svc.resend_verification(tenant_id, &email).await
            }));
        }
        let (mut minted, mut refused) = (0, 0);
        for racer in racers {
            match racer.await.unwrap() {
                Ok(Some(_)) => minted += 1,
                Err(AxiamError::RateLimited) => refused += 1,
                other => panic!("round {round}: unexpected outcome {other:?}"),
            }
        }
        assert_eq!(
            (minted, refused),
            (RESEND_CAP as usize, N - RESEND_CAP as usize),
            "round {round}: the cap's worth mint, the rest are refused"
        );
        assert_eq!(
            tokens(&w, "email_verification_token", user_id).await.0,
            RESEND_CAP as usize,
            "round {round}: never above the cap"
        );
    }
}
