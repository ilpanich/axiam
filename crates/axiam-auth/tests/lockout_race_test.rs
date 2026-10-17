//! Item 5 of the 1.1.0 atomicity audit: a sign-in's counter reset must not
//! undo a lock committed after the sign-in read the account.
//!
//! `AuthService::login` reads the account, checks the lock, verifies the
//! password, and only then resets the failed-login counter. K guesses sent
//! together at threshold − 1 all pass the lock check. A wrong one locks the
//! account; a correct one whose reset landed after that used to clear the lock
//! and issue a session — K guesses per lockout cycle instead of the policy's.
//!
//! The race runs on `surrealkv`, the engine production runs, through the real
//! service and repository. A wrapper holds the K logins at a barrier once each
//! has read the account (all see `threshold − 1` and no lock), and holds the
//! correct one's admission until every wrong one's increment has committed —
//! the interleaving the audit describes, made certain rather than likely.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_auth::config::AuthConfig;
use axiam_auth::service::{AuthService, LoginInput, LoginResult};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, PaginatedResult, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::{other_password, test_password};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, SurrealKv};
use tokio::sync::{Barrier, Notify};
use uuid::Uuid;

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key

const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

/// The deployment-default policy the service falls back to: five failures.
const THRESHOLD: u32 = 5;
/// Guesses sent together: `K - 1` wrong ones and one correct one.
const K: usize = 4;
/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

fn config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        jwt_issuer: "axiam-test".into(),
        max_failed_login_attempts: THRESHOLD,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        hash_acquire_timeout_secs: 30,
        ..AuthConfig::default()
    }
}

/// The SurrealDB repository with the race's two holds around it.
#[derive(Clone)]
struct Racing {
    inner: SurrealUserRepository<Db>,
    /// Released once all K logins have read the account.
    read: Arc<Barrier>,
    /// Wrong guesses whose increment has committed.
    increments: Arc<AtomicUsize>,
    incremented: Arc<Notify>,
    /// How many increments the correct login's admission waits for.
    wait_for: usize,
}

impl UserRepository for Racing {
    async fn create(&self, input: CreateUser) -> AxiamResult<User> {
        self.inner.create(input).await
    }
    async fn get_by_id(&self, t: Uuid, id: Uuid) -> AxiamResult<User> {
        self.inner.get_by_id(t, id).await
    }
    async fn get_by_username(&self, t: Uuid, name: &str) -> AxiamResult<User> {
        let user = self.inner.get_by_username(t, name).await;
        self.read.wait().await;
        user
    }
    async fn get_by_email(&self, t: Uuid, email: &str) -> AxiamResult<User> {
        self.inner.get_by_email(t, email).await
    }
    async fn update(&self, t: Uuid, id: Uuid, input: UpdateUser) -> AxiamResult<User> {
        self.inner.update(t, id, input).await
    }
    async fn delete(&self, t: Uuid, id: Uuid) -> AxiamResult<()> {
        self.inner.delete(t, id).await
    }
    async fn update_totp_step(&self, t: Uuid, id: Uuid, step: u64) -> AxiamResult<bool> {
        self.inner.update_totp_step(t, id, step).await
    }
    async fn list(&self, t: Uuid, p: Pagination) -> AxiamResult<PaginatedResult<User>> {
        self.inner.list(t, p).await
    }
    async fn increment_failed_logins(
        &self,
        t: Uuid,
        id: Uuid,
        threshold: u32,
        base: i64,
        mult: f64,
        max: i64,
    ) -> AxiamResult<()> {
        let out = self
            .inner
            .increment_failed_logins(t, id, threshold, base, mult, max)
            .await;
        self.increments.fetch_add(1, Ordering::SeqCst);
        self.incremented.notify_waiters();
        out
    }
    async fn admit_unless_locked(&self, t: Uuid, id: Uuid, clear: bool) -> AxiamResult<bool> {
        // The correct guess lands after the lock: every wrong guess's
        // increment has committed before its admission is asked.
        loop {
            let notified = self.incremented.notified();
            if self.increments.load(Ordering::SeqCst) >= self.wait_for {
                break;
            }
            notified.await;
        }
        self.inner.admit_unless_locked(t, id, clear).await
    }
    async fn anonymize_user(&self, t: Uuid, id: Uuid, hash: &str, p: &str) -> AxiamResult<()> {
        self.inner.anonymize_user(t, id, hash, p).await
    }
}

struct World {
    db: Surreal<Db>,
    _dir: tempfile::TempDir,
    org_id: Uuid,
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
        org_id: org.id,
        tenant_id: tenant.id,
    }
}

/// An `Active` account `name` with `failures` failed logins and no lock.
async fn account(w: &World, name: &str, failures: u32) -> Uuid {
    let users = SurrealUserRepository::new(w.db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: w.tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            w.tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                failed_login_attempts: Some(failures),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    user.id
}

fn service(
    w: &World,
    users: Racing,
) -> AuthService<
    Racing,
    SurrealSessionRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
> {
    AuthService::new(
        users,
        SurrealSessionRepository::new(w.db.clone()),
        SurrealFederationLinkRepository::new(w.db.clone()),
        SurrealRefreshTokenRepository::new(w.db.clone()),
        config(),
        Arc::new(tokio::sync::Semaphore::new(K)),
    )
}

fn guess(w: &World, name: &str, password: String) -> LoginInput {
    LoginInput {
        tenant_id: w.tenant_id,
        org_id: w.org_id,
        username_or_email: name.into(),
        password,
        ip_address: None,
        user_agent: None,
        mfa_policy: None,
        lockout_policy: None,
    }
}

async fn sessions_of(w: &World, user_id: Uuid) -> usize {
    let ids: Vec<String> =
        w.db.query("SELECT VALUE meta::id(id) FROM session WHERE user_id = $user_id")
            .bind(("user_id", user_id.to_string()))
            .await
            .unwrap()
            .take(0)
            .unwrap();
    ids.len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_correct_guess_landing_after_the_lock_gets_no_session_and_the_lock_stands() {
    let w = world().await;
    for round in 0..ROUNDS {
        let name = format!("victim-{round}");
        let user_id = account(&w, &name, THRESHOLD - 1).await;
        let users = Racing {
            inner: SurrealUserRepository::new(w.db.clone()),
            read: Arc::new(Barrier::new(K)),
            increments: Arc::new(AtomicUsize::new(0)),
            incremented: Arc::new(Notify::new()),
            wait_for: K - 1,
        };
        let svc = Arc::new(service(&w, users));

        let mut wrong = Vec::new();
        for _ in 0..K - 1 {
            let (svc, input) = (svc.clone(), guess(&w, &name, other_password()));
            wrong.push(tokio::spawn(async move { svc.login(input).await }));
        }
        let correct = {
            let (svc, input) = (svc.clone(), guess(&w, &name, test_password()));
            tokio::spawn(async move { svc.login(input).await })
        };

        for handle in wrong {
            assert!(
                handle.await.unwrap().is_err(),
                "round {round}: a wrong guess"
            );
        }
        match correct.await.unwrap() {
            Err(AxiamError::AuthenticationFailed { .. }) => {}
            Ok(LoginResult::Success(_)) => {
                panic!("round {round}: the correct guess got a session after the lock")
            }
            other => panic!("round {round}: unexpected outcome {other:?}"),
        }

        let after = SurrealUserRepository::new(w.db.clone())
            .get_by_id(w.tenant_id, user_id)
            .await
            .unwrap();
        assert!(
            after
                .locked_until
                .is_some_and(|until| until > chrono::Utc::now()),
            "round {round}: the lock stands ({after:?})"
        );
        assert!(
            after.failed_login_attempts >= THRESHOLD,
            "round {round}: the counter was not reset"
        );
        assert_eq!(
            sessions_of(&w, user_id).await,
            0,
            "round {round}: no session"
        );
    }
}

/// The control: with no lock in force, the correct guess is admitted, gets
/// its session, and its write clears the counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_correct_guess_with_no_lock_in_force_signs_in_and_clears_the_counter() {
    let w = world().await;
    let user_id = account(&w, "owner", THRESHOLD - 1).await;
    let users = Racing {
        inner: SurrealUserRepository::new(w.db.clone()),
        read: Arc::new(Barrier::new(1)),
        increments: Arc::new(AtomicUsize::new(0)),
        incremented: Arc::new(Notify::new()),
        wait_for: 0,
    };
    let svc = service(&w, users);
    assert!(matches!(
        svc.login(guess(&w, "owner", test_password())).await,
        Ok(LoginResult::Success(_))
    ));
    let after = SurrealUserRepository::new(w.db.clone())
        .get_by_id(w.tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(after.failed_login_attempts, 0);
    assert!(after.locked_until.is_none());
    assert_eq!(sessions_of(&w, user_id).await, 1);
}

/// An expired lock is no lock: the sign-in is admitted and the stale stamp
/// cleared, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_lock_admits_the_sign_in_and_is_cleared() {
    let w = world().await;
    let user_id = account(&w, "returning", 0).await;
    SurrealUserRepository::new(w.db.clone())
        .update(
            w.tenant_id,
            user_id,
            UpdateUser {
                failed_login_attempts: Some(THRESHOLD),
                locked_until: Some(Some(chrono::Utc::now() - chrono::Duration::seconds(5))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let users = Racing {
        inner: SurrealUserRepository::new(w.db.clone()),
        read: Arc::new(Barrier::new(1)),
        increments: Arc::new(AtomicUsize::new(0)),
        incremented: Arc::new(Notify::new()),
        wait_for: 0,
    };
    assert!(matches!(
        service(&w, users)
            .login(guess(&w, "returning", test_password()))
            .await,
        Ok(LoginResult::Success(_))
    ));
    let after = SurrealUserRepository::new(w.db.clone())
        .get_by_id(w.tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(after.failed_login_attempts, 0);
    assert!(after.locked_until.is_none());
}
