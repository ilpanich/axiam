//! A2/J2 — a standing budget on how many datastore round trips one refresh
//! rotation is allowed to make.
//!
//! # Why a budget test and not a benchmark
//!
//! Run 5 measured `token_refresh` at 545/s and p50 88.8 ms against run 4's
//! 839/s and 47.5 ms — a −35 % throughput regression with tight medians in
//! both runs, i.e. the whole latency distribution shifted right. That is the
//! signature of *added serialized work*, and the work in question is
//! round trips: refresh is the one hot endpoint that is round-trip-bound
//! rather than CPU-bound.
//!
//! A throughput assertion cannot live in CI (it would measure the runner, not
//! the code) but the thing that actually regressed can: the *count* of
//! sequential repository calls the rotation makes. This test pins it. If a
//! future security fix needs another read on this path — as NEW-1's tenant
//! lookup and OBS-3's `.check()`s did — this test fails and forces that cost
//! to be a decision rather than a discovery three benchmark runs later.
//!
//! Counting session-repository calls specifically is deliberate: every one of
//! them is a network round trip, they are the calls the rotation logic owns,
//! and they are where the regression lived.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axiam_auth::{AuthConfig, AuthService, LoginInput, LoginResult, RefreshInput};
use axiam_core::error::AxiamResult;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{CreateSession, Session};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// The budget. Two calls: one to atomically find-and-consume the presented
/// refresh token, one to create the rotated session.
///
/// It was three (`get_by_token_hash` + `consume` + `create`) before A2. Raising
/// this number is a real product decision about the cost of the hottest
/// rotation path in the product — not a test fix.
const MAX_SESSION_ROUND_TRIPS_PER_REFRESH: usize = 2;

/// Delegating `SessionRepository` that counts calls.
///
/// Wraps the *real* repository rather than faking it, so the count is taken
/// against the same code paths (and the same SurrealDB statements) production
/// runs — a hand-rolled fake would be free to have a different call shape than
/// the thing it stands in for, which is exactly the property this test cannot
/// afford.
#[derive(Clone)]
struct CountingSessionRepo {
    inner: SurrealSessionRepository<surrealdb::engine::local::Db>,
    calls: Arc<AtomicUsize>,
}

impl CountingSessionRepo {
    fn new(inner: SurrealSessionRepository<surrealdb::engine::local::Db>) -> Self {
        Self {
            inner,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn hit(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn take_count(&self) -> usize {
        self.calls.swap(0, Ordering::SeqCst)
    }
}

impl SessionRepository for CountingSessionRepo {
    async fn create(&self, input: CreateSession) -> AxiamResult<Session> {
        self.hit();
        self.inner.create(input).await
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Session> {
        self.hit();
        self.inner.get_by_id(tenant_id, id).await
    }

    async fn get_by_token_hash(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<Session> {
        self.hit();
        self.inner.get_by_token_hash(tenant_id, token_hash).await
    }

    async fn invalidate(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.hit();
        self.inner.invalidate(tenant_id, id).await
    }

    async fn consume(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<bool> {
        self.hit();
        self.inner.consume(tenant_id, id).await
    }

    async fn consume_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<Option<Session>> {
        self.hit();
        self.inner
            .consume_by_token_hash(tenant_id, token_hash)
            .await
    }

    async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.hit();
        self.inner
            .invalidate_user_sessions(tenant_id, user_id)
            .await
    }

    async fn invalidate_user_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        keep: Uuid,
    ) -> AxiamResult<u64> {
        self.hit();
        self.inner
            .invalidate_user_sessions_except(tenant_id, user_id, keep)
            .await
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        self.hit();
        self.inner.cleanup_expired(tenant_id).await
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Session>> {
        self.hit();
        self.inner.list_by_user(tenant_id, user_id).await
    }
}

fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----".into(), // nosemgrep: generic.secrets.security.detected-private-key
        jwt_public_key_pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----".into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        ..AuthConfig::default()
    }
}

#[tokio::test]
async fn refresh_rotation_stays_within_its_datastore_round_trip_budget() {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory surreal");
    db.use_ns("test").use_db("test").await.expect("ns/db");
    axiam_db::run_migrations(&db).await.expect("migrations");

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db.clone());

    let org = org_repo
        .create(CreateOrganization {
            name: "Budget Org".into(),
            slug: "budget-org".into(),
            metadata: None,
        })
        .await
        .expect("org");
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Budget Tenant".into(),
            slug: "budget-tenant".into(),
            metadata: None,
        })
        .await
        .expect("tenant");

    // This test authenticates, so the same value has to reach both `create`
    // and `login`. The shared helper is memoised per process precisely so that
    // holds without every caller having to bind it.
    let password = test_password();

    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "budget".into(),
            email: "budget@example.com".into(),
            password: password.clone(),
            metadata: None,
        })
        .await
        .expect("user");
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .expect("activate");

    let session_repo = CountingSessionRepo::new(SurrealSessionRepository::new(db.clone()));
    let svc = AuthService::new(
        user_repo,
        session_repo.clone(),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let login = match svc
        .login(LoginInput {
            tenant_id: tenant.id,
            org_id: org.id,
            username_or_email: "budget".into(),
            password: password.clone(),
            ip_address: None,
            user_agent: None,
            mfa_policy: None,
            lockout_policy: None,
        })
        .await
        .expect("login")
    {
        LoginResult::Success(out) => out,
        other => panic!("expected Success, got {other:?}"),
    };

    // Only the refresh is measured; login's own calls are discarded.
    session_repo.take_count();

    let out = svc
        .refresh(RefreshInput {
            tenant_id: tenant.id,
            org_id: org.id,
            raw_refresh_token: login.refresh_token.clone(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .expect("refresh");

    let round_trips = session_repo.take_count();
    assert!(
        round_trips <= MAX_SESSION_ROUND_TRIPS_PER_REFRESH,
        "refresh made {round_trips} session-repository round trips, budget is \
         {MAX_SESSION_ROUND_TRIPS_PER_REFRESH}. Refresh is round-trip-bound \
         (run-5 A2/J2: −35 % throughput from added serialized work), so adding \
         one here is a product decision, not a test fix."
    );

    // The budget must not have been met by skipping the work: rotation still
    // has to actually rotate.
    assert_ne!(
        out.refresh_token, login.refresh_token,
        "the refresh token must be rotated"
    );

    // …and single-use must still hold — the old token is dead.
    assert!(
        svc.refresh(RefreshInput {
            tenant_id: tenant.id,
            org_id: org.id,
            raw_refresh_token: login.refresh_token,
            ip_address: None,
            user_agent: None,
        })
        .await
        .is_err(),
        "replaying the consumed refresh token must fail (single-use rotation)"
    );
}
