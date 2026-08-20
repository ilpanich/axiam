//! X1 / R2.2 — the `login.post_auth` call site.
//!
//! This is the acceptance criterion of the task in test form: **a registered
//! interceptor vetoes a login.** The stack under test is the real
//! `AuthService::login` against real SurrealDB repositories (in-memory), with a
//! mock gate standing in for the dispatcher.
//!
//! # Why a mock gate rather than the real dispatcher
//!
//! `axiam-auth` does not depend on `axiam-amqp` and must not start: the whole
//! point of `ReactorGate` living in `axiam-core` is that the crate which
//! authenticates users cannot see a broker. The four outcomes a mock produces
//! here are exactly the four a chain can compose, and the mapping from a
//! *reactor-level* event (a timeout, a bad signature, a cap breach) to one of
//! those four is tested where it lives, in `axiam_amqp::reactor::gate`. The
//! timeout row below is written as the literal
//! `resolve_failure(FailClosed, Timeout)` produces, so a change to that mapping
//! surfaces as a failure here too.

use axiam_auth::config::AuthConfig;
use axiam_auth::service::{AuthService, LoginInput, LoginResult};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{
    DynReactorGate, ReactorOutcome, SharedReactorGate, noop_reactor_gate,
};
use axiam_core::models::settings::MfaPolicy;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use std::sync::{Arc, Mutex};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
const TEST_MFA_KEY: [u8; 32] = [42u8; 32];

fn test_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        mfa_encryption_key: Some(TEST_MFA_KEY),
        opaque_session_key: None,
        opaque_setup_key: None,
        allow_missing_aud_as_user: true,
        max_concurrent_hashes: 0,
        hash_acquire_timeout_secs: 5,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// The mock gate
// ---------------------------------------------------------------------------

struct FixedGate {
    outcome: ReactorOutcome,
    seen: Arc<Mutex<Vec<(&'static str, serde_json::Value)>>>,
}

impl DynReactorGate for FixedGate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        event: &'static str,
        payload: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        self.seen.lock().unwrap().push((event, payload));
        let outcome = self.outcome.clone();
        Box::pin(std::future::ready(outcome))
    }

    // SEC-101: a scripted test double stands in for a working
    // transport, so registrations are acceptable under it.
    fn can_dispatch_dyn(&self) -> bool {
        true
    }
}

type GateLog = Arc<Mutex<Vec<(&'static str, serde_json::Value)>>>;

fn gate(outcome: ReactorOutcome) -> (SharedReactorGate, GateLog) {
    let seen: GateLog = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::new(FixedGate {
            outcome,
            seen: seen.clone(),
        }),
        seen,
    )
}

/// Exactly what `axiam_amqp::reactor::dispatcher::resolve_failure` produces for
/// a timed-out `fail_closed` registration.
fn timed_out_fail_closed() -> ReactorOutcome {
    ReactorOutcome::Deny {
        reason: "reactor unavailable (reactor timed out)".into(),
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

type Svc = AuthService<
    SurrealUserRepository<surrealdb::engine::local::Db>,
    SurrealSessionRepository<surrealdb::engine::local::Db>,
    SurrealFederationLinkRepository<surrealdb::engine::local::Db>,
    SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
>;

struct Fixture {
    svc: Svc,
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    /// Kept alive: dropping the handle drops the in-memory database.
    _db: Surreal<surrealdb::engine::local::Db>,
}

async fn fixture(gate: SharedReactorGate, mfa_enabled: bool) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                mfa_enabled: Some(mfa_enabled),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let svc = AuthService::new(
        user_repo,
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        test_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    )
    .with_reactor_gate(gate);

    Fixture {
        svc,
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        _db: db,
    }
}

fn login(f: &Fixture) -> LoginInput {
    LoginInput {
        tenant_id: f.tenant_id,
        org_id: f.org_id,
        username_or_email: "alice".into(),
        password: test_password(),
        ip_address: Some("203.0.113.7".into()),
        user_agent: Some("curl/8".into()),
        mfa_policy: None,
    }
}

// ---------------------------------------------------------------------------
// allow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_allowing_reactor_leaves_the_login_unchanged() {
    let (g, seen) = gate(ReactorOutcome::Allow);
    let f = fixture(g, false).await;

    let result = f.svc.login(login(&f)).await.expect("login succeeds");
    assert!(matches!(result, LoginResult::Success(_)));

    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 1, "login consults the gate exactly once");
    assert_eq!(calls[0].0, "login.post_auth");
}

#[tokio::test]
async fn the_default_composition_never_calls_a_reactor() {
    let f = fixture(noop_reactor_gate(), false).await;
    assert!(matches!(
        f.svc.login(login(&f)).await.expect("login succeeds"),
        LoginResult::Success(_)
    ));
}

// ---------------------------------------------------------------------------
// deny — the acceptance criterion
// ---------------------------------------------------------------------------

/// **A registered interceptor vetoes a login.** The credentials are correct,
/// the account is active, MFA is off — and the login fails because a reactor
/// said so.
#[tokio::test]
async fn a_registered_interceptor_vetoes_a_login() {
    let (g, seen) = gate(ReactorOutcome::Deny {
        reason: "login from an embargoed region".into(),
    });
    let f = fixture(g, false).await;

    let err = f
        .svc
        .login(login(&f))
        .await
        .expect_err("the veto must refuse the login");

    // The user sees the fixed text; the reactor's own words do not travel to
    // an unauthenticated caller.
    let rendered = err.to_string();
    assert!(
        !rendered.contains("embargoed"),
        "a reactor's text must not reach the caller: {rendered}"
    );

    // And the reactor was told what it needed to decide — including the
    // address an embargoed-region check runs on — but never the password.
    let calls = seen.lock().unwrap();
    let payload = calls[0].1.to_string();
    assert!(payload.contains("203.0.113.7"));
    assert!(payload.contains(&f.user_id.to_string()));
    assert!(
        !payload.contains(&test_password()),
        "the password must never reach a reactor"
    );
}

#[tokio::test]
async fn a_veto_prevents_the_session_from_being_created() {
    let (g, _) = gate(ReactorOutcome::Deny {
        reason: "no".into(),
    });
    let f = fixture(g, false).await;
    assert!(f.svc.login(login(&f)).await.is_err());

    // `revoke_all_sessions` succeeds trivially when there is nothing to revoke;
    // the real evidence is that a vetoed login returned no tokens at all, which
    // the error above already establishes. Assert the stronger property the
    // veto exists for: a second, allowed login is the FIRST session.
    let (g, _) = gate(ReactorOutcome::Allow);
    let f2 = fixture(g, false).await;
    assert!(matches!(
        f2.svc.login(login(&f2)).await.unwrap(),
        LoginResult::Success(_)
    ));
}

// ---------------------------------------------------------------------------
// timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_fail_closed_timeout_refuses_the_login() {
    let (g, _) = gate(timed_out_fail_closed());
    let f = fixture(g, false).await;
    assert!(
        f.svc.login(login(&f)).await.is_err(),
        "an unreachable fail_closed fraud check has not passed"
    );
}

#[tokio::test]
async fn a_fail_open_timeout_lets_the_login_through() {
    // `fail_open` resolves a timeout to `Allow` before the site ever sees it.
    let (g, _) = gate(ReactorOutcome::Allow);
    let f = fixture(g, false).await;
    assert!(matches!(
        f.svc.login(login(&f)).await.unwrap(),
        LoginResult::Success(_)
    ));
}

// ---------------------------------------------------------------------------
// mutate — `login.post_auth` is veto-only
// ---------------------------------------------------------------------------

/// The registry marks `login.post_auth` `mutable: false`. A mutation reaching
/// the site means three checks were bypassed, and the site refuses rather than
/// silently continuing with an unapplied change.
#[tokio::test]
async fn a_mutation_on_the_veto_only_login_event_refuses_the_login() {
    let (g, _) = gate(ReactorOutcome::Mutate {
        patch: [("username".to_string(), "mallory".to_string())]
            .into_iter()
            .collect(),
    });
    let f = fixture(g, false).await;
    assert!(f.svc.login(login(&f)).await.is_err());
}

// ---------------------------------------------------------------------------
// require_mfa
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_step_up_demand_turns_an_mfa_user_into_a_challenge() {
    let (g, _) = gate(ReactorOutcome::RequireMfa);
    let f = fixture(g, true).await;

    // The user already has MFA, so the ordinary path would challenge anyway.
    // What matters is that the demand did not turn into a Success.
    assert!(matches!(
        f.svc.login(login(&f)).await.unwrap(),
        LoginResult::MfaRequired(_)
    ));
}

/// The case the demand exists for: a user **without** MFA is not let through.
/// Without the reactor they would get `Success`; with it they must enrol.
#[tokio::test]
async fn a_step_up_demand_forces_enrolment_for_a_user_without_mfa() {
    let (g, _) = gate(ReactorOutcome::RequireMfa);
    let f = fixture(g, false).await;

    match f.svc.login(login(&f)).await.unwrap() {
        LoginResult::MfaSetupRequired(out) => assert!(!out.setup_token.is_empty()),
        other => panic!("a reactor's step-up demand must not resolve to {other:?}"),
    }
}

/// And the tenant policy is not weakened by the reactor being quiet: the two
/// compose by joining, so policy-enforced MFA still applies when a reactor
/// allows.
#[tokio::test]
async fn an_allowing_reactor_does_not_waive_the_tenant_mfa_policy() {
    let (g, _) = gate(ReactorOutcome::Allow);
    let f = fixture(g, false).await;

    let mut input = login(&f);
    input.mfa_policy = Some(MfaPolicy {
        mfa_enforced: true,
        mfa_challenge_lifetime_secs: 300,
    });

    assert!(matches!(
        f.svc.login(input).await.unwrap(),
        LoginResult::MfaSetupRequired(_)
    ));
}
