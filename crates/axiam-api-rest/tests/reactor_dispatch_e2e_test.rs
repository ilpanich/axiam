//! X1 / R2.2 — the acceptance test: **a registered interceptor vetoes a login**,
//! through the HTTP stack.
//!
//! # What is real here and what is not
//!
//! Real: the HTTP routes, the handlers, `AuthService::login` with Argon2id, the
//! SurrealDB registration store, the routing table with its TTL, the
//! `DispatchingReactorGate`, the interceptor chain, the §8 v2 reply signature
//! and freshness checks, the per-event mutable-field allow-list, the failure
//! policy, and the audit writes.
//!
//! Not real: **the broker**. The `ReactorTransport` here is a scripted double
//! that signs a reply with the same tenant subkey a reactor SDK would derive,
//! instead of publishing to RabbitMQ and consuming the answer. That is the one
//! seam the transport occupies, and `sdks/CONTRACT.md` §22.1's scope note
//! records that its lapin implementation is not merged yet — so a test that
//! required it would be testing code that does not exist, not the wiring this
//! task delivers. Everything between the HTTP request and the signed reply
//! bytes is the production path.
//!
//! This file needs no broker and no docker, so it runs in CI on every push.

use actix_web::{App, test, web};
use axiam_amqp::messages::CURRENT_KEY_VERSION;
use axiam_amqp::reactor::dispatcher::{DispatchFailure, ReactorTransport};
use axiam_amqp::reactor::gate::{
    DispatchingReactorGate, ReactorGateConfig, ReactorRoutingTable, RepositoryAuditSink,
    RepositoryReactorSource,
};
use axiam_amqp::reactor::protocol::{ReactorReply, ReplyDecision};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{Reactor, SharedReactorGate};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
    UserRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealReactorRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "reactor-e2e-placeholder-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";
/// The rate-limit middleware keys on the peer address and refuses a request
/// that has none, so every request in this file carries one.
const TEST_PEER: &str = "203.0.113.7:52001";
/// The same master key the gate is built with, so the scripted reactor derives
/// the same tenant subkey a real one would.
const MASTER_KEY: &[u8] = b"reactor-e2e-master-signing-key-32b";

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

// ---------------------------------------------------------------------------
// The scripted reactor
// ---------------------------------------------------------------------------

/// What the reactor on the other end of the (absent) broker answers with.
#[derive(Clone)]
enum Behaviour {
    Allow,
    Deny(&'static str),
    Mutate(&'static [(&'static str, &'static str)]),
    /// Never answers — the timeout row.
    Silent,
}

struct ScriptedReactor {
    behaviour: Mutex<Behaviour>,
    calls: Mutex<Vec<(String, serde_json::Value)>>,
}

impl ScriptedReactor {
    fn new(behaviour: Behaviour) -> Arc<Self> {
        Arc::new(Self {
            behaviour: Mutex::new(behaviour),
            calls: Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> Vec<(String, serde_json::Value)> {
        self.calls.lock().unwrap().clone()
    }
}

/// A newtype so the transport impl is local (orphan rule) while the handle
/// stays shareable between the test body and the gate.
#[derive(Clone)]
struct SharedReactor(Arc<ScriptedReactor>);

impl ReactorTransport for SharedReactor {
    async fn round_trip(
        &self,
        reactor: &Reactor,
        event: &'static str,
        correlation_id: Uuid,
        payload: serde_json::Value,
        _timeout_ms: u32,
    ) -> Result<ReactorReply, DispatchFailure> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push((event.to_string(), payload));

        let behaviour = self.0.behaviour.lock().unwrap().clone();
        let (decision, reason, patch) = match behaviour {
            Behaviour::Silent => return Err(DispatchFailure::Timeout),
            Behaviour::Allow => (ReplyDecision::Allow, None, None),
            Behaviour::Deny(r) => (ReplyDecision::Deny, Some(r.to_string()), None),
            Behaviour::Mutate(pairs) => (
                ReplyDecision::Mutate,
                None,
                Some(
                    pairs
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect::<BTreeMap<_, _>>(),
                ),
            ),
        };

        let mut reply = ReactorReply {
            correlation_id,
            tenant_id: reactor.tenant_id,
            event: event.to_string(),
            decision,
            reason,
            patch,
            require_mfa: false,
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: Utc::now(),
            hmac_signature: None,
        };
        // Signed with the tenant subkey derived from the same master key the
        // gate verifies against — an unsigned reply would be discarded, which
        // is itself covered in `axiam_amqp::reactor::protocol`.
        reply.sign(MASTER_KEY).expect("sign the reply");
        Ok(reply)
    }

    async fn publish_listen(
        &self,
        _reactor: &Reactor,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> Result<(), DispatchFailure> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Env {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    admin_id: Uuid,
    auth: AuthConfig,
}

async fn setup() -> Env {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Reactor E2E".into(),
            slug: "reactor-e2e".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Reactor E2E Tenant".into(),
            slug: "reactor-e2e-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let admin = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            admin.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    Env {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        admin_id: admin.id,
        auth: test_auth_config(),
    }
}

/// Build the `AppState` a production server builds, with the broker seam
/// replaced by `reactor`. Both service-side gates (`AuthService`,
/// `TokenService`) and the REST-side field get the SAME gate, exactly as
/// `axiam-server`'s composition root does.
fn state_with_gate(env: &Env, reactor: Arc<ScriptedReactor>, ttl: Duration) -> AppState<TestDb> {
    let routing = Arc::new(ReactorRoutingTable::new(
        RepositoryReactorSource(SurrealReactorRepository::new(env.db.clone())),
        ttl,
    ));
    let gate: SharedReactorGate = Arc::new(DispatchingReactorGate::new(
        Arc::clone(&routing),
        SharedReactor(reactor),
        RepositoryAuditSink(SurrealAuditLogRepository::new(env.db.clone())),
        MASTER_KEY.to_vec(),
        ReactorGateConfig {
            routing_ttl: ttl,
            ..Default::default()
        },
    ));

    let mut state = AppState::for_test(env.db.clone(), env.auth.clone());
    state.auth_service = state.auth_service.clone().with_reactor_gate(gate.clone());
    state.token_service = state.token_service.clone().with_reactor_gate(gate.clone());
    state.reactor_gate = gate;
    state.reactor_routing_invalidator = Some(Arc::new(move |tenant_id| {
        routing.invalidate_tenant(tenant_id)
    }));
    state
}

macro_rules! app_for {
    ($env:expr, $state:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($env.auth.clone()))
                .app_data(web::Data::new($state))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

macro_rules! authed {
    ($method:ident, $uri:expr, $token:expr) => {
        test::TestRequest::$method()
            .uri($uri)
            .peer_addr(TEST_PEER.parse::<std::net::SocketAddr>().unwrap())
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
    };
}

fn mint_token(env: &Env) -> String {
    issue_access_token(
        env.admin_id,
        env.tenant_id,
        env.org_id,
        &[],
        &env.auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

fn login_request(env: &Env) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .peer_addr(TEST_PEER.parse::<std::net::SocketAddr>().unwrap())
        .set_json(json!({
            "tenant_id": env.tenant_id,
            "org_id": env.org_id,
            "username_or_email": "alice",
            "password": TEST_PASSWORD,
        }))
}

/// Register a reactor through the real admin endpoint, so the registry row the
/// gate reads is the one an operator would have created.
async fn register_reactor(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    body: Value,
) -> Value {
    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "the reactor must register");
    test::read_body_json(resp).await
}

async fn audit_actions(env: &Env) -> Vec<String> {
    let repo: SurrealAuditLogRepository<TestDb> = SurrealAuditLogRepository::new(env.db.clone());
    repo.list(
        env.tenant_id,
        AuditLogFilter::default(),
        Pagination::default(),
    )
    .await
    .expect("read the audit trail")
        .items
        .into_iter()
        .map(|e| e.action)
        .collect()
}

// ---------------------------------------------------------------------------
// The acceptance test
// ---------------------------------------------------------------------------

/// **A registered interceptor demonstrably vetoes a login.**
///
/// The same credentials succeed before the registration and fail after it —
/// which is the property, rather than "a request 401'd".
#[actix_web::test]
async fn a_registered_interceptor_vetoes_a_login_over_http() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Deny("login from an embargoed region"));
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    // 1. Nothing registered: the login succeeds and no reactor was contacted.
    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "baseline: the credentials are good"
    );
    assert!(
        reactor.calls().is_empty(),
        "an un-hooked tenant must not reach a reactor at all"
    );

    // 2. Register a `login.post_auth` interceptor through the admin API.
    let created = register_reactor(
        &app,
        &token,
        json!({
            "name": "geo-veto",
            "events": ["login.post_auth"],
            "mode": "intercept",
        }),
    )
    .await;
    assert_eq!(
        created["failure_policy"], "fail_closed",
        "login.post_auth defaults closed — an unreachable fraud check has not passed"
    );

    // 3. The same login is now refused.
    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "the reactor vetoed a login whose credentials are correct"
    );

    // 4. The reactor was consulted, with the login context and no credential.
    let calls = reactor.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "login.post_auth");
    let payload = calls[0].1.to_string();
    assert!(payload.contains("alice"));
    assert!(
        !payload.contains(TEST_PASSWORD),
        "the password must never reach a reactor"
    );

    // 5. The veto is in the audit trail, which is what the health panel reads.
    let actions = audit_actions(&env).await;
    assert!(
        actions.iter().any(|a| a == "reactor.denied"),
        "the veto must be audited; saw {actions:?}"
    );

    // 6. Deleting the registration lets the login through again — the
    //    invalidation hook, end to end.
    let id = created["id"].as_str().unwrap();
    let resp = test::call_service(
        &app,
        authed!(delete, &format!("/api/v1/reactors/{id}"), token).to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 204);

    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "deleting the interceptor must restore the login immediately, not after the TTL"
    );
}

/// A `fail_closed` reactor that never answers denies, and the timeout is in the
/// audit trail under its own action.
#[actix_web::test]
async fn a_silent_interceptor_times_out_and_denies_the_login() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Silent);
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "silent-fraud-check",
            "events": ["login.post_auth"],
            "mode": "intercept",
            "timeout_ms": 50,
        }),
    )
    .await;

    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(resp.status().as_u16(), 401);

    let actions = audit_actions(&env).await;
    assert!(
        actions.iter().any(|a| a == "reactor.dispatch_failed"),
        "every timeout is audited; saw {actions:?}"
    );
}

/// A `fail_open` reactor that never answers must not break the operation — and
/// must still be audited, because that pair is the whole difference between
/// "no reactor was configured" and "the reactor never answered".
#[actix_web::test]
async fn a_silent_fail_open_interceptor_is_invisible_in_the_outcome_and_visible_in_the_audit() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Silent);
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "flaky-enrichment",
            "events": ["login.post_auth"],
            "mode": "intercept",
            "failure_policy": "fail_open",
            "timeout_ms": 50,
        }),
    )
    .await;

    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200, "fail_open lets the login through");
    assert!(
        audit_actions(&env)
            .await
            .iter()
            .any(|a| a == "reactor.dispatch_failed")
    );
}

// ---------------------------------------------------------------------------
// The other four sites, over HTTP
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn user_pre_create_vetoes_and_normalizes_over_http() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Deny("username reserved"));
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "profile-validator",
            "events": ["user.pre_create", "user.pre_update"],
            "mode": "intercept",
        }),
    )
    .await;

    let body = json!({
        "username": "bob",
        "email": "bob@example.com",
        "password": "another-placeholder-password-12345",
    });
    let resp = test::call_service(
        &app,
        authed!(post, "/api/v1/users", token)
            .set_json(body.clone())
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 403, "the veto refuses the write");
    assert_eq!(reactor.calls()[0].0, "user.pre_create");
    assert!(
        !reactor.calls()[0]
            .1
            .to_string()
            .contains("another-placeholder-password"),
        "a reactor validating a profile is not handed the credential"
    );
}

#[actix_web::test]
async fn user_pre_create_mutation_normalizes_the_stored_row() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Mutate(&[
        ("email", "bob@corp.example.com"),
        ("metadata.source", "hr-sync"),
    ]));
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "profile-normalizer",
            "events": ["user.pre_create"],
            "mode": "intercept",
        }),
    )
    .await;

    let resp = test::call_service(
        &app,
        authed!(post, "/api/v1/users", token)
            .set_json(json!({
                "username": "bob",
                "email": "bob@example.com",
                "password": "another-placeholder-password-12345",
            }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: Value = test::read_body_json(resp).await;
    assert_eq!(
        created["email"], "bob@corp.example.com",
        "the reactor's normalization is what got stored"
    );
    assert!(
        audit_actions(&env)
            .await
            .iter()
            .any(|a| a == "reactor.mutated")
    );
}

#[actix_web::test]
async fn grant_pre_assign_vetoes_a_role_assignment_over_http() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Deny("four-eyes approval pending"));
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "four-eyes",
            "events": ["grant.pre_assign"],
            "mode": "intercept",
        }),
    )
    .await;

    // Create a role to assign.
    let resp = test::call_service(
        &app,
        authed!(post, "/api/v1/roles", token)
            .set_json(json!({ "name": "auditor", "description": "read-only", "is_global": true }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 201);
    let role: Value = test::read_body_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    let resp = test::call_service(
        &app,
        authed!(post, &format!("/api/v1/roles/{role_id}/users"), token)
            .set_json(json!({ "user_id": env.admin_id }))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an unapproved assignment must not be written"
    );
    assert_eq!(reactor.calls()[0].0, "grant.pre_assign");
}

/// `token.pre_issue`, through the OAuth2 token endpoint, enriching the minted
/// token with an `ext.` claim.
#[actix_web::test]
async fn token_pre_issue_enriches_a_client_credentials_token_over_http() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Mutate(&[("ext.department", "engineering")]));
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_millis(50));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "hr-enrichment",
            "events": ["token.pre_issue"],
            "mode": "intercept",
        }),
    )
    .await;

    // Register an OAuth2 client for the client-credentials grant.
    let resp = test::call_service(
        &app,
        authed!(post, "/api/v1/oauth2-clients", token)
            .set_json(json!({
                "name": "bench-client",
                "redirect_uris": ["https://app.example.com/cb"],
                "grant_types": ["client_credentials"],
                "scopes": ["api"],
            }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 201, "the client must register");
    let client: Value = test::read_body_json(resp).await;
    let client_id = client["client_id"].as_str().unwrap().to_string();
    let client_secret = client["client_secret"].as_str().unwrap().to_string();

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/oauth2/token?tenant_id={}",
                env.tenant_id
            ))
            .peer_addr(TEST_PEER.parse::<std::net::SocketAddr>().unwrap())
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &client_id),
                ("client_secret", &client_secret),
                ("scope", "api"),
            ])
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "issuance succeeds");
    let issued: Value = test::read_body_json(resp).await;
    let access_token = issued["access_token"].as_str().unwrap();

    let claims = axiam_auth::token::validate_access_token(access_token, &env.auth)
        .expect("the enriched token validates")
        .0;
    let ext = claims.ext.expect("the reactor's claims are present");
    assert_eq!(ext["department"], "engineering");
    assert_eq!(
        claims.sub, client_id,
        "and nothing outside `ext.` moved"
    );
}

// ---------------------------------------------------------------------------
// Registry visibility
// ---------------------------------------------------------------------------

/// The invalidation acceptance test, over HTTP: a registration written on
/// ANOTHER replica (simulated by writing straight to the store, bypassing the
/// handler that invalidates) becomes live within the TTL.
#[actix_web::test]
async fn a_registration_written_elsewhere_becomes_live_within_the_ttl() {
    use axiam_core::models::reactor::{CreateReactor, FailurePolicy, ReactorMode};
    use axiam_core::repository::ReactorRepository;

    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Deny("registered on another replica"));
    // Generous enough that two Argon2id logins fit inside it — the point is
    // the bound, not how small it is.
    let ttl = Duration::from_secs(3);
    let state = state_with_gate(&env, Arc::clone(&reactor), ttl);
    let app = app_for!(env, state);

    // Prime the routing table with "nobody is listening".
    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Write the registration directly — no handler, so no invalidation hook.
    SurrealReactorRepository::new(env.db.clone())
        .create(CreateReactor {
            tenant_id: env.tenant_id,
            name: "remote-veto".into(),
            description: String::new(),
            events: vec!["login.post_auth".into()],
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: Some(500),
            failure_policy: Some(FailurePolicy::FailClosed),
            enabled: true,
        })
        .await
        .expect("write the registration");

    // Inside the TTL the cached (empty) list is still served — the documented
    // staleness bound, asserted rather than assumed.
    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);

    tokio::time::sleep(ttl + Duration::from_millis(200)).await;

    let resp = test::call_service(&app, login_request(&env).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "a registration this replica never served must be live within the TTL"
    );
}

/// The fifth site over HTTP: `user.pre_update`. An allowing reactor leaves the
/// update alone; a vetoing one refuses it.
#[actix_web::test]
async fn user_pre_update_is_consulted_and_can_veto_over_http() {
    let env = setup().await;
    let reactor = ScriptedReactor::new(Behaviour::Allow);
    let state = state_with_gate(&env, Arc::clone(&reactor), Duration::from_secs(3));
    let app = app_for!(env, state);
    let token = mint_token(&env);

    register_reactor(
        &app,
        &token,
        json!({
            "name": "profile-guard",
            "events": ["user.pre_update"],
            "mode": "intercept",
        }),
    )
    .await;

    let uri = format!("/api/v1/users/{}", env.admin_id);
    let resp = test::call_service(
        &app,
        authed!(put, &uri, token)
            .set_json(json!({ "email": "alice+new@example.com" }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "an allowing reactor is transparent");
    assert_eq!(reactor.calls()[0].0, "user.pre_update");

    // Now the same reactor refuses.
    *reactor.behaviour.lock().unwrap() = Behaviour::Deny("profile frozen");
    let resp = test::call_service(
        &app,
        authed!(put, &uri, token)
            .set_json(json!({ "email": "alice+blocked@example.com" }))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 403, "the veto refuses the update");

    // And the stored row still carries the value the ALLOWED update wrote.
    let resp = test::call_service(&app, authed!(get, &uri, token).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);
    let user: Value = test::read_body_json(resp).await;
    assert_eq!(user["email"], "alice+new@example.com");
}
