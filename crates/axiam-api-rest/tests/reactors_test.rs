//! Integration tests for the reactor management endpoints
//! (`/api/v1/reactors`, X1).
//!
//! Uses an in-memory SurrealDB and the `AllowAllAuthzChecker`, so every
//! request is authenticated (real minted JWT) but authorization is stubbed —
//! the focus is the handler's registry validation, not RBAC.
//!
//! The validation is the part worth testing through HTTP rather than against
//! `validate_registration` directly: a registration decides whether third-party
//! code can veto a login or add a claim to a token, and the failure mode is a
//! reactor that was accepted for an event nobody will ever fire it on.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Matching CSRF header/cookie value — the double-submit middleware only
/// checks header == cookie, so any matching pair satisfies it.
const CSRF_TOKEN: &str = "test-csrf-token";

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

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Reactor Org".into(),
            slug: "reactor-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Reactor Tenant".into(),
            slug: "reactor-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "reactor-admin".into(),
            email: "reactor-admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
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

/// Every request needs auth + the double-submit CSRF pair; this keeps the
/// tests about reactors rather than about headers.
macro_rules! authed {
    ($method:ident, $uri:expr, $token:expr) => {
        test::TestRequest::$method()
            .uri($uri)
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
    };
}

fn valid_body() -> Value {
    json!({
        "name": "hr-enrichment",
        "description": "adds ext.department from the HR system",
        "events": ["token.pre_issue"],
        "mode": "intercept",
    })
}

#[actix_web::test]
async fn create_list_get_update_delete_roundtrip() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(valid_body())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();

    assert_eq!(created["name"], "hr-enrichment");
    assert_eq!(created["mode"], "intercept");
    assert_eq!(created["enabled"], true);
    assert_eq!(created["timeout_ms"], 500, "the documented default");
    assert_eq!(
        created["failure_policy"], "fail_open",
        "token.pre_issue is enrichment, so an unreachable reactor must not block issuance"
    );
    assert!(
        created["last_seen_at"].is_null(),
        "a reactor that has never connected must be distinguishable"
    );

    let req = authed!(get, "/api/v1/reactors", token).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let listed: Value = test::read_body_json(resp).await;
    assert_eq!(listed["total"], 1);

    let req = authed!(get, &format!("/api/v1/reactors/{id}"), token).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let req = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({"enabled": false, "priority": 7}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let updated: Value = test::read_body_json(resp).await;
    assert_eq!(updated["enabled"], false);
    assert_eq!(updated["priority"], 7);
    assert_eq!(
        updated["name"], "hr-enrichment",
        "an unnamed field is left alone"
    );

    let req = authed!(delete, &format!("/api/v1/reactors/{id}"), token).to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let req = authed!(get, &format!("/api/v1/reactors/{id}"), token).to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);
}

/// A registration for an event nobody will ever fire is worse than a rejected
/// one: it looks configured and never runs.
#[actix_web::test]
async fn an_unknown_event_is_refused() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let mut body = valid_body();
    body["events"] = json!(["token.pre_issue", "authz.check"]);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "authz.check is a hot path and is deliberately not in the registry"
    );
}

#[actix_web::test]
async fn a_timeout_above_the_ceiling_is_refused() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let mut body = valid_body();
    body["timeout_ms"] = json!(30_000);
    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(body)
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);

    // The ceiling itself is accepted — the bound is inclusive.
    let mut body = valid_body();
    body["timeout_ms"] = json!(5_000);
    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(body)
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
}

/// The strictest-default rule, through HTTP: a reactor that can veto a login
/// must fail closed even though it also enriches tokens.
#[actix_web::test]
async fn an_omitted_failure_policy_takes_the_strictest_event_default() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let mut body = valid_body();
    body["name"] = json!("mixed");
    body["events"] = json!(["token.pre_issue", "login.post_auth"]);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: Value = test::read_body_json(resp).await;
    assert_eq!(created["failure_policy"], "fail_closed");
}

/// The update path validates the MERGED registration, not the request.
///
/// A PUT that only replaces `events` is valid in isolation; the violation is
/// in the pair (`mode: intercept` from storage + a listen-only event from the
/// request). Validating the request alone would let it through.
#[actix_web::test]
async fn update_validates_the_merged_registration_not_the_request() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(valid_body())
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    // `events` alone, naming something not in the registry: the stored
    // `mode: intercept` is what makes it invalid.
    let req = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({"events": ["authz.check"]}))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);

    // …and a timeout alone is validated against the stored name and events.
    let req = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({"timeout_ms": 0}))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);
}

/// Widening the event set re-derives the policy. A reactor that was
/// enrichment-only must not keep passing when unreachable once it can veto a
/// login.
#[actix_web::test]
async fn replacing_the_events_without_naming_a_policy_re_derives_it() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(valid_body())
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["failure_policy"], "fail_open");

    let req = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({"events": ["login.post_auth"]}))
        .to_request();
    let updated: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(
        updated["failure_policy"], "fail_closed",
        "the stored fail_open predates the veto capability and must not survive it"
    );
}

/// An explicit policy is honoured even when it is the looser one — the
/// re-derivation is a default, not an override.
#[actix_web::test]
async fn an_explicit_failure_policy_survives_an_event_change() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(valid_body())
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    let req = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({"events": ["login.post_auth"], "failure_policy": "fail_open"}))
        .to_request();
    let updated: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(updated["failure_policy"], "fail_open");
}

#[actix_web::test]
async fn a_blank_name_and_an_empty_event_list_are_refused() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let mut blank = valid_body();
    blank["name"] = json!("   ");
    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(blank)
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);

    let mut empty = valid_body();
    empty["events"] = json!([]);
    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(empty)
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);
}

/// The registry is served rather than documented, so an admin UI and an
/// operator read the same list the dispatcher enforces.
#[actix_web::test]
async fn the_event_registry_is_served_and_matches_the_enforced_one() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = authed!(get, "/api/v1/reactors/events", token).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/reactors/events must be routed before /reactors/{{id}}, or the UUID \
         parser swallows it"
    );

    let events: Value = test::read_body_json(resp).await;
    let served = events.as_array().unwrap();
    assert_eq!(
        served.len(),
        axiam_core::models::reactor::EVENT_REGISTRY.len(),
        "the served list must be the registry, not a copy of it"
    );

    let token_hook = served
        .iter()
        .find(|e| e["name"] == "token.pre_issue")
        .expect("token.pre_issue is in the registry");
    assert_eq!(token_hook["mutable"], true);
    assert_eq!(token_hook["mutable_fields"], json!(["ext."]));

    let veto_hook = served
        .iter()
        .find(|e| e["name"] == "grant.pre_assign")
        .expect("grant.pre_assign is in the registry");
    assert_eq!(veto_hook["mutable"], false);
    assert_eq!(veto_hook["default_failure_policy"], "fail_closed");

    assert!(
        !served.iter().any(|e| e["name"] == "authz.check"),
        "the hot path must not be advertised as hookable"
    );
}

/// Cross-tenant isolation on the REST surface, not just in the repository.
#[actix_web::test]
async fn a_reactor_is_invisible_to_another_tenant() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let owner = mint_token(&auth, user_id, tenant_id, org_id);
    let req = authed!(post, "/api/v1/reactors", owner)
        .set_json(valid_body())
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    let intruder = mint_token(&auth, Uuid::new_v4(), Uuid::new_v4(), org_id);
    let req = authed!(get, &format!("/api/v1/reactors/{id}"), intruder).to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);

    let req = authed!(delete, &format!("/api/v1/reactors/{id}"), intruder).to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);

    // …and the failed cross-tenant delete really did not delete it.
    let req = authed!(get, &format!("/api/v1/reactors/{id}"), owner).to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// SEC-101 — registration is refused while the transport cannot dispatch
// ---------------------------------------------------------------------------

/// A gate whose transport cannot deliver — what `axiam-server` composes today
/// (`UnavailableReactorTransport`), reduced to the one property the handler
/// reads.
struct UndispatchableGate;

impl axiam_core::models::reactor::DynReactorGate for UndispatchableGate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        _event: &'static str,
        _payload: serde_json::Value,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = axiam_core::models::reactor::ReactorOutcome>
                + Send
                + 'a,
        >,
    > {
        Box::pin(std::future::ready(
            axiam_core::models::reactor::ReactorOutcome::Allow,
        ))
    }

    fn can_dispatch_dyn(&self) -> bool {
        false
    }
}

macro_rules! undispatchable_app {
    ($db:expr, $auth:expr) => {{
        let mut state = AppState::for_test($db.clone(), $auth.clone());
        state.reactor_gate = Arc::new(UndispatchableGate);
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

/// Registering a reactor while nothing can reach it is a **self-service,
/// tenant-wide, complete login outage**: the transport fails every dispatch,
/// `login.post_auth` defaults to `fail_closed`, and the only warning is a
/// `tracing::warn!` emitted once at boot for every deployment — including the
/// majority that will never register a reactor, which is how a warning becomes
/// a filtered line. The action that causes the outage happens weeks later, in
/// a UI that gave no indication anything was wrong.
///
/// Before the fix this asserts 201.
#[actix_web::test]
async fn creating_a_reactor_is_refused_while_the_transport_cannot_dispatch() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = undispatchable_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(json!({
            "name": "fraud-veto",
            "events": ["login.post_auth"],
            "mode": "intercept",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        503,
        "the dependency this registration needs is absent from this build"
    );
    let body: Value = test::read_body_json(resp).await;
    assert!(
        body.to_string().contains("fail_closed"),
        "the refusal must say what would have happened: {body}"
    );
}

/// `listen` is refused too. `ReactorTransport::publish_listen` has no caller
/// anywhere in the tree — `run_chain` filters listeners out and `intercept`
/// returns early when the interceptor list is empty — so a listen registration
/// receives nothing, which is the inverse of its contract (SEC-099).
#[actix_web::test]
async fn a_listen_registration_is_refused_too_while_the_transport_cannot_dispatch() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = undispatchable_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(json!({
            "name": "observer",
            "events": ["token.pre_issue"],
            "mode": "listen",
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 503);
}

/// The operator must keep a way out. A registration created while the
/// transport worked has to remain *disable*-able and *delete*-able when it
/// stops — otherwise the refusal becomes the outage it exists to prevent.
#[actix_web::test]
async fn a_disabled_registration_and_a_delete_are_always_permitted() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // Created through the ordinary (dispatchable) app …
    let created: Value = {
        let app = test_app!(db, auth);
        let req = authed!(post, "/api/v1/reactors", token)
            .set_json(valid_body())
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        test::read_body_json(resp).await
    };
    let id = created["id"].as_str().unwrap().to_string();

    // … and then the transport goes away.
    let app = undispatchable_app!(db, auth);

    let disable = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({ "enabled": false }))
        .to_request();
    assert_eq!(
        test::call_service(&app, disable).await.status().as_u16(),
        200,
        "disabling must always be available — it is the way out"
    );

    // Re-enabling is what stays refused.
    let reenable = authed!(put, &format!("/api/v1/reactors/{id}"), token)
        .set_json(json!({ "enabled": true }))
        .to_request();
    assert_eq!(
        test::call_service(&app, reenable).await.status().as_u16(),
        503
    );

    let delete = authed!(delete, &format!("/api/v1/reactors/{id}"), token).to_request();
    assert_eq!(
        test::call_service(&app, delete).await.status().as_u16(),
        204
    );
}

/// A disabled registration may be created even when nothing can reach it: it
/// dispatches to nothing, so it causes no outage, and refusing it would block
/// a legitimate "stage the configuration now, enable it when the transport
/// ships" workflow.
#[actix_web::test]
async fn creating_a_disabled_registration_is_permitted() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = undispatchable_app!(db, auth);

    let req = authed!(post, "/api/v1/reactors", token)
        .set_json(json!({
            "name": "staged",
            "events": ["login.post_auth"],
            "mode": "intercept",
            "enabled": false,
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
}
