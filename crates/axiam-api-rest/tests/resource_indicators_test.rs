//! T21.3 — RFC 8707 resource indicators, end to end.
//!
//! The feature is one sentence: a client may ask for a token addressed at a
//! resource server that is not AXIAM, and the token's `aud` says so. Every
//! test here is asking one of four questions about that sentence.
//!
//! **Does the audience actually travel?** Through each of the four grants that
//! can carry the parameter — `authorization_code` (including via PAR),
//! `refresh_token`, `client_credentials` and `device_code` — the value the
//! client named comes back as `aud` on the minted token.
//!
//! **Can it be widened?** No, and the tests that prove it are the ones worth
//! reading first. A grant's audience is fixed when the grant is made: a token
//! request may repeat the resource or omit it, a refresh may do the same, and
//! anything else is `invalid_target`. A grant that named no resource cannot
//! acquire one at redemption or at rotation, because nobody asked the end user
//! about that resource.
//!
//! **Does AXIAM still refuse foreign audiences at its own doors?** This is
//! invariant I3 and it is a test that is *added*, never relaxed: a token minted
//! for an MCP server is `401` at `/api/v1/auth/me`. The gRPC half of the same
//! invariant lives in `axiam-api-grpc/tests/grpc_auth_test.rs`, beside the
//! interceptor it is about.
//!
//! **Is the default path untouched?** This is I1 and I2. A request that sends
//! no `resource` mints `axiam:user` / `axiam:m2m` exactly as it always has, and
//! a client registered with no `allowed_resources` — which is every client that
//! existed before this change — may name nothing at all.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const ISSUER: &str = "https://localhost";
const REDIRECT: &str = "https://rp.example.com/callback";
/// The MCP server this tenant fronts, as an operator would register it.
const MCP: &str = "https://mcp.example.com/mcp";
/// A second registered resource, so "changed to another resource" can be told
/// apart from "changed to something unregistered".
const MCP_TWO: &str = "https://tools.example.com/mcp";
const UNREGISTERED: &str = "https://elsewhere.example.com/mcp";
const VERIFIER: &str = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4.1";

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
        oauth2_issuer_url: ISSUER.into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    user_token: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.3 Org".into(),
            slug: "org-t21-3".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "T21.3 Tenant".into(),
            slug: "tenant-t21-3".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            // Generated rather than written down: nothing here signs in with
            // it, so a literal would be a credential in the tree buying
            // nothing.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let user_token = issue_access_token(
        user.id,
        tenant.id,
        org.id,
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();

    Fixture {
        db,
        auth,
        tenant_id: tenant.id,
        user_token,
    }
}

macro_rules! test_app {
    ($f:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    $f.auth.clone(),
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

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

/// The `aud` claim of a JWT, read without verifying anything.
///
/// A test assertion, not a validation primitive: what is under test is which
/// audience the server *stamped*, and verifying the signature here would only
/// re-assert what `validate_access_token`'s own tests already cover.
fn aud_of(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["aud"]
        .as_str()
        .unwrap_or_else(|| panic!("no aud in {claims}"))
        .to_owned()
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

macro_rules! register {
    ($app:expr, $f:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json($body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

macro_rules! get_authorize {
    ($app:expr, $f:expr, $query:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/authorize?{}", $query))
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("Location")
            .map(|v| v.to_str().unwrap().to_owned());
        let body = test::read_body(resp).await;
        (
            status,
            location,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

macro_rules! post_form {
    ($app:expr, $f:expr, $path:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("{}?tenant_id={}", $path, $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload($body.to_string())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
        )
    }};
}

/// The registration every code-grant test starts from: two registered
/// resources and the grants to exercise them.
fn code_client_body(name: &str, allowed: &[&str]) -> Value {
    json!({
        "name": name,
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "allowed_resources": allowed,
    })
}

/// The query parameter a redirect carries, or `None`.
fn param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn code_from(location: &str) -> String {
    param(location, "code").unwrap_or_else(|| panic!("no code in {location}"))
}

// ---------------------------------------------------------------------------
// Registration — the allow-list
// ---------------------------------------------------------------------------

/// The stored list is the **normalised** one, so what an operator reads back is
/// what the request path will compare. An allow-list whose read-back differs
/// from its comparison is an allow-list nobody can audit.
#[actix_rt::test]
async fn allowed_resources_are_stored_and_returned_in_their_normalised_form() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register!(
        app,
        f,
        code_client_body("mcp-rp", &["HTTPS://MCP.Example.COM:443/mcp"])
    );
    assert_eq!(status, 201, "{body}");

    let id = body["id"].as_str().unwrap();
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {}", f.user_token)))
        .to_request();
    let read: Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(
        read["allowed_resources"],
        json!([MCP]),
        "the scheme, host and default port normalise; the path does not change"
    );
}

/// RFC 8707 §2's two structural rules, refused where the operator can act on
/// them rather than where the client discovers them.
#[actix_rt::test]
async fn a_malformed_allowed_resource_is_refused_at_registration() {
    let f = setup().await;
    let app = test_app!(f);

    for bad in [
        "https://mcp.example.com/mcp#tools", // fragment (RFC 8707 §2)
        "/mcp",                              // relative reference
        "not a uri",
    ] {
        let (status, body) = register!(app, f, code_client_body("bad", &[bad]));
        assert_eq!(status, 400, "{bad} must be refused, got {body}");
        assert!(
            body.to_string().contains("allowed_resources"),
            "the refusal must name the field and the entry: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// I1 / I2 — the default path is untouched
// ---------------------------------------------------------------------------

/// I2, on the grant the SDK contract's row 6 is about. No `resource`, no
/// `allowed_resources`, and the token is exactly the token this flow has always
/// minted.
#[actix_rt::test]
async fn i2_a_code_flow_without_resource_still_mints_the_user_audience() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("plain-rp", &[]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();

    let challenge = pkce_challenge(VERIFIER);
    let (status, location, body) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    assert_eq!(status, 302, "{body}");
    let code = code_from(&location.unwrap());

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        axiam_auth::token::AUD_USER,
        "a request that names no resource is the request AXIAM has always served"
    );
}

/// I1's "absent when off" half: the feature is opt-in per client, and a client
/// that opted into nothing may name nothing. This is every client registered
/// before T21.3, whose `allowed_resources` migrated in as `[]`.
#[actix_rt::test]
async fn a_client_with_an_empty_allow_list_may_name_no_resource() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("plain-rp", &[]));
    let client_id = client["client_id"].as_str().unwrap();

    let challenge = pkce_challenge(VERIFIER);
    let (status, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256\
             &resource={MCP}"
        )
    );
    assert_eq!(status, 302, "the refusal is redirected, not rendered");
    let location = location.unwrap();
    assert_eq!(
        param(&location, "error").as_deref(),
        Some("invalid_target"),
        "{location}"
    );
}

// ---------------------------------------------------------------------------
// The authorization code grant
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_code_grant_mints_the_named_resource_as_the_audience() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP, MCP_TWO]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();

    let challenge = pkce_challenge(VERIFIER);
    let (status, location, body) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256\
             &resource={MCP}"
        )
    );
    assert_eq!(status, 302, "{body}");
    let code = code_from(&location.unwrap());

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        MCP,
        "the audience is the resource the authorization named"
    );
}

/// The parameter is an allow-list check at the authorization endpoint, and the
/// refusal is redirected — the client is known and its `redirect_uri` has been
/// validated by the time this is decided (RFC 6749 §4.1.2.1).
#[actix_rt::test]
async fn an_unregistered_resource_is_invalid_target_at_the_authorization_endpoint() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP]));
    let client_id = client["client_id"].as_str().unwrap();

    let challenge = pkce_challenge(VERIFIER);
    let (status, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256\
             &resource={UNREGISTERED}&state=xyz"
        )
    );
    assert_eq!(status, 302);
    let location = location.unwrap();
    assert_eq!(param(&location, "error").as_deref(), Some("invalid_target"));
    assert_eq!(
        param(&location, "state").as_deref(),
        Some("xyz"),
        "an error redirect still echoes state, so the client can correlate it"
    );
}

/// The redemption rule, in all three directions. This is the test that would
/// fail if anybody made the token endpoint consult `allowed_resources` instead
/// of the code's own binding.
#[actix_rt::test]
async fn a_code_may_be_redeemed_for_its_own_resource_and_no_other() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP, MCP_TWO]));
    let client_id = client["client_id"].as_str().unwrap().to_owned();
    let secret = client["client_secret"].as_str().unwrap().to_owned();
    let challenge = pkce_challenge(VERIFIER);

    // A fresh code each time: redemption is single-use, and a test that
    // reused one would be asserting the replay rule by accident.
    let code_for = |resource: Option<&str>| match resource {
        Some(r) => format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
                 &scope=openid&code_challenge={challenge}&code_challenge_method=S256&resource={r}"
        ),
        None => format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
                 &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        ),
    };

    // 1. Repeating the bound resource is accepted, and mints it.
    let (_, location, _) = get_authorize!(app, f, code_for(Some(MCP)));
    let code = code_from(&location.unwrap());
    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}&resource={MCP}"
        )
    );
    assert_eq!(
        status, 200,
        "repeating the bound value is allowed: {tokens}"
    );
    assert_eq!(aud_of(tokens["access_token"].as_str().unwrap()), MCP);

    // 2. Naming a *different registered* resource is refused. Registered, so
    //    that what is being tested is the binding and not the allow-list.
    let (_, location, _) = get_authorize!(app, f, code_for(Some(MCP)));
    let code = code_from(&location.unwrap());
    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}\
             &resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // 3. A code bound to nothing cannot acquire a resource at redemption.
    let (_, location, _) = get_authorize!(app, f, code_for(None));
    let code = code_from(&location.unwrap());
    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}&resource={MCP}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body["error"], "invalid_target",
        "a grant that named no resource must not acquire one at the token endpoint"
    );
}

// ---------------------------------------------------------------------------
// Refresh — the rule that stops widening
// ---------------------------------------------------------------------------

/// A refresh re-mints the **same** audience, may repeat the value, and cannot
/// change it. Without the first of those a resource-bound token would silently
/// become an `axiam:user` token fifteen minutes later — a widening performed by
/// the server, with nobody's consent behind it.
#[actix_rt::test]
async fn a_refresh_re_mints_the_same_audience_and_cannot_change_it() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP, MCP_TWO]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (_, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256&resource={MCP}"
        )
    );
    let code = code_from(&location.unwrap());
    let (_, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    // Refreshing a different resource is refused — and refused *before* the
    // rotation, so the refresh token below is still spendable.
    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}&resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // Omitting it inherits the bound audience.
    let (status, refreshed) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}"
        )
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(
        aud_of(refreshed["access_token"].as_str().unwrap()),
        MCP,
        "a refresh must not silently widen a resource-bound token to axiam:user"
    );

    // And the successor is bound too, so the chain cannot drift.
    let refresh = refreshed["refresh_token"].as_str().unwrap().to_owned();
    let (status, again) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}&resource={MCP}"
        )
    );
    assert_eq!(status, 200, "{again}");
    assert_eq!(aud_of(again["access_token"].as_str().unwrap()), MCP);
}

/// The other direction of the same rule: a grant made without a resource stays
/// without one, however many times it is rotated.
#[actix_rt::test]
async fn an_unbound_grant_cannot_acquire_a_resource_by_refreshing() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (_, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    let code = code_from(&location.unwrap());
    let (_, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}&resource={MCP}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // I2: and the ordinary refresh still mints what it always did.
    let (status, refreshed) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}"
        )
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(
        aud_of(refreshed["access_token"].as_str().unwrap()),
        axiam_auth::token::AUD_USER
    );
}

// ---------------------------------------------------------------------------
// PAR
// ---------------------------------------------------------------------------

/// PAR is the only carrier a `require_par` client has, so the parameter has to
/// travel through it — and the query string beside a `request_uri` must not be
/// able to substitute a different target.
#[actix_rt::test]
async fn par_carries_the_resource_and_the_query_string_cannot_override_it() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP, MCP_TWO]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (status, pushed) = post_form!(
        app,
        f,
        "/oauth2/par",
        format!(
            "client_id={client_id}&client_secret={secret}&response_type=code\
             &redirect_uri={REDIRECT}&scope=openid&code_challenge={challenge}\
             &code_challenge_method=S256&resource={MCP}"
        )
    );
    assert_eq!(status, 201, "{pushed}");
    let request_uri = pushed["request_uri"].as_str().unwrap();

    // The query string proposes MCP_TWO; the pushed copy wins.
    let (status, location, _) = get_authorize!(
        app,
        f,
        format!("client_id={client_id}&request_uri={request_uri}&resource={MCP_TWO}")
    );
    assert_eq!(status, 302);
    let code = code_from(&location.unwrap());

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        MCP,
        "the browser must not be able to re-address a pushed request"
    );
}

/// Validated at push time, where the client is authenticated, so the refusal is
/// attributable and never surfaces in a browser after a needless sign-in.
#[actix_rt::test]
async fn par_refuses_an_unregistered_resource_under_client_authentication() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/par",
        format!(
            "client_id={client_id}&client_secret={secret}&response_type=code\
             &redirect_uri={REDIRECT}&scope=openid&code_challenge={challenge}\
             &code_challenge_method=S256&resource={UNREGISTERED}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");
}

// ---------------------------------------------------------------------------
// Device authorization grant
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_device_flow_carries_the_resource_from_authorization_to_token() {
    use axiam_core::models::oauth2_client::DeviceGrantStatus;
    use axiam_core::repository::DeviceGrantRepository;

    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(
        app,
        f,
        json!({
            "name": "tv",
            "redirect_uris": [REDIRECT],
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
            "scopes": ["openid"],
            "allowed_resources": [MCP, MCP_TWO],
        })
    );
    let client_id = client["client_id"].as_str().unwrap();

    let repo = axiam_db::repository::SurrealDeviceGrantRepository::new(f.db.clone());
    let user_id = Uuid::parse_str(
        serde_json::from_slice::<Value>(
            &URL_SAFE_NO_PAD
                .decode(f.user_token.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap()["sub"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    // A macro rather than a closure: two grants are needed rather than two
    // polls of one, because RFC 8628 §3.5's interval is enforced before
    // anything this test is about — a second poll of the same code inside a
    // second is `slow_down` whatever the `resource` says, and the test would
    // be asserting the polling contract by accident.
    macro_rules! approved_device_code {
        ($resource:expr) => {{
            let (status, device) = post_form!(
                app,
                f,
                "/oauth2/device_authorization",
                format!("client_id={client_id}&scope=openid&resource={}", $resource)
            );
            assert_eq!(status, 200, "{device}");
            let device_code = device["device_code"].as_str().unwrap().to_owned();
            let normalised =
                axiam_oauth2::device::normalize_user_code(device["user_code"].as_str().unwrap());
            // Approved out of band, as the verification page would.
            assert!(
                repo.decide(f.tenant_id, &normalised, true, user_id)
                    .await
                    .unwrap()
            );
            assert_eq!(
                repo.get_by_user_code(f.tenant_id, &normalised)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                DeviceGrantStatus::Approved
            );
            device_code
        }};
    }

    // A poll naming a different target is refused, and refused before the
    // code is spent — the device gets an actionable answer rather than
    // discovering it has burnt the user's approval.
    let device_code = approved_device_code!(MCP);
    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code\
             &device_code={device_code}&resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");

    // The honest poll gets its token, addressed at the resource the device
    // named when it started the flow.
    let device_code = approved_device_code!(MCP);
    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(aud_of(tokens["access_token"].as_str().unwrap()), MCP);

    // I2: a device flow that names no resource still mints `axiam:user`.
    let device_code = approved_device_code!("");
    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        axiam_auth::token::AUD_USER
    );
}

#[actix_rt::test]
async fn the_device_authorization_endpoint_refuses_an_unregistered_resource() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(
        app,
        f,
        json!({
            "name": "tv",
            "redirect_uris": [REDIRECT],
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
            "scopes": ["openid"],
            "allowed_resources": [MCP],
        })
    );
    let client_id = client["client_id"].as_str().unwrap();

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/device_authorization",
        format!("client_id={client_id}&scope=openid&resource={UNREGISTERED}")
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");
}

// ---------------------------------------------------------------------------
// Client credentials
// ---------------------------------------------------------------------------

/// The machine grant is the one with no earlier credential to inherit a target
/// from, so its allow-list check is at the token endpoint. I2's `axiam:m2m`
/// half is asserted in the same test, from the same registration.
#[actix_rt::test]
async fn the_client_credentials_grant_addresses_a_resource_or_stays_m2m() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(
        app,
        f,
        json!({
            "name": "service",
            "redirect_uris": [],
            "grant_types": ["client_credentials"],
            "scopes": ["read"],
            "allowed_resources": [MCP],
        })
    );
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={secret}\
             &scope=read&resource={MCP}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(aud_of(tokens["access_token"].as_str().unwrap()), MCP);

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={secret}&scope=read"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        axiam_auth::token::AUD_M2M,
        "I2: no resource, no change"
    );

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={secret}\
             &scope=read&resource={UNREGISTERED}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target");
}

// ---------------------------------------------------------------------------
// I3 — AXIAM's own APIs keep refusing foreign audiences
// ---------------------------------------------------------------------------

/// **I3.** A token minted for an MCP server is not a token for AXIAM.
///
/// This is the invariant T21.3 adds a test for rather than relaxes. The refusal
/// happens in `validate_access_token`, which pins the audience set, so it is
/// the same refusal every AXIAM-protected route gives — and it is what makes
/// `resource` safe to offer at all: a client that asks for a token for
/// somebody else gets a token it cannot turn around and use here.
///
/// The gRPC half is `grpc_rejects_a_resource_bound_token` in
/// `axiam-api-grpc/tests/grpc_auth_test.rs`.
#[actix_rt::test]
async fn i3_a_resource_bound_token_is_refused_by_axiams_own_rest_api() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (_, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256&resource={MCP}"
        )
    );
    let code = code_from(&location.unwrap());
    let (_, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    let bound = tokens["access_token"].as_str().unwrap();
    assert_eq!(aud_of(bound), MCP, "the token under test really is bound");

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Authorization", format!("Bearer {bound}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "a token addressed at an MCP server must not open AXIAM's own doors"
    );

    // The same request with an ordinary token succeeds, so the 401 above is
    // about the audience and not about the route being closed to everybody.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", f.user_token)))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// Introspection and revocation
// ---------------------------------------------------------------------------

/// RFC 7662 §2.2 — introspection must be able to *describe* a resource-bound
/// token, including its `aud`, which is the whole of the audience check a
/// resource server performs.
///
/// This is the one place a decode that does not pin the audience is correct,
/// and the test pins both halves: the token is `active` here, and the test
/// above proves the same token is `401` at AXIAM's own endpoints.
#[actix_rt::test]
async fn introspection_describes_a_resource_bound_token_and_reports_its_aud() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (_, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256&resource={MCP}"
        )
    );
    let code = code_from(&location.unwrap());
    let (_, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        )
    );
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/introspect",
        format!("token={access}&client_id={client_id}&client_secret={secret}")
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["active"], true,
        "a resource-bound token is live, not inactive: {body}"
    );
    assert_eq!(
        body["aud"], MCP,
        "and the resource server is told whose: {body}"
    );

    // RFC 7009 — revocation reaches a resource-bound grant's refresh token.
    let (status, _) = post_form!(
        app,
        f,
        "/oauth2/revoke",
        format!("token={refresh}&client_id={client_id}&client_secret={secret}")
    );
    assert_eq!(status, 200);
    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=refresh_token&refresh_token={refresh}\
             &client_id={client_id}&client_secret={secret}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant");
}

/// I2 for the introspection response: a token with AXIAM's own audience is
/// described exactly as it was, with `aud` now present and naming it.
#[actix_rt::test]
async fn introspection_still_describes_an_ordinary_token() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("plain-rp", &[]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/introspect",
        format!(
            "token={}&client_id={client_id}&client_secret={secret}",
            f.user_token
        )
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["active"], true);
    assert_eq!(body["aud"], axiam_auth::token::AUD_USER);
}

// ---------------------------------------------------------------------------
// D1 — one resource per request
// ---------------------------------------------------------------------------

/// RFC 8707 §2 lets `resource` repeat; AXIAM's access token carries a single
/// `aud`, so a second value is `invalid_target` rather than a guess at which
/// one the caller meant.
///
/// The refusal itself is structural — the form and query deserializers reject a
/// repeated key before a handler runs — so what is asserted here is that the
/// *code* a client sees is the one RFC 8707 defines.
#[actix_rt::test]
async fn two_resource_values_are_refused_with_invalid_target() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, client) = register!(app, f, code_client_body("mcp-rp", &[MCP, MCP_TWO]));
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (status, _, body) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256\
             &resource={MCP}&resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target", "{body}");

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=client_credentials&client_id={client_id}&client_secret={secret}\
             &resource={MCP}&resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target", "{body}");

    let (status, body) = post_form!(
        app,
        f,
        "/oauth2/par",
        format!(
            "client_id={client_id}&client_secret={secret}&response_type=code\
             &redirect_uri={REDIRECT}&scope=openid&resource={MCP}&resource={MCP_TWO}"
        )
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_target", "{body}");
}

/// I1 — the error handlers added for D1 change **only** the repeated-`resource`
/// case. Any other query the extractor cannot read gets the answer it always
/// got, which is a `400` that is not this JSON body.
#[actix_rt::test]
async fn an_unrelated_malformed_request_keeps_its_old_answer() {
    let f = setup().await;
    let app = test_app!(f);

    // `tenant_id` must be a UUID; this one is not, and the response must not
    // have become an `invalid_target` JSON body on the way past the new
    // handler.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/token?tenant_id=not-a-uuid")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload("grant_type=client_credentials".to_string())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("invalid_target"),
        "only a repeated resource earns that code: {text}"
    );
}

// ---------------------------------------------------------------------------
// Sender constraining is orthogonal
// ---------------------------------------------------------------------------

/// RFC 9449 binds a token to a **key**; RFC 8707 addresses it at a **resource**.
/// They answer different questions, and a token for an MCP server should carry
/// both — T7 recommends exactly that posture, so it has to work.
#[actix_rt::test]
async fn a_dpop_bound_token_carries_both_the_confirmation_and_the_resource() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, client) = register!(
        app,
        f,
        json!({
            "name": "mcp-rp",
            "redirect_uris": [REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid"],
            "allowed_resources": [MCP],
            "dpop_bound_access_tokens": true,
        })
    );
    assert_eq!(status, 201, "{client}");
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();
    let challenge = pkce_challenge(VERIFIER);

    let (_, location, _) = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={REDIRECT}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256&resource={MCP}"
        )
    );
    let code = code_from(&location.unwrap());

    let key = proof_key();
    let proof = dpop_proof(&key, "POST", &format!("{ISSUER}/oauth2/token"));
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={}", f.tenant_id))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", proof))
        .set_payload(format!(
            "grant_type=authorization_code&code={code}&redirect_uri={REDIRECT}\
             &client_id={client_id}&client_secret={secret}&code_verifier={VERIFIER}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let tokens: Value = test::read_body_json(resp).await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        tokens["token_type"], "DPoP",
        "a bound token is announced as one (RFC 9449 section 5): {tokens}"
    );

    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        aud_of(access),
        MCP,
        "the resource still decides the audience"
    );
    let payload = URL_SAFE_NO_PAD
        .decode(access.split('.').nth(1).unwrap())
        .unwrap();
    let claims: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        claims["cnf"]["jkt"].as_str(),
        Some(key.jkt.as_str()),
        "and the key still decides who may present it: {claims}"
    );
}

/// An Ed25519 keypair, its public JWK, and that JWK's RFC 7638 thumbprint.
struct ProofKey {
    encoding: jsonwebtoken::EncodingKey,
    jwk: Value,
    jkt: String,
}

fn proof_key() -> ProofKey {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate Ed25519");
    let encoding = jsonwebtoken::EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes())
        .expect("encoding key");
    let spki = kp.public_key_raw();
    let x = URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
    let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk.clone()).expect("a well-formed OKP JWK");
    let jkt = axiam_oauth2::jose::jwk_thumbprint(&parsed).expect("thumbprint");
    ProofKey { encoding, jwk, jkt }
}

/// A DPoP proof for the token endpoint (RFC 9449 §4.2). No `ath`: that claim
/// binds a proof to a token being *presented*, and this one accompanies the
/// request that mints one.
fn dpop_proof(key: &ProofKey, htm: &str, htu: &str) -> String {
    let header: jsonwebtoken::Header = serde_json::from_value(json!({
        "typ": axiam_oauth2::dpop::DPOP_TYP,
        "alg": "EdDSA",
        "jwk": key.jwk,
    }))
    .expect("proof header");
    let claims = json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    jsonwebtoken::encode(&header, &claims, &key.encoding).expect("sign the proof")
}
