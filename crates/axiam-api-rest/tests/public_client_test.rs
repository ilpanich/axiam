//! T21.2 — public clients (`token_endpoint_auth_method: none`) and the
//! RFC 8252 §7.3 loopback redirect allowance.
//!
//! The two halves are one feature: a desktop MCP client (Claude Code, VS Code,
//! MCP Inspector) holds no secret *and* listens on a port the operating system
//! picks. Either gap alone makes it unable to complete a code flow against
//! AXIAM, so both are tested here against the real HTTP layer.
//!
//! What every test in this file is ultimately asking is whether "public" has
//! stayed a **registration decision**:
//!
//! * a client registered for `none` authenticates by presenting nothing, and
//!   is refused if it presents anything (`a_public_client_may_not_present_a_secret`);
//! * a client registered for a credential that presents nothing stays
//!   `invalid_client` — invariant I4, the whole reason the new arm is keyed on
//!   the registration rather than on an absent parameter
//!   (`i4_a_confidential_client_that_omits_its_secret_is_still_refused`);
//! * nothing can move a client across that line after the fact
//!   (`the_auth_method_may_not_be_patched_across_the_public_line`);
//! * and the grants that rest on a client credential are refused to public
//!   clients at registration *and* at request time.
//!
//! The loopback tests pin the other direction: the allowance widens the port
//! and nothing else, and it never reaches an `https` registration (I6).

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
/// The two desktop clients this work exists for, as they actually register.
/// VS Code takes the literal address, Claude Code takes the name; T21.2 keeps
/// them distinct rather than treating one as the other.
const VSCODE_REDIRECT: &str = "http://127.0.0.1/callback";
const CLAUDE_CODE_REDIRECT: &str = "http://localhost/callback";
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
        oauth2_issuer_url: "https://localhost".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    admin_token: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.2 Org".into(),
            slug: "org-t21-2".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "T21.2 Tenant".into(),
            slug: "tenant-t21-2".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            // Generated, not written down. Nothing in this file signs in with
            // it — the admin token below is minted directly — so a literal
            // would be a credential in the tree buying nothing, which is
            // exactly what CodeQL's `hard-coded cryptographic value` rule is
            // right to ask about even in a test.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let admin_token = issue_access_token(
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
        admin_token,
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

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// `POST /api/v1/oauth2-clients` with whatever body the caller wants, so the
/// refusals can be asserted on the same path the happy case takes.
async fn register(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    body: Value,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn public_client_body(name: &str, redirect_uri: &str) -> Value {
    json!({
        "name": name,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "token_endpoint_auth_method": "none",
    })
}

/// Register a public client and return its `client_id`, asserting on the way
/// through that the response carried no secret.
async fn register_public(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    name: &str,
    redirect_uri: &str,
) -> String {
    let (status, body) = register(app, token, public_client_body(name, redirect_uri)).await;
    assert_eq!(status, 201, "public registration must succeed: {body}");
    assert!(
        body.get("client_secret").is_none(),
        "a public client has no secret to show; got {body}"
    );
    body["client_id"].as_str().unwrap().to_owned()
}

/// `GET /oauth2/authorize`, returning the `Location` header of the 302 (or the
/// status and error body when it is not one).
async fn authorize(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: Option<&str>,
) -> Result<String, (u16, Value)> {
    let mut uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&scope=openid"
    );
    if let Some(ch) = code_challenge {
        uri.push_str(&format!("&code_challenge={ch}&code_challenge_method=S256"));
    }
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    if status != 302 {
        let body = test::read_body(resp).await;
        return Err((status, serde_json::from_slice(&body).unwrap_or(Value::Null)));
    }
    Ok(resp
        .headers()
        .get("Location")
        .expect("a 302 carries a Location")
        .to_str()
        .unwrap()
        .to_owned())
}

fn code_from(location: &str) -> String {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("no code in {location}"))
}

/// `POST /oauth2/token`, form-encoded, returning `(status, body)`.
async fn token(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    tenant_id: Uuid,
    form: &str,
) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form.to_owned())
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_public_registration_mints_no_secret_and_returns_none() {
    let f = setup().await;
    let app = test_app!(f);

    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    // The stored row must hold no hash either — "no secret" is a fact about
    // the database, not a field omitted from one response.
    let mut result = f
        .db
        .query("SELECT client_secret_hash, token_endpoint_auth_method FROM oauth2_client WHERE client_id = $c")
        .bind(("c", client_id))
        .await
        .unwrap();
    let rows: Vec<Value> = result.take(0).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["client_secret_hash"].as_str(), Some(""));
    assert_eq!(rows[0]["token_endpoint_auth_method"].as_str(), Some("none"));
}

#[actix_rt::test]
async fn a_confidential_registration_still_shows_its_secret() {
    // I1's registration half: nothing about the default path changes.
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "confidential-rp",
            "redirect_uris": ["https://rp.example/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201);
    assert!(
        body["client_secret"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "a confidential client is still shown its secret exactly once; got {body}"
    );
}

#[actix_rt::test]
async fn a_public_client_may_not_hold_a_credential_bearing_grant() {
    let f = setup().await;
    let app = test_app!(f);

    for grant in [
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ] {
        let (status, body) = register(
            &app,
            &f.admin_token,
            json!({
                "name": format!("public-{grant}"),
                "redirect_uris": [VSCODE_REDIRECT],
                "grant_types": ["authorization_code", grant],
                "scopes": ["openid"],
                "token_endpoint_auth_method": "none",
            }),
        )
        .await;
        assert_eq!(
            status, 400,
            "a public client must not be registrable for {grant}; got {body}"
        );
    }
}

#[actix_rt::test]
async fn i5_a_fapi2_client_may_not_be_public() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "fapi-public",
            "redirect_uris": ["https://rp.example/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
            "token_endpoint_auth_method": "none",
            "profile": "fapi2",
            "require_par": true,
            "tls_client_certificate_bound_access_tokens": true,
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "FAPI 2.0 §5.3.1.1 admits only the two strong families; got {body}"
    );
}

#[actix_rt::test]
async fn a_public_client_may_not_also_register_a_credential() {
    let f = setup().await;
    let app = test_app!(f);

    for extra in [
        json!({"tls_client_auth_subject_dn": "CN=rp"}),
        json!({"self_signed_tls_client_auth_thumbprints":
               ["E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"]}),
        json!({"jwks_uri": "https://rp.example/jwks.json"}),
        json!({"jwks": "{\"keys\":[]}"}),
    ] {
        let mut body = public_client_body("public-with-credential", VSCODE_REDIRECT);
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (status, resp) = register(&app, &f.admin_token, body).await;
        assert_eq!(
            status, 400,
            "`none` plus {extra} is two answers to one question; got {resp}"
        );
    }
}

#[actix_rt::test]
async fn the_auth_method_may_not_be_patched_across_the_public_line() {
    // I4 — a confidential client cannot become public (nor the reverse) by an
    // update, because the secret cannot follow the change.
    let f = setup().await;
    let app = test_app!(f);

    let (status, confidential) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "confidential-rp",
            "redirect_uris": ["https://rp.example/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201);
    let confidential_id = confidential["id"].as_str().unwrap().to_owned();

    let (status, public) = register(
        &app,
        &f.admin_token,
        public_client_body("public-rp", VSCODE_REDIRECT),
    )
    .await;
    assert_eq!(status, 201);
    let public_id = public["id"].as_str().unwrap().to_owned();

    for (id, method) in [(confidential_id, "none"), (public_id, "client_secret_post")] {
        let req = test::TestRequest::put()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/api/v1/oauth2-clients/{id}"))
            .insert_header(("Authorization", format!("Bearer {}", f.admin_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(json!({ "token_endpoint_auth_method": method }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "moving a client to {method} must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_public_client_completes_a_code_and_pkce_flow_with_no_secret() {
    let f = setup().await;
    let app = test_app!(f);
    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    // The ephemeral port the operating system handed the client. It is not the
    // one that was registered, and that is the point.
    let presented_redirect = "http://127.0.0.1:51703/callback";
    let location = authorize(
        &app,
        &f.admin_token,
        &client_id,
        presented_redirect,
        Some(&pkce_challenge(VERIFIER)),
    )
    .await
    .expect("authorize must redirect");
    assert!(
        location.starts_with(presented_redirect),
        "the code goes back to the URI that was actually used: {location}"
    );
    let code = code_from(&location);

    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={presented_redirect}\
             &client_id={client_id}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(
        status, 200,
        "a public client redeems with no secret: {body}"
    );
    assert!(body["access_token"].as_str().is_some());
    let refresh = body["refresh_token"]
        .as_str()
        .expect("the refresh grant was registered")
        .to_owned();

    // And it can refresh with no secret either — a desktop client that could
    // not would be signed out every fifteen minutes.
    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!("grant_type=refresh_token&refresh_token={refresh}&client_id={client_id}"),
    )
    .await;
    assert_eq!(status, 200, "a public client may refresh: {body}");
}

#[actix_rt::test]
async fn a_public_client_may_not_present_a_secret() {
    let f = setup().await;
    let app = test_app!(f);
    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    let location = authorize(
        &app,
        &f.admin_token,
        &client_id,
        VSCODE_REDIRECT,
        Some(&pkce_challenge(VERIFIER)),
    )
    .await
    .expect("authorize");
    let code = code_from(&location);

    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={VSCODE_REDIRECT}\
             &client_id={client_id}&client_secret=anything-at-all&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, 401, "got {body}");
    assert_eq!(body["error"].as_str(), Some("invalid_client"));
}

#[actix_rt::test]
async fn i4_a_confidential_client_that_omits_its_secret_is_still_refused() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "confidential-rp",
            "redirect_uris": ["https://rp.example/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201);
    let client_id = body["client_id"].as_str().unwrap().to_owned();

    let location = authorize(
        &app,
        &f.admin_token,
        &client_id,
        "https://rp.example/callback",
        None,
    )
    .await
    .expect("authorize");
    let code = code_from(&location);

    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=https://rp.example/callback&client_id={client_id}"
        ),
    )
    .await;
    assert_eq!(
        status, 401,
        "a client_secret_post client that omits its secret stays invalid_client (I4); got {body}"
    );
    assert_eq!(body["error"].as_str(), Some("invalid_client"));

    // The unknown-client answer is the same one, which is what keeps client
    // existence undecidable from a credential-less request (SEC-086).
    let (unknown_status, unknown_body) = token(
        &app,
        f.tenant_id,
        "grant_type=authorization_code&code=whatever\
         &redirect_uri=https://rp.example/callback&client_id=oa_no_such_client",
    )
    .await;
    assert_eq!(unknown_status, status);
    assert_eq!(unknown_body["error"], body["error"]);
    assert_eq!(
        unknown_body["error_description"], body["error_description"],
        "the two must be indistinguishable"
    );
}

#[actix_rt::test]
async fn a_public_client_must_use_pkce_at_the_authorization_endpoint() {
    let f = setup().await;
    let app = test_app!(f);
    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    // RFC 6749 §4.1.2.1: the refusal is redirectable, because it is found
    // after `redirect_uri` has been validated. The client learns of it the way
    // it learns of every other authorization error — in the query string of
    // its own callback — which is what a browser-driven client can actually
    // read.
    let location = authorize(&app, &f.admin_token, &client_id, VSCODE_REDIRECT, None)
        .await
        .expect("the refusal is delivered as a redirect");
    let url = url::Url::parse(&location).unwrap();
    let error = url
        .query_pairs()
        .find(|(k, _)| k == "error")
        .map(|(_, v)| v.into_owned());
    assert_eq!(
        error.as_deref(),
        Some("invalid_request"),
        "a public client without code_challenge is refused: {location}"
    );
    assert!(
        !location.contains("code="),
        "and no code is issued: {location}"
    );
}

#[actix_rt::test]
async fn a_code_without_a_challenge_cannot_be_redeemed_by_a_public_client() {
    // The authorization endpoint refuses to mint such a code for a public
    // client, so the only way to hold one is to have been confidential when it
    // was issued. The registration is flipped in the database rather than
    // through the API — which refuses exactly this move — because the point of
    // the token-endpoint gate is to answer for the rows the API cannot reach.
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "was-confidential",
            "redirect_uris": [VSCODE_REDIRECT],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201);
    let client_id = body["client_id"].as_str().unwrap().to_owned();
    let client_secret = body["client_secret"].as_str().unwrap().to_owned();

    let location = authorize(&app, &f.admin_token, &client_id, VSCODE_REDIRECT, None)
        .await
        .expect("a confidential client may skip PKCE");
    let code = code_from(&location);

    f.db.query(
        "UPDATE oauth2_client SET token_endpoint_auth_method = 'none', \
         client_secret_hash = '' WHERE client_id = $c",
    )
    .bind(("c", client_id.clone()))
    .await
    .expect("flip the registration");

    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={VSCODE_REDIRECT}\
             &client_id={client_id}"
        ),
    )
    .await;
    assert_eq!(status, 400, "got {body}");
    assert_eq!(
        body["error"].as_str(),
        Some("invalid_grant"),
        "a code carrying no PKCE challenge is not redeemable by a public client: {body}"
    );

    // And the secret it used to hold is no help either.
    let (status, _) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={VSCODE_REDIRECT}\
             &client_id={client_id}&client_secret={client_secret}"
        ),
    )
    .await;
    assert_eq!(status, 401, "the public arm refuses a presented credential");
}

#[actix_rt::test]
async fn a_public_client_may_not_introspect() {
    let f = setup().await;
    let app = test_app!(f);
    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/introspect?tenant_id={}", f.tenant_id))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(format!("token=whatever&client_id={client_id}"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "RFC 7662 §2.1 requires an authenticated caller"
    );
}

// ---------------------------------------------------------------------------
// RFC 8252 §7.3 — the loopback allowance
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn each_loopback_host_accepts_any_port_and_only_itself() {
    let f = setup().await;
    let app = test_app!(f);
    let challenge = pkce_challenge(VERIFIER);

    // Claude Code's registration: the name, not the address.
    let claude = register_public(&app, &f.admin_token, "claude-code", CLAUDE_CODE_REDIRECT).await;
    assert!(
        authorize(
            &app,
            &f.admin_token,
            &claude,
            "http://localhost:62119/callback",
            Some(&challenge)
        )
        .await
        .is_ok(),
        "a registered localhost URI accepts an ephemeral port"
    );
    assert!(
        authorize(
            &app,
            &f.admin_token,
            &claude,
            "http://127.0.0.1:62119/callback",
            Some(&challenge)
        )
        .await
        .is_err(),
        "`127.0.0.1` is not `localhost`: each client registers what it uses"
    );

    // VS Code's: the address, not the name.
    let vscode = register_public(&app, &f.admin_token, "vscode", VSCODE_REDIRECT).await;
    assert!(
        authorize(
            &app,
            &f.admin_token,
            &vscode,
            "http://127.0.0.1:33445/callback",
            Some(&challenge)
        )
        .await
        .is_ok()
    );
    for refused in [
        "http://localhost:33445/callback",
        "http://127.0.0.1:33445/callback/",
        "http://127.0.0.1:33445/callback?next=https://evil.example",
        "http://127.0.0.2:33445/callback",
        "https://127.0.0.1:33445/callback",
    ] {
        assert!(
            authorize(&app, &f.admin_token, &vscode, refused, Some(&challenge))
                .await
                .is_err(),
            "the allowance widens the port and nothing else: {refused} must be refused"
        );
    }
}

#[actix_rt::test]
async fn i6_an_https_registration_keeps_exact_matching() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = register(
        &app,
        &f.admin_token,
        json!({
            "name": "https-rp",
            "redirect_uris": ["https://rp.example/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201);
    let client_id = body["client_id"].as_str().unwrap().to_owned();

    assert!(
        authorize(
            &app,
            &f.admin_token,
            &client_id,
            "https://rp.example:8443/callback",
            None
        )
        .await
        .is_err(),
        "an https registration does not take the port allowance (I6)"
    );
    assert!(
        authorize(
            &app,
            &f.admin_token,
            &client_id,
            "https://rp.example/callback",
            None
        )
        .await
        .is_ok(),
        "and it still matches itself"
    );
}

#[actix_rt::test]
async fn the_token_request_must_name_the_uri_the_code_was_issued_to() {
    // The code stores the PRESENTED URI, so the token endpoint's comparison
    // stays exact: a client that authorized on port 51703 cannot redeem on
    // 51704, even though both would have been accepted at authorize.
    let f = setup().await;
    let app = test_app!(f);
    let client_id = register_public(&app, &f.admin_token, "public-rp", VSCODE_REDIRECT).await;

    let location = authorize(
        &app,
        &f.admin_token,
        &client_id,
        "http://127.0.0.1:51703/callback",
        Some(&pkce_challenge(VERIFIER)),
    )
    .await
    .expect("authorize");
    let code = code_from(&location);

    let (status, body) = token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=http://127.0.0.1:51704/callback\
             &client_id={client_id}&code_verifier={VERIFIER}"
        ),
    )
    .await;
    assert_eq!(status, 400, "got {body}");
    assert_eq!(body["error"].as_str(), Some("invalid_grant"));
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn discovery_advertises_the_public_method_last() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let doc: Value = test::read_body_json(resp).await;
    let methods: Vec<&str> = doc["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        methods.last(),
        Some(&"none"),
        "advertised, and last: the order is the operator's recommendation"
    );
}
