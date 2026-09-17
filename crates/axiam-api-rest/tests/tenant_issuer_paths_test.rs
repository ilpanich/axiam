//! T21.6 — per-tenant path issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS`).
//!
//! RFC 8414 §2 forbids a query in an issuer identifier, so `{root}` plus
//! `?tenant_id=` cannot be published as one tenant's issuer and an MCP server
//! fronting a multi-tenant AXIAM had no issuer to name in its RFC 9728
//! `authorization_servers`. `{root}/t/{tenant_id}` is one. This file is where
//! that form is held to three things:
//!
//! 1. **It does not weaken tenant isolation.** A path is a selector a caller
//!    chooses, and the JWKS is shared — one key set signs every tenant — so a
//!    token minted for tenant `A` verifies perfectly on a request addressed to
//!    tenant `B`. Every test under "Tenant isolation" below is one shape of
//!    that attack, and they come first because they are the reason this feature
//!    needed an Opus session rather than a route alias.
//! 2. **The three discovery forms agree**, and every `iss` a request mints —
//!    access token, ID token, logout token, RFC 9207 response parameter —
//!    equals the `issuer` those documents publish. OIDC Core §2 requires the
//!    match and RFC 9207 makes a client check it, so an `iss` that disagreed
//!    would be a feature that discovers correctly and then fails to log in.
//! 3. **With the flag off it does not exist.** Not "exists and 404s" — the
//!    routes are not mounted, and the documents the deployment already served
//!    are byte-identical (I1, and T1's own assertion re-run here in both
//!    modes).

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, SessionClientRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealSessionClientRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const ROOT_ISSUER: &str = "https://localhost";
const REDIRECT_URI: &str = "https://rp.test.example/callback";
const VERIFIER: &str = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4.1";

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

// Test-only Ed25519 keypair with no real-world value. nosemgrep
fn test_auth_config(tenant_issuer_paths: bool) -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        tenant_issuer_paths,
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

/// One tenant's worth of fixture: the tenant, a user in it, an access token for
/// that user, and a public client registered for the code grant.
struct Tenant {
    id: Uuid,
    user_id: Uuid,
    token: String,
    client_id: String,
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    org_id: Uuid,
    a: Tenant,
    b: Tenant,
}

impl Fixture {
    fn issuer_of(&self, tenant_id: Uuid) -> String {
        format!("{ROOT_ISSUER}/t/{tenant_id}")
    }
}

fn public_client(tenant_id: Uuid, name: &str, backchannel: Option<String>) -> CreateOAuth2Client {
    CreateOAuth2Client {
        tenant_id,
        name: name.into(),
        redirect_uris: vec![REDIRECT_URI.into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["openid".into(), "profile".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: backchannel,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: ClientAuthMethod::None,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: vec![],
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: AuthnRequestParamsMode::Ignore,
        browser_sso: false,
        allowed_resources: Vec::new(),
    }
}

async fn setup_tenant(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    org_id: Uuid,
    slug: &str,
    backchannel: Option<String>,
) -> Tenant {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("T21.6 {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("user-{slug}"),
            email: format!("user-{slug}@example.com"),
            // Generated rather than written down: nothing here signs in with
            // it, so a literal would be a credential in the tree buying
            // nothing.
            password: format!("pw-{}", Uuid::new_v4()),
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
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (client, _) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(public_client(tenant.id, &format!("rp-{slug}"), backchannel))
        .await
        .unwrap();

    // Minted under the deployment ROOT issuer, deliberately: it stands in for
    // the session cookie a browser carries to `/oauth2/authorize`, and a
    // browser's AXIAM session is not tenant-path-scoped. That it is accepted on
    // a tenant path is itself part of what T21.6 promises — the extractors
    // accept the root issuer AND any `{root}/t/{uuid}`.
    let token = issue_access_token(
        user.id,
        tenant.id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    Tenant {
        id: tenant.id,
        user_id: user.id,
        token,
        client_id: client.client_id,
    }
}

async fn setup_with(backchannel: Option<String>) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.6 Org".into(),
            slug: "org-t21-6".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config(true);
    let a = setup_tenant(&db, &auth, org.id, "tenant-a", backchannel).await;
    let b = setup_tenant(&db, &auth, org.id, "tenant-b", None).await;

    Fixture {
        db,
        auth,
        org_id: org.id,
        a,
        b,
    }
}

async fn setup() -> Fixture {
    setup_with(None).await
}

/// The app, with the flag in whichever position the test is about.
///
/// `$paths` is the *only* difference between the two modes — one boolean on
/// `RouteOptions`, which is exactly the shape the "with it off nothing exists"
/// tests need in order to prove anything.
macro_rules! test_app {
    ($f:expr, $paths:expr) => {{
        let auth = test_auth_config($paths);
        test::init_service(
            App::new()
                .app_data(web::Data::new(auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &RateLimitConfig::default(),
                        RouteOptions {
                            tenant_issuer_paths: $paths,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
    ($f:expr) => {
        test_app!($f, true)
    };
}

/// The bound every helper below takes, spelled once. `impl Trait` rather than a
/// `dyn` alias because `test::init_service` returns an opaque type whose
/// `Future` associated type cannot be named.
macro_rules! app_svc {
    () => {
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >
    };
}

async fn get(app: &app_svc!(), uri: &str) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .to_request();
    test::call_service(app, req).await
}

async fn get_with_bearer(
    app: &app_svc!(),
    uri: &str,
    token: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    test::call_service(app, req).await
}

async fn post_form(app: &app_svc!(), uri: &str, form: &str) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form.to_owned())
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// The `iss` of a JWT, read without verifying anything — this file asserts on
/// the claim's *value*, and the signature is what every other test in the
/// repository already covers.
fn iss_of(jwt: &str) -> String {
    claims_of(jwt)["iss"].as_str().unwrap().to_owned()
}

fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

/// Drive a full code + PKCE flow on `base` (either `""` for the deployment-wide
/// endpoints or `/t/{tenant}` for the T21.6 form) and return the token
/// response.
async fn code_flow(app: &app_svc!(), base: &str, tenant: &Tenant) -> Value {
    let challenge = pkce_challenge(VERIFIER);
    let tenant_query = if base.is_empty() {
        format!("&tenant_id={}", tenant.id)
    } else {
        String::new()
    };
    let authorize_uri = format!(
        "{base}/oauth2/authorize?response_type=code&client_id={}\
         &redirect_uri={REDIRECT_URI}&scope=openid&state=xyz\
         &code_challenge={challenge}&code_challenge_method=S256{tenant_query}",
        tenant.client_id
    );
    let resp = get_with_bearer(app, &authorize_uri, &tenant.token).await;
    assert_eq!(
        resp.status().as_u16(),
        302,
        "authorize must redirect with a code on {authorize_uri}"
    );
    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let code = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| panic!("no code in {location}"));

    let token_uri = if base.is_empty() {
        format!("/oauth2/token?tenant_id={}", tenant.id)
    } else {
        format!("{base}/oauth2/token")
    };
    let (status, body) = post_form(
        app,
        &token_uri,
        &format!(
            "grant_type=authorization_code&code={code}&client_id={}\
             &redirect_uri={REDIRECT_URI}&code_verifier={VERIFIER}",
            tenant.client_id
        ),
    )
    .await;
    assert_eq!(status, 200, "token exchange must succeed: {body}");
    body
}

// ---------------------------------------------------------------------------
// Tenant isolation — the tests this feature exists to survive
// ---------------------------------------------------------------------------

/// The headline. One key set signs every tenant's tokens (the JWKS is shared,
/// and the deployment documentation says so), so nothing about the *signature*
/// of a tenant-`A` token distinguishes it from a tenant-`B` one. If the path
/// were merely a routing prefix, presenting `A`'s token under `/t/{B}` would be
/// a cross-tenant authorization primitive handed to anyone who can read a URL.
#[actix_rt::test]
async fn a_token_minted_under_one_tenant_path_is_refused_by_another() {
    let f = setup().await;
    let app = test_app!(f);

    let tokens = code_flow(&app, &format!("/t/{}", f.a.id), &f.a).await;
    let access_token = tokens["access_token"].as_str().unwrap();

    // Sanity: it works where it belongs. A test that only asserts the refusal
    // passes just as well against a feature that refuses everything.
    let own = get_with_bearer(
        &app,
        &format!("/t/{}/oauth2/userinfo", f.a.id),
        access_token,
    )
    .await;
    assert_eq!(
        own.status().as_u16(),
        200,
        "a tenant-A token must work on tenant A's path"
    );

    let foreign = get_with_bearer(
        &app,
        &format!("/t/{}/oauth2/userinfo", f.b.id),
        access_token,
    )
    .await;
    assert_eq!(
        foreign.status().as_u16(),
        401,
        "a tenant-A token presented on tenant B's path must be refused"
    );
}

/// The same refusal on the other carrier RFC 6750 defines. `POST
/// /oauth2/userinfo` authenticates from the request **body** (§2.2) through a
/// different code path from the extractor, which is exactly how a check added
/// in one place comes to be missing in the other.
#[actix_rt::test]
async fn the_refusal_also_holds_for_a_body_carried_token() {
    let f = setup().await;
    let app = test_app!(f);

    let tokens = code_flow(&app, &format!("/t/{}", f.a.id), &f.a).await;
    let access_token = tokens["access_token"].as_str().unwrap();

    let (status, _) = post_form(
        &app,
        &format!("/t/{}/oauth2/userinfo", f.b.id),
        &format!("access_token={access_token}"),
    )
    .await;
    assert_eq!(
        status, 401,
        "a body-carried tenant-A token must be refused on tenant B's path"
    );
}

/// Two tenant selectors on one request is the shape a confused-deputy bug
/// takes: one component reads the path, another reads the query, and they
/// answer differently. Refused outright — including when they agree, because a
/// rule with an exception is a rule somebody gets wrong.
#[actix_rt::test]
async fn a_tenant_id_query_on_a_tenant_path_is_refused_agreeing_or_not() {
    let f = setup().await;
    let app = test_app!(f);

    for (label, query_tenant) in [("disagreeing", f.b.id), ("agreeing", f.a.id)] {
        let resp = get(
            &app,
            &format!(
                "/t/{}/oauth2/authorize?client_id={}&tenant_id={query_tenant}",
                f.a.id, f.a.client_id
            ),
        )
        .await;
        assert_eq!(
            resp.status().as_u16(),
            400,
            "a {label} tenant_id query on a tenant path must be refused"
        );
        let body = test::read_body(resp).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"], "invalid_request",
            "the refusal must be an OAuth2 error object, not actix prose"
        );
    }
}

/// Also on the token endpoint, whose tenant arrives in the query on the
/// deployment-wide form — so this is the endpoint where a caller is most likely
/// to send one out of habit.
#[actix_rt::test]
async fn a_tenant_id_query_on_the_tenant_token_endpoint_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = post_form(
        &app,
        &format!("/t/{}/oauth2/token?tenant_id={}", f.a.id, f.b.id),
        "grant_type=refresh_token&refresh_token=whatever",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
}

/// Decided from the path alone, with no repository read: `not-a-uuid` is
/// refused for being the wrong shape, not for naming a tenant that does not
/// exist. Traversal spellings land here too — there is no normalisation step to
/// defeat, because nothing but a UUID is accepted in the first place.
#[actix_rt::test]
async fn a_malformed_tenant_segment_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    for segment in ["not-a-uuid", "..", "%2e%2e", "00000000", ""] {
        let resp = get(
            &app,
            &format!("/t/{segment}/.well-known/openid-configuration"),
        )
        .await;
        assert!(
            matches!(resp.status().as_u16(), 400 | 404),
            "`/t/{segment}/…` must be refused, got {}",
            resp.status()
        );
        assert_ne!(
            resp.status().as_u16(),
            200,
            "`/t/{segment}/…` must never be served a document"
        );
    }
}

/// Discovery is public and unauthenticated. A `404` for an unknown-but-
/// well-formed tenant would make the path a tenant-enumeration oracle, so an
/// unknown tenant gets exactly what `?tenant_id=<unknown>` gets today: the
/// document, and a refusal only when a credential-taking endpoint is reached.
#[actix_rt::test]
async fn an_unknown_tenant_is_not_an_enumeration_oracle() {
    let f = setup().await;
    let app = test_app!(f);
    let unknown = Uuid::new_v4();

    let known = get(
        &app,
        &format!("/t/{}/.well-known/openid-configuration", f.a.id),
    )
    .await;
    let unknown_resp = get(
        &app,
        &format!("/t/{unknown}/.well-known/openid-configuration"),
    )
    .await;
    assert_eq!(
        known.status(),
        unknown_resp.status(),
        "a known and an unknown tenant must be indistinguishable at discovery"
    );

    // And the token endpoint answers the same for an unknown tenant on the path
    // as it does for one in the query — the refusal is the client lookup's, not
    // the path's.
    let (path_status, path_body) = post_form(
        &app,
        &format!("/t/{unknown}/oauth2/token"),
        &format!(
            "grant_type=authorization_code&code=nope&client_id={}&redirect_uri={REDIRECT_URI}",
            f.a.client_id
        ),
    )
    .await;
    let (query_status, query_body) = post_form(
        &app,
        &format!("/oauth2/token?tenant_id={unknown}"),
        &format!(
            "grant_type=authorization_code&code=nope&client_id={}&redirect_uri={REDIRECT_URI}",
            f.a.client_id
        ),
    )
    .await;
    assert_eq!(path_status, query_status);
    assert_eq!(path_body, query_body);
}

/// A caller who holds a valid token for a tenant they are in, reaching for a
/// tenant they are not in. Distinct from the first test only in intent, and
/// worth its own name: this is the "no access" shape rather than the
/// "wrong-tenant token" shape, and both must land on the same answer.
#[actix_rt::test]
async fn a_tenant_the_caller_has_no_access_to_answers_the_same_as_no_credential() {
    let f = setup().await;
    let app = test_app!(f);

    let with_foreign_token =
        get_with_bearer(&app, &format!("/t/{}/oauth2/userinfo", f.b.id), &f.a.token).await;
    let with_nothing = get(&app, &format!("/t/{}/oauth2/userinfo", f.b.id)).await;

    assert_eq!(with_foreign_token.status().as_u16(), 401);
    assert_eq!(
        with_foreign_token.status(),
        with_nothing.status(),
        "holding tenant A's token must tell the caller nothing about tenant B"
    );
}

/// The token-level half of the same isolation. `iss` and `tenant_id` are two
/// answers to "which tenant is this?", and the shared JWKS means a forged
/// pairing would verify. They are required to agree.
#[actix_rt::test]
async fn a_token_whose_issuer_names_another_tenant_than_its_tenant_id_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    // Minted with tenant B's *issuer* but tenant A's `tenant_id` claim — the
    // pairing an attacker would want if either claim alone decided the tenant.
    let mismatched = issue_access_token(
        f.a.user_id,
        f.a.id,
        f.org_id,
        &[],
        &f.auth.for_tenant_path(f.b.id).expect("tenant paths are on"),
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    assert_eq!(iss_of(&mismatched), f.issuer_of(f.b.id));
    assert_eq!(claims_of(&mismatched)["tenant_id"], f.a.id.to_string());

    for path in [
        format!("/t/{}/oauth2/userinfo", f.a.id),
        format!("/t/{}/oauth2/userinfo", f.b.id),
        "/oauth2/userinfo".to_owned(),
    ] {
        let resp = get_with_bearer(&app, &path, &mismatched).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "a token whose iss and tenant_id disagree must be refused at {path}"
        );
    }
}

/// The widening the extractors DID take: the root issuer and any
/// `{root}/t/{uuid}` are both accepted, and the JWKS behind them is one key set.
#[actix_rt::test]
async fn the_root_issuer_and_a_tenant_issuer_are_both_accepted() {
    let f = setup().await;
    let app = test_app!(f);

    let root_minted = &f.a.token;
    assert_eq!(iss_of(root_minted), ROOT_ISSUER);
    let tenant_minted = issue_access_token(
        f.a.user_id,
        f.a.id,
        f.org_id,
        &[],
        &f.auth.for_tenant_path(f.a.id).expect("tenant paths are on"),
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    assert_eq!(iss_of(&tenant_minted), f.issuer_of(f.a.id));

    for token in [root_minted.as_str(), tenant_minted.as_str()] {
        for path in [
            "/oauth2/userinfo",
            &format!("/t/{}/oauth2/userinfo", f.a.id),
        ] {
            let resp = get_with_bearer(&app, path, token).await;
            assert_eq!(
                resp.status().as_u16(),
                200,
                "issuer {} must be accepted at {path}",
                iss_of(token)
            );
        }
    }
}

/// "One key set, many issuers" is a claim the deployment documentation makes to
/// operators; this is the assertion behind it.
#[actix_rt::test]
async fn the_jwks_is_one_document_under_every_issuer() {
    let f = setup().await;
    let app = test_app!(f);

    let root = test::read_body(get(&app, "/oauth2/jwks").await).await;
    let under_a = test::read_body(get(&app, &format!("/t/{}/oauth2/jwks", f.a.id)).await).await;
    let under_b = test::read_body(get(&app, &format!("/t/{}/oauth2/jwks", f.b.id)).await).await;

    assert_eq!(root, under_a);
    assert_eq!(root, under_b);
}

// ---------------------------------------------------------------------------
// The three discovery forms
// ---------------------------------------------------------------------------

/// RFC 8414 §3.1 *inserts* the well-known segment after the host; OIDC
/// Discovery 1.0 §4 *appends* it to the issuer. Clients disagree about which to
/// derive, so AXIAM serves all three — and they must be one document, not three
/// that happen to agree today.
#[actix_rt::test]
async fn the_three_discovery_forms_are_byte_identical() {
    let f = setup().await;
    let app = test_app!(f);
    let t = f.a.id;

    let forms = [
        format!("/.well-known/oauth-authorization-server/t/{t}"),
        format!("/.well-known/openid-configuration/t/{t}"),
        format!("/t/{t}/.well-known/openid-configuration"),
    ];

    let mut bodies = Vec::new();
    for form in &forms {
        let resp = get(&app, form).await;
        assert_eq!(resp.status().as_u16(), 200, "{form} must be served");
        bodies.push(test::read_body(resp).await);
    }
    assert_eq!(bodies[0], bodies[1], "{} vs {}", forms[0], forms[1]);
    assert_eq!(bodies[0], bodies[2], "{} vs {}", forms[0], forms[2]);
}

/// What the document must actually say: the tenant issuer, endpoints under it,
/// and **no** `tenant_id` anywhere — which is the whole point, since RFC 8414 §2
/// forbids a query in an issuer and a client derives the discovery URL from the
/// issuer it was given.
#[actix_rt::test]
async fn the_tenant_document_names_the_tenant_issuer_and_carries_no_tenant_id() {
    let f = setup().await;
    let app = test_app!(f);
    let t = f.a.id;
    let issuer = f.issuer_of(t);

    let body =
        test::read_body(get(&app, &format!("/t/{t}/.well-known/openid-configuration")).await).await;
    let raw = String::from_utf8(body.to_vec()).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();

    assert_eq!(doc["issuer"], issuer);
    for endpoint in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "revocation_endpoint",
        "introspection_endpoint",
        "device_authorization_endpoint",
        "pushed_authorization_request_endpoint",
        "end_session_endpoint",
    ] {
        let url = doc[endpoint].as_str().unwrap_or_else(|| {
            panic!("the document must carry {endpoint}");
        });
        assert!(
            url.starts_with(&format!("{issuer}/oauth2/")),
            "{endpoint} must live under the tenant issuer, got {url}"
        );
    }
    // `tenant_id=` rather than `tenant_id`: the bare name legitimately appears
    // in `claims_supported`, where it is a claim AXIAM can assert. What must
    // not appear anywhere is the QUERY — the form RFC 8414 §2 forbids in an
    // issuer and which this whole feature exists to replace.
    assert!(
        !raw.contains("tenant_id="),
        "no endpoint in a tenant-issuer document may carry a tenant_id query: {raw}"
    );
}

/// Every endpoint the tenant document advertises must be one the server
/// actually serves. A document that names a 404 is worse than no document: a
/// client follows it.
#[actix_rt::test]
async fn every_endpoint_the_tenant_document_advertises_is_routed() {
    let f = setup().await;
    let app = test_app!(f);
    let t = f.a.id;

    let body =
        test::read_body(get(&app, &format!("/t/{t}/.well-known/openid-configuration")).await).await;
    let doc: Value = serde_json::from_slice(&body).unwrap();

    for endpoint in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "revocation_endpoint",
        "introspection_endpoint",
        "device_authorization_endpoint",
        "pushed_authorization_request_endpoint",
        "end_session_endpoint",
    ] {
        let url = doc[endpoint].as_str().unwrap();
        let path = url.strip_prefix(ROOT_ISSUER).unwrap();
        // GET on every one of them: some answer 405 or 400, none may answer
        // 404, which is the only status that means "not routed".
        let resp = get(&app, path).await;
        assert_ne!(
            resp.status().as_u16(),
            404,
            "{endpoint} ({path}) is advertised but not routed"
        );
    }
}

// ---------------------------------------------------------------------------
// `iss` consistency
// ---------------------------------------------------------------------------

/// OIDC Core §2: the `iss` of every token must equal the `issuer` of the
/// discovery document the client read. A feature that discovers correctly and
/// then mints the wrong `iss` fails at the last step, in the client's validator,
/// where it is hardest to diagnose.
#[actix_rt::test]
async fn the_access_and_id_tokens_minted_on_a_tenant_path_carry_the_tenant_issuer() {
    let f = setup().await;
    let app = test_app!(f);
    let issuer = f.issuer_of(f.a.id);

    let tokens = code_flow(&app, &format!("/t/{}", f.a.id), &f.a).await;
    assert_eq!(iss_of(tokens["access_token"].as_str().unwrap()), issuer);
    assert_eq!(
        iss_of(tokens["id_token"].as_str().unwrap()),
        issuer,
        "the ID token is the one a relying party validates against the document"
    );

    // And the document agrees, read through the third discovery form.
    let doc: Value = serde_json::from_slice(
        &test::read_body(
            get(
                &app,
                &format!("/t/{}/.well-known/openid-configuration", f.a.id),
            )
            .await,
        )
        .await,
    )
    .unwrap();
    assert_eq!(doc["issuer"], issuer);
}

/// A refresh on the tenant path re-mints under the tenant issuer too. Worth its
/// own test because the refresh grant re-issues from a stored row rather than
/// from the request, which is how a request-scoped value gets lost.
#[actix_rt::test]
async fn a_refresh_on_the_tenant_path_keeps_the_tenant_issuer() {
    let f = setup().await;
    let app = test_app!(f);
    let issuer = f.issuer_of(f.a.id);

    let tokens = code_flow(&app, &format!("/t/{}", f.a.id), &f.a).await;
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("the code grant issues a refresh token");

    let (status, refreshed) = post_form(
        &app,
        &format!("/t/{}/oauth2/token", f.a.id),
        &format!(
            "grant_type=refresh_token&refresh_token={refresh_token}&client_id={}",
            f.a.client_id
        ),
    )
    .await;
    assert_eq!(status, 200, "refresh must succeed: {refreshed}");
    assert_eq!(iss_of(refreshed["access_token"].as_str().unwrap()), issuer);
}

/// RFC 9207 §2: the authorization response carries `iss` so a client can detect
/// a mix-up attack. A client that discovered `{root}/t/{T}` compares against
/// that, so the root issuer here would make every authorization fail — in the
/// one check that exists to stop an attack.
#[actix_rt::test]
async fn the_rfc_9207_iss_parameter_on_a_tenant_path_is_the_tenant_issuer() {
    let f = setup().await;
    let app = test_app!(f);

    let challenge = pkce_challenge(VERIFIER);
    let resp = get_with_bearer(
        &app,
        &format!(
            "/t/{}/oauth2/authorize?response_type=code&client_id={}\
             &redirect_uri={REDIRECT_URI}&scope=openid\
             &code_challenge={challenge}&code_challenge_method=S256",
            f.a.id, f.a.client_id
        ),
        &f.a.token,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    let iss = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "iss")
        .map(|(_, v)| v.into_owned())
        .expect("RFC 9207 iss is emitted on every authorization response");
    assert_eq!(iss, f.issuer_of(f.a.id));
}

/// Back-Channel Logout 1.0 §2.4 requires the logout token's `iss` to be the OP's
/// issuer, and the relying party validates it against the `issuer` of the
/// document it registered with. A wiremock RP is the only way to read the token
/// AXIAM actually sends.
#[actix_rt::test]
async fn the_logout_token_iss_is_the_tenant_issuer() {
    let rp = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/backchannel"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&rp)
        .await;

    let f = setup_with(Some(format!("{}/backchannel", rp.uri()))).await;
    let app = test_app!(f);

    // A live session with the RP recorded as a participant — the fan-out
    // iterates participation rows, so without one there is nothing to deliver.
    let session_id = SurrealSessionRepository::new(f.db.clone())
        .create(CreateSession {
            tenant_id: f.a.id,
            user_id: f.a.user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            authenticated_at: chrono::Utc::now(),
            amr: vec![],
            browser_token_hash: None,
        })
        .await
        .unwrap()
        .id;
    SurrealSessionClientRepository::new(f.db.clone())
        .record(axiam_core::models::oauth2_client::CreateSessionClient {
            tenant_id: f.a.id,
            session_id,
            client_id: f.a.client_id.clone(),
            user_id: f.a.user_id,
        })
        .await
        .unwrap();

    // The hint is a *signed* statement of which session and client; it is
    // minted under the tenant issuer because that is what a client that
    // authenticated on the tenant path holds.
    let hint = axiam_auth::token::issue_id_token(
        f.a.user_id,
        &f.a.client_id,
        None,
        None,
        &["openid".to_string()],
        &f.auth.for_tenant_path(f.a.id).expect("tenant paths are on"),
        Some(session_id),
        &axiam_auth::token::IdTokenEvidence::NONE,
    )
    .unwrap();

    let resp = get(
        &app,
        &format!("/t/{}/oauth2/end_session?id_token_hint={hint}", f.a.id),
    )
    .await;
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "end_session answered {}",
        resp.status()
    );

    // Delivery is detached and best-effort by design (§2.6), so it is polled
    // rather than awaited.
    let mut delivered = None;
    for _ in 0..40 {
        let requests = rp.received_requests().await.unwrap_or_default();
        if let Some(req) = requests.first() {
            delivered = Some(String::from_utf8(req.body.clone()).unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let body = delivered.expect("the RP must receive a back-channel logout");
    let logout_token = body
        .split('&')
        .find_map(|p| p.strip_prefix("logout_token="))
        .expect("the POST carries a logout_token");
    let logout_token = urlencoding_decode(logout_token);

    assert_eq!(
        iss_of(&logout_token),
        f.issuer_of(f.a.id),
        "the logout token must name the issuer the RP registered with"
    );
}

/// Minimal `application/x-www-form-urlencoded` value decoding — a JWT is
/// base64url, so only `%2E`-class escapes and `+` can appear.
fn urlencoding_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap()
}

// ---------------------------------------------------------------------------
// I1 — with the flag off, none of this exists
// ---------------------------------------------------------------------------

/// Not "mounted and answering 404 to a malformed tenant" — not mounted at all.
/// A route that exists is a route an operator finds in a log, a proxy is
/// configured for and a scanner reports on, and an off-by-default feature that
/// leaves traces is not off.
#[actix_rt::test]
async fn with_the_flag_off_nothing_is_mounted() {
    let f = setup().await;
    let app = test_app!(f, false);
    let t = f.a.id;

    for path in [
        format!("/.well-known/oauth-authorization-server/t/{t}"),
        format!("/.well-known/openid-configuration/t/{t}"),
        format!("/t/{t}/.well-known/openid-configuration"),
        format!("/t/{t}/oauth2/authorize?client_id={}", f.a.client_id),
        format!("/t/{t}/oauth2/jwks"),
        format!("/t/{t}/oauth2/userinfo"),
    ] {
        let resp = get(&app, &path).await;
        assert_eq!(
            resp.status().as_u16(),
            404,
            "{path} must not exist with AXIAM__AUTH__TENANT_ISSUER_PATHS unset"
        );
    }
}

/// I1, the document half: the two `?tenant_id=` discovery documents a
/// deployment already served are byte-identical with the flag off and with it
/// on. T1 asserts the two *paths* agree; this asserts the *flag* changes
/// neither.
#[actix_rt::test]
async fn the_existing_discovery_documents_are_byte_identical_in_both_modes() {
    let f = setup().await;
    let off = test_app!(f, false);
    let on = test_app!(f, true);

    for path in [
        "/.well-known/openid-configuration".to_owned(),
        "/.well-known/oauth-authorization-server".to_owned(),
        format!("/.well-known/openid-configuration?tenant_id={}", f.a.id),
        format!(
            "/.well-known/oauth-authorization-server?tenant_id={}",
            f.a.id
        ),
    ] {
        let off_body = test::read_body(get(&off, &path).await).await;
        let on_body = test::read_body(get(&on, &path).await).await;
        assert_eq!(
            off_body, on_body,
            "{path} must be byte-identical with the flag off and on"
        );
    }
}

/// T1's own assertion — the RFC 8414 alias is byte-identical to the OIDC path —
/// re-run with the flag set, which is what T21.6's item 3 asks for by name.
#[actix_rt::test]
async fn the_t1_alias_is_still_byte_identical_with_the_flag_on() {
    let f = setup().await;
    let app = test_app!(f, true);

    for query in [String::new(), format!("?tenant_id={}", f.a.id)] {
        let oidc =
            test::read_body(get(&app, &format!("/.well-known/openid-configuration{query}")).await)
                .await;
        let alias = test::read_body(
            get(
                &app,
                &format!("/.well-known/oauth-authorization-server{query}"),
            )
            .await,
        )
        .await;
        assert_eq!(
            oidc, alias,
            "the T21.1 alias must still hold (query: {query:?})"
        );
    }
}

/// The deployment-wide endpoints keep minting the root issuer with the flag on.
/// The flag adds a second issuer form; it does not move the first.
#[actix_rt::test]
async fn the_deployment_wide_endpoints_still_mint_the_root_issuer() {
    let f = setup().await;
    let app = test_app!(f, true);

    let tokens = code_flow(&app, "", &f.a).await;
    assert_eq!(
        iss_of(tokens["access_token"].as_str().unwrap()),
        ROOT_ISSUER
    );
    assert_eq!(iss_of(tokens["id_token"].as_str().unwrap()), ROOT_ISSUER);
}
