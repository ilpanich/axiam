//! T21.5 — Client ID Metadata Documents, end to end.
//!
//! The feature is one sentence: a client identifies itself with a URL, and
//! AXIAM fetches that URL to learn what the client is. Every test here asks
//! one of five questions about that sentence.
//!
//! **Is it off until somebody turns it on?** This is I1, and it is the first
//! section because it is the only one about every deployment rather than about
//! the deployments that want this. A tenant that changes nothing treats a
//! URL-shaped `client_id` as exactly what it treated it as before this task —
//! an unknown client — and the publisher is never contacted at all.
//!
//! **Does a real MCP client get through, and does its token work?** The
//! acceptance case: a VS-Code-shaped document with a loopback callback on a
//! random port completes a code + PKCE + `resource` flow whose token is
//! addressed at the MCP server.
//!
//! **Does a stranger get to decide anything they should not?** D3: the
//! materialised client's audiences are the tenant's list and nothing else, and
//! the settings interlocks that make D3 real are tested beside it.
//!
//! **Is the end user asked?** D4: the first authorization for a CIMD client
//! goes to the consent screen, through the same record `POST /oauth2/register`
//! clients use.
//!
//! **Is the abuse surface bounded, and is the existing world safe from it?**
//! The publisher an operator did not trust, the document that describes
//! somebody else, and — the one that matters most here — an administrator's
//! client whose `client_id` happens to be a URL, which a document must never
//! be able to rewrite.
//!
//! The URL rules, the document rules, the SSRF refusals and the cache bounds
//! are unit-tested in `axiam_oauth2::cimd`, against a mock publisher, because
//! they are pure functions of a document and a policy and need no server.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::oauth2_client::{
    ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{CimdPolicy, SetOrgSettings, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, SettingsRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
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
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const ISSUER: &str = "https://localhost";
/// The MCP server this tenant fronts, as an operator would register it.
const MCP: &str = "https://mcp.example.com/mcp";
const VERIFIER: &str = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4.1";
/// The loopback callback on a random port, which is what every desktop MCP
/// client actually listens on (RFC 8252 §7.3). The registered URI names one
/// port and the request uses another — the T21.2 matcher is what makes that
/// work, and this is the acceptance criterion that it still does for a client
/// nobody registered.
const REGISTERED_CALLBACK: &str = "http://127.0.0.1:33418/callback";
const ACTUAL_CALLBACK: &str = "http://127.0.0.1:51397/callback";

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
    org_id: Uuid,
    tenant_id: Uuid,
    user_token: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.5 Org".into(),
            slug: "org-t21-5".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "T21.5 Tenant".into(),
            slug: "tenant-t21-5".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
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
        org_id: org.id,
        tenant_id: tenant.id,
        user_token,
    }
}

async fn set_org_settings(f: &Fixture, input: SetOrgSettings) {
    SurrealSettingsRepository::new(f.db.clone())
        .set_org_settings(f.org_id, input)
        .await
        .map(|_| ())
        .expect("settings written");
}

/// The baseline an operator writes to turn CIMD on properly: the mechanism,
/// the publisher this tenant trusts, the scopes an external client may ask
/// for, and — the part that matters — the MCP server this tenant fronts.
///
/// `allow_http` is on because the publisher in these tests is a loopback mock
/// server, which is the same seam every SSRF-guarded fetch's tests use, and
/// `restrict_same_domain` is off because the callbacks are on loopback — which
/// is exactly the profile `docs/admin/client-id-metadata-documents.md`
/// documents for Claude Code and VS Code.
fn cimd_policy(publisher_host: &str) -> SetOrgSettings {
    SetOrgSettings {
        dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
        external_client_allowed_resources: vec![MCP.into()],
        cimd: CimdPolicy {
            enabled: true,
            allow_http: true,
            trusted_client_id_domains: vec![publisher_host.to_owned()],
            trusted_redirect_domains: Vec::new(),
            restrict_same_domain: false,
            confidential_only: false,
            ..CimdPolicy::default()
        },
        ..system_defaults()
    }
}

fn permissive_rate_limits() -> RateLimitConfig {
    RateLimitConfig {
        dcr_per_min: 1_000,
        ..RateLimitConfig::default()
    }
}

/// The application under test, sharing **one** `AppState` with the caller.
///
/// The state is passed in rather than built inside, because the CIMD document
/// cache lives on it: a test that wants to reach the expiry branch has to hold
/// the same cache the handlers are using, and `AppState::for_test` would hand
/// it a second, empty one.
macro_rules! test_app {
    ($f:expr) => {
        test_app!($f, AppState::for_test($f.db.clone(), $f.auth.clone()))
    };
    ($f:expr, $state:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new($state))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &permissive_rate_limits())),
        )
        .await
    };
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

macro_rules! admin {
    ($app:expr, $f:expr, $method:ident, $path:expr, $json:expr) => {{
        let req = test::TestRequest::$method()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri($path)
            .insert_header(("Authorization", format!("Bearer {}", $f.user_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json($json)
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

macro_rules! discovery {
    ($app:expr, $tenant_id:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!(
                "/.well-known/oauth-authorization-server?tenant_id={}",
                $tenant_id
            ))
            .to_request();
        let doc: Value = test::call_and_read_body_json(&$app, req).await;
        doc
    }};
}

/// A VS-Code-shaped document: a public client with a loopback callback.
fn vscode_document(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "client_name": "Example Editor",
        "redirect_uris": [REGISTERED_CALLBACK],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile",
    })
}

/// Start a publisher serving `body` at `/client.json`, and return
/// `(server, client_id)`.
async fn publisher(body: Value) -> (MockServer, String) {
    let server = MockServer::start().await;
    let client_id = format!("{}/client.json", server.uri());
    let document = if body.is_null() {
        vscode_document(&client_id)
    } else {
        body
    };
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(document)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;
    (server, client_id)
}

/// The publisher's host, for `cimd.trusted_client_id_domains`.
fn host_of(client_id: &str) -> String {
    url::Url::parse(client_id)
        .expect("a URL")
        .host_str()
        .expect("a host")
        .to_owned()
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn aud_of(jwt: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["aud"]
        .as_str()
        .unwrap_or_else(|| panic!("no aud in {claims}"))
        .to_owned()
}

fn param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

async fn stored_client(f: &Fixture, client_id: &str) -> Option<axiam_core::models::oauth2_client::OAuth2Client> {
    SurrealOAuth2ClientRepository::new(f.db.clone())
        .get_by_client_id(f.tenant_id, client_id)
        .await
        .ok()
}

// ---------------------------------------------------------------------------
// I1 — absent until a tenant enables it
// ---------------------------------------------------------------------------

/// **The mandatory I1 test.** With the policy at its default, a URL-shaped
/// `client_id` is an unknown client — the same refusal, at the same endpoint,
/// with the same body, that an unregistered opaque `client_id` gets — and the
/// publisher is never contacted.
#[actix_rt::test]
async fn i1_a_url_client_id_is_an_unknown_client_when_cimd_is_off() {
    let f = setup().await;
    let (server, client_id) = publisher(Value::Null).await;
    let app = test_app!(f);

    let (url_status, url_body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!("grant_type=authorization_code&code=nope&redirect_uri={ACTUAL_CALLBACK}&client_id={client_id}&code_verifier={VERIFIER}")
    );
    let (opaque_status, opaque_body) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!("grant_type=authorization_code&code=nope&redirect_uri={ACTUAL_CALLBACK}&client_id=oa_never_registered&code_verifier={VERIFIER}")
    );

    assert_eq!(
        (url_status, &url_body),
        (opaque_status, &opaque_body),
        "a URL-shaped client_id on a tenant without CIMD must be answered exactly as any other \
         unknown client is"
    );
    assert!(
        server.received_requests().await.expect("recorded").is_empty(),
        "nothing may be fetched for a tenant that has not enabled the mechanism"
    );
    assert!(
        stored_client(&f, &client_id).await.is_none(),
        "and no shadow client may be written"
    );

    // The other half: discovery says nothing about it.
    let doc = discovery!(app, f.tenant_id);
    assert!(
        doc.get("client_id_metadata_document_supported").is_none(),
        "the member must be ABSENT, not false, for a tenant that never made a decision: {doc}"
    );
}

/// The deployment-wide document — every conformance run, and every client
/// written before this task — never advertises the capability, even with the
/// tenant switched fully on. A document that names no tenant cannot say
/// whether the capability exists.
#[actix_rt::test]
async fn i1_the_deployment_wide_document_never_advertises_cimd() {
    let f = setup().await;
    let (_server, client_id) = publisher(Value::Null).await;
    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let doc: Value = test::call_and_read_body_json(&app, req).await;
    assert!(
        doc.get("client_id_metadata_document_supported").is_none(),
        "{doc}"
    );
}

/// The advertisement appears for the tenant that enabled it (I7).
#[actix_rt::test]
async fn the_capability_is_advertised_once_the_tenant_enables_it() {
    let f = setup().await;
    let (_server, client_id) = publisher(Value::Null).await;
    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let app = test_app!(f);

    let doc = discovery!(app, f.tenant_id);
    assert_eq!(doc["client_id_metadata_document_supported"], json!(true));
}

// ---------------------------------------------------------------------------
// The acceptance case
// ---------------------------------------------------------------------------

/// **The whole feature in one test.** A VS-Code-shaped document becomes a
/// client, the first authorization passes the forced consent hop (D4), the
/// callback arrives on a *different* loopback port from the registered one
/// (RFC 8252 §7.3, the T21.2 matcher), and the token is addressed at the MCP
/// server rather than at AXIAM (D3 + T21.3).
#[actix_rt::test]
async fn a_cimd_client_completes_a_pkce_resource_flow_on_a_random_loopback_port() {
    let f = setup().await;
    let (_server, client_id) = publisher(Value::Null).await;
    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let app = test_app!(f);

    let challenge = pkce_challenge(VERIFIER);
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={ACTUAL_CALLBACK}\
         &scope=openid+profile&code_challenge={challenge}&code_challenge_method=S256\
         &resource={MCP}"
    );

    // D4 — a client an administrator did not create asks the end user first.
    let (status, location, body) = get_authorize!(app, f, query.clone());
    assert_eq!(status, 302, "{body}");
    let location = location.unwrap();
    assert!(
        location.contains("consent"),
        "a client materialised from a stranger's document must ask the end user first: \
         {location}"
    );

    // The shadow row is what the document said, and what the tenant said.
    let row = stored_client(&f, &client_id)
        .await
        .expect("the document materialised a client");
    assert_eq!(row.managed_by, ManagedBy::Cimd);
    assert_eq!(row.profile, ClientProfile::Standard, "I5");
    assert_eq!(row.token_endpoint_auth_method, ClientAuthMethod::None);
    assert!(
        row.client_secret_hash.is_empty(),
        "a client whose registration is a public document has no secret"
    );
    assert_eq!(
        row.allowed_resources,
        vec![MCP.to_owned()],
        "D3 — the audiences are the tenant's list, never the document's"
    );

    // The end user consents, through the same endpoint the account page uses.
    let (status, body) = admin!(
        app,
        f,
        post,
        "/api/v1/account/consents/oidc-scopes",
        json!({ "client_id": client_id, "scopes": ["openid", "profile"] })
    );
    assert_eq!(status, 200, "{body}");

    let (status, location, body) = get_authorize!(app, f, query);
    assert_eq!(status, 302, "{body}");
    let location = location.unwrap();
    let code = param(&location, "code").unwrap_or_else(|| panic!("no code in {location}"));
    assert!(
        location.starts_with(ACTUAL_CALLBACK),
        "the code goes back to the port the client actually opened: {location}"
    );

    let (status, tokens) = post_form!(
        app,
        f,
        "/oauth2/token",
        format!(
            "grant_type=authorization_code&code={code}&redirect_uri={ACTUAL_CALLBACK}\
             &client_id={client_id}&code_verifier={VERIFIER}&resource={MCP}"
        )
    );
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(
        aud_of(tokens["access_token"].as_str().unwrap()),
        MCP,
        "the token a CIMD client obtains is for the MCP server, not for AXIAM"
    );
}

/// The document is authoritative on every fetch: a client that renames itself
/// or narrows its callbacks is followed, once the cached copy has expired.
#[actix_rt::test]
async fn a_changed_document_is_picked_up_after_the_ttl() {
    let f = setup().await;
    let (server, client_id) = publisher(Value::Null).await;
    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let state = AppState::for_test(f.db.clone(), f.auth.clone());
    let cache = state.oauth2.cimd_cache.clone();
    let app = test_app!(f, state);

    let challenge = pkce_challenge(VERIFIER);
    let query = format!(
        "response_type=code&client_id={client_id}&redirect_uri={ACTUAL_CALLBACK}\
         &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
    );
    let _ = get_authorize!(app, f, query.clone());
    assert_eq!(
        stored_client(&f, &client_id).await.unwrap().name,
        "Example Editor"
    );

    // The publisher edits the document.
    server.reset().await;
    let mut changed = vscode_document(&client_id);
    changed["client_name"] = json!("Renamed Editor");
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(changed)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    // Inside the TTL, the cached copy stands — the row is unchanged and the
    // publisher is not contacted a second time.
    let _ = get_authorize!(app, f, query.clone());
    assert_eq!(
        stored_client(&f, &client_id).await.unwrap().name,
        "Example Editor",
        "a document is not re-read on every authorization request; that bound is what \
         cimd.min_cache_secs exists for"
    );

    // Past it, the new document is read and the row is refreshed in place.
    assert!(
        cache
            .backdate_for_test(f.tenant_id, &client_id, 100_000)
            .await,
        "the cache must hold an entry to backdate"
    );
    let _ = get_authorize!(app, f, query);
    assert_eq!(
        stored_client(&f, &client_id).await.unwrap().name,
        "Renamed Editor"
    );
}

// ---------------------------------------------------------------------------
// The registrations a document may not touch or invent
// ---------------------------------------------------------------------------

/// **The sharpest refusal in the task.** An administrator registered a client
/// whose `client_id` happens to be a URL. A document published at that URL by
/// anybody at all must not be able to rewrite it — not its redirect URIs, not
/// its secret, not its provenance.
#[actix_rt::test]
async fn a_document_cannot_rewrite_an_administrators_client() {
    let f = setup().await;
    let server = MockServer::start().await;
    let client_id = format!("{}/client.json", server.uri());

    // The administrator's client, with the URL as its... name, since AXIAM
    // mints its own `client_id`. To reach the case at all, the row is written
    // with the URL as its `client_id` through the CIMD upsert's own path and
    // then re-stamped as an administrator's — which is the only way a row of
    // that shape can exist, and exactly the row the guard must protect.
    let repo = SurrealOAuth2ClientRepository::new(f.db.clone());
    repo.upsert_cimd_client(
        &client_id,
        CreateOAuth2Client {
            tenant_id: f.tenant_id,
            name: "An administrator's client".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::None,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params:
                axiam_core::models::oauth2_client::AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Cimd,
        },
    )
    .await
    .expect("seeded");
    f.db.query("UPDATE oauth2_client SET managed_by = 'admin' WHERE client_id = $c")
        .bind(("c", client_id.clone()))
        .await
        .expect("re-stamped as an administrator's client");

    // A document that would take the client somewhere else entirely.
    let mut hostile = vscode_document(&client_id);
    hostile["redirect_uris"] = json!(["http://127.0.0.1:1/attacker"]);
    hostile["client_name"] = json!("Taken over");
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(hostile)
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let app = test_app!(f);
    let challenge = pkce_challenge(VERIFIER);
    let _ = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri=https://app.example.com/cb\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );

    let row = stored_client(&f, &client_id).await.expect("still there");
    assert_eq!(row.managed_by, ManagedBy::Admin, "provenance is untouched");
    assert_eq!(row.name, "An administrator's client");
    assert_eq!(
        row.redirect_uris,
        vec!["https://app.example.com/cb".to_owned()],
        "the document must not be able to move an administrator's callback"
    );
}

/// A publisher the operator did not name is not fetched at all, and no client
/// appears. This is the bound that keeps an unauthenticated caller from
/// choosing what this server connects to.
#[actix_rt::test]
async fn an_untrusted_publisher_is_never_contacted() {
    let f = setup().await;
    let (server, client_id) = publisher(Value::Null).await;
    // The policy trusts somebody else entirely.
    set_org_settings(&f, cimd_policy("trusted.example.com")).await;
    let app = test_app!(f);

    let challenge = pkce_challenge(VERIFIER);
    let _ = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={ACTUAL_CALLBACK}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );

    assert!(
        server.received_requests().await.expect("recorded").is_empty(),
        "a publisher outside cimd.trusted_client_id_domains must not be contacted"
    );
    assert!(stored_client(&f, &client_id).await.is_none());
}

/// A document that describes a different URL is refused: a file copied from
/// another publisher, or a host that mirrors other people's documents, does
/// not become that other client.
#[actix_rt::test]
async fn a_document_describing_another_url_materialises_nothing() {
    let f = setup().await;
    let server = MockServer::start().await;
    let client_id = format!("{}/client.json", server.uri());
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(vscode_document("https://someone.else.example/client.json"))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;
    set_org_settings(&f, cimd_policy(&host_of(&client_id))).await;
    let app = test_app!(f);

    let challenge = pkce_challenge(VERIFIER);
    let _ = get_authorize!(
        app,
        f,
        format!(
            "response_type=code&client_id={client_id}&redirect_uri={ACTUAL_CALLBACK}\
             &scope=openid&code_challenge={challenge}&code_challenge_method=S256"
        )
    );
    assert!(stored_client(&f, &client_id).await.is_none());
}

// ---------------------------------------------------------------------------
// The settings interlocks
// ---------------------------------------------------------------------------

/// D3 at the settings layer, through the endpoint an operator actually uses:
/// CIMD cannot be enabled while the tenant has named no MCP server.
#[actix_rt::test]
async fn d3_cimd_cannot_be_enabled_without_audiences() {
    let f = setup().await;
    let app = test_app!(f);

    let refused = SetOrgSettings {
        external_client_allowed_resources: Vec::new(),
        cimd: CimdPolicy {
            enabled: true,
            trusted_client_id_domains: vec!["*.example.com".into()],
            ..CimdPolicy::default()
        },
        ..system_defaults()
    };
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/organizations/{}/settings", f.org_id))
        .insert_header(("Authorization", format!("Bearer {}", f.user_token)))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(&refused)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("D3"), "{text}");
}

/// The second interlock, which is AXIAM's own: no trusted publisher, no
/// mechanism.
#[actix_rt::test]
async fn cimd_cannot_be_enabled_without_a_trusted_publisher() {
    let f = setup().await;
    let app = test_app!(f);

    let refused = SetOrgSettings {
        external_client_allowed_resources: vec![MCP.into()],
        cimd: CimdPolicy {
            enabled: true,
            trusted_client_id_domains: Vec::new(),
            ..CimdPolicy::default()
        },
        ..system_defaults()
    };
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/organizations/{}/settings", f.org_id))
        .insert_header(("Authorization", format!("Bearer {}", f.user_token)))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(&refused)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body = test::read_body(resp).await;
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("trusted_client_id_domains"), "{text}");
}
