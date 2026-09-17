//! T21.8 — the MCP authorization sequence, end to end, against a real server.
//!
//! Every other test in this phase asks whether one endpoint behaves. This one
//! asks the only question an operator actually has: **if I point Claude Code,
//! VS Code or MCP Inspector at an MCP server fronted by AXIAM, does the
//! handshake the MCP specification describes complete?** It is therefore
//! written as the client's sequence rather than as the server's surface, and it
//! runs that sequence four times — once per registration mechanism (RFC 7591
//! dynamic registration and a client ID metadata document), in each of the two
//! issuer modes T21.6 introduced.
//!
//! # The sequence, as the specification states it
//!
//! 1. The client calls the MCP server with no credential and is answered `401`
//!    with `WWW-Authenticate: Bearer resource_metadata="…"` (RFC 9728 §5.1).
//!    The MCP server here is a `wiremock` stub, because publishing that
//!    challenge is the resource server's job and not AXIAM's — T9 gives it to
//!    the SDKs.
//! 2. The client fetches the protected-resource metadata the challenge named
//!    and reads `authorization_servers[0]`.
//! 3. It turns that issuer into a discovery URL by the RFC 8414 §3 rule and
//!    fetches `/.well-known/oauth-authorization-server` — the path T21.1 added,
//!    and the one MCP clients probe first.
//! 4. It obtains a `client_id`: by registering (T21.4) or by publishing a
//!    metadata document AXIAM fetches (T21.5).
//! 5. It runs the code grant with PKCE, a `resource` naming the MCP server, and
//!    a loopback callback **on a port chosen at request time** (RFC 8252 §7.3 /
//!    T21.2a).
//! 6. It presents the token to the MCP server, which validates `aud`.
//! 7. The MCP server introspects the token (RFC 7662) and is told its `aud`.
//!
//! # What this file proves that the per-task tests do not
//!
//! The per-task tests each hold everything but one variable still. What breaks
//! an integration is the *composition*: a token minted through a path issuer
//! for a client registered anonymously against a resource the tenant declared,
//! redeemed on a port nobody knew at registration time. Each of those five
//! features was written by a different session. This is the first thing that
//! runs them together.
//!
//! It also carries the adversarial cases from
//! `claude_dev/security-review-mcp-2026-09-17.md`, each named for the finding
//! it pins, so that a regression fails here rather than in a deployment.
//!
//! # What it does not cover, and why
//!
//! * **The MCP protocol itself.** No `initialize`, no `tools/call`. The stub
//!   answers one guarded route; what an MCP server does behind its audience
//!   check is not AXIAM's concern, and `examples/b7-mcp-server` is where the
//!   real transport lives.
//! * **A browser.** The authorization hop is driven with a bearer for an
//!   already-signed-in user, as every other OAuth2 test in this crate does. The
//!   consent screen is answered through the account endpoint the SPA itself
//!   calls, not by rendering it.
//! * **TLS, DPoP and mTLS.** Orthogonal to the handshake and each covered by
//!   its own file. `docs/api/mcp.md` recommends a sender-constrained token;
//!   proving the recommendation works is `dpop`'s and `mtls`'s job.

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{
    CimdPolicy, DynamicRegistrationMode, SetOrgSettings, system_defaults,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
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
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const CSRF_TOKEN: &str = "test-csrf-token";
const ROOT_ISSUER: &str = "https://axiam.example.com";
const VERIFIER: &str = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4.1";
/// The loopback callback as a desktop client **registers** it: no port, because
/// the port is not knowable until the client asks the operating system for one.
const LOOPBACK_CALLBACK: &str = "http://127.0.0.1/callback";

// ---------------------------------------------------------------------------
// The two issuer modes
// ---------------------------------------------------------------------------

/// Which of T21.6's two tenant-selection forms a run exercises.
///
/// Every request in this file is built through here rather than by
/// interpolating a path, so that "run it in both modes" is a parameter and not
/// a copy of the file. The difference is exactly the one T21.6 describes: a
/// query parameter that RFC 8414 §2 forbids inside an issuer, or a path segment
/// that it permits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// `{root}/oauth2/…?tenant_id={T}` — the form every deployment has today.
    Query,
    /// `{root}/t/{T}/oauth2/…` — opt-in, `AXIAM__AUTH__TENANT_ISSUER_PATHS`.
    TenantPath,
}

impl Mode {
    fn tenant_issuer_paths(self) -> bool {
        self == Mode::TenantPath
    }

    /// The RFC 8414 discovery URL an MCP client derives from the issuer.
    fn discovery(self, tenant: Uuid) -> String {
        match self {
            Mode::Query => format!("/.well-known/oauth-authorization-server?tenant_id={tenant}"),
            Mode::TenantPath => format!("/.well-known/oauth-authorization-server/t/{tenant}"),
        }
    }

    /// An OAuth2 endpoint, with the tenant selected the way this mode selects
    /// it. `extra` is appended as further query parameters.
    fn endpoint(self, tenant: Uuid, name: &str, extra: &str) -> String {
        match self {
            Mode::Query if extra.is_empty() => format!("/oauth2/{name}?tenant_id={tenant}"),
            Mode::Query => format!("/oauth2/{name}?tenant_id={tenant}&{extra}"),
            Mode::TenantPath if extra.is_empty() => format!("/t/{tenant}/oauth2/{name}"),
            Mode::TenantPath => format!("/t/{tenant}/oauth2/{name}?{extra}"),
        }
    }

    /// The `issuer` the discovery document must carry, and therefore the `iss`
    /// every token minted through this mode must carry.
    fn issuer(self, tenant: Uuid) -> String {
        match self {
            Mode::Query => ROOT_ISSUER.to_owned(),
            Mode::TenantPath => format!("{ROOT_ISSUER}/t/{tenant}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

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

/// One tenant, its end user, and a bearer for that user.
struct Tenant {
    id: Uuid,
    token: String,
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    /// The tenant every happy-path test works in.
    a: Tenant,
    /// A second tenant in the same organization, so that "isolation" is
    /// asserted against a tenant that actually exists rather than against a
    /// random UUID that would be refused for not existing.
    b: Tenant,
}

async fn make_tenant(db: &Surreal<TestDb>, org_id: Uuid, slug: &str, auth: &AuthConfig) -> Tenant {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("T21.8 {slug}"),
            slug: slug.to_owned(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("user-{slug}"),
            email: format!("{slug}@example.com"),
            // Generated: nothing here signs in with it, so a literal would be a
            // credential in the tree buying nothing.
            password: format!("pw-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();
    let token = issue_access_token(
        user.id,
        tenant.id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();
    Tenant {
        id: tenant.id,
        token,
    }
}

async fn setup(mode: Mode) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "T21.8 Org".into(),
            slug: "org-t21-8".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config(mode.tenant_issuer_paths());
    let a = make_tenant(&db, org.id, "tenant-a", &auth).await;
    let b = make_tenant(&db, org.id, "tenant-b", &auth).await;

    Fixture {
        db,
        org_id: org.id,
        a,
        b,
    }
}

/// Wide enough that a test driving a whole handshake is not measuring the
/// governor. The shipped default is asserted by `dynamic_registration_test`,
/// which is the file that is *about* the limit.
fn permissive_rate_limits() -> RateLimitConfig {
    RateLimitConfig {
        dcr_per_min: 1_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! test_app {
    ($f:expr, $mode:expr) => {
        test_app!($f, $mode, permissive_rate_limits())
    };
    ($f:expr, $mode:expr, $limits:expr) => {{
        let auth = test_auth_config($mode.tenant_issuer_paths());
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
                        &$limits,
                        RouteOptions {
                            tenant_issuer_paths: $mode.tenant_issuer_paths(),
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

macro_rules! app_svc {
    () => {
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >
    };
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

async fn get_json(app: &app_svc!(), uri: &str) -> (u16, Value) {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A `GET` as the signed-in end user, returning `(status, Location, body)`.
async fn get_as_user(app: &app_svc!(), uri: &str, token: &str) -> (u16, Option<String>, Value) {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("Location")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = test::read_body(resp).await;
    (
        status,
        location,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
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

async fn post_json(app: &app_svc!(), uri: &str, body: Value) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// An authenticated account/admin call, with the CSRF pair the middleware wants.
async fn post_as_user(app: &app_svc!(), uri: &str, token: &str, body: Value) -> (u16, Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
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

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// A JWT's claims, read without verifying anything.
///
/// An assertion helper, never a validation primitive: what is under test here
/// is which values the server *stamped*, and the signature is what
/// `validate_access_token`'s own tests cover.
fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url")).expect("claims")
}

fn param(location: &str, key: &str) -> Option<String> {
    url::Url::parse(location)
        .ok()?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Percent-encode a value for use in a query string.
fn enc(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn set_org_settings(f: &Fixture, input: SetOrgSettings) {
    SurrealSettingsRepository::new(f.db.clone())
        .set_org_settings(f.org_id, input)
        .await
        .map(|_| ())
        .expect("the organization baseline is fixture setup, not the thing under test")
}

// ---------------------------------------------------------------------------
// The stub MCP server
// ---------------------------------------------------------------------------

/// A `wiremock` matcher that does what an MCP server's middleware does: read the
/// bearer and check that its `aud` is this resource.
///
/// This is the half of the handshake AXIAM does not implement. Writing it as a
/// matcher rather than asserting on the claim in the test body is deliberate: it
/// makes the stub *refuse* a token addressed elsewhere, so the I3 direction (an
/// `axiam:user` token is not usable at the MCP server) and the T3 direction (a
/// resource-bound token is) are both observed as the MCP server's own behaviour
/// rather than as the test's opinion of it.
struct AudienceIs(String);

impl wiremock::Match for AudienceIs {
    fn matches(&self, request: &Request) -> bool {
        let Some(value) = request
            .headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
        else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        let Some(claims) = token
            .split('.')
            .nth(1)
            .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            return false;
        };
        claims["aud"].as_str() == Some(self.0.as_str())
    }
}

/// The MCP server the tenant fronts.
struct McpStub {
    _server: MockServer,
    /// `{base}/mcp` — the RFC 9728 `resource`, and the `aud` a usable token must
    /// carry.
    resource: String,
    /// Where the `401`'s `resource_metadata` points.
    metadata_url: String,
}

/// Start a stub MCP server that behaves the way RFC 9728 and the MCP
/// authorization specification say a resource server behaves.
///
/// `authorization_servers` carries the issuer for **this run's mode**, which is
/// the point of pointing the stub at AXIAM rather than hard-coding a URL: in
/// `TenantPath` mode the MCP server publishes a per-tenant issuer, and a client
/// that derives discovery from it must land on that tenant.
async fn mcp_stub(issuer: &str) -> McpStub {
    let server = MockServer::start().await;
    let resource = format!("{}/mcp", server.uri());
    let metadata_url = format!("{}/.well-known/oauth-protected-resource", server.uri());

    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "resource": resource,
                    "authorization_servers": [issuer],
                    "scopes_supported": ["openid", "profile"],
                    "bearer_methods_supported": ["header"],
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&server)
        .await;

    // Two mocks on the same route, and the priority is load-bearing: wiremock
    // resolves equal-priority matches in mount order, so without an explicit
    // ordering the unconditional `401` would answer every request and the
    // audience check would never run. The guarded route is `1` (highest) and
    // the challenge is the fallback beneath it.
    Mock::given(method("GET"))
        .and(path("/mcp"))
        .and(AudienceIs(resource.clone()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "tools": ["echo"] }))
                .insert_header("content-type", "application/json"),
        )
        .with_priority(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!("Bearer resource_metadata=\"{metadata_url}\", error=\"invalid_token\"")
                .as_str(),
        ))
        .with_priority(2)
        .mount(&server)
        .await;

    McpStub {
        _server: server,
        resource,
        metadata_url,
    }
}

/// Call the stub the way an MCP client does, returning
/// `(status, resource_metadata_url_if_challenged)`.
async fn call_mcp(resource: &str, bearer: Option<&str>) -> (u16, Option<String>) {
    let client = reqwest::Client::new();
    let mut request = client.get(resource);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.expect("the stub is reachable");
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let start = v.find("resource_metadata=\"")? + "resource_metadata=\"".len();
            let rest = &v[start..];
            Some(rest[..rest.find('"')?].to_owned())
        });
    (status, challenge)
}

async fn fetch_json(url: &str) -> Value {
    reqwest::get(url)
        .await
        .expect("reachable")
        .json()
        .await
        .expect("JSON")
}

// ---------------------------------------------------------------------------
// Tenant policy
// ---------------------------------------------------------------------------

/// The baseline an operator writes to front `resource` with self-registration.
fn dcr_policy(resource: &str) -> SetOrgSettings {
    SetOrgSettings {
        dynamic_registration: DynamicRegistrationMode::Anonymous,
        dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
        external_client_allowed_resources: vec![resource.to_owned()],
        ..system_defaults()
    }
}

/// The same, for a tenant that accepts client ID metadata documents from
/// `publisher_host` instead.
///
/// `allow_http` is on because the publisher here is a loopback mock server,
/// which is the seam every SSRF-guarded fetch's tests use.
fn cimd_policy(resource: &str, publisher_host: &str) -> SetOrgSettings {
    SetOrgSettings {
        dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
        external_client_allowed_resources: vec![resource.to_owned()],
        cimd: CimdPolicy {
            enabled: true,
            allow_http: true,
            trusted_client_id_domains: vec![publisher_host.to_owned()],
            ..CimdPolicy::default()
        },
        ..system_defaults()
    }
}

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .expect("a URL")
        .host_str()
        .expect("a host")
        .to_owned()
}

// ---------------------------------------------------------------------------
// Steps 1–3: challenge, protected-resource metadata, discovery
// ---------------------------------------------------------------------------

/// The first three steps of the sequence, shared by every run.
///
/// Returns the discovery document, having gone through the challenge and the
/// RFC 9728 metadata to reach it rather than reading AXIAM's URL out of the
/// fixture — which is what makes this a test of the *handshake* and not of the
/// discovery handler.
async fn discover(app: &app_svc!(), stub: &McpStub, mode: Mode, tenant: Uuid) -> Value {
    // 1 — the unauthenticated call is challenged.
    let (status, challenge) = call_mcp(&stub.resource, None).await;
    assert_eq!(status, 401, "an MCP server answers an uncredentialed call 401");
    let metadata_url = challenge.expect(
        "RFC 9728 §5.1: the challenge must carry resource_metadata, or the client has nowhere \
         to go",
    );
    assert_eq!(metadata_url, stub.metadata_url);

    // 2 — the protected-resource metadata names the authorization server.
    let metadata = fetch_json(&metadata_url).await;
    assert_eq!(metadata["resource"], stub.resource);
    let issuer = metadata["authorization_servers"][0]
        .as_str()
        .expect("RFC 9728 §2: authorization_servers")
        .to_owned();
    assert_eq!(
        issuer,
        mode.issuer(tenant),
        "the MCP server publishes the issuer for the mode this deployment runs"
    );

    // 3 — the issuer becomes a discovery URL by the RFC 8414 §3 rule. The client
    // probes the RFC 8414 path, which is the one T21.1 added; a client library
    // that does not implement the OIDC fallback would stop here.
    let (status, document) = get_json(app, &mode.discovery(tenant)).await;
    assert_eq!(status, 200, "{document}");
    assert_eq!(
        document["issuer"], issuer,
        "RFC 8414 §3.3: the document's issuer must equal the one that was dereferenced"
    );
    for member in [
        "authorization_endpoint",
        "token_endpoint",
        "introspection_endpoint",
    ] {
        assert!(
            document[member].is_string(),
            "an MCP client needs {member}: {document}"
        );
    }
    assert!(
        document["code_challenge_methods_supported"]
            .as_array()
            .expect("PKCE methods")
            .iter()
            .any(|m| m == "S256"),
        "MCP requires PKCE S256: {document}"
    );
    document
}

// ---------------------------------------------------------------------------
// Steps 5–7: the grant, the call, the introspection
// ---------------------------------------------------------------------------

/// Run steps 5 to 7 for a client that already exists, and assert the whole
/// chain: consent, code, token, `aud`, the MCP server's acceptance, its refusal
/// of an AXIAM-audience token, and I3.
///
/// `ephemeral_port` is the port the client's loopback listener actually got — a
/// value nobody knew when `LOOPBACK_CALLBACK` was registered, which is the whole
/// of RFC 8252 §7.3.
async fn complete_grant(
    app: &app_svc!(),
    f: &Fixture,
    mode: Mode,
    stub: &McpStub,
    client_id: &str,
    ephemeral_port: u16,
) -> Value {
    let tenant = f.a.id;
    let callback = format!("http://127.0.0.1:{ephemeral_port}/callback");
    let challenge = pkce_challenge(VERIFIER);
    let authorize = mode.endpoint(
        tenant,
        "authorize",
        &format!(
            "response_type=code&client_id={}&redirect_uri={}&scope=openid+profile&state=xyz\
             &code_challenge={challenge}&code_challenge_method=S256&resource={}",
            enc(client_id),
            enc(&callback),
            enc(&stub.resource)
        ),
    );

    // D4 — a client an administrator did not create asks the end user first.
    let (status, location, body) = get_as_user(app, &authorize, &f.a.token).await;
    assert_eq!(status, 302, "{body}");
    let location = location.expect("a redirect carries Location");
    assert!(
        location.contains("consent"),
        "D4: an externally registered client must pass the consent hop first: {location}"
    );

    let (status, body) = post_as_user(
        app,
        "/api/v1/account/consents/oidc-scopes",
        &f.a.token,
        json!({ "client_id": client_id, "scopes": ["openid", "profile"] }),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Now the same request produces a code.
    let (status, location, body) = get_as_user(app, &authorize, &f.a.token).await;
    assert_eq!(status, 302, "{body}");
    let location = location.expect("a redirect carries Location");
    let code = param(&location, "code")
        .unwrap_or_else(|| panic!("no code in {location}; the flow did not complete"));
    assert_eq!(
        param(&location, "iss").as_deref(),
        Some(mode.issuer(tenant).as_str()),
        "RFC 9207: the iss on the authorization response must be the issuer the client \
         discovered, or the client refuses the response: {location}"
    );
    assert!(
        location.starts_with(&callback),
        "RFC 8252 §7.3: the code comes back on the ephemeral port the client actually opened, \
         which is not the port it registered: {location}"
    );

    // 5 — redemption. A public client presents no secret.
    let (status, tokens) = post_form(
        app,
        &mode.endpoint(tenant, "token", ""),
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={}\
             &code_verifier={VERIFIER}&resource={}",
            enc(&callback),
            enc(client_id),
            enc(&stub.resource)
        ),
    )
    .await;
    assert_eq!(status, 200, "{tokens}");
    let access = tokens["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    let claims = claims_of(&access);
    assert_eq!(
        claims["aud"], stub.resource,
        "RFC 8707: the token is addressed at the MCP server, not at AXIAM"
    );
    assert_eq!(
        claims["iss"],
        mode.issuer(tenant),
        "the token's iss is the issuer the client discovered"
    );

    // 6 — the MCP server accepts it, because its `aud` is this resource.
    let (status, _) = call_mcp(&stub.resource, Some(&access)).await;
    assert_eq!(
        status, 200,
        "the MCP server's audience check must admit a token minted for it"
    );

    // …and refuses an ordinary AXIAM token, which is the same check from the
    // other side.
    let (status, _) = call_mcp(&stub.resource, Some(&f.a.token)).await;
    assert_eq!(
        status, 401,
        "an axiam:user token is not a credential at somebody else's resource server"
    );

    // 7 — I3. The converse, and the invariant this phase must never relax.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Authorization", format!("Bearer {access}")))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "I3: a resource-bound token must be refused by AXIAM's own endpoints"
    );

    tokens
}

/// Register a confidential client to stand for the MCP server at the
/// introspection endpoint.
///
/// RFC 7662 §2.1 wants an authenticated caller, and T21.2a refuses introspection
/// to public clients — so the resource server is a *separate*, confidential
/// registration from the desktop client that holds the token. That is also the
/// real topology: the MCP server is a server.
async fn register_resource_server(app: &app_svc!(), f: &Fixture) -> (String, String) {
    let (status, body) = post_as_user(
        app,
        "/api/v1/oauth2-clients",
        &f.a.token,
        json!({
            "name": "mcp-resource-server",
            "redirect_uris": ["https://mcp.example.com/unused"],
            "grant_types": ["client_credentials"],
            "scopes": ["openid"],
        }),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    (
        body["client_id"].as_str().unwrap().to_owned(),
        body["client_secret"].as_str().unwrap().to_owned(),
    )
}

/// Step 7, shared: the resource server asks AXIAM what the token says.
async fn introspect_as_resource_server(
    app: &app_svc!(),
    f: &Fixture,
    mode: Mode,
    stub: &McpStub,
    access: &str,
) {
    let (rs_id, rs_secret) = register_resource_server(app, f).await;
    let (status, introspection) = post_form(
        app,
        &mode.endpoint(f.a.id, "introspect", ""),
        &format!(
            "token={}&client_id={}&client_secret={}",
            enc(access),
            enc(&rs_id),
            enc(&rs_secret)
        ),
    )
    .await;
    assert_eq!(status, 200, "{introspection}");
    assert_eq!(introspection["active"], true, "{introspection}");
    assert_eq!(
        introspection["aud"], stub.resource,
        "RFC 7662 §2.2: the resource server is told whose token this is, which is how a server \
         that does not verify JWTs locally performs the audience check: {introspection}"
    );
}

// ---------------------------------------------------------------------------
// The four end-to-end runs
// ---------------------------------------------------------------------------

/// The MCP sequence with RFC 7591 dynamic client registration, in one mode.
async fn dcr_sequence(mode: Mode) {
    let f = setup(mode).await;
    let stub = mcp_stub(&mode.issuer(f.a.id)).await;
    set_org_settings(&f, dcr_policy(&stub.resource)).await;
    let app = test_app!(f, mode);

    let document = discover(&app, &stub, mode, f.a.id).await;

    // 4 — registration, at the endpoint the document advertises. That member is
    // published only for a tenant whose policy is not `disabled`, so a client
    // that read a document without it would stop here.
    assert!(
        document["registration_endpoint"].is_string(),
        "a tenant that permits self-registration must advertise where: {document}"
    );
    let (status, registered) = post_json(
        &app,
        &mode.endpoint(f.a.id, "register", ""),
        json!({
            "client_name": "MCP Inspector",
            "redirect_uris": [LOOPBACK_CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "openid profile",
        }),
    )
    .await;
    assert_eq!(status, 201, "{registered}");
    let client_id = registered["client_id"].as_str().unwrap().to_owned();
    assert!(
        registered.get("client_secret").is_none(),
        "a public client is issued no secret: {registered}"
    );

    let tokens = complete_grant(&app, &f, mode, &stub, &client_id, 49_152).await;
    introspect_as_resource_server(
        &app,
        &f,
        mode,
        &stub,
        tokens["access_token"].as_str().unwrap(),
    )
    .await;
}

/// The same sequence, with a client ID metadata document instead of a
/// registration call.
async fn cimd_sequence(mode: Mode) {
    let f = setup(mode).await;
    let stub = mcp_stub(&mode.issuer(f.a.id)).await;

    // The desktop client publishes its own metadata; the URL *is* the client_id.
    let publisher = MockServer::start().await;
    let client_id = format!("{}/client.json", publisher.uri());
    Mock::given(method("GET"))
        .and(path("/client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "client_id": client_id,
                    "client_name": "Example Editor",
                    "redirect_uris": [LOOPBACK_CALLBACK],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                    "scope": "openid profile",
                }))
                .insert_header("content-type", "application/json"),
        )
        .mount(&publisher)
        .await;

    set_org_settings(&f, cimd_policy(&stub.resource, &host_of(&client_id))).await;
    let app = test_app!(f, mode);

    let document = discover(&app, &stub, mode, f.a.id).await;
    assert_eq!(
        document["client_id_metadata_document_supported"], true,
        "a tenant that accepts metadata documents must say so, or a client has no reason to \
         send a URL as its client_id: {document}"
    );

    // No registration call at all — step 4 is "publish a document", and the
    // first time AXIAM sees the URL is in the authorization request.
    let tokens = complete_grant(&app, &f, mode, &stub, &client_id, 51_001).await;
    introspect_as_resource_server(
        &app,
        &f,
        mode,
        &stub,
        tokens["access_token"].as_str().unwrap(),
    )
    .await;
}

#[actix_rt::test]
async fn mcp_sequence_with_dynamic_registration_on_query_tenants() {
    dcr_sequence(Mode::Query).await;
}

#[actix_rt::test]
async fn mcp_sequence_with_dynamic_registration_on_path_issuers() {
    dcr_sequence(Mode::TenantPath).await;
}

#[actix_rt::test]
async fn mcp_sequence_with_a_client_id_metadata_document_on_query_tenants() {
    cimd_sequence(Mode::Query).await;
}

#[actix_rt::test]
async fn mcp_sequence_with_a_client_id_metadata_document_on_path_issuers() {
    cimd_sequence(Mode::TenantPath).await;
}
