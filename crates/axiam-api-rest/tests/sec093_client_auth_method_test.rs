//! SEC-093 — the client's registered `token_endpoint_auth_method` is enforced
//! at every client-authenticating endpoint, not only at the three grants
//! `TokenService::exchange` dispatches.
//!
//! ## What was wrong
//!
//! `TokenService::authenticate_client` verified the shared secret and nothing
//! else, while its sibling `authenticate_client_credential` — reached only
//! from authorization_code, client_credentials and refresh_token — honoured
//! the registration. Five endpoints used the former: PAR, revoke, introspect,
//! the token-exchange grant and the uma-ticket grant.
//!
//! That is exploitable rather than theoretical because
//! `SurrealOAuth2ClientRepository::create` mints a `client_secret` for **every**
//! client, whatever method it registers. So a FAPI 2.0 client registered for
//! `tls_client_auth` — whose registration validation explicitly forbids
//! shared-secret authentication — nonetheless held a live password-equivalent
//! credential that worked at all five. The operator's model was "this client
//! authenticates with a certificate"; the reality was an OR over two
//! credentials, one of which they were told to discard at creation time.
//!
//! PAR is the sharpest instance: FAPI 2.0 §5.3.1.1 requires strong client
//! authentication and FAPI 2.0 requires PAR, so a FAPI deployment's PAR
//! endpoint accepting `client_secret_post` was both an authentication
//! downgrade and a conformance failure.
//!
//! ## What this file asserts
//!
//! For each of the five endpoints, and for each strong method
//! (`tls_client_auth`, `self_signed_tls_client_auth`, `private_key_jwt`):
//!
//! * presenting the client's **correct** secret over a connection with no
//!   client certificate is refused with `invalid_client`; and
//! * a `client_secret_post` client presenting the same shaped request is
//!   **not** refused — the ordinary path is untouched.
//!
//! Every test is named after the thing it stops.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::oauth2_client::{ClientAuthMethod, CreateOAuth2Client, UpdateOAuth2Client};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::uma::UMA_TICKET_GRANT_TYPE;
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:34567";
const REDIRECT_URI: &str = "https://rp.test.example/callback";
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The three methods whose whole point is that they are NOT a shared secret.
const STRONG_METHODS: [ClientAuthMethod; 3] = [
    ClientAuthMethod::TlsClientAuth,
    ClientAuthMethod::SelfSignedTlsClientAuth,
    ClientAuthMethod::PrivateKeyJwt,
];

fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    /// Registered `client_secret_post` — the control.
    weak_client_id: String,
    weak_secret: String,
    /// Registered for a strong method, but still holding the secret the
    /// repository unconditionally minted for it. This is the bug's premise.
    strong_client_id: String,
    strong_secret: String,
}

async fn setup(strong_method: ClientAuthMethod) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SEC093 Org".into(),
            slug: "org-sec093".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SEC093 Tenant".into(),
            slug: "tenant-sec093".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let new_client = |name: &str| CreateOAuth2Client {
        tenant_id: tenant.id,
        name: name.into(),
        redirect_uris: vec![REDIRECT_URI.into()],
        grant_types: vec![
            "authorization_code".into(),
            "refresh_token".into(),
            TOKEN_EXCHANGE_GRANT_TYPE.into(),
            UMA_TICKET_GRANT_TYPE.into(),
        ],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
        // Both clients are CREATED as `client_secret_post`, exactly as the
        // admin API does, and the strong one is then switched over. That is
        // the real registration sequence, and it is what leaves the secret
        // hash behind.
        token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: vec![],
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
    };

    let (weak, weak_secret) = client_repo.create(new_client("weak-rp")).await.unwrap();
    let (strong, strong_secret) = client_repo.create(new_client("strong-rp")).await.unwrap();

    // Switch the second client to the strong method. Its secret hash stays in
    // the row — nothing deletes it, which is precisely why the old
    // `authenticate_client` kept accepting it.
    client_repo
        .update(
            tenant.id,
            strong.id,
            UpdateOAuth2Client {
                token_endpoint_auth_method: Some(strong_method),
                // A `tls_client_auth` registration must name an expected
                // subject DN, or the mTLS branch would refuse for a second,
                // unrelated reason and the test would pass for the wrong one.
                tls_client_auth_subject_dn: match strong_method {
                    ClientAuthMethod::TlsClientAuth => Some("CN=strong-rp".into()),
                    _ => None,
                },
                self_signed_tls_client_auth_thumbprints: match strong_method {
                    ClientAuthMethod::SelfSignedTlsClientAuth => Some(vec!["a".repeat(43)]),
                    _ => None,
                },
                jwks: match strong_method {
                    ClientAuthMethod::PrivateKeyJwt => Some(r#"{"keys":[]}"#.into()),
                    _ => None,
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let reloaded = client_repo
        .get_by_client_id(tenant.id, &strong.client_id)
        .await
        .unwrap();
    assert_eq!(
        reloaded.token_endpoint_auth_method,
        strong_method,
        "fixture precondition: the client must actually be registered for {}",
        strong_method.as_str()
    );
    assert!(
        !reloaded.client_secret_hash.is_empty(),
        "fixture precondition: the strong-auth client still holds the secret hash the \
         repository minted — without that there would be no bug to test"
    );

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        weak_client_id: weak.client_id,
        weak_secret,
        strong_client_id: strong.client_id,
        strong_secret,
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

/// POST a form-encoded body and return `(status, error_code)`. `error_code` is
/// `None` when the body is not an OAuth2 error object.
macro_rules! post_form {
    ($app:expr, $path:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri($path)
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload($body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        let error: Option<String> = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned));
        (status, error, String::from_utf8_lossy(&body).into_owned())
    }};
}

fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

// ---------------------------------------------------------------------------
// The five endpoints, as (name, path, body-builder)
// ---------------------------------------------------------------------------

/// The request body each endpoint needs, carrying `client_id` + `client_secret`
/// and otherwise the minimum that reaches the client-authentication step.
///
/// Deliberately minimal beyond the credentials: every one of these bodies is
/// missing something the endpoint needs *after* authentication, so a request
/// that authenticates successfully fails later with a DIFFERENT error code.
/// That is what lets one helper assert both directions — `invalid_client`
/// means the credential was refused, anything else means it was accepted.
fn bodies(tenant_id: Uuid, client_id: &str, secret: &str) -> Vec<(&'static str, String, String)> {
    vec![
        (
            "PAR",
            format!("/oauth2/par?tenant_id={tenant_id}"),
            format!(
                "client_id={client_id}&client_secret={secret}\
                 &response_type=code&redirect_uri={}",
                enc(REDIRECT_URI)
            ),
        ),
        (
            "revoke",
            format!("/oauth2/revoke?tenant_id={tenant_id}"),
            format!("client_id={client_id}&client_secret={secret}&token=not-a-real-token"),
        ),
        (
            "introspect",
            format!("/oauth2/introspect?tenant_id={tenant_id}"),
            format!("client_id={client_id}&client_secret={secret}&token=not-a-real-token"),
        ),
        (
            "token-exchange",
            format!("/oauth2/token?tenant_id={tenant_id}"),
            format!(
                "grant_type={}&client_id={client_id}&client_secret={secret}",
                enc(TOKEN_EXCHANGE_GRANT_TYPE)
            ),
        ),
        (
            "uma-ticket",
            format!("/oauth2/token?tenant_id={tenant_id}"),
            format!(
                "grant_type={}&client_id={client_id}&client_secret={secret}",
                enc(UMA_TICKET_GRANT_TYPE)
            ),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

async fn assert_strong_client_secret_is_refused_everywhere(method: ClientAuthMethod) {
    let f = setup(method).await;
    let app = test_app!(f);

    for (name, path, body) in bodies(f.tenant_id, &f.strong_client_id, &f.strong_secret) {
        let (status, error, raw) = post_form!(app, &path, body);
        assert_eq!(
            error.as_deref(),
            Some("invalid_client"),
            "{name}: a client registered for {} must NOT be authenticated by its \
             shared secret (SEC-093). Got {status} {raw}",
            method.as_str()
        );
        assert_eq!(
            status, 401,
            "{name}: a refused client credential is 401, got {status} {raw}"
        );
    }
}

#[actix_web::test]
async fn a_tls_client_auth_clients_secret_is_refused_at_all_five_endpoints() {
    assert_strong_client_secret_is_refused_everywhere(ClientAuthMethod::TlsClientAuth).await;
}

#[actix_web::test]
async fn a_self_signed_tls_client_auth_clients_secret_is_refused_at_all_five_endpoints() {
    assert_strong_client_secret_is_refused_everywhere(ClientAuthMethod::SelfSignedTlsClientAuth)
        .await;
}

#[actix_web::test]
async fn a_private_key_jwt_clients_secret_is_refused_at_all_five_endpoints() {
    assert_strong_client_secret_is_refused_everywhere(ClientAuthMethod::PrivateKeyJwt).await;
}

// ---------------------------------------------------------------------------
// The other half: `client_secret_post` still works
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn client_secret_post_still_authenticates_at_all_five_endpoints() {
    // If this ever fails, SEC-093's remedy has become an outage.
    let f = setup(ClientAuthMethod::TlsClientAuth).await;
    let app = test_app!(f);

    for (name, path, body) in bodies(f.tenant_id, &f.weak_client_id, &f.weak_secret) {
        let (status, error, raw) = post_form!(app, &path, body);
        assert_ne!(
            error.as_deref(),
            Some("invalid_client"),
            "{name}: a client_secret_post client presenting its correct secret must \
             still authenticate. Got {status} {raw}"
        );
    }
}

#[actix_web::test]
async fn a_wrong_secret_is_still_refused_for_a_client_secret_post_client() {
    // The control for the control: the refusals above must not be an artefact
    // of everything being refused.
    let f = setup(ClientAuthMethod::TlsClientAuth).await;
    let app = test_app!(f);

    for (name, path, body) in bodies(f.tenant_id, &f.weak_client_id, "definitely-not-the-secret") {
        let (status, error, raw) = post_form!(app, &path, body);
        assert_eq!(
            error.as_deref(),
            Some("invalid_client"),
            "{name}: a wrong secret must still be refused. Got {status} {raw}"
        );
    }
}

#[actix_web::test]
async fn par_still_succeeds_for_a_client_secret_post_client() {
    // `bodies()` deliberately builds requests that fail *after* authentication
    // at four of the five endpoints, so this pins the one endpoint where a
    // full success is cheap to assert end-to-end.
    let f = setup(ClientAuthMethod::PrivateKeyJwt).await;
    let app = test_app!(f);

    let body = format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri={}",
        f.weak_client_id,
        f.weak_secret,
        enc(REDIRECT_URI)
    );
    let (status, _, raw) = post_form!(app, &format!("/oauth2/par?tenant_id={}", f.tenant_id), body);
    assert_eq!(status, 201, "PAR must still mint a request_uri: {raw}");
}

// ---------------------------------------------------------------------------
// Omitting the secret entirely is still `invalid_client`, not a bypass
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn omitting_the_credential_entirely_is_refused_not_accepted() {
    // `authenticate_client` now takes `Option<&str>`. The one way to get that
    // wrong is to treat `None` as "no credential required".
    for method in STRONG_METHODS {
        let f = setup(method).await;
        let app = test_app!(f);

        for (name, path, body) in bodies(f.tenant_id, &f.strong_client_id, "") {
            // Strip the empty `client_secret=` so the parameter is genuinely
            // absent rather than present-and-empty.
            let body = body.replace("&client_secret=", "");
            let (status, error, raw) = post_form!(app, &path, body);
            assert_eq!(
                error.as_deref(),
                Some("invalid_client"),
                "{name}/{}: a request with no credential at all must be refused. \
                 Got {status} {raw}",
                method.as_str()
            );
        }
    }
}
