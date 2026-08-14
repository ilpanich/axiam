//! Integration tests for the RFC 8693 token-exchange grant (B3).
//!
//! The scope-narrowing arithmetic is proved exhaustively in
//! `axiam-oauth2`'s own unit tests. What this file exercises is what only
//! exists once the grant is mounted: that the token endpoint routes it, that
//! the exchanging client is authenticated, and — most of all — that the
//! narrowing rules survive the trip through the wire in both directions.
//!
//! Every test here is named after the thing it stops.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_M2M, AUD_USER, issue_access_token};
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::token_exchange::{
    MAY_IMPERSONATE_GRANT, TOKEN_EXCHANGE_GRANT_TYPE, TOKEN_TYPE_ACCESS_TOKEN,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const TEST_PEER: &str = "127.0.0.1:34567";

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
    org_id: Uuid,
    user_id: Uuid,
    /// Registered for the exchange grant, scopes {read, write}.
    client_id: String,
    client_secret: String,
    /// Same, plus the impersonation grant.
    imp_client_id: String,
    imp_client_secret: String,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Exchange Org".into(),
            slug: "org-exchange".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Exchange Tenant".into(),
            slug: "tenant-exchange".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "mesh-user".into(),
            email: "mesh-user@example.com".into(),
            password: TEST_PASSWORD.into(),
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

    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let (client, secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "orders-service".into(),
            redirect_uris: vec!["https://orders.internal".into()],
            grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
            scopes: vec!["read".into(), "write".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();
    let (imp_client, imp_secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "support-console".into(),
            redirect_uris: vec![],
            grant_types: vec![
                TOKEN_EXCHANGE_GRANT_TYPE.into(),
                MAY_IMPERSONATE_GRANT.into(),
            ],
            scopes: vec!["read".into(), "write".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
        })
        .await
        .unwrap();

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        client_id: client.client_id,
        client_secret: secret,
        imp_client_id: imp_client.client_id,
        imp_client_secret: imp_secret,
    }
}

/// Mint a subject token for the seeded user with the given scopes.
fn subject_token(f: &Fixture, scopes: &[&str]) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_string()).collect();
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &scopes,
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// The claims of a JWT, without verifying it.
///
/// Deliberately not `decode_access_token`: that helper accepts only AXIAM's own
/// two audiences, so it cannot read a token minted for a third-party target —
/// and a test that could only inspect the tokens the server is willing to
/// re-accept would be blind to exactly the ones worth checking.
fn decode_claims(token: &str) -> Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("claims are JSON")
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

/// Form-encode a token-exchange request. Only the values in these tests need
/// escaping, and only for the grant/token-type URNs' colons.
fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

macro_rules! exchange {
    ($app:expr, $f:expr, $client_id:expr, $secret:expr, $extra:expr) => {{
        let body = format!(
            "grant_type={}&client_id={}&client_secret={}{}",
            enc(TOKEN_EXCHANGE_GRANT_TYPE),
            $client_id,
            $secret,
            $extra
        );
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let json: Value = test::read_body_json(resp).await;
        (status, json)
    }};
}

/// Subject parameters ONLY — no actor token.
///
/// Absence of an actor token means *impersonation*, which is refused unless
/// the client holds the grant. Only the impersonation tests want this shape;
/// every other test wants delegation, below.
fn subject_only_params(f: &Fixture, scopes: &[&str]) -> String {
    format!(
        "&subject_token={}&subject_token_type={}",
        subject_token(f, scopes),
        enc(TOKEN_TYPE_ACCESS_TOKEN)
    )
}

/// Subject **and** actor parameters — a delegation exchange.
///
/// This is the default shape for every test that is about something other
/// than impersonation, because the impersonation gate sits before the scope,
/// audience and lifetime checks: a request without an actor token never
/// reaches them, and a test written that way would assert
/// `unauthorized_client` while believing it was testing scope narrowing.
fn subject_params(f: &Fixture, scopes: &[&str]) -> String {
    format!(
        "{}&actor_token={}&actor_token_type={}",
        subject_only_params(f, scopes),
        subject_token(f, &["read"]),
        enc(TOKEN_TYPE_ACCESS_TOKEN)
    )
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn an_exchange_narrows_the_subjects_scopes() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!("{}&scope=read", subject_params(&f, &["read", "write"]));
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 200, "exchange returned {body:?}");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
    assert_eq!(body["scope"], "read");
    assert_eq!(body["token_type"], "Bearer");
    // RFC 8693 §2.2.1 makes this mandatory: a client that asked for one token
    // type and got another must be able to tell.
    assert_eq!(body["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);
    // A refresh token would let the holder outlive the subject token
    // indefinitely — the lifetime cap, defeated.
    assert!(
        body.get("refresh_token").is_none(),
        "an exchange must never issue a refresh token: {body:?}"
    );
}

#[actix_web::test]
async fn omitting_scope_inherits_the_subjects_own() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = exchange!(
        app,
        f,
        f.client_id,
        f.client_secret,
        subject_params(&f, &["read", "write"])
    );
    assert_eq!(status, 200, "exchange returned {body:?}");
    let granted: Vec<&str> = body["scope"].as_str().unwrap().split(' ').collect();
    assert!(granted.contains(&"read") && granted.contains(&"write"));
}

// ---------------------------------------------------------------------------
// Narrowing — the rule the whole feature exists to preserve
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_scope_the_subject_does_not_hold_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    // The client is registered for `write`; the subject token is not.
    let extra = format!("{}&scope=write", subject_params(&f, &["read"]));
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 400);
    // Refused, not silently narrowed to nothing: a quietly-dropped scope
    // produces a token that works for some calls and not others, and the
    // caller finds out at the second service.
    assert_eq!(body["error"], "invalid_scope");
}

#[actix_web::test]
async fn the_clients_registration_bounds_a_broader_subject_token() {
    let f = setup().await;
    let app = test_app!(f);

    // The headline case: the subject holds `admin`, the client does not.
    // A compromised low-privilege service holding an admin's token must not
    // be able to mint an admin token.
    let extra = format!("{}&scope=admin", subject_params(&f, &["read", "admin"]));
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_scope");
}

#[actix_web::test]
async fn an_exchanged_token_never_outlives_its_subject() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = exchange!(
        app,
        f,
        f.client_id,
        f.client_secret,
        subject_params(&f, &["read"])
    );
    assert_eq!(status, 200, "exchange returned {body:?}");

    // The subject was minted with the config lifetime, so the exchanged token
    // can be at most that — never more. Without the cap an exchange launders
    // lifetime: hold a token briefly, exchange it, hold the result for the
    // full window.
    let expires_in = body["expires_in"].as_u64().unwrap();
    assert!(
        expires_in <= f.auth.access_token_lifetime_secs,
        "exchanged token lives {expires_in}s, longer than its subject's \
         {}s ceiling",
        f.auth.access_token_lifetime_secs
    );
    assert!(expires_in > 0);
}

// ---------------------------------------------------------------------------
// Impersonation
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn impersonation_is_refused_without_the_grant() {
    let f = setup().await;
    let app = test_app!(f);

    // No actor_token means impersonation. This client does not hold the
    // grant, so it must be REFUSED rather than silently downgraded to
    // delegation — a downgrade would hand back a token that is not the one
    // the caller asked for.
    let (status, body) = exchange!(
        app,
        f,
        f.client_id,
        f.client_secret,
        subject_only_params(&f, &["read"])
    );
    assert_eq!(status, 400);
    assert_eq!(body["error"], "unauthorized_client");
}

#[actix_web::test]
async fn impersonation_succeeds_for_a_client_that_holds_the_grant() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = exchange!(
        app,
        f,
        f.imp_client_id,
        f.imp_client_secret,
        subject_only_params(&f, &["read"])
    );
    assert_eq!(status, 200, "exchange returned {body:?}");
    assert!(!body["access_token"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Client authentication and grant registration
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn the_exchanging_client_must_authenticate() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = subject_params(&f, &["read"]);
    let (status, body) = exchange!(app, f, f.client_id, "the-wrong-secret", extra);
    assert_eq!(status, 401, "body was {body:?}");
    assert_eq!(body["error"], "invalid_client");
}

#[actix_web::test]
async fn an_unknown_client_is_indistinguishable_from_a_wrong_secret() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = subject_params(&f, &["read"]);
    let (unknown_status, unknown) = exchange!(app, f, "oa_does_not_exist", "whatever", extra);
    let extra = subject_params(&f, &["read"]);
    let (wrong_status, wrong) = exchange!(app, f, f.client_id, "the-wrong-secret", extra);

    // Identical code AND description, so the endpoint cannot be used to probe
    // which client ids exist (SEC-086).
    assert_eq!(unknown_status, wrong_status);
    assert_eq!(unknown["error"], wrong["error"]);
    assert_eq!(unknown["error_description"], wrong["error_description"]);
}

// ---------------------------------------------------------------------------
// Audience
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn an_unregistered_audience_is_invalid_target() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&audience={}",
        subject_params(&f, &["read"]),
        enc("https://someone-elses.internal")
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 400);
    // Its own code rather than invalid_request: the target is well-formed, it
    // is simply not this client's to address. An unconstrained `aud` would be
    // the mesh equivalent of an open redirect.
    assert_eq!(body["error"], "invalid_target");
}

#[actix_web::test]
async fn a_registered_audience_is_accepted() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&audience={}",
        subject_params(&f, &["read"]),
        enc("https://orders.internal")
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 200, "exchange returned {body:?}");
}

#[actix_web::test]
async fn axiams_own_audiences_are_always_addressable() {
    let f = setup().await;
    let app = test_app!(f);

    // Narrowing a user token to an M2M one is the common mesh case; refusing
    // it would make the feature unable to express its main use.
    let extra = format!(
        "{}&audience={}",
        subject_params(&f, &["read"]),
        enc(AUD_M2M)
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 200, "exchange returned {body:?}");
}

#[actix_web::test]
async fn narrowing_to_the_machine_audience_keeps_sub_and_sub_kind_consistent() {
    // SEC-088. The `sub_kind` claim is the instruction for how to read `sub`:
    // `AuthenticatedServiceAccount` documents `oauth2_client` as meaning `sub`
    // IS an OAuth2 client id (`oa_…`). An earlier revision rewrote `sub_kind`
    // to `oauth2_client` whenever the target audience was `axiam:m2m` while
    // leaving `sub` as the user's UUID — the one pairing the contract says
    // cannot occur, aimed at whoever writes the first consumer.
    //
    // Asserted as a PAIR rather than on `sub_kind` alone: the property that
    // matters is that the two claims still agree, not that either has some
    // particular value.
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&audience={}",
        subject_params(&f, &["read"]),
        enc(AUD_M2M)
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 200, "exchange returned {body:?}");

    let token = body["access_token"].as_str().expect("access_token");
    let claims = decode_claims(token);
    assert_eq!(
        claims["sub"].as_str().unwrap(),
        f.user_id.to_string(),
        "the subject is still the user"
    );
    assert_eq!(
        claims["sub_kind"].as_str().unwrap(),
        "user",
        "the subject kind must still describe the subject, not the audience"
    );
    assert_eq!(claims["aud"].as_str().unwrap(), AUD_M2M);
}

#[actix_web::test]
async fn audience_and_resource_must_agree_when_both_are_given() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&audience={}&resource={}",
        subject_params(&f, &["read"]),
        enc("https://orders.internal"),
        enc("https://something-else.internal")
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 400);
    // Silently preferring one would make the request mean something the
    // caller did not write.
    assert_eq!(body["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// Malformed and cross-tenant inputs
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn a_missing_subject_token_is_invalid_request() {
    let f = setup().await;
    let app = test_app!(f);
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, "");
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn an_unsupported_subject_token_type_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "&subject_token={}&subject_token_type={}",
        subject_token(&f, &["read"]),
        enc("urn:ietf:params:oauth:token-type:saml2")
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
}

/// Asking for a refresh token must fail, not quietly yield an access token.
///
/// This is the lifetime cap seen from the request side: the whole grant is
/// built on the exchanged token not outliving its subject, and a refresh token
/// is exactly the thing that would defeat it. Substituting an access token
/// would satisfy the response *shape* while answering a different question, and
/// the caller would find out when their refresh call 400s somewhere else.
#[actix_web::test]
async fn asking_for_a_refresh_token_is_refused_not_substituted() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&requested_token_type={}",
        subject_params(&f, &["read"]),
        enc("urn:ietf:params:oauth:token-type:refresh_token")
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 400, "returned {body:?}");
    assert_eq!(body["error"], "invalid_request");
}

/// Naming the type we do issue is accepted — the check refuses mismatches, it
/// does not refuse the parameter.
#[actix_web::test]
async fn explicitly_requesting_an_access_token_is_accepted() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "{}&requested_token_type={}",
        subject_params(&f, &["read"]),
        enc(TOKEN_TYPE_ACCESS_TOKEN)
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 200, "returned {body:?}");
    assert_eq!(body["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);
}

#[actix_web::test]
async fn a_garbage_subject_token_is_invalid_grant() {
    let f = setup().await;
    let app = test_app!(f);

    let extra = format!(
        "&subject_token=not.a.jwt&subject_token_type={}",
        enc(TOKEN_TYPE_ACCESS_TOKEN)
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn a_subject_token_from_another_tenant_is_invalid_grant() {
    let f = setup().await;
    let app = test_app!(f);

    // Same signing key, different tenant claim: the token verifies
    // cryptographically and must still be refused.
    let foreign = issue_access_token(
        f.user_id,
        Uuid::new_v4(),
        f.org_id,
        &["read".to_string()],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    let extra = format!(
        "&subject_token={foreign}&subject_token_type={}",
        enc(TOKEN_TYPE_ACCESS_TOKEN)
    );
    let (status, body) = exchange!(app, f, f.client_id, f.client_secret, extra);

    assert_eq!(status, 400);
    // Deliberately the same answer as an invalid token: a caller learning
    // their token is valid SOMEWHERE ELSE is a tenant-enumeration signal.
    assert_eq!(body["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn discovery_advertises_the_exchange_grant() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    let grants: Vec<String> =
        serde_json::from_value(body["grant_types_supported"].clone()).unwrap();
    assert!(
        grants.iter().any(|g| g == TOKEN_EXCHANGE_GRANT_TYPE),
        "discovery advertises {grants:?}, missing {TOKEN_EXCHANGE_GRANT_TYPE}"
    );
}
