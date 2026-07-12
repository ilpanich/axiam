//! CONTRACT.md §10 oracle: the Actix `FromRequest` extractor `AxiamUser`
//! reads the session from the `axiam_access` cookie OR the `Authorization:
//! Bearer` header, verifies it locally against the cached JWKS (no
//! AXIAM-server round-trip for the token itself — only the initial JWKS
//! fetch touches the network), injects `{ user_id, tenant_id, roles }`, and
//! maps verification failure to HTTP 401/403 with a standardized JSON
//! error body.

#![cfg(feature = "actix")]

use actix_web::{test::TestRequest, web, FromRequest};
use axiam_sdk::middleware::AxiamUser;
use axiam_sdk::token::JwksVerifier;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixed test Ed25519 private seed (test-only, deterministic), reused
/// verbatim from `tests/login_mfa_flow_test.rs` so both suites share one
/// known-good keypair. Stored as a raw 32-byte seed — NOT a PEM/DER key
/// block — so no private-key literal lives in source; the PKCS8 v1 DER is
/// rebuilt at runtime and fed to `EncodingKey::from_ed_der`.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
/// Standard PKCS8 v1 DER prefix for an Ed25519 private key (alg id + seed OCTET STRING header).
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The raw public key `x` coordinate (base64url, no padding) matching the seed above.
const TEST_ED25519_PUBLIC_X: &str = "_r-I_0nRSSV8kvwA93gwhX-hFRiWkaNk5HEud-DjnMk";
const TEST_KID: &str = "test-kid-1";

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    tenant_id: String,
    org_id: String,
    iss: String,
    iat: i64,
    exp: i64,
    jti: String,
    scope: Option<String>,
}

fn issue_test_access_token(
    tenant_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
    jti: Uuid,
    exp: i64,
    scope: Option<&str>,
) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp,
        jti: jti.to_string(),
        scope: scope.map(str::to_owned),
    };
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&TEST_ED25519_SEED);
    let key = EncodingKey::from_ed_der(&der);
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test access token")
}

fn jwks_body() -> serde_json::Value {
    json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": TEST_KID,
                "alg": "EdDSA",
                "x": TEST_ED25519_PUBLIC_X,
            }
        ]
    })
}

/// Starts a mock server serving only `GET /oauth2/jwks`. No other route is
/// registered, so any test that reaches a *different* path would fail loud
/// — this doubles as the "no outbound AXIAM-server request for the token
/// itself" proof: the extractor only ever calls this one JWKS endpoint,
/// never a token-introspection/verification endpoint.
async fn mount_jwks_server() -> MockServer {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(&mock_server)
        .await;
    mock_server
}

fn build_verifier(base_url: &str) -> JwksVerifier {
    let http_client = reqwest::Client::new();
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(http_client, &url).expect("verifier constructs")
}

#[tokio::test]
async fn cookie_path_extracts_axiam_user() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        org_id,
        user_id,
        jti,
        9_999_999_999,
        Some("users:read users:write"),
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-path extraction should succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
    assert_eq!(
        user.roles,
        vec!["users:read".to_string(), "users:write".to_string()]
    );
}

#[tokio::test]
async fn bearer_header_path_extracts_axiam_user_when_no_cookie() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let jti = Uuid::new_v4();
    let token = issue_test_access_token(tenant_id, org_id, user_id, jti, 9_999_999_999, None);

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("bearer-header-path extraction should succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
    assert!(
        user.roles.is_empty(),
        "no scope claim must yield an empty roles vec"
    );
}

#[tokio::test]
async fn missing_credentials_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("missing credentials must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_signature_token_yields_401_with_json_body_not_panic() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    // Signed with a *different* Ed25519 key than the one served by the JWKS
    // mock, so signature verification must fail (not panic).
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: Uuid::new_v4().to_string(),
        scope: None,
    };
    let mut wrong_seed = TEST_ED25519_SEED;
    wrong_seed[0] ^= 0xFF; // flip bits to get a different (but still valid-length) key
    let mut der = ED25519_PKCS8_DER_PREFIX.to_vec();
    der.extend_from_slice(&wrong_seed);
    let wrong_key = EncodingKey::from_ed_der(&der);
    let bad_token = jsonwebtoken::encode(&header, &claims, &wrong_key)
        .expect("encode token with mismatched key");

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {bad_token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("signature-invalid token must fail, not panic");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);

    // The standardized JSON error body must be well-formed and must never
    // contain the raw token value (§7/§10 — no token echoed in error body).
    let resp = err.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body())
        .await
        .expect("error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body must be valid JSON, not a panic");
    assert!(body.get("error").is_some());
    assert!(body.get("message").is_some());
    let body_str = body.to_string();
    assert!(
        !body_str.contains(&bad_token),
        "error body must never echo the raw token"
    );
}

#[tokio::test]
async fn expired_token_yields_401() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        1, // expired long ago
        None,
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("expired token must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::UNAUTHORIZED);
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request (POST) with no `X-CSRF-Token` header must be rejected with 403
/// before any token verification is attempted.
#[tokio::test]
async fn cookie_auth_state_changing_without_csrf_header_yields_403() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let token = issue_test_access_token(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            "matching-csrf-token",
        ))
        // Deliberately no X-CSRF-Token header.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let err = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect_err("cookie-sourced POST without X-CSRF-Token must fail");

    use actix_web::ResponseError;
    assert_eq!(err.status_code(), actix_web::http::StatusCode::FORBIDDEN);

    let resp = err.error_response();
    let body_bytes = actix_web::body::to_bytes(resp.into_body())
        .await
        .expect("error body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body must be valid JSON");
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("authorization_denied")
    );
}

/// §3 CSRF double-submit: a cookie-sourced credential on a state-changing
/// request WITH a matching `X-CSRF-Token` header/`axiam_csrf` cookie pair
/// must pass the CSRF gate and proceed to (successful) verification.
#[tokio::test]
async fn cookie_auth_state_changing_with_matching_csrf_token_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .cookie(actix_web::cookie::Cookie::new(
            "axiam_csrf",
            "matching-csrf-token",
        ))
        .insert_header(("X-CSRF-Token", "matching-csrf-token"))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-sourced POST with matching CSRF token must succeed");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

/// A Bearer-header-sourced request needs no CSRF token at all, even for a
/// state-changing method — a cross-site attacker cannot set custom headers,
/// so the header path is CSRF-immune by construction.
#[tokio::test]
async fn bearer_auth_state_changing_without_csrf_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::post()
        .app_data(web::Data::new(verifier))
        .insert_header(("Authorization", format!("Bearer {token}")))
        // No CSRF cookie/header at all.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("Bearer-header POST needs no CSRF token");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

/// A cookie-sourced credential on a safe method (GET) must NOT be subject
/// to the CSRF gate — safe methods must not have side effects, so the §3
/// double-submit check only applies to state-changing methods.
#[tokio::test]
async fn cookie_auth_safe_method_without_csrf_succeeds() {
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::get()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        // No X-CSRF-Token header, no axiam_csrf cookie.
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("cookie-sourced GET needs no CSRF token");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}

#[tokio::test]
async fn local_verification_makes_no_outbound_axiam_server_request() {
    // Only the JWKS endpoint is mounted (no /api/v1/auth/* or /oauth2/introspect
    // route exists on this mock server). A successful extraction therefore
    // proves the extractor performed no server round-trip beyond the one-time
    // JWKS fetch — local verification only (§10.2).
    let mock_server = mount_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let token = issue_test_access_token(
        tenant_id,
        Uuid::new_v4(),
        user_id,
        Uuid::new_v4(),
        9_999_999_999,
        None,
    );

    let req = TestRequest::default()
        .app_data(web::Data::new(verifier))
        .cookie(actix_web::cookie::Cookie::new("axiam_access", token))
        .to_http_request();

    let mut payload = actix_web::dev::Payload::None;
    let user = AxiamUser::from_request(&req, &mut payload)
        .await
        .expect("local-only verification should succeed with no auth-check route mounted");

    assert_eq!(user.user_id, user_id);
    assert_eq!(user.tenant_id, tenant_id);
}
