//! SC#1 oracle (CONTRACT.md §1, §5): `login()` yields a typed
//! `LoginResult { mfa_required }` and, on MFA, `verify_mfa(code)` completes
//! the two-phase flow — against a `wiremock` server returning the exact
//! response shapes AXIAM's real `POST /api/v1/auth/login` /
//! `POST /api/v1/auth/mfa/verify` handlers produce
//! (`crates/axiam-api-rest/src/handlers/auth.rs`).

#![cfg(feature = "rest")]

use axiam_sdk::client::AxiamClient;
use axiam_sdk::AxiamError;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixed test Ed25519 private seed (test-only, deterministic). Stored as raw
/// bytes — NOT a PEM/DER key block — so no private-key literal lives in source.
/// The PKCS8 v1 DER is rebuilt at runtime (standard 16-byte Ed25519 prefix +
/// this 32-byte seed) and fed to `EncodingKey::from_ed_der`. Same keypair as the
/// original test fixture, so `TEST_ED25519_PUBLIC_X` below still matches.
const TEST_ED25519_SEED: [u8; 32] = [
    0x74, 0x8c, 0x0b, 0xd3, 0xad, 0xc0, 0x28, 0x0a, 0xfd, 0xd7, 0xc0, 0x7c, 0x35, 0x07, 0x03, 0x64,
    0x6d, 0x14, 0x2d, 0x1d, 0xbd, 0x73, 0x4c, 0xd4, 0xf8, 0x17, 0x17, 0x0b, 0x91, 0x7b, 0x49, 0xfc,
];
/// Standard PKCS8 v1 DER prefix for an Ed25519 private key (alg id + seed OCTET STRING header).
const ED25519_PKCS8_DER_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The raw public key `x` coordinate (base64url, no padding) matching the seed
/// above, embedded directly in a hand-built JWKS response so the test needs no
/// extra crypto dependency to derive it.
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
}

fn issue_test_access_token(tenant_id: Uuid, org_id: Uuid, user_id: Uuid, jti: Uuid) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp: 9_999_999_999,
        jti: jti.to_string(),
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

async fn mount_jwks(mock_server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(mock_server)
        .await;
}

fn session_cookies_header(access_token: &str) -> Vec<String> {
    vec![
        format!("axiam_access={access_token}; Path=/; HttpOnly"),
        "axiam_refresh=test-refresh-token; Path=/; HttpOnly".to_string(),
        "axiam_csrf=test-csrf-token; Path=/".to_string(),
    ]
}

fn build_client(base_url: &str) -> AxiamClient {
    AxiamClient::builder()
        .base_url(base_url)
        .expect("valid base_url")
        .tenant_slug("acme")
        .build()
        .expect("client with tenant_slug builds successfully")
}

#[tokio::test]
async fn login_without_mfa_yields_completed_session() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let access_token = issue_test_access_token(tenant_id, org_id, user_id, session_id);

    let mut response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": user_id, "username": "alice", "email": "alice@example.com" },
        "session_id": session_id,
        "expires_in": 900,
    }));
    for cookie in session_cookies_header(&access_token) {
        response = response.append_header("Set-Cookie", cookie.as_str());
    }

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(response)
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let result = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login should succeed against the no-MFA mock");

    assert!(
        !result.mfa_required,
        "no-MFA login must report mfa_required = false"
    );
    assert_eq!(result.session_id, Some(session_id));
    assert_eq!(result.expires_in, Some(900));
    assert!(
        result.challenge_token.is_none(),
        "a completed login must not carry a challenge token"
    );

    // The access token must now be present in the jar (D-05: never in the
    // JSON body — only via Set-Cookie, already asserted implicitly by the
    // fact that verification below succeeds by reading it back out).
    let resolved_tenant = client.resolved_tenant_id().await;
    assert_eq!(
        resolved_tenant,
        Some(tenant_id),
        "tenant_id must be resolved from the verified access token's claims"
    );
}

#[tokio::test]
async fn login_with_mfa_required_then_verify_mfa_completes_two_phase_flow() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    let challenge_token = "test-challenge-token";

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "mfa_required": true,
            "challenge_token": challenge_token,
            "available_methods": ["totp"],
        })))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let login_result = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect("login should succeed (with MFA pending) against the mock");

    assert!(
        login_result.mfa_required,
        "server-signaled MFA must be surfaced"
    );
    assert_eq!(login_result.available_methods, vec!["totp".to_string()]);
    assert!(
        login_result.session_id.is_none(),
        "an MFA-pending login must not yet report a session id"
    );
    // The challenge token must be present but redacted in Debug output (§7).
    let debug_repr = format!("{:?}", login_result.challenge_token);
    assert!(!debug_repr.contains(challenge_token));

    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let access_token = issue_test_access_token(tenant_id, org_id, user_id, session_id);

    let mut mfa_response = ResponseTemplate::new(200).set_body_json(json!({
        "user": { "id": user_id, "username": "alice", "email": "alice@example.com" },
        "session_id": session_id,
        "expires_in": 900,
    }));
    for cookie in session_cookies_header(&access_token) {
        mfa_response = mfa_response.append_header("Set-Cookie", cookie.as_str());
    }

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/mfa/verify"))
        .respond_with(mfa_response)
        .mount(&mock_server)
        .await;

    let verified = client
        .verify_mfa("123456")
        .await
        .expect("verify_mfa should complete the two-phase flow");

    assert!(!verified.mfa_required);
    assert_eq!(verified.session_id, Some(session_id));
    assert_eq!(client.resolved_tenant_id().await, Some(tenant_id));
}

#[tokio::test]
async fn status_401_maps_to_auth_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid credentials"))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .login("alice@example.com", "wrong-password")
        .await
        .expect_err("401 must surface as an error");
    assert!(matches!(err, AxiamError::Auth { .. }));
}

#[tokio::test]
async fn status_403_maps_to_authz_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(403).set_body_string("mfa setup required"))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("403 must surface as an error");
    assert!(matches!(err, AxiamError::Authz { .. }));
}

#[tokio::test]
async fn status_429_maps_to_network_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login"))
        .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());
    let err = client
        .login("alice@example.com", "correct horse battery staple")
        .await
        .expect_err("429 must surface as an error");
    assert!(matches!(err, AxiamError::Network { .. }));
}

#[tokio::test]
async fn check_access_targets_exact_paths_and_preserves_batch_order() {
    let mock_server = MockServer::start().await;
    mount_jwks(&mock_server).await;

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "allowed": true,
        })))
        .mount(&mock_server)
        .await;

    let resource_a = Uuid::new_v4();
    let resource_b = Uuid::new_v4();

    Mock::given(method("POST"))
        .and(path("/api/v1/authz/check/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                { "allowed": true },
                { "allowed": false, "reason": "denied" },
            ]
        })))
        .mount(&mock_server)
        .await;

    let client = build_client(&mock_server.uri());

    let decision = client
        .check_access("users:get", resource_a, None)
        .await
        .expect("check_access should succeed");
    assert!(decision.allowed);

    let can = client
        .can("users:get", resource_a, None)
        .await
        .expect("can should succeed");
    assert!(can);

    let batch = client
        .batch_check(vec![
            axiam_sdk::rest::authz::AccessCheckRequest::new("users:get", resource_a),
            axiam_sdk::rest::authz::AccessCheckRequest::new("users:delete", resource_b),
        ])
        .await
        .expect("batch_check should succeed");

    assert_eq!(batch.len(), 2);
    assert!(
        batch[0].allowed,
        "first result must correspond to the first input"
    );
    assert!(
        !batch[1].allowed,
        "second result must correspond to the second input"
    );
}
