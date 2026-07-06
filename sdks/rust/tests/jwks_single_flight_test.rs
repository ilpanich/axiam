//! PERF-03 oracle: a burst of concurrent `verify()` calls against a cold
//! JWKS cache collapses to exactly ONE network fetch (D-08/D-09). Mirrors
//! the counting-mock harness used by `tests/single_flight_refresh_test.rs`
//! for the token-refresh single-flight guard, applied here to the JWKS
//! fetch path in `src/token/jwks.rs`.

#![cfg(feature = "rest")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axiam_sdk::token::JwksVerifier;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A fixed test Ed25519 private seed (test-only, deterministic), reused
/// verbatim from `tests/actix_extractor_test.rs`/`tests/login_mfa_flow_test.rs`
/// so all suites share one known-good keypair. Stored as a raw 32-byte seed
/// — NOT a PEM/DER key block — so no private-key literal lives in source;
/// the PKCS8 v1 DER is rebuilt at runtime and fed to `EncodingKey::from_ed_der`.
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

fn issue_test_access_token(exp: i64) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(TEST_KID.to_string());
    let claims = TestClaims {
        sub: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4().to_string(),
        org_id: Uuid::new_v4().to_string(),
        iss: "axiam-test".to_string(),
        iat: 0,
        exp,
        jti: Uuid::new_v4().to_string(),
        scope: None,
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

/// Starts a mock server serving `GET /oauth2/jwks` via a counting responder —
/// every invocation increments the shared `Arc<AtomicUsize>` before replying,
/// so the test can assert the exact number of network fetches regardless of
/// how many concurrent callers raced to fetch.
async fn mount_counting_jwks_server() -> (MockServer, Arc<AtomicUsize>) {
    let mock_server = MockServer::start().await;
    let call_count = Arc::new(AtomicUsize::new(0));
    let counter_for_responder = Arc::clone(&call_count);
    Mock::given(method("GET"))
        .and(path("/oauth2/jwks"))
        .respond_with(move |_req: &wiremock::Request| {
            counter_for_responder.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(jwks_body())
        })
        .mount(&mock_server)
        .await;
    (mock_server, call_count)
}

fn build_verifier(base_url: &str) -> JwksVerifier {
    let http_client = reqwest::Client::new();
    let url = url::Url::parse(base_url).expect("valid base url");
    JwksVerifier::new(http_client, &url).expect("verifier constructs")
}

#[tokio::test]
async fn concurrent_cache_miss_burst_triggers_exactly_one_fetch() {
    let (mock_server, call_count) = mount_counting_jwks_server().await;
    let verifier = Arc::new(build_verifier(&mock_server.uri()));
    let token = issue_test_access_token(9_999_999_999);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let verifier = Arc::clone(&verifier);
        let token = token.clone();
        handles.push(tokio::spawn(async move { verifier.verify(&token).await }));
    }

    for handle in handles {
        let claims = handle
            .await
            .expect("task should not panic")
            .expect("verify should succeed for every concurrent caller once the JWKS is fetched");
        assert_eq!(claims.iss, "axiam-test");
    }

    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "exactly one JWKS fetch must occur across 8 concurrent cold-cache callers (D-08/D-09)"
    );
}

#[tokio::test]
async fn second_call_after_fetch_completes_uses_cache_with_no_additional_fetch() {
    let (mock_server, call_count) = mount_counting_jwks_server().await;
    let verifier = build_verifier(&mock_server.uri());
    let token = issue_test_access_token(9_999_999_999);

    verifier
        .verify(&token)
        .await
        .expect("first verify should succeed and populate the cache");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    verifier
        .verify(&token)
        .await
        .expect("second verify should succeed served from the fresh cache");
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        1,
        "a second call after the cache is fresh must not trigger an additional fetch"
    );
}
