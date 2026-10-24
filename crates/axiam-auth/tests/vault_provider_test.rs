//! `VaultSecretProvider::fetch` against a mock Vault.
//!
//! The fetch path is the one part of the secret provider that talks to the
//! network, and the one where a mistake is least visible: a provider that
//! quietly returned no keys would look exactly like a deployment that had not
//! configured them, and AXIAM would answer `503` on the OPAQUE endpoints with
//! nothing in the logs pointing at Vault.
//!
//! So these assert the distinction the port's docs insist on — `Ok(None)` for
//! "not configured", `Err` for "configured and unreachable" — over the shapes
//! Vault actually returns.

use std::collections::HashMap;
use std::net::TcpListener;
use std::time::Duration;

use axiam_auth::secrets::{VaultConfig, VaultSecretProvider};
use axiam_core::secrets::{
    AUTH_PEPPER, JWT_PRIVATE_KEY_PEM, OPAQUE_SESSION_KEY, OPAQUE_SETUP_KEY, SecretProvider,
};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A key minted per call rather than written as a literal.
fn a_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("a CSPRNG");
    key
}

fn config(server: &MockServer) -> VaultConfig {
    VaultConfig {
        address: server.uri(),
        token: "test-token".into(),
        mount: "secret".into(),
        path: "axiam".into(),
        // The mock speaks plain HTTP; a private-CA anchor has nothing to verify.
        ca_cert_path: None,
    }
}

const KEYS: &[&str] = &[OPAQUE_SESSION_KEY, OPAQUE_SETUP_KEY];
const SECRETS: &[&str] = &[AUTH_PEPPER, JWT_PRIVATE_KEY_PEM];

/// Mount a KV v2 read returning `fields`.
async fn mount_kv2(server: &MockServer, fields: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/axiam"))
        .and(header("X-Vault-Token", "test-token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "data": { "data": fields } })),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn keys_and_text_secrets_are_read_from_a_kv2_response() {
    let session = a_key();
    let setup = a_key();
    let server = MockServer::start().await;
    mount_kv2(
        &server,
        json!({
            OPAQUE_SESSION_KEY: hex::encode(session),
            OPAQUE_SETUP_KEY: hex::encode(setup),
            AUTH_PEPPER: "a-pepper",
            JWT_PRIVATE_KEY_PEM: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        }),
    )
    .await;

    let provider =
        VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
            .await
            .unwrap();

    assert_eq!(provider.get_key(OPAQUE_SESSION_KEY).unwrap(), Some(session));
    assert_eq!(provider.get_key(OPAQUE_SETUP_KEY).unwrap(), Some(setup));
    assert_eq!(
        provider
            .get_secret(AUTH_PEPPER)
            .unwrap()
            .map(|s| s.to_string()),
        Some("a-pepper".to_string())
    );
    // A PEM survives verbatim, newlines and all — the reason `get_secret` is
    // separate from `get_key`.
    assert!(
        provider
            .get_secret(JWT_PRIVATE_KEY_PEM)
            .unwrap()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}

#[tokio::test]
async fn a_kv1_response_is_read_too() {
    // KV v1 does not nest under `data.data`. A deployment on the older engine
    // should not be silently told its secrets are absent.
    let key = a_key();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/axiam"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { OPAQUE_SETUP_KEY: hex::encode(key) }
        })))
        .mount(&server)
        .await;

    let provider =
        VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
            .await
            .unwrap();
    assert_eq!(provider.get_key(OPAQUE_SETUP_KEY).unwrap(), Some(key));
}

#[tokio::test]
async fn a_secret_vault_does_not_hold_is_absent_not_an_error() {
    // A deployment may legitimately keep only some secrets in Vault.
    let server = MockServer::start().await;
    mount_kv2(&server, json!({ OPAQUE_SETUP_KEY: hex::encode(a_key()) })).await;

    let provider =
        VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
            .await
            .unwrap();
    assert_eq!(provider.get_key(OPAQUE_SESSION_KEY).unwrap(), None);
    assert_eq!(provider.get_secret(AUTH_PEPPER).unwrap(), None);
}

#[tokio::test]
async fn a_rejected_token_is_an_error_not_an_absence() {
    // The distinction the port's docs insist on. If this returned "no secrets",
    // a bad policy would present as "OPAQUE is off" and the operator would go
    // looking in entirely the wrong place.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let err = VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("403"),
        "the status belongs in the message (text withheld)"
    );
    assert!(
        err.contains("policy") || err.contains("mount"),
        "and a hint at the cause (text withheld)"
    );
}

#[tokio::test]
async fn an_unreachable_vault_is_an_error() {
    // This used to start a `MockServer`, take its address and drop it, on the
    // reasoning that nothing was then listening. That races, and lost roughly
    // one run in five: dropping the server returns its port to the ephemeral
    // range, and the eight sibling tests in this binary run concurrently and
    // each call `MockServer::start()`, which binds a port from exactly that
    // range. When one of them drew the port this test had just released, the
    // fetch reached a live server, returned `Ok`, and the assertion failed —
    // a red build with nothing wrong in the code under test.
    //
    // So reserve the port instead of releasing it. `reservation` is held for
    // the whole test, which makes the address un-bindable by anything else in
    // the process; it never accepts, so the request is answered by nobody and
    // the client's timeout is what ends it. Unreachable either way, and the
    // outcome no longer depends on which test happens to run alongside.
    let reservation = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let addr = reservation.local_addr().expect("the bound address");

    let config = VaultConfig {
        address: format!("http://{addr}"),
        token: "test-token".into(),
        mount: "secret".into(),
        path: "axiam".into(),
        ca_cert_path: None,
    };
    // Nothing will ever answer, so any timeout is correct and the shortest one
    // that is unambiguously a timeout keeps the suite fast.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .expect("a client");

    assert!(
        VaultSecretProvider::fetch(&client, &config, KEYS, SECRETS)
            .await
            .is_err()
    );

    drop(reservation);
}

#[tokio::test]
async fn a_malformed_key_in_vault_is_an_error() {
    // Someone pasted a truncated key. Failing at startup is far better than
    // discovering it when the first login needs it.
    let server = MockServer::start().await;
    mount_kv2(&server, json!({ OPAQUE_SETUP_KEY: "not-a-key" })).await;

    let err = VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(OPAQUE_SETUP_KEY),
        "vault refusal text did not match (withheld)"
    );
}

#[tokio::test]
async fn the_token_never_appears_in_an_error_message() {
    // Errors get logged. A token that leaks into one is a credential in the
    // log aggregator.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let err = VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !err.contains("test-token"),
        "vault refusal text did not match (withheld)"
    );
}

#[tokio::test]
async fn a_response_without_a_data_object_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "errors": [] })))
        .mount(&server)
        .await;

    assert!(
        VaultSecretProvider::fetch(&reqwest::Client::new(), &config(&server), KEYS, SECRETS)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn from_values_serves_without_any_network() {
    // The seam that keeps a KMS off the login path: once built, the provider
    // answers from memory.
    let key = a_key();
    let provider = VaultSecretProvider::from_values(
        HashMap::from([(OPAQUE_SETUP_KEY.to_string(), key)]),
        HashMap::from([(AUTH_PEPPER.to_string(), "p".to_string())]),
    );
    assert_eq!(provider.get_key(OPAQUE_SETUP_KEY).unwrap(), Some(key));
    assert_eq!(
        provider
            .get_secret(AUTH_PEPPER)
            .unwrap()
            .map(|s| s.to_string()),
        Some("p".to_string())
    );
    assert_eq!(provider.describe(), "vault");
}

/// T-476: a `307` from Vault is an error naming the host, and the host it
/// points at sees nothing. reqwest strips only the standard credential headers
/// on a cross-host redirect, so `X-Vault-Token` would otherwise have followed.
///
/// Two paths build the client that reaches Vault: the bootstrap client
/// (`axiam_auth::secrets::bootstrap_client`, which `main.rs` calls), and the one `build` makes when a private CA is named.
/// Both are exercised.
async fn assert_redirect_refused(vault: &MockServer, elsewhere: &MockServer, err: String) {
    let host = reqwest::Url::parse(&vault.uri()).unwrap();
    assert!(
        err.contains("redirect") && err.contains(host.host_str().unwrap()),
        "the refusal names the host that redirected (text withheld)"
    );
    assert!(
        !err.contains("test-token"),
        "vault refusal text did not match (withheld)"
    );
    assert_eq!(vault.received_requests().await.unwrap().len(), 1);
    assert!(
        elsewhere.received_requests().await.unwrap().is_empty(),
        "the second host must see no request, and so no X-Vault-Token"
    );
}

async fn redirecting_vault() -> (MockServer, MockServer) {
    let vault = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(307).insert_header(
            "location",
            format!("{}/v1/secret/data/axiam", elsewhere.uri()).as_str(),
        ))
        .mount(&vault)
        .await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": { "data": {} } })))
        .expect(0)
        .mount(&elsewhere)
        .await;
    (vault, elsewhere)
}

#[tokio::test]
async fn a_redirect_from_vault_is_an_error_and_the_other_host_sees_nothing() {
    let (vault, elsewhere) = redirecting_vault().await;
    // The client the composition root hands the provider: the very function
    // `main.rs` calls, so what is pinned here is what runs at startup.
    let bootstrap = axiam_auth::secrets::bootstrap_client().unwrap();

    let err = VaultSecretProvider::fetch(&bootstrap, &config(&vault), KEYS, SECRETS)
        .await
        .unwrap_err()
        .to_string();
    assert_redirect_refused(&vault, &elsewhere, err).await;
}

#[tokio::test]
async fn a_redirect_from_vault_is_refused_on_the_private_ca_client_too() {
    use axiam_auth::secrets::SecretProviderKind;

    let (vault, elsewhere) = redirecting_vault().await;

    // Any parseable PEM certificate: the mock speaks plain HTTP, so the anchor
    // only has to make `build` take the branch that constructs its own client.
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["vault.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let dir = std::env::temp_dir().join(format!("axiam-vault-redirect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let anchor = dir.join("ca.pem");
    std::fs::write(&anchor, cert.pem()).unwrap();

    let mut cfg = config(&vault);
    cfg.ca_cert_path = Some(anchor);
    let kind = SecretProviderKind::Vault(Box::new(cfg));
    // The client passed in is deliberately one that WOULD follow redirects: the
    // private-CA branch must not use it.
    let err = kind
        .build(&reqwest::Client::new(), KEYS, SECRETS)
        .await
        .err()
        .expect("a redirect is refused")
        .to_string();
    let _ = std::fs::remove_dir_all(&dir);
    assert_redirect_refused(&vault, &elsewhere, err).await;
}

#[tokio::test]
async fn a_vault_that_never_answers_fails_within_the_bound_naming_the_host_and_no_token() {
    // A Vault that accepts the connection and answers after the bound: without
    // a client timeout the fetch would wait the full delay (and, for a Vault
    // that never answers, forever — #667).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let bound = Duration::from_millis(300);
    let client = axiam_auth::secrets::bootstrap_client_with_timeout(bound).unwrap();

    let started = std::time::Instant::now();
    let err = VaultSecretProvider::fetch(&client, &config(&server), KEYS, SECRETS)
        .await
        .unwrap_err()
        .to_string();
    let took = started.elapsed();

    assert!(
        took < Duration::from_secs(5),
        "the bound did not hold: {took:?}"
    );
    let host = reqwest::Url::parse(&server.uri()).unwrap();
    assert!(
        err.contains(host.host_str().unwrap()),
        "vault refusal text did not match (withheld)"
    );
    assert!(
        err.contains("timed out"),
        "vault refusal text did not match (withheld)"
    );
    assert!(
        !err.contains("test-token"),
        "vault refusal text did not match (withheld)"
    );
}

#[test]
fn the_production_bounds_match_the_documented_ones() {
    assert_eq!(axiam_auth::secrets::VAULT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(
        axiam_auth::secrets::VAULT_CONNECT_TIMEOUT,
        Duration::from_secs(5)
    );
}
