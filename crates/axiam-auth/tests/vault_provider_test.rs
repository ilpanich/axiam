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
        "the status belongs in the message: {err}"
    );
    assert!(
        err.contains("policy") || err.contains("mount"),
        "and a hint at the cause: {err}"
    );
}

#[tokio::test]
async fn an_unreachable_vault_is_an_error() {
    let server = MockServer::start().await;
    let uri = server.uri();
    drop(server); // nothing is listening now

    let config = VaultConfig {
        address: uri,
        token: "test-token".into(),
        mount: "secret".into(),
        path: "axiam".into(),
        ca_cert_path: None,
    };
    assert!(
        VaultSecretProvider::fetch(&reqwest::Client::new(), &config, KEYS, SECRETS)
            .await
            .is_err()
    );
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
    assert!(err.contains(OPAQUE_SETUP_KEY), "{err}");
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
    assert!(!err.contains("test-token"), "{err}");
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
