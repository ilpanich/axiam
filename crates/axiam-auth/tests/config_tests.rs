//! Coverage for `AuthConfig` — defaults, effective issuer resolution, and
//! Ed25519 key parsing (`resolve_keys`).

use axiam_auth::config::AuthConfig;

const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

#[test]
fn default_has_sane_values() {
    let c = AuthConfig::default();
    assert_eq!(c.access_token_lifetime_secs, 900);
    assert_eq!(c.refresh_token_lifetime_secs, 2_592_000);
    assert_eq!(c.min_password_length, 12);
    assert!(c.allow_missing_aud_as_user);
    assert!(c.cookie_secure);
    assert_eq!(c.max_failed_login_attempts, 5);
    assert_eq!(c.hibp_breaker_threshold, 5);
    assert!(c.mfa_encryption_key.is_none());
}

#[test]
fn effective_issuer_falls_back_to_jwt_issuer() {
    let mut c = AuthConfig {
        jwt_issuer: "https://issuer.example.com/".into(),
        oauth2_issuer_url: String::new(),
        ..Default::default()
    };
    // Empty oauth2 url → use jwt_issuer, trailing slash trimmed.
    assert_eq!(c.effective_issuer(), "https://issuer.example.com");

    c.oauth2_issuer_url = "https://auth.example.com///".into();
    assert_eq!(c.effective_issuer(), "https://auth.example.com");
}

#[test]
fn resolve_keys_populates_cached_keys() {
    let mut c = AuthConfig {
        jwt_private_key_pem: PRIV_PEM.into(),
        jwt_public_key_pem: PUB_PEM.into(),
        ..Default::default()
    };
    assert!(c.jwt_encoding_key.is_none());
    c.resolve_keys().expect("valid PEM must resolve");
    assert!(c.jwt_encoding_key.is_some());
    assert!(c.jwt_decoding_key.is_some());
}

#[test]
fn resolve_keys_rejects_invalid_private_pem() {
    let mut c = AuthConfig {
        jwt_private_key_pem: "not-a-pem".into(),
        jwt_public_key_pem: PUB_PEM.into(),
        ..Default::default()
    };
    let err = c.resolve_keys().unwrap_err();
    assert!(err.contains("private key"));
}

#[test]
fn resolve_keys_rejects_invalid_public_pem() {
    let mut c = AuthConfig {
        jwt_private_key_pem: PRIV_PEM.into(),
        jwt_public_key_pem: "not-a-pem".into(),
        ..Default::default()
    };
    let err = c.resolve_keys().unwrap_err();
    assert!(err.contains("public key"));
}

#[test]
fn deserializes_from_empty_object_using_defaults() {
    // `#[serde(default)]` on the struct means an empty object yields defaults.
    let c: AuthConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(c.jwt_issuer, "axiam");
    assert!(c.cookie_secure);
}
