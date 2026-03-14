//! JWT access token issuance/verification and opaque refresh token
//! generation.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::error::AuthError;

/// JWT claims embedded in every access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    pub org_id: String,
    /// Issuer.
    pub iss: String,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Unique token ID (UUID string).
    pub jti: String,
    /// OAuth2 scopes (space-separated string). Present when non-empty
    /// scopes are granted — both Client Credentials and Authorization
    /// Code flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Issue a signed EdDSA (Ed25519) JWT access token.
///
/// When `scopes` is non-empty a space-separated `scope` claim is
/// included in the token; otherwise the claim is omitted.
pub fn issue_access_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti: Uuid::new_v4().to_string(),
        scope,
    };

    let key = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue a JWT access token for OAuth2 Client Credentials grant (M2M).
///
/// The `sub` claim is the OAuth2 `client_id` (not a user UUID).
/// If `scopes` is non-empty, a space-separated `scope` claim is
/// included in the token.
pub fn issue_client_credentials_token(
    client_id: &str,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    let claims = AccessTokenClaims {
        sub: client_id.to_owned(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti: Uuid::new_v4().to_string(),
        scope,
    };

    let key = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// OIDC ID Token claims per OpenID Connect Core 1.0 section 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer identifier.
    pub iss: String,
    /// Subject — user ID (UUID string).
    pub sub: String,
    /// Audience — the OAuth2 `client_id`.
    pub aud: String,
    /// Expiration (Unix timestamp).
    pub exp: i64,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Nonce echoed from the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Tenant ID (UUID string).
    pub tenant_id: String,
    /// Organization ID (UUID string).
    pub org_id: String,
    /// User email — included only when `email` scope is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Preferred username — included only when `profile` scope is requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
}

/// Issue a signed OIDC ID token (EdDSA / Ed25519).
///
/// The token includes standard OIDC claims plus AXIAM-specific
/// `tenant_id` and `org_id`. Profile/email claims are gated behind
/// the corresponding scopes.
#[allow(clippy::too_many_arguments)]
pub fn issue_id_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    client_id: &str,
    nonce: Option<&str>,
    email: Option<&str>,
    username: Option<&str>,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let has_scope = |s: &str| scopes.iter().any(|sc| sc == s);

    let claims = IdTokenClaims {
        iss: config.effective_issuer().to_owned(),
        sub: user_id.to_string(),
        aud: client_id.to_owned(),
        exp: now + config.access_token_lifetime_secs as i64,
        iat: now,
        nonce: nonce.map(str::to_owned),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        email: if has_scope("email") {
            email.map(str::to_owned)
        } else {
            None
        },
        preferred_username: if has_scope("profile") {
            username.map(str::to_owned)
        } else {
            None
        },
    };

    let key = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Decode and verify an EdDSA JWT access token.
pub fn decode_access_token(
    token: &str,
    config: &AuthConfig,
) -> Result<AccessTokenClaims, AuthError> {
    let key = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[config.effective_issuer()]);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

    jsonwebtoken::decode::<AccessTokenClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            _ => AuthError::TokenInvalid(e.to_string()),
        })
}

/// Validated JWT claims — a newtype proving the token was verified.
///
/// Used by the API layer to extract authenticated context from
/// incoming requests.
#[derive(Debug, Clone)]
pub struct ValidatedClaims(pub AccessTokenClaims);

/// Pre-validated user identity that can be cached in request extensions.
///
/// When the audit middleware (or any other middleware) validates a JWT,
/// it stores a `CachedUserIdentity` so downstream extractors can skip
/// re-verification.
#[derive(Debug, Clone)]
pub struct CachedUserIdentity {
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub org_id: uuid::Uuid,
    pub claims: ValidatedClaims,
}

/// Validate a JWT access token (signature, expiry, issuer) and return
/// the verified claims.
///
/// This is the entry point for request-level authentication
/// middleware. It is purely stateless — no database lookup is
/// performed.
pub fn validate_access_token(
    token: &str,
    config: &AuthConfig,
) -> Result<ValidatedClaims, AuthError> {
    decode_access_token(token, config).map(ValidatedClaims)
}

/// Generate a cryptographically random opaque refresh token
/// (32 bytes → base64url-encoded, no padding).
pub fn generate_refresh_token() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rand::Rng::random(&mut rng);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hash of a raw refresh token, hex-encoded.
///
/// This is the value stored in the database as `session.token_hash`.
pub fn hash_refresh_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate an Ed25519 key pair in PEM format for testing.
    fn test_keypair() -> (String, String) {
        // Use a pre-generated Ed25519 test key pair (PEM).
        // Generated with: openssl genpkey -algorithm Ed25519
        let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";

        let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

        (private_key.into(), public_key.into())
    }

    fn test_config() -> AuthConfig {
        let (priv_pem, pub_pem) = test_keypair();
        AuthConfig {
            jwt_private_key_pem: priv_pem,
            jwt_public_key_pem: pub_pem,
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            jwt_issuer: "axiam-test".into(),
            pepper: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM-Test".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            auth_code_lifetime_secs: 600,
            oauth2_issuer_url: String::new(),
        }
    }

    #[test]
    fn jwt_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        let token = issue_access_token(user_id, tenant_id, org_id, &[], &config).unwrap();
        let claims = decode_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.iss, "axiam-test");
    }

    #[test]
    fn jti_is_unique() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        let t1 = issue_access_token(uid, tid, oid, &[], &config).unwrap();
        let t2 = issue_access_token(uid, tid, oid, &[], &config).unwrap();

        let c1 = decode_access_token(&t1, &config).unwrap();
        let c2 = decode_access_token(&t2, &config).unwrap();
        assert_ne!(c1.jti, c2.jti);
    }

    #[test]
    fn refresh_token_is_url_safe() {
        let token = generate_refresh_token();
        // base64url characters only (A-Z a-z 0-9 - _), no padding.
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // 32 bytes → 43 base64url chars.
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn refresh_token_hash_is_deterministic() {
        let raw = "some-refresh-token";
        assert_eq!(hash_refresh_token(raw), hash_refresh_token(raw));
    }

    #[test]
    fn different_tokens_different_hashes() {
        let h1 = hash_refresh_token("token-a");
        let h2 = hash_refresh_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn client_credentials_token_roundtrip() {
        let config = test_config();
        let client_id = "my-service-client";
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let scopes = vec!["read:data".to_owned(), "write:data".to_owned()];

        let token =
            issue_client_credentials_token(client_id, tenant_id, org_id, &scopes, &config).unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, client_id);
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.scope.as_deref(), Some("read:data write:data"));
    }

    #[test]
    fn client_credentials_token_no_scopes() {
        let config = test_config();
        let token = issue_client_credentials_token(
            "svc-client",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub, "svc-client");
        assert!(claims.scope.is_none());
    }

    #[test]
    fn user_token_has_no_scope_claim() {
        let config = test_config();
        let token =
            issue_access_token(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), &[], &config)
                .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert!(claims.scope.is_none());
    }

    #[test]
    fn user_token_includes_scopes() {
        let config = test_config();
        let scopes = vec!["openid".to_owned(), "email".to_owned()];
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &scopes,
            &config,
        )
        .unwrap();

        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.scope.as_deref(), Some("openid email"),);
    }

    // ------------------------------------------------------------------
    // ID token tests
    // ------------------------------------------------------------------

    /// Helper to decode an ID token with the test public key.
    fn decode_id_token(token: &str, config: &AuthConfig) -> IdTokenClaims {
        let key = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[config.effective_issuer()]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);
        // ID token `aud` is the client_id, not the issuer.
        validation.set_audience(&["test-client"]);
        jsonwebtoken::decode::<IdTokenClaims>(token, &key, &validation)
            .unwrap()
            .claims
    }

    #[test]
    fn id_token_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let scopes = vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ];

        let token = issue_id_token(
            user_id,
            tenant_id,
            org_id,
            "test-client",
            Some("abc123"),
            Some("user@example.com"),
            Some("jdoe"),
            &scopes,
            &config,
        )
        .unwrap();

        let claims = decode_id_token(&token, &config);

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.aud, "test-client");
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.nonce.as_deref(), Some("abc123"));
        assert_eq!(claims.email.as_deref(), Some("user@example.com"),);
        assert_eq!(claims.preferred_username.as_deref(), Some("jdoe"),);
    }

    #[test]
    fn id_token_includes_nonce() {
        let config = test_config();
        let scopes = vec!["openid".to_owned()];

        let with_nonce = issue_id_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-client",
            Some("my-nonce"),
            None,
            None,
            &scopes,
            &config,
        )
        .unwrap();

        let without_nonce = issue_id_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test-client",
            None,
            None,
            None,
            &scopes,
            &config,
        )
        .unwrap();

        let c1 = decode_id_token(&with_nonce, &config);
        assert_eq!(c1.nonce.as_deref(), Some("my-nonce"));

        let c2 = decode_id_token(&without_nonce, &config);
        assert!(c2.nonce.is_none());
    }

    #[test]
    fn id_token_email_scope() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        // With email scope
        let token_with = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            Some("user@example.com"),
            None,
            &["openid".to_owned(), "email".to_owned()],
            &config,
        )
        .unwrap();
        let c = decode_id_token(&token_with, &config);
        assert_eq!(c.email.as_deref(), Some("user@example.com"),);

        // Without email scope
        let token_without = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            Some("user@example.com"),
            None,
            &["openid".to_owned()],
            &config,
        )
        .unwrap();
        let c = decode_id_token(&token_without, &config);
        assert!(c.email.is_none());
    }

    #[test]
    fn id_token_profile_scope() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        // With profile scope
        let token_with = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            None,
            Some("jdoe"),
            &["openid".to_owned(), "profile".to_owned()],
            &config,
        )
        .unwrap();
        let c = decode_id_token(&token_with, &config);
        assert_eq!(c.preferred_username.as_deref(), Some("jdoe"),);

        // Without profile scope
        let token_without = issue_id_token(
            uid,
            tid,
            oid,
            "test-client",
            None,
            None,
            Some("jdoe"),
            &["openid".to_owned()],
            &config,
        )
        .unwrap();
        let c = decode_id_token(&token_without, &config);
        assert!(c.preferred_username.is_none());
    }
}
