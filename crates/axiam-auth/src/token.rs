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
}

/// Issue a signed EdDSA (Ed25519) JWT access token.
pub fn issue_access_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.jwt_issuer.clone(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti: Uuid::new_v4().to_string(),
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
    validation.set_issuer(&[&config.jwt_issuer]);
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
        }
    }

    #[test]
    fn jwt_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();
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

        let t1 = issue_access_token(uid, tid, oid, &config).unwrap();
        let t2 = issue_access_token(uid, tid, oid, &config).unwrap();

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
}
