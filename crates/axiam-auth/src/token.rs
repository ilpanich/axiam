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

/// Audience value for user-facing access tokens (issued by the login/refresh
/// flow — `sub` is a user UUID).
pub const AUD_USER: &str = "axiam:user";

/// Audience value for M2M / service-account access tokens (issued by the
/// OAuth2 Client Credentials grant — `sub` is a `client_id` string).
pub const AUD_M2M: &str = "axiam:m2m";

/// Self-describing subject kind carried by an access token (FUNC-04).
///
/// Informational only (D-10) — no validator or authz path branches on this
/// claim; it exists so SDK modeling and audit attribution can distinguish
/// which kind of subject minted the token. Tokens issued before this claim
/// existed have no `sub_kind` key and deserialize to [`SubjectKind::User`]
/// via `#[serde(default)]` on [`AccessTokenClaims::sub_kind`] (D-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A human user authenticated via password/social login/MFA.
    #[default]
    User,
    /// A service account authenticated via mTLS client certificate
    /// (device-auth cert-auth path).
    ServiceAccount,
    /// An OAuth2 client authenticated via the Client Credentials grant.
    OAuth2Client,
}

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
    /// Unique token ID.
    ///
    /// For tokens issued from Phase 4 onward this equals the `session.id` of
    /// the issuing session (user flow) or a random UUIDv4 (M2M / no session
    /// row). Pre-Phase-4 tokens carry a random UUID here — D-15 session
    /// revocation tolerates this by treating the jti-to-session relationship
    /// as advisory.
    pub jti: String,
    /// Token audience — `"axiam:user"` or `"axiam:m2m"`.
    ///
    /// `None` means the token was issued before Phase 4 and should be treated
    /// as `axiam:user` when `AuthConfig.allow_missing_aud_as_user` is `true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// OAuth2 scopes (space-separated string). Present when non-empty
    /// scopes are granted — both Client Credentials and Authorization
    /// Code flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Self-describing subject kind (FUNC-04, D-09/D-10/D-11).
    ///
    /// Always serialized when a token is issued. Missing on decode (a
    /// pre-phase token) defaults to [`SubjectKind::User`]. Informational
    /// only — does not affect validation or authorization decisions.
    #[serde(default)]
    pub sub_kind: SubjectKind,
}

/// Issue a signed EdDSA (Ed25519) JWT access token.
///
/// `jti` should be the `session.id` of the issuing session (pass
/// `session.id.to_string()`). This enables stateless session revocation
/// checks in D-15 without a DB lookup.
///
/// `aud` should be [`AUD_USER`] for user-facing tokens.
///
/// When `scopes` is non-empty a space-separated `scope` claim is
/// included in the token; otherwise the claim is omitted.
pub fn issue_access_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
    jti: String,
    aud: &str,
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
        jti,
        aud: Some(aud.to_string()),
        scope,
        sub_kind: SubjectKind::User,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue a JWT access token for OAuth2 Client Credentials grant (M2M).
///
/// The `sub` claim is the OAuth2 `client_id` (not a user UUID).
/// `jti` is a random UUID — service accounts have no session row.
/// `aud` is set to [`AUD_M2M`].
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
        aud: Some(AUD_M2M.to_string()),
        scope,
        sub_kind: SubjectKind::OAuth2Client,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Issue a JWT access token for a service account authenticated via mTLS
/// client certificate (device-auth cert-auth path, resolving `TODO(T15)`).
///
/// The `sub` claim is the service account's `user_id` (mirrors the shape
/// the device-auth handler previously passed to [`issue_access_token`]).
/// `jti` is caller-supplied — service-account/device auth has no session
/// row, so callers pass a random UUID. `aud` and `scope` mirror the values
/// the device-auth call previously passed to `issue_access_token`
/// ([`AUD_USER`], no scopes) — only `sub_kind` differs (D-09). This claim
/// is informational only (D-10): validation and authz are unaffected.
pub fn issue_service_account_token(
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    jti: String,
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();

    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti,
        aud: Some(AUD_USER.to_string()),
        scope: None,
        sub_kind: SubjectKind::ServiceAccount,
    };

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
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

    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };

    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}

/// Decode and verify an EdDSA JWT access token.
///
/// Audience validation: when `aud` is present it must be either
/// [`AUD_USER`] or [`AUD_M2M`]. When `aud` is absent (pre-Phase-4 token)
/// the library skips the audience check, preserving backward compatibility
/// during the rollout window. Per-route narrowing to a specific audience
/// happens in plan 04-04.
pub fn decode_access_token(
    token: &str,
    config: &AuthConfig,
) -> Result<AccessTokenClaims, AuthError> {
    // CQ-B14: Use pre-parsed key cache when available; fall back to PEM parsing.
    let owned;
    let key: &DecodingKey = if let Some(ref cached) = config.jwt_decoding_key {
        cached.as_ref()
    } else {
        owned = DecodingKey::from_ed_pem(config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;
        &owned
    };

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[config.effective_issuer()]);
    // Do NOT require `aud` — pre-Phase-4 tokens omit it (D-20 back-compat).
    validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);
    // Accept both user and M2M audiences; presence is checked for membership
    // only when the claim exists (jsonwebtoken skips aud check when token has
    // no `aud` claim and validate_aud=true with a configured audience set).
    validation.set_audience(&[AUD_USER, AUD_M2M]);
    validation.leeway = 60;

    jsonwebtoken::decode::<AccessTokenClaims>(token, key, &validation)
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
        let private_key = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key

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
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM-Test".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            auth_code_lifetime_secs: 600,
            oauth2_issuer_url: String::new(),
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM-Test".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
            hibp_breaker_threshold: 5,
            hibp_breaker_cooldown_secs: 30,
        }
    }

    #[test]
    fn jwt_roundtrip() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let jti = Uuid::new_v4().to_string();

        let token = issue_access_token(
            user_id,
            tenant_id,
            org_id,
            &[],
            &config,
            jti.clone(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.iss, "axiam-test");
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.aud, Some(AUD_USER.to_string()));
    }

    #[test]
    fn jti_equals_session_id() {
        // D-15: jti must equal the issuing session.id so revocation can be
        // performed statlessly without a DB lookup.
        let config = test_config();
        let session_id = "00000000-0000-0000-0000-000000000001".to_string();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            session_id.clone(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.jti, session_id);
        assert_eq!(claims.aud, Some("axiam:user".to_string()));
    }

    #[test]
    fn jti_is_unique() {
        let config = test_config();
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let oid = Uuid::new_v4();

        let t1 = issue_access_token(
            uid,
            tid,
            oid,
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();
        let t2 = issue_access_token(
            uid,
            tid,
            oid,
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();

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
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
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
            Uuid::new_v4().to_string(),
            AUD_USER,
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

    // ------------------------------------------------------------------
    // sub_kind tests (FUNC-04, D-09/D-10/D-11)
    // ------------------------------------------------------------------

    #[test]
    fn missing_sub_kind_defaults_to_user() {
        // D-11: a pre-phase token payload with no `sub_kind` key must still
        // deserialize successfully, defaulting to `SubjectKind::User`.
        let json = r#"{
            "sub": "some-subject",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "org_id": "00000000-0000-0000-0000-000000000002",
            "iss": "axiam-test",
            "iat": 0,
            "exp": 9999999999,
            "jti": "00000000-0000-0000-0000-000000000003"
        }"#;
        let claims: AccessTokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub_kind, SubjectKind::User);
    }

    #[test]
    fn issue_access_token_stamps_user_sub_kind() {
        let config = test_config();
        let token = issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            &config,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap();
        let claims = decode_access_token(&token, &config).unwrap();
        assert_eq!(claims.sub_kind, SubjectKind::User);
    }

    #[test]
    fn issue_client_credentials_token_stamps_oauth2_client_sub_kind() {
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
        assert_eq!(claims.sub_kind, SubjectKind::OAuth2Client);
    }

    #[test]
    fn issue_service_account_token_stamps_service_account_sub_kind() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let jti = Uuid::new_v4().to_string();

        let token =
            issue_service_account_token(user_id, tenant_id, org_id, jti.clone(), &config).unwrap();
        let claims = decode_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.tenant_id, tenant_id.to_string());
        assert_eq!(claims.org_id, org_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.sub_kind, SubjectKind::ServiceAccount);
    }

    #[test]
    fn validate_access_token_accepts_service_account_token() {
        // D-10: sub_kind is informational only — validation must not reject
        // (or otherwise treat differently) a ServiceAccount-kinded token.
        let config = test_config();
        let token = issue_service_account_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4().to_string(),
            &config,
        )
        .unwrap();

        let validated = validate_access_token(&token, &config).unwrap();
        assert_eq!(validated.0.sub_kind, SubjectKind::ServiceAccount);
    }
}
