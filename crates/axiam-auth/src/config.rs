//! Authentication configuration.

use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use secrecy::SecretString;
use serde::Deserialize;

fn default_true() -> bool {
    true
}

/// Configuration for the authentication service.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// PEM-encoded Ed25519 private key for JWT signing.
    pub jwt_private_key_pem: String,
    /// PEM-encoded Ed25519 public key for JWT verification.
    pub jwt_public_key_pem: String,
    /// Access token lifetime in seconds (default: 900 = 15 minutes).
    pub access_token_lifetime_secs: u64,
    /// Refresh token lifetime in seconds (default: 2_592_000 = 30 days).
    pub refresh_token_lifetime_secs: u64,
    /// Authorization code lifetime in seconds (default: 600 = 10 minutes).
    pub auth_code_lifetime_secs: u64,
    /// JWT issuer (`iss` claim).
    pub jwt_issuer: String,
    /// OIDC issuer base URL (e.g. "https://auth.example.com"). Used for
    /// OIDC discovery endpoint URLs. Falls back to `jwt_issuer` if unset.
    pub oauth2_issuer_url: String,
    /// Optional pepper prepended to passwords before Argon2id verification.
    /// Wrapped in `SecretString` so `Debug`/logging never leaks it by
    /// accident (SECHRD-12) — exposed only via `.expose_secret()` at the
    /// `&str` boundary where a pepper value is consumed.
    pub pepper: Option<SecretString>,
    /// Minimum password length for policy enforcement.
    pub min_password_length: usize,
    /// 256-bit AES-GCM key for encrypting TOTP secrets at rest.
    /// `None` disables MFA enrollment. Set programmatically (not from config files).
    #[serde(skip)]
    pub mfa_encryption_key: Option<[u8; 32]>,
    /// 256-bit AES-GCM key for encrypting federation client secrets at rest.
    /// `None` means federation config create/update will fail at runtime.
    /// Set programmatically from `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` (not from
    /// config files). Federation is optional — absence is warned, not fatal.
    #[serde(skip)]
    pub federation_encryption_key: Option<[u8; 32]>,
    /// When `true`, access tokens decoded without an `aud` claim are treated as
    /// `axiam:user`. Enables a back-compat window during the Phase 4 rollout
    /// while pre-Phase-4 tokens are still circulating. Default: `true`.
    #[serde(default = "default_true")]
    pub allow_missing_aud_as_user: bool,
    /// When `true` (default), all auth cookies are marked `Secure` and are
    /// therefore sent only over HTTPS. Set `AXIAM__AUTH__COOKIE_SECURE=false`
    /// **only** in local HTTP development (e.g. http://localhost) — **never**
    /// in production or staging (D-18).
    #[serde(default = "default_true")]
    pub cookie_secure: bool,
    /// MFA challenge token lifetime in seconds (default: 300 = 5 minutes).
    pub mfa_challenge_lifetime_secs: u64,
    /// Issuer name shown in authenticator apps.
    pub totp_issuer: String,
    /// Max consecutive failed login attempts before lockout (default: 5).
    pub max_failed_login_attempts: u32,
    /// Initial lockout duration in seconds (default: 900 = 15 min).
    pub lockout_duration_secs: u64,
    /// Exponential backoff multiplier for repeated lockouts (default: 2.0).
    pub lockout_backoff_multiplier: f64,
    /// Maximum lockout duration in seconds (default: 3600 = 1 hour).
    pub max_lockout_duration_secs: u64,
    /// Grace period in hours during which PendingVerification users
    /// can still log in (default: 24). Set to 0 to disable.
    pub email_verification_grace_period_hours: u32,
    /// Password reset token expiry in hours (default: 1).
    pub password_reset_token_expiry_hours: u32,
    /// WebAuthn Relying Party ID (typically the domain name,
    /// e.g. "auth.example.com").
    pub webauthn_rp_id: String,
    /// WebAuthn Relying Party origin
    /// (e.g. "https://auth.example.com").
    pub webauthn_rp_origin: String,
    /// WebAuthn Relying Party display name.
    pub webauthn_rp_name: String,
    /// CQ-B14: Pre-parsed Ed25519 signing key. Populated once at startup via
    /// `resolve_keys()`. When `Some`, token-issue functions skip PEM re-parsing.
    /// When `None`, they fall back to parsing from `jwt_private_key_pem`.
    #[serde(skip)]
    pub jwt_encoding_key: Option<Arc<EncodingKey>>,
    /// CQ-B14: Pre-parsed Ed25519 verification key. Populated once at startup via
    /// `resolve_keys()`. When `Some`, token-verify functions skip PEM re-parsing.
    /// When `None`, they fall back to parsing from `jwt_public_key_pem`.
    #[serde(skip)]
    pub jwt_decoding_key: Option<Arc<DecodingKey>>,
}

impl AuthConfig {
    /// Effective issuer for JWT `iss` claims and OIDC discovery.
    ///
    /// Returns `oauth2_issuer_url` when set, falling back to
    /// `jwt_issuer`. Trailing slashes are stripped so that the
    /// OIDC discovery `issuer` exactly matches token `iss` claims
    /// (OIDC Core §2 requires an exact string match).
    pub fn effective_issuer(&self) -> &str {
        if self.oauth2_issuer_url.is_empty() {
            self.jwt_issuer.trim_end_matches('/')
        } else {
            self.oauth2_issuer_url.trim_end_matches('/')
        }
    }

    /// CQ-B14: Parse Ed25519 keys from PEM once and cache in `Arc`.
    ///
    /// Call this once at startup after loading config from environment.
    /// After this returns `Ok(())`, all token functions skip per-call PEM
    /// parsing and use the cached keys instead.
    pub fn resolve_keys(&mut self) -> Result<(), String> {
        let enc = EncodingKey::from_ed_pem(self.jwt_private_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT private key PEM: {e}"))?;
        let dec = DecodingKey::from_ed_pem(self.jwt_public_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT public key PEM: {e}"))?;
        self.jwt_encoding_key = Some(Arc::new(enc));
        self.jwt_decoding_key = Some(Arc::new(dec));
        Ok(())
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_private_key_pem: String::new(),
            jwt_public_key_pem: String::new(),
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            auth_code_lifetime_secs: 600,
            jwt_issuer: "axiam".into(),
            oauth2_issuer_url: String::new(),
            pepper: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 900,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
        }
    }
}
