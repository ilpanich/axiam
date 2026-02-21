//! Authentication configuration.

/// Configuration for the authentication service.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// PEM-encoded Ed25519 private key for JWT signing.
    pub jwt_private_key_pem: String,
    /// PEM-encoded Ed25519 public key for JWT verification.
    pub jwt_public_key_pem: String,
    /// Access token lifetime in seconds (default: 900 = 15 minutes).
    pub access_token_lifetime_secs: u64,
    /// Refresh token lifetime in seconds (default: 2_592_000 = 30 days).
    pub refresh_token_lifetime_secs: u64,
    /// JWT issuer (`iss` claim).
    pub jwt_issuer: String,
    /// Optional pepper prepended to passwords before Argon2id verification.
    pub pepper: Option<String>,
    /// Minimum password length for policy enforcement.
    pub min_password_length: usize,
    /// 256-bit AES-GCM key for encrypting TOTP secrets at rest.
    /// `None` disables MFA enrollment.
    pub mfa_encryption_key: Option<[u8; 32]>,
    /// MFA challenge token lifetime in seconds (default: 300 = 5 minutes).
    pub mfa_challenge_lifetime_secs: u64,
    /// Issuer name shown in authenticator apps.
    pub totp_issuer: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_private_key_pem: String::new(),
            jwt_public_key_pem: String::new(),
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            jwt_issuer: "axiam".into(),
            pepper: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM".into(),
        }
    }
}
