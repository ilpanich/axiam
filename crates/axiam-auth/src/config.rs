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
    /// Max consecutive failed login attempts before lockout (default: 5).
    pub max_failed_login_attempts: u32,
    /// Initial lockout duration in seconds (default: 300 = 5 min).
    pub lockout_duration_secs: u64,
    /// Exponential backoff multiplier for repeated lockouts (default: 2.0).
    pub lockout_backoff_multiplier: f64,
    /// Maximum lockout duration in seconds (default: 3600 = 1 hour).
    pub max_lockout_duration_secs: u64,
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
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
        }
    }
}
