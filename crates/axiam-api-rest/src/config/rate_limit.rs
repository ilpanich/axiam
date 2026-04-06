//! Rate limiting configuration loaded from environment variables.

use serde::Deserialize;

/// Rate limit configuration.
/// Environment variables: AXIAM__RATE_LIMIT__LOGIN_PER_MIN, etc.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Max login requests per minute per IP (default: 10).
    pub login_per_min: u32,
    /// Max register requests per minute per IP (default: 5).
    pub register_per_min: u32,
    /// Max oauth2/token requests per minute per client (default: 20).
    pub token_per_min: u32,
    /// Max password-reset requests per minute per IP (default: 3).
    pub password_reset_per_min: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_min: 10,
            register_per_min: 5,
            token_per_min: 20,
            password_reset_per_min: 3,
        }
    }
}

impl RateLimitConfig {
    /// Validates all rate limits are >= 1 (governor panics on zero).
    pub fn validate(&self) {
        assert!(self.login_per_min >= 1, "login_per_min must be >= 1");
        assert!(self.register_per_min >= 1, "register_per_min must be >= 1");
        assert!(self.token_per_min >= 1, "token_per_min must be >= 1");
        assert!(
            self.password_reset_per_min >= 1,
            "password_reset_per_min must be >= 1"
        );
    }
}
