//! Rate limiting configuration loaded from environment variables.

use serde::Deserialize;

/// Rate-limit bucket-key derivation mode (D8).
///
/// Environment variable: `AXIAM__RATE_LIMIT__KEY` = `ip` | `client_id` |
/// `ip_client_id` (default `ip`).
///
/// **Why this exists (NAT'd-fleet lesson):** the bucket key was
/// unconditionally `"{endpoint}:{ip}"` (see
/// `middleware::rate_limit_shared::RateLimitShared` and
/// `extractors::rate_limit::XForwardedForKeyExtractor`). Behind a NAT/proxy
/// fleet (many distinct OAuth2 clients — e.g. IoT devices or microservices —
/// egressing through one shared IP), every client sharing that IP collided
/// into a SINGLE bucket, so one noisy/misbehaving client could exhaust the
/// `/oauth2/token`, `/oauth2/revoke`, or `/oauth2/introspect` quota for every
/// other client behind the same NAT gateway. `client_id` and `ip_client_id`
/// give each OAuth2 client its own bucket (optionally still scoped per-IP)
/// on the endpoints where a client identity is actually known.
///
/// **Scope — where this setting applies:** ONLY the three endpoints where an
/// OAuth2 client authenticates itself via a form-encoded `client_id`
/// (`client_secret_post`, RFC 6749 §2.3.1): `/oauth2/token`,
/// `/oauth2/revoke`, `/oauth2/introspect` (see `handlers::oauth2` and
/// `server.rs`'s wiring of `RateLimitShared::new_client_identity_aware` /
/// the client-aware governor for exactly those three resources).
///
/// **`/auth/login` (and every other rate-limited endpoint) ALWAYS keys
/// per-IP, regardless of this setting.** Login authenticates a *user* via
/// username/password — there is no OAuth2 client identity anywhere in that
/// request, so there is nothing meaningful to key on besides the source IP.
/// This is intentional and NOT a bug: switching this config value never
/// changes login's (or MFA's, or password-reset's, etc.) rate-limit
/// behavior. See `server.rs` — those resources are wired with the plain
/// `build_governor`/`RateLimitShared::new` constructors, which never read
/// this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyMode {
    /// Key on source IP only (current/default behavior, unchanged).
    #[default]
    Ip,
    /// Key on the OAuth2 `client_id` alone — independent buckets per client,
    /// regardless of which IP(s) it connects from.
    ClientId,
    /// Key on the `(ip, client_id)` pair — independent buckets per client
    /// AND per IP, so a compromised/leaked client credential rate-limited
    /// from one IP doesn't automatically throttle the same client_id
    /// operating legitimately from a different IP.
    IpClientId,
}

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
    /// Max MFA requests per minute per IP (default: 5).
    /// Covers /auth/mfa/enroll, /confirm, /verify, /setup/enroll, /setup/confirm (SEC-020).
    pub mfa_per_min: u32,
    /// Max oauth2/introspect requests per minute per IP (default: 10).
    /// SEC-020: introspect endpoint rate-limited to prevent token probing.
    pub introspect_per_min: u32,
    /// Max oauth2/revoke requests per minute per IP (default: 10).
    /// SEC-020: revoke endpoint rate-limited to prevent DoS via token flooding.
    pub revoke_per_min: u32,
    /// Max authz-check requests per minute per IP (default: 300).
    /// Authz checks are read-only and high-frequency — used by UI permission gating.
    /// Kept in a dedicated bucket so heavy UI use does not consume the login/token limit (D-07).
    pub authz_check_per_min: u32,
    /// Rate-limit bucket-key derivation mode (D8, default: `Ip` — current
    /// behavior, unchanged). See [`RateLimitKeyMode`] for the full
    /// rationale and scope (only `/oauth2/token`, `/oauth2/revoke`,
    /// `/oauth2/introspect` honor this; `/auth/login` and every other
    /// endpoint always stay per-IP).
    pub key: RateLimitKeyMode,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_min: 10,
            register_per_min: 5,
            token_per_min: 20,
            password_reset_per_min: 3,
            mfa_per_min: 5,
            introspect_per_min: 10,
            revoke_per_min: 10,
            authz_check_per_min: 300,
            key: RateLimitKeyMode::Ip,
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
        assert!(self.mfa_per_min >= 1, "mfa_per_min must be >= 1");
        assert!(
            self.introspect_per_min >= 1,
            "introspect_per_min must be >= 1"
        );
        assert!(self.revoke_per_min >= 1, "revoke_per_min must be >= 1");
        assert!(
            self.authz_check_per_min >= 1,
            "authz_check_per_min must be >= 1"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D8 acceptance: default behavior (`ip`) is unchanged — a
    /// freshly-defaulted config must key exactly the way it did before this
    /// field existed.
    #[test]
    fn default_key_mode_is_ip() {
        assert_eq!(RateLimitConfig::default().key, RateLimitKeyMode::Ip);
        assert_eq!(RateLimitKeyMode::default(), RateLimitKeyMode::Ip);
    }

    /// `AXIAM__RATE_LIMIT__KEY` values must map onto exactly `ip`,
    /// `client_id`, `ip_client_id` via serde `snake_case` — this is what the
    /// `config` crate's `Environment` source (see `axiam-server::main`)
    /// deserializes the raw env var string against.
    #[test]
    fn key_mode_deserializes_from_documented_env_values() {
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"ip\"").unwrap(),
            RateLimitKeyMode::Ip
        );
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"client_id\"").unwrap(),
            RateLimitKeyMode::ClientId
        );
        assert_eq!(
            serde_json::from_str::<RateLimitKeyMode>("\"ip_client_id\"").unwrap(),
            RateLimitKeyMode::IpClientId
        );
    }
}
