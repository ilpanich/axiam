//! gRPC server configuration.

use std::net::SocketAddr;

use serde::Deserialize;

/// gRPC rate-limit bucket-key mode (D8 parity with
/// `axiam_api_rest::config::rate_limit::RateLimitKeyMode`).
///
/// **Currently a no-op / reserved for forward compatibility.** The only
/// gRPC surface wrapped by the rate-limit layers today
/// (`middleware::rate_limit::{build_grpc_governor_layer,
/// GrpcSharedRateLimitLayer}`) is the low-latency, service-mesh-wide authz
/// check (`AuthorizationService`) — those layers are `Server::builder()`-
/// wide `tower::Layer`s that run BEFORE tonic resolves any per-RPC
/// authenticated identity (`ValidatedClaims`, inserted by each service's
/// own `with_interceptor(...)` auth interceptor — see `server.rs`). There is
/// therefore no client identity available at the point these layers key a
/// request, structurally identical to why REST's `/auth/login` always stays
/// per-IP (see `axiam_api_rest::config::rate_limit::RateLimitKeyMode`
/// docs). Setting this to anything other than `Ip` has no observable effect
/// yet; it exists so `AXIAM__GRPC__KEY` round-trips through config the same
/// way `AXIAM__RATE_LIMIT__KEY` does on the REST side, and so a future
/// per-RPC client-identity-aware interceptor (re-ordering the auth
/// interceptor ahead of the rate-limit layer for `TokenService`'s
/// `introspect_token`/`validate_token`, which DO have a caller identity via
/// `ValidatedClaims.sub`) has a config surface to land on without another
/// env var rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcRateLimitKeyMode {
    /// Key on source IP only (current and only implemented behavior).
    #[default]
    Ip,
    /// Reserved (D8 parity) — not yet wired to any gRPC surface; behaves
    /// identically to `Ip` today.
    ClientId,
    /// Reserved (D8 parity) — not yet wired to any gRPC surface; behaves
    /// identically to `Ip` today.
    IpClientId,
}

/// Configuration for the gRPC server.
#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Max gRPC authz requests per second per IP (default: 100).
    /// Generous for service-mesh patterns where authz is called per-request.
    /// Configure via AXIAM__GRPC__GRPC_AUTHZ_PER_SEC env var.
    #[serde(default = "default_grpc_authz_per_sec")]
    pub grpc_authz_per_sec: u32,
    /// D8 parity field — see [`GrpcRateLimitKeyMode`]. Currently always
    /// behaves as `Ip` regardless of value; reserved for a future per-RPC
    /// client-identity-aware rate limiter. Configure via `AXIAM__GRPC__KEY`.
    #[serde(default)]
    pub key: GrpcRateLimitKeyMode,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            grpc_authz_per_sec: default_grpc_authz_per_sec(),
            key: GrpcRateLimitKeyMode::Ip,
        }
    }
}

/// `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` — presence pins
/// [`GrpcConfig::grpc_authz_per_sec`] against a posture preset.
pub const ENV_GRPC_AUTHZ_PER_SEC: &str = "AXIAM__GRPC__GRPC_AUTHZ_PER_SEC";

impl GrpcConfig {
    /// G7: applies the deployment rate-limit posture preset's gRPC authz
    /// ceiling, reading the process environment.
    ///
    /// The preset values live in ONE place —
    /// `axiam_api_rest::config::rate_limit::RateLimitProfile::preset()` — and
    /// are handed here by the composition root (`axiam-server::main`) so the
    /// whole `AXIAM__RATE_LIMIT__PROFILE` family (REST + gRPC) moves
    /// coherently from a single operator-facing env var. This crate
    /// deliberately does not own a second copy of the numbers.
    ///
    /// Returns `true` when the preset was applied, `false` when the operator
    /// pinned [`ENV_GRPC_AUTHZ_PER_SEC`] explicitly (explicit env always wins).
    ///
    /// **Keying caveat:** the gRPC limiter is per-IP only — there is no
    /// client identity at the layer that keys it (see
    /// [`GrpcRateLimitKeyMode`]). Behind a shared NAT/ingress IP this is a
    /// *fleet-wide* ceiling, not a per-client one; that is exactly why the
    /// M2M presets raise it.
    pub fn apply_rate_limit_preset_from_env(&mut self, per_sec: u32) -> bool {
        self.apply_rate_limit_preset(per_sec, |name| std::env::var_os(name).is_some())
    }

    /// [`GrpcConfig::apply_rate_limit_preset_from_env`] with the environment
    /// lookup injected, for tests.
    pub fn apply_rate_limit_preset<F>(&mut self, per_sec: u32, is_set: F) -> bool
    where
        F: Fn(&str) -> bool,
    {
        if is_set(ENV_GRPC_AUTHZ_PER_SEC) {
            false
        } else {
            self.grpc_authz_per_sec = per_sec;
            true
        }
    }

    pub fn bind_address(&self) -> SocketAddr {
        let addr = format!("{}:{}", self.host, self.port);
        addr.parse()
            .unwrap_or_else(|e| panic!("invalid gRPC bind address '{addr}': {e}"))
    }
}

/// Default gRPC bind host.
///
/// Binds to loopback (`127.0.0.1`) so the gRPC API is not exposed on
/// all interfaces unless explicitly configured. Deploy behind mTLS or
/// an internal network when binding to `0.0.0.0`.
fn default_host() -> String {
    "127.0.0.1".into()
}

fn default_port() -> u16 {
    50051
}

fn default_grpc_authz_per_sec() -> u32 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_key_mode_is_ip() {
        assert_eq!(GrpcConfig::default().key, GrpcRateLimitKeyMode::Ip);
        assert_eq!(GrpcRateLimitKeyMode::default(), GrpcRateLimitKeyMode::Ip);
    }

    /// G7 single-source-of-truth guard: the gRPC shipped default written
    /// down in `docs/deployment/rate-limit-sizing.md` must equal
    /// [`GrpcConfig::default`]. (The `gateway`/`mesh` columns of the same
    /// row are checked against the preset table on the REST side, which
    /// owns the numbers — see
    /// `axiam_api_rest::config::rate_limit::tests::documented_presets_match_applied_profiles`.)
    #[test]
    fn documented_grpc_default_matches_shipped_config() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs/deployment/rate-limit-sizing.md");
        let md = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{} must be readable: {e}", path.display()));
        let row = md
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(&format!("| `{ENV_GRPC_AUTHZ_PER_SEC}`")))
            .unwrap_or_else(|| panic!("{} must document {ENV_GRPC_AUTHZ_PER_SEC}", path.display()));
        let documented: u32 = row
            .trim_matches('|')
            .split('|')
            .nth(1)
            .expect("posture row has an `internet` column")
            .trim()
            .parse()
            .expect("`internet` column is a plain integer");
        assert_eq!(
            documented,
            GrpcConfig::default().grpc_authz_per_sec,
            "docs/deployment/rate-limit-sizing.md disagrees with GrpcConfig::default()"
        );
    }

    /// G7: the preset only lands when the operator has NOT pinned
    /// `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` — explicit env always wins.
    #[test]
    fn rate_limit_preset_applies_only_when_env_unset() {
        let mut cfg = GrpcConfig::default();
        assert_eq!(cfg.grpc_authz_per_sec, 100);
        assert!(cfg.apply_rate_limit_preset(1_000, |_| false));
        assert_eq!(cfg.grpc_authz_per_sec, 1_000);

        let mut pinned = GrpcConfig::default();
        assert!(!pinned.apply_rate_limit_preset(1_000, |n| n == ENV_GRPC_AUTHZ_PER_SEC));
        assert_eq!(pinned.grpc_authz_per_sec, 100);
    }

    #[test]
    fn key_mode_deserializes_from_documented_env_values() {
        assert_eq!(
            serde_json::from_str::<GrpcRateLimitKeyMode>("\"ip\"").unwrap(),
            GrpcRateLimitKeyMode::Ip
        );
        assert_eq!(
            serde_json::from_str::<GrpcRateLimitKeyMode>("\"client_id\"").unwrap(),
            GrpcRateLimitKeyMode::ClientId
        );
        assert_eq!(
            serde_json::from_str::<GrpcRateLimitKeyMode>("\"ip_client_id\"").unwrap(),
            GrpcRateLimitKeyMode::IpClientId
        );
    }
}
