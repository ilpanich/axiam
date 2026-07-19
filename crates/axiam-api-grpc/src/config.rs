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

impl GrpcConfig {
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
