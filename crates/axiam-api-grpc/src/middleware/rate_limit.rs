//! gRPC rate limiting via tower-governor (per D-10, D-11), brought to parity
//! with the fixed REST limiter's key-extraction logic (SECHRD-03, D-01c).
//!
//! [`GrpcTrustedHopsKeyExtractor`] is a custom `tower_governor::KeyExtractor`
//! that replaces `SmartIpKeyExtractor`. `SmartIpKeyExtractor` unconditionally
//! trusts the LEFTMOST `X-Forwarded-For` hop and, more fundamentally, can
//! never find tonic's real peer address at all (it only looks for an
//! `axum::extract::ConnectInfo<SocketAddr>` extension or a bare `SocketAddr`
//! extension — tonic inserts `TcpConnectInfo`/`TlsConnectInfo<TcpConnectInfo>`
//! instead). This extractor mirrors the fixed REST `XForwardedForKeyExtractor`
//! (plan 24-03): a configured `trusted_hops` selects the rightmost trusted
//! XFF hop, and when there are NOT enough hops to trust, XFF is ignored
//! entirely and the verified tonic connection peer address is used instead
//! (never `hops[0]` — SECHRD-03/D-01d).
//!
//! HARD CONSTRAINT (D-01c coordination note): the `Quota::per_second(...)
//! .burst_size(...)` throughput/quota math in [`build_grpc_governor_layer`]
//! is untouched by this module — CORR-01/Phase 26 owns it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use http::Request;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tower_governor::{
    GovernorLayer, errors::GovernorError, governor::GovernorConfigBuilder,
    key_extractor::KeyExtractor,
};

/// Reads the SAME `AXIAM__RATE_LIMIT__TRUSTED_HOPS` env var the REST shared
/// pre-check (`axiam-api-rest::middleware::rate_limit_shared::trusted_hops`)
/// and `server.rs::build_governor` use, so the gRPC key and the REST key are
/// derived identically from the same deployment-topology configuration.
fn trusted_hops_from_env() -> usize {
    std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Extracts the gRPC caller's IP from `X-Forwarded-For`, falling back to the
/// verified tonic connection peer address (`TcpConnectInfo`/
/// `TlsConnectInfo<TcpConnectInfo>`).
///
/// `trusted_hops` controls how many rightmost XFF entries are trusted
/// reverse-proxy hops to skip (mirrors
/// `axiam-api-rest::extractors::rate_limit::XForwardedForKeyExtractor`).
/// When `trusted_hops >= hops.len()`, the header is NOT trusted at all and
/// XFF is ignored entirely — the key is derived from the verified peer
/// address instead (a client cannot manufacture extra hops to force a
/// fallback to an attacker-controlled `hops[0]` — SECHRD-03/D-01d).
#[derive(Debug, Clone, Default)]
pub struct GrpcTrustedHopsKeyExtractor {
    pub trusted_hops: usize,
}

impl GrpcTrustedHopsKeyExtractor {
    /// Create an extractor keyed by `trusted_hops` trusted reverse-proxy
    /// hops (0 = no trusted hops; XFF is only ever used when it has more
    /// than 0 entries beyond what's trusted).
    pub fn new(trusted_hops: usize) -> Self {
        Self { trusted_hops }
    }
}

impl KeyExtractor for GrpcTrustedHopsKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        if let Some(forwarded_for) = req.headers().get("x-forwarded-for")
            && let Ok(val) = forwarded_for.to_str()
        {
            let hops: Vec<&str> = val.split(',').map(str::trim).collect();
            // Select the rightmost-untrusted hop (parity with REST).
            if self.trusted_hops < hops.len() {
                let idx = hops.len() - 1 - self.trusted_hops;
                if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
            // Fewer hops than trusted_hops requires: the header cannot be
            // trusted. Fall through to the verified peer address below
            // instead of indexing into XFF (SECHRD-03 — no `hops[0]`
            // fallback that would let a rotating XFF mint a fresh bucket).
        }

        grpc_peer_addr(req)
            .map(|addr| addr.ip())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Reads the verified tonic connection peer address from request
/// extensions, mirroring `tonic::Request::remote_addr()`'s own lookup
/// (`TcpConnectInfo` for plaintext, `TlsConnectInfo<TcpConnectInfo>` for TLS)
/// — the extension types tonic's `ConnectInfoLayer` actually inserts (NOT
/// the `axum::extract::ConnectInfo<SocketAddr>` / bare `SocketAddr`
/// extensions `SmartIpKeyExtractor` looks for, which tonic never sets).
fn grpc_peer_addr<T>(req: &Request<T>) -> Option<SocketAddr> {
    req.extensions()
        .get::<TcpConnectInfo>()
        .and_then(TcpConnectInfo::remote_addr)
        .or_else(|| {
            req.extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .and_then(|info| info.get_ref().remote_addr())
        })
}

/// Concrete type alias for the gRPC GovernorLayer.
///
/// - `K` = [`GrpcTrustedHopsKeyExtractor`] — trusted_hops-aware, keys off the
///   verified peer address when XFF hops are insufficient (SECHRD-03).
/// - `M` = NoOpMiddleware — no rate-limit headers injected into responses (gRPC transport)
/// - `RespBody` = tonic::body::Body — tonic's native streaming body type
pub type GrpcGovernorLayer =
    GovernorLayer<GrpcTrustedHopsKeyExtractor, NoOpMiddleware<QuantaInstant>, tonic::body::Body>;

/// Build a [`GovernorLayer`] for gRPC server-wide rate limiting.
///
/// The layer uses token-bucket semantics (via the `governor` crate) with one
/// token replenished per second and a burst allowance of `authz_per_sec` tokens.
/// For service-mesh patterns where the authz endpoint is called on every request,
/// the default of 100 tokens/sec is intentionally generous.
///
/// # Panics
///
/// Panics at startup if `authz_per_sec` is 0 — the governor crate requires a
/// non-zero burst size.
pub fn build_grpc_governor_layer(authz_per_sec: u32) -> GrpcGovernorLayer {
    assert!(authz_per_sec >= 1, "grpc_authz_per_sec must be >= 1");

    // CQ-B44: was `.per_second(1).burst_size(authz_per_sec)` — the hardcoded
    // `per_second(1)` meant the rate was 1 req/s regardless of `authz_per_sec`.
    // Fixed: replenish `authz_per_sec` tokens per second with 2× burst.
    // SECHRD-03/D-01c: key extractor swapped to GrpcTrustedHopsKeyExtractor
    // for IP-spoofing resistance parity with REST — this throughput/quota
    // math is otherwise untouched (CORR-01/Phase 26 owns it).
    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(authz_per_sec as u64)
            .burst_size(authz_per_sec * 2)
            .key_extractor(GrpcTrustedHopsKeyExtractor::new(trusted_hops_from_env()))
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );

    GovernorLayer::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with_xff(xff: Option<&str>) -> Request<()> {
        let mut builder = Request::builder();
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        builder.body(()).unwrap()
    }

    fn req_with_xff_and_peer(xff: Option<&str>, peer: SocketAddr) -> Request<()> {
        let mut req = req_with_xff(xff);
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer),
        });
        req
    }

    #[test]
    fn uses_rightmost_trusted_xff_hop_when_enough_hops_present() {
        // trusted_hops=1, 3 hops present -> index = 3 - 1 - 1 = 1
        let extractor = GrpcTrustedHopsKeyExtractor::new(1);
        let req = req_with_xff(Some("203.0.113.9, 198.51.100.7, 192.0.2.1"));

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_peer_addr_when_trusted_hops_exceeds_hop_count() {
        // SECHRD-03/D-01d: trusted_hops(1) >= hops.len()(1) => XFF is
        // completely untrusted; a rotating single-hop XFF must NOT be used
        // (never `hops[0]`) — fall through to the verified peer address.
        let extractor = GrpcTrustedHopsKeyExtractor::new(1);
        let peer: SocketAddr = "203.0.113.42:1234".parse().unwrap();

        let req1 = req_with_xff_and_peer(Some("198.51.100.1"), peer);
        let req2 = req_with_xff_and_peer(Some("6.6.6.6"), peer);

        let key1 = extractor.extract(&req1).unwrap();
        let key2 = extractor.extract(&req2).unwrap();

        assert_eq!(key1, peer.ip());
        assert_eq!(key2, peer.ip());
        assert_eq!(key1, key2, "rotating XFF must not yield a fresh key");
    }

    #[test]
    fn errors_when_no_xff_and_no_peer_info() {
        let extractor = GrpcTrustedHopsKeyExtractor::new(0);
        let req = req_with_xff(None);

        assert!(matches!(
            extractor.extract(&req),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
