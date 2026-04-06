//! gRPC rate limiting via tower-governor (per D-10, D-11).
//!
//! Uses SmartIpKeyExtractor which reads from `x-forwarded-for` and `x-real-ip`
//! metadata headers automatically, falling back to the peer address. This mirrors
//! the XForwardedForKeyExtractor used in the REST API.

use std::sync::Arc;

use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};

/// Concrete type alias for the gRPC GovernorLayer.
///
/// - `K` = SmartIpKeyExtractor — reads client IP from `x-forwarded-for`/`x-real-ip`
/// - `M` = NoOpMiddleware — no rate-limit headers injected into responses (gRPC transport)
/// - `RespBody` = tonic::body::Body — tonic's native streaming body type
pub type GrpcGovernorLayer =
    GovernorLayer<SmartIpKeyExtractor, NoOpMiddleware<QuantaInstant>, tonic::body::Body>;

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

    let config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(authz_per_sec)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("valid GovernorConfig for gRPC rate limiter"),
    );

    GovernorLayer::new(config)
}
