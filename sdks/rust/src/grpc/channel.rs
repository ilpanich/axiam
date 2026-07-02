//! Shared lazily-connected `tonic::Channel` (D-04, RESEARCH.md Pitfall 5).
//!
//! Built once via `Endpoint::from_shared(base_url)?.connect_lazy()` — no
//! network I/O (no TCP/TLS handshake) happens until the first RPC call.
//! The resulting `Channel` is `Clone + Send + Sync` and is reused across
//! every RPC made through the client (never reconstructed per-call).
//!
//! CONTRACT.md §6: TLS verification is always strict by default. The only
//! escape hatch is a custom CA certificate (PEM) added to the verification
//! chain — there is deliberately no API surface here that disables or skips
//! certificate verification.

use std::time::Duration;

use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::AxiamError;

/// Default gRPC connect timeout (D-14), mirroring the REST transport's
/// default in `src/client.rs`.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default gRPC per-request timeout (D-14).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for constructing the shared gRPC channel. Mirrors the subset of
/// `AxiamClientBuilder` (`src/client.rs`) settings relevant to gRPC: base
/// URL, timeouts, and an optional custom CA PEM (§6's one and only TLS
/// escape hatch — never an insecure/skip-verification surface).
#[derive(Debug, Clone, Default)]
pub struct GrpcChannelConfig {
    pub connect_timeout: Option<Duration>,
    pub request_timeout: Option<Duration>,
    /// PEM-encoded custom CA certificate bytes (§6). `None` means: verify
    /// strictly against the platform's native trust store only.
    pub custom_ca_pem: Option<Vec<u8>>,
}

/// Build the single, lazily-connected `tonic::Channel` for `base_url`.
///
/// No network I/O occurs here — the first actual RPC call triggers the
/// TCP+TLS handshake (Pitfall 5). Store the returned `Channel` once and
/// clone it for every RPC; never call this function per-call.
pub fn build_channel(base_url: &str, config: &GrpcChannelConfig) -> Result<Channel, AxiamError> {
    let mut endpoint =
        Endpoint::from_shared(base_url.to_string()).map_err(|e| AxiamError::Network {
            message: format!("invalid gRPC base_url: {e}"),
            source: Some(Box::new(e)),
        })?;

    endpoint = endpoint
        .connect_timeout(config.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT))
        .timeout(config.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));

    // §6: strict TLS verification is always on for `https` endpoints. Unlike
    // `Endpoint::new`, `Endpoint::from_shared` does NOT auto-detect the
    // scheme and enable TLS — it must be configured explicitly here.
    // `with_enabled_roots()` activates the `tls-native-roots` feature's
    // platform trust store (the system trust store per §6). The custom CA
    // path (`with_custom_ca`, if configured) ADDS to that chain — it never
    // replaces or bypasses it.
    if base_url.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_enabled_roots();
        if let Some(pem) = &config.custom_ca_pem {
            let cert = tonic::transport::Certificate::from_pem(pem);
            tls = tls.ca_certificate(cert);
        }
        endpoint = endpoint.tls_config(tls).map_err(|e| AxiamError::Network {
            message: format!("failed to configure gRPC TLS: {e}"),
            source: Some(Box::new(e)),
        })?;
    }

    // `connect_lazy` performs NO network I/O — the returned `Channel` is
    // `Clone + Send + Sync` and is safe to store and reuse across every RPC
    // (Pitfall 5, D-04). The actual TCP+TLS handshake happens transparently
    // on the first RPC call.
    Ok(endpoint.connect_lazy())
}
