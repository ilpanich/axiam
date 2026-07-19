//! REST API server configuration.

use std::path::PathBuf;

use serde::Deserialize;

pub mod rate_limit;

pub use rate_limit::RateLimitConfig;

/// Configuration for the Actix-Web REST API server.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address (default: "127.0.0.1").
    pub host: String,
    /// Bind port (default: 8090).
    pub port: u16,
    /// Allowed CORS origins. Empty disables cross-origin requests (restrictive).
    pub cors_allowed_origins: Vec<String>,
    /// Optional direct-TLS termination. Disabled by default — the recommended
    /// deployment terminates TLS at the proxy/load-balancer layer (ASVS V9.1.x,
    /// D-06). When enabled, the server binds with rustls restricted to TLS 1.3
    /// (see `axiam-server`).
    pub tls: TlsConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8090,
            cors_allowed_origins: Vec::new(),
            tls: TlsConfig::default(),
        }
    }
}

/// Direct-TLS configuration for the REST API listener.
///
/// TLS is **opt-in**: the default (`enabled = false`) preserves the plaintext
/// bind used behind a TLS-terminating proxy. When `enabled = true`, both
/// `cert_path` and `key_path` must point at readable PEM files; the server
/// negotiates TLS 1.3 only (ASVS V9.1.2), whose cipher suites are all
/// ASVS-approved (V9.1.3).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Enable direct TLS termination in the server process.
    pub enabled: bool,
    /// Path to the PEM-encoded certificate chain (leaf first).
    pub cert_path: Option<PathBuf>,
    /// Path to the PEM-encoded private key (PKCS#8, PKCS#1, or SEC1).
    pub key_path: Option<PathBuf>,
    /// Offer HTTP/2 (`h2`) over ALPN alongside `http/1.1`. Default `true`
    /// (backward-compatible; matches what the actix-web rustls bind advertises).
    ///
    /// Set `false` to build the rustls listener advertising `http/1.1` only —
    /// used to run the p2 benchmark apples-to-apples with the plaintext p0
    /// listener (which is HTTP/1.1), isolating the h2-vs-h1.1 throughput effect
    /// (B2). See `axiam-server`'s `tls` module for the important caveat that the
    /// actix-web `HttpServer` bind re-adds `h2` to ALPN regardless.
    pub http2: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            http2: true,
        }
    }
}

impl ServerConfig {
    /// Returns the socket bind address as "host:port".
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
