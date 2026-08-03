//! REST API server configuration.

use std::path::PathBuf;

use serde::Deserialize;

pub mod rate_limit;

pub use rate_limit::{RateLimitConfig, RateLimitPosture, RateLimitProfile};

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
    /// Set `TCP_NODELAY` (disable Nagle's algorithm) on accepted connections.
    ///
    /// **Default: `true`.** Override with
    /// `AXIAM__SERVER__TCP_NODELAY=false`.
    ///
    /// # Why this exists and why the default is `true` (I5)
    ///
    /// actix-web 4.14 exposes `HttpServer::tcp_nodelay` but leaves it *unset*
    /// by default, and an unset value means "never call `set_nodelay`"
    /// (`actix-http-3.13.1 src/service.rs:28-35`, `src/h2/service.rs:29-35`:
    /// `fn desired_nodelay(tcp_nodelay: Option<bool>) -> Option<bool> {
    /// tcp_nodelay }`). The kernel default therefore applied and Nagle stayed
    /// **on** for every REST connection — while the gRPC listener has had it
    /// off all along, because tonic's `Server` defaults `tcp_nodelay` to `true`
    /// (`tonic .../transport/server/mod.rs:132`).
    ///
    /// Nagle only costs anything when a response reaches the socket as more
    /// than one write and the last write is a partial segment: the kernel holds
    /// that final fragment until the peer acknowledges the previous one, and
    /// Linux's delayed-ACK timer is **40 ms** (`TCP_DELACK_MIN`). A response
    /// emitted as a single `sendmsg` is immune (`tcp_push` sets
    /// `TCP_NAGLE_PUSH` on the tail), which is why an HTTP/1.1 plaintext bind
    /// can look clean while the h2-over-TLS bind — where the `h2` crate emits
    /// HEADERS and DATA frames through separate `poll_write`s into
    /// `tokio-rustls`, each becoming its own TLS record — is exposed.
    ///
    /// That is the leading hypothesis for the run-4 TLS client-credentials
    /// plateau: 1 180 req/s at a flat p50/p95/p99 of 42.6/43.9/44.8 ms with
    /// nothing saturated, i.e. ~40 ms of pure timer plus ~2.6 ms of work, on
    /// the one endpoint whose response happened to straddle a segment boundary.
    /// It is a *hypothesis*, not a measured result: run 5 must A/B this knob
    /// (see the run-5 runbook). Keeping it configurable is what makes that A/B
    /// possible; `false` reproduces the pre-I5 behaviour exactly.
    ///
    /// Setting `TCP_NODELAY` is standard for request/response HTTP servers and
    /// has no security implication.
    pub tcp_nodelay: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8090,
            cors_allowed_origins: Vec::new(),
            tls: TlsConfig::default(),
            tcp_nodelay: true,
        }
    }
}

/// Native client-certificate (mTLS) authentication policy for the direct-TLS
/// listener (D3).
///
/// When client auth is enabled, rustls verifies the presented client
/// certificate against the CA bundle at [`TlsConfig::client_ca_path`] during
/// the TLS handshake, and the *verified* leaf certificate is exposed to request
/// handlers via the connection extensions — the certificate-auth flow then
/// consumes that verified cert rather than a spoofable proxy header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// No client certificate requested (server-auth only). Backward-compatible
    /// default — the rustls config is built with `with_no_client_auth()`.
    #[default]
    Off,
    /// Request a client certificate but allow anonymous clients. A presented
    /// certificate is still verified against the CA bundle; connections without
    /// one are accepted (`WebPkiClientVerifier::builder(..).allow_unauthenticated()`).
    Optional,
    /// Require a client certificate verified against the CA bundle. The TLS
    /// handshake is rejected if the client presents no certificate or an
    /// unverifiable one (`WebPkiClientVerifier::builder(..).build()`).
    Required,
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
    /// Native client-certificate (mTLS) policy (D3). Default `off` keeps the
    /// server-auth-only behaviour. `optional`/`required` build the rustls config
    /// with a `WebPkiClientVerifier` over [`Self::client_ca_path`].
    pub client_auth: ClientAuth,
    /// Path to the PEM CA bundle used to verify client certificates. Required
    /// (and must be readable) when `client_auth` is `optional` or `required`;
    /// ignored when `off`.
    pub client_ca_path: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
            http2: true,
            client_auth: ClientAuth::Off,
            client_ca_path: None,
        }
    }
}

impl ServerConfig {
    /// Returns the socket bind address as "host:port".
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I5: the whole point of the knob is that the socket option is now set
    /// *explicitly*. If this default ever flips to `false`, the REST listener
    /// silently goes back to running with Nagle enabled while gRPC does not.
    #[test]
    fn tcp_nodelay_defaults_to_enabled() {
        assert!(
            ServerConfig::default().tcp_nodelay,
            "TCP_NODELAY must default to enabled — actix-web leaves the socket \
             option untouched when unset, which means Nagle stays on"
        );
    }

    /// The knob must be reachable from configuration, since the run-5
    /// measurement plan depends on being able to turn it off.
    #[test]
    fn tcp_nodelay_can_be_disabled_from_config() {
        let parsed: ServerConfig = serde_json::from_str(r#"{"tcp_nodelay": false}"#)
            .expect("a partial server config must deserialize");
        assert!(!parsed.tcp_nodelay);
        // Everything else still falls back to the defaults.
        assert_eq!(parsed.port, ServerConfig::default().port);
    }

    #[test]
    fn client_auth_defaults_to_off() {
        assert_eq!(ClientAuth::default(), ClientAuth::Off);
        assert_eq!(TlsConfig::default().client_auth, ClientAuth::Off);
        assert!(TlsConfig::default().client_ca_path.is_none());
    }

    #[test]
    fn client_auth_parses_all_three_values() {
        for (raw, expected) in [
            ("\"off\"", ClientAuth::Off),
            ("\"optional\"", ClientAuth::Optional),
            ("\"required\"", ClientAuth::Required),
        ] {
            let parsed: ClientAuth =
                serde_json::from_str(raw).unwrap_or_else(|e| panic!("{raw} must parse: {e}"));
            assert_eq!(parsed, expected, "{raw}");
        }
    }

    #[test]
    fn client_auth_rejects_invalid_value() {
        let err = serde_json::from_str::<ClientAuth>("\"enabled\"");
        assert!(err.is_err(), "unknown client_auth value must be rejected");
    }

    #[test]
    fn tls_config_deserializes_client_auth_fields() {
        let cfg: TlsConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "cert_path": "/etc/axiam/server.crt",
            "key_path": "/etc/axiam/server.key",
            "client_auth": "required",
            "client_ca_path": "/etc/axiam/ca.crt",
        }))
        .expect("TlsConfig with client-auth fields must deserialize");
        assert_eq!(cfg.client_auth, ClientAuth::Required);
        assert_eq!(
            cfg.client_ca_path.as_deref(),
            Some(std::path::Path::new("/etc/axiam/ca.crt"))
        );
    }
}
