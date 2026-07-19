//! Optional direct-TLS support for the REST API listener (ASVS V9.1.2/V9.1.3).
//!
//! TLS termination at a proxy/load balancer remains the recommended deployment
//! pattern (D-06). This module provides an *opt-in* alternative for deployments
//! that terminate TLS in-process: when `server.tls.enabled` is set, the server
//! builds a rustls [`ServerConfig`] restricted to **TLS 1.3 only**. Restricting
//! to TLS 1.3 also satisfies V9.1.3 — every TLS 1.3 cipher suite is
//! ASVS-approved, so no manual cipher-suite filtering is required.
//!
//! The `ring` crypto provider is selected explicitly (rather than relying on a
//! process-default provider) so `build_rustls_server_config` is self-contained
//! and deterministic regardless of what other crates in the tree pull in.

use std::fs::File;
use std::io;
use std::sync::Arc;

use axiam_api_rest::config::TlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerSessionMemoryCache;

/// Number of resumption entries kept in the in-process session cache.
///
/// TLS 1.3 resumption is ticket-based (stateless — the ticket travels with the
/// client), so this cache mainly bounds any non-ticket session state; a small
/// value is plenty for a benchmark/service workload and caps memory.
const RESUMPTION_CACHE_SIZE: usize = 512;

/// The ALPN protocol list the rustls listener is *built with*, given the
/// `http2` knob.
///
/// **Important caveat (B2):** for the REST listener this list is only fully
/// authoritative when the rustls `ServerConfig` is used directly. actix-web's
/// `HttpServer::bind_rustls_0_23` path funnels through
/// `actix_http::HttpService::rustls_0_23_with_config`, which unconditionally
/// **prepends** `["h2", "http/1.1"]` to whatever `alpn_protocols` we set. So
/// with the current actix bind, `http2 = false` narrows the config's list to
/// `http/1.1` but h2 is re-added and still wins negotiation. A *true*
/// http/1.1-only TLS listener therefore requires either fronting with the
/// `tls13-h1` nginx edge (see the benchmarks) or an H1-only actix service.
/// This helper is unit-tested and records operator intent; it is authoritative
/// for any non-actix consumer of the config.
fn alpn_protocols(http2: bool) -> Vec<Vec<u8>> {
    if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    }
}

/// Build a TLS 1.3-only rustls [`ServerConfig`] from the configured PEM files.
///
/// Fails fast (returning an `io::Error` that aborts startup) when TLS is enabled
/// but misconfigured: a missing `cert_path`/`key_path`, an unreadable or
/// malformed PEM file, an empty cert chain, or a cert/key mismatch.
pub fn build_rustls_server_config(tls: &TlsConfig) -> io::Result<ServerConfig> {
    let cert_path = tls.cert_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.enabled is true but server.tls.cert_path is not set",
        )
    })?;
    let key_path = tls.key_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.enabled is true but server.tls.key_path is not set",
        )
    })?;

    // Open the files explicitly so a missing/unreadable path yields a clean
    // io::Error (NotFound / PermissionDenied) before any PEM parsing. Cert and
    // key are parsed via rustls-pki-types' `PemObject` trait directly —
    // rustls-pemfile is unmaintained (RUSTSEC-2025-0134) and is a thin wrapper
    // over this same code.
    let cert_file = File::open(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open TLS cert file {}: {e}", cert_path.display()),
        )
    })?;
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse TLS certificates from {}: {e}",
                    cert_path.display()
                ),
            )
        })?;
    if cert_chain.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no certificates found in {}", cert_path.display()),
        ));
    }

    let key_file = File::open(key_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open TLS key file {}: {e}", key_path.display()),
        )
    })?;
    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "failed to read a TLS private key from {}: {e}",
                key_path.display()
            ),
        )
    })?;

    // TLS 1.3 only (ASVS V9.1.2). ring provider selected explicitly.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("rustls TLS 1.3 configuration failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS certificate/key pair: {e}"),
            )
        })?;

    // ALPN (B2): advertise h2+http/1.1 by default, or http/1.1-only when the
    // operator disables h2. See `alpn_protocols` for the actix-bind caveat.
    config.alpn_protocols = alpn_protocols(tls.http2);

    // TLS 1.3 session resumption (B2). Without a ticketer + session store a
    // rustls server does a *full* handshake on every connection; k6 opens many
    // short-lived connections per VU, so a full ECDHE handshake per request is a
    // per-request fixed cost that shows up as the ~2× p50 inflation on the token
    // endpoints. Enabling stateless TLS 1.3 tickets lets repeat connections
    // resume (PSK) instead. We deliberately do NOT enable 0-RTT/early-data:
    // rustls' `max_early_data_size` stays at its default 0 because the token
    // endpoints are non-idempotent POSTs and early data is replayable
    // (see docs/security-profiles.md).
    config.session_storage = ServerSessionMemoryCache::new(RESUMPTION_CACHE_SIZE);
    match rustls::crypto::ring::Ticketer::new() {
        Ok(ticketer) => config.ticketer = ticketer,
        Err(e) => tracing::warn!(
            error = %e,
            "failed to construct a TLS ticketer; session resumption disabled \
             (falling back to full handshakes)"
        ),
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_is_the_default() {
        let tls = TlsConfig::default();
        assert!(!tls.enabled);
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
    }

    #[test]
    fn alpn_list_reflects_http2_knob() {
        assert_eq!(alpn_protocols(true), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(alpn_protocols(false), vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn default_offers_http2() {
        assert!(TlsConfig::default().http2);
    }

    #[test]
    fn missing_cert_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: Some("/tmp/does-not-matter.key".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("missing cert_path must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_key_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some("/tmp/does-not-matter.crt".into()),
            key_path: None,
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("missing key_path must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn unreadable_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some("/nonexistent/axiam-test-cert.pem".into()),
            key_path: Some("/nonexistent/axiam-test-key.pem".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("unreadable cert file must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
