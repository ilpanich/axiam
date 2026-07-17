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
use std::io::{self, BufReader};
use std::sync::Arc;

use axiam_api_rest::config::TlsConfig;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

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

    let cert_file = File::open(cert_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to open TLS cert file {}: {e}", cert_path.display()),
        )
    })?;
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_file))
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
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse TLS private key from {}: {e}",
                    key_path.display()
                ),
            )
        })?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("no private key found in {}", key_path.display()),
            )
        })?;

    // TLS 1.3 only (ASVS V9.1.2). ring provider selected explicitly.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("rustls TLS 1.3 configuration failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid TLS certificate/key pair: {e}"),
            )
        })
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
    fn missing_cert_path_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: Some("/tmp/does-not-matter.key".into()),
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
        };
        let err = build_rustls_server_config(&tls).expect_err("unreadable cert file must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
