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

use axiam_api_rest::config::{ClientAuth, TlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};

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

/// Build a rustls [`ClientCertVerifier`] from the configured client-CA bundle
/// (D3 native mTLS).
///
/// Loads the PEM bundle at `client_ca_path` into a [`RootCertStore`] and builds
/// a [`WebPkiClientVerifier`] over it, using the same [`CryptoProvider`] as the
/// server config. For [`ClientAuth::Optional`] the verifier still *offers* and
/// *verifies* client certs but permits anonymous clients
/// (`allow_unauthenticated`); for [`ClientAuth::Required`] a verified client
/// cert is mandatory.
///
/// Fails fast (aborting startup) when the CA path is unset, missing/unreadable,
/// empty, or malformed — matching this file's existing `io::Error` style so a
/// misconfigured mTLS server never starts.
fn build_client_cert_verifier(
    tls: &TlsConfig,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> io::Result<Arc<dyn ClientCertVerifier>> {
    let ca_path = tls.client_ca_path.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server.tls.client_auth is optional/required but \
             server.tls.client_ca_path is not set",
        )
    })?;

    let ca_file = File::open(ca_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "failed to open TLS client CA bundle {}: {e}",
                ca_path.display()
            ),
        )
    })?;
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(ca_file)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse client CA certificates from {}: {e}",
                    ca_path.display()
                ),
            )
        })?;
    if ca_certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no client CA certificates found in {}", ca_path.display()),
        ));
    }

    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid client CA certificate in {}: {e}",
                    ca_path.display()
                ),
            )
        })?;
    }

    let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
    let verifier = match tls.client_auth {
        // Verify presented certs but accept anonymous clients.
        ClientAuth::Optional => builder.allow_unauthenticated().build(),
        // Require a verified client cert (Off is unreachable here).
        _ => builder.build(),
    }
    .map_err(|e| io::Error::other(format!("failed to build client cert verifier: {e}")))?;

    Ok(verifier)
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
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("rustls TLS 1.3 configuration failed: {e}")))?;

    // Client-certificate (mTLS) policy (D3). `off` keeps the server-auth-only
    // behaviour (`with_no_client_auth`); `optional`/`required` install a
    // WebPkiClientVerifier over the configured CA bundle so rustls verifies the
    // client cert during the handshake and the *verified* cert (not a header)
    // drives certificate-based identity.
    let builder = match tls.client_auth {
        ClientAuth::Off => builder.with_no_client_auth(),
        ClientAuth::Optional | ClientAuth::Required => {
            let verifier = build_client_cert_verifier(tls, &provider)?;
            builder.with_client_cert_verifier(verifier)
        }
    };

    let mut config = builder.with_single_cert(cert_chain, key).map_err(|e| {
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
        assert_eq!(
            alpn_protocols(true),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
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

    /// The cert-file-unreadable case above always fails on the CERT open
    /// (checked first), so the sibling `File::open(key_path)` error arm was
    /// never separately reached. Use a valid, readable cert here so the
    /// function gets past the cert stage and hits the key-file-unreadable
    /// branch specifically.
    #[test]
    fn unreadable_key_file_fails_fast() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-readable", &pki.server_cert_pem)),
            key_path: Some("/nonexistent/axiam-test-key-only.pem".into()),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("unreadable key file must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("failed to open TLS key file"),
            "got: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // D3 — native client-certificate (mTLS) support
    // ---------------------------------------------------------------------

    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use rcgen::{
        BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };

    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Write `contents` to a unique temp file and return its path.
    fn write_tmp(tag: &str, contents: &str) -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("axiam-d3-{}-{n}-{tag}.pem", std::process::id()));
        let mut f = File::create(&path).expect("create temp pem");
        f.write_all(contents.as_bytes()).expect("write temp pem");
        path
    }

    struct TestPki {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    /// Generate a throwaway CA plus a server leaf (SAN `localhost`) and a client
    /// leaf (SAN `URI:spiffe://axiam/device-01`), all signed by the CA.
    fn gen_test_pki() -> TestPki {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // Server leaf: SAN localhost so the in-process client can verify it.
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.is_ca = IsCa::NoCa;
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        // Client leaf: carries a URI SAN we assert on after extraction.
        let client_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        client_params.is_ca = IsCa::NoCa;
        client_params
            .subject_alt_names
            .push(SanType::URI("spiffe://axiam/device-01".try_into().unwrap()));
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    #[test]
    fn client_auth_off_is_the_default() {
        assert_eq!(TlsConfig::default().client_auth, ClientAuth::Off);
        assert!(TlsConfig::default().client_ca_path.is_none());
    }

    #[test]
    fn verifier_builds_from_ca_bundle() {
        let pki = gen_test_pki();
        let ca_path = write_tmp("ca", &pki.ca_pem);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        for mode in [ClientAuth::Optional, ClientAuth::Required] {
            let tls = TlsConfig {
                enabled: true,
                client_auth: mode,
                client_ca_path: Some(ca_path.clone()),
                ..TlsConfig::default()
            };
            build_client_cert_verifier(&tls, &provider)
                .unwrap_or_else(|e| panic!("verifier must build for {mode:?}: {e}"));
        }
    }

    #[test]
    fn required_without_ca_path_fails_fast() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: None,
            ..TlsConfig::default()
        };
        let err = build_client_cert_verifier(&tls, &provider)
            .expect_err("required client-auth with no CA path must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn missing_ca_bundle_file_fails_fast() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some("/nonexistent/axiam-d3-ca.pem".into()),
            ..TlsConfig::default()
        };
        let err = build_client_cert_verifier(&tls, &provider)
            .expect_err("unreadable CA bundle must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_ca_bundle_fails_fast() {
        let ca_path = write_tmp("empty-ca", "# no certificates here\n");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = build_client_cert_verifier(&tls, &provider)
            .expect_err("empty CA bundle must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn server_config_builds_with_required_client_auth() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key", &pki.server_key_pem)),
            client_auth: ClientAuth::Required,
            client_ca_path: Some(write_tmp("ca", &pki.ca_pem)),
            ..TlsConfig::default()
        };
        build_rustls_server_config(&tls).expect("server config with mTLS must build");
    }

    /// The common/default deployment shape: TLS enabled, `client_auth: Off`
    /// (no mTLS). Every other test either fails fast before reaching the
    /// `client_auth` match (missing/unreadable cert or key) or exercises
    /// `Optional`/`Required`, so the plain server-auth-only success path
    /// (`ClientAuth::Off => builder.with_no_client_auth()`) was never
    /// actually driven to completion.
    #[test]
    fn server_config_builds_with_client_auth_off() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-off", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key-off", &pki.server_key_pem)),
            client_auth: ClientAuth::Off,
            ..TlsConfig::default()
        };
        let config =
            build_rustls_server_config(&tls).expect("server config with client_auth off must build");
        // Sanity: default ALPN (http2 defaults to true) is wired through.
        assert_eq!(config.alpn_protocols, alpn_protocols(true));
    }

    /// A CA bundle file whose content isn't valid PEM at all (garbage bytes
    /// where a base64 body is expected) must fail with `InvalidData` — the
    /// `CertificateDer::pem_reader_iter(..).collect()` parse-error arm in
    /// `build_client_cert_verifier`, distinct from "file unreadable" and
    /// "well-formed PEM but zero certificates".
    #[test]
    fn malformed_ca_bundle_fails_fast() {
        let ca_path = write_tmp(
            "garbage-ca",
            "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n",
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = build_client_cert_verifier(&tls, &provider)
            .expect_err("malformed CA bundle PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A CA bundle entry that is valid *PEM* (base64 decodes cleanly) but
    /// whose decoded bytes are not a valid X.509 certificate must be rejected
    /// by `RootCertStore::add` — the `roots.add(cert).map_err(...)` arm,
    /// distinct from the PEM-parse failure above.
    #[test]
    fn ca_bundle_with_valid_pem_but_invalid_der_fails_fast() {
        use base64::Engine as _;
        // Valid base64 (decodes to plain text), but nowhere near a valid
        // ASN.1 DER certificate structure.
        let bogus_body = base64::engine::general_purpose::STANDARD
            .encode(b"not a real certificate, just plain text padding to be long enough");
        let ca_path = write_tmp(
            "bogus-der-ca",
            &format!("-----BEGIN CERTIFICATE-----\n{bogus_body}\n-----END CERTIFICATE-----\n"),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = TlsConfig {
            enabled: true,
            client_auth: ClientAuth::Required,
            client_ca_path: Some(ca_path),
            ..TlsConfig::default()
        };
        let err = build_client_cert_verifier(&tls, &provider)
            .expect_err("PEM-valid but DER-invalid CA cert must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A server cert file that isn't valid PEM must fail with `InvalidData` —
    /// the main `CertificateDer::pem_reader_iter(cert_file).collect()`
    /// parse-error arm (the cert-side sibling of the CA-bundle test above).
    #[test]
    fn malformed_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp(
                "garbage-cert",
                "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n",
            )),
            key_path: Some(write_tmp("some-key", "irrelevant, parsed after cert")),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("malformed cert PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A cert file that IS well-formed (readable, and would parse as valid
    /// PEM if it contained any `CERTIFICATE` blocks) but contains zero
    /// certificates must be rejected with the "no certificates found"
    /// `InvalidData` error, distinct from a parse failure.
    #[test]
    fn empty_cert_file_fails_fast() {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("empty-cert", "# no certificates here\n")),
            key_path: Some(write_tmp("some-key", "irrelevant, never reached")),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("empty cert file must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("no certificates found"),
            "got: {err}"
        );
    }

    /// A key file that isn't a parseable private key (valid cert supplied,
    /// but the key file is garbage) must fail with `InvalidData` — the
    /// `PrivateKeyDer::from_pem_reader(key_file)` parse-error arm.
    #[test]
    fn malformed_key_file_fails_fast() {
        let pki = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert-badkey", &pki.server_cert_pem)),
            key_path: Some(write_tmp(
                "garbage-key",
                "-----BEGIN PRIVATE KEY-----\nnot valid base64 !!!\n-----END PRIVATE KEY-----\n",
            )),
            ..TlsConfig::default()
        };
        let err = build_rustls_server_config(&tls).expect_err("malformed key PEM must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A syntactically valid cert and a syntactically valid key that simply
    /// don't belong together (different keypairs) must be rejected at
    /// `with_single_cert` — the "invalid TLS certificate/key pair" arm, which
    /// is only reached once every earlier parse step already succeeded.
    #[test]
    fn mismatched_cert_and_key_fails_fast() {
        let pki_a = gen_test_pki();
        let pki_b = gen_test_pki();
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("mismatch-cert", &pki_a.server_cert_pem)),
            // A key from a completely different, unrelated PKI.
            key_path: Some(write_tmp("mismatch-key", &pki_b.server_key_pem)),
            ..TlsConfig::default()
        };
        let err =
            build_rustls_server_config(&tls).expect_err("mismatched cert/key pair must fail fast");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("invalid TLS certificate/key pair"),
            "got: {err}"
        );
    }

    // --- In-process rustls handshake tests (no live socket needed) ---------

    /// Pump handshake records between two in-memory rustls connections until
    /// both finish handshaking or one errors. Returns the first processing
    /// error (e.g. the server rejecting a missing required client cert).
    fn drive_handshake(
        client: &mut rustls::Connection,
        server: &mut rustls::Connection,
    ) -> Result<(), rustls::Error> {
        for _ in 0..16 {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            let mut rd: &[u8] = &buf;
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
            }
            server.process_new_packets()?;

            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            let mut rd: &[u8] = &buf;
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
            }
            client.process_new_packets()?;

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn make_server(pki: &TestPki) -> rustls::ServerConnection {
        let tls = TlsConfig {
            enabled: true,
            cert_path: Some(write_tmp("srv-cert", &pki.server_cert_pem)),
            key_path: Some(write_tmp("srv-key", &pki.server_key_pem)),
            client_auth: ClientAuth::Required,
            client_ca_path: Some(write_tmp("ca", &pki.ca_pem)),
            ..TlsConfig::default()
        };
        let config = build_rustls_server_config(&tls).expect("server config must build");
        rustls::ServerConnection::new(Arc::new(config)).expect("server connection")
    }

    /// Client config trusting the CA; `client_cert` toggles whether it presents
    /// its own certificate.
    fn make_client(pki: &TestPki, present_cert: bool) -> rustls::ClientConnection {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).unwrap())
            .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots);

        let config = if present_cert {
            let chain =
                vec![CertificateDer::from_pem_slice(pki.client_cert_pem.as_bytes()).unwrap()];
            let key = PrivateKeyDer::from_pem_slice(pki.client_key_pem.as_bytes()).unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        } else {
            builder.with_no_client_auth()
        };

        let name = ServerName::try_from("localhost").unwrap();
        rustls::ClientConnection::new(Arc::new(config), name).expect("client connection")
    }

    #[test]
    fn handshake_rejected_without_client_cert_when_required() {
        let pki = gen_test_pki();
        let mut server = rustls::Connection::Server(make_server(&pki));
        let mut client = rustls::Connection::Client(make_client(&pki, false));
        let result = drive_handshake(&mut client, &mut server);
        assert!(
            result.is_err(),
            "required client-auth must reject a client presenting no certificate"
        );
    }

    #[test]
    fn handshake_accepts_bench_client_cert_and_exposes_verified_peer_cert() {
        let pki = gen_test_pki();
        let mut server = rustls::Connection::Server(make_server(&pki));
        let mut client = rustls::Connection::Client(make_client(&pki, true));
        drive_handshake(&mut client, &mut server)
            .expect("handshake with a CA-signed client cert must succeed");
        assert!(
            !server.is_handshaking(),
            "server handshake should complete with a valid client cert"
        );

        // The VERIFIED peer certificate is what handlers consume (never a header).
        let peer = server
            .peer_certificates()
            .expect("verified client cert must be present after mTLS handshake");
        let leaf = peer.first().expect("at least one peer cert");

        // SAN extraction (the axiam-api-rest side of D3) must find the URI SAN.
        let verified = axiam_api_rest::VerifiedClientCert::from_der(leaf.as_ref())
            .expect("verified client cert must parse");
        assert!(
            verified
                .sans
                .iter()
                .any(|s| s == "URI:spiffe://axiam/device-01"),
            "expected the client URI SAN to be extracted, got {:?}",
            verified.sans
        );
        assert_eq!(
            verified.spki_sha256.len(),
            64,
            "SPKI fingerprint is hex-SHA256"
        );
    }
}
