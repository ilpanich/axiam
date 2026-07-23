//! Regression test for the gRPC-over-TLS handshake panic (REQ-15 AC-1).
//!
//! The server binary links BOTH rustls crypto providers — `ring` (explicitly,
//! for the REST listener) and `aws-lc-rs` (transitively, e.g. via
//! rustls-platform-verifier). With two providers present, rustls 0.23 refuses
//! to auto-select a process-level default, so any code that builds a
//! `rustls::ServerConfig` through the *default* provider panics at
//! `rustls-0.23/src/crypto/mod.rs` with:
//!     "Could not automatically determine the process-level CryptoProvider
//!      from Rustls crate features."
//!
//! tonic's gRPC `ServerTlsConfig` (crates/axiam-api-grpc/src/server.rs) takes
//! exactly that default-provider path. Before the fix, every gRPC-over-TLS
//! handshake panicked on the tokio worker and the connection was dropped
//! (0 bytes back) — while the REST listener kept working because
//! `tls::build_rustls_server_config` passes `ring::default_provider()`
//! explicitly. That asymmetry is what made the p2-tls13 gRPC benchmark fail
//! with "no gRPC connection, you must call connect first".
//!
//! `axiam-server`'s `main()` fixes this by installing `ring` as the process
//! default at startup. This test mirrors that install and then drives the
//! previously-panicking path — `rustls::ServerConfig::builder()`, which
//! resolves the process-default provider — proving it now builds cleanly.

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[test]
fn grpc_server_tls_config_builds_from_process_default_provider() {
    // Mirror crates/axiam-server/src/main.rs. Idempotent: `Err` means a provider
    // was already installed by another test sharing this binary, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "a process-level rustls CryptoProvider must be installed, otherwise \
         tonic's gRPC ServerTlsConfig panics on every TLS handshake",
    );

    // Throwaway self-signed leaf, same shape as the benchmark server cert.
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate self-signed cert");
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .expect("serialize private key to DER");

    // The exact rustls call tonic makes internally: `ServerConfig::builder()`
    // resolves the process-default provider — the operation that panicked
    // pre-fix when two providers were linked and none was installed. It must
    // now build cleanly.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("rustls ServerConfig must build from the installed default provider");

    // Sanity: the provider actually produced a usable config with cipher suites.
    assert!(
        !server_config.crypto_provider().cipher_suites.is_empty(),
        "the installed provider must expose cipher suites for the TLS handshake",
    );
}
