//! `axiam-server healthcheck` (D-09), including over TLS (DF-016).
//!
//! These drive `axiam_server::healthcheck::run` — the function `main.rs` calls
//! — rather than re-implementing the probe beside it. The previous version of
//! this file did re-implement it, because the probe lived in `main.rs` and
//! `main.rs` cannot be linked from an integration test; a test that agrees with
//! its own copy of the code under test is the shape of a test that keeps
//! passing after the code changes.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use axiam_server::healthcheck::{Probe, run};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

fn write_tmp(tag: &str, contents: &str) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "axiam-healthcheck-{}-{n}-{tag}.pem",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write temp pem");
    path
}

// ---------------------------------------------------------------------------
// Plaintext — what this file always covered
// ---------------------------------------------------------------------------

#[test]
fn an_unreachable_endpoint_is_not_healthy() {
    // A port nothing is listening on. If it happens to be in use the worst
    // outcome is a false pass, which is acceptable for a smoke test.
    assert!(!run(&Probe {
        url: "http://127.0.0.1:19923/health".to_owned(),
        trust_anchors: None,
    }));
}

#[test]
fn a_plaintext_200_is_healthy() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(RESPONSE);
        }
    });

    assert!(run(&Probe {
        url: format!("http://{addr}/health"),
        trust_anchors: None,
    }));
}

// ---------------------------------------------------------------------------
// TLS (DF-016)
// ---------------------------------------------------------------------------

struct TestPki {
    ca_pem: String,
    /// Leaf first, then the CA — the shape of an `AXIAM__SERVER__TLS__CERT_PATH`
    /// `fullchain.pem`.
    server_chain_pem: String,
    /// The leaf alone, with no issuer beside it.
    server_leaf_pem: String,
    server_key_pem: String,
    /// A server certificate that is its own issuer.
    self_signed_pem: String,
    self_signed_key_pem: String,
}

/// A throwaway CA, a server leaf beneath it, and a self-signed server
/// certificate — all carrying an IP SAN for `127.0.0.1`, because that is the
/// address the resolved default probes and rustls verifies the name.
fn gen_test_pki() -> TestPki {
    let loopback = SanType::IpAddress("127.0.0.1".parse().expect("ip"));

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut server_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    server_params.is_ca = IsCa::NoCa;
    server_params.subject_alt_names.push(loopback.clone());
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let ss_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut ss_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ss_params.is_ca = IsCa::NoCa;
    ss_params.subject_alt_names.push(loopback);
    let ss_cert = ss_params.self_signed(&ss_key).unwrap();

    TestPki {
        ca_pem: ca_cert.pem(),
        server_chain_pem: format!("{}{}", server_cert.pem(), ca_cert.pem()),
        server_leaf_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        self_signed_pem: ss_cert.pem(),
        self_signed_key_pem: ss_key.serialize_pem(),
    }
}

/// Install the process-level rustls `CryptoProvider` once.
///
/// `rustls` is compiled with both provider features reachable in this
/// dependency graph, so it will not choose one on its own; the server does the
/// same thing at startup. `reqwest`'s rustls backend builds its own
/// configuration and is unaffected either way — this is for the test listener.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Serve exactly one TLS connection, answering `200 OK`, and return the address.
fn spawn_tls_listener(chain_pem: &str, key_pem: &str) -> std::net::SocketAddr {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    ensure_crypto_provider();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("chain");
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    let config = Arc::new(config);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let Ok(conn) = rustls::ServerConnection::new(config) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 1024];
            // A client that refuses the certificate closes here; that is the
            // outcome the negative tests are asserting, so it is not a failure.
            if tls.read(&mut buf).is_ok() {
                let _ = tls.write_all(RESPONSE);
                let _ = tls.flush();
            }
        }
    });

    addr
}

#[test]
fn a_tls_listener_is_healthy_when_the_chain_file_carries_the_issuer() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.server_chain_pem, &pki.server_key_pem);
    let chain = write_tmp("fullchain", &pki.server_chain_pem);

    assert!(
        run(&Probe {
            url: format!("https://{addr}/health"),
            trust_anchors: Some(chain),
        }),
        "a fullchain.pem contains the issuing CA, so the server's own chain \
         file is a usable trust anchor for a self-probe"
    );
}

/// The question the plan asked to **verify**: does the verifier accept an
/// end-entity certificate as a trust anchor?
///
/// It does, when that certificate is its own issuer. A self-signed server
/// certificate — the common shape for an internal direct-TLS deployment — is
/// therefore a working anchor for the process serving it, which is what makes
/// the zero-configuration default sound.
#[test]
fn a_self_signed_server_certificate_is_a_usable_trust_anchor() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.self_signed_pem, &pki.self_signed_key_pem);
    let anchor = write_tmp("self-signed", &pki.self_signed_pem);

    assert!(
        run(&Probe {
            url: format!("https://{addr}/health"),
            trust_anchors: Some(anchor),
        }),
        "an end-entity certificate that is its own issuer must work as a trust \
         anchor, or the documented default cannot be zero-configuration"
    );
}

/// The case the documentation has to warn about: a `cert_path` holding the leaf
/// **alone**, when that leaf was issued by a CA. There is then no anchor for
/// the issuer, and the probe correctly refuses — which is why
/// `AXIAM_HEALTHCHECK_CA_FILE` exists.
#[test]
fn a_ca_issued_leaf_without_its_issuer_is_not_a_usable_anchor() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.server_chain_pem, &pki.server_key_pem);
    let leaf_only = write_tmp("leaf-only", &pki.server_leaf_pem);

    assert!(
        !run(&Probe {
            url: format!("https://{addr}/health"),
            trust_anchors: Some(leaf_only),
        }),
        "a leaf whose issuer is absent must not verify — set \
         AXIAM_HEALTHCHECK_CA_FILE to the issuing CA"
    );
}

#[test]
fn the_ca_file_alone_verifies_the_listener() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.server_chain_pem, &pki.server_key_pem);
    let ca = write_tmp("ca", &pki.ca_pem);

    assert!(run(&Probe {
        url: format!("https://{addr}/health"),
        trust_anchors: Some(ca),
    }));
}

/// There is no "insecure" switch, and this is what that means in practice: a
/// TLS listener the probe cannot verify is **not** healthy.
#[test]
fn an_unverifiable_tls_listener_is_not_healthy() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.self_signed_pem, &pki.self_signed_key_pem);

    assert!(
        !run(&Probe {
            url: format!("https://{addr}/health"),
            trust_anchors: None,
        }),
        "a self-signed certificate must not verify against the platform trust \
         store"
    );
}

#[test]
fn an_anchor_file_that_is_not_there_is_not_healthy() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.server_chain_pem, &pki.server_key_pem);

    assert!(!run(&Probe {
        url: format!("https://{addr}/health"),
        trust_anchors: Some(PathBuf::from("/nonexistent/axiam-probe-ca.pem")),
    }));
}

/// An anchor bundle that parses but holds no certificate must fail rather than
/// fall back to the platform trust store — the pinning the operator asked for,
/// absent, with nothing to say so.
#[test]
fn an_empty_anchor_file_is_not_healthy() {
    let pki = gen_test_pki();
    let addr = spawn_tls_listener(&pki.server_chain_pem, &pki.server_key_pem);
    let empty = write_tmp("empty", "# no certificates here\n");

    assert!(!run(&Probe {
        url: format!("https://{addr}/health"),
        trust_anchors: Some(empty),
    }));
}
