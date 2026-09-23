//! S-7 (DF-001) end to end, against real TLS stacks rather than parsed bytes.
//!
//! **The browser-shaped acceptance.** DF-001's claim was that AXIAM cannot issue
//! a certificate a TLS *server* can present, so every listener certificate in
//! the demo was signed offline. Here AXIAM issues one — organization root →
//! tenant signing CA → `Server` leaf, through the real `CaService` and
//! `CertService` — an actix listener presents it, and a rustls client that
//! trusts **only the organization root** completes a handshake for a name on
//! the allow-list, and fails for a name that is not in the leaf.
//!
//! **The other direction (c).** The same issued leaf presented as a *client*
//! certificate to the verifier the REST listener installs — and, since S-8,
//! the gRPC listener too — is refused, because webpki requires `clientAuth`
//! when an EKU extension is present and a `Server` leaf carries `serverAuth`
//! only. A `Device` leaf from the same CA is the I4 twin.
//!
//! No assertion prints a `GeneratedCertificate`: it carries a private key.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use axiam_api_rest::config::ClientAuth;
use axiam_core::models::certificate::{
    CertTrust, CertificateType, CreateCaCertificate, CreateCertificate, CreateIntermediateCa,
    GeneratedCertificate, KeyAlgorithm, SubjectAltName,
};
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::{CaService, CertService, IssuingScope, PkiConfig};
use axiam_server::tls::ReloadableClientCertVerifier;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What the organization issued: its root, the tenant CA, and two leaves.
struct IssuedPki {
    root_pem: String,
    tenant_ca_pem: String,
    server: GeneratedCertificate,
    device: GeneratedCertificate,
}

const ALLOWED: &[&str] = &[".lakeside.internal"];

async fn issue_pki() -> IssuedPki {
    let db: Surreal<TestDb> = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let custodians = Arc::new(
        axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
            .expect("custodians"),
    );
    let config = PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
        ..Default::default()
    };
    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cas = CaService::new(
        ca_repo.clone(),
        config.clone(),
        sem.clone(),
        custodians.clone(),
    );
    let certs = CertService::new(
        ca_repo,
        SurrealCertificateRepository::new(db),
        config,
        sem,
        custodians,
    );

    let org = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let root = cas
        .generate(CreateCaCertificate {
            organization_id: org,
            subject: "Lakeside Root".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
            intermediate_subject: None,
            intermediate_validity_days: None,
            issue_from_root: false,
        })
        .await
        .expect("root");
    let tenant_ca = cas
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org,
            tenant_id: tenant,
            parent_ca_id: root.certificate.id,
            subject: "Lakeside Plant Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 180,
        })
        .await
        .expect("tenant signing CA");

    let allowed: Vec<String> = ALLOWED.iter().map(|s| s.to_string()).collect();
    let leaf = |cert_type, subject: &str, sans| CreateCertificate {
        tenant_id: tenant,
        issuer_ca_id: tenant_ca.certificate.id,
        subject: subject.into(),
        cert_type,
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days: 30,
        metadata: None,
        subject_alt_names: sans,
    };

    // Off the list: there is no leaf to present for it at all.
    assert!(
        certs
            .generate(
                org,
                IssuingScope::Tenant,
                leaf(
                    CertificateType::Server,
                    "login.example.com",
                    vec![SubjectAltName::Dns("login.example.com".into())]
                ),
                None,
                &allowed,
            )
            .await
            .is_err(),
        "a name off the allow-list is never issued"
    );

    let server = certs
        .generate(
            org,
            IssuingScope::Tenant,
            leaf(
                CertificateType::Server,
                "api.lakeside.internal",
                vec![SubjectAltName::Dns("api.lakeside.internal".into())],
            ),
            None,
            &allowed,
        )
        .await
        .expect("an allow-listed Server leaf");
    let device = certs
        .generate(
            org,
            IssuingScope::Tenant,
            leaf(CertificateType::Device, "device-7", vec![]),
            None,
            &allowed,
        )
        .await
        .expect("a Device leaf");

    IssuedPki {
        root_pem: root.certificate.public_cert_pem,
        tenant_ca_pem: tenant_ca.certificate.public_cert_pem,
        server,
        device,
    }
}

fn der(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("certificate PEM")
}

fn roots(pem: &str) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(der(pem)).expect("root");
    store
}

/// An actix listener on loopback presenting `leaf` + the tenant CA.
async fn serve(
    pki: &IssuedPki,
    leaf: &GeneratedCertificate,
) -> (SocketAddr, actix_web::dev::ServerHandle) {
    let chain = vec![
        der(&leaf.certificate.public_cert_pem),
        der(&pki.tenant_ca_pem),
    ];
    let key = PrivateKeyDer::from_pem_slice(leaf.private_key_pem.as_bytes()).expect("leaf key");
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = HttpServer::new(|| App::new().route("/", web::get().to(|| async { "lakeside" })))
        .workers(1)
        .listen_rustls_0_23(listener, config)
        .expect("listen")
        .run();
    let handle = server.handle();
    actix_rt::spawn(server);
    (addr, handle)
}

/// Handshake as `name`, trusting only `root_pem`; on success, one HTTP request.
async fn fetch(addr: SocketAddr, root_pem: &str, name: &str) -> Result<String, std::io::Error> {
    let config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(root_pem))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut tls = connector
        .connect(ServerName::try_from(name.to_string()).unwrap(), tcp)
        .await?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut body = String::new();
    tls.read_to_string(&mut body).await?;
    Ok(body)
}

/// (f) — the thing DF-001 says is impossible today.
#[actix_rt::test]
async fn a_browser_shaped_client_trusting_only_the_root_accepts_the_issued_server_leaf() {
    let pki = issue_pki().await;
    let (addr, handle) = serve(&pki, &pki.server).await;

    let body = fetch(addr, &pki.root_pem, "api.lakeside.internal")
        .await
        .expect("the handshake completes for the allow-listed name in the leaf");
    assert!(
        body.starts_with("HTTP/1.1 200"),
        "status line: {:?}",
        body.lines().next()
    );
    assert!(body.ends_with("lakeside"));

    // A name inside the allow-list but not in this leaf, and one outside it:
    // the client refuses both, because the leaf names neither.
    for name in ["other.lakeside.internal", "login.example.com"] {
        let err = fetch(addr, &pki.root_pem, name)
            .await
            .expect_err("a name the leaf does not carry must fail the handshake");
        assert!(
            err.to_string().contains("NotValidForName")
                || err.to_string().contains("not valid for"),
            "{name}: {err}"
        );
    }
    handle.stop(true).await;
}

/// The I4 twin of (f): a leaf of any other type, from the same CA, is not a
/// server certificate to a browser-shaped client — it names no host and its
/// usage is `clientAuth`.
#[actix_rt::test]
async fn a_device_leaf_is_not_a_server_certificate() {
    let pki = issue_pki().await;
    let (addr, handle) = serve(&pki, &pki.device).await;
    assert!(fetch(addr, &pki.root_pem, "device-7").await.is_err());
    handle.stop(true).await;
}

/// (c) — the verifier the REST listener installs, and S-8's gRPC listener
/// installs a second instance of, refuses a Server leaf as a client
/// certificate under `optional` and `required`; a Device leaf passes.
#[actix_rt::test]
async fn the_client_cert_verifier_refuses_a_server_leaf_by_its_usage() {
    let pki = issue_pki().await;
    let server = der(&pki.server.certificate.public_cert_pem);
    let device = der(&pki.device.certificate.public_cert_pem);
    let intermediates = [der(&pki.tenant_ca_pem)];

    for policy in [ClientAuth::Optional, ClientAuth::Required] {
        let verifier = ReloadableClientCertVerifier::empty(policy);
        verifier.replace(roots(&pki.root_pem), &provider()).unwrap();

        let err = verifier
            .verify_client_cert(&server, &intermediates, UnixTime::now())
            .expect_err("a serverAuth-only leaf is not a client certificate");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::InvalidPurposeContext {
                        required: rustls::ExtendedKeyPurpose::ClientAuth,
                        ..
                    }
                )
            ),
            "refused for its usage, not for anything else: {err:?}"
        );
        verifier
            .verify_client_cert(&device, &intermediates, UnixTime::now())
            .expect("I4: a clientAuth Device leaf from the same CA passes");
    }

    // Under `optional_self_signed` the handshake admits any certificate, and
    // what separates them is the trust classification every consumer reads:
    // the Server leaf is `SelfAsserted`, which device login and
    // `tls_client_auth` both refuse.
    let verifier = ReloadableClientCertVerifier::empty(ClientAuth::OptionalSelfSigned);
    verifier.replace(roots(&pki.root_pem), &provider()).unwrap();
    assert_eq!(
        verifier.trust_of(&server, &intermediates),
        CertTrust::SelfAsserted
    );
    assert_eq!(
        verifier.trust_of(&device, &intermediates),
        CertTrust::ChainedToAnchor
    );
}
