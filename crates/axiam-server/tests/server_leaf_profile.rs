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
//! **`tls_client_auth` at the route (#610 (b)).** The token-endpoint tests in
//! `axiam-api-rest` drive `TokenService::exchange` with a hand-built
//! `PresentedCertificate`, because an actix test request carries no TLS
//! connection. The last three tests here close that gap: a listener built by
//! the server's own `build_rustls_server_config` over the bundle
//! `TrustAnchorReload` writes from the flagged CAs, the server's own
//! `on_connect` hook ([`lift_verified_client_certificate`]), and the real
//! `/oauth2/token` route — driven by a rustls client presenting a leaf AXIAM
//! issued. Nothing between the handshake and `TokenService` is stubbed: the
//! trust level and the issuer path the R1W1-02 check reads are the ones the
//! listener derived.
//!
//! No assertion prints a `GeneratedCertificate`: it carries a private key.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use axiam_api_rest::TrustAnchorReloader as _;
use axiam_api_rest::config::rate_limit::RateLimitConfig;
use axiam_api_rest::config::{ClientAuth, TlsConfig};
use axiam_api_rest::server::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::certificate::{
    CaCertificate, CertTrust, CertificateType, CreateCaCertificate, CreateCertificate,
    CreateIntermediateCa, GeneratedCertificate, ImportCaCertificate, KeyAlgorithm, SubjectAltName,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    CaCertificateRepository, OAuth2ClientRepository, OrganizationRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealTenantRepository,
};
use axiam_pki::{CaService, CertService, IssuingScope, PkiConfig};
use axiam_server::mtls_anchors::TrustAnchorReload;
use axiam_server::tls::{
    ReloadableClientCertVerifier, build_rustls_server_config, lift_verified_client_certificate,
};
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
        user_id: None,
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

// ---------------------------------------------------------------------------
// #610 (b): `tls_client_auth` through the listener, the hook and the route
// ---------------------------------------------------------------------------

/// The listener's verifier is a process-global the `on_connect` hook reads
/// (`tls::peer_certificate_issuer_path`), and each test below installs its own
/// anchors on it, so the route-level tests take turns.
static LISTENER_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The subject the `tls_client_auth` client registers, and every leaf below
/// carries — whichever CA issued it.
const CLIENT_CN: &str = "svc-mtls";

/// A scratch directory that cleans up after itself even on a failed assertion.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("axiam-route-mtls-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self(dir)
    }

    fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn auth_config() -> AuthConfig {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
    AuthConfig {
        jwt_private_key_pem: key.serialize_pem(),
        jwt_public_key_pem: key.public_key_pem(),
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.route-mtls.example".into(),
        ..AuthConfig::default()
    }
}

/// What a TLS client presents: its chain, leaf first, and the leaf's key.
/// Deliberately not `Debug` — it carries a private key.
struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key_pem: String,
}

impl ClientIdentity {
    /// A leaf AXIAM issued, presented with the tenant CA that issued it; the
    /// organization root above that is the listener's anchor.
    fn issued(leaf: &GeneratedCertificate, issuer: &CaCertificate) -> Self {
        Self {
            chain: vec![
                der(&leaf.certificate.public_cert_pem),
                der(&issuer.public_cert_pem),
            ],
            key_pem: leaf.private_key_pem.clone(),
        }
    }
}

/// A CA outside AXIAM whose key the test holds: what an administrator who
/// imports a keyless CA and flags it keeps offline. Also signs the listener's
/// own server certificate, which nothing here is about.
struct ExternalCa {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pem: String,
}

impl ExternalCa {
    fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }

    fn sign(
        &self,
        sans: Vec<String>,
        cn: &str,
        usage: rcgen::ExtendedKeyUsagePurpose,
    ) -> (rcgen::Certificate, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(sans).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.extended_key_usages = vec![usage];
        let cert = params
            .signed_by(&key, &rcgen::Issuer::from_params(&self.params, &self.key))
            .unwrap();
        (cert, key.serialize_pem())
    }

    /// A client leaf carrying the registered subject, signed by this CA.
    fn client_leaf(&self) -> ClientIdentity {
        let (leaf, key_pem) = self.sign(
            Vec::new(),
            CLIENT_CN,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        );
        ClientIdentity {
            chain: vec![leaf.der().clone()],
            key_pem,
        }
    }
}

/// How the token endpoint answered a `client_credentials` request.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// `200` with an access token.
    Tokens,
    /// `401 invalid_client`.
    InvalidClient,
    /// Anything else, by status.
    Other(u16),
}

/// The listener a fixture serves `/oauth2/token` on.
struct RouteListener {
    addr: SocketAddr,
    handle: actix_web::dev::ServerHandle,
    /// The root the listener's own server certificate chains to.
    server_root_pem: String,
}

/// Two organizations, each root flagged as an mTLS trust anchor of the one
/// listener: the client's (A), whose tenants `a` and `b` each have a tenant
/// signing CA under A's root, and another (B), whose tenant `c` has one under
/// B's. The `tls_client_auth` client lives in tenant `a` and registers
/// `CN=svc-mtls`.
struct RouteFixture {
    db: Surreal<TestDb>,
    state: AppState<TestDb>,
    dir: ScratchDir,
    org_a: Uuid,
    org_b: Uuid,
    tenant_a: Uuid,
    tenant_b: Uuid,
    tenant_c: Uuid,
    ca_a: CaCertificate,
    ca_b: CaCertificate,
    ca_c: CaCertificate,
    client_id: String,
}

impl RouteFixture {
    async fn new() -> Self {
        let db: Surreal<TestDb> = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let state = AppState::for_test(db.clone(), auth_config());

        let orgs = SurrealOrganizationRepository::new(db.clone());
        let tenants = SurrealTenantRepository::new(db.clone());
        let mut org_ids = Vec::new();
        for slug in ["org-a", "org-b"] {
            org_ids.push(
                orgs.create(CreateOrganization {
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .unwrap()
                .id,
            );
        }
        let (org_a, org_b) = (org_ids[0], org_ids[1]);
        let mut tenant_ids = Vec::new();
        for (org, slug) in [
            (org_a, "tenant-a"),
            (org_a, "tenant-b"),
            (org_b, "tenant-c"),
        ] {
            tenant_ids.push(
                tenants
                    .create(CreateTenant {
                        organization_id: org,
                        kind: TenantKind::Standard,
                        name: slug.into(),
                        slug: slug.into(),
                        metadata: None,
                    })
                    .await
                    .unwrap()
                    .id,
            );
        }
        let (tenant_a, tenant_b, tenant_c) = (tenant_ids[0], tenant_ids[1], tenant_ids[2]);

        let cas = &state.pki.ca_service;
        let ca_repo = SurrealCaCertificateRepository::new(db.clone());
        let mut roots = Vec::new();
        for (org, subject) in [(org_a, "Org A Root"), (org_b, "Org B Root")] {
            let root = cas
                .generate(CreateCaCertificate {
                    organization_id: org,
                    subject: subject.into(),
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 365,
                    intermediate_subject: None,
                    intermediate_validity_days: None,
                    issue_from_root: false,
                })
                .await
                .expect("organization root")
                .certificate;
            ca_repo
                .set_mtls_trust_anchor(org, root.id, true)
                .await
                .expect("flag the root as an mTLS trust anchor");
            roots.push(root);
        }
        let mut tenant_cas = Vec::new();
        for (org, root, tenant, subject) in [
            (org_a, &roots[0], tenant_a, "Tenant A Signing CA"),
            (org_a, &roots[0], tenant_b, "Tenant B Signing CA"),
            (org_b, &roots[1], tenant_c, "Tenant C Signing CA"),
        ] {
            tenant_cas.push(
                cas.generate_intermediate(CreateIntermediateCa {
                    organization_id: org,
                    tenant_id: tenant,
                    parent_ca_id: root.id,
                    subject: subject.into(),
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 180,
                })
                .await
                .expect("tenant signing CA")
                .certificate,
            );
        }
        let [ca_a, ca_b, ca_c]: [CaCertificate; 3] = tenant_cas.try_into().unwrap();

        let (client, _secret) = SurrealOAuth2ClientRepository::new(db.clone())
            .create(CreateOAuth2Client {
                tenant_id: tenant_a,
                name: "mtls-service".into(),
                redirect_uris: vec![],
                grant_types: vec!["client_credentials".into()],
                scopes: vec![],
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                require_par: false,
                profile: ClientProfile::Standard,
                token_endpoint_auth_method: ClientAuthMethod::TlsClientAuth,
                tls_client_auth_subject_dn: Some(format!("CN={CLIENT_CN}")),
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                self_signed_tls_client_auth_thumbprints: vec![],
                tls_client_certificate_bound_access_tokens: false,
                jwks: None,
                jwks_uri: None,
                dpop_bound_access_tokens: false,
                dpop_require_nonce: false,
                authn_request_params: AuthnRequestParamsMode::Ignore,
                browser_sso: false,
                allowed_resources: Vec::new(),
                managed_by: ManagedBy::Admin,
                ciba: Default::default(),
            })
            .await
            .unwrap();

        Self {
            db,
            state,
            dir: ScratchDir::new(),
            org_a,
            org_b,
            tenant_a,
            tenant_b,
            tenant_c,
            ca_a,
            ca_b,
            ca_c,
            client_id: client.client_id,
        }
    }

    /// A `Service` leaf carrying [`CLIENT_CN`], issued in `tenant` by its
    /// signing CA `ca`.
    async fn issue(&self, org: Uuid, tenant: Uuid, ca: &CaCertificate) -> GeneratedCertificate {
        self.state
            .pki
            .cert_service
            .generate(
                org,
                IssuingScope::Tenant,
                CreateCertificate {
                    tenant_id: tenant,
                    issuer_ca_id: ca.id,
                    subject: CLIENT_CN.into(),
                    cert_type: CertificateType::Service,
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 30,
                    metadata: None,
                    subject_alt_names: vec![],
                    user_id: None,
                },
                None,
                &[],
            )
            .await
            .expect("leaf")
    }

    /// Import `ca` into `org` without its key and flag it, as an administrator
    /// of `org` can.
    async fn import_and_flag(&self, org: Uuid, ca: &ExternalCa) {
        let imported = self
            .state
            .pki
            .ca_service
            .import(ImportCaCertificate {
                organization_id: org,
                public_cert_pem: ca.pem.clone(),
                private_key_pem: None,
            })
            .await
            .expect("import the CA");
        SurrealCaCertificateRepository::new(self.db.clone())
            .set_mtls_trust_anchor(org, imported.id, true)
            .await
            .expect("flag it as an mTLS trust anchor");
    }

    /// The server's own TLS listener, over the anchors flagged so far, serving
    /// the real `/api/v1` wiring with the server's own `on_connect` hook.
    ///
    /// The anchor bundle is written, and installed on the process's live
    /// verifier, by `TrustAnchorReload` — what flagging a CA through the admin
    /// API runs — and the listener is built from it by
    /// `build_rustls_server_config`, as at boot. Call it after every CA the
    /// test needs is flagged.
    async fn listen(&self) -> RouteListener {
        let bundle = self.dir.join("client-ca-bundle.pem");
        TrustAnchorReload::new(
            SurrealCaCertificateRepository::new(self.db.clone()),
            Some(bundle.clone()),
        )
        .reload()
        .await
        .expect("write and install the anchor bundle");

        let server_ca = ExternalCa::new("Route Listener CA");
        let (server_leaf, server_key) = server_ca.sign(
            vec!["localhost".into()],
            "localhost",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        );
        let (cert_path, key_path) = (self.dir.join("server.pem"), self.dir.join("server.key"));
        std::fs::write(&cert_path, server_leaf.pem()).unwrap();
        std::fs::write(&key_path, server_key).unwrap();

        let config = build_rustls_server_config(&TlsConfig {
            enabled: true,
            cert_path: Some(cert_path),
            key_path: Some(key_path),
            client_auth: ClientAuth::Optional,
            client_ca_path: Some(bundle),
            ..TlsConfig::default()
        })
        .expect("the server's listener config");

        let state = self.state.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default()))
        })
        .on_connect(lift_verified_client_certificate)
        .workers(1)
        .listen_rustls_0_23(listener, config)
        .expect("listen")
        .run();
        let handle = server.handle();
        actix_rt::spawn(server);
        RouteListener {
            addr,
            handle,
            server_root_pem: server_ca.pem,
        }
    }

    /// `POST /oauth2/token` (`client_credentials`) for the fixture's client,
    /// over a fresh TLS connection presenting `identity` (or no certificate).
    /// `Err` when no HTTP answer came back — the handshake refused the
    /// certificate.
    async fn token(
        &self,
        listener: &RouteListener,
        identity: Option<&ClientIdentity>,
    ) -> std::io::Result<Outcome> {
        let builder = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots(&listener.server_root_pem));
        let config = match identity {
            Some(id) => builder
                .with_client_auth_cert(
                    id.chain.clone(),
                    PrivateKeyDer::from_pem_slice(id.key_pem.as_bytes()).expect("leaf key"),
                )
                .expect("client identity"),
            None => builder.with_no_client_auth(),
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(listener.addr).await?;
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await?;
        let form = format!("grant_type=client_credentials&client_id={}", self.client_id);
        tls.write_all(
            format!(
                "POST /oauth2/token?tenant_id={} HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{form}",
                self.tenant_a,
                form.len()
            )
            .as_bytes(),
        )
        .await?;
        let mut response = String::new();
        tls.read_to_string(&mut response).await?;

        let status: u16 = response
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no HTTP status line")
            })?;
        let body: serde_json::Value = response
            .split_once("\r\n\r\n")
            .and_then(|(_, body)| serde_json::from_str(body).ok())
            .unwrap_or(serde_json::Value::Null);
        Ok(match status {
            200 if body["access_token"].is_string() => Outcome::Tokens,
            401 if body["error"] == "invalid_client" => Outcome::InvalidClient,
            other => Outcome::Other(other),
        })
    }
}

/// #610 (b), first half — `crl_test.rs`'s revoked-leaf test, at the route: the
/// tenant's own leaf, presented on the wire, authenticates its `tls_client_auth`
/// client; once revoked it is refused with `invalid_client`, although the
/// handshake verifies its chain exactly as before.
#[actix_rt::test]
async fn a_revoked_leaf_is_refused_at_the_token_route_under_tls_client_auth() {
    let _turn = LISTENER_TURN.lock().await;
    let f = RouteFixture::new().await;
    let leaf = f.issue(f.org_a, f.tenant_a, &f.ca_a).await;
    let identity = ClientIdentity::issued(&leaf, &f.ca_a);
    let listener = f.listen().await;

    assert_eq!(
        f.token(&listener, Some(&identity))
            .await
            .expect("an HTTP answer"),
        Outcome::Tokens,
        "the active leaf authenticates its client through the listener and the route"
    );

    f.state
        .pki
        .cert_service
        .revoke(f.tenant_a, leaf.certificate.id)
        .await
        .unwrap();
    assert_eq!(
        f.token(&listener, Some(&identity))
            .await
            .expect("the handshake still admits the revoked leaf: its chain is unchanged"),
        Outcome::InvalidClient,
        "a revoked leaf is refused at the route"
    );
    listener.handle.stop(true).await;
}

/// #610 (b), second half — R1W1-02 at the route. One listener trusts both
/// organizations' anchors, so every leaf below completes the handshake and
/// carries the client's registered subject; only the leaf the client's own
/// tenant issued — or one under an anchor the client's organization holds —
/// authenticates it.
#[actix_rt::test]
async fn a_leaf_of_another_tenants_ca_is_refused_at_the_token_route_under_tls_client_auth() {
    let _turn = LISTENER_TURN.lock().await;
    let f = RouteFixture::new().await;
    let own = ClientIdentity::issued(&f.issue(f.org_a, f.tenant_a, &f.ca_a).await, &f.ca_a);
    let sibling = ClientIdentity::issued(&f.issue(f.org_a, f.tenant_b, &f.ca_b).await, &f.ca_b);
    let foreign = ClientIdentity::issued(&f.issue(f.org_b, f.tenant_c, &f.ca_c).await, &f.ca_c);

    // Certificates AXIAM did not issue are decided on the chain the listener
    // reports, which only a real handshake produces: an anchor another
    // organization imported and flagged, and one the client's own did.
    let attacker_anchor = ExternalCa::new("Org B Imported Anchor");
    f.import_and_flag(f.org_b, &attacker_anchor).await;
    let own_anchor = ExternalCa::new("Org A Imported Anchor");
    f.import_and_flag(f.org_a, &own_anchor).await;

    let listener = f.listen().await;
    for (identity, expected, what) in [
        (
            &own,
            Outcome::Tokens,
            "the client's own tenant CA (control)",
        ),
        (
            &sibling,
            Outcome::InvalidClient,
            "a sibling tenant's CA, same organization",
        ),
        (
            &foreign,
            Outcome::InvalidClient,
            "another organization's tenant CA",
        ),
        (
            &attacker_anchor.client_leaf(),
            Outcome::InvalidClient,
            "an anchor another organization imported",
        ),
        (
            &own_anchor.client_leaf(),
            Outcome::Tokens,
            "an anchor the client's organization imported (control)",
        ),
    ] {
        let outcome = f
            .token(&listener, Some(identity))
            .await
            .unwrap_or_else(|e| panic!("{what}: the handshake must admit it, failed with {e}"));
        assert_eq!(outcome, expected, "{what}");
    }
    listener.handle.stop(true).await;
}

/// The handshake is the first gate: a leaf that chains to no anchor the
/// listener trusts — here a CA nobody imported or flagged, carrying the
/// client's subject — gets no HTTP answer at all, while a connection with no
/// certificate reaches the route under `optional` and is refused there.
#[actix_rt::test]
async fn a_leaf_chained_to_no_listener_anchor_is_refused_at_the_handshake() {
    let _turn = LISTENER_TURN.lock().await;
    let f = RouteFixture::new().await;
    let listener = f.listen().await;

    assert_eq!(
        f.token(&listener, None)
            .await
            .expect("no certificate is an HTTP answer under optional"),
        Outcome::InvalidClient
    );
    let stray = ExternalCa::new("Unflagged CA").client_leaf();
    assert!(
        f.token(&listener, Some(&stray)).await.is_err(),
        "a leaf no listener anchor vouches for must not reach the route"
    );
    listener.handle.stop(true).await;
}
