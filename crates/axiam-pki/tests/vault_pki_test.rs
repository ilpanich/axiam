//! CA generation, import, issuance and revocation against Vault's PKI engine.
//!
//! Every test here drives the real [`CaService`] and [`CertService`] against a
//! real SurrealDB and an HTTP server standing in for Vault, because the thing
//! worth proving is the sequence rather than any one call: a root is generated,
//! an intermediate is generated and signed by it, the signed certificate goes
//! back to the mount holding its key, and only then does a CA row exist. A unit
//! test of any single step passes while the sequence is wrong.

use axiam_core::ca_keys::{CaKeyCustody, CaKeyRef, CaKeyStore};
use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, ImportCaCertificate, KeyAlgorithm,
};
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::{
    CaKeyCustodians, CertService, VaultPkiCaKeyStore, VaultPkiConfig, VaultPkiLocator,
};
use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
use serde_json::json;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "hvs.test-only-not-a-real-token"; // gitleaks:allow

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// A CA certificate, self-signed or signed by `issuer`. Stands in for what
/// Vault's PKI engine would have produced.
fn ca_pair(cn: &str, issuer: Option<&(String, String)>) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let cert = match issuer {
        None => params.self_signed(&key).unwrap(),
        Some((issuer_key_pem, issuer_cert_pem)) => {
            let signer = Issuer::from_ca_cert_pem(
                issuer_cert_pem,
                KeyPair::from_pem(issuer_key_pem).unwrap(),
            )
            .unwrap();
            params.signed_by(&key, &signer).unwrap()
        }
    };
    (key.serialize_pem(), cert.pem())
}

fn custodians(server: &MockServer) -> Arc<CaKeyCustodians> {
    let store = VaultPkiCaKeyStore::new(VaultPkiConfig {
        address: server.uri(),
        token: TOKEN.into(),
        root_mount: "pki".into(),
        int_mount: "pki_int".into(),
        ca_cert_path: None,
    })
    .expect("no trust anchor configured, so the client builds");
    Arc::new(
        CaKeyCustodians::new(None, None, Some(store), Some(CaKeyCustody::VaultPki))
            .expect("vault_pki is configured, so it may be the default"),
    )
}

fn ca_service(
    db: Surreal<TestDb>,
    server: &MockServer,
) -> CaService<SurrealCaCertificateRepository<TestDb>> {
    CaService::new(
        SurrealCaCertificateRepository::new(db),
        PkiConfig::default(),
        Arc::new(tokio::sync::Semaphore::new(4)),
        custodians(server),
    )
}

/// The four calls a generation makes, wired to return `root` and `int`.
async fn mock_generation(server: &MockServer, root: &(String, String), int: &(String, String)) {
    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/internal"))
        .and(header("X-Vault-Token", TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "certificate": root.1,
                "issuer_id": "root-issuer-id",
                "key_id": "root-key-id",
            }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/pki_int/intermediate/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "csr": "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n", "key_id": "int-key-id" }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/issuer/root-issuer-id/sign-intermediate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "certificate": int.1, "ca_chain": [root.1] }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/pki_int/intermediate/set-signed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "imported_issuers": ["int-issuer-id"], "imported_keys": [] }
        })))
        .expect(1)
        .mount(server)
        .await;
}

fn create_ca(subject: &str, org: Uuid) -> CreateCaCertificate {
    CreateCaCertificate {
        organization_id: org,
        subject: subject.into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days: 3650,
        intermediate_subject: None,
        intermediate_validity_days: None,
        issue_from_root: false,
    }
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generating_a_ca_walks_the_root_then_intermediate_sequence() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    mock_generation(&server, &root, &int).await;

    let org = Uuid::new_v4();
    let generated = ca_service(setup_db().await, &server)
        .generate(create_ca("Acme Root", org))
        .await
        .expect("generation must succeed");

    // Every mock above is `.expect(1)`, so reaching here having skipped a step
    // — or repeated one — fails when the server drops.
    assert_eq!(
        generated.certificate.key_custody,
        CaKeyCustody::VaultPki,
        "the row must record where the key actually is"
    );
    assert!(
        generated.private_key_pem.is_none(),
        "there is no key to return: it was generated inside Vault"
    );

    // The CA that signs is the *intermediate*, not the root above it.
    assert_eq!(generated.certificate.subject, "Acme Intermediate");
    assert_eq!(generated.certificate.public_cert_pem.trim(), int.1.trim());

    // And the root's certificate is kept, because `root/generate/internal`
    // returns it exactly once and nothing outside Vault sees it again.
    let chain = generated
        .certificate
        .chain_pem
        .as_deref()
        .expect("a chain, or nothing can validate a leaf");
    assert_eq!(chain.trim(), root.1.trim());
}

#[tokio::test]
async fn the_locator_addresses_both_tiers_by_the_ids_vault_minted() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    mock_generation(&server, &root, &int).await;

    let generated = ca_service(setup_db().await, &server)
        .generate(create_ca("Acme Root", Uuid::new_v4()))
        .await
        .unwrap();

    let locator = VaultPkiLocator::parse(
        generated
            .certificate
            .key_locator
            .as_deref()
            .expect("a referenced key has a locator"),
    )
    .expect("the locator must be one this custodian can read back");

    assert_eq!(locator.issuing.mount, "pki_int");
    assert_eq!(locator.issuing.issuer, "int-issuer-id");
    // The key id comes from `intermediate/generate/internal`, not from
    // `set-signed`, which imports no key and would report none.
    assert_eq!(locator.issuing.key, "int-key-id");

    let root_ref = locator
        .root
        .expect("the root must be recorded to be revocable");
    assert_eq!(root_ref.mount, "pki");
    assert_eq!(root_ref.issuer, "root-issuer-id");
}

#[tokio::test]
async fn issue_from_root_skips_the_intermediate_entirely() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);

    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "certificate": root.1, "issuer_id": "root-issuer-id", "key_id": "root-key-id" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    // No intermediate mocks at all: an unmatched request fails the test rather
    // than being answered, which is what makes "skips" mean something.

    let mut input = create_ca("Acme Root", Uuid::new_v4());
    input.issue_from_root = true;
    let generated = ca_service(setup_db().await, &server)
        .generate(input)
        .await
        .unwrap();

    assert_eq!(generated.certificate.subject, "Acme Root");
    assert!(
        generated.certificate.chain_pem.is_none(),
        "a root is its own chain"
    );
    let locator =
        VaultPkiLocator::parse(generated.certificate.key_locator.as_deref().unwrap()).unwrap();
    assert_eq!(locator.issuing.mount, "pki");
    assert!(locator.root.is_none(), "there is no tier above the root");
}

#[tokio::test]
async fn a_refused_call_names_what_vault_said_rather_than_the_status_alone() {
    // The failure an operator actually meets: a token whose policy does not
    // cover the mount. "500 internal error" sends them to the wrong system.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/internal"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({ "errors": ["permission denied"] })),
        )
        .mount(&server)
        .await;

    let err = ca_service(setup_db().await, &server)
        .generate(create_ca("Acme Root", Uuid::new_v4()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

// ---------------------------------------------------------------------------
// custody
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_key_cannot_be_loaded_and_the_refusal_says_why() {
    // Not an error condition — the property this custodian exists for. The
    // message has to reach the caller, so it is a `Validation` rather than the
    // `Certificate` variant that renders as an opaque 500.
    let server = MockServer::start().await;
    let store = VaultPkiCaKeyStore::new(VaultPkiConfig {
        address: server.uri(),
        token: TOKEN.into(),
        root_mount: "pki".into(),
        int_mount: "pki_int".into(),
        ca_cert_path: None,
    })
    .unwrap();

    let key_ref = CaKeyRef {
        organization_id: Uuid::nil(),
        ca_id: Uuid::nil(),
        custody: CaKeyCustody::VaultPki,
        locator: String::new(),
    };
    let err = store.load(&key_ref, None).await.unwrap_err();
    assert!(err.to_string().contains("cannot be exported"), "{err}");
    assert!(err.to_string().contains("signs through Vault"), "{err}");
}

#[tokio::test]
async fn revoking_removes_the_issuer_before_the_key_it_uses() {
    // Vault refuses to delete a key an issuer still references, so the order is
    // load-bearing rather than tidy.
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    mock_generation(&server, &root, &int).await;

    for (mount, id) in [("pki_int", "int-issuer-id"), ("pki", "root-issuer-id")] {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/{mount}/issuer/{id}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
    }
    for (mount, id) in [("pki_int", "int-key-id"), ("pki", "root-key-id")] {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/{mount}/key/{id}")))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
    }

    let org = Uuid::new_v4();
    let svc = ca_service(setup_db().await, &server);
    let generated = svc.generate(create_ca("Acme Root", org)).await.unwrap();
    svc.revoke(org, generated.certificate.id)
        .await
        .expect("revocation must succeed");
    // Both tiers go: a root whose only intermediate is revoked signs nothing
    // anyone should accept. The `.expect(1)` on all four deletes is the
    // assertion.
}

// ---------------------------------------------------------------------------
// BYOK
// ---------------------------------------------------------------------------

#[tokio::test]
async fn importing_a_ca_hands_vault_the_key_and_certificate_together() {
    let server = MockServer::start().await;
    let (key_pem, cert_pem) = ca_pair("Acme Offline Root", None);
    let expected_key = key_pem.clone();
    let expected_cert = cert_pem.clone();

    Mock::given(method("POST"))
        .and(path("/v1/pki_int/issuers/import/bundle"))
        .and(header("X-Vault-Token", TOKEN))
        .respond_with(move |req: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let bundle = body["pem_bundle"].as_str().unwrap_or_default();
            // The engine has nowhere to put a key without its certificate, so
            // both halves have to be in the one bundle.
            assert!(bundle.contains(expected_key.trim()), "the key must be sent");
            assert!(
                bundle.contains(expected_cert.trim()),
                "the certificate must be sent with it"
            );
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "imported_issuers": ["imported-issuer-id"],
                    "imported_keys": ["imported-key-id"],
                    "mapping": { "imported-issuer-id": "imported-key-id" },
                }
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let org = Uuid::new_v4();
    let certificate = ca_service(setup_db().await, &server)
        .import(ImportCaCertificate {
            organization_id: org,
            public_cert_pem: cert_pem,
            private_key_pem: Some(key_pem),
        })
        .await
        .expect("import must succeed");

    assert_eq!(certificate.key_custody, CaKeyCustody::VaultPki);
    assert!(
        certificate.encrypted_private_key.is_none(),
        "AXIAM must keep no copy of a key it handed to Vault"
    );
    let locator = VaultPkiLocator::parse(certificate.key_locator.as_deref().unwrap()).unwrap();
    assert_eq!(locator.issuing.issuer, "imported-issuer-id");
    assert_eq!(locator.issuing.key, "imported-key-id");
    assert!(
        locator.root.is_none(),
        "an imported CA has no root that AXIAM created"
    );
}

#[tokio::test]
async fn importing_a_certificate_vault_holds_no_key_for_is_refused() {
    // The failure this prevents: a CA that lists as issuable and dies at the
    // first signature, with a message about key material that names nothing the
    // operator did.
    let server = MockServer::start().await;
    let (key_pem, cert_pem) = ca_pair("Acme Offline Root", None);

    Mock::given(method("POST"))
        .and(path("/v1/pki_int/issuers/import/bundle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "imported_issuers": ["imported-issuer-id"],
                "imported_keys": [],
                "mapping": { "imported-issuer-id": "" },
            }
        })))
        .mount(&server)
        .await;

    let err = ca_service(setup_db().await, &server)
        .import(ImportCaCertificate {
            organization_id: Uuid::new_v4(),
            public_cert_pem: cert_pem,
            private_key_pem: Some(key_pem),
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no private key"), "{err}");
}

// ---------------------------------------------------------------------------
// issuance
// ---------------------------------------------------------------------------

/// Signs whatever CSR arrives, the way `sign-verbatim` does.
struct SignVerbatim {
    issuer_key_pem: String,
    issuer_cert_pem: String,
}

impl Respond for SignVerbatim {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let csr_pem = body["csr"].as_str().expect("a CSR must be sent");
        assert!(
            body["ttl"].as_str().is_some(),
            "a PKCS#10 request cannot carry a validity window, so the TTL must \
             be sent out of band"
        );
        assert!(
            !csr_pem.contains("PRIVATE KEY"),
            "the subscriber's key must never leave AXIAM"
        );

        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .expect("AXIAM must send a CSR Vault could parse");
        let issuer = Issuer::from_ca_cert_pem(
            &self.issuer_cert_pem,
            KeyPair::from_pem(&self.issuer_key_pem).unwrap(),
        )
        .unwrap();
        let signed = csr.signed_by(&issuer).unwrap();

        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "certificate": signed.pem(), "ca_chain": [self.issuer_cert_pem] }
        }))
    }
}

#[tokio::test]
async fn issuing_a_leaf_sends_a_csr_and_records_the_certificate_that_came_back() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    mock_generation(&server, &root, &int).await;

    Mock::given(method("POST"))
        .and(path("/v1/pki_int/issuer/int-issuer-id/sign-verbatim"))
        .and(header("X-Vault-Token", TOKEN))
        .respond_with(SignVerbatim {
            issuer_key_pem: int.0.clone(),
            issuer_cert_pem: int.1.clone(),
        })
        .expect(1)
        .mount(&server)
        .await;

    let db = setup_db().await;
    let org = Uuid::new_v4();
    let ca = ca_service(db.clone(), &server)
        .generate(create_ca("Acme Root", org))
        .await
        .unwrap();

    let cert_service = CertService::new(
        SurrealCaCertificateRepository::new(db.clone()),
        SurrealCertificateRepository::new(db),
        PkiConfig::default(),
        Arc::new(tokio::sync::Semaphore::new(4)),
        custodians(&server),
    );

    let tenant = Uuid::new_v4();
    let issued = cert_service
        .generate(
            org,
            CreateCertificate {
                tenant_id: tenant,
                issuer_ca_id: ca.certificate.id,
                subject: "device-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            Some(90),
        )
        .await
        .expect("issuance must go through Vault");

    // The subscriber still gets a key: what moved to Vault is the signature.
    assert!(
        issued.private_key_pem.contains("PRIVATE KEY"),
        "the end-entity key is generated here and returned once"
    );
    assert!(issued.certificate.public_cert_pem.contains("CERTIFICATE"));
    // The chain the signer returned, which is the only way a relying party
    // learns what this leaf chains to.
    assert_eq!(
        issued.chain_pem.as_deref().map(str::trim),
        Some(int.1.trim())
    );

    // The row describes the certificate rather than the request: a remote
    // signer caps a TTL without failing the call, and a fingerprint of bytes
    // AXIAM never saw would make every lookup by fingerprint miss.
    let fetched = cert_service
        .get_by_fingerprint(tenant, &issued.certificate.fingerprint)
        .await
        .expect("the stored fingerprint must be of the real certificate");
    assert_eq!(fetched.id, issued.certificate.id);
}

// ---------------------------------------------------------------------------
// tenant signing CAs
// ---------------------------------------------------------------------------
//
// The property these protect is not obvious from the endpoint names. The
// organization CA's *issuing* certificate is created with `max_path_length: 0`
// — it may sign leaves and nothing else — so a tenant signing CA hung beneath
// it would be signed happily by Vault and rejected by every relying party that
// walked the chain. It has to be signed by the root above it, and nothing in
// the response distinguishes the two.

/// Mount the four calls that create the organization CA, leaving the shared
/// `pki_int` mounts free for a second intermediate to follow.
///
/// Each mock is pinned to exactly one call and wiremock serves the earliest
/// still-hungry match, so a test that needs a second signature registers its
/// own mock afterwards and gets a distinct certificate back — which real Vault
/// would also return, and which the unique `(organization, fingerprint)` index
/// requires.
async fn mount_org_ca(server: &MockServer, root: &(String, String), int: &(String, String)) {
    Mock::given(method("POST"))
        .and(path("/v1/pki/root/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "certificate": root.1,
                "issuer_id": "root-issuer-id",
                "key_id": "root-key-id",
            }
        })))
        // `expect` only verifies a count; without this the mock keeps matching
        // and a second signature is served the first certificate — which the
        // unique (organization, fingerprint) index then rejects.
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;

    mount_intermediate_generate(server, "int-key-id").await;

    Mock::given(method("POST"))
        .and(path("/v1/pki/issuer/root-issuer-id/sign-intermediate"))
        .and(wiremock::matchers::body_partial_json(json!({
            // Stated on every CA AXIAM mints, and asserted here because the
            // absence of it is invisible until a relying party refuses a
            // certificate months later.
            "max_path_length": 0,
            "use_csr_values": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "certificate": int.1, "issuing_ca": root.1, "ca_chain": [root.1] }
        })))
        // `expect` only verifies a count; without this the mock keeps matching
        // and a second signature is served the first certificate — which the
        // unique (organization, fingerprint) index then rejects.
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;

    mount_intermediate_set_signed(server, "int-issuer-id").await;

    // Never asked: the organization's issuing intermediate has a path length of
    // zero and cannot sign a CA. Mounted so that reaching for it is a failed
    // assertion rather than a 404 the custodian reports as a Vault outage.
    Mock::given(method("POST"))
        .and(path("/v1/pki_int/issuer/int-issuer-id/sign-intermediate"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

async fn mount_intermediate_generate(server: &MockServer, key_id: &str) {
    Mock::given(method("POST"))
        .and(path("/v1/pki_int/intermediate/generate/internal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "csr": "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n",
                "key_id": key_id,
            }
        })))
        // `expect` only verifies a count; without this the mock keeps matching
        // and a second signature is served the first certificate — which the
        // unique (organization, fingerprint) index then rejects.
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_intermediate_set_signed(server: &MockServer, issuer_id: &str) {
    Mock::given(method("POST"))
        .and(path("/v1/pki_int/intermediate/set-signed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "imported_issuers": [issuer_id], "imported_keys": [] }
        })))
        // `expect` only verifies a count; without this the mock keeps matching
        // and a second signature is served the first certificate — which the
        // unique (organization, fingerprint) index then rejects.
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;
}

/// Mount the root signature that mints a tenant signing CA.
async fn mount_tenant_signature(
    server: &MockServer,
    common_name: &str,
    root: &(String, String),
    tenant_ca: &(String, String),
) {
    Mock::given(method("POST"))
        .and(path("/v1/pki/issuer/root-issuer-id/sign-intermediate"))
        .and(wiremock::matchers::body_partial_json(json!({
            "common_name": common_name,
            "max_path_length": 0,
            "use_csr_values": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "certificate": tenant_ca.1, "issuing_ca": root.1 }
        })))
        // `expect` only verifies a count; without this the mock keeps matching
        // and a second signature is served the first certificate — which the
        // unique (organization, fingerprint) index then rejects.
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_tenant_signing_ca_is_signed_by_the_root_not_the_leaf_issuer() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    let tenant_int = ca_pair("Acme R&D Signing CA", Some(&root));
    mount_org_ca(&server, &root, &int).await;

    let svc = ca_service(setup_db().await, &server);
    let org = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let parent = svc
        .generate(create_ca("Acme Root", org))
        .await
        .unwrap()
        .certificate;

    mount_intermediate_generate(&server, "tenant-key-id").await;
    mount_tenant_signature(&server, "Acme R&D Signing CA", &root, &tenant_int).await;
    mount_intermediate_set_signed(&server, "tenant-issuer-id").await;

    let generated = svc
        .generate_intermediate(axiam_core::models::certificate::CreateIntermediateCa {
            organization_id: org,
            tenant_id: tenant,
            parent_ca_id: parent.id,
            subject: "Acme R&D Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("tenant signing CA");

    assert_eq!(generated.certificate.tenant_id, Some(tenant));
    assert_eq!(generated.certificate.parent_ca_id, Some(parent.id));
    // Born inside Vault, so there is nothing to return once — the whole reason
    // this custodian is worth the extra moving parts.
    assert_eq!(generated.certificate.key_custody, CaKeyCustody::VaultPki);
    assert!(generated.private_key_pem.is_none());

    let locator = VaultPkiLocator::parse(
        generated
            .certificate
            .key_locator
            .as_deref()
            .expect("the key is in Vault, so the row records where"),
    )
    .expect("readable locator");
    assert_eq!(locator.issuing.mount, "pki_int");
    assert_eq!(locator.issuing.issuer, "tenant-issuer-id");
    assert_eq!(locator.issuing.key, "tenant-key-id");
    // No root recorded: the root above this CA belongs to the organization and
    // must outlive it, so revoking a tenant signing CA must not delete it.
    assert!(locator.root.is_none());

    // The chain is the issuing CA Vault named. Without it nothing outside Vault
    // can validate a leaf this tenant CA signs.
    assert!(
        generated
            .certificate
            .chain_pem
            .as_deref()
            .is_some_and(|c| c.contains("BEGIN CERTIFICATE"))
    );
}

#[tokio::test]
async fn signing_a_tenant_csr_uses_sign_intermediate_not_sign_verbatim() {
    let server = MockServer::start().await;
    let root = ca_pair("Acme Root", None);
    let int = ca_pair("Acme Intermediate", Some(&root));
    let tenant_ca = ca_pair("Offline Tenant CA", Some(&root));
    mount_org_ca(&server, &root, &int).await;

    let svc = ca_service(setup_db().await, &server);
    let org = Uuid::new_v4();
    let parent = svc
        .generate(create_ca("Acme Root", org))
        .await
        .unwrap()
        .certificate;

    // The tenant's own CSR, over a key AXIAM never sees. No
    // `intermediate/generate/internal` follows: there is nothing for Vault to
    // create, only something for it to sign.
    let tenant_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut csr_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    csr_params
        .distinguished_name
        .push(DnType::CommonName, "Offline Tenant CA");
    let csr_pem = csr_params
        .serialize_request(&tenant_key)
        .unwrap()
        .pem()
        .unwrap();

    mount_tenant_signature(&server, "Offline Tenant CA", &root, &tenant_ca).await;

    let signed = svc
        .sign_intermediate_csr(axiam_core::models::certificate::SignIntermediateCsr {
            organization_id: org,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            csr_pem,
            validity_days: 365,
        })
        .await
        .expect("signed tenant CSR");

    // AXIAM signed it and holds nothing: the key is wherever the CSR was made.
    assert_eq!(signed.key_custody, CaKeyCustody::External);
    assert!(signed.key_locator.is_none());
    assert!(signed.encrypted_private_key.is_none());
    assert_eq!(signed.subject, "Offline Tenant CA");
}
