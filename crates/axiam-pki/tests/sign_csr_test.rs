//! `CertService::sign_csr` — an end-entity certificate for a key AXIAM never
//! sees (C-1, T-268).
//!
//! One test per rule the endpoint states. The rules are the feature: a CSR path
//! that signed what it was asked for rather than what AXIAM decided would be a
//! way to mint a CA, a certificate for a name you do not hold, or one over a
//! 2048-bit key recorded as 4096.

use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm,
    SignCertificateCsr, StoreCaCertificate,
};
use axiam_core::repository::CaCertificateRepository;
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use chrono::{Duration, Utc};
use rsa::pkcs8::EncodePrivateKey;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

type TestDb = surrealdb::engine::local::Db;

fn custodians() -> std::sync::Arc<axiam_pki::CaKeyCustodians> {
    std::sync::Arc::new(
        axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
            .expect("test CA key custodians"),
    )
}

fn pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
        ..Default::default()
    }
}

struct Fixture {
    certs:
        CertService<SurrealCaCertificateRepository<TestDb>, SurrealCertificateRepository<TestDb>>,
    ca_repo: SurrealCaCertificateRepository<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    ca_id: Uuid,
}

async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let org_id = Uuid::new_v4();

    let ca = CaService::new(ca_repo.clone(), pki_config(), sem.clone(), custodians())
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Test Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 3650,
            intermediate_subject: None,
            intermediate_validity_days: None,
            issue_from_root: false,
        })
        .await
        .expect("CA generation");

    Fixture {
        certs: CertService::new(ca_repo.clone(), cert_repo, pki_config(), sem, custodians()),
        ca_repo,
        org_id,
        tenant_id: Uuid::new_v4(),
        ca_id: ca.certificate.id,
    }
}

impl Fixture {
    fn request(&self, csr_pem: String) -> SignCertificateCsr {
        SignCertificateCsr {
            tenant_id: self.tenant_id,
            issuer_ca_id: self.ca_id,
            csr_pem,
            cert_type: CertificateType::Service,
            validity_days: 30,
            metadata: None,
        }
    }
}

/// An Ed25519 CSR with nothing but a common name — the ordinary case.
fn plain_csr(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem")
}

fn with_cert<T>(pem: &str, f: impl FnOnce(&X509Certificate<'_>) -> T) -> T {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    let (_, cert) = X509Certificate::from_der(&block.contents).expect("DER");
    f(&cert)
}

fn validation_message(err: &AxiamError) -> String {
    match err {
        AxiamError::Validation { message } => message.clone(),
        other => panic!("expected a Validation error (a 400), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Happy path, and what the certificate says
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_csr_becomes_a_leaf_certificate_and_no_key_is_produced() {
    let f = fixture().await;

    let cert = f
        .certs
        .sign_csr(f.org_id, f.request(plain_csr("device-001")), None)
        .await
        .expect("a well-formed CSR must be signed");

    // The subject is the CSR's, so the row and the certificate agree (T-194).
    assert_eq!(cert.subject, "device-001");
    assert_eq!(cert.tenant_id, f.tenant_id);
    assert_eq!(cert.issuer_ca_id, f.ca_id);
    assert_eq!(cert.status, CertificateStatus::Active);
    // Read off the CSR's public key, not asserted by the caller.
    assert_eq!(cert.key_algorithm, KeyAlgorithm::Ed25519);
    assert!(cert.public_cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(
        !cert.public_cert_pem.contains("PRIVATE KEY"),
        "no key exists on this path, so none can appear anywhere in the answer"
    );
    assert_eq!(cert.fingerprint.len(), 64, "SHA-256 hex over the DER");

    with_cert(&cert.public_cert_pem, |c| {
        assert!(
            !c.basic_constraints()
                .expect("readable")
                .map(|bc| bc.value.ca)
                .unwrap_or(false),
            "a leaf, not a CA"
        );
    });
}

#[tokio::test]
async fn a_csr_signed_leaf_is_the_same_shape_as_a_generated_one() {
    // D-5, parity. Two ways of asking for the same certificate must not produce
    // two different certificates: adding a usage profile to one path only would
    // be a worse outcome than neither having one.
    let f = fixture().await;

    let from_csr = f
        .certs
        .sign_csr(f.org_id, f.request(plain_csr("parity-check")), None)
        .await
        .expect("signed");
    let generated = f
        .certs
        .generate(
            f.org_id,
            CreateCertificate {
                tenant_id: f.tenant_id,
                issuer_ca_id: f.ca_id,
                subject: "parity-check".into(),
                cert_type: CertificateType::Service,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("generated");

    let extensions = |pem: &str| -> Vec<String> {
        with_cert(pem, |c| {
            let mut oids: Vec<String> = c
                .extensions()
                .iter()
                .map(|e| e.oid.to_id_string())
                .collect();
            oids.sort();
            oids
        })
    };
    assert_eq!(
        extensions(&from_csr.public_cert_pem),
        extensions(&generated.certificate.public_cert_pem),
        "the two leaf paths must carry the same extension set — neither has a \
         subjectAltName, a key usage or an extended key usage, and both say CA:FALSE"
    );
}

// ---------------------------------------------------------------------------
// Rule 1 — proof of possession
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_malformed_csr_is_a_validation_error_not_an_internal_one() {
    // The distinction matters at the HTTP boundary: `Validation` is a 400 whose
    // message reaches the operator who pasted the request; anything else is a
    // 500 that says "an internal error occurred".
    let f = fixture().await;

    for (what, csr) in [
        ("not PEM at all", "hello"),
        (
            "PEM that is not base64",
            "-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n\
             -----END CERTIFICATE REQUEST-----",
        ),
    ] {
        let err = f
            .certs
            .sign_csr(f.org_id, f.request(csr.into()), None)
            .await
            .unwrap_err();
        let message = validation_message(&err);
        assert!(
            message.contains("certificate signing request"),
            "the message must name the request ({what}): {message}"
        );
    }
}

#[tokio::test]
async fn a_csr_whose_signature_does_not_verify_is_refused() {
    // The whole point of the endpoint. Without this check a caller could have a
    // certificate minted over somebody else's public key.
    let f = fixture().await;

    let mut csr = plain_csr("impostor");
    // Corrupt the signature by flipping a character deep inside the base64
    // body, which leaves the PEM framing and the DER structure intact.
    let body_start = csr.find('\n').expect("a PEM has line breaks") + 40;
    let victim = csr.as_bytes()[body_start];
    let replacement = if victim == b'A' { b'B' } else { b'A' };
    unsafe { csr.as_bytes_mut()[body_start] = replacement };

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .unwrap_err();
    let message = validation_message(&err);
    assert!(
        message.contains("could not be parsed") || message.contains("does not verify"),
        "a request that does not prove possession must be refused: {message}"
    );
}

#[tokio::test]
async fn the_subject_is_the_csr_s_and_comes_from_nowhere_else() {
    // There is no `subject` field on the request type, so this is the only
    // place a name can come from — which is what keeps the row and the
    // certificate from disagreeing (T-194).
    //
    // A CSR carrying *no* common name is refused by `ca::inspect_csr`, and that
    // branch is not exercised here: rcgen substitutes the placeholder
    // "rcgen self signed cert" when asked to serialize a request with an empty
    // distinguished name, so a CN-less CSR cannot be built with the tools this
    // test has. An openssl-built one can be, and is refused; the check is one
    // line and reads its own condition.
    let f = fixture().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let cert = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .expect("rcgen's placeholder name is still a name");
    assert_eq!(
        cert.subject, "rcgen self signed cert",
        "whatever the CSR says is what the certificate and the row say"
    );
}

// ---------------------------------------------------------------------------
// Rule 2 — key policy (D-4, T-96)
// ---------------------------------------------------------------------------

/// An RSA CSR of the requested modulus size. Built the way production builds
/// RSA keys, because rcgen's signer cannot generate them.
fn rsa_csr(bits: usize, common_name: &str) -> String {
    let mut rng = rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).expect("RSA keygen");
    let pkcs8 = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("PKCS#8");
    let key = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)
        .expect("rcgen accepts the RSA key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem")
}

#[tokio::test]
async fn an_rsa_2048_csr_is_refused_rather_than_recorded_as_rsa_4096() {
    // T-96, and the reason the modulus check has to be explicit:
    // `parse_ca_certificate` maps *any* RSA OID onto `KeyAlgorithm::Rsa4096`,
    // deliberately, so an imported root of another size stays usable. Reusing
    // that mapping here would sign a 2048-bit key and write "Rsa4096" on the
    // row — a certificate weaker than every reader of that row believes.
    let f = fixture().await;

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(rsa_csr(2048, "too-small")), None)
        .await
        .unwrap_err();
    let message = validation_message(&err);
    assert!(
        message.contains("2048") && message.contains("4096"),
        "the refusal must name both the modulus found and the floor: {message}"
    );
}

#[tokio::test]
async fn an_rsa_4096_csr_is_signed_and_recorded_as_rsa_4096() {
    let f = fixture().await;

    let cert = f
        .certs
        .sign_csr(f.org_id, f.request(rsa_csr(4096, "big-enough")), None)
        .await
        .expect("an RSA-4096 CSR is within policy");
    assert_eq!(cert.key_algorithm, KeyAlgorithm::Rsa4096);
    assert_eq!(cert.subject, "big-enough");
}

#[tokio::test]
async fn an_ecdsa_csr_is_refused_by_name() {
    // P-256 is a perfectly good key and AXIAM does not sign over it. The
    // refusal names what is accepted, so the operator's next attempt works.
    let f = fixture().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "p256-device");
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .unwrap_err();
    let message = validation_message(&err);
    assert!(
        message.contains("Ed25519") && message.contains("RSA"),
        "the refusal must say what AXIAM does sign: {message}"
    );
}

// ---------------------------------------------------------------------------
// Rule 3 — extensions (D-3, D-5)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_csr_that_asked_to_be_a_ca_does_not_get_to_be_one() {
    // The leaf twin of `a_csr_that_asked_to_be_an_unconstrained_ca_does_not_get_to_be_one`.
    // Basic constraints are overwritten rather than refused: the in-process
    // path replaces the whole parameter set, and Vault ignores a CSR's basic
    // constraints outright, so there is no custodian on which asking could work.
    let f = fixture().await;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ambitious-leaf");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let cert = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .expect("signed as a leaf");

    with_cert(&cert.public_cert_pem, |c| {
        assert!(
            !c.basic_constraints()
                .expect("readable")
                .map(|bc| bc.value.ca)
                .unwrap_or(false),
            "the request's own extensions must not decide its powers"
        );
        assert!(
            c.key_usage().expect("readable").is_none(),
            "a leaf AXIAM issues carries no key usage extension, on either path"
        );
    });
}

#[tokio::test]
async fn a_csr_requesting_a_subject_alt_name_is_refused_and_told_why() {
    // D-3. Silent stripping is what the intermediate path does for its
    // extensions, but a CA has no SANs and a caller cannot have meant them
    // there. A caller who put SANs in a *leaf* CSR meant them, and a
    // certificate issued without them and with nothing said fails where it is
    // deployed.
    let f = fixture().await;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params =
        rcgen::CertificateParams::new(vec!["service.example.com".to_string()]).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "service.example.com");
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .unwrap_err();
    let message = validation_message(&err);
    assert!(
        message.contains("subjectAltName"),
        "the refusal must name the extension: {message}"
    );
    assert!(
        message.contains("Remove the extension request"),
        "and say what to do about it: {message}"
    );
}

#[tokio::test]
async fn a_csr_requesting_key_usage_is_refused_because_vault_would_honour_it() {
    // The rule exists for a custodian this test does not run against, which is
    // exactly why it is enforced here rather than in the Vault branch: Vault's
    // `sign-verbatim` discards the `key_usage` request parameter when the CSR
    // carries the extension and issues what the CSR asked for. Refusing in the
    // shared inspection is what keeps one CSR from being accepted on a
    // database-custody deployment and refused on a Vault one, or worse, signed
    // differently by each.
    let f = fixture().await;

    for (label, usages) in [
        (
            "keyUsage",
            vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ],
        ),
        (
            "digitalSignature",
            vec![rcgen::KeyUsagePurpose::DigitalSignature],
        ),
    ] {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "usage-requester");
        params.key_usages = usages;
        let csr = params
            .serialize_request(&key)
            .expect("csr")
            .pem()
            .expect("pem");

        let err = f
            .certs
            .sign_csr(f.org_id, f.request(csr), None)
            .await
            .unwrap_err();
        let message = validation_message(&err);
        assert!(
            message.contains("keyUsage"),
            "the refusal must name the extension ({label}): {message}"
        );
    }
}

#[tokio::test]
async fn a_csr_requesting_an_extended_key_usage_is_refused() {
    let f = fixture().await;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "eku-requester");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let csr = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(csr), None)
        .await
        .unwrap_err();
    assert!(validation_message(&err).contains("extendedKeyUsage"));
}

// ---------------------------------------------------------------------------
// Rule 4 — tenant and issuer scope (T-98)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_ca_in_another_organization_is_not_found() {
    let f = fixture().await;

    let err = f
        .certs
        .sign_csr(Uuid::new_v4(), f.request(plain_csr("cross-org")), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, AxiamError::NotFound { .. }),
        "a CA belonging to another organization must be invisible, not merely \
         refused — got {err:?}"
    );
}

#[tokio::test]
async fn a_revoked_ca_cannot_sign() {
    let f = fixture().await;
    f.ca_repo.revoke(f.org_id, f.ca_id).await.expect("revoked");

    let err = f
        .certs
        .sign_csr(f.org_id, f.request(plain_csr("after-revocation")), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, AxiamError::Certificate(m) if m.contains("not active")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn an_expired_ca_cannot_sign() {
    let f = fixture().await;
    // A CA row whose window has already closed. Stored directly: the generation
    // path will not produce one, which is the point.
    let expired_id = Uuid::new_v4();
    let expired = f
        .ca_repo
        .create(StoreCaCertificate {
            id: expired_id,
            organization_id: f.org_id,
            tenant_id: None,
            parent_ca_id: None,
            subject: "Expired CA".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
                .into(),
            chain_pem: None,
            fingerprint: "0".repeat(64),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::days(400),
            not_after: Utc::now() - Duration::days(1),
            encrypted_private_key: None,
            key_custody: axiam_core::ca_keys::CaKeyCustody::Database,
            key_locator: None,
        })
        .await
        .expect("stored");

    let mut request = f.request(plain_csr("after-expiry"));
    request.issuer_ca_id = expired.id;
    let err = f.certs.sign_csr(f.org_id, request, None).await.unwrap_err();
    assert!(
        matches!(&err, AxiamError::Certificate(m) if m.contains("expired or not yet valid")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn an_imported_ca_with_no_key_cannot_sign() {
    // `External` custody: AXIAM holds the certificate as a trust anchor and has
    // no key to issue with. `store_for` gives this refusal for free, which is
    // why the CSR path gets it without stating it.
    let f = fixture().await;
    let external_id = Uuid::new_v4();
    let external = f
        .ca_repo
        .create(StoreCaCertificate {
            id: external_id,
            organization_id: f.org_id,
            tenant_id: None,
            parent_ca_id: None,
            subject: "Imported Anchor".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
                .into(),
            chain_pem: None,
            fingerprint: "1".repeat(64),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(365),
            encrypted_private_key: None,
            key_custody: axiam_core::ca_keys::CaKeyCustody::External,
            key_locator: None,
        })
        .await
        .expect("stored");

    let mut request = f.request(plain_csr("no-key-to-sign-with"));
    request.issuer_ca_id = external.id;
    assert!(f.certs.sign_csr(f.org_id, request, None).await.is_err());
}

// ---------------------------------------------------------------------------
// Rule 5 — validity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validity_is_capped_the_same_way_generation_is() {
    let f = fixture().await;

    for (days, tenant_cap, what) in [
        (0u32, None, "zero days"),
        (900, None, "beyond the 825-day hard cap"),
        (60, Some(30u32), "beyond the tenant's own cap"),
    ] {
        let mut request = f.request(plain_csr("validity-check"));
        request.validity_days = days;
        let err = f
            .certs
            .sign_csr(f.org_id, request, tenant_cap)
            .await
            .unwrap_err();
        let message = validation_message(&err);
        assert!(
            message.contains("validity_days"),
            "{what} must be refused by name: {message}"
        );
    }
}

#[tokio::test]
async fn a_certificate_may_not_outlive_its_issuer_and_is_told_what_it_can_have() {
    let f = fixture().await;
    // A CA with a fortnight left. The refusal quotes the real number rather
    // than silently truncating, so a renewal calendar is not built on a date
    // the certificate does not carry.
    let short_id = Uuid::new_v4();
    let short = f
        .ca_repo
        .create(StoreCaCertificate {
            id: short_id,
            organization_id: f.org_id,
            tenant_id: None,
            parent_ca_id: None,
            subject: "Nearly Expired CA".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----"
                .into(),
            chain_pem: None,
            fingerprint: "2".repeat(64),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(14),
            encrypted_private_key: None,
            key_custody: axiam_core::ca_keys::CaKeyCustody::Database,
            key_locator: None,
        })
        .await
        .expect("stored");

    let mut request = f.request(plain_csr("too-long"));
    request.issuer_ca_id = short.id;
    request.validity_days = 90;
    let err = f.certs.sign_csr(f.org_id, request, None).await.unwrap_err();
    let message = validation_message(&err);
    assert!(
        message.contains("cannot outlive its issuer") && message.contains("13 day"),
        "the refusal must name the number the CA can actually grant: {message}"
    );
}

// ---------------------------------------------------------------------------
// Rule 7 — the row says what the certificate says
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_row_and_the_certificate_agree_and_the_certificate_is_retrievable() {
    let f = fixture().await;

    let cert = f
        .certs
        .sign_csr(f.org_id, f.request(plain_csr("round-trip")), None)
        .await
        .expect("signed");

    let fetched = f
        .certs
        .get(f.tenant_id, cert.id)
        .await
        .expect("the certificate is readable afterwards");
    assert_eq!(fetched.fingerprint, cert.fingerprint);
    assert_eq!(fetched.subject, "round-trip");

    // The fingerprint is over the DER of the certificate that was produced, so
    // a lookup by fingerprint — which is how mTLS finds a certificate — hits.
    let by_fingerprint = f
        .certs
        .get_by_fingerprint(f.tenant_id, &cert.fingerprint)
        .await
        .expect("findable by fingerprint");
    assert_eq!(by_fingerprint.id, cert.id);

    with_cert(&cert.public_cert_pem, |c| {
        let cn = c
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .expect("a common name");
        assert_eq!(cn, fetched.subject, "T-194: the row cannot disagree");
    });
}

#[tokio::test]
async fn metadata_is_stored_as_given_and_defaults_to_an_empty_object() {
    let f = fixture().await;

    let mut request = f.request(plain_csr("with-metadata"));
    request.metadata = Some(serde_json::json!({ "device_serial": "SN-42" }));
    let cert = f
        .certs
        .sign_csr(f.org_id, request, None)
        .await
        .expect("signed");
    assert_eq!(cert.metadata["device_serial"], "SN-42");

    let bare = f
        .certs
        .sign_csr(f.org_id, f.request(plain_csr("no-metadata")), None)
        .await
        .expect("signed");
    assert_eq!(bare.metadata, serde_json::json!({}));
}
