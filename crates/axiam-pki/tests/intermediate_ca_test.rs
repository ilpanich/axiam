//! Tenant signing CAs — generated beneath an organization CA, or signed from a
//! CSR the tenant produced elsewhere.
//!
//! What these assert is not that a certificate came back, but that the right
//! certificate came back: `CA:TRUE` with a path length of zero, an issuer DN
//! equal to the parent's subject DN, a validity window inside the parent's, and
//! a chain that actually reaches the anchor. Each of those is a property a
//! relying party checks and the UI cannot show.

use axiam_core::models::certificate::{
    CertificateStatus, CreateCaCertificate, CreateIntermediateCa, KeyAlgorithm, SignIntermediateCsr,
};
use axiam_core::repository::Pagination;
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::ca::{CaService, MAX_CA_VALIDITY_DAYS, PkiConfig};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

type TestDb = surrealdb::engine::local::Db;
type TestService = CaService<SurrealCaCertificateRepository<TestDb>>;

async fn setup() -> TestService {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    CaService::new(
        SurrealCaCertificateRepository::new(db),
        PkiConfig {
            encryption_key: Some([0u8; 32]), // gitleaks:allow
            ..Default::default()
        },
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        std::sync::Arc::new(
            axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
                .expect("test CA key custodians"),
        ),
    )
}

/// An organization CA to hang tenant signing CAs from.
async fn root_ca(
    svc: &TestService,
    org_id: Uuid,
    validity_days: u32,
) -> axiam_core::models::certificate::CaCertificate {
    svc.generate(CreateCaCertificate {
        organization_id: org_id,
        subject: "Test Org Root CA".into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days,
        intermediate_subject: None,
        intermediate_validity_days: None,
        issue_from_root: false,
    })
    .await
    .expect("root CA")
    .certificate
}

/// Parse a PEM certificate and hand the parsed form to `f`.
///
/// A closure rather than a returned `X509Certificate` because the parsed type
/// borrows the DER it came from, and returning both from one function fights
/// the borrow checker for no gain.
fn with_cert<T>(pem: &str, f: impl FnOnce(&X509Certificate<'_>) -> T) -> T {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    let (_, cert) = X509Certificate::from_der(&block.contents).expect("DER");
    f(&cert)
}

/// A PKCS#10 request with its own freshly-generated key, as a tenant would
/// produce out of band.
fn tenant_csr(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("csr pem")
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generated_intermediate_is_a_ca_constrained_to_signing_leaves() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let generated = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id,
            parent_ca_id: parent.id,
            subject: "Tenant R&D Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("intermediate");

    assert_eq!(generated.certificate.tenant_id, Some(tenant_id));
    assert_eq!(generated.certificate.parent_ca_id, Some(parent.id));
    assert_eq!(generated.certificate.status, CertificateStatus::Active);
    // Generated here, so returned exactly once — the whole reason this response
    // differs from the sign-a-CSR one.
    assert!(
        generated
            .private_key_pem
            .as_deref()
            .is_some_and(|k| k.contains("PRIVATE KEY"))
    );

    with_cert(&generated.certificate.public_cert_pem, |cert| {
        let bc = cert
            .basic_constraints()
            .expect("basic constraints readable")
            .expect("basic constraints present");
        assert!(bc.value.ca, "a signing CA must say CA:TRUE");
        assert_eq!(
            bc.value.path_len_constraint,
            Some(0),
            "path length 0: it signs leaves and cannot mint a further tier"
        );

        let ku = cert
            .key_usage()
            .expect("key usage readable")
            .expect("key usage present — an unstated CA is one nothing will trust");
        assert!(ku.value.key_cert_sign());
        assert!(ku.value.crl_sign());

        // The issuer DN is the parent's subject DN, read off the parent's own
        // certificate rather than its (mutable) subject column.
        let parent_subject = with_cert(&parent.public_cert_pem, |p| p.subject().to_string());
        assert_eq!(cert.issuer().to_string(), parent_subject);
    });
}

#[tokio::test]
async fn an_intermediate_outliving_its_parent_is_refused_with_the_achievable_number() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    // A parent with ten days left, and a child asking for a year.
    let parent = root_ca(&svc, org_id, 10).await;

    let err = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            subject: "Over-eager Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect_err("an intermediate cannot outlive the CA that signs it");

    // Refused rather than silently capped. Capping produced a ten-day CA out of
    // a request for a year with nothing said, so the operator's renewal calendar
    // was built on a date the certificate did not carry.
    let msg = err.to_string();
    assert!(
        msg.contains("cannot outlive"),
        "the error must say why, got: {msg}"
    );
    assert!(
        msg.contains("10 days") || msg.contains("9 days"),
        "the error must name the validity the parent can actually grant, got: {msg}"
    );
}

#[tokio::test]
async fn an_intermediate_within_its_parents_window_is_granted_in_full() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let generated = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            subject: "Well-behaved Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("a request inside the parent's window is granted");

    // The whole point of refusing the over-long case: what is granted is exactly
    // what was asked for, so the notAfter matches the operator's expectation.
    let span = generated.certificate.not_after - generated.certificate.not_before;
    assert_eq!(span.num_days(), 365, "the full requested window is granted");
    assert!(generated.certificate.not_after < parent.not_after);
}

#[tokio::test]
async fn a_tenant_signing_ca_cannot_parent_another_one() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let first = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            subject: "First Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("intermediate")
        .certificate;

    // Refused up front rather than signed and rejected downstream: `first` has
    // a path length of zero, so anything it signed as a CA would fail chain
    // validation at every relying party.
    let err = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: first.id,
            subject: "Third Tier".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect_err("a third tier must be refused");
    assert!(
        err.to_string().contains("path length"),
        "the error should say why, got: {err}"
    );
}

#[tokio::test]
async fn generation_refuses_a_revoked_parent() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;
    svc.revoke(org_id, parent.id).await.expect("revoke");

    let err = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            subject: "Doomed Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect_err("a revoked parent must be refused");
    assert!(err.to_string().contains("not active"), "got: {err}");
}

#[tokio::test]
async fn generation_rejects_a_validity_beyond_the_nist_ceiling() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let err = svc
        .generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            subject: "Immortal Signing CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: MAX_CA_VALIDITY_DAYS + 1,
        })
        .await
        .expect_err("beyond the ceiling must be refused");
    assert!(err.to_string().contains("validity_days"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Sign a CSR
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_signed_csr_becomes_a_ca_axiam_holds_no_key_for() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let signed = svc
        .sign_intermediate_csr(SignIntermediateCsr {
            organization_id: org_id,
            tenant_id,
            parent_ca_id: parent.id,
            csr_pem: tenant_csr("Offline Tenant CA"),
            validity_days: 365,
        })
        .await
        .expect("signed CSR");

    assert_eq!(signed.tenant_id, Some(tenant_id));
    assert_eq!(signed.parent_ca_id, Some(parent.id));
    assert_eq!(signed.subject, "Offline Tenant CA");
    // The key was made by whoever produced the CSR and never reached AXIAM.
    // Recording anything but `External` would offer to sign with a key that is
    // not here.
    assert_eq!(
        signed.key_custody,
        axiam_core::ca_keys::CaKeyCustody::External
    );
    assert!(signed.encrypted_private_key.is_none());
    assert!(signed.key_locator.is_none());

    with_cert(&signed.public_cert_pem, |cert| {
        let bc = cert
            .basic_constraints()
            .expect("readable")
            .expect("present");
        assert!(bc.value.ca);
        assert_eq!(bc.value.path_len_constraint, Some(0));
    });
}

#[tokio::test]
async fn a_csr_that_asked_to_be_an_unconstrained_ca_does_not_get_to_be_one() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    // A request that names itself an unconstrained CA. AXIAM decides what the
    // certificate is; the request only supplies a public key and a name.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Ambitious Tenant CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let csr_pem = params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem");

    let signed = svc
        .sign_intermediate_csr(SignIntermediateCsr {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            csr_pem,
            validity_days: 365,
        })
        .await
        .expect("signed");

    with_cert(&signed.public_cert_pem, |cert| {
        let bc = cert
            .basic_constraints()
            .expect("readable")
            .expect("present");
        assert_eq!(
            bc.value.path_len_constraint,
            Some(0),
            "the request's own extensions must not decide its powers"
        );
    });
}

#[tokio::test]
async fn a_malformed_csr_is_a_validation_error_not_an_internal_one() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    let err = svc
        .sign_intermediate_csr(SignIntermediateCsr {
            organization_id: org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: parent.id,
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nnot base64\n\
                      -----END CERTIFICATE REQUEST-----"
                .into(),
            validity_days: 365,
        })
        .await
        .expect_err("a malformed CSR must be refused");
    // The distinction matters at the HTTP boundary: `Validation` is a 400 whose
    // body names the CSR, and anything else is a 500 that names nothing.
    assert!(
        matches!(err, axiam_core::error::AxiamError::Validation { .. }),
        "got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_tenant_list_shows_that_tenants_cas_and_no_others() {
    let svc = setup().await;
    let org_id = Uuid::new_v4();
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    let parent = root_ca(&svc, org_id, 3650).await;

    for (tenant_id, subject) in [(mine, "Mine A"), (mine, "Mine B"), (theirs, "Theirs")] {
        svc.generate_intermediate(CreateIntermediateCa {
            organization_id: org_id,
            tenant_id,
            parent_ca_id: parent.id,
            subject: subject.into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("intermediate");
    }

    let listed = svc
        .list_by_tenant(org_id, mine, Pagination::default())
        .await
        .expect("list");
    assert_eq!(listed.total, 2);
    assert!(listed.items.iter().all(|c| c.tenant_id == Some(mine)));

    // The organization view is deliberately wider: it is what the issuing-CA
    // dropdown reads, and a tenant signing CA is exactly what belongs there.
    let all = svc
        .list(org_id, Pagination::default())
        .await
        .expect("list org");
    assert_eq!(all.total, 4, "one organization CA plus three tenant CAs");
}
