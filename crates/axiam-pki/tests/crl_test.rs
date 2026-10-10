//! #565 (T-102) — a certificate revocation list per issuing CA, and the
//! distribution point every certificate issued afterwards carries.
//!
//! Every list is parsed back with `x509-parser` and its signature verified
//! under the issuing CA's own public key, so these tests check the bytes a
//! relying party would fetch rather than the service's account of them.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, CreateIntermediateCa,
    GeneratedCaCertificate, ImportCaCertificate, KeyAlgorithm, SignCertificateCsr,
};
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::crl::DEFAULT_CRL_NEXT_UPDATE_SECS;
use axiam_pki::{
    CaKeyCustodians, CaService, CertService, CrlDistribution, CrlService, IssuingScope, PkiConfig,
    PublishedCrl,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

const BASE: &str = "https://id.example.test";

struct Fixture {
    org: Uuid,
    tenant: Uuid,
    cas: CaService<SurrealCaCertificateRepository<Db>>,
    certs: CertService<SurrealCaCertificateRepository<Db>, SurrealCertificateRepository<Db>>,
    db: Surreal<Db>,
    custodians: Arc<CaKeyCustodians>,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl Fixture {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
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
        let semaphore = Arc::new(tokio::sync::Semaphore::new(4));
        let distribution = Some(CrlDistribution::new(BASE).unwrap());
        let ca_repo = SurrealCaCertificateRepository::new(db.clone());
        Self {
            org: Uuid::new_v4(),
            tenant: Uuid::new_v4(),
            cas: CaService::new(
                ca_repo.clone(),
                config.clone(),
                semaphore.clone(),
                custodians.clone(),
            )
            .with_crl_distribution(distribution.clone()),
            certs: CertService::new(
                ca_repo,
                SurrealCertificateRepository::new(db.clone()),
                config,
                semaphore.clone(),
                custodians.clone(),
            )
            .with_crl_distribution(distribution),
            db,
            custodians,
            semaphore,
        }
    }

    fn crl_service(
        &self,
        next_update_secs: u64,
    ) -> CrlService<SurrealCaCertificateRepository<Db>, SurrealCertificateRepository<Db>> {
        CrlService::new(
            SurrealCaCertificateRepository::new(self.db.clone()),
            SurrealCertificateRepository::new(self.db.clone()),
            self.semaphore.clone(),
            self.custodians.clone(),
            next_update_secs,
        )
    }

    async fn root(
        &self,
        key_algorithm: KeyAlgorithm,
        validity_days: u32,
    ) -> GeneratedCaCertificate {
        self.cas
            .generate(CreateCaCertificate {
                organization_id: self.org,
                subject: "CRL Test Root".into(),
                key_algorithm,
                validity_days,
                intermediate_subject: None,
                intermediate_validity_days: None,
                issue_from_root: false,
            })
            .await
            .expect("root CA")
    }

    async fn tenant_ca(&self, parent: Uuid) -> GeneratedCaCertificate {
        self.cas
            .generate_intermediate(CreateIntermediateCa {
                organization_id: self.org,
                tenant_id: self.tenant,
                parent_ca_id: parent,
                subject: "CRL Test Tenant CA".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 180,
            })
            .await
            .expect("tenant signing CA")
    }

    async fn leaf(
        &self,
        issuer: Uuid,
        subject: &str,
    ) -> axiam_core::models::certificate::Certificate {
        self.certs
            .generate(
                self.org,
                IssuingScope::Organization,
                CreateCertificate {
                    tenant_id: self.tenant,
                    issuer_ca_id: issuer,
                    subject: subject.into(),
                    cert_type: CertificateType::Device,
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 30,
                    metadata: None,
                    subject_alt_names: vec![],
                },
                None,
                &[],
            )
            .await
            .expect("leaf")
            .certificate
    }
}

fn der_of(pem: &str) -> Vec<u8> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    block.contents
}

fn serial_of(pem: &str) -> Vec<u8> {
    let der = der_of(pem);
    let (_, cert) = X509Certificate::from_der(&der).expect("certificate");
    cert.serial.to_bytes_be()
}

/// The serials a list names, verified first under `ca_pem`'s key.
fn verified_serials(crl: &PublishedCrl, ca_pem: &str) -> Vec<Vec<u8>> {
    let ca_der = der_of(ca_pem);
    let (_, ca) = X509Certificate::from_der(&ca_der).expect("CA certificate");
    let (_, list) = CertificateRevocationList::from_der(&crl.der).expect("a DER CRL");
    list.verify_signature(ca.public_key())
        .expect("the list verifies under the issuing CA's key");
    assert_eq!(list.issuer(), ca.subject(), "the list is issued by the CA");
    list.iter_revoked_certificates()
        .map(|entry| entry.serial().to_bytes_be())
        .collect()
}

/// The URIs a certificate's CRL distribution points extension names.
fn distribution_uris(pem: &str) -> Vec<String> {
    let der = der_of(pem);
    let (_, cert) = X509Certificate::from_der(&der).expect("certificate");
    let mut uris = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
            for point in points.iter() {
                if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
                    for name in names {
                        if let GeneralName::URI(uri) = name {
                            uris.push((*uri).to_owned());
                        }
                    }
                }
            }
        }
    }
    uris
}

/// The issue's second test: the CRL lists the revoked leaf, and nothing else
/// the CA issued, and verifies under the CA — for both key algorithms a CA can
/// have, each signing through the custodian that holds its key.
#[tokio::test]
async fn the_crl_lists_the_revoked_leaf_and_verifies_under_the_ca() {
    for key_algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa4096] {
        let f = Fixture::new().await;
        let ca = f.root(key_algorithm.clone(), 365).await;
        let revoked = f.leaf(ca.certificate.id, "device-revoked").await;
        let kept = f.leaf(ca.certificate.id, "device-kept").await;
        f.certs
            .revoke(f.tenant, revoked.id)
            .await
            .expect("revoke the leaf");

        let crl = f
            .crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS)
            .current(f.org, ca.certificate.id)
            .await
            .expect("the CA publishes a list");
        let serials = verified_serials(&crl, &ca.certificate.public_cert_pem);
        assert_eq!(
            serials,
            vec![serial_of(&revoked.public_cert_pem)],
            "{key_algorithm:?}: exactly the revoked leaf is listed"
        );
        assert!(!serials.contains(&serial_of(&kept.public_cert_pem)));

        // The two extensions RFC 5280 §5.2 requires, and the entry's date.
        let (_, list) = CertificateRevocationList::from_der(&crl.der).unwrap();
        assert_eq!(
            list.crl_number().map(|n| n.to_string()),
            Some(crl.crl_number.to_string())
        );
        let ca_der = der_of(&ca.certificate.public_cert_pem);
        let (_, ca_x509) = X509Certificate::from_der(&ca_der).unwrap();
        let ski = ca_x509
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(kid) => Some(kid.0.to_vec()),
                _ => None,
            });
        let aki = list
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|k| k.0.to_vec())
                }
                _ => None,
            });
        assert!(
            ski.is_some(),
            "an AXIAM CA carries a subject key identifier"
        );
        assert_eq!(aki, ski, "the list names the CA's own key identifier");
        let entry = list.iter_revoked_certificates().next().unwrap();
        let revoked_at = entry.revocation_date.timestamp();
        assert!(
            (Utc::now().timestamp() - revoked_at).abs() < 120,
            "the entry carries the date the revocation was recorded"
        );
    }
}

/// The issue's third test: `nextUpdate` is the configured interval after
/// `thisUpdate`, in the list and in what the route caches by — and never past
/// the CA's own expiry.
#[tokio::test]
async fn next_update_is_honoured() {
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let crl = f
        .crl_service(3_600)
        .current(f.org, ca.certificate.id)
        .await
        .unwrap();
    let (_, list) = CertificateRevocationList::from_der(&crl.der).unwrap();
    let this_update = list.last_update().timestamp();
    let next_update = list
        .next_update()
        .expect("nextUpdate is present")
        .timestamp();
    assert_eq!(next_update - this_update, 3_600);
    assert_eq!(crl.this_update.timestamp(), this_update);
    assert_eq!(crl.next_update.timestamp(), next_update);
    assert!(crl.max_age_secs(Utc::now()) <= 3_600);
    assert!(crl.max_age_secs(Utc::now()) > 3_500);
    assert_eq!(crl.max_age_secs(crl.next_update + Duration::seconds(5)), 0);

    // A CA with a day left is not listed as current for a week.
    let short = f.root(KeyAlgorithm::Ed25519, 1).await;
    let crl = f
        .crl_service(604_800)
        .current(f.org, short.certificate.id)
        .await
        .unwrap();
    assert_eq!(crl.next_update, short.certificate.not_after);
}

/// A tenant signing CA its organization CA revoked is on the organization CA's
/// list: a relying party anchored at the root learns of it there.
#[tokio::test]
async fn a_revoked_tenant_ca_is_on_its_parents_list() {
    let f = Fixture::new().await;
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    f.cas
        .revoke(f.org, tenant_ca.certificate.id)
        .await
        .expect("revoke the tenant CA");

    let crls = f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS);
    let crl = crls.current(f.org, root.certificate.id).await.unwrap();
    assert_eq!(
        verified_serials(&crl, &root.certificate.public_cert_pem),
        vec![serial_of(&tenant_ca.certificate.public_cert_pem)]
    );
    // And a revoked CA publishes no list of its own.
    assert!(matches!(
        crls.current(f.org, tenant_ca.certificate.id).await,
        Err(AxiamError::NotFound { .. })
    ));
}

/// The list is signed once and served until something changes: the same bytes
/// for an unchanged list — so `If-None-Match` revalidates — and a new list,
/// with a greater number, as soon as another certificate is revoked.
#[tokio::test]
async fn a_revocation_reaches_the_next_list_and_an_unchanged_list_is_the_same_bytes() {
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let first = f.leaf(ca.certificate.id, "device-a").await;
    let second = f.leaf(ca.certificate.id, "device-b").await;
    f.certs.revoke(f.tenant, first.id).await.unwrap();

    let crls = f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS);
    let a = crls.current(f.org, ca.certificate.id).await.unwrap();
    let b = crls.current(f.org, ca.certificate.id).await.unwrap();
    assert_eq!(a.etag, b.etag);
    assert_eq!(a.der, b.der);

    f.certs.revoke(f.tenant, second.id).await.unwrap();
    let c = crls.current(f.org, ca.certificate.id).await.unwrap();
    assert_ne!(c.etag, a.etag, "a new revocation changes the list at once");
    assert!(c.crl_number > a.crl_number, "the CRL number only grows");
    let mut serials = verified_serials(&c, &ca.certificate.public_cert_pem);
    serials.sort();
    let mut expected = vec![
        serial_of(&first.public_cert_pem),
        serial_of(&second.public_cert_pem),
    ];
    expected.sort();
    assert_eq!(serials, expected);

    // Revoking an already-revoked certificate is not a second revocation: its
    // date, and therefore the list, are unchanged.
    f.certs.revoke(f.tenant, first.id).await.unwrap();
    let d = crls.current(f.org, ca.certificate.id).await.unwrap();
    assert_eq!(d.etag, c.etag);
}

/// The route answers `404` alike for a CA it does not know and for one that
/// publishes no list: another organization's CA, and an imported trust anchor
/// AXIAM holds no key for.
#[tokio::test]
async fn a_ca_that_cannot_sign_a_list_publishes_none() {
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let crls = f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS);
    assert!(matches!(
        crls.current(Uuid::new_v4(), ca.certificate.id).await,
        Err(AxiamError::NotFound { .. })
    ));

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "External Anchor");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let anchor = params.self_signed(&key).unwrap();
    let imported = f
        .cas
        .import(ImportCaCertificate {
            organization_id: f.org,
            public_cert_pem: anchor.pem(),
            private_key_pem: None,
        })
        .await
        .expect("import a keyless trust anchor");
    assert!(matches!(
        crls.current(f.org, imported.id).await,
        Err(AxiamError::NotFound { .. })
    ));
}

/// Every certificate AXIAM signs in-process from now on names its issuer's
/// list: a generated leaf, a CSR-signed leaf and a subordinate CA.
#[tokio::test]
async fn a_newly_issued_certificate_carries_the_crl_distribution_point() {
    let f = Fixture::new().await;
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    let root_list = CrlDistribution::new(BASE)
        .unwrap()
        .uri_for(f.org, root.certificate.id);

    let generated = f.leaf(root.certificate.id, "device-cdp").await;
    assert_eq!(
        distribution_uris(&generated.public_cert_pem),
        vec![root_list.clone()]
    );

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "service-cdp");
    let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
    let signed = f
        .certs
        .sign_csr(
            f.org,
            IssuingScope::Organization,
            SignCertificateCsr {
                tenant_id: f.tenant,
                issuer_ca_id: root.certificate.id,
                csr_pem,
                cert_type: CertificateType::Service,
                validity_days: 30,
                metadata: None,
                subject_alt_names: vec![],
            },
            None,
            &[],
        )
        .await
        .expect("sign the CSR");
    assert_eq!(
        distribution_uris(&signed.public_cert_pem),
        vec![root_list.clone()]
    );

    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    assert_eq!(
        distribution_uris(&tenant_ca.certificate.public_cert_pem),
        vec![root_list],
        "a subordinate CA names its parent's list"
    );
    let under_tenant = f
        .leaf(tenant_ca.certificate.id, "device-under-tenant")
        .await;
    assert_eq!(
        distribution_uris(&under_tenant.public_cert_pem),
        vec![
            CrlDistribution::new(BASE)
                .unwrap()
                .uri_for(f.org, tenant_ca.certificate.id)
        ]
    );
}
