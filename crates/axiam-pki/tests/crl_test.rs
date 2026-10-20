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
                    user_id: None,
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
    // #608: a cache keeps it until the next scheduled re-sign — at most half
    // the interval — and never until nextUpdate.
    assert!(crl.max_age_secs(Utc::now()) <= 1_800);
    assert_eq!(crl.max_age_secs(crl.refresh_at), 0);
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

/// The distribution point written into a certificate is the parsed form of the
/// configured URL, not the operator's text: a tab or newline the parser removes,
/// an upper-case host and a trailing slash do not reach the certificate.
#[tokio::test]
async fn the_issued_distribution_point_is_the_normalised_url() {
    let mut f = Fixture::new().await;
    let messy = CrlDistribution::new(" HTTPS://ID.Example.TEST/pk\ti/\n").unwrap();
    f.cas = f.cas.with_crl_distribution(Some(messy.clone()));
    f.certs = f.certs.with_crl_distribution(Some(messy));
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    let leaf = f.leaf(root.certificate.id, "device-normalised").await;
    assert_eq!(
        distribution_uris(&leaf.public_cert_pem),
        vec![format!(
            "https://id.example.test/pki/pki/v1/{}/ca/{}/crl",
            f.org, root.certificate.id
        )]
    );
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
                user_id: None,
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

/// #653 — a serial is drawn per certificate, not derived from the key. The same
/// CSR (one public key) signed twice yields two serials, so revoking one leaves
/// the other off the list; every issuance path draws at most 20 octets with the
/// top bit clear (RFC 5280 §4.1.2.2); and the value in the database is the one
/// the list encodes.
#[tokio::test]
async fn the_same_csr_signed_twice_gets_two_serials_and_one_revocation_lists_one() {
    let f = Fixture::new().await;
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "same-key");
    let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();
    let mut signed = Vec::new();
    for _ in 0..2 {
        signed.push(
            f.certs
                .sign_csr(
                    f.org,
                    IssuingScope::Organization,
                    SignCertificateCsr {
                        tenant_id: f.tenant,
                        issuer_ca_id: root.certificate.id,
                        csr_pem: csr_pem.clone(),
                        cert_type: CertificateType::Device,
                        validity_days: 30,
                        metadata: None,
                        subject_alt_names: vec![],
                        user_id: None,
                    },
                    None,
                    &[],
                )
                .await
                .expect("the same CSR may be signed twice"),
        );
    }
    let (first, second) = (&signed[0], &signed[1]);
    assert_ne!(
        serial_of(&first.public_cert_pem),
        serial_of(&second.public_cert_pem),
        "two certificates on one key must not share a serial"
    );

    // Every local issuance path: leaf (generated and CSR-signed), root,
    // intermediate.
    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    let generated = f.leaf(tenant_ca.certificate.id, "device-generated").await;
    for pem in [
        &first.public_cert_pem,
        &second.public_cert_pem,
        &generated.public_cert_pem,
        &root.certificate.public_cert_pem,
        &tenant_ca.certificate.public_cert_pem,
    ] {
        let der = der_of(pem);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let raw = cert.raw_serial();
        assert!(raw.len() <= 20, "at most 20 octets, got {}", raw.len());
        assert_eq!(raw[0] & 0x80, 0, "positive: the top bit is clear");
        assert!(raw.iter().any(|b| *b != 0), "non-zero");
    }

    // The column the unique index is on holds what the list encodes.
    let mut rows =
        f.db.query("SELECT VALUE serial FROM certificate WHERE issuer_ca_id = $ca")
            .bind(("ca", root.certificate.id.to_string()))
            .await
            .unwrap();
    let mut stored: Vec<Option<String>> = rows.take(0).unwrap();
    stored.sort();
    let mut expected: Vec<Option<String>> = [first, second]
        .iter()
        .map(|c| Some(hex::encode(serial_of(&c.public_cert_pem))))
        .collect();
    expected.sort();
    assert_eq!(stored, expected);

    f.certs
        .revoke(f.tenant, first.id)
        .await
        .expect("revoke one of the two");
    let crl = f
        .crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS)
        .current(f.org, root.certificate.id)
        .await
        .expect("the CA publishes a list");
    let serials = verified_serials(&crl, &root.certificate.public_cert_pem);
    assert_eq!(serials, vec![serial_of(&first.public_cert_pem)]);
    assert!(
        !serials.contains(&serial_of(&second.public_cert_pem)),
        "revoking one certificate must not revoke its same-key twin"
    );
}

/// R1W1-01: deleting a tenant revokes its certificates and signing CAs, and
/// the purge keeps every revoked, unexpired one — so each stays on its
/// issuer's list after the tombstone, after the purge, and until it expires.
/// Another tenant's leaf under the same CA is untouched throughout.
///
/// Before the fix the organization CA's list held the leaf revoked before the
/// deletion, then nothing at all once the tenant was purged: the purge
/// un-revoked it for every relying party outside AXIAM, and every leaf the
/// tenant still held was never revoked in the first place.
#[tokio::test]
async fn a_deleted_tenants_certificates_stay_on_the_crl_until_they_expire() {
    use axiam_core::models::certificate::CertificateStatus;
    use axiam_core::models::tenant::{CreateTenant, TenantKind};
    use axiam_core::repository::{CertificateRepository, TenantRepository};
    use axiam_db::repository::SurrealTenantRepository;

    let mut f = Fixture::new().await;
    let tenants = SurrealTenantRepository::new(f.db.clone());
    let tenant = |slug: &'static str| {
        let tenants = tenants.clone();
        let org = f.org;
        async move {
            tenants
                .create(CreateTenant {
                    organization_id: org,
                    kind: TenantKind::Standard,
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .expect("tenant")
                .id
        }
    };
    let doomed = tenant("doomed").await;
    let bystander = tenant("bystander").await;

    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    f.tenant = bystander;
    let bystanders = f.leaf(root.certificate.id, "bystander-device").await;
    f.tenant = doomed;
    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    let revoked_before = f.leaf(root.certificate.id, "revoked-before").await;
    let live = f.leaf(root.certificate.id, "live").await;
    let under_tenant_ca = f.leaf(tenant_ca.certificate.id, "under-tenant-ca").await;
    f.certs.revoke(doomed, revoked_before.id).await.unwrap();

    // What `DELETE …/tenants/{id}` does: the services, then the tombstone.
    let revoked = f.certs.revoke_tenant(doomed).await.unwrap();
    assert_eq!(
        revoked.revoked, 2,
        "the live leaf and the one under the tenant CA"
    );
    assert_eq!(revoked.vault_pending, 0);
    assert_eq!(
        f.cas
            .revoke_tenant_cas(f.org, doomed)
            .await
            .unwrap()
            .revoked,
        1
    );
    // A leaf issued while the deletion ran: the tombstone transaction revokes it.
    let raced = f.leaf(root.certificate.id, "raced").await;
    tenants.delete(doomed).await.unwrap();

    let crls = f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS);
    let mut expected = vec![
        serial_of(&revoked_before.public_cert_pem),
        serial_of(&live.public_cert_pem),
        serial_of(&tenant_ca.certificate.public_cert_pem),
        serial_of(&raced.public_cert_pem),
    ];
    expected.sort();
    let listed = |crl: &PublishedCrl| {
        let mut serials = verified_serials(crl, &root.certificate.public_cert_pem);
        serials.sort();
        serials
    };
    let crl = crls.current(f.org, root.certificate.id).await.unwrap();
    assert_eq!(listed(&crl), expected, "after the tombstone");

    tenants.purge_tombstoned(doomed).await.unwrap();
    let crl = crls.current(f.org, root.certificate.id).await.unwrap();
    assert_eq!(listed(&crl), expected, "after the purge");

    // Every kept row is revoked, so every sign-in that reads it refuses it;
    // a kept CA no longer holds its key, and a kept leaf no metadata.
    let cert_repo = SurrealCertificateRepository::new(f.db.clone());
    for (name, leaf) in [
        ("revoked_before", &revoked_before),
        ("live", &live),
        ("under_tenant_ca", &under_tenant_ca),
        ("raced", &raced),
    ] {
        let row = cert_repo
            .get_by_fingerprint_global(&leaf.fingerprint)
            .await
            .expect("a revoked, unexpired leaf is kept");
        assert_eq!(row.status, CertificateStatus::Revoked, "{name}");
    }
    let ca_rows = |query: &'static str| {
        let db = f.db.clone();
        async move {
            let mut result = db
                .query(query)
                .bind(("t", doomed.to_string()))
                .await
                .unwrap()
                .check()
                .unwrap();
            let rows: Vec<serde_json::Value> = result.take(0).unwrap();
            rows
        }
    };
    assert_eq!(
        ca_rows("SELECT VALUE status FROM ca_certificate WHERE tenant_id = $t").await,
        vec![serde_json::json!("Revoked")]
    );
    assert_eq!(
        ca_rows(
            "SELECT VALUE encrypted_private_key = NONE FROM ca_certificate WHERE tenant_id = $t"
        )
        .await,
        vec![serde_json::json!(true)],
        "a kept CA no longer holds its key"
    );

    // The bystander's leaf is untouched.
    let row = cert_repo
        .get_by_fingerprint_global(&bystanders.fingerprint)
        .await
        .unwrap();
    assert_eq!(row.status, CertificateStatus::Active);

    // Kept rows are not orphans until eight days after they expire (#608): an
    // entry that has just expired is still on the list — RFC 5280 §3.3 keeps
    // it until a list issued after its expiry names it — and the purge must
    // not take it off mid-epoch. Then the orphan purge removes them, and only
    // them.
    assert!(
        !tenants
            .orphaned_tenant_ids()
            .await
            .unwrap()
            .contains(&doomed)
    );
    let expire = |ago: &'static str| {
        let db = f.db.clone();
        let fp = revoked_before.fingerprint.clone();
        async move {
            db.query(format!(
                "UPDATE certificate SET not_after = time::now() - {ago} WHERE fingerprint = $fp"
            ))
            .bind(("fp", fp))
            .await
            .unwrap()
            .check()
            .unwrap();
        }
    };
    expire("1s").await;
    assert!(
        !tenants
            .orphaned_tenant_ids()
            .await
            .unwrap()
            .contains(&doomed),
        "a row that has just expired is kept"
    );
    tenants.purge_orphan(doomed).await.unwrap();
    let crl = crls.current(f.org, root.certificate.id).await.unwrap();
    assert_eq!(
        listed(&crl),
        expected,
        "a just-expired entry stays on the list"
    );
    expire("9d").await;
    assert_eq!(tenants.orphaned_tenant_ids().await.unwrap(), vec![doomed]);
    tenants.purge_orphan(doomed).await.unwrap();
    assert!(matches!(
        cert_repo
            .get_by_fingerprint_global(&revoked_before.fingerprint)
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    let crl = crls.current(f.org, root.certificate.id).await.unwrap();
    expected.retain(|s| *s != serial_of(&revoked_before.public_cert_pem));
    assert_eq!(listed(&crl), expected, "an expired entry leaves the list");
    assert!(tenants.orphaned_tenant_ids().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// #607: one CA's re-sign holds up nothing but itself
// ---------------------------------------------------------------------------

/// A fake Vault KV v2 endpoint that answers each request only when the test
/// says so: the custodian double that lets a test hold a CA's re-sign inside
/// its custodian `load` — the remote call the issue names — for as long as it
/// likes, and know for certain that it is there.
struct HeldVault {
    listener: tokio::net::TcpListener,
}

impl HeldVault {
    async fn start() -> Self {
        Self {
            listener: tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    fn address(&self) -> String {
        format!("http://{}", self.listener.local_addr().unwrap())
    }

    /// Wait until a request has arrived and been read in full, and return the
    /// connection, unanswered.
    async fn next_request(&self) -> tokio::net::TcpStream {
        use tokio::io::AsyncReadExt;
        let (mut socket, _) = self.listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0, "the custodian closed its request");
            request.extend_from_slice(&buf[..n]);
        }
        socket
    }

    /// Answer a held request with the KV v2 read of `private_key_pem`.
    async fn answer(mut socket: tokio::net::TcpStream, private_key_pem: &str) {
        use tokio::io::AsyncWriteExt;
        let body =
            serde_json::json!({ "data": { "data": { "private_key_pem": private_key_pem } } })
                .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    }
}

/// The issue's test: CA A's re-sign is in flight — held inside its custodian
/// `load` — and CA B's cached list answers, as does a first list for CA C.
///
/// Before the fix one process-wide lock was held from the cache lookup to the
/// signature, so B's request (a cache hit) and C's queued behind A's custodian
/// call, however long it took. The test knows A is inside `load` because the
/// fake Vault has read A's request; nothing here depends on timing. The
/// timeouts only turn the old behaviour's hang into a failure.
#[tokio::test]
async fn a_cached_list_answers_while_another_cas_re_sign_is_in_flight() {
    use axiam_core::ca_keys::CaKeyCustody;
    use axiam_pki::{DatabaseCaKeyStore, VaultCaKeyConfig, VaultCaKeyStore};
    use std::time::Duration as StdDuration;

    const GUARD: StdDuration = StdDuration::from_secs(30);

    let f = Fixture::new().await;
    let vault = HeldVault::start().await;
    let a = f.root(KeyAlgorithm::Ed25519, 365).await;
    let b = f.root(KeyAlgorithm::Ed25519, 365).await;
    let c = f.root(KeyAlgorithm::Ed25519, 365).await;
    let revoked = f.leaf(a.certificate.id, "device-under-a").await;
    f.certs.revoke(f.tenant, revoked.id).await.unwrap();

    // A's key moves to Vault — the remote custodian — and B and C keep theirs
    // in the database.
    f.db.query(
        "UPDATE type::record('ca_certificate', $id) SET key_custody = 'vault', \
         key_locator = 'axiam/ca-keys/held'",
    )
    .bind(("id", a.certificate.id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    let custodians = Arc::new(
        CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])), // gitleaks:allow
            Some(
                VaultCaKeyStore::new(VaultCaKeyConfig {
                    address: vault.address(),
                    token: "hvs.test-only-not-a-real-token".into(), // gitleaks:allow
                    mount: "secret".into(),
                    prefix: "axiam/ca-keys".into(),
                    ca_cert_path: None,
                })
                .unwrap(),
            ),
            None,
            Some(CaKeyCustody::Database),
        )
        .unwrap(),
    );
    let crls = CrlService::new(
        SurrealCaCertificateRepository::new(f.db.clone()),
        SurrealCertificateRepository::new(f.db.clone()),
        f.semaphore.clone(),
        custodians,
        DEFAULT_CRL_NEXT_UPDATE_SECS,
    );

    let b_cached = crls.current(f.org, b.certificate.id).await.unwrap();

    let in_flight = tokio::spawn({
        let crls = crls.clone();
        let (org, ca) = (f.org, a.certificate.id);
        async move { crls.current(org, ca).await }
    });
    let held = tokio::time::timeout(GUARD, vault.next_request())
        .await
        .expect("A's re-sign reaches its custodian");

    // A is inside `load`, holding its own re-sign. B's cached list answers…
    let b_again = tokio::time::timeout(GUARD, crls.current(f.org, b.certificate.id))
        .await
        .expect("B's cached list does not wait on A's re-sign")
        .unwrap();
    assert_eq!(b_again.etag, b_cached.etag);
    assert_eq!(b_again.der, b_cached.der);
    // …and so does a first list for C, which has to be signed.
    let c_list = tokio::time::timeout(GUARD, crls.current(f.org, c.certificate.id))
        .await
        .expect("C's re-sign does not wait on A's")
        .unwrap();
    assert!(verified_serials(&c_list, &c.certificate.public_cert_pem).is_empty());
    assert!(!in_flight.is_finished(), "A is still held in its custodian");

    // Released, A's list is signed with the key Vault handed over.
    HeldVault::answer(held, a.private_key_pem.as_deref().expect("A's key")).await;
    let a_list = tokio::time::timeout(GUARD, in_flight)
        .await
        .expect("A completes once its custodian answers")
        .unwrap()
        .unwrap();
    assert_eq!(
        verified_serials(&a_list, &a.certificate.public_cert_pem),
        vec![serial_of(&revoked.public_cert_pem)]
    );
}

/// A re-sign waits for a crypto permit at most the permit wait, then answers
/// `ServiceUnavailable` (the route's `503`); a cached list needs no permit and
/// is served throughout. Deterministic: every permit is held by the test for
/// the whole wait.
#[tokio::test]
async fn a_saturated_crypto_gate_refuses_a_re_sign_but_not_a_cached_list() {
    let f = Fixture::new().await;
    let cached = f.root(KeyAlgorithm::Ed25519, 365).await;
    let unsigned = f.root(KeyAlgorithm::Ed25519, 365).await;
    let crls = f
        .crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS)
        .with_permit_wait(std::time::Duration::from_millis(50));
    let before = crls.current(f.org, cached.certificate.id).await.unwrap();

    let permits = u32::try_from(f.semaphore.available_permits()).unwrap();
    let held = f
        .semaphore
        .clone()
        .acquire_many_owned(permits)
        .await
        .unwrap();
    assert!(matches!(
        crls.current(f.org, unsigned.certificate.id).await,
        Err(AxiamError::ServiceUnavailable(_))
    ));
    let during = crls.current(f.org, cached.certificate.id).await.unwrap();
    assert_eq!(during.etag, before.etag, "the cached list needs no permit");

    drop(held);
    crls.current(f.org, unsigned.certificate.id)
        .await
        .expect("signed once a permit is free");
}

/// The per-CA cache does not grow under requests for CA ids that do not exist
/// — the route is unauthenticated — and lets go of a CA once it stops
/// publishing a list.
#[tokio::test]
async fn the_cache_holds_only_cas_that_publish_a_list() {
    let f = Fixture::new().await;
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    let crls = f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS);

    for _ in 0..64 {
        assert!(matches!(
            crls.current(f.org, Uuid::new_v4()).await,
            Err(AxiamError::NotFound { .. })
        ));
    }
    assert_eq!(crls.cached_ca_count(), 0, "made-up CA ids add nothing");

    crls.current(f.org, tenant_ca.certificate.id).await.unwrap();
    crls.current(f.org, root.certificate.id).await.unwrap();
    assert_eq!(crls.cached_ca_count(), 2);

    f.cas.revoke(f.org, tenant_ca.certificate.id).await.unwrap();
    assert!(matches!(
        crls.current(f.org, tenant_ca.certificate.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(crls.cached_ca_count(), 1, "a revoked CA's slot is dropped");
}

/// The light read that decides whether a list changed names exactly the
/// certificates, with exactly the dates, the list is signed over.
#[tokio::test]
async fn the_light_read_names_exactly_what_the_list_is_signed_over() {
    use axiam_core::repository::{CaCertificateRepository, CertificateRepository};

    let f = Fixture::new().await;
    let root = f.root(KeyAlgorithm::Ed25519, 365).await;
    let tenant_ca = f.tenant_ca(root.certificate.id).await;
    let revoked = f.leaf(root.certificate.id, "device-light-a").await;
    let _kept = f.leaf(root.certificate.id, "device-light-b").await;
    f.certs.revoke(f.tenant, revoked.id).await.unwrap();
    f.cas.revoke(f.org, tenant_ca.certificate.id).await.unwrap();

    let certs = SurrealCertificateRepository::new(f.db.clone());
    let cas = SurrealCaCertificateRepository::new(f.db.clone());
    let issuer = root.certificate.id;
    let now = Utc::now();
    let light = |stamps: Vec<axiam_core::models::certificate::RevocationStamp>| {
        stamps
            .into_iter()
            .map(|s| (s.fingerprint, s.revoked_at, s.not_before))
            .collect::<Vec<_>>()
    };
    let full = |entries: Vec<axiam_core::models::certificate::RevokedCertificate>| {
        entries
            .into_iter()
            .map(|e| (e.fingerprint, e.revoked_at, e.not_before))
            .collect::<Vec<_>>()
    };
    let leaves = light(
        certs
            .list_revocation_stamps_by_issuer(issuer, now)
            .await
            .unwrap(),
    );
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].0, revoked.fingerprint);
    assert!(leaves[0].1.is_some(), "the revocation date is read");
    assert_eq!(
        leaves,
        full(certs.list_revoked_by_issuer(issuer, now).await.unwrap())
    );
    let children = light(cas.list_revoked_children_stamps(issuer, now).await.unwrap());
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].0, tenant_ca.certificate.fingerprint);
    assert_eq!(
        children,
        full(cas.list_revoked_children(issuer, now).await.unwrap())
    );

    // #608: the caller's cut-off decides which expired entries are named — a
    // cut-off past every notAfter names none, in either read.
    let later = now + Duration::days(400);
    assert!(
        certs
            .list_revocation_stamps_by_issuer(issuer, later)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        certs
            .list_revoked_by_issuer(issuer, later)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        cas.list_revoked_children_stamps(issuer, later)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        cas.list_revoked_children(issuer, later)
            .await
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// #608: the same list from every replica, and a number that only grows
// ---------------------------------------------------------------------------

/// The start of the refresh epoch after the current one, for lists valid
/// `next_update_secs`: an instant every revocation the test makes precedes.
fn next_epoch_start(next_update_secs: i64) -> chrono::DateTime<Utc> {
    let half = next_update_secs / 2;
    let now = Utc::now().timestamp();
    chrono::DateTime::from_timestamp((now.div_euclid(half) + 1) * half, 0).unwrap()
}

/// The issue's test: two `CrlService`s over one store — two replicas, each
/// with its own cache — sign the same state to the same bytes, CRL number and
/// `ETag`, at different instants of one refresh epoch, for both key types a CA
/// can have. Before the fix each signed its own list with its own clock's
/// `thisUpdate` and number, so a relying party behind a balancer got `200`s
/// instead of `304`s.
#[tokio::test]
async fn two_replicas_sign_the_same_state_to_the_same_bytes() {
    for key_algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::Rsa4096] {
        let f = Fixture::new().await;
        let ca = f.root(key_algorithm.clone(), 365).await;
        let revoked = f.leaf(ca.certificate.id, "device-replicated").await;
        f.certs.revoke(f.tenant, revoked.id).await.unwrap();

        let (one, two) = (
            f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS),
            f.crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS),
        );
        let half = i64::try_from(DEFAULT_CRL_NEXT_UPDATE_SECS / 2).unwrap();
        let epoch = next_epoch_start(i64::try_from(DEFAULT_CRL_NEXT_UPDATE_SECS).unwrap());
        let early = epoch + Duration::seconds(5);
        let late = epoch + Duration::seconds(half - 5);

        let a = one
            .current_at(f.org, ca.certificate.id, early)
            .await
            .unwrap();
        let b = two
            .current_at(f.org, ca.certificate.id, late)
            .await
            .unwrap();
        assert_eq!(a.der, b.der, "{key_algorithm:?}: the same bytes");
        assert_eq!(a.etag, b.etag);
        assert_eq!(a.crl_number, b.crl_number);
        assert_eq!(a.this_update, epoch, "thisUpdate is the epoch's start");
        assert_eq!(a.refresh_at, epoch + Duration::seconds(half));
        assert_eq!(
            verified_serials(&b, &ca.certificate.public_cert_pem),
            vec![serial_of(&revoked.public_cert_pem)]
        );

        // A revocation reaches both at once, and both again agree.
        let second = f.leaf(ca.certificate.id, "device-replicated-2").await;
        f.certs.revoke(f.tenant, second.id).await.unwrap();
        let c = two
            .current_at(f.org, ca.certificate.id, early)
            .await
            .unwrap();
        let d = one
            .current_at(f.org, ca.certificate.id, late)
            .await
            .unwrap();
        assert_eq!(c.der, d.der, "{key_algorithm:?}: the same bytes again");
        assert!(c.crl_number > a.crl_number);
    }
}

/// RFC 5280 §5.2.3: a CA's CRL number grows with every change of its list —
/// a revocation, the next epoch, and an entry that expires and leaves, which
/// takes an epoch boundary — and a just-expired entry stays until a list issued
/// after its expiry has named it (§3.3).
#[tokio::test]
async fn the_crl_number_grows_across_revocations_epochs_and_an_expiry() {
    const SECS: u64 = 3_600;
    let half = Duration::seconds(1_800);
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let expiring = f.leaf(ca.certificate.id, "device-expiring").await;
    let staying = f.leaf(ca.certificate.id, "device-staying").await;
    let crls = f.crl_service(SECS);
    let at = next_epoch_start(i64::try_from(SECS).unwrap()) + Duration::seconds(10);

    f.certs.revoke(f.tenant, expiring.id).await.unwrap();
    let first = crls.current_at(f.org, ca.certificate.id, at).await.unwrap();
    f.certs.revoke(f.tenant, staying.id).await.unwrap();
    let second = crls.current_at(f.org, ca.certificate.id, at).await.unwrap();
    assert!(second.crl_number > first.crl_number, "a revocation");

    // The first leaf expires ten seconds into the epoch `at` is in.
    f.db.query("UPDATE certificate SET not_after = $t WHERE fingerprint = $fp")
        .bind(("t", at + Duration::seconds(10)))
        .bind(("fp", expiring.fingerprint.clone()))
        .await
        .unwrap()
        .check()
        .unwrap();

    // The next epoch: expired during the previous one, it is still listed.
    let third = crls
        .current_at(f.org, ca.certificate.id, at + half)
        .await
        .unwrap();
    assert!(third.crl_number > second.crl_number, "the next epoch");
    assert_eq!(
        verified_serials(&third, &ca.certificate.public_cert_pem).len(),
        2
    );

    // The epoch after: it has left, and the number is greater still.
    let fourth = crls
        .current_at(f.org, ca.certificate.id, at + half + half)
        .await
        .unwrap();
    assert!(fourth.crl_number > third.crl_number, "an entry left");
    assert!(fourth.this_update > third.this_update);
    assert_eq!(
        verified_serials(&fourth, &ca.certificate.public_cert_pem),
        vec![serial_of(&staying.public_cert_pem)]
    );

    // And another replica, asked at the same instant, says the same.
    let other = f
        .crl_service(SECS)
        .current_at(f.org, ca.certificate.id, at + half + half)
        .await
        .unwrap();
    assert_eq!(other.der, fourth.der);
}

/// #666 — `current_at` keeps a named instant that lies in the past: the list
/// is signed with that instant's epoch, not at the wall clock.
#[tokio::test]
async fn current_at_signs_a_past_instant_at_that_instant() {
    const SECS: u64 = 60;
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let crls = f.crl_service(SECS);

    // The CA is valid from its creation; move that back so the named instant
    // lies inside its validity window.
    let past = Utc::now() - Duration::seconds(10 * 60);
    f.db.query("UPDATE type::record('ca_certificate', $id) SET not_before = $t")
        .bind(("id", ca.certificate.id.to_string()))
        .bind(("t", past - Duration::seconds(60)))
        .await
        .unwrap()
        .check()
        .unwrap();
    let named = crls
        .current_at(f.org, ca.certificate.id, past)
        .await
        .unwrap();
    assert!(
        named.this_update <= past,
        "thisUpdate is the named epoch's, not the wall clock's"
    );
    assert!(named.refresh_at > past && named.refresh_at <= past + Duration::seconds(60));

    // Asked as of the clock, the same service answers with the current epoch's list.
    let now = crls.current(f.org, ca.certificate.id).await.unwrap();
    assert!(now.this_update > named.this_update);
    assert_ne!(now.crl_number, named.crl_number);

    // And the named instant is still answered as of itself afterwards.
    let again = crls
        .current_at(f.org, ca.certificate.id, past)
        .await
        .unwrap();
    assert_eq!(again.this_update, named.this_update);
}

/// #615, the issue's test: a revocation dated past the end of the epoch — the
/// datastore's clock ahead of the replica's — beside an entry that expires at
/// the boundary. The list signed before the boundary states its epoch's last
/// second as `thisUpdate` and no entry later than that; the list signed after
/// it, one entry fewer, has a greater number. Before the fix the first list
/// stated the future date as `thisUpdate` and the second, with the same
/// `thisUpdate` and one entry fewer, a lower number.
#[tokio::test]
async fn a_revocation_dated_past_the_epoch_cannot_lower_the_number_across_the_boundary() {
    const SECS: u64 = 3_600;
    let half = Duration::seconds(1_800);
    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let expiring = f
        .leaf(ca.certificate.id, "device-expiring-at-boundary")
        .await;
    let ahead = f.leaf(ca.certificate.id, "device-revoked-ahead").await;
    f.certs.revoke(f.tenant, expiring.id).await.unwrap();
    f.certs.revoke(f.tenant, ahead.id).await.unwrap();

    let start = next_epoch_start(i64::try_from(SECS).unwrap());
    let end = start + half;
    let set = |field: &'static str, fp: String, t: chrono::DateTime<Utc>| {
        let db = f.db.clone();
        async move {
            db.query(format!(
                "UPDATE certificate SET {field} = $t WHERE fingerprint = $fp"
            ))
            .bind(("t", t))
            .bind(("fp", fp))
            .await
            .unwrap()
            .check()
            .unwrap();
        }
    };
    // Expired a second before the epoch began: listed in it (RFC 5280 §3.3),
    // gone from the next.
    set(
        "not_after",
        expiring.fingerprint.clone(),
        start - Duration::seconds(1),
    )
    .await;
    // Revoked, by the datastore's clock, ten seconds past the epoch's end.
    let revoked_at = end + Duration::seconds(10);
    set("revoked_at", ahead.fingerprint.clone(), revoked_at).await;

    let crls = f.crl_service(SECS);
    let before = crls
        .current_at(f.org, ca.certificate.id, end - Duration::seconds(12))
        .await
        .unwrap();
    assert!(
        before.this_update < end,
        "thisUpdate stays inside its epoch"
    );
    assert_eq!(before.this_update, end - Duration::seconds(1));
    assert_eq!(
        before.next_update - before.this_update,
        Duration::seconds(i64::try_from(SECS).unwrap())
    );
    let (_, list) = CertificateRevocationList::from_der(&before.der).unwrap();
    assert_eq!(
        list.last_update().timestamp(),
        before.this_update.timestamp()
    );
    let dates: Vec<i64> = list
        .iter_revoked_certificates()
        .map(|e| e.revocation_date.timestamp())
        .collect();
    assert_eq!(
        dates.len(),
        2,
        "both entries are listed before the boundary"
    );
    assert!(
        dates.iter().all(|d| *d <= before.this_update.timestamp()),
        "no entry is stated later than the list itself: {dates:?}"
    );
    verified_serials(&before, &ca.certificate.public_cert_pem);

    // Another replica, earlier in the same epoch, signs the same bytes.
    let early = f
        .crl_service(SECS)
        .current_at(f.org, ca.certificate.id, start + Duration::seconds(5))
        .await
        .unwrap();
    assert_eq!(
        early.der, before.der,
        "the clamp is a function of the epoch"
    );

    let after = crls
        .current_at(f.org, ca.certificate.id, end + Duration::seconds(1))
        .await
        .unwrap();
    assert_eq!(
        verified_serials(&after, &ca.certificate.public_cert_pem),
        vec![serial_of(&ahead.public_cert_pem)],
        "the expired entry left at the boundary"
    );
    assert_eq!(
        after.this_update, revoked_at,
        "its own date, inside this epoch"
    );
    assert!(
        after.crl_number > before.crl_number,
        "the number grows across the boundary"
    );
}

// ---------------------------------------------------------------------------
// #616: a re-sign in flight is waited on for a bounded time, and shared
// ---------------------------------------------------------------------------

type Crls = CrlService<SurrealCaCertificateRepository<Db>, SurrealCertificateRepository<Db>>;

/// A `CrlService` over `f`'s store in which CA `held_ca` keeps its key in the
/// fake Vault — so its re-sign stops inside the custodian `load` until the test
/// answers — and every other CA in the database.
async fn crls_with_a_held_custodian(
    f: &Fixture,
    vault: &HeldVault,
    held_ca: Uuid,
    permit_wait: std::time::Duration,
) -> Crls {
    use axiam_core::ca_keys::CaKeyCustody;
    use axiam_pki::{DatabaseCaKeyStore, VaultCaKeyConfig, VaultCaKeyStore};

    f.db.query(
        "UPDATE type::record('ca_certificate', $id) SET key_custody = 'vault', \
         key_locator = 'axiam/ca-keys/held'",
    )
    .bind(("id", held_ca.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    let custodians = Arc::new(
        CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])), // gitleaks:allow
            Some(
                VaultCaKeyStore::new(VaultCaKeyConfig {
                    address: vault.address(),
                    token: "hvs.test-only-not-a-real-token".into(), // gitleaks:allow
                    mount: "secret".into(),
                    prefix: "axiam/ca-keys".into(),
                    ca_cert_path: None,
                })
                .unwrap(),
            ),
            None,
            Some(CaKeyCustody::Database),
        )
        .unwrap(),
    );
    CrlService::new(
        SurrealCaCertificateRepository::new(f.db.clone()),
        SurrealCertificateRepository::new(f.db.clone()),
        f.semaphore.clone(),
        custodians,
        DEFAULT_CRL_NEXT_UPDATE_SECS,
    )
    .with_permit_wait(permit_wait)
}

/// The issue's test: eight concurrent requests for a list that has to be
/// signed, with every crypto permit held. One flight waits the permit wait and
/// fails; the seven requests that joined it receive its `503` rather than each
/// starting a wait of its own in turn. Before the fix the k-th caller answered
/// after about k permit waits (the review's probe: 253 … 1714 ms at 200 ms).
#[tokio::test]
async fn eight_requests_under_a_held_gate_all_answer_within_about_the_permit_wait() {
    use std::time::Duration as StdDuration;

    const WAIT: StdDuration = StdDuration::from_millis(1_000);
    // A second permit wait is what the old queue cost the second caller; the
    // margin is for eight light reads and the scheduler.
    const BOUND: StdDuration = StdDuration::from_millis(1_750);

    let f = Fixture::new().await;
    let ca = f.root(KeyAlgorithm::Ed25519, 365).await;
    let revoked = f.leaf(ca.certificate.id, "device-under-a-held-gate").await;
    f.certs.revoke(f.tenant, revoked.id).await.unwrap();
    let crls = f
        .crl_service(DEFAULT_CRL_NEXT_UPDATE_SECS)
        .with_permit_wait(WAIT);

    let permits = u32::try_from(f.semaphore.available_permits()).unwrap();
    let held = f
        .semaphore
        .clone()
        .acquire_many_owned(permits)
        .await
        .unwrap();

    let started = tokio::time::Instant::now();
    let requests: Vec<_> = (0..8)
        .map(|_| {
            let crls = crls.clone();
            let (org, ca) = (f.org, ca.certificate.id);
            tokio::spawn(async move {
                let answer = crls.current(org, ca).await;
                (answer, started.elapsed())
            })
        })
        .collect();
    let mut slowest = StdDuration::ZERO;
    for request in requests {
        let (answer, elapsed) = request.await.unwrap();
        assert!(
            matches!(answer, Err(AxiamError::ServiceUnavailable(_))),
            "every caller is told to come back: {answer:?}"
        );
        assert!(
            elapsed < BOUND,
            "a caller answered after {elapsed:?}, more than about one permit wait ({WAIT:?})"
        );
        slowest = slowest.max(elapsed);
    }
    assert!(slowest >= WAIT, "the flight did wait for a permit");

    drop(held);
    let crl = crls
        .current(f.org, ca.certificate.id)
        .await
        .expect("signed once a permit is free");
    assert_eq!(
        verified_serials(&crl, &ca.certificate.public_cert_pem),
        vec![serial_of(&revoked.public_cert_pem)]
    );
}

/// A request for a list whose re-sign is held inside its custodian waits for
/// it at most the permit wait, then answers `503`; the flight goes on, and its
/// list is the next answer. Before the fix the second request queued on the
/// CA's signing lock for as long as the custodian took. Deterministic: the test
/// knows the flight is inside `load` because the fake Vault has read its
/// request.
#[tokio::test]
async fn a_request_behind_a_held_re_sign_answers_503_within_the_permit_wait() {
    use std::time::Duration as StdDuration;

    const GUARD: StdDuration = StdDuration::from_secs(30);
    const WAIT: StdDuration = StdDuration::from_millis(300);

    let f = Fixture::new().await;
    let vault = HeldVault::start().await;
    let a = f.root(KeyAlgorithm::Ed25519, 365).await;
    let revoked = f
        .leaf(a.certificate.id, "device-under-a-held-re-sign")
        .await;
    f.certs.revoke(f.tenant, revoked.id).await.unwrap();
    let crls = crls_with_a_held_custodian(&f, &vault, a.certificate.id, WAIT).await;

    let first = tokio::spawn({
        let crls = crls.clone();
        let (org, ca) = (f.org, a.certificate.id);
        async move { crls.current(org, ca).await }
    });
    let held = tokio::time::timeout(GUARD, vault.next_request())
        .await
        .expect("the re-sign reaches its custodian");

    let started = tokio::time::Instant::now();
    let second = tokio::time::timeout(GUARD, crls.current(f.org, a.certificate.id))
        .await
        .expect("a request behind the held re-sign is not queued for as long as it is held");
    let waited = started.elapsed();
    assert!(
        matches!(second, Err(AxiamError::ServiceUnavailable(_))),
        "{second:?}"
    );
    assert!(
        waited >= WAIT,
        "it waited for the flight first ({waited:?})"
    );
    assert!(!first.is_finished(), "the flight is still held");

    HeldVault::answer(held, a.private_key_pem.as_deref().expect("A's key")).await;
    let signed = tokio::time::timeout(GUARD, first)
        .await
        .expect("the flight lands once its custodian answers")
        .unwrap()
        .unwrap();
    assert_eq!(
        verified_serials(&signed, &a.certificate.public_cert_pem),
        vec![serial_of(&revoked.public_cert_pem)]
    );
    let next = tokio::time::timeout(GUARD, crls.current(f.org, a.certificate.id))
        .await
        .expect("the cached list answers")
        .unwrap();
    assert_eq!(next.etag, signed.etag, "the flight's list, from the cache");
}

/// The flight is the CA's, not the caller's: the request that started a
/// re-sign hangs up while it is held in its custodian, and the list is still
/// signed and cached — the next request is answered without a second read of
/// the key. Before the fix the re-sign ran inside the request and died with it.
#[tokio::test]
async fn a_re_sign_outlives_the_request_that_started_it() {
    use std::time::Duration as StdDuration;

    const GUARD: StdDuration = StdDuration::from_secs(30);

    let f = Fixture::new().await;
    let vault = HeldVault::start().await;
    let a = f.root(KeyAlgorithm::Ed25519, 365).await;
    let revoked = f.leaf(a.certificate.id, "device-after-a-hang-up").await;
    f.certs.revoke(f.tenant, revoked.id).await.unwrap();
    let crls = crls_with_a_held_custodian(
        &f,
        &vault,
        a.certificate.id,
        axiam_pki::crl::DEFAULT_CRL_PERMIT_WAIT,
    )
    .await;

    let caller = tokio::spawn({
        let crls = crls.clone();
        let (org, ca) = (f.org, a.certificate.id);
        async move { crls.current(org, ca).await }
    });
    let held = tokio::time::timeout(GUARD, vault.next_request())
        .await
        .expect("the re-sign reaches its custodian");
    caller.abort();
    assert!(
        caller.await.unwrap_err().is_cancelled(),
        "the caller hung up"
    );

    HeldVault::answer(held, a.private_key_pem.as_deref().expect("A's key")).await;
    // A second key read would never be answered: this request would hang
    // until the guard, and fail.
    let next = tokio::time::timeout(GUARD, crls.current(f.org, a.certificate.id))
        .await
        .expect("answered from the abandoned flight, without a second key read")
        .unwrap();
    assert_eq!(
        verified_serials(&next, &a.certificate.public_cert_pem),
        vec![serial_of(&revoked.public_cert_pem)]
    );
}
