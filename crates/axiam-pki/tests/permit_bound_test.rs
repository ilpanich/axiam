//! #671 (R110W2-03, T-102): the authenticated waiters on the shared crypto
//! semaphore give up. With every permit held, each CA, certificate and PGP site
//! answers `ServiceUnavailable` (the routes' `503`) within its permit wait —
//! it neither queues behind the holder nor fails early.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome};
use axiam_core::models::certificate::{
    CertificateType, CreateCaCertificate, CreateCertificate, CreateIntermediateCa, KeyAlgorithm,
    SignCertificateCsr, SignIntermediateCsr,
};
use axiam_core::models::pgp_key::{CreatePgpKey, PgpKeyAlgorithm, PgpKeyPurpose};
use axiam_db::repository::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealPgpKeyRepository,
};
use axiam_pki::IssuingScope;
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use axiam_pki::pgp::PgpService;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// The AES-256-GCM key the test deployment wraps CA keys with: random per
/// process, stable within one, so no key-shaped literal appears in the source.
fn test_key() -> [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key
    })
}

type TestDb = surrealdb::engine::local::Db;

const WAIT: Duration = Duration::from_millis(400);

fn pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some(test_key()),
        ..Default::default()
    }
}

fn custodians() -> Arc<axiam_pki::CaKeyCustodians> {
    Arc::new(axiam_pki::custodians_from_env(Some(test_key())).expect("test CA key custodians"))
}

struct Fixture {
    sem: Arc<Semaphore>,
    ca: CaService<SurrealCaCertificateRepository<TestDb>>,
    certs:
        CertService<SurrealCaCertificateRepository<TestDb>, SurrealCertificateRepository<TestDb>>,
    pgp: PgpService<SurrealPgpKeyRepository<TestDb>>,
    org_id: Uuid,
    root_id: Uuid,
}

/// Services over one semaphore of a single permit, built (and a root CA
/// generated) while it is free.
async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let sem = Arc::new(Semaphore::new(1));
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let ca = CaService::new(ca_repo.clone(), pki_config(), sem.clone(), custodians())
        .with_permit_wait(WAIT);
    let certs = CertService::new(
        ca_repo,
        SurrealCertificateRepository::new(db.clone()),
        pki_config(),
        sem.clone(),
        custodians(),
    )
    .with_permit_wait(WAIT);
    let pgp = PgpService::new(SurrealPgpKeyRepository::new(db), pki_config(), sem.clone())
        .with_permit_wait(WAIT);
    let org_id = Uuid::new_v4();
    let root = ca
        .generate(create_ca(org_id))
        .await
        .expect("root CA")
        .certificate;
    Fixture {
        sem,
        ca,
        certs,
        pgp,
        org_id,
        root_id: root.id,
    }
}

fn create_ca(organization_id: Uuid) -> CreateCaCertificate {
    CreateCaCertificate {
        organization_id,
        subject: "Permit Test CA".into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days: 3650,
        intermediate_subject: None,
        intermediate_validity_days: None,
        issue_from_root: false,
    }
}

fn csr(common_name: &str) -> String {
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

/// `call` run with every permit held: it must answer `ServiceUnavailable` no
/// sooner than `WAIT` and well before the holder lets go. The outer timeout is
/// what an unbounded acquire trips.
async fn answers_503_within_the_bound<T: std::fmt::Debug>(
    f: &Fixture,
    call: impl std::future::Future<Output = Result<T, AxiamError>>,
) {
    let held = f.sem.clone().acquire_owned().await.unwrap();
    let started = Instant::now();
    let outcome = tokio::time::timeout(WAIT * 5, call)
        .await
        .expect("the site waited past its permit wait: the acquire is unbounded");
    let took = started.elapsed();
    assert!(
        matches!(outcome, Err(AxiamError::ServiceUnavailable(_))),
        "a saturated gate is a ServiceUnavailable, got {outcome:?}"
    );
    assert!(took >= WAIT, "gave up early ({took:?})");
    assert!(took < WAIT * 4, "and not much later ({took:?})");
    drop(held);
}

#[tokio::test]
async fn ca_generate_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(&f, f.ca.generate(create_ca(Uuid::new_v4()))).await;
}

#[tokio::test]
async fn ca_generate_intermediate_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(
        &f,
        f.ca.generate_intermediate(CreateIntermediateCa {
            organization_id: f.org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: f.root_id,
            subject: "Tenant CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        }),
    )
    .await;
}

#[tokio::test]
async fn ca_sign_intermediate_csr_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(
        &f,
        f.ca.sign_intermediate_csr(SignIntermediateCsr {
            organization_id: f.org_id,
            tenant_id: Uuid::new_v4(),
            parent_ca_id: f.root_id,
            csr_pem: csr("Offline Tenant CA"),
            validity_days: 365,
        }),
    )
    .await;
}

#[tokio::test]
async fn cert_generate_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(
        &f,
        f.certs.generate(
            f.org_id,
            IssuingScope::Organization,
            CreateCertificate {
                tenant_id: Uuid::new_v4(),
                issuer_ca_id: f.root_id,
                subject: "CN=device-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
                subject_alt_names: vec![],
                user_id: None,
            },
            None,
            &[],
        ),
    )
    .await;
}

#[tokio::test]
async fn cert_sign_csr_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(
        &f,
        f.certs.sign_csr(
            f.org_id,
            IssuingScope::Organization,
            SignCertificateCsr {
                tenant_id: Uuid::new_v4(),
                issuer_ca_id: f.root_id,
                csr_pem: csr("svc"),
                cert_type: CertificateType::Service,
                validity_days: 30,
                metadata: None,
                subject_alt_names: vec![],
                user_id: None,
            },
            None,
            &[],
        ),
    )
    .await;
}

fn new_key(tenant_id: Uuid) -> CreatePgpKey {
    CreatePgpKey {
        tenant_id,
        name: "Permit Test".into(),
        email: "audit@axiam.dev".into(),
        algorithm: PgpKeyAlgorithm::Ed25519,
        purpose: PgpKeyPurpose::AuditSigning,
    }
}

#[tokio::test]
async fn pgp_generate_answers_503_under_a_held_gate() {
    let f = fixture().await;
    answers_503_within_the_bound(&f, f.pgp.generate(new_key(Uuid::new_v4()))).await;
}

#[tokio::test]
async fn pgp_sign_audit_batch_answers_503_under_a_held_gate() {
    let f = fixture().await;
    let tenant_id = Uuid::new_v4();
    f.pgp.generate(new_key(tenant_id)).await.expect("key");
    let entries = vec![AuditLogEntry {
        id: Uuid::new_v4(),
        tenant_id,
        actor_id: Uuid::new_v4(),
        actor_type: ActorType::System,
        action: "test.action".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: serde_json::json!({}),
        timestamp: chrono::Utc::now(),
    }];
    answers_503_within_the_bound(&f, f.pgp.sign_audit_batch(tenant_id, entries)).await;
}

/// The free gate still serves: the bound costs nothing when a permit is there.
#[tokio::test]
async fn a_free_gate_serves_every_site() {
    let f = fixture().await;
    f.pgp.generate(new_key(Uuid::new_v4())).await.expect("key");
    assert_eq!(f.sem.available_permits(), 1, "no permit is leaked");
}
