//! `CaService::migrate_key_custody` — moving a CA signing key between
//! custodians.
//!
//! This is the operation `docs/pki/README.md` points an operator at when their
//! CA keys are in the database and they wanted them in Vault, and it had no
//! test: the whole function was uncovered, error arms and success path alike.
//! It is also the one PKI operation that reads a private key back out of one
//! custodian and writes it into another, so "what does it do when a step
//! fails" is worth pinning rather than inferring.
//!
//! Vault is a `wiremock` server here, the same way `vault_ca_key_store_test.rs`
//! does it — the custodian under test is the real `VaultCaKeyStore` talking
//! real HTTP, only the far end is a fake.

use std::sync::Arc;

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::certificate::{CreateCaCertificate, KeyAlgorithm};
use axiam_core::repository::CaCertificateRepository as _;
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::{CaKeyCustodians, DatabaseCaKeyStore, VaultCaKeyConfig, VaultCaKeyStore};
use serde_json::json;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TOKEN: &str = "hvs.test-only-not-a-real-token"; // gitleaks:allow
const PREFIX: &str = "axiam/ca-keys";
const KEY: [u8; 32] = [0u8; 32]; // gitleaks:allow

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some(KEY),
        ..Default::default()
    }
}

fn vault_store(server: &MockServer) -> VaultCaKeyStore {
    VaultCaKeyStore::new(VaultCaKeyConfig {
        address: server.uri(),
        token: TOKEN.into(),
        mount: "secret".into(),
        prefix: PREFIX.into(),
        ca_cert_path: None,
    })
    .expect("no trust anchor configured, so the client builds")
}

/// Both custodians available, defaulting to whichever the test is migrating
/// *to* — `migrate_key_custody` reads its target from `default_store()`.
fn custodians(server: Option<&MockServer>, default: CaKeyCustody) -> Arc<CaKeyCustodians> {
    Arc::new(
        CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new(KEY)),
            server.map(vault_store),
            None,
            Some(default),
        )
        .expect("both custodians configured"),
    )
}

fn service(
    db: &Surreal<TestDb>,
    custodians: Arc<CaKeyCustodians>,
) -> CaService<SurrealCaCertificateRepository<TestDb>> {
    CaService::new(
        SurrealCaCertificateRepository::new(db.clone()),
        pki_config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
        custodians,
    )
}

fn new_ca(organization_id: Uuid) -> CreateCaCertificate {
    CreateCaCertificate {
        organization_id,
        subject: "Migration Test CA".into(),
        key_algorithm: KeyAlgorithm::Ed25519,
        validity_days: 365,
        intermediate_subject: None,
        intermediate_validity_days: None,
        issue_from_root: false,
    }
}

/// Accept every Vault KV write and read, so a migration *into* Vault completes.
async fn mount_vault_accepts_writes(server: &MockServer, pem_readback: &str) {
    Mock::given(method("POST"))
        .and(path_regex(r"^/v1/secret/data/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 1 }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/v1/secret/data/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "private_key_pem": pem_readback } }
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// The move itself
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrating_a_database_ca_into_vault_moves_the_key_and_re_keys_the_row() {
    let server = MockServer::start().await;
    mount_vault_accepts_writes(&server, "unused").await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let db = setup_db().await;
    let org = Uuid::new_v4();

    // Generate under database custody...
    let generated = service(&db, custodians(None, CaKeyCustody::Database))
        .generate(new_ca(org))
        .await
        .expect("CA generation must succeed")
        .certificate;
    assert_eq!(generated.key_custody, CaKeyCustody::Database);
    assert!(
        generated.encrypted_private_key.is_some(),
        "database custody seals the key into the row — that is the state this \
         migration exists to get a deployment out of"
    );

    // ...then migrate into Vault.
    let migrated = service(&db, custodians(Some(&server), CaKeyCustody::Vault))
        .migrate_key_custody(org, generated.id)
        .await
        .expect("migration must succeed");

    assert_eq!(migrated.key_custody, CaKeyCustody::Vault);
    assert_eq!(
        migrated.key_locator.as_deref(),
        Some(format!("{PREFIX}/{org}/{}", generated.id).as_str()),
        "the row must now point at the Vault path rather than hold the key"
    );

    // The row is the record of custody, so re-read it rather than trusting the
    // returned value: a migration that answered correctly and persisted
    // nothing would leave the key unreachable after a restart.
    let refetched = SurrealCaCertificateRepository::new(db.clone())
        .get_by_id(org, generated.id)
        .await
        .expect("the CA row must still exist");
    assert_eq!(refetched.key_custody, CaKeyCustody::Vault);
    assert!(
        refetched.encrypted_private_key.is_none(),
        "the database copy must be released once Vault holds the key — leaving \
         it is the whole exposure the migration is meant to end"
    );

    // And Vault actually received the key, under the field its own loader reads.
    let writes = server.received_requests().await.unwrap();
    let put = writes
        .iter()
        .find(|r| r.method == wiremock::http::Method::POST)
        .expect("the key must have been written to Vault");
    let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
    let sent = body["data"]["private_key_pem"]
        .as_str()
        .expect("the key must be sent under `private_key_pem`");
    assert!(
        sent.contains("PRIVATE KEY"),
        "a PEM private key must reach Vault, got {sent:?}"
    );
}

#[tokio::test]
async fn a_release_failure_still_completes_the_migration() {
    // The key has already moved by the time the old custodian is released, so
    // a failure there is an orphaned copy to clean up — not a reason to fail
    // the operation and leave the row pointing at a custodian that no longer
    // has it. Migrating Vault -> database with Vault's DELETE refusing is the
    // way to drive that arm: the database store's own delete cannot fail.
    let server = MockServer::start().await;
    let db = setup_db().await;
    let org = Uuid::new_v4();

    // Generate under Vault custody, then read the key back out of "Vault"
    // during the migration.
    let pem = {
        // A throwaway CA under database custody, only to obtain a real,
        // well-formed private key PEM for the fake Vault to serve back.
        let seed = service(&db, custodians(None, CaKeyCustody::Database))
            .generate(new_ca(org))
            .await
            .unwrap()
            .certificate;
        let store = DatabaseCaKeyStore::new(KEY);
        let key_ref = CaService::<SurrealCaCertificateRepository<TestDb>>::key_ref(&seed);
        use axiam_core::ca_keys::CaKeyStore as _;
        store
            .load(&key_ref, seed.encrypted_private_key.as_deref())
            .await
            .expect("the seed key must decrypt")
    };

    mount_vault_accepts_writes(&server, &pem).await;
    Mock::given(method("DELETE"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let vault_ca = service(&db, custodians(Some(&server), CaKeyCustody::Vault))
        .generate(new_ca(org))
        .await
        .expect("CA generation under Vault custody must succeed")
        .certificate;
    assert_eq!(vault_ca.key_custody, CaKeyCustody::Vault);

    let migrated = service(&db, custodians(Some(&server), CaKeyCustody::Database))
        .migrate_key_custody(org, vault_ca.id)
        .await
        .expect("a failed release must not fail the migration");

    assert_eq!(migrated.key_custody, CaKeyCustody::Database);
    assert!(
        migrated.encrypted_private_key.is_some(),
        "the database custodian must now hold the key — it has nowhere but this \
         column to put it, and the Vault copy has just been released"
    );

    // Not merely "a column is populated": the key must still open, and be the
    // key Vault handed over. A migration that stored something unreadable
    // there would satisfy the assertion above and still have destroyed the CA.
    use axiam_core::ca_keys::CaKeyStore as _;
    let recovered = DatabaseCaKeyStore::new(KEY)
        .load(
            &CaService::<SurrealCaCertificateRepository<TestDb>>::key_ref(&migrated),
            migrated.encrypted_private_key.as_deref(),
        )
        .await
        .expect("the migrated key must decrypt out of its new custodian");
    assert_eq!(
        recovered.trim(),
        pem.trim(),
        "the key that came out of Vault must be the key now in the row"
    );
}

// ---------------------------------------------------------------------------
// The refusals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrating_to_the_custodian_it_already_uses_is_refused() {
    let db = setup_db().await;
    let org = Uuid::new_v4();

    let generated = service(&db, custodians(None, CaKeyCustody::Database))
        .generate(new_ca(org))
        .await
        .unwrap()
        .certificate;

    let err = service(&db, custodians(None, CaKeyCustody::Database))
        .migrate_key_custody(org, generated.id)
        .await
        .expect_err("a no-op migration must be refused, not silently re-done");

    let msg = err.to_string();
    assert!(
        msg.contains("already held by") && msg.contains("database"),
        "the refusal must name the custodian the operator is already on: {msg}"
    );
}

#[tokio::test]
async fn migrating_an_imported_trust_anchor_is_refused() {
    // An imported trust anchor is a certificate AXIAM holds no private key
    // for. There is nothing to move, and the message has to say so — an
    // operator reading "migration failed" would reasonably retry it.
    let server = MockServer::start().await;
    mount_vault_accepts_writes(&server, "unused").await;
    let db = setup_db().await;
    let org = Uuid::new_v4();

    let repo = SurrealCaCertificateRepository::new(db.clone());
    let generated = service(&db, custodians(None, CaKeyCustody::Database))
        .generate(new_ca(org))
        .await
        .unwrap()
        .certificate;
    repo.update_key_custody(org, generated.id, CaKeyCustody::External, None, None)
        .await
        .expect("re-mark the row as an imported anchor");

    let err = service(&db, custodians(Some(&server), CaKeyCustody::Vault))
        .migrate_key_custody(org, generated.id)
        .await
        .expect_err("there is no key to move");

    let msg = err.to_string();
    assert!(
        msg.contains("nothing to move") || msg.contains("trust anchor"),
        "the refusal must explain that AXIAM holds no key for this CA: {msg}"
    );
}

#[tokio::test]
async fn migrating_an_unknown_ca_is_not_found() {
    let db = setup_db().await;
    let err = service(&db, custodians(None, CaKeyCustody::Database))
        .migrate_key_custody(Uuid::new_v4(), Uuid::new_v4())
        .await
        .expect_err("an unknown CA cannot be migrated");
    assert!(
        matches!(err, axiam_core::error::AxiamError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );
}
