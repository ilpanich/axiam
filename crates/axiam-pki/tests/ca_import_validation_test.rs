//! What `CaService::import` refuses, and why the message matters.
//!
//! Importing a trust anchor is the one PKI entry point whose input comes
//! entirely from outside AXIAM — an operator pasting a root out of an existing
//! PKI. Every validation in `parse_ca_certificate` and
//! `verify_key_matches_certificate` exists because the alternative is a row
//! that lists as issuable and fails at the first signature, so the refusals
//! and their wording are the feature.
//!
//! Only the happy path was covered (through `vault_pki_test.rs`, incidentally
//! rather than deliberately); every rejection arm was not.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::certificate::ImportCaCertificate;
use axiam_db::repository::SurrealCaCertificateRepository;
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::{CaKeyCustodians, DatabaseCaKeyStore};
use rcgen::{CertificateParams, IsCa, KeyPair};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const KEY: [u8; 32] = [0u8; 32]; // gitleaks:allow

async fn service() -> CaService<SurrealCaCertificateRepository<TestDb>> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    CaService::new(
        SurrealCaCertificateRepository::new(db),
        PkiConfig {
            encryption_key: Some(KEY),
            ..Default::default()
        },
        Arc::new(tokio::sync::Semaphore::new(4)),
        Arc::new(
            CaKeyCustodians::new(
                Some(DatabaseCaKeyStore::new(KEY)),
                None,
                None,
                Some(axiam_core::ca_keys::CaKeyCustody::Database),
            )
            .unwrap(),
        ),
    )
}

/// A self-signed certificate and its key. `is_ca` decides whether it is a CA
/// or an ordinary leaf — the difference this module is mostly about.
fn self_signed(common_name: &str, is_ca: bool) -> (String, String) {
    signed_with(common_name, is_ca, &rcgen::PKCS_ED25519)
}

/// The same, for a named algorithm — so a test can build a CA AXIAM refuses.
fn signed_with(
    common_name: &str,
    is_ca: bool,
    alg: &'static rcgen::SignatureAlgorithm,
) -> (String, String) {
    let key = KeyPair::generate_for(alg).expect("keypair");
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("params");
    params.is_ca = if is_ca {
        IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
    } else {
        IsCa::ExplicitNoCa
    };
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("self-signed");
    (cert.pem(), key.serialize_pem())
}

async fn import_err(input: ImportCaCertificate) -> AxiamError {
    service()
        .await
        .import(input)
        .await
        .expect_err("this import must be refused")
}

fn import(public_cert_pem: String, private_key_pem: Option<String>) -> ImportCaCertificate {
    ImportCaCertificate {
        organization_id: Uuid::new_v4(),
        public_cert_pem,
        private_key_pem,
    }
}

// ---------------------------------------------------------------------------
// It has to be a certificate at all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn text_that_is_not_pem_is_refused_as_not_pem() {
    let err = import_err(import("clearly not a certificate".into(), None)).await;
    let msg = err.to_string();
    assert!(
        msg.contains("not a PEM-encoded X.509 certificate"),
        "the message must say what shape was expected: {msg}"
    );
}

#[tokio::test]
async fn a_pem_envelope_around_garbage_is_refused_as_unparseable() {
    // Well-formed PEM framing, contents that are not a certificate. Distinct
    // from the case above: the operator got the envelope right and the payload
    // wrong, and telling them "not PEM" would send them to re-export it in the
    // format they already used.
    let pem = "-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n";
    let err = import_err(import(pem.into(), None)).await;
    let msg = err.to_string();
    assert!(
        msg.contains("could not be parsed"),
        "a PEM envelope with a bad payload must be named as such: {msg}"
    );
}

#[tokio::test]
async fn an_empty_certificate_is_refused() {
    let err = import_err(import(String::new(), None)).await;
    assert!(
        matches!(err, AxiamError::Validation { .. }),
        "expected a Validation error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// It has to be a CA
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_ordinary_leaf_certificate_is_refused() {
    // The one that would otherwise be discovered months later: a leaf imported
    // as a trust anchor is offered in the issuing-CA dropdown and rejected by
    // every relying party that checks basicConstraints.
    let (leaf_pem, _) = self_signed("not-a-ca.example.com", false);
    let err = import_err(import(leaf_pem, None)).await;
    let msg = err.to_string();
    assert!(
        matches!(err, AxiamError::Validation { .. }),
        "expected a Validation error, got {err:?}"
    );
    assert!(
        msg.to_lowercase().contains("ca"),
        "the refusal must say the certificate is not a CA: {msg}"
    );
}

#[tokio::test]
async fn a_genuine_ca_without_a_key_imports_as_a_trust_anchor() {
    // The control for the tests above — the same construction, `is_ca` flipped,
    // must succeed. Without it, a refusal that rejected *everything* would pass
    // every assertion in this file.
    let (ca_pem, _) = self_signed("Import Test Root", true);
    let imported = service()
        .await
        .import(import(ca_pem, None))
        .await
        .expect("a real CA with no private key is a trust anchor");

    assert_eq!(
        imported.key_custody,
        axiam_core::ca_keys::CaKeyCustody::External,
        "a CA imported without a key is held by nobody — AXIAM cannot sign with it"
    );
    assert!(
        imported.encrypted_private_key.is_none(),
        "there is no key to seal"
    );
}

// ---------------------------------------------------------------------------
// The key has to match the certificate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_key_from_a_different_ca_is_refused() {
    // Two valid CAs, each valid on its own, paired with each other. Nothing
    // about either PEM is malformed — only the relationship between them is
    // wrong, which is precisely the mistake a copy-paste out of two files
    // makes.
    let (ca_pem, _) = self_signed("Import Test Root", true);
    let (_, other_key_pem) = self_signed("A Different Root", true);

    let err = import_err(import(ca_pem, Some(other_key_pem))).await;
    assert!(
        matches!(err, AxiamError::Validation { .. }),
        "expected a Validation error, got {err:?}"
    );
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("key") && (msg.contains("match") || msg.contains("certificate")),
        "the refusal must point at the pairing, not at either PEM: {msg}"
    );
}

#[tokio::test]
async fn a_private_key_that_is_not_a_key_is_refused() {
    let (ca_pem, _) = self_signed("Import Test Root", true);
    let err = import_err(import(ca_pem, Some("not a private key".into()))).await;
    let msg = err.to_string();
    assert!(
        msg.contains("private key"),
        "the refusal must name the private key as the bad input, not the \
         certificate that was fine: {msg}"
    );
}

#[tokio::test]
async fn a_matching_pair_imports_and_is_held_by_the_configured_custodian() {
    // The second control: a correctly matched pair must survive every check
    // above and land under database custody with the key sealed into the row.
    let (ca_pem, key_pem) = self_signed("Import Test Root", true);
    let imported = service()
        .await
        .import(import(ca_pem, Some(key_pem)))
        .await
        .expect("a matching pair must import");

    assert_eq!(
        imported.key_custody,
        axiam_core::ca_keys::CaKeyCustody::Database
    );
    assert!(
        imported.encrypted_private_key.is_some(),
        "database custody seals the imported key into the row"
    );
    assert_eq!(imported.subject, "Import Test Root");
}

// ---------------------------------------------------------------------------
// It has to use an algorithm AXIAM can issue against
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_ca_on_an_unsupported_curve_is_refused_by_algorithm_oid() {
    // A perfectly valid, perfectly ordinary P-256 CA. AXIAM issues Ed25519 and
    // RSA only, so this has to be refused — and the refusal names the OID,
    // because "unsupported algorithm" without saying which one leaves an
    // operator guessing at a root they cannot open.
    //
    // Worth a test of its own rather than an incidental: this file's first
    // draft built every fixture with `KeyPair::generate()`, whose default is
    // exactly this curve, and four tests failed on an arm they were not
    // written for.
    let (p256_ca_pem, _) = signed_with("P-256 Root", true, &rcgen::PKCS_ECDSA_P256_SHA256);
    let err = import_err(import(p256_ca_pem, None)).await;
    let msg = err.to_string();
    assert!(
        msg.contains("1.2.840.10045.2.1"),
        "the refusal must name the algorithm OID it found: {msg}"
    );
    assert!(
        msg.contains("Ed25519") && msg.contains("RSA"),
        "and what it would have accepted: {msg}"
    );
}
