//! Integration test: the mTLS trust-anchor hot reload.
//!
//! Flagging a CA as an mTLS trust anchor used to take effect at the *next*
//! boot. `TrustAnchorReload` closes that gap by re-reading the flagged set and
//! installing it on the running listener. This pins the half that survives the
//! process: what reaches disk.
//!
//! # Why this is an integration test and not a unit test
//!
//! `tls::reload_trust_anchors` reads `LIVE_VERIFIER`, a process-global
//! `OnceLock` holding the listener's verifier. The lib's own TLS tests install
//! one and then handshake against it, so a reload test living beside them
//! would replace the anchors under a test that is mid-handshake — and would
//! itself see `Some(count)` or `None` depending on which test won the race.
//!
//! An integration test gets its own process, where no listener has been
//! installed. `reload_trust_anchors` then answers `Ok(None)` deterministically
//! and nothing is shared. That is not a weaker test: the bundle on disk is
//! precisely what a restart reads, and a reload that installed a set the next
//! boot could not reproduce is the failure the write-then-swap ordering exists
//! to prevent. The install half is covered by `tls`'s own verifier tests.

use std::path::PathBuf;

use axiam_api_rest::TrustAnchorReloader as _;
use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::models::certificate::{KeyAlgorithm, StoreCaCertificate};
use axiam_core::repository::CaCertificateRepository as _;
use axiam_db::{SurrealCaCertificateRepository, run_migrations};
use axiam_server::mtls_anchors::TrustAnchorReload;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn db_with_migrations() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("ns/db");
    run_migrations(&db).await.expect("migrations");
    db
}

/// A scratch directory that cleans up after itself even on a failed assertion.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("axiam-reload-{}", Uuid::new_v4())))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Store a CA, optionally flagged as an mTLS trust anchor. Returns its id.
async fn store_ca(
    repo: &SurrealCaCertificateRepository<Db>,
    organization_id: Uuid,
    pem: &str,
    flagged: bool,
) -> Uuid {
    let id = Uuid::new_v4();
    repo.create(StoreCaCertificate {
        id,
        organization_id,
        tenant_id: None,
        parent_ca_id: None,
        subject: "CN=Reload Root".into(),
        public_cert_pem: pem.into(),
        chain_pem: None,
        fingerprint: format!("fp-{id}"),
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - Duration::days(1),
        not_after: Utc::now() + Duration::days(365),
        encrypted_private_key: None,
        key_custody: CaKeyCustody::Vault,
        key_locator: Some(format!("axiam/ca/{id}")),
    })
    .await
    .expect("store the CA");

    if flagged {
        repo.set_mtls_trust_anchor(organization_id, id, true)
            .await
            .expect("flag it as a trust anchor");
    }
    id
}

#[tokio::test]
async fn reload_writes_the_bundle_from_the_database() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let org = Uuid::new_v4();
    store_ca(&repo, org, "-----ANCHOR-A-----", true).await;

    let dir = ScratchDir::new();
    // Deliberately nested: the parent does not exist, and a first-ever reload
    // on a fresh deployment has to create it rather than fail.
    let path = dir.join("nested/client-ca.pem");
    let reloader = TrustAnchorReload::new(repo, Some(path.clone()));

    // `None` = no listener in this process, so there was nothing to install
    // into. The write still happened, which is the assertion that matters.
    assert_eq!(reloader.reload().await.expect("reload must succeed"), None);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "-----ANCHOR-A-----\n"
    );
}

/// The set is re-read, not appended to.
///
/// `reload` takes no argument for a reason: two administrators flagging two
/// CAs at once must converge on a bundle holding both, and a caller-supplied
/// delta could not express that. The file is what the next boot reads, so
/// "converge" has to mean the file, not just the listener.
#[tokio::test]
async fn reload_rebuilds_the_whole_set_rather_than_appending() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let org = Uuid::new_v4();
    store_ca(&repo, org, "-----ANCHOR-A-----", true).await;

    let dir = ScratchDir::new();
    let path = dir.join("client-ca.pem");
    let reloader = TrustAnchorReload::new(
        SurrealCaCertificateRepository::new(db.clone()),
        Some(path.clone()),
    );

    reloader.reload().await.expect("first reload");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "-----ANCHOR-A-----\n"
    );

    store_ca(&repo, org, "-----ANCHOR-B-----", true).await;
    reloader.reload().await.expect("second reload");

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("-----ANCHOR-A-----"), "got {written:?}");
    assert!(written.contains("-----ANCHOR-B-----"), "got {written:?}");
    assert_eq!(
        written.lines().count(),
        2,
        "the bundle is the whole set, each certificate once: {written:?}"
    );
}

/// An unflagged CA leaves the bundle, rather than lingering on disk for the
/// next boot to read back as trusted.
#[tokio::test]
async fn reload_after_the_last_anchor_is_unflagged_empties_the_bundle() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let org = Uuid::new_v4();
    let id = store_ca(&repo, org, "-----ANCHOR-A-----", true).await;

    let dir = ScratchDir::new();
    let path = dir.join("client-ca.pem");
    let reloader = TrustAnchorReload::new(
        SurrealCaCertificateRepository::new(db.clone()),
        Some(path.clone()),
    );

    reloader.reload().await.expect("first reload");
    assert!(!std::fs::read_to_string(&path).unwrap().is_empty());

    repo.set_mtls_trust_anchor(org, id, false)
        .await
        .expect("unflag");
    reloader.reload().await.expect("second reload");
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "",
        "an emptied set must empty the file, not leave the old anchors on disk"
    );
}

/// An unflagged CA is never in the bundle in the first place.
#[tokio::test]
async fn an_unflagged_ca_is_not_written_to_the_bundle() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    let org = Uuid::new_v4();
    store_ca(&repo, org, "-----FLAGGED-----", true).await;
    store_ca(&repo, org, "-----NOT-FLAGGED-----", false).await;

    let dir = ScratchDir::new();
    let path = dir.join("client-ca.pem");
    let reloader = TrustAnchorReload::new(repo, Some(path.clone()));
    reloader.reload().await.expect("reload must succeed");

    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(written, "-----FLAGGED-----\n", "got {written:?}");
}

/// A deployment with nowhere to write still reloads.
///
/// `bundle_path` is `None` when TLS is configured without a certificate path to
/// derive one from. There is then nothing for a restart to read — which is what
/// the API's `restart_required` reports — but the running listener can still be
/// updated, so this must not be an error.
#[tokio::test]
async fn reload_without_a_bundle_path_writes_nothing_and_still_succeeds() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    store_ca(&repo, Uuid::new_v4(), "-----ANCHOR-A-----", true).await;

    let reloader = TrustAnchorReload::new(repo, None);
    assert_eq!(reloader.reload().await.expect("reload must succeed"), None);
}

/// Anchors cross organization boundaries by design.
///
/// The client trust store is a property of the *listener*, which is one
/// process serving every organization. `list_mtls_trust_anchors` is therefore
/// deliberately not organization-scoped, and the bundle holds every flagged CA
/// in the deployment.
#[tokio::test]
async fn the_bundle_spans_organizations() {
    let db = db_with_migrations().await;
    let repo = SurrealCaCertificateRepository::new(db.clone());
    store_ca(&repo, Uuid::new_v4(), "-----ORG-ONE-----", true).await;
    store_ca(&repo, Uuid::new_v4(), "-----ORG-TWO-----", true).await;

    let dir = ScratchDir::new();
    let path = dir.join("client-ca.pem");
    let reloader = TrustAnchorReload::new(repo, Some(path.clone()));
    reloader.reload().await.expect("reload must succeed");

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("-----ORG-ONE-----"), "got {written:?}");
    assert!(written.contains("-----ORG-TWO-----"), "got {written:?}");
}
