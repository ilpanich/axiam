//! The boot-time warning for confidential device clients (R110W3-02, #675).
//!
//! `device_grant_scan` is the code `boot::serve` runs; these tests drive it
//! over the embedded in-memory datastore with a captured `tracing`
//! subscriber. The warning is emitted once, with the count, when such a client
//! exists; not at all when none does; a failed or stalled scan is one `warn!`
//! and no panic. The log line carries counts and no client id or name.

use std::future::pending;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use axiam_server::device_grant_scan::{scan_with, spawn_boot_scan};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

const URN: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Captured {
    /// One captured line per event, at WARN and above.
    fn warnings(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains(" WARN "))
            .map(str::to_owned)
            .collect()
    }
}

fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let sink = Captured::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (sink, tracing::subscriber::set_default(sub))
}

async fn fresh_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

async fn tenant(db: &Surreal<Db>, slug: &str) -> Uuid {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn client(db: &Surreal<Db>, tenant_id: Uuid, name: &str, method: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "tenant_id": tenant_id,
        "name": name,
        "redirect_uris": [],
        "grant_types": [URN],
        "scopes": ["openid"],
    });
    if let Some(m) = method {
        body["token_endpoint_auth_method"] = m.into();
    }
    let input: CreateOAuth2Client = serde_json::from_value(body).unwrap();
    SurrealOAuth2ClientRepository::new(db.clone())
        .create(input)
        .await
        .unwrap()
        .0
        .client_id
}

/// The only test that touches the once-per-process guard, so it owns it: the
/// first call scans and warns once with the count, every later one starts
/// nothing.
#[tokio::test(flavor = "current_thread")]
async fn the_boot_scan_warns_once_with_the_count_and_names_nobody() {
    let db = fresh_db().await;
    let repo = SurrealOAuth2ClientRepository::new(db.clone());
    let a = tenant(&db, "alpha-tenant-name").await;
    let b = tenant(&db, "beta-tenant-name").await;
    // Two confidential device clients in `a`, one in `b`; a public one is not counted.
    let id1 = client(&db, a, "secret-client-name-1", None).await;
    let id2 = client(&db, a, "secret-client-name-2", Some("client_secret_basic")).await;
    let id3 = client(&db, b, "secret-client-name-3", None).await;
    let id4 = client(&db, b, "public-client-name", Some("none")).await;

    let (sink, _guard) = capture();
    spawn_boot_scan(repo.clone())
        .expect("the first call starts the scan")
        .await
        .unwrap();
    assert!(
        spawn_boot_scan(repo.clone()).is_none(),
        "a second call in the same process starts nothing"
    );

    let warnings = sink.warnings();
    assert_eq!(warnings.len(), 1, "exactly one warning: {warnings:?}");
    let line = &warnings[0];
    assert!(
        line.contains("3 confidential OAuth2 client(s) in 2 tenant(s)"),
        "{line}"
    );
    assert!(
        line.contains("clients=3") && line.contains("tenants=2"),
        "{line}"
    );
    assert!(line.contains("/oauth2/device_authorization"), "{line}");
    assert!(line.contains("401"), "{line}");
    assert!(line.contains("CHANGELOG.md [1.1.0]"), "{line}");
    assert!(line.contains("docs/api/device-flow.md"), "{line}");
    for private in [
        &id1,
        &id2,
        &id3,
        &id4,
        "secret-client-name",
        "public-client-name",
        "alpha-tenant-name",
        "beta-tenant-name",
    ] {
        assert!(!line.contains(private), "the line names {private}: {line}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn no_warning_when_no_confidential_device_client_exists() {
    let db = fresh_db().await;
    let repo = SurrealOAuth2ClientRepository::new(db.clone());
    let t = tenant(&db, "quiet").await;
    client(&db, t, "public", Some("none")).await;
    let gone = tenant(&db, "gone").await;
    client(&db, gone, "tombstoned", None).await;
    SurrealTenantRepository::new(db.clone())
        .delete(gone)
        .await
        .unwrap();

    let (sink, _guard) = capture();
    scan_with(
        repo.count_confidential_with_grant(&["urn:ietf:params:oauth:grant-type:device_code"]),
        Duration::from_secs(5),
    )
    .await;
    assert!(sink.warnings().is_empty(), "{:?}", sink.warnings());
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_or_stalled_scan_is_one_warning_and_does_not_panic() {
    let (sink, _guard) = capture();
    scan_with(
        async { Err(AxiamError::Internal("datastore is down".into())) },
        Duration::from_secs(5),
    )
    .await;
    let failed = sink.warnings();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0].contains("startup continues"), "{}", failed[0]);

    scan_with(pending(), Duration::from_millis(20)).await;
    let all = sink.warnings();
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all[1].contains("timed out"), "{}", all[1]);
}
