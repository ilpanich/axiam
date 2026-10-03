//! The directory sync job as the scheduler runs it (T23.3.5, G-3, D-31): what a
//! pass reports to `GET /health/jobs`.
//!
//! The job's behaviour against a directory — deactivation, the safety valve, the
//! watermark — is pinned in `axiam-directory`'s `sync_test.rs`, against an
//! in-process TLS directory. What belongs here is the seam this crate owns:
//! `sweep_directories` turns a pass into the `Result` the scheduler records, so
//! an unreachable directory is a **failure in job health** and changes nothing,
//! a deployment with no directory is a clean no-op, and a shutdown request
//! abandons the pass before it starts.

use std::sync::Arc;
use std::time::Duration;

use axiam_api_rest::health::JobHealthReporter;
use axiam_auth::service::RepositoryDirectoryAuditSink;
use axiam_core::error::AxiamError;
use axiam_core::models::directory::{DirectoryKind, NewDirectoryConfig};
use axiam_core::models::user::{CreateDirectoryAccount, UserStatus};
use axiam_core::repository::{
    DirectoryConfigRepository, DirectorySyncStateRepository, UserRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealDirectoryConfigRepository,
    SurrealDirectorySyncStateRepository, SurrealGroupRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealUserRepository, run_migrations,
};
use axiam_directory::{
    ClientLimits, DirectoryClient, DirectorySync, RepositoryDirectoryAuthenticator,
    RepositoryGroupMapper,
};
use axiam_server::cleanup::{CleanupTask, DirectorySyncJob, sweep_directories};
use axiam_server::job_health::JobHealth;
use secrecy::zeroize::Zeroizing;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::sync::watch;
use uuid::Uuid;

fn encryption_material() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

struct Fixture {
    db: Surreal<Db>,
    job: DirectorySyncJob<Db>,
    config: SurrealDirectoryConfigRepository<Db>,
}

async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");

    let config = SurrealDirectoryConfigRepository::new(db.clone(), Some(encryption_material()));
    let authenticator = Arc::new(RepositoryDirectoryAuthenticator::with_client(
        config.clone(),
        Arc::new(DirectoryClient::new(ClientLimits {
            acquire_timeout: Duration::from_millis(300),
            connect_timeout: Duration::from_millis(500),
            operation_timeout: Duration::from_millis(500),
            authentication_deadline: Duration::from_secs(2),
            ..ClientLimits::default()
        })),
    ));
    let job = DirectorySync::new(
        config.clone(),
        Arc::clone(&authenticator),
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        SurrealDirectorySyncStateRepository::new(db.clone()),
        Arc::new(RepositoryGroupMapper::new(
            authenticator,
            SurrealGroupRepository::new(db.clone()),
        )),
        Arc::new(RepositoryDirectoryAuditSink(
            SurrealAuditLogRepository::new(db.clone()),
        )),
    );
    Fixture { db, job, config }
}

/// A directory nobody is listening at: connecting is refused at once.
async fn configure_unreachable_directory(
    config: &SurrealDirectoryConfigRepository<Db>,
    tenant_id: Uuid,
) {
    let kind = DirectoryKind::OpenLdap;
    config
        .create(NewDirectoryConfig {
            tenant_id,
            enabled: true,
            kind,
            url: "ldaps://localhost:1".into(),
            start_tls: false,
            bind_dn: "cn=reader,dc=example,dc=com".into(),
            bind_secret: Some(Zeroizing::new(Uuid::new_v4().to_string())),
            base_dn: "dc=example,dc=com".into(),
            user_filter: "(uid={username})".into(),
            user_attribute_map: kind.default_user_attribute_map(),
            group_base_dn: None,
            group_filter: None,
            group_member_attribute: kind.default_group_member_attribute().into(),
            group_nesting_depth: 5,
            group_mappings: vec![],
            sync_interval_secs: 3600,
            jit_provisioning: false,
            trust_anchors_pem: vec![],
        })
        .await
        .expect("a configuration");
}

fn health() -> JobHealth {
    let health = JobHealth::new(Duration::from_secs(300));
    health.register("directory_sync");
    health
}

#[tokio::test]
async fn a_deployment_with_no_directory_sweeps_cleanly() {
    let f = fixture().await;
    let (_tx, rx) = watch::channel(false);
    let health = health();

    let outcome = sweep_directories(&f.job, rx).await;
    assert_eq!(outcome.as_ref().ok(), Some(&0));
    CleanupTask::<Db>::record(&health, "directory_sync", outcome, tracing::Level::INFO);

    let status = &health.snapshot()[0];
    assert!(status.last_success_at.is_some());
    assert_eq!(status.consecutive_failures, 0);
}

/// The directory cannot be reached: the pass fails, **job health says so with
/// the fixed tag and no tenant data**, and the account is exactly as it was —
/// an absent directory is not an empty one.
#[tokio::test]
async fn an_unreachable_directory_is_a_failure_in_job_health_and_changes_nothing() {
    let f = fixture().await;
    let tenant_id = Uuid::new_v4();
    configure_unreachable_directory(&f.config, tenant_id).await;
    let users = SurrealUserRepository::new(f.db.clone());
    let account = users
        .create_directory_account(CreateDirectoryAccount {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            external_id: Uuid::new_v4().to_string(),
            metadata: serde_json::json!({}),
        })
        .await
        .unwrap();
    let (_tx, rx) = watch::channel(false);
    let health = health();

    let outcome = sweep_directories(&f.job, rx).await;
    let Err(AxiamError::Internal(message)) = &outcome else {
        panic!("an unreachable directory must fail the sweep");
    };
    assert_eq!(
        message,
        "directory sync failed for 1 of 1 tenants (directory_unavailable)"
    );
    CleanupTask::<Db>::record(&health, "directory_sync", outcome, tracing::Level::INFO);

    let status = &health.snapshot()[0];
    assert_eq!(status.consecutive_failures, 1);
    assert!(
        status
            .last_error
            .as_deref()
            .unwrap()
            .contains("directory_unavailable")
    );
    assert!(status.last_success_at.is_none());

    // Nothing changed, and the state records the failure.
    let after = users.get_by_id(tenant_id, account.id).await.unwrap();
    assert_eq!(after.status, UserStatus::Active);
    let state = SurrealDirectorySyncStateRepository::new(f.db.clone())
        .get(tenant_id)
        .await
        .unwrap()
        .expect("a state row");
    assert_eq!(
        state.last_result,
        Some(axiam_core::models::directory_sync::DirectorySyncResult::Failed)
    );
}

/// One tenant's outage does not stop the next: both are attempted, both counted.
#[tokio::test]
async fn one_tenants_failure_is_counted_and_does_not_stop_the_others() {
    let f = fixture().await;
    let users = SurrealUserRepository::new(f.db.clone());
    for _ in 0..2 {
        let tenant_id = Uuid::new_v4();
        configure_unreachable_directory(&f.config, tenant_id).await;
        // A tenant with no directory accounts has nothing to ask the directory
        // about, so it is not asked; one account makes the outage matter.
        users
            .create_directory_account(CreateDirectoryAccount {
                tenant_id,
                username: "alice".into(),
                email: "alice@example.com".into(),
                external_id: Uuid::new_v4().to_string(),
                metadata: serde_json::json!({}),
            })
            .await
            .unwrap();
    }
    let (_tx, rx) = watch::channel(false);
    let outcome = sweep_directories(&f.job, rx).await;
    let Err(AxiamError::Internal(message)) = outcome else {
        panic!("both tenants fail");
    };
    assert_eq!(
        message,
        "directory sync failed for 2 of 2 tenants (directory_unavailable, directory_unavailable)"
    );
}

/// A shutdown request abandons the pass before it starts: nothing is attempted,
/// no state is written.
#[tokio::test]
async fn a_shutdown_request_abandons_the_pass() {
    let f = fixture().await;
    let tenant_id = Uuid::new_v4();
    configure_unreachable_directory(&f.config, tenant_id).await;
    let (tx, rx) = watch::channel(false);
    tx.send(true).unwrap();

    let outcome = sweep_directories(&f.job, rx).await;
    assert_eq!(outcome.ok(), Some(0));
    assert!(
        SurrealDirectorySyncStateRepository::new(f.db.clone())
            .get(tenant_id)
            .await
            .unwrap()
            .is_none(),
        "no attempt was made"
    );
}
