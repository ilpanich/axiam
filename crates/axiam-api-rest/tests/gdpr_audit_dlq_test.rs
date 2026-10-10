//! Integration test for the GDPR erasure audit dead-letter queue
//! (SECHRD-12 / T19.27, decision D-02).
//!
//! When the erasure audit DB-write fails, the record must be dead-lettered
//! to BOTH an append-only local file AND a structured `tracing` audit event
//! (T-24-61). The dead-letter file must be opened in append mode and must
//! never truncate an existing file (T-24-62).
//!
//! Drives the failure via the injectable `AuditWriteSink` seam
//! (`axiam_api_rest::handlers::gdpr::AuditWriteSink`) — no live/broken
//! database required.
//!
//! The two request records, `gdpr.data_export_requested` and
//! `gdpr.erasure_requested`, take the same route (P23W5-A8): a test per action
//! drives the real handler against a datastore that refuses every audit append
//! and reads the record back from the dead-letter file. The tests share one
//! process-wide environment variable, so they hold `ENV_LOCK`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use actix_web::test as actix_test;
use actix_web::{App, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::handlers::gdpr::{
    AuditWriteSink, GDPR_AUDIT_DLQ_FILE_ENV, write_audit_with_dead_letter,
};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
    UserRepository,
};
use axiam_db::SurrealAuditLogRepository;
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Serialises the tests below: each points `AXIAM__GDPR_AUDIT_DLQ_FILE` at its
/// own file, and the environment is process-wide.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const TEST_PEER: &str = "127.0.0.1:12345";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

/// Test double that always fails, simulating a transient SurrealDB outage on
/// the erasure audit-write path.
struct FailingAuditSink;

impl AuditWriteSink for FailingAuditSink {
    async fn write(&self, _entry: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        Err(AxiamError::Database(
            "simulated erasure audit DB outage".into(),
        ))
    }
}

/// In-memory `tracing_subscriber::fmt::MakeWriter` so the test can assert on
/// the structured audit DLQ event without a real log sink.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn gdpr_audit_dlq_on_db_failure() {
    let _env = ENV_LOCK.blocking_lock();
    let dlq_path = std::env::temp_dir().join(format!(
        "axiam-gdpr-audit-dlq-test-{}-{}.jsonl",
        std::process::id(),
        Uuid::new_v4()
    ));

    // Pre-populate the dead-letter file with a sentinel line to prove the
    // append-only sink never truncates an existing file (T-24-62).
    std::fs::write(&dlq_path, "SENTINEL-EXISTING-LINE\n").expect("seed dead-letter file");

    // SAFETY: this test binary has a single test function that touches this
    // env var, and it runs single-threaded within this process (no other
    // test in this file reads/writes it concurrently). Rust 2024 requires
    // `unsafe` for env mutation because another thread could otherwise be
    // reading env simultaneously (mirrors bootstrap_test.rs's convention).
    unsafe {
        std::env::set_var(GDPR_AUDIT_DLQ_FILE_ENV, &dlq_path);
    }

    let tenant_id = Uuid::new_v4();
    let entry = CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: "gdpr.user_pseudonymized".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: Some(serde_json::json!({ "pseudonym": "DELETED_USER_test0123456789" })),
    };

    let log_buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufWriter(log_buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tokio_test::block_on(write_audit_with_dead_letter(&FailingAuditSink, entry));
    });

    // SAFETY: see above — sole test in this binary touching this env var.
    unsafe {
        std::env::remove_var(GDPR_AUDIT_DLQ_FILE_ENV);
    }

    // --- Sink 1: append-only dead-letter file --------------------------
    let contents = std::fs::read_to_string(&dlq_path).expect("read dead-letter file");
    let lines: Vec<&str> = contents.lines().collect();
    let _ = std::fs::remove_file(&dlq_path);

    assert_eq!(
        lines.len(),
        2,
        "expected the pre-existing sentinel line plus exactly one dead-lettered \
         record (proves append-only, no truncate), got: {contents:?}"
    );
    assert_eq!(
        lines[0], "SENTINEL-EXISTING-LINE",
        "existing dead-letter file content must survive — file must be opened append-only, \
         never truncated (T-24-62)"
    );
    assert!(
        lines[1].contains(&tenant_id.to_string()) && lines[1].contains("gdpr.user_pseudonymized"),
        "dead-lettered line missing expected erasure-audit fields: {}",
        lines[1]
    );

    // --- Sink 2: structured tracing audit DLQ event ---------------------
    let log_output = String::from_utf8(log_buf.lock().unwrap().clone()).expect("utf8 log output");
    assert!(
        log_output.contains("axiam.audit.dlq"),
        "expected a structured tracing audit event on target axiam.audit.dlq, got: {log_output}"
    );
    assert!(
        log_output.contains(&tenant_id.to_string()),
        "structured audit DLQ event missing tenant_id, got: {log_output}"
    );
    assert!(
        log_output.contains("gdpr_audit_dlq"),
        "structured audit DLQ event missing expected message, got: {log_output}"
    );
}

// ---------------------------------------------------------------------------
// The request records (P23W5-A8)
// ---------------------------------------------------------------------------

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "GDPR Org".into(),
            slug: "gdpr-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "GDPR Tenant".into(),
            slug: "gdpr-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "gdpr-user".into(),
            email: "gdpr-user@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    Fixture {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
    }
}

fn test_auth_config() -> AuthConfig {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// A datastore that takes every write except the audit log's: the table
/// refuses a row the way an unreachable or full store would.
async fn refuse_audit_appends(db: &Surreal<TestDb>) {
    db.query(
        "DEFINE EVENT refuse_audit ON TABLE audit_log WHEN true THEN { THROW 'audit store down' };",
    )
    .await
    .unwrap()
    .check()
    .unwrap();
}

fn dead_letter_file(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "axiam-gdpr-request-dlq-{tag}-{}-{}.jsonl",
        std::process::id(),
        Uuid::new_v4()
    ))
}

/// POST `uri` as the fixture's user, with the audit log refusing every append,
/// and return the dead-letter file's lines.
async fn post_with_failing_audit(uri: &str, tag: &str) -> (Fixture, Vec<Value>) {
    let _env = ENV_LOCK.lock().await;
    let f = setup().await;
    let auth = test_auth_config();
    let token = issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(AppState::for_test(
                f.db.clone(),
                auth.clone(),
            )))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;
    refuse_audit_appends(&f.db).await;

    let path = dead_letter_file(tag);
    // SAFETY: every test in this binary that reads or writes the variable holds
    // `ENV_LOCK` for the whole of its use.
    unsafe {
        std::env::set_var(GDPR_AUDIT_DLQ_FILE_ENV, &path);
    }
    let req = actix_test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    // SAFETY: see above.
    unsafe {
        std::env::remove_var(GDPR_AUDIT_DLQ_FILE_ENV);
    }
    // The user's request succeeded: only the record of it was refused.
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the request itself must succeed"
    );

    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    let lines = contents
        .lines()
        .map(|l| serde_json::from_str(l).expect("a dead-letter line is JSON"))
        .collect();
    (f, lines)
}

#[actix_web::test]
async fn export_request_audit_failure_is_dead_lettered() {
    let (f, lines) = post_with_failing_audit("/api/v1/account/export", "export").await;

    assert_eq!(lines.len(), 1, "exactly one record, got: {lines:?}");
    assert_eq!(lines[0]["action"], json!("gdpr.data_export_requested"));
    assert_eq!(lines[0]["tenant_id"], json!(f.tenant_id.to_string()));
    assert_eq!(lines[0]["actor_id"], json!(f.user_id.to_string()));
    assert_eq!(lines[0]["resource_id"], json!(f.user_id.to_string()));
    // The line is the replayable form: it parses back into the entry.
    serde_json::from_value::<CreateAuditLogEntry>(lines[0].clone())
        .expect("replayable as a CreateAuditLogEntry");
}

#[actix_web::test]
async fn erasure_request_audit_failure_is_dead_lettered() {
    let (f, lines) = post_with_failing_audit("/api/v1/account/delete", "erasure").await;

    assert_eq!(lines.len(), 1, "exactly one record, got: {lines:?}");
    assert_eq!(lines[0]["action"], json!("gdpr.erasure_requested"));
    assert_eq!(lines[0]["tenant_id"], json!(f.tenant_id.to_string()));
    assert_eq!(lines[0]["actor_id"], json!(f.user_id.to_string()));
    assert_eq!(lines[0]["resource_id"], json!(f.user_id.to_string()));
    assert!(
        lines[0]["metadata"]["scheduled_purge_at"].is_string(),
        "the purge date is in the record: {:?}",
        lines[0]
    );
    serde_json::from_value::<CreateAuditLogEntry>(lines[0].clone())
        .expect("replayable as a CreateAuditLogEntry");
}

// ---------------------------------------------------------------------------
// The replay recipe (docs/deployment/README.md, "The audit dead-letter file")
// ---------------------------------------------------------------------------

/// The `jq` filter of the replay recipe, as the README prints it.
fn replay_filter_from_docs() -> String {
    let readme = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/deployment/README.md"
    ))
    .expect("read docs/deployment/README.md");
    let start = readme.find("jq -r '").expect("the recipe's jq command") + "jq -r '".len();
    let end = start
        + readme[start..]
            .find("' \\\n")
            .expect("the end of the jq filter");
    readme[start..end].to_string()
}

/// The recipe turns each line of the file into a `CREATE audit_log` statement.
/// This runs the recipe's own filter, taken from the README, over lines written
/// by the dead-letter writer and applies the statements to a migrated datastore:
/// the rows that come back must be the rows that were dead-lettered, including
/// the ones with a `null` `resource_id`/`ip_address`, which SurrealDB takes as
/// `NONE` and not as `NULL`.
#[actix_web::test]
async fn the_replay_recipe_in_the_docs_restores_dead_lettered_rows() {
    let jq_present = std::process::Command::new("jq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !jq_present {
        // CI has jq; a developer machine without it skips rather than fails.
        assert!(
            std::env::var_os("CI").is_none(),
            "jq is required to check the replay recipe in CI"
        );
        eprintln!("jq not installed: replay recipe not checked");
        return;
    }

    let f = setup().await;
    let with_resource = CreateAuditLogEntry {
        tenant_id: f.tenant_id,
        actor_id: f.user_id,
        actor_type: ActorType::User,
        action: "gdpr.erasure_requested".into(),
        resource_id: Some(f.user_id),
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: Some(json!({
            "subject_id": f.user_id.to_string(),
            "note": "quote \" backslash \\ unicode \u{e9}"
        })),
    };
    let without_resource = CreateAuditLogEntry {
        tenant_id: f.tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: "request.audit".into(),
        resource_id: None,
        outcome: AuditOutcome::Denied,
        ip_address: Some("203.0.113.9".into()),
        metadata: None,
    };

    // The file as the writer leaves it: `encode_line` per record.
    let file = dead_letter_file("recipe");
    let mut contents = String::new();
    for entry in [&with_resource, &without_resource] {
        contents.push_str(&axiam_audit::dead_letter::encode_line(entry).unwrap());
        contents.push('\n');
    }
    std::fs::write(&file, contents).unwrap();

    let out = std::process::Command::new("jq")
        .arg("-r")
        .arg(replay_filter_from_docs())
        .arg(&file)
        .output()
        .expect("run jq");
    let _ = std::fs::remove_file(&file);
    assert!(
        out.status.success(),
        "the recipe's jq filter failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let statements = String::from_utf8(out.stdout).unwrap();
    assert_eq!(statements.lines().count(), 2, "one statement per line");

    f.db.query(statements)
        .await
        .expect("the recipe's statements run")
        .check()
        .expect("the recipe's statements are accepted by the audit_log schema");

    let repo = SurrealAuditLogRepository::new(f.db.clone());
    let rows = repo
        .list(
            f.tenant_id,
            AuditLogFilter::default(),
            Pagination::default(),
        )
        .await
        .unwrap()
        .items;
    for want in [&with_resource, &without_resource] {
        let got = rows
            .iter()
            .find(|r| r.action == want.action)
            .unwrap_or_else(|| panic!("{} was not replayed", want.action));
        assert_eq!(got.tenant_id, want.tenant_id);
        assert_eq!(got.actor_id, want.actor_id);
        assert_eq!(got.actor_type, want.actor_type);
        assert_eq!(got.resource_id, want.resource_id);
        assert_eq!(got.outcome, want.outcome);
        assert_eq!(got.ip_address, want.ip_address);
        assert_eq!(
            got.metadata,
            want.metadata.clone().unwrap_or_else(|| json!({}))
        );
    }
}
