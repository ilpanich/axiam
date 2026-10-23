//! Integration test: periodic cleanup task sweeps expired federation rows and
//! shuts down gracefully (Task 1 acceptance criteria).
//!
//! Uses an in-memory SurrealDB (no external infra) and short intervals (100 ms)
//! to keep the test fast. This does NOT exercise `CleanupTask` itself (which
//! depends on `axiam-server` compiling with the xmlsec feature — see SUMMARY for
//! the local-compile limitation); instead it verifies the underlying
//! `cleanup_expired` methods that `CleanupTask` calls, and the watch-shutdown
//! logic is verified via a standalone tokio task that mimics CleanupTask behaviour.

use axiam_test_support::test_password;
use std::time::Duration;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::{CreateErasureProof, ErasureProof};
use axiam_core::models::user::{CreateUser, UpdateUser, User};
use axiam_core::repository::{
    AssertionReplayRepository, AuditLogFilter, AuditLogRepository, ErasureProofRepository,
    FederationLoginStateRepository, PaginatedResult, Pagination, UserRepository,
};
use axiam_db::{
    SurrealAssertionReplayRepository, SurrealAuditLogRepository, SurrealErasureProofRepository,
    SurrealFederationLoginStateRepository, SurrealUserRepository, run_migrations,
};
use axiam_server::cleanup::SweptClientGrants;
use axiam_server::cleanup::run_erasure_pipeline;
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use surrealdb_types::SurrealValue;
use tokio::sync::watch;
use uuid::Uuid;

async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");
    db
}

/// A migrated `surrealkv` datastore in a fresh temporary directory, the engine
/// production runs, for a test whose assertion is "exactly one concurrent
/// caller wins". `kv-mem` admits two winners to a guarded write in about 2 % of
/// contended rounds (`axiam-db`'s `tests/common/mod.rs` measured it and says
/// why), so a race test on it measures an engine AXIAM never deploys. The
/// directory is removed when the returned guard drops, so it is held for the
/// test's whole life.
async fn setup_serialising_db() -> (Surreal<surrealdb::engine::local::Db>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("temp dir for the surrealkv datastore");
    let path = dir.path().join("axiam-test.db");
    let db =
        Surreal::new::<surrealdb::engine::local::SurrealKv>(path.to_string_lossy().into_owned())
            .await
            .expect("open surrealkv datastore");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");
    (db, dir)
}

// ---------------------------------------------------------------------------
// saml_assertion_replay sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_sweeps_expired_saml_assertion_replay_rows() {
    let db = setup_db().await;
    let repo = SurrealAssertionReplayRepository::new(db.clone());

    let tenant_id = Uuid::new_v4();
    let past = Utc::now() - chrono::Duration::seconds(2);
    let future = Utc::now() + chrono::Duration::seconds(3600);

    // Insert one expired row and one fresh row.
    repo.insert_assertion(tenant_id, "expired-id-1", past)
        .await
        .expect("insert expired");
    repo.insert_assertion(tenant_id, "fresh-id-1", future)
        .await
        .expect("insert fresh");

    // Run cleanup; exactly one expired row should be removed.
    let swept = repo.cleanup_expired().await.expect("cleanup");
    assert_eq!(swept, 1, "exactly 1 expired row should be swept");

    // Second sweep should find nothing.
    let swept2 = repo.cleanup_expired().await.expect("cleanup again");
    assert_eq!(swept2, 0, "no more expired rows");
}

// ---------------------------------------------------------------------------
// federation_login_state sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_sweeps_expired_federation_login_state_rows() {
    let db = setup_db().await;
    let repo = SurrealFederationLoginStateRepository::new(db.clone());

    let tenant_id = Uuid::new_v4();
    let config_id = Uuid::new_v4();

    let past = Utc::now() - chrono::Duration::seconds(2);
    let future = Utc::now() + chrono::Duration::seconds(3600);

    let expired_row = axiam_core::repository::FederationLoginState {
        state: "state-expired".into(),
        nonce: "nonce-expired".into(),
        tenant_id,
        federation_config_id: config_id,
        redirect_uri: "https://example.com/cb".into(),
        expires_at: past,
        request_id: String::new(),
        code_verifier: None,
        idp_redirect_uri: None,
    };
    let fresh_row = axiam_core::repository::FederationLoginState {
        state: "state-fresh".into(),
        nonce: "nonce-fresh".into(),
        tenant_id,
        federation_config_id: config_id,
        redirect_uri: "https://example.com/cb".into(),
        expires_at: future,
        request_id: String::new(),
        code_verifier: None,
        idp_redirect_uri: None,
    };

    repo.insert(&expired_row).await.expect("insert expired");
    repo.insert(&fresh_row).await.expect("insert fresh");

    let swept = repo.cleanup_expired().await.expect("cleanup");
    assert_eq!(swept, 1, "exactly 1 expired row should be swept");

    let swept2 = repo.cleanup_expired().await.expect("cleanup again");
    assert_eq!(swept2, 0, "no more expired rows");
}

// ---------------------------------------------------------------------------
// Graceful-shutdown via watch channel (unit-style, no DB required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_task_shuts_down_on_watch_signal_within_200ms() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn a task that mimics the CleanupTask loop with a very long interval
    // (10 s) — the shutdown signal should fire long before the first tick.
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut rx = shutdown_rx;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Would run cleanup; nothing to do here.
                }
                changed = rx.changed() => {
                    if changed.is_ok() && *rx.borrow() {
                        return;
                    }
                }
            }
        }
    });

    // Give the task a moment to start.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Send shutdown signal; task should exit within 200 ms.
    shutdown_tx.send(true).expect("send shutdown");

    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("task must shut down within 200 ms")
        .expect("task must not panic");
}

// ---------------------------------------------------------------------------
// Error-tolerance: DB failure does not panic the loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_does_not_propagate_db_errors_as_panics() {
    // Use a closed/disconnected DB to force errors.
    // We verify this by calling cleanup_expired on a repo whose DB has been
    // dropped (namespace not selected → query fails gracefully).
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    // Intentionally do NOT call use_ns/use_db or run_migrations.
    // SurrealDB v3 in-memory with no namespace returns an error on queries.
    let repo = SurrealAssertionReplayRepository::new(db);
    let result = repo.cleanup_expired().await;
    // Should return an Err (DB not configured), NOT panic.
    // We just assert it doesn't panic; the result shape is already verified by
    // the trait contract (returns AxiamResult<u64>).
    let _ = result; // Ok or Err — both acceptable; no panic is the requirement.
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: fatal pseudonymize_actor failure (SECHRD-06, D-03a)
//
// Exercises the Pattern 3 test-seam extraction directly (not the concrete,
// non-generic `CleanupTask`): a synthetic failing `AuditLogRepository`
// double is paired with real in-memory SurrealDB `user`/`erasure_proof`
// repos to prove the erasure pipeline is atomic — a failed
// `pseudonymize_actor` must abort the erasure, leave the user re-selectable,
// and write NO erasure proof.
// ---------------------------------------------------------------------------

/// Synthetic `AuditLogRepository` whose `pseudonymize_actor` always fails.
/// Every other method is unreachable by this test (`run_erasure_pipeline`
/// never calls them), so they `unimplemented!()`.
struct FailingAuditRepo;

impl AuditLogRepository for FailingAuditRepo {
    async fn datastore_now(&self) -> axiam_core::error::AxiamResult<chrono::DateTime<chrono::Utc>> {
        Ok(chrono::Utc::now())
    }
    async fn append(&self, _: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        unimplemented!("not exercised by erasure_pipeline_fatal_on_pseudonymize_failure")
    }
    async fn list(
        &self,
        _: Uuid,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!("not exercised by erasure_pipeline_fatal_on_pseudonymize_failure")
    }
    async fn list_system(
        &self,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!("not exercised by erasure_pipeline_fatal_on_pseudonymize_failure")
    }
    async fn get_by_ids(&self, _: Uuid, _: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!("not exercised by erasure_pipeline_fatal_on_pseudonymize_failure")
    }
    async fn pseudonymize_actor(&self, _: Uuid, _: Uuid, _: &str) -> AxiamResult<u64> {
        Err(AxiamError::Internal(
            "synthetic pseudonymize_actor failure (test double)".into(),
        ))
    }
    async fn prune_older_than(&self, _cutoff: chrono::DateTime<chrono::Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

/// Row shape for a `SELECT count() ... GROUP ALL` query.
#[derive(SurrealValue)]
struct CountRow {
    total: u64,
}

#[tokio::test]
async fn erasure_pipeline_fatal_on_pseudonymize_failure() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());
    let failing_audit_repo = FailingAuditRepo;

    // Create a user and mark it deletion-pending, mirroring the real purge
    // flow's precondition (find_due_for_purge selects on this).
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "fatal_pseudonymize_user".into(),
            email: "fatal_pseudonymize@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    let past_purge = Utc::now() - chrono::Duration::seconds(1);
    user_repo
        .mark_deletion_pending(tenant_id, user.id, past_purge)
        .await
        .expect("mark deletion pending");

    let pseudonym = "DELETED_USER_deadbeefcafe0000".to_string();
    let email_hash = "irrelevant_email_hash_for_this_test".to_string();

    // Run the pipeline with a FAILING audit repo — pseudonymize_actor is now
    // FATAL, so this must return Err (not swallow-and-continue).
    let result = run_erasure_pipeline(
        &failing_audit_repo,
        &erasure_proof_repo,
        &user_repo,
        tenant_id,
        user.id,
        &pseudonym,
        &email_hash,
    )
    .await;

    assert!(
        result.is_err(),
        "run_erasure_pipeline must return Err when pseudonymize_actor fails (D-03a)"
    );

    // (1)/(2) The user remains re-selectable: deletion_pending is still
    // true, and find_due_for_purge still returns the user — anonymize_user
    // (the only step that clears deletion_pending) never ran because
    // pseudonymize_actor aborted the pipeline before reaching it.
    let still_pending = user_repo
        .get_by_id(tenant_id, user.id)
        .await
        .expect("get_by_id");
    assert!(
        still_pending.deletion_pending,
        "deletion_pending must remain true after a failed pseudonymize_actor \
         — the user must stay re-selectable for a retry"
    );
    let due = user_repo
        .find_due_for_purge(Utc::now())
        .await
        .expect("find_due_for_purge");
    assert!(
        due.iter().any(|u| u.id == user.id),
        "the user must still be returned by find_due_for_purge (re-selectable) \
         after the fatal pseudonymize_actor failure"
    );

    // (3) NO erasure proof was written for this user — the proof-last
    // ordering means erasure_proof_repo.create() was never reached.
    let mut count_result = db
        .query(
            "SELECT count() AS total FROM erasure_proof \
             WHERE tenant_id = $tenant_id AND user_id = $user_id GROUP ALL",
        )
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("user_id", user.id.to_string()))
        .await
        .expect("query erasure_proof count");
    let rows: Vec<CountRow> = count_result.take(0).expect("take count rows");
    let proof_count = rows.first().map(|r| r.total).unwrap_or(0);
    assert_eq!(
        proof_count, 0,
        "no erasure_proof row must exist after a failed pseudonymize_actor — \
         the proof must never certify an incomplete erasure"
    );
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: shared helpers for the additional tests below
// ---------------------------------------------------------------------------

/// Count `erasure_proof` rows for a given `(tenant_id, user_id)` pair.
async fn erasure_proof_count(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> u64 {
    let mut count_result = db
        .query(
            "SELECT count() AS total FROM erasure_proof \
             WHERE tenant_id = $tenant_id AND user_id = $user_id GROUP ALL",
        )
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("user_id", user_id.to_string()))
        .await
        .expect("query erasure_proof count");
    let rows: Vec<CountRow> = count_result.take(0).expect("take count rows");
    rows.first().map(|r| r.total).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: full success path (D-01..D-06, D-03a/D-03b)
//
// Exercises every `Ok` branch of `run_erasure_pipeline` (previously only the
// fatal-failure branch was covered): audit pseudonymization actually scrubs
// the seeded entry, the user row is anonymized in place, and the erasure
// proof is written exactly once with the matching pseudonym.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_erasure_pipeline_success_path_scrubs_audit_anonymizes_user_and_writes_proof() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "erasure_success_user".into(),
            email: "erasure_success@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(
            tenant_id,
            user.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");

    // Seed an audit entry authored by (and referencing) this user so we can
    // verify the pseudonymize_actor scrub actually ran.
    let entry = audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user.id,
            actor_type: ActorType::User,
            action: "user.login".into(),
            resource_id: Some(user.id),
            outcome: AuditOutcome::Success,
            ip_address: Some("203.0.113.7".into()),
            metadata: Some(serde_json::json!({ "email": "erasure_success@example.com" })),
        })
        .await
        .expect("append audit entry");

    let pseudonym = "DELETED_USER_success0000000001".to_string();
    let email_hash = "hashed_success_email".to_string();

    let result = run_erasure_pipeline(
        &audit_repo,
        &erasure_proof_repo,
        &user_repo,
        tenant_id,
        user.id,
        &pseudonym,
        &email_hash,
    )
    .await;
    assert!(
        result.is_ok(),
        "run_erasure_pipeline must succeed when every step succeeds: {result:?}"
    );

    // User row anonymized in place: deletion_pending cleared, PII scrubbed.
    let anonymized = user_repo
        .get_by_id(tenant_id, user.id)
        .await
        .expect("get_by_id");
    assert!(
        !anonymized.deletion_pending,
        "deletion_pending must be cleared by anonymize_user on success"
    );
    assert_eq!(anonymized.username, pseudonym);
    assert_eq!(anonymized.email, email_hash);

    // Audit entry pseudonymized: actor_id -> nil, metadata carries the
    // correlation pseudonym, ip_address scrubbed.
    let scrubbed = audit_repo
        .get_by_ids(tenant_id, &[entry.id])
        .await
        .expect("get_by_ids");
    let scrubbed_entry = scrubbed
        .into_iter()
        .next()
        .expect("audit entry must still exist");
    assert_eq!(
        scrubbed_entry.actor_id,
        Uuid::nil(),
        "actor_id must be scrubbed to nil"
    );
    assert!(
        scrubbed_entry.ip_address.is_none(),
        "ip_address must be scrubbed"
    );
    assert_eq!(
        scrubbed_entry
            .metadata
            .get("actor_pseudonym")
            .and_then(|v| v.as_str()),
        Some(pseudonym.as_str()),
        "metadata.actor_pseudonym must carry the new correlation key"
    );

    // Exactly one erasure proof written, strictly last.
    assert_eq!(
        erasure_proof_count(&db, tenant_id, user.id).await,
        1,
        "exactly one erasure_proof row must exist after a successful pipeline run"
    );
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: anonymize_user failure aborts before the proof
// (D-03a) — pseudonymize_actor already ran (and is NOT rolled back), but no
// proof is ever written and the caller's `?` propagates the error.
// ---------------------------------------------------------------------------

/// Synthetic `UserRepository` whose `anonymize_user` always fails. Every
/// other method is unreachable by `run_erasure_pipeline` (it only calls
/// `anonymize_user`), so they `unimplemented!()`.
struct FailingAnonymizeUserRepo;

impl UserRepository for FailingAnonymizeUserRepo {
    async fn create(&self, _: CreateUser) -> AxiamResult<User> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<User> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn get_by_username(&self, _: Uuid, _: &str) -> AxiamResult<User> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn get_by_email(&self, _: Uuid, _: &str) -> AxiamResult<User> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn update(&self, _: Uuid, _: Uuid, _: UpdateUser) -> AxiamResult<User> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn update_totp_step(&self, _: Uuid, _: Uuid, _: u64) -> AxiamResult<bool> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn list(&self, _: Uuid, _: Pagination) -> AxiamResult<PaginatedResult<User>> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn increment_failed_logins(
        &self,
        _: Uuid,
        _: Uuid,
        _: u32,
        _: i64,
        _: f64,
        _: i64,
    ) -> AxiamResult<()> {
        unimplemented!(
            "not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails"
        )
    }
    async fn anonymize_user(&self, _: Uuid, _: Uuid, _: &str, _: &str) -> AxiamResult<()> {
        Err(AxiamError::Internal(
            "synthetic anonymize_user failure (test double)".into(),
        ))
    }
}

#[tokio::test]
async fn run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());
    let failing_user_repo = FailingAnonymizeUserRepo;

    // Seed an audit entry so we can prove pseudonymize_actor (the step
    // BEFORE anonymize_user) actually committed even though the overall
    // pipeline later fails and returns Err.
    let entry = audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user_id,
            actor_type: ActorType::User,
            action: "user.login".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: Some("198.51.100.4".into()),
            metadata: None,
        })
        .await
        .expect("append audit entry");

    let pseudonym = "DELETED_USER_anonfail00000001".to_string();
    let email_hash = "irrelevant_email_hash".to_string();

    let result = run_erasure_pipeline(
        &audit_repo,
        &erasure_proof_repo,
        &failing_user_repo,
        tenant_id,
        user_id,
        &pseudonym,
        &email_hash,
    )
    .await;

    assert!(
        result.is_err(),
        "run_erasure_pipeline must return Err when anonymize_user fails"
    );

    // pseudonymize_actor ran to completion before the abort — it is not
    // transactional with the later steps.
    let scrubbed = audit_repo
        .get_by_ids(tenant_id, &[entry.id])
        .await
        .expect("get_by_ids");
    let scrubbed_entry = scrubbed
        .into_iter()
        .next()
        .expect("audit entry must still exist");
    assert_eq!(
        scrubbed_entry.actor_id,
        Uuid::nil(),
        "pseudonymize_actor must have already scrubbed actor_id before the abort"
    );

    // No erasure proof was ever written — the proof-last invariant holds
    // even when the failure is in the SECOND step rather than the first.
    assert_eq!(
        erasure_proof_count(&db, tenant_id, user_id).await,
        0,
        "no erasure_proof row must exist when anonymize_user fails"
    );
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: erasure_proof_repo.create failure (Pitfall 3) — the
// proof is the LITERAL LAST statement, so a failure here happens after the
// user has already been anonymized (deletion_pending cleared). This proves
// the documented ordering: a transient proof-write failure leaves an
// anonymized user that is no longer re-selectable by `find_due_for_purge`
// (see report for the residual-risk discussion).
// ---------------------------------------------------------------------------

/// Synthetic `ErasureProofRepository` whose `create` always fails.
struct FailingErasureProofRepo;

impl ErasureProofRepository for FailingErasureProofRepo {
    async fn create(&self, _: CreateErasureProof) -> AxiamResult<ErasureProof> {
        Err(AxiamError::Internal(
            "synthetic erasure_proof create failure (test double)".into(),
        ))
    }
}

#[tokio::test]
async fn run_erasure_pipeline_returns_err_when_erasure_proof_create_fails_after_anonymize() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let failing_erasure_proof_repo = FailingErasureProofRepo;

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "proof_fail_user".into(),
            email: "proof_fail@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(
            tenant_id,
            user.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");

    let pseudonym = "DELETED_USER_prooffail0000001".to_string();
    let email_hash = "hashed_proof_fail_email".to_string();

    let result = run_erasure_pipeline(
        &audit_repo,
        &failing_erasure_proof_repo,
        &user_repo,
        tenant_id,
        user.id,
        &pseudonym,
        &email_hash,
    )
    .await;

    assert!(
        result.is_err(),
        "run_erasure_pipeline must return Err when erasure_proof_repo.create fails"
    );

    // anonymize_user already ran (it precedes the proof write): the user is
    // anonymized in place even though no proof was ever recorded for it.
    let anonymized = user_repo
        .get_by_id(tenant_id, user.id)
        .await
        .expect("get_by_id");
    assert!(
        !anonymized.deletion_pending,
        "anonymize_user must have already cleared deletion_pending before the proof-write failure"
    );
    assert_eq!(anonymized.username, pseudonym);
}

// ---------------------------------------------------------------------------
// run_erasure_pipeline: retried erasure after a prior success is rejected
// idempotently by the DB UNIQUE index (D-03b) rather than silently
// overwriting/duplicating the proof.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_erasure_pipeline_retry_after_success_is_rejected_idempotently() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "retry_user".into(),
            email: "retry@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(
            tenant_id,
            user.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");

    let pseudonym = "DELETED_USER_retry0000000001".to_string();
    let email_hash = "hashed_retry_email".to_string();

    // First run succeeds.
    let first = run_erasure_pipeline(
        &audit_repo,
        &erasure_proof_repo,
        &user_repo,
        tenant_id,
        user.id,
        &pseudonym,
        &email_hash,
    )
    .await;
    assert!(first.is_ok(), "first erasure run must succeed: {first:?}");

    // A retry (e.g. a duplicate cleanup-sweep tick that somehow re-selects
    // the same user) re-runs anonymize_user idempotently but must be
    // rejected at the proof-write step by the UNIQUE(tenant_id, user_id)
    // index — never a silent duplicate/overwrite (D-03b).
    let second = run_erasure_pipeline(
        &audit_repo,
        &erasure_proof_repo,
        &user_repo,
        tenant_id,
        user.id,
        &pseudonym,
        &email_hash,
    )
    .await;
    assert!(
        second.is_err(),
        "a retried erasure for an already-erased user must be rejected, not silently succeed"
    );

    assert_eq!(
        erasure_proof_count(&db, tenant_id, user.id).await,
        1,
        "exactly one erasure_proof row must exist even after a retried pipeline run"
    );
}

// ---------------------------------------------------------------------------
// T21.4 — the dynamic-registration sweeps
// ---------------------------------------------------------------------------

/// Back-date a client's `created_at` and `last_authorized_at`.
///
/// There is no API for this and there should not be: both columns are written
/// by the server, one at creation and one when an authorization code is
/// issued. A test about a TTL has to move the clock somehow, and moving the
/// row is honest where mocking `Utc::now()` across three crates would not be.
async fn backdate_client(
    db: &Surreal<surrealdb::engine::local::Db>,
    client_id: &str,
    days: i64,
    ever_authorized: bool,
) {
    let when = Utc::now() - chrono::Duration::days(days);
    let sql = if ever_authorized {
        "UPDATE oauth2_client SET created_at = $when, last_authorized_at = $when \
         WHERE client_id = $client_id"
    } else {
        "UPDATE oauth2_client SET created_at = $when, last_authorized_at = NONE \
         WHERE client_id = $client_id"
    };
    db.query(sql)
        .bind(("when", when))
        .bind(("client_id", client_id.to_string()))
        .await
        .expect("backdate")
        .check()
        .expect("backdate check");
}

/// Move a row's `updated_at` back by `days`, which `backdate_client` does not
/// touch because the `dcr` clock does not read it. The `cimd` clock does — it
/// is the stamp every resolve moves — so its tests need to set it.
async fn backdate_updated_at(
    db: &Surreal<surrealdb::engine::local::Db>,
    client_id: &str,
    days: i64,
) {
    db.query("UPDATE oauth2_client SET updated_at = $when WHERE client_id = $client_id")
        .bind(("when", Utc::now() - chrono::Duration::days(days)))
        .bind(("client_id", client_id.to_string()))
        .await
        .expect("backdate updated_at")
        .check()
        .expect("backdate updated_at check");
}

/// #517 — the grant stores the sweep revokes a client's grants from.
fn grants(
    db: &Surreal<surrealdb::engine::local::Db>,
) -> SweptClientGrants<surrealdb::engine::local::Db> {
    SweptClientGrants::new(
        axiam_db::SurrealRefreshTokenRepository::new(db.clone()),
        axiam_db::SurrealAuthorizationCodeRepository::new(db.clone()),
        axiam_db::SurrealPushedAuthRequestRepository::new(db.clone()),
        axiam_db::SurrealDeviceGrantRepository::new(db.clone()),
        axiam_db::SurrealCibaRequestRepository::new(db.clone(), None),
    )
}

/// Create one client with the given provenance and return its `client_id`.
async fn seed_client(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    name: &str,
    managed_by: axiam_core::models::oauth2_client::ManagedBy,
) -> String {
    use axiam_core::repository::OAuth2ClientRepository as _;
    let (client, _) = axiam_db::SurrealOAuth2ClientRepository::new(db.clone())
        .create(axiam_core::models::oauth2_client::CreateOAuth2Client {
            tenant_id,
            name: name.into(),
            redirect_uris: vec!["http://127.0.0.1/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: Default::default(),
            token_endpoint_auth_method: Default::default(),
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: Default::default(),
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by,
            ciba: Default::default(),
        })
        .await
        .expect("seed client");
    client.client_id
}

/// The same, plus a registration mode — T21.8's second clock is gated on it.
///
/// `anonymous` needs `external_client_allowed_resources` non-empty or the
/// baseline is refused (D3), which is the interlock T21.4a added and this
/// helper has to satisfy rather than work around.
async fn seed_tenant_with_mode(
    db: &Surreal<surrealdb::engine::local::Db>,
    slug: &str,
    ttl_days: u32,
    mode: axiam_core::models::settings::DynamicRegistrationMode,
) -> Uuid {
    use axiam_core::repository::{
        OrganizationRepository as _, SettingsRepository as _, TenantRepository as _,
    };
    let org = axiam_db::SurrealOrganizationRepository::new(db.clone())
        .create(axiam_core::models::organization::CreateOrganization {
            name: format!("org {slug}"),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .expect("org");
    let tenant = axiam_db::SurrealTenantRepository::new(db.clone())
        .create(axiam_core::models::tenant::CreateTenant {
            organization_id: org.id,
            kind: axiam_core::models::tenant::TenantKind::Standard,
            name: format!("tenant {slug}"),
            slug: format!("tenant-{slug}"),
            metadata: None,
        })
        .await
        .expect("tenant");
    axiam_db::SurrealSettingsRepository::new(db.clone())
        .set_org_settings(
            org.id,
            axiam_core::models::settings::SetOrgSettings {
                dcr_unused_client_ttl_days: ttl_days,
                dynamic_registration: mode,
                external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
                ..axiam_core::models::settings::system_defaults()
            },
        )
        .await
        .expect("org settings");
    tenant.id
}

/// Create an organization and a tenant, and write the organization baseline.
async fn seed_tenant_with_ttl(
    db: &Surreal<surrealdb::engine::local::Db>,
    slug: &str,
    ttl_days: u32,
) -> Uuid {
    use axiam_core::repository::{
        OrganizationRepository as _, SettingsRepository as _, TenantRepository as _,
    };
    let org = axiam_db::SurrealOrganizationRepository::new(db.clone())
        .create(axiam_core::models::organization::CreateOrganization {
            name: format!("org {slug}"),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .expect("org");
    let tenant = axiam_db::SurrealTenantRepository::new(db.clone())
        .create(axiam_core::models::tenant::CreateTenant {
            organization_id: org.id,
            kind: axiam_core::models::tenant::TenantKind::Standard,
            name: format!("tenant {slug}"),
            slug: format!("tenant-{slug}"),
            metadata: None,
        })
        .await
        .expect("tenant");
    axiam_db::SurrealSettingsRepository::new(db.clone())
        .set_org_settings(
            org.id,
            axiam_core::models::settings::SetOrgSettings {
                dcr_unused_client_ttl_days: ttl_days,
                ..axiam_core::models::settings::system_defaults()
            },
        )
        .await
        .expect("org settings");
    tenant.id
}

/// The acceptance case, and the one property the sweeper must never get wrong:
/// it removes a self-registered client nobody has used, and leaves an
/// administrator's client alone however old it is.
#[tokio::test]
async fn dcr_sweep_removes_an_unused_client_and_leaves_an_admin_one() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "sweep", 30).await;

    let stale_dcr = seed_client(&db, tenant_id, "stale-dcr", ManagedBy::Dcr).await;
    let fresh_dcr = seed_client(&db, tenant_id, "fresh-dcr", ManagedBy::Dcr).await;
    let stale_admin = seed_client(&db, tenant_id, "stale-admin", ManagedBy::Admin).await;

    // Both stale rows are 60 days past anything; only one of them is `dcr`.
    backdate_client(&db, &stale_dcr, 60, false).await;
    backdate_client(&db, &stale_admin, 60, false).await;
    // The fresh one was authorized yesterday, though it was registered long
    // before — which is the whole point of reading `last_authorized_at` first.
    backdate_client(&db, &fresh_dcr, 90, false).await;
    db.query("UPDATE oauth2_client SET last_authorized_at = $when WHERE client_id = $client_id")
        .bind(("when", Utc::now() - chrono::Duration::days(1)))
        .bind(("client_id", fresh_dcr.clone()))
        .await
        .expect("touch")
        .check()
        .expect("touch check");

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let tenant_repo = axiam_db::SurrealTenantRepository::new(db.clone());
    let settings_repo = axiam_db::SurrealSettingsRepository::new(db.clone());

    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &tenant_repo,
        &settings_repo,
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 1, "exactly the one stale self-registered client");

    assert!(
        client_repo
            .get_by_client_id(tenant_id, &stale_dcr)
            .await
            .is_err(),
        "a self-registered client unused past its tenant's TTL is swept"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &fresh_dcr)
            .await
            .is_ok(),
        "a self-registered client authorized yesterday is not"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &stale_admin)
            .await
            .is_ok(),
        "an administrator's client is never swept, however long it sits unused: somebody \
         decided it should exist"
    );
}

/// **T21.8 / MCP-04.** The `cimd` sweep removes a shadow row nobody has
/// presented, keeps one that was presented recently, and never touches an
/// administrator's client.
///
/// The clock is the difference from the `dcr` arm: a `cimd` row's `updated_at`
/// moves on **every resolve**, because `materialise_if_cimd` upserts after
/// each one and the upsert's `UPDATE` sets it. So a document presented once a
/// day is never due under a 30-day TTL, however old its `created_at` is —
/// which is what makes eviction-on-last-seen consistent with T21.4's argument
/// that a shadow row is a cache, rather than a contradiction of it.
#[tokio::test]
async fn cimd_sweep_removes_an_unpresented_row_and_keeps_a_fresh_one() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "cimd-sweep", 30).await;

    let stale = seed_client(&db, tenant_id, "stale-cimd", ManagedBy::Cimd).await;
    let presented = seed_client(&db, tenant_id, "presented-cimd", ManagedBy::Cimd).await;
    let admin = seed_client(&db, tenant_id, "admin-url", ManagedBy::Admin).await;

    // Everything is ancient by `created_at` and by `last_authorized_at`...
    for client_id in [&stale, &presented, &admin] {
        backdate_client(&db, client_id, 60, false).await;
        backdate_updated_at(&db, client_id, 60).await;
    }
    // ...except that one row was resolved an hour ago, which is the only stamp
    // a CIMD refresh moves.
    backdate_updated_at(&db, &presented, 0).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let removed = axiam_server::cleanup::sweep_unused_cimd_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 1, "exactly the one unpresented shadow row");

    assert!(
        client_repo
            .get_by_client_id(tenant_id, &stale)
            .await
            .is_err(),
        "a shadow row nobody has presented past the TTL is swept; it re-materialises on the \
         next request if the document is still published, which is what a cache should do"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &presented)
            .await
            .is_ok(),
        "updated_at moves on every resolve, so a document presented today is not due however \
         old its created_at is"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &admin)
            .await
            .is_ok(),
        "an administrator's client is never swept by either arm"
    );

    // And the `dcr` arm leaves `cimd` rows alone: one `managed_by` per call,
    // so the two health counters mean what they say.
    let tenant_id = seed_tenant_with_ttl(&db, "arm-isolation", 30).await;
    let lonely = seed_client(&db, tenant_id, "lonely-cimd", ManagedBy::Cimd).await;
    backdate_client(&db, &lonely, 60, false).await;
    backdate_updated_at(&db, &lonely, 60).await;
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 0, "the dcr arm lists dcr rows and nothing else");
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &lonely)
            .await
            .is_ok()
    );
}

/// **#517.** A swept `cimd` row comes back on the client's next request —
/// `materialise_if_cimd` upserts it under the same `client_id`, its document's
/// URL — and nothing it was granted before the sweep may come back with it:
/// the refresh token the refresh grant would look up is revoked, and the
/// authorization code and pushed request are gone. Before #517 the sweep only
/// deleted the row, and all three worked again against the re-materialised
/// one.
#[tokio::test]
async fn a_swept_cimd_clients_grants_do_not_come_back_when_it_rematerialises() {
    use axiam_core::models::oauth2_client::{
        CreateAuthorizationCode, CreateOAuth2Client, CreatePushedAuthRequest, CreateRefreshToken,
        ManagedBy, PushedAuthParams,
    };
    use axiam_core::repository::{
        AuthorizationCodeRepository as _, OAuth2ClientRepository as _,
        PushedAuthRequestRepository as _, RefreshTokenRepository as _,
    };

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "cimd-revive", 30).await;
    let client_id = "https://tool.example.com/client.json";
    let document = || CreateOAuth2Client {
        tenant_id,
        name: "Example Tool".into(),
        redirect_uris: vec!["http://127.0.0.1/cb".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: Default::default(),
        token_endpoint_auth_method: Default::default(),
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: Vec::new(),
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: Default::default(),
        browser_sso: false,
        allowed_resources: Vec::new(),
        managed_by: ManagedBy::Cimd,
        ciba: Default::default(),
    };
    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let before = client_repo
        .upsert_cimd_client(client_id, document(), 20)
        .await
        .expect("materialised")
        .expect("under the ceiling");

    // What the client was granted while it was in use.
    let refresh_repo = axiam_db::SurrealRefreshTokenRepository::new(db.clone());
    refresh_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: "rt-before-sweep".into(),
            client_id: client_id.into(),
            user_id: Some(Uuid::new_v4()),
            scopes: vec!["openid".into()],
            session_id: None,
            requested_userinfo_claims: Vec::new(),
            resource: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            dpop_jkt: None,
            expires_at: Utc::now() + chrono::Duration::days(90),
        })
        .await
        .expect("refresh token");
    let code_repo = axiam_db::SurrealAuthorizationCodeRepository::new(db.clone());
    code_repo
        .create(CreateAuthorizationCode {
            tenant_id,
            client_id: client_id.into(),
            user_id: Uuid::new_v4(),
            code_hash: "code-before-sweep".into(),
            redirect_uri: "http://127.0.0.1/cb".into(),
            scopes: vec!["openid".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            session_id: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            dpop_jkt: None,
            requested_userinfo_claims: Vec::new(),
            resource: None,
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        })
        .await
        .expect("code");
    let par_repo = axiam_db::SurrealPushedAuthRequestRepository::new(db.clone());
    par_repo
        .create(CreatePushedAuthRequest {
            tenant_id,
            client_id: client_id.into(),
            request_uri_hash: "par-before-sweep".into(),
            params: PushedAuthParams::default(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        })
        .await
        .expect("pushed request");

    // Unseen past the tenant's TTL, so the sweep evicts it.
    backdate_client(&db, client_id, 60, false).await;
    backdate_updated_at(&db, client_id, 60).await;
    let removed = axiam_server::cleanup::sweep_unused_cimd_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 1);

    // The client presents its document again.
    let after = client_repo
        .upsert_cimd_client(client_id, document(), 20)
        .await
        .expect("re-materialised")
        .expect("under the ceiling");
    assert_ne!(after.id, before.id, "a new row under the same client_id");

    assert!(
        refresh_repo
            .get_by_token_hash(tenant_id, "rt-before-sweep")
            .await
            .is_err(),
        "the refresh grant's lookup must not find a pre-sweep refresh token"
    );
    assert!(
        code_repo
            .get_by_hash(
                tenant_id,
                "code-before-sweep",
                client_id,
                "http://127.0.0.1/cb"
            )
            .await
            .is_err(),
        "a pre-sweep authorization code must not be redeemable"
    );
    assert!(
        par_repo
            .find_unconsumed(tenant_id, "par-before-sweep")
            .await
            .expect("read")
            .is_none(),
        "a pre-sweep request_uri must not be spendable"
    );
}

/// The `cimd` sweep honours `0` as "never sweep" too, and a tenant that never
/// enabled CIMD has nothing to list — which is the I1 shape: the same one
/// indexed query per interval the `dcr` sweep already makes, over an empty set.
#[tokio::test]
async fn a_zero_ttl_sweeps_no_cimd_rows_either() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "cimd-never", 0).await;
    let ancient = seed_client(&db, tenant_id, "ancient-cimd", ManagedBy::Cimd).await;
    backdate_client(&db, &ancient, 3650, false).await;
    backdate_updated_at(&db, &ancient, 3650).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let removed = axiam_server::cleanup::sweep_unused_cimd_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 0);
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &ancient)
            .await
            .is_ok()
    );
}

/// The predicate's table, read against a real row rather than through a
/// sweep, because the clock choice is the part of #470 worth asserting
/// directly: which of the three stamps wins decides whether a document
/// somebody is still using gets deleted.
#[tokio::test]
async fn the_cimd_clock_reads_the_latest_of_the_three_stamps() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::models::settings::DynamicRegistrationMode;
    use axiam_core::repository::OAuth2ClientRepository as _;
    use axiam_server::cleanup::{
        DcrSweepWindow, cimd_client_is_due_for_sweep, cimd_client_last_seen,
    };

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "clock", 30).await;
    let client_id = seed_client(&db, tenant_id, "clock-cimd", ManagedBy::Cimd).await;

    let now = Utc::now();
    let read = |db: Surreal<surrealdb::engine::local::Db>, id: String| {
        let repo = axiam_db::SurrealOAuth2ClientRepository::new(db);
        async move { repo.get_by_client_id(tenant_id, &id).await.expect("row") }
    };

    // Everything ancient: due. This is the row #470 is about — materialised
    // once by a stranger and never presented again.
    backdate_client(&db, &client_id, 400, true).await;
    backdate_updated_at(&db, &client_id, 400).await;
    let dead = read(db.clone(), client_id.clone()).await;
    let window = |days| DcrSweepWindow {
        days,
        // The mode is irrelevant to the `cimd` arm — T21.8's second clock does
        // not apply to a row that exists because a document was presented —
        // and `anonymous` is passed here precisely to assert that.
        mode: DynamicRegistrationMode::Anonymous,
    };
    assert!(cimd_client_is_due_for_sweep(&dead, window(30), now));
    // `0` is never due, in this arm as in the other.
    assert!(!cimd_client_is_due_for_sweep(&dead, window(0), now));

    // `updated_at` alone is enough to keep it, and that is the whole reason
    // #470 needs no migration: a resolve moves this stamp, and a resolve
    // happens on every authorize, token and PAR presentation — including one
    // served from the in-memory document cache with no fetch at all.
    backdate_updated_at(&db, &client_id, 1).await;
    let refreshed = read(db.clone(), client_id.clone()).await;
    assert!(
        !cimd_client_is_due_for_sweep(&refreshed, window(30), now),
        "a document presented yesterday is not due, whatever created_at says"
    );
    assert!(
        cimd_client_last_seen(&refreshed) > now - chrono::Duration::days(2),
        "the clock reads the latest of the three, not the earliest"
    );

    // `last_authorized_at` is read beside it, because `touch_last_authorized`
    // guards on `managed_by != 'admin'` rather than `== 'dcr'` and therefore
    // stamps cimd rows too. With `updated_at` ancient again, an authorization
    // two days ago still keeps the row.
    backdate_updated_at(&db, &client_id, 400).await;
    backdate_client(&db, &client_id, 400, false).await;
    db.query("UPDATE oauth2_client SET last_authorized_at = $when WHERE client_id = $client_id")
        .bind(("when", now - chrono::Duration::days(2)))
        .bind(("client_id", client_id.clone()))
        .await
        .expect("touch")
        .check()
        .expect("touch check");
    // `backdate_client` moved `created_at`, so re-set `updated_at` after it.
    backdate_updated_at(&db, &client_id, 400).await;
    let authorized = read(db.clone(), client_id.clone()).await;
    assert!(
        !cimd_client_is_due_for_sweep(&authorized, window(30), now),
        "an authorization two days ago keeps the row even with updated_at ancient"
    );

    // And the repository is what it says it is: this row is `cimd`, so the
    // table above is about the arm it belongs to.
    assert_eq!(authorized.managed_by, ManagedBy::Cimd);
}

/// `0` means "never sweep", which is the explicit opt-out for a deployment
/// that prunes out of band. Read the other way round — "sweep everything
/// immediately" — it would delete a tenant's whole client table on the next
/// tick, so the direction is asserted rather than assumed.
#[tokio::test]
async fn a_zero_ttl_sweeps_nothing() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_ttl(&db, "never", 0).await;
    let ancient = seed_client(&db, tenant_id, "ancient", ManagedBy::Dcr).await;
    backdate_client(&db, &ancient, 3650, false).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 0);
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &ancient)
            .await
            .is_ok()
    );
}

/// The TTL is each row's own tenant's, so two tenants with different windows
/// get different answers from one sweep.
#[tokio::test]
async fn the_ttl_is_resolved_per_tenant() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let short = seed_tenant_with_ttl(&db, "short", 7).await;
    let long = seed_tenant_with_ttl(&db, "long", 365).await;

    let a = seed_client(&db, short, "a", ManagedBy::Dcr).await;
    let b = seed_client(&db, long, "b", ManagedBy::Dcr).await;
    // Thirty days: past the seven-day window, inside the year-long one.
    backdate_client(&db, &a, 30, true).await;
    backdate_client(&db, &b, 30, true).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 1);
    assert!(client_repo.get_by_client_id(short, &a).await.is_err());
    assert!(client_repo.get_by_client_id(long, &b).await.is_ok());
}

/// The decision function on its own, at the boundary, where an off-by-one
/// would be a client swept a day early or kept a day late.
///
/// Every case here runs in `initial_access_token` mode, which is how this
/// table keeps meaning exactly what it meant before T21.8: that mode has no
/// unauthenticated exposure, so the second clock does not apply and the days
/// TTL governs both situations as it always did. The `anonymous` arm is the
/// test below. No assertion in this one changed — only the shape of the
/// argument the predicate takes.
#[test]
fn the_sweep_decision_reads_last_authorized_then_created() {
    use axiam_core::models::oauth2_client::{ManagedBy, OAuth2Client};
    use axiam_core::models::settings::DynamicRegistrationMode;
    use axiam_server::cleanup::{DcrSweepWindow, dcr_client_is_due_for_sweep};

    let now = Utc::now();
    let client = |created_days: i64, authorized_days: Option<i64>| OAuth2Client {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        client_id: "c".into(),
        client_secret_hash: String::new(),
        name: "c".into(),
        redirect_uris: Vec::new(),
        grant_types: Vec::new(),
        scopes: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: Default::default(),
        token_endpoint_auth_method: Default::default(),
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: Vec::new(),
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: Default::default(),
        browser_sso: false,
        allowed_resources: Vec::new(),
        managed_by: ManagedBy::Dcr,
        last_authorized_at: authorized_days.map(|d| now - chrono::Duration::days(d)),
        created_at: now - chrono::Duration::days(created_days),
        updated_at: now,
        ciba: Default::default(),
    };

    let window = |days| DcrSweepWindow {
        days,
        mode: DynamicRegistrationMode::InitialAccessToken,
    };

    // Never authorized: `created_at` is the clock.
    assert!(dcr_client_is_due_for_sweep(
        &client(31, None),
        window(30),
        now
    ));
    assert!(!dcr_client_is_due_for_sweep(
        &client(29, None),
        window(30),
        now
    ));
    // Authorized: `last_authorized_at` wins, however old the registration is.
    assert!(!dcr_client_is_due_for_sweep(
        &client(3650, Some(1)),
        window(30),
        now
    ));
    assert!(dcr_client_is_due_for_sweep(
        &client(3650, Some(31)),
        window(30),
        now
    ));
    // Zero is never.
    assert!(!dcr_client_is_due_for_sweep(
        &client(3650, None),
        window(0),
        now
    ));
}

/// **MCP-05 (#471).** The second clock's table: a never-authorized
/// registration in `anonymous` mode is due in an hour, and nothing else
/// changes.
///
/// One quota served two situations that have nothing in common — "registered
/// and abandoned" and "used once, gone quiet" — and the thirty-day default is
/// sized for the second. So in `anonymous` mode, which is the only mode where
/// a stranger can create the row at all, a registration nobody has authorized
/// is measured against `DCR_UNAUTHORIZED_CLIENT_TTL_SECS` instead. What that
/// turns a quota-exhaustion attack into is an hour of denial rather than a
/// month of it, at the same cost to the attacker.
#[test]
fn the_second_clock_reads_never_authorized_in_anonymous_mode_only() {
    use axiam_core::models::oauth2_client::{ManagedBy, OAuth2Client};
    use axiam_core::models::settings::{DCR_UNAUTHORIZED_CLIENT_TTL_SECS, DynamicRegistrationMode};
    use axiam_server::cleanup::{DcrSweepWindow, dcr_client_is_due_for_sweep};

    let now = Utc::now();
    let row = |age_secs: i64, authorized_days: Option<i64>| OAuth2Client {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        client_id: "c".into(),
        client_secret_hash: String::new(),
        name: "c".into(),
        redirect_uris: Vec::new(),
        grant_types: Vec::new(),
        scopes: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: Default::default(),
        token_endpoint_auth_method: Default::default(),
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: Vec::new(),
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: Default::default(),
        browser_sso: false,
        allowed_resources: Vec::new(),
        managed_by: ManagedBy::Dcr,
        last_authorized_at: authorized_days.map(|d| now - chrono::Duration::days(d)),
        created_at: now - chrono::Duration::seconds(age_secs),
        updated_at: now,
        ciba: Default::default(),
    };
    let hour = i64::from(DCR_UNAUTHORIZED_CLIENT_TTL_SECS);
    let window = |mode| DcrSweepWindow { days: 30, mode };
    use DynamicRegistrationMode::{Anonymous, Disabled, InitialAccessToken};

    // Never authorized + anonymous + past the hour → due. This is the row the
    // issue is about: created by a stranger, never used, holding a slot.
    assert!(dcr_client_is_due_for_sweep(
        &row(hour + 60, None),
        window(Anonymous),
        now
    ));
    // ...and inside the hour it is not. The floor on the window exists so that
    // a client which registers, shows a consent screen and waits for somebody
    // to read it is never swept mid-flow.
    assert!(!dcr_client_is_due_for_sweep(
        &row(hour - 60, None),
        window(Anonymous),
        now
    ));

    // Never authorized + initial_access_token → the days clock, so an
    // hour-old row is kept. An operator who hands somebody a registration
    // token on Friday should not find the registration gone on Monday.
    assert!(!dcr_client_is_due_for_sweep(
        &row(hour + 60, None),
        window(InitialAccessToken),
        now
    ));
    // Nor under `disabled`, where the row is a leftover from a mode the tenant
    // has since turned off.
    assert!(!dcr_client_is_due_for_sweep(
        &row(hour + 60, None),
        window(Disabled),
        now
    ));
    // But the days clock still reaches it eventually, in every mode.
    for mode in [Anonymous, InitialAccessToken, Disabled] {
        assert!(
            dcr_client_is_due_for_sweep(&row(31 * 24 * 3600, None), window(mode), now),
            "the days TTL still applies in {mode}"
        );
    }

    // Authorized two hours ago + anonymous → not due. The second clock reads
    // `last_authorized_at: None` and nothing else, so a client that completed
    // a flow is on the thirty-day window like any other.
    assert!(!dcr_client_is_due_for_sweep(
        &row(hour * 10, Some(0)),
        window(Anonymous),
        now
    ));

    // `days: 0` — "never sweep" — does not disable the second clock, and that
    // is deliberate: `0` is a decision about how long a client somebody *uses*
    // is kept, and a row nobody has ever authorized is not that client. An
    // operator who prunes out of band still gets the hour on the one sweep
    // that deletes rows strangers created.
    assert!(dcr_client_is_due_for_sweep(
        &row(hour + 60, None),
        DcrSweepWindow {
            days: 0,
            mode: Anonymous
        },
        now
    ));
    assert!(!dcr_client_is_due_for_sweep(
        &row(3650 * 24 * 3600, Some(3650)),
        DcrSweepWindow {
            days: 0,
            mode: Anonymous
        },
        now
    ));
}

/// **MCP-05 (#471), end to end.** Twenty anonymous registrations, one of them
/// authorized; an hour and a minute later nineteen are gone and the one that
/// completed a flow is not.
///
/// This is the shape the issue describes: `dcr_max_clients` defaults to twenty,
/// the endpoint's rate limit is five a minute, so a stranger fills the quota in
/// about four minutes — and before T21.8 held it for thirty days, because one
/// TTL served both "registered and abandoned" and "used once, gone quiet". The
/// second clock does not make the attack more expensive; it makes the denial an
/// hour long instead of a month, which is the half of the fix that was worth
/// having. The other half is documentation, and it is on the operator page.
#[tokio::test]
async fn the_second_clock_reclaims_a_quota_filled_by_a_stranger() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::models::settings::{DCR_UNAUTHORIZED_CLIENT_TTL_SECS, DynamicRegistrationMode};
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id =
        seed_tenant_with_mode(&db, "flood", 30, DynamicRegistrationMode::Anonymous).await;

    // Twenty registrations, as an unauthenticated caller would leave them:
    // `last_authorized_at` is NONE on every one.
    let mut registered = Vec::new();
    for n in 0..20 {
        registered.push(seed_client(&db, tenant_id, &format!("flood-{n}"), ManagedBy::Dcr).await);
    }
    // One of them belongs to somebody who actually signed in.
    let genuine = registered[7].clone();
    db.query("UPDATE oauth2_client SET last_authorized_at = $when WHERE client_id = $client_id")
        .bind(("when", Utc::now()))
        .bind(("client_id", genuine.clone()))
        .await
        .expect("touch")
        .check()
        .expect("touch check");
    // And an administrator's client in the same tenant, which must survive
    // whatever happens: somebody decided it should exist.
    let admin = seed_client(&db, tenant_id, "flood-admin", ManagedBy::Admin).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let tenant_repo = axiam_db::SurrealTenantRepository::new(db.clone());
    let settings_repo = axiam_db::SurrealSettingsRepository::new(db.clone());

    // Right now, nothing is due: the flood is minutes old.
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &tenant_repo,
        &settings_repo,
        &grants(&db),
        Utc::now(),
    )
    .await
    .expect("sweep");
    assert_eq!(removed, 0, "a fresh registration is never due");

    // Advance the clock past the window rather than the rows past the clock,
    // so the assertion is about the sweeper's arithmetic and not about a
    // fixture's backdating.
    let later = Utc::now()
        + chrono::Duration::seconds(i64::from(DCR_UNAUTHORIZED_CLIENT_TTL_SECS))
        + chrono::Duration::minutes(1);
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &tenant_repo,
        &settings_repo,
        &grants(&db),
        later,
    )
    .await
    .expect("sweep");
    assert_eq!(
        removed, 19,
        "nineteen never-authorized anonymous registrations are reclaimed an hour later, not \
         thirty days later"
    );

    assert!(
        client_repo
            .get_by_client_id(tenant_id, &genuine)
            .await
            .is_ok(),
        "the one client somebody actually authorized is on the thirty-day clock like any other"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &admin)
            .await
            .is_ok(),
        "an administrator's client is never swept"
    );
    assert_eq!(
        client_repo
            .count_by_managed_by(tenant_id, ManagedBy::Dcr)
            .await
            .expect("count"),
        1,
        "the quota is available again"
    );
}

/// **I1 for #471.** The same flood in `initial_access_token` mode is untouched
/// an hour later, because that mode has no unauthenticated exposure to bound.
///
/// This is the invariant the mode gate exists for, stated as a test rather than
/// as a comment: an operator who mints a registration handle on Friday must not
/// find the registration gone on Monday, and a tenant that never opted into
/// `anonymous` behind D3 takes byte for byte the path it took before T21.8.
#[tokio::test]
async fn the_second_clock_does_not_touch_an_initial_access_token_tenant() {
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::models::settings::{DCR_UNAUTHORIZED_CLIENT_TTL_SECS, DynamicRegistrationMode};
    use axiam_core::repository::OAuth2ClientRepository as _;

    let db = setup_db().await;
    let tenant_id = seed_tenant_with_mode(
        &db,
        "handled",
        30,
        DynamicRegistrationMode::InitialAccessToken,
    )
    .await;
    let minted = seed_client(&db, tenant_id, "minted", ManagedBy::Dcr).await;

    let client_repo = axiam_db::SurrealOAuth2ClientRepository::new(db.clone());
    let later = Utc::now()
        + chrono::Duration::seconds(i64::from(DCR_UNAUTHORIZED_CLIENT_TTL_SECS))
        + chrono::Duration::days(1);
    let removed = axiam_server::cleanup::sweep_unused_dcr_clients(
        &client_repo,
        &axiam_db::SurrealTenantRepository::new(db.clone()),
        &axiam_db::SurrealSettingsRepository::new(db.clone()),
        &grants(&db),
        later,
    )
    .await
    .expect("sweep");
    assert_eq!(
        removed, 0,
        "a registration an administrator authorised by minting a handle is on the days clock"
    );
    assert!(
        client_repo
            .get_by_client_id(tenant_id, &minted)
            .await
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// G-5 (T23.5.3, D-52): an erasure is reported to the SSF port as an
// `account-purged`, with the account as it was **before** the write.
// ---------------------------------------------------------------------------

use axiam_core::models::ssf::{SsfFuture, SsfSystemAccountSink};
use axiam_server::cleanup::run_erasure_pipeline_reporting;

/// The port, recording `(tenant, user id, address, status)` as it was told.
#[derive(Default)]
struct RecordingPurgeSink {
    inactive: bool,
    purged: std::sync::Mutex<Vec<(Uuid, Uuid, String, axiam_core::models::user::UserStatus)>>,
}

impl SsfSystemAccountSink for RecordingPurgeSink {
    fn is_active(&self) -> bool {
        !self.inactive
    }

    fn account_disabled<'a>(&'a self, _tenant_id: Uuid, _user: &'a User) -> SsfFuture<'a, ()> {
        Box::pin(async {})
    }

    fn account_purged<'a>(&'a self, tenant_id: Uuid, user: &'a User) -> SsfFuture<'a, ()> {
        Box::pin(async move {
            self.purged.lock().unwrap().push((
                tenant_id,
                user.id,
                user.email.clone(),
                user.status.clone(),
            ));
        })
    }
}

async fn user_due_for_erasure(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    name: &str,
) -> User {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    users
        .mark_deletion_pending(
            tenant_id,
            user.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");
    users.get_by_id(tenant_id, user.id).await.expect("reload")
}

#[tokio::test]
async fn an_erasure_reports_the_account_as_it_was_before_the_write() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let users = SurrealUserRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let proofs = SurrealErasureProofRepository::new(db.clone());
    let user = user_due_for_erasure(&db, tenant_id, "purge_reported").await;
    let sink = RecordingPurgeSink::default();

    run_erasure_pipeline_reporting(
        &audit,
        &proofs,
        &users,
        tenant_id,
        user.id,
        "DELETED_USER_ssf000000000001",
        "hashed_ssf_email",
        Some(&sink),
    )
    .await
    .expect("the erasure succeeds");

    let told = sink.purged.lock().unwrap().clone();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].0, tenant_id);
    assert_eq!(told[0].1, user.id);
    // The address the receivers need is the one the erasure then destroyed.
    assert_eq!(told[0].2, "purge_reported@example.com");
    let after = users.get_by_id(tenant_id, user.id).await.expect("reload");
    assert_eq!(after.email, "hashed_ssf_email");
}

/// D-53 (1): the Art. 17 erasure takes the person's SSF step-up record with the
/// rest of what names them, and leaves another user's alone.
#[tokio::test]
async fn an_erasure_removes_the_persons_ssf_step_up_record() {
    use axiam_core::models::ssf::SsfStepUp;
    use axiam_core::repository::SsfStepUpRepository as _;

    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let users = SurrealUserRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let proofs = SurrealErasureProofRepository::new(db.clone());
    let step_ups = axiam_db::SurrealSsfStepUpRepository::new(db.clone());
    let erased = user_due_for_erasure(&db, tenant_id, "step_up_erased").await;
    let bystander = user_due_for_erasure(&db, tenant_id, "step_up_bystander").await;
    for user in [&erased, &bystander] {
        step_ups
            .put(
                &SsfStepUp {
                    tenant_id,
                    user_id: user.id,
                    previous_session_id: Uuid::new_v4(),
                    previous_acr: "urn:axiam:acr:1fa".into(),
                },
                Utc::now(),
            )
            .await
            .expect("record a step-up");
    }

    run_erasure_pipeline_reporting(
        &audit,
        &proofs,
        &users,
        tenant_id,
        erased.id,
        "DELETED_USER_ssf000000000009",
        "hashed_step_up_email",
        None,
    )
    .await
    .expect("the erasure succeeds");

    assert!(
        step_ups
            .take(tenant_id, erased.id, Uuid::new_v4(), Utc::now())
            .await
            .unwrap()
            .is_none(),
        "the erased person's record went with the erasure"
    );
    assert!(
        step_ups
            .take(tenant_id, bystander.id, Uuid::new_v4(), Utc::now())
            .await
            .unwrap()
            .is_some(),
        "another user's record is untouched"
    );
}

#[tokio::test]
async fn an_erasure_that_never_got_as_far_as_anonymizing_reports_nothing() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let users = SurrealUserRepository::new(db.clone());
    let proofs = SurrealErasureProofRepository::new(db.clone());
    let user = user_due_for_erasure(&db, tenant_id, "purge_aborted").await;
    let sink = RecordingPurgeSink::default();

    // `pseudonymize_actor` fails first: the account is untouched and still due.
    let result = run_erasure_pipeline_reporting(
        &FailingAuditRepo,
        &proofs,
        &users,
        tenant_id,
        user.id,
        "DELETED_USER_ssf000000000002",
        "hashed",
        Some(&sink),
    )
    .await;
    assert!(result.is_err());
    assert!(sink.purged.lock().unwrap().is_empty());
    assert!(
        users
            .get_by_id(tenant_id, user.id)
            .await
            .expect("reload")
            .deletion_pending
    );
}

/// A proof that fails to write leaves an anonymized account no sweep selects
/// again: the report is sent at the anonymization, not held for the proof.
#[tokio::test]
async fn an_erasure_whose_proof_fails_to_write_is_still_reported() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let users = SurrealUserRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let user = user_due_for_erasure(&db, tenant_id, "purge_proofless").await;
    let sink = RecordingPurgeSink::default();

    let result = run_erasure_pipeline_reporting(
        &audit,
        &FailingErasureProofRepo,
        &users,
        tenant_id,
        user.id,
        "DELETED_USER_ssf000000000003",
        "hashed",
        Some(&sink),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(sink.purged.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn no_sink_or_an_inactive_one_changes_nothing_about_the_erasure() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let users = SurrealUserRepository::new(db.clone());
    let audit = SurrealAuditLogRepository::new(db.clone());
    let proofs = SurrealErasureProofRepository::new(db.clone());

    let inactive = RecordingPurgeSink {
        inactive: true,
        ..RecordingPurgeSink::default()
    };
    for (name, sink) in [
        ("purge_no_sink", None),
        (
            "purge_inactive",
            Some(&inactive as &dyn SsfSystemAccountSink),
        ),
    ] {
        let user = user_due_for_erasure(&db, tenant_id, name).await;
        run_erasure_pipeline_reporting(
            &audit,
            &proofs,
            &users,
            tenant_id,
            user.id,
            &format!("DELETED_USER_{name}"),
            &format!("hashed_{name}"),
            sink,
        )
        .await
        .expect("the erasure succeeds");
        assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 1);
    }
    assert!(inactive.purged.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// #523 (D-4): the `tenant_purge` sweep
// ---------------------------------------------------------------------------

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository};
use axiam_server::cleanup::{AuditedWork, sweep_tenant_purge};
use std::sync::Arc;

/// Units that never stop: no stop is ever requested (the sender is gone).
fn never_stopping() -> AuditedWork {
    AuditedWork::new(watch::channel(false).1)
}

/// A tenant of a fresh organization with one user in it.
async fn tenant_with_a_user(
    db: &Surreal<surrealdb::engine::local::Db>,
    org: Uuid,
    slug: &str,
) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant,
            username: format!("user-{slug}"),
            email: format!("{slug}@example.com"),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    tenant
}

async fn users_in(db: &Surreal<surrealdb::engine::local::Db>, tenant: Uuid) -> usize {
    SurrealUserRepository::new(db.clone())
        .list(
            tenant,
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .len()
}

async fn purged_records(db: &Surreal<surrealdb::engine::local::Db>) -> Vec<AuditLogEntry> {
    SurrealAuditLogRepository::new(db.clone())
        .list_system(
            AuditLogFilter {
                action: Some(axiam_api_rest::handlers::tenants::TENANT_PURGED_ACTION.into()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
}

/// The sweep purges a tombstoned tenant — its rows, then its row — leaves a
/// live tenant alone, sweeps an orphaned tenant id (rows left by a deletion
/// made before the tombstone) only when asked to look for orphans, and records
/// each purge in the system log as `tenants.purged` — with, for the tombstoned
/// tenant, the export time its deletion record names and how many of its audit
/// rows went (those at or before it) and stayed (R1W1-04, #602). The audit
/// retention sweep then removes a kept row once it is past the window.
#[tokio::test]
async fn the_tenant_purge_sweep_purges_tombstoned_and_orphaned_tenants_and_records_it() {
    let db = setup_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "purge-sweep".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let work = never_stopping();
    let tombstoned = tenant_with_a_user(&db, org, "tombstoned").await;
    let orphan = tenant_with_a_user(&db, org, "orphan").await;
    let live = tenant_with_a_user(&db, org, "live").await;
    let entry = |tenant_id: Uuid, action: &str, metadata: Option<serde_json::Value>| {
        let audit = &audit;
        let action = action.to_owned();
        async move {
            audit
                .append(CreateAuditLogEntry {
                    tenant_id,
                    actor_id: Uuid::nil(),
                    actor_type: ActorType::System,
                    action,
                    resource_id: None,
                    outcome: AuditOutcome::Success,
                    ip_address: None,
                    metadata,
                })
                .await
                .unwrap()
        }
    };
    // The tombstoned tenant's trail: one row the export holds, then the
    // export, then one row it does not hold — its receipt, which the deletion
    // record names and whose timestamp caps the bound (R101W3-03, #637).
    entry(tombstoned, "users.updated", None).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let exported_through = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let late = entry(
        tombstoned,
        axiam_api_rest::handlers::tenants::AUDIT_EXPORT_ACTION,
        Some(serde_json::json!({ "exported_through": exported_through })),
    )
    .await;
    tenants.delete(tombstoned).await.unwrap();
    audit
        .append(CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::User,
            action: axiam_api_rest::handlers::tenants::TENANT_DELETED_ACTION.into(),
            resource_id: Some(tombstoned),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "audit_export_receipt_id": late.id,
                "audit_exported_through": exported_through,
            })),
        })
        .await
        .unwrap();
    db.query("DELETE type::record('tenant', $id)")
        .bind(("id", orphan.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    // A tick that does not look for orphans purges the tombstoned tenant only.
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, false, &work)
            .await
            .unwrap(),
        1
    );
    assert_eq!(users_in(&db, tombstoned).await, 0);
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(users_in(&db, orphan).await, 1);

    // The tick that looks finds the orphan.
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, true, &work)
            .await
            .unwrap(),
        1
    );
    assert_eq!(users_in(&db, orphan).await, 0);
    // Nothing is left to do, and the live tenant was never touched.
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, true, &work)
            .await
            .unwrap(),
        0
    );
    assert_eq!(users_in(&db, live).await, 1);
    assert!(tenants.get_by_id(live).await.is_ok());

    let records = purged_records(&db).await;
    let of = |id: Uuid| records.iter().find(|e| e.resource_id == Some(id));
    let purged = &of(tombstoned).unwrap().metadata;
    assert_eq!(purged["orphan"], false);
    assert_eq!(
        purged["audit_exported_through"],
        serde_json::json!(exported_through)
    );
    assert_eq!(purged["audit_rows_deleted"], 1);
    assert_eq!(purged["audit_rows_kept"], 1);
    assert_eq!(of(orphan).unwrap().metadata["orphan"], true);
    assert_eq!(
        of(orphan).unwrap().metadata["audit_exported_through"],
        serde_json::Value::Null
    );
    assert!(of(live).is_none());

    // The row written after the export survived under the tenant id, and the
    // audit retention sweep (T-119) removes it once it is past the window.
    let kept = audit.get_by_ids(tombstoned, &[late.id]).await.unwrap();
    assert_eq!(kept.len(), 1, "the row after the export survives the purge");
    db.query("UPDATE audit_log SET timestamp = time::now() - 400d WHERE tenant_id = $tenant")
        .bind(("tenant", tombstoned.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    audit
        .prune_older_than(Utc::now() - chrono::Duration::days(365))
        .await
        .unwrap();
    assert!(
        audit
            .get_by_ids(tombstoned, &[late.id])
            .await
            .unwrap()
            .is_empty()
    );
}

/// #610: the cleanup job runs on every replica. Two replicas' sweeps over one
/// store, run at once, purge a tombstoned tenant once between them: one
/// `tenants.purged` record, and both sweeps `Ok` — `CleanupTask::record` marks
/// the job failed only on `Err`, so neither replica reports it failed. A
/// replica holding a live claim keeps the others off the tenant; one that died
/// holding it does so for the lease only.
#[tokio::test]
async fn two_replicas_sweeping_at_once_purge_a_tenant_once_and_neither_fails() {
    let db = setup_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "purge-race".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    // Two replicas: each its own repositories over the one datastore.
    let (tenants_a, audit_a) = (
        Arc::new(SurrealTenantRepository::new(db.clone())),
        Arc::new(SurrealAuditLogRepository::new(db.clone())),
    );
    let (tenants_b, audit_b) = (
        Arc::new(SurrealTenantRepository::new(db.clone())),
        Arc::new(SurrealAuditLogRepository::new(db.clone())),
    );
    let (work, work_b) = (never_stopping(), never_stopping());
    let records_of = |records: &[AuditLogEntry], id: Uuid| {
        records.iter().filter(|e| e.resource_id == Some(id)).count()
    };

    let doomed = tenant_with_a_user(&db, org, "doomed").await;
    tenants_a.delete(doomed).await.unwrap();
    let (a, b) = tokio::join!(
        sweep_tenant_purge(&tenants_a, &audit_a, false, &work),
        sweep_tenant_purge(&tenants_b, &audit_b, false, &work_b)
    );
    let (a, b) = (a.expect("replica A's sweep"), b.expect("replica B's sweep"));
    assert_eq!(a + b, 1, "one replica purged the tenant");
    assert_eq!(users_in(&db, doomed).await, 0);
    assert!(tenants_a.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(
        records_of(&purged_records(&db).await, doomed),
        1,
        "one tenants.purged record"
    );

    // Replica B holds a live claim on another tenant: A's sweep leaves it,
    // and is still `Ok`.
    let lease = chrono::TimeDelta::from_std(axiam_server::cleanup::TENANT_PURGE_LEASE).unwrap();
    let held = tenant_with_a_user(&db, org, "held").await;
    tenants_a.delete(held).await.unwrap();
    assert!(
        tenants_b
            .claim_purge(held, Utc::now(), lease)
            .await
            .unwrap()
    );
    assert_eq!(
        sweep_tenant_purge(&tenants_a, &audit_a, false, &work)
            .await
            .unwrap(),
        0
    );
    assert_eq!(users_in(&db, held).await, 1);

    // B died holding it: once the lease has run out (the claim is dated back
    // past it), A takes the purge over.
    let crashed_at = Utc::now() - lease - chrono::TimeDelta::minutes(1);
    db.query("UPDATE type::record('tenant', $id) SET purge_claimed_at = $at")
        .bind(("id", held.to_string()))
        .bind(("at", crashed_at))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        sweep_tenant_purge(&tenants_a, &audit_a, false, &work)
            .await
            .unwrap(),
        1
    );
    assert_eq!(users_in(&db, held).await, 0);
    assert_eq!(records_of(&purged_records(&db).await, held), 1);
}

/// R101W1-09 (a): every replica also scans for orphaned tenant ids. Two
/// replicas' sweeps over one store, both looking for orphans at once, purge an
/// orphaned id once between them: one `tenants.purged {orphan: true}` record,
/// and both sweeps `Ok`. A replica whose scan predates the other's finished
/// purge finds nothing left and records nothing. And a claim left by a replica
/// that died mid-purge holds the id for the lease, then the tombstoned-tenant
/// sweep takes it over and records it — once, and as the orphan it is.
#[tokio::test]
async fn two_replicas_whose_orphan_scans_coincide_record_its_purge_once() {
    let db = setup_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "orphan-race".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let (tenants_a, audit_a) = (
        Arc::new(SurrealTenantRepository::new(db.clone())),
        Arc::new(SurrealAuditLogRepository::new(db.clone())),
    );
    let (tenants_b, audit_b) = (
        Arc::new(SurrealTenantRepository::new(db.clone())),
        Arc::new(SurrealAuditLogRepository::new(db.clone())),
    );
    let (work, work_b) = (never_stopping(), never_stopping());
    let records_of = |records: &[AuditLogEntry], id: Uuid| {
        records
            .iter()
            .filter(|e| e.resource_id == Some(id))
            .map(|e| e.metadata.clone())
            .collect::<Vec<_>>()
    };
    // What a deletion made before the tombstone left behind.
    let orphaned = |slug: &'static str| {
        let db = db.clone();
        async move {
            let id = tenant_with_a_user(&db, org, slug).await;
            db.query("DELETE type::record('tenant', $id)")
                .bind(("id", id.to_string()))
                .await
                .unwrap()
                .check()
                .unwrap();
            id
        }
    };

    // Both replicas' scans find the orphan at once: one purge, one record.
    let orphan = orphaned("orphan").await;
    let (a, b) = tokio::join!(
        sweep_tenant_purge(&tenants_a, &audit_a, true, &work),
        sweep_tenant_purge(&tenants_b, &audit_b, true, &work_b)
    );
    let (a, b) = (a.expect("replica A's sweep"), b.expect("replica B's sweep"));
    assert_eq!(a + b, 1, "one replica purged the orphan");
    assert_eq!(users_in(&db, orphan).await, 0);
    let records = records_of(&purged_records(&db).await, orphan);
    assert_eq!(records.len(), 1, "one tenants.purged record");
    assert_eq!(records[0]["orphan"], true);
    assert!(
        tenants_a.list_tombstoned().await.unwrap().is_empty(),
        "the claim marker went with the purge"
    );
    assert!(tenants_a.orphaned_tenant_ids().await.unwrap().is_empty());

    // Replica B scanned before A purged: by the time B gets to the id there is
    // nothing left, and B records nothing.
    let stale = orphaned("stale").await;
    let scanned = tenants_b.orphaned_tenant_ids().await.unwrap();
    assert_eq!(scanned, vec![stale]);
    assert_eq!(
        sweep_tenant_purge(&tenants_a, &audit_a, true, &work)
            .await
            .unwrap(),
        1
    );
    for id in scanned {
        assert!(
            tenants_b.purge_orphan(id).await.unwrap().is_none(),
            "a stale scan purges and records nothing"
        );
    }
    assert_eq!(records_of(&purged_records(&db).await, stale).len(), 1);
    assert!(
        tenants_a.list_tombstoned().await.unwrap().is_empty(),
        "the stale claim's marker is dropped"
    );

    // B claims an orphan and dies before purging it. During the lease the id
    // is neither an orphan to A's scan nor a tombstone A may claim.
    let held = orphaned("held").await;
    assert!(
        tenants_b
            .claim_orphan_purge(held, Utc::now())
            .await
            .unwrap()
    );
    assert_eq!(
        sweep_tenant_purge(&tenants_a, &audit_a, true, &work)
            .await
            .unwrap(),
        0
    );
    assert_eq!(users_in(&db, held).await, 1);
    // Once the lease has run out (the claim is dated back past it), A's
    // tombstoned-tenant pass takes the marker over and purges the id as an
    // orphan: its audit trail kept, and recorded once.
    let lease = chrono::TimeDelta::from_std(axiam_server::cleanup::TENANT_PURGE_LEASE).unwrap();
    db.query("UPDATE type::record('tenant', $id) SET purge_claimed_at = $at")
        .bind(("id", held.to_string()))
        .bind(("at", Utc::now() - lease - chrono::TimeDelta::minutes(1)))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        sweep_tenant_purge(&tenants_a, &audit_a, false, &work)
            .await
            .unwrap(),
        1
    );
    assert_eq!(users_in(&db, held).await, 0);
    let records = records_of(&purged_records(&db).await, held);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["orphan"], true);
    assert_eq!(
        records[0]["audit_exported_through"],
        serde_json::Value::Null
    );
    assert!(tenants_a.list_tombstoned().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// #533 — the Art. 17 purge revokes the erased account's certificates
// ---------------------------------------------------------------------------

/// The purge's step (b4), then the erasure pipeline, in the purge's order: the
/// account's `User` certificates are revoked — by the binding, and for a row
/// without one by the convention on the account's username and email — and
/// another account's certificate with the same common name is not. Revoked,
/// not deleted: the rows stay, dated, on their issuer's list. And why the step
/// runs before `anonymize_user`: once the names are overwritten the convention
/// has nothing left to match.
#[tokio::test]
async fn the_purge_revokes_the_erased_accounts_certificates_before_it_anonymizes() {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };
    use axiam_core::repository::CertificateRepository;
    use axiam_db::SurrealCertificateRepository;
    use axiam_server::cleanup::revoke_erased_users_certificates;

    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());
    let certs = SurrealCertificateRepository::new(db.clone());

    let erased = user_repo
        .create(CreateUser {
            tenant_id,
            username: "carol".into(),
            email: "carol@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create user");
    let other = Uuid::new_v4();
    user_repo
        .mark_deletion_pending(
            tenant_id,
            erased.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");

    let issuer = Uuid::new_v4();
    let leaf = |fingerprint: &str, subject: &str, user_id: Option<Uuid>| StoreCertificate {
        tenant_id,
        issuer_ca_id: issuer,
        subject: subject.into(),
        public_cert_pem: "not-a-parsed-certificate".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - chrono::Duration::minutes(1),
        not_after: Utc::now() + chrono::Duration::days(30),
        metadata: serde_json::json!({}),
        user_id,
    };
    let bound = certs
        .create(leaf("fp-bound", "carol-phone", Some(erased.id)))
        .await
        .unwrap();
    let legacy = certs
        .create(leaf("fp-legacy", "Carol@Example.com", None))
        .await
        .unwrap();
    let someone_elses = certs
        .create(leaf("fp-other", "carol", Some(other)))
        .await
        .unwrap();

    // The sweep hands the purge the account as `find_due_for_purge` read it.
    let due = user_repo
        .find_due_for_purge(Utc::now())
        .await
        .expect("find due");
    let account = due
        .iter()
        .find(|u| u.id == erased.id)
        .expect("the account is due");
    let revoked = revoke_erased_users_certificates(&certs, account)
        .await
        .expect("step (b4)");
    assert_eq!(revoked, 2, "the bound and the legacy certificate");

    run_erasure_pipeline(
        &audit_repo,
        &erasure_proof_repo,
        &user_repo,
        tenant_id,
        erased.id,
        "DELETED_USER_533",
        "hashed_533",
    )
    .await
    .expect("erasure pipeline");

    for (i, (cert, expected)) in [
        (&bound, CertificateStatus::Revoked),
        (&legacy, CertificateStatus::Revoked),
        (&someone_elses, CertificateStatus::Active),
    ]
    .into_iter()
    .enumerate()
    {
        // Read back at all: the erasure kept the row.
        let read = certs.get_by_id(tenant_id, cert.id).await.unwrap();
        assert_eq!(read.status, expected, "certificate #{i}");
    }
    let on_the_list = certs
        .list_revoked_by_issuer(issuer, Utc::now())
        .await
        .unwrap();
    assert_eq!(on_the_list.len(), 2);
    assert!(on_the_list.iter().all(|e| e.revoked_at.is_some()));

    // After `anonymize_user` the account's names are gone, so a legacy
    // certificate that carries the old name is no longer the account's by any
    // rule the repository can apply — the reason (b4) runs first.
    let late = certs.create(leaf("fp-late", "carol", None)).await.unwrap();
    let anonymized = user_repo.get_by_id(tenant_id, erased.id).await.unwrap();
    assert_ne!(anonymized.username, "carol");
    assert_eq!(
        revoke_erased_users_certificates(&certs, &anonymized)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        certs.get_by_id(tenant_id, late.id).await.unwrap().status,
        CertificateStatus::Active
    );
}

/// R101W1-01 — the Art. 17 purge is started by the data subject, so an account
/// named after an existing certificate's CN must not be able to revoke it by
/// erasing itself: `Alice`, created after `alice`'s unbound CN-`alice`
/// certificate, is erased and the certificate stays active.
#[tokio::test]
async fn erasing_an_account_leaves_an_older_namesakes_certificate_alone() {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };
    use axiam_core::repository::CertificateRepository;
    use axiam_db::SurrealCertificateRepository;
    use axiam_server::cleanup::revoke_erased_users_certificates;

    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let certs = SurrealCertificateRepository::new(db.clone());

    user_repo
        .create(CreateUser {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("create alice");
    let alices = certs
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: "alice".into(),
            public_cert_pem: "not-a-parsed-certificate".into(),
            fingerprint: "fp-alice".into(),
            cert_type: CertificateType::User,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - chrono::Duration::minutes(1),
            not_after: Utc::now() + chrono::Duration::days(30),
            metadata: serde_json::json!({}),
            user_id: None,
        })
        .await
        .unwrap();
    let erased = user_repo
        .create(CreateUser {
            tenant_id,
            username: "Alice".into(),
            email: "ALICE@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .expect("case variants coexist");
    user_repo
        .mark_deletion_pending(
            tenant_id,
            erased.id,
            Utc::now() - chrono::Duration::seconds(1),
        )
        .await
        .expect("mark deletion pending");

    let due = user_repo
        .find_due_for_purge(Utc::now())
        .await
        .expect("find due");
    let account = due
        .iter()
        .find(|u| u.id == erased.id)
        .expect("the account is due");
    assert_eq!(
        revoke_erased_users_certificates(&certs, account)
            .await
            .expect("step (b4)"),
        0
    );
    assert_eq!(
        certs.get_by_id(tenant_id, alices.id).await.unwrap().status,
        CertificateStatus::Active,
        "alice's certificate is not Alice's"
    );
}

// ---------------------------------------------------------------------------
// R101W1-05 (#618) — the certificate retention sweep
// ---------------------------------------------------------------------------

use axiam_core::models::certificate::{
    CertificateType as RetentionType, KeyAlgorithm as RetentionAlgorithm,
    StoreCertificate as RetentionLeaf,
};
use axiam_core::repository::CertificateRepository as _;
use axiam_db::SurrealCertificateRepository;
use axiam_server::cleanup::{CERTIFICATE_RETENTION_BATCH, sweep_certificate_retention};

/// A `User` certificate of `tenant` under `issuer`, whose `notAfter` is `days`
/// days ago (negative: ahead), revoked or not.
async fn leaf_expired_days_ago(
    certs: &SurrealCertificateRepository<surrealdb::engine::local::Db>,
    tenant: Uuid,
    issuer: Uuid,
    fingerprint: &str,
    days: i64,
    revoked: bool,
) -> Uuid {
    let cert = certs
        .create(RetentionLeaf {
            tenant_id: tenant,
            issuer_ca_id: issuer,
            subject: format!("holder-{fingerprint}"),
            public_cert_pem: "not-a-parsed-certificate".into(),
            fingerprint: fingerprint.into(),
            cert_type: RetentionType::User,
            key_algorithm: RetentionAlgorithm::Ed25519,
            not_before: Utc::now() - chrono::Duration::days(days + 365),
            not_after: Utc::now() - chrono::Duration::days(days),
            metadata: serde_json::json!({ "note": "a person" }),
            user_id: Some(Uuid::new_v4()),
        })
        .await
        .unwrap();
    if revoked {
        certs.revoke(tenant, cert.id).await.unwrap();
    }
    cert.id
}

/// The sweep deletes a certificate row more than eight days past `notAfter` —
/// revoked, or expired without ever being revoked — and its binding edge, and
/// leaves one seven days past, one still valid, and one of a tenant that is
/// being deleted (the tenant purge's). The issuer's revocation list is the
/// same before and after: it stopped naming the deleted row at seven days at
/// the latest. It touches no audit row, and a second run finds nothing.
#[tokio::test]
async fn the_certificate_sweep_deletes_rows_past_the_grace_and_the_crl_does_not_change() {
    let db = setup_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "cert-retention".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenants = SurrealTenantRepository::new(db.clone());
    let live = tenant_with_a_user(&db, org, "cert-live").await;
    let dying = tenant_with_a_user(&db, org, "cert-dying").await;
    let certs = SurrealCertificateRepository::new(db.clone());
    let issuer = Uuid::new_v4();

    let nine = leaf_expired_days_ago(&certs, live, issuer, "fp-nine", 9, true).await;
    let nine_unrevoked = leaf_expired_days_ago(&certs, live, issuer, "fp-nine-u", 9, false).await;
    let seven = leaf_expired_days_ago(&certs, live, issuer, "fp-seven", 7, true).await;
    let ahead = leaf_expired_days_ago(&certs, live, issuer, "fp-ahead", -30, true).await;
    let dying_nine = leaf_expired_days_ago(&certs, dying, issuer, "fp-dying", 9, true).await;
    tenants.delete(dying).await.unwrap();

    // The nine-day row is bound to a service account; its edge must go too.
    db.query(format!(
        "RELATE certificate:`{nine}`->cert_bound_to->service_account:`{}`",
        Uuid::new_v4()
    ))
    .await
    .unwrap()
    .check()
    .unwrap();
    let edges = |db: &Surreal<surrealdb::engine::local::Db>| {
        let db = db.clone();
        async move {
            #[derive(SurrealValue)]
            struct C {
                total: i64,
            }
            let mut r = db
                .query("SELECT count() AS total FROM cert_bound_to GROUP ALL")
                .await
                .unwrap();
            let rows: Vec<C> = r.take(0).unwrap();
            rows.first().map_or(0, |c| c.total)
        }
    };
    assert_eq!(edges(&db).await, 1);

    // The widest window a list can keep an expired entry for (seven days), and
    // a minute more: the seven-day row is on it, the nine-day one never is.
    let widest = Utc::now() - chrono::Duration::days(7) - chrono::Duration::minutes(1);
    let list = || async {
        let mut fingerprints: Vec<String> = certs
            .list_revoked_by_issuer(issuer, widest)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.fingerprint)
            .collect();
        fingerprints.sort();
        fingerprints
    };
    let before = list().await;
    assert_eq!(
        before,
        vec!["fp-ahead", "fp-seven"],
        "the nine-day rows are not on the list: it dropped them already"
    );
    let audit_before = SurrealAuditLogRepository::new(db.clone())
        .list_system(AuditLogFilter::default(), Pagination::default())
        .await
        .unwrap()
        .total;

    let (_stop, shutdown) = watch::channel(false);
    let removed = sweep_certificate_retention(&certs, &shutdown)
        .await
        .unwrap();
    assert_eq!(removed, 2, "the revoked and the unrevoked nine-day rows");

    for (i, gone) in [nine, nine_unrevoked].into_iter().enumerate() {
        assert!(
            certs.get_by_id(live, gone).await.is_err(),
            "swept row #{i} is gone"
        );
    }
    for (i, kept) in [(live, seven), (live, ahead), (dying, dying_nine)]
        .into_iter()
        .enumerate()
    {
        assert!(
            certs.get_by_id(kept.0, kept.1).await.is_ok(),
            "kept row #{i} survives"
        );
    }
    assert_eq!(edges(&db).await, 0, "the binding went with its row");
    assert_eq!(list().await, before, "the list is unchanged");
    assert_eq!(
        SurrealAuditLogRepository::new(db.clone())
            .list_system(AuditLogFilter::default(), Pagination::default())
            .await
            .unwrap()
            .total,
        audit_before,
        "no audit row is touched"
    );
    assert_eq!(
        sweep_certificate_retention(&certs, &shutdown)
            .await
            .unwrap(),
        0,
        "a second run finds nothing"
    );
}

/// Bounded: a batch removes at most its limit, the sweep takes batches until
/// one comes back short, and two replicas sweeping at once between them remove
/// each row exactly once, neither failing.
#[tokio::test]
async fn the_certificate_sweep_is_bounded_and_two_replicas_remove_each_row_once() {
    let db = setup_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "cert-retention-2".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenant = tenant_with_a_user(&db, org, "cert-batches").await;
    let certs = SurrealCertificateRepository::new(db.clone());
    let issuer = Uuid::new_v4();
    for n in 0..7 {
        leaf_expired_days_ago(
            &certs,
            tenant,
            issuer,
            &format!("fp-{n}"),
            10 + n,
            n % 2 == 0,
        )
        .await;
    }

    assert_eq!(certs.delete_past_retention(3).await.unwrap(), 3);
    assert_eq!(certs.delete_past_retention(3).await.unwrap(), 3);
    assert_eq!(certs.delete_past_retention(3).await.unwrap(), 1);
    assert_eq!(certs.delete_past_retention(3).await.unwrap(), 0);

    for n in 0..40 {
        leaf_expired_days_ago(&certs, tenant, issuer, &format!("fq-{n}"), 10, true).await;
    }
    let (_stop, shutdown) = watch::channel(false);
    let a = SurrealCertificateRepository::new(db.clone());
    let b = SurrealCertificateRepository::new(db.clone());
    let (ra, rb) = tokio::join!(
        sweep_certificate_retention(&a, &shutdown),
        sweep_certificate_retention(&b, &shutdown)
    );
    assert_eq!(ra.unwrap() + rb.unwrap(), 40);
    assert!(u32::try_from(40).unwrap() < CERTIFICATE_RETENTION_BATCH);

    // A stop request ends the sweep before its first batch.
    leaf_expired_days_ago(&certs, tenant, issuer, "fp-stop", 10, true).await;
    let (stop, stopped) = watch::channel(false);
    stop.send(true).unwrap();
    assert_eq!(
        sweep_certificate_retention(&certs, &stopped).await.unwrap(),
        0
    );
    assert_eq!(
        sweep_certificate_retention(&certs, &shutdown)
            .await
            .unwrap(),
        1
    );
}

// ---------------------------------------------------------------------------
// rate_limit_bucket sweep (#638)
// ---------------------------------------------------------------------------

mod rate_limit_bucket {
    use super::*;
    use axiam_db::SurrealRateLimitBucketRepository;
    use axiam_server::cleanup::{
        RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS, RATE_LIMIT_BUCKET_RETENTION,
        RATE_LIMIT_BUCKET_SWEEP_BATCH, sweep_rate_limit_buckets,
    };

    /// Set a bucket's `updated_at` to `age` before `now`.
    async fn age(db: &Surreal<surrealdb::engine::local::Db>, key: &str, age: Duration) {
        let at = Utc::now() - chrono::Duration::from_std(age).unwrap();
        db.query("UPDATE type::record('rate_limit_bucket', $key) SET updated_at = $at")
            .bind(("key", key.to_owned()))
            .bind(("at", at))
            .await
            .unwrap()
            .check()
            .unwrap();
    }

    async fn keys(db: &Surreal<surrealdb::engine::local::Db>) -> Vec<String> {
        let mut r = db
            .query("SELECT VALUE meta::id(id) FROM rate_limit_bucket ORDER BY id")
            .await
            .unwrap();
        r.take(0).unwrap()
    }

    /// The longest window is the hint cap's, and the retention is twice it
    /// plus the margin: longer than two of every window a writer counts in.
    #[test]
    fn the_retention_is_derived_from_the_windows_in_use() {
        assert_eq!(
            RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS,
            axiam_oauth2::ciba::HINT_CAP_WINDOW_SECS
        );
        for window in [
            axiam_oauth2::ciba::HINT_CAP_WINDOW_SECS,
            axiam_db::rate_limit_counter::DEFAULT_WINDOW_SECS,
            axiam_api_grpc::middleware::rate_limit::WINDOW_SECS as u64,
        ] {
            assert!(window <= RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS);
            assert!(RATE_LIMIT_BUCKET_RETENTION.as_secs() > 2 * window);
        }
        assert_eq!(RATE_LIMIT_BUCKET_RETENTION, Duration::from_secs(21 * 60));
    }

    /// The sweep removes the rows nobody can read and keeps every row a
    /// limiter still can: the hint cap's previous window (the oldest row it
    /// reads, up to two windows old), a counter's bucket, a fresh one.
    #[tokio::test]
    async fn the_sweep_removes_stale_rows_and_keeps_current_ones() {
        let db = setup_db().await;
        let repo = SurrealRateLimitBucketRepository::new(db.clone());
        let w = Utc::now();
        let hint_window = Duration::from_secs(axiam_oauth2::ciba::HINT_CAP_WINDOW_SECS);
        let retention = RATE_LIMIT_BUCKET_RETENTION;
        let second = Duration::from_secs(1);
        for k in [
            "ciba_hint_cap:t:dead:0",
            "login:203.0.113.1",
            "ciba_hint_cap:t:previous:1",
            "ciba_hint_cap:t:edge:0",
            "authz_check:203.0.113.2",
            "ciba_hint_cap:t:current:0",
        ] {
            repo.increment_by(k, w, 1).await.unwrap();
        }
        age(&db, "ciba_hint_cap:t:dead:0", retention + second).await;
        age(&db, "login:203.0.113.1", retention + hint_window).await;
        // Written in the window before this one: read as `previous` right now.
        age(&db, "ciba_hint_cap:t:previous:1", hint_window).await;
        // Two windows old: no longer read, but inside the margin.
        age(&db, "ciba_hint_cap:t:edge:0", 2 * hint_window + second).await;
        age(&db, "authz_check:203.0.113.2", retention - 5 * second).await;

        assert_eq!(sweep_rate_limit_buckets(&repo).await.unwrap(), 2);
        assert_eq!(
            keys(&db).await,
            [
                "authz_check:203.0.113.2",
                "ciba_hint_cap:t:current:0",
                "ciba_hint_cap:t:edge:0",
                "ciba_hint_cap:t:previous:1",
            ]
        );
        assert_eq!(sweep_rate_limit_buckets(&repo).await.unwrap(), 0);
        // A kept bucket still counts where it was.
        assert_eq!(
            repo.peek_count("ciba_hint_cap:t:current:0", w)
                .await
                .unwrap(),
            1
        );
    }

    /// #676 — the cutoff is the datastore's. A hint-cap row from the previous
    /// window, aged 20 minutes (inside the 21-minute retention), is kept. The
    /// sweep takes no application clock; before the fix it took one, and a
    /// sweeper five minutes ahead of the datastore computed a 16-minute cutoff
    /// and removed this row while the cap still reads it.
    #[tokio::test]
    async fn the_sweep_ignores_the_application_clock() {
        let db = setup_db().await;
        let repo = SurrealRateLimitBucketRepository::new(db.clone());
        repo.increment_by("ciba_hint_cap:t:previous:1", Utc::now(), 1)
            .await
            .unwrap();
        age(
            &db,
            "ciba_hint_cap:t:previous:1",
            Duration::from_secs(20 * 60),
        )
        .await;
        assert_eq!(sweep_rate_limit_buckets(&repo).await.unwrap(), 0);
        assert_eq!(keys(&db).await, ["ciba_hint_cap:t:previous:1"]);
    }

    /// More stale rows than a batch are all removed, by two replicas sweeping
    /// at once: neither fails, every row goes exactly once and the fresh one
    /// stays.
    #[tokio::test]
    async fn two_replicas_sweeping_at_once_remove_each_row_once() {
        let db = setup_db().await;
        let repo = SurrealRateLimitBucketRepository::new(db.clone());
        let stale = 2 * RATE_LIMIT_BUCKET_SWEEP_BATCH as usize + 37;
        db.query(
            "FOR $i IN 0..$n { CREATE type::record('rate_limit_bucket', string::concat('old:', $i)) \
             SET count = 1, window_start = d'2000-01-01T00:00:00Z', \
                 updated_at = d'2000-01-01T00:00:00Z'; }",
        )
        .bind(("n", stale as i64))
        .await
        .unwrap()
        .check()
        .unwrap();
        repo.increment_by("fresh", Utc::now(), 1).await.unwrap();

        let (a, b) = tokio::join!(
            sweep_rate_limit_buckets(&repo),
            sweep_rate_limit_buckets(&repo)
        );
        // A sweeper that loses a contended commit leaves the rows to the
        // winner or to the next pass; no row is removed twice, none is missed.
        let rest = sweep_rate_limit_buckets(&repo).await.unwrap();
        assert_eq!(a.unwrap() + b.unwrap() + rest, stale as u64);
        assert_eq!(keys(&db).await, ["fresh"]);
    }
}

// ---------------------------------------------------------------------------
// #655, #624 — a stop does not cut a tenant purge or an erasure from its record
// ---------------------------------------------------------------------------

use axiam_core::models::gdpr::CreateAccountDeletion;
use axiam_core::repository::AccountDeletionRepository;
use axiam_db::SurrealAccountDeletionRepository;
use axiam_server::cleanup::{
    ErasureSubject, TENANT_PURGE_LEASE, UnitStep, UnitStepForTests, erase_and_record,
};
use tokio::sync::Notify;

/// A unit step that, at `at`, says so on `entered` and then holds until `go`
/// is notified — forever, when it never is.
fn hold_at(at: UnitStep, entered: watch::Sender<bool>, go: Arc<Notify>) -> UnitStepForTests {
    Arc::new(move |step| {
        let (entered, go) = (entered.clone(), Arc::clone(&go));
        Box::pin(async move {
            if step == at {
                entered.send_replace(true);
                go.notified().await;
            }
        })
    })
}

/// What the composition root's `join_cleanup` does once the cleanup task has
/// been told to stop: wait for the task until the bound, abort it past that,
/// then wait for the unit it left in flight until the same deadline.
async fn join_like_the_teardown(
    mut task: tokio::task::JoinHandle<()>,
    work: &AuditedWork,
    bound: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + bound;
    if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
    work.join(deadline).await
}

async fn wait_until_entered(entered: &mut watch::Receiver<bool>) {
    tokio::time::timeout(Duration::from_secs(10), entered.wait_for(|on| *on))
        .await
        .expect("the unit reaches its step")
        .expect("the step's sender lives as long as the unit");
}

async fn purge_records_of(db: &Surreal<surrealdb::engine::local::Db>, tenant: Uuid) -> usize {
    purged_records(db)
        .await
        .iter()
        .filter(|e| e.resource_id == Some(tenant))
        .count()
}

async fn new_org(db: &Surreal<surrealdb::engine::local::Db>, slug: &str) -> Uuid {
    SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// #655: a stop that finds a tick inside a tenant purge — the tenant's rows
/// removed, its tenant row not yet — no longer holds the tenant for the claim's
/// one-hour lease. While the purge runs its claim keeps every other replica off
/// the tenant; at the stop the purge gives itself up before its point of no
/// return and releases the claim, so the next start purges the tenant at once
/// and records it exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_purge_held_across_a_stop_is_purged_at_once_by_the_next_start_and_recorded_once() {
    let db = setup_db().await;
    let org = new_org(&db, "purge-at-stop").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let doomed = tenant_with_a_user(&db, org, "held-at-stop").await;
    tenants.delete(doomed).await.unwrap();

    // The first start: its tick holds inside the purge, which is never let go.
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::TenantRowsPurged(doomed),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = {
        let (tenants, audit, work) = (Arc::clone(&tenants), Arc::clone(&audit), work.clone());
        tokio::spawn(async move {
            sweep_tenant_purge(&tenants, &audit, false, &work)
                .await
                .expect("a stop is not a failure of the sweep");
        })
    };
    wait_until_entered(&mut entered).await;
    assert_eq!(users_in(&db, doomed).await, 0, "the purge is under way");
    let lease = chrono::TimeDelta::from_std(TENANT_PURGE_LEASE).unwrap();
    assert!(
        !tenants
            .claim_purge(doomed, Utc::now(), lease)
            .await
            .unwrap(),
        "while the purge runs, its claim keeps another replica off the tenant"
    );

    // The stop.
    stop_tx.send_replace(true);
    assert!(
        join_like_the_teardown(tick, &work, Duration::from_secs(5)).await,
        "nothing was left to cut: the purge gave itself up at the stop"
    );
    assert!(
        tenants.list_tombstoned().await.unwrap().contains(&doomed),
        "the tenant row is still there, tombstoned, for the next start"
    );
    assert_eq!(purge_records_of(&db, doomed).await, 0);

    // The next start purges it at once, without waiting out the lease.
    let next_start = never_stopping();
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, false, &next_start)
            .await
            .unwrap(),
        1
    );
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(purge_records_of(&db, doomed).await, 1);
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, false, &next_start)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        purge_records_of(&db, doomed).await,
        1,
        "tenants.purged exists exactly once"
    );
}

/// #655: the claim is released from a drop guard on any exit but a finished
/// purge — here a purge that panics, and one aborted where it is (the
/// teardown's cut at its bound) — so neither holds the tenant for the lease:
/// the next sweep purges it, and records it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_purge_that_panics_or_is_cut_releases_its_claim() {
    let db = setup_db().await;
    let org = new_org(&db, "purge-guard").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    // The guard's release is spawned when the unit is dropped: give it a
    // moment, without ever waiting anything like the lease.
    let purged_soon = |tenant: Uuid| {
        let (tenants, audit) = (Arc::clone(&tenants), Arc::clone(&audit));
        async move {
            for _ in 0..50 {
                if sweep_tenant_purge(&tenants, &audit, false, &never_stopping())
                    .await
                    .unwrap()
                    == 1
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("tenant {tenant} is still held by the claim of a purge that did not finish");
        }
    };

    // A purge that panics: the sweep fails, the claim is released.
    let panicked = tenant_with_a_user(&db, org, "panicked").await;
    tenants.delete(panicked).await.unwrap();
    let panicking: UnitStepForTests = Arc::new(|step| {
        Box::pin(async move {
            if matches!(step, UnitStep::TenantRowsPurged(_)) {
                panic!("a tenant purge that panics");
            }
        })
    });
    let work = never_stopping().with_step_for_tests(Some(panicking));
    assert!(
        sweep_tenant_purge(&tenants, &audit, false, &work)
            .await
            .is_err(),
        "a purge without an outcome fails the sweep"
    );
    purged_soon(panicked).await;
    assert_eq!(purge_records_of(&db, panicked).await, 1);

    // A purge aborted where it is, as the teardown's join does at its bound.
    let cut = tenant_with_a_user(&db, org, "cut").await;
    tenants.delete(cut).await.unwrap();
    let (_running, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::TenantRowsPurged(cut),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = {
        let (tenants, audit, work) = (Arc::clone(&tenants), Arc::clone(&audit), work.clone());
        tokio::spawn(async move { sweep_tenant_purge(&tenants, &audit, false, &work).await })
    };
    wait_until_entered(&mut entered).await;
    assert!(
        !work.join(tokio::time::Instant::now()).await,
        "the purge was cut"
    );
    assert!(
        tick.await.unwrap().is_err(),
        "a cut purge has no outcome, and the sweep says so"
    );
    purged_soon(cut).await;
    assert_eq!(purge_records_of(&db, cut).await, 1);
}

/// #687 (R110W4-01): the guard's release is a task spawned from `drop`, and
/// nothing waits for it. A unit cut by the teardown's `join` at its bound is the
/// one exit where the guard is the only release; the process exit that follows
/// drops the runtime, which cancels a release that has not landed, and the
/// tenant then waits out the claim's lease. The documented behaviour, pinned
/// here, is that outcome — not that the claim is always released.
///
/// A release that never answers is a release the runtime ends before it runs:
/// the unit's runtime polls one task per turn (`event_interval(1)`), so `join`
/// returns the turn after the unit is dropped, with the spawned release alive
/// and not yet polled, and the runtime is dropped right after. The datastore
/// lives on the test's own runtime and is only used by the unit's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_purge_cut_at_the_bound_keeps_its_claim_when_the_runtime_ends_right_after() {
    let db = setup_db().await;
    let org = new_org(&db, "purge-cut-at-exit").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let doomed = tenant_with_a_user(&db, org, "cut-at-exit").await;
    tenants.delete(doomed).await.unwrap();

    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::TenantRowsPurged(doomed),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let process = {
        let (tenants, audit, work) = (Arc::clone(&tenants), Arc::clone(&audit), work.clone());
        std::thread::spawn(move || {
            let mut entered = entered;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .event_interval(1)
                .build()
                .expect("the unit's runtime");
            let sweeping = work.clone();
            runtime.spawn(async move {
                let _ = sweep_tenant_purge(&tenants, &audit, false, &sweeping).await;
            });
            runtime.block_on(wait_until_entered(&mut entered));

            // The teardown's bound has run out on a unit that is still inside
            // its step (the stop is not set: with it set, the unit gives itself
            // up and awaits its release, which is the path that works).
            let _running = stop_tx;
            let cut = !runtime.block_on(work.join(tokio::time::Instant::now()));
            let release_pending = runtime.metrics().num_alive_tasks();
            // Process exit: `main` returns and the runtime is dropped.
            drop(runtime);
            (cut, release_pending)
        })
    };
    let (cut, pending) = tokio::task::block_in_place(|| process.join().expect("the unit's thread"));
    assert!(cut, "the unit was cut by join");
    assert!(
        pending > 0,
        "the guard's release was spawned and had not run when the runtime ended"
    );

    // The release never landed: the claim is still set, the tenant row is still
    // there, and nothing was recorded.
    let lease = chrono::TimeDelta::from_std(TENANT_PURGE_LEASE).unwrap();
    assert!(
        !tenants
            .claim_purge(doomed, Utc::now(), lease)
            .await
            .unwrap(),
        "the claim is still set after the runtime ended"
    );
    assert!(tenants.list_tombstoned().await.unwrap().contains(&doomed));
    assert_eq!(purge_records_of(&db, doomed).await, 0);
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, false, &never_stopping())
            .await
            .unwrap(),
        0,
        "the next start's sweep skips the tenant: the claim is younger than its lease"
    );

    // Only the lease frees it.
    assert!(
        tenants
            .claim_purge(
                doomed,
                Utc::now() + lease + chrono::TimeDelta::seconds(1),
                lease
            )
            .await
            .unwrap(),
        "once the lease has run out, the tenant can be claimed again"
    );
}

/// #714 (R110-04): an orphan purge holds its claim guard from the marker's
/// `CREATE`. A unit held right after its claim — where the read of the rows
/// left used to run with no guard — across a stop, and then aborted by the
/// teardown at its bound, releases the claim: the next start's
/// tombstoned-tenant sweep (no orphan scan) takes the marker over at once,
/// without waiting out the lease, purges the id as the orphan it is and
/// records it once. A scan that predates that purge then writes no marker and
/// records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphan_purge_cut_right_after_its_claim_is_taken_over_at_once_and_recorded_once() {
    let db = setup_db().await;
    let org = new_org(&db, "orphan-cut").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    // What a deletion made before the tombstone left behind.
    let orphan = tenant_with_a_user(&db, org, "cut-after-claim").await;
    db.query("DELETE type::record('tenant', $id)")
        .bind(("id", orphan.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(tenants.orphaned_tenant_ids().await.unwrap(), vec![orphan]);

    // The first start: its tick claims the orphan and holds there.
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::OrphanClaimed(orphan),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = {
        let (tenants, audit, work) = (Arc::clone(&tenants), Arc::clone(&audit), work.clone());
        tokio::spawn(async move {
            sweep_tenant_purge(&tenants, &audit, true, &work)
                .await
                .expect("a stop is not a failure of the sweep");
        })
    };
    wait_until_entered(&mut entered).await;
    assert_eq!(
        tenants.list_tombstoned().await.unwrap(),
        vec![orphan],
        "the claim marker stands"
    );
    let lease = chrono::TimeDelta::from_std(TENANT_PURGE_LEASE).unwrap();
    assert!(
        !tenants
            .claim_purge(orphan, Utc::now(), lease)
            .await
            .unwrap(),
        "while the unit holds it, the claim keeps another replica off the marker"
    );

    // The stop, and the teardown's cut at its bound.
    stop_tx.send_replace(true);
    assert!(
        !join_like_the_teardown(tick, &work, Duration::from_millis(200)).await,
        "the unit was cut where it was held"
    );
    assert_eq!(users_in(&db, orphan).await, 1, "nothing was purged yet");
    assert_eq!(purge_records_of(&db, orphan).await, 0);

    // The next start's sweep, without an orphan scan, takes the marker over at
    // once. The guard's release is spawned when the unit is dropped: give it a
    // moment, without ever waiting anything like the lease.
    let next_start = never_stopping();
    let mut purged = 0;
    for _ in 0..50 {
        purged = sweep_tenant_purge(&tenants, &audit, false, &next_start)
            .await
            .unwrap();
        if purged == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        purged, 1,
        "the marker is still held by the claim of a cut unit"
    );
    assert_eq!(users_in(&db, orphan).await, 0);
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    let records: Vec<_> = purged_records(&db)
        .await
        .into_iter()
        .filter(|e| e.resource_id == Some(orphan))
        .collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].metadata["orphan"], true);

    // A scan that predates that purge claims nothing: no marker, no record.
    assert!(
        !tenants
            .claim_orphan_purge(orphan, Utc::now())
            .await
            .unwrap()
    );
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(
        sweep_tenant_purge(&tenants, &audit, true, &next_start)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        purge_records_of(&db, orphan).await,
        1,
        "tenants.purged exists exactly once for the id"
    );
}

/// An account due for erasure, with its pending `account_deletion` row.
async fn erasure_due_with_its_request(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    name: &str,
) -> User {
    let user = user_due_for_erasure(db, tenant_id, name).await;
    SurrealAccountDeletionRepository::new(db.clone())
        .create(CreateAccountDeletion {
            tenant_id,
            user_id: user.id,
            cancel_token_hash: format!("{:064x}", 7),
            scheduled_purge_at: Utc::now() - chrono::Duration::seconds(1),
        })
        .await
        .expect("the deletion request");
    user
}

async fn pseudonymized_rows(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
) -> Vec<AuditLogEntry> {
    SurrealAuditLogRepository::new(db.clone())
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some("gdpr.user_pseudonymized".into()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
}

/// The cleanup task's tick running one erasure as its unit, held at
/// [`UnitStep::ErasureAnonymized`] until `go`.
fn erasure_tick(
    db: &Surreal<surrealdb::engine::local::Db>,
    user: &User,
    work: &AuditedWork,
) -> tokio::task::JoinHandle<()> {
    let (audit, proofs, users, deletions, certs) = (
        SurrealAuditLogRepository::new(db.clone()),
        SurrealErasureProofRepository::new(db.clone()),
        SurrealUserRepository::new(db.clone()),
        SurrealAccountDeletionRepository::new(db.clone()),
        SurrealCertificateRepository::new(db.clone()),
    );
    let (tenant_id, user_id, work) = (user.tenant_id, user.id, work.clone());
    tokio::spawn(async move {
        let unit_work = work.clone();
        let _ = work
            .run(async move {
                erase_and_record(
                    &audit,
                    &proofs,
                    &users,
                    &certs,
                    &deletions,
                    None,
                    ErasureSubject {
                        tenant_id,
                        user_id,
                        pseudonym: "DELETED_USER_held0000000001",
                        email_hash: "hashed_held_email",
                        certificates_revoked: 0,
                    },
                    &unit_work,
                )
                .await
            })
            .await;
    })
}

/// #624: a stop that finds an erasure between the anonymization — its point of
/// no return, after which no sweep selects the account again — and its audit
/// row no longer loses the row: the erasure runs as a task of its own, which
/// the cut of the cleanup task does not reach, and the teardown waits for it
/// within its bound. The `account_deletion` row is completed too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_held_between_the_anonymization_and_its_audit_row_across_a_stop_keeps_the_row() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "held_erasure").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let go = Arc::new(Notify::new());
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::ErasureAnonymized(user.id),
        entered_tx,
        Arc::clone(&go),
    )));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;
    let users = SurrealUserRepository::new(db.clone());
    assert_eq!(
        users.get_by_id(tenant_id, user.id).await.unwrap().email,
        "hashed_held_email",
        "the account is anonymized"
    );
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());

    // The stop, and the cut of the cleanup task itself — the abort the
    // teardown's bound used to cut the erasure with.
    stop_tx.send_replace(true);
    tick.abort();
    let _ = tick.await;

    // The erasure's last statements run inside the teardown's bound.
    go.notify_one();
    assert!(
        work.join(tokio::time::Instant::now() + Duration::from_secs(5))
            .await,
        "the erasure finished within the bound"
    );
    let rows = pseudonymized_rows(&db, tenant_id).await;
    assert_eq!(rows.len(), 1, "gdpr.user_pseudonymized is written, once");
    assert_eq!(rows[0].actor_id, user.id);
    assert_eq!(rows[0].metadata["pseudonym"], "DELETED_USER_held0000000001");
    assert!(
        SurrealAccountDeletionRepository::new(db.clone())
            .find_pending_by_user_id(tenant_id, user.id)
            .await
            .unwrap()
            .is_none(),
        "the account_deletion row is completed"
    );
}

/// The other side of the bound (#624, and the lease's): an erasure still held
/// when the teardown's deadline passes is aborted there, so the instance writes
/// nothing after its stop's budget — not even the audit row it was about to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_still_running_at_the_deadline_is_cut_and_writes_nothing_after_it() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "cut_erasure").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let go = Arc::new(Notify::new());
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::ErasureAnonymized(user.id),
        entered_tx,
        Arc::clone(&go),
    )));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;

    stop_tx.send_replace(true);
    assert!(
        !join_like_the_teardown(tick, &work, Duration::from_millis(300)).await,
        "the erasure outlasted the bound and was cut"
    );
    // Let it go after the cut: nothing is left to run it.
    go.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        pseudonymized_rows(&db, tenant_id).await.is_empty(),
        "nothing is written after the bound"
    );
}

/// #624, the other half of the design: an erasure never crosses its point of
/// no return once the process is stopping. Asked to run then, it stops after
/// the (idempotent) audit scrub and before the anonymization: the account is
/// untouched and still due, and nothing — proof, completion, audit row — is
/// written, so the next start erases it whole.
#[tokio::test]
async fn an_erasure_does_not_start_its_anonymization_once_the_process_is_stopping() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "stopping_erasure").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    stop_tx.send_replace(true);
    let work = AuditedWork::new(stop_rx);
    let (audit, proofs, users, deletions, certs) = (
        SurrealAuditLogRepository::new(db.clone()),
        SurrealErasureProofRepository::new(db.clone()),
        SurrealUserRepository::new(db.clone()),
        SurrealAccountDeletionRepository::new(db.clone()),
        SurrealCertificateRepository::new(db.clone()),
    );

    let erased = erase_and_record(
        &audit,
        &proofs,
        &users,
        &certs,
        &deletions,
        None,
        ErasureSubject {
            tenant_id,
            user_id: user.id,
            pseudonym: "DELETED_USER_stop000000001",
            email_hash: "hashed_stopping_email",
            certificates_revoked: 0,
        },
        &work,
    )
    .await
    .expect("giving up is not a failure");

    assert!(!erased, "the erasure gave itself up");
    let after = users.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(after.email, "stopping_erasure@example.com");
    assert!(
        users
            .find_due_for_purge(Utc::now())
            .await
            .unwrap()
            .iter()
            .any(|due| due.id == user.id),
        "the account is still due"
    );
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 0);
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());
    assert!(
        deletions
            .find_pending_by_user_id(tenant_id, user.id)
            .await
            .unwrap()
            .is_some(),
        "the deletion request is still pending"
    );
}

/// #668 — the purge revokes at step (b4) and anonymizes afterwards, so a bound
/// certificate issued in between survived. A step hook issues one at
/// [`UnitStep::ErasurePrepared`]; the second revocation, by binding, after the
/// anonymization revokes it, and leaves another account's certificate alone.
#[tokio::test]
async fn a_certificate_bound_between_the_first_revocation_and_the_anonymization_is_revoked_after_it()
 {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };

    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "late_bound").await;
    let certs = Arc::new(SurrealCertificateRepository::new(db.clone()));
    let leaf = move |fingerprint: &str, user_id: Uuid| StoreCertificate {
        tenant_id,
        issuer_ca_id: Uuid::new_v4(),
        subject: "device".into(),
        public_cert_pem: "not-a-parsed-certificate".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - chrono::Duration::minutes(1),
        not_after: Utc::now() + chrono::Duration::days(30),
        metadata: serde_json::json!({}),
        user_id: Some(user_id),
    };
    let other = certs
        .create(leaf("fp-668-other", Uuid::new_v4()))
        .await
        .unwrap();
    let issued = Arc::new(std::sync::Mutex::new(None));
    let hook: UnitStepForTests = {
        let (certs, issued, user_id) = (Arc::clone(&certs), Arc::clone(&issued), user.id);
        Arc::new(move |step| {
            let (certs, issued) = (Arc::clone(&certs), Arc::clone(&issued));
            let cert = leaf("fp-668-late", user_id);
            Box::pin(async move {
                if step == UnitStep::ErasurePrepared(user_id) {
                    let created = certs.create(cert).await.unwrap();
                    *issued.lock().unwrap() = Some(created.id);
                }
            })
        })
    };
    let work = never_stopping().with_step_for_tests(Some(hook));
    let erased = erase_and_record(
        &SurrealAuditLogRepository::new(db.clone()),
        &SurrealErasureProofRepository::new(db.clone()),
        &SurrealUserRepository::new(db.clone()),
        certs.as_ref(),
        &SurrealAccountDeletionRepository::new(db.clone()),
        None,
        ErasureSubject {
            tenant_id,
            user_id: user.id,
            pseudonym: "DELETED_USER_668000000001",
            email_hash: "hashed_668",
            certificates_revoked: 0,
        },
        &work,
    )
    .await
    .expect("the erasure");
    assert!(erased);

    let late = issued
        .lock()
        .unwrap()
        .expect("the hook issued a certificate");
    assert_eq!(
        certs.get_by_id(tenant_id, late).await.unwrap().status,
        CertificateStatus::Revoked,
        "the late bound certificate is revoked after the anonymization"
    );
    assert_eq!(
        certs.get_by_id(tenant_id, other.id).await.unwrap().status,
        CertificateStatus::Active,
        "another account's certificate is left alone"
    );
}

// ---------------------------------------------------------------------------
// #689 (R110W4-03) — a unit cut past its point of no return is recorded by the
// next start, exactly once
// ---------------------------------------------------------------------------

use axiam_server::cleanup::{PENDING_RECORD_LEASE, record_owed_erasures, record_pending_purges};

fn record_lease() -> chrono::TimeDelta {
    chrono::TimeDelta::from_std(PENDING_RECORD_LEASE).unwrap()
}

/// One GDPR sweep's recovery step over `db` ([`record_owed_erasures`]), as a
/// replica runs it.
async fn record_owed(db: &Surreal<surrealdb::engine::local::Db>) -> Result<u64, AxiamError> {
    record_owed_erasures(
        &SurrealAuditLogRepository::new(db.clone()),
        &SurrealErasureProofRepository::new(db.clone()),
        &SurrealCertificateRepository::new(db.clone()),
        &SurrealAccountDeletionRepository::new(db.clone()),
        record_lease(),
        &never_stopping(),
    )
    .await
}

/// The `tenant_purge_pending` markers standing for `tenant`.
async fn purge_markers_of(db: &Surreal<surrealdb::engine::local::Db>, tenant: Uuid) -> usize {
    let mut result = db
        .query("SELECT VALUE meta::id(id) FROM tenant_purge_pending WHERE meta::id(id) = $id")
        .bind(("id", tenant.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let ids: Vec<String> = result.take(0).unwrap();
    ids.len()
}

/// Whether `user`'s erasure-record marker is set.
async fn erasure_marker_set(db: &Surreal<surrealdb::engine::local::Db>, user: Uuid) -> bool {
    let mut result = db
        .query("SELECT VALUE erasure_audit_pending FROM type::record('user', $id)")
        .bind(("id", user.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let stamps: Vec<Option<chrono::DateTime<Utc>>> = result.take(0).unwrap();
    stamps.into_iter().next().flatten().is_some()
}

/// The next start's tenant purge sweep, repeated briefly: the cut unit's guard
/// releases its marker from a spawned task, so give it a moment — never
/// anything like the lease.
async fn next_start_records_the_purge(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenants: &Arc<SurrealTenantRepository<surrealdb::engine::local::Db>>,
    audit: &Arc<SurrealAuditLogRepository<surrealdb::engine::local::Db>>,
    tenant: Uuid,
) {
    let next_start = never_stopping();
    for _ in 0..50 {
        sweep_tenant_purge(tenants, audit, true, &next_start)
            .await
            .expect("the next start's sweep");
        if purge_records_of(db, tenant).await > 0 && purge_markers_of(db, tenant).await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        purge_records_of(db, tenant).await,
        1,
        "the next start writes the record the cut unit owed"
    );
    assert_eq!(
        purge_markers_of(db, tenant).await,
        0,
        "and clears the marker"
    );
    sweep_tenant_purge(tenants, audit, true, &next_start)
        .await
        .unwrap();
    assert_eq!(
        purge_records_of(db, tenant).await,
        1,
        "tenants.purged exists exactly once"
    );
}

/// A sweep started while `tenants`' purge unit is held at `at`, spawned on a
/// stop channel the test controls.
fn held_purge_tick(
    tenants: &Arc<SurrealTenantRepository<surrealdb::engine::local::Db>>,
    audit: &Arc<SurrealAuditLogRepository<surrealdb::engine::local::Db>>,
    scan_orphans: bool,
    at: UnitStep,
) -> (
    tokio::task::JoinHandle<()>,
    AuditedWork,
    watch::Sender<bool>,
    watch::Receiver<bool>,
) {
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        at,
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = {
        let (tenants, audit, work) = (Arc::clone(tenants), Arc::clone(audit), work.clone());
        tokio::spawn(async move {
            let _ = sweep_tenant_purge(&tenants, &audit, scan_orphans, &work).await;
        })
    };
    (tick, work, stop_tx, entered)
}

/// #689: a tombstoned tenant's purge held past its point of no return — the
/// tenant row removed, `tenants.purged` not yet written — across a stop, and
/// cut by the teardown at its bound. Before the marker the record was lost: no
/// sweep found the tenant again. Now the removal left `tenant_purge_pending`,
/// and the next start records the purge once, with what the unit would have
/// written. While the unit holds the marker, another replica's sweep records
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_purge_cut_past_its_point_of_no_return_is_recorded_by_the_next_start_once() {
    let db = setup_db().await;
    let org = new_org(&db, "purge-past-pnr").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let doomed = tenant_with_a_user(&db, org, "cut-past-pnr").await;
    tenants.delete(doomed).await.unwrap();

    let (tick, work, stop_tx, mut entered) =
        held_purge_tick(&tenants, &audit, false, UnitStep::TenantRowRemoved(doomed));
    wait_until_entered(&mut entered).await;
    assert!(
        tenants.list_tombstoned().await.unwrap().is_empty(),
        "the tenant row is gone: past the point of no return"
    );
    assert_eq!(purge_markers_of(&db, doomed).await, 1, "the marker stands");
    assert_eq!(
        record_pending_purges(&tenants, audit.as_ref(), record_lease(), &never_stopping())
            .await
            .unwrap(),
        0,
        "while the unit holds the marker, another replica's sweep records nothing"
    );

    stop_tx.send_replace(true);
    assert!(
        !join_like_the_teardown(tick, &work, Duration::from_millis(200)).await,
        "the unit was cut where it was held"
    );
    assert_eq!(
        purge_records_of(&db, doomed).await,
        0,
        "nothing was recorded"
    );

    next_start_records_the_purge(&db, &tenants, &audit, doomed).await;
    let record = purged_records(&db)
        .await
        .into_iter()
        .find(|e| e.resource_id == Some(doomed))
        .unwrap();
    assert_eq!(record.metadata["orphan"], false);
    assert!(record.metadata["audit_rows_deleted"].is_u64());
}

/// #689: the same for an orphaned id, whose point of no return is the removal
/// of its claim marker: the next start records it once, as an orphan, and a
/// scan that predates that writes no marker and records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_orphan_purge_cut_past_its_point_of_no_return_is_recorded_by_the_next_start_once() {
    let db = setup_db().await;
    let org = new_org(&db, "orphan-past-pnr").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let orphan = tenant_with_a_user(&db, org, "orphan-cut-past-pnr").await;
    db.query("DELETE type::record('tenant', $id)")
        .bind(("id", orphan.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    let (tick, work, stop_tx, mut entered) =
        held_purge_tick(&tenants, &audit, true, UnitStep::TenantRowRemoved(orphan));
    wait_until_entered(&mut entered).await;
    assert_eq!(users_in(&db, orphan).await, 0, "the rows are purged");
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    assert_eq!(purge_markers_of(&db, orphan).await, 1);

    stop_tx.send_replace(true);
    assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(200)).await);
    assert_eq!(purge_records_of(&db, orphan).await, 0);

    next_start_records_the_purge(&db, &tenants, &audit, orphan).await;
    let record = purged_records(&db)
        .await
        .into_iter()
        .find(|e| e.resource_id == Some(orphan))
        .unwrap();
    assert_eq!(record.metadata["orphan"], true);
    assert!(
        !tenants
            .claim_orphan_purge(orphan, Utc::now())
            .await
            .unwrap()
    );
}

/// #689: a purge cut after its record and before it cleared its marker is not
/// recorded twice: the next start finds `tenants.purged` written since the
/// removal and only clears the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tenant_purge_cut_between_its_record_and_its_marker_is_not_recorded_twice() {
    let db = setup_db().await;
    let org = new_org(&db, "purge-after-record").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let doomed = tenant_with_a_user(&db, org, "cut-after-record").await;
    tenants.delete(doomed).await.unwrap();

    let (tick, work, stop_tx, mut entered) =
        held_purge_tick(&tenants, &audit, false, UnitStep::Recorded(doomed));
    wait_until_entered(&mut entered).await;
    assert_eq!(purge_records_of(&db, doomed).await, 1, "recorded");
    assert_eq!(purge_markers_of(&db, doomed).await, 1, "not yet cleared");

    stop_tx.send_replace(true);
    assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(200)).await);

    next_start_records_the_purge(&db, &tenants, &audit, doomed).await;
}

/// #689: two replicas' sweeps that find one released marker at once record it
/// once between them: each claim is conditional on the claim read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sweeps_finding_one_pending_purge_record_it_once() {
    let db = setup_db().await;
    let org = new_org(&db, "pending-race").await;
    let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
    let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
    let doomed = tenant_with_a_user(&db, org, "pending-race").await;
    tenants.delete(doomed).await.unwrap();
    // A unit cut past its point of no return whose guard released the marker.
    let report = tenants.purge_tombstoned_rows(doomed).await.unwrap();
    let stamp = Utc::now();
    tenants
        .remove_purged_tenant(doomed, &report, stamp)
        .await
        .unwrap();
    tenants.release_purge_record(doomed, stamp).await.unwrap();

    let (one, other) = (never_stopping(), never_stopping());
    let (a, b) = tokio::join!(
        record_pending_purges(&tenants, audit.as_ref(), record_lease(), &one),
        record_pending_purges(&tenants, audit.as_ref(), record_lease(), &other),
    );
    assert_eq!(a.unwrap() + b.unwrap(), 1, "one of the two recorded it");
    assert_eq!(purge_records_of(&db, doomed).await, 1);
    assert_eq!(purge_markers_of(&db, doomed).await, 0);
}

/// The next start's GDPR sweep recording what a cut erasure owed, repeated
/// briefly for the cut unit's spawned release; then once more, which records
/// nothing.
async fn next_start_records_the_erasure(db: &Surreal<surrealdb::engine::local::Db>, user: &User) {
    let deletions = SurrealAccountDeletionRepository::new(db.clone());
    for _ in 0..50 {
        record_owed(db).await.expect("the next start's sweep");
        if !pseudonymized_rows(db, user.tenant_id).await.is_empty()
            && !erasure_marker_set(db, user.id).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(record_owed(db).await.unwrap(), 0);
    assert_eq!(
        pseudonymized_rows(db, user.tenant_id).await.len(),
        1,
        "gdpr.user_pseudonymized exists exactly once"
    );
    assert!(
        !erasure_marker_set(db, user.id).await,
        "the marker is cleared"
    );
    assert!(
        deletions
            .find_pending_by_user_id(user.tenant_id, user.id)
            .await
            .unwrap()
            .is_none(),
        "the deletion request, if any, is completed"
    );
    assert_eq!(
        erasure_proof_count(db, user.tenant_id, user.id).await,
        1,
        "#737: the erasure and its proof stand, the proof once"
    );
}

/// #689 (i): an erasure with its deletion request, held past the
/// anonymization and cut at the teardown's bound. Before the change the
/// record was lost and the request stayed pending for ever; now the next
/// start's GDPR sweep writes `gdpr.user_pseudonymized` — with the pseudonym on
/// the row — and completes the request, once. While the unit holds the
/// marker, another replica's sweep records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_cut_past_its_point_of_no_return_is_recorded_by_the_next_start_once() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "cut_past_pnr").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::ErasureAnonymized(user.id),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;
    assert!(erasure_marker_set(&db, user.id).await, "the marker stands");
    assert_eq!(
        record_owed(&db).await.unwrap(),
        0,
        "while the unit holds the marker, another replica's sweep records nothing"
    );

    stop_tx.send_replace(true);
    assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(300)).await);
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());

    next_start_records_the_erasure(&db, &user).await;
    let row = &pseudonymized_rows(&db, tenant_id).await[0];
    assert_eq!(row.actor_id, user.id);
    assert_eq!(row.metadata["pseudonym"], "DELETED_USER_held0000000001");
    assert_eq!(row.metadata["recovered"], true);
}

/// #689 (ii): an erasure with no deletion request row is recorded through the
/// account's own marker, `user.erasure_audit_pending`, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_without_a_request_cut_past_its_point_of_no_return_is_recorded_once() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = user_due_for_erasure(&db, tenant_id, "cut_no_request").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::ErasureAnonymized(user.id),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;
    stop_tx.send_replace(true);
    assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(300)).await);
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());
    assert!(erasure_marker_set(&db, user.id).await);

    next_start_records_the_erasure(&db, &user).await;
}

/// A `User` certificate bound to `user_id`, active for a month.
fn bound_certificate(
    tenant_id: Uuid,
    user_id: Uuid,
    fingerprint: &str,
) -> axiam_core::models::certificate::StoreCertificate {
    use axiam_core::models::certificate::{CertificateType, KeyAlgorithm, StoreCertificate};
    StoreCertificate {
        tenant_id,
        issuer_ca_id: Uuid::new_v4(),
        subject: "device".into(),
        public_cert_pem: "not-a-parsed-certificate".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - chrono::Duration::minutes(1),
        not_after: Utc::now() + chrono::Duration::days(30),
        metadata: serde_json::json!({}),
        user_id: Some(user_id),
    }
}

/// #737 (R111W1-03): an erasure held between its anonymization — its point of
/// no return — and its erasure proof, while an issuance that raced the
/// erasure binds a certificate to the account, then cut at the teardown's
/// bound. Before the fix the next start recorded the erasure and completed the
/// request with no proof behind it, never ran the second revocation, and —
/// the marker's guard being armed only after the proof — waited out the
/// one-hour lease first. Now the guard is armed from the stamp the unit chose
/// before the anonymization, so the cut releases the marker, and the next
/// start's sweep, at once, writes the proof, revokes the certificate, writes
/// the record and completes the request, each once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_cut_before_its_proof_is_proven_revoked_and_recorded_by_the_next_start_at_once()
{
    use axiam_core::models::certificate::CertificateStatus;

    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "cut_before_proof").await;
    let certs = Arc::new(SurrealCertificateRepository::new(db.clone()));
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let issued = Arc::new(std::sync::Mutex::new(None));
    let hold: UnitStepForTests = {
        let (certs, issued, user_id) = (Arc::clone(&certs), Arc::clone(&issued), user.id);
        Arc::new(move |step| {
            let (certs, issued, entered) =
                (Arc::clone(&certs), Arc::clone(&issued), entered_tx.clone());
            Box::pin(async move {
                if step == UnitStep::ErasureProofOwed(user_id) {
                    let late = certs
                        .create(bound_certificate(tenant_id, user_id, "fp-737-late"))
                        .await
                        .unwrap();
                    *issued.lock().unwrap() = Some(late.id);
                    entered.send_replace(true);
                    std::future::pending::<()>().await;
                }
            })
        })
    };
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;
    let late = issued
        .lock()
        .unwrap()
        .expect("the hook issued a certificate");
    assert_eq!(
        SurrealUserRepository::new(db.clone())
            .get_by_id(tenant_id, user.id)
            .await
            .unwrap()
            .email,
        "hashed_held_email",
        "the account is anonymized: past the point of no return"
    );
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 0);
    assert!(erasure_marker_set(&db, user.id).await, "the marker stands");
    assert_eq!(
        record_owed(&db).await.unwrap(),
        0,
        "while the unit holds the marker, another replica's sweep finishes nothing"
    );
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 0);

    stop_tx.send_replace(true);
    assert!(
        !join_like_the_teardown(tick, &work, Duration::from_millis(300)).await,
        "the unit was cut where it was held"
    );
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());
    assert_eq!(
        certs.get_by_id(tenant_id, late).await.unwrap().status,
        CertificateStatus::Active,
        "the cut unit never ran its second revocation"
    );

    // At once: within the few hundred milliseconds the guard's spawned release
    // takes to land, never the hour of the lease.
    let started = std::time::Instant::now();
    next_start_records_the_erasure(&db, &user).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    let row = &pseudonymized_rows(&db, tenant_id).await[0];
    assert_eq!(row.metadata["recovered"], true);
    assert!(row.metadata["certificates_revoked"].is_null());
    assert_eq!(
        certs.get_by_id(tenant_id, late).await.unwrap().status,
        CertificateStatus::Revoked,
        "the recovery's second revocation revokes the late bound certificate"
    );
}

/// #737 (R111W1-03 (a)): an erasure whose proof fails to write, past its point
/// of no return, fails its tick and releases its marker, awaited; the next
/// sweep writes the proof and the record at once, and completes the request.
/// Before the fix the request was completed by the next sweep past the lease,
/// with no proof ever written.
#[tokio::test]
async fn an_erasure_whose_proof_fails_is_proven_and_recorded_by_the_next_sweep_at_once() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "proof_fails").await;
    let deletions = SurrealAccountDeletionRepository::new(db.clone());

    let failed = erase_and_record(
        &SurrealAuditLogRepository::new(db.clone()),
        &FailingErasureProofRepo,
        &SurrealUserRepository::new(db.clone()),
        &SurrealCertificateRepository::new(db.clone()),
        &deletions,
        None,
        ErasureSubject {
            tenant_id,
            user_id: user.id,
            pseudonym: "DELETED_USER_proof00000001",
            email_hash: "hashed_proof_fails",
            certificates_revoked: 0,
        },
        &never_stopping(),
    )
    .await;
    assert!(failed.is_err(), "a failed proof fails the tick");
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 0);
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());

    assert_eq!(
        record_owed(&db).await.unwrap(),
        1,
        "the marker was released, not left to its lease"
    );
    next_start_records_the_erasure(&db, &user).await;
    assert_eq!(
        pseudonymized_rows(&db, tenant_id).await[0].metadata["pseudonym"],
        "DELETED_USER_proof00000001"
    );
}

/// #689: an erasure cut after its record and before it settled is not recorded
/// twice; the next start completes the request and clears the marker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_cut_between_its_record_and_its_completion_is_not_recorded_twice() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "cut_after_record").await;
    let (stop_tx, stop_rx) = watch::channel(false);
    let (entered_tx, mut entered) = watch::channel(false);
    let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
        UnitStep::Recorded(user.id),
        entered_tx,
        Arc::new(Notify::new()),
    )));
    let tick = erasure_tick(&db, &user, &work);
    wait_until_entered(&mut entered).await;
    assert_eq!(pseudonymized_rows(&db, tenant_id).await.len(), 1);
    assert!(
        SurrealAccountDeletionRepository::new(db.clone())
            .find_pending_by_user_id(tenant_id, user.id)
            .await
            .unwrap()
            .is_some(),
        "(i): the record is written before the completion"
    );
    stop_tx.send_replace(true);
    assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(300)).await);

    next_start_records_the_erasure(&db, &user).await;
    assert!(
        pseudonymized_rows(&db, tenant_id).await[0].metadata["recovered"].is_null(),
        "the row is the unit's own"
    );
}

/// #689 (i): an erasure cut before schema v108 left its account anonymized and
/// its request pending, with no marker. The sweep completes the request and
/// writes the record, once.
#[tokio::test]
async fn a_pending_request_whose_account_is_anonymized_is_completed_and_recorded_once() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "pre_v108").await;
    let users = SurrealUserRepository::new(db.clone());
    users
        .anonymize_user(
            tenant_id,
            user.id,
            "hashed_pre_v108",
            "DELETED_USER_pre0000000001",
        )
        .await
        .unwrap();
    // What an anonymization before v108 left: no marker.
    db.query("UPDATE type::record('user', $id) SET erasure_audit_pending = NONE")
        .bind(("id", user.id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();

    next_start_records_the_erasure(&db, &user).await;
    assert_eq!(
        pseudonymized_rows(&db, tenant_id).await[0].metadata["pseudonym"],
        "DELETED_USER_pre0000000001"
    );
}

// ---------------------------------------------------------------------------
// #738 (R111W1-04) — two replicas' sweeps never run one erasure twice
// ---------------------------------------------------------------------------

use axiam_server::cleanup::{ERASURE_CLAIM_LEASE, purge_under_claim};

fn erasure_claim_lease() -> chrono::TimeDelta {
    chrono::TimeDelta::from_std(ERASURE_CLAIM_LEASE).unwrap()
}

/// One replica's GDPR sweep over the due accounts, as
/// `CleanupTask::sweep_pending_purges` runs it: the accounts due at its `now`,
/// each erased as a unit of its `work` under an exclusive claim. The unit's
/// steps before the anonymization — the revocations of (a)…(b4) — are left
/// out; the claim is taken before them, so they change nothing here. An error
/// of any unit fails this sweep, which the real one only logs, so that "no
/// error" is asserted, not assumed.
async fn replica_sweep(
    db: &Surreal<surrealdb::engine::local::Db>,
    sink: &Arc<RecordingPurgeSink>,
    work: &AuditedWork,
) -> Result<u64, AxiamError> {
    let now = Utc::now();
    let due = SurrealUserRepository::new(db.clone())
        .find_due_for_purge(now)
        .await?;
    let mut purged = 0;
    for user in due {
        let (db, sink, unit_work) = (db.clone(), Arc::clone(sink), work.clone());
        let (tenant_id, user_id) = (user.tenant_id, user.id);
        let outcome = work
            .run(async move {
                let deletions = SurrealAccountDeletionRepository::new(db.clone());
                let (audit, proofs, users, certs) = (
                    SurrealAuditLogRepository::new(db.clone()),
                    SurrealErasureProofRepository::new(db.clone()),
                    SurrealUserRepository::new(db.clone()),
                    SurrealCertificateRepository::new(db.clone()),
                );
                let pseudonym = format!("DELETED_USER_{}", user_id.simple());
                // Per account: the address column is unique per tenant.
                let email_hash = format!("hashed_{}", user_id.simple());
                purge_under_claim(
                    &deletions,
                    tenant_id,
                    user_id,
                    now,
                    erasure_claim_lease(),
                    erase_and_record(
                        &audit,
                        &proofs,
                        &users,
                        &certs,
                        &deletions,
                        Some(sink.as_ref() as &dyn SsfSystemAccountSink),
                        ErasureSubject {
                            tenant_id,
                            user_id,
                            pseudonym: &pseudonym,
                            email_hash: &email_hash,
                            certificates_revoked: 0,
                        },
                        &unit_work,
                    ),
                )
                .await
            })
            .await
            .expect("the unit ran to its end");
        if outcome? {
            purged += 1;
        }
    }
    Ok(purged)
}

/// The `account_purged` reports the sink received for `user`.
fn reports_for(sink: &RecordingPurgeSink, user: Uuid) -> usize {
    sink.purged
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, id, _, _)| *id == user)
        .count()
}

/// #738: every replica runs the GDPR sweep. Two sweeps over one store, run at
/// once against one due account — one with its deletion request, one without
/// (claimed by the stamp on its user row) — erase each once: one unit erases,
/// the other skips without an error, and the SSF sink sees one
/// `account_purged` per account. Then, to make the overlap certain rather than
/// likely, replica A is held after its claim and before the anonymization
/// while replica B sweeps: B skips the account, and A erases it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sweeps_at_once_erase_one_due_account_once_and_neither_fails() {
    // The engine production runs: `kv-mem` may admit two winners (R112W1-06 c).
    let (db, _dir) = setup_serialising_db().await;
    let tenant_id = Uuid::new_v4();
    let with_request = erasure_due_with_its_request(&db, tenant_id, "race_738_req").await;
    let without_request = user_due_for_erasure(&db, tenant_id, "race_738_bare").await;
    let sink = Arc::new(RecordingPurgeSink::default());
    let (a, b) = (never_stopping(), never_stopping());

    let (one, other) = tokio::join!(replica_sweep(&db, &sink, &a), replica_sweep(&db, &sink, &b));
    let (one, other) = (
        one.expect("replica A's sweep reports no error"),
        other.expect("replica B's sweep reports no error"),
    );
    assert_eq!(one + other, 2, "each account is erased by one replica");
    for user in [&with_request, &without_request] {
        assert_eq!(reports_for(&sink, user.id), 1, "one account_purged");
        assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 1);
    }
    assert_eq!(pseudonymized_rows(&db, tenant_id).await.len(), 2);
    assert!(
        SurrealAccountDeletionRepository::new(db.clone())
            .find_pending_by_user_id(tenant_id, with_request.id)
            .await
            .unwrap()
            .is_none(),
        "the request is completed"
    );

    // The overlap, held open: A has claimed and not yet anonymized.
    let held = erasure_due_with_its_request(&db, tenant_id, "held_738").await;
    let (entered_tx, mut entered) = watch::channel(false);
    let go = Arc::new(Notify::new());
    let holding = never_stopping().with_step_for_tests(Some(hold_at(
        UnitStep::ErasurePrepared(held.id),
        entered_tx,
        Arc::clone(&go),
    )));
    let replica_a = {
        let (db, sink, holding) = (db.clone(), Arc::clone(&sink), holding.clone());
        tokio::spawn(async move { replica_sweep(&db, &sink, &holding).await })
    };
    wait_until_entered(&mut entered).await;
    assert_eq!(
        replica_sweep(&db, &sink, &never_stopping())
            .await
            .expect("replica B's sweep reports no error"),
        0,
        "B skips the account A holds"
    );
    assert_eq!(reports_for(&sink, held.id), 0);
    go.notify_one();
    assert_eq!(replica_a.await.unwrap().expect("replica A's sweep"), 1);
    assert_eq!(reports_for(&sink, held.id), 1);
    assert_eq!(erasure_proof_count(&db, tenant_id, held.id).await, 1);
    assert_eq!(pseudonymized_rows(&db, tenant_id).await.len(), 3);
}

/// #738: a claimant that stalls — a replica that died holding the claim, or a
/// unit held past the lease — keeps the account from the other replicas for
/// the lease only. Inside it, a sweep skips the account; past it, a sweep takes
/// it over and erases it, once. A stalled unit that then wakes and runs its
/// erasure finds the account no longer deletion-pending and stops before its
/// scrub (#784): not an error, and nothing written — the other unit's record
/// keeps the account as its actor, the account is not anonymized again (no
/// marker set, the row untouched), and the SSF sink sees one `account_purged`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_claimants_account_is_taken_over_once_its_lease_runs_out() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = erasure_due_with_its_request(&db, tenant_id, "stalled_738").await;
    let deletions = SurrealAccountDeletionRepository::new(db.clone());
    let sink = Arc::new(RecordingPurgeSink::default());

    // The stalled replica's claim.
    assert_eq!(
        deletions
            .claim_for_purge(tenant_id, user.id, Utc::now(), erasure_claim_lease())
            .await
            .unwrap(),
        axiam_db::repository::PurgeClaimOutcome::Claimed
    );
    assert_eq!(
        replica_sweep(&db, &sink, &never_stopping()).await.unwrap(),
        0,
        "inside the lease the account is skipped"
    );
    assert_eq!(reports_for(&sink, user.id), 0);

    // The lease runs out (the claim is dated back past it).
    db.query("UPDATE account_deletion SET purge_claimed_at = $at WHERE user_id = $u")
        .bind(("u", user.id.to_string()))
        .bind((
            "at",
            Utc::now() - erasure_claim_lease() - chrono::TimeDelta::minutes(1),
        ))
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        replica_sweep(&db, &sink, &never_stopping()).await.unwrap(),
        1,
        "past the lease the account is taken over and erased"
    );
    assert_eq!(reports_for(&sink, user.id), 1);
    let erased = SurrealUserRepository::new(db.clone())
        .get_by_id(tenant_id, user.id)
        .await
        .unwrap();
    assert!(
        !erasure_marker_set(&db, user.id).await,
        "the record is settled"
    );

    // The stalled unit wakes and runs its erasure regardless.
    let woke = erase_and_record(
        &SurrealAuditLogRepository::new(db.clone()),
        &SurrealErasureProofRepository::new(db.clone()),
        &SurrealUserRepository::new(db.clone()),
        &SurrealCertificateRepository::new(db.clone()),
        &deletions,
        Some(sink.as_ref() as &dyn SsfSystemAccountSink),
        ErasureSubject {
            tenant_id,
            user_id: user.id,
            pseudonym: &format!("DELETED_USER_{}", user.id.simple()),
            email_hash: &format!("hashed_{}", user.id.simple()),
            certificates_revoked: 0,
        },
        &never_stopping(),
    )
    .await
    .expect("an account another unit erased is not an error");
    assert!(!woke, "the stalled unit records nothing");
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 1);
    let records = pseudonymized_rows(&db, tenant_id).await;
    assert_eq!(records.len(), 1, "gdpr.user_pseudonymized exists once");
    // #784: the stalled unit's scrub used to nil the record's actor for good.
    assert_eq!(
        records[0].actor_id, user.id,
        "the record still names the erased account as its actor"
    );
    assert_eq!(reports_for(&sink, user.id), 1, "one account_purged");
    // #784: nor is the account anonymized again — no marker set (its release
    // would have left the epoch there), the row as the erasure left it.
    assert!(
        !erasure_marker_set(&db, user.id).await,
        "no marker set again"
    );
    assert_eq!(
        SurrealUserRepository::new(db.clone())
            .get_by_id(tenant_id, user.id)
            .await
            .unwrap()
            .updated_at,
        erased.updated_at,
        "the erased row is not written again"
    );
    assert_eq!(record_owed(&db).await.unwrap(), 0);
    assert!(!erasure_marker_set(&db, user.id).await);
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 1);
    assert_eq!(pseudonymized_rows(&db, tenant_id).await.len(), 1);
}

// ---------------------------------------------------------------------------
// #753 — the OAuth2 refresh-token rows: deleted at erasure, swept after the
// replay-detection retention
// ---------------------------------------------------------------------------

use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::repository::RefreshTokenRepository as _;
use axiam_db::SurrealRefreshTokenRepository;
use axiam_server::cleanup::{
    REFRESH_REPLAY_RETENTION, REFRESH_SWEEP_BATCH, REFRESH_SWEEP_MAX_BATCHES,
    erase_oauth2_refresh_tokens, sweep_refresh_tokens,
};

async fn issue_refresh_token(
    repo: &SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    let hash = Uuid::new_v4().to_string();
    repo.create(CreateRefreshToken {
        tenant_id,
        user_id: Some(user_id),
        token_hash: hash.clone(),
        client_id: "client-a".into(),
        scopes: vec!["openid".into()],
        session_id: None,
        requested_userinfo_claims: Vec::new(),
        expires_at,
        resource: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        dpop_jkt: Some("thumbprint-of-the-device-key".into()),
    })
    .await
    .unwrap();
    hash
}

#[derive(SurrealValue)]
struct RowCount {
    total: u64,
}

async fn refresh_rows_naming(db: &Surreal<surrealdb::engine::local::Db>, user: Uuid) -> u64 {
    let mut res = db
        .query("SELECT count() AS total FROM oauth2_refresh_token WHERE user_id = $u GROUP ALL")
        .bind(("u", user.to_string()))
        .await
        .unwrap();
    let rows: Vec<RowCount> = res.take(0).unwrap();
    rows.first().map_or(0, |r| r.total)
}

async fn refresh_rows_total(db: &Surreal<surrealdb::engine::local::Db>) -> u64 {
    let mut res = db
        .query("SELECT count() AS total FROM oauth2_refresh_token GROUP ALL")
        .await
        .unwrap();
    let rows: Vec<RowCount> = res.take(0).unwrap();
    rows.first().map_or(0, |r| r.total)
}

/// R111-03: after an erasure no `oauth2_refresh_token` row names the user —
/// revoked, rotated or live — and another user's rows are untouched. The step
/// is re-entered by the recovery of a cut erasure (#737), so a second run
/// deletes nothing and fails nothing.
#[tokio::test]
async fn an_erasure_leaves_no_refresh_token_row_naming_the_user_and_can_be_re_entered() {
    let db = setup_db().await;
    let (tenant_id, user_id, other) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let repo = SurrealRefreshTokenRepository::new(db.clone());
    let later = Utc::now() + chrono::Duration::days(1);

    let revoked = issue_refresh_token(&repo, tenant_id, user_id, later).await;
    repo.revoke(tenant_id, &revoked).await.unwrap();
    let rotated = issue_refresh_token(&repo, tenant_id, user_id, later).await;
    repo.revoke_rotated(tenant_id, &rotated).await.unwrap();
    issue_refresh_token(&repo, tenant_id, user_id, later).await;
    issue_refresh_token(&repo, tenant_id, other, later).await;
    assert_eq!(refresh_rows_naming(&db, user_id).await, 3);

    let deleted = erase_oauth2_refresh_tokens(&repo, tenant_id, user_id)
        .await
        .unwrap();
    assert_eq!(deleted, 3);
    assert_eq!(refresh_rows_naming(&db, user_id).await, 0);
    assert_eq!(refresh_rows_naming(&db, other).await, 1);
    assert!(
        repo.find_rotated(tenant_id, &rotated)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        erase_oauth2_refresh_tokens(&repo, tenant_id, user_id)
            .await
            .unwrap(),
        0,
        "a re-run finds nothing and does not fail"
    );
    assert_eq!(refresh_rows_naming(&db, other).await, 1);
}

/// R111-03: a tick removes a token expired past the replay-detection
/// retention, and keeps a live one, one expired inside the retention, and a
/// revoked/rotated one whose expiry is still ahead — its replay must stay
/// detectable (T-254).
#[tokio::test]
async fn the_refresh_token_sweep_removes_only_rows_expired_past_the_retention() {
    let db = setup_db().await;
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let repo = SurrealRefreshTokenRepository::new(db.clone());
    let now = Utc::now();

    let _past_window = issue_refresh_token(
        &repo,
        tenant_id,
        user_id,
        now - REFRESH_REPLAY_RETENTION - chrono::Duration::hours(1),
    )
    .await;
    // Revoked as well: revocation does not shorten the retention.
    let past_window_revoked = issue_refresh_token(
        &repo,
        tenant_id,
        user_id,
        now - REFRESH_REPLAY_RETENTION - chrono::Duration::hours(1),
    )
    .await;
    repo.revoke(tenant_id, &past_window_revoked).await.unwrap();
    let _inside_window = issue_refresh_token(
        &repo,
        tenant_id,
        user_id,
        now - REFRESH_REPLAY_RETENTION + chrono::Duration::hours(1),
    )
    .await;
    let live =
        issue_refresh_token(&repo, tenant_id, user_id, now + chrono::Duration::days(1)).await;
    let rotated =
        issue_refresh_token(&repo, tenant_id, user_id, now + chrono::Duration::days(1)).await;
    repo.revoke_rotated(tenant_id, &rotated).await.unwrap();
    assert_eq!(refresh_rows_total(&db).await, 5);

    let (_stop, never) = watch::channel(false);
    assert_eq!(sweep_refresh_tokens(&repo, now, &never).await.unwrap(), 2);
    assert_eq!(refresh_rows_total(&db).await, 3);
    assert!(repo.get_by_token_hash(tenant_id, &live).await.is_ok());
    assert!(
        repo.find_rotated(tenant_id, &rotated)
            .await
            .unwrap()
            .is_some(),
        "a rotated token's replay is still detectable"
    );

    // The next tick finds nothing more; the in-window row goes once the
    // retention has run out on it.
    assert_eq!(sweep_refresh_tokens(&repo, now, &never).await.unwrap(), 0);
    assert_eq!(
        sweep_refresh_tokens(&repo, now + chrono::Duration::hours(2), &never)
            .await
            .unwrap(),
        1
    );
    assert_eq!(refresh_rows_total(&db).await, 2);
}

/// R112W1-02: the first run over a backlog — every row expired since the
/// deployment began — is bounded. One tick deletes at most
/// `BATCH * MAX_BATCHES` rows and leaves the rest to the next, never the whole
/// backlog in one statement; a shutdown signal stops it between batches; a
/// later tick finishes the job.
#[tokio::test]
async fn the_refresh_token_sweep_bounds_a_first_run_over_a_backlog() {
    let db = setup_db().await;
    let bound = u64::from(REFRESH_SWEEP_BATCH) * u64::from(REFRESH_SWEEP_MAX_BATCHES);
    let backlog = bound + 700;
    let expired = (Utc::now() - REFRESH_REPLAY_RETENTION - chrono::Duration::days(1)).to_rfc3339();
    let live = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    let mut inserted = 0_u64;
    while inserted < backlog {
        let end = (inserted + 2_000).min(backlog);
        let rows: Vec<serde_json::Value> = (inserted..end)
            .map(|k| serde_json::json!({ "hash": format!("backlog-{k}"), "at": expired }))
            .collect();
        db.query(
            "FOR $r IN $rows { CREATE oauth2_refresh_token SET tenant_id = 't', \
             token_hash = $r.hash, client_id = 'c', scopes = [], revoked = false, \
             expires_at = <datetime>$r.at; }",
        )
        .bind(("rows", rows))
        .await
        .unwrap()
        .check()
        .unwrap();
        inserted = end;
    }
    db.query(
        "CREATE oauth2_refresh_token SET tenant_id = 't', token_hash = 'live', \
         client_id = 'c', scopes = [], revoked = false, expires_at = <datetime>$at",
    )
    .bind(("at", live))
    .await
    .unwrap()
    .check()
    .unwrap();
    let repo = SurrealRefreshTokenRepository::new(db.clone());
    let now = Utc::now();

    // A stopped process starts no batch.
    let (_keep, stopped) = watch::channel(true);
    assert_eq!(sweep_refresh_tokens(&repo, now, &stopped).await.unwrap(), 0);
    assert_eq!(refresh_rows_total(&db).await, backlog + 1);

    let (_stop, running) = watch::channel(false);
    assert_eq!(
        sweep_refresh_tokens(&repo, now, &running).await.unwrap(),
        bound,
        "one tick deletes at most BATCH * MAX_BATCHES rows"
    );
    assert_eq!(refresh_rows_total(&db).await, backlog + 1 - bound);
    assert_eq!(
        sweep_refresh_tokens(&repo, now, &running).await.unwrap(),
        backlog - bound,
        "the next tick takes the rest"
    );
    assert_eq!(refresh_rows_total(&db).await, 1, "the live row stays");
}

// ---------------------------------------------------------------------------
// #758 (e) — the erasure's role pass writes `network_role.unassigned` rows,
// and no `network_role.*` row keeps the subject's id
// ---------------------------------------------------------------------------

use axiam_core::models::permission::CreatePermission;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::repository::{PermissionRepository as _, RoleRepository as _};
use axiam_db::{SurrealPermissionRepository, SurrealRoleRepository};
use axiam_server::cleanup::remove_erased_users_roles;

async fn role_granting(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    name: &str,
    action: &str,
) -> Uuid {
    let role = SurrealRoleRepository::new(db.clone())
        .create(CreateRole {
            tenant_id,
            name: name.into(),
            description: String::new(),
            is_global: false,
        })
        .await
        .expect("role");
    let perms = SurrealPermissionRepository::new(db.clone());
    let permission = perms
        .create(CreatePermission {
            tenant_id,
            action: action.into(),
            description: String::new(),
        })
        .await
        .expect("permission");
    perms
        .grant_to_role(tenant_id, role.id, permission.id)
        .await
        .expect("grant");
    role.id
}

async fn rows_of(
    db: &Surreal<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    action: &str,
) -> Vec<AuditLogEntry> {
    SurrealAuditLogRepository::new(db.clone())
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some(action.into()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 50,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_erasure_writes_one_unassigned_row_per_network_role_and_no_network_row_keeps_the_subject()
 {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user = user_due_for_erasure(&db, tenant_id, "network_holder").await;
    let (roles, audit) = (
        SurrealRoleRepository::new(db.clone()),
        SurrealAuditLogRepository::new(db.clone()),
    );
    let network_a = role_granting(&db, tenant_id, "net-a", "network:join").await;
    let network_b = role_granting(&db, tenant_id, "net-b", "NETWORK:admin").await;
    let plain = role_granting(&db, tenant_id, "docs", "documents:read").await;
    for role in [network_a, network_b, plain] {
        roles
            .assign_to_user(tenant_id, user.id, role, AssignmentScope::global())
            .await
            .expect("assign");
    }
    // An administrator's earlier assignment row names the subject as grantee.
    audit
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::User,
            action: "network_role.assigned".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "role_id": network_a,
                "grantee": { "kind": "user", "id": user.id },
            })),
        })
        .await
        .unwrap();

    let written = remove_erased_users_roles(
        &roles,
        &SurrealPermissionRepository::new(db.clone()),
        &audit,
        tenant_id,
        user.id,
    )
    .await
    .expect("role pass");
    assert_eq!(
        written, 2,
        "one row per network role removed, none for the plain one"
    );
    assert!(
        roles
            .get_user_role_assignments(tenant_id, user.id)
            .await
            .unwrap()
            .is_empty(),
        "every assignment is gone"
    );
    let unassigned = rows_of(&db, tenant_id, "network_role.unassigned").await;
    assert_eq!(unassigned.len(), 2);
    let mut names: Vec<_> = unassigned
        .iter()
        .map(|r| r.metadata["role"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["net-a", "net-b"]);
    for row in &unassigned {
        assert_eq!(row.actor_type, ActorType::System);
        assert_eq!(row.actor_id, Uuid::nil());
        assert_eq!(row.metadata["grantee"]["kind"], "user");
        assert_eq!(row.metadata["node"], "none");
        assert!(!row.metadata["permissions"].as_array().unwrap().is_empty());
    }

    // A re-entered erasure finds nothing left and writes nothing.
    let again = remove_erased_users_roles(
        &roles,
        &SurrealPermissionRepository::new(db.clone()),
        &audit,
        tenant_id,
        user.id,
    )
    .await
    .unwrap();
    assert_eq!(again, 0);
    assert_eq!(
        rows_of(&db, tenant_id, "network_role.unassigned")
            .await
            .len(),
        2
    );

    audit
        .pseudonymize_actor(tenant_id, user.id, "DELETED_USER_net00000001")
        .await
        .unwrap();
    for action in ["network_role.assigned", "network_role.unassigned"] {
        let rows = rows_of(&db, tenant_id, action).await;
        assert!(!rows.is_empty());
        for row in rows {
            assert!(
                !row.metadata.to_string().contains(&user.id.to_string()),
                "{action} row still names the erased user: {}",
                row.metadata
            );
            assert_eq!(
                row.metadata["grantee"]["id"],
                serde_json::json!(Uuid::nil())
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #758 (f) — two recoveries over one store record each owed erasure once
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_recoveries_over_one_store_record_an_owed_erasure_once() {
    // The engine production runs: `kv-mem` may admit two winners (R112W1-06 c).
    let (db, _dir) = setup_serialising_db().await;
    let tenant_id = Uuid::new_v4();
    // An erasure cut past its point of no return (the helper's pseudonym is
    // fixed, so one account per store).
    let user = erasure_due_with_its_request(&db, tenant_id, "owed_one").await;
    {
        let (stop_tx, stop_rx) = watch::channel(false);
        let (entered_tx, mut entered) = watch::channel(false);
        let work = AuditedWork::new(stop_rx).with_step_for_tests(Some(hold_at(
            UnitStep::ErasureAnonymized(user.id),
            entered_tx,
            Arc::new(Notify::new()),
        )));
        let tick = erasure_tick(&db, &user, &work);
        wait_until_entered(&mut entered).await;
        stop_tx.send_replace(true);
        assert!(!join_like_the_teardown(tick, &work, Duration::from_millis(300)).await);
    }
    assert!(pseudonymized_rows(&db, tenant_id).await.is_empty());

    // Two replicas' recoveries at once, repeated while the cut units' spawned
    // releases land; the owed erasures are recorded exactly once between them.
    let mut recorded = 0;
    for _ in 0..50 {
        let (a, b) = tokio::join!(record_owed(&db), record_owed(&db));
        recorded += a.expect("replica A") + b.expect("replica B");
        if recorded >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (a, b) = tokio::join!(record_owed(&db), record_owed(&db));
    recorded += a.unwrap() + b.unwrap();
    assert_eq!(recorded, 1, "the owed erasure is recorded once");
    assert_eq!(
        pseudonymized_rows(&db, tenant_id).await.len(),
        1,
        "one gdpr.user_pseudonymized row"
    );
    assert_eq!(erasure_proof_count(&db, tenant_id, user.id).await, 1);
    assert!(!erasure_marker_set(&db, user.id).await);
}
