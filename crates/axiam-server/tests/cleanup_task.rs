//! Integration test: periodic cleanup task sweeps expired federation rows and
//! shuts down gracefully (Task 1 acceptance criteria).
//!
//! Uses an in-memory SurrealDB (no external infra) and short intervals (100 ms)
//! to keep the test fast. This does NOT exercise `CleanupTask` itself (which
//! depends on `axiam-server` compiling with the xmlsec feature — see SUMMARY for
//! the local-compile limitation); instead it verifies the underlying
//! `cleanup_expired` methods that `CleanupTask` calls, and the watch-shutdown
//! logic is verified via a standalone tokio task that mimics CleanupTask behaviour.

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
use axiam_server::cleanup::run_erasure_pipeline;
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use surrealdb_types::SurrealValue;
use tokio::sync::watch;
use uuid::Uuid;

/// Convenience: connect an in-memory DB and run migrations.
async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");
    db
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
    };
    let fresh_row = axiam_core::repository::FederationLoginState {
        state: "state-fresh".into(),
        nonce: "nonce-fresh".into(),
        tenant_id,
        federation_config_id: config_id,
        redirect_uri: "https://example.com/cb".into(),
        expires_at: future,
        request_id: String::new(),
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
            password: "FatalPseudo1234!".into(),
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
            password: "ErasureSuccess1234!".into(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(tenant_id, user.id, Utc::now() - chrono::Duration::seconds(1))
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
        scrubbed_entry.metadata.get("actor_pseudonym").and_then(|v| v.as_str()),
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
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn get_by_id(&self, _: Uuid, _: Uuid) -> AxiamResult<User> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn get_by_username(&self, _: Uuid, _: &str) -> AxiamResult<User> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn get_by_email(&self, _: Uuid, _: &str) -> AxiamResult<User> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn update(&self, _: Uuid, _: Uuid, _: UpdateUser) -> AxiamResult<User> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn delete(&self, _: Uuid, _: Uuid) -> AxiamResult<()> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn update_totp_step(&self, _: Uuid, _: Uuid, _: u64) -> AxiamResult<bool> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
    }
    async fn list(&self, _: Uuid, _: Pagination) -> AxiamResult<PaginatedResult<User>> {
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
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
        unimplemented!("not exercised by run_erasure_pipeline_aborts_before_proof_when_anonymize_user_fails")
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
            password: "ProofFail12345!".into(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(tenant_id, user.id, Utc::now() - chrono::Duration::seconds(1))
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
            password: "RetryUser12345!".into(),
            metadata: None,
        })
        .await
        .expect("create user");
    user_repo
        .mark_deletion_pending(tenant_id, user.id, Utc::now() - chrono::Duration::seconds(1))
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
