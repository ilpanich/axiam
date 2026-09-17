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
        })
        .await
        .expect("seed client");
    client.client_id
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
    use axiam_core::repository::OAuth2ClientRepository as _;
    use axiam_server::cleanup::{cimd_client_is_due_for_sweep, cimd_client_last_seen};

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
    assert!(cimd_client_is_due_for_sweep(&dead, 30, now));
    // `0` is never due, in this arm as in the other.
    assert!(!cimd_client_is_due_for_sweep(&dead, 0, now));

    // `updated_at` alone is enough to keep it, and that is the whole reason
    // #470 needs no migration: a resolve moves this stamp, and a resolve
    // happens on every authorize, token and PAR presentation — including one
    // served from the in-memory document cache with no fetch at all.
    backdate_updated_at(&db, &client_id, 1).await;
    let refreshed = read(db.clone(), client_id.clone()).await;
    assert!(
        !cimd_client_is_due_for_sweep(&refreshed, 30, now),
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
        !cimd_client_is_due_for_sweep(&authorized, 30, now),
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
#[test]
fn the_sweep_decision_reads_last_authorized_then_created() {
    use axiam_core::models::oauth2_client::{ManagedBy, OAuth2Client};
    use axiam_server::cleanup::dcr_client_is_due_for_sweep;

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
    };

    // Never authorized: `created_at` is the clock.
    assert!(dcr_client_is_due_for_sweep(&client(31, None), 30, now));
    assert!(!dcr_client_is_due_for_sweep(&client(29, None), 30, now));
    // Authorized: `last_authorized_at` wins, however old the registration is.
    assert!(!dcr_client_is_due_for_sweep(
        &client(3650, Some(1)),
        30,
        now
    ));
    assert!(dcr_client_is_due_for_sweep(
        &client(3650, Some(31)),
        30,
        now
    ));
    // Zero is never.
    assert!(!dcr_client_is_due_for_sweep(&client(3650, None), 0, now));
}
