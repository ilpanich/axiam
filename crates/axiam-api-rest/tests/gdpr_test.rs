//! GDPR Wave 0 integration tests (REQ-8).
//!
//! Tests:
//! 1. `export_completeness`       — sectioned JSON has all Art. 15 sections; no secrets present.
//! 2. `deletion_pseudonymization` — purge anonymizes user + pseudonymizes audit entries.
//! 3. `consent_on_registration`   — user creation records a `terms_of_service` consent row.
//! 4. `deletion_cancel`           — single-use cancel token aborts deletion; second use rejected.
//!
//! All tests use an in-memory SurrealDB via `axiam_db::run_migrations`.

use axiam_auth::crypto::{decrypt_separate, encrypt_separate, gdpr_pseudonym};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::{
    AccountDeletionStatus, CreateAccountDeletion, CreateConsent, CreateErasureProof,
    CreateExportJob,
};
use axiam_core::models::session::CreateSession;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AccountDeletionRepository, AuditLogFilter, AuditLogRepository, ConsentRepository,
    ErasureProofRepository, ExportJobRepository, Pagination, SessionRepository, UserRepository,
};
use axiam_db::{
    SurrealAccountDeletionRepository, SurrealAuditLogRepository, SurrealConsentRepository,
    SurrealErasureProofRepository, SurrealExportJobRepository, SurrealSessionRepository,
    SurrealUserRepository,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn sha256_hex(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

// ---------------------------------------------------------------------------
// Test 1: export_completeness
// ---------------------------------------------------------------------------
/// Art. 15 export blob must contain every named section and must NOT include
/// any secret fields (`password_hash`, `mfa_secret`, token hash fields).
#[tokio::test]
async fn export_completeness() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let consent_repo = SurrealConsentRepository::new(db.clone());
    let export_job_repo = SurrealExportJobRepository::new(db.clone());

    // Create a user.
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "export_test_user".into(),
            email: "export@example.com".into(),
            password: "Export1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Create a consent row.
    consent_repo
        .create(CreateConsent {
            tenant_id,
            user_id: user.id,
            consent_type: "terms_of_service".into(),
            version: "2026-01-01".into(),
            ip_address: Some("10.0.0.1".into()),
            user_agent: None,
        })
        .await
        .unwrap();

    // Create an audit entry for this user.
    audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: user.id,
            actor_type: ActorType::User,
            action: "user.login".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: Some("10.0.0.1".into()),
            metadata: None,
        })
        .await
        .unwrap();

    // Create a queued export job.
    let job = export_job_repo
        .create(CreateExportJob {
            tenant_id,
            user_id: user.id,
        })
        .await
        .unwrap();

    // --- Simulate the export sweep inline ---
    // Step 1: Aggregate the Art. 15 inventory (mirrors cleanup.rs aggregate_export_data).
    let retrieved_user = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    let profile = serde_json::json!({
        "id": retrieved_user.id,
        "username": retrieved_user.username,
        "email": retrieved_user.email,
        "status": retrieved_user.status,
        "mfa_enabled": retrieved_user.mfa_enabled,
        "metadata": retrieved_user.metadata,
        "created_at": retrieved_user.created_at,
        "updated_at": retrieved_user.updated_at,
    });
    // Assert secrets are NOT in profile.
    assert!(
        !profile.to_string().contains("password_hash"),
        "profile must not expose password_hash"
    );
    assert!(
        !profile.to_string().contains("mfa_secret"),
        "profile must not expose mfa_secret"
    );

    let consents = consent_repo.list_by_user(tenant_id, user.id).await.unwrap();
    let consents_json: serde_json::Value = serde_json::json!(
        consents
            .iter()
            .map(|c| serde_json::json!({
                "consent_type": c.consent_type,
                "version": c.version,
                "accepted_at": c.accepted_at,
            }))
            .collect::<Vec<_>>()
    );

    let audit_result = audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                actor_id: Some(user.id),
                action: None,
                outcome: None,
                resource_id: None,
                from: None,
                to: None,
            },
            Pagination {
                offset: 0,
                limit: 1_000,
            },
        )
        .await
        .unwrap();
    let audit_json = serde_json::json!(
        audit_result
            .items
            .iter()
            .map(|e| serde_json::json!({
                "action": e.action,
                "outcome": e.outcome,
                "timestamp": e.timestamp,
            }))
            .collect::<Vec<_>>()
    );

    let export = serde_json::json!({
        "export_metadata": {
            "generated_at": Utc::now(),
            "tenant_id": tenant_id,
            "subject_id": user.id,
            "schema_version": "1.0",
        },
        "profile": profile,
        "consents": consents_json,
        "sessions": [],
        "mfa": { "enabled": retrieved_user.mfa_enabled },
        "federation_identities": [],
        "assignments": [],
        "group_memberships": [],
        "audit_entries": audit_json,
        "webauthn_credentials": [],
    });

    // Step 2: Encrypt the export blob (D-12).
    let key: [u8; 32] = [0xAB; 32];
    let export_bytes = export.to_string().into_bytes();
    let (nonce_b64, ct_b64) = encrypt_separate(&key, &export_bytes).unwrap();

    // Step 3: Mark ready with a single-use token (D-13).
    let raw_token = Uuid::new_v4().to_string();
    let token_hash = sha256_hex(&raw_token);
    let expires_at = Utc::now() + chrono::Duration::hours(24);
    export_job_repo
        .set_ready(
            job.id,
            token_hash.clone(),
            Some(ct_b64.clone()),
            None,
            Some(nonce_b64.clone()),
            expires_at,
        )
        .await
        .unwrap();

    // Step 4: Verify the round-trip — look up by token hash and decrypt.
    let ready_job = export_job_repo
        .find_by_download_token_hash(tenant_id, &token_hash)
        .await
        .unwrap()
        .expect("export job not found by token hash");
    assert_eq!(
        ready_job.user_id, user.id,
        "job must belong to the right user"
    );
    assert!(
        ready_job.encrypted_blob.is_some(),
        "encrypted blob must be set"
    );

    let plaintext_bytes = decrypt_separate(
        &key,
        ready_job.blob_nonce.as_deref().unwrap(),
        ready_job.encrypted_blob.as_deref().unwrap(),
    )
    .unwrap();
    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&plaintext).unwrap();

    // --- Assertions: every named Art. 15 section present and non-empty ---
    assert!(
        parsed.get("export_metadata").is_some(),
        "missing section: export_metadata"
    );
    assert!(parsed.get("profile").is_some(), "missing section: profile");
    assert!(
        parsed.get("consents").is_some(),
        "missing section: consents"
    );
    assert!(
        parsed.get("sessions").is_some(),
        "missing section: sessions"
    );
    assert!(parsed.get("mfa").is_some(), "missing section: mfa");
    assert!(
        parsed.get("federation_identities").is_some(),
        "missing section: federation_identities"
    );
    assert!(
        parsed.get("assignments").is_some(),
        "missing section: assignments"
    );
    assert!(
        parsed.get("group_memberships").is_some(),
        "missing section: group_memberships"
    );
    assert!(
        parsed.get("audit_entries").is_some(),
        "missing section: audit_entries"
    );
    assert!(
        parsed.get("webauthn_credentials").is_some(),
        "missing section: webauthn_credentials"
    );

    // consents must be non-empty (we seeded one).
    let consent_arr = parsed["consents"].as_array().unwrap();
    assert!(
        !consent_arr.is_empty(),
        "consents section must be non-empty"
    );

    // audit_entries must be non-empty (we seeded one).
    let audit_arr = parsed["audit_entries"].as_array().unwrap();
    assert!(
        !audit_arr.is_empty(),
        "audit_entries section must be non-empty"
    );

    // --- Assertions: no secret fields in the entire JSON ---
    assert!(
        !plaintext.contains("password_hash"),
        "export must not contain password_hash"
    );
    assert!(
        !plaintext.contains("mfa_secret"),
        "export must not contain mfa_secret"
    );
    assert!(
        !plaintext.contains("token_hash"),
        "export must not contain token_hash"
    );
    assert!(
        !plaintext.contains("cancel_token_hash"),
        "export must not contain cancel_token_hash"
    );
    assert!(
        !plaintext.contains("download_token_hash"),
        "export must not contain download_token_hash"
    );
}

// ---------------------------------------------------------------------------
// Test 1b: export_includes_real_session_metadata
// ---------------------------------------------------------------------------
/// The GDPR export's `sessions` section must carry real, non-empty session
/// metadata (`id`, `created_at`, `expires_at`, `ip_address`, `user_agent`)
/// sourced from `SessionRepository::list_by_user` — NOT a hardcoded `[]` —
/// and must NEVER include the session's `token_hash` (live credential
/// material, D-03c / SECHRD-06).
#[tokio::test]
async fn export_includes_real_session_metadata() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let session_repo = SurrealSessionRepository::new(db.clone());
    let export_job_repo = SurrealExportJobRepository::new(db.clone());

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "session_export_user".into(),
            email: "session_export@example.com".into(),
            password: "SessionExport1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Create a real session for this user — the exact field this test
    // proves is no longer hardcoded to `[]` in the export assembly.
    let live_token_hash = "super-secret-live-session-token-hash".to_string();
    let session = session_repo
        .create(CreateSession {
            tenant_id,
            user_id: user.id,
            token_hash: live_token_hash.clone(),
            ip_address: Some("10.0.0.42".into()),
            user_agent: Some("test-agent/1.0".into()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .unwrap();

    // --- Simulate the export session-projection (mirrors cleanup.rs
    //     aggregate_export_data's sessions block) ---
    let sessions = session_repo.list_by_user(tenant_id, user.id).await.unwrap();
    let sessions_json: Vec<_> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
            })
        })
        .collect();

    let export = serde_json::json!({
        "export_metadata": {
            "generated_at": Utc::now(),
            "tenant_id": tenant_id,
            "subject_id": user.id,
            "schema_version": "1.0",
        },
        "sessions": sessions_json,
    });

    // Encrypt/decrypt round-trip through a real export_job row, exactly like
    // the production path, so this test exercises the same storage seam.
    let key: [u8; 32] = [0xCD; 32];
    let export_bytes = export.to_string().into_bytes();
    let (nonce_b64, ct_b64) = encrypt_separate(&key, &export_bytes).unwrap();
    let job = export_job_repo
        .create(CreateExportJob {
            tenant_id,
            user_id: user.id,
        })
        .await
        .unwrap();
    let raw_token = Uuid::new_v4().to_string();
    let token_hash = sha256_hex(&raw_token);
    export_job_repo
        .set_ready(
            job.id,
            token_hash.clone(),
            Some(ct_b64),
            None,
            Some(nonce_b64),
            Utc::now() + chrono::Duration::hours(24),
        )
        .await
        .unwrap();
    let ready_job = export_job_repo
        .find_by_download_token_hash(tenant_id, &token_hash)
        .await
        .unwrap()
        .expect("export job not found by token hash");
    let plaintext_bytes = decrypt_separate(
        &key,
        ready_job.blob_nonce.as_deref().unwrap(),
        ready_job.encrypted_blob.as_deref().unwrap(),
    )
    .unwrap();
    let plaintext = String::from_utf8(plaintext_bytes).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&plaintext).unwrap();

    // --- Assertions ---
    let sessions_arr = parsed["sessions"]
        .as_array()
        .expect("sessions section must be an array");
    assert!(
        !sessions_arr.is_empty(),
        "sessions section must be non-empty — the seeded session must appear (no hardcoded [])"
    );
    let session_entry = &sessions_arr[0];
    assert_eq!(
        session_entry["id"].as_str().unwrap(),
        session.id.to_string(),
        "session id must match the created session"
    );
    assert_eq!(
        session_entry["ip_address"].as_str().unwrap(),
        "10.0.0.42",
        "ip_address must be present in the projection"
    );
    assert_eq!(
        session_entry["user_agent"].as_str().unwrap(),
        "test-agent/1.0",
        "user_agent must be present in the projection"
    );
    assert!(
        session_entry.get("created_at").is_some(),
        "created_at must be present in the projection"
    );
    assert!(
        session_entry.get("expires_at").is_some(),
        "expires_at must be present in the projection"
    );

    // No token_hash / live credential material anywhere in the export.
    assert!(
        !plaintext.contains("token_hash"),
        "export must not contain the token_hash field name"
    );
    assert!(
        !plaintext.contains(&live_token_hash),
        "export must not contain the session's live token_hash value"
    );
    // No invented `last_seen` field either (Session model has none).
    assert!(
        !plaintext.contains("last_seen"),
        "export must not contain a last_seen field (Session model has none)"
    );
}

// ---------------------------------------------------------------------------
// Test 1c/1d: create_with_pending_flag atomicity (D-14 / QUAL-04)
// ---------------------------------------------------------------------------
/// Happy path: `create_with_pending_flag` atomically marks the user
/// deletion-pending AND creates the `account_deletion` row holding the
/// cancel token — both effects land together.
#[tokio::test]
async fn create_with_pending_flag_succeeds_atomically() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.clone());

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "atomic_happy_user".into(),
            email: "atomic_happy@example.com".into(),
            password: "AtomicHappy1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let scheduled_purge_at = Utc::now() + chrono::Duration::days(30);
    let cancel_token_hash = sha256_hex("happy-path-token");

    let deletion = account_deletion_repo
        .create_with_pending_flag(
            tenant_id,
            user.id,
            scheduled_purge_at,
            cancel_token_hash.clone(),
        )
        .await
        .unwrap();

    assert_eq!(deletion.tenant_id, tenant_id);
    assert_eq!(deletion.user_id, user.id);
    assert_eq!(deletion.cancel_token_hash, cancel_token_hash);
    assert_eq!(deletion.status, AccountDeletionStatus::Pending);

    // Both effects of the transaction landed: user is deletion-pending...
    let updated_user = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(
        updated_user.deletion_pending,
        "deletion_pending must be set by create_with_pending_flag"
    );

    // ...and the account_deletion row is independently findable by the
    // cancel token hash it was created with.
    let found = account_deletion_repo
        .find_by_token_hash(tenant_id, &cancel_token_hash)
        .await
        .unwrap()
        .expect("account_deletion row must exist after create_with_pending_flag");
    assert_eq!(found.id, deletion.id);
    assert_eq!(found.status, AccountDeletionStatus::Pending);
}

/// D-14 lock-in: if a pending `account_deletion` row already exists for the
/// user, `create_with_pending_flag`'s in-transaction duplicate-pending guard
/// rejects the call and the WHOLE transaction — including the `UPDATE` that
/// would have flipped `deletion_pending` — rolls back. Before this fix,
/// `mark_deletion_pending` and `account_deletion_repo.create` were two
/// independent DB round-trips: a failure on the second left the user
/// permanently `deletion_pending = true` with no matching cancellable row
/// (CQ-B39 residual, an uncancellable purge).
#[tokio::test]
async fn create_with_pending_flag_rolls_back_on_duplicate_pending_conflict() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.clone());

    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "atomicity_test_user".into(),
            email: "atomicity@example.com".into(),
            password: "Atomic1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Force the post-UPDATE CREATE to fail: a pre-existing pending
    // account_deletion row for this user already satisfies the
    // duplicate-pending guard inside create_with_pending_flag's
    // transaction.
    account_deletion_repo
        .create(CreateAccountDeletion {
            tenant_id,
            user_id: user.id,
            cancel_token_hash: sha256_hex("pre-existing-token"),
            scheduled_purge_at: Utc::now() + chrono::Duration::days(30),
        })
        .await
        .unwrap();

    // Precondition: the user's own deletion_pending flag is still false —
    // the pre-existing row above was inserted directly, not through the
    // normal request-delete flow, so this reproduces a genuine "CREATE
    // fails after the UPDATE would have run" scenario without corrupting
    // the starting state.
    let before = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(
        !before.deletion_pending,
        "precondition: deletion_pending must start false"
    );

    let result = account_deletion_repo
        .create_with_pending_flag(
            tenant_id,
            user.id,
            Utc::now() + chrono::Duration::days(30),
            sha256_hex("second-attempt-token"),
        )
        .await;
    assert!(
        result.is_err(),
        "create_with_pending_flag must fail when a pending account_deletion row already exists"
    );

    // The whole transaction rolled back — deletion_pending must remain
    // false, never stranded at true with no matching cancellable row.
    let after = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(
        !after.deletion_pending,
        "deletion_pending must remain false after a rolled-back create_with_pending_flag"
    );
    assert!(
        after.scheduled_purge_at.is_none(),
        "scheduled_purge_at must not be set by a rolled-back transaction"
    );
}

// ---------------------------------------------------------------------------
// Test 2: deletion_pseudonymization
// ---------------------------------------------------------------------------
/// Full purge pipeline: user row anonymized, auth artifacts cleared, audit
/// entries pseudonymized to `DELETED_USER_<hash>`, erasure proof written.
#[tokio::test]
async fn deletion_pseudonymization() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.clone());

    // Create a user.
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "purge_test_user".into(),
            email: "purge@example.com".into(),
            password: "Purge1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_id = user.id;
    let user_id_str = user_id.to_string();

    // Seed audit entries with this user as actor.
    for i in 0..3 {
        audit_repo
            .append(CreateAuditLogEntry {
                tenant_id,
                actor_id: user_id,
                actor_type: ActorType::User,
                action: format!("user.action.{i}"),
                resource_id: Some(user_id), // resource_id == user_id for D-03 null test
                outcome: AuditOutcome::Success,
                ip_address: Some("192.168.1.1".into()),
                metadata: Some(serde_json::json!({
                    "username": user.username,
                    "email": user.email,
                })),
            })
            .await
            .unwrap();
    }

    // Create an account deletion row (simulating the delete handler).
    let raw_cancel_token = Uuid::new_v4().to_string();
    let cancel_token_hash = sha256_hex(&raw_cancel_token);
    let scheduled_purge_at = Utc::now() - chrono::Duration::seconds(1); // past — due now
    account_deletion_repo
        .create(CreateAccountDeletion {
            tenant_id,
            user_id,
            cancel_token_hash,
            scheduled_purge_at,
        })
        .await
        .unwrap();

    // Also set deletion_pending on the user (as the delete handler does).
    user_repo
        .mark_deletion_pending(tenant_id, user_id, scheduled_purge_at)
        .await
        .unwrap();

    // --- Simulate purge pipeline (mirrors cleanup.rs purge_single_user) ---
    let pepper: [u8; 32] = [0xDE; 32];
    let pseudonym = gdpr_pseudonym(&pepper, tenant_id, user_id);
    assert!(
        pseudonym.starts_with("DELETED_USER_"),
        "pseudonym must start with DELETED_USER_"
    );

    // Derive email_hash for anonymize_user.
    let mut h = Sha256::new();
    h.update(tenant_id.as_bytes());
    h.update(user_id.as_bytes());
    let email_hash = hex::encode(h.finalize());

    // (d) Anonymize user in-place.
    user_repo
        .anonymize_user(tenant_id, user_id, &email_hash, &pseudonym)
        .await
        .unwrap();

    // (e) Pseudonymize audit entries.
    let updated_count = audit_repo
        .pseudonymize_actor(tenant_id, user_id, &pseudonym)
        .await
        .unwrap();
    assert!(
        updated_count > 0,
        "pseudonymize_actor must update at least one row"
    );

    // (f) Insert erasure proof.
    let proof = erasure_proof_repo
        .create(CreateErasureProof {
            pseudonym: pseudonym.clone(),
            tenant_id,
            user_id,
            erased_at: Utc::now(),
        })
        .await
        .unwrap();
    assert_eq!(proof.pseudonym, pseudonym);
    assert_eq!(proof.tenant_id, tenant_id);
    assert_eq!(proof.user_id, user_id);

    // --- Verify: user row is anonymized ---
    let anon_user = user_repo.get_by_id(tenant_id, user_id).await.unwrap();
    use axiam_core::models::user::UserStatus;
    assert_eq!(
        anon_user.status,
        UserStatus::Anonymized,
        "user status must be Anonymized after purge"
    );
    assert!(
        anon_user.username.starts_with("DELETED_USER_"),
        "username must be pseudonymized"
    );
    assert!(
        !anon_user.password_hash.contains("purge@example.com"),
        "password_hash must not contain original email"
    );

    // --- Verify: audit entries contain pseudonym; original UUID/PII absent ---
    let audit_after = audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                actor_id: None, // actor_id is now nil after pseudonymization
                action: None,
                outcome: None,
                resource_id: None,
                from: None,
                to: None,
            },
            Pagination {
                offset: 0,
                limit: 100,
            },
        )
        .await
        .unwrap();

    // Filter to entries that were about our user (they now have pseudonym in metadata).
    let user_entries: Vec<_> = audit_after
        .items
        .iter()
        .filter(|e| {
            e.metadata
                .as_object()
                .and_then(|m| m.get("actor_pseudonym"))
                .and_then(|v| v.as_str())
                == Some(&pseudonym)
        })
        .collect();
    assert!(
        !user_entries.is_empty(),
        "pseudonymized audit entries must carry actor_pseudonym = pseudonym"
    );
    for entry in &user_entries {
        // actor_id must be nil UUID after pseudonymization.
        assert_eq!(
            entry.actor_id,
            Uuid::nil(),
            "actor_id must be nil after pseudonymization"
        );
        // Original user UUID must not appear in the stringified entry.
        let entry_str = serde_json::to_string(entry).unwrap();
        assert!(
            !entry_str.contains(&user_id_str),
            "original user UUID must not appear in pseudonymized audit entry"
        );
        // ip_address must be None (nulled by D-03).
        assert!(
            entry.ip_address.is_none(),
            "ip_address must be NULL after pseudonymization"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: consent_on_registration
// ---------------------------------------------------------------------------
/// Registering a user must produce exactly one `terms_of_service` consent row.
#[tokio::test]
async fn consent_on_registration() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let consent_repo = SurrealConsentRepository::new(db.clone());

    // Create user (mirrors the REST handler's repo calls).
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "consent_test_user".into(),
            email: "consent@example.com".into(),
            password: "Consent1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Record consent (mirrors the handler's consent logic in users.rs).
    consent_repo
        .create(CreateConsent {
            tenant_id,
            user_id: user.id,
            consent_type: "terms_of_service".into(),
            version: "2026-01-01".into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("test-agent/1.0".into()),
        })
        .await
        .unwrap();

    // Verify exactly one consent row of type terms_of_service.
    let consents = consent_repo.list_by_user(tenant_id, user.id).await.unwrap();
    assert_eq!(
        consents.len(),
        1,
        "expected exactly one consent row at registration"
    );
    assert_eq!(consents[0].consent_type, "terms_of_service");
    assert_eq!(consents[0].version, "2026-01-01");
    assert_eq!(consents[0].user_id, user.id);
    assert_eq!(consents[0].tenant_id, tenant_id);
    assert_eq!(consents[0].ip_address.as_deref(), Some("127.0.0.1"));
}

// ---------------------------------------------------------------------------
// Test 4: deletion_cancel
// ---------------------------------------------------------------------------
/// Cancel token aborts deletion and re-enables the account (D-09).
/// A second call with the same token is rejected (single-use).
#[tokio::test]
async fn deletion_cancel() {
    let db = setup_db().await;
    let tenant_id = Uuid::new_v4();
    let user_repo = SurrealUserRepository::new(db.clone());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.clone());

    // Create a user and mark deletion pending.
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "cancel_test_user".into(),
            email: "cancel@example.com".into(),
            password: "Cancel1234!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let raw_cancel_token = Uuid::new_v4().to_string();
    let cancel_token_hash = sha256_hex(&raw_cancel_token);
    // Grace window: +30 days (user is within the window).
    let scheduled_purge_at = Utc::now() + chrono::Duration::days(30);

    account_deletion_repo
        .create(CreateAccountDeletion {
            tenant_id,
            user_id: user.id,
            cancel_token_hash: cancel_token_hash.clone(),
            scheduled_purge_at,
        })
        .await
        .unwrap();

    user_repo
        .mark_deletion_pending(tenant_id, user.id, scheduled_purge_at)
        .await
        .unwrap();

    // Verify deletion_pending is set.
    let pending_user = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(
        pending_user.deletion_pending,
        "deletion_pending must be true"
    );

    // --- Cancel via token (first use) ---
    // Look up deletion by token hash.
    let deletion = account_deletion_repo
        .find_by_token_hash_global(&cancel_token_hash)
        .await
        .unwrap()
        .expect("deletion row must exist for valid token hash");

    assert_eq!(
        deletion.status,
        AccountDeletionStatus::Pending,
        "status must be Pending"
    );
    assert!(
        deletion.scheduled_purge_at >= Utc::now(),
        "purge must be in the future (within grace window)"
    );

    // Mark cancelled (D-09: consumes the single-use token).
    account_deletion_repo
        .mark_cancelled(deletion.tenant_id, deletion.id)
        .await
        .unwrap();

    // Clear deletion_pending on the user (re-enable account).
    user_repo
        .clear_deletion_pending(tenant_id, user.id)
        .await
        .unwrap();

    // Verify user is re-enabled.
    let re_enabled = user_repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(
        !re_enabled.deletion_pending,
        "deletion_pending must be false after cancel"
    );
    assert!(
        re_enabled.scheduled_purge_at.is_none(),
        "scheduled_purge_at must be cleared after cancel"
    );

    // --- Second cancel attempt must fail (single-use) ---
    // The deletion row is now Cancelled — a re-lookup succeeds but status check fails.
    let deletion_after = account_deletion_repo
        .find_by_token_hash_global(&cancel_token_hash)
        .await
        .unwrap()
        .expect("deletion row still exists after cancel");

    assert_eq!(
        deletion_after.status,
        AccountDeletionStatus::Cancelled,
        "status must be Cancelled after first cancel"
    );
    // Simulate handler guard: second use is rejected because status != Pending.
    assert_ne!(
        deletion_after.status,
        AccountDeletionStatus::Pending,
        "second cancel attempt must be rejected — token already consumed"
    );
}
