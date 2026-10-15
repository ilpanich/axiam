//! Broker-free tests for `process_audit_event` — the pure
//! decode/verify/replay/parse/persist logic factored out of the audit AMQP
//! consumer loop (R1). Each test calls `process_audit_event` directly with a
//! real kv-mem `SurrealAuditLogRepository` (or a failing mock), a real
//! `SurrealAmqpNonceRepository`, and the HMAC signing helpers from
//! `axiam_amqp::messages` — no live RabbitMQ broker.
//!
//! Covered branches: valid Ack (event persisted), malformed JSON,
//! unsigned/invalid HMAC, key_version below minimum, stale `issued_at`, an
//! action reserved for the server's control records (R101W3-03), nonce
//! replay, nonce-store error, unknown actor_type, unknown outcome, and a
//! persistence failure.

use std::sync::Mutex;

use axiam_amqp::audit_consumer::{AuditIngestOutcome, process_audit_event};
use axiam_amqp::messages::{
    AuditEventMessage, CURRENT_KEY_VERSION, derive_tenant_key, sign_payload,
};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::repository::{
    AmqpNonceRepository, AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination,
};
use axiam_db::SurrealAmqpNonceRepository;
use axiam_db::repository::SurrealAuditLogRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const MASTER: &[u8] = b"test-amqp-master-signing-key-for-audit";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

async fn setup_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn skew() -> Duration {
    Duration::seconds(300)
}

/// Build and sign an `AuditEventMessage`, returning the wire bytes.
#[allow(clippy::too_many_arguments)]
fn signed_event(
    tenant_id: Uuid,
    actor_id: Uuid,
    actor_type: &str,
    outcome: &str,
    action: &str,
    key_version: u8,
    issued_at: DateTime<Utc>,
    nonce: Uuid,
) -> Vec<u8> {
    let mut msg = AuditEventMessage {
        tenant_id,
        actor_id,
        actor_type: actor_type.into(),
        action: action.into(),
        resource_id: None,
        outcome: outcome.into(),
        ip_address: None,
        metadata: None,
        key_version,
        nonce,
        issued_at,
        hmac_signature: None,
    };
    let canonical = serde_json::to_vec(&msg).unwrap();
    let subkey = derive_tenant_key(MASTER, tenant_id, key_version);
    msg.hmac_signature = Some(sign_payload(&subkey, &canonical));
    serde_json::to_vec(&msg).unwrap()
}

// Mock nonce repo that always fails with a non-replay DB error.
struct FailingNonceRepo;
impl AmqpNonceRepository for FailingNonceRepo {
    async fn insert_nonce(
        &self,
        _tenant_id: Uuid,
        _nonce: Uuid,
        _expires_at: DateTime<Utc>,
    ) -> AxiamResult<()> {
        Err(AxiamError::Database("nonce store unavailable".into()))
    }
    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        Ok(0)
    }
}

// Mock audit repo whose `append` always fails, to exercise the persistence
// failure → NackDrop branch.
struct FailingAuditRepo;
impl AuditLogRepository for FailingAuditRepo {
    async fn append(&self, _input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        Err(AxiamError::Database("audit store unavailable".into()))
    }
    async fn list(
        &self,
        _t: Uuid,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _t: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _t: Uuid, _u: Uuid, _p: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn prune_older_than(&self, _cutoff: chrono::DateTime<chrono::Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

// Records how many appends happened without a DB, for the counting-only cases.
struct CountingAuditRepo {
    count: Mutex<u32>,
}
impl AuditLogRepository for CountingAuditRepo {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        *self.count.lock().unwrap() += 1;
        Ok(AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            action: input.action,
            resource_id: input.resource_id,
            outcome: input.outcome,
            ip_address: input.ip_address,
            metadata: input.metadata.unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
        })
    }
    async fn list(
        &self,
        _t: Uuid,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _t: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _t: Uuid, _u: Uuid, _p: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn prune_older_than(&self, _cutoff: chrono::DateTime<chrono::Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_event_is_acked_and_persisted() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let tenant_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let now = Utc::now();

    let raw = signed_event(
        tenant_id,
        actor_id,
        "User",
        "Success",
        "user.login",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );

    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::Ack));

    // The event must be durably persisted.
    let listed = audit_repo
        .list(
            tenant_id,
            AuditLogFilter::default(),
            Pagination {
                offset: 0,
                limit: 100,
                search: None,
            },
        )
        .await
        .unwrap();
    assert!(
        listed.items.iter().any(|e| e.action == "user.login"),
        "the ingested audit event must be persisted"
    );
}

#[tokio::test]
async fn lowercase_actor_and_outcome_are_accepted() {
    // parse_actor_type / parse_outcome accept snake/lower spellings too.
    let db = setup_db().await;
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let audit_repo = CountingAuditRepo {
        count: Mutex::new(0),
    };
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "service_account",
        "denied",
        "authz.check",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::Ack));
    assert_eq!(*audit_repo.count.lock().unwrap(), 1);
}

#[tokio::test]
async fn malformed_json_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let outcome = process_audit_event(
        b"{not-valid",
        &audit_repo,
        MASTER,
        &nonce_repo,
        skew(),
        Utc::now(),
    )
    .await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn unsigned_event_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let mut val: serde_json::Value = serde_json::from_slice(&signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        Utc::now(),
        Uuid::new_v4(),
    ))
    .unwrap();
    val.as_object_mut().unwrap().remove("hmac_signature");
    let raw = serde_json::to_vec(&val).unwrap();
    let outcome =
        process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), Utc::now()).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn wrong_signature_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let mut val: serde_json::Value = serde_json::from_slice(&signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        Utc::now(),
        Uuid::new_v4(),
    ))
    .unwrap();
    val["hmac_signature"] = serde_json::Value::String("deadbeef".into());
    let raw = serde_json::to_vec(&val).unwrap();
    let outcome =
        process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), Utc::now()).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn key_version_below_minimum_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let now = Utc::now();
    // Signed validly under kv1 to isolate the key_version gate.
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        1,
        now,
        Uuid::new_v4(),
    );
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn stale_issued_at_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let issued = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        issued,
        Uuid::new_v4(),
    );
    let now = issued + Duration::hours(1);
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn duplicate_nonce_replay_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let first = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(first, AuditIngestOutcome::Ack));
    let second = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(second, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn nonce_store_error_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome =
        process_audit_event(&raw, &audit_repo, MASTER, &FailingNonceRepo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn unknown_actor_type_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "Martian",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn unknown_outcome_is_nackdropped() {
    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Perhaps",
        "x",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

#[tokio::test]
async fn persistence_failure_is_nackdropped() {
    // A well-formed, verified, fresh, non-replayed event whose append fails
    // must be nacked (dead-letter), never acked.
    let db = setup_db().await;
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let now = Utc::now();
    let raw = signed_event(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "User",
        "Success",
        "x",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome =
        process_audit_event(&raw, &FailingAuditRepo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::NackDrop));
}

/// R101W3-03 (#637): an action in a namespace the server reserves for its
/// control records — every `tenants.*` record the tenant deletion and purge
/// read back (the export receipt, `tenants.deleted`, `tenants.purged`), the
/// `gdpr.*` records, in any case — is refused even when the message is validly
/// signed with the tenant's subkey, fresh and new, and nothing is persisted.
/// The review's probe: a forged `tenants.audit_exported` receipt with
/// `exported_through` 2100-01-01 was acknowledged and became the newest
/// receipt the deletion accepted. An ordinary action from the same producer is
/// still persisted.
#[tokio::test]
async fn a_reserved_control_action_is_refused_and_not_persisted() {
    use axiam_db::repository::tenant_purge::TENANT_CONTROL_ACTIONS;

    let db = setup_db().await;
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let nonce_repo = SurrealAmqpNonceRepository::new(db.clone());
    let tenant_id = Uuid::new_v4();
    let now = Utc::now();

    let mut reserved: Vec<&str> = TENANT_CONTROL_ACTIONS.to_vec();
    reserved.extend([
        "gdpr.user_pseudonymized",
        "gdpr.erasure_requested",
        "Tenants.Audit_Exported",
    ]);
    for action in reserved {
        // As the probe sent it: the receipt's metadata, signed by the tenant.
        let mut msg = AuditEventMessage {
            tenant_id,
            actor_id: Uuid::new_v4(),
            actor_type: "User".into(),
            action: action.into(),
            resource_id: Some(tenant_id),
            outcome: "Success".into(),
            ip_address: None,
            metadata: Some(serde_json::json!({
                "record_count": 0,
                "exported_through": "2100-01-01T00:00:00Z",
            })),
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: now,
            hmac_signature: None,
        };
        let canonical = serde_json::to_vec(&msg).unwrap();
        let subkey = derive_tenant_key(MASTER, tenant_id, CURRENT_KEY_VERSION);
        msg.hmac_signature = Some(sign_payload(&subkey, &canonical));
        let raw = serde_json::to_vec(&msg).unwrap();

        let outcome =
            process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
        assert!(
            matches!(outcome, AuditIngestOutcome::NackDrop),
            "{action} must be refused"
        );
    }
    let page = Pagination {
        offset: 0,
        limit: 100,
        search: None,
    };
    let listed = audit_repo
        .list(tenant_id, AuditLogFilter::default(), page.clone())
        .await
        .unwrap();
    assert!(listed.items.is_empty(), "no reserved action was persisted");

    let raw = signed_event(
        tenant_id,
        Uuid::new_v4(),
        "User",
        "Success",
        "tenant.audit_exported_lookalike",
        CURRENT_KEY_VERSION,
        now,
        Uuid::new_v4(),
    );
    let outcome = process_audit_event(&raw, &audit_repo, MASTER, &nonce_repo, skew(), now).await;
    assert!(matches!(outcome, AuditIngestOutcome::Ack));
    let listed = audit_repo
        .list(tenant_id, AuditLogFilter::default(), page)
        .await
        .unwrap();
    assert_eq!(
        listed.items.len(),
        1,
        "an ordinary action is still persisted"
    );
}
