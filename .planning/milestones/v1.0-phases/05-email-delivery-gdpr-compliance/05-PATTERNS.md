# Phase 5: Email Delivery & GDPR Compliance - Pattern Map

**Mapped:** 2026-06-02
**Files analyzed:** 18 new/modified files
**Analogs found:** 16 / 18

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-amqp/src/connection.rs` (modify) | config | event-driven | self | exact |
| `crates/axiam-amqp/src/messages.rs` (modify) | model | event-driven | self | exact |
| `crates/axiam-amqp/src/mail_consumer.rs` (new) | service | event-driven | `crates/axiam-amqp/src/audit_consumer.rs` | exact |
| `crates/axiam-db/src/repository/email_config.rs` (new) | repository | CRUD | `crates/axiam-db/src/repository/federation_config.rs` | exact |
| `crates/axiam-db/src/repository/audit.rs` (modify) | repository | CRUD | self | exact |
| `crates/axiam-db/src/repository/user.rs` (modify) | repository | CRUD | self | exact |
| `crates/axiam-db/src/repository/consent.rs` (new) | repository | CRUD | `crates/axiam-db/src/repository/email_template.rs` | role-match |
| `crates/axiam-db/src/repository/account_deletion.rs` (new) | repository | CRUD | `crates/axiam-db/src/repository/email_verification_token.rs` | role-match |
| `crates/axiam-db/src/repository/export_job.rs` (new) | repository | CRUD | `crates/axiam-db/src/repository/email_verification_token.rs` | role-match |
| `crates/axiam-db/src/schema.rs` (modify) | migration | CRUD | self | exact |
| `crates/axiam-auth/src/crypto.rs` (modify) | utility | transform | self | exact |
| `crates/axiam-server/src/cleanup.rs` (modify) | service | batch | self | exact |
| `crates/axiam-server/src/main.rs` (modify) | config | request-response | self | exact |
| `crates/axiam-api-rest/src/handlers/password_reset.rs` (modify) | controller | request-response | self | exact |
| `crates/axiam-api-rest/src/handlers/email_verification.rs` (modify) | controller | request-response | self | exact |
| `crates/axiam-api-rest/src/handlers/gdpr.rs` (new) | controller | request-response | `crates/axiam-api-rest/src/handlers/password_reset.rs` | role-match |
| `crates/axiam-audit/src/notification.rs` (modify) | service | event-driven | `crates/axiam-amqp/src/audit_consumer.rs` | partial |
| `crates/axiam-core/src/models/email_template.rs` (modify) | model | transform | self | exact |

---

## Pattern Assignments

### `crates/axiam-amqp/src/mail_consumer.rs` (new — service, event-driven)

**Analog:** `crates/axiam-amqp/src/audit_consumer.rs`

**Imports pattern** (audit_consumer.rs lines 1-12):
```rust
use axiam_core::repository::AuditLogRepository;
use futures_lite::StreamExt;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};
use crate::connection::queues;
use crate::messages::AuditEventMessage;
```

**Consumer loop pattern** (audit_consumer.rs lines 33-150 — full file):
```rust
pub async fn start_audit_consumer<A>(channel: Channel, audit_repo: A)
where
    A: AuditLogRepository + 'static,
{
    info!("Starting audit event AMQP consumer");

    let mut consumer = match channel
        .basic_consume(
            queues::AUDIT_EVENTS.into(),
            "axiam-audit-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to start audit event consumer");
            return;
        }
    };

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving audit event delivery");
                continue;
            }
        };

        let tag = delivery.delivery_tag;

        let msg: AuditEventMessage = match serde_json::from_slice(&delivery.data) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, delivery_tag = tag, "Invalid payload, nacking");
                let _ = delivery.acker.nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                }).await;
                continue;
            }
        };

        // ... process msg ...

        if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
            error!(error = %e, delivery_tag = tag, "Failed to ack delivery");
        }
    }

    warn!("Consumer stream ended");
}
```

**Mail consumer additions vs audit consumer:**
- New parameter: `email_config_repo: impl EmailConfigRepository`
- New parameter: `audit_repo: impl AuditLogRepository` (for `email.delivery_failed` events)
- Retry logic: embed `attempt_count` in `OutboundMailMessage`; re-publish with incremented count if `count < MAX_RETRIES`; on exhaustion nack with `requeue: false` and append audit event
- On nack-final: `audit_repo.append(CreateAuditLogEntry { action: "email.delivery_failed", metadata: json!({ provider, error_class, attempt_count, mail_type }), actor_id: msg.user_id, ... })`
- `to_address` is in `OutboundMailMessage` for delivery — MUST NOT appear in audit metadata (D-16)

---

### `crates/axiam-amqp/src/connection.rs` (modify — add new queues + DLQ)

**Analog:** self

**Current queues module** (connection.rs lines 12-21):
```rust
pub mod queues {
    pub const AUTHZ_REQUEST: &str  = "axiam.authz.request";
    pub const AUTHZ_RESPONSE: &str = "axiam.authz.response";
    pub const AUDIT_EVENTS: &str   = "axiam.audit.events";
    pub const NOTIFICATIONS: &str  = "axiam.notifications";
}

const ALL_QUEUES: &[&str] = &[
    queues::AUTHZ_REQUEST, queues::AUTHZ_RESPONSE,
    queues::AUDIT_EVENTS,  queues::NOTIFICATIONS,
];
```

**Add to queues module:**
```rust
pub const MAIL_OUTBOUND: &str     = "axiam.mail.outbound";
pub const MAIL_OUTBOUND_DLQ: &str = "axiam.mail.outbound.dlq";
```

**DLQ declaration pattern** (add alongside normal durable queues in `declare_queues`):
```rust
// DLQ declared first (no x-dead-letter-exchange itself)
self.channel
    .queue_declare(queues::MAIL_OUTBOUND_DLQ.into(), options, FieldTable::default())
    .await
    .map_err(AmqpError::Declaration)?;

// Main queue with x-dead-letter-exchange pointing to DLQ
let mut mail_args = FieldTable::default();
mail_args.insert(
    "x-dead-letter-exchange".into(),
    lapin::types::AMQPValue::LongString(queues::MAIL_OUTBOUND_DLQ.into()),
);
self.channel
    .queue_declare(queues::MAIL_OUTBOUND.into(), options, mail_args)
    .await
    .map_err(AmqpError::Declaration)?;
```

---

### `crates/axiam-amqp/src/messages.rs` (modify — add OutboundMailMessage)

**Analog:** self (existing message types)

**Existing message pattern** (messages.rs lines 1-61 — full file):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationEvent {
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
```

**New message type to add:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMailMessage {
    pub mail_type: MailType,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub to_address: String,   // delivery only — NEVER log in audit (D-16)
    pub template_context: serde_json::Value,
    pub attempt_count: u32,
    pub enqueued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailType {
    PasswordReset,
    EmailVerification,
    Notification,
    DeletionCancel,
    ExportReady,
}
```

---

### `crates/axiam-db/src/repository/email_config.rs` (new — repository, CRUD)

**Analog:** `crates/axiam-db/src/repository/federation_config.rs`

**Imports pattern** (federation_config.rs lines 1-14):
```rust
use axiam_core::error::AxiamResult;
use axiam_core::models::federation::{...};
use axiam_core::repository::{FederationConfigRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use crate::error::DbError;
```

**Row struct pattern** (federation_config.rs lines 19-58):
```rust
#[derive(Debug, SurrealValue)]
struct FederationConfigRow {
    tenant_id: String,
    // ... domain fields ...
    client_secret_ciphertext: Option<String>,
    client_secret_nonce: Option<String>,
    client_secret_key_version: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct FederationConfigRowWithId {
    record_id: String,          // meta::id() extraction
    // ... same fields ...
}
```

**Repository struct + Clone** (federation_config.rs lines 139-155):
```rust
pub struct SurrealFederationConfigRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealFederationConfigRepository<C> {
    fn clone(&self) -> Self { Self { db: self.db.clone() } }
}

impl<C: Connection> SurrealFederationConfigRepository<C> {
    pub fn new(db: Surreal<C>) -> Self { Self { db } }
}
```

**CREATE pattern** (federation_config.rs lines 163-199):
```rust
let result = self
    .db
    .query("CREATE type::record('federation_config', $id) SET \
            tenant_id = $tenant_id, ...")
    .bind(("id", id.to_string()))
    .bind(("tenant_id", input.tenant_id.to_string()))
    // ...
    .await
    .map_err(DbError::from)?;

let mut result = result
    .check()
    .map_err(|e| DbError::Migration(e.to_string()))?;
let rows: Vec<FederationConfigRow> = result.take(0).map_err(DbError::from)?;
let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound { ... })?;
```

**Email config row struct differs:** uses `smtp_password_ciphertext`, `smtp_password_nonce`, `api_key_ciphertext`, `api_key_nonce`, `secret_key_version` (all `Option<String>`/`Option<i64>`). Decrypt at read-time using `axiam_auth::crypto::decrypt_separate(&key, &nonce, &ct)` before returning `EmailConfig`.

---

### `crates/axiam-db/src/repository/audit.rs` (modify — add `pseudonymize_actor`)

**Analog:** self

**Existing append pattern** (audit.rs lines 154+):
```rust
// The privileged UPDATE path (D-04) differs from all other audit ops.
// It must SET actor_id = nil_uuid, metadata.actor_pseudonym = pseudonym,
// ip_address = NULL, resource_id = NULL where resource_id = user_id.
// Schema permission relaxation (v15 migration) required before this works.
```

**New method shape** (add to `SurrealAuditLogRepository<C>` impl block):
```rust
pub async fn pseudonymize_actor(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
) -> AxiamResult<u64> {
    // Issues UPDATE — requires schema v15 permission relaxation
    // Returns count of rows updated
}
```

---

### `crates/axiam-db/src/repository/consent.rs` (new — repository, CRUD)

**Analog:** `crates/axiam-db/src/repository/email_template.rs`

**Row struct pattern** (email_template.rs lines 18-41):
```rust
#[derive(Debug, SurrealValue)]
struct TemplateRow {
    scope: String,
    scope_id: String,
    kind: String,
    // ... fields ...
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct TemplateRowWithId {
    record_id: String,
    // ... same fields ...
}

impl TemplateRowWithId {
    fn try_into_domain(self) -> Result<EmailTemplate, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("bad UUID: {e}")))?;
        // ... field conversions ...
    }
}
```

**Consent-specific shape:** `tenant_id: String`, `user_id: String`, `consent_type: String`, `version: String`, `accepted_at: DateTime<Utc>`, `ip_address: Option<String>`, `user_agent: Option<String>`. No `updated_at` (consent records are immutable).

**Atomicity note (pitfall 5):** When recording consent at registration, use a single `.query()` call that creates both user and consent in one SurrealDB transaction — see user.rs `CREATE type::record(...)` pattern.

---

### `crates/axiam-db/src/repository/account_deletion.rs` (new — repository, CRUD)

**Analog:** `crates/axiam-db/src/repository/email_verification_token.rs`

**Token-hash storage pattern** (email_verification_token.rs — similar shape):
```rust
// Store cancel_token_hash (not raw token); return raw token to caller only at creation time.
// Fields: tenant_id, user_id, cancel_token_hash, scheduled_purge_at, status, created_at
// status ASSERT: ['pending', 'cancelled', 'completed']
```

---

### `crates/axiam-db/src/repository/export_job.rs` (new — repository, CRUD)

**Analog:** `crates/axiam-db/src/repository/email_verification_token.rs`

**Expiring-record pattern:** Fields: `tenant_id`, `user_id`, `status`, `encrypted_blob` (or `file_path`), `download_token_hash`, `expires_at`, `created_at`. Single-use token: consumed on first download; purge on expiry. All same `SurrealValue` derive, `CREATE type::record(...)`, `meta::id(id) AS record_id` on SELECT.

---

### `crates/axiam-db/src/repository/user.rs` (modify — add deletion/anonymization methods)

**Analog:** self

**Existing soft-delete pattern** (user.rs lines 411-428):
```rust
async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
    // Soft-delete: set status to Inactive.
    let id_str = id.to_string();
    let tenant_id_str = tenant_id.to_string();

    self.db
        .query(
            "UPDATE type::record('user', $id) SET \
             status = 'Inactive', updated_at = time::now() \
             WHERE tenant_id = $tenant_id",
        )
        .bind(("id", id_str))
        .bind(("tenant_id", tenant_id_str))
        .await
        .map_err(DbError::from)?;

    Ok(())
}
```

**New methods to add:**
```rust
// Mark deletion-pending (D-08)
pub async fn mark_deletion_pending(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    scheduled_purge_at: DateTime<Utc>,
) -> AxiamResult<()>

// Anonymize user in-place at purge time (D-05) — sets email=hash, username=pseudonym,
// password_hash=NULL, mfa_secret=NULL, metadata={}, status='Anonymized'
pub async fn anonymize_user(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    email_hash: &str,
    pseudonym: &str,
) -> AxiamResult<()>

// Find users past their purge date (for CleanupTask sweep)
pub async fn find_due_for_purge(
    &self,
    now: DateTime<Utc>,
) -> AxiamResult<Vec<User>>
```

Also add `deletion_pending: Option<bool>` and `scheduled_purge_at: Option<DateTime<Utc>>` to `UserRow` and `UserRowWithId` structs (pitfall 4).

---

### `crates/axiam-db/src/schema.rs` (modify — add migration v15)

**Analog:** self

**Migration registration pattern** (schema.rs lines 40-111):
```rust
static MIGRATIONS: &[Migration] = &[
    Migration { version: 1,  name: "initial_schema",          sql: SCHEMA_V1  },
    // ...
    Migration { version: 14, name: "webauthn_credentials",    sql: SCHEMA_V14 },
    // ADD:
    Migration { version: 15, name: "phase5_email_gdpr",       sql: SCHEMA_V15 },
];
```

**New table DDL pattern** (schema.rs lines 704-725 — SCHEMA_V10 email_template as reference):
```sql
-- email_template SCHEMAFULL table (reference shape):
DEFINE TABLE email_template SCHEMAFULL;
DEFINE FIELD scope ON TABLE email_template TYPE string
    ASSERT $value IN ['org', 'tenant'];
DEFINE FIELD scope_id ON TABLE email_template TYPE string;
DEFINE FIELD kind ON TABLE email_template TYPE string
    ASSERT $value IN ['activation', 'password_reset', 'mfa_setup_reminder', 'admin_notification'];
-- ... more fields ...
DEFINE INDEX idx_email_template_scope_kind ON TABLE email_template
    COLUMNS scope, scope_id, kind UNIQUE;
```

**ALTER existing table pattern** (schema.rs lines 731-751 — SCHEMA_V11 adds field to user table):
```sql
-- Add email_verified_at to user table
DEFINE FIELD email_verified_at ON TABLE user TYPE option<datetime>;
```

**SCHEMA_V15 must contain (full list):**
1. New `email_config` table (SCHEMAFULL, with `smtp_password_ciphertext`, `smtp_password_nonce`, `api_key_ciphertext`, `api_key_nonce`, `secret_key_version` columns)
2. New `consent` table (SCHEMAFULL)
3. New `account_deletion` table (SCHEMAFULL)
4. New `export_job` table (SCHEMAFULL)
5. New `erasure_proof` table (SCHEMAFULL — PII-free: `pseudonym`, `tenant_id`, `erased_at`)
6. ALTER `user` table: add `deletion_pending BOOL DEFAULT false`, `scheduled_purge_at option<datetime>`
7. ALTER `user.status` ASSERT: add `'Anonymized'` to the allowed values
8. ALTER `audit_log` permissions: add `FOR update WHERE $auth.role = 'gdpr_pseudonymizer'` (or document root-auth approach)
9. ALTER `email_template.kind` ASSERT: add `'deletion_scheduled'`, `'export_ready'`

---

### `crates/axiam-auth/src/crypto.rs` (modify — add HMAC pseudonym helper)

**Analog:** self + `crates/axiam-api-rest/src/webhook.rs`

**HMAC-SHA256 pattern** (webhook.rs lines 4-9, 133-137):
```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn compute_signature(secret: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
```

**New function to add to crypto.rs:**
```rust
/// Compute GDPR audit pseudonym for a deleted user (D-02).
///
/// Returns `"DELETED_USER_{16-char-hex}"` — deterministic for the same
/// (pepper, tenant_id, user_id) tuple; brute-force-resistant via keyed HMAC.
pub fn gdpr_pseudonym(pepper: &[u8; 32], tenant_id: Uuid, user_id: Uuid) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper)
        .expect("HMAC accepts any key length");
    mac.update(tenant_id.as_bytes());
    mac.update(user_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("DELETED_USER_{}", hex::encode(&tag[..8]))
}
```

Note: `hex` crate is already a workspace dep (verified: used in `webhook.rs` via `hex::encode`). Add `use hmac::{Hmac, Mac}; use sha2::Sha256;` imports to crypto.rs (already workspace deps).

**AES-256-GCM split-output** (crypto.rs lines 92-136 — already correct, confirmed function names):
```rust
// encrypt_separate(key: &[u8; 32], plaintext: &[u8]) -> Result<(String, String), AuthError>
// Returns (nonce_b64, ciphertext_with_tag_b64)
// decrypt_separate(key: &[u8; 32], nonce_b64: &str, ciphertext_b64: &str) -> Result<Vec<u8>, AuthError>
```

---

### `crates/axiam-server/src/cleanup.rs` (modify — extend for purge and export sweeps)

**Analog:** self

**CleanupTask struct pattern** (cleanup.rs lines 20-89 — full file):
```rust
pub struct CleanupTask<C: Connection> {
    replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
    state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
}

impl<C: Connection + Send + Sync + 'static> CleanupTask<C> {
    pub async fn run(mut self) -> Result<(), AxiamError> {
        let mut ticker = tokio::time::interval(self.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.replay_repo.cleanup_expired().await {
                        Ok(n) if n > 0 => { tracing::debug!(deleted = n, "..."); }
                        Ok(_) => {}
                        Err(e) => { tracing::warn!(error = ?e, "... cleanup failed"); }
                    }
                }
                changed = self.shutdown.changed() => {
                    if changed.is_ok() && *self.shutdown.borrow() {
                        tracing::info!("cleanup task received shutdown signal");
                        return Ok(());
                    }
                }
            }
        }
    }
}
```

**Extension pattern:** Add to constructor and struct:
- `user_repo: Arc<SurrealUserRepository<C>>`
- `auth_svc: Arc<AuthService<C>>`  (for session revocation cascade)
- `audit_repo: Arc<SurrealAuditLogRepository<C>>`
- `gdpr_pepper: Option<[u8; 32]>`
- `export_encryption_key: Option<[u8; 32]>`

Add two sweep arms inside `_ = ticker.tick() =>` block:
1. `sweep_pending_purges()` — finds users with `deletion_pending = true AND scheduled_purge_at <= now`; runs full purge pipeline
2. `sweep_pending_exports()` — finds export_jobs with `status = 'queued'`; generates/encrypts JSON; enqueues `ExportReady` mail

Each sweep arm follows the existing `match .await { Ok(n) => ..., Err(e) => warn! }` pattern.

---

### `crates/axiam-server/src/main.rs` (modify — load new keys + spawn extended cleanup)

**Analog:** self

**Env key loading pattern** (main.rs lines 82-112 — exact copy-paste template):
```rust
if let Ok(hex) = std::env::var("AXIAM__AUTH__MFA_ENCRYPTION_KEY") {
    let bytes = hex::decode(&hex).expect(
        "AXIAM__AUTH__MFA_ENCRYPTION_KEY must be a 64-char hex string (32 bytes / 256 bits)",
    );
    let key: [u8; 32] = bytes
        .try_into()
        .expect("AXIAM__AUTH__MFA_ENCRYPTION_KEY must be exactly 32 bytes (256 bits)");
    config.auth.mfa_encryption_key = Some(key);
    tracing::info!("MFA encryption key loaded");
} else {
    tracing::warn!("AXIAM__AUTH__MFA_ENCRYPTION_KEY not set ...");
}
```

**New keys to load with same pattern:**
- `AXIAM__EMAIL_ENCRYPTION_KEY` → `config.email_encryption_key: Option<[u8; 32]>`
- `AXIAM__GDPR_PSEUDONYM_PEPPER` → `config.gdpr_pseudonym_pepper: Option<[u8; 32]>`

**Backfill migration pattern** (main.rs lines 139-162):
```rust
// Boot backfill: encrypt any legacy plaintext federation client_secret rows (D-12).
// Idempotent — rows that are already encrypted are skipped.
{
    let boot_fed_repo = axiam_db::SurrealFederationConfigRepository::new(db.client().clone());
    let boot_audit_repo = axiam_db::SurrealAuditLogRepository::new(db.client().clone());
    if let Some(fed_key) = config.auth.federation_encryption_key {
        match axiam_federation::secrets::migrate_plaintext_federation_secrets(...).await {
            Ok(n) => tracing::info!(migrated = n, "..."),
            Err(e) => tracing::warn!(error = %e, "..."),
        }
    }
}
```

Same pattern for email-config plaintext backfill (D-17): `if ciphertext IS NULL AND password IS NOT NULL, encrypt and update`.

**AMQP consumer spawn pattern** (main.rs after line 213 — existing consumer spawn):
```rust
// Spawn mail consumer (same pattern as audit consumer spawn)
let mail_channel = amqp.create_channel().await.expect("mail channel");
let mail_email_config_repo = SurrealEmailConfigRepository::new(db_handle.clone());
let mail_audit_repo = SurrealAuditLogRepository::new(db_handle.clone());
tokio::spawn(axiam_amqp::start_mail_consumer(
    mail_channel,
    mail_email_config_repo,
    mail_audit_repo,
    config.email_encryption_key,
));
```

---

### `crates/axiam-api-rest/src/handlers/password_reset.rs` (modify — replace TODO stubs)

**Analog:** self

**TODO stub locations** (password_reset.rs lines 87-91):
```rust
Ok(Some((_raw_token, _user_id, _expires_at))) => {
    // TODO(T19): wire up actual email sending via EmailService
    tracing::debug!(email = %req.email, "password reset token created");
}
```

**Replace with enqueue pattern:**
```rust
Ok(Some((raw_token, user_id, expires_at))) => {
    let msg = OutboundMailMessage {
        mail_type: MailType::PasswordReset,
        tenant_id: req.tenant_id,
        org_id: /* resolved from tenant */,
        user_id,
        to_address: req.email.clone(),
        template_context: serde_json::json!({
            "token": raw_token,
            "expiry_time": expires_at.to_rfc3339(),
        }),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    };
    if let Err(e) = mail_publisher.publish(msg).await {
        tracing::warn!(error = %e, "failed to enqueue password-reset email");
        // Do NOT return error — D-15: uniform 200 regardless of delivery outcome
    }
}
```

Response stays `Ok(HttpResponse::Ok().json(json!({ "sent": true })))` unconditionally (D-15 enumeration-safe).

---

### `crates/axiam-api-rest/src/handlers/gdpr.rs` (new — controller, request-response)

**Analog:** `crates/axiam-api-rest/src/handlers/password_reset.rs`

**Handler structure pattern** (password_reset.rs lines 54-112 — full handler):
```rust
pub async fn request_password_reset(
    body: web::Json<PasswordResetRequest>,
    user_repo: web::Data<SurrealUserRepository<C>>,
    auth_config: web::Data<AuthConfig>,
    // ... repos ...
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    // ... service call ...
    Ok(HttpResponse::Ok().json(json!({ "sent": true })))
}
```

**Four new handlers in gdpr.rs:**
1. `POST /api/v1/account/export` — enqueues export job; returns `{"queued": true}`; requires `AuthenticatedUser` (self or `gdpr:export` permission)
2. `POST /api/v1/account/delete` — marks deletion-pending, revokes sessions, enqueues cancel-link mail, appends audit; requires `AuthenticatedUser` (self or `users:erase`)
3. `GET /auth/account/delete/cancel?token=<opaque>` — public endpoint; validates cancel token, aborts deletion, re-enables account
4. `GET /api/v1/account/export/{token}` — download export file (single-use token); deletes file on success

**Self-service ownership pattern:** Copy from Phase 3 handler:
```rust
// Ownership check mirrors Phase 3 /users/{id} self-service:
if auth_user.id != target_user_id {
    require_permission(&auth_user, "users:erase")?;
}
```

---

### `crates/axiam-audit/src/notification.rs` (modify — enqueue instead of return)

**Analog:** partially `crates/axiam-amqp/src/audit_consumer.rs`

**Current shape** (notification.rs line 68 TODO):
```
// TODO(T19): Send actual emails via EmailService with template resolution and org_id lookup
// Returns Vec<(event_name, recipient_emails)> for the caller to send.
```

**Replace with:** `NotificationDispatcher::dispatch` should accept an AMQP publisher and enqueue one `OutboundMailMessage { mail_type: MailType::Notification, ... }` per recipient instead of returning the list.

---

### `crates/axiam-core/src/models/email_template.rs` (modify — add TemplateKind variants)

**Analog:** self

**Existing TemplateKind ASSERT** (schema.rs line 712-714):
```sql
DEFINE FIELD kind ON TABLE email_template TYPE string
    ASSERT $value IN ['activation', 'password_reset',
                      'mfa_setup_reminder', 'admin_notification'];
```

**Add to Rust enum:** `DeletionScheduled` and `ExportReady`. Also extend:
- `TemplateKind::ALL` const array
- `builtin_template()` match arms for both new kinds
- `FromStr` impl parse arm for both new kinds
- Schema v15 ALTER to add `'deletion_scheduled'` and `'export_ready'` to the ASSERT

---

## Shared Patterns

### AMQP Publish (all handlers that enqueue mail)

**Source:** `crates/axiam-amqp/src/connection.rs` — `create_publisher_channel()` + `channel.basic_publish()`
**Apply to:** `password_reset.rs`, `email_verification.rs`, `gdpr.rs`, `notification.rs`

```rust
// Publish with publisher confirms (create_publisher_channel)
let payload = serde_json::to_vec(&msg).expect("serializable");
channel.basic_publish(
    "",                              // default exchange
    queues::MAIL_OUTBOUND,
    BasicPublishOptions::default(),
    &payload,
    BasicProperties::default().with_delivery_mode(2), // persistent
).await.map_err(AmqpError::from)?;
```

### AES-256-GCM Encryption at Rest

**Source:** `crates/axiam-auth/src/crypto.rs` lines 92-136 (`encrypt_separate` / `decrypt_separate`)
**Apply to:** `email_config.rs` repository (email secrets), `export_job.rs` (export file), `cleanup.rs` (export generation)

```rust
use axiam_auth::crypto::{encrypt_separate, decrypt_separate};

// Encrypt before DB write:
let (nonce_b64, ct_b64) = encrypt_separate(&key, plaintext.as_bytes())?;
// Store: smtp_password_nonce = nonce_b64, smtp_password_ciphertext = ct_b64

// Decrypt at read time:
let plaintext_bytes = decrypt_separate(&key, &nonce_b64, &ct_b64)?;
let plaintext = String::from_utf8(plaintext_bytes)?;
```

### Env Key Loading

**Source:** `crates/axiam-server/src/main.rs` lines 82-95 (MFA key pattern)
**Apply to:** `AXIAM__EMAIL_ENCRYPTION_KEY` and `AXIAM__GDPR_PSEUDONYM_PEPPER` in `main.rs`

```rust
if let Ok(hex) = std::env::var("AXIAM__EMAIL_ENCRYPTION_KEY") {
    let bytes = hex::decode(&hex)
        .expect("AXIAM__EMAIL_ENCRYPTION_KEY must be a 64-char hex string");
    let key: [u8; 32] = bytes
        .try_into()
        .expect("AXIAM__EMAIL_ENCRYPTION_KEY must be exactly 32 bytes");
    config.email_encryption_key = Some(key);
    tracing::info!("Email encryption key loaded");
} else {
    tracing::warn!("AXIAM__EMAIL_ENCRYPTION_KEY not set — email provider secrets unavailable");
}
```

### Template Rendering (HTML safety — D-18)

**Source:** `crates/axiam-email/src/template.rs` — `render_email()` (uses `render_html` internally)
**Apply to:** All new mail types in `mail_consumer.rs`

```rust
use axiam_email::template::{render_email, resolve_template, TemplateContext};

let mut ctx = TemplateContext::new();
ctx.insert("username".into(), user.username.clone()); // HTML-escaped by render_html
ctx.insert("action_url".into(), cancel_url);
ctx.insert("expiry_time".into(), purge_date.to_rfc3339());

let template = resolve_template(TemplateKind::DeletionScheduled, org_tmpl, tenant_tmpl);
let message = render_email(&template, &to_address, &ctx);
// message.html_body is HTML-escaped via render_html
// NEVER use render() for HTML bodies — only render_email() or render_html() directly
```

### Tenant-Scoped Repository Queries

**Source:** `crates/axiam-db/src/repository/user.rs` lines 248, 271, 294 (all tenant-scoped)
**Apply to:** All new repositories (`consent.rs`, `account_deletion.rs`, `export_job.rs`)

```rust
// Pattern: every query WHERE clause includes tenant_id = $tenant_id
"SELECT meta::id(id) AS record_id, * FROM consent \
 WHERE tenant_id = $tenant_id AND user_id = $user_id"
```

### SurrealDB Row Struct

**Source:** `crates/axiam-db/src/repository/audit.rs` lines 20-50
**Apply to:** All new repositories

```rust
// Two structs per table:
// 1. Without ID (for CREATE results — ID bound in query)
#[derive(Debug, SurrealValue)]
struct XxxRow { field: Type, ... }

// 2. With ID (for SELECT results using meta::id(id) AS record_id)
#[derive(Debug, SurrealValue)]
struct XxxRowWithId { record_id: String, field: Type, ... }

// CountRow reused across all repos:
#[derive(Debug, SurrealValue)]
struct CountRow { total: u64 }
```

### Error Handling / .check() Pattern

**Source:** `crates/axiam-db/src/repository/federation_config.rs` lines 191-194
**Apply to:** All new repository query calls

```rust
let mut result = result
    .check()
    .map_err(|e| DbError::Migration(e.to_string()))?;
let rows: Vec<XxxRow> = result.take(0).map_err(DbError::from)?;
```

### Test Mock Email Provider

**Source:** `crates/axiam-email/src/providers/mock.rs` lines 1-99 (full file)
**Apply to:** All mail consumer tests, GDPR handler tests

```rust
use axiam_email::providers::mock::MockProvider;
use axiam_email::service::EmailService;

// Succeeding mock:
let mock = MockProvider::new();
let sent_handle = mock.sent.clone();
let svc = EmailService::new(...).with_provider(Box::new(mock));

// Failing mock (for delivery-failure audit test):
let failing = MockProvider::failing();
let svc = EmailService::new(...).with_provider(Box::new(failing));

// Assertion:
assert_eq!(mock.sent_count(), 1);
let sent = mock.sent_messages();
assert_eq!(sent[0].message.to, "user@example.com");
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `crates/axiam-db/src/repository/erasure_proof.rs` | repository | CRUD | No PII-free deletion-proof record table exists; append-only INSERT only, no UPDATE/DELETE — closest is audit.rs but append-only is even simpler |

Planner: use the SurrealDB `CREATE type::record(...)` + `SurrealValue` derive pattern from any existing simple repo (e.g., `password_history.rs`) for this file. The table is INSERT-only, no other methods needed.

---

## Metadata

**Analog search scope:** `crates/axiam-amqp/`, `crates/axiam-db/src/repository/`, `crates/axiam-auth/src/`, `crates/axiam-server/src/`, `crates/axiam-api-rest/src/handlers/`, `crates/axiam-email/src/providers/`
**Files scanned:** 18 source files read (plus grep for line locations)
**Pattern extraction date:** 2026-06-02

### Verification Notes

- `encrypt_separate` / `decrypt_separate` — **CONFIRMED** exact function names in `axiam-auth/src/crypto.rs` lines 92 and 111
- `hex` crate — **CONFIRMED** workspace dep (used in `webhook.rs` via `hex::encode`)
- `futures_lite::StreamExt` — **CONFIRMED** in `audit_consumer.rs` line 5
- `audit_log FOR update NONE` — **CONFIRMED** at `schema.rs` line 310
- `EmailConfigRepository` trait — **CONFIRMED** defined at `repository.rs` line 1022, no SurrealDB impl exists
- `CleanupTask` shutdown pattern — **CONFIRMED** `tokio::select!` + `watch::Receiver<bool>` at `cleanup.rs` lines 57-86
- SCHEMA v15 is the next version — **CONFIRMED** v14 is `webauthn_credentials` at `schema.rs` line 108
