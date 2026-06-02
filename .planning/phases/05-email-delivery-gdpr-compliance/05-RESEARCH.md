# Phase 5: Email Delivery & GDPR Compliance — Research

**Researched:** 2026-06-02
**Domain:** Email delivery wiring, GDPR Art. 15/17, append-only audit pseudonymization, async job infrastructure
**Confidence:** HIGH (all major claims verified against actual codebase files)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Audit Pseudonymization (Art. 17 ↔ append-only invariant)**
- D-01: Reconcile via controlled in-place PII overwrite. The invariant is redefined as: event facts (action, outcome, timestamp) are immutable; identifier/PII fields may be pseudonymized exactly once.
- D-02: `DELETED_USER_<hash>` uses keyed HMAC-SHA256(pepper, tenant_id || user_id), truncated. Pepper is a dedicated env-loaded key following the Phase 4 D-10 pattern.
- D-03: Full PII scrub: `actor_id` → nil UUID AND `metadata.actor_pseudonym = "DELETED_USER_<hash>"`; `ip_address` → NULL; `metadata` scanned for known PII keys; `resource_id` → nil where it equals the deleted user_id.
- D-04: Exactly one privileged repo method `pseudonymize_actor(tenant_id, user_id, hash)` — only non-INSERT write audit repo permits. Runs inside purge transaction. Emits fresh `gdpr.user_pseudonymized` audit event.

**Deletion Semantics (Art. 17)**
- D-05: Anonymize user row in place, not hard-delete. Scrub ALL PII columns (email, username, display name → hash/null; password_hash → null; status → `anonymized`). PII column inventory is a first-class deliverable.
- D-06: Hard-delete all auth artifacts: sessions, refresh tokens, MFA secret, password-reset/verify tokens, federation identity links, WebAuthn credentials. Retain minimal PII-free erasure-proof record.
- D-07: Self-service + admin-permission trigger. Ownership check mirrors Phase 3 self-service pattern.
- D-08: 30-day grace period. On request: account immediately disabled, marked `deletion_pending`, `scheduled_purge_at = now + 30d`. Destructive work runs at purge time.
- D-09: Cancellation via emailed one-time cancel link (server-generated token). Clicking aborts deletion and re-enables account. New email template type.

**GDPR Data Export (Art. 15)**
- D-10: Export scope: profile + consent + sessions (metadata only, NOT token values) + MFA enrollment status (NOT secret) + federation identities + role/group/permission assignments + audit entries where `actor_id = user`. Secrets excluded unconditionally.
- D-11: Format: single sectioned-by-entity JSON with `export_metadata` block + named sections.
- D-12: Async generation: request endpoint enqueues job; worker aggregates, writes JSON encrypted (AES-256-GCM), emails download link.
- D-13: Download link is opaque token, single-use, 24h TTL; export file deleted on download or expiry. Every export emits `gdpr.data_exported` audit event.

**Email Delivery & Failure Handling (REQ-6)**
- D-14: All outbound mail sent asynchronously via AMQP with retry. Five mail types: password reset, email verification, audit notifications, deletion-cancel link, export-ready link.
- D-15: Password-reset and email-verification request endpoints return uniform enumeration-safe response. Merely enqueue; account existence never leaks.
- D-16: `email.delivery_failed` audit event keyed on `user_id` (not raw email); `metadata = { provider, error_class, attempt_count, next_retry_at, mail_type }`.
- D-17: Provider secrets encrypted at rest mirroring Phase 4 federation-secret pattern: `AXIAM__EMAIL_ENCRYPTION_KEY` (32-byte base64), AES-256-GCM, ciphertext + nonce + key_version. Research must verify whether already implemented or aspirational stub.

**Template Escaping**
- D-18: Triple-stash `{{{...}}}` audit is moot — axiam-email uses custom `{{placeholder}}` engine. New wiring must use `render_html` for HTML bodies.

### Claude's Discretion
- Exact background-job/queue mechanism — strong recommendation to unify purge job, export job, and mail consumer onto one hardened primitive.
- Truncation length of the HMAC pseudonym; precise list of metadata PII keys to redact.
- Storage backend for encrypted export file (DB blob vs object store).
- AMQP exchange/queue topology and dead-letter configuration for mail queue; retry count and backoff schedule.
- Consent tracking model — planner to propose minimal model unless research surfaces richer requirement.
- New email templates for deletion-cancel and export-ready link flows.
- Endpoint paths for export/erase/cancel.

### Deferred Ideas (OUT OF SCOPE)
- Grace-window edge cases for already-issued tokens during 30-day window.
- Synchronous-download export fallback.
- Login-allowed-during-window cancellation UX.
- Consent richness: withdrawal tracking, per-purpose granularity.
- Export Art. 15(1) processing metadata.
- Email i18n / localized templates.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-6 | Wire EmailService to password reset, email verification, notification dispatcher; configurable provider; failure audit with retry info; template escaping; server-generated tokens only | §Email Abstraction and §AMQP Mail Queue sections |
| REQ-8 | GDPR Art. 15 data export, Art. 17 deletion+pseudonymization, consent tracking, two integration tests | §GDPR Art. 17 Pseudonymization and §GDPR Art. 15 Export sections |
</phase_requirements>

---

## Summary

Phase 5 wires the already-built `axiam-email` `EmailService` into three stub points (password reset `:88`, email verification `:105`, notification dispatcher `:68`), implements GDPR data-subject rights (Art. 15 export, Art. 17 erasure with audit pseudonymization), and delivers the consent tracking table.

**Critical finding — EmailConfig not stored in DB:** The `EmailConfigRepository` trait exists in `axiam-core/src/repository.rs` (line 1022) but has **no SurrealDB implementation** — `axiam-db` contains no `email_config.rs` repository and no `email_config` table in the schema (verified: only `email_template` and `email_verification_token` tables). The `SmtpConfig.password` / `ApiProviderConfig.api_key` fields in `axiam-core/src/models/email.rs` are doc-commented "stored encrypted at rest by the DB layer" but no DB layer implementation exists. **D-17 must implement both the repository and encryption from scratch.** [VERIFIED: codebase grep]

**Critical finding — HMAC crate already workspace-available:** `hmac = "0.12"` and `sha2 = "0.10"` are workspace dependencies (Cargo.toml lines 67, 69). The `WebhookDeliveryService` in `axiam-api-rest/src/webhook.rs` already uses `Hmac<Sha256>` with identical type alias pattern `type HmacSha256 = Hmac<Sha256>`. D-02 pseudonym HMAC can follow this exact pattern without new deps. [VERIFIED: codebase grep]

**Critical finding — Audit append-only is schema-enforced:** The `audit_log` table schema at `axiam-db/src/schema.rs:306-312` uses `FOR update NONE / FOR delete NONE` permissions. The D-04 `pseudonymize_actor` method **cannot use standard UPDATE SurrealQL** against this table — it must either use a privileged DB user bypassing row-level permissions or the planner must document a schema change to relax the permission for a single path. This is the central technical tension for D-04. [VERIFIED: schema.rs line 306]

**Primary recommendation:** Implement as three interlocked waves: (1) AMQP mail consumer infrastructure + email wiring (resolves T19.11/12/13), (2) schema migrations + GDPR endpoint handlers, (3) integration tests.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Email delivery (async) | AMQP Consumer (axiam-amqp) | axiam-email (send) | Decouples request latency from provider latency; enables retry/dead-letter |
| Email template rendering | axiam-email (template.rs) | axiam-core (email_template model) | Template engine lives in email crate; model/storage in core/db |
| Email config resolution | axiam-email (effective_email_config) | axiam-db (EmailConfigRepository — to be built) | Inheritance engine already exists; needs DB backend |
| GDPR export aggregation | axiam-api-rest (new handler) | axiam-db (multi-table queries) | REST handler triggers; queries span all user-scoped tables |
| GDPR export encryption | axiam-auth (crypto.rs helpers) | axiam-server (key loading) | Reuse existing AES-256-GCM split-output variant |
| Audit pseudonymization | axiam-db (SurrealAuditLogRepository — extended) | axiam-core (new `pseudonymize_actor` method on AuditLogRepository trait) | Only the DB layer can issue the privileged UPDATE |
| Scheduled purge job | axiam-server (cleanup.rs extended or new task) | axiam-db (user repo anonymize + auth artifact delete) | Mirrors existing CleanupTask pattern; unify or extend |
| Consent recording | axiam-db (new consent table) | axiam-api-rest (registration hook) | New schema + repo; called at registration |
| HMAC pseudonym generation | axiam-auth (crypto.rs) | axiam-core (new helper) | Crypto helpers live in axiam-auth; HMAC + sha2 already workspace deps |

---

## Standard Stack

### Core (all already in workspace — no new installs)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `lettre` | 0.11 (workspace) | SMTP delivery | Already used by `SmtpProvider` in axiam-email |
| `hmac` + `sha2` | 0.12 / 0.10 (workspace) | HMAC-SHA256 for D-02 pseudonym | Already workspace deps; used in webhook delivery |
| `aes-gcm` | 0.10 (workspace) | AES-256-GCM for export file + email secrets | Already used for TOTP/federation secrets |
| `lapin` | 4 (workspace) | AMQP producer/consumer for mail queue | Already the AMQP crate; audit+authz consumers built on it |
| `axiam-email` | internal | EmailService + template engine + providers | Fully built; `from_config` + `send` |
| `serde_json` | 1 (workspace) | GDPR export JSON assembly | Workspace dep |

### No New Package Installs Required

All dependencies for Phase 5 are already in the workspace. This phase is purely wiring and new code using existing infrastructure.

**Package Legitimacy Audit:** N/A — no new packages. Existing packages are all long-established workspace dependencies verified in prior phases.

---

## Architecture Patterns

### Email Wiring Data Flow

```
HTTP Request (reset/verify/notify)
    |
    v
actix-web handler (password_reset.rs / email_verification.rs / notification.rs)
    |
    +-- resolve effective EmailConfig (tenant -> org) via EmailConfigRepository
    |
    +-- build MailMessage { mail_type, user_id, tenant_id, token, expiry }
    |
    v
AMQP publish to "axiam.mail.outbound" queue (new queue)
    |
    v [async, decoupled]
axiam-amqp: start_mail_consumer (new — mirrors audit_consumer.rs pattern)
    |
    +-- deserialize MailMessage
    +-- resolve EmailConfig from DB
    +-- resolve template (tenant -> org -> builtin via resolve_template())
    +-- render via render_email() [uses render_html for HTML body]
    +-- EmailService::from_config(&config)?.send(&message)
    |
    +-- [Success] ack delivery
    +-- [Failure] retry with backoff; on N exhausted retries:
         - dead-letter message
         - append audit event: action="email.delivery_failed",
           actor_id=user_id, metadata={provider, error_class, attempt_count, next_retry_at, mail_type}
```

**AMQP queue naming convention** (existing queues: `axiam.authz.request/response`, `axiam.audit.events`, `axiam.notifications`):
- New: `axiam.mail.outbound` — transactional email jobs
- New: `axiam.mail.outbound.dlq` — dead-letter queue for failed deliveries
- New: `axiam.jobs.background` — background jobs (export generation, scheduled purge) — OR extend `CleanupTask` pattern

### GDPR Pseudonymization Flow (Art. 17)

```
DELETE /api/v1/account/delete (authenticated)
    |
    v
handler: ownership check (AuthenticatedUser.id == target_id OR users:erase permission)
    |
    +-- user.status = "deletion_pending"
    +-- user.scheduled_purge_at = now + 30d
    +-- generate cancel token (opaque, server-generated, 30d TTL)
    +-- store cancel token in new "account_deletion" table
    +-- AuthService::revoke_all_sessions(tenant_id, user_id)   [existing]
    +-- enqueue mail: DeletionScheduled { user_id, cancel_token, expiry }
    +-- append audit: action="gdpr.erasure_requested", actor_id=user_id
    |
    v
[After 30 days — CleanupTask extended or new PurgeTask]
    |
    +-- find users WHERE deletion_pending AND scheduled_purge_at <= now
    +-- for each:
         a. Hard-delete auth artifacts:
            - DELETE sessions WHERE user_id = X
            - DELETE refresh_tokens WHERE user_id = X
            - DELETE password_reset_tokens WHERE user_id = X
            - DELETE email_verification_tokens WHERE user_id = X
            - DELETE federation_links WHERE user_id = X
            - DELETE webauthn_credentials WHERE user_id = X
            - UPDATE user SET mfa_secret = NULL
         b. Compute HMAC pseudonym:
            hash = HMAC-SHA256(AXIAM__GDPR_PSEUDONYM_PEPPER, tenant_id || user_id)
            truncated_hex = &hex(hash)[..16]  // 16 hex chars = 64 bits
            pseudonym = format!("DELETED_USER_{truncated_hex}")
         c. Anonymize user row in place:
            UPDATE user SET
              email = sha256(email) [or hash],
              username = pseudonym,
              display_name = NULL,   [if column added]
              password_hash = NULL,
              mfa_secret = NULL,
              status = "anonymized",
              metadata = {}
         d. Pseudonymize audit entries:
            AuditLogRepository::pseudonymize_actor(tenant_id, user_id, hash)
            [issues privileged UPDATE — see schema permission discussion]
         e. INSERT erasure_proof record
         f. Append audit: action="gdpr.user_pseudonymized", actor=System
```

### GDPR Art. 17 Schema Permission Tension

The `audit_log` table is defined with `FOR update NONE` (schema.rs:310). Two resolution paths:

**Option A — Schema migration relaxes permission for one path:**
```sql
-- Migration v15 (partial):
DEFINE TABLE audit_log SCHEMAFULL
    PERMISSIONS
        FOR create FULL
        FOR select FULL
        FOR update WHERE $auth.role = 'gdpr_pseudonymizer'
        FOR delete NONE;
```
Requires a dedicated DB role/user. Adds schema complexity.

**Option B — Application-layer override via raw query with elevated credentials:**
The SurrealDB v3 SDK allows issuing queries as `Root` auth. The `pseudonymize_actor` method can open a root-auth connection for this single operation while all other audit writes use the standard connection. This keeps the schema unchanged. [ASSUMED — SurrealDB v3 behavior; verify that root auth bypasses table-level permission checks]

**Option C — New table: `audit_pseudonymization_log`** (tombstone append):
Rather than updating `audit_log`, append a new record to `audit_pseudonymization_log` linking `entry_id → pseudonym`. A read-time view masks the original. **D-01 explicitly rejects this** — genuine erasure, not concealment. Do not use.

**Recommendation:** Option A (schema migration with scoped UPDATE permission). This is explicit, auditable, and consistent with SurrealDB's security model. The planner must add migration v15+ to relax the UPDATE permission specifically for the pseudonymization path. The application-level guard (only `pseudonymize_actor` calls UPDATE) is the true enforcement mechanism; the schema permission adds a DB-layer safety net.

### Background Job Pattern (unified primitive)

The existing `CleanupTask` (`axiam-server/src/cleanup.rs`) is a tokio::select! loop with:
- `tokio::time::interval` ticker
- `watch::Receiver<bool>` shutdown signal
- Error handling: log warn, continue (never panic)
- Spawned via `tokio::spawn(cleanup.run())`

**Recommended: extend CleanupTask or create a parallel `BackgroundJobTask`** with the same shape but two additional sweep methods:
1. `sweep_pending_purges()` — finds `deletion_pending` users past `scheduled_purge_at`, runs the purge pipeline
2. `sweep_pending_export_jobs()` — finds queued export jobs, generates/encrypts/stores output, enqueues export-ready mail

Both can run in the same ticker loop as the existing cleanup sweeps, or in a dedicated task. The AMQP mail consumer is separate (event-driven, not polling).

### Existing Code Patterns to Reuse

**AES-256-GCM split-output** (for email secrets + export file):
```rust
// Source: crates/axiam-auth/src/crypto.rs — encrypt_separate / decrypt_separate
// Already used for federation client secrets (Phase 4 D-11)
use axiam_auth::crypto::{encrypt_separate, decrypt_separate};

// Returns (nonce_b64, ciphertext_b64)
let (nonce, ciphertext) = encrypt_separate(&email_key, plaintext.as_bytes())?;
// DB columns: email_config.password_ciphertext, .password_nonce, .password_key_version
```

**HMAC-SHA256 pseudonym** (mirrors webhook.rs pattern):
```rust
// Source: crates/axiam-api-rest/src/webhook.rs lines 5-9
// hmac = "0.12", sha2 = "0.10" — workspace deps already present
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn compute_pseudonym(pepper: &[u8; 32], tenant_id: Uuid, user_id: Uuid) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper).expect("HMAC any key size");
    mac.update(tenant_id.as_bytes());
    mac.update(user_id.as_bytes());
    let result = mac.finalize().into_bytes();
    let hex = hex::encode(&result[..8]); // 16 hex chars = 64 bits
    format!("DELETED_USER_{hex}")
}
```
Note: `hex` crate — check if workspace dep. If not, use `format!("{:02x}", b)` or add to workspace. [ASSUMED: `hex` not confirmed as workspace dep — planner should check or use manual format]

**Env-key loading** (for new `AXIAM__EMAIL_ENCRYPTION_KEY` and `AXIAM__GDPR_PSEUDONYM_PEPPER`):
```rust
// Source: crates/axiam-server/src/main.rs lines 83-112
// Pattern: read env hex string, hex::decode, try_into [u8; 32]
if let Ok(hex) = std::env::var("AXIAM__EMAIL_ENCRYPTION_KEY") {
    let bytes = hex::decode(&hex).expect("...");
    let key: [u8; 32] = bytes.try_into().expect("...");
    // store in config struct
}
```

**Tokio background task with shutdown** (matches cleanup.rs):
```rust
// Source: crates/axiam-server/src/cleanup.rs
// Pattern: tokio::time::interval + watch::Receiver<bool> + MissedTickBehavior::Skip
```

### Anti-Patterns to Avoid

- **Sending email synchronously in request handlers:** D-14 mandates AMQP enqueue. Never call `EmailService::send()` directly from a handler — it blocks the request and loses retry.
- **Storing raw recipient email in audit events:** D-16 mandates `user_id` key, not email address. The `email.delivery_failed` event must NOT include the recipient address in `metadata`.
- **Hard-deleting the user row (D-05):** Referential integrity for `created_by`/owner references requires the row to survive as an anonymized tombstone.
- **Using `render()` instead of `render_html()` for HTML bodies (D-18):** All new HTML mail bodies must go through `render_html` to prevent XSS from user-controlled values like username.
- **Three separate background task implementations:** The planner must unify purge job, export job, and mail consumer under a consistent pattern. Ad-hoc tasks are the noted highest planning risk.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SMTP delivery | Custom SMTP client | `lettre` (already in axiam-email SmtpProvider) | TLS, auth, MIME encoding, connection pooling all handled |
| HTTP email API calls | Custom reqwest client per provider | Existing SendGrid/Postmark/Resend/Brevo providers in `axiam-email/src/providers/` | Already built and tested |
| AES-256-GCM encryption | Manual cipher impl | `axiam_auth::crypto::{encrypt_separate, decrypt_separate}` | Already in use for TOTP and federation secrets |
| HMAC-SHA256 | Manual hash | `hmac` + `sha2` workspace crates (used in webhook.rs) | RustCrypto ecosystem, already workspace deps |
| Template rendering | New template engine | `axiam_email::template::{render_html, render_email, resolve_template}` | Already injection-safe, tested |
| Tokio background task loop | New polling pattern | Extend `CleanupTask` pattern from `axiam-server/src/cleanup.rs` | shutdown signal, missed-tick handling, error-continue all solved |
| Session revocation | Custom session sweep | `AuthService::revoke_all_sessions(tenant_id, user_id)` | Already implemented (Phase 4 D-16/D-18) |

---

## GDPR Art. 15 Export — Completeness Inventory

The export must cover ALL tables where `user_id` or `actor_id` references the subject.

| Section | Table(s) | Query Key | Notes |
|---------|----------|-----------|-------|
| `profile` | `user` | `id = user_id` | All fields EXCEPT `password_hash`, `mfa_secret` |
| `consents` | `consent` (new table, v15 migration) | `user_id` | All consent records |
| `sessions` | `session` | `user_id` | `token_hash` excluded; include `ip_address`, `user_agent`, `created_at`, `expires_at` |
| `mfa` | `user` (mfa_enabled, mfa_secret excluded) | same `id` | enrollment status + timestamps only |
| `federation_identities` | `federation_link` | `user_id` | `external_subject`, `external_email`, `created_at` |
| `assignments` | `has_role` graph relation | `in = user_id` | role/group/resource assignments |
| `group_memberships` | `member_of` graph relation | `in = user_id` | group memberships |
| `audit_entries` | `audit_log` | `actor_id = user_id` | All entries where user was actor |
| `webauthn_credentials` | `webauthn_credential` | `user_id` | `credential_id`, `name`, `credential_type`, `created_at` |
| `password_history` | `password_history` | `user_id` | Hashes only (already hashed, no raw password) |

**Intentionally EXCLUDED (D-10):**
- `password_hash`, `mfa_secret` — secrets, never exported
- Session `token_hash` — opaque, security-sensitive
- OAuth2 `token_hash` values — same
- Federation `client_secret` — not user data

**Risk: missed tables from schema.** The planner's integration test (REQ-8: "create user with data in every table, export, verify completeness") is the safety net. The test fixture must exercise every table above.

---

## GDPR Art. 17 — User PII Column Inventory

**`user` table PII columns that MUST be anonymized (D-05):**

| Column | Type | Anonymization Action |
|--------|------|---------------------|
| `email` | string | Replace with `sha256(tenant_id + email)` (one-way, not recoverable) |
| `username` | string | Replace with `DELETED_USER_<hash>` (same pseudonym as audit) |
| `password_hash` | string | Set to `NULL` (login impossible) |
| `mfa_secret` | option<string> | Set to `NULL` |
| `ip_address` | (not on user table — on session/audit) | N/A |
| `metadata` | object FLEXIBLE | Clear to `{}` (may contain display_name, phone, etc.) |
| `locked_until`, `last_failed_login_at` | option<datetime> | Clear to `NULL` (operational, not PII, but included for clean tombstone) |
| `status` | string | Set to `"anonymized"` (new status value — requires schema migration AND `UserStatus` enum update) |

**Schema migration needed:** Add `"anonymized"` to the ASSERT constraint on `user.status`:
```sql
DEFINE FIELD status ON TABLE user TYPE string
    ASSERT $value IN ['Active', 'Inactive', 'Locked', 'PendingVerification', 'Anonymized'];
```
And add `UserStatus::Anonymized` to the Rust enum in `axiam-core/src/models/user.rs`.

**Auth artifact tables — hard-delete by user_id (D-06):**
- `session` WHERE `user_id = X`
- `refresh_token` (OAuth2 refresh tokens) WHERE `user_id = X`
- `password_reset_token` WHERE `user_id = X`
- `email_verification_token` WHERE `user_id = X`
- `federation_link` WHERE `user_id = X`
- `webauthn_credential` WHERE `user_id = X`
- `password_history` WHERE `user_id = X`

**Audit entries — pseudonymize, not delete (D-01..D-04):**
Entries in `audit_log` WHERE `actor_id = X` or `resource_id = X`.

---

## Consent Tracking Model (Claude's Discretion)

**Minimal model for REQ-8 scope:**

```sql
-- Migration v15+ (new table)
DEFINE TABLE consent SCHEMAFULL;
DEFINE FIELD tenant_id ON TABLE consent TYPE string;
DEFINE FIELD user_id ON TABLE consent TYPE string;
DEFINE FIELD consent_type ON TABLE consent TYPE string
    ASSERT $value IN ['terms_of_service', 'privacy_policy', 'marketing'];
DEFINE FIELD version ON TABLE consent TYPE string;   -- e.g., "2026-01-01"
DEFINE FIELD accepted_at ON TABLE consent TYPE datetime DEFAULT time::now();
DEFINE FIELD ip_address ON TABLE consent TYPE option<string>;
DEFINE FIELD user_agent ON TABLE consent TYPE option<string>;
DEFINE INDEX idx_consent_user ON TABLE consent COLUMNS tenant_id, user_id;
DEFINE INDEX idx_consent_user_type ON TABLE consent
    COLUMNS tenant_id, user_id, consent_type UNIQUE;
```

**When recorded:** At registration, after `CreateUser` succeeds, a `consent` record is inserted with `consent_type = "terms_of_service"`, `version = "current"` (configurable), and the request `ip_address`/`user_agent`.

**Rationale:** GDPR Art. 7 requires proof of consent. This minimal table records the timestamp, IP, and terms version. Withdrawal tracking is deferred (CONTEXT.md Deferred).

---

## Email Config Repository — Implementation Gap (D-17)

**Finding:** `EmailConfigRepository` trait is defined in `axiam-core/src/repository.rs` (line 1022) but has NO SurrealDB implementation. There is no `email_config` table in the schema. The `SmtpConfig.password` and `ApiProviderConfig.api_key` fields are doc-commented "stored encrypted at rest by the DB layer" but no encryption is implemented. [VERIFIED: codebase grep of axiam-db/src/repository/ and axiam-db/src/schema.rs]

**Required planner tasks for D-17:**

1. **Schema migration v15+:** Create `email_config` table with encrypted secret columns following the Phase 4 federation pattern:
```sql
DEFINE TABLE email_config SCHEMAFULL;
DEFINE FIELD scope ON TABLE email_config TYPE string
    ASSERT $value IN ['org', 'tenant'];
DEFINE FIELD scope_id ON TABLE email_config TYPE string;
DEFINE FIELD enabled ON TABLE email_config TYPE bool DEFAULT true;
DEFINE FIELD from_name ON TABLE email_config TYPE string;
DEFINE FIELD from_email ON TABLE email_config TYPE string;
DEFINE FIELD reply_to ON TABLE email_config TYPE option<string>;
DEFINE FIELD provider_kind ON TABLE email_config TYPE string;
-- SMTP fields (nullable for non-SMTP providers)
DEFINE FIELD smtp_host ON TABLE email_config TYPE option<string>;
DEFINE FIELD smtp_port ON TABLE email_config TYPE option<int>;
DEFINE FIELD smtp_username ON TABLE email_config TYPE option<string>;
DEFINE FIELD smtp_starttls ON TABLE email_config TYPE option<bool>;
DEFINE FIELD smtp_password_ciphertext ON TABLE email_config TYPE option<string>;
DEFINE FIELD smtp_password_nonce ON TABLE email_config TYPE option<string>;
-- API provider fields
DEFINE FIELD api_url ON TABLE email_config TYPE option<string>;
DEFINE FIELD api_key_ciphertext ON TABLE email_config TYPE option<string>;
DEFINE FIELD api_key_nonce ON TABLE email_config TYPE option<string>;
DEFINE FIELD secret_key_version ON TABLE email_config TYPE option<int>;
DEFINE FIELD created_at ON TABLE email_config TYPE datetime DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE email_config TYPE datetime DEFAULT time::now();
DEFINE INDEX idx_email_config_scope ON TABLE email_config
    COLUMNS scope, scope_id UNIQUE;
```

2. **SurrealEmailConfigRepository implementation** in `axiam-db/src/repository/email_config.rs` implementing the `EmailConfigRepository` trait.

3. **Env key loading** in `axiam-server/src/main.rs`: `AXIAM__EMAIL_ENCRYPTION_KEY` (same pattern as `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`, lines 96-112).

4. **Decrypt at read time** in the repository's `get_org_config` / `get_effective_config` — return plaintext `password`/`api_key` fields in the `EmailConfig` struct (which is ephemeral, not persisted plaintext).

**Until email_config repository exists:** The mail consumer cannot resolve the effective config from the DB. The AMQP mail message must carry enough context (tenant_id, org_id) to allow the consumer to look up the config.

---

## New Schema Tables / Migrations Summary

| Migration | Table | Purpose |
|-----------|-------|---------|
| v15 | `email_config` | Email provider config with encrypted secrets (D-17) |
| v15 | `consent` | GDPR consent records (REQ-8) |
| v15 | `account_deletion` | Pending deletions: `user_id`, `tenant_id`, `cancel_token_hash`, `scheduled_purge_at`, `status` |
| v15 | `export_job` | Async export tracking: `user_id`, `tenant_id`, `status`, `file_path` or `encrypted_blob`, `download_token_hash`, `expires_at` |
| v15 | `erasure_proof` | PII-free deletion record: `pseudonym`, `tenant_id`, `erased_at` (D-06) |
| v15 (ALTER) | `user` | Add `deletion_pending` bool, `scheduled_purge_at` option<datetime>, add `"Anonymized"` to status ASSERT |
| v15 (ALTER) | `audit_log` | Add `UPDATE` permission scoped to a GDPR path (or use root auth in repo method) |
| v15 (ALTER) | `email_template` | Add `deletion_scheduled` and `export_ready` to `kind` ASSERT (D-09, D-12) |

**Migration version:** Current schema is at v14 (`webauthn_credentials`). Phase 5 adds v15 (may be split into v15a, v15b if needed, but the current pattern is one migration per logical change — consider grouping all Phase 5 additions in v15 with sub-sections).

---

## AMQP Mail Queue Infrastructure

**Existing AMQP consumer pattern** (from `audit_consumer.rs`):
- `basic_consume` on a queue name
- `futures_lite::StreamExt` consumer loop
- Deserialize payload, process, `ack` on success, `nack` on failure
- Dead-letter via `requeue: false` nack (messages go to DLQ if RabbitMQ is configured with `x-dead-letter-exchange`)

**Mail consumer additions needed:**
1. New queue `axiam.mail.outbound` declared in `connection.rs::queues` module and `ALL_QUEUES` array.
2. Dead-letter queue `axiam.mail.outbound.dlq` — requires `x-dead-letter-exchange` argument on queue declaration (use `FieldTable` with `"x-dead-letter-exchange"` key).
3. Retry logic: the consumer performs N retries with backoff before dead-lettering. Pattern: embed `attempt_count` in the message payload; on failure, re-publish with incremented count if `count < MAX_RETRIES`, else nack with `requeue: false`.

**New AMQP message type** for `axiam-amqp/src/messages.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMailMessage {
    pub mail_type: MailType,   // enum: PasswordReset, EmailVerification, Notification, DeletionCancel, ExportReady
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub to_address: String,    // resolved at enqueue time, NOT logged in audit
    pub template_context: serde_json::Value,  // { token, expiry, username, etc. }
    pub attempt_count: u32,
    pub enqueued_at: DateTime<Utc>,
}
```

**Note on `to_address` in the message:** The address must be in the message for delivery but MUST NOT appear in the `email.delivery_failed` audit event (D-16). The consumer reads it for delivery, audits by `user_id` only.

---

## Template System — New Templates Needed

**Existing `TemplateKind` variants** (from `axiam-core/src/models/email_template.rs`):
- `Activation`, `PasswordReset`, `MfaSetupReminder`, `AdminNotification`

**New variants required for Phase 5:**
- `DeletionScheduled` — includes cancel link (D-09)
- `ExportReady` — includes download link (D-12)

**Schema changes:** `email_template.kind` ASSERT constraint must add these values. `TemplateKind` Rust enum must add the variants. `TemplateKind::ALL` const array must be extended. `builtin_template()` match must add arms.

**Placeholders for new templates:**
- `DeletionScheduled`: `{{username}}`, `{{tenant_name}}`, `{{action_url}}` (cancel link), `{{expiry_time}}` (purge date)
- `ExportReady`: `{{username}}`, `{{tenant_name}}`, `{{action_url}}` (download link), `{{expiry_time}}` (24h TTL)

---

## Common Pitfalls

### Pitfall 1: Audit UPDATE Permission Blocks Pseudonymization

**What goes wrong:** `SurrealDB FOR update NONE` on `audit_log` rejects any UPDATE query issued by the application connection, even if called from `pseudonymize_actor`.
**Why it happens:** Schema-level permissions apply to all connections using the normal application credentials.
**How to avoid:** Either (a) modify the schema to permit UPDATE via a scoped role (recommended), or (b) issue the pseudonymization UPDATE using root-level credentials stored as a separate key.
**Warning signs:** `DbError::Permission` or SurrealDB 403-equivalent on the UPDATE query in tests.

### Pitfall 2: Email Config Repository Missing — Mail Consumer Cannot Resolve Config

**What goes wrong:** The mail consumer builds `EmailService::from_config(&effective_config)` but `get_effective_config` has no implementation.
**Why it happens:** `SurrealEmailConfigRepository` does not exist — the trait is defined but not implemented.
**How to avoid:** Implement the repository as part of the first plan wave, before wiring the mail consumer.
**Warning signs:** Linker error on `SurrealEmailConfigRepository` reference; missing `email_config` table at runtime.

### Pitfall 3: User Status "Anonymized" Not in Schema ASSERT

**What goes wrong:** `UPDATE user SET status = 'anonymized'` fails with a SurrealDB ASSERT violation.
**Why it happens:** The `user.status` ASSERT only allows `['Active', 'Inactive', 'Locked', 'PendingVerification']`.
**How to avoid:** Schema migration v15 must add `'Anonymized'` to the ASSERT. `UserStatus` Rust enum and `parse_status` / `status_to_string` helpers in `axiam-db/src/repository/user.rs` must also be updated.
**Warning signs:** SurrealDB validation error during purge; test fails on user row verification after deletion.

### Pitfall 4: `deletion_pending` / `scheduled_purge_at` Missing from User Row Struct

**What goes wrong:** New schema fields are not in `UserRow` / `UserRowWithId` — SurrealDB v3 returns them but they're not deserialized.
**Why it happens:** `SurrealValue` derive requires all SCHEMAFULL fields to be represented or use FLEXIBLE.
**How to avoid:** Add `deletion_pending: Option<bool>` and `scheduled_purge_at: Option<DateTime<Utc>>` to both row structs in `axiam-db/src/repository/user.rs`. Mirror pattern of other `Option<>` fields.

### Pitfall 5: Consent INSERT at Registration Not Atomic

**What goes wrong:** Registration succeeds but consent INSERT fails — user exists without consent record.
**Why it happens:** Two separate DB operations without a transaction.
**How to avoid:** Use SurrealDB's `LET $user = CREATE ...; CREATE consent SET user_id = meta::id($user.id), ...;` in one `.query()` call or run both in a SurrealDB transaction.

### Pitfall 6: Export File AES-GCM Key Not Available to Consumer

**What goes wrong:** Background export worker cannot encrypt the file because `AXIAM__EMAIL_ENCRYPTION_KEY` is not loaded.
**Why it happens:** The key is loaded in `main.rs` but not passed to the background job task.
**How to avoid:** Pass the key (as `[u8; 32]`) to the background job at construction time (mirrors how `auth_config.mfa_encryption_key` is used in auth handlers).

### Pitfall 7: Missing `SurrealEmailNotificationTokenRepository` / Password Reset Token Handlers

**What goes wrong:** The password reset handler (`password_reset.rs:87`) captures `_raw_token` and `_user_id` but discards them. Wiring requires passing these to the enqueue call.
**Why it happens:** The TODO was structured to discard; the wiring must extract the returned tuple values.
**How to avoid:** Replace the `(_raw_token, _user_id, _expires_at)` binding with named variables and use them to build the `OutboundMailMessage`.

---

## Code Examples

### Verified Pattern: AMQP Consumer Structure
```rust
// Source: crates/axiam-amqp/src/audit_consumer.rs — start_audit_consumer
// Pattern: futures_lite::StreamExt consumer loop with ack/nack
pub async fn start_mail_consumer<E, A>(
    channel: Channel,
    email_service_factory: E,   // fn(EmailConfig) -> EmailService
    audit_repo: A,
) where
    E: Fn(&EmailConfig) -> AxiamResult<EmailService> + Send + 'static,
    A: AuditLogRepository + 'static,
{
    let mut consumer = channel.basic_consume(
        queues::MAIL_OUTBOUND.into(), "axiam-mail-consumer".into(),
        BasicConsumeOptions::default(), FieldTable::default(),
    ).await?;

    while let Some(delivery_result) = consumer.next().await {
        // deserialize, retry logic, send, ack/nack, audit on DLQ
    }
}
```

### Verified Pattern: CleanupTask Shutdown Signal
```rust
// Source: crates/axiam-server/src/cleanup.rs — CleanupTask::run()
// Pattern: tokio::select! with interval + watch::Receiver<bool>
tokio::select! {
    _ = ticker.tick() => { /* sweep */ }
    changed = self.shutdown.changed() => {
        if changed.is_ok() && *self.shutdown.borrow() {
            return Ok(());
        }
    }
}
```

### Verified Pattern: Env Key Loading
```rust
// Source: crates/axiam-server/src/main.rs lines 83-112
// Pattern for AXIAM__EMAIL_ENCRYPTION_KEY and AXIAM__GDPR_PSEUDONYM_PEPPER
if let Ok(hex) = std::env::var("AXIAM__EMAIL_ENCRYPTION_KEY") {
    let bytes = hex::decode(&hex).expect("must be 64-char hex");
    let key: [u8; 32] = bytes.try_into().expect("must be 32 bytes");
    config.email_encryption_key = Some(key);
}
```

### Verified Pattern: AES-256-GCM Split-Output Encryption
```rust
// Source: crates/axiam-auth/src/crypto.rs — encrypt_separate / decrypt_separate
// Already used for Phase 4 federation secrets
use axiam_auth::crypto::{encrypt_separate, decrypt_separate};

// Encrypt: (nonce_b64, ciphertext_b64)
let (nonce, ct) = encrypt_separate(&key, plaintext.as_bytes())?;
// Decrypt:
let plaintext = decrypt_separate(&key, &nonce, &ct)?;
```

### Verified Pattern: HMAC-SHA256 (mirrors webhook.rs)
```rust
// Source: crates/axiam-api-rest/src/webhook.rs lines 5-9
// Workspace deps: hmac = "0.12", sha2 = "0.10"
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

fn gdpr_pseudonym(pepper: &[u8; 32], tenant_id: Uuid, user_id: Uuid) -> String {
    let mut mac = HmacSha256::new_from_slice(pepper)
        .expect("HMAC accepts any key length");
    mac.update(tenant_id.as_bytes());
    mac.update(user_id.as_bytes());
    let tag = mac.finalize().into_bytes();
    format!("DELETED_USER_{}", hex_encode_short(&tag[..8]))
}
```

### Verified Pattern: Template Rendering (HTML safety)
```rust
// Source: crates/axiam-email/src/template.rs — render_email()
// render_email uses render_html for html_body automatically
use axiam_email::template::{render_email, resolve_template, PH_ACTION_URL, PH_USERNAME, TemplateContext};

let mut ctx = TemplateContext::new();
ctx.insert(PH_USERNAME.into(), user.username.clone());
ctx.insert(PH_ACTION_URL.into(), reset_url);
ctx.insert("expiry_time".into(), expires_at.to_string());

let template = resolve_template(TemplateKind::PasswordReset, org_tmpl, tenant_tmpl);
let message = render_email(&template, &user.email, &ctx);
// message.html_body is HTML-escaped; message.text_body is not (safe for plain text)
```

---

## Validation Architecture

Nyquist validation is enabled (`nyquist_validation: true` in config.json).

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[cfg(test)]` + actix-web test + SurrealDB in-memory |
| Config file | None — inline test module pattern |
| Quick run command | `cargo test -p axiam-api-rest gdpr` |
| Full suite command | `cargo test -p axiam-api-rest` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-6-T19.11 | Password reset handler enqueues mail (mock AMQP) | unit | `cargo test -p axiam-api-rest password_reset` | partially (handler exists, wiring test needed) |
| REQ-6-T19.12 | Email verification handler enqueues mail | unit | `cargo test -p axiam-api-rest email_verification` | partially |
| REQ-6-T19.13 | Notification dispatcher enqueues instead of returning list | unit | `cargo test -p axiam-audit notification` | no |
| REQ-6-delivery-fail | `email.delivery_failed` audit event written on N exhausted retries | unit | `cargo test -p axiam-amqp mail_consumer` | no |
| REQ-6-enum-safe | Reset/verify endpoint returns `{"sent": true}` for unknown emails | unit | `cargo test -p axiam-api-rest password_reset::unknown_email` | partially (pattern exists) |
| REQ-8-export | Create user with data in every table; export; verify all sections present | integration | `cargo test -p axiam-api-rest gdpr_test::export_completeness` | no (Wave 0 gap) |
| REQ-8-deletion | Delete user; verify PII removed from all tables; verify audit pseudonymized | integration | `cargo test -p axiam-api-rest gdpr_test::deletion_pseudonymization` | no (Wave 0 gap) |
| REQ-8-pseudonym | Deleted user audit entries show `DELETED_USER_<hash>` not UUID | integration | part of deletion test | no |
| REQ-8-consent | Registration inserts consent record | integration | `cargo test -p axiam-api-rest gdpr_test::consent_on_registration` | no |
| REQ-8-cancel | Cancel link aborts deletion, re-enables account | integration | `cargo test -p axiam-api-rest gdpr_test::deletion_cancel` | no |

### Sampling Rate
- **Per task commit:** `cargo test -p axiam-api-rest -p axiam-amqp -p axiam-audit --lib`
- **Per wave merge:** `cargo test -p axiam-api-rest`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `crates/axiam-api-rest/tests/gdpr_test.rs` — covers REQ-8 export completeness + deletion/pseudonymization
- [ ] `crates/axiam-amqp/tests/mail_consumer_test.rs` — covers delivery failure audit (new test file for axiam-amqp)
- [ ] Mock `EmailService` / `MockEmailProvider` for mail consumer tests — use `with_provider(Box::new(MockProvider::new()))` (exists: `crates/axiam-email/src/providers/mock.rs`)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes — enumeration-safe responses | Uniform 200 for reset/verify regardless of address existence (D-15) |
| V3 Session Management | yes — deletion cascade | `AuthService::revoke_all_sessions` on deletion request |
| V4 Access Control | yes — GDPR endpoints | `RequirePermission("users:erase")` / ownership check (D-07) |
| V5 Input Validation | yes — all new endpoints | Validate token formats, UUIDs, export request parameters |
| V6 Cryptography | yes — export file + email secrets | AES-256-GCM for export file (D-12); email secret encryption (D-17); HMAC-SHA256 for pseudonym (D-02) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Email enumeration via differential response | Information Disclosure | D-15: uniform 200 for reset/verify regardless of outcome |
| GDPR export token theft (download link) | Spoofing | D-13: single-use, 24h TTL, server-generated opaque token |
| Audit PII re-identification from HMAC | Information Disclosure | D-02: keyed HMAC with dedicated pepper; brute-force of candidate user_ids requires knowing the pepper |
| Deletion cancel token replay | Elevation of Privilege | Token is single-use; consumed on click; stored as hash |
| Export file exposure at rest | Information Disclosure | D-12: AES-256-GCM encrypted; deleted on download or TTL expiry |
| Purge job acting on wrong tenant | Elevation of Privilege | All purge queries include `tenant_id` scope; same pattern as all other tenant-scoped repos |
| Template injection via username | Tampering | D-18: `render_html` HTML-escapes all context values before insertion into HTML body |

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Handlebars triple-stash `{{{...}}}` | Custom `{{placeholder}}` with `render_html` | Before Phase 5 (already built) | Template injection is not possible with current engine |
| Synchronous email delivery in handler | AMQP async + retry (D-14) | Phase 5 | Request latency decoupled from SMTP/API latency; retries on provider failure |
| Hard-delete for GDPR Art. 17 | In-place anonymization + audit pseudonymization | Phase 5 (D-01/D-05) | Referential integrity preserved; regulators satisfied by genuine erasure |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | SurrealDB root auth bypasses `FOR update NONE` table permission | GDPR Art. 17 / schema tension | If false, schema migration to relax UPDATE permission becomes mandatory; Option A is the fallback |
| A2 | `hex` crate available as workspace dep (needed for `hex_encode` in HMAC pseudonym) | Code Examples | If absent, use `format!("{:02x}", b)` loop or add `hex` to workspace Cargo.toml |
| A3 | `encrypt_separate` / `decrypt_separate` are the correct function names in `axiam-auth/src/crypto.rs` for the split-output AES-GCM variant | Standard Stack / Code Examples | The function names may differ; planner must verify exact API from the crypto.rs file |
| A4 | The `futures_lite` crate is already a dependency of `axiam-amqp` (for `StreamExt`) | AMQP mail consumer | Verified indirectly: `audit_consumer.rs` imports `futures_lite::StreamExt`; adding a new consumer in the same crate does not require a new dep |
| A5 | `TemplateKind` enum can be extended without breaking the DB schema ASSERT constraint until a migration is applied | Template System | If the enum is extended before the schema migration, new templates cannot be stored (only builtins work — acceptable for MVP wire-up) |

---

## Open Questions (RESOLVED)

1. **Schema permission for `pseudonymize_actor` (D-04)** — **RESOLVED**
   - What we know: `audit_log FOR update NONE` is schema-enforced (schema.rs:310)
   - Resolution: **Option A is the default.** Schema migration v15 (Plan 05-01, Task 1) relaxes the `audit_log` UPDATE permission to `FOR update WHERE $auth.role = 'gdpr_pseudonymizer'`, scoping the single sanctioned `pseudonymize_actor` path. Option B (root-auth connection bypass) is the documented **runtime fallback** if assumption A1 holds (root auth bypasses `FOR update NONE`) and the scoped-role relaxation proves insufficient in SurrealDB v3. The 05-01 SUMMARY records which mechanism SurrealDB actually honored. True enforcement remains the app-layer single-method guard (only `pseudonymize_actor` issues UPDATE).

2. **Email config for the mail consumer before DB implementation** — **RESOLVED**
   - What we know: The mail consumer needs `effective_email_config` to send; the DB implementation doesn't exist yet.
   - Resolution: Wave ordering guarantees the repo exists first. **EmailConfigRepository is built in Plan 05-01 (Wave 1); the mail consumer is Plan 05-03 (Wave 2).** Wave 2 cannot start until Wave 1 completes, so the consumer always has a real `SurrealEmailConfigRepository`. No env-var fallback config is needed or planned.

3. **AMQP dead-letter exchange configuration** — **RESOLVED**
   - What we know: Current queue declarations in `connection.rs` use `FieldTable::default()` (no DLQ arguments).
   - Resolution: **Plan 05-02 declares an explicit `x-dead-letter-exchange` on the `axiam.mail.outbound` queue** (FieldTable arg pointing at `axiam.mail.outbound.dlq`), and declares the DLQ itself in `ALL_QUEUES`. The application never assumes broker-level DLQ pre-config.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| RabbitMQ | AMQP mail queue (D-14) | Runtime dep (dev-up) | — | No fallback — dev-up required for mail consumer tests |
| SurrealDB in-memory | Integration tests | ✓ | via kv-mem feature | — |
| `axiam-email` crate | Mail consumer | ✓ (internal) | workspace | — |
| `hmac` + `sha2` | HMAC pseudonym | ✓ | 0.12 / 0.10 (workspace) | — |
| `aes-gcm` | Export encryption, email secret | ✓ | 0.10 (workspace) | — |
| `lettre` | SMTP delivery | ✓ | 0.11 (workspace, in axiam-email) | Other providers (SendGrid etc.) |

**Missing dependencies with no fallback:**
- RabbitMQ must be running (`just dev-up`) for mail consumer integration tests.

---

## Sources

### Primary (HIGH confidence — codebase verification)
- `crates/axiam-email/src/service.rs` — EmailService::from_config, send; verified fully built
- `crates/axiam-email/src/template.rs` — render, render_html, render_email, resolve_template; injection-safe engine verified
- `crates/axiam-email/src/provider.rs` — EmailProvider trait (Pin<Box<dyn Future>>)
- `crates/axiam-core/src/models/email.rs` — SmtpConfig, ApiProviderConfig, ProviderConfig, EmailConfig, effective_email_config
- `crates/axiam-core/src/models/email_template.rs` — TemplateKind (4 variants), EmailTemplate
- `crates/axiam-core/src/repository.rs` (line 1022) — EmailConfigRepository trait; (line 1067) EmailTemplateRepository
- `crates/axiam-db/src/schema.rs` — all table DDL including audit_log FOR update NONE (line 310)
- `crates/axiam-db/src/lib.rs` — confirmed NO SurrealEmailConfigRepository export
- `crates/axiam-db/src/repository/` — directory listing confirmed no email_config.rs
- `crates/axiam-db/src/repository/audit.rs` — append-only repo; no UPDATE method
- `crates/axiam-core/src/models/audit.rs` — AuditLogEntry structure (actor_id: Uuid, ip_address: Option<String>, metadata: serde_json::Value)
- `crates/axiam-auth/src/crypto.rs` — AES-256-GCM helpers; encrypt_separate/decrypt_separate
- `crates/axiam-auth/src/config.rs` — AuthConfig; env key loading pattern; existing mfa_encryption_key, federation_encryption_key fields
- `crates/axiam-server/src/main.rs` — env key loading pattern; CleanupTask spawn; AMQP consumer spawn pattern
- `crates/axiam-server/src/cleanup.rs` — tokio::select! + watch::Receiver<bool> shutdown pattern
- `crates/axiam-amqp/src/connection.rs` — queues module, AmqpManager, ALL_QUEUES array; DLQ not yet declared
- `crates/axiam-amqp/src/audit_consumer.rs` — consumer loop pattern; futures_lite::StreamExt
- `crates/axiam-amqp/src/messages.rs` — existing message types
- `crates/axiam-api-rest/src/handlers/password_reset.rs` — TODO(T19) at line 88
- `crates/axiam-api-rest/src/handlers/email_verification.rs` — TODO(T19) at line 105
- `crates/axiam-audit/src/notification.rs` — TODO(T19) at line 68
- `crates/axiam-api-rest/src/webhook.rs` — HMAC-SHA256 usage pattern with hmac+sha2 crates
- `Cargo.toml` (workspace) — hmac = "0.12", sha2 = "0.10", aes-gcm = "0.10", lapin = "4", lettre = "0.11"
- `.planning/config.json` — nyquist_validation: true

### Secondary (MEDIUM confidence — planning documents)
- `.planning/phases/05-email-delivery-gdpr-compliance/05-CONTEXT.md` — decisions D-01..D-18
- `.planning/REQUIREMENTS.md` REQ-6, REQ-8

---

## Metadata

**Confidence breakdown:**
- Email wiring (T19.11/12/13): HIGH — all stub points located, EmailService verified fully built
- EmailConfig DB implementation: HIGH — confirmed missing, gap is clear
- GDPR pseudonymization approach: HIGH — schema permission issue is real and documented
- AMQP mail consumer pattern: HIGH — verified from existing audit consumer
- Background job pattern: HIGH — verified from CleanupTask
- Art. 15 export completeness: MEDIUM — table inventory from schema; some graph edge tables (member_of, has_role) may not be enumerable without RELATE queries; planner should verify
- HMAC pseudonym implementation: HIGH — workspace deps confirmed, pattern verified from webhook.rs
- SurrealDB root auth bypasses FOR update NONE: LOW (ASSUMED) — not confirmed from docs in this session

**Research date:** 2026-06-02
**Valid until:** 2026-07-02 (stable Rust ecosystem; SurrealDB v3 API may change)
