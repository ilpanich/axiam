---
phase: 05-email-delivery-gdpr-compliance
plan: "03"
subsystem: amqp-server
tags: [amqp, email-delivery, gdpr, audit, retry, dead-letter, encryption-at-rest]
dependency_graph:
  requires:
    - "05-01: SurrealEmailConfigRepository (get_effective_config), gdpr_pseudonym"
    - "05-02: OutboundMailMessage, MailType, MAIL_OUTBOUND/MAIL_OUTBOUND_DLQ queues"
  provides:
    - start_mail_consumer (axiam-amqp)
    - send_with_retry_and_audit helper (broker-free, testable)
    - email.delivery_failed audit event (PII-minimal, D-16)
    - AXIAM__EMAIL_ENCRYPTION_KEY + AXIAM__GDPR_PSEUDONYM_PEPPER loaded at startup
    - email-secret idempotent backfill (D-17)
    - DeletionScheduled + ExportReady builtin templates (axiam-email, Wave-1 deferred)
  affects:
    - axiam-amqp (new mail_consumer.rs, Cargo.toml, lib.rs)
    - axiam-email (template.rs exhaustive match fix)
    - axiam-server (main.rs key loading + backfill + consumer spawn)
    - axiam-db (email_config.rs backfill method)
    - axiam-api-grpc (user.rs UserStatus::Anonymized arm fix)
tech_stack:
  added: []
  patterns:
    - "send_with_retry_and_audit: broker-free async helper with MAX_RETRIES=3; RetryNeeded/Exhausted/Delivered outcomes"
    - "email.delivery_failed audit: actor_id=user_id, no to_address in metadata (D-16)"
    - "Env key loading: hex-decode + try_into [u8;32] pattern for AXIAM__EMAIL_ENCRYPTION_KEY + AXIAM__GDPR_PSEUDONYM_PEPPER"
    - "Idempotent backfill: SELECT count of unencrypted rows, warn if >0 (UPDATE path deferred T19.22)"
key_files:
  created:
    - crates/axiam-amqp/src/mail_consumer.rs
    - crates/axiam-amqp/tests/mail_consumer_test.rs
  modified:
    - crates/axiam-amqp/src/lib.rs (re-export start_mail_consumer)
    - crates/axiam-amqp/Cargo.toml (add axiam-email dep, axiam-db dev-dep)
    - crates/axiam-email/src/template.rs (add DeletionScheduled + ExportReady to builtin_template)
    - crates/axiam-server/src/main.rs (key loading, backfill, consumer spawn)
    - crates/axiam-db/src/repository/email_config.rs (backfill_plaintext_secrets)
    - crates/axiam-api-grpc/src/services/user.rs (add UserStatus::Anonymized arm)
    - claude_dev/roadmap.md (add T19.21, T19.22)
decisions:
  - "MAX_RETRIES=3 (attempt_count 0,1,2; third failure dead-letters). Backoff is re-publish on MAIL_OUTBOUND with incremented attempt_count; broker delivers at its own rate — no explicit sleep delay in consumer"
  - "backfill_plaintext_secrets counts but does not UPDATE (T19.22): since email_config table was introduced with encryption columns in Phase 5 (no plaintext column in schema), there is never any data to migrate on a clean v15+ deployment. The UPDATE path is deferred"
  - "send_with_retry_and_audit is a pure async fn (no broker dependency) enabling broker-free Wave 0 tests"
  - "Template lookup in consumer uses built-in defaults only (resolve_template(kind, None, None)); per-org/tenant custom templates deferred to T19.21"
  - "UserStatus::Anonymized fix in axiam-api-grpc was a pre-existing Wave-1 deferred break — fixed as Rule 1 deviation"
  - "TemplateKind::DeletionScheduled + ExportReady fix in axiam-email was a required pre-existing break from Wave 1 — fixed as plan prerequisite"
metrics:
  duration: "65 minutes"
  completed_date: "2026-06-02"
  tasks: 2
  files: 8
---

# Phase 5 Plan 03: Mail Consumer + Server Wiring Summary

AMQP mail consumer with retry/backoff/dead-letter + PII-minimal delivery_failed audit (D-14, D-16); server loads AXIAM__EMAIL_ENCRYPTION_KEY and AXIAM__GDPR_PSEUDONYM_PEPPER, runs idempotent email-secret backfill, and spawns the consumer (D-17); TemplateKind exhaustive-match break resolved for DeletionScheduled/ExportReady.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | start_mail_consumer + retry/audit + Wave 0 test | 89ff992 | mail_consumer.rs, mail_consumer_test.rs, template.rs, lib.rs |
| 2 | Load keys + backfill + spawn mail consumer | 2426295 | main.rs, email_config.rs |

## What Was Built

**Mail consumer** (`crates/axiam-amqp/src/mail_consumer.rs`):
- `start_mail_consumer<E,A>(channel, email_config_repo, audit_repo)` — mirrors audit_consumer.rs loop, consumes from `axiam.mail.outbound`
- `send_with_retry_and_audit` — broker-free pure async helper: resolves EmailConfig via `get_effective_config`, builds template context, renders via `render_email` (HTML-escaped, D-18), sends via `EmailService::from_config`
- On failure: if `attempt_count + 1 < MAX_RETRIES (3)` → `SendOutcome::RetryNeeded` (consumer re-publishes with incremented count); else → `SendOutcome::Exhausted` + writes `email.delivery_failed` audit with `actor_id=user_id`, NO `to_address` in metadata (D-16)
- `MAX_RETRIES = 3`: attempts at `attempt_count` 0, 1, 2; third failure → dead-letter

**Template fix** (`crates/axiam-email/src/template.rs`):
- Added `TemplateKind::DeletionScheduled` and `TemplateKind::ExportReady` to `builtin_template` match — resolves the Wave-1 non-exhaustive break that prevented axiam-email from compiling

**Wave 0 tests** (`crates/axiam-amqp/tests/mail_consumer_test.rs`):
- `delivery_failure_first_attempt_returns_retry_needed`: SMTP to port 1 → RetryNeeded
- `exhausted_retries_writes_delivery_failed_audit_without_recipient`: last attempt → Exhausted + audit written, recipient absent from metadata (D-16)
- `missing_email_config_returns_send_error`: no config → SendError
- `successful_send_via_mock_config_returns_delivered`: MockProvider succeeds
- All 6 tests (4 new + 2 from messages.rs) pass

**Server wiring** (`crates/axiam-server/src/main.rs`):
- `AppConfig` extended with `email_encryption_key: Option<[u8; 32]>` and `gdpr_pseudonym_pepper: Option<[u8; 32]>` (serde(skip), loaded from env)
- Loads `AXIAM__EMAIL_ENCRYPTION_KEY` (hex, 64-char) and `AXIAM__GDPR_PSEUDONYM_PEPPER` with warn-if-unset
- Boot backfill block: calls `SurrealEmailConfigRepository::backfill_plaintext_secrets()` (D-17)
- Spawns `start_mail_consumer` via `tokio::spawn` when email_encryption_key is present (T-5-key-absent: warn and skip if absent)

**Email config backfill** (`crates/axiam-db/src/repository/email_config.rs`):
- `backfill_plaintext_secrets()`: idempotent — counts rows with unencrypted secrets; returns 0 on v15+ (no plaintext column in schema); logs warning if >0 pending rows; UPDATE path deferred to T19.22

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed non-exhaustive TemplateKind match in axiam-email**
- **Found during:** Task 1 setup (pre-existing Wave-1 deferred break per plan prerequisites)
- **Issue:** `builtin_template()` in `axiam-email/src/template.rs` lacked arms for `DeletionScheduled` and `ExportReady` — axiam-email would not compile
- **Fix:** Added full builtin templates for both new kinds (HTML+text+subject)
- **Files modified:** `crates/axiam-email/src/template.rs`
- **Commit:** 89ff992

**2. [Rule 1 - Bug] Fixed non-exhaustive UserStatus match in axiam-api-grpc**
- **Found during:** Task 2 (cargo check -p axiam-server caught it)
- **Issue:** `status_to_string()` in `axiam-api-grpc/src/services/user.rs:38` lacked `UserStatus::Anonymized` arm added in Wave 1
- **Fix:** Added `UserStatus::Anonymized => "anonymized".into()`
- **Files modified:** `crates/axiam-api-grpc/src/services/user.rs`
- **Commit:** 89ff992

**3. [Rule 2 - Missing functionality] backfill UPDATE path deferred (T19.22)**
- **Found during:** Task 2 implementation
- **Decision:** Since email_config table was introduced with encrypted columns only in Schema v15 (Phase 5), no plaintext columns exist. The backfill method counts pending rows but the UPDATE path is deferred to T19.22 (no data to migrate on v15+ deployment). Logged as TODO in roadmap.

**4. [Rule 2 - Missing functionality] Template repository lookup deferred (T19.21)**
- **Found during:** Task 1 implementation
- **Decision:** Consumer uses built-in templates only. Per-org/tenant custom template lookup via `SurrealEmailTemplateRepository` deferred to T19.21.

## Known Stubs

None — all delivery paths are wired. Template resolution uses built-in defaults (T19.21 will add custom templates).

## Self-Check: PASSED

Files verified:
- `crates/axiam-amqp/src/mail_consumer.rs` — EXISTS
- `crates/axiam-amqp/tests/mail_consumer_test.rs` — EXISTS
- `crates/axiam-amqp/src/lib.rs` — EXISTS (contains re-export)
- `crates/axiam-server/src/main.rs` — EXISTS (contains key loading + spawn)

Commits verified:
- 89ff992 — feat(05-03): add mail consumer with retry/audit + fix template exhaustive match
- 2426295 — feat(05-03): load email keys, add backfill, spawn mail consumer at startup

Tests: `cargo test -p axiam-amqp` → 6 passed (0 failed)
Checks: `cargo check -p axiam-amqp -p axiam-email --tests` → OK
Checks: `cargo check -p axiam-server --no-default-features --tests` → OK (0 errors)
