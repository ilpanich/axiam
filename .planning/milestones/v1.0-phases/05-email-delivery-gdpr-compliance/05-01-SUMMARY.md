---
phase: 05-email-delivery-gdpr-compliance
plan: "01"
subsystem: db-core-auth
tags: [gdpr, schema-migration, encryption-at-rest, pseudonymization, consent, account-deletion, export-job]
dependency_graph:
  requires: []
  provides:
    - schema_v15_migration
    - SurrealEmailConfigRepository
    - gdpr_pseudonym_helper
    - user_anonymization_methods
    - SurrealAuditLogRepository.pseudonymize_actor
    - SurrealConsentRepository
    - SurrealAccountDeletionRepository
    - SurrealExportJobRepository
    - SurrealErasureProofRepository
  affects:
    - axiam-db (schema, repositories)
    - axiam-auth (crypto)
    - axiam-core (models, repository traits)
tech_stack:
  added: [hmac (axiam-auth), aes-gcm (axiam-db), base64 (axiam-db)]
  patterns: [AES-256-GCM split-output encrypt-at-write/decrypt-at-read, HMAC-SHA256 keyed pseudonym, SurrealValue derive row structs, CREATE type::record pattern]
key_files:
  created:
    - crates/axiam-core/src/models/gdpr.rs
    - crates/axiam-db/src/repository/email_config.rs
    - crates/axiam-db/src/repository/consent.rs
    - crates/axiam-db/src/repository/account_deletion.rs
    - crates/axiam-db/src/repository/export_job.rs
    - crates/axiam-db/src/repository/erasure_proof.rs
  modified:
    - crates/axiam-db/src/schema.rs (SCHEMA_V15 + MIGRATIONS entry)
    - crates/axiam-core/src/models/user.rs (UserStatus::Anonymized, deletion_pending, scheduled_purge_at)
    - crates/axiam-core/src/models/email_template.rs (DeletionScheduled, ExportReady)
    - crates/axiam-core/src/models.rs (pub mod gdpr)
    - crates/axiam-core/src/repository.rs (GDPR traits, pseudonymize_actor)
    - crates/axiam-auth/src/crypto.rs (gdpr_pseudonym, hmac dep)
    - crates/axiam-auth/Cargo.toml (hmac dep)
    - crates/axiam-db/Cargo.toml (aes-gcm, base64 deps)
    - crates/axiam-db/src/repository/user.rs (UserStatus::Anonymized, deletion fields, GDPR methods)
    - crates/axiam-db/src/repository/audit.rs (pseudonymize_actor impl + test)
    - crates/axiam-db/src/repository/group.rs (Anonymized arm, deletion_pending defaults)
    - crates/axiam-db/src/repository/service_account.rs (Anonymized arm)
    - crates/axiam-auth/src/service.rs (Anonymized arm in check_user_status)
    - crates/axiam-db/src/repository/mod.rs (new pub mods)
    - crates/axiam-db/src/lib.rs (new re-exports)
decisions:
  - "Schema OVERWRITE required for extending existing field ASSERTs in SurrealDB v3 (user.status, audit_log permissions, email_template.kind) — IF NOT EXISTS only works for new definitions"
  - "password_hash is TYPE string (not nullable); anonymize_user sets it to empty string tombstone instead of NULL — Argon2 output is never empty so login remains permanently blocked"
  - "No circular dep between axiam-db and axiam-auth; email_config.rs implements AES-256-GCM inline using workspace aes-gcm dep rather than importing axiam-auth"
  - "audit_log UPDATE permission (Option A schema relaxation) resolved: DEFINE TABLE OVERWRITE audit_log ... FOR update WHERE auth.role = 'gdpr_pseudonymizer'. In kv-mem test engine auth context is absent so the permission check is bypassed; the single repo method pseudonymize_actor is the true application-layer guard (D-04)"
  - "pseudonymize_actor count returned is based on entries matching nil actor_id post-scrub, not a true UPDATE return count (SurrealDB v3 UPDATE does not return modified row count directly)"
metrics:
  duration: "75 minutes"
  completed_date: "2026-06-02"
  tasks: 3
  files: 18
---

# Phase 5 Plan 01: Schema v15 + GDPR Persistence Foundation Summary

Schema migration v15 with 5 new tables and 3 field/permission alters; EmailConfigRepository encrypting all 5 provider variants at rest; gdpr_pseudonym HMAC-SHA256 helper; user anonymization pipeline; privileged audit pseudonymize_actor; 4 GDPR support repositories.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Schema v15 + model extensions | f97e5bc | schema.rs, user.rs, email_template.rs, group.rs, service_account.rs, auth/service.rs |
| 2 | EmailConfigRepository + gdpr_pseudonym | 9eba7a8 | email_config.rs, axiam-auth/crypto.rs, Cargo.tomls |
| 3 | User anonymization + audit pseudonymize_actor + GDPR repos | 9ad6b8a | audit.rs, user.rs, consent.rs, account_deletion.rs, export_job.rs, erasure_proof.rs, gdpr.rs |

## What Was Built

**Schema v15** (`SCHEMA_V15` in schema.rs, `Migration { version: 15, name: "phase5_email_gdpr" }`):
- `email_config` SCHEMAFULL table: all provider fields + encrypted columns (`smtp_password_ciphertext/nonce`, `api_key_ciphertext/nonce`, `secret_key_version`)
- `consent` table (immutable records, UNIQUE index on tenant+user+type+version)
- `account_deletion` table (cancel_token_hash only; status ASSERT ['pending','cancelled','completed'])
- `export_job` table (status ASSERT, single-use download_token_hash)
- `erasure_proof` table (PII-free: pseudonym + tenant_id + erased_at)
- ALTER `user`: `deletion_pending BOOL DEFAULT false`, `scheduled_purge_at option<datetime>`
- `DEFINE FIELD OVERWRITE status ON TABLE user` to add 'Anonymized' to ASSERT
- `DEFINE TABLE OVERWRITE audit_log` to add `FOR update WHERE $auth.role = 'gdpr_pseudonymizer'`
- `DEFINE FIELD OVERWRITE kind ON TABLE email_template` to add 'deletion_scheduled','export_ready'

**EmailConfigRepository** (`SurrealEmailConfigRepository<C>`):
- Constructor takes `db` + `key: [u8; 32]` (dedicated blast radius per D-17)
- All 5 providers round-trip with secrets encrypted on write / decrypted on read
- AES-256-GCM implemented inline in axiam-db (no circular dep with axiam-auth)

**gdpr_pseudonym** (`axiam-auth::crypto::gdpr_pseudonym`):
- HMAC-SHA256(pepper, tenant_id || user_id), truncated to 8 bytes (64 bits) → `DELETED_USER_{16-char-hex}`
- Determinism + difference tests pass

**User anonymization pipeline**:
- `mark_deletion_pending` → sets status=Inactive, deletion_pending=true, scheduled_purge_at
- `anonymize_user` → email→hash, username→pseudonym, password_hash→'' (empty tombstone, schema is TYPE string), mfa_secret/locked_until→NONE, metadata→{}, status→Anonymized
- `find_due_for_purge(now)` → finds users past their scheduled_purge_at

**Audit pseudonymize_actor** (D-04):
- Single sanctioned non-INSERT write on audit_log
- Full D-03 scrub: actor_id→nil UUID, metadata.actor_pseudonym→pseudonym, ip_address→NONE, PII metadata keys (email/username/name/display_name/phone)→'[redacted]', resource_id→nil where resource_id==user_id
- Returns count of entries matching nil actor_id post-scrub
- Test asserts actor_id nil, actor_pseudonym set, ip_address None, action/timestamp immutable

**GDPR support repositories**: Consent, AccountDeletion (token hash stored), ExportJob (full lifecycle), ErasureProof (INSERT-only); all with round-trip tests.

## Decisions Made

**A1 / Open Question 1 — Audit UPDATE mechanism:**
Option A (schema permission relaxation) was implemented: `DEFINE TABLE OVERWRITE audit_log SCHEMAFULL PERMISSIONS FOR update WHERE $auth.role = 'gdpr_pseudonymizer'`. In the kv-mem test engine the `$auth` context is absent so permission checks are bypassed, and tests pass. In production SurrealDB the application-layer guard (this method is the only path through which UPDATEs are issued) is the true enforcement. `FOR delete` stays `NONE` unconditionally.

**Open Question 2 — EmailConfigRepository:** Resolved by creating it in this plan. The mail consumer can now resolve provider config at startup.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SurrealDB OVERWRITE required for extending field ASSERTs**
- **Found during:** Task 1 — running tests after adding SCHEMA_V15
- **Issue:** `DEFINE FIELD status ON TABLE user` failed with "The field 'status' already exists" (SurrealDB v3 behavior). Same for audit_log table and email_template.kind.
- **Fix:** Changed to `DEFINE FIELD OVERWRITE status`, `DEFINE TABLE OVERWRITE audit_log`, `DEFINE FIELD OVERWRITE kind` for the three alter statements.
- **Files modified:** crates/axiam-db/src/schema.rs
- **Commit:** 9eba7a8

**2. [Rule 1 - Bug] password_hash schema TYPE string prevents NULL**
- **Found during:** Task 3 — user anonymization test panicked with "Expected string but found NONE"
- **Issue:** Plan spec says "password_hash=NULL" but schema `TYPE string` does not allow NULL/NONE. Setting to NONE in SurrealDB v3 is rejected.
- **Fix:** Use empty string `''` as tombstone value. Argon2id output is always non-empty, so login remains permanently blocked. Test updated to assert `password_hash == ""`.
- **Files modified:** crates/axiam-db/src/repository/user.rs
- **Commit:** 9ad6b8a

**3. [Rule 1 - Bug] Non-exhaustive match on UserStatus::Anonymized**
- **Found during:** Task 1 — cargo check on axiam-auth and axiam-db after adding Anonymized variant
- **Issue:** service.rs, group.rs, service_account.rs all had non-exhaustive match statements on UserStatus
- **Fix:** Added Anonymized arms in all three files; service.rs maps Anonymized → AccountInactive
- **Files modified:** axiam-auth/src/service.rs, axiam-db/src/repository/group.rs, axiam-db/src/repository/service_account.rs
- **Commit:** f97e5bc

**4. [Rule 2 - Missing critical] group.rs User struct missing new GDPR fields**
- **Found during:** Task 1 — cargo check error "missing fields deletion_pending, scheduled_purge_at"
- **Issue:** group.rs constructs User manually and needed the new GDPR fields
- **Fix:** Added `deletion_pending: false, scheduled_purge_at: None` defaults (group queries don't fetch deletion fields)
- **Files modified:** crates/axiam-db/src/repository/group.rs
- **Commit:** f97e5bc

**5. [Rule 2 - Architecture] No circular dep axiam-db → axiam-auth**
- **Found during:** Task 2 — planning the EmailConfigRepository
- **Issue:** axiam-auth has axiam-db as a dev-dep; adding axiam-auth as a dep of axiam-db would create a circular dependency
- **Fix:** Added aes-gcm + base64 workspace deps to axiam-db/Cargo.toml and implemented local `encrypt_field`/`decrypt_field` helpers in email_config.rs. These mirror the split-output variant in axiam-auth/crypto.rs exactly.
- **Files modified:** crates/axiam-db/Cargo.toml, crates/axiam-db/src/repository/email_config.rs

## Known Stubs

None — all repository methods are fully implemented.

## Threat Surface Scan

All security mitigations from the plan's threat register were implemented:

| Threat ID | Status |
|-----------|--------|
| T-5-secret-rest | MITIGATED: AES-256-GCM via local encrypt_field; ciphertext+nonce+key_version columns; dedicated key parameter |
| T-5-pseudonym | MITIGATED: HMAC-SHA256 with 32-byte pepper; 64-bit truncation; per-tenant scoping |
| T-5-audit-update | MITIGATED: Schema permission + single repo method guard; FOR delete stays NONE |
| T-5-token-store | MITIGATED: account_deletion stores cancel_token_hash; export_job stores download_token_hash |
| T-5-SC | N/A: No new packages from external registries; all deps are workspace-existing or already in Cargo.toml |

No new unplanned threat surface found.

## Self-Check: PASSED

All key files exist. All 3 commits verified. All acceptance criteria grep checks pass.
`cargo test -p axiam-db -p axiam-auth -p axiam-core --lib` reports 142 passed.
`cargo check -p axiam-core -p axiam-db -p axiam-auth --tests` reports no errors.
