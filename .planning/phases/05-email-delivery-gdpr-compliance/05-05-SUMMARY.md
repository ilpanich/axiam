---
phase: 05-email-delivery-gdpr-compliance
plan: "05"
subsystem: api-rest, axiam-server
tags: [gdpr, art15, art17, erasure, export, pseudonymization, cleanup, rest, d-01, d-05, d-06, d-07, d-08, d-09, d-10, d-12, d-13, req-8]

requires:
  - phase: 05-email-delivery-gdpr-compliance
    plan: "01"
    provides: SurrealExportJobRepository, SurrealAccountDeletionRepository, SurrealErasureProofRepository, SurrealConsentRepository, user repo GDPR methods, audit pseudonymize_actor, gdpr_pseudonym, encrypt_separate/decrypt_separate
  - phase: 05-email-delivery-gdpr-compliance
    plan: "02"
    provides: OutboundMailMessage, MailType::DeletionCancel/ExportReady, queues::MAIL_OUTBOUND
  - phase: 05-email-delivery-gdpr-compliance
    plan: "03"
    provides: email_encryption_key, gdpr_pseudonym_pepper loaded in main.rs
  - phase: 05-email-delivery-gdpr-compliance
    plan: "04"
    provides: MailPublisher trait, MailOutboundPublisher, consent at registration

provides:
  - GDPR Art.15 export endpoint (POST /api/v1/account/export, GET /api/v1/account/export/{token})
  - GDPR Art.17 erasure endpoint (POST /api/v1/account/delete)
  - GDPR cancel endpoint (GET /api/v1/auth/account/delete/cancel) — public, in PUBLIC_PATHS
  - CleanupTask.sweep_pending_purges — full Art.17 purge pipeline (anonymize + pseudonymize + erasure proof)
  - CleanupTask.sweep_pending_exports — async encrypted Art.15 export generation
  - gdpr_test.rs — Wave 0 REQ-8 integration tests (4 passing)

affects:
  - crates/axiam-api-rest/src/handlers/gdpr.rs (new)
  - crates/axiam-api-rest/src/handlers/mod.rs
  - crates/axiam-api-rest/src/permissions.rs
  - crates/axiam-api-rest/src/server.rs
  - crates/axiam-server/src/cleanup.rs
  - crates/axiam-server/src/main.rs
  - crates/axiam-db/src/repository/account_deletion.rs
  - crates/axiam-db/src/repository/user.rs
  - crates/axiam-api-rest/tests/gdpr_test.rs (new)

key-decisions:
  - Export stored as DB blob (encrypted_blob field), not on-disk file — avoids filesystem management complexity and file-deletion coordination; file_path=None (A1 open question resolved: DB blob)
  - MailPublisher not dyn-compatible (impl Future return) — used Arc<MailOutboundPublisher> concrete type in CleanupTask instead of Arc<dyn MailPublisher>; handlers already used concrete type
  - AuthService in cleanup.rs uses AuthSvc<C> type alias (same 4-param pattern as auth.rs) — avoids type inference ambiguity in the generic CleanupTask<C>
  - sha2 accessed via rsa::sha2 re-export in axiam-server (no standalone sha2 dep in axiam-server Cargo.toml)
  - gdpr_test.rs tests repo logic directly (not HTTP), matching the consent_tests precedent in users.rs — avoids full actix-web harness overhead while still covering the acceptance criteria

tech-stack:
  added: []
  patterns:
    - AuthSvc<C> type alias for multi-param generic services (same as auth.rs)
    - sha256_hex helper (Sha256 + hex::encode) shared between gdpr.rs and test
    - PaginatedResult unwrap_or_else with explicit field initialisation (no Default impl)

key-files:
  created:
    - crates/axiam-api-rest/src/handlers/gdpr.rs
    - crates/axiam-api-rest/tests/gdpr_test.rs
  modified:
    - crates/axiam-server/src/cleanup.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-rest/src/handlers/mod.rs
    - crates/axiam-api-rest/src/permissions.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-db/src/repository/account_deletion.rs
    - crates/axiam-db/src/repository/user.rs

metrics:
  duration: ~90 minutes (resume from interrupted WIP)
  completed: 2026-06-02
  tasks: 3
  files: 9
---

# Phase 05 Plan 05: GDPR Art.15 Export and Art.17 Erasure Summary

GDPR Art.15 export (AES-256-GCM encrypted DB blob, single-use 24h token, all named sections, secrets excluded) and Art.17 erasure (30d grace, in-place anonymization, audit pseudonymization to DELETED_USER_<hash>, erasure proof, single-use emailed cancel link) implemented end-to-end and proven by 4 passing Wave 0 integration tests.

## What Was Built

### Task 1: GDPR REST Handlers (gdpr.rs)

Four endpoints implementing GDPR data-subject rights:

- `POST /api/v1/account/export` — enqueue async Art.15 export job; returns `{"queued": true}`
- `GET /api/v1/account/export/{token}` — single-use download (D-13): look up by SHA-256(token), decrypt AES-256-GCM blob, mark downloaded + delete job
- `POST /api/v1/account/delete` — Art.17 erasure: mark_deletion_pending(+30d), revoke_all_sessions, create account_deletion row (cancel_token_hash = SHA-256 of raw token), enqueue DeletionCancel email
- `GET /api/v1/auth/account/delete/cancel?token=` — PUBLIC endpoint: mark_cancelled + clear_deletion_pending; second call rejected (single-use)

Ownership checks: self OR gdpr:export/users:erase permission (D-07). Both permissions added to registry and permissions.rs. Cancel endpoint added to PUBLIC_PATHS.

### Task 2: CleanupTask Sweeps (cleanup.rs)

Two new sweep methods added to the existing CleanupTask tick loop:

**sweep_pending_purges** — for each user past `scheduled_purge_at`:
- (a) revoke_all_sessions
- (b) delete federation identity links
- (c) gdpr_pseudonym(pepper, tenant, user) → deterministic DELETED_USER_<hash>
- (d) anonymize_user → UserStatus::Anonymized, username/email pseudonymized
- (e) pseudonymize_actor → actor_id=nil, metadata.actor_pseudonym=pseudonym, ip_address=NULL, PII keys redacted, resource_id=nil where ==user_id
- (f) insert erasure_proof (PII-free accountability record)
- (g) mark account_deletion completed
- (h) emit gdpr.user_pseudonymized audit event (actor=System)

**sweep_pending_exports** — for each queued export job:
- Aggregate Art.15 inventory (profile, consents, audit_entries, federation_identities — secrets excluded)
- encrypt_separate(key, json_bytes) → AES-256-GCM (D-12)
- set_ready with SHA-256-hashed 24h single-use download token (D-13)
- Enqueue ExportReady mail with raw token

Both sweeps guarded on key presence (skip + warn if absent — pitfall 6).

### Task 3: gdpr_test.rs — 4 Wave 0 Tests

- `export_completeness` — all 10 Art.15 sections present; password_hash/mfa_secret/token_hash absent from decrypted JSON
- `deletion_pseudonymization` — UserStatus::Anonymized, DELETED_USER_ prefix, actor_id=nil, ip_address=None, original UUID absent from audit entries, erasure_proof created
- `consent_on_registration` — exactly one terms_of_service consent row after user creation
- `deletion_cancel` — first cancel clears deletion_pending; second cancel rejected (AccountDeletionStatus::Cancelled != Pending)

All 4 pass. Full suite: 0 new failures (the 3 SAML-off pre-existing failures remain).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] MailPublisher not dyn-compatible**
- **Found during:** Task 2 (axiam-server compile)
- **Issue:** `MailPublisher` trait uses `impl Future` in return position — not object-safe. `Arc<dyn MailPublisher>` in main.rs (from prior WIP) caused 6 E0038 errors.
- **Fix:** Changed `CleanupTask.mail_publisher` from `Arc<dyn MailPublisher>` to `Arc<MailOutboundPublisher>` (concrete type). Updated main.rs to match. Same pattern already used by handlers (web::Data<MailOutboundPublisher>).
- **Files:** crates/axiam-server/src/cleanup.rs, crates/axiam-server/src/main.rs

**2. [Rule 1 - Bug] AuthService<C> wrong arity in gdpr.rs and cleanup.rs**
- **Found during:** Task 1 + 2 (compile)
- **Issue:** Prior WIP used `AuthService<C>` (1 generic arg) but `AuthService` takes 4 (U, S, F, T). E0107 errors.
- **Fix:** Added `type AuthSvc<C> = AuthService<SurrealUserRepository<C>, SurrealSessionRepository<C>, SurrealFederationLinkRepository<C>, SurrealRefreshTokenRepository<C>>` alias in both files.
- **Files:** crates/axiam-api-rest/src/handlers/gdpr.rs, crates/axiam-server/src/cleanup.rs

**3. [Rule 1 - Bug] ActorType/AuditOutcome string coercions fail**
- **Found during:** Task 1 + 2 (compile)
- **Issue:** `"user".into()` / `"success".into()` don't impl `From<&str>`. E0277 errors.
- **Fix:** Used `ActorType::User`, `ActorType::System`, `AuditOutcome::Success` enum variants directly.
- **Files:** crates/axiam-api-rest/src/handlers/gdpr.rs, crates/axiam-server/src/cleanup.rs

**4. [Rule 1 - Bug] metadata field type mismatch (Value vs Option<Value>)**
- **Found during:** Task 1 + 2 (compile)
- **Issue:** `CreateAuditLogEntry.metadata` is `Option<serde_json::Value>` but code passed `serde_json::json!({...})` (unwrapped Value). E0308 errors.
- **Fix:** Wrapped all `serde_json::json!({...})` in `Some(...)`.
- **Files:** crates/axiam-api-rest/src/handlers/gdpr.rs, crates/axiam-server/src/cleanup.rs

**5. [Rule 1 - Bug] AxiamError::Unauthorized doesn't exist**
- **Found during:** Task 1 (compile)
- **Issue:** Prior WIP used `AxiamError::Unauthorized { reason }` — variant not in AxiamError enum. E0599 errors.
- **Fix:** Changed to `AxiamError::AuthorizationDenied { reason }`.
- **Files:** crates/axiam-api-rest/src/handlers/gdpr.rs

**6. [Rule 1 - Bug] sha2 not a direct dep of axiam-server**
- **Found during:** Task 2 (compile)
- **Issue:** `use sha2::{Digest, Sha256}` unresolved in axiam-server context.
- **Fix:** Changed to `use rsa::sha2::{Digest, Sha256}` (sha2 re-exported by the rsa crate which is a dep).

**7. [Rule 1 - Bug] Missing trait imports (AssertionReplayRepository, FederationLoginStateRepository)**
- **Found during:** Task 2 (compile)
- **Issue:** `cleanup_expired()` method not in scope.
- **Fix:** Added both traits to the repository use list.

**8. [Rule 1 - Bug] PaginatedResult has no Default impl**
- **Found during:** Task 2 (compile)
- **Issue:** `.unwrap_or_default()` on audit_repo.list() result — PaginatedResult<T> doesn't impl Default.
- **Fix:** Changed to `.unwrap_or_else(|_| PaginatedResult { items: vec![], total: 0, offset: 0, limit: 10_000 })`.

## Open Question Resolution

**A1 (export storage backend):** DB blob chosen. `encrypted_blob` stored in the `export_job` table as a base64 string; `file_path = None`. Avoids filesystem lifecycle management, file-deletion race conditions, and mount-point dependencies. The download handler decrypts on-the-fly from the DB field. Trade-off: blob size limited to SurrealDB document limits (adequate for typical GDPR exports).

## Known Stubs

None — all sections in the export are wired to real DB queries. Sessions, assignments, group_memberships, and webauthn_credentials return empty arrays (reflecting actual DB state for test users); these tables have real repos, the export just returns what's there.

## Threat Flags

None — all STRIDE mitigations from the plan's threat model are implemented:
- T-5-export-token: single-use SHA-256 token, delete-on-download ✓
- T-5-export-rest: AES-256-GCM via encrypt_separate ✓
- T-5-pseudonym: keyed HMAC-SHA256 via gdpr_pseudonym ✓
- T-5-delete: ownership check + users:erase permission ✓
- T-5-cancel: single-use hash-stored token, consumed on click ✓
- T-5-purge-tenant: all queries scoped by tenant_id ✓
- T-5-audit-update: only pseudonymize_actor UPDATEs audit_log ✓

## Self-Check: PASSED

Files created:
- crates/axiam-api-rest/src/handlers/gdpr.rs — FOUND
- crates/axiam-api-rest/tests/gdpr_test.rs — FOUND

Commits:
- 4d182c8 feat(05-05): GDPR Art.15/Art.17 REST handlers — FOUND
- 2e21759 feat(05-05): CleanupTask purge + export sweeps — FOUND
- bd95365 test(05-05): Wave 0 gdpr_test.rs — FOUND

Tests: `cargo test -p axiam-api-rest --no-default-features --test gdpr_test` → 4 passed
Full suite: 0 new failures (3 pre-existing SAML-off failures unchanged)
Server: `cargo check -p axiam-server --no-default-features --tests` → 0 errors
