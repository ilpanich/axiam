---
phase: 12-low-remediation
plan: "01"
subsystem: backend-cleanup
tags: [cq-b28, cq-b29, cq-b31, cq-b33, cq-b34, cq-b35, cq-b36, cq-b42, axiam-auth, axiam-api-rest, axiam-audit, axiam-db, axiam-server, axiam-oauth2]
dependency_graph:
  requires: []
  provides: [shared-client-extractor, logged-errors, hibp-sync-change-password, seeder-hash-skip]
  affects: [axiam-api-rest, axiam-auth, axiam-audit, axiam-db, axiam-server, axiam-oauth2, axiam-authz, axiam-pki]
tech_stack:
  added: []
  patterns:
    - shared-capped-extractor
    - if-let-err-tracing
    - sha256-hash-guard
    - surreal-upsert-seeder-state
key_files:
  created:
    - crates/axiam-api-rest/src/extractors/client_info.rs
    - crates/axiam-db/tests/seeder_skip_test.rs
  modified:
    - crates/axiam-api-rest/src/extractors/mod.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/src/handlers/webauthn.rs
    - crates/axiam-api-rest/src/handlers/users.rs
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-server/src/cleanup.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-rest/src/handlers/gdpr.rs
    - crates/axiam-oauth2/src/token.rs
    - crates/axiam-audit/src/middleware.rs
    - crates/axiam-auth/src/error.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-auth/tests/auth_service_test.rs
    - crates/axiam-db/src/seeder.rs
    - crates/axiam-db/src/schema.rs
    - crates/axiam-db/src/repository/role.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-auth/Cargo.toml
    - crates/axiam-db/Cargo.toml
    - crates/axiam-authz/Cargo.toml
    - crates/axiam-pki/Cargo.toml
decisions:
  - "CQ-B29: NotificationDispatcher REMOVED from app_data (not wired); wiring requires rule_repo + mail_publisher in the audit worker — deferred to Phase 19"
  - "CQ-B27/CQ-B43 AppState refactor: explicitly deferred to Phase 19; TODO(T19) added near OidcFederationService construction in federation.rs"
  - "rand removed from axiam-db: compile check failed — direct use confirmed; kept with re-export comment"
  - "rand_core 0.6 pins in axiam-pki/axiam-server: retained with explicit comment per MEMORY.md"
metrics:
  duration: "~45 minutes"
  completed: "2026-06-19T08:21:31Z"
  tasks: 3
  files_created: 2
  files_modified: 21
---

# Phase 12 Plan 01: Backend Cleanup / Dead-Code / Shared Helpers Summary

Single shared client_ip/user_agent extractor, logged error handling at five GDPR/audit-drop sites, typed crypto error variants, dep pruning with rand_core pins preserved, HIBP wired to sync change-password, structured alertable audit-drop event, and hash-guarded seeder with seeder_state table and a passing skip test.

## Tasks Completed

### Task 1: Shared client_ip/user_agent extractor (CQ-B28)

Created `crates/axiam-api-rest/src/extractors/client_info.rs` with two `pub fn` — `client_ip` (realip_remote_addr, capped to 45 chars) and `user_agent` (user-agent header, capped to 512 chars). Registered as `pub mod client_info` in `extractors/mod.rs`. Removed private duplicate definitions from `handlers/auth.rs` and `handlers/webauthn.rs` (including MAX_IP_LEN/MAX_UA_LEN constants). Replaced the inline header read in `handlers/users.rs`. All three handlers import from `crate::extractors::client_info`.

Commit: `262483a`

### Task 2: Logged errors, audit-drop metric, typed crypto, dep pruning (CQ-B29/31/33/34/36)

**CQ-B31 — Silent errors replaced:**
- `cleanup.rs:247` — federation link delete: `let _ =` → `if let Err(e) { tracing::warn! }`
- `cleanup.rs:294` — account_deletion mark_completed: same pattern
- `cleanup.rs:314` — GDPR audit append: `let _ =` → `if let Err(e) { tracing::error! }` (legally significant)
- `gdpr.rs:124` — `append_gdpr_audit` helper: `let _ =` → `if let Err(e) { tracing::error! }`
- `token.rs:555` — orphan revoke cleanup: `let _ =` → `if let Err(e) { tracing::warn! }`

**CQ-B36 — Audit-drop metric:** `middleware.rs:161` escalated from `warn!` to `tracing::error!(audit_dropped = true, method, path, ...)`. The `warn` import was removed; remaining warn calls updated to `tracing::warn!`.

**CQ-B33 — Typed crypto errors:** Added `AuthError::CryptoKeyParse`, `CryptoAesDecrypt`, `CryptoHmacInvalid` sub-variants to `error.rs`. All map to `AxiamError::Crypto` via the existing From impl.

**CQ-B29 — NotificationDispatcher decision: REMOVED.** `NotificationPublisher` removed from `app_data` registration in `main.rs`. The `dispatch()` method requires both `rule_repo: &impl NotificationRuleRepository` and `mail_publisher: &impl MailPublisher` — neither is available in the audit worker's scope (the worker holds only `AuditLogRepository`). Wiring would require a larger refactor (deferred to Phase 19). Variable prefixed with `_notification_publisher` to suppress unused-variable warning.

**CQ-B34 — Dep pruning:**
- `webauthn-rs-proto` removed from `axiam-auth` (types re-exported via `webauthn-rs`)
- `rand` kept in `axiam-db` (compile check failed — direct use confirmed)
- `rand_core = "0.6"` pins in `axiam-pki` and `axiam-server` retained; comments added: "Required: pgp/rsa crate uses rand_core 0.6 CryptoRng"
- Comments added to `axiam-authz` Cargo.toml confirming serde/thiserror/tracing are needed

Commit: `a9d0c80`

### Task 3: HIBP on sync change-password + seeder hash-skip + seeder_state table (CQ-B35/B42)

**CQ-B35 — HIBP on sync change-password:**
- Added `http_client: Option<&reqwest::Client>` parameter to `AuthService::change_password` in `service.rs`
- Replaced `None, // no HIBP client` at line ~715 with `http_client`
- `handlers/auth.rs` change_password handler now extracts `web::Data<reqwest::Client>` and passes `Some(http_client.as_ref())`
- `reqwest::Client` was already registered in `main.rs:637` — no change needed there
- Updated two call sites in `auth_service_test.rs` with `None` for the new param

**CQ-B42 — Seeder hash-skip:**
- `seed_permissions` now computes sha256 of registry (`sha2::Sha256`, `hex::encode`), reads `seeder_state` for tenant, returns early if hash matches
- After successful UPSERT loop, persists hash to `seeder_state` via `UPSERT type::record('seeder_state', $id)`
- `SeederStateRow { hash: String }` pub struct added deriving `SurrealValue`
- Schema migration v20 adds `seeder_state` table (SCHEMAFULL, IF NOT EXISTS)
- `SurrealRoleRepository::get_by_name(tenant_id, name)` added to repository/role.rs
- `SeederStateRow` exported from `axiam_db` crate

**TDD — RED→GREEN:**
- RED commit: `crates/axiam-db/tests/seeder_skip_test.rs` written with two tests; failed on `SeederStateRow` not found
- GREEN commit: implementation added; `cargo test -p axiam-db --test seeder_skip_test`: 2 passed

Commit: `1c1216c` (implementation) + `b7c38e5` (test call-site fix)

**CQ-B27/CQ-B43 — AppState refactor deferred:** Added `// TODO(T19): AppState refactor — CQ-B27/CQ-B43 deferred` comment near `OidcFederationService::new(...)` in `handlers/federation.rs`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `warn!` macro import removed from middleware.rs**
- Found during: Task 2
- Issue: Removing `use tracing::warn;` while two other warn! calls in audit_worker remained — compilation failure
- Fix: Updated both remaining `warn!` calls to `tracing::warn!` (consistent qualified path)
- Files modified: `crates/axiam-audit/src/middleware.rs`

**2. [Rule 3 - Blocking] auth_service_test.rs change_password call-site arity mismatch**
- Found during: Task 3 overall verification
- Issue: Two test call sites in `auth_service_test.rs` did not pass the new `http_client` param
- Fix: Added `None` as final argument to both calls
- Files modified: `crates/axiam-auth/tests/auth_service_test.rs`
- Commit: `b7c38e5`

### Decisions

**CQ-B29 — NotificationDispatcher: REMOVED (not wired)**
The `NotificationDispatcher::dispatch()` signature requires `rule_repo: &impl NotificationRuleRepository` and `mail_publisher: &impl MailPublisher`. Neither is available in the `AuditMiddleware` worker task (holds only `AuditLogRepository`). Wiring would require a structural change to the audit worker — a new service type with three generic bounds. Given this is a LOW finding (CQ-B29), the simpler fix is to remove the unused `app_data` registration. Deferred to Phase 19.

**CQ-B27/CQ-B43 — AppState refactor deferred to Phase 19**
Per plan objective: significant scope (refactor main.rs + every handler signature). TODO(T19) note added.

**rand in axiam-db — kept**
`cargo check` failed when rand was removed from axiam-db. Kept with comment `# used via <dep> re-export pattern; do not remove`.

## Threat Surface Scan

No new network endpoints, auth paths, or schema trust boundaries introduced. The `seeder_state` table is internal infrastructure — no user-controlled inputs. No threat flags.

## Known Stubs

None. All functionality is wired end-to-end.

## Self-Check

Files exist:
- `crates/axiam-api-rest/src/extractors/client_info.rs`: FOUND
- `crates/axiam-db/tests/seeder_skip_test.rs`: FOUND
- `crates/axiam-db/src/schema.rs` contains `seeder_state`: FOUND

Commits exist:
- `262483a` (Task 1): FOUND
- `a9d0c80` (Task 2): FOUND
- `1c1216c` (Task 3): FOUND
- `b7c38e5` (test fix): FOUND

Test result: `cargo test -p axiam-db --test seeder_skip_test --no-default-features`: 2 passed

## Self-Check: PASSED
