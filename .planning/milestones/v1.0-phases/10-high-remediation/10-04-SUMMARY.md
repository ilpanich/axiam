---
phase: 10-high-remediation
plan: "04"
subsystem: settings-migrations-amqp-gdpr
tags: [data-correctness, settings, migrations, amqp, gdpr, tdd, cq-b03, cq-b05, cq-b06, cq-b38, sec-033, sec-056]
dependency_graph:
  requires: ["10-01", "10-02"]
  provides: [sparse-tenant-settings, idempotent-migrations, amqp-dlq-parity, gdpr-purge-reselect, gdpr-paginated-export, export-failed-status]
  affects: [axiam-db, axiam-amqp, axiam-server, axiam-core, axiam-api-rest]
tech_stack:
  added: []
  patterns: [sparse-overrides-store, tdd-red-green, dead-letter-queue, paginated-collection, atomic-conditional-update]
key_files:
  created:
    - crates/axiam-db/tests/req14_settings_migration_test.rs
    - crates/axiam-server/tests/req14_gdpr_test.rs
  modified:
    - crates/axiam-db/src/repository/settings.rs
    - crates/axiam-db/src/schema.rs
    - crates/axiam-amqp/src/connection.rs
    - crates/axiam-amqp/src/audit_consumer.rs
    - crates/axiam-amqp/src/authz_consumer.rs
    - crates/axiam-core/src/models/gdpr.rs
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/export_job.rs
    - crates/axiam-server/src/cleanup.rs
    - crates/axiam-api-rest/src/handlers/gdpr.rs
decisions:
  - "Store only sparse TenantSettingsOverride (Option fields) as overrides_json; merge with CURRENT org at read time — fixes stale propagation (CQ-B03/SEC-033)"
  - "Schema migration wrapped in BEGIN/COMMIT with _migration_lock startup guard (CQ-B06)"
  - "AMQP nacks set requeue=false everywhere; DLQ declared for audit+authz consumers (CQ-B05)"
  - "Export job gains Failed status; mark_failed called on sweep error; paginated audit collection replaces 10k cap (CQ-B38)"
  - "Atomic consume_ready_and_delete uses WHERE status='ready' conditional UPDATE; handler returns 403 on double-consume (SEC-056)"
metrics:
  duration: "38 minutes"
  completed: "2026-06-13"
  tasks: 3
  files_modified: 10
  files_created: 2
---

# Phase 10 Plan 04: Data-Correctness Defects — Settings, Migrations, AMQP DLQ, GDPR Summary

Sparse tenant settings + idempotent migrations + AMQP dead-lettering + GDPR purge/export correctness across four defects (CQ-B03, CQ-B05, CQ-B06, CQ-B38 / SEC-033, SEC-056).

## Commits

| Task | Type | Hash | Description |
|------|------|------|-------------|
| 1 RED | test | 9259baa | Failing tests for sparse settings + idempotent migrations |
| 1 GREEN | feat | b06d9f9 | Sparse tenant settings + transactional migrations |
| 2 | feat | 1ed4597 | AMQP DLQ parity for audit + authz consumers |
| 3 GREEN | feat | 4c7ddce | GDPR purge re-selectability, paginated export, Failed status, atomic download |

Note: Task 3 RED was embedded in the same wave as Task 1 tests; the test file `req14_gdpr_test.rs` was staged separately before GREEN.

## Task 1: Sparse Tenant Settings + Idempotent Migrations (CQ-B03/SEC-033, CQ-B06)

**Root cause fixed:** `set_tenant_override` previously stored a fully-merged `SecuritySettings` row. After an org baseline change, `get_effective_settings` read the stale merged snapshot — non-overridden tenant fields never received the new org baseline.

**Fix:** Added `overrides_json: Option<String>` column to `security_settings` table (Schema V16). Stores only the sparse `TenantSettingsOverride` (fields the tenant explicitly set). `get_effective_settings` now reads `overrides_json` directly and merges with the CURRENT org row at read time, so org baseline changes propagate immediately to all non-overridden tenant fields.

**Migration idempotency:** Each migration DDL is now wrapped in `BEGIN TRANSACTION; {ddl}; CREATE _migration SET ...; COMMIT`. A `_migration_lock` record is upserted at startup and deleted when all migrations complete — prevents concurrent startup races without a separate migration-lock table.

**Tests (3 passing):**
- `settings_baseline_propagates` — org change propagates to tenant effective settings
- `store_effective_propagates_baseline` — idempotent store then org change still propagates
- `migration_runs_twice` — double-run against fresh DB succeeds without error

## Task 2: AMQP Dead-Letter Queue Parity (CQ-B05)

**Root cause fixed:** `audit_consumer` used `nack` with default options (requeue=true implicitly set in some paths); `authz_consumer` nacked with explicit `requeue: true`. Both caused hot-loops on poison messages.

**Fix:**
- Added `AUDIT_EVENTS_DLQ` and `AUTHZ_REQUEST_DLQ` queue constants
- `declare_queues` now sets `x-dead-letter-exchange` FieldTable entry for both `axiam.audit.events` and `axiam.authz.request` queues (mirrors the existing `MAIL_OUTBOUND` pattern)
- All nacks changed to `requeue: false` so rejected messages route to DLQ instead of cycling

## Task 3: GDPR Purge/Export Correctness (CQ-B38/SEC-056)

**Four defects fixed:**

1. **Purge re-selectability:** `purge_single_user` moved `anonymize_user` to the LAST step (after pseudonymize_audit, erasure_proof, mark_completed). A partial failure before anonymize leaves the deletion row in `pending` so the next sweep picks it up cleanly.

2. **Complete paginated export:** Replaced single `audit_repo.list(..., limit: 10_000)` call with a loop collecting `PAGE_SIZE = 1_000` pages until exhausted. Ensures exports >10k audit entries are complete.

3. **Failed export status:** Added `ExportJobStatus::Failed` variant. `sweep_pending_exports` now calls `export_job_repo.mark_failed(job.id).await` when processing fails. Failed jobs are excluded from `find_queued` results.

4. **Atomic single-use download:** Replaced `mark_downloaded + delete` two-step in the REST handler with `consume_ready_and_delete` — a single `UPDATE ... WHERE status = 'ready'` that returns 0 rows if already consumed. Handler returns HTTP 403 on double-consume (TOCTTOU-safe).

**Tests (3 passing):**
- `purge_reselectable_after_partial_failure`
- `export_audit_pagination_covers_all_entries`
- `export_failure_sets_failed_status`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SurrealDB IF NOT EXISTS rejected for data records in schema.rs**
- **Found during:** Task 1 — migration lock implementation
- **Issue:** `CREATE _migration_lock:\`startup\` IF NOT EXISTS SET ...` causes a SurrealDB v3 parse error; IF NOT EXISTS is only valid for DDL (DEFINE), not data DML
- **Fix:** Changed to `UPSERT _migration_lock:\`startup\` SET locked_at = time::now()`
- **Files modified:** `crates/axiam-db/src/schema.rs`
- **Commit:** b06d9f9

**2. [Rule 1 - Bug] Duplicate SettingsRowWithId struct and duplicate DbError import**
- **Found during:** Task 1 — incremental edits to settings.rs
- **Issue:** Patch accidentally duplicated the `SettingsRowWithId` struct definition and a `use crate::error::DbError` import
- **Fix:** Removed duplicates via targeted Edit
- **Files modified:** `crates/axiam-db/src/repository/settings.rs`
- **Commit:** b06d9f9

**3. [Rule 2 - Missing critical] unwrap_or_default on fallible repo calls in aggregate_export_data**
- **Found during:** Task 3 — cleanup.rs review
- **Issue:** `consent_repo.list_consents()` and `federation_link_repo.find_by_user()` used `unwrap_or_default()` silently ignoring errors that could produce an incomplete export
- **Fix:** Replaced with `unwrap_or_else(|e| { warn!(...); vec![] })` — errors logged, export continues with empty collection and audit trail
- **Files modified:** `crates/axiam-server/src/cleanup.rs`
- **Commit:** 4c7ddce

## Known Stubs

None — all four defects are wired end-to-end with repository, service, and handler layers updated.

## Threat Flags

None — no new network endpoints, auth paths, or trust-boundary schema changes beyond the planned `overrides_json` column and `Failed` enum variant.

## Self-Check: PASSED

- `crates/axiam-db/tests/req14_settings_migration_test.rs` — EXISTS
- `crates/axiam-server/tests/req14_gdpr_test.rs` — EXISTS
- Commit 9259baa (RED) — FOUND
- Commit b06d9f9 (GREEN Task 1) — FOUND
- Commit 1ed4597 (Task 2) — FOUND
- Commit 4c7ddce (GREEN Task 3) — FOUND
- `cargo test -p axiam-db --no-default-features --test req14_settings_migration_test` — 3 passed
- `cargo check -p axiam-amqp --no-default-features` — clean
- `cargo test -p axiam-server --no-default-features --test req14_gdpr_test` — 3 passed
- `cargo check -p axiam-api-rest --no-default-features` — clean
