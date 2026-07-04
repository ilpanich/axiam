---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 04
subsystem: database
tags: [surrealdb, gdpr, repository, unique-index, rust]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: "25-01/25-02/25-03 federation/PKI hardening fixes (parallel-wave siblings, no direct dependency)"
provides:
  - "SessionRepository::list_by_user(tenant_id, user_id) -> Vec<Session>, tenant-scoped"
  - "export_job::has_pending_for_user widened to block queued/ready/failed (not just queued)"
  - "erasure_proof.user_id field + DB UNIQUE index on (tenant_id, user_id)"
affects: [25-05-PLAN.md]

# Tech tracking
tech-stack:
  added: []
  patterns: ["SurrealDB DEFINE INDEX ... UNIQUE for idempotent-retry invariants", "tenant-scoped SELECT with meta::id(id) AS record_id for full-row reads"]

key-files:
  created: []
  modified:
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/session.rs
    - crates/axiam-db/src/repository/export_job.rs
    - crates/axiam-db/src/repository/erasure_proof.rs
    - crates/axiam-core/src/models/gdpr.rs
    - crates/axiam-db/src/schema.rs
    - crates/axiam-server/src/cleanup.rs
    - crates/axiam-api-rest/tests/gdpr_test.rs

key-decisions:
  - "Added erasure_proof.user_id column (model + schema + repository) since it did not previously exist — D-03b's locked decision requires a UNIQUE index on it, but the current erasure_proof table only carried pseudonym/tenant_id/erased_at"
  - "UNIQUE index defined on (tenant_id, user_id), not a bare user_id — erasure_proof is tenant-scoped like every other domain entity in this codebase (mirrors idx_erasure_proof_tenant, idx_user_tenant_username, etc.)"
  - "SessionRepository::list_by_user returns full Session rows including token_hash; redaction is the caller's responsibility (D-03c), exercised in plan 25-05's export path"

patterns-established:
  - "list_by_user pattern mirrors get_by_token_hash's meta::id(id) AS record_id projection for full-row tenant-scoped reads"

requirements-completed: [SECHRD-06]

coverage:
  - id: D1
    description: "SessionRepository::list_by_user returns exactly the target user's sessions, tenant-scoped"
    requirement: "SECHRD-06"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/repository/session.rs#list_by_user_returns_only_target_users_sessions"
        status: pass
    human_judgment: false
  - id: D2
    description: "export_job::has_pending_for_user blocks queued/ready/failed but not downloaded"
    requirement: "SECHRD-06"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/repository/export_job.rs#export_job_dedup_blocks_ready_and_failed"
        status: pass
    human_judgment: false
  - id: D3
    description: "erasure_proof has a DB UNIQUE index on (tenant_id, user_id) enforcing idempotent duplicate-proof rejection"
    requirement: "SECHRD-06"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/repository/erasure_proof.rs#erasure_proof_duplicate_user_rejected_by_unique_index"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 04: DB-Layer GDPR Erasure/Export Prerequisites Summary

**SessionRepository::list_by_user + widened export dedup (queued/ready/failed) + erasure_proof.user_id UNIQUE index — the durable DB invariants plan 25-05's GDPR erasure/export negative tests build on.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-04T16:32:00Z (approx, following 25-03 completion)
- **Completed:** 2026-07-04T16:57:33Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Added `SessionRepository::list_by_user(tenant_id, user_id) -> Vec<Session>` (trait + `SurrealSessionRepository` impl), tenant-scoped, mirroring the `get_by_token_hash` query shape
- Widened `export_job::has_pending_for_user`'s dedup filter from `status IN ['queued']` to `status IN ['queued', 'ready', 'failed']` — a `downloaded` job still allows a fresh request
- Added `erasure_proof.user_id` (model, schema, repository) and a DB `UNIQUE` index on `(tenant_id, user_id)`, so a retried erasure's duplicate proof `CREATE` is rejected idempotently at the schema level

## Task Commits

Each task was committed atomically:

1. **Task 1: Add SessionRepository::list_by_user (trait + Surreal impl), metadata-only** - `39b1fbb` (feat)
2. **Task 2: Widen export dedup filter + add UNIQUE index on erasure_proof.user_id** - `440c284` (feat)

_Note: the Task 2 commit also folds in a trivial `cargo fmt` reflow of Task 1's test (session.rs) and the two other call sites that needed `user_id` added to compile against the widened `CreateErasureProof` struct._

## Files Created/Modified
- `crates/axiam-core/src/repository.rs` - Added `list_by_user` to the `SessionRepository` trait
- `crates/axiam-db/src/repository/session.rs` - `SurrealSessionRepository::list_by_user` impl + test
- `crates/axiam-db/src/repository/export_job.rs` - Widened `has_pending_for_user` status filter + `export_job_dedup_blocks_ready_and_failed` test
- `crates/axiam-core/src/models/gdpr.rs` - Added `user_id: Uuid` to `ErasureProof`/`CreateErasureProof`
- `crates/axiam-db/src/schema.rs` - Added `erasure_proof.user_id` field + `idx_erasure_proof_tenant_user` UNIQUE index on `(tenant_id, user_id)`
- `crates/axiam-db/src/repository/erasure_proof.rs` - Read/write `user_id`; added `erasure_proof_duplicate_user_rejected_by_unique_index` test
- `crates/axiam-server/src/cleanup.rs` - Updated the existing `CreateErasureProof` call site to pass `user_id` (compile fix only — ordering/error-swallowing bugs the plan documents as pre-existing pitfalls are explicitly out of scope for this plan and belong to plan 25-05)
- `crates/axiam-api-rest/tests/gdpr_test.rs` - Updated the existing `CreateErasureProof` call site + added a `user_id` assertion

## Decisions Made
- `erasure_proof.user_id` did not exist on the table/model before this plan (only `pseudonym`/`tenant_id`/`erased_at`). D-03b (locked in 25-CONTEXT.md) explicitly calls for a UNIQUE index on `user_id`, so the column was added as part of this plan rather than treated as a blocker — this is a schema column addition (Rule 2: missing critical functionality for a locked design decision), not a new table or architectural pivot.
- Uniqueness scoped to `(tenant_id, user_id)` rather than a bare `user_id`, consistent with every other tenant-scoped UNIQUE index in `schema.rs` (documented with a one-line comment in the schema per the plan's own note).
- `list_by_user` returns complete `Session` rows (including `token_hash`); the plan explicitly assigns token-hash redaction to the caller (plan 25-05's export path), not this method.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `erasure_proof.user_id` column (model + schema + repository)**
- **Found during:** Task 2
- **Issue:** The plan's `read_first` step assumed `erasure_proof`'s `user_id`/`tenant_id` columns "exist from prior phases," but the actual table (`schema.rs:969-975`) only had `pseudonym`, `tenant_id`, and `erased_at` — there was no `user_id` field to index. D-03b (25-CONTEXT.md, locked decision) explicitly requires uniqueness on `user_id`.
- **Fix:** Added `user_id: Uuid` to the `ErasureProof`/`CreateErasureProof` models, a `user_id` schema field on `erasure_proof`, and a `DEFINE INDEX ... COLUMNS tenant_id, user_id UNIQUE` index. Updated the repository's `create()` to write/read the new field, and updated the two pre-existing call sites (`cleanup.rs`, `gdpr_test.rs`) to pass `user_id` so the build stays green.
- **Files modified:** `crates/axiam-core/src/models/gdpr.rs`, `crates/axiam-db/src/schema.rs`, `crates/axiam-db/src/repository/erasure_proof.rs`, `crates/axiam-server/src/cleanup.rs`, `crates/axiam-api-rest/tests/gdpr_test.rs`
- **Verification:** `erasure_proof_duplicate_user_rejected_by_unique_index` test asserts a second `create()` for the same `(tenant_id, user_id)` fails; `cargo build -p axiam-server`, `cargo test -p axiam-api-rest --test gdpr_test --no-run` both compile clean.
- **Committed in:** `440c284` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical / locked-decision gap)
**Impact on plan:** Necessary to satisfy D-03b as written; no scope creep beyond the column this plan's own must_haves already mandated. Plan 25-05's `run_erasure_pipeline` (per 25-RESEARCH.md Pattern 3) will need to pass `user_id` into its `CreateErasureProof { .. }` construction — the RESEARCH.md code snippet predates this column and is now stale on that one field name, but the ordering/fatal-propagation logic it documents is unaffected.

## Issues Encountered
None beyond the deviation above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `SessionRepository::list_by_user`, the widened export dedup, and the `erasure_proof` UNIQUE index are all in place and tested — plan 25-05 (`cleanup.rs`'s `run_erasure_pipeline` refactor and negative tests) can now proceed.
- Flag for 25-05's planner/executor: `CreateErasureProof` now requires a `user_id: Uuid` field (added this plan); 25-RESEARCH.md's Pattern 3 snippet and 25-PATTERNS.md's matching example predate this and will need `user_id` added to their `CreateErasureProof { .. }` literal when implemented.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*
