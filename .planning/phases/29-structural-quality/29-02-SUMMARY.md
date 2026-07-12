---
phase: 29-structural-quality
plan: 02
subsystem: database
tags: [surrealdb, transactions, rbac, gdpr, rust]

# Dependency graph
requires:
  - phase: 29-structural-quality
    provides: "29-01's classify_write_error/DbError::Serialization helpers (used for the account_deletion.rs write-path classification)"
provides:
  - "role.rs::delete — single tenant-predicated transaction (has_role/grants edge deletes no longer strip foreign-tenant edges)"
  - "resource.rs::delete — single tenant-predicated transaction with an in-transaction (LET-captured) child-count guard, closing the child-guard TOCTOU"
  - "SurrealAccountDeletionRepository::create_with_pending_flag — single transaction marking a user deletion-pending and creating its account_deletion row, with an in-transaction duplicate-pending guard"
affects: [29-03, 29-04, 29-05, 29-06, 29-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Node-tenant subquery guard (out.tenant_id = $tenant_id / in.tenant_id = $tenant_id via graph-traversal dereference) for tenant-scoping DELETEs on edge tables that carry no tenant_id field of their own — mirrors the existing out.tenant_id projection pattern already used by role.rs::get_user_role_assignments"
    - "LET-capture guard inside a transaction (LET $x = (...); IF ...len($x) > 0 { THROW ...}; <mutating statements>) to fold a pre-check into the same atomic unit as the mutation it gates, closing TOCTOU windows that a separate pre-check .query() round-trip would leave open"

key-files:
  created: []
  modified:
    - crates/axiam-db/src/repository/role.rs
    - crates/axiam-db/src/repository/resource.rs
    - crates/axiam-db/src/repository/account_deletion.rs
    - crates/axiam-api-rest/src/handlers/gdpr.rs
    - crates/axiam-db/tests/role_permission_test.rs
    - crates/axiam-db/tests/resource_scope_test.rs
    - crates/axiam-api-rest/tests/gdpr_test.rs

key-decisions:
  - "Resolved the open schema question (RESEARCH.md): has_role/grants/child_of/on_resource edge tables carry NO tenant_id field of their own (schema.rs only defines UNIQUE(in,out) indexes on them) — tenant predicates on these four DELETEs are expressed as node-tenant subquery guards (out.tenant_id / in.tenant_id, dereferencing the linked record's field via graph traversal) rather than flat WHERE clauses. scope and the resource/role records themselves DO carry their own tenant_id field and keep flat predicates."
  - "resource::delete's child-count guard is captured via LET $children = (SELECT VALUE id FROM child_of WHERE out = resource:id) + IF array::len($children) > 0 { THROW ... } inside the transaction, rather than a scalar count() aggregation — this mirrors the array::len($u)/$r cross-tenant guard idiom already used throughout role.rs/permission.rs, avoiding a new SurrealQL scalar-coalesce pattern."
  - "Added a duplicate-pending-request guard inside create_with_pending_flag's transaction (Rule 2): without it, a double-submit race could mint two live account_deletion rows (two outstanding cancel tokens) for the same user. The guard also gives the atomicity test a genuine, reproducible way to force the CREATE to fail post-UPDATE without inventing an artificial UUID collision or adding a new schema-level UNIQUE index (schema.rs was intentionally out of this plan's file scope)."
  - "create_with_pending_flag returns the AccountDeletion built entirely from client-known values (generated id, inputs, Utc::now() bound explicitly as $created_at) rather than .take()-ing the CREATE statement's row — this sidesteps needing to verify exact result-slot indices for a transaction containing an UPDATE, a LET, and an IF/THROW ahead of the CREATE."

requirements-completed: [QUAL-04]

coverage:
  - id: D1
    description: "role.rs::delete runs has_role/grants edge deletes and the role record delete inside one BEGIN/COMMIT transaction, with has_role/grants tenant-scoped via a node-tenant subquery guard — a foreign-tenant role id can no longer strip that tenant's edges"
    requirement: "QUAL-04"
    verification:
      - kind: integration
        ref: "crates/axiam-db/tests/role_permission_test.rs#delete_role_does_not_strip_foreign_tenant_edge"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/tests/role_permission_test.rs#delete_role_removes_own_tenant_edges"
        status: pass
    human_judgment: false
  - id: D2
    description: "resource.rs::delete folds the child-count guard into the same transaction as the deletes via a LET-capture, closing the CQ-B46 TOCTOU; child_of/on_resource deletes are tenant-scoped via a node-tenant subquery guard"
    requirement: "QUAL-04"
    verification:
      - kind: integration
        ref: "crates/axiam-db/tests/resource_scope_test.rs#concurrent_child_create_never_orphans_after_parent_delete"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/tests/resource_scope_test.rs#delete_resource_blocked_by_existing_child"
        status: pass
    human_judgment: false
  - id: D3
    description: "GDPR deletion setup (create_with_pending_flag) marks the user deletion-pending and creates the account_deletion row in one transaction; a duplicate-pending conflict rolls the whole transaction back so deletion_pending never strands at true with no cancellable row"
    requirement: "QUAL-04"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/gdpr_test.rs#create_with_pending_flag_succeeds_atomically"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/gdpr_test.rs#create_with_pending_flag_rolls_back_on_duplicate_pending_conflict"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-07-06
status: complete
---

# Phase 29 Plan 02: Transactional Multi-Statement Mutations Summary

**role/resource edge deletes are now single tenant-predicated transactions (closing the CQ-B07/SEC-058 cross-tenant edge-strip family and the CQ-B46 child-guard TOCTOU), and GDPR deletion setup is one atomic transaction via a new `create_with_pending_flag` method (closing the CQ-B39 uncancellable-purge residual).**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-07-06
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments
- Resolved the open schema question from RESEARCH.md by reading `schema.rs`: `has_role`, `grants`, `child_of`, and `on_resource` edge tables carry no `tenant_id` field of their own (only `UNIQUE(in, out)` indexes) — every tenant predicate on these edges is expressed as a node-tenant subquery guard (`out.tenant_id` / `in.tenant_id`, dereferencing the linked record's field via graph traversal), reusing syntax already proven in `role.rs::get_user_role_assignments`.
- `role.rs::delete` now wraps all three DELETEs (`has_role`, `grants`, the role record) in one `BEGIN TRANSACTION`/`COMMIT TRANSACTION` block, with the two edge DELETEs carrying the resolved node-tenant guard — a caller supplying a foreign-tenant role id can no longer strip that tenant's `has_role`/`grants` edges.
- `resource.rs::delete` folds the "cannot delete resource with children" guard into the SAME transaction as the deletes via a `LET $children = (...)` capture + `IF array::len($children) > 0 { THROW ... }`, closing the TOCTOU where the guard previously ran as an independent `.query()` round-trip before the deletes. `child_of`/`on_resource` deletes are now tenant-scoped via the same node-tenant subquery guard; `scope` and the resource record keep their pre-existing flat `tenant_id` predicates.
- Added `SurrealAccountDeletionRepository::create_with_pending_flag`, a single transaction that both marks the user `deletion_pending` and creates the `account_deletion` row holding the `cancel_token_hash`. `gdpr.rs::request_account_delete` now calls this one method instead of the previous two independent round-trips (`mark_deletion_pending` + `account_deletion_repo.create`); `revoke_all_sessions` remains a separate subsequent call, deliberately out of the strand-risk transaction scope.
- Added an in-transaction duplicate-pending-request guard to `create_with_pending_flag` (Rule 2): a `THROW` on a pre-existing pending row rolls back the whole transaction, including the just-issued user `UPDATE` — this both prevents a double-submit race from minting two live cancel tokens for one user, and gives the atomicity test a genuine, reproducible way to force the CREATE to fail post-UPDATE.
- Added 6 new lock-in/regression tests across `role_permission_test.rs`, `resource_scope_test.rs`, and `gdpr_test.rs`, including a real `tokio::spawn` concurrency race (15 trials) for the resource TOCTOU, mirroring the proven pattern in `totp_step_cas_test.rs`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Resolve edge-tenant question; make role::delete transactional + tenant-predicated (D-13)** - `0e9d7c3` (fix)
2. **Task 2: Fold resource::delete child-guard into the transaction; tenant-predicate all deletes (D-13)** - `3e8394a` (fix)
3. **Task 3: Transactional GDPR deletion setup — create_with_pending_flag (D-14)** - `04544f0` (feat)

_No TDD RED/GREEN split commits — tests were added alongside each task's implementation in a single commit per task (each task's acceptance criteria bundles the SQL rewrite with its lock-in test as one reviewable unit)._

## Files Created/Modified
- `crates/axiam-db/src/repository/role.rs` - `delete` rewritten as a single tenant-predicated transaction
- `crates/axiam-db/src/repository/resource.rs` - `delete` rewritten with an in-transaction LET-captured child guard and tenant-predicated edge deletes
- `crates/axiam-db/src/repository/account_deletion.rs` - New `create_with_pending_flag` transactional method
- `crates/axiam-api-rest/src/handlers/gdpr.rs` - `request_account_delete` now calls `create_with_pending_flag`; `CreateAccountDeletion` import removed (no longer used directly)
- `crates/axiam-db/tests/role_permission_test.rs` - 2 new tests (cross-tenant edge-strip lock-in, same-tenant edge-removal regression)
- `crates/axiam-db/tests/resource_scope_test.rs` - 2 new tests (concurrent-child TOCTOU lock-in with real race, child-guard regression)
- `crates/axiam-api-rest/tests/gdpr_test.rs` - 2 new tests (atomicity happy path, duplicate-pending rollback)

## Decisions Made
- Edge-table tenant scoping resolved as node-tenant subquery guards (`out.tenant_id` / `in.tenant_id`), not flat `WHERE tenant_id = ...` clauses, since `has_role`/`grants`/`child_of`/`on_resource` carry no own `tenant_id` field (confirmed by reading `schema.rs`).
- `resource::delete`'s child guard captures an array of child ids (`array::len($children) > 0`) rather than a scalar `count()`, matching the existing `array::len($u)`/`$r` cross-tenant guard idiom already used throughout this codebase rather than introducing a new scalar-coalesce SurrealQL pattern.
- Added a duplicate-pending-request guard inside `create_with_pending_flag` (Rule 2, not explicitly named in the plan) — this is both a genuine correctness improvement (prevents two live cancel tokens for one user) and the mechanism the atomicity test uses to force the CREATE to fail post-UPDATE, without inventing an artificial id collision or touching `schema.rs` (which was intentionally out of this plan's file scope).
- `create_with_pending_flag` returns an `AccountDeletion` built entirely from client-known values rather than `.take()`-ing the transaction's CREATE-statement row, avoiding any dependency on exact result-slot indices for a transaction containing an UPDATE/LET/IF ahead of the CREATE.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added a duplicate-pending-request guard to create_with_pending_flag**
- **Found during:** Task 3
- **Issue:** The plan's literal SQL sketch (RESEARCH.md) was just `UPDATE user; CREATE account_deletion;` with no guard against a second concurrent deletion-setup for the same user — without one, a double-submit race could silently create two live `account_deletion` rows (two outstanding cancel tokens) for one user, and there was no schema-level way to reliably force the CREATE to fail for the atomicity test.
- **Fix:** Added `LET $existing = (SELECT id FROM account_deletion WHERE tenant_id = $tenant_id AND user_id = $user_id AND status = 'pending'); IF array::len($existing) > 0 { THROW 'pending deletion request already exists'; };` between the UPDATE and CREATE, inside the same transaction. The THROW message contains the `classify_write_error` "already exists" marker so a duplicate-pending conflict surfaces as 409, not 500.
- **Files modified:** `crates/axiam-db/src/repository/account_deletion.rs`
- **Verification:** `create_with_pending_flag_rolls_back_on_duplicate_pending_conflict` — asserts `deletion_pending` returns to `false` after the guard trips.
- **Committed in:** `04544f0` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical addition)
**Impact on plan:** The guard is additive to the plan's stated behavior — it doesn't change the transaction's shape (still one BEGIN/COMMIT covering the user UPDATE and the account_deletion CREATE) and directly enables the plan's own suggested test scenario ("e.g. a pre-existing duplicate-pending row"). No scope creep beyond `create_with_pending_flag`'s own transaction body.

## Issues Encountered
- The sandbox's root filesystem briefly hit its disk quota mid-plan (multiple full-workspace `cargo build`/`cargo test` invocations across `axiam-db` and `axiam-api-rest` accumulated `target/` artifacts) — `Bash` and all write tools failed with `ENOSPC` per CLAUDE.md's documented failure mode. Recovered by deleting `target/` (`rm -rf /home/user/axiam/target`), per CLAUDE.md's "Build & Disk Hygiene" guidance, then re-ran and re-verified every test suite from a clean rebuild with identical (all-passing) results.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `role::delete`, `resource::delete`, and GDPR deletion setup are now final, tenant-predicated, and transactionally atomic — later plans in this phase (e.g. QUAL-01's AppState wiring, per D-19) can wire in these already-final repository bodies without further churn.
- `cargo clean` was run mid-plan due to the disk-hygiene incident documented above; per this environment's executor instructions, the orchestrator is still responsible for disk hygiene between plans going forward — this plan's own `target/` is currently a fresh rebuild from the last verification pass.
- Full workspace regression gate (per D-06) remains deferred to end-of-phase, as planned. This plan's own scoped tests (`axiam-db` role_permission_test/resource_scope_test/lib unit tests, `axiam-api-rest` gdpr_test/resource_scope_test/role_permission_test/bootstrap_test, `axiam-server` req14_gdpr_test) all pass green on both the pre- and post-disk-cleanup runs.

---
*Phase: 29-structural-quality*
*Completed: 2026-07-06*

## Self-Check: PASSED

All 3 task commits (`0e9d7c3`, `3e8394a`, `04544f0`) and all 7 modified files verified present.
