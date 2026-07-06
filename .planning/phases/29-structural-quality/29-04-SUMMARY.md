---
phase: 29-structural-quality
plan: 04
subsystem: database
tags: [surrealdb, pagination, repository-pattern, argon2id, dead-code-removal]

# Dependency graph
requires:
  - phase: 29-structural-quality (29-03)
    provides: AppState<C> composition root — this plan's changes stay compatible with it (no repository signatures touched)
provides:
  - "helpers::paginate<T>(items, count_rows, &pagination) -> PaginatedResult<T> generic helper with unit tests"
  - "8 group-A repos (organization, tenant, permission, resource, service_account, session, audit, group) deduped onto helpers::{CountRow, paginate, take_first_or_not_found}"
  - "scope.rs migrated to helpers::take_first_or_not_found (no CountRow/paginate — no paginated list method)"
  - "Pepper-less axiam-db::verify_password duplicate deleted; sole caller repointed to canonical axiam_auth::password::verify_password"
affects: [29-05 (file-group B — remaining ~15 repos + federation_link.rs parse_uuid removal)]

tech-stack:
  added: []
  patterns:
    - "helpers::paginate<T>(items, count_rows, &pagination) replaces the `let total = count_rows.first()...; PaginatedResult { items, total, offset, limit }` tail duplicated across every repo's list method"
    - "helpers::take_first_or_not_found(rows, entity, &id) replaces `rows.into_iter().next().ok_or_else(|| DbError::NotFound { entity, id })?`"

key-files:
  created: []
  modified:
    - crates/axiam-db/src/helpers.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-db/src/repository/mod.rs
    - crates/axiam-db/src/repository/user.rs
    - crates/axiam-db/src/repository/organization.rs
    - crates/axiam-db/src/repository/tenant.rs
    - crates/axiam-db/src/repository/permission.rs
    - crates/axiam-db/src/repository/resource.rs
    - crates/axiam-db/src/repository/scope.rs
    - crates/axiam-db/src/repository/service_account.rs
    - crates/axiam-db/src/repository/session.rs
    - crates/axiam-db/src/repository/audit.rs
    - crates/axiam-db/src/repository/group.rs
    - crates/axiam-db/tests/user_repository_test.rs

key-decisions:
  - "scope.rs gets take_first_or_not_found only — no local CountRow/paginated list existed, so no CountRow import or paginate() call was added (plan's documented exception)"
  - "session.rs imports helpers::CountRow but has no paginate() call site — cleanup_expired returns a raw u64 count, not a PaginatedResult"
  - "group.rs's add_member existence-check CountRow usages (check.take(0)/take(1)) left as raw count reads — not list methods, no paginate() applies"
  - "audit.rs's pseudonymize_actor count query left as a raw count read (returns u64, not PaginatedResult) — only list() adopted paginate()"
  - "Cargo.toml's now-unused argon2 dependency left untouched — out of files_modified scope, no unused_crate_dependencies lint enabled in this workspace"

patterns-established:
  - "Generic paginate<T> helper is the canonical way new/refactored repos should build PaginatedResult<T> from a count query + data query"

requirements-completed: [QUAL-02, QUAL-07]

coverage:
  - id: D1
    description: "Generic paginate<T> helper added to helpers.rs with unit tests covering empty count_rows and offset/limit preservation"
    requirement: QUAL-02
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/helpers.rs#helpers::tests::paginate_empty_count_rows_defaults_to_zero"
        status: pass
      - kind: unit
        ref: "crates/axiam-db/src/helpers.rs#helpers::tests::paginate_preserves_pagination_offset_and_limit"
        status: pass
    human_judgment: false
  - id: D2
    description: "8 group-A repos (organization, tenant, permission, resource, service_account, session, audit, group) + scope.rs deduped onto shared helpers with no behavior change"
    requirement: QUAL-02
    verification:
      - kind: integration
        ref: "cargo test -p axiam-db (group_repository_test, repository_test, resource_scope_test, role_permission_test, service_account_session_test, session_invalidate_except, oauth2_refresh_revoke_all, req14_settings_migration_test, saml_replay, schema_test, seeder_skip_test, totp_step_cas_test, webauthn_credential_test, connection_resilience_test, federation_login_state)"
        status: pass
      - kind: unit
        ref: "cargo test -p axiam-db --lib (40/40)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Pepper-less axiam-db::verify_password deleted (with re-exports); sole caller repointed to canonical axiam_auth::password::verify_password"
    requirement: QUAL-07
    verification:
      - kind: integration
        ref: "cargo test -p axiam-db --test user_repository_test (11/11, incl. password_verification and password_with_pepper)"
        status: pass
      - kind: other
        ref: "grep -rn axiam_db::verify_password crates/*/src crates/*/tests → 0 matches outside repointed import"
        status: pass
    human_judgment: false

duration: 21min
completed: 2026-07-06
status: complete
---

# Phase 29 Plan 04: helpers::paginate<T> + file-group-A dedup + verify_password deletion Summary

**Generic `paginate<T>` helper added and adopted across 9 file-group-A repos; pepper-less `axiam_db::verify_password` duplicate deleted (QUAL-07/CQ-B47), repointing its sole caller to the canonical `axiam_auth::password::verify_password`.**

## Performance

- **Duration:** 21 min
- **Started:** 2026-07-06T12:49:20Z
- **Completed:** 2026-07-06T13:09:55Z
- **Tasks:** 2
- **Files modified:** 14

## Accomplishments

- `helpers::paginate<T>(items, count_rows, &pagination) -> PaginatedResult<T>` added with 2 unit tests, replacing the `let total = count_rows.first()...; PaginatedResult{...}` tail that was duplicated in every repo's list method.
- Deleted the pepper-less second `verify_password` impl from `user.rs` (dead-code / auth-bypass-trap removal, CQ-B47/QUAL-07/D-17) along with its `mod.rs` and `lib.rs` re-exports; the only caller (`user_repository_test.rs`) now uses `axiam_auth::password::verify_password` directly.
- Collapsed the local `struct CountRow` in 8 file-group-A repos (organization, tenant, permission, resource, service_account, session, audit, group) onto `helpers::CountRow`, and adopted `helpers::paginate` in every list method that returns a `PaginatedResult<T>` (organization::list, tenant::list_by_organization, permission::list, resource::list, service_account::list, audit::list, group::list, group::get_members).
- Routed every group-A single-record read (create/get_by_id/get_by_slug/update, including `scope.rs` which has no CountRow/paginated list) through `helpers::take_first_or_not_found`.

## Task Commits

1. **Task 1: Add paginate<T> helper + tests; delete the pepper-less verify_password (QUAL-07/D-17)** - `daf5044` (feat)
2. **Task 2: Dedup file-group A repos — CountRow, paginate<T>, take_first_or_not_found** - `00c69bf` (refactor)

_No TDD tasks — this is a mechanical, behavior-preserving dedup pass gated by the existing repo test suite (D-03)._

## Files Created/Modified

- `crates/axiam-db/src/helpers.rs` - added `paginate<T>` + 2 unit tests
- `crates/axiam-db/src/repository/user.rs` - deleted pepper-less `verify_password`
- `crates/axiam-db/src/repository/mod.rs` - removed `verify_password` re-export
- `crates/axiam-db/src/lib.rs` - removed `verify_password` re-export
- `crates/axiam-db/tests/user_repository_test.rs` - repointed import to `axiam_auth::password::verify_password`
- `crates/axiam-db/src/repository/{organization,tenant,permission,resource,service_account,session,audit,group}.rs` - CountRow → helpers::CountRow, list()/get_members() → helpers::paginate, single-record reads → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/scope.rs` - single-record reads → helpers::take_first_or_not_found only

## Decisions Made

- `scope.rs` received only the `take_first_or_not_found` substitution — it has no local `struct CountRow` and no paginated list method, so no `CountRow` import or `paginate()` call was added (matches the plan's documented exception for this file).
- `session.rs` imports `helpers::CountRow` but has no `paginate()` call site: `cleanup_expired` returns a raw `u64` total, not a `PaginatedResult<T>`.
- `group.rs`'s `add_member` existence-check reads (`check.take(0)`/`check.take(1)` against `CountRow`) were left as raw count reads — they aren't list methods and have no `Pagination`/items to pass to `paginate()`.
- `audit.rs`'s `pseudonymize_actor` count query was left as a raw count read for the same reason — only `list()` (which builds a `PaginatedResult<AuditLogEntry>`) adopted `paginate()`.
- Left the now-unused `argon2` dependency in `crates/axiam-db/Cargo.toml` untouched — `Cargo.toml` is outside this plan's `files_modified` list, and no `unused_crate_dependencies` lint is enabled in this workspace, so it does not fail any gate. Logged in `deferred-items.md` as a future cleanup candidate.

## Deviations from Plan

None - plan executed exactly as written. Two out-of-scope findings were discovered during verification and logged (not fixed) per the scope-boundary rule; see `29-structural-quality/deferred-items.md`:

1. **Pre-existing test failure, unrelated file:** `req14_tenant_isolation_test::resource_delete_with_children_rejected` fails against `resource.rs`'s `delete()` method (a `.check()`/THROW error-text mismatch: `.check()` surfaces `"Migration failed: The query was not executed due to a failed transaction"` instead of the expected `"cannot delete resource with children"` substring). Confirmed pre-existing and unrelated to this plan: `delete()` was never touched (verified via `git diff` — zero lines changed), and the failure reproduces identically at the Task 1 commit (`daf5044`), before any Task 2 dedup edits (verified by `git stash`/`git stash pop` on the un-worktreed main checkout to test the pre-Task-2 baseline in isolation).
2. **Pre-existing clippy warning, different crate:** `crates/axiam-auth/src/token.rs:42` (`impl Default for SubjectKind` triggers `clippy::derivable_impls`) causes `cargo clippy -p axiam-db -- -D warnings` to fail because it also lints the `axiam-auth` dependency. `axiam-db` itself has zero clippy warnings (`cargo clippy -p axiam-db --lib --tests` without `-D warnings` compiles clean). `axiam-auth/src/token.rs` is outside this plan's scope.

## Issues Encountered

None beyond the two out-of-scope findings documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- File-group A (9 repos) fully deduped onto the shared `helpers` module; `helpers::paginate<T>` is ready for adoption by 29-05's file-group B (the remaining ~15 repos + `federation_link.rs` parse_uuid removal, per D-07 narrow scope).
- `axiam_db::verify_password` no longer exists — any future code must call `axiam_auth::password::verify_password` (already the pattern used by `axiam-api-grpc`'s `user.rs`).
- `cargo clean -p axiam-db` run after this plan per CLAUDE.md disk hygiene (freed ~9.9 GiB).

---
*Phase: 29-structural-quality*
*Completed: 2026-07-06*
