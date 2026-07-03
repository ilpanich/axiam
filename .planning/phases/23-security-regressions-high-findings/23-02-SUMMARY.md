---
phase: 23-security-regressions-high-findings
plan: 02
subsystem: database
tags: [surrealdb, rbac, tenant-isolation, access-control, security]

# Dependency graph
requires: []
provides:
  - "grant_to_role_with_scopes now enforces the same LET/IF-array::len-THROW tenant predicate as grant_to_role, on both the wildcard (empty scope_ids) and scoped branches"
  - "Per-scope tenant-ownership check (array::len($sc) == array::len($scope_ids)) rejecting any scope_id not owned by the caller's tenant, atomic with the RELATE"
affects: [23-security-regressions-high-findings]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "In-query SurrealQL LET/IF/THROW tenant-ownership predicate, evaluated atomically before RELATE — no TOCTOU window between check and mutation (same pattern as grant_to_role/revoke_from_role)"

key-files:
  created: []
  modified:
    - crates/axiam-db/src/repository/permission.rs
    - crates/axiam-db/tests/req14_tenant_isolation_test.rs

key-decisions:
  - "Scope-ownership check done inline in SurrealQL (LET $sc = SELECT ... WHERE tenant_id = $tid AND meta::id(id) IN $scope_ids) rather than injecting a ScopeRepository dependency into SurrealPermissionRepository — keeps the fix a same-file mirror of grant_to_role with no new cross-repository coupling, per the plan's explicit constraint."
  - "Reused the exact result.check() -> \"cross-tenant edge denied\" -> AxiamError::AuthorizationDenied error-mapping from grant_to_role verbatim, so both sibling methods fail the same way for the same class of violation."

requirements-completed: [SECFIX-02]

coverage:
  - id: D1
    description: "Tenant-A permissions:grant holder cannot attach a tenant-B permission to a tenant-A role via grant_to_role_with_scopes (empty-scope/wildcard branch) — the REST-reachable POST /api/v1/roles/{id}/permissions path"
    requirement: "SECFIX-02"
    verification:
      - kind: integration
        ref: "crates/axiam-db/tests/req14_tenant_isolation_test.rs#permission_grant_cross_tenant_rejected"
        status: pass
    human_judgment: false
  - id: D2
    description: "A tenant-A role/permission pair cannot have a tenant-B scope_id attached via the scoped branch of grant_to_role_with_scopes — rejected atomically before the RELATE"
    requirement: "SECFIX-02"
    verification:
      - kind: integration
        ref: "crates/axiam-db/tests/req14_tenant_isolation_test.rs#permission_grant_cross_tenant_scope_rejected"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-03
status: complete
---

# Phase 23 Plan 02: Tenant Guard on grant_to_role_with_scopes Summary

**Closed SEC-058 by lifting the proven LET/IF-array::len-THROW tenant predicate from `grant_to_role` into both branches of `grant_to_role_with_scopes` — the actual REST-reachable grant path — and adding a per-scope tenant-ownership check so no cross-tenant permission or scope can be RELATEd onto a role.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-03
- **Tasks:** 2/2
- **Files modified:** 2

## Accomplishments
- Repointed the existing `permission_grant_cross_tenant_rejected` regression test from the already-guarded `grant_to_role` sibling onto the actually-vulnerable `grant_to_role_with_scopes` (the method the REST handler `POST /api/v1/roles/{role_id}/permissions` calls), and confirmed it failed against the unguarded repo before the fix landed (fail-before proof).
- Added a new negative test, `permission_grant_cross_tenant_scope_rejected`, proving that even when the role and permission are both tenant-A, a tenant-B `scope_id` in the request is rejected — this exercises the scoped branch's independent scope-ownership check, not just the role/permission guard.
- Fixed `grant_to_role_with_scopes`: the `_tenant_id` parameter (previously ignored) is now bound as `$tid` and used in a `LET $ro/$pe (/$sc)` + `IF ... THROW 'cross-tenant edge denied'` predicate on both the empty-scope (wildcard) and scoped branches, evaluated atomically before the `RELATE`. The scoped branch additionally requires `array::len($sc) == array::len($scope_ids)` — every supplied scope must resolve to a tenant-owned scope record, or the whole mutation aborts with no partial edge written.
- Reused the identical `result.check()` → match `"cross-tenant edge denied"` → `AxiamError::AuthorizationDenied` error-mapping already used by `grant_to_role`/`revoke_from_role`, so callers see the same error type for the same violation across all three methods.

## Task Commits

Each task was committed atomically:

1. **Task 1: Repoint + add the cross-tenant negative test at the vulnerable path (fail-before)** - `ee30cfc` (test)
2. **Task 2: Apply the tenant + scope-ownership guard to both branches of grant_to_role_with_scopes (pass-after)** - `2f9d042` (fix)

## Files Created/Modified
- `crates/axiam-db/src/repository/permission.rs` - `grant_to_role_with_scopes` now takes a used `tenant_id`, both branches carry the LET/IF/THROW tenant predicate, and the scoped branch additionally validates scope ownership before the RELATE
- `crates/axiam-db/tests/req14_tenant_isolation_test.rs` - `permission_grant_cross_tenant_rejected` repointed to call `grant_to_role_with_scopes`; new `permission_grant_cross_tenant_scope_rejected` test added; imports for `CreateScope`/`ScopeRepository`/`SurrealScopeRepository` added

## Decisions Made
- Scope-ownership validation implemented as an inline SurrealQL sub-query (`LET $sc = SELECT id FROM scope WHERE tenant_id = $tid AND meta::id(id) IN $scope_ids`) rather than a new `ScopeRepository` dependency injected into `SurrealPermissionRepository` — matches the plan's explicit "do NOT inject a ScopeRepository dependency" constraint and keeps the change a same-file mirror of the existing `grant_to_role` pattern.
- Reused `grant_to_role`'s exact error-mapping (`"cross-tenant edge denied"` substring match → `AxiamError::AuthorizationDenied`) verbatim rather than introducing a new error variant or message, for consistency across the sibling methods.

## Deviations from Plan

None - plan executed exactly as written. The one incidental fix — `cargo fmt` re-wrapping the test file's import list after the Task 1 edit — was folded into the Task 2 commit since it was required for the plan's own `cargo fmt -p axiam-db --check` acceptance criterion; it changes only line-wrapping of an existing import list, no logic.

## Issues Encountered
None.

## Next Phase Readiness
- SECFIX-02 fully closed: `grant_to_role_with_scopes` (the REST-reachable path) now rejects cross-tenant permission grants and cross-tenant scope attachments atomically, matching `grant_to_role`'s existing guard.
- No blockers for subsequent Phase 23 plans (23-03 through 23-06 address SECFIX-03..06, independent subsystems: webhook encryption, SAML XSW, logout, reset/resend).

---
*Phase: 23-security-regressions-high-findings*
*Completed: 2026-07-03*

## Self-Check: PASSED

All modified files verified present on disk (`permission.rs`, `req14_tenant_isolation_test.rs`, this SUMMARY); both task commits (`ee30cfc`, `2f9d042`) verified present in `git log`.
