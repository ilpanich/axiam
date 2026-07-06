---
phase: 29-structural-quality
plan: 01
subsystem: database
tags: [surrealdb, error-handling, rust, oauth2, rbac]

# Dependency graph
requires:
  - phase: 28-functional-completeness
    provides: stable REST/RBAC/OAuth2 surface this plan corrects error taxonomy on
provides:
  - "helpers::classify_write_error — centralized DB write-error classifier (marker-string detection)"
  - "DbError::Serialization — corrupt-read variant distinct from Migration"
  - "409 (not 500) on duplicate user create, duplicate role assignment, duplicate group membership"
  - "OAuth2 client-lookup DB-outage vs invalid_client distinction (ServerError)"
affects: [29-02, 29-03, 29-04, 29-05, 29-06, 29-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "classify_write_error<E: Display>(err, entity) -> DbError — single centralized marker-string detector reused across CREATE/RELATE write paths, replacing the blanket .map_err(|e| DbError::Migration(e.to_string()))"

key-files:
  created:
    - crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs
  modified:
    - crates/axiam-db/src/error.rs
    - crates/axiam-db/src/helpers.rs
    - crates/axiam-db/src/repository/user.rs
    - crates/axiam-db/src/repository/role.rs
    - crates/axiam-db/src/repository/group.rs
    - crates/axiam-oauth2/src/authorize.rs
    - crates/axiam-oauth2/src/token.rs

key-decisions:
  - "classify_write_error is generic over E: std::fmt::Display (not concrete surrealdb::Error) so the same centralized detector can be called from every Migration-mapped site in user.rs, including the two password::hash_password (AuthError) sites, not just the surrealdb::Error .check() sites"
  - "Routed BOTH role.rs has_role RELATE sites (assign_to_user AND assign_to_group), not just the one line the plan named — both are reachable from mutating REST endpoints and hit the identical idx_has_role_unique index"
  - "group.rs add_member was missing a .check() call entirely — a duplicate RELATE silently 'succeeded' without ever creating the edge; added .check() + classify_write_error routing (in-scope per D-09's explicit member_of target, not a scope violation)"

requirements-completed: [QUAL-03]

coverage:
  - id: D1
    description: "Duplicate username/email on the mainstream user create path returns HTTP 409 (AlreadyExists), not 500"
    requirement: "QUAL-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs#duplicate_user_create_returns_409"
        status: pass
    human_judgment: false
  - id: D2
    description: "Duplicate has_role RELATE (role already assigned to user) returns 409, not 500"
    requirement: "QUAL-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs#duplicate_role_assignment_returns_409"
        status: pass
    human_judgment: false
  - id: D3
    description: "Duplicate member_of RELATE (group membership already exists) returns 409, not a silent 204"
    requirement: "QUAL-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs#duplicate_group_membership_returns_409"
        status: pass
    human_judgment: false
  - id: D4
    description: "OAuth2 client-lookup DB outage returns 5xx ServerError, distinct from invalid_client"
    requirement: "QUAL-03"
    verification:
      - kind: unit
        ref: "crates/axiam-oauth2/src/authorize.rs#authorize_client_lookup_db_outage_returns_server_error_not_invalid_client"
        status: pass
    human_judgment: false
  - id: D5
    description: "helpers::parse_uuid emits DbError::Serialization (not Migration) on a corrupt UUID read"
    requirement: "QUAL-03"
    verification:
      - kind: unit
        ref: "crates/axiam-db/src/helpers.rs#parse_uuid_invalid_returns_serialization_not_migration"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-07-06
status: complete
---

# Phase 29 Plan 01: Error Taxonomy Correctness Summary

**Centralized `classify_write_error` marker-string detector routes genuine unique/index violations to 409 on the user-create and has_role/member_of RELATE paths, fixes a silent-no-op bug in group.rs `add_member`, adds `DbError::Serialization`, and stops OAuth2 client-lookup DB outages from masquerading as `invalid_client`.**

## Performance

- **Duration:** ~30 min
- **Completed:** 2026-07-06
- **Tasks:** 3
- **Files modified:** 7 modified, 1 created

## Accomplishments
- Added `helpers::classify_write_error<E: Display>(err, entity) -> DbError`, reusing the exact 3-marker-string set (`already contains` / `already exists` / `unique`) already proven correct by `saml_replay.rs`/`federation_login_state.rs`/`seeder.rs`, and `DbError::Serialization` for corrupt-read errors (distinct from `Migration`).
- Routed all 11 `DbError::Migration`-mapped sites in `user.rs` (both CREATE paths, both GDPR paths, and the update/lockout sites for drift-safety) through `classify_write_error`; duplicate username/email now returns 409.
- Routed both `role.rs` `has_role` RELATE sites (`assign_to_user` and `assign_to_group`) through `classify_write_error("role_assignment")`; a duplicate role assignment now returns 409, not 500.
- Discovered and fixed a latent bug in `group.rs::add_member`: the RELATE query's `.await` result was never `.check()`-ed, so a duplicate group-membership RELATE silently produced no error (and no edge) while the handler returned 204 as if it succeeded. Added the missing `.check()` and routed it through `classify_write_error("group_membership")` — now correctly 409.
- Fixed the 5 OAuth2 client-lookup sites (`authorize.rs` + 4 in `token.rs`) that discarded the underlying error via `.map_err(|_| ...)`: now match `AxiamError::NotFound` (→ `invalid_client`, unchanged) vs any other error (→ `OAuth2Error::ServerError`, reusing the pre-existing 500-mapped variant) — a DB outage at client lookup no longer masquerades as bad client credentials.
- Added `qual03_error_taxonomy_test.rs` (3 integration tests) and an oauth2 DB-outage unit test, all green.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add classify_write_error + DbError::Serialization, fix parse_uuid** - `cd83262` (feat)
2. **Task 2: Route create + reachable edge-uniqueness paths through classify_write_error** - `d8e060e` (feat)
3. **Task 3: OAuth2 distinguishes DB outage from invalid_client** - `8df6c89` (fix)

_No TDD RED/GREEN split commits were made — tests were added alongside each task's implementation in a single commit per task, consistent with this plan's `tdd="true"` tasks being reviewed as one unit each (unit tests for Task 1 in helpers.rs, integration tests for Task 2 in the new test file, unit test for Task 3 in authorize.rs)._

## Files Created/Modified
- `crates/axiam-db/src/error.rs` - Added `DbError::Serialization(String)` variant
- `crates/axiam-db/src/helpers.rs` - Added `classify_write_error`; `parse_uuid` now emits `Serialization`; new unit tests
- `crates/axiam-db/src/repository/user.rs` - All 11 Migration-mapped sites routed through `classify_write_error`
- `crates/axiam-db/src/repository/role.rs` - `assign_to_user` and `assign_to_group` has_role RELATE sites routed
- `crates/axiam-db/src/repository/group.rs` - `add_member` gained a `.check()` call, routed through `classify_write_error`
- `crates/axiam-oauth2/src/authorize.rs` - Client-lookup error match (NotFound vs other); DB-outage mock repo + test
- `crates/axiam-oauth2/src/token.rs` - 4 client-lookup sites (authorization_code, client_credentials, refresh_token, authenticate_client) fixed
- `crates/axiam-api-rest/tests/qual03_error_taxonomy_test.rs` - New: 3 lock-in integration tests (409 on duplicate user/role-assignment/group-membership)

## Decisions Made
- `classify_write_error` is generic over `E: std::fmt::Display` rather than concrete `surrealdb::Error` — the plan named `user.rs:252`/`:725` (Argon2 `hash_password` errors) among the sites to route, but those aren't `surrealdb::Error`; a `Display`-generic signature lets the same centralized detector cover both `.check()` sites and non-DB fallible steps without a type mismatch, while preserving identical marker-matching semantics everywhere.
- Routed both `role.rs` has_role RELATE sites, not just the single line the plan referenced — `assign_to_user` and `assign_to_group` are both reachable from mutating REST endpoints (`POST /roles/{id}/users` and `POST /roles/{id}/groups`) and both hit the identical `idx_has_role_unique` index, so both needed the fix for the "reachable edge-uniqueness RELATE" requirement to actually hold.
- `group.rs::add_member`'s missing `.check()` (discovered during implementation, not previously flagged) is fixed as part of this plan's explicit `member_of` routing target (D-09/CONTEXT names group.rs:392 as in-scope) rather than deferred — without it, "duplicate group membership returns 409" would have been unverifiable (the RELATE error was never surfaced at all).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] group.rs::add_member never checked the RELATE query's per-statement result**
- **Found during:** Task 2
- **Issue:** `self.db.query(query).await.map_err(DbError::from)?;` never called `.check()` on the response, so a duplicate `member_of` RELATE (violating `idx_member_of_unique`) silently produced no error — the handler returned 204 as if a new membership edge had been created, when in fact SurrealDB's statement-level error was discarded.
- **Fix:** Added `result.check().map_err(|e| classify_write_error(e.to_string(), "group_membership"))?;` after the query, matching the `.check()` pattern already used elsewhere in this file and in `role.rs`/`saml_replay.rs`.
- **Files modified:** `crates/axiam-db/src/repository/group.rs`
- **Verification:** `duplicate_group_membership_returns_409` integration test — asserts the second `add_member` call now returns 409 instead of a silent 204.
- **Committed in:** `d8e060e` (Task 2 commit)

**2. [Rule 3 - Blocking type mismatch] classify_write_error made generic over Display instead of concrete surrealdb::Error**
- **Found during:** Task 1/2
- **Issue:** The plan's literal signature `classify_write_error(err: surrealdb::Error, entity: &str) -> DbError` would not compile at `user.rs:252`/`:725`, where the mapped error comes from `password::hash_password` (an `axiam_auth::AuthError`), not `surrealdb::Error`.
- **Fix:** Declared `classify_write_error<E: std::fmt::Display>(err: E, entity: &str) -> DbError`, preserving identical marker-matching behavior while being callable from every named site regardless of concrete error type.
- **Files modified:** `crates/axiam-db/src/helpers.rs`
- **Verification:** `cargo test -p axiam-db --lib` (38/38 pass, including two new classify_write_error unit tests); `cargo test -p axiam-api-rest --test qual03_error_taxonomy_test` (3/3 pass).
- **Committed in:** `cd83262` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking type-signature adjustment)
**Impact on plan:** Both changes were necessary for the plan's stated behavior (409 on duplicate group membership; compilable, uniformly-applied centralized detector) — no scope creep beyond the plan's own named targets.

## Issues Encountered
None beyond the deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `classify_write_error` and `DbError::Serialization` are now available in `axiam-db::helpers` for any later plan in this phase (e.g. QUAL-02's shared-helper adoption pass) to reuse or extend.
- Full workspace regression gate (per D-06) is deferred to end-of-phase, as planned — this plan's own scoped tests (axiam-db --lib, axiam-api-rest qual03 test, axiam-oauth2, plus the pre-existing group/role/user/bootstrap/oauth2 integration suites) all pass green.
- `cargo clean` was intentionally NOT run at the end of this plan — per this environment's executor instructions, disk hygiene between plans is the orchestrator's responsibility, not the individual plan executor's.

---
*Phase: 29-structural-quality*
*Completed: 2026-07-06*
