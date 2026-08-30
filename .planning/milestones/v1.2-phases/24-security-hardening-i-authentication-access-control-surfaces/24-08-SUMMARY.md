---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 08
subsystem: auth
tags: [surrealdb, bootstrap, rbac, actix-web, transactions]

# Dependency graph
requires:
  - phase: 24-04
    provides: transactional+gated bootstrap (Phase 11 baseline), AXIAM_BOOTSTRAP_ADMIN_EMAIL email-match gate
provides:
  - bootstrap_lock / bootstrap_setup_token / bootstrap_setup_token_consumed SurrealDB tables (schema v22)
  - server-minted, single-log-line, hash-only first-run setup token (mint_bootstrap_setup_token_if_needed)
  - mandatory fail-closed bootstrap gate (env var OR one-time setup token; unset ⇒ refuse)
  - atomic uniqueness-invariant bootstrap transaction replacing the TOCTOU SELECT-then-branch check
  - idempotent/concurrency-safe seed_default_roles (find_or_create_role, grant_to_role_idempotent)
affects: [24-09, phase-25-federation-pki-data-infra-hardening]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "uniqueness-invariant CREATE on a deterministic record ID as an atomicity primitive (bootstrap_lock, saml_replay precedent)"
    - "consumption-by-existence for single-use tokens (bootstrap_setup_token_consumed, same pattern as SAML assertion replay)"
    - "race-tolerant seeding helpers (find_or_create_role / grant_to_role_idempotent) that treat a UNIQUE-index violation from a concurrent caller as success, not failure"

key-files:
  created: []
  modified:
    - crates/axiam-db/src/schema.rs
    - crates/axiam-db/src/seeder.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-api-rest/src/handlers/bootstrap.rs
    - crates/axiam-api-rest/tests/bootstrap_test.rs

key-decisions:
  - "Setup token is global (not tenant-scoped) — server mints exactly one, consumed by any single successful bootstrap call, mirroring D-03b's 'server-minted, logged once' design"
  - "bootstrap gate error reuses AxiamError::AuthorizationDenied (403) for all gate-refusal cases (unset, missing token, invalid token) — consistent with the pre-existing email-mismatch 403, no new error variant needed"
  - "already-bootstrapped tenant now returns 409 Conflict (AlreadyExists) instead of the old 404 NotFound — status code changed as a direct, intended consequence of replacing the TOCTOU check with the bootstrap_lock uniqueness invariant"
  - "seed_default_roles made concurrency-safe (find_or_create_role + grant_to_role_idempotent) — necessary because removing the old TOCTOU gate makes this function reachable twice (sequentially or concurrently) for the same tenant, which it was never designed to tolerate"

patterns-established:
  - "grant_to_role_idempotent / find_or_create_role: seeding helpers that swallow 'already exists' UNIQUE-index violations from a concurrent caller instead of propagating them as errors"

requirements-completed: [SECHRD-04]

coverage:
  - id: D1
    description: "Server mints a one-time setup token on first boot, logs it exactly once, and persists only its sha256 hash"
    requirement: "SECHRD-04"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/bootstrap_test.rs#bootstrap_setup_token"
        status: pass
    human_judgment: false
  - id: D2
    description: "Bootstrap is refused (fail-closed, zero admins created) when neither AXIAM_BOOTSTRAP_ADMIN_EMAIL nor a valid setup token is presented"
    requirement: "SECHRD-04"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/bootstrap_test.rs#bootstrap_refused_when_gate_unset"
        status: pass
    human_judgment: false
  - id: D3
    description: "Two concurrent first-run bootstrap requests against one tenant create exactly one super-admin; the loser gets 409 AlreadyExists with no partial state"
    requirement: "SECHRD-04"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/bootstrap_test.rs#bootstrap_concurrent_race_single_admin"
        status: pass
    human_judgment: false
  - id: D4
    description: "A second (sequential) bootstrap call against an already-bootstrapped tenant is refused with 409 Conflict via the bootstrap_lock uniqueness invariant, not the old TOCTOU check"
    requirement: "SECHRD-04"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/tests/bootstrap_test.rs#bootstrap_returns_409_after_admin"
        status: pass
    human_judgment: false

duration: 50min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 08: Bootstrap Atomicity + Mandatory Gate Summary

**Closed the bootstrap TOCTOU (SEC-049) with a uniqueness-invariant `bootstrap_lock` CREATE folded into the admin-creation transaction, and made the first-run gate mandatory (env var OR a server-minted one-time setup token) — an unset gate now always refuses instead of defaulting to open.**

## Performance

- **Duration:** ~50 min
- **Started:** 2026-07-04T11:19:54Z (approx, from STATE.md)
- **Completed:** 2026-07-04T12:06:00Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- `bootstrap_lock` / `bootstrap_setup_token` / `bootstrap_setup_token_consumed` tables added (schema v22); a first-boot mint routine generates a random setup token, persists only its sha256 hash, and returns the plaintext once for the server to log exactly once (D-03b).
- Bootstrap now requires EITHER `AXIAM_BOOTSTRAP_ADMIN_EMAIL` (matching) OR a valid, unconsumed setup token — an unset/absent gate is refused (fail-closed), closing the "unconditional bootstrap when env var unset" bug (D-03a).
- The SELECT-then-branch TOCTOU ("list roles → find super-admin → list users → total > 0") is deleted. First-super-admin creation is now atomic: a `CREATE type::record('bootstrap_lock', $tenant_id)` inside the same `BEGIN/COMMIT` transaction that creates the admin user + RELATE is the uniqueness invariant. The race loser's UNIQUE-index violation maps to `AxiamError::AlreadyExists` (409) and rolls back the whole transaction — no partial admin, no orphan role RELATE (D-03c). The same transaction also consumes the setup token (when used) and seeds the admin's initial password hash into `password_history` (Pitfall 5).
- Discovered and fixed a latent non-idempotency bug in `seed_default_roles`: removing the old TOCTOU gate makes this function reachable a second time (sequentially or concurrently) for an already-bootstrapped tenant, and its role-creation/grant logic was never safe against that — both `role_repo.create()` and `grant_to_role()` hit UNIQUE-index violations on a retry/race. Added `find_or_create_role` and `grant_to_role_idempotent`, which treat a concurrent caller's "already exists" violation as success (re-fetching/no-op) instead of a hard error.
- Three new/updated tests prove the invariants: `bootstrap_setup_token` (mint-once, hash-only persistence), `bootstrap_refused_when_gate_unset` (missing/invalid token refused, zero admins created), `bootstrap_concurrent_race_single_admin` (two truly concurrent requests via `tokio::join!` yield exactly one 201 + one 409 + exactly one super-admin — stable across 8+ repeated runs).

## Task Commits

1. **Task 1: bootstrap_lock / bootstrap_setup_token tables + server-minted setup token logged once at first boot** - `73395dc` (feat)
2. **Task 2: Mandatory fail-closed gate (env var OR valid setup token) + gate-unset refusal test** - `9e17d80` (feat)
3. **Task 3: Atomic uniqueness-invariant bootstrap transaction (replace TOCTOU) + history seed + concurrency test** - `42bf2c8` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `crates/axiam-db/src/schema.rs` - Schema v22: `bootstrap_lock`, `bootstrap_setup_token`, `bootstrap_setup_token_consumed` additive tables
- `crates/axiam-db/src/seeder.rs` - `mint_bootstrap_setup_token_if_needed`; `find_or_create_role` and `grant_to_role_idempotent` race-tolerant seeding helpers; `granted_permission_ids` shared helper (de-duplicated out of `reconcile_default_role_grants`)
- `crates/axiam-db/src/lib.rs` - Export `mint_bootstrap_setup_token_if_needed`
- `crates/axiam-server/src/main.rs` - Invoke the setup-token mint at boot (right after migrations run); logs the plaintext token exactly once on first boot only
- `crates/axiam-api-rest/src/handlers/bootstrap.rs` - `BootstrapRequest.setup_token`; mandatory gate; setup-token validation helper; TOCTOU deleted; atomic transaction extended with `bootstrap_lock` / `bootstrap_setup_token_consumed` / `password_history` CREATEs; `AlreadyExists` (409) mapping
- `crates/axiam-api-rest/tests/bootstrap_test.rs` - `bootstrap_setup_token`, `bootstrap_refused_when_gate_unset`, `bootstrap_concurrent_race_single_admin` (new); `bootstrap_returns_404_after_admin` renamed/updated to `bootstrap_returns_409_after_admin`; `bootstrap_creates_admin` / `bootstrap_admin_can_login` updated to satisfy the now-mandatory gate

## Decisions Made

- Setup token is minted globally (one per server, not per tenant) — matches D-03b's "server-minted, logged once" design; the bootstrap endpoint itself remains per-tenant.
- Reused `AxiamError::AuthorizationDenied` (403) for every gate-refusal branch (unset, missing token, invalid/consumed token) rather than introducing a new error variant — consistent with the pre-existing email-mismatch 403 path.
- Already-bootstrapped tenant now returns 409 Conflict instead of the old 404 — an intended, direct consequence of replacing the TOCTOU check with the `bootstrap_lock` uniqueness invariant (the plan explicitly directs deleting the TOCTOU block).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing tests relying on the insecure unset-gate default-allow**
- **Found during:** Task 2
- **Issue:** `bootstrap_creates_admin`, `bootstrap_returns_404_after_admin`, and `bootstrap_admin_can_login` all called the bootstrap endpoint with `AXIAM_BOOTSTRAP_ADMIN_EMAIL` unset and no setup token — relying on exactly the SEC-049 bug (unset gate ⇒ unconditional allow) this task closes.
- **Fix:** Updated each test to set `AXIAM_BOOTSTRAP_ADMIN_EMAIL` to match the request email, satisfying the now-mandatory gate via the env-var path.
- **Files modified:** `crates/axiam-api-rest/tests/bootstrap_test.rs`
- **Committed in:** `9e17d80` (Task 2 commit)

**2. [Rule 1 - Bug] Fixed non-idempotent `seed_default_roles` uncovered by deleting the TOCTOU gate**
- **Found during:** Task 3 (writing the concurrency test surfaced the bug immediately; also broke the sequential `bootstrap_returns_409_after_admin` test)
- **Issue:** With the old TOCTOU check removed, `seed_permissions`/`seed_default_roles` run on EVERY bootstrap call, including retries against an already-bootstrapped tenant and true concurrent races. `role_repo.create()` (random UUID, no upsert) and `grant_to_role()` (UNIQUE `(in,out)` edge index, CQ-B17) both hit hard UNIQUE-index-violation errors on a second call for the same tenant, surfacing as 500 Internal instead of the correct 409 AlreadyExists from the bootstrap_lock invariant.
- **Fix:** Added `find_or_create_role` (treats a concurrent create-race's UNIQUE violation as "someone else won — re-fetch their row" instead of a hard error) and `grant_to_role_idempotent` (treats "already granted" as success); pre-fetch already-granted permission IDs via the existing `granted_permission_ids` helper (also de-duplicated out of `reconcile_default_role_grants`) to skip redundant grant attempts in the common sequential-retry case.
- **Files modified:** `crates/axiam-db/src/seeder.rs`
- **Verification:** `bootstrap_returns_409_after_admin` and `bootstrap_concurrent_race_single_admin` both pass reliably (concurrency test re-run 8+ times with no flakes); full `axiam-db` and `axiam-api-rest` (rbac_test, organization_test) test suites remain green.
- **Committed in:** `42bf2c8` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — bugs directly caused/uncovered by this plan's required changes)
**Impact on plan:** Both fixes were necessary for the plan's own acceptance criteria (a reliable concurrency test, and correct behavior for a retried bootstrap call) to hold. No scope creep — `reconcile_default_role_grants` (server-startup path, not reachable from bootstrap) was only touched to de-duplicate a helper function, not to change its behavior.

## Issues Encountered

- Initial concurrency test attempt surfaced a 500 instead of the expected 409 on both the sequential-retry and true-concurrency tests. Root-caused via a temporary debug `eprintln!` in the transaction's error-mapping closure (removed before commit) — the actual failure was in `seed_default_roles`'s permission-grant loop, not the `bootstrap_lock` CREATE itself. Fixed per deviation #2 above.

## User Setup Required

None - no external service configuration required. Operators upgrading an existing deployment will see a new setup-token log line on first boot after this change if `AXIAM_BOOTSTRAP_ADMIN_EMAIL` was never set and no admin exists yet; existing bootstrapped tenants are unaffected (the mint routine is a no-op once any user exists).

## Next Phase Readiness

- SECHRD-04 / SEC-049 fully closed: atomicity proven by a stable concurrency test, mandatory gate proven by a dedicated refusal test.
- Plan 24-09 (per ROADMAP) can proceed; no blockers introduced by this plan.
- `find_or_create_role` / `grant_to_role_idempotent` / `granted_permission_ids` are now general-purpose race-tolerant seeding primitives available to any future caller that re-invokes `seed_default_roles` on an already-seeded tenant.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED
