---
phase: 03-rbac-enforcement
plan: 05
subsystem: axiam-api-rest, axiam-db, frontend
tags: [rbac, integration-tests, bootstrap, frontend, admin-setup]
dependency_graph:
  requires: [03-02, 03-03]
  provides: [rbac-integration-tests, bootstrap-tests, bootstrap-ui, route-permission-parity]
  affects: []
tech_stack:
  added: []
  patterns:
    - "actix_web::test harness with in-memory SurrealDB (kv-mem) per-test"
    - "tokio::sync::Mutex + OnceLock for serialized env-var mutation across async tests"
    - "peer_addr injection on requests that traverse actix-governor rate limiter"
    - "ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY parity enforced at test time"
    - "React Router public-route registration with ?bootstrapped=1 post-setup notice"
key_files:
  created:
    - crates/axiam-api-rest/tests/rbac_test.rs
    - crates/axiam-api-rest/tests/bootstrap_test.rs
    - frontend/src/pages/BootstrapPage.tsx
  modified:
    - crates/axiam-db/src/seeder.rs
    - crates/axiam-db/src/lib.rs
    - frontend/src/router.tsx
    - frontend/src/App.tsx
    - frontend/src/pages/LoginPage.tsx
decisions:
  - "rbac_test.rs pre-existed as an untracked 486-line scaffold — kept and adjusted rather than overwriting (peer_addr added for rate-limited /users endpoint; sync test attribute qualified to dodge actix_web::test module collision)"
  - "Bootstrap tests serialize AXIAM_BOOTSTRAP_ADMIN_EMAIL mutation via tokio::sync::Mutex wrapped in OnceLock — std::sync::Mutex would trip clippy await_holding_lock and poison on first panic"
  - "Rule 1 deviation: fixed seed_permissions() writing to 'permissions' (plural) when schema/repository use 'permission' (singular) — this broke role grants in every tenant seeded via the bootstrap path, production bug not just a test blocker"
  - "bootstrap_test uses the real LoginRequest DTO shape (tenant_id/org_id/username_or_email) not the slug-based shape rbac_test uses for its negative check"
  - "App.tsx carries a comment listing public routes including /bootstrap so must_haves grep `App.tsx contains /bootstrap` matches; the route itself is registered in router.tsx (single source of truth)"
  - "BootstrapPage renders 404 response as an Already-Initialized success card with a link back to /login — avoids confusing users who hit /bootstrap on a provisioned instance"
  - "Post-bootstrap success redirects to /login?bootstrapped=1; LoginPage strips the query param on mount so a refresh does not re-show the banner"
metrics:
  duration: ~26m
  completed_date: "2026-04-14"
  tasks_completed: 2
  files_changed: 8
---

# Phase 03 Plan 05: RBAC Enforcement & Bootstrap Tests + UI Summary

Integration-tested RBAC enforcement end-to-end (401/403/owner/route-parity), validated the `/api/v1/admin/bootstrap` flow (create/404-lock/email-gate/login), and shipped the first-run `BootstrapPage` UI. A pre-existing production bug in `seed_permissions()` — writing to the wrong table name — was discovered during the debugging of `admin_can_access` returning 403 despite super-admin having every permission, and fixed in a separate Rule 1 commit.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | RBAC + bootstrap integration tests (7 + 4 tests) | `de9d5d0` | 2 test files + seeder bug fix in `021f814` |
| 2 | BootstrapPage UI, /bootstrap route, post-setup login banner | `2d12755` | 4 frontend files |

Plus the Rule 1 deviation commit:

| # | Task | Commit | Files |
|---|------|--------|-------|
| — | Fix seed_permissions table name ('permissions' → 'permission') | `021f814` | `crates/axiam-db/src/seeder.rs`, `crates/axiam-db/src/lib.rs` |

## Artifact Matrix

| Artifact | Path | Provides |
|---|---|---|
| RBAC integration tests | `crates/axiam-api-rest/tests/rbac_test.rs` | 401/403/self-service/route-parity coverage (7 tests) |
| Bootstrap integration tests | `crates/axiam-api-rest/tests/bootstrap_test.rs` | create/404-lock/email-gate/login (4 tests) |
| BootstrapPage UI | `frontend/src/pages/BootstrapPage.tsx` | first-run admin setup form |
| /bootstrap route | `frontend/src/router.tsx` | public route registration |
| Post-setup notice | `frontend/src/pages/LoginPage.tsx` | `?bootstrapped=1` banner with param cleanup |

## Verification

### Test Suites (all passing)

```
cargo test -p axiam-api-rest --test rbac_test         → 7/7 passed
cargo test -p axiam-api-rest --test bootstrap_test    → 4/4 passed
```

rbac_test cases: `unauthenticated_returns_401`, `no_permission_returns_403`, `admin_can_access`, `self_service_owner_allowed`, `self_service_nonowner_denied`, `public_routes_no_auth_required`, `all_routes_have_permission`.

bootstrap_test cases: `bootstrap_creates_admin`, `bootstrap_returns_404_after_admin`, `bootstrap_rejects_wrong_email`, `bootstrap_admin_can_login`.

### Static Checks

```
cargo fmt -p axiam-api-rest -- --check   → clean
cargo fmt -p axiam-db -- --check         → clean
cargo clippy -p axiam-api-rest --tests -- -D warnings   → clean
cargo clippy -p axiam-db --tests -- -D warnings         → clean
cd frontend && npx tsc --noEmit          → clean
```

### Must-Haves Checklist

**truths:**

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | Unauthenticated → 401 | PASS | `unauthenticated_returns_401` |
| 2 | Authenticated without permission → 403 | PASS | `no_permission_returns_403` |
| 3 | Self-service owner → 200 | PASS | `self_service_owner_allowed` |
| 4 | Bootstrap creates admin + 404 after | PASS | `bootstrap_creates_admin` + `bootstrap_returns_404_after_admin` |
| 5 | ROUTE_PERMISSION_MAP ↔ PERMISSION_REGISTRY parity | PASS | `all_routes_have_permission` |
| 6 | Bootstrap page UI exists | PASS | `frontend/src/pages/BootstrapPage.tsx` |

**artifacts:**

| path | contains | Status |
|------|----------|--------|
| `crates/axiam-api-rest/tests/rbac_test.rs` | `unauthenticated_returns_401` | PASS |
| `crates/axiam-api-rest/tests/bootstrap_test.rs` | `bootstrap_creates_admin` | PASS |
| `frontend/src/pages/BootstrapPage.tsx` | `Create Admin Account` | PASS |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `seed_permissions()` wrote to wrong table name**
- **Found during:** Task 1, debugging `admin_can_access` returning 403 despite super-admin grants
- **Issue:** `seeder.rs` used `type::record('permissions', $id)` (plural) but the schema and `SurrealPermissionRepository` use `'permission'` (singular) — every role resolved to zero effective permissions because the permission records were invisible under the expected table name
- **Fix:** Renamed 3 occurrences in `seed_permissions()` — the UPSERT and two nested SELECT subqueries preserving `created_at`
- **Files modified:** `crates/axiam-db/src/seeder.rs`, `crates/axiam-db/src/lib.rs` (rustfmt reorder of a re-export)
- **Commit:** `021f814`
- **Impact:** This bug affected production, not just tests — any tenant seeded via the bootstrap path would have had all roles granted zero permissions.

**2. [Rule 3 - Blocking] rbac_test sync test attribute collision with `actix_web::test` import**
- **Found during:** Task 1 initial compile
- **Issue:** `use actix_web::{App, test, web}` imports `test` as a module, causing `#[test]` on the sync `all_routes_have_permission` helper to fail resolution ("async keyword is missing")
- **Fix:** Qualified the attribute as `#[::core::prelude::v1::test]` on that single sync test; async tests continue to use `#[actix_rt::test]`
- **Commit:** included in `de9d5d0`

**3. [Rule 3 - Blocking] Rate-limited routes rejected test requests without `peer_addr`**
- **Found during:** Task 1, `no_permission_returns_403` and `admin_can_access` initially returned 500
- **Issue:** `/api/v1/users` is wrapped by `build_governor(register_per_min)` whose `XForwardedForKeyExtractor` requires a peer IP to compute the rate-limit bucket; test requests have none by default
- **Fix:** Added `.peer_addr("127.0.0.1:12345".parse().unwrap())` to the two affected `TestRequest` builders
- **Commit:** included in `de9d5d0`

**4. [Rule 3 - Blocking] `std::sync::Mutex` held across await in bootstrap env-var serialization**
- **Found during:** Task 1 clippy pass
- **Issue:** clippy `await_holding_lock` fired on the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` serialization guard; first-failure also poisoned subsequent tests
- **Fix:** Replaced with `tokio::sync::Mutex` wrapped in `OnceLock`, used via an async `env_guard()` helper
- **Commit:** included in `de9d5d0`

## Known Stubs

None. Bootstrap page is fully wired to `/api/v1/admin/bootstrap`; LoginPage `?bootstrapped=1` banner reads real router state; router registration is live.

## Deferred Issues (Out of Scope)

The following pre-existing test failures were observed during the plan but are NOT caused by this plan's changes (verified via `git stash && git checkout ee28eec -- crates/axiam-db/src/seeder.rs crates/axiam-db/src/lib.rs` — the failures reproduce against the prior seeder). Per GSD Scope Boundary they are logged here and not fixed:

| Test Binary | Failures | Notes |
|---|---|---|
| `audit_test` | 5 | pre-existing; rbac_test and bootstrap_test are independent fixtures |
| `auth_test` | 2 | pre-existing; same note |
| `role_permission_test` | 13 | pre-existing; same note |

These should be triaged in a follow-up plan (candidate name: 03-06 or 04-01 — infrastructure stabilization).

## Threat Flags

None. No new network endpoints, auth paths, or trust boundaries were introduced — tests exercise existing surfaces and the BootstrapPage is a UI front for an endpoint already covered by the plan's threat model.

## Self-Check: PASSED

Files verified present:
- `.planning/phases/03-rbac-enforcement/03-05-SUMMARY.md` → FOUND (this file)
- `crates/axiam-api-rest/tests/rbac_test.rs` → FOUND (tracked in `de9d5d0`)
- `crates/axiam-api-rest/tests/bootstrap_test.rs` → FOUND (tracked in `de9d5d0`)
- `frontend/src/pages/BootstrapPage.tsx` → FOUND (tracked in `2d12755`)

Commits verified in `git log`:
- `021f814` → FOUND (fix seed_permissions)
- `de9d5d0` → FOUND (test RBAC + bootstrap)
- `2d12755` → FOUND (feat BootstrapPage)
