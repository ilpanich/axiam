---
phase: 03-rbac-enforcement
plan: 03
subsystem: axiam-api-rest, axiam-db
tags: [bootstrap, rbac, seeder, admin]
dependency_graph:
  requires: [03-01]
  provides: [admin-bootstrap-endpoint, default-role-seeder]
  affects: [03-04, 03-05]
tech_stack:
  added: []
  patterns: [one-shot-bootstrap, idempotent-seeder, env-gate-guard]
key_files:
  created:
    - crates/axiam-api-rest/src/handlers/bootstrap.rs
  modified:
    - crates/axiam-db/src/seeder.rs
    - crates/axiam-api-rest/src/handlers/mod.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/permissions.rs
decisions:
  - "Bootstrap endpoint is one-shot: returns 404 after first admin+user exists (D-09)"
  - "No token issued on bootstrap: user must authenticate separately via /auth/login (D-11)"
  - "AXIAM_BOOTSTRAP_ADMIN_EMAIL env var gates allowed email at handler entry (D-10)"
  - "Bootstrap returns 404 (not 409) to avoid leaking system state to unauthenticated callers"
metrics:
  duration: 15m
  completed_date: "2026-04-12"
  tasks_completed: 2
  files_changed: 5
---

# Phase 03 Plan 03: Bootstrap Handler and Default Role Seeder Summary

Admin bootstrap endpoint with idempotent default role seeder — seeds super-admin/admin/viewer roles with correct permission grants and creates the first admin user via POST /api/v1/admin/bootstrap.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Create default role seeder function | 1b2af70 | crates/axiam-db/src/seeder.rs |
| 2 | Create bootstrap handler and register route | 22e71e8 | bootstrap.rs, mod.rs, server.rs, permissions.rs |

## What Was Built

### Task 1 — Default Role Seeder (1b2af70)
`seed_default_roles` in `crates/axiam-db/src/seeder.rs` creates three default roles idempotently:
- **super-admin**: all permissions
- **admin**: all permissions except `admin:bootstrap`
- **viewer**: only `:list` and `:get` permissions

Returns `SeedRolesResult { super_admin_role_id, admin_role_id, viewer_role_id }`.

### Task 2 — Bootstrap Handler (22e71e8)
`POST /api/v1/admin/bootstrap` handler in `crates/axiam-api-rest/src/handlers/bootstrap.rs`:
- `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env gate blocks non-matching emails with 403
- Verifies org and tenant exist before proceeding
- Returns 404 if super-admin role + any user already exists (endpoint self-disables)
- Seeds permissions then default roles (both idempotent)
- Creates admin user and assigns super-admin role
- Returns 201 with user_id — no token (user must login via /auth/login)
- Registered at `/api/v1/admin/bootstrap` in PUBLIC_PATHS (no JWT required)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed unused import SurrealPermissionRepository**
- **Found during:** Task 2 cargo check
- **Issue:** `SurrealPermissionRepository` imported but not used in bootstrap.rs — would cause clippy -D warnings failure
- **Fix:** Removed from import list
- **Files modified:** crates/axiam-api-rest/src/handlers/bootstrap.rs
- **Commit:** 22e71e8

**2. [Rule 1 - Bug] Collapsed nested if-let into let-chain**
- **Found during:** Task 2 clippy check
- **Issue:** clippy flagged nested `if let Ok(...) { if condition { ... } }` as collapsible
- **Fix:** Used Rust 2024 let-chain syntax: `if let Ok(expected) = ... && req.email != expected { ... }`
- **Files modified:** crates/axiam-api-rest/src/handlers/bootstrap.rs
- **Commit:** 22e71e8

## Known Stubs

None — bootstrap handler is fully wired with real repository calls.

## Self-Check: PASSED

- crates/axiam-api-rest/src/handlers/bootstrap.rs: FOUND
- crates/axiam-db/src/seeder.rs contains seed_default_roles: FOUND
- commit 1b2af70: FOUND
- commit 22e71e8: FOUND
- cargo clippy -p axiam-api-rest -- -D warnings: PASSED
