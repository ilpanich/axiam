---
phase: 03-rbac-enforcement
plan: "01"
subsystem: axiam-api-rest, axiam-db, axiam-server
tags: [rbac, middleware, permissions, seeder, authz]
dependency_graph:
  requires: []
  provides:
    - PERMISSION_REGISTRY (compile-time permission list)
    - PUBLIC_PATHS (allowlist for auth-exempt endpoints)
    - ROUTE_PERMISSION_MAP (route-permission mapping for Plan 05 test)
    - seed_permissions (idempotent UPSERT-based permission seeder)
    - AuthzMiddleware (global default-deny middleware)
    - AuthzChecker (app_data injection for per-handler checks)
  affects:
    - crates/axiam-api-rest/src/server.rs (all three API scopes wrapped)
    - crates/axiam-server/src/main.rs (startup seeding + AuthzChecker injection)
tech_stack:
  added: []
  patterns:
    - Actix-Web Transform/Service middleware pattern (mirrors CsrfMiddleware)
    - Deterministic UUIDs via Uuid::new_v5 for idempotent UPSERT seeding
    - Arc<dyn Trait> type erasure for AuthzChecker app_data
key_files:
  created:
    - crates/axiam-api-rest/src/permissions.rs
    - crates/axiam-api-rest/src/middleware/authz.rs
    - crates/axiam-db/src/seeder.rs
  modified:
    - crates/axiam-api-rest/src/lib.rs
    - crates/axiam-api-rest/src/middleware/mod.rs
    - crates/axiam-api-rest/src/authz.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-server/src/main.rs
decisions:
  - "TenantRepository has no generic list() — used OrganizationRepository::list() + TenantRepository::list_by_organization() to enumerate all tenants for seeding"
  - "UPSERT syntax verified with type::record() approach per SurrealDB v3 SDK patterns in MEMORY.md"
  - "AuthzMiddleware wraps /auth scope inside CsrfMiddleware (order: AuthzMiddleware outermost, CsrfMiddleware innermost)"
metrics:
  duration: "~20 minutes"
  completed_date: "2026-04-10"
  tasks: 2
  files: 9
---

# Phase 3 Plan 1: RBAC Enforcement Foundation Summary

**One-liner:** Permission registry with 100+ entity:action pairs, UPSERT-based idempotent seeder, and global default-deny AuthzMiddleware wired on all API scopes.

## What Was Built

### Task 1: Permission Registry and Seeder

**`crates/axiam-api-rest/src/permissions.rs`** — Three compile-time constants:

1. `PERMISSION_REGISTRY` — 100+ `(action, description)` pairs covering all AXIAM entities (users, groups, roles, permissions, resources, scopes, certificates, CA certificates, audit logs, service accounts, PGP keys, webhooks, OAuth2 clients, federation, notification rules, settings, tenants, organizations, admin bootstrap).

2. `PUBLIC_PATHS` — 21 path entries that bypass authentication (login, register, device auth, WebAuthn flows, health probes, OIDC discovery, OAuth2 token endpoints, federation callbacks, admin bootstrap, OpenAPI docs). Entries ending with `*` are prefix-matched.

3. `ROUTE_PERMISSION_MAP` — `(HTTP_METHOD, path_pattern, permission)` for every protected route. Used by the Plan 05 integration test to verify 100% route coverage.

**`crates/axiam-db/src/seeder.rs`** — `seed_permissions()` function:

- Takes `db`, `tenant_id`, `registry` parameters
- Generates deterministic UUIDs via `Uuid::new_v5(&tenant_id, action.as_bytes())`
- Uses raw SurrealQL `UPSERT type::record('permissions', $id) SET ...` — NOT list+create
- Preserves original `created_at` on subsequent runs (conditional UPSERT)
- Idempotent: same tenant+action always targets the same record

### Task 2: AuthzMiddleware and Server Wiring

**`crates/axiam-api-rest/src/middleware/authz.rs`** — AuthzMiddleware:

- Follows the CsrfMiddleware Transform/Service pattern exactly
- `is_public_path()` helper checks `PUBLIC_PATHS` (prefix match for `*` entries, exact match otherwise)
- Public paths → forward unchanged (left body)
- Protected paths with no JWT cookie/Authorization header → **401 Unauthorized** with `authentication_failed` JSON
- Protected paths with credentials → forward to handler for per-handler `RequirePermission` check

**`crates/axiam-api-rest/src/authz.rs`** — Added `AuthzChecked` marker struct for defense-in-depth signaling from handlers.

**`crates/axiam-api-rest/src/server.rs`** — `AuthzMiddleware` added to:
- `/auth` scope (outermost, inside CsrfMiddleware)
- `/oauth2` scope
- `/api/v1` scope

**`crates/axiam-server/src/main.rs`** — Startup changes:
- Permission seeding: lists all orgs → all tenants → calls `seed_permissions()` for each tenant
- REST `AuthzChecker`: `Arc<dyn axiam_api_rest::authz::AuthzChecker>` created from `AuthorizationEngine`
- Injected as `web::Data::from(rest_authz.clone())` into `HttpServer` closure

## Commits

| Hash | Message |
|------|---------|
| `72fe4af` | feat(03-01): create permission registry and permission seeder |
| `0ac89aa` | feat(03-01): add AuthzMiddleware and wire into server with AuthzChecker injection |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TenantRepository::list() does not exist**
- **Found during:** Task 2 (permission seeding implementation)
- **Issue:** The plan instructed `tenant_repo.list()` with large pagination, but `TenantRepository` only exposes `list_by_organization()`. No generic list exists.
- **Fix:** Used `OrganizationRepository::list()` to get all orgs, then `TenantRepository::list_by_organization()` for each org.
- **Files modified:** `crates/axiam-server/src/main.rs`
- **Commit:** 0ac89aa

**2. [Rule 1 - Bug] Pagination struct uses offset/limit (not page/per_page)**
- **Found during:** Task 2 (first compile attempt)
- **Issue:** Plan used `Pagination { page: 1, per_page: 10_000 }` but the struct has `offset` and `limit` fields.
- **Fix:** Used `Pagination { offset: 0, limit: 10_000 }`.
- **Files modified:** `crates/axiam-server/src/main.rs`
- **Commit:** 0ac89aa

## Known Stubs

None — all functionality is implemented and wired. No placeholder values or TODO stubs.

## Self-Check: PASSED

- `crates/axiam-api-rest/src/permissions.rs` — FOUND (contains PERMISSION_REGISTRY, PUBLIC_PATHS, ROUTE_PERMISSION_MAP)
- `crates/axiam-api-rest/src/middleware/authz.rs` — FOUND (contains AuthzMiddleware, is_public_path)
- `crates/axiam-db/src/seeder.rs` — FOUND (contains seed_permissions with UPSERT)
- Commit `72fe4af` — FOUND
- Commit `0ac89aa` — FOUND
- `cargo check -p axiam-api-rest -p axiam-db -p axiam-server` — PASSED (exit 0)
- `cargo fmt --check` — PASSED (no diff)
- `cargo clippy -- -D warnings` — PASSED (no warnings)
