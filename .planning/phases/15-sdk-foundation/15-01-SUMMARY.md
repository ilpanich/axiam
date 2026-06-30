---
phase: "15"
plan: "01"
subsystem: axiam-api-rest
tags: [authz, rest-api, rate-limit, openapi, audit, fnd-04]
dependency_graph:
  requires: [D-06, D-07, D-08, D-15]
  provides: [FND-04]
  affects: [axiam-api-rest, axiam-authz, axiam-db]
tech_stack:
  added: []
  patterns:
    - "AuthzChecker trait-object via web::Data<Arc<dyn AuthzChecker>> — same pattern as gRPC (D-08)"
    - "RequirePermission::new gate inside handler (not route-level) for conditional cross-subject check"
    - "Fire-and-forget audit append: tokio::spawn, log error, never propagate (legally significant)"
    - "AllowAllAuthzChecker/DenyAllAuthzChecker test doubles for unit tests without full engine"
    - "actix_http::body::to_bytes for response body extraction in unit tests"
    - "CARGO_BUILD_JOBS=1 + --lib to avoid linker OOM when building large test binary"
key_files:
  created:
    - crates/axiam-api-rest/src/handlers/authz_check.rs
    - crates/axiam-api-rest/src/tests/authz_check_test.rs
  modified:
    - crates/axiam-api-rest/src/permissions.rs
    - crates/axiam-api-rest/src/config/rate_limit.rs
    - crates/axiam-api-rest/src/handlers/mod.rs
    - crates/axiam-api-rest/src/openapi.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/tests/mod.rs
    - crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs
decisions:
  - "authz:check_as goes in PERMISSION_REGISTRY only — not in ROUTE_PERMISSION_MAP (gate is conditional inside handler, not per-route)"
  - "Both /authz/check and /authz/check/batch go in AUTHENTICATED_SELF_SERVICE_PATHS (JWT required, no fixed permission gate)"
  - "Batch handler validates authz:check_as once up-front if any check has subject_id (atomic 403 for the whole batch)"
  - "Reason field uses engine string only (T-15-02 — no amplification of engine internals beyond the deny message)"
  - "tenant_id always from authenticated user.tenant_id, never from request body (T-15-03)"
metrics:
  duration: "~2 sessions (context overflow); active execution ~90 minutes"
  completed: "2026-06-30"
  tasks_completed: 3
  tasks_total: 3
  commits: 3
status: complete
requirements: [FND-04]
---

# Phase 15 Plan 01: REST Authz-Check Endpoints Summary

FND-04 REST authorization-check endpoints (`POST /api/v1/authz/check` and `POST /api/v1/authz/check/batch`) implemented using the same `AuthorizationEngine::check_access` as gRPC (D-08), with a dedicated `authz_check_per_min` rate-limit tier (default 300), full OpenAPI annotation, and 5 unit tests + 2 parity tests passing.

## Tasks Completed

| Task | Description | Commit | Status |
|------|-------------|--------|--------|
| 1 | Register `authz:check_as` permission and `authz_check_per_min` rate-limit tier | a8db1ea | done |
| 2 | Create `handlers/authz_check.rs` with `check_access` and `batch_check_access` | 2af4020 | done |
| 3 | Wire routes in server.rs, OpenAPI annotations, parity test, unit tests | 862f1bb | done |

## What Was Built

### Permission + Rate-Limit Registration (Task 1)

- `PERMISSION_REGISTRY` in `permissions.rs`: added `("authz:check_as", "Perform an authorization check on behalf of another subject (admin override)")`.
- `RateLimitConfig` in `config/rate_limit.rs`: added `pub authz_check_per_min: u32` (default 300, validate >=1).

### Handler (Task 2)

`crates/axiam-api-rest/src/handlers/authz_check.rs` implements:

- `CheckAccessBody { action, resource_id, scope, subject_id? }` — request body
- `CheckAccessResponse { allowed, reason? }` — response; `reason` is `skip_serializing_if = None` (T-15-02)
- `BatchCheckAccessBody / BatchCheckAccessResponse` — wraps Vec<CheckAccessBody/Response>
- `check_access<C: Connection>` — single check with cross-subject override gate
- `batch_check_access<C: Connection>` — batch check; validates `authz:check_as` once if any check has subject_id

Security mitigations implemented:
- T-15-01: `RequirePermission::new("authz:check_as", user.tenant_id).check(...)` guards subject_id override
- T-15-02: `reason` field carries engine deny message only, never amplified
- T-15-03: `tenant_id` always from `user.tenant_id` (authenticated), never from request body
- T-15-04: `append_check_as_audit` fire-and-forget tokio::spawn writes audit row on cross-subject override

### Routes + OpenAPI + Tests (Task 3)

- `server.rs`: `/authz/check` and `/authz/check/batch` registered with `build_governor(rate_limit_cfg.authz_check_per_min)`
- `openapi.rs`: paths, schemas, and `(name = "authz", description = "...")` tag added
- `route_openapi_parity_test.rs`: both paths in `AUTHENTICATED_SELF_SERVICE_PATHS`
- `authz_check_test.rs`: 5 unit tests — self-check allow, override-denied-403, override-allowed+audit-row, batch ordering, batch-override-403

## Test Results

```
cargo test --lib -- authz_check     : 5 passed, 35 filtered out
cargo test --lib -- route_openapi_parity: 2 passed, 38 filtered out
```

Note: full test binary for axiam-api-rest is ~760MB (links SurrealDB, PKI, federation, OAuth2, etc.). Linker fails with Bus Error (signal 7) during parallel linking due to memory pressure. Tests pass with `CARGO_BUILD_JOBS=1 --lib`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test helper `read_body()` used `bytes::Bytes` return type**
- **Found during:** Task 3 first compilation
- **Issue:** `bytes` crate not in dev-dependencies; `[u8]` is unsized so async return type failed
- **Fix:** Replaced `read_body() -> bytes::Bytes` with `read_body_json() -> serde_json::Value` using `actix_http::body::to_bytes` (already available via actix-http dev-dep). All 5 test call sites updated accordingly.
- **Files modified:** `crates/axiam-api-rest/src/tests/authz_check_test.rs`
- **Commit:** 862f1bb (final test file)

### Infrastructure Issues (Out of Scope)

**Disk exhaustion during test compilation**
- Root cause: prior test binary artifacts (600-760MB each, 34 binaries = ~25GB) filled `/dev/vda`
- Recovery: iteratively deleted large binary artifacts from `target/debug/deps/` to free space
- These are pre-existing binaries from prior phases; not caused by this plan's changes
- Test runs with `CARGO_BUILD_JOBS=1 --lib` avoid triggering the full linker for integration test binaries

## Known Stubs

None — all handler logic is fully implemented and wired.

## Threat Flags

No new threat surface beyond what was planned in `<threat_model>`:
- T-15-01, T-15-02, T-15-03, T-15-04 all mitigated in `handlers/authz_check.rs`

## Self-Check: PASSED

Files created/modified:
- /home/user/axiam/crates/axiam-api-rest/src/handlers/authz_check.rs: FOUND
- /home/user/axiam/crates/axiam-api-rest/src/tests/authz_check_test.rs: FOUND
- /home/user/axiam/crates/axiam-api-rest/src/permissions.rs: FOUND (modified)
- /home/user/axiam/crates/axiam-api-rest/src/config/rate_limit.rs: FOUND (modified)
- /home/user/axiam/crates/axiam-api-rest/src/server.rs: FOUND (modified)
- /home/user/axiam/crates/axiam-api-rest/src/openapi.rs: FOUND (modified)

Commits verified:
- a8db1ea (Task 1): FOUND
- 2af4020 (Task 2): FOUND
- 862f1bb (Task 3): FOUND
