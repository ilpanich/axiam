---
phase: 10-high-remediation
plan: 03
subsystem: axiam-auth, axiam-pki, axiam-db, axiam-server
tags: [async-safety, spawn_blocking, semaphore, tenant-isolation, rbac, hierarchy, CQ-B02, CQ-B07, CQ-B08, REQ-14]
dependency_graph:
  requires: [10-01, 10-02]
  provides: [crypto-spawn-blocking, crypto-bounding-semaphore, tenant-edge-isolation, resource-hierarchy-integrity]
  affects: [axiam-auth, axiam-pki, axiam-db, axiam-server]
tech_stack:
  patterns: [tokio spawn_blocking for CPU-bound crypto, Arc<Semaphore> bounding for blocking pool, transactional edge mutation with both-endpoint tenant check, cycle/orphan rejection in resource hierarchy]
key_files:
  created:
    - crates/axiam-auth/tests/req14_async_safety_test.rs
    - crates/axiam-db/tests/req14_tenant_isolation_test.rs
  modified:
    - crates/axiam-auth/src/service.rs
    - crates/axiam-auth/src/policy.rs
    - crates/axiam-pki/src/ca.rs
    - crates/axiam-pki/src/cert.rs
    - crates/axiam-pki/src/pgp.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-db/src/repository/role.rs
    - crates/axiam-db/src/repository/permission.rs
    - crates/axiam-db/src/repository/resource.rs
    - "(call-site updates) crates/axiam-pki/tests/{ca,cert,mtls,pgp,req14_pki_failfast}_test.rs"
    - "(call-site updates) crates/axiam-api-rest/tests/*, crates/axiam-server/tests/req7_*"
decisions:
  - "CPU-bound Argon2 (axiam-auth) and PKI keygen/sign (axiam-pki) wrapped in tokio::task::spawn_blocking, gated by a shared Arc<Semaphore> so blocking threads cannot starve the async runtime"
  - "Semaphore is constructed in main.rs and threaded into the PKI service constructors (new 3rd/4th arg), which forced — and the executor completed — call-site updates across every PKI test"
  - "Tenant-edge RELATE mutations (role->user, permission->role) verify BOTH endpoints belong to the tenant inside a transaction; cross-tenant attempts return AuthorizationDenied"
  - "Resource hierarchy rejects cycles and orphaned parents and drops the prior depth-50 truncation"
  - "10-01 pepper and 10-02 PKI Option<[u8;32]> fail-fast guards preserved through the spawn_blocking refactor"
metrics:
  completed: "2026-06-13T11:00:00Z"
  tasks: 3
  files: 30
  note: "Original executor stream terminated after emitting a mid-task fragment but had already committed all three tasks (ef484bf, 67a8241). SUMMARY/STATE/ROADMAP closed out by the orchestrator per safe_resume_gate after full verification."
---

# Phase 10 Plan 03: Async-Safe Crypto + Tenant Isolation + Resource Hierarchy

CPU-bound crypto (Argon2 hash/verify, PKI keygen/sign) now runs in `spawn_blocking` behind a bounding `Arc<Semaphore>` (CQ-B02). Tenant-scoped role/permission edge mutations verify both endpoints belong to the tenant and run in transactions (CQ-B07). Resource hierarchy rejects cycles/orphans and no longer truncates at depth 50 (CQ-B08).

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | spawn_blocking + bounding semaphore for Argon2 and PKI | ef484bf | axiam-auth/{service,policy}.rs, axiam-pki/{ca,cert,pgp}.rs, axiam-server/main.rs, all PKI test call sites, req14_async_safety_test.rs |
| 2 | Tenant isolation on role/permission edge mutations | 67a8241 | axiam-db/repository/{role,permission}.rs, req14_tenant_isolation_test.rs |
| 3 | Resource hierarchy cycle/orphan rejection + depth fix | 67a8241 | axiam-db/repository/resource.rs |

## Closeout Fixes (orchestrator)

- `fix(10-03)` d9015da — removed unused `create_tenant` test helper (clippy `dead_code`); tenant-isolation tests use `setup_two_tenants`.
- `fix(10)` 65bc5d8 — moved pre-existing `csrf.rs` `clear_*_cookie` fns above the test module to clear a pre-existing "items after a test module" clippy failure (csrf.rs untouched by Phase 10; unblocks the `axiam-api-rest -D warnings` gate).

## Verification

- `cargo check -p axiam-auth -p axiam-pki -p axiam-db -p axiam-server -p axiam-api-rest --tests --no-default-features`: 0 errors
- `cargo clippy` (same crates, `--tests --no-default-features -- -D warnings`): 0 errors
- `cargo test -p axiam-auth --test req14_async_safety_test --no-default-features`: 2 passed
- `cargo test -p axiam-db --test req14_tenant_isolation_test --no-default-features`: 6 passed
- 10-01 pepper round-trip and 10-02 PKI fail-fast tests still green (re-verified during wave gates)

## Known Stubs

None.

## Threat Flags

None new. Tenant-isolation edge checks narrow the attack surface (block cross-tenant privilege grants); semaphore bounding mitigates a crypto-driven async-runtime starvation DoS.

## Self-Check: PASSED

- Commits ef484bf, 67a8241 exist (git log confirms)
- req14_async_safety_test.rs and req14_tenant_isolation_test.rs exist and pass
- All affected crates compile + clippy-clean under the project's `--no-default-features` Arch off-path
