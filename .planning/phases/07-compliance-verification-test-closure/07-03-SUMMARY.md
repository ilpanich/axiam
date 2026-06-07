---
phase: 07-compliance-verification-test-closure
plan: "03"
subsystem: axiam-api-grpc
tags: [grpc, testing, authz, tonic, in-process-harness, T19.1, T19.2, D-10]
dependency_graph:
  requires: []
  provides: [grpc-authz-integration-tests, concurrent-batch-authz-tests, axiam-api-grpc-test-harness]
  affects: [axiam-api-grpc]
tech_stack:
  added: [tokio-stream 0.1]
  patterns: [tonic in-process TcpListener harness, feature-gated client stub generation, join_all concurrent test]
key_files:
  created:
    - crates/axiam-api-grpc/tests/grpc_authz_test.rs
  modified:
    - crates/axiam-api-grpc/build.rs
    - crates/axiam-api-grpc/Cargo.toml
decisions:
  - "Feature-flag approach chosen for client stubs: CARGO_FEATURE_CLIENT in build.rs (not separate test crate)"
  - "Governor layer explicitly omitted from test server: SmartIpKeyExtractor panics on in-process connections"
  - "tokio-stream added as direct version dep (0.1, not workspace) since it was absent from workspace"
  - "Concurrent test uses 10 tasks (>= 8 required) with alternating allow/deny assertions per task"
metrics:
  duration: "25m"
  completed: "2026-06-07"
  tasks: 2
  files: 3
---

# Phase 07 Plan 03: gRPC In-Process Harness + T19.1/T19.2 Summary

One-liner: In-process tonic server harness with feature-gated client stubs, covering gRPC authorization allow/deny/invalid-arg (T19.1) and concurrent batch authz correctness (T19.2).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Feature-gate client stub generation (build.rs + Cargo.toml) | 977991c | build.rs, Cargo.toml |
| 2 | In-process harness + T19.1 authz + T19.2 batch/concurrent | b2310b9 | tests/grpc_authz_test.rs |

## What Was Built

### Task 1: Feature-Gated Client Stubs

Modified `crates/axiam-api-grpc/build.rs` to conditionally generate client stubs:

```rust
let build_client = std::env::var("CARGO_FEATURE_CLIENT").is_ok();
tonic_prost_build::configure()
    .build_server(true)
    .build_client(build_client)
    // ...
```

Added to `Cargo.toml`:
- `[features] client = []`
- Dev dependencies: `axiam-db`, `axiam-auth`, `surrealdb` (kv-mem), `tokio-stream`, `tokio`, `uuid`

Both `cargo build -p axiam-api-grpc` (server-only) and `cargo build -p axiam-api-grpc --features client` (with client stubs) succeed. `AuthorizationServiceClient` is verified present in generated output.

### Task 2: Test Harness + T19.1 + T19.2

Created `crates/axiam-api-grpc/tests/grpc_authz_test.rs` (508 lines, 7 tests):

**Harness** (`start_test_server`):
- Binds `TcpListener` to `127.0.0.1:0` (ephemeral port)
- Wraps in `TcpListenerStream` for `serve_with_incoming_shutdown`
- `Server::builder().add_service(AuthorizationServiceServer::new(...))` — no governor layer
- Graceful shutdown via `oneshot::channel`

**T19.1 cases:**
- `check_access_allows_when_role_grants_permission` — allowed=true for valid grant
- `check_access_denies_when_no_role` — allowed=false (default-deny, ASVS V4.1.1)
- `check_access_denies_wrong_action` — allowed=false when action not in grant
- `check_access_rejects_malformed_user_id` — `Code::InvalidArgument` on bad UUID
- `check_access_rejects_malformed_tenant_id` — `Code::InvalidArgument` on bad UUID

**T19.2 cases:**
- `batch_check_access_returns_mixed_results` — 3 requests (allow / deny-no-role / deny-wrong-action); asserts each result individually
- `concurrent_check_access_all_resolve_correctly` — 10 tokio tasks spawned; each task connects its own client channel and calls `check_access`; results collected sequentially with `join_result.await.unwrap()`; each task asserts its expected allow/deny outcome (alternating even=allow, odd=deny)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Unused imports `AccessDecision` and `AccessRequest`**
- Found during: Task 2, clippy run
- Issue: Imported from `axiam_authz` but not used directly in tests (only used implicitly via engine)
- Fix: Removed the two unused imports, left `AuthorizationEngine` which is required for type alias
- Files modified: crates/axiam-api-grpc/tests/grpc_authz_test.rs
- Commit: b2310b9 (included in task commit)

**2. [Rule 2 - Missing] `futures` crate not in workspace**
- Found during: Task 2, initial design used `futures::future::join_all`
- Issue: `futures` is not in workspace deps (only `futures-lite`); adding it would require a new dep
- Fix: Used sequential `handle.await.unwrap()` iteration instead — functionally equivalent for the join_all pattern, all 10 tasks spawn in parallel, results are awaited sequentially
- Files modified: crates/axiam-api-grpc/tests/grpc_authz_test.rs
- No deviation in task outcome: all tasks run concurrently (tokio::spawn), join is sequential but that is fine for a test

## Threat Model Coverage

| Threat ID | Status | Evidence |
|-----------|--------|----------|
| T-07-09 | Covered | `check_access_denies_when_no_role` + `check_access_denies_wrong_action` assert default-deny |
| T-07-10 | Covered | `check_access_rejects_malformed_user_id` + `check_access_rejects_malformed_tenant_id` assert InvalidArgument |
| T-07-11 | Covered | `concurrent_check_access_all_resolve_correctly` spawns 10 tasks each asserting individual outcome |
| T-07-DoS-note | Accepted | Governor omitted by design — no SmartIpKeyExtractor peer IP in-process |

## Known Stubs

None. All test assertions operate against real RPC responses.

## Threat Flags

None. No new network endpoints, auth paths, or schema changes introduced. Tests only.

## Self-Check: PASSED

- `crates/axiam-api-grpc/tests/grpc_authz_test.rs` — exists
- `crates/axiam-api-grpc/build.rs` — CARGO_FEATURE_CLIENT present
- `crates/axiam-api-grpc/Cargo.toml` — `[features] client = []` present
- Commit 977991c — verified in log
- Commit b2310b9 — verified in log
- 7 tests green under `cargo test -p axiam-api-grpc --features client --test grpc_authz_test`
- `cargo clippy -p axiam-api-grpc --features client --tests -- -Dwarnings` clean
