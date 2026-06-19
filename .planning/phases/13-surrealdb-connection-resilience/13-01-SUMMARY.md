---
phase: 13-surrealdb-connection-resilience
plan: "01"
subsystem: axiam-db
tags: [resilience, surrealdb, reconnect, health-check, regression-test]
dependency_graph:
  requires: []
  provides: [REQ-17]
  affects: [axiam-db, axiam-api-rest, axiam-server]
tech_stack:
  added: []
  patterns:
    - Arc<Surreal<Client>> for shared session ownership between guard and health_check
    - Periodic background guard task (tokio::time::interval) for ns/db keepalive
    - session::ns()/session::db() SurrealQL functions for server-side session assertion
key_files:
  created:
    - crates/axiam-db/tests/reconnect_regression.rs
  modified:
    - crates/axiam-db/src/connection.rs
    - crates/axiam-db/src/error.rs
decisions:
  - "Arc<Surreal<Client>> chosen over plain clone after regression test proved clones have independent session state (RESEARCH A4 empirically settled)"
  - "health_check return type changed from Result<(),surrealdb::Error> to Result<(),DbError> — cleaner error semantics, avoids coupling to unstable surrealdb::Error internals (RESEARCH Open Question 2 / A3)"
  - "DbManager drops #[derive(Clone)] — JoinHandle not Clone; main.rs only clones client(), no caller change needed"
metrics:
  duration: "~20 minutes"
  completed: "2026-06-19T13:22:19Z"
  tasks_completed: 3
  files_changed: 3
---

# Phase 13 Plan 01: DbManager Reconnect Resilience Summary

One-liner: Background ns/db keepalive guard + session-asserting health_check using Arc<Surreal<Client>> after empirically confirming clone session independence.

## Tasks Completed

| Task | Commit | Files | Status |
|------|--------|-------|--------|
| 1: DbError::SessionMismatch variant | 941444c | error.rs | Done |
| 2: Reconnect regression test (kv-mem) | 15febd6 | tests/reconnect_regression.rs | Done |
| 3: ns/db keepalive guard + asserting health_check | 4f7053f | connection.rs | Done |

## Key Technical Finding: Clone Session Independence (RESEARCH A4)

**Empirically settled.** `Surreal<Client>` clones have **independent** session state.

Proof from Task 2 regression test:
1. Seeded org in `db` (axiam/main)
2. Called `db.use_ns("main").use_db("main")`
3. Cloned `db` AFTER the flip → new clone inherits the wrong ns/db
4. `get_by_id` on the new clone returned `Err(NotFound)` — confirmed failure mode
5. Called `db.use_ns("axiam").use_db("main")`, cloned again → `get_by_id` returned `Ok`

**Implication for Task 3:** The guard CANNOT use `db.clone()` for re-selection (it would fix the guard's session, not `DbManager.db`). Wrapping `db` in `Arc<Surreal<Client>>` ensures the guard and `DbManager.health_check` operate on the SAME session allocation.

**Limitation documented:** Repository handles obtained via `db.client().clone()` at startup (in main.rs) are independent clones. After a live WS reconnect, all clones' server-side sessions reset simultaneously. The guard re-selects `DbManager.db` (the Arc-wrapped handle), so `health_check` correctly detects and signals the state. New `.client().clone()` calls after the guard re-selects would be correct. Long-lived startup clones remain out of scope for this plan — documented as a known limitation below.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as written.

### Scope Notes

**main.rs untouched:** The plan noted "if main.rs needs a trivial signature touch, flag in SUMMARY." The only interface change was `health_check` return type (`surrealdb::Error` → `DbError`). The `HealthChecker` impl in `axiam-api-rest/src/health.rs` maps via `.map_err(|e| format!("... {e}"))` — `DbError` implements `Display`, so no change was needed.

## Known Stubs

None.

## Known Limitations (deferred)

**Long-lived startup clones in main.rs:** All repository handles in main.rs are created once at startup via `db.client().clone()`. After a WS reconnect, these clones' sessions are also reset to unselected. The guard re-selects `DbManager.db` but NOT these clones. A full fix would require either:
- Re-cloning after each reconnect detection (architectural change — Phase 14+ scope)
- Calling `use_ns/use_db` before each query (per-query overhead)
- Switching to a connection pool where each handle re-selects on checkout

For the current deployment (internal service, reliable network), the guard + health_check provide meaningful defense-in-depth. The health endpoint will catch the state; ops can restart the service.

## Verification Results

```
cargo test -p axiam-db --no-default-features --test reconnect_regression
→ test result: ok. 1 passed; 0 failed

cargo test -p axiam-db --no-default-features
→ test result: ok. 122 passed; 0 failed

cargo clippy -p axiam-db --no-default-features -- -D warnings
→ No issues found

grep -c 'session::ns' crates/axiam-db/src/connection.rs
→ 4 (guard + health_check, both in non-comment code)
```

## Self-Check: PASSED

- [x] `crates/axiam-db/src/error.rs` — SessionMismatch variant present
- [x] `crates/axiam-db/tests/reconnect_regression.rs` — 89 lines, passes
- [x] `crates/axiam-db/src/connection.rs` — guard + asserting health_check, session::ns >= 1
- [x] Commits: 941444c, 15febd6, 4f7053f all exist in git log
- [x] 122 axiam-db tests pass
- [x] clippy clean
