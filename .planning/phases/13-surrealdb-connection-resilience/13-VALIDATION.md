---
phase: 13
slug: surrealdb-connection-resilience
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-19
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (per-crate, targeted `--test`); `#[tokio::test]` macros; in-memory `kv-mem` SurrealDB engine (no live server needed) |
| **Config file** | `crates/axiam-db/Cargo.toml` `[dev-dependencies]` |
| **Quick run command** | `cargo test -p axiam-db --no-default-features --test reconnect_regression` |
| **Full (crate) command** | `cargo test -p axiam-db --no-default-features` |
| **Estimated runtime** | ~30–90s for the axiam-db crate tests |

> ⚠️ Disk near-full: per-crate `-p axiam-db --no-default-features` ONLY. NEVER whole-workspace `cargo build`/`cargo test`/`just test` (linking → ENOSPC). Verify via OUTPUT TEXT, not exit codes (rtk masks them). DB tests use the `kv-mem` in-memory engine — no `just dev-up` dependency. `scripts/e2e-bootstrap.sh` hitting `/sql` must inspect each statement's `status` field (HTTP 200 hides per-statement ERR — CR-01 false-green).

---

## Sampling Rate

- **After every task commit:** Run the quick command for `axiam-db`
- **After the wave:** `cargo test -p axiam-db --no-default-features` + `cargo clippy -p axiam-db --no-default-features -- -D warnings`
- **Max feedback latency:** ~90 seconds

---

## Per-Task Verification Map

| Task | Plan | Wave | Req | Behavior verified | Method | Automated command | Wave 0 | Status |
|------|------|------|-----|-------------------|--------|-------------------|--------|--------|
| 13-01-01 | 13-01 | 1 | REQ-17 | `DbError::SessionMismatch` variant exists + maps to an error (not panic) | Compilation + source assertion | `cargo check -p axiam-db --no-default-features --tests` | ✅ | ⬜ pending |
| 13-01-02 | 13-01 | 1 | REQ-17 | Reconnect regression: a session that lost ns/db selection returns NotFound for a known record; after re-select it returns OK. Test must FAIL without the Task-3 guard. | Integration test (kv-mem) | `cargo test -p axiam-db --no-default-features --test reconnect_regression` | ✅ | ⬜ pending |
| 13-01-03 | 13-01 | 1 | REQ-17 | Background guard re-issues `use_ns`/`use_db` on detected mismatch; `health_check` asserts active ns/db via `session::ns()`/`session::db()` (not just liveness) | Unit test + source assertion | `cargo test -p axiam-db --no-default-features -- health_check` | ✅ | ⬜ pending |
| 13-02-01 | 13-02 | 1 | REQ-17 | `e2e-bootstrap.sh` seeds the db the server reads (`main`, not `axiam`) and the tenant CREATE no longer sets the non-existent `is_active` field | Source assertion + statement-status check | `grep -n 'surreal-db' scripts/e2e-bootstrap.sh` (== main) + `! grep -q 'is_active' scripts/e2e-bootstrap.sh` | ✅ | ⬜ pending |
| 13-02-02 | 13-02 | 1 | REQ-17 | `just bootstrap-local` exists and seeds org+tenant+admin against the run-local server | Recipe presence + parse | `just --list \| grep bootstrap-local` | ✅ | ⬜ pending |

---

## Manual-Only Verifications

| Verification | Req | Why manual | How |
|--------------|-----|-----------|-----|
| Deferred Phase-12 11-item smoke (`12-HUMAN-UAT.md`) is now runnable end-to-end | REQ-17 | Requires live REST+gRPC+federation+email + a human walking flows | After Phase 13 lands: `just dev-up` → `just run-local` → `just bootstrap-local` → log in as the seeded admin → walk `12-HUMAN-UAT.md`. This phase only makes it runnable; it does not execute the smoke. |

---

## Nyquist Compliance

- [x] Every task has an `<automated>` verify command (sampling continuity: no 3 consecutive tasks without automated verify)
- [x] The reconnect invariant has a regression test that fails without the fix (no trivially-passing test)
- [x] `health_check` correctness is unit-tested against the active-ns/db assertion
- [x] Manual-only item (deferred smoke) is explicitly carved out and not counted as automated coverage
