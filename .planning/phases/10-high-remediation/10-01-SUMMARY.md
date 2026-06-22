---
phase: 10-high-remediation
plan: "01"
subsystem: axiam-db, axiam-server, axiam-api-rest
tags: [security, password-hashing, pepper, refactor, test]
dependency_graph:
  requires: []
  provides: [single-hashing-path, pepper-wiring-end-to-end]
  affects: [axiam-db, axiam-server, axiam-api-rest]
tech_stack:
  added: [axiam-auth dep in axiam-db]
  patterns: [delegate-to-auth-layer, env-based-pepper-loading, with_pepper-constructor]
key_files:
  modified:
    - crates/axiam-db/src/repository/user.rs
    - crates/axiam-db/Cargo.toml
    - crates/axiam-server/src/main.rs
  created:
    - crates/axiam-api-rest/tests/req14_pepper_test.rs
decisions:
  - Delete repo-layer hash_password rather than delegate; the function was a full duplication, not a wrapper
  - Keep verify_password in user.rs (still used by axiam-db integration tests); no plan scope to remove it
  - Pre-existing clippy error in csrf.rs (items-after-test-module) is out of scope; deferred
metrics:
  duration: "~25 min"
  completed: "2026-06-13T08:24:57Z"
  tasks: 3
  files_changed: 4
---

# Phase 10 Plan 01: Collapse Password-Hashing Paths + Wire Auth Pepper Summary

Single sentence: Deleted the duplicate Argon2id hasher in the user repository, wired all password
hashing through `axiam_auth::password::hash_password`, and threaded `AXIAM__AUTH__PEPPER` from
env into both the user repo and auth config so REST-created users can authenticate.

## Tasks Completed

| # | Name | Commit | Key Files |
|---|------|--------|-----------|
| 1 | Delete repo-layer hasher, route through axiam-auth::password | 66fc530 | user.rs, axiam-db/Cargo.toml |
| 2 | Load AXIAM__AUTH__PEPPER and wire with_pepper in main.rs | 4c18348 | axiam-server/src/main.rs |
| 3 | Integration test — REST-created user logs in with pepper | 12bd31d | axiam-api-rest/tests/req14_pepper_test.rs |

## Verification Results

- `cargo check -p axiam-db --no-default-features`: CLEAN
- `cargo check -p axiam-server --no-default-features`: CLEAN
- `cargo test -p axiam-api-rest --no-default-features --test req14_pepper_test`: 2 passed
- `grep -rn 'fn hash_password' crates/ | grep -v axiam-auth`: empty (single implementation confirmed)

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as written.

### Pre-existing Issues Deferred

**1. [Pre-existing] clippy: items-after-test-module in csrf.rs**
- **Found during:** Task 3 clippy run with `--tests`
- **Scope:** Pre-existed before this plan; `git stash` confirmed
- **Action:** Logged to deferred-items; not fixed (out-of-scope per deviation boundary rule)

## Known Stubs

None — both new call sites wire real data; the test creates real in-memory users.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced.

## Self-Check: PASSED

- `crates/axiam-db/src/repository/user.rs` — exists, modified
- `crates/axiam-db/Cargo.toml` — exists, modified
- `crates/axiam-server/src/main.rs` — exists, modified
- `crates/axiam-api-rest/tests/req14_pepper_test.rs` — exists, created
- Commits: 66fc530, 4c18348, 12bd31d — all present in `git log --oneline -5`
