# Plan 08-01 Summary — Build Unblock (Wave 0)

**Phase:** 08-build-unblock
**Plan:** 01
**Requirements:** REQ-12
**Status:** Complete
**Executed:** 2026-06-10 (inline/sequential on `feature/full-review`, no worktree)

## What was built

Unblocked the `axiam-server` build (was failing with 13 compile errors) so the
audit-remediation waves (Phases 9–12) can compile and run.

### Task 1 — dependency relocation + sha2 import fix (commit `cd8a89b`)
- `crates/axiam-server/Cargo.toml`: added `uuid`, `chrono`, `serde_json`, `sha2`
  to `[dependencies]` (each `{ workspace = true }`); removed the now-duplicate
  `uuid`/`chrono`/`serde_json` from `[dev-dependencies]`.
- `crates/axiam-server/src/cleanup.rs:260,399`: `use rsa::sha2::{Digest, Sha256}`
  → `use sha2::{Digest, Sha256}` (identical type, re-export path correction only).
- `rsa` **retained** in `[dev-dependencies]` (Cargo.toml:60) — `req5_oidc_e2e.rs`
  and `req5_clock_skew.rs` still use it.

### Task 2 — clear 9 test warnings for the `-D warnings` gate (commit `a6ad127`)
Removed genuinely-unused items (no `#[allow]`) across 5 test files:
- `cleanup_task.rs`: dropped `use std::sync::Arc`
- `req5_oidc_e2e.rs`: dropped `Utc`, `EncodePublicKey`, `JwksCacheMap`, `STALE_WINDOW`
- `req5_secret_at_rest.rs`: dropped base64 `Engine`/`STANDARD`; removed needless `mut`
- `req5_clock_skew.rs`: renamed unused param `cache` → `_cache` in `make_svc`
  (`make_oidc_svc` still uses its `cache`)
- `req7_service_account_aud.rs`: renamed unused `app` → `_app` (line 276 only;
  lines 244/336 keep `app` — consumed by `call_service`)

## Verification (all local, project convention: `-p axiam-server`, `--no-default-features`)

| SC | Command | Result |
|----|---------|--------|
| SC1 | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features` | ✅ Finished clean (5m07s) |
| SC2 | `grep -n 'rsa::sha2' crates/axiam-server/src/cleanup.rs` | ✅ 0 matches; `use sha2::{Digest, Sha256}` ×2 |
| SC3 | `RUSTFLAGS="-Dwarnings" cargo build -p axiam-server --no-default-features --tests` | ✅ Finished clean (4m17s) |
| SC4 | `cargo clippy -p axiam-server --all-targets --no-default-features -- -D warnings` | ✅ Finished clean |

## Deviations from plan

- **`rsa` retained, NOT dropped.** The ROADMAP success criterion said "rsa dropped
  from binary deps if now unused"; research + this execution confirmed it is still
  used by test files, so it stays in `[dev-dependencies]`. (Plan already encoded this.)
- **Warning count was 9, not the ROADMAP's "12".** Research-verified; the gate
  asserts a clean `-D warnings` run rather than a hard count, so no discrepancy.
- **`EncodePublicKey` removal validated against clippy, not assumed.** clippy initially
  didn't flag it (file aborted at the line-476 errors before the unused-import pass
  completed); after fixing line 476 the test build stayed green with it removed,
  confirming it was genuinely unused.

## Self-Check: PASSED

## Not verifiable locally (manual / CI)

- SC3 true-CI: push branch → confirm GitHub Actions `build`, `build-no-saml`, and
  `test` jobs transition red→green. (Local `--no-default-features` build is the
  closest local proxy; the SAML-on path is exercised only in CI/Docker per the
  known xmlsec-on-Arch limitation.)

## Key files
- created: `.planning/phases/08-build-unblock/08-01-SUMMARY.md`
- modified: `crates/axiam-server/Cargo.toml`, `crates/axiam-server/src/cleanup.rs`,
  `crates/axiam-server/tests/{cleanup_task,req5_oidc_e2e,req5_secret_at_rest,req5_clock_skew,req7_service_account_aud}.rs`
