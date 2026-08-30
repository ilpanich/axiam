---
phase: 10-high-remediation
plan: 02
subsystem: axiam-pki, axiam-server
tags: [security, refactor, pki, env-keys, CQ-B43, SEC-012, REQ-14]
dependency_graph:
  requires: [10-01]
  provides: [load_key_from_env, PkiConfig-Option, PKI-fail-fast]
  affects: [axiam-pki, axiam-server]
tech_stack:
  added: [axiam-pki/src/config.rs]
  patterns: [fail-fast on missing secret, Option-wrapping for absent config keys]
key_files:
  created:
    - crates/axiam-pki/src/config.rs
    - crates/axiam-pki/tests/req14_pki_failfast_test.rs
  modified:
    - crates/axiam-server/src/main.rs
    - crates/axiam-pki/src/lib.rs
    - crates/axiam-pki/src/ca.rs
    - crates/axiam-pki/src/cert.rs
    - crates/axiam-pki/src/pgp.rs
    - crates/axiam-pki/tests/ca_test.rs
    - crates/axiam-pki/tests/cert_test.rs
    - crates/axiam-pki/tests/mtls_test.rs
decisions:
  - "PkiConfig moved to dedicated config.rs for single-responsibility; ca.rs re-exports it"
  - "load_key_from_env uses panic for malformed keys (operator config error at startup, not runtime); returns None for absent keys"
  - "ok_or_else guard in ca.rs, cert.rs, pgp.rs (all three encrypt/decrypt sites) rather than only ca.rs — complete SEC-012 coverage"
metrics:
  duration: "22 min"
  completed: "2026-06-13T09:22:53Z"
  tasks: 3
  files: 10
---

# Phase 10 Plan 02: load_key_from_env + PKI Fail-Fast Summary

Single `load_key_from_env` helper replaces four copy-pasted hex-decode blocks; `PkiConfig.encryption_key` changed to `Option<[u8;32]>` so CA/cert/PGP private-key encryption fails fast with a clear error instead of silently using an all-zero key.

## Tasks Completed

| # | Name | Commit | Files |
|---|------|--------|-------|
| 1 | Extract load_key_from_env, replace four blocks | 5b18815 | main.rs |
| 2 (RED) | Add failing PKI fail-fast test | (intermediate) | req14_pki_failfast_test.rs |
| 2 (GREEN) | PkiConfig.encryption_key → Option; guard encrypt paths | 11d5076 | config.rs, lib.rs, ca.rs, cert.rs, pgp.rs, 3 test files |
| 3 | Wire PKI key via helper; remove zero-key fallback | a2ff6d4 | main.rs, mtls_test.rs, cert_test.rs |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing coverage] Updated mtls_test.rs and second cert_test.rs site**
- Found during: Task 3 compile check
- Issue: Two more `test_pki_config()` helpers used `[0u8;32]` bare — `mtls_test.rs` and an inline `Cfg { encryption_key: [0u8;32] }` in `cert_test.rs:162`
- Fix: Updated both to `Some([0u8;32])` to match new `Option<[u8;32]>` type
- Files modified: `tests/mtls_test.rs`, `tests/cert_test.rs`
- Commit: a2ff6d4

**2. [Rule 2 - Missing coverage] Guard added in cert.rs and pgp.rs**
- Plan mentioned only ca.rs explicitly; cert.rs decrypts CA private keys and pgp.rs encrypts/decrypts audit-signing keys — both needed the same `ok_or_else` guard for complete SEC-012 coverage
- All three encrypt/decrypt sites now return `AxiamError::Internal` on absent key

## Verification

- `cargo check -p axiam-server -p axiam-pki --tests --no-default-features`: 0 errors
- `cargo clippy -p axiam-server -p axiam-pki --no-default-features -- -D warnings`: no issues
- `cargo test -p axiam-pki --no-default-features --test req14_pki_failfast_test`: 2 passed
  - `ca_generate_without_key_errors`: Err(Internal("AXIAM__PKI__ENCRYPTION_KEY..."))
  - `ca_generate_with_key_ok`: Ok

## Known Stubs

None.

## Threat Flags

None — all changes narrow the attack surface (removing zero-key fallback). No new network endpoints or trust-boundary crossings introduced.

## TDD Gate Compliance

Task 2 followed RED/GREEN cycle:
- RED commit: failing test (type mismatch errors confirming test precedes implementation)
- GREEN commit: 11d5076 — both tests pass after Option change + ok_or_else guard

## Self-Check: PASSED

- `crates/axiam-pki/src/config.rs` — exists
- `crates/axiam-pki/tests/req14_pki_failfast_test.rs` — exists
- Commit 5b18815 — exists (git log confirms)
- Commit 11d5076 — exists
- Commit a2ff6d4 — exists
