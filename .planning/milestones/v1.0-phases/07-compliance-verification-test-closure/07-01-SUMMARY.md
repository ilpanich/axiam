---
phase: 07-compliance-verification-test-closure
plan: "01"
subsystem: axiam-pki
tags: [testing, pki, certificates, mtls, pgp, security]
dependency_graph:
  requires: []
  provides: [axiam-pki-test-coverage]
  affects: [REQ-11, ROADMAP-SC-4]
tech_stack:
  added: []
  patterns:
    - Surreal::new::<Mem>() + run_migrations for in-process DB fixture
    - CaService / CertService / DeviceAuthService / PgpService via real repo impls
    - pgp::composed::Message::verify_read for PGP signature verification roundtrip
key_files:
  created:
    - crates/axiam-pki/tests/ca_test.rs
    - crates/axiam-pki/tests/cert_test.rs
    - crates/axiam-pki/tests/mtls_test.rs
    - crates/axiam-pki/tests/pgp_test.rs
  modified:
    - crates/axiam-pki/Cargo.toml
decisions:
  - "Expired CA test uses StoreCaCertificate directly to inject a row with past not_after (Active status) — avoids needing a raw SurrealQL UPDATE path in the repo"
  - "Unknown-fingerprint mTLS test uses two separate in-memory DB instances so the cert is registered in one but authenticated against another (clean fingerprint table)"
  - "Ed25519Legacy key encrypt reject asserted via PgpKeyAlgorithm::Ed25519 + PgpKeyPurpose::Export on the same test key; pgp.rs:173 path confirmed"
  - "PGP verify roundtrip uses Message::verify_read (consumes internal reader + signature chain) rather than verify (requires prior drain)"
metrics:
  duration: "~15 min (compile: 71s + pgp RSA test: 106s)"
  completed: "2026-06-07"
  tasks_completed: 2
  files_created: 4
  files_modified: 1
---

# Phase 7 Plan 01: axiam-pki Test Coverage Summary

**One-liner:** Four PKI integration test files covering CA gen, leaf cert issuance/reject, mTLS
device auth reject cases, and PGP audit-sign+verify roundtrip — closing the only 0-test crate.

## Tasks Completed

| # | Task | Commit | Status |
|---|------|--------|--------|
| 1 | CA + leaf cert tests (ca_test.rs, cert_test.rs) | c951ec0 | done |
| 2 | mTLS reject cases + PGP roundtrip (mtls_test.rs, pgp_test.rs) | 193a199 | done |

## Test Results

```
cargo test -p axiam-pki
13 passed (6 suites, ~83s)
```

- **ca_test.rs** (3 tests): Ed25519 CA happy path; zero-validity reject; above-max-validity reject
- **cert_test.rs** (3 tests): leaf cert happy path; revoked-CA reject; expired-CA reject
- **mtls_test.rs** (4 tests): valid cert → DeviceIdentity; unknown fingerprint → NotFound; expired cert → Certificate error; revoked cert → not-active
- **pgp_test.rs** (3 tests): Ed25519 sign+verify roundtrip; Ed25519 encryption reject; Rsa4096 encryption success

## Threat Coverage Verified

| Threat | Test | Result |
|--------|------|--------|
| T-07-01: mTLS spoofing | `mtls_rejects_unknown_fingerprint`, `mtls_rejects_expired_cert`, `mtls_rejects_revoked_cert` | PASS |
| T-07-02: Cert elevation via revoked CA | `cert_generate_rejects_revoked_ca`, `cert_generate_rejects_expired_ca` | PASS |
| T-07-03: PGP key purpose confusion | `pgp_rejects_ed25519_for_encryption` | PASS |
| T-07-04: CA private key at rest | `pgp_sign_audit_batch_and_verify_roundtrip` | PASS |

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None.

## Threat Flags

None — test files introduce no new network endpoints or trust boundaries.

## Self-Check: PASSED

- `crates/axiam-pki/tests/ca_test.rs` — FOUND
- `crates/axiam-pki/tests/cert_test.rs` — FOUND
- `crates/axiam-pki/tests/mtls_test.rs` — FOUND
- `crates/axiam-pki/tests/pgp_test.rs` — FOUND
- Commit c951ec0 — FOUND (git log confirmed)
- Commit 193a199 — FOUND (git log confirmed)
