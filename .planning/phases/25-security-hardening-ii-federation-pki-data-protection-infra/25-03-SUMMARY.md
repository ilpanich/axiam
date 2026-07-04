---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 03
subsystem: auth
tags: [mtls, pki, x509, rust, surrealdb]

requires:
  - phase: 11-medium-remediation
    provides: "mtls.rs SEC-024 client-cert-to-CA chain verification (leaf status/validity + get_by_issuer_id + verify_signature) that this plan extends to the issuer"
provides:
  - "Issuing-CA status/validity gate in DeviceAuthService::authenticate — a revoked or expired issuing CA now fails closed before verify_signature"
  - "mtls_rejects_revoked_issuing_ca and mtls_rejects_expired_issuing_ca negative tests proving the gate"
affects: [26-correctness-resilience, security-audit, pki]

tech-stack:
  added: []
  patterns:
    - "Issuer-trust gate mirrors the pre-existing leaf-cert status/validity check (same AxiamError::Certificate type, same Utc::now() clock source, same comparison direction) rather than introducing a new pattern"

key-files:
  created: []
  modified:
    - crates/axiam-pki/src/mtls.rs
    - crates/axiam-pki/tests/mtls_chain_test.rs

key-decisions:
  - "Mirrored the leaf-cert status/validity check exactly onto the issuing CA (same error type/style, same clock source) per D-02/D-xx guidance — no new pattern introduced"
  - "mtls_rejects_revoked_issuing_ca uses the existing CaCertificateRepository::revoke(org_id, id) production method rather than a raw SurrealDB UPDATE, since a real revoke path already exists"
  - "mtls_rejects_expired_issuing_ca backdates not_after via a direct SurrealDB UPDATE — documented in-code as a test-only escape hatch, not a new production API, since no repo method sets an arbitrary validity window"
  - "Full chain-walk beyond the immediate issuing CA remains explicitly out of scope (D-02 — flat org/tenant-CA -> device hierarchy); tracked as accepted low-severity residual risk T-25-09"

requirements-completed: [SECHRD-05]

coverage:
  - id: D1
    description: "Device-cert mTLS auth against a revoked issuing CA fails closed before verify_signature"
    requirement: "SECHRD-05"
    verification:
      - kind: unit
        ref: "crates/axiam-pki/tests/mtls_chain_test.rs#mtls_rejects_revoked_issuing_ca"
        status: pass
    human_judgment: false
  - id: D2
    description: "Device-cert mTLS auth against an expired/not-yet-valid issuing CA fails closed before verify_signature"
    requirement: "SECHRD-05"
    verification:
      - kind: unit
        ref: "crates/axiam-pki/tests/mtls_chain_test.rs#mtls_rejects_expired_issuing_ca"
        status: pass
    human_judgment: false

duration: 12min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 03: Issuing-CA Status/Validity Gate for mTLS Summary

**Mirrored the existing leaf-cert status/validity check onto the immediate issuing CA in `axiam-pki::mtls.rs`, closing the gap where a revoked or expired issuing CA was still trusted for device-cert authentication (SECHRD-05).**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-07-04T16:18:56Z
- **Completed:** 2026-07-04T16:30:51Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `DeviceAuthService::authenticate` now asserts the issuing CA's `status == Active` and `Utc::now()` is within `[not_before, not_after]` immediately before `verify_signature`, failing closed with `AxiamError::Certificate` otherwise
- Added `mtls_rejects_revoked_issuing_ca` — proves a genuinely-signed leaf cert is rejected once its issuing CA is revoked via the repository's own `revoke()` method
- Added `mtls_rejects_expired_issuing_ca` — proves a genuinely-signed leaf cert is rejected once its issuing CA's `not_after` has passed (backdated via a documented test-only SurrealDB UPDATE escape hatch)
- Manually verified fail-before/pass-after discipline for both new tests: reverted `mtls.rs` to the pre-Task-1 version and confirmed both tests failed, then restored the gate and confirmed both pass alongside the 3 pre-existing chain tests (5/5 green)

## Task Commits

Each task was committed atomically:

1. **Task 1: Insert the issuing-CA status + validity gate before verify_signature** - `2d2490e` (feat)
2. **Task 2: Add revoked-CA and expired-CA negative integration tests** - `653d8a8` (test)

**Plan metadata:** (this commit, below)

## Files Created/Modified
- `crates/axiam-pki/src/mtls.rs` - Added the issuing-CA `status == Active` + validity-window gate immediately before `verify_signature`
- `crates/axiam-pki/tests/mtls_chain_test.rs` - Added `mtls_rejects_revoked_issuing_ca` and `mtls_rejects_expired_issuing_ca`, plus a `CaCertificateRepository` trait import needed for the `.revoke()` call

## Decisions Made
- Mirrored the leaf-cert check's exact comparison direction, error style (`AxiamError::Certificate`), and clock source (`Utc::now()`) for the issuer gate — no new pattern
- Used the repo's real `revoke()` method for the revoked-CA test (no need for a raw DB escape hatch there); used a direct SurrealDB `UPDATE` only for backdating `not_after` in the expired-CA test, since no production API sets an arbitrary validity window — clearly commented as test-only
- Kept the full chain-walk (intermediates/root) out of scope per D-02; this residual gap is tracked as the low-severity, accepted threat T-25-09 in the plan's threat register

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- The initial test-file addition didn't import `CaCertificateRepository` into scope, so `ca_repo.revoke(...)` failed to resolve (trait method not in scope) — fixed by adding the import alongside the existing `CertificateRepository`/`ServiceAccountRepository` imports. Caught immediately by the fail-before verification pass; no separate commit needed since it was folded into Task 2's single commit.
- `cargo fmt -p axiam-pki` reformatted two multi-line `.authenticate(...).await` chains in the new tests to match project style; applied before verification and folded into the same Task 2 commit.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SECHRD-05 fully closed with both required negative tests green; `cargo clippy -p axiam-pki --lib -- -D warnings` and `--tests -- -D warnings` both clean; `cargo fmt -p axiam-pki -- --check` clean
- No blockers for subsequent Phase 25 plans (05-10) or later phases; T-25-09 (full chain-walk) remains an accepted, documented residual gap for future revisit only if intermediate CAs are introduced

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*

## Self-Check: PASSED

- FOUND: crates/axiam-pki/src/mtls.rs
- FOUND: crates/axiam-pki/tests/mtls_chain_test.rs
- FOUND: .planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-03-SUMMARY.md
- FOUND commit: 2d2490e
- FOUND commit: 653d8a8
- FOUND commit: 07956bb
