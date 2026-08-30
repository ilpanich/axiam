---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 09
subsystem: database
tags: [serde, security, federation, pki, surrealdb, redaction]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: existing skip_serializing convention on CaCertificate.encrypted_private_key (certificate.rs)
provides:
  - "FederationConfig secret fields (client_secret, client_secret_ciphertext, client_secret_nonce, client_secret_key_version) never serialize"
  - "Manual redacting Debug impls on FederationConfig, CaCertificate, GeneratedCaCertificate"
  - "Narrowed federation_config::list() SurrealQL projection excluding encrypted columns"
  - "federation_config_secret_not_serialized negative test (SC #4b)"
affects: [axiam-api-rest federation handlers, axiam-db federation_config repository]

# Tech tracking
tech-stack:
  added: []
  patterns: [manual redacting Debug impl (mirrors existing skip_serializing convention), narrowed list-view SELECT excluding encrypted columns]

key-files:
  created: []
  modified:
    - crates/axiam-core/src/models/federation.rs
    - crates/axiam-core/src/models/certificate.rs
    - crates/axiam-db/src/repository/federation_config.rs

key-decisions:
  - "Manual Debug impls print '[REDACTED]' in place of raw secret/key bytes rather than omitting the field entirely, keeping struct field order legible in logs"
  - "New FederationConfigListRow struct (not reuse of FederationConfigRowWithId) for list() — keeps the narrowed projection type-safe rather than defaulting unselected columns to None at runtime"
  - "list() populates client_secret as String::new() and the three encrypted-secret fields as None on the returned FederationConfig — list callers never had a legitimate use for ciphertext/nonce/key_version, matching get_by_id as the only legitimate decrypt-at-use path"

patterns-established:
  - "Manual Debug impl pattern for secret-bearing models: derive(Clone, Serialize, Deserialize) without Debug, then impl std::fmt::Debug manually redacting sensitive fields to '[REDACTED]'"

requirements-completed: [SECHRD-09]

coverage:
  - id: D1
    description: "FederationConfig's 4 secret fields never serialize via serde_json::to_string, and Debug/{:?} redacts them"
    requirement: "SECHRD-09"
    verification:
      - kind: unit
        ref: "crates/axiam-core/src/models/federation.rs#tests::federation_config_secret_not_serialized"
        status: pass
    human_judgment: false
  - id: D2
    description: "CaCertificate and GeneratedCaCertificate Debug impls redact encrypted_private_key / private_key_pem instead of printing raw key bytes"
    requirement: "SECHRD-09"
    verification:
      - kind: unit
        ref: "crates/axiam-core/src/models/federation.rs#tests::ca_certificate_debug_redacts_private_key"
        status: pass
    human_judgment: false
  - id: D3
    description: "federation_config::list() no longer selects client_secret/client_secret_ciphertext/client_secret_nonce/client_secret_key_version columns"
    requirement: "SECHRD-09"
    verification:
      - kind: unit
        ref: "cargo clippy -p axiam-db --lib -- -D warnings (compiles clean against narrowed FederationConfigListRow projection)"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 09: Federation/PKI Secret-Leak Closure Summary

**Closed the federation/PKI secret-leak class at the type level: `FederationConfig`'s 4 secret fields now `skip_serializing`, both `FederationConfig` and `CaCertificate`/`GeneratedCaCertificate` got manual redacting `Debug` impls, and `federation_config::list()` no longer hydrates encrypted secret columns per row.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-04
- **Tasks:** 2/2
- **Files modified:** 3

## Accomplishments

- `FederationConfig`'s `client_secret`, `client_secret_ciphertext`, `client_secret_nonce`, and `client_secret_key_version` are now `#[serde(skip_serializing)]`, matching the existing `certificate.rs` convention — `serde_json::to_string(&config)` no longer includes any of the four fields.
- Replaced `derive(Debug)` on `FederationConfig`, `CaCertificate`, and `GeneratedCaCertificate` with manual `impl std::fmt::Debug` that redacts secret/private-key material to `"[REDACTED]"` while keeping all other fields human-readable — closes the residual leak that `skip_serializing` alone (Serialize-only) could not (PATTERNS.md-flagged gap).
- `federation_config::list()`'s SurrealQL query narrowed from `SELECT *` to an explicit field list omitting the four secret columns, via a new `FederationConfigListRow` struct — list views populate `client_secret`/`client_secret_ciphertext`/`client_secret_nonce`/`client_secret_key_version` as empty/`None` placeholders on the returned `FederationConfig`; `get_by_id` remains the only legitimate decrypt-at-use path and is unchanged.
- Added `federation_config_secret_not_serialized` unit test proving neither `serde_json::to_string(&config)` nor `format!("{:?}", config)` contain the plaintext secret, encrypted ciphertext, or nonce (SC #4b).
- Added companion `ca_certificate_debug_redacts_private_key` assertion proving `CaCertificate`'s Debug output redacts `encrypted_private_key` bytes.

## Task Commits

1. **Task 1: skip_serializing + redacting Debug on FederationConfig and CaCertificate/GeneratedCaCertificate** - `541ee1d` (fix)
2. **Task 2: Narrow federation_config list() projection + secret non-serialization negative test** - `9ab6e92` (fix)

**Plan metadata:** (this commit, following SUMMARY.md write)

## Files Created/Modified

- `crates/axiam-core/src/models/federation.rs` — `#[serde(skip_serializing)]` on 4 secret fields, manual redacting `Debug` impl, new test module with `federation_config_secret_not_serialized` and `ca_certificate_debug_redacts_private_key`
- `crates/axiam-core/src/models/certificate.rs` — manual redacting `Debug` impls for `CaCertificate` (redacts `encrypted_private_key`) and `GeneratedCaCertificate` (redacts `private_key_pem`, delegates nested `certificate` field to `CaCertificate`'s own `Debug`)
- `crates/axiam-db/src/repository/federation_config.rs` — new `FederationConfigListRow` struct + narrowed `list()` SurrealQL projection excluding the 4 encrypted secret columns

## Decisions Made

- Manual `Debug` impls print `"[REDACTED]"` in place of raw secret/key bytes (rather than omitting the field) to keep struct field order and log/trace readability intact for non-secret fields.
- Introduced a dedicated `FederationConfigListRow` type for `list()` rather than reusing `FederationConfigRowWithId` with unselected columns defaulting at runtime — keeps the narrowed projection compiler-enforced.
- `list()`'s returned `FederationConfig` instances carry `client_secret: String::new()` and `None` for the three encrypted-secret fields; no caller in the codebase currently relies on those fields being populated from `list()` (confirmed via grep of `axiam-api-rest` handlers).

## Deviations from Plan

None — plan executed exactly as written. Both tasks matched their `<action>` and `<acceptance_criteria>` blocks with no architectural changes, blocking issues, or scope expansion.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SECHRD-09 fully closed: federation/PKI secrets never serialize or Debug-print, and list views no longer hydrate encrypted columns.
- `cargo test -p axiam-core --lib` (60/60 passing), `cargo clippy -p axiam-core --lib -- -D warnings` and `cargo clippy -p axiam-db --lib -- -D warnings` both clean, `cargo fmt --check` clean for both crates.
- No blockers for subsequent Phase 25 plans.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*

## Self-Check: PASSED

All modified files verified present on disk; all task/summary commit hashes (541ee1d, 9ab6e92, 3d0038e) verified present in git log.
