---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 07
subsystem: infra
tags: [amqp, hmac, hkdf, rustcrypto, rabbitmq, multi-tenant, fail-closed]

# Dependency graph
requires:
  - phase: 23-security-regressions-high-findings
    provides: "AxiamError::ServiceUnavailable (503) precedent for a missing operator-provided key"
provides:
  - "Mandatory, per-tenant HKDF-derived AMQP message signing for AuthzRequest + AuditEventMessage"
  - "derive_tenant_key/verify_tenant_signature shared verification path used by both consumers"
  - "AmqpConfig::resolve_signing_key() fail-closed-in-production key resolution"
affects: [25-08, sechrd-audit, amqp-signing]

# Tech tracking
tech-stack:
  added: ["hkdf 0.12.4"]
  patterns:
    - "HKDF-SHA256 per-tenant subkey derivation with domain-separated + versioned info parameter (D-05a/b)"
    - "Debug-build-only dev-key fallback + release-build fail-closed via cfg!(debug_assertions), mirroring the actual `cargo build --release` production image build"

key-files:
  created: []
  modified:
    - crates/axiam-amqp/src/messages.rs
    - crates/axiam-amqp/src/config.rs
    - crates/axiam-amqp/src/audit_consumer.rs
    - crates/axiam-amqp/src/authz_consumer.rs
    - crates/axiam-server/src/main.rs
    - Cargo.toml
    - crates/axiam-amqp/Cargo.toml
    - Cargo.lock

key-decisions:
  - "Pinned hkdf = \"0.12\" instead of the plan-cited 0.13.0 — 0.13 pulls in hmac 0.13/digest 0.11, which conflicts with the workspace's existing hmac 0.12/sha2 0.10 (digest 0.10) pins. hkdf 0.12.4 is the same RustCrypto crate with an identical Hkdf::<Sha256>::new/expand API and resolves cleanly against the existing pins — no legitimacy concern, pure version-compatibility fix (Rule 3)."
  - "Used cfg!(debug_assertions) as the production-flagged signal for AmqpConfig::resolve_signing_key(), since the codebase has no existing environment/production-flag config surface and docker/Dockerfile.server builds the shipped production binary with `cargo build --release` (debug_assertions=false there)."
  - "Extracted the fail-closed verify logic into a single shared messages::verify_tenant_signature() helper used by both consumers, removing the previously-duplicated fail-open branch from each (per 25-PATTERNS.md's identified anti-pattern)."

patterns-established:
  - "AMQP master key -> per-tenant subkey: derive_tenant_key(master, tenant_id, key_version) via hkdf::Hkdf::<Sha256>, never hand-rolled concatenation hashing."

requirements-completed: [SECHRD-08]

coverage:
  - id: D1
    description: "derive_tenant_key(master, tenant_id, key_version) implemented with HKDF-SHA256, domain-separated + versioned info; a tenant-A signature cannot validate under tenant-B's derived subkey"
    requirement: "SECHRD-08"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/src/messages.rs#per_tenant_signature_cross_tenant_rejected"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/messages.rs#derive_tenant_key_is_deterministic_and_versioned"
        status: pass
    human_judgment: false
  - id: D2
    description: "Both audit_consumer.rs and authz_consumer.rs reject unsigned and invalid-signature messages; no warn-and-process fail-open branch remains"
    requirement: "SECHRD-08"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/src/messages.rs#verify_tenant_signature_rejects_unsigned_message"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/messages.rs#verify_tenant_signature_rejects_tampered_payload"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/messages.rs#verify_tenant_signature_rejects_invalid_hex_signature"
        status: pass
    human_judgment: false
  - id: D3
    description: "AmqpConfig resolves the signing key to a mandatory Vec<u8>: valid hex decodes, invalid hex fails closed, unset falls back to a documented dev-only key in debug builds and fails closed (ServiceUnavailable) in release builds"
    requirement: "SECHRD-08"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/src/config.rs#resolve_signing_key_decodes_configured_hex"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/config.rs#resolve_signing_key_rejects_invalid_hex"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/config.rs#resolve_signing_key_falls_back_to_dev_default_when_unset_in_debug_build"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 07: AMQP Mandatory Per-Tenant Signing Summary

**HKDF-SHA256 per-tenant AMQP subkey derivation (`derive_tenant_key`) makes signing mandatory and fail-closed for `AuthzRequest`/`AuditEventMessage`, replacing both consumers' warn-and-process fail-open branches.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-04T17:29:01Z
- **Completed:** 2026-07-04T17:48:23Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- `derive_tenant_key(master, tenant_id, key_version) -> [u8; 32]` in `messages.rs` using `hkdf::Hkdf<Sha256>` with a fixed app salt and a domain-separated + versioned `info` (`b"axiam-amqp-v1" || key_version || tenant_id`) — a tenant-A signature can never validate under tenant-B's derived subkey, even from the same master key (T-25-19).
- `key_version: u8` added to `AuthzRequest` and `AuditEventMessage` envelopes (default `1`), making the master key rotation-ready per D-05b.
- `verify_tenant_signature()` shared helper: derives the subkey and verifies; returns `false` for both an absent signature and an invalid one — no accept-when-unsigned branch exists anywhere in the call path (T-25-20).
- `AmqpConfig::resolve_signing_key()`: hex-decodes a configured key (fails closed on malformed hex); when unset, falls back to a documented dev-only default **only** in debug builds; in a release build (the actual production container image, built with `cargo build --release`) it returns `AxiamError::ServiceUnavailable` — signing is mandatory in production with zero unsigned code path (D-05c).
- Both `audit_consumer.rs` and `authz_consumer.rs` now take a mandatory `Vec<u8>` master key (not `Option<Vec<u8>>`), removed their `else { warn!(unsigned) }` fail-open branch and the warn-but-still-process branch on invalid signatures — unsigned/invalid ⇒ nack-without-requeue, never processed.
- `crates/axiam-server/src/main.rs` wired to `AmqpConfig::resolve_signing_key()` (deviation — see below) so the server actually fails closed at startup rather than silently accepting unsigned messages.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add hkdf; implement derive_tenant_key (domain-separated + versioned) in messages.rs** - `974ec70` (feat)
2. **Task 2: Make the signing key mandatory (dev default) and remove both consumer fail-open branches** - `0b30407` (fix)

_Note: Task 2's commit also includes the necessary `main.rs` wiring deviation (see below) since it was required for the consumer signature change to compile._

## Files Created/Modified
- `Cargo.toml` - added `hkdf = "0.12"` to `[workspace.dependencies]`
- `crates/axiam-amqp/Cargo.toml` - added `hkdf = { workspace = true }`
- `crates/axiam-amqp/src/messages.rs` - `derive_tenant_key`, `verify_tenant_signature`, `key_version` field on both message envelopes, negative tests
- `crates/axiam-amqp/src/config.rs` - `AmqpConfig::resolve_signing_key()`, dev-default constant, removed "migration mode" doc comment
- `crates/axiam-amqp/src/audit_consumer.rs` - mandatory `Vec<u8>` key param, fail-open branch removed
- `crates/axiam-amqp/src/authz_consumer.rs` - mandatory `Vec<u8>` key param, fail-open branch removed
- `crates/axiam-server/src/main.rs` - wired `resolve_signing_key()` to both consumer spawns (deviation)
- `Cargo.lock` - updated for the new `hkdf` dependency

## Decisions Made
- Pinned `hkdf = "0.12"` (not the plan-cited `0.13.0`) — `hkdf 0.13` depends on `hmac 0.13`/`digest 0.11`, which conflicts with the workspace's existing `hmac = "0.12"` / `sha2 = "0.10"` (`digest 0.10`) pins; the build failed with a `HashMarker`/`EagerHash` trait-bound mismatch across two `digest` crate versions. `hkdf 0.12.4` is the same audited RustCrypto crate with an identical `Hkdf::<Sha256>::new(...).expand(...)` API and resolves cleanly. No package-legitimacy concern — this is a version-compatibility fix within an already-verified crate family (Rule 3), not a new/different package.
- Used `cfg!(debug_assertions)` as the "production-flagged" signal for `resolve_signing_key()`. The codebase has no existing environment/production config flag; `docker/Dockerfile.server` builds the shipped production binary with `cargo build --release` (`debug_assertions == false` there), so this heuristic accurately gates the dev-key fallback to non-production builds without inventing new config surface.
- Extracted the previously-duplicated fail-open verify logic (identical in both consumers per 25-PATTERNS.md) into a single `messages::verify_tenant_signature()` helper, reducing duplication and making the fail-closed contract independently unit-testable without a live broker.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pinned `hkdf = "0.12"` instead of the plan's `"0.13"`**
- **Found during:** Task 1
- **Issue:** `hkdf 0.13.0` (cited in 25-RESEARCH.md as VERIFIED OK) requires `hmac 0.13`/`digest 0.11`; the workspace's existing `hmac = "0.12"` and `sha2 = "0.10"` pins resolve to `digest 0.10`, producing two incompatible `digest` crate versions in the dependency graph and a `HashMarker`/`EagerHash` compile error.
- **Fix:** Verified `hkdf 0.12.4` (same crate, RustCrypto, already legitimacy-audited family) depends on `hmac 0.12.1` — compatible with the existing pins — and has an identical public API. Repinned to `hkdf = "0.12"` in the workspace `Cargo.toml`.
- **Files modified:** `Cargo.toml`, `Cargo.lock`
- **Verification:** `cargo test -p axiam-amqp --lib` and `cargo clippy -p axiam-amqp --lib -- -D warnings` both clean after the repin.
- **Committed in:** `974ec70` (Task 1 commit)

**2. [Rule 3 - Blocking] Wired `crates/axiam-server/src/main.rs` to the new mandatory-key consumer signatures**
- **Found during:** Task 2
- **Issue:** The plan's `files_modified` list did not include `main.rs`, but changing `start_audit_consumer`/`start_authz_consumer` to require `Vec<u8>` (not `Option<Vec<u8>>`) is a breaking signature change; `main.rs` is the only caller and previously built the key via inline `hex::decode`-into-`Option` logic with its own warn-and-continue behavior. Leaving it unmodified would break the `axiam-server` build and silently regress the fail-closed guarantee at the one real call site.
- **Fix:** Replaced the inline decode/warn logic in `main.rs` with a call to `config.amqp.resolve_signing_key()`, `.expect(...)`-ing on failure (main() has no `AxiamError`-compatible return path; a resolution failure is a startup-fatal misconfiguration, consistent with other mandatory-key patterns in `main.rs`, e.g. `load_key_from_env`'s panic-on-malformed-key).
- **Files modified:** `crates/axiam-server/src/main.rs`
- **Verification:** `cargo build -p axiam-server` (with `SWAGGER_UI_DOWNLOAD_URL` workaround set, since `axiam-server` depends on `axiam-api-rest`) succeeds.
- **Committed in:** `0b30407` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 3 — blocking issues)
**Impact on plan:** Both fixes were necessary for the plan's own must-haves to compile and actually take effect at the real call site. No scope creep — mail signing was not touched, and no architectural change was made.

## Issues Encountered
None beyond the two blocking issues documented above.

## User Setup Required
None - no external service configuration required. Operators deploying to production MUST set `AXIAM__AMQP__SIGNING_KEY` (hex-encoded) — the release binary now fails closed at startup if it is unset, per D-05c.

## Next Phase Readiness
- SECHRD-08's AMQP signing portion (per-tenant HKDF keying + mandatory fail-closed config + fail-closed consumers) is fully closed with passing negative tests.
- The other SECHRD-08 sub-items (ExportReady `org_id` resolution, mail-retry backoff — D-05d) are explicitly out of scope for this plan per its `files_modified` list and are tracked for plan 25-08.
- `cargo clean` run after this plan per CLAUDE.md build-hygiene guidance (freed ~9.4GiB); disk at 15G used / 23G free before the next plan's build.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*
