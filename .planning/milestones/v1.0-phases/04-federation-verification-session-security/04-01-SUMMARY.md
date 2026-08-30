---
phase: 04-federation-verification-session-security
plan: "01"
subsystem: auth
tags: [crypto, jwt, schema, federation, session]
dependency_graph:
  requires: []
  provides:
    - axiam_auth::crypto (aes256gcm_encrypt/decrypt, encrypt_separate/decrypt_separate)
    - AuthConfig.federation_encryption_key
    - AuthConfig.allow_missing_aud_as_user
    - AccessTokenClaims.aud (AUD_USER / AUD_M2M)
    - jti = session.id at issuance
    - federation_config schema with 5 new columns
    - saml_assertion_replay table
    - federation_login_state table
    - FederationConfig domain model with 5 new optional fields
  affects:
    - all callers of issue_access_token (25 files updated)
    - axiam-oauth2 token service
    - axiam-api-rest handlers and tests
tech_stack:
  added: []
  patterns:
    - "crypto module centralizes AES-256-GCM with bundled + split-output variants"
    - "jti=session.id enables stateless session revocation (D-15)"
    - "aud claim introduced with back-compat window (allow_missing_aud_as_user)"
key_files:
  created:
    - crates/axiam-auth/src/crypto.rs
  modified:
    - crates/axiam-auth/src/totp.rs
    - crates/axiam-auth/src/lib.rs
    - crates/axiam-auth/src/config.rs
    - crates/axiam-auth/src/token.rs
    - crates/axiam-auth/src/service.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-db/src/schema.rs
    - crates/axiam-core/src/models/federation.rs
    - crates/axiam-db/src/repository/federation_config.rs
    - crates/axiam-oauth2/src/token.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - "25 test files (signature update for issue_access_token)"
decisions:
  - "SurrealValue derive does not support #[serde(default)] — removed; DB schema DEFAULT [] handles empty arrays"
  - "issue_access_token gains explicit jti+aud params (not defaulted) so call sites are forced to be intentional"
  - "OAuth2 auth-code and refresh flows use random jti (no session row); session-based flows pass session.id"
metrics:
  duration: "~45m"
  completed: "2026-05-29T08:40:01Z"
  tasks: 3
  files_modified: 35
---

# Phase 04 Plan 01: Foundation — Crypto, JWT aud/jti, Schema Migration Summary

Removed the four structural blockers identified in 04-RESEARCH.md before any verifier or
password-change handler is written: domain-neutral AES-256-GCM helpers, aud claim on
access tokens, jti=session.id, and schema migration for federation tables.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Extract AES-256-GCM helpers; add federation key + aud backcompat config | 77bc530 | crypto.rs, config.rs, main.rs, totp.rs |
| 2 | jti=session.id + aud claim on AccessTokenClaims; update all call sites | e7bd137 | token.rs, service.rs, 23 test files |
| 3 | Schema migration — federation_config 5 cols, 2 new tables, FederationConfig model | d36193b | schema.rs, federation.rs, federation_config.rs |

## What Was Built

### Task 1 — axiam-auth::crypto module

Created `crates/axiam-auth/src/crypto.rs` with four public functions:

- `aes256gcm_encrypt` / `aes256gcm_decrypt` — bundled format (`nonce||ct+tag` in one base64 string). Used by TOTP; wire format unchanged.
- `encrypt_separate` / `decrypt_separate` — split-output format (nonce and ciphertext+tag in separate base64 strings). Required by D-11 for `federation_config` column storage.

Both variants share a private `build_cipher` helper. Four unit tests verify: bundled round-trip, split round-trip, wrong-nonce failure, format incompatibility.

`totp.rs` `encrypt_secret`/`decrypt_secret` now delegate to the bundled variant (1-line wrappers). Existing TOTP-encrypted secrets in the DB remain decryptable.

`AuthConfig` gains:
- `federation_encryption_key: Option<[u8; 32]>` (`#[serde(skip)]`)
- `allow_missing_aud_as_user: bool` (default `true`)

`main.rs` loads `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` from env at startup (warn on absence, never panic — federation is optional).

### Task 2 — JWT aud claim + jti=session.id

`AccessTokenClaims` gains `aud: Option<String>`. New constants `AUD_USER = "axiam:user"` and `AUD_M2M = "axiam:m2m"`.

`issue_access_token` accepts explicit `jti: String` and `aud: &str` params. The `session.id` UUID is now the JWT `jti` for user-facing tokens — enables D-15 `revoke_all_sessions_except` without a DB lookup.

`decode_access_token` now sets `set_audience([AUD_USER, AUD_M2M])` and `leeway = 60`. The `aud` claim is not required (back-compat for pre-Phase-4 tokens).

All 25 call sites updated: `service.rs` (create_session + refresh), `axiam-oauth2` token service, `axiam-api-rest` device-auth handler, and all integration test helpers.

### Task 3 — Schema migration

`federation_config` schema extended with 5 `IF NOT EXISTS` columns:
- `allowed_algorithms: array<string> DEFAULT []`
- `idp_signing_cert_pem: option<string>`
- `client_secret_ciphertext: option<string>`
- `client_secret_nonce: option<string>`
- `client_secret_key_version: option<int>`

Two new tables added:
- `saml_assertion_replay` — UNIQUE index on `(tenant_id, assertion_id)`, expires_at index for sweep (D-09)
- `federation_login_state` — UNIQUE index on `state`, expires_at index for sweep (D-24)

`FederationConfig` domain model and DB row structs updated to carry all 5 new fields.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] test_config() in token.rs missing new AuthConfig fields**
- **Found during:** Task 1 verification
- **Issue:** Adding `federation_encryption_key` and `allow_missing_aud_as_user` to `AuthConfig` broke the struct literal in `token.rs` test helper.
- **Fix:** Added both new fields to `test_config()` in token.rs.
- **Files modified:** `crates/axiam-auth/src/token.rs`
- **Commit:** 77bc530

**2. [Rule 1 - Bug] SurrealValue derive does not support #[serde(default)]**
- **Found during:** Task 3 verification
- **Issue:** `#[serde(default)]` on `allowed_algorithms: Vec<String>` in DB row structs produced a compile error — SurrealValue derive doesn't support serde attributes.
- **Fix:** Removed `#[serde(default)]` from both row structs and the domain model. The SurrealDB schema uses `DEFAULT []` so all rows have a value.
- **Files modified:** `crates/axiam-db/src/repository/federation_config.rs`, `crates/axiam-core/src/models/federation.rs`
- **Commit:** d36193b

**3. [Rule 3 - Blocking] 25 call sites of issue_access_token needed updating**
- **Found during:** Task 2
- **Issue:** Signature change propagated to axiam-oauth2, axiam-api-rest handlers, and all integration test helpers (25 files).
- **Fix:** Updated all call sites; OAuth2 flows and device-auth use `Uuid::new_v4().to_string()` as jti (no session row).
- **Commit:** e7bd137

### Pre-existing Semgrep Finding (not introduced by this plan)

The semgrep `post-tool-cli-scan` hook fires on every edit to files containing a pre-committed Ed25519 test key fixture (present in the base commit `9389850`). This is a `#[cfg(test)]`-only key used exclusively for unit test JWT signing. It was not added by this plan.

## Threat Surface Scan

No new network endpoints, auth paths, or trust boundaries introduced by this plan. The threat register items T-04-01..T-04-06 are addressed:
- T-04-02: `client_secret_key_version` column added; federation key logged as "loaded" (never value)
- T-04-03: `.expect()` messages reference length only, not the key value
- T-04-05: `allow_missing_aud_as_user` config knob in place

## Self-Check: PASSED

Files created/modified verified present:
- `crates/axiam-auth/src/crypto.rs` — exists
- `crates/axiam-auth/src/config.rs` — federation_encryption_key present
- `crates/axiam-auth/src/token.rs` — AUD_USER/AUD_M2M/aud field present
- `crates/axiam-db/src/schema.rs` — all 5 DEFINE FIELD IF NOT EXISTS present
- `crates/axiam-core/src/models/federation.rs` — 5 new fields present

Commits verified:
- 77bc530 (Task 1)
- e7bd137 (Task 2)
- d36193b (Task 3)

All acceptance criteria met per plan spec.
