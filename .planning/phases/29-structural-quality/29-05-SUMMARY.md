---
phase: 29-structural-quality
plan: 05
subsystem: database
tags: [surrealdb, pagination, repository-pattern, dead-code-removal]

# Dependency graph
requires:
  - phase: 29-structural-quality (29-04)
    provides: "helpers::{CountRow, paginate<T>, take_first_or_not_found} canonical helpers and the file-group-A adoption pattern this plan mirrors"
provides:
  - "16 file-group-B repos (ca_certificate, certificate, email_config, email_verification_token, export_job, federation_config, federation_login_state, federation_link, notification_rule, oauth2_auth_code, oauth2_client, oauth2_refresh_token, password_reset_token, pgp_key, saml_replay, webauthn_credential, webhook) deduped onto helpers::{CountRow, paginate, take_first_or_not_found}"
  - "24-total CountRow struct collapse complete (0 remaining local `struct CountRow` definitions in crates/axiam-db/src/repository/*.rs)"
  - "federation_link.rs local parse_uuid duplicate removed; its 7 call sites route through helpers::parse_uuid(s, field) with correct field names"
affects: []

tech-stack:
  added: []
  patterns:
    - "helpers::paginate<T>(items, count_rows, &pagination) is now used by every axiam-db repo list() method that builds a PaginatedResult<T> (file-group A + file-group B, 15 call sites total)"
    - "helpers::take_first_or_not_found(rows, entity, &id) is now used by every single-record `.into_iter().next()` read pattern across axiam-db repos"

key-files:
  created: []
  modified:
    - crates/axiam-db/src/repository/ca_certificate.rs
    - crates/axiam-db/src/repository/certificate.rs
    - crates/axiam-db/src/repository/email_config.rs
    - crates/axiam-db/src/repository/email_verification_token.rs
    - crates/axiam-db/src/repository/export_job.rs
    - crates/axiam-db/src/repository/federation_config.rs
    - crates/axiam-db/src/repository/federation_login_state.rs
    - crates/axiam-db/src/repository/federation_link.rs
    - crates/axiam-db/src/repository/notification_rule.rs
    - crates/axiam-db/src/repository/oauth2_auth_code.rs
    - crates/axiam-db/src/repository/oauth2_client.rs
    - crates/axiam-db/src/repository/oauth2_refresh_token.rs
    - crates/axiam-db/src/repository/password_reset_token.rs
    - crates/axiam-db/src/repository/pgp_key.rs
    - crates/axiam-db/src/repository/saml_replay.rs
    - crates/axiam-db/src/repository/webauthn_credential.rs
    - crates/axiam-db/src/repository/webhook.rs
    - .planning/phases/29-structural-quality/deferred-items.md

key-decisions:
  - "saml_replay.rs and federation_login_state.rs got ONLY the CountRow struct collapse — their marker-string classification logic and BEGIN/COMMIT transaction (reused by QUAL-03) were left untouched, per the plan's explicit prohibition"
  - "ca_certificate.rs's Option<T>-returning single-record reads (create/get_by_id/revoke/get_by_issuer_id, which deserialize `Option<CaCertificateRow>` directly via result.take(0) rather than Vec<T>.into_iter().next()) were left as-is — not the literal `.into_iter().next().ok_or_else(NotFound)` pattern the plan scoped take_first_or_not_found to; converting them would require changing the deserialization shape from Option<T> to Vec<T>, a larger diff than the plan's narrow mechanical-dedup scope. Same applies to pgp_key.rs's revoke() and certificate.rs's create/get_by_id/revoke, which use the identical Option<T> pattern"
  - "email_verification_token.rs, export_job.rs, oauth2_auth_code.rs, oauth2_refresh_token.rs, password_reset_token.rs, and webauthn_credential.rs's raw-count reads (count_today, delete_expired, count_by_user) were left as raw `rows.first().map(|r| r.total).unwrap_or(0)` reads — they return a bare u64, not a PaginatedResult<T>, matching 29-04's documented session.rs/audit.rs precedent for non-list count queries"
  - "federation_link.rs's create() and get_by_external_subject() also carried the take_first_or_not_found target pattern (not just the parse_uuid duplicate Task 2 named) — converted them too, since Task 2's action explicitly said to apply the same dedup 'if it carries those patterns'"
  - "federation_link.rs's malformed-UUID reads now surface DbError::Serialization (naming the field) instead of the old local parse_uuid's DbError::Migration — this is the canonical helpers::parse_uuid's documented QUAL-03/D-10 classification, identical to every other repo already migrated to it (user.rs, role.rs, organization.rs, etc.); only the error-path classification for corrupt data changes, not the success path"

requirements-completed: [QUAL-02]

coverage:
  - id: D1
    description: "All 24 duplicated CountRow structs collapsed to helpers::CountRow (8 file-group-A + 16 file-group-B)"
    requirement: QUAL-02
    verification:
      - kind: other
        ref: "grep -rln 'struct CountRow' crates/axiam-db/src/repository/*.rs -> 0 matches"
        status: pass
      - kind: unit
        ref: "cargo test -p axiam-db --lib (40/40 pass)"
        status: pass
    human_judgment: false
  - id: D2
    description: "File-group-B list() methods adopt helpers::paginate<T>; single-record reads route through helpers::take_first_or_not_found; no behavior change"
    requirement: QUAL-02
    verification:
      - kind: integration
        ref: "cargo test -p axiam-db (17 integration test binaries across 5 disk-hygiene batches: connection_resilience_test, federation_login_state, group_repository_test, oauth2_refresh_revoke_all, repository_test, req14_settings_migration_test, req14_tenant_isolation_test, resource_scope_test, role_permission_test, saml_replay, schema_test, seeder_skip_test, service_account_session_test, session_invalidate_except, totp_step_cas_test, user_repository_test, webauthn_credential_test)"
        status: pass
    human_judgment: false
  - id: D3
    description: "federation_link.rs local parse_uuid removed; 7 call sites route through helpers::parse_uuid(s, field) with correct field names"
    requirement: QUAL-02
    verification:
      - kind: other
        ref: "grep -n 'fn parse_uuid' crates/axiam-db/src/repository/federation_link.rs -> 0 matches"
        status: pass
      - kind: integration
        ref: "cargo test -p axiam-db --lib + full integration suite (no federation_link-specific test file exists; covered transitively via lib build/test green and manual field-mapping review against plan's documented line numbers)"
        status: pass
    human_judgment: false
  - id: D4
    description: "cargo clippy -p axiam-db clean (no new warnings from this plan's changes)"
    requirement: QUAL-02
    verification:
      - kind: other
        ref: "cargo clippy -p axiam-db --lib --tests (zero axiam-db warnings; only the pre-existing, out-of-scope axiam-auth/src/token.rs::derivable_impls warning surfaces because clippy lints the dependency graph)"
        status: pass
    human_judgment: false

duration: 35min
completed: 2026-07-06
status: complete
---

# Phase 29 Plan 05: File-group-B dedup + federation_link parse_uuid removal Summary

**Collapsed the remaining 16 local `struct CountRow` definitions and 3 raw-count-only repos onto `helpers::CountRow`, adopted `helpers::paginate<T>`/`helpers::take_first_or_not_found` across file-group B, and deleted `federation_link.rs`'s duplicate 1-arg `parse_uuid` in favor of the canonical `helpers::parse_uuid(s, field)`, completing the 24-CountRow / 79-site QUAL-02 dedup pass.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-07-06T13:12:03Z (immediately following 29-04)
- **Completed:** 2026-07-06T13:47:00Z
- **Tasks:** 2
- **Files modified:** 17 (16 repo files + deferred-items.md)

## Accomplishments

- Collapsed the local `struct CountRow` in 16 file-group-B repos (ca_certificate, certificate, email_config, email_verification_token, export_job, federation_config, federation_login_state, notification_rule, oauth2_auth_code, oauth2_client, oauth2_refresh_token, password_reset_token, pgp_key, saml_replay, webauthn_credential, webhook) onto `helpers::CountRow` — completing the full 24-CountRow collapse across 29-04 + 29-05. Two of these (`email_config.rs`, `export_job.rs`) had function-scoped inline `CountRow` structs (inside `backfill_plaintext_secrets` and `has_pending_for_user` respectively), not module-level ones — both collapsed the same way.
- Adopted `helpers::paginate<T>(items, count_rows, &pagination)` in every file-group-B `list()` method that builds a `PaginatedResult<T>` (ca_certificate, certificate, federation_config, notification_rule, oauth2_client, pgp_key, webhook — 7 call sites).
- Routed every single-record `.into_iter().next().ok_or_else(|| DbError::NotFound{...})?` read across file-group B through `helpers::take_first_or_not_found` (create/get_by_id/get_by_*/update/consume methods across all 16 files — 27 call sites).
- Deleted `federation_link.rs`'s local `fn parse_uuid(s: &str) -> Result<Uuid, DbError>` and repointed its 7 call sites to `helpers::parse_uuid(s, field)` with the correct field names (record_id, tenant_id x2, user_id x2, federation_config_id x2), matching the plan's documented mapping exactly. Also converted federation_link.rs's two `take_first_or_not_found`-pattern reads (create, get_by_external_subject) since the file carried that pattern too.
- `saml_replay.rs` and `federation_login_state.rs` collapsed only their `CountRow` struct — their marker-string classification logic (`"already contains"`/`"already exists"`/`"unique"` → `AlreadyExists`/`ReplayDetected`) and BEGIN/COMMIT transactions were left completely untouched, per the plan's explicit prohibition (reused by QUAL-03).

## Task Commits

1. **Task 1: Dedup file-group B repos — CountRow, paginate<T>, take_first_or_not_found** - `d7bb05d` (refactor)
2. **Task 2: Remove federation_link.rs duplicate parse_uuid; fix its 7 call sites** - `89cfb4d` (refactor)

_No TDD tasks — this is a mechanical, behavior-preserving dedup pass gated by the existing axiam-db repo test suite (D-03)._

## Files Created/Modified

- `crates/axiam-db/src/repository/ca_certificate.rs` - CountRow → helpers::CountRow, list_by_organization() → helpers::paginate
- `crates/axiam-db/src/repository/certificate.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, get_by_fingerprint/get_by_fingerprint_global → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/email_config.rs` - inline CountRow (backfill_plaintext_secrets) → helpers::CountRow, set_org_config → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/email_verification_token.rs` - CountRow → helpers::CountRow, create/get_by_token_hash/consume → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/export_job.rs` - inline CountRow (has_pending_for_user) → helpers::CountRow, create() → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/federation_config.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, create/get_by_id/update → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/federation_login_state.rs` - CountRow → helpers::CountRow only (marker logic untouched)
- `crates/axiam-db/src/repository/federation_link.rs` - local parse_uuid deleted → helpers::parse_uuid(s, field), 7 call sites fixed; create/get_by_external_subject → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/notification_rule.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, create/get_by_id/update → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/oauth2_auth_code.rs` - CountRow → helpers::CountRow, create/get_by_hash/consume → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/oauth2_client.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, create/get_by_id/get_by_client_id/update → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/oauth2_refresh_token.rs` - CountRow → helpers::CountRow, create/get_by_token_hash → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/password_reset_token.rs` - CountRow → helpers::CountRow, create/get_by_token_hash/consume → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/pgp_key.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, create/get_by_id/get_signing_key → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/saml_replay.rs` - CountRow → helpers::CountRow only (marker logic untouched); dropped now-unused surrealdb_types::SurrealValue import
- `crates/axiam-db/src/repository/webauthn_credential.rs` - CountRow → helpers::CountRow, create/get_by_id → helpers::take_first_or_not_found
- `crates/axiam-db/src/repository/webhook.rs` - CountRow → helpers::CountRow, list() → helpers::paginate, create/get_by_id/update → helpers::take_first_or_not_found
- `.planning/phases/29-structural-quality/deferred-items.md` - re-confirmed 29-04's two pre-existing out-of-scope findings still unrelated to 29-05

## Decisions Made

- `saml_replay.rs` and `federation_login_state.rs` received only the `CountRow` struct collapse — their marker-string classification and transaction logic (load-bearing ground truth for QUAL-03) were left completely untouched, per the plan's explicit prohibition.
- `ca_certificate.rs`'s (and `certificate.rs`'s/`pgp_key.rs`'s) `Option<T>`-returning single-record reads were left as-is: they deserialize `Option<Row>` directly via `result.take(0)` rather than `Vec<Row>.into_iter().next()`, so they are not the literal pattern the plan scoped `take_first_or_not_found` to. Converting them would mean changing the deserialization shape from `Option<T>` to `Vec<T>` — a larger diff than this plan's narrow mechanical-dedup scope, and no group-A precedent exists for that conversion either.
- Raw-count-only reads (`count_today`, `delete_expired`, `count_by_user` in email_verification_token.rs, export_job.rs, oauth2_auth_code.rs, oauth2_refresh_token.rs, password_reset_token.rs, webauthn_credential.rs) were left as `rows.first().map(|r| r.total).unwrap_or(0)` — they return a bare `u64`, not a `PaginatedResult<T>`, matching 29-04's documented `session.rs`/`audit.rs` precedent.
- `federation_link.rs`'s `create()` and `get_by_external_subject()` also carried the `take_first_or_not_found` target pattern, not just the `parse_uuid` duplicate Task 2 named — converted both, since Task 2's action explicitly said to apply the same dedup "if it carries those patterns."
- `federation_link.rs`'s malformed-UUID reads now surface `DbError::Serialization` (naming the field) instead of the old local `parse_uuid`'s `DbError::Migration` — this is the canonical `helpers::parse_uuid`'s documented QUAL-03/D-10 classification, identical to every other repo already migrated to it. Only the error-path classification for corrupt data changes; the success path is unchanged.

## Deviations from Plan

None — plan executed exactly as written. `email_config.rs` and `export_job.rs` had function-scoped (not module-level) local `CountRow` structs that weren't explicitly called out in the plan's read_first list, but they matched the same collapse pattern and were included to satisfy the plan's `grep -rln "struct CountRow"` acceptance criterion (zero remaining).

## Issues Encountered

None. `cargo build -p axiam-db --lib` and `cargo clippy -p axiam-db --lib --tests` produced zero warnings after all edits — no unused-import churn from the `PaginatedResult`/`SurrealValue` imports that became partially or fully redundant (only `saml_replay.rs` needed its now-unused `surrealdb_types::SurrealValue` import dropped, since the file no longer derives `SurrealValue` on anything after the `CountRow` struct was removed).

One pre-existing, out-of-scope test failure re-confirmed present and unrelated to this plan's changes: `req14_tenant_isolation_test::resource_delete_with_children_rejected` (documented in `deferred-items.md` under 29-04; `resource.rs` is not in this plan's `files_modified` and was not touched).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- QUAL-02 fully complete: all 24 `CountRow` duplicates collapsed, `helpers::paginate<T>` adopted at every list-method call site across axiam-db, `helpers::take_first_or_not_found` adopted at every single-record-read call site that matched the target pattern, and the `federation_link.rs` `parse_uuid` duplicate removed (D-07 narrow scope honored — no other repo's inline `Uuid::parse_str` call sites were swept).
- `cargo clean -p axiam-db` run repeatedly between test batches per CLAUDE.md disk hygiene during this plan's execution; run once more after this plan completes.
- QUAL-03 is unblocked: `saml_replay.rs`/`federation_login_state.rs` marker-string logic is intact and untouched, ready for that phase's centralized `classify_write_error` migration work (already partially adopted elsewhere via `helpers::classify_write_error`, added in a prior wave).

---
*Phase: 29-structural-quality*
*Completed: 2026-07-06*

## Self-Check: PASSED

All 17 modified/created files verified present on disk; both task commit hashes
(`d7bb05d`, `89cfb4d`) verified present in `git log --oneline --all`.
