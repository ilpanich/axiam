---
phase: 28-functional-completeness
plan: 01
subsystem: database
tags: [email, secrets, encryption, surrealdb, axiam-core, axiam-db]

# Dependency graph
requires:
  - phase: 05-email-delivery-gdpr-compliance
    provides: email_config table (Schema v15, ciphertext-only columns), SurrealEmailConfigRepository, EmailConfigRepository trait
provides:
  - "EmailConfig write-only + redacted secrets (SmtpConfig.password, ApiProviderConfig.api_key): #[serde(skip_serializing)] + manual redacting Debug"
  - "Omit-preserve write semantics: empty-string secret on the write path means 'preserve stored ciphertext'; non-empty secret replaces it"
  - "EmailConfigRepository::delete_org_config trait method + SurrealEmailConfigRepository impl (D-13)"
  - "row_to_provider / try_into_domain return AxiamError::EmailConfig(...) on NULL/missing secret ciphertext instead of silently reconstructing an empty secret (D-08)"
  - "backfill_plaintext_secrets documented and tested as an intentional no-op (D-07), with a fixed provider_kind typo bug in its detection query"
affects: [28-04 (admin email-config API handlers — the Wave-2 consumer of this model/repository layer)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Sentinel-empty write-path secret representation: keep SmtpConfig.password/ApiProviderConfig.api_key as concrete String everywhere (write input AND resolved/stored model); an empty string on the write path means 'omit — preserve stored value', avoiding a parallel Option<String> input DTO and its ripple effect on existing consumers (mail_consumer_test.rs, axiam-email providers)"
    - "row_to_provider/try_into_domain return AxiamError directly (not DbError) so a NULL-ciphertext read surfaces as AxiamError::EmailConfig, matching the crate's existing 'no email config' error family"

key-files:
  created: []
  modified:
    - crates/axiam-core/src/models/email.rs
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/email_config.rs

key-decisions:
  - "D-02-input-shape resolved via sentinel-empty convention (not a separate optional-secret input DTO): SmtpConfig/ApiProviderConfig secrets stay concrete String in SetOrgEmailConfig.provider (still type ProviderConfig); an empty string is the 'omit/preserve' signal. Chosen over an input-specific type because it keeps every existing consumer of ProviderConfig/SmtpConfig/ApiProviderConfig (axiam-amqp's mail_consumer_test.rs, axiam-email's provider constructors) compiling unchanged, and keeps the resolved/stored model exactly as the plan mandated (concrete String, not Option)."
  - "validate_email_config's 'API key must not be empty' check was removed (not narrowed) — an empty api_key is now always a valid 'omit' signal at the structural-validation layer; whether a secret is actually required (e.g. first-time creation with nothing to preserve) is left to the repository/handler layer, not model-level validation. The pre-existing empty_api_key_fails test was renamed to empty_api_key_is_treated_as_omit_and_passes_validation to reflect this intentional behavior change (plan explicitly required it)."
  - "delete_org_config scope-filter: DELETE FROM email_config WHERE scope = 'org' AND scope_id = $scope_id — same shape as the existing delete_tenant_override, just scoped to 'org'."
  - "row_to_provider and EmailConfigRowWithId::try_into_domain changed return type from Result<_, DbError> to Result<_, AxiamError> so the D-08 NULL-ciphertext case can return AxiamError::EmailConfig(\"...no usable credential...\") directly, matching the crate's existing dedicated EmailConfig error variant rather than routing through the generic Database(String) variant."
  - "set_org_config's preserve-on-omit merge only substitutes the *ciphertext/nonce* columns when the incoming secret is empty AND a prior stored secret exists for that field; the in-memory EmailConfig object returned by set_org_config itself is NOT re-decrypted to show the preserved value (it reflects input.provider as given, which may be the empty sentinel) — callers must re-fetch via get_org_config to see the true stored/decrypted secret. This is a low-risk simplification since D-01 forbids surfacing secrets in any response anyway."

patterns-established:
  - "Redacting manual Debug impl for any struct holding a secret intended for serde skip_serializing (mirrors FederationConfig's SECHRD-09 precedent) — print '[REDACTED]' for the secret field, real values for everything else."

requirements-completed: [FUNC-03]

coverage:
  - id: D1
    description: "SmtpConfig/ApiProviderConfig secrets are never serialized (D-01) and never appear in Debug output"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#smtp_config_password_not_serialized"
        status: pass
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#smtp_config_debug_redacts_password"
        status: pass
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#api_provider_config_api_key_not_serialized"
        status: pass
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#api_provider_config_debug_redacts_api_key"
        status: pass
    human_judgment: false
  - id: D2
    description: "A write input that omits the secret deserializes and validates successfully; a stored secret is preserved on omit and replaced on supply (D-02)"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#smtp_config_deserializes_without_password_field"
        status: pass
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#api_provider_config_deserializes_without_api_key_field"
        status: pass
      - kind: unit
        ref: "crates/axiam-core/src/models/email.rs#empty_api_key_is_treated_as_omit_and_passes_validation"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#set_org_config_omitted_secret_preserves_stored_smtp_password"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#set_org_config_supplied_secret_replaces_stored_value"
        status: pass
    human_judgment: false
  - id: D3
    description: "delete_org_config repository method exists and removes the org's email config row (D-13)"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#delete_org_config_removes_row"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#delete_org_config_is_ok_when_nothing_to_delete"
        status: pass
    human_judgment: false
  - id: D4
    description: "A NULL/missing-ciphertext row surfaces a clear AxiamError::EmailConfig at read time instead of a silent empty secret (D-08)"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#read_path_errors_on_null_ciphertext_row"
        status: pass
    human_judgment: false
  - id: D5
    description: "backfill_plaintext_secrets is a documented, tested no-op on the v15+ ciphertext-only schema (D-07)"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#backfill_plaintext_secrets_is_a_noop_on_v15_schema_with_data_present"
        status: pass
      - kind: integration
        ref: "crates/axiam-db/src/repository/email_config.rs#backfill_plaintext_secrets_is_a_noop_on_empty_table"
        status: pass
    human_judgment: false

duration: ~20min
completed: 2026-07-05
status: complete
---

# Phase 28 Plan 01: Email-Config Secret Hygiene & Repository CRUD Foundation Summary

**Email-provider secrets (SMTP password, API keys) are now write-only and redacted end-to-end (D-01), updates preserve an omitted secret via an empty-string sentinel while replacing a supplied one (D-02), org-level email config can now be deleted (D-13), a NULL-ciphertext row errors clearly instead of silently decrypting to an empty secret (D-08), and the plaintext-secret backfill is honestly documented as a no-op with a fixed provider_kind typo bug (D-07).**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-05T18:39:29Z
- **Tasks:** 3 completed
- **Files modified:** 3

## Accomplishments

- `SmtpConfig.password` / `ApiProviderConfig.api_key` are `#[serde(skip_serializing)]` with `#[serde(default)]`, plus manual redacting `Debug` impls (mirrors `FederationConfig`'s SECHRD-09 precedent) — secrets never leak via JSON serialization or `{:?}` logging.
- Write-path omit-preserve semantics: an empty-string secret is the sentinel for "no new secret supplied"; `validate_email_config` no longer rejects it structurally, and `SurrealEmailConfigRepository::set_org_config` preserves the previously-stored ciphertext/nonce instead of encrypting an empty value. Supplying a non-empty secret still encrypts and replaces as before.
- `EmailConfigRepository::delete_org_config(org_id)` added to the trait and implemented, mirroring `delete_tenant_override`'s shape, closing the D-13 org-level DELETE gap.
- `row_to_provider` (and its caller `EmailConfigRowWithId::try_into_domain`) now return `AxiamError` directly and produce a clear `AxiamError::EmailConfig("email config has no usable credential: ... ciphertext/nonce is missing")` when a row has a configured provider but NULL secret columns — this propagates through `get_org_config`/`get_tenant_override`/`get_effective_config` (and therefore the mail-send path) instead of silently sending with an empty credential.
- `backfill_plaintext_secrets` rewritten from a TODO-laden pseudo-migration into an honestly-documented anomaly-detector: `email_config` was created ciphertext-only in Schema v15 (Phase 5), unlike `federation_config`'s legacy plaintext `client_secret` column, so there is no plaintext source to migrate from. Also fixed a pre-existing bug where the detection query checked `provider_kind IN ['sendgrid', ...]` (no underscore) against the actual stored value `'send_grid'`, silently excluding all SendGrid rows from the anomaly count.

## Task Commits

Each task was committed atomically:

1. **Task 1: Make email-provider secrets write-only + redacted, and inputs omit-preserving (D-01/D-02)** — `614fc46` (feat)
2. **Task 2: Repository — delete_org_config, preserve-on-omit set_org_config, NULL-ciphertext error (D-13/D-02/D-08)** — `a25bdf8` (feat)
3. **Task 3: Close plaintext-secret backfill honestly (D-07) with a no-op test** — `ef5bbc9` (docs)

## Files Created/Modified

- `crates/axiam-core/src/models/email.rs` — `#[serde(skip_serializing, default)]` on secret fields; manual redacting `Debug` for `SmtpConfig`/`ApiProviderConfig`; `validate_email_config` no longer treats empty `api_key` as a violation; 8 new tests, 1 renamed test.
- `crates/axiam-core/src/repository.rs` — `EmailConfigRepository::delete_org_config` trait method added.
- `crates/axiam-db/src/repository/email_config.rs` — `delete_org_config` impl; `set_org_config` preserve-on-omit merge (new `fetch_org_secret_columns` helper + `ExistingSecretColumns` row struct); `row_to_provider`/`try_into_domain` return `AxiamError` and error clearly on NULL ciphertext; `backfill_plaintext_secrets` rewritten doc + typo fix; 8 new tests (2 delete, 2 preserve/replace, 1 NULL-ciphertext, 2 backfill no-op, plus the existing 5 round-trip tests kept green).

## Decisions Made

- **D-02 mechanism: sentinel-empty, not a new input type.** The plan explicitly offered either "an input-specific optional-secret representation" or "a sentinel-empty convention mapped to preserve" (`plan_decision id="D-02-input-shape"`). Chosen: sentinel-empty. Rationale: `SetOrgEmailConfig.provider: ProviderConfig` is a public type already consumed outside this plan's declared files (`crates/axiam-amqp/tests/mail_consumer_test.rs` constructs `SetOrgEmailConfig { provider: ProviderConfig::Smtp(SmtpConfig {..}) }` directly). Introducing a parallel `ProviderConfigInput`/`SmtpConfigInput` type would have forced type changes on `SetOrgEmailConfig.provider` and rippled into that test file and future handler code, well beyond this plan's `files_modified` list. The sentinel-empty design keeps `ProviderConfig`/`SmtpConfig`/`ApiProviderConfig` as a single, unified type for both write-input and resolved/stored use (satisfying the plan's "do NOT make the resolved/stored model optional" constraint) with zero blast radius outside the three declared files. Verified via a scoped `cargo test -p axiam-amqp --test mail_consumer_test` run (5/5 pass, unchanged).
- **`delete_org_config` scope-filter:** `DELETE FROM email_config WHERE scope = 'org' AND scope_id = $scope_id` — identical shape to the existing `delete_tenant_override`, just scoped to `'org'`.
- **New test names** (all under `crates/axiam-core/src/models/email.rs::tests` unless noted):
  - `smtp_config_password_not_serialized`, `smtp_config_debug_redacts_password`, `api_provider_config_api_key_not_serialized`, `api_provider_config_debug_redacts_api_key` (D-01)
  - `smtp_config_deserializes_without_password_field`, `api_provider_config_deserializes_without_api_key_field`, `set_org_email_config_with_omitted_smtp_secret_passes_validation`, `empty_api_key_is_treated_as_omit_and_passes_validation` (renamed from `empty_api_key_fails`) (D-02)
  - `crates/axiam-db/src/repository/email_config.rs::tests::delete_org_config_removes_row`, `delete_org_config_is_ok_when_nothing_to_delete` (D-13)
  - `crates/axiam-db/src/repository/email_config.rs::tests::set_org_config_omitted_secret_preserves_stored_smtp_password`, `set_org_config_supplied_secret_replaces_stored_value` (D-02, repository layer)
  - `crates/axiam-db/src/repository/email_config.rs::tests::read_path_errors_on_null_ciphertext_row` (D-08)
  - `crates/axiam-db/src/repository/email_config.rs::tests::backfill_plaintext_secrets_is_a_noop_on_v15_schema_with_data_present`, `backfill_plaintext_secrets_is_a_noop_on_empty_table` (D-07)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed `provider_kind` typo in the backfill detection query**
- **Found during:** Task 3 (backfill honesty pass)
- **Issue:** `backfill_plaintext_secrets`'s detection SELECT checked `provider_kind IN ['sendgrid','postmark','resend','brevo']`, but the actual stored/valid value (per `provider_kind_str`/`parse_provider_kind` and the schema's `ASSERT $value IN [...]` clause) is `'send_grid'` (with underscore). This silently excluded every SendGrid row from the NULL-ciphertext anomaly count.
- **Fix:** Changed the query literal from `'sendgrid'` to `'send_grid'`.
- **Files modified:** `crates/axiam-db/src/repository/email_config.rs`
- **Verification:** Covered indirectly by the existing `round_trip_sendgrid` test (unaffected — writes go through `encrypt_provider`) plus the new backfill no-op tests exercising the corrected query.
- **Committed in:** `ef5bbc9` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary for D-07's honesty requirement — an anomaly detector that structurally can't detect one of its five provider kinds would be worse than no detector. No scope creep; fixed inline in the same file/task already being edited for D-07.

## Issues Encountered

- **Return-type refactor ripple within `email_config.rs`:** Making `row_to_provider` return `AxiamError` (needed for D-08's `AxiamError::EmailConfig` variant, matching the crate's existing "no email config" error family) required also changing `EmailConfigRowWithId::try_into_domain`'s return type from `Result<_, DbError>` to `Result<_, AxiamError>`, and simplifying `get_org_config`/`get_tenant_override`'s now-redundant `.map_err(Into::into)`/`.map_err(AxiamError::from)` calls. Contained entirely within `crates/axiam-db/src/repository/email_config.rs` (already a declared file); no external callers of these private functions exist. Resolved during Task 2, verified via the full scoped test suite.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Wave-2 plan 28-04 (admin email-config API handlers) can now build on: write-only/redacted secrets, omit-preserve write semantics, `delete_org_config`, and a clear D-08 error surfaced through `get_effective_config` — the handler layer just needs to map `AxiamError::EmailConfig` to an appropriate HTTP status and expose the DELETE org route.
- No blockers. All three declared files (`crates/axiam-core/src/models/email.rs`, `crates/axiam-core/src/repository.rs`, `crates/axiam-db/src/repository/email_config.rs`) compile cleanly (`cargo build`/`cargo clippy`, zero warnings) and all scoped tests pass: `cargo test -p axiam-core --lib models::email` (26 tests), `cargo test -p axiam-db --lib email_config` (13 tests), plus a downstream sanity check `cargo test -p axiam-amqp --test mail_consumer_test` (5 tests, unaffected).

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*
