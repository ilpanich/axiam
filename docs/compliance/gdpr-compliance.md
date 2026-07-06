# GDPR Compliance — AXIAM IAM

**Standard:** EU General Data Protection Regulation (GDPR) — Art. 15 (Right of
Access), Art. 17 (Right to Erasure), Art. 7 (Conditions for Consent)

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Date:** 2026-07-06
**Commit reviewed:** `1446151`
**Last verified:** 2026-07-06

**Scope:** This document describes AXIAM's implementation of data-subject
export (Art. 15), account erasure/pseudonymization (Art. 17), and consent
record-keeping (Art. 7) as of the v1.2 beta. It closes **CMPL-02** by citing
executable evidence (existing, re-run tests) rather than re-implementing
already-proven behavior (D-04). This is a point-in-time, self-assessed
description of the beta state — not a legal opinion or an external DPA audit.

**Method (D-03 "trust but verify"):** every claim below is backed by (a) a
named source-code location and (b) a named test in
[`crates/axiam-api-rest/tests/gdpr_test.rs`](../../crates/axiam-api-rest/tests/gdpr_test.rs)
that was **re-run** during this verification pass, not merely cited from
memory. Re-run command and result:

```
$ SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip \
    cargo test -p axiam-api-rest --test gdpr_test
running 7 tests
test consent_on_registration ... ok
test create_with_pending_flag_rolls_back_on_duplicate_pending_conflict ... ok
test deletion_cancel ... ok
test create_with_pending_flag_succeeds_atomically ... ok
test deletion_pseudonymization ... ok
test export_includes_real_session_metadata ... ok
test export_completeness ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.12s
```

All 4 CMPL-02 evidence tests (`export_completeness`,
`export_includes_real_session_metadata`, `deletion_pseudonymization`,
`consent_on_registration`) pass, alongside the 3 sibling export-job tests in
the same file.

**Compliance assertion:** export covers every user-owned data table
(including real session metadata, with an optional PGP re-encryption path);
erasure durably pseudonymizes audit PII (SECHRD-06); consent is recorded and
exportable. No genuine gap was found during this verification pass — no
production code was changed by this plan.

---

## 1. Export Completeness (Art. 15 — Right of Access)

**Evidence:**
[`crates/axiam-server/src/cleanup.rs::aggregate_export_data`](../../crates/axiam-server/src/cleanup.rs)
(assembled inside `sweep_pending_exports` / `process_export_job`) builds a
single sectioned JSON "Art. 15 personal-data inventory" for a user, covering:

| Export section | Source | Notes |
|---|---|---|
| `profile` | `UserRepository::get_by_id` | id, username, email, status, mfa_enabled flag, metadata, timestamps — **excludes** `password_hash` and `mfa_secret` |
| `consents` | `ConsentRepository::list_by_user` | consent type, version, accepted_at, ip_address — see §3 |
| `sessions` | `SessionRepository::list_by_user` | id, created_at, expires_at, ip_address, user_agent — **metadata only**, `token_hash` deliberately excluded (D-03c) |
| `mfa` | derived from `user.mfa_enabled` | boolean flag only — **excludes** `mfa_secret` |
| `federation_identities` | `FederationLinkRepository::get_by_user_id` | federation_config_id, external_subject, created_at |
| `assignments` | `RoleRepository::get_user_role_assignments` | direct + group-inherited role grants, incl. resource scope |
| `group_memberships` | `GroupRepository::get_user_groups` | group id, name, description |
| `audit_entries` | `AuditLogRepository::list` (paginated, 1,000-row pages, looped to completion) | action, outcome, timestamp, resource_id for every entry where the user was the actor |
| `webauthn_credentials` | `WebauthnCredentialRepository::list_by_user` | id, credential_id, name, credential_type, timestamps — **excludes** the encrypted `passkey_json` secret material |

**Executable proof:**
- `export_completeness` — asserts every named section is present in the
  serialized blob and that no secret field (`password_hash`, `mfa_secret`,
  any `token_hash`) leaks into it.
- `export_includes_real_session_metadata` — asserts the `sessions` array is
  non-empty against a seeded session row; this is the regression test that
  would fail if `sessions_json` ever reverted to a hardcoded empty array.

**Planning-time completeness cross-check (D-04):** every module under
[`crates/axiam-db/src/repository/`](../../crates/axiam-db/src/repository/)
was enumerated and classified as either (a) already covered by a section
above, (b) not user-owned personal data (organization/tenant/role/permission/
resource/webhook/email-template/rate-limit config, which belong to the
tenant or organization, not to an individual data subject), or (c)
short-lived security/token material deliberately excluded by design
(`oauth2_refresh_token`, `oauth2_auth_code`, `password_reset_token`,
`email_verification_token`, `password_history`, `saml_replay`,
`federation_login_state`, `account_deletion`, `export_job`,
`erasure_proof`) — consistent with the same "no live credential/token
material in the export" principle already applied to sessions and WebAuthn
above. `git log --diff-filter=A -- 'crates/axiam-db/src/repository/*.rs'`
confirms no repository file has been added since Phase 25 other than
`rate_limit.rs` (Phase 24, infra rate-limiting — not personal data). **No
user-owned table is missing from the export blob.**

### Encryption at rest and the optional PGP layer

The export blob is encrypted with **AES-256-GCM** before being stored
(`cleanup.rs::process_export_job`, using `axiam_auth::crypto::encrypt_separate`
with the tenant's `AXIAM__EMAIL_ENCRYPTION_KEY`-derived key) and only
decrypted transiently inside
[`handlers/gdpr.rs::download_account_export`](../../crates/axiam-api-rest/src/handlers/gdpr.rs)
when the data subject (or an authorized admin) redeems the single-use,
24-hour download token.

AXIAM additionally supports **PGP-encrypted data exports** as an optional
extra layer: a tenant can generate a dedicated `Export`-purpose OpenPGP key
(`PgpKeyPurpose::Export`, zero-knowledge — only the public key is stored
server-side) via the PKI/PGP key management API, then pass the decrypted
export JSON (base64-encoded) to
`POST /api/v1/pgp-keys/{id}/encrypt` (`handlers/pgp_keys.rs::encrypt`) to
receive an ASCII-armored PGP ciphertext (`EncryptedExport`,
`axiam_core::models::pgp_key`) suitable for secure out-of-band delivery.
**Honest scope note:** this PGP step is a general-purpose, permissioned
(`pgp_keys:encrypt`) utility endpoint — it is not automatically chained
inside `sweep_pending_exports`/`download_account_export`. It is the
mechanism by which "optional PGP" is satisfied: available and tested
(`crates/axiam-api-rest/tests/pgp_key_test.rs::pgp_key_encrypt_for_export`),
invoked as a deliberate additional step rather than an always-on default.

---

## 2. Erasure Durability (Art. 17 — Right to Erasure)

**Evidence:** account deletion durably pseudonymizes audit PII per
**SECHRD-06** (Phase 25,
[`25-04-PLAN.md`](../../.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-04-PLAN.md)):

- `gdpr_pseudonym(pepper, tenant_id, user_id)` derives a stable
  `DELETED_USER_<hash>` pseudonym.
- `UserRepository::anonymize_user` scrubs the user's profile row in place
  (status becomes `Anonymized`, username/email pseudonymized, password hash
  no longer references the original email).
- `AuditLogRepository::pseudonymize_actor` rewrites every audit row where the
  deleted user was the actor: `actor_id` becomes the **nil UUID**, an
  `actor_pseudonym` metadata field is set to the pseudonym, the original
  user UUID no longer appears anywhere in the row, and `ip_address` is
  nulled.
- An `erasure_proof` row (pseudonym, tenant_id, user_id, erased_at) is
  written durably, backed by a **`UNIQUE` index on `erasure_proof.user_id`**
  for idempotent-retry safety (Phase 25).

**Executable proof:** `deletion_pseudonymization` — seeds a user with audit
entries, runs the full purge pipeline (pseudonymize → anonymize → pseudonymize
audit → write erasure proof), then asserts: pseudonym format, `Anonymized`
status, pseudonymized username, absence of the original email from
`password_hash`, `actor_id == Uuid::nil()` on every affected audit row,
presence of `actor_pseudonym` metadata, absence of the original user UUID
from the serialized audit entry, and `ip_address == None` post-erasure.

Deletion is initiated via `POST /api/v1/account/delete`
(`handlers/gdpr.rs::request_account_delete`) — Art. 17 erasure request with
immediate account disablement, session revocation, a single-use cancel
link, and a 30-day grace period before the purge pipeline above runs; the
grace period can be aborted via `POST /api/v1/account/delete/cancel`
(`cancel_account_delete`, proven by `deletion_cancel`).

---

## 3. Consent (Art. 7 — Conditions for Consent)

**Evidence:** a `terms_of_service` consent row is created at registration
(`ConsentRepository`, backed by
[`crates/axiam-db/src/repository/consent.rs`](../../crates/axiam-db/src/repository/consent.rs)
and `axiam_core::models::gdpr`), and the same `consent_repo.list_by_user`
result that produces this row is exactly what `aggregate_export_data`
serializes into the export blob's `consents` section (see §1).

**Executable proof:** `consent_on_registration` — asserts exactly one
`terms_of_service` consent row is created at registration with `version`
and `ip_address` populated.

**Scope boundary (D-06 — deliberate, honest closure):** CMPL-02's
acceptance criterion is "consent recorded and exportable," which is fully
satisfied by the mechanism above. **Consent-capture UI and consent-withdrawal
flows are explicitly deferred** — they are new user-facing capabilities
beyond "recorded and exportable," and belong in a future consent-management
phase (see `.planning/phases/30-compliance-documentation/30-CONTEXT.md`
Deferred Ideas). No consent UI was built in this plan.

---

## 4. Export API Reconciliation (D-05 — Honest Closure)

**Roadmap shorthand vs. shipped design:** `.planning/ROADMAP.md` and
`REQUIREMENTS.md` describe CMPL-02's export criterion using the descriptive
shorthand `GET /api/v1/users/:id/export`. **No such literal, synchronous
endpoint exists**, and this plan does **not** add one (explicitly out of
scope per D-05 and RESEARCH.md Pitfall 1).

**Canonical shipped design — async enqueue + single-use token download:**

1. `POST /api/v1/account/export` (`handlers/gdpr.rs::request_account_export`)
   — enqueues an export job (dedup against `queued`/`ready`/`failed` states).
2. The background cleanup sweep
   (`cleanup.rs::sweep_pending_exports` → `process_export_job`) aggregates
   the Art. 15 inventory (§1), encrypts it with AES-256-GCM, and emails an
   `ExportReady` notification containing a single-use download link.
3. `GET /api/v1/account/export/{token}`
   (`handlers/gdpr.rs::download_account_export`) — validates the token
   (hash lookup, `Ready` status, 24-hour TTL), decrypts the blob, and
   **atomically** consumes the token (`consume_ready_and_delete`,
   TOCTTOU-safe single-use) before returning the plaintext JSON.

**Why this satisfies CMPL-02's intent:** the async design was a deliberate
SECHRD-06 choice — it lets export generation run outside the request/response
cycle (correct for the paginated, potentially large audit-entry aggregation
in §1), and it lets the download step be single-use and time-boxed rather
than a standing, replayable GET. The async flow covers every table incl.
real sessions (§1) with an optional PGP re-encryption layer (§1), which is
the substance of the roadmap's `GET /api/v1/users/:id/export` shorthand.
**This document treats the async
`POST /api/v1/account/export` → `GET /api/v1/account/export/{token}` flow as
the canonical, complete implementation of CMPL-02's export requirement.**
No literal synchronous `GET /users/:id/export` route exists in
`handlers/gdpr.rs`, confirming this reconciliation accurately reflects the
shipped surface — it is not a retroactive rationalization of a missing
endpoint.

---

## 5. Provenance

- **Requirement:** CMPL-02 (`.planning/REQUIREMENTS.md` §CMPL-02)
- **Decisions applied:** D-04 (verify + close any real gap + document), D-05
  (async export canonical, roadmap shorthand reconciled), D-06 (consent
  scope = record + export; UI/withdrawal deferred) —
  `.planning/phases/30-compliance-documentation/30-CONTEXT.md`
- **Related certification doc:** [`claude_dev/security-audit.md`](../../claude_dev/security-audit.md)
  §6 cites `sc4-coverage.md`'s GDPR data-lifecycle test row; this document is
  the detailed CMPL-02 backing evidence that `security-audit.md` should link
  to for its own GDPR row (cross-reference, not duplication, per D-01/D-09).
- **Erasure durability upstream artifact:** SECHRD-06, Phase 25
  ([`25-04-PLAN.md`](../../.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-04-PLAN.md))
- **No production code was modified by this verification pass** — all four
  evidence tests already existed and already passed prior to this plan; this
  document is the net-new artifact.
- **Milestone:** v1.2 (Beta) — this document will be re-verified (re-run
  tests, re-check the repository cross-check) at the next milestone that
  touches GDPR export/erasure/consent behavior.
