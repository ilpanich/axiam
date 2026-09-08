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
| `profile` | `UserRepository::get_by_id` | id, username, email, status, mfa_enabled flag, **`phone_number`, `phone_number_verified`, `address`** (X7 G8 / W7), metadata, timestamps — **excludes** `password_hash` and `mfa_secret` |
| `consents` | `ConsentRepository::list_by_user` | consent type, version, accepted_at, ip_address — see §3 |
| `sessions` | `SessionRepository::list_by_user` | id, created_at, expires_at, ip_address, user_agent — **metadata only**, `token_hash` deliberately excluded (D-03c) |
| `mfa` | derived from `user.mfa_enabled` | boolean flag only — **excludes** `mfa_secret` |
| `federation_identities` | `FederationLinkRepository::get_by_user_id` | federation_config_id, external_subject, created_at |
| `assignments` | `RoleRepository::get_user_role_assignments` | direct + group-inherited role grants, incl. resource scope |
| `group_memberships` | `GroupRepository::get_user_groups` | group id, name, description |
| `audit_entries` | `AuditLogRepository::list` (paginated, 1,000-row pages, looped to completion) | action, outcome, timestamp, resource_id for every entry where the user was the actor |
| `webauthn_credentials` | `WebauthnCredentialRepository::list_by_user` | id, credential_id, name, credential_type, timestamps — **excludes** the encrypted `passkey_json` secret material |

**A new column is not exported for free (W7).** `aggregate_export_data` builds
the `profile` section from an **explicit field list**, so a column added to the
`user` table is absent from every export until it is named there. W7's plan text
assumed the opposite — that `phone_number` and `address` would be "covered by
the existing export path because they are user-row fields" — and they were not.
Anybody adding a user column that holds personal data must add it here as well,
and the same is true of the two erasure statements in §2.

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
`.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-04-PLAN.md`):

- `gdpr_pseudonym(pepper, tenant_id, user_id)` derives a stable
  `DELETED_USER_<hash>` pseudonym.
- `UserRepository::anonymize_user` scrubs the user's profile row in place
  (status becomes `Anonymized`, username/email pseudonymized, password hash
  no longer references the original email, and — since W7 — `phone_number`,
  `phone_number_verified_at` and `address` are cleared).
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

**Both erasure statements write explicit column lists (W7).** `anonymize_user`
and the administrator's tombstone each name every column they clear, so a column
this list does not name **survives erasure**. That is not a theoretical hazard:
W7 added `phone_number` and `address` under a plan that said they would be
"covered by the existing erasure paths because they are user-row fields", and
without the correction an erased subject would have kept their telephone number
and postal address indefinitely with the account hidden from the UI — which the
tombstone's own documentation calls "retention with the UI hidden, not erasure".
Proved by erasing a subject who has both and reading the row back
([`crates/axiam-db/tests/w7_sensitive_columns_test.rs`](../../crates/axiam-db/tests/w7_sensitive_columns_test.rs)),
on both paths, rather than by inspecting the SQL — a test that grepped the
statement would pass the day somebody adds a third erasure path.

### Administrative deletion (`DELETE /api/v1/users/{id}`)

A second, immediate path: an administrator removing an account from the Users
page. It is **not** an Art. 17 erasure request — nobody exercised a right, there
is no grace period and no cancel link — but it must not leave personal data
behind either, so it erases the same data the purge pipeline does.

`UserRepository::delete` overwrites `username`, `email` and `metadata` with
values derived from the row's own id (an internal identifier, not personal
data), clears every credential column, and sets `status = 'Deleted'`. The
handler additionally revokes all sessions **before** the row is touched, then
deletes the user's WebAuthn credentials, federation identity links and password
history, and strips their group memberships and role assignments.

The row itself survives, holding its id and nothing identifying. Audit entries
are append-only and reference their actor by id; dropping the row would leave
every entry the user ever produced pointing at nothing, and an audit trail that
cannot be resolved to a person is not an audit trail.

**Re-registration.** Overwriting the identifiers rather than merely hiding the
row is what frees them from `idx_user_tenant_username` and
`idx_user_tenant_email`. Those uniqueness constraints are enforced by the
database, so a tombstone still holding an address would refuse any new account
carrying it — whether created by an administrator through `POST /api/v1/users`
or provisioned over SCIM, both of which go through the same repository — and the
duplicate-account error would itself disclose that the deleted account had
existed. Proven by
`a_deleted_user_can_register_again_with_the_same_identifiers`.

**What this path does not do**, and why it is not a substitute for the pipeline
above: it does not pseudonymize the audit log's actor references, and it writes
no `erasure_proof` row. Both leave the account unable to authenticate and
holding no personal data; only the Art. 17 pipeline produces durable evidence of
it. A data subject's erasure request must therefore go through
`POST /api/v1/account/delete`, not through an administrator pressing Delete.

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

**Scope boundary (D-06), and what W7 changed.** CMPL-02's acceptance criterion
was "consent recorded and exportable," satisfied by the mechanism above, and
consent-capture UI and withdrawal flows were deferred as capabilities beyond it.
W7 needed both — a scope release cannot rest on a record the subject can neither
see nor revoke — so §3.1 below is that deferral being closed for one category of
consent. `terms_of_service` still has no capture UI and still has no withdrawal
path other than erasure, deliberately: withdrawing it is not a consent operation
but a request to be forgotten, and it has its own endpoint and its own grace
period (§2).

---

### 3.1 OIDC scope-release consent (X7 G8 / wave W7)

**What is being consented to.** The OIDC `address` and `phone` scopes
(Core §5.4) release a postal address and a telephone number to a relying party.
AXIAM holds both for no operational purpose of its own — nothing authenticates
against them, nothing is sent to them, nothing is keyed by them — so the
**purpose limitation** (Art. 5(1)(b)) is stated as: *identity claims released to
relying parties the data subject has consented to, and nothing else.* They are
written by the admin API and by SCIM, read by the UserInfo endpoint, and read
by nothing else in the system.

**Lawful basis: consent, and the four conditions Art. 7 attaches.**

| Art. 7 / Art. 4(11) condition | How it is met | Evidence |
|---|---|---|
| **Freely given** | The consent screen offers "Allow" and "Not now" with equal prominence; declining returns the relying party a normal protocol answer (`access_denied`) rather than a dead end, so refusing costs the subject nothing beyond the feature they refused | `ConsentPage.tsx`; row 109 |
| **Specific** | The record names one relying party and one exact scope set. Consenting for one client says nothing about another, and a client that later widens its request re-prompts rather than inheriting | rows 110, 119 |
| **Informed** | The screen names the relying party and lists the categories of data — a telephone number, a postal address — in the subject's own language, in each of the five shipped locales | `ConsentPage.test.tsx`; row 107 |
| **Unambiguous** | Consent is an affirmative click that writes a record. There is no pre-ticked box, no implied consent from continued use, and no consent inferred from the scope being registered | row 107 |
| **Demonstrable** (Art. 7(1)) | Two places, on purpose: the `consent` row is live state, and `gdpr.oidc_scope_consent_granted` in the append-only audit log is the history | §3.1 audit table below |
| **As easy to withdraw as to give** (Art. 7(3)) | One call from the subject's own Privacy & Data page, no confirmation step, no grace period, effective on the relying party's **next** UserInfo request with the token it already holds | row 115 |

**Four gates, and each is asked again at the moment of release.** A decision
taken when the access token was minted would outlive the facts it rested on — a
token lives fifteen minutes and the refresh behind it thirty days — so the
release path re-derives all four on every call. That is what makes withdrawal
immediate rather than effective on the next token.

1. **The organization** enabled `sensitive_scopes_enabled`. Off in
   `system_defaults()`, off in the v57 migration's `DEFAULT false`, and off in
   the settings-row decoder's fallback for a row it cannot read. It is the only
   *disable*-only control in the org/tenant settings model: a tenant may refuse
   a release its organization allows and may never authorise one it forbade,
   because the lawful basis for holding the data was established at the
   organization level.
2. **The operator** registered the scope on the client. No client registered
   before W7 carries either scope — they were unregistrable — so no existing
   integration's behaviour moved.
3. **The data subject** consented, and has not withdrawn.
4. **The client is not on the `fapi2` profile.** That lane collects no consent
   record, and "the registration says it is allowed" is not evidence that
   anybody agreed.

**Data minimisation (Art. 5(1)(c)), as structure rather than as care.**

- The `user.address` column is `SCHEMAFULL` with exactly the six OIDC §5.1.1
  members and is deliberately **not** `FLEXIBLE`, so an integration cannot park
  a tax number or a date of birth in it and have it released under `address`.
- Claims are released from **UserInfo only**, never from the ID token: an ID
  token is a long-lived artefact relying parties log and cache, and OIDC
  Core §5.4 puts scope claims at UserInfo for the code flow anyway.
- SCIM's `type` qualifiers (`"work"`, `"home"`) are accepted and **not stored**:
  they are personal data nothing in this system reads.
- Neither value reaches a log line. `User`, `UserRow`, `UserRowWithId`,
  `UserInfoResponse` and the two SCIM output types redact them in `Debug` while
  still printing presence, which is the diagnostic anybody actually needs.

**Audit (Art. 5(2), accountability) — names, never values.**

| Event | When | Carries |
|---|---|---|
| `gdpr.oidc_scope_consent_granted` | the subject consents | relying party, canonical scope set, IP, timestamp |
| `gdpr.oidc_scope_consent_withdrawn` | the subject withdraws | relying party, IP, timestamp |
| `userinfo.sensitive_claims_released` | a release actually happens | relying party, claim **names**, IP, timestamp |

The third row carries claim names and never claim values, and this is not
fastidiousness: the audit log is append-only and is itself exported to subjects
under Art. 15, so a row carrying the telephone number would be a second copy of
the personal data in the one store that cannot be erased. A UserInfo call that
releases nothing writes no row, so the rows that *are* disclosures stay findable.

**Withdrawal deletes the record, and the audit log keeps the history.** The
`consent` table answers "may I release this now", and a table that answered with
tombstones would be one where forgetting to filter them releases data the
subject withdrew. `ConsentRepository::withdraw` is therefore a delete — and it
is confined by the repository itself to the `oidc_scope_release:` namespace, so
no caller can reach a `terms_of_service` row however the call is written. The
invariant registration depends on (a user never exists without proof of consent,
threat T-5-consent-gap) is untouched.

**Endpoints.**

| Endpoint | Art. | Notes |
|---|---|---|
| `GET /api/v1/account/consents` | 15(1)(a) | the subject's own records; marks which are withdrawable |
| `POST /api/v1/account/consents/oidc-scopes` | 7(1) | what the consent screen calls; refuses a client that does not exist, a scope the client has not registered, a scope outside the two, and any request while the capability is off |
| `DELETE /api/v1/account/consents/oidc-scopes/{client_id}` | 7(3) | one call, no confirmation, no grace period |

All three are strictly self-service: there is deliberately no `user_id`
parameter to act for somebody else with, unlike the export and erasure
endpoints, because consent is "an indication of the data subject's wishes" and
an administrator cannot indicate it on their behalf.

**Executable proof:**
[`crates/axiam-api-rest/tests/oauth2_sensitive_scopes_test.rs`](../../crates/axiam-api-rest/tests/oauth2_sensitive_scopes_test.rs)
(25 tests) and
[`crates/axiam-db/tests/w7_sensitive_columns_test.rs`](../../crates/axiam-db/tests/w7_sensitive_columns_test.rs)
(8 tests). Rows 104–129 of
[`docs/compliance/oidc-conformance.md`](oidc-conformance.md) map each behaviour
to the test that shows it.

**Not claimed.** AXIAM ships no telephone-verification ceremony, so
`phone_number_verified` is written by an administrator asserting an out-of-band
check and by nothing else. It is released as `false` — never omitted, never
assumed true — when a number is present and unverified, because OIDC Core §5.1
makes it a statement the OP is answerable for.

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
  (`.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-04-PLAN.md`)
  — cited by path rather than linked, like the two `.planning/` references
  above it: `5d454f1` archived that phase, and `.planning/` is not part of the
  repository, so a link would resolve to nothing in a fresh checkout. The path
  still names the artifact for anyone who has the planning tree.
- **No production code was modified by this verification pass** — all four
  evidence tests already existed and already passed prior to this plan; this
  document is the net-new artifact.
- **Milestone:** v1.2 (Beta) — this document will be re-verified (re-run
  tests, re-check the repository cross-check) at the next milestone that
  touches GDPR export/erasure/consent behavior.
