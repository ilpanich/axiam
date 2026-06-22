---
phase: 10-high-remediation
verified: 2026-06-13T12:56:12Z
status: human_needed
score: 6/6 must-haves verified
overrides_applied: 0
human_verification:
  - test: "SAML protocol checks — InResponseTo, Destination, Conditions, XSW guard, WantAssertionsSigned"
    expected: "SAML ACS handler rejects responses with mismatched InResponseTo/Destination, absent Conditions, and XSW signatures; SP metadata emits WantAssertionsSigned=true"
    why_human: "SAML code path is behind the `saml` feature flag. All SAML tests are #[cfg(feature = \"saml\")] and the --no-default-features build used locally cannot execute them. Verification requires the CI/Docker SAML-ON path. The 3 pre-existing baseline failures (saml_acs/saml_authn/saml_metadata) must not increase to 4+."
  - test: "AMQP DLQ live routing — audit and authz dead-letter queues receive poison messages"
    expected: "A publish to axiam.audit.events or axiam.authz.requests that cannot be processed appears on axiam.audit.events.dlq / axiam.authz.request.dlq"
    why_human: "No in-process RabbitMQ broker available in unit tests. DLX routing requires a live broker to verify end-to-end dead-lettering. Compile-only verification is confirmed; runtime routing needs a real broker."
  - test: "GDPR export completeness — sessions, assignments, group_memberships, webauthn_credentials populated"
    expected: "Export blob contains non-empty arrays for all four categories when the user has related data"
    why_human: "The pagination loop and category population (cleanup.rs aggregate_export_data) require a populated in-memory DB with >10k audit rows to exercise the pagination path; cannot be confirmed via grep alone."
---

# Phase 10: High Remediation Verification Report

**Phase Goal:** Resolve high-severity correctness, async-safety, tenant-isolation, and protocol-hardening defects.
**Verified:** 2026-06-13T12:56:12Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | One password-hashing path with pepper; repo-layer hasher deleted; REST-created user logs in with pepper | VERIFIED | `grep -rn 'fn hash_password' crates/ \| grep -v axiam-auth` returns empty. `user.rs:187,521` call `password::hash_password` via axiam-auth. `main.rs:160-165` loads `AXIAM__AUTH__PEPPER`; `main.rs:290` calls `SurrealUserRepository::with_pepper`. Test file `req14_pepper_test.rs` exists. |
| 2 | Argon2 hash/verify and PKI keygen/sign run in `spawn_blocking` behind a bounding semaphore | VERIFIED | `service.rs:221-232` acquires `crypto_semaphore` permit then `spawn_blocking` for Argon2 verify. `policy.rs:247-257` wraps history-check verify in `spawn_blocking`. `ca.rs:82` wraps keygen+self-signing in `spawn_blocking`. Single `Arc::new(Semaphore::new(4))` at `main.rs:315`. |
| 3 | Tenant settings persist sparse overrides merged at read; baseline change propagates | VERIFIED | `settings.rs:533,536,560,596,631,636` all route through `diff_against_org`. The store path at `settings.rs:560` explicitly calls `diff_against_org` before upsert. `get_effective_settings` re-merges at read time (unchanged). |
| 4 | Tenant-scoped edge mutations verify both endpoints belong to tenant and run atomically; resource hierarchy rejects cycles/orphans, no depth-50 truncation | VERIFIED | `role.rs:336,395,536,595` all embed `THROW 'cross-tenant edge denied'` with matching error mapper. `permission.rs:328,368` same pattern. `resource.rs:205-218` cycle detection (self-parent + ancestor walk). `resource.rs:292` blocks delete of resources with children. `resource.rs:396-398` returns `Err` on depth overflow (not silent truncation). |
| 5 | GDPR, SAML, TOTP, pagination, 5xx, PKI, AMQP, migration correctness | VERIFIED (with human items — see below) | `repository.rs:57` clamps limit to `[1,200]`. `error.rs:94-96` generic 5xx + `tracing::error!`. `totp.rs:90,104,120-122` tracks `last_used_step`, rejects same-step replay. `gdpr.rs:90` has `Failed` variant; `cleanup.rs:377` calls `mark_failed`. `export_job.rs:241-243` atomic `WHERE status = 'ready'`. `connection.rs:142-169` DLX on audit+authz queues; consumers use `requeue: false`. `schema.rs:1061-1093` wraps migrations in `BEGIN TRANSACTION` with `_migration_lock`. `config.rs:11` `encryption_key: Option<[u8;32]>`; `ca.rs:105` `ok_or_else` fail-fast. SAML: code is present (`saml.rs:386,405-407,442-446,555`) but requires CI SAML-ON path (human check). |
| 6 | Frontend High items fixed; CI lint/tsc gate | VERIFIED | `PgpKeysPage.tsx:268` uses `user?.id`. `Topbar.tsx:91,95` calls `POST /api/v1/auth/logout` then `queryClientInstance.clear()`. `TenantsPage.tsx` — zero matches for `status`/`active` column. `ConfirmDialog.tsx:11,108` has `confirmLabel` prop. `AuditLogsPage.tsx:207-212` useEffect cleanup clears timers. `UserSearchDialog.tsx` uses `useQuery`; `RoleDetailPage.tsx` and `GroupDetailPage.tsx` import it with no manual `setTimeout`. `OrganizationDetailPage.tsx:634` useEffect initializes form. `ci.yml:220` runs `npm run lint && npx tsc -b`. |

**Score:** 6/6 truths verified (2 sub-items deferred to human checks)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-db/src/repository/user.rs` | Delegates hashing to axiam-auth::password | VERIFIED | Lines 187, 521 call `password::hash_password`; no local `fn hash_password` |
| `crates/axiam-server/src/main.rs` | `load_key_from_env` helper + pepper + PKI wiring | VERIFIED | Helper at line 51; 5 call sites (MFA, federation, email, GDPR, PKI); `with_pepper` at line 290 |
| `crates/axiam-pki/src/config.rs` | `encryption_key: Option<[u8;32]>` | VERIFIED | Line 11 |
| `crates/axiam-pki/src/ca.rs` | `ok_or_else` fail-fast before encrypt | VERIFIED | Lines 72, 105 |
| `crates/axiam-auth/src/service.rs` | `spawn_blocking` + `Semaphore` | VERIFIED | Lines 163, 219-232 |
| `crates/axiam-auth/src/policy.rs` | `spawn_blocking` around history verify | VERIFIED | Lines 247-257 |
| `crates/axiam-db/src/repository/role.rs` | `THROW` cross-tenant check | VERIFIED | Lines 336, 395, 536, 595 |
| `crates/axiam-db/src/repository/permission.rs` | `THROW` cross-tenant check | VERIFIED | Lines 328, 368 |
| `crates/axiam-db/src/repository/resource.rs` | cycle + orphan + depth-error | VERIFIED | Lines 205-218, 292, 396-398 |
| `crates/axiam-db/src/repository/settings.rs` | sparse overrides via `diff_against_org` | VERIFIED | Lines 533, 536, 560, 596, 631, 636 |
| `crates/axiam-db/src/schema.rs` | Transactional migrations + `_migration_lock` | VERIFIED | Lines 1061-1093; lock at lines 26-27 |
| `crates/axiam-amqp/src/connection.rs` | DLX on audit + authz queues | VERIFIED | Lines 142-169; DLQ constants at lines 18, 22 |
| `crates/axiam-amqp/src/audit_consumer.rs` | `requeue: false` | VERIFIED | Lines 77, 96, 115, 145 |
| `crates/axiam-amqp/src/authz_consumer.rs` | `requeue: false` (no hot-loop) | VERIFIED | Lines 73, 180 |
| `crates/axiam-core/src/models/gdpr.rs` | `ExportJobStatus::Failed` variant | VERIFIED | Line 90 |
| `crates/axiam-server/src/cleanup.rs` | `mark_failed` called in error handler | VERIFIED | Line 377 |
| `crates/axiam-db/src/repository/export_job.rs` | atomic `WHERE status = 'ready'` consume | VERIFIED | Lines 241-243 in `consume_ready_and_delete` |
| `crates/axiam-core/src/repository.rs` | `clamp_pagination_limit` deserializer | VERIFIED | Lines 52-57, clamping to `[1, 200]` |
| `crates/axiam-api-rest/src/error.rs` | generic 5xx body + `tracing::error!` | VERIFIED | Lines 73, 94-96 |
| `crates/axiam-auth/src/totp.rs` | `last_used_step` replay rejection | VERIFIED | Lines 90, 104, 120-122 |
| `crates/axiam-core/src/models/user.rs` | `totp_last_used_step: Option<u64>` | VERIFIED | Line 32 |
| `crates/axiam-db/src/schema.rs` | `totp_last_used_step` field migration | VERIFIED | Lines 1012-1018 |
| `crates/axiam-federation/src/saml.rs` | `in_response_to`, `destination`, `Conditions` checks, `WantAssertionsSigned=true` | VERIFIED (CI-only) | Lines 386, 405-407, 442-446, 555; `#[cfg(feature="saml")]` gated |
| `crates/axiam-api-rest/src/handlers/federation.rs` | `idp_signing_cert_pem` field in Create/Update | VERIFIED | Lines 70, 86, 256, 419 |
| `crates/axiam-federation/src/cert.rs` | `pem::parse()` (not line-concat) | VERIFIED | Line 16 |
| `frontend/src/pages/pgp/PgpKeysPage.tsx` | `user?.id` not hardcoded | VERIFIED | Lines 268, 314 |
| `frontend/src/components/layout/Topbar.tsx` | `POST /api/v1/auth/logout` + `queryClientInstance.clear()` | VERIFIED | Lines 91, 95 |
| `frontend/src/components/ConfirmDialog.tsx` | `confirmLabel?: string` prop | VERIFIED | Lines 11, 21, 108 |
| `frontend/src/pages/audit/AuditLogsPage.tsx` | useEffect unmount clears timers | VERIFIED | Lines 207-212 |
| `frontend/src/components/UserSearchDialog.tsx` | `useQuery` based search | VERIFIED | Lines 2, 34 |
| `frontend/src/pages/roles/RoleDetailPage.tsx` | Uses `UserSearchDialog`, no manual `setTimeout` | VERIFIED | Lines 16, 744 |
| `frontend/src/pages/groups/GroupDetailPage.tsx` | Uses `UserSearchDialog`, no manual `setTimeout` | VERIFIED | Lines 11, 325 |
| `frontend/src/pages/organizations/OrganizationDetailPage.tsx` | useEffect initializes form from settings | VERIFIED | Line 634; no `syncedRef` |
| `frontend/src/pages/tenants/TenantsPage.tsx` | No fabricated `status` column | VERIFIED | Zero matches for `status`/`active` status column |
| `.github/workflows/ci.yml` | `npm run lint && npx tsc -b` step | VERIFIED | Line 220 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `main.rs` | `SurrealUserRepository::with_pepper` | constructor call | WIRED | Line 290 |
| `user.rs` create paths | `axiam_auth::password::hash_password` | direct call | WIRED | Lines 187, 521 |
| `main.rs` | `load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY")` | PKI config | WIRED | Line 341 |
| `ca.rs` | `AxiamError` when `encryption_key` is `None` | `ok_or_else` guard | WIRED | Line 105 |
| `service.rs` | `tokio::task::spawn_blocking + Semaphore` | `crypto_semaphore` acquire | WIRED | Lines 221-232 |
| `role.rs` | SurrealQL `THROW` cross-tenant check | LET+THROW before RELATE | WIRED | Lines 336, 395, 536, 595 |
| `saml.rs` | `federation_login_state.request_id` via `in_response_to` | response comparison | WIRED (CI-only) | Line 386 |
| `Topbar.tsx` | `POST /api/v1/auth/logout` + `queryClient.clear` | `handleLogout` | WIRED | Lines 91, 95 |
| `PgpKeysPage.tsx` | `useAuthStore().user?.id` | real current-user id | WIRED | Lines 268, 314 |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `user.rs` create | `password_hash` | `password::hash_password(input.password, pepper)` | Yes — peppered Argon2id hash | FLOWING |
| `settings.rs` store | sparse overrides | `diff_against_org(&org, &merged_settings)` | Yes — diff of tenant vs org | FLOWING |
| `cleanup.rs` | `ExportJobStatus::Failed` | `export_job_repo.mark_failed(job.id)` | Yes — DB write on error path | FLOWING |
| `repository.rs` | `Pagination.limit` | serde `clamp_pagination_limit` deserializer | Yes — clamped `[1,200]` | FLOWING |
| `totp.rs` | `current_step` | `SystemTime::now() / 30` compared to `last_used_step` | Yes — time-based | FLOWING |

### Behavioral Spot-Checks

Step 7b: No server running. Static source checks used as proxy.

| Behavior | Check | Result | Status |
|----------|-------|--------|--------|
| No duplicate hash_password outside axiam-auth | `grep -rn 'fn hash_password' crates/ \| grep -v axiam-auth` | 0 matches | PASS |
| Zero-key fallback removed from main.rs | `grep -n '0u8; 32' main.rs` | 0 matches | PASS |
| No `requeue: true` in authz_consumer.rs | grep | 0 matches | PASS |
| Pagination deserialization clamps | `clamp(1, 200)` present in `repository.rs:57` | present | PASS |
| `WantAssertionsSigned="false"` removed | grep saml.rs | 0 matches | PASS |
| No `mark_downloaded` standalone call in gdpr.rs handler | `grep -c 'mark_downloaded' handlers/gdpr.rs` | 0 matches | PASS |
| `totp_last_used_step` in User model and schema | grep | present in both | PASS |

### Probe Execution

Step 7c: No conventional probe scripts found for phase 10.

```
find scripts -path '*/tests/probe-*.sh' 2>/dev/null → 0 results
```

Step 7c: SKIPPED (no probe scripts declared or present)

### Requirements Coverage

| Requirement | Plans | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| REQ-14 AC-1 (CQ-B09/B01) | 10-01 | Single hashing path + pepper | SATISFIED | `user.rs` delegates to `password::hash_password`; `main.rs` loads `AXIAM__AUTH__PEPPER` |
| REQ-14 AC-1 (CQ-B43) | 10-02 | `load_key_from_env` extracted | SATISFIED | `main.rs:51` defines helper; 5 call sites confirmed |
| REQ-14 AC-1 (SEC-012) | 10-02 | PKI fail-fast on missing key | SATISFIED | `config.rs:11` is `Option`; `ca.rs:105` guards with `ok_or_else` |
| REQ-14 AC-2 (CQ-B02) | 10-03 | spawn_blocking + semaphore | SATISFIED | `service.rs`, `policy.rs`, `ca.rs` all use pattern; single semaphore in `main.rs:315` |
| REQ-14 AC-3 (CQ-B03/SEC-033) | 10-04 | Sparse tenant settings | SATISFIED | `settings.rs` store path uses `diff_against_org` |
| REQ-14 AC-4 (CQ-B07/SEC-007) | 10-03 | Tenant-scoped edge mutations | SATISFIED | `role.rs` and `permission.rs` embed `THROW 'cross-tenant edge denied'` |
| REQ-14 AC-4 (CQ-B08) | 10-03 | Resource hierarchy correctness | SATISFIED | Cycle check, orphan block, depth-error present in `resource.rs` |
| REQ-14 AC-5 (CQ-B06) | 10-04 | Idempotent/transactional migrations | SATISFIED | `schema.rs` wraps each migration in `BEGIN TRANSACTION` + `_migration_lock` |
| REQ-14 AC-5 (CQ-B05) | 10-04 | AMQP DLQ parity | SATISFIED (compile) | DLX declared in `connection.rs`; consumers use `requeue:false` — live routing needs human |
| REQ-14 AC-5 (CQ-B38/SEC-056) | 10-04 | GDPR correctness | SATISFIED | `mark_failed`, `consume_ready_and_delete`, `Failed` variant; pagination loop replaces `10_000` cap |
| REQ-14 AC-5 (SEC-010/CQ-B30) | 10-05 | Pagination clamp | SATISFIED | `repository.rs:57` clamps `[1,200]` |
| REQ-14 AC-5 (SEC-011/SEC-039/CQ-B33) | 10-05 | Generic 5xx errors | SATISFIED | `error.rs:94-96` generic body + logged detail |
| REQ-14 AC-5 (SEC-008) | 10-05 | TOTP replay rejection | SATISFIED | `totp.rs:120-122` rejects `current_step <= last_used_step` |
| REQ-14 AC-5 (SEC-005) | 10-05 | SAML protocol checks | NEEDS HUMAN (CI SAML-ON only) | Code present in `saml.rs`; feature-gated — cannot run locally |
| REQ-14 AC-5 (CQ-B40) | 10-05 | Federation API completeness | SATISFIED | `handlers/federation.rs:70` has `idp_signing_cert_pem`; `cert.rs:16` uses `pem::parse` |
| REQ-14 AC-6 (CQ-F01–F08) | 10-06 | Frontend High items | SATISFIED | All 8 items verified by source inspection; CI gate at `ci.yml:220` |
| REQ-14 AC-6 (SEC-015) | 10-06 | Logout clears session + cache | SATISFIED | `Topbar.tsx:91,95` calls logout API then `queryClientInstance.clear()` |

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `crates/axiam-db/src/repository/user.rs:714` | Local `verify_password` (Argon2id) retained | INFO | Intentional — documented in 10-01-SUMMARY.md ("Keep verify_password in user.rs used by axiam-db integration tests"). The *create* (hashing) path is single-sourced; this is the *verify* path for DB-layer tests only. Not a BLOCKER. |

No TBD/FIXME/XXX markers found in phase-10-modified files (confirmed by orchestrator pre-checks).

### Human Verification Required

#### 1. SAML Protocol Checks (CI SAML-ON path)

**Test:** Run the SAML feature-gated integration tests: `cargo test -p axiam-federation --features saml` and `cargo test -p axiam-api-rest --features saml` in CI/Docker.
**Expected:** All SAML tests pass except the 3 pre-existing baseline failures (saml_acs_rejects_empty_saml_response, saml_authn_request_rejects_empty_acs_url, saml_metadata_returns_xml). InResponseTo mismatch, Destination mismatch, and absent Conditions each cause `SamlResponseFailed` — not a panic or Ok.
**Why human:** The SAML feature is disabled under `--no-default-features` (local Arch box constraint). All new SAML tests are `#[cfg(feature = "saml")]`. A Docker/CI build with `--features saml` is required.

#### 2. AMQP DLQ Live Routing

**Test:** Start RabbitMQ + AXIAM; publish a malformed audit or authz message to `axiam.audit.events` / `axiam.authz.requests`; confirm it appears on `axiam.audit.events.dlq` / `axiam.authz.request.dlq` after the consumer nacks it.
**Expected:** Poison message lands on the `.dlq` queue within the consumer's nack cycle; it does not requeue or get silently dropped.
**Why human:** No in-process broker available. DLX routing semantics require a live RabbitMQ instance; compile-time declarations are verified but runtime routing is not testable with grep.

#### 3. GDPR Export Completeness (sessions, assignments, group_memberships, webauthn_credentials)

**Test:** Create a user with data across sessions, assignments, group memberships, and WebAuthn credentials in a running instance; trigger a GDPR export job; inspect the decrypted blob.
**Expected:** All four categories in the blob are non-empty and reflect the user's actual data. Audit export paginates past 10k entries if the user has >10k audit rows.
**Why human:** The pagination loop and category population in `cleanup.rs:aggregate_export_data` require a populated runtime environment with representative data volumes.

---

## Gaps Summary

No blocking gaps found. All 6 roadmap success criteria are verified against source code. The 3 human verification items above are behavioral checks requiring a running system — they do not indicate missing code.

The `user.rs` local `verify_password` function is not a gap: the plan explicitly scoped the fix to the *create* (hashing) path only, and the SUMMARY documents retaining `verify_password` as an intentional deviation within scope boundaries.

---

_Verified: 2026-06-13T12:56:12Z_
_Verifier: Claude (gsd-verifier)_
