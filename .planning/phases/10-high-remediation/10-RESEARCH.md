# Phase 10: High Remediation (Wave 2) — Research

**Researched:** 2026-06-12
**Domain:** Security remediation — password-hashing consolidation, async-safety, tenant isolation, protocol hardening, frontend correctness
**Confidence:** HIGH (all findings verified directly from source files)

---

## Summary

Phase 10 closes the REQ-14 high-severity findings from `claude_dev/code-review.md` and
`claude_dev/security-review.md`. It is a brownfield remediation phase: every defect has a
known file:line location verified in this session. No new dependencies are required; all
fixes reuse existing crate APIs and internal patterns already present in the codebase.

The phase has a hard dependency ordering constraint: **CQ-B43 (`load_key_from_env`
extraction) must land before SEC-012** because SEC-012 reuses the extracted helper.
Similarly, **CQ-B09/B01 (single hashing path + pepper wiring) must land in Wave A** before
any integration test that exercises user creation via the REST API with a pepper configured.

Six logical work streams can proceed in parallel after Wave A ships:
async-safety (CQ-B02), tenant settings (CQ-B03), tenant edge isolation (CQ-B07/CQ-B08),
correctness/hardening (CQ-B05/CQ-B06/CQ-B38/SEC-005/008/010/011/012/CQ-B40), and frontend
High (CQ-F01–F08). The CI SAML-ON path is the only item that cannot be verified locally
(see SAML section).

**Primary recommendation:** Five plans in two waves. Wave A (plans 1–2): foundational
hashing + key extraction. Wave B (plans 3–5): async-safety + tenant isolation, correctness
+ hardening, frontend High.

---

## Phase Requirements

<phase_requirements>

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-14 AC-1 | One password-hashing path with pepper; repo-layer hasher deleted; REST-created user logs in with pepper set | CQ-B09/B01 — `db/repository/user.rs:152-173` (duplicate hasher), `main.rs:296` (no with_pepper wiring) |
| REQ-14 AC-2 | Argon2 hash/verify and PKI keygen/sign in `spawn_blocking` behind a bounding semaphore | CQ-B02 — `auth/service.rs:212-217`, `policy.rs:247`, `axiam-pki/ca.rs:57,128-131`, `cert.rs`, `pgp.rs` |
| REQ-14 AC-3 | Tenant settings persist sparse overrides merged at read; baseline change propagates | CQ-B03/SEC-033 — `repository/settings.rs:482-491` (stores merged snapshot instead of sparse) |
| REQ-14 AC-4 | Tenant-scoped edge mutations verify both endpoints belong to tenant and run in transactions; resource hierarchy rejects cycles/orphans; no depth-50 truncation | CQ-B07/CQ-B08 — `role.rs:320,477`, `permission.rs:314,333`, `resource.rs:86,350-393` |
| REQ-14 AC-5 | GDPR/SAML/TOTP/pagination/5xx/PKI/AMQP/migration correctness | CQ-B05/B06/B38/B40/SEC-005/008/010/011/012 — multiple files |
| REQ-14 AC-6 | Frontend High items fixed | CQ-F01–F08 — frontend source files |

</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Password hashing with pepper | API / Backend (axiam-auth) | — | Crypto belongs in service layer, not repo layer |
| Async-safe crypto (Argon2/PKI) | API / Backend (auth/pki services) | — | Tokio runtime; blocking CPU work must go in spawn_blocking |
| Tenant settings merge | Database / Storage (axiam-db) | — | Read-time merge is a repo-layer concern |
| Edge mutation tenant isolation | Database / Storage (axiam-db) | — | Constraint enforcement at persistence layer |
| Resource cycle detection | Database / Storage (axiam-db) | — | Graph integrity checked before write |
| GDPR purge/export | API / Backend (axiam-server/cleanup.rs) | axiam-api-rest | Cleanup task + download handler |
| SAML protocol checks | API / Backend (axiam-federation) | — | Feature-gated; CI SAML-ON path only |
| TOTP replay | API / Backend (axiam-auth) | Database / Storage | Check-then-persist; needs last-used-step field |
| Pagination clamp | API / Backend (axiam-core) | — | Centralized in Pagination deserialization |
| Generic 5xx | API / Backend (axiam-api-rest) | — | error.rs error_response() body |
| PKI fail-fast | API / Backend (axiam-server/main.rs) | — | Startup-time key validation |
| AMQP DLQ parity | API / Backend (axiam-amqp) | — | audit_consumer.rs + authz_consumer.rs |
| Migration idempotency | Database / Storage (axiam-db) | — | schema.rs runner |
| Frontend High fixes | Browser / Client (React) | — | Component/page fixes + CI lint gate |

---

## Standard Stack

No new external dependencies required. All fixes use crates already in `Cargo.toml`:
`tokio` (spawn_blocking, Semaphore), `argon2`, `axiam-auth::password`, `axiam-pki` internals.

**Installation:** none

---

## Package Legitimacy Audit

N/A — no new packages introduced in this phase.

---

## Architecture Patterns

### Recommended Project Structure

No new directories. All changes are within existing files.

---

## Item-by-Item Research

### WAVE A — Foundational (must land before Wave B)

---

#### A1. CQ-B09 + CQ-B01 — Single hashing path + pepper wiring

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-db/src/repository/user.rs` | 152–173 | Duplicate `hash_password` function, identical to `axiam-auth::password::hash_password`. Called at lines 210 (create) and 521 (create_with_consent). |
| `crates/axiam-server/src/main.rs` | 296 | `SurrealUserRepository::new(db.client().clone())` — does NOT use `with_pepper`. |
| `crates/axiam-server/src/main.rs` | 105–120 | MFA encryption key loaded from env (`AXIAM__AUTH__MFA_ENCRYPTION_KEY`). Pattern exists for auth pepper (`AXIAM__AUTH__PEPPER`) but is NOT loaded. |
| `crates/axiam-auth/src/config.rs` | 28–29 | `pepper: Option<String>` field already exists in `AuthConfig`. |

**What already exists:**
- `axiam-auth::password::hash_password(password, pepper)` — identical logic to the repo duplicate, already correct.
- `SurrealUserRepository::with_pepper(db, pepper)` at `user.rs:196-201` — constructor already exists but is never called from `main.rs`.
- `AuthService` already reads `self.config.pepper.as_deref()` and calls `password::verify_password` at `service.rs:212-217` — verify path is already correct.
- Pattern for loading env keys: `main.rs:106-119` (`AXIAM__AUTH__MFA_ENCRYPTION_KEY`) is the exact pattern to replicate for `AXIAM__AUTH__PEPPER`.

**Fix:**
1. `user.rs`: Delete `fn hash_password(...)` at lines 152–173. Replace call sites (210, 521) with `axiam_auth::password::hash_password(&input.password, self.pepper.as_deref()).map_err(|e| DbError::Migration(e.to_string()))?`.
2. `main.rs`: Add env-key loading block for `AXIAM__AUTH__PEPPER` → `config.auth.pepper = Some(pepper_str)` (mirrors the MFA key block at 106–119). Change line 296 to `SurrealUserRepository::with_pepper(db.client().clone(), config.auth.pepper.clone().unwrap_or_default())` — or pass `Option<String>` directly if `with_pepper` is changed to accept `Option<String>`.
3. `user.rs` imports: remove `argon2::*` imports that are no longer used after deleting the local hasher; add `use axiam_auth::password;`.

**Test:** Integration test — create user via `POST /api/v1/tenants/{tid}/users` with `AXIAM__AUTH__PEPPER` set; then `POST /api/v1/auth/login` with same credentials succeeds; with wrong pepper fails.

**Verification crate:** `axiam-db`, `axiam-server`. `cargo check -p axiam-db && cargo check -p axiam-server --no-default-features`.

---

#### A2. CQ-B43 — Extract `load_key_from_env` helper (enables SEC-012)

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-server/src/main.rs` | 106–170 | Four nearly-identical copy-paste blocks each doing `env::var → hex::decode → try_into → Option<[u8;32]>` |

**What already exists:**
- Pattern at `main.rs:106-119` (MFA key), 122–136 (federation key), 138–153 (email key), 155–170 (GDPR pepper) — all identical except the env var name and the config field they assign to.

**Fix:**
Extract a private helper in `main.rs` (or a small `src/keys.rs` module if it gets large):
```rust
fn load_key_from_env(name: &str) -> Option<[u8; 32]> {
    match std::env::var(name) {
        Ok(hex) => {
            let bytes = hex::decode(&hex)
                .unwrap_or_else(|_| panic!("{name} must be a 64-char hex string"));
            Some(bytes.try_into()
                .unwrap_or_else(|_| panic!("{name} must be exactly 32 bytes")))
        }
        Err(_) => {
            tracing::warn!("{name} not set");
            None
        }
    }
}
```
Then replace all four blocks with calls to this helper.

**Dependency note:** SEC-012 (PKI fail-fast) calls `load_key_from_env` to replace the `[0u8;32]` fallback — plan A2 must be committed before SEC-012 is implemented.

**Verification crate:** `axiam-server`. `cargo check -p axiam-server --no-default-features`.

---

### WAVE B — Parallel streams (all depend on Wave A being green)

---

#### B1. CQ-B02 — Async-safe crypto (spawn_blocking + semaphore)

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-auth/src/service.rs` | 212–217 | `password::verify_password(...)` called directly on async executor (Argon2id is CPU-intensive, blocks runtime thread) |
| `crates/axiam-auth/src/policy.rs` | 247 | `verify_password` called in a loop over password history |
| `crates/axiam-pki/src/ca.rs` | 57, 125–131 | `generate_keypair` (RSA-4096 in worst case) + `params.self_signed` called inline in `async fn generate` |
| `crates/axiam-pki/src/cert.rs` | (signing operations) | Similar inline crypto |
| `crates/axiam-pki/src/pgp.rs` | (key generation) | Similar inline crypto |

**What already exists:**
- `tokio::task::spawn_blocking` is available; `axiam-server` depends on `tokio`. No existing usage in these files — this is purely additive.
- `tokio::sync::Semaphore` for bounding concurrent hashing — not yet used.

**Pattern to use:**
```rust
// In AuthService::new or PkiService::new, create a shared Arc<Semaphore>:
let crypto_semaphore = Arc::new(tokio::sync::Semaphore::new(4)); // bound to CPU cores

// At call site (service.rs:212-217):
let password = input.password.clone();
let hash = user.password_hash.clone();
let pepper = self.config.pepper.clone();
let _permit = self.crypto_semaphore.acquire().await.unwrap();
let valid = tokio::task::spawn_blocking(move || {
    password::verify_password(&password, &hash, pepper.as_deref())
})
.await
.map_err(|e| AxiamError::Internal(format!("spawn_blocking: {e}")))?
.map_err(|e| AxiamError::Crypto(e.to_string()))?;
```

**Semaphore placement:** Add `crypto_semaphore: Arc<Semaphore>` field to `AuthService` and `CaService`/`PgpService`/`CertService` (or a shared `CryptoPool` struct passed by `Arc`). `main.rs` constructs one shared semaphore and passes it to all services.

**Semaphore bound:** 4 is a safe default (configurable); document in config. This prevents all worker threads being saturated during burst CA generation.

**Verification crate:** `axiam-auth`, `axiam-pki`. Tests: existing `#[tokio::test]` in `password.rs` / new `axiam-pki` tests (CQ-B24 adds them — coordinate with that work item).

---

#### B2. CQ-B03 / SEC-033 — Sparse tenant settings override

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-db/src/repository/settings.rs` | 482–491 | `store_effective_tenant_settings` persists a fully-merged `SecuritySettings` snapshot. When org baseline changes later, the stored tenant row retains stale merged values for fields the tenant never explicitly overrode. |
| `settings.rs` | 524–542 | `get_effective_settings` already has the correct re-merge logic — it calls `diff_against_org` then `effective_settings`. The problem is upstream in `store_effective_tenant_settings` which stores too much. |

**What already exists:**
- `diff_against_org(&org, &tenant_row)` — already implemented, returns a `TenantSettingsOverride` (sparse `Option` fields).
- `effective_settings(&org, &overrides, tenant_id, row_id)` — already merges org + overrides.
- `set_tenant_override` (lines 493–510) already stores sparse and re-diffs correctly — this is the correct pattern.
- `get_effective_settings` (524–542) already re-merges at read time correctly.

**Fix:** `store_effective_tenant_settings` is only called from ... (grep needed at plan time for callers). The planner should check call sites and either: (a) replace with `set_tenant_override` semantics, or (b) store only the sparse diff. The existing `diff_against_org` + `upsert` pattern from `set_tenant_override` is the reuse target.

**Test:** Create org settings. Create tenant with override for one field. Change org baseline for a different field. Read tenant effective settings — the changed org field must propagate, the override field must remain.

**Verification crate:** `axiam-db`. Test in `axiam-db` integration tests.

---

#### B3. CQ-B07 / SEC-007 — Tenant-scoped edge mutations + transactions

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-db/src/repository/role.rs` | 320–343 | `assign_to_user`: `_tenant_id` ignored; no tenant membership check; no transaction |
| `role.rs` | 345–376 | `unassign_from_user`: `_tenant_id` ignored |
| `role.rs` | 477–500 | `assign_to_group`: `_tenant_id` ignored |
| `role.rs` | 502–528 | `unassign_from_group`: `_tenant_id` ignored |
| `crates/axiam-db/src/repository/permission.rs` | 314–331 | `grant_to_role`: `_tenant_id` ignored; no tenant check; no transaction |
| `permission.rs` | 333–351 | `revoke_from_role`: `_tenant_id` ignored |

**Pattern to reuse — two options (choose per call type):**

Option 1 (SurrealQL LET + THROW, from `certificate.rs:413-438`):
```rust
// Verify both endpoints belong to tenant, then RELATE in one atomic query
let verify_sql = format!(
    "LET $user = (SELECT id FROM user:`{user_id}` WHERE tenant_id = $tid); \
     LET $role = (SELECT id FROM role:`{role_id}` WHERE tenant_id = $tid); \
     IF array::len($user) = 0 OR array::len($role) = 0 {{ \
         THROW 'cross-tenant edge denied'; \
     }}; \
     RELATE user:`{user_id}` -> has_role -> role:`{role_id}` SET resource_id = $resource_id"
);
// error-match on "cross-tenant edge denied" → AxiamError::AuthorizationDenied
```

Option 2 (two-SELECT count check, from `group.rs:354-388`):
```rust
// Two COUNT queries, check both before issuing the RELATE
```

Option 1 is preferred — it is atomic in one round-trip and fails fast with a meaningful error. Option 2 requires a TOCTTOU window between the check and the RELATE.

**Transaction requirement:** When `unassign_from_user` issues `DELETE has_role WHERE ...` + any side-effects, wrap in `BEGIN TRANSACTION ... COMMIT TRANSACTION`. For simple single-statement RELATE/DELETE without side-effects, the check+RELATE in a single query (Option 1) is sufficient.

**SurrealDB note:** `BEGIN=0, stmt1=1` slot offset applies to multi-statement transactions (see MEMORY.md).

**Test pattern:** Create two tenants. Create a user in tenant A and a role in tenant B. Attempt `assign_to_user(tenant_a_id, user_a_id, role_b_id)` — must return `AuthorizationDenied`. Same-tenant assignment must succeed.

**Verification crate:** `axiam-db`.

---

#### B4. CQ-B08 — Resource hierarchy: cycles, orphan delete, depth-50 truncation

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-db/src/repository/resource.rs` | 86 | `const MAX_ANCESTOR_DEPTH: usize = 50` used as truncation in `get_ancestors` — silently stops walking at depth 50 rather than detecting a cycle |
| `resource.rs` | 202–215 | `update` when `parent_id` changes: no cycle check before creating new `child_of` edge |
| `resource.rs` | 257–277 | `delete`: deletes resource even if it has children (orphans them) |
| `resource.rs` | 350–393 | `get_ancestors`: depth-50 truncation loop — should detect depth overflow as cycle indicator |

**Fix approaches:**

*Cycle detection (update):* Before creating new `child_of` edge, walk proposed ancestors using `get_ancestors(tenant_id, new_parent_id)`. If the walk visits `id` (current resource), it's a cycle → return `AxiamError::Validation { message: "cycle detected" }`. This adds one round-trip but is safe.

*Orphan delete:* Before `DELETE type::record('resource', $id)`, query `SELECT count() AS total FROM child_of WHERE out = resource:\`{id}\` GROUP ALL`. If > 0 → return `AxiamError::Validation { message: "cannot delete resource with children" }` (or re-home children, based on product decision — research cannot resolve this without user input; flag as open question). **Conservative safe default: block delete with children.**

*Depth-50 truncation:* Change loop from silent truncation to: if loop reaches `MAX_ANCESTOR_DEPTH` without finding a `None` parent, return `Err(DbError::Migration("resource hierarchy exceeds maximum depth — possible cycle".into()))`. This surfaces the problem instead of hiding it.

**Test:** Create A → B → C chain. Attempt to re-parent A under C → must fail with cycle error.

**Verification crate:** `axiam-db`.

---

#### B5. CQ-B38 / SEC-056 — GDPR purge/export correctness

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-server/src/cleanup.rs` | 233–308 | `purge_user`: anonymize step (d) runs before mark_completed (g). If anonymize succeeds but mark_completed fails, re-running purge finds no pending row and skips → user not marked completed. Fix: move `anonymize_user` to last step, or wrap in a single transaction |
| `cleanup.rs` | 461–503 | `aggregate_export_data`: `unwrap_or_default()` swallows errors from `consent_repo.list_by_user` (line 466), `federation_link_repo` (line 520) |
| `cleanup.rs` | 480–496 | Audit export hard-codes `limit: 10_000` — users with > 10k audit entries get truncated export |
| `cleanup.rs` | 534–549 | `sessions`, `assignments`, `group_memberships`, `webauthn_credentials` hardcoded as `[]` — incomplete Art. 15 export |
| `axiam-core/src/models/gdpr.rs` | 84–89 | `ExportJobStatus` enum missing `Failed` variant |
| `cleanup.rs` | ~362–375 | `process_export_job` on failure: skips but leaves job as `Queued` — no `Failed` status transition |
| `crates/axiam-api-rest/src/handlers/gdpr.rs` | 212–246 | Download: `mark_downloaded` then `delete` — not atomic; concurrent downloads of same token could both proceed before delete lands |

**Fixes:**

*Re-selectable purge:* Reorder steps — call `anonymize_user` last (after mark_completed and erasure_proof). Or: wrap in `BEGIN TRANSACTION` where atomicity matters. SurrealDB transactions support multi-table updates.

*Export errors:* Change `unwrap_or_default()` to `?` (propagate) or `unwrap_or_else(|e| { tracing::warn!(...); Default::default() })` to log without swallowing.

*Paginated audit export:* Loop with Pagination offset until `items.len() < limit`. Collect all pages.

*Complete export:* Populate `webauthn_credentials`, `group_memberships`, `assignments` from their repos. These repos already exist in `CleanupTask` fields or can be added.

*`Failed` status:* Add `Failed` variant to `ExportJobStatus`. Add `mark_failed(job_id)` method to `ExportJobRepository`. Call `mark_failed` in `process_export_job` error handler.

*Atomic download:* Use a SurrealDB `UPDATE export_job SET status = 'Downloaded' WHERE id = $id AND status = 'Ready'` — check rows-affected = 1 before returning data. The current two-step `mark_downloaded` + `delete` is fine functionally but is a TOCTTOU. Simpler: use `UPDATE ... WHERE status = 'Ready'` and treat 0 rows as "already used".

**Verification crate:** `axiam-server`. Integration test in `axiam-api-rest/tests/` (or server tests): create user, trigger export, paginate audit, verify completeness.

---

#### B6. CQ-B05 — AMQP DLQ parity

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-amqp/src/audit_consumer.rs` | 140 | `nack(BasicNackOptions::default())` — default has `requeue: false`, so failed audit messages are dropped (permanent loss), not dead-lettered |
| `crates/axiam-amqp/src/authz_consumer.rs` | 175–181 | `nack(requeue: true)` on processing failure → hot-loop if the message is permanently bad (e.g., bad payload) |
| `crates/axiam-amqp/src/connection.rs` | 120–143 | Only `MAIL_OUTBOUND` has DLX configured; audit and authz queues are plain-durable with no dead-letter routing |

**Fix:**
1. `connection.rs`: Declare `axiam.audit.events.dlq` and `axiam.authz.requests.dlq` as plain-durable queues (like `MAIL_OUTBOUND_DLQ`). Then re-declare `axiam.audit.events` and `axiam.authz.requests` with `x-dead-letter-exchange` pointing at their respective DLQs. Follow the exact `MAIL_OUTBOUND` pattern at lines 129–142.
2. `audit_consumer.rs:140`: Change to `nack(BasicNackOptions { requeue: false, .. })` — this dead-letters to the DLQ (once connection.rs has DLX configured).
3. `authz_consumer.rs:175-181`: Change `requeue: true` to `requeue: false` — a permanently bad authz message should dead-letter, not loop. Add retry logic at the publish side instead if retry is needed.

**Verification crate:** `axiam-amqp`. Unit test or integration test with in-process RabbitMQ mock (or document as manual smoke test in CI).

---

#### B7. CQ-B06 — Migration idempotency + transaction

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-db/src/schema.rs` | 979–1031 | `run_migrations`: each migration applies DDL then records version in two separate queries — if the record step fails, migration re-runs on next start; no startup lock against races |
| Various SCHEMA_V* constants | — | Some DDL statements may not use `IF NOT EXISTS` / `OVERWRITE` (check individually for each DEFINE TABLE/FIELD/INDEX in v1..vN) |

**Fix:**
1. Wrap `db.query(migration.sql)` + `db.query("CREATE _migration ...")` in a `BEGIN TRANSACTION ... COMMIT TRANSACTION`. SurrealDB supports DDL in transactions.
2. Add a startup lock record: `CREATE _migration_lock SET locked_at = time::now(), instance = $instance IF NOT EXISTS` — if it already exists from another instance, wait or skip.
3. Audit `SCHEMA_V1` and later for any `DEFINE TABLE` / `DEFINE FIELD` / `DEFINE INDEX` without `IF NOT EXISTS` — add where missing. (The `MIGRATION_TABLE_DDL` at line 17 already uses `IF NOT EXISTS` as the correct model.)

**Note:** SurrealDB v3 `DEFINE TABLE` errors on existing tables without `IF NOT EXISTS` (see MEMORY.md) — this is exactly the defect being fixed.

**Verification crate:** `axiam-db`. Test: run migrations twice against an in-memory SurrealDB — must succeed both times without error.

---

#### B8. SEC-005 — SAML protocol checks (InResponseTo / Destination / Conditions / XSW)

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-federation/src/saml.rs` | 324–455 | `handle_saml_response`: does NOT validate `InResponseTo` against issued request IDs |
| `saml.rs` | 354–412 | No `Destination` / `Recipient` check on the Response element |
| `saml.rs` | 382 | `if let Some(conditions)` — conditions block is optional; should be REQUIRED |
| `saml.rs` | 487–488 | SP metadata emits `WantAssertionsSigned="false"` and `AuthnRequestsSigned="false"` |
| `saml.rs` | ~254 | `AuthnRequest.id` is generated (`format!("_{}", Uuid::new_v4())`) but NOT stored in `federation_login_state` |

**What already exists:**
- `federation_login_state` repo — already stores `state`, `nonce`, `config_id`, `tenant_id`, `expires_at`. Adding a `request_id` field requires a schema migration (Wave B plan).
- Assertion replay: already implemented (`saml_replay` table + `insert_assertion`).
- Conditions block partial validation: already validates `NotBefore`, `NotOnOrAfter`, `AudienceRestriction`.

**Fix (feature-gated under `saml` feature):**
1. Store `authn_request_id` in `federation_login_state` on `build_authn_request`. Add DB migration for the new field.
2. In `handle_saml_response`: read `federation_login_state` via `relay_state` (the state param maps to the row). Check `response.in_response_to == login_state.request_id`. Return `SamlResponseFailed` on mismatch.
3. Check `response.destination` == ACS URL (passed as parameter or derived from config).
4. Make `Conditions` block required (not optional) — return error if missing.
5. Change SP metadata to `WantAssertionsSigned="true"` / `AuthnRequestsSigned="true"`.
6. XSW: bind the verified signature reference ID to the assertion being consumed — reject if the signature covers a different element than the assertion being processed.

**Critical constraint:** This feature is gated by `#[cfg(feature = "saml")]`. The 3 pre-existing baseline failures (`saml_acs`, `saml_authn`, `saml_metadata`) under `--no-default-features` are NOT regressions. Verification runs on the CI SAML-ON path (`build-saml` job) only, not locally on Arch. The planner must note: "verify via CI Docker build, not `cargo test --no-default-features`".

**Verification:** CI SAML-ON Docker path. Any new test added to `saml.rs` must also be gated `#[cfg(feature = "saml")]`.

---

#### B9. SEC-008 — TOTP replay rejection

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-auth/src/totp.rs` | 70 | `totp.check_current(code)` — checks valid time window but does NOT reject reuse of the same code within the same 30s step |
| `crates/axiam-auth/src/service.rs` | 316, 425 | Both MFA verify calls do not persist last-used TOTP step |

**What already exists:**
- `User` model — check if it has `totp_last_used_at` or `totp_last_used_step` field. Likely does not. A new field + schema migration needed.
- `totp_rs::TOTP::generate_current` returns current step counter. `check_current` accepts codes for `±skew` steps. To reject replay: after verifying, store the step number; on next verify, reject if `current_step <= stored_step`.

**Fix:**
1. Add `totp_last_used_step: Option<u64>` to `User` model and DB schema (migration).
2. `totp::verify_code` signature change: add `last_used_step: Option<u64>` parameter. Before returning `Ok(true)`, check `current_step > last_used_step.unwrap_or(0)`.
3. `service.rs`: after successful TOTP verify at lines 316 and 425, persist the current step via `user_repo.update_totp_step(tenant_id, user_id, step)`.

**Note:** `totp_rs::TOTP::get_current_step()` or equivalent — check crate API at plan time. If not available, compute `unix_timestamp / 30`.

**Verification crate:** `axiam-auth`. Test: verify same code twice in same 30s window — second call must fail.

---

#### B10. SEC-010 / CQ-B30 — Pagination clamp

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-core/src/repository.rs` | 51–53 | `Pagination { pub limit: u64 }` — no validation; callers can pass `limit=0` or `limit=1000000` |

**Fix:** Add a `#[serde(deserialize_with = "clamp_limit")]` custom deserializer on `limit`, or implement `Deserialize` manually for `Pagination`:
```rust
impl<'de> Deserialize<'de> for Pagination {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // ... deserialize raw then clamp
        let raw = /* raw struct */;
        Ok(Self {
            offset: raw.offset,
            limit: raw.limit.max(1).min(200), // clamp [1, 200]
        })
    }
}
```
Or use `serde_with` (already in workspace) for `#[serde(deserialize_with)]`.

**Note:** Ensure `limit: 10_000` in `aggregate_export_data` (cleanup.rs:493) is intentional (not user-controlled — it's internal, not from a query param). Only the serde deserialization path needs clamping; internal callers constructing `Pagination { limit: N }` directly are fine.

**Verification crate:** `axiam-core`. Test: deserialize `{"offset":0,"limit":999999}` → `limit` is clamped to 200.

---

#### B11. SEC-011 / SEC-039 / CQ-B33 — Generic 5xx

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-api-rest/src/error.rs` | 72–75 | `error_response()` for 5xx variants: `message: self.0.to_string()` — leaks internal error detail (DB connection strings, crypto errors, internal state) to HTTP clients |

**Fix:**
```rust
// In error_response():
let message = match &self.0 {
    // Client errors: echo the message (validation, auth, not-found)
    AxiamError::NotFound { .. }
    | AxiamError::AlreadyExists { .. }
    | AxiamError::AuthenticationFailed { .. }
    | AxiamError::ReplayDetected
    | AxiamError::AuthorizationDenied { .. }
    | AxiamError::Validation { .. }
    | AxiamError::PasswordPolicy { .. }
    | AxiamError::TenantContext
    | AxiamError::RateLimited
    | AxiamError::EmailConfig(_) => self.0.to_string(),
    // Server errors: generic message, log internal detail
    _ => {
        tracing::error!(error = %self.0, "internal server error");
        "An internal error occurred".into()
    }
};
```

**Verification crate:** `axiam-api-rest`. Test: trigger a DB error → response body must not contain connection string or internal detail.

---

#### B12. SEC-012 — PKI fail-fast on missing key

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-server/src/main.rs` | 335–353 | `AXIAM__PKI__ENCRYPTION_KEY` not set → `[0u8;32]` zero-key fallback used silently; `PkiConfig { encryption_key: [0u8;32] }` is constructed and the warning is only at tracing level |

**Fix (depends on A2 `load_key_from_env`):**
Change `PkiConfig.encryption_key` to `Option<[u8; 32]>`. Update `CaService`, `CertService`, `PgpService` to check `config.encryption_key.is_some()` before attempting operations that encrypt private keys — return `AxiamError::Internal("PKI encryption key not configured")` instead of using zero-key.

At `main.rs:335-353`:
```rust
let pki_encryption_key = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY");
// No fallback — None means PKI operations that encrypt keys will fail at runtime
let pki_config = PkiConfig { encryption_key: pki_encryption_key };
```

`CaService::generate` should check:
```rust
let key = self.config.encryption_key.ok_or_else(|| AxiamError::Internal(
    "AXIAM__PKI__ENCRYPTION_KEY not set — CA generation unavailable".into()
))?;
```

**Verification crate:** `axiam-pki`, `axiam-server`. Test: call `CaService::generate` without encryption key → error (not panics, not silent zero-key encrypt).

---

#### B13. CQ-B40 — Federation operable via API (idp_signing_cert_pem + algorithms)

**Defect location:**

| File | Line(s) | Problem |
|------|---------|---------|
| `crates/axiam-api-rest/src/handlers/federation.rs` | 53–77 | `CreateFederationConfigRequest` DTO missing `idp_signing_cert_pem` and `allowed_algorithms` fields |
| `crates/axiam-federation/src/cert.rs` | 18–27 | PEM parser uses line-concatenation instead of the `pem` crate |

**Note:** CQ-B40 is listed in the remediation plan Wave 2 scope but the ROADMAP Phase 10 scope line mentions it only in the "correctness + hardening" bucket. Treat as a B-wave item alongside the others.

**Fix:**
1. Add fields to `CreateFederationConfigRequest` and `UpdateFederationConfigRequest`.
2. Validate PEM with `cert.rs:36-41` `validate_pem_cert` before persisting.
3. Replace line-concatenation parser with `pem::parse()`.
4. Schema migration to persist new fields (already added in Phase 9 per `schema.rs:378-386`).

**Verification crate:** `axiam-api-rest`. Integration test: API-created SAML config with cert PEM completes a login.

---

### FRONTEND HIGH — CQ-F01 through CQ-F08

All six target files verified:

#### F01. CQ-F01 — PgpKeysPage: real user.id

**File:** `frontend/src/pages/pgp/PgpKeysPage.tsx:267-268,314`

**Fix:** Import `useAuthStore` from `@/stores/auth`. Replace:
```typescript
const currentUserId = "current-user";
```
with:
```typescript
const { user } = useAuthStore();
const currentUserId = user?.id ?? "";
```
`AuthUser.id` is a `string` field — no type change needed.

---

#### F02. CQ-F02 — ConfirmDialog: `confirmLabel` prop + retire bespoke unlock dialog

**File:** `frontend/src/components/ConfirmDialog.tsx:4-11,99,106`

**Fix:** Add `confirmLabel?: string` to `ConfirmDialogProps` (default `"Delete"`). Replace hardcoded `"Delete"` at line 106 with `{confirmLabel ?? "Delete"}`. Update all consumers to pass `confirmLabel` where the action is not deletion (unlock, revoke, etc.).

---

#### F03. CQ-F03 — AuditLogsPage: debounce timer cleanup

**File:** `frontend/src/pages/audit/AuditLogsPage.tsx:203-204,241-250`

**Current state:** `actorTimer` and `actionTimer` are created by `setTimeout` but not cleared on component unmount or when the "Clear" button resets filters.

**Fix:** Add `useEffect` return cleanup:
```typescript
useEffect(() => {
  return () => {
    if (actorTimer) clearTimeout(actorTimer);
    if (actionTimer) clearTimeout(actionTimer);
  };
}, [actorTimer, actionTimer]);
```
Also call `clearTimeout` in the Clear button handler.

---

#### F04. CQ-F04 — RoleDetailPage + GroupDetailPage: replace manual debounce with `useQuery`

**Files:**
- `frontend/src/pages/roles/RoleDetailPage.tsx:285-298`
- `frontend/src/pages/groups/GroupDetailPage.tsx:83-97`

**Current state:** Both use `useRef<ReturnType<typeof setTimeout>>` + manual `setTimeout`/`clearTimeout` for user search.

**Fix:** Replace with:
```typescript
const { data: searchResults } = useQuery({
  queryKey: ["user-search", searchTerm, tenantId],
  queryFn: () => userService.search(tenantId, searchTerm),
  enabled: searchTerm.length >= 2,
});
```
Extract a shared `UserSearchDialog` component used by both pages.

---

#### F05. CQ-F05 / SEC-015 — Topbar: logout calls backend + clears queryClient

**File:** `frontend/src/components/layout/Topbar.tsx:86-89`

**Current state:** `handleLogout` at line 86 only calls `clearAuth()` + navigate — does NOT call `POST /api/v1/auth/logout` to revoke server-side session and does NOT call `queryClient.clear()`.

**Fix:**
```typescript
const queryClient = useQueryClient();

const handleLogout = async () => {
  try {
    await api.post("/api/v1/auth/logout", {});
  } catch { /* best-effort */ }
  queryClient.clear();
  clearAuth();
  navigate("/login");
};
```
Also: on refresh failure (in `api.ts` interceptor at line 108), add `queryClient.clear()` before `clearAuth()`.

---

#### F06. CQ-F06 — Fix ESLint errors + add `npm run lint && tsc -b` to CI

**File:** `frontend/src/...` (9 eslint errors — enumerate at plan time with `npm run lint 2>&1`), `.github/workflows/ci.yml`

**CI fix:** In `ci.yml`, after `npm ci` and before `npm run build`:
```yaml
- name: Frontend lint and type-check
  working-directory: frontend
  run: npm run lint && npx tsc -b
```

---

#### F07. CQ-F07 — OrganizationDetailPage: fix dead `syncedRef` + make handleSubmit save

**File:** `frontend/src/pages/organizations/OrganizationDetailPage.tsx:632-635,662-667`

**Current state:** `syncedRef` at line 632 is created as a plain object literal on every render (`const syncedRef = { current: false }`) — it is reset each render and never actually gates the sync. The form does have `handleSubmit` at line 662 that calls `updateMutation.mutate(merged)` — this part is correct. The bug is that the form's displayed values may not be initialized from `settings` correctly because the `syncedRef` pattern is broken.

**Fix:** Replace `syncedRef` with `useEffect` to initialize `form` from `settings` when data loads:
```typescript
useEffect(() => {
  if (settings) {
    setForm(settings);
  }
}, [settings?.id]); // only reinitialize when settings identity changes
```

---

#### F08. CQ-F08 — TenantsPage: no fabricated "Active" status

**File:** `frontend/src/pages/tenants/TenantsPage.tsx:378-381`

**Current state:** `render: () => <StatusBadge status="active" />` — always shows "Active" regardless of actual tenant status.

**Fix:** `render: (row) => <StatusBadge status={row.status ?? "unknown"} />`. The `Tenant` domain model must have a `status` field for this to work — verify at plan time. If `Tenant` has no status field, remove the Status column entirely rather than fabricating data.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CPU-intensive crypto on async executor | Custom thread pool | `tokio::task::spawn_blocking` + `Arc<Semaphore>` | Standard Tokio pattern; semaphore bounds concurrent hash ops |
| Tenant membership check before edge mutation | Custom Rust membership check | SurrealDB `LET $x = (SELECT FROM ... WHERE tenant_id = $tid); IF array::len($x) = 0 { THROW ... }` | Single atomic round-trip; no TOCTTOU |
| SAML InResponseTo tracking | Custom in-memory map | `federation_login_state` table (already exists) + new `request_id` field | Persistent across restarts |
| TOTP replay prevention | Time-window check only | Store last-used step in `user` table + reject `step <= last_used_step` | Standard RFC 6238 replay prevention |
| Generic 5xx message | Inspect error type at each handler | Central `error_response()` in `axiam-api-rest/src/error.rs` | One change, all endpoints hardened |
| Load env key | Repeated copy-paste blocks | `load_key_from_env(name)` helper | Already identified as CQ-B43; DRY |

---

## Common Pitfalls

### Pitfall 1: Forgetting transaction slot offset
**What goes wrong:** `result.take(0)` on a transaction gets `BEGIN` result, not first statement.
**Why it happens:** SurrealDB multi-statement: `BEGIN=0, stmt1=1, stmt2=2, COMMIT=3`.
**How to avoid:** Use `result.take(1)` for first statement in a `BEGIN...COMMIT` block.
**Warning signs:** Empty results from `take(0)` on transaction queries.

### Pitfall 2: Running `cargo check` on the whole workspace
**What goes wrong:** `xmlsec` / SAML feature fails to compile on Arch.
**Why it happens:** `axiam-federation` requires native xmlsec which is not available without Docker.
**How to avoid:** Always `cargo check -p <specific-crate> --no-default-features`.
**Warning signs:** Build fails with xmlsec-related errors on first compile.

### Pitfall 3: Baseline SAML test failures
**What goes wrong:** 3 SAML tests fail under `--no-default-features` — treat as regression.
**Why it happens:** Pre-existing baseline: `saml_acs`, `saml_authn`, `saml_metadata` fail when SAML feature is off.
**How to avoid:** A 4th+ failure IS a regression. Any new SAML tests must be gated `#[cfg(feature = "saml")]`.

### Pitfall 4: `surrealdb::Value` doesn't impl Display
**What goes wrong:** `format!("{}", some_value)` compile error.
**How to avoid:** Use `{:?}` for debug formatting.

### Pitfall 5: `bind()` requires owned values
**What goes wrong:** `bind(("key", &some_string))` — requires owned `String`.
**How to avoid:** `.to_string()` or `.clone()` at bind sites.

### Pitfall 6: `useAuthStore` vs `queryClient` in React
**What goes wrong:** `queryClient.clear()` not called on logout → stale cached data shown to next user.
**How to avoid:** Always pair `clearAuth()` with `queryClient.clear()` in logout path. Use `useQueryClient()` hook to get the same `QueryClient` instance.

---

## Proposed Wave Ordering

```
WAVE A (prerequisite — must be green before Wave B starts)
  Plan 1: CQ-B09/B01 — single hashing path + pepper wiring (axiam-db, axiam-server)
  Plan 2: CQ-B43 — load_key_from_env extraction (axiam-server/main.rs)
           └─ SEC-012 — PKI fail-fast on missing key (axiam-pki, axiam-server)

WAVE B (parallel after Wave A green; group into 3 plans)
  Plan 3: Async-safety + tenant isolation
           ├─ CQ-B02 — spawn_blocking + semaphore (axiam-auth, axiam-pki)
           ├─ CQ-B07 — edge mutations tenant check + transactions (axiam-db/role.rs, permission.rs)
           └─ CQ-B08 — resource cycle/orphan/truncation (axiam-db/resource.rs)

  Plan 4: Correctness + hardening
           ├─ CQ-B03/SEC-033 — sparse tenant settings (axiam-db/settings.rs)
           ├─ CQ-B05 — AMQP DLQ parity (axiam-amqp)
           ├─ CQ-B06 — migration idempotency/transaction (axiam-db/schema.rs)
           ├─ CQ-B38/SEC-056 — GDPR purge/export (axiam-server/cleanup.rs, axiam-api-rest/handlers/gdpr.rs)
           ├─ CQ-B40 — federation API completeness (axiam-api-rest/handlers/federation.rs)
           ├─ SEC-005 — SAML protocol checks (axiam-federation/saml.rs) [CI only]
           ├─ SEC-008 — TOTP replay (axiam-auth/totp.rs + service.rs)
           ├─ SEC-010/CQ-B30 — pagination clamp (axiam-core/repository.rs)
           └─ SEC-011/CQ-B33 — generic 5xx (axiam-api-rest/error.rs)

  Plan 5: Frontend High
           ├─ CQ-F01 — PgpKeysPage real user.id
           ├─ CQ-F02 — ConfirmDialog confirmLabel
           ├─ CQ-F03 — AuditLogsPage debounce cleanup
           ├─ CQ-F04 — RoleDetailPage/GroupDetailPage useQuery search
           ├─ CQ-F05/SEC-015 — Topbar logout + queryClient.clear
           ├─ CQ-F06 — eslint + tsc -b in CI
           ├─ CQ-F07 — OrganizationDetailPage settings save
           └─ CQ-F08 — TenantsPage no fabricated status
```

**Rationale for grouping:**
- Plan 1+2 are foundational — everything downstream reads auth config or env keys.
- Plan 3 groups the async-safety and edge-mutation fixes because both touch axiam-db and axiam-auth; grouping reduces merge conflicts.
- Plan 4 is a sweep of independent correctness items; none depends on Plan 3.
- Plan 5 is entirely frontend; can be reviewed/merged independently of backend plans 3–4.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust: `cargo test` (tokio-based integration tests); Frontend: Vitest + Playwright |
| Config | `Cargo.toml` workspace; `frontend/vitest.config.ts` |
| Quick run command | `cargo test -p <crate> --no-default-features -- <test_name>` |
| Full suite command | `cargo test -p axiam-db -p axiam-auth -p axiam-pki -p axiam-server -p axiam-api-rest --no-default-features` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| AC-1 | REST-created user logs in with pepper | integration | `cargo test -p axiam-api-rest --no-default-features -- test_user_login_with_pepper` | ❌ Wave A |
| AC-2 | Argon2/PKI in spawn_blocking; no executor stall | unit | `cargo test -p axiam-auth -- hash_runs_in_spawn_blocking` | ❌ Wave B |
| AC-3 | Org baseline change propagates to tenant | integration | `cargo test -p axiam-db -- settings_baseline_propagates` | ❌ Wave B |
| AC-4 | Cross-tenant edge mutation rejected | integration | `cargo test -p axiam-db -- role_assign_cross_tenant_rejected` | ❌ Wave B |
| AC-4 | Resource cycle rejected | integration | `cargo test -p axiam-db -- resource_cycle_rejected` | ❌ Wave B |
| AC-5 | TOTP replay rejected | unit | `cargo test -p axiam-auth -- totp_replay_rejected` | ❌ Wave B |
| AC-5 | Pagination limit clamped | unit | `cargo test -p axiam-core -- pagination_limit_clamped` | ❌ Wave B |
| AC-5 | 5xx body generic | unit | `cargo test -p axiam-api-rest -- internal_error_body_generic` | ❌ Wave B |
| AC-5 | Migration idempotent | unit | `cargo test -p axiam-db -- migration_runs_twice` | ❌ Wave B |
| AC-5 | SAML InResponseTo validated | unit (saml feature) | `cargo test -p axiam-federation --features client -- saml_in_response_to_mismatch_rejected` | ❌ Wave B (CI only) |
| AC-6 | ESLint + tsc clean | CI | `cd frontend && npm run lint && npx tsc -b` | ❌ Wave B |

### Wave 0 Gaps (test infrastructure needed before Wave A commits)

- No new test infrastructure files needed — existing `cargo test` and Vitest setups are sufficient.
- New test functions per item above must be added as part of each task.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `tokio::task::spawn_blocking` | CQ-B02 async-safety | ✓ | in workspace tokio | — |
| `tokio::sync::Semaphore` | CQ-B02 bounding | ✓ | in workspace tokio | — |
| `argon2` | CQ-B09 hashing | ✓ | in axiam-auth Cargo.toml | — |
| `pem` crate | CQ-B40 PEM parse | check at plan time | — | line-concat (existing, not ideal) |
| SAML feature (`xmlsec`) | SEC-005 | ✗ locally | Docker/CI only | All SAML changes verified via CI SAML-ON job |
| `samael::schema::Response.in_response_to` | SEC-005 InResponseTo check | verify at plan time | — | If field absent, check samael schema |

**Missing dependencies with no local fallback:**
- SAML/xmlsec: SEC-005 items verified only in CI Docker build.

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Argon2id + pepper (CQ-B09), TOTP replay (SEC-008) |
| V3 Session Management | yes | Logout clears queryClient + server session (CQ-F05) |
| V4 Access Control | yes | Tenant edge isolation (CQ-B07), resource hierarchy (CQ-B08) |
| V5 Input Validation | yes | Pagination clamp (SEC-010), cycle detection (CQ-B08) |
| V6 Cryptography | yes | spawn_blocking semaphore (CQ-B02), PKI fail-fast (SEC-012) |
| V9 Communication | partial | SAML protocol checks (SEC-005) |
| V15 Business Logic | yes | GDPR purge re-selectable (CQ-B38), TOTP replay (SEC-008) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Cross-tenant privilege escalation via edge mutations | Elevation of Privilege | SurrealDB LET+THROW tenant membership check before RELATE |
| SAML assertion forgery (XSW) | Spoofing | Bind verified signature reference ID to consumed assertion |
| TOTP replay | Repudiation | Persist last-used step; reject step ≤ stored |
| Async executor starvation via Argon2 | Denial of Service | spawn_blocking + bounding semaphore |
| PKI private key encrypted with zero-key | Tampering / Info Disclosure | Fail fast at startup; no [0u8;32] fallback |
| Internal error detail in HTTP 5xx | Information Disclosure | Generic 5xx message; log internal detail via tracing |
| GDPR export token race condition | Tampering | Atomic `UPDATE WHERE status='Ready'` before returning data |

---

## Open Questions

1. **Orphan resource delete — block or re-home?**
   - What we know: `resource.rs:257-277` deletes resources without checking for children.
   - What's unclear: Should deleting a resource with children be blocked (safest), or should children be re-parented to the deleted resource's parent?
   - Recommendation: Block delete (return 409 Conflict). Re-homing adds complexity and UI changes. Flag for user confirmation at discuss-phase if needed.

2. **Tenant status field for TenantsPage (CQ-F08)**
   - What we know: `TenantsPage` shows fabricated "Active" status. The `Tenant` model may or may not have a `status` field.
   - What's unclear: Does `axiam-core/src/models/tenant.rs` expose `status`? If not, should the column be removed or a status field added?
   - Recommendation: Check at plan time. If no status field: remove the column. If status exists but is not mapped to frontend Tenant type: add it.

3. **Semaphore size for CQ-B02**
   - What we know: 4 is a common default for CPU-bound work.
   - What's unclear: Should it be configurable via `AuthConfig`/`PkiConfig`? Or hardcoded?
   - Recommendation: Hardcode `4` initially; add a config field in Phase 11 if operators need tuning.

4. **`samael::AuthnRequest.id` storage for InResponseTo (SEC-005)**
   - What we know: `authn_request.id` is generated at `saml.rs:254` but not stored.
   - What's unclear: Does `samael::schema::Response` have an `in_response_to` field accessible via the Rust type?
   - Recommendation: Verify samael schema at plan time with `grep -r "in_response_to" crates/axiam-federation/`.

---

## Sources

### Primary (HIGH confidence — all verified by direct file inspection)

- `crates/axiam-db/src/repository/user.rs` — duplicate hash_password at 152-173; with_pepper constructor
- `crates/axiam-server/src/main.rs` — four env key loading blocks; PKI zero-key fallback at 335-353
- `crates/axiam-auth/src/password.rs` — canonical hash_password/verify_password
- `crates/axiam-auth/src/service.rs` — verify_password call site at 212-217; TOTP call at 316, 425
- `crates/axiam-auth/src/totp.rs` — check_current at 70; no last-step persistence
- `crates/axiam-pki/src/ca.rs` — generate_keypair + self_signed blocking at 57, 125-131
- `crates/axiam-db/src/repository/role.rs` — `_tenant_id` ignored at 320, 345, 477, 502
- `crates/axiam-db/src/repository/permission.rs` — `_tenant_id` ignored at 314, 333
- `crates/axiam-db/src/repository/resource.rs` — MAX_ANCESTOR_DEPTH=50 at 86; no cycle check at 202-215
- `crates/axiam-db/src/repository/settings.rs` — store_effective_tenant_settings at 482-491; get_effective_settings re-merge at 524-542
- `crates/axiam-db/src/repository/certificate.rs` — tenant check + THROW pattern at 413-438
- `crates/axiam-db/src/repository/group.rs` — COUNT tenant check pattern at 349-388
- `crates/axiam-db/src/repository/user.rs` — BEGIN TRANSACTION pattern at 527-551
- `crates/axiam-db/src/schema.rs` — migration runner at 979-1031; no transaction wrapping
- `crates/axiam-server/src/cleanup.rs` — purge_user order at 233-308; aggregate_export at 440-553
- `crates/axiam-api-rest/src/handlers/gdpr.rs` — download handler at 210-254
- `crates/axiam-api-rest/src/error.rs` — 5xx leaks internal detail at 72-75
- `crates/axiam-amqp/src/audit_consumer.rs` — nack default (requeue:false, no DLX) at 140
- `crates/axiam-amqp/src/authz_consumer.rs` — hot-loop nack requeue:true at 175-181
- `crates/axiam-amqp/src/connection.rs` — DLX only on MAIL_OUTBOUND at 129-142
- `crates/axiam-federation/src/saml.rs` — missing InResponseTo, Destination checks; WantAssertionsSigned=false at 487-488
- `frontend/src/pages/pgp/PgpKeysPage.tsx` — hardcoded "current-user" at 268
- `frontend/src/components/ConfirmDialog.tsx` — hardcoded "Delete" at 106; no confirmLabel prop
- `frontend/src/pages/audit/AuditLogsPage.tsx` — debounce timer leak at 203-204
- `frontend/src/pages/roles/RoleDetailPage.tsx` — manual debounce at 285-298
- `frontend/src/pages/groups/GroupDetailPage.tsx` — manual debounce at 83-97
- `frontend/src/components/layout/Topbar.tsx` — logout only clearAuth, no backend call at 86-89
- `frontend/src/pages/organizations/OrganizationDetailPage.tsx` — dead syncedRef at 632-635
- `frontend/src/pages/tenants/TenantsPage.tsx` — fabricated "active" status at 380
- `frontend/src/stores/auth.ts` — AuthUser.id field confirmed at line 4
- `.github/workflows/ci.yml` — no lint/tsc step; only npm run build at 242
- `claude_dev/remediation-plan.md` — Wave 2 items confirmed and cross-referenced

### Metadata

**Confidence breakdown:**
- File:line targets: HIGH — all verified by direct read
- Fix patterns: HIGH — reuse of existing patterns in same codebase
- Wave ordering: HIGH — dependency analysis from remediation-plan.md

**Research date:** 2026-06-12
**Valid until:** 2026-07-12 (stable codebase, 30-day horizon)

---

## RESEARCH COMPLETE

**Phase:** 10 — High Remediation (Wave 2)
**Confidence:** HIGH

### Key Findings

- **Foundational prerequisite confirmed:** `user.rs:152-173` has a duplicate `hash_password` that must be deleted; `main.rs` never calls `with_pepper` — these two fixes unlock the pepper acceptance test.
- **CQ-B43 is genuinely foundational:** `load_key_from_env` extraction must precede SEC-012 (PKI fail-fast) because SEC-012 directly reuses the helper.
- **Tenant edge isolation has a proven pattern:** `certificate.rs:413-438` (SurrealDB LET+THROW) and `group.rs:349-388` (two-COUNT check) are both in the codebase and can be copied verbatim to `role.rs` and `permission.rs`.
- **GDPR completeness has four distinct sub-defects:** purge ordering, swallowed errors, 10k hard limit on audit export, hardcoded empty arrays for webauthn/assignments/memberships — plan 4 must address all four.
- **SAML protocol checks are CI-only:** cannot be tested locally on Arch; plan 4 must document CI SAML-ON verification path.
- **Frontend fixes are all isolated single-file changes** except CQ-F04 (shared UserSearchDialog extraction) and CQ-F06 (CI yml addition).

### File Created

`.planning/phases/10-high-remediation/10-RESEARCH.md`

### Confidence Assessment

| Area | Level | Reason |
|------|-------|--------|
| File:line targets | HIGH | Direct source read for every item |
| Reuse patterns | HIGH | Patterns extracted from actual codebase code |
| Wave ordering | HIGH | Dependency analysis from remediation-plan.md |
| SAML field availability | MEDIUM | samael schema field `in_response_to` not directly read — verify at plan time |
| Tenant model status field | MEDIUM | `axiam-core/models/tenant.rs` not read — verify at plan time for CQ-F08 |

### Open Questions

1. Block or re-home children on resource delete? (product decision — conservative default: block)
2. `samael::schema::Response.in_response_to` field accessibility — verify at plan time
3. `Tenant` model `status` field existence — verify at plan time for CQ-F08

### Ready for Planning

Research complete. Planner can now create PLAN.md files for plans 10-01 through 10-05.
