# Phase 24: Security Hardening I — Authentication & Access-Control Surfaces - Pattern Map

**Mapped:** 2026-07-03
**Files analyzed:** 20 (11 source modified, 1 source new, 1 schema, 7 test files)
**Analogs found:** 18 / 20 (2 net-new components have partial/structural analogs only)

All file:line citations below were re-verified against live code on 2026-07-03. Where CONTEXT.md drifted, the current line is noted.

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `crates/axiam-db/src/repository/user.rs` (`update_totp_step` :484-497) | repository (impl-in-db) | CAS / transform | `crates/axiam-db/src/repository/oauth2_auth_code.rs::consume` (:213-243) | exact (same CAS shape) |
| `crates/axiam-core/src/repository.rs` (`update_totp_step` trait sig) | trait (trait-in-core) | contract | sibling repo trait methods returning `AxiamResult<bool>`/typed error | role-match |
| `crates/axiam-auth/src/totp.rs` (`verify_code_with_replay_check` :85-125) | service | transform | in-file existing skew/step logic (self) | in-place |
| `crates/axiam-api-rest/src/handlers/auth.rs` (MFA verify handler) | handler (thin) | request-response | existing thin MFA handler branch treating `!valid` → `MfaInvalidCode` | in-place |
| `crates/axiam-db/src/repository/saml_replay.rs` (analog only, read) | repository | uniqueness-CREATE | — (this IS the analog) | exact |
| `crates/axiam-api-rest/src/handlers/bootstrap.rs` (:97-140 TOCTOU, :171-187 txn) | handler + txn | uniqueness-CREATE / request-response | `saml_replay.rs::insert_assertion` (:61-93) | exact (pattern), in-place (file) |
| `crates/axiam-db/src/seeder.rs` + `schema.rs` (new tables) | config / migration | schema | existing `DEFINE TABLE`/`seeder_state` additive schema | role-match |
| `crates/axiam-server/src/main.rs` (gate check, `web::Data` crypto_semaphore) | config / composition | DI wiring | existing `.app_data(...)` registrations + `crypto_semaphore` origin (:353) | in-place |
| `crates/axiam-api-rest/src/extractors/rate_limit.rs` (`XForwardedForKeyExtractor` :50-75) | extractor | request-parsing | in-file (self, bug at :62-67) | in-place |
| `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs` (**NEW**) | middleware | request-response + CAS | `oauth2_auth_code.rs::consume` (CAS) + `authz.rs` middleware `Transform`/`Service` scaffold | role-match / partial |
| `crates/axiam-db/src/repository/rate_limit.rs` (**NEW**) | repository | CAS counter | `oauth2_auth_code.rs::consume` + `increment_failed_logins` (IF/THEN-vs-NONE) | role-match |
| `crates/axiam-api-rest/src/server.rs` (`build_governor` fail-open fallback) | config | request-response | existing `Governor`/`GovernorLayer` wiring (self — keep) | in-place |
| `crates/axiam-api-grpc/src/middleware/rate_limit.rs` (store swap only) | middleware (tower) | request-response + CAS | REST `rate_limit_shared.rs` (this phase) + existing `GovernorLayer` | role-match |
| `crates/axiam-api-rest/src/middleware/authz.rs` (`is_public_path` :38-51) | middleware | request-parsing | in-file (self) | in-place |
| `crates/axiam-auth/src/password_reset.rs` (`initiate_reset` :83-235) | service | request-response | `crates/axiam-auth/src/service.rs::login` (:210-233 SEC-026) | exact (pattern) |
| `crates/axiam-auth/src/password.rs` (`hash_password`/`verify_password`) | utility | transform | in-file (self) + `zeroize::Zeroizing` idiom | in-place |
| `crates/axiam-auth/src/crypto.rs` / `AuthConfig.pepper` | config | secret-handling | existing `#[serde(skip_serializing)]` secret convention → `secrecy::SecretString` | role-match |
| `crates/axiam-db/src/repository/password_history.rs` + `create_with_consent` | repository | CRUD (seed) | existing `BEGIN/CREATE user/CREATE consent/COMMIT` txn (self) | in-place |
| `crates/axiam-server/src/cleanup.rs` (GDPR audit DLQ) + `handlers/gdpr.rs:119-126` | service | file-I/O + event | existing append-only audit write + existing cleanup ticker | role-match |

### Test files (Wave 0)

| Test File | Role | Analog | Match Quality |
|-----------|------|--------|---------------|
| `crates/axiam-db/tests/totp_step_cas_test.rs` (**NEW**) | test (concurrency) | `crates/axiam-auth/tests/req14_totp_replay_test.rs` | role-match |
| `crates/axiam-api-rest/tests/rate_limit_shared_store_test.rs` (**NEW**) | test (integration) | existing `actix_web::test::call_service` tests in `tests/` | role-match |
| `crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs` (**NEW**) | test (integration) | REST rate-limit test (this phase) | role-match |
| `crates/axiam-api-rest/tests/bootstrap_test.rs` (EXTEND) | test (concurrency + gate) | self — `env_lock()`/`env_guard()` helper (:56-67) | exact (in-file) |
| `crates/axiam-api-rest/src/middleware/authz.rs` inline `mod tests` (EXTEND) | test (unit) | self — existing `is_public_path` direct-call tests | exact (in-file) |
| `crates/axiam-auth/src/password_reset.rs` inline `mod tests` (EXTEND) | test (unit) | self + `req14_pepper_test.rs` | in-file |
| `crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs` (**NEW**) | test (integration) | existing `gdpr_test.rs` | role-match (needs injectable audit-repo seam) |

---

## Pattern Assignments

### `crates/axiam-db/src/repository/user.rs` — `update_totp_step` (repository, CAS) [SECHRD-01]

**Analog:** `crates/axiam-db/src/repository/oauth2_auth_code.rs::consume` (verified live :213-243)

**Current code (unconditional UPDATE — the bug), `user.rs:484-497`:**
```rust
async fn update_totp_step(&self, tenant_id: Uuid, id: Uuid, step: u64) -> AxiamResult<()> {
    self.db
        .query(
            "UPDATE type::record('user', $id) SET \
             totp_last_used_step = $step, updated_at = time::now() \
             WHERE tenant_id = $tenant_id",           // <-- no step guard: replay-vulnerable
        )
        .bind(("id", id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .bind(("step", step))
        .await
        .map_err(DbError::from)?;
    Ok(())
}
```

**CAS pattern to copy (analog `oauth2_auth_code.rs:213-243`):**
```rust
let result = self.db.query(
    "SELECT meta::id(id) AS record_id, * FROM \
     (UPDATE oauth2_auth_code SET used = true \
      WHERE tenant_id = $tenant_id AND code_hash = $code_hash \
        AND client_id = $client_id AND redirect_uri = $redirect_uri \
        AND used = false AND expires_at > time::now())",
).bind(...).await.map_err(DbError::from)?;
let mut result = result.check().map_err(|e| DbError::Migration(e.to_string()))?;
let rows: Vec<AuthCodeRowWithId> = result.take(0).map_err(DbError::from)?;
// rows.is_empty() == CAS lost (concurrent winner or precondition false)
```

**Apply:** wrap the UPDATE in `SELECT * FROM (UPDATE ... WHERE tenant_id = $tenant_id AND (totp_last_used_step = NONE OR totp_last_used_step < $step))`, take(0), return `Ok(!rows.is_empty())`. Change trait sig `axiam-core/src/repository.rs` from `AxiamResult<()>` → `AxiamResult<bool>` OR map CAS-miss to `AxiamError::ReplayDetected` (see saml_replay pattern below) so the handler `?`-propagates a 401 with no new branch. The `= NONE OR` extension mirrors `increment_failed_logins`'s existing NONE-handling in the same file.

---

### `crates/axiam-api-rest/src/handlers/bootstrap.rs` — single-super-admin (uniqueness-CREATE) [SECHRD-04]

**Analog:** `crates/axiam-db/src/repository/saml_replay.rs::insert_assertion` (verified live :61-93)

**Pattern to copy (uniqueness-invariant CREATE → typed error, `saml_replay.rs:76-93`):**
```rust
result.check().map_err(|e| {
    let msg = e.to_string();
    // SurrealDB v3 UNIQUE index violation message contains "already contains"
    if msg.contains("already contains")
        || msg.contains("already exists")
        || msg.contains("unique")
    {
        AxiamError::ReplayDetected
    } else {
        AxiamError::Database(msg)
    }
}).map(|_| ())
```

**Apply:** delete the SELECT-then-branch TOCTOU at `bootstrap.rs:97-140` (list roles → find super-admin → list users → `total > 0`). Fold `CREATE type::record('bootstrap_lock', $tenant_id) SET locked_at = time::now()` into the SAME hand-written `BEGIN TRANSACTION ... COMMIT TRANSACTION` string that already creates the admin user + RELATE (:171-187). The loser's whole transaction rolls back on the UNIQUE violation; surface it via the same `result.check()` string-match, mapped to `AxiamError::AlreadyExists { entity: "bootstrap".into() }` (existing variant in `axiam-core/src/error.rs`). Setup-token single-use (D-03b): add a second `CREATE type::record('bootstrap_setup_token_consumed', $token_hash)` inside the same txn — consumption-by-existence, same precedent.

**Note (Pitfall 5 / history seed):** this same txn must also gain a `CREATE type::record('password_history', $ph_id)` statement to seed the bootstrap admin's initial password into history (bootstrap bypasses `create_with_consent`).

---

### `crates/axiam-auth/src/password_reset.rs` — constant-time reset (dummy-Argon2) [SECHRD-12]

**Analog:** `crates/axiam-auth/src/service.rs::login` (verified live :210-233, SEC-026)

**Pattern to copy (`service.rs:218-226`):**
```rust
Err(AxiamError::NotFound { .. }) => {
    // SEC-026: timing equalization — run a dummy Argon2 verify so
    // user-not-found takes the same time as wrong-password (ASVS V2).
    let _permit = self.crypto_semaphore.acquire().await.ok();
    let pepper_owned = self.config.pepper.clone();
    let _ = tokio::task::spawn_blocking(move || {
        password::verify_password("dummy", DUMMY_HASH, pepper_owned.as_deref())
    })
    .await;
    return Err(AuthError::InvalidCredentials.into());
}
```

**Apply:** `initiate_reset`'s two `Ok(None)` branches (unknown email ~:94-98; federated user ~:100-108) each run a `dummy_hash_wait(pepper)` helper with this exact body, then `return Ok(None)`. **Wiring gap (Pitfall 3):** `PasswordResetService` has no `crypto_semaphore` field and `initiate_reset` no `pepper` param — grow the ctor + signature, thread from both call sites in `handlers/password_reset.rs`, and register `.app_data(web::Data::new(Arc::clone(&crypto_semaphore)))` in `main.rs` (origin at `main.rs:353`, currently moved into service ctors but never registered as `web::Data`). Move `DUMMY_HASH` const from `service.rs` to `pub(crate)` in `crate::password` to avoid drift.

---

### `crates/axiam-api-rest/src/extractors/rate_limit.rs` — XFF keying fix [SECHRD-03]

**Analog:** in-file (self). **Current bug verified live at `:62-67`:**
```rust
let idx = if self.trusted_hops < hops.len() {
    hops.len() - 1 - self.trusted_hops
} else {
    0                // <-- BUG (D-01d): returns hops[0], attacker-controlled leftmost
};
if let Ok(ip) = hops[idx].parse::<IpAddr>() {
    return Ok(ip);
}
// falls through to peer_addr() below
```

**Apply:** when `trusted_hops >= hops.len()`, do NOT index `hops[0]` — skip the XFF path entirely and fall through to the existing `req.peer_addr().map(|a| a.ip())` at `:72-74`. Negative test: rotating `X-Forwarded-For` per request yields the SAME bucket. Also correct the nginx `proxy_add_x_forwarded_for` doc comment (rightmost = real client).

---

### `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs` (**NEW**) — shared store [SECHRD-03]

**Analog (CAS):** `oauth2_auth_code.rs::consume` for the SurrealQL counter; **analog (middleware scaffold):** the `Transform`/`Service` impl in `middleware/authz.rs:60-82`.

**Critical (Pitfall 1):** `governor::StateStore::measure_and_replace` is **synchronous** — do NOT `impl StateStore for SurrealStore` or `block_on` inside it. Build a NEW async Actix middleware that runs an async SurrealDB CAS-increment BEFORE delegating to the existing (untouched) `Governor`/`GovernorLayer` in `server.rs::build_governor`, which becomes the **fail-open fallback** (D-01b) on any DB error.

**SurrealQL counter (windowed CAS, follows `increment_failed_logins` read-before-write-in-one-statement semantics):**
```sql
UPSERT type::record('rate_limit_bucket', $key) SET
  count = IF window_start = NONE OR window_start < $window_start THEN 1 ELSE count + 1 END,
  window_start = IF window_start = NONE OR window_start < $window_start THEN $window_start ELSE window_start END,
  updated_at = time::now()
RETURN AFTER;
-- $key = format!("{endpoint}:{ip}") to preserve per-endpoint limits; allow if count <= limit
```

**gRPC (`axiam-api-grpc/src/middleware/rate_limit.rs`):** store/key-extractor swap ONLY — leave the `.per_second(authz_per_sec).burst_size(...)` quota math untouched (CORR-01/Phase 26 owns it; RESEARCH confirms the `per_millisecond` bug is already fixed in live code). See Pitfall 2 / Open Question 1: `SmartIpKeyExtractor` has no `trusted_hops` — parity fix is an explicit planner decision.

---

### `crates/axiam-api-rest/src/middleware/authz.rs` — `is_public_path` hardening [SECHRD-11]

**Analog:** in-file (self). **Current code verified live `:38-51`:**
```rust
pub fn is_public_path(path: &str) -> bool {
    for &entry in PUBLIC_PATHS {
        if let Some(prefix) = entry.strip_suffix('*') {
            if path.starts_with(prefix) {   // <-- no segment boundary: /auth/* matches /authz/...
                return true;
            }
        } else if path == entry {
            return true;
        }
    }
    false
}
```

**Apply:** for `*`-suffixed entries require a path-segment boundary (strip `*`, then match only if remainder is empty or next char is `/`), and normalize the path (collapse `//`, reject `..` via `path.split('/').any(|s| s == "..")`) BEFORE the check. Fail-closed: a normalization failure falls through to the existing 401/403 credential check, never implicit-allow. Test in the inline `#[cfg(test)] mod tests` (existing tests call `is_public_path` directly — assert the AC property `/api/v1/auth/*` does NOT match `/api/v1/authz/...` regardless of live `PUBLIC_PATHS`, per Pitfall 6).

---

### `crates/axiam-auth/src/password.rs` — zeroize/secrecy [SECHRD-12]

**Analog:** in-file + `zeroize::Zeroizing<String>` idiom (RESEARCH Code Examples :417-441). Wrap the peppered buffer in `Zeroizing<String>` (drop-based wipe fires on every `?` exit path — do NOT hand-roll a trailing `.zeroize()`). Wrap `AuthConfig.pepper` in `secrecy::SecretString`; add `.expose_secret()` only at the `&str` boundary. Keep `argon2::Params::new(19456, 2, 1, None)` unchanged.

---

## Shared Patterns

### SurrealDB CAS ("claim once" / "advance only if valid")
**Source:** `crates/axiam-db/src/repository/oauth2_auth_code.rs:213-243`
**Apply to:** SECHRD-01 (`update_totp_step`), SECHRD-03 (rate-limit counter), SECHRD-04 (setup-token consume)
**Shape:** `SELECT * FROM (UPDATE ... WHERE guard)` → `.check()` → `.take(0)` → empty rows = CAS lost. No separate SELECT.

### Uniqueness-invariant CREATE → typed error
**Source:** `crates/axiam-db/src/repository/saml_replay.rs:76-93`
**Apply to:** SECHRD-04 (bootstrap_lock, bootstrap_setup_token_consumed)
**Shape:** `CREATE type::record(...)` in-txn → `.check().map_err(|e| if e.to_string().contains("already contains"|"already exists"|"unique") { typed } else { Database })`.

### Dummy-Argon2 timing equalization
**Source:** `crates/axiam-auth/src/service.rs:218-226` (SEC-026)
**Apply to:** SECHRD-12 (`initiate_reset` both `Ok(None)` branches)
**Shape:** `crypto_semaphore.acquire()` → `spawn_blocking(verify_password("dummy", DUMMY_HASH, pepper))` → return the safe/None result.

### Process-global env mutation lock for tests
**Source:** `crates/axiam-api-rest/tests/bootstrap_test.rs:56-67` (`env_lock()` / `env_guard()`)
**Apply to:** SECHRD-04 gate tests (`AXIAM_BOOTSTRAP_ADMIN_EMAIL` / setup-token env cases) — reuse this exact helper (`tokio::sync::Mutex` held across awaits) to serialize env mutation.

### Direct-call unit tests for pure matchers
**Source:** existing `#[cfg(test)] mod tests` in `middleware/authz.rs` (calls `is_public_path` directly, not via live registry)
**Apply to:** SECHRD-11 negative tests (assert the matching-function property, not the current `PUBLIC_PATHS` contents).

---

## No Analog Found (structural/partial only — planner should use RESEARCH.md patterns)

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `crates/axiam-db/src/repository/rate_limit.rs` (NEW) | repository | CAS counter | No windowed-counter repo exists yet; CAS shape borrowed from `oauth2_auth_code.rs`, NONE-handling from `increment_failed_logins` — but the table + repo are net-new |
| `crates/axiam-server/src/cleanup.rs` GDPR audit DLQ (D-02) | service | file-I/O + structured log | No dead-letter-to-durable-file precedent in repo; append-only audit posture is the only analog. Injectable audit-repo seam (`gdpr_audit_dlq_test.rs`) also net-new. A4 flags "structured syslog" interpretation as needing sign-off |

---

## Metadata

**Analog search scope:** `crates/axiam-db/src/repository/`, `crates/axiam-auth/src/`, `crates/axiam-api-rest/src/{extractors,middleware,handlers}/`, `crates/axiam-api-grpc/src/middleware/`, `crates/axiam-*/tests/`
**Files scanned/verified live:** 8 primary analog surfaces re-read at cited lines (oauth2_auth_code, saml_replay, service.rs login, authz.rs, rate_limit.rs extractor, user.rs update_totp_step, bootstrap_test.rs helper)
**Drift found vs CONTEXT.md:** none material — `update_totp_step` at :484-497 (cited :483-497), `is_public_path` at :38-51 (cited :38-45, now slightly longer), XFF bug at :62-67 (cited :55-72), env helper at :56-67. All within tolerance.
**Pattern extraction date:** 2026-07-03
