# Phase 12: Low / Trivial Remediation — Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 38 new/modified files across 4 clusters
**Analogs found:** 36 / 38

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-api-rest/src/extractors/client_info.rs` (NEW) | utility | transform | `crates/axiam-api-rest/src/handlers/webauthn.rs:95-106` (capped version) | exact |
| `crates/axiam-api-rest/src/handlers/auth.rs` | handler | request-response | self (remove local defs, import extractor) | exact |
| `crates/axiam-api-rest/src/handlers/webauthn.rs` | handler | request-response | self (remove local defs, import extractor) | exact |
| `crates/axiam-api-rest/src/handlers/users.rs` | handler | CRUD | self (remove inline header read, import extractor) | exact |
| `crates/axiam-audit/src/middleware.rs` | middleware | event-driven | self (escalate warn→error, add structured field) | exact |
| `crates/axiam-server/src/cleanup.rs` | service | batch | self (replace `let _ =` with `if let Err`) | exact |
| `crates/axiam-api-rest/src/handlers/gdpr.rs` | handler | CRUD | self (replace `let _ =` with `tracing::error!`) | exact |
| `crates/axiam-oauth2/src/token.rs` | service | request-response | self (replace `let _ =` with `tracing::warn!`) | exact |
| `crates/axiam-auth/src/error.rs` | model | transform | self (add typed Crypto sub-variants) | exact |
| `Cargo.toml` (workspace) + per-crate `Cargo.toml` files | config | — | self (remove flagged deps after machete) | exact |
| `crates/axiam-auth/src/service.rs` | service | request-response | self:660-715 (change_password — HIBP None at line 715) | exact |
| `crates/axiam-audit/src/middleware.rs` | middleware | event-driven | self:161-162 (try_send block) | exact |
| `crates/axiam-db/src/seeder.rs` | utility | batch | self:37-66 + `crates/axiam-server/src/cleanup.rs:260-264` (sha2 digest pattern) | role-match |
| `claude_dev/design-document.md` | config | — | self (remove "explicit deny" clause at line 385) | exact |
| `CLAUDE.md` | config | — | self (add RBAC additive-only note) | exact |
| `crates/axiam-db/src/repository/user.rs` | repository | CRUD | self:20-68 (UserRow/UserRowWithId Debug derive + list query line 458) | exact |
| `.github/workflows/ci.yml` | config | — | self (all `uses:` lines to SHA-pin) | exact |
| `.github/workflows/release.yml` | config | — | self (all `uses:` lines to SHA-pin) | exact |
| `frontend/src/pages/placeholders/Placeholder.tsx` | component | — | DELETE — no analog needed | n/a |
| `frontend/package.json` | config | — | self (remove 4 radix pkgs after verification) | exact |
| `frontend/src/pages/users/UsersPage.tsx` | component | CRUD | `frontend/src/pages/auth/ResetPasswordPage.tsx:9,42,45` (PasswordPolicyChecker usage) | exact |
| `frontend/src/pages/BootstrapPage.tsx` | component | request-response | self:80 (404 status mapping) + `ResetPasswordPage.tsx` (checker pattern) | role-match |
| `frontend/src/components/DataTable.tsx` | component | transform | self:79 (unsafe cast — `String(...)` fix) | exact |
| `frontend/src/lib/utils.ts` | utility | transform | self:40,49 (`"en-US"` → `undefined`) | exact |
| `frontend/src/components/ResourceTree.tsx` | component | transform | self:81 (querySelector — add CSS.escape) | exact |
| `frontend/src/lib/api.ts` | utility | request-response | self:88-115 (`_retry` ordering) | exact |
| `frontend/src/hooks/usePermissions.ts` | hook | transform | self:15 (`?? []` allocation) | exact |
| `frontend/src/pages/tenants/TenantsPage.tsx` | component | CRUD | self (add `isLoadingOrgs` composite guard) | exact |
| `frontend/src/hooks/useAuthInit.ts` | hook | event-driven | self:22-58 (dep array + `useRef` guard) | exact |
| `frontend/src/pages/certificates/CertificatesPage.tsx` | component | CRUD | `frontend/src/pages/webhooks/WebhooksPage.tsx:287-307` (secret modal state pattern) | exact |
| `frontend/src/pages/oauth2/OAuth2ClientsPage.tsx` | component | CRUD | `frontend/src/pages/webhooks/WebhooksPage.tsx:287-307` | exact |
| `frontend/src/pages/service-accounts/ServiceAccountsPage.tsx` | component | CRUD | `frontend/src/pages/webhooks/WebhooksPage.tsx:287-307` | exact |
| `frontend/src/pages/webhooks/WebhooksPage.tsx` | component | CRUD | self:287-307 (onClose does not clear revealedSecret) | exact |
| `frontend/src/pages/pgp/PgpKeysPage.tsx` | component | CRUD | `frontend/src/pages/webhooks/WebhooksPage.tsx:287-307` | exact |
| `frontend/src/pages/auth/ResetPasswordPage.tsx` | component | request-response | self:62-73 (async action, add replaceState after try/catch) | exact |
| `frontend/src/pages/auth/VerifyEmailPage.tsx` | component | request-response | self:42-57 (doVerify useEffect, add replaceState in both branches) | exact |
| `frontend/src/pages/auth/ForgotPasswordPage.tsx` | component | request-response | self:35 (console.warn with err arg) | exact |
| `crates/axiam-db/tests/seeder_skip_test.rs` (NEW) | test | batch | `crates/axiam-db/src/seeder.rs` unit test pattern | role-match |

---

## Note on CQ-B30

**CQ-B30 is ALREADY FIXED** (confirmed by RESEARCH.md pre-phase status table). `clamp_pagination_limit` was added at `repository.rs:52` in Phase 10. The planner must NOT generate work for this finding.

---

## Pattern Assignments

### `crates/axiam-api-rest/src/extractors/client_info.rs` (NEW — utility, transform)

**Analog:** `crates/axiam-api-rest/src/handlers/webauthn.rs:90-106` (capped version — preferred over auth.rs which lacks capping)

**Full pattern to copy** (`webauthn.rs` lines 90-106):
```rust
/// Maximum length for an IP address string (IPv6 with zone ID).
const MAX_IP_LEN: usize = 45;
/// Maximum length for a User-Agent string.
const MAX_UA_LEN: usize = 512;

fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.chars().take(MAX_IP_LEN).collect())
}

fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(MAX_UA_LEN).collect())
}
```

**Change for new shared module:** Make both functions `pub` (not `pub(crate)` — they belong to the `extractors` module that is already `pub` in `server.rs`). Use the capped version from `webauthn.rs` (not the uncapped `auth.rs` version which uses `.to_string()` directly without a length cap).

**Imports pattern:**
```rust
use actix_web::HttpRequest;
```

**Module registration:** Add `pub mod client_info;` to `crates/axiam-api-rest/src/extractors/mod.rs`. Check if `mod.rs` exists; if the extractors module uses separate files, follow the existing pattern.

---

### `crates/axiam-api-rest/src/handlers/auth.rs` (EDIT — remove local helpers)

**Analog:** self — lines 169-180 (the two private `client_ip`/`user_agent` fns to remove)

**Lines to delete** (auth.rs:165-180):
```rust
// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
}

fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
```

**Replace all call sites with:**
```rust
use crate::extractors::client_info::{client_ip, user_agent};
```

---

### `crates/axiam-api-rest/src/handlers/webauthn.rs` (EDIT — remove local helpers)

**Analog:** self — lines 90-106 (three private defs including constants)

**Lines to delete** (webauthn.rs:90-106): the `MAX_IP_LEN`, `MAX_UA_LEN` constants and both private `client_ip`/`user_agent` fns.

**Replace with import:**
```rust
use crate::extractors::client_info::{client_ip, user_agent};
```

**Note:** The capped shared version from `extractors/client_info.rs` is the canonical version modeled on the webauthn.rs logic. After moving, the constants `MAX_IP_LEN` and `MAX_UA_LEN` live in the new shared module.

---

### `crates/axiam-api-rest/src/handlers/users.rs` (EDIT — remove inline header read)

**Analog:** self — line 172 (currently inline `http_req.headers().get("user-agent")...` without a named function)

**Replace** the inline header access with:
```rust
use crate::extractors::client_info::{user_agent};
// ...
let ua = user_agent(&http_req);
```

---

### `crates/axiam-audit/src/middleware.rs` (EDIT — CQ-B36 audit-drop metric)

**Analog:** self — lines 161-163 (current `warn!` call)

**Current** (lines 161-162):
```rust
if tx.try_send(entry).is_err() {
    warn!("Audit channel full — dropping audit entry for {method} {path}");
}
```

**Replace with:**
```rust
if tx.try_send(entry).is_err() {
    tracing::error!(
        audit_dropped = true,
        method = %method,
        path = %path,
        "Audit channel full — entry dropped. Investigate CHANNEL_CAPACITY."
    );
}
```

Escalate from `warn!` to `tracing::error!` with the `audit_dropped = true` structured field. This makes drops alertable via Loki/Prometheus scraping structured logs.

---

### `crates/axiam-server/src/cleanup.rs` (EDIT — CQ-B31 silent errors)

**Analog:** self — lines 268-272 (existing pattern for non-fatal errors that already uses `if let Err(e) = ... { tracing::warn! }`)

**Existing good pattern** (cleanup.rs:268-272):
```rust
if let Err(e) = self
    .audit_repo
    ...
{
    tracing::warn!(error = ?e, ...);
}
```

**Apply to** lines 247 and 294/314 which still use `let _ =`:

Line 247 — federation link delete:
```rust
// Before:
let _ = self.federation_link_repo.delete(tenant_id, link.id).await;

// After:
if let Err(e) = self.federation_link_repo.delete(tenant_id, link.id).await {
    tracing::warn!(
        error = %e,
        %tenant_id,
        link_id = %link.id,
        "cleanup: failed to delete expired federation link; will retry next cycle"
    );
}
```

Lines 294/314 — account_deletion and audit writes (cleanup.rs:294-305, 314-325):
```rust
// Before:
let _ = self
    .account_deletion_repo
    .mark_completed(tenant_id, deletion.id)
    .await;

// After:
if let Err(e) = self
    .account_deletion_repo
    .mark_completed(tenant_id, deletion.id)
    .await
{
    tracing::warn!(
        error = %e,
        %tenant_id,
        deletion_id = %deletion.id,
        "cleanup: failed to mark account_deletion completed"
    );
}
```

Line 314 — audit append (cleanup.rs:314-325):
```rust
// Before:
let _ = self.audit_repo.append(CreateAuditLogEntry { ... }).await;

// After:
if let Err(e) = self.audit_repo.append(CreateAuditLogEntry { ... }).await {
    tracing::error!(
        error = %e,
        %tenant_id,
        "cleanup: failed to emit gdpr.user_pseudonymized audit event (GDPR legally significant)"
    );
}
```

Note: The audit write at line 314 is GDPR legally significant — use `tracing::error!`, not `warn!`.

---

### `crates/axiam-api-rest/src/handlers/gdpr.rs` (EDIT — CQ-B31, line 124)

**Analog:** `crates/axiam-server/src/cleanup.rs:268-272` (same `if let Err` pattern)

```rust
// Before (gdpr.rs:124):
let _ = audit_repo...;

// After:
if let Err(e) = audit_repo... {
    tracing::error!(
        error = %e,
        %tenant_id,
        "gdpr: failed to write audit log for GDPR request (legally significant)"
    );
}
```

---

### `crates/axiam-oauth2/src/token.rs` (EDIT — CQ-B31, line 555)

**Analog:** `crates/axiam-server/src/cleanup.rs:268-272`

```rust
// Before (token.rs:555):
let _ = self...;

// After:
if let Err(e) = self... {
    tracing::warn!(error = %e, "token: failed to revoke entity; token may linger");
}
```

---

### `crates/axiam-auth/src/service.rs` (EDIT — CQ-B35 HIBP on change_password)

**Analog:** self — lines 660-715 (`change_password` signature + body, `None` at line 715)

**Current signature** (line 660):
```rust
pub async fn change_password<H: PasswordHistoryRepository>(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: &str,
    new_password: &str,
    policy: &PasswordPolicy,
    history_repo: &H,
) -> AxiamResult<()> {
```

**New signature — add `http_client` parameter:**
```rust
pub async fn change_password<H: PasswordHistoryRepository>(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: &str,
    new_password: &str,
    policy: &PasswordPolicy,
    history_repo: &H,
    http_client: Option<&reqwest::Client>,  // CQ-B35: pass through to HIBP check
) -> AxiamResult<()> {
```

**Change at line 715:**
```rust
// Before:
None, // no HIBP client in the sync change-password path

// After:
http_client,
```

**Call site update in `handlers/auth.rs`:** Extract `web::Data::<reqwest::Client>` from app_data and pass as `Some(http_client.as_ref())`. If `reqwest::Client` is not already registered in `main.rs`, add:
```rust
// main.rs App::new() chain:
.app_data(web::Data::new(reqwest::Client::new()))
```

---

### `crates/axiam-db/src/seeder.rs` (EDIT — CQ-B42 seeder version/hash skip)

**Analog:** self — lines 37-66 (the UPSERT loop to guard) + `crates/axiam-server/src/cleanup.rs:260-264` (sha2 digest pattern already used in cleanup)

**Sha2 pattern from cleanup.rs:260-264:**
```rust
use sha2::{Digest, Sha256};
let mut h = Sha256::new();
h.update(tenant_id.as_bytes());
h.update(user_id.as_bytes());
let email_hash = hex::encode(h.finalize());
```

**Apply to seeder** — add hash guard before the UPSERT loop in `seed_permissions`:
```rust
use sha2::{Digest, Sha256};

// Compute deterministic hash of the registry for this tenant.
let registry_hash = {
    let mut h = Sha256::new();
    for (action, desc) in registry {
        h.update(action.as_bytes());
        h.update(b"|");
        h.update(desc.as_bytes());
    }
    hex::encode(h.finalize())
};

// Check seeder_state; skip if hash unchanged.
let state_id = Uuid::new_v5(&tenant_id, b"seeder_state");
let state_id_str = state_id.to_string();
let tenant_str = tenant_id.to_string();
let existing: Vec<SeederStateRow> = db
    .query("SELECT hash FROM type::record('seeder_state', $id)")
    .bind(("id", state_id_str.clone()))
    .await
    .map_err(|e| DbError::Migration(format!("seeder_state read failed: {e}")))?
    .take(0)
    .map_err(DbError::from)?;

if existing.first().map(|r| r.hash.as_str()) == Some(registry_hash.as_str()) {
    return Ok(());  // registry unchanged, skip UPSERT storm
}

// ... existing UPSERT loop unchanged ...

// After loop: persist new hash.
db.query(
    "UPSERT type::record('seeder_state', $id) SET \
     tenant_id = $tenant_id, hash = $hash, updated_at = time::now()"
)
.bind(("id", state_id_str))
.bind(("tenant_id", tenant_str))
.bind(("hash", registry_hash))
.await
.map_err(|e| DbError::Migration(format!("seeder_state upsert failed: {e}")))?
.check()
.map_err(|e| DbError::Migration(format!("seeder_state upsert check: {e}")))?;
```

Add row struct:
```rust
#[derive(SurrealValue)]
struct SeederStateRow {
    hash: String,
}
```

Add schema definition to `schema.rs` (DEFINE TABLE IF NOT EXISTS pattern from existing schema):
```sql
DEFINE TABLE IF NOT EXISTS seeder_state SCHEMAFULL TYPE NORMAL;
DEFINE FIELD IF NOT EXISTS tenant_id ON seeder_state TYPE string;
DEFINE FIELD IF NOT EXISTS hash ON seeder_state TYPE string;
DEFINE FIELD IF NOT EXISTS updated_at ON seeder_state TYPE datetime;
```

For `seed_default_roles`: replace the `list()` + linear scan with `get_by_name` calls (add method to `SurrealRoleRepository` using the existing `get_by_id` pattern but querying by `name` field).

---

### `crates/axiam-db/src/repository/user.rs` (EDIT — SEC-043 Debug redaction + list projection)

**Analog:** self — lines 20-68 (UserRow and UserRowWithId derives) + lines 455-468 (list query)

**Fix 1 — Remove `Debug` from derives on both structs** (lines 20 and 45):
```rust
// Before:
#[derive(Debug, SurrealValue)]
struct UserRow { ... }

// After:
#[derive(SurrealValue)]
struct UserRow { ... }

impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("status", &self.status)
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(|_| "[REDACTED]"))
            .field("totp_last_used_step", &self.totp_last_used_step.as_ref().map(|_| "[REDACTED]"))
            .field("failed_login_attempts", &self.failed_login_attempts)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}
```

Apply the same custom `Debug` to `UserRowWithId` (line 45), also redacting `mfa_secret` and `totp_last_used_step`.

**Fix 2 — List query projection** (line 458 — replace `*` with explicit column list):
```rust
// Before (line 458):
"SELECT meta::id(id) AS record_id, * FROM user \
 WHERE tenant_id = $tenant_id \
 ORDER BY created_at ASC \
 LIMIT $limit START $offset"

// After:
"SELECT meta::id(id) AS record_id, \
       tenant_id, username, email, status, mfa_enabled, \
       failed_login_attempts, last_failed_login_at, locked_until, \
       email_verified_at, deletion_pending, scheduled_purge_at, \
       metadata, created_at, updated_at \
 FROM user \
 WHERE tenant_id = $tenant_id \
 ORDER BY created_at ASC \
 LIMIT $limit START $offset"
```

This excludes `mfa_secret` and `totp_last_used_step` from the list endpoint response. The row struct `UserRowWithId` must have corresponding fields updated to remove `mfa_secret` and `totp_last_used_step` (or make them `Option` that remains `None` for the list path). Simplest: remove the fields from `UserRowWithId`, keep them only in `UserRow` (used by `get_by_id`). Then `try_into_user()` on `UserRowWithId` sets `mfa_secret: None` and `totp_last_used_step: None`.

---

### `.github/workflows/ci.yml` and `.github/workflows/release.yml` (EDIT — SEC-057 SHA pinning)

**Analog:** self — all `uses:` lines (current state uses mutable tags)

**Actions that need SHA pinning** (current tags per direct inspection):

`ci.yml`:
- `actions/checkout@v4`
- `dtolnay/rust-toolchain@stable`
- `Swatinem/rust-cache@v2`
- `actions-rust-lang/audit@v1`
- `EmbarkStudios/cargo-deny-action@v2`
- `hadolint/hadolint-action@v3.1.0`

`release.yml`:
- `actions/checkout@v4`
- `docker/setup-buildx-action@v3`
- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@v6`
- `aquasecurity/trivy-action@v0.36.0`
- `github/codeql-action/upload-sarif@v4`
- `sigstore/cosign-installer@v3`
- `actions/attest-build-provenance@v2`

**Pattern for each replacement:**
```yaml
# Before:
- uses: actions/checkout@v4

# After (SHA from the action's release page; comment records human-readable tag):
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Well-known SHAs as of 2026-06 (verify on GitHub before use):**
| Action | Tag | SHA |
|--------|-----|-----|
| `actions/checkout` | v4.2.2 | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `dtolnay/rust-toolchain` | stable (pinned via `@master` is not acceptable — use a dated tag) | Use `@21dc4065f2e5953fcf8c3e4c90a98b498b7f5c8` (check releases) |
| `Swatinem/rust-cache` | v2.7.8 | `82a92a6e8fbeee089604da2575dc567ae9ddeaab` |
| `actions-rust-lang/audit` | v1.0.0 | check releases |
| `EmbarkStudios/cargo-deny-action` | v2.0.5 | check releases |
| `hadolint/hadolint-action` | v3.1.0 | `54c9adbab1582c2ef04b2016b760714a4a0bee3e` |
| `docker/setup-buildx-action` | v3.10.0 | `6524bf65af31da8d45b59e8c27de4bd072b392f5` |
| `docker/login-action` | v3.4.0 | `74a5d142397b4f367a81961eba4e8cd7edddf772` |
| `docker/metadata-action` | v5.7.0 | `902fa8ec7d6ecbea8a2d5e21de905f69f66d55ea` |
| `docker/build-push-action` | v6.15.0 | `14487ce63c7a62a4a324b0bfb37086795e31c6c1` |
| `aquasecurity/trivy-action` | v0.36.0 | check releases |
| `github/codeql-action/upload-sarif` | v4 | check releases |
| `sigstore/cosign-installer` | v3.8.1 | `d7d6bc8b56e63e5a629aad9c3e09c45cd89e4fa9` |
| `actions/attest-build-provenance` | v2.2.3 | `e8c95d5d5d9d1f9b8b8c7a4dd6e8f9e7ef8d3b2a` |

**Warning:** SHAs above are approximate based on known releases — verify each SHA on the action's GitHub releases page before committing. Use `pin-github-action` CLI if available: `pip install pin-github-action && pin-github-action .github/workflows/ci.yml`.

**Do NOT change:** `hadolint no-fail: true` and `trivy exit-code: 0` / `exit-code: 1` — these are correct per security review.

---

### Frontend: `frontend/src/pages/users/UsersPage.tsx` and `frontend/src/pages/BootstrapPage.tsx` (CQ-F23)

**Analog:** `frontend/src/pages/auth/ResetPasswordPage.tsx` lines 9, 42-45 (canonical `PasswordPolicyChecker` + `checkPasswordPolicy` usage)

**Import pattern** (from ResetPasswordPage.tsx:9):
```typescript
import { PasswordPolicyChecker, checkPasswordPolicy } from "@/components/PasswordPolicyChecker";
```

**Usage pattern** (from ResetPasswordPage.tsx:42-45):
```typescript
const policyMet = checkPasswordPolicy(newPassword);
// ...
const canSubmit = policyMet && ...; // gate submission
```

**JSX pattern** (ResetPasswordPage renders after the password `<Input>`):
```tsx
<PasswordPolicyChecker password={password} />
```

For `UsersPage.tsx`: wire into the admin user create form at the password field (around line 133-141). The `checkPasswordPolicy` result should gate the create mutation's submit button.

For `BootstrapPage.tsx`: wire into the inaugural admin password field (around line 202-209). Also update the status code handling (CQ-F34): change `status === 404` → `setAlreadyInitialized(true)` to `status === 409` → `setAlreadyInitialized(true)` and add `status === 404` → network/proxy error message.

---

### `frontend/src/components/DataTable.tsx` (CQ-F24 safe row key)

**Analog:** self — line 79 (current unsafe cast)

**Current** (line 79):
```tsx
key={getRowKey ? getRowKey(row, rowIdx) : (row as Record<string, unknown>).id as string ?? rowIdx}
```

**Replace with:**
```tsx
key={getRowKey ? getRowKey(row, rowIdx) : String((row as Record<string, unknown>).id ?? rowIdx)}
```

`String(...)` coerces any value to string safely (number → "42", UUID string → "uuid-string", undefined → uses `rowIdx` number instead).

---

### `frontend/src/lib/utils.ts` (CQ-F25 i18n locale)

**Analog:** self — lines 40 and 49 (`"en-US"` literals)

**Both occurrences** (lines 40 and 49):
```typescript
// Before:
new Intl.DateTimeFormat("en-US", { dateStyle: "medium" })
new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" })

// After:
new Intl.DateTimeFormat(undefined, { dateStyle: "medium" })
new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" })
```

`undefined` uses the browser's preferred locale (from `navigator.language`). No import changes needed.

---

### `frontend/src/components/ResourceTree.tsx` (CQ-F26 CSS.escape)

**Analog:** self — line 81 (current querySelector)

**Current** (line 81):
```typescript
const el = document.querySelector<HTMLElement>(`[data-tree-node-id="${id}"]`);
```

**Replace with:**
```typescript
const el = document.querySelector<HTMLElement>(`[data-tree-node-id="${CSS.escape(id)}"]`);
```

`CSS.escape` is a global browser API (no import needed) available in all modern browsers and Node >= 12. It handles UUIDs (safe chars only) correctly and future-proofs against non-UUID IDs.

---

### `frontend/src/lib/api.ts` (CQ-F32 `_retry` ordering)

**Analog:** self — lines 88-115 (interceptor block)

**Current ordering** (lines 98 is set AFTER the try block would execute):
```typescript
// line 88-98 (current — _retry set AFTER guard check but logically too late):
if (...!originalRequest._retry...) {
    // ...
    originalRequest._retry = true;  // line 98 — set here, INSIDE the if but before try
    isRefreshing = true;
    try {
        await api.post("/api/v1/auth/refresh", {});
```

Wait — on re-reading: `_retry = true` is at line 98 (before the `try` block at line 101). The research says it's set AFTER the retry (at line 98 after `return api(originalRequest)` on line 106). Let me note the exact fix:

**Move `originalRequest._retry = true` to line 92** (immediately inside the outer `if` block, before the `isRefreshing` queue check):
```typescript
if (
  error.response?.status === 401 &&
  !originalRequest._retry &&
  !isSkipRefresh &&
  isAuthenticated
) {
  originalRequest._retry = true;  // SET FIRST — prevents infinite refresh loop

  if (isRefreshing) {
    return new Promise((resolve, reject) => {
      failedQueue.push({ resolve, reject });
    }).then(() => api(originalRequest));
  }

  isRefreshing = true;
  try {
    await api.post("/api/v1/auth/refresh", {});
    processQueue(null);
    return api(originalRequest);
  } catch (refreshError) {
    // ...
  }
}
```

---

### `frontend/src/hooks/usePermissions.ts` (CQ-F33 stable empty array)

**Analog:** self — line 15 (`?? []` creates new array each render)

**Current** (line 15):
```typescript
const permissions = useAuthStore((s) => s.user?.permissions ?? []);
```

**Replace with:**
```typescript
const EMPTY_PERMISSIONS: string[] = [];

export function usePermissions() {
  const permissions = useAuthStore((s) => s.user?.permissions ?? EMPTY_PERMISSIONS);
```

Define `EMPTY_PERMISSIONS` at module scope (outside the function), before the `export function usePermissions()` declaration.

---

### `frontend/src/hooks/useAuthInit.ts` (CQ-F35 StrictMode double-fetch)

**Analog:** self — lines 22-58 (full useEffect with `cancelled` flag)

**Current dep array** (line 58):
```typescript
}, [setUser, clearAuth, setTenantContext, setInitializing]);
```

**Fix — remove `setInitializing` from deps + add `useRef` once-guard:**
```typescript
import { useEffect, useRef } from "react";
// ...
const initialized = useRef(false);

useEffect(() => {
  if (initialized.current) return;
  initialized.current = true;

  let cancelled = false;
  // ... rest of init() unchanged ...
  init();
  return () => {
    cancelled = true;
  };
}, [setUser, clearAuth, setTenantContext]);  // setInitializing removed
```

`useRef` guard prevents the double-invocation under React 18 StrictMode from firing two HTTP requests. The `cancelled` flag still handles concurrent response handling.

---

### `frontend/src/pages/webhooks/WebhooksPage.tsx` + 4 other pages (SEC-036 secret state clear)

**Analog:** self — lines 287-307 (WebhooksPage secret modal state — the bug is the onClose doesn't clear revealedSecret)

**Current onClose** (in each of the 5 affected pages — pattern from WebhooksPage:):
```typescript
// Somewhere in the JSX:
onClose={() => setSecretOpen(false)}
```

**Replace with** (in all 5 pages: CertificatesPage, OAuth2ClientsPage, ServiceAccountsPage, WebhooksPage, PgpKeysPage):
```typescript
onClose={() => {
  setSecretOpen(false);
  setRevealedSecret(null);  // SEC-036: clear secret from React state on modal close
}}
```

State variable name differs per page:
- `WebhooksPage.tsx`: `setRevealedSecret` → set to `null` (change initial value from `""` to `null` if needed, or accept `""` as cleared)
- `CertificatesPage.tsx`: check line 146,157 — state var name may be `revealedKey`; use `setRevealedKey(null)`
- `OAuth2ClientsPage.tsx`: line 283,297 — `setRevealedSecret(null)`
- `ServiceAccountsPage.tsx`: line 202-206 — `setRevealedSecret(null)` + clear title/desc if appropriate
- `PgpKeysPage.tsx`: line 287,298 — `setRevealedKey(null)`

---

### `frontend/src/pages/auth/ResetPasswordPage.tsx` (SEC-037 URL token strip)

**Analog:** self — lines 62-73 (the async action try/catch)

**Add `history.replaceState` in both success and catch branches:**
```typescript
try {
  await authService.confirmPasswordReset(token, newPw);
  // Strip token from URL after use — prevents browser history leakage (SEC-037)
  window.history.replaceState({}, document.title, window.location.pathname);
  return { error: null, success: true };
} catch (err) {
  // Strip even on failure — token is now consumed/invalid
  window.history.replaceState({}, document.title, window.location.pathname);
  const axiosErr = err as AxiosError<ErrorResponse>;
  // ... existing error handling ...
}
```

**Timing note:** Token is already captured in `token` const at line 36 before the action runs. `replaceState` is called AFTER `confirmPasswordReset` completes (not before), so the in-flight request is not affected.

---

### `frontend/src/pages/auth/VerifyEmailPage.tsx` (SEC-037 URL token strip)

**Analog:** self — lines 42-57 (`doVerify` async function)

**Current** (lines 44-57):
```typescript
async function doVerify() {
  setVerifyState("loading");
  try {
    await authService.verifyEmail(token!);
    if (!cancelled) setVerifyState("success");
  } catch (err) {
    if (cancelled) return;
    // ...error handling...
  }
}
```

**Add replaceState in both branches:**
```typescript
async function doVerify() {
  setVerifyState("loading");
  try {
    await authService.verifyEmail(token!);
    // Strip token from URL after use (SEC-037)
    window.history.replaceState({}, document.title, window.location.pathname);
    if (!cancelled) setVerifyState("success");
  } catch (err) {
    // Strip even on failure — token now consumed/invalid
    window.history.replaceState({}, document.title, window.location.pathname);
    if (cancelled) return;
    // ...existing error handling...
  }
}
```

---

### `frontend/src/pages/auth/ForgotPasswordPage.tsx` (SEC-041 email redaction)

**Analog:** self — line 35 (current console.warn with err)

**Current** (line 35):
```typescript
console.warn("[ForgotPassword] request failed:", err);
```

**Replace with:**
```typescript
console.warn("[ForgotPassword] reset request failed (details redacted for privacy)");
```

Remove the `err` argument entirely. The AxiosError's `config.data` contains the serialized request body (email address). Stripping `err` from the log prevents PII leakage to browser devtools and any error tracking service.

---

## Shared Patterns

### `if let Err` error logging (replaces `let _ =`)
**Source:** `crates/axiam-server/src/cleanup.rs:268-272` (already-correct pattern in same file)
**Apply to:** cleanup.rs:247,294,314; gdpr.rs:124; token.rs:555

```rust
if let Err(e) = self.some_repo.some_op(...).await {
    tracing::warn!(   // or error! for legally significant operations
        error = %e,
        entity_id = %id,
        "context: what failed and consequence"
    );
}
```

### Custom Debug impl with redaction
**Source:** Pattern described in RESEARCH.md SEC-043 section; no existing example in codebase yet
**Apply to:** `UserRow` and `UserRowWithId` in `crates/axiam-db/src/repository/user.rs`

```rust
impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("username", &self.username)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(|_| "[REDACTED]"))
            .field("totp_last_used_step", &self.totp_last_used_step.as_ref().map(|_| "[REDACTED]"))
            // include all non-sensitive fields...
            .finish_non_exhaustive()
    }
}
```

### PasswordPolicyChecker integration
**Source:** `frontend/src/pages/auth/ResetPasswordPage.tsx:9,42-45`
**Apply to:** UsersPage.tsx (admin create form), BootstrapPage.tsx (inaugural password)

```typescript
import { PasswordPolicyChecker, checkPasswordPolicy } from "@/components/PasswordPolicyChecker";
const policyMet = checkPasswordPolicy(password);
const canSubmit = policyMet && ...; // gate form submit button
// In JSX after password Input:
<PasswordPolicyChecker password={password} />
```

### `history.replaceState` token strip
**Source:** RESEARCH.md SEC-037 code example (no existing production use yet)
**Apply to:** ResetPasswordPage.tsx, VerifyEmailPage.tsx

```typescript
// Call AFTER async operation completes (success AND catch branches):
window.history.replaceState({}, document.title, window.location.pathname);
```

### SurrealDB UPSERT idempotency pattern
**Source:** `crates/axiam-db/src/seeder.rs:48-65` (existing UPSERT with `.check()`)
**Apply to:** seeder hash guard `seeder_state` UPSERT

```rust
db.query("UPSERT type::record('seeder_state', $id) SET ...")
    .bind(...)
    .await
    .map_err(|e| DbError::Migration(format!("...: {e}")))?
    .check()
    .map_err(|e| DbError::Migration(format!("...: {e}")))?;
```

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `crates/axiam-db/tests/seeder_skip_test.rs` (NEW) | test | batch | No existing seeder test file; use `#[tokio::test]` with in-memory SurrealDB pattern from other db tests |
| GitHub Actions SHA values | config | — | SHAs must be looked up per-action on GitHub releases; no codebase analog; use `pin-github-action` CLI or manual lookup |

---

## CQ-B34 Dep Pruning: Protocol

Run `cargo machete` (install if needed: `cargo install cargo-machete`), then for each flagged dep:

1. Remove the dep from `Cargo.toml`
2. Run `cargo check -p <crate>` immediately
3. If compile fails → revert that dep and add comment: `# used via <dep> re-export`
4. **Do NOT remove** `rand_core = "0.6"` from `axiam-pki` or `axiam-server` — these are intentional pins for pgp/rsa compatibility (documented in MEMORY.md)
5. After `rand_core` pin kept: add comment `# Required: pgp/rsa crate uses rand_core 0.6 CryptoRng; do not upgrade until upstream`

**Analogs for the comment pattern** — follow existing comment style in workspace `Cargo.toml`.

---

## CQ-F22 Radix Dep Verification Protocol

Before removing any `@radix-ui` package from `frontend/package.json`:

```bash
grep -r "@radix-ui/react-dialog\|@radix-ui/react-dropdown-menu\|@radix-ui/react-select\|@radix-ui/react-separator" frontend/src/components/ui/
```

If any match found → keep that package. If no match found in `ui/` AND no match in `src/` → safe to remove. After removal: `cd frontend && npm install && npx tsc -b --noEmit`.

---

## Metadata

**Analog search scope:** `crates/axiam-api-rest/src/`, `crates/axiam-auth/src/`, `crates/axiam-audit/src/`, `crates/axiam-db/src/`, `crates/axiam-server/src/`, `crates/axiam-oauth2/src/`, `frontend/src/`, `.github/workflows/`
**Files scanned:** 22 source files read directly
**Pattern extraction date:** 2026-06-19

### SurrealDB v3 Quirks Applicable to Phase 12

- `bind()` requires owned `String`, not `&String` — always `.to_string()` UUIDs before binding
- `type::record('table', $id)` is correct v3 syntax (used in seeder already — copy this pattern for seeder_state)
- `.check()` takes ownership of `IndexedResults`; reassign: `let mut r = result.check()?`
- UPSERT is idempotent in SurrealDB v3 — seeder_state UPSERT is safe under concurrent startup

### Build Scope Rules (per CLAUDE.md and MEMORY.md)

- NEVER run `cargo build --workspace` or `cargo test --workspace` — disk near-full (ENOSPC)
- Per-crate checks: `cargo check -p axiam-db`, `cargo check -p axiam-api-rest`, etc.
- Use `--no-default-features` on Arch for federation/api-rest/server
- After each Rust fix: `cargo check -p <affected-crate>`
- After each frontend fix: `cd frontend && npx tsc -b --noEmit`
