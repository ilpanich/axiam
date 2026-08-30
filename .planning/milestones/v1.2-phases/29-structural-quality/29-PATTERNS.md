# Phase 29: Structural Quality - Pattern Map

**Mapped:** 2026-07-06
**Files analyzed:** 6 new/modified symbol families (AppState struct, `paginate<T>`,
`classify_write_error`, `from_ca_cert_pem` CA reconstruction + shared `axiam-pki::crypto`,
tenant-predicated inline transactions, mechanical dedup adoptions)
**Analogs found:** 6 / 6 (this phase is overwhelmingly adoption/refactor of existing patterns —
every new symbol has a strong same-crate analog)

**Note on scope:** Per the phase's own research, most "files to modify" are mechanical adoption
sites (24 `CountRow` collapses, 79 `take_first_or_not_found` adoptions, 283 handler
`web::Data<T>`→`AppState<C>` rewrites, 11 frontend page migrations). Per the orchestrator's
instruction, one representative analog per family is documented below rather than enumerating
every site — the planner should apply the same excerpt shape to every remaining site in each family.

## File Classification

| New/Modified Symbol | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `AppState<C>` struct (new `crates/axiam-api-rest/src/state.rs`) | provider (DI composition root) | request-response | `crates/axiam-server/src/main.rs` `app_data` registration block (lines ~772-838) | exact — same fields, same generic `C`, just collapsed into one struct |
| `paginate<T>` (new fn in `crates/axiam-db/src/helpers.rs`) | utility | CRUD (list/count) | `crates/axiam-db/src/repository/webhook.rs::list` (count+list+`PaginatedResult` construction, lines ~280-319) + existing `helpers.rs::take_first_or_not_found`/`parse_uuid` (test style) | exact — generalizes the literal repeated 5-line tail of every list method |
| `classify_write_error` (new fn in `crates/axiam-db/src/helpers.rs` or `error.rs`) | utility (error classification) | request-response (create paths) | `crates/axiam-db/src/repository/saml_replay.rs:76-93` (centralized marker-string detection) | exact — same 3-marker-string set, same fallthrough-to-Migration shape |
| `from_ca_cert_pem` CA reconstruction (`crates/axiam-pki/src/cert.rs`) + shared `crates/axiam-pki/src/crypto.rs` module | service (crypto/PKI) | transform (cert signing) | `crates/axiam-pki/src/cert.rs:224` `build_ca_params` (function being replaced) + `crates/axiam-pki/src/ca.rs:150-168` (`generate_keypair`/`compute_fingerprint`/`encrypt_private_key` — the byte-identical triplicated helpers to consolidate) | exact — direct replacement + direct helper unification |
| Tenant-predicated inline `BEGIN/COMMIT` transactions (`role.rs::delete`, `resource.rs::delete`, GDPR `create_with_pending_flag`) | model/repository (multi-statement mutation) | CRUD (transactional delete/create) | `crates/axiam-db/src/repository/federation_login_state.rs:110-127` (`consume_by_state`, LET-capture + DELETE in one transaction) and `crates/axiam-db/src/repository/user.rs:736-760` (`create_with_consent`, 3-statement CREATE transaction) | exact — same inline SQL idiom, same `.take(N)` slot convention |
| Mechanical family: `CountRow`/`take_first_or_not_found` adoption (24 + 79 sites) | model/repository | CRUD | `crates/axiam-db/src/repository/user.rs` and `role.rs` (already-migrated exemplars per research) + `helpers.rs` canonical definitions | exact — literal 1:1 substitution |
| Mechanical family: frontend shared-component/service adoption (11 pages) | component/hook | request-response | `frontend/src/components/shared.tsx` (`ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`), `frontend/src/hooks/useCrudMutations.ts`, `frontend/src/services/users.ts` | exact — canonical shared modules already exist, unadopted |

## Pattern Assignments

### `crates/axiam-api-rest/src/state.rs` — new `AppState<C>` (provider, request-response)

**Analog:** `crates/axiam-server/src/main.rs` (current `app_data` registration block)

**Current composition-root pattern to collapse** (`main.rs`, ~lines 772-838):
```rust
let app = App::new()
    .wrap(SecurityHeadersMiddleware)
    .wrap(TracingLogger::default())
    .wrap(audit_middleware.clone())
    .wrap(build_cors(&server_config.cors_allowed_origins))
    .app_data(web::Data::new(rest_authz.clone()))
    .app_data(web::Data::new(config.authz.clone()))
    .app_data(web::Data::new(auth_config.clone()))
    .app_data(web::Data::new(db_handle.clone()))
    // ... 44 more identical .app_data(web::Data::new(x.clone())) lines ...
    .app_data(web::Data::new(Arc::clone(&crypto_semaphore)));
// Conditional dep (D-02 precedent — mirror this exact shape for other Option<> fields):
let app = match &email_config_repo {
    Some(repo) => app.app_data(web::Data::new(repo.clone())),
    None => app,
};
app.configure(health_routes)
    .configure(|cfg| register_api_v1_routes::<axiam_db::DbClient>(cfg, &rl))
    .configure(openapi_routes)
```

**Target shape:** one `AppState<C: surrealdb::Connection + Clone>` struct with one field per
current registration (48 fields total, including `email_config_repo: Option<SurrealEmailConfigRepository<C>>`
using the exact `Option<>` pattern already shown above), built once and registered with a single
`.app_data(web::Data::new(app_state.clone()))`. The generic bound must mirror the existing bound
already used identically by production and tests:
```rust
// crates/axiam-api-rest/src/server.rs:61 — mirror this exact generic bound on AppState<C>
pub fn register_api_v1_routes<C: surrealdb::Connection + Clone>(
    cfg: &mut web::ServiceConfig,
    rate_limit_cfg: &RateLimitConfig,
)
```

**Handler extraction rewrite pattern** (apply to all 283 sites across 28 handler files, e.g.
`handlers/users.rs`): change each `dep: web::Data<SurrealUserRepository<C>>` parameter to
`state: web::Data<AppState<C>>` and rewrite body references `dep.method(...)` → `state.user_repo.method(...)`.

**Non-handler extraction sites requiring the same treatment (do not miss these — not in the "283" count):**
- `crates/axiam-api-rest/src/extractors/auth.rs:97,150,193,207` — `.app_data::<web::Data<Arc<dyn SessionValidator>>>()` / `.app_data::<web::Data<AuthConfig>>()`
- `crates/axiam-api-rest/src/extractors/cert_auth.rs:36`
- `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs:192`
- `crates/axiam-api-rest/src/health.rs:61`

**Test-harness adoption:** ~35 test files each define one `macro_rules! test_app! { ... }` (or a
small number of variants) that independently builds an `App::new()...app_data(...)` chain — update
each macro definition to construct and register one `AppState<C>`, not each individual call site.

**Hoisted per-request services (D-18):** fold these into `AppState` as singleton fields instead of
constructing per-request:
```rust
// BEFORE (password_reset.rs:162, :292 — per-request construction):
let service = PasswordResetService::new(user_repo.clone(), token_repo.clone(), ...);
// AFTER: state.password_reset_service.method(...)
```
All 13 sites (`PasswordResetService::new` ×2, `EmailVerificationService::new` ×2,
`OidcFederationService::new` ×4, `SamlFederationService::new` ×5) were confirmed to carry no
per-request state (`tenant_id` always passed to the method call, never baked into the constructor)
— safe to hoist uniformly. The 5 SAML constructions are behind `#[cfg(feature = "saml")]` on the
*handlers* only, not on the constructor's dependencies — construct the `SamlFederationService`
field unconditionally in `main.rs` to avoid cfg-attribute sprawl on `AppState`'s field list.

---

### `crates/axiam-db/src/helpers.rs` — new `paginate<T>` (utility, CRUD)

**Analog 1 — the boilerplate it replaces** (`crates/axiam-db/src/repository/webhook.rs:280-319`):
```rust
let count_result = self.db.query(
        "SELECT count() AS total FROM webhook WHERE tenant_id = $tenant_id GROUP ALL")
    .bind(("tenant_id", tid.clone())).await.map_err(DbError::from)?;
let mut count_result = count_result.check().map_err(|e| DbError::Migration(e.to_string()))?;
let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
let total = count_rows.first().map(|r| r.total).unwrap_or(0);
// ... list query ...
Ok(PaginatedResult { items, total, offset: pagination.offset, limit: pagination.limit })
```

**Analog 2 — existing `helpers.rs` function shape + doc-comment + test style to mirror exactly**
(`crates/axiam-db/src/helpers.rs:1-51`):
```rust
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use crate::error::DbError;

#[derive(Debug, SurrealValue)]
pub struct CountRow {
    pub total: u64,
}

pub fn parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError> {
    s.parse::<Uuid>()
        .map_err(|e| DbError::Migration(format!("invalid {field} UUID: {e}")))
}

pub fn take_first_or_not_found<T>(items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError> {
    items.into_iter().next().ok_or_else(|| DbError::NotFound {
        entity: entity.to_string(),
        id: id.to_string(),
    })
}
```

**New function to add, following the exact same doc-comment/signature convention:**
```rust
/// Assemble a `PaginatedResult<T>` from an already-fetched item page and its
/// count-query result. Collapses the identical 5-line "extract total +
/// construct PaginatedResult" boilerplate repeated in every list-repo method.
pub fn paginate<T>(
    items: Vec<T>,
    count_rows: Vec<CountRow>,
    pagination: &Pagination,
) -> PaginatedResult<T> {
    let total = count_rows.first().map(|r| r.total).unwrap_or(0);
    PaginatedResult {
        items,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
    }
}
```

**Test style to mirror** (`helpers.rs:57-118`'s `#[cfg(test)] mod tests` with `use super::*;` and
one `#[test] fn <name>_<condition>_<expectation>()` per case) — add `paginate_empty_count_rows_defaults_to_zero`
and `paginate_preserves_pagination_offset_and_limit`.

**Mechanical adoption family (24 `CountRow` + 79 `take_first_or_not_found` sites):** `user.rs` and
`role.rs` are already-migrated exemplars — grep either file for `use crate::helpers::{CountRow, parse_uuid};`
to see the target import shape every other of the 24 files should converge on. For
`take_first_or_not_found`, the replacement is a direct 1:1 swap of:
```rust
// BEFORE (79 sites, e.g. tenant.rs:126):
items.into_iter().next().ok_or_else(|| DbError::NotFound { entity: "tenant".into(), id: id_str.clone() })?
// AFTER:
helpers::take_first_or_not_found(items, "tenant", &id_str)?
```

**`parse_uuid` duplicate to delete** (`crates/axiam-db/src/repository/federation_link.rs:44`):
```rust
// DELETE this local fn (different signature — 1 arg, no field name):
fn parse_uuid(s: &str) -> Result<Uuid, DbError> {
    Uuid::parse_str(s).map_err(|e| DbError::Migration(e.to_string()))?
}
// Replace its 7 call sites with helpers::parse_uuid(s, "field_name") — field names per
// research: record_id (:65), tenant_id (:52,:68), user_id (:53,:69), federation_config_id (:54,:70)
```

---

### `crates/axiam-db/src/helpers.rs` — new `classify_write_error` (utility, error classification)

**Analog — the exact centralized-detection precedent already proven in 3 files, reuse verbatim**
(`crates/axiam-db/src/repository/saml_replay.rs:76-93`):
```rust
result
    .check()
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique") {
            AxiamError::ReplayDetected
        } else {
            AxiamError::Database(msg)
        }
    })
    .map(|_| ())
```

**`DbError` enum to extend** (`crates/axiam-db/src/error.rs:7-27` — full file, already read):
```rust
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("SurrealDB error: {0}")]
    Surreal(#[from] surrealdb::Error),
    #[error("SurrealDB authentication unhealthy: {0}")]
    Unhealthy(String),
    #[error("Migration failed: {0}")]
    Migration(String),
    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },
    #[error("Record already exists: {entity}")]
    AlreadyExists { entity: String },
    // ADD (D-10): Serialization(String) — parse_uuid's corrupt-read errors move here
}

impl From<DbError> for AxiamError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound { entity, id } => AxiamError::NotFound { entity, id },
            DbError::AlreadyExists { entity } => AxiamError::AlreadyExists { entity },
            other => AxiamError::Database(other.to_string()),
            // Serialization falls through this catch-all automatically — zero changes needed here
        }
    }
}
```

**New function, mirroring `saml_replay.rs`'s shape but returning `DbError` instead of `AxiamError`:**
```rust
/// Classify a checked SurrealDB query-execution error: genuine unique/index
/// violations map to `DbError::AlreadyExists`; everything else (including DB
/// outages) falls through unchanged so it still maps to a 5xx (CQ-B11/17).
pub fn classify_write_error(err: surrealdb::Error, entity: &str) -> DbError {
    let msg = err.to_string();
    if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique") {
        DbError::AlreadyExists { entity: entity.to_string() }
    } else {
        DbError::Migration(msg)
    }
}
```

**Call-site rewrite pattern** (`user.rs` CREATE sites `:252`, `:285`, `:725`, `:780`):
```rust
// BEFORE:
.map_err(|e| DbError::Migration(e.to_string()))?
// AFTER:
.map_err(|e| helpers::classify_write_error(e, "user"))?
```

**OAuth2 sites (D-11) — different shape, match on `AxiamError` not raw `surrealdb::Error`**
(5 identical sites: `authorize.rs:67`, `token.rs:175,346,454,745`):
```rust
// BEFORE:
.get_by_client_id(tenant_id, client_id).await
    .map_err(|_| OAuth2Error::InvalidClient("client not found".into()))?
// AFTER:
.get_by_client_id(tenant_id, client_id).await
    .map_err(|e| match e {
        AxiamError::NotFound { .. } => OAuth2Error::InvalidClient("client not found".into()),
        other => OAuth2Error::ServerError(other.to_string()),
    })?
```

---

### `crates/axiam-pki/src/cert.rs` — `from_ca_cert_pem` reconstruction + `crates/axiam-pki/src/crypto.rs` (service, transform)

**Analog — the function being replaced** (`crates/axiam-pki/src/cert.rs:224-231`, already read):
```rust
/// Build minimal CA params for rcgen (used to reconstruct CA certificate for signing).
fn build_ca_params(subject: &str) -> AxiamResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| AxiamError::Certificate(e.to_string()))?;
    params.distinguished_name.push(DnType::CommonName, subject);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    Ok(params)
}
```

**Replacement pattern (from rcgen's own vendored test suite, `rcgen-0.13.2/src/certificate.rs:1466`):**
```rust
let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
let ca_kp = KeyPair::from_pem(ca_key_pem)?;
let ca_cert = params.self_signed(&ca_kp)?; // use `ca_cert` as the issuer in signed_by()
```
Requires adding `features = ["x509-parser"]` to `rcgen = { workspace = true }` in
`crates/axiam-pki/Cargo.toml:19` (the `pem` feature is already default-on).

**Analog for triplicated helper unification** — byte-identical `generate_keypair`/`compute_fingerprint`
in both `ca.rs:150-168` and `cert.rs:224-260`:
```rust
// ca.rs:150-158 (identical to cert.rs's copy — this is the pattern to lift into crypto.rs)
fn generate_keypair(algorithm: &KeyAlgorithm) -> AxiamResult<KeyPair> {
    match algorithm {
        KeyAlgorithm::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| AxiamError::Certificate(format!("Ed25519 keygen failed: {e}"))),
        KeyAlgorithm::Rsa4096 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
            .map_err(|e| AxiamError::Certificate(format!("RSA-4096 keygen failed: {e}"))),
    }
}

fn compute_fingerprint(der: &[u8]) -> String {
    let hash = Sha256::digest(der);
    hex::encode(hash)
}
```
Move these plus the AES-256-GCM `encrypt_private_key`/`decrypt_private_key` pair (functionally
identical across `ca.rs`, `cert.rs`, `pgp.rs`) into a new internal `mod crypto;` in
`crates/axiam-pki/src/crypto.rs`, exporting `generate_keypair`, `compute_fingerprint`,
`encrypt_secret`, `decrypt_secret` (renamed from `_private_key` since PGP keys reuse them too).
`ca.rs`/`cert.rs` import these; `pgp.rs` keeps its own distinct `generate_keypair` (different key
type) but imports the shared encrypt/decrypt.

---

### `role.rs::delete` / `resource.rs::delete` / GDPR `create_with_pending_flag` — tenant-predicated transactions (model/repository, CRUD)

**Analog 1 — LET-capture + atomic DELETE, the exact pattern for the `resource.rs` child-guard fix**
(`crates/axiam-db/src/repository/federation_login_state.rs:110-127`, verified this session):
```rust
let mut result = self
    .db
    .query(
        "BEGIN TRANSACTION; \
         LET $row = (SELECT state, nonce, tenant_id, federation_config_id, \
                       redirect_uri, expires_at, request_id \
                     FROM federation_login_state \
                     WHERE state = $state LIMIT 1); \
         DELETE federation_login_state WHERE state = $state; \
         RETURN $row; \
         COMMIT TRANSACTION",
    )
    .bind(("state", state_owned))
    .await
    .map_err(DbError::from)?;
// Result slots: BEGIN=0, LET=1, DELETE=2, RETURN=3
let rows: Vec<FederationLoginStateRow> = result.take(3).map_err(|e| AxiamError::Database(e.to_string()))?;
```

**Analog 2 — multi-CREATE transaction, the exact pattern for GDPR's `create_with_pending_flag`**
(`crates/axiam-db/src/repository/user.rs:736-760`, per research — 3-statement CREATE with
documented `.take(N)` slot convention: "BEGIN=0, CREATE user=1, CREATE consent=2, CREATE
password_history=3, COMMIT=4").

**Current bug to fix in `role.rs::delete` (`:264-282`, confirmed by research):**
```rust
// CURRENT — no BEGIN/COMMIT at all, only the LAST statement is tenant-scoped:
let query = format!(
    "DELETE has_role WHERE out = role:`{id_str}`; \
     DELETE grants WHERE in = role:`{id_str}`; \
     DELETE type::record('role', $id) WHERE tenant_id = $tenant_id;"
);
```
Target: wrap in `BEGIN TRANSACTION; ... COMMIT TRANSACTION;` and add a tenant predicate to every
statement — **verify first** whether `has_role`/`grants` edge tables carry their own `tenant_id`
field (`schema.rs` `DEFINE FIELD ... ON TABLE has_role`/`grants`) before finalizing the exact
predicate shape (flat `WHERE tenant_id = ...` vs. a subquery against the node's tenant — this is
an open question the research flagged; resolve via `Grep schema.rs` before writing the SQL).

**Current bug to fix in `resource.rs::delete` (`:275-310`):** the child-count guard runs as a
separate `.query()` call (TOCTOU) before the cleanup query, and 2 of the 4 cleanup statements lack
tenant predicates. Target shape (mirroring analog 1's LET-capture idiom):
```sql
BEGIN TRANSACTION;
LET $child_count = (SELECT count() AS total FROM child_of
                    WHERE out = resource:`{id_str}` GROUP ALL);
DELETE child_of WHERE (in = resource:`{id_str}` OR out = resource:`{id_str}`)
    AND tenant_id = $tenant_id;
DELETE on_resource WHERE out = resource:`{id_str}` AND tenant_id = $tenant_id;
DELETE scope WHERE resource_id = $resource_id AND tenant_id = $tenant_id;
DELETE type::record('resource', $id) WHERE tenant_id = $tenant_id;
COMMIT TRANSACTION;
```
(Same edge-table `tenant_id`-field open question applies here — resolve before finalizing.)

**GDPR `create_with_pending_flag` target shape** (new method on `SurrealAccountDeletionRepository`,
replacing the two independent calls in `gdpr.rs::request_account_delete:451-495`):
```sql
BEGIN TRANSACTION;
UPDATE type::record('user', $user_id) SET
    deletion_pending = true, scheduled_purge_at = $purge_at,
    status = 'Inactive', updated_at = time::now()
    WHERE tenant_id = $tenant_id;
CREATE type::record('account_deletion', $ad_id) SET
    tenant_id = $tenant_id, user_id = $user_id,
    cancel_token_hash = $hash, scheduled_purge_at = $purge_at,
    status = 'pending', created_at = time::now();
COMMIT TRANSACTION;
```

---

### Frontend mechanical family (component/hook, request-response)

**Analog — canonical shared modules already exist, zero current adopters:**
- `frontend/src/components/shared.tsx` — `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`.
  Fix `ActionBadge` first (add `.toLowerCase()` before the `ACTION_COLOR_MAP[action]` lookup,
  matching `RoleDetailPage.tsx`'s local copy behavior) before migrating the 11 consumer pages off
  their local duplicates (`UserDetailPage.tsx`, `UsersPage.tsx`, `FederationPage.tsx`,
  `NotificationRulesPage.tsx`, `SettingsPage.tsx`, `RolesPage.tsx`, `WebhooksPage.tsx`,
  `ServiceAccountsPage.tsx`, `RoleDetailPage.tsx`, `GroupDetailPage.tsx`, `PermissionsPage.tsx`).
- `frontend/src/lib/utils.ts::slugify` — replace local copies in `OrganizationsPage.tsx:21` and
  `OrganizationDetailPage.tsx:36` with the shared import (both files already import `formatDate`
  from the same module — just add `slugify` to the existing import line).
- `frontend/src/services/users.ts::userService` — `ProfilePage.tsx` and `MfaManagementPage.tsx`
  currently type-only import from this module while calling raw `api.get`/`api.put`/`api.delete`;
  swap those calls for `userService.get(...)`/`userService.update(...)`/`userService.deleteMfaMethod(...)`.
- `frontend/src/hooks/useCrudMutations.ts` — `RolesPage.tsx:146-236`'s existing
  `createMutation`/`editMutation`/`deleteMutation` map directly onto this hook's
  `queryKey`/`createFn`/`updateFn`/`deleteFn`/`onCreateSuccess`/`onCreateError` shape. Note: the
  hook's `onError` always fires a `toast({variant:"destructive"})` — an accepted additive UX change
  (D-15/A2) since `RolesPage`'s current `deleteMutation` has no `onError` at all today (silent
  failure). Check `GroupsPage.tsx`, `PermissionsPage.tsx`, `WebhooksPage.tsx`,
  `ServiceAccountsPage.tsx`, `NotificationRulesPage.tsx` for the same inline-`useMutation` shape.

## Shared Patterns

### Error classification (DB layer)
**Source:** `crates/axiam-db/src/repository/saml_replay.rs:76-93` (marker-string set:
`"already contains"` / `"already exists"` / `"unique"`)
**Apply to:** `classify_write_error` in `helpers.rs`, called from `user.rs` create-path sites and
reachable edge-uniqueness `RELATE` sites (`role.rs:550`, `group.rs:392`, etc.)

### Multi-statement transaction idiom
**Source:** `crates/axiam-db/src/repository/federation_login_state.rs:110-127`,
`crates/axiam-db/src/repository/user.rs:736-760`
**Apply to:** `role.rs::delete`, `resource.rs::delete`, new GDPR `create_with_pending_flag` —
always inline `BEGIN TRANSACTION; ...; COMMIT TRANSACTION;` compound SQL with a documented
`.take(N)` slot-index comment; no new Rust abstraction (D-12).

### Generic `C: surrealdb::Connection + Clone` bound
**Source:** `crates/axiam-api-rest/src/server.rs:61`
**Apply to:** `AppState<C>` struct declaration and every handler signature migrating to
`web::Data<AppState<C>>`.

### `web::Data<T>` extraction convention
**Source:** current 283 handler sites across 28 files (e.g. `handlers/users.rs`)
**Apply to:** unchanged extraction *mechanism* (actix `web::Data`), only the *type* extracted
changes from per-dependency types to `AppState<C>`.

## No Analog Found

None — every new symbol in this phase has a strong, same-crate (or same-workspace) analog per the
research's own "most shared assets already exist" finding.

## Metadata

**Analog search scope:** `crates/axiam-server/src/main.rs`, `crates/axiam-api-rest/src/{handlers,
extractors,middleware,server.rs,health.rs}`, `crates/axiam-db/src/{helpers.rs,error.rs,
repository/*.rs}`, `crates/axiam-pki/src/{ca.rs,cert.rs,pgp.rs}`, `crates/axiam-oauth2/src/
{error.rs,authorize.rs,token.rs}`, `frontend/src/{components/shared.tsx,hooks/useCrudMutations.ts,
lib/utils.ts,services/users.ts,pages/**}`
**Files scanned:** 15 read directly this session (helpers.rs, error.rs, main.rs excerpt, ca.rs
excerpt, cert.rs excerpt, webhook.rs excerpt) + all file:line evidence from 29-RESEARCH.md
(itself independently verified via grep/Read against the live codebase this session)
**Pattern extraction date:** 2026-07-06

## PATTERN MAPPING COMPLETE

**Phase:** 29 - Structural Quality
**Files classified:** 6 symbol/module families (covering ~450+ individual mechanical sites)
**Analogs found:** 6 / 6

### Coverage
- Files/symbols with exact analog: 6
- Files/symbols with role-match analog: 0
- Files/symbols with no analog: 0

### Key Patterns Identified
- `AppState<C>` collapses the existing 48-registration `app_data` chain in `main.rs` into one
  struct/field-per-dep, mirroring the generic `C: surrealdb::Connection + Clone` bound already
  established in `server.rs:61`.
- `paginate<T>` and `classify_write_error` are both simple compositions of already-existing pieces
  (`CountRow`+`Pagination`/`PaginatedResult`; the 3-marker-string set 3 files already independently
  converged on) — write them in `helpers.rs` following its exact existing doc-comment/test style.
- All new inline transactions must mirror the established `BEGIN TRANSACTION; ...; COMMIT
  TRANSACTION;` idiom verbatim (`federation_login_state.rs:110`, `user.rs:736`) — no new Rust
  transaction abstraction (D-12 explicitly rejects this).
- PKI dedup is a direct swap: `build_ca_params` → `rcgen::CertificateParams::from_ca_cert_pem`
  (requires the `x509-parser` Cargo feature flag), plus lifting the byte-identical
  `generate_keypair`/`compute_fingerprint`/AES-256-GCM helpers from `ca.rs`/`cert.rs`/`pgp.rs`
  into one `crates/axiam-pki/src/crypto.rs`.
- Frontend dedup: canonical shared modules (`shared.tsx`, `useCrudMutations.ts`, `services/users.ts`)
  already exist with zero/partial adoption — this is wiring, not extraction, except for one
  required `ActionBadge` behavior fix before adoption.

### File Created
`/home/user/axiam/.planning/phases/29-structural-quality/29-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. Planner can now reference analog patterns in PLAN.md files.
