# Phase 28: Functional Completeness - Pattern Map

**Mapped:** 2026-07-05
**Files analyzed:** 9 new/modified files + 4 shared cross-cutting seams
**Analogs found:** 8 / 9 (1 has no true analog — new minting fn is intentionally novel)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-api-rest/src/handlers/email_config.rs` (NEW) | controller | CRUD (scope-nested singleton) | `crates/axiam-api-rest/src/handlers/settings.rs` | exact |
| `crates/axiam-core/src/models/email.rs` (MODIFY: secret hygiene) | model | transform | `crates/axiam-core/src/models/federation.rs` | exact |
| `crates/axiam-auth/src/token.rs` (MODIFY: add `SubjectKind` + `issue_service_account_token`) | service | transform (JWT mint) | `issue_client_credentials_token` in same file | exact (self-analog) |
| `crates/axiam-api-rest/src/handlers/auth.rs` (MODIFY: `auth.rs:556` SA cert-auth call site) | controller | request-response | same file, `issue_access_token` call site being replaced | exact |
| `crates/axiam-amqp/src/mail_consumer.rs` (MODIFY: `send_with_retry_and_audit`) | service | event-driven (AMQP consumer) | itself (existing `resolve_template(kind, None, None)` call site) | exact |
| `crates/axiam-db/src/repository/email_config.rs` (MODIFY: backfill doc/test, D-08 error, optional `delete_org_config`) | model/repository | CRUD | `crates/axiam-db/src/repository/federation_config.rs` (backfill analogy — explicitly NOT applicable, see below) | partial (documented divergence) |
| `crates/axiam-api-rest/src/server.rs` + `openapi.rs` + `permissions.rs` (MODIFY: route triangle) | route/config | request-response | federation-configs triangle (same 3 files, federation block) | exact |
| `crates/axiam-api-rest/tests/email_config_test.rs` (NEW) | test | request-response (e2e) | `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs` | role-match |
| `crates/axiam-api-rest/tests/federation_first_time_sso_test.rs` (NEW) | test | request-response (e2e) | `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs` (`test_app!` macro, cookie assertions) | exact |

## Pattern Assignments

### `crates/axiam-api-rest/src/handlers/email_config.rs` (controller, CRUD)

**Analog:** `crates/axiam-api-rest/src/handlers/settings.rs` (full file read; 168 lines)

**Imports pattern** (settings.rs lines 1-15):
```rust
use actix_web::{HttpResponse, web};
use axiam_core::models::settings::{
    SecuritySettings, SetOrgSettings, TenantSettingsOverride, effective_settings,
    validate_org_settings, validate_tenant_override,
};
use axiam_core::repository::SettingsRepository;
use axiam_db::SurrealSettingsRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
```
For `email_config.rs`, substitute `axiam_core::models::email::{...}`, `EmailConfigRepository`, `SurrealEmailConfigRepository`.

**RBAC + ownership-check core pattern** (settings.rs lines 31-53, `get_org_settings`):
```rust
pub async fn get_org_settings<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealSettingsRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();

    // Authorization: only allow reads for the authenticated user's own org.
    if org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot read settings for a different organization".into(),
            },
        ));
    }

    let settings = repo.get_org_settings(org_id).await?;
    Ok(HttpResponse::Ok().json(settings))
}
```
**Copy verbatim for `get_org_email_config`**, replacing:
- `"settings:get"` → `"email_config:read"` (D-03: single read permission, not per-verb)
- `repo.get_org_settings(org_id)` → `repo.get_org_config(org_id)` (D-14: raw own-scope row, NOT `get_effective_config`)
- error reason string → "cannot read email config for a different organization"

For PUT (settings.rs lines 70-95, `set_org_settings`), same shape but permission is `"email_config:write"` (D-03: single write permission for all mutations — PUT AND DELETE both use `email_config:write`, diverging from `settings:update`'s narrower verb). D-02 (omit-preserves/value-replaces) requires the input DTO's secret fields be `Option<String>` and the repository merge logic (already implemented per RESEARCH.md) to skip re-encryption when `None`.

**Tenant-scoped route needs an explicit path param** (unlike `settings.rs`'s `get_tenant_settings`/`set_tenant_settings` which use `user.tenant_id` implicitly with NO path param — settings.rs lines 111-123, 142-167). Per D-13, email-config tenant routes take an explicit `{tenant_id}` path segment, so the tenant handlers must ALSO include the `tenant_id != user.tenant_id` ownership check shown above for org, not the implicit-current-tenant pattern. Do not copy the no-path-param settings.rs tenant pattern — it doesn't match D-13's URL shape.

**DELETE handler — no existing analog in settings.rs** (settings has no DELETE). Follow the same skeleton (RBAC check → ownership check → `repo.delete_tenant_override(tenant_id)` / repo method for org). Per RESEARCH.md Open Question 2: `EmailConfigRepository` trait currently has NO `delete_org_config` method (only `delete_tenant_override`) — this repository method must be added first if org-level DELETE is implemented per D-13.

---

### `crates/axiam-core/src/models/email.rs` (model, secret hygiene D-01)

**Analog:** `crates/axiam-core/src/models/federation.rs` lines 1-80 (SECHRD-09 precedent)

**Serde skip pattern** (federation.rs lines 16-55):
```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    // ...
    /// Legacy plaintext client secret (kept for back-compat; nulled by plan 04-02 backfill).
    #[serde(skip_serializing)]
    pub client_secret: String,
    // ...
    #[serde(skip_serializing)]
    pub client_secret_ciphertext: Option<String>,
    #[serde(skip_serializing)]
    pub client_secret_nonce: Option<String>,
    #[serde(skip_serializing)]
    pub client_secret_key_version: Option<i64>,
    // ...
}
```

**Manual redacting `Debug` impl** (federation.rs lines 57-80):
```rust
impl std::fmt::Debug for FederationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationConfig")
            .field("id", &self.id)
            // ... all non-secret fields printed normally ...
            .field("client_secret", &"[REDACTED]")
            .field("client_secret_ciphertext", &"[REDACTED]")
            .field("client_secret_nonce", &"[REDACTED]")
            .field("client_secret_key_version", &"[REDACTED]")
            .finish()
    }
}
```

**Target — current state to modify** (`email.rs` lines 30-48, verified this session):
```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Stored encrypted at rest by the DB layer.
    pub password: String,
    pub starttls: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ApiProviderConfig {
    /// Stored encrypted at rest by the DB layer.
    pub api_key: String,
    pub api_url: Option<String>,
}
```
Both currently `#[derive(Debug, ...)]` — no redaction. Per RESEARCH.md 3a: add `#[serde(skip_serializing)]` to `password`/`api_key`, and replace `#[derive(Debug, ...)]` with a manual `Debug` impl analogous to `FederationConfig`'s (redacting only those two fields; `host`/`port`/`username`/`api_url`/`starttls` print normally). This is flagged in RESEARCH.md as assumption A2 — discretionary hardening beyond D-01's literal JSON-only requirement, but matches established precedent.

---

### `crates/axiam-auth/src/token.rs` (service, JWT mint — `SubjectKind` + `issue_service_account_token`)

**No true existing analog for the NEW function** — the closest self-analog is `issue_client_credentials_token` in the same file (token.rs lines 119-158), which the new `issue_service_account_token` should structurally clone.

**Current `AccessTokenClaims`** (token.rs lines 24-57, verified):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub tenant_id: String,
    pub org_id: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}
```
Add a new field per D-09/D-11:
```rust
#[serde(default)]
pub sub_kind: SubjectKind,
```
with
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    User,
    ServiceAccount,
    OAuth2Client,
}
impl Default for SubjectKind {
    fn default() -> Self { Self::User }
}
```
(mirrors the `#[serde(default)]` claim-tolerance convention already used for `aud`/`scope` optionality in this same struct, satisfying D-11's backward-compat requirement with zero changes to `validate_access_token`'s decode path.)

**Clone-target for `issue_service_account_token`** (token.rs lines 119-158, `issue_client_credentials_token` — copy this shape almost verbatim):
```rust
pub fn issue_client_credentials_token(
    client_id: &str,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[String],
    config: &AuthConfig,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let scope = if scopes.is_empty() { None } else { Some(scopes.join(" ")) };
    let claims = AccessTokenClaims {
        sub: client_id.to_owned(),
        tenant_id: tenant_id.to_string(),
        org_id: org_id.to_string(),
        iss: config.effective_issuer().to_owned(),
        iat: now,
        exp: now + config.access_token_lifetime_secs as i64,
        jti: Uuid::new_v4().to_string(),
        aud: Some(AUD_M2M.to_string()),
        scope,
    };
    let owned;
    let key: &EncodingKey = if let Some(ref cached) = config.jwt_encoding_key {
        cached.as_ref()
    } else {
        owned = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        &owned
    };
    let header = Header::new(Algorithm::EdDSA);
    jsonwebtoken::encode(&header, &claims, key)
        .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
}
```
Per RESEARCH.md's explicit recommendation (avoiding the 49-call-site diff on `issue_access_token`): write `issue_service_account_token(user_id: Uuid, tenant_id: Uuid, org_id: Uuid, jti: String, config: &AuthConfig) -> Result<String, AuthError>` cloning this exact key-resolution + encode block, but setting `sub_kind: SubjectKind::ServiceAccount`. Inside the existing `issue_access_token` and `issue_client_credentials_token`, add `sub_kind: SubjectKind::User` and `sub_kind: SubjectKind::OAuth2Client` respectively to their `AccessTokenClaims` literals — no signature changes, no call-site changes for either.

**Call site to update:** `crates/axiam-api-rest/src/handlers/auth.rs` around line 556 (`TODO(T15)`) — replace the `issue_access_token(...)` call with `issue_service_account_token(...)`. This is the ONLY call-site change required outside `token.rs`.

---

### `crates/axiam-amqp/src/mail_consumer.rs` (service, event-driven — template resolution D-05/D-06)

**Current code to modify** (verified this session, lines 127-154 and surrounding):
```rust
pub async fn send_with_retry_and_audit<E, A, U>(
    msg: &OutboundMailMessage,
    email_config_repo: &E,
    audit_repo: &A,
    user_repo: &U,
) -> Result<SendOutcome, SendError>
where
    E: EmailConfigRepository,
    A: AuditLogRepository,
    U: UserRepository,
{
    // 1. Resolve effective email config (tenant → org cascade).
    let email_config = email_config_repo
        .get_effective_config(msg.org_id, msg.tenant_id)
        .await
        .map_err(|e| SendError(e.to_string()))?;

    let Some(config) = email_config else {
        return Err(SendError("no email config for org/tenant".into()));
    };

    // 2. Build EmailService from resolved config.
    let svc = EmailService::from_config(&config).map_err(|e| SendError(e.to_string()))?;

    // 3. Resolve built-in template (no per-org/tenant custom templates fetched here;
    //    template repository lookup is deferred to a future task — T19.21).
    let kind = template_kind_for(&msg.mail_type);
    let template = resolve_template(kind, None, None);
    // ...
```
**Pattern for D-05/D-06 fix:** add a 4th generic `T: EmailTemplateRepository` parameter, then replace the `resolve_template(kind, None, None)` line with fetch-then-resolve, following the SAME defensive `.unwrap_or_else(|_| { warn!(...); None })`-style fallback already used a few lines below for recipient-address resolution (SEC-055 pattern, lines ~161-172 of the same function):
```rust
let resolved_address = user_repo
    .get_by_id(msg.tenant_id, msg.user_id)
    .await
    .map(|u| u.email)
    .unwrap_or_else(|_| {
        warn!(
            user_id = %msg.user_id,
            tenant_id = %msg.tenant_id,
            "SEC-055: could not resolve user email — falling back to message to_address"
        );
        msg.to_address.clone()
    });
```
Copy this exact `.await.<transform>().unwrap_or_else(|_| { warn!(...); <fallback> })` shape for each of `template_repo.get_org_template(...)` and `template_repo.get_tenant_template(...)`, falling back to `None` on error (D-06), then call the EXISTING `resolve_template(kind, org.as_ref(), tenant.as_ref())` — do not modify `resolve_template` itself (`axiam-email/src/template.rs:130`, already implements tenant→org→built-in precedence).

**D-08 fix location:** the config-fetch branch above (`let Some(config) = email_config else { return Err(...) }`) is the existing precedent for a "hard fail, no fallback" path — model the NULL-ciphertext check the same way (hard error, not silent), either in `row_to_provider` (`crates/axiam-db/src/repository/email_config.rs:177-212`) or right after `EmailService::from_config(&config)` here.

**Wiring in `main.rs`:** `SurrealEmailTemplateRepository::new(db_handle.clone())` (constructor confirmed no-arg beyond db handle) constructed alongside the other repositories already passed into `start_mail_consumer(...)` at `main.rs:279` vicinity (same file already wires `boot_email_repo.backfill_plaintext_secrets()`).

---

### Route↔OpenAPI↔Permission triangle (`server.rs` / `openapi.rs` / `permissions.rs`)

**Analog:** the federation-configs block, which is itself a full CRUD (not singleton) example of the same 3-file discipline.

**`server.rs` route registration pattern** (lines 585-598, federation-configs; lines 613-622, settings singleton — closer shape match for email-config):
```rust
.service(
    web::resource("/settings")
        .route(web::get().to(handlers::settings::get_tenant_settings::<C>))
        .route(web::put().to(handlers::settings::set_tenant_settings::<C>)),
)
```
and org-scoped (line ~286):
```rust
web::resource("/organizations/{org_id}/settings")
    .route(web::get().to(handlers::settings::get_org_settings::<C>))
    .route(web::put().to(handlers::settings::set_org_settings::<C>)),
```
For email-config, register FOUR resources total (org singleton + tenant singleton, each with GET/PUT/DELETE — DELETE has no settings.rs precedent, add `.route(web::delete().to(...))` following the federation-configs DELETE at line 596: `.route(web::delete().to(handlers::federation::delete::<C>))`).

**`permissions.rs::ROUTE_PERMISSION_MAP` pattern** (lines 566-591, verified):
```rust
("GET", "/api/v1/federation-configs", "federation:list"),
("POST", "/api/v1/federation-configs", "federation:create"),
("GET", "/api/v1/federation-configs/{id}", "federation:get"),
("PUT", "/api/v1/federation-configs/{id}", "federation:update"),
("DELETE", "/api/v1/federation-configs/{id}", "federation:delete"),
...
("GET", "/api/v1/settings", "settings:get"),
```
For email-config, add 6 entries (org GET/PUT/DELETE, tenant GET/PUT/DELETE), each mapped to `"email_config:read"` (GET) or `"email_config:write"` (PUT, DELETE) per D-03's single-write-permission decision — NOT per-verb like federation's `:create`/`:update`/`:delete` split.

**`permissions.rs::PERMISSION_REGISTRY` pattern** (line 144 shown):
```rust
("settings:get", "Read tenant or organization settings"),
```
Add: `("email_config:read", "Read organization or tenant email configuration")`, `("email_config:write", "Create, update, or delete organization or tenant email configuration")`. No further role-mapping code needed — `seed_default_roles` (axiam-db `seeder.rs:208`) auto-grants all registry perms to `super-admin`, all-but-`admin:bootstrap` to `admin`; since neither new permission ends in `:list`/`:get` the `viewer` role correctly excludes them (RESEARCH.md assumption A3).

**`openapi.rs`:** add each new handler to `#[openapi(paths(...))]` and each request/response DTO to `components(schemas(...))`, matching however `settings.rs`'s `get_org_settings`/`set_org_settings` (or federation's `create`/`get`/`update`/`delete`) are currently registered there — grep `openapi.rs` for `handlers::settings::` to find the exact line-pattern to clone for `handlers::email_config::`.

**Also required for FUNC-01 (D-12):** the SAME 3-file triangle applies to `oidc_start_public`, `oidc_callback_public`, `saml_login_public`, `saml_acs_public` — RESEARCH.md confirms these are ALREADY in `server.rs` and `permissions.rs::PUBLIC_PATHS`, but MISSING from `openapi.rs` entirely (zero grep matches). This is purely an `openapi.rs`-only addition (no `server.rs`/`permissions.rs` change needed) — add the 4 handlers + their DTOs (`OidcStartRequest`, `OidcStartResponse`, `OidcPublicCallbackRequest`, `SsoLoginSuccessResponse`, `SamlLoginRequest`, `SamlLoginResponse`) to the existing `#[openapi(...)]` macro, following the exact same `paths(...)`/`components(schemas(...))` entry shape used for any existing public handler already listed there (e.g. `saml_metadata`, already public and already documented — use its entry as the direct template).

---

### Test files

**`crates/axiam-api-rest/tests/email_config_test.rs` (NEW) — analog `password_reset_revokes_sessions.rs`**

Full pattern to copy (verified, whole file read):
- `test_app!` macro (lines 144-191) building an `actix_web::test::init_service` with all needed `app_data` repos + `AllowAllAuthzChecker` (bypasses real RBAC in test — note: for RBAC-gated email-config tests, this macro's `AllowAllAuthzChecker` means asserting 403-on-missing-permission requires a DIFFERENT authz checker fixture; check for an existing "real RBAC" test harness elsewhere, e.g. `rbac_test.rs`, rather than this macro, if permission-denial assertions are needed).
- `setup_db()` pattern (lines 67-123): creates org → tenant → settings baseline → user via repositories directly, returns `(db, org_id, tenant_id, user_id)`.
- `login()` helper (lines 194-228): logs in via `POST /api/v1/auth/login`, extracts `axiam_access`/`axiam_csrf` cookies from `resp.response().cookies()`.
- Assertion style: `assert_eq!(resp.status().as_u16(), 200, "<message>")`.

New email-config test should: create org+tenant, log in as admin, `PUT` an email config (assert 200, assert response body omits `password`/`api_key` per D-01), `GET` it back (assert same field omission + correct non-secret fields), attempt cross-org/tenant GET (assert 403 IDOR block), `DELETE` (assert 200/204), confirm subsequent GET 404s.

**`crates/axiam-api-rest/tests/federation_first_time_sso_test.rs` (NEW) — same analog, exact match**

Copy the `test_app!` macro and `setup_db()`/cookie-extraction helpers verbatim; per RESEARCH.md the new test additionally needs a `wiremock`-based mock IdP (follow `req5_oidc_e2e.rs`'s `MockServer` pattern for JWKS/discovery — read that file if not already familiar) layered on top of this harness. Assert final state via a `me_status`-style call (lines 230-249) against `/api/v1/auth/me` using the cookies returned from the OIDC callback response, confirming a 200 for the newly-provisioned user.

## Shared Patterns

### RBAC gate + ownership check (org/tenant IDOR guard)
**Source:** `crates/axiam-api-rest/src/handlers/settings.rs` lines 37-49 (org), 116-118 (tenant, implicit via `user.tenant_id`)
**Apply to:** all 6 new email-config handlers — every handler must call `RequirePermission::new(perm, Uuid::nil()).check(&user, authz.get_ref().as_ref()).await?` FIRST, then compare the path `org_id`/`tenant_id` against `user.org_id`/`user.tenant_id`, returning `AxiamApiError(AxiamError::AuthorizationDenied { reason: ... })` on mismatch, before any repository call.

### Secret write-only + redacted Debug (SECHRD-09)
**Source:** `crates/axiam-core/src/models/federation.rs` lines 27-28, 44-51 (skip_serializing) and 60-80 (manual Debug)
**Apply to:** `SmtpConfig`/`ApiProviderConfig` in `email.rs` (D-01/D-02).

### `#[serde(default)]` claim-tolerance for backward-compatible token evolution
**Source:** `crates/axiam-auth/src/token.rs` lines 50-56 (`aud`/`scope` optionality precedent, though those use `skip_serializing_if` not `default` — the NEW `sub_kind` field is the first to use bare `#[serde(default)]`, establishing D-11's pattern)
**Apply to:** `AccessTokenClaims::sub_kind`.

### Route↔OpenAPI↔Permission 3-file triangle
**Source:** federation-configs block across `server.rs:585-598`, `permissions.rs:566-591`, and `openapi.rs` (grep for `handlers::federation::` there)
**Apply to:** every new email-config route AND the 4 already-existing-but-undocumented public SSO routes (FUNC-01/D-12 — `openapi.rs` only for those 4, since routes/permissions already exist).

### AMQP consumer defensive fallback (`unwrap_or_else` + `warn!`)
**Source:** `crates/axiam-amqp/src/mail_consumer.rs` lines 159-172 (SEC-055 recipient-resolution fallback)
**Apply to:** the new template-fetch fallback (D-06) in the same function.

### `test_app!` + cookie-based session assertion harness
**Source:** `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs` lines 144-249 (whole harness)
**Apply to:** both new test files (`email_config_test.rs`, `federation_first_time_sso_test.rs`).

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `issue_service_account_token` (new fn in `token.rs`) | service | transform | Genuinely novel function; closest self-analog (`issue_client_credentials_token`) documented above and should be cloned structurally — not a gap, just noting there's no *external* file to point to. |
| `crates/axiam-db/src/repository/email_config.rs::backfill_plaintext_secrets` doc/test update | model/repository | CRUD | `federation_config.rs`'s backfill (`list_with_legacy_plaintext_secret`/`set_encrypted_secret`) is explicitly the WRONG analog per D-07 — email_config has no plaintext column to migrate. The fix here is documentation + a no-op assertion test, not a ported migration function. |

## Metadata

**Analog search scope:** `crates/axiam-api-rest/src/handlers/`, `crates/axiam-core/src/models/`, `crates/axiam-auth/src/`, `crates/axiam-amqp/src/`, `crates/axiam-api-rest/tests/`, `crates/axiam-api-rest/src/{server,openapi,permissions}.rs`
**Files scanned:** settings.rs, federation.rs (handler + model), token.rs, mail_consumer.rs, password_reset_revokes_sessions.rs, email.rs, server.rs, permissions.rs (grep)
**Pattern extraction date:** 2026-07-05
