# Phase 11: Medium Remediation (Wave 3) — Pattern Map

**Mapped:** 2026-06-13
**Files analyzed:** 42 new/modified files across 5 clusters
**Analogs found:** 38 / 42

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/axiam-db/src/helpers.rs` (NEW) | utility | transform | `crates/axiam-db/src/repository/user.rs` (CountRow, parse pattern) | role-match |
| `crates/axiam-db/src/error.rs` | model | transform | self (extend) | exact |
| `crates/axiam-db/src/repository/user.rs` | repository | CRUD | self (extend) | exact |
| `crates/axiam-api-rest/src/error.rs` | middleware | request-response | self (extend, AlreadyExists already mapped) | exact |
| `crates/axiam-api-rest/src/webhook.rs` | service | request-response | self (extend) | exact |
| `crates/axiam-core/src/models/webhook.rs` | model | transform | `crates/axiam-core/src/models/` (any serde model) | role-match |
| `crates/axiam-api-rest/src/server.rs` | config | request-response | self (extend rate limits + CSRF wrap) | exact |
| `crates/axiam-api-grpc/src/server.rs` | config | request-response | self (extend builder) | exact |
| `crates/axiam-oauth2/src/authorize.rs` | service | request-response | self (extend PKCE guard) | exact |
| `crates/axiam-amqp/src/messages.rs` | model | event-driven | `crates/axiam-auth/src/crypto.rs` (gdpr_pseudonym HMAC) | partial |
| `crates/axiam-pki/src/mtls.rs` | service | request-response | self (extend) | exact |
| `crates/axiam-auth/src/service.rs` | service | request-response | self (extend, spawn_blocking pattern present) | exact |
| `crates/axiam-api-rest/src/handlers/bootstrap.rs` | handler | CRUD | `crates/axiam-db/src/repository/user.rs::create_with_consent` (transaction) | partial |
| `crates/axiam-api-rest/src/handlers/users.rs` | handler | CRUD | self (extend self-update strip) | exact |
| `crates/axiam-api-rest/src/handlers/auth.rs` | handler | request-response | self (extend logout) | exact |
| `crates/axiam-api-rest/src/permissions.rs` | config | request-response | self (extend PUBLIC_PATHS) | exact |
| `crates/axiam-api-rest/src/config/rate_limit.rs` | config | request-response | self (extend fields) | exact |
| `crates/axiam-api-rest/src/middleware/csrf.rs` | middleware | request-response | self (read-only, already fully implemented) | exact |
| `k8s/server/configmap.yml` | config | — | `docker/docker-compose.prod.yml` (AXIAM__ pattern) | role-match |
| `k8s/server/secret.yml` | config | — | self (extend) | exact |
| `k8s/namespace.yml` | config | — | self (extend PSA label) | exact |
| `k8s/network-policy/allow-ingress-to-surrealdb.yml` (NEW) | config | — | `k8s/network-policy/allow-ingress-to-server.yml` | exact |
| `k8s/network-policy/allow-ingress-to-rabbitmq.yml` (NEW) | config | — | `k8s/network-policy/allow-ingress-to-server.yml` | exact |
| `docker/nginx.conf` | config | request-response | self (extend location blocks) | exact |
| `k8s/ingress.yml` | config | request-response | self (extend paths) | exact |
| `docker/docker-compose.prod.yml` | config | — | self (lines 41-42 already use `${VAR:?msg}`) | exact |
| `frontend/src/lib/apiError.ts` (NEW) | utility | transform | `frontend/src/pages/LoginPage.tsx` (AxiosError handling at line 118-128) | partial |
| `frontend/src/components/Toaster.tsx` (NEW) | component | event-driven | no analog — radix-ui standard pattern | none |
| `frontend/src/components/FormDialog.tsx` | component | request-response | self (remove noValidate line 99) | exact |
| `frontend/src/pages/resources/ResourcesPage.tsx` | component | CRUD | `frontend/src/pages/roles/RolesPage.tsx` (mutation + onError pattern) | role-match |
| `frontend/src/pages/federation/FederationPage.tsx` | component | CRUD | self (extend, lock type select) | exact |
| `frontend/src/pages/users/UsersPage.tsx` | component | CRUD | `frontend/src/pages/roles/RolesPage.tsx` | role-match |
| `frontend/src/router.tsx` | config | request-response | `frontend/src/components/layout/AppLayout.tsx` (isAuthenticated check) | role-match |
| `frontend/src/pages/LoginPage.tsx` | component | request-response | self (extend mfa_setup_required branch at line 98) | exact |
| `frontend/src/stores/auth.ts` | store | event-driven | self (extend setTenantContext) | exact |
| `frontend/src/hooks/useAuthInit.ts` | hook | event-driven | self (extend, call setTenantContext after fetchCurrentUser) | exact |
| `frontend/src/lib/fetchCurrentUser.ts` | utility | request-response | self (extend to return tenantSlug/orgSlug) | exact |
| `crates/axiam-api-rest/src/handlers/certificates.rs` etc (DTO) | handler | CRUD | `crates/axiam-api-rest/src/handlers/users.rs` (CreateUserRequest pattern) | exact |

---

## Pattern Assignments

### `crates/axiam-db/src/helpers.rs` (NEW — utility, transform)

**Analog:** `crates/axiam-db/src/repository/user.rs` + `crates/axiam-db/src/repository/role.rs`

**Imports pattern** (`user.rs` lines 1-16, `role.rs` lines 1-10):
```rust
use axiam_core::error::AxiamResult;
use axiam_core::repository::{PaginatedResult, Pagination};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
```

**CountRow — copy from** `user.rs` lines 146-150 and `role.rs` lines 52-55 (both have identical private structs):
```rust
// Currently duplicated in every repo as a private struct.
// Extract to helpers.rs as pub:
#[derive(Debug, SurrealValue)]
pub struct CountRow {
    pub total: u64,
}
```

**parse_uuid pattern — distilled from** `role.rs` lines 36-39:
```rust
// Current inline pattern (repeated in ~25 repos):
Uuid::parse_str(&self.record_id)
    .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))
// helpers.rs should expose:
pub fn parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError> {
    s.parse::<Uuid>()
        .map_err(|e| DbError::Serialization(format!("invalid {field} UUID: {e}")))
}
```
Note: use `DbError::Migration` if `DbError::Serialization` is not added; keep consistent with existing repos.

**take_first_or_not_found — analog from** any repo `get_by_id` `into_iter().next().ok_or_else(|| DbError::NotFound {...})`:
```rust
pub fn take_first_or_not_found<T>(mut items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError> {
    items.into_iter().next().ok_or_else(|| DbError::NotFound {
        entity: entity.to_string(),
        id: id.to_string(),
    })
}
```

---

### `crates/axiam-db/src/error.rs` (EDIT — add AlreadyExists)

**Analog:** `crates/axiam-api-rest/src/error.rs` lines 39, 63 — `AxiamError::AlreadyExists` is already mapped to `StatusCode::CONFLICT` in the REST error handler, confirming the variant must propagate from DbError.

Current file (full, 25 lines):
```rust
// crates/axiam-db/src/error.rs — current
pub enum DbError {
    #[error("SurrealDB error: {0}")]
    Surreal(#[from] surrealdb::Error),
    #[error("Migration failed: {0}")]
    Migration(String),
    #[error("Record not found: {entity} with id {id}")]
    NotFound { entity: String, id: String },
}
```

Add after `NotFound`:
```rust
    #[error("Record already exists: {entity}")]
    AlreadyExists { entity: String },
```

Add to `From<DbError> for AxiamError`:
```rust
DbError::AlreadyExists { entity } => AxiamError::AlreadyExists { entity },
```

Note: `AxiamError::AlreadyExists` is already defined in `axiam-core/src/error.rs` (confirmed by `error.rs` line 39 referencing it). Verify the exact field name in axiam-core before adding the From mapping.

---

### `crates/axiam-api-rest/src/server.rs` (EDIT — rate limits + CSRF on api_scope)

**Analog:** self — lines 24-32 (`build_governor`), lines 58-61 (auth_scope with CsrfMiddleware + JsonConfig), lines 182-195 (oauth2 scope with missing rate limits).

**build_governor pattern** (lines 24-32):
```rust
fn build_governor(requests_per_min: u32) -> Governor<XForwardedForKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .requests_per_minute(requests_per_min as u64)
        .burst_size(requests_per_min)
        .key_extractor(XForwardedForKeyExtractor)
        .finish()
        .expect("valid governor config");
    Governor::new(&config)
}
```

**CSRF wrap — copy pattern from auth_scope** (lines 58-61) to api_scope (line 197):
```rust
// BEFORE (line 197):
let api_scope = web::scope("/api/v1")
    .wrap(AuthzMiddleware)
    // ...

// AFTER:
let api_scope = web::scope("/api/v1")
    .wrap(AuthzMiddleware)
    .wrap(CsrfMiddleware)   // ADD (SEC-046)
    .app_data(web::JsonConfig::default().limit(65_536))  // ADD (CQ-B21)
    // ...
```

**Rate limit MFA resources — copy web::resource wrap pattern from** lines 63-65:
```rust
// Existing pattern for login (lines 63-65):
web::resource("/login")
    .wrap(build_governor(rate_limit_cfg.login_per_min))
    .route(web::post().to(handlers::auth::login::<C>))

// Apply same pattern to MFA routes (SEC-020):
web::resource("/mfa/enroll")
    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
    .route(web::post().to(handlers::auth::enroll_mfa::<C>))
// Repeat for /mfa/confirm, /mfa/verify, /mfa/setup/enroll, /mfa/setup/confirm
```

**Rate limit oauth2 revoke/introspect — copy web::resource wrap from** lines 184-188:
```rust
// Existing pattern for /oauth2/token (lines 184-188):
web::resource("/token")
    .wrap(build_governor(rate_limit_cfg.token_per_min))
    .route(web::post().to(handlers::oauth2::token::<C>))

// Apply to /revoke and /introspect (SEC-020):
web::resource("/revoke")
    .wrap(build_governor(rate_limit_cfg.revoke_per_min))
    .route(web::post().to(handlers::oauth2::revoke::<C>))
web::resource("/introspect")
    .wrap(build_governor(rate_limit_cfg.introspect_per_min))
    .route(web::post().to(handlers::oauth2::introspect::<C>))
```

---

### `crates/axiam-api-rest/src/config/rate_limit.rs` (EDIT — add mfa/introspect/revoke fields)

**Analog:** self — lines 1-42 (full file, all fields follow same pattern).

**Add fields** following the `token_per_min: u32` pattern at line 14:
```rust
/// Max MFA requests per minute per IP (default: 5).
pub mfa_per_min: u32,
/// Max oauth2/introspect requests per minute (default: 10).
pub introspect_per_min: u32,
/// Max oauth2/revoke requests per minute (default: 10).
pub revoke_per_min: u32,
```

Add to `Default::default()` impl matching existing defaults pattern:
```rust
mfa_per_min: 5,
introspect_per_min: 10,
revoke_per_min: 10,
```

Add assertions to `validate()` matching existing pattern at lines 33-40.

---

### `crates/axiam-api-rest/src/webhook.rs` (EDIT — SSRF resolve+check at delivery)

**Analog:** self — lines 55-118 (inner delivery loop). The `client.post(&webhook.url)` call is at line 75.

**SSRF guard — insert before line 75** in the retry loop (`for attempt in 0..=max_retries`):
```rust
// At top of each delivery attempt in the retry loop (before client.post):
async fn resolve_and_validate_host(url: &str) -> Result<(), WebhookError> {
    use std::net::IpAddr;
    let parsed = url::Url::parse(url).map_err(|_| WebhookError::InvalidUrl)?;
    let host = parsed.host_str().ok_or(WebhookError::InvalidUrl)?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port)).await
        .map_err(|_| WebhookError::ResolveFailed)?;
    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(WebhookError::SsrfBlocked);
        }
    }
    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local()
            || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
```

**Delivery loop insertion** (analog to error handling at lines 107-116):
```rust
// Insert as first step in retry loop, before client.post():
if let Err(e) = resolve_and_validate_host(&webhook.url).await {
    tracing::warn!(webhook_id = %webhook.id, error = %e, "SSRF check failed — aborting");
    return; // abort all retries
}
```

**Webhook secret encryption** — analog: `axiam-auth/src/crypto.rs::aes256gcm_encrypt` (lines 45-58). Use bundled format (nonce+ct in one base64 string) consistent with TOTP secret storage. On delivery, call `aes256gcm_decrypt(key, &webhook.secret)` to recover plaintext secret before computing HMAC.

---

### `crates/axiam-core/src/models/webhook.rs` (EDIT — skip_serializing + encrypt doc)

**Analog:** any model field with serde attribute. Pattern from `axiam-amqp/src/messages.rs` line 31:
```rust
#[serde(skip_serializing_if = "Option::is_none")]
```

Apply to `secret` field:
```rust
#[serde(skip_serializing)]  // SEC-031: never include HMAC secret in API responses
pub secret: String,          // stored AES-256-GCM encrypted; decrypt in WebhookDeliveryService
```

---

### `crates/axiam-api-grpc/src/server.rs` (EDIT — add builder limits)

**Analog:** self — lines 55-61 (current builder chain).

Current (lines 55-61):
```rust
Server::builder()
    .layer(governor_layer)
    .add_service(authz_svc)
    .add_service(user_svc)
    .add_service(token_svc)
    .serve(addr)
    .await
```

Target pattern (CQ-B20):
```rust
Server::builder()
    .max_decoding_message_size(4 * 1024 * 1024)   // 4 MiB
    .max_encoding_message_size(4 * 1024 * 1024)
    .timeout(std::time::Duration::from_secs(30))
    .concurrency_limit_per_connection(256)
    .layer(governor_layer)
    .add_service(authz_svc)
    .add_service(user_svc)
    .add_service(token_svc)
    .serve(addr)
    .await
```

Also fix rate-limit bug (CQ-B44): in `crates/axiam-api-grpc/src/middleware/rate_limit.rs` line 39-40, change `.per_second(1).burst_size(authz_per_sec)` to `.per_second(authz_per_sec as u64).burst_size(authz_per_sec * 2)`.

---

### `crates/axiam-oauth2/src/authorize.rs` (EDIT — PKCE S256 enforce for public clients)

**Analog:** self — lines 105-126 (PKCE validation block, already validates S256 when present).

**Insert after client lookup** (after line 67, before line 71 redirect_uri check — or after grant_type check at line 87):
```rust
// SEC-025: Enforce PKCE for public clients (no client_secret).
// Public client = client_secret is None or empty.
if client.client_secret.is_none() && req.code_challenge.is_none() {
    return Err(OAuth2Error::InvalidRequest(
        "PKCE (code_challenge) is required for public clients".into(),
    ));
}
```

Note (A3 from RESEARCH.md): If `OAuthClient` has no `client_secret` field, add `pub is_public: bool` to the model and check `client.is_public` instead.

---

### `crates/axiam-amqp/src/messages.rs` (EDIT — add HMAC signature field)

**Analog:** `crates/axiam-auth/src/crypto.rs` lines 158-164 (`gdpr_pseudonym` — shows HMAC-SHA256 pattern using `hmac::Mac`).

**HMAC sign/verify pattern** (from `axiam-auth/src/crypto.rs` line 25 + 159):
```rust
type HmacSha256 = Hmac<Sha256>;

// Sign:
fn sign_payload(key: &[u8], payload: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}
```

**Add `hmac_signature` field to** `AuthzRequest` (line 14) and `AuditEventMessage` (line 38):
```rust
/// HMAC-SHA256 of the JSON-serialized message body, excluding this field.
/// Computed with the per-tenant AMQP signing key.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub hmac_signature: Option<String>,
```

Keep `#[derive(Deserialize)]` on consumers; add `Serialize` to `AuthzRequest` if needed for the response.

---

### `crates/axiam-pki/src/mtls.rs` (EDIT — chain verify to org/tenant CA)

**Analog:** self — lines 35-77 (`authenticate` method, already loads cert via `cert_repo`).

**Struct extension** (line 17-19 current):
```rust
// BEFORE:
pub struct DeviceAuthService<CR> {
    cert_repo: CR,
}

// AFTER (SEC-024):
pub struct DeviceAuthService<CR, CCR> {
    cert_repo: CR,
    ca_cert_repo: CCR,   // CaCertificateRepository to load org CA
}
```

**Chain verify insertion** — after `cert.status` check (line 50), before resolve service account (line 63):
```rust
// Load tenant CA cert and verify chain
let ca_cert = self.ca_cert_repo.get_active_for_tenant(cert.tenant_id).await
    .map_err(|_| AxiamError::Certificate("no active CA cert for tenant".into()))?;
let (_, ca_x509) = x509_parser::parse_x509_certificate(ca_cert.der_bytes.as_ref())
    .map_err(|e| AxiamError::Certificate(format!("invalid CA cert: {e}")))?;
let (_, client_x509) = x509_parser::parse_x509_certificate(&pem_obj.contents)
    .map_err(|e| AxiamError::Certificate(format!("invalid client cert: {e}")))?;
client_x509.verify_signature(Some(ca_x509.public_key()))
    .map_err(|_| AxiamError::Certificate("certificate chain verify failed".into()))?;
```

Note: `x509_parser` is already a dependency (used at line 13 for `parse_x509_pem`). Check if `parse_x509_certificate` function is available in the same crate version; if not, use `pem_obj.parse_x509()` from `x509_parser::pem::Pem`.

---

### `crates/axiam-auth/src/service.rs` — dummy-Argon2 (SEC-026)

**Analog:** self — lines 219-233 (the existing `spawn_blocking` + semaphore + `verify_password` pattern used for real password check).

Current real-password check (lines 219-233):
```rust
let _permit = self.crypto_semaphore.acquire().await
    .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;
let pw_owned = input.password.clone();
let hash_owned = user.password_hash.clone();
let pepper_owned = self.config.pepper.clone();
let valid = tokio::task::spawn_blocking(move || {
    password::verify_password(&pw_owned, &hash_owned, pepper_owned.as_deref())
})
.await
.map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
.map_err(|e| AxiamError::Crypto(e.to_string()))?;
```

**Dummy-Argon2 — apply same pattern on user-not-found** (replace line 208 `map_err(|_| AuthError::InvalidCredentials)?`):
```rust
Err(AxiamError::NotFound { .. }) => {
    // Timing equalization (SEC-026): run dummy Argon2 to match timing of
    // the found-user + wrong-password path. Result is discarded.
    let _permit = self.crypto_semaphore.acquire().await.ok();
    let pepper_owned = self.config.pepper.clone();
    let _ = tokio::task::spawn_blocking(move || {
        password::verify_password("dummy", DUMMY_HASH, pepper_owned.as_deref())
    }).await;
    return Err(AuthError::InvalidCredentials.into());
}
```

Add constant near top of file:
```rust
/// Constant Argon2id hash of "dummy" used for timing equalization on
/// user-not-found. Must be a valid Argon2 PHC string.
const DUMMY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaasfNiu6f6WSz0n28";
```

---

### `crates/axiam-auth/src/service.rs` — atomic failed-login (SEC-032) via new repo method

**Analog:** `crates/axiam-db/src/repository/user.rs` lines 500-567 (`create_with_consent` — SurrealQL multi-statement with bind pattern).

Add to `SurrealUserRepository` impl:
```rust
pub async fn increment_failed_logins(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    lockout_threshold: u32,
    lockout_duration_secs: i64,
) -> AxiamResult<()> {
    let tenant_id_str = tenant_id.to_string();
    let user_id_str = user_id.to_string();
    self.db
        .query(r#"
            UPDATE type::record('user', $id)
            SET
                failed_login_attempts += 1,
                last_failed_login_at = time::now(),
                locked_until = IF (failed_login_attempts >= $threshold)
                    THEN time::now() + duration::secs($lockout_secs)
                    ELSE locked_until
                END,
                updated_at = time::now()
            WHERE tenant_id = $tenant_id
        "#)
        .bind(("id", user_id_str))
        .bind(("tenant_id", tenant_id_str))
        .bind(("threshold", lockout_threshold))
        .bind(("lockout_secs", lockout_duration_secs))
        .await
        .map_err(DbError::from)?;
    Ok(())
}
```

SurrealDB v3 quirk: `bind()` requires owned values — pass `u32`/`i64` directly (they implement Into<surrealdb::Value>). Then in `auth/service.rs`, replace `record_failed_login` method body with a call to this repo method.

---

### `crates/axiam-auth/src/service.rs` — block reset to current (SEC-028)

**Analog:** self — lines 637-688 (`change_password` — already has `verify_password` spawn_blocking at lines 649-663 and policy check at lines 670-684).

**Insert before "Hash new password" step** (before line 688):
```rust
// SEC-028: Block reset to current password.
let new_pw_owned = new_password.to_string();
let current_hash_owned = user.password_hash.clone();
let pepper_owned2 = self.config.pepper.clone();
let is_same = tokio::task::spawn_blocking(move || {
    password::verify_password(&new_pw_owned, &current_hash_owned, pepper_owned2.as_deref())
})
.await
.map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
.map_err(|e| AxiamError::Crypto(e.to_string()))?;
if is_same {
    return Err(AuthError::PasswordReusedCurrent.into());
}
```

Add `PasswordReusedCurrent` variant to `AuthError` enum.

---

### `crates/axiam-api-rest/src/handlers/auth.rs` — logout session ownership (SEC-051)

**Analog:** self — `logout` function at lines 364-375. `AuthenticatedUser` extractor provides `user.session_id` (JWT `jti`).

**Current** (line 369):
```rust
svc.logout(user.tenant_id, body.session_id).await?;
```

**Replace with** (verify caller owns the session):
```rust
// SEC-051: Logout must only revoke the caller's own session.
// user.session_id == JWT jti; reject if body claims a different session.
if body.session_id != user.session_id {
    return Err(AxiamApiError(AxiamError::AuthorizationDenied {
        reason: "cannot revoke another user's session".into(),
    }));
}
svc.logout(user.tenant_id, body.session_id).await?;
```

Note: verify `AuthenticatedUser` has a `session_id: Uuid` field (check `crates/axiam-api-rest/src/extractors/auth.rs`). If the field is named differently (e.g. `jti`), adjust accordingly.

---

### `crates/axiam-api-rest/src/handlers/bootstrap.rs` (EDIT — transactional SEC-049)

**Analog:** `crates/axiam-db/src/repository/user.rs` lines 528-567 (`create_with_consent` — BEGIN TRANSACTION; stmt1; stmt2; COMMIT TRANSACTION pattern).

Key SurrealDB v3 quirk: `BEGIN TRANSACTION` occupies result slot 0; first statement result is at `.take(1)`.

The bootstrap handler (lines 142-171) has 4 sequential awaits:
1. `seed_permissions` (line 143)
2. `seed_default_roles` (line 147)
3. `user_repo.create` (line 152)
4. `role_repo.assign_to_user` (line 164)

Strategy: wrap steps 3+4 in a transaction (seed_permissions and seed_default_roles are idempotent and can remain outside). The `create_with_consent` transaction pattern at `user.rs:532-567` is the direct analog — copy the BEGIN/COMMIT structure, adapting for user+role-assignment statements.

---

### `crates/axiam-api-rest/src/handlers/users.rs` (EDIT — self-update strip status SEC-050)

**Analog:** self — `update` function at lines 209-232. `is_own_resource` used at line 217.

**Strip status when caller is self** (after `is_own_resource` check, in the `req.status` handling):
```rust
// SEC-050: Self-update must not allow status change.
let input = UpdateUser {
    username: req.username,
    email: req.email,
    // Strip status for self-update; admin can still change via a separate flow.
    status: if is_own_resource(&user, target_id) { None } else { req.status },
    metadata: req.metadata,
    ..Default::default()
};
```

---

### `crates/axiam-api-rest/src/permissions.rs` (EDIT — remove /auth/register from PUBLIC_PATHS)

**Analog:** self — `PUBLIC_PATHS` at line 188. Each entry is a `&str` path in the array.

Remove line 197: `"/api/v1/auth/register"` from the array (SEC-047). No other files need changing for this specific fix.

---

### Request DTOs (CQ-B25) — handlers needing `CreateXxxRequest` structs

**Analog:** `crates/axiam-api-rest/src/handlers/users.rs` lines 20-34 (CreateUserRequest + UpdateUserRequest pattern).

Pattern to copy into `certificates.rs`, `ca_certificates.rs`, `organizations.rs`, `permissions.rs`, `resources.rs`, `roles.rs`, `scopes.rs`, `pgp_keys.rs`:
```rust
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateXxxRequest {
    pub field_one: String,
    // ... typed fields matching the domain model
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateXxxRequest {
    pub field_one: Option<String>,
    // ... all optional
}
```

Note: `roles.rs` handler already uses this pattern per Phase 9/10 work — verify before adding.

---

## Shared Patterns

### Semaphore + spawn_blocking (CPU-bound crypto)
**Source:** `crates/axiam-auth/src/service.rs` lines 219-233
**Apply to:** dummy-Argon2 (SEC-026) and reset-to-current (SEC-028) in `service.rs`
```rust
let _permit = self.crypto_semaphore.acquire().await
    .map_err(|_| AxiamError::Internal("crypto semaphore closed".into()))?;
let value_owned = value.to_string();
let hash_owned = hash.clone();
let pepper_owned = self.config.pepper.clone();
let result = tokio::task::spawn_blocking(move || {
    password::verify_password(&value_owned, &hash_owned, pepper_owned.as_deref())
})
.await
.map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))?
.map_err(|e| AxiamError::Crypto(e.to_string()))?;
```

### SurrealDB transaction (BEGIN/COMMIT slot shift)
**Source:** `crates/axiam-db/src/repository/user.rs` lines 528-569
**Apply to:** `bootstrap.rs` transactional user+role-assign (SEC-049)
**Critical:** `BEGIN TRANSACTION` = slot 0; first statement = `.take(1)`. See MEMORY.md.

### AES-256-GCM bundled encrypt/decrypt
**Source:** `crates/axiam-auth/src/crypto.rs` lines 45-79 (`aes256gcm_encrypt` / `aes256gcm_decrypt`)
**Apply to:** webhook secret encrypt on create/update, decrypt in delivery (SEC-031)
```rust
// Encrypt on write:
let encrypted = axiam_auth::crypto::aes256gcm_encrypt(&pki_key, secret.as_bytes())?;
// Decrypt on delivery:
let plaintext = axiam_auth::crypto::aes256gcm_decrypt(&pki_key, &webhook.secret)?;
let secret_str = String::from_utf8(plaintext)?;
```

### actix-web rate limit wrapping
**Source:** `crates/axiam-api-rest/src/server.rs` lines 24-32 (`build_governor`) + lines 63-65 (web::resource + .wrap)
**Apply to:** MFA routes in auth_scope, /revoke and /introspect in oauth2 scope

### HMAC-SHA256 signing
**Source:** `crates/axiam-auth/src/crypto.rs` lines 158-163 (`gdpr_pseudonym`) + `crates/axiam-api-rest/src/webhook.rs` lines 1-9 (HmacSha256 type alias)
**Apply to:** `axiam-amqp/src/messages.rs` AMQP payload signing (SEC-022)

### actix-web error mapping to HTTP status
**Source:** `crates/axiam-api-rest/src/error.rs` lines 35-55 (`ResponseError` impl)
**Apply to:** `DbError::AlreadyExists` → `AxiamError::AlreadyExists` → HTTP 409 (already wired at line 39, just needs the DbError variant added)

### Frontend useMutation + onError
**Source:** `frontend/src/pages/roles/RolesPage.tsx` lines 146-158
**Apply to:** all mutation pages missing `onError` toast (UsersPage, PermissionsPage, ResourcesPage, CertificatesPage, PgpKeysPage, FederationPage, NotificationRulesPage, ServiceAccountsPage)
```typescript
const mutation = useMutation({
  mutationFn: (payload: Payload) => service.create(payload),
  onSuccess: () => {
    void queryClient.invalidateQueries({ queryKey: ["resource-key"] });
    setOpen(false);
  },
  onError: (err: unknown) => {
    // After Toaster.tsx is wired: toast({ description: getApiErrorMessage(err), variant: "destructive" })
    // Before Toaster exists: setError(getApiErrorMessage(err))
  },
});
```

### k8s NetworkPolicy ingress structure
**Source:** `k8s/network-policy/allow-ingress-to-server.yml` (lines 1-23)
**Apply to:** `allow-ingress-to-surrealdb.yml` and `allow-ingress-to-rabbitmq.yml` (SEC-053)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-surrealdb  # or rabbitmq
  namespace: axiam
spec:
  podSelector:
    matchLabels:
      component: surrealdb  # or rabbitmq
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              component: server
      ports:
        - protocol: TCP
          port: 8000  # surrealdb; use 5672 for rabbitmq
```

### nginx location proxy_pass block
**Source:** `docker/nginx.conf` lines 61-67 (`location /api` block)
**Apply to:** Add `/oauth2` and `/.well-known` location blocks (SEC-016)
```nginx
location /oauth2 {
    proxy_pass http://axiam-server:8090;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /.well-known {
    proxy_pass http://axiam-server:8090;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```
Also add security headers block (copy pattern from lines 22-26) to each new location block to prevent header inheritance gap.

### Docker Compose env-var fail-fast pattern
**Source:** `docker/docker-compose.prod.yml` lines 41-42
**Apply to:** Replace hardcoded `root`/`axiam` creds (lines 31-32, 35, 102, 121-122)
```yaml
# Pattern from lines 41-42:
AXIAM__AUTH__JWT_PRIVATE_KEY_PEM: "${AXIAM__AUTH__JWT_PRIVATE_KEY_PEM:?JWT private key required}"

# Apply to DB creds:
AXIAM__DB__USERNAME: "${AXIAM__DB__USERNAME:?SurrealDB username required}"
AXIAM__DB__PASSWORD: "${AXIAM__DB__PASSWORD:?SurrealDB password required}"
# Apply to SurrealDB command:
command: start --user ${AXIAM__DB__USERNAME:?} --pass ${AXIAM__DB__PASSWORD:?} --log info surrealkv:/data/axiam.db
# Apply to RabbitMQ:
RABBITMQ_DEFAULT_USER: "${RABBITMQ_DEFAULT_USER:?RabbitMQ username required}"
RABBITMQ_DEFAULT_PASS: "${RABBITMQ_DEFAULT_PASS:?RabbitMQ password required}"
```

### k8s ConfigMap AXIAM__ double-underscore key
**Source:** `docker/docker-compose.prod.yml` lines 30-37 (correct double-underscore pattern)
**Apply to:** `k8s/server/configmap.yml` lines 10-16 (fix single-underscore keys, SEC-052)

The current configmap (lines 10-16) uses single-underscore prefix: `AXIAM_DB__URL`, `AXIAM_DB__NAMESPACE`, etc. These are silently ignored by config-rs because `.with_prefix("AXIAM").separator("__")` expects the form `AXIAM__DB__URL`. All keys must be renamed to double-underscore after `AXIAM`.

Additionally, `AXIAM__DB__URL` value must be `"surrealdb:8000"` (bare host:port) — the SurrealDB v3 WsClient does not accept a URL scheme prefix. See MEMORY.md: "SurrealDB SDK crate is surrealdb 3.0.0".

Also set `RUST_LOG: "info"` (remove the internal module exposure `axiam=debug` from production ConfigMap, per SEC-052).

### Frontend ProtectedRoute guard
**Source:** `frontend/src/components/layout/AppLayout.tsx` lines 8-22 (`isAuthenticated` check + Navigate)
**Apply to:** `frontend/src/router.tsx` — new `ProtectedRoute` wrapper component (CQ-F30)
```typescript
// AppLayout.tsx pattern (lines 8-22):
const { isAuthenticated } = useAuthStore();
if (!isAuthenticated) {
  return <Navigate to="/login" replace />;
}

// Extend for permission check:
function ProtectedRoute({ requiredPermission }: { requiredPermission: string }) {
  const { isAuthenticated } = useAuthStore();
  const { can, isLoading } = usePermissions();  // usePermissions.ts line 14

  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (isLoading) return null; // or a loading spinner
  if (!can(requiredPermission)) return <ForbiddenPage />;
  return <Outlet />;
}
```

**Source for `can` hook:** `frontend/src/hooks/usePermissions.ts` lines 14-22 (already implements wildcard check).

### Frontend MFA branch in LoginPage
**Source:** self `frontend/src/pages/LoginPage.tsx` lines 98-101 (existing `mfa_required` branch)
**Apply to:** add `mfa_setup_required` branch after line 101 (CQ-F31)
```typescript
// Existing (line 98-101):
if (data.mfa_required) {
  setMfaChallengeToken(data.challenge_token ?? "");
  setStep("mfa");
  return;
}

// Add (CQ-F31):
if (data.mfa_setup_required) {
  // Navigate to MFA setup flow with setup_token in state
  navigate("/profile/mfa", { state: { setup_token: data.setup_token } });
  return;
}
```

### Frontend fetchCurrentUser + setTenantContext
**Source:** `frontend/src/lib/fetchCurrentUser.ts` lines 14-28 (returns `AuthUser`), `frontend/src/stores/auth.ts` line 45 (`setTenantContext` action)
**Apply to:** `useAuthInit.ts` — call `setTenantContext` after `/auth/me` resolves (CQ-F29)

The `/auth/me` response must include `tenant_slug` and `org_slug`. If the API response already has them, extend `fetchCurrentUser` to return them. If not, they need to be added to the me endpoint response.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `frontend/src/components/Toaster.tsx` (NEW) | component | event-driven | No existing Radix-UI toast provider in codebase; use standard `@radix-ui/react-toast` setup pattern |
| `frontend/src/lib/apiError.ts` (NEW) | utility | transform | No existing shared error-to-string helper; pattern distilled from LoginPage.tsx lines 118-128 (AxiosError unwrapping) |

---

## Metadata

**Analog search scope:** `crates/axiam-db/src/`, `crates/axiam-api-rest/src/`, `crates/axiam-auth/src/`, `crates/axiam-api-grpc/src/`, `crates/axiam-amqp/src/`, `crates/axiam-pki/src/`, `crates/axiam-oauth2/src/`, `frontend/src/`, `docker/`, `k8s/`
**Files scanned:** ~35 source files read directly
**Pattern extraction date:** 2026-06-13

### SurrealDB v3 Quirks to Apply in This Phase

- `bind()` requires owned `String`, not `&String` — always `.to_string()` UUIDs before binding
- `BEGIN TRANSACTION` occupies slot 0; use `.take(1)` for first statement
- `UPDATE SET field += 1` is atomic in SurrealDB v3 (no TOCTOU) — verified pattern for SEC-032
- `.check()` takes ownership of `IndexedResults`; reassign after: `let mut r = result.check()?`
- `type::record('table', $id)` is the correct v3 syntax (not `type::thing()`)
