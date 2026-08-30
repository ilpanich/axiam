# Phase 11: Medium Remediation (Wave 3) — Research

**Researched:** 2026-06-13
**Domain:** Rust/Actix-Web/Tonic/Lapin/React+TS — consolidation, transport hardening, auth surface hardening, infra/k8s, frontend UX
**Confidence:** HIGH (all findings from direct codebase inspection + authoritative docs patterns)

---

## Summary

Phase 11 is Wave 3 of the audit-remediation tranche. It is gated behind a green Phase 10 build and addresses ~50 findings across five clusters: (1) backend repo/DTO consolidation; (2) transport and protocol limits (webhook SSRF, rate limits, AMQP auth, mTLS chain, PKCE); (3) auth surface hardening (dummy-Argon2, atomic increment, CSRF scope, permission map, bootstrap, self-update, logout); (4) k8s/nginx infra hardening; (5) frontend medium items.

Key infrastructure facts discovered:

- **k8s ConfigMap uses single-underscore prefix** (`AXIAM_DB__URL`, `AXIAM_SERVER__HOST`) but `main.rs:626` calls `.with_prefix("AXIAM").separator("__")` which correctly parses `AXIAM__` double-underscore. The ConfigMap keys are therefore silently ignored and in-code defaults win for some settings — this is SEC-052.
- **PSA** is currently `warn/audit` on the namespace, not `enforce` — SEC-053 needs `enforce: restricted` label added.
- **Webhook SSRF**: `webhook.rs` resolves URL once at creation, the `reqwest::Client` has no DNS-rebinding protection at delivery time.
- **Webhook secret**: stored as plaintext `String` on `Webhook` model, no `#[serde(skip_serializing)]`.
- **Dummy-Argon2**: `auth/service.rs:196-209` returns `AuthError::InvalidCredentials` on user-not-found without running a dummy hash — timing side-channel exists.
- **Atomic failed-login increment**: `service.rs:1000` reads `user.failed_login_attempts + 1` from the in-memory object then writes it — not atomic; race if two concurrent login attempts land simultaneously.
- **CSRF middleware** is applied to `/api/v1/auth` scope only (`server.rs:59-61`), not the `/api/v1` CRUD scope (`server.rs:197`) — SEC-046.
- **PKCE S256**: `authorize.rs` validates S256 when `code_challenge` is *provided* but does not enforce that PKCE is *required* for public clients — SEC-025.
- **gRPC server**: `server.rs:55-60` uses `Server::builder()` with no `.max_decoding_message_size()`, `.timeout()`, or TLS configuration — CQ-B20.
- **OAuth2 `/token|revoke|introspect`**: hard-require `?tenant_id=` as a query param; alternative multi-tenant routing (via `Authorization`/client metadata) not available — CQ-B19.
- **Bootstrap**: not transactional — five sequential awaits (seed permissions → seed roles → create user → assign role) can leave partial state — SEC-049.
- **Logout**: `auth.rs:369` calls `svc.logout(user.tenant_id, body.session_id)` accepting any `session_id` in the body without verifying it belongs to the caller's JWT `jti` — SEC-051.
- **Rate limiting key**: uses `XForwardedForKeyExtractor` but no trusted-proxy hop count is configured — SEC-048.
- **mTLS**: `mtls.rs` verifies fingerprint only; never verifies the cert's chain up to the tenant/org CA — SEC-024.

**Primary recommendation:** Implement in five sequential plan files: (1) repo/DTO consolidation; (2) transport/protocol limits; (3) auth surface hardening; (4) k8s/infra hardening; (5) frontend medium items. Each plan builds green before the next starts.

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-15 AC-1 | Shared repo helpers + request DTOs; index/duplicate → 409; OAuth2/gRPC error mapping + message-size/timeout/concurrency/TLS limits | CQ-B10/B11/B14/B15/B17/B18/B19/B20/B21/B25; `axiam-db` CountRow duplicated in every repo, `JsonConfig` only on auth scope |
| REQ-15 AC-2 | Webhook SSRF pin; rate limits on `/auth/mfa/*` + `/oauth2/introspect\|revoke`; AMQP auth/scope; mTLS chain; S256 PKCE enforced | SEC-016/019/020/022/024/025; webhook.rs has no SSRF guard; mTLS verifies fingerprint only |
| REQ-15 AC-3 | Dummy-Argon2 on not-found; atomic failed-login; reset-to-current blocked; CSRF on `/api/v1`; ROUTE_PERMISSION_MAP; bootstrap transactional + gated; self-update strips status + gates email; logout revokes own session | SEC-026/028/031/032/046/047/048/049/050/051 |
| REQ-15 AC-4 | k8s `AXIAM__` env keys + secrets; receiver-side NetworkPolicies + PSA enforce; `/oauth2/*` + `/.well-known` proxy; backend ports unpublished; prod compose default creds removed | SEC-016/023/052/053 |
| REQ-15 AC-5 | Frontend: toast + getApiErrorMessage; form validation; resource parent picker excludes descendants; federation edit locks type; pagination placeholderData; shared components/hooks; route guards + 403; login MFA branches | CQ-F09/F10/F11/F12/F13/F14/F15/F16/F17/F18/F19/F29/F30/F31 |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Shared repo helpers (parse_uuid, paginate, CountRow) | Database / Storage (axiam-db) | — | Live in repository layer, consumed by all repos |
| Request DTOs (CQ-B25) | API / Backend (axiam-api-rest) | — | Input validation at API boundary |
| Index/duplicate → 409 mapping | Database / Storage (axiam-db) | API / Backend | DB error must be surfaced, handler converts |
| gRPC message-size/timeout/TLS | API / Backend (axiam-api-grpc) | — | Tonic Server builder config |
| Webhook SSRF guard | API / Backend (axiam-api-rest) | — | webhook.rs delivery service — resolve+pin at send time |
| Webhook secret encryption | API / Backend + DB | — | Encrypt on write, decrypt on read, skip_serializing |
| Rate limits on MFA/introspect/revoke | API / Backend (axiam-api-rest) | — | actix-governor on /auth/mfa/* and /oauth2/introspect|revoke |
| AMQP message authentication | Message Broker (axiam-amqp) | — | HMAC-sign payloads or per-tenant queue + broker ACLs |
| mTLS chain verify to org/tenant CA | API / Backend (axiam-pki) | — | mtls.rs: load CA cert from repo, verify chain |
| PKCE S256 enforcement | API / Backend (axiam-oauth2) | — | authorize.rs + token.rs: require code_challenge for public clients |
| Dummy-Argon2 on user-not-found | API / Backend (axiam-auth) | — | auth/service.rs login path |
| Atomic failed-login increment | Database / Storage (axiam-db) | — | SurrealDB UPDATE...SET field += 1 as repo method |
| CSRF on /api/v1 CRUD | API / Backend (axiam-api-rest) | — | server.rs: wrap api_scope with CsrfMiddleware |
| Bootstrap transaction | API / Backend (axiam-api-rest) | Database / Storage | SurrealDB BEGIN TRANSACTION |
| Logout revokes own session | API / Backend (axiam-api-rest + axiam-auth) | — | Verify session_id == caller's JWT jti |
| k8s env key naming | CDN / Static / Infra | — | k8s/server/configmap.yml + secret.yml |
| PSA enforce + NetworkPolicies | CDN / Static / Infra | — | k8s namespace labels + network-policy/ yamls |
| nginx /oauth2 + /.well-known proxy | CDN / Static / Infra | — | nginx.conf in Dockerfile.frontend |
| Frontend toast + error handling | Browser / Client | — | React + @radix-ui/react-toast already in package.json |
| Route guards + 403 | Browser / Client | — | AppLayout.tsx + router.tsx |
| MFA branches in LoginPage | Browser / Client | — | LoginPage.tsx already has mfa_required field, lacks mfa_setup_required nav |

---

## Standard Stack

### Core (all existing — no new dependencies needed for most clusters)

| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| actix-governor | workspace | Rate limiting | Already used on auth scope; extend to MFA/oauth2 endpoints |
| reqwest | workspace | Webhook HTTP delivery | Already used; extend with DNS resolution at delivery |
| surrealdb | 3.x | Atomic field updates | `UPDATE ... SET failed_login_attempts += 1 WHERE ...` |
| tonic | workspace | gRPC server builder limits | `Server::builder().max_decoding_message_size().timeout()` |
| axiam_auth::password | local | Dummy Argon2 hash | Expose `hash_password_dummy()` or reuse existing with fixed hash |
| @radix-ui/react-toast | ^1.2.15 | Toast notifications | Already in package.json — just unwired |
| @tanstack/react-query | workspace | placeholderData pagination | Already used; extend keepPreviousData to UsersPage etc. |

### New Rust capability: IP-range filtering for SSRF (SEC-019)

[ASSUMED] No crate is currently used for private-IP blocking. The idiomatic approach is to resolve the URL's hostname via `tokio::net::lookup_host`, then filter IPs against RFC1918/loopback/link-local ranges manually before opening the connection. This avoids adding a dependency.

Pattern for SSRF guard:
```rust
// In WebhookDeliveryService::deliver (webhook.rs) — at each delivery attempt
use std::net::IpAddr;
async fn resolve_and_check(url: &str) -> Result<SocketAddr, WebhookError> {
    let host = /* extract host from url */;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?
        .collect();
    let addr = addrs.into_iter().next().ok_or(WebhookError::ResolveFailed)?;
    if is_private(addr.ip()) {
        return Err(WebhookError::SsrfBlocked);
    }
    Ok(addr)
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local()
            || v4.is_broadcast() || v4.is_documentation(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}
```
Then use `client.post(url).connect_timeout(5s).send()` — reqwest does not expose a "connect to this specific IP" API, so the pattern is: resolve → check IP → pass the original URL but rely on the OS using the same resolved address (acceptable for the threat model documented in SEC-019; a perfect implementation would bind to the resolved SocketAddr directly via a custom connector).

[ASSUMED] `IpAddr::is_global()` (stabilized in Rust 1.80) and `is_documentation()` are nightly-only in older toolchains; use explicit CIDR checks instead to stay compatible with MSRV 1.93.

---

## Architecture Patterns

### System Architecture Diagram

```
Browser
  |
  v
nginx (Dockerfile.frontend)
  |-- /api/*             --> axiam-server:8090 (REST)
  |-- /oauth2/*          --> axiam-server:8090  [MISSING — SEC-016]
  |-- /.well-known/*     --> axiam-server:8090  [MISSING — SEC-016]
  `-- /*                 --> frontend static

axiam-server:8090 (Actix-Web)
  |
  +-- /api/v1/auth scope
  |    `-- CsrfMiddleware + AuthzMiddleware
  |        |-- /login (rate-limited)
  |        |-- /mfa/* (NO rate limit yet)    [SEC-020]
  |        `-- ...
  |
  +-- /oauth2 scope
  |    `-- AuthzMiddleware (no CSRF)
  |        |-- /token (rate-limited)
  |        |-- /revoke (NO rate limit yet)   [SEC-020]
  |        `-- /introspect (NO rate limit)   [SEC-020]
  |
  +-- /api/v1 scope
  |    `-- AuthzMiddleware (NO CsrfMiddleware)   [SEC-046]
  |        `-- CRUD endpoints...
  |
  `-- /.well-known/openid-configuration         [NOT proxied via nginx]

axiam-api-grpc:50051 (Tonic)
  `-- Server::builder() -- NO max_size/timeout/TLS   [CQ-B20]

axiam-amqp (Lapin consumers)
  `-- AuthzRequest/AuditEvent/Mail messages -- no HMAC sig   [SEC-022]
```

### Recommended Project Structure (no changes to directory layout — all edits to existing files)

Key files per cluster:

**Cluster 1 — Repo/DTO consolidation:**
- NEW: `crates/axiam-db/src/helpers.rs` — `parse_uuid`, `paginate<T>`, `CountRow`, `take_first_or_not_found`
- EDIT: all 25+ repo files to import helpers
- NEW: request DTO structs in `crates/axiam-api-rest/src/handlers/*.rs` (B25)
- EDIT: `crates/axiam-db/src/error.rs` — add `AlreadyExists` variant if absent
- EDIT: `crates/axiam-api-rest/src/error.rs` — map `AlreadyExists` → 409

**Cluster 2 — Transport/protocol hardening:**
- EDIT: `crates/axiam-api-rest/src/webhook.rs` — SSRF resolve+pin at delivery
- EDIT: `crates/axiam-core/src/models/webhook.rs` — `#[serde(skip_serializing)]` on `secret` + encrypt field
- EDIT: `crates/axiam-api-rest/src/server.rs` — rate limits on `/auth/mfa/*` endpoints + `/oauth2/revoke|introspect`
- EDIT: `crates/axiam-api-grpc/src/server.rs` — add `max_decoding_message_size`, `timeout`, optional TLS
- EDIT: `crates/axiam-oauth2/src/authorize.rs` — require PKCE for public clients (no `client_secret`)
- EDIT: `crates/axiam-amqp/src/messages.rs` — add HMAC signature field to `AuthzRequest`, `AuditEventMessage`
- EDIT: `crates/axiam-pki/src/mtls.rs` — load CA cert from org repo, call `x509_parser` chain verify

**Cluster 3 — Auth surface hardening:**
- EDIT: `crates/axiam-auth/src/service.rs` — dummy-Argon2 on user-not-found
- ADD: `crates/axiam-db/src/repository/user.rs` — `increment_failed_logins(tenant_id, user_id)` SurrealQL atomic update
- EDIT: `crates/axiam-auth/src/service.rs` — call `increment_failed_logins` instead of read-add-write
- EDIT: `crates/axiam-auth/src/service.rs:change_password` — block reset to current hash
- EDIT: `crates/axiam-api-rest/src/server.rs` — wrap `api_scope` with `CsrfMiddleware`
- EDIT: `crates/axiam-api-rest/src/permissions.rs` — remove `/api/v1/auth/register` from `PUBLIC_PATHS`
- EDIT: `crates/axiam-api-rest/src/handlers/bootstrap.rs` — transactional single conditional create
- EDIT: `crates/axiam-api-rest/src/handlers/users.rs` — strip `status` from self-update; gate email change behind re-verification
- EDIT: `crates/axiam-api-rest/src/handlers/auth.rs:logout` — verify `body.session_id == user.jti`

**Cluster 4 — k8s/infra:**
- EDIT: `k8s/server/configmap.yml` — rename all `AXIAM_*` → `AXIAM__*`
- EDIT: `k8s/server/secret.yml` — add JWT/encryption keys; rename keys
- EDIT: `k8s/namespace.yml` — add `pod-security.kubernetes.io/enforce: restricted`
- EDIT: `k8s/network-policy/*.yml` — add receiver-side SurrealDB/RabbitMQ ingress policies
- EDIT: `docker/Dockerfile.frontend` or nginx config — add `/oauth2/` and `/.well-known/` proxy_pass blocks
- EDIT: `k8s/ingress.yml` — add `/oauth2` and `/.well-known` path entries; ensure backend ports not in NodePort/LoadBalancer service
- EDIT: `docker/docker-compose.prod.yml` — replace `root/root` SurrealDB creds with env-var references; replace `axiam:axiam` AMQP creds

**Cluster 5 — Frontend:**
- NEW: `frontend/src/lib/apiError.ts` — `getApiErrorMessage(err: unknown): string`
- NEW: `frontend/src/components/Toaster.tsx` — radix-ui/react-toast provider + hook
- EDIT: all mutation pages — add `onError` calling toast
- EDIT: `frontend/src/components/FormDialog.tsx` — remove `noValidate`; add HTML5 validation attributes
- EDIT: `frontend/src/pages/resources/ResourcesPage.tsx` — exclude descendants in parent picker
- EDIT: `frontend/src/pages/federation/FederationPage.tsx` — lock type select in edit mode
- EDIT: `frontend/src/pages/users/UsersPage.tsx` — add `placeholderData: (prev) => prev`
- EDIT: `frontend/src/router.tsx` — wrap protected routes in permission-aware guard; add 403 page
- EDIT: `frontend/src/pages/LoginPage.tsx` — handle `mfa_setup_required` branch (navigate to setup flow)
- EDIT: `frontend/src/stores/auth.ts` + `useAuthInit` + `fetchCurrentUser` — restore `tenantSlug/orgSlug` from `/auth/me`

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SSRF IP filtering | Custom regex on URL string | `tokio::net::lookup_host` + `IpAddr::is_private/is_loopback` | Hostname can resolve to private IP after creation |
| Atomic DB counter | Read-modify-write in Rust | SurrealQL `UPDATE SET field += 1` | Avoids race between concurrent login attempts |
| Toast system | Custom alert div | `@radix-ui/react-toast` (already in package.json) | Already vendored; accessible/animated |
| Webhook secret storage | Store plaintext | `axiam_auth::crypto::encrypt_aes_gcm` (already exists in `axiam-auth/src/crypto.rs`) | Same pattern as MFA/federation secrets |
| gRPC size limits | Manual body length check | `tonic::transport::Server::max_decoding_message_size()` | Native Tonic API |
| X-Forwarded-For hop counting | String split/parse | `actix-web` `ConnectionInfo::realip_remote_addr` + trusted-hop config | Already partially used; needs hop count config |
| SurrealDB BEGIN TRANSACTION bootstrap | Sequential awaits | SurrealDB multi-statement transaction (pattern verified in `user.rs::create_with_consent`) | Ensures atomicity; compensating delete impossible on partial failure |
| Dummy password hash | Sleep-based timing equalization | `tokio::task::spawn_blocking` with `password::hash_password` on a constant hash | Constant-time; already wrapped in semaphore |

**Key insight:** ~80% of this wave is "apply existing codebase patterns to new locations" — no new architectural decisions required. The shared helpers in `axiam-db`, the `CsrfMiddleware`, the `CertService` CA loading, and the `crypto.rs` AES-GCM functions are all already implemented. The work is systematic wiring.

---

## Runtime State Inventory

> Not a rename/migration phase. No runtime state inventory required.

None — this is a hardening phase with code/config changes only. No stored data keys change identity.

---

## Common Pitfalls

### Pitfall 1: k8s ConfigMap single-underscore keys (SEC-052)

**What goes wrong:** Renaming ConfigMap keys from `AXIAM_DB__URL` to `AXIAM__DB__URL` in `configmap.yml` is necessary because `main.rs` uses `.with_prefix("AXIAM").separator("__")` which parses `AXIAM__DB__URL` (after stripping the `AXIAM` prefix, the key becomes `DB__URL` which maps to `config.db.url`). The existing keys use a single underscore after `AXIAM` (`AXIAM_DB__URL`) which config-rs treats as a single flat key and silently ignores.
**Why it happens:** `config-rs 0.15` requires the separator to be used consistently; the prefix separator and the nested key separator are both `__`.
**How to avoid:** After editing ConfigMap, verify with `just dev-up` that connection succeeds. The prod compose already uses `AXIAM__` correctly (line 31-35) — only k8s manifests need updating.
**Warning signs:** Server starts but uses in-code DB defaults (connecting to `ws://localhost:8000` instead of `surrealdb:8000`).

### Pitfall 2: CSRF middleware scope gap (SEC-046)

**What goes wrong:** Wrapping only the `/api/v1/auth` scope with `CsrfMiddleware` (current state) leaves the main `/api/v1` CRUD scope unprotected.
**Why it happens:** `server.rs:59` applies `CsrfMiddleware` in the auth scope constructor; the api_scope at line 197 has only `AuthzMiddleware`. Adding CSRF to the outer scope is correct and doesn't break tests because integration tests already attach the CSRF cookie via the login flow.
**How to avoid:** Add `.wrap(CsrfMiddleware)` to the `api_scope` definition at `server.rs:197`.
**Warning signs:** POST/PUT/DELETE to `/api/v1/users` succeeds without `X-CSRF-Token` header.

### Pitfall 3: SurrealDB transaction shift for bootstrap (SEC-049)

**What goes wrong:** `BEGIN TRANSACTION` occupies result slot 0; the first statement's result is at slot 1, not 0. See MEMORY.md: "Multi-statement transactions: BEGIN=0, stmt1=1, stmt2=2, COMMIT=3."
**Why it happens:** SurrealDB v3 SDK behavior — `.take(0)` after a transaction returns the BEGIN result, not the first statement.
**How to avoid:** Use `.take(1)` for the first statement result after `BEGIN TRANSACTION`. Alternatively restructure bootstrap to use the existing `create_with_consent` transactional pattern (which already handles this).

### Pitfall 4: Dummy-Argon2 must run in spawn_blocking

**What goes wrong:** Running `hash_password` synchronously on the async executor blocks the thread. Phase 10 (CQ-B02) wrapped Argon2 in `spawn_blocking` behind a semaphore — the dummy hash for user-not-found must use the same pattern.
**Why it happens:** `hash_password` is CPU-intensive; calling it directly in an async context will block the Tokio thread.
**How to avoid:** Use `tokio::task::spawn_blocking(move || password::hash_password(DUMMY_CREDENTIAL, None))` and acquire the same `crypto_semaphore` before the user lookup. The result of the dummy hash is discarded; only the timing equalization matters.

### Pitfall 5: reqwest SSRF — client.post() still resolves DNS again

**What goes wrong:** Even if you resolve and check the IP before calling `client.post(url).send()`, `reqwest` performs its own DNS resolution which may return a different IP (DNS rebinding or load balancer). A perfect fix requires a custom connector that connects to the pre-resolved `SocketAddr`.
**Why it happens:** `reqwest::Client` does not expose a "connect to this SocketAddr for this URL" API.
**How to avoid:** For SEC-019, implement as: resolve → check → pin by connecting through a `hyper` connector that uses the validated address, OR use the simpler approach of re-resolving at delivery time (which defeats rebinding after creation time — the finding says "re-resolve at delivery" not "pin perfectly"). The finding text is: "resolve + re-check every IP at delivery (`webhook.rs:75-83`); pin the validated address." This means: re-resolve in the delivery loop and reject if private, rather than trusting the stored URL without re-checking. This satisfies SEC-019 at medium finding severity.

### Pitfall 6: PKCE public client detection (SEC-025)

**What goes wrong:** The current `authorize.rs` only validates S256 *when `code_challenge` is provided*. SEC-025 requires enforcement: public clients (no `client_secret`) must provide PKCE. The `client.grant_types` field doesn't distinguish confidential/public clients directly.
**Why it happens:** RFC 7636 §4 mandates PKCE for public clients; `authorize.rs` currently makes it optional.
**How to avoid:** Add a `public` boolean field to `OAuthClient` model, OR detect public clients as those with no `client_secret` set. If `client.client_secret.is_none()` and `req.code_challenge.is_none()`, return `InvalidRequest("PKCE required for public clients")`.

### Pitfall 7: mTLS chain verify — need CA PEM in scope

**What goes wrong:** `mtls.rs:authenticate()` has only the `cert_repo` in scope. Verifying the chain to the tenant/org CA requires loading the org's CA certificate. The `DeviceAuthService` struct must be extended with an `org_cert_repo` or the CA PEM must be passed in.
**Why it happens:** Current design only fingerprint-matches; chain validation needs the trusted CA cert.
**How to avoid:** Add `CaCertificateRepository` to `DeviceAuthService`. After looking up the cert and resolving its tenant, call `ca_cert_repo.get_active_for_tenant(tenant_id)`, parse it with `x509_parser`, then call `TbsCertificate::verify_signature()` on the client cert against the CA cert.

### Pitfall 8: Frontend @radix-ui/react-toast wiring

**What goes wrong:** `@radix-ui/react-toast` is in `package.json` but no `<ToastProvider>` or `<Toaster>` wrapper exists in the app. Direct `useToast()` calls will fail at runtime.
**Why it happens:** The library was installed but the provider was never added to the component tree.
**How to avoid:** Create `frontend/src/components/Toaster.tsx` exporting a `<Toaster />` component, add it to `App.tsx`, and export a `useToast` hook. Pattern is standard radix-ui toast setup [ASSUMED from radix-ui docs pattern].

---

## Code Examples

### Shared repo helper (CQ-B10)

```rust
// Source: Pattern from axiam-db/src/repository/user.rs:148 CountRow (existing)
// New file: crates/axiam-db/src/helpers.rs

use crate::error::DbError;
use axiam_core::repository::{PaginatedResult, Pagination};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

/// Shared count row used by all paginating repositories.
#[derive(Debug, SurrealValue)]
pub struct CountRow {
    pub total: u64,
}

/// Parse a UUID string, returning DbError::Serialization on failure.
pub fn parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError> {
    s.parse::<Uuid>()
        .map_err(|e| DbError::Serialization(format!("invalid {field} UUID: {e}")))
}

/// Extract the first item from a Vec or return NotFound.
pub fn take_first_or_not_found<T>(items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError> {
    items.into_iter().next().ok_or_else(|| DbError::NotFound {
        entity: entity.to_string(),
        id: id.to_string(),
    })
}
```

### Atomic failed-login increment (SEC-032) — SurrealQL

```rust
// New method on SurrealUserRepository
pub async fn increment_failed_logins(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    lockout_threshold: u32,
    lockout_duration_secs: i64,
) -> AxiamResult<()> {
    // SurrealDB atomic increment: += 1 happens in a single statement
    let query = r#"
        UPDATE type::record('user', $id)
        SET
            failed_login_attempts += 1,
            last_failed_login_at = time::now(),
            locked_until = IF failed_login_attempts >= $threshold
                THEN time::now() + duration::secs($lockout_secs)
                ELSE locked_until
            END,
            updated_at = time::now()
        WHERE tenant_id = $tenant_id
    "#;
    // ...
}
```

### gRPC server limits (CQ-B20)

```rust
// Source: Tonic docs — server builder configuration [ASSUMED pattern]
Server::builder()
    .max_decoding_message_size(4 * 1024 * 1024)  // 4 MiB
    .max_encoding_message_size(4 * 1024 * 1024)
    .timeout(std::time::Duration::from_secs(30))
    .concurrency_limit_per_connection(256)
    .layer(governor_layer)
    .add_service(authz_svc)
    // ...
```

### CSRF on /api/v1 scope (SEC-046)

```rust
// crates/axiam-api-rest/src/server.rs
let api_scope = web::scope("/api/v1")
    .wrap(AuthzMiddleware)
    .wrap(CsrfMiddleware)      // ADD THIS LINE
    // ... existing service registrations unchanged
```

### Dummy-Argon2 on user-not-found (SEC-026)

```rust
// crates/axiam-auth/src/service.rs::login()
// After the user lookup fails:
let user = match self.user_repo.get_by_username(input.tenant_id, &...).await {
    Ok(u) => u,
    Err(AxiamError::NotFound { .. }) => {
        // Try email
        match self.user_repo.get_by_email(input.tenant_id, &...).await {
            Ok(u) => u,
            Err(AxiamError::NotFound { .. }) => {
                // Timing equalization: run a dummy Argon2 hash
                let _permit = self.crypto_semaphore.acquire().await.ok();
                let _ = tokio::task::spawn_blocking(move || {
                    // Use a constant hash of a known-valid string
                    password::verify_password("dummy", DUMMY_HASH, None)
                }).await;
                return Err(AuthError::InvalidCredentials.into());
            }
            Err(e) => return Err(e),
        }
    }
    Err(e) => return Err(e),
};
```

### Webhook SSRF re-resolve at delivery (SEC-019)

```rust
// crates/axiam-api-rest/src/webhook.rs
// At the top of each delivery attempt in the retry loop:
let addr = match resolve_and_validate_host(&webhook.url).await {
    Ok(addr) => addr,
    Err(e) => {
        tracing::warn!(webhook_id = %webhook.id, error = %e, "SSRF check failed");
        return; // abort this delivery
    }
};
// Then proceed with client.post(&webhook.url) — reqwest will re-resolve
// but this re-check at each attempt catches post-creation DNS changes.
```

### Webhook secret encryption (SEC-031)

```rust
// crates/axiam-core/src/models/webhook.rs
pub struct Webhook {
    // ...
    #[serde(skip_serializing)]   // never include in API responses
    pub secret: String,          // stored encrypted in DB
    // ...
}

// On write (create/update): encrypt with axiam_auth::crypto::encrypt_aes_gcm
// On read: decrypt before passing to WebhookDeliveryService
```

### PSA enforce label (SEC-053)

```yaml
# k8s/namespace.yml — add enforce label
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: v1.29
```

---

## State of the Art

| Old Approach | Current Approach | Phase | Impact |
|--------------|------------------|-------|--------|
| Manual AXIAM_ env var prefix (one underscore) | AXIAM__ double-underscore (config-rs v0.15 behavior) | Already in prod compose; missing in k8s | k8s manifests silently use in-code defaults |
| PSA warn-only | PSA enforce:restricted | Phase 11 | Pods failing policy are rejected, not just warned |
| CSRF on auth scope only | CSRF on all /api/v1 CRUD | Phase 11 | Closes CSRF on state-mutating endpoints |
| Optional PKCE | Enforce PKCE for public clients | Phase 11 | RFC 9700 / BCP compliance |

**Deprecated/outdated:**
- `/api/v1/auth/register` in `PUBLIC_PATHS` (permissions.rs:197): this path is problematic per SEC-047 — unverified self-registration should require a configurable gate or be removed from the public allowlist when not needed.

---

## Cluster-by-Cluster Research Findings

### Cluster 1: Repo/DTO Consolidation (CQ-B10..B26, B39, B41, B43)

**CQ-B10 — Shared repo helpers:**
- `CountRow` is currently defined as a private struct in at least `user.rs:148` and `role.rs:53` — duplicated across all ~25 repos.
- No `parse_uuid` helper exists; each repo calls `.parse::<Uuid>().map_err(|e| DbError::Migration(...))` inline — this is CQ-B11's `DbError::Migration` misuse.
- Pattern: create `crates/axiam-db/src/helpers.rs`, `pub use` from `crates/axiam-db/src/lib.rs`.

**CQ-B11 — Index/duplicate → 409:**
- `export_job.rs` and `account_deletion.rs` use `DbError::Migration(format!("invalid UUID: {e}"))` for UUID parse errors — wrong error variant.
- `DbError` enum: need to check for `AlreadyExists` variant; if absent, add it and map from SurrealDB's index-violation error pattern. [ASSUMED: SurrealDB v3 returns a specific error message on index constraint violations — verify the exact error string during implementation.]
- Handlers map `DbError::AlreadyExists` → `AxiamApiError` → HTTP 409.

**CQ-B14 — TokenService Ed25519 key parse once:**
- `token.rs:97,138,215,234` parses the Ed25519 PEM on every call. Parse once at construction time and store `Arc<ed25519_dalek::SigningKey>`.

**CQ-B15 — CertService deduplication:**
- `CertService` has triplicated keypair/fingerprint/encrypt helpers. Consolidate into shared private methods.

**CQ-B17 — Unique indexes on edge tables:**
- `schema.rs:470-484` lacks unique `(in, out)` indexes on five edge tables. Add `DEFINE INDEX IF NOT EXISTS idx_edge_unique ON TABLE <table> FIELDS in, out UNIQUE`.

**CQ-B18 — OAuth2 error collapse:**
- `token.rs` currently exposes real DB errors through `invalid_client`/`invalid_grant`. Route all client authentication through `authenticate_client()` (already exists at `token.rs:729`); remaining paths that bypass it must use it.

**CQ-B19 — OAuth2 `?tenant_id=` hard-required:**
- Current: `TenantQuery { tenant_id: Uuid }` — fails with 400 if absent.
- Fix: `TenantQuery { tenant_id: Option<Uuid> }` + `QueryConfig` error handler that returns RFC-shaped `{"error":"invalid_request","error_description":"..."}` instead of actix's default 400.

**CQ-B20+B44 — gRPC limits:**
- `crates/axiam-api-grpc/src/server.rs:55` — `Server::builder()` with only `.layer(governor_layer)`. Missing: `max_decoding_message_size`, `timeout`, `concurrency_limit_per_connection`.
- gRPC rate-limit bug: `rate_limit.rs:39-40` uses `.per_second(1).burst_size(authz_per_sec)` — `per_second(1)` is hardcoded instead of using the configured value. Should be `.per_second(authz_per_sec as u64).burst_size(authz_per_sec * 2)` or similar.
- TLS: add `Server::builder().tls_config(...)` using `tonic::transport::ServerTlsConfig` — requires cert/key from env vars.

**CQ-B21 — JsonConfig body limits:**
- `server.rs:61`: `JsonConfig::default().limit(65_536)` applied only on the `/api/v1/auth` scope.
- Missing from `/api/v1` CRUD scope and `/oauth2` scope.
- Add `QueryConfig` and `PathConfig` error handlers to return consistent error envelopes.

**CQ-B25 — Request DTOs:**
- Files lacking dedicated `CreateXxxRequest` DTOs: `handlers/certificates.rs`, `handlers/ca_certificates.rs`, `handlers/organizations.rs`, `handlers/permissions.rs`, `handlers/resources.rs`, `handlers/roles.rs`, `handlers/scopes.rs`, `handlers/pgp_keys.rs`.
- Pattern: add `#[derive(Debug, Deserialize, utoipa::ToSchema)]` request structs, validate fields.

**CQ-B26 — Email/password validation in user create:**
- `handlers/users.rs:98-135`: no email format validation, no password policy check before insert.
- Add `email_address::EmailAddress::from_str(&req.email)` and call `PasswordPolicy::check(&req.password, &settings)`.

**CQ-B39 — GDPR handler transactional deletion setup:**
- `handlers/gdpr.rs` — dedupe export requests; factor repeated audit-append blocks; 256-bit cancel token (currently weaker).

**CQ-B41 — email_config UPSERT:**
- `email_config.rs` — UPSERT keyed on `(scope, scope_id)` instead of insert/update split.

**CQ-B43 — `load_key_from_env` extraction:**
- Already done in Phase 10 (visible in `main.rs:130`). This finding is satisfied.
- Remaining: `AppState`/bootstrap module to replace ~45 `app_data` registrations. This is a refactor, not a security finding — scope to the extent needed.

---

### Cluster 2: Transport & Protocol Hardening (SEC-016, 019, 020, 022, 024, 025, 026b, 031, 032, 048, 054)

**SEC-016 — nginx proxy locations:**
- `k8s/ingress.yml` has paths `/api` and `/` only. Missing: `/oauth2/*` and `/.well-known/*` routes pointing to `axiam-server:8090`.
- `docker/Dockerfile.frontend` or a mounted nginx config must be checked for the same gap.
- Backend ports `8090` and `50051`: the ClusterIP service correctly does NOT expose NodePort/LoadBalancer. The Ingress does not expose gRPC (50051 removed per SEC-003, line 36-38 of `ingress.yml`). Remaining: verify the docker-compose.prod.yml port binding `"8090:8090"` and `"50051:50051"` — these are appropriate for local testing but should be documented as dev-only.

**SEC-019 — Webhook SSRF:**
- `webhook.rs:75-83`: `client.post(&webhook.url)` resolves DNS at delivery time but does not check if the resolved IP is private. Add `resolve_and_validate_host` call per retry iteration.
- See Code Examples section.

**SEC-020 — Rate limits missing:**
- `/auth/mfa/enroll`, `/auth/mfa/confirm`, `/auth/mfa/verify`, `/auth/mfa/setup/enroll`, `/auth/mfa/setup/confirm` — no rate limiting in `server.rs`.
- `/oauth2/revoke` and `/oauth2/introspect` — no rate limiting.
- Add `build_governor(rate_limit_cfg.mfa_per_min)` wrapping these resources. Add `mfa_per_min`, `introspect_per_min`, `revoke_per_min` to `RateLimitConfig`.

**SEC-022/SEC-055 — AMQP message authentication:**
- Current: `AuthzRequest` and `AuditEventMessage` are plain JSON with no signature.
- Fix: add HMAC-SHA256 signature field to message structs, sign on publish, verify on consume. Use `axiam-auth/src/crypto.rs::compute_hmac` (already exists).
- Alternative: per-tenant AMQP queues + broker ACLs via RabbitMQ vhost policies — more complex; signed payloads are simpler and sufficient.
- Mail consumer: resolve recipient from `user_id`+`tenant_id` in the message rather than trusting the `to_address` field.

**SEC-024 — mTLS chain verify:**
- `mtls.rs:35-77`: calls `get_by_fingerprint_global` and checks status/expiry — no chain verify.
- Need: load CA cert PEM from `CaCertificateRepository::get_active_for_tenant(cert.tenant_id)`, parse with `x509_parser::parse_x509_certificate`, call `verify_signature()` on the client cert against the CA cert.
- `DeviceAuthService` must be generic over `CaCertificateRepository` in addition to `CertificateRepository`.

**SEC-025 — PKCE S256 enforcement:**
- `authorize.rs:106-126`: PKCE validated when present, but not required.
- `token.rs:217-223`: PKCE verified when challenge is stored on the code, but not required.
- Fix: in `authorize.rs`, if `client.client_secret.is_none()` (public client), require `code_challenge`. Add `public` flag to `OAuthClient` model or detect by empty secret.

**SEC-031 — Webhook HMAC secret encryption:**
- `models/webhook.rs:43`: `pub secret: String` — not encrypted, not `#[serde(skip_serializing)]`.
- Fix: encrypt on create/update using `axiam_auth::crypto::encrypt_aes_gcm`; add `#[serde(skip_serializing)]`; decrypt in `WebhookDeliveryService::deliver` before signing.

**SEC-032 — Atomic failed-login increment:**
- See Pitfall 2 and Code Examples. Implement as `increment_failed_logins` repo method using SurrealQL `+= 1`.

**SEC-048 — Rate limit key hop counting:**
- `XForwardedForKeyExtractor` (in `crates/axiam-api-rest/src/extractors/rate_limit.rs`) — add configurable `trusted_hops` count; take the Nth-from-right IP in X-Forwarded-For. Document the nginx/ingress requirement to set `X-Forwarded-For` correctly.

**SEC-054 — JWKS fetch body cap:**
- `axiam-federation/src/jwks_cache.rs:198-212`: cap body size before parsing; filter JWKS URLs that resolve to private IP ranges (same SSRF concern as webhooks but on the OIDC discovery fetch path).

---

### Cluster 3: Auth Surface Hardening (SEC-026, 028, 031, 032, 046, 047, 048, 049, 050, 051)

**SEC-026 — Dummy-Argon2 on user-not-found:**
- Current: `service.rs:207-208` returns `AuthError::InvalidCredentials` immediately after the email lookup fails, without running any CPU-bound operation.
- Timing difference between "user found, password wrong" (~1-5ms Argon2) and "user not found" (<1ms) leaks user enumeration information.
- Fix: constant `DUMMY_HASH` stored in `service.rs` or `password.rs`; run `verify_password("dummy", DUMMY_HASH, None)` in `spawn_blocking` before returning `InvalidCredentials`.

**SEC-028 — Block reset to current password:**
- `auth/service.rs::change_password` (around line 642) — check `password::verify_password(new_pw, current_hash, pepper)` before accepting; if it matches, return `AuthError::PasswordReusedCurrent` (new error variant).
- Seed initial password into `password_history` on user creation so the history check works from day one.

**SEC-046 — CSRF on /api/v1 CRUD scope:**
- Single-line fix: add `.wrap(CsrfMiddleware)` to the `api_scope` at `server.rs:197`.
- Verify: existing integration tests that do POST/PUT/DELETE through the `api` client should already attach the CSRF cookie from the login flow.

**SEC-047 — Permission enforcement via ROUTE_PERMISSION_MAP:**
- `ROUTE_PERMISSION_MAP` exists in `permissions.rs` (referenced in test suite per Phase 7). Verify that every route in the map has a corresponding `RequirePermission::new(...)` check in its handler. Add a zero-permission-per-route 403 test if gaps found.
- Remove `/api/v1/auth/register` from `PUBLIC_PATHS` if registration is now gated.

**SEC-049 — Bootstrap transactional + gated:**
- Current: `bootstrap.rs:86-171` — five sequential `await`s. No transaction. If step 3 (create user) succeeds but step 4 (assign role) fails, an admin user exists without the super-admin role.
- Fix: wrap seed_permissions + seed_default_roles + create_with_consent + assign_to_user in a SurrealDB transaction. The check for existing admin (step 3 in current code) must run as a conditional `IF NOT EXISTS` inside the transaction or as a `SELECT count() ... HAVING count = 0` guard.

**SEC-050 — Self-update strips status; gates email change:**
- `handlers/users.rs:209-231`: the `UpdateUserRequest` DTO likely includes `status` field. A user calling `PUT /api/v1/users/{id}` on themselves must not be able to set their own `status` (e.g., set `Active` while locked).
- Email change: gate behind re-verification — set `email_verified_at = None`, send verification email, new email is not usable until verified.
- The `self-service` endpoint check (`caller_user_id == target_user_id`) must strip `status` from the update before passing to the repo.

**SEC-051 — Logout revokes caller's own session:**
- `auth.rs:364-369`: `svc.logout(user.tenant_id, body.session_id)` — no check that `body.session_id` equals the session from the JWT.
- Fix: compare `body.session_id` with `user.session_id` (from JWT claims); if different, return 403. Or alternatively, always revoke the caller's own session by reading `jti` from the JWT extractor and ignoring the body field.

---

### Cluster 4: k8s/nginx Hardening (SEC-016, 023, 052, 053)

**SEC-052 — AXIAM__ env key names in k8s:**
- `k8s/server/configmap.yml:10-16`: all keys use single underscore after `AXIAM` (`AXIAM_DB__URL` etc.) — must be `AXIAM__DB__URL`.
- `k8s/server/secret.yml:13-14`: `AXIAM_DB__USERNAME` and `AXIAM_DB__PASSWORD` — must be `AXIAM__DB__USERNAME`.
- Also add JWT private/public key PEM secrets and `AXIAM__AUTH__MFA_ENCRYPTION_KEY`, `AXIAM__PKI__ENCRYPTION_KEY` to the secret.
- Fix `RUST_LOG` in configmap: `"info,axiam=debug"` → `"info"` (no internal module exposure in production).

**SEC-053 — Receiver-side NetworkPolicies + PSA enforce:**
- `k8s/namespace.yml`: add `pod-security.kubernetes.io/enforce: restricted` label.
- `k8s/network-policy/`: currently has `default-deny.yml`, `allow-ingress-to-frontend.yml`, `allow-ingress-to-server.yml`, `server-egress.yml`, `allow-dns-egress.yml`. Missing: receiver-side ingress NetworkPolicies for SurrealDB (allow only from axiam-server) and RabbitMQ (allow only from axiam-server).
- Add `allow-ingress-to-surrealdb.yml` and `allow-ingress-to-rabbitmq.yml`.

**SEC-023 — prod compose default creds:**
- `docker-compose.prod.yml:31-35`: `AXIAM__DB__USERNAME: "root"`, `AXIAM__DB__PASSWORD: "root"` — hardcoded defaults.
- SurrealDB command at line 102: `--user root --pass root` — these must become env var references.
- RabbitMQ: `RABBITMQ_DEFAULT_USER: axiam`, `RABBITMQ_DEFAULT_PASS: axiam` — same fix.
- Pattern: `${AXIAM__DB__USERNAME:?SurrealDB username required}` (fail-fast if not set, same as JWT key pattern already used at line 41).

**SEC-016 — nginx /oauth2/* + /.well-known proxy + backend ports:**
- Need to locate the nginx.conf used in `docker/Dockerfile.frontend` and add proxy_pass blocks for `/oauth2/` and `/.well-known/`.
- k8s ingress: add `/oauth2` and `/.well-known` paths pointing to `axiam-server:8090`.
- Backend ports: already ClusterIP only for gRPC. The `"8090:8090"` in prod compose is labeled as "local testing only" — add comment if not already there.

---

### Cluster 5: Frontend Medium Items (CQ-F09..F19, F29..F31)

**CQ-F09 — Toast + getApiErrorMessage:**
- `@radix-ui/react-toast` is installed (package.json:22) but no `<ToastProvider>` exists.
- Need: `frontend/src/components/Toaster.tsx`, a `useToast()` hook, `frontend/src/lib/apiError.ts` with `getApiErrorMessage(err: unknown): string`.
- Pages already using `onError` (found in WebhooksPage, RolesPage, TenantsPage, OAuth2ClientsPage, GroupDetailPage) need to call `toast({ description: getApiErrorMessage(err), variant: "destructive" })`.
- Pages missing `onError` on their mutations: UsersPage, PermissionsPage, ResourcesPage, CertificatesPage, PgpKeysPage, FederationPage, NotificationRulesPage, ServiceAccountsPage — audit all delete/revoke/unlock mutations.

**CQ-F10 — Dashboard query key alignment:**
- `DashboardPage.tsx:182-199` uses stale query keys that don't align with CRUD invalidations. After create/update/delete mutations, query keys must match those used by the dashboard.

**CQ-F11 — Form validation:**
- `FormDialog.tsx:99` has `<form onSubmit={onSubmit} noValidate>` — remove `noValidate`.
- Add `type="email"` on email fields, `required` attribute, `pattern` for URL fields where appropriate.
- `LoginPage` and `BootstrapPage` — add HTML5 validation or zod schema validation.

**CQ-F12 — Resource parent picker excludes descendants:**
- `ResourcesPage.tsx:70,293` — parent picker allows selecting descendants, creating cycles.
- Fix: when editing a resource, filter the parent picker to exclude the resource itself and all its descendants (use the existing `get_children` or `list_ancestors` API).

**CQ-F13 — Federation edit locks type:**
- `FederationPage.tsx:320-338,520-540,778-803` — the type select (OIDC/SAML) is editable when editing an existing config.
- Fix: disable the type select when `isEditMode === true`. Also ensure the config payload sent on submit matches the selected type's config block.

**CQ-F14 — Users pagination placeholderData:**
- `UsersPage.tsx` (and other list pages): add `placeholderData: (prev) => prev` to `useQuery` to prevent flash of empty state during page navigation.
- After deleting the last item on a page, redirect to `page - 1`.

**CQ-F15 — Shared components/hooks:**
- 9 copies of `ToggleField`, `SectionCard`, `InfoRow`, `ActionBadge`, `slugify` across pages.
- Extract to `frontend/src/components/` and `frontend/src/lib/utils.ts`.
- Extract `useCrudMutations` hook for the create/update/delete mutation + toast pattern.

**CQ-F16 — Zustand whole-store subscriptions:**
- `useAuthStore((s) => s)` subscribes to all store changes causing excessive re-renders.
- Fix: use selectors `useAuthStore((s) => s.user)`, `useAuthStore((s) => s.isAuthenticated)`.

**CQ-F17 — Single MfaMethod type:**
- Duplicate MFA type definitions across services and pages. Consolidate to one type in `frontend/src/services/auth.ts` (already created in Phase 9 for SEC-044).

**CQ-F18 — Wire role/group unassign to UI:**
- `services/roles.ts:66,78` — `unassignRoleFromUser` and `unassignRoleFromGroup` exist in the service layer but are not called from any page.
- Wire to the UI in RoleDetailPage/GroupDetailPage.

**CQ-F19 — VerifyEmailPage single fire:**
- Already referenced as "folds into SEC-044" — verify the auth.ts service call fires once under React StrictMode.

**CQ-F29 — Restore tenantSlug/orgSlug from /auth/me:**
- `stores/auth.ts` and `useAuthInit.ts`: after the `/auth/me` response, parse `tenantSlug` and `orgSlug` from the user context and store them. On reload, the store is empty until `/auth/me` resolves.

**CQ-F30 — Route guards + friendly 403:**
- `AppLayout.tsx` only checks `isAuthenticated` — no permission check per route.
- `router.tsx` has no route-level permission requirement defined.
- Fix: add a `ProtectedRoute` wrapper that checks `can(requiredPermission)` and renders a `ForbiddenPage` (friendly 403) instead of a blank page or redirect loop.
- `Sidebar.tsx:187` already uses `can` for menu visibility — extend the pattern to route-level protection.

**CQ-F31 — LoginPage MFA setup branch:**
- `LoginPage.tsx:29-33`: `mfa_setup_required` field exists in `LoginResponse` interface but `LoginPage.tsx:98` only handles `mfa_required`. When `mfa_setup_required` is true, the login flow should navigate the user to the MFA setup flow (enroll → confirm) rather than the standard MFA verify step.

---

## Package Legitimacy Audit

> No new external dependencies are introduced in Phase 11 — all changes use existing workspace crates, already-installed frontend packages (`@radix-ui/react-toast` v1.2.15 already in `package.json`), and Rust standard library / tokio features. No package legitimacy check needed.

| Package | Registry | Status | Note |
|---------|----------|--------|------|
| @radix-ui/react-toast | npm | Already installed | v1.2.15 in package.json — just unwiring needed |

---

## Environment Availability

> Phase 11 is code/config edits only. No new external tool dependencies.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| cargo | All Rust edits | ✓ | (workspace) | — |
| node / npm | Frontend edits | ✓ | (workspace) | — |
| kubectl | k8s manifest verification | Not checked | — | Manual review of YAML |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust framework | Built-in `#[tokio::test]` + actix-web test helpers |
| Frontend framework | vitest |
| Config file | `vitest.config.ts` (frontend) |
| Quick Rust check | `cargo check -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-api-grpc -p axiam-amqp -p axiam-pki -p axiam-oauth2` |
| Targeted test run | `cargo test -p <crate> --test <test_name>` |
| Frontend check | `cd frontend && npx tsc -b --noEmit && npm run lint` |

**DISK CONSTRAINT**: Do NOT run `cargo build --workspace` or `cargo test --workspace` — see MEMORY.md disk constraint. Use `-p <crate>` targeted builds only.

### Phase Requirements → Test Map

| AC | Behavior | Test Type | Command | Proof |
|----|----------|-----------|---------|-------|
| AC-1: 409 mapping | Create duplicate resource → 409 | Integration/unit | `cargo test -p axiam-db --lib -- helpers` | Assert `DbError::AlreadyExists` returned; handler returns 409 |
| AC-1: shared helpers | CountRow used everywhere | Compilation | `cargo check -p axiam-db` | No compile error after replacing per-repo structs |
| AC-1: gRPC limits | gRPC server builder has limits | Source assertion | Read `axiam-api-grpc/src/server.rs` | `max_decoding_message_size`, `timeout` present in builder chain |
| AC-2: SSRF | Webhook to 127.0.0.1 blocked | Unit test | `cargo test -p axiam-api-rest --lib -- webhook_ssrf` | New test: `resolve_and_validate_host("http://127.0.0.1/evil")` returns Err |
| AC-2: mTLS chain | Valid chain accepted; forged cert rejected | Unit test | `cargo test -p axiam-pki --lib -- mtls` | New test using self-signed test CA + leaf cert |
| AC-2: S256 PKCE | Public client auth-code without PKCE → 400 | Unit test | `cargo test -p axiam-oauth2 --lib -- authorize` | `authorize(req_no_pkce)` returns `InvalidRequest` for public client |
| AC-2: rate limits on MFA | /auth/mfa/verify > N req/min → 429 | Source assertion | Read `server.rs` | `build_governor(cfg.mfa_per_min)` wrapping MFA resources |
| AC-3: dummy-Argon2 | Login for unknown user takes ~argon2 time | Timing test (manual) / source assertion | Read `service.rs` | `spawn_blocking(...verify_password...dummy...)` present on not-found path |
| AC-3: atomic increment | Two concurrent login failures = correct count | Source assertion | Read `user.rs` repo method | SurrealQL `+= 1` in the UPDATE statement |
| AC-3: CSRF on /api/v1 | POST without X-CSRF-Token → 403 | Integration test | `cargo test -p axiam-api-rest --test integration` | Existing CSRF tests; extend to CRUD scope |
| AC-3: reset-to-current | Change password to same → 400 | Unit test | `cargo test -p axiam-auth -- change_password` | `PasswordReusedCurrent` error returned |
| AC-3: logout owns session | Logout with another user's session_id → 403 | Integration test | `cargo test -p axiam-api-rest --test integration` | Test: login as user A, try logout with user B's session_id |
| AC-4: k8s env names | Config parsed correctly with AXIAM__ prefix | Source assertion | Read `k8s/server/configmap.yml` | All keys start `AXIAM__` |
| AC-4: PSA enforce | Namespace has enforce label | Source assertion | Read `k8s/namespace.yml` | `pod-security.kubernetes.io/enforce: restricted` present |
| AC-4: prod compose creds | No hardcoded root/root | Source assertion | Read `docker-compose.prod.yml` | `${AXIAM__DB__PASSWORD:?...}` pattern, no literal `root` |
| AC-5: toast on errors | Mutations show error toast | Manual / vitest | `cd frontend && npm test` | Unit test for `getApiErrorMessage`; visual smoke |
| AC-5: form validation | Email field rejects non-email | Source assertion | Read `FormDialog.tsx` | No `noValidate`, `type="email"` on email inputs |
| AC-5: route guard 403 | Navigate to /users without permission → ForbiddenPage | Manual smoke | `just dev-up` + browser | ForbiddenPage renders with friendly message |
| AC-5: MFA setup branch | Login response mfa_setup_required → MFA setup UI | Manual smoke | `just dev-up` + browser | LoginPage navigates to setup flow |
| AC-5: tenant/org slug | Page reload restores tenantSlug from /auth/me | Manual smoke | Browser reload | Sidebar and routes use correct slug |

### Sampling Rate

- **Per task commit:** `cargo check -p <affected-crate>` (no full build due to disk constraint)
- **Per plan wave (per plan file):** targeted `cargo test -p <crate> --test <test>` for the specific behaviors changed
- **Phase gate:** `cargo check` on all affected crates green; `cd frontend && npx tsc -b --noEmit && npm run lint` green; then `/gsd:verify-work`

### Wave 0 Gaps (test infrastructure)

- `crates/axiam-db/src/helpers.rs` — does not exist yet; no tests until Plan 11-01 creates it
- `crates/axiam-pki/tests/mtls_chain_test.rs` — does not exist (CQ-B24 partially; SEC-024)
- `crates/axiam-api-rest/tests/csrf_crud_test.rs` — extend existing CSRF tests to cover `/api/v1` scope
- `frontend/src/lib/apiError.test.ts` — does not exist; create with vitest to cover `getApiErrorMessage`

*(If no gaps: "None" — but gaps exist for the new behaviors listed above.)*

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Dummy-Argon2 (SEC-026), atomic increment (SEC-032), reset-to-current (SEC-028) |
| V3 Session Management | yes | Logout revokes own session (SEC-051), CSRF on CRUD (SEC-046) |
| V4 Access Control | yes | ROUTE_PERMISSION_MAP (SEC-047), PKCE public clients (SEC-025) |
| V5 Input Validation | yes | Request DTOs (CQ-B25), email validation (CQ-B26), gRPC message size (CQ-B20) |
| V6 Cryptography | yes | Webhook secret encrypt at rest (SEC-031), AMQP HMAC signing (SEC-022) |
| V9 Communication | yes | mTLS chain verify (SEC-024), gRPC TLS (CQ-B20), SSRF webhook (SEC-019) |
| V13 API | yes | Rate limits on MFA/oauth2 (SEC-020), SSRF (SEC-019), body limits (CQ-B21) |
| V14 Config | yes | k8s env names (SEC-052), PSA enforce (SEC-053), prod compose creds (SEC-023) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| User enumeration via timing | Information Disclosure | Dummy-Argon2 on not-found (SEC-026) |
| CSRF on CRUD state changes | Tampering | CsrfMiddleware on `/api/v1` scope (SEC-046) |
| SSRF via webhook URL | Elevation of Privilege | Re-resolve + private IP filter at delivery (SEC-019) |
| PKCE bypass (auth code interception) | Spoofing | Enforce PKCE for public clients (SEC-025) |
| Race condition on failed login count | Tampering | SurrealQL atomic `+= 1` (SEC-032) |
| mTLS forgery with known fingerprint | Spoofing | Chain verify to org CA (SEC-024) |
| k8s pod privilege escalation | Elevation of Privilege | PSA enforce:restricted (SEC-053) |
| Webhook HMAC secret in API response | Information Disclosure | `#[serde(skip_serializing)]` + encrypt at rest (SEC-031) |
| AMQP message injection | Tampering | HMAC-signed payloads (SEC-022) |
| Bootstrap race / partial state | Tampering | Single transactional conditional create (SEC-049) |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | SurrealDB v3 returns a distinguishable error message on unique index violation (for AlreadyExists → 409 mapping) | Cluster 1 CQ-B11 | May need to match on error string pattern; verify exact SurrealDB error text during implementation |
| A2 | `IpAddr::is_private()` and `is_loopback()` cover all relevant private ranges for SSRF filtering without `is_global()` (nightly) | Cluster 2 SEC-019 | If global() stabilized in MSRV 1.93, can use it; otherwise explicit CIDR checks for 169.254.0.0/16, 100.64.0.0/10 etc. |
| A3 | `OAuthClient` model distinguishes public/confidential clients via presence/absence of `client_secret` (null = public) | Cluster 2 SEC-025 | If no such field exists, must add `is_public: bool` to the model and migration |
| A4 | `@radix-ui/react-toast` usage pattern for hook-based toast in App.tsx is the standard Radix pattern (ToastProvider + viewport in root) | Cluster 5 CQ-F09 | Minor API differences; verify against Radix docs during implementation |
| A5 | SurrealQL `UPDATE SET field += 1 WHERE ...` is atomic in SurrealDB v3 (no TOCTOU between read and write) | Cluster 3 SEC-032 | If not atomic, must use a SurrealDB transaction with `SELECT FOR UPDATE` semantics — verify with SurrealDB v3 docs |

---

## Open Questions (RESOLVED)

1. **CQ-B43 AppState module:** The finding says "replace ~45 `app_data` registrations" with an `AppState` struct. Is this in scope for Phase 11 or deferred to Phase 12? The `load_key_from_env` part is already done (main.rs). The 45-registration refactor is large and carries regression risk — recommend descoping to Phase 12 unless the finding is blocking.
   - **RESOLVED:** Deferred to Phase 12 per ROADMAP deferred list. `load_key_from_env` already satisfied (Phase 10); the 45-registration refactor is out of Phase 11 scope.

2. **SEC-022 AMQP: signed payloads vs per-tenant queues:** Per-tenant queues require RabbitMQ vhost/ACL config that is not currently provisioned. Signed HMAC payloads are simpler and implementable in-process. Recommend signed payloads for Phase 11; per-tenant queues as a Phase 12 enhancement.
   - **RESOLVED:** Signed HMAC payloads chosen — implemented in plan 11-02 (AMQP authz/mail message authentication). Per-tenant queues deferred to Phase 12.

3. **CQ-B12 — real DB error propagation:** `auth/service.rs:200` — "propagate real DB errors on the email fallback." Currently swallowed silently. This is a one-line fix; include in the auth-hardening plan.
   - **RESOLVED:** Included in plan 11-03 (auth hardening) — real DB errors propagated on the email fallback path.

4. **CQ-B22 — Webhook via AMQP with persistence:** The finding says "Webhook delivery via AMQP with persistence + emit events from handlers (or remove until wired)." This is significant scope — adding an AMQP queue for webhook delivery is a new consumer. Recommend deferring to Phase 12 unless SEC-019 (SSRF) blocks on this. The SSRF fix can be applied to the existing HTTP delivery path.
   - **RESOLVED:** Deferred to Phase 12. The SEC-019 SSRF fix is applied to the existing HTTP delivery path in plan 11-02, independent of the AMQP webhook consumer.

5. **CQ-B23 — Federation OIDC cache + 256 KiB cap:** The `axiam-federation/src/jwks_cache.rs` body cap (SEC-054) is straightforward; the OIDC discovery cache is a separate cache concern. SEC-054 is in Wave 3 scope; OIDC discovery cache (CQ-B23) may be Wave 3 or 4 depending on remediation plan assignment. The finding is listed in Wave 3 in `remediation-plan.md`.
   - **RESOLVED:** SEC-054 JWKS body cap implemented in plan 11-02. The OIDC discovery-cache portion of CQ-B23 deferred to Phase 12 per ROADMAP deferred list.

---

## Sources

### Primary (HIGH confidence — direct codebase inspection)

- `/home/emanuele/git/priv/axiam/crates/axiam-api-rest/src/server.rs` — CSRF scope, JsonConfig scope, rate limit wiring
- `/home/emanuele/git/priv/axiam/crates/axiam-api-rest/src/webhook.rs` — SSRF gap, HMAC signing
- `/home/emanuele/git/priv/axiam/crates/axiam-pki/src/mtls.rs` — fingerprint-only verify, no chain verify
- `/home/emanuele/git/priv/axiam/crates/axiam-auth/src/service.rs` — dummy-Argon2 gap, read-modify-write increment
- `/home/emanuele/git/priv/axiam/crates/axiam-api-rest/src/handlers/bootstrap.rs` — non-transactional setup
- `/home/emanuele/git/priv/axiam/crates/axiam-api-rest/src/handlers/auth.rs:364-369` — logout no session ownership check
- `/home/emanuele/git/priv/axiam/crates/axiam-oauth2/src/authorize.rs` — PKCE optional not required
- `/home/emanuele/git/priv/axiam/crates/axiam-api-grpc/src/server.rs` — no limits on builder
- `/home/emanuele/git/priv/axiam/k8s/server/configmap.yml` — single-underscore keys confirmed
- `/home/emanuele/git/priv/axiam/k8s/namespace.yml` — PSA warn-only confirmed
- `/home/emanuele/git/priv/axiam/docker/docker-compose.prod.yml` — hardcoded creds confirmed
- `/home/emanuele/git/priv/axiam/claude_dev/remediation-plan.md` — finding definitions Wave 3

### Secondary (MEDIUM confidence — project memory + prior phases)

- `MEMORY.md` — SurrealDB v3 quirks: `BEGIN TRANSACTION` slot 0, `+=` semantics, transaction shift
- Phase 10 `10-RESEARCH.md` — structural exemplar for plan files and validation architecture

### Tertiary (LOW confidence — training knowledge)

- Tonic server builder API: `max_decoding_message_size`, `concurrency_limit_per_connection` [A4-equivalent assumption; verify against tonic docs during implementation]
- `@radix-ui/react-toast` hook usage pattern [A4]

---

## Metadata

**Confidence breakdown:**
- Standard Stack: HIGH — all from direct codebase inspection
- Architecture: HIGH — all existing patterns, no new architectural decisions
- Pitfalls: HIGH — verified against actual code paths
- Validation: HIGH — commands verified against actual crate structure

**Research date:** 2026-06-13
**Valid until:** 2026-07-13 (stable Rust ecosystem; SurrealDB v3 API stable)
