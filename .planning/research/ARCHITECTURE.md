# Architecture Patterns: Security Hardening Integration

**Domain:** IAM system — Actix-Web + React security hardening
**Researched:** 2026-03-30
**Confidence:** HIGH — based on direct codebase inspection

---

## Current Architecture Snapshot

The system is a layered Rust monorepo. The request path that matters for this
milestone is:

```
HTTP request
  -> AuditMiddleware (axiam-audit: validates JWT, caches identity)
  -> CORS middleware
  -> Route dispatch
  -> AuthenticatedUser extractor (axiam-api-rest: reads Bearer token OR cached identity)
  -> Handler body
  -> Repository call (axiam-db)
  -> JSON response
```

The four hardening changes intersect this path at different layers. Each is
described below with its exact integration point.

---

## Change 1: JWT from sessionStorage to httpOnly Cookies

### Problem

`frontend/src/stores/auth.ts` uses Zustand `persist` with
`createJSONStorage(() => sessionStorage)`. The `accessToken` and `refreshToken`
are stored in `sessionStorage`, which is readable by any JavaScript running in
the page origin — including XSS payloads.

`frontend/src/lib/api.ts` reads the token from the Zustand store and injects it
as `Authorization: Bearer <token>` on every outgoing Axios request.

The `/auth/refresh` call in `api.ts` already passes `{ withCredentials: true }`
but there is no cookie being set by the server — it reads `refresh_token` from
the request JSON body (`RefreshRequest` struct in `handlers/auth.rs`).

### Target Architecture

```
Login response
  -> Backend sets:
       access_token  — httpOnly, Secure, SameSite=Strict, Path=/,    Max-Age=900
       refresh_token — httpOnly, Secure, SameSite=Strict, Path=/auth/refresh, Max-Age=<refresh_lifetime>

Subsequent API requests
  -> Browser sends cookies automatically (no JS involvement)
  -> Backend reads access_token from cookie (not Authorization header)
  -> Frontend Zustand store holds only non-secret state: user metadata, tenant/org slugs

/auth/refresh
  -> Browser sends refresh_token cookie automatically
  -> Backend rotates: clears old cookie, sets new pair
  -> Frontend retains same silent-refresh interceptor logic but no longer
     needs to read/write the token value itself
```

### Backend Changes Required

**File: `crates/axiam-api-rest/src/handlers/auth.rs`**

All handlers that currently return `LoginSuccessResponse { access_token, refresh_token, … }`
must change to:
1. Build `actix_web::cookie::Cookie` for each token.
2. Return `HttpResponse::Ok().cookie(access_cookie).cookie(refresh_cookie).json(…)`
   where the JSON body carries only non-secret fields (`session_id`, `expires_in`).

The `RefreshRequest` struct (`tenant_id`, `org_id`, `refresh_token`) must drop
the `refresh_token` field — the token arrives via cookie, not body.

**File: `crates/axiam-api-rest/src/extractors/auth.rs`**

`extract_user()` currently reads `Authorization: Bearer …`. It must be extended
to also read the `access_token` cookie as a fallback (or primary) source.

Priority order to maintain backward compatibility during transition:
1. Check `Authorization: Bearer` header first (machine clients, device auth, SDK use).
2. Fall back to `access_token` cookie for browser clients.

This keeps the gRPC and service-account paths unchanged.

**File: `crates/axiam-audit/src/middleware.rs`**

`extract_or_cache_user_info()` currently reads only the `Authorization` header.
It must mirror the extractor's dual-source logic.

**Cookie attributes (non-negotiable for OWASP ASVS Level 2):**

| Attribute | Value | Reason |
|-----------|-------|--------|
| `HttpOnly` | true | Blocks JS read — core of the migration |
| `Secure` | true | HTTPS-only transmission |
| `SameSite` | `Strict` | CSRF protection; admin UI is same-origin |
| `Path` for access_token | `/` | Available on all API routes |
| `Path` for refresh_token | `/auth/refresh` | Scoped to prevent unnecessary cookie send |
| `Max-Age` for access_token | 900 (15 min) | Matches `access_token_lifetime_secs` in `AuthConfig` |
| `Max-Age` for refresh_token | per config | Matches `refresh_token_lifetime_secs` |

Actix-Web uses `actix_web::cookie::Cookie` and `actix_web::cookie::SameSite`. The
`actix-web` 4.x crate includes `cookie` support natively; no new dependency needed.

**Logout must explicitly clear both cookies:**

```rust
// In handlers/auth.rs logout handler
let clear_access = Cookie::build("access_token", "")
    .path("/")
    .max_age(Duration::ZERO)
    .finish();
let clear_refresh = Cookie::build("refresh_token", "")
    .path("/auth/refresh")
    .max_age(Duration::ZERO)
    .finish();
HttpResponse::NoContent()
    .cookie(clear_access)
    .cookie(clear_refresh)
    .finish()
```

### Frontend Changes Required

**File: `frontend/src/stores/auth.ts`**

Remove `accessToken` from state entirely. The Zustand store becomes:

```typescript
interface AuthState {
  user: AuthUser | null;
  tenantId: string | null;
  orgId: string | null;
  isAuthenticated: boolean;
}
```

Remove `persist` middleware — there is nothing sensitive to persist, and
`isAuthenticated` should be derived from a lightweight `/auth/me` call on
page load rather than sessionStorage rehydration.

**File: `frontend/src/lib/api.ts`**

Remove the request interceptor that injects `Authorization: Bearer`. Replace with
`withCredentials: true` on the Axios instance so cookies are sent automatically:

```typescript
const api: AxiosInstance = axios.create({
  baseURL: "/",
  withCredentials: true,  // send httpOnly cookies on every request
  headers: { "Content-Type": "application/json" },
});
```

The refresh interceptor logic is preserved but simplified — on 401, call
`/auth/refresh` (which reads the cookie server-side), then retry. No token
strings to pass around.

**Backend must provide `/auth/me`:**

The frontend needs to know if the user is still authenticated after a page
reload (since the access token is no longer in sessionStorage). A lightweight
`GET /auth/me` endpoint that validates the cookie and returns user identity
replaces the "does sessionStorage have a token?" check.

This endpoint lives in `axiam-api-rest/src/handlers/auth.rs` and uses
`AuthenticatedUser` extractor (which reads the cookie).

### Crates Modified

| Crate | Change |
|-------|--------|
| `axiam-api-rest` | `extractors/auth.rs` — dual-source token extraction; `handlers/auth.rs` — cookie responses; add `/auth/me` |
| `axiam-audit` | `middleware.rs` — mirror dual-source extraction |
| frontend `src/stores/auth.ts` | Remove accessToken field and persist |
| frontend `src/lib/api.ts` | Add `withCredentials`, remove Bearer injection |

No new crate dependencies required for the Rust side.

---

## Change 2: Wire RBAC to All REST Endpoints

### Problem

`axiam-authz` contains a complete RBAC engine (`AuthorizationEngine`) with
resource hierarchy, permission inheritance, and scope evaluation. It is registered
as `web::Data<Arc<dyn AuthzChecker>>` in `axiam-server`.

`RequirePermission` in `crates/axiam-api-rest/src/authz.rs` is the guard struct
that handlers should call. The code is correct and complete. The problem is
**zero handlers call it**. Every endpoint authenticates the user (via
`AuthenticatedUser` extractor) but then performs no authorization check before
proceeding to the repository.

### Target Architecture

Every state-modifying or sensitive-read endpoint follows this pattern:

```rust
pub async fn create_user<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,            // web::Data<Arc<dyn AuthzChecker>>
    body: web::Json<CreateUserRequest>,
    repo: web::Data<SurrealUserRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    // Resolve the resource ID for "users" in this tenant.
    // The admin bootstrap populates a well-known resource ID per
    // operation category (see Bootstrap section below).
    RequirePermission::new("create", USERS_RESOURCE_ID)
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // ... handler body unchanged
}
```

`AuthzData` is already defined as a type alias in `axiam-api-rest/src/authz.rs`.

### Resource ID Convention

The authorization engine checks access against a `resource_id: Uuid`. For
admin UI operations these map to well-known resource categories, not individual
database records. A bootstrap record must create these resources at startup.

Recommended convention — one top-level resource per entity type:

| Resource name | Action | Which endpoints |
|---------------|--------|-----------------|
| `users` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/users/*` |
| `groups` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/groups/*` |
| `roles` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/roles/*` |
| `permissions` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/permissions/*` |
| `resources` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/resources/*` |
| `scopes` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/scopes/*` |
| `organizations` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/organizations/*` |
| `tenants` | `create`, `read`, `update`, `delete`, `list` | `/api/v1/tenants/*` |
| `audit` | `read` | `/api/v1/audit/*` |
| `certificates` | `create`, `read`, `revoke` | `/api/v1/certs/*` |
| `oauth2-clients` | `create`, `read`, `update`, `delete` | `/api/v1/oauth2-clients/*` |
| `federation-configs` | `create`, `read`, `update`, `delete` | `/api/v1/federation/*` |
| `webhooks` | `create`, `read`, `update`, `delete` | `/api/v1/webhooks/*` |
| `settings` | `read`, `update` | `/api/v1/settings/*` |
| `service-accounts` | `create`, `read`, `update`, `delete` | `/api/v1/service-accounts/*` |

### Admin Bootstrap

`axiam-server/src/main.rs` must call a bootstrap function at startup that:

1. Creates the admin `Organization` and `Tenant` if none exist (already done in
   earlier phases).
2. Creates the set of well-known `Resource` records above (idempotent — only if
   not already present) and records their UUIDs in a stable config structure.
3. Creates an `admin` `Role` with all permissions on all resources.
4. Assigns the `admin` role to the first admin `User`.

The resource UUIDs should be stored as a `BootstrapIds` struct in
`axiam-server` app state so handlers can resolve them without a DB query:

```rust
// axiam-server/src/bootstrap.rs
pub struct BootstrapIds {
    pub users_resource_id: Uuid,
    pub groups_resource_id: Uuid,
    // ... one field per resource category
}
```

`BootstrapIds` is registered as `web::Data<BootstrapIds>` and injected into
handlers that need it alongside `AuthzData`.

### MFA Reset Special Case

`handlers/auth.rs::reset_mfa` already has a TODO comment disabling it
specifically because RBAC is not yet in place. Once RBAC is wired, remove the
blanket deny and gate it with:

```rust
RequirePermission::new("reset-mfa", bootstrap.users_resource_id)
    .check(&user, authz.get_ref().as_ref())
    .await?;
```

### Crates Modified

| Crate | Change |
|-------|--------|
| `axiam-api-rest` | All handlers in `src/handlers/` — add `AuthzData` parameter + `RequirePermission::check` call |
| `axiam-server` | `src/main.rs` — add `BootstrapIds`; new `src/bootstrap.rs` for idempotent resource creation |
| `axiam-core` | No change — `ResourceRepository`, `RoleRepository`, etc. already exist |
| `axiam-db` | No change — repositories already implement the required traits |
| `axiam-authz` | No change — engine is complete |

---

## Change 3: Federation Token Signature Verification (JWKS)

### Problem

`crates/axiam-federation/src/oidc.rs::decode_id_token_claims()` base64-decodes
the JWT payload without verifying the signature. Lines 285-295 contain an
explicit TODO(T19.6) and a `warn!` logging that verification is skipped. This
means any attacker who can forge a JWT payload (e.g., via MITM on the token
endpoint — which is protected by HTTPS, but defense in depth demands
cryptographic verification) can provision arbitrary federated users.

### Target Architecture

```
handle_callback()
  1. Fetch discovery document (already done)
  2. Fetch JWKS from discovery.jwks_uri  <-- NEW
  3. Parse JWT header to get "kid" (key ID)
  4. Find matching JWK in JWKS by kid
  5. Verify JWT signature using JWK
  6. Only then decode and trust claims
```

### Implementation: `jsonwebtoken` + manual JWKS parsing

The project already uses `jsonwebtoken` (visible in `axiam-auth/src/service.rs`
and `axiam-auth/src/token.rs`). The `jsonwebtoken` crate supports JWKS key
decoding via `DecodingKey::from_jwk()` (available since v9).

**New function in `crates/axiam-federation/src/oidc.rs`:**

```rust
/// Fetch the JWKS document and return a `DecodingKey` for the given `kid`.
async fn fetch_jwks_key(
    http_client: &reqwest::Client,
    jwks_uri: &str,
    kid: Option<&str>,
) -> Result<jsonwebtoken::DecodingKey, FederationError>
```

**Updated flow in `handle_callback()`:**

```rust
// Replace the unsafe decode_id_token_claims() call with:
let header = jsonwebtoken::decode_header(&id_token_str)
    .map_err(|e| FederationError::IdTokenValidationFailed(...))?;

let decoding_key = self
    .fetch_jwks_key(&discovery.jwks_uri, header.kid.as_deref())
    .await?;

let mut validation = jsonwebtoken::Validation::new(header.alg);
validation.set_audience(&[&config.client_id]);
validation.set_issuer(&[&discovery.issuer]);

let token_data = jsonwebtoken::decode::<IdTokenClaims>(
    &id_token_str,
    &decoding_key,
    &validation,
)?;
let claims = token_data.claims;
```

The `exp`, `aud`, `iss`, and nonce checks that currently run manually on the
decoded claims are replaced by `jsonwebtoken::Validation` fields — cleaner and
less error-prone.

**JWKS caching:**

Fetching JWKS on every callback is wasteful and adds latency. Add a simple
in-memory cache on `OidcFederationService`:

```rust
pub struct OidcFederationService<FC, FL, UR> {
    federation_config_repo: FC,
    federation_link_repo: FL,
    user_repo: UR,
    http_client: reqwest::Client,
    jwks_cache: tokio::sync::RwLock<HashMap<String, CachedJwks>>,  // NEW
}

struct CachedJwks {
    keys: Vec<jsonwebtoken::jwk::Jwk>,
    fetched_at: std::time::Instant,
}
```

Cache TTL: 5 minutes. On cache miss or key-not-found, re-fetch and update.
This is the industry standard pattern (used by all major OIDC libraries).

**Cargo.toml for `axiam-federation`:**

`jsonwebtoken` version must be `>= 9.0` to have `DecodingKey::from_jwk()`.
Verify the workspace-level version in `Cargo.toml`.

**SAML signature verification** follows a different path (XML DSig) and is
handled by the `samael` or `xmlsec` crate — this is separate from the OIDC
JWKS work and should be scoped as a distinct task.

### Crates Modified

| Crate | Change |
|-------|--------|
| `axiam-federation` | `src/oidc.rs` — replace unsafe decode with JWKS verification; add JWKS cache; update `OidcFederationService` struct |
| `Cargo.toml` (workspace) | Ensure `jsonwebtoken >= 9.0` |

---

## Change 4: Connect EmailService to Auth Flows

### Problem

Three handlers have TODO(T19) comments indicating email delivery was deliberately
deferred:

1. `handlers/password_reset.rs::request_reset()` — creates a reset token, has
   the raw token, but calls `tracing::debug!` instead of sending an email.
2. `handlers/email_verification.rs` — the `resend_verification` handler likely
   has the same gap (token created, not sent).
3. Session invalidation email (on password reset) — `confirm_reset` invalidates
   sessions but does not notify the user.

The `axiam-email` crate is complete — `EmailService::send()` works, templates
exist via `render_email()`, and providers (SMTP, SendGrid, Postmark, Resend, Brevo)
are all implemented.

### Target Architecture

**Email service injection:**

`EmailService` is not `Clone` (it wraps a `Box<dyn EmailProvider>`). It must be
wrapped in `Arc<EmailService>` and registered as `web::Data<Arc<EmailService>>`
in `axiam-server`. The service is built from the resolved `EmailConfig` at
startup (fetched from the `SettingsRepository`).

```rust
// axiam-server/src/main.rs (conceptual)
let email_config = settings_repo
    .get_effective_settings(org_id, tenant_id)
    .await?;
let email_service = Arc::new(
    EmailService::from_config(&email_config.email)?
);
app_data.push(web::Data::new(email_service));
```

**Handler integration for password reset:**

```rust
// handlers/password_reset.rs::request_reset
pub async fn request_reset<C: Connection>(
    // ... existing params ...
    email_svc: web::Data<Arc<EmailService>>,   // NEW
    body: web::Json<RequestResetBody>,
) -> Result<HttpResponse, AxiamApiError> {
    match svc.initiate_reset(...).await {
        Ok(Some((raw_token, user_id, expires_at))) => {
            // Build message from template
            let ctx = TemplateContext { /* token, expires_at */ };
            let msg = render_email("password_reset", &ctx)?;
            // Fire-and-forget — log errors but don't fail the response
            if let Err(e) = email_svc.send(&msg).await {
                tracing::warn!(error = %e, "password reset email delivery failed");
            }
        }
        // ... rest unchanged
    }
}
```

Fire-and-forget (log + continue) is the correct pattern for password reset email
delivery. The user already sees `{"sent": true}` regardless of outcome; failing
to deliver should not block the API response or reveal delivery status
(email enumeration prevention).

**Handler integration for email verification:**

Same pattern in `handlers/email_verification.rs::resend_verification()`:
inject `Arc<EmailService>`, send the verification email with the token, log
failures without propagating them.

**Template resolution:**

`axiam-email::template::resolve_template()` and `render_email()` are the
integration points. The templates themselves need to exist in the templates
directory with the correct names. Verify that `password_reset` and
`email_verification` template names exist.

**Multi-tenant email config:**

The tricky part is that `EmailService` is configured at org/tenant level.
The server holds one default service, but tenants may override the provider.
For the MVP, a single org-level config is acceptable — tenant-level override
can be deferred. Document this as a known limitation.

**EmailService availability:**

`EmailService::from_config()` returns `Err` if email is disabled. The server
startup should tolerate a missing email config and register a `None` (or a
`NoOpEmailService`). Handlers that need email should skip sending gracefully
when no email service is available, not panic at startup.

### Crates Modified

| Crate | Change |
|-------|--------|
| `axiam-api-rest` | `handlers/password_reset.rs` — inject `Arc<EmailService>`, send email; `handlers/email_verification.rs` — same |
| `axiam-server` | `src/main.rs` — build and register `Arc<EmailService>` from settings |
| `axiam-email` | No functional change — potentially add `NoOpEmailService` for the disabled case |

---

## Component Boundary Map

```
axiam-server (composition root)
  |
  +-- registers: web::Data<Arc<dyn AuthzChecker>>
  |              web::Data<BootstrapIds>
  |              web::Data<Arc<EmailService>>  (new)
  |
  +-- axiam-api-rest
  |     |
  |     +-- extractors/auth.rs
  |     |     reads: "access_token" cookie  (change)
  |     |     reads: Authorization header   (existing, preserved)
  |     |
  |     +-- handlers/auth.rs
  |     |     sets: httpOnly cookies on login/refresh/logout  (change)
  |     |     adds: GET /auth/me  (new)
  |     |
  |     +-- handlers/password_reset.rs
  |     |     uses: Arc<EmailService>  (change)
  |     |
  |     +-- handlers/email_verification.rs
  |     |     uses: Arc<EmailService>  (change)
  |     |
  |     +-- handlers/* (all CRUD handlers)
  |           uses: AuthzData + RequirePermission  (change)
  |           uses: BootstrapIds  (change)
  |
  +-- axiam-audit
  |     |
  |     +-- middleware.rs
  |           reads: "access_token" cookie  (change, mirrors extractor)
  |
  +-- axiam-federation
        |
        +-- oidc.rs
              verifies: JWKS signature  (change)
              caches: JWKS keys  (new)

frontend/src/
  |
  +-- lib/api.ts
  |     withCredentials: true  (change)
  |     remove: Bearer injection  (change)
  |
  +-- stores/auth.ts
        remove: accessToken, persist  (change)
        add: session check via /auth/me  (change)
```

---

## Data Flow: Hardened Login Sequence

```
Browser                   axiam-api-rest               axiam-auth       axiam-db
   |                           |                            |               |
   |-- POST /auth/login ------->|                            |               |
   |   (JSON: credentials)     |                            |               |
   |                           |-- AuthService.login() ---->|               |
   |                           |                            |-- DB query --->|
   |                           |                            |<-- User -------|
   |                           |<-- LoginOutput (tokens) ---|               |
   |                           |                            |               |
   |<-- 200 OK                 |                            |               |
   |   Set-Cookie: access_token=...; HttpOnly; Secure; SameSite=Strict
   |   Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh
   |   Body: { session_id, expires_in }
   |                           |
   |-- GET /api/v1/users ------>|   (browser auto-sends cookie)
   |                           |-- extract_user() reads "access_token" cookie
   |                           |-- RequirePermission("list", users_resource_id).check()
   |                           |       |-- AuthorizationEngine.check_access()
   |                           |<-- Allow
   |                           |-- UserRepository.list()
   |<-- 200 OK (users list)    |
```

---

## Build Order (Dependency Constraints)

The four changes have dependencies on each other. Build order must respect them:

### Stage 1: Cookie infrastructure (no other changes depend on this, but frontend depends on it)

- `axiam-api-rest`: `extractors/auth.rs` — add cookie source
- `axiam-api-rest`: `handlers/auth.rs` — emit Set-Cookie on login/refresh/logout; add `/auth/me`
- `axiam-audit`: `middleware.rs` — mirror cookie extraction
- Frontend: `stores/auth.ts`, `lib/api.ts`

**Gating condition:** Cookie extraction must work before frontend stops sending Bearer.
Deploy backend cookie support first, then frontend change. During the transition
window, the extractor accepts both. Remove Bearer-first fallback in a follow-up
after frontend is deployed.

### Stage 2: RBAC bootstrap (RBAC wiring depends on bootstrap existing)

- `axiam-server`: `src/bootstrap.rs` — create well-known resources + admin role
- `axiam-server`: `src/main.rs` — call bootstrap, register `BootstrapIds`

**Gating condition:** `BootstrapIds` must be in app state before handlers use it.

### Stage 3: RBAC endpoint wiring (depends on Stage 2)

- `axiam-api-rest`: all handlers — add `AuthzData` + `RequirePermission`
- `axiam-api-rest`: `handlers/auth.rs::reset_mfa` — remove blanket deny, add
  proper permission check

**Gating condition:** Do not wire RBAC before the admin bootstrap has run and
created the admin role assignment — or every request will deny.

### Stage 4: JWKS verification (independent, no cross-dependencies)

- `axiam-federation`: `src/oidc.rs` — JWKS fetch, cache, verify

### Stage 5: Email wiring (independent, no cross-dependencies)

- `axiam-server`: register `Arc<EmailService>`
- `axiam-api-rest`: `handlers/password_reset.rs`, `handlers/email_verification.rs`

### Summary

```
Stage 1 (cookie)  ─────────────────────────────────────────────────── independent
Stage 2 (bootstrap) ──┐                                                independent
Stage 3 (RBAC wiring) ┘ (3 depends on 2)
Stage 4 (JWKS) ────────────────────────────────────────────────────── independent
Stage 5 (email) ───────────────────────────────────────────────────── independent
```

Stages 1, 4, and 5 can be parallelised across phases. Stage 3 must follow Stage 2.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Storing tokens in memory on the frontend after cookie migration

**What:** Keeping `accessToken` in Zustand even as an in-memory (non-persisted) field.
**Why bad:** `window.__zustandState` and React DevTools expose in-memory store contents.
XSS can still exfiltrate from memory. The migration is only complete when the token
never touches JS memory.
**Instead:** The frontend holds zero token strings. All authenticated state is
derived from `/auth/me` and user metadata returned at login.

### Anti-Pattern 2: Wiring RBAC before the admin bootstrap

**What:** Adding `RequirePermission` calls before the admin user has a role assignment.
**Why bad:** Every API call returns 403 Forbidden, including the call needed to create
roles. The system becomes locked.
**Instead:** Bootstrap runs at server startup, creates admin role+assignment atomically,
then RBAC checks are safe to enable.

### Anti-Pattern 3: Global JWKS fetch without caching

**What:** Calling `fetch_jwks_key()` on every federation callback.
**Why bad:** Each OIDC login hits the external IdP's JWKS endpoint, adding 100–500ms
latency and creating a dependency on IdP availability for every login.
**Instead:** Cache JWKS with a 5-minute TTL. Re-fetch only on cache miss or
unknown `kid`.

### Anti-Pattern 4: Failing startup if email is not configured

**What:** `EmailService::from_config()` returning `Err` causes `axiam-server` to
panic if no email config exists.
**Why bad:** Systems with no email config (test environments, early deployments)
can't start.
**Instead:** Register `Option<Arc<EmailService>>` or a `NoOpEmailService`.
Handlers skip delivery when `None`.

### Anti-Pattern 5: SameSite=None for the refresh cookie

**What:** Setting `SameSite=None` to allow cross-origin cookie send.
**Why bad:** Allows CSRF. The admin UI is same-origin (served from same domain
as the API); `SameSite=Strict` is correct and sufficient.
**Instead:** `SameSite=Strict` everywhere. If a third-party client needs token
refresh, it uses the `Authorization: Bearer` flow with explicit refresh tokens
(not cookies).

---

## Scalability Considerations

These hardening changes do not affect scalability in the current single-cluster
target. Notes for future reference:

| Concern | Current | Implication of change |
|---------|---------|----------------------|
| Cookie parsing | O(1) per request | No change vs Bearer header parsing |
| RBAC check | O(roles + ancestors) per request | Adds one DB round-trip per request — acceptable at current scale; add Redis cache if this becomes a bottleneck |
| JWKS cache | Per-process in-memory | On multi-replica deployments, each replica maintains its own cache — no shared state needed |
| Email delivery | Async, fire-and-forget | No request latency impact |

---

## Sources

- Direct inspection of codebase files (HIGH confidence — source of truth):
  - `crates/axiam-api-rest/src/extractors/auth.rs`
  - `crates/axiam-api-rest/src/authz.rs`
  - `crates/axiam-api-rest/src/handlers/auth.rs`
  - `crates/axiam-api-rest/src/handlers/password_reset.rs`
  - `crates/axiam-audit/src/middleware.rs`
  - `crates/axiam-federation/src/oidc.rs`
  - `crates/axiam-auth/src/service.rs`
  - `crates/axiam-email/src/service.rs`
  - `frontend/src/stores/auth.ts`
  - `frontend/src/lib/api.ts`
- OWASP ASVS 4.0 §3.4 (Cookie-based session management requirements)
- RFC 6265 §4.1.2 (Cookie attributes: HttpOnly, Secure, SameSite)
- OIDC Core 1.0 §3.1.3.7 (ID Token validation requirements, including JWKS)
- `jsonwebtoken` crate v9 changelog: `DecodingKey::from_jwk()` availability
