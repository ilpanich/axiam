# Phase 9: Critical Remediation (Wave 1) - Research

**Researched:** 2026-06-11
**Domain:** Rust / Actix-Web / Tonic gRPC / React-TypeScript security remediation
**Confidence:** HIGH

---

## Summary

Phase 9 closes five critical security defects identified by the code and security audits at commit `d69323b`.
The defects span four distinct subsystems: REST cross-org authorization, gRPC authentication, frontend auth
page wiring, and federation secret storage. Each subsystem has a clearly bounded scope and follows patterns
already present in the codebase.

**The five defects in scope:**

| Defect | Type | Location |
|--------|------|----------|
| SEC-002 | Cross-org IDOR in REST org routes | `organizations.rs`, `tenants.rs`, `ca_certificates.rs` |
| SEC-003 | gRPC server unauthenticated — no interceptor | `axiam-api-grpc` |
| SEC-044/CQ-F27 | Frontend auth pages call wrong/missing endpoints | 6 frontend pages |
| CQ-F28 | Silent refresh drops CSRF token; boot refresh missing | `api.ts`, `useAuthInit.ts` |
| SEC-045/SEC-017 | Federation client_secret used in plaintext at call-site | `oidc.rs`, REST federation handler |

**Primary recommendation:** Work in four task streams. Each stream is independently committable; stream 1 (org-scoping) and stream 3 (silent refresh) are code-only and can proceed in parallel with streams 2 (gRPC interceptor) and 4 (federation decrypt).

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-13-AC1 | Cross-org IDOR closed: org/tenant/CA routes return 403 on org_id mismatch; org create/list system-admin restricted; cross-org negative tests pass | Org-scoping pattern verified in `settings.rs` — exact 4-line guard documented below |
| REQ-13-AC2 | gRPC authenticated: Tonic interceptor validates bearer JWT/mTLS; tenant_id/subject_id from claims; public gRPC ingress removed; interceptor tests | Tonic 0.14 interceptor pattern confirmed; `validate_access_token` entry point identified |
| REQ-13-AC3 | Six frontend auth flows call real backend via typed `auth.ts`; frontend↔OpenAPI contract test | All 6 pages read; exact URL mismatches documented; existing Playwright+parity test infra identified |
| REQ-13-AC4 | Silent refresh succeeds (CSRF attached, skip-list narrowed); boot refresh once before unauthenticated | `api.ts` code read; current CSRF gap and skip-list blindspot documented |
| REQ-13-AC5 | Federation secrets decrypted at use; encrypt on create/update; never serialized; OIDC login after restart | `secrets.rs` crypto exists; `oidc.rs` is missing the decrypt-at-use call; backfill already wired in `main.rs` |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Org-ownership check (IDOR guard) | API / Backend | — | Permission check must be server-side; `org_id` derived from verified JWT, not request body |
| gRPC authentication | API / Backend (gRPC tier) | — | Interceptor lives in the gRPC server layer; no frontend involvement |
| Frontend auth page wiring | Browser / Client | Frontend Server (Vite/nginx) | URL mismatch is client-side; the backend routes already exist |
| Silent refresh / CSRF token | Browser / Client | API / Backend | CSRF cookie is set by backend; attach logic is client-side in `api.ts` |
| Federation secret crypto | API / Backend | Database / Storage | Encrypt on write (DB layer); decrypt at use (service layer); never in response DTOs |

---

## Standard Stack

No new dependencies are required. All tools are already in the workspace:

| Crate / Module | Version | Purpose |
|----------------|---------|---------|
| `axiam-auth::token::validate_access_token` | workspace | JWT validation for gRPC interceptor |
| `axiam-auth::crypto::{decrypt_separate, encrypt_separate}` | workspace | AES-256-GCM for federation secrets |
| `axiam-federation::secrets::{decrypt_client_secret_or_legacy, encrypt_client_secret}` | workspace | High-level wrappers already exist |
| `tonic::service::interceptor` | 0.14 | Tonic Interceptor trait for gRPC auth |
| `axiam-api-rest::extractors::auth::AuthenticatedUser` | workspace | Pattern to replicate in gRPC |

**Installation:** none — no new packages.

---

## Package Legitimacy Audit

> No external packages are added in this phase. All dependencies are already in the workspace.

| Package | Registry | Disposition |
|---------|----------|-------------|
| (none) | — | N/A — workspace-only changes |

---

## Architecture Patterns

### System Architecture Diagram

```
[Browser]
    │ cookies + X-CSRF-Token (fixed)
    ▼
[Actix REST / /api/v1/...]
    │ AuthenticatedUser extractor → org_id
    │ org_id check → 403 if mismatch   ← SEC-002 guard added here
    ▼
[SurrealDB]

[gRPC client (service mesh)]
    │ Bearer <JWT>
    ▼
[Tonic Server]
    │ AuthInterceptor → validate_access_token() → insert CachedUserIdentity
    │ services extract tenant_id / subject_id from request metadata     ← SEC-003 fixed
    ▼
[AuthorizationEngine]

[OidcFederationService]
    │ handle_callback()
    │ resolve_client_secret() → decrypt_client_secret_or_legacy(key, …) ← SEC-045 fixed
    ▼
[external IdP token endpoint]
```

### Recommended Project Structure

No new directories. Changes are within existing files:

```
crates/axiam-api-rest/src/handlers/
├── organizations.rs    ← add org_id == user.org_id guard + system-admin restriction
├── tenants.rs          ← already has org_id guard on GET/PUT/DELETE; add to CREATE/LIST
└── ca_certificates.rs  ← add org_id == user.org_id guard to all 4 handlers

crates/axiam-api-grpc/src/
├── middleware/
│   └── auth.rs         ← NEW: Tonic interceptor module
└── server.rs           ← wire interceptor into Server::builder()

crates/axiam-api-grpc/tests/
└── grpc_auth_test.rs   ← NEW: accept/reject tests for the interceptor

k8s/ingress.yml         ← remove axiam-grpc-ingress block

frontend/src/
├── services/
│   └── auth.ts         ← NEW: typed auth service (6 flows)
├── pages/auth/
│   ├── ForgotPasswordPage.tsx     ← rewire to auth.ts
│   ├── ResetPasswordPage.tsx      ← rewire to auth.ts
│   └── VerifyEmailPage.tsx        ← rewire to auth.ts
├── pages/profile/
│   ├── ChangePasswordPage.tsx     ← rewire to auth.ts
│   ├── ProfilePage.tsx            ← rewire resend to auth.ts
│   └── MfaManagementPage.tsx      ← rewire setupTotp/confirmTotp to auth.ts
└── lib/
    ├── api.ts                     ← fix CSRF on refresh; narrow skip-list
    └── useAuthInit.ts             ← add boot refresh attempt before declaring unauth

crates/axiam-federation/src/oidc.rs ← wire decrypt_client_secret_or_legacy at use-site
```

---

## Domain 1: Cross-Org IDOR (SEC-002)

### Exact Org-Scoping Pattern (from `settings.rs:42-48`)

```rust
// [VERIFIED: codebase read] — from settings.rs get_org_settings handler
let org_id = path.into_inner();
if org_id != user.org_id {
    return Err(AxiamApiError(
        axiam_core::error::AxiamError::AuthorizationDenied {
            reason: "cannot read settings for a different organization".into(),
        },
    ));
}
```

The `user.org_id` field is type `Uuid`, sourced from the validated JWT `org_id` claim via `AuthenticatedUser`. `AxiamError::AuthorizationDenied` maps to HTTP 403 via `ResponseError` impl on `AxiamApiError`. The pattern is 4 lines and has no database round-trip.

### What the Org Handlers Currently Do (and Don't Do)

**`organizations.rs`** — MISSING org-scoping on ALL handlers:
- `create` — no guard. Any authenticated user with `organizations:create` permission can create an org. Must be restricted to system-admin (no cross-org guard; this is a create, not a read of another org).
- `list` — no guard. Returns ALL organizations. Must be restricted to system-admin.
- `get` — no guard. Returns any org by UUID. Must add: `if org_id != user.org_id { 403 }`.
- `update` — no guard. Updates any org. Must add: `if org_id != user.org_id { 403 }`.
- `delete` — no guard. Deletes any org. Must add: `if org_id != user.org_id { 403 }`.

**`tenants.rs`** — PARTIAL:
- `create` — no org guard. `path.org_id` is available; must add: `if path.org_id != user.org_id { 403 }`.
- `list` — no org guard. Must add: `if path.org_id != user.org_id { 403 }`.
- `get` — PARTIALLY guarded: checks `tenant.organization_id != path.org_id` (returns 404, not 403). Must also check `path.org_id != user.org_id`.
- `update` — same as get: checks path vs DB but not user.org_id.
- `delete` — same pattern.

**`ca_certificates.rs`** — MISSING org-scoping on ALL handlers:
- `generate` — no guard. Must add: `if org_id != user.org_id { 403 }`.
- `list` — no guard. Must add: `if org_id != user.org_id { 403 }`.
- `get` — no guard. `(org_id, id) = path.into_inner()`. Must add org guard.
- `revoke` — no guard. Must add org guard.

### System-Admin Restriction for org `create` and `list`

The seeder creates a `super-admin` role with all permissions. The `organizations:create` and `organizations:list` permissions exist in `PERMISSION_REGISTRY` (`permissions.rs:153-155`). The planner must decide the enforcement strategy:

**Option A — Named permission guard (current pattern):** Add a new permission `organizations:list:any` / `organizations:create:any` and only grant it to the super-admin role. Requires seeder/registry update.

**Option B — Explicit role check in handler:** Check that the caller has the `super-admin` role name. No new permission needed.

**Recommendation:** [ASSUMED] Option A aligns better with the existing RBAC-via-permission model and the route↔OpenAPI parity test. The planner should choose between them. The simplest path for this phase: restrict via the existing `RequirePermission` check by NOT granting these permissions to tenant-level admin roles — the super-admin role already has them.

The key insight: `create` and `list` for organizations are already gated by `organizations:create` and `organizations:list` permissions. The actual gap is that a tenant-level admin who somehow has those permissions can cross-org. The correct fix is to ensure those permissions are NOT granted during tenant seeding (`seed_permissions` in `seeder.rs`) — they should only be on the super-admin role. This requires NO code change to the handler — only to the permission seed list.

---

## Domain 2: gRPC Authentication (SEC-003)

### Current State

`server.rs` builds the Tonic `Server` with only a rate-limiting Tower layer. No auth interceptor is registered. Every gRPC call (from any caller) hits the service methods directly. The `check_access` and `batch_check_access` methods trust the `tenant_id` and `subject_id` strings from the request body with no identity verification.

### Tonic 0.14 Interceptor Pattern

Tonic 0.14 (`tonic = "0.14"`) supports `tonic::service::interceptor` via the `Interceptor` trait and `InterceptedService` wrapper. The pattern is:

```rust
// [CITED: docs.rs/tonic/0.14] — Interceptor implementation
use tonic::{Request, Status};
use tonic::service::Interceptor;

#[derive(Clone)]
pub struct AuthInterceptor {
    auth_config: AuthConfig,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let claims = axiam_auth::token::validate_access_token(token, &self.auth_config)
            .map_err(|_| Status::unauthenticated("invalid token"))?;

        // Insert claims as request extension for service handlers to read
        request.extensions_mut().insert(claims);
        Ok(request)
    }
}
```

Wiring into the server:

```rust
// [CITED: docs.rs/tonic/0.14] — InterceptedService on per-service basis
use tonic::service::interceptor;

let authz_svc = AuthorizationServiceServer::with_interceptor(
    AuthorizationServiceImpl::new(engine),
    AuthInterceptor::new(auth_config.clone()),
);
```

**Important:** `validate_access_token` is synchronous (`pub fn`, not `async fn`) — safe to call in a synchronous `Interceptor::call` without spawning. [VERIFIED: codebase read — `token.rs:281-285`]

### mTLS vs Bearer Token

mTLS identity is available in Tonic 0.14 via `tonic::transport::server::TlsStream` peer certificate, but requires TLS termination at the Tonic layer (not at the ingress/nginx). For this phase, the ROADMAP specifies "validates bearer JWT / mTLS identity" — implement bearer JWT first (required); mTLS extraction is a secondary concern if TLS terminates at Tonic. The interceptor should accept either: bearer token OR (if TLS is configured on the server transport) a peer certificate claim. [ASSUMED: mTLS peer cert extraction in Tonic 0.14 requires server-side TLS setup not currently configured; start with bearer-only]

### K8s Ingress — Public gRPC Exposure

The second `Ingress` resource in `k8s/ingress.yml` (lines 36-63) exposes `grpc.axiam.example.com` → port 50051 publicly with no auth at the ingress layer:

```yaml
# [VERIFIED: codebase read — k8s/ingress.yml:39-63]
metadata:
  name: axiam-grpc-ingress
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
```

This entire `Ingress` object should be removed. gRPC should only be accessible from within the cluster (service mesh). The `axiam-server` K8s `Service` on port 50051 should be `ClusterIP` (not `NodePort` / `LoadBalancer`).

### Claims → tenant_id / subject_id

The `AccessTokenClaims` struct (from `validate_access_token`) contains `sub` (user UUID string) and `tenant_id`. After inserting into request extensions, service handlers retrieve them:

```rust
// In service handler:
let claims = request.extensions().get::<ValidatedClaims>()
    .ok_or_else(|| Status::internal("missing auth claims"))?;
// Use claims.0.sub as subject_id, claims.0.tenant_id as tenant_id
```

This allows removing the now-caller-trusted `tenant_id`/`subject_id` from the gRPC request body for the authenticated check path (or at minimum cross-validating them).

---

## Domain 3: Frontend Auth Wiring (SEC-044 / CQ-F27)

### Current URL Mismatches (VERIFIED against backend handlers)

All 6 frontend pages call incorrect paths — they drop the `/api/v1/` prefix that the backend requires:

| Page | Current URL called | Correct backend URL |
|------|-------------------|---------------------|
| `ForgotPasswordPage.tsx` | `POST /auth/forgot-password` | `POST /api/v1/auth/reset` |
| `ResetPasswordPage.tsx` | `POST /auth/reset-password` | `POST /api/v1/auth/reset/confirm` |
| `VerifyEmailPage.tsx` | `GET /auth/verify-email?token=…` | `GET /api/v1/auth/verify-email?token=…` |
| `ProfilePage.tsx` (resend) | `POST /auth/resend-verification` | `POST /api/v1/auth/resend-verification` |
| `ChangePasswordPage.tsx` | `POST /auth/change-password` | `POST /api/v1/auth/password/change` |
| `MfaManagementPage.tsx` (setup) | `POST /auth/mfa/setup` | `POST /api/v1/auth/mfa/setup/enroll` |
| `MfaManagementPage.tsx` (confirm) | `POST /auth/mfa/confirm` | `POST /api/v1/auth/mfa/setup/confirm` |

[VERIFIED: codebase read — backend paths from `password_reset.rs:55`, `email_verification.rs:52,86`, `auth.rs:726`, `auth.rs:563`, `auth.rs:587`; frontend calls from page source files]

### Backend Request/Response Contracts

| Backend Route | Method | Request body fields | Success response |
|---------------|--------|---------------------|-----------------|
| `/api/v1/auth/reset` | POST | `{ email: String }` | 200 (body TBD — check handler) |
| `/api/v1/auth/reset/confirm` | POST | `{ token: String, new_password: String }` | 200 |
| `/api/v1/auth/verify-email` | GET | `?token=<str>` | 200 |
| `/api/v1/auth/resend-verification` | POST | `{}` (authenticated) | 200 |
| `/api/v1/auth/password/change` | POST | `{ current_password: String, new_password: String }` | 200 |
| `/api/v1/auth/mfa/setup/enroll` | POST | `{}` | `{ secret, qr_code_uri }` |
| `/api/v1/auth/mfa/setup/confirm` | POST | `{ code: String }` | 200 |

The frontend body field names match the backend structs (e.g., `new_password` matches backend `ChangePasswordRequest`). Only the URL paths need fixing.

### Typed `auth.ts` Service

Create `frontend/src/services/auth.ts` with typed functions for each flow. All calls go through the existing `api` axios instance (handles cookies + CSRF automatically):

```typescript
// Pattern from existing services (e.g., users.ts, organizations.ts)
import api from "@/lib/api";

export async function requestPasswordReset(email: string): Promise<void> {
  await api.post("/api/v1/auth/reset", { email });
}
export async function confirmPasswordReset(token: string, new_password: string): Promise<void> {
  await api.post("/api/v1/auth/reset/confirm", { token, new_password });
}
// ... etc
```

### Frontend↔OpenAPI Contract Test

The existing backend has `route_openapi_parity_test.rs` (server-side Rust test). For the frontend contract, the simplest approach that fits the existing CI is:

1. Add a Playwright test (`e2e/auth-contract.spec.ts`) that checks each auth page sends to the correct backend URL by intercepting requests via `page.route()`.
2. Alternatively, add a vitest unit test in `frontend/src/services/__tests__/auth.test.ts` that verifies the service module exports the correct URL strings.

Since `npm test` = `playwright test` (no vitest in CI), use Playwright's `page.route()` intercept to verify correct endpoint paths. This does not require a running backend.

---

## Domain 4: Silent Refresh / Boot Refresh (CQ-F28)

### Current Silent Refresh Gap (`api.ts:92-97`)

```typescript
// [VERIFIED: codebase read — api.ts:92-97]
await axios.post(
  "/api/v1/auth/refresh",
  {},
  { withCredentials: true }  // <-- uses plain axios, not the api instance
);
```

**Problem 1 — CSRF token missing:** The refresh call uses bare `axios`, bypassing the `api` instance's request interceptor which attaches `X-CSRF-Token`. The refresh endpoint `/api/v1/auth/refresh` is a POST and is protected by CSRF middleware. This means the silent refresh POST has no CSRF token and is rejected by the backend → 403 → calls `clearAuth()` → redirects to `/login`.

**Fix:** Change to `await api.post("/api/v1/auth/refresh", {})` (remove the bare `axios` call). The `api` instance already has `withCredentials: true` set globally.

**Problem 2 — Skip-list too broad:** The skip-list `const isAuthRoute = originalRequest.url?.includes("/auth/")` matches ALL `/auth/` paths. This means a 401 from `/api/v1/auth/me` during boot also bypasses the refresh attempt, causing the interceptor to never attempt refresh when the /me call itself returns 401. However, `/auth/refresh` SHOULD remain in the skip-list (to avoid infinite loop).

**Fix:** Narrow the skip-list to specific paths that must not trigger refresh:
```typescript
const SKIP_REFRESH_URLS = [
  "/api/v1/auth/refresh",
  "/api/v1/auth/login",
  "/api/v1/auth/logout",
];
const isSkipRefresh = SKIP_REFRESH_URLS.some(u => originalRequest.url?.includes(u));
```

### Current Boot Refresh Gap (`useAuthInit.ts`)

```typescript
// [VERIFIED: codebase read — useAuthInit.ts:18-26]
async function init() {
  const user = await fetchCurrentUser();  // calls GET /api/v1/auth/me
  if (cancelled) return;
  if (user) { setUser(user); } else { clearAuth(); }
}
```

If the access token cookie has expired but the refresh cookie is still valid, `fetchCurrentUser()` returns `null` (catches the 401 and returns null — does NOT attempt refresh because `isAuthenticated` is `false` at boot time). The interceptor in `api.ts:76` checks `!isAuthenticated` and skips refresh.

**Fix:** Add an explicit boot refresh attempt before declaring unauthenticated:

```typescript
async function init() {
  let user = await fetchCurrentUser();
  if (!user) {
    // Access token expired — try one silent refresh, then re-fetch
    try {
      await api.post("/api/v1/auth/refresh", {});
      user = await fetchCurrentUser();
    } catch {
      // Refresh token also expired — genuinely unauthenticated
    }
  }
  if (cancelled) return;
  user ? setUser(user) : clearAuth();
}
```

The `setInitializing` store action is imported but never called (as noted in the hook's dep array). This is pre-existing and out of scope.

---

## Domain 5: Federation Secret Decrypt-at-Use (SEC-045 / SEC-017)

### Current State

The `axiam-federation` crate has complete crypto infrastructure:
- `secrets.rs::decrypt_client_secret_or_legacy()` — resolves from encrypted columns or falls back to legacy plaintext. [VERIFIED: codebase read — `secrets.rs:75-91`]
- `main.rs` — loads `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` at boot and runs `migrate_plaintext_federation_secrets` backfill. [VERIFIED: codebase read — `main.rs:122-136`, `203-216`]
- `federation_config.rs` (DB repo) — has `list_with_legacy_plaintext_secret()` and `set_encrypted_secret()`. [VERIFIED: codebase read]

**The gap:** `OidcFederationService::handle_callback()` at line 292 reads `&config.client_secret` — the legacy plaintext field — without calling `decrypt_client_secret_or_legacy`. The `OidcFederationService` struct has no `encryption_key: [u8; 32]` field.

### What Must Change

**Step 1 — Add key to service:** Add `encryption_key: [u8; 32]` to `OidcFederationService` (and its `new()` constructor).

**Step 2 — Wire in server:** In `main.rs`, pass the `federation_encryption_key` when constructing `OidcFederationService`. Currently the service is constructed without the key (the key is only used for the boot backfill, not injected into the service).

**Step 3 — Call decrypt at use-site:** In `handle_callback()`:

```rust
// Replace:
&config.client_secret,

// With:
&axiam_federation::secrets::decrypt_client_secret_or_legacy(
    &self.encryption_key,
    config.client_secret_nonce.as_deref(),
    config.client_secret_ciphertext.as_deref(),
    &config.client_secret,
)
.map_err(|e| FederationError::ConfigIncomplete)?
```

**Step 4 — Encrypt on create/update:** The REST federation handler creates/updates `FederationConfig` via `CreateFederationConfig { client_secret: req.client_secret }`. The DB repo's `create()` has a `TODO(T19.8)` comment. Move the encrypt call to the handler or service layer (not the DB layer) so the plaintext secret is never passed down:

```rust
// In federation REST handler create():
let (nonce, ct) = axiam_federation::secrets::encrypt_client_secret(
    &fed_key,
    &req.client_secret,
)?;
// Store nonce/ct in separate columns; pass empty string for legacy field
```

Then call `set_encrypted_secret()` (already in the repo trait) instead of the `CREATE ... client_secret = $client_secret` path.

**Step 5 — Never-serialize:** `FederationConfig` currently derives `Serialize` with `client_secret: String` as a plain field. Add `#[serde(skip)]` to `client_secret`, `client_secret_ciphertext`, `client_secret_nonce`, and `client_secret_key_version` in the response DTO used by the list/get REST endpoints. The domain model can retain these fields for internal use.

**Key realization:** The backfill at startup (`main.rs:203`) already runs and migrates existing rows. After this phase, the backfill is still needed for rows that were created before the fix. After encrypt-on-create is deployed, new rows are written encrypted; the backfill handles legacy rows. The flow works end-to-end after restart because:
1. Boot backfill encrypts any remaining plaintext rows.
2. `handle_callback()` calls `decrypt_client_secret_or_legacy()`.
3. If key is set and row is encrypted → decrypts. If key is not set → config error at boot (already logged as WARN).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWT validation in gRPC | Custom base64/HMAC decode | `axiam_auth::token::validate_access_token` | Already verified against EdDSA key, handles expiry, issuer, leeway |
| AES-GCM for federation secrets | Custom crypto | `axiam_auth::crypto::{encrypt_separate, decrypt_separate}` via `axiam_federation::secrets` | Already tested; wrong format choice causes decrypt-on-wrong-variant failure |
| HTTP client for frontend auth | Raw `fetch()` | `api` axios instance (already handles cookies + CSRF) | Bypassing `api` is exactly the CQ-F28 bug |
| gRPC client-side auth | Custom gRPC interceptor | Tonic `Interceptor` trait / `InterceptedService` | Tonic's own mechanism; any other approach breaks streaming |

---

## Common Pitfalls

### Pitfall 1: Tonic 0.14 Interceptor Only Intercepts Unary RPCs by Default
**What goes wrong:** If you use `Server::builder().layer(interceptor(...))` as a Tower layer instead of `ServiceServer::with_interceptor(impl, interceptor)`, streaming RPCs may bypass it.
**Why it happens:** Tower layers and Tonic interceptors have different behavior for streaming. The ROADMAP only requires auth on the existing unary services.
**How to avoid:** Use `AuthorizationServiceServer::with_interceptor(...)` per-service. Test with the `grpc_authz_test.rs` harness.

### Pitfall 2: Bare `axios` vs `api` Instance for Refresh
**What goes wrong:** Using `axios.post("/api/v1/auth/refresh")` instead of `api.post(...)` silently drops the `X-CSRF-Token` header because the interceptor is on `api`, not on `axios`.
**Why it happens:** CQ-F28 root cause — the existing code uses bare `axios` to avoid calling the response interceptor recursively, but the request interceptor (CSRF) is also on `api`, not bare `axios`.
**How to avoid:** Use `api.post` with `_retry: true` pre-set on the refresh call to prevent the response interceptor from treating the refresh's own 401 as retriable.

### Pitfall 3: Tenant `create`/`list` Org Guard
**What goes wrong:** Adding `if path.org_id != user.org_id { 403 }` to tenants `create` is correct but the `organization_id` in `CreateTenant` is set from `path.org_id`, not from the body. Verify this doesn't require a body change.
**Why it happens:** The `CreateTenantRequest` body intentionally omits `organization_id` (it comes from the URL). Adding the org guard does NOT change the input shape.
**How to avoid:** Guard check goes BEFORE `repo.create()`. No body change needed.

### Pitfall 4: `FederationConfig` Serialize Skip Must Not Break Tests
**What goes wrong:** Adding `#[serde(skip)]` to `client_secret` on `FederationConfig` will break any test that serializes a `FederationConfig` and then checks the JSON output.
**Why it happens:** The domain model is the same type used by both the REST response and internal logic.
**How to avoid:** Create a `FederationConfigResponse` DTO (without secret fields) for REST responses, OR add `#[serde(skip_serializing)]` (keep deserializing for existing stored data).

### Pitfall 5: Boot Refresh in `useAuthInit` Must Not Loop
**What goes wrong:** If the refresh endpoint also returns 401 (expired refresh token), and the retry logic re-calls `fetchCurrentUser`, it could loop.
**Why it happens:** The response interceptor in `api.ts` could trigger again on the /me call after a failed refresh.
**How to avoid:** Wrap the boot refresh in try/catch; if it fails, call `clearAuth()` immediately without re-entering the interceptor. The interceptor's `_retry` guard already prevents repeated retries on individual requests.

### Pitfall 6: `cargo check` vs `cargo build` for gRPC Proto Changes
**What goes wrong:** Changes to `server.rs` that add `AuthInterceptor` parameter to functions will require the `AuthConfig` to be `Clone`. `AuthConfig` likely is Clone already but verify.
**How to avoid:** Run `cargo check -p axiam-api-grpc` immediately after changes. Do NOT run full workspace build.

---

## Code Examples

### Org-Scoping Guard (canonical pattern)
```rust
// Source: verified from crates/axiam-api-rest/src/handlers/settings.rs:42-48
if org_id != user.org_id {
    return Err(AxiamApiError(
        axiam_core::error::AxiamError::AuthorizationDenied {
            reason: "cannot access a different organization".into(),
        },
    ));
}
```

### Tonic Interceptor (Tonic 0.14)
```rust
// Source: [CITED: docs.rs/tonic/0.14/tonic/service/trait.Interceptor.html]
use tonic::{Request, Status};
use tonic::service::Interceptor;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::validate_access_token;

#[derive(Clone)]
pub struct AuthInterceptor {
    auth_config: AuthConfig,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = req.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;
        let claims = validate_access_token(token, &self.auth_config)
            .map_err(|_| Status::unauthenticated("invalid or expired token"))?;
        req.extensions_mut().insert(claims);
        Ok(req)
    }
}
```

### Frontend Auth Service (`auth.ts`)
```typescript
// Pattern: same as existing services/users.ts, services/organizations.ts
import api from "@/lib/api";

export const authService = {
  requestPasswordReset: (email: string) =>
    api.post("/api/v1/auth/reset", { email }),
  confirmPasswordReset: (token: string, new_password: string) =>
    api.post("/api/v1/auth/reset/confirm", { token, new_password }),
  verifyEmail: (token: string) =>
    api.get(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`),
  resendVerification: () =>
    api.post("/api/v1/auth/resend-verification", {}),
  changePassword: (current_password: string, new_password: string) =>
    api.post("/api/v1/auth/password/change", { current_password, new_password }),
  enrollMfa: () =>
    api.post("/api/v1/auth/mfa/setup/enroll", {}),
  confirmMfa: (code: string) =>
    api.post("/api/v1/auth/mfa/setup/confirm", { code }),
};
```

### Silent Refresh Fix (`api.ts`)
```typescript
// Fix 1: replace bare axios with api instance
await api.post("/api/v1/auth/refresh", {});

// Fix 2: narrow skip-list
const SKIP_REFRESH = ["/api/v1/auth/refresh", "/api/v1/auth/login", "/api/v1/auth/logout"];
const isSkipRefresh = SKIP_REFRESH.some(u => originalRequest.url?.includes(u));
```

---

## Runtime State Inventory

> Not a rename/refactor phase. However, the federation secret migration touches runtime DB state.

| Category | Items Found | Action Required |
|----------|-------------|-----------------|
| Stored data | `federation_config` table rows with `client_secret != ""` and `client_secret_ciphertext IS NONE` | Boot backfill already in `main.rs` — runs on next deploy. Code-only fix to wire decrypt-at-use. |
| Live service config | No n8n/external service config involved | None |
| OS-registered state | None | None |
| Secrets/env vars | `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` — must be set for encrypt/decrypt to work. Already loaded by `main.rs`. | Verify env var is set in dev compose and k8s secrets before deploy |
| Build artifacts | None | None |

**Critical runtime risk:** If `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` is not set, the boot backfill is skipped (logged as WARN) AND the new `decrypt_client_secret_or_legacy()` call will fail with `FederationError::ConfigIncomplete` for any row that has been backfilled. The operator MUST set this env var before the Phase 9 deploy.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|-------------|-----------|---------|---------|
| `cargo check -p axiam-api-grpc` | gRPC interceptor build | ✓ | Rust 1.93+ | — |
| `cargo check -p axiam-api-rest` | Org guard changes | ✓ | Rust 1.93+ | — |
| `cargo check -p axiam-federation` | Decrypt-at-use wiring | ✓ | Rust 1.93+ | — |
| `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | gRPC interceptor test | ✓ | in-process SurrealDB Mem | — |
| `cargo test -p axiam-api-rest --test organization_test` | Cross-org 403 test | ✓ | in-process SurrealDB Mem | — |
| `npm test` (Playwright) | Frontend auth contract test | ✓ | Node 20 / Playwright 1.58 | — |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust test framework | `cargo test` (built-in) |
| gRPC test harness | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` (in-process TcpListener + Tonic client stubs) |
| REST test harness | `crates/axiam-api-rest/tests/` (actix-web test server, in-process SurrealDB Mem) |
| Frontend test framework | Playwright 1.58 (`npm test`) |
| Quick run (Rust) | `cargo test -p axiam-api-rest --test organization_test -p axiam-api-grpc --test grpc_auth_test 2>&1` |
| Full suite (Rust) | `cargo test -p axiam-api-rest -p axiam-api-grpc -p axiam-federation 2>&1` |
| Quick run (frontend) | `npm test --prefix frontend -- --grep "auth contract"` |

### Phase Requirements → Test Map

| Req | Behavior | Test Type | Automated Command | File Exists? |
|-----|----------|-----------|-------------------|-------------|
| REQ-13-AC1 | Cross-org GET /orgs/{other_org_id} returns 403 | integration | `cargo test -p axiam-api-rest --test organization_test` | ❌ Wave 0 (add cross-org test case) |
| REQ-13-AC1 | Cross-org GET /orgs/{org_id}/tenants returns 403 | integration | `cargo test -p axiam-api-rest --test tenant_test` | ❌ Wave 0 (add cross-org test case) |
| REQ-13-AC1 | Cross-org GET /orgs/{org_id}/ca-certificates returns 403 | integration | `cargo test -p axiam-api-rest --test ca_certificate_test` | ❌ Wave 0 (add cross-org test case) |
| REQ-13-AC2 | gRPC call without bearer token returns UNAUTHENTICATED | integration | `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | ❌ Wave 0 (new test file) |
| REQ-13-AC2 | gRPC call with valid bearer token succeeds | integration | `cargo test -p axiam-api-grpc --features client --test grpc_auth_test` | ❌ Wave 0 (new test file) |
| REQ-13-AC3 | Frontend reset page calls `/api/v1/auth/reset` | E2E/contract | `npm test --prefix frontend` | ❌ Wave 0 (new Playwright auth-contract spec) |
| REQ-13-AC3 | Frontend MFA enroll calls `/api/v1/auth/mfa/setup/enroll` | E2E/contract | `npm test --prefix frontend` | ❌ Wave 0 |
| REQ-13-AC4 | Silent refresh POST includes X-CSRF-Token header | unit/contract | `npm test --prefix frontend -- --grep "csrf"` | ❌ Wave 0 |
| REQ-13-AC4 | Boot init attempts refresh before declaring unauth | integration (manual smoke) | Manual: expire access cookie, reload app | manual-only |
| REQ-13-AC5 | OIDC login succeeds after server restart with encrypted secret | integration | `cargo test -p axiam-api-rest --test federation_test` | ❌ Wave 0 (add encrypt/decrypt round-trip) |

### Sampling Rate

- **Per task commit:** `cargo check -p <changed_crate> --tests 2>&1 | tail -5`
- **Per wave merge:** `cargo test -p axiam-api-rest -p axiam-api-grpc -p axiam-federation 2>&1` + `npm test --prefix frontend`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/axiam-api-rest/tests/organization_test.rs` — add cross-org 403 test cases (org/tenant/ca-cert)
- [ ] `crates/axiam-api-grpc/tests/grpc_auth_test.rs` — new file for interceptor accept/reject tests
- [ ] `frontend/e2e/auth-contract.spec.ts` — Playwright contract test for all 6 auth endpoint URLs

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | `validate_access_token` (EdDSA JWT); cookie-based session |
| V3 Session Management | yes | Session revocation on password change (existing) |
| V4 Access Control | yes | Org-ownership check; gRPC interceptor enforces identity |
| V5 Input Validation | yes | Org ID from JWT (trusted), not from request body |
| V6 Cryptography | yes | `axiam_auth::crypto::encrypt_separate` / `decrypt_separate` (AES-256-GCM, 12-byte nonce, OsRng) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Cross-org IDOR (SEC-002) | Spoofing + Info Disclosure | JWT-derived `org_id` check before DB query |
| Unauthenticated gRPC (SEC-003) | Elevation of Privilege | Tonic `Interceptor` validates bearer JWT |
| Plaintext client secret in DB (SEC-045) | Info Disclosure | AES-256-GCM encrypt-at-rest; decrypt-at-use; `#[serde(skip_serializing)]` |
| CSRF token missing on refresh (CQ-F28) | CSRF | Use `api` axios instance (not bare `axios`) for the refresh POST |
| Wrong endpoint path (SEC-044) | Authentication bypass (calls fail silently) | Replace inline URL strings with `auth.ts` typed service |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | mTLS peer cert extraction in Tonic 0.14 requires server-side TLS setup not currently in `server.rs` — implement bearer-only for this phase | Domain 2 gRPC | Low risk: bearer JWT satisfies the ROADMAP; mTLS is additive |
| A2 | `organizations:create` and `organizations:list` should be super-admin-only via permission seeder change, not a new handler check | Domain 1 org-scoping | Medium: if existing tenants have those permissions seeded, the seeder fix alone won't revoke them; may need a migration to revoke from non-super-admin roles |
| A3 | `FederationConfigResponse` DTO separation is preferable to `#[serde(skip_serializing)]` on the domain model | Domain 5 | Low: either approach works; `skip_serializing` is simpler |

---

## Open Questions

1. **Super-admin restriction for org create/list:**
   - What we know: The `super-admin` seeder role already has all permissions. Tenant-level roles should not have `organizations:create` / `organizations:list`.
   - What's unclear: Whether any existing dev/test tenants have those permissions incorrectly seeded.
   - Recommendation: Check `seed_permissions` in `seeder.rs` — if those two permissions are in `PERMISSION_REGISTRY` but omitted from the tenant seed loop, the guard is automatically enforced. Verify this is the case before adding handler-level role checks.

2. **gRPC ingress removal scope:**
   - What we know: The `axiam-grpc-ingress` object should be removed from `k8s/ingress.yml`.
   - What's unclear: Whether the `axiam-server` K8s `Service` on port 50051 is `NodePort` or `ClusterIP`.
   - Recommendation: Check `k8s/server/service.yml`. If it's `NodePort`, change to `ClusterIP` as part of this task.

---

## Sources

### Primary (HIGH confidence)
- Codebase read: `crates/axiam-api-rest/src/handlers/settings.rs` — org-scoping pattern (lines 42-48)
- Codebase read: `crates/axiam-api-rest/src/handlers/organizations.rs` — missing guards
- Codebase read: `crates/axiam-api-rest/src/handlers/tenants.rs` — partial guards
- Codebase read: `crates/axiam-api-rest/src/handlers/ca_certificates.rs` — missing guards
- Codebase read: `crates/axiam-api-grpc/src/server.rs` — no interceptor present
- Codebase read: `crates/axiam-auth/src/token.rs:281-285` — `validate_access_token` is sync
- Codebase read: `frontend/src/lib/api.ts:92-97` — bare axios CSRF gap
- Codebase read: `frontend/src/hooks/useAuthInit.ts` — no boot refresh
- Codebase read: `crates/axiam-federation/src/oidc.rs:292` — uses `config.client_secret` (plaintext)
- Codebase read: `crates/axiam-federation/src/secrets.rs` — `decrypt_client_secret_or_legacy` exists
- Codebase read: `crates/axiam-server/src/main.rs:122-136,203-216` — key loading and backfill
- Codebase read: `k8s/ingress.yml:36-63` — public gRPC ingress object

### Secondary (MEDIUM confidence)
- [CITED: docs.rs/tonic/0.14] — `Interceptor` trait and `InterceptedService` pattern for Tonic 0.14

### Tertiary (LOW confidence)
- None

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages; all crates verified in workspace
- Architecture: HIGH — all patterns verified from codebase reads
- Pitfalls: HIGH — root causes verified from actual code (not training data)
- Validation: HIGH — test files verified to exist or not exist

**Research date:** 2026-06-11
**Valid until:** 2026-07-11 (stable codebase; valid until next wave of changes)
