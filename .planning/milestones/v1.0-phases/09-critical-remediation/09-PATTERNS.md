# Phase 9: Critical Remediation - Pattern Map

**Mapped:** 2026-06-11
**Files analyzed:** 3 (net-new files only; modify targets already covered in RESEARCH.md)
**Analogs found:** 3 / 3

> **Scope note:** RESEARCH.md already contains verified code excerpts for every MODIFY target
> (org-scoping guard from `settings.rs:42-48`, gRPC interceptor from docs.rs/tonic/0.14,
> federation `secrets.rs` helper, `api.ts` CSRF fix, `oidc.rs:292` use-site).
> This document covers only the three NET-NEW files.

---

## File Classification

| New File | Role | Data Flow | Closest Analog | Match Quality |
|----------|------|-----------|----------------|---------------|
| `crates/axiam-api-grpc/tests/grpc_auth_test.rs` | test | request-response | `crates/axiam-api-grpc/tests/grpc_authz_test.rs` | exact |
| `frontend/src/services/auth.ts` | service | request-response | `frontend/src/services/users.ts` | exact |
| `frontend/e2e/auth-contract.spec.ts` | test | request-response | `frontend/e2e/identity.spec.ts` (route-intercept) + `frontend/e2e/login.spec.ts` (describe structure) | exact |

---

## Pattern Assignments

### `crates/axiam-api-grpc/tests/grpc_auth_test.rs` (test, request-response)

**Analog:** `crates/axiam-api-grpc/tests/grpc_authz_test.rs`

**Imports pattern** (lines 1-35):
```rust
use axiam_api_grpc::proto::authorization_service_client::AuthorizationServiceClient;
use axiam_api_grpc::proto::authorization_service_server::AuthorizationServiceServer;
use axiam_api_grpc::services::AuthorizationServiceImpl;
use axiam_db::repository::{SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use uuid::Uuid;
```

**In-process server harness** (lines 184-211):
```rust
async fn start_test_server(engine: TestEngine) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let authz_svc = AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine));

    tokio::spawn(
        Server::builder()
            .add_service(authz_svc)
            .serve_with_incoming_shutdown(incoming, async {
                rx.await.ok();
            }),
    );

    let endpoint = format!("http://{addr}");
    (endpoint, tx)
}

async fn connect_client(endpoint: String) -> AuthorizationServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    AuthorizationServiceClient::new(channel)
}
```

**Key adaptation for `grpc_auth_test.rs`:** The new test wires `AuthorizationServiceServer::with_interceptor(impl, AuthInterceptor::new(auth_config))` instead of `AuthorizationServiceServer::new(impl)`. The `start_test_server` function must accept `AuthConfig` and construct the interceptor. The DB setup (`setup()` / `make_engine()`) is identical to `grpc_authz_test.rs` — copy verbatim.

**Test structure pattern** (lines 217-348 — accept/reject shape):
```rust
#[tokio::test]
async fn grpc_rejects_unauthenticated_call() {
    let (db, _tenant_id, _user_id) = setup().await;
    let engine = make_engine(&db);
    let auth_config = test_auth_config(); // helper that builds a valid AuthConfig
    let (endpoint, _shutdown) = start_test_server(engine, auth_config).await;
    let mut client = connect_client(endpoint).await;

    // Call WITHOUT authorization metadata — must return UNAUTHENTICATED
    let result = client
        .check_access(CheckAccessRequest { /* ... */ })
        .await;

    let err = result.expect_err("expected UNAUTHENTICATED");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn grpc_accepts_valid_bearer_token() {
    let (db, tenant_id, user_id) = setup().await;
    let engine = make_engine(&db);
    let auth_config = test_auth_config();
    let (endpoint, _shutdown) = start_test_server(engine, auth_config.clone()).await;

    // Mint a valid token using axiam_auth::token::create_access_token
    let token = mint_test_token(tenant_id, user_id, &auth_config);

    let channel = Channel::from_shared(endpoint).unwrap().connect().await.unwrap();
    let mut client = AuthorizationServiceClient::with_interceptor(
        channel,
        move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {token}").parse().unwrap(),
            );
            Ok(req)
        },
    );

    // Call WITH authorization metadata — must succeed (UNAUTHENTICATED not returned)
    let resp = client
        .check_access(CheckAccessRequest { /* tenant_id, subject_id from claims */ })
        .await;
    // Expect Ok (allowed or denied by authz — not rejected at interceptor level)
    assert!(resp.is_ok(), "expected Ok, got {:?}", resp);
}
```

**Critical note:** Do NOT attach `build_grpc_governor_layer` in the test server — `SmartIpKeyExtractor` panics without a real peer IP on in-process connections. This is documented in `grpc_authz_test.rs:181-182`.

**Cargo feature gate** (mirrors existing test invocation):
```
// Run with: cargo test -p axiam-api-grpc --features client --test grpc_auth_test
```

---

### `frontend/src/services/auth.ts` (service, request-response)

**Analog:** `frontend/src/services/users.ts`

**Imports pattern** (line 1):
```typescript
import api from "@/lib/api";
```

**Domain type convention** (lines 3-33 of `users.ts`):
```typescript
// Export typed interfaces for request payloads and response shapes
export interface PasswordResetRequest {
  email: string;
}
export interface PasswordResetConfirmRequest {
  token: string;
  new_password: string;
}
export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}
export interface MfaEnrollResponse {
  secret: string;
  qr_code_uri: string;
}
export interface MfaConfirmRequest {
  code: string;
}
```

**Service object pattern** (lines 69-108 of `users.ts`):
```typescript
// Named export as a const object — mirrors userService, groupService convention
export const authService = {
  requestPasswordReset: (email: string): Promise<void> =>
    api.post("/api/v1/auth/reset", { email }).then(() => undefined),

  confirmPasswordReset: (token: string, new_password: string): Promise<void> =>
    api.post("/api/v1/auth/reset/confirm", { token, new_password }).then(() => undefined),

  verifyEmail: (token: string): Promise<void> =>
    api.get(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`).then(() => undefined),

  resendVerification: (): Promise<void> =>
    api.post("/api/v1/auth/resend-verification", {}).then(() => undefined),

  changePassword: (current_password: string, new_password: string): Promise<void> =>
    api.post("/api/v1/auth/password/change", { current_password, new_password }).then(() => undefined),

  enrollMfa: (): Promise<MfaEnrollResponse> =>
    api.post<MfaEnrollResponse>("/api/v1/auth/mfa/setup/enroll", {}).then((r) => r.data),

  confirmMfa: (code: string): Promise<void> =>
    api.post("/api/v1/auth/mfa/setup/confirm", { code }).then(() => undefined),
};
```

**Convention notes from analog:**
- All calls go through `api` (never bare `axios`) — this is exactly what CQ-F28 requires
- Methods that return no body use `.then(() => undefined)` (not `.then((r) => r.data)`)
- Methods that return a body use `.then((r) => r.data)` with generic type param `api.post<T>`
- Service is a named `const` export (not a class), consistent with `userService`, `groupService`, `roleService` etc.

---

### `frontend/e2e/auth-contract.spec.ts` (test, request-response)

**Analogs:**
- Structure: `frontend/e2e/login.spec.ts` (describe + test idiom, `loginAsAdmin` helper import)
- Request interception: `frontend/e2e/identity.spec.ts:125-141` (route intercept + method check)
- URL assertion: `frontend/e2e/federation.spec.ts:92-103` (route intercept to check outbound URL)

**Imports pattern** (line 1 of `login.spec.ts`):
```typescript
import { test, expect } from "@playwright/test";
// No loginAsAdmin needed for contract tests — pages are exercised unauthenticated
// (password reset, verify email) or the service call is intercepted before it fires
```

**Route intercept + URL assertion pattern** (from `identity.spec.ts:125-141`):
```typescript
test("Forgot Password submits to /api/v1/auth/reset", async ({ page }) => {
  let capturedUrl: string | undefined;

  await page.route("**/auth/**", (route) => {
    // Capture the actual URL the page called
    capturedUrl = route.request().url();
    route.fulfill({ status: 200, json: {} });
  });

  await page.goto("/auth/forgot-password");
  await page.getByLabel("Email address").fill("test@example.com");
  await page.getByRole("button", { name: /Send Reset Link/i }).click();

  expect(capturedUrl).toContain("/api/v1/auth/reset");
  expect(capturedUrl).not.toContain("/auth/forgot-password"); // old wrong path
});
```

**Method check pattern** (from `identity.spec.ts:127`):
```typescript
if (route.request().method() === "POST") {
  route.fulfill({ status: 200, json: {} });
} else {
  route.continue();
}
```

**Describe wrapper pattern** (from `login.spec.ts:4`):
```typescript
test.describe("Auth endpoint contract", () => {
  // One test per auth flow — each verifies the URL the page calls
  test("ForgotPasswordPage calls POST /api/v1/auth/reset", ...);
  test("ResetPasswordPage calls POST /api/v1/auth/reset/confirm", ...);
  test("VerifyEmailPage calls GET /api/v1/auth/verify-email", ...);
  test("ProfilePage resend-verification calls POST /api/v1/auth/resend-verification", ...);
  test("ChangePasswordPage calls POST /api/v1/auth/password/change", ...);
  test("MfaManagementPage enroll calls POST /api/v1/auth/mfa/setup/enroll", ...);
  test("MfaManagementPage confirm calls POST /api/v1/auth/mfa/setup/confirm", ...);
  // CSRF contract: silent refresh POST includes X-CSRF-Token header
  test("silent refresh POST includes X-CSRF-Token header", ...);
});
```

**CSRF header contract pattern** (new pattern, no direct analog — use `page.route` request headers):
```typescript
test("silent refresh POST includes X-CSRF-Token header", async ({ page }) => {
  let refreshHeaders: Record<string, string> = {};

  await page.route("**/auth/refresh", (route) => {
    refreshHeaders = route.request().headers();
    route.fulfill({ status: 200, json: {} });
  });

  // Trigger a refresh by expiring the session and reloading
  // (simplest approach: call the refresh directly via evaluate)
  await page.goto("/");
  await page.evaluate(() =>
    fetch("/api/v1/auth/refresh", { method: "POST", credentials: "include" })
  );

  // Or: navigate to a protected page after clearing access token cookie
  // The specific trigger mechanism depends on test setup
  expect(refreshHeaders["x-csrf-token"]).toBeTruthy();
});
```

**Playwright config** (`playwright.config.ts`):
- `testDir: "./e2e"` — spec must be placed at `frontend/e2e/auth-contract.spec.ts`
- `baseURL: process.env["E2E_BASE_URL"] ?? "http://localhost:5173"` — tests run against the dev/prod server
- `reuseExistingServer: true` — CI uses `npx serve dist -l 5173`; no separate dev server spawned

---

## Shared Patterns

### gRPC Test Auth Config Helper

No analog exists in the codebase yet. The new `grpc_auth_test.rs` needs a `test_auth_config()` helper that builds an `AuthConfig` with an ephemeral Ed25519 key pair, and a `mint_test_token()` helper that calls `axiam_auth::token::create_access_token`. These are analogous to the JWT helpers in `axiam-api-rest/tests/` (look for `create_test_jwt` or similar if they exist in REST test helpers before implementing).

### Axios `api` Instance (Cross-cutting for frontend)

**Source:** `frontend/src/lib/api.ts:92-97` (documented in RESEARCH.md)
**Apply to:** `auth.ts` service — must always use `api`, never bare `axios`.
All 14 existing service files (`users.ts`, `roles.ts`, `organizations.ts`, etc.) follow this without exception.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `crates/axiam-api-grpc/src/middleware/auth.rs` | middleware | request-response | No Tonic interceptor module exists yet in the codebase; Tonic 0.14 docs.rs pattern (already in RESEARCH.md) is the reference |

---

## Metadata

**Analog search scope:** `crates/axiam-api-grpc/tests/`, `crates/axiam-api-rest/tests/`, `frontend/src/services/`, `frontend/e2e/`
**Files scanned:** `grpc_authz_test.rs`, `users.ts`, `login.spec.ts`, `identity.spec.ts`, `federation.spec.ts`
**Pattern extraction date:** 2026-06-11
