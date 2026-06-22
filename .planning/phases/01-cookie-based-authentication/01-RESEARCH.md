# Phase 1: Cookie-Based Authentication - Research

**Researched:** 2026-03-30
**Domain:** Rust / Actix-Web 4 cookie security, CSRF double-submit, frontend auth refactor
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**CSRF Protection**
- D-01: Double-submit cookie pattern (per design document) with cryptographically random token — no HMAC derivation, no server secret key management needed
- D-02: CSRF token issued per-session — new token on login and refresh-token rotation. No per-request rotation
- D-03: Frontend sends CSRF token via `X-CSRF-Token` header
- D-04: CSRF validation required on all state-changing requests (POST, PUT, PATCH, DELETE) via middleware. GET/HEAD/OPTIONS exempt

**Cookie Scope & Configuration**
- D-05: Access token cookie: `httpOnly; Secure; SameSite=Strict; Path=/`
- D-06: Refresh token cookie: `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh`
- D-07: CSRF token cookie: readable by JS (no httpOnly), `Secure; SameSite=Strict; Path=/`
- D-08: Omit `Domain` attribute on all cookies — origin-only scoping
- D-09: Cookie `Max-Age` matches JWT TTL — access cookie = 900s (15 min), refresh cookie = refresh token TTL

**Frontend Auth State**
- D-10: Login response body returns `{ user: { id, username, email }, session_id, expires_in }` — tokens in Set-Cookie only
- D-11: Frontend calls `GET /api/v1/auth/me` on app initialization to rehydrate auth state
- D-12: Zustand store becomes memory-only — remove `persist` middleware and all sessionStorage usage

**Backend Response Shape**
- D-13: `LoginSuccessResponse` changes to `{ user, session_id, expires_in }` — access_token and refresh_token fields removed
- D-14: Refresh endpoint returns `{ expires_in }` in body + new cookies
- D-15: Auth extractor must support reading JWT from cookie instead of `Authorization: Bearer` header

**Testing**
- D-16: Integration tests use cookie jar in Actix-Web test client — no Authorization header fallback

### Claude's Discretion
- Cookie names (e.g., `axiam_access`, `axiam_refresh`, `axiam_csrf` or similar)
- CSRF middleware implementation details (Actix-Web middleware vs extractor)
- `/me` endpoint implementation (new handler or extend existing)
- Order of refactoring (backend-first or frontend-first)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-1 | Cookie-Based Authentication (8 acceptance criteria) | All AC are directly addressed: cookie builder API (AC1-2), path-scoped refresh cookie (AC3), CSRF double-submit (AC4-5), logout clearing (AC6), refresh endpoint (AC7), integration test update (AC8) |
</phase_requirements>

---

## Summary

This phase migrates AXIAM's JWT delivery from JSON body + sessionStorage (XSS-vulnerable) to httpOnly secure cookies with CSRF protection. The Actix-Web 4.13 cookie API is mature and provides all required attributes directly via the `Cookie::build()` builder — no external crate needed for cookie setting. CSRF protection will be implemented as custom Actix-Web middleware (wrapping the service) rather than using `actix-csrf`, because the decided pattern (cryptographically random per-session token, `X-CSRF-Token` header validation) is straightforward to implement in ~60 lines and avoids adding an unaudited dependency.

The backend changes are surgical: login/refresh/logout handlers gain Set-Cookie calls, the auth extractor gains cookie fallback, a new `/api/v1/auth/me` handler is added, and a CSRF middleware is registered on the app. The frontend changes replace the sessionStorage-backed Zustand store with a memory-only store and refactor the Axios client to use `withCredentials: true` + CSRF token header injection.

**Primary recommendation:** Implement backend-first (cookies, CSRF middleware, /me endpoint, test updates), then frontend refactor. This allows cookie behavior to be fully tested independently before the frontend is changed.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| actix-web | 4.13.0 (resolved) | HTTP response builder with cookie API | Already in use; `HttpResponseBuilder::cookie()` supports all required attributes |
| actix-web `cookie` module | re-exported from `cookie` 0.18 | `Cookie::build()`, `SameSite`, `time::Duration` | Built into actix-web 4; no separate dependency needed |
| rand | 0.9.2 (workspace) | Cryptographically random CSRF token generation | Already in workspace; use `rand::rng().random::<[u8; 32]>()` → hex encode |
| hex | 0.4 (workspace) | Encode CSRF token bytes as hex string | Already in workspace |
| zustand | ^5.0.12 (frontend) | In-memory auth state store | Already in use; simply remove `persist` middleware |
| axios | ^1.13.6 (frontend) | HTTP client with `withCredentials` + interceptors | Already in use; refactor interceptors to read CSRF cookie |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `cookie::time::Duration` | via actix-web re-export | Set `Max-Age` on cookies | Required for access (900s) and refresh (2_592_000s) TTLs |
| `js-cookie` or native `document.cookie` | — | Read CSRF token cookie in frontend | For reading `axiam_csrf` cookie to inject in `X-CSRF-Token` header |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Custom CSRF middleware | `actix-csrf` crate | actix-csrf adds `__Host-` prefixes and is more opinionated; the decided pattern is simpler and avoids an unaudited dependency |
| Custom CSRF middleware | `actix-session` | actix-session is session storage, not CSRF protection — wrong tool |
| Native `document.cookie` | `js-cookie` npm package | js-cookie is convenient but adds a dependency; `document.cookie` parsing is a 5-line utility function |

**Installation (workspace Cargo.toml — no new deps needed):**

All required crates are already in the workspace. No new dependencies to add.

**Version verification:** actix-web 4.13.0 and rand 0.9.2 confirmed from `Cargo.lock`.

---

## Architecture Patterns

### Recommended Project Structure Changes

```
crates/axiam-api-rest/src/
├── middleware/
│   ├── mod.rs          # pub mod csrf;
│   └── csrf.rs         # NEW: CsrfMiddleware (Transform + Service impl)
├── handlers/
│   └── auth.rs         # MODIFIED: login/logout/refresh/me handlers
├── extractors/
│   └── auth.rs         # MODIFIED: cookie fallback, keep header support for device/gRPC
frontend/src/
├── stores/
│   └── auth.ts         # MODIFIED: remove persist, remove accessToken field
└── lib/
    └── api.ts          # MODIFIED: withCredentials, X-CSRF-Token interceptor
```

### Pattern 1: Setting httpOnly Cookies in actix-web 4

**What:** Use `Cookie::build()` builder with chained attribute methods, then `.finish()`. Pass to `HttpResponseBuilder::cookie()`.

**When to use:** Login success, refresh success, and MFA verify success — any response that issues new tokens.

**Example:**
```rust
// Source: https://docs.rs/actix-web/4.13.0/actix_web/cookie/struct.Cookie.html
use actix_web::cookie::{Cookie, SameSite, time::Duration};

fn access_cookie(token: &str, lifetime_secs: u64) -> Cookie<'static> {
    Cookie::build("axiam_access", token.to_owned())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(lifetime_secs as i64))
        .finish()
}

fn refresh_cookie(token: &str, lifetime_secs: u64) -> Cookie<'static> {
    Cookie::build("axiam_refresh", token.to_owned())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/api/v1/auth/refresh")   // path-scoped per D-06
        .max_age(Duration::seconds(lifetime_secs as i64))
        .finish()
}

fn csrf_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("axiam_csrf", token.to_owned())
        .http_only(false)              // JS-readable per D-07
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .finish()                      // No Max-Age — session cookie; cleared on browser close
        // OR: set same Max-Age as access token for SPA convenience
}
```

Note: `Domain` attribute is intentionally omitted (D-08) — `Cookie::build` does not set it by default.

### Pattern 2: Clearing Cookies on Logout

**What:** Set cookies with `Max-Age=0` to instruct browsers to delete them immediately.

**When to use:** POST /auth/logout handler.

**Example:**
```rust
// Source: actix-web 4 docs — Cookie::make_removal() sets Max-Age=0 and expires to Unix epoch
fn clear_access_cookie() -> Cookie<'static> {
    let mut c = Cookie::build("axiam_access", "")
        .path("/")
        .finish();
    c.make_removal();
    c
}

fn clear_refresh_cookie() -> Cookie<'static> {
    let mut c = Cookie::build("axiam_refresh", "")
        .path("/api/v1/auth/refresh")  // Must match original path
        .finish();
    c.make_removal();
    c
}

fn clear_csrf_cookie() -> Cookie<'static> {
    let mut c = Cookie::build("axiam_csrf", "")
        .path("/")
        .finish();
    c.make_removal();
    c
}

// In logout handler:
Ok(HttpResponse::NoContent()
    .cookie(clear_access_cookie())
    .cookie(clear_refresh_cookie())
    .cookie(clear_csrf_cookie())
    .finish())
```

**Critical:** The `path` on the removal cookie MUST exactly match the `path` set when the cookie was created. Mismatch causes browsers to ignore the removal.

### Pattern 3: Reading Cookies in Actix-Web Extractors

**What:** Use `HttpRequest::cookie("name")` to extract a named cookie from an incoming request.

**When to use:** Modified `AuthenticatedUser` extractor (reading access token), CSRF middleware (reading CSRF cookie to compare against header).

**Example:**
```rust
// Source: actix-web 4 docs — HttpRequest::cookie()
fn extract_user(req: &HttpRequest) -> Result<AuthenticatedUser, AxiamApiError> {
    // Try cached identity first (audit middleware sets this)
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        return Ok(/* ... from cached ... */);
    }

    let config = req.app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    // Try cookie first, then fall back to Authorization header
    let token = if let Some(cookie) = req.cookie("axiam_access") {
        cookie.value().to_owned()
    } else {
        // Header fallback for device auth / service-to-service (non-browser clients)
        extract_bearer_token(req)?
    };

    let validated = validate_access_token(&token, config).map_err(AxiamError::from)?;
    // ... rest of extraction
}
```

### Pattern 4: CSRF Middleware (Double-Submit)

**What:** Actix-Web `Transform` + `Service` middleware that validates `X-CSRF-Token` header matches `axiam_csrf` cookie on state-changing requests.

**When to use:** Registered on the full app or `/api/v1` scope; exempts GET, HEAD, OPTIONS.

**Example (skeleton):**
```rust
// Source: actix-web middleware docs — https://actix.rs/docs/middleware/
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use std::future::{Future, Ready, ready};
use std::pin::Pin;

pub struct CsrfMiddleware;

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = CsrfMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, ()>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfMiddlewareService { service }))
    }
}

pub struct CsrfMiddlewareService<S> { service: S }

const CSRF_SAFE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    // ... poll_ready delegates to inner service ...

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().as_str().to_uppercase();
        if CSRF_SAFE_METHODS.contains(&method.as_str()) {
            return Box::pin(self.service.call(req));
        }

        // Read CSRF cookie
        let cookie_token = req.cookie("axiam_csrf")
            .map(|c| c.value().to_owned());

        // Read X-CSRF-Token header
        let header_token = req.headers()
            .get("X-CSRF-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        match (cookie_token, header_token) {
            (Some(cookie), Some(header)) if subtle::ConstantTimeEq::ct_eq(
                cookie.as_bytes(), header.as_bytes()
            ).into() => {
                Box::pin(self.service.call(req))
            }
            _ => {
                let err = AxiamError::AuthenticationFailed {
                    reason: "CSRF validation failed".into(),
                };
                Box::pin(async move {
                    Err(actix_web::Error::from(AxiamApiError(err)))
                })
            }
        }
    }
}
```

**Important:** Use constant-time comparison (`subtle` crate, already in workspace) to prevent timing attacks on CSRF token comparison.

### Pattern 5: CSRF Token Generation

**What:** Generate a cryptographically random 32-byte token encoded as hex. Issue on login and on refresh.

**Example:**
```rust
// Source: rand 0.9.x docs
use rand::Rng;

fn generate_csrf_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}
```

Note: `rand::rng()` is the rand 0.9 API (replaces `thread_rng()` from 0.8). The workspace uses rand 0.9.2.

### Pattern 6: GET /api/v1/auth/me Handler

**What:** New handler that returns authenticated user info from JWT claims. Called by frontend on app init to rehydrate auth state (D-11).

**When to use:** Frontend `useEffect` on app mount.

**Example:**
```rust
// Source: existing UserResponse pattern from users.rs
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MeResponse {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    pub username: String,    // fetched from DB or stored in JWT claims
    pub email: String,
}

pub async fn me<C: Connection>(
    user: AuthenticatedUser,
    user_repo: web::Data<SurrealUserRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let u = user_repo.get_by_id(user.tenant_id, user.user_id).await?;
    Ok(HttpResponse::Ok().json(MeResponse {
        user_id: user.user_id,
        tenant_id: user.tenant_id,
        org_id: user.org_id,
        username: u.username,
        email: u.email,
    }))
}
```

Alternative (no DB call): store username/email in JWT claims. But current JWT claims only store `sub`, `tenant_id`, `org_id` — a DB call is needed. This is consistent with the current `AuthenticatedUser` pattern.

### Pattern 7: Frontend Auth Refactor

**What:** Remove sessionStorage, remove Authorization header, add `withCredentials: true`, inject CSRF token.

**When to use:** `frontend/src/lib/api.ts` and `frontend/src/stores/auth.ts`.

**Example (api.ts after refactor):**
```typescript
// Source: axios docs — withCredentials for cross-origin cookie sending
import axios from "axios";
import { useAuthStore } from "@/stores/auth";

const api = axios.create({
  baseURL: "/",
  headers: { "Content-Type": "application/json" },
  withCredentials: true,   // send cookies on all requests
});

// Read CSRF token from cookie (set by server, JS-readable)
function getCsrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)axiam_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// Request interceptor: inject CSRF token header (no Authorization header)
api.interceptors.request.use((config) => {
  const csrf = getCsrfToken();
  if (csrf && config.headers) {
    config.headers["X-CSRF-Token"] = csrf;
  }
  return config;
});

// Response interceptor: on 401, call /api/v1/auth/me; if still fails, redirect to login
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    // ... silent refresh: POST /auth/refresh (browser sends cookie automatically)
    // ... if refresh fails: clearAuth() + redirect to login
  }
);
```

**Example (auth.ts after refactor):**
```typescript
// Remove: persist middleware, createJSONStorage, sessionStorage
// Remove: accessToken field, setTokens (token-related), updateAccessToken
// Keep: user, isAuthenticated, tenantSlug, orgSlug in memory
import { create } from "zustand";

interface AuthState {
  user: AuthUser | null;
  tenantSlug: string | null;
  orgSlug: string | null;
  isAuthenticated: boolean;
}

interface AuthActions {
  setUser: (user: AuthUser) => void;
  clearAuth: () => void;
  setTenantContext: (tenantSlug: string, orgSlug: string) => void;
}

export const useAuthStore = create<AuthState & AuthActions>()((set) => ({
  user: null, tenantSlug: null, orgSlug: null, isAuthenticated: false,
  setUser: (user) => set({ user, isAuthenticated: true }),
  clearAuth: () => set({ user: null, tenantSlug: null, orgSlug: null, isAuthenticated: false }),
  setTenantContext: (tenantSlug, orgSlug) => set({ tenantSlug, orgSlug }),
}));
```

### Pattern 8: App Initialization — /me Rehydration

**What:** On frontend app mount, call `GET /api/v1/auth/me`. On 200, populate store. On 401, redirect to login.

**Example:**
```typescript
// In App.tsx or a top-level AuthGuard component
useEffect(() => {
  api.get("/api/v1/auth/me")
    .then((res) => {
      store.setUser(res.data.user);
    })
    .catch(() => {
      // 401 = no valid session; redirect handled by response interceptor
    });
}, []);
```

### Pattern 9: Integration Test Cookie Jar

**What:** Actix-web's `test::TestRequest` does not automatically manage cookies between requests. Extract `Set-Cookie` headers from login response and inject them into subsequent requests.

**When to use:** auth_test.rs and all tests that require an authenticated request.

**Example:**
```rust
// Source: actix-web test module docs
use actix_web::test;

// Login and extract cookies
let req = test::TestRequest::post()
    .uri("/auth/login")
    .set_json(/* login body */)
    .to_request();
let resp = test::call_service(&app, req).await;
assert_eq!(resp.status().as_u16(), 200);

// Collect Set-Cookie headers into a Vec<String>
let cookies: Vec<String> = resp.headers()
    .get_all(actix_web::http::header::SET_COOKIE)
    .map(|v| v.to_str().unwrap().to_owned())
    .collect();

// Also extract CSRF token from cookie (for use in X-CSRF-Token header)
let csrf_token = cookies.iter()
    .find(|c| c.starts_with("axiam_csrf="))
    .and_then(|c| c.split('=').nth(1))
    .and_then(|v| v.split(';').next())
    .unwrap();

// Use cookies in subsequent requests
let req = test::TestRequest::post()
    .uri("/some/endpoint")
    .insert_header(("Cookie", cookies.join("; ")))
    .insert_header(("X-CSRF-Token", csrf_token))
    .set_json(/* body */)
    .to_request();
```

### Anti-Patterns to Avoid

- **Setting `Domain` attribute on cookies:** Makes cookies accessible to subdomains. Omit entirely (D-08).
- **Using `httpOnly` on CSRF cookie:** Prevents JavaScript from reading it, defeating double-submit pattern. CSRF cookie must be JS-readable (D-07).
- **Using per-request CSRF rotation:** Creates race conditions when SPA fires concurrent requests (D-02 explicitly prohibits this).
- **Using a shared CSRF middleware secret key:** Adds key management complexity without security benefit when using random tokens (D-01).
- **Mutable authorization header extractor:** Do not remove Bearer header support from `extractors/auth.rs` entirely — device auth (`/auth/device`) and service-to-service calls still use JWT in Authorization header. The extractor must try cookie first, then header.
- **Setting `SameSite=Strict` and calling it CSRF-safe without validation:** SameSite alone is not sufficient when the application has same-site requests from other subdomain origins or when older browsers don't support it. Double-submit adds the defense-in-depth layer.
- **Not scoping refresh cookie to exact path:** If refresh cookie is scoped to `/api/v1/auth/` instead of `/api/v1/auth/refresh`, it is sent on all auth endpoints, widening the attack surface.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cookie attribute setting | Custom header strings like `Set-Cookie: name=val; HttpOnly; ...` | `actix_web::cookie::Cookie::build()` | Builder handles RFC 6265 escaping, `make_removal()` for clearing |
| Constant-time comparison | `==` on CSRF tokens | `subtle::ConstantTimeEq` | Timing-safe; `subtle` already in workspace |
| CSRF random token | UUID v4 | `rand::rng().random::<[u8; 32]>()` + hex | 256-bit entropy; UUID is only 122 bits and has structure |
| Cookie parsing in tests | Custom string-split logic | Standard `Set-Cookie` header extraction pattern (see Pattern 9) | Prevents bugs in test setup that mask real failures |

**Key insight:** actix-web 4 exposes the full `cookie` 0.18 API directly. There is no need to add `cookie` as a separate workspace dependency — use `use actix_web::cookie::{Cookie, SameSite}` and `use actix_web::cookie::time::Duration`.

---

## Common Pitfalls

### Pitfall 1: Refresh Cookie Path Mismatch on Logout

**What goes wrong:** Logout endpoint sets removal cookie for `axiam_refresh` without the `Path=/api/v1/auth/refresh` attribute. Browser ignores the removal because the cookie paths don't match.

**Why it happens:** Developers often forget that cookie removal requires matching `Path`, `Domain`, and `Secure` attributes. `make_removal()` only sets `Max-Age=0` and `Expires` — you still must set the path.

**How to avoid:** Always construct removal cookies with `.path("/api/v1/auth/refresh")` to mirror the creation path.

**Warning signs:** Browser DevTools shows `axiam_refresh` cookie still present after logout.

### Pitfall 2: Audit Middleware Does Not Find JWT in Cookie

**What goes wrong:** The audit middleware in `axiam-audit/src/middleware.rs` (`extract_or_cache_user_info`) reads only the `Authorization: Bearer` header. After the migration, authenticated requests no longer carry this header, so audit entries are logged with `actor_type: System` and nil UUIDs.

**Why it happens:** Audit middleware has its own JWT extraction code (lines 183-207 of middleware.rs) that is not shared with `extractors/auth.rs`.

**How to avoid:** Update `extract_or_cache_user_info` in the audit middleware to also check the `axiam_access` cookie, using the same priority (cookie first, then header).

**Warning signs:** All audit log entries after login show `actor_id: 00000000-0000-0000-0000-000000000000`.

### Pitfall 3: Vite Dev Proxy Loses Cookies

**What goes wrong:** Local development: `withCredentials: true` works in production (same origin), but in dev the Vite proxy at `localhost:5173` forwards requests to `localhost:8080`. The `Secure` flag on cookies fails because localhost is not HTTPS.

**Why it happens:** `Secure` flag cookies are not sent over plain HTTP, even on localhost.

**How to avoid:** One of:
a) Conditionally set `Secure` based on whether the connection is HTTPS (check `AXIAM_DEV_MODE` env var). In dev mode, omit `Secure`. This is a common dev/prod config split.
b) Use `actix-web`'s `HttpServer::bind_rustls()` for local HTTPS.
c) Easier: configure a cookie `Secure` setting in `AuthConfig` that defaults to `true` but can be set to `false` via env var for dev.

**Warning signs:** Login appears to succeed (200 response with Set-Cookie headers) but subsequent authenticated requests return 401, because the browser rejected the Secure cookie.

**Recommended approach:** Add `cookie_secure: bool` field to `AuthConfig` (defaults `true`), settable via `AXIAM__AUTH__COOKIE_SECURE=false` in dev. Update docker-compose.dev.yml to set this env var.

### Pitfall 4: Refresh Endpoint Needs tenant_id / org_id from Cookie, Not Body

**What goes wrong:** Current `RefreshRequest` takes `tenant_id` and `org_id` from the JSON body. With cookie-based auth, the client no longer has these values (the JWT is httpOnly). The refresh endpoint needs to extract them from the refresh token cookie (JWT claims contain tenant_id and org_id).

**Why it happens:** The existing `RefreshInput` struct in `axiam-auth/src/service.rs` requires `tenant_id` and `org_id`.

**How to avoid:** Change the refresh handler to: (1) read `axiam_refresh` cookie value, (2) decode the refresh token to extract tenant_id/org_id claims (or pass them through `axiam_auth::AuthService::refresh()` which already does token lookup), (3) remove tenant_id/org_id from the JSON body. The `RefreshRequest` body can be empty or removed entirely.

**Warning signs:** Refresh endpoint returns 400 because `tenant_id` is missing from request body, or the frontend cannot send it because it never received it.

### Pitfall 5: LoginPage.tsx Uses tenant_slug / org_slug (Not UUIDs)

**What goes wrong:** The backend `LoginRequest` currently takes `tenant_id: Uuid` and `org_id: Uuid`. But `LoginPage.tsx` sends `tenant_slug` and `org_slug` (slugs, not UUIDs). The frontend has always been inconsistent with the backend.

**Why it happens:** The frontend UI collects human-readable slugs; UUIDs are not user-facing. The current frontend code and backend are not fully wired up yet.

**How to avoid:** The login handler must either: (a) accept slugs and resolve them to UUIDs internally (better UX), or (b) document that login still requires UUIDs. This is already the current behavior, so the cookie migration does not need to fix this mismatch — but do not break it further.

### Pitfall 6: CSRF Validation Breaks Login and Refresh Endpoints

**What goes wrong:** CSRF middleware validates `X-CSRF-Token` on all POST requests. But `/auth/login` is the endpoint that ISSUES the first CSRF token — the browser has no token yet. Similarly, `/auth/refresh` must be exempt (the CSRF cookie may have expired along with the access token).

**Why it happens:** Blanket POST validation without exempting token-issuance endpoints.

**How to avoid:** Exempt specific paths from CSRF validation:
- `/auth/login` — pre-authentication, no CSRF token exists yet
- `/auth/refresh` — token rotation endpoint; protected instead by the httpOnly refresh cookie being inaccessible to JS
- `/auth/mfa/verify`, `/auth/mfa/setup/enroll`, `/auth/mfa/setup/confirm` — these are continuation-of-login flows before a session CSRF token exists
- `/auth/device` — machine-to-machine, no browser session

**Warning signs:** MFA flows return 401/403 CSRF validation errors during login.

### Pitfall 7: Test Setup Sending Wrong Credentials

**What goes wrong:** Existing integration tests (auth_test.rs) read `access_token` and `refresh_token` from the JSON body and use them in `Authorization: Bearer` headers. After migration, these fields no longer exist in the body — tests will panic on `unwrap()`.

**Why it happens:** Tests are tightly coupled to the old response shape.

**How to avoid:** Per D-16, update all integration tests to: (1) parse `Set-Cookie` from login response, (2) carry cookies forward in subsequent requests, (3) extract and inject CSRF token for state-changing requests. This is a comprehensive test rewrite.

---

## Code Examples

### Complete Login Handler Change (before → after)

```rust
// BEFORE: LoginSuccessResponse includes tokens in body
// AFTER:
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginSuccessResponse {
    // access_token: REMOVED — delivered via Set-Cookie
    // refresh_token: REMOVED — delivered via Set-Cookie
    pub user: LoginUser,
    pub session_id: Uuid,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct LoginUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
}

// In the login success branch:
axiam_auth::LoginResult::Success(out) => {
    let auth_config = req.app_data::<web::Data<AuthConfig>>().unwrap();
    let csrf_token = generate_csrf_token();

    Ok(HttpResponse::Ok()
        .cookie(access_cookie(&out.access_token, auth_config.access_token_lifetime_secs))
        .cookie(refresh_cookie(&out.refresh_token, auth_config.refresh_token_lifetime_secs))
        .cookie(csrf_cookie(&csrf_token))
        .json(LoginSuccessResponse {
            user: LoginUser {
                id: out.user_id,     // need user_id in LoginOutput — check axiam-auth/src/service.rs
                username: out.username,
                email: out.email,
            },
            session_id: out.session_id,
            expires_in: out.expires_in,
        }))
}
```

### CSRF Exempt Path List for Middleware Registration

```rust
// In server.rs middleware registration or in CsrfMiddleware itself:
const CSRF_EXEMPT_PATHS: &[&str] = &[
    "/auth/login",
    "/auth/refresh",
    "/auth/mfa/verify",
    "/auth/mfa/setup/enroll",
    "/auth/mfa/setup/confirm",
    "/auth/device",
    "/auth/register",
    "/oauth2/token",          // machine-to-machine
    "/oauth2/authorize",      // OAuth2 flow
    "/health",
    "/ready",
];
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| localStorage / sessionStorage for JWT | httpOnly cookie | OWASP ASVS 3.4.2-3.4.5 (current) | sessionStorage tokens are XSS-readable; httpOnly cookies are not |
| Authorization: Bearer header from JS | Browser sends cookie automatically | Industry standard post-2018 | No JS access to token; impossible to steal via XSS |
| No CSRF protection needed (SameSite) | SameSite + double-submit in depth | SameSite=Strict added ~2020, not universally trusted | Defense-in-depth per OWASP |

**Deprecated/outdated:**
- `sessionStorage` for auth tokens: XSS vulnerable — any injected script can read it
- `localStorage` for tokens: Same issue, plus persists across sessions
- Sending refresh token in JSON body: Token is JS-readable on client side

---

## Open Questions

1. **`LoginOutput` struct in `axiam-auth` — does it include `user_id`, `username`, `email`?**
   - What we know: `LoginSuccessResponse` in the current handler uses `out.access_token`, `out.refresh_token`, `out.session_id`, `out.expires_in`. The user identity must come from somewhere.
   - What's unclear: Whether `LoginOutput` already carries user fields beyond `session_id`/`expires_in`, or whether the login handler needs to do a separate user lookup.
   - Recommendation: Planner should verify `axiam-auth/src/service.rs` `LoginOutput` struct fields before writing the handler task.

2. **`RefreshInput` — how to eliminate tenant_id/org_id from body**
   - What we know: `RefreshInput` currently requires `tenant_id`, `org_id`, `raw_refresh_token`. With cookie auth, the frontend cannot supply UUIDs.
   - What's unclear: Does `AuthService::refresh()` internally decode the refresh token to extract tenant info, or does it rely on caller-provided IDs?
   - Recommendation: Planner should check `axiam-auth/src/service.rs` `refresh()` method to determine if `tenant_id`/`org_id` can be derived from the token itself.

3. **`axiam_csrf` cookie: should it expire with the access token?**
   - What we know: D-09 says cookie Max-Age matches JWT TTL. The CSRF cookie could be a session cookie (no Max-Age, cleared on browser close) or match access token TTL.
   - What's unclear: If CSRF cookie expires but access token cookie has not yet, the next request fails CSRF validation even though the session is still valid.
   - Recommendation: Set CSRF cookie Max-Age to match the access token TTL (900s). Refresh endpoint must issue a new CSRF token alongside the new access token cookie.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `rand` (workspace) | CSRF token generation | Yes | 0.9.2 | — |
| `hex` (workspace) | CSRF token encoding | Yes | 0.4.x | — |
| `subtle` (workspace) | Constant-time CSRF comparison | Yes | 2.x | — |
| `actix-web` `cookie` module | Cookie builder | Yes | 4.13.0 | — |
| Vite proxy dev environment | Local dev with cookies | Yes | Configured | Need `cookie_secure: false` in dev mode |
| `axiam-auth` `LoginOutput` user fields | D-10 response body | Unknown — verify | — | Add DB lookup in handler |

**Missing dependencies with no fallback:** None — all required crates are already in the workspace.

**Missing dependencies with fallback:**
- `LoginOutput` user fields: if not present, add a `user_repo.get_by_id()` call in the login handler (small DB roundtrip; acceptable).

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `#[actix_rt::test]` (actix-rt 2.x) + in-memory SurrealDB |
| Config file | `crates/axiam-api-rest/Cargo.toml` dev-dependencies |
| Quick run command | `cargo test -p axiam-api-rest --test auth_test` |
| Full suite command | `cargo test -p axiam-api-rest` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-1 AC1 | Access token NOT in response body, IS in Set-Cookie with httpOnly | integration | `cargo test -p axiam-api-rest --test auth_test -- login_sets_httponly_access_cookie` | ❌ Wave 0 |
| REQ-1 AC2 | Refresh token Set-Cookie path-scoped to /api/v1/auth/refresh | integration | `cargo test -p axiam-api-rest --test auth_test -- login_sets_pathscoped_refresh_cookie` | ❌ Wave 0 |
| REQ-1 AC3 | Frontend: no sessionStorage reads in auth flow | manual | — | manual-only |
| REQ-1 AC4 | Frontend: Axios uses `withCredentials: true`, no Authorization header | manual | — | manual-only |
| REQ-1 AC5 | POST to protected endpoint without CSRF token returns 401 | integration | `cargo test -p axiam-api-rest --test auth_test -- csrf_missing_header_returns_401` | ❌ Wave 0 |
| REQ-1 AC6 | Logout clears all three cookies (Max-Age=0) | integration | `cargo test -p axiam-api-rest --test auth_test -- logout_clears_cookies` | ❌ Wave 0 |
| REQ-1 AC7 | Refresh endpoint reads refresh cookie, returns new access cookie | integration | `cargo test -p axiam-api-rest --test auth_test -- refresh_uses_cookie_returns_new_access_cookie` | ❌ Wave 0 |
| REQ-1 AC8 | All existing integration tests pass after migration | integration (suite) | `cargo test -p axiam-api-rest` | ❌ Wave 0 (all require rewrite) |

### Sampling Rate
- **Per task commit:** `cargo test -p axiam-api-rest --test auth_test`
- **Per wave merge:** `cargo test -p axiam-api-rest`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] New test functions in `crates/axiam-api-rest/tests/auth_test.rs` — covers all REQ-1 ACs listed above
- [ ] Existing tests in `auth_test.rs` require rewrite: `login_with_valid_credentials_returns_200`, `logout_returns_204`, `refresh_returns_new_tokens`, `mfa_setup_full_flow_returns_tokens`
- [ ] CSRF-related test helpers (cookie jar extraction utility function)

---

## Project Constraints (from CLAUDE.md)

| Directive | Impact on This Phase |
|-----------|---------------------|
| Rust edition 2024, MSRV 1.93 — native async fn in traits | CSRF middleware uses `Pin<Box<dyn Future>>` (standard Actix-Web pattern); no `async_trait` |
| `rustfmt.toml` max_width = 100 | Cookie builder chains may need line breaks |
| `cargo clippy -D warnings` on all changed crates | Run before committing; check for unused imports in modified handler |
| Build/check only specific crates (`-p`), never full workspace | Use `cargo check -p axiam-api-rest` and `cargo test -p axiam-api-rest` |
| Signed commits before proceeding to next task | Each task commit must be signed |
| Frontend uses React + TypeScript (Vite) | Remove `persist` from zustand; axios `withCredentials`; no localStorage/sessionStorage |
| `SurrealValue` derive for DB row structs | Not affected by this phase (no DB schema changes) |

---

## Sources

### Primary (HIGH confidence)
- actix-web 4.13.0 resolved from `Cargo.lock` — cookie builder API confirmed
- `crates/axiam-api-rest/src/handlers/auth.rs` — existing handler shapes that must change
- `crates/axiam-api-rest/src/extractors/auth.rs` — extractor that must gain cookie support
- `crates/axiam-audit/src/middleware.rs` — audit middleware that must be updated to read cookie
- `crates/axiam-api-rest/tests/auth_test.rs` — existing tests that must all be rewritten
- `frontend/src/stores/auth.ts` — store that must be stripped to memory-only
- `frontend/src/lib/api.ts` — Axios client that must be refactored
- Workspace `Cargo.toml` — confirms all required crates (rand 0.9, hex, subtle, actix-web) already present

### Secondary (MEDIUM confidence)
- [actix-web 4 HttpResponseBuilder cookie docs](https://docs.rs/actix-web/4.3.1/actix_web/struct.HttpResponseBuilder.html) — `cookie()` method, `make_removal()` pattern
- [actix-web Cookie builder docs](https://docs.rs/actix-web/latest/actix_web/cookie/struct.Cookie.html) — confirmed `http_only()`, `secure()`, `same_site()`, `path()`, `max_age()` builder methods
- [actix-web middleware docs](https://actix.rs/docs/middleware/) — Transform + Service pattern confirmed

### Tertiary (LOW confidence)
- [actix-csrf crate](https://crates.io/crates/actix-csrf) — reviewed and rejected (too opinionated for the decided pattern)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crates verified in Cargo.lock; actix-web cookie API confirmed from docs
- Architecture: HIGH — existing code read directly; patterns derived from actix-web 4 docs
- Pitfalls: HIGH — derived from direct code analysis (audit middleware, LoginPage.tsx slug mismatch, refresh body schema)

**Research date:** 2026-03-30
**Valid until:** 2026-06-30 (actix-web 4.x is stable; cookie API unlikely to change)
