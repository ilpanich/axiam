# Phase 2: Security Headers & Rate Limiting - Research

**Researched:** 2026-04-04
**Domain:** Actix-Web middleware, Tower layers, nginx config, React admin UI
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Rate Limiting Strategy:**
- D-01: In-memory rate limiting using `actix-governor` crate with in-memory store. No distributed/Redis dependency. Each pod tracks its own limits — sufficient for MVP beta.
- D-02: Client identification via `X-Forwarded-For` header (nginx already sets this). Fall back to peer address if header missing.
- D-03: Rate limit error response: HTTP 429 with JSON body `{"error": "rate_limit_exceeded", "retry_after": N}` and `Retry-After` header. Consistent with AXIAM's existing JSON error format.
- D-04: Rate limits configurable via environment variables (e.g., `AXIAM_RATE_LIMIT__LOGIN_PER_MIN=10`) with REQ-3 values as defaults: login 10/min, register 5/min, oauth2/token 20/min, password-reset 3/min.

**CSP Policy for React SPA:**
- D-05: `script-src 'self'` — strict, no inline scripts, no eval. Vite bundles are external files so this works out of the box.
- D-06: `style-src 'self' 'unsafe-inline'` — allows inline styles for Tailwind CSS and React style props.
- D-07: CSP applied on nginx only (frontend HTML/asset responses). Backend API returns JSON where CSP is irrelevant.

**Lockout Admin UI:**
- D-08: 'Locked' badge/chip on user list table for locked users, plus a filter to show only locked users. Integrated into existing Users page — no dedicated locked-users page.
- D-09: Manual unlock button for admins. Resets `failed_login_attempts` to 0 and clears `locked_until`.

**gRPC Brute-Force Protection:**
- D-10: Custom Tower Layer wrapping the `governor` crate's in-memory rate limiter. Same algorithm as REST for consistency.
- D-11: gRPC rate limits configurable via environment variables, same pattern as REST rate limits.

### Claude's Discretion

- Backend security headers middleware implementation details (single middleware vs per-header)
- Specific `Permissions-Policy` directive values
- HSTS preload decision (include or omit `preload` directive)
- gRPC client identity extraction method (metadata vs peer address)
- Default gRPC rate limit values (should be generous for service-mesh authz patterns)
- Nginx CSP directive details beyond script-src and style-src (img-src, connect-src, font-src, etc.)

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-2 | Backend middleware adds X-Content-Type-Options, X-Frame-Options, Referrer-Policy; nginx adds CSP, HSTS, Permissions-Policy; CSP restricts scripts to self-origin; HSTS with max-age=31536000 | Security headers values verified from OWASP Cheat Sheet; middleware pattern identified from CsrfMiddleware; nginx config gaps identified |
| REQ-3 | Rate limiting on 4 auth endpoints; account lockout after 5 failures (15-min cooldown); lockout visible in admin UI; gRPC brute-force protection | actix-governor 0.10.0 API verified; tower-governor 0.8.0 tonic integration pattern verified; lockout logic already exists in AuthService; frontend Users page already has StatusBadge component |
</phase_requirements>

---

## Summary

Phase 2 adds security headers and rate limiting to a Rust/Actix-Web IAM system. The backend already has a production-quality `CsrfMiddleware` that serves as the exact template for the new `SecurityHeadersMiddleware`. The account lockout domain logic (`record_failed_login`, `reset_failed_logins`) is already complete in `axiam-auth`; Phase 2 only needs to expose the lockout status in the admin UI and add a REST unlock endpoint. The nginx config already has four security headers but is missing CSP, HSTS, and Permissions-Policy — a targeted config edit.

The rate limiting library (`actix-governor 0.10.0`) is mature and supports per-scope configuration with custom key extractors (needed for X-Forwarded-For). The gRPC side uses `tower-governor 0.8.0` with an IP-injecting interceptor — the crate has a documented tonic integration example. Both crates wrap the same underlying `governor` crate, ensuring consistent token-bucket behaviour.

The critical implementation concern is that actix-governor requires per-endpoint Governor instances sharing separate in-memory stores. Each rate-limited endpoint (login, register, oauth2/token, password-reset) needs its own `GovernorConfig` built from its own rate limit parameters. Reusing a single config across endpoints would merge their counters.

**Primary recommendation:** Implement SecurityHeadersMiddleware following the CsrfMiddleware pattern; add per-endpoint actix-governor wrappers with a custom XForwardedForKeyExtractor; add tower-governor as a layer in the gRPC server via an IP-injecting interceptor; add unlock endpoint and locked filter to the Users page.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| actix-governor | 0.10.0 | Rate limiting middleware for Actix-Web | Direct Actix-Web integration; wraps `governor` crate; supports custom key extractors |
| governor | 0.10.4 | Token-bucket rate limiting core | Used by both actix-governor and tower-governor; single algorithm, shared semantics |
| tower-governor | 0.8.0 | Tower layer for gRPC (tonic) rate limiting | Official tower-governor crate with tonic feature; documented integration example |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| actix-web | 4 (workspace) | Middleware framework | Already in workspace — SecurityHeadersMiddleware and Governor middleware |
| tonic | 0.14 (workspace) | gRPC server | Already in workspace — add GovernorLayer via Server::builder().layer() |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| actix-governor | actix-limitation (Redis) | D-01 locks in-memory; actix-governor is simpler and has no Redis dep |
| tower-governor | hand-rolled Tower middleware | D-10 locks tower-governor; avoids reimplementing token-bucket correctly |

**Installation (new dependencies to add):**

```bash
# In crates/axiam-api-rest/Cargo.toml
actix-governor = "0.10"

# In crates/axiam-api-grpc/Cargo.toml
tower-governor = { version = "0.8", features = ["tonic"] }
governor = "0.10"
tower = { version = "0.5", features = ["util"] }

# In workspace Cargo.toml [workspace.dependencies]
actix-governor = "0.10"
tower-governor = { version = "0.8", features = ["tonic"] }
governor = "0.10"
tower = { version = "0.5", features = ["util"] }
```

**Version verification (confirmed 2026-04-04):**
- actix-governor: `0.10.0` (crates.io)
- governor: `0.10.4` (crates.io)
- tower-governor: `0.8.0` (crates.io)
- tower: `0.5.3` (crates.io)

---

## Architecture Patterns

### Recommended Project Structure

New files this phase creates:

```
crates/axiam-api-rest/src/
├── middleware/
│   ├── csrf.rs          # existing — template to follow
│   └── security_headers.rs   # NEW — SecurityHeadersMiddleware
├── config/
│   └── rate_limit.rs    # NEW — RateLimitConfig (env var driven)
├── handlers/
│   └── users.rs         # MODIFIED — add unlock handler
tests/
├── security_headers_test.rs  # NEW
└── rate_limit_test.rs        # NEW

crates/axiam-api-grpc/src/
├── middleware/
│   └── rate_limit.rs    # NEW — gRPC GovernorLayer setup + interceptor
└── server.rs            # MODIFIED — add layer

docker/
└── nginx.conf           # MODIFIED — add CSP, HSTS, Permissions-Policy
```

### Pattern 1: SecurityHeadersMiddleware (follow CsrfMiddleware exactly)

**What:** Actix-Web Transform + Service pair that appends headers to every response.
**When to use:** Global `.wrap()` in App builder — all responses get headers without per-handler code.

The middleware does NOT need path inspection or conditional logic. It runs on the response path and calls `res.headers_mut().insert(...)` for each header before returning.

```rust
// Source: modelled on crates/axiam-api-rest/src/middleware/csrf.rs
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderName, HeaderValue};

pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(SecurityHeadersService { inner: service }))
    }
}

pub struct SecurityHeadersService<S> {
    inner: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();
            headers.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                HeaderName::from_static("x-frame-options"),
                HeaderValue::from_static("DENY"),
            );
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            Ok(res)
        })
    }
}
```

**Note on X-Frame-Options:** REQ-2 specifies `DENY`. Nginx currently has `SAMEORIGIN` — nginx must be updated to `DENY` to match backend policy.

### Pattern 2: actix-governor Per-Endpoint Rate Limiting

**What:** Each rate-limited scope gets its own `GovernorConfig` and its own `Governor` middleware instance with a custom `XForwardedForKeyExtractor`.
**When to use:** Per-scope because each endpoint has different limits (10/min, 5/min, 20/min, 3/min).

**Critical rule:** Never share a `GovernorConfig` between scopes with different rate limits. Each must be built independently.

```rust
// Source: actix-governor 0.10.0 docs
use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor};
use actix_web::dev::ServiceRequest;
use std::net::IpAddr;

/// Extract rate-limit key from X-Forwarded-For; fall back to peer IP.
#[derive(Clone)]
pub struct XForwardedForKeyExtractor;

impl KeyExtractor for XForwardedForKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = actix_web::Error;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        // X-Forwarded-For is set by nginx (proxy_set_header in nginx.conf)
        if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
            if let Ok(val) = forwarded_for.to_str() {
                // First IP in the chain is the client
                if let Some(first) = val.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return Ok(ip);
                    }
                }
            }
        }
        // Fallback to peer address
        req.peer_addr()
            .map(|addr| addr.ip())
            .ok_or_else(|| actix_web::error::ErrorInternalServerError("no peer addr"))
    }

    fn exceed_rate_limit_response(
        &self,
        negative: &actix_governor::governor::clock::QuantaInstant,
        mut response: actix_web::HttpResponseBuilder,
    ) -> actix_web::HttpResponse {
        // negative.wait_time_from(...).as_secs() gives retry_after
        use actix_governor::governor::clock::{Clock, DefaultClock};
        let wait_secs = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type("application/json")
            .insert_header(("Retry-After", wait_secs.to_string()))
            .body(format!(
                r#"{{"error":"rate_limit_exceeded","retry_after":{}}}"#,
                wait_secs
            ))
    }
}

// Building per-endpoint configs (from RateLimitConfig env vars):
fn build_login_governor(cfg: &RateLimitConfig) -> Governor<XForwardedForKeyExtractor, ...> {
    let config = GovernorConfigBuilder::default()
        .per_second(60 / cfg.login_per_min)   // replenishment interval
        .burst_size(cfg.login_per_min)          // allow burst equal to limit
        .key_extractor(XForwardedForKeyExtractor)
        .finish()
        .expect("valid governor config");
    Governor::new(&config)
}
```

**Route registration pattern (in server.rs):**

```rust
// Each /auth/login scope gets its own governor
web::scope("/auth")
    .service(
        web::resource("/login")
            .wrap(build_login_governor(&rate_cfg))
            .route(web::post().to(handlers::auth::login::<C>))
    )
    .service(
        web::resource("/reset")
            .wrap(build_password_reset_governor(&rate_cfg))
            .route(web::post().to(handlers::password_reset::request_reset::<C>))
    )
    // ...
```

**Note:** The existing `/auth` scope wraps `CsrfMiddleware`. Rate limiting wraps individual resources, not the whole scope — this avoids CSRF middleware ordering issues.

### Pattern 3: RateLimitConfig (env var driven, per D-04)

```rust
// crates/axiam-api-rest/src/config/rate_limit.rs
use serde::Deserialize;

/// Rate limit configuration loaded from environment variables.
/// Prefix: AXIAM_RATE_LIMIT__ (via `config` crate)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Max login requests per minute per IP (default: 10)
    pub login_per_min: u32,
    /// Max register requests per minute per IP (default: 5)
    pub register_per_min: u32,
    /// Max oauth2/token requests per minute per client (default: 20)
    pub token_per_min: u32,
    /// Max password-reset requests per minute per IP (default: 3)
    pub password_reset_per_min: u32,
    /// Max gRPC authz requests per second per IP (default: 100)
    pub grpc_authz_per_sec: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_per_min: 10,
            register_per_min: 5,
            token_per_min: 20,
            password_reset_per_min: 3,
            grpc_authz_per_sec: 100,  // generous for service-mesh
        }
    }
}
```

### Pattern 4: gRPC Tower GovernorLayer

**What:** An IP-injecting `InterceptorLayer` followed by a `GovernorLayer` stacked on the tonic `Server::builder()`.
**When to use:** gRPC server setup in `crates/axiam-api-grpc/src/server.rs`.

The `tower-governor` tonic example (confirmed in docs) uses this pattern:

```rust
// Source: tower-governor 0.8.0 tonic example
use tower_governor::{GovernorLayer, GovernorConfigBuilder, governor::state::keyed::DefaultKeyedStateStore};
use tower_governor::key_extractor::SmartIpKeyExtractor;
use tonic::transport::Server;

// The interceptor injects the client IP into request extensions
// so SmartIpKeyExtractor can find it
let governor_config = GovernorConfigBuilder::default()
    .per_second(grpc_cfg.grpc_authz_per_sec)
    .burst_size(grpc_cfg.grpc_authz_per_sec * 2)
    .use_headers()
    .finish()
    .expect("valid governor config");

let governor_layer = GovernorLayer {
    config: Arc::new(governor_config),
};

Server::builder()
    .layer(InterceptorLayer::new(ConnectInfoInterceptor))
    .layer(governor_layer)
    .add_service(authz_svc)
    .add_service(user_svc)
    .add_service(token_svc)
    .serve(addr)
    .await
```

**Client identity for gRPC (Claude's discretion — recommended):** Use `SmartIpKeyExtractor` from tower-governor with a `ConnectInfoInterceptor` that reads the peer address and injects it into the `forwarded` metadata header. This mirrors what nginx does for REST. Service-mesh environments typically propagate the real client IP via proxy headers.

**Default gRPC rate limits (Claude's discretion — recommended):** 100 req/sec with burst of 200. AuthZ checks in service-mesh patterns are high-frequency per-request calls from many services. These limits protect against runaway loops, not legitimate traffic.

### Pattern 5: Admin Unlock Endpoint

**What:** `POST /api/v1/users/{user_id}/unlock` — calls `reset_failed_logins` in AuthService.
**No new domain logic needed** — `reset_failed_logins` already exists in `AuthService`.

The handler needs:
- `AuthenticatedUser` extractor (admin check in Phase 3 — for now, any authenticated user)
- Call `user_repo.update(tenant_id, user_id, UpdateUser { failed_login_attempts: Some(0), locked_until: Some(None), last_failed_login_at: Some(None), ..Default::default() })`
- Return 200 with updated `UserResponse`

Route registration in `server.rs`:
```rust
web::resource("/users/{user_id}/unlock")
    .route(web::post().to(handlers::users::unlock::<C>))
```

The `UserResponse` struct currently omits `failed_login_attempts` and `locked_until`. These must be added so the frontend can display lock state. Add to `UserResponse`:
```rust
pub failed_login_attempts: u32,
pub locked_until: Option<DateTime<Utc>>,
pub is_locked: bool,   // computed: locked_until > now
```

### Pattern 6: Frontend Locked Badge + Filter

The existing `UsersPage.tsx` already has:
- `StatusBadge` component (handles `Active`, `Inactive`, `PendingVerification`)
- `DataTable` component accepting `Column<T>[]`
- `MfaBadge` inline component pattern (dark-mode chip, easy to replicate)

**Additions to `UsersPage.tsx`:**
1. `LockedBadge` component — matches `MfaBadge` pattern, amber/orange color scheme
2. A column in the DataTable for lock status (badge + unlock button if locked)
3. Filter state: `showOnlyLocked: boolean` — filters `users` array client-side before rendering
4. Unlock button calls `POST /api/v1/users/{id}/unlock`, then invalidates the `users` query via `queryClient.invalidateQueries`

**Note:** The `User` type in `frontend/src/services/users.ts` must be extended with `failed_login_attempts`, `locked_until`, and `is_locked` fields to match the updated `UserResponse`.

### Pattern 7: Nginx Security Headers

Current nginx.conf has four headers: `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection`, `Referrer-Policy`. Three problems:

1. `X-Frame-Options` must change from `SAMEORIGIN` to `DENY` (per REQ-2)
2. Missing: `Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy`
3. Headers must be **repeated in every `location` block** — nginx `add_header` in a child location block drops parent-context headers (this pattern already exists in the current config but must be extended)

**Complete nginx header set to add:**

```nginx
# Global context headers (existing, corrected + extended)
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'" always;
```

**Remove:** `X-XSS-Protection` — OWASP no longer recommends it (deprecated; can actually enable XSS in old browsers). Not in REQ-2.

**HSTS preload (Claude's discretion — recommended):** Omit `preload` for now. Preload requires submission to browser preload lists and cannot be easily reversed. For an MVP beta, `max-age=31536000; includeSubDomains` satisfies REQ-2 without the commitment overhead.

**CSP directives beyond D-05/D-06 (Claude's discretion — recommended):**
- `img-src 'self' data:` — allows base64 data URIs for avatars/icons common in React UI
- `font-src 'self'` — local fonts only; no CDN fonts
- `connect-src 'self'` — XHR/fetch to same origin only (API proxy is same origin)
- `frame-ancestors 'none'` — stronger than X-Frame-Options DENY; belt-and-suspenders
- `form-action 'self'` — prevents form hijacking to external origins
- `base-uri 'self'` — prevents base tag injection

**Permissions-Policy directives (Claude's discretion — recommended):** Disable browser features AXIAM does not use: `geolocation`, `camera`, `microphone`, `payment`, `usb`, `magnetometer`, `gyroscope`, `accelerometer`. All set to empty list `()` to deny all origins including self.

### Anti-Patterns to Avoid

- **Sharing GovernorConfig across endpoints:** Creates a merged rate limiter. Login at 10/min and register at 5/min would share one 10/min bucket. Build separate configs.
- **Wrapping the whole /auth scope with one Governor:** CsrfMiddleware already wraps the scope. Adding Governor at scope level conflicts with CSRF exemptions. Wrap individual resources instead.
- **Using `.map_into_right_body()` in SecurityHeadersMiddleware:** Not needed — unlike CsrfMiddleware, security headers middleware never short-circuits with an error response. Use simpler `ServiceResponse<B>` (no `EitherBody`) return type.
- **Repeating nginx headers without updating all location blocks:** nginx child location blocks shadow parent `add_header` directives. The existing config already handles this — ensure all three location blocks get the full updated header set.
- **Not updating `UserResponse` before the frontend work:** The frontend badge and filter depend on `is_locked`/`locked_until` from the API. Backend `UserResponse` update must be in an earlier wave than the frontend task.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Token-bucket rate limiting | Custom counter + TTL map | `actix-governor` / `governor` | Token-bucket is subtle: burst, replenishment, clock drift, concurrent access. governor has been validated extensively. |
| X-Forwarded-For parsing | Custom header parsing | Implement `KeyExtractor` with standard IP parsing | First-IP-in-chain semantics, IPv6 edge cases, trust chain issues. Use `IpAddr::parse()` on the trimmed first segment. |
| gRPC Tower rate limit layer | Custom `tower::Layer` + counter | `tower-governor` | tower-governor handles the layer/service wiring, backpressure, and integrates with governor's async-safe state. |
| Lockout logic | New failed-login counter | `AuthService::record_failed_login()` (already exists) | Already implemented with exponential backoff. Phase 2 only exposes the UI surface and unlock endpoint. |

**Key insight:** The lockout domain logic is complete. Phase 2 is primarily about (1) middleware plumbing and (2) UI surface area. There is no new lockout algorithm to write.

---

## Common Pitfalls

### Pitfall 1: nginx `add_header` Inheritance
**What goes wrong:** Adding new headers in the global nginx context but not repeating them in `location` blocks causes those headers to be missing from static asset responses and the index.html cache-control location.
**Why it happens:** nginx's `add_header` directive does not inherit across location contexts. Child blocks replace parent `add_header` sets entirely.
**How to avoid:** The existing nginx.conf already duplicates headers in each location block. When adding CSP, HSTS, and Permissions-Policy, add them to ALL four header blocks: the global context, the static assets location, the index.html location, and any future locations.
**Warning signs:** Headers present on `/` but missing on `/assets/main.js` in browser devtools.

### Pitfall 2: actix-governor Ordering vs CsrfMiddleware
**What goes wrong:** If a Governor middleware wraps the entire `/auth` scope (instead of individual routes), it runs before CsrfMiddleware exemption logic. A legitimate POST to `/auth/login` (CSRF-exempt) gets rate-limited before reaching the handler, which is acceptable, but a misconfigured scope could affect non-auth endpoints.
**Why it happens:** `.wrap()` middleware on a scope applies to all routes in that scope. The execution order is last-registered-first-executed (LIFO).
**How to avoid:** Apply rate-limiting Governor instances to individual `web::resource()` registrations, not to the `/auth` scope. This keeps rate limiting orthogonal to CsrfMiddleware.

### Pitfall 3: actix-governor `exceed_rate_limit_response` Signature
**What goes wrong:** The `exceed_rate_limit_response` method signature in actix-governor 0.10.0 uses `actix_governor::governor::clock::QuantaInstant` (from the re-exported governor crate), not a `NotUntil<QuantaInstant>`. The exact type depends on the governor version bundled with actix-governor.
**Why it happens:** The trait signature changed between actix-governor versions.
**How to avoid:** Check the exact method signature from the compiled docs (`cargo doc -p actix-governor`) rather than relying on external examples. The wait time calculation is `negative.wait_time_from(DefaultClock::default().now()).as_secs()`.

### Pitfall 4: governor `NonZeroU32` Requirements
**What goes wrong:** `GovernorConfigBuilder::per_second(0)` panics at runtime. Environment variable `AXIAM_RATE_LIMIT__LOGIN_PER_MIN=0` (misconfiguration) would cause startup panic.
**Why it happens:** governor uses `NonZeroU32` internally; zero is invalid.
**How to avoid:** Validate `RateLimitConfig` on startup — assert all values are >= 1. Consider wrapping in `NonZeroU32::new(val).unwrap_or(NonZeroU32::new(1).unwrap())` with a warning log.

### Pitfall 5: `UserResponse` Missing Lock Fields
**What goes wrong:** Frontend `User` type has no `is_locked` or `locked_until` field. Badge and filter silently show no locked users even when users are locked.
**Why it happens:** The current `UserResponse` was designed before lock visibility was a requirement. It maps from `User` but omits `failed_login_attempts` and `locked_until`.
**How to avoid:** Extend `UserResponse` in the backend first. Add `locked_until: Option<DateTime<Utc>>` and compute `is_locked: user.locked_until.map(|t| t > Utc::now()).unwrap_or(false)`. Update the TypeScript `User` type in `frontend/src/services/users.ts` to match.

### Pitfall 6: CSP Breaking API Proxy Calls
**What goes wrong:** `connect-src 'self'` blocks frontend XHR to `/api/v1/...` if the frontend's origin and the nginx proxy are on different origins in some deployment configurations.
**Why it happens:** If the React app is served from `https://dashboard.example.com` but the API proxy is at `https://api.example.com`, they are different origins and `connect-src 'self'` blocks API calls.
**How to avoid:** In the MVP Docker/dev setup, nginx proxies `/api` on the same origin — `connect-src 'self'` is correct. Document that multi-origin deployments would need `connect-src 'self' https://api.example.com`. For this phase, single-origin is the target.

---

## Code Examples

### Applying SecurityHeadersMiddleware globally

```rust
// Source: actix-web docs + CsrfMiddleware pattern from axiam-api-rest/src/server.rs
// In axiam-server/src/main.rs or wherever HttpServer::new is called
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;

HttpServer::new(move || {
    App::new()
        .wrap(SecurityHeadersMiddleware)     // outermost — applies to all responses
        .wrap(TracingLogger::default())
        // ... other middleware
})
```

### Rate limit config loading (consistent with AuthConfig pattern)

```rust
// In AppConfig struct (axiam-server/src/config.rs or equivalent)
#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(default)]
    auth: AuthConfig,
    #[serde(default)]
    rate_limit: RateLimitConfig,   // NEW
    // ...
}
```

Environment variable mapping via `config` crate:
- `AXIAM__RATE_LIMIT__LOGIN_PER_MIN=10` (double underscore for nesting)
- `AXIAM__RATE_LIMIT__REGISTER_PER_MIN=5`

**Note:** The existing pattern uses `AXIAM__` prefix (double underscore), not `AXIAM_RATE_LIMIT__` as written in D-04. Verify the actual env prefix used in `axiam-server/src/config.rs` — the locked decision says `AXIAM_RATE_LIMIT__LOGIN_PER_MIN` which implies a flat prefix without the workspace separator. Treat D-04 as specifying the env var name pattern; the exact crate config structure follows the existing `config` crate conventions.

### Frontend unlock mutation pattern

```typescript
// Source: existing UsersPage.tsx React Query pattern
const unlockMutation = useMutation({
  mutationFn: (userId: string) =>
    userService.unlock(userId),  // POST /api/v1/users/{id}/unlock
  onSuccess: () => {
    queryClient.invalidateQueries({ queryKey: ['users'] });
  },
});
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| actix-limitation (Redis) | actix-governor (in-memory) | actix-governor stable since 2022 | No Redis dep; simpler; locked by D-01 |
| X-XSS-Protection header | Remove it | OWASP deprecated 2023 | Do not add X-XSS-Protection; remove from nginx |
| Feature-Policy header | Permissions-Policy | Chrome 90+ (2021) | Use Permissions-Policy only; Feature-Policy is dead |
| HSTS with preload always | HSTS without preload for beta | Best practice | Preload is hard to reverse; omit until domain is stable |

**Deprecated/outdated:**
- `X-XSS-Protection`: Remove from nginx.conf (line 23, 35, 45). OWASP no longer recommends it; can enable XSS in IE. Not in REQ-2.
- `Feature-Policy`: Do not add; use `Permissions-Policy` instead.

---

## Open Questions

1. **Config prefix for rate limits**
   - What we know: D-04 specifies env var names like `AXIAM_RATE_LIMIT__LOGIN_PER_MIN=10`
   - What's unclear: The existing `config` crate setup in axiam-server uses `AXIAM__` double-underscore for struct nesting. `AXIAM_RATE_LIMIT__LOGIN_PER_MIN` implies a flat prefix style different from existing configs.
   - Recommendation: Read `axiam-server/src/config.rs` before implementing `RateLimitConfig`. Follow the exact same prefix pattern already established. If existing pattern is `AXIAM__AUTH__` then use `AXIAM__RATE_LIMIT__`. D-04's env var names are illustrative, not prescriptive about the prefix format.

2. **`/auth/register` endpoint existence**
   - What we know: REQ-3 specifies rate limiting on `/auth/register`. The current `server.rs` has no `/auth/register` route.
   - What's unclear: Was registration removed, renamed, or never added? The users POST handler at `/api/v1/users` creates users but is not named "register".
   - Recommendation: Check `axiam-api-rest/src/handlers/auth.rs` for a register handler. If absent, add registration rate limiting to the user creation endpoint at `/api/v1/users` instead, and note the discrepancy in the plan. Do not create a new route without understanding the auth flow.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust / cargo | All Rust compilation | Yes | 1.94.1 | — |
| Node.js | Frontend TypeScript build | Yes | 22.22.2 | — |
| Docker (nginx) | nginx.conf changes | Not verified | — | Edit file only; verify at integration |
| actix-governor crate | REST rate limiting | Not in workspace yet | 0.10.0 (crates.io) | — |
| tower-governor crate | gRPC rate limiting | Not in workspace yet | 0.8.0 (crates.io) | — |

**Missing dependencies with no fallback:**
- `actix-governor` and `tower-governor` must be added to Cargo.toml before any rate-limiting code compiles.

**Missing dependencies with fallback:**
- Docker runtime: nginx.conf edits can be written and verified by inspection; runtime test requires Docker compose.

---

## Validation Architecture

nyquist_validation is enabled (config.json has `"nyquist_validation": true`).

### Test Framework

| Property | Value |
|----------|-------|
| Framework | actix-web test (`actix_web::test`) + `#[actix_web::test]` macro |
| Config file | None — tests are integration tests in `crates/axiam-api-rest/tests/` |
| Quick run command | `cargo test -p axiam-api-rest --test security_headers_test 2>&1 \| tail -5` |
| Full suite command | `cargo test -p axiam-api-rest 2>&1 \| tail -20` |

Frontend test framework: none currently configured (no jest.config or vitest.config found). Frontend changes (badge, filter, unlock button) are manually tested in this phase.

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-2 | X-Content-Type-Options: nosniff on all API responses | integration | `cargo test -p axiam-api-rest --test security_headers_test test_security_headers_present` | No — Wave 0 |
| REQ-2 | X-Frame-Options: DENY on all API responses | integration | `cargo test -p axiam-api-rest --test security_headers_test test_x_frame_options_deny` | No — Wave 0 |
| REQ-2 | Referrer-Policy: strict-origin-when-cross-origin | integration | `cargo test -p axiam-api-rest --test security_headers_test test_referrer_policy` | No — Wave 0 |
| REQ-2 | Nginx CSP/HSTS/Permissions-Policy | manual | nginx config review; `curl -I http://localhost:8080` | manual-only |
| REQ-3 | Login rate limit: 10 req/min returns 429 on 11th | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_login_rate_limit` | No — Wave 0 |
| REQ-3 | Register rate limit: 5 req/min returns 429 on 6th | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_register_rate_limit` | No — Wave 0 |
| REQ-3 | oauth2/token rate limit: 20 req/min returns 429 on 21st | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_token_rate_limit` | No — Wave 0 |
| REQ-3 | Password-reset rate limit: 3 req/min returns 429 on 4th | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_password_reset_rate_limit` | No — Wave 0 |
| REQ-3 | 429 response has JSON body with `retry_after` and `Retry-After` header | integration | included in rate_limit_test | No — Wave 0 |
| REQ-3 | Account lockout after 5 failures | integration | `cargo test -p axiam-api-rest --test auth_test` (existing test file) | Yes — verify existing coverage |
| REQ-3 | Lockout status visible in admin UI (is_locked field in UserResponse) | integration | `cargo test -p axiam-api-rest --test user_test test_user_response_includes_lock_fields` | No — Wave 0 |
| REQ-3 | Manual unlock endpoint resets lockout | integration | `cargo test -p axiam-api-rest --test user_test test_unlock_user` | No — Wave 0 |
| REQ-3 | gRPC brute-force protection | manual | gRPC rate limit is a Tower layer — verify by inspection + manual test | manual-only |

### Sampling Rate

- **Per task commit:** `cargo test -p axiam-api-rest 2>&1 | tail -10`
- **Per wave merge:** `cargo test -p axiam-api-rest && cargo test -p axiam-api-grpc`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/axiam-api-rest/tests/security_headers_test.rs` — covers REQ-2 headers
- [ ] `crates/axiam-api-rest/tests/rate_limit_test.rs` — covers REQ-3 rate limiting (uses in-memory DB; actix test client sends N requests)
- [ ] actix-governor and tower-governor added to Cargo.toml (workspace + crate-level)

---

## Sources

### Primary (HIGH confidence)

- Codebase direct read: `crates/axiam-api-rest/src/middleware/csrf.rs` — middleware pattern
- Codebase direct read: `crates/axiam-api-rest/src/server.rs` — route registration pattern
- Codebase direct read: `crates/axiam-auth/src/service.rs` lines 763-809 — existing lockout logic
- Codebase direct read: `crates/axiam-auth/src/config.rs` — AuthConfig pattern for new RateLimitConfig
- Codebase direct read: `docker/nginx.conf` — existing header set, confirmed gaps
- crates.io API: actix-governor 0.10.0, governor 0.10.4, tower-governor 0.8.0, tower 0.5.3 (verified 2026-04-04)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) — exact header values

### Secondary (MEDIUM confidence)

- [actix-governor 0.10.0 docs.rs](https://docs.rs/actix-governor/0.10.0/actix_governor/) — GovernorConfigBuilder API, KeyExtractor trait
- [tower-governor 0.8.0 tonic example](https://github.com/benwis/tower-governor/blob/main/examples/src/tonic.rs) — gRPC integration pattern

### Tertiary (LOW confidence)

- None — all critical claims verified against official sources.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — versions verified from crates.io registry 2026-04-04
- Architecture: HIGH — based on direct codebase read; patterns follow established CsrfMiddleware
- Pitfalls: HIGH — nginx inheritance and actix-governor config sharing are documented behaviours
- Lockout logic: HIGH — read directly from service.rs; no new implementation needed

**Research date:** 2026-04-04
**Valid until:** 2026-05-04 (stable ecosystem; actix-governor/tower-governor versions unlikely to change)
