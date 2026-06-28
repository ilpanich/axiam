# Feature Research — AXIAM Client SDKs (v1.1)

**Domain:** IAM Client SDK — 7 languages (Rust, TypeScript, Python, Java, C#, PHP, Go)
**Researched:** 2026-06-28
**Confidence:** HIGH (grounded in AXIAM server code + Auth0/Keycloak SDK pattern research)

---

## Context: Two SDK Personas

Every feature below applies differently to two distinct SDK consumer personas:

**Persona A — Browser / SPA SDK** (TypeScript primarily): Tokens live in httpOnly cookies set
by AXIAM. The SDK _cannot_ read the token value from JS — it must intercept 401 responses to
trigger refresh and forward CSRF tokens. Authorization checks go via REST.

**Persona B — Server / Service SDK** (Rust, Go, Java, C#, Python, PHP): Receives a Bearer
token in the `Authorization` header from upstream callers. Validates it via gRPC
`TokenService.ValidateToken` or `POST /oauth2/introspect`. Authorization checks use gRPC
`AuthorizationService.CheckAccess` (low-latency). CSRF not applicable (no browser cookie).

This split is not aesthetic — it determines token storage model, refresh strategy, CSRF
handling, and the gRPC vs REST choice for every feature. Feature descriptions below call out
which persona each behavior applies to.

---

## Feature Landscape

### Table Stakes (Users Expect These)

These are the features a developer expects any IAM SDK to provide out of the box. Missing any
of these means the SDK is not usable as a standalone library.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Password login** | Entry point for all auth flows | MEDIUM | `POST /api/v1/auth/login` with `{username_or_email, password, tenant_slug}`. Response: httpOnly cookies (access JWT + refresh). SDK extracts `X-CSRF-Token` response header for subsequent calls. Must expose login result struct with `mfa_required` field to signal step-2 needed. |
| **MFA step-up** (TOTP) | TOTP is enabled for all security-conscious tenants | LOW | After password-login returns `mfa_required: true`, call `POST /api/v1/auth/mfa/verify` with TOTP code. SDK must model this as a two-phase login: `login()` → if `mfa_required` → `verify_mfa(code)`. |
| **OAuth2 Authorization Code + PKCE** | Standard for third-party app integration | HIGH | Generate `code_verifier` (32-byte random, base64url), derive `code_challenge` (S256). Redirect to `GET /oauth2/authorize`. Exchange code at `POST /oauth2/token`. S256 is **mandatory** (server enforces it for public clients). SDK must handle the redirect round-trip and PKCE bookkeeping. |
| **OAuth2 Client Credentials** | Required for service account / M2M auth | MEDIUM | `POST /oauth2/token` with `grant_type=client_credentials`, `client_id`, `client_secret`, tenant context. Returns JSON `access_token` (not a cookie) for service-to-service use. SDK must expose a `ServiceAccountClient` or equivalent that holds the credential and refreshes proactively. |
| **Token refresh** | Access tokens expire in 15 min; refresh is mandatory | HIGH | `POST /api/v1/auth/refresh` uses the httpOnly refresh cookie (Persona A: browser sends it automatically). Persona B: SDK must send the opaque refresh token explicitly. Server returns new access + refresh pair (single-use rotation). SDK must handle rotation atomically. See concurrency note in Differentiators. |
| **Logout** | Expected in every auth library | LOW | `POST /api/v1/auth/logout`. Server clears cookies (`Max-Age=0`). SDK must clear any local state (stored refresh token, CSRF token, cached authz decisions). |
| **Current user / profile fetch** | Needed to render user identity | LOW | `GET /api/v1/auth/me`. Returns JWT claims + user profile. Persona B can call gRPC `UserService.GetUser` instead (lower latency). |
| **Token introspection** | RFC 7662 — validate a token without parsing it locally | MEDIUM | `POST /oauth2/introspect` or gRPC `TokenService.IntrospectToken`. Needed when a service wants full claims (subject, tenant, org, exp). SDK must expose both REST and gRPC paths. |
| **Token revocation** | Users and services must be able to invalidate tokens | LOW | `POST /oauth2/revoke`. SDK should call this on explicit logout and on credential rotation. |
| **Single authorization check** | Core authz primitive for protected resources | MEDIUM | gRPC `AuthorizationService.CheckAccess({tenant_id, subject_id, action, resource_id, scope?})` or REST fallback. SDK must expose a typed `can(subject, action, resource)` method. Persona B should default to gRPC for latency. |
| **Tenant context binding** | All AXIAM calls are tenant-scoped | LOW | SDK must allow developers to bind a `tenant_id` (UUID) at client construction time, propagating it to every request automatically. Must also accept `tenant_slug` for login (human-readable identifier before UUID is known). |
| **Framework middleware / route guard** | Developers expect plug-and-play auth middleware | HIGH | Each language SDK must ship a framework integration: TypeScript (Express + Fastify), Python (FastAPI + Django), Java (Spring Security filter), C# (ASP.NET Core middleware), PHP (Laravel + Symfony guard), Go (`net/http` middleware), Rust (Actix-Web middleware). Middleware must: extract token, validate via gRPC `ValidateToken`, attach claims to request context, reject unauthorized with 401. |
| **Error model** | Typed errors, not raw HTTP status codes | LOW | SDK must surface typed errors: `AuthError::InvalidCredentials`, `AuthError::MfaRequired`, `AuthError::TokenExpired`, `AuthError::AccountLocked`, `AuthzError::Denied(reason)`, `NetworkError`, etc. Developers must be able to match on error type without parsing HTTP bodies. |
| **CSRF token forwarding** (Persona A) | Server enforces CSRF on all `/api/v1` CRUD routes | MEDIUM | AXIAM uses double-submit cookie pattern. SDK must read `X-CSRF-Token` from login/refresh responses and attach it to every subsequent state-changing request via `X-CSRF-Token` header. The framework middleware (TypeScript/browser) must automate this. |

### Differentiators (Competitive Advantage)

These features exceed what a minimal IAM SDK provides. They are where AXIAM SDKs can
differentiate over generic HTTP clients wrapping auth endpoints.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Concurrency-safe refresh** | Prevents race conditions in multi-threaded / concurrent apps | HIGH | When multiple concurrent requests all receive 401, only ONE refresh call must fire; all others wait for it to complete and reuse the new token. Implementation: mutex/async lock (Rust `tokio::sync::Mutex`, Go `sync.Mutex`, Java `ReentrantLock`, TS `Promise` deduplication). Without this, concurrent 401s trigger parallel refreshes — each one invalidates the previous (single-use rotation), causing cascading auth failures. This is the #1 correctness requirement for the refresh path. |
| **gRPC authorization check** | Sub-millisecond authz in service meshes | MEDIUM | `AuthorizationService.CheckAccess` / `BatchCheckAccess`. REST authz adds ~10–30 ms round-trip; gRPC over persistent HTTP/2 connection is 1–5 ms. Service-side SDKs (Rust, Go, Java, C#, Python) should default to gRPC. Requires proto-generated client stubs per language. |
| **Batch authorization check** | Check N permissions in one round-trip | MEDIUM | `AuthorizationService.BatchCheckAccess` — takes `repeated CheckAccessRequest`. Useful for rendering permission-aware UIs (show/hide N buttons based on N permissions). SDK should expose `can_batch([(action, resource)])` returning a map. |
| **Authorization decision cache** | Avoid redundant authz calls on hot paths | MEDIUM | Local in-process TTL cache (30–60 s) keyed on `(tenant_id, subject_id, action, resource_id, scope)`. Must be invalidated on logout, token revocation, and explicit `flush_authz_cache()`. Risk: stale decisions if roles change mid-session — document TTL tradeoff. Cache should be configurable (enable/disable, TTL). |
| **AMQP async authz consumer** (Rust, Go, Java, C#, Python) | Subscribe to async authz decisions for event-driven architectures | HIGH | AXIAM's AMQP channel delivers async authorization decisions (for workloads where synchronous gRPC checks are not feasible). SDK must expose a consumer helper that connects to RabbitMQ, verifies HMAC-SHA256 message signatures, and calls a user-supplied callback. TypeScript/PHP: AMQP support is ecosystem-constrained — provide if viable (amqplib / php-amqplib), document clearly if not. |
| **AMQP event consumer / webhook helper** | Consume IAM events (user created, role changed, etc.) | HIGH | AXIAM publishes events over AMQP. SDK provides a typed consumer that verifies HMAC-SHA256 signatures on received messages and deserializes into typed event structs. Webhook signature verification helper for HTTP delivery: `verify_webhook_signature(payload, signature, secret)`. |
| **WebAuthn / passkey helpers** | Passkeys are the modern credential standard | HIGH | AXIAM supports WebAuthn: `POST /api/v1/auth/webauthn/register/start|finish`, `authenticate/start|finish`. SDK (TypeScript browser SDK especially) should wrap the WebAuthn ceremony and handle the challenge/response JSON serialization. Server-side SDKs: expose typed request/response models only. |
| **Certificate / mTLS auth** (Rust, Go, Java, C#) | Required for IoT device authentication | HIGH | AXIAM supports X.509 mTLS for IoT. SDK must support configuring a client certificate + key for mutual TLS. Expose `CertificateAuthClient` that wraps the transport with the client cert. PHP/TypeScript: lower priority (atypical in those ecosystems for IoT). |
| **OIDC discovery auto-configuration** | Production hardening — don't hardcode endpoints | LOW | SDK should support fetching `/.well-known/openid-configuration` at startup and auto-configuring endpoint URLs (authorization, token, introspection, revocation, JWKS). Allows switching server base URL without code changes. Cache discovery document with a reasonable TTL (~1 h). |
| **Proactive token refresh** (Persona B) | Avoid latency spike on token expiry | LOW | Server-side SDK can read the `exp` claim from the JWT (no httpOnly restriction for service SDKs). Spawn a background task to refresh ~60 s before expiry. Avoids the 401 round-trip on hot paths. Persona A (browser) cannot do this (httpOnly cookie — `exp` not readable). |
| **Device Authorization Flow** | IoT / CLI device auth standard | MEDIUM | `POST /api/v1/auth/device`. SDK exposes a polling helper that presents the device code to the user, then polls the token endpoint until approved or expired. Primarily for Rust (IoT) and Go/Python (CLI tools). |
| **Federation login helpers** | SSO entry point for OIDC/SAML federations | MEDIUM | `POST /api/v1/auth/federation/oidc/start|callback` and (feature-flagged) SAML equivalents. SDK exposes typed request/response models and redirect helpers for initiating and completing federated logins. |

### Anti-Features (Do Not Build)

These are features that seem natural for an IAM SDK but must be explicitly avoided.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **Token storage in localStorage / sessionStorage** | Simpler to implement, survives page reload | XSS-vulnerable; any injected script steals the token. AXIAM already solved this with httpOnly cookies — SDK must not undo it. | Let the browser cookie jar hold tokens. SDK operates cookieless on the wire; browser handles storage. |
| **JWT parsing / signature verification in SDK** | Faster than a gRPC roundtrip to validate | Requires distributing the Ed25519 public key to every SDK consumer; adds key-rotation complexity; creates a drift risk if AXIAM rotates without SDK updates. | Always call `TokenService.ValidateToken` or `POST /oauth2/introspect`. The gRPC path is fast enough (< 5 ms). |
| **Client-side RBAC engine / permission cache pre-loading** | Devs want instant permission checks | AXIAM's RBAC includes resource hierarchy inheritance — a client-side reimplementation will drift and produce wrong deny decisions. | Use the authorization cache (TTL-based) which stays correct while being fast. |
| **Embedding client secrets in frontend bundles** | Public clients want client_credentials flow | client_secret in a browser bundle is publicly readable. OAuth2 RFC forbids this. | Browser SDKs use Authorization Code + PKCE only. Client credentials are strictly for Persona B (server-side). |
| **Blocking/synchronous refresh in async runtimes** | Simpler code | Blocks the thread pool in async runtimes (tokio, asyncio, Netty). One blocked refresh blocks all in-flight requests. | Use async/non-blocking refresh with a concurrency gate (mutex + `await`). |
| **Auto-retry on every 401** | Resilience | Creates retry loops when the refresh token is also expired or the account is locked — the loop hides the real error. | Retry exactly once after a successful refresh. If the re-attempt also 401s, propagate `TokenExpired` or `AccountLocked`. |
| **AMQP in browser** | Feature parity across SDKs | Browser JS has no AMQP support. Shipping a broken/stub implementation misleads users. | Document clearly which transports each SDK supports. TypeScript browser: REST only. Node.js (server-side): AMQP via amqplib. |

---

## Feature Dependencies

```
Password Login
    └──enables──> MFA Step-Up (if mfa_required in response)
    └──enables──> Token Refresh (issues refresh token)
    └──enables──> CSRF Token Forwarding (X-CSRF-Token in login response)

Token Refresh
    └──requires──> Concurrency-Safe Refresh Gate (mutex/promise lock)
    └──produces──> New CSRF Token (must update stored CSRF token after each refresh)

Framework Middleware
    └──requires──> Single Authorization Check (validate + authz in one pipeline)
    └──requires──> Tenant Context Binding (tenant_id must flow into middleware)
    └──enhances──> Authorization Decision Cache (cache injected into middleware)

gRPC Authorization Check
    └──requires──> Proto-generated stubs (per-language codegen from proto/axiam/v1/)
    └──enhances──> Batch Authorization Check (same gRPC channel)

AMQP Consumer
    └──requires──> HMAC-SHA256 signature verification (security gate on every message)
    └──enables──> Authorization Decision Cache invalidation (consume role-change events)

Certificate / mTLS Auth
    └──requires──> Transport-level TLS client cert configuration
    └──requires──> Server exposes /api/v1/auth cert endpoint (existing)

OIDC Discovery Auto-Configuration
    └──enhances──> OAuth2 Authorization Code + PKCE (endpoint URLs auto-resolved)
    └──enhances──> Token Introspection (introspection URL from discovery doc)

Device Auth Flow
    └──requires──> POST /api/v1/auth/device (existing endpoint in server.rs:102)
    └──enables──> Token Refresh (issues refresh token on approval)
```

### Dependency Notes

- **MFA step-up requires password login first**: The `verify_mfa` step uses the incomplete
  session from the initial `login` call. SDK must track the "pending MFA" state between the
  two calls.

- **Concurrency-safe refresh is a hard dependency of token refresh**: Without it, rotating
  refresh tokens cause cascading invalidation under concurrent load. Not optional.

- **CSRF token forwarding depends on token refresh**: Every refresh response returns a new
  `X-CSRF-Token`. The SDK must update its stored CSRF token after every refresh, not just
  after login.

- **gRPC stubs must be generated per language**: Each SDK's build process must include proto
  compilation from `proto/axiam/v1/{authorization,token,user}.proto`. Grpc codegen tooling
  varies by language: `tonic-build` (Rust), `grpc-tools` + `@grpc/grpc-js` (TypeScript/Node),
  `grpcio-tools` (Python), `protoc` + `grpc-java` (Java), `Grpc.Tools` (C#),
  `google.golang.org/grpc` (Go). PHP gRPC support is marginal — optional for that SDK.

- **AMQP consumer message signature verification is non-optional**: AXIAM signs all AMQP
  messages with HMAC-SHA256. An SDK consumer that does not verify signatures could be fed
  forged authorization grants. Expose this as a mandatory step, not an optional callback.

---

## MVP Definition

The v1.1 milestone is a "starter SDK" release. Each SDK ships a working foundation, not the
complete feature set.

### Launch With (v1.1 — each SDK)

- [x] Password login (username/password → tokens/session) — blocks everything
- [x] MFA step-up (TOTP verify after login) — required for tenants with MFA enabled
- [x] OAuth2 Client Credentials — required for service-to-service auth (most common SDK use case)
- [x] Token refresh (concurrency-safe) — mandatory; access tokens expire in 15 min
- [x] Logout — table stakes
- [x] Single authorization check (REST for all SDKs, gRPC for Rust/Go/Java/C#/Python)
- [x] Tenant context binding — required; all AXIAM calls are tenant-scoped
- [x] Framework middleware / route guard — the primary integration point for most developers
- [x] Typed error model — without this, SDK is not ergonomic
- [x] CSRF token forwarding (TypeScript browser SDK only) — mandatory for browser persona

### Add After Validation (v1.1.x)

- [ ] OAuth2 Authorization Code + PKCE — needed for third-party app integrations; complex to implement correctly (PKCE generation, redirect handling, state parameter)
- [ ] Batch authorization check — value add, requires gRPC stubs already present
- [ ] Authorization decision cache — perf optimization; only after correctness is proven
- [ ] Concurrency-safe proactive refresh (Persona B) — after basic refresh is solid
- [ ] OIDC discovery auto-configuration — once SDK is in production use
- [ ] WebAuthn helpers (TypeScript) — after core login flow is stable

### Future Consideration (v1.2+)

- [ ] AMQP event consumer / async authz — high value for event-driven architectures; high complexity
- [ ] Device Authorization Flow — IoT/CLI niche; implement when requested
- [ ] Federation login helpers — depends on server federation being fully hardened
- [ ] Certificate / mTLS auth — IoT scenario; needs dedicated SDK consumers to prioritize

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Password login | HIGH | MEDIUM | P1 |
| MFA step-up | HIGH | LOW | P1 |
| Client Credentials | HIGH | MEDIUM | P1 |
| Token refresh (concurrency-safe) | HIGH | HIGH | P1 |
| Logout | HIGH | LOW | P1 |
| Tenant context binding | HIGH | LOW | P1 |
| Framework middleware | HIGH | HIGH | P1 |
| Typed error model | HIGH | LOW | P1 |
| CSRF forwarding (TS browser) | HIGH | MEDIUM | P1 |
| Single authz check (REST) | HIGH | MEDIUM | P1 |
| Single authz check (gRPC) | HIGH | MEDIUM | P1 |
| OAuth2 PKCE | HIGH | HIGH | P2 |
| Batch authz check | MEDIUM | MEDIUM | P2 |
| Authz decision cache | MEDIUM | MEDIUM | P2 |
| OIDC discovery | MEDIUM | LOW | P2 |
| Proactive refresh (Persona B) | MEDIUM | LOW | P2 |
| WebAuthn helpers | MEDIUM | HIGH | P2 |
| AMQP consumer | MEDIUM | HIGH | P3 |
| Device auth flow | LOW | MEDIUM | P3 |
| Federation login helpers | LOW | MEDIUM | P3 |
| Certificate/mTLS auth | LOW | HIGH | P3 |

---

## Competitor Feature Analysis

| Feature | Auth0 SDK | Keycloak Adapter | Clerk SDK | AXIAM SDK |
|---------|-----------|------------------|-----------|-----------|
| Login (password) | Via Universal Login (redirect) | Direct to Keycloak | Via Clerk-hosted UI or SDK | Direct `POST /api/v1/auth/login` — no redirect required |
| MFA flow | Step-up challenge in Universal Login | Challenge in Keycloak login flow | Built into Clerk UI | Two-phase: `login()` + `verify_mfa()` in SDK |
| Token storage | Rotating refresh token in memory (SPA), httpOnly cookie (server) | Server-side session or bearer | Clerk-managed session cookie | httpOnly cookie (browser) / bearer (service) — matches industry best practice |
| Token refresh | `useRefreshTokens: true` — SDK handles automatically with deduplication | Auto-refresh via session store | Clerk SDK auto-manages | Must implement; concurrency gate is the key requirement |
| gRPC authz | Not supported | Not supported | Not supported | **Differentiator**: gRPC `CheckAccess` sub-5ms for service mesh |
| Batch authz | Not supported | Not supported | Not supported | **Differentiator**: `BatchCheckAccess` — N checks in 1 round-trip |
| Multi-tenant context | Via custom claims / organizations | Via realm parameter | Via org ID in headers | `tenant_id` in JWT; SDK binds at client construction |
| Framework middleware | Auth0 provides per-framework SDKs | Keycloak adapter per framework | Clerk per-framework middleware | Per-framework SDK modules — same approach |
| AMQP async authz | Not supported | Not supported | Not supported | **Differentiator**: event-driven authz for IoT/microservices |

---

## Cross-Language Consistency Requirements

Each SDK ships the same logical feature set, expressed in the idiomatic style of each language.
The following behavioral contracts must be consistent across all 7 SDKs:

1. **`login(username, password, tenant_slug)` → `LoginResult`** — always returns a typed struct
   with an `mfa_required` field, never throws on MFA challenge.
2. **`refresh()` → atomic, concurrency-safe** — only one in-flight refresh per client instance.
3. **`can(subject_id, action, resource_id)` → `bool`** — single authz check, gRPC preferred.
4. **`TenantContext` or equivalent** — bound at client construction, propagated to every request.
5. **`logout()` → clears all local state** — cookies (via server), CSRF token, authz cache.
6. **Error taxonomy** — same error categories (credentials, mfa, locked, expired, denied, network)
   across all SDKs, even if type names follow language conventions.
7. **Framework middleware** — attaches `AxiamClaims` (subject_id, tenant_id, org_id) to request
   context in the framework's idiomatic way (Express `req.auth`, FastAPI dependency, Spring
   `SecurityContext`, ASP.NET Core `HttpContext.Items`, Laravel `Request::user()`,
   Go `context.Context`, Rust Actix-Web extractor).

---

## Server Endpoint Reference (SDK Perspective)

| Feature | Endpoint | Method | Auth Required | CSRF Required |
|---------|----------|--------|---------------|---------------|
| Password login | `/api/v1/auth/login` | POST | No | No (sets CSRF) |
| MFA step-up | `/api/v1/auth/mfa/verify` | POST | Partial (session) | Yes |
| MFA enroll (setup) | `/api/v1/auth/mfa/setup/enroll` + `/confirm` | POST | Yes | Yes |
| Logout | `/api/v1/auth/logout` | POST | Yes | Yes |
| Token refresh | `/api/v1/auth/refresh` | POST | Refresh cookie | No |
| Current user | `/api/v1/auth/me` | GET | Yes | No |
| OAuth2 authorize | `/oauth2/authorize` | GET | No (redirect) | No |
| OAuth2 token | `/oauth2/token` | POST | Client auth | No |
| Token introspect | `/oauth2/introspect` | POST | Client auth | No |
| Token revoke | `/oauth2/revoke` | POST | Client auth | No |
| OIDC userinfo | `/oauth2/userinfo` | GET | Bearer | No |
| OIDC discovery | `/.well-known/openid-configuration` | GET | No | No |
| JWKS | `/oauth2/jwks` | GET | No | No |
| WebAuthn register | `/api/v1/auth/webauthn/register/start` + `/finish` | POST | Yes | Yes |
| WebAuthn auth | `/api/v1/auth/webauthn/authenticate/start` + `/finish` | POST | No / Yes | No |
| Device auth | `/api/v1/auth/device` | POST | No | No |
| Federation OIDC | `/api/v1/auth/federation/oidc/start` + `/callback` | POST | No | No |
| gRPC check access | `AuthorizationService.CheckAccess` | gRPC | Bearer (metadata) | No |
| gRPC batch check | `AuthorizationService.BatchCheckAccess` | gRPC | Bearer (metadata) | No |
| gRPC validate token | `TokenService.ValidateToken` | gRPC | None (token is input) | No |
| gRPC introspect | `TokenService.IntrospectToken` | gRPC | None (token is input) | No |
| gRPC get user | `UserService.GetUser` | gRPC | Bearer (metadata) | No |
| AMQP authz consumer | RabbitMQ queue (HMAC-SHA256 signed) | AMQP | Shared secret | No |

---

## Sources

- Auth0 SDK patterns: refresh token rotation, `useRefreshTokens`, SPA token storage —
  [Auth0 Docs — Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation),
  [Auth0 Blog — Securing SPAs with Refresh Token Rotation](https://auth0.com/blog/securing-single-page-applications-with-refresh-token-rotation/)
- Keycloak Node.js adapter middleware pattern —
  [Keycloak Docs — Node.js Adapter](https://www.keycloak.org/securing-apps/nodejs-adapter)
- Concurrency-safe token refresh / mutex pattern —
  [Brains & Beards — Token Renewal Mutex](https://brainsandbeards.com/blog/2024-token-renewal-mutex/)
- httpOnly cookie auth for SPAs / CSRF —
  [Cookie-based authentication with SPA and Django](https://yoongkang.com/blog/cookie-based-authentication-spa-django/)
- Istio external authorization / gRPC authz patterns —
  [Istio — Better External Authorization](https://istio.io/latest/blog/2021/better-external-authz/)
- WorkOS / Clerk multi-tenant SDK architecture —
  [Clerk — Multi-tenant architecture](https://clerk.com/docs/guides/how-clerk-works/multi-tenant-architecture)
- AXIAM server ground truth: `crates/axiam-api-rest/src/server.rs` (route registrations),
  `proto/axiam/v1/authorization.proto`, `token.proto`, `user.proto`

---
*Feature research for: AXIAM Client SDKs v1.1*
*Researched: 2026-06-28*
