# Phase 2: Security Headers & Rate Limiting - Context

**Gathered:** 2026-04-04
**Status:** Ready for planning

<domain>
## Phase Boundary

Add OWASP-recommended security headers to all HTTP responses (backend API + nginx frontend) and protect authentication endpoints from brute-force attacks via rate limiting. Includes REST rate limiting (actix-governor), gRPC rate limiting (Tower layer + governor), account lockout admin UI surface, and CSP/HSTS/Permissions-Policy on nginx.

</domain>

<decisions>
## Implementation Decisions

### Rate Limiting Strategy
- **D-01:** In-memory rate limiting using `actix-governor` crate with in-memory store. No distributed/Redis dependency. Each pod tracks its own limits — sufficient for MVP beta.
- **D-02:** Client identification via `X-Forwarded-For` header (nginx already sets this). Fall back to peer address if header missing.
- **D-03:** Rate limit error response: HTTP 429 with JSON body `{"error": "rate_limit_exceeded", "retry_after": N}` and `Retry-After` header. Consistent with AXIAM's existing JSON error format.
- **D-04:** Rate limits configurable via environment variables (e.g., `AXIAM_RATE_LIMIT__LOGIN_PER_MIN=10`) with REQ-3 values as defaults: login 10/min, register 5/min, oauth2/token 20/min, password-reset 3/min.

### CSP Policy for React SPA
- **D-05:** `script-src 'self'` — strict, no inline scripts, no eval. Vite bundles are external files so this works out of the box.
- **D-06:** `style-src 'self' 'unsafe-inline'` — allows inline styles for Tailwind CSS and React style props. Inline styles don't execute code, minimal XSS risk.
- **D-07:** CSP applied on **nginx only** (frontend HTML/asset responses). Backend API returns JSON where CSP is irrelevant. Backend middleware handles other security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy).

### Lockout Admin UI
- **D-08:** 'Locked' badge/chip on user list table for locked users, plus a filter to show only locked users. Integrated into existing Users page — no dedicated locked-users page.
- **D-09:** Manual unlock button for admins. Resets `failed_login_attempts` to 0 and clears `locked_until`.

### gRPC Brute-Force Protection
- **D-10:** Custom Tower Layer wrapping the `governor` crate's in-memory rate limiter. Same algorithm as REST for consistency.
- **D-11:** gRPC rate limits configurable via environment variables, same pattern as REST rate limits.

### Claude's Discretion
- Backend security headers middleware implementation details (single middleware vs per-header)
- Specific `Permissions-Policy` directive values
- HSTS preload decision (include or omit `preload` directive)
- gRPC client identity extraction method (metadata vs peer address)
- Default gRPC rate limit values (should be generous for service-mesh authz patterns)
- Nginx CSP directive details beyond script-src and style-src (img-src, connect-src, font-src, etc.)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Security Requirements
- `.planning/REQUIREMENTS.md` §REQ-2 — Security Headers acceptance criteria (4 items)
- `.planning/REQUIREMENTS.md` §REQ-3 — Rate Limiting & Brute-Force Protection acceptance criteria (7 items)
- `claude_dev/design-document.md` — Master architecture document; security standards section

### Existing Implementation
- `crates/axiam-api-rest/src/server.rs` — Middleware registration point (CsrfMiddleware pattern to follow)
- `crates/axiam-api-rest/src/middleware/csrf.rs` — Existing middleware pattern to replicate for security headers
- `crates/axiam-auth/src/service.rs` lines 763-802 — Existing account lockout logic (`record_failed_login`, `reset_failed_logins`)
- `crates/axiam-auth/src/config.rs` — AuthConfig with `max_failed_login_attempts` setting
- `crates/axiam-core/src/models/user.rs` — User model with `failed_login_attempts`, `locked_until`, `UserStatus::Locked`
- `crates/axiam-api-grpc/` — gRPC server where Tower rate-limit layer will be added
- `docker/nginx.conf` — Current nginx config (has basic security headers, missing CSP/HSTS/Permissions-Policy)

### Frontend
- `frontend/src/pages/users/` — Existing Users page where lockout badge/filter/unlock will be added

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` — Layer structure, crate dependency graph
- `.planning/codebase/CONVENTIONS.md` — Naming patterns, middleware patterns

### Prior Phase Context
- `.planning/phases/01-cookie-based-authentication/01-CONTEXT.md` — Cookie auth decisions (CsrfMiddleware pattern, cookie config)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `CsrfMiddleware` in `axiam-api-rest/src/middleware/csrf.rs` — Pattern to follow for security headers middleware
- Account lockout logic in `AuthService` — `record_failed_login()`, `reset_failed_logins()` already functional
- `UserStatus::Locked` enum variant — already exists in domain model
- `failed_login_attempts` and `locked_until` fields — already in User model and DB schema
- `max_failed_login_attempts` in settings — already configurable per-tenant

### Established Patterns
- Actix-Web middleware registered via `.wrap()` in `server.rs`
- AuthConfig for environment-variable-driven configuration
- JSON error responses via `AxiamApiError` type
- Frontend uses React + Tailwind with existing Users page components

### Integration Points
- `crates/axiam-api-rest/src/server.rs` — Security headers middleware and rate limiter registration
- `crates/axiam-api-grpc/` — Tower layer for gRPC rate limiting
- `docker/nginx.conf` — CSP, HSTS, Permissions-Policy headers
- `frontend/src/pages/users/` — Lockout badge, filter, unlock button

</code_context>

<specifics>
## Specific Ideas

No specific requirements — all recommended approaches selected. Standard OWASP-compliant implementation with configurable rate limits via environment variables.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-security-headers-rate-limiting*
*Context gathered: 2026-04-04*
