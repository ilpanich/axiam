# Phase 1: Cookie-Based Authentication - Context

**Gathered:** 2026-03-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Migrate JWT token delivery from JSON response body + sessionStorage to httpOnly secure cookies. Add CSRF protection for all state-changing endpoints. Refactor frontend auth layer to work without JavaScript access to tokens. Update all integration tests to use cookie-based auth.

</domain>

<decisions>
## Implementation Decisions

### CSRF Protection
- **D-01:** Double-submit cookie pattern (per design document) with **cryptographically random** token — no HMAC derivation, no server secret key management needed
- **D-02:** CSRF token issued **per-session** — new token on login and refresh-token rotation. No per-request rotation (avoids concurrent request complications in SPA)
- **D-03:** Frontend sends CSRF token via **`X-CSRF-Token`** header
- **D-04:** CSRF validation required on **all state-changing requests** (POST, PUT, PATCH, DELETE) via middleware. GET/HEAD/OPTIONS exempt

### Cookie Scope & Configuration
- **D-05:** Access token cookie: `httpOnly; Secure; SameSite=Strict; Path=/`
- **D-06:** Refresh token cookie: `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh` — exact path, not broader `/api/v1/auth/`
- **D-07:** CSRF token cookie: readable by JS (no httpOnly), `Secure; SameSite=Strict; Path=/`
- **D-08:** **Omit `Domain` attribute** on all cookies — origin-only scoping (most secure default)
- **D-09:** Cookie `Max-Age` **matches JWT TTL** — access cookie = 900s (15 min), refresh cookie = refresh token TTL. Browser auto-clears expired cookies

### Frontend Auth State
- **D-10:** Login response body returns `{ user: { id, username, email }, session_id, expires_in }` — tokens are in Set-Cookie headers only, never in the body
- **D-11:** Frontend calls `GET /api/v1/auth/me` on app initialization to rehydrate auth state. If 200 → populate store. If 401 → redirect to login
- **D-12:** Zustand store becomes **memory-only** — remove `persist` middleware and all sessionStorage usage. Store holds `{ user, isAuthenticated, tenantSlug, orgSlug }` in memory only

### Backend Response Shape
- **D-13:** `LoginSuccessResponse` changes to `{ user, session_id, expires_in }` — `access_token` and `refresh_token` fields removed from JSON body
- **D-14:** Refresh endpoint returns `{ expires_in }` in body + new cookies. No user info re-sent on refresh
- **D-15:** Auth extractor (`extractors/auth.rs`) must support reading JWT from cookie in addition to or instead of `Authorization: Bearer` header

### Testing
- **D-16:** Integration tests use **cookie jar** in Actix-Web test client — login, extract Set-Cookie, carry cookies forward. No dual-mode Authorization header fallback

### Claude's Discretion
- Cookie names (e.g., `axiam_access`, `axiam_refresh`, `axiam_csrf` or similar)
- CSRF middleware implementation details (Actix-Web middleware vs extractor)
- `/me` endpoint implementation (new handler or extend existing)
- Order of refactoring (backend-first or frontend-first)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Security & Architecture
- `claude_dev/design-document.md` — Master architecture document; specifies double-submit cookie pattern, SameSite cookies, session security requirements
- `.planning/REQUIREMENTS.md` §REQ-1 — Cookie-Based Authentication acceptance criteria (8 items)

### Existing Auth Implementation
- `crates/axiam-api-rest/src/handlers/auth.rs` — Current login/logout/refresh handlers returning tokens in JSON body
- `crates/axiam-api-rest/src/extractors/auth.rs` — JWT extractor reading `Authorization: Bearer` header
- `crates/axiam-auth/src/token.rs` — Token issuance and validation logic
- `crates/axiam-auth/src/config.rs` — AuthConfig with JWT TTL settings

### Frontend Auth
- `frontend/src/stores/auth.ts` — Zustand store with sessionStorage persistence (must be rewritten)
- `frontend/src/lib/api.ts` — Axios client with Authorization header interceptor (must be rewritten)

### Codebase Maps
- `.planning/codebase/CONVENTIONS.md` — Naming patterns, code style, import organization
- `.planning/codebase/ARCHITECTURE.md` — Layer structure, crate dependency graph

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AuthService` in `axiam-auth` — login/refresh/logout logic; returns token strings. Can be wrapped to set cookies instead of returning in body
- `validate_access_token()` in `axiam-auth/src/token.rs` — JWT validation; currently called by extractor with token from header. Same function works regardless of token source
- `CachedUserIdentity` in `axiam-auth/src/token.rs` — Already cached in request extensions by audit middleware. Cookie extractor can reuse this caching pattern
- Actix-Web middleware infrastructure already in place (audit middleware, CORS)

### Established Patterns
- **Extractor pattern**: `AuthenticatedUser` implements `FromRequest`, extracts from header. Same pattern extends to cookie extraction
- **Repository trait pattern**: Changes to auth are in the API/service layer, not the DB layer — no repository changes needed
- **Error types**: `AxiamApiError` already handles 401 Unauthorized responses
- **Test setup**: Integration tests use `actix_web::test::init_service` — supports cookie jar via `TestServer`

### Integration Points
- `crates/axiam-api-rest/src/server.rs` — Where middleware is registered; CSRF middleware adds here
- `crates/axiam-api-rest/src/handlers/auth.rs` — Login/refresh/logout handlers; Set-Cookie logic goes here
- `frontend/src/lib/api.ts` — Axios interceptors; remove Authorization header, add `withCredentials: true`
- `docker/docker-compose.yml` — May need `Secure` flag config for local dev (or relaxed for HTTP dev mode)

</code_context>

<specifics>
## Specific Ideas

No specific requirements — all recommended approaches selected. Standard OWASP-compliant cookie auth implementation.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-cookie-based-authentication*
*Context gathered: 2026-03-30*
