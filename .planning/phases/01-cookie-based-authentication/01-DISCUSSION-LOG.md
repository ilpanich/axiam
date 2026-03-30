# Phase 1: Cookie-Based Authentication - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-30
**Phase:** 01-cookie-based-authentication
**Areas discussed:** CSRF Protection Strategy, Cookie Scope & Refresh Path, Frontend Auth State After Migration, Backend Response Shape Change

---

## CSRF Protection Strategy

### Q1: CSRF token derivation

| Option | Description | Selected |
|--------|-------------|----------|
| Random | Cryptographically random token per session. Simple, proven, OWASP recommended | ✓ |
| HMAC-derived | Derive from session ID + server secret. Stateless validation but adds key management | |
| You decide | Let Claude pick | |

**User's choice:** Random
**Notes:** None

### Q2: CSRF token lifetime

| Option | Description | Selected |
|--------|-------------|----------|
| Per-session | One CSRF token per login session. Simpler frontend logic | ✓ |
| Per-request | New token on every response. Maximum security but complicates concurrent requests | |
| You decide | Let Claude pick | |

**User's choice:** Per-session
**Notes:** None

### Q3: CSRF header name

| Option | Description | Selected |
|--------|-------------|----------|
| X-CSRF-Token | Explicit, widely recognized. Used by Rails, Django | ✓ |
| X-XSRF-Token | Angular convention. Auto-reads XSRF-TOKEN cookie | |
| You decide | Let Claude pick | |

**User's choice:** X-CSRF-Token
**Notes:** None

### Q4: Protected endpoint scope

| Option | Description | Selected |
|--------|-------------|----------|
| All state-changing | POST/PUT/PATCH/DELETE via middleware. GET/HEAD/OPTIONS exempt | ✓ |
| Auth endpoints only | Only login, logout, refresh, password reset | |
| You decide | Let Claude pick | |

**User's choice:** All state-changing (POST/PUT/PATCH/DELETE)
**Notes:** None

---

## Cookie Scope & Refresh Path

### Q1: Refresh cookie path strictness

| Option | Description | Selected |
|--------|-------------|----------|
| Exact: /api/v1/auth/refresh | Tightest scope. Matches REQ-1 acceptance criteria | ✓ |
| Broader: /api/v1/auth/ | Covers refresh + logout but leaks token to other auth endpoints | |
| You decide | Let Claude pick | |

**User's choice:** Exact path
**Notes:** None

### Q2: Cookie Domain attribute

| Option | Description | Selected |
|--------|-------------|----------|
| Omit (origin-only) | Browser scopes to exact origin. Most secure default | ✓ |
| Set to deployment domain | Allows subdomain sharing. More flexible but larger surface | |
| You decide | Let Claude pick | |

**User's choice:** Omit (origin-only)
**Notes:** None

### Q3: Cookie Max-Age alignment

| Option | Description | Selected |
|--------|-------------|----------|
| Match JWT TTL | Access=900s, refresh=refresh token TTL. Browser auto-clears | ✓ |
| Session cookies | Expire when browser closes. Simpler but tokens may outlive cookie | |
| You decide | Let Claude pick | |

**User's choice:** Match JWT TTL
**Notes:** None

---

## Frontend Auth State After Migration

### Q1: How does the frontend know the user is authenticated?

| Option | Description | Selected |
|--------|-------------|----------|
| Login response body returns user info | { user, session_id, expires_in } in body, tokens in cookies | ✓ |
| Dedicated /me endpoint only | Login returns no body, always call /me | |
| Non-httpOnly metadata cookie | Readable cookie with user info | |
| You decide | Let Claude pick | |

**User's choice:** Login response body returns user info (recommended)
**Notes:** None

### Q2: Page refresh / rehydration

| Option | Description | Selected |
|--------|-------------|----------|
| Call /me on app init | GET /api/v1/auth/me on startup. If 200 populate, if 401 redirect | ✓ |
| Persist user info in sessionStorage | Optimistic render from cache, validate in background | |
| You decide | Let Claude pick | |

**User's choice:** Call /me on app init (recommended)
**Notes:** None

### Q3: Zustand store design

| Option | Description | Selected |
|--------|-------------|----------|
| Memory-only | Remove persist middleware. No sessionStorage at all | ✓ |
| Keep persist for tenant/org | Remove token persistence but keep navigation context | |
| You decide | Let Claude pick | |

**User's choice:** Memory-only (recommended)
**Notes:** None

---

## Backend Response Shape Change

### Q1: Login response body contents

| Option | Description | Selected |
|--------|-------------|----------|
| User info + session metadata | { user: { id, username, email }, session_id, expires_in } | ✓ |
| Minimal: just session_id | Frontend calls /me for everything else | |
| You decide | Let Claude pick | |

**User's choice:** User info + session metadata (recommended)
**Notes:** None

### Q2: Refresh endpoint response

| Option | Description | Selected |
|--------|-------------|----------|
| Just cookies + expires_in | { expires_in } in body. User info hasn't changed | ✓ |
| Include user info | Useful if user data changes between refreshes | |
| You decide | Let Claude pick | |

**User's choice:** Just cookies + expires_in (recommended)
**Notes:** None

### Q3: Integration test auth strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Cookie jar in test client | Login, extract Set-Cookie, carry cookies forward | ✓ |
| Dual mode: cookies + Authorization | Keep Bearer header as fallback for tests/SDKs | |
| You decide | Let Claude pick | |

**User's choice:** Cookie jar in test client (recommended)
**Notes:** None

---

## Claude's Discretion

- Cookie names (e.g., `axiam_access`, `axiam_refresh`, `axiam_csrf`)
- CSRF middleware implementation details
- `/me` endpoint implementation
- Order of refactoring

## Deferred Ideas

None — discussion stayed within phase scope
