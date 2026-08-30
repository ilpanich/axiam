# Phase 2: Security Headers & Rate Limiting - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-04
**Phase:** 02-security-headers-rate-limiting
**Areas discussed:** Rate limiting strategy, CSP policy for React SPA, Lockout admin UI, gRPC brute-force protection

---

## Rate Limiting Strategy

### Q1: Rate limit state storage

| Option | Description | Selected |
|--------|-------------|----------|
| In-memory (Recommended) | actix-governor with in-memory store. Simple, zero dependencies, sufficient for single-pod or per-pod rate limiting. | ✓ |
| Distributed (Redis) | Shared state across pods via Redis. Accurate global limits but adds infrastructure dependency. | |
| You decide | Claude picks based on architecture and MVP scope. | |

**User's choice:** In-memory (Recommended)
**Notes:** None

### Q2: Client identification

| Option | Description | Selected |
|--------|-------------|----------|
| X-Forwarded-For header (Recommended) | Extract real client IP from X-Forwarded-For (nginx sets this). Fall back to peer addr if missing. | ✓ |
| Peer address only | Use direct TCP peer address. All clients behind proxy share one bucket. | |
| You decide | Claude picks based on nginx/K8s setup. | |

**User's choice:** X-Forwarded-For header (Recommended)
**Notes:** None

### Q3: Rate limit error response format

| Option | Description | Selected |
|--------|-------------|----------|
| JSON error + Retry-After (Recommended) | 429 with JSON body and Retry-After header. Consistent with existing API error responses. | ✓ |
| Plain 429 + Retry-After | Minimal 429 with Retry-After only, no JSON body. | |
| You decide | Claude picks the response format. | |

**User's choice:** JSON error + Retry-After (Recommended)
**Notes:** None

### Q4: Rate limit configurability

| Option | Description | Selected |
|--------|-------------|----------|
| Environment variables (Recommended) | Configurable via env vars with REQ-3 values as defaults. | ✓ |
| Hardcoded defaults only | Bake values directly into code. Simpler but requires recompile to change. | |
| You decide | Claude picks configurability level. | |

**User's choice:** Environment variables (Recommended)
**Notes:** None

---

## CSP Policy for React SPA

### Q1: Script CSP strictness

| Option | Description | Selected |
|--------|-------------|----------|
| Strict: self only (Recommended) | script-src 'self'. Only allow scripts from same origin. Blocks inline and eval. | ✓ |
| Nonce-based | script-src 'nonce-<random>'. Maximum security but requires server-side HTML rendering. | |
| You decide | Claude picks based on Vite build output. | |

**User's choice:** Strict: self only (Recommended)
**Notes:** None

### Q2: Style CSP handling

| Option | Description | Selected |
|--------|-------------|----------|
| unsafe-inline for styles (Recommended) | style-src 'self' 'unsafe-inline'. Allows inline styles for Tailwind/React. Minimal XSS risk. | ✓ |
| Strict: self only for styles | style-src 'self'. Would break Tailwind dynamic classes and React style props. | |
| You decide | Claude picks based on Tailwind/React requirements. | |

**User's choice:** unsafe-inline for styles (Recommended)
**Notes:** None

### Q3: CSP scope

| Option | Description | Selected |
|--------|-------------|----------|
| Nginx only (Recommended) | CSP on nginx for HTML/asset responses. Backend API returns JSON where CSP is irrelevant. | ✓ |
| Both backend and nginx | CSP on all responses including API. Defense-in-depth but adds noise to JSON responses. | |
| You decide | Claude picks based on where CSP matters. | |

**User's choice:** Nginx only (Recommended)
**Notes:** None

---

## Lockout Admin UI

### Q1: Lockout status display

| Option | Description | Selected |
|--------|-------------|----------|
| Badge on user list (Recommended) | 'Locked' badge/chip next to locked users in existing user list table, plus filter for locked users. | ✓ |
| Dedicated locked users page | New page listing only locked accounts with unlock actions. | |
| Both: badge + filter + detail panel | Badge on list, filter, AND lockout details in user detail view. | |
| You decide | Claude picks the UI approach. | |

**User's choice:** Badge on user list (Recommended)
**Notes:** None

### Q2: Manual unlock capability

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, unlock button (Recommended) | Unlock action resets failed_login_attempts to 0 and clears locked_until. | ✓ |
| No, wait for cooldown only | Auto-unlock after 15-min cooldown only. Simpler but less helpful for support. | |
| You decide | Claude picks based on IAM best practices. | |

**User's choice:** Yes, unlock button (Recommended)
**Notes:** None

---

## gRPC Brute-Force Protection

### Q1: Implementation approach

| Option | Description | Selected |
|--------|-------------|----------|
| Custom Tower layer + governor (Recommended) | Tower Layer wrapping governor crate's in-memory rate limiter. Same algorithm as REST. | ✓ |
| Tonic interceptor with manual tracking | Tonic interceptor with hand-rolled token bucket. Simpler API but duplicates logic. | |
| You decide | Claude picks based on Tonic/Tower patterns. | |

**User's choice:** Custom Tower layer + governor (Recommended)
**Notes:** None

### Q2: gRPC rate limit values

**User's choice:** Configurable via environment variables, same pattern as REST rate limits.
**Notes:** User interrupted the options question to specify: make it configurable via environment variables.

---

## Claude's Discretion

- Backend security headers middleware implementation details
- Specific Permissions-Policy directive values
- HSTS preload decision
- gRPC client identity extraction method
- Default gRPC rate limit values
- Nginx CSP directive details beyond script-src and style-src

## Deferred Ideas

None — discussion stayed within phase scope
