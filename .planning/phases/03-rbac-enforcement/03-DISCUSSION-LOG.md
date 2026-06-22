# Phase 3: RBAC Enforcement - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md -- this log preserves the alternatives considered.

**Date:** 2026-04-09
**Phase:** 03-rbac-enforcement
**Areas discussed:** Middleware strategy, Permission model, Admin bootstrap flow, Self-service boundaries

---

## Middleware Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Global middleware + allowlist | A middleware layer that rejects all requests unless the route is in a public allowlist OR the handler explicitly passed authorization. Catches any handler that forgets to check. | ✓ |
| Per-handler only | Each handler calls RequirePermission explicitly. No middleware safety net. Simpler but relies on developer discipline. | |
| Route-level guards | Use Actix-Web's Guard trait to attach permission requirements at route registration time. Declarative but Guard trait is sync-only, can't do async DB lookups. | |

**User's choice:** Global middleware + allowlist (Recommended)
**Notes:** Standard request flow: CookieAuth extracts JWT, handler calls RequirePermission which sets authz_checked flag, outer middleware verifies flag is set or route is public.

### Follow-up: Error codes for unauthorized requests

| Option | Description | Selected |
|--------|-------------|----------|
| 401 if no JWT, 403 if JWT but denied | Standard HTTP semantics: 401 = identify yourself, 403 = known but insufficient permission | ✓ |
| Always 403 for non-public | Simpler but hides whether issue is missing auth or insufficient permissions | |

**User's choice:** 401 if no JWT, 403 if JWT but denied (Recommended)

---

## Permission Model

### Permission naming and endpoint mapping

| Option | Description | Selected |
|--------|-------------|----------|
| Entity:action flat model | Simple flat strings: users:read, users:write, users:delete. List and get share :read. | |
| Verb-based granular model | More granular: users:list, users:get, users:create, users:update, users:delete. Each CRUD verb distinct. | ✓ |
| You decide | Claude picks based on codebase and RBAC engine capabilities. | |

**User's choice:** Verb-based granular model
**Notes:** Finer control appropriate for an IAM product. Allows scenarios like "can list users but not view details."

### Permission seeding strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-seed on startup | Server creates all known permissions in SurrealDB on startup from compile-time PERMISSION_REGISTRY. | ✓ |
| Admin-created only | Permissions fully user-managed. Risks mismatch between endpoint expectations and DB. | |
| You decide | Claude picks based on AuthorizationEngine capabilities. | |

**User's choice:** Auto-seed on startup (Recommended)
**Notes:** Ensures no permission drift between code and DB. Integration test can verify all routes have matching perms.

---

## Admin Bootstrap Flow

### Bootstrap mechanism

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated REST endpoint | POST /api/v1/admin/bootstrap. Only works when zero admin users exist. AXIAM_BOOTSTRAP_ADMIN_EMAIL env var optionally restricts email. | ✓ |
| Auto-create on startup | Server creates admin from env vars on first boot. Simpler but requires password in env. | |
| CLI command | Separate axiam bootstrap-admin binary. Useful for air-gapped but adds operational complexity. | |

**User's choice:** Dedicated REST endpoint (Recommended)
**Notes:** Endpoint disabled (404) after first admin exists. Created user must login via normal flow.

### Default role seeding

| Option | Description | Selected |
|--------|-------------|----------|
| Seed default roles | Bootstrap creates super-admin, admin, and viewer roles with appropriate permissions. | ✓ |
| Only admin user + role | Creates one user and one super-admin role. All other roles admin-created. | |
| You decide | Claude picks for best out-of-box experience. | |

**User's choice:** Seed default roles (Recommended)
**Notes:** Three default roles: super-admin (all perms), admin (CRUD but not bootstrap/system), viewer (read-only).

---

## Self-Service Boundaries

### Self-service operations

| Option | Description | Selected |
|--------|-------------|----------|
| Profile (get/update own user) | GET/PUT /users/{own_id} for resource owner | ✓ |
| MFA management | Enroll, confirm, verify, WebAuthn for own account | ✓ |
| Own audit logs | GET /audit-logs filtered to own user_id | ✓ |
| Own certificates/PGP keys | List and view certificates and PGP keys issued to user | ✓ |

**User's choice:** All four self-service categories selected.

### Email change via self-service

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, with email verification | User can update email, verification required (wired in Phase 5, no-op for now) | ✓ |
| No, admin-only | Email changes require admin permission | |
| You decide | Claude picks based on IAM best practices | |

**User's choice:** Yes, with email verification (Recommended)
**Notes:** Email verification enforcement deferred to Phase 5. Field updatable now.

---

## Claude's Discretion

- Middleware implementation details (Transform/Service trait impl pattern)
- Permission registry data structure
- Public allowlist path matching strategy
- Bootstrap endpoint location in route registration
- Self-service check integration pattern
- Frontend RBAC-gated navigation (minimal if touched)

## Deferred Ideas

None -- discussion stayed within phase scope.
