# Phase 3: RBAC Enforcement - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire the existing `AuthorizationEngine` to every REST API endpoint with default-deny authorization. Add a global authorization middleware with a public endpoint allowlist. Implement admin bootstrap (first admin creation + default role seeding). Implement self-service access patterns for users to manage their own profile, MFA, audit logs, and certificates. Auto-seed all permission definitions on startup. Add an integration test verifying every registered route has an authorization check.

</domain>

<decisions>
## Implementation Decisions

### Middleware Strategy
- **D-01:** Global authorization middleware (`AuthzMiddleware`) wraps all routes. Rejects requests unless the route is in the `PUBLIC_ALLOWLIST` OR the handler has set an `authz_checked` flag in request extensions.
- **D-02:** `RequirePermission` guard (existing in `authz.rs`) remains the per-handler mechanism. After a successful check, it sets `authz_checked = true` in request extensions so the outer middleware knows authorization was performed.
- **D-03:** HTTP status codes follow standard semantics: **401 Unauthorized** when no JWT is present (unauthenticated), **403 Forbidden** when JWT is valid but the user lacks the required permission.
- **D-04:** Public endpoint allowlist includes: `/auth/login`, `/auth/register`, `/auth/device`, `/health`, `/ready`, `/.well-known/openid-configuration`, `/oauth2/jwks`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/federation/*/oidc/callback`, `/federation/*/saml/acs`, `/federation/*/saml/metadata`, `/auth/password-reset/*`, `/auth/email/verify`, `/auth/email/resend`.

### Permission Model
- **D-05:** Verb-based granular permissions using `entity:action` format: `users:list`, `users:get`, `users:create`, `users:update`, `users:delete`. Each CRUD verb has its own permission.
- **D-06:** Special admin actions use `:admin` suffix: `users:admin` (unlock, reset MFA for others).
- **D-07:** All permissions auto-seeded into SurrealDB on server startup from a compile-time `PERMISSION_REGISTRY`. Uses UPSERT to avoid duplicates. Ensures no drift between code expectations and database state.
- **D-08:** Integration test verifies every registered route has a matching permission in the registry — catches missing permission definitions at CI time.

### Admin Bootstrap
- **D-09:** Dedicated `POST /api/v1/admin/bootstrap` endpoint. Creates the first admin user when zero admin users exist in the tenant. Returns 404 after the first admin is created (endpoint effectively disabled).
- **D-10:** Request body: `{ email, password, username }`. If `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var is set, the request `email` must match — otherwise the endpoint rejects with 403.
- **D-11:** Bootstrap does not issue a token — the created user must log in via the normal `/auth/login` flow.
- **D-12:** Bootstrap seeds 3 default roles:
  - **super-admin** — ALL permissions. Assigned to the bootstrap user.
  - **admin** — All entity CRUD permissions. Excludes `admin:bootstrap` and system-level settings.
  - **viewer** — All `:list` and `:get` permissions. Read-only access.

### Self-Service Boundaries
- **D-13:** Self-service access uses a `caller_user_id == target_user_id` check. If the caller is accessing their own resource, the request is authorized without requiring the corresponding admin permission.
- **D-14:** Self-service endpoints:
  - **Profile:** `GET /users/{own_id}` and `PUT /users/{own_id}` — view and update own profile.
  - **MFA:** Enroll, confirm, verify TOTP, and WebAuthn registration/authentication for own account. `POST /users/{own_id}/reset-mfa` also self-service.
  - **Audit logs:** `GET /audit-logs` filtered to own `user_id`.
  - **Certificates/PGP keys:** `GET /certificates` and `GET /pgp-keys` filtered to own resources.
- **D-15:** Self-service profile update allows email changes. Email verification is wired in Phase 5 — for now, the field is updatable without verification enforcement.

### Claude's Discretion
- Middleware implementation details (Transform/Service trait impl pattern in Actix-Web)
- Permission registry data structure (const array, lazy_static, or build-time macro)
- Exact public allowlist path matching strategy (prefix match, regex, or route-name based)
- Bootstrap endpoint location within server.rs route registration
- Self-service check integration pattern (separate extractor, helper function, or inline in handlers)
- Whether to add a `RequireOwnership` helper alongside `RequirePermission` for self-service checks
- Frontend RBAC-gated navigation (sidebar visibility based on user permissions) — if touched, implement minimally

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Security & Architecture
- `claude_dev/design-document.md` -- Master architecture document; RBAC section with authorization algorithm, resource hierarchy, scope evaluation
- `.planning/REQUIREMENTS.md` REQ-4 -- RBAC Enforcement acceptance criteria (9 items)
- `.planning/ROADMAP.md` Phase 3 -- Scope definition and success criteria

### Existing Authorization Engine
- `crates/axiam-authz/src/engine.rs` -- `AuthorizationEngine` with `check_access()` method implementing the RBAC algorithm
- `crates/axiam-authz/src/lib.rs` -- Public API and `types` module (`AccessRequest`, `AccessDecision`)
- `crates/axiam-api-rest/src/authz.rs` -- Type-erased `AuthzChecker` trait, `RequirePermission` guard, `AuthzData` alias. Already built, currently unused by any handler

### Route Registration & Middleware
- `crates/axiam-api-rest/src/server.rs` -- All route registrations (60+ endpoints); where middleware is `.wrap()`'d
- `crates/axiam-api-rest/src/middleware/csrf.rs` -- Existing middleware pattern to follow (Transform/Service impl)
- `crates/axiam-api-rest/src/middleware/security_headers.rs` -- Another middleware pattern reference
- `crates/axiam-api-rest/src/extractors/auth.rs` -- `AuthenticatedUser` extractor (provides user_id, tenant_id, org_id)

### Domain Models
- `crates/axiam-core/src/models/` -- All domain model definitions (Permission, Role, Resource, Scope, User)
- `crates/axiam-core/src/repository.rs` -- Repository traits for all entities

### Prior Phase Context
- `.planning/phases/01-cookie-based-authentication/01-CONTEXT.md` -- Cookie auth decisions (JWT in cookies, CSRF pattern)
- `.planning/phases/02-security-headers-rate-limiting/02-CONTEXT.md` -- Rate limiting decisions, security headers middleware pattern

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` -- Layer structure, crate dependency graph, data flow
- `.planning/codebase/CONVENTIONS.md` -- Naming patterns, code style

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AuthorizationEngine` in `axiam-authz/src/engine.rs` -- Full RBAC engine with resource hierarchy, scope evaluation, group-based inheritance. Ready to use.
- `AuthzChecker` trait + `RequirePermission` guard in `axiam-api-rest/src/authz.rs` -- Type-erased wrapper and per-handler check mechanism. Built but unused.
- `AuthzData` type alias (`web::Data<Arc<dyn AuthzChecker>>`) -- Ready for injection into handlers.
- `CsrfMiddleware` in `middleware/csrf.rs` and `SecurityHeadersMiddleware` in `middleware/security_headers.rs` -- Patterns to follow for the new AuthzMiddleware.
- `AuthenticatedUser` extractor -- Already provides `user_id`, `tenant_id`, `org_id` from JWT cookie claims.
- `AxiamError::AuthorizationDenied` -- Error variant that maps to HTTP 403 via `ResponseError` impl.

### Established Patterns
- Actix-Web middleware registered via `.wrap()` in `server.rs` -- AuthzMiddleware follows the same pattern
- `FromRequest` extractors for dependency injection (AuthenticatedUser, TenantContext)
- Repository trait pattern: all data access through `web::Data<SurrealXxxRepository>` injected via app data
- JSON error responses via `AxiamApiError` -- already handles 401 and 403

### Integration Points
- `crates/axiam-api-rest/src/server.rs` -- AuthzMiddleware wraps here; bootstrap route registered here
- `crates/axiam-server/src/main.rs` -- Permission seeding runs here on startup; `AuthzChecker` instantiated and injected as app data
- `crates/axiam-db/src/migrations/` -- Permission seed migration or separate seeder function
- `frontend/src/` -- Sidebar navigation gating based on user permissions (minimal, if touched)

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- all recommended approaches selected with verb-based granularity. Standard IAM RBAC enforcement with defense-in-depth (middleware + per-handler checks).

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>

---

*Phase: 03-rbac-enforcement*
*Context gathered: 2026-04-09*
