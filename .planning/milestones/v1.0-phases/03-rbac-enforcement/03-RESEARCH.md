# Phase 3: RBAC Enforcement - Research

**Researched:** 2026-04-09
**Domain:** Actix-Web authorization middleware, RBAC enforcement, admin bootstrap, permission seeding
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**D-01:** Global authorization middleware (`AuthzMiddleware`) wraps all routes. Rejects requests unless the route is in the `PUBLIC_ALLOWLIST` OR the handler has set an `authz_checked` flag in request extensions.

**D-02:** `RequirePermission` guard (existing in `authz.rs`) remains the per-handler mechanism. After a successful check, it sets `authz_checked = true` in request extensions so the outer middleware knows authorization was performed.

**D-03:** HTTP status codes — **401 Unauthorized** when no JWT is present, **403 Forbidden** when JWT is valid but user lacks permission.

**D-04:** Public endpoint allowlist: `/auth/login`, `/auth/register`, `/auth/device`, `/health`, `/ready`, `/.well-known/openid-configuration`, `/oauth2/jwks`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/federation/*/oidc/callback`, `/federation/*/saml/acs`, `/federation/*/saml/metadata`, `/auth/password-reset/*`, `/auth/email/verify`, `/auth/email/resend`.

**D-05:** Verb-based granular permissions using `entity:action` format: `users:list`, `users:get`, `users:create`, `users:update`, `users:delete`.

**D-06:** Special admin actions use `:admin` suffix: `users:admin` (unlock, reset MFA for others).

**D-07:** All permissions auto-seeded into SurrealDB on server startup from a compile-time `PERMISSION_REGISTRY`. Uses UPSERT to avoid duplicates.

**D-08:** Integration test verifies every registered route has a matching permission in the registry.

**D-09:** Dedicated `POST /api/v1/admin/bootstrap` endpoint. Returns 404 after first admin is created.

**D-10:** Bootstrap request body: `{ email, password, username }`. `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var enforces email match if set.

**D-11:** Bootstrap does NOT issue a token — user must log in via `/auth/login`.

**D-12:** Bootstrap seeds 3 default roles: `super-admin` (ALL permissions), `admin` (all entity CRUD, no `admin:bootstrap`), `viewer` (all `:list` and `:get` permissions).

**D-13:** Self-service: `caller_user_id == target_user_id` check allows access without admin permission.

**D-14:** Self-service endpoints: own profile GET/PUT, own MFA operations, own audit logs, own certificates/PGP keys.

**D-15:** Self-service profile update allows email changes without verification enforcement (wired in Phase 5).

### Claude's Discretion

- Middleware implementation details (Transform/Service trait impl pattern in Actix-Web)
- Permission registry data structure (const array, lazy_static, or build-time macro)
- Exact public allowlist path matching strategy (prefix match, regex, or route-name based)
- Bootstrap endpoint location within server.rs route registration
- Self-service check integration pattern (separate extractor, helper function, or inline in handlers)
- Whether to add a `RequireOwnership` helper alongside `RequirePermission` for self-service checks
- Frontend RBAC-gated navigation (sidebar visibility based on user permissions) — if touched, implement minimally

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-4 | RBAC Enforcement — wire existing authorization engine to ALL REST API endpoints with default-deny | Fully covered: existing `AuthzChecker`, `RequirePermission`, `AuthzMiddleware` pattern, permission seeding, bootstrap flow, self-service checks, integration test architecture all researched |
</phase_requirements>

---

## Summary

Phase 3 wires the already-built `AuthorizationEngine` and `RequirePermission` guard to all 60+ REST API endpoints. The core RBAC logic (`axiam-authz`) is complete and unused — this phase is about plumbing, not algorithm design.

Three distinct workstreams:

1. **Middleware layer**: A new `AuthzMiddleware` (Transform/Service pattern, same as `CsrfMiddleware`) guards all routes globally. Public routes are exempted via path matching. Protected routes that skip `RequirePermission` are caught as a programming error (authz_checked flag not set → 403).

2. **Handler layer**: Every handler that is not on the public allowlist receives `authz: AuthzData` and calls `RequirePermission::new("entity:action", resource_id).check(&user, authz.get_ref().as_ref()).await?`. Self-service routes add a `caller_user_id == target_user_id` short-circuit before the authz check.

3. **Bootstrap and seeding**: A `seed_permissions()` function in `axiam-db` (or a new seeder module) runs at startup via SurrealQL UPSERT. A separate `POST /api/v1/admin/bootstrap` handler creates the first admin user + seeds the 3 default roles.

**Primary recommendation:** Follow the existing `CsrfMiddleware` Transform/Service pattern for `AuthzMiddleware`. Use a `const` array for `PERMISSION_REGISTRY`. Add a free function `is_self_service(caller_id, target_id)` used inline in handlers.

---

## Standard Stack

### Core (all existing — no new dependencies required)

| Library | Purpose | Status |
|---------|---------|--------|
| `actix-web` (workspace) | Transform/Service middleware traits, `Extensions`, `FromRequest` | Already present |
| `axiam-authz` | `AuthorizationEngine`, `AuthzChecker` trait, `AccessRequest`/`AccessDecision` | Already present, already wired to AMQP and gRPC |
| `axiam-api-rest` | `RequirePermission`, `AuthzData`, `AuthenticatedUser`, `AxiamApiError` | Already present, unused by handlers |
| `axiam-db` | `SurrealPermissionRepository`, `SurrealRoleRepository`, `SurrealUserRepository` | Already present |
| `axiam-core` | `PermissionRepository`, `RoleRepository`, `UserRepository` traits | Already present |

No new crate dependencies needed for this phase.

---

## Architecture Patterns

### Recommended Project Structure (additions only)

```
crates/axiam-api-rest/src/
├── middleware/
│   ├── csrf.rs           # existing
│   ├── security_headers.rs  # existing
│   └── authz.rs          # NEW: AuthzMiddleware
├── authz.rs              # existing: RequirePermission, AuthzChecker — extend with authz_checked flag
├── permissions.rs        # NEW: PERMISSION_REGISTRY const array
├── handlers/
│   ├── bootstrap.rs      # NEW: admin bootstrap handler
│   └── *.rs              # existing — add authz calls
crates/axiam-db/src/
└── seeder.rs             # NEW: seed_permissions() + seed_default_roles()
```

### Pattern 1: AuthzMiddleware (Transform/Service)

**What:** Global middleware that intercepts every request after route dispatch, checks if the path is in the public allowlist OR `authz_checked` extension is set. Rejects with 401 (no JWT) or 403 (JWT present but not checked) otherwise.

**Critical design note:** The middleware runs BEFORE the handler. It cannot know if the handler will set `authz_checked`. The correct approach is the two-phase model: middleware extracts the JWT (if any), checks the public allowlist. If the path is NOT public, it forwards to the handler. The handler must call `RequirePermission::check()` which sets `authz_checked = true` in request extensions. A post-handler check in the middleware catches any handler that forgot.

**Simpler alternative (recommended):** Since `RequirePermission::check()` already returns `Err(AxiamApiError)` on denial, the handler-layer enforcement IS the enforcement. The middleware only needs to: (a) reject unauthenticated requests to non-public paths with 401, and (b) inject the `AuthenticatedUser` into extensions for handler reuse. The `authz_checked` flag is defense-in-depth for CI integration test verification.

**Pattern (follows CsrfMiddleware exactly):**

```rust
// crates/axiam-api-rest/src/middleware/authz.rs
pub struct AuthzMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthzMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B>>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthzMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthzMiddlewareService { inner: service }))
    }
}

impl<S, B> Service<ServiceRequest> for AuthzMiddlewareService<S>
where ...
{
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path();
        if is_public(path) {
            // forward as-is
            return Box::pin(async move { Ok(fut.await?.map_into_left_body()) });
        }
        // Check JWT presence — extract user identity
        // If no JWT: reject 401
        // Else: forward; after response check authz_checked extension
        ...
    }
}
```

**Source:** Pattern validated against `crates/axiam-api-rest/src/middleware/csrf.rs` (verified in codebase).

### Pattern 2: PERMISSION_REGISTRY as const array

**What:** A compile-time `&[(&str, &str)]` array listing all `(action, description)` pairs. Seeder iterates it at startup.

**Why const array:** No runtime cost, no proc macros, no `lazy_static`. The registry is never modified at runtime. A `const` slice of tuples is the idiomatic Rust approach.

```rust
// crates/axiam-api-rest/src/permissions.rs
pub const PERMISSION_REGISTRY: &[(&str, &str)] = &[
    ("users:list",   "List users in tenant"),
    ("users:get",    "Get a specific user"),
    ("users:create", "Create a new user"),
    ("users:update", "Update a user"),
    ("users:delete", "Delete a user"),
    ("users:admin",  "Admin actions on users (unlock, reset MFA)"),
    ("groups:list",  "List groups"),
    // ... all entities
];
```

**Integration test:** Iterate `App`'s registered routes (via `actix-web` test infrastructure), cross-reference against `PERMISSION_REGISTRY`. Any route not in the public allowlist must have a corresponding permission.

### Pattern 3: Permission Seeding (UPSERT via raw SurrealQL)

**What:** At startup (in `axiam-server/src/main.rs`, after `run_migrations()`), call `seed_permissions(&db, tenant_id)` for each known tenant, or use a global permission seed that is tenant-agnostic.

**Key constraint:** `PermissionRepository::create()` will return `AlreadyExists` on re-run. The seeder must use SurrealDB's `UPSERT` statement (or `INSERT ... ON DUPLICATE KEY IGNORE` equivalent). Direct SurrealQL via `db.query()` with UPSERT bypasses the repository trait, which only has `create()`.

**Recommended approach:** Add `upsert_by_action()` to `PermissionRepository` trait OR use a free seeder function in `axiam-db` that runs raw SurrealQL:

```sql
UPSERT permissions SET
  tenant_id = $tenant_id,
  action = $action,
  description = $description,
  created_at = time::now(),
  updated_at = time::now()
WHERE action = $action AND tenant_id = $tenant_id;
```

**Important:** Permissions are currently tenant-scoped (see `Permission` model: `tenant_id: Uuid`). The seeder must run per-tenant OR permissions must be redesigned as system-level. For bootstrap, seed into the bootstrap tenant. For production, seed when a new tenant is created.

**Simpler alternative:** Seed permissions into a "system" tenant and make the auth engine check both system and tenant permissions. However, this contradicts the existing model — `AccessRequest` carries `tenant_id` and the engine filters by tenant. Stick with per-tenant seeding.

### Pattern 4: Admin Bootstrap Handler

**What:** `POST /api/v1/admin/bootstrap` — no `AuthenticatedUser` extractor (unauthenticated endpoint). Checks if any super-admin exists in the target tenant, if not creates user + seeds roles + assigns super-admin role.

**Return 404 after bootstrap:** Query users with super-admin role. If count > 0, return `AxiamError::NotFound` (maps to 404 per the existing `ResponseError` impl). This matches D-09.

**Note on tenant context:** Bootstrap needs a tenant_id to scope the admin user and roles. Options:
1. The first org+tenant is created at startup via another bootstrap step (or assumed to exist).
2. The bootstrap request body includes `org_slug` + `tenant_slug`.
3. A single "default" tenant is created during `run_migrations()`.

The CONTEXT.md is silent on this. Given multi-tenant design, the planner must decide: bootstrap request body should likely include `org_id` + `tenant_id` so the caller specifies the target context. Alternatively, bootstrap creates the org+tenant too (simpler for first run).

### Pattern 5: Self-Service Ownership Check

**What:** A helper function (not a trait or extractor) that short-circuits authorization for own-resource access:

```rust
// inline in handler or free function in authz.rs
fn is_own_resource(caller: &AuthenticatedUser, target_user_id: Uuid) -> bool {
    caller.user_id == target_user_id
}

// In handler:
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    path: web::Path<Uuid>,
    ...
) -> Result<HttpResponse, AxiamApiError> {
    let target_id = path.into_inner();
    if !is_own_resource(&user, target_id) {
        RequirePermission::new("users:get", /* resource_id */)
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }
    // proceed
}
```

**Resource ID question:** `RequirePermission::check()` requires a `resource_id: Uuid`. The RBAC engine uses this for hierarchical role resolution. For tenant-level endpoints that aren't scoped to a specific resource entity, a sentinel resource ID is needed — typically the tenant's root resource or a well-known UUID derived from the tenant_id. The planner must establish the convention (e.g., `Uuid::nil()` means "tenant root").

### Pattern 6: RequirePermission.check() sets authz_checked

**What:** Extend `RequirePermission::check()` to write a marker into `HttpRequest` extensions so `AuthzMiddleware` can verify that authorization was performed.

**Implementation:** `RequirePermission::check()` currently has signature `async fn check(&self, user: &AuthenticatedUser, authz: &dyn AuthzChecker) -> Result<(), AxiamApiError>`. It does not have access to the `HttpRequest`. Two options:

1. Pass `&HttpRequest` to `check()` — add it as a parameter (breaking change to existing call sites if any exist, but currently zero handlers use it so no breaking change).
2. Use a separate call `req.extensions_mut().insert(AuthzChecked)` in each handler after `RequirePermission::check()`.

Option 2 is simpler and keeps `RequirePermission` independent of Actix types.

### Anti-Patterns to Avoid

- **Using `AlreadyExists` error for duplicate permission seed:** The seeder must use UPSERT/INSERT-ignore, not trap errors from `create()`. Catching and ignoring `AlreadyExists` is fragile under concurrent startup.
- **Single global permission seed at first startup only:** Permissions must be seeded every startup (idempotent UPSERT) so adding new permissions in code automatically propagates to existing deployments.
- **Hardcoded resource UUID in permission check:** The authorization engine resolves resource hierarchy from `resource_id`. If all handlers pass `Uuid::nil()` as resource_id, hierarchy checking is skipped but the system still works for flat RBAC. Document this explicitly.
- **Bootstrap endpoint always returning 404:** D-09 says "returns 404 AFTER first admin is created." Before that, it returns 201 or appropriate success. The endpoint must be in the public allowlist during its active window.
- **Putting bootstrap in the public allowlist permanently:** Once an admin exists, the endpoint should also be in the public allowlist (no auth required to check), but the handler logic gates creation. The 404 response IS the "disabled" behavior.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Authorization decision | Custom permission check logic | `RequirePermission` + `AuthzChecker` | Already implements full RBAC with hierarchy, scopes, group inheritance |
| JWT extraction | Manual cookie/header parsing | `AuthenticatedUser` extractor | Already handles cookie + Bearer fallback, caches via `CachedUserIdentity` |
| HTTP error responses | Custom error serialization | `AxiamApiError` + `ResponseError` impl | Already maps `AuthorizationDenied` → 403, `AuthenticationFailed` → 401 |
| Middleware boilerplate | Raw `Service` impl from scratch | Copy `CsrfMiddleware` pattern | Transform + Service pattern is established in codebase |
| Permission UPSERT | Try/catch around `create()` | Raw SurrealQL UPSERT via `db.query()` | Correct concurrency semantics; `create()` will return `AlreadyExists` on restart |
| Role seeding | Runtime REST calls to role endpoints | Direct repository calls in seeder function | Simpler, no HTTP round-trip, testable in unit tests |

---

## Common Pitfalls

### Pitfall 1: AuthzMiddleware Resource ID Ambiguity

**What goes wrong:** `RequirePermission::check()` requires a `resource_id: Uuid`, but most handlers don't have a natural resource entity to check against. The RBAC engine queries `resource_repo.get_ancestors()` with this ID — if the UUID doesn't exist as a resource, the ancestor list is empty and only global roles apply.

**Why it happens:** The engine was designed for fine-grained resource-scoped RBAC. For coarse-grained endpoint-level authorization, the resource concept is not needed but the API requires it.

**How to avoid:** Establish a convention: use `Uuid::nil()` (all zeros) as the "tenant root" resource ID for endpoint-level checks. Global roles (is_global = true) will apply because the engine filters: `a.resource_id.is_none()` (global) OR matches the requested resource. When the request resource doesn't exist in the DB, ancestor lookup returns empty, but global roles still apply. This means global role assignments work correctly for all endpoint-level checks.

**Warning signs:** 403s for users who clearly have admin roles assigned → check resource_id passed to `RequirePermission::new()`.

### Pitfall 2: Permission Seeding is Tenant-Scoped

**What goes wrong:** `seed_permissions()` runs once at startup but new tenants created after startup don't have permissions seeded. The authz engine finds no matching permission grants and returns Deny for all actions.

**Why it happens:** The `Permission` model has `tenant_id: Uuid`. Permissions are data, not schema. They must be seeded per-tenant.

**How to avoid:** Hook `seed_permissions()` into the tenant creation path (in the `tenants::create` handler or in a `TenantService`). On startup, seed for all existing tenants. On new tenant creation, seed immediately.

**Warning signs:** Fresh-tenant users always get 403 on all operations.

### Pitfall 3: Bootstrap Endpoint Needs Its Own Tenant Context

**What goes wrong:** The bootstrap handler creates the first admin but doesn't know which tenant to scope them to. If the request body doesn't include tenant context, the handler has no `AuthenticatedUser` (it's an unauthenticated endpoint) and no `TenantContext` extractor.

**Why it happens:** All other handlers get tenant_id from `AuthenticatedUser.tenant_id`. Bootstrap is unauthenticated.

**How to avoid:** Bootstrap request body MUST include `org_id` + `tenant_id` (or slugs). The handler resolves them from the DB. If the org/tenant don't exist yet, bootstrap fails with 400. Document that org+tenant must be pre-created (e.g., via CLI or a separate setup step).

**Warning signs:** Panic or 500 in bootstrap handler when trying to access tenant context.

### Pitfall 4: Middleware Ordering

**What goes wrong:** `AuthzMiddleware` runs before or after `AuditMiddleware`, causing the `CachedUserIdentity` (set by audit middleware) to not be available in `AuthzMiddleware`'s JWT extraction.

**Why it happens:** `AuthenticatedUser::from_request()` checks `req.extensions().get::<Arc<CachedUserIdentity>>()` to reuse cached claims. If `AuditMiddleware` hasn't run yet, the cache is empty and `from_request` does fresh JWT validation.

**How to avoid:** Order matters: in `HttpServer::new()`, `.wrap()` calls are applied in REVERSE order (last wrap = outermost = runs first). `AuditMiddleware` should be outer (wraps first = added last in code). `AuthzMiddleware` should be inner (added first in code). But since `AuthzMiddleware` does its own JWT extraction (not relying on audit cache), ordering is less critical. Document the wrap order explicitly.

**Warning signs:** Double JWT parsing overhead (minor); if audit middleware has side effects on extensions, ordering must be verified.

### Pitfall 5: Public Allowlist Path Matching for Parameterized Routes

**What goes wrong:** The allowlist contains `/federation/*/oidc/callback` (wildcard pattern) but the actual route path is `/api/v1/federation/oidc/callback`. String matching fails.

**Why it happens:** Routes in `server.rs` are registered under `/api/v1/` scope, but the CONTEXT.md allowlist uses paths without the prefix in some cases.

**How to avoid:** Verify all allowlist paths against actual routes in `server.rs`. The auth routes are under `/auth/` (CSRF middleware wraps them), the API routes are under `/api/v1/`. Use prefix matching for OAuth2 (`starts_with("/oauth2/")`), exact matching for specific paths. Wildcards require simple glob-style matching (split on `*`, check prefix/suffix).

**Warning signs:** Public endpoints returning 401 in tests.

### Pitfall 6: Integration Test — Route Enumeration

**What goes wrong:** The integration test that "verifies every registered route has an authorization check" has no reliable way to enumerate registered routes from outside the `App` in Actix-Web.

**Why it happens:** Actix-Web does not expose a public route registry for introspection.

**How to avoid:** Maintain a separate compile-time `ROUTE_PERMISSION_MAP: &[(&str, &str, &str)]` — `(method, path, permission)` — and test that: (1) every entry in `ROUTE_PERMISSION_MAP` has a matching entry in `PERMISSION_REGISTRY`, and (2) every non-public path in `ROUTE_PERMISSION_MAP` maps to a permission. This is a static analysis test, not a runtime route-inspection test.

---

## Code Examples

### Example 1: AuthzMiddleware call structure (from CsrfMiddleware)

```rust
// Source: crates/axiam-api-rest/src/middleware/csrf.rs (verified)
impl<S, B> Service<ServiceRequest> for AuthzMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B>>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_owned();
        if is_public_path(&path) {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                Ok(fut.await?.map_into_left_body())
            });
        }
        // Check JWT — if missing, reject 401
        let has_token = req.cookie("axiam_access").is_some()
            || req.headers().contains_key("Authorization");
        if !has_token {
            let error: Error = AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "authentication required".into(),
            }).into();
            return Box::pin(async move {
                Ok(req.error_response(error).map_into_right_body())
            });
        }
        // Forward — per-handler RequirePermission does authz
        let fut = self.inner.call(req);
        Box::pin(async move {
            Ok(fut.await?.map_into_left_body())
        })
    }
}
```

### Example 2: Handler with RequirePermission (from middleware_test.rs)

```rust
// Source: crates/axiam-api-rest/tests/middleware_test.rs (verified)
async fn guarded_endpoint(
    user: AuthenticatedUser,
    authz: web::Data<Arc<dyn AuthzChecker>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let resource_id = path.into_inner();
    RequirePermission::new("read", resource_id)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"})))
}
```

### Example 3: Seeder function pattern (direct SurrealQL)

```rust
// Seeder in crates/axiam-db/src/seeder.rs
pub async fn seed_permissions<C: Connection>(
    db: &Surreal<C>,
    tenant_id: Uuid,
    registry: &[(&str, &str)],
) -> Result<(), DbError> {
    for (action, description) in registry {
        let id = Uuid::new_v4().to_string();
        let tid = tenant_id.to_string();
        db.query(
            "UPSERT type::record('permission', $id) CONTENT {
                tenant_id: $tenant_id,
                action: $action,
                description: $description,
                created_at: time::now(),
                updated_at: time::now()
            } WHERE action = $action AND tenant_id = $tenant_id"
        )
        .bind(("id", id))
        .bind(("tenant_id", tid))
        .bind(("action", action.to_string()))
        .bind(("description", description.to_string()))
        .await
        .map_err(|e| DbError::Migration(e.to_string()))?;
    }
    Ok(())
}
```

**Note:** SurrealDB UPSERT with WHERE condition may need verification — the SurrealQL UPSERT syntax is `UPSERT record SET ...`, not `UPSERT ... WHERE`. Alternative: use `INSERT ... ON DUPLICATE UPDATE` if supported, or `SELECT` then `CREATE IF NOT EXISTS`. Check SurrealDB v3 docs for idempotent insert pattern. A safe fallback is `list()` then create only missing permissions.

### Example 4: Bootstrap handler skeleton

```rust
// crates/axiam-api-rest/src/handlers/bootstrap.rs
#[derive(Debug, Deserialize)]
pub struct BootstrapRequest {
    pub org_id: Uuid,
    pub tenant_id: Uuid,
    pub email: String,
    pub username: String,
    pub password: String,
}

pub async fn bootstrap<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    role_repo: web::Data<SurrealRoleRepository<C>>,
    body: web::Json<BootstrapRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // Check AXIAM_BOOTSTRAP_ADMIN_EMAIL env gate
    if let Ok(expected) = std::env::var("AXIAM_BOOTSTRAP_ADMIN_EMAIL") {
        if req.email != expected {
            return Err(AxiamError::AuthorizationDenied {
                reason: "email does not match AXIAM_BOOTSTRAP_ADMIN_EMAIL".into(),
            }.into());
        }
    }

    // Check if super-admin role already has any users
    // If so, return 404 (endpoint disabled)
    // ... (count admins via role assignment query)

    // Create user, seed roles, assign super-admin
    // Return 201 Created (no token)
    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Admin user created. Login via /auth/login."
    })))
}
```

### Example 5: AuthzData injection in main.rs (existing pattern)

```rust
// Source: crates/axiam-server/src/main.rs (verified — AuthorizationEngine already created for AMQP)
// In Phase 3, create a REST-facing AuthzChecker and inject as app_data:
let rest_engine: Arc<dyn AuthzChecker> = Arc::new(
    axiam_authz::AuthorizationEngine::new(
        role_repo.clone(),
        permission_repo.clone(),
        resource_repo.clone(),
        scope_repo.clone(),
        group_repo.clone(),
    )
);
// In HttpServer::new() closure:
.app_data(web::Data::new(rest_engine.clone()))
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in (`#[actix_web::test]`, `#[tokio::test]`) |
| Config file | `Cargo.toml` (dev-dependencies) |
| Quick run command | `cargo test -p axiam-api-rest rbac` |
| Full suite command | `cargo test -p axiam-api-rest` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-4.1 | Unauthenticated request → 401 | Integration | `cargo test -p axiam-api-rest rbac::unauthenticated_returns_401` | ❌ Wave 0 |
| REQ-4.2 | Authenticated, no permission → 403 | Integration | `cargo test -p axiam-api-rest rbac::no_permission_returns_403` | ❌ Wave 0 |
| REQ-4.3 | Self-service owner access → 200 | Integration | `cargo test -p axiam-api-rest rbac::self_service_owner_allowed` | ❌ Wave 0 |
| REQ-4.4 | Self-service non-owner → 403 | Integration | `cargo test -p axiam-api-rest rbac::self_service_nonowner_denied` | ❌ Wave 0 |
| REQ-4.5 | Bootstrap creates first admin | Integration | `cargo test -p axiam-api-rest rbac::bootstrap_creates_admin` | ❌ Wave 0 |
| REQ-4.6 | Bootstrap disabled after first admin | Integration | `cargo test -p axiam-api-rest rbac::bootstrap_returns_404_after_admin` | ❌ Wave 0 |
| REQ-4.7 | Public endpoints reachable without auth | Integration | `cargo test -p axiam-api-rest rbac::public_routes_no_auth_required` | ❌ Wave 0 |
| REQ-4.8 | PERMISSION_REGISTRY covers all routes | Static/unit | `cargo test -p axiam-api-rest rbac::all_routes_have_permission` | ❌ Wave 0 |
| REQ-4.9 | Admin can list users | Integration | `cargo test -p axiam-api-rest rbac::admin_can_list_users` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p axiam-api-rest`
- **Per wave merge:** `cargo test -p axiam-api-rest && cargo test -p axiam-authz`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/axiam-api-rest/tests/rbac_test.rs` — covers REQ-4.1 through REQ-4.9
- [ ] Helper in `rbac_test.rs`: `setup_db_with_authz()` that seeds roles+permissions and returns authz engine
- [ ] `crates/axiam-api-rest/tests/bootstrap_test.rs` — covers REQ-4.5 and REQ-4.6

---

## Open Questions

1. **Resource ID for endpoint-level permission checks**
   - What we know: `RequirePermission::new(action, resource_id)` — the engine does ancestor lookup on `resource_id`. For endpoints without a natural resource entity (e.g., list users), a sentinel is needed.
   - What's unclear: Convention for sentinel resource ID. `Uuid::nil()` would cause `resource_repo.get_ancestors()` to return empty list, and only global roles apply. This is correct behavior for global admin permissions.
   - Recommendation: Use `Uuid::nil()` as convention for "tenant root / global resource." Document this in a code comment. Global role assignments (is_global = true) bypass resource lookup entirely.

2. **Permission seeding scope — system-wide vs per-tenant**
   - What we know: `Permission` model has `tenant_id: Uuid`. Engine filters by tenant_id.
   - What's unclear: Should permissions be system-level (no tenant) or per-tenant? The existing design is per-tenant.
   - Recommendation: Keep per-tenant. Seed permissions in `seed_permissions(db, tenant_id, PERMISSION_REGISTRY)` called: (a) at startup for all existing tenants, (b) in tenant create handler for new tenants. This is more work but correct.

3. **Bootstrap request body — how to specify tenant**
   - What we know: All handlers get tenant context from `AuthenticatedUser`. Bootstrap is unauthenticated.
   - What's unclear: Does bootstrap create org+tenant, or does it require pre-existing org+tenant?
   - Recommendation: Bootstrap request body includes `{ org_id, tenant_id, email, username, password }`. Org and tenant must pre-exist. For a true first-run experience, a separate CLI/docs step creates org+tenant first. This is simpler than bootstrap creating org+tenant (avoids bootstrap needing OrgRepository + TenantRepository injection).

4. **SurrealDB idempotent INSERT syntax for v3**
   - What we know: From MEMORY.md: SurrealDB v3 quirks documented but not specifically UPSERT pattern for "insert if not exists."
   - What's unclear: Whether `UPSERT ... WHERE` works or if we need `INSERT IGNORE` or check-then-insert.
   - Recommendation: Implement seeder as: `list()` all existing permissions → filter out actions already in DB → `create()` only new ones. This uses existing repository traits and avoids raw SurrealQL UPSERT pitfalls. Lower risk than raw query.

---

## Environment Availability

Step 2.6: SKIPPED — this phase is purely code/logic changes. External dependencies (SurrealDB, RabbitMQ) are runtime dependencies already proven working in prior phases. No new external tools are introduced.

---

## Project Constraints (from CLAUDE.md)

- **Rust edition 2024, MSRV 1.93** — native async fn in traits, no `async_trait` crate
- **rustfmt.toml max_width = 100** — all new code formatted to 100 chars
- **Run `cargo fmt` and `cargo clippy -D warnings`** on all changed crates before commit/push
- **Build scope:** Only build/check specific crates with `-p`, never the whole workspace
- **TODOs must be tracked** — every TODO in code needs a corresponding T19.x task in the roadmap
- **Signed commits** required before proceeding to next task
- **Feature branch** `feature/full-review` is current (per git status)
- **SurrealDB v3 quirks:** `bind()` requires owned values; `type::record()` not RELATE syntax; `.check()` takes ownership
- **Error handling:** Use `?` operator; `AxiamError::AuthorizationDenied` maps to HTTP 403, `AxiamError::AuthenticationFailed` maps to HTTP 401 — already correct per `AxiamApiError::status_code()`

---

## Sources

### Primary (HIGH confidence — verified in codebase)

- `crates/axiam-api-rest/src/middleware/csrf.rs` — Transform/Service middleware pattern (verified)
- `crates/axiam-api-rest/src/authz.rs` — `AuthzChecker`, `RequirePermission`, `AuthzData` (verified)
- `crates/axiam-api-rest/src/server.rs` — All 60+ route registrations, middleware wrap pattern (verified)
- `crates/axiam-api-rest/src/error.rs` — Error → HTTP status mapping (verified: 401/403 correct)
- `crates/axiam-api-rest/src/extractors/auth.rs` — `AuthenticatedUser` extractor, JWT+cookie extraction (verified)
- `crates/axiam-authz/src/engine.rs` — `AuthorizationEngine::check_access()` algorithm (verified)
- `crates/axiam-server/src/main.rs` — Startup sequence, repository injection, middleware registration order (verified)
- `crates/axiam-core/src/repository.rs` — `PermissionRepository`, `RoleRepository`, `UserRepository` traits (verified)
- `crates/axiam-core/src/models/permission.rs` — `Permission` model with `tenant_id` field (verified)
- `crates/axiam-api-rest/tests/middleware_test.rs` — Integration test pattern for RequirePermission (verified)
- `.planning/phases/03-rbac-enforcement/03-CONTEXT.md` — All locked decisions D-01 through D-15 (verified)

### Secondary (MEDIUM confidence)

- MEMORY.md — SurrealDB v3 quirks (project-specific verified learnings)
- `.planning/REQUIREMENTS.md` REQ-4 acceptance criteria (9 items)
- `.planning/codebase/CONVENTIONS.md` — Naming, error handling, derive patterns

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in workspace, no new dependencies
- Architecture patterns: HIGH — verified against actual codebase (middleware pattern, handler pattern, repository pattern)
- Pitfalls: HIGH — derived from direct code reading plus SurrealDB v3 quirks in MEMORY.md
- Open questions: MEDIUM — require planner decisions, not research gaps

**Research date:** 2026-04-09
**Valid until:** 2026-05-09 (stable domain — Actix-Web middleware API is stable)
