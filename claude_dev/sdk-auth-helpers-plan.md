# SDK Declarative Authorization Helpers — Implementation Plan

> **Status: PLAN — not yet implemented.**
> Scope: all seven client SDKs (`axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
> `axiam-java-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`, `axiam-go-sdk`) plus a contract
> amendment in this repository (`sdks/CONTRACT.md`).
> Each per-SDK section below is sized to be one executable task in a follow-up run.

## 1. Goal

Every SDK today ships the CONTRACT §10 middleware/route-guard (request authentication:
extract credential → verify JWT locally via JWKS → inject identity → 401/403). What is
missing is the **declarative, per-endpoint authorization layer** on top of it: a macro /
annotation / attribute / decorator / wrapper that a consuming application places directly
on a handler, controller method, or function to require a specific AXIAM permission —
without hand-writing `check_access(...)` calls in every handler body.

Target developer experience (canonical semantics, per-language syntax):

```
Rust        #[require_access(action = "read", resource_param = "id")]
TypeScript  router.get('/docs/:id', requireAccess(guard, 'read', fromParam('id')), handler)
Python      @app.get(...)  ...  user = Depends(require_access(verifier, tenant, client, "read", resource_param="doc_id"))
Java        @AxiamRequireAccess(action = "read", resourceParam = "id")
C#          [AxiamAccess("read", ResourceRouteParam = "id")]
PHP         #[RequireAccess(action: 'read', resourceParam: 'id')]
Go          mux.Handle("/docs/{id}", middleware.RequireAccess(checker, "read", middleware.ResourceFromPath("id"))(handler))
```

Every language in the matrix supports a first-class mechanism for this (proc macros,
stage-3 decorators, annotations + interceptor, attributes + policy, PHP 8 attributes +
reflection). Go is the one language with no annotation-like feature; there the idiomatic
equivalent is a per-route wrapper function, which we provide under the same canonical
name.

## 2. Current state (surveyed 2026-07-16)

| SDK | §10 guard in place | Identity injected as | Declarative helper today |
|-----|--------------------|-----------------------|--------------------------|
| Rust (`axiam-sdk` crate, single crate + empty `[workspace]`, edition 2021, MSRV 1.88) | Actix `FromRequest` extractor `AxiamUser { user_id, tenant_id, roles }` (`src/middleware/actix.rs`, feature `actix`) | handler parameter | **None** — no `macro_rules!`, no proc-macro crate |
| TypeScript (`axiam-sdk` npm, TS ~5.9, subpath exports incl. `./middleware`) | `axiamMiddleware()` (Express `req.axiamUser`) + `axiamPlugin` (Fastify `preHandler`), shared `authenticateRequest` in `src/middleware/verifyCore.ts`, identity `AxiamIdentity { userId, tenantId, roles }` | request property | **None** — decorators not enabled in tsconfig, no NestJS code |
| Python (`axiam-sdk` PyPI, ≥3.10, extras `fastapi`/`django`) | FastAPI `require_authenticated_user(...)` dependency factory (`src/axiam_sdk/fastapi/__init__.py:134`) + Django `AxiamAuthMiddleware` (`src/axiam_sdk/django/middleware.py:190`), both yield `AxiamUser(user_id, tenant_id, roles)` | `Depends` return value / `request.axiam_user` | **None** — no auth decorators |
| Java (`io.github.ilpanich:axiam-sdk`, Java 21, Spring optional/provided) | `AxiamAuthenticationFilter extends OncePerRequestFilter` + `AxiamAutoConfiguration` (`src/main/java/io/axiam/sdk/spring/`), identity = `UsernamePasswordAuthenticationToken` on `SecurityContextHolder` | SecurityContext principal + authorities | **None** — no `@interface` declarations, no AOP |
| C# (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`, net8.0) | `AxiamAuthMiddleware` sets `ClaimsPrincipal` (claims `user_id`, `tenant_id`, roles); **plus** `AxiamPolicyProvider`/`AxiamPolicyHandler`/`AxiamRequirement` already resolve `[Authorize(Policy = "resource:action")]` dynamically and call `Authz.CheckAccessAsync(...)` with route value `"id"` | `HttpContext.User` | **Partial** — magic-string policy names work; no typed attribute, no scope support, route param hardcoded to `"id"` |
| PHP (`axiam/axiam-sdk`, ≥8.1, Laravel provider + Symfony bundle) | Laravel `AxiamMiddleware` + `AxiamGate`; Symfony `AxiamAuthSubscriber` (kernel.request) + `AxiamVoter`; identity in request attribute `axiam_user` | request attribute | **None** — zero `#[...]` attribute classes defined (AxiamVoter docblock merely *mentions* Symfony's `#[IsGranted]`) |
| Go (`github.com/ilpanich/axiam-go-sdk`, go 1.25) | `middleware.Middleware(verifier, tenant, opts...) func(http.Handler) http.Handler` (`middleware/nethttp.go:81`), identity via `middleware.UserFromContext(ctx)` → `User{UserID, TenantID, Roles}` | `context.Context` value | **None** — net/http only, no per-route permission wrapper |

Common properties already shared by all seven §10 guards (the helpers MUST preserve
them): Bearer-header-then-`axiam_access`-cookie extraction, local JWKS verification
(EdDSA), cross-tenant claim check, §3a CSRF double-submit for cookie credentials,
standardized JSON error body `{ "error": ..., "message": ... }`, 401 =
`authentication_failed` / 403 = `authorization_denied`, no raw token in errors or logs.

## 3. Cross-language design (the part that must be identical everywhere)

### 3.1 Canonical helper vocabulary — proposed CONTRACT.md §11

Two mandatory helpers plus one optional local helper, added to the §1-style naming map:

| Canonical operation | Semantics |
|---------------------|-----------|
| `require_auth` | Endpoint requires an authenticated AXIAM identity. Pure sugar over the §10 guard for frameworks where the guard is opt-in per route rather than global. 401 on failure. |
| `require_access(action, resource[, scope])` | Endpoint requires the **authenticated caller** to pass an AXIAM authorization check for `action` on a resource resolved from the request. 401 if unauthenticated, 403 if denied. Argument order follows §1: action before resource, always. |
| `require_role(role...)` *(optional, MAY)* | Local check that the verified token's `roles` contain at least one of the given roles. No server round-trip. Cheaper but coarser than `require_access`; documented as NOT a substitute for resource-level checks. 403 on failure. |

Per-language naming map (follows each language's §1 casing convention):

| Canonical | Rust | TypeScript | Python | Java | C# | PHP | Go |
|-----------|------|------------|--------|------|----|----|----|
| require_auth | `#[require_auth]` | `requireAuth(...)` | `require_authenticated_user` (exists, unchanged) / `@require_auth` (Django) | `@AxiamRequireAuth` | `[Authorize]` (framework-native, documented) | `#[RequireAuth]` | `middleware.RequireAuth(...)` |
| require_access | `#[require_access(...)]` | `requireAccess(...)` / `@RequireAccess()` (NestJS) | `require_access(...)` (FastAPI dep) / `@require_access` (Django) | `@AxiamRequireAccess(...)` | `[AxiamAccess(...)]` | `#[RequireAccess(...)]` | `middleware.RequireAccess(...)` |
| require_role | `#[require_role(...)]` | `requireRole(...)` | `require_role(...)` / `@require_role` | `@AxiamRequireRole(...)` | `[Authorize(Roles = ...)]` (framework-native, documented) | `#[RequireRole(...)]` | `middleware.RequireRole(...)` |

### 3.2 Semantics (normative, identical in all SDKs)

1. **Composition with the §10 guard.** `require_access` runs strictly *after*
   authentication. If no verified identity is present in the request context, the helper
   returns 401 (`authentication_failed`) — it never attempts its own token extraction,
   so the §10 verification path (JWKS, tenant check, CSRF) is never duplicated or
   bypassed.
2. **Subject propagation.** The check is made for the *request's* authenticated user,
   not for the application's own SDK session: the helper passes
   `subject_id = <authenticated user_id>` to `check_access`/`batch_check`. This matters
   because the app's `AxiamClient` typically holds a service-account session; omitting
   `subject_id` would check the service account's permissions instead of the end
   user's. (The C# `AxiamPolicyHandler` already does exactly this — it is the reference
   behavior.)
3. **Resource resolution.** The resource id is a UUID resolved from the request, in
   order of precedence:
   a. explicit static `resource_id` argument (UUID literal) — for singleton resources;
   b. `resource_param` — the name of a path/route parameter whose value is the UUID;
   c. a language-idiomatic resolver callback (`fn(request) -> Uuid` or equivalent) for
      anything else (body fields, headers, composite lookups).
   A missing or unparseable resource value is a **400-equivalent programming error**
   surfaced as the framework's bad-request response (400), never a silent allow, never
   `Guid.Empty`/nil-UUID fallback (the current C# handler's `Guid.Empty` fallback is
   fixed as part of this work).
4. **Scope.** Optional `scope` argument, passed through to `check_access` verbatim.
5. **Error mapping** (extends the §10 table, same JSON body shape):
   - unauthenticated → 401 `authentication_failed`
   - check returns `allowed = false`, or server 403 → 403 `authorization_denied`
   - unresolvable resource id → 400 `invalid_request`
   - `NetworkError` while calling the authz endpoint → **fail closed** with 503
     `authz_unavailable` (deny; never allow on transport failure; never retry beyond the
     SDK's existing bounded read-only retry policy)
6. **No decision caching.** Helpers MUST NOT cache allow/deny decisions (consistent
   with §10's TTL rule and the existing C# handler's fresh-check-per-request behavior).
   Batch/page-level optimization stays the application's job via `batch_check`.
7. **Transport.** Helpers call the SDK's existing `check_access` surface (REST by
   default; gRPC where the SDK's dispatcher already prefers it, e.g. PHP). No new
   transport code.
8. **Redaction.** Deny/error paths MUST NOT log or echo the token, and SHOULD log the
   denied `action` + `resource_id` at debug level only (consistent with §2 rules).
9. **`require_role` is local.** It reads the verified claims already in the request
   context; it never calls the server. Docs in every SDK must state that role names are
   tenant-defined and that `require_access` is the authoritative check.

### 3.3 Contract change (this repository — do first)

- Add **§11 "Declarative Authorization Helpers"** to `sdks/CONTRACT.md` containing
  3.1 + 3.2 above (naming map, semantics, error table), marked as a **SHOULD**-level
  requirement for v1.0 (helpers are additive API; SDKs remain conformant to §1–§10
  without them, so this does not retroactively break the "conforms to §1–§10"
  statements — READMEs will be updated to "§1–§11" as each SDK lands its helpers).
- Record the addition in the Breaking Changes Log as **non-breaking/additive**.
- Re-sync the updated `CONTRACT.md` into all seven SDK repos (each vendors a copy at
  its root) — do this as the first commit *of each per-SDK task* so the vendored copy
  and the implementation land together.

**Commit (axiam repo):** `docs(contract): add §11 declarative authorization helpers`

## 4. Per-SDK implementation plans

Order within every SDK task: (1) re-sync vendored `CONTRACT.md`; (2) implement; (3)
tests; (4) example; (5) README + CHANGELOG. Effort: S ≈ half session, M ≈ one session,
L ≈ one full session or slightly more.

### 4.1 Rust — proc-macro attributes + programmatic guard (L)

The only SDK needing a new crate: proc macros cannot live in a normal crate.

- **New crate `axiam-sdk-macros`** (proc-macro = true) as a workspace member next to
  the existing single crate (the root `Cargo.toml` already has an empty `[workspace]`
  table to extend). Published separately, version-locked to `axiam-sdk`; re-exported
  from `axiam-sdk` behind a new feature `macros = ["dep:axiam-sdk-macros", "actix"]`
  so users write `use axiam_sdk::require_access;`.
- **`#[require_access(action = "read", resource_param = "id", scope = "…")]`**
  (also accepts `resource_id = "<uuid literal>"` or `resolver = path::to::fn`):
  expands the annotated Actix handler `async fn` into a wrapper that
  1. adds an `AxiamUser` parameter (existing extractor → 401 path already handled),
  2. reads `web::Data<AxiamClient>` from app data (compile-time-checked expansion,
     runtime 500 with clear message if the client is not registered),
  3. parses the route param into `Uuid` (400 on failure),
  4. calls `check_access(action, resource_id, scope)` with
     `subject_id = Some(user.user_id)` — requires threading `subject_id` through the
     REST helper, which `AccessCheckRequest` already supports,
  5. maps deny → `AxiamExtractorError(Authz)` (403), network → new 503 response per
     §11.
- **`#[require_auth]`**: expands to injecting the `AxiamUser` extractor only.
- **`#[require_role("admin", …)]`**: local check against `AxiamUser.roles`.
- **Programmatic fallback** for non-macro users: `middleware::RequireAccess` builder
  usable as an explicit guard call inside handlers (this is also what the macro
  expands to, keeping the macro thin and testable).
- **Tests:** `tests/macro_require_access_test.rs` (wiremock-backed actix test app:
  allow, deny→403, unauthenticated→401, bad uuid→400, network→503, subject_id
  asserted on the wire), plus `trybuild` UI tests for macro misuse (missing action,
  both resource_id and resource_param, non-async fn).
- **Example:** extend `examples/actix_route_guard.rs` (required-features
  `actix,macros`).
- **Commit:** `feat(macros): add #[require_access]/#[require_auth]/#[require_role] actix helpers (CONTRACT §11)`
- Note for executor: repo CI and local builds follow the axiam sandbox disk-hygiene
  rules (scoped `cargo test -p`, `cargo clean` between steps).

### 4.2 TypeScript — route-guard factories + stage-3 decorators + NestJS module (M/L)

Two tiers, because Express/Fastify are function-composition frameworks (decorators are
the wrong shape there) while NestJS is where decorators actually pay off.

- **Tier 1 (mandatory) — new `./middleware` exports** (same subpath, no new entry
  needed): `requireAuth(session)`, `requireAccess(session, action, resource, opts?)`,
  `requireRole(session, ...roles)` returning an Express `RequestHandler` and a
  Fastify `preHandler`-compatible hook (mirror the existing dual
  `axiamMiddleware`/`axiamPlugin` split: `requireAccess` / `requireAccessHook`).
  `resource` accepts `fromParam('id')`, a literal UUID string, or
  `(req) => string`. Needs a small extension of `VerifiableSession` to carry an
  authz-capable client (`checkAccess`) — add `authzClient?: AuthzChecker` to the
  session type; helpers throw at construction if absent. Reuse `AxiamIdentity`
  already injected by the base middleware; if `req.axiamUser` is absent, respond 401
  (base middleware not installed or unauthenticated).
- **Tier 2 (optional subpath `./nestjs`)** — new tsup entry + subpath export:
  `@RequireAccess('read', { param: 'id' })` metadata decorator + `AxiamGuard`
  (`CanActivate`) reading the metadata via `Reflector`. Peer deps
  `@nestjs/common`/`@nestjs/core` (optional, like express/fastify today), added to
  tsup `external`. Uses NestJS's own decorator machinery, so the SDK's tsconfig stays
  free of `experimentalDecorators` (only the consuming Nest app enables it, which it
  already does by being a Nest app). If maintenance budget is a concern this tier can
  be deferred — it is additive and independently shippable.
- **Tests:** `test/middleware/requireAccess.express.test.ts`, `.fastify.test.ts`
  (msw-mocked authz endpoint: allow/deny/unauth/bad-resource/network→503,
  subjectId on the wire), `test/nestjs/guard.test.ts` (Tier 2).
- **Examples:** extend `examples/express-app.ts` and `examples/fastify-app.ts`; add
  `examples/nestjs-app.ts` (Tier 2).
- **Commit:** `feat(middleware): add requireAuth/requireAccess/requireRole route guards (CONTRACT §11)`
  (+ `feat(nestjs): add AxiamGuard and @RequireAccess decorator` if Tier 2 ships).

### 4.3 Python — FastAPI dependency factory + Django view decorator (M)

- **FastAPI (`src/axiam_sdk/fastapi/__init__.py`):**
  `require_access(verifier, configured_tenant, client, action, *, resource_param=None, resource_id=None, resolver=None, scope=None)`
  → returns an async dependency that composes the existing
  `require_authenticated_user` logic (refactor its body into a shared internal
  `_authenticate(request)` so both factories use one code path), resolves the resource
  from `request.path_params[resource_param]`, calls
  `client.check_access(...)`/`await` on `AsyncAxiamClient` (accept both; prefer
  requiring `AsyncAxiamClient` since FastAPI is async — decision recorded in §6),
  raises `HTTPException(403/401/400/503)` per §11, and returns the `AxiamUser` so
  handlers keep the identity. Also `require_role(verifier, configured_tenant, *roles)`
  (local, no client needed).
- **Django (`src/axiam_sdk/django/decorators.py`, new):** `@require_auth`,
  `@require_access(client, action, resource_param="pk", scope=None)`,
  `@require_role(*roles)` view decorators that read `request.axiam_user` (set by the
  existing `AxiamAuthMiddleware`; if attribute missing → 401 JSON response with a
  hint that the middleware is not installed). Sync client here (`AxiamClient`);
  async-view support via `asgiref.sync.iscoroutinefunction` branch mirroring the
  middleware's dual-mode pattern.
- **Tests:** `tests/test_fastapi_require_access.py`,
  `tests/test_django_decorators.py` (respx-mocked authz endpoint; the standard §11
  matrix: allow/deny/unauth/bad-uuid/network-fail-closed/subject_id asserted; keep
  coverage ≥ 96 gate green).
- **Examples:** extend `examples/fastapi_dependency.py` and
  `examples/django_middleware.py`.
- **Commit:** `feat(integrations): add require_access/require_role helpers for FastAPI and Django (CONTRACT §11)`

### 4.4 Java — annotations + Spring HandlerInterceptor (M/L)

- **Annotation types (framework-free, `io.axiam.sdk.annotations`, new package):**
  `@AxiamRequireAuth`, `@AxiamRequireAccess(action, resourceParam default "id", resourceId default "", scope default "")`,
  `@AxiamRequireRole(String[] value)` — `@Retention(RUNTIME)`, `@Target({METHOD, TYPE})`.
  Living in the core jar keeps them usable by any future non-Spring integration.
- **Spring enforcement (`io.axiam.sdk.spring.AxiamAuthorizationInterceptor`, new):**
  a `HandlerInterceptor` that inspects `HandlerMethod` for the annotations
  (method-level overrides type-level), pulls the authenticated principal from
  `SecurityContextHolder` (present when `AxiamAuthenticationFilter` accepted the
  request; otherwise 401), resolves the resource UUID from
  `HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE` path variables, and calls
  `AxiamClient.checkAccess(action, resourceId, scope)` with the subject id — this
  requires adding a `subjectId` overload to `checkAccess`/`AccessCheck` in
  `AxiamClient` (REST body already supports it server-side; keep existing overloads).
  Chosen over an AspectJ aspect deliberately: no new dependency, no proxying
  surprises, works on plain `@Controller` methods; a method-security
  (`@EnableMethodSecurity` authorization manager) variant is noted as a possible
  follow-up, not in scope.
  Registered by `AxiamAutoConfiguration` via a `WebMvcConfigurer`
  (`@ConditionalOnMissingBean`, `@ConditionalOnClass(HandlerInterceptor.class)`),
  requires an `AxiamClient` bean (auto-config already can build one from
  `axiam.base-url`/`axiam.tenant-id`).
- **Tests:** `spring/AxiamAuthorizationInterceptorTest` (MockMvc + mockwebserver:
  §11 matrix incl. type-level annotation, missing path variable → 400, network → 503)
  and an auto-config wiring test; JaCoCo ≥ 0.92 gate stays green.
- **Example:** add an annotated controller to `examples/spring-boot-app`
  (`@AxiamRequireAccess(action = "read", resourceParam = "id")` on
  `GET /documents/{id}`) + integration test.
- **Commit:** `feat(spring): add @AxiamRequireAccess/@AxiamRequireAuth/@AxiamRequireRole with enforcement interceptor (CONTRACT §11)`

### 4.5 C# — typed attribute over the existing policy infrastructure (S/M)

C# already has 80% of this (policy provider + handler + result-handler). Work is:

- **`AxiamAccessAttribute` (`Axiam.Sdk.AspNetCore/AxiamAccessAttribute.cs`, new):**
  `sealed class AxiamAccessAttribute : AuthorizeAttribute` with ctor
  `(string action, string? resource = null)` and properties `Scope`,
  `ResourceRouteParam` (default `"id"`); it serializes itself into a structured policy
  name (e.g. `axiam::<action>::<resource>::<scope>::<param>`) that
  `AxiamPolicyProvider` learns to parse alongside the existing single-colon
  `"resource:action"` form (kept for back-compat, documented as legacy).
- **`AxiamRequirement`/`AxiamPolicyHandler` extensions:** carry `Scope` and
  `ResourceRouteParam`; pass `scope` to `CheckAccessAsync`; **replace the
  `Guid.Empty` fallback** with a 400 `invalid_request` outcome when the route value is
  missing/non-UUID (per §11.3); keep fresh-check-per-request and
  `subjectId = user_id` behavior (already correct).
- **`require_auth`/`require_role`:** documented as framework-native `[Authorize]` /
  `[Authorize(Roles = "...")]` (the middleware already emits `ClaimTypes.Role`); no
  new types. NetworkError during check → 503 via
  `AxiamAuthorizationMiddlewareResultHandler`.
- **Tests:** extend `AspNetCoreMiddlewareTests` with the attribute-based §11 matrix
  (allow/deny/missing-route-param→400/scope on the wire/network→503).
- **Example:** switch one `AspNetCoreSample` endpoint to
  `[AxiamAccess("read", "documents")]`, keep one legacy policy-string endpoint.
- **Commit:** `feat(aspnetcore): add AxiamAccessAttribute with scope + route-param resolution (CONTRACT §11)`

### 4.6 PHP — PHP 8 attributes enforced in both bridges (M)

- **Attribute classes (`src/Attributes/`, new):**
  `#[RequireAuth]`, `#[RequireAccess(string $action, ?string $resourceId = null, ?string $resourceParam = 'id', ?string $scope = null)]`,
  `#[RequireRole(string ...$roles)]` — `#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]`,
  plain final classes, zero framework deps (PHP ≥8.1 already the floor).
- **Symfony (`src/Symfony/AxiamAccessAttributeListener.php`, new):** an
  `EventSubscriberInterface` on `KernelEvents::CONTROLLER` (mirrors how Symfony's own
  `#[IsGranted]` works) that reflects the resolved controller callable for the
  attributes, reads the identity from the `axiam_user` request attribute (set by the
  existing `AxiamAuthSubscriber`; absent → 401), resolves the resource from route
  params, calls `AxiamClient::checkAccess()` (dispatcher already picks REST/gRPC),
  and sets a 403/401/400/503 JSON response per §11. Class-existence-guarded like the
  other Symfony classes; registered in `services.yaml` example + bundle.
- **Laravel (`src/Laravel/AxiamAccessMiddleware.php`, new):** route middleware
  registered as `axiam.access` accepting string params
  (`->middleware('axiam.access:read,documents,id')`) **and**, when the route resolves
  to a controller method, reflecting the same `#[RequireAccess]` attributes so both
  styles work; delegates the check to the same shared enforcement service
  (`src/AccessEnforcer.php`, new — one §11 implementation used by both bridges).
- **Tests:** `SymfonyAccessAttributeListenerTest`, `LaravelAccessMiddlewareTest`,
  `AccessEnforcerTest` (Guzzle mock handler; §11 matrix incl. attribute-on-class,
  string-param form, network fail-closed).
- **Examples:** extend `examples/symfony_app/` and `examples/laravel_app/routes.php`
  with attribute-annotated controllers.
- **Commit:** `feat(attributes): add #[RequireAccess]/#[RequireAuth]/#[RequireRole] with Laravel + Symfony enforcement (CONTRACT §11)`

### 4.7 Go — per-route wrapper helpers (S/M)

Go has no macros/annotations; the §11-conformant shape is a wrapper with the canonical
name, composing with the existing middleware:

- **`middleware/require.go` (new):**
  - `type ResourceResolver func(*http.Request) (string, error)` with helpers
    `ResourceFromPath(name string)` (uses go 1.22+ `r.PathValue`), `StaticResource(id string)`.
  - `type AccessChecker interface { CheckAccess(ctx, action, resourceID string, scope ...string) (bool, string, error) }`
    (satisfied by `*axiam.Client`; interface keeps tests dependency-free, matching the
    existing unexported `jwksVerifier` pattern). **Requires adding subject-aware
    checking**: a new root-package method
    `CheckAccessAs(ctx, subjectID, action, resourceID string, scope ...string)`
    (additive; existing signatures unchanged) so the wrapper can pass the
    request-user's id per §11.2.
  - `RequireAuth() func(http.Handler) http.Handler` — 401 unless
    `UserFromContext(ctx)` is present.
  - `RequireAccess(checker AccessChecker, action string, resolve ResourceResolver, opts ...Option) func(http.Handler) http.Handler`
    — 401 no identity; 400 resolver error; 403 deny; 503 `*axiam.NetworkError`
    (fail closed); `WithScope(string)` and `WithLogger(*slog.Logger)` options.
  - `RequireRole(roles ...string) func(http.Handler) http.Handler` — local claim
    check.
  - All reuse the existing `writeError` JSON shape.
- **Tests:** `middleware/require_test.go` (+`require_more_test.go` per repo
  convention): httptest server, fake checker + real-client wiring, full §11 matrix,
  race test with parallel requests.
- **Example:** extend `examples/middleware-guard/` with a
  `RequireAccess`-protected `/docs/{id}` route.
- **Commit:** `feat(middleware): add RequireAuth/RequireAccess/RequireRole route wrappers (CONTRACT §11)`

## 5. Tests, docs & examples — quality gates per SDK (verified in CI configs, 2026-07-16)

Every per-SDK task in §4 already includes tests, an example update, and README/CHANGELOG
work. This section pins the **exact gates the new code must pass** and the doc-toolchain
files that need touching, so executors don't discover them by CI failure.

### 5.1 Test-coverage gates (hard CI floors — new helper code must not sink them)

| SDK | Gate | Where enforced | Implication for this work |
|-----|------|----------------|---------------------------|
| Rust | **89% lines** (`cargo llvm-cov report --fail-under-lines 89`, `--all-features`) | `.github/workflows/coverage.yml` | The new `macros` feature is inside `--all-features`, so macro *expansion output* is measured. Keep the macro thin (expand to calls into the programmatic `RequireAccess` guard, per §4.1) so the logic is coverable by ordinary actix tests; `trybuild` compile-fail cases cover misuse paths. |
| TypeScript | **lines 93 / statements 92 / functions 95 / branches 84** (vitest v8 thresholds) | `vitest.config.ts` | Guard factories must test every branch (401/403/400/503, param vs literal vs resolver). If Tier 2 `./nestjs` ships, its guard counts toward the same global thresholds — do not ship it undertested or the whole suite fails. |
| Python | **96% (`fail_under = 96`)**, plus **interrogate docstring coverage `fail-under = 100`** and `mypy --strict` | `pyproject.toml`, `sdk-ci-python.yml` | Both new modules (`fastapi.require_access`, `django/decorators.py`) need full branch tests *and* a docstring on every public function/class/param-carrying object — 100% docstring coverage is a hard gate, not a style suggestion. |
| Java | **JaCoCo 0.92 line ratio** | `pom.xml` | `AxiamAuthorizationInterceptor` + annotation parsing must be MockMvc-tested across the full §11 matrix; annotation `@interface` types themselves carry no executable lines. |
| C# | **92% merged line floor** (coverlet → gate in workflow) | `.github/workflows/coverage.yml` | Attribute + provider/handler changes are in `Axiam.Sdk.AspNetCore`, which is part of the merged floor — extend `AspNetCoreMiddlewareTests` with the full matrix including the new 400 path. |
| PHP | **No enforced floor** — pcov → Coveralls reporting only | `.github/workflows/coverage.yml` | Do not treat this as license to undertest: match the repo's existing one-test-class-per-concern convention (`AccessEnforcerTest`, `SymfonyAccessAttributeListenerTest`, `LaravelAccessMiddlewareTest`) and keep the Coveralls trendline from dropping. |
| Go | **93% floor** | `.github/workflows/coverage.yml` | `middleware/require.go` needs the repo's usual `require_test.go` + `require_more_test.go` pairing; table-driven tests over the §11 matrix reach the floor cheaply. |

Shared test matrix (restated from §7, applies to every SDK): allow / deny→403 /
unauthenticated→401 / unresolvable-resource→400 / transport-failure→503 fail-closed /
`subject_id` asserted on the wire / scope passthrough / no token material in output.

### 5.2 Documentation gates and doc-site plumbing

Several repos enforce *documentation* in CI as strictly as coverage; new public API
must land fully documented or the build fails:

| SDK | Doc gate (hard) | Doc site / plumbing to touch |
|-----|------------------|------------------------------|
| Rust | `cargo doc --all-features` with `RUSTDOCFLAGS: -D warnings` + `#![warn(missing_docs)]` — every public item in **both** crates (incl. the new `axiam-sdk-macros`) needs rustdoc, with doctest-friendly examples | docs.rs builds automatically per release; the new crate needs its own `[package.metadata.docs.rs]` (all-features) and README section |
| TypeScript | none hard, but TypeDoc publishes from the entry points | `docs-publish.yml` (TypeDoc), `typedoc.json` entry points, `package.json` exports map + `tsup.config.ts` entries — a new `./nestjs` subpath must be added to **all three** or it silently vanishes from docs and dist |
| Python | **interrogate `fail-under = 100`** (docstrings, see 5.1) | `docs-publish.yml` runs pdoc with an **explicit module list** — if any new importable submodule is added (e.g. `axiam_sdk.django.decorators` is auto-covered under `axiam_sdk.django`, but a hypothetical new subpackage is not), append it to the pdoc command |
| Java | **javadoc gate**: `mvn compile javadoc:javadoc` with `doclint=all`, `failOnWarnings=true` — every new public annotation/class/method needs complete javadoc incl. `@param`/`@return` | javadoc.io serves the released `-javadoc.jar` automatically (D-22) |
| C# | **CS1591 in `WarningsAsErrors`** — XML doc comment on every public member is a compile gate in both projects | `docs-publish.yml` (docfx) picks up projects via `docfx.json` metadata; new types in existing projects need no config change, but check `toc.yml` if a new docs page is warranted |
| PHP | none hard (phpstan level gate applies to code, not docs) | `docs-publish.yml` (phpDocumentor phar) scans `src/` per `phpdoc.dist.xml` — new `src/Attributes/` is auto-included; write full docblocks anyway (repo convention) |
| Go | none hard | pkg.go.dev re-indexes on release (CI pokes proxy.golang.org); godoc conventions: package-level doc comment for any new file-level concepts, examples as `ExampleRequireAccess` test functions so they render on pkg.go.dev |

### 5.3 README / CHANGELOG / examples checklist (identical for all seven repos)

Per SDK, in the same PR as the implementation:

1. **README**: new "Declarative authorization helpers" section with a copy-pasteable
   snippet per supported framework; conformance statement updated to
   "conforms to CONTRACT.md §1–§11".
2. **CHANGELOG.md**: `Added` entry under the unreleased version (all repos ship a
   CHANGELOG; the CONTRACT's "no SDK currently ships a dedicated CHANGELOG" note is
   stale — they all have one now).
3. **Examples**: extend the existing example app (listed per SDK in §4) rather than
   adding a new one, so example CI stays cheap. Examples must build in CI where the
   repo already builds them (Go builds examples with tests; Java's spring-boot-app has
   a Failsafe IT; C#'s examples compile via solution).
4. **Vendored contract**: re-synced `CONTRACT.md` (with §11) as the task's first
   commit (per §3.3).

## 6. Execution order for the follow-up run(s)

| Step | Repo(s) | Task | Depends on |
|------|---------|------|------------|
| 1 | `axiam` | CONTRACT.md §11 + breaking-changes-log entry (this plan's §3) | — |
| 2a–2g | each SDK repo | §4.1–§4.7, each starting with a vendored-CONTRACT re-sync commit | 1 |
| 3 | each SDK repo | README conformance statement → "§1–§11", CHANGELOG entry, doc-site plumbing per §5.2/§5.3 | its 2x |
| 4 | `axiam` | Cross-SDK verification sweep: naming-map audit vs §11 table, error-code matrix spot-check per SDK test suite | all 2x |

Steps 2a–2g are mutually independent — they can be seven parallel executor tasks.
Suggested batching if run sequentially: C# + Go first (smallest, validate the §11
semantics in practice), then Python + PHP + TS, then Java, then Rust (largest — new
crate + release wiring for `axiam-sdk-macros` on crates.io must be added to the
publish workflow, mirroring the existing publishing setup documented in
`claude_dev/publishing-and-secrets.md`).

## 7. Decisions taken in this plan (flag disagreement before the second run)

1. **Fail-closed on transport failure = 503, not 403** — distinguishes "denied" from
   "couldn't decide" for operators while still denying.
2. **`subject_id` is mandatory in helper-issued checks** (§3.2.2). This surfaces a
   small additive API need in Java (`checkAccess` subjectId overload) and Go
   (`CheckAccessAs`); Rust/TS/Python/C#/PHP request shapes already carry it.
3. **`require_role` included as optional-but-recommended** in all SDKs except C#
   (framework-native `[Authorize(Roles=…)]` already covers it) — cheap to build since
   roles are already in every injected identity.
4. **No NestJS-first TypeScript design** — Express/Fastify guard factories are the
   mandatory tier; NestJS decorators are an optional Tier 2 subpath.
5. **Java enforcement via `HandlerInterceptor`, not AspectJ** — zero new deps, no
   proxy semantics; method-security variant deferred.
6. **FastAPI helper takes `AsyncAxiamClient`** (async-native); Django decorators take
   the sync `AxiamClient` with an async-view branch.
7. **C# legacy `"resource:action"` policy strings remain supported**; the new
   attribute is sugar over the same provider/handler.
8. **No decision caching anywhere** (matches §10 TTL rule); page-level batching stays
   on `batch_check`.

## 8. Acceptance criteria (per SDK)

- Helper names/casing match the §11 naming map exactly; `(action, resource[, scope])`
  order everywhere.
- Full §11 test matrix present: allow / deny→403 / unauthenticated→401 /
  unresolvable-resource→400 / transport-failure→503 (fail closed) / `subject_id`
  asserted on the wire / scope passthrough.
- No token material in any error/log output (reuse each repo's existing redaction
  tests as the pattern).
- Coverage gates stay green at their exact CI floors (§5.1): Rust ≥89 lines,
  TypeScript 93/92/95/84, Python ≥96 + interrogate 100, Java JaCoCo ≥0.92,
  C# ≥92, Go ≥93; PHP has no floor but the Coveralls trendline must not drop.
- Documentation gates pass (§5.2): rustdoc `-D warnings` (both crates),
  Java doclint/failOnWarnings, C# CS1591; doc-site plumbing updated where required
  (TypeDoc entry points + exports map for any new TS subpath, pdoc module list for
  any new Python subpackage).
- Example app updated and buildable in CI; README states §1–§11 conformance;
  CHANGELOG `Added` entry present; vendored CONTRACT.md re-synced.
