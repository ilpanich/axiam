---
phase: 06-ci-cd-infrastructure-hardening
plan: 04
subsystem: infra
tags: [vite, sri, cookie-security, openapi, parity-test, csrf, auth-config]

# Dependency graph
requires:
  - phase: 06-01
    provides: frontend/package.json license field; Apache-2.0 fixed
  - phase: 01-cookie-based-authentication
    provides: csrf.rs cookie helpers, AuthConfig struct
  - phase: 03-rbac-enforcement
    provides: ROUTE_PERMISSION_MAP, PUBLIC_PATHS, permissions.rs pattern

provides:
  - cookie_secure field on AuthConfig (config-driven, serde default=true)
  - Parameterized csrf.rs cookie helpers (no more hardcoded .secure(true))
  - Route↔OpenAPI bi-directional parity test in axiam-api-rest
  - frontend/dist/*.js/.css have SHA-384 SRI integrity hashes
  - frontend build emits no source maps (sourcemap:false)
  - docker-compose.dev.yml has axiam-server service with COOKIE_SECURE=false

affects: [06-05, future-auth-changes, ci-cd-security]

# Tech tracking
tech-stack:
  added:
    - vite-plugin-sri3@2.0.0 (SRI hash injection for Vite production builds)
  patterns:
    - AuthConfig boolean config-driven via serde default_true() helper
    - Two-direction HashSet parity tests (A⊆B and B⊆A) for route/openapi drift detection
    - AUTHENTICATED_SELF_SERVICE_PATHS constant for jwt-auth, no-permission openapi endpoints

key-files:
  created:
    - crates/axiam-api-rest/src/tests/mod.rs
    - crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs
  modified:
    - crates/axiam-auth/src/config.rs (cookie_secure field + Default impl)
    - crates/axiam-api-rest/src/middleware/csrf.rs (parameterized cookie helpers)
    - crates/axiam-api-rest/src/handlers/auth.rs (cookie_secure wired)
    - crates/axiam-api-rest/src/handlers/federation.rs (cookie_secure wired)
    - crates/axiam-api-rest/src/extractors/auth.rs (AuthConfig literal updated)
    - crates/axiam-api-rest/src/lib.rs (added #[cfg(test)] mod tests)
    - crates/axiam-api-rest/tests/middleware_test.rs (AuthConfig literal updated)
    - crates/axiam-auth/src/token.rs (AuthConfig literal updated)
    - crates/axiam-auth/tests/auth_service_test.rs (AuthConfig literal updated)
    - frontend/vite.config.ts (sri() plugin + build.sourcemap:false)
    - frontend/package.json (vite-plugin-sri3 devDependency)
    - docker/docker-compose.dev.yml (axiam-server service + COOKIE_SECURE=false)

key-decisions:
  - "vite-plugin-sri3 uses named export { sri } not default export — fixed import in vite.config.ts"
  - "AUTHENTICATED_SELF_SERVICE_PATHS added to parity test for jwt-auth/no-permission openapi paths (logout, enroll_mfa, confirm_mfa, federation/oidc/authorize)"
  - "docker-compose.dev.yml gets minimal server service with COOKIE_SECURE=false; no image build needed (use published image)"

patterns-established:
  - "Route/OpenAPI parity: two-direction HashSet diff with ROUTE_PERMISSION_MAP + PUBLIC_PATHS + AUTHENTICATED_SELF_SERVICE_PATHS as three categories"
  - "Config booleans that must default true in prod use fn default_true() + #[serde(default)] pattern"
  - "Tests module at src/tests/ wired via #[cfg(test)] mod tests in lib.rs"

requirements-completed: [REQ-9, REQ-10]

# Metrics
duration: 90min
completed: 2026-06-07
---

# Phase 06 Plan 04: Security Hardening Closure Summary

**Cookie Secure flag config-driven (D-18), route↔openapi parity test (D-15), and SRI+sourcemap-free frontend build (D-17) completing three Phase 6 security hardening targets**

## Performance

- **Duration:** ~90 min (resumed from interrupted state)
- **Started:** 2026-06-07T09:00:00Z
- **Completed:** 2026-06-07T10:43:00Z
- **Tasks:** 3 of 3
- **Files modified:** 15

## Accomplishments

- Threaded `AuthConfig::cookie_secure` (serde default=true) through all three csrf.rs cookie helpers and all handler call-sites; units tests assert toggle behavior
- Created bi-directional route↔OpenAPI parity test that fails if a route is added to ROUTE_PERMISSION_MAP without a matching `#[utoipa::path]` annotation, or vice versa
- Frontend production build now injects SHA-384 SRI hashes into `index.html` (T-06-13) and emits zero `.map` files (T-06-14)
- docker-compose.dev.yml extended with `axiam-server` service carrying `AXIAM__AUTH__COOKIE_SECURE: "false"` so auth cookies work over http://localhost

## Task Commits

Each task was committed atomically:

1. **Task 1: cookie_secure (D-18)** - `c0503a7` (feat)
2. **Task 2: route↔openapi parity test (D-15)** - `2e9f1ca` (feat)
3. **Task 3: vite SRI + sourcemap:false + dev compose (D-17)** - `d672ac2` (feat)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified

- `crates/axiam-auth/src/config.rs` - `cookie_secure: bool` with `#[serde(default = "default_true")]`
- `crates/axiam-api-rest/src/middleware/csrf.rs` - parameterized cookie helpers + unit tests
- `crates/axiam-api-rest/src/handlers/auth.rs` - wired `config.auth.cookie_secure` through login/refresh
- `crates/axiam-api-rest/src/handlers/federation.rs` - wired `auth_config.cookie_secure` through OIDC/SAML login
- `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` - new bi-directional parity test
- `crates/axiam-api-rest/src/tests/mod.rs` - test module declaration
- `crates/axiam-api-rest/src/lib.rs` - `#[cfg(test)] mod tests;`
- `frontend/vite.config.ts` - `sri()` plugin + `build.sourcemap: false`
- `frontend/package.json` - `vite-plugin-sri3@2.0.0` devDependency
- `docker/docker-compose.dev.yml` - axiam-server service with `AXIAM__AUTH__COOKIE_SECURE: "false"`
- AuthConfig test literals updated in: `token.rs`, `auth_service_test.rs`, `extractors/auth.rs`, `tests/middleware_test.rs`

## Decisions Made

- `vite-plugin-sri3` uses named export `{ sri }` not a default export — import fixed from `import sri from` to `import { sri } from`
- Parity test includes `AUTHENTICATED_SELF_SERVICE_PATHS` for paths documented in OpenAPI that require JWT but no named permission (logout, mfa/enroll, mfa/confirm, federation/oidc/authorize) — a third category beyond ROUTE_PERMISSION_MAP and PUBLIC_PATHS
- docker-compose.dev.yml server service uses `ghcr.io/axiamhq/axiam/server:latest` matching prod image convention

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] vite-plugin-sri3 named export vs default export**
- **Found during:** Task 3 (vite.config.ts update)
- **Issue:** `import sri from "vite-plugin-sri3"` caused TypeScript error TS2613 — module has no default export
- **Fix:** Changed to `import { sri } from "vite-plugin-sri3"` per TypeScript hint and package type definitions
- **Files modified:** frontend/vite.config.ts
- **Verification:** `npm run build` succeeds; `dist/index.html` contains `integrity="sha384-..."`
- **Committed in:** d672ac2 (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Minor import style correction. No scope creep.

## Issues Encountered

- Previous executor run left partial uncommitted changes; build was broken due to `cookie_secure` added to `AuthConfig` struct without updating all struct literals. Analysis confirmed all remaining struct literals used `..AuthConfig::default()` fallback — no explicit `cookie_secure:` fields needed beyond the ones already added.

## Known Stubs

None — all three task deliverables are fully wired.

## Threat Flags

No new threat surface beyond what the plan's threat model covers:
- T-06-13 (Tampering): SRI hashes mitigated via vite-plugin-sri3 ✓
- T-06-14 (Info Disclosure): sourcemap:false ✓
- T-06-15 (Info Disclosure): cookie_secure default true + dev override ✓
- T-06-16 (Spoofing): route↔openapi parity test ✓

## Next Phase Readiness

- All D-15, D-17, D-18 decisions from 06-CONTEXT.md are closed
- Phase 6 (06-ci-cd-infrastructure-hardening) is now complete (all 5 plans done)
- No blockers for final STATE.md/ROADMAP.md update

---
*Phase: 06-ci-cd-infrastructure-hardening*
*Completed: 2026-06-07*
