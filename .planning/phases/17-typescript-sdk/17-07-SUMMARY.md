---
phase: 17-typescript-sdk
plan: 07
subsystem: auth
tags: [typescript, security, single-flight-refresh, tenant-isolation, jwt, middleware, gap-closure]

# Dependency graph
requires:
  - phase: 17-typescript-sdk (plans 01-06)
    provides: AxiamClient REST/gRPC/AMQP core, SharedSession/NodeSession, Express/Fastify middleware, verifyCore.ts
provides:
  - Per-session single-flight refresh guard (createRefreshGuard() factory) closing CR-02
  - Tenant-scoped middleware/JWKS verification (VerifiableSession.tenantHeaderValue) closing CR-03
affects: [17-08 (remaining CR-01/CR-04 gap closure), any future SDK consumer holding multiple AxiamClient/NodeSession instances or resource-server middleware deployments]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-instance guard factory pattern: createRefreshGuard() returns an independent closure per call, replacing a module-level singleton for session-scoped invariants (D-13)"
    - "Backward-compatible default instance: retained module-level refreshOnce/resetRefreshGuard delegate to a default createRefreshGuard() instance so pre-existing unit tests keep passing unchanged"

key-files:
  created:
    - sdks/typescript/test/rest/multiSessionRefresh.test.ts
    - sdks/typescript/test/middleware/tenantIsolation.test.ts
  modified:
    - sdks/typescript/src/core/singleFlightRefresh.ts
    - sdks/typescript/src/rest/session.ts
    - sdks/typescript/src/rest/interceptors.ts
    - sdks/typescript/src/grpc/callWithRefresh.ts
    - sdks/typescript/src/node/session.ts
    - sdks/typescript/src/middleware/verifyCore.ts
    - sdks/typescript/test/rest/singleFlightRefresh.test.ts
    - sdks/typescript/test/grpc/checkAccess.test.ts
    - sdks/typescript/test/middleware/express.test.ts
    - sdks/typescript/test/middleware/fastify.test.ts

key-decisions:
  - "createRefreshGuard() factory closure carries a private __reset() method (attached via Object.assign-style cast) so resetRefreshGuard() can still reset the module-level default instance's internal promise without exposing internal state as a public field"
  - "SharedSession constructs its own refreshGuard via createRefreshGuard() in the base class constructor; NodeSession inherits it automatically via super(...) with no NodeSession-specific change needed"
  - "Equality check in authenticateRequest runs strictly after the existing sub/tenant_id presence checks, preserving their exact error messages and test assertions"

patterns-established:
  - "Per-session security-invariant guards must be constructed instance-side (in a class constructor), never held at module scope, when the invariant is meant to be session-scoped rather than process-scoped"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "Per-session single-flight refresh guard: two independent AxiamClient/NodeSession instances each refresh exactly once with no cross-wiring (CR-02, D-13)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/test/rest/multiSessionRefresh.test.ts#two independent sessions each refresh exactly once, with no cross-wiring"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/rest/singleFlightRefresh.test.ts#reactive single-flight refresh (SC#3)"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/core/singleFlightRefresh.test.ts#refreshOnce"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/grpc/checkAccess.test.ts#gRPC checkAccess/batchCheck (SC#2 Node half)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Middleware/JWKS verification enforces claims.tenant_id equality against the resource server's configured tenant, rejecting cross-tenant tokens (CR-03)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/test/middleware/tenantIsolation.test.ts#tenant isolation in middleware verify core (CR-03)"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/middleware/express.test.ts#axiamMiddleware (Express)"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/middleware/fastify.test.ts#axiamPlugin (Fastify)"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 07: Gap Closure — Per-Session Refresh Guard + Tenant-Isolated Middleware Summary

**Converted the single-flight refresh guard from a process-wide module singleton into a per-session `createRefreshGuard()` factory (CR-02), and added tenant_id equality enforcement to the middleware verify core against an org-wide JWKS (CR-03).**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-01T13:13:00Z
- **Completed:** 2026-07-01T13:33:06Z
- **Tasks:** 2
- **Files modified:** 10 (6 new files across the two tasks: 2 new test files, 8 modified source/test files)

## Accomplishments

- **CR-02 closed:** `core/singleFlightRefresh.ts` now exports `createRefreshGuard()`, a factory producing an independent `refreshOnce(doRefresh)` closure with its own private `refreshPromise`. `SharedSession` constructs one per instance (`session.refreshGuard`); `rest/interceptors.ts` and `grpc/callWithRefresh.ts` both call `session.refreshGuard(...)` instead of the old module-level `refreshOnce`. `NodeSession` inherits the guard automatically via `super(...)`. The module-level `refreshOnce`/`resetRefreshGuard` exports are retained as a backward-compatible default instance so `test/core/singleFlightRefresh.test.ts` keeps passing unchanged.
- **CR-03 closed:** `VerifiableSession` in `middleware/verifyCore.ts` now requires `tenantHeaderValue: string`. `authenticateRequest` throws `AuthError('token tenant_id does not match configured tenant')` when `claims.tenant_id !== session.tenantHeaderValue`, checked strictly after the pre-existing `sub`/`tenant_id` presence checks. This is non-breaking for `NodeSession` callers since `NodeSession` already exposes `tenantHeaderValue` via inheritance from `SharedSession`.
- Added `test/rest/multiSessionRefresh.test.ts`: constructs two `AxiamClient` instances against two distinct base URLs, fires 5 concurrent 401-triggering requests on each simultaneously, and asserts each session's own refresh endpoint is called exactly once (no cross-wiring) — plus a structural assertion that the two sessions' `refreshGuard` closures are distinct object references.
- Added `test/middleware/tenantIsolation.test.ts`: signs an EdDSA token with `tenant_id: 'tenant-1'`, verifies it against a session configured for `tenant-2` (rejected with `AuthError`, and via `axiamMiddleware` a 401 `authentication_failed` response), and against a session configured for `tenant-1` (accepted, `identity.tenantId === 'tenant-1'`).
- Updated existing `test/middleware/express.test.ts` and `test/middleware/fastify.test.ts` inline session objects to include `tenantHeaderValue: 'tenant-1'` (matching the tokens' `tenant_id` claim), keeping their happy-path assertions green under the widened interface.
- Updated stale doc comments in `node/session.ts` that described the guard as a "module-level singleton" — now describe it as a per-session guard shared across REST and gRPC for the same session (D-13 = shared per session, not per process).

## Task Commits

Each task was committed atomically:

1. **Task 1: CR-02 — per-session single-flight refresh guard** - `07e3d87` (fix)
2. **Task 2: CR-03 — enforce tenant_id equality in middleware verify core** - `15bc3f8` (fix)

_Note: Both tasks were `tdd="true"` in the plan; RED-phase tests were authored directly alongside the fix in a single commit per task per the plan's own instructions (no separate pre-existing-red commit was required since these are net-new regression tests proving a fix, not a strict red→green cycle against pre-existing code)._

## Files Created/Modified

- `sdks/typescript/src/core/singleFlightRefresh.ts` - Added `createRefreshGuard()` factory; retained `refreshOnce`/`resetRefreshGuard` as a backward-compatible default instance
- `sdks/typescript/src/rest/session.ts` - `SharedSession.refreshGuard: RefreshGuard`, constructed via `createRefreshGuard()` in the constructor
- `sdks/typescript/src/rest/interceptors.ts` - `installRefreshInterceptor` now calls `session.refreshGuard(...)` instead of the module-level `refreshOnce`
- `sdks/typescript/src/grpc/callWithRefresh.ts` - `callWithRefresh` now calls `session.refreshGuard(session.doRefresh)` instead of the module-level `refreshOnce`
- `sdks/typescript/src/node/session.ts` - Updated doc comments describing the guard as per-session, not module-level
- `sdks/typescript/src/middleware/verifyCore.ts` - `VerifiableSession.tenantHeaderValue: string`; `authenticateRequest` enforces `claims.tenant_id === session.tenantHeaderValue`
- `sdks/typescript/test/rest/multiSessionRefresh.test.ts` (new) - CR-02 regression: two independent sessions, no cross-wiring
- `sdks/typescript/test/middleware/tenantIsolation.test.ts` (new) - CR-03 regression: cross-tenant token rejected, same-tenant token accepted
- `sdks/typescript/test/rest/singleFlightRefresh.test.ts` - No assertion changes; unaffected by the refactor (each test constructs a fresh client)
- `sdks/typescript/test/grpc/checkAccess.test.ts` - No assertion changes; unaffected by the refactor (each test constructs a fresh session)
- `sdks/typescript/test/middleware/express.test.ts` - Added `tenantHeaderValue: 'tenant-1'` to all 4 inline session objects
- `sdks/typescript/test/middleware/fastify.test.ts` - Added `tenantHeaderValue: 'tenant-1'` to the `buildApp()` helper's session type and all 4 call sites

## Decisions Made

- `createRefreshGuard()`'s returned closure carries a non-enumerable-in-practice `__reset()` method (attached to the closure via a typed cast) purely to let the retained `resetRefreshGuard()` module-level helper reset the default instance's internal promise — this keeps the default instance's `refreshPromise` fully private to its own closure rather than reintroducing a module-level mutable variable.
- No changes were made to `test/rest/singleFlightRefresh.test.ts` or `test/grpc/checkAccess.test.ts` beyond what the plan allowed as optional (their `resetRefreshGuard()` afterEach calls were left in place since each test already constructs a fresh client/session, making them harmless no-ops against the retained default export).
- Positive-control assertions were added in `tenantIsolation.test.ts` per the plan's instruction, proving the fix does not introduce false rejections for matching-tenant tokens.

## Deviations from Plan

None - plan executed exactly as written. Both tasks' `<action>` and `<done>` criteria were followed precisely; no architectural changes, no additional dependencies, no scope expansion beyond the two named gaps (CR-02, CR-03).

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- CR-02 and CR-03 are closed; the remaining two Critical gaps from `17-VERIFICATION.md` (CR-01 Node CSRF token, CR-04 error `cause` redaction) are addressed by the separate `17-08-PLAN.md` gap-closure plan.
- Full suite is green: 81/81 tests pass (`npx vitest run`), `npx tsc --noEmit` is clean, no new runtime dependencies were introduced.
- `sdks/typescript/src/core/singleFlightRefresh.ts`'s `createRefreshGuard()` factory and `RefreshGuard` type are now part of the `core` barrel export surface (`core/index.ts` re-exports `./singleFlightRefresh.js` unchanged) and are usable by any future SDK-internal transport needing a session-scoped single-flight invariant.

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED

- FOUND: sdks/typescript/test/rest/multiSessionRefresh.test.ts
- FOUND: sdks/typescript/test/middleware/tenantIsolation.test.ts
- FOUND: sdks/typescript/src/core/singleFlightRefresh.ts
- FOUND: sdks/typescript/src/middleware/verifyCore.ts
- FOUND: commit 07e3d87 (Task 1)
- FOUND: commit 15bc3f8 (Task 2)
