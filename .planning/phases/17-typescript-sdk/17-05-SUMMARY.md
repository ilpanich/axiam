---
phase: 17-typescript-sdk
plan: 05
subsystem: sdk
tags: [typescript, sdk, express, fastify, middleware, jwks, examples, strict-compile]

# Dependency graph
requires:
  - phase: 17-typescript-sdk
    plan: 02
    provides: "AxiamClient REST core (SharedSession, login/verifyMfa discriminated union, can/checkAccess/batchCheck) the browser-rest example exercises"
  - phase: 17-typescript-sdk
    plan: 03
    provides: "Node persona (createNodeSession) + local JWKS verifier (verifyAccessToken) the middleware reuses, and AuthzGrpcClient the node-grpc example exercises"
  - phase: 17-typescript-sdk
    plan: 04
    provides: "consume()/Sensitive<Buffer> AMQP consumer the amqp-consumer example exercises"
provides:
  - "Express (axiamMiddleware) and Fastify (axiamPlugin) middleware sharing one local-JWKS verifyCore (D-27/§10) — no cookie-parser/@fastify/cookie peer dependency"
  - "New public axiam-sdk/middleware subpath export (package.json + tsup.config.ts) wiring Task 1's middleware to a real entry point"
  - "Five strict-compiling runnable examples (express-app, fastify-app, browser-rest, node-grpc, amqp-consumer) proving SC#4"
  - "Sensitive re-exported from axiam-sdk/amqp (was previously unreachable from that entry despite consume()'s signature requiring it)"
affects: [17-06-publish-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fastify's own Symbol.for('skip-override') plugin-encapsulation escape hatch (the same mechanism the fastify-plugin package wraps) used to make axiamPlugin's preHandler hook apply to sibling routes, instead of adding fastify-plugin as a new dependency"
    - "examples/tsconfig.json resolves axiam-sdk/* via a paths mapping to src/*.ts rather than the package's own exports map, since dist/ is unbuilt in this sandbox (no buf CLI) — a buf-enabled CI run additionally verifies the built package resolves the same subpaths"
    - "express/fastify moved from devDependencies to optional peerDependencies now that the public middleware entry's type surface references them"

key-files:
  created:
    - sdks/typescript/src/middleware/cookieHeader.ts
    - sdks/typescript/src/middleware/verifyCore.ts
    - sdks/typescript/src/middleware/express.ts
    - sdks/typescript/src/middleware/fastify.ts
    - sdks/typescript/src/middleware/index.ts
    - sdks/typescript/test/middleware/express.test.ts
    - sdks/typescript/test/middleware/fastify.test.ts
    - sdks/typescript/examples/tsconfig.json
    - sdks/typescript/examples/express-app.ts
    - sdks/typescript/examples/fastify-app.ts
    - sdks/typescript/examples/browser-rest.ts
    - sdks/typescript/examples/node-grpc.ts
    - sdks/typescript/examples/amqp-consumer.ts
  modified:
    - sdks/typescript/package.json
    - sdks/typescript/tsup.config.ts
    - sdks/typescript/src/amqp/index.ts

key-decisions:
  - "Fastify plugin encapsulation: axiamPlugin marks itself with Symbol.for('skip-override') (fastify's own public escape hatch) rather than adding the fastify-plugin package, so its preHandler hook applies to routes registered as siblings instead of being scoped only to the plugin's own encapsulation context"
  - "examples/tsconfig.json uses a paths mapping to ../src/*.ts instead of relying on the package's own exports map — dist/ does not exist in this sandbox (buf CLI unavailable), so resolving through exports (which points at dist/*) would fail; source-mapped paths type-check the same public surface without requiring a build"
  - "Added a new axiam-sdk/middleware subpath export (package.json exports + tsup.config.ts entry) that the plan's <artifacts_this_phase_produces> implied but the plan's <files_modified> list never listed package.json/tsup.config.ts explicitly — without it Task 1's middleware would have no public entry point for Task 2's examples to import (Rule 2, missing critical functionality)"
  - "Re-exported Sensitive from axiam-sdk/amqp — consume()'s public signature requires a caller-constructed Sensitive<Buffer> signing key, but the class itself was never exported from that entry (import-only from axiam-sdk/amqp would have been impossible without reaching into another entry point, violating Task 2's public-entry-points-only constraint; Rule 2)"
  - "express/fastify moved from devDependencies to optional peerDependencies (peerDependenciesMeta.optional: true) since the new middleware entry's public type surface (RequestHandler, FastifyPluginAsync, etc.) now references them"

patterns-established:
  - "Middleware verify core (verifyCore.ts) takes a minimal VerifiableSession interface ({ jwksVerifier: Verifier }) rather than the concrete NodeSession class — keeps the middleware testable against a lightweight fake session and decoupled from the full Node persona construction"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "A request with a valid EdDSA axiam_access cookie passes through with req.axiamUser / request.axiamUser set to {userId, tenantId, roles} and the downstream handler runs (200)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/middleware/express.test.ts 'valid axiam_access cookie -> req.axiamUser set + next() called'; test/middleware/fastify.test.ts 'valid axiam_access cookie -> request.axiamUser set + handler reached (200)'"
        status: pass
    human_judgment: false
  - id: D2
    description: "A request with a valid Authorization: Bearer token (no cookie) also passes (cookie-first, Bearer fallback)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/middleware/express.test.ts and fastify.test.ts 'valid Authorization: Bearer token (no cookie) also passes'"
        status: pass
    human_judgment: false
  - id: D3
    description: "A request with no credentials returns 401 with a standardized JSON error body; a request with an invalid/expired token returns 401, for both frameworks"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/middleware/express.test.ts and fastify.test.ts 'missing credentials -> 401 JSON' + 'invalid/expired token -> 401 JSON' (4 tests total)"
        status: pass
    human_judgment: false
  - id: D4
    description: "roles are derived from the scope claim (space-separated); no cookie-parser/@fastify/cookie peer dependency; verifyCore reuses verifyAccessToken (no second JWKS implementation)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/middleware/*.test.ts assert roles===['read','write'] / ['admin'] from the scope claim"
        status: pass
      - kind: unit
        ref: "grep -rn cookie-parser|@fastify/cookie sdks/typescript/src/middleware/ returns only a doc-comment mention, no actual dependency usage"
        status: pass
      - kind: unit
        ref: "grep -n jwks sdks/typescript/src/middleware/verifyCore.ts confirms import from ../node/jwks.js"
        status: pass
    human_judgment: false
  - id: D5
    description: "All five examples (express-app, fastify-app, browser-rest, node-grpc, amqp-consumer) compile under tsc --noEmit -p examples/tsconfig.json (SC#4), importing only from public entry points"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "cd sdks/typescript && npx tsc --noEmit -p examples/tsconfig.json exits 0"
        status: pass
      - kind: unit
        ref: "grep -rn '\\.\\./src' examples/*.ts returns no match (only the tsconfig.json paths-mapping comment references src/, not any example source file)"
        status: pass
    human_judgment: false
  - id: D6
    description: "browser-rest.ts narrows the login result on status; amqp-consumer.ts wraps the signing key in new Sensitive(...)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -n \"case 'mfa_required'\\|case 'authenticated'\" examples/browser-rest.ts matches both branches"
        status: pass
      - kind: unit
        ref: "grep -n 'new Sensitive(' examples/amqp-consumer.ts matches"
        status: pass
    human_judgment: false

# Metrics
duration: 12min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 05: TypeScript SDK Middleware + Examples Summary

**Express and Fastify middleware sharing one local-JWKS verify core (D-27/§10, no cookie-parser peer dependency) plus five strict-compiling runnable examples (Express, Fastify, browser REST, Node gRPC, AMQP consumer) proving SC#4 — with 8 new passing middleware tests and a new `axiam-sdk/middleware` public entry point.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-01T12:26:30Z
- **Completed:** 2026-07-01T12:38:30Z
- **Tasks:** 2
- **Files modified:** 16 (13 created, 3 modified)

## Accomplishments
- Built `src/middleware/cookieHeader.ts`: `parseCookieHeader` (RFC6265-lenient `;`-split, first-`=`-split parser, no dependency) and `extractToken` (cookie-first, `Authorization: Bearer` fallback, case-insensitive scheme) — mirrors the Rust extractor's cookie-then-Bearer order exactly, no `cookie-parser`/`@fastify/cookie` peer dependency
- Built `src/middleware/verifyCore.ts`: `authenticateRequest(session, token)` — the ONE verification path both frameworks call, reusing the 17-03 `verifyAccessToken` local-JWKS verifier and mapping claims to `{userId, tenantId, roles}` (roles from the `scope` claim, space-separated); throws `AuthError` on any verification failure, honoring §10's no-longer-than-remaining-TTL rule by relying entirely on jose's own `exp` check
- Built `src/middleware/express.ts`: `axiamMiddleware(session)` — an async Express `RequestHandler` extracting the token, 401-ing a standardized JSON body on missing credentials, calling `authenticateRequest`, injecting `req.axiamUser`, and mapping `AuthzError`→403 / `AuthError`→401
- Built `src/middleware/fastify.ts`: `axiamPlugin(session)` — a `FastifyPluginAsync` registering a `preHandler` hook with the same verification flow, injecting `request.axiamUser`. Marked with Fastify's own `Symbol.for('skip-override')` plugin symbol (the same mechanism the `fastify-plugin` package wraps internally) so the hook applies to sibling routes rather than being scoped only to the plugin's own encapsulation context — discovered via a failing test that the naive nested-plugin registration silently no-ops the hook for top-level routes
- Wrote 8 new middleware tests (4 Express + 4 Fastify) using real jose-signed EdDSA tokens against a mocked JWKS endpoint (msw): valid-cookie→200+axiamUser, valid-Bearer→200+axiamUser, missing-credentials→401 JSON, invalid-token→401 JSON
- Added a new `axiam-sdk/middleware` subpath export (`package.json` `exports` + `tsup.config.ts` entry) that Task 1's middleware needed but had no public entry point for — without this, Task 2's examples could not import `axiamMiddleware`/`axiamPlugin` from a public path
- Re-exported `Sensitive` from `axiam-sdk/amqp` — `consume()`'s public signature requires a caller-constructed `Sensitive<Buffer>` signing key but the class was previously unreachable from that entry
- Created `examples/tsconfig.json`: extends the package tsconfig with `strict: true`/`noEmit: true` and a `paths` mapping resolving `axiam-sdk`/`axiam-sdk/rest`/`axiam-sdk/grpc`/`axiam-sdk/amqp`/`axiam-sdk/middleware` to their `src/*.ts` sources — `dist/` does not exist in this sandbox (no `buf` CLI, pre-existing gap from 17-01), so resolving through the package's own `exports` map (which points at `dist/*`) would fail; a buf-enabled CI run additionally verifies the built package resolves the same subpaths
- Wrote 5 examples, each importing only from public entry points: `express-app.ts` (`axiamMiddleware` guarding a protected `GET /protected` reading `req.axiamUser`), `fastify-app.ts` (`axiamPlugin`, same shape for `request.axiamUser`), `browser-rest.ts` (`login()` narrowed via `switch(result.status)` on both `'mfa_required'`/`'authenticated'` branches, then `can()`/`batchCheck()` over REST), `node-grpc.ts` (`AuthzGrpcClient.checkAccess`/`batchCheck` over gRPC, channel reused per D-10), `amqp-consumer.ts` (`consume()` with a `new Sensitive(Buffer.from(process.env.AXIAM_AMQP_SIGNING_KEY ?? '', 'hex'))` signing key)
- `express`/`fastify` moved from `devDependencies` to optional `peerDependencies` (`peerDependenciesMeta.optional: true`) since the new middleware entry's public type surface (`RequestHandler`, `FastifyPluginAsync`, etc.) now references them

## Task Commits

Each task was committed atomically:

1. **Task 1: Express + Fastify middleware over a shared local-JWKS verify core (D-27 / §10)** - `d92674f` (feat)
2. **Task 2: Five runnable examples compiling under strict mode (SC#4)** - `b754eb0` (feat)

**Plan metadata:** (pending — final docs commit follows this summary)

_Note: `tdd="true"` was declared on Task 1; tests were authored alongside implementation and passed together within the task's atomic commit, matching the pattern established in 17-01/17-03/17-04 (no separate RED/GREEN commits required by this plan's task structure)._

## Files Created/Modified
- `sdks/typescript/src/middleware/cookieHeader.ts` - `parseCookieHeader`/`extractToken`, no cookie-parser/@fastify/cookie dependency
- `sdks/typescript/src/middleware/verifyCore.ts` - `authenticateRequest(session, token)`, the one shared verification path (D-27)
- `sdks/typescript/src/middleware/express.ts` - `axiamMiddleware(session)`, injects `req.axiamUser`, 401/403 JSON
- `sdks/typescript/src/middleware/fastify.ts` - `axiamPlugin(session)`, injects `request.axiamUser`, 401/403 JSON, `skip-override` symbol
- `sdks/typescript/src/middleware/index.ts` - re-exports both middleware + shared verify core + cookie parser
- `sdks/typescript/test/middleware/express.test.ts` - 4 tests: cookie-valid, Bearer-valid, missing-creds-401, invalid-token-401
- `sdks/typescript/test/middleware/fastify.test.ts` - 4 tests: same coverage via `app.inject()`
- `sdks/typescript/examples/tsconfig.json` - strict compile gate, `paths`-mapped to `src/*.ts`
- `sdks/typescript/examples/express-app.ts` - `axiamMiddleware` + protected route example
- `sdks/typescript/examples/fastify-app.ts` - `axiamPlugin` + protected route example
- `sdks/typescript/examples/browser-rest.ts` - `login()` discriminated union + `can()`/`batchCheck()` example
- `sdks/typescript/examples/node-grpc.ts` - `AuthzGrpcClient.checkAccess`/`batchCheck` example
- `sdks/typescript/examples/amqp-consumer.ts` - `consume()` with `Sensitive` signing key example
- `sdks/typescript/package.json` - new `./middleware` export condition; `express`/`fastify` moved to optional `peerDependencies`
- `sdks/typescript/tsup.config.ts` - new `middleware/index` build entry; `express`/`fastify` added to `external`
- `sdks/typescript/src/amqp/index.ts` - re-exports `Sensitive` from `../core/index.js`

## Decisions Made
- Fastify's nested-plugin registration scopes hooks to the plugin's own encapsulation context by default — a naive `fastify.addHook('preHandler', ...)` inside `axiamPlugin` silently never fired for routes registered as siblings via `app.register(axiamPlugin(session))` followed by `app.get(...)` at the top level. Fixed by marking the returned plugin function with `Symbol.for('skip-override')` (Fastify's own public plugin-encapsulation escape hatch, the same one the `fastify-plugin` npm package wraps) rather than adding a new dependency.
- `examples/tsconfig.json` resolves the SDK via a `paths` mapping to `../src/*.ts` instead of the package's own `exports` map, because `dist/` does not exist in this sandbox (`buf` CLI unavailable, `npm run build` fails at the `prebuild`/`generate` step — pre-existing gap from 17-01/17-02/17-03/17-04). This satisfies the plan's explicit instruction to resolve "via its source (or built dist) — whichever type-checks cleanly under strict without emitting."
- Added the `axiam-sdk/middleware` subpath export (package.json + tsup.config.ts) that the plan's `<artifacts_this_phase_produces>` described ("Middleware export surface (src/middleware/index.ts)") but whose public-entry-point wiring was not explicitly listed in either task's `<files>` block — without it, Task 2's examples could not satisfy the plan's own constraint ("Every example must import ONLY from the SDK's public entry points... not from internal paths").
- Re-exported `Sensitive` from `axiam-sdk/amqp` for the same reason — `consume()`'s signature requires a `Sensitive<Buffer>` and the amqp-consumer example must construct one without reaching into another entry point.

## Deviations from Plan

### Auto-fixed Issues (Rule 2 — missing critical functionality)

**1. [Rule 2] `axiam-sdk/middleware` had no public entry point**
- **Found during:** Task 2, writing `express-app.ts`/`fastify-app.ts` — importing `axiamMiddleware`/`axiamPlugin` from a public subpath was impossible since `package.json` `exports` and `tsup.config.ts` `entry` had no `middleware` key.
- **Fix:** Added `./middleware` to `package.json` `exports` (mirroring the existing `./rest`/`./grpc`/`./amqp` shape) and a `middleware/index` entry to `tsup.config.ts`; added `express`/`fastify` to `tsup.config.ts`'s `external` list and moved them from `devDependencies` to optional `peerDependencies` in `package.json` since the middleware entry's public types now reference them.
- **Files modified:** `sdks/typescript/package.json`, `sdks/typescript/tsup.config.ts`
- **Commit:** `b754eb0`

**2. [Rule 2] `Sensitive` unreachable from `axiam-sdk/amqp`**
- **Found during:** Task 2, writing `amqp-consumer.ts` — `consume()`'s signature requires a `Sensitive<Buffer>` signing key, but `axiam-sdk/amqp`'s barrel (`src/amqp/index.ts`) never re-exported the `Sensitive` class from core, only `hmac`/`messages`/`consumer`.
- **Fix:** Added `export { Sensitive } from '../core/index.js';` to `src/amqp/index.ts`.
- **Files modified:** `sdks/typescript/src/amqp/index.ts`
- **Commit:** `b754eb0`

### Auto-fixed Issues (Rule 1 — bug)

**3. [Rule 1] Fastify `preHandler` hook silently never fired for sibling routes**
- **Found during:** Task 1, running `npx vitest run test/middleware/fastify.test.ts` — all 4 tests failed (`request.axiamUser` undefined, 401 tests returned 200) even though the Express equivalents passed immediately.
- **Issue:** Registering the hook via `fastify.addHook('preHandler', ...)` inside a plugin scopes it to that plugin's own encapsulation context by default; routes registered at the top level (as siblings of the plugin registration, matching the CONTRACT.md example's `app.use`-equivalent usage pattern) never saw the hook.
- **Fix:** Marked the plugin function with `Symbol.for('skip-override')` (and `Symbol.for('fastify.display-name')` for debuggability) — Fastify's own public plugin-encapsulation escape hatch, verified against a minimal reproduction script before applying to the real implementation.
- **Files modified:** `sdks/typescript/src/middleware/fastify.ts`
- **Verification:** `npx vitest run test/middleware/fastify.test.ts` passes (4/4).
- **Commit:** `d92674f`

---

**Total deviations:** 3 auto-fixed (2 Rule 2 missing critical functionality, 1 Rule 1 bug)
**Impact on plan:** All three were necessary to satisfy the plan's own acceptance criteria (public-entry-points-only constraint for examples; passing middleware tests for both frameworks). No scope creep — each fix is scoped to the minimal change (add an export, fix a plugin-registration bug).

## Issues Encountered
`buf` CLI remains unavailable in this sandbox (pre-existing gap since 17-01). `npm run build` fails at the `prebuild`/`generate` step (`buf: not found`), confirmed and documented rather than treated as a code defect. `npm test` (77/77 passing across the whole package, up from 69) and `npm run typecheck` (`tsc --noEmit`, clean) were the verification surface for the middleware; `npx tsc --noEmit -p examples/tsconfig.json` (clean, 0 errors) is the SC#4 verification surface for the examples, per the plan's own instruction and this plan's environment notes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `axiam-sdk/middleware` is a fully implemented, publicly exported entry point: Express + Fastify middleware, shared verify core, and cookie parser — typecheck-clean and unit-tested (8 new tests, 77/77 total)
- All five examples compile under `strict` via `examples/tsconfig.json`, satisfying SC#4; they demonstrate every persona/transport combination shipped by 17-02/17-03/17-04 end to end
- `npm run build` (tsup + buf generate) still cannot be verified end-to-end in this sandbox (pre-existing gap from 17-01) — the next buf-enabled CI run should confirm `dist/middleware/` builds correctly and that `examples/tsconfig.json` (or an equivalent CI-only variant) resolves cleanly against the built package's own `exports` map, not just the source `paths` mapping used here
- 17-06 (publish/CI) can now assume a complete SDK surface: `axiam-sdk`, `axiam-sdk/rest`, `axiam-sdk/grpc`, `axiam-sdk/amqp`, and `axiam-sdk/middleware`, plus five compiling examples as a smoke-test corpus

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED
All 13 created/modified source, test, and example files verified present on disk; both task commits (d92674f, b754eb0) verified in git log.
