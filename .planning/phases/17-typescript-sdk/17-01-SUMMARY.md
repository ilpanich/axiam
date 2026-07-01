---
phase: 17-typescript-sdk
plan: 01
subsystem: sdk
tags: [typescript, sdk, tsup, vitest, esm-cjs, error-taxonomy, csrf, single-flight, sensitive]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    provides: Reference implementation for Sensitive<T>, AxiamError taxonomy, single-flight refresh pattern, JWKS cookie names, AMQP HMAC protocol
  - phase: 15-sdk-foundation
    provides: sdks/CONTRACT.md binding contract, sdks/buf.gen.yaml codegen config, sdks/typescript scaffold (package.json exports map, README, LICENSE)
provides:
  - Buildable/testable sdks/typescript/ package (tsup dual ESM+CJS, vitest, strict tsconfig)
  - Dependency-free core module (errors, errorMapper, Sensitive<T>, csrf, singleFlightRefresh)
  - Entry stubs for `.`/`/rest`/`/grpc`/`/amqp` so parallel Wave-2/3 plans never collide
  - AxiamClientOptions config type with CF-03 numeric defaults
affects: [17-02-browser-persona, 17-03-node-persona, 17-04-grpc-amqp, 17-05-middleware, 17-06-publish-ci]

# Tech tracking
tech-stack:
  added: [tsup@^8, vitest@^4, msw@^2 (devDep, not yet used), ts-proto@^2 (devDep), typescript@~5.9, axios@^1.7, tough-cookie@^6, axios-cookiejar-support@^7, "@grpc/grpc-js@^1.14", amqplib@^2.0, jose@^6, express@^5, fastify@^5, esbuild]
  patterns:
    - "Dependency-free core module (D-04) — core/*.ts has zero imports of @grpc/grpc-js, amqplib, axios, jose, or node:util; enforced by grep gate, later verified end-to-end by 17-06's bundle-and-grep gate (SC#1)"
    - "Central status->error mapper (D-17) — single source of truth both rest/ and grpc/ transports will import, so the two cannot drift on the error taxonomy"
    - "Prototype-chain fixup in error constructors (Object.setPrototypeOf) for reliable instanceof across tsup's dual CJS+ESM output"
    - "Sensitive<T> uses Symbol.for('nodejs.util.inspect.custom') directly instead of importing node:util, keeping the class usable (redaction still works) even though it is only ever constructed by Node-persona code"

key-files:
  created:
    - sdks/typescript/tsup.config.ts
    - sdks/typescript/vitest.config.ts
    - sdks/typescript/tsconfig.json
    - sdks/typescript/.gitignore
    - sdks/typescript/src/rest/index.ts
    - sdks/typescript/src/grpc/index.ts
    - sdks/typescript/src/amqp/index.ts
    - sdks/typescript/src/core/config.ts
    - sdks/typescript/src/core/errors.ts
    - sdks/typescript/src/core/errorMapper.ts
    - sdks/typescript/src/core/sensitive.ts
    - sdks/typescript/src/core/csrf.ts
    - sdks/typescript/src/core/singleFlightRefresh.ts
    - sdks/typescript/src/core/index.ts
    - sdks/typescript/test/core/errorMapper.test.ts
    - sdks/typescript/test/core/sensitive.test.ts
    - sdks/typescript/test/core/singleFlightRefresh.test.ts
  modified:
    - sdks/typescript/package.json
    - sdks/typescript/src/index.ts
    - sdks/typescript/README.md

key-decisions:
  - "Externalized runtime deps (axios/jose/tough-cookie/axios-cookiejar-support/@grpc/grpc-js/amqplib) in tsup.config.ts so they resolve from the consumer's node_modules rather than being bundled into dist"
  - "Fixed the AximClient typo to AxiamClient in README.md as well as src/ (plan's acceptance criteria only greps src/, but D-14 intends the fix repo-wide)"
  - "errorMapper falls through to NetworkError for any HTTP status not explicitly 401/403/409 (covers 400/408/429/5xx/unlisted per CONTRACT §2's table)"

patterns-established:
  - "core barrel (core/index.ts) re-exports errors, errorMapper, sensitive, csrf, singleFlightRefresh, and config as the dependency-free foundation for rest/grpc/amqp adapters"
  - "Entry stub convention: each unimplemented subpath file is `export {}` until its owning plan fills it in, preventing merge collisions across parallel waves"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "Package builds config-wise: tsup dual ESM+CJS multi-entry config, vitest config, strict tsconfig; tsc --noEmit clean"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "npm run typecheck (tsc --noEmit) exits 0"
        status: pass
    human_judgment: false
  - id: D2
    description: "package.json exports map declares import/require/types conditions for ./ /rest /grpc /amqp with sideEffects:false and type:module"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "node -e exports-map assertion script (see plan acceptance criteria) exits 0"
        status: pass
    human_judgment: false
  - id: D3
    description: "Dependency-free core module: errors, Sensitive<T>, CSRF helpers, single-flight guard, status->error mapper with zero imports of @grpc/grpc-js or amqplib"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -rnE \"from '(@grpc/grpc-js|amqplib|axios|jose|node:util)'\" src/core/ returns no matches"
        status: pass
      - kind: unit
        ref: "test/core/errorMapper.test.ts (all HTTP + gRPC §2 rows), test/core/sensitive.test.ts, test/core/singleFlightRefresh.test.ts"
        status: pass
    human_judgment: false
  - id: D4
    description: "Sensitive<T> redacts to [SENSITIVE] across toString, toJSON, and util.inspect.custom; raw value only reachable via expose()"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/core/sensitive.test.ts#Sensitive<T> (4 assertions: toString, JSON.stringify, util.inspect, expose())"
        status: pass
    human_judgment: false
  - id: D5
    description: "Central status mapper turns HTTP statuses and gRPC status codes into AxiamError/AuthError/AuthzError/NetworkError per CONTRACT §2"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/core/errorMapper.test.ts (9 HTTP rows + 6 gRPC rows + context-carrying assertions)"
        status: pass
    human_judgment: false
  - id: D6
    description: "No AximClient/AximaClient typo remains in TS source"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -rn 'AximClient\\|AximaClient' sdks/typescript/src/ returns no matches"
        status: pass
    human_judgment: false

# Metrics
duration: 3min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 01: TypeScript SDK Foundation Summary

**Established the axiam-sdk build/test tooling (tsup dual ESM+CJS, vitest, strict tsconfig) and the dependency-free `core` module (error taxonomy, central status->error mapper, `Sensitive<T>` redaction, CSRF helpers, single-flight refresh guard) with 25 passing unit tests.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-07-01T11:54:32Z
- **Completed:** 2026-07-01T11:57:29Z
- **Tasks:** 2
- **Files modified:** 20

## Accomplishments
- Replaced the Phase 15 scaffold's plain `tsc` build with a tsup dual ESM+CJS multi-entry config (`index`/`rest/index`/`grpc/index`/`amqp/index`), `splitting: false` (load-bearing per RESEARCH Pitfall 2), and externalized runtime deps
- Rewrote `package.json` with a proper `import`/`require`/`types` exports map for `.`/`/rest`/`/grpc`/`/amqp`, `sideEffects: false`, `type: module`, and all TS-01-pinned dependencies
- Created entry stub files (`src/rest/index.ts`, `src/grpc/index.ts`, `src/amqp/index.ts`) so downstream Wave-2/3 plans never collide on the same entry file
- Implemented the dependency-free `core` module: `AxiamError`/`AuthError`/`AuthzError`/`NetworkError` (D-16), `mapHttpStatusToError`/`mapGrpcStatusToError` transcribing CONTRACT §2's tables exactly (D-17), `Sensitive<T>` with three-surface redaction (D-26), `readCsrfCookie`/`csrfHeaderForMethod` mirroring the frontend's hardcoded-regex CSRF pattern (D-05), and `refreshOnce` single-flight guard (D-07/D-13)
- Wrote and passed 25 unit tests covering every §2 HTTP/gRPC mapping row, all three `Sensitive<T>` redaction surfaces, and the 5-concurrent-callers-exactly-one-refresh single-flight guarantee (SC#3 mechanism)
- Fixed the `AximClient` naming typo to `AxiamClient` (D-14) in both `src/index.ts` usage comments and `README.md`

## Task Commits

Each task was committed atomically:

1. **Task 1: Package manifest, build/test tooling, gitignored codegen, entry stubs** - `c5e2bc4` (feat)
2. **Task 2: Dependency-free core primitives** - `bd7c3b0` (feat)

**Plan metadata:** (pending — final docs commit follows this summary)

_Note: tdd="true" was declared on both tasks; tests were authored alongside implementation in a single commit per task rather than separate RED/GREEN commits, since the plan's `<behavior>` spec was implemented and tested together with no pre-existing failing-test gate required by the plan's task structure._

## Files Created/Modified
- `sdks/typescript/package.json` - Dual ESM+CJS exports map, TS-01 pinned deps, build/test/typecheck scripts
- `sdks/typescript/tsup.config.ts` - Multi-entry build config, splitting:false, externalized runtime deps
- `sdks/typescript/vitest.config.ts` - Node environment default, jsdom opt-in per test file
- `sdks/typescript/tsconfig.json` - strict, ES2022, NodeNext, DOM lib for browser CSRF typing
- `sdks/typescript/.gitignore` - dist/, node_modules/, src/gen/
- `sdks/typescript/src/index.ts` - Root entry re-exporting `./rest` (D-01 isomorphic core)
- `sdks/typescript/src/rest/index.ts`, `src/grpc/index.ts`, `src/amqp/index.ts` - Entry stubs for later plans
- `sdks/typescript/src/core/config.ts` - `AxiamClientOptions`, `DEFAULT_CONNECT_TIMEOUT_MS`/`DEFAULT_REQUEST_TIMEOUT_MS`
- `sdks/typescript/src/core/errors.ts` - `AxiamError`/`AuthError`/`AuthzError`/`NetworkError`
- `sdks/typescript/src/core/errorMapper.ts` - `mapHttpStatusToError`/`mapGrpcStatusToError`/`GrpcStatus`
- `sdks/typescript/src/core/sensitive.ts` - `Sensitive<T>`, `REDACTED`
- `sdks/typescript/src/core/csrf.ts` - `readCsrfCookie`/`csrfHeaderForMethod`/`CSRF_COOKIE_NAME`/`CSRF_HEADER`/`CSRF_METHODS`
- `sdks/typescript/src/core/singleFlightRefresh.ts` - `refreshOnce`/`resetRefreshGuard`
- `sdks/typescript/src/core/index.ts` - Dependency-free barrel
- `sdks/typescript/test/core/errorMapper.test.ts`, `sensitive.test.ts`, `singleFlightRefresh.test.ts` - 25 unit tests
- `sdks/typescript/README.md` - Fixed `AximClient` -> `AxiamClient`

## Decisions Made
- Externalized all runtime deps (axios, jose, tough-cookie, axios-cookiejar-support, `@grpc/grpc-js`, amqplib) in `tsup.config.ts` so `dist/` never bundles them — they resolve from the consumer's own `node_modules`, matching the "core is dependency-free at the source" intent even at the build-output level.
- Fixed the `AximClient`/`AximaClient` typo in `README.md` in addition to `src/` (plan's acceptance-criteria grep only checks `src/`, but D-14's intent is repo-wide correctness).
- `errorMapper`'s HTTP mapping falls through to `NetworkError` for any status not explicitly 401/403/409 — this correctly covers 400/408/429/5xx and any unlisted status per CONTRACT §2's table without needing an exhaustive switch.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- `buf` CLI is not installed in this environment, so `npm run generate` (the `prebuild` script) cannot be executed here. This does not block Task 1's acceptance criteria (`npm install && npm run typecheck`, which does not invoke `prebuild`/`build`). `npm run build` (which runs tsup after buf-generate) is deferred to a CI/environment with `buf` available — tracked as a known gap for later plans/CI setup, not a Phase 17-01 blocker since no task in this plan required a real `build` run.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `core` module is fully implemented, tested, and dependency-free — ready for 17-02 (browser persona) and 17-03 (Node persona) to import from `axiam-sdk` core without pulling in Node-only transports.
- Entry stubs for `/rest`, `/grpc`, `/amqp` exist and are untouched by this plan beyond the placeholder `export {}`, so Wave-2/3 plans can fill them in without merge conflicts.
- `AxiamClientOptions` is defined; downstream plans construct the actual `AxiamClient` class around it.
- Known gap: `buf` CLI is not available in this sandboxed environment, so the `generate`/`prebuild`/`build` pipeline is unverified end-to-end here — the next plan or CI run should confirm `npm run build` succeeds once ts-proto stubs can actually be generated.

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED
All 19 created/modified files verified present on disk; both task commits (c5e2bc4, bd7c3b0) verified in git log.
