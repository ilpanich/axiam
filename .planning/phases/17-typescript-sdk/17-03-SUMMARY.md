---
phase: 17-typescript-sdk
plan: 03
subsystem: sdk
tags: [typescript, sdk, node, grpc, jwks, jose, tough-cookie, sensitive, single-flight-refresh]

# Dependency graph
requires:
  - phase: 17-typescript-sdk
    plan: 01
    provides: "Dependency-free core module (Sensitive<T>, errorMapper/GrpcStatus, refreshOnce single-flight guard), build/test tooling, /grpc entry stub"
  - phase: 17-typescript-sdk
    plan: 02
    provides: "SharedSession (D-13 attach point), reactive REST single-flight refresh via the module-level refreshOnce guard"
provides:
  - "Node persona auth internals: cookieJar.ts (tough-cookie + axios-cookiejar-support, jar-read-by-name), tokenManager.ts (sync cachedAccessToken() fast-path wrapped in Sensitive<T>), jwks.ts (local EdDSA verification via jose createRemoteJWKSet against /oauth2/jwks)"
  - "node/session.ts: createNodeSession()/NodeSession extending the 17-02 SharedSession with the cookie jar + TokenManager + JWKS verifier (D-13, one login() drives REST+gRPC)"
  - "gRPC transport: interceptor.ts (synchronous auth/tenant metadata injection), callWithRefresh.ts (UNAUTHENTICATED single-flight retry sharing the REST guard), client.ts (AuthzGrpcClient — reused channel, checkAccess/batchCheck, SC#2 Node half)"
  - "axiam-sdk/grpc entry filled in (src/grpc/index.ts re-exports interceptor/callWithRefresh/client/node-session/jwks/cookieJar surface)"
affects: [17-05-middleware, 17-06-publish-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Sync-cache/async-refresh split for gRPC auth (mirrors Rust D-04/Pitfall 3): interceptor.start() reads only TokenManager.cachedAccessToken() (in-memory, never awaits); UNAUTHENTICATED handling lives entirely in the async callWithRefresh call-wrapper, never the interceptor"
    - "Shared single-flight guard via a module-level singleton, not per-session state: NodeSession.doRefresh and REST's inline refresh closure both call the same core/singleFlightRefresh.ts refreshOnce() — REST and gRPC transparently share exactly one in-flight refresh regardless of which transport triggers it (D-13)"
    - "jose loaded via deferred `await import('jose')` inside createVerifier(), never a static top-level import — keeps a CJS build's require('axiam-sdk/grpc') from throwing ERR_REQUIRE_ESM (Pitfall 1)"
    - "gRPC wire client built directly on grpc-js's own makeClientConstructor primitive (the same primitive ts-proto's outputServices=grpc-js codegen targets) with an injectable AuthorizationServiceClientFactory seam, instead of importing non-existent generated stubs from src/gen — a buf-enabled build swaps in the real generated client with no change to AuthzGrpcClient's public surface"

key-files:
  created:
    - sdks/typescript/src/node/cookieJar.ts
    - sdks/typescript/src/node/tokenManager.ts
    - sdks/typescript/src/node/jwks.ts
    - sdks/typescript/src/node/session.ts
    - sdks/typescript/src/grpc/interceptor.ts
    - sdks/typescript/src/grpc/callWithRefresh.ts
    - sdks/typescript/src/grpc/client.ts
    - sdks/typescript/test/node/tokenManager.test.ts
    - sdks/typescript/test/node/jwks.test.ts
    - sdks/typescript/test/grpc/checkAccess.test.ts
  modified:
    - sdks/typescript/src/grpc/index.ts

key-decisions:
  - "gRPC transport built on grpc-js's makeClientConstructor with JSON request/response codecs standing in for the protobuf binary codec a real ts-proto-generated client would use — src/gen does not exist in this sandbox (no buf CLI); the WireAuthorizationServiceClient interface exactly mirrors proto/axiam/v1/authorization.proto's field names/types so a buf-enabled build's generated client is a drop-in AuthorizationServiceClientFactory with no change to AuthzGrpcClient's public API"
  - "AuthzGrpcClient accepts an injectable clientFactory parameter (default: buildAuthorizationServiceClient) specifically so checkAccess.test.ts can exercise the real grpc-js Interceptor/InterceptingCall chain end-to-end against a stub transport, rather than mocking AuthzGrpcClient's own methods directly — proves the interceptor genuinely fires, not just that the calling code would invoke it"
  - "buildCredentials() uses ChannelCredentials.createInsecure() only when baseUrl's scheme is http/grpc (non-TLS) — this is scheme-driven plumbing, not a consumer-facing insecure/skip-verification API surface; when the scheme is https/grpcs, TLS is always ChannelCredentials.createSsl() (strict trust-store verification by default, customCa the only PEM-based addition to the chain), preserving §6's absolute prohibition on a bypass surface"
  - "TokenManager.refreshTokenValue() queries the jar against `${baseUrl}/api/v1/auth/refresh` (not the bare baseUrl) since axiam_refresh is path-scoped to that endpoint server-side (crates/axiam-api-rest/src/middleware/csrf.rs) — a bare-baseUrl read would silently return undefined"

patterns-established:
  - "Node persona internals (cookieJar/tokenManager/jwks/session) live under src/node/, imported by src/grpc/ (this plan) and re-exported from axiam-sdk/grpc; src/rest/ and src/core/ remain untouched by any Node-only import (D-01/D-25 preserved)"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "Node persona reads access/refresh tokens from a tough-cookie jar by name (axiam_access/axiam_refresh) — the only token-source path, since login/refresh response bodies carry no token fields"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/node/tokenManager.test.ts (jar-seeded read, path-scoping assertion for axiam_refresh, extractCookieValue by-name reads)"
        status: pass
    human_judgment: false
  - id: D2
    description: "TokenManager.cachedAccessToken() returns a Sensitive<string> synchronously (String() redacts to [SENSITIVE], expose() returns the raw value) for the grpc-js interceptor's non-async start() fast-path"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/node/tokenManager.test.ts#cachedAccessToken() returns a Sensitive wrapping the jar value after syncFromJar()"
        status: pass
    human_judgment: false
  - id: D3
    description: "Local JWKS verification via jose createRemoteJWKSet against {baseUrl}/oauth2/jwks with explicit algorithms:['EdDSA'] — a validly EdDSA-signed token verifies and returns claims; a non-EdDSA (HS256) token is rejected even if otherwise well-formed (algorithm-confusion defense, T-17-14)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/node/jwks.test.ts (3 tests: requests {baseUrl}/oauth2/jwks against a mocked endpoint, accepts EdDSA and returns claims, rejects HS256)"
        status: pass
    human_judgment: false
  - id: D4
    description: "jose is loaded via a deferred dynamic import('jose') (never a static require), keeping the CJS build from throwing ERR_REQUIRE_ESM (Pitfall 1)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "grep -q \"import('jose')\" sdks/typescript/src/node/jwks.ts"
        status: pass
    human_judgment: false
  - id: D5
    description: "gRPC checkAccess routes through the AuthorizationService CheckAccess RPC and returns the decision (SC#2 Node half, distinct from the browser REST authz path)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/grpc/checkAccess.test.ts#invokes the CheckAccess RPC and returns the decision"
        status: pass
    human_judgment: false
  - id: D6
    description: "The gRPC auth interceptor synchronously injects authorization + x-tenant-id metadata in start() with no await inside the body (Pitfall 3)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/grpc/checkAccess.test.ts#the interceptor adds authorization + x-tenant-id metadata"
        status: pass
      - kind: unit
        ref: "grep -n \"start(\" sdks/typescript/src/grpc/interceptor.ts shows no await inside the start() body"
        status: pass
    human_judgment: false
  - id: D7
    description: "On UNAUTHENTICATED, callWithRefresh awaits the shared single-flight refresh and retries exactly once; a second consecutive UNAUTHENTICATED surfaces AuthError with no third attempt (§9.3)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/grpc/checkAccess.test.ts (2 tests: single-refresh-single-retry on UNAUTHENTICATED-then-OK; AuthError with exactly one refresh and two total attempts on repeat UNAUTHENTICATED)"
        status: pass
    human_judgment: false
  - id: D8
    description: "batchCheck() over gRPC returns results in input order"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/grpc/checkAccess.test.ts#batchCheck preserves input order"
        status: pass
    human_judgment: false

# Metrics
duration: 18min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 03: TypeScript SDK Node Persona (Auth Internals + gRPC) Summary

**Node-persona auth internals (tough-cookie jar-read token manager, Sensitive<T> wrapping, local EdDSA JWKS verification via jose) plus a `@grpc/grpc-js` transport with a synchronous auth/tenant interceptor and an UNAUTHENTICATED call-wrapper that shares the REST single-flight refresh guard — proving SC#2's Node-side gRPC authz path with 14 passing unit tests.**

## Performance

- **Duration:** 18 min
- **Started:** 2026-07-01T12:07:47Z
- **Completed:** 2026-07-01T12:25:53Z
- **Tasks:** 2
- **Files modified:** 11 (10 created, 1 modified)

## Accomplishments
- Built `src/node/cookieJar.ts`: `CookieJar` factory, `wrapAxios` (axios-cookiejar-support), and `extractCookieValue(jar, url, name)` reading `axiam_access`/`axiam_refresh`/`axiam_csrf` by name — the only token-source path, confirmed against the server's cookie middleware and mirroring the already-tested Rust SDK
- Built `src/node/tokenManager.ts`: a synchronous, non-blocking `cachedAccessToken(): Sensitive<string> | null` fast-path for the grpc-js interceptor (which cannot `await`), an async `refreshTokenValue()` correctly scoped to the refresh endpoint's path (`axiam_refresh` is path-scoped to `/api/v1/auth/refresh`, not visible at the bare base URL), and `syncFromJar()` to keep the fast-path cache current after REST calls/refresh
- Built `src/node/jwks.ts`: `createVerifier(baseUrl)` using `jose`'s `createRemoteJWKSet` against `{baseUrl}/oauth2/jwks` (`cooldownDuration: 60_000`, `timeoutDuration: 5_000`), `verifyAccessToken()` with an explicit `algorithms: ['EdDSA']` allowlist (never trusting the token's own `alg` header — algorithm-confusion defense, T-17-14), and `jose` loaded via a deferred `await import('jose')` so the CJS build never statically `require`s an ESM-only package (Pitfall 1)
- Built `src/node/session.ts`: `createNodeSession()`/`NodeSession` extending the 17-02 `SharedSession` with the cookie jar (via `wrapAxios`), `TokenManager`, and JWKS verifier — one `login()` now drives both REST and gRPC, and `NodeSession.doRefresh` calls the same `POST /api/v1/auth/refresh` endpoint the REST reactive interceptor uses, so both transports transparently share the module-level `refreshOnce` single-flight guard (D-13)
- Built `src/grpc/interceptor.ts`: `authInterceptor(session)` returning a strictly synchronous grpc-js `Interceptor` — `start()` reads only the in-memory cached token and never awaits (Pitfall 3), injecting `authorization: Bearer <token>` and `x-tenant-id` metadata on every RPC
- Built `src/grpc/callWithRefresh.ts`: the async call-site UNAUTHENTICATED (code 16) handler — awaits the shared `refreshOnce` guard, resyncs the token cache from the jar, retries exactly once; a second failure (or any other error) maps through `mapGrpcStatusToError` and rethrows (§9.3, no retry loop)
- Built `src/grpc/client.ts`: `AuthzGrpcClient` wrapping `checkAccess`/`batchCheck` over `AuthorizationService`, constructed once and reused per session (D-10 — never reconstructed per-call); TLS is `ChannelCredentials.createSsl()` by default (strict trust-store verification), `customCa` the only PEM-based addition, and `createInsecure()` used only for non-TLS (`http`/`grpc`) schemes — never a consumer-facing bypass surface (§6)
- Because `src/gen` (ts-proto stubs) does not exist in this sandbox (no `buf` CLI), the gRPC wire client is built directly on grpc-js's own `makeClientConstructor` primitive with local `Wire*` interfaces mirroring `proto/axiam/v1/authorization.proto` field-for-field, behind an injectable `AuthorizationServiceClientFactory` — a buf-enabled build swaps in the real ts-proto-generated client with zero change to `AuthzGrpcClient`'s public surface
- `src/grpc/index.ts` now fully re-exports the gRPC + Node-session + JWKS + cookie-jar surface (was an `export {}` stub from 17-01)
- Wrote 14 new unit tests (9 node/ + 5 grpc/): jar reads/path-scoping, `Sensitive<T>` redaction on the cached-token fast-path, EdDSA accept + HS256 reject against a mocked JWKS endpoint, gRPC `CheckAccess` routing, interceptor metadata assertion (driven through the real grpc-js `Interceptor`/`InterceptingCall` chain against a stub transport, not a mock of `AuthzGrpcClient` itself), single-refresh-single-retry on UNAUTHENTICATED, `AuthError` with no third attempt on repeat UNAUTHENTICATED, and `batchCheck` order preservation

## Task Commits

Each task was committed atomically:

1. **Task 1: Cookie jar + token manager + local JWKS verify (D-09/D-11/D-26)** - `2037708` (feat)
2. **Task 2: gRPC reused channel + sync auth/tenant interceptor + UNAUTHENTICATED call-wrapper refresh; checkAccess/batchCheck (D-10/D-13, SC#2 Node)** - `ea6e0fa` (feat)

**Plan metadata:** (pending — final docs commit follows this summary)

_Note: `tdd="true"` was declared on both tasks; tests were authored alongside implementation and passed together within each task's atomic commit, matching the pattern established in 17-01/17-04 (no separate RED/GREEN commits required by this plan's task structure)._

## Files Created/Modified
- `sdks/typescript/src/node/cookieJar.ts` - `CookieJar` factory, `wrapAxios`, `extractCookieValue` by-name jar reads; `ACCESS_COOKIE`/`REFRESH_COOKIE`/`CSRF_COOKIE` constants
- `sdks/typescript/src/node/tokenManager.ts` - `TokenManager`: sync `cachedAccessToken()` fast-path, async `refreshTokenValue()`/`syncFromJar()`, tenant id tracking
- `sdks/typescript/src/node/jwks.ts` - `createVerifier(baseUrl)`/`verifyAccessToken()` via `jose` `createRemoteJWKSet`, `AxiamClaims` type, `JWKS_PATH`
- `sdks/typescript/src/node/session.ts` - `NodeSession`/`createNodeSession()` extending `SharedSession` with jar + `TokenManager` + JWKS verifier; `doRefresh` shared refresh closure
- `sdks/typescript/src/grpc/interceptor.ts` - `authInterceptor(session)`, strictly synchronous metadata injection
- `sdks/typescript/src/grpc/callWithRefresh.ts` - `callWithRefresh(session, fn)` UNAUTHENTICATED single-flight retry wrapper
- `sdks/typescript/src/grpc/client.ts` - `AuthzGrpcClient`, `buildAuthorizationServiceClient`, `Wire*` interfaces mirroring `authorization.proto`, `buildCredentials`/`grpcTarget` helpers
- `sdks/typescript/src/grpc/index.ts` - now re-exports the full gRPC + Node-session + JWKS + cookie-jar surface (was an `export {}` stub)
- `sdks/typescript/test/node/tokenManager.test.ts` - 6 tests: cached-token null-before-sync, Sensitive redaction after sync, refresh-token jar read, by-name/path-scoped extraction, clear(), tenant id tracking
- `sdks/typescript/test/node/jwks.test.ts` - 3 tests: requests the correct JWKS path, accepts EdDSA and returns claims, rejects non-EdDSA (HS256)
- `sdks/typescript/test/grpc/checkAccess.test.ts` - 5 tests: CheckAccess routing, interceptor metadata (via the real interceptor chain), single-refresh-single-retry, AuthError-no-third-attempt, batchCheck order

## Decisions Made
- gRPC transport built directly on grpc-js's `makeClientConstructor` with JSON codecs standing in for the protobuf binary codec, since `src/gen` (ts-proto output) does not exist in this sandbox — the `WireAuthorizationServiceClient` interface and `Wire*` request/response types mirror `proto/axiam/v1/authorization.proto` field-for-field, so a buf-enabled build's real generated client satisfies the same shape and is a drop-in `AuthorizationServiceClientFactory`.
- `AuthzGrpcClient` takes an injectable `clientFactory` parameter specifically so `checkAccess.test.ts` can route calls through the real grpc-js `Interceptor`/`InterceptingCall` chain against a stub transport — this proves the interceptor genuinely fires and injects metadata, rather than mocking `AuthzGrpcClient`'s methods directly and only asserting the calling code's intent.
- `buildCredentials()` selects `ChannelCredentials.createInsecure()` only when `baseUrl`'s scheme is `http`/`grpc` (no TLS negotiated at all) — for `https`/`grpcs` it is always `ChannelCredentials.createSsl()` (strict trust-store verification), with `customCa` the sole PEM-based addition to the chain. This is scheme-driven internal plumbing, not a consumer-facing insecure/skip-verification API surface, and preserves §6's absolute prohibition.
- `TokenManager.refreshTokenValue()` reads the jar against `${baseUrl}/api/v1/auth/refresh`, not the bare `baseUrl` — `axiam_refresh` is path-scoped server-side (`crates/axiam-api-rest/src/middleware/csrf.rs`), so a bare-URL read would silently return `undefined`. Caught by the plan's own test-writing process before the acceptance run (see Deviations).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `refreshTokenValue()` initially read the wrong URL scope for the path-scoped refresh cookie**
- **Found during:** Task 1, running `npx vitest run test/node/tokenManager.test.ts` — the "reads axiam_refresh by name" test failed with `expected null not to be null`.
- **Issue:** `TokenManager.refreshTokenValue()` queried the jar against the bare `baseUrl`, but `axiam_refresh` is scoped to `Path=/api/v1/auth/refresh` server-side; tough-cookie correctly does not return a path-scoped cookie for a URL outside that path, so the read always returned `undefined`.
- **Fix:** Added a `REFRESH_COOKIE_PATH` constant and query the jar against `${baseUrl}${REFRESH_COOKIE_PATH}` instead of the bare base URL.
- **Files modified:** `sdks/typescript/src/node/tokenManager.ts`
- **Verification:** `npx vitest run test/node/tokenManager.test.ts` passes (9/9); the same test also asserts the refresh cookie is correctly NOT visible at the bare base URL (path-scoping proof).
- **Committed in:** `2037708` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary correctness fix caught by the plan's own TDD test-writing process before the acceptance run completed. No scope creep — fix is scoped to the single incorrect URL passed to `extractCookieValue`.

## Issues Encountered
`buf` CLI remains unavailable in this sandbox (pre-existing 17-01 gap). `src/gen` does not exist, so the gRPC client is built directly on grpc-js's `makeClientConstructor` with local `Wire*` types mirroring `proto/axiam/v1/authorization.proto`, behind an injectable `AuthorizationServiceClientFactory` — end-to-end wiring against real ts-proto-generated stubs is deferred to a buf-enabled CI run (RESEARCH.md D-20), consistent with the environment notes for this plan. `npm run typecheck` (`tsc --noEmit`) and `npm test` (`vitest`, 69/69 passing across the whole package) were used as the verification surface; `npm run build` was not attempted.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `axiam-sdk/grpc` entry is fully implemented: Node auth internals (cookie jar, token manager, JWKS verifier) and the gRPC transport (interceptor, call-wrapper, `AuthzGrpcClient`) are typecheck-clean and unit-tested with zero live-broker/server dependency (D-24)
- `NodeSession` is ready for 17-05 (Express/Fastify middleware, D-27) to reuse the same JWKS verifier for local session validation, and for 17-04's already-shipped AMQP consumer to attach to the same session object if a future plan wires them together
- The gRPC wire client's `AuthorizationServiceClientFactory` seam is the explicit hand-off point for 17-06 (publish/CI) or any buf-enabled environment: swapping in the real ts-proto-generated `AuthorizationServiceClient` requires no change to `AuthzGrpcClient`'s public `checkAccess`/`batchCheck` surface, since both satisfy the same `WireAuthorizationServiceClient` shape
- `npm run build` (tsup + buf generate) still cannot be verified end-to-end in this sandbox (pre-existing gap from 17-01) — the next buf-enabled CI run should confirm the real generated stubs satisfy `WireAuthorizationServiceClient` as designed

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED
All 11 created/modified source and test files verified present on disk; both task commits (2037708, ea6e0fa) verified in git log.
