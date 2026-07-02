---
phase: 17-typescript-sdk
plan: 08
subsystem: auth
tags: [typescript, security, csrf, token-redaction, error-taxonomy, node-persona, gap-closure]

# Dependency graph
requires:
  - phase: 17-typescript-sdk (plans 01-06)
    provides: AxiamClient REST core, SharedSession/NodeSession, cookie jar (CSRF_COOKIE/extractCookieValue), error taxonomy (NetworkError), mapHttpStatusToError, rest/auth.ts
  - phase: 17-typescript-sdk (plan 07)
    provides: per-session refresh guard (CR-02), tenant-isolated middleware (CR-03) — on the tree before this plan ran
provides:
  - Node-persona CSRF token population via SharedSession.onAuthenticated() hook + NodeSession jar-read (CR-01, D-05)
  - Set-Cookie/sensitive-header redaction of NetworkError.cause via sanitizeAxiosError() (CR-04, D-16)
affects: [any Node SDK consumer making state-changing REST calls (login/refresh/logout/checkAccess/batchCheck); any consumer logging/serializing thrown AxiamErrors]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Optional session-level lifecycle hook: SharedSession declares onAuthenticated?() (browser no-op); NodeSession implements it to sync jar-derived state after login/verifyMfa (CR-01)"
    - "Single choke-point sanitization: mapHttpStatusToError always passes ctx.cause through sanitizeAxiosError() before constructing NetworkError, with the same guard re-applied at the four auth.ts fallback constructors that bypass the mapper (CR-04)"

key-files:
  created:
    - sdks/typescript/test/node/csrf.test.ts
    - sdks/typescript/test/core/errorRedaction.test.ts
  modified:
    - sdks/typescript/src/node/session.ts
    - sdks/typescript/src/rest/session.ts
    - sdks/typescript/src/rest/auth.ts
    - sdks/typescript/src/core/errorMapper.ts
    - sdks/typescript/test/grpc/checkAccess.test.ts
    - sdks/typescript/test/core/errorMapper.test.ts

key-decisions:
  - "onAuthenticated?() is declared optional on SharedSession (browser persona has no jar to sync and reads document.cookie per request) and implemented only by NodeSession — auth.ts calls it via optional chaining (client.session.onAuthenticated?.()) so the browser path is a no-op"
  - "NodeSession's constructor now receives the CookieJar so #syncCsrfFromJar() can read axiam_csrf via the existing extractCookieValue(jar, baseUrl, CSRF_COOKIE) helper, mirroring TokenManager.syncFromJar()"
  - "doRefresh() resyncs csrfToken after refresh because the refresh endpoint may rotate the axiam_csrf cookie"
  - "sanitizeAxiosError() returns a shallow clone (never mutates the caller's axios error) and strips set-cookie/authorization/cookie case-insensitively; it is wired as the single choke point inside mapHttpStatusToError AND applied at the four auth.ts fallback NetworkError(msg, err) constructors that do not route through the mapper"

patterns-established:
  - "Any raw external error attached as a public AxiamError.cause must first pass through sanitizeAxiosError() (or equivalent redaction) — raw response headers may carry token material and are reachable via ordinary error logging"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "Node persona forwards a real X-CSRF-Token equal to the jar's axiam_csrf cookie on state-changing REST calls once a CSRF cookie exists (CR-01, D-05)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/test/node/csrf.test.ts#Node persona forwards X-CSRF-Token equal to the jar's axiam_csrf value"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/node/csrf.test.ts#doRefresh resyncs csrfToken from a rotated cookie"
        status: pass
    human_judgment: false
  - id: D2
    description: "A NetworkError from a failed login/refresh whose response carried Set-Cookie token material never exposes the raw cookie value via console.log / JSON.stringify / util.inspect (CR-04, D-16)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/test/core/errorRedaction.test.ts#raw axiam_access/axiam_refresh never surface via JSON.stringify/String/util.inspect"
        status: pass
      - kind: unit
        ref: "sdks/typescript/test/core/errorMapper.test.ts#cause is redacted (set-cookie stripped) instead of preserved verbatim"
        status: pass
    human_judgment: false

# Metrics
duration: 10min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 08: Gap Closure — Node CSRF Population + Error-Cause Redaction Summary

**Populated the Node persona's `session.csrfToken` from the cookie jar via a new `onAuthenticated()` session hook (CR-01), and redacted `Set-Cookie`/sensitive headers from `NetworkError.cause` via `sanitizeAxiosError()` at the mapper choke point and all four auth.ts fallback sites (CR-04).**

## Performance

- **Duration:** ~10 min
- **Completed:** 2026-07-01
- **Tasks:** 2
- **Files modified:** 8 (2 new test files; 6 modified source/test files)

## Accomplishments

- **CR-01 closed (Node CSRF, D-05):** `SharedSession` now declares an optional `onAuthenticated?(): Promise<void>` hook. `NodeSession` implements it to (a) resync the cached access token and (b) read the `axiam_csrf` cookie out of its `tough-cookie` jar into `session.csrfToken` via the existing `extractCookieValue(jar, baseUrl, CSRF_COOKIE)` helper (mirroring `TokenManager.syncFromJar()`). `rest/auth.ts` calls `client.session.onAuthenticated?.()` after both the `login()` 200 branch and `verifyMfa()` success. `NodeSession.doRefresh()` also resyncs `csrfToken` after refresh, since the endpoint may rotate the cookie. Result: every state-changing Node REST call now forwards a real `X-CSRF-Token` instead of an empty header. The browser persona is unaffected (no `onAuthenticated` implementation → optional-chaining no-op).
- **CR-04 closed (error leak, D-16):** added `sanitizeAxiosError(err)` in `core/errorMapper.ts`, which shallow-clones an axios-error-shaped input and strips `set-cookie`, `authorization`, and `cookie` response headers (case-insensitive) before the error can become a public `NetworkError.cause`. Wired as the single choke point inside `mapHttpStatusToError` (`new NetworkError(message, sanitizeAxiosError(ctx?.cause))`), and additionally applied at the four `auth.ts` fallback `NetworkError(msg, err)` constructors (login/verifyMfa/refresh/logout) that bypass the mapper. Raw `axiam_access`/`axiam_refresh` token material can no longer surface through `console.log`/`JSON.stringify`/`util.inspect` of a thrown error.
- Added `test/node/csrf.test.ts` (4 cases): a jar-backed `NodeSession` driven through login→POST asserts `X-CSRF-Token` equals the jar's `axiam_csrf` value, that a GET omits the header, and that `doRefresh()` picks up a rotated cookie.
- Added `test/core/errorRedaction.test.ts` (8 cases): proves raw token substrings never appear in `JSON.stringify(err)` / `String(err)` / `util.inspect(err)` for errors thrown from login/refresh error paths carrying `Set-Cookie`.
- Updated `test/core/errorMapper.test.ts`: the previous assertion locking in verbatim `cause` preservation was replaced with an assertion that a header-bearing `cause` is redacted (set-cookie stripped), while non-header causes are still passed through.
- Updated `test/grpc/checkAccess.test.ts` (2 lines): adjusted its session double for the widened `onAuthenticated` surface.

## Task Commits

Each task was committed atomically:

1. **Task 1: CR-01 — populate session.csrfToken for the Node persona** - `f017880` (fix)
2. **Task 2: CR-04 — redact Set-Cookie from NetworkError.cause** - `1c49288` (fix)

## Files Created/Modified

- `sdks/typescript/src/node/session.ts` - `onAuthenticated()` + private `#syncCsrfFromJar()`; constructor now takes the `CookieJar`; `doRefresh()` resyncs `csrfToken`
- `sdks/typescript/src/rest/session.ts` - `SharedSession.onAuthenticated?(): Promise<void>` optional hook declaration
- `sdks/typescript/src/rest/auth.ts` - calls `onAuthenticated?.()` after login/verifyMfa success; `sanitizeAxiosError()` applied at all four fallback `NetworkError` constructors
- `sdks/typescript/src/core/errorMapper.ts` - `sanitizeAxiosError()` + choke-point wiring in `mapHttpStatusToError`
- `sdks/typescript/test/node/csrf.test.ts` (new) - CR-01 regression: jar-backed Node CSRF forwarding
- `sdks/typescript/test/core/errorRedaction.test.ts` (new) - CR-04 regression: no raw token via serialization
- `sdks/typescript/test/core/errorMapper.test.ts` - assert redaction instead of verbatim cause preservation
- `sdks/typescript/test/grpc/checkAccess.test.ts` - session-double adjustment for `onAuthenticated`

## Decisions Made

- `onAuthenticated` is optional on the base class so the browser persona stays a no-op — the browser reads `document.cookie` on every request and has no jar to sync.
- `sanitizeAxiosError()` never mutates the caller's error (returns a shallow clone) and is applied at both the mapper choke point and the fallback constructors, since the fallbacks construct `NetworkError` directly without routing through `mapHttpStatusToError`.

## Deviations from Plan

None — plan executed exactly as written. Both tasks' `<action>`/`<done>` criteria were followed; no architectural changes, no new dependencies, no scope expansion beyond CR-01 and CR-04.

## Issues Encountered

The executor agent completed and atomically committed both tasks (`f017880`, `1c49288`) with the working tree clean, but hit a transient `API Error: Overloaded` immediately before writing this SUMMARY.md and the tracking commit. Per the execute-phase safe-resume/close-out policy, the orchestrator independently re-verified the tree (`npx tsc --noEmit` clean; `npx vitest run` = 94/94 passing across 18 files, including the 4 CR-01 and 8 CR-04 cases) and then wrote this SUMMARY and updated STATE.md/ROADMAP.md. No code work was re-run or duplicated.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All four Critical gaps from `17-VERIFICATION.md` are now closed: CR-01 (Node CSRF) and CR-04 (error redaction) in this plan; CR-02 (per-session refresh guard) and CR-03 (tenant isolation) in 17-07.
- Full suite is green: 94/94 tests pass (`npx vitest run`), `npx tsc --noEmit` is clean, no new runtime dependencies introduced.
- Ready for phase re-verification (`gsd-verifier`) to confirm the 4 previously-failed observable truths now hold.

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED

- FOUND: sdks/typescript/test/node/csrf.test.ts
- FOUND: sdks/typescript/test/core/errorRedaction.test.ts
- FOUND: sdks/typescript/src/node/session.ts (onAuthenticated + #syncCsrfFromJar)
- FOUND: sdks/typescript/src/core/errorMapper.ts (sanitizeAxiosError)
- FOUND: commit f017880 (Task 1 — CR-01)
- FOUND: commit 1c49288 (Task 2 — CR-04)
