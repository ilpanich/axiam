---
phase: 17-typescript-sdk
verified: 2026-07-01T14:05:00Z
status: passed
score: 8/8 must-haves verified (code-level); documentation-drift gap resolved by orchestrator closeout
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 4/8
  gaps_closed:
    - "Node persona forwards a real CSRF token on state-changing REST calls (D-05) — CR-01"
    - "The single-flight refresh guard is scoped per client/session (D-13) — CR-02"
    - "JWKS/middleware verification validates the access token's tenant_id claim against the resource server's configured tenant — CR-03"
    - "Error objects surfaced from the public API never carry raw, unredacted token/cookie material (D-16) — CR-04"
  gaps_remaining: []
  regressions: []
gaps:
  - truth: "REQUIREMENTS.md TS-01 acceptance criteria and STATE.md accurately reflect the current gap-closure status"
    status: resolved
    resolution: "Orchestrator applied the verifier's prescribed mechanical fix: flipped REQUIREMENTS.md line 460's TS-01 CSRF/refresh-guard criterion to [x] with wording reflecting CR-01/CR-02 closure; STATE.md is refreshed by the phase.complete step. No code changes were required or made."
    reason: "REQUIREMENTS.md line 460 still reads '- [ ] CSRF interceptor auto-forwards X-CSRF-Token; promise-deduplicated refresh guard (Node CSRF still unpopulated — CR-01 pending in 17-08; refresh guard is now per-session via createRefreshGuard(), CR-02 closed in 17-07)'. This line was last updated in the 17-07 completion commit (ef66b06) and was never revised after 17-08 closed CR-01/CR-04 — the checkbox is stale and factually wrong (CR-01 is no longer pending; it is closed and passes 4 regression tests). STATE.md is similarly stale: it still says 'stopped_at: Completed 17-07-PLAN.md', 'Plan: 17-07 of 2 gap-closure plans (17-07, 17-08) complete', and 'Status: 17-07 complete (CR-02, CR-03 closed); 17-08 remaining (CR-01, CR-04)' — but 17-08-SUMMARY.md documents 17-08 as complete with commits f017880/1c49288. This is a documentation/bookkeeping gap, not a code defect: all four underlying code fixes are structurally confirmed correct and covered by passing tests."
    artifacts:
      - path: ".planning/REQUIREMENTS.md"
        issue: "Line 460: TS-01 acceptance criterion checkbox unchecked and stale-worded, contradicting the actual (closed) state of CR-01/CR-02."
      - path: ".planning/STATE.md"
        issue: "current_phase progress block and narrative text describe 17-08 as 'remaining' when 17-08-SUMMARY.md shows it complete (commits f017880, 1c49288); completed_plans count (19) does not include 17-08."
    missing:
      - "Update REQUIREMENTS.md TS-01's 4th acceptance criterion to '[x]' with wording reflecting all four CRs closed (CR-01..CR-04)."
      - "Update STATE.md's stopped_at/current-position narrative and completed_plans/percent counters to reflect 17-08's completion."
    fix_direction: "Mechanical documentation sync — no code changes required. Flip the REQUIREMENTS.md checkbox and update its parenthetical to reference 17-08 closure; update STATE.md's stopped_at, narrative status lines, and progress counters to include 17-08. This can be done directly without a new gap-closure PLAN."
---

# Phase 17: TypeScript SDK Verification Report

**Phase Goal:** A TypeScript developer can use the SDK in a browser (REST-only) or Node.js (REST + gRPC + AMQP) context with correct per-persona behavior and framework middleware for Express and Fastify — a production-ready, spec-conformant SDK satisfying TS-01 and sdks/CONTRACT.md.
**Verified:** 2026-07-01T14:05:00Z
**Status:** passed (all 8 code-level truths verified; the sole documentation-drift gap was resolved by the orchestrator per the verifier's mechanical fix direction)
**Re-verification:** Yes — after gap closure (17-07, 17-08)

## Goal Achievement

### Observable Truths (carried forward from initial 17-VERIFICATION.md, re-verified against current code)

| # | Truth | Prior Status | Current Status | Evidence |
|---|-------|--------------|-----------------|----------|
| 1 | SC#1: A browser bundler importing `axiam-sdk/rest` tree-shakes all Node-only exports | VERIFIED | ✓ VERIFIED (no regression) | Not touched by 17-07/17-08; `src/rest/*` gained no new Node-only imports. `test/rest/*` suite (unaffected files) still green. |
| 2 | SC#2: Browser persona `can()`/`checkAccess()` uses REST; Node persona uses gRPC `CheckAccess` | VERIFIED | ✓ VERIFIED (no regression) | `test/rest/can.test.ts` (4/4) and `test/grpc/checkAccess.test.ts` (5/5) pass in the current 94/94 run; `callWithRefresh.ts`'s only change was routing through `session.refreshGuard` instead of the module-level `refreshOnce` — call sites and retry semantics unchanged. |
| 3 | SC#3: 5 parallel fetches on an expired token trigger exactly 1 refresh; CSRF token is auto-forwarded on state-changing requests | ⚠️ PARTIALLY FAILED (CR-01, CR-02) | ✓ VERIFIED | Within-one-session single-flight: `test/rest/singleFlightRefresh.test.ts` passes unchanged. Cross-session isolation: `test/rest/multiSessionRefresh.test.ts` — two independent `AxiamClient` instances, 5 concurrent 401s each, asserts `stateA.refreshCallCount === 1` AND `stateB.refreshCallCount === 1` AND `clientA.session.refreshGuard !== clientB.session.refreshGuard` (structural proof of no shared state). CSRF (Node persona): `test/node/csrf.test.ts` — `onAuthenticated()` populates `session.csrfToken` from a real `tough-cookie` jar; subsequent POST captures `x-csrf-token` header equal to the jar's `axiam_csrf` value; GET omits the header; `doRefresh()` resyncs on cookie rotation. All 4 new cases pass. |
| 4 | SC#4: Express and Fastify middleware examples compile under strict TypeScript and protect a sample route; package publishes as `axiam-sdk` | VERIFIED (build parts) / ✗ GAP (CR-03 tenant isolation) | ✓ VERIFIED | `test/middleware/express.test.ts` (4/4) and `test/middleware/fastify.test.ts` (4/4) pass with `tenantHeaderValue` added to their inline session doubles (non-weakening diff confirmed: only the new required field was added, zero assertion changes). `test/middleware/tenantIsolation.test.ts` (3/3): cross-tenant token (`tenant_id=tenant-1` vs. session `tenantHeaderValue=tenant-2`) is rejected with `AuthError('token tenant_id does not match configured tenant')` both at `authenticateRequest` and via `axiamMiddleware` (401 `authentication_failed`); same-tenant token is accepted as a positive control. |
| 5 | SC#5: `npm publish --dry-run` succeeds; npm publish CI pipeline runs on release tag | VERIFIED | ✓ VERIFIED (no regression) | `.github/workflows/sdk-ci-typescript.yml` untouched by 17-07/17-08 (not in either plan's `files_modified`). `npm run build` could not be re-run live in this verification sandbox (missing `buf` CLI binary for the `generate` pre-step — an environment/tooling limitation unrelated to these two gap-closure plans, which touched no build/publish config). This is unchanged from the prior VERIFIED evidence and out of scope for CR-01..CR-04. |
| 6 | Error taxonomy / status mapping (D-16/D-17) is a single source of truth and never embeds raw token strings | ✗ FAILED (CR-04) | ✓ VERIFIED | `sanitizeAxiosError()` (core/errorMapper.ts) strips `set-cookie`/`authorization`/`cookie` response headers (case-insensitive), wired as the single choke point inside `mapHttpStatusToError` (line 104: `new NetworkError(message, sanitizeAxiosError(ctx?.cause))`) AND independently applied at all four `rest/auth.ts` fallback constructors (login/verifyMfa/refresh/logout, lines 89/116/138/158: `sanitizeAxiosError(err)`). `test/core/errorRedaction.test.ts` (8/8) proves raw `axiam_access`/`axiam_refresh` substrings never appear in `JSON.stringify`/`String`/`util.inspect` output of a thrown error, and includes an explicit control case proving an *unsanitized* cause WOULD leak (demonstrating the test is meaningful, not vacuous). `test/core/errorMapper.test.ts` was updated to assert redaction instead of verbatim preservation and passes. |
| 7 | Node persona CSRF forwarding works end-to-end (D-05, all state-changing Node REST calls) | ✗ FAILED (CR-01) | ✓ VERIFIED | `SharedSession.onAuthenticated?(): Promise<void>` optional hook declared in `rest/session.ts`; `NodeSession` implements it (`node/session.ts`) via private `#syncCsrfFromJar()` reading `extractCookieValue(jar, baseUrl, CSRF_COOKIE)`. `rest/auth.ts` calls `await client.session.onAuthenticated?.()` after both `login()`'s 200 branch (line 80) and `verifyMfa()`'s success branch (line 107). `doRefresh()` also resyncs `csrfToken` after refresh (rotation-safe). 4/4 tests in `test/node/csrf.test.ts` pass, covering: initial population, GET-omits-header, doRefresh cookie-rotation resync, and pre-auth absence. |
| 8 | Middleware/JWKS enforces tenant isolation for verified tokens (core multi-tenant guarantee) | ✗ FAILED (CR-03) | ✓ VERIFIED | `VerifiableSession` (middleware/verifyCore.ts) now requires `tenantHeaderValue: string`. `authenticateRequest` enforces `claims.tenant_id !== session.tenantHeaderValue` → throws `AuthError`, checked strictly after the pre-existing `sub`/`tenant_id` presence checks (preserving their error messages/ordering). 3/3 tests in `test/middleware/tenantIsolation.test.ts` pass: cross-tenant rejection (direct call + via `axiamMiddleware` 401), same-tenant positive control. |

**Score:** 8/8 truths now verified at the code level (all four Critical gaps from the initial verification — CR-01, CR-02, CR-03, CR-04 — are closed and independently confirmed by direct source inspection plus passing regression tests).

### Full Test Suite (run live in this verification, not trusted from SUMMARY.md)

```
cd sdks/typescript && npx tsc --noEmit   → "TypeScript: No errors found"
cd sdks/typescript && npx vitest run     → Test Files  18 passed (18) / Tests  94 passed (94)
```

Verified test files include the four new/updated regression suites specific to this re-verification:
- `test/rest/multiSessionRefresh.test.ts` (1/1) — CR-02
- `test/middleware/tenantIsolation.test.ts` (3/3) — CR-03
- `test/node/csrf.test.ts` (4/4) — CR-01
- `test/core/errorRedaction.test.ts` (8/8) — CR-04
- `test/core/errorMapper.test.ts` (updated assertion, 1 new case) — CR-04

Plus regression confirmation that no pre-existing test weakened: `git diff` of `test/rest/singleFlightRefresh.test.ts`, `test/grpc/checkAccess.test.ts`, `test/middleware/express.test.ts`, `test/middleware/fastify.test.ts` between the pre-gap-closure commit (`c893322`) and HEAD shows only additive, non-assertion-weakening changes (a `jar` constructor arg threaded through; `tenantHeaderValue: 'tenant-1'` added to inline session doubles to satisfy the widened `VerifiableSession` interface).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `sdks/typescript/src/core/singleFlightRefresh.ts` | `createRefreshGuard()` factory; per-instance closures | ✓ VERIFIED | Factory returns an independent closure over a private `refreshPromise`; `refreshOnce`/`resetRefreshGuard` retained as a backward-compatible default-instance delegate (module-level singleton semantics preserved ONLY for that legacy export, not for wired transports). |
| `sdks/typescript/src/rest/session.ts` | `SharedSession.refreshGuard` per-instance field; `onAuthenticated?()` hook | ✓ VERIFIED | Line 36: `readonly refreshGuard: RefreshGuard`, constructed via `createRefreshGuard()` in the constructor (line 42). Line 53: `onAuthenticated?(): Promise<void>` optional hook declared. |
| `sdks/typescript/src/node/session.ts` | `NodeSession.onAuthenticated()`, `#syncCsrfFromJar()`, `doRefresh` resync | ✓ VERIFIED | Lines 66-69 (`onAuthenticated`), 71-73 (`#syncCsrfFromJar`), 50-57 (`doRefresh` calls `#syncCsrfFromJar()` after `tokenManager.syncFromJar()`). |
| `sdks/typescript/src/rest/interceptors.ts` | `installRefreshInterceptor` uses `session.refreshGuard(...)`, not module-level `refreshOnce` | ✓ VERIFIED | Line 71: `await session.refreshGuard(async () => { ... })`. No `refreshOnce` import remains in this file. |
| `sdks/typescript/src/grpc/callWithRefresh.ts` | Uses `session.refreshGuard(session.doRefresh)` | ✓ VERIFIED | Line 37: `await session.refreshGuard(session.doRefresh)`. No `refreshOnce` import remains. |
| `sdks/typescript/src/middleware/verifyCore.ts` | `VerifiableSession.tenantHeaderValue`; equality enforcement | ✓ VERIFIED | Line 21: `tenantHeaderValue: string` on the interface. Lines 62-64: equality throw after presence checks. |
| `sdks/typescript/src/core/errorMapper.ts` | `sanitizeAxiosError()` exported and wired at the mapper choke point | ✓ VERIFIED | Lines 30 (`SENSITIVE_RESPONSE_HEADERS`), 45-72 (`sanitizeAxiosError`), 104 (choke-point wiring in `mapHttpStatusToError`). Shallow-clones; does not mutate input (confirmed by its own test). |
| `sdks/typescript/src/rest/auth.ts` | `onAuthenticated?.()` called post-login/verifyMfa; `sanitizeAxiosError` at all 4 fallback sites | ✓ VERIFIED | Lines 80, 107 (`onAuthenticated?.()`); lines 89, 116, 138, 158 (`sanitizeAxiosError(err)` at login/verifyMfa/refresh/logout fallback `NetworkError` constructors). |
| `sdks/typescript/test/rest/multiSessionRefresh.test.ts` | CR-02 regression | ✓ VERIFIED | Exists, substantive (two real `AxiamClient` instances, two msw-backed base URLs, concurrent 401 storms, structural guard-identity assertion), passes. |
| `sdks/typescript/test/middleware/tenantIsolation.test.ts` | CR-03 regression | ✓ VERIFIED | Exists, substantive (real EdDSA keypair + JWKS via msw, cross-tenant reject + same-tenant positive control + Express-level 401), passes. |
| `sdks/typescript/test/node/csrf.test.ts` | CR-01 regression | ✓ VERIFIED | Exists, substantive (real `tough-cookie` CookieJar, not jsdom/document.cookie), passes 4/4. |
| `sdks/typescript/test/core/errorRedaction.test.ts` | CR-04 regression | ✓ VERIFIED | Exists, substantive, includes a deliberate "control case" test proving an unsanitized cause WOULD leak — demonstrates the redaction test is not vacuous, passes 8/8. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `rest/auth.ts` login()/verifyMfa() success | `NodeSession.onAuthenticated()` | `client.session.onAuthenticated?.()` | ✓ WIRED | Confirmed at lines 80 and 107; optional-chaining makes it a no-op for the browser `SharedSession`. |
| `NodeSession.onAuthenticated()` / `doRefresh()` | `session.csrfToken` | `#syncCsrfFromJar()` reading `extractCookieValue(jar, baseUrl, CSRF_COOKIE)` | ✓ WIRED | Confirmed in node/session.ts lines 56, 68, 71-73. |
| `rest/interceptors.ts` refresh trigger | `SharedSession.refreshGuard` (per-instance) | direct method call, no shared module state | ✓ WIRED | Line 71 of interceptors.ts; no `refreshOnce` import remains in this file (grep-confirmed). |
| `grpc/callWithRefresh.ts` refresh trigger | `session.refreshGuard` (same instance as REST for that session) | direct method call | ✓ WIRED | Line 37; inherited from the same `SharedSession`/`NodeSession` instance, so REST and gRPC share ONE guard per session but never across sessions. |
| `middleware/verifyCore.ts` `authenticateRequest` | `session.tenantHeaderValue` | equality comparison against `claims.tenant_id` | ✓ WIRED | Lines 62-64; `NodeSession` already exposes `tenantHeaderValue` via inheritance from `SharedSession`, confirmed non-breaking. |
| `core/errorMapper.ts` `mapHttpStatusToError` | `NetworkError.cause` | `sanitizeAxiosError(ctx?.cause)` | ✓ WIRED | Line 104 — single choke point. |
| `rest/auth.ts` fallback `NetworkError` constructors (4 call sites) | `NetworkError.cause` | `sanitizeAxiosError(err)` applied directly (bypasses the mapper) | ✓ WIRED | Lines 89, 116, 138, 158 — confirmed each of the four call sites applies sanitization, closing the gap the mapper choke point alone would have missed. |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| TS-01 | 17-01 through 17-08 | TypeScript SDK — browser (REST) + Node (REST+gRPC+AMQP), Express/Fastify middleware, npm publish | ⚠️ CODE SATISFIED / DOCUMENTATION STALE | All code-level acceptance criteria are now genuinely satisfied: CSRF interceptor auto-forwards `X-CSRF-Token` for BOTH browser and Node personas; the refresh guard is promise-deduplicated AND correctly per-session-scoped. However, `.planning/REQUIREMENTS.md` line 460 still shows this criterion as an unchecked `[ ]` box with text claiming "CR-01 pending in 17-08" — stale since 17-08 (commits f017880, 1c49288) has closed it. `.planning/STATE.md` is similarly stale (describes 17-08 as not yet done). This is a paperwork/bookkeeping gap, not a functional one — see Gaps section below. |

No orphaned requirements found. TS-01 remains the only requirement ID mapped to Phase 17.

### Anti-Patterns Found

Scanned all files modified across 17-07 and 17-08 (both source and test):

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | No TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER markers found | — | Clean |

No stub patterns, empty handlers, or hardcoded-empty-data anti-patterns found in any of the 17-07/17-08 modified source or test files. The `sanitizeAxiosError` implementation is a genuine shallow-clone-and-strip function (not a no-op), confirmed by its own "does not mutate the original input object" test and the "unsanitized cause WOULD have leaked" control-case test.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full typecheck clean | `cd sdks/typescript && npx tsc --noEmit` | "TypeScript: No errors found" | ✓ PASS |
| Full test suite green | `cd sdks/typescript && npx vitest run` | 18 files / 94 tests, 0 failures | ✓ PASS |
| CR-01 regression (named) | `npx vitest run test/node/csrf.test.ts` (subset of the full run above; individually confirmed in verbose output) | 4/4 pass | ✓ PASS |
| CR-02 regression (named) | `npx vitest run test/rest/multiSessionRefresh.test.ts` (subset, confirmed in verbose output) | 1/1 pass | ✓ PASS |
| CR-03 regression (named) | `npx vitest run test/middleware/tenantIsolation.test.ts` (subset, confirmed in verbose output) | 3/3 pass | ✓ PASS |
| CR-04 regression (named) | `npx vitest run test/core/errorRedaction.test.ts` (subset, confirmed in verbose output) | 8/8 pass | ✓ PASS |
| Commit existence | `git cat-file -e <hash>` for 07e3d87, 15bc3f8, f017880, 1c49288 | All 4 objects exist in git history | ✓ PASS |
| dist build / publish dry-run | `npm run build` | FAILED: `sh: 1: buf: not found` (missing `buf` CLI in this sandbox) | ? SKIP — environment tooling gap unrelated to 17-07/17-08 (neither plan touched build/codegen config; SC#5 was already fully verified live in the initial verification pass and is not re-claimed here as freshly re-run) |

### Probe Execution

Not applicable — no `scripts/*/tests/probe-*.sh` conventions found in this project; no probes declared in 17-07-PLAN.md or 17-08-PLAN.md.

### Human Verification Required

None. All four gap closures are deterministically confirmed via direct source inspection plus passing automated regression tests exercising the exact failure modes the initial verification identified (cross-session refresh cross-wiring, cross-tenant token acceptance, Node CSRF header omission, raw token leak via error serialization). No visual/runtime-behavior-dependent ambiguity remains.

### Gaps Summary

**All four Critical security/correctness gaps (CR-01 through CR-04) confirmed closed at the code level:**

1. **CR-01 (Node CSRF)** — closed via `SharedSession.onAuthenticated?()` hook + `NodeSession.#syncCsrfFromJar()`, called from `rest/auth.ts` after login/verifyMfa and from `doRefresh()`. 4 passing regression tests using a real cookie jar (not a browser/jsdom shim).
2. **CR-02 (cross-session refresh)** — closed via `createRefreshGuard()` factory; `SharedSession.refreshGuard` is a per-instance closure; both REST and gRPC transports call it instead of the old module-level `refreshOnce`. Structural test proves two sessions' guards are distinct object references AND that concurrent 401 storms on two independent sessions each trigger exactly one refresh with no cross-satisfaction.
3. **CR-03 (tenant isolation bypass)** — closed via `VerifiableSession.tenantHeaderValue` + equality enforcement in `authenticateRequest`, checked after existing presence checks. A cross-tenant token is now rejected with `AuthError` both directly and through the Express middleware (401 `authentication_failed`); same-tenant tokens still succeed (positive control confirmed).
4. **CR-04 (token leak via error `cause`)** — closed via `sanitizeAxiosError()`, wired at the single `mapHttpStatusToError` choke point AND independently applied at all four `rest/auth.ts` fallback `NetworkError` constructors that bypass the mapper. A deliberate control-case test proves the redaction test itself is meaningful (an unsanitized cause DOES leak when the helper is skipped).

All 94 tests pass (18 files) in a live `npx vitest run`; `npx tsc --noEmit` is clean. No regressions were introduced in the four pre-existing test files whose inline session doubles needed widening (`singleFlightRefresh.test.ts`, `checkAccess.test.ts`, `express.test.ts`, `fastify.test.ts`) — diffed against the pre-gap-closure commit and confirmed additive-only, zero assertion weakening. No debt markers (TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER) found in any of the 17-07/17-08 modified files.

**One non-blocking documentation-drift gap remains:** `.planning/REQUIREMENTS.md`'s TS-01 acceptance criterion (line 460) and `.planning/STATE.md`'s narrative/progress fields were updated after 17-07 but never after 17-08 completed — they currently read as if CR-01 is still "pending in 17-08" when it has in fact been closed (commits f017880, 1c49288, both independently confirmed to exist and both covered by passing tests in this verification). This is pure bookkeeping drift, not a functional defect: every code-level truth and artifact this phase is responsible for delivering is present, wired, and test-covered. It should be corrected (mechanically, no new plan needed) before the phase is marked complete/archived, since REQUIREMENTS.md's checkbox state is the project's own traceability contract for TS-01 and an auditor reading REQUIREMENTS.md today would draw the wrong conclusion.

**Recommended next step:** Update `.planning/REQUIREMENTS.md` line 460 to `[x]` (all four CRs closed) and refresh `.planning/STATE.md`'s stopped_at/progress fields to reflect 17-08's completion, then proceed to phase closure. No further code changes or gap-closure plans are required — this is a direct documentation edit, not a re-run of `/gsd-plan-phase --gaps`.

---

_Verified: 2026-07-01T14:05:00Z_
_Verifier: Claude (gsd-verifier)_
