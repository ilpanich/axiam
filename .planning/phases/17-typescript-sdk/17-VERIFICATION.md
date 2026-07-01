---
phase: 17-typescript-sdk
verified: 2026-07-01T13:10:00Z
status: gaps_found
score: 4/8 must-haves verified (4 confirmed Critical security/correctness gaps from code review)
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "Node persona forwards a real CSRF token on state-changing REST calls (D-05)"
    status: failed
    reason: "session.csrfToken is declared as a mutable field but is only ever cleared (set to undefined) — nothing in the Node code path ever writes a real value into it. Every Node-originated POST/PUT/PATCH/DELETE (login, refresh, logout, checkAccess, batchCheck) sends an empty X-CSRF-Token once a CSRF cookie exists server-side, which the server's CSRF double-submit middleware will reject."
    artifacts:
      - path: "sdks/typescript/src/rest/interceptors.ts"
        issue: "Line 33-34: csrfHeaderForMethod is called with session.csrfToken, which is never populated by any writer in the Node path."
      - path: "sdks/typescript/src/rest/session.ts"
        issue: "Line 25: csrfToken: string | undefined — declared as the Node token store but has no writer."
      - path: "sdks/typescript/src/node/session.ts"
        issue: "Line 35-38: doRefresh() calls tokenManager.syncFromJar() but never reads the axiam_csrf cookie out of the jar into session.csrfToken."
      - path: "sdks/typescript/src/rest/auth.ts"
        issue: "Line 155: logout() sets session.csrfToken = undefined — the only other place csrfToken is touched, and it's another clear, not a write."
    missing:
      - "A jar-read step (mirroring TokenManager.syncFromJar()) that extracts the axiam_csrf cookie value from the Node cookie jar and assigns it to session.csrfToken, invoked after login()/verifyMfa() succeed and after doRefresh()."
      - "A Node-specific CSRF integration test (analogous to test/rest/csrf.test.ts but going through a real tough-cookie jar instead of document.cookie) proving X-CSRF-Token is forwarded correctly for the Node persona."
    fix_direction: "Add extractCookieValue(jar, baseUrl, CSRF_COOKIE) read to NodeSession (node/session.ts) — call it from doRefresh() and from a post-login/verifyMfa hook (auth.ts needs a session-level hook since it operates on the SharedSession-typed client.session, not NodeSession specifically) — and assign the result to session.csrfToken. Add test/node/csrf.test.ts driving a real jar-backed NodeSession through login->POST and asserting X-CSRF-Token equals the jar's axiam_csrf value."

  - truth: "The single-flight refresh guard (SC#3 mechanism) is scoped per client/session, not shared across unrelated AxiamClient instances in the same process (D-13)"
    status: failed
    reason: "core/singleFlightRefresh.ts declares refreshPromise at module scope. Both rest/interceptors.ts and grpc/callWithRefresh.ts import and call the SAME module-level refreshOnce function. If a process constructs more than one AxiamClient/NodeSession (multi-tenant backend holding one client per tenant, or two independent SDK consumers in the same process), two 401s on DIFFERENT sessions occurring concurrently will have the second caller silently await the first session's in-flight refresh — resolving as if its own session had been refreshed when a completely different session/tenant's /api/v1/auth/refresh was actually called. This is a correctness bug that becomes a cross-tenant/cross-session data-integrity issue in any multi-client Node process, which is the SDK's own documented target use case (a server-side multi-tenant consumer)."
    artifacts:
      - path: "sdks/typescript/src/core/singleFlightRefresh.ts"
        issue: "Line 9: let refreshPromise: Promise<void> | null = null; — module-level singleton, not per-session."
      - path: "sdks/typescript/src/rest/interceptors.ts"
        issue: "Line 71: refreshOnce(async () => { await session.axios.post(...) }) — closure captures 'session' but the guard itself is shared across ALL sessions in the process."
      - path: "sdks/typescript/src/grpc/callWithRefresh.ts"
        issue: "Line 36 (import), call site awaits the same module-level refreshOnce with a different session's doRefresh closure."
    missing:
      - "A per-session (or per-SharedSession-instance) refresh guard instead of a process-wide module singleton."
      - "A regression test that constructs two independent AxiamClient/NodeSession instances, triggers concurrent 401s on both, and asserts each session's own refresh endpoint is called (not cross-wired)."
    fix_direction: "Convert core/singleFlightRefresh.ts's refreshOnce into a factory (e.g. createRefreshGuard()) that returns a session-scoped closure holding its own refreshPromise; instantiate one guard per SharedSession/NodeSession at construction time and thread it through installRefreshInterceptor and callWithRefresh instead of importing the shared module-level function."

  - truth: "JWKS/middleware verification validates the access token's tenant_id claim against the resource server's configured tenant (cross-tenant auth bypass prevention, core tenant-isolation guarantee)"
    status: failed
    reason: "authenticateRequest in middleware/verifyCore.ts only checks that claims.tenant_id is present (truthy) — it never compares it to the tenant the middleware/session was constructed for. Since JWKS is documented as organization-wide (not tenant-scoped) — node/jwks.ts:5 — a validly-signed access token issued for Tenant A passes verification unchanged when presented to a resource server instance configured for Tenant B in the same org. This directly undermines the project's stated core guarantee (CLAUDE.md: 'Tenants provide full data isolation') and is a genuine cross-tenant authentication bypass, not a cosmetic gap."
    artifacts:
      - path: "sdks/typescript/src/middleware/verifyCore.ts"
        issue: "Line 13-15: VerifiableSession = { jwksVerifier: Verifier } — does not carry an expected/configured tenant identifier at all. Line 48-49: only checks `if (!claims.tenant_id)` (presence), never equality against a configured tenant."
      - path: "sdks/typescript/src/node/jwks.ts"
        issue: "Line 5 (comment) confirms the JWKS endpoint is organization-wide, not tenant-scoped — meaning any token signed by the org's key will pass jose's signature check regardless of which tenant it was minted for."
    missing:
      - "VerifiableSession must carry the expected tenant identifier (NodeSession already exposes tenantHeaderValue via inheritance from SharedSession)."
      - "authenticateRequest must reject when claims.tenant_id !== session's configured tenant, before returning the identity."
      - "A cross-tenant test: sign a token for tenant-1, construct/verify against a session configured for tenant-2, assert AuthError/401 is returned."
    fix_direction: "Add tenantHeaderValue: string to the VerifiableSession interface in middleware/verifyCore.ts and enforce `if (claims.tenant_id !== session.tenantHeaderValue) throw new AuthError('token tenant_id does not match configured tenant')` after the existing presence checks. This is non-breaking for existing NodeSession callers since NodeSession already has tenantHeaderValue."

  - truth: "Error objects surfaced from the public API never carry raw, unredacted token/cookie material reachable via console.log/JSON.stringify (D-16 no-raw-token-in-error-fields invariant)"
    status: failed
    reason: "NetworkError.cause (core/errors.ts) is a real, enumerable public class field, and every failing call site in rest/auth.ts (login, verifyMfa, refresh, logout) passes the raw caught axios error verbatim as cause. On a login/refresh error path where the server has already issued Set-Cookie headers (containing the literal axiam_access/axiam_refresh values) before the client observes/maps the error, err.response.headers['set-cookie'] on that raw AxiosError is reachable via networkError.cause.response.headers, and appears in plain console.log(err)/JSON.stringify(err) output. This contradicts the module's own documented invariant ('No error message or field may embed a raw token string (D-16)') and the SDK's stated intent behind its own CI token-leak gate (which only scans built dist/ output for literal 'eyJ' strings and would NOT catch this runtime leak). test/core/errorMapper.test.ts:28-32 explicitly asserts cause is preserved verbatim, confirming this is by design rather than an untested oversight."
    artifacts:
      - path: "sdks/typescript/src/core/errors.ts"
        issue: "Line 38-39: readonly cause?: unknown — a real enumerable field with no redaction wrapper, unlike Sensitive<T> which has custom toString/toJSON/util.inspect.custom redaction."
      - path: "sdks/typescript/src/rest/auth.ts"
        issue: "Lines 82-84, 107-109, 128-130, 149-150 (mapHttpStatusToError(..., { cause: err })) — every auth call site attaches the raw caught axios error as cause."
      - path: "sdks/typescript/src/core/errorMapper.ts"
        issue: "Line 43-56: mapHttpStatusToError accepts and forwards ctx?.cause unmodified into NetworkError — no sanitization step exists anywhere in the chain."
      - path: "sdks/typescript/test/core/errorMapper.test.ts"
        issue: "Line 28-32: test explicitly asserts cause is preserved verbatim (`expect((err as NetworkError).cause).toBe(cause)`), locking in the leaky behavior as intended rather than flagging it."
    missing:
      - "Redaction/sanitization of Set-Cookie (and any other sensitive response headers) before attaching a raw axios error as NetworkError.cause, OR replacing the raw error with a minimal { message, status } diagnostic object that drops the header-bearing response entirely."
      - "A test proving that a NetworkError thrown from login/refresh with a Set-Cookie-bearing response never yields the raw cookie value from console.log(err)/JSON.stringify(err)/util.inspect(err)."
    fix_direction: "Add a sanitizeAxiosError(err) helper in rest/auth.ts (or core/errorMapper.ts) that strips the set-cookie response header (and any other Set-Cookie-bearing structure) before it is passed as cause at each of the four auth.ts call sites; or simpler, stop passing the full axios error as cause and instead extract only { message, status } for NetworkError's cause. Update errorMapper.test.ts to assert redaction instead of verbatim-preservation once fixed."
---

# Phase 17: TypeScript SDK Verification Report

**Phase Goal:** Deliver a production-ready, spec-conformant AXIAM TypeScript/JavaScript client SDK (isomorphic REST+auth core, Node gRPC + auth internals, Node AMQP consumer, Express/Fastify middleware, runnable examples, and a CI/publish pipeline), satisfying requirement TS-01 and the sdks/CONTRACT.md conformance contract.
**Verified:** 2026-07-01T13:10:00Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP.md Phase 17 Success Criteria + PLAN must_haves)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | SC#1: A browser bundler importing `axiam-sdk/rest` tree-shakes all Node-only exports (zero `@grpc/grpc-js`/`amqplib` in browser bundle) | VERIFIED | `node scripts/bundle-grep.mjs` run live against actual `dist/rest/index.mjs` build output: `OK: browser bundle ... contains no @grpc/grpc-js or amqplib reference (SC#1)`. |
| 2 | SC#2: Browser persona `can()`/`checkAccess()` uses REST (`POST /api/v1/authz/check`); Node persona uses gRPC `CheckAccess` — each persona uses only its viable transport | VERIFIED | `src/rest/authz.ts` posts to `/api/v1/authz/check`; `src/grpc/client.ts`/`callWithRefresh.ts` route through the gRPC `AuthorizationService`; `test/rest/can.test.ts` and `test/grpc/checkAccess.test.ts` pass (confirmed in the 77/77 full `vitest run`). |
| 3 | SC#3: 5 parallel fetches on an expired token trigger exactly 1 refresh; CSRF token is auto-forwarded on state-changing requests | ⚠️ PARTIALLY FAILED | The single-flight mechanism is proven correct **within one session** (`test/rest/singleFlightRefresh.test.ts` passes), but the guard is a process-wide singleton (CR-02, see Gaps) — the "exactly 1 refresh" guarantee does not hold across multiple `AxiamClient`/`NodeSession` instances in one process. CSRF auto-forwarding works for the **browser** persona only; the **Node** persona never populates `csrfToken` (CR-01, see Gaps) — a must-have for a Node-and-browser dual-persona SDK. |
| 4 | SC#4: Express and Fastify middleware examples compile under strict TypeScript and protect a sample route; package publishes as `axiam-sdk` | VERIFIED | `npx tsc --noEmit -p examples/tsconfig.json` exits 0 against the built dist (run live). `test/middleware/express.test.ts` and `fastify.test.ts` pass (200/401 paths). **However**, the middleware's tenant-isolation guarantee is broken — see CR-03 in Gaps; the middleware "protects a route" but not against cross-tenant tokens. |
| 5 | SC#5: `npm publish --dry-run` succeeds; npm publish CI pipeline runs on release tag | VERIFIED | `npm publish --dry-run` run live: succeeds, packs `dist/` (39 files, excludes `src/gen`/`node_modules`). `.github/workflows/sdk-ci-typescript.yml` contains `test` job (bundle-grep, CJS-require smoke, `eyJ` leak gate, TLS-lint, dry-run) and a `publish` job gated on `refs/tags/sdks/typescript/v*` with `id-token: write` + `npm publish --provenance`. |
| 6 | Error taxonomy / status mapping (D-16/D-17) is a single source of truth and never embeds raw token strings | ✗ FAILED | Taxonomy/mapping mechanism itself is correct and unit-tested (errorMapper.test.ts passes all HTTP/gRPC rows). But the "never embeds raw token strings" half of D-16 is violated: `NetworkError.cause` carries the raw unredacted axios error, which can leak `Set-Cookie` session/refresh token values on login/refresh error paths (CR-04, see Gaps). |
| 7 | Node persona CSRF forwarding works end-to-end (D-05, applies to all state-changing Node REST calls: login/refresh/logout/checkAccess/batchCheck) | ✗ FAILED | Confirmed via direct code read: `session.csrfToken` has no writer anywhere in the Node code path (CR-01). |
| 8 | Middleware/JWKS enforces tenant isolation for verified tokens (core multi-tenant guarantee) | ✗ FAILED | Confirmed via direct code read: `authenticateRequest` never compares `claims.tenant_id` to a configured tenant; `VerifiableSession` doesn't even carry one (CR-03). |

**Score:** 4/8 truths fully verified; 4 confirmed FAILED (all four map 1:1 to the 17-REVIEW.md Critical findings CR-01 through CR-04).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `sdks/typescript/src/core/*` | Dependency-free error taxonomy, status mapper, Sensitive<T>, CSRF helpers, single-flight guard | ✓ VERIFIED (existence/substance) / ✗ GAP (correctness) | Files exist, are substantive, unit-tested. `Sensitive<T>` redaction verified correct. `singleFlightRefresh.ts` and `errors.ts` exist and work as designed, but that design itself has the CR-02/CR-04 gaps documented above. |
| `sdks/typescript/src/rest/*` | AxiamClient REST core, session, interceptors, auth, authz | ✓ VERIFIED (existence/substance/wiring) / ✗ GAP (CR-01) | All files present, wired, tests pass. CSRF interceptor code exists but the Node half of its data source (`session.csrfToken`) is never populated. |
| `sdks/typescript/src/node/*` | cookieJar, tokenManager, jwks, session | ✓ VERIFIED | Jar reads, Sensitive-wrapped tokens, EdDSA-only JWKS verification all confirmed by direct code read and passing tests (`test/node/`). |
| `sdks/typescript/src/grpc/*` | client, interceptor, callWithRefresh | ✓ VERIFIED (existence/substance/wiring) / ✗ GAP (CR-02) | Reused channel, synchronous interceptor (no await in start()), UNAUTHENTICATED retry-once all present and tested. Shares the same flawed module-level `refreshOnce` singleton as REST. |
| `sdks/typescript/src/amqp/*` | hmac, messages, consumer | ✓ VERIFIED | HMAC constant-time verify, verify-before-handler, nack-no-requeue on every failure path, security event without signature/key — all confirmed by direct code read and passing `test/amqp/` suite. No review findings against this module. |
| `sdks/typescript/src/middleware/*` | verifyCore, express, fastify, cookieHeader | ✓ VERIFIED (existence/substance/wiring) / ✗ GAP (CR-03) | Both frameworks share one verify core, inject identity, return 401/403, no cookie-parser dependency — all confirmed. The shared verify core omits tenant-scoping (CR-03), a correctness gap affecting both frameworks identically. |
| `sdks/typescript/examples/*` | 5 runnable examples, strict-compiling | ✓ VERIFIED | `npx tsc --noEmit -p examples/tsconfig.json` exits 0 (run live against built dist). |
| `.github/workflows/sdk-ci-typescript.yml` | Full CI/publish pipeline with SC#1/leak/TLS-lint/dry-run gates + tag publish | ✓ VERIFIED | Confirmed by direct read: bundle-grep, CJS-require smoke, eyJ leak gate, TLS-lint gate, dry-run on PR job; tag-gated publish job with `id-token: write` + `--provenance`. |
| `sdks/CONTRACT.md` (§3 + naming edits) | Cookie double-submit canonical for browser; AximaClient→AxiamClient | ✓ VERIFIED | Confirmed by grep: §3 states "cookie double-submit" and "axiam_csrf" as canonical browser behavior; zero `AximaClient`/`AximClient` occurrences remain in CONTRACT.md or README.md. |
| `sdks/typescript/README.md` | CONTRACT conformance statement | ✓ VERIFIED | Line 13: "This SDK conforms to CONTRACT.md §1–§10." confirmed present. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `rest/interceptors.ts` (Node CSRF read) | `session.csrfToken` | jar-read sync | ✗ NOT_WIRED | No call site anywhere writes to `session.csrfToken`; only clears exist (CR-01). |
| `rest/interceptors.ts` refresh guard | `grpc/callWithRefresh.ts` refresh guard | shared `core/singleFlightRefresh.ts` module singleton | ⚠️ WIRED-BUT-OVERBROAD | Both correctly import the same function (D-13 "shared guard" intent honored) but the guard is shared across the ENTIRE PROCESS, not scoped to one session as the design doc and CR-02 fix direction requires (CR-02). |
| `middleware/verifyCore.ts` | tenant-scoping check | `session.tenantHeaderValue` (available on NodeSession) | ✗ NOT_WIRED | `VerifiableSession` interface (the type middleware actually uses) doesn't expose or consume any tenant field at all; `authenticateRequest` never reads it (CR-03). |
| `core/errorMapper.ts` `ctx.cause` | `NetworkError.cause` | direct passthrough, no sanitization | ⚠️ WIRED-BUT-UNSAFE | The pipe exists and works as coded, but nothing in the pipe redacts Set-Cookie-bearing axios errors before they become a public field (CR-04). |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| TS-01 | 17-01 through 17-06 (all plans declare `requirements: [TS-01]`) | TypeScript SDK — browser (REST) + Node (REST+gRPC+AMQP), Express/Fastify middleware, npm publish | ⚠️ PARTIALLY SATISFIED | REQUIREMENTS.md marks TS-01 acceptance criteria checked (`[x]`), and the mechanical/build deliverables (transports, tree-shaking, examples, CI/publish) are genuinely present and verified. However, TS-01's own acceptance line "CSRF interceptor auto-forwards `X-CSRF-Token`; promise-deduplicated refresh guard" is only half-true: it works in the browser persona and within a single session, but fails for the Node persona (CR-01) and across multiple sessions in one process (CR-02). REQUIREMENTS.md's `[x]` marks should not be trusted as final until CR-01/CR-02 are closed — this verification treats TS-01 as not yet fully satisfied for an IAM SDK's security-critical surface. |

No orphaned requirements found — TS-01 is the only requirement ID declared across all 6 plans and it matches the single REQUIREMENTS.md entry mapped to Phase 17.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/rest/session.ts` | 25 | Mutable public field declared but never assigned a real value in its intended (Node) path | 🛑 Blocker (= CR-01) | Silent security-relevant no-op; CSRF protection absent for an entire persona. |
| `src/core/singleFlightRefresh.ts` | 9 | Module-level mutable singleton used to back a per-session invariant | 🛑 Blocker (= CR-02) | Cross-session/cross-tenant refresh cross-wiring in any multi-client process. |
| `src/middleware/verifyCore.ts` | 13-15, 48-49 | Presence-only claim check where an equality/scoping check was required | 🛑 Blocker (= CR-03) | Cross-tenant authentication bypass — undermines the project's stated multi-tenant isolation guarantee. |
| `src/core/errors.ts` | 38-39 | Unredacted raw external error object exposed as a public, enumerable class field | 🛑 Blocker (= CR-04) | Token/cookie leak via ordinary error logging (`console.log`, `JSON.stringify`) on login/refresh failure paths. |
| `test/core/errorMapper.test.ts` | 28-32 | Test explicitly locks in the leaky `cause`-preservation behavior instead of asserting redaction | ⚠️ Warning | Confirms CR-04 is by-design, not an oversight a test would catch; must be updated alongside the CR-04 fix. |

No unreferenced `TBD`/`FIXME`/`XXX` debt markers found in phase-modified files (the one "placeholder" grep hit in `src/amqp/hmac.ts:24` is a doc-comment describing an attack scenario the code defends against, not a stub marker).

### Human Verification Required

None. All four gaps are deterministically confirmed by direct source inspection (grep + read of the exact call sites cited in 17-REVIEW.md) and are not visual/runtime-behavior-dependent — they are structural absence-of-a-writer (CR-01), structural absence-of-scoping (CR-02), structural absence-of-a-comparison (CR-03), and structural absence-of-redaction (CR-04). No ambiguity remains that would benefit from human judgment beyond confirming the fix plans below.

### Gaps Summary

The TypeScript SDK's **mechanical/build deliverables are solid**: all 77 unit tests pass in a single run, `tsc --noEmit` is clean, the SC#1 bundle-grep gate passes against a real build, the SC#4 examples compile strict against a real build, the SC#5 `npm publish --dry-run` succeeds and packs the expected `dist/` contents, the CJS-require smoke gate passes, and the CI workflow/CONTRACT.md/README edits are all present and correctly scoped. The AMQP module in particular has no confirmed gaps — its verify-before-handler, nack-no-requeue, and key-redaction guarantees hold up under direct code inspection.

However, four **Critical** findings from the independent code review (`17-REVIEW.md`) were independently re-confirmed against the current codebase, all in the auth/session security surface the review was specifically asked to focus on:

1. **CR-01 (CSRF, Node persona):** `session.csrfToken` has zero writers in the Node code path — every state-changing Node REST call (login, refresh, logout, checkAccess, batchCheck) sends an empty CSRF header once a real session exists, which the server will reject in practice.
2. **CR-02 (single-flight refresh, cross-session):** the refresh guard is a true process-wide singleton, not scoped per client/session — a multi-tenant server holding multiple `AxiamClient`/`NodeSession` instances can have one tenant's refresh silently satisfy a different tenant's 401.
3. **CR-03 (tenant isolation, middleware/JWKS):** neither the middleware's shared verify core nor its `VerifiableSession` type ever compares the verified token's `tenant_id` claim against the resource server's configured tenant — a validly-signed token from Tenant A in an org authenticates successfully against a resource server configured for Tenant B in the same org. This is a cross-tenant auth bypass in a system whose core stated guarantee is per-tenant data isolation.
4. **CR-04 (token leak via error objects):** `NetworkError.cause` is a public, unredacted field that can carry raw `Set-Cookie` session/refresh token values from axios errors on login/refresh failure paths, reachable via ordinary `console.log`/`JSON.stringify` — contradicting the SDK's own documented "no raw token in error fields" invariant (D-16), and a test explicitly locks this behavior in as intentional.

None of these are false positives, by-design deviations, or issues an override would be appropriate for — they are correctness/security defects in an IAM client SDK's own auth and multi-tenancy guarantees, the exact surface this phase exists to deliver correctly. The phase goal ("production-ready, spec-conformant" SDK "satisfying requirement TS-01") is therefore **not fully achieved**: the SDK builds, tests, and publishes correctly, but is not yet safe to recommend for the Node persona's CSRF-protected endpoints, for multi-client/multi-tenant server deployments, or for tenant-isolated middleware deployment — and its own error objects can leak the very tokens the rest of the SDK works hard to protect (`Sensitive<T>`) through an uncovered side door.

**Recommended next step:** Run `/gsd-plan-phase 17 --gaps` to generate a closure plan addressing CR-01 through CR-04. Each gap's `fix_direction` above closely follows the review's own suggested fix and should require touching only `rest/interceptors.ts`, `node/session.ts`, `core/singleFlightRefresh.ts`, `grpc/callWithRefresh.ts`, `middleware/verifyCore.ts`, and `core/errors.ts`/`rest/auth.ts` — no architectural rework, but each fix needs a regression test proving the specific failure mode is closed (Node-jar CSRF test, multi-session single-flight test, cross-tenant rejection test, cause-redaction test).

---

_Verified: 2026-07-01T13:10:00Z_
_Verifier: Claude (gsd-verifier)_
