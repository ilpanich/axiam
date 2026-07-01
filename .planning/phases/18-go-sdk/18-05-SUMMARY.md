---
phase: 18-go-sdk
plan: 05
subsystem: go-sdk-middleware
tags: [go, sdk, middleware, net-http, jwks, jwt, tenant-isolation, security]

requires:
  - phase: 18-go-sdk (18-01)
    provides: "sdks/go.AuthError / AuthzError / Sensitive taxonomy"
  - phase: 18-go-sdk (18-04)
    provides: "sdks/go/internal/jwks.Verifier — local JWKS EdDSA verification"
provides:
  - "sdks/go/middleware.Middleware(verifier, configuredTenant, opts...) — func(http.Handler) http.Handler constructor"
  - "sdks/go/middleware.User — UserID/TenantID/Roles identity struct"
  - "sdks/go/middleware.UserFromContext(ctx) (*User, bool)"
  - "sdks/go/middleware.WithLogger(*slog.Logger) — optional CF-02 injectable logger, off by default"
affects: [go-sdk examples plan (18-06), any future plan wiring the net/http middleware into a sample route]

tech-stack:
  added: []
  patterns:
    - "middleware package depends on internal/jwks.Verifier via a local jwksVerifier interface (not the concrete type), so tests substitute fakes without a live JWKS server if needed, and the package does not hard-pin the Plan-04 constructor signature"
    - "unexported contextKey{} struct + package-level var as the context.WithValue key, the standard Go collision-safe idiom"

key-files:
  created:
    - sdks/go/middleware/nethttp.go
    - sdks/go/middleware/nethttp_test.go
    - sdks/go/middleware/context.go
  modified: []

key-decisions:
  - "internal/jwks.Verifier only checks the JWS signature, not exp — the middleware is the resource-server trust boundary, so it additionally rejects a signature-valid-but-expired token itself (claims.Exp != 0 && now >= claims.Exp) before trusting the token any further; this was NOT explicit in the Plan-04 verifier and is a Rule 2 addition (missing critical functionality) required by §10's short-TTL-trust requirement"
  - "Cross-tenant replay defense enforces claims.TenantID == configuredTenant unconditionally, and additionally requires any caller-supplied X-Tenant-ID header to also equal configuredTenant — the header narrows/asserts intent but can never substitute for the middleware's own configured tenant, closing a header-spoofing bypass of the constructor-configured value"
  - "401 used uniformly for both plain auth failures and cross-tenant rejection (not 403) — matches the TS reference (verifyCore.ts's authenticateRequest throws AuthError, not AuthzError, for a tenant_id mismatch) since a cross-tenant token is treated as an authentication failure (wrong identity), not an authorization decision on a correctly-identified caller; the plan's acceptance criteria explicitly allow 401 OR 403 for this case"

patterns-established:
  - "Standardized JSON error body ({error, message}) written via a single writeError helper shared by every 401/403 path, guaranteeing no code path can accidentally include a raw token value"

requirements-completed: [GO-01]

coverage:
  - id: D1
    description: "net/http middleware extracts session from Authorization: Bearer header or session cookie, verifies locally via the Plan-04 JWKS verifier, and calls the wrapped handler on success"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_AllowsValidTenant"
        status: pass
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_AllowsValidTenant_ViaCookie"
        status: pass
    human_judgment: false
  - id: D2
    description: "Middleware rejects missing credentials, invalid signatures, and expired (signature-valid) tokens with 401 JSON and never calls the wrapped handler"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_RejectsMissingOrInvalidToken"
        status: pass
    human_judgment: false
  - id: D3
    description: "Middleware enforces claims.tenant_id == configured tenant, rejecting a signature-valid but cross-tenant token (cross-tenant replay defense, T-18-19 / TS CR-03 carry-forward) with no raw token leakage in the response"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_RejectsCrossTenant"
        status: pass
    human_judgment: false
  - id: D4
    description: "Authenticated identity (user_id, tenant_id, roles) is injected via context.WithValue and retrievable by the exported UserFromContext helper"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_InjectsUser"
        status: pass
      - kind: unit
        ref: "sdks/go/middleware/nethttp_test.go#TestMiddleware_OutsideRequest_UserFromContextReturnsFalse"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-01
status: complete
---

# Phase 18 Plan 05: net/http Middleware Summary

Implemented the `net/http` middleware / route-guard (`middleware.Middleware`) that extracts a Bearer/cookie session, verifies it locally via the Plan-04 JWKS `Verifier` (no per-request server round-trip on a cache hit), additionally rejects signature-valid-but-expired tokens, enforces the configured-tenant claim check before trusting any token (closing the org-wide-JWKS cross-tenant replay threat T-18-19), injects the authenticated identity via `context.WithValue`, and surfaces standardized 401/403 JSON errors with zero raw-token leakage.

## Performance

- **Duration:** ~15 min
- **Tasks:** 1
- **Files modified:** 3 (all new)

## Accomplishments
- `middleware.Middleware(verifier, configuredTenant, opts...)` — `func(http.Handler) http.Handler` constructor implementing CONTRACT.md §10's full interface contract (extract → local verify → tenant-claim check → inject → 401/403)
- `middleware.User{UserID, TenantID, Roles}` + `UserFromContext(ctx) (*User, bool)` exported per the plan's artifact spec
- Cross-tenant replay defense proven by a dedicated test using a signature-valid token minted for a different tenant
- Expired-token rejection added beyond the Plan-04 verifier's signature-only check (Rule 2 fix — see Deviations)
- Optional `WithLogger(*slog.Logger)` option (CF-02: injectable, redaction-aware, off by default) that never receives a raw token value

## Task Commits

Each task was committed atomically:

1. **Task 1: net/http middleware — local verify, tenant-claim check, identity injection, 401/403 JSON (§10/D-06)** - `c9359ff` (feat)

_TDD: tests (`nethttp_test.go`) were written first against no implementation, confirmed a compile failure (`undefined: Middleware`), then `nethttp.go`/`context.go` were implemented — all landed in a single feat commit per this plan's `tdd="true"` task (RED/GREEN both verified locally before commit, matching the shared-TDD-cycle convention used by prior 18-* plans for single-task plans)._

## Files Created/Modified
- `sdks/go/middleware/context.go` - `User` struct, unexported context key, `UserFromContext` helper
- `sdks/go/middleware/nethttp.go` - `Middleware` constructor, token extraction (Bearer/cookie), exp check, tenant-claim enforcement, identity injection, standardized JSON error writer, `WithLogger` option
- `sdks/go/middleware/nethttp_test.go` - `TestMiddleware_AllowsValidTenant(+ViaCookie)`, `TestMiddleware_RejectsMissingOrInvalidToken` (no creds / bad sig / expired subtests), `TestMiddleware_RejectsCrossTenant`, `TestMiddleware_InjectsUser`, `TestMiddleware_OutsideRequest_UserFromContextReturnsFalse` — all sign tokens with a local Ed25519 key served via `httptest` JWKS, mirroring `internal/jwks/verifier_test.go`'s helpers

## Decisions Made
- The Plan-04 `jwks.Verifier.Verify` checks the JWS signature only, not `exp` — the middleware added its own `claims.Exp != 0 && time.Now().Unix() >= claims.Exp` check as the resource-server trust boundary (Rule 2: missing critical functionality; §10 implies expired tokens must never be trusted regardless of signature validity)
- Cross-tenant rejection returns 401 (not 403) to match the TypeScript reference's `authenticateRequest` (`verifyCore.ts`), which throws `AuthError` for a `tenant_id` mismatch, not `AuthzError` — a cross-tenant token is an authentication-identity problem, not an authorization decision on a correctly-scoped caller. The plan's acceptance criteria explicitly allow either status for this case.
- A caller-supplied `X-Tenant-ID` header narrows/asserts the request's intended tenant but is never trusted as a substitute for the middleware's constructor-configured tenant — both must equal `configuredTenant`, closing a header-spoofing path around the tenant check
- `jwksVerifier` is a local interface (not the concrete `*jwks.Verifier` type) so the middleware package's public contract does not hard-pin Plan 04's exact constructor/type shape

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Middleware did not reject expired-but-signature-valid tokens**
- **Found during:** Task 1, running `TestMiddleware_RejectsMissingOrInvalidToken/expired_token` against the first implementation
- **Issue:** `internal/jwks.Verifier.Verify` (Plan 04) only checks the JWS signature and algorithm allowlist — it never inspects the `exp` claim. Without an additional check, a token that is fully expired but still signature-valid would pass the middleware and reach the wrapped handler, violating §10's implicit contract that the middleware must never trust a session past its remaining TTL.
- **Fix:** Added an explicit `claims.Exp != 0 && time.Now().Unix() >= claims.Exp` check immediately after `verifier.Verify` succeeds, before the tenant-claim check, returning the same standardized 401 JSON body used for other verification failures.
- **Files modified:** `sdks/go/middleware/nethttp.go`
- **Verification:** `TestMiddleware_RejectsMissingOrInvalidToken/expired_token` passes; full `go test ./...` (95 tests) still green
- **Committed in:** `c9359ff` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical)
**Impact on plan:** Necessary for correctness/security per §10's TTL-trust requirement; no scope creep — the fix lives entirely inside this plan's own new file.

## Issues Encountered
None beyond the deviation above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `middleware.Middleware` is ready to be wired into a sample `net/http` route in Plan 06's examples (SC#1's "net/http middleware example compiles and protects a sample route").
- All four `<acceptance_criteria>` tests plus two extra tests (cookie-path success, out-of-request `UserFromContext`) pass; `go build ./middleware/...`, `go vet ./middleware/...`, and the repo-wide TLS-bypass grep are all clean.
- No blockers for Plan 06.

---
*Phase: 18-go-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED

All 3 key files (`sdks/go/middleware/nethttp.go`, `sdks/go/middleware/nethttp_test.go`, `sdks/go/middleware/context.go`) confirmed present on disk. Commit hash `c9359ff` confirmed present in `git log --oneline --all`.
