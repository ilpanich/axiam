---
phase: 18-go-sdk
reviewed: 2026-07-01T16:26:02Z
depth: standard
files_reviewed: 19
files_reviewed_list:
  - sdks/go/sensitive.go
  - sdks/go/errors.go
  - sdks/go/client.go
  - sdks/go/login.go
  - sdks/go/authz.go
  - sdks/go/jwks.go
  - sdks/go/internal/refreshguard/guard.go
  - sdks/go/internal/jwks/verifier.go
  - sdks/go/internal/jwks/claims.go
  - sdks/go/amqp/hmac.go
  - sdks/go/amqp/consumer.go
  - sdks/go/amqp/errdrop.go
  - sdks/go/amqp/event.go
  - sdks/go/grpc/tls.go
  - sdks/go/grpc/interceptor.go
  - sdks/go/grpc/client.go
  - sdks/go/middleware/nethttp.go
  - sdks/go/middleware/context.go
  - .github/workflows/sdk-ci-go.yml
findings:
  critical: 1
  warning: 4
  info: 2
  total: 7
status: issues_found
---

# Phase 18: Code Review Report

**Reviewed:** 2026-07-01T16:26:02Z
**Depth:** standard
**Files Reviewed:** 19
**Status:** issues_found

## Summary

Reviewed the Go SDK's security-critical surfaces: the `Sensitive` redaction
type, error taxonomy/header redaction, HTTP client/TLS/CSRF/tenant-header
handling, login/refresh flow, JWKS verification, the single-flight refresh
guard, AMQP HMAC verification, gRPC TLS/interceptor, and the net/http
middleware's cross-tenant claim check.

The `Sensitive` redaction type is verified sound (String/Format/GoString/
MarshalJSON all confirmed to redact under fmt verbs including `%x`/width/
precision, and through pointer-field/struct-embedding paths, via targeted
repro). No TLS-bypass surface exists anywhere in the reviewed REST or gRPC
transport code — `MinVersion: tls.VersionTLS13` is unconditional and
`WithCustomCA`/`NewTLSCredentials` are the only certificate-related knobs,
neither of which can disable verification. AMQP HMAC verification correctly
uses `hmac.Equal` (constant-time) and rejects on missing/malformed
signatures without leaking the HMAC value in security-event logs. The JWKS
verifier enforces an EdDSA-only algorithm allowlist before signature
verification and the middleware independently re-checks token expiry and
enforces the cross-tenant claim check before trusting a token.

One BLOCKER was found and confirmed via Go's race detector: `Client.guard`
is read and written without synchronization across `Login`/`Refresh` and
`Logout`, producing a real, reproducible data race under concurrent use of
a single `*Client` — the exact usage pattern the single-flight refresh
guard exists to support. Four WARNING-level gaps were also found: an
unfiltered response-body leak path into exported error `Message` fields
(bypassing the header-redaction work done elsewhere), a JWKS `Verify` that
silently skips the algorithm-allowlist check for a token with zero
signatures, an exported `jwks.Verifier.Verify` that never validates
expiry (undocumented trap for any future direct caller), and redundant/
confusing dead logic in the middleware's tenant-header check.

## Critical Issues

### CR-01: Unsynchronized concurrent read/write of `Client.guard` — data race between `Refresh`/`Login` and `Logout`

**File:** `sdks/go/login.go:168`, `sdks/go/login.go:292`, `sdks/go/login.go:377`

**Issue:** `Client.guard` is a plain `*refreshguard.Guard` field (declared in
`sdks/go/client.go:111`) with no mutex protecting the field itself (unlike
`csrfToken`/`resolvedOrg`, which are correctly guarded by `csrfMu`/
`orgIDMu`). `absorbSessionCookies` (called from `Login`/`VerifyMfa`) and
`Refresh` both dereference `c.guard` to call `.Seed(...)` /
`.RefreshIfNeeded(...)`, while `Logout` unconditionally reassigns
`c.guard = &refreshguard.Guard{}` with no locking at all:

```go
// login.go:377 — Logout, no lock held
c.guard = &refreshguard.Guard{}
```

Any concurrent call to `Refresh()` (or a `Login()`/`VerifyMfa()` racing a
`Logout()`) on the same `*Client` races on this field. This was reproduced
directly with `go test -race`: concurrent `Refresh()`/`Logout()` calls on
one `Client` trigger `WARNING: DATA RACE` on the `c.guard` read in
`login.go:292` against the write in `login.go:377`, and on `sync.Mutex`
internals once the two goroutines happen to observe different `*Guard`
pointer values mid-flight. This is exactly the "any number of concurrent
callers" scenario CONTRACT.md §9 and the refresh guard's own doc comments
describe as the primary use case the guard exists to serialize —
`*Client` is documented and tested (`TestRefreshGuard_SingleFlight`) as
safe for concurrent use, but `Logout` breaks that guarantee. Under Go's
memory model this is undefined behavior: at best a lost/duplicated
refresh, at worst a panic if the race detector is enabled in production
builds or if the two pointer writes tear on a platform without atomic
pointer stores guaranteed by hardware alignment.

**Fix:** Protect `c.guard` with the same mutex discipline already used for
`csrfToken`/`resolvedOrg`, or make the field itself an
`atomic.Pointer[refreshguard.Guard]`:

```go
type Client struct {
    // ...
    guardMu sync.RWMutex
    guard   *refreshguard.Guard
}

func (c *Client) getGuard() *refreshguard.Guard {
    c.guardMu.RLock()
    defer c.guardMu.RUnlock()
    return c.guard
}

// Logout:
c.guardMu.Lock()
c.guard = &refreshguard.Guard{}
c.guardMu.Unlock()
```
and replace every direct `c.guard.X(...)` call site with `c.getGuard().X(...)`.
An `atomic.Pointer[refreshguard.Guard]` with `Load()`/`Store()` is an
equally valid, slightly cheaper alternative.

## Warnings

### WR-01: Response body is never redacted before landing in exported error `Message` fields

**File:** `sdks/go/login.go:426-437` (`mapErrorResponse`, `readBodyForError`), consumed by `sdks/go/errors.go:142-151` (`errorFromHTTPStatus`)

**Issue:** `errors.go`/`errors_test.go` invest significant, well-tested
effort in stripping `Set-Cookie`/`Authorization`/`Cookie` **headers** from
`*http.Response` before they can reach a `NetworkError`'s wrapped `cause`
(D-04, "CR-04 carry-forward"). However, `mapErrorResponse` reads up to
4096 bytes of the raw response **body** verbatim and places it, unfiltered,
into the exported `Message` field of `AuthError`/`AuthzError`/
`NetworkError`:

```go
func mapErrorResponse(resp *http.Response) error {
    message := readBodyForError(resp.Body)
    return errorFromHTTPStatus(resp.StatusCode, message, resp, nil)
}
```

`Message` is an exported struct field with no redaction surface (unlike
`Sensitive`) — it participates in default `json.Marshal`, `%v`, `%+v`, and
`.Error()` output directly. If a server ever returns diagnostic detail in
an error body (a proxy/WAF error page reflecting request headers, a
misconfigured debug handler, or a body that happens to echo a cookie/
token value in a JSON error payload), that content flows straight into
caller-visible, loggable, JSON-serializable error state — defeating the
purpose of the header-redaction work done elsewhere in the same file.

**Fix:** Either cap/sanitize the body the same way headers are sanitized
(e.g., strip anything matching a token-shaped pattern, or simply do not
echo raw server body text into a public field — log it server-side only
via the optional `WithLogger` hook instead), or explicitly document
`Message` as untrusted/caller-must-not-log-verbatim and truncate more
aggressively:

```go
func readBodyForError(r io.Reader) string {
    b, err := io.ReadAll(io.LimitReader(r, 256)) // smaller cap
    if err != nil || len(b) == 0 {
        return "no response body"
    }
    return "server returned an error (body redacted; enable WithLogger for details)"
}
```

### WR-02: Algorithm allowlist check is skipped for a JWS with zero signatures

**File:** `sdks/go/internal/jwks/verifier.go:81-86`

**Issue:** The alg-allowlist defense is implemented as a loop over
`msg.Signatures()`:

```go
for _, sig := range msg.Signatures() {
    alg, ok := sig.ProtectedHeaders().Algorithm()
    if !ok || alg != jwa.EdDSA() {
        return Claims{}, fmt.Errorf("jwks: unexpected alg %q: only EdDSA is accepted", alg.String())
    }
}
```

If `jws.Parse` ever accepts and returns a message with an empty
`Signatures()` slice (e.g., a JWS General/Flattened JSON serialization
with a `signatures: []` array, or a library-permitted unsecured/`alg:none`
variant), this loop body never executes and the function silently falls
through to the keyset lookup and `jws.Verify` — the algorithm-confusion
defense the doc comment on `Verify` explicitly promises ("checked against
an explicit EdDSA allowlist BEFORE any keyset lookup") does not actually
run for that input shape. In practice `jws.Verify` itself would very
likely also reject a signature-less message, so this is defense-in-depth
degrading rather than a full bypass, but the code's own stated invariant
("only EdDSA is accepted... BEFORE any keyset lookup") is not actually
enforced for this edge case.

**Fix:** Fail closed when there are no signatures to check:

```go
sigs := msg.Signatures()
if len(sigs) == 0 {
    return Claims{}, fmt.Errorf("jwks: token has no signatures")
}
for _, sig := range sigs {
    alg, ok := sig.ProtectedHeaders().Algorithm()
    if !ok || alg != jwa.EdDSA() {
        return Claims{}, fmt.Errorf("jwks: unexpected alg %q: only EdDSA is accepted", alg.String())
    }
}
```

### WR-03: Exported `jwks.Verifier.Verify` / `axiam.JWKSVerifier` never validates token expiry

**File:** `sdks/go/internal/jwks/verifier.go:67-108`, re-exported at `sdks/go/jwks.go:15-26`

**Issue:** `Verify`'s doc comment says only that it "verifies token's
signature against the cached JWKS" — it makes no expiry check at all, and
`Claims.Exp` is returned as a plain field for the caller to check. The
*only* consumer in this codebase, `middleware.Middleware`, correctly
performs that check itself (`nethttp.go:73-76`), with a comment explaining
why it must ("the Plan-04 verifier checks the signature only, not exp").
However, `NewJWKSVerifier`/`JWKSVerifier` is a public, exported SDK
surface (`sdks/go/jwks.go`) that any external caller can use directly
without going through `middleware.Middleware` — and nothing in `Verify`'s
public documentation warns that a caller doing so will silently accept an
expired-but-signature-valid token. This is a footgun baked into the public
API surface, not just an internal implementation detail.

**Fix:** Either enforce expiry inside `Verify` itself (moving the
middleware's check there and simplifying `nethttp.go`), or, at minimum,
make the doc comment on the exported `Verify` method state explicitly and
prominently that expiry is NOT checked and callers MUST check
`Claims.Exp` themselves:

```go
// Verify parses and verifies token's signature against the cached JWKS,
// returning the token's Claims on success.
//
// Verify does NOT check token expiry — callers MUST compare the returned
// Claims.Exp against time.Now().Unix() themselves before trusting the
// result (see middleware.Middleware for a reference implementation).
```

### WR-04: Redundant/confusing tenant-header logic in the cross-tenant check

**File:** `sdks/go/middleware/nethttp.go:85-92`

**Issue:**

```go
expectedTenant := configuredTenant
if h := r.Header.Get("X-Tenant-ID"); h != "" {
    expectedTenant = h
}
if claims.TenantID == "" || claims.TenantID != configuredTenant || expectedTenant != configuredTenant {
    writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "token tenant_id does not match the configured tenant")
    return
}
```

`expectedTenant` is computed from the caller-supplied `X-Tenant-ID` header
but is never compared against `claims.TenantID` — it is only ever compared
against `configuredTenant`. Since the security-relevant check is already
fully captured by `claims.TenantID != configuredTenant`, the
`expectedTenant`/`X-Tenant-ID` branch is dead weight: whenever the header
is present and differs from `configuredTenant`, `expectedTenant !=
configuredTenant` is true and the request is rejected — but it would
already have been rejected (or not) purely based on `claims.TenantID`
regardless of the header's value. The comment above the block ("must also
match the middleware's configured tenant, never substitute for it")
suggests the intent was to prevent the header from being used to bypass
the tenant check, but as written the header has no effect on the outcome
at all in the currently-reachable cases — it is not wired to
`claims.TenantID` anywhere. This is not an exploitable bypass (the
`claims.TenantID != configuredTenant` check alone is sufficient and
correct), but the extra logic is misleading: it reads as if the header
narrows/cross-checks the tenant, when it does not affect the decision.

**Fix:** Either remove the dead `expectedTenant`/header-read entirely
(since `claims.TenantID != configuredTenant` alone is the correct and
sufficient check), or, if the intent was genuinely to require the header
to agree with the token's claim, wire it up explicitly:

```go
if claims.TenantID == "" || claims.TenantID != configuredTenant {
    writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "token tenant_id does not match the configured tenant")
    return
}
if h := r.Header.Get("X-Tenant-ID"); h != "" && h != claims.TenantID {
    writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "X-Tenant-ID header does not match token tenant_id")
    return
}
```

## Info

### IN-01: `deliveryAdapter.Ack`/`Nack` transport errors are silently discarded

**File:** `sdks/go/amqp/consumer.go:63-69`

**Issue:** `_ = a.d.Ack(false)` / `_ = a.d.Nack(false, requeue)` swallow any
error the underlying AMQP library returns for the ack/nack call itself
(e.g., if the channel/connection is already closed). This is explicitly
documented as intentional and mirrors the Rust reference implementation,
so it is not flagged as a defect, but it does mean an ack/nack failure is
completely unobservable — even via the optional `WithSecurityLogger` hook,
which only covers HMAC-verification failures, not delivery
acknowledgement failures.

**Fix:** Consider surfacing ack/nack errors through the same
`securityLogger`/a new observability seam (e.g., a generic `Warn` method)
so operators can detect a channel that is silently failing to
acknowledge, rather than only being able to infer it from broker-side
redelivery metrics.

### IN-02: `readBodyForError` caps at 4096 bytes but does not guard against a slow/hanging body reader

**File:** `sdks/go/login.go:431-437`

**Issue:** `io.LimitReader(r, 4096)` bounds the number of bytes read, but
`io.ReadAll` on a body that streams very slowly (a misbehaving or
malicious server) can still block for as long as the request's context
allows, since there is no independent read deadline here beyond whatever
timeout was configured on the `http.Client`/context. This is a minor
robustness gap rather than a functional bug, given `WithTimeout`/context
deadlines already bound the overall request lifecycle in the normal path.

**Fix:** No action likely needed given the existing `WithTimeout`/context
deadline coverage; noted for completeness since this function is on the
error path for every non-2xx response across the SDK.

---

_Reviewed: 2026-07-01T16:26:02Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
