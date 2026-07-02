# Phase 20: Java SDK - Pattern Map

**Mapped:** 2026-07-02
**Files analyzed:** ~26 new Java files + pom.xml + CI workflow
**Analogs found:** 26 / 26 (all have a strong structural analog in Go/Python/TS/Rust; Spring filter has no direct sibling but Go's `middleware/nethttp.go` + TS `middleware/verifyCore.ts` cover the same logic)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `sdks/java/pom.xml` | config | build | `sdks/java/pom.xml` (existing scaffold, Java 11/empty deps) + RESEARCH.md Code Examples POM | exact (fill-in) |
| `src/main/java/io/axiam/sdk/AxiamClient.java` | service/client | request-response | `sdks/go/client.go` (`NewClient`, builder-safety, org resolution, CSRF capture) | exact |
| `src/main/java/io/axiam/sdk/AxiamClient.Builder` (nested) | config/builder | — | `sdks/go/client.go` (`clientConfig`+`Option`) + RESEARCH.md Pattern 1 | exact |
| `src/main/java/io/axiam/sdk/rest/*Auth*.java` (`login`/`verifyMfa`/`refresh`/`logout`) | controller (client-side) | request-response | `sdks/go/login.go`, `sdks/python/src/axiam_sdk/_client.py` | exact |
| `src/main/java/io/axiam/sdk/rest/*Authz*.java` (`checkAccess`/`can`/`batchCheck`) | controller (client-side) | request-response (batch=batch) | `sdks/go/authz.go` + `crates/axiam-api-rest/src/handlers/authz_check.rs` (server contract) | exact |
| `src/main/java/io/axiam/sdk/LoginResult.java` (record) | model | — | `sdks/python/src/axiam_sdk/_models.py` (`LoginResult`/`mfaRequired` flag), `sdks/go` login result struct | role-match |
| `src/main/java/io/axiam/sdk/AxiamUser.java` (record) | model | — | `sdks/go/middleware/context.go` `User` struct, `sdks/python/src/axiam_sdk/_models.py` | role-match |
| `src/main/java/io/axiam/sdk/Sensitive.java` | utility (hardened wrapper) | transform | `sdks/go/sensitive.go` (String/Format/GoString/MarshalJSON quartet) + `sdks/typescript/src/core/sensitive.ts` | exact |
| `src/main/java/io/axiam/sdk/errors/AuthError.java` | model (exception) | — | `sdks/go/errors.go` (`AuthError`) | exact |
| `src/main/java/io/axiam/sdk/errors/AuthzError.java` | model (exception) | — | `sdks/go/errors.go` (`AuthzError`) | exact |
| `src/main/java/io/axiam/sdk/errors/NetworkError.java` | model (exception) | — | `sdks/go/errors.go` (`NetworkError`+`sanitizeResponse`), `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`) | exact |
| `src/main/java/io/axiam/sdk/errors/ErrorMapper.java` | utility (central mapper) | transform | `sdks/go/errors.go` (`errorFromHTTPStatus`/`errorFromGRPCStatus`) + `sdks/typescript/src/core/errorMapper.ts` (`mapHttpStatusToError`/`mapGrpcStatusToError`) | exact |
| `src/main/java/io/axiam/sdk/internal/RefreshGuard.java` | service (concurrency primitive) | event-driven | `sdks/go/internal/refreshguard/guard.go` (`Guard.RefreshIfNeeded`, double-check pattern) — direct `Mutex`→`ReentrantLock` port; RESEARCH.md Pattern 2 already has a near-final `CompletableFuture`-in-`AtomicReference` sketch | exact |
| `src/main/java/io/axiam/sdk/internal/SessionState.java` | service (session/cookie/csrf state) | request-response | `sdks/go/client.go` (csrfMu/csrfToken/decorateRequest/captureCSRFFromResponse), `sdks/typescript/src/rest/session.ts` | exact |
| `src/main/java/io/axiam/sdk/internal/JwksVerifier.java` | service (crypto/verification) | request-response (cached) | `sdks/go/internal/jwks/verifier.go`, `sdks/rust/src/token/jwks.rs` — cross-tenant claim check carried forward | role-match (Java uses nimbus `RemoteJWKSet`, no hand-rolled cache like Go/Rust) |
| `src/main/java/io/axiam/sdk/rest/AuthInterceptor.java` | middleware (OkHttp Interceptor) | request-response | `sdks/typescript/src/rest/interceptors.ts`, `sdks/go/client.go` (`decorateRequest`) — proactive-refresh logic is RESEARCH.md Pattern 3 | role-match |
| `src/main/java/io/axiam/sdk/rest/AuthAuthenticator.java` | middleware (OkHttp Authenticator, reactive) | request-response | RESEARCH.md Pattern 3 (no direct sibling — OkHttp-specific extension point); conceptually mirrors `sdks/go/grpc/client.go`'s UNAUTHENTICATED-retry-once logic | partial (Java/OkHttp-idiom-specific) |
| `src/main/java/io/axiam/sdk/grpc/GrpcAuthzClient.java` | service (gRPC client wrapper) | request-response | `sdks/go/grpc/client.go` (`AuthzClient.CheckAccess`/`BatchCheck`, retry-once-on-UNAUTHENTICATED, `mapGRPCError`) + `crates/axiam-api-grpc/src/services/authorization.rs` (server semantics) + `proto/axiam/v1/authorization.proto` (wire shapes) | exact |
| `src/main/java/io/axiam/sdk/grpc/AuthClientInterceptor.java` | middleware (gRPC interceptor) | request-response | `sdks/go/grpc/interceptor.go` (`authUnaryInterceptor`, non-blocking `TokenFunc`) | exact |
| `src/main/java/io/axiam/sdk/amqp/Hmac.java` | utility (crypto verify) | transform | `sdks/go/amqp/hmac.go` (`verifyHMAC`) — **ordering divergence, see Shared Patterns** — + `crates/axiam-amqp/src/messages.rs` (`sign_payload`/`verify_payload`, canonical source of truth) | exact (logic), divergent (Go alphabetizes; Java must NOT) |
| `src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java` | service (event consumer, ack/nack loop) | event-driven | `sdks/go/amqp/consumer.go` (`Consume`/`verifyAndDispatch`, ack/nack matrix, QoS prefetch) | exact |
| `src/main/java/io/axiam/sdk/amqp/ErrDrop.java` | model (sentinel exception) | — | `sdks/go/amqp/errdrop.go` | exact |
| `src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java` | middleware (`OncePerRequestFilter`) | request-response | `sdks/go/middleware/nethttp.go` (`Middleware`: extract→verify→cross-tenant-check→inject-identity→401/403 JSON) + `sdks/typescript/src/middleware/verifyCore.ts` | role-match (no Spring sibling exists; Go's net/http middleware is the closest logic-level analog) |
| `src/main/java/io/axiam/sdk/spring/AxiamAutoConfiguration.java` | provider (Spring `@AutoConfiguration`) | — | No sibling analog (Java-only concern); RESEARCH.md Pattern 9 is the primary source | none — RESEARCH.md pattern only |
| `sdks/java/src/test/.../RefreshGuardSingleFlightTest.java` | test | concurrency | `sdks/go/internal/refreshguard` test suite (pattern), RESEARCH.md Pattern 2's JUnit skeleton | exact |
| `sdks/java/src/test/.../ErrorRedactionTest.java` | test | — | TS CR-04 regression test (17-REVIEW.md) + Go equivalent redaction test | exact |
| `.github/workflows/sdk-ci-java.yml` | config (CI) | batch | `.github/workflows/sdk-ci-python.yml` (paths filter, scaffold-check job, tag-triggered publish job pattern) | role-match (Java needs `mvn`/GPG-specific steps, Python is `pytest`/PyPI-specific) |

## Pattern Assignments

### `AxiamClient.java` + `Builder` (client, request-response)

**Analog:** `sdks/go/client.go`

**tenantId-required + no-default-tenant guard** (`sdks/go/client.go:133-136`):
```go
if tenantSlug == "" {
    return nil, &AuthError{Message: "tenantSlug is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"}
}
```
Java translation: static factory `AxiamClient.builder(baseUrl, tenantId)` throws `AuthError` (unchecked) if blank — see RESEARCH.md Pattern 1 (`sdks/java` code example, lines 397-449 of RESEARCH.md) which is already a near-complete port of this exact guard.

**Client-override safety (D-27, Go D-09 carry-forward)** (`sdks/go/client.go:164-211`, `buildHTTPClient`):
```go
// D-09: the SDK's own jar and TLS config ALWAYS win — re-applied here,
// unconditionally, regardless of what the supplied client had set.
httpc.Jar = jar
...
transport.TLSClientConfig = tlsConfig
httpc.Transport = transport
```
Java: in `Builder.build()`, if `overrideHttpClient` is supplied, call `overrideHttpClient.newBuilder().cookieJar(new JavaNetCookieJar(cookieManager)).sslSocketFactory(strictSslSocketFactory, trustManager).hostnameVerifier(strictHostnameVerifier).build()` — never trust the override's jar/TLS config as-is.

**Org resolution fallback (Pitfall 2 / RESEARCH.md)** (`sdks/go/client.go:271-295`):
```go
func (c *Client) resolvedOrgID() (uuid.UUID, bool) {
    if c.org.id != nil { return *c.org.id, true }
    ...
    if c.resolvedOrg != nil { return *c.resolvedOrg, true }
    return uuid.UUID{}, false
}
```
Java: package-internal `resolvedOrgId()` method on `SessionState`, populated from the access token's `org_id` claim after first successful login (mirrors Go/Python/Rust — Pitfall 2 is universal across all sibling SDKs).

**CSRF capture/echo (§3 CF-01)** (`sdks/go/client.go:220-255`):
```go
func (c *Client) decorateRequest(req *http.Request) {
    req.Header.Set("X-Tenant-ID", c.tenantSlug)
    if stateChangingMethods[strings.ToUpper(req.Method)] {
        if token := c.getCSRFToken(); token != "" {
            req.Header.Set("X-CSRF-Token", token)
        }
    }
}
func (c *Client) captureCSRFFromResponse(resp *http.Response) {
    if token := resp.Header.Get("X-CSRF-Token"); token != "" { ... }
}
```
Java: this logic moves into `AuthInterceptor.intercept()` (OkHttp doesn't have a separate `decorateRequest`/`doRequest` choke point the way Go's `http.Client` does) — see RESEARCH.md Pattern 3 lines 636-666, which already implements this exact capture/echo pair.

---

### `internal/RefreshGuard.java` (service, event-driven, SC#2's literal target)

**Analog:** `sdks/go/internal/refreshguard/guard.go`

**Double-check-after-lock single-flight** (`sdks/go/internal/refreshguard/guard.go:63-88`):
```go
func (g *Guard) RefreshIfNeeded(ctx context.Context, observedAccess string, doRefresh func(ctx context.Context) (RefreshedTokens, error)) (Sensitive, error) {
    g.mu.Lock()
    defer g.mu.Unlock()
    if g.hasAny && string(g.access) != observedAccess {
        return g.access, nil  // another goroutine already refreshed
    }
    tokens, err := doRefresh(ctx)  // §9.3: no retry loop
    if err != nil { return "", err }
    g.access = tokens.Access
    ...
    return g.access, nil
}
```
Java translation (D-07: `ReentrantLock` + `CompletableFuture` in `AtomicReference`, NOT a plain mutex, since Java must support unlock-before-block for concurrent waiters — see RESEARCH.md Pattern 2 lines 471-525 which already ports this exact double-check idiom with the required lock-release-before-`join()` step Go's blocking mutex doesn't need). Key structural carry-over: **no retry loop on failure (§9.3)** — `doRefresh`'s exception propagates to every waiter unchanged, exactly as Go's `err` return does.

**Non-blocking cached-token read for the interceptor hot path** (`sdks/go/internal/refreshguard/guard.go:90-99`, `CachedAccessToken`):
```go
func (g *Guard) CachedAccessToken() (Sensitive, bool) {
    g.mu.Lock()
    defer g.mu.Unlock()
    return g.access, g.hasAny
}
```
Java: same shape — a short-held-lock (or `volatile` read) accessor, never blocking on the `CompletableFuture`, called from `AuthInterceptor`/`AuthClientInterceptor`'s hot path (Anti-Pattern explicitly called out in RESEARCH.md: "never lock in the interceptor").

---

### `Sensitive.java` (model/utility, D-17)

**Analog:** `sdks/go/sensitive.go`

**Multi-surface redaction quartet** (`sdks/go/sensitive.go:20-54`):
```go
func (Sensitive) String() string { return redacted }
func (Sensitive) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, redacted) }
func (Sensitive) GoString() string { return redacted }
func (Sensitive) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
func (s Sensitive) expose() string { return string(s) }  // package-internal only
```
Java translation: `toString()` (→ `String`/`Format`/`GoString` combined), Jackson `@JsonSerialize(using = Sensitive.Redactor.class)` (→ `MarshalJSON`), package-private `String expose()` (→ `expose()` verbatim same name/visibility contract). RESEARCH.md Pattern 6 (lines 885-936) is already a complete, ready-to-use Java port of this exact file — additionally correctly adds `NOT Serializable` (a JVM-specific leak class Go has no equivalent of, since Go has no default reflective serialization).

---

### `errors/{AuthError,AuthzError,NetworkError,ErrorMapper}.java` (model + utility, D-18/CR-04)

**Analog:** `sdks/go/errors.go` (primary) + `sdks/typescript/src/core/errorMapper.ts` (redact-before-wrap, the exact CR-04 fix Java must mirror)

**Single choke-point redact-before-wrap constructor** (`sdks/go/errors.go:104-127`, `newNetworkError`):
```go
// This is the SINGLE choke point for building a NetworkError from an
// *http.Response ... it ALWAYS derives the wrapped cause from a sanitized
// (Set-Cookie/Authorization/Cookie stripped) copy of resp, never the raw
// response (D-04, Phase 17 CR-04 carry-forward: redact BEFORE wrap, never after).
func newNetworkError(message string, resp *http.Response, cause error) *NetworkError {
    if resp != nil {
        sanitized := sanitizeResponse(resp)
        return &NetworkError{Message: message, cause: fmt.Errorf("http status %d, headers: %v", sanitized.StatusCode, sanitized.Header)}
    }
    return &NetworkError{Message: message, cause: cause}
}
```
And the TS equivalent (`sdks/typescript/src/core/errorMapper.ts:45-72`, `sanitizeAxiosError`):
```ts
const sanitizedHeaders: Record<string, unknown> = { ...(response.headers as Record<string, unknown>) };
for (const key of Object.keys(sanitizedHeaders)) {
  if (SENSITIVE_RESPONSE_HEADERS.includes(key.toLowerCase())) {
    delete sanitizedHeaders[key];
  }
}
```
Java translation is already sketched correctly in RESEARCH.md Pattern 7 (lines 955-997, `ErrorMapper.fromHttpResponse`/`sanitize`) — verify at implementation time that `sanitize()` is the **only** call path into `NetworkError`'s constructor from a live `okhttp3.Response` (matching Go's "SINGLE choke point" comment verbatim — this is the load-bearing invariant the regression test proves).

**Status→error table** (`sdks/go/errors.go:129-174`, `errorFromHTTPStatus`/`errorFromGRPCStatus`) — transcribe exactly; both Go and TS agree on the table (401→Auth, 403/409→Authz, else→Network; UNAUTHENTICATED→Auth, PERMISSION_DENIED→Authz, else→Network) so there is no ambiguity for the Java port.

**CR-04 regression test shape** — Go/TS pattern: build a response/error carrying `Set-Cookie: axiam_access=super-secret-token`, map it, assert the raw value never appears in `toString()`/message/cause chain, **plus** a non-vacuous control case with a non-sensitive header (e.g. `X-Request-Id`) that DOES survive — this control case is explicitly required per RESEARCH.md Pattern 7's closing note and should be copied verbatim as a Java JUnit test.

---

### `amqp/Hmac.java` (utility, §8/D-13) — CRITICAL: key-order divergence from Go

**Analog:** `crates/axiam-amqp/src/messages.rs` (`sign_payload`/`verify_payload`, canonical source of truth) — **NOT** `sdks/go/amqp/hmac.go`, whose comment is actually now known-stale/wrong for this codebase.

**Server canonical signer** (`crates/axiam-amqp/src/messages.rs:33-49`, `sign_payload`):
```rust
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}
```
The Rust `#[derive(Serialize)]` structs (e.g. `AuthzRequest`, fields `correlation_id, tenant_id, subject_id, action, resource_id, scope, hmac_signature`) serialize in **field-declaration order**, not alphabetically.

**Go's comment is misleading for a Java port** (`sdks/go/amqp/hmac.go:24-26`):
```go
// 3. Delete hmac_signature from the map and re-serialize the remainder to
//    canonical JSON. Go's encoding/json sorts map keys alphabetically,
//    matching the server's serde_json::to_vec ordering (BTreeMap-backed,
//    no preserve_order feature) for the same field set.
```
**Do NOT port this alphabetical-sort assumption to Java.** RESEARCH.md (Pitfall 5, Pattern 5, lines 767-841 and 1301-1322) explicitly documents that this was Phase 19 (Python)'s empirically-proven finding: **wire/insertion order must be preserved, never alphabetized** — Jackson's `ObjectNode` (backed by `LinkedHashMap`) does this natively. Use RESEARCH.md's `Hmac.verify()` code example (lines 804-840) as the authoritative Java implementation — parse into `ObjectNode`, `node.remove("hmac_signature")`, re-serialize via `MAPPER.writeValueAsBytes(node)`, compare via `MessageDigest.isEqual`. If Go's SDK is later found to actually be failing HMAC verification against the real server, that is a pre-existing Go-SDK bug out of this phase's scope — Java must follow the Rust/Python-proven behavior, not Go's stated comment.

---

### `amqp/AmqpConsumer.java` (service, event-driven, D-13)

**Analog:** `sdks/go/amqp/consumer.go`

**ack/nack matrix** (`sdks/go/amqp/consumer.go:108-155`, `verifyAndDispatch`):
```go
if !verifyHMAC(signingKey, body) {
    logger.SecurityWarn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue")
    delivery.Nack(false)
    return
}
event, err := parseEvent(body)
if err != nil { ... delivery.Nack(false); return }
if err := handler(ctx, event); err != nil {
    if errors.Is(err, ErrDrop) { delivery.Nack(false); return }
    delivery.Nack(true)
    return
}
delivery.Ack()
```
Java translation (RESEARCH.md Pattern 5, lines 843-878, `AmqpConsumer.consume` `DeliverCallback`) already matches this ack/nack matrix 1:1: HMAC-fail/parse-fail → `basicNack(tag, false, false)` + security log; `ErrDrop` → `basicNack(tag, false, false)`; other exception → `basicNack(tag, false, true)`; success → `basicAck`. QoS default: Go uses `defaultPrefetch = 10` (`sdks/go/amqp/consumer.go:13`) — Java should match this default (RESEARCH.md already proposes prefetch 10).

**Built-in automatic recovery note** — Go's consumer relies on `amqp091-go`'s reconnect via a `NotifyClose` channel it must manually re-subscribe on (`sdks/go/amqp/consumer.go:182-197`); `com.rabbitmq:amqp-client`'s `ConnectionFactory.setAutomaticRecoveryEnabled(true)` (on by default since 4.x, D-13) means Java does **not** need Go's manual close-notify re-subscription loop — this is a case where the Java library does more than Go's, not a pattern to port literally.

---

### `grpc/GrpcAuthzClient.java` + `AuthClientInterceptor.java` (service + middleware, D-11/D-12)

**Analog:** `sdks/go/grpc/client.go` + `sdks/go/grpc/interceptor.go`

**Retry-once-on-UNAUTHENTICATED, then map error** (`sdks/go/grpc/client.go:82-98`, `CheckAccess`):
```go
resp, err := c.inner.CheckAccess(ctx, wire)
if err != nil {
    if c.refresh != nil && status.Code(err) == codes.Unauthenticated {
        if refreshErr := c.refresh(ctx); refreshErr != nil { return false, "", refreshErr }
        resp, err = c.inner.CheckAccess(ctx, wire)
    }
    if err != nil { return false, "", mapGRPCError(err) }
}
return resp.GetAllowed(), resp.GetDenyReason(), nil
```
Java: `GrpcAuthzClient.checkAccess`/`batchCheck` follow the identical shape — call the blocking stub, on `Status.Code.UNAUTHENTICATED` invoke `RefreshGuard.refreshIfNeeded(...)` (the SAME guard instance shared with REST, per D-07/D-11), retry exactly once, then route any terminal error through `ErrorMapper.fromGrpcStatus`.

**Non-blocking metadata-injecting interceptor** (`sdks/go/grpc/interceptor.go:27-37`, `authUnaryInterceptor`):
```go
func authUnaryInterceptor(tokenFn TokenFunc, tenantID string) grpc.UnaryClientInterceptor {
    return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
        if token, ok := tokenFn(); ok {
            ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token, "x-tenant-id", tenantID)
        }
        return invoker(ctx, method, req, reply, cc, opts...)
    }
}
```
Java: `AuthClientInterceptor implements io.grpc.ClientInterceptor`, wraps `ClientCall.Listener` to attach `Metadata` headers on `start()`. `tokenFn` (Go's non-blocking closure) → a package-internal `RefreshGuard.cachedAccessToken()`-style non-blocking accessor, **never** `refreshIfNeeded()` directly on this hot path (same anti-pattern warning as the REST interceptor).

**Wire shapes + server semantics:** `proto/axiam/v1/authorization.proto` (`CheckAccessRequest`/`BatchCheckAccessRequest`) define the request/response fields Go's `toWire()` (`sdks/go/grpc/client.go:65-76`) maps to; `crates/axiam-api-grpc/src/services/authorization.rs` implements the server-side `check_access`/`batch_check_access` handlers Java's stub calls against — read both before wiring `GrpcAuthzClient`'s field mapping.

---

### `spring/AxiamAuthenticationFilter.java` (middleware, D-14, SC#3)

**Analog:** `sdks/go/middleware/nethttp.go` (closest logic-level analog — no Spring/Java-framework sibling exists)

**Extract → verify → cross-tenant-check → inject-identity → 401/403 JSON** (`sdks/go/middleware/nethttp.go:53-107`, `Middleware`'s returned handler):
```go
token, err := extractToken(r)
if err != nil { writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", err.Error()); return }
claims, err := verifier.Verify(r.Context(), []byte(token))
if err != nil { writeError(...); return }
if claims.Exp != 0 && time.Now().Unix() >= claims.Exp { writeError(...); return }
// Cross-tenant replay defense (T-18-19, TS CR-03 carry-forward):
if claims.TenantID == "" || claims.TenantID != configuredTenant { writeError(...); return }
if h := r.Header.Get("X-Tenant-ID"); h != "" && h != claims.TenantID { writeError(...); return }
user := &User{UserID: claims.Subject, TenantID: claims.TenantID, Roles: claims.Roles}
ctx := withUser(r.Context(), user)
next.ServeHTTP(w, r.WithContext(ctx))
```
Java: `AxiamAuthenticationFilter.doFilterInternal` (RESEARCH.md Pattern 8, lines 1033-1097) already ports this exact five-step sequence, substituting `SecurityContextHolder.setAuthentication` for Go's `context.WithValue`. **Preserve the cross-tenant claim check** (`configuredTenantId.equals(tokenTenantId)`) — this is a **MUST-carry-forward control** per RESEARCH.md, not optional, present in every sibling SDK (TS CR-03, Go, Python).

**Token extraction (Bearer header, cookie fallback)** (`sdks/go/middleware/nethttp.go:109-125`, `extractToken`):
```go
if header := r.Header.Get("Authorization"); header != "" {
    scheme, credentials, found := strings.Cut(...)
    if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credentials) == "" { return "", errMissingCredentials }
    return strings.TrimSpace(credentials), nil
}
if cookie, err := r.Cookie("axiam_access"); err == nil && cookie.Value != "" { return cookie.Value, nil }
```
Java `extractToken()` (RESEARCH.md lines 1078-1090) already mirrors this Bearer-then-cookie fallback order exactly.

---

## Shared Patterns

### Redact-before-wrap error handling
**Source:** `sdks/go/errors.go` (`newNetworkError`/`sanitizeResponse`) + `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`)
**Apply to:** `errors/NetworkError.java`, `errors/ErrorMapper.java`, and every REST/gRPC call site that constructs an error from a live response — the single-choke-point invariant (never construct `NetworkError` directly from an unredacted `Response`) must hold across `rest/`, `grpc/`, and `internal/` packages alike.

### Single-flight refresh guard shared across transports
**Source:** `sdks/go/internal/refreshguard/guard.go` + `sdks/go/grpc/client.go`'s `RefreshFunc` (caller-supplied closure so `grpc/` package has no REST dependency)
**Apply to:** `internal/RefreshGuard.java` is instantiated once per `AxiamClient` and injected into both `rest/AuthInterceptor.java`/`AuthAuthenticator.java` and `grpc/GrpcAuthzClient.java` — never a second guard instance per transport (D-07's explicit requirement).

### Cross-tenant JWKS claim check (MUST-carry-forward control)
**Source:** `sdks/go/middleware/nethttp.go` lines 78-85 (TS CR-03 origin)
**Apply to:** `internal/JwksVerifier.java` callers in both `spring/AxiamAuthenticationFilter.java` and any resource-server-style local verification path — signature validity alone never implies tenant authorization since JWKS is org-wide.

### AMQP HMAC canonicalization — preserve wire order, never sort
**Source:** `crates/axiam-amqp/src/messages.rs` (canonical) — explicitly **diverges from** `sdks/go/amqp/hmac.go`'s stated (and for this codebase, incorrect-if-taken-literally) alphabetical-sort comment
**Apply to:** `amqp/Hmac.java` only — this is the single highest-risk correctness bug callable out in RESEARCH.md Pitfall 5; do not use Go's file as a literal ordering reference, use RESEARCH.md Pattern 5 / the Rust source directly.

### Constant-time comparison
**Source:** `sdks/go/amqp/hmac.go:66` (`hmac.Equal`), `crates/axiam-amqp/src/messages.rs` (`mac.verify_slice`)
**Apply to:** `amqp/Hmac.java` — use `java.security.MessageDigest.isEqual()`, never `Arrays.equals`/`String.equals` (RESEARCH.md Anti-Patterns).

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `spring/AxiamAutoConfiguration.java` | provider | — | Java/Spring-Boot-only mechanism (`AutoConfiguration.imports`); no sibling SDK has an equivalent framework auto-registration concept. Use RESEARCH.md Pattern 9 (lines 1133-1161) as the primary/only source. |
| `.github/workflows/sdk-ci-java.yml` GPG-signing job | config (CI) | — | No sibling SDK publishes via GPG-signed Maven Central (npm/PyPI/crates.io/Go-proxy all use token/OIDC publishing, not GPG). Use `sdk-ci-python.yml`'s tag-triggered-job *structure* (paths filter, scaffold-check, separate PR-gate vs. tag-triggered jobs) but source the GPG-specific steps from RESEARCH.md Pitfall 4/Common Pitfalls section directly. |
| `pom.xml` GPG/Central Portal plugin chain | config | — | No sibling SDK's build file is a Maven POM; use RESEARCH.md's "Complete `pom.xml` skeleton" code example (RESEARCH.md line 1325+) as the primary source, informed by the existing stale scaffold at `sdks/java/pom.xml` for what to preserve (groupId/artifactId/licenses/scm). |

## Metadata

**Analog search scope:** `sdks/go/`, `sdks/python/src/axiam_sdk/`, `sdks/typescript/src/`, `sdks/rust/src/`, `sdks/java/` (existing scaffold), `crates/axiam-amqp/src/messages.rs`, `crates/axiam-api-rest/src/handlers/authz_check.rs`, `.github/workflows/sdk-ci-python.yml`
**Files scanned:** ~30 (Go: client.go, errors.go, sensitive.go, refreshguard/guard.go, amqp/{consumer,hmac,errdrop}.go, middleware/nethttp.go, grpc/{client,interceptor}.go; TypeScript: core/errorMapper.ts; server: axiam-amqp/messages.rs, axiam-api-rest/handlers/authz_check.rs; CI: sdk-ci-python.yml; Java scaffold: pom.xml)
**Pattern extraction date:** 2026-07-02
