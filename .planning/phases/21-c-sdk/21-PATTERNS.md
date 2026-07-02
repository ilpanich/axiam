# Phase 21: C# SDK - Pattern Map

**Mapped:** 2026-07-02
**Files analyzed:** 24 (core Axiam.Sdk + Axiam.Sdk.AspNetCore + tests + CI)
**Analogs found:** 24 / 24 (all have a strong sibling-SDK analog; none in "No Analog Found")

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `sdks/csharp/Axiam.Sdk/AxiamClient.cs` | service (facade) | request-response | `sdks/java/src/main/java/io/axiam/sdk/AxiamClient.java` | exact |
| `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` | utility (concurrency guard) | request-response (single-flight) | `sdks/java/.../internal/RefreshGuard.java` | exact |
| `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs` | utility (crypto/verification) | request-response (cached fetch + verify) | `sdks/java/.../internal/JwksVerifier.java` (BouncyCastle path); Go `sdks/go/internal/jwks/verifier.go` (fetch/cache/kid pattern) | exact (Java = crypto workaround shape; Go = cache/tenant-check shape) |
| `sdks/csharp/Axiam.Sdk/Auth/LoginResult.cs` | model (DTO) | request-response | `sdks/java/.../LoginResult.java` | exact |
| `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs` | middleware (transport handler) | request-response | `sdks/go/grpc/tls.go` (TLS-safety escape-hatch shape) + Java `AuthInterceptor.java`/`AuthAuthenticator.java` (header injection + client-override safety) | role-match |
| `sdks/csharp/Axiam.Sdk/Rest/AuthzRestClient.cs` | service (CRUD-like authz calls) | request-response | Java `rest/` package (`AuthInterceptor.java` sibling calls) + Go `authz.go` | role-match |
| `sdks/csharp/Axiam.Sdk/Grpc/AxiamGrpcChannel.cs` | service (transport/channel mgmt) | request-response | `sdks/java/.../grpc/GrpcAuthzClient.java` + `AuthClientInterceptor.java`; Go `sdks/go/grpc/client.go` + `interceptor.go` | exact |
| `sdks/csharp/Axiam.Sdk/Amqp/AxiamAmqpConsumer.cs` | service (event-driven consumer) | event-driven | `sdks/java/.../amqp/AmqpConsumer.java` (verify-before-handler + ack/nack matrix) | exact |
| `sdks/csharp/Axiam.Sdk/Amqp/Hmac.cs` | utility (crypto verify) | transform | `sdks/java/.../amqp/Hmac.java` (ObjectNode wire-order) + `crates/axiam-amqp/src/messages.rs` (canonical sign/verify reference) | exact |
| `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs` | utility (redaction wrapper) | transform | `sdks/java/.../Sensitive.java` + `sdks/go/sensitive.go` | exact |
| `sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs` | utility (status→error mapping) | transform | `sdks/java/.../errors/ErrorMapper.java` + `sdks/go/errors.go` (`errorFromHTTPStatus`/`errorFromGRPCStatus`) | exact |
| `sdks/csharp/Axiam.Sdk/Core/NetworkError.cs` (+ AuthError/AuthzError) | model (typed error) | transform | `sdks/java/.../errors/NetworkError.java` + `sdks/go/errors.go` (`NetworkError`, `sanitizeResponse`, `newNetworkError`) + `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`) | exact |
| `sdks/csharp/Axiam.Sdk/Core/TenantContext.cs` | model/config | request-response | Go `middleware/context.go` (tenant context propagation) | role-match |
| `sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs` | config | — | Java client-builder options + Go functional-options in `client.go` | role-match |
| `sdks/csharp/Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs` | middleware (authn) | request-response | `sdks/java/.../spring/AxiamAuthenticationFilter.java` (exact sequence: extract→verify→exp-check→tenant-check→inject-identity→401/403 JSON); Go `sdks/go/middleware/nethttp.go` | exact |
| `sdks/csharp/Axiam.Sdk.AspNetCore/AxiamPolicyHandler.cs` | middleware (authz, policy-based) | request-response | Java D-08 has no direct 1:1 (Spring uses method-security instead) — closest is `AxiamAuthenticationFilter.java`'s AuthzError→403 mapping + Go's authz.go `CheckAccess` call shape | partial (novel .NET-specific `IAuthorizationHandler`, adapt Java's error-status mapping) |
| `sdks/csharp/Axiam.Sdk.AspNetCore/AxiamPolicyProvider.cs` | middleware (policy resolution) | request-response | novel .NET-idiom (`IAuthorizationPolicyProvider`); no sibling analog — build from RESEARCH.md Pattern 5 | no direct analog (see below) |
| `sdks/csharp/Axiam.Sdk.AspNetCore/ServiceCollectionExtensions.cs` | provider (DI registration) | — | `sdks/java/.../spring/AxiamAutoConfiguration.java` (zero-config auto-registration, `@ConditionalOnMissingBean` ≈ `TryAdd*` in .NET DI) | role-match |
| `sdks/csharp/tests/.../RefreshGuardSingleFlightTests.cs` | test | request-response (concurrency) | `sdks/java/.../internal/RefreshGuardSingleFlightTest.java` | exact |
| `sdks/csharp/tests/.../HmacVerifyTests.cs` | test | transform | `sdks/java/.../amqp/HmacVerifyTest.java` + `sdks/java/src/test/resources/amqp_hmac_vectors.json` (fixture) | exact |
| `sdks/csharp/tests/.../SensitiveRedactionTests.cs` | test | transform | `sdks/java/.../SensitiveTest.java` + `sdks/java/.../errors/ErrorRedactionTest.java` | exact |
| `sdks/csharp/tests/.../JwksVerifierTests.cs` | test | request-response | `sdks/java/.../internal/JwksVerifierTest.java` + Go `internal/jwks/verifier_test.go` | exact |
| `sdks/csharp/tests/.../AspNetCoreMiddlewareTests.cs` | test | request-response | `sdks/java/.../spring/AxiamAuthenticationFilterIT.java` | exact |
| `.github/workflows/csharp-sdk.yml` | config (CI) | batch | sibling per-SDK workflows (`java-sdk.yml`/`go-sdk.yml`/etc., path-filtered) | role-match |

## Pattern Assignments

### `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` (utility, single-flight)

**Analog:** `sdks/java/src/main/java/io/axiam/sdk/internal/RefreshGuard.java`

**Core pattern** (full file, lines 32-126): double-checked-lock single-flight refresh — acquire lock, check cached token still stale vs. `observedAccessToken`, if a refresh is already in-flight release the lock and await/join the shared future, otherwise start exactly one refresh **outside** the lock, propagate failure to every waiter with **no retry** (§9.3), clear `inFlight` on both success and failure paths.

C# translation is already drafted in RESEARCH.md Pattern 2 (`21-RESEARCH.md` lines 372-425) using `SemaphoreSlim(1,1)` + `Task<TokenPair>` per D-10/CONTRACT §9 — use that as the primary template; the Java file is the conceptual source for the double-check-after-lock structure and the "release lock before blocking, no retry-on-failure" invariants. Key correctness rule carried from Java lines 96-98: on failure, propagate the exception as-is to the awaited task and clear `inFlight`/`_inFlight` so a failed refresh is never cached for the next caller.

---

### `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs` (utility, crypto verify)

**Analogs:** `sdks/java/src/main/java/io/axiam/sdk/internal/JwksVerifier.java` (not fully read this pass, but referenced via `AxiamAuthenticationFilter.java` usage) and Go `sdks/go/internal/jwks/verifier.go`.

**Pattern to copy:**
- alg-pin (`alg=="EdDSA"`) **before** kid lookup — never let the token select its own verifier (JWT alg-confusion defense).
- fetch+cache JWKS keyed by `kid`; refetch on unknown `kid`.
- **After** signature verification, explicitly check `tenant_id` claim == configured tenant (JWKS is org-wide, not tenant-scoped — Pitfall 3 in RESEARCH.md, independently confirmed by every sibling SDK).
- Never throw on malformed/untrusted input — return null/false, fail closed.

Concrete C# implementation is fully drafted in RESEARCH.md Pattern 1 (lines 260-370) using `BouncyCastle.Cryptography`'s `Ed25519Signer`/`Ed25519PublicKeyParameters` (native `System.Security.Cryptography` Ed25519 support does NOT exist — confirmed research finding, do not attempt a native-only path).

---

### `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs` (utility, redaction wrapper)

**Analog:** `sdks/java/src/main/java/io/axiam/sdk/Sensitive.java`

**Core pattern** (lines 30-73):
```java
@JsonSerialize(using = Sensitive.Redactor.class)
public final class Sensitive {
    private static final String REDACTED = "[SENSITIVE]";
    private final String value;
    private Sensitive(String value) { this.value = Objects.requireNonNull(value, "value"); }
    public static Sensitive of(String value) { return new Sensitive(value); }
    @Override public String toString() { return REDACTED; }
    String expose() { return value; }  // package-internal only, never public
    static final class Redactor extends StdSerializer<Sensitive> {
        @Override public void serialize(Sensitive value, JsonGenerator gen, SerializerProvider p) throws IOException {
            gen.writeString(REDACTED);
        }
    }
}
```
Key invariants to carry into C#: (1) private/internal constructor + internal-only accessor (`internal T Reveal()`), never a public getter; (2) `ToString()` always returns `"[SENSITIVE]"`; (3) custom serializer converter always emits the redacted literal, never the real value; (4) no `Equals`/`GetHashCode` override that could leak the value via a timing side channel. C# target shape is already drafted in RESEARCH.md Pattern 7 (lines 748-763) as `readonly struct Sensitive<T>` + `SensitiveJsonConverter<T>` — use that as the primary template, Java as the invariant source.

---

### `sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs` + `NetworkError.cs`/`AuthError.cs`/`AuthzError.cs` (utility + model, redact-before-wrap)

**Analogs:** `sdks/java/src/main/java/io/axiam/sdk/errors/ErrorMapper.java`, `NetworkError.java`; `sdks/go/errors.go` (full file read, 181 lines).

**Central mapper pattern** (Java `ErrorMapper.java` lines 36-71 / Go `errors.go` lines 129-174): single source of truth for HTTP status → error class (401→AuthError, 403/409→AuthzError, everything else→NetworkError) and gRPC status → error class (UNAUTHENTICATED→AuthError, PERMISSION_DENIED→AuthzError, else→NetworkError). Both transports (REST + gRPC) MUST route through the same mapper so they cannot drift on the error taxonomy.

**Redact-before-wrap pattern** (Java `ErrorMapper.java` lines 73-93 `sanitize()`; Go `errors.go` lines 89-127 `sanitizeResponse`/`newNetworkError`):
```go
var sensitiveResponseHeaders = []string{"Set-Cookie", "Authorization", "Cookie"}

func sanitizeResponse(resp *http.Response) *http.Response {
    if resp == nil { return nil }
    clone := *resp
    clone.Header = resp.Header.Clone()
    for _, h := range sensitiveResponseHeaders { clone.Header.Del(h) }
    return &clone
}

func newNetworkError(message string, resp *http.Response, cause error) *NetworkError {
    if resp != nil {
        sanitized := sanitizeResponse(resp)
        return &NetworkError{Message: message, cause: fmt.Errorf("http status %d, headers: %v", sanitized.StatusCode, sanitized.Header)}
    }
    return &NetworkError{Message: message, cause: cause}
}
```
Critical invariant (Go comment lines 104-117, Java Javadoc lines 9-21): there must be exactly **one** choke-point constructor that accepts a live response object, and it must ALWAYS derive the wrapped cause from a sanitized copy — no other code path may construct a `NetworkError` from a raw, unredacted response. Java additionally documents (`NetworkError.java` lines 14-18) that the constructor has **no overload accepting a live response directly** — this structurally prevents the CR-04 bug class. C#'s `NetworkError.FromResponse(HttpResponseMessage, ...)` (RESEARCH.md Pattern 7, lines 765-793) is the direct translation — mirror the "single construction path" invariant precisely, and add the `SanitizeMessage` regex-based defense-in-depth shown there for exception-message leakage.

**Test analog:** `sdks/java/src/test/java/io/axiam/sdk/errors/ErrorRedactionTest.java` — non-vacuous control case (assert a non-secret header/value DOES survive, secret one does not).

---

### `sdks/csharp/Axiam.Sdk/Amqp/Hmac.cs` (utility, HMAC verify, wire-order preserving)

**Analogs:** `sdks/java/src/main/java/io/axiam/sdk/amqp/Hmac.java` (full file); `crates/axiam-amqp/src/messages.rs` (canonical reference, lines 26-50).

**Server reference** (`messages.rs` lines 29-50):
```rust
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = hex::decode(signature_hex).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}
```
Note: the signed bytes are whatever `serde_json` struct-declaration-order serialization produced with `hmac_signature` absent — this is the "canonical JSON" that must be byte-identically reproduced client-side.

**Java client verify pattern** (`Hmac.java` lines 53-81): parse into `ObjectNode` (LinkedHashMap-backed, preserves insertion/wire order) → check `hmac_signature` present (else reject) → **`node.remove("hmac_signature")` mutates the same ordered map in place, preserving relative order of remaining keys** (the single load-bearing property — do NOT alphabetize or POCO-round-trip) → re-serialize → `HexFormat.parseHex` the expected signature → `Mac.getInstance("HmacSHA256")` → `MessageDigest.isEqual` (constant-time) → never throw, any parse/format failure returns `false`.

C# target: `System.Text.Json.Nodes.JsonObject` (confirmed `OrderedDictionary`-backed) + `Remove("hmac_signature")` + `ToJsonString()` + `HMACSHA256.HashData` + `CryptographicOperations.FixedTimeEquals` — full code already drafted in RESEARCH.md Pattern 3 (lines 452-483). Use Java's file as the structural template (never-throw try/catch wrapper, same method shape) and `messages.rs` as the byte-for-byte wire-format ground truth.

**Test fixture analog:** `sdks/java/src/test/resources/amqp_hmac_vectors.json` — reuse the identical Rust-signed fixture vectors for the C# `HmacVerifyTests.cs` (do not regenerate; same vectors guarantee cross-SDK byte-for-byte parity).

---

### `sdks/csharp/Axiam.Sdk/Amqp/AxiamAmqpConsumer.cs` (service, event-driven, verify-before-handler)

**Analog:** `sdks/java/src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java` (full file, 153 lines).

**Ack/nack decision matrix** (Java lines 97-123, `deliverCallback`):
```java
if (!Hmac.verify(signingKey, body)) {
    logger.warn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue "
            + "(exchange={}, routingKey={})", ...);
    channel.basicNack(deliveryTag, false, false); // no requeue
    return; // handler structurally unreachable
}
try {
    handler.accept(body);           // handler NEVER sees an unverified message
    channel.basicAck(deliveryTag, false);
} catch (ErrDrop drop) {
    channel.basicNack(deliveryTag, false, false); // poison, no requeue
} catch (Exception transientFailure) {
    channel.basicNack(deliveryTag, false, true);  // retryable, requeue
}
```
This is exactly D-11's required matrix (HMAC-fail→nack-no-requeue+security-log; handler-success→ack; drop-sentinel→nack-no-requeue; transient-exception→nack-with-requeue). Security log MUST NOT contain the HMAC value itself (Java lines 104-109) — only exchange/routing-key context.

`configureAutomaticRecovery` (Java lines 138-151) shows the "never disable automatic recovery, only make interval overridable" pattern — RabbitMQ.Client 7.x C# equivalent already drafted in RESEARCH.md Pattern 3 (`AsyncEventingBasicConsumer`, `ConnectionFactory{AutomaticRecoveryEnabled=true, NetworkRecoveryInterval=...}`).

**`ErrDrop` sentinel analog:** `sdks/java/.../amqp/ErrDrop.java` → C# `PoisonMessageException` (already named in RESEARCH.md Pattern 3, line 545).

**Test analog:** `sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java` — constructs the deliver-callback directly against synthesized deliveries + a fake channel, proving every matrix branch without a live broker; mirror this shape for `AxiamAmqpConsumer`'s xUnit tests (fake `IChannel`, no live RabbitMQ broker required in CI per RESEARCH.md's fixture-based fallback).

---

### `sdks/csharp/Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs` (middleware, authn)

**Analog:** `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAuthenticationFilter.java` (full file, 169 lines) — the direct Spring `SecurityContext` integration D-06 is explicitly modeled on (per CONTEXT.md D-06: "Direct analog of Java D-14's Spring `SecurityContext` integration").

**Sequence to replicate** (lines 74-112, `doFilterInternal`):
1. `extractToken` — `Authorization: Bearer` header first, then `axiam_access` cookie (lines 135-152).
2. If no token: pass through unauthenticated (let framework's own `[Authorize]`/`authorizeHttpRequests` 401/403 it) — do NOT reject at the middleware layer when no credential was presented at all.
3. If token present: `jwksVerifier.verify(token)` (alg-pinned signature check).
4. Explicit `exp` check even though the verifier doesn't itself check expiry (defense in depth, lines 88-91).
5. **Mandatory cross-tenant check** `assertTenant(claims, configuredTenantId)` (lines 93-96) — carried forward from Pitfall 3.
6. Map scope/roles claim → framework identity/authority objects (lines 98-100, `scopeToAuthorities`).
7. Set framework identity (`SecurityContextHolder`/C# `HttpContext.User = ClaimsPrincipal(...)`).
8. `AuthzError`→403, `AuthError`→401, any other exception→401 fail-closed (lines 102-111) — always via a **standardized JSON body written through the JSON serializer** (lines 159-167, `writeJsonError` uses Jackson `ObjectNode`, never manual string concatenation, to prevent JSON injection via a message containing quotes).

C# target is fully drafted in RESEARCH.md Pattern 5 (lines 585-638, `AxiamAuthMiddleware.InvokeAsync`) — use Java's file as the authoritative sequence/invariant source (especially the "no-credential passthrough" and "JSON-serializer-not-string-concat for error body" rules, which RESEARCH.md's draft implicitly assumes but doesn't spell out as explicitly).

---

### `sdks/csharp/Axiam.Sdk.AspNetCore/ServiceCollectionExtensions.cs` (provider, DI registration)

**Analog:** `sdks/java/src/main/java/io/axiam/sdk/spring/AxiamAutoConfiguration.java` (full file, 62 lines).

**Pattern** (lines 37-61): `@ConditionalOnClass(SecurityFilterChain.class)` keeps the auto-config inert unless the framework security package is present; `@ConditionalOnMissingBean` on both the filter bean and the security-chain bean means a consumer who wires things explicitly always takes precedence over the zero-config default. C# equivalent: `AddAxiamAspNetCore()` should use `TryAddSingleton`/`TryAddScoped` (not `AddSingleton`) so an explicit consumer registration always wins, matching Java's `@ConditionalOnMissingBean` precedence rule exactly. RESEARCH.md Pattern 5 (lines 640-658) already drafts `AddAxiam`/`AddAxiamAspNetCore` — verify/adjust it to use `TryAdd*` semantics per this analog.

---

### `sdks/csharp/Axiam.Sdk.AspNetCore/AxiamPolicyHandler.cs` (middleware, policy-based authz, D-08)

**No direct 1:1 analog** — Spring's sibling SDK uses method-security annotations rather than a `IAuthorizationHandler`/policy-provider pair, so this is genuinely the most novel file in the phase. Closest partial matches:
- Error-status mapping precedent: Java `AxiamAuthenticationFilter.java` lines 102-111 (`AuthzError`→403 JSON body pattern) — reuse the same standardized-JSON-body convention.
- Server-call shape: Go `sdks/go/authz.go`'s `CheckAccess` call (same `CheckAccessAsync` semantics the handler must invoke) and `crates/axiam-api-grpc/src/services/authorization.rs` (`check_access`/`batch_check_access` semantics).
- RESEARCH.md Pattern 5 (lines 660-679) already contains a complete draft `AxiamPolicyHandler : AuthorizationHandler<AxiamRequirement>` — use this as primary source; note the project constraint (CLAUDE.md, RBAC additive-only) that this handler must NEVER cache an authz decision beyond the single request — always call `CheckAccessAsync` fresh.

---

## Shared Patterns

### Redact-before-wrap (CR-04 carry-forward)
**Source:** `sdks/go/errors.go` (`sanitizeResponse`/`newNetworkError`, lines 89-127), `sdks/java/.../errors/ErrorMapper.java` (`sanitize`, lines 73-93), `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError` — the original CR-04 fix, not re-read this pass but referenced by every later sibling).
**Apply to:** `NetworkError.cs`, `ErrorMapper.cs`, and any transport code (`AxiamHttpMessageHandler.cs`, `AxiamGrpcChannel.cs`) that could construct an error from a raw response/exception. **Rule:** exactly one choke-point constructor accepts a live response object; it always redacts `Set-Cookie`/`Authorization`/`Cookie` before storing anything; no other code path may build a `NetworkError` from an unredacted response.

### Single-flight refresh guard (§9)
**Source:** `sdks/java/.../internal/RefreshGuard.java` (full file).
**Apply to:** `RefreshGuard.cs`, shared by both `AxiamHttpMessageHandler.cs` (REST) and `AxiamGrpcChannel.cs` (gRPC) — **one instance per `AxiamClient`**, never one per transport.

### Verify-before-handler (HMAC / JWKS)
**Source:** `sdks/java/.../amqp/AmqpConsumer.java` + `Hmac.java` (AMQP); `sdks/java/.../spring/AxiamAuthenticationFilter.java` (JWKS in middleware).
**Apply to:** `AxiamAmqpConsumer.cs`/`Hmac.cs` and `AxiamAuthMiddleware.cs` — in both cases, the consumer-supplied handler / downstream framework pipeline must be structurally unreachable until verification succeeds; never throw on malformed/attacker-controlled input, fail closed instead.

### Cross-tenant claim check (JWKS is org-wide)
**Source:** every sibling SDK independently implements this; Java's `assertTenant` call site in `AxiamAuthenticationFilter.java` lines 93-96 is the clearest illustration of "signature valid ≠ tenant valid."
**Apply to:** `JwksVerifier.cs` and `AxiamAuthMiddleware.cs` — always check `tenant_id` claim against the configured tenant AFTER signature verification succeeds.

### Standardized JSON error body (never string concatenation)
**Source:** Java `AxiamAuthenticationFilter.java` `writeJsonError` (lines 159-167) — builds the error body via Jackson `ObjectNode`, never manual string interpolation, so a message containing quotes/control characters can't produce malformed/injected JSON.
**Apply to:** `AxiamAuthMiddleware.cs`'s error responses and `AxiamPolicyHandler.cs`'s 403 body — use `HttpContext.Response.WriteAsJsonAsync` (System.Text.Json), never manual string building.

### No-TLS-bypass gate (§6)
**Source:** `sdks/go/grpc/tls.go` (`newTLSCredentials` — the ONLY escape hatch is `customCAPEM` added to the trust pool; certificate verification is never disabled).
**Apply to:** `AxiamHttpMessageHandler.cs` and any gRPC channel-construction code — mirror Go's "additive custom-CA trust store, never an unconditional bypass" shape; this is exactly what the CI grep gate (SC#4) checks for.

## No Analog Found

None — every file has at least a partial analog from a sibling SDK per the classification table above. `AxiamPolicyHandler.cs`/`AxiamPolicyProvider.cs` are the most novel (no direct Spring-equivalent), but RESEARCH.md Pattern 5 already provides a concrete draft to build from.

## Metadata

**Analog search scope:** `sdks/java/src/`, `sdks/go/`, `sdks/python/src/axiam_sdk/` (not deep-read this pass — Java/Go patterns were sufficiently strong and directly cited in CONTEXT.md as primary analogs), `sdks/typescript/src/core/errorMapper.ts` (referenced, not re-read — already summarized in RESEARCH.md Pattern 7/CR-04), `crates/axiam-amqp/src/messages.rs`, `sdks/csharp/` (existing scaffold).
**Files scanned:** ~24 read/grepped directly (Java: 8 files fully read; Go: 2 files fully read; Rust: 1 file partially read; csharp scaffold: 1 csproj read).
**Pattern extraction date:** 2026-07-02
