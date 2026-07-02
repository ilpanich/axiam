---
phase: 21-c-sdk
reviewed: 2026-07-02T00:00:00Z
depth: deep
files_reviewed: 28
files_reviewed_list:
  - sdks/csharp/Axiam.Sdk/AxiamClient.cs
  - sdks/csharp/Axiam.Sdk/Core/Sensitive.cs
  - sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs
  - sdks/csharp/Axiam.Sdk/Core/NetworkError.cs
  - sdks/csharp/Axiam.Sdk/Core/AuthError.cs
  - sdks/csharp/Axiam.Sdk/Core/AuthzError.cs
  - sdks/csharp/Axiam.Sdk/Core/TenantContext.cs
  - sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs
  - sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs
  - sdks/csharp/Axiam.Sdk/Auth/Jwk.cs
  - sdks/csharp/Axiam.Sdk/Auth/LoginResult.cs
  - sdks/csharp/Axiam.Sdk/Auth/TokenPair.cs
  - sdks/csharp/Axiam.Sdk/Amqp/Hmac.cs
  - sdks/csharp/Axiam.Sdk/Amqp/AxiamAmqpConsumer.cs
  - sdks/csharp/Axiam.Sdk/Amqp/PoisonMessageException.cs
  - sdks/csharp/Axiam.Sdk/Rest/AxiamHttpClientFactory.cs
  - sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs
  - sdks/csharp/Axiam.Sdk/Rest/AuthzRestClient.cs
  - sdks/csharp/Axiam.Sdk/Grpc/AxiamGrpcChannel.cs
  - sdks/csharp/Axiam.Sdk/Grpc/AuthInterceptor.cs
  - sdks/csharp/Axiam.Sdk/Grpc/AxiamGrpcAuthzClient.cs
  - sdks/csharp/Axiam.Sdk/Options/AxiamClientOptions.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/AxiamAuthMiddleware.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/AxiamPolicyHandler.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/AxiamPolicyProvider.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/AxiamRequirement.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/AxiamOptions.cs
  - sdks/csharp/Axiam.Sdk.AspNetCore/ServiceCollectionExtensions.cs
findings:
  critical: 2
  warning: 5
  info: 2
  total: 9
status: issues_found
---

# Phase 21: Code Review Report

**Reviewed:** 2026-07-02T00:00:00Z
**Depth:** deep
**Files Reviewed:** 28
**Status:** issues_found

## Summary

This review traced the C# SDK's REST/gRPC/AMQP transports and the ASP.NET Core
middleware against both the cross-language `sdks/CONTRACT.md` and, where the
contract's own text was ambiguous, the **actual AXIAM server implementation**
(`crates/axiam-api-rest`, `crates/axiam-auth`, `crates/axiam-oauth2`) so the
findings below are grounded in what the real server does, not just what the
contract says it should do.

The security-critical primitives called out in the review priorities are
sound: `Amqp/Hmac.cs` is constant-time and fails closed; `JwksVerifier`
correctly pins `alg=EdDSA` before any `kid` lookup, verifies via BouncyCastle
Ed25519, and enforces `tenant_id` post-signature; `RefreshGuard` is a true
single-flight guard (the `SemaphoreSlim` already serializes all callers, so
the "double-check" is really just a freshness-reuse optimization, and it
correctly discards a faulted attempt); and there is no TLS-bypass branch
anywhere in `AxiamHttpClientFactory`/`AxiamGrpcChannel` — the only
`ServerCertificateCustomValidationCallback` assigned is the additive
`CustomTrustStore` path, which still calls `chain.Build(cert)`.

However, cross-referencing the REST transport against the real server
surfaced a **critical, cross-cutting defect that breaks the SDK's core
functionality**: the SDK's CSRF-token capture mechanism can never actually
receive a token from the real AXIAM server, because the server only ever
sets the CSRF value via a `Set-Cookie` header, never via the
`X-CSRF-Token` **response** header the SDK's `CaptureCsrfToken` looks for.
Since the server's `CsrfMiddleware` requires that header on essentially
every authenticated write endpoint (`/api/v1/auth/refresh`,
`/api/v1/auth/logout`, `/api/v1/authz/check(/batch)`, and every other
`/api/v1/*` mutation), this means `RefreshAsync`, `LogoutAsync`, and both
`AuthzRestClient` methods will **always** fail with a 403 against a real
server once a session is established. Only `LoginAsync`/`VerifyMfaAsync`
(both CSRF-exempt server-side) work as coded.

A second, more subtle finding is that `Sensitive<T>`'s doc comments assert a
specific security property ("default reference-identity behavior…avoids
opening a value-equality/timing side channel") that C# struct semantics do
not actually provide — `ValueType.Equals`/`GetHashCode` perform structural
(value) comparison by default, so the stated mitigation does not exist as
implemented.

## Critical Issues

### CR-01: CSRF-token capture is a no-op against the real server — refresh, logout, and all authz checks always fail

**File:** `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs:149-159` (also `:36`, `:141-146`)
**Also depends on (ground truth, not part of this review's file list but load-bearing for the finding):**
`crates/axiam-api-rest/src/handlers/auth.rs:190-206` (login response) and
`crates/axiam-api-rest/src/middleware/csrf.rs:39-55,120-156` (CSRF enforcement + exempt list).

**Issue:**
`CaptureCsrfToken` only ever looks for the CSRF value on the **response
header** `X-CSRF-Token`:

```csharp
private void CaptureCsrfToken(HttpResponseMessage response)
{
    if (response.Headers.TryGetValues(CsrfHeaderName, out IEnumerable<string>? values))
    {
        string? newToken = values.FirstOrDefault();
        if (!string.IsNullOrEmpty(newToken))
        {
            _csrfToken = newToken;
        }
    }
}
```

The real AXIAM login handler, however, only ever sets the CSRF value as a
**cookie** (`axiam_csrf`) — it never emits an `X-CSRF-Token` response
header anywhere in the codebase (confirmed by grepping the entire
`axiam-api-rest` crate: `HEADER_CSRF`/`"X-CSRF-Token"` is only ever *read*
from the incoming request in `middleware/csrf.rs`, never written to a
response):

```rust
// crates/axiam-api-rest/src/handlers/auth.rs:190-206
let csrf_token = generate_csrf_token();
Ok(HttpResponse::Ok()
    .cookie(access_cookie(...))
    .cookie(refresh_cookie(...))
    .cookie(csrf_cookie(&csrf_token, ...))   // <-- cookie only, no header
    .json(LoginSuccessResponse { ... }))
```

Because `_csrfToken` therefore never becomes non-`null`, `ApplyHeaders`
never attaches `X-CSRF-Token` to any outgoing state-changing request:

```csharp
string? csrf = _csrfToken;               // always null in practice
if (csrf is not null && StateChangingMethods.Contains(request.Method.Method))
{
    request.Headers.TryAddWithoutValidation(CsrfHeaderName, csrf);
}
```

The server's `CsrfMiddleware` rejects any state-changing request that is
missing that header, **even when the `axiam_csrf` cookie itself is present
and valid** — both must be present and match:

```rust
// crates/axiam-api-rest/src/middleware/csrf.rs:141-156
let valid = match (cookie_value, header_value) {
    (Some(cookie), Some(header)) => cookie.as_bytes().ct_eq(header.as_bytes()).into(),
    _ => false,                       // header missing => always invalid
};
if !valid { /* 403 AuthorizationDenied */ }
```

The CSRF-exempt path list (`crates/axiam-api-rest/src/middleware/csrf.rs:39-55`)
covers only `/api/v1/auth/login`, the MFA endpoints, `/device`, `/reset*`,
and `/oauth2/*` — it explicitly does **not** cover
`/api/v1/auth/refresh`, `/api/v1/auth/logout`, or any `/api/v1/*` CRUD/authz
route (`/api/v1/authz/check`, `/api/v1/authz/check/batch`, etc., all live
under the `/api/v1` scope wrapped by `CsrfMiddleware` at
`crates/axiam-api-rest/src/server.rs:216-218`).

**Net effect:** after a successful `LoginAsync`, every subsequent
state-changing REST call this SDK makes — `RefreshAsync` (`POST
/api/v1/auth/refresh`), `LogoutAsync` (`POST /api/v1/auth/logout`), and
`AuthzRestClient.CheckAccessAsync`/`BatchCheckAsync`/`CanAsync` (`POST
/api/v1/authz/check[/batch]`) — will unconditionally receive HTTP 403 from
a real AXIAM server (mapped by `ErrorMapper` to `AuthzError`, which is
itself a misleading error type for what is actually a CSRF/session-plumbing
bug, not an authorization decision). This is not a corner case: it is the
default, always-reproducible behavior for any consumer of this SDK.

**Fix:** Read the `axiam_csrf` cookie from the same `CookieContainer` the
SDK already uses for `axiam_access`, mirroring `ReadAccessTokenFromCookieJar`,
instead of (or in addition to) relying on a response header the real server
never sends:

```csharp
private const string CsrfCookieName = "axiam_csrf";

private string? ReadCsrfTokenFromCookieJar()
{
    CookieCollection cookies = _cookieContainer.GetCookies(_baseUri);
    foreach (Cookie cookie in cookies)
    {
        if (cookie.Name == CsrfCookieName)
        {
            return cookie.Value;
        }
    }
    return null;
}

private void ApplyHeaders(HttpRequestMessage request, string? overrideAccessToken = null)
{
    ...
    string? csrf = _csrfToken ?? ReadCsrfTokenFromCookieJar();
    if (csrf is not null && StateChangingMethods.Contains(request.Method.Method))
    {
        request.Headers.Remove(CsrfHeaderName);
        request.Headers.TryAddWithoutValidation(CsrfHeaderName, csrf);
    }
}
```
(Keep `CaptureCsrfToken`'s response-header path too, as defense against a
future server version that starts echoing the header — but the cookie-jar
read is the load-bearing fix.) This should be covered by an integration
test that performs `LoginAsync` → `RefreshAsync`/`Authz.CheckAccessAsync`
against a fake server that enforces the same double-submit CSRF check the
real server does; the current test seam (`AxiamClient.CreateForTesting`)
appears not to exercise this, since no test would have caught it.

---

### CR-02: `Sensitive<T>`'s documented equality "mitigation" does not exist — default struct/record equality performs value comparison

**File:** `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs:34-54`

**Issue:** The type's remarks explicitly claim:

> `Equals(object?)` and `GetHashCode` are intentionally NOT overridden to
> compare/hash the wrapped value — the default **reference-identity
> behavior** for the boxed comparison avoids opening a value-equality/timing
> side channel that could otherwise be used to probe the redacted value.

This is factually incorrect for a C# `struct`. `System.ValueType.Equals(object)`
(the implementation a struct inherits when it doesn't override `Equals`)
performs a **structural, field-by-field value comparison** via reflection —
not reference-identity — and the inherited `GetHashCode()` likewise derives
a hash from field values. Structs have no reference identity to fall back
on in the first place (each box is a distinct object), so leaving `Equals`
un-overridden does not yield "reference identity"; it yields **value
equality on the wrapped secret**.

Concretely: `Sensitive<string> a = Sensitive.Of("secret1"); object b = Sensitive.Of("secret1"); a.Equals(b)` returns `true` today, and it does so via a
non-constant-time comparison path (`ValueType.Equals`'s field walk, and — for
a `string` field — `string.Equals`, which is not guaranteed constant-time).
This also means every public record type carrying a `Sensitive<T>` field —
`LoginResult.ChallengeToken`, `TokenPair.AccessToken`/`RefreshToken` — gets a
compiler-synthesized `Equals`/`GetHashCode`/`==` that transitively performs
this same value comparison, since record equality is generated by calling
`EqualityComparer<T>.Default.Equals(...)` on each property. A consumer
calling `loginResult1 == loginResult2`, or using a `Sensitive<T>`-bearing
record as a dictionary key/`HashSet` member, is silently comparing/hashing
the redacted secret — precisely the side channel the doc comment claims is
closed.

**Fix:** Override `Equals`/`GetHashCode` on `Sensitive<T>` itself to make the
"never comparable" intent real, e.g.:

```csharp
public override bool Equals(object? obj) => false; // Sensitive<T> is never equal to anything via the default path
public override int GetHashCode() => 0;             // never derive a hash from the wrapped value
```

(or implement `IEquatable<Sensitive<T>>` similarly). Update the XML remarks
to describe what is actually implemented rather than the incorrect
"reference-identity" rationale.

## Warnings

### WR-01: `AuthzRestClient` never translates transport-level exceptions into `NetworkError`

**File:** `sdks/csharp/Axiam.Sdk/Rest/AuthzRestClient.cs:68-82, 96-114`

**Issue:** `CheckAccessAsync`/`BatchCheckAsync` call `_http.PostAsJsonAsync(...)`
with no surrounding `try/catch`:

```csharp
using HttpResponseMessage response = await _http.PostAsJsonAsync(CheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
if (!response.IsSuccessStatusCode)
{
    throw ErrorMapper.FromHttpResponse(response, "checkAccess failed");
}
```

`ErrorMapper.FromHttpResponse` only handles a *received* HTTP status; it does
nothing for a connection refusal, DNS failure, TLS failure, or timeout — an
`HttpRequestException`/`TaskCanceledException` thrown by `PostAsJsonAsync`
itself propagates to the caller completely unwrapped. This is inconsistent
with `AxiamClient.PostJsonAsync` (`AxiamClient.cs:342-352`), which does catch
`HttpRequestException` and wraps it in `NetworkError`, and it violates
`sdks/CONTRACT.md` §2's explicit requirement that "Connection error / DNS /
TLS" map to `NetworkError`. A consumer who structures error handling around
the SDK's documented three-exception taxonomy (`AuthError`/`AuthzError`/
`NetworkError`) will see an unexpected, unhandled exception type from these
two methods specifically.

**Fix:** Wrap the `PostAsJsonAsync` calls the same way `AxiamClient.PostJsonAsync`
does:

```csharp
HttpResponseMessage response;
try
{
    response = await _http.PostAsJsonAsync(CheckPath, wireRequest, cancellationToken).ConfigureAwait(false);
}
catch (HttpRequestException ex)
{
    throw NetworkError.FromException(ex, "checkAccess failed");
}
using (response) { ... }
```

### WR-02: A client-side request timeout is never mapped to `NetworkError` anywhere in the REST transport

**File:** `sdks/csharp/Axiam.Sdk/AxiamClient.cs:342-352`

**Issue:** `PostJsonAsync` only catches `HttpRequestException`:

```csharp
catch (HttpRequestException ex)
{
    throw NetworkError.FromException(ex, $"POST {path} failed");
}
```

`HttpClient.Timeout` (set from `AxiamClientOptions.RequestTimeout`,
`AxiamClient.cs:104`) expiring throws `TaskCanceledException` (typically
wrapping a `TimeoutException` as its `InnerException`), which is not an
`HttpRequestException` and is not caught here — it propagates as a raw
`TaskCanceledException` from `LoginAsync`/`VerifyMfaAsync`/`LogoutAsync`/
`RefreshAsync` alike. Combined with WR-01, this means no REST-transport
timeout in this SDK is ever surfaced as the documented `NetworkError` type.

**Fix:** Also catch `TaskCanceledException`/`OperationCanceledException`
(distinguishing an actual user-supplied `cancellationToken` cancellation,
which should probably propagate as-is, from an `HttpClient.Timeout`
expiry, which should become a `NetworkError`) — e.g. check
`ex.CancellationToken == cancellationToken` to tell them apart, matching
the well-known .NET pattern for this exact ambiguity.

### WR-03: The reactive 401→refresh→retry is not exempted for Login/MfaVerify/Logout, only for the refresh path itself

**File:** `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs:33, 90-124`

**Issue:** `RefreshPath` is the only path exempted from the automatic
401-triggers-refresh-then-retry behavior:

```csharp
if (response.StatusCode == HttpStatusCode.Unauthorized && !isRefreshCall && !isRetry)
{
    refreshed = await _refreshGuard.RefreshIfNeededAsync(cancellationToken).ConfigureAwait(false);
    ...
}
```

A 401 from `POST /api/v1/auth/login` (bad credentials) or `POST
/api/v1/auth/mfa/verify` (bad TOTP code) has nothing to do with an expired
access token, yet it is not exempted here the way the refresh path is. If
the cookie jar happens to still hold an older, still-valid access token
(e.g., the caller is attempting a fresh login while a previous session's
token is present), a failed login/MFA attempt will trigger a real,
unrelated background token refresh (and, if that unexpectedly succeeds,
silently mutate session state) before the original 401 is returned to the
caller. Even when there is no old token present, this wastes a guard
acquisition and an `AuthError`-throwing round trip on every failed
login/MFA attempt. `LogoutAsync`'s own 401 (an already-invalid session)
has the same problem.

**Fix:** Exempt `LoginPath`, `MfaVerifyPath`, and `LogoutPath` (not just
`RefreshPath`) from the reactive-refresh branch, the same way the Java/Go
siblings referenced in this file's own comments exempt their auth
endpoints.

### WR-04: `AuthInterceptor.InjectAuthMetadata` mutates a possibly caller-owned `Metadata` instance in place

**File:** `sdks/csharp/Axiam.Sdk/Grpc/AuthInterceptor.cs:118-139`

**Issue:**

```csharp
Metadata headers = context.Options.Headers ?? new Metadata();
RemoveIfPresent(headers, AuthorizationHeader);
RemoveIfPresent(headers, TenantHeader);
...
headers.Add(AuthorizationHeader, $"Bearer {token}");
headers.Add(TenantHeader, _tenantId);
CallOptions newOptions = context.Options.WithHeaders(headers);
```

When `context.Options.Headers` is already non-null (a caller supplied their
own `CallOptions.Headers`/`Metadata` instance, e.g. to pass custom metadata
on a call), `headers` aliases that *same* `Metadata` object rather than a
defensive copy, and `RemoveIfPresent`/`Add` mutate it in place. `Metadata`
(a `List<Entry>` wrapper) is not documented as safe for concurrent mutation.
If a consumer reuses the same `CallOptions`/`Metadata` instance across
multiple concurrent calls (a plausible pattern for a "default options"
object), two concurrent interceptor invocations mutating the same list is a
data race. It also means the caller's own `Metadata` object is silently and
permanently mutated by this SDK as a side effect of making a call.

**Fix:** Build a fresh `Metadata` and copy any pre-existing entries into it
rather than mutating `context.Options.Headers` directly:

```csharp
var headers = new Metadata();
if (context.Options.Headers is { } existing)
{
    foreach (Metadata.Entry entry in existing)
    {
        if (!string.Equals(entry.Key, AuthorizationHeader, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(entry.Key, TenantHeader, StringComparison.OrdinalIgnoreCase))
        {
            headers.Add(entry);
        }
    }
}
```

### WR-05: The 401-retry request clone drops any headers/options beyond tenant/auth/CSRF/content-type

**File:** `sdks/csharp/Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs:107-121`

**Issue:** The retry request is built from scratch with only method, URI,
and (optionally) body/content-type:

```csharp
var retryRequest = new HttpRequestMessage(request.Method, request.RequestUri);
if (bodyBytes is not null) { ... retryRequest.Content = retryContent; }
retryRequest.Options.Set(RetryMarkerKey, true);
ApplyHeaders(retryRequest, refreshed.AccessToken.Reveal());
```

Any additional headers or `HttpRequestOptions` a caller set directly on the
original `HttpRequestMessage` (reachable today only via the `internal
TransportHttpClient` seam, but that seam is explicitly exposed to the
`Axiam.Sdk.AspNetCore`/gRPC/test assemblies via `InternalsVisibleTo`) are
silently dropped on retry. This is low-probability under the SDK's own
current call sites (none of which set extra headers), but is a latent
correctness gap for any future internal consumer of `TransportHttpClient`.

**Fix:** Copy `request.Headers` (excluding the ones `ApplyHeaders` manages)
onto `retryRequest` before calling `ApplyHeaders`.

## Info

### IN-01: `DecodeUnverifiedClaims`/`Base64UrlDecode` duplicated verbatim across two files

**File:** `sdks/csharp/Axiam.Sdk/AxiamClient.cs:377-406` and
`sdks/csharp/Axiam.Sdk/Grpc/AxiamGrpcAuthzClient.cs:236-265`

**Issue:** The exact same private `DecodeUnverifiedClaims`/`Base64UrlDecode`
implementation (unverified-JWT-payload decode for operational hints only) is
copy-pasted between `AxiamClient` and `AxiamGrpcAuthzClient`. Any future fix
or hardening (e.g., tightening the fallback decode's error handling) has to
be applied in two places and can easily drift.

**Fix:** Extract a small `internal static` helper (e.g. on a shared
`Jwt`/`UnverifiedJwt` type in `Axiam.Sdk.Core`) and have both call sites use
it.

### IN-02: `JwksVerifier`'s cache fields are mutated without synchronization

**File:** `sdks/csharp/Axiam.Sdk/Auth/JwksVerifier.cs:55-56, 161-182`

**Issue:** `_keysByKid`/`_fetchedAt` are plain fields read/written from
`EnsureFreshAsync` with no lock. Because the refetch path always builds a
brand-new `Dictionary` and swaps the reference (`_keysByKid = map;`), there
is no torn-read risk, but concurrent `VerifyAsync` calls racing on a stale
cache can each independently trigger a redundant JWKS refetch. Purely a
minor inefficiency/quality note, not a correctness bug (explicitly out of
this review's performance scope), but worth a one-line comment noting the
lock-free-by-design choice so a future maintainer doesn't "fix" it into a
lock that changes behavior.

---

_Reviewed: 2026-07-02T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
