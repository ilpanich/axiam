---
phase: 17-typescript-sdk
reviewed: 2026-07-01T12:54:02Z
depth: standard
files_reviewed: 32
files_reviewed_list:
  - sdks/typescript/src/index.ts
  - sdks/typescript/src/core/config.ts
  - sdks/typescript/src/core/csrf.ts
  - sdks/typescript/src/core/errorMapper.ts
  - sdks/typescript/src/core/errors.ts
  - sdks/typescript/src/core/index.ts
  - sdks/typescript/src/core/sensitive.ts
  - sdks/typescript/src/core/singleFlightRefresh.ts
  - sdks/typescript/src/rest/auth.ts
  - sdks/typescript/src/rest/authz.ts
  - sdks/typescript/src/rest/client.ts
  - sdks/typescript/src/rest/index.ts
  - sdks/typescript/src/rest/interceptors.ts
  - sdks/typescript/src/rest/retry.ts
  - sdks/typescript/src/rest/session.ts
  - sdks/typescript/src/rest/types.ts
  - sdks/typescript/src/grpc/callWithRefresh.ts
  - sdks/typescript/src/grpc/client.ts
  - sdks/typescript/src/grpc/index.ts
  - sdks/typescript/src/grpc/interceptor.ts
  - sdks/typescript/src/node/cookieJar.ts
  - sdks/typescript/src/node/jwks.ts
  - sdks/typescript/src/node/session.ts
  - sdks/typescript/src/node/tokenManager.ts
  - sdks/typescript/src/amqp/consumer.ts
  - sdks/typescript/src/amqp/hmac.ts
  - sdks/typescript/src/amqp/index.ts
  - sdks/typescript/src/amqp/messages.ts
  - sdks/typescript/src/middleware/cookieHeader.ts
  - sdks/typescript/src/middleware/express.ts
  - sdks/typescript/src/middleware/fastify.ts
  - sdks/typescript/src/middleware/index.ts
  - sdks/typescript/src/middleware/verifyCore.ts
  - sdks/typescript/scripts/bundle-grep.mjs
  - sdks/typescript/package.json
  - .github/workflows/sdk-ci-typescript.yml
findings:
  critical: 4
  warning: 5
  info: 4
  total: 13
status: issues_found
---

# Phase 17: Code Review Report

**Reviewed:** 2026-07-01T12:54:02Z
**Depth:** standard
**Files Reviewed:** 32 source files (+ package.json, CI workflow)
**Status:** issues_found

## Summary

Reviewed the AXIAM TypeScript client SDK — a security-sensitive IAM client covering REST auth/authz, gRPC (Node), AMQP HMAC-verified consumption, JWKS verification, and Express/Fastify resource-server middleware. Overall architecture is deliberate and well-documented (dependency-free `core`, module-level single-flight refresh guard, `Sensitive<T>` redaction, strict-by-default AMQP verification, algorithm-pinned JWT verification). However, four issues rise to BLOCKER severity, all in the auth/session and multi-tenant correctness surface the review was asked to focus on:

1. **CSRF token is never populated for the Node persona** — every state-changing REST call from Node (login, refresh, logout, checkAccess, batchCheck) will be rejected by the server's CSRF middleware in practice, because `session.csrfToken` is written by nothing in the codebase.
2. **The single-flight refresh guard is a true process-wide singleton**, not scoped per `AxiamClient`/session — any process running two or more `AxiamClient` instances (multi-tenant server, multiple test clients, etc.) can have one client's token refresh silently satisfy a completely different client's request.
3. **JWKS/middleware verification never checks the token's `tenant_id` claim against the session's configured tenant** — since JWKS is documented as organization-wide (not tenant-scoped), a token minted for Tenant A validates successfully against a resource server configured for Tenant B in the same org, undermining the project's core tenant-isolation guarantee.
4. **`NetworkError.cause` stores the raw, unredacted axios error**, which (on requests to `/api/v1/auth/login`, `/refresh`, `/logout`) can carry `Set-Cookie` response headers containing the literal session/refresh token values, reachable via `networkError.cause.response.headers` and exposed to `console.log`/`util.inspect` on the error object — contradicting the project's own no-raw-token-in-error-fields invariant (D-16) and the SDK's own "eyJ" token-leak CI gate intent.

Several further correctness/robustness issues (WARNING) affect the gRPC token-cache freshness right after login and general defensive coding around dead-code retry hints.

## Critical Issues

### CR-01: Node persona never populates `session.csrfToken` — CSRF header is silently omitted on every state-changing call

**File:** `sdks/typescript/src/rest/interceptors.ts:29-42`
**Issue:** `installCsrfInterceptor` reads the CSRF token from `document.cookie` in the browser, or from `session.csrfToken` in Node (`sdks/typescript/src/rest/interceptors.ts:33-34`). `session.csrfToken` is declared as a mutable field on `SharedSession` (`sdks/typescript/src/rest/session.ts:25`) and is only ever *cleared* (`= undefined`) on refresh failure and on `logout()` (`sdks/typescript/src/rest/interceptors.ts:77`, `sdks/typescript/src/rest/auth.ts:155`) — nothing in the codebase ever *writes* a real value into it. The Node cookie jar defines `CSRF_COOKIE = 'axiam_csrf'` (`sdks/typescript/src/node/cookieJar.ts:22`) and exports `extractCookieValue`, but no call site in `node/session.ts`, `node/tokenManager.ts`, or anywhere else reads the CSRF cookie out of the jar and assigns it to `session.csrfToken`. Consequently, for every `NodeSession` (used by the gRPC and middleware personas, and any Node consumer of the REST client), `csrfHeaderForMethod` is always called with an empty cookie string, so `X-CSRF-Token` is never attached on POST/PUT/PATCH/DELETE. Per CONTRACT.md §3/D-05 and the server's CSRF double-submit middleware, this means `login`, `refresh`, `logout`, `checkAccess`, and `batchCheck` will all be rejected server-side once a CSRF cookie exists (post-login), in any Node application using this SDK. This is untested — `test/rest/csrf.test.ts` only exercises the jsdom/`document.cookie` browser branch.
**Fix:** After each request that would set the `axiam_csrf` cookie (i.e., after `wrapAxios`'s jar receives a `Set-Cookie`), sync `session.csrfToken` from the jar, mirroring `TokenManager.syncFromJar()`. Concretely, add a jar-read step to `createNodeSession`/`NodeSession.doRefresh`/post-login flow, e.g.:
```typescript
// node/session.ts
doRefresh = async (): Promise<void> => {
  await this.axios.post('/api/v1/auth/refresh', {});
  await this.tokenManager.syncFromJar();
  this.csrfToken = await extractCookieValue(this.jar, this.baseUrl, CSRF_COOKIE);
};
```
and invoke the same sync after `login()`/`verifyMfa()` succeed (e.g. via a session hook called from `auth.ts`, since `auth.ts` already has `client.session` in scope). Add a Node-specific CSRF integration test analogous to `test/rest/csrf.test.ts` that goes through a real cookie jar rather than `document.cookie`.

### CR-02: Single-flight refresh guard is a global process singleton, not scoped per client/session — cross-session refresh cross-wiring

**File:** `sdks/typescript/src/core/singleFlightRefresh.ts:9-23`
**Issue:** `refreshPromise` is declared at module scope (`let refreshPromise: Promise<void> | null = null;`). Both `rest/interceptors.ts:71` (`refreshOnce(async () => { await session.axios.post(...) })`) and `grpc/callWithRefresh.ts:36` (`refreshOnce(session.doRefresh)`) call this same module-level function with a closure bound to *their own* `session`. If a process constructs more than one `AxiamClient`/`NodeSession` (e.g. a multi-tenant backend service holding one client per tenant, or simply two independent SDK consumers in the same Node process, or parallel test suites sharing a module registry), and two 401s occur concurrently on *different* sessions, the second caller's `refreshOnce` call sees `refreshPromise` already set (from the first session's in-flight refresh) and awaits *that* promise instead of triggering its own refresh — silently resolving as if its own session had been refreshed, when in fact a completely different session/tenant's `/api/v1/auth/refresh` was called. This directly contradicts the module's own doc comment ("Concurrent callers awaiting an in-flight refresh") which assumes single-flight is scoped to one logical session, and the header note "D-13" which elsewhere in the codebase means "shared across gRPC/REST for **the same session**" — not shared across independent client instances.
**Fix:** Scope the guard per-session instead of module-level, e.g. attach the in-flight promise to `SharedSession` itself and pass it through, or convert `refreshOnce` into a factory that returns a session-scoped closure:
```typescript
// core/singleFlightRefresh.ts
export function createRefreshGuard() {
  let refreshPromise: Promise<void> | null = null;
  return function refreshOnce(doRefresh: () => Promise<void>): Promise<void> {
    if (!refreshPromise) {
      refreshPromise = doRefresh().finally(() => { refreshPromise = null; });
    }
    return refreshPromise;
  };
}
```
and instantiate one guard per `SharedSession`/`NodeSession`, threading it through `installRefreshInterceptor` and `callWithRefresh` instead of importing the shared module-level function.

### CR-03: JWKS/middleware verification never validates the access token's `tenant_id` against the resource server's configured tenant — cross-tenant auth bypass

**File:** `sdks/typescript/src/middleware/verifyCore.ts:34-59`, `sdks/typescript/src/node/jwks.ts:51-79`
**Issue:** `createVerifier(baseUrl)` builds a `jose` remote JWKS bound only to `{baseUrl}/oauth2/jwks`, which the code's own comment states is "organization-wide, NOT tenant-scoped" (`node/jwks.ts:5`). `authenticateRequest` (`middleware/verifyCore.ts:34-59`) verifies the JWT signature/`exp`/algorithm, and merely checks that `claims.sub` and `claims.tenant_id` are *present* (truthy) — it never compares `claims.tenant_id` to the tenant the middleware/session was constructed for. `VerifiableSession` (`middleware/verifyCore.ts:13-15`) is deliberately minimal (`{ jwksVerifier: Verifier }`) and does not even carry a tenant identifier, even though `NodeSession` (which typically satisfies this interface) has `tenantHeaderValue` available. Because a single organization can contain multiple tenants sharing the same signing key/JWKS endpoint (per this codebase's own domain model: "Organizations ... contain tenants ... each tenant has its own users, roles, permissions"), a validly-signed access token issued for Tenant A will pass `authenticateRequest`/`axiamMiddleware`/`axiamPlugin` verification unchanged when presented to a resource server instance configured for Tenant B in the same org. This is a cross-tenant authentication/authorization bypass in a system whose stated core guarantee is full per-tenant data isolation.
**Fix:** Thread the expected tenant through `VerifiableSession` and enforce it in `authenticateRequest`:
```typescript
export interface VerifiableSession {
  jwksVerifier: Verifier;
  tenantHeaderValue: string;
}

export async function authenticateRequest(session: VerifiableSession, token: string): Promise<AxiamIdentity> {
  // ... existing verify ...
  if (claims.tenant_id !== session.tenantHeaderValue) {
    throw new AuthError('token tenant_id does not match configured tenant');
  }
  // ...
}
```
`NodeSession` already exposes `tenantHeaderValue` (inherited from `SharedSession`), so this is a non-breaking addition for existing callers that pass a `NodeSession`.

### CR-04: `NetworkError.cause` retains the raw axios error, which can carry the literal session/refresh token via `Set-Cookie` response headers — token leak through error objects

**File:** `sdks/typescript/src/core/errors.ts:38-47`, `sdks/typescript/src/rest/auth.ts:82,107,129,149`, `sdks/typescript/src/core/errorMapper.ts:43-56`
**Issue:** `NetworkError` declares `readonly cause?: unknown` as a real, enumerable public class field, and every call site in `auth.ts` (`login`, `verifyMfa`, `refresh`, `logout`) passes the *raw caught axios error* as `cause` (`{ cause: err }`) whenever the request fails with a mapped HTTP status. On a `login`/`refresh` call that partially succeeds at the network layer but the SDK still treats as an error path (e.g. a 4xx alongside a `Set-Cookie` header, or more importantly transient failures on retried/duplicate refresh attempts where the server has already issued new cookies before the client-observed error), `err.response.headers['set-cookie']` on the underlying `AxiosError` contains the literal `axiam_access=<jwt>`/`axiam_refresh=<opaque token>` values. Because `cause` is not wrapped in `Sensitive<T>` and `NetworkError` implements no custom `toString`/`toJSON`/`util.inspect.custom` redaction (unlike `Sensitive<T>` in `core/sensitive.ts`), any consumer that does `console.log(err)`, `JSON.stringify(err)` (via a custom serializer that walks own properties), or logs `err.cause` directly will surface the raw token material. This directly contradicts the project's stated invariant "No error message or field may embed a raw token string (D-16)" (`core/errors.ts:3-4`) and the SDK's own CI "Token-leak gate" intent (`sdk-ci-typescript.yml:89-97`) — that gate only scans the *built dist/* output for literal `eyJ`-prefixed strings, so it would not catch a runtime leak like this one, which only manifests when a real error/cookie flows through the SDK at request time. `test/core/errorMapper.test.ts:28-32` explicitly asserts `cause` is preserved verbatim, confirming this is by design rather than an oversight that tests would catch.
**Fix:** Either strip/redact sensitive headers before attaching `cause`, or wrap `cause` so default stringification redacts it:
```typescript
function sanitizeAxiosError(err: unknown): unknown {
  if (err && typeof err === 'object' && 'response' in err) {
    const response = (err as { response?: { headers?: Record<string, unknown> } }).response;
    if (response?.headers) {
      const { 'set-cookie': _omit, ...rest } = response.headers as Record<string, unknown>;
      return { ...err, response: { ...response, headers: rest } };
    }
  }
  return err;
}
// call sites: cause: sanitizeAxiosError(err)
```
or simpler: never pass the full axios error as `cause`; extract only `{ message, status }` for diagnostic purposes and drop the header-bearing object entirely.

## Warnings

### WR-01: gRPC access-token cache is stale immediately after login/verifyMfa — first RPC always unauthenticated, forcing an unnecessary refresh cycle

**File:** `sdks/typescript/src/node/tokenManager.ts:61-64`, `sdks/typescript/src/rest/auth.ts:63-87,96-112`, `sdks/typescript/src/grpc/interceptor.ts:25-39`
**Issue:** `TokenManager.syncFromJar()` — the only writer of `#cachedAccess` — is called solely from `NodeSession.doRefresh()` (`node/session.ts:35-38`) and from `callWithRefresh` after a retry-triggering refresh (`grpc/callWithRefresh.ts:37`). `auth.ts`'s `login()`/`verifyMfa()` set `client.session.authenticated = true` but never call `tokenManager.syncFromJar()`, even though the cookie jar has just received a fresh `axiam_access` cookie via `Set-Cookie`. Consequently the very first gRPC call after a fresh login finds `cachedAccessToken()` returning `null`; the synchronous `authInterceptor` (`grpc/interceptor.ts:25-39`) silently omits the `authorization` metadata (no error, no warning) rather than failing fast, the RPC goes out unauthenticated, the server returns UNAUTHENTICATED (16), and `callWithRefresh` forces a full refresh-and-retry cycle that was unnecessary since the access token was valid all along.
**Fix:** Call `tokenManager.syncFromJar()` after a successful `login()`/`verifyMfa()`, not just after `refresh()`. Since `auth.ts` operates on `AxiamClient`/`client.session` (typed as `SharedSession`, not `NodeSession`), either narrow/duck-type check for a `tokenManager` on the session, or move the sync responsibility to a session-level hook (e.g. an optional `session.onAuthenticated?.()` called from `login`/`verifyMfa` that `NodeSession` implements).

### WR-02: `withRetry`'s `retryAfterMs` hint is dead code — nothing in the SDK ever attaches it to a thrown error

**File:** `sdks/typescript/src/rest/retry.ts:17-23,56-57`, `sdks/typescript/src/core/errorMapper.ts:43-56`, `sdks/typescript/src/core/errors.ts:38-47`
**Issue:** `withRetry`'s doc comment states it "Honors a `retryAfterMs` hint on the thrown error (set by callers that observed a 429 Retry-After header)." `NetworkError` has no `retryAfterMs` field, and `mapHttpStatusToError` never reads/attaches a `Retry-After` response header value anywhere in the codebase. `isRetryAfterCarrier`/the `retryAfterMs` branch in `withRetry` can therefore never be true in practice — it is unreachable, undocumented-as-such dead code that misrepresents the SDK's actual 429-handling behavior (falls back to pure exponential backoff, ignoring any server-provided `Retry-After` hint).
**Fix:** Either implement the documented behavior (parse `Retry-After` in `mapHttpStatusToError` for 429s and attach it to the resulting `NetworkError`), or remove the `retryAfterMs`/`isRetryAfterCarrier` machinery and doc claim until it's actually wired up.

### WR-03: `SKIP_REFRESH` uses substring `.includes()` matching on request URLs, not exact/prefix-with-boundary matching

**File:** `sdks/typescript/src/rest/interceptors.ts:16,63`
**Issue:** `isSkipRefresh = SKIP_REFRESH.some((skipUrl) => url.includes(skipUrl))` will match any URL containing `/api/v1/auth/refresh`, `/api/v1/auth/login`, or `/api/v1/auth/logout` as a substring anywhere — not just as the full path. A future endpoint such as `/api/v1/auth/refresh-token-status` or `/api/v1/auth/login-history` would be incorrectly classified as a refresh-skip endpoint, silently disabling the reactive-refresh-on-401 behavior for it.
**Fix:** Use exact match or a path-boundary check, e.g. `url === skipUrl || url.startsWith(skipUrl + '?')`, or compare against `new URL(url, baseUrl).pathname`.

### WR-04: `extractErrorMessage` fallback (`?? 'login failed'` etc.) is unreachable — function never returns `undefined`/`null`

**File:** `sdks/typescript/src/rest/auth.ts:49-54,81,106,128,148`
**Issue:** `extractErrorMessage` always returns a `string` (either the extracted `message` or the literal `'request failed'`); it never returns `undefined`/`null`. Every call site nonetheless writes `extractErrorMessage(...) ?? 'login failed'` (and similarly for `verifyMfa`/`refresh`/`logout`), which is dead code implying the author intended a different return type (e.g. `string | undefined`) at some point. Harmless today, but misleading and will mask a real bug if `extractErrorMessage` is later changed to actually return `undefined` without re-auditing call sites.
**Fix:** Either change `extractErrorMessage` to return `string | undefined` and drop the generic `'request failed'` fallback (moving that string to each call site's `??`), or simplify call sites to drop the redundant `?? '...'`.

### WR-05: `TokenManager.clear()` does not clear the CSRF-adjacent/refresh-cookie state, and `logout()`'s `session.csrfToken = undefined` in `auth.ts` has no effect on the Node persona (compounds CR-01)

**File:** `sdks/typescript/src/rest/auth.ts:142-157`, `sdks/typescript/src/node/tokenManager.ts:76-79`
**Issue:** `logout()`'s `finally` block sets `client.session.authenticated = false` and `client.session.csrfToken = undefined`, but for the Node persona the actual token state lives in `NodeSession.tokenManager` (`#cachedAccess`) and the `tough-cookie` jar — neither is cleared by `logout()`. `TokenManager.clear()` exists and clears `#cachedAccess`, but nothing calls it from `logout()`. Combined with CR-01 (csrfToken is already always `undefined` in Node), this means a Node client that calls `logout()` still has a stale cached access token in `TokenManager` and stale cookies in the jar (the jar isn't cleared either), so a subsequent gRPC call could still present a stale-but-not-yet-expired cached bearer token after "logout."
**Fix:** Have `logout()` (or a session-level hook it calls) also invoke `client.session.tokenManager?.clear()` and clear/reset the cookie jar for Node sessions.

## Info

### IN-01: `README`/doc comment vs. reality — `csrfHeaderForMethod`'s Node branch comment implies a working mechanism that doesn't exist (compounds CR-01)

**File:** `sdks/typescript/src/rest/interceptors.ts:24-27`
**Issue:** The doc comment states "Node: reads the session's csrfToken store, populated by the Node persona's cookie-jar read (17-03)" — describing intended behavior that was never implemented (see CR-01). This is misleading to future maintainers who may read the comment and assume the mechanism works.
**Fix:** Fix alongside CR-01; update/remove the comment once the sync is implemented, or fix the comment now to flag it as a known gap if CR-01 isn't fixed immediately.

### IN-02: `@types/amqplib@^0.10.0` devDependency does not match `amqplib@^2.0.0` runtime dependency's major version

**File:** `sdks/typescript/package.json:92-93,112`
**Issue:** `amqplib` runtime dependency is pinned to `^2.0.0` (a real, recently-published major version per the npm registry) but `@types/amqplib` devDependency is pinned to `^0.10.0`, a type-definitions version tracking the older `0.x` amqplib API. This can produce silently-wrong type checking (missing new v2 APIs / incorrect signatures for existing ones) since DefinitelyTyped versioning for `amqplib` doesn't necessarily track 1:1 with amqplib's own versioning, but `0.10.x` types are very unlikely to accurately describe a `2.x` runtime.
**Fix:** Verify TypeScript compiles cleanly against the actual `amqplib@2.x` shipped type declarations (amqplib 2.x ships its own `.d.ts` per its changelog in some versions) and either drop the `@types/amqplib` devDependency if amqplib now self-types, or bump it to a version compatible with v2.

### IN-03: `maybeBuildHttpsAgent`'s `require('node:https')` inside a CAPABILITY guard silently swallows the case where `process` exists but `require` doesn't (pure ESM Node without a CJS shim)

**File:** `sdks/typescript/src/rest/session.ts:58-76`
**Issue:** The function guards on `typeof process !== 'undefined'` and then unconditionally calls the CJS-only `require('node:https')`. In a build/runtime context where `process` is defined (e.g. some edge/worker runtimes expose partial Node compat globals like `process` for env-var access) but `require` is not (pure ESM, no CJS interop), this would throw a `ReferenceError: require is not defined` instead of failing with the module's own clear error message, or gracefully falling back. This is a narrow edge case but worth hardening given the module's own comment stresses "this branch never executes ... in a browser bundle" — it does not equally guarantee never executing in a non-Node, `process`-polyfilling edge runtime.
**Fix:** Guard on `typeof require !== 'undefined'` as well, or use a dynamic `await import('node:https')` (already the pattern used for `jose` in `node/jwks.ts` to solve an analogous ESM-interop problem) instead of `require`.

### IN-04: `verifyAndDispatch`'s security-event log omits the parsed message-type context beyond `tenant_id`, weakening operational triage for AMQP verification failures

**File:** `sdks/typescript/src/amqp/consumer.ts:101-116`
**Issue:** On HMAC verification failure, the emitted security log includes `timestamp`, `exchange`, `routingKey`, and `tenantId` (if present) but not any indication of message type/correlation id, making it harder to correlate a burst of verification failures with a specific upstream producer or incident without correlating against exchange/routing-key naming conventions alone. Not a defect against the documented contract (which only requires exchange/routing key/tenant, explicitly excluding the signature/key), just a minor operability gap.
**Fix:** Consider including `correlation_id` (present on `AuthzRequest`) when available, since it is not secret and materially aids incident triage.

---

_Reviewed: 2026-07-01T12:54:02Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
