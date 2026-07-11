# AXIAM SDK Behavioral Contract

> **Status: normative/binding (D-09)**
>
> This document is the cross-language behavioral contract for all AXIAM SDKs.
> Every SDK implementation (Phases 16–22) MUST conform to §1–§10 in full.
> Each downstream SDK README must state: "This SDK conforms to CONTRACT.md §1–§10."
>
> Vocabulary locked: 2026-06-30 (D-10). Rust (Phase 16) implements this contract; it does not define it.

---

## §1 Method Naming Map

The canonical method vocabulary is locked here (D-10). All SDKs expose these operations;
each language uses its own idiomatic naming convention as shown below.

| Canonical operation | Rust (snake_case) | TypeScript/JS (camelCase) | Python (snake_case) | Java (camelCase) | C# (PascalCase) | PHP (camelCase) | Go (PascalCase) |
|---------------------|-------------------|---------------------------|---------------------|------------------|-----------------|-----------------|-----------------|
| login               | `login`           | `login`                   | `login`             | `login`          | `Login`         | `login`         | `Login`         |
| MFA verification    | `verify_mfa`      | `verifyMfa`               | `verify_mfa`        | `verifyMfa`      | `VerifyMfa`     | `verifyMfa`     | `VerifyMfa`     |
| token refresh       | `refresh`         | `refresh`                 | `refresh`           | `refresh`        | `Refresh`       | `refresh`       | `Refresh`       |
| logout              | `logout`          | `logout`                  | `logout`            | `logout`         | `Logout`        | `logout`        | `Logout`        |
| single access check | `check_access`    | `checkAccess`             | `check_access`      | `checkAccess`    | `CheckAccess`   | `checkAccess`   | `CheckAccess`   |
| browser access alias| `can`             | `can`                     | `can`               | `can`            | `Can`           | `can`           | `Can`           |
| batch access check  | `batch_check`     | `batchCheck`              | `batch_check`       | `batchCheck`     | `BatchCheck`    | `batchCheck`    | `BatchCheck`    |

**Argument order:** every operation above takes the acted-upon subject before the object it
acts on — concretely, `check_access`/`can` take `(action, resource[, scope])` in every SDK,
with no exception. PHP's `can(action, resource)` (`sdks/php/src/AxiamClient.php`) was
reversed relative to this rule prior to SDK-Q09 remediation (2026-07); it has been corrected
to match its own `checkAccess(action, resource)` and every other SDK's `can`/`Can`.

**Notes:**
- `can` is an alias for `check_access` targeting browser/UI scenarios; it calls `POST /api/v1/authz/check` via REST (avoids N round-trips when combined with `batch_check` for page-level permission gating).
- `batch_check` calls `POST /api/v1/authz/check/batch` and returns results in the same order as input.
- No SDK is permitted to expose additional login/auth/authz method names that diverge from this map.

### Async method naming (SDK-Q08)

The canonical names above are what every SDK's **synchronous** (or, for languages with no
sync/async distinction, single) surface exposes. Where a language also offers an async
surface, the following per-language conventions are all accepted — a language MUST NOT mix
approaches within itself, but different languages are not required to converge on one
convention:

| Language   | Accepted async convention                                                                | Notes |
|------------|-------------------------------------------------------------------------------------------|-------|
| Python     | A **separate `AsyncAxiamClient` class** exposing the canonical names (`login`, `verify_mfa`, `refresh`, `logout`, `check_access`, `can`, `batch_check`) as `async def` methods. | Confirmed-breaking (pre-1.0) fix, 2026-07: previously a single `AxiamClient` exposed both the sync methods AND `async_*`-prefixed twins (`async_login`, `async_check_access`, ...) on the same object. `async_*` names are no longer permitted anywhere in the Python SDK's public surface. |
| Java       | The sync method PLUS a same-named class with an **`*Async` suffix companion method** (e.g. `checkAccess`/`checkAccessAsync`) on the same client object. | **Accepted exception** to the "no additional diverging names" rule above — Java idiom favors suffix-async twins on one object (mirrors `CompletableFuture`-returning sibling methods in the broader Java ecosystem, e.g. `java.util.concurrent` conventions). |
| C#         | **`*Async`-only** methods (e.g. `CheckAccessAsync`), per the .NET Task-based Asynchronous Pattern (TAP) — no separate non-`Async` sync method is required to exist alongside it. | **Accepted exception**: TAP is the idiomatic .NET convention; C# is not required to also offer a blocking `CheckAccess`. |
| Rust, TypeScript/JS, Go, PHP | No separate async naming convention — the canonical name IS the (only, or primarily-used) call form for that language's ecosystem (`async fn`/`Promise`-returning function/goroutine-friendly call/Fiber-safe call, respectively, under the same canonical name). | N/A |

---

## §2 Error Taxonomy

### Error Types

All SDKs MUST expose exactly three error types. Additional sub-types are permitted as language-idiomatic variants of these three, but MUST NOT replace them:

| Error type    | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| `AuthError`   | Authentication failure: wrong credentials, expired session, MFA failure, 401 on refresh |
| `AuthzError`  | Authorization failure: caller lacks permission for the requested operation |
| `NetworkError`| Transport-level failure: connection refused, timeout, TLS error, DNS failure |

### HTTP Status → Error Type Mapping

| HTTP Status | Error Type    | Notes                                         |
|-------------|---------------|-----------------------------------------------|
| 400         | `NetworkError`| Malformed request (SDK programming error)     |
| 401         | `AuthError`   | Unauthenticated; triggers refresh if tokens present |
| 403         | `AuthzError`  | Authenticated but not authorized              |
| 408, 429    | `NetworkError`| Timeout / rate-limited                        |
| 409         | `AuthzError`  | Conflict (resource-level access denied)       |
| 5xx         | `NetworkError`| Server error; SDK should NOT retry auth       |
| Connection error / DNS / TLS | `NetworkError` | Transport-layer failures   |

### gRPC Status → Error Type Mapping

| gRPC Status Code          | Error Type    | Notes                                         |
|---------------------------|---------------|-----------------------------------------------|
| `UNAUTHENTICATED` (16)    | `AuthError`   | Triggers single-flight refresh (see §9)       |
| `PERMISSION_DENIED` (7)   | `AuthzError`  | Caller lacks the required permission          |
| `UNAVAILABLE` (14)        | `NetworkError`| Server unreachable                            |
| `DEADLINE_EXCEEDED` (4)   | `NetworkError`| Request timed out                             |
| `INTERNAL` (13)           | `NetworkError`| Server-side error                             |
| `RESOURCE_EXHAUSTED` (8)  | `NetworkError`| Rate-limited by the server                   |

### Error Construction Rules

- `AuthError` MUST carry a `message` field describing the failure.
- `AuthzError` MUST carry a `message` field and SHOULD carry the denied `action` and `resource_id` if available from the response body.
- `NetworkError` MUST carry the underlying OS/transport error as a `cause` (or equivalent chained exception).
- Errors MUST NOT expose raw token strings in their messages, context fields, or stack traces.

---

## §3 CSRF Behavior

All SDKs (browser and non-browser) MUST implement automatic CSRF token forwarding. The
AXIAM server validates CSRF via **cookie double-submit**: it compares the `X-CSRF-Token`
request header against the `axiam_csrf` cookie value directly. The two client shapes below
are both conformant implementations of that single server-side mechanism — pick the one
that matches your SDK's HTTP client model:

**Canonical browser behavior (cookie double-submit):**
1. The browser reads the `axiam_csrf` cookie (via `document.cookie`, since the cookie is
   not `httpOnly`) on each request.
2. On all state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`), echo the cookie value
   as the `X-CSRF-Token` request header.
3. If the `axiam_csrf` cookie is not yet present (no session established), omit the header
   — the server rejects unauthenticated state-changing calls for other reasons first.
4. Do not read the CSRF value from the response header in the browser; read the cookie
   directly. This avoids extra response-header plumbing and matches
   `frontend/src/lib/api.ts`'s proven implementation.

**Non-browser SDKs (Rust, Python, Java, C#, PHP, Go):**
1. On any response from the AXIAM server, capture the `X-CSRF-Token` response header value
   and store it in the client's session state (these SDKs' cookie jars are typically
   `httpOnly`-cookie-opaque or simply do not expose a convenient per-request cookie read,
   so capturing the value the server already echoes back is the idiomatic non-browser path).
2. On all state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`), include the stored
   token as the `X-CSRF-Token` request header.
3. If no CSRF token has been received yet, omit the header (same fallback as the browser
   case above).
4. Non-browser SDKs are subject to the **same server-side enforcement** as browser
   clients — the AXIAM server's CSRF middleware does not distinguish client type; it always
   compares `X-CSRF-Token` against the `axiam_csrf` cookie. The response-header-capture
   pattern above is simply how non-browser SDKs obtain the value to echo back, since they
   are not reading `document.cookie`.

**Implementation note for browser SDKs (TypeScript):** Read the `axiam_csrf` cookie via a
hardcoded (non-dynamic, ReDoS-safe) regex against `document.cookie`, store nothing beyond
that read — no `localStorage`/`sessionStorage` caching of the token value.

### §3a Resource-Server Middleware CSRF (inbound)

Every SDK's resource-server middleware (the component that authenticates requests to the
*consuming application*, not to AXIAM) MUST additionally enforce the cookie double-submit
check locally when — and only when — the credential it accepted was sourced from the
`axiam_access` cookie rather than an `Authorization: Bearer` header, and the request
method is state-changing (anything other than `GET`, `HEAD`, `OPTIONS`). The check: the
`X-CSRF-Token` request header must be present and equal (constant-time comparison) to the
`axiam_csrf` cookie value; reject with 403 on failure.

Bearer-header-authenticated requests are exempt — a cross-site attacker cannot set custom
request headers, so they are not subject to browser-driven CSRF. Cookie-sourced requests
are not exempt: in any same-site deployment where the `axiam_access` cookie reaches the
consuming application, the non-`httpOnly` `axiam_csrf` cookie does too. This clause is
distinct from and independent of §3's client-to-AXIAM-server CSRF forwarding: the
resource-server middleware must not assume the host framework's own CSRF protection is
active (frameworks such as Spring or ASP.NET Core commonly disable it to avoid
double-protecting Bearer clients).

---

## §4 Cookie-Jar Requirement

All non-browser SDKs (Rust, Python, Java, C#, PHP, Go) **MUST** initialize their HTTP client with a persistent in-memory cookie store before making any requests.

**Rationale:** AXIAM delivers access and refresh tokens via `httpOnly` cookies. An HTTP client that does not persist cookies across requests will fail every request after the initial login because the server will not see the session cookie.

Requirements:
- The cookie store MUST persist across all requests made through the same `AxiamClient` instance.
- The cookie store SHOULD be per-client-instance (not process-global), so multiple clients can hold independent sessions.
- The cookie store MUST follow the cookie domain/path/secure attributes set by the server.

Per-language guidance:
| Language | Recommended approach |
|----------|----------------------|
| Rust     | `reqwest::Client` with `cookie_store(true)` builder option |
| Python   | `requests.Session` or `httpx.AsyncClient` with `cookies` parameter |
| Java     | `CookieManager` + `CookieHandler.setDefault()` or per-client store |
| C#       | `HttpClient` with `HttpClientHandler { UseCookies = true, CookieContainer = new() }` |
| PHP      | Guzzle `CookieJar` with `cookies: true` handler option |
| Go       | `http.CookieJar` (e.g. `cookiejar.New(nil)`) assigned to `http.Client.Jar` |

---

## §5 Tenant Context Contract

**`tenant_slug` or `tenant_id` is a non-optional constructor parameter.**

All SDKs MUST:
1. Require either `tenant_slug` (human-readable) or `tenant_id` (UUID) at client construction time. Neither can be deferred or set later.
2. Inject the tenant identifier as the `X-Tenant-ID` HTTP header on **every** outgoing request.
3. For gRPC, inject `x-tenant-id` as a metadata key on every outgoing RPC call.

There is NO default tenant. Constructing an `AxiamClient` without a tenant identifier is a compile-time or runtime error, never a silent behavior.

```
AxiamClient::new(base_url, tenant_slug: "acme")   // tenant_slug form
AxiamClient::new(base_url, tenant_id: uuid)        // tenant_id UUID form
```

**Why this matters:** AXIAM is a multi-tenant system. Omitting the tenant identifier causes every authenticated API call to fail with 400 or 403. Enforcing it at construction time gives a clear, early error.

---

## §6 TLS Policy

**Default: strict TLS verification is ALWAYS on.**

- All SDKs MUST verify the server's TLS certificate against the system trust store by default.
- The ONLY escape hatch is `with_custom_ca(pem: &[u8])` (or language equivalent), which adds a custom CA certificate (PEM-encoded) to the verification chain. This is intended for development environments using self-signed certificates.
- **There is NO `skip_tls_verification()`, `insecure()`, `allow_insecure()`, `disable_tls()`, `verify_peer(false)`, or any other API surface that bypasses TLS verification.** This is an absolute prohibition enforced by §6 of this contract (T-15-08).
- CI lint gates MUST verify no TLS-bypass patterns exist in SDK source trees (e.g. `grep -rn 'InsecureSkipVerify'` for Go).

Per-language builder pattern:
```
// Rust
AxiamClient::builder()
    .with_custom_ca(pem_bytes)
    .build()

// TypeScript
new AxiamClient({ baseUrl, tenantSlug, customCa })

// Go
client.WithCustomCA(pemBytes)

// Python
AxiamClient(base_url, tenant_slug, custom_ca=pem_bytes)
```

The `with_custom_ca` parameter accepts PEM-encoded certificate bytes/string for the issuing CA. It does NOT accept raw DER bytes, PKCS#12, or JKS. If a non-PEM format is passed, the SDK MUST return a clear error at construction time.

---

## §7 `Sensitive<T>` Requirement

All token-carrying fields in all SDKs MUST suppress the token value from any debug, logging, or display output (T-15-09).

**Required behavior:**
- The raw token string MUST NOT be exposed via any public getter API.
- Debug/logging representations (`Debug`, `Display` in Rust; `toString`, JSON serialization in JS/TS; `__repr__`, `__str__` in Python; `toString` in Java/Go; `ToString` in C#; `__toString` in PHP) MUST emit a redacted placeholder such as `[SENSITIVE]` or `Sensitive<String>`.
- SDK internal code THAT NEEDS the raw value accesses it via a crate/module-private method or friend function, not a public API.

Per-language implementation guidance:
| Language   | Mechanism                                                         |
|------------|-------------------------------------------------------------------|
| Rust       | Newtype `Sensitive<T>` with custom `Debug`/`Display` impl        |
| TypeScript | Class with private `#value`; `toString()` returns `"[SENSITIVE]"` |
| Python     | `__repr__` / `__str__` return `"Sensitive(<redacted>)"`          |
| Java       | Final class; `toString()` returns `"[SENSITIVE]"`                |
| C#         | Struct with `ToString()` override returning `"[SENSITIVE]"`      |
| PHP        | `__toString()` returns `"[SENSITIVE]"`                           |
| Go         | String type with `String()` method returning `"[SENSITIVE]"`     |

**The token MUST NOT appear in:**
- Log files (structured or unstructured)
- Error messages
- Stack traces
- Serialized diagnostic output

---

## §8 AMQP HMAC Contract

All SDKs that consume AXIAM AMQP messages (currently: Rust, TypeScript/Node, Go, Python, Java, PHP) MUST implement the following HMAC verification protocol (SEC-022/055, T-15-10):

### Protocol

1. **Signing key**: Each tenant has a per-tenant AMQP signing secret. Obtain it from the AXIAM server via the management API (not hardcoded).
2. **Verification**: When a message arrives with an `hmac_signature` field:
   a. Extract the `hmac_signature` value from the message.
   b. Set `hmac_signature` to `null` (or remove it) in the message body.
   c. Serialize the remaining message body to canonical JSON.
   d. Compute `HMAC-SHA256(secret_key, canonical_json_bytes)`.
   e. Compare the computed hex-encoded HMAC to the received `hmac_signature` using constant-time comparison.
   f. If they match: process the message normally.
   g. If they do NOT match: **nack the message WITHOUT requeue** and emit a security event log entry.
3. **Missing signature**: A message arriving without `hmac_signature` SHOULD be nacked without requeue in strict mode. During rolling deployments, lenient mode (log-and-accept) is permitted as a temporary measure; strict mode MUST be the default.
4. **Security event**: A failed HMAC check MUST be logged as a security event with at minimum: timestamp, exchange, routing key, and tenant context (if available from other message fields). Do NOT log the received or expected HMAC value.

### v2 — Replay Protection (NEW-4, `key_version = 2`) — BREAKING

**As of `CURRENT_KEY_VERSION = 2` the signed body carries two additional
mandatory fields — `nonce` and `issued_at` — that are covered by the HMAC.**
This is a **hard cutover with no grace window**: the AXIAM server **rejects**
(nack, requeue:false) any `AuthzRequest`/`AuditEventMessage` with
`key_version < 2`, a stale/future `issued_at`, or a replayed `nonce`. **Every
producer MUST be upgraded to emit the v2 body BEFORE the enforcing server is
deployed**, or its messages are dropped.

New fields (always emitted — never omitted — so they are inside the signed bytes):

| Field | Type | Position (signed body) | Meaning |
|-------|------|------------------------|---------|
| `nonce` | UUID | immediately AFTER `key_version` | Per-message unique value. The server records `(tenant_id, nonce)` in a durable store; a duplicate within the freshness window is a **replay** and is rejected. Producers MUST use a fresh UUIDv4 per message. |
| `issued_at` | RFC3339 UTC timestamp | immediately AFTER `nonce` | Producer send time. The server rejects the message when `issued_at` is outside **±5 minutes** (`DEFAULT_FRESHNESS_SKEW_SECS = 300`, configurable via `AXIAM__AMQP__REPLAY_SKEW_SECS`) of its own clock. |

**Exact signed field order (the HMAC is computed over these bytes, `hmac_signature` ABSENT):**

- `AuthzRequest`: `correlation_id`, `tenant_id`, `subject_id`, `action`,
  `resource_id`, `scope`(optional, omitted when null), `key_version`,
  `nonce`, `issued_at`.
- `AuditEventMessage`: `tenant_id`, `actor_id`, `actor_type`, `action`,
  `resource_id`(optional), `outcome`, `ip_address`(optional),
  `metadata`(optional), `key_version`, `nonce`, `issued_at`.

**Consumer (SDK) obligations for v2 — hard-cutover parity with the server.**
After a valid HMAC signature, an SDK consumer MUST additionally nack
(requeue:false) when: (a) `key_version < 2`; (b) `issued_at` is outside the
±skew freshness window; (c) the `nonce` has already been seen (SDKs that
persist state SHOULD dedup nonces durably; at minimum reject within the
freshness window). SDKs that re-serialize the received body minus
`hmac_signature` (order-preserving) automatically cover `nonce`/`issued_at`
in the HMAC and need only add these three validation gates plus the optional
DTO fields.

**Canonical reference vectors.** `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`
contains server-produced, byte-exact vectors (master key, derived subkey,
canonical signed JSON, and resulting `hmac_signature`) for both message types.
Every SDK MUST validate its HMAC implementation byte-for-byte against this file.

### Reference Implementation

See `crates/axiam-amqp/src/messages.rs`:
- `sign_payload(key, payload_json)` — HMAC-SHA256 of payload bytes, returns hex string.
- `verify_payload(key, payload_json, signature_hex)` — constant-time comparison via the `hmac` crate's `verify_slice`.
- `is_fresh(issued_at, now, skew)` — the freshness gate (±skew acceptance window).
- `hmac_signature`, `key_version`, `nonce`, `issued_at` fields present on `AuthzRequest` and `AuditEventMessage`.

### Message Types Subject to HMAC Verification

| AMQP Exchange/Queue            | Message Type        | hmac_signature field | Replay-protected (v2) |
|-------------------------------|---------------------|----------------------|-----------------------|
| `axiam.authz.request`          | `AuthzRequest`      | Yes                  | Yes (`nonce`+`issued_at`) |
| `axiam.audit.events`           | `AuditEventMessage` | Yes                  | Yes (`nonce`+`issued_at`) |

`AuthzResponse` and `NotificationEvent` are published by the server and do not carry `hmac_signature` in v1.0.

---

## §9 Single-Flight Refresh Guard

All SDKs that manage token state (access + refresh tokens) MUST implement a single-flight refresh guard to prevent thundering-herd token refresh calls:

1. **Exactly one in-flight refresh at any time.** When a 401 (or gRPC `UNAUTHENTICATED`) response arrives and the client has a valid refresh token, the SDK attempts a token refresh. If a refresh is already in progress, all concurrent 401-triggering requests MUST wait for the existing refresh to complete.
2. **Result sharing.** After the single in-flight refresh resolves (success or failure), all waiting requesters receive the outcome simultaneously:
   - On success: all waiting requests are retried with the new tokens.
   - On failure: all waiting requests fail with `AuthError`.
3. **No retry on refresh failure.** A 401 response to the refresh call itself is `AuthError` — the user must re-authenticate. The SDK MUST NOT attempt to refresh again (no retry loop).
4. **Thread/concurrency safety.** The guard MUST be safe across concurrent goroutines (Go), async tasks (Rust/TS/Python), threads (Java/C#/PHP-Swoole).

Per-language implementation guidance:
| Language   | Mechanism                                                         |
|------------|-------------------------------------------------------------------|
| Rust       | `tokio::sync::OnceCell` or `Mutex<Option<JoinHandle>>`           |
| TypeScript | `Promise` shared via module-level variable; `null` check guard   |
| Python     | `asyncio.Lock` + shared `asyncio.Future`                         |
| Java       | `ReentrantLock` + `CompletableFuture` held in `AtomicReference`  |
| C#         | `SemaphoreSlim(1,1)` + `Task<TokenPair>` stored in field        |
| PHP        | Fiber-safe `Mutex` from `revolt/event-loop` or equivalent        |
| Go         | `sync.Mutex` + single goroutine holding `chan TokenPair`         |

**Test requirement:** Each SDK MUST include a test that fires N (≥5) concurrent requests against an expired token and asserts exactly 1 refresh call is made. (See Phase 18 success criterion #2 for Go reference.)

---

## §10 Middleware / Route-Guard Interface

Each SDK MUST provide a per-framework middleware or route-guard integration that:
1. Extracts the session from incoming requests (cookie or `Authorization: Bearer`).
2. Verifies the session is valid against the AXIAM server (or locally if short-TTL tokens are cached).
3. Injects the authenticated user identity into the request context.
4. Returns the appropriate HTTP error (401 or 403) when verification fails.

Per-framework expectations:

| Framework                        | Language   | Integration mechanism                                              |
|----------------------------------|------------|--------------------------------------------------------------------|
| Actix-Web                        | Rust       | `FromRequest` extractor returning `AxiamUser`; registered on App  |
| Express / Fastify                | TypeScript | `app.use(axiamMiddleware())` / `fastify.addHook('preHandler', ...)` |
| FastAPI                          | Python     | `Depends(require_authenticated_user)` dependency injection         |
| Django                           | Python     | `MIDDLEWARE = [..., 'axiam_sdk.middleware.AxiamAuthMiddleware']`   |
| Spring Boot                      | Java       | `OncePerRequestFilter` subclass registered in `SecurityFilterChain` |
| ASP.NET Core                     | C#         | `app.UseMiddleware<AxiamAuthMiddleware>()` in `Program.cs`         |
| `net/http`                       | Go         | Handler wrapping: `axiamMiddleware(next http.Handler) http.Handler` |
| Laravel / Symfony                | PHP        | `Middleware` (Laravel) / `EventSubscriber` (Symfony)               |

**Interface contract:**
- The middleware/extractor MUST read the `X-Tenant-ID` header (or use the client's configured tenant) to scope the session verification.
- On success, the authenticated user identity (at minimum: `user_id`, `tenant_id`, `roles`) MUST be available from the request context in a framework-idiomatic way.
- The middleware MUST NOT cache session verification results longer than the token's remaining TTL.
- The middleware MUST surface `AuthError` as HTTP 401 and `AuthzError` as HTTP 403 to the end-user with a standardized JSON error body.

---

## Closing Notes

### Conformance Statement

Each downstream SDK README (Phases 16–22) MUST include the following statement:

> "This SDK conforms to CONTRACT.md §1–§10."

Phase acceptance criteria in each SDK plan include: "CONTRACT.md §1–§10 conformance verified."

### C# `Grpc.Tools` Exception

C# is the one documented deviation from the repository-wide `buf` codegen pipeline. The C# SDK uses `Grpc.Tools` MSBuild integration (via `<Protobuf Include="../../proto/**/*.proto" GrpcServices="Client" />` in the `.csproj`) to generate gRPC client stubs at build time, rather than a `buf generate` plugin entry. This is intentional (D-01 in `15-CONTEXT.md`) and does not affect behavioral conformance with §1–§10. All other SDKs (Rust, TypeScript, Go, Python, Java, PHP) run `buf generate` as their codegen step.

### Breaking Changes Log

No SDK currently ships a dedicated `CHANGELOG.md`; breaking changes to this contract are
recorded here until one exists.

- **2026-07 (SDK-Q08/SDK-Q09, pre-1.0)** — confirmed-breaking, made now rather than deferred:
  - PHP: `AxiamClient::can()` argument order reversed from `(resource, action)` to
    `(action, resource)` — matches `checkAccess()` and every other SDK's `can`/`Can` (§1).
  - Python: the `async_*`-prefixed methods (`async_login`, `async_verify_mfa`, `async_refresh`,
    `async_logout`, `async_check_access`, `async_can`, `async_batch_check`) were removed from
    `AxiamClient`. A new `AsyncAxiamClient` class exposes the canonical names (`login`,
    `verify_mfa`, `refresh`, `logout`, `check_access`, `can`, `batch_check`) as `async def`
    methods instead (§1 "Async method naming" table above).
  - Java `*Async` companion methods and C# `*Async`-only (TAP) methods are unaffected —
    formally documented as accepted per-language async conventions (§1).

### OpenAPI Export Feature Flag

`sdks/openapi.json` is generated with `--no-default-features` (SAML endpoints excluded). Both the committed spec and the CI drift gate use identical flags. SDK consumers requiring SAML endpoint documentation should build AXIAM with the `saml` feature enabled and export locally.

---

*Contract version: 1.0 — Phase 15 (sdk-foundation)*
*Binding since: 2026-06-30*
*Reference: D-09, D-10 in `.planning/phases/15-sdk-foundation/15-CONTEXT.md`*
