# AXIAM SDK Behavioral Contract

> **Status: normative/binding (D-09)**
>
> This document is the cross-language behavioral contract for all AXIAM SDKs.
> Every SDK implementation (Phases 16–22) MUST conform to §1–§10 in full.
> Each downstream SDK README must state: "This SDK conforms to CONTRACT.md §1–§10."
>
> Vocabulary locked: 2026-06-30 (D-10). Rust (Phase 16) implements this contract; it does not define it.

### Where the SDKs live

Each SDK is its own repository — the AXIAM repository keeps only this contract and
[`openapi.json`](openapi.json), which are the two inputs every SDK builds against:

| Language | Repository |
|----------|------------|
| Rust | [`ilpanich/axiam-rust-sdk`](https://github.com/ilpanich/axiam-rust-sdk) |
| TypeScript | [`ilpanich/axiam-typescript-sdk`](https://github.com/ilpanich/axiam-typescript-sdk) |
| Python | [`ilpanich/axiam-python-sdk`](https://github.com/ilpanich/axiam-python-sdk) |
| Java | [`ilpanich/axiam-java-sdk`](https://github.com/ilpanich/axiam-java-sdk) |
| C# | [`ilpanich/axiam-csharp-sdk`](https://github.com/ilpanich/axiam-csharp-sdk) |
| PHP | [`ilpanich/axiam-php-sdk`](https://github.com/ilpanich/axiam-php-sdk) |
| Go | [`ilpanich/axiam-go-sdk`](https://github.com/ilpanich/axiam-go-sdk) |
| Kotlin | [`ilpanich/axiam-kotlin-sdk`](https://github.com/ilpanich/axiam-kotlin-sdk) |
| Swift | [`ilpanich/axiam-swift-sdk`](https://github.com/ilpanich/axiam-swift-sdk) |
| C | [`ilpanich/axiam-c-sdk`](https://github.com/ilpanich/axiam-c-sdk) |
| C++ | [`ilpanich/axiam-cplusplus-sdk`](https://github.com/ilpanich/axiam-cplusplus-sdk) |

**This file is the source of truth.** A copy is vendored at the root of every SDK repository
(alongside a copy of `openapi.json` and of `proto/`); when this file changes, the copies must
be re-synced. File paths quoted below (`crates/…`, `proto/…`) are relative to the AXIAM
repository; SDK source paths are relative to that SDK's own repository root.

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
| userinfo (gRPC)     | `get_user_info`   | `getUserInfo`             | `get_user_info`     | `getUserInfo`    | `GetUserInfoAsync` | `getUserInfo` | `GetUserInfo`   |

`get_user_info` is a **gRPC-only** operation (added 2026-07, contract 1.3) — see
[§1.1](#§11-grpc-only-operations) for its normative semantics. Unlike every other row in
this map it has no REST form and is implemented only by SDKs that ship a gRPC transport.

**Additional languages (Kotlin, Swift, C, C++ — added 2026-07):** these expose the same
canonical operations with the same `(action, resource[, scope])` argument order. Casing:
**Kotlin** and **Swift** use camelCase (`login`, `verifyMfa`, `refresh`, `logout`,
`checkAccess`, `can`, `batchCheck`); **C++** uses snake_case (`login`, `verify_mfa`,
`refresh`, `logout`, `check_access`, `can`, `batch_check`); **C** uses snake_case with an
`axiam_` prefix on every symbol (`axiam_login`, `axiam_verify_mfa`, `axiam_refresh`,
`axiam_logout`, `axiam_check_access`, `axiam_can`, `axiam_batch_check`). No new
login/auth/authz method names beyond this map and the
[§12](#§12-oidc--sso-relying-party-helpers) OIDC/SSO relying-party map are permitted in these
SDKs either. The
gRPC-only `get_user_info` operation is **deferred** in all four of these SDKs for as long
as they ship no gRPC transport (they already defer gRPC in v1 — see §1.1); when a gRPC
transport is added, the method name is `getUserInfo` (Kotlin/Swift), `get_user_info` (C++),
or `axiam_get_user_info` (C).

**Argument order:** every operation above takes the acted-upon subject before the object it
acts on — concretely, `check_access`/`can` take `(action, resource[, scope])` in every SDK,
with no exception. PHP's `can(action, resource)` (`src/AxiamClient.php` in the PHP SDK repo) was
reversed relative to this rule prior to SDK-Q09 remediation (2026-07); it has been corrected
to match its own `checkAccess(action, resource)` and every other SDK's `can`/`Can`.

**Notes:**
- `can` is an alias for `check_access` targeting browser/UI scenarios; it calls `POST /api/v1/authz/check` via REST (avoids N round-trips when combined with `batch_check` for page-level permission gating).
- `batch_check` calls `POST /api/v1/authz/check/batch` and returns results in the same order as input.
- `get_user_info` calls `axiam.v1.UserInfoService/GetUserInfo` over gRPC (§1.1). It is the only operation in this map without a REST equivalent in the SDK vocabulary.
- No SDK is permitted to expose additional login/auth/authz method names that diverge from this map or from the [§12](#§12-oidc--sso-relying-party-helpers) OIDC/SSO relying-party map, which extends the same locked vocabulary.

### §1.1 gRPC-only operations

`get_user_info` is the first operation whose SDK surface is served **only over gRPC**. It is
the low-latency counterpart of the server's REST `GET /oauth2/userinfo` endpoint and mirrors
Zitadel's `zitadel.auth.v1.AuthService/GetMyUser`. The following semantics are **normative and
identical in every SDK that implements it**:

1. **Transport.** Invokes `axiam.v1.UserInfoService/GetUserInfo` (proto in the vendored
   `proto/axiam/v1/userinfo.proto`) on the same gRPC channel the SDK already builds. The
   request message is empty; identity is derived entirely server-side from the bearer token.
2. **Metadata.** The call carries `authorization: Bearer <current access token>` and the
   `x-tenant-id` metadata key on every outgoing RPC (the §5 rule already mandates `x-tenant-id`
   on all RPCs — this operation is no exception). Reuse the SDK's existing gRPC
   channel/interceptor machinery; do not build a second channel.
3. **Precondition.** Requires a prior successful `login()` (or an explicitly injected token).
   Calling it with no token MUST raise the `AuthenticationError` taxonomy type (§2)
   **client-side, without a wire call**.
4. **Auth-failure / refresh.** A gRPC `UNAUTHENTICATED` response participates in the §9
   single-flight refresh guard exactly like a REST `401` (the §9 text already reads
   "401 (or gRPC `UNAUTHENTICATED`)"). On a successful refresh the SDK retries the RPC once.
5. **Return shape.** A small typed value/record `UserInfo { sub, tenant_id, org_id, email?,
   preferred_username? }`. `sub`, `tenant_id`, and `org_id` are always present; `email` is
   populated only when the access token carries the `email` scope, and `preferred_username`
   only with the `profile` scope (the server gates these exactly as the REST endpoint does).
6. **Deferral / no REST substitution.** An SDK that ships no gRPC transport MUST document
   `get_user_info` as a deferred follow-up in its scope section (same pattern as its existing
   "gRPC transport deferred" carve-out) and MUST NOT silently substitute the REST
   `/oauth2/userinfo` endpoint — that endpoint is intentionally outside the SDK method
   vocabulary (it is exercised only by the protocol-level benchmark scenarios, not by any SDK).

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
| Kotlin     | The canonical name IS a `suspend` function (coroutines). No `*Async` twin; a caller that needs a blocking form uses `runBlocking`. Optional `Deferred`-returning twins are NOT added. | N/A |
| Swift      | The canonical name IS an `async` method (`async`/`await`). No `*Async` twin. | N/A |
| C++        | The canonical name is the (blocking) call form; a language-idiomatic `std::future`-returning twin MAY be offered under a `_async` suffix (`check_access_async`) — accepted per-language exception, mirroring C#/Java suffix-async idiom. | N/A |
| C          | Synchronous canonical calls only (`axiam_*`); no async surface (an optional non-blocking variant, if ever added, takes a completion callback and is out of scope for v1.0). | N/A |

---

## §2 Error Taxonomy

### Error Types

All SDKs MUST expose exactly three error types. Additional sub-types are permitted as language-idiomatic variants of these three, but MUST NOT replace them:

| Error type    | Meaning                                                              |
|---------------|----------------------------------------------------------------------|
| `AuthError`   | Authentication failure: wrong credentials, expired session, MFA failure, 401 on refresh |
| `AuthzError`  | Authorization failure: caller lacks permission for the requested operation |
| `NetworkError`| Transport-level failure: connection refused, timeout, TLS error, DNS failure |

Sub-types added by later sections of this contract:

| Error type          | Meaning                                                        |
|---------------------|----------------------------------------------------------------|
| `OAuthProtocolError`| RFC 6749 protocol error returned by an `/oauth2/*` endpoint as an `OAuth2ErrorResponse` body (`invalid_grant`, `invalid_client`, `invalid_request`, `unsupported_grant_type`, …). A language-idiomatic **sub-type of `AuthError`** (it does not replace it), added for [§12](#§12-oidc--sso-relying-party-helpers). Carries `error` and `error_description` as publicly accessible fields |

### HTTP Status → Error Type Mapping

| HTTP Status | Error Type    | Notes                                         |
|-------------|---------------|-----------------------------------------------|
| 400         | `NetworkError`| Malformed request (SDK programming error)     |
| 400 from `/oauth2/*` with an `OAuth2ErrorResponse` body | `OAuthProtocolError` | RFC 6749 protocol error (e.g. `invalid_grant` from `POST /oauth2/token`). MUST NOT collapse into the generic `400` → `NetworkError` row above ([§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3) |
| 401         | `AuthError`   | Unauthenticated; triggers refresh if tokens present |
| 401 from `/oauth2/*` with an `OAuth2ErrorResponse` body | `OAuthProtocolError` | Client authentication failed at `POST /oauth2/introspect` / `POST /oauth2/revoke`. MUST NOT trigger the §9 single-flight refresh guard |
| 403         | `AuthzError`  | Authenticated but not authorized              |
| 408, 429    | `NetworkError`| Timeout / rate-limited                        |
| 409         | `AuthzError`  | Conflict (resource-level access denied)       |
| 5xx         | `NetworkError`| Server error; SDK should NOT retry auth       |
| Connection error / DNS / TLS | `NetworkError` | Transport-layer failures   |

Where two rows match the same response, the more specific (endpoint- and body-qualified) row
wins.

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
- `OAuthProtocolError`, being an `AuthError` sub-type, MUST satisfy the `AuthError` rule above: its `message` field MUST be present and MUST be `"<error>: <error_description>"`, built from the two `OAuth2ErrorResponse` fields it also exposes individually.
  - Clarified in contract 1.5: the exactness requirement is on the `message` **field/property**.
    A language whose error-*rendering* convention prefixes that field (Go `Error()` →
    `"authentication failed: <message>"`, Rust `Display` via `#[error("authentication failed:
    {message}")]`) MAY keep the prefix in the rendered string, provided the field itself is
    exactly `"<error>: <error_description>"`.
  - Also clarified in contract 1.5: the two individually-exposed field names follow each
    language's **public-API casing** (`error_description` → `errorDescription` /
    `ErrorDescription`). Go exports the first as `ErrorCode` rather than `Error`, because a
    struct field named `Error` would collide with the promoted `Error()` method that satisfies
    the `error` interface; that rename is conformant.
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
| Kotlin   | OkHttp `CookieJar` backed by a per-client `JavaNetCookieJar(CookieManager(...))` |
| Swift    | `URLSession` with a per-instance `HTTPCookieStorage` on its `URLSessionConfiguration` |
| C        | libcurl per-handle in-memory cookie engine (`CURLOPT_COOKIEFILE ""` to enable, share handle per client) |
| C++      | libcurl per-handle cookie engine (as C), or the HTTP library's per-client cookie store |

---

## §5 Tenant & Organization Context Contract

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

### §5.1 Organization Context (required for login and refresh)

**A tenant slug is only unique *within* an organization, so the login and
refresh endpoints require organization context in addition to tenant context.**

All SDKs MUST expose an optional organization identifier alongside the tenant
identifier — `org_slug` (human-readable) or `org_id` (UUID) — settable at client
construction time (mirroring `tenant_slug`/`tenant_id`), and MUST forward it as
follows:

1. **`POST /api/v1/auth/login`** — the request body MUST carry organization
   context: either `org_slug` (paired with `tenant_slug`) or `org_id` (paired
   with `tenant_id`). A login body without any organization identifier is
   rejected by the server with `400 Bad Request` — *"must provide org_id or
   org_slug"*. `LoginRequest` fields: `tenant_id?`, `org_id?`, `tenant_slug?`,
   `org_slug?` (each optional individually; one tenant form **and** one org form
   are required together).
2. **`POST /api/v1/auth/refresh`** — `RefreshRequest` requires **both**
   `tenant_id` and `org_id` as non-optional UUIDs. An SDK constructed with slugs
   MUST resolve the authoritative `tenant_id`/`org_id` UUIDs from the
   access-token claims returned by login (the `tenant_id`/`org_id` JWT claims are
   read best-effort/unverified purely to populate the refresh body, which the
   server re-validates) and emit them on refresh.

```
// Slug form — org + tenant slugs supplied up front
AxiamClient::new(base_url, tenant_slug: "acme", org_slug: "acme")
// UUID form
AxiamClient::new(base_url, tenant_id: uuid, org_id: uuid)
```

Because the organization identifier is only consumed by the login/refresh flow,
it is an **optional** constructor parameter (unlike the tenant identifier):
resource-server / token-verification-only usage (middleware, route guards) that
never calls `login`/`refresh` does not require it. Any SDK example or benchmark
that calls `login` MUST supply organization context; omitting it makes login
fail at runtime.

**Why this matters:** without organization context every `login` call fails with
`400 "must provide org_id or org_slug"` and every `refresh` fails request
deserialization. All AXIAM SDKs expose this field uniformly.

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

### §6.1 Client Certificate Authentication (mTLS)

**Additive to §6; strict server verification stays ON.** AXIAM authenticates IoT devices
and service accounts by **mutual TLS**: the client presents an X.509 identity certificate
(signed by the tenant's organization CA) that the server binds to a service account
(`POST /api/v1/auth/device` — "Authenticate a device via its client certificate (mTLS)").
Every SDK MUST expose an optional way to configure that client identity, and MUST apply it
to **both** the REST and gRPC transports of the same client instance.

Per-language builder/config API (PEM cert chain + PEM private key is the mandatory baseline):

| Language   | Client-certificate API |
|------------|-------------------------|
| Rust       | `AxiamClient::builder().with_client_cert(cert_pem: &[u8], key_pem: &[u8])` |
| TypeScript | `new AxiamClient({ …, clientCert, clientKey })` (PEM strings; Node only, ignored in browser) |
| Python     | `AxiamClient(…, client_cert=cert_pem, client_key=key_pem)` |
| Java       | `AxiamClient.builder(…).clientCertificate(byte[] certPem, byte[] keyPem)` |
| Kotlin     | `AxiamClient.builder(…).clientCertificate(certPem, keyPem)` |
| C#         | `AxiamClientOptions { ClientCertificatePem = …, ClientKeyPem = … }` |
| PHP        | `new AxiamClient(…, clientCert: $certPem, clientKey: $keyPem)` |
| Go         | `axiam.WithClientCertificate(certPEM, keyPEM []byte)` |
| Swift      | `AxiamClient(config: .init(…, clientCertificate: .pem(certificate:privateKey:)))` |
| C          | `axiam_client_config_set_client_cert(cfg, cert_pem, key_pem)` |
| C++        | `AxiamClient::builder().with_client_cert(cert_pem, key_pem)` |

Rules (normative):

1. **Format.** The mandatory input is a PEM certificate chain plus a PEM private key
   (PKCS#8 or PKCS#1). A non-PEM value MUST produce a clear error at construction time,
   consistent with §6's PEM-only rule. A language whose platform TLS stack is natively
   keystore-based (Java/Kotlin `KeyStore`, C#/Swift PKCS#12) MAY *additionally* accept a
   PKCS#12 identity via a clearly-named secondary overload
   (`with_client_identity_pkcs12` / `clientIdentityPkcs12` / `.pkcs12(...)`), but PEM
   cert+key MUST always be accepted.
2. **Strict TLS preserved.** Presenting a client certificate NEVER relaxes server
   verification. The §6 absolute prohibition on any TLS-bypass surface is unchanged; the
   client-cert code path MUST be kept separate from server-verification code so CI
   TLS-bypass lint gates are not tripped.
3. **Key secrecy (§7).** The private key is secret material: it MUST NOT appear in any
   debug/log/display/serialized output and MUST NOT be exposed via a public getter. Where
   the SDK retains it in memory it SHOULD be held behind the language's `Sensitive<T>`
   equivalent (§7).
4. **Both transports.** The configured identity applies to the REST client and to any
   gRPC channel the same `AxiamClient` builds (`reqwest::Identity` / `ClientTlsConfig::identity`,
   `tls.Config.Certificates`, `handler.ClientCertificates` / `SslClientAuthenticationOptions`,
   OkHttp `KeyManager` + `GrpcSslContexts.keyManager`, Guzzle `cert`/`ssl_key`,
   `grpc.ssl_channel_credentials(private_key=, certificate_chain=)`, `URLSession`
   `urlSession(_:didReceive:)` identity challenge, libcurl `CURLOPT_SSLCERT`/`CURLOPT_SSLKEY`).
5. **Optional.** mTLS is opt-in; omitting the client certificate leaves the SDK's default
   bearer-cookie behavior unchanged. An SDK that ships §6.1 states conformance to
   "§1–§10 (including §6.1 mTLS)".

---

## §7 `Sensitive<T>` Requirement

All token-carrying fields in all SDKs MUST suppress the token value from any debug, logging, or display output (T-15-09).

**Required behavior** (restructured in contract 1.5 — see the rationale note below):

1. **Redaction — unconditional MUST.** Debug/logging representations (`Debug`, `Display` in
   Rust; `toString`, JSON serialization in JS/TS; `__repr__`, `__str__` in Python; `toString`
   in Java/Go; `ToString` in C#; `__toString` in PHP) MUST emit a redacted placeholder such as
   `[SENSITIVE]` or `Sensitive<String>`. This covers **every** stringification and
   structured-serialization sink the language offers, including the ones a naive wrapper
   misses: Go `%#v`/`fmt.Formatter`/`MarshalJSON`, Node `util.inspect`, Java and C#
   compiler-generated `record` `toString`, Jackson / `System.Text.Json` /
   `kotlinx.serialization` writers, and PHP `var_dump`/`print_r`/`var_export`. No other
   section of this contract relaxes this rule.
2. **No implicit reachability — MUST.** The raw value MUST NOT be reachable without an
   explicit, named call: no public field or property, no `Deref`/`AsRef`/implicit conversion
   operator, no auto-unboxing accessor, and no inherited structural equality that compares the
   raw value. (A Go named-type conversion — `string(s)` on a `type Sensitive string` — is an
   *explicit* conversion and is accepted as that language's equivalent of calling the
   accessor; it is the shape the Go row below prescribes.)
3. **One explicit accessor — MAY, and RECOMMENDED for §12.** An SDK MAY expose exactly one
   clearly-named public accessor (`expose`, `reveal`, `get_secret_value`, `Expose`, …)
   returning the raw value. Where the SDK implements
   [§12](#§12-oidc--sso-relying-party-helpers) this accessor is RECOMMENDED, because §12 hands
   `access_token`/`refresh_token`/`id_token` to the **calling application** in the
   `/oauth2/token` response body rather than to a `Set-Cookie` jar, and the application must be
   able to read them in order to persist, forward, or later revoke them. An SDK whose accessor
   stays module-private remains conformant to §7 — but the §12 token set it returns is then
   unreadable by its own callers, so it SHOULD widen the accessor. Widening a module-private
   accessor to public is a non-breaking, additive change.
4. **Point-of-use discipline — MUST.** SDK internal code that needs the raw value calls that
   accessor (or a module-private equivalent) explicitly, at the point of use, and MUST NOT pass
   the returned value to any log/trace/serialize sink.

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
| Kotlin     | `value class Sensitive<T>` (or final class); `toString()` returns `"[SENSITIVE]"`, no `data class` auto-`toString` leak |
| Swift      | `struct Sensitive<T>: CustomStringConvertible` whose `description` returns `"[SENSITIVE]"`; not `Encodable` in a way that emits the value |
| C          | Opaque `axiam_sensitive_t` handle; there is no public accessor returning the raw string, and it is never written to logs/`printf` output |
| C++        | `class Sensitive<T>` with `operator<<`/`to_string` returning `"[SENSITIVE]"`; raw value only via a private/friend accessor |

The **C** and **C++** rows keep their "no public accessor" wording deliberately: both SDKs defer
§12 in its entirety ([§12.6](#§126-deferred-sdks-swift-c-c)), so no token material is ever handed
to their callers outside the §4 cookie jar and rule 3 above has nothing to enable there. Should a
later §12 port land in either, rule 3 applies to it unchanged.

**Why §7 reads this way (contract 1.5, non-breaking clarification).** Contract 1.4's §7 said
flatly that "the raw token string MUST NOT be exposed via any public getter API". That was written
when every token lived only in the §1/§4 `httpOnly` cookie jar, where no caller ever needed one.
§12 changed the premise: it returns tokens *to* the caller. Read literally, §7 and §12 were
mutually unsatisfiable, and the eight implementing SDKs resolved it three different ways —
accessor already public (TypeScript `expose()`, Python `SecretStr.get_secret_value()`, PHP
`reveal()`, Go's named-type conversion), accessor widened for §12 (Rust `Sensitive::expose()`
`pub(crate)` → `pub`; C# a new public `Sensitive<T>.Expose()`), or accessor left module-private
(Java package-private `expose()`, Kotlin `internal expose()`). The rules above separate the
non-negotiable half — redaction, rule 1 — from the half §12 legitimately needs — an explicit
accessor, rule 3 — so that all three resolutions are conformant. The point of the wrapper was
never to make reading a token impossible; it is to make *leaking* one require a deliberate,
greppable call.

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

   **Observable requirement (clarified in contract 1.5; not a new obligation).** A burst of N
   concurrent refresh-triggering callers MUST produce exactly **one** refresh wire call, and all
   N callers MUST receive *that one call's* outcome. Merely serializing the N callers behind a
   mutex so that each then issues its **own** refresh call is **not** conformant: AXIAM refresh
   tokens are opaque, server-stored, and **single-use with rotation**, so callers 2..N would
   replay an already-consumed token and fail with `invalid_grant`. "Exactly one in-flight"
   (rule 1) and "result sharing" (rule 2) are two halves of one requirement, not alternatives.
3. **No retry on refresh failure.** A 401 response to the refresh call itself is `AuthError` — the user must re-authenticate. The SDK MUST NOT attempt to refresh again (no retry loop).
4. **Thread/concurrency safety.** The guard MUST be safe across concurrent goroutines (Go), async tasks (Rust/TS/Python), threads (Java/C#/PHP-Swoole).
5. **Mechanism is free; a dedicated guard instance is permitted** (added in contract 1.5).
   Rules 1–4 constrain observable behaviour only. The per-language table below is guidance, not
   a mandate: an own coalescer holding a shared future/promise/`Deferred`/`Task`, a channel
   broadcast, a condition variable publishing a shared result, and a semaphore guarding a cached
   task are all conformant, provided rule 2's observable requirement holds. An operation that
   needs its own guard because the shared guard's API is specialized to a different token
   namespace — e.g. the §1 cookie-session access-token freshness comparison, which is
   meaningless for an OAuth2 `refresh_token` grant — MAY use a **dedicated instance of an
   equally strong mechanism**; it MUST NOT substitute a weaker one. Where an implementation
   composes an operation-specific coalescer *with* the shared guard, a **bounded** (never
   unbounded) wait to acquire the shared guard is permitted, and exhausting that bound MUST
   raise `AuthError` rather than return a stale token set; the specific bound is an
   implementation detail and is deliberately **not** part of this contract.

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
| Kotlin     | `Mutex` (kotlinx.coroutines) guarding a shared `Deferred<TokenPair>`   |
| Swift      | An `actor` serializing refresh, sharing one in-flight `Task<TokenPair, Error>` |
| C          | `pthread_mutex_t` guarding an in-flight flag + condition variable; waiters block until the single refresh completes |
| C++        | `std::mutex` + `std::shared_future<TokenPair>` held under the lock   |

**Test requirement:** Each SDK MUST include a test that fires N (≥5) concurrent requests against
an expired token and asserts exactly 1 refresh call is made. (See Phase 18 success criterion #2
for Go reference.) Clarified in contract 1.5: the test MUST also assert that **all N callers
received that one call's outcome** (rule 2), and the requirement applies **per refresh
operation** — an SDK that ships both the §1 `refresh` and the
[§12](#§12-oidc--sso-relying-party-helpers) `oidc_refresh` needs the test for each, because they
run on different token namespaces and (per rule 5) may use different guard instances.

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
| Ktor / Spring Boot               | Kotlin     | Ktor `Plugin` intercepting `ApplicationCallPipeline` injecting `AxiamUser`; Spring Boot reuses the Java `OncePerRequestFilter` |
| Vapor                            | Swift      | `AsyncMiddleware` (`respond(to:chainingTo:)`) storing `AxiamUser` on `Request.auth` / `Request.storage` |
| Framework-agnostic guard         | C          | `axiam_middleware_authenticate(client, headers, cookies) -> axiam_user_t*`; adapters documented for embedded HTTP servers (CivetWeb) |
| Framework-agnostic guard         | C++        | `AxiamGuard` callable `AxiamUser guard(const Request&)`; adapters documented for Crow / Pistache handlers |

**Interface contract:**
- The middleware/extractor MUST read the `X-Tenant-ID` header (or use the client's configured tenant) to scope the session verification.
- On success, the authenticated user identity (at minimum: `user_id`, `tenant_id`, `roles`) MUST be available from the request context in a framework-idiomatic way.
- The middleware MUST NOT cache session verification results longer than the token's remaining TTL.
- The middleware MUST surface `AuthError` as HTTP 401 and `AuthzError` as HTTP 403 to the end-user with a standardized JSON error body.

---

## §11 Declarative Authorization Helpers

**Requirement level: SHOULD (v1.0).** The helpers in this section are an *additive*
per-endpoint authorization layer built strictly on top of the §10 middleware/route-guard.
An SDK that ships §1–§10 without these helpers remains conformant; an SDK that ships them
states conformance to §1–§11. The helpers MUST NOT duplicate, bypass, or re-implement any
part of the §10 verification path (JWKS, tenant check, §3a CSRF) — they run strictly
*after* it and consume the identity it injected.

### §11.1 Canonical helper vocabulary

Three helpers (two mandatory where an SDK ships §11, one optional), following the §1-style
naming discipline:

| Canonical operation | Requirement | Semantics |
|---------------------|-------------|-----------|
| `require_auth` | SHOULD | Endpoint requires an authenticated AXIAM identity. Pure sugar over the §10 guard for frameworks where the guard is opt-in per route rather than global. 401 on failure. |
| `require_access(action, resource[, scope])` | SHOULD | Endpoint requires the **authenticated caller** to pass an AXIAM authorization check for `action` on a resource resolved from the request. 401 if unauthenticated, 403 if denied. Argument order follows §1: action before resource, always. |
| `require_role(role...)` | MAY | Local check that the verified token's `roles` contain at least one of the given roles. No server round-trip. Cheaper but coarser than `require_access`; documented as NOT a substitute for resource-level checks. 403 on failure. |

Per-language naming map (follows each language's §1 casing convention):

| Canonical | Rust | TypeScript | Python | Java | C# | PHP | Go |
|-----------|------|------------|--------|------|----|----|----|
| require_auth | `#[require_auth]` | `requireAuth(...)` | `require_authenticated_user` (FastAPI, existing) / `@require_auth` (Django) | `@AxiamRequireAuth` | `[Authorize]` (framework-native, documented) | `#[RequireAuth]` | `middleware.RequireAuth(...)` |
| require_access | `#[require_access(...)]` | `requireAccess(...)` / `@RequireAccess()` (NestJS) | `require_access(...)` (FastAPI dep) / `@require_access` (Django) | `@AxiamRequireAccess(...)` | `[AxiamAccess(...)]` | `#[RequireAccess(...)]` | `middleware.RequireAccess(...)` |
| require_role | `#[require_role(...)]` | `requireRole(...)` | `require_role(...)` / `@require_role` | `@AxiamRequireRole(...)` | `[Authorize(Roles = ...)]` (framework-native, documented) | `#[RequireRole(...)]` | `middleware.RequireRole(...)` |

**Additional languages (Kotlin, Swift, C, C++).** Where these SDKs ship the §11 helpers
(SHOULD-level), they follow the same canonical vocabulary and `(action, resource[, scope])`
order: **Kotlin** `@AxiamRequireAuth` / `@AxiamRequireAccess(...)` / `@AxiamRequireRole(...)`
annotations (Spring interceptor / Ktor plugin enforcement); **Swift** `requireAuth` /
`requireAccess(_:resource:)` / `requireRole(_:)` route-middleware factories (Vapor), and
optionally a `@RequireAccess` property-wrapper form; **C++** `AXIAM_REQUIRE_ACCESS(...)`
macro plus a `require_access(action, resolver)` guard functor; **C** `AXIAM_REQUIRE_ACCESS`
macro over an `axiam_require_access(...)` guard function. All compose strictly on top of the
§10 guard exactly as specified in §11.2.

### §11.2 Semantics (normative, identical in all SDKs)

1. **Composition with the §10 guard.** `require_access` runs strictly *after*
   authentication. If no verified identity is present in the request context, the helper
   returns 401 (`authentication_failed`) — it never attempts its own token extraction, so
   the §10 verification path (JWKS, tenant check, CSRF) is never duplicated or bypassed.
2. **Subject propagation.** The check is made for the *request's* authenticated user, not
   for the application's own SDK session: the helper passes
   `subject_id = <authenticated user_id>` to `check_access`/`batch_check`. This matters
   because the app's client typically holds a service-account session; omitting
   `subject_id` would check the service account's permissions instead of the end user's.
3. **Resource resolution.** The resource id is a UUID resolved from the request, in order
   of precedence:
   a. explicit static `resource_id` argument (UUID literal) — for singleton resources;
   b. `resource_param` — the name of a path/route parameter whose value is the UUID;
   c. a language-idiomatic resolver callback (`fn(request) -> Uuid` or equivalent) for
      anything else (body fields, headers, composite lookups).
   A missing or unparseable resource value is a **programming error** surfaced as the
   framework's bad-request response (400), never a silent allow and never a nil/empty-UUID
   fallback.
4. **Scope.** Optional `scope` argument, passed through to `check_access` verbatim.
5. **Error mapping** (extends the §2 taxonomy; same JSON body shape as §10:
   `{ "error": ..., "message": ... }`):
   - unauthenticated → 401 `authentication_failed`
   - check returns `allowed = false`, or server 403 → 403 `authorization_denied`
   - unresolvable resource id → 400 `invalid_request`
   - `NetworkError` while calling the authz endpoint → **fail closed** with 503
     `authz_unavailable` (deny; never allow on transport failure; never retry beyond the
     SDK's existing bounded read-only retry policy)
6. **No decision caching.** Helpers MUST NOT cache allow/deny decisions (consistent with
   §10's TTL rule). Batch/page-level optimization stays the application's job via
   `batch_check`.
7. **Transport.** Helpers call the SDK's existing `check_access` surface (REST by default;
   gRPC where the SDK's dispatcher already prefers it, e.g. PHP). No new transport code.
8. **Redaction.** Deny/error paths MUST NOT log or echo the token, and SHOULD log the
   denied `action` + `resource_id` at debug level only (consistent with §2 rules).
9. **`require_role` is local.** It reads the verified claims already in the request
   context; it never calls the server. Docs in every SDK must state that role names are
   tenant-defined and that `require_access` is the authoritative check.

---

## §12 OIDC / SSO Relying-Party Helpers

**Requirement level: SHOULD (v1.0).** This section adds the *relying-party* (RP) half of the
OIDC/OAuth2 story: the operations a backend application needs in order to offer "Login with
AXIAM" (authorization-code + PKCE against AXIAM's own OIDC provider), to authenticate itself
as a service account (`client_credentials`), to introspect/revoke tokens, and to drive the
server's upstream-IdP federation endpoints. It is **additive to §1**: the nine operations
below are part of the same locked method vocabulary and are subject to the same
"no diverging names" rule. An SDK that ships §1–§11 without these helpers remains conformant;
an SDK that ships them states conformance to §1–§12. Three SDKs defer the whole section —
see [§12.6](#§126-deferred-sdks-swift-c-c).

These helpers MUST be built on the SDK's existing machinery — the §4 cookie jar, the §6/§6.1
TLS configuration, the §7 `Sensitive<T>` wrapper, the §9 single-flight refresh guard, and the
JWKS verifier the §10 middleware already uses. No SDK may fork, duplicate, or re-implement
any of them for §12.

### §12.1 Canonical operation set and endpoint map

Nine canonical operations. Every column below is verified against `openapi.json`; deviating
from a schema name, HTTP method, content type, or parameter location is a contract violation.

| Canonical operation | Wire call | Request (content type / schema) | Success response |
|---------------------|-----------|---------------------------------|------------------|
| `oidc_discover` | `GET /.well-known/openid-configuration` | no body, no query parameters | `200` `OidcDiscoveryDocument` |
| `oidc_begin` | **none — pure local computation, no network I/O** | n/a | `AuthorizationRequest` (SDK type) |
| `oidc_exchange` | `POST /oauth2/token?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse` |
| `oidc_refresh` | `POST /oauth2/token?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse` |
| `login_client_credentials` | `POST /oauth2/token?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse` |
| `introspect` | `POST /oauth2/introspect?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `IntrospectRequest` | `200` `IntrospectionResponse` |
| `revoke` | `POST /oauth2/revoke?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `RevokeRequest` | `200`, **empty body** |
| `sso_start` | `POST /api/v1/auth/federation/oidc/start` | `application/json` / `OidcStartRequest` | `200` `OidcStartResponse` |
| `sso_complete` | `POST /api/v1/auth/federation/oidc/callback` | `application/json` / `OidcPublicCallbackRequest` | `200` `SsoLoginSuccessResponse` + `Set-Cookie` |

Error responses: `400` from `POST /oauth2/token` and `401` from `POST /oauth2/introspect` /
`POST /oauth2/revoke` carry an `OAuth2ErrorResponse` body and map to `OAuthProtocolError`
(§2, [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3).
`GET /oauth2/jwks` (schema `JwksDocument`) is used by [§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange)
rule 2 but is **not** a vocabulary operation — it is reached through the SDK's existing JWKS
verifier, at the `jwks_uri` the discovery document advertises.

**Non-obvious wire details (all normative):**

1. **The token endpoint is form-encoded, not JSON.** `POST /oauth2/token` accepts
   `application/x-www-form-urlencoded` per RFC 6749 §4.1.3. An SDK that posts JSON to it is
   non-conformant.
2. **`tenant_id` is a required *query* parameter, not a body field.** `TokenRequest`,
   `IntrospectRequest`, and `RevokeRequest` have no `tenant_id` property; all three endpoints
   require `?tenant_id=<uuid>` because the client is authenticating *itself* there. The §5
   `X-Tenant-ID` header is still emitted on these requests (§5 rule 2 is unconditional) — the
   header and the query parameter are **not** substitutes for one another.

   **The header and the query parameter may legitimately disagree in form** (documented in
   contract 1.5). §5 rule 2 emits `X-Tenant-ID` carrying whichever identifier the client was
   constructed with, which may be a **slug**, while these three endpoints require a **UUID**
   in `?tenant_id=`. A slug-configured client therefore sends a slug header alongside a UUID
   query parameter on the same request. This is correct and accepted: the `/oauth2/*` handlers
   are public paths that read the tenant **only** from the query parameter
   (`crates/axiam-api-rest/src/handlers/oauth2.rs`, `web::Query<TenantQuery>`) and never
   inspect `X-Tenant-ID`, so the header is inert there. It is still emitted because §5 rule 2
   admits no exceptions and because request logging/tracing relies on it.

   **Consequence — a slug-only client cannot call five of the nine operations.** A client
   constructed with `tenant_slug` and with no prior login to resolve the UUID from cannot call
   `oidc_exchange`, `oidc_refresh`, `login_client_credentials`, `introspect`, or `revoke`: per
   [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 4 the SDK MUST raise
   its taxonomy error client-side rather than send a slug in `tenant_id`. Applications needing
   those five operations SHOULD construct the client in UUID form, or pass `tenant_id`
   explicitly per call. `oidc_discover`, `oidc_begin`, `sso_start`, and `sso_complete` are
   unaffected — the first two touch no tenant-scoped endpoint, and the federation pair carries
   slug forms in its JSON body (§5.1).
3. **Client authentication is `client_secret_post`.** `client_id`/`client_secret` travel in the
   form body. The server documents no HTTP Basic (`client_secret_basic`) alternative, so SDKs
   MUST NOT send an `Authorization: Basic` header to `/oauth2/*`.
4. **`introspect` and `revoke` require confidential-client credentials.** `IntrospectRequest`
   and `RevokeRequest` both mark `token`, `client_id`, and `client_secret` as required
   (non-nullable); `token_type_hint` is optional. A public client cannot call them.
5. **`revoke` returns no body.** Per RFC 7009 the server answers `200` for unknown, expired,
   or already-revoked tokens. `revoke` therefore returns void/`Unit`/`nil` and MUST treat a
   `200` as success — including for a token it has never issued (idempotence is the point of
   RFC 7009), and every implementing SDK MUST carry a test for that idempotent case.

   **Corrected in contract 1.5.** Contract 1.4 added "Only `401` (client authentication failed)
   is an error", which contradicted the §2 `5xx → NetworkError` row and would have turned a
   server failure into a silent success. The rule is: a `200` MUST be success; treating **any
   other `2xx`** as success is permitted and RECOMMENDED (six of the eight implementing SDKs
   accept any 2xx, which is what their HTTP clients report natively); a `5xx` MUST **not** be
   treated as success and remains a `NetworkError` per §2; a `401` carrying an
   `OAuth2ErrorResponse` body is an `OAuthProtocolError` per
   [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3. `revoke`
   returning void does not make a server error a success.
6. **`sso_complete` delivers the session as `Set-Cookie`.** `SsoLoginSuccessResponse` carries
   `user_id`, `session_id`, `expires_in`, and `redirect_uri` and **no token material**; the
   §4 cookie-jar requirement therefore applies verbatim, and an SDK without a persistent
   cookie store silently loses the session.
7. **The federation `nonce` never leaves the server.** `OidcStartResponse` returns
   `authorize_url`, `state`, and `expires_in_secs` only (10-min TTL, single-use `state`,
   D-22). SDKs MUST round-trip `state` unmodified into `sso_complete` and MUST NOT synthesize,
   expect, or validate a nonce on the federation path. [§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange)
   does **not** apply to `sso_start`/`sso_complete` — no ID token is returned to the SDK there.
8. **CSRF.** `/oauth2/*` is unauthenticated, so no `axiam_csrf` cookie exists yet on a first
   call; §3 step 3 already governs this — omit the `X-CSRF-Token` header rather than inventing
   a value.

**SDK-side types.** These are the type names every SDK exposes (per-language casing applies to
type names as it does to methods); the wire schema each one deserializes is named in
parentheses. Where an SDK type name differs from the OpenAPI schema name, the SDK name below is
authoritative for the public surface:

| SDK type | Wire schema | Fields |
|----------|-------------|--------|
| `OidcConfiguration` | `OidcDiscoveryDocument` | `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `revocation_endpoint`, `introspection_endpoint`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`, `scopes_supported`, `token_endpoint_auth_methods_supported`, `claims_supported`, `grant_types_supported` — all required |
| `AuthorizationRequest` | *(local, no wire form)* | `url`, `state`, `nonce`, `code_verifier` |
| `OidcTokenSet` | `TokenResponse` | `access_token`, `token_type`, `expires_in` (required); `scope?`, `refresh_token?`, `id_token?`, `id_claims?` (optional) |
| `IntrospectionResult` | `IntrospectionResponse` | `active` (required); `sub?`, `client_id?`, `scope?`, `token_type?`, `exp?`, `iat?` |
| `OidcStateStore` / `MemoryOidcStateStore` | *(local, optional — rule 1)* | see [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 1 |

`id_claims` is the decoded, **already-validated** ID-token claim set (see
[§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange)). It MUST expose at
minimum `iss`, `sub`, `aud`, `exp`, `iat`, and `nonce` when present, and MUST preserve any
further claims the server sends in a language-idiomatic open map — the ID token's full claim
set is not enumerated by `openapi.json` (the field is typed as an opaque string there), so SDKs
MUST NOT reject unknown claims.

**`AuthorizationRequest` carries no `redirect_uri` — the caller owns it** (documented in
contract 1.5). The four fields above are the complete shape, and all eight implementing SDKs
match it exactly. `oidc_exchange` must nevertheless replay the `redirect_uri` **byte-identically**
(RFC 6749 §4.1.3), so the caller MUST remember it alongside `state`, `nonce`, and `code_verifier`
between `oidc_begin` and `oidc_exchange` — this is a real footgun and is called out here
deliberately. Where an SDK offers the optional `OidcStateStore`
([§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 1), the store **entry**
does carry a `redirect_uri` field and is where every SDK's framework glue parks it. Adding
`redirect_uri` to `AuthorizationRequest` itself is a candidate for a future revision; it is
explicitly *not* part of contract 1.5, because doing so now would change a type all eight SDKs
have already shipped.

**`oidc_begin` inputs and construction (normative).** `oidc_begin` performs **no network I/O**
— it takes an already-fetched `OidcConfiguration` (from `oidc_discover`), the `redirect_uri`, and
the requested scope, and returns `AuthorizationRequest`. **`client_id` is not a per-call
argument** (corrected in contract 1.5 — contract 1.4 listed it here in error): it comes from
client configuration, because [§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange)
rule 4 must compare the ID token's `aud` against the *same* value and two sources could disagree.
All eight implementing SDKs read it from client configuration. When no `client_id` is configured
an SDK MUST fail fast with **no wire call** — either its §2 taxonomy error or its language's
programming-error type is acceptable, since a missing client configuration is a deployment
mistake, not an authentication outcome. Given that, the returned `AuthorizationRequest` is built
as follows:

1. `state` and `nonce` are independently generated from a cryptographically secure RNG, at
   least 16 bytes (128 bits) each — 32 bytes RECOMMENDED — encoded base64url **without**
   padding (RFC 4648 §5; no `=` characters).
2. `code_verifier` is a fresh high-entropy string of 43–128 characters drawn only from the
   RFC 7636 §4.1 unreserved set `[A-Za-z0-9-._~]`. The RECOMMENDED construction is 32 CSPRNG
   bytes encoded base64url without padding (43 characters).
3. `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, without padding, and
   `code_challenge_method` is the literal string `S256`. Every SDK MUST include the RFC 7636
   Appendix B test vector as a unit test.
4. The requested scope MUST contain `openid`; the helper adds it when the caller omits it.
5. `url` is `authorization_endpoint` (taken from the discovery document, never hardcoded) with
   exactly these RFC 3986-percent-encoded query parameters: `response_type=code`, `client_id`,
   `redirect_uri`, `scope` (space-separated), `state`, `nonce`, `code_challenge`,
   `code_challenge_method=S256`. An SDK MAY accept additional caller-supplied query parameters
   but MUST NOT add any of its own beyond these eight.

**Grant-specific `TokenRequest` field sets (normative).**

| Operation | `grant_type` | Additional form fields |
|-----------|--------------|------------------------|
| `oidc_exchange` | `authorization_code` | `code`, `code_verifier`, `redirect_uri`, `client_id`, `client_secret` (confidential clients only) |
| `oidc_refresh` | `refresh_token` | `refresh_token`, `client_id`, `client_secret` (confidential clients only), `scope` (optional) |
| `login_client_credentials` | `client_credentials` | `client_id`, `client_secret`, `scope` (optional) |

An SDK MUST NOT send form fields outside the set listed for the grant it is performing, and
MUST omit (rather than send empty/null) any optional field the caller did not supply.

**`oidc_refresh` vs `refresh`.** `oidc_refresh` operates on an `OidcTokenSet` obtained from
the OAuth2 token endpoint. It is a **distinct operation** from the §1 `refresh`, which drives
the cookie/opaque-token session path at `POST /api/v1/auth/refresh` (§5.1). The two MUST NOT
be merged, aliased, or made to fall back to one another. `oidc_refresh` MUST be governed by a
§9-conformant single-flight guard — including §9 rule 2's observable requirement (one wire call
per burst, that one outcome shared with every concurrent caller) and §9's test requirement in its
own right. Clarified in contract 1.5: §9 rule 5 permits a **dedicated guard instance** for the
OAuth2 token namespace rather than literally reusing the §1 cookie-session guard object, and five
of the eight implementing SDKs deliberately do exactly that because the §1 guard's API is
specialized to comparing the cookie access token's freshness — a comparison with no meaning for a
`refresh_token` grant. The mechanism is free; the observable behaviour is not.

**`login_client_credentials` as a credential source.** After a successful
`login_client_credentials` an SDK MAY adopt the returned `access_token` as the client's bearer
credential exactly as it does for a `login()` result. It requests no `openid` scope and the
response carries no `id_token`.

### §12.2 Per-language naming map

Casing follows the §1 rules unchanged. Twelve languages are covered: the seven columns below
(TypeScript and JavaScript share one column, as in §1) plus Kotlin, Swift, C, and C++ in the
"Additional languages" paragraph that follows.

| Canonical operation | Rust (snake_case) | TypeScript/JS (camelCase) | Python (snake_case) | Java (camelCase) | C# (PascalCase) | PHP (camelCase) | Go (PascalCase) |
|---------------------|-------------------|---------------------------|---------------------|------------------|-----------------|-----------------|-----------------|
| `oidc_discover` | `oidc_discover` | `oidcDiscover` | `oidc_discover` | `oidcDiscover` | `OidcDiscoverAsync` | `oidcDiscover` | `OidcDiscover` |
| `oidc_begin` | `oidc_begin` | `oidcBegin` | `oidc_begin` | `oidcBegin` | `OidcBegin` | `oidcBegin` | `OidcBegin` |
| `oidc_exchange` | `oidc_exchange` | `oidcExchange` | `oidc_exchange` | `oidcExchange` | `OidcExchangeAsync` | `oidcExchange` | `OidcExchange` |
| `oidc_refresh` | `oidc_refresh` | `oidcRefresh` | `oidc_refresh` | `oidcRefresh` | `OidcRefreshAsync` | `oidcRefresh` | `OidcRefresh` |
| `login_client_credentials` | `login_client_credentials` | `loginClientCredentials` | `login_client_credentials` | `loginClientCredentials` | `LoginClientCredentialsAsync` | `loginClientCredentials` | `LoginClientCredentials` |
| `introspect` | `introspect` | `introspect` | `introspect` | `introspect` | `IntrospectAsync` | `introspect` | `Introspect` |
| `revoke` | `revoke` | `revoke` | `revoke` | `revoke` | `RevokeAsync` | `revoke` | `Revoke` |
| `sso_start` | `sso_start` | `ssoStart` | `sso_start` | `ssoStart` | `SsoStartAsync` | `ssoStart` | `SsoStart` |
| `sso_complete` | `sso_complete` | `ssoComplete` | `sso_complete` | `ssoComplete` | `SsoCompleteAsync` | `ssoComplete` | `SsoComplete` |

**C# `Async` suffix (§1 "Async method naming", SDK-Q08).** C# is `*Async`-only (TAP) for every
operation that performs I/O, exactly as it is for `GetUserInfoAsync` in the §1 map. `OidcBegin`
is the **single deliberate exception in this section**: it performs no network I/O (see
[§12.1](#§121-canonical-operation-set-and-endpoint-map)), so it is a synchronous
`OidcBegin` with **no** `Async` suffix. No `OidcBeginAsync` may be added.

**Java.** The canonical camelCase names above are the synchronous surface. Per the §1
"Async method naming" table Java MAY additionally expose `*Async` companion methods on the same
client object (`oidcExchangeAsync`, `oidcRefreshAsync`, …); these are the accepted per-language
exception to the "no additional diverging names" rule and nothing else.

**Python.** The canonical snake_case names above appear on `AxiamClient` (sync) and, as
`async def` twins under the *same* names, on `AsyncAxiamClient`. `async_*`-prefixed names remain
prohibited (SDK-Q08).

**Additional languages (Kotlin, Swift, C, C++).** **Kotlin** implements §12 and uses camelCase
`suspend` functions identical to the TypeScript column (`oidcDiscover`, `oidcBegin`,
`oidcExchange`, `oidcRefresh`, `loginClientCredentials`, `introspect`, `revoke`, `ssoStart`,
`ssoComplete`); no `*Async` twins. **Swift**, **C**, and **C++** defer the whole section
([§12.6](#§126-deferred-sdks-swift-c-c)), but the names are reserved now so a later port cannot
diverge: **Swift** camelCase and **C++** snake_case exactly as the TypeScript and Rust columns
above; **C** snake_case with the mandatory `axiam_` prefix — `axiam_oidc_discover`,
`axiam_oidc_begin`, `axiam_oidc_exchange`, `axiam_oidc_refresh`,
`axiam_login_client_credentials`, `axiam_introspect`, `axiam_revoke`, `axiam_sso_start`,
`axiam_sso_complete`. No login/auth/authz method names beyond this map and the §1 map are
permitted in any SDK.

**Which object hosts the nine methods** (added in contract 1.5 — §12 was previously silent). They
SHOULD live directly on the SDK's existing client type, and do in seven of the eight implementing
SDKs. An SDK MAY instead place them on a separate, additionally-exported host object where a
**packaging constraint** requires it: the TypeScript SDK uses a Node-only `OidcClient` because its
CI forbids `node:crypto` and `jose` from reaching the browser bundle, and §12 has no browser
persona to serve (a browser relying party performs the redirect; it holds no `client_secret` and
never calls `/oauth2/token`). The method **names** in the map above are fixed either way — only the
host is free. An SDK that uses a separate host MUST say so in its README's §12 section, and MUST
NOT split the nine across two hosts.

### §12.3 Cross-cutting rules (normative, identical in all SDKs)

1. **Stateless by default.** `oidc_begin` and `oidc_exchange` MUST NOT store `state`, `nonce`,
   or `code_verifier` inside the SDK, in process-global state, or in any implicit cache. The
   caller owns that storage (typically its own HTTP session) and passes the `nonce` and
   `code_verifier` back into `oidc_exchange` explicitly. Framework integrations MAY offer an
   optional `OidcStateStore` interface with a `MemoryOidcStateStore` reference implementation;
   where offered it MUST have a 10-minute TTL and a **single-use** `consume(state)` operation
   that returns the stored tuple and atomically deletes it (mirroring the server's
   `federation_login_state` semantics). The store MUST be opt-in: the core operations MUST
   remain usable without one. Clarified in contract 1.5: a store **entry** carries `state`,
   `nonce`, `code_verifier` (wrapped per rule 2), and `redirect_uri` — the last because
   `oidc_exchange` must replay it byte-identically and `AuthorizationRequest` does not carry it
   — plus, optionally, a caller-supplied `return_to`. The 10-minute TTL is a **maximum**: a
   constructor-configurable TTL MUST be clamped down to it so no caller can exceed the
   contract, while a shorter TTL (for tests, or a tighter deployment) is honoured. Expiry
   sweeping MUST be **lazy** — performed on write and/or on a size query — and MUST NOT use a
   background timer, thread, or task: a library must not keep its host process alive.
2. **Sensitive wrapping (§7).** `access_token`, `refresh_token`, `id_token`, `client_secret`,
   and `code_verifier` MUST each be held behind the SDK's `Sensitive<T>` equivalent (§7). They
   MUST NOT appear in `Debug`/`toString`/`__repr__`/`ToString`/`String()` output, log records,
   error messages, exception payloads, stack traces, or serialized diagnostics, and MUST NOT be
   reachable through a public getter. `state` and `nonce` are **not** secrets and are exposed
   as plain strings. See [§12.5](#§125-sensitivet-applicability) for the per-language wrapper.
3. **Error taxonomy (§2).** An `OAuth2ErrorResponse` body MUST surface as `OAuthProtocolError`
   — a language-idiomatic sub-type of `AuthError` — carrying `error` and `error_description` as
   publicly accessible fields, with `message` set to `"<error>: <error_description>"`. A `400`
   from `POST /oauth2/token` MUST NOT surface as the generic `NetworkError` the §2 `400` row
   otherwise prescribes, and a `401` from `POST /oauth2/introspect` or `POST /oauth2/revoke`
   MUST NOT enter the §9 single-flight refresh guard (client-credential failure is not a
   session expiry, and retrying cannot help). ID-token validation failures MUST raise
   `AuthError` (or an `AuthError` sub-type) carrying a stable machine-readable reason code —
   `invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`, `invalid_audience`,
   `token_expired`, or `nonce_mismatch` — matching the [§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange)
   rule that failed. Per §2's construction rules, no error raised by this section may embed a
   token, client secret, or code verifier in its message or context fields.

   **The seven reason codes are a closed vocabulary** (clarified in contract 1.5). No SDK may
   add an eighth, so several distinct failures deliberately share one code, and the following
   mappings are normative rather than incidental:
   - `token_expired` is the code for **every** §12.4 rule-5 time failure — a past `exp`, an
     **absent** `exp`, an absent or future `iat`, and a future `nbf` all report `token_expired`.
     (There is no `token_not_yet_valid`, `iat_in_future`, or `missing_exp` code, and contract 1.4
     enumerated three time conditions against a single code without saying so.)
   - `unknown_kid` covers "the JOSE header carries no `kid` at all" as well as "no key matches
     the `kid`", and a JWKS transport failure during the rule-2 re-fetch MAY surface as
     `unknown_kid` rather than `invalid_signature`.
   - `invalid_alg` covers a JOSE header that cannot be parsed or decoded at all, since the
     algorithm cannot then be established.
   - `invalid_signature` is the catch-all for any other verification failure, so no SDK needs to
     invent a code for an unclassified case.

   A future contract revision MAY widen the vocabulary; until then a caller needing finer
   granularity reads the error message, not the code.
4. **Tenant context (§5).** `oidc_exchange`, `oidc_refresh`, `login_client_credentials`,
   `introspect`, and `revoke` all require a `tenant_id` **UUID** for the query parameter. An SDK
   MUST accept it as an explicit argument, and MAY default to the client-level `tenant_id` when
   the client was constructed in UUID form (§5). When no UUID is available — e.g. a client
   constructed with `tenant_slug` only and no prior login to resolve it from — the SDK MUST
   raise its taxonomy error **client-side, without a wire call** (same discipline as §1.1
   rule 3); it MUST NOT send a slug in the `tenant_id` query parameter. `sso_start` carries
   org/tenant context in the `OidcStartRequest` body and follows the §5.1 rules: one tenant form
   (`tenant_id` or `tenant_slug`) **and** one org form (`org_id` or `org_slug`), alongside the
   required `federation_config_id` and `redirect_uri`. `sso_complete` needs neither, because the
   server recovers the full context from the single-use `state` row.
5. **REST `/oauth2/userinfo` stays out of the vocabulary.** §12 adds no userinfo operation. A
   relying party's claims come from the validated ID token (`OidcTokenSet.id_claims`); identity
   lookups against a live session use the gRPC `get_user_info` operation (§1.1). SDKs MUST NOT
   call `GET /oauth2/userinfo`, and MUST NOT substitute it for either — §1.1 rule 6 already
   places that endpoint outside the SDK method vocabulary.
6. **TLS and discovery-cache keying (§6).** Every §12 call goes through the SDK's §6-configured
   transport with strict verification on; §6's absolute prohibition on TLS-bypass surfaces is
   unchanged, and §6.1 client identities apply if configured. The discovery cache MUST be keyed
   on the normalized **scheme + host + port** of the base URL used to fetch the document
   (lowercased scheme and host, default port made explicit), so a document fetched from one
   origin can never be served for another — cross-issuer cache poisoning.

   **Rewritten in contract 1.5** — contract 1.4 said the cache "MUST NOT be keyed on, or shared
   across, tenants", which is self-contradictory (not keying on the tenant *is* sharing across
   tenants). The rule is:
   - The cache MUST NOT be keyed on the tenant, and sharing one document across tenants of the
     same origin is **correct and intended**: the discovery document is a per-origin protocol
     artifact and carries no tenant-specific content. (JWKS likewise: it is a single global key
     set, so per-tenant JWKS caches MUST NOT be built.)
   - The cache MUST NOT serve a document fetched from one origin to a request against another.
     A **per-client-instance** cache satisfies this by construction where the client is bound to
     a single base URL for its lifetime, and four of the eight implementing SDKs rely on exactly
     that invariant rather than on an explicit key; the other four key on the normalized origin
     explicitly. Both are conformant.
   - A **process-global** cache, or any cache shared between clients that may target different
     origins, MUST key on the normalized origin exactly as specified above.

   TTL MUST be at least 5 minutes, MAY be configurable (a smaller configured value MUST be
   raised to the 5-minute floor), and concurrent
   callers MUST share a single in-flight fetch (single-flight, using the same mechanism §9
   prescribes for that language). The document's own `issuer` value is the authoritative issuer
   for [§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange) rule 3; because
   the server derives it from `AuthConfig::oauth2_issuer_url` (falling back to
   `AuthConfig::jwt_issuer`) it may legitimately differ from the base URL behind a proxy, so an
   SDK MUST NOT reject a discovery document on an issuer/base-URL mismatch. Likewise SDKs MUST
   read `jwks_uri` from the document rather than hardcoding `/oauth2/jwks`.

### §12.4 ID-token validation checklist (normative for `oidc_exchange`)

Validation reuses each SDK's existing JWKS verifier (the one the §10 middleware uses — extend
it, never fork it) and follows OIDC Core §3.1.3.7. All seven requirements below MUST be
enforced before `oidc_exchange` returns, and every SDK MUST carry one failing test per
requirement:

1. **Algorithm.** The JOSE header `alg` MUST be exactly `EdDSA`. The value `none` MUST be
   rejected outright, as MUST every other algorithm — including any algorithm the discovery
   document's `id_token_signing_alg_values_supported` might additionally advertise. The `alg`
   MUST be read from the header and checked *before* any signature work; an SDK MUST NOT let
   the token select its own verification algorithm.
2. **Signature.** Verify the Ed25519 signature against the key from `jwks_uri` (schema
   `JwksDocument`) selected by the header's `kid`. On an unknown `kid` the SDK performs **one**
   JWKS re-fetch and then fails — the same rule the §10 middleware already implements. A token
   with no `kid`, or whose `kid` is still unknown after the single re-fetch, MUST be rejected.

   **"One re-fetch" is normative per cooldown window, not per token** (corrected in contract
   1.5). Taken literally against a *warm* JWKS cache, "one re-fetch then fail" is
   unimplementable without defeating the fetch rate-limiting that makes an unknown-`kid` path
   safe in the first place: an attacker who can present arbitrary `kid` values would otherwise
   drive one JWKS fetch per forged token. Every real implementation — the §10 middleware, and
   the libraries the SDKs build on (`jose`'s `createRemoteJWKSet`, Nimbus `RemoteJWKSet`, and the
   hand-rolled equivalents) — therefore enforces a **cooldown window** (30–60 s is typical):
   the first unknown `kid` triggers exactly one re-fetch and opens the window; a further unknown
   `kid` inside that window re-consults the cached set with **no** network call and fails
   immediately. The observable requirements are that an unknown `kid` MUST NOT cause unbounded
   JWKS fetching, MUST NOT be accepted, and MUST cause at most one re-fetch per window. An SDK
   MUST NOT weaken this into "never re-fetch" (key rotation would break) or "always re-fetch"
   (a fetch-amplification vector).
3. **Issuer.** The `iss` claim MUST equal the discovery document's `issuer` by exact string
   comparison — no normalization, no trailing-slash tolerance, no substring or prefix matching.
4. **Audience.** The `aud` claim MUST contain the RP's own `client_id`. When `aud` holds more
   than one audience, an `azp` claim MUST be present and MUST equal that `client_id`.
5. **Time.** `exp` MUST be in the future and `iat` MUST NOT be in the future; `nbf` MUST be
   honored when present. Permitted clock skew is at most 60 seconds in either direction and
   MUST NOT be configurable above that bound (a larger configured value MUST be clamped down,
   not rejected). Clarified in contract 1.5: `exp` and `iat` are both treated as **required** —
   an ID token missing either is rejected — and every failure of this rule reports the single
   reason code `token_expired`, per the closed-vocabulary note in
   [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3.
6. **Nonce.** The `nonce` claim MUST be present and MUST equal, by constant-time comparison,
   the nonce the caller received from `oidc_begin` and passed into `oidc_exchange`. This is
   mandatory for `oidc_exchange` — the helper always requests the `openid` scope, so the server
   always issues a `nonce`. For `oidc_refresh` and `login_client_credentials`, rules 1–5 and 7
   apply to any `id_token` present and rule 6 is skipped (OIDC Core §12.2 does not require a
   `nonce` in a refresh-issued ID token).
7. **All-or-nothing failure.** On failure of *any* rule above, the SDK MUST raise `AuthError`
   with the matching reason code from [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks)
   rule 3 and MUST **discard the entire token set** — the `access_token` and `refresh_token`
   from the same response MUST NOT be returned to the caller, adopted as the client's
   credential, or written to any store. There is no partial success, and no "validation
   disabled" or "skip ID-token checks" option may exist on any public API.

[§12.4](#§124-id-token-validation-checklist-normative-for-oidc_exchange) does not apply to
`sso_start`/`sso_complete`: the federation flow returns the session as `Set-Cookie` and no ID
token reaches the SDK ([§12.1](#§121-canonical-operation-set-and-endpoint-map) note 7).

### §12.5 `Sensitive<T>` applicability

The five fields named in [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks)
rule 2 — `access_token`, `refresh_token`, `id_token`, `client_secret`, `code_verifier` — use
the **same concrete wrapper this contract already specifies per language in §7**; §12 defines
no new mechanism. Concretely: Rust newtype `Sensitive<T>` with custom `Debug`/`Display`;
TypeScript class with a private `#value` and `toString()` returning `"[SENSITIVE]"`; Python
`__repr__`/`__str__` returning `"Sensitive(<redacted>)"`; final Java class with a redacting
`toString()`; C# struct with a `ToString()` override; PHP `__toString()`; Go string type with a
redacting `String()`; Kotlin `value class Sensitive<T>` (never a `data class`, whose generated
`toString` would leak); Swift `struct Sensitive<T>: CustomStringConvertible`; C opaque
`axiam_sensitive_t`; C++ `class Sensitive<T>` with a redacting `operator<<`/`to_string`. See
the §7 table for the authoritative per-language row. Two additions specific to §12:
`code_verifier` is secret **for its whole lifetime**, including while it sits in an
`AuthorizationRequest` returned to the caller and in any `OidcStateStore` entry; and JSON or
other structured serialization of `OidcTokenSet`, `AuthorizationRequest`, or an
`OidcStateStore` entry MUST NOT emit the wrapped values.

### §12.6 Deferred SDKs (Swift, C, C++)

`axiam-swift-sdk`, `axiam-c-sdk`, and `axiam-cplusplus-sdk` **defer §12 in its entirety**, with
the same carve-out discipline §1/§1.1 already applies to their `get_user_info`/gRPC deferral.
These are device- and IoT-oriented SDKs: the Swift SDK ships NIOSSL specifically for client-cert
mTLS, and the C/C++ SDKs target embedded consumers. The browser-redirect relying-party flow has
no natural home in any of them, and their authentication story — §6.1 mTLS, password login,
service credentials — is already complete without it.

Accordingly, each of these three SDKs MUST document §12 as a deferred follow-up in its scope
section (same wording pattern as its existing "gRPC transport deferred" carve-out), MUST NOT
partially implement the vocabulary, and MUST NOT substitute a hand-rolled OAuth2 flow for it.
Their conformance statement stays at "§1–§10" (or "§1–§11" where the §11 helpers ship) and MUST
NOT claim §12. If a later port lands, it MUST use the reserved names already fixed in
[§12.2](#§122-per-language-naming-map) and MUST satisfy §12.1–§12.5 unchanged. Two follow-up
decisions are recorded as open rather than resolved here: a server-side-Swift (Vapor) port
cloned from the Kotlin shape, and adding `login_client_credentials` alone to C/C++ for
machine-to-machine use.

---

## Closing Notes

### Conformance Statement

Each downstream SDK README (Phases 16–22) MUST include the following statement:

> "This SDK conforms to CONTRACT.md §1–§10."

An SDK that additionally ships the §11 declarative authorization helpers updates its
statement to:

> "This SDK conforms to CONTRACT.md §1–§11."

An SDK that additionally ships the §12 OIDC/SSO relying-party helpers updates its statement to:

> "This SDK conforms to CONTRACT.md §1–§12."

The three SDKs that defer §12 ([§12.6](#§126-deferred-sdks-swift-c-c)) keep their existing
statement and MUST NOT claim §12.

Phase acceptance criteria in each SDK plan include: "CONTRACT.md §1–§10 conformance
verified." (and §1–§11 where the §11 helpers are shipped, §1–§12 where the §12 helpers are
shipped).

**Conformance state as of contract 1.5** (2026-07). Eight SDKs implement §12 and state §1–§12;
three defer it and are unchanged:

| SDK | Statement | Notes |
|-----|-----------|-------|
| Rust | §1–§12 | §12 host: existing `AxiamClient` |
| TypeScript | §1–§12 | §12 host: Node-only `OidcClient` (§12.2 packaging carve-out) |
| Python | §1–§12 | nine identical names on `AxiamClient` and `AsyncAxiamClient` |
| Java | §1–§12 | plus the permitted `*Async` companion twins (no `oidcBeginAsync`) |
| Kotlin | §1–§7, §9–§12 | §8 AMQP deferred (pre-existing, documented carve-out); `suspend` functions, no `*Async` twins |
| C# | §1–§12 | `*Async` throughout except the deliberate synchronous `OidcBegin` |
| PHP | §1–§12 | — |
| Go | §1–§12 | — |
| Swift | unchanged (no §12) | [§12.6](#§126-deferred-sdks-swift-c-c) deferral |
| C | unchanged (no §12) | [§12.6](#§126-deferred-sdks-swift-c-c) deferral |
| C++ | unchanged (no §12) | [§12.6](#§126-deferred-sdks-swift-c-c) deferral |

`login_client_credentials` credential adoption is a §12.1 **MAY**: TypeScript, PHP, and Go
implement it as an opt-in flag; Rust, Python, Java, and Kotlin skip it; C# exposes the flag and
throws `NotSupportedException` when it is set. All five positions are conformant — divergence on a
MAY is not a defect.

### C# `Grpc.Tools` Exception

C# is the one documented deviation from the `buf` codegen pipeline. The C# SDK uses `Grpc.Tools` MSBuild integration (via a `<Protobuf Include=... GrpcServices="Client" />` entry in the `.csproj`, pointed at the `proto/` copy vendored in its repo) to generate gRPC client stubs at build time, rather than a `buf generate` plugin entry. This is intentional (D-01 in `15-CONTEXT.md`) and does not affect behavioral conformance with §1–§10. All other SDKs (Rust, TypeScript, Go, Python, Java, PHP) run `buf generate` as their codegen step.

### Breaking Changes Log

No SDK currently ships a dedicated `CHANGELOG.md`; breaking changes to this contract are
recorded here until one exists.

- **2026-07 (§12 cross-SDK conformance review, contract 1.5)** — **non-breaking / clarifying.**
  No new obligations, no signature changes, no vocabulary changes. Contract 1.4's §12 was
  implemented independently in eight SDKs; the cross-SDK review
  (`claude_dev/sdk-oidc-sso-conformance-review.md`) found ten places where the contract text was
  self-contradictory, unimplementable as literally worded, or silent on a point the eight ports
  had to resolve for themselves. This revision makes the contract describe the behaviour the eight
  already share:
  - **§7 restructured** into four numbered rules that separate the unconditional redaction MUST
    (rule 1) from the explicit-accessor MAY (rule 3). §7's flat "the raw token string MUST NOT be
    exposed via any public getter API" and §12's requirement to hand tokens to the caller were
    mutually unsatisfiable; six of the eight SDKs have a publicly reachable accessor and two do
    not, and all eight are now conformant. Redaction is unchanged and non-negotiable. The C/C++
    "no public accessor" rows are unchanged (both defer §12).
  - **§9 gains rule 5** (mechanism is free; a dedicated guard instance for a second token
    namespace is permitted; a bounded wait for a shared guard is permitted and its bound is not
    contract-worthy), and rule 2 now states the observable requirement — one wire call per burst,
    that one outcome shared with all N callers — explicitly, because serialize-without-sharing
    fails against single-use rotating refresh tokens. The §9 test requirement is clarified to
    apply per refresh operation, so `oidc_refresh` needs its own burst test.
  - **§12.1 note 2** documents that a slug `X-Tenant-ID` header legitimately accompanies a UUID
    `?tenant_id=` query parameter (the `/oauth2/*` handlers read only the query parameter), and
    that a slug-only client with no resolved UUID cannot call five of the nine operations.
  - **§12.1 note 5** corrected: a `200` MUST be success, any other `2xx` MAY be, a `5xx` MUST NOT
    be — removing the contradiction with the §2 `5xx → NetworkError` row.
  - **§12.1** now states that `client_id` is **not** a per-call `oidc_begin` argument (it comes
    from client configuration, as all eight SDKs implement it), and documents that
    `AuthorizationRequest` deliberately carries no `redirect_uri` and that the caller must carry
    it between `oidc_begin` and `oidc_exchange`.
  - **§12.1** `oidc_refresh` paragraph: "MUST run under the §9 guard" → "MUST be governed by a
    §9-conformant single-flight guard", pointing at the new §9 rule 5.
  - **§12.2** gains one normative paragraph permitting either host object for the nine methods,
    with the browser-bundle rationale; the method names remain fixed.
  - **§12.3 rule 1** now enumerates the state-store entry fields (including `redirect_uri`),
    states that the 10-minute TTL is a clamped maximum, and requires lazy sweeping with no
    background timer/thread.
  - **§12.3 rule 3** declares the seven ID-token reason codes a **closed** vocabulary and pins
    the many-to-one mappings that follow from it — notably that every rule-5 time failure
    (past `exp`, absent `exp`, absent or future `iat`, future `nbf`) reports `token_expired`.
  - **§12.3 rule 6** rewritten: contract 1.4's "MUST NOT be keyed on, or shared across, tenants"
    was self-contradictory. Sharing one discovery document across tenants of an origin is correct;
    a per-client-instance cache satisfies the origin requirement by construction; a process-global
    or cross-client cache MUST key on the normalized origin.
  - **§12.4 rule 2** corrected: "one JWKS re-fetch then fail" is normative **per cooldown
    window**, not per token — the literal reading is unimplementable on a warm cache without
    creating a fetch-amplification vector.
  - **§12.4 rule 5** states that `exp` and `iat` are both required and that skew above 60 s is
    clamped, not rejected.
  - **§2** construction rules clarify that the `"<error>: <error_description>"` requirement binds
    the `message` *field* (a language may still prefix its rendered form) and that the two
    exposed field names follow per-language casing, with Go's `ErrorCode` rename accepted.
  - **Conformance Statement** gains a per-SDK table for the eight §12 implementers (including
    Kotlin's pre-existing §8 carve-out) and records that `login_client_credentials` credential
    adoption is a MAY on which divergence is legal.

- **2026-07 (§12 OIDC / SSO relying-party helpers, contract 1.4)** — **non-breaking / additive.**
  Added §12 "OIDC / SSO Relying-Party Helpers" (SHOULD-level for v1.0): nine new canonical
  operations — `oidc_discover`, `oidc_begin`, `oidc_exchange`, `oidc_refresh`,
  `login_client_credentials`, `introspect`, `revoke`, `sso_start`, `sso_complete` — with a
  twelve-language naming map (§12.2), six cross-cutting rules (§12.3), the normative ID-token
  validation checklist (§12.4, `EdDSA`-only, S256-only PKCE, all-or-nothing discard), and a
  `Sensitive<T>` applicability note (§12.5). They target the already-shipping server surface
  (`/.well-known/openid-configuration`, `/oauth2/token|introspect|revoke|jwks`,
  `/api/v1/auth/federation/oidc/start|callback`) — no server or `openapi.json` change. The §2
  taxonomy gains one sub-type, `OAuthProtocolError` (an `AuthError` sub-type carrying `error` +
  `error_description`), plus two endpoint-qualified rows in the HTTP-status mapping; the three
  existing top-level error types are unchanged. No existing signature changes. The eight
  backend-capable SDKs (Rust, TypeScript, Python, Java, Kotlin, C#, PHP, Go) add the operations
  and state "§1–§12"; the device-oriented SDKs (Swift, C, C++) document §12 as a deferred
  follow-up and keep their existing statement (§12.6).

- **2026-07 (§1.1 gRPC userinfo, contract 1.3)** — **non-breaking / additive.** Added a new
  canonical operation `get_user_info` (§1 naming map + §1.1 normative semantics), served only
  over gRPC via `axiam.v1.UserInfoService/GetUserInfo` (new `proto/axiam/v1/userinfo.proto`).
  It mirrors the server's REST `/oauth2/userinfo` claim set and OIDC scope gating. No existing
  signature changes. SDKs with a gRPC transport (Rust, TypeScript, Python, Java, C#, PHP, Go)
  add the method; REST-only SDKs (Kotlin, Swift, C, C++) document it as a deferred follow-up.
  SDKs that ship the operation state "§1–§11" conformance unchanged (the new op lives in §1).

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
- **2026-07 (§6.1 client-certificate / mTLS)** — **non-breaking / additive.** Added §6.1
  defining an optional client-identity-certificate API (`with_client_cert(cert_pem, key_pem)`
  and per-language equivalents) applied to both REST and gRPC transports, PEM cert+key as the
  mandatory baseline (PKCS#12 optional where keystore-native). Strict server verification and
  the §6 TLS-bypass prohibition are unchanged; this only lets a client *present* an identity
  for mutual TLS (IoT/service-account auth, `POST /api/v1/auth/device`). SDKs shipping it state
  "§1–§10 (including §6.1 mTLS)".
- **2026-07 (Kotlin, Swift, C, C++ SDKs)** — **non-breaking / additive.** Extended the
  per-language tables (§1 casing + async, §4 cookie-jar, §6.1 mTLS, §7 `Sensitive`, §9
  single-flight, §10 middleware, §11 helpers) to cover four new SDK languages
  (`axiam-kotlin-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk`). No change to
  existing languages' surfaces.
- **2026-07 (§11 declarative authorization helpers)** — **non-breaking / additive.** Added
  §11 "Declarative Authorization Helpers" (SHOULD-level for v1.0): the `require_auth` /
  `require_access(action, resource[, scope])` / `require_role` vocabulary layered on top of
  the §10 guard. Purely additive API — SDKs remain conformant to §1–§10 without it; those
  that ship it state §1–§11 conformance. No existing signature changes; the only new
  client-surface additions are subject-aware check overloads where a language's existing
  `check_access` could not already carry `subject_id` (Java `checkAccess` subjectId
  overload, Go `CheckAccessAs`), both additive alongside the unchanged existing signatures.

### OpenAPI Export Feature Flag

`openapi.json` (kept in this directory, and mirrored into every SDK repo) is generated with `--no-default-features` (SAML endpoints excluded). Both the committed spec and the CI drift gate use identical flags. SDK consumers requiring SAML endpoint documentation should build AXIAM with the `saml` feature enabled and export locally.

---

*Contract version: 1.5 — Phase 15 (sdk-foundation); §11 declarative authorization helpers added 2026-07; §6.1 mTLS client certificates and Kotlin/Swift/C/C++ SDK columns added 2026-07; §1.1 gRPC-only `get_user_info` operation added 2026-07; §12 OIDC/SSO relying-party helpers and the `OAuthProtocolError` taxonomy sub-type added 2026-07; §7 accessor rules, §9 rule 5, and the §12 cross-SDK clarifications from the eight-SDK conformance review added 2026-07*
*Binding since: 2026-06-30*
*Reference: D-09, D-10 in `.planning/phases/15-sdk-foundation/15-CONTEXT.md`*
