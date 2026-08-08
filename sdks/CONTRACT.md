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

## §8b AMQP Transport Security (A6)

**Requirement level: MUST**, for every SDK that speaks AMQP directly (Rust,
TypeScript, Go, Python, Java, PHP).

### The layering, stated once

HMAC signing (§8) gives **authenticity and replay protection**. It does not
give **confidentiality**. A signed `AuthzRequest` still names a subject, a
resource and an action in cleartext on the wire; a signed `AuditEventMessage`
still carries the audit record; a signed mail payload still carries the mail.

TLS gives confidentiality. HMAC gives end-to-end authenticity *across broker
hops* — a property TLS cannot provide, because TLS terminates at the broker and
the broker then re-sends. **Both are required in production. Neither
substitutes for the other**, and an SDK that offers one as an alternative to
the other is not conformant.

### Requirements

| # | Rule |
|---|---|
| 1 | An SDK that connects to AMQP **MUST** support `amqps://` URLs (broker TLS port 5671). |
| 2 | It **MUST** support supplying a custom CA bundle, for a privately-issued broker certificate. This is the common case — an in-cluster broker's certificate is not issued by a public CA. |
| 3 | It **SHOULD** support client certificates (mutual TLS toward the broker), and where it does, the certificate and its key **MUST** be required together: half a client identity MUST fail closed rather than connect without the mutual half. |
| 4 | It **MUST NOT** offer a certificate-verification-skip option in a production build, under any name. |
| 5 | It **MUST NOT** fall back to plaintext when a TLS connection fails. A failed `amqps://` connection is an error to surface, not a condition to work around. |
| 6 | HMAC signing (§8) remains mandatory on every message regardless of transport. |

### On rule 4, specifically

A verification-skip switch is the most reliably misused option in TLS. It
appears in a dev compose file, it works, and it travels unchanged into
production, where it turns TLS into an expensive no-op against precisely the
attacker TLS exists to stop. Rule 2 exists so that nobody has a legitimate
reason to want rule 4 relaxed: a custom CA bundle covers the real case (a
self-signed or private-CA broker certificate) without covering the rest.

Where an SDK's underlying AMQP library exposes such a switch, the SDK MUST NOT
surface it. Where a debug-build-only escape hatch is genuinely wanted, it MUST
follow the server's own `DEV_DEFAULT_SIGNING_KEY` pattern — present only in a
debug build, absent from the shipped artifact, and loud when used.

### Required tests, per SDK

- connect over `amqps://` against a broker with a privately-issued certificate,
  using a supplied CA bundle: publish/consume round trip succeeds;
- connect with the **wrong** CA bundle: rejected, with an error naming the
  verification failure;
- a client certificate without its key (and the mirror case): rejected before
  dialling;
- an HMAC-invalid message over TLS is still rejected — rule 6, i.e. TLS does
  not become an excuse to trust the payload.

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
6. **Implementation invariants for "equally strong" (added in contract 1.6; not new
   obligations — these are what rule 2's observable requirement was already implying, made
   explicit because three independently-written SDKs violated one of them in three different
   shapes before this clarification existed).** Whatever mechanism is chosen (rule 5), it MUST
   satisfy all four of the following, stated in mechanism-neutral terms so they apply equally to
   a channel, a future/promise, a condition variable, or a watch/state cell:
   - **(a) Publish-before-vacate.** The shared outcome MUST be made observable to the guard's
     synchronization point *before* the in-flight slot is cleared. There MUST be no reachable
     instant at which a new caller sees "slot empty" while the outcome that just settled has not
     yet been handed to already-waiting callers — that instant is indistinguishable from "no
     refresh has run yet" and lets a new caller start a **second** wire call against an
     already-consumed refresh token. (Found in production as: a Go/Rust implementation that
     cleared its slot immediately, then handed the result to waiters as a second step.)
   - **(b) Occupancy is not liveness.** Any code that needs to know whether a refresh is
     *currently on the wire* — not merely whether the slot happens to be non-empty — MUST test
     for that specifically (e.g., "is the held future/promise still pending," not "is the
     reference non-null"). A slot MAY legitimately hold an already-settled outcome for a brief
     bookkeeping window after rule (a)'s publication and before cleanup; that window MUST NOT be
     misread as "a refresh is in flight" by unrelated logic that shares the same guard (for
     example, an operation requiring mutual exclusion with a live refresh). (Found in production
     as: a bounded-retry mutual-exclusion check that counted a settled-but-uncleared slot as
     "busy" and exhausted its retry budget in microseconds, failing an otherwise-valid unrelated
     operation.)
   - **(c) Only the current owner clears its own slot.** An attempt (leader) that failed,
     completed, or was cancelled MUST clear only the slot entry it itself created — identity- or
     generation-checked, not merely "the slot is non-empty." A lagging attempt unwinding after a
     *newer* attempt has already taken the slot MUST NOT clear that newer attempt's entry.
     (Found in production as: an unconditional clear-on-error path that could wipe a different,
     currently-live refresh's slot, again opening the door to a second concurrent wire call.)
   - **(d) A caller arriving after full settlement gets a fresh refresh.** Once an outcome has
     been published (rule a) and the slot fully vacated (rules b–c), a subsequently arriving
     caller MUST perform its own new refresh attempt, never be handed a previous burst's outcome
     as if it were current. Joining is only for callers whose request predates or coincides with
     a *live* attempt (rule b); it is never for callers arriving after that attempt has already
     concluded.

   These four properties are what "an equally strong mechanism" (rule 5) means in practice; a
   mechanism that satisfies rules 1–4's *stated* behavior on the happy path but admits a window
   violating (a)–(d) under contention is not conformant, even though nothing in rules 1–4's prose
   was literally broken. See the fixes in `axiam-java-sdk`, `axiam-go-sdk`, `axiam-cplusplus-sdk`
   and `axiam-rust-sdk` (2026-07, contract 1.6) for four independent, sanitizer/loop-verified
   implementations of these invariants across four different mechanisms (a shared future behind
   a re-checked liveness test, a channel with corrected publish ordering, a generation-counted
   `shared_future`, and a value-retaining `watch` cell respectively).

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

**Extended in contract 1.6**, to cover rule 6's invariants directly (each was the exact scenario
a production bug survived the pre-1.6 test requirement under):
- A caller whose request lands strictly after a refresh has published its outcome but before the
  slot is fully vacated (rule 6a/6b's bookkeeping window) MUST join that outcome, not trigger a
  second wire call. Assert the wire-call count stays at 1.
- A caller whose request lands strictly after a refresh's slot has been fully vacated MUST
  trigger its own new wire call, not receive the prior burst's outcome. Assert a second wire call
  occurs and that this caller's outcome is that second call's, not the first's.
- Where the guard's owner is identified across concurrent attempts (rule 6c), a failed or
  cancelled attempt MUST NOT clear a different, still-live attempt's slot. Construct the race
  (a lagging failure/cancellation unwinding after a new leader has already been elected) and
  assert the new leader's slot survives it.

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

### §10.1 Minimum local-verification set (normative)

Wherever an SDK verifies an AXIAM access token **locally** — a route guard, a
middleware, a `§10` authenticator, or any helper that turns a token into an
identity without asking the server — it MUST apply **every** rule below. This
section exists because the same defect recurred independently in two SDKs
(`SEC-071`, `SEC-080`): each verified a *different subset* of the token, and
each subset looked complete in isolation. A guard that checks the signature and
stops is not a weaker guard, it is not a guard.

`§10` verification is a **relying-party** control. The server enforces its own
side; these rules are what stops an SDK from accepting something the server
would never have honoured.

| # | Claim | Rule |
|---|---|---|
| 1 | signature | Verify against the org JWKS with `alg` **pinned to EdDSA before key lookup**. `alg: none` and HS-family confusion MUST be rejected without consulting a key. |
| 2 | `exp` | **REQUIRED.** A token with no `exp`, or a non-numeric `exp`, MUST be rejected. An absent `exp` is a *permanent* credential and MUST NOT be treated as "no expiry constraint". |
| 3 | `nbf` | **Honoured when present.** A token whose `nbf` is in the future MUST be rejected. Absent `nbf` is valid. |
| 4 | `tenant_id` | **REQUIRED and asserted.** MUST equal the client's configured tenant. Absent claim, or no configured tenant to compare against, MUST fail closed. The JWKS trust anchor is **organization-wide**, so signature validity alone does not bound a token to a tenant. |
| 5 | `iss` | **Checked when the SDK is configured with an expected issuer**; absent configuration means no check. When configured, a mismatch MUST be rejected. |
| 6 | `aud` | **Checked when the SDK is configured with an expected audience.** When configured, a token whose `aud` does not contain it MUST be rejected. SDKs guarding a user-facing resource server SHOULD expect `axiam:user`; one guarding a **machine-facing** resource server SHOULD expect `axiam:m2m`, which is what *every* service-account token now carries — both the client-credentials grant and the mTLS device path (§12.1). |
| 7 | clock skew | Rules 2 and 3 MAY allow a **small, named, documented** leeway (RECOMMENDED 60 s). It MUST be a named constant, not an inline literal, and MUST NOT be operator-configurable to an unbounded value. |
| 8 | subject of the decision | The guard MUST decide on **the caller's credential and no other**. When that credential fails any rule above, the guard MUST reject. It MUST NOT retry, refresh, or fall back to a *different* credential — in particular not the SDK client's own session — and MUST NOT admit the request under any identity other than the one the caller presented. |

**Rule 8 is about control flow, not claims.** Rules 1–7 ask *"is this token
good?"*; rule 8 asks *"is this the token the decision is about?"*. A guard can
satisfy all seven and still be an authentication bypass if a failed verification
routes into a second, successful one — which is exactly `SEC-085`: the PHP
framework bridges called a local-verify-**or-refresh-fallback** helper, so a
caller with an expired, foreign-tenant or forged token was admitted as the
*application's own* AXIAM principal, typically a service account with more
privilege than the user whose request it replaced.

A reactive-refresh helper of that shape is legitimate — but only for the SDK's
**outbound** calls, where the token being refreshed genuinely is the client's
own. Where an SDK ships both, the two MUST be separate methods, the no-fallback
one MUST be the documented guard entry point, and the fallback one MUST carry an
explicit warning against guard use (the PHP SDK's `verifyLocally()` versus
`verifyLocallyOrFallback()` is the reference spelling).

**Fail-closed is the default for every rule.** A claim that is required and
absent, unparseable, or of the wrong JSON type MUST cause rejection. An SDK MUST
NOT treat "the claim was missing so there was nothing to check" as success —
that is precisely the `SEC-080` defect.

**A raw signature-only primitive MAY be exposed**, for integrators who are
deliberately implementing their own policy, but it MUST NOT be the documented
guard entry point and its name MUST make the omission obvious at the call site
(the C++ SDK's `verify_signature_only_unchecked` is the reference spelling).
The SDK's own guards MUST route through the full set.

**Required negative tests**, per SDK, each asserting rejection: expired token;
token with **no** `exp`; token with a non-numeric `exp`; token whose `nbf` is in
the future; token for a **different tenant**; token with no `tenant_id`; and
`alg: none` plus an HS-signed token bearing an EdDSA key id. Where the SDK
supports issuer/audience configuration, add a mismatch case for each. For rule 8,
where the SDK ships a request guard: a failing caller token MUST still yield 401
**while the client's own session is healthy and verifiable** — a test whose
client session is unusable passes vacuously and does not satisfy this clause.

> **Compatibility note.** Rule 3 (`nbf`) and the required-`exp` half of rule 2
> tighten acceptance in SDKs that previously ignored those claims. A token the
> AXIAM server minted is unaffected — it always carries `exp` and never a future
> `nbf` — but a guard fed tokens from another signer sharing the org JWKS may
> start rejecting what it used to accept. That is the intent, and it MUST be
> called out as a breaking change in each SDK's CHANGELOG.

### §10.2 Revocation posture differs per transport (informative, MUST be documented)

Local verification (§10.1) proves a token was *issued* and has not *expired*. It
cannot prove the session behind it still exists. What closes that gap depends on
which AXIAM transport the request reaches, and the two do not agree:

| Transport | Session revocation re-checked per request? | A revoked session stops working after |
|---|---|---|
| REST | yes | immediately (or the server's session-cache TTL) |
| gRPC, default | **no** | **token expiry — up to 15 minutes** |
| gRPC, `AXIAM__GRPC__STRICT_REVOCATION=true` | yes | immediately (or the server's session-cache TTL) |

The gRPC default is a deliberate latency trade — it is the service-mesh check
surface — not an oversight, and it is measured: the server-side session cache
enforces an event-path revocation in **262 ms** (run 5), with out-of-band
revocation bounded by the cache TTL plus slack.

**SDKs MUST document this in their middleware/route-guard documentation**, in
the integrator's terms rather than AXIAM's: a guard built on `§10` local
verification alone, in front of a gRPC data plane running the default posture,
admits a logged-out user for the remainder of their access token's lifetime. An
integrator who needs sign-out to take effect immediately must either route the
authorization decision through REST or ask their operator to enable strict
revocation.

SDKs MUST NOT try to close this gap client-side (for example by polling session
state before each call). Doing so would put an unbounded per-request cost on
the hot path to work around a decision that is the deployment's to make, and it
would be a *different* staleness window rather than none.

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
9. **Decision reason (B1 — deny-override).** `check_access` and `batch_check`
   responses carry a `reason_code` alongside `allowed`:

   | `reason_code` | Meaning |
   |---|---|
   | `allowed` | an allow grant matched and no deny did |
   | `no_grant` | nothing matched — default deny |
   | `denied_by_rule` | an explicit deny rule matched and overrode any allow |

   **SDKs MUST surface `reason_code` on the result type**, and MUST NOT collapse
   the two refusals into a bare `false`. They mean opposite things to the person
   on the other end: `no_grant` says *ask an admin for access*, `denied_by_rule`
   says *an admin has already decided*. An application that cannot tell them
   apart sends users to raise tickets that will be refused.

   **Middleware behaviour is unchanged.** Both refusals are still 403
   `authorization_denied` — the route guard's job is to stop the request, and it
   stops it identically either way. This clause is about *reporting*, not
   enforcement, and an SDK MUST NOT vary its guard behaviour on `reason_code`.

   A `reason_code` an SDK does not recognise MUST be surfaced verbatim and MUST
   NOT change the allow/deny outcome, which is carried by `allowed` alone. An
   older SDK against a newer server therefore degrades to today's behaviour, and
   a newer SDK against an older server (which omits the field) MUST treat it as
   absent rather than as an error.

   Required tests: an allow, a `no_grant` deny and a `denied_by_rule` deny each
   surface their own reason code; the guard returns 403 for both refusals; an
   unknown reason code does not alter the outcome.
10. **`require_role` is local.** It reads the verified claims already in the request
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

**Two kinds of principal use `login_client_credentials`, and the token differs.**
The `client_id` identifies either an **OAuth2 client** (`oa_…`) or a **service
account** (`sa_…`); the request is byte-identical, so **no SDK code change is
required to support either**. What differs is the token that comes back, which
matters to any SDK that verifies tokens locally (§10.1) or renders an identity:

| | OAuth2 client (`oa_…`) | Service account (`sa_…`) |
|---|---|---|
| `sub` | the `client_id` | the service-account **UUID** |
| `sub_kind` | `oauth2_client` | `service_account` |
| `aud` | `axiam:m2m` | `axiam:m2m` |
| `scope` | requested subset of the client's registered scopes | **none** — a service account registers no scopes, so requesting one is `invalid_scope`; its authorization comes from the roles assigned to it |

Consequences an SDK MUST respect:

1. **`sub` is not portable across the two.** An SDK MUST NOT assume `sub` is a
   `client_id`, nor parse it as a UUID, without first checking `sub_kind`.
2. **A §10 guard fronting a resource server that accepts machine callers MUST be
   configured to expect `axiam:m2m`** (§10.1 rule 6). The default guidance —
   expect `axiam:user` — is for user-facing resource servers and correctly
   rejects *both* kinds of client-credentials token. That rejection is not a bug
   to work around; it is rule 6 doing its job, and the fix is configuration.
3. A service-account token carries **no `scope` claim**, so an SDK MUST NOT
   derive authorization from scope for these callers.

**⚠ Breaking change — a device (mTLS) token is now `axiam:m2m` too.**
`POST /api/v1/auth/device` (§6.1) used to return a token stamped
`aud: axiam:user`, so a certificate-authenticated device passed every
user-facing route guard. It now returns `aud: axiam:m2m`, matching the
client-credentials path above: **both** ways a service account can
authenticate now yield a machine-audience token. The audience finally
describes *what kind of principal holds the token* rather than which endpoint
issued it.

What this means for an SDK:

- **No SDK code change is required.** The device-auth call and its response
  shape are unchanged; only the `aud` claim value differs.
- **A §10 guard fronting a resource server that accepts device callers MUST
  expect `axiam:m2m`** — the same rule-6 consequence as point 2 above, now
  reaching a second class of caller. A guard configured for `axiam:user` will
  reject device tokens, correctly.
- **Server-side, a device token no longer reaches user-facing REST routes.**
  It is accepted on the authorization-check endpoints (`POST
  /api/v1/authz/check` and the batch form), which are the machine-facing
  surface. An SDK whose device flow called any other endpoint with the
  device token must migrate that call deliberately — the previous access was
  implicit, not designed.

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

### §12.7 Logout helpers (B5)

**Requirement level: SHOULD, and only where the SDK already ships §12.** The
RP-side of OIDC RP-Initiated Logout 1.0 and Back-Channel Logout 1.0. An SDK
that ships §12 without these stays conformant to §12; one that ships them
states §12.7 alongside (see [Closing Notes](#conformance-statement)).

Server documentation: [`docs/api/logout.md`](../docs/api/logout.md).

#### §12.7.1 Canonical operation set

Two operations, and they sit on opposite sides of the flow: one builds a URL
for the browser, the other verifies something the *server* pushed to the RP.

| Canonical operation | Wire call | Semantics |
|---|---|---|
| `logout_url` | **none — pure local computation, no network I/O** | Build the `end_session_endpoint` URL to redirect the user agent to. Mirrors `oidc_begin`. |
| `verify_logout_token` | **none — local verification against cached JWKS** | Validate a back-channel logout token the OP POSTed to the RP's own endpoint. Returns the `sid`/`sub` it names. |

`logout_url` takes `(id_token, post_logout_redirect_uri=None, state=None)` and
returns a URL string. The ID token is passed whole and placed in
`id_token_hint`.

**`logout_url` MUST NOT be given an `id_token_hint`-less mode that names the
user some other way.** There is no such parameter on the wire, and an SDK that
invented one (a `sub`, a session cookie value) would be encouraging exactly the
request the server refuses to act on.

#### §12.7.2 `logout_url` rules (normative)

1. **`end_session_endpoint` comes from discovery**, not from string
   concatenation onto the issuer. An SDK that builds `{issuer}/oauth2/end_session`
   works against AXIAM and breaks against any other OP the same code is pointed
   at, which is the whole reason discovery exists.
2. **`state` is the caller's to generate and the caller's to check.** The SDK
   passes it through and MUST NOT invent one, because the value only means
   something to the application that will receive it back.
3. **The SDK MUST NOT pre-validate `post_logout_redirect_uri` against a local
   list.** The allow-list lives in the client's registration, server-side; a
   client-side copy would drift and would reject a URI an operator had just
   registered.
4. **`logout_url` performs no network I/O** (beyond a discovery fetch the SDK
   would cache anyway) and does not clear the SDK client's own session. Whether
   the local session ends is the application's call — a backend that holds a
   service-account session must not lose it because a *user* logged out. An SDK
   MAY offer that as a separate explicit call.

#### §12.7.3 `verify_logout_token` rules (normative)

This is the half that carries security weight: the input arrives unsolicited,
from the network, and instructs the RP to terminate a session. Every check
below is required, and each exists because skipping it has a name:

1. **Signature verified against the OP's JWKS**, through the SDK's existing
   §12.4 verifier. No second key-fetching path.
2. **`iss` matches the configured issuer; `aud` matches this client's
   `client_id`.** A token minted for another RP must not be accepted here.
3. **`events` MUST contain the key
   `http://schemas.openid.net/event/backchannel-logout`**, with an object
   value. This is what distinguishes a logout token from an ID token; an SDK
   that skips it will accept a replayed ID token as a logout instruction.
4. **`nonce` MUST be absent.** Back-Channel Logout 1.0 §2.4 forbids it, and its
   presence is the documented signature of an ID token being replayed. Reject,
   do not ignore.
5. **At least one of `sid` and `sub` MUST be present.** A token naming neither
   identifies nothing.
6. **`exp` MUST be in the future** and `iat` recent (AXIAM issues a 120 s
   lifetime); an SDK SHOULD apply the same freshness tolerance as §13.
7. **`jti` MUST be surfaced so the RP can dedup.** Delivery is at-least-once
   with retry, so a valid token legitimately arrives twice; the SDK MUST NOT
   dedup internally (it has no durable store and would silently drop a real
   second logout after a restart) but MUST make the key available.
8. **Failure is a typed error or `false`, never a partial result**, and the
   error MUST NOT echo the token.

Return type carries `sid`, `sub` and `jti`. **An SDK MUST NOT collapse the
result to a bare boolean**: the RP has to know *which* session to end, and a
verifier that only says "valid" forces the caller to re-parse the token
themselves — with none of the checks above.

**When `sid` is present, the RP MUST end that session only.** Falling back to
"every session for `sub`" when `sid` was supplied is the same over-reach the
server refuses to make, and SDK documentation MUST say so.

#### §12.7.4 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go |
|---|---|---|---|---|---|---|---|---|
| `logout_url` | `logout_url` | `logoutUrl` | `logout_url` | `logoutUrl` | `logoutUrl` | `LogoutUrl` | `logoutUrl` | `LogoutURL` |
| `verify_logout_token` | `verify_logout_token` | `verifyLogoutToken` | `verify_logout_token` | `verifyLogoutToken` | `verifyLogoutToken` | `VerifyLogoutToken` | `verifyLogoutToken` | `VerifyLogoutToken` |

Both are synchronous where the language has the distinction (as `oidc_begin`
is): neither performs network I/O of its own, so C# takes no `Async` suffix
here. The three §12.6 deferrals (Swift, C, C++) defer §12.7 with it.

#### §12.7.5 `Sensitive<T>` applicability

The `id_token` passed to `logout_url` and the raw logout token passed to
`verify_logout_token` are both bearer-shaped and MUST NOT be logged at any
level. They are **not** wrapped in `Sensitive<T>`: `logout_url` embeds the ID
token in a URL the application is about to hand to a browser, and a wrapper
whose whole purpose is to resist stringification is the wrong type for a value
that must be stringified. The returned `sid`/`sub`/`jti` are identifiers, not
credentials, and are not wrapped.

#### §12.7.6 Required tests

`logout_url` uses the discovered `end_session_endpoint` (assert it is not
built by concatenation); `id_token_hint`, `post_logout_redirect_uri` and
`state` are present when supplied and absent when not; a caller-supplied
`state` is passed through unmodified.

`verify_logout_token`: a valid token verifies and surfaces `sid`, `sub` and
`jti`; wrong `aud` rejected; wrong `iss` rejected; bad signature rejected;
expired rejected; **missing `events` key rejected**; **`nonce` present
rejected** (assert with an otherwise-valid ID token, which is the actual
attack); neither `sid` nor `sub` rejected; and the same token verifying twice
does **not** raise — dedup is the RP's job, and an SDK that failed the second
delivery would break a legitimate retry.

---

## §13 Webhook Signature Verification

Every SDK MUST ship a webhook-signature verifier. AXIAM signs each webhook
delivery with a Stripe-style signed timestamp; without an SDK helper every
integrator hand-rolls the HMAC comparison (or skips it), which is the
`T-145` gap this section closes.

### 13.1 The wire format (server side, normative)

The delivery `POST` carries:

| Header | Value |
|---|---|
| `X-Axiam-Timestamp` | unix seconds, decimal ASCII |
| `X-Axiam-Signature` | `t=<unix_seconds>,v1=<hex_lowercase>` |
| `X-Axiam-Event` | event type |
| `X-Axiam-Delivery` | delivery UUID (at-least-once dedup key) |

`v1 = HMAC-SHA256(secret_utf8_bytes, "<timestamp>.<raw_body>")`, hex-encoded
lowercase, where `<timestamp>` is byte-identical to the `t=` field.

### 13.2 Required helper

| SDK | Entry point |
|---|---|
| Rust | `axiam_sdk::webhook::verify_webhook` |
| TypeScript | `verifyWebhook` |
| Python | `axiam_sdk.webhook.verify_webhook` |
| Java | `io.axiam.sdk.webhook.AxiamWebhooks.verify` |
| Kotlin | `io.axiam.sdk.webhook.AxiamWebhooks.verify` |
| C# | `Axiam.Sdk.Webhooks.AxiamWebhooks.Verify` |
| PHP | `Axiam\Sdk\Webhook\AxiamWebhooks::verify` |
| Go | `webhook.Verify` |
| Swift | `AxiamWebhooks.verify` |
| C | `axiam_webhook_verify` |
| C++ | `axiam::webhook::verify` |

Parameters: the plaintext `secret` (wrapped in `Sensitive<T>` per §7 wherever
the SDK has that type), the raw `X-Axiam-Signature` header value, the **raw
request body bytes**, and a freshness `tolerance` defaulting to **300 s**. A
`now` injection seam for tests is required.

### 13.3 Rules

1. **Raw body only.** The helper MUST accept the untouched bytes received off
   the wire. Re-serializing parsed JSON changes key order/whitespace and breaks
   the MAC; every SDK's documentation MUST state this.
2. **Parse `t=` from the signature header**, not from `X-Axiam-Timestamp` —
   only the former is covered by the MAC. If the SDK also reads the separate
   header it MUST require the two to be equal.
3. **A header with no `v1` is a failure.** Unknown keys and future schemes are
   ignored for forward compatibility, but "nothing to verify" MUST NOT be
   treated as success.
4. **Constant-time comparison** over the decoded MAC bytes. Never `==` on hex
   strings, never an early-return byte loop. Failed hex decode fails closed.
5. **Freshness is two-sided.** Reject when `abs(now - t) > tolerance`, so a
   future-dated timestamp is rejected as well as a stale one.
6. **Fail closed and quiet.** Return a typed error or `false`; never surface
   the expected signature in an error message, and never log the secret or the
   computed MAC at any level.
7. **Dedup is the receiver's job.** Document that `X-Axiam-Delivery` is the
   at-least-once dedup key, since a retry replays a valid signature inside the
   freshness window.

### 13.4 Required tests

Valid-and-fresh accepted; tampered body rejected; wrong secret rejected; stale
`t` rejected; future `t` beyond tolerance rejected; malformed header (missing
`v1`, non-numeric `t`, empty) rejected. Plus a cross-SDK pin: compute the MAC
for the shared vector below in test setup and assert the helper accepts it.

```
secret    = "whsec_test_0123456789abcdef"
timestamp = 1785700000
body      = {"event":"user.created","id":"01JQ0000000000000000000000"}
```

---

## §14 Device Authorization Grant (RFC 8628)

**Requirement level: SHOULD (v1.0).** An SDK that ships §14 states conformance to it
alongside whatever else it implements. This section covers the *client* half of the grant —
the device that cannot show a browser. The verification page (`GET /api/v1/device/verify`,
`POST /api/v1/device/decide`) is an authenticated first-party surface and is **out of
scope**: it is the AXIAM console's job, not an SDK's.

Server documentation: [`docs/api/device-flow.md`](../docs/api/device-flow.md).

### §14.1 Canonical operation set and endpoint map

| Canonical operation | Wire call | Request (content type / schema) | Success response |
|---|---|---|---|
| `device_authorize` | `POST /oauth2/device_authorization?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `DeviceAuthorizationRequest` | `200` `DeviceAuthorizationResponse` |
| `device_poll` | `POST /oauth2/token?tenant_id=<uuid>` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse` |
| `device_login` | the two above, composed — see [§14.3](#§143-device_login-the-composed-helper) | — | `200` `TokenResponse` |

`device_authorize` is **unauthenticated**: a device that cannot show a browser also cannot
hold a client secret. SDKs MUST NOT send `client_secret` on it, and MUST NOT refuse to call
it from a client constructed without one.

The §12.1 wire rules apply unchanged: form-encoded bodies, `tenant_id` as a **query**
parameter and never a body field, `X-Tenant-ID` still emitted per §5 rule 2, no HTTP Basic.
A slug-only client therefore cannot call either operation, exactly as for the five §12
operations — same rule, same client-side error, same remedy.

### §14.2 Polling (normative — the part implementations get wrong)

`device_poll` maps the RFC 8628 §3.5 answer table. Every row is a `400` with an
`OAuth2ErrorResponse` body, and only two of the five are terminal:

| `error` | Meaning | SDK behaviour |
|---|---|---|
| `authorization_pending` | user has not decided yet | keep polling at the current interval |
| `slow_down` | polling too fast | **add 5 s to the interval**, then keep polling |
| `expired_token` | the grant's lifetime ran out | terminal — raise |
| `access_denied` | the user refused | terminal — raise, and distinctly from `expired_token` |
| `invalid_grant` | unknown/consumed device code | terminal — raise |

1. **`slow_down` increases the interval permanently, and never resets it.** RFC 8628 §3.5
   requires the increase; an SDK that backs off for one round and returns to the original
   interval will be told to slow down again, forever. The increment is 5 s per occurrence,
   added to the *current* interval.
2. **The initial interval comes from the response, not from a constant.** `interval` is a
   field of `DeviceAuthorizationResponse`; when the server omits it, default to **5 s**
   (RFC 8628 §3.2). An SDK MUST NOT hard-code a faster floor.
3. **The two refusals are distinct errors.** `access_denied` means a human said no;
   `expired_token` means nobody answered. Collapsing them into one error loses the only
   information the device can act on — retry versus stop asking.
4. **Polling stops at `expires_in`.** The SDK MUST NOT poll past the deadline the
   authorization response gave it even if the server has not yet answered `expired_token`;
   the deadline is authoritative and the extra requests are pure load.
5. **These five are not §2 taxonomy errors from the HTTP status.** All arrive as `400`,
   which §2 would map to `ValidationError`. §14 overrides that for this grant: an SDK MUST
   dispatch on the `error` field first. A `400` whose `error` is none of the five falls back
   to the §2 mapping.
6. **`5xx` and transport failures remain §2 `NetworkError`** and are **not** terminal —
   they are retried under the SDK's existing bounded read-only retry policy, then surfaced.
   A server restart mid-flow must not lose a grant the user has already approved.

### §14.3 `device_login` — the composed helper

The one operation applications actually want: start the grant, hand the caller the user code
and verification URI, poll to completion, and adopt the resulting session per the SDK's
existing credential-adoption rule.

Normative shape (naming per each language's §1 convention):

1. Call `device_authorize`.
2. Surface `user_code`, `verification_uri` and `verification_uri_complete` to the caller
   **before** polling begins — via a callback, an emitted event, or a returned handle the
   caller polls itself. An SDK MUST NOT print them to stdout on the caller's behalf, and MUST
   NOT begin polling before the caller has had the chance to display them.
3. Poll per [§14.2](#§142-polling-normative--the-part-implementations-get-wrong) until a
   terminal outcome.
4. On success, **return the token set**. Whether the SDK also adopts it as the client's own
   credential is the **same MAY** as `login_client_credentials` adoption in §12.1, and an SDK
   MUST follow whichever posture it already took there rather than inventing a second one.
   A refresh token issued by this grant is refreshed through `oidc_refresh` and therefore
   through the §9 single-flight guard, exactly like any other.

   *(Errata, contract 1.7 — this rule previously read "adopt the tokens into the client's
   session exactly as `oidc_exchange` does (§12.3)". That instruction was impossible to
   follow: §12.3 rule 1 makes `oidc_exchange` **stateless by default**, so it adopts nothing,
   and no SDK's `oidc_exchange` has ever adopted. An implementer reading the old text would
   have had to pick a behaviour and call it "exactly as `oidc_exchange` does" — the improvised
   per-language divergence this contract exists to prevent.)*

`verification_uri_complete` embeds the user code so a device that *can* render a QR code
does not make the user type anything. SDKs MUST surface it when present and MUST NOT
synthesise it by concatenation when absent — its format is the server's to choose.

### §14.4 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `device_authorize` | `device_authorize` | `deviceAuthorize` | `device_authorize` | `deviceAuthorize` | `deviceAuthorize` | `DeviceAuthorizeAsync` | `deviceAuthorize` | `DeviceAuthorize` | `deviceAuthorize` | `axiam_device_authorize` | `device_authorize` |
| `device_poll` | `device_poll` | `devicePoll` | `device_poll` | `devicePoll` | `devicePoll` | `DevicePollAsync` | `devicePoll` | `DevicePoll` | `devicePoll` | `axiam_device_poll` | `device_poll` |
| `device_login` | `device_login` | `deviceLogin` | `device_login` | `deviceLogin` | `deviceLogin` | `DeviceLoginAsync` | `deviceLogin` | `DeviceLogin` | `deviceLogin` | `axiam_device_login` | `device_login` |

Async-twin rules follow §1: Java/C# add their `*Async` companions, Kotlin uses `suspend`,
Python exposes the same three names on both `AxiamClient` and `AsyncAxiamClient`.

### §14.5 `Sensitive<T>` applicability

`device_code` is a bearer credential for the duration of the grant and MUST be wrapped in
`Sensitive<T>` (§7) wherever the SDK has that type, and MUST NOT appear in logs at any
level. `user_code` is **not** wrapped: it is designed to be read aloud and typed by a human,
and wrapping it would defeat the one thing it exists for. It still MUST NOT be logged —
displaying is the caller's job.

### §14.6 Required tests

Interval honoured from the response; `slow_down` raises the interval and the raised interval
persists across subsequent polls; `authorization_pending` loops rather than raising;
`access_denied` and `expired_token` raise **distinct** errors; polling stops at `expires_in`;
a `500` mid-poll is retried rather than treated as terminal; `device_login` surfaces the user
code before its first poll (assert ordering, not just presence); a successful `device_login`
returns a token set carrying the access token.

An SDK that implements the [§14.3](#§143-device_login--the-composed-helper) rule-4 adoption
MAY additionally assert the client is authenticated afterwards, and an SDK that gates adoption
behind a flag MUST assert both states — adopted when set, untouched when not. An SDK that does
not adopt MUST NOT be read as failing this section. *(Errata, contract 1.7: this test
previously read "a successful `device_login` leaves the client authenticated", which
contradicted the stateless posture §12.3 rule 1 requires of every non-adopting SDK.)*

---

## §15 Token Exchange (RFC 8693)

**Requirement level: SHOULD (v1.0).** For service-to-service calls: a backend holding a
user's access token exchanges it for a *narrower* one before calling the next service.

Server documentation: [`docs/api/token-exchange.md`](../docs/api/token-exchange.md).

**The rule an SDK must not paper over: an exchange only ever narrows.** The server enforces
this; an SDK's job is to not hide the refusals, because every one of them is the server
telling the caller their assumption about their own privileges was wrong.

### §15.1 Canonical operation and endpoint map

| Canonical operation | Wire call | Request (content type / schema) | Success response |
|---|---|---|---|
| `token_exchange` | `POST /oauth2/token?tenant_id=<uuid>` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenExchangeResponse` |

Signature (canonical order; each language's §1 casing applies):

```
token_exchange(subject_token, *, actor_token=None, scopes=None, audience=None, resource=None)
```

`subject_token` is positional and first. Everything else is optional and keyword/named where
the language has that, because four optional strings in positional order is a bug waiting to
be written.

The exchanging client **authenticates** (`client_secret_post`, per §12.1 rule 3) — unlike
§14's device, this is a confidential service. §12.1's `tenant_id`-as-query rule and the
slug-only-client consequence apply unchanged.

### §15.2 Semantics (normative)

1. **`actor_token` selects delegation; its absence selects impersonation.** These are
   different operations with different risk, and an SDK MUST NOT paper over the difference —
   no default actor token, no "helpfully" reusing the client's own session token as the
   actor. If the caller passed no actor token they asked for impersonation, and the server
   will refuse unless the client holds the grant.
2. **Surface `unauthorized_client` verbatim.** It means either "this client may not exchange
   at all" or "this client may not impersonate". Both are registration facts an operator
   must fix; an SDK that retries, downgrades, or reworks the request into a delegation is
   sending a request the caller did not write.
3. **`invalid_scope` is not a hint to retry with fewer scopes.** The server refuses rather
   than silently narrowing precisely so the caller finds out here. An SDK MUST NOT
   auto-narrow and re-send.
4. **No refresh token comes back, ever.** `TokenExchangeResponse` has no `refresh_token`
   field. An SDK MUST NOT synthesise one, MUST NOT feed the result into the §9 single-flight
   refresh guard, and MUST document that re-running the exchange is how you get a fresh
   token.
5. **The exchanged token is not the client's session.** `token_exchange` MUST NOT adopt the
   returned token as the SDK client's own credentials — not even in an SDK whose
   `login_client_credentials` and [§14.3](#§143-device_login--the-composed-helper)
   `device_login` do adopt, and not behind an opt-in flag. This is a MUST NOT where those are
   a MAY. It is a token to *hand onward* in one outbound call; adopting it would
   silently re-privilege every subsequent call the client makes.
6. **`issued_token_type` MUST be surfaced on the result**, not dropped. It is mandatory in
   RFC 8693 §2.2.1 so a client that asked for one type and received another can tell.
7. **`scope` in the response is the granted set, which may be narrower than requested** even
   on success (when `scope` was omitted and the client's registration bounds the subject's
   own). Applications MUST be able to read what they actually got.

### §15.3 Error mapping

Extends §2. As in §14.2 rule 5, dispatch on the `error` field of `OAuth2ErrorResponse`
before falling back to the status-code mapping:

| `error` | Meaning |
|---|---|
| `invalid_request` | malformed, unsupported `subject_token_type`/`requested_token_type`, `audience`/`resource` disagree, or the `act` chain is already at depth 3 |
| `invalid_grant` | subject or actor token invalid, expired, or from another tenant |
| `invalid_scope` | a requested scope the subject does not hold, or an empty intersection |
| `invalid_target` | `audience`/`resource` not registered to this client |
| `unauthorized_client` | client not registered for the grant, or impersonation without the grant |
| `invalid_client` | client authentication failed |

**Cross-tenant answers `invalid_grant`, deliberately.** An SDK MUST NOT try to distinguish
"wrong tenant" from "bad token" or report a guess to the caller — the server collapses them
because telling them apart is a tenant-enumeration signal, and re-deriving the distinction
client-side hands back what the server withheld.

### §15.4 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `token_exchange` | `token_exchange` | `tokenExchange` | `token_exchange` | `tokenExchange` | `tokenExchange` | `TokenExchangeAsync` | `tokenExchange` | `TokenExchange` | `tokenExchange` | `axiam_token_exchange` | `token_exchange` |

### §15.5 `Sensitive<T>` applicability

`subject_token`, `actor_token` and the returned `access_token` are all bearer credentials and
MUST be wrapped in `Sensitive<T>` (§7) wherever the SDK has that type. None may be logged at
any level, including in error paths — an exchange failure is exactly when a naive
implementation logs the request body.

### §15.6 Required tests

A delegation narrows scopes and the result carries the granted set; omitting `scope` inherits
the subject's; an impersonation request without the grant surfaces `unauthorized_client`
unchanged (assert no retry and no request rewriting); `invalid_scope` is not auto-narrowed;
the response carries no refresh token and the client's own session is unchanged after the
call; `issued_token_type` is surfaced; a cross-tenant subject token surfaces `invalid_grant`
with no attempt to refine it.

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

An SDK that additionally ships the §13 webhook-signature verifier updates its statement to:

> "This SDK conforms to CONTRACT.md §1–§13."

An SDK that additionally ships the §12.7 logout helpers states them by name
alongside its §12 claim, e.g.:

> "This SDK conforms to CONTRACT.md §1–§13 and §12.7."

§12.7 is named rather than folded into the §1–§12 range because it landed after
several SDKs had already stated §12: an SDK claiming §1–§12 today means what it
meant when it was written, and silently widening that range would turn a true
statement into a false one without anyone editing it.

§14 (device authorization grant) and §15 (token exchange) are **independent** SHOULD-level
sections, not a continuation of the §1–§13 run: an SDK may ship either, both, or neither.
Because of that, they are stated by name rather than by extending the range — an SDK that
ships both writes:

> "This SDK conforms to CONTRACT.md §1–§13, §14 and §15."

and one that ships only the device grant names only §14. Writing "§1–§15" would claim the
other section by implication, which is the failure mode a range invites.

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

- **2026-07 (§9 single-flight guard invariant clarification, contract 1.6)** —
  **non-breaking / clarifying.** No new obligations, no signature changes, no vocabulary
  changes — this states, precisely, what rule 2's pre-existing observable requirement ("exactly
  one wire call, result shared with all N callers") was already implying about *how* a
  conformant mechanism must behave under contention. It exists because that implication was not
  explicit enough: `axiam-java-sdk`, `axiam-go-sdk` and `axiam-cplusplus-sdk` each independently
  violated one of the four invariants below (found by a cross-SDK audit after the first,
  `axiam-java-sdk`'s, was fixed), and `axiam-rust-sdk` was hardened against the same class
  pre-emptively — four different mechanisms (a re-checked-liveness shared future, a
  corrected-ordering channel, a generation-counted `shared_future`, a value-retaining `watch`
  cell), the same four properties.
  - **§9 gains rule 6**: publish-before-vacate (6a), occupancy is not liveness (6b), only the
    current owner clears its own slot (6c), and a caller arriving after full settlement always
    gets a fresh refresh rather than a previous burst's outcome (6d). Together these are what
    rule 5's "equally strong mechanism" means in practice.
  - **The §9 test requirement is extended** to cover the two windows that let these bugs ship
    past the pre-1.6 requirement: a caller landing in the publish-before-vacate bookkeeping
    window (must join, not re-call), and a caller landing after full vacate (must re-call, not
    join a stale outcome) — plus, where ownership is tracked, that a losing/cancelled attempt
    cannot clear a different, currently-live attempt's slot.
  - **Fixed**: [`axiam-java-sdk#27`](https://github.com/ilpanich/axiam-java-sdk/pull/27) (§12
    `runExclusive` counted a settled-but-uncleared slot as live, exhausting a bounded retry and
    failing a valid unrelated operation — rule 6b), [`axiam-go-sdk#20`](https://github.com/ilpanich/axiam-go-sdk/pull/20)
    (`OidcRefresh`/`OidcDiscover` cleared the slot before publishing, opening a window for a
    second wire call — rule 6a), [`axiam-cplusplus-sdk#6`](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/6)
    (a non-owner could clear a newer attempt's slot, rule 6c; a settled future was served to a
    late arrival instead of that arrival refreshing itself, rule 6d), and
    [`axiam-rust-sdk#34`](https://github.com/ilpanich/axiam-rust-sdk/pull/34) (pre-emptive
    hardening of the same `oidc_refresh` coalescer, replacing a broadcast channel that required
    retire-before-send with a value-retaining `watch` cell so rule 6a holds structurally).
  - **Not affected, audited clean, for their `oidc_refresh` coalescer specifically**:
    `axiam-typescript-sdk` (`singleFlightRefresh.ts`) and `axiam-php-sdk` (`OidcClient.php`) —
    single-threaded promise/fiber-chain ordering makes rule 6a hold by construction, because the
    slot clear is chained onto the very value being shared, so no application code can observe
    the ordering violated. `axiam-csharp-sdk`'s dedicated OIDC guard was already checking
    completion (not mere occupancy) before this clarification existed, satisfying 6b.
  - **Not affected for the §1 cookie-session refresh guard** (a *different* operation from
    `oidc_refresh`, sharing the same four invariants by construction): `axiam-python-sdk`,
    `axiam-go-sdk`'s `internal/refreshguard`, `axiam-rust-sdk`'s `token::refresh_guard`, and the
    C SDK's `single_flight_refresh` all hold the lock across the entire wire call, so there is no
    publish/vacate gap to violate at all — releasing the lock is definitionally the last step,
    which cannot precede the outcome being computed.
  - **Follow-up audit completed (2026-07), and it found three more violations** — the initial
    pass had only checked the Java-shaped bug (6b) SDK-wide, before the Go/C++/Rust bugs
    (6a/6c/6d) were known, so Python's, Kotlin's and Swift's own guards were re-audited against
    all four rules. None was clean:
    - **`axiam-python-sdk`** — violations on **both** the sync and async `oidc_refresh` paths.
      Async broke 6a in exactly Go's shape (slot vacated before `set_result`/`set_exception`),
      and reachably so, not latently: a cancelled joiner cancels the shared future, so the
      publish step itself raised `InvalidStateError` while the slot was already empty and the
      outcome reached nobody. Sync broke 6b by waking waiters on a boolean flag rather than the
      attempt they joined, so a not-yet-rescheduled waiter read a *newer* burst's occupancy as
      its own refresh still being live and was handed the newer attempt's outcome (~82% per
      interleaving round). Async also broke 6c: a *joiner's* cancellation destroyed the live
      leader's publication, losing an already-rotated token set.
    - **`axiam-kotlin-sdk`** — the most damaging variant found. Acquiring a kotlinx `Mutex` is a
      cancellable suspension point, so a cancelled leader that hit contention threw *before*
      clearing its own slot (6c), leaving a settled-exceptionally `Deferred` parked there
      permanently; every later caller then joined that dead burst with zero further wire calls
      (6d). Because the wire call ran in the electing caller's own coroutine over a blocking,
      non-interruptible OkHttp call, a `withTimeout` typically fired *after* the refresh had
      succeeded and the server had rotated the single-use token — discarding it and leaving the
      session unrecoverable. Three sites shared the defect, including the §1 guard, which
      (unlike Python's/Go's/Rust's/C's) did **not** hold its lock across the wire call and so was
      never covered by that clearing argument.
    - **`axiam-swift-sdk`** — 6c violated (unconditional slot clear, so a lagging attempt could
      wipe a newer leader's live entry); 6a/6b/6d hold structurally for its actor + `Task`
      mechanism and are now asserted by test. Swift's unstructured `Task {}` not inheriting
      caller cancellation is what spared it from Kotlin's session-destroying variant.

    Fixed in [`axiam-python-sdk#23`](https://github.com/ilpanich/axiam-python-sdk/pull/23),
    [`axiam-kotlin-sdk#8`](https://github.com/ilpanich/axiam-kotlin-sdk/pull/8) and
    [`axiam-swift-sdk#7`](https://github.com/ilpanich/axiam-swift-sdk/pull/7). Final tally: of
    eleven SDKs, **six** carried a genuine rule-6 violation (Java, Go, C++, Kotlin, Swift,
    Python), one was hardened pre-emptively (Rust), and four were clean on their own merits
    (TypeScript, PHP, C#, C) — which is the empirical case for stating these invariants
    normatively rather than leaving them implied by rule 2.

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

*Contract version: 1.7 — Phase 15 (sdk-foundation); §11 declarative authorization helpers added 2026-07; §6.1 mTLS client certificates and Kotlin/Swift/C/C++ SDK columns added 2026-07; §1.1 gRPC-only `get_user_info` operation added 2026-07; §12 OIDC/SSO relying-party helpers and the `OAuthProtocolError` taxonomy sub-type added 2026-07; §7 accessor rules, §9 rule 5, and the §12 cross-SDK clarifications from the eight-SDK conformance review added 2026-07; §9 rule 6 single-flight implementation invariants and the extended §9 test requirement added 2026-07; §8b AMQP transport, §10.2 gRPC revocation modes, §12.7 logout helpers, §14 device authorization grant and §15 token exchange added 2026-08; §14.3 rule 4 / §14.6 credential-adoption errata 2026-08 (contract 1.7)*
*Binding since: 2026-06-30*
*Reference: D-09, D-10 in `.planning/phases/15-sdk-foundation/15-CONTEXT.md`*
