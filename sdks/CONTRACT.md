# AXIAM SDK Behavioral Contract

> **Status: normative/binding (D-09)**
>
> This document is the cross-language behavioral contract for all AXIAM SDKs.
> Every SDK implementation (Phases 16–22) MUST conform to §1–§10 in full.
> Each downstream SDK README must state: "This SDK conforms to CONTRACT.md §1–§10."
>
> Vocabulary locked: 2026-06-30 (D-10). Rust (Phase 16) implements this contract; it does not define it.

### Where the SDKs live

Each SDK is its own repository — the AXIAM repository keeps only this contract,
[`openapi.json`](openapi.json) and [`management-registry.json`](management-registry.json),
which are the three inputs every SDK builds against:

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
(alongside a copy of `openapi.json`, of `management-registry.json`, and of `proto/`); when
this file changes, the copies must be re-synced. `management-registry.json` is *generated*
(`scripts/gen-management-registry.py`) and is re-synced downstream like the others; it is
never edited in an SDK repository, and §27.8 requires each SDK's CI to regenerate its
management layer from it and diff. File paths quoted below (`crates/…`, `proto/…`) are relative to the AXIAM
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
| device certificate login (REST) | `authenticate_device` | `authenticateDevice` | `authenticate_device` | `authenticateDevice` | `AuthenticateDevice` | `authenticateDevice` | `AuthenticateDevice` |
| token validation (gRPC) | `validate_token` | `validateToken`       | `validate_token`    | `validateToken`  | `ValidateTokenAsync` | `validateToken` | `ValidateToken` |
| token introspection (gRPC) | `introspect_token` | `introspectToken` | `introspect_token` | `introspectToken` | `IntrospectTokenAsync` | `introspectToken` | `IntrospectToken` |

The last three rows were added in contract 1.51. `authenticate_device` is
`POST /api/v1/auth/device`, the mTLS device login of [§6.1](#§61-client-certificate-authentication-mtls).
The C++ SDK's `Client::authenticate_device()` is the one implementation that
existed when the row was written, so its name is the one that spreads.
`validate_token` and `introspect_token` wrap `axiam.v1.TokenService/ValidateToken`
and `/IntrospectToken`, whose `cnf` field [§10.3](#§103-sender-constrained-tokens-over-grpc-contract-117-normative)
makes normative. Until 1.51 §10.3 required an SDK to read that field, but this
table did not permit any method that could return it. The two sections
contradicted each other. Five repositories generated the stubs, and in none of them
did a public method wrap them.

`get_user_info` is a **gRPC-only** operation (added 2026-07, contract 1.3) — see
[§1.1](#§11-grpc-only-operations) for its normative semantics. Unlike every other row in
this map it has no REST form and is implemented only by SDKs that ship a gRPC transport.

**Additional languages (Kotlin, Swift, C, C++ — added 2026-07):** these expose the same
canonical operations with the same `(action, resource[, scope])` argument order. Casing:
**Kotlin** and **Swift** use camelCase (`login`, `verifyMfa`, `refresh`, `logout`,
`checkAccess`, `can`, `batchCheck`); **C++** uses snake_case (`login`, `verify_mfa`,
`refresh`, `logout`, `check_access`, `can`, `batch_check`); **C** uses snake_case with an
`axiam_` prefix on every symbol (`axiam_login`, `axiam_verify_mfa`, `axiam_refresh`,
`axiam_logout`, `axiam_check_access`, `axiam_can`, `axiam_batch_check`). The REST
device login (contract 1.51) is `authenticateDevice` in Kotlin and Swift,
`authenticate_device` in C++ and `axiam_authenticate_device` in C. No new
login/auth/authz method names beyond this map and the
[§12](#§12-oidc--sso-relying-party-helpers) OIDC/SSO relying-party map are permitted in these
SDKs either. The
gRPC-only `get_user_info` operation is **deferred** in all four of these SDKs for as long
as they ship no gRPC transport (they already defer gRPC in v1 — see §1.1); when a gRPC
transport is added, the method name is `getUserInfo` (Kotlin/Swift), `get_user_info` (C++),
or `axiam_get_user_info` (C). The same holds for the two gRPC token operations of
[§1.1.1](#§111-validate_token-and-introspect_token-contract-151): they are deferred
while there is no gRPC transport, and are named `validateToken` / `introspectToken`
(Kotlin, Swift), `validate_token` / `introspect_token` (C++) and
`axiam_validate_token` / `axiam_introspect_token` (C) when one is added.

**Argument order:** every operation above takes the acted-upon subject before the object it
acts on — concretely, `check_access`/`can` take `(action, resource[, scope])` in every SDK,
with no exception. PHP's `can(action, resource)` (`src/AxiamClient.php` in the PHP SDK repo) was
reversed relative to this rule prior to SDK-Q09 remediation (2026-07); it has been corrected
to match its own `checkAccess(action, resource)` and every other SDK's `can`/`Can`.

**Notes:**
- `can` is an alias for `check_access` targeting browser/UI scenarios; it calls `POST /api/v1/authz/check` via REST (avoids N round-trips when combined with `batch_check` for page-level permission gating).
- `batch_check` calls `POST /api/v1/authz/check/batch` and returns results in the same order as input.
- `get_user_info` calls `axiam.v1.UserInfoService/GetUserInfo` over gRPC (§1.1). `validate_token` and `introspect_token` call `axiam.v1.TokenService/ValidateToken` and `/IntrospectToken` (§1.1.1). These three are the operations in this map without a REST equivalent in the SDK vocabulary.
- `authenticate_device` calls `POST /api/v1/auth/device` (§6.1). It is REST-only: no RPC performs a device login.
- No SDK is permitted to expose additional login/auth/authz method names that diverge from this map or from the [§12](#§12-oidc--sso-relying-party-helpers) OIDC/SSO relying-party map, which extends the same locked vocabulary.

### §1.1 gRPC-only operations

`get_user_info` is the first of the three operations whose SDK surface is served **only
over gRPC**. The other two, `validate_token` and `introspect_token`, were added in
contract 1.51 and are specified in [§1.1.1](#§111-validate_token-and-introspect_token-contract-151)
below; the rules numbered here are `get_user_info`'s. It is
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

#### §1.1.1 `validate_token` and `introspect_token` (contract 1.51)

These two operations wrap `axiam.v1.TokenService` (vendored `proto/axiam/v1/token.proto`).
They exist so that an SDK validating a token over gRPC has a public method that returns what
§10.3 obliges it to read. The following rules are **normative and identical in every SDK
that ships a gRPC transport**:

1. **Transport and metadata.** They are unary calls to `ValidateToken` and `IntrospectToken`,
   made on the SDK's existing channel with its existing interceptor, exactly as §1.1 rules 1
   and 2 require for `get_user_info`. The call carries the **caller's** bearer token in
   `authorization`, and the server's interceptor enforces that token like any other,
   including its own `cnf`. The token being inspected travels in the request message
   (`access_token`) and is a different credential. An SDK MUST keep the two apart and MUST
   NOT default the inspected token to the caller's.
2. **Precondition.** Both calls need a caller token, so §1.1 rule 3 applies: with no token,
   the SDK raises `AuthError` client-side, without a wire call. The inspected token
   is secret material, and the parameter that carries it is `Sensitive<T>` (§7).
3. **Return shape.** A typed value holding **every** field the response message defines.
   For `validate_token` that is `valid`, `subject_id`, `tenant_id`, `org_id`, `exp`, `cnf`
   and `token_type`. For `introspect_token` it is the RFC 7662 set: `active`, `sub`,
   `tenant_id`, `org_id`, `iss`, `iat`, `exp`, `jti`, `scope`, `client_id`, `token_type`,
   `cnf`, `permissions` and `ext_exchange_iss`. `cnf` is modelled as **optional**, and
   absent is distinct from present-but-empty (§10.3 rule 3). An SDK MUST NOT drop `cnf`
   from the typed value on the grounds that the caller did not ask for it. §10.3 exists
   because a client that could not see the field treated every token as a bearer token.
4. **`valid` / `active` is not "usable as presented".** §10.3 rule 2 governs, and this
   operation is where it bites. When `cnf` is present, the SDK MUST NOT report the token as
   usable by whoever presented it. It MUST either verify possession against its own
   connection, or return the value in a form that forces the caller to. An accessor
   documented as "`valid` means the caller may proceed" is non-conformant.
5. **`token_type` does not tell you whether a token is bound.** The server reports `"DPoP"`
   only for a `jkt`-bound token. A certificate-bound token (`cnf.x5t_s256` set, which is
   what every device token from [§6.1](#§61-client-certificate-authentication-mtls) carries)
   is reported as `"Bearer"`. An SDK MUST decide boundness from `cnf` alone.
6. **A token from another tenant is `valid: false` / `active: false`**, with the other fields
   empty and no `cnf`. That is the server answering "not a token of yours", not an error, and
   an SDK MUST NOT raise on it.
7. **No REST substitution.** An SDK without a gRPC transport documents both operations as
   deferred, exactly as §1.1 rule 6 does for `get_user_info`. It MUST NOT substitute `POST
   /oauth2/introspect`: that endpoint authenticates a registered OAuth2 client
   (RFC 7662 §2.1) and is not in the SDK vocabulary. Kotlin, Swift, C and C++ defer both
   today.

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
| **Any status** from `/oauth2/*` with an `OAuth2ErrorResponse` body | `OAuthProtocolError` | RFC 6749 protocol error. Dispatch on the `error` field, NOT on the status ([§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3). Rewritten in contract 1.12 — see the note below |
| 401         | `AuthError`   | Unauthenticated; triggers refresh if tokens present |
| 403         | `AuthzError`  | Authenticated but not authorized              |
| 408, 429    | `NetworkError`| Timeout / rate-limited                        |
| 409         | `AuthzError`  | Conflict (resource-level access denied)       |
| 5xx         | `NetworkError`| Server error; SDK should NOT retry auth       |
| Connection error / DNS / TLS | `NetworkError` | Transport-layer failures   |

Where two rows match the same response, the more specific (endpoint- and body-qualified) row
wins.

**The `/oauth2/*` row was two rows until contract 1.12, gated to `400` and `401`.** That
enumeration was a description of which statuses the endpoints happened to use, written before
[§20](#§20-uma-20--protection-api-and-ticket-grant-x2) existed. §20.4's `access_denied` answers
`403`, so a status-gated mapper dropped it through to the `AuthzError` row and lost the one
field a caller can act on — and **nine of the eleven SDKs grew a near-identical private mapper
for that single grant** rather than widen a shared one that other endpoints depend on. (PHP
needed none: its mapper already dispatched on the `error` field, which is what §20.4 asks for in
the abstract and what this row now says outright.)

Three things this rewrite does **not** do, each load-bearing:

1. **It is scoped to `/oauth2/*` paths only.** An ordinary REST `403` — including from
   `/api/v1/authz/check` and from the §20 Protection API at `/uma2/perm` and `/uma2/rreg/*`,
   whose refusals §20.4 maps by status precisely because they are not OAuth2 protocol errors —
   still maps to `AuthzError`. An SDK MUST keep a test for that; the assertion to make is that
   an ordinary REST `403` maps to `AuthzError`, not the older and now-false "the OAuth2 rows
   apply to no status but 400 and 401".
2. **It requires a well-formed body.** A `403` from `/oauth2/*` whose body is not an
   `OAuth2ErrorResponse` — a proxy's HTML error page, an empty body — falls back to the status
   mapping. "Has an `error` member that is a non-empty string" is the test; a body that merely
   parses as JSON is not enough.
3. **It does not change what happens next.** A `401` carrying an `OAuth2ErrorResponse` still
   MUST NOT enter the §9 single-flight refresh guard ([§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks)
   rule 3): client-authentication failure is not a session expiry, and retrying cannot fix a
   wrong client secret.

### gRPC Status → Error Type Mapping

| gRPC Status Code          | Error Type    | Notes                                         |
|---------------------------|---------------|-----------------------------------------------|
| `UNAUTHENTICATED` (16)    | `AuthError`   | Triggers single-flight refresh (see §9)       |
| `PERMISSION_DENIED` (7)   | `AuthzError`  | Caller lacks the required permission          |
| `UNAVAILABLE` (14)        | `NetworkError`| Server unreachable                            |
| `DEADLINE_EXCEEDED` (4)   | `NetworkError`| Request timed out                             |
| `INTERNAL` (13)           | `NetworkError`| Server-side error                             |
| `RESOURCE_EXHAUSTED` (8)  | `NetworkError`| Rate-limited by the server                   |

**`UserService/ValidateCredentials` and `UNAVAILABLE` (contract 1.60, informative).** The call
costs one Argon2id verify on every invocation, a refusal included — an unknown name, a locked,
non-active or directory account — so when the server's password-hash gate is saturated every
call, whatever its outcome would have been, answers `UNAVAILABLE` (`NetworkError`), never an
immediate `valid: false`; `valid: false` itself never says why. An SDK maps `UNAVAILABLE` as
the row above says and MUST NOT read it as "the credentials were wrong".

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

> **`X-Tenant-ID` is not the acting-tenant header** (contract 1.36, issue #395). The
> AXIAM server does not read it: the tenant a request is scoped to comes from the access
> token, and the tenant an organization-level principal *switches* to is named by
> **`X-Axiam-Tenant`** (§5.2, §5.2.2, §5.2.3) — a different header, read by a different
> mechanism. This one stays required because it is what a reverse proxy, a gateway or an
> SDK's own resource-server middleware (§10) routes and logs on, and because removing a
> header eleven SDKs already send is a breaking change for those consumers and not for
> AXIAM. It MUST NOT be renamed to `X-Axiam-Tenant`: an unconditional per-request header
> naming the client's *constructor* tenant would override the acting tenant on every
> request an organization-level principal made after switching, which is precisely the
> bug this note exists to prevent. The helper that *does* send the acting-tenant header
> is specified in [§5.2](#§52-organization-level-principals-contract-131) rule 1
> (contract 1.51).

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

### §5.2 Organization-level principals (contract 1.31)

Every organization has one reserved tenant holding the principals that operate across
all of its tenants. A principal whose record lives there is **organization-level**: its
global grants apply in every tenant of the organization, while an ordinary tenant
principal is a principal of exactly one tenant and of no other.

The distinction is visible on the wire as one boolean:

- **`LoginUserInfo.organization_level`** (`boolean`) — present on the user object of the
  login response and of `GET /api/v1/auth/me`. An SDK that models that user object MUST
  expose the field, and MUST default it to `false` when it is absent, which is what a
  server older than contract 1.31 answers and is the safe direction in both cases.

Two rules follow, and both are about not inventing capability the server did not grant:

1. **`organization_level` is the only thing that makes switching the acting tenant
   meaningful.** Such a principal changes the tenant it acts on by sending
   `X-Axiam-Tenant` on the next request — no re-login, because it already is a principal
   of every tenant in its organization. That header is distinct from §5 rule 2's
   `X-Tenant-ID`, which is sent unconditionally and which the server does not read. For an
   ordinary tenant principal the same header change produces a `403`, and an SDK that
   offers the switch anyway has turned a type-level distinction into a runtime failure.

   **An SDK SHOULD offer the acting-tenant helper** (contract 1.51; until then it was a
   MAY). None of the eleven offered it, so a provisioning tool running as an
   organization-level principal had to hand-roll the header on every call. The shape
   is fixed so that eleven SDKs cannot invent eleven:

   | | Rust | TypeScript | Python | Java / Kotlin | C# | PHP | Go | Swift | C | C++ |
   |---|---|---|---|---|---|---|---|---|---|---|
   | at construction | `with_acting_tenant(id)` | `actingTenant` option | `acting_tenant=` | builder `.actingTenant(id)` | `ActingTenant` option | `actingTenant:` | `WithActingTenant(id)` | `actingTenant:` config | `axiam_client_config_set_acting_tenant` | `with_acting_tenant(id)` |
   | on an existing client | `acting_tenant(id)` | `actingTenant(id)` | `acting_tenant(id)` | `actingTenant(id)` | `ActingTenant(id)` | `actingTenant($id)` | `ActingTenant(id)` | `actingTenant(_:)` | `axiam_client_set_acting_tenant` | `acting_tenant(id)` |

   Every name here is new in 1.51. Each follows the language's §1 casing and the
   construction style its §6.1 client-certificate option already uses. The rules:

   - **The value is a tenant UUID, checked client-side.** The server parses the header as
     a UUID and **silently ignores** a value that does not parse. The request then acts on
     the caller's own tenant and succeeds. A helper that forwarded a slug would therefore
     report success about the wrong tenant. It MUST refuse a non-UUID with the same §2
     client-side error §27.4 rule 2 uses, before any wire call.
   - **The header is sent only when set.** A client without an acting tenant sends no
     `X-Axiam-Tenant` at all, byte for byte as before 1.51. The on-client form MUST also
     offer a way to clear it (`None`, `null`, or an explicit `clear_acting_tenant`), and
     clearing sends no header.
   - **It is REST-only.** The gRPC server reads no acting-tenant metadata: its interceptor
     reads `authorization` and takes the tenant from the token. An SDK MUST NOT invent a
     metadata key for it, and MUST document that its gRPC calls act on the token's
     tenant whatever the helper says.
   - **Gate it on what the SDK knows, and let the server decide the rest.** When the
     client holds a login result (§5.2.2), the on-client form MUST refuse client-side
     unless `organization_level` is true, and MUST refuse a tenant outside
     `reachable_tenant_ids` when that field is present (§5.2.3 rule 4). A client holding
     no login result has nothing to gate on. That covers a service account from client
     credentials or the device login, and an injected token. It sends the header as asked,
     and the server's `403` is the answer. An **organization-level service account** is a
     supported design, and the server honours the header for one on exactly the terms it
     does for a user.
   - **It is documented as meaningful only for an organization-level principal**, never
     as a general "switch tenant" capability.
   - **§27.4 rule 3 is unchanged.** A management route whose path carries `{tenant_id}`
     still defaults that segment from the constructor tenant, and an explicit argument
     still overrides it. The header and the path are read by different mechanisms, and an
     SDK MUST NOT couple them.

   **What 1.51 left open (contract 1.52, C-12).** The eleven 1.51 ports read the helper
   six ways. Each point below is the reading this revision fixes; §27.14 records who
   diverged and where each fix landed.

   - **Where the header goes.** The server reads `X-Axiam-Tenant` in one place, the
     authentication extractor, so only an **authenticated** `/api/v1` route ever acts on
     it. While an acting tenant is set, every request to such a route MUST carry the
     header. Some requests have no authenticated principal yet: login, `verify_mfa`,
     OPAQUE, the device login, the SSO completions, the WebAuthn setup pair and
     `/oauth2/*`. On those the server reads no acting tenant, so the header is optional,
     and sending it is harmless. Neither the header, nor `X-Tenant-ID`, nor any
     credential goes to a host other than the client's configured base URL.
   - **A new handle, or the same client.** The on-client form MAY return a new handle, or
     MAY change the client in place. It is the language's choice. The README MUST say
     which, and, for the in-place form, whether copies of the client share the change.
     `logout` MAY also clear the acting tenant; the README says whether it does.
   - **One gate per session.** Every handle over one session gates on the same login
     result, so a login on any handle changes what all of them refuse. A per-handle copy
     of the gate goes stale the moment another handle signs in.
   - **A refusal is `AuthzError`.** The gate stands in for the server's `403`, so its
     refusal is §2's `AuthzError`, not `AuthError` and never `NetworkError`.
   - **Which responses set the gate.**
     - A response that establishes a session and carries the user object records the
       gate from it: login, `verify_mfa`, the OPAQUE finish, the MFA setup confirmation
       and the WebAuthn setup completion. The server builds all five with one function,
       `cookie_response_from_output` in `handlers/auth.rs`.
     - A response that establishes a session without that object resets the gate to
       unknown: a WebAuthn authentication, an SSO completion, the device login and
       client-credentials adoption. So does `logout`.
     - `refresh` keeps the principal, so it SHOULD leave the gate as it is. Resetting it
       to unknown also conforms, at the cost of the client-side refusal until the next
       login.
     - A `200` that lacks a documented user object is malformed. An SDK MAY raise §2's
       `NetworkError`, MAY treat the gate as unknown, or MAY read it as the too-old-server
       default above, `organization_level: false`. It MUST NOT read it as `true`.
   - **Tenant ids compare as UUIDs.** Reach (`reachable_tenant_ids`) is decided on
     parsed UUIDs. Letter case and formatting never decide it: a string comparison
     between an upper-case formatter and the server's lower-case output refuses every
     tenant.
2. **It is derived, never asserted.** The flag is resolved server-side from the caller's
   own tenant record. An SDK MUST NOT accept it as constructor input, MUST NOT infer it
   from a slug or a name, and MUST NOT send it — it is a response field in one direction
   only.

#### §5.2.1 Signing one in (contract 1.32)

The reserved tenant has a fixed slug, `"organization"`, the same in every deployment, so
the ordinary §5.1 login body reaches it with nothing new:

```json
{ "org_slug": "acme", "tenant_slug": "organization",
  "username_or_email": "root", "password": "…" }
```

An SDK constructed with `tenant_slug: "organization"` therefore needs no new surface, and
that is the form an SDK SHOULD use, because §5 rule 2 requires a tenant on the
`X-Tenant-ID` header of every subsequent request regardless.

Two rules govern what happens when the tenant is *not* named, which is what a login form
with an empty tenant field produces:

1. **Naming no tenant means the organization's own scope.** `POST /auth/login`,
   `POST /auth/opaque/login/start`, `POST /auth/opaque/register/start` and
   `POST /auth/webauthn/authenticate/discoverable/start` all resolve the reserved tenant
   when neither `tenant_id` nor `tenant_slug` is present. A tenant principal that omits
   its tenant is simply not found there and gets the ordinary enumeration-safe `401` — a
   tenant principal must name its tenant, and learns nothing by failing to.

2. **An SDK MUST NOT send an empty-string slug.** A field the caller left blank is
   omitted from the body, never serialized as `""`. No row can carry an empty slug, so
   `""` resolves nothing; on the four routes above it also takes rule 1 away, and on
   `/auth/opaque/login/start` it does so *before* the tenant's OPAQUE mode is read — so
   the `404` of §23.4 rule 10 never arrives and the client has no fallback to take. This
   is the shape of a real outage: an organization-level administrator who could not sign
   in at all, on a deployment with OPAQUE **disabled**.

Nothing else about §5 changes: `X-Tenant-ID` is still required on every request (rule 2)
— and is still not the header that switches the acting tenant, per the note under that
rule — and there is still no default tenant.

#### §5.2.2 Acting tenant vs principal tenant (contract 1.34)

`X-Axiam-Tenant` says which tenant a request **acts on**. It says nothing about where the
caller *lives*, and for four things the second tenant is the one that matters. The login
response and `GET /api/v1/auth/me` therefore carry both:

| Field | Meaning |
|---|---|
| `tenant_id` | the tenant being acted on — what `X-Axiam-Tenant` names |
| `principal_tenant_id` | the tenant this principal's record lives in |
| `principal_tenant_slug` | its slug (`"organization"` for an organization-level principal) |
| `org_id` | the caller's organization, as a UUID |

Three rules:

1. **Absent means equal.** A server older than contract 1.34 omits all four. An SDK MUST
   read `principal_tenant_id` as defaulting to `tenant_id`, which is exactly true for every
   ordinary tenant principal — they diverge only once an organization-level principal
   switches the acting tenant, which such a server cannot do either.

2. **The caller's own credentials belong to the principal tenant.** `POST
   /auth/password/change` and the OPAQUE registration record that accompanies it are about
   the account, not about whatever tenant the client is currently pointed at. An SDK that
   builds a §23 record for its own password change MUST seal it against
   `principal_tenant_id`; a record sealed against the acting tenant is refused with
   *"the OPAQUE session was issued for a different tenant"*. When creating **another**
   account (§27 `users.create`), the record is sealed against the tenant that account is
   being created in — the acting tenant — for the same reason.

3. **`org_id` removes the detour.** Every organization-scoped route is addressed by id
   (`/api/v1/organizations/{org_id}/…`). `GET /api/v1/organizations` is restricted to
   `super-admin` and returns only the caller's own organization, so an SDK MUST NOT use it
   to turn a slug into an id — it reads `org_id` from the session instead.

4. **Self-service endpoints ignore the header, and an SDK MUST NOT help them** (contract
   1.36). Rule 2 is one case of a general rule the server applies: a request whose target
   is the **caller's own user id** is scoped to `principal_tenant_id`, whatever
   `X-Axiam-Tenant` names. That covers `GET`/`PUT /users/{own id}`, `GET`/`DELETE` on that
   user's `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
   `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
   /users/me/resend-verification`, the §25 account export and erasure requests for the
   caller's own id, and `GET /oauth2/userinfo`. The same endpoints for **anybody else's**
   id follow the header, unchanged.

   A server older than contract 1.36 scoped all of them to the acting tenant, so each
   answered `404` for an organization-level caller that had switched tenant. An SDK MUST
   NOT work around that by clearing or rewriting `X-Axiam-Tenant` for those calls: the
   header is what makes the *administrative* form of the same endpoint reach the right
   tenant, and an SDK that strips it would break reading another tenant's user in order
   to fix reading its own. Send the header as normal; the server decides.

   **`POST /users/{own id}/reset-mfa` is refused with `403` and the error code
   `mfa_enforced` where the caller's own tenant enforces MFA** (contract 1.45): the reset
   removes every factor at once, and an enforcing tenant's floor is not the user's to
   lower — an administrator resets it for them. The administrative form of the same
   endpoint, under `users:admin`, is unaffected. An SDK surfaces the code as it surfaces
   `opaque_required`: it is not an `authorization_denied`, the caller holds every
   permission the call needs, and a client that renders it as "forbidden" tells the user
   the wrong thing about their own account.

`permissions` on `/auth/me` is the caller's effective actions **in the scope it is acting
on**: across a tenant boundary it carries only the caller's global grants, mirroring the
authorization engine. It is advisory — the server enforces every action independently —
and an SDK MUST NOT treat its absence or emptiness as authoritative.

#### §5.2.3 Tenant-scoped role assignments (contract 1.35)

§5.2 is all-or-nothing: an organization-level principal's global grants reach every
tenant of its organization. A role **assignment** may now name the tenants it reaches,
which is how an organization-level account is confined to some of them.

Two wire changes, both additive:

- **`tenant_scope`** (`array<uuid>`, optional) on the three assignment request bodies —
  `POST /roles/{id}/users`, `POST /roles/{id}/groups`,
  `POST /roles/{id}/service-accounts` — and on the assignment objects those endpoints
  and `GET /users/{id}/roles`, `GET /groups/{id}/roles` return. Omitted means the
  assignment reaches wherever the role does, which is what every assignment written
  before this field existed means.
- **`LoginUserInfo.reachable_tenant_ids`** (`array<uuid>`, optional) on `GET
  /auth/me`. Absent means unrestricted. Present means the caller's roles reach only
  those tenants.

Four rules:

1. **Omit, never send an empty array.** `[]` is refused with `400`: an assignment that
   reaches no tenant contributes nothing anywhere, so it is a grant that does not exist
   rather than a restriction. An SDK whose builder defaults the field to an empty
   collection MUST drop it from the serialized body rather than send it.
2. **It is only legal in an organization scope.** Sending it on an assignment made in an
   ordinary tenant is refused with `400`. An SDK MUST NOT silently drop it there — a
   caller that asked for a restriction and got a `204` would reasonably believe one was
   applied.
3. **A restricted principal is refused organization-level actions.** Creating, renaming
   or deleting a tenant or an organization, minting or revoking an organization CA,
   flagging an mTLS trust anchor, the organization email config and the MDS refresh all
   answer `403` for it, and `GET /auth/me` does **not** emit the `*` wildcard in
   `permissions`. An SDK that gates client-side on that wildcard therefore needs no
   change; one that gates on `organization_level` alone MUST also consult
   `reachable_tenant_ids`, or it will offer what the server refuses.
4. **`reachable_tenant_ids` bounds the acting tenant.** Sending `X-Axiam-Tenant` naming a
   tenant outside it is refused with `403` at the header rather than as a denial on each
   subsequent request. An SDK that offers a "switch tenant" helper (§5.2 rule 1) MUST
   restrict its choices to that list when it is present.

A server older than contract 1.35 omits both fields and accepts neither. An SDK MUST
treat absence as "unrestricted", which is exactly true there.

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
and service accounts by **mutual TLS**. The client presents an X.509 identity certificate
that chains to an mTLS trust anchor of its organization and is bound to a service account
(`POST /api/v1/auth/device` — "Authenticate a device via its client certificate (mTLS)").
A tenant principal issues such a certificate under **its own tenant's signing CA**. The
organization CA is reachable only by an organization-level human principal, and never by a
service account (server T22.1, T22.13). Until contract 1.51 this paragraph said "signed by
the tenant's organization CA"; a tenant administrator who follows that is refused with
`404`.

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

**The device login, `authenticate_device()` (contract 1.51).** Configuring a client
certificate without being able to log in with it was the state of ten SDKs of eleven.
One of them, C, documented the endpoint in its README but shipped no symbol that called
it. Rules 6–10 close that. The name is §1's.

6. **One call, no body, three fields back.** `authenticate_device()` issues
   `POST /api/v1/auth/device` with no request body and returns a typed value
   `{ access_token, token_type, expires_in }`. `access_token` is `Sensitive<T>` (§7).
   `token_type` is `"Bearer"`. `expires_in` is the access-token lifetime in seconds
   (default 900). There is **no refresh token**; that is a server decision (D-6 of the
   dogfooding remediation plan). A device re-authenticates by calling this operation
   again, which costs one TLS handshake. The SDK adopts the token as the client's
   credential exactly as it adopts a `login` result. With no refresh token, the §9 guard
   has nothing to spend: a later `401` on this token is surfaced as `AuthError`
   without a refresh attempt, and the caller recovers by calling `authenticate_device()`
   again.
7. **Reachable only on a client configured with a certificate.** On a client built
   without rules 1–5's identity, the operation MUST NOT be reachable. Where the type
   system can express that, it does. Elsewhere, the call MUST fail client-side with the
   §2 `AuthError`, with zero wire calls. Without a certificate the server would
   answer `401`, so going to the wire gains nothing and turns a configuration mistake into
   an authentication failure.
8. **Every refusal is a `401`** (server T22.4). An unknown, untrusted, expired, revoked
   or unbound certificate, and a `Server`-type certificate (§27.13), all return 401 with
   the error code `authentication_failed`. The message differs by case, and the SDK
   surfaces it verbatim. Before T22.4 an unbound certificate returned `403`. An SDK MUST
   map the operation's `401` to `AuthError` and MUST NOT enter the §9 refresh
   guard for it: this *is* the login. The route is rate-limited per client IP (default 60
   per minute, server T22.2). A `429` follows §16 and is not an authentication failure.
9. **The token is certificate-bound, and §10.1 rule 9 applies to it** (server T22.3).
   When AXIAM itself terminated the TLS handshake, the token carries
   `cnf: { "x5t#S256": <thumbprint of the presented certificate> }`. From then on it is
   usable only on a connection presenting **that** certificate. A REST request without it
   is a `401`. A gRPC call without it is `UNAUTHENTICATED`, and on a gRPC listener that
   does not request client certificates (the server's default,
   `AXIAM__GRPC_TLS_CLIENT_AUTH=off`), a bound token is refused on **every** call. The
   rule 4 requirement that one identity serve both transports is therefore load-bearing.
   A client that logs in over mTLS and then calls from a second client object without the
   certificate has built the theft scenario the claim exists to close. When a
   trusted proxy terminated TLS instead (`X-Client-Certificate`), the token is **not**
   bound, because AXIAM could not re-check it. An SDK MUST NOT infer boundness from
   `token_type`, which stays `"Bearer"` either way (§1.1.1 rule 5).
10. **What the token can do.** It is a service-account token (`aud` = `axiam:m2m`). It is
   accepted by §1's `check_access` / `batch_check` and by the §27 operations listed in
   §27.13's S-9 note, where the account's roles authorize it exactly as a user's would. A
   route outside that set answers `401` for an audience mismatch, and an SDK MUST NOT
   turn that into a refresh attempt.
11. **The device credential's lifecycle (contract 1.52, C-12).** Rule 6 says the token is
    adopted "exactly as a `login` result", and the eleven 1.51 ports read that eleven
    ways. §27.14 records the divergences. The lifecycle is:
    - **The device POST carries nothing of a prior session**: no `Cookie` and no
      `Authorization`. The server reads the `axiam_access` cookie before the header, so
      either one could evaluate the call against the earlier principal. The POST carries
      `X-Tenant-ID`, and MAY carry `X-Axiam-Tenant` (§5.2 rule 1).
    - **A refused or malformed device login changes nothing.** The client keeps the
      credential, the cookie jar and the acting-tenant gate it had. It MAY clear the §17
      memo, because dropping entries is always correct (§17 rule 8). A caller who was
      mid-session when a device login was refused still has a working session.
    - **On success, the device token is the credential of every request the client
      makes**: authz, management, self-service, WebAuthn, logout, and the gRPC channel
      (rule 4). No request carries a cookie from before. An empty `Cookie` header and no
      header both conform. A left-over `X-CSRF-Token` is harmless, because the server
      checks it only against a cookie session.
    - **It is held until something replaces it.** `logout` clears it. So does any later
      call that establishes a session, and that session is used from then on: login,
      `verify_mfa`, OPAQUE, a WebAuthn authentication, an SSO completion,
      client-credentials adoption, or another device login. `refresh` does not clear it.
      A device credential that outlives a later login silently runs the new session as
      the device.
    - **It is never refreshed, on either transport.** A REST `401` or a gRPC
      `UNAUTHENTICATED` on the device credential is `AuthError`, with no refresh call.
      So is a `401` on the device POST itself when the client also holds an earlier
      session. The caller gets the server's message, not the refresh guard's.
    - **Returning a new handle instead of adopting in place conforms.** The new handle
      carries the acting tenant of the handle that made it, and the original client is
      unchanged.
    - **§27.4 rule 1's session check accepts a bearer credential.** A client holding a
      device or client-credentials token has a session for that rule, and a management
      call MUST NOT be refused client-side for want of a cookie.

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
| C          | Opaque `axiam_sensitive_t` handle; `axiam_sensitive_reveal()` is the single explicit accessor (rule 3), and the value is never written to logs/`printf` output |
| C++        | `class Sensitive<T>` with `operator<<`/`to_string` returning `"[SENSITIVE]"`; `expose()` is the single explicit accessor (rule 3) |

**The C and C++ rows changed in contract 1.11.** Through 1.10 both read "no public accessor",
and that wording was correct for as long as it was true that no token material ever reached
their callers: both SDKs deferred §12 in its entirety, so everything they held lived in the §4
cookie jar and rule 3 had nothing to enable. §12.6's 1.11 port removes that premise — §12 hands
the caller an `OidcTokenSet`, and a token no caller can read cannot be persisted, forwarded or
revoked. This is the same collision contract 1.5 resolved for the other eight SDKs, resolved the
same way: **one** explicit accessor, documented as the single one, never reached from a
log/trace/serialization sink. Swift already exposed `expose()` for the §20 requesting-party
token and is unchanged here.

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

**Minimal profile (contract 1.60, informative).** A server running in the minimal profile
(`AXIAM__AMQP__ENABLED=false`) reads no AMQP queue: it does not consume `axiam.authz.request`
or `axiam.audit.events`, whatever a broker holds. A broker confirm (a publisher confirm, or the
broker's `basic.ack` of a publish) never means AXIAM decided the request or recorded the event;
it means only that the broker accepted the message. An SDK MUST NOT treat a confirm as evidence
that AXIAM saw a message, and its README says so. Against a minimal-profile server use REST or
gRPC; `GET /health` reports `profile: minimal` and lists `amqp_authz` and `amqp_audit_ingestion`
under `unavailable`.

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

### The server is TLS-only (contract 1.23)

`AXIAM__AMQP__URL` **must** be `amqps://`. Every other scheme is refused before
a socket is opened, in a debug build exactly as in a release one, and there is
no environment variable, build profile or flag that changes the answer. The
`AXIAM__AMQP__ALLOW_PLAINTEXT` escape hatch that permitted `amqp://` in a
release build has been **removed**.

This matters to an SDK author for one practical reason and one design reason.
The practical one: there is no plaintext broker listener to connect to any more,
so an SDK that offers a plaintext code path offers a path to nothing. The design
one is the history, which is worth stating because it is the usual shape of this
failure. The flag existed for a year and four of the project's own stacks
reached for it — dev compose, the e2e stack, the benchmark target and CI — each
with a locally sound argument: throwaway data on a compose network, an ephemeral
broker carrying synthetic fixtures for one job, a hop the benchmark harness is
trying to measure rather than encrypt. None of those arguments was wrong. The
aggregate was that "AMQP is TLS-only" described the production compose file and
the k8s manifests, and nothing else the repository actually ran.

### Requirements

| # | Rule |
|---|---|
| 1 | An SDK that connects to AMQP **MUST** require `amqps://` URLs (broker TLS port 5671), and **MUST** refuse every other scheme, including `amqp://`. |
| 2 | It **MUST** support supplying a custom CA bundle, for a privately-issued broker certificate. This is the common case — an in-cluster broker's certificate is not issued by a public CA. |
| 3 | It **SHOULD** support client certificates (mutual TLS toward the broker), and where it does, the certificate and its key **MUST** be required together: half a client identity MUST fail closed rather than connect without the mutual half. |
| 4 | It **MUST NOT** offer a certificate-verification-skip option in a production build, under any name. |
| 5 | It **MUST NOT** fall back to plaintext when a TLS connection fails. A failed `amqps://` connection is an error to surface, not a condition to work around. |
| 6 | HMAC signing (§8) remains mandatory on every message regardless of transport. |
| 7 | **Rules 1–5 MUST be enforced in code, not stated in documentation** (contract 1.23). A doc comment saying the URL "must be `amqps://`" on a parameter that accepts anything is not conformance. Where the SDK opens the connection, it validates before the socket does; where the SDK takes a caller-supplied channel or connection, it **MUST** also ship a constructor that applies rules 1–4, and that constructor is what its README and examples show. |
| 8 | There is **no loopback exception** (contract 1.23). Rules 1 and 5 apply to `localhost`, `127.0.0.1` and `::1` exactly as to any other host. An SDK whose HTTP transports grant a `http://localhost` dev carve-out under §6 **MUST NOT** extend it to the broker URL: §6 and §8b are different rules, and the server has no plaintext listener for such an exception to reach. |

### Where rule 7 is satisfied, per SDK (normative index)

Rule 7 is about a specific failure mode — a requirement that reads as enforced
and is not — so the enforcement point is named rather than left to be found.
Each of these validates the scheme **before** a socket is opened, accepts a CA
bundle, and offers no verification-skip option:

| SDK | Enforcement point |
|-----|-------------------|
| Rust (server) | `AmqpConfig::validate_transport_security` — the whole server, one path |
| Rust (SDK) | `amqp::transport::ensure_amqps` / `connect_amqps`, behind `consume`, `consume_with_tls` and `reactor_serve` |
| TypeScript | `amqp/transport.ts` — `assertAmqpsUrl` / `buildAmqpConnectOptions`, behind `consume()` and `reactorServe()` |
| Python | `aio_pika_dialer` |
| Go | `AMQPSDialer` (+ `WithReactorCABundle`) |
| PHP | `AmqpLibReactorTransport::parseAmqpsUrl` / `::connect` |
| Kotlin | `reactorConnectionFactory` |
| Java | `ReactorConnections.connectionFactory` / `requireAmqps` |
| C# | `ReactorConnections.CreateConnectionFactory` / `RequireAmqps`, and `AxiamAmqpConsumer.StartAsync` |
| Swift | `amqpsEndpoint` (`Sources/AxiamSDK/Reactor/AmqpsEndpoint.swift`) |
| C | `axiam_amqps_endpoint` (`src/reactor.c`) |
| C++ | `axiam::amqps_endpoint` (`src/reactor.cpp`) |

Java, Kotlin and C# take a caller-supplied channel in their reactor options, so
rule 7's second clause is what applies: the runtime cannot inspect a channel
somebody else opened, and refusing to serve on one whose provenance is
unknowable would break every legitimate custom setup to catch a mistake the
constructor already prevents.

Swift, C and C++ are the same clause taken further: they bundle no AMQP client
at all (§22.11), so their runtime never sees a URL and could not validate one if
it wanted to. Rule 7's second clause is therefore the whole of their obligation —
ship the constructor, and show it in the README and the example. Before contract
1.28 this row read "a hand-rolled integrator satisfies §8b themselves", which was
rule 7's failure mode written into rule 7's own index: a requirement stated in
prose, enforced nowhere.

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
  not become an excuse to trust the payload;
- **a plaintext `amqp://` URL is refused, and no connection is attempted**
  (contract 1.23). Assert on the connection *not having been made* — a mock
  connect function never called, or no socket opened — rather than only on the
  thrown message. Rule 5 is a claim about the absence of a fallback, and an
  implementation that dialled first and complained second would pass a
  message-only assertion while violating the rule;
- the same refusal for `amqp://localhost` (rule 8), and for an unparseable URL.
  An input the SDK cannot parse must fail closed: a guard written as "check the
  scheme *if* the URL parses" silently exempts everything malformed, which is a
  real defect this project shipped and fixed.

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

**Every entry point is a guard (contract 1.52, C-12).** The 1.51 review found C-1's
defect in all ten ports: the SDK's default verify call, the one with no evidence parameter
and the one every guard reached, never read `cnf`. The same defect sat one layer down in
TypeScript's `Verifier.verifyAccessToken`, whose own documentation named it as the guard
entry point. These rules govern every public function that turns an access token into a
verified identity or claims:

- **An overload with no evidence parameter is still a guard.** It verifies against no
  evidence, and so refuses a `cnf`-bound token under rule 9.
- **A signature-only primitive is exempt** only when its name or its documentation says
  it is not a guard.
- **§10.3's gRPC `validate_token` and `introspect_token` are not identity entry points.**
  They return the server's verdict together with `cnf`, and the caller applies rule 9
  (§10.3 rule 1).
- **A guard that cannot reach transport evidence refuses every bound token.** When the
  framework it plugs into exposes no peer certificate and no verified DPoP proof, the
  guard refuses them all. That conforms, but it means device tokens (§6.1 rule 9) and
  DPoP-bound tokens never pass that guard, and the SDK's README MUST say so, per guard.

| # | Claim | Rule |
|---|---|---|
| 1 | signature | Verify against the org JWKS with `alg` **pinned to EdDSA before key lookup**. `alg: none` and HS-family confusion MUST be rejected without consulting a key. |
| 2 | `exp` | **REQUIRED.** A token with no `exp`, or a non-numeric `exp`, MUST be rejected. An absent `exp` is a *permanent* credential and MUST NOT be treated as "no expiry constraint". |
| 3 | `nbf` | **Honoured when present.** A token whose `nbf` is in the future MUST be rejected. Absent `nbf` is valid. |
| 4 | `tenant_id` | **REQUIRED and asserted.** MUST equal the client's configured tenant. Absent claim, or no configured tenant to compare against, MUST fail closed. The JWKS trust anchor is **organization-wide**, so signature validity alone does not bound a token to a tenant. |
| 5 | `iss` | **Checked when the SDK is configured with an expected issuer**; absent configuration means no check. When configured, a mismatch MUST be rejected. |
| 6 | `aud` | **Checked when the SDK is configured with an expected audience.** When configured, a token whose `aud` does not contain it MUST be rejected. SDKs guarding a user-facing resource server SHOULD expect `axiam:user`; one guarding a **machine-facing** resource server SHOULD expect `axiam:m2m`, which is what *every* service-account token now carries — both the client-credentials grant and the mTLS device path (§12.1) — or the resource URL an MCP server fronts, once minted through RFC 8707 (`docs/api/resource-indicators.md`; §28 is the MCP resource-server helpers that configure this rule in that case). |
| 7 | clock skew | Rules 2 and 3 MAY allow a **small, named, documented** leeway (RECOMMENDED 60 s). It MUST be a named constant, not an inline literal, and MUST NOT be operator-configurable to an unbounded value. |
| 8 | subject of the decision | The guard MUST decide on **the caller's credential and no other**. When that credential fails any rule above, the guard MUST reject. It MUST NOT retry, refresh, or fall back to a *different* credential — in particular not the SDK client's own session — and MUST NOT admit the request under any identity other than the one the caller presented. |
| 9 | `cnf` | **A token carrying `cnf` is not a bearer token, and MUST NOT be accepted as one.** When the claim is present the guard MUST verify **every** sender constraint it names, or reject. See the normative rules below. |

**Rule 9 — sender-constrained tokens (contract 1.15; extended for DPoP in
contract 1.16. RFC 8705 §3 / RFC 9449 §6 / RFC 7800).**

AXIAM can issue sender-constrained access tokens under **two** mechanisms, and a
token may carry either or both:

```json
"cnf": { "x5t#S256": "<base64url-unpadded SHA-256 of the DER client certificate>" }
"cnf": { "jkt":      "<base64url-unpadded RFC 7638 SHA-256 thumbprint of the DPoP public key>" }
```

* `x5t#S256` (RFC 8705 §3) comes from a client registered with
  `tls_client_certificate_bound_access_tokens`. The caller proves possession by
  completing a TLS handshake with the certificate — which the transport has
  already done by the time the guard runs.
* `jkt` (RFC 9449) comes from a client registered with
  `dpop_bound_access_tokens`. The caller proves possession by **signing a fresh
  DPoP proof on every request**, which the guard must verify itself. That is a
  materially larger obligation than the certificate case, and §21.7 is where it
  is spelled out.

The claim's presence changes what the token *is*. An ordinary AXIAM access token
is a bearer credential — whoever holds it may use it. A token with `cnf` names a
key, and a resource server that accepts it without checking that the caller
holds that key has silently converted it back into a bearer token, discarding
the entire protection the operator turned on. That is why this is a rule and not
a recommendation.

An SDK guard MUST behave exactly as follows. "Evidence" means a certificate the
transport verified for this connection, or a DPoP proof **the SDK has itself
verified** per §21.7 — never one it has merely received:

| Token's `cnf` | `x5t#S256` evidence | `jkt` evidence | Guard MUST |
|---|---|---|---|
| absent | — | — | **accept** (subject to rules 1–8) |
| `x5t#S256` only | a certificate whose `x5t#S256` equals it | — | **accept** (subject to rules 1–8) |
| `x5t#S256` only | a different certificate, or none | — | **reject** |
| `jkt` only | — | a verified proof whose key thumbprint equals it | **accept** (subject to rules 1–8) |
| `jkt` only | — | a different key, an unverified proof, or none | **reject** |
| `jkt` only | anything | the SDK cannot verify DPoP proofs at all | **reject** |
| **both** | matching certificate | matching verified proof | **accept** (subject to rules 1–8) |
| **both** | either half missing or wrong | | **reject** |
| present, naming neither | anything | anything | **reject** |
| present, but an empty object `{}` | anything | anything | **reject** |

Three rows carry the weight:

1. **`jkt` only, and the SDK cannot verify DPoP proofs → reject.** This is not a
   deficiency to route around; it is the rule. An SDK whose role is
   resource-server-only and which has not implemented §21.7 MUST refuse
   `jkt`-bound tokens and MUST say so in its README. It MUST NOT accept them as
   bearer tokens, and it MUST NOT accept them on the strength of the proof's
   *presence* without verifying it.
2. **Both present is a conjunction, never a disjunction.** A token that named two
   constraints was issued under two, and honouring it on one uses it under
   weaker terms than the operator configured. "Check whichever we can" is the
   characteristic bug of a binding validator and is forbidden.
3. **`cnf` naming no method the SDK knows → reject**, including an empty object.
   An absent claim means "never bound"; an empty or unrecognised one means
   "bound by something that did not survive the trip", and reading it as
   unconstrained downgrades a sender-constrained token exactly when a newer
   AXIAM has started issuing a confirmation the SDK predates. **Fail closed**,
   consistently with every other rule in this section.

Normative details:

1. **The thumbprint is base64url without padding** (RFC 7515 §2), computed over
   the **DER** encoding of the leaf certificate. A padded value, standard-base64
   (`+`/`/`), or a hex digest will not compare equal. A well-formed value is
   exactly 43 characters.
2. **The comparison input MUST come from the transport.** The certificate must
   be the one the TLS layer verified for *this* connection — the peer
   certificate, or a value a **trusted** terminating proxy forwarded over a
   channel the application controls. An SDK MUST NOT take it from a
   request header supplied by the caller, and MUST NOT document doing so as a
   supported deployment. A forgeable input makes the whole mechanism decorative.
3. **When the SDK cannot see any client certificate at all** — a deployment
   behind a TLS terminator that forwards nothing — a bound token MUST be
   rejected, and the SDK's documentation MUST say that guarding bound tokens
   requires the certificate to be made available. Silently accepting is
   forbidden; silently rejecting without saying why in the docs is a support
   burden.
4. **Introspection carries it too.** An SDK verifying through
   `POST /oauth2/introspect` rather than locally MUST apply this same rule to
   the response's `cnf` field (RFC 8705 §3.3), which AXIAM populates for bound
   tokens. Local-verification SDKs and introspecting SDKs must not disagree
   about whether a token is a bearer token.
5. **Comparison SHOULD be constant-time** where the language makes it
   available. The thumbprint is usually public, so this is defence in depth
   rather than load-bearing — but it costs nothing and matches the discipline
   §10.1 applies elsewhere.
6. **`jkt` is the RFC 7638 JWK thumbprint**, SHA-256, base64url without
   padding — 43 characters, the same shape and encoding as `x5t#S256`, and
   therefore trivially confusable with it. An SDK MUST NOT compare a `jkt`
   against a certificate thumbprint or vice versa. Where the language permits,
   the two SHOULD be distinct types or at minimum distinctly named parameters;
   two same-shaped strings in adjacent positional parameters is a swap that
   compiles.
7. **A `jkt` comparison input MUST come from a proof the SDK verified.** A
   thumbprint computed from the JWK in an *unverified* proof header is
   attacker-supplied: anyone can mint a proof naming their own key. Taking it
   without checking the signature turns DPoP into a self-signed permission slip.
   §21.7 lists what "verified" means.
8. **`cnf` from introspection carries `jkt` too** (RFC 9449 §6.1). Rule 9's
   detail 4 applies unchanged: a local-verification SDK and an introspecting SDK
   must not disagree about whether a token is a bearer token.

**Required negative tests** (in addition to those listed below): a bound token
presented with **no** certificate; a bound token presented with a **different**
certificate; a token whose `cnf` carries a method the SDK does not implement; a
token whose `cnf` is an empty object. For contract 1.16, additionally: a
`jkt`-bound token presented **without** a proof; a `jkt`-bound token presented
with a proof signed by a **different** key; and — for an SDK that does not
implement proof verification — a `jkt`-bound token that is **rejected rather
than accepted as a bearer token**.

And one positive regression test that matters more than all of them: **an
unbound token MUST still be accepted with or without a certificate and with or
without a DPoP proof present.** Rule 9 must not become a requirement that every
caller present a proof — that would break every existing deployment, and it
remains the most likely way to implement this rule wrongly. Contract 1.16
widens the ways to get it wrong without widening the rule: a client that has
never heard of DPoP must get exactly the behaviour it got before.

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

SDKs MUST NOT try to close this gap client-side **on the request path** — for
example by asking the server about the session before each call. Doing so would
put an unbounded per-request cost on the hot path to work around a decision that
is the deployment's to make, and it would be a *different* staleness window
rather than none. That rule is unchanged and is what it always meant: the words
are "before each call".

[§10.4](#§104-the-revocation-feed-contract-144) defines the bounded,
off-the-hot-path alternative, and nothing in it relaxes the sentence above.

### §10.4 The revocation feed (contract 1.44)

**Requirement level: SHOULD. Disabled by default.**

A deployment MAY publish `GET /oauth2/revocations` — the hashed ids of sessions
revoked within the last access-token lifetime. An SDK route guard **SHOULD**
poll it and reject a token whose `sid` appears, which narrows the §10.2 window
from one token lifetime to one poll interval.

The document:

```json
{
  "alg": "SHA-256",
  "issued_at": 1757664000,
  "ttl": 900,
  "revoked": ["i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ", "…"]
}
```

An entry is the **base64url-unpadded SHA-256 of the `sid` claim's exact
string**, in its canonical hyphenated lowercase form — the same encoding
`cnf.x5t#S256` and `jkt` already use, so no SDK needs a new primitive. Hash the
claim as read; do not parse it to a UUID and re-render it, or the guard's answer
depends on its UUID parser rather than on the feed.

The rules, all normative where an SDK implements this at all:

1. **Default off.** A caller opts in. An SDK that polls by default has changed
   what every existing integration does on upgrade, for a feature the
   deployment may not even serve.
2. **Never on the request path.** Poll on an interval, serve the guard from the
   cached set. RECOMMENDED interval 30–60 s; an SDK MUST bound both the
   interval (no shorter than 15 s) and the cached set.
3. **Never fail closed on the feed.** A guard that cannot fetch the document,
   that gets a non-`200`, that cannot parse it, or that sees an `alg` other
   than `SHA-256`, MUST behave **exactly** as it does with the feature off. It
   MUST NOT treat any of those as an empty list either — an empty list asserts
   that nothing has been revoked, which is a guard silently honouring no
   revocations while appearing to honour them. Hold the last good set until it
   ages out, then behave as with the feature off.
4. **It only ever rejects.** The feed can turn an accept into a reject and never
   the reverse. Every §10.1 rule still runs first and still decides; a token
   that fails one of them is rejected whatever the feed says.
5. **`Retry-After`, `ETag` and `Cache-Control` are honoured** as §16 honours
   them. A poller that ignores the caching headers is the caller a deployment
   will notice.
6. **A token with no `sid`** — a client-credentials token, an RPT, a token
   exchange — is never matched against the feed. There is no session behind it
   to revoke, and hashing `jti` instead would match nothing while looking like
   it worked.

Required tests, per SDK: a revoked `sid` is rejected **after one poll and not
before** (which pins that the guard is not fetching per request); and a guard
with the feature **off**, and one with the feature on whose feed is
**unreachable**, each behave byte-for-byte as they do today — asserted through
the guard's public surface and by counting requests on the wire, so "does not
fetch" is proven rather than asserted.

#### §10.4.1 Per-SDK posture

As §21.9 and §21.10: an unrecorded row is not a supported answer, and
`declines` with a reason is.

| SDK | Polls the revocation feed |
|---|---|
| rust | yes — `RevocationFeed`, attached with `JwksVerifier::with_revocation_feed` |
| typescript | yes — `RevocationFeed`, set as `VerifiableSession.revocationFeed` |
| python | yes — `RevocationFeed`, passed as `JwksVerifier(revocation_feed=…)` |
| go | yes — `RevocationFeed`, attached with `JWKSVerifier.WithRevocationFeed` |
| java | yes — `RevocationFeed`, passed to the three-argument `JwksVerifier` |
| kotlin | yes — `RevocationFeed`, attached with `Builder.revocationFeed` |
| csharp | yes — `RevocationFeed`, passed as `JwksVerifier(revocationFeed:)` |
| php | yes — `RevocationFeed`, passed as the sixth `JwksVerifier` argument |
| swift | yes — `RevocationFeed`, enabled with `AxiamConfig.revocationFeedEnabled` |
| c | yes — `axiam_client_enable_revocation_feed`, off by default |
| cplusplus | yes — `RevocationFeed`, set as `AuthenticatorOptions::revocation_feed` |

### §10.3 Sender-constrained tokens over gRPC (contract 1.17, normative)

§10.1 rule 9 is transport-independent — a token carrying `cnf` is not a bearer
token, whichever wire it arrived on. This section says how an SDK obtains that
`cnf` when it validates through **gRPC** rather than REST, and it exists because
until contract 1.17 an SDK doing so **could not obtain it at all**.

#### What changed on the wire

`TokenService.ValidateToken` and `TokenService.IntrospectToken` now carry the
confirmation, alongside the RFC 7662 fields the REST endpoint always returned
and this one did not:

| Field | Message | Notes |
|---|---|---|
| `cnf` | both | `CnfClaim { x5t_s256, jkt }`. **Absent** for an unbound token. |
| `token_type` | both | `"Bearer"` or `"DPoP"` (RFC 9449 §5). |
| `scope`, `client_id` | introspect | RFC 7662 §2.2 parity. |
| `permissions` | introspect | UMA 2.0 RPT permissions (§20). |
| `ext_exchange_iss` | introspect | X4 cross-domain provenance. |

All are additive proto fields; a client built against the older schema keeps
working and simply does not see them. **That is precisely the risk**, and it is
why this section is normative rather than informative.

#### Rules

1. **An SDK that validates or introspects over gRPC MUST read `cnf` and apply
   §10.1 rule 9 to it**, identically to the REST path. Rule 9 detail 4 already
   required that local-verifying and introspecting SDKs not disagree about
   whether a token is a bearer token; over gRPC that was previously impossible
   to satisfy, and an SDK that keeps ignoring the field now fails the rule
   rather than merely lacking the data.
2. **`valid: true` / `active: true` does not mean "usable as presented."** It
   means the signature, expiry and tenant check out. When `cnf` is present the
   SDK MUST additionally verify possession against **its own** connection — the
   AXIAM server cannot do it, because the proof is against the caller's
   connection and not against the one carrying the introspection call.
3. **A `CnfClaim` with both members empty MUST be refused**, not read as
   unbound. Proto3 cannot distinguish "absent string" from "empty string", so
   this is the wire-level spelling of rule 9's "names neither" row: absence of
   the whole `cnf` message means unbound, an empty one does not.
4. **Do not mirror the server's gRPC-side refusal of DPoP.** AXIAM's own gRPC
   interceptor refuses `jkt`-bound tokens because a tonic interceptor sees
   neither the HTTP method nor the URI a proof is bound to. An SDK guarding a
   real endpoint **does** know both, so it can and should verify per §21.7.2.
   The server's limitation is the server's.

**The operations these rules bind** are §1's `validate_token` and `introspect_token`,
specified in [§1.1.1](#§111-validate_token-and-introspect_token-contract-151) (contract
1.51). Before 1.51, §1's closed list permitted no method that could return `cnf`, so rule
1 could only be satisfied by an SDK breaking §1. The wording of rules 1–4 is unchanged;
they now have a surface to apply to.

#### Required tests

Through `validate_token` and `introspect_token`, the same shape §10.1 rule 9 requires,
against the gRPC path: a `cnf`-bearing
introspection response is not treated as a bearer token; an empty `CnfClaim` is
refused; and — the positive regression — **an unbound response still
validates**, since a response with no `cnf` is what every pre-1.17 server and
every unbound token produces.

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
     bounded read-only retry policy of [§16](#§16-retry-policy-d5))
6. **No decision caching by default.** Helpers MUST NOT cache allow/deny decisions (consistent
   with §10's TTL rule). Batch/page-level optimization stays the application's job via
   `batch_check`. The **single** exception is the explicitly opt-in, TTL-clamped decision memo
   of [§17](#§17-client-side-decision-memo-d5), which is disabled by default and which
   §17.1 rule 10 forbids from serving the fail-closed path above.
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

   **Amended 2026-08 (SDK-Q10).** The decision has one shape now, and it is the
   REST one. The gRPC `CheckAccessResponse` called its human-readable reason
   `deny_reason` (`proto/axiam/v1/authorization.proto`) while the REST decision
   body has always called the same string `reason`
   (`crates/axiam-api-rest/src/handlers/authz_check.rs`) — one decision under two
   names, which every SDK speaking both transports had to reconcile in its own
   mapper, and which is why two same-named `AccessDecision` types could disagree
   about their own field list.

   - **`reason` (proto field 4) is the canonical name and supersedes
     `deny_reason`.** It carries exactly the string `deny_reason` carries, and it
     has *explicit presence*: absent on an allow — REST omits it there — and
     present on every refusal.
   - **`deny_reason` (proto field 2) is deprecated, not removed.** It is marked
     `[deprecated = true]`, so most languages' codegen now warns at the use site,
     and the server keeps populating it with the identical string. **Both fields
     ship until AXIAM 2.0**, where `deny_reason` is removed. Renaming it now would
     have broken every deployed gRPC client on the wire for no behavioural gain;
     that is why this is a deprecation and not a rename.
   - **What an SDK does in the meantime.** Read `reason` when present. Fall back
     to `deny_reason` only when `reason` is absent *on a refusal* — that
     combination means the server predates this change and nothing else. Expose
     **one** human-readable reason on the result type, named `reason` in the
     language's own casing, fed by that rule; do not expose both and do not make
     callers choose. An SDK whose public type already says `denyReason` /
     `deny_reason` adds `reason`, deprecates the old accessor in its own idiom on
     this same 2.0 schedule, and MUST NOT remove it before then. `reason` remains
     what it always was — a generic string for a human, never a structural hint
     (T-15-02) and never something to branch on. `reason_code` is the field for
     that.
   - **The reconciled decision shape, both transports:** `allowed` (bool),
     `reason_code` (string, the closed vocabulary above), `reason` (string, absent
     on an allow). Those three and no others. In particular the check request and
     the decision carry **no `resource_type` / `resourceType`** — the server has
     never had such a field on either, so an SDK declaring one on its
     `AccessCheck` type is declaring something it can never send, and MUST drop
     it.
   - **`subject_id` is optional over gRPC too.** REST's `subject_id` is optional
     and defaults to the token's subject; gRPC required it and then refused
     anything that was not a restatement of the caller. It is now optional there
     in the only way proto3 permits without a wire break: an **empty**
     `subject_id` means "the subject in the verified token", exactly as REST's
     absent field does. A non-empty value must still equal the token's subject —
     gRPC has no `authz:check_as` cross-subject form. Making the proto field
     `optional` was rejected because `buf breaking` refuses the cardinality change
     (verified against `main`), the same wire-level constraint §10.3 records for
     an empty `CnfClaim`.

   Required tests for this amendment: a refusal over gRPC surfaces `reason`, and
   `deny_reason` carries the identical string; an allow surfaces no `reason`; a
   response carrying only `deny_reason` (an older server) still surfaces its text
   through the SDK's single `reason` accessor; and a gRPC check with `subject_id`
   omitted returns the same decision as one that spells the caller out.
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
an SDK that ships them states conformance to §1–§12. All eleven SDKs implement the section as of
contract 1.11 — Swift, C and C++ deferred it through contract 1.10 and were ported in 1.11; see
[§12.6](#§126-swift-c-and-c-ported--contract-111).

These helpers MUST be built on the SDK's existing machinery — the §4 cookie jar, the §6/§6.1
TLS configuration, the §7 `Sensitive<T>` wrapper, the §9 single-flight refresh guard, and the
JWKS verifier the §10 middleware already uses. No SDK may fork, duplicate, or re-implement
any of them for §12.

### §12.1 Canonical operation set and endpoint map

Thirteen canonical operations — the original nine, plus the four public "Sign in with X" entry points
added at contract 1.37. Every column below is verified against `openapi.json`; deviating
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
| `sso_providers` | `GET /api/v1/auth/federation/providers` | no body; `org_slug`/`org_id` and optional `tenant_slug`/`tenant_id` as **query** parameters | `200` `PublicFederationProvidersResponse` |
| `sso_start_oauth2` | `POST /api/v1/auth/federation/oauth2/start` | `application/json` / `OAuth2StartRequest` | `200` `OAuth2StartResponse` |
| `sso_complete_oauth2` | `POST /api/v1/auth/federation/oauth2/callback` | `application/json` / `OAuth2CallbackRequest` | `200` `SsoLoginSuccessResponse` + `Set-Cookie` |
| `sso_complete_handoff` | `POST /api/v1/auth/federation/handoff` | `application/json` / `SsoHandoffRequest` | `200` `SsoLoginSuccessResponse` + `Set-Cookie` |

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
   form body. SDKs MUST NOT send an `Authorization: Basic` header to `/oauth2/*`.

   **Rationale amended 2026-09 (contract 1.41, W8).** The rule previously rested on the server
   documenting no alternative. It now documents one: `client_secret_basic` (RFC 6749 §2.3.1) is
   accepted server-side and advertised in `token_endpoint_auth_methods_supported`, for the
   third-party relying parties — and the OpenID Foundation's Basic OP certification suite —
   that can speak nothing else. **The rule itself does not change, and no SDK changes any
   code.** The reason is now the one that was always the better one: the two methods carry the
   identical credential, and the header is the channel reverse proxies, load balancers and APM
   agents log by default while the form body is not. An SDK that switched would hand a
   password-equivalent secret to every intermediary on the path for no protocol gain.

   Per-client, and per-registration: a client is authenticated by the method its registration
   names and by no other (SEC-093), so a `client_secret_post` client that sends a Basic header
   has it ignored — the header is never a second way in. An SDK therefore cannot acquire Basic
   authentication by accident, and an application that genuinely needs it registers the client
   for `client_secret_basic` and uses a plain HTTP client rather than an AXIAM SDK.
4. **`introspect` and `revoke` require confidential-client credentials.** `IntrospectRequest`
   and `RevokeRequest` both mark `token` and `client_id` as required (non-nullable);
   `token_type_hint` is optional. A public client cannot call them.

   **Amended 2026-08 (SEC-093).** `client_secret` was required (non-nullable) on both
   requests, and both endpoints authenticated by shared secret **regardless of the
   client's registered `token_endpoint_auth_method`** — so a client registered for
   `tls_client_auth` or `private_key_jwt` (see §21.2's `token_endpoint_auth_method`
   row) kept a working password-equivalent credential here, which is the opposite of
   what registering the stronger method is for. The server now honours the
   registration at `revoke`, `introspect`, `/oauth2/par`, and the `token-exchange`
   and `uma-ticket` grants, exactly as it already did at the `authorization_code`,
   `client_credentials` and `refresh_token` grants.

   Consequences for an SDK:

   - `client_secret` is now **optional** (nullable) on `IntrospectRequest`,
     `RevokeRequest` and the PAR request body, and both requests additionally accept
     the RFC 7521 pair `client_assertion` / `client_assertion_type`. This is a
     widening, not a break: an SDK that keeps sending `client_secret` for a
     `client_secret_post` client is unchanged and stays conformant.
   - An SDK that supports the strong methods MUST NOT send `client_secret` for a
     client registered for one of them — it is refused with `invalid_client`, not
     ignored. Send `client_assertion` for `private_key_jwt`, or nothing at all for
     the two mTLS methods, whose credential is the TLS connection.
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
   a value. The same holds for every `POST /api/v1/auth/federation/*` operation in this table.

9. **`sso_providers` never distinguishes "no such organization" from "no providers".** Both
   answer `200` with an empty `providers` array. An SDK MUST NOT synthesise a
   not-found error from an empty list, and MUST NOT treat the empty case as a
   failure: the endpoint is deliberately shaped so it cannot be used to
   enumerate organization or tenant slugs, and an SDK that reintroduces the
   distinction reintroduces the oracle. A request naming **no** workspace at all
   answers the same way, for the same reason — a `400` there against a `200 []`
   for an unknown slug would restore the two-valued answer the empty list
   removes. The start operations, where every failure is a uniform `401`, are
   where a caller learns it named the workspace wrongly.

   The response carries only what a sign-in button needs — `id`, `provider_kind`,
   `display_name`, `protocol`, `has_bundled_mark`, an optional `button_icon`
   data URL, and `inherited`. It carries **no** `client_id`, `metadata_url`,
   endpoint URL or secret, and SDKs MUST NOT expect one.

10. **`protocol` selects which start operation to call.** `OidcConnect` → `sso_start`;
    `OAuth2` → `sso_start_oauth2`; `Saml` → the SAML login endpoint (not a §12
    vocabulary operation). Calling the wrong one is refused with `400`, not
    silently accepted, so an SDK MUST dispatch on the value rather than assuming
    OIDC.

11. **The OAuth2 variant carries reduced assurance, and PKCE on it is not optional.**
    A provider whose `protocol` is `OAuth2` issues no ID token: the server
    authenticates by calling a configured userinfo endpoint with the access
    token, so there is no signature, no `nonce` and no `aud`. The server
    generates and stores the PKCE verifier itself and never returns it — as with
    the federation `nonce` (note 7), SDKs MUST NOT synthesize, expect or validate
    one. An SDK that surfaces the provider list to an application SHOULD make the
    distinction visible rather than presenting `OAuth2` and `OidcConnect`
    providers as equivalent.

12. **Handoff codes are single-use and short-lived.** SAML and Apple's
    `response_mode=form_post` return **cross-site**, so the server cannot set
    `SameSite=Strict` session cookies on that response. It instead redirects the
    browser to the SPA's callback URL with an `axiam_handoff` query parameter
    carrying a 256-bit code, valid for **60 seconds** and redeemable **once**, at
    `sso_complete_handoff`. An SDK driving a browser flow MUST redeem it from the
    same origin, MUST NOT retry a redemption that failed (the code is gone
    either way), and MUST treat `401` as terminal. Unknown, expired and
    already-redeemed all answer the same `401`, deliberately.

12a. **On every federated start operation the `redirect_uri` MUST be on the
    deployment's own origin.** The server refuses, with `400`, any `redirect_uri`
    whose **origin** — scheme, host *and* port — is neither its own issuer origin
    nor one the operator has listed in `AXIAM__AUTH__SSO_SPA_ORIGINS`. This
    applies to all four start operations — `saml_login`, and `sso_start` for the
    Apple, OIDC and plain-OAuth2 protocols — and again where the server issues
    the session or mints the handoff code. An SDK MUST surface that `400` as a
    configuration error rather than retrying it, and MUST NOT construct a
    `redirect_uri` from any value the identity provider supplied. The refusal is
    raised only after the workspace and config have resolved, so an unknown
    organization still answers the uniform `401` described in rule 9.

    The rule was written for the two cross-site flows, where it is the *only*
    check there is: SAML and Apple return by form POST to an AXIAM server
    endpoint, so the identity provider never sees — and never validates — the
    `redirect_uri`, and the server is all that stands between that value and a
    handoff code being delivered to it. On the OIDC and plain-OAuth2 flows the
    provider *does* see it and *does* compare it against its registered set; that
    comparison remains, as a second and independent layer. It is not a substitute
    for this one, because it is only as strict as each provider's registration
    hygiene — several providers accept wildcard or prefix registrations — and it
    is a control the deployment does not own.

    **Deployment note, not an SDK change.** A deployment whose SPA is served from
    an origin other than the issuer's, signing in through OIDC or OAuth2
    providers, must now set `AXIAM__AUTH__SSO_SPA_ORIGINS` — the same requirement
    SAML and Apple have imposed since the rule was written. The shipped
    same-origin topology needs nothing. No SDK code changes: an SDK that passes
    the deployment's own callback URL is unaffected, and one that does not now
    receives the same `400` on two more operations than before.

13. **Federation configs may be inherited from the organization.** A config whose
    `allow_tenant_inheritance` is set and which lives in the organization-scope
    tenant is effective for the organization's tenants, unless a tenant holds one
    with the same override key — the `provider_kind` for the branded kinds, or
    `provider_kind:provider_slug` for the `generic_*` ones. A tenant's own config
    shadows the inherited one **whether or not it is enabled**. Resolution happens
    server-side: an SDK passes the workspace and the config id it was given by
    `sso_providers` and does not compute inheritance itself. The user and the
    federation link are always created in the **requesting** tenant, never the
    config's.

14. **A templated issuer requires an explicit accepted-tenant list.** Where a
    provider's discovery document publishes an issuer containing `{tenantid}`
    (Entra ID's `common`/`organizations` authorities), the server substitutes the
    ID token's `tid` and requires it to appear in the config's
    `allowed_issuer_tenants`. A config with a templated issuer and an empty list
    is refused at write time with `400`. Management SDKs writing a
    `FederationConfig` MUST surface that refusal rather than retrying without the
    field.

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
| `FederationProviderList` | `PublicFederationProvidersResponse` | `providers` (required) |
| `FederationProvider` | `PublicFederationProvider` | `id`, `provider_kind`, `display_name`, `protocol`, `has_bundled_mark`, `inherited` (required); `button_icon?` |

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
| `sso_providers` | `sso_providers` | `ssoProviders` | `sso_providers` | `ssoProviders` | `SsoProvidersAsync` | `ssoProviders` | `SsoProviders` |
| `sso_start_oauth2` | `sso_start_oauth2` | `ssoStartOauth2` | `sso_start_oauth2` | `ssoStartOauth2` | `SsoStartOauth2Async` | `ssoStartOauth2` | `SsoStartOauth2` |
| `sso_complete_oauth2` | `sso_complete_oauth2` | `ssoCompleteOauth2` | `sso_complete_oauth2` | `ssoCompleteOauth2` | `SsoCompleteOauth2Async` | `ssoCompleteOauth2` | `SsoCompleteOauth2` |
| `sso_complete_handoff` | `sso_complete_handoff` | `ssoCompleteHandoff` | `sso_complete_handoff` | `ssoCompleteHandoff` | `SsoCompleteHandoffAsync` | `ssoCompleteHandoff` | `SsoCompleteHandoff` |

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
`ssoComplete`, `ssoProviders`, `ssoStartOauth2`, `ssoCompleteOauth2`, `ssoCompleteHandoff`);
no `*Async` twins. **Swift**, **C**, and **C++** implement the section as of contract
1.11 ([§12.6](#§126-swift-c-and-c-ported--contract-111)), using the names reserved for them here
while it was deferred — a port that diverged from them was never an option: **Swift** camelCase
and **C++** snake_case exactly as the TypeScript and Rust columns above; **C** snake_case with
the mandatory `axiam_` prefix — `axiam_oidc_discover`,
`axiam_oidc_begin`, `axiam_oidc_exchange`, `axiam_oidc_refresh`,
`axiam_login_client_credentials`, `axiam_introspect`, `axiam_revoke`, `axiam_sso_start`,
`axiam_sso_complete`, `axiam_sso_providers`, `axiam_sso_start_oauth2`,
`axiam_sso_complete_oauth2`, `axiam_sso_complete_handoff`. No login/auth/authz method names beyond this map and the §1 map are
permitted in any SDK.

**Which object hosts the methods** (added in contract 1.5 — §12 was previously silent; it said "the
nine methods" until the four login-provider operations joined them at contract 1.37, and their
arrival changes nothing about the rule). They
SHOULD live directly on the SDK's existing client type, and do in seven of the eight implementing
SDKs. An SDK MAY instead place them on a separate, additionally-exported host object where a
**packaging constraint** requires it: the TypeScript SDK uses a Node-only `OidcClient` because its
CI forbids `node:crypto` and `jose` from reaching the browser bundle, and §12 has no browser
persona to serve (a browser relying party performs the redirect; it holds no `client_secret` and
never calls `/oauth2/token`). The method **names** in the map above are fixed either way — only the
host is free. An SDK that uses a separate host MUST say so in its README's §12 section, and MUST
NOT split them across two hosts.

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
   publicly accessible fields, with `message` set to `"<error>: <error_description>"`.

   **Dispatch on the `error` field, at any status** (rewritten in contract 1.12; it enumerated
   `400` and `401` before). An SDK's `/oauth2/*` mapper MUST check for a well-formed
   `OAuth2ErrorResponse` body **first**, and fall back to the §2 status mapping only when there
   is none. Concretely: a `400` from `POST /oauth2/token` MUST NOT surface as the generic
   `NetworkError` the §2 `400` row otherwise prescribes; a `403` from the §20 ticket grant MUST
   NOT surface as `AuthzError` and lose its `access_denied` code; and a `401` from
   `POST /oauth2/introspect` or `POST /oauth2/revoke` MUST NOT enter the §9 single-flight
   refresh guard (client-credential failure is not a session expiry, and retrying cannot help).

   **One mapper, not one per grant.** The status enumeration this replaces forced nine of the
   eleven SDKs to grow a private mapper for the §20 ticket grant alone, because widening the
   shared one would have changed every other endpoint's behaviour. Dispatching on the field
   removes that: the shared mapper is correct for every `/oauth2/*` grant, present and future,
   and a section that introduces a new status needs no SDK change at all. The scoping that makes
   this safe is in the §2 note — `/oauth2/*` only, well-formed body only, §9 behaviour unchanged.

   ID-token validation failures MUST raise
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

### §12.6 Swift, C and C++ (ported — contract 1.11)

**This section previously deferred §12 in these three SDKs. Contract 1.11 reverses that.**
`axiam-swift-sdk`, `axiam-c-sdk`, and `axiam-cplusplus-sdk` implement §12 in full, using the
names already reserved for them in [§12.2](#§122-per-language-naming-map), and satisfy
§12.1–§12.5 unchanged. Their conformance statements say §1–§12 alongside whatever else they
ship.

**Why the deferral was written, and why it no longer holds.** The original text reasoned from
persona: these are device- and IoT-oriented SDKs, the browser-redirect relying-party flow has
no natural home in any of them, and their authentication story — §6.1 mTLS, password login,
service credentials — was already complete without it. That reasoning covered `oidc_begin` and
`oidc_exchange`, the two operations that genuinely assume a browser. It never covered the other
seven. `login_client_credentials` is exactly the machine-to-machine login an embedded consumer
wants; `introspect` and `revoke` are ordinary token-endpoint calls a device makes about its own
credentials; `oidc_refresh` is the grant the §9 single-flight guard was built for. §12.6 itself
recorded "adding `login_client_credentials` alone to C/C++" as an open follow-up — an admission
that the all-or-nothing deferral was cutting across the wrong seam.

Two later sections settled it from the other direction. §14 (device authorization grant) exists
precisely *because* a device cannot show a browser, and its naming map lists all three; §20 gave
all three a token-endpoint call (`uma_exchange_ticket`) and its own discovery document. By
contract 1.10 these SDKs were already speaking OAuth2 at `/oauth2/token` — the "second, parallel
OIDC stack" the deferral warned about had arrived anyway, in pieces, without the shared discovery
cache and ID-token validation §12 specifies. Porting §12 removes a divergence rather than adding
one.

**What the port must satisfy.** §12.1's endpoint map, §12.3's cross-cutting rules (statelessness
above all — the caller owns `state`/`nonce`/`code_verifier`), §12.4's ID-token validation
checklist, and §12.5's `Sensitive<T>` applicability, all unchanged and all as binding here as in
the eight SDKs that shipped them first. Two consequences follow that these three did not
previously have to face:

1. **§7 rule 3 now applies to C and C++.** §12 returns tokens *to* the caller, so each of the
   three needs the single explicit accessor rule 3 permits — see the §7 table, whose C and C++
   rows change with this revision. A `Sensitive<T>` a §12 caller can never read makes §12
   unusable, which is the same reasoning contract 1.5 recorded when it restructured §7.
2. **`oidc_begin` stays synchronous and network-free** in all three, exactly as §12.1 requires.
   In C that means it allocates a URL string and a `code_verifier` the caller frees; it does not
   acquire the client's transport.

The remaining open follow-up from the original text — a server-side-Swift (Vapor) integration
cloned from the Kotlin shape — is unaffected: it concerns a framework binding, not the §12
vocabulary, and stays open.

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
here. Swift, C and C++ deferred §12.7 with §12 through contract 1.10; since
their 1.11 port ([§12.6](#§126-swift-c-and-c-ported--contract-111)) the same
SHOULD applies to them as to everyone else.

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

**A receiver is registered at its final URL (contract 1.60, informative).** AXIAM does not
follow a redirect when it delivers a webhook, and a `3xx` answer is a failed (retried) attempt.
A receiver behind an `http` → `https` or canonicalising redirect is re-registered at the URL
the redirect leads to.

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
scope**: it is the AXIAM console's job, not an SDK's. **Contract 1.60:** those two routes take
a console sign-in only — an access token AXIAM minted for an OAuth2 client (one carrying a
`client_id` claim, from the code, refresh, CIBA or device grant) is answered `403` with `error`
`authorization_denied` before the user code is looked up, as the CIBA approval routes are
([§33.3](#§333-server-rules-every-sdk-can-observe-normative) rule 16). An SDK has no call to
make there, so it has nothing to change.

Server documentation: [`docs/api/device-flow.md`](../docs/api/device-flow.md).

### §14.1 Canonical operation set and endpoint map

| Canonical operation | Wire call | Request (content type / schema) | Success response |
|---|---|---|---|
| `device_authorize` | `POST /oauth2/device_authorization?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `DeviceAuthorizationRequest` | `200` `DeviceAuthorizationResponse` |
| `device_poll` | `POST /oauth2/token?tenant_id=<uuid>` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse` |
| `device_login` | the two above, composed — see [§14.3](#§143-device_login--the-composed-helper) | — | `200` `TokenResponse` |

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
   they are retried under the bounded read-only retry policy of
   [§16](#§16-retry-policy-d5), then surfaced. A server restart mid-flow must not lose a
   grant the user has already approved. Per §16.2 that budget is **per poll attempt** and is
   separate from this grant's own `expires_in` polling loop: an exhausted retry budget ends
   that one poll, not the flow.

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
token_exchange(subject_token, subject_token_type, *, actor_token=None, scopes=None,
               audience=None, resource=None)
```

`subject_token` is positional and first, and **`subject_token_type` is positional, second, and
required**. Everything else is optional and keyword/named where the language has that, because
four optional strings in positional order is a bug waiting to be written.

**`subject_token_type` is required, and has no default.** Through contract 1.12 it was not a
parameter at all: every SDK sent `…:access_token` unconditionally, which was true by
construction while an AXIAM access token was the only admissible subject token. [§15.7](#§157-external-idp-subject-tokens-x4)
ended that, and a defaulted type would mean the SDK guessing which kind of credential the
caller holds — the one thing §15.7 forbids. Requiring it moves the guess to the only party who
cannot get it wrong. Pass `urn:ietf:params:oauth:token-type:access_token` explicitly for the
same-domain exchange this section describes.

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
8. **`token_type` on the exchange response MUST be read, not assumed `Bearer`** (SEC-096).
   An exchanging client registered for DPoP- or certificate-bound access tokens now receives
   a **sender-constrained** exchanged token: the response carries `"token_type": "DPoP"` when
   the result is bound to the client's proof key, and the token itself carries a `cnf` naming
   the constraint the client proved *on this request*. §10.1 rule 9 applies to it in full — a
   resource server MUST NOT accept it as a bearer token.

   Before SEC-096 the exchange grant stripped sender-constraining unconditionally: a client
   holding a `cnf.jkt`-bound token could exchange it and receive a plain bearer token with the
   same subject and a subset of the same scopes. It also skipped the FAPI profile gate, so a
   `fapi2` client could obtain an unconstrained token from this grant while being refused one
   from the three grants the gate guarded. Both are closed, and the consequences an SDK must
   handle are:

   * an SDK that hard-codes `Bearer` when forwarding the exchanged token will send a DPoP
     token under the wrong scheme;
   * a `fapi2` client, or any client registered for binding, that exchanges **without**
     presenting its certificate or proof now receives `invalid_client` rather than an unbound
     token. That refusal is correct and MUST NOT be retried unbound.

   A client that registered no binding — every client that existed before X5.1 — sees exactly
   the bytes it saw before: `"token_type": "Bearer"` and no `cnf`.

   The same rule applies verbatim to the §20 uma-ticket grant's RPT.
9. **An `actor_token` must have been issued to the exchanging client (contract 1.60,
   normative).** The client authenticating the exchange is the one the actor token names: its
   `client_id` claim (a token from that client's code, refresh, CIBA or device grant) or, for a
   client-credentials token, its `sub` must be that client's `client_id`. Any other actor token —
   one issued to another client, a console sign-in, a service account's token — is answered
   `400` `invalid_request` with `error_description` `actor_token was not issued to the
   exchanging client`, which an SDK surfaces as it surfaces every OAuth2 `invalid_request`
   (§15.3): unchanged, not retried, not rewritten into an impersonation (rule 1) and not
   repaired by substituting a token of its own. The usual actor is the exchanging client's own
   `client_credentials` token, whose `sub` — and so the issued token's `act.sub` — is its
   `client_id`; the caller obtains and passes it, and an SDK supplies no default (rule 1). An
   actor token whose signature or tenant fails still answers `invalid_grant`, as before. `may_act`
   (RFC 8693 §4.4) is not supported. An SDK's documentation and examples that show `actor_token`
   obtain it with the same client's `client_credentials` grant.

### §15.3 Error mapping

Extends §2. As in §14.2 rule 5, dispatch on the `error` field of `OAuth2ErrorResponse`
before falling back to the status-code mapping:

| `error` | Meaning |
|---|---|
| `invalid_request` | malformed, unsupported `subject_token_type`/`requested_token_type`, `audience`/`resource` disagree, the `act` chain is already at depth 3, or the `actor_token` was not issued to the exchanging client (§15.2 rule 9) |
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
with no attempt to refine it. Contract 1.60 adds one: an `actor_token` the mock answers with
`400 invalid_request` (`actor_token was not issued to the exchanging client`) surfaces that
error unchanged, with exactly one request and no rewriting.

### §15.7 External-IdP subject tokens (X4)

**No new per-language surface.** `token_exchange`'s existing parameters already carry
everything an external exchange needs; what changes is *which* subject tokens the server
will accept and *what the refusals mean*. Server documentation:
[`docs/api/federated-token-exchange.md`](../docs/api/federated-token-exchange.md).

**The use case:** a partner runs their own IdP (Entra, Okta, Keycloak). Their service calls
yours carrying *their* token. You present it here and get back an AXIAM token scoped to what
the resolved AXIAM user may actually do.

#### What to pass

| Parameter | External exchange |
|---|---|
| `subject_token` | the **partner's** access token (a JWT) |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` — or `…:access_token`; both are accepted for an external issuer. **Required** (§15.1); there is no default to fall back on |
| `actor_token` | **MUST be omitted.** Delegation across a trust boundary is not supported in v1 and is refused with `invalid_request` |
| `scope` | as always: omit to get everything the trust configuration and the user's permissions allow, or name scopes to be told about any you cannot have |

An SDK MUST NOT inspect the subject token to decide which `subject_token_type` to send, and
MUST NOT default `subject_token_type` on the caller's behalf. Which kind of token the caller
holds is something only the caller knows, and a wrong guess here is the difference between a
request that is refused and one that is silently reinterpreted.

**This is enforced by making the parameter required** ([§15.1](#§151-canonical-operation-and-endpoint-map)),
not merely by documenting a prohibition. An optional parameter with a sensible-looking default
is a default an SDK applies on every call where the caller said nothing — which is exactly the
guess this clause forbids, relocated from the SDK's code into its signature. Where the language
can refuse to compile a call that omits it, it MUST; where it cannot (a nullable field, a
zero-initialised struct), the SDK MUST fail **client-side with no wire call**, the same way
§15.1's missing-client-secret check does. A request that reaches the server with a type nobody
chose is the failure mode this section exists to prevent.

#### Which errors mean what

`error` codes are unchanged (§15.3). One `error_description` is normative and an SDK MAY
match on it:

> `the subject token's issuer is not configured for token exchange`

carried on `invalid_grant`. It is the **only** external failure that is distinguishable, and
it means *fix the AXIAM trust configuration* (an operator must enable token exchange for
that federation provider and list your audience) rather than *fix your token*. Every other
external failure — bad signature, expired, too old, audience not accepted, wrong token kind,
subject not linked — answers `invalid_grant` with a generic description, deliberately:
which of a dozen checks refused a token is a map of the server's validation order, drawn one
request at a time.

Two refusals worth surfacing with their own guidance:

- `invalid_request` naming a **refresh or ID token type**. A refresh token is a
  re-authentication credential and an ID token is an assertion to a client about a login;
  neither is a bearer credential for an API. An SDK MUST NOT retry as a different type.
- `invalid_request` saying the subject token is **already the product of an exchange**.
  Exchanges do not compose. An SDK MUST NOT attempt to re-exchange a token it obtained from
  a previous `token_exchange` call, in either direction.

#### The issued token

Identical in shape to a same-domain exchange, with one additional claim:

```json
{ "ext_exchange": { "iss": "https://partner.example/" } }
```

A resource server MAY read it to tell a cross-domain token from a locally-issued one. An SDK
MUST NOT treat its presence or absence as an authorization input — the `scope` claim and the
server's own checks remain the authority — and MUST NOT strip it when forwarding.

`§15.2` rules 4–7 apply verbatim: no refresh token, never adopted as the client's session,
`issued_token_type` surfaced, and `scope` read as the granted set.

#### Required tests (extends §15.6)

An exchange with an external subject token and `subject_token_type=…:jwt` surfaces the
result unchanged; passing an `actor_token` alongside an external subject token surfaces
`invalid_request` with no retry and no rewriting; the `issuer is not configured` description
reaches the caller intact; a token carrying `ext_exchange` is not re-exchanged by any helper.

Two more pin the required parameter of §15.1. **A subject token that looks exactly like a JWT
does not change what is sent** — without this, an SDK that sniffed the token and one that
obeyed the caller are indistinguishable. And **an omitted type never reaches the wire**: either
the call does not compile, or it fails client-side with no request sent. Assert whichever of
the two the language admits.

---

## §16 Retry Policy (D5)

**Requirement level: MUST (v1.0).**

Two earlier clauses — [§11.2](#§112-semantics-normative-identical-in-all-sdks) rule 5 and
[§14.2](#§142-polling-normative--the-part-implementations-get-wrong) — instruct SDKs to retry
"under the SDK's existing bounded read-only retry policy". **No such policy was ever defined
here.** The survey behind this section was wrong three times before it was right, and the
way it was wrong is itself the argument for §16.7's wire-count requirement.

**Only three SDKs actually retried a read-only failure: Java, Rust, Go.** Two more had a
retry *surface* that no production path invoked, so they retried nothing while appearing to.
The remaining six had neither — only §9's refresh-then-retry-once, a different mechanism.

| SDK | Attempts | Base | Cap | Jitter | `Retry-After` | Actually retried? |
|---|---|---|---|---|---|---|
| Java | 3 | 200 ms | 5 s | full | floor | **yes** |
| Rust | 3 | library default | — | none | ignored | **yes** |
| Go | 3 | 100 ms | **none** | **none** | ignored | **yes** |
| TypeScript | 3 | 1000 ms | 8 s | partial | **replaced** the backoff | **no** — helper never called |
| C# | 3 | 200 ms | 5 s | yes | — | **no** — config never read |

Four things in that table, each a different way the same clause goes wrong.

*Go's row.* An uncapped, unjittered `backoff *= 2` is the shape this section most wants to
eliminate: without a cap the wait is bounded by nothing but the attempt count, and without
jitter every client retries in lockstep — the herd a backoff exists to prevent.

*TypeScript's `Retry-After`.* `retryAfterMs ?? backoff(n)` means the hint **replaces** the
computed backoff instead of flooring it, so a `Retry-After: 0` retries immediately. §16.1's
"floor, never a ceiling" was written on principle and then found to describe shipped code.

*The two "no" rows.* TypeScript's helper was exported and unit-tested; C#'s three settings
were defaulted, documented and asserted in tests. Both suites were green. Neither SDK
retried anything. **A tested surface nobody calls is worse than an absent one: the passing
tests are exactly what stop anyone from looking.** Hence §16.7 — an SDK claiming §16
conformance MUST assert the policy through its public `check_access` surface by counting
requests **on the wire**, not against a helper in isolation.

*C#'s configurability.* Its defaults matched this table, but `MaxRetryAttempts`,
`RetryBaseDelay` and `RetryMaxDelay` were publicly settable upward. §16.1 permits *lowering*
the cap or disabling retry, never raising either — a caller who can raise them turns one
client into the herd. (Fixed by clamping, in that SDK's D5 change.)

This section is the missing policy, so the two forward references resolve to one table
instead of eleven guesses.

### §16.1 The policy (normative — every value here is binding)

| Parameter | Value | Why this value |
|---|---|---|
| Attempt cap | **3 total** (1 initial + 2 retries) | Bounds worst-case added latency at ~10 s. A caller who needs more can retry at their own layer, where they know the deadline. |
| Base delay | **200 ms** | Long enough that a retry is not simply re-entering the same overload; short enough to be invisible on a recovery from a single dropped packet. |
| Delay cap | **5 s** | The ceiling on any single wait. |
| Backoff | `min(cap, base × 2^(attempt−1))` | attempt 1 → 200 ms, attempt 2 → 400 ms, both under the cap. |
| Jitter | **full jitter** — the actual wait is uniform random in `[0, backoff]` | Not "backoff ± 10%". Full jitter is what stops a thundering herd: partial jitter keeps every client's retries clustered around the same instant, which is the failure mode retries cause rather than fix. |
| `Retry-After` | **honored, as a floor**: wait = `max(jittered_backoff, retry_after)` | The server is telling you when it will be ready. Retrying sooner is not permitted; the value never *shortens* a wait either, so a `Retry-After: 0` cannot defeat the backoff. |
| Randomness source | Any uniform PRNG. It need not be cryptographic. | The jitter is a load-spreading device, not a secret. |

An SDK MUST NOT make the attempt cap, base, or cap configurable upward beyond these values in
v1.0. It MAY expose a switch that disables retrying entirely — some callers own their own
retry layer and want exactly one attempt — and MUST default that switch to **on**.

### §16.2 What is eligible (normative)

Retry applies **only to operations that change no server state**, and "idempotent" here means
exactly that. It does **not** mean "HTTP GET": AXIAM's authorization check is a `POST` with a
request body and is the single most important operation in this section. An SDK that gates
retry on the HTTP verb will retry nothing that matters.

**Eligible:**

| Operation | Note |
|---|---|
| `check_access`, `can`, `batch_check` | `POST`, side-effect-free. The reason this section exists. |
| JWKS fetch (§10.1) | Cache fill; pure read. |
| OIDC discovery fetch (§12) | Pure read. |
| `oidc_userinfo`, `get_user_info` (§1.1) | Pure reads. |
| `oidc_introspect` | A read *about* a token; mints nothing. |
| `device_poll` on a 5xx or transport failure (§14.2) | The clause that referenced this policy. The retry budget here is **per poll attempt**, and is separate from — and does not consume — the device grant's own `expires_in` polling loop. |

**Not eligible, and an SDK MUST NOT retry them automatically:**

`login`, `verify_mfa`, `logout`, `refresh`, `oidc_exchange`, `device_authorize`,
`device_login`, `token_exchange`, `oidc_revoke`, and every mutation. Two distinct reasons,
both disqualifying on their own:

1. **They change state.** A transient failure after the server committed but before the
   response arrived is indistinguishable, at the client, from one before it committed. A
   silent retry then duplicates a side effect the caller never asked for twice.
2. **Their credentials are single-use.** An authorization code, a device code at the moment
   it is redeemed, and a rotating refresh token are each consumed by the attempt. Retrying
   replays a spent credential, which the server correctly refuses — turning a recoverable
   blip into a hard `invalid_grant` the caller cannot interpret.

`refresh` is additionally out of scope because [§9](#§9-single-flight-refresh-guard) rule 3
already forbids it by name ("no retry loop"). **§16 does not amend §9.** The two mechanisms
compose in one direction only: the operation *inside* a §9 refresh-then-retry may itself be
retried per §16 if it is eligible, but a §9 refresh MUST NOT be re-attempted under §16, and
§16's budget MUST NOT be reset by a §9 refresh occurring mid-operation. One §9 refresh, one
§16 budget, per logical call.

Revocation deserves its own note because §12.1 records that the server treats it idempotently
per RFC 7009. That is a statement about **server** behaviour — revoking an already-revoked
token returns `200` rather than an error. It is not licence for the client to retry a
mutation, and an SDK MUST NOT read it as one.

### §16.3 Which failures retry (normative)

| Condition | Retry? |
|---|---|
| Transport failure — connection refused, DNS, TLS handshake, read timeout | **Yes** |
| `408`, `429` | **Yes** (`429` is exactly where `Retry-After` usually arrives) |
| `5xx` | **Yes** |
| `401` / `AuthError` | **No** — decisive, not transient. §9 owns the refresh path. |
| `403` / `AuthzError` | **No** — the server has decided. |
| `400`, `404`, `409`, and every other `4xx` | **No** — retrying an unacceptable request produces an identical rejection. |
| `OAuthProtocolError` (§12.3 rule 3) | **No**, at any status. It is a protocol answer, not a transport failure. |

The §2 taxonomy maps `408`/`429`/`5xx`/transport all to `NetworkError`, so "retry
`NetworkError` only" is a correct and sufficient implementation of this table in an SDK whose
errors carry no status. An SDK whose errors *do* carry the status MUST NOT retry a
`NetworkError` that came from a row marked **No**.

### §16.4 Interaction with the fail-closed rule

[§11.2](#§112-semantics-normative-identical-in-all-sdks) rule 5 requires the route guard to
**fail closed** — deny with `503 authz_unavailable` — when the authz endpoint is unreachable.
§16 does not soften that. The retry budget is spent *first*; when it is exhausted the guard
denies. An SDK MUST NOT extend the budget because the caller is a guard, and MUST NOT admit a
request because retries were attempted.

### §16.5 Observability

Every retry MUST emit the `retry` telemetry event of [§19](#§19-telemetry-hooks-d5) when the
caller has installed a hook. A retried-then-succeeded operation is otherwise **invisible** —
the caller sees a slow success and no signal at all that the server is failing. That silence
is the standing objection to automatic retry, and the hook is what answers it.

Retries MUST NOT be logged at `info` or above by default. Redaction rules (§2, §11.2 rule 8)
apply unchanged: a retry log line carries the operation and attempt number, never the token.

### §16.6 Per-language naming map

The policy is internal machinery; only the disable switch and the parameters are public
surface, and only where the language's client builder already has a place for them.

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `retry_enabled` | `retry_enabled` | `retryEnabled` | `retry_enabled` | `retryEnabled` | `retryEnabled` | `RetryEnabled` | `retryEnabled` | `RetryEnabled` | `retryEnabled` | `axiam_client_config_set_retry_enabled` | `retry_enabled` |

### §16.7 Required tests

Backoff and jitter MUST be tested with an **injected clock and an injected PRNG** — never by
sleeping. A test that really waits 200 ms is a test nobody runs.

Required: the attempt cap is honored exactly (a permanently failing eligible operation makes
exactly 3 attempts, not 2, not 4); the delay sequence with jitter pinned to its maximum is
`200 ms, 400 ms`; full jitter with the PRNG pinned to `0` waits `0` and with it pinned to `1`
waits the full backoff — proving the range is `[0, backoff]` and not `backoff ± something`; a
`Retry-After` longer than the backoff wins, and one shorter than the backoff does **not**
shorten it; a `403` and a `401` each make exactly one attempt; a **non-idempotent operation
makes exactly one attempt even when the failure is a `503`** (assert the request count on the
wire, not just the raised error — this is the test that catches a retry wired at the transport
layer instead of the operation layer); the guard still denies `503 authz_unavailable` after
the budget is exhausted; a `retry` telemetry event is emitted per retry.

---

## §17 Client-Side Decision Memo (D5)

**Requirement level: MAY (v1.0). Disabled by default.**

[§11.2](#§112-semantics-normative-identical-in-all-sdks) rule 6 says helpers MUST NOT cache
allow/deny decisions. **That rule stands as the default.** This section defines the single
exception: an explicitly opt-in, TTL-bounded memo that a caller must switch on, having read
what it costs them.

The server already ships the same trade with the same shape — `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS`
(default 5 s) and `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` (default `0`, off) — where
the documented bound is that a revoked grant can still be served for up to the TTL. The SDK
memo mirrors that bound rather than inventing a second staleness story.

### §17.1 Semantics (normative)

1. **Off by default.** The default TTL is `0`, which means disabled — not "cache for zero
   seconds". An SDK MUST NOT enable it because it looks like an easy win.
2. **Ceiling of 5 seconds, clamped.** A configured TTL above 5 s MUST be clamped to 5 s, and
   the SDK MUST document that it clamps. This deliberately differs from the server, whose
   equivalent setting is an unclamped `u64` — a known residual that lets an operator
   configure a multi-hour staleness window. The client has no reason to repeat it.
3. **Key.** `(subject_id, resource_id, action, scope, acting_tenant)`, all five, with an
   absent `scope`, `subject_id` or `acting_tenant` each forming a distinct key from any
   present value. A memo that ignores `scope` answers a narrower question with a broader
   answer. One that ignores the acting tenant answers tenant A's question for tenant B,
   because since contract 1.51 one session can ask the same question of two tenants
   (§5.2 rule 1). The acting tenant joined the key in contract 1.52 (C-12), after all
   eleven SDKs had already added it on their own. An SDK MAY also clear the memo when the
   acting tenant changes, but the key alone is what this rule requires.
4. **Allows and denies are cached identically.** Not "cache allows only", and not "cache
   denies only". Asymmetric caching changes the *timing* of the two outcomes and so leaks
   which one occurred to anyone who can observe latency, and it surprises every reader who
   assumed a cache is a cache. Uniform is both safer to reason about and simpler to
   implement.
5. **`reason_code` is cached with the decision** (§11 rule 9) and MUST be returned from the
   memo unchanged. A memo that returns `allowed` but drops the code would make the field
   intermittently absent, which is worse than never having it.
6. **The staleness bound is the TTL, in both directions.** A grant revoked on the server can
   still read as `allowed` for up to the TTL, and a grant just *added* can still read as
   denied for up to the TTL. **Read-your-own-writes is not guaranteed**, and every SDK
   enabling this MUST say so in its documentation in those words. An admin UI that grants a
   role and immediately re-checks is the case that breaks, and it breaks silently.
7. **Never negative-cache a failure.** Only a decision the server actually returned is
   memoized. A `NetworkError`, a `503`, an exhausted §16 retry budget — none of them are
   entries. Caching a transport failure as a deny would turn a blip into a TTL-long outage,
   and caching it as an allow is unthinkable.
8. **Bounded, and safe to drop.** The memo MUST have an entry cap and MUST evict rather than
   grow. It is a latency optimisation; dropping an entry is always correct, so eviction needs
   no coordination.
9. **Invalidated by identity change.** `login`, `logout`, `refresh` and any credential change
   MUST clear the memo entirely. Entries are keyed by subject, not by session, so a
   re-authentication as a different principal would otherwise read the previous principal's
   decisions.
10. **Not consulted by the guard's fail-closed path.** When the authz endpoint is unreachable
    §11.2 rule 5 denies. An SDK MUST NOT serve a stale allow from the memo to paper over an
    outage — that inverts fail-closed into fail-open at exactly the moment it matters.

### §17.2 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `decision_memo_ttl` | `decision_memo_ttl` | `decisionMemoTtl` | `decision_memo_ttl` | `decisionMemoTtl` | `decisionMemoTtl` | `DecisionMemoTtl` | `decisionMemoTtl` | `DecisionMemoTTL` | `decisionMemoTtl` | `axiam_client_config_set_decision_memo_ttl` | `decision_memo_ttl` |

### §17.3 Required tests

With an injected clock: a repeat check inside the TTL makes **no second wire call** and
returns an equal decision including its `reason_code`; the same check after the TTL makes a
fresh call; a deny is memoized exactly as an allow is (assert the wire-call count for both,
not just the outcome); a TTL configured above 5 s is clamped to 5 s; differing `scope`,
`action`, `resource_id`, `subject_id` or acting tenant each miss rather than collide,
absent-`scope` does not hit a present-`scope` entry, and no acting tenant does not hit an
acting-tenant entry (contract 1.52); a `NetworkError` is not memoized (the next call reaches
the wire); `logout` clears the memo; with the memo enabled and the endpoint unreachable the
guard still denies `503 authz_unavailable` rather than serving a stale allow; and with the
default configuration **every** repeat check reaches the wire, proving off-by-default.

---

## §18 Deterministic Shutdown (D5)

**Requirement level: MUST (v1.0).**

Every SDK client owns things the runtime will not reclaim promptly on its own: a connection
pool, a cookie jar, a JWKS refresh timer, an AMQP consumer thread, a gRPC channel. Without an
explicit shutdown the caller has no way to know when those are released, which shows up as
sockets held open past the end of a test, a process that will not exit, and — in the C++ SDK's
D2 investigation — lifecycle gaps that were only visible under load.

### §18.1 Semantics (normative)

1. **Every SDK MUST expose a deterministic shutdown** in whatever form its language already
   uses. Not a new invented spelling: `Drop` plus an explicit `close()` in Rust, a context
   manager in Python, `AutoCloseable` in Java, `IDisposable`/`IAsyncDisposable` in C#, a
   `Closeable` in Kotlin, `Close() error` in Go, `close()` in TypeScript and PHP, a `deinit`
   plus explicit `close()` in Swift, `axiam_client_free` in C, a destructor plus `close()` in
   C++.
2. **Idempotent.** Closing twice MUST NOT raise, double-free, or double-release. Cleanup code
   runs from error paths, and an error path that itself throws hides the original failure.
3. **Releases everything.** Connections closed, pools drained, background threads and timers
   joined or cancelled, the cookie jar cleared. After `close()` returns, the client holds no
   OS handle.
4. **Use after close is an error, not undefined.** A call on a closed client MUST raise the
   SDK's own error type with a message naming the cause. It MUST NOT silently reopen, and MUST
   NOT be undefined behaviour in the manual-memory languages.
5. **Close does not log out.** Shutting down a client releases *local* resources; it MUST NOT
   issue a `logout`, revoke a token, or otherwise reach the network. The session outlives the
   client object, which is what lets a process restart and resume. An SDK that logged out on
   close would silently end sessions on every deploy.
6. **`Sensitive<T>` material is zeroed where the language allows it** (§7), on the same path.

### §18.2 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `close` | `close` (+ `Drop`) | `close` | `close` / `__exit__` | `close` (`AutoCloseable`) | `close` (`Closeable`) | `Dispose` / `DisposeAsync` | `close` | `Close` | `close` (+ `deinit`) | `axiam_client_free` | `close` (+ destructor) |

### §18.3 Required tests

Close is idempotent (twice, no raise); a call after close raises the SDK's error type rather
than reconnecting; the language's scope-based form releases on both the normal and the
exception path (a context manager on a raised exception, a `try`-with-resources on a throw, a
`defer Close()` on an early return); **no network request is issued by close** (assert against
the transport, which is what catches a `logout` accidentally wired in); and — where the
language can observe it — no thread or timer outlives the call.

---

## §19 Telemetry Hooks (D5)

**Requirement level: SHOULD (v1.0).**

A caller who wants metrics currently has to wrap every SDK method or monkey-patch the
transport. This section defines an optional callback surface so they can wire OpenTelemetry,
Prometheus, or a log line **without this SDK taking a dependency on any of them**. No SDK
ships an OTel dependency in v1.0; each ships an OTel adapter as an `examples/` entry, where it
costs nothing to anyone who does not want it.

### §19.1 Events (normative)

| Event | Fired | Carries |
|---|---|---|
| `request_start` | Before an outbound call leaves the SDK | operation name, HTTP method, path template, attempt number |
| `request_end` | After it completes, success or failure | the `request_start` fields, plus status code (or `None`), duration, outcome |
| `retry` | Before each §16 retry wait | operation name, attempt number, the delay about to be taken, the failure that triggered it |
| `refresh` | Around a §9 single-flight refresh | whether this caller performed the refresh or waited on another's |
| `config_clamped` | At client construction, once per clamped setting | the setting's name, the value the caller asked for, the value in force, and the §-reference for the limit |

`path template` means `/api/v1/authz/check`, not the URL with ids substituted in — a metric
label with a UUID in it is a cardinality bomb.

### §19.2 Rules (normative)

1. **Off unless installed.** No hook, no cost beyond a null check.
2. **A hook MUST NOT be able to break the SDK.** An exception thrown by a caller's hook MUST
   be caught and swallowed by the SDK. Telemetry is not permitted to fail an authorization
   check. An SDK MAY report the swallowed error through its own debug log; it MUST NOT
   propagate it.
3. **No secrets, ever.** Hook payloads MUST NOT carry tokens, credentials, `Sensitive<T>`
   contents, request bodies, or `Authorization` headers. This surface exists to be shipped to
   a metrics backend, which is the last place a bearer token should land. What a hook carries
   is the fixed list in §19.1 and nothing else.
4. **Synchronous and fast, by contract.** Hooks are invoked on the calling path. The SDK MUST
   document that a hook must not block, and MUST NOT introduce a queue or thread to defend
   against one — a caller who needs async delivery buffers on their side, where they can pick
   the policy.
5. **Ordering.** `request_start` precedes its `request_end`. A retried operation emits one
   `request_start`/`request_end` pair **per attempt**, with the attempt number distinguishing
   them, plus one `retry` between consecutive pairs. A caller must be able to count real wire
   calls from these events, so one pair per logical operation would be wrong.

6. **A clamped setting MUST be reported, not swallowed.** Wherever this contract requires an
   SDK to clamp a caller-supplied value rather than reject it — §16.1's attempt cap, base
   delay and delay cap; §17.1 rule 2's memo TTL — the SDK MUST emit one `config_clamped`
   event per clamped setting at construction.

   Clamping is the right behaviour: rejecting would break a caller whose configuration was
   merely optimistic, and honoring would let one client become the herd §16 exists to
   prevent. But *silently* clamping means an operator who set a 60-second memo TTL believes
   they have one, and their staleness reasoning is wrong by a factor of twelve with nothing
   anywhere to say so. The event is what makes the clamp discoverable at the only moment it
   can be acted on.

   `config_clamped` is exempt from §19.1's "no cost when uninstalled" framing only in the
   sense that it fires at construction rather than per request; with no hook installed it is
   still a null check and nothing more. It MUST NOT be emitted for a value that was already
   within the limit — an event that fires when nothing happened trains its reader to ignore it.

### §19.3 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `telemetry_hook` | `telemetry_hook` | `telemetryHook` | `telemetry_hook` | `telemetryHook` | `telemetryHook` | `TelemetryHook` | `telemetryHook` | `TelemetryHook` | `telemetryHook` | `axiam_client_config_set_telemetry_hook` | `telemetry_hook` |

### §19.4 Required tests

Events fire in order for a successful call; a failing call still emits `request_end` carrying
the failure; a retried call emits one `request_start`/`request_end` pair per attempt with
distinct attempt numbers and a `retry` between them; **a hook that throws does not fail the
operation** and does not escape; no event payload contains the access token, the refresh
token, or any `Sensitive<T>` content (assert by scanning the serialized payload for the
fixture token value, the same discipline §12/§14/§15 use for error paths); and a client with
no hook installed behaves identically to one before this section existed.

---

## §20 UMA 2.0 — Protection API and Ticket Grant (X2)

**Requirement level: SHOULD (v1.0).** For the **resource-server** side of a
User-Managed Access deployment: a service that guards resources on someone else's behalf
registers them, asks the authorization server what a caller would need, and exchanges the
resulting ticket for a Requesting Party Token.

Server documentation: [`docs/api/uma.md`](../docs/api/uma.md). Wire reference:
`/.well-known/uma2-configuration`.

**The rule an SDK must not paper over: a permission ticket is single-use and is not
retryable.** Every other refusal in this contract can be re-sent after the caller fixes
something. This one cannot — the ticket is spent whether or not the exchange succeeded, and
re-sending it is not a retry but a second, different request. See §20.2 rule 6.

### §20.1 Canonical operations and endpoint map

| Canonical operation | Wire call | Request | Success response |
|---|---|---|---|
| `uma_register_resource` | `POST /uma2/rreg/resource_set` | `application/json` / `ResourceSet` | `201` `ResourceSet` (carries `_id`) |
| `uma_read_resource` | `GET /uma2/rreg/resource_set/{id}` | — | `200` `ResourceSet` |
| `uma_update_resource` | `PUT /uma2/rreg/resource_set/{id}` | `application/json` / `ResourceSet` | `200` `ResourceSet` |
| `uma_delete_resource` | `DELETE /uma2/rreg/resource_set/{id}` | — | `204` |
| `uma_list_resources` | `GET /uma2/rreg/resource_set` | — | `200` array of ids |
| `uma_request_ticket` | `POST /uma2/perm` | `application/json` / array of `RequestedPermission` | `201` `{ "ticket": "…" }` |
| `uma_exchange_ticket` | `POST /oauth2/token?tenant_id=<uuid>` with `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` | `application/x-www-form-urlencoded` | `200` `TokenResponse` (the RPT) |

Signatures (canonical order; each language's §1 casing applies):

```
uma_register_resource(name, *, type=None, resource_scopes=[])
uma_request_ticket(permissions)            # [(resource_id, [scope, …]), …]
uma_exchange_ticket(ticket, claim_token)
```

**The Protection API is bearer-authenticated; the ticket grant is client-authenticated.**
The five `rreg` operations and `uma_request_ticket` carry a **PAT** — an ordinary access
token obtained through `login_client_credentials` with the `uma_protection` scope — in the
`Authorization` header. `uma_exchange_ticket` instead authenticates the client at the token
endpoint (`client_secret_post`, per §12.1 rule 3), because it is a token-endpoint grant.
§12.1's `tenant_id`-as-query rule and its slug-only-client consequence apply to
`uma_exchange_ticket` unchanged.

### §20.2 Semantics (normative)

1. **A PAT is a client-credentials token, not a user token.** The server requires the
   subject to be an OAuth2 client, because a minted ticket is bound to the `client_id` that
   minted it. An SDK MUST NOT offer a user access token as a PAT, and MUST NOT silently fall
   back to the client's ordinary session token if that session is a user session.

2. **`claim_token` is required, though UMA 2.0 §3.3.1 marks it optional.** AXIAM v1
   implements neither incremental authorization nor claims-gathering, so it is the only
   channel that names a requesting party. An SDK MUST make it a required parameter rather
   than defaulting it — in particular MUST NOT default it to the resource server's own PAT,
   which would mint an RPT for the resource server instead of for the user.

3. **Partial grants are refused whole. An SDK MUST NOT auto-narrow and re-ask.** If a ticket
   names three pairs and the requesting party may have two, the answer is `access_denied` for
   the whole ticket. Re-requesting a smaller ticket is a decision for the calling application,
   not for the SDK: the SDK cannot know whether two-of-three is useful or useless to it, and a
   library that quietly obtains a lesser authority than was asked for has answered a question
   nobody posed. Same shape as §15.2 rule 3.

4. **The RPT is not the client's session.** As in §15.2 rule 5, `uma_exchange_ticket` MUST
   NOT adopt the returned token as the SDK client's own credentials — not behind a flag. It
   is the requesting party's token, to be handed onward or checked; adopting it would
   re-privilege every later call the resource server makes as that user.

5. **No refresh token comes back, ever.** The grant deliberately issues none, so an RPT
   cannot outlive the ticket that authorised it. An SDK MUST NOT synthesise one, MUST NOT
   feed the result into the §9 single-flight refresh guard, and MUST document that re-running
   the grant is how you get a fresh RPT.

6. **A permission ticket MUST NOT be retried.** This is an exception to §16, and it is the
   one rule in this section whose violation is a security bug rather than a usability one.
   The ticket is consumed *before* the request is evaluated, so a failed exchange has still
   spent it. An SDK MUST exclude `uma_exchange_ticket` from any automatic retry — including
   §16's idempotent-retry path, including on timeout, and including on `5xx` — and MUST
   surface the failure so the caller can request a **new** ticket.

   Two reasons. The first stands alone and always holds: a retried ticket answers
   `invalid_grant`, so the retry is useless — it can only turn a clear failure into a
   confusing one. The second is why violating this is a security bug rather than a usability
   one.

   That second reason is that single-use is a property of the *server's deployment*, not of
   the protocol. The server decides the race with a transaction its storage engine must
   arbitrate, plus a redemption nonce read back after that transaction commits
   (ilpanich/axiam#302). It holds on a persistent storage engine, which an AXIAM deployment
   is required to run — but an SDK is talking to a server it did not deploy and **cannot
   attest**, and against one running an in-memory datastore the guarantee does not hold. An
   SDK that retries is deliberately generating the concurrent redemption such a server can
   admit twice.

   So an SDK MUST NOT weaken this rule on the grounds that a particular server is well
   deployed. It has no way to know that, the first reason applies either way, and there is
   nothing to gain from the retry even when the second does not apply. Do not retry.

7. **The `permissions` claim is a record, not a capability.** An RPT carries the pairs the
   engine allowed **at mint time**. An SDK that exposes them MUST NOT present them as a live
   authorization answer, and MUST NOT cache them beyond the RPT's own `exp`: a grant revoked
   after issuance does not empty a live RPT, which is exactly why its lifetime is bounded to
   the minimum of the subject token's remaining life, the server's ceiling, and 300 s.

8. **Registration replaces the scope list; it does not merge.** `uma_update_resource` sends
   the resource set's new state. An SDK MUST NOT read-modify-write the existing scopes into
   the payload as a convenience, because that would make removing a scope impossible through
   the SDK.

### §20.3 The `WWW-Authenticate: UMA` challenge

A resource server that refuses a request SHOULD tell the caller how to obtain authority, per
UMA 2.0 §3.2. Two halves, and an SDK may ship either:

- **Emit (resource-server side).** A helper that, given the required `(resource, scopes)`,
  calls `uma_request_ticket` and formats the header:
  `WWW-Authenticate: UMA realm="<realm>", as_uri="<issuer>", ticket="<ticket>"`.
- **Consume (client side).** A helper that parses that header into its three fields.

**The consuming helper MUST NOT automatically exchange the ticket it parsed.** Parsing a
challenge and acting on it are separate decisions: the `as_uri` names an authorization
server the client has not necessarily chosen to trust, and auto-exchanging would send the
user's `claim_token` to whatever host the 403 asked it to. Return the parsed challenge and
let the caller decide.

### §20.4 Error mapping

Extends §2. As in §14.2 rule 5, dispatch on the `error` field of `OAuth2ErrorResponse`
before falling back to the status-code mapping.

| Where | `error` / status | Meaning |
|---|---|---|
| `/uma2/perm`, `/uma2/rreg/*` | `401` | PAT missing, malformed, or expired |
| `/uma2/perm`, `/uma2/rreg/*` | `403` | the token is not a PAT — wrong subject kind, or missing the `uma_protection` scope |
| `/uma2/perm` | `400` | a requested scope the resource has not declared |
| ticket grant | `invalid_request` | `ticket` or `claim_token` absent, or an unsupported `claim_token_format` |
| ticket grant | `invalid_grant` | ticket unknown, expired, already used, or presented by a client other than the one that minted it; or `claim_token` invalid, expired, or from another tenant |
| ticket grant | `access_denied` (**HTTP 403**) | the requesting party is not authorized for every requested pair |
| ticket grant | `invalid_client` | client authentication failed |

**`access_denied` answers 403, not 400.** UMA 2.0 §3.3.6 specifies it, and it is how a
conforming resource server tells "you may not have this" from "your request was malformed".
An SDK MUST map on the `error` field rather than the status, so this stays correct if either
moves.

**No grant-local mapper is needed for this, as of contract 1.12.** The shared `/oauth2/*`
mapper §2 and [§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3 now
describe already dispatches on the `error` field at any status, which is exactly what the
paragraph above asks for — so the ticket grant uses the same mapper as every other
token-endpoint grant. It did not, between contracts 1.10 and 1.11: §12.3 rule 3 enumerated
`400` and `401`, and nine of the eleven SDKs answered by writing a private mapper for this one
grant rather than widening a shared one every other endpoint depended on. Those private mappers
are now removable, and an SDK that still carries one is carrying dead weight rather than a
divergence.

Note the boundary this does not cross. The `/uma2/perm` and `/uma2/rreg/*` rows above are mapped
**by status**, and stay that way: those are Protection API refusals rather than OAuth2 protocol
errors, they carry no `OAuth2ErrorResponse` body, and a `403` there means "this token is not a
PAT" — an authorization failure, which is what `AuthzError` is for.

**The four ticket refusals are one error, deliberately.** Unknown, expired, consumed and
wrong-client all answer `invalid_grant` with one message. An SDK MUST NOT attempt to
re-derive which one occurred or report a guess: the server collapses them because telling
them apart lets a caller probe for live ticket handles, and reconstructing the distinction
client-side hands back exactly what the server withheld. Same discipline as §15.3's
cross-tenant note.

### §20.5 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `uma_register_resource` | `uma_register_resource` | `umaRegisterResource` | `uma_register_resource` | `umaRegisterResource` | `umaRegisterResource` | `UmaRegisterResourceAsync` | `umaRegisterResource` | `UmaRegisterResource` | `umaRegisterResource` | `axiam_uma_register_resource` | `uma_register_resource` |
| `uma_read_resource` | `uma_read_resource` | `umaReadResource` | `uma_read_resource` | `umaReadResource` | `umaReadResource` | `UmaReadResourceAsync` | `umaReadResource` | `UmaReadResource` | `umaReadResource` | `axiam_uma_read_resource` | `uma_read_resource` |
| `uma_update_resource` | `uma_update_resource` | `umaUpdateResource` | `uma_update_resource` | `umaUpdateResource` | `umaUpdateResource` | `UmaUpdateResourceAsync` | `umaUpdateResource` | `UmaUpdateResource` | `umaUpdateResource` | `axiam_uma_update_resource` | `uma_update_resource` |
| `uma_delete_resource` | `uma_delete_resource` | `umaDeleteResource` | `uma_delete_resource` | `umaDeleteResource` | `umaDeleteResource` | `UmaDeleteResourceAsync` | `umaDeleteResource` | `UmaDeleteResource` | `umaDeleteResource` | `axiam_uma_delete_resource` | `uma_delete_resource` |
| `uma_list_resources` | `uma_list_resources` | `umaListResources` | `uma_list_resources` | `umaListResources` | `umaListResources` | `UmaListResourcesAsync` | `umaListResources` | `UmaListResources` | `umaListResources` | `axiam_uma_list_resources` | `uma_list_resources` |
| `uma_request_ticket` | `uma_request_ticket` | `umaRequestTicket` | `uma_request_ticket` | `umaRequestTicket` | `umaRequestTicket` | `UmaRequestTicketAsync` | `umaRequestTicket` | `UmaRequestTicket` | `umaRequestTicket` | `axiam_uma_request_ticket` | `uma_request_ticket` |
| `uma_exchange_ticket` | `uma_exchange_ticket` | `umaExchangeTicket` | `uma_exchange_ticket` | `umaExchangeTicket` | `umaExchangeTicket` | `UmaExchangeTicketAsync` | `umaExchangeTicket` | `UmaExchangeTicket` | `umaExchangeTicket` | `axiam_uma_exchange_ticket` | `uma_exchange_ticket` |
| `uma_parse_challenge` | `uma_parse_challenge` | `umaParseChallenge` | `uma_parse_challenge` | `umaParseChallenge` | `umaParseChallenge` | `UmaParseChallenge` | `umaParseChallenge` | `UmaParseChallenge` | `umaParseChallenge` | `axiam_uma_parse_challenge` | `uma_parse_challenge` |

`uma_parse_challenge` is synchronous in every language — it parses a string — so it takes no
`Async` suffix in C# and returns no future.

### §20.6 `Sensitive<T>` applicability

The **ticket**, the **`claim_token`**, the **PAT** and the returned **RPT** are all bearer
credentials and MUST be wrapped in `Sensitive<T>` (§7) wherever the SDK has that type. None
may be logged at any level, including in error paths.

The ticket deserves explicit mention because its 60-second lifetime invites treating it as
harmless. It is not: for those 60 seconds it is the credential that converts into an RPT, and
a ticket in a log line is a live credential in a log line.

`resource_scopes`, the resource `_id` and the `permissions` claim are **not** sensitive and
MUST remain readable — an application cannot act on an RPT whose contents it may not inspect.

### §20.7 Required tests

Registration round-trips and the returned `_id` is usable as the `resource_id` of a
subsequent `uma_request_ticket`; an update that omits a previously declared scope removes it
(assert the SDK did not merge); a ticket request naming an undeclared scope surfaces the
`400` unchanged; a happy-path exchange returns an RPT whose `permissions` carry the requested
pairs; **a failed exchange is not retried** — assert exactly one outbound request for a
`5xx`, for a timeout, and for `invalid_grant`, since this is the §16 exception; the RPT is
not adopted as the client's credentials (assert the client's own token is unchanged after the
call) and carries no refresh token; a `403 access_denied` is surfaced as such and not
auto-narrowed into a smaller ticket request; a user token offered as a PAT is refused by the
SDK or surfaces the server's `403` unchanged; `uma_parse_challenge` parses a well-formed
header and does **not** perform an exchange (assert zero outbound requests); and no ticket,
`claim_token`, PAT or RPT value appears in any log or error payload (scan the serialized
payload for the fixture value, as §12/§14/§15 require).

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

Swift, C and C++ claimed no §12 through contract 1.10. Since their 1.11 port
([§12.6](#§126-swift-c-and-c-ported--contract-111)) they state it like everyone else — but only
once the port has actually landed in that repository: the statement follows the code, never the
contract's expectation of it.

§16 (retry policy) and §18 (deterministic shutdown) are **MUST**-level and land with contract
1.8, so unlike §14/§15 they are not optional and are not named in the statement — an SDK is
either conformant or it is not. Neither was implemented anywhere when 1.8 was written: §16
formalizes a policy §11.2 rule 5 and §14.2 had been *requiring by reference* since before it
existed (two SDKs had improvised one and disagreed; nine had none), and §18 was absent
everywhere except the TypeScript and Python gRPC clients and C's `axiam_client_free`. Both
reach conformance through the D6 re-sync fan-out, one repo at a time, exactly as §12.7, §14
and §15 did. Until a given SDK lands them it is non-conformant on those two sections, and
its README MUST NOT imply otherwise.

§17 (decision memo, MAY) and §19 (telemetry hooks, SHOULD) are optional and, like §14/§15, are
stated by name when shipped:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17 and §19."

§27 (management API, SHOULD) is stated by name for the same reason §14/§15 are — several
SDKs have already published a §1–§13 claim, and widening a range silently would turn a
true statement into a false one without anyone editing it:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19 and §27."

An SDK that ships §27's imperative surface but not the §27.6 declarative manifest states
§27 all the same — the manifest is SHOULD-level *within* a SHOULD-level section — but its
README MUST say which of the two it has, because "supports management" is otherwise read
as both. As with every other section here, the statement follows the code in that
repository, never this contract's expectation of it.

§28 (MCP resource-server helpers, SHOULD) is stated by name on the same footing:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27 and §28."

That sentence read "No SDK may state it at contract 1.48, because none implements it yet"
when §28 was published ahead of every port. **All eleven now implement it**
([§28.10](#§2810-per-sdk-posture)), so all eleven state it, and a repository whose statement
still omits §28 or names a contract version older than the `CONTRACT.md` it vendors is
understating its own code — which contract 1.49 found in six of the eleven and
[§28.11](#§2811-cross-sdk-conformance-review-contract-149) row R-3 tracks to a fix.
The statement follows the code, which is the same rule §12.6 and §27.10 record and the same
one that kept three SDKs from claiming §12 while it was deferred.

§28.12 (RFC 7592 client configuration, contract 1.53) is named rather than folded into
§28, for the reason §12.7 is: eleven SDKs already state §28, and a claim written before
§28.12 existed must keep meaning what it meant. An SDK that ships it writes:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28 and §28.12."

§30 (directory configuration, contract 1.54) is a §27 namespace, and an SDK's §27
generator will emit its six operations as soon as the re-synced registry carries them. It is
stated by name all the same, because what it adds beyond the generated surface — the
`bind_secret` wrapping, the call-site documentation of §30.3's rules — is what the claim
asserts:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28, §28.12 and §30."

§29 (SAML service-provider registration, contract 1.55) is a §27 namespace too, stated by
name for the same reason — what the claim adds beyond the generated surface is §29.2's
absence rule (no key member on `SamlIdpCredential`), §29.3's call-site documentation and
§29.8's tests:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28, §28.12, §29 and §30."

An SDK states it only after porting it from the merge commit that carries the routes
([§29.10](#§2910-per-sdk-posture)); all eleven do at contract 1.59.

§32 (SSF stream registration, contract 1.56) is a §27 namespace too, stated by name for §32.5's
wrapping and §32.3's call-site documentation:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28, §28.12, §29, §30 and §32."

Its receiver helper (§32.7) is independent of the management surface — a relying party that
only receives events needs it and nothing else — so an SDK that ships it names it on its own,
"§32.7", whether or not it states §32.

§31 (outbound SCIM targets, contract 1.57) is a §27 namespace too, stated by name for §31.5's
wrapping and §31.3's call-site documentation (rules 2 and 8):

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28, §28.12, §29, §30, §31 and §32."

An SDK states it only after porting it from the merge commit that carries the routes
([§31.10](#§3110-per-sdk-posture)); all eleven do at contract 1.59.

§33 (CIBA, contract 1.58) is **not** a §27 namespace: an SDK that ships the initiation helper
(`ciba_initiate`, `ciba_poll`, `ciba_await`, `ciba_handle_ping`) names it on its own, "§33", and
the signed-request form "§33.2 signed" when it offers that:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §17, §19, §27, §28, §28.12, §29, §30, §31, §32 and §33."

An SDK states it only after porting it from the merge commit that carries the routes
([§33.10](#§3310-per-sdk-posture)); all eleven do at contract 1.59, and an SDK that signs with a
subset of the three algorithms names them ([§34.2](#§342-clarifications-normative-from-159) P12.7). The §21.3.1 amendment of the same version is
not part of that claim: every SDK that pins vector A re-vendors it.

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
| Swift | unchanged (no §12) | [§12.6](#§126-swift-c-and-c-ported--contract-111) deferral — **lifted in contract 1.11** |
| C | unchanged (no §12) | [§12.6](#§126-swift-c-and-c-ported--contract-111) deferral — **lifted in contract 1.11** |
| C++ | unchanged (no §12) | [§12.6](#§126-swift-c-and-c-ported--contract-111) deferral — **lifted in contract 1.11** |

The table above is a snapshot of contract 1.5 and is kept as written; the three deferrals in it
were lifted by contract 1.11, and each of those SDKs states §1–§12 once its port lands.

`login_client_credentials` credential adoption is a §12.1 **MAY**: TypeScript, PHP, and Go
implement it as an opt-in flag; Rust, Python, Java, and Kotlin skip it; C# exposes the flag and
throws `NotSupportedException` when it is set. All five positions are conformant — divergence on a
MAY is not a defect.

### C# `Grpc.Tools` Exception

C# is the one documented deviation from the `buf` codegen pipeline. The C# SDK uses `Grpc.Tools` MSBuild integration (via a `<Protobuf Include=... GrpcServices="Client" />` entry in the `.csproj`, pointed at the `proto/` copy vendored in its repo) to generate gRPC client stubs at build time, rather than a `buf generate` plugin entry. This is intentional (D-01 in `15-CONTEXT.md`) and does not affect behavioral conformance with §1–§10. All other SDKs (Rust, TypeScript, Go, Python, Java, PHP) run `buf generate` as their codegen step.

### Breaking Changes Log

No SDK currently ships a dedicated `CHANGELOG.md`; breaking changes to this contract are
recorded here until one exists.

- **2026-10-10 (1.0.0 release, answers to #588 and the platform's additions, contract 1.60)** —
  **clarifications and two optional fields; one SDK-side breaking change (Rust's `ReplayStore`).**
  Issue #588 collected the sixteen questions the eleven follow-up ports of contract 1.59 raised;
  **§34.4** answers each in one testable sentence, amends §34.2 (P1, P4, P6, P10, P11, P12.2, new
  P12.9) and the §34.3 rows it touches (R-2, R-4, R-8, R-11, R-14, R-17, R-20, R-22, R-23, R-27) in
  place, and lists which SDK fixes which row, its "Fixed in" column filled by the ports.

  - **§32.7 / P4 — the replay store is fallible.** A store that cannot answer gives no verdict:
    the SET is neither refused nor acknowledged and stays unjudged. 1.59's documentation route
    for a store that answers a bare `bool` is **withdrawn**; Rust's `ReplayStore::check_and_record`
    becomes fallible — **a breaking change, released with 1.0.0 (D-7)** — and Go and Swift change
    their store interfaces; the other eight verify.
  - **P6** — a successful cold-cache key fill does not count toward the once-a-minute refetch
    limit; a failed fill does. **P10** — a §16 retry inside `ciba_poll` never waits past the
    deadline. **P11** — C#, C and C++ give each never-retried write a fresh connection.
    **P12.2** — one validation error for every local refusal; event types as strings.
    **P12.9** — an input type is built for submission, not decoded.
  - **§31** — `ScimTargetInput` gains an optional `expected_updated_at`; **§27.15** — the
    `notification_rules` models gain an optional `window_minutes`. **§14**, **§33.3** — the
    `403` on the device approval routes and the pending-request list as console surfaces.
    **§15.2 rule 9** — an `actor_token` must have been issued to the exchanging client
    (`400 invalid_request` otherwise). **§8**, **§2**, **§13**, **§21.3**, **§27.15** — informative
    notes. **§21.3.1**, **§21.9** — vector A's abridgement and the DPoP-decline reason.
    **New §35** — certificate revocation lists, informative.

  `openapi.json` and `management-registry.json` are regenerated by the same release (schemas
  and one console route; no registry operation is added). **Re-sync required for 1.60** in all
  eleven SDK repositories, from the **merged** commit that carries this entry (the 1.49 rule),
  together with the SDK's rows in §34.4.

- **2026-10-09 (Phase 23 close-out, cross-SDK review of the 1.53 – 1.58 ports, contract 1.59)** —
  **clarifications; no wire change.** The review that §28.10's rule and §28.12.7, §29.10 … §33.10
  name re-read the eleven ports of §28.12, §29, §30, §31, §32 with its §32.7 helper, and §33 with
  its §33.2 signed form, from each repository's 2026-10-09 merge, and the §21.3.1 seven-key pin.
  All eleven implement every section in scope; the four REST-only SDKs took §32.7's and §33's
  MAYs. **New §34** records what was read, twelve clarifications P1 … P12, and forty-two
  divergences, each **contract fixed**, **forced by the language, recorded**, or an **SDK fix**
  named as one of eleven follow-ups F-59-01 … F-59-11 (§28.11's shape). The full evidence is
  [`claude_dev/sdk-phase23-ports-conformance-review.md`](../claude_dev/sdk-phase23-ports-conformance-review.md).

  - **§28.12.7, §29.10, §30.10, §31.10, §32.10, §33.10** — filled from the merged ports;
    **§21.10** gains the re-read.
  - **§32.7** (P1 – P7) — `poll` never keeps a `jti` it does not return; a `replayed` SET on a
    later poll is acknowledged; a failed key fetch or store is no verdict (a `5xx` on a push
    endpoint); a store that cannot answer refuses; the RFC 8935 mapping of `malformed` and
    `invalid_type`; how key fetches are counted, and the cache's expiry; `poll` retries `408` and
    `429`. §32.8 helper test 8 gains a two-SET batch.
  - **§33.4, §33.7** (P8 – P10) — on `ciba_poll` a `5xx` is transient whatever its body
    (the server's own `500 {"error":"server_error"}`); anything that fails after a `2xx` is
    terminal; the deadline's anchor, an early stop and the injected clock; cancellation is a MAY.
    §33.8 test 8's `500` carries the body.
  - **§12.3 rule 3, §16** (P11) — the §9 exemption covers the tenant-path form of the OAuth2
    endpoints; "never retried" includes an HTTP library's transparent re-send.
  - **§28.12.2 rule 4, §29 – §33 shapes** (P12) — declared members only, in unknown union arms
    too; an unknown value refused locally and still renderable; no `null` for a write-only
    secret; no `[]` for a list the read lacked; a plain string accepted at a `Sensitive<T>`
    argument; equivalent forms that conform; §33.2 signed per algorithm; three names.
  - **Conformance Statement** — the three "none does yet" sentences now say all eleven do.

  `openapi.json`, `management-registry.json` and `proto/` are **unchanged**. **Re-sync
  required for 1.59** in all eleven SDK repositories, `CONTRACT.md` only, from the **merged**
  commit that carries this entry (the 1.49 rule), together with the SDK's follow-up.

- **2026-10-05 (T23.7.3, G-7, contract 1.58)** — **non-breaking / additive, with one in-place
  amendment an SDK may have to re-vendor.** A new section,
  [§33](#§33-ciba--client-initiated-backchannel-authentication-contract-158): AXIAM as an OpenID
  Connect CIBA authorization server (CIBA Core 1.0, **poll and ping**, no push), the client's half.
  Four operations on the OAuth2 handle — `ciba_initiate` (`POST /oauth2/bc-authorize`),
  `ciba_poll` (the token endpoint with `urn:openid:params:grant-type:ciba`), `ciba_await` (poll
  to a terminal outcome, honouring `interval` and `slow_down`) and `ciba_handle_ping` (verify the
  server's `Authorization: Bearer` ping and return the `auth_req_id`) — SHOULD in the seven
  full-surface SDKs and MAY in the other four; the signed authentication request
  (CIBA Core §7.1.1, FAPI-CIBA) is §33.2's optional form. The server rules an SDK can observe
  (§33.3): **`unknown_user_id` is never sent** (an unknown, locked or ineligible user is answered
  like a real one and simply expires), `invalid_binding_message`, the interval's `slow_down`
  growth, expiry with ten minutes' retention, single-use redemption, lockout applied at request,
  approval **and redemption**, the `fapi2` rules, `request_uri`, `login_hint_token` and
  `user_code` refused, dynamic registration by initial access token only, and the dedicated
  `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN` bucket. §33 narrows §16: **`ciba_initiate` MUST NOT
  be retried**. Three values are `Sensitive<T>` from the first version an SDK ships it
  (`auth_req_id`, `client_notification_token`, the signed request's key material; §33.5);
  §27.5 gains no row, because CIBA is not a management namespace and the registry gains no
  operation (190 across 28). Sixteen required tests per SDK that ships the signed form (nine
  initiation, four ping, three signed). The Conformance Statement gains §33's sentence.

  - **§21.3.1 is amended in place** (D-61). `mtls_endpoint_aliases` gains a **seventh** member,
    `backchannel_authentication_endpoint`: a `tls_client_auth` CIBA client authenticates at
    `bc-authorize` as at the token endpoint and has no other way to present its certificate on
    a two-listener deployment. Vector A carries it at the top level and in the alias object; the
    vector text, the assertions table and §21.3 rule 2 say "seven" where they said "six", and
    §21.5's table lists the four CIBA discovery members. **An SDK whose test pinned the six keys
    fails against the new vector and against a server that publishes seven; it must re-vendor
    `CONTRACT.md` and update the pin.** An SDK that decodes the member as an open map needs no
    code change. No version bump of its own: no SDK has published a CIBA alias, and the
    amendment travels with the section that needs it (the 1.43 precedent).
  - **The routes lead the ports.** `openapi.json` was regenerated by T23.7.1 and T23.7.2
    (`POST /oauth2/bc-authorize`, the CIBA grant on the token endpoint, the approval routes under
    the registry's excluded tag `ciba`, the RFC 7591/7592 members, the discovery members); this
    revision changes no route and no shape.
  - **Re-sync required for 1.58** in all eleven SDK repositories: `CONTRACT.md` and `openapi.json`
    from the **merged** commit (the 1.49 rule); `management-registry.json` carries only a new
    excluded-tag reason and is re-synced with them; `proto/` is unchanged. Implementing §33 is the
    post-merge fan-out (D-35). Per-SDK tests: §33.8.

- **2026-10-05 (T23.6.4, G-6, contract 1.57)** — **non-breaking / additive.** A new
  section, [§31](#§31-outbound-scim-targets-management-api-contract-157): AXIAM as a SCIM 2.0
  **client** of downstream service providers a tenant administrator registers. The management
  namespace `scim_targets` — `list` (paginated), `create`, `get` (with the target's delivery
  state), `update` (**replace**, with the credential kept when absent), `delete` and
  `reconcile` — with `ScimTargetInput.credential` **Sensitive** from the first version (§27.5
  gains two rows); the server rules an SDK can observe (every write validated, `base_url` and
  `token_url` held to the webhook outbound address policy, the group scope checked against the
  tenant, the credential bound to its URL — moving it, or switching the authentication kind,
  without it is a `400` naming the field — an overtaken `update` as `409`, `503` without the
  sealing key, `reconcile` as `202` or `409`, `delete` deprovisioning nothing downstream, the
  permissions `scim_targets:read` and `scim_targets:write`, human principals only, the bucket
  `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN`, audit rows) and, as informative text, the
  level-triggered delivery behind it. Six required tests per SDK. The Conformance Statement
  gains §31's sentence.

  - **The routes lead the ports.** `openapi.json` and `management-registry.json` are
    regenerated in the same task (190 operations across 28 namespaces); the delivery, the
    reconciliation and the dead-letter notification (T23.6.2, T23.6.3) change no shape here.
  - **Re-sync required for 1.57** in all eleven SDK repositories: `CONTRACT.md`,
    `openapi.json` and `management-registry.json`, from the **merged** commit (the 1.49 rule).
    `proto/` is unchanged. Implementing §31 is the post-merge fan-out (D-35). Per-SDK tests:
    §31.8.

- **2026-10-04 (T23.5.2, G-5, contract 1.56)** — **non-breaking / additive.** A new
  section, [§32](#§32-ssf-stream-registration-and-the-receiver-helper-contract-156): AXIAM as a
  Shared Signals Framework transmitter (SSF 1.0, CAEP 1.0, RISC 1.0). The management namespace
  `ssf` — `list_streams` (paginated), `create_stream`, `get_stream`, `update_stream`
  (**replace**, with the push header kept when absent) and `delete_stream` — with
  `SsfStreamInput.authorization_header` **Sensitive** from the first version (§27.5 gains two
  rows); the server rules an SDK can observe (every write validated, the push endpoint held to
  the webhook outbound address policy, the receiver binding to an OAuth2 client with the
  `ssf.manage` scope, the audience unique across the deployment as `409`, the header never
  following the endpoint to another origin, `503` without the sealing key, the status a
  receiver cannot override, independence from the tenant's `ssf_enabled`, the permissions
  `ssf_streams:read` and `ssf_streams:write`, human principals only, the bucket
  `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN`, audit rows); the receiver protocol for reference
  (discovery on both issuer forms, the stream management API, the SET's header, claims, subject
  identifiers and the eight event shapes, push and poll); and the **receiver helper**
  (`verify_set`, `poll`), SHOULD in the seven full-surface SDKs, with its verification order,
  reason codes and replay window. Six management tests and eight helper tests per SDK. The section is
  §32, not §31: the plan already names §31 for G-6's outbound SCIM management (D-44). The Conformance Statement
  gains §32's sentence and §32.7's.

  - **The routes lead the ports.** `openapi.json` and `management-registry.json` are
    regenerated in the same task (184 operations across 27 namespaces); delivery (push, poll,
    the event sources) follows in T23.5.3 and changes no shape here.
  - **Re-sync required for 1.56** in all eleven SDK repositories: `CONTRACT.md`,
    `openapi.json` and `management-registry.json`, from the **merged** commit (the 1.49 rule).
    `proto/` is unchanged. Implementing §32 is the post-merge fan-out (D-35); T23.5.4 opens the
    tracking issue. Per-SDK tests: §32.8.

  - **Amended before 1.56 shipped (T23.5.3, G-5; D-53).** No version bump: no SDK has ported §32
    and 1.56 is unreleased, so the text is corrected in place (the T23.2.9 precedent for §29
    under 1.55). (a) The status paragraph no longer says delivery "follows in T23.5.3": it has
    landed, with `openapi.json` regenerated for the poll route. (b) §32.6 states the poll
    endpoint's details the first text left to the code: `400` on a push stream, a negative
    `maxEvents`, a malformed body or more than 1 000 `ack` / 100 `setErrs` entries; `413` over
    32 KiB; an empty `sets` for a paused or disabled stream; the `ssf_stream.poll_set_error` audit
    row; the 30-second long poll and the rule that **one long poll waits per stream per
    instance**, a second answering at once. (c) §32.6 states the **push response mapping** (D-49,
    completed by D-53): every `4xx` other than `404`, `408` and `429` is dead-lettered (a `400`
    with a known RFC 8935 code keeping its code, the rest `HTTP <status>`), `3xx` and anything
    else retry, and **redirects are not followed**, by construction. (d) §32.6 states the
    **event sources**: `x509` is not emitted (no user-certificate binding), the directory sync
    never re-enables an account, an administrator's password write is SCIM's, SCIM `DELETE` is an
    `account-purged`, WebAuthn kinds map to `fido2-platform` / `fido2-roaming`, and
    `assurance-level-change` follows a step-up through a server-side record. (e) §32.6 names the
    retry variables `AXIAM__SSF_PUSH__MAX_ATTEMPTS`, `…__BACKOFF_BASE_MS` and
    `…__BACKOFF_CEILING_MS` and the seven-day lifetime of the push dead-letter queue. None of it
    changes a management shape, an operation or a required test.

  - **Amended before 1.56 shipped (F4 W4 P23W4-11; D-55, maintainer decision on
    ilpanich/axiam#539).** No version bump: no SDK has ported §32 and 1.56 is unreleased, so the
    text is corrected in place. (a) **§32.3 rule 13**, new: SSF requires per-tenant issuers in a
    deployment of more than one tenant. With `AXIAM__AUTH__TENANT_ISSUER_PATHS` off and more
    than one tenant (counted across organizations), SSF behaves for every tenant as with
    `ssf_enabled` off — discovery `404`, no stream on the receiver API, nothing produced, held,
    verified or signed, a queued push dead-lettered, a poll answering nothing — and turning
    `ssf_enabled` on is `400` naming the cause; the count is cached for at most 60 s, a change
    is logged once at `WARN` and audited as `ssf.inactive_shared_issuer`. Rule 9 points at it;
    §32.6's discovery, receiver API, push and emitter paragraphs say it. (b) **§32.2**:
    `SsfStream` gains the read-only `transmitter_active` and `transmitter_inactive_reason`, and
    §32.8 test 3 decodes them; the §27 settings response gains the read-only
    `oidc.ssf_inactive_reason`. Both are additive response members, so the operation set and
    the number of required tests are unchanged. `openapi.json` and
    `management-registry.json` are regenerated in the same fix.

- **2026-10-04 (T23.2.8, G-2, contract 1.55)** — **non-breaking / additive.** A new
  section, [§29](#§29-saml-service-provider-registration-management-api-contract-155): the
  management surface for AXIAM as a SAML 2.0 identity provider, as a §27 namespace `saml`
  with eleven operations — `get_idp`; `list_service_providers` (paginated),
  `create_service_provider`, `get_service_provider`, `update_service_provider`
  (**replace**) and `delete_service_provider`; `parse_sp_metadata`, which turns an SP's
  metadata (uploaded, or fetched by the server through its SSRF guard) into a draft and
  stores nothing; and `list_idp_credentials`, `issue_idp_credential`,
  `promote_idp_credential` (one transaction: `next` → `active`, the old `active` →
  `retired`) and `retire_idp_credential` for the tenant's signing credential. Nothing is
  `Sensitive`: the registry holds no secret, and `SamlIdpCredential` has **no key member**
  (an SDK MUST NOT declare one). The server rules an SDK can observe: every write through
  `validate_saml_service_provider`; `encrypt_assertions` refused while encryption is
  unimplemented; an SP signing certificate the SSO endpoint could not use refused;
  `entity_id` unique per tenant and immutable; the routes present in every build and
  independent of `saml_idp_enabled`, with `parse_sp_metadata` alone `503` in a build
  without SAML; the permissions `saml_sp:read`, `saml_sp:write` and `saml_idp:credential`;
  human principals only; the bucket `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN`; audit rows;
  no retry of writes; seven required tests per SDK (eight after the amendment below). The browser routes (SSO, SLO, IdP
  metadata) stay out of SDK scope and out of `openapi.json`. §29 replaces the number §30
  reserved; §27.1 and §27.5 gain a note; the Conformance Statement gains §29's sentence.

  - **The text leads the routes.** `openapi.json` and `management-registry.json` are
    unchanged at 1.55; the server task that adds the routes (T23.2.5) regenerates both, and
    the eleven operations reach the SDKs' generated §27 surface from that merge.
  - **Re-sync required for 1.55** in all eleven SDK repositories: `CONTRACT.md`, from the
    **merged** commit (the 1.49 rule). `openapi.json`, `management-registry.json` and
    `proto/` are unchanged here; they are re-synced again when the server task lands.
    Implementing §29 is a follow-up per SDK after that, in the post-merge fan-out (D-35).
    Per-SDK tests to add (§29.8, all eleven SDKs): (1) replacement body and required
    members; (2) no `sign_assertions`, open decoding of members and enums; (3) the
    `parse_sp_metadata` exclusivity and the draft passed unchanged to
    `create_service_provider`; (4) no key member on `SamlIdpCredential`, and a nullable
    `retired` on the promotion; (5) `Page<T>` with `search` carried by the auto-pager, and a
    plain list for credentials; (6) no retry of the seven writes on `503`; (7) the
    `400`/`409`/`404`/`503` mapping.

  - **Amended before 1.55 shipped (T23.2.9, G-2; D-43).** No version bump: no SDK has ported
    §29 and 1.55 is unreleased, so the text is corrected in place (D-43 amended rule 9 the same way). (a)
    §29.3 rule 9: a service-account token on the `saml` namespace is `401`, not `403` — the
    shared human-only extractor answers `401` for every human-only family, as §30 says
    (D-43). (b) §29's status paragraph, the Conformance Statement note and §29.10 no longer
    say the routes are absent: T23.2.5 regenerated `openapi.json` and
    `management-registry.json` (179 operations across 26 namespaces at that task, 184 across
    27 with §32), and the eleven `saml` operations carry the ids of §29.1. (c) §29.8 gains an
    **eighth required test** (`get_idp` readiness decoding, nullable credential ids, no
    caching, the implicit tenant), so the count above, "seven required tests per SDK",
    reads eight. (d) §29.10 states that all eleven SDKs are in scope — Kotlin, Swift, C and
    C++ included, since §29 is management REST and they carry REST — and that the manifest
    has no `saml` kind. The tracking issue for the post-merge ports covers 1.53 (§28.12),
    1.54 (§30) and 1.55 (§29) together (D-35); §32 (1.56) is tracked separately.

- **2026-10-04 (T23.3.7, G-3, contract 1.54)** — **non-breaking / additive.** A new
  section, [§30](#§30-directory-configuration-management-api-contract-154): the management
  surface for a tenant's LDAP / Active Directory identity source, as a §27 namespace
  `directory` with six operations (`get`, `set`, `update`, `delete`, `link_account`,
  `get_sync_status`), the write-only `bind_secret` **Sensitive** from the first version,
  the server rules an SDK can observe (every write validated and address-guarded; moving
  the connection requires the secret again — P23W2-01; no enabled directory under
  `opaque_mode = required`; `503` without the deployment's key; linking resolved by the
  directory and revoking), the permissions `directory:read`, `directory:write` and
  `directory:link`, a rate-limit bucket of its own, and six required tests per SDK. §29 is
  reserved for G-2's SAML service-provider registration. §27.5 gains a note; the
  Conformance Statement gains §30's sentence. Sign-in for directory accounts is §1 `login`,
  unchanged.

  - **The text leads the routes.** `openapi.json` and `management-registry.json` are
    unchanged at 1.54; the server task that adds the routes (T23.3.8) regenerates both, and
    the six operations reach the SDKs' generated §27 surface from that merge.
  - **Re-sync required for 1.54** in all eleven SDK repositories: `CONTRACT.md`, from the
    **merged** commit (the 1.49 rule). `openapi.json`, `management-registry.json` and
    `proto/` are unchanged; they are re-synced again when the server task lands.
    Implementing §30 is a follow-up per SDK, after that.

- **2026-10-02 (T23.4.1, RFC 7592, contract 1.53)** — **non-breaking / additive.** AXIAM
  gains RFC 7592's client configuration endpoint, and §28 gains
  [§28.12](#§2812-rfc-7592-client-configuration-operations-contract-153): three
  SHOULD-level operations, `read_client_registration`, `update_client_registration` and
  `delete_client_registration`, with `registration_access_token` **Sensitive** from the
  first version (the #480 lesson). §28.0 is reworded to say its "no network I/O" rules
  describe §28.1–§28.11; nothing an SDK already ships changes.

  - `openapi.json` gains `GET` / `PUT` / `DELETE /oauth2/register/{client_id}`, a third
    security scheme `registration_access_token`, and four optional members on
    `RegistrationResponse` (`registration_client_uri`, `registration_access_token`,
    `jwks`, `jwks_uri`); `registration_client_uri` is now present on every registration
    response. `management-registry.json` regenerates with an unchanged operation count:
    the routes are `oauth2`-tagged protocol surface, excluded from §27, and the exclusion
    reason now names §28.12. An SDK that decodes `RegistrationResponse` strictly MUST
    tolerate the new members — RFC 7591 §3.2.1 already required that.
  - **Re-sync required for 1.53** in all eleven SDK repositories: `CONTRACT.md`,
    `openapi.json` and `management-registry.json`, from the **merged** commit (the 1.49
    rule). `proto/` is unchanged. Implementing §28.12 is a follow-up per SDK, not part of
    the re-sync.

- **2026-09 (C-12 cross-SDK conformance review, contract 1.52)** — **clarifications;
  no wire change.** C-12 re-read the eleven 1.51 ports from each merged `main`. The seven
  questions 1.51 left open had been answered in up to four ways each, and several
  answers were defects. This revision writes one answer to each, as rules N1 … N6, and
  records every divergence in §27.14. There, each row is resolved as contract fixed,
  SDK fixed, or forced by the language. Nothing is removed or renamed. The rules bind
  behaviour an SDK already has, and **an SDK that passes §27.14's fixes is conformant
  at 1.52**.

  - **§10.1 (N1)** — every public function that turns an access token into an identity
    is a rule 9 guard, a no-evidence overload included, and it refuses a bound token.
    A signature-only primitive is exempt only when documented as one. gRPC
    `validate_token` / `introspect_token` are not identity entry points. A guard that
    cannot obtain transport evidence MUST say in its README that it refuses bound tokens.
  - **§17.1 rule 3 (N2)** — the memo key is five components, the acting tenant the
    fifth. Every SDK already keyed on it.
  - **§27.13 S-7 rule 1 (N3)** — a `SubjectAltName` with neither branch or both is
    refused client-side, before any request, and is never silently dropped.
  - **§6.1 rule 11 (N4, new)** — the device credential's lifecycle:
    1. The device POST carries no prior session.
    2. A refused device login changes nothing.
    3. After success, the device token authenticates every request, gRPC included.
    4. The token is held until logout or another session replaces it, and `refresh`
       does not release it.
    5. It is never refreshed.
    6. The new-handle form conforms, and the new handle carries the acting tenant.
    7. §27.4 rule 1's session check accepts a bearer.
  - **§5.2 rule 1 (N5)** — the acting-tenant helper:
    1. `X-Axiam-Tenant` is required on authenticated routes and optional elsewhere, and
       nothing goes off-origin.
    2. A new handle and in-place both conform, and the README says which.
    3. There is one gate per session.
    4. A refusal is `AuthzError`.
    5. The record and reset sets are named. `refresh` SHOULD keep the gate. A `200`
       missing the user object MUST NOT record `organization_level: true`.
    6. Tenant ids compare as UUIDs.
  - **§27.6.1 (N6)** — bindings:
    1. The global-role refusal becomes a MUST.
    2. A stated `inherit: true` is accepted and never sent, and an object binding
       requires a resource.
    3. A failed rebind's two end states are defined and reported as data.
    4. `plan` reports a binding Update.
    5. Metadata compares as JSON values, and a stated `{}` is distinct from an omitted
       one.
    6. References resolve by kind.
  - **§27.10** — the per-SDK manifest table is refilled from the merged 1.51 ports.
  - **§27.14 (new)** — the review table, with no open row.

  `openapi.json`, `management-registry.json` and `proto/` are **unchanged**. **Re-sync
  required for 1.52** in all eleven SDK repositories, `CONTRACT.md` only. The C-12 fix
  PRs are merged as they pass review, since none depends on this text. Each SDK then
  re-vendors `CONTRACT.md` in one follow-up PR, from the **merged** commit that carries
  this entry (the 1.49 rule), together with its README conformance line at 1.52.

- **2026-09 (dogfooding remediation, contract 1.51)** — **additive; one behaviour an
  existing SDK must tolerate.** The `axiam-domo-demo` integration (findings DF-001 …
  DF-029) drove a server wave: roadmap Phase 22 of this repository, T22.1 … T22.14b,
  which is what "server T22.n" means in the sections below. This revision brings the
  contract up to what that wave shipped, and closes the five SDK-side findings: DF-008
  acting tenant, DF-009 device login, DF-010 bootstrap, DF-011 manifest, and DF-012
  `TokenService`. It was planned as "1.50", but 1.50 is the entry below, published
  first. Nothing in it removes or renames anything, and every new request field is
  optional: **an SDK written against 1.50 is conformant against 1.51 on everything it
  already does**, with one exception called out below. What it does not yet do is
  listed as SHOULD for the port that brings it.

  - **§1, §1.1, §1.1.1** — three operations join the locked vocabulary.
    `authenticate_device` (REST, §6.1) takes C++'s existing name.
    `validate_token` and `introspect_token` (gRPC, §1.1.1) wrap `TokenService`. They
    resolve the contradiction between §1's closed list and §10.3's MUST, which had no
    method to return `cnf` through. §10.3's wording is unchanged apart from a pointer.
  - **§5.2 rule 1** — the acting-tenant helper moves from MAY to **SHOULD**, with a
    fixed shape: a construction option and an on-client rebind. The value is a UUID,
    checked client-side, because the server silently ignores a malformed one. The header
    is sent only when set. The helper is **REST-only**: the gRPC server reads no tenant
    metadata.
  - **§6.1** — `authenticate_device()` is specified (rules 6–10). It takes no body and
    returns `{ access_token, token_type, expires_in }`. It is reachable only with a
    client certificate, and every refusal is `401` (T22.4). The token is
    **certificate-bound** (`cnf.x5t#S256`, T22.3) whenever AXIAM terminated TLS, and
    §10.1 rule 9 applies to it. The intro no longer says a device certificate is signed
    by the organization CA (T22.1).
  - **§27.0** — the exclusion table lists all five `excluded_operations` the registry
    always had, including `/admin/bootstrap` with its four outcomes and **no helper**
    (D-8).
  - **§27.1, §27.2, §27.4, §27.9** — every figure is re-rendered from the registry: 162
    operations, not 147. `privacy.cancel_delete`, `platform.health` and `platform.ready`
    are the three unauthenticated operations. The surface itself did not change; each
    SDK's §27.8 regeneration already carried it.
  - **§27.5 rule 5, §27.6, §27.6.1, §27.9** — the manifest gains `resources[].metadata`,
    a two-shape role binding (`{ role, resource, inherit? }`) and a `service_accounts`
    section. `apply` returns a created account's `client_secret` exactly as `create`
    does: once, `Sensitive<T>`, on that action's outcome, even when a later action
    fails. It never rotates to reconcile.
  - **§27.10** — the per-SDK manifest table records the two tiers as they are. It also
    records three defects: PHP never reconciles grants or group bindings; PHP, Swift, C
    and C++ never send a resource's parent; Swift, C and C++ default a resource type to
    `"folder"`.
  - **§27.13 (new)** — the DTO and status changes of S-4, S-7, S-9 and S-10.
    **The one exception above is here:** `CertificateType` gains `"Server"`, which
    appears in `certificates.list` responses. An SDK that decodes it as a closed enum
    fails the whole list, and MUST decode it openly (the §27.11 rule 1 lesson).

  `openapi.json`, `management-registry.json` and `proto/` are **unchanged by this
  revision**. They already describe the server as of this commit. The first two are
  listed for re-sync because all eleven SDKs last vendored them before Phase 22 landed;
  their copies carry no `"Server"` and no `inherit`. `proto/` is already current in
  every SDK that vendors it, and is listed so that the four artefacts travel together.

  **Re-sync required for 1.51** in all eleven SDK repositories —
  `axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
  `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`,
  `axiam-go-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk`. Vendor
  `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/` from the
  **merged** commit that carries this entry (the 1.49 rule), regenerating the §27
  surface in the same commit. Until they do, `scripts/check-sdk-artifact-drift.py`
  reports all eleven as stale, which is expected and is the gate doing its job. The
  ports are one PR per repository, Rust first as the reference (the dogfooding plan's
  C-1 … C-11 and §8).

- **2026-09 (contract 1.50)** — **security fix; source-breaking for one field.**
  T21.4 added `oauth2_clients.create_registration_token`, whose response carries
  `initial_access_token` — the plaintext RFC 7591 §1.2 bearer a registering client
  presents, returned **once** and never retrievable, exactly like
  `scim_tokens.create`'s `provisioning_token`. It was never added to the registry's
  curated `(schema, field)` table, so `management-registry.json` published
  `sensitive_response_fields: []` for it and all eleven generators emitted a bare
  string: the one-time credential appeared in every model's debug/`toString`
  rendering, the leak §7 rule 1 and §27.5 exist to prevent. It was found during the
  F-28-01 re-sync, by the Java port's generator review.

  - **§27.5** gains the row, so the table lists **fifteen** operations, and rule 3's
    "once" list names the operation. `scripts/gen-management-registry.py`'s
    `SENSITIVE_FIELDS` gains `("CreateRegistrationTokenResponse",
    "initial_access_token")`; `management-registry.json` regenerates with exactly
    that one change. `openapi.json` and `proto/` are **unchanged**: the wire shape
    is the same, only the SDK-side type moves.
  - **Source-breaking for a caller that reads the field.** In an SDK whose §27
    surface already shipped the operation, `initial_access_token` changes from the
    plain string type to `Sensitive<T>`, and reading it now takes the language's
    explicit reveal (§7). That is the point of the change; an SDK MUST NOT keep a
    plain-string accessor alongside it for compatibility, since the plain accessor
    is precisely the leak. Nothing else on the surface moves.
  - The three unnumbered T21.4 / T21.5 / T21.6 entries below predate 1.49 and were
    published as part of its text; every SDK re-synced to 1.49 already carries them.
    1.50 does not alter them.

  **Re-sync required for 1.50** in all eleven SDK repositories —
  `axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
  `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`,
  `axiam-go-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk` — for
  the vendored `CONTRACT.md` and `management-registry.json`, regenerating the §27
  surface in the same commit, from a **merged** `main` (the 1.49 rule).

- **2026-09 (§28 cross-SDK conformance review, contract 1.49)** —
  **non-breaking / clarifying.** No new operation, no signature change, no
  vocabulary change. Contract 1.48's §28 was implemented independently in
  eleven SDKs; the cross-SDK review
  ([`claude_dev/sdk-mcp-helpers-conformance-review.md`](../claude_dev/sdk-mcp-helpers-conformance-review.md),
  T21.9 T9d) read all eleven and found six places where §28's text was wrong,
  silent, or unsatisfiable on a framework it names. This revision makes the
  contract describe the behaviour the eleven already share, and records every
  divergence in a new [§28.11](#§2811-cross-sdk-conformance-review-contract-149)
  with no open row. It takes its own version for the reason the §12 review took
  1.5: a clarification the eleven must re-sync needs a number to re-sync
  against. An SDK written against 1.48 is conformant against 1.49 unedited.

  - **§28.3 rule 1** no longer pins the `Content-Type` header verbatim. Its
    **media type** binds; a `charset` parameter a framework appends is
    permitted, and a test compares with parameters dropped. Fastify — one of the
    two surfaces §28.7 names for TypeScript — appends `; charset=utf-8` and
    offers no supported way to suppress it, so 1.48's rule could be satisfied
    there only by abandoning the framework's supported API.
  - **§28.4 and §28.9 test 2** state that how `error` is typed is the SDK's own
    choice. Seven ports made a fourth value unrepresentable and four validate a
    string; both secure the property the table states. Where the value cannot be
    written, the `invalid_grant` vector is discharged by a comment at the test
    site naming it, not by an assertion — and never by dropping it in silence.
  - **§28.5 rule 4** gains the resolved-identity clause. A §11 helper that is
    handed the identity the §10 guard already resolved, rather than the request,
    cannot tell "no credential" from "credential rejected"; its missing-identity
    401 carries no challenge, is reachable only where the §10 guard did not run,
    and is recorded in that SDK's §28.10 row. A §11 helper that *can* see the
    request MUST still pick the vector from it.
  - **§28.7's C row** gains `axiam_protected_resource_metadata_url`. §28.1
    already required an SDK to expose `metadata_url`; the row named only `_json`
    and `_path`, and a reader following the row would have made C's integrator
    concatenate the URL by hand.
  - **§28.7** reserves `MCPResourceMetadata` as Go's returned type and states
    that **no other language needs the accommodation**. Go's single package-scope
    namespace cannot hold the pinned function name and the type name at once;
    the seven languages Go's port expected to hit the same wall were each checked
    and none does.
  - **§28.7** also states that "raises the SDK's `ValidationError`" is a
    per-language mapping onto whatever that SDK already raises for a local,
    pre-request refusal — C returns `NULL` with `axiam_error_t`, C++ throws
    `std::invalid_argument` — and that §28.6's "no new type" forbids inventing
    one *for §28*, not using the one a language already has.
  - **§28.10** is now maintained here, by the review, and a port records its
    posture in its own README and `CHANGELOG.md` instead. 1.48 told each port to
    update its own row in a file it holds only as a vendored copy; seven left
    theirs reading *not yet* while shipping §28, three edited theirs, and the
    eleven ended up holding five distinct byte-states of one document. Every
    row is filled in from the merged code.
  - **The Closing Notes' §28 sentence** is corrected: it said no SDK may state
    §28 at 1.48 because none implemented it. All eleven do now.

  **Vendoring rule, stated because 1.48 did not state it.** A vendored artefact
  is re-synced from a **merged** `ilpanich/axiam` `main`, never from a phase
  branch. A branch moves; seven repositories vendored `openapi.json` from one
  and were stale against that same branch within hours, while four declined and
  were stale against the other seven. The `openapi.json` half of 1.48's re-sync
  is therefore deferred to one follow-up, **F-28-01**, recorded in all eleven
  repositories' `CHANGELOG.md`, to be run once Phase 21 lands on `main`.

  **Re-sync required for 1.49** in all eleven SDK repositories —
  `axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
  `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`,
  `axiam-go-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk` — for
  the vendored `CONTRACT.md`, **as part of F-28-01 and not before**, so that the
  eleven return to one file in one step rather than eleven. `openapi.json`,
  `proto/` and `management-registry.json` are unchanged by this revision: §28
  describes SDK behaviour and moves no server API surface.

- **2026-09 (contract version pending, T21.5)** — **non-breaking / additive.**
  Client ID metadata documents reach `openapi.json`. **No version number is
  taken here on purpose**, on exactly the terms T21.3, T21.4 and T21.6 state
  below: 1.47 is T21.2's and 1.48 is T21.9a's, both published, and an SDK
  written against 1.48 is conformant with this change unedited. The next
  version to be published folds this entry in with theirs.

  - `openapi.json` gains **no path**. The change is two schema additions: the
    discovery document (`OidcDiscoveryDocument`) gains an optional boolean
    `client_id_metadata_document_supported`, and the two settings DTOs
    (`SetOrgSettings`, `TenantSettingsOverride`) gain a `cimd` member of a new
    `CimdPolicy` schema. `management-registry.json` regenerates with the spec
    digest; its operation count does not move, because no operation was added.
  - **No SDK operation changes signature or behaviour.** `CimdPolicy` is an
    administrative settings shape, reached only by the settings operations an
    SDK already generates from this document; a generated client picks the
    member up on its next regeneration and an SDK that does not model settings
    is unaffected.
  - **What an SDK's client-side code may do with it.** Nothing is required.
    `client_id_metadata_document_supported: true` in a tenant's discovery
    document says that tenant will resolve a `client_id` that is an `https`
    URL. AXIAM's SDKs guard MCP *servers* rather than drive MCP *clients*
    (plan §7 puts client-side CIMD out of scope), so no §-level surface is
    specified for it here; the member exists so that a client which does
    implement the draft can discover the capability rather than probe for it.
  - **The audience rule is unchanged and is the one that matters.** A client
    materialised from a metadata document inherits the tenant's
    `external_client_allowed_resources` as its `allowed_resources` and cannot
    name its own (plan D3), so §10.1 row 6's expectation — the middleware
    verifies a configured `aud` — holds exactly as written for a token such a
    client obtains.

  The server change behind it is AXIAM Phase 21 T21.5
  (`docs/admin/client-id-metadata-documents.md`).

  **Re-sync required, with the version that folds this entry in**, in all
  eleven SDK repositories — `axiam-rust-sdk`, `axiam-typescript-sdk`,
  `axiam-python-sdk`, `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`,
  `axiam-php-sdk`, `axiam-go-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`,
  `axiam-cplusplus-sdk` — for the vendored `CONTRACT.md` and `openapi.json`.
  `proto/` is unchanged; `management-registry.json`'s operation set is
  unchanged and only its recorded spec digest moves.

- **2026-09 (contract version pending, T21.6)** — **non-breaking / additive.**
  Per-tenant path issuers reach `openapi.json`. **No version number is taken
  here on purpose.** 1.47 is T21.2's and 1.48 is T21.9a's — published below
  while this task was in flight, carrying §28 and folding in T21.3's own
  unnumbered entry. An SDK written against 1.48 is conformant with this change
  unedited (nothing here alters an operation), so rather than take a number for
  a change no SDK has to act on, this is recorded unnumbered for the next
  version to fold in — the same discipline T21.3 followed, and the reason its
  fan-out was not lost. T21.4's entry below is pending on the same terms;
  whichever version publishes next carries both.

  - `openapi.json` gains three paths, all `GET` and all unauthenticated:
    `/.well-known/oauth-authorization-server/t/{tenant_id}`,
    `/.well-known/openid-configuration/t/{tenant_id}` and
    `/t/{tenant_id}/.well-known/openid-configuration`. All three return the
    same `OidcDiscoveryDocument` schema the existing discovery path returns; no
    schema changes. `management-registry.json` regenerates with it, but its
    operation count does not move — discovery is outside the §27 management
    vocabulary — so only the recorded spec digest changes.
  - **The eleven OAuth2 endpoints the `/t/{tenant_id}` scope re-bases are
    deliberately not in the document.** They are the documented endpoints with
    a prefix, served by the same handlers; documenting them would have meant a
    second copy of every path item for no new operation. A client does not need
    them from the specification, because the discovery document it fetches
    names every endpoint in full.
  - **No SDK operation changes signature or behaviour**, and an SDK written
    against 1.47 is conformant with no edit. The three paths are served only
    where the deployment sets `AXIAM__AUTH__TENANT_ISSUER_PATHS`; they are
    documented unconditionally for the same reason `/oauth2/revocations` is,
    because a capability statement that changed shape per deployment would be
    one no SDK could vendor.
  - **What an SDK's resource-server middleware must know.** On such a
    deployment, the `iss` of a token minted through a tenant path is
    `{root}/t/{tenant_id}` rather than `{root}`. An SDK that pins one issuer
    string must be configured with the issuer of the tenant it guards — which
    is the value the discovery document it read reports as `issuer`, so an SDK
    that takes its issuer from discovery is already correct. The **JWKS is
    shared**: one key set verifies every issuer of a deployment, so the
    `jwks_uri` of either form resolves to the same keys. `aud` rules are
    unchanged; §10.1 row 6's expectation holds as written.

  The server change behind it is AXIAM Phase 21 T21.6 (the issuer section of
  `docs/deployment/README.md`).

- **2026-09 (contract version pending, T21.4)** — **non-breaking / additive.**
  RFC 7591 dynamic client registration reaches `openapi.json`. **No version
  number is taken here on purpose.** 1.47 is taken by T21.2, and 1.48 — below —
  has since been published by T9a, closed around exactly two halves (§28 and
  T21.3's folded-in entry). Adding a third half to a number that is already
  published would mean two different contents re-syncing downstream under the
  same label, so this entry stays unnumbered on the same terms T21.3 used: the
  next contract version to be published folds it in.

  - `openapi.json` gains three paths — `POST /oauth2/register` (unauthenticated,
    RFC 7591 §3.1) and `POST` / `GET /api/v1/oauth2-clients/registration-tokens`
    (the initial access tokens §1.2's protected profile needs) — and the
    schemas behind them. `management-registry.json` regenerates: the
    `oauth2_clients` namespace gains `create_registration_token` and
    `list_registration_tokens`, so the operation count moves by **two**.
    `/oauth2/register` is **not** management surface and is excluded by the
    existing `oauth2` tag exclusion — it is a protocol endpoint an MCP client
    calls, not one an administrator does.
  - **No SDK operation changes signature or behaviour**, and an SDK written
    against 1.48 is conformant with no edit. The two management operations are
    new surface an SDK MAY expose; nothing existing moves.
  - **What an SDK MUST NOT infer from a `registration_endpoint` in discovery.**
    Its presence says this *tenant* accepts self-registration; it says nothing
    about whether the caller may register, since `initial_access_token` mode
    answers `403` to a caller holding no handle. An SDK that offers
    registration must treat a `403` with an `invalid_request` body as "not for
    you" rather than as an error to retry. Its **absence** is not a failure
    either: a deployment whose clients are all administrator-created publishes
    no such member, which is the default.

  The server change behind it is AXIAM Phase 21 T21.4
  (`docs/admin/dynamic-client-registration.md`).

  **Re-sync required** in all eleven SDK repositories — `axiam-rust-sdk`,
  `axiam-typescript-sdk`, `axiam-python-sdk`, `axiam-java-sdk`,
  `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`, `axiam-go-sdk`,
  `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk` — for the vendored
  `CONTRACT.md` and `openapi.json`. `proto/` is unchanged.

- **2026-09 (contract 1.48)** — **non-breaking / additive.** Two changes under
  one version, because the second was deliberately left unnumbered for the first
  to carry.

  **§28 — MCP resource-server helpers (T21.9).** A new section: the RFC 9728
  protected-resource metadata document an SDK publishes, the route it is served
  at, the RFC 6750 `WWW-Authenticate` challenge, and one middleware option
  (`resource_metadata_url`) that attaches the challenge to the 401s and to one
  class of 403 the guard already emits. It is the resource-server half of the
  MCP authorization handshake; AXIAM is the authorization server and implements
  none of it. **Requirement level SHOULD, off by default, and additive by
  construction**: with the option unset an SDK's guard is byte-for-byte what it
  is today, which [§28.9](#§289-required-tests)'s regression asserts. §28
  references [§10.1](#§101-minimum-local-verification-set-normative) row 6,
  [§10.2](#§102-revocation-posture-differs-per-transport-informative-must-be-documented),
  [§10.3](#§103-sender-constrained-tokens-over-grpc-contract-117-normative),
  §21.7 and [§11](#§11-declarative-authorization-helpers) and changes none of
  them — [§28.6](#§286-what-§28-does-not-change) is the list, written so that an
  implementer can check it rather than infer it. No existing operation changes
  signature or behaviour, and an SDK written against 1.47 is conformant against
  1.48 with no edit; it simply does not implement §28 yet, which
  [§28.10](#§2810-per-sdk-posture) records for all eleven.

  The server change behind it is AXIAM Phase 21 T21.9; the deployment picture is
  `docs/api/mcp.md` (T21.7).

  **RFC 8707 resource indicators in `openapi.json` (T21.3).** Recorded
  **unnumbered** by T21.3 — "contract version pending" — because the MCP plan had
  reserved 1.48 for §28 and a task that quietly took it would have collided with
  the one that was promised it. It is folded in here, which is what that entry
  said would happen.

  - `openapi.json` regenerates with the RFC 8707 `resource` parameter on
    `/oauth2/authorize`, `/oauth2/par`, `/oauth2/device_authorization` and
    `/oauth2/token`; with `allowed_resources` (an array of absolute URIs) on
    the OAuth2-client create, update and read schemas; and with `aud` on the
    introspection response (RFC 7662 §2.2). `management-registry.json`
    regenerates with it — the operation count is unchanged and only the
    recorded spec digest moves.
  - **No SDK operation changes signature or behaviour**, and an SDK written
    against 1.47 is conformant with no edit. The parameter is opt-in per
    client: a client whose `allowed_resources` is empty — which is every client
    that exists — may not name a resource, and a request that sends none mints
    `axiam:user` / `axiam:m2m` exactly as before, so §10.1 row 6's expectation
    is unchanged.
  - **One thing an SDK's resource-server middleware must NOT infer.** A token
    whose `aud` is neither `axiam:user` nor `axiam:m2m` is not malformed: it is
    a token for somebody else's resource server. AXIAM's own `/oauth2/introspect`
    now reports such a token as `active` and names its `aud`; AXIAM's own REST
    and gRPC endpoints still refuse it. An SDK guarding an AXIAM API keeps
    checking for its configured audience and keeps refusing anything else.

  The server change behind it is AXIAM Phase 21 T21.3
  ([`docs/api/resource-indicators.md`](../docs/api/resource-indicators.md)).

  **Re-sync required for 1.48** in all eleven SDK repositories —
  `axiam-rust-sdk`, `axiam-typescript-sdk`, `axiam-python-sdk`,
  `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`,
  `axiam-go-sdk`, `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk` — for
  the vendored `CONTRACT.md` (both halves) and `openapi.json` (the T21.3 half).
  `proto/` and `management-registry.json`'s operation set are unchanged; the
  registry's recorded spec digest moves with `openapi.json`. Re-syncing does not
  by itself implement §28: a repository that has re-vendored 1.48 still reads
  *not yet* in [§28.10](#§2810-per-sdk-posture) until its port lands.

- **2026-09 (contract 1.47)** — **non-breaking / additive.** Two server
  capabilities an SDK may observe and MUST NOT act on unasked:

  - `token_endpoint_auth_methods_supported` gains `none` (RFC 6749 §2.1),
    listed last. §21.5's row says what it means and what it does not: an SDK
    configured with a client secret keeps sending it, because the registration
    decides how a client authenticates and this member describes the
    deployment. No SDK operation changes signature or behaviour; an SDK written
    against 1.46 is conformant against 1.47 with no edit.
  - `openapi.json` regenerates: `token_endpoint_auth_method` gains the enum
    value `none` on the OAuth2-client create/update schemas, and
    `OAuth2ClientCreatedResponse.client_secret` becomes optional (it is
    **absent**, never empty, for a client registered as public). A generated
    management-layer model for that response must therefore treat the member
    as nullable/optional; every confidential registration still carries it.
    `management-registry.json` regenerates with it — the operation count is
    unchanged at 160 across 24 namespaces, and only the recorded spec digest
    moves.

  The server change behind it is AXIAM Phase 21 T21.2: public clients at the
  token endpoint and the RFC 8252 §7.3 loopback port allowance
  (`docs/admin/public-clients.md`).

  **Re-sync required** in all eleven SDK repositories — `axiam-rust-sdk`,
  `axiam-typescript-sdk`, `axiam-python-sdk`, `axiam-java-sdk`,
  `axiam-kotlin-sdk`, `axiam-csharp-sdk`, `axiam-php-sdk`, `axiam-go-sdk`,
  `axiam-swift-sdk`, `axiam-c-sdk`, `axiam-cplusplus-sdk` — for the vendored
  `CONTRACT.md` and `openapi.json`. `proto/` is unchanged.

- **2026-09 (contract 1.46)** — **documentation only; no SDK behaviour changes, no
  signature moves, and `openapi.json` is byte-identical to 1.45.**

  §26.2 rule 3 now states both forms a spent-`request_uri` refusal can take, and
  which of the two a conformant SDK can reach. The server change behind it closes
  two OpenID Foundation FAPI 2.0 modules — `par-attempt-reuse-request_uri` and
  `state-only-outside-request-object-not-used` — and touches only
  `/oauth2/authorize`, which no SDK operation calls: §12's `oidc_begin` builds
  that URL and hands it to a user agent, and the authorization response is the
  application's to read, not the SDK's.

  Rule 2 is unchanged, and it is what keeps this additive: an SDK's
  `request_uri` authorization URL carries exactly `client_id` and `request_uri`,
  so it never names a `redirect_uri` and never sees the redirected form. An SDK
  written against 1.45 is conformant against 1.46 with no edit, and no test in
  §26.6 changes.

- **2026-09 (contract 1.45)** — **non-breaking / additive.** Three additions, none of
  which changes what an existing name means:

  - `certificates.sign_csr` (§27.1, §27.5) — `POST /api/v1/certificates/sign-csr`. The
    `certificates` namespace's operation count moves from 4 to 5, generated into
    `management-registry.json` like every other; the management surface total goes
    159 → 160 across the same 24 namespaces. Its response is a plain `Certificate` with
    no sensitive field — §27.5 states explicitly that an SDK MUST NOT reuse
    `GeneratedCertificate` for it, since that type's key field is mandatory and would
    always be absent here.
  - `webauthn_setup_register_start` / `webauthn_setup_register_finish` (§24.1, §24.5,
    §24.7, §24.8, §25.1, §25.2) — `POST /api/v1/auth/webauthn/setup/register/{start,finish}`.
    The WebAuthn twin of `mfa_setup_enroll` / `mfa_setup_confirm`: a setup token enrols a
    passkey or a security key as a first factor exactly as it already enrolled TOTP, and
    takes no session credential. The `webauthn` tag is excluded from §27's count, so this
    does not move it.
  - The §5.2 rule 4 `403 mfa_enforced` refusal on `POST /users/{own id}/reset-mfa` — a
    self-service reset is refused where the caller's own tenant enforces MFA, on the same
    footing as `opaque_required`: not an `authorization_denied`, because the caller holds
    every permission the call needs and the refusal is a floor only an administrator can
    lower.

  All three are additive: no existing operation, field, or error code changes meaning, and
  a client written against contract 1.44 compiles and behaves identically against a
  contract-1.45 server.

- **2026-08 (§5.2.2, §27 `roles`/`groups`/`service_accounts` — acting vs principal tenant,
  and service accounts as RBAC principals, contract 1.34)** — additive; nothing is removed
  or renamed.

  - `LoginUserInfo` gains `principal_tenant_id`, `principal_tenant_slug` and `org_id`. All
    three are optional response fields and absent from an older server, where
    `principal_tenant_id` equals `tenant_id` by construction. An SDK that models the user
    object SHOULD expose them; one that does not keeps working unchanged.
  - An SDK that builds a §23 OPAQUE record for the caller's **own** password change MUST
    seal it against `principal_tenant_id` rather than the acting tenant. This is a
    correctness fix, not a new capability: sealing against the acting tenant is refused by
    the server, and an SDK that never switches the acting tenant cannot tell the
    difference.
  - `roles.list_service_accounts` / `assign_to_service_account` /
    `unassign_from_service_account`, `groups.list_service_accounts` /
    `add_service_account` / `remove_service_account`, and `service_accounts.list_roles` /
    `list_groups` are new §27 operations, generated into `management-registry.json` like
    every other. A service account is a principal like any other and the authorization
    engine has always treated it as one; nothing could create the grant, so a machine
    identity could authenticate and then do nothing at all.

- **2026-08 (§27.1, §27.12 — `tenants.export_audit` and the delete precondition,
  contract 1.33)** — **breaking for callers that delete tenants.** Recorded as breaking
  even though nothing is removed or renamed, because working code stops working:
  `tenants.delete` now answers `409` unless `tenants.export_audit` ran against the same
  tenant in the previous six hours, and a caller that deletes tenants today will start
  failing against a beta03 server without any change on its side.

  The management surface grows from 146 operations to 147; the new one is generated from
  `management-registry.json` like every other (§27.8), so an SDK's only work is to
  re-vendor the registry and regenerate. §27.12 states the flow and the two things an SDK
  MUST NOT do with it.

  Deployments also need to grant `tenants:export_audit` to whichever role holds
  `tenants:delete`, or deletion becomes unreachable.

- **2026-08 (§5.2.1 — signing in an organization-level principal, contract 1.32)** —
  **not breaking.** Additive, and for most SDKs a no-op: an SDK already requires a tenant
  at construction (§5), so it already sends one and already reaches the reserved tenant by
  naming its slug, `"organization"`.

  It is recorded because one of its two rules is a **MUST** that existing code can
  violate: an SDK that serializes a blank tenant slug as `""` rather than omitting the
  field breaks organization-level sign-in on four routes, and on
  `/auth/opaque/login/start` it does so before the tenant's OPAQUE mode is read — the
  `404` of §23.4 rule 10 never arrives, so the client has no fallback and sign-in fails
  even where OPAQUE is disabled. An SDK that builds its login body from optional fields
  and drops the absent ones already conforms; one that builds it from a struct with
  `String` defaults should check.

  No field is added, removed or renamed, and no response shape changes.

- **2026-08 (§5.2, §25.7, §27.4 rule 4, §27.11 — organization scope, truthful resend, and
  list search, contract 1.31)** — **not breaking.** Everything in this revision is
  additive, and a caller written against contract 1.30 compiles and behaves identically.
  Recorded because it is the first revision to change a rule that already had SDK code
  behind it — §27.4 rule 4's page request grows a third field — and an SDK author reading
  only the naming maps would take the rest for server-side detail:
  - `resend_own_verification` (§25.1, §25.7) is the one **new server route**,
    `POST /api/v1/users/me/resend-verification`. It does not replace
    `resend_verification`; §25.7 rule 2 forbids routing either to the other.
  - `search` (§27.4 rule 4) is a third optional field on the page request of all twenty
    paginated operations. Adding a field to a struct is source-compatible everywhere the
    struct is constructed by name or by builder; an SDK whose page request is a
    positional tuple or a fixed-arity constructor should add the term as a trailing
    optional rather than reorder anything.
  - `organization_level` (§5.2) and the three §27.11 model fields are optional response
    fields, absent from older servers and defaulted on read.

  Nothing is renamed and nothing changes meaning. `is_global` in particular keeps its
  wire name and its semantics — what an organization-level principal's global grant now
  *reaches* is wider, but that is a server-side authorization property, not a change to
  any field an SDK sends or decodes.

- **2026-08 (§27 — management API, contract 1.30)** — **not breaking.** Recorded here
  because of its size rather than its risk: it is the largest single addition this
  contract has taken, and an SDK author reading only this log would otherwise miss it.
  §27 adds 146 operations across 24 namespaces, all of them additive and all of them on
  namespace handles rather than on the client object, so §1's vocabulary lock is
  untouched and no existing name changes meaning. The three error sub-types it introduces
  (`NotFoundError`, `ConflictError`, `ValidationError`) are language-idiomatic sub-types
  of existing §2 types, as §2 already permits, so code catching the parents keeps
  compiling and keeps working. The one genuinely new artifact is
  `management-registry.json`, which every SDK now vendors alongside `openapi.json` and
  regenerates its management layer from.

- **2026-08 (§25.2 rule 1 — `login` gains a third outcome, contract 1.28)** —
  **breaking for any SDK whose login result is exhaustively matched by callers.**
  `POST /api/v1/auth/login` has always been able to answer `403` with
  `mfa_setup_required: true` and a `setup_token`, meaning "the tenant requires MFA,
  this account has none, here is how to finish". Every SDK mapped that `403` through
  §2 to `AuthorizationError` — telling the caller they lack permission to log in,
  when what the server said was recoverable and came with the means to recover.

  §25.2 rule 1 makes it an **outcome**: a third variant on the SDKs whose `login`
  returns a discriminated result, and a distinct error type carrying the token
  everywhere else. Adding a variant breaks an exhaustive match, which is why this is
  in the log rather than in the additive note below. It is taken because the
  alternative cannot be fixed by documentation — a caller cannot handle a state the
  type does not have, and the state is one a correctly-configured tenant produces
  for every new user.

  Not affected: any SDK whose callers match non-exhaustively, and every caller of
  `verify_mfa`, `refresh` and `logout`, whose shapes are unchanged. No wire change:
  the server has answered this `403` since before §1 was written.

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
  and state "§1–§12"; the device-oriented SDKs (Swift, C, C++) documented §12 as a deferred
  follow-up and kept their existing statement (§12.6 — deferral lifted in contract 1.11).

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

- **2026-08 (§20 UMA 2.0)** — **non-breaking / additive.** Added §20 defining the
  resource-server side of User-Managed Access: the Protection API (`uma_register_resource`
  and the rest of the `rreg` family, `uma_request_ticket`), the `uma-ticket` grant
  (`uma_exchange_ticket`), and the `WWW-Authenticate: UMA` challenge helpers. Purely
  additive — no existing signature changes, and SDKs remain conformant to §1–§19 without it.
  Two rules in it are load-bearing rather than stylistic: **§20.2 rule 6 makes the ticket
  grant an explicit exception to §16's retry policy** (a permission ticket is spent even on
  failure, and retrying it is a concurrent redemption against a server the SDK cannot
  attest — see contract 1.14, which restated the second half of that reasoning), and
  **§20.3 forbids the challenge-parsing helper from auto-exchanging** the ticket it parsed,
  since the `as_uri` names a host the client has not chosen to trust.

- **2026-08 (§12.6 deferral lifted for Swift, C and C++)** — **non-breaking / additive**, with
  one narrow widening. §12.6 previously required `axiam-swift-sdk`, `axiam-c-sdk` and
  `axiam-cplusplus-sdk` to defer §12 in its entirety, forbade partial implementation, and
  forbade their conformance statements from claiming it. Contract 1.11 reverses that: all three
  implement §12 — and, with it, §12.7 — using the names §12.2 had already reserved for them,
  satisfying §12.1–§12.5 unchanged.

  The deferral reasoned from persona (device- and IoT-oriented SDKs have no browser to redirect),
  which is true of `oidc_begin`/`oidc_exchange` and of nothing else in the section:
  `login_client_credentials` is the machine-to-machine login an embedded consumer actually wants,
  `introspect`/`revoke` are ordinary token-endpoint calls about a device's own credentials, and
  §12.6 itself recorded "adding `login_client_credentials` alone to C/C++" as an open follow-up.
  §14 and §20 then settled it from the other side: §14 exists because a device cannot show a
  browser and lists all three, and §20 gave all three a `/oauth2/token` call and a discovery
  document of their own. By 1.10 the "second, parallel OIDC stack" the deferral warned about had
  arrived anyway, in pieces. Porting §12 removes a divergence rather than adding one.

  **The one widening:** §7's C and C++ rows no longer read "no public accessor". That wording was
  load-bearing only while those SDKs handed their callers no token material; §12 returns tokens
  *to* the caller, so rule 3's **single** explicit accessor now applies to them — `expose()` in
  C++, `axiam_sensitive_reveal()` in C — exactly as contract 1.5 resolved the same collision for
  the other eight. Every redaction surface (`operator<<`/`to_string`, log output) is unchanged.

  No existing signature changes anywhere, and no SDK that already shipped §12 is affected. A
  conformance statement still follows the code: each of the three claims §1–§12 only once its own
  port has landed.

- **2026-08 (SDK-Q10 — one decision shape, contract 1.19)** — **non-breaking on the
  wire; one deprecation with a named removal.** The gRPC decision called its
  human-readable reason `deny_reason` and the REST decision called the same string
  `reason`. SDK-Q10 had been deferred three times because every way of closing it
  looked like a break; the answer taken is **deprecate-and-add**, and it breaks
  nothing today.
  - `CheckAccessResponse` gains **`reason` (field 4, explicit presence)** — the
    canonical name, absent on an allow and present on every refusal, matching the
    REST body exactly. `deny_reason` (field 2) is marked `[deprecated = true]`,
    still carries the identical string, and is **removed at AXIAM 2.0** — the only
    dated removal in this log, and the point of writing it down.
  - The migration rule is stated in [§11.2](#§112-semantics-normative-identical-in-all-sdks)
    rule 9's amendment: read `reason`; fall back to `deny_reason` only when
    `reason` is absent on a refusal; expose **one** reason accessor, not two.
  - The same amendment settles two shape questions the SDKs had answered
    inconsistently: the decision has exactly `allowed` + `reason_code` + `reason`
    and **no `resource_type`/`resourceType`** (the server has never had one — a TS
    `AccessCheck` declaring it must drop it), and gRPC `subject_id` is now optional
    the way REST's is, with an **empty** value meaning "the token's subject".
  - Not done, deliberately: renaming the field and taking a major bump, and
    marking `subject_id` proto3 `optional`. Both are wire- or codegen-breaking for
    no behavioural gain; `buf breaking` refuses the second outright (cardinality
    change), which is the same constraint §10.3 records for `CnfClaim`.

## §21 FAPI 2.0 Profile and mTLS Client Credentials (X5)

AXIAM 1.0-alpha24 adds a per-client **security profile** and RFC 8705 mutual-TLS
client credentials. Most of this is server-side and invisible to an SDK. This
section states the parts that are not, so that eleven SDKs do not each invent
their own answer.

### §21.1 What an SDK MUST do (normative)

Exactly one thing is mandatory of **every** SDK, and it is **§10.1 rule 9** —
verifying the `cnf` sender constraint when it is present. Everything else in this
section is informative or optional.

*(One addition, contract 1.28: an SDK claiming the FAPI 2.0 **client** role must
also implement [§26](#§26-pushed-authorization-requests-rfc-9126). This is not a
new obligation so much as a newly-stated one — `profile: "fapi2"` refuses a
registration that does not set `require_par`, so a FAPI 2.0 client that cannot push
an authorization request cannot authorize at all. The guard role, which is what
rule 9 governs, is unaffected.)*

That asymmetry is deliberate. The mechanism's security depends entirely on the
*relying party*: the authorization server can stamp `cnf` into every token it
issues, and it buys nothing at all if resource servers ignore the claim.
Issuing is the easy half.

### §21.2 Client registration fields (informative)

`POST /api/v1/oauth2-clients` and `PATCH /api/v1/oauth2-clients/{id}` accept:

| Field | Type | Meaning |
|---|---|---|
| `profile` | `"standard"` \| `"fapi2"` | The security posture. Default `"standard"` — what every client registered before this contract version already is. |
| `token_endpoint_auth_method` | `"client_secret_post"` \| `"tls_client_auth"` \| `"self_signed_tls_client_auth"` \| `"private_key_jwt"` | Default `"client_secret_post"`. `private_key_jwt` arrived with §21.8 in contract 1.16 and was missing from this row. |
| `tls_client_auth_subject_dn` | string | RFC 8705 §2.1.2. Exactly one of the three `tls_client_auth_*` parameters may be set. |
| `tls_client_auth_san_dns` | string | RFC 8705 §2.1.2. |
| `tls_client_auth_san_uri` | string | RFC 8705 §2.1.2. |
| `self_signed_tls_client_auth_thumbprints` | string[] | Accepted `x5t#S256` values for `self_signed_tls_client_auth`. More than one permits an overlapping rotation. |
| `tls_client_certificate_bound_access_tokens` | bool | RFC 8705 §3.4. Default `false`. Independent of the auth method — a client MAY authenticate with a secret and still receive bound tokens. |

`profile: "fapi2"` is a **switch, not a label**: the server refuses the
registration unless it also sets `require_par`, an mTLS
`token_endpoint_auth_method`, and `tls_client_certificate_bound_access_tokens`.
An SDK exposing client management SHOULD surface the server's `400` message
verbatim rather than pre-validating the combination itself — the bundle is the
server's to define, and a client-side copy of it will drift.

### §21.3 Authenticating as an mTLS client (informative)

An SDK acting as an OAuth2 **client** against a `tls_client_auth` or
`self_signed_tls_client_auth` registration presents its certificate through the
same transport configuration §6.1 already defines for device mTLS, and sends
**no** `client_secret`. The server selects the credential from the
*registration*, never from the request, so sending a secret as well is neither
required nor harmful — but omitting the certificate is fatal, and produces the
same uniform `invalid_client` as every other client-authentication failure.

SDKs are NOT required to implement mTLS client authentication. Where an SDK does
not, it MUST NOT claim §21 conformance for the client role; §10.1 rule 9 (the
guard role) is required of everyone regardless.

**Rule 1 — the certificate, not the secret.** As above: present the certificate
through §6.1 transport configuration and send no `client_secret`.

**Rule 2 — `mtls_endpoint_aliases` (contract 1.40, RFC 8705 §5, normative for
the client role).** When the discovery document carries an
`mtls_endpoint_aliases` object, an SDK making a call **over mTLS** — either to
authenticate as an mTLS client, or to use a certificate-bound token — MUST use
the alias URL for that endpoint in preference to the top-level entry of the same
name. An SDK that is *not* doing mTLS on a given call MUST keep using the
top-level entry.

The member exists because a TLS listener decides whether to request a client
certificate during the handshake, before it has seen any HTTP. "Ask for a
certificate on `/oauth2/token` but not on `/oauth2/authorize`" is therefore not
something one listener can do, and a deployment wanting both runs two — leaving
the client with a question the top-level metadata alone cannot answer.

Three consequences worth stating, because each is a way to implement this
wrongly:

1. **An absent member means "no separate host", not "not supported".** Keep
   using the top-level endpoints. A deployment running `client_auth = optional`
   on one listener serves both populations there and correctly publishes no
   aliases, so an SDK that treats absence as an error refuses the most common
   mTLS topology AXIAM ships.
2. **Only the seven endpoints listed are ever aliased** (six until contract 1.58, which
   added CIBA's `backchannel_authentication_endpoint`; §21.3.1 vector A is the list), and an SDK MUST NOT
   synthesise an alias for one that is not — in particular not
   `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`. Those are
   front-channel or public by design; sending a browser to an mTLS host produces
   a native certificate-chooser dialog most users cannot answer.
3. **`issuer` is never aliased and never changes.** §10.1 rule 3 still requires
   `iss` to equal the discovery document's `issuer` by exact string comparison,
   including for a token minted at an alias endpoint. An SDK that derives an
   expected issuer from the *host it called* will reject every token it obtains
   over mTLS.
4. **An alias's query component is preserved, not appended to** (contract
   1.43). AXIAM's aliases carry the tenant as a query component —
   `https://mtls.example/oauth2/token?tenant_id=…` — because every endpoint
   that authenticates a client requires one, and RFC 6749 §3.1 and §3.2 require
   a client to retain a query component when adding parameters of its own.

   So an SDK that knows its own tenant and **appends** `?tenant_id=` to an
   endpoint it read from discovery produces `…?tenant_id=A&tenant_id=B`, which
   the server cannot deserialise into one tenant; and one that rebuilds the URL
   from the host and path **strips** whatever else the deployment put there.
   Neither is permitted.

   **Replacing the `tenant_id` value with the one the caller actually
   authenticated against is correct and expected**, and is not what this clause
   forbids. The single-tenant document names a tenant and a client targeting it
   agrees; the multi-tenant document names none, and the client supplies its
   own. An SDK doing this MUST displace the existing pair rather than add a
   second, and MUST leave every other parameter as the server wrote it —
   including its encoding, which is not the SDK's to normalise.

   This clause states what AXIAM already publishes and what a correct client
   already does. It is written out because it is the one way to get rule 2
   wrong that fails **only on a two-listener deployment**, which is the
   deployment the rule exists for.

**A revoked certificate authenticates nobody (contract 1.60, informative).** A certificate AXIAM
issued that is revoked or expired, or whose issuing CA is, authenticates no client under either
mTLS method, whatever the registration matches; the answer is the same uniform `invalid_client`
as every other client-authentication failure. An SDK needs no change and MUST NOT retry it with
another credential. The list a relying party outside AXIAM validates against is
[§35](#§35-certificate-revocation-lists-informative).

The discovery cache keying of §12 rule 6 is unaffected: aliases are part of the
document, cached with it, and keyed by the same origin.

#### §21.3.1 Test vectors (normative, contract 1.43)

Three documents, abridged to the members that matter. An SDK claiming the §21
client role MUST pin all three. They live here rather than in a separate
fixture file because this document is already vendored byte-for-byte by every
SDK repository and already drift-gated in CI — a fourth vendored artifact would
be a fourth thing to go stale.

**Vector A — a two-listener deployment.** The member is present; an mTLS call
uses the alias, and only for the seven aliased endpoints. (**Amended in place in
contract 1.58:** the vector gained `backchannel_authentication_endpoint`, at the top level and
as the seventh alias, for CIBA, [§33](#§33-ciba--client-initiated-backchannel-authentication-contract-158).
An SDK whose test pinned the six keys it carried before MUST re-vendor this document and update
the pin; no behaviour changes for an SDK that decodes the member as an open map.)

```json
{
  "issuer": "https://iam.example.test",
  "authorization_endpoint": "https://iam.example.test/oauth2/authorize?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "token_endpoint": "https://iam.example.test/oauth2/token?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "userinfo_endpoint": "https://iam.example.test/oauth2/userinfo",
  "jwks_uri": "https://iam.example.test/oauth2/jwks",
  "revocation_endpoint": "https://iam.example.test/oauth2/revoke?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "introspection_endpoint": "https://iam.example.test/oauth2/introspect?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "device_authorization_endpoint": "https://iam.example.test/oauth2/device_authorization?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "pushed_authorization_request_endpoint": "https://iam.example.test/oauth2/par?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "backchannel_authentication_endpoint": "https://iam.example.test/oauth2/bc-authorize?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
  "end_session_endpoint": "https://iam.example.test/oauth2/logout",
  "mtls_endpoint_aliases": {
    "token_endpoint": "https://mtls.iam.example.test/oauth2/token?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
    "userinfo_endpoint": "https://mtls.iam.example.test/oauth2/userinfo",
    "revocation_endpoint": "https://mtls.iam.example.test/oauth2/revoke?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
    "introspection_endpoint": "https://mtls.iam.example.test/oauth2/introspect?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
    "device_authorization_endpoint": "https://mtls.iam.example.test/oauth2/device_authorization?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
    "pushed_authorization_request_endpoint": "https://mtls.iam.example.test/oauth2/par?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b",
    "backchannel_authentication_endpoint": "https://mtls.iam.example.test/oauth2/bc-authorize?tenant_id=6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
  }
}
```

**Vector A is abridged, and how to pin it (contract 1.60).** It leaves out members a decoder's
discovery type requires — `response_types_supported`, for one — so it does not decode on its own.
The expected way to pin it is to fill **only the `*_supported` lists** from a fixture and to take
every endpoint, the `issuer` and the `mtls_endpoint_aliases` from the vector's own text, read from
this document rather than retyped (§34.3 R-31); a pin that supplies an endpoint, the issuer or
an alias from anywhere else does not pin the vector.

Required assertions against vector A, for an SDK **configured with a client
certificate**:

| Call | Host used |
|---|---|
| token, revocation, introspection, device authorization, PAR, UserInfo, CIBA backchannel authentication | `mtls.iam.example.test` — the alias, with its query component intact (a `tenant_id` may be displaced by the caller's own, never duplicated or dropped) |
| authorization, end session, JWKS | `iam.example.test` — never aliased, never synthesised |
| `iss` validation | compared against `https://iam.example.test`, unchanged |

**Vector B — a single-listener deployment.** Vector A with
`mtls_endpoint_aliases` **absent** (never `null`). Every call, mTLS or not, uses
the top-level entry. An SDK that treats absence as "mTLS unsupported" and
refuses fails here — and this is the most common AXIAM topology, so failing it
is failing the default.

**Vector C — a malformed alias.** Vector A with

```json
"mtls_endpoint_aliases": { "token_endpoint": "/oauth2/token", "userinfo_endpoint": "http://mtls.iam.example.test/oauth2/userinfo" }
```

An SDK MUST **refuse** — an error surfaced to the caller, naming the member —
and MUST NOT fall back to the top-level endpoint. Falling back is the dangerous
answer, not the safe one: the caller asked to authenticate with a certificate,
the operator published something unusable, and quietly presenting the
certificate to the front-channel host authenticates nothing while appearing to
work. Both defects are refusals on their own:

1. **Not an absolute URL.** A relative alias resolves against nothing a client
   holds, and the one base that might seem obvious — the issuer's host — is
   precisely the host the alias exists to name a different one from.
2. **A scheme weaker than the endpoint it replaces.** An alias is a substitute
   for one top-level endpoint, and it must not be weaker than the thing it
   substitutes for: an `http` alias for an `https` `token_endpoint` is a
   downgrade, and mutual TLS over cleartext is a contradiction rather than a
   weaker option.

   The comparison is against **the top-level endpoint of the same name**, and
   getting that wrong is easy in two different directions. "The alias must be
   `https`" refuses the dev and test topologies AXIAM ships — the server's own
   `build_mtls_aliases` accepts `http` for local development, and every SDK's
   suite runs against a mock server that speaks plain HTTP. "Weaker than the
   `issuer`" refuses them too, because an SDK test fixture routinely pairs a
   realistic `issuer` string with loopback endpoints, and a production
   deployment behind a TLS-terminating proxy can legitimately do the same.
   Comparing like with like is the only test that is true in all three.

The refusal is at the **point of use**, not at decode. An SDK with no
certificate configured MUST NOT read the member at all, in any of the three
vectors — not even to validate it. A deployment whose aliases are malformed
must not break the clients that never use them, and asserting that is what
proves the check sits where it belongs.

An SDK with **no certificate configured** is asserted separately in each
vector: every call goes to the top-level entry, including against vector C,
which such an SDK must not even fail on.

### §21.4 RFC 9207 `iss` on authorization responses (informative, act on it)

Every AXIAM authorization response — success and error, for every client,
whatever its profile — now carries an `iss` query parameter naming the issuer.
Discovery advertises `authorization_response_iss_parameter_supported: true`.

An SDK implementing the §12 relying-party flow **SHOULD** compare it against the
issuer it began the flow with and reject a mismatch. That comparison is the
entire defence against the **mix-up attack**, in which a response minted by one
authorization server is delivered to a client's callback as though it came from
another. This is a SHOULD only because an SDK that ignores an unknown query
parameter is not *broken* — but an SDK that talks to more than one issuer and
skips it is exposed, and the check is three lines.

**It must be checked on the error redirect too.** One variant of the attack works
by injecting an error response; a client that validates `iss` on success and
skips it on failure has left ajar the door it just closed.

### §21.5 Discovery additions (informative)

| Field | Value | Meaning |
|---|---|---|
| `authorization_response_iss_parameter_supported` | `true` | §21.4 |
| `tls_client_certificate_bound_access_tokens` | `true` | The server can issue bound tokens. Whether a *given* client receives them is that client's registration and is deliberately not discoverable — this document is scoped to the server, and a per-client answer here would leak one client's posture to every reader. |
| `token_endpoint_auth_methods_supported` | includes `tls_client_auth`, `self_signed_tls_client_auth`, (contract 1.16) `private_key_jwt`, (contract 1.41) `client_secret_basic`, and (contract 1.47) `none`, listed last | Advertised unconditionally; whether an mTLS listener is reachable is a deployment's listener configuration, discovered at connect time. `private_key_jwt` needs nothing from the listeners at all. `client_secret_basic` is a server capability an SDK MUST NOT act on — see §5 rule 3: the list is a statement about the deployment, not an instruction to the client. The same applies to `none` (RFC 6749 §2.1): it says the deployment can serve public clients, never that this client is one — whether a client authenticates, and how, is its registration's answer, and an SDK MUST keep sending the credential it was configured with. |
| `mtls_endpoint_aliases` | an object, or **absent** (contract 1.40) | RFC 8705 §5. Present only when the deployment terminates mutual TLS on a different host from the issuer; absent — never `null` — when it does not. See §21.3 rule 2 for what an SDK owes it. |
| `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported`, `backchannel_user_code_parameter_supported`, `backchannel_authentication_request_signing_alg_values_supported` | the endpoint (tenant-scoped, both issuer forms); `["poll", "ping"]`; `false`; `["PS256", "ES256", "EdDSA"]` (contract 1.58) | CIBA Core §4, [§33](#§33-ciba--client-initiated-backchannel-authentication-contract-158). Advertised unconditionally. The delivery modes and `false` are statements about the **server** — whether a given client holds the grant, and which mode, is its registration's answer, never discoverable; an SDK MUST NOT send a `user_code` or offer push because of what this list says. The endpoint is the seventh member of `mtls_endpoint_aliases` (§21.3.1). |
| `dpop_signing_alg_values_supported` | `["PS256", "ES256", "EdDSA"]` (contract 1.16) | RFC 9449 §5.1. Its **presence** is what says DPoP is supported — the RFC defines no separate boolean. Note the omission of `RS256`: a client library defaulting to RSA-PKCS#1 will be refused, and this list is where it should find that out. |
| `code_challenge_methods_supported` | `["S256"]` (contract 1.42) | RFC 8414 §2 / RFC 7636 §4.3. `S256` and only `S256` — the authorization endpoint refuses `plain`. RFC 8414 defines no default for this member, so its **absence** does not mean "S256"; it means a conforming client cannot establish that PKCE is available at all. It was absent until the first OIDF conformance run reported it NOT FOUND. |
| `token_endpoint_auth_signing_alg_values_supported` | `["PS256", "ES256", "EdDSA"]` (contract 1.42) | RFC 8414 §2 — the JWS algorithms accepted on a `private_key_jwt` client assertion. The same three `dpop_signing_alg_values_supported` lists, and for the same reason: they are one profile (FAPI 2.0 §5.3.1.1), derived server-side from a single constant so the advertisement cannot drift from the verifier. Also absent until the first conformance run named it. |

### §21.6 What is NOT in this contract version

Contract 1.15 listed `private_key_jwt` and DPoP here as absent server-side. Both
landed in contract 1.16; §21.7 and §21.8 replace those two entries. What remains
out of scope:

- **FAPI Message Signing** (JARM, signed request objects, signed introspection
  responses): a separate optional OIDF certification and out of scope for this
  pass. `response_mode=jwt` is not accepted by this server.
- **Certificate-bound *refresh* tokens.** Only access tokens carry `cnf`.
- **Sender-constrained token exchange.** RFC 8693 exchange deliberately does not
  inherit or mint a `cnf` — the exchanging client is a different party from the
  subject, so copying the constraint would bind the new token to a key its
  holder does not have. An SDK MUST NOT synthesise one.

### §21.7 DPoP sender-constrained tokens (contract 1.16, RFC 9449)

**This section is normative for the resource-server role and informative for the
client role.** The normative part is small and it is already stated: §10.1 rule
9's table. This section says what "verify a DPoP proof" means, so that an SDK
which chooses to implement it does so correctly, and so that one which does not
knows exactly what it is declining.

#### §21.7.1 What a DPoP-bound request looks like

```http
GET /api/v1/whoami HTTP/1.1
Host: rs.example
Authorization: DPoP eyJhbGciOiJFZERTQSJ9...        <- the access token, scheme DPoP not Bearer
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6...          <- a proof, freshly signed for THIS request
```

Two consequences an SDK guard MUST handle:

1. **The scheme is `DPoP`, not `Bearer`.** A guard that only ever splits on
   `Bearer ` will not find the token at all. Scheme comparison MUST be
   case-insensitive (RFC 9110 §11.1).
2. **The token endpoint's response says `"token_type": "DPoP"`.** A client that
   hard-codes `Bearer` when building its own outbound `Authorization` header will
   be refused by every DPoP-aware resource server.

#### §21.7.2 Verifying a proof (normative for any SDK that claims to)

An SDK that verifies DPoP proofs MUST perform **all** of the following. Partial
verification is worse than none, because it produces a guard that reports
success:

| # | Check | Why |
|---|---|---|
| 1 | `typ` header is exactly `dpop+jwt` (case-insensitive) | Without it, an access token or ID token signed by the same key is replayable as a proof |
| 2 | `alg` is `PS256`, `ES256` or `EdDSA`, **taken from the embedded `jwk`, not believed from the header** | `alg: none` and RSA-public-key-as-HMAC-secret are both "the token told the verifier how to check the token" |
| 3 | The header carries a public `jwk`, and the signature verifies under it | |
| 4 | The `jwk` carries **no private key material** (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) — reject if it does | RFC 9449 §4.3. Many JWK libraries silently drop these when parsing into a public-key type, so the check MUST be made against the raw header JSON |
| 5 | `htm` equals the request method | |
| 6 | `htu` equals the request URI **with query and fragment removed**, compared without further normalisation | A normalising comparison is where two unequal URIs become equal |
| 7 | `iat` is within a small window of now, in **both** directions (RECOMMENDED 60 s, a named constant) | |
| 8 | `jti` is present, non-empty, and **single-use within that window** | Freshness bounds the window; the `jti` guard is what makes the window unusable. An SDK that cannot store `jti` MUST document that it does not prevent replay within the freshness window |
| 9 | `ath` equals the base64url-unpadded SHA-256 of the access token | Without it, a proof captured on one request can be re-aimed at another token held by the same key |
| 10 | The `jkt` (RFC 7638 thumbprint of the `jwk`) equals the token's `cnf.jkt` | This is the step that ties the proof to the token; the other nine are what make the proof mean anything |

A server may answer `use_dpop_nonce` with a `DPoP-Nonce` response header. A
**client**-role SDK SHOULD retry once with the supplied nonce in the proof's
`nonce` claim; retrying more than once on the same nonce is a loop, not a retry,
and §16's policy applies. A **resource-server**-role SDK is not required to
issue nonces.

#### §21.7.3 Declining is a supported answer

Client-side proof *generation* is a per-language judgement call. An SDK whose
role is resource-server-only, or whose language lacks a usable JOSE
implementation for the three permitted algorithms, MAY decline to implement this
section. Declining means, exactly:

- `jkt`-bound tokens are **rejected**, per §10.1 rule 9 (never accepted as
  bearer tokens);
- the SDK's README says so, in the section that documents token validation; and
- the required negative test for "a `jkt`-bound token is rejected" is present.

What declining does **not** mean is shipping a stub that returns "verified".
§21.9's per-SDK table records which SDKs implement §21.7.2 and which decline.

### §21.8 `private_key_jwt` client authentication (contract 1.16, RFC 7523 §2.2)

**Informative.** The server now accepts `private_key_jwt` as the second FAPI
client-authentication family. A client registers `token_endpoint_auth_method:
"private_key_jwt"` plus **exactly one** of `jwks` (inline) or `jwks_uri`
(RFC 7591 §2 permits at most one), and authenticates by posting:

| Parameter | Value |
|---|---|
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | a JWT with `iss` = `sub` = `client_id`, `aud` = the issuer or the token endpoint URL, a future `exp` within 3600 s, and a unique `jti` |

Signed with `PS256`, `ES256` or `EdDSA`. The server takes the algorithm from the
**registered key**, not the assertion header, so an assertion whose header
disagrees with the registered key is refused rather than reinterpreted. The
`jti` is single-use.

This is optional for every SDK: the client role may keep using
`client_secret_post` or mTLS. An SDK that implements it MUST NOT default the
`aud` to anything — an assertion minted for another authorization server is a
cross-AS replay, and guessing the audience is how one gets minted by accident.

### §21.9 Per-SDK DPoP posture

Each SDK records here whether it implements §21.7.2 proof verification, proof
generation, both, or neither. "Neither" is a supported answer (§21.7.3); an
unrecorded row is not.

| SDK | Verifies proofs (RS role) | Generates proofs (client role) |
|---|---|---|
| rust | yes | yes |
| typescript | yes | yes |
| python | yes | yes |
| go | yes | yes |
| java | yes | yes |
| kotlin | yes | yes |
| csharp | yes | yes |
| php | yes | no — see its README |
| swift | yes | no — see its README |
| c | verification of `cnf` shape only; declines §21.7.2 | no |
| cplusplus | verification of `cnf` shape only; declines §21.7.2 | no |

The two "declines" rows are not oversights. Both SDKs' role in this contract is
resource-server-side validation, and verifying a DPoP proof (§21.7.2) needs the **HTTP
request** — its method, its URL and the `DPoP` header — while the guards of §10 see only a
token. (Until contract 1.60 this paragraph gave a different reason: that
neither SDK ships a JOSE implementation covering PS256/ES256/EdDSA. That stopped being true
for C at contract 1.58, whose §33.2 signer signs all three; the decline stands for the reason
above.) They **reject** `jkt`-bound tokens, which is what §10.1 rule 9 requires of them,
and their READMEs say so.

### §21.10 Per-SDK `mtls_endpoint_aliases` posture (contract 1.43)

§21.3 rule 2 has been normative since contract 1.40 and, until the 2026-09-12
pass, was implemented by nobody: the server published the member and every SDK
ignored it. That is the shape of gap this table exists to make impossible to
repeat — as §21.9 does for DPoP, an unrecorded row is not a supported answer.

Two columns, because they are separable and eight SDKs need only the first.
**Decodes** means the discovery decoder reads `mtls_endpoint_aliases` into an
optional structure and applies the §21.3.1 vector C refusal. **Prefers** means
the mTLS client path actually calls the alias — which only an SDK implementing
the §21 client role has a call to prefer with; check §21.9 before reading a
"no" here as a gap.

| SDK | Decodes the member | Prefers the alias on an mTLS call |
|---|---|---|
| rust | yes | yes |
| typescript | yes | yes |
| python | yes | yes |
| go | yes | yes |
| java | yes | yes |
| kotlin | yes | yes |
| csharp | yes | yes |
| php | yes | yes |
| swift | yes | yes |
| c | yes | yes |
| cplusplus | yes | yes |

Re-read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)):
every SDK pins vector A at seven keys and prefers the `backchannel_authentication_endpoint` alias
on an mTLS client. Three pin it from something other than the vendored text — a fixture (Rust), a
hand fixture without the vector's query (PHP), an inline copy (Swift) — which §34.3 R-31 records.

A `—` means the row has not been filled in for that SDK yet and is **not** a
claim either way. `declines`, with a reason and a pointer to that SDK's README,
is a supported answer; silence is not.

---

## §22 Reactors — AMQP Extension Actors (X1)

**Requirement level: SHOULD (v1.0)** for the eight managed-runtime SDKs (rust,
typescript, python, java, kotlin, csharp, go, php), and — since contract 1.28 —
for swift, c and cplusplus, which ship §22.1–§22.8 and §22.14 over a
caller-supplied transport (§22.11). **The wire protocol below is normative for
anything that speaks it**, including an integrator who supplies their own AMQP
client on one of those three.

A **Reactor** is an external process that subscribes to named hook events on the
AMQP bus and answers back — allow, deny, or a field-allow-listed mutation —
inside a timeout the server declared. It is AXIAM's answer to Zitadel Actions
and Keycloak SPIs, and the difference is the whole design: those load third-party
code *into* the authorization server, and this keeps it outside, reachable only
through a signed reply schema the server validates before it believes a word of
it.

Server implementation: `crates/axiam-amqp/src/reactor/` (wire protocol and
dispatch chain) and `crates/axiam-core/src/models/reactor.rs` (the event
registry, which is the single source of truth this section restates).

**The rule an SDK must not paper over: a reply is an instruction to change a
token or refuse a login, so an unsigned reply is not a weak reply — it is not a
reply at all.** Both directions are signed, with the same §8 v2 primitives and
the same tenant subkey. A reactor runtime that consumes an event without
verifying it, or emits a reply without signing it, is not partially conformant;
it is a hole in the authorization server it is attached to.

§22 is stated **by name**, like §14, §15, §17 and §19 — it is not a continuation
of the §1–§13 run. An SDK that ships a reactor runtime writes, for example:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15 and §22."

### §22.1 Topology

| Element | Value |
|---|---|
| Exchange | `axiam.reactor.events`, type **topic** |
| Routing key | `<tenant_id>.<event>` — e.g. `11111111-1111-1111-1111-111111111111.token.pre_issue` |
| Per-reactor queue | `axiam.reactor.q.<tenant_id>.<reactor_id>`, durable, **declared by the server** |
| Reply correlation | `correlation_id`, inside the signed reply body |

`routing_key()` and `queue_name()` in
`crates/axiam-amqp/src/reactor/protocol.rs` are the definitions; the fixture in
§22.13 carries both rendered for a known tenant so an SDK can assert against them
rather than reimplement the format string.

**Actors consume; they never declare topology.** The server declares the
exchange, the queue, and the bindings from the registration's `events`. An SDK
reactor runtime MUST NOT declare, redeclare or bind its own queue, and MUST NOT
derive a queue name for a reactor other than the one it is configured as. This
is not tidiness: a reactor that can bind is a reactor that can bind itself to
`*.token.pre_issue` and read another tenant's issuance events. Refusing to hold
that capability at all is cheaper than proving each actor does not misuse it.

**Reply addressing.** The reply is published back to the reply queue named in
the delivery's AMQP `reply_to` basic property, echoing the delivery's
`correlation_id` property — standard AMQP RPC. What the **server** authenticates
is not either property but the `correlation_id` field inside the signed reply
body (§22.3), which is the single-use handle binding one reply to one event. An
SDK MUST copy `correlation_id` from the event body into the reply body; copying
it only into the AMQP property produces a reply the server discards.

*Scope note closed as of contract 1.21: the server's lapin `ReactorTransport`
is merged (`crates/axiam-amqp/src/reactor/transport.rs`), `axiam-server`
composes it, and the whole section — signed bodies, field order, validation
rules and the two reply-addressing properties above — is now pinned by a
running implementation exercised against a real broker in
`crates/axiam-amqp/tests/reactor_containerized_test.rs`.*

**One clarification the implementation makes normative for the server, and
changes nothing for an SDK.** An `intercept` event is published to the
reactor's queue directly, through the default exchange, rather than fanned out
through `axiam.reactor.events`. The routing key is per `(tenant, event)`, so a
publish through the exchange reaches every reactor registered for that event at
once, while §22.6's chain dispatches sequentially in priority order and
correlates exactly one reply per event — fanning one `correlation_id` out to
the whole chain would let whichever reactor answered first be consumed as the
reply of whichever reactor the chain was waiting on. The exchange and the
bindings are still declared by the server for every registration and every
event it names. **A reactor runtime sees no difference:** it consumes the queue
whose name it was configured with, and it MUST still not declare or bind
anything.

### §22.2 Message security — §8 in both directions

**§8 and §8b apply to the reactor exchange verbatim, and this section adds no
new cryptography.** The key, the derivation, the canonicalization rule and the
freshness window are the ones §8's "v2 — Replay Protection" subsection already
defines:

- the signing key is the tenant's HKDF-derived AMQP subkey —
  `HKDF-SHA256(salt = "axiam-amqp-hkdf-salt-v1", ikm = master_key, info =
  "axiam-amqp-v1" || key_version || tenant_id_16_raw_bytes)`;
- the MAC is `HMAC-SHA256(subkey, canonical_bytes)`, hex-encoded, compared in
  constant time;
- `key_version` is `2` and a body carrying less than `2` is refused before
  anything else about it is considered;
- `issued_at` must lie within ±`DEFAULT_FRESHNESS_SKEW_SECS` (300 s) of the
  verifier's clock, in **both** directions — a future timestamp is not "extra
  fresh", it is the shape of a captured message held for later;
- `nonce` is a fresh UUIDv4 per message and is **inside** the signed bytes.

What is new here is that the signing is **symmetric in direction**. The server
signs the event with the tenant subkey; the reactor signs its reply with the
same subkey. There is no second key and no asymmetric variant in v1.

**What exactly is signed.** The message serialized to JSON in its declared field
order, with `hmac_signature` present and set to **`null`** — not omitted. This
differs from `AuthzRequest` and `AuditEventMessage` in §8, whose
`hmac_signature` is *absent* from their canonical bytes, and it is the single
most likely place for an SDK to produce a MAC that will not verify. The §22.13
vectors carry `canonical_signed_json` for every message so the difference is
testable rather than memorable.

Field order, event (server → reactor):

`tenant_id`, `event`, `correlation_id`, `payload`, `timeout_ms`, `key_version`,
`nonce`, `issued_at`, `hmac_signature` (**`null` while signing**).

Field order, reply (reactor → server):

`correlation_id`, `tenant_id`, `event`, `decision`, `reason` (omitted when
absent), `patch` (omitted when absent), `require_mfa` (**omitted when
`false`**), `key_version`, `nonce`, `issued_at`, `hmac_signature` (**`null`
while signing**).

The three conditionally-omitted fields are load-bearing. A reply that serializes
`"require_mfa": false` rather than omitting it produces different canonical
bytes and therefore a different MAC; an SDK MUST reproduce the omission rule,
not merely the values.

**Replay, precisely.** On an event a reactor consumes, §8's v2 consumer
obligations apply unchanged: reject `key_version < 2`, reject a stale or future
`issued_at`, and reject a `nonce` already seen inside the freshness window. On a
**reply**, the server's protection is the freshness window plus the
`correlation_id` binding — the correlation is minted per dispatch and the
dispatcher reads exactly one reply for it, so a captured reply re-presented
against any other event is refused as `wrong_correlation` even though its
signature is perfectly valid. The server does **not** maintain a durable
nonce-dedup store for reactor replies the way it does for `AuthzRequest` and
`AuditEventMessage`. An SDK MUST still emit a fresh nonce per reply. It is
inside the signed bytes, so a unique one is what keeps two replies from being
byte-identical — which is what makes a captured reply distinguishable from a
fresh one, and it is the field a server-side dedup store would key on if one is
added. Emitting a constant nonce is not a small deviation; it removes the only
uniqueness the reply body carries beyond its timestamp. §22.13's
`nonce_binding` vector is two replies differing in nothing but the nonce, with
different MACs, so this is assertable.

**§8b transport rules apply.** Reactors connect across a trust boundary:
`amqps://`, a supplied CA bundle, no verification-skip switch, no plaintext
fallback. HMAC does not substitute for TLS and TLS does not substitute for HMAC.

### §22.3 The event (server → reactor)

```json
{
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "event": "token.pre_issue",
  "correlation_id": "22222222-2222-2222-2222-222222222222",
  "payload": { "sub": "alice", "client_id": "portal" },
  "timeout_ms": 500,
  "key_version": 2,
  "nonce": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "issued_at": "2026-07-10T12:00:00Z",
  "hmac_signature": "…"
}
```

| Field | Meaning |
|---|---|
| `event` | A registry name (§22.5). Also the second half of the routing key. |
| `correlation_id` | The single-use handle for this dispatch. Echo it in the reply body. |
| `payload` | Event-specific body. **Never carries a credential, a token, or a signing key** — a reactor is told what is being decided, not handed the means to act on it elsewhere. |
| `timeout_ms` | How long the server will actually wait for *this* dispatch. It is inside the signed body, so it cannot be widened in transit. |

`timeout_ms` is sent so an actor can **shed load rather than answer into a
closed window**. An SDK runtime SHOULD surface it to the handler and SHOULD stop
work and skip the reply when the window has already passed — a late reply is
discarded, and the CPU spent producing it was spent for nothing.

**Chained events carry `_reactor_patch`.** When an earlier reactor in the chain
returned a mutation, the server inserts the accumulated patch into the payload
object under the key `_reactor_patch` before dispatching to the next reactor, so
a later reactor decides against the state that will actually be committed. A
handler MUST treat it as read-only context; echoing it back inside its own
`patch` is not how a field is preserved (the server merges, §22.6).

**What an SDK runtime MUST do before invoking a handler**, in order: reject
`key_version < 2`; verify the MAC; check freshness; check the nonce against its
seen-set. Only then decode the payload. A runtime that hands an unverified
payload to user code has already lost — the handler will act on it, and "we
checked afterwards" is not a check.

### §22.4 The reply (reactor → server)

```json
{
  "correlation_id": "22222222-2222-2222-2222-222222222222",
  "tenant_id": "11111111-1111-1111-1111-111111111111",
  "event": "token.pre_issue",
  "decision": "mutate",
  "patch": { "ext.cost_center": "42", "ext.department": "eng" },
  "key_version": 2,
  "nonce": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "issued_at": "2026-07-10T12:00:00Z",
  "hmac_signature": "…"
}
```

| Field | Type | Rules |
|---|---|---|
| `decision` | `"allow"` \| `"deny"` \| `"mutate"` | Lowercase, closed set. |
| `reason` | string, optional | Audited on a `deny`. A deny with no reason still denies — the reason is for the audit trail, not for the decision. The server substitutes `"denied by reactor"` when it is absent. |
| `patch` | flat map of **string → string**, optional | `mutate` only, and only on a mutable event. Values are strings; there is no nested or typed patch in v1. |
| `require_mfa` | bool, optional (omitted when false) | `login.post_auth` **only**. |

**The server's validation order is fixed: identity, then freshness, then
signature, then semantics.** Checking the patch allow-list before the signature
would spend allow-list logic on bytes nobody authenticated, and would let an
unauthenticated party learn which fields are accepted by watching which
rejections come back differently. The rejections, in the order they can occur:

| # | Rejection | Cause |
|---|---|---|
| 1 | `wrong_correlation` | `correlation_id` is not the one dispatched |
| 2 | `tenant_mismatch` | reply names another tenant |
| 3 | `event_mismatch` | reply names another event |
| 4 | `key_version_too_old` | `key_version < 2` |
| 5 | `stale` | `issued_at` outside ±300 s, in either direction |
| 6 | `bad_signature` | missing or wrong MAC |
| 7 | `require_mfa_not_supported` | `require_mfa` on any event other than `login.post_auth` — checked before the decision, so it refuses a `deny` carrying it too |
| 8 | `not_mutable` | `mutate` on a veto-only event |
| 9 | `forbidden_patch_field` | a patch key outside the event's allow-list; the offending key is named in the audit record |
| 10 | `malformed_mutation` | `mutate` with no patch, `mutate` with an empty patch, or `allow` carrying a patch |

**Every rejection resolves to the registration's failure policy** (§22.8) and
every rejection is audited. A rejected reply is not a softer failure than no
reply at all: a reactor that answers with a forbidden patch has failed, and its
policy decides what that costs.

Three consequences an SDK's reply builder must encode structurally rather than
by documentation:

1. **No partial application.** One forbidden key rejects the *whole* patch,
   including the fields that would have been fine. An SDK MUST NOT filter a
   handler's patch down to the allowed subset before sending — doing so leaves
   the reactor author believing a field was set when it was dropped, which is
   the exact failure the server refuses to produce.
2. **`allow` and `patch` are mutually exclusive.** A patch attached to an
   `allow` is a reply whose author and whose reader disagree about what will
   happen; it is refused rather than resolved. A handler that returns a
   mutation MUST produce `decision: "mutate"`.
3. **`require_mfa` rides on `allow`.** `allow` + `require_mfa: true` on
   `login.post_auth` resolves to *proceed only after step-up*. It is not a
   separate decision value, and it MUST NOT be sent on any other event.

### §22.5 The event registry and the mutable-field allow-lists

Five interceptable events in v1. The list is served live at
`GET /api/v1/reactors/events`, which is the copy an SDK or admin UI SHOULD read;
the table below is the same data, stated here because a wire contract that
requires a network call to be understood is not a contract.

| Event | Mutable | Mutable fields (the complete allow-list) | Default failure policy |
|---|---|---|---|
| `token.pre_issue` | yes | **`ext.` namespace only** | `fail_open` |
| `login.post_auth` | no | — (veto, or `require_mfa`) | `fail_closed` |
| `user.pre_create` | yes | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `user.pre_update` | yes | `username`, `email`, `metadata.` namespace | `fail_closed` |
| `grant.pre_assign` | no | — (veto only) | `fail_closed` |

**`login.post_auth` covers every interactive sign-in, not only password login
(clarified 2026-08, SEC-095).** The event fires on password authentication, on
SAML ACS (`POST /api/v1/auth/federation/saml/acs`), on the OIDC callback
(`POST /api/v1/auth/federation/oidc/callback`) and on usernameless passkey
sign-in (`POST /api/v1/auth/webauthn/authenticate/discoverable/finish`) — in
every case after the credentials verify and before any session or token is
issued, which is what the row above has always said. MFA completion and the
username-bound WebAuthn `authenticate/finish` ceremony are **not** separate
firings: both continue a login that was already gated at its first step.

The usernameless ceremony is on the firing side of that line for exactly the
reason the others are not: it has no first step to have been gated at. It is
reached with no challenge token and no prior request, so if it did not fire, an
operator's `login.post_auth` veto — the embargoed-region example in §22.5's own
worked case — could be sidestepped by choosing "sign in with a passkey" instead
of typing a password.

One difference is worth stating because it is not discoverable from the table.
The federated paths have no step-up branch — a SAML or OIDC sign-in completes in
one round trip, with no `MfaRequired` result for the caller to act on — so a
`require_mfa` answer on those paths is **refused** (the sign-in fails) rather
than silently dropped. A reactor that needs step-up on federated logins must
answer `deny` and drive enrolment out of band. Usernameless passkey sign-in
behaves the same way and for the same reason; the passkey ceremony already
required user verification, so the factor a `require_mfa` verdict would ask for
has in effect already been presented.

**The namespace-prefix rule.** An allow-list entry ending in `.` is a namespace
prefix, and it matches a field that starts with the entry **and has at least one
character after the dot**. So `ext.` admits `ext.department` and `ext.a.b.c`,
and refuses:

- `ext.` itself — it names the namespace, not a claim, and admitting it would
  let a reactor set a claim literally called `ext.`;
- `ext` — not in the namespace;
- `extra`, `external_id` — a prefix match on the *string* is not a match on the
  namespace;
- `evil.ext.department` — not a suffix match either.

Everything else follows from that one rule. `token.pre_issue` cannot reach
`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `scp`, `azp`, `act`,
`client_id` or any other standard claim, because none of them begins with
`ext.`. A hook that can rewrite `sub` is a hook that can mint a token for
anyone, and no amount of correct signing changes that — a **correctly signed**
reply setting `sub` is refused exactly as a forged one is.

`user.pre_create` / `user.pre_update` admit `username`, `email` and the
`metadata.` namespace, and therefore refuse `password`, `password_hash`,
`tenant_id`, `id`, `roles`, `is_admin` — and refuse bare `metadata`, per the
prefix rule above.

**Listeners.** `mode: "listen"` is fire-and-forget observation: the server never
waits and never reads a reply, so a listener cannot affect any outcome. A
listener MAY subscribe to **every** registered event, including any the registry
marks non-interceptable — precisely because it cannot influence them. (All five
v1 events happen to be interceptable, so the distinction has no effect today;
the rule is stated because the registry carries the flag and a sixth event may
use it.) An SDK listener handler
MUST NOT publish a reply, and MUST be written idempotently — a redelivery after
a broker hiccup is normal, and a listener that double-counts is a listener that
was assuming exactly-once delivery it was never promised.

### §22.6 Ordering, mutation merge, and the chain

Interceptors registered for one event run **sequentially, in ascending
`priority`, ties broken by reactor id** — a total order that is stable across
restarts and does not depend on message timing.

1. **Deny short-circuits.** Once any reactor refuses, no later reactor is
   consulted. There is no allow-override at any priority, so calling them would
   spend the caller's latency to learn nothing.
2. **Patches accumulate; later wins per key.** Each reactor sees the prior patch
   (as `_reactor_patch`, §22.3) and the merged result is a union with
   last-write-wins, so the reactor with the higher priority number is the one
   whose value survives a contested key.
3. **`require_mfa` is sticky.** Once any reactor demands step-up, no later
   reactor can clear it. A step-up demand a later registration could overrule
   would be a security control with a race in it.
4. **A listener registered on an intercepted event is not consulted** and is
   never waited on.
5. **An event outside the registry dispatches to nothing** and resolves to
   `allow` — no reactor could have been validly registered for it, so there is
   nothing to wait for. This is what makes §22.7's hot-path exclusion structural
   rather than advisory.

The chain's composed result is `deny` if any reactor denied; otherwise
`require_mfa` if any demanded it; otherwise `mutate` with the merged patch if
any mutated; otherwise `allow`.

### §22.7 Hot-path exclusion (normative MUST NOT)

**`authz.check`, `authz.check_batch` and `token.introspect` are not hookable,
and no SDK may present them as such.** They are absent from the registry, a
registration naming one is refused at `POST /api/v1/reactors` as an unknown
event, and the dispatcher resolves an unregistered event to `allow` without
contacting anything.

The reason is arithmetic, not policy. A reactor round-trip is milliseconds; the
check path's budget is microseconds, and the benchmark matrix runs it at
1 000–12 000 req/s. Hooking it would not produce a slower check, it would
produce a different product.

An SDK MUST NOT:

- expose `authz.check`, `authz.check_batch` or `token.introspect` in any
  reactor-event enum, constant list, or documentation example;
- offer a client-side interceptor, middleware hook or callback that presents
  itself as the reactor equivalent for those operations;
- work around the exclusion by registering a listener on a decision event and
  blocking the calling path on it.

An application that needs external input on an authorization decision writes a
**deny grant**, which the engine evaluates in the hot path at hot-path cost.
That is the supported answer, and it is a better one.

### §22.8 Timeouts, failure policy, and the budget

| Setting | Value |
|---|---|
| `timeout_ms` default | **500** |
| `timeout_ms` accepted range | **1 … 5 000** — `0` and anything above 5 000 are refused at registration |
| Chain wall-clock ceiling | **5 000 ms** |
| Effective per-reactor budget | `min(timeout_ms, 5000 − elapsed)` |
| Total per-event budget | `min(sum of the chain's timeouts, 5 000 ms)` |
| Per-tenant in-flight interceptions | **64** by default |

`failure_policy` is per registration, and takes one of two values:

| Value | Effect when the reactor produces no usable reply |
|---|---|
| `fail_open` | proceed as if the reactor had replied `allow` |
| `fail_closed` | deny the underlying operation, with an audited reason naming the failure |

"No usable reply" is one closed set, and **every member takes the same path**:
timeout, transport failure, budget exhausted before this reactor was reached,
in-flight cap breached, and every §22.4 rejection — including a valid signature
carrying a forbidden patch field.

**The defaults are pinned per event, and the strictest wins.** A registration
that names no `failure_policy` gets `fail_closed` if *any* of its events
defaults to `fail_closed`, and `fail_open` only when all of them default open.
A reactor registered for both `token.pre_issue` (open) and `login.post_auth`
(closed) can veto a login, so it inherits `fail_closed` — in either array order.
An SDK or admin UI MUST NOT reimplement this composition as "take the first
event's default": that lets the order of a JSON array decide whether an
unreachable fraud check passes.

**The budget is wall-clock, not a sum, and running out of it is not a way to
skip a check.** Each reactor gets the smaller of its own `timeout_ms` and what
remains of the 5 000 ms ceiling. When the ceiling is exhausted the remaining
reactors are **not contacted**, and each of their own failure policies is
applied anyway — so an unreached `fail_closed` veto still denies. Registering
slow reactors ahead of a veto does not starve the veto; it only makes the whole
event fail.

**Back-pressure is immediate, not queued.** The per-tenant in-flight cap is
enforced with a non-blocking acquire: breaching it fails the interception at
once and applies the failure policy. Queueing behind the cap would turn a
concurrency bound into an unbounded latency bound, which is the failure the cap
exists to prevent.

**Failures are audited even when they are invisible in the outcome.** A
`fail_open` timeout produces `allow` *and* an audit record naming the reactor —
that pair is the whole difference between "no reactor was configured" and "the
reactor never answered". An SDK surfacing reactor health MUST NOT infer health
from the outcome alone.

**Only `intercept` registrations have a failure policy that can affect an
outcome (SEC-099).** A `listen`-mode registration is never dispatched to
synchronously and can never deny — including on the two out-of-chain failure
paths (the in-flight cap breach and the unreadable registry) where the server
resolves policies without contacting anyone. `default_failure_policy_for` still
assigns a listener `fail_closed` when it subscribes to `login.post_auth`,
because the default is derived from the *events*, not the mode; that stored
value is inert for a listener and an admin UI MUST NOT present it as a control
that does something.

**An unreadable registration store is not evidence that no veto was registered
(SEC-100, and §14.2 of the F4-bis review).** When the server cannot read the
registrations for `(tenant, event)` and has nothing cached, it applies the
**event's** default failure policy — so `login.post_auth`, `user.pre_create`,
`user.pre_update` and `grant.pre_assign` deny. This is a normative server
behaviour an SDK author cannot infer from the per-registration table above, and
an operator reading that table would not predict a deny with no registration in
sight. Two bounds on it, both of which an SDK or admin UI may rely on:

* a tenant the server can establish has **no reactor registrations at all** is
  exempt — there is provably nothing to consult, so it allows;
* once any successful read has happened, the stale list is served instead, and
  the per-registration policies in the table above apply as usual.

The alternative — treating an unreadable store as "no reactors" — would give
every `fail_closed` control in the deployment an availability-shaped off switch,
which is the failure mode `fail_closed` exists to prevent.

### §22.9 Registration (informative — the admin surface)

Reactors are registered through the admin REST API; an SDK that exposes reactor
management mirrors these shapes. Every endpoint below is permission-gated
(`reactors:list`, `reactors:create`, `reactors:get`, `reactors:update`,
`reactors:delete`) and tenant-scoped from the caller's token — a caller never
names the tenant, and cannot reach another one's reactors.

| Operation | Wire call | Success |
|---|---|---|
| list hookable events | `GET /api/v1/reactors/events` | `200` array of event descriptors |
| register | `POST /api/v1/reactors` | `201` reactor |
| list | `GET /api/v1/reactors` | `200` paginated reactors |
| read | `GET /api/v1/reactors/{id}` | `200` reactor |
| update | `PUT /api/v1/reactors/{id}` | `200` reactor |
| delete | `DELETE /api/v1/reactors/{id}` | `204` |

Registration body:

| Field | Type | Notes |
|---|---|---|
| `name` | string | Non-blank. |
| `description` | string | Optional, defaults to empty. |
| `events` | string[] | Non-empty; every entry must be a registry name. |
| `mode` | `"intercept"` \| `"listen"` | An `intercept` registration naming a non-interceptable event is refused. |
| `priority` | int | Optional, defaults `0`. Ascending; ties break by id. |
| `timeout_ms` | int | Optional. Omit to take **500**. Refused outside 1…5 000. |
| `failure_policy` | `"fail_open"` \| `"fail_closed"` | Optional. Omit to take the strictest default among `events` (§22.8). |
| `enabled` | bool | Optional, defaults `true`. A disabled reactor keeps its registration and its queue and is simply never dispatched to — the routing table is built from the enabled rows only. |

The response adds `id`, `tenant_id`, `created_at`, `updated_at`, and
`last_seen_at` — the last time this reactor consumed from its queue, `null` when
it has never connected, which an admin UI shows differently from "connected
once, silent since". An SDK runtime keeps that field moving by consuming; it is
a heartbeat derived from real work, not a separate ping.

Two behaviours a client MUST NOT re-derive locally:

1. **`PUT` validates the merged registration**, not the request. A `PUT` setting
   only `mode: "intercept"` is valid in isolation and invalid against a stored
   `events` list containing a listen-only event. Send the change and surface the
   server's `400`; do not pre-validate one field against nothing.
2. **Replacing `events` without naming a `failure_policy` re-derives it.** A
   reactor that was enrichment-only and is now also registered for
   `login.post_auth` must not keep passing when unreachable. An SDK MUST NOT
   preserve the old stored policy on the client side to "avoid a surprise".
3. **A registration may be refused with `503` when it could never be
   delivered to** (SEC-101). `POST /api/v1/reactors` and any `PUT` that would
   leave the registration **enabled** answer `503 service_unavailable` with a
   body naming the reason, in two cases. The first is a deployment that
   composes a transport which fails every round trip; accepting the
   registration would hand a tenant admin a complete, self-inflicted login
   outage through a supported admin action, because the transport fails,
   `login.post_auth` defaults to `fail_closed`, and the first login after the
   registration is denied. The second is `mode: "listen"`, for as long as no
   hook site fans out to listeners — the registration would receive nothing
   and, being a listener, would produce no outcome in which its silence could
   be noticed. `enabled: false`, `DELETE` and creating-already-disabled stay
   open in both cases: an operator must always keep a way out.

   A **broker outage is deliberately not one of these cases.** Since the lapin
   transport merged (§22.1) the server composes a transport that reports itself
   dispatchable even while its broker session is down; a dispatch during the
   outage fails fast and each registration's `failure_policy` decides, exactly
   as §22.8 specifies. Refusing registrations for the duration of a blip would
   turn a broker problem into an admin-API problem.

   Two exits stay open by design and an SDK MUST NOT block them client-side: a
   `PUT` setting `enabled: false` and a `DELETE` are **always** permitted, and
   creating an already-disabled registration is permitted too (it dispatches to
   nothing, so it causes no outage, and staging configuration ahead of the
   transport is a legitimate workflow).

   An SDK MUST surface this `503` as the server's message rather than retrying:
   it is not transient in the RFC 9110 sense. It clears when the operator
   deploys a build whose transport works, not on the next attempt.

### §22.10 The SDK runtime helper

The eight managed runtimes expose one helper. It connects (TLS per §8b and
§6.1), consumes the server-declared queue, and for each delivery: verifies §8 v2
(key version, MAC, freshness, nonce), decodes the event, dispatches to a
user-supplied handler, then signs and publishes the reply. It maintains
reconnect and heartbeat, and drains in-flight events on shutdown per §18.

The handler contract is one function from an event to one of three answers —
`Allow`, `Deny(reason)`, `Mutate(patch)` — with `require_mfa` available on
`login.post_auth` as a flag on the allow answer, expressed in whatever way the
language makes natural.

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `reactor_serve` | `reactor_serve` | `reactorServe` | `reactor_serve` | `reactorServe` | `reactorServe` | `ReactorServeAsync` | `reactorServe` | `ReactorServe` | `reactorServe` † | `axiam_reactor_serve` † | `reactor_serve` † |

† Swift, C and C++ ship the same runtime over a **caller-supplied transport** —
they bundle no AMQP client. See [§22.11](#§2211-swift-c-and-c--the-protocol-core-and-the-transport-that-is-not-bundled).

Two of the eight managed runtimes did not speak AMQP when this section was
written: §8's scope list names six SDKs, and Kotlin's §8 deferral is a documented
pre-existing carve-out. Shipping `reactor_serve` in Kotlin or C# means
implementing §8 and §8b first — a reactor runtime **is** an AMQP consumer, and
there is no reactor-shaped subset of §8 that would let one arrive without the
other.

Four rules on the helper itself:

1. **It MUST NOT declare topology** (§22.1). It consumes a queue whose name it
   was given or derives from its own configured `reactor_id`, and nothing else.
2. **It MUST fail closed on its own errors.** A handler that throws, or a
   payload the runtime cannot decode, MUST result in *no reply* — letting the
   server's `failure_policy` decide — rather than a synthesized `allow`. An SDK
   that answers `allow` on behalf of a handler that crashed has overridden the
   operator's `fail_closed` setting from inside the library.
3. **It MUST NOT filter a patch** to the allowed subset (§22.4 rule 1).
4. **It SHOULD honour `timeout_ms`** by abandoning work whose window has closed
   rather than replying late (§22.3).

### §22.11 Swift, C and C++ — the protocol core, and the transport that is not bundled

**No bundled AMQP client in v1, and that part is unchanged.** `axiam-swift-sdk`,
`axiam-c-sdk` and `axiam-cplusplus-sdk` vendor no AMQP dependency: there is no
maintained client for those targets this project is willing to put onto embedded
and mobile deployments, which is the same reason §8 scopes itself to the SDKs that
speak AMQP and has never listed these three.

**What changed in contract 1.28 is what that deferral was allowed to take with
it.** Until then these three shipped nothing from §22 at all, and the section told
an integrator that §22.1–§22.8 bound them anyway. Both halves were true and the
combination was a poor trade: the part deferred for want of a *dependency* was the
transport, and the part an integrator was left to hand-roll was the **protocol** —
v2 HMAC over a canonical serialization with a `null` signature placeholder,
freshness in both directions, nonce and correlation binding, the §22.5 allow-lists.
That is the half with the sharp edges, none of them AMQP-shaped, and asking eleven
integrators to reimplement it from prose is how a signing bug ships.

So these three now implement **§22.1–§22.8 and §22.14 in full, over a transport the
caller supplies**, and MAY claim §22 on that basis. The runtime helper exists; what
it does not do is open a connection.

**The transport seam (normative).**

1. The SDK exposes a **transport interface** with exactly the two capabilities the
   runtime needs: deliver an inbound message (body plus the `reply_to` and
   `correlation_id` basic properties), and publish a reply to a named destination.
   It MUST NOT be wider than that. A transport interface that also exposes declare,
   bind or queue-name derivation hands the integrator the tools §22.1 forbids using.

2. **§22.10's four rules bind the runtime unchanged.** It declares no topology, it
   fails closed on its own errors, it does not filter a patch, and it honours
   `timeout_ms`. Rules 2 and 3 in particular are the runtime's, not the transport's,
   and a caller-supplied transport does not relocate them.

3. **§8b rule 7 cannot be satisfied by a runtime that never sees a URL, so the SDK
   MUST hand the integrator the check rather than a paragraph.** Each of the three
   MUST expose the §8b rule 1–5 guard — scheme refusal, no plaintext fallback, no
   verification-skip switch, fail-closed on an unparseable URL — as a **public,
   tested function**, and MUST call it in its own example transport. Documenting the
   requirement instead is precisely the failure contract 1.23 was written to stop:
   three SDKs asserting `amqps://` in a doc comment above a call that accepted
   anything.

4. **The README MUST say the transport is caller-supplied**, and the conformance
   statement MUST NOT imply a bundled broker client. "Conforms to … §22" is the
   claim; "ships an AMQP client" is not, and a reader who assumes the second from
   the first will discover it at integration time.

Each of the three ships a **non-normative** sample (`examples/reactor/`,
`examples/reactor.c`, `Examples/Reactor`) that drives the runtime over a transport
skeleton and calls the §8b constructor before anything opens a socket — which is
what rule 7's second clause asks an example to show. The samples are examples, not
contract surfaces: this chapter governs, and a sample conforms to it or is wrong.
Where one previously reimplemented §22.1–§22.8 by hand, that copy is gone: the
library carries it, and a second implementation living beside the first is the
divergence §1 exists to prevent.

**Why this seam and not the other one.** §12.6's deferral, which contract 1.11
lifted, cut across the wrong join — it deferred a whole section because two of its
operations assumed a browser. The 1.18 version of this subsection improved on that
by cutting between *protocol* and *runtime convenience*, and 1.28 finds that the cut
was still one notch too wide: the convenience that genuinely needed a vendored
dependency was the **connection**, and the runtime around it needed none. Revisit
the remaining deferral when a vendorable AMQP client exists for these targets; the
wire protocol will not need to change for it, and now neither will the runtime.

### §22.12 `Sensitive<T>` applicability

The tenant AMQP **signing key** is a credential and MUST be wrapped in
`Sensitive<T>` (§7) wherever the SDK has that type, exactly as §8's key already
is. It MUST NOT be logged at any level, and MUST NOT appear in a reconnect
diagnostic.

The event `payload`, the `patch`, the `reason` and the `decision` are **not**
sensitive in the §7 sense and MUST remain readable — a handler that cannot
inspect the event cannot decide anything. They are, however, tenant business
data: an SDK MUST NOT log the payload at info level by default, and its
"Writing a Reactor" documentation SHOULD say so. The `nonce`, `correlation_id`
and `hmac_signature` are not secrets and may be logged for correlation.

### §22.13 Required tests

Against the vectors in
`crates/axiam-amqp/tests/fixtures/reactor_v2_reference_vectors.json` (generated
by the server's own sign path; the same master key, tenant and derived subkey as
the §8 fixture, so one loader serves both):

**Sign direction.** For each committed reply vector, building the reply from its
fields reproduces `canonical_signed_json` byte-for-byte and recomputes
`hmac_signature_hex` — including the `"hmac_signature": null` placeholder inside
the signed bytes, the omission of `reason`/`patch` when absent, and the omission
of `require_mfa` when false. Assert the omission rules directly: a reply built
with `require_mfa = false` MUST NOT serialize the field.

**Verify direction.** Each committed event vector verifies under the derived
subkey and fails under any other key; tampering with `payload`, `timeout_ms`,
`tenant_id` or `nonce` after signing invalidates it; a `key_version` below 2 is
refused before the signature is even computed; an `issued_at` outside ±300 s is
refused in **both** directions (stale and future).

**Replay.** The committed `correlation_replay` vector — the accepted reply
verbatim, valid signature, inside the freshness window — is refused when
presented against a different `correlation_id`. And the `nonce_binding` pair:
two replies differing only in `nonce` carry different MACs.

**Reply construction.** A handler returning a mutation produces
`decision: "mutate"` and never `allow` + `patch`; a handler returning a
mutation containing a forbidden key sends it **unfiltered** (assert the SDK did
not silently drop `sub` from a `token.pre_issue` patch); `require_mfa` is
rejected client-side, or sent and surfaced as the server's rejection, on any
event other than `login.post_auth`.

**Registry.** `token.pre_issue` accepts `ext.department` and `ext.a.b.c` and
rejects `ext.`, `ext`, `extra`, `external_id`, `evil.ext.department` and every
standard claim; `user.pre_create` accepts `email` and `metadata.source` and
rejects `password`, `tenant_id`, `roles` and bare `metadata`; `login.post_auth`
and `grant.pre_assign` accept no patch field at all.

**Hot path.** `authz.check`, `authz.check_batch` and `token.introspect` are
absent from every event constant the SDK exposes — assert on the enum/list, not
on a comment.

**Runtime.** A handler that throws produces **no reply** (assert zero published
messages, not an `allow`); the runtime declares no exchange, queue or binding
(assert against the AMQP client's declare calls); shutdown drains in-flight
events per §18; and the signing key never appears in any log line or error
payload (scan the serialized output for the fixture value, as §12/§14/§15/§20
require).

### §22.14 Declarative handler binding (contract 1.22)

**Requirement level: SHOULD**, for the SDKs that ship a §22.10 runtime — the
eight managed runtimes, and since contract 1.28 the three of
[§22.11](#§2211-swift-c-and-c--the-protocol-core-and-the-transport-that-is-not-bundled)
that drive one over a caller-supplied transport.
Additive in the strongest sense: no signature moves, no existing rule changes,
and an SDK that ships `reactor_serve` and nothing from this subsection is
exactly as conformant as it was under 1.21.

§22.10's handler is **one** function from an event to one answer, which is the
right shape for the wire and the wrong shape for the code. A reactor registered
for three events opens with a dispatch on `event.event`, and that dispatch is
where two defects live. The first is cheap: a misspelled event name compiles,
binds nothing, and is discovered as an event that never fires. The second is
not. It is the catch-all arm:

```
default:
    return allow();   // ← this is the bug
```

That line answers on behalf of code that never ran. It is the same defect
§22.10 rule 2 already forbids the *runtime* from committing — synthesizing an
`allow` for a handler that did not produce one — relocated into user code,
where the rule does not reach it. An operator who set `fail_closed` on a
registration has it defeated by a `default` arm in a file they never read.

This subsection is the declarative form: bind one handler per event, and let
the SDK compose them into the single handler §22.10 takes. It is **pure
sugar**, in the same sense and for the same reason as §11's declarative
authorization helpers — it runs strictly on top of the runtime, consumes what
the runtime already verified, and re-implements no part of §22.1–§22.8.

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `reactor_handlers` | `#[reactor_handler]` + `ReactorRouter` | `reactorHandlers` | `ReactorRouter` / `@on_reactor_event` | `@OnReactorEvent` + `ReactorHandlers` | `reactorHandlers { }` | `[OnReactorEvent]` + `ReactorHandlers` | `#[OnReactorEvent]` + `ReactorHandlers` | `ReactorMux` | `ReactorRouter` | `axiam_reactor_router` | `ReactorRouter` |

Each language uses the metadata mechanism it already uses for §11 — Java
annotations, C# and PHP attributes, a Python decorator, a Rust attribute macro —
and Go, which has no such mechanism and did not get one for §11 either, uses a
binding table named for `http.ServeMux`. Where an SDK offers both a declarative
form and a builder, the two MUST produce the same handler and be governed by
every rule below.

**Kotlin is the first place this section diverges from §11**, and the reason is
worth recording rather than discovering. *(Swift joins it under contract 1.28, for
the same reason in a different runtime: collecting `async` members by reflection
costs a dependency the SDK should not add to hand out an attribute, and a builder
type-checks the closure at compile time instead. C and C++ use a binding table, as
Go does, having no attribute mechanism to reach for.)* §11 gave Kotlin annotations; §22.14
gives it a type-safe builder, because a Kotlin reactor handler is a `suspend`
function. Collecting annotated `suspend` members means invoking through the
hidden `Continuation` parameter, which needs `kotlin-reflect` on every
consumer's runtime classpath — a dependency an SDK should not add to hand out an
attribute. A builder is Kotlin's own declarative mechanism, costs nothing, and
type-checks the lambda against `suspend (ReactorEvent) -> ReactorDecision` at
compile time, which is stricter than what the reflection would have bought. An
SDK in the same position — a language where the handler shape cannot be
collected without a new runtime dependency — MAY make the same trade, and MUST
document it where the helper is documented.

**Six rules, and the fourth is the one this subsection exists for.**

1. **It composes; it does not replace.** The binder's output is exactly the
   handler `reactor_serve` accepts. It MUST NOT open a connection, consume a
   queue, verify an event, sign a reply, or interpret `timeout_ms`. An SDK that
   makes the binder mandatory has removed the plain-handler form §22.10 names,
   which is a breaking change dressed as an ergonomic one — the binder is
   always additive.

2. **A name outside the §22.5 registry is refused at bind time**, not at
   dispatch time. Failing when the binding is written is the entire point: a
   typo that survives to production is discovered as silence, and silence on a
   `fail_open` event is indistinguishable from a healthy reactor with nothing
   to say.

   This is also, and deliberately, how §22.7's three hot-path operations are
   refused: they are in no registry row, so they fail rule 2 like any other
   unknown name. An SDK MUST NOT introduce a separate hot-path list to produce
   a more specific error message — that list would be a constant naming them,
   which §22.13's hot-path assertion forbids outright. The error message names
   the registry; it does not name what is absent from it.

3. **One handler per event.** A second binding for an already-bound event is an
   error, never a silent overwrite. Which of two handlers runs is not something
   the author of either can see from their own file.

4. **An event with no bound handler MUST abstain** — publish no reply, and let
   the registration's `failure_policy` resolve it exactly as §22.8 resolves a
   timeout. It MUST NOT be answered `allow`, and MUST NOT be answered `deny`
   either: the binder does not know what the registration was for, and the
   operator's policy does.

   An SDK MAY let the caller install an explicit fallback handler for
   unbound events. It MUST NOT default that fallback to any of the three
   answers.

5. **A handler's own failure propagates unchanged.** The binder MUST NOT catch
   an exception, error return or panic and MUST NOT convert one into an answer.
   §22.10 rule 2 puts the fail-closed obligation on the runtime, and a binder
   that swallowed a failure before the runtime saw it would satisfy the letter
   of that rule while defeating it.

6. **It MUST NOT filter a patch** (§22.10 rule 3). A binder sits between the
   handler and the runtime and is therefore the newest place to be tempted into
   "helpfully" pruning a forbidden key.

An SDK SHOULD expose the bound event names, so a reactor author can compute
§22.8's strictest-wins default from the code that actually handles the events
rather than from a restatement of the registration.

**Conformance.** §22.14 is not a separate claim. An SDK that ships §22 with the
binder and one that ships §22 without it both write "conforms to … §22"; the
subsection is an ergonomic obligation on how the helper behaves *if* it exists,
not a new capability to advertise.

#### §22.14.1 Required tests

Six, mirroring the six rules, and all of them run against a fake — none needs a
broker:

1. **Dispatch.** Two events bound to two handlers reach their own handler, and
   the composed value is accepted by `reactor_serve`'s handler parameter
   (a compile-time assertion where the language has one).
2. **Bind-time rejection.** A misspelled registry name is refused when bound.
3. **Hot path.** Binding `authz.check`, `authz.check_batch` or
   `token.introspect` is refused — asserted on behaviour, in whichever test
   file the SDK's §22.13 hot-path source scan already permits to name them.
4. **Unbound abstains.** An event with no handler produces **no reply** —
   assert zero published messages, and assert specifically that the answer is
   not `allow`. This is rule 4, and it is the test that distinguishes this
   subsection from a `switch`.
5. **Failure propagates.** A handler that throws/returns an error/panics
   reaches the runtime unchanged, and the runtime publishes nothing.
6. **Duplicate refused.** Binding the same event twice is an error.

---

## §23 OPAQUE (RFC 9807)

**Status: additive, and a replacement.** §23 previously specified SRP-6a. SRP
is removed from AXIAM entirely — server, admin UI and all eleven SDKs — and
nothing migrates: an SRP verifier cannot be converted into an OPAQUE record,
because both are sealed against a plaintext the server has never had. An SDK
that does not implement §23 is exactly as conformant as it was under contract
1.23. Nothing in §1–§22 changes, no signature moves, and a server with
`opaque_mode: disabled` — the default — behaves byte-identically to a server
without OPAQUE.

OPAQUE is an *augmented PAKE*: the client proves knowledge of the password
without the password, or anything from which the password can be cheaply
recovered, ever crossing the wire. The server stores a **registration record**
whose envelope is sealed under a key the client can only reconstruct by running
the password through the server's oblivious PRF.

### §23.0 What this is for, and what it is not for

Stated up front because an SDK's own documentation will repeat it, and
overclaiming here is worse than not shipping the feature.

OPAQUE closes holes that TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under OPAQUE it sees a blinded group element
  and a MAC, which are useless without the record *and* the tenant's OPRF seed;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- a stolen record database is **not** offline-crackable on its own. This is the
  property SRP could not offer, and the main reason for the change: recovering a
  password from a stolen record additionally requires the tenant's OPRF seed,
  and without it there is no dictionary attack to mount at any cost.

It does **not** protect against a compromised AXIAM server, and in a browser it
does not protect against AXIAM serving malicious JavaScript. An SDK MUST NOT
claim either.

### §23.0.1 Why SRP was replaced, in one paragraph an SDK README can quote

RFC 9807 was published in July 2025; OPAQUE was a draft when SRP was chosen, and
§23's own text named improving implementation coverage as the migration trigger.
Beyond the standardization, OPAQUE resists the pre-computation attack SRP is
open to — AXIAM's SRP had to bolt a memory-hard KDF onto RFC 5054's bare hash
merely to *match* the Argon2id hashes it replaced — and it is specified to the
byte, where AXIAM's SRP carried two deliberate divergences from its own RFC.

### §23.1 One implementation, not eleven — and what that means for an SDK

**This is the structural change in §23 and it is not optional.**

SRP is modular arithmetic and every language has a bignum, so every SDK
hand-wrote it. OPAQUE needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE. An SDK
**MUST NOT** implement the OPAQUE protocol itself. It binds one audited
implementation:

| SDK | How it binds |
|---|---|
| Rust | `axiam-opaque` as a crate dependency |
| TypeScript | WebAssembly build of `axiam-opaque` |
| Go | native `github.com/bytemare/opaque` (RFC 9807) — kept native so consumers are not forced onto cgo |
| Python, Java, Kotlin, C#, PHP, Swift, C, C++ | `axiam-opaque`'s C ABI |

Go is the one permitted exception, and only because a vetted, independently
maintained RFC 9807 implementation exists for it and because cgo would break
`CGO_ENABLED=0` builds for every consumer. Any future exception needs the same
two justifications.

Consequences an SDK author must plan for:

1. **SDKs now ship a native or WebAssembly artifact.** A pure-source install is
   no longer possible for the C-ABI languages. Each SDK's README MUST state the
   platform matrix it publishes.
2. **`opaqueAvailable()`** (naming per §23.2) reports whether this build can
   speak OPAQUE at all — i.e. whether the native library or WASM module loaded.
   It MUST return `false` rather than throw at login time. This replaces SRP's
   `srpAvailable()`, which reported the same kind of fact for a different
   reason.
3. **There is no per-exchange capability question any more.** SRP had two axes
   of conditionality, because four SDKs could not compute `argon2id` and found
   out only when a tenant asked for it. One shared core removes that axis
   entirely, and with it CONTRACT 1.25's errata.

### §23.2 Method naming map

Extends the §1 locked vocabulary. No other OPAQUE-related public method names
are permitted.

| Canonical operation | Rust | TypeScript/JS | Python | Java | C# | PHP | Go |
|---|---|---|---|---|---|---|---|
| OPAQUE login | `login_opaque` | `loginOpaque` | `login_opaque` | `loginOpaque` | `LoginOpaque` | `loginOpaque` | `LoginOpaque` |
| build an enrolment | `opaque_enrollment` | `opaqueEnrollment` | `opaque_enrollment` | `opaqueEnrollment` | `OpaqueEnrollment` | `opaqueEnrollment` | `OpaqueEnrollment` |
| capability probe | `opaque_available` | `opaqueAvailable` | `opaque_available` | `opaqueAvailable` | `OpaqueAvailable` | `opaqueAvailable` | `OpaqueAvailable` |

**Kotlin** and **Swift** use camelCase (`loginOpaque`, `opaqueEnrollment`,
`opaqueAvailable`); **C++** snake_case (`login_opaque`, `opaque_enrollment`,
`opaque_available`); **C** snake_case with the `axiam_` prefix
(`axiam_login_opaque`, `axiam_opaque_enrollment`, `axiam_opaque_available`).

`login_opaque` takes the same `(username_or_email, password)` arguments as
`login` and returns the **same result type**. That is a hard requirement, not a
convenience: it is what lets an application switch a tenant to OPAQUE without
touching its own code, and it is why the server returns the same 200/202/403
union on both paths.

`opaque_enrollment` returns the object §23.5 describes, ready to embed in any
password-setting request body. It performs the `register/start` round trip
internally; a caller never handles a session token.

### §23.3 The exchanges

```text
  REGISTRATION                                     server
    |  RegistrationRequest (blinded password)         |
    | -----------------------------------------------> |  POST /auth/opaque/register/start
    |  RegistrationResponse, ksf params, opaque_session |
    | <----------------------------------------------- |
    |   stretch, seal an envelope under the OPRF output
    |  { opaque_session, registration_record }         |
    |   embedded in POST /users, /auth/password/change,
    |   or /auth/reset/confirm

  LOGIN                                            server
    |  KE1                                             |
    | -----------------------------------------------> |  POST /auth/opaque/login/start
    |  KE2, ksf params, opaque_session                 |
    | <----------------------------------------------- |
    |   stretch, open the envelope, derive the AKE keys
    |  { opaque_session, KE3 }                         |
    | -----------------------------------------------> |  POST /auth/opaque/login/finish
    |  the ordinary login result (§3 union)            |
    | <----------------------------------------------- |
```

There is deliberately **no `register/finish` endpoint**. A record can only be
built where the plaintext legitimately exists on the client, and every such
moment is already an endpoint that takes a password.

### §23.4 Normative rules

1. **Do not implement the protocol.** See §23.1. An SDK that hand-rolls OPAQUE
   is non-conformant regardless of whether its output happens to interoperate.

2. **Honour the KSF the server names, per exchange.** Both `register/start` and
   `login/start` return a `ksf` and its cost parameters. An SDK MUST pass those
   to the core and MUST NOT substitute its own defaults, cache them across
   logins, or reuse a value from a previous response. A credential enrolled
   under one cost keeps working after a tenant raises its policy, so a client
   that guessed would derive a different randomized password and fail against a
   record that is perfectly good — surfacing to the user as a wrong password.

3. **Refuse an unknown `ksf` or `suite`.** Raise **`NetworkError`** — §2's
   catch-all for a client-side fault — with the offending value in the message.
   MUST NOT raise `AuthError`, which means *wrong credentials* and would send a
   user off to reset a password that works. MUST NOT substitute a different
   function. Unlike contract 1.25's SRP situation, this is now genuinely
   exceptional: every SDK's core supports every KSF AXIAM offers, so hitting
   this means the server is newer than the SDK.

4. **Range-check the cost parameters** against §23.7's bounds before stretching.
   A server is trusted to name its own policy, not to name a cost that would
   wedge every device an account owns. Out of range is `NetworkError`.

5. **Read the flat KSF fields correctly.** They arrive flat and optional:
   `memory_kib`/`iterations`/`parallelism` for `argon2id`, `log_n`/`r`/`p` for
   `scrypt`. Fields that do not apply are **absent, not zero**. An SDK that
   reads an absent field as `0` stretches with the wrong cost.

6. **There is no server proof to verify.** RFC 9807's AKE authenticates the
   server during the handshake: a client that successfully opens `KE2` has
   already proved the server holds the record. The login response carries no
   `server_proof` and an SDK MUST NOT expect one. This replaces SRP's §23.3
   rule 6, which had to mandate an `M2` check in capitals because skipping it
   silently discarded half the protocol. That failure mode no longer exists.

7. **A failure to open `KE2` means the SDK MUST NOT send `KE3`.** Wrong
   password, unknown identity, an account with no registration record, and a
   hostile endpoint are indistinguishable here by design; an SDK MUST NOT report
   them differently or claim to know which occurred.

   What the SDK does next depends on `mode` in the `login/start` response, and
   only on that:

   - `"required"` (and **any response with no `mode` field**, which is a server
     older than the field): the failure is `AuthenticationError` and the
     exchange is over. The SDK MUST NOT retry over `POST /auth/login`. It
     would be refused anyway — `required` answers `403 opaque_required` for
     every principal — and an SDK that tried would put a plaintext password on
     the wire for nothing.
   - `"optional"`: the SDK MUST retry over `POST /auth/login` with the same
     credentials before reporting any failure. Under `optional` an account
     with no record is the ordinary case, not an error: every account has none
     the moment an operator enables OPAQUE, and they acquire one only as they
     next set a password. An SDK that treats the failed exchange as final locks
     out every user of a tenant mid-migration, which is the state `optional`
     exists to serve.

   The `mode` field is **not** downgrade protection, and an SDK MUST NOT
   present it as such: a hostile server that wanted the plaintext could answer
   `404` and get the fallback whatever it puts here. `required` is what closes
   that, server-side, by refusing `/auth/login` before examining any
   credential.

8. **Echo `opaque_session` verbatim.** It is opaque sealed server state, valid
   for 120 seconds. An SDK MUST NOT parse, cache, reuse across exchanges, or
   store it.

9. **`opaque_required` maps to a distinguishable error**, never to
   `AuthenticationError`. It is how an SDK learns to switch to the OPAQUE
   endpoints rather than telling a user their correct password is wrong.

10. **`404` from `/auth/opaque/*` means the tenant has OPAQUE disabled**, a
    property of the tenant and not of any user. It MUST NOT be reported as "no
    such user".

11. **Never log.** `opaque_session`, `ke1`, `ke2`, `ke3`, `registration_request`,
    `registration_response`, `registration_record`, `export_key` and
    `session_key` MUST NOT appear in any log record at any level, under the §19
    telemetry hooks or otherwise. `opaque_session` in particular is
    bearer-equivalent for the 120 seconds it lives.

12. **Pass the password as UTF-8.** The core takes bytes. An SDK that hands it a
    platform-default encoding fails for any non-ASCII password; §23.7's fixture
    pins a case.

### §23.5 Wire shapes

`POST /api/v1/auth/opaque/register/start` request:

```json
{ "org_slug": "acme", "tenant_slug": "default",
  "registration_request": "<hex>" }
```

Response `200`:

```json
{ "opaque_session": "<opaque, echo verbatim>",
  "registration_response": "<hex>",
  "suite": "ristretto255_sha512", "ksf": "argon2id",
  "memory_kib": 19456, "iterations": 2, "parallelism": 1 }
```

This endpoint is **unauthenticated**, and must be, because it is used while
creating a user who does not exist yet. It is safe because the server mints the
credential identifier itself: an anonymous caller obtains OPRF evaluations under
identifiers they neither chose nor can predict.

The `opaque` enrolment object, accepted by `POST /api/v1/users`,
`POST /api/v1/auth/password/change` and `POST /api/v1/auth/reset/confirm`:

```json
{ "opaque_session": "<verbatim>", "registration_record": "<hex>" }
```

`POST /api/v1/auth/opaque/login/start` request:

```json
{ "org_slug": "acme", "tenant_slug": "default",
  "username_or_email": "alice", "ke1": "<hex>" }
```

Both endpoints take the workspace exactly as `POST /auth/login` does, §5.2.1 included:
`org_slug`/`org_id` is required, the tenant pair is optional, and omitting the tenant
resolves the organization's own scope. An empty-string slug is not a slug — see §5.2.1
rule 2, which is the rule that keeps the `404` below reachable.

Response `200`: as `register/start`, with `ke2` in place of
`registration_response`, plus a `mode` field carrying the tenant's
`opaque_mode` — `"optional"` or `"required"`, never `"disabled"` (that answers
`404`). §23.4 rule 7 is the only thing an SDK does with it. It is a property of
the tenant and is identical for a real and a decoy exchange, so it cannot be
used to tell whether an identity is enrolled.

`404` means the tenant has OPAQUE disabled.

Note what is **not** in it: any identity field. SRP's challenge had to return the
canonical `identity` because that string was inside the client's key derivation.
OPAQUE's credential identifier is server-side only and is never disclosed.

`POST /api/v1/auth/opaque/login/finish` request:

```json
{ "opaque_session": "<verbatim>", "ke3": "<hex>" }
```

Responses are the §3 login union — `200` success, `202` MFA challenge, `403` MFA
setup. Cookies are set exactly as on `/auth/login`; §3, §4 and §9 apply
unchanged.

`POST /api/v1/admin/bootstrap` takes **no** `opaque` object, only
`opaque_mode`/`opaque_suite`/`opaque_ksf`. Bootstrap already receives the
plaintext password — it must, to compute the Argon2id hash — so it runs both
halves of the registration server-side. An SDK MUST NOT send an enrolment there.

### §23.6 Server policy an SDK must understand

`opaque_mode` is an organization baseline that a tenant may tighten:

- `disabled` — `/auth/opaque/*` answers `404`; sending an `opaque` object is a
  `400`.
- `optional` — both login paths work; records accumulate as passwords are set.
- `required` — `/auth/login` answers `403 opaque_required` **for every principal
  in the tenant**, before any credential is examined.

`required` is tenant-wide rather than per-user deliberately, and an SDK's docs
should say why: refusing only the users who *have* a record would split the
response on a fact about the account, so one junk password per name would
enumerate which accounts exist and are enrolled. It also means `required` locks
out anyone not yet enrolled — a record cannot be created retroactively, since it
needs the plaintext password and a stored Argon2id hash is not invertible.
Operators turn it on last, after a reset campaign.

`optional` is therefore the mode a tenant lives in for as long as the migration
takes, and under it an SDK that tries OPAQUE first will see the exchange fail
for every user who has not yet set a password since it was enabled. Handling
that is §23.4 rule 7's `optional` clause, and it is not optional to implement:
without it, enabling `optional` is indistinguishable from enabling `required`
with nobody enrolled.

Enabling OPAQUE also provisions the tenant's server-side key material at the
settings write rather than on the first `/auth/opaque/*` request, so an operator
who has enabled it and seen no traffic can still tell that it took effect. This
is invisible to an SDK; it is noted here only because the observable "the
tables are empty" no longer means "nothing is configured".

### §23.7 Required tests

Vendored `opaque-test-vectors.json` (generated from `axiam-opaque` and re-synced
with `CONTRACT.md` and `openapi.json`) is deliberately **smaller than the SRP
fixture it replaces**, and an SDK author should understand why before concluding
something is missing.

The SRP file pinned every protocol intermediate — `k`, `v`, `A`, `B`, `u`, `S`,
`K`, `M1`, `M2` — because eleven SDKs each contained their own implementation and
one that got `u` wrong had to find out at `u`. No SDK computes any of that now.
Re-pinning it would be eleven copies of one test of one library.

An SDK also **cannot** complete a real exchange locally: OPAQUE is randomized and
the blind is generated inside the core, so no pre-recorded server response
matches a fresh `KE1`. Round-trip correctness is asserted upstream, in
`axiam-opaque` and against a live server in the AXIAM repository's end-to-end
tests.

What an SDK MUST test is the layer it actually owns:

1. **Message widths** match `message_lengths_bytes` for every message it
   constructs or parses.
2. **KSF field mapping**, both cases in `ksf_wire_cases`: `argon2id` fields
   present with `scrypt` fields **absent**, and the converse. Assert absence, not
   zero.
3. **An unknown `ksf` is refused** with `NetworkError` naming it, and no
   stretching is attempted.
4. **Out-of-range costs are refused** at each bound in `ksf_bounds`.
5. **A non-ASCII password round-trips**, pinning UTF-8. The SDK chooses its
   own: the fixture carries no shared password, because the SRP file only
   needed one to pin `x` across implementations and there is one
   implementation now. The obligation is unchanged — a binding that hands the
   core its platform's default encoding must fail in a test rather than for
   one unlucky user.
6. **`opaque_required` maps to a distinguishable error**, not to
   `AuthenticationError`.
7. **`404` from `login/start` is not reported as "no such user".**
8. **Nothing sensitive is logged** — drive a login through the SDK's own
   log/telemetry sink and assert the absence of every value in §23.4 rule 11.
9. **`opaqueAvailable()` reports `false` rather than throwing** when the native
   library or WASM module is unavailable.
10. **The login result type is identical** to `login`'s, asserted structurally
    rather than by eye — that is what rule §23.2 exists for.

### §23.8 Per-SDK posture

Every SDK is `full`. There is no conditional row, which is itself the headline:
SRP's §23.8 had four SDKs that could not compute `argon2id` and one that could
not do bignum arithmetic without an optional extension.

| SDK | Binding | Notes |
|---|---|---|
| Rust | native crate | also compiles to `wasm32-unknown-unknown` for `axiam-sdk-wasm` |
| TypeScript | WASM | adds a WebAssembly module to the package; see its README for the size |
| Go | native `bytemare/opaque` | no cgo, so `CGO_ENABLED=0` still builds |
| Python | C ABI via wheels | platform wheels; a source install needs a Rust toolchain |
| Java | C ABI via JNI/FFM | native artifacts in the jar |
| Kotlin | as Java (JVM target) | |
| C# | C ABI via P/Invoke | native assets in the NuGet package |
| PHP | C ABI via `ext-ffi` | `opaqueAvailable()` is `false` without `ext-ffi` or the shared library |
| Swift | C interop | replaces the bundled Montgomery modexp SRP required |
| C | header + library | |
| C++ | wraps the C binding | |

PHP remains the one build-time conditional, but for a different and simpler
reason than under SRP: it needs `ext-ffi` and the shared library present, rather
than a choice between two bignum extensions plus an Argon2id it could never
satisfy.

---

## §24 WebAuthn and Passkeys (W1)

**Requirement level: SHOULD (v1.0)** for all eleven SDKs. Stated **by name**, like
§14, §15, §17, §19 and §22 — an SDK that ships it writes, for example:

> "This SDK conforms to CONTRACT.md §1–§13, §14, §15, §22 and §24."

Server implementation: `crates/axiam-auth/src/webauthn.rs` (the ceremonies),
`crates/axiam-api-rest/src/handlers/webauthn.rs` (the six endpoints) and
`crates/axiam-api-rest/src/handlers/webauthn_policy.rs` (the per-tenant
attestation policy).

Contract 1.27 recorded in passing that "WebAuthn is a browser ceremony and no
SDK speaks it". The first half was true; the conclusion was wrong, and it is
worth saying why rather than quietly reversing it. A WebAuthn ceremony is **two**
exchanges stacked: one with an *authenticator*, which needs a platform API, and
one with *AXIAM*, which is four ordinary JSON round trips. Only the first needs a
browser. The second is what an SDK is for, and it does not stop existing on a
runtime that has no authenticator — a Go service enrolling a passkey for a native
client it fronts, a Java backend completing a ceremony a handset ran, a Python
harness driving a virtual authenticator in CI all speak the AXIAM half and none of
them touches `navigator.credentials`.

§24 splits along that seam, and the split is the design:

- **§24.1–§24.5 — the relying-party layer.** The round trips, credential adoption,
  the error taxonomy. Binding on **every** SDK that claims §24.
- **§24.6a — the JSON bridge.** Handing the challenge to whatever runs the
  ceremony, and taking its answer back. Also binding on every SDK, because the
  platform authenticator APIs take and return exactly this — which is what lets a
  Kotlin SDK be fully usable from an Android app without linking one Android class.
- **§24.6b — the linked-API helper.** Driving the authenticator from inside the
  SDK. Only where the build can reach one; §24.7 records who can.

### §24.0 The division of labour (normative — everything below follows from it)

**The server does all of the crypto and all of the policy.** It generates the
challenge, chooses `residentKey`, `userVerification`, the attestation conveyance,
the credential exclusion list and the timeout, and it verifies the resulting
attestation or assertion against the tenant's attestation policy. An SDK **MUST**
hand the server's options to the authenticator unchanged, and **MUST** post the
authenticator's response back unchanged.

This is §23.1's "one implementation, not eleven" argument reached from the
opposite direction. OPAQUE is centralized because it is too intricate to
hand-write eleven times. WebAuthn options are centralized because they are *not*
intricate — and that is the hazard. Every field in
`PublicKeyCredentialCreationOptions` is a security parameter, every one of them
looks locally adjustable, and an SDK that relaxes `userVerification` to
`"preferred"` because a CI authenticator kept prompting has weakened a ceremony
the server believes it configured. The server cannot catch it: it verifies the
assertion it receives, and an assertion produced under weaker options is a
perfectly valid assertion. The damage is invisible at exactly the layer that
would notice it.

Three consequences an SDK must not talk itself out of:

1. **No defaulting, no filling in, no normalizing.** If the server omits a field,
   it is omitted on purpose. An SDK MUST NOT supply a `timeout` the server did not
   send, MUST NOT expand an absent `authenticatorSelection` into an empty object,
   and MUST NOT reorder or prune `pubKeyCredParams` or `excludeCredentials`.
2. **No validation that can reject.** An SDK MAY fail to *parse* the options —
   that is a bug report about the server — but MUST NOT refuse options it parsed
   merely because it disagrees with them. A client-side allow-list of acceptable
   algorithms is a second policy engine, and the tenant's is the only one that
   counts.
3. **The response goes back verbatim.** `clientDataJSON`, `attestationObject`,
   `authenticatorData`, `signature`, `userHandle` and the credential `id`/`rawId`
   are inputs to a signature check over bytes the SDK did not produce. Re-encoding
   base64url "to be safe" is the single most common way to break a ceremony that
   was otherwise correct.

The one permitted addition is **§24.6 rule 4's `authenticatorAttachment` hint**,
and it is permitted because it cannot weaken verification — it selects which
authenticator the user is prompted for, not what the server will accept.

### §24.1 Canonical operation set and endpoint map

Eight wire operations and three composed helpers. Every row is verified against
`openapi.json`.

| Canonical operation | Wire call | Auth | Request | Success |
|---|---|---|---|---|
| `webauthn_register_start` | `POST /api/v1/auth/webauthn/register/start` | **session** | no body | `200` `StartRegistrationResponse` |
| `webauthn_register_finish` | `POST /api/v1/auth/webauthn/register/finish` | **session** | `application/json` / `FinishRegistrationRequest` | `201` `CredentialResponse` |
| `webauthn_authenticate_start` | `POST /api/v1/auth/webauthn/authenticate/start` | none | `application/json` / `StartAuthenticationRequest` | `200` `StartAuthenticationResponse` |
| `webauthn_authenticate_finish` | `POST /api/v1/auth/webauthn/authenticate/finish` | none | `application/json` / `FinishAuthenticationRequest` | `200` `WebauthnLoginResponse` |
| `webauthn_discoverable_start` | `POST /api/v1/auth/webauthn/authenticate/discoverable/start` | none | `application/json` / `StartDiscoverableAuthenticationRequest` | `200` `StartAuthenticationResponse` |
| `webauthn_discoverable_finish` | `POST /api/v1/auth/webauthn/authenticate/discoverable/finish` | none | `application/json` / `FinishAuthenticationRequest` | `200` `WebauthnLoginResponse` |
| `webauthn_setup_register_start` | `POST /api/v1/auth/webauthn/setup/register/start` | **none (setup token)** | `application/json` / `SetupRegisterStartRequest` | `200` `StartRegistrationResponse` |
| `webauthn_setup_register_finish` | `POST /api/v1/auth/webauthn/setup/register/finish` | **none (setup token)** | `application/json` / `SetupRegisterFinishRequest` | `200` `LoginSuccessResponse` |
| `webauthn_register` | the register pair, composed with a §24.6 ceremony | | | `CredentialResponse` |
| `webauthn_login` | the authenticate pair, composed | | | token set |
| `webauthn_discoverable_login` | the discoverable pair, composed | | | token set |

**JSON, not form-encoded.** Unlike the `/oauth2/*` operations of §12, §14 and §15,
every endpoint here takes `application/json` and carries no `tenant_id` query
parameter. The §5 `X-Tenant-ID` header is still emitted on all six (§5 rule 2
admits no exceptions).

**Where the tenant actually comes from, which is not the header.** The four
`authenticate/*` endpoints are unauthenticated and resolve the tenant from the
request itself:

- `authenticate/start` and both `*/finish` calls read it out of the `state_token`
  (respectively the `challenge_token`), which is a JWT the server minted. An SDK
  MUST treat those tokens as **opaque** and MUST NOT decode them to make a
  decision — the server peeks at the payload to route the request and then
  verifies the whole thing; an SDK that parsed one would be trusting an unverified
  claim to do something the server does not need it to do.
- `discoverable/start` is the exception and carries the workspace explicitly,
  because a usernameless ceremony has no prior step to have minted a token. It
  accepts `org_id`/`org_slug` and `tenant_id`/`tenant_slug` and, unlike the five
  `/oauth2/*` operations of §12.1 rule 2, **accepts slugs** — so a slug-only client
  can run it. An SDK MUST populate these from its own configured workspace
  identity, in whichever form it holds, rather than requiring the caller to repeat
  it.

**`register/*` requires an authenticated session** — enrolling a passkey is
something an already-signed-in user does to their own account. Calling either
without credentials MUST raise the §2 `AuthenticationError` **client-side, with no
wire call**, exactly as §1.1 rule 3 requires of `get_user_info`.

**`setup/register/*` is the exception, and takes no session at all** (contract
1.45). It is the WebAuthn twin of `mfa_setup_enroll` / `mfa_setup_confirm`
(§25.1): its caller is in the middle of a forced first-login enrolment under a
tenant that requires MFA, and *has* no session — the setup token from the
login's `403` is the only credential the pair accepts, and it travels in the
request body. An SDK MUST NOT attach its session credential to these two, MUST
NOT require one to call them, and MUST treat the setup token as opaque exactly
as it treats a `state_token`.

The account whose first factor is being enrolled is named by the token, never by
the caller: there is no `user_id` on either request and an SDK MUST NOT invent
one. The server refuses an account that already has a factor with `400` — the
same answer `mfa_setup_enroll` gives, because it is the same rule: a setup token
adds the **first** factor, never a second.

### §24.2 The two authentication ceremonies are different flows, not one with a flag

`authenticate/*` is a **second factor**. It continues a `POST /api/v1/auth/login`
that answered `202` with `mfa_required` and a `challenge_token`, listing
`"webauthn"` among its `available_methods`. The challenge token names the user, so
the server can send an `allowCredentials` list.

`discoverable/*` is a **primary factor**. Nothing precedes it. The server sends an
empty `allowCredentials`, the authenticator offers whichever discoverable
credential it holds for the relying party, and the assertion itself identifies the
user.

**They MUST NOT be merged behind one operation with an optional
`challenge_token`.** That was the server's original shape and it could not work:
`authenticate/start` decodes the challenge token to learn who is signing in, so an
empty string is rejected as a malformed token before anything else happens. An SDK
that models this as one nullable parameter reproduces a bug the server already
fixed, and reproduces it as a runtime failure with a misleading message.

The two also differ in what the server does around them, which an SDK's
documentation SHOULD state because a reactor author will ask:
`discoverable/finish` fires the `login.post_auth` hook event (§22.5) and
`authenticate/finish` does not — the latter continues a login that was already
gated at its password step, and the former has no such step to have been gated at.

### §24.3 Credential adoption (normative)

Both `*/finish` authentication calls answer `200 WebauthnLoginResponse`, carrying
`access_token`, `refresh_token`, `session_id` and `expires_in` **and** setting the
`axiam_access` / `axiam_refresh` / `axiam_csrf` cookie triple with an
`X-CSRF-Token` response header — the same triple and the same header
`POST /api/v1/auth/login` sets.

*(The cookies arrived with contract 1.28. Before it, these two endpoints answered
with the body alone, which made a browser passkey sign-in impossible to complete
and left `POST /api/v1/auth/refresh` — which reads the refresh token from
`axiam_refresh` and never from a body — unreachable afterwards. An SDK built
against an older server sees the body exactly as it always did.)*

1. **A completed passkey sign-in MUST leave the client authenticated**, in exactly
   the state a successful `login()` leaves it. This is **not** the §14.3 rule 4
   "MAY adopt" posture and MUST NOT be implemented as one: `device_login` and
   `oidc_exchange` are token-minting operations whose result the caller may want
   to hand elsewhere, and this is the SDK's own primary authentication. An SDK
   that returned a token set without adopting it would make
   `webauthn_login()` the only way to log in that does not log you in.
2. **Cookie-jar SDKs adopt through the jar** (§4) and MUST capture `X-CSRF-Token`
   into the same slot `login()` populates (§3). An SDK that adopts the body tokens
   but skips the CSRF token will pass its own login test and fail on the first
   state-changing call afterwards.
3. **Non-cookie SDKs adopt the body tokens.** Both mechanisms are present on the
   same response precisely so that neither kind of client has to emulate the
   other.
4. **The §17 decision memo MUST be cleared** and the §9 refresh guard left
   untouched-but-usable, exactly as `login()` and `verify_mfa()` do — §17.1 rule 9
   keys entries by subject, and this call changes the subject.
5. `refresh_token` from this response is refreshed through the §1 `refresh`
   operation (`POST /api/v1/auth/refresh`), **not** `oidc_refresh`. It is a session
   refresh token, not an OAuth2 one, and the two paths are distinct per §12.1.

`webauthn_register_finish` adopts nothing — the caller was already authenticated
— and returns the `CredentialResponse` describing the credential just enrolled.

### §24.4 Error taxonomy (normative)

§2 maps most of this correctly on status alone. Three rows do not, and each is a
case where the generic mapping loses the only thing the caller can act on:

| Status | Endpoint | §2 would say | §24 requires |
|---|---|---|---|
| `401` | any | `AuthenticationError` | `AuthenticationError` — unchanged |
| `403` | `register/finish` | `AuthorizationError` | `AuthorizationError`, **and the server's message MUST be surfaced verbatim** |
| `503` | `register/start` | `NetworkError`/retryable | **`ValidationError`, and NOT retried** |
| `400` | `discoverable/start` | `ValidationError` | `ValidationError` — unchanged |

1. **`403` on `register/finish` is the tenant's attestation policy refusing this
   authenticator**, not a permission problem with the user. The message names why
   — an AAGUID that is not allow-listed, a missing FIDO certification, a revoked
   status — and it is the only way the person holding the security key learns that
   *this* key will never work and a different one might. An SDK MUST NOT replace it
   with a generic string.

   **This does not license dumping the response body into an error.** An SDK whose
   error taxonomy deliberately redacts bodies — several do, because a body is a
   place a token can end up — satisfies this rule by decoding the **`message`
   field** and nothing else, exactly as it already decodes named fields like
   `action` and `resource_id`. One named field is what the rule asks for; the raw
   body is not, and an SDK that relaxed its redaction to satisfy §24 would have
   traded a real protection for a message it could have had either way.
2. **`503` on `register/start` means the attestation policy requires attestation
   and the FIDO metadata service has no usable snapshot.** It is a server
   configuration state, not a transient failure, and §16 MUST NOT retry it: retrying
   changes nothing, and the bounded budget merely delays a message an operator needs
   to see. This is a **documented exception to §16.3's "retry every 5xx"**, and the
   second such exception in this contract after §20's.
3. **An `InvalidStateError` from the authenticator is not a §2 error at all** — see
   §24.6 rule 5. It means the authenticator already holds a credential for this
   account, which is a successful outcome of the exclusion list working.

### §24.5 `Sensitive<T>` applicability

`state_token` and `challenge_token` are **bearer credentials for the duration of a
ceremony** — a `state_token` is what binds the response to the challenge, and one
that leaks inside its window is a ceremony an attacker can try to complete. Both
MUST be wrapped in `Sensitive<T>` (§7) wherever the SDK has that type and MUST NOT
be logged at any level.

`access_token` and `refresh_token` from `WebauthnLoginResponse` are wrapped
exactly as the same two fields are everywhere else in this contract.

The `setup_token` the `setup/register/*` pair carries (contract 1.45) is wrapped
too, by §25.3's row for it — it is the same token and the same credential, and it
is listed there rather than duplicated here so the two sections cannot disagree
about it. It is a bearer credential that completes a login, which makes it the
most sensitive field either section names.

The **challenge**, the **authenticator response** and the `CredentialResponse` are
**not** sensitive in the §7 sense and MUST remain readable: a caller that cannot
inspect the options cannot pass them to a platform API, and a caller that cannot
read `CredentialResponse` cannot show the user what they just enrolled. They are
still not info-level log material by default — a credential `id` is a stable
per-user identifier across sessions, which is exactly what a correlation log
should not accumulate.

There is **no user private key anywhere in this section**, and an SDK's
documentation SHOULD say so where it explains passkeys: the private half never
leaves the authenticator, which is the property the whole mechanism is built on
and the one a reader coming from password auth will not assume.

### §24.6 Running the ceremony: the JSON bridge, and the linked-API helpers

There are two ways an SDK can help with the authenticator half, and every SDK
that claims §24 ships the first.

**§24.6a The JSON bridge (required of every SDK claiming §24).**

The WebAuthn "JSON form" is not an internal detail of this contract — it is the
interchange format the platform authenticator APIs themselves take and return:

| Platform | Takes | Returns |
|---|---|---|
| Browsers | `PublicKeyCredential.parseCreationOptionsFromJSON()` / `parseRequestOptionsFromJSON()` | `credential.toJSON()` |
| **Android** (Credential Manager) | `CreatePublicKeyCredentialRequest(requestJson)` / `GetPublicKeyCredentialOption(requestJson)` | `registrationResponseJson` / `authenticationResponseJson` |
| **iOS / macOS** (`AuthenticationServices`) | decoded fields | assembled fields |

Android is the row that decides this subsection. Credential Manager's entire
WebAuthn surface is **a JSON string in and a JSON string out** — so an SDK does
not need to link a single Android class to be fully usable from an Android app.
It needs to hand the app the request JSON and take the response JSON back.

Every SDK claiming §24 MUST therefore expose:

1. **The challenge in its wire JSON form**, unparsed and unreassembled, ready to
   hand to a platform API. Where an SDK models the challenge as a typed value,
   this is an accessor beside it, not instead of it.
2. **A `*_finish` that accepts the platform's response JSON**, in addition to
   whatever typed form it offers. An SDK that only accepts a typed response
   forces every Android and browser caller to destructure a string the SDK will
   immediately re-serialize, which is three chances to corrupt a signed buffer
   in service of nothing.

Both directions MUST be byte-preserving (§24.0). This is the seam that makes
"no platform ceremony" a statement about *convenience* rather than about
capability, and it is why the table in §24.7 has no "cannot" column.

**§24.6b The linked-API helper (where the SDK can link an authenticator API).**

An SDK whose build can reach an authenticator API SHOULD additionally expose the
three composed helpers of §24.1 — `*_start`, ceremony, `*_finish` in one call.

1. **Composed helpers are additive.** The six wire operations and the §24.6a
   bridge stay public. An SDK MUST NOT make a composed helper the only way to
   reach them — a caller running a virtual authenticator in a test, or holding a
   response produced on another device, needs the pieces. Same shape and same
   argument as §22.14 rule 1.
2. **No software authenticator, ever.** An SDK MUST NOT emulate an authenticator
   in process. A "credential" held in process memory is not a second factor, and
   shipping one under this section's name would make an SDK the weakest link in a
   mechanism chosen for being the strongest. Where no API is reachable, §24.6a is
   the answer and it is a complete one.
3. **Conditional mediation** (passkey autofill) SHOULD be exposed as a flag where
   the platform supports it, and MUST degrade to the explicit prompt where it does
   not. The probe for it MUST NOT throw on platforms that lack it. A ceremony in
   this mode may never settle — the user simply may not pick a passkey — so the SDK
   MUST let the caller abandon it and MUST NOT surface an abandoned conditional
   ceremony as an authentication failure.
4. **`authenticatorAttachment` is the one permitted addition** to the server's
   options (§24.0), and only from an explicit caller argument. It is a hint about
   which authenticator the user is reaching for; without it, a user who asked for a
   security key is prompted for the platform's built-in biometric instead. An SDK
   MUST NOT infer it and MUST NOT default it.
5. **The five ceremony failures are classified, not passed through raw.** Every
   platform reports them as one opaque error type whose only machine-readable part
   is a name, and translating that once beats translating it in every caller:

   | Platform error | Canonical classification |
   |---|---|
   | `NotAllowedError` / `ASAuthorizationError.canceled` | `cancelled` |
   | `InvalidStateError` | `already_registered` |
   | `AbortError` / `.timeout` | `timeout` |
   | `NotSupportedError`, `SecurityError` | `unsupported` |
   | anything else | `unknown` |

   **`cancelled` covers both an explicit refusal and a silent timeout, and this is
   correct rather than lossy.** The WebAuthn spec deliberately refuses to
   distinguish them, because telling a website which one happened leaks whether an
   authenticator was present. An SDK MUST NOT recover the distinction by timing the
   call, and its user-facing copy MUST NOT accuse the user of cancelling.

   `already_registered` is the exclusion list doing its job: the authenticator
   already holds a credential for this account and refused to silently mint a
   second. It MUST be distinguishable from the other four, because it is the only
   one whose remedy is "use a different device" rather than "try again".

   An SDK that ships only §24.6a MUST still expose this classification, applied to
   an error the *caller* hands it — an Android app catching a
   `CreateCredentialException` has the same five outcomes and the same reason to
   want one vocabulary for them.

6. **Feature detection is a query, not an exception.** An SDK exposing a linked-API
   helper MUST expose a predicate for whether this runtime can perform a ceremony,
   so a caller hides a button rather than offering one that throws.

### §24.7 Per-language naming map and per-SDK posture

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `webauthn_register_start` | `webauthn_register_start` | `webauthnRegisterStart` | `webauthn_register_start` | `webauthnRegisterStart` | `webauthnRegisterStart` | `WebauthnRegisterStartAsync` | `webauthnRegisterStart` | `WebauthnRegisterStart` | `webauthnRegisterStart` | `axiam_webauthn_register_start` | `webauthn_register_start` |
| `webauthn_register_finish` | `webauthn_register_finish` | `webauthnRegisterFinish` | `webauthn_register_finish` | `webauthnRegisterFinish` | `webauthnRegisterFinish` | `WebauthnRegisterFinishAsync` | `webauthnRegisterFinish` | `WebauthnRegisterFinish` | `webauthnRegisterFinish` | `axiam_webauthn_register_finish` | `webauthn_register_finish` |
| `webauthn_authenticate_start` | `webauthn_authenticate_start` | `webauthnAuthenticateStart` | `webauthn_authenticate_start` | `webauthnAuthenticateStart` | `webauthnAuthenticateStart` | `WebauthnAuthenticateStartAsync` | `webauthnAuthenticateStart` | `WebauthnAuthenticateStart` | `webauthnAuthenticateStart` | `axiam_webauthn_authenticate_start` | `webauthn_authenticate_start` |
| `webauthn_authenticate_finish` | `webauthn_authenticate_finish` | `webauthnAuthenticateFinish` | `webauthn_authenticate_finish` | `webauthnAuthenticateFinish` | `webauthnAuthenticateFinish` | `WebauthnAuthenticateFinishAsync` | `webauthnAuthenticateFinish` | `WebauthnAuthenticateFinish` | `webauthnAuthenticateFinish` | `axiam_webauthn_authenticate_finish` | `webauthn_authenticate_finish` |
| `webauthn_discoverable_start` | `webauthn_discoverable_start` | `webauthnDiscoverableStart` | `webauthn_discoverable_start` | `webauthnDiscoverableStart` | `webauthnDiscoverableStart` | `WebauthnDiscoverableStartAsync` | `webauthnDiscoverableStart` | `WebauthnDiscoverableStart` | `webauthnDiscoverableStart` | `axiam_webauthn_discoverable_start` | `webauthn_discoverable_start` |
| `webauthn_discoverable_finish` | `webauthn_discoverable_finish` | `webauthnDiscoverableFinish` | `webauthn_discoverable_finish` | `webauthnDiscoverableFinish` | `webauthnDiscoverableFinish` | `WebauthnDiscoverableFinishAsync` | `webauthnDiscoverableFinish` | `WebauthnDiscoverableFinish` | `webauthnDiscoverableFinish` | `axiam_webauthn_discoverable_finish` | `webauthn_discoverable_finish` |
| `webauthn_setup_register_start` | `webauthn_setup_register_start` | `webauthnSetupRegisterStart` | `webauthn_setup_register_start` | `webauthnSetupRegisterStart` | `webauthnSetupRegisterStart` | `WebauthnSetupRegisterStartAsync` | `webauthnSetupRegisterStart` | `WebauthnSetupRegisterStart` | `webauthnSetupRegisterStart` | `axiam_webauthn_setup_register_start` | `webauthn_setup_register_start` |
| `webauthn_setup_register_finish` | `webauthn_setup_register_finish` | `webauthnSetupRegisterFinish` | `webauthn_setup_register_finish` | `webauthnSetupRegisterFinish` | `webauthnSetupRegisterFinish` | `WebauthnSetupRegisterFinishAsync` | `webauthnSetupRegisterFinish` | `WebauthnSetupRegisterFinish` | `webauthnSetupRegisterFinish` | `axiam_webauthn_setup_register_finish` | `webauthn_setup_register_finish` |
| `webauthn_request_json` (§24.6a) | `request_json` | `requestJson` | `request_json` | `requestJson` | `requestJson` | `RequestJson` | `requestJson` | `RequestJSON` | `requestJson` | `axiam_webauthn_request_json` | `request_json` |
| `webauthn_register` (§24.6b) | — | `webauthnRegister` | — | — | — | — | — | — | `webauthnRegister` | — | — |
| `webauthn_login` (§24.6b) | — | `webauthnLogin` | — | — | — | — | — | — | `webauthnLogin` | — | — |
| `webauthn_discoverable_login` (§24.6b) | — | `webauthnDiscoverableLogin` | — | — | — | — | — | — | `webauthnDiscoverableLogin` | — | — |

Async-twin rules follow §1: Java and C# add their `*Async` companions, Kotlin uses
`suspend`, Swift uses `async`, Python exposes every name on both `AxiamClient` and
`AsyncAxiamClient`. `webauthn_request_json` is pure local computation and is
synchronous everywhere.

**Who ships a §24.6b linked-API helper, and why the line falls where it does.**
Reaching an authenticator API is a property of the *build target*, not of the
language, which is why this table matches none of the others in this contract:

| SDK | RP layer (§24.1) | JSON bridge (§24.6a) | Linked-API helper (§24.6b) |
|---|---|---|---|
| TypeScript | yes | yes | **yes** — `navigator.credentials`, in the `axiam-sdk/browser` subpath. Absent from the Node build as a module boundary rather than a runtime throw. |
| Rust (`axiam-sdk-wasm`) | yes | yes | **yes** — `navigator.credentials` through `web-sys`. |
| Swift | yes | yes | **yes** — `AuthenticationServices`, on **both** iOS 16+ and macOS 13+, behind `#if canImport(AuthenticationServices)` and an availability guard. Absent on the Linux build, which is a supported target of this SDK. |
| Kotlin | yes | yes | **no, and this is not a capability gap** — see below. |
| Rust (native), Python, Java, C#, PHP, Go, C, C++ | yes | yes | no. Server-side and CLI runtimes have no authenticator; §24.6b rule 2 forbids inventing one. |

**Kotlin runs on Android and on the desktop JVM, and §24.6a is what makes both
work.** `axiam-kotlin-sdk` is a `kotlin("jvm")` library, and it stays one: an
Android artifact means the Android Gradle Plugin, an `AAR` packaging, an Android
SDK in CI, and a second published coordinate — a large change to the shape of the
deliverable, taken to wrap an API that is already a string in and a string out.
Instead, an Android app passes `requestJson` straight into
`CreatePublicKeyCredentialRequest` / `GetPublicKeyCredentialOption`, and passes
`registrationResponseJson` / `authenticationResponseJson` straight back into the
matching `*Finish`. Nothing is destructured, nothing is re-encoded, and the SDK
links no Android class. That SDK's README MUST show this — worked, in Kotlin, with
the Credential Manager call in it — because "Kotlin ships no §24.6b helper" reads
as "Kotlin cannot do passkeys" to every reader who does not follow the link.

**Swift ships one helper for both its platforms**, not an iOS one and a macOS one.
`ASAuthorizationPlatformPublicKeyCredentialProvider` and
`ASAuthorizationSecurityKeyPublicKeyCredentialProvider` exist on both, and the
presentation anchor is the only genuinely per-platform part; that is supplied by
the caller. The Linux build keeps the RP layer and §24.6a, compiled without the
framework.

### §24.8 Required tests

**Relying-party layer — every SDK claiming §24:**

- **Options pass-through.** Given a `register/start` response whose options carry
  an unusual-but-valid combination — `userVerification: "required"`, a non-empty
  `excludeCredentials`, an `attestation` conveyance other than `"none"`, a
  `timeout`, and at least one `pubKeyCredParams` entry the SDK has no opinion about
  — assert the bytes handed onward are **equal** to the bytes received. Assert
  structurally (compare the parsed value, or the raw JSON), not by spot-checking
  three fields.
- **No synthesized fields.** A `start` response with `authenticatorSelection`
  absent and `timeout` absent produces a ceremony input with both still absent.
- **Response verbatim.** A fixed authenticator response round-trips through
  `*_finish` unchanged, including base64url padding characters exactly as given.
- **Adoption.** A successful `webauthn_authenticate_finish` leaves the client
  authenticated (§24.3 rule 1) — assert the client's own authenticated state, not
  just that a token was returned. A cookie-jar SDK additionally asserts the CSRF
  token was captured, and that a state-changing call made immediately afterwards
  carries it.
- **Memo cleared.** A decision memoized before the ceremony is absent after it
  (§24.3 rule 4).
- **`register/*` without a session** raises `AuthenticationError` with **zero**
  wire calls — assert on the transport, not on the exception type alone.
- **`setup/register/finish` adopts credentials exactly as `mfa_setup_confirm`
  does** (§25.2 rule 2, contract 1.45). Run the same adoption assertions §24.3
  requires of `webauthn_authenticate_finish` against a successful
  `webauthn_setup_register_finish`: the client is authenticated afterwards, a
  cookie-jar SDK has captured the CSRF token, and a state-changing call made
  immediately afterwards carries it. The two completions of a forced first-login
  enrolment must leave the client in the same state, or a caller's next request
  succeeds or fails depending on which factor the user happened to choose.
- **`setup/register/*` carries no session credential.** With a session
  configured *and* a setup token supplied, assert on the transport that neither
  call sent the session's `Authorization` header or cookie. The setup token is
  the credential; attaching a second one invites a server that changes its mind
  about which to trust.
- **The `503` is not retried.** A `register/start` answering `503` produces
  exactly one request. This is §24.4 rule 2 and it will regress the moment
  someone tidies the retry predicate, which is why it is asserted on the request
  count.
- **The `403` message survives.** A `register/finish` answering `403` with a
  policy message surfaces that message, not a generic one.
- **Opaque tokens.** Assert the SDK never parses `state_token` — the simplest
  form is a test whose `state_token` is not a JWT at all and which still
  round-trips, proving nothing decoded it.
- **The two ceremonies are separate operations.** A compile-time or signature
  assertion that `webauthn_authenticate_start` cannot be called without a
  challenge token, and that the discoverable pair does not accept one.
- **Sensitive.** `state_token`, `challenge_token` and both returned tokens do not
  appear in any log line, error payload or debug/`toString` rendering — scan the
  serialized output for the fixture values, as §12, §14, §15, §20 and §22 all
  require.

**The §24.6a JSON bridge — every SDK claiming §24:**

- **Round trip.** The request JSON handed to a caller parses to a value equal to
  the challenge the server sent, field for field — assert structurally, and
  include a fixture whose `excludeCredentials`, `timeout` and `attestation` are
  all populated.
- **A response JSON string reaches `*_finish` unaltered.** Give the bridge a
  fixed platform response string and assert the request body carries those exact
  bytes — no re-encode, no key reordering that changes a value, no dropped
  unknown field.
- **The error classification is reachable without a linked API**, and maps the
  five §24.6b rule 5 outcomes.

**§24.6b linked-API helpers — the SDKs that ship one:**

- Each of the five platform errors maps to its canonical classification, and
  `already_registered` is distinguishable from `cancelled`.
- `authenticatorAttachment` is applied when the caller passes it and **absent**
  from the options when they do not.
- The feature-detection predicate answers `false` rather than throwing on a
  runtime without an authenticator.
- The conditional-mediation probe answers `false` rather than throwing where the
  probe itself is missing, and an abandoned conditional ceremony is not reported
  as an authentication failure.

---

## §25 Account Lifecycle and MFA Enrolment (W2)

**Requirement level: SHOULD (v1.0)** for all eleven SDKs. Stated by name, like §24.

Server implementation: `crates/axiam-api-rest/src/handlers/auth.rs` (the MFA
operations), `email_verification.rs` and `password_reset.rs`.

§1 locked a small authentication vocabulary and it has held well, but it locked the
*middle* of the account's life: `login`, `verify_mfa`, `refresh`, `logout` all
assume an account that already exists, is already verified, and already has its
second factor. Everything that gets an account into that state has been reachable
only by hand-rolling a POST against a path the SDK also knows — which is the exact
divergence §1 exists to prevent, arrived at through omission rather than through
disagreement.

Ten operations. Nine of them are not new server surface; they have been live and
undocumented-for-SDKs since before §1 was written. The tenth,
`resend_own_verification`, **is** new server surface (2026-08, contract 1.31), and it
exists because reusing the ninth for a signed-in caller is what made a profile page's
"resend" button report success while doing nothing — see
[§25.7](#§257-resend_own_verification-and-why-it-is-not-resend_verification).

### §25.1 Canonical operation set and endpoint map

| Canonical operation | Wire call | Auth | Request | Success |
|---|---|---|---|---|
| `mfa_enroll` | `POST /api/v1/auth/mfa/enroll` | **session** | no body | `200` `MfaEnrollResponse` |
| `mfa_confirm` | `POST /api/v1/auth/mfa/confirm` | **session** | `MfaConfirmRequest` | `200` `MfaConfirmResponse` |
| `mfa_setup_enroll` | `POST /api/v1/auth/mfa/setup/enroll` | none (setup token) | `MfaSetupEnrollRequest` | `200` `MfaEnrollResponse` |
| `mfa_setup_confirm` | `POST /api/v1/auth/mfa/setup/confirm` | none (setup token) | `MfaSetupConfirmRequest` | `200` `LoginSuccessResponse` |
| `webauthn_setup_register_start` | `POST /api/v1/auth/webauthn/setup/register/start` | none (setup token) | `SetupRegisterStartRequest` | `200` `StartRegistrationResponse` |
| `webauthn_setup_register_finish` | `POST /api/v1/auth/webauthn/setup/register/finish` | none (setup token) | `SetupRegisterFinishRequest` | `200` `LoginSuccessResponse` |
| `verify_email` | `POST /api/v1/auth/verify-email` | none | `VerifyEmailRequest` | `200`, empty body |
| `resend_verification` | `POST /api/v1/auth/resend-verification` | none | `ResendVerificationRequest` | `200`, empty body |
| `resend_own_verification` | `POST /api/v1/users/me/resend-verification` | **session** | no body | `200` `{ "sent": true }` |
| `request_password_reset` | `POST /api/v1/auth/reset` | none | `RequestResetBody` | `200`, empty body |
| `confirm_password_reset` | `POST /api/v1/auth/reset/confirm` | none | `ConfirmResetBody` | `200`, empty body |
| `password_reset_context` | `GET /api/v1/auth/reset/context?token=<t>` | none | no body | `200` `ResetContextResponse` |

All JSON, all `/api/v1/*`, all carrying `X-Tenant-ID` per §5 rule 2. `tenant_id`
is a **body field** on `verify_email`, `resend_verification` and
`confirm_password_reset` — these are not `/oauth2/*` endpoints and the §12.1 rule 2
query-parameter convention does not reach them. `request_password_reset` accepts
the workspace in slug form as well, like `login`.

`resend_own_verification` takes **no body at all** — not even an address. The server
reads the address off the caller's own record, and an SDK MUST NOT add a parameter
for it: a signature that accepts an address is a signature that lets an authenticated
session mail an arbitrary one.

Eight of the twelve are **deliberately unauthenticated**: a user who cannot log in
is the entire audience for a password reset, and a user whose email is unverified
may have no session at all.

The last two rows are the WebAuthn half of forced enrolment, added at contract
1.45 and specified in full in §24.1 and §24.7 — they are listed here because
this is where a reader looks for "what can I do with a setup token", and the
answer is no longer "TOTP only".

### §25.2 The two MFA enrolment paths are different, and confusing them locks users out

`mfa_enroll` / `mfa_confirm` is **voluntary enrolment by a signed-in user**. It
needs a session and it changes nothing about the current one.

`mfa_setup_enroll` / `mfa_setup_confirm` is **forced enrolment during login**. It
is reached when `POST /api/v1/auth/login` answers `403` with
`mfa_setup_required: true` and a `setup_token`, because the tenant requires MFA and
this account has none. There is no session yet — the setup token *is* the
credential — and `mfa_setup_confirm` answers `LoginSuccessResponse`, completing the
login that was interrupted.

**As of contract 1.45 that path has a second pair**:
`webauthn_setup_register_start` / `webauthn_setup_register_finish` enrol a passkey
or a security key instead of TOTP, from the same setup token, and
`webauthn_setup_register_finish` answers the same `LoginSuccessResponse`. A user
of an enforcing tenant chooses their first factor; they are no longer required to
own a TOTP app to get in. An SDK that surfaces the setup branch (rule 1) SHOULD
make both reachable from it, and MUST NOT present TOTP as the only option where
its runtime can perform a ceremony (§24.6's feature-detection predicate is how it
knows).

1. **`login` MUST surface the setup branch as an outcome, not as an error.** An SDK
   whose `login` maps the `403` to §2 `AuthorizationError` has told the caller they
   lack permission to log in, when what the server said was "finish setting up, here
   is the token". The caller cannot recover from the former and can from the latter.
   Where an SDK's `login` returns a discriminated result (§1's `LoginResult` shape),
   it gains a third variant carrying the setup token. Where the language has no such
   type, the SDK MUST raise a **distinct** error type carrying the token, and MUST
   NOT reuse `AuthorizationError`.

   *This is a **breaking change** for any SDK whose login result is exhaustively
   matched by callers — see the Breaking Changes Log entry for contract 1.28. It is
   taken because the alternative is an SDK that reports a recoverable, guided state
   as a refusal, and no amount of documentation makes a caller handle a variant the
   type does not have.*

2. **Either completion adopts credentials exactly as `login` does** — both
   `mfa_setup_confirm` and `webauthn_setup_register_finish` *are* the completion
   of a login, and answer the same `LoginSuccessResponse`. §24.3's five adoption
   rules apply verbatim to both, including clearing the §17 decision memo. An SDK
   that adopted on one and not the other would leave a caller authenticated or
   not depending on which factor the user chose, which is not a distinction any
   caller can be expected to handle. §24.8 requires the test.

3. **`mfa_enroll` does not adopt anything and does not change the session.** An SDK
   MUST NOT clear the decision memo on it: the subject has not changed, and
   discarding a warm memo on an unrelated profile action is a needless round trip
   for every subsequent check.

4. **Enrolment is two calls and the first one is not enough.** `mfa_enroll` returns
   a secret; the factor is not active until `mfa_confirm` accepts a code derived
   from it. An SDK MUST NOT present a composed one-call helper here, because the
   human step in the middle — scanning the URI, reading a code — is not something a
   composed helper can wait for, and one that returned after `enroll` would report
   MFA as enabled when it is not.

### §25.3 `Sensitive<T>` applicability, and the one field that will be got wrong

| Field | Wrapped? | Why |
|---|---|---|
| `secret_base32` | **yes** | The TOTP shared secret. Anyone holding it can generate valid codes forever. |
| `totp_uri` | **yes** | `otpauth://totp/...?secret=<the same secret>` — it *contains* `secret_base32`. An SDK that wraps the secret and leaves the URI bare has wrapped nothing: the URI is the field that actually gets logged, because it is the field the caller passes to a QR renderer. |
| `setup_token` | **yes** | A bearer credential that completes a login. |
| `token` (email verification, password reset) | **yes** | Single-use, and single-use is not the same as harmless: it is a credential right up until it is spent. |
| `new_password` | **yes** | Where the SDK has the type, and per §7 as everywhere else. |
| `totp_code` | **yes** | Short-lived, but a code in a log is a code in a log. |
| `mfa_enabled`, the reset context | no | Not credentials. |

`totp_uri` is called out in its own row because it is the one an implementer skips.
Every SDK's test for §25 MUST scan serialized output for the **secret value itself**
rather than for the field name, which catches the URI case automatically.

### §25.4 Password reset, and what `password_reset_context` is actually for

`password_reset_context` exists because of §23. A tenant with OPAQUE enabled needs
the client to build a registration record before it can send a new password, and
building one needs the server's OPAQUE parameters — which the client cannot know
before it has a token to ask with. The endpoint answers with the effective OPAQUE
policy for the account the token belongs to.

1. **An SDK that implements §23 MUST call `password_reset_context` before
   `confirm_password_reset`** and MUST populate `ConfirmResetBody.opaque` when the
   context says the tenant requires it. Sending `new_password` in plaintext to a
   tenant in `opaque_mode: required` is refused, and refused late.
2. **It discloses no identity.** Contract 1.26 removed the username from this
   response when OPAQUE replaced SRP — OPAQUE has no identity in its key derivation,
   so there was nothing left that needed it, and an unauthenticated endpoint that
   confirms which account a token belongs to is an oracle worth not having. An SDK
   MUST NOT reintroduce one by inferring the account from elsewhere and displaying
   it beside the form.
3. **`404` means unknown, expired or already-consumed**, and the three are
   deliberately not distinguished. An SDK MUST NOT present a message that
   distinguishes them either.

`request_password_reset` answers `200` whether or not the address exists. This is
not an implementation detail an SDK may improve on: an SDK that surfaced a
"no such user" state — even inferred from timing — would turn the endpoint into
the enumeration oracle the uniform response exists to prevent.

### §25.5 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `mfa_enroll` | `mfa_enroll` | `mfaEnroll` | `mfa_enroll` | `mfaEnroll` | `mfaEnroll` | `MfaEnrollAsync` | `mfaEnroll` | `MfaEnroll` | `mfaEnroll` | `axiam_mfa_enroll` | `mfa_enroll` |
| `mfa_confirm` | `mfa_confirm` | `mfaConfirm` | `mfa_confirm` | `mfaConfirm` | `mfaConfirm` | `MfaConfirmAsync` | `mfaConfirm` | `MfaConfirm` | `mfaConfirm` | `axiam_mfa_confirm` | `mfa_confirm` |
| `mfa_setup_enroll` | `mfa_setup_enroll` | `mfaSetupEnroll` | `mfa_setup_enroll` | `mfaSetupEnroll` | `mfaSetupEnroll` | `MfaSetupEnrollAsync` | `mfaSetupEnroll` | `MfaSetupEnroll` | `mfaSetupEnroll` | `axiam_mfa_setup_enroll` | `mfa_setup_enroll` |
| `mfa_setup_confirm` | `mfa_setup_confirm` | `mfaSetupConfirm` | `mfa_setup_confirm` | `mfaSetupConfirm` | `mfaSetupConfirm` | `MfaSetupConfirmAsync` | `mfaSetupConfirm` | `MfaSetupConfirm` | `mfaSetupConfirm` | `axiam_mfa_setup_confirm` | `mfa_setup_confirm` |
| `verify_email` | `verify_email` | `verifyEmail` | `verify_email` | `verifyEmail` | `verifyEmail` | `VerifyEmailAsync` | `verifyEmail` | `VerifyEmail` | `verifyEmail` | `axiam_verify_email` | `verify_email` |
| `resend_verification` | `resend_verification` | `resendVerification` | `resend_verification` | `resendVerification` | `resendVerification` | `ResendVerificationAsync` | `resendVerification` | `ResendVerification` | `resendVerification` | `axiam_resend_verification` | `resend_verification` |
| `resend_own_verification` | `resend_own_verification` | `resendOwnVerification` | `resend_own_verification` | `resendOwnVerification` | `resendOwnVerification` | `ResendOwnVerificationAsync` | `resendOwnVerification` | `ResendOwnVerification` | `resendOwnVerification` | `axiam_resend_own_verification` | `resend_own_verification` |
| `request_password_reset` | `request_password_reset` | `requestPasswordReset` | `request_password_reset` | `requestPasswordReset` | `requestPasswordReset` | `RequestPasswordResetAsync` | `requestPasswordReset` | `RequestPasswordReset` | `requestPasswordReset` | `axiam_request_password_reset` | `request_password_reset` |
| `confirm_password_reset` | `confirm_password_reset` | `confirmPasswordReset` | `confirm_password_reset` | `confirmPasswordReset` | `confirmPasswordReset` | `ConfirmPasswordResetAsync` | `confirmPasswordReset` | `ConfirmPasswordReset` | `confirmPasswordReset` | `axiam_confirm_password_reset` | `confirm_password_reset` |
| `password_reset_context` | `password_reset_context` | `passwordResetContext` | `password_reset_context` | `passwordResetContext` | `passwordResetContext` | `PasswordResetContextAsync` | `passwordResetContext` | `PasswordResetContext` | `passwordResetContext` | `axiam_password_reset_context` | `password_reset_context` |

Async-twin rules follow §1.

**An SDK that already shipped `confirm_password_reset` under a different name keeps
it as a deprecated alias** for one release rather than renaming in place. Seven SDKs
had reached `POST /api/v1/auth/reset/confirm` before this section existed, under
names that did not agree with each other — which is the divergence §25 is closing,
and breaking those callers to close it faster would be a poor trade.

### §25.6 Required tests

- `mfa_enroll` returns a secret and a URI; the URI contains the secret; **neither
  the secret nor the URI appears in any log line, error payload or debug rendering**
  — scan for the secret *value*, per §25.3.
- `mfa_confirm` with a wrong code raises `AuthenticationError` and leaves
  `mfa_enabled` false.
- `mfa_enroll` does **not** clear the decision memo; `mfa_setup_confirm` **does**
  (§25.2 rules 2–3).
- A `login` answering `403 mfa_setup_required` produces the setup outcome carrying
  the token, and **not** `AuthorizationError` (§25.2 rule 1).
- `mfa_setup_confirm` leaves the client authenticated, asserted on the client's own
  state.
- `request_password_reset` for an unknown address resolves successfully — assert the
  SDK does not raise, and does not expose any signal distinguishing it from a known
  address.
- `password_reset_context` on an unknown token raises the §2 mapping of `404` and
  the SDK exposes no distinction between unknown, expired and consumed.
- An SDK implementing §23 asserts that `confirm_password_reset` against a tenant
  whose context requires OPAQUE sends an `opaque` object and **no** plaintext
  `new_password`.
- `setup_token`, the verification token and the reset token are `Sensitive<T>`
  where the SDK has it, and absent from serialized output.
- `resend_own_verification` sends **no caller-supplied data** — assert on the
  serialized request that it carries no address field, not merely that the method
  signature has no parameter for one. An SDK that sends an empty body, or the empty
  JSON object its `mfa_enroll` already sends, is conformant; one that sends
  `{"email": …}` is not, whatever it does with the value.
- `resend_own_verification` against a `409` raises the §2 mapping of `409` and does
  **not** resolve successfully; the same against a `429` raises the §2 mapping of
  `429`. Both assertions matter more than they look: the bug this operation exists to
  fix was a success return on a request that sent nothing.
- `resend_own_verification` with no token raises `AuthError` with **zero** wire calls,
  like every other session-authenticated operation.
- `resend_verification` and `resend_own_verification` are distinct operations that hit
  distinct paths — assert the path of each, because an SDK that aliases one to the
  other reintroduces exactly the defect §25.7 describes.

### §25.7 `resend_own_verification`, and why it is not `resend_verification`

The two look like the same operation and are not. Reusing one for the other is a
defect that shipped, survived a beta, and was invisible from the client side, so the
distinction is stated here rather than left to a reader of the endpoint map.

`resend_verification` takes an address from an **unauthenticated** caller. It must
answer a constant `200 {"sent": true}` whatever happens — a `404` for "no such user"
or a `429` for "rate limited" would tell an anonymous caller which addresses have
accounts. That constancy is a security property, and §25's D-15 tests pin it.

`resend_own_verification` is asked by a caller that is **signed in to the account it
is asking about**. It already knows the account exists. None of the three outcomes
discloses anything the caller did not bring with it, so this endpoint says which one
happened:

| Status | Meaning | §2 mapping |
|---|---|---|
| `200` `{ "sent": true }` | A token was minted and the mail enqueued. | success |
| `409` | Already verified, or the account is in a state that must not be sent a live token. | `AuthzError` (the `ConflictError` sub-type where the SDK has §27's) |
| `429` | The daily resend limit is reached. | `NetworkError` |

Three rules, normative:

1. **An SDK MUST expose both operations.** They are not alternatives; they serve
   callers in different states. A sign-up screen has no session and needs the
   enumeration-safe one; a profile page has a session and needs the truthful one.
2. **An SDK MUST NOT route one to the other**, in either direction, and MUST NOT
   "helpfully" fall back from the authenticated one to the public one on `409` or
   `429`. That fallback turns both failures back into `200 {"sent": true}` and
   restores the original bug with an extra round-trip.
3. **`sent: true` means enqueued, not delivered.** Delivery is asynchronous and can
   still fail at the provider. An SDK MUST NOT document or name this operation as
   though the mail has arrived — a mail queue that accepts everything in front of a
   provider that rejects it looks identical to this operation working.

---

## §26 Pushed Authorization Requests (RFC 9126)

**Requirement level: SHOULD (v1.0)** for the eleven SDKs, and **MUST** for any SDK
claiming the §21 FAPI 2.0 *client* role — `profile: "fapi2"` sets `require_par` on
the registration, so a FAPI 2.0 client that cannot push cannot authorize at all.

Server implementation: `crates/axiam-oauth2/src/par.rs` and the `request_uri`
branch of `authorize` in `crates/axiam-api-rest/src/handlers/oauth2.rs`.

PAR moves the authorization request off the browser. Instead of putting
`scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user agent
carries, the client POSTs them straight to AXIAM over an authenticated back
channel and puts an opaque `request_uri` in the redirect. What travels through the
browser is then a random string that cannot be edited into meaning something else.

This is a **§12 extension, not a replacement**: `oidc_discover`, `oidc_exchange`,
`oidc_refresh` and the whole §12.4 ID-token checklist are unchanged, and a client
that never calls `oidc_par` behaves exactly as it did.

### §26.1 Canonical operation set and endpoint map

| Canonical operation | Wire call | Request | Success |
|---|---|---|---|
| `oidc_par` | `POST /oauth2/par?tenant_id=<uuid>` | `application/x-www-form-urlencoded` / `PushedAuthorizationRequest` | **`201`** `PushedAuthorizationResponse` |

The §12.1 wire rules apply unchanged and without exception: form-encoded body,
`tenant_id` as a **query** parameter and never a body field, `X-Tenant-ID` still
emitted per §5 rule 2, no HTTP Basic. A slug-only client cannot call `oidc_par`,
for the same reason and with the same client-side error as the other five
tenant-scoped `/oauth2/*` operations (§12.1 rule 2).

**It answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and the response
names a resource that did not exist before the call. An SDK whose success predicate
is `status == 200` will treat every successful push as a failure. This is the single
most likely defect in an implementation of this section, which is why it is stated
here rather than left to the table above.

**It is authenticated, unlike `/oauth2/device_authorization`.** That asymmetry is
the point of the mechanism: the parameters stop travelling through the browser, and
the ones that arrive are attributable to a client that proved it holds a credential.
Client authentication follows §12.1 rule 4 as amended by SEC-093 — `client_secret`
for `client_secret_post`, `client_assertion` + `client_assertion_type` for
`private_key_jwt`, and **nothing at all** for the two mTLS methods, whose credential
is the TLS connection. An SDK MUST NOT send `client_secret` for a client registered
for a strong method: it is refused with `invalid_client`, not ignored.

### §26.2 Semantics (normative)

1. **`oidc_par` pushes what `oidc_begin` computed; it does not compute anything
   itself.** The `state`, `nonce`, `code_verifier` and `code_challenge` are produced
   exactly as §12.1's `oidc_begin` construction rules 1–4 require — same entropy
   floors, same encodings, same `S256`. An SDK MUST NOT grow a second generator
   here. The natural shape is `oidc_begin` → push its parameters → replace its
   `url`; the `code_verifier` the caller must keep for `oidc_exchange` is the one
   `oidc_begin` already gave them.

2. **The authorization URL built from a `request_uri` carries exactly two query
   parameters: `client_id` and `request_uri`.** Not `response_type`, not
   `redirect_uri`, not `scope`, not `state`, not the PKCE pair — the server
   **refuses** a request that carries both a `request_uri` and any inline
   authorization parameter, rather than merging them.

   The refusal is not tidiness and an SDK MUST NOT work around it by "helpfully"
   re-adding the parameters for compatibility. Merging is where parameter confusion
   lives: an attacker supplies the inline value they want and lets the pushed copy
   satisfy whichever check reads the other one. `state` and `nonce` come from the
   pushed request too, for the same reason — they were the client's to choose at
   push time, and honouring a query-string copy would let the browser substitute
   its own.

3. **The `request_uri` is single-use and short-lived.** It is consumed when
   `/oauth2/authorize` reads it. An SDK MUST NOT retry a redirect with a spent
   `request_uri`, MUST NOT cache one across authorization attempts, and MUST NOT
   treat `expires_in` as advisory. A second use is refused, never a
   duplicate-suppressed success.

   **How that refusal is delivered depends on the request, and contract 1.46
   made the second form reachable** where before there was only the first. A
   handle that is unknown, expired, already spent, or issued to a different
   client is answered either:

   - **directly** — `invalid_request` in an `OAuth2ErrorResponse` body, or the
     same code rendered as an HTML error page when the caller is a browser —
     when the authorization request named no `redirect_uri`, or named one this
     client did not register. **This is the only form a conformant SDK can
     produce**, because rule 2's authorization URL carries no `redirect_uri` at
     all; or
   - **redirected to the relying party** — `error=invalid_request_uri` on the
     registered `redirect_uri`, carrying the request's own `state` — when the
     request did name a `redirect_uri` the client registered (RFC 6749
     §4.1.2.1). The code is OIDC Core §3.1.2.6's `invalid_request_uri` and not
     `invalid_request` because it is the one a relying party can act on: push
     again and restart. A handle issued to a **different** client keeps
     `invalid_request` — that is a different failure and stays distinguishable
     from a handle that is simply gone.

   Nothing here asks an SDK to change anything. Rule 2 is unchanged and still
   forbids sending `redirect_uri` beside a `request_uri`, so the redirected form
   is out of a conformant SDK's reach; it is written down because
   [§21.4](#§214-rfc-9207-iss-on-authorization-responses-informative-act-on-it)
   already tells an SDK to validate `iss` on an error redirect, and an
   application that handles one should know which code it may carry.

4. **`oidc_par` is not retryable.** It is a `POST` that creates server state, so it
   falls outside §16.2's read-only eligibility exactly as `oidc_exchange` does. A
   transport failure after the request left the client MUST be surfaced, not retried:
   the safe recovery is a fresh push, which costs one round trip and cannot
   double-consume anything.

5. **`request_uri` is opaque.** An SDK MUST NOT parse it, MUST NOT validate its
   `urn:` prefix as a precondition, and MUST NOT reconstruct one. Checking the
   prefix buys nothing — a server that sends something else is a server the client
   cannot help — and it breaks the moment the format is versioned.

6. **PAR does not change the token exchange.** `oidc_exchange` sends the same
   `authorization_code` grant with the same `code_verifier` and the same
   `redirect_uri` it always did. The `redirect_uri` sent at exchange is the one that
   was *pushed*, which is the same value `oidc_begin` produced — an SDK that stores
   the pushed parameters and the exchange parameters separately has created two
   places for them to disagree.

### §26.3 Error mapping

`400` and `401` from `/oauth2/par` carry an `OAuth2ErrorResponse` and map to
`OAuthProtocolError` through the shared §12.3 rule 3 mapper — dispatch on the
`error` field at any status, per contract 1.12. No grant-local mapper is permitted
here; the whole point of 1.12 was removing the nine that existed.

`invalid_client` on a push is the most common configuration failure in this section
and an SDK's documentation SHOULD name the three causes: a wrong secret, a secret
sent by a client registered for `tls_client_auth`/`private_key_jwt`/
`self_signed_tls_client_auth`, or a client certificate the transport did not
present.

### §26.4 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `oidc_par` | `oidc_par` | `oidcPar` | `oidc_par` | `oidcPar` | `oidcPar` | `OidcParAsync` | `oidcPar` | `OidcPar` | `oidcPar` | `axiam_oidc_par` | `oidc_par` |

Async-twin rules follow §1. Where an SDK offers a helper that builds the
`request_uri` authorization URL, it MUST be named for the §12 operation it extends
rather than introducing a second vocabulary — the accepted forms are a flag or an
overload on the SDK's existing authorize-URL builder, never a parallel
`par_authorize_url`.

### §26.5 `Sensitive<T>` applicability

`client_secret` and `client_assertion` are wrapped exactly as §12 already wraps
them.

`request_uri` is **wrapped**. It is short-lived and single-use, and both of those
are reasons it gets treated as harmless — but between the push and the redirect it
is a bearer handle to a fully-formed authorization request, and a log line is
exactly the wrong place for it to sit for the length of that window. `expires_in`
is not sensitive.

`code_verifier` is wrapped as §12 already requires; the `code_challenge` is not.

### §26.6 Required tests

- A `201` is treated as **success** — assert against a mocked `201`, because a
  success predicate written as `== 200` passes every other test in this section.
- The pushed body carries the form fields §26.2 rule 1 names, form-encoded, with
  `tenant_id` in the **query** and absent from the body.
- The authorization URL built from a `request_uri` carries **exactly**
  `client_id` and `request_uri` — assert on the full parameter set, not on the
  presence of the two.
- A slug-only client raises the §12.1 rule 2 client-side error with **zero** wire
  calls.
- A `400 invalid_request` maps to `OAuthProtocolError` through the shared mapper,
  carrying the server's `error` value.
- `oidc_par` is **not** retried on a `5xx` or a transport failure — assert exactly
  one request (§26.2 rule 4).
- `request_uri` and `client_secret` do not appear in any log line, error payload or
  debug rendering — scan the serialized output for the fixture values.
- An end-to-end assertion that the `code_verifier` surviving from `oidc_begin`
  through the push is the one `oidc_exchange` sends.

---

## §27 Management API (M1)

**Requirement level: SHOULD (v1.0), contract 1.30.** Every section before this one
assumes a populated tenant. §1 logs a user in; §10 guards a route with a role; §13
verifies a webhook's signature; §22 runs a reactor. None of them can create the user,
define the role, register the webhook, or declare the reactor — so until now an
application built on an AXIAM SDK authenticated users it could not create and checked
access to resources it could not declare. The tenant had to be built first, by hand,
through `curl` or the admin UI, and every application that needed to build one at
runtime hand-rolled HTTP against paths its SDK already knew.

That is the same gap [§25](#§25-account-lifecycle-and-mfa-enrolment-w2) closed for the
nine account-lifecycle endpoints, at eighteen times the surface area. This section closes
it for the rest: **162 operations across 24 namespaces**, which is the entire server API
minus the routes other sections already own and minus the five the
[§27.0](#§270-the-boundary) boundary deliberately excludes. (The section was written at
147. The count is the registry's `operation_count` and moves with it. Contract 1.51
re-rendered every figure in this section from the registry it names; see §27.1.)

An SDK that ships §1–§26 without this section remains conformant. An SDK that ships it
states §27 by name (see [Conformance Statement](#conformance-statement)) — by name rather
than by extending a range, for the reason §14/§15 are: several SDKs have already stated
their conformance, and silently widening a range turns a true statement into a false one
without anyone editing it.

### §27.0 The boundary

**In scope: everything in [`management-registry.json`](management-registry.json).** That
file is generated from [`openapi.json`](openapi.json) by
`scripts/gen-management-registry.py` and is the normative vocabulary of this section —
not the tables below, which are rendered from it for a human reader and which a
disagreement resolves *against*.

Five routes are excluded by name — the registry's `excluded_operations` — rather than by
belonging to another section's tag. Until contract 1.51 this table listed two of them.
The registry, which is normative and against which a disagreement resolves, always
listed all five.

| Route | Why it is not SDK surface |
|-------|---------------------------|
| `POST /api/v1/organizations` | Provisioning an organization is a platform-operator act. It allocates the CA trust root every tenant beneath it chains to, and it happens once, out of band, before any SDK client has a tenant to be constructed with. |
| `DELETE /api/v1/organizations/{org_id}` | Destroying an organization destroys every tenant, user, role and certificate under it. There is no application-level use for it and no undo, so it is deliberately unreachable from a client library. |
| `POST /api/v1/admin/bootstrap` | First-run creation of the first organization, its scope tenant and the first administrator. It is gated on an out-of-band setup token or on `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, and performed once by a platform operator. No tenant-scoped client can hold the credential to call it, because the call is what brings the first tenant into existence. See the note below the table. |
| `GET /health/jobs` | An operator's inventory of the deployment's background jobs: names, last runs and consecutive failures. It is deliberately not routed at the edge, and an SDK talks to the edge. Its siblings `/health` and `/ready` **are** §27 surface (`platform.health`, `platform.ready`). |
| `POST /api/v1/users/me/resend-verification` | Self-service on the caller's own record, owned by [§25](#§25-account-lifecycle-and-mfa-enrolment-w2) (§25.7). It sits under the `users` tag only because of its path. |

**`/admin/bootstrap` gets no helper, and a provisioning tool still needs its outcomes.**
It is the one excluded route a tool built on an SDK is likely to reach for, since a
fresh deployment has no organization for the tool to address. An SDK MUST NOT generate a
method for it, and MUST NOT hide one behind the management accessor: the registry's
reason stands (decision D-8 of the dogfooding remediation plan). A tool that drives it
over raw HTTP handles these outcomes. They are listed here so that they are handled
consistently rather than rediscovered:

| Status | `error` | Meaning |
|---|---|---|
| `201` | — | Created. The body is `{ message, organization_id, organization_slug, tenant_id, tenant_slug, user_id }`. `tenant_id` is the organization's own scope tenant (§5.2.1), not an ordinary tenant. **No token is issued**: the administrator signs in afterwards with an ordinary §5.1 login against `tenant_slug: "organization"`. |
| `403` | `authorization_denied` | The gate is not satisfied. Either the email differs from `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, or no gate is set and no setup token was sent, or the setup token is unknown or already consumed. The gate is checked **before** the fields, so a request that fails both answers `403`. |
| `409` | `already_exists` | Bootstrap has already happened on this deployment, including a lost race between two concurrent calls. It is final: treat it as "this deployment exists", not as a retryable conflict, and never retry it under §16. |
| `400` | `validation_error` | A required field is missing (`organization_name`, `email`, `username`, `password`), `organization_name` has no alphanumeric character, or OPAQUE was requested where the deployment has no OPAQUE engine. |

The route is public and never answers `401`. A lost setup token is re-minted by the
operator (`axiam-server setup-token --remint`, server T22.7), never by a client.

Everything else an organization-scoped route offers **is** in scope, including
`ca_certificates` and org-level `settings` and `email_config` — a client that could not
reach them could not create a tenant or issue a device certificate, which is most of what
this section exists for.

The remaining server routes belong to sections that already specify them, and are
excluded by tag:

| Tag | Owned by |
|-----|----------|
| `auth` | §1 login/MFA/refresh/logout, §23 OPAQUE, §25 account lifecycle |
| `authz` | §1 `check_access` / `batch_check` |
| `oauth2` | §12 RP helpers, §14 device grant, §15 token exchange, §26 PAR |
| `oidc` | §12 discovery/JWKS; `/oauth2/userinfo` is §1.1 gRPC-only by design |
| `uma` | §20 UMA 2.0 protection API and ticket grant |
| `webauthn` | §24 ceremonies — credential I/O, not administration |
| `federation-sso` | §12 public SSO entry points |
| `device` | §14 device-grant user-interaction endpoints |

**The vocabulary is derived, not declared.** §1 locks eight method names in a table a
human reviews. That does not scale to 162 across eleven languages: the table would be
wrong by the next release. So an SDK's §27 surface **MUST** be generated from
`management-registry.json` and **MUST NOT** be hand-maintained. Two gates in the AXIAM
repository's CI enforce the registry's own correctness — one fails when it names a route
the server no longer serves, the other when a live management route is claimed by no
namespace and excluded by no stated reason. The second is the one that matters: without
it, adding a handler to `axiam-api-rest` silently creates surface no SDK can reach.

### §27.1 Namespaces and the canonical operation set

Rendered from `management-registry.json`. Re-rendered in contract 1.51. The table had last been
rendered at 148 rows while the prose around it said 147, and the registry had since
grown to 162. The fourteen operations added since are:

- `users.list_sessions`;
- the three `groups` service-account membership operations;
- the three `roles` service-account assignment operations;
- `service_accounts.list_roles` and `list_groups`;
- the two `oauth2_clients` registration-token operations;
- the three `privacy` consent operations.

Each SDK's §27.8 CI regeneration already carried them, so no SDK surface changes here.
Only the prose had fallen behind. The five CRUD verbs read identically in every
namespace that has them — `list`, `create`, `get`, `update`, `delete` — and anything
beyond CRUD says what it does. `generate` rather than `create` marks the namespaces where
the server mints key material the caller never supplies; `sign_csr` (contract 1.45) marks
the operation where the caller did — the request carries a PKCS#10 request for a key
AXIAM never holds, and the response has no key field to return.

| Namespace | Ops | Operations |
|-----------|-----|------------|
| `organizations` | 3 | `list`, `get`, `update` |
| `tenants` | 6 | `list`, `create`, `get`, `update`, `delete`, `export_audit` |
| `users` | 11 | `list`, `create`, `get`, `update`, `delete`, `list_mfa_methods`, `delete_mfa_method`, `reset_mfa`, `unlock`, `list_roles`, `list_sessions` |
| `groups` | 12 | `list`, `create`, `get`, `update`, `delete`, `list_members`, `add_member`, `remove_member`, `list_roles`, `list_service_accounts`, `add_service_account`, `remove_service_account` |
| `roles` | 17 | `list`, `create`, `get`, `update`, `delete`, `list_users`, `assign_to_user`, `unassign_from_user`, `list_groups`, `assign_to_group`, `unassign_from_group`, `list_permissions`, `grant_permission`, `revoke_permission`, `list_service_accounts`, `assign_to_service_account`, `unassign_from_service_account` |
| `permissions` | 5 | `list`, `create`, `get`, `update`, `delete` |
| `resources` | 7 | `list`, `create`, `get`, `update`, `delete`, `list_children`, `list_ancestors` |
| `scopes` | 5 | `list`, `create`, `get`, `update`, `delete` |
| `service_accounts` | 9 | `list`, `create`, `get`, `update`, `delete`, `rotate_secret`, `bind_certificate`, `list_roles`, `list_groups` |
| `certificates` | 5 | `list`, `generate`, `sign_csr`, `get`, `revoke` |
| `ca_certificates` | 10 | `list`, `generate`, `import_ca`, `get`, `revoke`, `migrate_custody`, `set_mtls_trust_anchor`, `list_signing_cas`, `generate_signing_ca`, `sign_signing_ca_csr` |
| `pgp_keys` | 6 | `list`, `generate`, `get`, `revoke`, `encrypt`, `sign_audit_batch` |
| `webhooks` | 5 | `list`, `create`, `get`, `update`, `delete` |
| `oauth2_clients` | 7 | `list`, `create`, `get`, `update`, `delete`, `create_registration_token`, `list_registration_tokens` |
| `federation` | 9 | `list_configs`, `create_config`, `get_config`, `update_config`, `delete_config`, `list_user_links`, `delete_link`, `oidc_authorize`, `oidc_callback` |
| `notification_rules` | 5 | `list`, `create`, `get`, `update`, `delete` |
| `email_config` | 8 | `get_org`, `set_org`, `delete_org`, `test_org`, `get_tenant`, `set_tenant`, `delete_tenant`, `test_tenant` |
| `directory` | 6 | `get`, `set`, `update`, `delete`, `link_account`, `get_sync_status` |
| `settings` | 7 | `get_org`, `set_org`, `get_effective`, `set_effective`, `get_tenant_override`, `set_tenant_override`, `delete_tenant_override` |
| `scim_tokens` | 3 | `list`, `create`, `revoke` |
| `reactors` | 6 | `list`, `create`, `get`, `update`, `delete`, `list_events` |
| `webauthn_policy` | 3 | `get`, `set`, `compliance_report` |
| `audit` | 2 | `list`, `list_system` |
| `privacy` | 7 | `request_export`, `download_export`, `request_delete`, `cancel_delete`, `list_consents`, `grant_scope_consent`, `withdraw_scope_consent` |
| `platform` | 4 | `health`, `ready`, `mds_status`, `mds_refresh` |

Contract 1.54 adds the `directory` namespace ([§30](#§30-directory-configuration-management-api-contract-154)),
which brings the registry to 168 operations across 25 namespaces. Contract 1.55 adds the `saml`
namespace ([§29](#§29-saml-service-provider-registration-management-api-contract-155)),
eleven operations, which brings it to 179 across 26 once the server task regenerates it. Contract 1.56 adds the
`ssf` namespace ([§32](#§32-ssf-stream-registration-and-the-receiver-helper-contract-156)), five
operations, which brings the registry to 184 across 27. Contract 1.57 adds the `scim_targets`
namespace ([§31](#§31-outbound-scim-targets-management-api-contract-157)), six operations, which
brings it to 190 across 28. Contract 1.58 adds **none**: CIBA
([§33](#§33-ciba--client-initiated-backchannel-authentication-contract-158)) is OAuth2 protocol and
a console page, not management, so the registry stays at 190 operations across 28 namespaces
(its approval routes sit under the excluded tag `ciba`). The figures quoted elsewhere
in §27 were last re-rendered at 1.51 and are not re-rendered here; the registry is the
authority ([§27.0](#§270-the-boundary)).

Contract 1.60 adds **no namespace and no operation**; it adds one optional member to the
`notification_rules` models and four server-behaviour notes
([§27.15](#§2715-model-and-behaviour-notes-contract-160)). `GET /api/v1/ciba/requests` joins the
approval routes under the excluded tag `ciba` ([§33.3](#§333-server-rules-every-sdk-can-observe-normative)
rule 16), and the certificate revocation list route
([§35](#§35-certificate-revocation-lists-informative)) is outside `/api/v1`: neither is
registry surface.

### §27.2 The surface is namespaced, not flat

§1's operations sit directly on the client. This section's 162 **MUST NOT**. An SDK
exposes each namespace as a handle reached from the client, and the operations on that
handle:

```
client.users().list()            client.roles().assign_to_user(role_id, user_id)
client.tenants().create(spec)    client.certificates().generate(spec)
```

Three reasons this is normative rather than stylistic:

1. **The names collide.** Eighteen namespaces have a `list`; seventeen have a `get`. Flattened,
   every one needs a disambiguating prefix, and `listUsers`/`listRoles`/`listRolePermissions`
   is a naming scheme that has to be invented once per operation and remembered by every
   caller. Namespaced, `list` means `list` everywhere.
2. **162 methods on one object is not an API.** It is a wall. Every SDK's client already
   carries §1, §12, §14, §15, §20, §24, §25 and §26; adding the management surface flat
   would roughly quintuple it and bury the eight operations most callers actually want.
3. **It keeps §1's vocabulary lock meaningful.** §1 forbids new login/auth/authz method
   names on the client. Namespacing means this section adds *no* names to that object at
   all — only namespace accessors — so the lock stays exactly as tight as it was.

**Handle rules (normative).**

1. A namespace handle is **cheap and stateless**. It borrows or references the client and
   carries no configuration, no connection and no cached data of its own. Acquiring one
   performs **no I/O**. An SDK MAY return a fresh handle on every access or memoize one; a
   caller MUST NOT be able to tell the difference.
2. A handle **MUST NOT** outlive its client, and where the language can express that
   (Rust lifetimes, C++ references, a C handle that borrows), it MUST.
3. Handles **MUST NOT** be constructible independently of a client. There is no
   `new UsersApi(baseUrl)` — that would be a second client, with none of §3–§9's
   machinery attached to it.
4. The whole management surface **SHOULD** additionally be reachable behind one accessor
   (`client.management()`, `client.admin`) for SDKs whose client object is already large;
   where an SDK offers both, the two MUST return equivalent handles.

### §27.3 Per-language naming map

The namespace name is `snake_case` in the registry; each SDK casts it and the operation
name into its own §1 convention. Nothing here introduces a new convention — this is the
existing per-language casing applied to a derived vocabulary.

| Language | Accessor | Example |
|----------|----------|---------|
| Rust | method, `snake_case` | `client.service_accounts().rotate_secret(id)` |
| TypeScript | property, `camelCase` | `client.serviceAccounts.rotateSecret(id)` |
| Python | property, `snake_case` | `client.service_accounts.rotate_secret(id)` |
| Java | method, `camelCase` | `client.serviceAccounts().rotateSecret(id)` |
| C# | property, `PascalCase`, `Async` suffix | `client.ServiceAccounts.RotateSecretAsync(id)` |
| PHP | method, `camelCase` | `$client->serviceAccounts()->rotateSecret($id)` |
| Go | method, `PascalCase` | `client.ServiceAccounts().RotateSecret(ctx, id)` |
| Kotlin | property, `camelCase`, `suspend` | `client.serviceAccounts.rotateSecret(id)` |
| Swift | property, `camelCase`, `async` | `client.serviceAccounts.rotateSecret(id)` |
| C++ | method, `snake_case` | `client.service_accounts().rotate_secret(id)` |
| C | free function, `axiam_<ns>_<op>` | `axiam_service_accounts_rotate_secret(client, id, &out)` |

C has no handle to hang operations on, so it keeps §1's flat prefixed-function shape and
carries the namespace in the symbol. That is the same accommodation §1 already makes for
it, and it is why the registry's namespace names are chosen to read as identifier
fragments.

The §1.1 async-naming rule applies unchanged: a language whose §1 surface is
`suspend`/`async`/`*Async` keeps that discipline here, and an SDK that ships both
synchronous and asynchronous twins ships them for all 162 operations or for none.

### §27.4 Semantics (normative, identical in all SDKs)

1. **Authentication precondition.** Every operation but three — `platform.health`,
   `platform.ready` and `privacy.cancel_delete`, the registry's `authenticated: false` —
   requires a token. (Until contract 1.51 this read "the four in `platform`", but
   `mds_status` and `mds_refresh` have always required one.) Sixty-six of them also
   accept a service-account token as an alternative to a user's; see §27.13. Calling one with no token MUST
   raise the §2 `AuthError` **client-side, with zero wire calls** — the same rule §1.1
   rule 3 states for `get_user_info`. An SDK that lets the request go out trades a clear
   local error for a 401 that then enters the §9 refresh guard and fails there, which is
   two indirections away from the actual mistake.

2. **Identifiers are UUIDs.** Every `{…_id}` path parameter on this surface is a UUID.
   Slugs are **not** accepted — unlike `login`, which takes a tenant slug because it must
   work before the caller knows any UUID. An SDK MUST reject a non-UUID identifier
   client-side (§2 `NetworkError`, "SDK programming error"), with no wire call.

3. **Implicit path context.** `{org_id}` and `{tenant_id}` appear in 34 of the 162 routes,
   and in almost every call they are the client's own. An SDK MUST default them from the
   client's configured `org_id`/`tenant_id`, and MUST accept an explicit argument that
   overrides the default (a platform-admin token legitimately administers a tenant other
   than the one the client was constructed with).
   - A client constructed with `tenant_slug` but no `tenant_id`, calling a route that
     needs `{tenant_id}`, MUST fail **client-side** with a §2 `NetworkError` naming the
     missing configuration. It MUST NOT resolve the slug behind the caller's back — a
     silent extra round-trip on an admin path is exactly the behaviour §12.1 rule 2
     forbids for the same reason.
   - The `X-Tenant-ID` header of §5 rule 2 is still sent on every request regardless, and
     is **not** a substitute for the path parameter.

4. **Pagination.** Twenty-one operations take `offset`/`limit`/`search` and return the
   envelope `{ items, total, offset, limit }`. An SDK MUST:
   - return a typed `Page<T>` (or the language's equivalent) exposing all four fields —
     never a bare list, which throws away `total` and leaves the caller unable to tell a
     complete result from a truncated one;
   - offer an auto-paging form (`list_all`, an iterator, an async stream) that walks to
     exhaustion; and
   - **never silently truncate.** An SDK MUST NOT quietly apply a default `limit` and
     return the first page as though it were the whole set. Where a default is applied it
     is the server's, and `total` tells the caller the rest exists.
   Nineteen other reads return a **bare array** and are not paginated
   (`scopes.list`, `users.list_roles`, `roles.list_permissions`, …). An SDK MUST NOT
   invent pagination for them, and MUST NOT model them as `Page<T>` — the registry's
   `paginated` flag says which is which.

   **`search` (contract 1.31).** All twenty-one paginated operations additionally accept an
   optional free-text `search` term, matched case-insensitively by the server against the
   identifying fields of whatever is being listed — a name or username, plus the record
   id, so an operator holding a UUID from a log line can paste it into the same box.
   Which fields exactly is the server's business and is not part of this contract; the
   *shape* is, because twenty-one endpoints spelling it twenty-one ways is the divergence §27
   exists to prevent.

   - It belongs on the **same page-request type** as `offset`/`limit`, not as a separate
     positional argument on twenty-one generated methods. An SDK whose page request is a
     struct/record adds a third field; one whose `list` takes loose arguments adds a
     third optional argument in the same position everywhere.
   - **It is applied before `offset`/`limit`, and `total` counts matches, not rows.** An
     SDK MUST NOT filter client-side after fetching a page: that gives a pager whose page
     count belongs to a different result set than the page it is showing, and it re-reads
     `total` as something it is not.
   - **The auto-paging form MUST carry the same term on every request it issues.** A walk
     that sends `search` on the first page and drops it on the second silently returns the
     unfiltered tail, which looks like a server bug from the caller's side.
   - **Absent and blank are the same request.** An SDK MUST omit the parameter entirely
     when the term is unset, and MUST treat an empty or whitespace-only term as unset —
     a UI that sends `?search=` on every keystroke, including after the box is cleared,
     must not thereby ask a different question. The server normalises the same way
     (trim, then blank becomes absent) and caps the term's length; an SDK MUST NOT
     re-implement that cap, because a client-side truncation the server would not have
     made is a silently different query.
   - It is **additive**: an existing call that passes no term sends no `search` parameter
     and behaves exactly as it did before contract 1.31.

5. **Update has two shapes, and confusing them destroys data.** The registry's
   `update_style` distinguishes them:
   - **`sparse` (17 operations).** The body's fields are all optional; an absent field
     means *leave unchanged*. `users().update(id, { email })` changes the email and
     nothing else.
   - **`replace` (4 operations: `settings.set_org`, `email_config.set_org`,
     `webauthn_policy.set`, `ca_certificates.set_mtls_trust_anchor`).** The body's fields
     are required. This is a **replacement**: what is omitted is not preserved, it is
     gone. `SetOrgSettings` requires twenty fields, and a PUT carrying only the two
     somebody meant to change silently resets the other eighteen to whatever the request
     type's defaults are.

   An SDK MUST model the two differently — an all-optional patch type for `sparse`, an
   all-required value type for `replace` — so that the compiler, not a runbook, is what
   stops someone raising a lockout threshold and wiping the password policy on the way
   past. For every `replace` operation the SDK MUST document the read-modify-write pattern
   beside it, and SHOULD offer the composed form (`settings().update_org(|s| …)`) that
   performs the `get` first.

   **Null is not absent.** In a `sparse` body, omitting a field leaves it unchanged;
   sending it as `null` sets it to null where the field is nullable. A language whose
   serializer emits every field of a struct — including the ones the caller never set —
   turns every sparse update into a replacement. An SDK MUST ensure unset fields are
   omitted from the wire body, and MUST have a test that asserts on the **exact** key set
   of the serialized request, not on the presence of the field that was set.

6. **Deletes are not idempotent, and MUST NOT be made to look it.** A second `delete`
   returns 404. An SDK MUST surface that as `NotFoundError` (rule 7) and MUST NOT swallow
   it into a success — a caller retrying a failed delete needs to know whether it is
   finishing the job or looking at someone else's.

7. **Error mapping.** §2 governs, unchanged, with three sub-types this section adds. Each
   is a **language-idiomatic sub-type of an existing §2 type**, as §2's opening paragraph
   permits, so a caller catching the parent keeps working and this is additive:

   | Status | Type | Parent | Why that parent |
   |--------|------|--------|-----------------|
   | 404 | `NotFoundError` | `AuthzError` | §2 has no 404 row because nothing before this section could produce one. In a multi-tenant IAM "does not exist" and "is not yours" are **deliberately** indistinguishable: the server answers 404 for a resource in another tenant precisely so that a probing caller cannot enumerate one. Sorting it under `AuthzError` says what it means. |
   | 409 | `ConflictError` | `AuthzError` | §2 already maps 409 to `AuthzError`, described as "resource-level access denied". On this surface it is nearly always a uniqueness violation — a role by that name exists. The sub-type keeps §2's mapping while giving the caller something to act on. |
   | 400, 422 | `ValidationError` | `NetworkError` | §2 maps 400 to `NetworkError` as "SDK programming error". On this surface a 400 is usually a *user's* invalid input, not the SDK's. The parent is inherited from §2 rather than chosen here; the sub-type exists so an application can tell a rejected email address from a broken connection without matching on strings. |

   `ValidationError` SHOULD carry the server's field-level detail where the response body
   provides it. None of the three may be raised for a status the table does not name.

8. **Retry.** [§16](#§16-retry-policy-d5) governs and is not widened. Every `GET` on this
   surface is read-only and therefore retry-eligible under §16.2; every `POST`, `PUT` and
   `DELETE` is **not**, including the ones that look idempotent. `roles.assign_to_user`
   twice is harmless, but `certificates.generate` twice mints two certificates and
   `service_accounts.rotate_secret` twice invalidates the secret the first call returned
   and the caller has already stored. An SDK MUST NOT special-case any write here as
   retriable, and MUST NOT retry on a `ConflictError` — a 409 is the server telling the
   truth, not a transient fault.

9. **`Sensitive<T>`.** See [§27.5](#§275-sensitivet-applicability). §7 applies in full.

10. **No caching.** An SDK MUST NOT cache management reads. The §17 decision memo is
    scoped to authorization decisions and does not extend here; a stale role list is how
    an administrator concludes a permission change did not take.

11. **Telemetry.** Where the SDK ships [§19](#§19-telemetry-hooks-d5), management calls
    emit the same request/response events as any other REST call, with the namespace and
    operation as the operation label (`management.users.create`). Event payloads MUST NOT
    carry any field named in §27.5.

### §27.5 `Sensitive<T>` applicability

Nineteen operations carry secret material. The registry names them and the exact fields,
under `sensitive_request_fields` / `sensitive_response_fields`, so this is a generated
property of the surface rather than a list somebody remembers to update.

| Operation | Direction | Field | Note |
|-----------|-----------|-------|------|
| `users.create` | request | `password` | The initial password. Supplied by the caller, never returned. |
| `service_accounts.create` | response | `client_secret` | Returned **once**. Only its hash is kept server-side. |
| `service_accounts.rotate_secret` | response | `client_secret` | Returned **once**, and invalidates the previous secret. |
| `certificates.generate` | response | `private_key_pem` | The device/service private key. Returned once and never stored — §27.6's device flow is built around this. |
| `ca_certificates.generate` | response | `private_key_pem` | Absent under `vault_pki` custody, where the key was born inside Vault. Optional, and still `Sensitive` when present. |
| `ca_certificates.import_ca` | request | `private_key_pem` | The caller's own CA key, travelling to the server. |
| `ca_certificates.generate_signing_ca` | response | `private_key_pem` | The tenant signing CA's key, returned once. |
| `pgp_keys.generate` | response | `private_key_armored` | Present for `Export` keys only; `null` for `AuditSigning`, whose key stays server-side. |
| `webhooks.create` | request | `secret` | The HMAC signing secret the §13 verifier will need. |
| `webhooks.update` | request | `secret` | As above; rotating it re-keys every subsequent delivery. |
| `oauth2_clients.create` | response | `client_secret` | Returned **once**; the client cannot read it back. |
| `federation.create_config` | request | `client_secret` | The upstream IdP's client secret. |
| `federation.update_config` | request | `client_secret` | As above. |
| `scim_tokens.create` | response | `provisioning_token` | The plaintext provisioning handle. Shown once, never retrievable. |
| `oauth2_clients.create_registration_token` | response | `initial_access_token` | The RFC 7591 §1.2 initial access token a registering client presents as `Authorization: Bearer`. Shown once, never retrievable; `list_registration_tokens` returns metadata only. (contract 1.50) |
| `directory.set` | request | `bind_secret` | The credential of the customer's directory service account. Write-only: never returned, on no response. (contract 1.54, [§30.5](#§305-sensitivet-applicability)) |
| `directory.update` | request | `bind_secret` | As above; absent keeps the stored secret, and moving the connection without it is a `400` ([§30.3](#§303-server-rules-every-sdk-can-observe-normative) rule 2). (contract 1.54) |
| `ssf.create_stream` | request | `authorization_header` | The `Authorization` header AXIAM presents to an SSF receiver's push endpoint — a credential to a third party. Write-only: never returned, on no response. (contract 1.56, [§32.5](#§325-sensitivet-applicability)) |
| `ssf.update_stream` | request | `authorization_header` | As above; absent keeps the stored header, and moving the push endpoint to another origin without it is a `400` ([§32.3](#§323-server-rules-every-sdk-can-observe-normative) rule 5). (contract 1.56) |
| `scim_targets.create` | request | `credential` | The bearer token or OAuth2 client secret AXIAM presents to a downstream SCIM service provider — a credential to a third party. Write-only: never returned, on no response. (contract 1.57, [§31.5](#§315-sensitivet-applicability)) |
| `scim_targets.update` | request | `credential` | As above; absent keeps the stored credential, and moving it to another URL (`base_url` of a bearer target, `auth.token_url` or `base_url` of a client-credentials one) or switching `auth.type` without it is a `400` ([§31.3](#§313-server-rules-every-sdk-can-observe-normative) rule 2). (contract 1.57) |

**RFC 7592's `registration_access_token` (contract 1.53) is Sensitive too, and is not in
this table only because no §27 operation carries it**: it is returned by the protocol
endpoint `POST /oauth2/register` and presented to the three §28.12 operations, and
[§28.12.4](#§28124-sensitivet-applicability) states its rule. The registry generator
lists `RegistrationResponse.registration_access_token` among its sensitive fields all the
same, so the day a management operation returns that schema the token is wrapped from the
first build.

**The directory bind secret (contract 1.54) is Sensitive too**: `bind_secret` on the
`directory.set` and `directory.update` requests, the only two places it appears, from the first
version any SDK ships ([§30.5](#§305-sensitivet-applicability)). The table above carries the two
rows; the registry names the fields under `sensitive_request_fields`.

**CIBA (contract 1.58) adds no row here.** It is not a §27 namespace; its three `Sensitive<T>`
values — `auth_req_id`, `client_notification_token` and the signed request's key material — are
stated in [§33.5](#§335-sensitivet-applicability).

**The `saml` namespace (contract 1.55) adds no row.** It carries no secret: certificates,
fingerprints, URLs and entity ids are public, and the IdP's private key is on no request
and no response at all ([§29.5](#§295-sensitivet-applicability)).

**`certificates.sign_csr` (contract 1.45) is deliberately absent from this table.** Its
response is a plain `Certificate`, with no `private_key_pem` field and no other sensitive
field — the key stays with whoever generated the CSR, and AXIAM never sees it. An SDK MUST
NOT reuse the `GeneratedCertificate` model for it, and MUST NOT wrap anything on it in
`Sensitive<T>` on the theory that "certificates have keys, so this must too." A model with
a mandatory key field that is *always* absent is a type that lies about every value it
ever holds; the honest fix is a distinct response type that reflects what the operation
actually returns, not an optional field on the existing one that a caller has to learn is
never populated. This is the same discipline rule 2 states for the surface generally,
applied to a case where the omission is total rather than field-by-field.

**Rules.**

1. Every field above MUST be `Sensitive<T>` in the SDK's model type, in both directions.
   A request-side secret is wrapped for the same reason a response-side one is: the
   request object reaches a debug log just as easily as the response does, and
   `users().create(spec)` with a plaintext password in `spec` is the most-logged object on
   this surface.
2. **Nothing else on this surface is wrapped.** `SecuritySettings.password` is a
   `PasswordPolicy` object, not a password; `token_endpoint_auth_method` is an enum;
   `access_token_lifetime_secs` is an integer. A name-based rule wraps all three, and an
   SDK annoying enough to fight gets unwrapped everywhere, which is how the real secrets
   end up bare. This is why the registry curates `(schema, field)` pairs.
3. The **once** in the table is literal. `service_accounts.create`,
   `oauth2_clients.create`, `oauth2_clients.create_registration_token`,
   `scim_tokens.create`, `certificates.generate`,
   `ca_certificates.generate`, `ca_certificates.generate_signing_ca` and
   `pgp_keys.generate` return material that no subsequent `get` will ever return again.
   An SDK MUST document that at each call site — a caller who discards the result because
   they can "fetch it later" has destroyed the credential, and the corresponding `get`
   returns the non-secret projection with no indication that anything is missing.
4. §7 rule 1's redaction covers these fields in every stringification sink the language
   has, and §27.4 rule 11 keeps them out of telemetry payloads.
5. **A `service_accounts` section of a §27.6 manifest returns the secret exactly as
   `create` does** (contract 1.51). This is the one place the declarative layer touches a
   one-time secret, so the rule is stated here rather than left to eleven readings.

   - When `apply` performs a `Create` for a service account, that action's outcome carries
     the `ServiceAccountCreatedResponse` it received, `client_secret` included and
     `Sensitive<T>` as always. An SDK MUST NOT discard it, and MUST NOT summarise the
     outcome as a bare "created" that drops the body.
   - The outcome MUST be returned **even when a later action of the same `apply` fails**.
     §27.6 rule 7 already requires every attempted action's outcome. Here that rule is
     the only thing between the caller and a credential that was minted, is held nowhere
     else, and cannot be read back.
   - `Update` and `NoChange` return no secret, and `apply` **never** calls
     `rotate_secret` to reconcile anything. A re-run after a lost result is `NoChange`,
     and the only recovery is an explicit imperative `rotate_secret`, which the caller
     chooses to make.
   - The SDK documents rule 3's "once" at the manifest's `service_accounts` entry point,
     as rule 3 requires at every other call site.

   **Why this rule and not another.** It follows from the imperative contract. `POST
   /service-accounts` is the only moment the plaintext exists: the server keeps a hash,
   `get` and `list` return `ServiceAccountResponse` with no secret field, and
   `rotate_secret` invalidates the old secret rather than revealing it. So `apply` can
   only return the secret where `create` returns it, and it must. There are two ways to
   do otherwise, and both are worse. An `apply` that dropped the secret would create
   accounts nobody can authenticate as, which a second `apply` then reports as
   `NoChange`. An `apply` that rotated to "ensure" a secret would break every deployed
   holder of the previous one on every run. This is also why service accounts are in
   the manifest at all while `certificates` are not (§27.6, "What a manifest covers"). A
   service account has a stable identity apart from its secret, so the secret is minted
   once, at `Create`. A certificate *is* its key material, so "ensure it exists" has no
   answer that is not a re-mint.

### §27.6 Declarative management — the manifest

**Requirement level: SHOULD where the SDK ships §27.** The 162 imperative operations are
the floor, not the ceiling. Almost nobody actually wants to call them one at a time:
what an application does at start-up, in a migration, or in a test fixture is *assert a
shape* — this tenant has these resources, with these scopes, these permissions, these
roles, and these role bindings — and let the SDK work out which calls that takes.

Written imperatively, that assertion is forty calls wrapped in exists-checks, and it is
wrong the second time it runs. The declarative layer is one object and one call.

**The vocabulary.**

| Canonical | Semantics |
|-----------|-----------|
| `ManagementManifest` | The desired state. A value, inert, constructible without a client and comparable without one. |
| `plan(manifest)` | Reads current state, returns a `ManagementPlan` — the ordered list of actions that would reconcile it. **Performs no writes.** |
| `apply(manifest)` | `plan` followed by execution. Returns the plan that was executed, each action carrying its outcome. |

**Semantics (normative).**

1. **`plan` writes nothing.** Not "writes nothing important" — nothing. It issues `GET`s
   only. This is what makes the layer safe to point at production, and it is testable by
   asserting that a mock transport saw no non-`GET` method during a `plan`.

2. **Reconciliation is by natural key, not by UUID.** A manifest is written before the
   things in it exist, so it cannot name them by id. Each spec carries the natural key its
   namespace is unique on within a tenant (`users` → `username`, `roles` → `name`,
   `resources` → `name` within a parent, `scopes` → `name` within a resource, and so on).
   Cross-references between specs use a manifest-local `key`, resolved to UUIDs during
   `plan`. An SDK MUST reject a manifest containing a dangling `key` **before** issuing
   any request.

3. **Three actions, and only three.** Each spec resolves to `Create`, `Update` or
   `NoChange`. `Update` is emitted only when a field the manifest *states* differs from
   the server's value — a manifest that omits a field is silent about it, never an
   assertion that it should be cleared. This is what makes `apply` safe to run against a
   tenant that also has hand-made state in it.

4. **Deletion is opt-in, per namespace, and never a default.** An `apply` MUST NOT delete
   anything unless the caller explicitly enables pruning, and pruning MUST be selectable
   per namespace rather than globally. A manifest is usually a *subset* of a tenant's
   truth; a global prune turns "make sure these three roles exist" into "delete the other
   forty".

5. **Ordering is derived, and dependencies are real.** Actions are ordered
   resources → scopes → permissions → roles → role/permission grants → groups →
   group/role bindings → users → user/role bindings → service accounts →
   service-account/role bindings → webhooks (the service-account binding step named in
   contract 1.51, §27.6.1), and
   `resources` is additionally sorted topologically so a parent is created before its
   children. An SDK MUST detect a cycle in the resource parent graph and reject the
   manifest client-side.

6. **Idempotence is the acceptance test.** `apply(m)` followed by `plan(m)` MUST yield a
   plan whose actions are all `NoChange`. An SDK that cannot make that assertion pass has
   a drift-detection bug, and the test is worth more than any other in this section.

7. **There is no transaction, and the SDK MUST NOT pretend otherwise.** These are 162 independent HTTP endpoints; nothing spans them. If action 12 of 30 fails, actions 1–11
   have happened and will not be undone. `apply` MUST therefore return the outcome of
   *every* action attempted, MUST stop at the first failure rather than continuing
   blindly, and MUST document that re-running after fixing the cause is the recovery path
   — which rule 6 makes safe. An SDK MUST NOT offer a `rollback`; it could not honour one.

8. **`plan` is stable.** Two `plan` calls against unchanged state produce equal plans, in
   the same order. A plan that reorders between runs cannot be diffed, and diffing it is
   most of why it exists.

**What a manifest covers.** `resources`, `scopes`, `permissions`, `roles`, `groups`,
`users`, `service_accounts` and `webhooks` — the namespaces that describe a tenant's
*shape*. Deliberately **not** covered: `certificates`, `ca_certificates`, `pgp_keys` and
`scim_tokens`, because they mint one-time secrets (§27.5). A declarative layer that
"ensures a certificate exists" either re-mints one on every run or silently accepts drift,
and both are worse than an imperative call the caller makes once, on purpose, and stores
the result of.

`service_accounts` is covered despite minting a one-time secret, and §27.5 rule 5 says
why and what `apply` returns for it. `webhooks` stays named and **unspecified**. A
webhook's `secret` is caller-supplied, not minted, so nothing forbids it, but no
consumer has asked for it. An SDK that omits it says so in its README; nothing in
1.51 requires it.

#### §27.6.1 The manifest spec, where 1.51 makes it explicit

Before contract 1.51 this section named the namespaces a manifest covers and left their
specs to each SDK. Eleven SDKs read it eleven ways (§27.10), and three things a real
consumer needed were in none of them: resource metadata, a role binding scoped to a
resource, and service accounts. They are specified here. Everything else about a spec
stays as each SDK has it. The three additions are SHOULD-level, like the manifest itself,
and an SDK that has not implemented one says so in its README (§27.10 records it upstream).

**1. `resources[].metadata`** — an optional JSON object.

- It is sent on `Create` and, when stated, on `Update`.
- Omitted means silent (rule 3), as for any other field.
- The server stores `{}` when a resource is created without metadata, returns an object
  on every read, and replaces the whole object on an update that carries one. So drift
  is **JSON value equality of the whole object**, with a stated `{}` equal to what the
  server returns for none. It is never a key-by-key merge. A merge would make `apply`
  unable to remove a key, and rule 6 unable to hold.
- Equality is of JSON **values**: key order never counts, so comparing serialized strings
  does not conform. A stated `{}` is a statement (it clears the object) and so is distinct
  from an omitted field, which says nothing (contract 1.52, C-12).

**2. Role bindings have two shapes.** Every `roles[]` entry of a `groups`, `users` or
`service_accounts` spec is one of:

- a **role key** (a string) — the binding as every SDK has it today: no resource, and
  so no inheritance question; or
- an **object `{ role, resource, inherit? }`** — `role` is a role key, `resource` a
  resource key (both manifest-local, resolved per rule 2), and `inherit` a boolean
  defaulting to `true`. It is sent as `resource_id` and, only when `false`, as `inherit`
  on the `assign_to_*` call. This is server T22.11's non-inheritable assignment. An
  SDK MUST NOT send `inherit: true` explicitly, so that an inheritable binding's body stays
  byte-for-byte a pre-1.51 body.

Contract 1.52 (C-12) settles three points about stating these values:

- A manifest MAY **state** `inherit: true`. The SDK accepts it, plans it like an omitted
  one, and still never sends it.
- The object shape requires `resource`. An `inherit` with no resource is refused before
  any request, since a binding with no resource has nothing to stop inheriting at.
- Every key resolves against **its own kind** only. A role key that names a group is a
  dangling reference, refused before any request. It is never discovered mid-`apply`,
  after earlier writes have landed.

The rules that make the two shapes reconcilable:

- **A subject holds a role at most once.** The server keys assignments on
  `(subject, role)` with no resource component (`has_role` is `UNIQUE(in, out)`, and a
  repeat is `409`). A manifest that binds one role to one subject twice — at two
  resources, or once plain and once scoped — therefore describes a state the server
  cannot hold. An SDK MUST reject it before any request, naming the subject and the role.
  Whether the key should widen is a recorded maintainer decision (D-3 of the dogfooding
  plan), not something a manifest can work around.
- **A binding's natural key is `(subject, role)`, and its resource and `inherit` are
  fields.** The binding is `NoChange` when the server's assignment of that role names
  the same resource (none for the string shape) and the same `inherit`. It is `Update`
  when either differs, and `plan` reports that `Update`. An SDK that finds binding drift
  only inside `apply` has a `plan` that lies about it. There is no update endpoint, so `apply` performs an `Update` as
  **unassign, then assign**, and the subject holds no such role between the two calls.
  If the assign fails, the SDK MUST attempt to assign the previous binding again (same
  resource, same `inherit`) and report both outcomes. **As data** (contract 1.52): the
  report says, in a field and not only in a message, whether the restore succeeded, and
  when it did not, carries the restore's own error. The two outcomes leave two states: the
  subject holds the previous binding, or, when both calls failed, holds neither. This is how the admin console
  changes the flag (server T22.11b), and a manifest must not be less careful than a form.
- **`tenant_scope` is not part of a manifest binding in 1.51**, and a stated binding is
  silent about it (rule 3). An `Update`'s re-assignment MUST carry the server binding's
  existing `tenant_scope` across unchanged. Dropping it would silently widen an
  organization-level account's reach (§5.2.3).
- A global role (`is_global: true`) bound with `inherit: false` is refused by the server
  with `400`. When the manifest declares the role global, an SDK MUST refuse the binding
  client-side, before any request (contract 1.52; it was a MAY, and all eleven already
  did). A role the manifest does not declare global reaches the server, and its refusal
  is that action's failure.

**3. `service_accounts[]`** — `{ key, name, description?, roles[]? }`.

- **The natural key is `name`, and the server does not enforce it.** A service account's
  only unique index is its `client_id`, so a tenant can hold two accounts with one name.
  `plan` MUST fail with a client-side error, before `apply` writes anything, when more
  than one existing account matches a stated name. Picking one would reconcile an
  arbitrary account.
- `description` is the only field reconciled by `Update` (sparse, §27.4 rule 5).
  `status` is not a manifest field in 1.51.
- `roles[]` takes both binding shapes above, through `roles.assign_to_service_account`.
  Group membership of a service account is not a manifest field in 1.51.
- A `Create` returns the one-time `client_secret` on its outcome. §27.5 rule 5 governs.
- An `apply` whose manifest has a `service_accounts` or `users` section needs a caller
  that may manage them. A service-account caller may manage the first and not the
  second (§27.13, S-9), and meets `401` at the first `users` action.

### §27.7 Per-language declarative form

The manifest is a value type, so every language can build one from plain constructors —
and every SDK MUST support that, because it is what deserializing a manifest from
configuration produces. On top of it, each SDK SHOULD offer the declarative form its
users would expect:

| Language | Form |
|----------|------|
| Rust | `manifest!` macro (a `declare!`-style DSL), plus `#[derive(AxiamSpec)]` on a caller's own struct |
| TypeScript | `defineManifest({...})` with full type inference, plus `@AxiamRole()` / `@AxiamResource()` decorators |
| Python | dataclass specs plus `@axiam_role` / `@axiam_resource` decorators |
| Java | `@AxiamRole` / `@AxiamResource` / `@AxiamPermission` annotations, scanned into a manifest |
| Kotlin | type-safe builder DSL (`manifest { role("editor") { … } }`) |
| C# | `[AxiamRole]` / `[AxiamResource]` attributes, plus an object-initializer manifest |
| PHP | `#[AxiamRole]` / `#[AxiamResource]` attributes |
| Go | struct tags (`axiam:"role,name=editor"`) over a declared manifest struct |
| Swift | `@resultBuilder` DSL (`Manifest { Role("editor") { … } }`) |
| C++ | designated-initializer aggregate specs plus an `AXIAM_MANIFEST(...)` macro |
| C | static `axiam_manifest_spec_t` tables plus `AXIAM_MANIFEST_ROLE(...)` initializer macros |

Whatever the surface syntax, it MUST lower to the same `ManagementManifest` value and go
through the same `plan`/`apply`. A declarative form that talks to the network itself is a
second implementation of §27.6, and the two will disagree.

### §27.8 How an SDK builds this

**Generated core, hand-written facade.** The 162 operations and their model types are
**generated** from `management-registry.json`; the ergonomics are not.

Generated, and regenerated whenever the registry changes:
- the model types, including `Sensitive<T>` placement (§27.5) and the sparse/replace
  split (§27.4 rule 5);
- one raw call per operation — path interpolation, query assembly, body serialization,
  response deserialization, status→error mapping.

Hand-written, once, per SDK:
- the namespace handles and their §27.3 naming;
- `Page<T>` and the auto-paging form;
- the §27.6 manifest, `plan`/`apply`, and the §27.7 declarative form;
- the composed helpers, examples and prose docs.

**The generated layer MUST sit on the SDK's existing request path** — the same one §1 uses
— and MUST NOT open its own connection, build its own client, or re-implement any of §3
(CSRF), §4 (cookie jar), §5 (tenant/org headers), §6 (TLS), §9 (single-flight refresh),
§16 (retry) or §19 (telemetry). Everything in this section inherits all of it by
construction; an SDK whose management layer has its own HTTP client has 162 endpoints
outside its own refresh guard.

Generated files MUST be committed (not produced at build time), MUST carry a
"generated — do not edit" header naming the registry and generator, and MUST be verified
in the SDK's CI by regenerating and diffing.

### §27.9 Required tests

Every assertion below exists because the thing it checks is easy to get wrong and silent
when wrong. Coverage MUST NOT fall in the SDK's existing modules as a result of adding
this section.

**Surface and generation**
- The generated surface covers **all** of the registry's operations (162 at contract
  1.51) — assert the count against the registry's `operation_count` and the namespace
  set against `management-registry.json`, so a partial regeneration fails rather than
  quietly shipping fewer.
- Regenerating from the committed registry produces no diff (the CI gate of §27.8).
- A namespace handle performs **no I/O** when acquired — assert the mock transport saw
  zero requests.

**Context and identifiers**
- `{org_id}` / `{tenant_id}` default from the client's configuration, and an explicit
  argument overrides them — assert on the request **path**, not on the arguments.
- A slug-only client calling a `{tenant_id}` route fails client-side with **zero** wire
  calls.
- A non-UUID identifier fails client-side with zero wire calls.
- `X-Tenant-ID` is still present on management requests (§5 rule 2 does not lapse here).

**Pagination**
- A `Page<T>` exposes `total` as distinct from `len(items)` — assert against a mocked
  envelope where the two differ, because a `Page` that reports `total = items.len()` passes
  every test written against a single-page fixture.
- The auto-paging form walks to exhaustion and issues exactly the expected number of
  requests, with the expected `offset` on each.
- A bare-array operation (`scopes.list`) is **not** modelled as a page.
- A page request carrying a `search` term puts it on the **query string** — assert on the
  request URI, not on the arguments, because a term the SDK accepts and never sends is the
  failure mode this test exists for.
- A page request with **no** term sends **no** `search` key at all, and an empty or
  whitespace-only term is treated identically to none — assert on the exact query key set.
- The auto-paging form carries the term on **every** request of the walk, not only the
  first — assert the term on each recorded request, not just on the count of requests.

**Update shapes** — the two assertions this section most needs
- A sparse update carrying one field serializes a body with **exactly that one key**.
  Assert on the full key set; asserting the field is present passes even when every other
  field went along as `null`.
- A `replace` operation's type does not compile — or, in a dynamic language, does not
  serialize — with a field omitted.

**Secrets**
- Each of the fifteen §27.5 fields is `Sensitive<T>`, and its value does not appear in
  the object's debug/stringified rendering — scan the serialized output for the fixture
  value rather than asserting the type.
- A one-time-reveal response and the corresponding `get` differ: the `get` projection has
  no secret field at all.

**Errors**
- 404 → `NotFoundError`, and it is catchable as `AuthzError`.
- 409 → `ConflictError`, catchable as `AuthzError`, and **not** retried.
- 400 → `ValidationError`, catchable as `NetworkError`.
- An ordinary REST 403 still maps to plain `AuthzError` (§2's rewrite note).
- A second `delete` surfaces `NotFoundError` and is not swallowed into success.

**Retry and refresh**
- A `GET` retries per §16; a `POST`/`PUT`/`DELETE` on this surface issues **exactly one**
  request on a 5xx.
- A 401 on a management call enters the §9 single-flight refresh guard and the call is
  retried once after a successful refresh.
- Calling any authenticated operation with no token raises `AuthError` with zero wire calls.

**Manifest**
- `plan` issues **no** non-`GET` request.
- `apply(m)` then `plan(m)` yields an all-`NoChange` plan (§27.6 rule 6).
- A manifest with a dangling cross-reference `key` is rejected before any request.
- A cycle in the resource parent graph is rejected client-side.
- Ordering: a resource is created before its child, and a role before the binding that
  uses it.
- A failure at action *n* reports outcomes for `1..n` and does not attempt `n+1..`.
- Pruning is off by default: a manifest omitting an existing role produces no `Delete`.
- Two `plan` calls against unchanged state produce equal plans in the same order.

**Manifest additions (contract 1.51, §27.6.1)** — required of an SDK that implements the
addition, alongside rule 6's idempotence test, which covers all three:
- `metadata` round-trips: `apply` of a resource with metadata, then `plan`, is all
  `NoChange`; changing one key yields `Update` whose body carries the **whole** object.
- A resource-scoped binding with `inherit: false` sends `resource_id` and `inherit: false`.
  The same binding with `inherit` omitted sends **no** `inherit` key (assert the key set).
- Changing a binding's resource is an unassign followed by an assign, in that order. When
  the assign fails, the previous binding is assigned again and both outcomes are reported.
  A `tenant_scope` on the server binding survives the change.
- A manifest binding one role to one subject twice is rejected with zero wire calls.
- A service-account `Create` outcome carries `client_secret` as `Sensitive<T>`, and it is
  still returned when a later action of the same `apply` fails. A second `apply` is
  `NoChange` and issues no `rotate-secret` request.
- Two existing service accounts with a stated `name` make `plan` fail before any write.

### §27.10 Per-SDK posture

§27 is SHOULD-level and lands per repository, exactly as §12.7, §14, §15, §16 and §18 did.
An SDK states it only once the code is in that repository — the statement follows the
code, never the contract's expectation of it.

| SDK | §27 status |
|-----|-----------|
| Rust | reference implementation (contract 1.30) |
| TypeScript | reference implementation (contract 1.30) |
| Python, Go, Java, Kotlin, C#, PHP, Swift, C, C++ | implemented (contract 1.30) |

**All eleven now implement the imperative surface.** The manifest is another matter;
see "The manifest, per SDK" below. The two reference implementations existed to prove the
section was buildable as written before nine more repositories committed to it, and to
give the rest a generator and a test suite to port rather than a specification to
interpret. That is what happened: each of the nine carries its own generator over
`management-registry.json`, its own committed output, and a CI job that regenerates and
diffs (§27.8).

**C is the only SDK with flat symbols.** §27.3's table gives C
`axiam_service_accounts_rotate_secret(client, id, &out)` and every other language a
namespace handle — C++ included, whose row reads
`client.service_accounts().rotate_secret(id)`. The sentence that stood here previously
said "the C and C++ ports carry the §27.3 flat-symbol accommodation", which contradicted
the table two sections above it and the prose beneath that table granting the
accommodation to C alone, on the stated ground that "C has no handle to hang operations
on". C++ has one and uses it.

**Both accessor forms are present everywhere.** §27.2 rule 4 makes the single
`client.management()` accessor an *addition* to the per-namespace accessors §27.3's table
specifies, and requires the two to return equivalent handles where an SDK offers both.
Five SDKs first shipped the addition without the baseline — reading "additionally" as
"instead" — and now ship both, with the direct accessors delegating to `management()` so
the equivalence is structural rather than a promise two code paths have to keep.

**The manifest, per SDK (contract 1.51, refilled in 1.52).** "All eleven implement it" was
true of §27 and read as true of §27.6. It was not. This table was first read at the commit
that vendors contract 1.50. The C-12 review (§27.14) re-read it from each repository's
`main` after the eleven 1.51 ports merged:

| Kind | Rust, TypeScript, Python, Java, Kotlin, C#, Go | PHP | Swift, C, C++ |
|---|---|---|---|
| resources | yes, nested; `parent_id` sent | yes, nested; `parent_id` sent (fixed in C-6) | yes, nested; `parent_id` sent (fixed in C-9, C-10, C-11) |
| `resource_type` | stated | stated | stated, or refused before any request; never a silent `"folder"` (fixed) |
| scopes | yes | no | no |
| permissions | yes | yes | yes |
| roles | yes | yes | yes |
| role → permission grants | yes | yes, reconciled (fixed in C-6) | no; grants only order the apply |
| groups | yes | yes | yes |
| group → role bindings | yes, both shapes | yes, both shapes (C-6) | yes, both shapes (new in C-9, C-10, C-11) |
| users, user → role bindings | yes, both shapes | no | no |
| `resources[].metadata` (1.51) | yes | yes | yes |
| resource-scoped binding, `inherit` (1.51) | yes | yes | yes |
| `service_accounts`, with role bindings (1.51) | yes | yes | yes |
| `webhooks` | no | no | no |

**The three defects the 1.50 reading recorded are fixed** by the 1.51 ports.

- **PHP** reconciles role grants and group role bindings. Before, it stored them, dropped
  them from the drift check and never applied them.
- **PHP, Swift, C and C++** send a resource's parent.
- **Swift, C and C++** no longer invent a `resource_type`.

The **tier gap** is recorded as a fact rather than a defect. PHP, Swift, C and C++ have
no `users` and no `scopes`, and Swift, C and C++ reconcile no role → permission grants. The
dogfooding plan (§7.2) defers closing it until a consumer needs it. An SDK in that tier
states §27 with the README note the Conformance Statement requires ("which of the two it
has"), and that note MUST name the missing kinds rather than say "manifest supported".
This table is maintained upstream by the conformance review, as §28.10's is. A port
records its own posture in its README and `CHANGELOG.md`.

### §27.12 `tenants.delete` requires a fresh audit export (contract 1.33)

Deleting a tenant destroys its audit trail along with everything else in it. From server
1.0.0-beta03 the server refuses to do that unless the trail was exported first:

1. **`tenants.export_audit(org_id, tenant_id)`** streams the tenant's complete audit
   trail as `application/x-ndjson` — one audit entry per line, newest first — and, once
   the whole trail has been written, appends a receipt to that tenant's own audit log.
   The final line of the body is not an entry but a manifest:

   ```json
   {"axiam_export":"tenant_audit","tenant_id":"…","exported_by":"…",
    "exported_through":"2026-08-28T12:00:00Z","record_count":41,
    "digest":"sha256:…","receipt_id":"…","receipt_valid_for_hours":6}
   ```

   `digest` is a SHA-256 over the entry lines that precede the manifest, so an archived
   file can be re-hashed and matched to the receipt named in `receipt_id`.

2. **`tenants.delete(org_id, tenant_id)`** answers `409` (`ConflictError`, per §27.4
   rule 8 **not** retried) unless a successful receipt for *that* tenant exists and is
   less than **six hours** old. The window is fixed server-side and there is no
   force/override parameter.

**What an SDK MUST do:** nothing beyond generating the new operation from
`management-registry.json` — the surface is derived (§27.8) and this is one more row.
The two normative points are for the SDK's *documentation*, not its code:

- `export_audit` is `response.kind: "none"` in the registry, exactly like
  `privacy.download_export`, so the generated method performs the export and returns no
  body. An SDK whose users need the bytes **SHOULD** document its raw-request escape
  hatch on this operation; an SDK that can return the raw body from a generated
  no-content operation **MAY** do so.
- An SDK **MUST NOT** paper over the `409` by calling `export_audit` automatically inside
  `delete`. The point of the gate is that a human decided to keep the trail; a client
  that exports-and-discards on the caller's behalf reproduces the failure the gate
  exists to prevent.

**Callers that delete tenants need one new permission**, `tenants:export_audit`, in
addition to `tenants:delete`.

### §27.11 Model additions (contract 1.31)

Three of the management models grew a field, and one list projection grew one. All four
are **additive and optional**: a caller that ignores them compiles and behaves as before,
and an SDK reading a response from a server older than contract 1.31 finds them absent.
They are recorded here rather than left to `openapi.json` because every SDK hand-writes
these model types, and a field nobody notices is a field nobody exposes.

| Model | Field | Type | Absent means |
|---|---|---|---|
| `Tenant` | `kind` | `TenantKind` — `"standard"` \| `"organization"` | `"standard"` |
| `LoginUserInfo` | `organization_level` | `boolean` | `false` (see [§5.2](#§52-organization-level-principals-contract-131)) |
| `MtlsTrustAnchorResponse` | `trusted_anchors` | `integer \| null` | `null` |
| `Certificate`, **in the `certificates.list` projection only** | `bound_service_account_id` | `uuid \| null` | `null` |

Four rules, one per row, each stating the way the field is got wrong:

1. **`TenantKind` is an open enum to a client, and a defaulted one.** An SDK MUST decode
   an unrecognised value without failing the whole response — a closed enum turns the
   next kind the server adds into a parse error on `tenants.list`, which takes down
   reading tenants that have nothing to do with it. Where the language has no natural
   "unknown" carrier, keep the raw string. The field is `#[serde(default)]` server-side,
   so a tenant row written before organization scope existed decodes as `Standard`; an
   SDK MUST default the same way rather than making `kind` required.

2. **`kind` is read-only.** It is not on `CreateTenant` or `UpdateTenant`, and an SDK
   MUST NOT put it there. An organization's scope tenant is reserved at organization
   creation and enforced by a unique index; a client that could set the field would be
   able to ask for a second one, and the request would be refused at the database rather
   than at the type.

3. **`trusted_anchors` counts what the *live listener* now trusts, and only when it was
   reloaded.** `null` is not zero — it means nothing was reloaded (a plaintext
   deployment, or `client_auth` off), which is exactly the case `restart_required: true`
   already reports. An SDK MUST model it as nullable and MUST NOT coalesce it to `0`,
   because "the listener trusts no CAs" and "there was no listener to ask" are different
   operational states and only one of them is a problem.

4. **`bound_service_account_id` is a projection, not a property of the certificate.** It
   is resolved from a graph edge and returned by `certificates.list` alone. An SDK MAY
   model the list item as a distinct type or as the certificate type with an extra
   optional field; whichever it picks, the field MUST be `null` — never absent-as-zero,
   never an empty UUID — on `certificates.get`, and the SDK MUST NOT synthesise it there
   with a second request. A `get` that silently costs two round-trips is the same
   behaviour §27.4 rule 3 forbids for slug resolution, for the same reason.

   The registry says which operations project and what they add:
   `response.projected_fields`, present only where there is something to project. The
   server expresses a projection as an `allOf` of the named base and an anonymous
   object, and a generator that reads only for a `$ref` sees a response with **no
   element name at all** — which is what happened here between the field landing in
   `openapi.json` and this revision: `certificates.list` went untyped over one added
   property, and the field reached no SDK. A generator MUST resolve the base through the
   `allOf` rather than treating the composition as anonymous.

### §27.13 Model and status changes from the dogfooding remediation (contract 1.51)

The server's Phase 22 wave changed four things an SDK's §27 surface (or §6.1 device
login) sees. All of them are already in `openapi.json` and `management-registry.json`,
so an SDK's §27.8 regeneration picks up the *types*. They are recorded here for the same
reason §27.11's are: a field nobody notices is a field nobody exposes, and two of them
change what an existing client must tolerate.

**Every new request field is optional, so an existing SDK request type keeps working
unedited.** A body built before 1.51 is a valid body after it and means what it meant.
Two response-side changes are *not* free for an SDK: the `"Server"` value (S-7, rule 2)
and `inherit` on the listings (S-10, rule 1). Both are additive on the wire and can
still break a decoder that assumed the old set.

**S-4 (server T22.4) — status, device login only.** An unbound certificate on `POST
/auth/device` is `401`, no longer `403`. §6.1 rule 8 gives the mapping. No DTO changed.

**S-7 (server T22.14) — the `Server` certificate type and `subject_alt_names`.**

1. **Requests.** `CreateCertificateRequest` (`certificates.generate`) and
   `SignCertificateCsrRequest` (`certificates.sign_csr`) gain `subject_alt_names`,
   optional and nullable: an array of `SubjectAltName`, which is externally tagged,
   `{"dns": "api.example.internal"}` or `{"ip": "10.0.0.5"}`. It is accepted **only** with
   `cert_type: "Server"`, where at least one entry is required. On any other type a
   present, non-empty list is a `400`. An SDK SHOULD omit the key when it has no names
   rather than send `null` or `[]`. It MUST NOT judge the names client-side (suffix
   match, wildcard, IDNA, CIDR). The organization's allow-list decides, and it answers
   `400 validation_error` naming the entry. `Server` is refused entirely until an
   organization administrator lists names (`certificate.server_cert_allowed_names`,
   empty by default).

   **The shape of each entry is judged client-side (contract 1.52, C-12).** Rule 1 keeps
   the names themselves from being judged, but not the shape of an entry. Each entry is
   exactly one of the two branches. A language with a closed sum type gets this from the
   type. A language whose type can hold neither branch or both, such as a struct of two
   optional fields, MUST refuse such an entry before any request, with §27.4 rule 2's
   client-side error. It MUST NOT send `{}` or both keys. An entry the SDK cannot build
   is refused, never silently dropped from the array: a list one name shorter than the
   caller wrote is a certificate for different names.
2. **`CertificateType` gains `"Server"`, and it appears in responses.** A tenant that
   issues one returns it from `certificates.list` and `certificates.get`. An SDK that
   decodes `cert_type` as a closed enum fails the **whole** list on one server
   certificate. That is the failure §27.11 rule 1 describes for `TenantKind`, and it has
   the same fix: decode an unrecognised value without failing the response, keeping the
   raw string where the language has no natural "unknown" carrier. An SDK whose
   generated enum gains `Server` when it re-vendors from this commit still owes the
   open-decoding rule for the next value.
3. **Responses carry no SANs.** `Certificate` and `GeneratedCertificate` did not gain
   `subject_alt_names`. The names are in the returned PEM, and an SDK MUST NOT add a
   field the server does not send.
4. **Two refusals an SDK surfaces verbatim.** First, `sign_csr` of a `Server`
   certificate under a CA whose key is custodied in Vault (`vault_pki`) is a `400` whose
   message names the `generate` path as the one that works. It fires after the CA
   lookup, so an unknown CA is still a `404`. Second, `service_accounts.bind_certificate`
   of a `Server` certificate is a `400`: a server certificate authenticates no client,
   and §6.1's device login refuses it with `401` in any case.
5. **`settings.set_org` replaces the allow-list too.** `SetOrgSettings.server_cert_allowed_names`
   is optional in the schema and defaults to `[]`. A `set_org` that omits it therefore
   **empties the organization's baseline**, and every tenant's effective list narrows to
   nothing. That is §27.4 rule 5's replacement hazard. The admin console shipped this bug
   and fixed it (server T22.14b). An SDK's composed read-modify-write form (§27.4 rule 5)
   MUST carry the field through. Tenants narrow the list through `settings.set_effective`
   and `settings.set_tenant_override` and can never widen it: a widening is a `400`.

**S-9 (server T22.13) — which operations accept a service-account token.** Sixty-six of
the 162 operations accept a service-account token (`aud` = `axiam:m2m`,
`sub_kind` = `service_account`) as an alternative to a user's. The rule is by the
**permission** a route requires, not by the registry namespace it sits in. The eight
admitted families are `resources`, `scopes`, `permissions`, `roles`, `groups`,
`service_accounts`, `certificates` and `webhooks`. That is why `users.list_roles`, which
requires `roles:get`, is admitted while the rest of `users` is not. The authoritative
per-operation answer is the operation's `security` in `openapi.json`: `service_account`
listed beside `bearer`. The registry does not carry it. §1's `check_access` and
`batch_check` accept both kinds as before.

1. **An SDK MUST NOT gate a management call client-side on the kind of token it holds.**
   The server decides, and it answers unambiguously in each case:
   - a service account on a route outside the set gets `401 authentication_failed`, for
     an audience mismatch;
   - a service account with no role on a route inside the set gets `403
     authorization_denied`, naming the permission in `action`;
   - a machine-audience token whose `sub_kind` is not `service_account` (an RFC 8693
     exchanged user token, for instance) gets `401`.
   An SDK MUST NOT treat the audience-mismatch `401` as an expired token: refreshing
   never changes a token's audience, so a refresh-and-retry only repeats the refusal.
2. **`X-Axiam-Tenant` works for an organization-level service account** on the same
   terms as for a user (§5.2 rule 1). The exception is certificate issuance: a service
   account never issues under the organization CA, only under the signing CA of the
   tenant it acts on.
3. **A certificate-bound service-account token** (§6.1 rule 9) is refused on every one of
   these routes unless the same certificate is presented.

**S-10 (server T22.11) — `inherit` on role assignments.**

1. **Requests.** `AssignRoleToUserRequest`, `AssignRoleToGroupRequest` and
   `AssignRoleToServiceAccountRequest` (`roles.assign_to_user` / `_group` /
   `_service_account`) gain `inherit`, an optional, nullable boolean. Absent means `true`,
   and `true` means what every assignment has always meant: the assignment reaches the
   resource's descendants. `false` stops it at the resource itself. An SDK SHOULD send the
   key only when it is `false`, so an inheritable assignment's body stays byte-for-byte
   a pre-1.51 body.
2. **Two `400`s**, both `validation_error`, both surfaced verbatim: `inherit: false`
   without a `resource_id` (there is no resource to stop at), and `inherit: false` on a
   global role (a global role ignores resource scope). Neither is to be pre-empted
   client-side on a guess. An SDK MAY check the first locally, since it needs no server
   state.
3. **Responses.** The three role-side listings (`roles.list_users`, `roles.list_groups`,
   `roles.list_service_accounts`) carry `inherit` as a **required** boolean. The
   subject-side listings (`users.list_roles`, `groups.list_roles`,
   `service_accounts.list_roles`) return `RoleAssignment`, where it is optional. An SDK
   MUST read absent as `true` there, which is also what a server that predates the field
   means by omitting it. An SDK MUST NOT read absent as `false`: that turns every
   pre-existing assignment into a non-inheritable one on the client's side of the wire.
4. **There is no update.** To change the flag, unassign and assign again. A second
   assign of the same role to the same subject is a `409`, whatever the flag (§27.6.1
   states the manifest's form of this).

### §27.14 Cross-SDK conformance review (contract 1.52)

C-12 re-read the eleven contract 1.51 ports from each repository's merged `main`, in the
format [§28.11](#§2811-cross-sdk-conformance-review-contract-149) carries forward. It asked
the seven questions the 1.51 ports left open and read every README claim against the code.
It also ran a wire probe per SDK. The full evidence is
[`claude_dev/sdk-dogfooding-conformance-review.md`](../claude_dev/sdk-dogfooding-conformance-review.md):
the per-question matrix, the file and line behind every cell, and the red test each fix
turned green. This table is the record, and it may have no open row.

**One row per divergence, not per SDK.** The dispositions are §28.11's four:

- **contract fixed:** the text was wrong or silent, and 1.52 changes it;
- **SDK fixed:** the code or its README was wrong, and a PR corrects it;
- **forced by the language, recorded:** neither is wrong, and the divergence is permanent;
- **open:** this table may not carry one.

Many rows are both: 1.52 writes the rule, and the SDKs that broke it are fixed. The
eleven C-12 fix PRs are:

- [`axiam-rust-sdk#116`](https://github.com/ilpanich/axiam-rust-sdk/pull/116)
- [`axiam-typescript-sdk#119`](https://github.com/ilpanich/axiam-typescript-sdk/pull/119)
- [`axiam-python-sdk#90`](https://github.com/ilpanich/axiam-python-sdk/pull/90)
- [`axiam-java-sdk#103`](https://github.com/ilpanich/axiam-java-sdk/pull/103)
- [`axiam-kotlin-sdk#69`](https://github.com/ilpanich/axiam-kotlin-sdk/pull/69)
- [`axiam-csharp-sdk#97`](https://github.com/ilpanich/axiam-csharp-sdk/pull/97)
- [`axiam-php-sdk#75`](https://github.com/ilpanich/axiam-php-sdk/pull/75)
- [`axiam-go-sdk#88`](https://github.com/ilpanich/axiam-go-sdk/pull/88)
- [`axiam-swift-sdk#67`](https://github.com/ilpanich/axiam-swift-sdk/pull/67)
- [`axiam-c-sdk#66`](https://github.com/ilpanich/axiam-c-sdk/pull/66)
- [`axiam-cplusplus-sdk#68`](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/68)

The table names them by language alone. They are merged as they pass review. Each SDK
then re-vendors this revision of `CONTRACT.md`, and states conformance at 1.52, in one
follow-up PR. Six defects the review found first, before
the rules were written, were fixed earlier, in five PRs:

- [`axiam-typescript-sdk#118`](https://github.com/ilpanich/axiam-typescript-sdk/pull/118)
- [`axiam-python-sdk#89`](https://github.com/ilpanich/axiam-python-sdk/pull/89)
- [`axiam-csharp-sdk#96`](https://github.com/ilpanich/axiam-csharp-sdk/pull/96)
- [`axiam-php-sdk#74`](https://github.com/ilpanich/axiam-php-sdk/pull/74)
- [`axiam-cplusplus-sdk#67`](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/67)

Two SSO resets were fixed before the 1.51 ports merged:

- [`axiam-typescript-sdk#117`](https://github.com/ilpanich/axiam-typescript-sdk/pull/117)
- [`axiam-go-sdk#87`](https://github.com/ilpanich/axiam-go-sdk/pull/87)

| # | Divergence | SDKs | Clause | Disposition | Where the fix landed |
|---|---|---|---|---|---|
| R-1 | A public verification entry point that accepts a `cnf`-bound token with no evidence. `Verifier.verifyAccessToken` never read `cnf`, while its own doc named it the guard entry | TypeScript | §10.1 rule 9 | **contract fixed** and **SDK fixed** | §10.1's "every entry point is a guard" (N1) · TypeScript #118 |
| R-2 | A guard that cannot obtain transport evidence from its framework refuses every bound token, and its README did not say so | Python (Django, FastAPI), Kotlin (Ktor), PHP (Laravel, Symfony), Swift, C, C++ | §10.1 rule 9 | **contract fixed** and **SDK fixed** | N1's README MUST · a README line in each |
| R-3 | A signature-only primitive whose documentation called it a rule 9 guard. `jwks.h` said `axiam_jwt_verify_ex` refuses `cnf` unconditionally, and `AXIAM_JWT_VERIFY_SIGNATURE_ONLY` skips the check | C | §10.1 rule 9 | **contract fixed** and **SDK fixed** | N1's exemption, which only a documented signature-only primitive gets · C #66 corrects the header |
| R-4 | gRPC `validate_token` / `introspect_token` report a bound token as valid | all seven gRPC SDKs | §1.1.1, §10.3 | **contract fixed** | N1: they return the server's verdict with its `cnf` and are not identity entry points. Every SDK already did this |
| R-5 | The §17 memo key had four components, while every SDK keyed on the acting tenant as a fifth. Two acting tenants must never share a cached decision | all eleven | §17.1 rule 3 | **contract fixed** | §17.1 rule 3 (N2) and §17.3's acting-tenant test. No SDK changed |
| R-6 | `SubjectAltName` built as a struct of two optional fields, which can send `{}` or both keys. C also dropped an element it could not build, and turned an out-of-range kind into `"dns"`. C++ sent `"subject_alt_names": []` | Go, C++, C, TypeScript (a union that admits both keys) | §27.13 S-7 rule 1 | **contract fixed** and **SDK fixed** | §27.13's "the shape of each entry is judged client-side" (N3) · Go #88, C++ #68, C #66 (in each generator, so the drift check stays green), TypeScript #119 |
| R-7 | An absent role-side `inherit` failed the whole listing | C++ | §27.13 S-10 rule 3 | **SDK fixed** | C++ #67 |
| R-8 | `authenticate_device()` sent the body `{}` | C++ | §6.1 rule 6 | **SDK fixed** | C++ #67 |
| R-9 | The device POST carried the prior session: its cookies (Python, C#), a bearer read from the jar (C#, Java), a bearer or CSRF token (PHP), or a proactive refresh first (Java) | Python, C#, PHP, Java | §6.1 rule 11.1 | **contract fixed** and **SDK fixed** | §6.1 rule 11 (N4.1) · Python #89, C# #96, PHP #74, Java #103 |
| R-10 | A refused or malformed device login changed client state. PHP cleared the jar before the POST, so a refused device login ended the session. TypeScript and Java dropped the previous device token before the POST, and Java also reset the gate. C++ and C# adopted a `200` with no token as an empty credential | PHP, Java, TypeScript, C++, C# | §6.1 rule 11.2 | **contract fixed** and **SDK fixed** | N4.2 · PHP #74, Java #103, TypeScript #119, C++ #68, C# #97 |
| R-11 | After a device login, some requests did not present the device credential. In Rust, self-service, WebAuthn and logout sent no bearer, and the old cookie rode. In TypeScript and Java, gRPC sent the previous session's token | Rust, TypeScript, Java | §6.1 rule 11.3 | **contract fixed** and **SDK fixed** | N4.3 · Rust #116, TypeScript #119, Java #103 |
| R-12 | The device credential was never released. A later `login` was shadowed by it, and in Go, C++ and PHP `logout` did not clear it either | Python, Kotlin, Go, Swift, C++, PHP, TypeScript, C#, Java | §6.1 rule 11.4 | **contract fixed** and **SDK fixed** | N4.4 · Python #90, Kotlin #69, Go #88, Swift #67, C++ #68, PHP #75, TypeScript #119, C# #97, Java #103 (its `refresh` dropped the token). Rust already released it on a later login |
| R-13 | A `401` on the device credential reached a refresh. PHP did this on REST and gRPC. TypeScript did it on re-authentication (the device path was missing from `SKIP_REFRESH`) and on gRPC. Java, Rust and C# did it on gRPC, and Python on REST | PHP, TypeScript, Java, Python, Rust, C# | §6.1 rule 11.5 | **contract fixed** and **SDK fixed** | N4.5 · PHP #75, TypeScript #119, Java #103, Python #90, Rust #116, C# #97 |
| R-14 | The device credential in a new handle, not the same client. The handle dropped the creating handle's acting tenant | C# | §6.1 rule 11.6 | **contract fixed** and **SDK fixed** | N4.6: the form conforms, and the tenant is carried · C# #97 |
| R-15 | Every management call was refused client-side after a device login, because the session check read only the cookie | Python, C++ | §27.4 rule 1 | **contract fixed** and **SDK fixed** | N4.7 · Python #90, C++ #68 |
| R-16 | A stale `X-CSRF-Token`, and an empty `Cookie` header set against no header at all, beside the device credential | stale CSRF sent: Rust, TypeScript, Python, Java, PHP, Go, C, C++ · `Cookie: ""`: Rust, TypeScript, Python, Swift, C · no `Cookie`: the other six | §6.1 rule 11.3 | **contract fixed** | N4.3: both forms conform, and a stale CSRF token is harmless because the server checks it only against a cookie session |
| R-17 | Where `X-Axiam-Tenant` goes: every `/api/v1` request, every POST, or authenticated routes only. The server reads it only in the auth extractor | all eleven | §5.2 rule 1 | **contract fixed** | §5.2 rule 1 (N5.1): the header is required on authenticated routes and optional elsewhere. READMEs and CHANGELOGs that stated a narrower or wider rule were corrected |
| R-18 | The header, `X-Tenant-ID` or a credential sent to an off-origin host, such as a discovered `/oauth2` endpoint | Python, C# | §5.2 rule 1 | **SDK fixed** | N5.1 · Python #90, C# #97 |
| R-19 | `X-Tenant-ID` missing on login, `verify_mfa`, the OPAQUE start, finish and registration calls, MFA-setup enrolment, the password-reset context, the WebAuthn authentication start and the WebAuthn setup pair | Rust | §5 rule 2 | **SDK fixed** | Rust #116 |
| R-20 | The acting-tenant helper as a new handle or in place | new handle: Rust, TypeScript, Python, Java, Kotlin, C#, Go · in place: PHP, Swift, C, C++ | §5.2 rule 1 | **forced by the language, recorded** | N5.2: both conform, and the README says which. `logout` MAY clear the acting tenant, as C's does |
| R-21 | A gate per handle, so a login on one handle left the other handle gating on the old principal | Python | §5.2 rule 1 | **SDK fixed** | N5.3 · Python #90 |
| R-22 | The gate refusal was `AuthError` (Swift) or `AXIAM_ERR_NETWORK` (C) | Swift, C | §5.2 rule 1 | **contract fixed** and **SDK fixed** | N5.4: it is §2's `AuthzError` · Swift #67, C #66 |
| R-23 | Which responses record the gate. Rust reset it on OPAQUE finish, MFA setup confirm and WebAuthn setup finish, whose `200` carries the user object | Rust | §5.2 rule 1 | **contract fixed** and **SDK fixed** | N5.5 names the record and reset sets · Rust #116 |
| R-24 | Client-credentials adoption, and device-grant adoption, did not reset the gate | Go, TypeScript | §5.2 rule 1 | **SDK fixed** | N5.5 · Go #88, TypeScript #119 |
| R-25 | A `200` with no user object handled four ways: recorded `false` (Python, Java, Kotlin, Go), unknown (C#, C, C++), a failed decode (Rust, Swift), or a throw (TypeScript, PHP) | all eleven | §5.2 rule 1 | **contract fixed** | N5.5: raise, unknown, or `false` all conform, and none may record `true`. No SDK changed |
| R-26 | `refresh` reset the gate, and C# did so before the request | Java, C# | §5.2 rule 1 | **contract fixed** | N5.5: `refresh` SHOULD keep the gate, and resetting it conforms. Both keep their reset, stated in the code. Java #103 stops `refresh` from dropping the device credential (R-12) |
| R-27 | Reach decided by comparing tenant ids as strings, so a server's lower-case id and an upper-case caller's id disagreed. The fixtures used all-digit UUIDs, where case cannot differ | Swift, PHP, TypeScript, Python, C, C++ | §5.2 rule 1 | **contract fixed** and **SDK fixed** | N5.6 · Swift #67, PHP #75, TypeScript #119, Python #90, C #66, C++ #68. The other five, Rust, Java, Kotlin, C# and Go, compare typed UUIDs, and C# now pins it with a hex-letter test |
| R-28 | A global role bound with `inherit: false` was refused client-side, and only a MAY required it. Go and Swift checked it only when a resource was given | all eleven | §27.6.1 | **contract fixed** | N6.1 makes it a MUST. All eleven already refuse a role the manifest declares global |
| R-29 | A stated `inherit: true` was refused (Java). `inherit: false` without a resource was sent (C++, TypeScript, C#) | Java, C++, TypeScript, C# | §27.6.1 | **contract fixed** and **SDK fixed** | N6.2 · Java #103, C++ #68, TypeScript #119, C# #97 |
| R-30 | The outcome of a failed rebind's restore was only in a message (Python), or was swallowed (C++). C# reported whether the restore succeeded but kept the restore's own error only in the message | Python, C++, C# | §27.6.1 | **contract fixed** and **SDK fixed** | N6.3, "as data" · Python #89, C++ #67, C# #97 |
| R-31 | `plan` did not report a binding Update, so it appeared only in `apply` | PHP | §27.6.1 | **contract fixed** and **SDK fixed** | N6.4 · PHP #75 |
| R-32 | Metadata drift compared serialized strings, which depend on key order. A stated `{}` could not be expressed (PHP) | TypeScript, PHP | §27.6.1 | **contract fixed** and **SDK fixed** | N6.5 · TypeScript #119, PHP #75 |
| R-33 | A reference resolved without its kind, so a role key colliding with a group key passed validation and failed mid-apply | PHP | §27.6.1 | **contract fixed** and **SDK fixed** | N6.6 · PHP #75 |
| R-34 | §6.1 rule 7's compile-time form. All eleven refuse at run time | all eleven | §6.1 rule 7 | **forced by the language, recorded** | The run-time refusal is what every SDK ships, and each README now states the compile-time form as a decline, with its reason |
| R-35 | A README or CHANGELOG sentence that the code contradicts, for example: <ul><li>a guard named by the wrong entry point (Java, C#);</li><li>a rule number off by one (Swift);</li><li>a conformance line omitting a section it ships or naming a stale contract (Java, C#, PHP, Kotlin, C);</li><li>a manifest example `plan()` rejects (Python);</li><li>"nothing is ever deleted" beside a binding Update that unassigns (Rust).</li></ul> | all eleven | Closing Notes, "the statement follows the code" | **SDK fixed** | Every fix PR |
| R-36 | Public signature-only **ID-token** helpers whose names do not say "unchecked": Java `verifyForOidc`, Kotlin `verifyForIdToken`, Go `VerifyPayload`, PHP `verifyIdTokenSignature`, C++ `verify_with_reason` | Java, Kotlin, Go, PHP, C++ | §10.1 rule 9, §12 | **contract fixed** | N1 governs functions that turn an **access** token into an identity. These verify §12's ID token, which rule 9 does not govern, so they need neither an "unchecked" name nor a `cnf` check |
| R-37 | §27.10's manifest table described the commit that vendors 1.50, not the merged 1.51 ports | — | §27.10 | **contract fixed** | §27.10 above, refilled from each `main` |

**No follow-ups.** Every row is closed in this revision or in one of the PRs above. Once this
revision merges, each SDK re-vendors this `CONTRACT.md` in one follow-up PR, and
`scripts/check-sdk-artifact-drift.py` must then report no drift.

### §27.15 Model and behaviour notes (contract 1.60)

One additive member and three notes about what the server does. None changes a route, a status
code or a registry operation; the §27.8 regeneration carries the schemas.

1. **`notification_rules` gain `window_minutes` (additive, #551).** `CreateNotificationRuleRequest`
   and `UpdateNotificationRuleRequest` gain an optional integer `window_minutes` (1 to 1440;
   omitted on create, the server stores 15), and `NotificationRuleResponse` always carries it: of
   the events of one type that match one rule, the first in each window is mailed to the rule's
   recipients and the rest are counted, the next mail reporting how many were not sent. A value
   outside 1 to 1440 is answered `400` (`validation_error`). An SDK **passes the field through
   and does not clamp it** (a client-side clamp is a silently different request, the reason
   §27.4 rule 4 gives for the `search` cap), omits it from a body whose caller did not set it,
   and on `update` treats an absent member as the operation's `update_style` says (§27.4 rule 5).
   Required test, one per SDK: `create` with `window_minutes` sends it as given, `create` without
   it sends no such key, and a response carrying it decodes it. Rules that existed before 1.60
   take the 15-minute window.
2. **Removing an OAuth2 client revokes (informative, #517).** `oauth2_clients.delete`
   (`DELETE /api/v1/oauth2-clients/{id}`), RFC 7592's `DELETE /oauth2/register/{client_id}`
   ([§28.12](#§2812-rfc-7592-client-configuration-operations-contract-153)) and the server's
   unused-client sweep revoke every refresh token issued to the client and void its outstanding
   authorization codes and pushed authorization requests; a code voided this way is answered
   `invalid_grant` like an unknown code. Access tokens already issued are not revoked and run
   out within the access-token lifetime. An SDK needs no change.
3. **Deleting a tenant removes it from every read at once (informative, #523).**
   `tenants.delete` — still `204`, still refused `409` without a fresh audit export (§27.12) —
   revokes the tenant's sessions and refresh tokens: from the response on, its users cannot sign
   in or refresh, its access tokens are refused wherever AXIAM checks the session, and the tenant
   answers `404`. The server purges its data afterwards, within one cleanup interval; until then
   its slug stays taken and creating a tenant with it answers `409`. An SDK needs no change: it
   surfaces the `204` and the `409` as it does today.
4. **`email_config` and the outbound address policy (informative, #529).**
   `email_config.set_org` and `email_config.set_tenant` answer `400` (`validation_error`) when
   the deployment's outbound address policy refuses the provider the request carries: an SMTP
   host that resolves to a loopback, link-local (the cloud metadata service), unspecified,
   multicast or reserved address, AXIAM's own listener, or a private network the operator has not
   listed in `AXIAM__EMAIL__ALLOWED_PRIVATE_NETWORKS`; an `api_url` that is not `https` or does
   not resolve to a globally routable address. For a host name the message is one fixed
   sentence whatever the name resolved to, and a configuration saved with `enabled: false` is not
   checked. `email_config.test_org` and `email_config.test_tenant` apply the same policy at the
   send and answer `400` (`email_config_error`) for its refusal, `500` when the provider could not
   be reached or did not accept the message, and `429` past a rate-limit bucket of their own
   (`AXIAM__RATE_LIMIT__EMAIL_TEST_PER_MIN`, per route). An SDK needs no change: it surfaces each
   as it does any other error of that status.

---

## §28 MCP Resource-Server Helpers (RFC 9728)

**Requirement level: SHOULD (v1.0). Every part of it is opt-in and off by default.**
This section is the *resource-server* half of the Model Context Protocol
authorization handshake: publishing the RFC 9728 protected-resource metadata
document that tells a client which authorization server guards this resource,
and emitting the `WWW-Authenticate` challenge that starts the client's
discovery. It is additive to [§10](#§10-middleware--route-guard-interface) and
consumes [§11](#§11-declarative-authorization-helpers); it changes neither.

**One subsection is the exception, and says so.** [§28.12](#§2812-rfc-7592-client-configuration-operations-contract-153)
(contract 1.53) adds three operations a *registered* MCP client — or the tool
that registered it — uses to read, replace and delete its own RFC 7591
registration at AXIAM, per RFC 7592. They talk to AXIAM, perform network I/O and
carry a bearer credential, so everything §28.0 says about the other operations
being local computation is stated for §28.1–§28.11 and does **not** describe
§28.12, which states its own rules.

Server documentation: [`docs/api/resource-indicators.md`](../docs/api/resource-indicators.md)
for the `aud` this section's guard checks, and `docs/api/mcp.md`, the
deployment picture, which lands with the runnable example. Wire references:
RFC 9728 §2 (the document), §3 (where it is served), §5.1 (the challenge
parameter); RFC 6750 §3 (the challenge's syntax and its three error codes).

**The one rule an SDK must not paper over: nothing in this section is a source
of truth about a token.** The document is a *claim* a resource server publishes
about itself and the challenge is a *hint* it gives a client that failed. Neither
is consulted when deciding whether a request is authorized — that decision is
§10.1's and §11's, unchanged and unreachable from here. An implementation that
lets the document or the challenge influence an accept/reject has inverted the
section.

### §28.0 The division of labour

Three parties, and confusing any two of them is how this gets built wrong:

| Party | Is | Owns |
|---|---|---|
| AXIAM | the authorization server | issuing the token, and minting its `aud` from the RFC 8707 `resource` parameter the client sent |
| The MCP server | the **resource server** | publishing the RFC 9728 document, checking `aud`, emitting the challenge — all of §28 |
| The MCP client | the client | reading the challenge, fetching the document, discovering the authorization server, running the code flow |

**An SDK implements the middle row and nothing else** — in §28.1–§28.11.
Those subsections add no operation that talks to AXIAM, and no operation in them
performs network I/O of any kind —
like `oidc_begin` (§12.1) and `uma_parse_challenge` (§20.5), all three
operations are pure local computation. Three consequences, all normative:

1. **[§16](#§16-retry-policy-d5) does not apply** — there is no request to
   retry. An SDK MUST NOT route any §28 operation through its retry machinery.
2. **[§9](#§9-single-flight-refresh-guard) does not apply** — there is no
   credential to refresh, and a §28 helper MUST NOT touch the SDK client's own
   session.
3. **C# takes no `Async` suffix on any of the three**, for the same reason
   `OidcBegin` and `UmaParseChallenge` do not (§1 "Async method naming").

The *client* half — parsing a challenge, fetching a document, choosing whether
to trust the authorization server it names — is **not in this contract version**
and an SDK MUST NOT ship it under a §28 name. §28.12 is not that half: it
starts from a registration that already exists, at an AXIAM the SDK client is
already configured for, and §28.12.2 rule 1 forbids it to follow a URI anywhere
else. §20.3's rule is the precedent and
the reason: a helper that read a 401 and acted on it would send a credential to
whatever host the 401 asked it to.

### §28.1 Canonical operation set

Three operations. They are part of the same locked vocabulary as §1 and §12 and
are subject to the same "no diverging names" rule.

| Canonical operation | Network I/O | Returns |
|---|---|---|
| `protected_resource_metadata` | **none** | a validated `ProtectedResourceMetadata` value |
| `serve_protected_resource_metadata` | **none** (registers a route) | the metadata URL it registered |
| `bearer_challenge` | **none** | the `WWW-Authenticate` **value**, as a string |

Signatures (canonical order; each language's §1 casing applies):

```
protected_resource_metadata(resource,
                            authorization_servers,
                            scopes_supported,
                            bearer_methods_supported = ["header"],
                            resource_documentation = None)

serve_protected_resource_metadata(app, metadata)   # `app` is the framework's
                                                   # application/router object

bearer_challenge(resource_metadata_url,
                 error = None,
                 error_description = None,
                 scope = None)
```

`protected_resource_metadata` returns a value carrying three things, all
readable:

| Member | Is |
|---|---|
| the document | the RFC 9728 §2 members, serializable to the exact JSON of §28.2 |
| `metadata_path` | the absolute path the document is served at, derived per §28.3 |
| `metadata_url` | `metadata_path` resolved against the resource's scheme and authority |

`metadata_url` exists so that an integrator feeds the guard's
`resource_metadata_url` option (§28.5) from the helper that derived it rather
than by retyping the string. `serve_protected_resource_metadata` returns the
same value for the same reason. An SDK MUST expose both; a surface that makes
the integrator write the URL twice is the surface on which the two disagree.

**The fourth piece of the set is a middleware option, not an operation**:
`resource_metadata_url` (§28.5). It is spelled in the host language's own
configuration idiom — a builder method, a constructor argument, a named
option — and it is the only thing in §28 that changes what an existing guard
does.

### §28.2 The document and its validation (normative)

The document carries **at most** the members below, in this order, and no
others — two of them are omitted when empty, and the rules say which. RFC 9728
§2 defines further members; an SDK MUST NOT emit them in this contract version,
because a member one port emits and ten do not is the divergence the cross-SDK
review would then have to reconcile. Member order in JSON is not semantically
significant and a test MUST compare parsed values rather than bytes — the order
is fixed so that an implementation has one obvious answer, not so that a byte
comparison becomes meaningful.

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://axiam.example.com"],
  "scopes_supported": ["mcp:read", "mcp:tools"],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://mcp.example.com/docs"
}
```

**Validation is at construction time and it refuses; it never repairs.** Every
rule below raises the SDK's `ValidationError` (§2) from
`protected_resource_metadata` itself, before any route exists and before any
request is served. An SDK MUST NOT normalise, trim, lowercase, re-encode or
otherwise adjust a value to make it pass — this is a configuration mistake an
operator can fix in one line, and a helper that quietly fixes it publishes a
document describing a resource server that does not exist.

1. **`resource` is an absolute URI with a scheme and an authority, carrying no
   query and no fragment.** RFC 8707 §2 permits a query and forbids a fragment;
   §28 forbids both, because §28.3 derives the document's own URL from this
   value and a query makes that derivation ambiguous. A trailing slash is
   significant and is preserved.
2. **The scheme is `https`, except on a loopback host.** `http` is accepted
   when — and only when — the host is `127.0.0.1`, `[::1]` or `localhost`, which
   are the three hosts AXIAM's RFC 8252 §7.3 loopback rule already names. An SDK
   MUST NOT offer a flag, an environment variable or a debug build that widens
   this. It applies to `resource`, to every `authorization_servers` entry, and
   to `resource_documentation`.
3. **`authorization_servers` is a non-empty list of issuer identifiers.**
   RFC 9728 §2 marks the member OPTIONAL; §28 requires at least one entry,
   because a document that names no authorization server answers none of the
   question the client asked. Each entry is an absolute URI with **no query and
   no fragment** (RFC 8414 §2), a path is permitted, and duplicates are refused.
4. **An entry is the issuer, verbatim.** AXIAM's issuer is the deployment's root
   URL; the tenant travels as `?tenant_id=` on the individual endpoint URLs and
   never on the issuer. An SDK MUST NOT append a query to an entry to make it
   tenant-specific: the result is not an issuer, the `iss` a token carries would
   never equal it, and the client that trusted the document would reject every
   token the flow produced.
5. **`scopes_supported` is a list of scope tokens**, each one or more characters
   from RFC 6749 Appendix A's `NQCHAR` (`%x21`, `%x23`–`%x5B`, `%x5D`–`%x7E` —
   no space, no `"`, no `\`, no control character, no non-ASCII). Duplicates are
   refused. The caller's **order is preserved**; an SDK MUST NOT sort. An
   **empty** list is accepted and the member is then **omitted** from the
   document, because an empty `scopes_supported` asserts that this resource
   server understands no scopes, which is a different and almost always false
   claim.
6. **`bearer_methods_supported` is exactly `["header"]`** in this contract
   version. RFC 6750 §2 defines three methods and RFC 9728 §2 lets a document
   name any of them; §10's guard reads a bearer credential from the
   `Authorization` header alone, so `body` or `query` would describe behaviour
   no conformant SDK has. Any other value, an empty list, a duplicate, or an
   unknown string is refused. The parameter exists so that the member is
   explicit in the document and so that a later contract version can widen it
   without moving an argument.
7. **`resource_documentation`, when given, is an absolute URL** under rule 2's
   scheme requirement and its loopback carve-out. It MAY carry a query and
   MAY carry a fragment — it is a page for a human, not an identifier. When it
   is not given the member is omitted; an SDK MUST NOT emit `null`.
8. **Nothing in the document may come from a request.** `resource` and
   `authorization_servers` are configuration. An SDK MUST NOT build either from
   the `Host` header, the `Forwarded`/`X-Forwarded-*` family, the request URL or
   any other caller-controlled input, and MUST NOT offer an option that does.
   A document assembled from the request is a document an attacker can point at
   an authorization server of their choosing, which is the whole handshake
   redirected with one header.
9. **`resource` MUST equal the guard's expected audience.** §28.5 rule 2 makes
   that audience mandatory whenever the challenge is configured, and §28.5
   rule 3 says when the equality is checked and how the two strings are
   compared.

### §28.3 Serving the document (normative)

`serve_protected_resource_metadata(app, metadata)` registers one route, on the
framework's own router, in the framework's own idiom — §10's table already says
which object that is for each language.

**The path is derived from the resource, not chosen.** Let *P* be the path
component of `resource`:

| *P* | Metadata path |
|---|---|
| empty | `/.well-known/oauth-protected-resource` |
| `/` | `/.well-known/oauth-protected-resource` |
| anything else | `/.well-known/oauth-protected-resource` + *P* |

This is RFC 9728 §3.1's insertion between the authority and the path. Worked
examples, which double as the fixtures §28.9 test 1 asserts:

| `resource` | `metadata_path` |
|---|---|
| `https://mcp.example.com` | `/.well-known/oauth-protected-resource` |
| `https://mcp.example.com/` | `/.well-known/oauth-protected-resource` |
| `https://mcp.example.com/mcp` | `/.well-known/oauth-protected-resource/mcp` |
| `https://mcp.example.com/mcp/` | `/.well-known/oauth-protected-resource/mcp/` |
| `https://mcp.example.com/a/b` | `/.well-known/oauth-protected-resource/a/b` |

A trailing slash is carried through rather than trimmed: it is part of the
resource identifier the client will compare, and two resources that differ only
by it are two resources.

**Exactly one route is registered.** An SDK MUST NOT also register the root form
for a resource that has a path: a deployment fronting two resources would then
have two helpers competing for the same root path, and the loser would be
decided by registration order. A deployment that fronts several resources calls
the helper once per resource, and the derived paths cannot collide because each
is derived from its own resource.

The response, on `GET`:

1. **Status `200`**, body exactly the document of §28.2, under a `Content-Type`
   whose **media type** is `application/json`. A `charset` parameter a framework
   appends is permitted, and a test MUST compare the media type with parameters
   dropped rather than the header verbatim. Contract 1.48 pinned the header to
   the bare string; Fastify — one of the two surfaces §28.7 names for TypeScript
   — appends `; charset=utf-8` to any `*json*` content type that carries no
   charset and offers no supported way to suppress it short of writing to the
   raw socket and losing every `onSend` hook. A rule an SDK can satisfy only by
   abandoning its framework's supported API is a rule about the framework, not
   about the document. An SDK MUST NOT emit a *different* media type, and MUST
   NOT add any parameter of its own.
2. **Served without authentication.** The route MUST be reachable with no
   credential of any kind. Where the framework applies the §10 guard globally,
   the SDK MUST exempt this path explicitly, and §28.9 test 3 proves it. A
   document that 401s cannot start the handshake it exists to start — the client
   is holding a 401 and being told to go read a page that answers 401.
3. **[§3a](#§3a-resource-server-middleware-csrf-inbound) does not apply.** It is
   a `GET`, and §3a is scoped to state-changing methods and to cookie-sourced
   credentials, neither of which this route has.
4. **Identical for every caller.** The response MUST NOT vary on the request —
   no `Set-Cookie`, no per-caller content, nothing read from a header. It is the
   same bytes for an anonymous client and for an administrator.
5. **SHOULD carry `Cache-Control: public, max-age=3600`.** The document changes
   when an operator redeploys, not during a session.
6. **SHOULD carry `Access-Control-Allow-Origin: *`**, because an MCP client
   running in a browser cannot read the document without it. This is safe
   precisely because of rule 4: the document is public, unauthenticated and the
   same for everyone, so `*` grants a reader nothing it could not fetch
   directly. The response MUST NOT carry `Access-Control-Allow-Credentials:
   true`, which would be asking a browser to attach the user's cookies to a
   request that has no use for them.

**C and C++ have no router**, so `serve_protected_resource_metadata` is not a
function in those two SDKs; §28.7 gives the shape each of them takes instead.
Their READMEs show the adapter — CivetWeb for C, Crow or Pistache for C++ —
wiring the document and the derived path into a handler. The six response rules
above still bind that handler; the README is where they are stated for those
SDKs, and §28.9 test 3's unauthenticated `200` is asserted against it.

### §28.4 The challenge (normative)

`bearer_challenge(...)` returns the **value** of the `WWW-Authenticate` header,
never the whole header line and never a map. The caller — usually the
middleware — sets the header.

**Syntax.** The auth-scheme `Bearer`, then the parameters that are present,
each as `name="value"`, separated by exactly `, ` (one comma, one space), in
**this order**:

```
Bearer error="…", error_description="…", scope="…", resource_metadata="…"
```

The order is fixed so that the four test vectors below are exact strings rather
than a set a test has to re-parse. `resource_metadata` is always present;
the other three are omitted when not given.

**Quoting: every value is quoted, and no value is ever escaped.** RFC 6750 §3
restricts each parameter to a character set that cannot contain `"` or `\`, so a
value needing an escape is a value that does not belong in the challenge. An SDK
MUST validate and refuse rather than escape, truncate or strip:

| Parameter | Accepted values |
|---|---|
| `error` | exactly one of `invalid_request`, `invalid_token`, `insufficient_scope` (RFC 6750 §3.1) — nothing else, not even a well-formed-looking OAuth error code such as `invalid_grant` |
| `error_description` | one or more characters from RFC 6749 Appendix A's `NQSCHAR`: `%x20`–`%x21`, `%x23`–`%x5B`, `%x5D`–`%x7E`. No `"`, no `\`, no control character, no non-ASCII |
| `scope` | one or more scope tokens joined by a single space; each token is one or more `NQCHAR` (§28.2 rule 5). No leading, trailing or doubled space, and no empty token |
| `resource_metadata` | an absolute URL under §28.2 rules 1 and 2, with the additional rule that it carries no `"`, no `\`, no space and no control character. It MAY carry a query and a fragment; a correctly encoded URL cannot contain the forbidden characters, so one that does has not been encoded |

A refusal is the SDK's `ValidationError` (§2). It is raised from
`bearer_challenge` itself — a challenge is built from the code's own constants
and a route's own configuration, so an invalid one is a programming error and
not a runtime condition to degrade around.

**How `error` is typed is the SDK's own choice, and where the language can make
a fourth value unrepresentable it SHOULD.** The property that binds is the one
the table states — a challenge never carries an `error` outside RFC 6750 §3.1's
three codes — not the mechanism that secures it. A closed type (a Rust or Kotlin
`enum`, a C++ `enum class`, a Swift `enum`, a TypeScript string-literal union, a
Python `Literal`) secures it at compile time; a validated string (Go, C#, PHP,
C) secures it at run time. Both are conformant, and the reference implementation
is itself of the first kind. §28.9 test 2 says what this costs its `invalid_grant`
vector.

**Status codes.** RFC 6750 §3.1 pins each code to a status, and an SDK MUST
honour the pairing wherever it emits the challenge itself:

| `error` | Status | Emitted by the middleware? |
|---|---|---|
| *absent* | `401` | yes — when the request carried **no** credential |
| `invalid_token` | `401` | yes — when a credential was presented and rejected |
| `insufficient_scope` | `403` | yes — under §28.5 rule 5 and only there |
| `invalid_request` | `400` | **no** — available to a caller building a challenge by hand |

**The challenge says what failed only in RFC 6750's vocabulary.** The
middleware's automatic challenge MUST carry no `error_description` at all.
Expired, not yet valid, wrong tenant, wrong audience, bad signature, `alg`
confusion, a `cnf` the guard could not satisfy, a `sid` in the §10.4 revocation
feed — all of them are `invalid_token`, indistinguishably, and an SDK MUST NOT
add a description, a header, a body field or a log-correlation id to the
*response* that tells them apart. It is a 401 to an unauthenticated stranger:
every distinction it draws is an oracle. The `error_description` parameter
exists for an application building its own challenge for its own 400, and the
SDK's own guard never uses it.

**Absent `error` is not an oversight.** RFC 6750 §3 says a resource server
SHOULD NOT include an error code when the request carried no authentication
information at all, and that is exactly the first row above: no credential is
not a bad credential. An SDK MUST distinguish the two, and §28.9 test 3 asserts
both.

**Test vectors (normative)**, for a resource of `https://mcp.example.com/mcp`
and therefore a metadata URL of
`https://mcp.example.com/.well-known/oauth-protected-resource/mcp`:

| Case | Exact value |
|---|---|
| no credential presented | `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"` |
| credential presented and rejected | `Bearer error="invalid_token", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"` |
| scope failure (403) | `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"` |
| all four parameters | `Bearer error="invalid_request", error_description="The access token is malformed", scope="mcp:read mcp:tools", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"` |

### §28.5 The `resource_metadata_url` middleware option (normative)

One option on the §10 middleware/route-guard, off by default.

1. **Setting it is what turns the section on.** With the option unset, the
   guard's behaviour is byte-identical to what it is today: no
   `WWW-Authenticate` header on any response, no status changed, no body
   changed. §28.9's regression asserts this, and it is the rule most likely to
   be broken by an implementation that emits a bare `Bearer` challenge
   "harmlessly" when the option is absent.
2. **`expected_audience` MUST be set when `resource_metadata_url` is.** A
   resource server that publishes "tokens for me carry this `aud`" and then does
   not check `aud` has published a claim it does not honour, and a token minted
   for a different resource server opens it. The SDK MUST refuse the
   configuration — at construction, at startup, before the first request — and
   the refusal MUST name both options. "Expected audience" is §10.1 row 6's
   existing configuration under whatever name that SDK already gives it; an SDK
   MUST NOT add a second audience option for §28.
3. **Two strings must agree, and they are compared exactly.** Where the SDK can
   see both the guard and a `protected_resource_metadata` value configured on
   the same application, it MUST refuse the configuration at startup unless:

   - the guard's `resource_metadata_url` equals the document's `metadata_url`
     (§28.1) — otherwise the challenge points at a document that is not this
     resource server's; **and**
   - the guard's expected audience equals the document's `resource` (§28.2
     rule 9) — otherwise the document announces one identifier and the guard
     checks `aud` against another, so every token the flow produces is refused.

   Note that these are two *different* strings: the resource is
   `https://mcp.example.com/mcp` and the metadata URL is
   `https://mcp.example.com/.well-known/oauth-protected-resource/mcp`. An
   implementation that compares one against the other rejects every correct
   configuration.

   Both comparisons are simple string equality (RFC 3986 §6.2.1): no
   normalisation, no case folding of the host, no trailing-slash tolerance. A
   trailing slash that differs between the document and the guard is a real
   misconfiguration, it will make a real client's `aud` check fail, and the
   place to report it is startup rather than a support ticket.

   Where the SDK cannot see both — the guard configured in one process and the
   document served by another — nothing can be checked and nothing is. The
   operator configures both from one constant, and the `metadata_url` §28.1
   returns is how.
4. **Every 401 the guard emits carries the challenge.** That is the §10
   middleware's own 401, §11's `require_auth`/`authentication_failed` 401, and a
   401 produced by the §10.4 revocation feed. The status is unchanged and the
   §10 JSON body (`{ "error": …, "message": … }`) is unchanged; a header is
   added. `error="invalid_token"` when a credential was presented, and no
   `error` when none was.

   **Choosing between the two vectors needs the request, and one shape of §11
   helper does not have it.** In several SDKs a §11 helper is not a
   self-contained middleware but a function the application calls with the
   identity the §10 guard already resolved — `enforceAuth(identity)`,
   `require_auth(std::optional<AxiamUser>)`. By the time it runs, whether a raw
   credential was ever presented is gone, and recovering it would mean either
   widening a shipped signature or re-extracting the credential the §11 helpers
   are forbidden to touch. Such a helper's missing-identity 401 therefore
   carries **no** challenge, and that is conformant: it is reachable only when
   the §10 guard did not run on that route, and where the §10 guard did run its
   own 401 already carried the correct vector. An SDK in this position records
   it in its §28.10 row, naming the helper. An SDK whose §11 helper *can* see
   the request — because it is itself middleware, or is handed one — MUST pick
   the vector from it and MUST NOT default to one.
5. **One kind of 403 carries the challenge, and only one.** When a §11
   `require_access(action, resource, scope)` was given a `scope` argument, and
   the decision came back `allowed = false` with `reason_code` **`no_grant`**
   (§11.2 rule 9), the 403 carries
   `error="insufficient_scope"` and `scope=` that argument, verbatim.

   Every other 403 carries **no** `WWW-Authenticate` header: a
   `require_access` with no `scope` argument, a `require_role` failure, a §3a
   CSRF refusal, and — the one that matters — a decision whose `reason_code` is
   **`denied_by_rule`**. §11.2 rule 9 already says why those two refusals are
   not the same thing: `no_grant` means *ask for more*, which is what a
   challenge invites a client to do, and `denied_by_rule` means *an
   administrator has already decided*, which no amount of re-authorization will
   change. Challenging on `denied_by_rule` sends an MCP client around the
   authorization loop to arrive at the identical 403.

   An **absent or unrecognised** `reason_code` — an older server, a value this
   SDK predates — is **not** eligible: emit no challenge. §11.2 rule 9 requires
   an unknown code to leave the outcome alone, and the outcome here is today's
   header-free 403.

   **Read this twice: the JSON body does not change.** The response is still
   `403` with §11.2 rule 5's body, `{"error": "authorization_denied", …}`.
   `insufficient_scope` appears **only** as the `error` parameter inside the
   `WWW-Authenticate` value. An implementation that puts `insufficient_scope`
   in the body has changed §11's error taxonomy, which §28 does not do.

6. **The scope named is the one the route asked for, verbatim.** The SDK MUST
   NOT synthesise a scope string, MUST NOT derive one from the `action` and
   `resource` arguments, and MUST NOT substitute the scopes from the document's
   `scopes_supported`. Where a deployment's AXIAM resource-scope names and its
   OAuth scope names differ, naming the route's scope in the form the
   authorization server will accept is the operator's decision, and
   `scopes_supported` is where they publish the list they chose. An SDK that
   guessed would be guessing on the operator's behalf about a namespace it
   cannot see.
7. **No other response is touched.** A `2xx`, a `400`, a `404`, a `405`, a `500`
   — none of them gains a header. A challenge on a success is a client asking
   the authorization server what went right.
8. **Other transports.** §28 is an HTTP section. An SDK whose guard also covers
   gRPC MAY attach the same string as `www-authenticate` metadata on an
   `UNAUTHENTICATED` status, where the value carries the identical parameters
   and the identical refusals; nothing requires it, and §10.3 is unchanged
   either way. AMQP has **no** equivalent and an SDK MUST NOT invent one — there
   is no client waiting on a response to re-authorize with.

### §28.6 What §28 does not change

Read as a list of things an implementer may be tempted to adjust and must not.
Each is a section §28 *consumes*:

| Section | Unchanged |
|---|---|
| §10.1 row 6 | the audience check, its configuration and its failure. §28.5 rule 2 makes it **required** in one configuration; it does not alter what it does |
| §10.1 rule 9 | `cnf`. A `jkt`- or `x5t#S256`-bound token is exactly as bound as before, and its refusal is an ordinary `invalid_token` 401 that now carries a challenge |
| §10.2 | the revocation posture, including the MUST NOT on per-request polling. An MCP server on a gRPC data plane under the default posture admits a logged-out user for the token's remaining lifetime, and publishing a metadata document does not change that. §10.4's feed remains the bounded answer, and remains off by default |
| §10.3, §21.7 | DPoP. §28 neither requires nor weakens proof verification. An SDK that declines DPoP still rejects `jkt`-bound tokens, and §28 gives that rejection a challenge rather than an exemption |
| §11 | the helpers, their arguments, their statuses and their JSON bodies. §28.5 rule 5 adds a header to one class of 403 and reads `reason_code` to decide; it writes nothing back |
| §2 | the error taxonomy. §28's refusals are `ValidationError`; no new type |
| §16, §9 | untouched, because §28 makes no request (§28.0) |

### §28.7 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `protected_resource_metadata` | `protected_resource_metadata` | `protectedResourceMetadata` | `protected_resource_metadata` | `protectedResourceMetadata` | `protectedResourceMetadata` | `ProtectedResourceMetadata` | `protectedResourceMetadata` | `ProtectedResourceMetadata` | `protectedResourceMetadata` | `axiam_protected_resource_metadata_json` (+ `_path`, `_url`) | `protected_resource_metadata` |
| `serve_protected_resource_metadata` | `serve_protected_resource_metadata` | `serveProtectedResourceMetadata` | `serve_protected_resource_metadata` | `serveProtectedResourceMetadata` | `serveProtectedResourceMetadata` | `ServeProtectedResourceMetadata` | `serveProtectedResourceMetadata` | `ServeProtectedResourceMetadata` | `serveProtectedResourceMetadata` | — (§28.3) | — (§28.3) |
| `bearer_challenge` | `bearer_challenge` | `bearerChallenge` | `bearer_challenge` | `bearerChallenge` | `bearerChallenge` | `BearerChallenge` | `bearerChallenge` | `BearerChallenge` | `bearerChallenge` | `axiam_bearer_challenge` | `bearer_challenge` |
| option `resource_metadata_url` | `resource_metadata_url` | `resourceMetadataUrl` | `resource_metadata_url` | `resourceMetadataUrl` | `resourceMetadataUrl` | `ResourceMetadataUrl` | `resourceMetadataUrl` | `ResourceMetadataURL` | `resourceMetadataUrl` | `axiam_client_set_resource_metadata_url` | `resource_metadata_url` |

**No `Async` suffix anywhere**, including C#: none of the three performs I/O
(§28.0), so all three are synchronous in every language and return no future,
no promise and no coroutine. Kotlin's are ordinary functions, not `suspend`
ones; Swift's are not `async`.

**Go's option is `ResourceMetadataURL`**, not `…Url`: Go's initialism
convention is what §1's "each language uses its own idiomatic naming
convention" means, and [§10.4.1](#§1041-per-sdk-posture) already spells Go's
row `JWKSVerifier.WithRevocationFeed` for the same reason.

**Go's returned type is `MCPResourceMetadata`, and only Go's is renamed.** Go
has one identifier namespace at package scope, and this table pins the *function*
there to `ProtectedResourceMetadata`; the value it returns cannot also be called
that. `MCPResourceMetadata` (and `MCPResourceMetadataDocument`) is the reserved
name, and an SDK MUST NOT invent a third spelling. **No other language needs the
accommodation**, and a port MUST NOT take it pre-emptively: in Rust and Python
the function is `snake_case` where the type is `PascalCase`; in Java, Kotlin, C#,
PHP and Swift the function is a member of a class, object or client rather than a
free name, so the type name is never in contention. The row a language gets is
the row it has; a collision it does not have is not a licence to rename.

**C and C++ have no `serve_` function** (§28.3). C has no value type to hang
the document on either, so its row is the §27.3 flat-symbol accommodation
again: `axiam_protected_resource_metadata_json(...)`,
`axiam_protected_resource_metadata_path(...)` and
`axiam_protected_resource_metadata_url(...)` each return an owned string,
freed with the SDK's existing string-free function, and each applies the whole
of §28.2's validation and returns the SDK's validation error rather than a
string when it fails. **All three, not two**: §28.1 requires an SDK to expose
`metadata_path` *and* `metadata_url`, and a row naming only the first two would
have C's integrator concatenate the URL by hand — which is precisely the second
place §28.1 says the two must not be allowed to disagree. (Contract 1.48 named
only `_json` and `_path`; the C port shipped `_url` anyway and said so, and this
revision makes the table say what §28.1 already required.)

**"Raises the SDK's `ValidationError`" (§28.2, §28.4) is a per-language mapping,
not a type name.** §28.6's "no new type" forbids inventing an error type *for
§28*; it does not require a language to acquire an exception mechanism it does
not have, nor to reach for a type that means something else in that SDK. Each
port uses whatever it already raises for a local, pre-request configuration
refusal — C returns `NULL` with its `axiam_error_t` out-parameter, C++ throws
`std::invalid_argument` (its own `ValidationError` denotes a *server's* 400 on
the management surface), and the other nine raise the type §2 names. What §28
forbids is a *new* type and a silently repaired value, and all eleven honour
both. C++ has a value type and uses it —
`protected_resource_metadata()` returns it, with the document, `metadata_path`
and `metadata_url` as members, exactly as every other language. Both READMEs
carry the adapter.

**The framework surfaces** are §10's, unchanged: an Actix-Web `web::resource`,
an Express route or Fastify plugin, a FastAPI router and a Django view, a Spring
`@RestController`, a Ktor route, an ASP.NET Core minimal-API endpoint, a Laravel
route or Symfony controller, a `net/http` `HandlerFunc`, a Vapor route.

**Kotlin, Swift, C and C++ ship the REST form only**, per `CLAUDE.md`'s
REST-surface carve-out. That costs them nothing here: §28.5 rule 8 makes the
gRPC form optional for everyone and forbids an AMQP form to everyone, so the
REST surface *is* the section, and all eleven are held to the same set of
operations and the same five tests.

### §28.8 `Sensitive<T>` applicability

**Nothing in §28 is sensitive, and that is a rule rather than an omission.** The
document is published unauthenticated to the world; the challenge is returned to
a caller who has just failed to authenticate. Both MUST remain readable and MUST
NOT be wrapped in `Sensitive<T>` (§7) — a resource server whose own operator
cannot read its published metadata in a log is a resource server nobody can
debug.

The corollary is the rule that matters: **no part of the presented credential
may reach either of them.** Not the token, not a prefix or suffix of it, not a
hash of it, not a claim decoded from it, not a `jti` or a `sid`, in any
parameter, in any header, in any body and in any log line the guard writes on
the 401 path. §28.4's ban on `error_description` in an automatic challenge is
the specific case; this is the general one.

### §28.9 Required tests

Five, per SDK. They are written to be portable: the same five assertions, on the
same fixtures, in every repository, so that a divergence is visible as a
different expected value rather than as a different test. **The fixture is one
configuration**, and every test below uses it:

```
resource                 = "https://mcp.example.com/mcp"
authorization_servers    = ["https://axiam.example.com"]
scopes_supported         = ["mcp:read", "mcp:tools"]
bearer_methods_supported = ["header"]                     # the default
resource_documentation   = "https://mcp.example.com/docs"

metadata_path            = "/.well-known/oauth-protected-resource/mcp"
metadata_url             = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
expected_audience        = "https://mcp.example.com/mcp"  # equal to `resource`
```

1. **Document shape, and the validation negatives.** The positive: the fixture
   above produces the exact JSON of §28.2, compared as parsed values, and each
   of the five `metadata_path` derivations in §28.3's table. The negatives,
   each asserting a `ValidationError` from `protected_resource_metadata` and
   **no** route registered: a relative `resource`; a `resource` with a fragment;
   a `resource` with a query; an `http` `resource` on a non-loopback host, and
   the same on `127.0.0.1` **accepted**; an empty `authorization_servers`; an
   `authorization_servers` entry carrying a query; the same carrying a fragment;
   a duplicate entry; a duplicate scope; `bearer_methods_supported` of
   `["query"]` and of `["header", "body"]`; an empty `scopes_supported` that is
   accepted and **omits the member**; an absent `resource_documentation` that
   **omits the member** rather than emitting `null`.
2. **Challenge quoting.** The four vectors of §28.4, asserted as exact strings —
   including the parameter order and the `, ` separator. Then the refusals, each
   a `ValidationError`: an `error` of `invalid_grant`; an `error_description`
   containing `"`; one containing `\`; one containing a newline; one containing a
   non-ASCII character; a `scope` with a leading space, with a doubled space, and
   empty; a `resource_metadata` containing a space. Assert **no escaping
   occurred** — that the refused values produce an exception rather than a
   challenge containing `\"`.

   **The `invalid_grant` vector, where the language will not let it be
   written.** §28.4 lets an SDK type `error` as a closed set. Where a fourth
   value is then unrepresentable without an unsafe cast — Rust, Kotlin, C++,
   Swift — the vector is discharged **structurally**, and the required artefact
   is a comment at the test site naming `invalid_grant` and saying the value
   cannot be constructed, not an assertion. Where the language offers a checked
   escape hatch that stays inside safe code — TypeScript's `as never`, a Python
   `Literal` the runtime does not enforce — the test uses it and asserts the
   refusal, which is what the reference implementation does. What is not
   conformant is dropping the vector in silence: a reader comparing eleven
   suites must see either the assertion or the reason there is none.
3. **401 with the challenge.** Against a route behind the guard, with
   `resource_metadata_url` set: a request with **no** `Authorization` header
   returns `401` whose `WWW-Authenticate` is vector 1 exactly — no `error`
   parameter; a request with an **expired** token returns `401` whose
   `WWW-Authenticate` is vector 2 exactly. In both, assert the §10 JSON body is
   unchanged from what the SDK returns today, and that the response carries no
   `error_description` and nothing derived from the token. Separately: a `GET`
   of `metadata_path` with **no** credential returns `200` and the document,
   with the guard registered globally.
4. **403 `insufficient_scope`.** A route guarded by
   `require_access(action, resource, "mcp:tools")` whose check returns
   `allowed = false, reason_code = "no_grant"` returns `403` whose
   `WWW-Authenticate` is vector 3 exactly, **and** whose JSON body is still
   `authorization_denied`. Then the three that carry **no**
   `WWW-Authenticate` header at all: the same route when `reason_code` is
   `denied_by_rule`; the same route when `reason_code` is absent; and a
   `require_access` denial where no `scope` argument was given.
5. **A token whose `aud` is not the resource is refused.** With the fixture's
   `expected_audience` and `resource_metadata_url` both set: a token carrying
   `aud: "https://other.example.com/mcp"` is refused `401` with vector 2, and a
   token carrying `aud: "axiam:user"` is refused identically — a
   general-purpose AXIAM user token is not a token for this resource server, and
   an implementation that admits it has not implemented the section. The
   positive alongside them: a token carrying
   `aud: "https://mcp.example.com/mcp"` is admitted. And the configuration
   negative: constructing the guard with `resource_metadata_url` set and no
   expected audience **fails at construction**, naming both options.

**And one regression that matters more than all five: with
`resource_metadata_url` unset, nothing changes.** Every response the guard
produces — `200`, `401`, `403` — is byte-for-byte what that SDK produced before
§28 existed, and carries **no** `WWW-Authenticate` header. Assert the header's
absence explicitly rather than asserting the status; a 401 that grew a header is
still a 401, and an implementation that emits a bare challenge unconditionally
passes every other test in this list. This is the §28 form of the rule §10.4 and
§8b both state: a feature that is off must be indistinguishable from a feature
that is absent.

### §28.10 Per-SDK posture

As §10.4.1, §21.9, §21.10 and §27.10: **an unrecorded row is not a supported
answer**, `declines` with a reason is, and the row follows the code in that
repository rather than this contract's expectation of it.

**This table is maintained here, by the cross-SDK review, and nowhere else.**
Contract 1.48 said "each SDK's own PR updates its row", and that instruction was
a mistake: the row lives in `CONTRACT.md`, which each SDK holds as a *vendored
copy* of this file. A port that follows the instruction makes its copy diverge
from upstream; a port that declines leaves the row unrecorded. **Seven of the
eleven left their row reading *not yet* while shipping §28**, three edited
theirs, and TypeScript's was written here by T9a and never said *not yet* at
all — so the instruction produced five distinct byte-states
of one document all calling themselves contract 1.48 ([§28.11](#§2811-cross-sdk-conformance-review-contract-149) row R-1).
A port now records its posture in its **own** README and `CHANGELOG.md` — files
it owns — and the review transcribes it here. The rows below were established
that way, by reading the eleven merged ports rather than their reports of
themselves.

| SDK | §28 status |
|-----|-----------|
| TypeScript | **implemented** — the reference implementation (`src/middleware/mcpCore.ts`), Express and Fastify. The ten ports are read against it |
| Rust | **implemented** — Actix-Web. `resource_metadata_url` is centralised on `JwksVerifier`, so the §28.5 rule 2 pairing is checked in exactly one place; the document route composes no extractor, so §28.3 rule 2's exemption is structural rather than coded |
| Python | **implemented** — FastAPI (dependency + router) and Django (middleware + view). Django's `urlpatterns` stands in for the `app` argument |
| Java | **implemented** — Spring Boot. The two 401 branches are split across `AxiamAuthenticationFilter` (a rejected credential) and `AxiamMcpAuthenticationEntryPoint` (no credential), which Spring's filter/exception-handling split forces; both are built from the same verifier |
| Kotlin | **implemented** — Ktor plugin + route, REST only. Spring Boot reuses the Java SDK's collaborators, as this SDK's README already directs for §10/§11 |
| C# | **implemented** — ASP.NET Core middleware + minimal-API endpoint. `declines` §28.5 rule 8's optional gRPC form: its `Grpc`/`Amqp` namespaces are client transports *to* AXIAM, so there is no inbound guard to extend |
| PHP | **implemented** — Laravel (middleware + `Route::` macro) and Symfony (subscriber + controller). `declines` rule 8's gRPC form for the same reason. Its standalone `#[RequireAuth]` 401 carries no challenge, per §28.5 rule 4's resolved-identity clause |
| Go | **implemented** — `net/http`. Its returned type is `MCPResourceMetadata` (§28.7); rule 2 is enforced on `Middleware`, the one guard that owns an audience; `declines` rule 8's gRPC form |
| Swift | **implemented** — REST only, guard-side; no first-party Vapor adapter, matching this SDK's existing framework-agnostic §10/§11 shape, with the wiring documented |
| C | **implemented** — REST only. No `serve_` function (§28.3); flat symbols per §28.7, including `axiam_protected_resource_metadata_url`; guard integration via the additive `axiam_require_auth_mcp`/`axiam_require_access_mcp`, on `axiam_require_access_uma`'s precedent |
| C++ | **implemented** — REST only. No `serve_` function; `AxiamGuard` carries the challenge, and bare `require_auth()` does not, per §28.5 rule 4's resolved-identity clause |

The reference implementation exists for the reason the §27 one did: to prove the
section is buildable as written before ten more repositories commit to it, and
to give them a test suite to port rather than a specification to interpret.

### §28.11 Cross-SDK conformance review (contract 1.49)

The T9d review of the eleven merged ports, in the format §12's review
(`claude_dev/sdk-oidc-sso-conformance-review.md`) established and §12.6 and
§27.10 carry forward. The full evidence — per-rule matrix, commits read, test
runs — is
[`claude_dev/sdk-mcp-helpers-conformance-review.md`](../claude_dev/sdk-mcp-helpers-conformance-review.md);
this table is the record that must have no open row.

**One row per divergence, not per SDK.** Disposition is one of **contract
fixed** (§28's text was wrong or silent and this revision changes it), **SDK
fixed** (the code was wrong and a PR corrects it), **forced by the language,
recorded** (neither is wrong; the divergence is real and permanent), or
**open** (which this table may not carry).

| # | Divergence | SDKs | §28 clause | Disposition | Where the fix landed |
|---|---|---|---|---|---|
| R-1 | "Vendored at contract 1.48" denotes **five different files**. Seven repos re-synced `openapi.json` from the unmerged phase branch and regenerated their §27 surfaces; four declined. None of the eleven matches this repository. TypeScript vendored an older `CONTRACT.md` snapshot than the other ten | all eleven | 1.48 version trailer | **contract fixed** | The 1.49 trailer below states the rule: a vendored artefact is re-synced from a **merged** `main`, never a phase branch. The `openapi.json` half of 1.48 is deferred to **follow-up F-28-01**, named in all eleven `CHANGELOG.md` files |
| R-2 | §28.10's row still read *not yet* in seven repos that had shipped §28 | Rust, Python, Java, Kotlin, Go, Swift, C++ (left as *not yet*); C#, PHP, C (edited theirs, in a vendored file); TypeScript (a forward-looking reference row T9a wrote, never *not yet*) | §28.10 | **contract fixed** | §28.10 above: the table is maintained upstream by this review; a port records its posture in its own README and CHANGELOG |
| R-3 | The README conformance statement does not follow the code: four repos omit §28 entirely, two name it at a stale contract version | Rust, Java, Go, Swift (omit); Python, C# (stale version) | Closing Notes, "the statement follows the code" | **SDK fixed** | One PR per repository (F-28-02) |
| R-4 | `Content-Type: application/json` cannot be emitted exactly on Fastify, which appends `; charset=utf-8` and offers no supported suppression | TypeScript (Fastify); PHP and C# assert the media type defensively | §28.3 rule 1 | **contract fixed** | §28.3 rule 1 above: the **media type** binds, a framework-appended `charset` is permitted, and a test compares with parameters dropped |
| R-5 | The returned value's type name collides with the pinned function name in one language only | Go | §28.7 | **forced by the language, recorded** | §28.7 above reserves `MCPResourceMetadata` for Go and states that no other language needs it. Go's premise that seven others would hit the same wall was checked against all seven and is **not** the case |
| R-6 | §28.7's C row named `_json` and `_path` but no `metadata_url` accessor, although §28.1 requires both | C (C++ correctly unaffected) | §28.7 vs §28.1 | **contract fixed** | §28.7 above. The C port had already shipped `axiam_protected_resource_metadata_url` and declared the gap |
| R-7 | `error` is a closed type in seven SDKs and a validated string in four, so §28.9 test 2's `invalid_grant` vector is unreachable in the first group | closed: TypeScript, Rust, Python, Java, Kotlin, Swift, C++ · string: C#, PHP, Go, C | §28.4, §28.9 test 2 | **contract fixed** | §28.4 and §28.9 test 2 above: the typing is the SDK's choice, the property is what binds, and the vector is discharged structurally with a comment where it cannot be written |
| R-8 | A §11 helper that receives an already-resolved identity cannot tell vector 1 from vector 2, so its missing-identity 401 carries no challenge | PHP (`enforceAuth`), C++ (bare `require_auth()`) | §28.5 rule 4 | **contract fixed** | §28.5 rule 4 above. The 401 is reachable only where the §10 guard did not run, and where it did its own 401 already carried the vector |
| R-9 | `RequireRole`'s missing-identity 401 carries no challenge, although its handler holds the request and its sibling `RequireAuth` does carry one | Go | §28.5 rule 4 | **SDK fixed** | `RequireRole`'s variadic is spent on `roles`, but an additive options-carrying companion constructor was available and is what the fix adds (F-28-03) |
| R-10 | §28.5 rule 2's "refuse at construction" is honoured by six different mechanisms | thrown `ValidationError` (TypeScript, Python, Java, Kotlin, PHP, C#) · `Result<Self, AxiamError>` (Rust) · `panic` (Go) · throwing initializer (Swift) · `std::invalid_argument` (C++) · `NULL` + `axiam_error_t` (C) | §28.5 rule 2, §28.6 | **forced by the language, recorded** | §28.7 above: "raises the SDK's `ValidationError`" is a per-language mapping. Every one refuses **at construction**, which is what the rule says; none invents a type for §28, which is what §28.6 forbids. All eleven name both options in the refusal |
| R-11 | The `reason_code` §28.5 rule 5 needs was not on the pre-existing access-check surface | Go (`AccessDecisionChecker`), PHP (`checkAccessDecision`), C# (`CheckAccessDecisionAsync`) | §28.5 rule 5, §11.2 rule 9 | **forced by the language, recorded** | Verified in all three: one wire call, never two (Go's is an `if`/`else`, PHP's and C#'s bare-bool check now delegates to the richer one), and a checker implementing only the old interface still compiles and still behaves as before |
| R-12 | `Rule8CallerCredentialTest`'s constructor pin (§10.1 rule 8 / SEC-085) widened from "exactly one constructor, these two parameters" to "every public constructor takes only a verifier and Strings" | Java | §10.1 rule 8 | **SDK fixed** | The widened pin still refuses every object-shaped credential and still pins the constructor count, but it would now admit a **String-shaped** one. Repaired by *adding* a field allow-list rather than by restoring the old assertion (F-28-04) |
| R-13 | Where a §20.3 UMA challenge and a §28.5 rule 5 challenge both apply to one 403, the UMA challenge wins and exactly one value is emitted | every SDK that ships §20.3's emit half | §28.5 rule 5 vs §20.3 | **forced by the language, recorded** | Not a divergence after all: independently reached and identically resolved in all of them. §28 does not mention §20.3 and does not need to — §28.4's exact-string vectors leave no room for a combined value, and the UMA ticket names a remedy where §28's names a scope |

**Follow-ups.** F-28-01 (the `openapi.json` re-sync, after Phase 21 merges),
F-28-02 (README conformance statements), F-28-03 (Go `RequireRole`), F-28-04
(the Java constructor pin). F-28-02 through F-28-04 are pushed by this review;
F-28-01 is blocked on a merge and is recorded in all eleven repositories so that
it cannot be lost.

### §28.12 RFC 7592 client configuration operations (contract 1.53)

**Requirement level: SHOULD. Additive; nothing in §28.0–§28.11 changes.** Server
documentation: [`docs/admin/dynamic-client-registration.md`](../docs/admin/dynamic-client-registration.md)
(the client configuration endpoint) and [`docs/api/mcp.md`](../docs/api/mcp.md).
Wire references: RFC 7592 §2 (the three requests), §3 (the response); RFC 7591
§2–§3 (the metadata and its errors); RFC 6750 §2.1 and §3 (the bearer and its
challenge). Threat model: T-289.

A successful `POST /oauth2/register` (RFC 7591) now also returns, **once**:

| Member | Is |
|---|---|
| `registration_client_uri` | `{issuer}/oauth2/register/{client_id}` — under a T21.6 tenant path issuer, `{root}/t/{tenant_id}/oauth2/register/{client_id}`; at the root, `{root}/oauth2/register/{client_id}?tenant_id={tenant_id}` |
| `registration_access_token` | an opaque bearer (43 base64url characters today; an SDK MUST NOT parse or length-check it) that authorizes reading, replacing and deleting **that one** registration and nothing else |

Only clients registered through `POST /oauth2/register` hold one. An
administrator's client, a CIMD client and a self-registered client older than
the server change have none, and every operation below answers them `401`.

#### §28.12.1 Canonical operation set

| Canonical operation | HTTP | Network I/O | Returns |
|---|---|---|---|
| `read_client_registration` | `GET registration_client_uri` | **yes** | a `ClientRegistration` (no token, no secret) |
| `update_client_registration` | `PUT registration_client_uri` | **yes** | a `ClientRegistration` carrying the **rotated** `registration_access_token` |
| `delete_client_registration` | `DELETE registration_client_uri` | **yes** | nothing (`204`) |

Signatures (canonical order; each language's §1 casing applies):

```
read_client_registration(registration_client_uri,
                         registration_access_token)          # Sensitive<String>

update_client_registration(registration_client_uri,
                           registration_access_token,        # Sensitive<String>
                           metadata)                         # ClientRegistration or the
                                                             # language's metadata map

delete_client_registration(registration_client_uri,
                           registration_access_token)        # Sensitive<String>
```

`ClientRegistration` carries the RFC 7591 §3.2.1 / RFC 7592 §3 members the
server returns: `client_id`, `client_id_issued_at`, `client_name`,
`redirect_uris`, `grant_types`, `response_types`, `token_endpoint_auth_method`,
`scope`, `registration_client_uri`, and, when present, `client_secret_expires_at`,
`jwks`, `jwks_uri`, `client_secret` and `registration_access_token`. An SDK MUST
decode unknown members without failing (RFC 7591 §3.2.1 lets a server add them).

They are methods of the SDK's existing client object, which is what supplies the
configured AXIAM origin rule 1 checks against. **C# takes the `Async` suffix**
on all three, and Kotlin's are `suspend`, Swift's `async`: unlike §28.1's, these
perform I/O (§1 "Async method naming").

#### §28.12.2 Rules (normative)

1. **The URI is used as given, and only at the configured AXIAM.** RFC 7592 §3:
   the client uses `registration_client_uri` verbatim, query included, and never
   builds it. Before any request, an SDK MUST refuse — the SDK's local
   `ValidationError` mapping, as §28.7 defines it, and **no request sent** — a
   URI whose scheme, host and port differ from the SDK client's configured
   AXIAM base URL, and an `http` URI unless that base URL is itself `http` on a
   loopback host. The token is a bearer: a helper that followed a URI to another
   origin would hand it to whoever wrote the URI (§20.3's argument, §28.0's
   reason for keeping the client half out).
2. **The token travels in the `Authorization` header only** —
   `Authorization: Bearer <token>`. Never in the query string (the server
   refuses it there with `400 invalid_request`, and by then it has been logged
   on the way), never in a body. `GET` and `DELETE` send no body.
3. **It is not the SDK's session.** The SDK MUST NOT attach its own access token
   or session cookie to these requests, and MUST NOT attach this token to any
   other request. A `401` from them MUST NOT enter [§9](#§9-single-flight-refresh-guard)
   — refreshing the SDK's session cannot fix a registration token
   ([§12.3](#§123-cross-cutting-rules-normative-identical-in-all-sdks) rule 3's
   reasoning).
4. **`update_client_registration` sends a full replacement** (RFC 7592 §2.2).
   The SDK builds the body from `metadata` and MUST: set `client_id` to the
   registration's own; remove `registration_access_token`,
   `registration_client_uri`, `client_secret_expires_at` and
   `client_id_issued_at` (the server refuses each with `400 invalid_request`);
   and not send `client_secret`. A member the caller omits is a member the
   server deletes — an SDK MUST document that `metadata` is the whole
   registration, and SHOULD let a caller start from the result of
   `read_client_registration`, which carries every member the update needs
   (including `jwks` / `jwks_uri` for a `private_key_jwt` client). A member the read did not
   carry is not sent, and a member of an unexpected shape is kept as read (contract 1.59,
   [§34.2](#§342-clarifications-normative-from-159) P12.4).
5. **An update rotates the token.** The returned `registration_access_token` is
   the only valid one from that moment; the presented one is dead, for every
   operation. An SDK MUST return it to the caller and MUST document at the call
   site that it must be persisted. An SDK MUST NOT retry an update — not through
   [§16](#§16-retry-policy-d5), not on a `NetworkError`, not on a `5xx` — because
   an update that reached the server and lost its response has already rotated
   the token, and a retry with the old one is a `401` that leaves the caller
   locked out of its own registration. `delete_client_registration` MUST NOT be
   retried either: a retry after a lost `204` reads `401`, which would report a
   successful deletion as a failure. `read_client_registration` MAY be retried
   per §16.
6. **The server's answers.** A read never returns the token or the client secret.
   An update that widens a scope or grant beyond the tenant's policy, leaves its
   redirect-host allow-list, or changes `token_endpoint_auth_method` is refused
   `400` (`invalid_client_metadata` / `invalid_redirect_uri`); the token is not
   rotated by a refusal. An unknown client, a wrong or rotated-away token,
   another tenant's client and a client with no token are all `401`
   `invalid_token` with `WWW-Authenticate: Bearer error="invalid_token"` — the
   server never says which (RFC 7592 §2.1), and an SDK MUST NOT try to. `403` is
   an update on a tenant that has since disabled registration. The three routes
   share one per-IP rate limit (`429`). A successful `delete_client_registration` revokes
   the client's refresh tokens and voids its outstanding codes and pushed requests
   ([§27.15](#§2715-model-and-behaviour-notes-contract-160) note 2); the SDK does nothing
   further.

#### §28.12.3 Error mapping

Per [§2](#§2-error-taxonomy)'s `/oauth2/*` row: any response whose body is an
error object with a non-empty `error` member is `OAuthProtocolError`, dispatched
on `error` (`invalid_token`, `invalid_request`, `invalid_client_metadata`,
`invalid_redirect_uri`) — a `401` included, and that `401` does not enter §9
(rule 3). Otherwise §2's status rows apply (`429` and `5xx` are
`NetworkError`). Rule 1's refusal is local and raises before any I/O. No new
error type.

#### §28.12.4 `Sensitive<T>` applicability

Unlike §28.8's helpers, these carry a credential. **`registration_access_token`
MUST be `Sensitive<T>`** ([§7](#§7-sensitivet-requirement)) wherever it
appears: as the argument of all three operations, and as the member of
`ClientRegistration`; and so MUST `client_secret` on that type. §7 rule 1's
redaction covers both in every stringification sink, §19 telemetry payloads
carry neither (§27.5 rule 4's rule, applied here), and an error raised by these
operations MUST NOT include the token, a prefix of it or a hash of it
([§2](#§2-error-taxonomy) "Errors MUST NOT expose raw token strings"). This is
the #480 lesson — `initial_access_token` was published unmarked and every SDK
could log it (§27.5, contract 1.50) — applied from the first version.

#### §28.12.5 Per-language naming map

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `read_client_registration` | `read_client_registration` | `readClientRegistration` | `read_client_registration` | `readClientRegistration` | `readClientRegistration` | `ReadClientRegistrationAsync` | `readClientRegistration` | `ReadClientRegistration` | `readClientRegistration` | `axiam_read_client_registration` | `read_client_registration` |
| `update_client_registration` | `update_client_registration` | `updateClientRegistration` | `update_client_registration` | `updateClientRegistration` | `updateClientRegistration` | `UpdateClientRegistrationAsync` | `updateClientRegistration` | `UpdateClientRegistration` | `updateClientRegistration` | `axiam_update_client_registration` | `update_client_registration` |
| `delete_client_registration` | `delete_client_registration` | `deleteClientRegistration` | `delete_client_registration` | `deleteClientRegistration` | `deleteClientRegistration` | `DeleteClientRegistrationAsync` | `deleteClientRegistration` | `DeleteClientRegistration` | `deleteClientRegistration` | `axiam_delete_client_registration` | `delete_client_registration` |
| type `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `ClientRegistration` | `axiam_client_registration_t` | `ClientRegistration` |

Python's async client carries the same three names, as §12 established. Java
MAY add the `*Async` companions §1 permits. Kotlin, Swift, C and C++ ship these
over REST, which is the only transport they use.

#### §28.12.6 Required tests

Five per SDK, against a mocked HTTP server:

1. **Origin refusal.** A `registration_client_uri` on another host, another port,
   and `http` against an `https` base URL each raise rule 1's local error, and
   the mock records **no** request.
2. **Header only.** `read` and `delete` send `Authorization: Bearer <token>`, no
   body, no SDK session token, and nothing in the query string beyond what the
   given URI already carried (its `tenant_id`, kept verbatim).
3. **Update body.** Given a `ClientRegistration` from a read with
   `registration_access_token`, `registration_client_uri`,
   `client_secret_expires_at`, `client_id_issued_at` and `client_secret` set,
   the request body carries none of the five, carries `client_id`, and the
   returned value carries the rotated token from the mocked `200`. The mock
   answering `503` once is **not** retried.
4. **Errors.** A `401` with `{"error":"invalid_token",…}` is `OAuthProtocolError`
   with `error == "invalid_token"` and does not trigger §9 (the mock records no
   refresh); a `400` `invalid_client_metadata` likewise; a `204` on delete
   returns normally.
5. **Redaction.** Printing, debug-formatting and serializing-for-logs a
   `ClientRegistration` carrying a token, and an error raised by an operation
   given a token, contain neither the token nor any 8-character substring of it.

#### §28.12.7 Per-SDK posture

**All eleven SDKs implement §28.12**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge. Each states it by name, "§28 and §28.12" (Closing
Notes). The rows follow the code; a row naming a §34.3 divergence points at the follow-up that
closes it.

| SDK | §28.12 | Notes |
|---|---|---|
| Rust | **implemented** | `AxiamClient::{read,update,delete}_client_registration` on a session-free transport. Update body: R-23 (F-59-01) |
| TypeScript | **implemented** | On `AxiamClient`, a bare transport (no jar, no interceptors, no redirects). The token argument also takes a plain `string` (P12.5). Update body: R-23 (F-59-02) |
| Python | **implemented** | On `AxiamClient` and `AsyncAxiamClient`; token arguments also take a `str` (P12.5) |
| Java | **implemented** | With `*Async` twins, on a session-free client with OkHttp retry off. Update body: R-23 (F-59-04) |
| Kotlin | **implemented** | `suspend` functions on a sessionless transport with OkHttp retry off |
| C# | **implemented** | `*Async` methods, session-free transport |
| PHP | **implemented** | A bare Guzzle client (no cookies, no refresh middleware, no redirects). Update body: R-23 (F-59-06) |
| Go | **implemented** | Its own bare transport; the origin check runs before any I/O. Update body: R-23 (1.60 port: `updateBody` is built from what the read carried) |
| Swift | **implemented** | `async` methods on a bare path, origin-pinned, writes never retried |
| C | **implemented** | Flat `axiam_*_client_registration` over `axiam_client_send_bare` |
| C++ | **implemented** | `Client::{read,update,delete}_client_registration`. Update body: R-23; the rotated token's accessor: R-19 (F-59-11) |

## §29 SAML service provider registration (management API, contract 1.55)

**Requirement level: SHOULD, as part of §27. Additive; nothing in §1–§28 or §30 changes.**
Server design: [`design-document.md`](../claude_dev/design-document.md) §8e, *SAML 2.0
Identity Provider*; decisions D-20 … D-27 and D-37 … D-42 in the plan's decision table
([`competitor-gap-remediation-plan-2026-10-02.md`](../claude_dev/competitor-gap-remediation-plan-2026-10-02.md)
§8). Threat model: T-304 … T-330 and T-357 … T-384.

AXIAM can act as a SAML 2.0 identity provider for a tenant (competitor-gap item G-2): it
signs assertions for the service providers (SPs) a tenant administrator registered, on the
Web Browser SSO profile, and logs a user out of them again. **The protocol itself is not
SDK surface.** Single sign-on, single logout and the IdP metadata document are browser and
SP-to-IdP routes under `/saml/v2/{tenant_id}/…`; an SP's own SAML library speaks to them,
not an AXIAM SDK, and they are compiled out of `openapi.json` (OpenAPI Export Feature
Flag, below). What this section adds is the administration: the per-tenant registry of
service providers, the import of an SP's metadata into a draft registration, and the
lifecycle of the tenant's IdP signing credential, as one §27 namespace.

**Status: the routes have landed.** The server task that implements them (T23.2.5)
regenerated `openapi.json` and `management-registry.json` (the `saml` namespace, eleven
operations, every one with the operation id of §29.1's first column); this section is
normative over what it builds, and an SDK implements §29 from the merge commit of the
branch that carries both, not from a draft (§7 rule 1 of the plan; the 1.49 rule; D-35).

### §29.1 Canonical operation set

A new §27 namespace, **`saml`**, generated from the registry like every other (§27.0: the
registry is normative, this table is rendered for a reader). The OpenAPI tag is `saml`.
All eleven paths carry `{tenant_id}`, defaulted from the client's configured tenant per
§27.4 rule 3. Every route is compiled into **every** server build, with or without the
`saml` Cargo feature, so every one of them is in the exported `openapi.json` (D-42).

| Operation | HTTP | Request body | Response | `update_style` |
|---|---|---|---|---|
| `saml.get_idp` | `GET /api/v1/tenants/{tenant_id}/saml/idp` | — | `200` `SamlIdpInfo` | — |
| `saml.list_service_providers` | `GET /api/v1/tenants/{tenant_id}/saml/service-providers` | — (`offset`, `limit`, `search`) | `200` page of `SamlServiceProvider` | — |
| `saml.create_service_provider` | `POST /api/v1/tenants/{tenant_id}/saml/service-providers` | `SamlServiceProviderInput` | `201` `SamlServiceProvider` | — |
| `saml.get_service_provider` | `GET /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}` | — | `200` `SamlServiceProvider` | — |
| `saml.update_service_provider` | `PUT /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}` | `SamlServiceProviderInput` | `200` `SamlServiceProvider` | **`replace`** |
| `saml.delete_service_provider` | `DELETE /api/v1/tenants/{tenant_id}/saml/service-providers/{sp_id}` | — | `204` | — |
| `saml.parse_sp_metadata` | `POST /api/v1/tenants/{tenant_id}/saml/parse-sp-metadata` | `ParseSamlSpMetadata` | `200` `SamlSpMetadataDraft` | — |
| `saml.list_idp_credentials` | `GET /api/v1/tenants/{tenant_id}/saml/idp-credentials` | — | `200` array of `SamlIdpCredential` | — |
| `saml.issue_idp_credential` | `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials` | `IssueSamlIdpCredential` | `201` `SamlIdpCredential` | — |
| `saml.promote_idp_credential` | `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/promote` | — | `200` `SamlIdpCredentialPromotion` | — |
| `saml.retire_idp_credential` | `POST /api/v1/tenants/{tenant_id}/saml/idp-credentials/{credential_id}/retire` | — | `200` `SamlIdpCredential` | — |

Names follow §27.1. The namespace holds two resources, so the CRUD verbs carry their noun,
as `federation`'s `list_configs` … `delete_config` do; `parse_sp_metadata` says that it
parses and does not store; `issue` rather than `create` marks the operation where the server
mints key material the caller never sees (§27.1's `generate` reasoning; the key is not
returned at all), and `promote` / `retire` are the two lifecycle moves. The component names
in the table are the ones the server's export uses. `list_service_providers` is one of
§27.4 rule 4's paginated operations (the `{ items, total, offset, limit }` envelope, with
`search` matched against `display_name`, `entity_id` and the id); `list_idp_credentials`
returns a bare array, newest first, and MUST NOT be modelled as a page.

### §29.2 Shapes (normative)

Field names are the server model's (`axiam_core::models::saml_sp`), unchanged.

**`SamlServiceProvider`** — what every SP read and write returns:

| Field | Type | Notes |
|---|---|---|
| `id`, `tenant_id` | UUID | |
| `enabled` | bool | A disabled SP stays registered and every sign-on for it is refused. Logout still works. |
| `display_name` | string | 1–256 bytes, no control characters, no surrounding whitespace. |
| `entity_id` | string | The SP's `entityID`, 1–1 024 bytes, unique per tenant, **immutable** after create (§29.3 rule 3). |
| `acs_urls` | array of `AcsEndpoint` | 1–32. The allow-list an assertion may be posted to. |
| `slo_url` | string \| null | The SP's single-logout endpoint. |
| `slo_binding` | `"http_post"` \| `"http_redirect"` \| null | Set together with `slo_url`. |
| `name_id_format` | `"persistent"` \| `"email_address"` | `persistent` (the default) is a pairwise identifier per SP (D-22). |
| `sign_responses` | bool | Sign the `Response` envelope too. The assertion is signed **always**; there is no field to turn that off, and an SDK MUST NOT invent one. |
| `encrypt_assertions` | bool | Always `false` in this revision (§29.3 rule 2). |
| `sp_signing_cert_pem` | string \| null | The certificate the SP signs its requests with. Public material. |
| `sp_encryption_cert_pem` | string \| null | Stored for when encryption is implemented. Public material. |
| `want_authn_requests_signed` | bool | Refuse an unsigned `AuthnRequest` from this SP. Requires `sp_signing_cert_pem`. |
| `allow_idp_initiated` | bool | IdP-initiated sign-on is a per-SP opt-in, default `false` (D-3). |
| `attribute_mappings` | array of `AttributeMapping` | 0–64. |
| `allowed_groups` | array of UUID | 0–256 groups of the tenant. **Empty means every active user of the tenant may sign in to this SP.** |
| `created_at`, `updated_at` | RFC 3339 | |

**`AcsEndpoint`** is `{ url, binding, index, is_default }`: `url` a string, `binding` as
`slo_binding`, `index` an unsigned 16-bit integer unique within the SP, `is_default` a
bool (at most one `true`; with none, the first listed is the default). **`AttributeMapping`**
is `{ saml_name, name_format, source }`: `saml_name` the emitted attribute's `Name` (1–256
bytes, unique within the SP, case-sensitive), `name_format` one of the three SAML
`attrname-format` URNs (`unspecified`, `uri`, `basic`) or absent, `source` one of
`"username"`, `"email"`, `"display_name"`, `"given_name"`, `"family_name"`, `"groups"`,
`"roles"`.

The four string enums (`binding`, `slo_binding`, `name_id_format`, `source`) are **open**:
an SDK MUST decode a value it does not know without failing, as §27.13 asks of
`CertificateType`, and MUST NOT send one it does not know.

**`SamlServiceProviderInput`** (`create_service_provider`, and `update_service_provider` as
a **replacement**) carries every `SamlServiceProvider` field except `id`, `tenant_id`,
`created_at` and `updated_at`. Required: `display_name`, `entity_id`, `acs_urls`. The rest
are optional **and an omitted one takes its default on every write, including an update**
— §27.4 rule 5's warning, which an SDK MUST repeat at the `update_service_provider` call
site: `enabled` and `sign_responses` default to `true`; `name_id_format` to `persistent`;
`encrypt_assertions`, `want_authn_requests_signed` and `allow_idp_initiated` to `false`;
the two certificates, `slo_url` and `slo_binding` to null; `attribute_mappings` and
`allowed_groups` to empty. An SDK SHOULD offer the read-modify-write form
(`update_service_provider` from a `get_service_provider` result) §27.4 rule 5 recommends.

**`ParseSamlSpMetadata`** is `{ metadata_xml }` or `{ metadata_url }` — **exactly one**, the
first a metadata document of at most 512 KiB, the second an `https` URL. An SDK MUST make
sending both, or neither, impossible or a local `ValidationError` (two methods, a sum type,
or a builder that refuses) — not a request the server refuses.

**`SamlSpMetadataDraft`** is `{ service_provider, signing_certificate_fingerprint,
encryption_certificate_fingerprint, warnings }`: `service_provider` a
`SamlServiceProviderInput` an SDK MUST be able to pass to `create_service_provider` (or
`update_service_provider`) unchanged; the two fingerprints the lower-case hex SHA-256 of
the certificate DER the draft carries, or null; `warnings` an array of human-readable
strings (an SDK MUST NOT parse them). **A draft is not a registration**: nothing is stored
until the caller submits it, and nothing in it is trusted because it came from a document
(§29.3 rule 6).

**`SamlIdpCredential`** — the tenant's IdP signing credential, public facts only:

| Field | Type | Notes |
|---|---|---|
| `id`, `tenant_id`, `issuer_ca_id` | UUID | `issuer_ca_id` is the signing CA that issued the leaf. |
| `certificate_pem` | string | The leaf certificate. Public: it is what the metadata publishes. |
| `serial` | string | Lower-case hex. |
| `fingerprint` | string | Lower-case hex SHA-256 of the certificate DER — what an SP administrator compares out of band. |
| `not_before`, `not_after` | RFC 3339 | At most 730 days apart. |
| `status` | `"active"` \| `"next"` \| `"retired"` | Open enum. At most one `active` and one `next` per tenant. |
| `created_at` | RFC 3339 | |
| `retired_at` | RFC 3339 \| null | |

**There is no key on it, and an SDK MUST NOT give it one.** The private key is generated
by the server, sealed at rest, never returned by any route, and destroyed on retirement
(D-21); `SamlIdpCredential` has no `private_key_pem`, no ciphertext, no custody field, and
an SDK's type MUST NOT declare one (§27.5's `certificates.sign_csr` discipline: a type with
a key field that is always absent lies about every value it holds).

**`IssueSamlIdpCredential`** is `{ issuer_ca_id, slot, validity_days }`: `issuer_ca_id` an
active signing CA the caller may issue from; `slot` `"active"` or `"next"` (required);
`validity_days` an integer 1–730, optional, default 365, and never beyond the CA's own
expiry. **`SamlIdpCredentialPromotion`** is `{ active, retired }`: the credential now
`active`, and the one it replaced, now `retired`, or null when there was none.

**`SamlIdpInfo`** is `{ tenant_id, saml_available, saml_idp_enabled, metadata_served,
entity_id, metadata_url, sso_url, slo_url, active_credential_id, next_credential_id }`:
`saml_available` whether this server build serves SAML at all; `saml_idp_enabled` the
tenant's **effective** `saml_idp_enabled` setting (D-20; written through the existing
`settings` operations, not here); `metadata_served` whether `metadata_url` answers now —
available, enabled, and an `active` or `next` credential exists (D-40); the four URLs
what the IdP's metadata and endpoints are, for the tenant, computed the same way in every
build; the two ids null when the slot is empty.

### §29.3 Server rules every SDK can observe (normative)

1. **Every SP write is validated before anything is stored**, by
   `axiam_federation::saml_sp::validate_saml_service_provider` — the function the SSO
   endpoint's own checks rest on — and each refusal is `400 validation_error` whose
   `message` names the field and the rule: an empty, over-long, padded or
   control-character `display_name` or `entity_id`; no ACS endpoint, more than 32, an ACS
   URL that is not a registrable redirect URI (absolute, `https` — `http` only for
   `localhost`, `127.0.0.1` and `[::1]` — and no fragment), any `*` in it, a duplicate URL
   or `index`, more than one default; an `slo_url` held to the same URL rule, or set
   without `slo_binding` (or the reverse); a certificate that is not exactly one
   `CERTIFICATE` PEM block of at most 16 KiB that parses as X.509 — a private key is
   refused by name; `want_authn_requests_signed` without `sp_signing_cert_pem`; more than
   64 attribute mappings, a duplicate or invalid `saml_name`, an unknown `name_format`;
   more than 256 `allowed_groups`. The `message` never echoes a certificate.
2. **Four write-time refusals beyond the validator (D-42)**, each `400 validation_error`
   naming the rule: `encrypt_assertions: true` — assertion encryption is not implemented
   yet (D-2), and an SP asking for it would be refused at every sign-on, never sent a
   plaintext assertion; an `sp_signing_cert_pem` the SSO endpoint could not use — its
   decoder refuses it, or its key is RSA under 2 048 bits or anything but RSA or ECDSA on
   P-256, P-384 or P-521 (an ECDSA certificate verifies HTTP-POST requests only; the
   HTTP-Redirect binding is RSA-only, and an SDK MUST say so where it documents the
   field); an `allowed_groups` entry that is not a group of the tenant; and rule 3's
   `entity_id` change. An expired SP certificate is **not** refused (SAML trusts a
   registered key as a key, not by its validity dates).
3. **`entity_id` is unique per tenant and immutable.** A create that repeats one is
   `409 conflict`. An `update_service_provider` that changes it is `400 validation_error`
   ("register a new service provider"): the pairwise `NameID` of every user is keyed on it
   (D-22), so a change would give every user a new, unknown account at that SP. Deleting
   an SP and registering the same `entity_id` again gives its users their identifiers back.
4. **Update is a replacement** (`update_style: replace`). An SDK MUST model the body as the
   whole registration and repeat §27.4 rule 5's warning at the call site.
5. **Delete** answers `204`, removes the registration and the SP's records of which live
   sessions signed in to it (D-37), and ends no session: users already signed in to the SP
   stay signed in there until their SP session ends. A second delete is `404` (§27.4
   rule 6).
6. **`parse_sp_metadata` parses and never stores (D-41).** A `metadata_url` is fetched by
   the server only through its SSRF guard: `https` only, every address the name resolves
   to and every redirect hop checked, private, loopback, link-local and cloud-metadata
   addresses refused, the response capped. The document is refused if it contains any DTD
   or entity declaration, is not UTF-8, is over 512 KiB, or is not exactly one
   `EntityDescriptor` with one SAML 2.0 `SPSSODescriptor`. Every one of these is `400
   validation_error` with a **generic** `message` (`metadata_url refused`, `metadata fetch
   failed`, `not SAML service-provider metadata`) that never carries the fetched body, a
   status line or an address. The metadata's own signature, if it has one, is **not
   evaluated** and the draft warns so; `encrypt_assertions` is never set in a draft. In a
   server built without SAML the operation is `503 service_unavailable` (every other §29
   operation works in every build). The server never re-reads an SP's metadata on its
   own: there is no refresh, and a changed SP is re-imported by a person.
7. **Credentials (D-21, D-42).** `issue_idp_credential` generates an RSA-4096 key and a
   leaf from `issuer_ca_id` into an **empty** slot: an occupied `active` or `next` slot is
   `409 conflict`; a CA the caller may not use (another organization's, another tenant's)
   is `404 not_found`; a CA that cannot sign (revoked, expired, imported or externally
   held) and a `validity_days` out of range are `400 validation_error`. It takes seconds —
   an SDK MUST NOT apply a timeout shorter than its ordinary write timeout to it.
   `promote_idp_credential` requires that `{credential_id}` is the tenant's **current
   `next`** credential and inside its validity window (`409 conflict` otherwise) and, in
   one transaction, retires the old `active` — destroying its key — and makes `next`
   `active`. `retire_idp_credential` retires a `next` or an `active` credential and
   destroys its key; retiring the **`active`** one with no successor stops SAML sign-on
   for the whole tenant at once (it is the incident response to a leaked key), and an SDK
   MUST say so at the call site. Retiring an already retired credential returns it
   unchanged. The safe rotation is: issue into `next`, wait until every SP has refreshed
   the metadata (which publishes both), then promote.
8. **Routes are independent of the tenant's `saml_idp_enabled` setting.** An administrator
   registers SPs and issues the credential before switching the IdP on. The setting itself
   is written through §27's `settings` operations and governs only the browser routes,
   which answer `404` while it is off (D-20).
9. **Authorization.** Three new permissions, seeded per tenant like every other:
   `saml_sp:read` (`get_idp`, `list_service_providers`, `get_service_provider`,
   `list_idp_credentials`), `saml_sp:write` (`create_service_provider`,
   `update_service_provider`, `delete_service_provider`, `parse_sp_metadata`) and
   **`saml_idp:credential`** (`issue_idp_credential`, `promote_idp_credential`,
   `retire_idp_credential`) — kept apart because one call can change or stop sign-on at
   every SP of the tenant. The `{tenant_id}` in the path must be the caller's tenant;
   another tenant is `403 authorization_denied`. A service-account token is not accepted
   on this namespace in this revision (`401`, as for every human-only family, S-9 and §30;
   amended by D-43 before 1.55 shipped): registering where a tenant's signed
   assertions go is a human administrator's act.
10. **Rate limiting.** The seven writes each have a per-IP bucket of their own,
    `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN` (default 30 per minute per route): `429` per §2.
    Reads are not limited.
11. **Audit.** `saml_sp.created`, `saml_sp.updated` (the **names** of the changed fields,
    with `acs_changed` and `certificate_changed`), `saml_sp.deleted`,
    `saml_sp.metadata_parsed` (upload or URL, the URL's host only, the outcome),
    `saml_idp.credential_issued`, `saml_idp.credential_promoted` and
    `saml_idp.credential_retired` (ids, slot and fingerprint). Never a certificate's or a
    document's content.

### §29.4 Error mapping

§2 and §27.4 rule 7, unchanged: `400` is `ValidationError` (carrying the server's `message`,
which names the rule), `404` is `NotFoundError`, `409` is `ConflictError`, `403` is
`AuthzError`, `401` is `AuthError`, `429` and `503` are `NetworkError`. No new error type
and no new response member. An SDK MUST NOT parse a `message` to recover the rule — it is
for a human and its wording may change.

### §29.5 `Sensitive<T>` applicability

**Nothing in §29 is wrapped.** The registry holds no secret: SP certificates, the IdP's
certificate, fingerprints, URLs and entity ids are public material or identifiers (§27.5
rule 2: wrapping what is not secret teaches callers to ignore the wrapper). §27.5's table
gains no row and the registry's `sensitive_*_fields` stay empty for the namespace. What an
SDK owes instead is §29.2's absence rule: `SamlIdpCredential` has **no** key member, and a
decoder that meets a member named `private_key_pem` (or any other member the type does not
declare) in a response MUST drop it rather than surface it.

### §29.6 Per-language naming map

§27.3 applies unchanged; for the record:

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `saml.get_idp` | `saml().get_idp` | `saml.getIdp` | `saml.get_idp` | `saml().getIdp` | `saml.getIdp` | `Saml.GetIdpAsync` | `saml()->getIdp` | `Saml().GetIdp` | `saml.getIdp` | `axiam_saml_get_idp` | `saml().get_idp` |
| `saml.list_service_providers` | `saml().list_service_providers` | `saml.listServiceProviders` | `saml.list_service_providers` | `saml().listServiceProviders` | `saml.listServiceProviders` | `Saml.ListServiceProvidersAsync` | `saml()->listServiceProviders` | `Saml().ListServiceProviders` | `saml.listServiceProviders` | `axiam_saml_list_service_providers` | `saml().list_service_providers` |
| `saml.create_service_provider` | `saml().create_service_provider` | `saml.createServiceProvider` | `saml.create_service_provider` | `saml().createServiceProvider` | `saml.createServiceProvider` | `Saml.CreateServiceProviderAsync` | `saml()->createServiceProvider` | `Saml().CreateServiceProvider` | `saml.createServiceProvider` | `axiam_saml_create_service_provider` | `saml().create_service_provider` |
| `saml.get_service_provider` | `saml().get_service_provider` | `saml.getServiceProvider` | `saml.get_service_provider` | `saml().getServiceProvider` | `saml.getServiceProvider` | `Saml.GetServiceProviderAsync` | `saml()->getServiceProvider` | `Saml().GetServiceProvider` | `saml.getServiceProvider` | `axiam_saml_get_service_provider` | `saml().get_service_provider` |
| `saml.update_service_provider` | `saml().update_service_provider` | `saml.updateServiceProvider` | `saml.update_service_provider` | `saml().updateServiceProvider` | `saml.updateServiceProvider` | `Saml.UpdateServiceProviderAsync` | `saml()->updateServiceProvider` | `Saml().UpdateServiceProvider` | `saml.updateServiceProvider` | `axiam_saml_update_service_provider` | `saml().update_service_provider` |
| `saml.delete_service_provider` | `saml().delete_service_provider` | `saml.deleteServiceProvider` | `saml.delete_service_provider` | `saml().deleteServiceProvider` | `saml.deleteServiceProvider` | `Saml.DeleteServiceProviderAsync` | `saml()->deleteServiceProvider` | `Saml().DeleteServiceProvider` | `saml.deleteServiceProvider` | `axiam_saml_delete_service_provider` | `saml().delete_service_provider` |
| `saml.parse_sp_metadata` | `saml().parse_sp_metadata` | `saml.parseSpMetadata` | `saml.parse_sp_metadata` | `saml().parseSpMetadata` | `saml.parseSpMetadata` | `Saml.ParseSpMetadataAsync` | `saml()->parseSpMetadata` | `Saml().ParseSpMetadata` | `saml.parseSpMetadata` | `axiam_saml_parse_sp_metadata` | `saml().parse_sp_metadata` |
| `saml.list_idp_credentials` | `saml().list_idp_credentials` | `saml.listIdpCredentials` | `saml.list_idp_credentials` | `saml().listIdpCredentials` | `saml.listIdpCredentials` | `Saml.ListIdpCredentialsAsync` | `saml()->listIdpCredentials` | `Saml().ListIdpCredentials` | `saml.listIdpCredentials` | `axiam_saml_list_idp_credentials` | `saml().list_idp_credentials` |
| `saml.issue_idp_credential` | `saml().issue_idp_credential` | `saml.issueIdpCredential` | `saml.issue_idp_credential` | `saml().issueIdpCredential` | `saml.issueIdpCredential` | `Saml.IssueIdpCredentialAsync` | `saml()->issueIdpCredential` | `Saml().IssueIdpCredential` | `saml.issueIdpCredential` | `axiam_saml_issue_idp_credential` | `saml().issue_idp_credential` |
| `saml.promote_idp_credential` | `saml().promote_idp_credential` | `saml.promoteIdpCredential` | `saml.promote_idp_credential` | `saml().promoteIdpCredential` | `saml.promoteIdpCredential` | `Saml.PromoteIdpCredentialAsync` | `saml()->promoteIdpCredential` | `Saml().PromoteIdpCredential` | `saml.promoteIdpCredential` | `axiam_saml_promote_idp_credential` | `saml().promote_idp_credential` |
| `saml.retire_idp_credential` | `saml().retire_idp_credential` | `saml.retireIdpCredential` | `saml.retire_idp_credential` | `saml().retireIdpCredential` | `saml.retireIdpCredential` | `Saml.RetireIdpCredentialAsync` | `saml()->retireIdpCredential` | `Saml().RetireIdpCredential` | `saml.retireIdpCredential` | `axiam_saml_retire_idp_credential` | `saml().retire_idp_credential` |

All eleven perform I/O, so §27.3's async discipline applies to each.

### §29.7 Retry

§27.4 rule 8 governs and is not widened: the four `GET`s MAY be retried per §16; the seven
writes MUST NOT be, on any status or transport error. The reasons are concrete here:
`issue_idp_credential` repeated after a lost response is a `409` that reads like a failure
while the credential exists; `promote_idp_credential` repeated is a `409` because the
first call already promoted; `create_service_provider` repeated is a `409` on the
`entity_id`. A caller who lost an answer reads the state (`list_idp_credentials`,
`get_service_provider`) instead.

### §29.8 Required tests

Eight per SDK that ships the namespace, against a mocked HTTP server:

1. **Replacement.** `update_service_provider` sends `PUT` with a body carrying every
   `SamlServiceProviderInput` member; the SDK's input type cannot be built without
   `display_name`, `entity_id` and `acs_urls` (or its builder refuses, in a language
   without the compile-time check) — a rule about building a body for submission, not about
   decoding one a response nests (contract 1.60, [§34.2](#§342-clarifications-normative-from-159)
   P12.9); a `200` decodes to `SamlServiceProvider`.
2. **No signing switch, open decoding.** The input and response types have no
   `sign_assertions` member; decoding a `SamlServiceProvider` that carries
   `"sign_assertions": false`, an unknown member and an unknown `binding` value succeeds,
   and re-encoding the decoded value for `update_service_provider` sends no
   `sign_assertions`.
3. **Draft round trip.** `parse_sp_metadata` sends exactly `{"metadata_url": "…"}` or
   exactly `{"metadata_xml": "…"}`; sending both or neither is impossible or raises a local
   `ValidationError` with **no** request recorded; the `service_provider` of a mocked draft
   is accepted by `create_service_provider` unchanged and sent as its body.
4. **Credentials carry no key.** A `SamlIdpCredential` body that (wrongly) carries
   `"private_key_pem": "<value>"` decodes to a value whose every stringification lacks the
   value, and the type has no accessor for it; a `SamlIdpCredentialPromotion` with
   `"retired": null` decodes.
5. **Pagination.** `list_service_providers` returns the SDK's `Page<T>` with `total`; the
   auto-paging form carries the same `search` on every request it issues;
   `list_idp_credentials` returns a plain list, not a page.
6. **No retry.** The mock answers `503` once to each of the seven writes: exactly one
   request each, and the error is `NetworkError`.
7. **Errors.** A `400 validation_error` is `ValidationError` carrying the `message`; a `409
   conflict` on `create_service_provider` and on `promote_idp_credential` is
   `ConflictError`; a `404 not_found` on `get_service_provider` is `NotFoundError`; a `503`
   on `parse_sp_metadata` is `NetworkError`.
8. **Readiness is read, not cached.** A mocked `get_idp` body carrying all ten members of
   `SamlIdpInfo`, with `active_credential_id` present and `next_credential_id` null,
   decodes with the null kept distinct from an absent member; two successive calls issue
   two requests (§29.9); and, with the client's tenant configured, the call is made without
   a `tenant_id` argument and the mock sees the configured tenant in the path (§27.4
   rule 3).

The server task adds its own tests for every rule in §29.3; they are not an SDK's to
duplicate.

### §29.9 What an SDK does not do

It does not run the browser flow: no helper builds an `AuthnRequest`, consumes an
assertion, starts a logout or fetches `/saml/v2/{tenant_id}/metadata` — an SP's SAML
library does that, and the routes are not in `openapi.json`. It does not parse SP metadata
locally (the server's parser and its DTD refusal are the authority, and a client copy
would drift) and does not validate a registration beyond §27.4's UUID rule. It offers no
way to read the IdP's private key, because none exists. It does not cache
`get_idp` — the readiness it reports changes with every credential write (§27.4 rule 10).

### §29.10 Per-SDK posture

**All eleven SDKs implement §29**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge, and state "§27 and §29". The rows follow the code.

| SDK | §29 | Notes |
|---|---|---|
| Rust | **implemented** | Generated `saml()`; the exactly-one check of `parse_sp_metadata` is local |
| TypeScript | **implemented** | `client.saml`; undeclared response members dropped by a denylist: R-20 (F-59-02) |
| Python | **implemented** | `client.saml` on both clients |
| Java | **implemented** | `saml()`; writes and the transport re-send: R-17; unknown enum values re-sent: R-22 (F-59-04). 1.60 port: `SamlSpMetadataDraft.service_provider` decodes without the required-member check and `create_service_provider` refuses it on submit (R-27, P12.9) |
| Kotlin | **implemented** | `client.saml`; required members are non-null constructor parameters. Transport re-send: R-17 (F-59-08). 1.60 port: an unknown value is refused with `ValidationError`, not `NetworkError` (P12.2) |
| C# | **implemented** | Generated `SamlApi` with `ParseSpMetadataExactlyOne` and a read-modify-write `ToInput`. 1.60 port: writes go on a connection that is not reused (P11, R-17) |
| PHP | **implemented** | Generated `SamlApi`, list as `listItems` (P12.8) |
| Go | **implemented** | `client.SAML()` (P12.8); no key member on `SAMLIdpCredential` |
| Swift | **implemented** | `client.saml`; no auto-pager: R-30 (F-59-09). 1.60 port: every open enum refuses `.unknown` on encode (R-22) |
| C | **implemented** | Flat `axiam_saml_*`; no auto-pager: R-30 (F-59-10). 1.60 port: `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on writes (P11, R-17) |
| C++ | **implemented** | `SamlApi`, no key member (`static_assert`); required members not enforced: R-27 (F-59-11). 1.60 port: an unknown value is refused with `std::invalid_argument`, not `NetworkError` (P12.2); `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on writes (P11, R-17) |

**All eleven SDKs are in scope, and the transport does not split them.** §29 is management
REST (§27), so Kotlin, Swift, C and C++ — which carry the REST surface only (§1–§7,
§9–§11) — implement it exactly as the seven full-surface SDKs do: §27.10 records that all
eleven implement the imperative management surface, and there is no gRPC or AMQP form of
any §29 operation. No SDK runs the browser flow (§29.9). §27.6's manifest has no `saml`
kind in this revision, so no SDK's declarative layer is touched by §29.

## §30 Directory configuration (management API, contract 1.54)

**Requirement level: SHOULD, as part of §27. Additive; nothing in §1–§28 changes.**
(§29, the SAML service-provider registration of competitor-gap item G-2, was reserved
when this section was written and arrived in contract 1.55; the numbers did not trade
places.) Server
documentation: [`docs/deployment/README.md`](../docs/deployment/README.md), *What a
tenant's directory needs*. Threat model: T-291 … T-303, T-331 … T-355; the F4 review's
P23W2-01 and P23W2-09/-10 (`claude_dev/security-review-phase23-w2-2026-10-03.md`).

A tenant can sign its people in through its own LDAP or Active Directory server (item
G-3): the directory checks the password, a first sign-in may create the account just in
time, and directory groups are mapped onto AXIAM groups. **Signing in needs nothing new
from an SDK** — a directory account calls the same §1 `login`. What this section adds is
the administration: one directory configuration per tenant, read and written as a §27
namespace, the explicit act that links an existing local account to its directory entry,
and a read-only view of the background sync job.

**Status: the routes now follow the text.** The server routes, their OpenAPI operations and
their `management-registry.json` entries landed with the server task that followed this
contract revision (T23.3.8), which regenerated both files; this section pins what that task
implemented and what every SDK then ships. An SDK implements §30 against the regenerated
`openapi.json` and `management-registry.json` from that merge commit, and none had yet when
it landed (§30.10).

### §30.1 Canonical operation set

A new §27 namespace, **`directory`**, generated from the registry like every other
(§27.0: the registry is normative, this table is rendered for a reader). All six paths
carry `{tenant_id}`, defaulted from the client's configured tenant per §27.4 rule 3.

| Operation | HTTP | Request body | Response | `update_style` |
|---|---|---|---|---|
| `directory.get` | `GET /api/v1/tenants/{tenant_id}/directory` | — | `200` `DirectoryConfig` | — |
| `directory.set` | `PUT /api/v1/tenants/{tenant_id}/directory` | `SetDirectoryConfig` | `201` (created) or `200` (replaced) `DirectoryConfig` | **`replace`** |
| `directory.update` | `PATCH /api/v1/tenants/{tenant_id}/directory` | `UpdateDirectoryConfig` | `200` `DirectoryConfig` | **`sparse`** |
| `directory.delete` | `DELETE /api/v1/tenants/{tenant_id}/directory` | — | `204` | — |
| `directory.link_account` | `POST /api/v1/tenants/{tenant_id}/directory/links` | `LinkDirectoryAccount` | `200` `DirectoryLinkResult` | — |
| `directory.get_sync_status` | `GET /api/v1/tenants/{tenant_id}/directory/sync-status` | — | `200` `DirectorySyncStatus` | — |

Names follow §27.1: `get`/`set`/`update`/`delete` as `email_config` and `webauthn_policy`
use them for a per-tenant singleton, `link_account` and `get_sync_status` saying what they
do. The OpenAPI tag is `directory`; the component names in the table are the ones the
server's export uses, so the registry's `sensitive_request_fields` can name them.

### §30.2 Shapes (normative)

**`DirectoryConfig`** — what every read and write returns. Field names are the server
model's (`axiam_core::models::directory::DirectoryConfig`), unchanged:

| Field | Type | Notes |
|---|---|---|
| `id`, `tenant_id` | UUID | |
| `enabled` | bool | A disabled directory serves no sign-in and is not synced. |
| `kind` | `"open_ldap"` \| `"active_directory"` | Chooses defaults only. An SDK MUST decode an unknown value without failing (an open enum, as §27.13 asks of `CertificateType`). |
| `url` | string | `ldaps://host[:port]`, or `ldap://host[:port]` with `start_tls`. |
| `start_tls` | bool | |
| `bind_dn` | string | The service account the search runs as. |
| `base_dn` | string | Where users are searched for. |
| `user_filter` | string | One `{username}` placeholder in value position, e.g. `(&(objectClass=person)(uid={username}))`. |
| `user_attribute_map` | object | `{ username, email, display_name, external_id }` — attribute names. |
| `group_base_dn` | string \| null | |
| `group_filter` | string \| null | |
| `group_member_attribute` | string | |
| `group_nesting_depth` | integer 0–10 | |
| `group_mappings` | array of `{ directory_group_dn, group_id }` | At most 500; every `group_id` a group of the same tenant (D-30). |
| `sync_interval_secs` | integer 300–86 400 | |
| `jit_provisioning` | bool | |
| `trust_anchors_pem` | array of PEM strings | At most 16 CA certificates; empty means the public roots. |
| `created_at`, `updated_at` | RFC 3339 | |

**There is no secret on it, and an SDK MUST NOT give it one.** `DirectoryConfig` has no
`bind_secret` member, no `bind_secret_set` flag and no hash or prefix of the secret; the
server never returns it (D-15). An SDK's response type MUST NOT declare such a member, and
a decoder that meets one in a response MUST drop it rather than surface it — the response
object is the one most often logged.

**`SetDirectoryConfig`** (`directory.set`, a replacement) carries every `DirectoryConfig`
field except `id`, `tenant_id`, `created_at` and `updated_at`, plus **`bind_secret`**.
Required: `enabled`, `kind`, `url`, `start_tls`, `bind_dn`, `base_dn`, `user_filter`.
The rest are optional **and a replacement resets an omitted one to its default** —
§27.4 rule 5's warning, which an SDK MUST repeat at the call site: `user_attribute_map`
and `group_member_attribute` default by `kind`, `group_base_dn` and `group_filter` to
null, `group_nesting_depth` to 5, `group_mappings` and `trust_anchors_pem` to empty,
`sync_interval_secs` to 3 600, `jit_provisioning` to false. `bind_secret` is required
when the tenant has no configuration yet; on a replacement, absent means *keep the stored
secret*, subject to §30.3 rule 2.

**`UpdateDirectoryConfig`** (`directory.update`) carries the same members, every one
optional: absent leaves the stored value, and for the two nullable members (`group_base_dn`,
`group_filter`) an explicit `null` clears it (§27.4 rule 5, "null is not absent").
`bind_secret` absent keeps the stored secret, subject to §30.3 rule 2.

**`bind_secret`** is a string of 1 to 4 096 octets, **write-only**: it appears in these
two request types and nowhere else in the contract.

**`LinkDirectoryAccount`** is `{ "user_id": UUID }`. **`DirectoryLinkResult`** is
`{ user_id, directory_external_id, webauthn_credentials_deleted, certificates_revoked,
was_already_linked }` — two counts and a flag that is `true` when the account was already
linked to that very entry and the call only re-ran the revocations (an interrupted link
completed). `directory_external_id` is the entry's `entryUUID` or `objectGUID` as text: an
identifier, not a secret.

**`DirectorySyncStatus`** is `{ last_result, last_attempt_at, last_full_run_at,
full_required, has_watermark }`: `last_result` one of `"ok"`, `"partial"`, `"failed"`,
`"safety_valve"` (an open enum, decoded without failing on another value) or null before
the first run; the two instants RFC 3339 or null; `full_required` true when the next run
must be a full reconciliation; `has_watermark` whether an incremental run has a starting
point. Counts of what a run did are in its audit rows (`directory.sync_run`,
`directory.sync_safety_valve`), not here, and no account id is.

### §30.3 Server rules every SDK can observe (normative)

1. **Every write is validated before anything is stored**, by the same function the bind
   path trusts (`axiam_directory::config::validate`) and by the address guard
   (`axiam_directory::address`, T-300): a plaintext URL (`ldap://` without `start_tls`,
   `ldaps://` with it, any other scheme), userinfo, a path or query, a user filter without
   exactly one `{username}` in value position, an empty or over-long `bind_secret`, a trust
   anchor that is not a CA certificate, a group mapping that is malformed, duplicated,
   over the 500 cap or names a group outside the tenant, a nesting depth or sync interval
   out of range, an **IPv6-literal host** (it can never be certificate-checked), a host that
   does not resolve, and a host that resolves to any address the deployment refuses
   (loopback, link-local and the cloud metadata service, unspecified, multicast,
   special-purpose, AXIAM's own listener, or a private address outside the operator's
   allowed networks) are each `400 validation_error`, whose `message` names the field and
   the rule — and never echoes the secret. **For a host name**, every refusal that depends
   on what the name resolved to (it does not resolve, too many addresses, or any refused
   address) is **one** `message` and one audit rule, `address_guard.not_permitted`, so the
   answer cannot tell a name that does not resolve from one that resolves into a refused
   range (W3 F4 P23W3-04, T-356); an IP literal's answer names its class. The guard runs on `url` as written, so a write
   that does not change `url` still re-checks it: a name re-pointed since the last save is
   caught on the next one. **One exception (D-33):** the address guard — not `validate` —
   is skipped for a write whose resulting configuration is **disabled** (`enabled: false`),
   since a disabled directory opens no connection; re-enabling runs it again. So a
   directory whose name now resolves to a refused address can still be switched off with
   `update {enabled: false}`, not only deleted.
2. **Moving the connection requires the secret again (P23W2-01).** A `set` or `update`
   that changes **`url`, `start_tls`, `bind_dn` or `trust_anchors_pem`** without a
   `bind_secret` is `400 validation_error` ("…requires entering the bind secret again…")
   and changes nothing. With the secret, the same change is an ordinary write. The reason
   is disclosure by redirection: a kept secret sent to a new host, through a trust anchor
   the editor chose, is the secret handed to whoever runs that host. The comparison is made
   against the stored row in the same statement as the write, so a concurrent change that
   moved the connection between a caller's read and its write is refused the same way. An
   SDK MUST document the rule at both call sites and MUST NOT attempt to work around it
   (for instance by re-sending a secret it cached — it holds none, §30.5).
3. **A directory and `opaque_mode = required` never coexist.** Under `required`, the
   tenant refuses `/auth/login` before reading a password, so directory accounts could not
   sign in at all. A `set` or `update` that would leave the tenant with an **enabled**
   directory while its effective `opaque_mode` is `required` is `409 conflict`, and so —
   on the existing §27 `settings` operations (`set_effective`, `set_tenant_override`, and
   `set_org` for the organization's tenants that inherit it) — is a write that would make
   `opaque_mode` `required` for a tenant with an enabled directory. A disabled
   configuration may coexist; enabling it is then the refused write.
4. **The deployment may not have the feature.** Without the deployment's
   `directory_encryption_key`, a write that carries a `bind_secret` — every create, every
   connection move — is `503 service_unavailable`, naming the key in the operator's log
   only; reads, `delete` and `get_sync_status` still answer. An SDK maps the `503` per §2
   (`NetworkError`) and MUST NOT retry it (rule 8 of §27.4 already forbids retrying a
   write).
5. **`delete` and disabling stop the directory, and only that.** Deleting the
   configuration removes it and its sync state; setting `enabled: false` keeps it. Either
   way directory accounts can no longer sign in with a password — there is no fallback to a
   local hash (T-303) — and the sync job stops for the tenant, so a later disable in the
   directory no longer reaches AXIAM. Sessions, refresh tokens and passkeys those accounts
   already hold keep working until they expire or an administrator deactivates the
   accounts; the audit row records how many live directory accounts the tenant had. There
   is no unlink: an account linked to a directory stays a directory account. An SDK MUST
   say so at the `delete` call site.
6. **Linking is explicit, resolved by the directory, and revokes.** `link_account` (D-28)
   finds the account's entry by the account's **own username** through the tenant's
   directory — the caller supplies only `user_id` — marks the account, deletes its WebAuthn
   credentials and its federation links, revokes its `User`-type certificates (by the D-29
   convention) and then all its sessions and OAuth2 refresh tokens; TOTP is kept. Answers:
   `404 not_found` for an unknown `user_id` or when the directory has no single entry for
   that username; `409 conflict` when the tenant has no enabled directory, the entry is
   already linked to another account, or the account is linked to a different entry; `400
   validation_error` for a deleted account; `503 service_unavailable` when the directory
   cannot be asked. A call on an account already linked to that entry is `200` with
   `was_already_linked: true` and repeats the revocations — the way an interrupted link is
   completed. The owner of the account is signed out everywhere by a successful link; an SDK
   MUST say so at the call site.
7. **No safety-valve override in this revision.** A full sync run that would deactivate
   more than 10 % of the tenant's directory accounts (and at least 5) applies nothing and
   reports `last_result: "safety_valve"` (D-31). This contract deliberately offers no
   operation that forces such a run through. An override is the one write here that
   *takes access away from many people at once*, on the word of the same role that can
   change `base_dn` and the filters that caused the mass "vanishing"; a safe one has to be
   bound to the exact candidate set of one run (which the state row does not keep), expire,
   and arguably need a second approver. The remedies exist without it: fix the
   configuration, or deactivate the accounts that really left by hand, which brings the
   next run under the valve. A later revision may add it, by name.
8. **Authorization.** Three new permissions, seeded per tenant like every other:
   `directory:read` (`get`, `get_sync_status`), `directory:write` (`set`, `update`,
   `delete`) and **`directory:link`** (`link_account`) — kept apart from `directory:write`
   because linking acts on an account rather than on the configuration (T-337). The
   `{tenant_id}` in the path must be the caller's tenant, as for `email_config`: another
   tenant is `403 authorization_denied`. A service-account token is not accepted on this
   namespace in this revision (the registry's `service_account` flag is false for all
   six): the bind secret is a human administrator's to enter.
9. **Rate limiting.** The four writes share a per-IP bucket of their own,
   `AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN` (default 30 per minute, per route as every
   bucket is keyed), because each one resolves a host name and `link_account` opens
   directory connections: `429` per §2. Reads are not in it.
10. **Audit.** `directory.config_created`, `directory.config_updated` and
    `directory.config_deleted` record the actor, the tenant and the **names** of the fields
    that changed, with `connection_moved` (true when `url`, `start_tls`, `bind_dn` or
    `trust_anchors_pem` changed) and `secret_replaced` flags; never the secret, never a
    trust anchor's content. A refused write that names a P23W2-01 or address-guard rule is
    audited too, with the rule. `link_account` writes the existing
    `directory.account_linked` row (identifiers and counts only).

### §30.4 Error mapping

§2 and §27.4 rule 7, unchanged: `400` is `ValidationError` (carrying the server's
`message`, which names the rule), `404` is `NotFoundError`, `409` is `ConflictError`, `403`
is `AuthzError`, `401` is `AuthError`, `429` and `503` are `NetworkError`. No new error
type, and no new response member: an SDK MUST NOT parse the `message` to recover the rule
— it is for a human, and its wording may change.

### §30.5 `Sensitive<T>` applicability

**`bind_secret` MUST be `Sensitive<T>`** ([§7](#§7-sensitivet-requirement)) wherever it
appears — `SetDirectoryConfig.bind_secret` and `UpdateDirectoryConfig.bind_secret`, the only
two places — from the first version an SDK ships, the #480 lesson (§27.5, contract 1.50)
applied before the fact. It is the credential of the customer's directory service account,
which can read every user and group in the corporate directory: more than an AXIAM tenant
administrator is necessarily entitled to, which is why the server never returns it. §7
rule 1's redaction covers it in every stringification sink; §27.4 rule 11 keeps it out of
§19 telemetry payloads; an error raised by `set` or `update` MUST NOT include it, a prefix
or a hash of it. An SDK MUST NOT cache it, persist it, or keep it after the request that
carried it has been sent. Nothing else in §30 is wrapped (§27.5 rule 2): `bind_dn`, the
URL, the trust anchors and `directory_external_id` are configuration and identifiers. When
the registry gains the namespace, `sensitive_request_fields` names
`(SetDirectoryConfig, bind_secret)` and `(UpdateDirectoryConfig, bind_secret)`, so the
generated surface wraps both from its first build, and §27.5's table gains the two rows.

### §30.6 Per-language naming map

§27.3 applies unchanged; for the record:

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `directory.get` | `directory().get` | `directory.get` | `directory.get` | `directory().get` | `directory.get` | `Directory.GetAsync` | `directory()->get` | `Directory().Get` | `directory.get` | `axiam_directory_get` | `directory().get` |
| `directory.set` | `directory().set` | `directory.set` | `directory.set` | `directory().set` | `directory.set` | `Directory.SetAsync` | `directory()->set` | `Directory().Set` | `directory.set` | `axiam_directory_set` | `directory().set` |
| `directory.update` | `directory().update` | `directory.update` | `directory.update` | `directory().update` | `directory.update` | `Directory.UpdateAsync` | `directory()->update` | `Directory().Update` | `directory.update` | `axiam_directory_update` | `directory().update` |
| `directory.delete` | `directory().delete` | `directory.delete` | `directory.delete` | `directory().delete` | `directory.delete` | `Directory.DeleteAsync` | `directory()->delete` | `Directory().Delete` | `directory.delete` | `axiam_directory_delete` | `directory().delete` |
| `directory.link_account` | `directory().link_account` | `directory.linkAccount` | `directory.link_account` | `directory().linkAccount` | `directory.linkAccount` | `Directory.LinkAccountAsync` | `directory()->linkAccount` | `Directory().LinkAccount` | `directory.linkAccount` | `axiam_directory_link_account` | `directory().link_account` |
| `directory.get_sync_status` | `directory().get_sync_status` | `directory.getSyncStatus` | `directory.get_sync_status` | `directory().getSyncStatus` | `directory.getSyncStatus` | `Directory.GetSyncStatusAsync` | `directory()->getSyncStatus` | `Directory().GetSyncStatus` | `directory.getSyncStatus` | `axiam_directory_get_sync_status` | `directory().get_sync_status` |

All six perform I/O, so §27.3's async discipline applies to each.

### §30.7 Retry

§27.4 rule 8 governs and is not widened: `get` and `get_sync_status` MAY be retried per §16;
`set`, `update`, `delete` and `link_account` MUST NOT be, on any status or transport error.
For `link_account` the reason is not that a repeat is harmful — it is idempotent by design —
but that it is a deliberate administrator act whose second run signs the owner out again,
and a caller who lost the answer can read the account rather than repeat it.

### §30.8 Required tests

Six per SDK that ships the namespace, against a mocked HTTP server:

1. **Redaction.** A `SetDirectoryConfig` and an `UpdateDirectoryConfig` carrying a
   `bind_secret`, and an error raised by `set` given one, printed, debug-formatted and
   serialized for logs contain neither the secret nor any 8-character substring of it.
2. **No secret on the response.** Decoding a `DirectoryConfig` body that (wrongly)
   carries `"bind_secret": "<value>"` yields a value whose every stringification lacks
   the value, and the type has no accessor for it.
3. **Sparse update.** `update` with only `enabled = false` sends exactly
   `{"enabled":false}`; with `url` and `bind_secret` it sends exactly those two keys; with
   `group_filter` explicitly null it sends `{"group_filter":null}` (§27.4 rule 5's
   exact-key-set test, applied here).
4. **Replacement.** `set` sends every required member; the SDK's replacement type
   cannot be built without them (or its builder refuses, in a language without the
   compile-time check); a `201` and a `200` both decode to `DirectoryConfig`.
5. **No retry.** The mock answers `503` once to each of `set`, `update`, `delete` and
   `link_account`: exactly one request each, and the error is `NetworkError`.
6. **Errors.** A `400 validation_error` is `ValidationError` carrying the `message`; a
   `409 conflict` is `ConflictError`; a `404 not_found` on `get` is `NotFoundError`;
   `link_account` sends `{"user_id": "<uuid>"}` and nothing else, and decodes all five
   members of `DirectoryLinkResult`.

The server task adds its own tests for every rule in §30.3; they are not an SDK's to
duplicate.

### §30.9 What an SDK does not do

It does not validate a configuration locally beyond §27.4's UUID rule — the server's
`validate` and address guard are the authority, and a client-side copy would drift from
them (the same reason §27.4 rule 4 forbids re-implementing the `search` cap). It does not
offer a "test connection" helper: no such route exists, and a client cannot reach a
directory on the server's network anyway. It does not model sign-in for directory
accounts: §1 `login` is unchanged.

### §30.10 Per-SDK posture

**All eleven SDKs implement §30**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge, and state "§27 and §30". All eleven are in scope: it is
management REST, which Kotlin, Swift, C and C++ carry.

| SDK | §30 | Notes |
|---|---|---|
| Rust | **implemented** | `bind_secret` `Sensitive`; `Option<Option<_>>` carries an explicit `null` on `update` |
| TypeScript | **implemented** | `bind_secret` `Sensitive`, but a failed write's error carries the body: R-18 (F-59-02) |
| Python | **implemented** | `bind_secret` a `SecretStr`; an assigned `None` is sent as `null`: R-25 (F-59-03) |
| Java | **implemented** | Transport re-send: R-17 (F-59-04) |
| Kotlin | **implemented** | `JsonNullable` for an explicit `null`; transport re-send: R-17 (F-59-08) |
| C# | **implemented** | `Sensitive<string>?`; `JsonNullable<T>` for an explicit `null` |
| PHP | **implemented** | `?Sensitive`; `JsonNull::Null` for an explicit `null` |
| Go | **implemented** | `*Sensitive`; a sparse update cannot send an empty list: R-26 (F-59-07) |
| Swift | **implemented** | `bindSecret` `Sensitive` on both request types; reflection: R-19 (F-59-09) |
| C | **implemented** | `axiam_sensitive_t *`; rendered bodies freed unscrubbed: R-19 (F-59-10) |
| C++ | **implemented** | `optional<Sensitive>`, tri-state PATCH body, `delete_` (P12.8) |

## §31 Outbound SCIM targets (management API, contract 1.57)

**Requirement level: SHOULD, as part of §27 (a namespace `scim_targets`), in all eleven SDKs.
Additive; nothing in §1–§30 or §32 changes.** Server design: plan item G-6 and decisions D-57 and
D-58 in the plan's decision table
([`competitor-gap-remediation-plan-2026-10-02.md`](../claude_dev/competitor-gap-remediation-plan-2026-10-02.md)
§8). Threat model: the G-6 entries, T-407 onward. (§31 was reserved for this section when §32
was written, D-44; the numbers did not trade places.) Operator documentation: the website's
*Integrate* page **Outbound SCIM provisioning**.

AXIAM can act as a **SCIM 2.0 client** (RFC 7643, RFC 7644) for a tenant (competitor-gap item
G-6): a tenant administrator registers **targets** — downstream SCIM service providers — and
AXIAM pushes the tenant's user and group lifecycle changes to them. **Nothing is needed from an
SDK to make that happen**; what this section adds is the administration: the registry of
targets, read and written as a §27 namespace, with each target's delivery state, and the
explicit *reconcile now* act. It is plain management CRUD, in the shape of §30 and §32.1–§32.5,
and an SDK never *speaks SCIM to a target*: AXIAM does.

**Status: the routes follow the text.** The server routes, their OpenAPI operations and their
`management-registry.json` entries landed with the server task that wrote this revision
(T23.6.4), which regenerated both files (190 operations across 28 namespaces). An SDK implements
§31 from that merge commit (§7 rule 1 of the plan; the 1.49 rule), in the post-merge fan-out
(D-35); none had when it landed (§31.10).

### §31.1 Canonical operation set

A new §27 namespace, **`scim_targets`**, OpenAPI tag `scim-targets`. The tenant is the
**token's**, as for `webhooks`: no path carries `{tenant_id}`, and a target of another tenant is
`404`, exactly as one that does not exist.

| Operation | HTTP | Request body | Response | `update_style` |
|---|---|---|---|---|
| `scim_targets.list` | `GET /api/v1/scim-targets` | — (`offset`, `limit`, `search`) | `200` page of `ScimTargetResponse` | — |
| `scim_targets.create` | `POST /api/v1/scim-targets` | `ScimTargetInput` | `201` `ScimTargetResponse` | — |
| `scim_targets.get` | `GET /api/v1/scim-targets/{id}` | — | `200` `ScimTargetResponse` | — |
| `scim_targets.update` | `PUT /api/v1/scim-targets/{id}` | `ScimTargetInput` | `200` `ScimTargetResponse` | **`replace`** |
| `scim_targets.delete` | `DELETE /api/v1/scim-targets/{id}` | — | `204` | — |
| `scim_targets.reconcile` | `POST /api/v1/scim-targets/{id}/reconcile` | — | `202` `ScimReconcileAccepted` | — |

`list` is one of §27.4 rule 4's paginated operations (`{ items, total, offset, limit }`, `search`
matched against `name`, `base_url` and the id, before paging). `update` is a **replacement**
(§27.4 rule 5): a member left out takes its default, **except the credential**, which absent
keeps (§31.3 rule 2).

### §31.2 Shapes (normative)

**`ScimTargetResponse`** — what every read and write returns. Field names are the server's:

| Field | Type | Notes |
|---|---|---|
| `id`, `tenant_id` | UUID | |
| `name` | string | |
| `base_url` | string | The downstream's SCIM service root, e.g. `https://idp.example/scim/v2`. |
| `enabled` | bool | A disabled target receives nothing. |
| `auth` | `ScimTargetAuth` | How AXIAM authenticates to the downstream — **no credential** (below). |
| `scope` | `ScimTargetScope` | Which users the target provisions. |
| `push_groups` | bool | Whether groups are pushed too: every group for `all_users`, the listed ones for `groups`. |
| `user_name_from` | `"username"` \| `"email"` | Which AXIAM attribute becomes the downstream `userName`. An open enum. |
| `deprovision` | `"deactivate"` \| `"delete"` | What happens downstream to a user who leaves scope or is no longer active: `PATCH active=false`, or `DELETE`. An erasure always deletes. An open enum. |
| `created_at`, `updated_at` | RFC 3339 | `updated_at` is the version an `update` is conditional on (§31.3 rule 4). |
| `state` | `ScimTargetDeliveryState` \| null | The delivery state; null only if the row cannot be read. |

**`ScimTargetAuth`** is a tagged object on `type`: `{ "type": "bearer" }`, or
`{ "type": "oauth2_client_credentials", "token_url": string, "client_id": string, "scope":
string \| null }`. An SDK MUST decode an unknown `type` without failing (§27.13's rule for open
enums) and MUST NOT give any variant a member for the credential. **`ScimTargetScope`** is a
tagged object on `type`: `{ "type": "all_users" }`, or `{ "type": "groups", "group_ids":
[UUID] }` — users who are **direct members** of any listed group.

**`ScimTargetDeliveryState`** — what the deliverer and the reconciliation job record, and the
only place a failure is visible to an administrator:

| Field | Type | Notes |
|---|---|---|
| `last_success_at` | RFC 3339 \| null | When a delivery last succeeded. |
| `last_failure_at` | RFC 3339 \| null | When an attempt last failed or was dead-lettered. |
| `last_failure_reason` | string \| null | A **fixed vocabulary** of short phrases chosen by the server — never a URL, a response body or a value. An SDK MUST NOT parse it. |
| `consecutive_failures` | integer | Failed attempts since the last success. |
| `dead_lettered_total` | integer | Deliveries dead-lettered over the target's lifetime. |
| `last_reconciled_at` | RFC 3339 \| null | When reconciliation last ran or was claimed. |

**`ScimTargetInput`** (`create` and `update`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | 1–128 bytes. |
| `base_url` | string | yes | An `https` URL under the outbound address policy (§31.3 rule 1). |
| `enabled` | bool | no | `true` by default. |
| `auth` | `ScimTargetAuth` | yes | For `oauth2_client_credentials`, `token_url` (the same URL policy) and `client_id` (1–256 bytes) are required, `scope` (at most 256 bytes) is optional. |
| `credential` | string | on `create`; on `update` per rule 2 | **Write-only.** The bearer token, or the OAuth2 client secret, 1–4 096 bytes. |
| `scope` | `ScimTargetScope` | yes | A `groups` scope lists 1–100 groups of the tenant. |
| `push_groups` | bool | no | `false` by default. |
| `user_name_from` | enum | no | `username` by default. |
| `deprovision` | enum | no | `deactivate` by default. |
| `expected_updated_at` | RFC 3339 | no | Contract 1.60, additive. The `updated_at` of the `ScimTargetResponse` the caller read; honoured on `update` only (§31.3 rule 4). |

**`ScimReconcileAccepted`** is `{ "target_id": UUID, "status": "started" }`.

**There is no credential on a response, and an SDK MUST NOT give it one.** `ScimTargetResponse`
has no `credential` member, no `credential_set` flag, and no hash, prefix or length of the
credential: the server never returns it (D-57). An SDK's response types MUST NOT declare such a
member, and a decoder that meets one MUST drop it rather than surface it — the response object
is the one most often logged.

### §31.3 Server rules every SDK can observe (normative)

1. **Every write is validated before anything is stored** — each failure is `400
   validation_error` whose `message` names the field or the rule and **never echoes a URL or the
   credential**: `name` 1–128 bytes without control characters; `base_url` and, for a
   client-credentials target, `auth.token_url`, under the **webhook outbound address policy**
   (absolute `https`, a host, no userinfo, no fragment, at most 2 048 bytes, no IP literal that
   is not globally routable — loopback, private, link-local, the cloud metadata address and the
   rest — and no `localhost`, `*.localhost`, `*.local` or `*.internal` name); `auth.client_id`
   1–256 bytes and `auth.scope` at most 256 bytes, neither with a control character;
   `credential` 1–4 096 bytes without surrounding whitespace or control characters, and — for a
   bearer target — visible ASCII without spaces (it travels in a header); a `groups` scope with
   no group, with more than 100, or naming a group that does not exist **in this tenant**
   (duplicates collapse, order kept). A request body that is not a valid `ScimTargetInput` is
   `400` and the response never quotes the body. The policy at write time is the webhook one;
   the real guard is at **delivery**, where every request goes to the host the name resolves to
   *now*, only if every address is globally routable, with no redirect followed (informative,
   rule 14).
2. **The credential is bound to its URL (D-57).** A `create` without `credential` is `400`
   naming it. An `update` that omits it keeps the stored one — **except** that a write which
   changes `base_url` of a **bearer** target, `auth.token_url` **or `base_url`** of a
   **client-credentials** target, or `auth.type`, without `credential` in the same write is
   `400`, naming `base_url`, `auth.token_url` or `auth.type`, and changes nothing. With the
   credential, the same change is an ordinary write. The reason is disclosure by redirection: a
   kept credential sent to a new host is the credential handed to whoever runs that host — and
   for a client-credentials target every access token minted with the secret is sent to
   `base_url`, so a `base_url` moved alone would hand the next freshly minted token to the new
   host (amended in place by the W5 F4 review, T-409; 1.57 is unreleased). An SDK MUST document
   the rule at both call sites and MUST NOT work around it (it holds no credential to re-send,
   §31.5).
3. **The deployment may not have the feature.** Without `pki_encryption_key`
   (`AXIAM__AUTH__PKI_ENCRYPTION_KEY`) — the key webhook secrets are sealed under — a write
   that carries a `credential` (every `create`, every credential change) is `503
   service_unavailable`; reads, `delete` and an `update` that sends no credential still answer.
   An SDK maps it per §2 (`NetworkError`) and MUST NOT retry it.
4. **A write that was overtaken is `409` (T-406).** An `update` is conditional on the
   `updated_at` of the target as the server read it **for this request**: if another write — an
   administrator's — lands between that read and this write, the write changes nothing and is
   `409 conflict` ("the SCIM target changed since it was read…"). The administrator reloads and
   retries; an SDK MUST NOT retry it on its own (§31.7). The deliverer never writes the target
   row (its state is the separate `state` projection), so a `409` always means another
   administrator. **`expected_updated_at` (contract 1.60, additive).** `ScimTargetInput` gains
   an optional `expected_updated_at` (an RFC 3339 timestamp, the `updated_at` of the
   `ScimTargetResponse` the caller read). On `PUT /api/v1/scim-targets/{id}`, when it is present
   and the target has been written since, the server answers `409` and writes nothing; the
   caller reloads and retries. When it is omitted the replacement is conditional only on the
   version the server reads during the request (last writer wins between callers who each
   reloaded), as before. `POST` ignores the field. An SDK passes the field through unchanged,
   and a client that read a target before editing it should send the `updated_at` it read; the
   composed read-modify-write form (§27.4 rule 5), where an SDK offers one, SHOULD do so.
5. **`state` is a projection, and the only one.** `get`, `list`, `create` and `update` return
   the target's `ScimTargetDeliveryState`; it is how an administrator learns that a downstream
   refuses AXIAM's credential (`consecutive_failures`, `last_failure_reason`) or that
   deliveries were dead-lettered. The dead letter itself is an audit row
   (`scim_push.delivery_failed`) that a tenant's notification rule for the event
   `scim_delivery_failed` can mail to administrators. *(Contract 1.60, informative.)* The
   server stops calling a target whose `consecutive_failures` is five or more until its retry
   backoff has passed since `last_failure_at` (a per-target breaker); a delivery it holds back
   makes no request and changes neither `last_failure_at` nor `last_failure_reason`, and if it is
   dead-lettered it is counted in `dead_lettered_total` only. In the minimal profile a delivery
   lost at an orderly stop, or refused at enqueue, is recorded as
   `scim_push.delivery_abandoned`, a different action from `scim_push.delivery_failed`: it
   triggers no `scim_delivery_failed` notification.
6. **Enabling starts the first synchronisation.** A `create` with `enabled: true`, or an
   `update` that switches a disabled target on, starts a reconciliation (rule 7), which queues
   a reference for every user and group in scope. It is best effort: the write stands whether
   or not the run could be started, and the nightly reconciliation finds the target either way.
7. **`reconcile` starts a reconciliation now, in the background.** `202
   ScimReconcileAccepted` when the request took the target's claim; the run — queue a
   reference for every user and group in scope and every linked resource, read the downstream,
   repair drift, never touch an account the downstream's own application created — is not
   awaited, and its outcome is on `state`. `409 conflict` when a run holds the claim or ran
   within the last five minutes (the same claim the nightly job takes, so two replicas do not
   both run), or when the target is **disabled**; `404` for an unknown target; `503` when
   delivery is not available in the deployment. An SDK MUST NOT poll to wait for the run
   (§31.9).
8. **`delete` removes the target, its link rows and its delivery state, and deprovisions
   nothing downstream.** The users and groups AXIAM created in the service provider stay
   there, and AXIAM no longer knows them. An administrator who wants them gone sets
   `deprovision` to `delete`, lets AXIAM push, and only then deletes the target. An SDK MUST
   say so at the `delete` call site.
9. **Authorization.** Two new permissions, seeded per tenant like every other:
   `scim_targets:read` (`list`, `get`) and `scim_targets:write` (`create`, `update`, `delete`,
   `reconcile`). **The namespace is human-only:** a service-account token is `401` (the
   registry's `service_account` flag is false for all six, and §27.13's list of admitted
   families does not grow) — the credential to an outbound endpoint, and the choice of where a
   tenant's people are sent, are a human administrator's. A token that holds only
   `scim_targets:write` cannot read.
10. **Rate limiting.** The four writes each have a per-IP bucket of their own,
    `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN` (default 30 per minute, never moved by a
    profile), because each can repoint where a tenant's directory is pushed and `reconcile`
    queues work and reads the downstream: `429` per §2. Reads are not in it.
11. **CSRF** is as for every `/api/v1` write (§3).
12. **Audit.** `scim_target.created`, `scim_target.updated`, `scim_target.deleted` and
    `scim_target.reconcile_requested` record the actor and the tenant and, for an update, the
    **names** of the fields that changed (and whether the credential was replaced); never a
    URL, never the credential.
13. **Tenant isolation.** A target is found only in the token's tenant. Every route answers
    `404` for another tenant's id, with no difference from a target that does not exist.
14. **Informative — what a target does once it is registered.** Delivery is **level-triggered**.
    A change to a user or a group — from any writer: the console, the API, SCIM inbound, a
    directory sync, a federation sign-in, an erasure — queues one **reference** per enabled
    target (`{resource_type, axiam_id}` and nothing else, on the queues `axiam.scim_push`,
    `.retry` and `.dlq`); each attempt re-reads the target, the resource and its link and sends
    what the downstream should look like *now*, so retries, reordering and duplicates converge
    and no attribute of a person ever sits in a queue. A new user is `POST /Users` with
    `externalId` set to the AXIAM id; a known one is a `PATCH` of the mapped attributes only
    (skipped when nothing changed); a user who leaves scope or is no longer active is
    deactivated or deleted per `deprovision`; an **erased** user is deleted whatever
    `deprovision` says. A downstream `5xx`, `408` and `429` retry with backoff; another `4xx`
    is dead-lettered and counted on `state`. A nightly reconciliation (and *reconcile now*)
    repairs drift. AXIAM **never touches a downstream account that is not one it created or
    adopted by `externalId`**. An SDK does none of this.

### §31.4 Error mapping

§2 and §27.4 rule 7, unchanged: `400` is `ValidationError` (carrying the server's `message`),
`404` `NotFoundError`, `409` `ConflictError`, `403` `AuthzError`, `401` `AuthError`, `429` and
`503` `NetworkError`. A `202` is success. An SDK MUST NOT parse a `message` to recover the rule.

### §31.5 `Sensitive<T>` applicability

**`ScimTargetInput.credential` MUST be `Sensitive<T>`** (§7) wherever it appears —
`scim_targets.create` and `scim_targets.update`, the only two places — from the first version an
SDK ships (the #480 lesson, §27.5, applied before the fact). It is a credential AXIAM presents
to a third party, write-only, sealed at rest and on no response. §7 rule 1's redaction covers it
in every stringification sink; §27.4 rule 11 keeps it out of §19 telemetry; an error raised by
`create` or `update` MUST NOT include it, a prefix or a hash of it. An SDK MUST NOT cache it,
persist it, or keep it after the request that carried it has been sent. Nothing else in §31 is
wrapped (§27.5 rule 2): `token_url`, `client_id`, `base_url` and the failure reason are
configuration and fixed vocabulary. The registry lists `(ScimTargetInput, credential)` in the
namespace's `sensitive_request_fields`, and §27.5's table gains the two rows.

### §31.6 Per-language naming map

§27.3 applies unchanged; for the record (`list` shown for the namespace, the other five follow
the same casing):

| Canonical | Rust | TypeScript | Python | Java | Kotlin | C# | PHP | Go | Swift | C | C++ |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `scim_targets.list` | `scim_targets().list` | `scimTargets.list` | `scim_targets.list` | `scimTargets().list` | `scimTargets.list` | `ScimTargets.ListAsync` | `scimTargets()->list` | `ScimTargets().List` | `scimTargets.list` | `axiam_scim_targets_list` | `scim_targets().list` |
| `scim_targets.create` | `scim_targets().create` | `scimTargets.create` | `scim_targets.create` | `scimTargets().create` | `scimTargets.create` | `ScimTargets.CreateAsync` | `scimTargets()->create` | `ScimTargets().Create` | `scimTargets.create` | `axiam_scim_targets_create` | `scim_targets().create` |
| `scim_targets.get` | `scim_targets().get` | `scimTargets.get` | `scim_targets.get` | `scimTargets().get` | `scimTargets.get` | `ScimTargets.GetAsync` | `scimTargets()->get` | `ScimTargets().Get` | `scimTargets.get` | `axiam_scim_targets_get` | `scim_targets().get` |
| `scim_targets.update` | `scim_targets().update` | `scimTargets.update` | `scim_targets.update` | `scimTargets().update` | `scimTargets.update` | `ScimTargets.UpdateAsync` | `scimTargets()->update` | `ScimTargets().Update` | `scimTargets.update` | `axiam_scim_targets_update` | `scim_targets().update` |
| `scim_targets.delete` | `scim_targets().delete` | `scimTargets.delete` | `scim_targets.delete` | `scimTargets().delete` | `scimTargets.delete` | `ScimTargets.DeleteAsync` | `scimTargets()->delete` | `ScimTargets().Delete` | `scimTargets.delete` | `axiam_scim_targets_delete` | `scim_targets().delete` |
| `scim_targets.reconcile` | `scim_targets().reconcile` | `scimTargets.reconcile` | `scim_targets.reconcile` | `scimTargets().reconcile` | `scimTargets.reconcile` | `ScimTargets.ReconcileAsync` | `scimTargets()->reconcile` | `ScimTargets().Reconcile` | `scimTargets.reconcile` | `axiam_scim_targets_reconcile` | `scim_targets().reconcile` |

All six perform I/O, so §27.3's async discipline applies to each.

### §31.7 Retry

§27.4 rule 8 governs and is not widened: `list` and `get` MAY be retried per §16; `create`,
`update`, `delete` and `reconcile` MUST NOT be, on any status or transport error. For
`reconcile` a repeat is merely refused (`409` while the claim is held), but it is a deliberate
administrator act, and a caller who lost the answer can read `state.last_reconciled_at`
instead of repeating it.

### §31.8 Required tests

Six per SDK that ships the namespace, against a mocked HTTP server:

1. **Redaction.** A `ScimTargetInput` carrying a `credential` made at run time, and an error
   raised by `create` given one, printed, debug-formatted and serialized for logs contain
   neither the credential nor any 8-character substring of it; the credential **is** in the
   request body.
2. **No credential on the response.** Decoding a `ScimTargetResponse` body that (wrongly)
   carries `"credential": "<value>"` yields a value whose every stringification lacks the value,
   and the type has no accessor for it.
3. **Replacement and the omitted credential.** `update` with no credential sends **no
   `credential` key**; with one it sends it; the input cannot be built without `name`,
   `base_url`, `auth` and `scope` (or its builder refuses, in a language without the
   compile-time check); both `ScimTargetAuth` variants and both `ScimTargetScope` variants
   serialize with the exact keys of §31.2; `expected_updated_at`, when the caller sets it, is sent on
   `update` exactly as given (the string, not re-formatted) and is absent from the body when unset
   (contract 1.60).
4. **Open decoding and pagination.** A `ScimTargetResponse` with an unknown `auth.type`,
   `deprovision` and `user_name_from`, with `state: null`, and with a `last_failure_reason` the
   SDK has never seen, decodes; `list` returns `Page<T>` with `total` and the auto-pager carries
   `search` on every request.
5. **No retry.** A `503` to each of `create`, `update`, `delete` and `reconcile`: exactly one
   request each, and the error is `NetworkError`.
6. **Errors and `reconcile`.** `400` → `ValidationError` with the `message`; `409` on `update`
   and on `reconcile` → `ConflictError`; `404` on `get` → `NotFoundError`; `401` → `AuthError`;
   `reconcile` sends no body, treats `202` as success and decodes `ScimReconcileAccepted`.

The server task adds its own tests for every rule in §31.3; they are not an SDK's to duplicate.

### §31.9 What an SDK does not do

It does not validate a target locally beyond §27.4's UUID rule — the server's policy and the
delivery-time guard are the authority, and a client-side copy would drift from them (the
reason §27.4 rule 4 gives for the `search` cap). It does not call a target's SCIM endpoint, test
a target's credential or offer a "test connection" helper: no such route exists, and a client
cannot reach the downstream from the server's network anyway. It does not poll `state` to wait
for a reconciliation to finish. It does not cache a target (§27.4 rule 10) or keep a credential
after the request that carried it. And `scim_targets` is **not** a manifest namespace (§27.6): a
declarative `apply` would have to carry a credential it could not read back.

### §31.10 Per-SDK posture

**All eleven SDKs implement §31**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge, and state "§27 and §31". All eleven are in scope: it is
management REST, which Kotlin, Swift, C and C++ carry.

| SDK | §31 | Notes |
|---|---|---|
| Rust | **implemented** | `credential` `Sensitive`, omitted when `None` |
| TypeScript | **implemented** | Error body: R-18; undeclared members: R-20 (F-59-02) |
| Python | **implemented** | An unknown `auth`/`scope` arm cannot be rendered as JSON: R-21; rule 2 missing on `create`: R-29 (F-59-03) |
| Java | **implemented** | Transport re-send: R-17; unknown enums re-sent: R-22; rule 2 on `create`: R-29 (F-59-04) |
| Kotlin | **implemented** | Sealed unions with an `Unknown` arm; transport re-send: R-17 (F-59-08) |
| C# | **implemented** | Open tagged unions; an unknown arm cannot be serialized for a log line: R-21 (F-59-05) |
| PHP | **implemented** | `listItems` (P12.8); an unknown arm keeps raw members and cannot be rendered: R-20, R-21 (F-59-06) |
| Go | **implemented** | An unknown union arm cannot be re-encoded, for logs either: R-21 (F-59-07) |
| Swift | **implemented** | An auth arm keeps the server object in `raw`: R-20; rule 2 on `create`: R-29 (F-59-09). 1.60 port: `deprovision` and `userNameFrom`, like every open enum, refuse `.unknown` on encode (R-22) |
| C | **implemented** | `ScimTargetAuth.raw` keeps the server object: R-20; rule 2 on `create`: R-29 (F-59-10) |
| C++ | **implemented** | Unknown arms decode and are refused on send; rule 2 on `create`: R-29 (F-59-11) |

## §32 SSF stream registration and the receiver helper (contract 1.56)

**Requirement level: §32.1 – §32.5 SHOULD, as part of §27 (a namespace `ssf`); §32.7 the
receiver helper SHOULD in the seven full-surface SDKs (Rust, TypeScript, Python, Java, C#, PHP,
Go) and MAY in Kotlin, Swift, C and C++. Additive; nothing in §1–§30 changes.**
Server design: plan item G-5 and decisions D-44 … D-53 and D-55 in the plan's decision table
([`competitor-gap-remediation-plan-2026-10-02.md`](../claude_dev/competitor-gap-remediation-plan-2026-10-02.md)
§8). Threat model: T-385 … T-406. (§31, G-6's outbound SCIM management, which the plan named
first (D-44), arrived in contract 1.57; the numbers did not trade places.)

AXIAM can act as a **Shared Signals Framework transmitter** for a tenant (competitor-gap item
G-5): it sends CAEP and RISC security events — `session-revoked`, `credential-change`,
`assurance-level-change`, `account-disabled`, `account-enabled`, `account-purged` — as Security
Event Tokens (RFC 8417) to the relying parties a tenant administrator registered, by push
(RFC 8935) or poll (RFC 8936). The specification followed is **OpenID Shared Signals Framework
1.0** (final, 2025-08-29), with **CAEP 1.0**, **RISC 1.0** and **RFC 9493** (D-44).

Two audiences use this section. A **tenant administrator** registers streams through the
management namespace `ssf` (§32.1 – §32.5), generated from the registry like every §27
namespace. A **relying party** that *receives* events uses the SSF protocol (§32.6), which is
not management surface and is not in the registry; what an SDK offers it is the optional
receiver helper (§32.7), which verifies a SET and polls. An SDK never *transmits*.

**Status: the routes and the delivery exist.** T23.5.2 added the five management routes, the
receiver protocol routes and discovery, and regenerated `openapi.json` and
`management-registry.json`; T23.5.3 added push and poll delivery and the event sources (§32.6),
and regenerated `openapi.json` for the poll route (the registry is unchanged). An SDK implements
§32 from the merge commit (§7 rule 1 of the plan; the 1.49 rule), in the post-merge fan-out
(D-35).

### §32.1 Canonical operation set

A new §27 namespace, **`ssf`**, OpenAPI tag `ssf`. All five paths carry `{tenant_id}`,
defaulted from the client's configured tenant per §27.4 rule 3.

| Operation | HTTP | Request body | Response | `update_style` |
|---|---|---|---|---|
| `ssf.list_streams` | `GET /api/v1/tenants/{tenant_id}/ssf/streams` | — (`offset`, `limit`, `search`) | `200` page of `SsfStream` | — |
| `ssf.create_stream` | `POST /api/v1/tenants/{tenant_id}/ssf/streams` | `SsfStreamInput` | `201` `SsfStream` | — |
| `ssf.get_stream` | `GET /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}` | — | `200` `SsfStream` | — |
| `ssf.update_stream` | `PUT /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}` | `SsfStreamInput` | `200` `SsfStream` | **`replace`** |
| `ssf.delete_stream` | `DELETE /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}` | — | `204` | — |

`list_streams` is one of §27.4 rule 4's paginated operations (`{ items, total, offset, limit }`,
`search` matched against `audience`, `receiver_client_id`, `description` and the id).

### §32.2 Shapes (normative)

**`SsfStream`** — what every read and write returns:

| Field | Type | Notes |
|---|---|---|
| `id`, `tenant_id` | UUID | `id` is also the SSF `stream_id`. |
| `receiver_client_id` | string | The OAuth2 `client_id` whose client-credentials token is this stream's receiver on the SSF protocol (§32.6). |
| `audience` | string | The SETs' `aud`. 1–512 bytes; **unique across the deployment** (§32.3 rule 3). |
| `description` | string \| null | At most 256 bytes. |
| `delivery_method` | `"push"` \| `"poll"` | Set by the administrator only. |
| `endpoint_url` | string \| null | The push endpoint; null for a poll stream (AXIAM serves its poll endpoint). |
| `authorization_header_set` | bool | Whether a push `Authorization` header is stored. **The value is never returned.** |
| `events_allowed` | array of event-type URI | The administrator's ceiling: 1–6 of the six URIs of §32.6. |
| `events_requested` | array of event-type URI | What the receiver asked for; always a subset of `events_allowed`. |
| `events_delivered` | array of event-type URI | What the stream carries: the intersection. Read-only. |
| `subject_format` | `"iss_sub"` \| `"email"` | How users are named in the stream's SETs (D-46). |
| `status` | `"enabled"` \| `"paused"` \| `"disabled"` | D-51: `paused` holds events for later, `disabled` drops them. |
| `status_reason` | string \| null | |
| `status_actor` | `"admin"` \| `"receiver"` | Who set the status. |
| `last_verification_at` | RFC 3339 \| null | The receiver's last verification request. |
| `created_at`, `updated_at` | RFC 3339 | |
| `transmitter_active` | bool | Read-only. Whether the tenant's transmitter is active: its `ssf_enabled` is on **and** the shared-issuer gate does not hold (§32.3 rule 13). A stream of an inactive transmitter is kept and carries nothing. |
| `transmitter_inactive_reason` | string, absent when active | Read-only. Why the transmitter is inactive. Text for a person: an SDK MUST NOT parse it. |

Every string enum, and the event-type URIs, are **open**: an SDK MUST decode a value it does not
know without failing and MUST NOT send one it does not know. An SDK SHOULD model event types as
strings with the six URIs as named constants. **Contract 1.60:** an event-type URI is sent as
the string the caller holds, and one the SDK has never seen — read from the server — decodes
with its value and is sent back unchanged on `update_stream`; the server judges it
([§34.2](#§342-clarifications-normative-from-159) P12.2).

**`SsfStreamInput`** (`create_stream`, and `update_stream` as a **replacement**) carries
`receiver_client_id`, `audience`, `delivery_method` and `events_allowed` (required), and
`description`, `endpoint_url`, `authorization_header`, `clear_authorization_header`,
`events_requested`, `subject_format`, `status`, `status_reason` (optional). An omitted optional
member takes its default **on every write, including an update** (§27.4 rule 5, repeated at the
`update_stream` call site): `description`, `endpoint_url`, `status_reason` null;
`events_requested` all of `events_allowed`; `subject_format` `iss_sub`; `status` `enabled`;
`clear_authorization_header` false. **The one exception is `authorization_header`**: absent on
an update keeps the stored header (unless rule 5 applies). `authorization_header` is
write-only (§32.5); `clear_authorization_header: true` removes the stored one and is refused
together with `authorization_header` and on create.

### §32.3 Server rules every SDK can observe (normative)

1. **Every write is validated before anything is stored**, each refusal `400
   validation_error` with a `message` naming the rule (never echoing a header or a URL): an
   empty, over-long, padded or control-character `audience`; a `description` over 256 bytes;
   a `push` stream without `endpoint_url`, a `poll` stream with one or with a header; an
   endpoint that is not absolute `https`, carries credentials or a fragment, is an IP literal
   that is not globally routable (loopback, private, link-local, the metadata address, their
   IPv4-mapped forms) or a `localhost`, `*.local` or `*.internal` name — the webhook outbound
   address policy (D-49); a header over 4 096 bytes or with anything but visible ASCII and
   spaces; an empty `events_allowed`; an `events_requested` outside `events_allowed`; an
   unknown event-type URI.
2. **The receiver binding (D-50).** `receiver_client_id` must be an OAuth2 client of the
   tenant, registered for the `client_credentials` grant and with the `ssf.manage` scope —
   otherwise `400` naming which.
3. **The audience is unique across the deployment** (D-47): a create or update that reuses
   one — in any tenant — is `409 conflict`, without saying where.
4. **Update is a replacement** (`update_style: replace`), with `authorization_header`'s
   exception (§32.2). It replaces the stream **as the server read it for this request**: if
   another write — the receiver's (§32.6) — lands between that read and this write, the
   update is refused with `409 conflict` rather than putting back what the other write
   changed, and the administrator reads the stream again (F4 W4, T-406).
5. **A stored header never follows the endpoint to another origin** (D-49): an update that
   moves `endpoint_url` to another scheme, host or port while a header is stored must carry
   `authorization_header` again or `clear_authorization_header: true`, else `400`.
6. **The sealing key.** A write that stores a header on a deployment without
   `pki_encryption_key` is `503 service_unavailable`; the same write without a header works.
7. **Delete** answers `204` and removes the stream and every event buffered for it. A second
   delete is `404`.
8. **Status (D-51).** An administrator may set any status. A status an administrator set to
   anything but `enabled` cannot be changed by the receiver. A status change is announced to
   the receiver with an SSF stream-updated event (SSF §8.1.5).
9. **The routes do not depend on the tenant's `ssf_enabled`** (D-45): an administrator
   registers streams before switching the transmitter on. The setting — a disable-only layered
   setting like `saml_idp_enabled`, default `false`, written through §27's `settings`
   operations — governs everything a receiver sees (§32.6) and whether any event is sent, and
   so does the deployment-wide gate of rule 13.
10. **Authorization.** `ssf_streams:read` (`list_streams`, `get_stream`) and
    `ssf_streams:write` (the three writes). The `{tenant_id}` in the path must be the caller's
    (`403`). A service-account token is `401`, as on every human-only family: deciding which
    third party receives security events about the tenant's users is a human administrator's
    act.
11. **Rate limiting.** Each of the three writes has a per-IP bucket of its own,
    `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN` (default 30): `429` per §2. Reads are not limited.
12. **Audit.** `ssf_stream.created`, `ssf_stream.updated` (the **names** of the changed
    members), `ssf_stream.deleted`; never the header.
13. **SSF requires per-tenant issuers in a deployment of more than one tenant** (D-55, F4 W4
    P23W4-11). Without per-tenant issuers (`AXIAM__AUTH__TENANT_ISSUER_PATHS` off) every
    tenant's SETs would carry the same `iss` and be signed by the same key, so a tenant that
    registered another tenant's receiver audience first — rule 3 cannot stop that — could push
    SETs that receiver accepts. The **shared-issuer gate** holds when per-tenant issuers are
    off **and** the deployment holds more than one tenant, counted across every organization
    (an organization's own scope tenant is not counted beside its standard tenants, and an
    organization with none counts as one). While it holds, SSF behaves for **every** tenant
    exactly as with `ssf_enabled` off: discovery answers its one empty `404`, the receiver API
    sees no stream, nothing is produced, held or verified, and no SET is signed — a push
    already queued is dead-lettered and a poll answers nothing (§32.6). The check is made where
    an event is produced, where a SET is signed and at discovery, never only when something is
    written. **Turning `ssf_enabled` on** — at the organization or as a tenant override —
    while the gate holds is `400 validation_error`, its `message` naming `ssf_enabled` and the
    cause; turning it off, and a write that leaves it as it was, are accepted. The stream routes
    keep working (rule 9): every `SsfStream` they return carries `transmitter_active: false`
    and the reason (§32.2), and the §27 `settings` reads and writes carry the read-only
    `oidc.ssf_inactive_reason` while `ssf_enabled` is on but the gate holds. The tenant count is
    read from the datastore and reused for at most **60 seconds**; a tenant or organization
    created or deleted through one server instance takes effect on that instance at once, and on
    the others within that minute. A change of the gate's state is logged once at `WARN` and
    audited as `ssf.inactive_shared_issuer` in every tenant whose `ssf_enabled` is on — never
    per event. A single-tenant deployment keeps the root issuer, which no other tenant shares,
    and a deployment that serves per-tenant issuers is never gated.

### §32.4 Error mapping

§2 and §27.4 rule 7, unchanged: `400` is `ValidationError`, `404` `NotFoundError`, `409`
`ConflictError`, `403` `AuthzError`, `401` `AuthError`, `429` and `503` `NetworkError`. An SDK
MUST NOT parse a `message` to recover the rule.

### §32.5 `Sensitive<T>` applicability

**`SsfStreamInput.authorization_header` is `Sensitive<T>`** (§7) from the first version an SDK
ships: it is a credential AXIAM presents to a third party, write-only, sealed at rest and on no
response. §27.5's table gains its row and the registry lists it in the namespace's
`sensitive_request_fields`. No response type has a member for it (`SsfStream` has only
`authorization_header_set`), and a decoder that meets one MUST drop it rather than surface it.

### §32.6 The receiver protocol (informative for SDKs, normative for the server)

What a relying party talks to. None of it is in the registry (`openapi.json` tags it
`ssf-receiver`), and an SDK does not generate a client for it beyond §32.7.

**Discovery.** `GET {root}/.well-known/ssf-configuration?tenant_id={tenant_id}` on every
deployment, and — where the deployment serves per-tenant issuers (T21.6) — SSF §7.2's insertion
form `GET {root}/.well-known/ssf-configuration/t/{tenant_id}` for the issuer
`{root}/t/{tenant_id}`. Unauthenticated. The document carries `spec_version` `"1_0"`,
`issuer`, `jwks_uri` (`{issuer}/oauth2/jwks`, the deployment key, D-13),
`delivery_methods_supported` (`urn:ietf:rfc:8935`, `urn:ietf:rfc:8936`),
`configuration_endpoint`, `status_endpoint`, `verification_endpoint`,
`authorization_schemes` (`[{"spec_urn": "urn:ietf:rfc:6749"}]`), `default_subjects` `"ALL"`
and the extension member `events_supported`. There are no add/remove-subject endpoints. An
unknown tenant, a malformed id, a tenant whose `ssf_enabled` is off and every tenant while the
shared-issuer gate holds (§32.3 rule 13) all answer the same empty `404`.

**The stream management API** — `{root}/ssf/v1/stream` (`GET` one stream by `stream_id` or the
receiver's list, `PATCH`, `PUT`; `POST` and `DELETE` are `403`: streams are an administrator's),
`{root}/ssf/v1/status` (`GET`, `POST`) and `{root}/ssf/v1/verify` (`POST`, `204`) — and the
poll endpoint `{root}/ssf/v1/poll/{stream_id}` (RFC 8936). Each takes a bearer access
token issued to the receiver's OAuth2 client by the client-credentials grant with the
`ssf.manage` scope (`403` otherwise); a stream bound to another client, another tenant's, or
one in a tenant whose transmitter is off or inactive (§32.3 rule 13) answers the same `404`. A
receiver may narrow its `events_requested` (never beyond `events_allowed`), change its
`description`, repoint a push endpoint under §32.3 rules 1 and 5 and supply the push
`authorization_header`; the method, the audience and the subject format are the administrator's. A receiver's `PATCH`, `PUT` and
status `POST` are each decided against the stream as read for the request and written only
if no other write — an administrator's — landed in between; when one did, the server decides
again from a fresh read (so an administrator's `disabled` is never undone by a receiver's
write that overlapped it), and answers `409` only if the stream kept changing over three
attempts (F4 W4, T-406). Verification is limited to one request per
`min_verification_interval` (60 s) per stream (`429`). Each route has a per-IP bucket,
`AXIAM__RATE_LIMIT__SSF_PER_MIN` (default 60).

**The SET** (D-45, D-46). JOSE header `{"alg": "EdDSA", "typ": "secevent+jwt", "kid": …}`.
Claims: `iss` (the tenant's issuer, identical to the discovery `issuer`), `aud` (the stream's
audience, one string), `iat`, `jti` (32 lower-case hex characters, 128 bits from a CSPRNG),
`txn` (when the event has a cause shared by several SETs), `sub_id` and `events` with
**exactly one** member. **No `sub` and no `exp`** (SSF §4.1.2, §4.1.7). `sub_id` is RFC 9493
`{"format": "iss_sub", "iss": <issuer>, "sub": <user id>}` (the `sub` of AXIAM's ID tokens) or,
on an `email` stream, `{"format": "email", "email": …}` — sent only for an address AXIAM vouches
for, otherwise the event is not sent on that stream. `session-revoked` names the session too:
`{"format": "complex", "user": <the above>, "session": {"format": "opaque", "id": <sid>}}`,
`sid` being the ID token's. The verification and stream-updated events name the stream:
`{"format": "opaque", "id": <stream_id>}`. The event objects:

| Event | URI | Members |
|---|---|---|
| CAEP session revoked | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | `initiating_entity`?, `event_timestamp` |
| CAEP credential change | `https://schemas.openid.net/secevent/caep/event-type/credential-change` | `credential_type` (`password`, `x509`, `fido2-platform`, `fido2-roaming`, `app`), `change_type` (`create`, `revoke`, `update`, `delete`), `initiating_entity`?, `event_timestamp`, `x509_issuer`? and `x509_serial`? (`x509` only), `fido2_aaguid`? (`fido2-*` only) |
| CAEP assurance level change | `https://schemas.openid.net/secevent/caep/event-type/assurance-level-change` | `namespace` `"urn:axiam:acr"`, `current_level`, `previous_level`?, `change_direction`? (`increase` / `decrease`), `initiating_entity`?, `event_timestamp` |
| RISC account disabled | `https://schemas.openid.net/secevent/risc/event-type/account-disabled` | `reason`? (`hijacking`, `bulk-account`) |
| RISC account enabled | `https://schemas.openid.net/secevent/risc/event-type/account-enabled` | none |
| RISC account purged | `https://schemas.openid.net/secevent/risc/event-type/account-purged` | none |
| SSF verification | `https://schemas.openid.net/secevent/ssf/event-type/verification` | `state`? |
| SSF stream updated | `https://schemas.openid.net/secevent/ssf/event-type/stream-updated` | `status`, `reason`? |

`initiating_entity` is one of `admin`, `user`, `policy`, `system`; `event_timestamp` is seconds
since the epoch; the levels are `urn:axiam:acr:1fa` and `urn:axiam:acr:mfa`. No member carries
free text a person typed. A receiver MUST ignore members it does not understand (SSF §4.2.3).

**Push** (RFC 8935): `POST` of the compact SET to the endpoint, `Content-Type:
application/secevent+jwt`, with the stored `Authorization` header if there is one; the receiver
answers `202`. **Poll** (RFC 8936): `POST` `{ "maxEvents", "returnImmediately", "ack",
"setErrs" }` to the stream's poll endpoint; the answer is `{ "sets": { <jti>: <SET> },
"moreAvailable" }`. An event stays in the stream's buffer — at most 1 000, the oldest dropped,
seven days at most — until its `jti` is acknowledged (D-48).

**The push response mapping** (D-49, D-53). Each attempt is one request, made to the address the
endpoint resolves to *now* (every address must be globally routable, and the connection is
pinned to the one validated; `https` is required) — an endpoint that was acceptable when it was
registered and resolves to an internal address later is refused at delivery. **A redirect is
never followed**: the one hop is made and a `3xx` is returned as the answer, so neither the SET
nor the `Authorization` header can reach a host the administrator did not name. The header and
the endpoint come from **one version** of the stream: an attempt that finds the stream changed
between reading its endpoint and opening its header is retried, so a header supplied with a new
endpoint is never sent to the old one (F4 W4, T-406). The response body is read to at most
64 KiB and never logged or audited. What the answer means:

| The receiver answers | Outcome |
|---|---|
| any `2xx` (RFC 8935: `202`) | delivered |
| `400` with an RFC 8935 §2.4 `err` code (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`, `access_denied`) | dead-lettered; the code is in the `ssf_push.delivery_failed` audit row |
| `401`, `403` | dead-lettered: the credential is wrong until someone changes it |
| any other `4xx` — a `400` without a known code, `410`, `422`, … | dead-lettered with the reason `HTTP <status>`: it will not change on retry — except `404`, `408` and `429` below |
| `404`, `408`, `429`, any `5xx`, a timeout, no connection | retried |
| a `3xx` (not followed), and anything else | retried |

Retrying follows the shared outbound dispatcher's schedule, `base × 2^(attempt − 1)` clamped to a
ceiling, set by `AXIAM__SSF_PUSH__MAX_ATTEMPTS` (default `5`, the first attempt counting as one),
`AXIAM__SSF_PUSH__BACKOFF_BASE_MS` (`5000`) and `AXIAM__SSF_PUSH__BACKOFF_CEILING_MS`
(`3600000`) — the webhook variables' names with the kind's prefix, read independently of them.
A message that is dead-lettered waits in `axiam.ssf_push.dlq`, which discards it after **seven
days** (`x-message-ttl`, D-53): it holds an unsigned event and so a subject. A retried push
carries the byte-identical SET, one `jti`; the attempt re-reads the stream and signs against it as
it is then (D-51), so a stream disabled meanwhile sends nothing and a paused one holds the event.
While the shared-issuer gate holds (§32.3 rule 13) an attempt dead-letters its message before
anything is signed, sent or held, whatever the stream's status.

**The poll endpoint in detail** (RFC 8936; every reply here is `200` with the body above unless a
status is named). A request body is optional — an empty one is `{}` — and at most 32 KiB
(`413` beyond it). `400` for a body that is not the RFC 8936 JSON, a **negative `maxEvents`**,
more than **1 000** `ack` entries or more than **100** `setErrs` entries, and for a **push**
stream (there is nothing to poll). `maxEvents` is clamped to 100; `0` acknowledges and returns
nothing. `ack` deletes exactly the named rows of *this* stream (an unknown `jti`, or another
stream's, is ignored). Each `setErrs` entry deletes its row — the receiver will not accept that
SET, so it is not offered again — and writes an audit row `ssf_stream.poll_set_error` carrying
the `jti`, whether the event was still held, and the `err` code if it is one of RFC 8935's (else
`unrecognized`); the receiver's free-text `description` is never stored. SETs are signed at poll
time against the stream as it is then. **A paused or disabled stream answers an empty `sets`**
and keeps what it holds (a disabled stream's held events stay until they expire). Without
`returnImmediately` a poll *long-polls*: it waits up to **30 seconds** for an event. **At most one
long poll waits per stream per server instance** (D-53): a second concurrent request on the same
stream is answered at once, as if `returnImmediately` were true. A receiver that polls in a loop
therefore keeps one connection open, not many.

**What is emitted, and from where** (D-52, D-53). One emitter, a no-op while the tenant's
`ssf_enabled` is off or the shared-issuer gate holds (§32.3 rule 13), one `txn` for every SET
one operation produces:

| Event | Emitted by |
|---|---|
| `session-revoked` | every revocation of a session — logout, an administrator's revoke, a password change or reset, an erasure — never an expiry or a refresh redemption |
| `credential-change` | a password change or reset; the SCIM password write; creating a user with an OPAQUE record; TOTP confirmation; an MFA reset or method deletion; a WebAuthn registration (`Passkey` → `fido2-platform`, `SecurityKey` → `fido2-roaming`). An administrator's password write has no REST route, so the SCIM write is the source. **`x509` is never emitted:** certificates bind only to service accounts, and an SSF subject is a user — the member shapes stay for the day a user-certificate binding exists |
| `assurance-level-change` | the honour lane's **step-up**: when an authorization request needs a higher `acr` and the browser presents a valid OP session, the server remembers (ten minutes, one record per user, the latest replacing) the session and its `acr`; the return leg that arrives with a **new** session of the same user consumes the record once and emits **only when the `acr` differs** — `previous_level` the old one, `change_direction` from the published order (`1fa` < `mfa`), `initiating_entity` `user`. No marker travels in `return_to`, so there is nothing for a relying party to forge or replay; no earlier session, another user, an expired record or the same session emit nothing |
| `account-disabled`, `account-enabled` | an administrator's status write, SCIM `active`, and — for `account-disabled` only — a directory deactivation. **The directory sync never re-enables an account** (D-31), so `account-enabled` comes from the administrator and SCIM alone |
| `account-purged` | `DELETE /api/v1/users/{id}`, SCIM `DELETE /Users/{id}` (the same tombstone) and the GDPR erasure; the subject is the account as it was **before** the write |
| `stream-updated` | an administrator's or receiver's status change, announced only while the tenant's `ssf_enabled` is on and the shared-issuer gate does not hold |

A lock-out is not an `account-disabled`; an unchanged status, a no-op patch and an equal `acr`
tell nobody anything.

### §32.7 The receiver helper (SHOULD, seven SDKs)

Two operations on a receiver configuration `{ issuer, audience, jwks_uri | discovery_url,
access_token_provider }`. Both are **pure client-side helpers**: neither is in the registry,
and both perform I/O only to fetch the JWKS and, for `poll`, to call the poll endpoint.

**`ssf.verify_set(set) → SecurityEvent`** verifies one compact SET, in this order, and refuses
(§2 `AuthError`, with one of the reason codes in brackets) at the first failure:

1. three base64url parts that decode, a JSON header and payload [`malformed`];
2. header `typ` equal to `secevent+jwt` or `application/secevent+jwt`, case-insensitively
   [`invalid_type`];
3. header `alg` exactly `EdDSA` — `none`, every `HS*` and every other value refused
   [`invalid_key`];
4. the key named by `kid` in the JWKS fetched from `jwks_uri` over §6's TLS policy; on an
   unknown `kid`, **one** refetch, no more often than once a minute, then refusal
   [`invalid_key`];
5. the signature [`invalid_key`];
6. `iss` equal to the configured issuer, exactly [`invalid_issuer`];
7. `aud` equal to the configured audience, or an array containing it [`invalid_audience`];
8. no `exp` and no `sub`; `jti`, `iat`, `sub_id` present; `events` exactly one member
   [`invalid_request`];
9. a `jti` not seen before within the helper's replay window — default **seven days**, the
   transmitter's buffer retention, configurable but never below it — kept in a pluggable store
   (in-memory by default) [`replayed`]. The `jti` is recorded only after steps 1–8 passed.

It returns `{ jti, iat, iss, aud, txn, event_type, event, sub_id }`, `event_type` the single
`events` key, `event` its object, both opaque to the helper beyond that. The reason codes match
RFC 8935 §2.4's `err` values, so a push endpoint can answer `400 {"err": <code>}` with them
(`malformed`, `invalid_type` and `replayed` are answered as `invalid_request`; a failed key fetch or
store is no verdict and is answered with a `5xx` — contract 1.59,
[§34.2](#§342-clarifications-normative-from-159) P3 – P5).

**`ssf.poll(stream_id, { max_events, return_immediately, ack, set_errs }) → { events,
more_available, refused }`** calls the stream's poll endpoint with a bearer token from
`access_token_provider` (a client-credentials token carrying `ssf.manage`, e.g. §12.1's
`login_client_credentials`), passes `ack` and `set_errs` through, runs `verify_set` on every
returned SET and returns the verified `events` and the `refused` ones as `{ jti, reason }`. It
MUST NOT acknowledge anything itself: the caller acknowledges the `jti`s it **processed** on
its next call, and SHOULD pass each refused one in `set_errs` (`{ <jti>: { "err": <reason> } }`)
instead — except a `replayed` one, which it acknowledges (P2). `poll` never leaves a `jti` recorded
that it does not return (P1). `poll` is not retried on a `4xx` other than `408` and `429`; §16
applies to those, to transport errors and to `5xx` (contract 1.59,
[§34.2](#§342-clarifications-normative-from-159) P1, P2, P7).

**Names.** `verify_set` and `poll` on an `ssf` receiver handle, not on the §27 `ssf`
management namespace (the two are different audiences, §32):

| Canonical | Rust | TypeScript | Python | Java | C# | PHP | Go |
|---|---|---|---|---|---|---|---|
| `ssf.verify_set` | `SsfReceiver::verify_set` | `SsfReceiver.verifySet` | `SsfReceiver.verify_set` | `SsfReceiver.verifySet` | `SsfReceiver.VerifySetAsync` | `SsfReceiver->verifySet` | `SsfReceiver.VerifySet` |
| `ssf.poll` | `SsfReceiver::poll` | `SsfReceiver.poll` | `SsfReceiver.poll` | `SsfReceiver.poll` | `SsfReceiver.PollAsync` | `SsfReceiver->poll` | `SsfReceiver.Poll` |

Both perform I/O (a JWKS fetch can happen inside `verify_set`), so §27.3's async discipline
applies. An SDK MAY offer a synchronous `verify_set` that takes an already-fetched JWKS.

### §32.8 Required tests

**Management namespace** — six per SDK that ships it, against a mocked HTTP server:

1. **Replacement.** `update_stream` sends `PUT` with every `SsfStreamInput` member it models;
   the input cannot be built without `receiver_client_id`, `audience`, `delivery_method` and
   `events_allowed`; a `200` decodes to `SsfStream`.
2. **The header is Sensitive.** `authorization_header` set from a runtime value is sent in the
   body and absent from every stringification of the input; an `SsfStream` body that (wrongly)
   carries `"authorization_header": "<value>"` decodes to a value whose every stringification
   lacks it, and the type has no accessor for it.
3. **Open decoding.** An `SsfStream` with an unknown `status`, `delivery_method`,
   `subject_format`, `status_actor` and an unknown event-type URI decodes, and so does one
   with `transmitter_active: false` and a `transmitter_inactive_reason`, and one without the
   reason.
4. **Pagination.** `list_streams` returns `Page<T>` with `total`; the auto-pager carries
   `search` on every request.
5. **No retry.** A `503` to each of the three writes: exactly one request, `NetworkError`.
6. **Errors.** `400` → `ValidationError` with the `message`; `409` on `create_stream` →
   `ConflictError`; `404` on `get_stream` → `NotFoundError`; `401` → `AuthError`.

**Receiver helper** — eight per SDK that ships it, with an Ed25519 key the test generates and
SETs the test signs (no key literal):

1. A SET signed by the JWKS key verifies, and every field of the result is the claim's.
2. `typ` absent or `JWT` → `invalid_type`; `alg` `none` or `HS256` → `invalid_key`.
3. A signature by another key, and a tampered payload → `invalid_key`.
4. Another `iss` → `invalid_issuer`; another `aud` → `invalid_audience`.
5. `exp` present, `sub` present, two events, no `jti` → `invalid_request`.
6. The same SET twice → the second `replayed`; a replay window below seven days is refused at
   configuration. A store that **cannot answer** for a SET (contract 1.60,
   [§34.2](#§342-clarifications-normative-from-159) P4) → `verify_set` raises the §2 type with no
   reason code, and `poll` returns that SET in neither `events` nor `refused`, does not record its
   `jti` and does not put it in `ack`.
7. An unknown `kid` → exactly one JWKS refetch, then `invalid_key`; a second unknown `kid`
   within the minute → no refetch. The first SET on an empty cache fills it, and a fill that
   **succeeds** is not a refetch (so an unknown `kid` right after it is refetched once); a fill
   that **fails** counts, so the next SET within the minute makes no fetch and is left unjudged
   (contract 1.60, [§34.2](#§342-clarifications-normative-from-159) P6).
8. `poll` sends `ack` and `set_errs` exactly as given, returns verified and refused SETs apart,
   acknowledges nothing on its own, and is not retried on `400`. **And a batch of two** whose
   second SET names an unknown `kid` while the refetch fails: afterwards the first SET's `jti` is
   not in the store, or the first SET is returned in `events` (contract 1.59,
   [§34.2](#§342-clarifications-normative-from-159) P1).

The server task adds its own tests for §32.3 and §32.6; they are not an SDK's to duplicate.

### §32.9 What an SDK does not do

It does not transmit, sign or register streams through the SSF protocol (`POST
/ssf/v1/stream` is `403`); it does not generate a client for the stream management API or the
poll endpoint beyond `poll`; it does not trust a SET it did not verify, and it never verifies
one against a key it did not fetch from the configured `jwks_uri` (no `jwk` or `x5c` header
member is honoured); it does not cache a stream's configuration (§27.4 rule 10).

### §32.10 Per-SDK posture

**All eleven SDKs implement §32 and the §32.7 receiver helper**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge. The helper is a SHOULD in
the seven full-surface SDKs and a MAY in Kotlin, Swift, C and C++, all four of which took it. Each
states "§27 and §32" for the namespace and "§32.7" for the helper. Every helper refuses a replay
and a window under seven days (§32.8 helper test 6), which is what closed T-388; every `poll` also
carries R-1, fixed by P1 and the follow-ups.

| SDK | §32 namespace | §32.7 helper | Notes |
|---|---|---|---|
| Rust | **implemented** | **implemented** | `SsfReceiver::{verify_set, poll}`; store interface infallible: R-4 (F-59-01). 1.60 port: `ReplayStore::check_and_record` becomes fallible — a breaking change released with 1.0.0 (D-7) |
| TypeScript | **implemented** | **implemented** (Node) | Namespace error body: R-18 (F-59-02). 1.60 port: a failed cold-cache fill counts toward the once-a-minute limit and the key cache expires (R-8); verify that a store failure raises and is never `replayed` (P4) |
| Python | **implemented** | **implemented** | `SsfReceiver` and `AsyncSsfReceiver`; the store is synchronous under both (R-41). 1.60 port: a failed cold-cache fill counts (R-8); an unknown union arm keeps its discriminator only (R-20) |
| Java | **implemented** | **implemented** | Event types a closed enum: R-22; transport re-send: R-17 (F-59-04). 1.60 port: an unseen event-type URI round-trips (P12.2); `SamlSpMetadataDraft` decode: R-27 |
| Kotlin | **implemented** | **implemented** (MAY) | JWKS cache never expires: R-8; closed event-type enum: R-22 (F-59-08). 1.60 port: a failed cold-cache fill counts (R-8); the local refusal is `ValidationError` (P12.2) |
| C# | **implemented** | **implemented** | Pluggable `IReplayStore`, fail closed; 1.60 port: verify that a store failure raises and is never `replayed` (P4) |
| PHP | **implemented** | **implemented** | Undeclared `ext-sodium`: R-33 (F-59-06). 1.60 port: the `poll()` docblock and README example acknowledge a `replayed` SET (R-2, P2) |
| Go | **implemented** | **implemented** | Store interface infallible: R-4 (F-59-07). 1.60 port: the store interface becomes fallible (an `error` return, P4) |
| Swift | **implemented** | **implemented** (MAY) | Non-throwing store: R-4; event types an enum: R-22 (F-59-09). 1.60 port: a throwing store (P4); `SsfStream.status`, `deliveryMethod` and `subjectFormat` refuse `.unknown` on encode (R-22) |
| C | **implemented** | **implemented** (MAY) | Function-pointer store with a failure channel, fail closed; 1.60 port: verify that a store failure is no verdict (P4) |
| C++ | **implemented** | **implemented** (MAY) | Closed event-type enum: R-22; a failed first fetch not rate-limited: R-8 (F-59-11). 1.60 port: an unseen event-type URI round-trips and the local refusal is `std::invalid_argument` (P12.2); verify that a store failure is no verdict (P4) |

## §33 CIBA — client-initiated backchannel authentication (contract 1.58)

**Requirement level: SHOULD in the seven full-surface SDKs (Rust, TypeScript, Python, Java, C#,
PHP, Go) and MAY in Kotlin, Swift, C and C++. Additive; nothing in §1–§32 changes, with one
exception, an in-place amendment of §21.3.1 (below) that every SDK pinning that vector must
re-vendor.** Server design: plan item G-7 and decisions D-56 and D-61 … D-70 in the plan's
decision table
([`competitor-gap-remediation-plan-2026-10-02.md`](../claude_dev/competitor-gap-remediation-plan-2026-10-02.md)
§8). Threat model: the G-7 entries, T-421 onward. (The plan first named this section §32; SSF
took that number in contract 1.56 and D-56 gave CIBA §33. §31, outbound SCIM, arrived in 1.57,
so 1.58 is the version that follows it.) Operator documentation: the website's *Integrate* page
**CIBA (backchannel authentication)**.

AXIAM can act as an **OpenID Connect CIBA authorization server** (CIBA Core 1.0; competitor-gap
item G-7) in **poll** and **ping** mode, the two modes FAPI-CIBA allows. A **client** — a call
centre's back-office system, a bank's teller application, a kiosk, a service that must have a
person confirm an action — that already knows whom it wants to authenticate asks AXIAM, over a
client-authenticated call, to authenticate that user **on another device**. AXIAM stores a
pending request and tells the user (a mail, with a link to the approval page of the console);
the user signs in, completes any step-up the request asked for and approves or refuses; the
client then collects the tokens by polling the token endpoint, or is *pinged* when the request
was decided and polls once.

Two audiences use this, and they are not the same code. The **user** approves on the console
page `/ciba/approve`, behind a human session and a CSRF check (`GET`/`POST
/api/v1/ciba/requests/{id}[/approve|/deny]`; a token AXIAM minted for an OAuth2 client — from the
code, refresh or CIBA grant — is `403` there even though it names the user, amended in place by
the W5 F4 review, T-447); that page is the console's job and **is not SDK
surface** — it is excluded from the management registry (tag `ciba`) and §33.9 says an SDK never
approves. The **client** is what this section covers: the **initiation helper** and the helpers
around it (§33.1). Nothing here is a §27 namespace, so contract 1.58 adds **no operation to the
management registry** and no row to §27.5; the three values that need `Sensitive<T>` are in
§33.5.

**Status: the routes exist.** T23.7.1 added `POST /oauth2/bc-authorize` and the CIBA grant at the
token endpoint, T23.7.2 the approval API, the mail and the ping; `openapi.json` was regenerated
in those tasks, and this revision (T23.7.3) changes no route. An SDK implements §33 from the
merge commit that carries them (§7 rule 1 of the plan; the 1.49 rule), in the post-merge
fan-out (D-35); none had when this was written (§33.10).

**§21.3.1 is amended in place: the seventh alias (contract 1.58).** `backchannel_authentication_endpoint` is a **seventh** member of `mtls_endpoint_aliases`
(D-61): a `tls_client_auth` CIBA client — the FAPI-CIBA shape — authenticates at `bc-authorize`
exactly as at the token endpoint and has no other way to present its certificate on a
two-listener deployment. §21.3.1 vector A, the assertions table beside it and §21.3 rule 2 now
say **seven**, and vector A carries the endpoint both at the top level and in the alias object.
No SDK change beyond the vector is needed *unless the SDK's test pinned the six keys*: such a
pin fails against a server that publishes seven, and the fix is to re-vendor `CONTRACT.md` and
update the pin. An SDK that decodes the member as an open map (§21.10's "decodes") already
tolerates the seventh.

### §33.1 Operations

Four operations on the client's OAuth2 handle. The first three are **wire calls**; the fourth is
a pure helper that does no I/O. All four are SHOULD in the seven full-surface SDKs.

| Canonical operation | Wire call | Request | Success |
|---|---|---|---|
| `ciba_initiate` | `POST /oauth2/bc-authorize?tenant_id=<uuid>` (or `/t/{tenant_id}/oauth2/bc-authorize`, the tenant-path form, when the SDK was configured with one) | `application/x-www-form-urlencoded` / `CibaInitiateRequest`, or the one-member signed form (§33.2) | `200` `CibaInitiateResponse` |
| `ciba_poll` | `POST /oauth2/token?tenant_id=<uuid>` with `grant_type=urn:openid:params:grant-type:ciba` and `auth_req_id` | `application/x-www-form-urlencoded` / `TokenRequest` | `200` `TokenResponse`, or one of the typed non-terminal and terminal answers of §33.3 rule 6 |
| `ciba_await` | `ciba_poll` repeated under §33.7 | — | `200` `TokenResponse` |
| `ciba_handle_ping` | none — the client's own HTTP endpoint receives the call | the ping's headers and body (§33.2) | the `auth_req_id` the ping names |

`ciba_initiate` and `ciba_poll` follow the §12.1 wire rules unchanged: form-encoded bodies,
`tenant_id` as a **query** parameter and never a body field, `X-Tenant-ID` still emitted per §5
rule 2, and **the client authenticates by the method it registered** — the same credential and
the same code path the SDK already uses for `/oauth2/token` (§12.1 rule 4 as amended by SEC-093,
§21.3 for an mTLS client, §21.8 for `private_key_jwt`). A CIBA client is **never** public
(§33.3 rule 1), so unlike `device_authorize` (§14.1) both calls carry client authentication, and
an SDK constructed with no credential MUST raise `AuthError` client-side, without a wire call,
rather than send an anonymous request. The discovery document publishes the endpoint as
`backchannel_authentication_endpoint` (§21.5's table gains the CIBA members); an SDK that already
holds a discovery document (§12) SHOULD use that URL, preferring the `mtls_endpoint_aliases`
entry on an mTLS call (§21.3 rule 2), and one that does not builds the path as §14.1 builds its
own. Either way it MUST NOT synthesise an alias.

**`ciba_await`** (SHOULD, a convenience) takes the `CibaInitiateResponse` and polls to a
terminal outcome, honouring §33.7. It surfaces **nothing to the user**: unlike `device_login`
(§14.3) there is no user code or verification URI for a CIBA client to display — the user is
notified by AXIAM — so there is no "display before polling" step and no callback. It returns the
token set; whether the SDK also adopts it as the client's own credential follows the same
posture as `login_client_credentials` and `device_login` (§14.3 rule 4), and an SDK MUST NOT
invent a second one. An SDK in **ping** mode does not loop: it calls `ciba_poll` **once**, from
the handler that received the ping (below).

**`ciba_handle_ping(headers, body, expected_token) → auth_req_id`** is the receiving half of ping
mode. It is a pure function over the raw request an HTTP framework handed the application:

1. The `Authorization` header is exactly the scheme `Bearer` (compared case-insensitively,
   RFC 9110 §11.1) followed by one space and the client's `client_notification_token`. The
   comparison of the token MUST be **constant-time**. Any other header, a missing header, or a
   second `Authorization` header is refused (`AuthError`, with a message that names no value).
2. The body is a JSON object with an `auth_req_id` that is a non-empty string and **no other
   member the helper acts on**. Anything else is refused (`ValidationError`).
3. It returns the `auth_req_id` as `Sensitive<T>` (§33.5). It does **not** call the token
   endpoint: the ping says only that the request was *decided*, never how (§33.2), so the
   application calls `ciba_poll` and learns the outcome — tokens, `access_denied` or
   `expired_token` — from the token endpoint, which is also where the single-use redemption is
   arbitrated.
4. It does not verify that the `auth_req_id` is one this client issued; the token endpoint
   already answers `invalid_grant` for any other (§33.3 rule 8). An SDK MAY offer a pluggable
   set of the `auth_req_id`s it has issued, and an SDK that does MUST NOT treat a miss as proof
   of anything: the helper still returns, because a restart loses an in-memory set.

The helper never answers the HTTP request itself, and it never retries or redelivers: the
**server** retries (§33.3 rule 13). The application's handler SHOULD answer `204` or `200` as
soon as the bearer check has passed and do the `ciba_poll` after it has answered — AXIAM treats
any `2xx` as delivered and any `408`, `429`, `5xx` or timeout as a reason to retry, and a ping
that triggers a slow redemption inside the request is a ping that times out and is delivered
twice.

### §33.2 Shapes (normative)

**`CibaInitiateRequest`** — the members the SDK sends. Field names are the wire's:

| Field | Type | Required | Notes |
|---|---|---|---|
| `scope` | string, space-separated | yes | Must include `openid`; every value must be one the client registered, else `invalid_scope`. |
| `login_hint` | string | one of the two hints | A username, then an e-mail address, within the tenant. At most 256 bytes. |
| `id_token_hint` | string | one of the two hints | An ID token **this deployment issued to this client**; its expiry is not checked, it names the user only. An SDK MUST NOT send both hints. |
| `binding_message` | string | no — **yes** for a `fapi2` client | At most 64 printable characters, no control or bidirectional-override characters. Shown to the user on the approval page as text; it is what lets the user tell the request they started from one an attacker did. |
| `requested_expiry` | integer seconds, sent as a string | no | 30 to 600. Absent means 300. |
| `acr_values` | string, space-separated | no | At most 8 values of at most 128 bytes. A value naming a class the approving session has not achieved makes the user step up before approving. |
| `resource` | string | no | RFC 8707, subject to the client's `allowed_resources`. |
| `client_notification_token` | string | **yes in ping mode** | The bearer the server presents at the ping. 1 – 1 024 visible ASCII characters; **at least 22 for a `fapi2` client**. Sealed on the server and never returned. |

`login_hint_token`, `user_code` and `request_uri` are **not** members: the server refuses each
(§33.3 rule 3), and an SDK MUST NOT offer a parameter for any of them. The client
authenticates as §33.1 says; for the client's own `client_id`, `client_secret` or assertion
members see §12.1 and §21.8.

**The signed form.** A client registered with
`backchannel_authentication_request_signing_alg` (`PS256`, `ES256` or `EdDSA`) MUST send **every**
request as a single `request` member, a JWS (CIBA Core §7.1.1) signed under exactly that
algorithm with a key of its registered `jwks` / `jwks_uri`, **and nothing else beside it**
except the client's authentication. Its claims are every member of the table above *inside* the
JWT, plus:

| Claim | Rule |
|---|---|
| `iss` | the `client_id` |
| `aud` | the issuer, in the form the call is made against (the deployment root, or the tenant-path issuer), as a string or a one-element array |
| `exp`, `nbf`, `iat` | all three required; `exp − nbf` at most 60 minutes and `nbf` at most 60 minutes old; the server allows 60 seconds of skew |
| `jti` | required and **single-use**: a second request with the same `jti` is refused |

An SDK that offers the signed form MUST take the key and the algorithm from the caller, MUST NOT
default either, MUST NOT choose an algorithm other than the one the caller names, and MUST NOT
send any authentication-request parameter beside `request` (the server refuses it as
`invalid_request` before authenticating). It reuses the JOSE machinery of §21.8's
`private_key_jwt` where it has it, and an SDK without that machinery MAY decline the signed form
(it then cannot be a `fapi2` CIBA client, §33.3 rule 10) with the documentation and test that
§21.7.3's declining requires. A client that registered **no** signing algorithm MUST NOT send a
`request` at all: the server refuses it.

**`CibaInitiateResponse`** — `{ auth_req_id, expires_in, interval }`:

| Field | Type | Notes |
|---|---|---|
| `auth_req_id` | string | 256 bits, base64url (43 characters today; an SDK MUST NOT parse or length-check it). **`Sensitive<T>`** (§33.5). |
| `expires_in` | integer seconds | The request's lifetime; **authoritative** (§33.7 rule 4). |
| `interval` | integer seconds | The minimum time between token requests: **5** today. §33.7 rule 2. |

**The ping.** After the user **approves or refuses**, AXIAM sends — for a client registered in
`ping` mode — one `POST` to the `backchannel_client_notification_endpoint` the client registered:

```http
POST /ciba/notify HTTP/1.1
Host: client.example
Content-Type: application/json
Authorization: Bearer <client_notification_token>

{"auth_req_id":"<the same auth_req_id the initiate response returned>"}
```

The body has **one member**, and the ping is **identical after an approval and after a
refusal**: the client learns that the request was decided, never how, and finds out at the
token endpoint. It carries no token and no user data. The `Authorization` value is the
`client_notification_token` the client supplied in the **request** that created that
`auth_req_id`; it is not a secret the server minted.

**`TokenResponse`** is the §12 token set (`access_token`, `token_type`, `expires_in`, `scope`,
`id_token`, and a `refresh_token` only for a client holding the `refresh_token` grant), with the
CIBA specifics of §33.3 rule 9. `ciba_poll` returns it on `200`, and otherwise raises the
errors of §33.4.

### §33.3 Server rules every SDK can observe (normative)

These are the server's, tested there; they are listed because each is something an SDK
**observes** and must not paper over or contradict.

1. **A CIBA client is registered, confidential, and poll or ping.** The grant
   `urn:openid:params:grant-type:ciba` and `backchannel_token_delivery_mode` (`poll` or `ping`;
   **push is not offered**) are set at registration — through the admin API
   (`POST`/`PUT /api/v1/oauth2-clients`, §27's `oauth2_clients`) or RFC 7591/7592. A ping-mode
   registration also names `backchannel_client_notification_endpoint`, an absolute `https` URL
   held to the webhook outbound address policy (no credentials, no fragment, no private,
   loopback or internal host). A client that is not confidential (any
   `token_endpoint_auth_method` but `none`) cannot hold the grant. A call from a client that
   does not hold it is `unauthorized_client`.
2. **Client authentication is the token endpoint's, and it is audited like it.** A failure is
   the uniform `invalid_client` (`401`) and is recorded as `oauth2.client_auth_failed`; the
   registered method decides, never the request (SEC-093).
3. **Exactly one hint, and only two kinds.** Both, or neither, of `login_hint` and
   `id_token_hint` is `invalid_request`. **`login_hint_token`, `user_code` and `request_uri` are
   refused with `invalid_request`**: AXIAM defines no format for the first, has no per-user
   secret to check a user code against that is not the password, and never fetches a request
   (CIBA Core §7.1.1 defines the signed request by value). Discovery says
   `backchannel_user_code_parameter_supported: false` and an SDK MUST NOT send a user code.
4. **`unknown_user_id` is never sent** (D-63). A hint that names nobody, a user who may not
   sign in, or a user under brute-force lockout is answered **exactly like a real one**: a
   stored request, an `auth_req_id`, `expires_in` and `interval`. Nobody is notified, nothing
   can approve it, and the client polls `authorization_pending` until `expired_token`. **A
   successful `ciba_initiate` therefore proves nothing about the user**, and an SDK MUST NOT
   report that the user "exists" or "was notified"; it MUST NOT map any error to a
   "no such user" result either, because the server will never send one — a client that waits
   for it would wait for ever. The only thing that tells a client a user did not answer is
   `expired_token`.
5. **Bounds, each an `invalid_request` unless noted:** `requested_expiry` outside 30 – 600
   seconds; `acr_values` over 8 values or 128 bytes each; `login_hint` over 256 bytes;
   `client_notification_token` over 1 024 bytes or not visible ASCII; `scope` without `openid`;
   a `scope` value the client did not register is `invalid_scope`; a `resource` the client may
   not name is `invalid_target`; a `binding_message` over 64 characters, empty after trimming,
   or carrying a control or bidirectional-override character is **`invalid_binding_message`**
   (CIBA Core §13, new). An SDK MAY pre-check none of them: the server's bounds are the
   authority and a client-side copy drifts (the reason §27.4 rule 4 gives for its `search`
   cap).
6. **The token endpoint's answers (CIBA Core §11), each a `400` with an `OAuth2ErrorResponse`
   body** (dispatch on the `error` field, §2):

   | `error` | Meaning | SDK behaviour |
   |---|---|---|
   | `authorization_pending` | the user has not decided | non-terminal: keep polling at the current interval |
   | `slow_down` | polled inside the interval | non-terminal: **add 5 s to the interval**, permanently (§33.7 rule 3) |
   | `access_denied` | the user refused | terminal, distinct from `expired_token` |
   | `expired_token` | the request's lifetime ran out | terminal |
   | `invalid_grant` | unknown, another client's, another tenant's, or **already redeemed**; also a user who may no longer act or is locked out | terminal |
   | `invalid_client`, `unauthorized_client`, `invalid_request` | the call itself was refused | terminal, with §2's mapping |

   **`slow_down` is answered for any request inside the interval, whatever its state** — an
   *approved* request polled too early is `slow_down`, not tokens. A client that polls on a
   timer faster than `interval` is therefore throttled even after the user approved, and the
   interval it must then respect has grown (rule 7).
7. **The interval is the server's, and it grows.** It starts at 5 s; each early poll adds 5 s,
   to a ceiling of 60 s. The `slow_down` answer carries no `interval`: the client keeps its own
   count and adds 5 s (§33.7 rule 3).
8. **Single-use, and a request belongs to one client in one tenant.** An approved request is
   redeemed **once**: the second token request for it — sequential or concurrent — is
   `invalid_grant`, and exactly one of two concurrent redemptions receives tokens. Another
   client's `auth_req_id`, another tenant's and an unknown one are all `invalid_grant`, and
   nothing is written for them.
9. **Tokens carry the approval's evidence.** An ID token is **always** issued, with `auth_time`,
   `amr` and `acr` taken from the session the user approved with (D-67); there is no
   `urn:openid:params:jwt:claim:auth_req_id` claim (that is push mode's). The access token's
   `sid` names the approving session, so **ending that session ends the tokens**. A refresh
   token is issued only to a client holding the `refresh_token` grant. Sender-constraining
   follows the client's registration as for every other grant (§10.1 rule 9, §21): a `cnf` on
   the access token is the SDK's to honour, not to strip.
10. **The `fapi2` CIBA client** (D-61) holds the grant only if it registered
    `backchannel_authentication_request_signing_alg` (**admin API only**: RFC 7591 never
    registers a `fapi2` client), authenticates by `tls_client_auth`,
    `self_signed_tls_client_auth` or `private_key_jwt`, and receives sender-constrained tokens.
    Every request from it MUST be signed, carry a `binding_message`, and — in ping mode — a
    `client_notification_token` of at least 22 characters. A row edited to drop the algorithm
    gets `unauthorized_client`; one edited to a shared secret gets `invalid_client`.
11. **Dynamic registration is initial-access-token only** (D-62): RFC 7591 can register the
    CIBA grant only with an initial access token (§28.12, `oauth2_clients.create_registration_token`),
    never anonymously, and a CIBA-only client needs no redirect URI. `backchannel_user_code_parameter: true`
    is refused at registration.
12. **Lockout applies to this grant** (D-69, the class of defect Keycloak 26.7.x had, where a
    brute-force lockout did not cover CIBA): the user's lockout and ability to act are checked
    at `bc-authorize` (the request becomes a decoy, rule 4), at approval, and **again at
    redemption** — after which a locked user's approved request is spent and answers
    `invalid_grant`. There is no client lockout keyed on a caller-supplied `client_id`: a stranger
    cannot lock a real client out.
13. **Limits.** `POST /oauth2/bc-authorize` has a rate-limit bucket of its own
    (`AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN`, 60 by default, in the machine presets) keyed like
    `/oauth2/token`, plus a per-client bucket after authentication; the CIBA grant is counted by
    the token endpoint's bucket and by each request's own interval. A `429` carries
    `{"error":"rate_limit_exceeded"}`, which is not an RFC 6749 §5.2 code: §2's rows decide it as
    for every other `/oauth2/*` call, it is **never terminal** for `ciba_poll` (§33.7 rule 5) and
    is **never retried** for `ciba_initiate` (§33.7 rule 1). A user is sent
    at most **three** notifications a minute whatever the clients asking, and a request past that
    is stored and answered as usual: the user is simply not told again, which a client cannot see.
14. **Expiry and retention.** `expires_in` is 300 s unless `requested_expiry` says otherwise.
    An expired request is marked, and deleted **ten minutes later**, so a late poll gets
    `expired_token` and a very late one `invalid_grant`. Erasing the user, or the tenant,
    removes its requests.
15. **The ping is the dispatcher's** (informative): queued after approval **and after denial**,
    carrying the request's record id only; the deliverer re-reads the request and the client,
    opens the sealed credentials and `POST`s through the outbound SSRF guard (`https`, the
    address must be globally routable, **a redirect is never followed**): `2xx` is delivered;
    a redirect, `408`, `429`, `5xx`, a timeout or no answer is retried on the dispatcher's
    schedule (`AXIAM__CIBA_PING__*`: 5 attempts, 5 s base, one hour ceiling by default); any
    other `4xx` is dead-lettered — the endpoint or the token is wrong until someone fixes it.
    A ping that never arrives is not a failed request: `ciba_poll` still works, and a ping-mode
    client SHOULD poll at `interval` after `expires_in / 2` as a fallback (§33.7 rule 6).
16. **Approval is not the SDK's.** The user decides on the console page; the approval API needs
    a human session and a CSRF token and answers one indistinguishable `404` for an unknown,
    another user's, expired, decided or changed-since-read request (D-68). A service principal
    or a client credential cannot approve. *(Contract 1.60, informative.)*
    `GET /api/v1/ciba/requests?status=pending` lists the signed-in user's own pending requests
    (client name, binding message, scopes, requested `acr`, expiry, and the `request_id` and
    `version` the approval page uses; never the `auth_req_id`) so that an account that is sent no
    approval mail can find a request. It is a console surface, not an SDK surface, under the
    approval routes' rules: a console sign-in only (a token carrying `client_id` is `403`), a
    rate-limit bucket of its own in `ciba_approval_per_min`; only `status=pending` is supported
    (any other value is `400`). Its tag is `ciba`, excluded from the registry.

### §33.4 Error mapping

§2 and §12.3 rule 3, unchanged: a body with an `error` member is `OAuthProtocolError`
(dispatched on `error`, at any status), with the mapping of §33.3 rule 6 deciding what is
terminal. `ciba_poll` MUST surface **`access_denied` and `expired_token` as distinct typed
outcomes** (§14.2 rule 3's reasoning: a human said no, or nobody answered, and the client acts
differently on each). `invalid_binding_message` is an `OAuthProtocolError` like any other and
MUST be surfaced with its `error_description`. `401` with an `OAuth2ErrorResponse` is **not** a
session expiry: it MUST NOT enter the §9 refresh guard (§12.3 rule 3). `400` without an
`error` member, `403` without one, and `5xx` map by status as in §2; `503` is
`NetworkError`, and a `429` is handled as §33.3 rule 13 says. **On `ciba_poll` a `5xx` is transient
whatever its body** — AXIAM's own token endpoint answers `500 {"error":"server_error"}` — and the
§9 exemption covers the tenant-path form of the endpoint too (contract 1.59,
[§34.2](#§342-clarifications-normative-from-159) P8, P11). `ciba_handle_ping`'s refusals are `AuthError` (the bearer) and `ValidationError`
(the body) and never reach the network.

### §33.5 `Sensitive<T>` applicability

Three values MUST be `Sensitive<T>` (§7) from the first version an SDK ships this section:

- **`auth_req_id`** — in `CibaInitiateResponse`, in `ciba_poll`'s and `ciba_await`'s input, and
  in `ciba_handle_ping`'s result. It is a **bearer credential for the grant**: whoever holds it
  and the client's credential can poll for the tokens of an approved request, and the mail that
  tells the user carries only the request's record id, never this value. The same rule applies
  to the `request` JWT form of the initiate call, whose members include the notification token.
- **`client_notification_token`** — in `CibaInitiateRequest` (and inside a signed `request`) and
  as `ciba_handle_ping`'s `expected_token`. It is the secret the *server* presents to the client
  to prove a ping is AXIAM's; anyone who learns it can make the client act on a forged ping, and
  anyone who can read it from a log can do so for as long as the request lives.
- **The signed request's key material** — the private key or key handle behind `request`,
  exactly as §21.8 treats `private_key_jwt` keys. A signed `request` string is itself wrapped
  wherever the SDK would otherwise hold it as a plain string.

§7 rule 1's redaction covers every stringification sink; §27.4 rule 11 keeps these out of §19
telemetry; an error raised by any of the four operations MUST NOT contain them, a prefix or a
hash of them. An SDK MUST NOT cache them, persist them, or keep them after the request that
carried them (`ciba_await` keeps the `auth_req_id` in memory for the length of its loop and no
longer). Nothing else in §33 is wrapped (§27.5 rule 2): `binding_message`, `login_hint`,
`acr_values`, `scope` and the bounds are not secrets — though `binding_message` and `login_hint`
can be personal data, so an SDK MUST NOT write them to a log line at any level it does not
already treat as application data (§19). **`TokenResponse`'s tokens are §7's, unchanged.**

### §33.6 Per-language naming map

§1's conventions apply; the helper hangs off the handle that already carries `oidc_exchange` and
`device_authorize`:

| Canonical | Rust | TypeScript | Python | Java | C# | PHP | Go |
|---|---|---|---|---|---|---|---|
| `ciba_initiate` | `ciba_initiate` | `cibaInitiate` | `ciba_initiate` | `cibaInitiate` | `CibaInitiateAsync` | `cibaInitiate` | `CibaInitiate` |
| `ciba_poll` | `ciba_poll` | `cibaPoll` | `ciba_poll` | `cibaPoll` | `CibaPollAsync` | `cibaPoll` | `CibaPoll` |
| `ciba_await` | `ciba_await` | `cibaAwait` | `ciba_await` | `cibaAwait` | `CibaAwaitAsync` | `cibaAwait` | `CibaAwait` |
| `ciba_handle_ping` | `ciba_handle_ping` | `cibaHandlePing` | `ciba_handle_ping` | `cibaHandlePing` | `CibaHandlePing` | `cibaHandlePing` | `CibaHandlePing` |

The first three perform I/O, so §27.3's async discipline applies and Java gains its `*Async`
companions, Kotlin (when it ships the helper) uses `suspend`, and Python exposes the names on
both `AxiamClient` and `AsyncAxiamClient`. `ciba_handle_ping` performs no I/O and is synchronous
everywhere (C# included, hence no `Async` suffix). The four SDKs outside the table that
ship it (MAY) follow §1 for their own casing.

### §33.7 Retry and polling (normative)

§16's policy governs the transport, and **§33 narrows it**:

1. **`ciba_initiate` MUST NOT be retried — on any status or transport error.** It is not
   idempotent: each accepted call stores a pending request, may send a person a sign-in
   prompt, and spends the client's own rate budget. A lost answer is a request the client does
   not know it made; the client's recourse is to let it expire (the user was told at most once)
   and ask again deliberately. This is the *opposite* of `device_authorize`, which creates
   nothing a person is notified about.
2. **The first poll waits for `interval`.** The initial interval is the response's `interval`,
   or **5 s** when the field is absent; an SDK MUST NOT hard-code a faster floor.
   Polling a request inside its interval earns `slow_down` and a **longer** interval, so a client
   that polls immediately after `ciba_initiate` has made its own wait longer for nothing.
3. **`slow_down` raises the interval by 5 s, permanently, and the increase is cumulative.**
   The answer carries no value, so the client counts: `interval += 5` per `slow_down`,
   never reset by a later `authorization_pending`. The server's ceiling is 60 s; an SDK MAY stop
   increasing at 60 s but MUST NOT shorten an interval it has raised.
4. **Polling stops at `expires_in`.** The deadline is `initiate time + expires_in`, authoritative
   (§14.2 rule 4): an SDK MUST NOT poll past it even if the server has not yet answered
   `expired_token`, and raises the same typed `expired_token` outcome locally when it stops.
5. **A `5xx` or transport failure on `ciba_poll` is not terminal.** It is retried under §16 for a
   read-only call, per poll attempt and separately from the loop's own deadline: an approved
   request must survive a server restart. A `429` on `ciba_poll` is waited out the same way and
   counts as one interval, never a reason to poll faster afterwards. A `5xx` is transient whatever
   its body, and anything that fails after a `2xx` is terminal (contract 1.59,
   [§34.2](#§342-clarifications-normative-from-159) P8 – P10). **A §16 retry's wait is bounded by
   rule 4's deadline** (contract 1.60, P10): `Retry-After` is a minimum wait, capped at the
   deadline, and nothing is sent after it.
6. **Ping mode.** A ping-mode client does not poll on a timer. It calls `ciba_poll` once when a
   ping arrives (`ciba_handle_ping`), once more at `interval` if that answered `slow_down` or
   `authorization_pending`, and SHOULD fall back to the polling loop of rules 2 – 5 once half of
   `expires_in` has passed without a ping: a ping is delivered at least once, never exactly once,
   and may not arrive at all (§33.3 rule 15).
7. **A request is redeemed once.** After tokens are returned, `ciba_poll` for the same
   `auth_req_id` is `invalid_grant`; an SDK MUST NOT re-issue the call "to be safe", and MUST
   NOT treat the second `invalid_grant` as a failure of the first redemption. In particular, a
   transport failure **after** the server committed the redemption cannot be retried to get the
   tokens back — a retry returns `invalid_grant` — which is why `ciba_poll`'s `200` must be
   consumed (stored) before anything else is done with the response.

### §33.8 Required tests

Against a mocked HTTP server, per SDK that ships the helper; the second group per SDK that
ships the signed form. No credential, key or token literal appears: the `auth_req_id`, the
notification token and the signing key are generated at run time.

**Initiation and polling** — nine:

1. **Redaction.** A `client_notification_token` made at run time, a `CibaInitiateResponse`
   carrying an `auth_req_id`, and an error raised by `ciba_initiate` given one, printed,
   debug-formatted and serialized for logs contain neither value nor any 8-character substring;
   both **are** on the wire.
2. **Client authentication is mandatory.** An SDK with no credential raises `AuthError` without
   a request; with one, `ciba_initiate` and `ciba_poll` send it by the registered method, and
   `tenant_id` goes in the query, never the body.
3. **The initiate request.** Exactly the members of §33.2 the caller set are sent, form-encoded;
   neither `login_hint_token`, `user_code` nor `request_uri` can be set; both hints at once is
   refused client-side; a ping-mode request without a `client_notification_token` is refused
   client-side (a ping client without one would receive nothing).
4. **No retry on initiate.** A `503`, a `429` and a dropped connection to `ciba_initiate`: exactly
   one request each; the `503` and the dropped connection are `NetworkError`, the `429` is
   whatever §2 gives it.
5. **Poll outcomes.** `authorization_pending` loops rather than raising; `slow_down` raises the
   interval and the raised interval **persists** (assert two `slow_down`s add 10 s and a later
   `authorization_pending` does not lower it); `access_denied` and `expired_token` are
   **distinct** typed outcomes; `invalid_grant` is terminal; an unknown `error` falls back to §2.
6. **The first poll waits.** The first `ciba_poll` of `ciba_await` is not sent before
   `interval` (from the response, or 5 s when absent) has elapsed, asserted with an injected
   clock rather than by sleeping.
7. **Deadline.** `ciba_await` sends no request after `expires_in` has passed and raises
   `expired_token` locally. A `503` with a `Retry-After` that reaches past the deadline makes the
   loop wait no longer than the deadline and send nothing after it (contract 1.60, P10).
8. **Transient failure is not terminal.** A `500` carrying `{"error":"server_error"}` and a `429`
   mid-loop are retried and the loop then succeeds; a `200` is returned with its `id_token` and
   `access_token` (contract 1.59, P8: the `500` carries the body the server sends).
9. **Single use.** After a `200`, a second `ciba_poll` for the same `auth_req_id` is surfaced as
   `invalid_grant` and **not** retried.

**The ping** — four:

10. A request with `Authorization: Bearer <the expected token>` and `{"auth_req_id": "…"}`
    returns that value, `Sensitive`; the scheme is accepted in any case.
11. A wrong, absent, empty or duplicated `Authorization`, a `Basic` scheme and a token differing
    in the **last** character are refused as `AuthError`; the comparison is constant-time
    (asserted structurally — the SDK calls its language's constant-time comparison — where the
    language has no timing harness).
12. A body that is not JSON, has no `auth_req_id`, or carries one that is not a non-empty string
    is refused as `ValidationError`; extra members are ignored, never acted on.
13. The helper makes **no network call**: run with the transport replaced by one that fails the
    test if touched.

**The signed form** — three:

14. **Shape.** The sent request has exactly one member besides client authentication, `request`;
    its header `alg` is the registered one; `iss` is the `client_id`, `aud` the issuer, `exp`,
    `nbf`, `iat` and `jti` are present with `exp − nbf` at most 60 minutes, and two requests have
    different `jti`s. The key is the caller's and signs under the caller's algorithm only.
15. **No defaulting, no mixing.** An SDK given no algorithm or no key refuses (no request is
    sent); given a form parameter as well, it refuses.
16. **Redaction.** The key material and the `request` string appear in no stringification.

The server task adds its own tests for every rule in §33.3; they are not an SDK's to
duplicate.

### §33.9 What an SDK does not do

It never **approves or refuses** a request: the approval API needs a human session and a CSRF
token, belongs to the console, and is excluded from the registry; an SDK MUST NOT offer an
`approve` or `deny` call, nor drive the approval page. It offers **no push mode** (the server
does not), **no `login_hint_token`**, **no `user_code`** and **no `request_uri`**; it does not
fetch or host a request object. It does not poll for the user's attention (the notification is
AXIAM's) or tell the user anything itself. It does not guess whether a user exists (§33.3 rule
4), does not pre-validate the server's bounds (rule 5), does not cache an `auth_req_id` or a
notification token beyond the call that needs it (§33.5), and does not retry `ciba_initiate`
(§33.7 rule 1). It does not pin discovery's `mtls_endpoint_aliases` to a fixed member count
(§21.3.1). `ciba_handle_ping` does not answer the HTTP request or call the token endpoint on the
application's behalf.

### §33.10 Per-SDK posture

**All eleven SDKs implement §33**, read by the contract 1.59 review ([§34](#§34-cross-sdk-conformance-review-of-the-phase-23-ports-contract-159)) at each repository's 2026-10-09 merge: the seven full-surface SDKs as the SHOULD, Kotlin, Swift,
C and C++ taking the MAY. Ten offer the §33.2 signed form with all three algorithms; PHP signs with
`ES256` and `EdDSA` and refuses `PS256` locally (P12.7). Every SDK pins §21.3.1 vector A at seven keys
and prefers the `backchannel_authentication_endpoint` alias for an mTLS client (§21.10, re-read).

| SDK | §33 | §33.2 signed | Notes |
|---|---|---|---|
| Rust | **implemented** | **implemented** — PS256, ES256, EdDSA | `ciba_await` treats a decisive error as transient: R-12; alias row untested: R-31 (F-59-01). 1.60 port: a §16 retry's wait is capped at the deadline (R-14, P10) |
| TypeScript | **implemented** (Node `OidcClient`) | **implemented** — PS256, ES256, EdDSA | Transient classification as P8 and P9 say |
| Python | **implemented** | **implemented** — PS256, ES256, EdDSA | `5xx` with a body ends the loop: R-11 (F-59-03); client authentication without `private_key_jwt` (R-39) |
| Java | **implemented** | **implemented** — PS256, ES256, EdDSA | R-11, R-12, R-16, R-19 (F-59-04); without `private_key_jwt` (R-39) |
| Kotlin | **implemented** (MAY) | **implemented** — PS256, ES256, EdDSA | R-11 (F-59-08) |
| C# | **implemented** | **implemented** — PS256, ES256, EdDSA | Tenant-path `401` re-sends the initiate: R-16 (F-59-05). 1.60 port: `ciba_initiate` goes on a connection that is not reused (P11, R-17) |
| PHP | **implemented** | **implemented** — ES256, EdDSA; PS256 declined | Claim to read "§33.2 signed (ES256, EdDSA)": R-32 (F-59-06) |
| Go | **implemented** | **implemented** — PS256, ES256, EdDSA | R-11 (F-59-07). 1.60 port: a §16 retry's wait is capped at the deadline (R-14, P10) |
| Swift | **implemented** (MAY) | **implemented** — PS256, ES256, EdDSA | Re-polls after an undecodable `200`: R-12; PS256 refusal-only test: R-31 (F-59-09) |
| C | **implemented** (MAY) | **implemented** — PS256, ES256, EdDSA | Injectable clock; not cancellable (P10). 1.60 port: `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on `ciba_initiate` (P11, R-17) |
| C++ | **implemented** (MAY) | **implemented** — PS256, ES256, EdDSA | R-11 (F-59-11). 1.60 port: `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on `ciba_initiate` (P11, R-17) |

## §34 Cross-SDK conformance review of the Phase 23 ports (contract 1.59)

The review that §28.10's rule and §28.12.7, §29.10 … §33.10 name: the eleven ports of contracts
1.53 – 1.58, read from each repository at its `claude/contract-1.58-sync` merge of 2026-10-09,
in the format of §28.11 (contract 1.49) and §27.14 (contract 1.52). The full evidence — the
checklist, the commit read in each repository, the test runs, and every cell with the file
and line behind it — is
[`claude_dev/sdk-phase23-ports-conformance-review.md`](../claude_dev/sdk-phase23-ports-conformance-review.md).
This section is the record. Contract 1.60 answers the questions the follow-up ports raised
([#588](https://github.com/ilpanich/axiam/issues/588)) in [§34.4](#§344-contract-160--answers-to-588-and-the-rows-assigned),
amends the rules and rows it names in place, and says so where it does.

### §34.1 What was read

Five sections, two helpers and one amended vector, in eleven repositories: §28.12, §29, §30,
§31 and §32 (the four management namespaces and RFC 7592, 190 operations across 28 namespaces),
the §32.7 receiver helper, §33 with its §33.2 signed form, and §21.3.1 vector A at seven keys.
For each section: the operations under the §NN.6 names, `Sensitive<T>` on every member §NN.5
names and on every sink, every §NN.8 required test by name and by what it asserts, the
call-site documentation, the retry guarantee, and the README conformance statement against
the code. Then ten questions asked of all eleven alike — the replay store, `verify_set`'s order,
`poll`, `ciba_await`'s clock and loop, `ciba_handle_ping`, the signed form, the kept secret on
update, the §21.3.1 pin, §28.12's URI and body, and anything else.

| SDK | Commit | Port |
|---|---|---|
| Rust | `53aa9ff` | [`axiam-rust-sdk#123`](https://github.com/ilpanich/axiam-rust-sdk/pull/123) |
| TypeScript | `ab1c5ee` | [`axiam-typescript-sdk#131`](https://github.com/ilpanich/axiam-typescript-sdk/pull/131) |
| Python | `db9fbd6` | [`axiam-python-sdk#93`](https://github.com/ilpanich/axiam-python-sdk/pull/93) |
| Java | `2b34d08` | [`axiam-java-sdk#108`](https://github.com/ilpanich/axiam-java-sdk/pull/108) |
| C# | `3b33515` | [`axiam-csharp-sdk#101`](https://github.com/ilpanich/axiam-csharp-sdk/pull/101) |
| PHP | `cec1594` | [`axiam-php-sdk#78`](https://github.com/ilpanich/axiam-php-sdk/pull/78) |
| Go | `ea9eb07` | [`axiam-go-sdk#93`](https://github.com/ilpanich/axiam-go-sdk/pull/93) |
| Kotlin | `611554d` | [`axiam-kotlin-sdk#72`](https://github.com/ilpanich/axiam-kotlin-sdk/pull/72) |
| Swift | `e92364c` | [`axiam-swift-sdk#70`](https://github.com/ilpanich/axiam-swift-sdk/pull/70) |
| C | `265f5b4` | [`axiam-c-sdk#69`](https://github.com/ilpanich/axiam-c-sdk/pull/69) |
| C++ | `3b949ab` | [`axiam-cplusplus-sdk#71`](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/71) |

Every repository ships every section in scope, the four REST-only SDKs included — they took
§32.7's and §33's MAYs — and every one carries the §NN.8 tests by name. Every suite that could
be built was green. The defects below sit where a required test asserts less than the rule it
discharges, which is why two required tests are amended here as well (§32.8 helper test 8 by P1, §33.8 test 8 by P8).

### §34.2 Clarifications (normative from 1.59)

Twelve rules. They bind behaviour, change no wire shape, and where they amend a sentence of an
earlier section that section now points here. Contract 1.60 amends P1, P4, P6, P10, P11 and P12
where marked *contract 1.60* and adds P12.9; [§34.4](#§344-contract-160--answers-to-588-and-the-rows-assigned)
lists every change.

**P1 — `poll` never keeps a `jti` it does not return (§32.7).** `ssf.poll` MUST NOT leave a
`jti` recorded in the replay store that it does not return in `events`. A failure that is not a
verdict on a SET — a JWKS or discovery fetch that fails, a store that cannot answer (P3) — leaves
that SET **unjudged**: it is in neither `events` nor `refused`, its `jti` is not recorded, and so
the caller does not acknowledge it and the transmitter offers it again. Two forms conform: run
steps 1 – 8 over the whole batch before recording any `jti`, and on a non-verdict failure raise
having recorded nothing; or return what was judged and leave the unjudged SETs unrecorded (an
SDK MAY list their `jti`s, and the list is named `unjudged` — *contract 1.60*). A store with one
atomic check-and-record and no un-record cannot undo a `jti` it recorded earlier in the batch, so
it uses the second form for the tail after its first record; that is a use of the second form,
not a third, mixed one. §32.8 helper test 8 gains a batch of two SETs whose second fails its
key fetch: afterwards the first SET's `jti` is not in the store, or the first SET is returned.

**P2 — a `replayed` SET on a later poll is acknowledged, not reported (§32.7).** A SET that
`poll` refuses as `replayed` was accepted by this receiver earlier. §32.7's "SHOULD pass each
refused one in `set_errs`" does not apply to it: the caller acknowledges it in `ack`, because
reporting an error for an event it accepted misinforms the transmitter, which removes the event
from its queue either way. The helper records a `jti` when it accepts the SET, so an application that crashes
between accepting and processing an event does not see it again; that durability is the
application's (a persistent store, processing before the next `poll`), not the helper's.

**P3 — what is not a verdict (§32.7).** A JWKS or discovery fetch that fails, and a replay store
that cannot answer, are not verdicts on the SET: `verify_set` raises the §2 type for the
failure (`NetworkError` for a transport failure or a `5xx`) and no reason code. A push endpoint
answers them with a `5xx`, never with `400 {"err": …}`, so that the transmitter retries
rather than dropping the event.

**P4 — the replay store (§32.7 step 9).** *Rewritten in contract 1.60.* A replay store has
three answers — seen, not seen, **cannot answer** — and its interface MUST be able to give the
third (a `Result`, an exception, an error return). A store that cannot answer gives **no
verdict**: the SET is neither refused nor accepted, it stays **unjudged** (P1), `verify_set`
raises the §2 type with no reason code (P3), and `poll` records nothing for it and does not
acknowledge it, so the transmitter offers it again; it is never accepted. Contract 1.59 let a
store interface that answers a bare `bool` conform if its documentation said to answer "already
seen" when it cannot answer; that route is **withdrawn**: it turned a store outage into a
`replayed` refusal, which P2 then acknowledges, so an event that was never processed was
lost. An interface that answers a bare `bool` does not conform from 1.60. For Rust,
`ReplayStore::check_and_record` becomes fallible, a breaking change released with 1.0.0 (D-7: a
1.0 is the place for it). The window is a bound in time; the default in-memory store MAY be
unbounded in count, and its README says so.

**P5 — RFC 8935 `err` values (§32.7).** `invalid_key`, `invalid_issuer` and `invalid_audience`
are sent as they are; `malformed`, `invalid_type`, `invalid_request` and `replayed` are all
answered as `invalid_request`, the only RFC 8935 code that covers them.

**P6 — key fetches (§32.7 step 4).** The fetch that fills an empty cache is not "the refetch":
step 4's one refetch is the one an unknown `kid` triggers on a cache that already holds a key
set. The once-a-minute limit is per receiver and counts every **refetch** and every **failed**
fetch, a failed fill included, so that a JWKS outage is not one fetch per SET: after a failed
fill a SET inside the minute makes no fetch and is left unjudged (P1, P3). *Contract 1.60:* a
**successful** fill is not counted — it is not a refetch — so an unknown `kid` right after a
successful fill is refetched once, and §32.8 helper test 7 passes. The cache SHOULD expire as
§10's JWKS cache does: a cache that never expires keeps verifying with a key the transmitter has
removed.

**P7 — what else `verify_set` and `poll` may check (§32.7).** `iat` is a JSON number; AXIAM
emits an integer and an SDK MAY refuse a non-integer as `invalid_request`. `sub_id` is an
object. `poll` MAY refuse a SET whose key in the poll response's `sets` map differs from its
`jti`, as `invalid_request`. `poll` is not retried on a `4xx` **other than `408` and `429`**,
which §16.3 retries.

**P8 — a `5xx` on `ciba_poll` is not terminal, whatever its body (§33.4, §33.7 rule 5).**
AXIAM's own token endpoint answers an internal failure `500 {"error":"server_error"}`, and a
`503 {"error":"temporarily_unavailable"}` is the same kind of answer. On `ciba_poll`, a `5xx` is
retried under §16 and never ends `ciba_await`, with or without an `error` member: §33.7 rule 5
prevails over §33.4's "at any status" and §16.3's `OAuthProtocolError` row, for this operation
only. §33.8 test 8's `500` carries `{"error":"server_error"}`.

**P9 — what ends `ciba_await` (§33.7 rules 5 and 7).** Only a transport failure, `408`, `429`
and a `5xx` are transient. A `4xx` without an `error` member is decisive (§2) and ends the loop.
Anything that fails **after a `2xx`** — a body that does not decode, an ID token that does not
validate, the key fetch that validation needs — is terminal: the redemption is spent (rule 7),
and polling again can only return `invalid_grant`. The SDK raises that failure and does not
poll again; under §12.4 the tokens of a redemption whose ID token cannot be validated are not
returned, so the application starts a new request.

**P10 — `ciba_await`'s time (§33.7 rules 2 – 4).** The deadline's anchor is either the instant
the initiate request was sent or the instant its response was received. The loop MAY stop when
the next poll would land past the deadline. The anchor and the waits SHOULD both come from the
injected clock that §33.8 test 6 uses. A §16 retry inside `ciba_poll`, as `ciba_await` calls it, MUST NOT
wait past the deadline — the SDK's anchor plus `expires_in`, `received_at + expires_in` at the
latest: `Retry-After` is a minimum wait capped at the deadline, a wait that ends at the deadline
is followed by no request, and `ciba_await` raises `expired_token` (§33.7 rule 4). *Contract 1.60:*
this binds now, and R-14 is amended; a bare `ciba_poll` has no deadline of its own and keeps §16's
bounded budget. An `interval` of `0` is treated as absent (5 s). Cancelling the loop is a MAY.

**P11 — no second request by another route (§12.3 rule 3, §16).** The §9 exemption of §12.3
rule 3, §28.12.2 rule 3 and §33.4 covers the OAuth2 endpoints **in both issuer forms** —
`/oauth2/…` and `/t/{tenant_id}/oauth2/…` — so an SDK recognises the endpoint, not one literal
path; a `401` on a tenant-path `bc-authorize` that enters §9 re-sends a request §33.7 rule 1
says is never sent twice. And "MUST NOT be retried" (§28.12.2 rule 5, §29.7, §30.7, §31.7, §32's
writes, §33.7 rule 1) includes an HTTP library's own transparent re-send after a dropped
connection, which an SDK MUST switch off for those requests. *Contract 1.60:* this binds every
SDK whose library has such a re-send, and the remedy where the library has no switch is a
**fresh connection per never-retried write** that is not reused afterwards: `CURLOPT_FRESH_CONNECT`
plus `CURLOPT_FORBID_REUSE` on those requests in C and C++; a non-pooled handler, or a handler
whose pooled connections are not reused, for them in C#. Test: a server that reads a write and
drops the connection unanswered receives that write **exactly once**.

**P12 — shapes and secrets (§28.12, §29 – §33).**

1. **Only declared members are kept** from a response, in a known union arm and in an unknown
   one: an unknown arm keeps its discriminator and nothing else (§29.5's rule, for §31.2's
   unions and for §30's and §32's responses as well).
2. **"MUST NOT send a value it does not know" binds the request path.** An SDK refuses such a
   value locally before sending — never as `""`, never by leaving the refusal to the server — and
   rendering it for a log line never fails. *Contract 1.60:* (a) the refusal is the SDK's
   validation error and no other category — the type §28.7 names for a local, pre-request
   refusal: `ValidationError` (a sub-type of `NetworkError`, §27.4 rule 7) in the nine SDKs that
   raise the §2 type there, `std::invalid_argument` in C++, `NULL` with its `axiam_error_t`
   out-parameter in C — never a bare `NetworkError`. (b) An event-type URI is not such a value
   (§32.2's SHOULD, strings, stands): it is sent as the string the caller holds, and one the SDK
   has never seen, read from the server, decodes with its value and is sent back unchanged on
   `update_stream`, the server judging it. An SDK that models event types as a closed enum
   (Swift, C++) keeps the original string of a value it read, and MAY refuse locally a URI the
   caller typed that is none of the six only if its documentation says so: a client-side list of
   URIs goes stale, which is why the stricter behaviour is permitted only when documented.
3. **A write-only secret is present or absent, never `null`.** `bind_secret`, `credential` and
   `authorization_header` are sent to replace the stored value and omitted to keep it; `null` is
   not a third state an SDK sends.
4. **§28.12.2 rule 4's replacement is built from what the read carried.** A member the read did
   not carry is not sent — no list becomes `[]` because the read lacked it — and a member of an
   unexpected shape is kept as read.
5. **A `Sensitive<T>` argument MAY also accept the language's plain string** at the call
   boundary, provided it is wrapped before any other use (TypeScript, Python).
6. **Equivalent forms that conform:** `registration_client_uri` parsed and re-serialized, as long
   as it is not rebuilt from parts (§28.12.2 rule 1); a replacement body that omits a nullable
   member whose omission equals its default (§29.8 test 1); `scope` absent or `null` on an OAuth2
   SCIM target (§31.2); `X-Tenant-ID` sent or omitted on the session-free requests of §28.12,
   §32.7 and §33 (the server does not read it; §5.2 rule 1 still forbids it off-origin);
   `requested_expiry` as a number or a string inside a signed request (the server reads both);
   a `client_notification_token` on a poll-mode request refused locally; the delivery mode as an
   SDK-side input.
7. **§33.2 per algorithm.** An SDK MAY sign with a subset of `PS256`, `ES256` and `EdDSA`, and
   states the subset in its claim — "§33.2 signed (ES256, EdDSA)". "§33.2 signed" alone means all
   three.
8. **Names.** PHP's §27 list operation is `listItems` in every namespace; Go's SAML accessor and
   types use the initialism, `SAML()`; C++'s `delete` is `delete_`, a keyword. The naming maps of
   §29.6, §30.6 and §31.6 are read with these.
9. **An input type is built for submission, not decoded (contract 1.60).** "The input cannot be
   built without its required members" (§29.8 test 1, §30.8 test 4, §31.8 test 3, §32.8 test 1)
   binds the constructor or builder a caller uses to make a body for `create` or `update`. It
   does not bind decoding: a response that nests an input-shaped value — `parse_sp_metadata`'s
   `SamlSpMetadataDraft.service_provider` — decodes even when a required member is absent, and
   the refusal comes on submit, as the validation error of item 2 with no request recorded. A type
   that is itself a response (`WebauthnAttestationPolicy`) stays tolerant.

### §34.3 Divergences

**One row per divergence, not per SDK.** The dispositions are §28.11's and §27.14's: **contract
fixed** (1.59 changes or clarifies the text), **SDK fix** (the code or its README is wrong, and
the follow-up named in the row corrects it), **forced by the language, recorded**. A row that is
both names both. The follow-ups are **F-59-01 … F-59-11**, one per repository, each an issue that
lists its rows:

- **F-59-01** Rust — [ilpanich/axiam#576](https://github.com/ilpanich/axiam/issues/576)
- **F-59-02** TypeScript — [ilpanich/axiam#577](https://github.com/ilpanich/axiam/issues/577)
- **F-59-03** Python — [ilpanich/axiam#578](https://github.com/ilpanich/axiam/issues/578)
- **F-59-04** Java — [ilpanich/axiam#579](https://github.com/ilpanich/axiam/issues/579)
- **F-59-05** C# — [ilpanich/axiam#580](https://github.com/ilpanich/axiam/issues/580)
- **F-59-06** PHP — [ilpanich/axiam#581](https://github.com/ilpanich/axiam/issues/581)
- **F-59-07** Go — [ilpanich/axiam#582](https://github.com/ilpanich/axiam/issues/582)
- **F-59-08** Kotlin — [ilpanich/axiam#583](https://github.com/ilpanich/axiam/issues/583)
- **F-59-09** Swift — [ilpanich/axiam#584](https://github.com/ilpanich/axiam/issues/584)
- **F-59-10** C — [ilpanich/axiam#585](https://github.com/ilpanich/axiam/issues/585)
- **F-59-11** C++ — [ilpanich/axiam#586](https://github.com/ilpanich/axiam/issues/586)

| # | Divergence | SDKs | Clause | Disposition |
|---|---|---|---|---|
| R-1 | `poll` aborted by a non-verdict failure on a later SET of a batch leaves the earlier SETs' `jti`s recorded and unreturned; offered again, they are refused `replayed`, and §32.7's `set_errs` advice then has the transmitter drop them — the events are lost. §32.8 test 8's one-SET batch cannot see it | all eleven | §32.7 step 9, `poll` | **contract fixed** (P1, and test 8's two-SET batch) and **SDK fix** (every follow-up) |
| R-2 | A SET re-offered after the receiver accepted it reads `replayed`, and the documented advice reports it in `set_errs` | all eleven (documented by Rust, TypeScript, C#, C++; PHP's docblock and README still report it) | §32.7 `poll` | **contract fixed** (P2) and, from 1.60, **SDK fix**: PHP's `poll()` docblock and README (A7) |
| R-3 | A failed key fetch or store error raises `NetworkError` (or the store's own exception) with no reason code; the contract named none | all eleven | §32.7 steps 4, 9 | **contract fixed** (P3). Every SDK already raises without a code |
| R-4 | A replay-store interface that cannot report failure, so fail-open or fail-closed is the implementer's guess | Rust, Go, Swift (infallible); the other eight fail closed, and 1.60 asks them to verify that a store failure raises and is never read as `replayed` | §32.7 step 9 | **contract fixed** (P4, rewritten in 1.60: a store that cannot answer gives no verdict) and **SDK fix**: the documentation route of F-59-01, F-59-07, F-59-09 is withdrawn, and the 1.60 port makes the interface fallible — Rust (breaking, D-7), Go, Swift (B1) |
| R-5 | Default in-memory store unbounded in count | all eleven | §32.7 step 9 | **contract fixed** (P4): conforms, and the README says so |
| R-6 | `malformed` and `invalid_type` are not RFC 8935 codes; SDKs map them to `invalid_request`, which §32.7 said only of `replayed` | Rust, TypeScript, Go | §32.7 | **contract fixed** (P5) |
| R-7 | `poll` retries `408` and `429` while §32.7 said "not retried on a `4xx`"; TypeScript's README repeats the old text | Rust, TypeScript, C#, PHP, Swift, C | §32.7 vs §16.3 | **contract fixed** (P7) and **SDK fix**, README: F-59-02 |
| R-8 | "One refetch" counted differently on a cold cache; a failed first fetch not rate-limited; a JWKS cache that never expires | Python, Go, C++ (counting); Kotlin (never expires); 1.60 adds Python, TypeScript and Kotlin (a failed cold-cache fill is not counted) and TypeScript (the cache never expires) | §32.7 step 4 | **contract fixed** (P6, amended in 1.60: a successful fill is not counted, a failed one is) and **SDK fix**: F-59-08 (cache lifetime), F-59-11 (limit a failed fetch); 1.60: Python, TypeScript, Kotlin (A3) |
| R-9 | `poll` refuses a SET whose map key differs from its `jti` | Rust, TypeScript, C#, C++ | §32.7 `poll` | **contract fixed** (P7): permitted |
| R-10 | `iat` required to be an integer and `sub_id` an object (Python accepts a fractional `iat`) | Java, C++ | §32.7 step 8 | **contract fixed** (P7): both conform |
| R-11 | A `5xx` with an `error` member — the server's real `500 {"error":"server_error"}` — is an `OAuthProtocolError`, not retried, and ends `ciba_await`; §33.8 test 8 passes with a bodiless `500` | Python, Java, Go, Kotlin, C++; 1.60 adds PHP, TypeScript, C#, Rust, C and Swift, whose 1.59 ports fixed it (A1) | §33.4 vs §33.7 rule 5 | **contract fixed** (P8, and test 8's body) and **SDK fix**: F-59-03, F-59-04, F-59-07, F-59-08, F-59-11, and the six ports of the SDKs added |
| R-12 | `ciba_await` keeps polling after a decisive answer — a bodiless `4xx`, or a failure after the `200` (a body that does not decode, an ID-token key fetch), re-polling a spent redemption into `invalid_grant` | Rust, Java, Swift | §33.7 rules 5, 7 | **contract fixed** (P9) and **SDK fix**: F-59-01, F-59-04, F-59-09 |
| R-13 | An ID-token validation failure after the `200` discards the redeemed tokens, which rule 7 and §12.4 seemed to settle differently | TypeScript, Python (and every SDK that validates) | §33.7 rule 7 vs §12.4 | **contract fixed** (P9): terminal, tokens not returned |
| R-14 | The deadline anchored at the response rather than the request; the loop stopping up to one interval early; the anchor read from the wall clock while the waits use the injected clock; §16 retries inside `ciba_poll` able to cross the deadline; `interval: 0` | all eleven, in some combination; a §16 retry's wait not capped at the deadline in Go and Rust (1.60) | §33.7 rules 2 – 4 | **contract fixed** (P10) and, from 1.60, **SDK fix**: Go and Rust cap a §16 retry's wait at the deadline (B3); the injected anchor stays a SHOULD |
| R-15 | `ciba_await` cannot be cancelled | Java (`cancel` does not stop it), C (blocking) | §33.7 | **contract fixed** (P10): cancellation is a MAY |
| R-16 | The §9 exemption matched exact paths, so a `401` on a tenant-path `bc-authorize` enters §9 and re-sends the initiate (a probe saw two initiate requests) | C#, Java | §33.4, §33.7 rule 1, §12.3 rule 3 | **contract fixed** (P11) and **SDK fix**: F-59-05, F-59-04 |
| R-17 | Management writes ride OkHttp's `retryOnConnectionFailure`, which re-sends a `PUT` after a dropped connection (a probe saw the server receive it twice); the no-retry tests use a `503` | Java, Kotlin; 1.60 adds C# (`SocketsHttpHandler` re-sends on a fresh connection), C and C++ (libcurl re-sends on a dead reused connection) | §29.7, §30.7, §31.7, §32 writes | **contract fixed** (P11, with its remedy in 1.60) and **SDK fix**: F-59-04, F-59-08; 1.60: C#, C, C++ (A6) |
| R-18 | A management write failing with a `5xx` or a transport error throws an error whose `cause` holds the request body, so `bind_secret`, `credential` or `authorization_header` prints in plaintext; the redaction tests use a `400`. The older §27.5 request secrets share the path | TypeScript | §30.5, §31.5, §32.5, §7 rule 1 | **SDK fix**: F-59-02 |
| R-19 | Secrets outside §7's one accessor: Swift's `Sensitive` reflected by `dump`/`Mirror`; Java's public `CibaInitiateRequest.members()` returning the raw notification token; Kotlin's public `ManagementTransport.WIRE`; Rust's crate-private wire twins deriving `Debug`; C freeing rendered secret bodies unscrubbed; and the reverse in C++, whose only accessor is documented as internal, so the rotated §28.12 token cannot be persisted as its README says | Swift, Java, Kotlin, Rust, C, C++ | §7 rules 1 – 3, §33.5, §30.5 – §32.5 | **SDK fix**: F-59-09, F-59-04, F-59-08, F-59-01, F-59-10, F-59-11 |
| R-20 | Undeclared response members kept: scrubbers that drop one named key (`private_key_pem`, `bind_secret`, …); an unknown union arm that keeps the server's whole object | TypeScript (denylist), PHP, Swift, C (raw arm); 1.60 adds Python (`extra="allow"` plus a denylist of four secret names) | §29.5, §31.2 | **contract fixed** (P12.1) and **SDK fix**: F-59-02, F-59-06, F-59-09, F-59-10; 1.60: Python (A5) |
| R-21 | Rendering an unknown union arm for a log line throws, because the type's only serializer refuses to send it | C#, Python, Go, PHP | §31.2, §7 rule 1 | **contract fixed** (P12.2) and **SDK fix**: F-59-05, F-59-03, F-59-07, F-59-06 |
| R-22 | An unknown open-enum value decoded as `UNKNOWN` and re-sent as `""`; event types modelled as a closed enum, so an unseen URI loses its value (§32.2's SHOULD is strings) | Java, Kotlin, C++ (re-sent); Kotlin, Swift, C++, Java (closed event types); 1.60 adds Swift (every other open enum decodes to `.unknown` and re-sends `""`: `SsfStream.status`, `deliveryMethod`, `subjectFormat`, `ScimTargetResponse.deprovision`, `userNameFrom`, …) | §29.2, §31.2, §32.2 | **contract fixed** (P12.2, amended in 1.60: the local refusal's type, and event types as strings) and **SDK fix**: F-59-04, F-59-08, F-59-11, F-59-09; 1.60: Swift's generator-level `encode(to:)` refuses `.unknown` for every open enum (A4); Kotlin and C++ raise the validation error (B5) |
| R-23 | `update_client_registration` sends `redirect_uris`, `grant_types` and `response_types` as `[]` when the read lacked them, and drops list items of an unexpected type | Rust, TypeScript, PHP, Java, C++; 1.60 adds Go (`updateBody` sends `[]` for a member the read lacked, overwrites a member of unexpected shape and drops non-string items) | §28.12.2 rule 4 | **contract fixed** (P12.4) and **SDK fix**: F-59-01, F-59-02, F-59-06, F-59-04, F-59-11; 1.60: Go (A2) |
| R-24 | A `Sensitive` argument also accepts a plain string | TypeScript, Python | §28.12.4, §33.5 | **contract fixed** (P12.5): permitted |
| R-25 | An explicitly assigned `None` secret is sent as `null`, a third state beside keep and replace | Python | §30.2, §31.3 rule 2, §32.2 | **contract fixed** (P12.3) and **SDK fix**: F-59-03 |
| R-26 | A sparse `directory.update` cannot send `[]` for `trust_anchors_pem` or `group_mappings` (`omitempty`) | Go | §30.2, §27.4 rule 5 | **SDK fix**: F-59-07 |
| R-27 | Input types buildable without their required members: a Go struct literal; Java record components with no null check (the tests say "does not compile"); C++ default constructors | Go, Java, C++ | §29.8 t1, §30.8 t4, §31.8 t3, §32.8 t1 | Go **forced by the language, recorded**; **SDK fix**: F-59-04, F-59-11; **contract fixed** in 1.60 (P12.9: the rule binds building an input, not decoding one a draft nests) with Java's draft decode as its **SDK fix** (B6) |
| R-28 | Generated documentation that contradicts the types: "Every field of the body is required" on replacements with optional members, `parse_sp_metadata` called a "sparse" body, "six" aliases | Rust, TypeScript, Python, Java, C#, PHP, Go | §27.4 rule 5, §29.2, §21.3.1 | **SDK fix** (the generators' text): F-59-01 … F-59-07 |
| R-29 | Call-site documentation missing: §31.3 rule 2 on `scim_targets.create` ("both call sites"); §29.3 rule 2 on the `sp_signing_cert_pem` field rather than only on the methods | Python, Java, Swift, C, C++ (rule 2 on create); Swift, C, C++ (the field) | §31.3 rule 2, §29.3 rule 2 | **SDK fix**: F-59-03, F-59-04, F-59-09, F-59-10, F-59-11 |
| R-30 | No auto-paging form for the management lists; §29.8 t5, §31.8 t4 and §32.8 t4 discharged with a hand-written loop. Management reads retried without §16's backoff, `Retry-After` or `408`/`429` | Swift, C (pager); C, C++ (reads). Both pre-date Phase 23 | §27.4 rules 4, 8; §16 | **SDK fix**: F-59-09, F-59-10, F-59-11 |
| R-31 | Tests that pin less than a rule requires: vector A carried by a fixture rather than read from the vendored text, and no test of the CIBA mTLS alias row (Rust); a hand fixture without the vector's `tenant_id` query (PHP); vector A retyped inline, and `PS256` only refusal-tested (Swift) | Rust, PHP, Swift | §21.3.1, §33.8 t14 | **SDK fix**: F-59-01, F-59-06, F-59-09 |
| R-32 | "§33.2 signed" claimed with `PS256` declined locally (documented) | PHP | §33.2, Conformance Statement | **contract fixed** (P12.7) and **SDK fix**, README claim "§33.2 signed (ES256, EdDSA)": F-59-06 |
| R-33 | The SSF receiver calls `sodium` with no guard, and `composer.json` does not declare `ext-sodium` | PHP | §32.7 | **SDK fix**: F-59-06 |
| R-34 | Names outside the maps: PHP `listItems`, Go `SAML()`, C++ `delete_` | PHP, Go, C++ | §29.6, §30.6, §31.6 | **contract fixed** (P12.8); PHP and Go a standing convention, C++ **forced by the language** |
| R-35 | `X-Tenant-ID` on the session-free requests: C omits it on §28.12 and §32.7, Swift sends it on a same-host request | C, Swift (opposite choices) | §5 rule 2, §28.12.2 rule 3 | **contract fixed** (P12.6): both conform |
| R-36 | `requested_expiry` a JSON number inside the signed request, a string on the form | Go, Kotlin, Swift, C | §33.2 | **contract fixed** (P12.6): both conform |
| R-37 | A notification token on a poll-mode request refused locally; the delivery mode an SDK input | Go, Python | §33.2 | **contract fixed** (P12.6): permitted |
| R-38 | Equivalent forms: the registration URI parsed and re-serialized; null-valued optional members omitted from a replacement; `scope` absent rather than `null` | Rust, Kotlin (URI); Rust, C# (omitted nulls); Go, Kotlin (`scope`) | §28.12.2 r1, §29.8 t1, §31.2 | **contract fixed** (P12.6): conform |
| R-39 | CIBA client authentication without `private_key_jwt` (`client_secret_post` or `tls_client_auth`), so a `fapi2` CIBA client uses mTLS | Python, Java | §33.1, §21.8 | **forced by the SDK's existing §21.8 posture, recorded** in §33.10 |
| R-40 | The signed form's free choices — lifetime (300 s), header `typ`, `aud` as a string, `jti` format | all eleven, consistently | §33.2 | **recorded**: none is wrong |
| R-41 | Smaller defects: Java's receiver telemetry not reaching the client hook, a missing `expires_in` decoded as `0`, a non-string secret kept in `extra`; Python's synchronous replay store under its async receiver; C's README giving a DPoP-decline reason its new signer contradicts; documentation saying PATCH arrived in 1.58 (Python) | Java, Python, C | §16.5, §33.2, §28.12.4, §21.9 | **SDK fix**: F-59-04, F-59-03, F-59-10 |
| R-42 | Platform limits: Node drops a duplicate `Authorization` header, so test 11's duplicate is refused only from `rawHeaders` (documented); in Swift the wire encoder is the only `Encodable` serializer, so "serialized for logs" means the description sinks | TypeScript, Swift | §33.8 t11, §7 rule 1 | **forced by the language, recorded** |

**T-388 stands.** Every helper refuses a replayed SET, which is what the entry's closing condition
names. R-1 is the opposite failure — an event refused as a replay that was never delivered —
and is fixed by P1 and the follow-ups, not by a threat-model change.

**After the merge.** Each SDK re-vendors this `CONTRACT.md` from the merge commit that carries it
(the 1.49 rule), in the PR that closes its follow-up or in its own; `scripts/check-sdk-artifact-drift.py`
then reports every repository at 1.59.

### §34.4 Contract 1.60 — answers to #588 and the rows assigned

[#588](https://github.com/ilpanich/axiam/issues/588) collected the sixteen questions the eleven
F-59 ports raised while they were brought to the text of §34.2 and §34.3: seven rows that missed an
SDK showing the same defect (A1 – A7) and nine clarifications that read ambiguously or collided
once implemented (B1 – B9). Contract 1.60 answers every one. Each answer below is one sentence an
implementer can test; the rule itself lives in the section of the last column, marked *contract
1.60* there, and the R-rows of §34.3 are amended in place wherever an SDK is added to them. No
answer changes a wire shape.

| Q | Answer | Lives in |
|---|---|---|
| A1 | R-11 also names PHP, TypeScript, C#, Rust, C and Swift, whose 1.59 ports fixed it: a mid-loop `500 {"error":"server_error"}` on `ciba_poll` is retried and `ciba_await` completes (§33.8 test 8). | P8; R-11 |
| A2 | Go joins R-23: `ClientRegistration.updateBody` sends no `redirect_uris`, `grant_types` or `response_types` member the read did not carry, sends a member of unexpected shape as read, and drops no non-string item. | P12.4; R-23 |
| A3 | Python, TypeScript and Kotlin join R-8: after a failed cold-cache fill a second SET within the minute makes no fetch, and TypeScript's key cache expires. | P6; R-8 |
| A4 | Swift's generated `encode(to:)` of every open enum refuses `.unknown`: a read-modify-write of an `SsfStream` or a `ScimTargetResponse` carrying an unknown value raises before any request and never sends `""`. | P12.2; R-22 |
| A5 | Python joins R-20: an unknown union arm keeps its discriminator and no other member, not every member but a denylist. | P12.1; R-20 |
| A6 | P11 binds C#, C and C++: every never-retried write goes on a fresh connection that is not reused afterwards — `CURLOPT_FRESH_CONNECT` plus `CURLOPT_FORBID_REUSE` in C and C++, a non-pooled handler (or one whose pooled connections are not reused) for writes in C# — and a server that drops a write unanswered receives it exactly once. | P11; R-17 |
| A7 | PHP's `SsfReceiver::poll()` docblock and README example say that a `replayed` SET is acknowledged in `ack`, not reported in `setErrs`. | P2; R-2 |
| B1 | A replay store that cannot answer gives no verdict — the SET is neither refused nor acknowledged and stays unjudged — so every store interface that answers a bare `bool` becomes fallible (a `Result`, an exception or an error return); for Rust that is a breaking change to `ReplayStore`, released with 1.0.0 (D-7). | P4; R-4; §32.8 test 6 |
| B2 | A successful cold-cache fill does not count toward the once-a-minute refetch limit and a failed fill does, so an unknown `kid` right after a successful fill is refetched once. | P6; §32.8 test 7 |
| B3 | The P10 MUST binds now: a §16 retry inside `ciba_poll` as `ciba_await` calls it never waits past the deadline (`received_at + expires_in` at the latest), `Retry-After` is capped at it and no request follows it; R-14 is amended and Go and Rust are assigned. | P10; §33.7 rule 5; R-14 |
| B4 | Event types are sent as the strings the caller holds: an unseen event-type URI read from the server decodes with its value and is sent back unchanged on `update_stream`, the server judging it, and a closed-enum SDK (Swift, C++) may refuse a URI the caller typed that is none of the six only if it documents the refusal — §32.2's SHOULD stands because a client-side list of URIs goes stale. | P12.2; §32.2 |
| B5 | Every local refusal raises one category, the SDK's validation error (`ValidationError`; `std::invalid_argument` in C++; `NULL` with `axiam_error_t` in C, as §28.7 says), so Kotlin and C++ stop raising a bare `NetworkError` for it. | P12.2 |
| B6 | "Cannot be built without" binds the constructor or builder that makes an input for submission, not the decoding of one a response nests: a decoded draft may lack a required member and the submit refuses it locally with the validation error and no request. | P12.9; R-27 |
| B7 | P1 names the list of unjudged SETs `unjudged`, and a store without an un-record uses the second form for the tail after its first record, which conforms and is not a mixed form. | P1 |
| B8 | §21.3.1 says vector A is abridged and that the expected pin fills only the `*_supported` lists from a fixture and takes every endpoint, the issuer and the aliases from the vector's text. | §21.3.1 |
| B9 | §21.9 gives the reason for the C and C++ DPoP decline as: verifying a proof needs the HTTP request, and the guards see only a token — not a missing JOSE implementation. | §21.9 |

**Which SDK fixes which row in 1.60.** One line per SDK per row, in the pull request of the SDK's
`claude/contract-1.60-sync` branch; "pending" is filled in by the port with its merge commit. A
row marked *verify* asks the port to confirm the behaviour and to add the test, and to change
code only if the check fails. Rows that every SDK shares are written once.

| Row | SDK | What the 1.60 port does | Fixed in |
|---|---|---|---|
| A2 | Go | `ClientRegistration.updateBody` sends no list member the read did not carry (no `[]` from `rawStringList(nil)`), keeps a member of unexpected shape as read, drops no non-string item (`takeRegistrationList` / `wireMembers` in `oidc_registration.go`) | pending |
| A3 | Python | a failed cold-cache fill counts toward the once-a-minute limit | pending |
| A3 | TypeScript | a failed cold-cache fill counts; the key cache expires as §10's JWKS cache does (P6's SHOULD) | pending |
| A3 | Kotlin | a failed cold-cache fill counts (the cache lifetime was F-59-08) | pending |
| A4 | Swift | a generator-level `encode(to:)` refuses `.unknown` for every open enum (`SsfStream.status`, `deliveryMethod`, `subjectFormat`, `ScimTargetResponse.deprovision`, `userNameFrom`, …) | pending |
| A5 | Python | an unknown union arm keeps its discriminator only (`OpenUnionUnknown` drops `extra="allow"` and the denylist) | pending |
| A6 | C# | never-retried writes use a non-pooled handler, or a handler whose pooled connections are not reused | pending |
| A6 | C | `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on every never-retried write | pending |
| A6 | C++ | `CURLOPT_FRESH_CONNECT` and `CURLOPT_FORBID_REUSE` on every never-retried write | pending |
| A7 | PHP | `SsfReceiver::poll()` docblock and README example: a `replayed` SET is acknowledged, not reported | pending |
| B1 | Rust | `ReplayStore::check_and_record` returns a `Result`; a store error is no verdict. **Breaking** (D-7) | pending |
| B1 | Go | the store interface returns an `error`; a store error is no verdict | pending |
| B1 | Swift | the store protocol `throws`; a store error is no verdict | pending |
| B1 | TypeScript, Python, Java, Kotlin, C#, PHP, C, C++ | *verify*: a store that cannot answer raises (or sets C's failure channel) and is never read as `replayed`; add §32.8 test 6's store-failure case | pending (eight rows, one per SDK) |
| B3 | Go | a §16 retry inside `ciba_poll` as `ciba_await` calls it waits no longer than the deadline | pending |
| B3 | Rust | the same | pending |
| B4 | Swift, C++ | an unseen event-type URI read from the server decodes with its value and is sent back unchanged; a refusal of a typed unlisted URI, if kept, is documented | pending |
| B4 | Java, Kotlin | *verify*: strings; an unseen URI round-trips through `update_stream` | pending |
| B5 | Kotlin | the local refusal raises `ValidationError`, not `NetworkError` | pending |
| B5 | C++ | the local refusal throws `std::invalid_argument`, not `NetworkError` | pending |
| B6 | Java | `SamlSpMetadataDraft.service_provider` decodes without the required-member check; `create_service_provider` refuses it locally | pending |
| §31 `expected_updated_at` | every SDK (eleven) | the member on `ScimTargetInput`, passed through unchanged; §31.8 test 3's added assertion | pending (eleven rows) |
| §27.15 `window_minutes` | every SDK (eleven) | the member on the `notification_rules` request and response models, never clamped; the one required test of §27.15 note 1 | pending (eleven rows) |
| §15.2 rule 9 | every SDK that ships §15 | the `actor_token` documentation and examples obtain the token from the same client's `client_credentials` grant; the added §15.6 test | pending |
| §8 minimal profile | the seven AMQP SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) | README sentence: a broker confirm is not evidence that AXIAM saw a message | pending |

Every SDK also re-vendors `CONTRACT.md`, `openapi.json`, `management-registry.json` and `proto/`
from the merge commit that carries this revision (the 1.49 rule), regenerates its §27 surface with
the drift job green, and states conformance at 1.60 in its README.

**Changes of 1.60 outside #588** (each lives in the section named): §31's `expected_updated_at`
([§31.2](#§312-shapes-normative), [§31.3](#§313-server-rules-every-sdk-can-observe-normative) rules 4 and 5);
`window_minutes`, client removal, tenant deletion and the `email_config` address policy
([§27.15](#§2715-model-and-behaviour-notes-contract-160)); the `403` on the device approval routes
([§14](#§14-device-authorization-grant-rfc-8628)); the pending-request list as a console surface
([§33.3](#§333-server-rules-every-sdk-can-observe-normative) rule 16); the actor-token rule
([§15.2](#§152-semantics-normative) rule 9); the minimal-profile note ([§8](#§8-amqp-hmac-contract));
`ValidateCredentials` and `UNAVAILABLE` ([§2](#§2-error-taxonomy)); a revoked certificate and the
certificate revocation list ([§21.3](#§213-authenticating-as-an-mtls-client-informative),
[§35](#§35-certificate-revocation-lists-informative)); the webhook redirect note
([§13](#§13-webhook-signature-verification)). The `user_id` certificate field of #533 is **not**
in 1.60; it is deferred to 1.0.x.

<!-- W3: pending W1 items #520 #531 #530 #532 #525 #524 #526 … — their contract text (the `allow_sha1_signatures` federation field of #531 among it) is not collected yet; a second pass adds it here and in the section each lives in, and extends the "Changes of 1.60 outside #588" list above. -->

**After the merge.** As §34.3's: each SDK re-vendors this `CONTRACT.md` from the merge commit that
carries it, in the PR that closes its 1.60 rows or in its own, and
`scripts/check-sdk-artifact-drift.py` then reports every repository at 1.60. The "Fixed in" column
above is filled from those pull requests.

---

## §35 Certificate revocation lists (informative)

**Informative, contract 1.60. Not a §27 namespace and no SDK surface.** The route below sits
outside `/api/v1`, takes no token and belongs to no management operation; an SDK generates nothing
for it, and none is required to use it. The section exists so that an SDK or an application that
validates AXIAM-issued certificates itself — a RADIUS server doing EAP-TLS, a VPN gateway, an
mTLS terminator — knows where the revocation list is and what it says.

1. **The route.** Each issuing CA whose key AXIAM holds publishes its certificate revocation list
   at `GET /pki/v1/{org_id}/ca/{ca_id}/crl` (also `HEAD`).
2. **No authentication; its own rate limit.** The route takes no authentication and is
   rate-limited per client IP in a bucket of its own (`AXIAM__RATE_LIMIT__CRL_PER_MIN`, default 60 a
   minute, never moved by a posture preset); past it the answer is `429`.
3. **The list.** `200` with an RFC 5280 version 2 CRL, DER-encoded, `Content-Type:
   application/pkix-crl`, signed with the CA's own key, carrying a CRL number, an authority key
   identifier equal to the CA's subject key identifier, `nextUpdate`
   `AXIAM__PKI__CRL_NEXT_UPDATE_SECS` after `thisUpdate` (default 86400, never past the CA's
   `notAfter`) and one entry (serial, revocation date, no reason code) per revoked, unexpired
   certificate the CA signed, leaves and subordinate CAs alike.
4. **Caching.** Responses carry `Cache-Control: public, max-age=<seconds to nextUpdate>`, a strong
   `ETag` and `Last-Modified` (equal to `thisUpdate`); a matching `If-None-Match` is answered `304`.
5. **When there is none.** A CA unknown in that organization, revoked, expired, imported without a
   key, or held by Vault's PKI engine answers `404`, alike.
6. **The distribution point.** Every certificate AXIAM signs in-process — generated and CSR-signed
   leaves, tenant signing CAs — carries a CRL distribution point with this route's absolute URL,
   built from `AXIAM__PKI__CRL_BASE_URL` or else the issuer URL, and omitted when neither is an
   absolute `http` or `https` URL.
7. **What an SDK may do.** An SDK that validates AXIAM-issued certificates MAY fetch the list from
   that distribution point; none is required to.
8. **Client authentication.** A certificate AXIAM issued that is revoked or expired, or whose
   issuing CA is, authenticates no client under either mTLS method of §21.3, whatever the
   registration matches.

---

### OpenAPI Export Feature Flag

`openapi.json` (kept in this directory, and mirrored into every SDK repo) is generated with `--no-default-features` (SAML endpoints excluded). Both the committed spec and the CI drift gate use identical flags. SDK consumers requiring SAML endpoint documentation should build AXIAM with the `saml` feature enabled and export locally.

### Telling two exports apart — `info.x-axiam-spec-digest`

`info.version` is the **release** version. It tracks the server's crate version, so it
moves when a release is cut — not when a path is added. Two builds can therefore describe
genuinely different APIs under the same string, and they have: `main` and a release branch
both reported `1.0.0-alpha44` while differing by two paths
(`.../ca-certificates/{id}/migrate-custody` and `.../mtls-trust-anchor`). Nothing in the
document let a consumer tell those exports apart.

Every export now carries a second field for exactly that question:

```json
"info": {
  "title": "AXIAM API",
  "version": "1.0.0-beta01",
  "x-axiam-spec-digest": "sha256:<64 hex characters>"
}
```

It is a SHA-256 over the whole document with that field itself absent, so it is a function
of the spec's content and re-stamping is idempotent. Two exports with the same digest are
the same document, byte for byte, whatever their versions say; two with different digests
differ somewhere, whatever their versions say.

`info.version` keeps its meaning and consumers should keep reading it as the API's semantic
version. The digest answers the other question — *is this the same document?* — which a
semantic version was never able to.

**The version is part of what is digested**, so a release bump changes the digest even when
no path did. That is deliberate: "same document" is a claim that can be checked, where "same
API" would need an argument about whether a `description`, a `tag` or an example counts as
part of the API. A consumer who wants the narrower question can compare the members they
care about; this field answers the wider one exactly. Both directions of the failure are now
visible — `1.0.0-alpha44` and `1.0.0-beta01` were the same document under two versions, and
`1.0.0-alpha44` on two branches was two documents under one.

**For SDK authors.** Nothing is required of you: the field is an OpenAPI `x-` extension, so
a validator and a code generator both ignore it, and no SDK's generated surface changes.
It is there for the tooling around the SDK — a generator deciding whether to re-run, a
contract test asserting the vendored copy is current, a gateway keyed on a spec revision.
Comparing digests is exact where comparing versions was not.

---

*Contract version: 1.60 — Phase 15 (sdk-foundation); §11 declarative authorization helpers added 2026-07; §6.1 mTLS client certificates and Kotlin/Swift/C/C++ SDK columns added 2026-07; §1.1 gRPC-only `get_user_info` operation added 2026-07; §12 OIDC/SSO relying-party helpers and the `OAuthProtocolError` taxonomy sub-type added 2026-07; §7 accessor rules, §9 rule 5, and the §12 cross-SDK clarifications from the eight-SDK conformance review added 2026-07; §9 rule 6 single-flight implementation invariants and the extended §9 test requirement added 2026-07; §8b AMQP transport, §10.2 gRPC revocation modes, §12.7 logout helpers, §14 device authorization grant and §15 token exchange added 2026-08; §14.3 rule 4 / §14.6 credential-adoption errata 2026-08 (contract 1.7); §16 retry policy, §17 decision memo, §18 deterministic shutdown and §19 telemetry hooks added 2026-08, with §11.2 rules 5–6 and §14.2 rule 6 amended to point at them (contract 1.8); §16 preamble errata + §19 `config_clamped` event 2026-08 (contract 1.9) — the divergence table rewritten from wire-counting conformance tests rather than greps, and a clamped setting must now be reported through §19 rather than applied silently; §20 UMA 2.0 Protection API and ticket grant added 2026-08 (contract 1.10), carrying the one documented exception to §16 retry policy; §12.6's Swift/C/C++ deferral lifted 2026-08 (contract 1.11), porting §12 and §12.7 to those three SDKs and widening §7's C/C++ rows to rule 3's single explicit accessor; §2's `/oauth2/*` error rows and §12.3 rule 3 rewritten to dispatch on the `error` field at any status rather than enumerating 400/401 2026-08 (contract 1.12), so §20.4's 403 `access_denied` reaches the shared mapper and the nine grant-local mappers it forced become removable; §15.1's signature gains a REQUIRED `subject_token_type` and §15.7's prohibition on defaulting it becomes structural rather than documentary 2026-08 (contract 1.13) — a breaking change to all eleven SDKs, taken because an optional parameter with a default is the same guess §15.7 forbids, moved from the SDK's code into its signature; §20.2 rule 6's second reason restated 2026-08 (contract 1.14) — **documentation only, no SDK behaviour changes and no signature moves**. ilpanich/axiam#302 closed: the server now decides the ticket race with a transaction the storage engine arbitrates plus a nonce read back after it commits, so the "measured residual of roughly 1 in 640" the rule cited no longer exists. The rule is unchanged and its first reason (a spent ticket makes the retry useless) was always sufficient on its own; what changes is that the second reason now rests on what an SDK can actually know — it is talking to a server whose storage engine it cannot attest, and the guarantee is conditional on that engine being persistent; **§10.1 rule 9 (sender-constrained tokens) and §21 (FAPI 2.0 profile, mTLS client credentials, RFC 9207 `iss`) added 2026-08 (contract 1.15)** — one new normative rule for every SDK: a token carrying `cnf` is not a bearer token and MUST NOT be accepted as one, and a `cnf` naming a confirmation method the SDK cannot check MUST be refused rather than read as unconstrained. No signature moves and no breaking change to any existing call; the compatibility risk runs the other way, and the required positive regression test (an **unbound** token is still accepted with or without a certificate) is there because the likeliest wrong implementation of rule 9 is one that starts demanding certificates from every caller. Everything else in §21 is informative: mTLS client authentication is optional for the client role, and RFC 9207 `iss` validation is a SHOULD that any SDK talking to more than one issuer should treat as a MUST; **§10.1 rule 9 extended for DPoP and §21.6–§21.9 added 2026-08 (contract 1.16)** — the server gained the second half of two X5.1 rows, `private_key_jwt` client authentication (RFC 7523 §2.2) and DPoP sender-constrained tokens (RFC 9449), and rule 9's four-row table becomes a ten-row one **extended in place** rather than duplicated. The SDK-visible surface is the resource-server side only: a `cnf` may now carry `jkt`, an SDK that cannot verify a DPoP proof MUST refuse such a token rather than accept it as a bearer, and a `cnf` naming **both** methods is a conjunction — "check whichever we can" is forbidden, as is reading an empty `cnf` as unbound. No signature moves and no breaking change to any existing call; the compatibility risk again runs the other way, and the positive regression test is widened to say an **unbound** token must still be accepted with no certificate *and* no proof. Client-side proof generation is a per-language judgement call and §21.7.3 makes declining a supported answer with exactly three obligations (reject, document, test) — §21.9 records each SDK's posture, and the C and C++ SDKs decline §21.7.2 deliberately rather than by omission. §21.8 (`private_key_jwt`) is informative throughout: the client role may keep using `client_secret_post` or mTLS; **§10.3 (sender-constrained tokens over gRPC) added 2026-08 (contract 1.17)** — the X5 work landed REST-first, and gRPC introspection was found to carry no `cnf` at all, which meant an SDK validating through `TokenService` could not satisfy rule 9 detail 4 even in principle: it had no way to tell a bound token from a bearer one and was forced into the exact downgrade rule 9 exists to prevent. `ValidateTokenResponse` and `IntrospectTokenResponse` now carry `cnf` and `token_type`, and introspection additionally gains the RFC 7662 §2.2 fields it had always been missing (`scope`, `client_id`) plus `permissions` (§20 UMA RPT) and `ext_exchange_iss` (X4 provenance). All additive proto fields, so an older client keeps working and simply does not see them — which is the risk, and why §10.3 is normative rather than informative. One wire-level subtlety has its own rule: proto3 cannot distinguish an absent string from an empty one, so an **empty** `CnfClaim` must be refused rather than read as unbound, exactly as rule 9's "names neither" row requires. SDKs must NOT copy the server's own gRPC-side refusal of DPoP-bound tokens — AXIAM's interceptor declines them because a tonic interceptor sees neither `htm` nor `htu`, whereas an SDK guarding a real endpoint knows both; **§22 (Reactors — AMQP extension actors) added 2026-08 (contract 1.18)** — **non-breaking / additive**, and additive in the strongest sense: no existing signature moves, no existing rule changes, and an SDK that ships no reactor runtime is exactly as conformant as it was under 1.17. The chapter documents a server surface that already exists (`crates/axiam-amqp/src/reactor/`, `crates/axiam-core/src/models/reactor.rs`): a Reactor is an external process that subscribes to hook events on the AMQP bus and answers allow/deny/mutate under a signed, timeout-bounded, field-allow-listed protocol — Zitadel-Actions parity without loading third-party code into the security kernel. Two things in it are new obligations rather than new options. The first is that §8's HMAC now runs in **both directions** on one exchange: the server signs the event, the reactor signs the reply with the same tenant subkey, and an unsigned or stale reply is discarded as though the reactor had never answered — with one canonicalization difference that will cost an implementer a day if it is not stated, namely that `hmac_signature` is serialized as `null` inside a reactor body rather than omitted as it is in §8's own two message types. That is why §22.13's vectors ship beside the §8 vectors, in the same fixture directory and under the same master key, tenant and derived subkey: one loader serves both, and the difference is a test rather than a paragraph to remember. The second is the hot-path exclusion (§22.7), written as a **MUST NOT** rather than a note — `authz.check`, `authz.check_batch` and `token.introspect` are not hookable and no SDK may present them as such, because a reactor round-trip is milliseconds and the check path's budget is microseconds; an application needing external input on a decision writes a deny grant, which the engine evaluates at hot-path cost. Swift, C and C++ ship no runtime (§22.11) for the same reason §8 has never listed them among the SDKs that speak AMQP — no vendorable client for those targets — but §22.1–§22.8 binds a hand-rolled integrator on them in full, a split that follows the §12.6 precedent contract 1.11 lifted while cutting at the seam between protocol and convenience rather than across a whole section. One scope note travels with the chapter: the server's lapin transport is not yet merged, so the two AMQP basic properties §22.1 names for reply addressing are the standard RPC convention rather than an implemented one — every signed body, field order, allow-list and validation rule in the chapter is implemented and tested today. Recorded here and not in the Breaking Changes Log above, which is untouched, because nothing breaks; **SDK-Q10 closed 2026-08 (contract 1.19)** — the last deferred contract item, and the one that had been deferred because every closure looked like a break. The gRPC decision's `deny_reason` and the REST decision's `reason` were the same string under two names, so an SDK speaking both transports reconciled them in its own mapper and the two same-named `AccessDecision` types could disagree about their own field list. Closed by **deprecate-and-add**: `CheckAccessResponse` gains `reason` (field 4, explicit presence — absent on an allow, present on every refusal, exactly the REST shape), `deny_reason` is marked `[deprecated = true]` and keeps carrying the identical string until it is **removed at AXIAM 2.0**, and §11.2 rule 9's amendment states the one migration rule: read `reason`, fall back to `deny_reason` only when `reason` is absent on a refusal, expose one reason accessor rather than two. Nothing breaks on the wire today and no signature moves. The same amendment settles the two shapes that went with it — the decision is `allowed` + `reason_code` + `reason` and carries no `resource_type`/`resourceType` (the server has never had one), and gRPC `subject_id` becomes optional the way REST's is, with an **empty** value meaning "the subject in the verified token". That last one is deliberately not proto3 `optional`: `buf breaking` refuses the cardinality change, so empty carries the meaning proto3 cannot express as absence — the same constraint §10.3 already records for an empty `CnfClaim`; **§15.2 rule 8, §22.8's listen/unreadable-registry paragraphs and §22.9 rule 3 added 2026-08 (contract 1.20)** — the medium-severity half of the F4-bis security review (SEC-096, SEC-099, SEC-100, SEC-101). One of the four is an SDK-visible **behaviour** change and it is the one to read: an exchanged token (and a §20 RPT) is now sender-constrained to whatever the *exchanging client* proved on that request, so `token_type` may be `DPoP` where it was always `Bearer`, the token may carry a `cnf` that §10.1 rule 9 governs, and a client registered for binding that exchanges without presenting its credential now receives `invalid_client` instead of an unbound token. No signature moves, and a client that registered no binding — every client that existed before X5.1 — receives byte-identical responses. The other three are statements of server behaviour an SDK could not have inferred: a `listen` registration can never deny even on the two out-of-chain failure paths, an unreadable registration store applies the *event's* default policy but exempts a tenant with no registrations at all, and a reactor registration is refused with `503` while the server's transport cannot dispatch — with `enabled: false`, `DELETE` and creating-already-disabled deliberately left open as the operator's way out; **§22.1's scope note closed and §22.9 rule 3 widened 2026-08 (contract 1.21)** — **no SDK behaviour changes and no signature moves**. The server's lapin `ReactorTransport` is merged (`crates/axiam-amqp/src/reactor/transport.rs`) and `axiam-server` composes it, so the one part of §22 that was not pinned by a running implementation — the two AMQP basic properties used for reply addressing — now is, exercised against a live broker in `crates/axiam-amqp/tests/reactor_containerized_test.rs`. An SDK that already echoed `reply_to`/`correlation_id` from the delivery, which the scope note told it to do, needs no change. Two things are worth reading anyway. The first is a server-side clarification with a security reason behind it: an `intercept` event goes to the reactor's queue directly rather than through the topic exchange, because the routing key is per `(tenant, event)` and a fan-out would let whichever reactor answered first be consumed as the reply of whichever reactor the priority-ordered chain was waiting on — the exchange and bindings are still declared by the server, and a reactor runtime still consumes its configured queue and still declares nothing. The second is that §22.9 rule 3's `503` now has a second trigger, `mode: "listen"`, for as long as no hook site fans out to listeners: such a registration receives nothing and, being a listener, produces no outcome in which its silence could be noticed, so refusing it is more honest than accepting it. `enabled: false`, `DELETE` and creating-already-disabled stay open, as they already did. A **broker outage is explicitly not** a `503` trigger — the merged transport reports itself dispatchable while disconnected and lets each registration's `failure_policy` decide, per §22.8, because refusing registrations for the duration of a blip would turn a broker problem into an admin-API problem; **§22.14 (declarative handler binding) added 2026-08 (contract 1.22)** — **additive, SHOULD-level, no signature moves and no behaviour change to any existing call.** §22.10's handler is one function from an event to one answer, which is right for the wire and wrong for the code: a reactor registered for three events opens with a dispatch on the event name, and the catch-all arm of that dispatch is almost always written `return allow()`. That line is §22.10 rule 2's defect — synthesizing an answer for a handler that never ran — relocated out of the runtime, where the rule binds, and into user code, where it does not. Every SDK example this project ships had one, which is how the pattern was found. The subsection defines the declarative form each language already uses for §11 (annotations in Java and Kotlin, attributes in C# and PHP, a decorator in Python, an attribute macro in Rust, a `ServeMux`-shaped binding table in Go and a typed record in TypeScript), and pins six rules on it. Five are restatements aimed one layer up — compose rather than replace, refuse an unregistered name at bind time, one handler per event, propagate a handler's own failure unchanged, never filter a patch. The sixth is the reason the subsection exists: an event with no bound handler MUST abstain, letting the registration's `failure_policy` decide exactly as it decides a timeout, and MUST NOT be answered `allow` or `deny`. Rule 2 carries one instruction that reads backwards until you see why: an SDK MUST NOT keep its own list of the three hot-path operations to give them a better error message, because that list would be a constant naming them and §22.13's hot-path assertion forbids exactly that — they are refused as unknown names, like any other name absent from the §22.5 registry. Nothing here is a new conformance claim: an SDK shipping §22 with the binder and one shipping §22 without it both write "conforms to … §22"; **§8b tightened and the server made TLS-only 2026-08 (contract 1.23)** — the server's `AXIAM__AMQP__ALLOW_PLAINTEXT` escape hatch is **removed**, so `AXIAM__AMQP__URL` must be `amqps://` in every build profile with no flag that changes it. The flag had existed for a year and four of this project's own stacks reached for it — dev compose, the e2e stack, the benchmark target and CI — each with a locally sound argument (throwaway data on a compose network, an ephemeral broker carrying synthetic fixtures for one job, a hop the benchmark harness measures rather than encrypts). None was wrong; the aggregate was that "AMQP is TLS-only" described the production compose file and the k8s manifests and nothing else the repository ran. Rule 1 is correspondingly restated as *refuse* every non-`amqps://` scheme rather than merely *support* `amqps://`, and two rules are added. **Rule 7** is the one with teeth: rules 1–5 MUST be enforced in code, not stated in documentation, because the review that produced this version found three SDKs asserting `amqps://` in a doc comment attached to a parameter that accepted anything — the TypeScript runtime's own comment read "there is no verification-skip switch and no plaintext fallback" directly above an `amqp.connect(url)` that would happily take `amqp://`. Where an SDK takes a caller-supplied channel (Java, Kotlin, C#) it must additionally ship a constructor that applies rules 1–4 and show that constructor in its README. **Rule 8** removes any loopback exception: §6's `http://localhost` dev carve-out for the HTTP transports does not extend to the broker URL, the server has no plaintext listener for it to reach, and the Rust SDK's AMQP path — the only one that had inherited it — no longer grants it. Two new required tests go with them: a refusal must be asserted as *no connection attempted* rather than as a thrown message, since rule 5 is a claim about the absence of a fallback and an implementation that dialled first and complained second would pass a message-only assertion; and an unparseable URL must fail closed, because a guard written as "check the scheme *if* the URL parses" silently exempts everything malformed — a defect this project shipped in the Rust SDK and fixed under this version. §8b also gains a normative per-SDK index naming each enforcement point, so "where is this actually checked" is answerable without a grep. No message format, field order or signing rule changes, and §22.2's transport paragraph is unchanged: it already deferred to §8b in full; **§23 (Secure Remote Password, SRP-6a) added 2026-08 (contract 1.24)** — **additive, no signature moves, no behaviour change to any existing call.** An SDK that does not implement §23 is exactly as conformant as it was under 1.23, and a server left at the `srp_mode: disabled` default — which is what every existing deployment gets on upgrade — behaves byte-identically to before. The chapter documents a second way to prove a password: an augmented PAKE in which the plaintext never reaches the server, which closes the holes TLS 1.3 does not — a TLS-terminating proxy, an accidental request-body log, a heap dump. §23.0 states the limits in the same breath, because an SDK's own README will repeat them and overclaiming is worse than not shipping the feature: SRP does not defend against a compromised AXIAM server, and in a browser it does not defend against AXIAM serving malicious JavaScript. Three things in it will cost an implementer a day each if they are skimmed. The first is `PAD()` (§23.3 rule 1): every hashed value is left-padded to the modulus width, and an implementation that skips it agrees with everyone else until a value happens to carry a leading zero byte, at which point roughly one login in 256 fails in a way that reads as a flaky network — which is why the vendored vectors are built with a leading-zero salt *and* a leading-zero `x` rather than random ones. The second is that the identity inside the KDF comes from the server's challenge response and never from what the human typed (rule 2): AXIAM lets a user sign in with a username or an email while only one of the two is bound into `x`. The third is that `M2` verification is mandatory (rule 6) — skipping it keeps the half of SRP that authenticates the client to the server and throws away the half that authenticates the server to the client, leaving a rogue endpoint that never knew the verifier indistinguishable from the real one. Two deliberate divergences from RFC 5054 are recorded rather than inherited: SHA-256 rather than SHA-1, and `x` as a memory-hard KDF output rather than a bare hash — the latter because a bare-hash verifier would be *cheaper* to attack offline than the Argon2id hashes AXIAM stores today, making adoption a net regression at rest. Both KDFs (`argon2id`, `pbkdf2_sha256`) are mandatory for login and the server dictates which per exchange; PBKDF2 exists because three languages have no vetted Argon2 binding in their standard distribution, and shipping SRP that only half the SDKs could speak would have been worse than shipping a weaker-but-universal fallback. §23.6 explains a server behaviour an SDK cannot infer and must not undo: `srp_mode: required` refuses password login for **every** principal in the tenant rather than only the enrolled ones, because the per-user variant would split the response on a fact about the account and turn `/auth/login` into an enumeration oracle costing one junk password per name. That uniformity is also why `required` is the last step of a migration and not the first — a verifier needs the plaintext password and a stored Argon2id hash is not invertible, so nobody can be enrolled retroactively. PHP is the one **conditional** posture in §23.8: it has no native bignum and neither `ext-gmp` nor `ext-bcmath` is guaranteed present, so its `srpAvailable()` reports `false` rather than throwing at login time; **§23.3 rule 4 errata and the §23.8 table corrected 2026-08 (contract 1.25)** — **documentation only; no SDK behaviour changes, no signature moves, and nothing that was conformant under 1.24 stops being so.** Implementing §23 across all eleven SDKs turned up a fact the chapter had assumed away: `argon2id` is not universally computable, and not for want of a dependency. PHP's only Argon2id that takes a caller-supplied salt (`sodium_crypto_pwhash`) requires exactly 16 bytes where §23.5's salt is 32, and `password_hash()` accepts no salt at all; Swift Crypto ships no Argon2 and none exists for every platform its SDK supports; C and C++ get it from OpenSSL only at 3.2 and later. Rule 4 already told an SDK what to do about a KDF it cannot perform — refuse with `NetworkError` naming it, never substitute — so no implementation changes; what the errata adds is that such a refusal is **conformant rather than a gap**, and that the SDK must say so in its README together with the trade-off. That trade-off is real and belongs in the open: a tenant serving those clients sets `srp_kdf: pbkdf2_sha256`, and PBKDF2 is not memory-hard, so a leaked verifier database enrolled under it is cheaper to attack with GPUs than one enrolled under Argon2id — while §23.0's threat model, which is about proxies, request logs and heap dumps rather than about the cost of an offline attack, is unaffected either way. The §23.8 table is corrected in the same pass to say what each SDK actually does rather than what was projected for it, and gains a second conditionality axis, because "can this build do SRP at all" and "can this build serve this tenant's KDF" are different questions answered at different times — the first by `srpAvailable()` before a login is attempted, the second by a `NetworkError` during one; **§23 rewritten from SRP-6a to OPAQUE (RFC 9807) 2026-08 (contract 1.26)** — **breaking for any SDK that implemented §23 under 1.24/1.25; no change to §1–§22 and no signature moves outside §23.** SRP is removed from AXIAM entirely rather than deprecated, and nothing migrates: a verifier cannot be converted into a registration record, because both are sealed against a plaintext the server has never had, and AXIAM is unreleased. Three reasons, in descending order of weight. OPAQUE was published as **RFC 9807** in July 2025, closing the one blocker 1.24's own text named — it was a draft when SRP was chosen, and improving implementation coverage was written down as the migration trigger. It resists the pre-computation attack SRP is open to, which is not a marginal gain: a stolen verifier database was offline-attackable at exactly the cost of the KDF, and that is why AXIAM's SRP had to bolt a memory-hard KDF onto RFC 5054's bare hash merely to *match* the Argon2id hashes it replaced, whereas a stolen OPAQUE record additionally requires the tenant's OPRF seed and without it there is no dictionary attack to mount at any cost. And it is specified to the byte, where AXIAM's SRP carried two documented divergences from its own RFC. **The structural change is §23.1, and it is the one to read first: an SDK MUST NOT implement the protocol.** SRP was hand-written eleven times because it is modular arithmetic and every language has a bignum; OPAQUE needs an OPRF, `hash_to_curve`, `expand_message_xmd`, an envelope and a three-message AKE, so every SDK binds one audited implementation — compiled, through WebAssembly, or through a C ABI — with Go the single permitted exception because a vetted RFC 9807 library exists for it and cgo would break `CGO_ENABLED=0` for every consumer. That costs SDKs their pure-source installs and buys back the whole of 1.25's errata: `pbkdf2_sha256` is gone, the second conditionality axis is gone, no tenant has to weaken its KDF policy to serve PHP or Swift clients, and the weaker KSF rung is now scrypt, which is memory-hard. Four §23 obligations disappear rather than change. There is **no server proof to verify** — RFC 9807's AKE authenticates the server during the handshake, so 1.24's rule 6, which had to mandate an `M2` check in capitals because skipping it silently discarded half the protocol, describes a failure mode that no longer exists. There is **no `PAD()`**. There is **no identity in the key derivation**, so `login/start` returns no identity field, `/auth/reset/context` no longer discloses the account's username, and a rename no longer invalidates a credential. And there is **no `register/finish` endpoint**: a record can only be built where the plaintext legitimately exists on the client, and every such moment is already an endpoint that takes a password. What is genuinely new is that enrolment now costs a server round trip — `POST /auth/opaque/register/start`, unauthenticated by necessity because it is called while creating a user who does not exist yet, and safe because the server mints the credential identifier itself. `POST /api/v1/admin/bootstrap` is the one endpoint that takes no enrolment object at all: it already receives the plaintext password because it has to hash it, so it runs both halves itself and stays a single call. §23.7's fixture is correspondingly smaller and an SDK author should read §23.7's first three paragraphs before concluding something is missing — what each SDK still owns is hex, field mapping, honouring the server's KSF parameters and the §2 error taxonomy, and that is what is pinned; **§22.5's firing list gains usernameless passkey sign-in 2026-08 (contract 1.27)** — **no SDK signature moves and no change to any SDK-implemented surface**; WebAuthn is a browser ceremony and no SDK speaks it. It is recorded here because §22.5 enumerates where `login.post_auth` fires, and a reactor author reading that list is the person who needs to know the list grew. The server gained `POST /api/v1/auth/webauthn/authenticate/discoverable/finish`, a sign-in that completes without a username and therefore without the password step that fired the event for the username-bound ceremony. The carve-out the section already carried — WebAuthn `authenticate/finish` does not fire, because it continues a login gated at its first step — reads as covering this one too, and does not: there is no first step to have been gated at. Left unfired it would have been SEC-095 a second time, with the bypass being a button rather than an identity provider. It behaves as the federated paths do, refusing `require_mfa` rather than dropping it, since a one-round-trip sign-in has no step-up branch — and the ceremony required user verification to complete, so the factor a step-up would demand was already presented; **§24 (WebAuthn and passkeys), §25 (account lifecycle and MFA enrolment) and §26 (pushed authorization requests) added, and §22.11's deferral narrowed, 2026-08 (contract 1.28)** — one breaking change, logged above, and everything else additive. Contract 1.27 had recorded in passing that “WebAuthn is a browser ceremony and no SDK speaks it”; the first half is true and the conclusion was wrong, because a ceremony is two exchanges stacked and only the one with the *authenticator* needs a browser. The one with AXIAM is four JSON round trips, which is what an SDK is for, and a Go service enrolling a passkey for a client it fronts or a Java backend completing a ceremony a handset ran speaks it without ever touching `navigator.credentials`. §24 therefore cuts three ways. The relying-party layer and the **JSON bridge** (§24.6a) bind all eleven SDKs; the linked-API helper (§24.6b) is offered only where the build can reach an authenticator — TypeScript's browser build, the Rust WASM build, and Swift on both iOS 16+ and macOS 13+. The bridge is the part worth reading twice, because it is what makes the third column a statement about convenience rather than about capability: Android's Credential Manager takes and returns the WebAuthn **JSON form as a string**, so `axiam-kotlin-sdk` stays a plain `kotlin("jvm")` library — no Android Gradle Plugin, no AAR, no second coordinate — and an Android app still runs a full ceremony by passing `requestJson` into `CreatePublicKeyCredentialRequest` and the response JSON straight back. §24.6b rule 2 then makes every remaining absence deliberate rather than a gap by **forbidding** an SDK from emulating an authenticator in software, which would put a key in process memory and call it a second factor. The rule the rest of §24 hangs off is §24.0: the server chooses every option and verifies every response, so an SDK passes both through byte-for-byte. Not because the fields are hard — they are not, and that is the hazard: relaxing `userVerification` to `“preferred”` because a CI authenticator kept prompting weakens a ceremony the server believes it configured, and the server cannot detect it, since an assertion produced under weaker options is a valid assertion. Two mappings override §2 and each loses something real if left generic: a `403` on `register/finish` is the tenant's attestation policy refusing *this* authenticator and its message is the only way the holder of a security key learns a different one would work, and a `503` on `register/start` is a server configuration state that §16 MUST NOT retry — the second documented exception to the retry policy after §20's. §24 also lands with a server fix it depends on: both `authenticate/*/finish` endpoints answered with the token pair in the body and set no cookies, which made a browser passkey sign-in impossible to complete and left `POST /api/v1/auth/refresh` — which reads the refresh token from `axiam_refresh`, never from a body — unreachable afterwards; they now set the same triple and the same `X-CSRF-Token` header as the password path, with the body unchanged so non-browser clients are not asked to read a cookie jar. §25 closes the other end of the same omission: §1 locked the *middle* of an account's life, so the nine operations that get an account into a state where §1 applies — both MFA enrolment paths, email verification, password reset — were reachable only by hand-rolling a POST against a path the SDK also knew, which is the divergence §1 exists to prevent arrived at through omission rather than disagreement. Its one breaking change is logged; its one field an implementer will get wrong is `totp_uri`, which *contains* `secret_base32`, so an SDK that wraps the secret and leaves the URI bare has wrapped nothing — which is why §25.6 requires scanning output for the secret **value** rather than the field name. §26 states PAR, whose likeliest defect is stated in the section rather than left to a table: it answers **`201`**, and a success predicate written `== 200` treats every successful push as a failure. Its other rule worth reading is that the authorization URL carries exactly `client_id` and `request_uri` and the server **refuses** a request mixing a `request_uri` with inline parameters rather than merging them — merging is where parameter confusion lives, and an SDK re-adding the parameters “for compatibility” would restore the attack. Finally §22.11: Swift, C and C++ still bundle no AMQP client, and the deferral is narrowed to that. Until now it also took the **protocol** with it — v2 HMAC over a canonical serialization with a `null` signature placeholder, freshness in both directions, nonce and correlation binding, the §22.5 allow-lists — which is the half with the sharp edges, none of them AMQP-shaped, left for each integrator to reimplement from prose. The three now ship §22.1–§22.8 and §22.14 over a caller-supplied transport and MAY claim §22; because the runtime never sees a URL, §8b rule 7 is satisfied by **exposing the guard as a public tested function** rather than by a paragraph, which is exactly the failure contract 1.23 was written to stop; §23.4 rule 7 and §23.5's `login/start` response gain the `mode` field 2026-08 (contract 1.29) — a failed `KE2` under `opaque_mode: optional` now REQUIRES a retry over `POST /auth/login`, where before every SDK was told the exchange was final. That reading locked out every user of a tenant that enabled `optional`, because an account with no registration record is the ordinary case under it and the server deliberately makes that indistinguishable from a wrong password. `required` is unchanged and an absent `mode` reads as `required`, so an SDK that does nothing stays correct against a `required` tenant and only a tenant mid-migration is affected; §5.2.3 tenant-scoped role assignments added 2026-08 (contract 1.35) — additive in both directions: `tenant_scope` on the three assignment bodies and `reachable_tenant_ids` on `/auth/me`, both absent against an older server and both meaning "unrestricted" when absent, so an SDK that does nothing stays correct; the acting-tenant header is corrected to `X-Axiam-Tenant` 2026-08 (contract 1.36, issue #395) — §5.2, §5.2.2 and §5.2.3 named it `X-Tenant-ID`, which the AXIAM server does not read, so a client following the contract to the letter switched nothing and got a successful response describing its own tenant's data. §5 rule 2's unconditional `X-Tenant-ID` is deliberately NOT renamed and now carries a note saying why: an unconditional header naming the constructor tenant would override the acting tenant on every request made after a switch. §5.2.2 rule 4 added 2026-08 (contract 1.36) — an errata, not a wire change: the server now scopes every self-service endpoint to `principal_tenant_id` rather than only `POST /auth/password/change`, so calls that answered `404` for an organization-level caller acting on a child tenant now succeed. Nothing is added to any request or response and no SDK needs a change; the rule is written down so that an SDK does not "fix" the old `404` by stripping `X-Tenant-ID`, which would break the administrative form of the same endpoints. `/api/v1/auth/me`, `/api/v1/auth/password/change` and `/api/v1/admin/bootstrap` also appear in `openapi.json` for the first time — all three were normative here and served by the server throughout, and were missing from the generated document only because their handlers were never listed in its `paths(…)`; §12.1 gains four operations and six normative rules 2026-08 (contract 1.37) — `sso_providers`, `sso_start_oauth2`, `sso_complete_oauth2` and `sso_complete_handoff`, covering the public "Sign in with X" surface: a providers listing that deliberately cannot distinguish an unknown organization from an unconfigured one, the plain-OAuth2 variant for providers that issue no ID token (GitHub, Facebook) with its reduced assurance and mandatory server-side PKCE stated rather than implied, single-use 60-second handoff codes that let a cross-site SAML or Apple return issue a `SameSite=Strict` session, organization→tenant inheritance of a federation config, and the accepted-tenant list a templated issuer (Entra's `common` authority) now requires. Additive: no existing operation, request or response changes, and an SDK that ships §12 as it stood remains conformant — it simply cannot render a login button. The leading version number above also jumps from a stale `1.29` to `1.37`, which is where the changelog chain had already reached; §12.1 rule 12a added 2026-08 (contract 1.38) — on the SAML and Apple flows the identity provider never sees the SPA `redirect_uri`, because it posts to an AXIAM server endpoint instead, so the server confines the handoff redirect to its own issuer origin plus whatever `AXIAM__AUTH__SSO_SPA_ORIGINS` names and answers `400` for anything else. Additive and restrictive on the server side only: an SDK that passes the deployment's own callback URL, which is the only value that ever worked, is unaffected; §12.1 rule 12a widened 2026-09 (contract 1.39) — the same deployment-origin rule now governs all four federated start operations rather than only the two cross-site ones, with the provider's registered-redirect comparison kept as a second, independent layer on the OIDC and OAuth2 flows rather than the only one. Additive and restrictive on the server side only, exactly as 12a itself was: no SDK code changes, and a deployment whose SPA is on a different origin than its issuer must set `AXIAM__AUTH__SSO_SPA_ORIGINS` for those two flows as it already had to for the other two; §21.3 rules 1–2 and the §21.5 `mtls_endpoint_aliases` row added 2026-09 (contract 1.40) — RFC 8705 §5 discovery metadata naming the endpoints of a deployment whose mutual TLS terminates on a separate host. **Additive and server-side only**: the member is absent unless an operator configures `AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`, so every existing SDK keeps working unchanged against every existing deployment. It becomes normative only for an SDK implementing the §21 *client* role, which must prefer an alias over the top-level endpoint on a call it makes over mTLS; the guard role (§10.1 rule 9) is untouched; §5 rule 3's rationale amended and the §21.5 `token_endpoint_auth_methods_supported` row widened 2026-09 (contract 1.41, W8) — the server now accepts `client_secret_basic` (RFC 6749 §2.3.1) for third-party relying parties and advertises it in discovery. **Text only: the rule itself is unchanged and no SDK changes any code.** SDKs keep `client_secret_post` because the two methods carry the identical credential and only the header channel is routinely logged by intermediaries; an advertised method is a statement about the deployment, not an instruction to the client; §21.5 gains `code_challenge_methods_supported` and `token_endpoint_auth_signing_alg_values_supported` 2026-09 (contract 1.42) — both are RFC 8414 members AXIAM already honoured and did not advertise, found by the first OpenID Foundation conformance run rather than by review; §21.3 rule 2 clause 4 (an alias is used verbatim), the §21.3.1 discovery test vectors and the §21.10 per-SDK alias table added 2026-09-12 (contract 1.43); §10.4 the revocation feed and §10.2's scoping of its MUST NOT to per-request polling added 2026-09-12 (contract 1.44); §27.1 gains `certificates.sign_csr` and §27.5 states its response carries no sensitive field, §24.1/§24.5/§24.7/§24.8/§25.1/§25.2 gain the `webauthn/setup/register/{start,finish}` pair, and §5.2 rule 4 gains the `403 mfa_enforced` self-service-reset refusal, all 2026-09 (contract 1.45); §26.2 rule 3 states both forms a spent-`request_uri` refusal takes and which one a conformant SDK can reach 2026-09-14 (contract 1.46) — documentation only, no SDK behaviour changes and `openapi.json` byte-identical; `token_endpoint_auth_methods_supported` gains `none` and `openapi.json` gains the `none` enum value with an optional `OAuth2ClientCreatedResponse.client_secret` 2026-09 (contract 1.47) — a capability statement about the deployment, not an instruction to a client, and no SDK operation changes; §28 MCP resource-server helpers added 2026-09-17 (contract 1.48), carrying with it the RFC 8707 `openapi.json` additions T21.3 recorded unnumbered for it to fold in. §28 is SHOULD-level, off by default and additive by construction — with its `resource_metadata_url` option unset a guard is byte-for-byte what it was — and it references §10.1 row 6, §10.2, §10.3, §11 and §21.7 without changing any of them; §28.11 cross-SDK conformance review and the §28.3 rule 1 media-type clarification 2026-09-17 (contract 1.49); `oauth2_clients.create_registration_token`'s `initial_access_token` made `Sensitive` in §27.5 2026-09-18 (contract 1.50); §1/§1.1.1 `authenticate_device`, `validate_token` and `introspect_token`, §5.2 rule 1's acting-tenant helper moved to SHOULD, §6.1's device login and certificate-bound device token, §27.0's five exclusions, §27's figures re-rendered at 162 operations, §27.5 rule 5 and §27.6.1's manifest additions, §27.10's per-SDK manifest table and §27.13's dogfooding-remediation model notes 2026-09-23 (contract 1.51) — every new request field optional, the one tolerance an existing SDK owes being the open decoding of `CertificateType`; §27.14's cross-SDK conformance review and its six clarifications (N1 §10.1 every entry point a guard, N2 §17.1 the acting tenant in the memo key, N3 §27.13 the shape of a `SubjectAltName`, N4 §6.1 rule 11 the device credential's lifecycle, N5 §5.2 rule 1 the acting-tenant helper's semantics, N6 §27.6.1 bindings) 2026-09-24 (contract 1.52) — no wire change, and `CONTRACT.md` the only artefact to re-sync; §28.12 RFC 7592 client configuration operations (`read_client_registration`, `update_client_registration`, `delete_client_registration`, with `registration_access_token` `Sensitive` throughout) and §28.0's scoping of its local-computation rules to §28.1–§28.11 2026-10-02 (contract 1.53) — additive, `openapi.json` gaining the three `/oauth2/register/{client_id}` operations and their security scheme; §30 directory configuration (the `directory` management namespace — `get`, `set`, `update`, `delete`, `link_account`, `get_sync_status` — with `bind_secret` `Sensitive` and write-only, the P23W2-01 rule, the address guard's refusals, the `opaque_mode = required` exclusion and the `directory:link` permission) and §29 reserved for SAML service-provider registration 2026-10-04 (contract 1.54) — additive, text ahead of the routes, `openapi.json` and `management-registry.json` unchanged until the server task regenerates them; §29 SAML service-provider registration (the `saml` management namespace — the SP registry, `parse_sp_metadata` and the IdP signing-credential lifecycle with `promote` — nothing `Sensitive`, no key member on `SamlIdpCredential`, the `saml_sp:read` / `saml_sp:write` / `saml_idp:credential` permissions) 2026-10-04 (contract 1.55) — additive, text ahead of the routes, `openapi.json` and `management-registry.json` unchanged until T23.2.5 regenerates them; §32 SSF stream registration and the receiver helper (the `ssf` management namespace with `authorization_header` `Sensitive`, the receiver protocol for reference, `verify_set` and `poll` SHOULD in the seven full-surface SDKs) 2026-10-04 (contract 1.56) — additive, routes and regenerated `openapi.json` and `management-registry.json` in the same task; §31 outbound SCIM targets (the `scim_targets` management namespace — `list`, `create`, `get`, `update`, `delete`, `reconcile` — with `credential` `Sensitive` and write-only, the credential bound to its URL, `409` on an overtaken update, `reconcile` as `202` / `409`, `delete` deprovisioning nothing downstream, human principals only) 2026-10-05 (contract 1.57) — additive, routes and regenerated `openapi.json` and `management-registry.json` in the same task; §33 CIBA, the client's half (`ciba_initiate`, `ciba_poll`, `ciba_await`, `ciba_handle_ping`, poll and ping, the signed authentication request; `auth_req_id`, `client_notification_token` and the signing key `Sensitive`; `ciba_initiate` never retried) 2026-10-05 (contract 1.58) — additive, routes and `openapi.json` already regenerated by the server tasks; with §21.3.1 vector A amended in place for a seventh `mtls_endpoint_aliases` member, `backchannel_authentication_endpoint`, which every SDK pinning the six keys must re-vendor; the cross-SDK review of the 1.53 – 1.58 ports (§34: the posture tables of §28.12.7 and §29.10 … §33.10 filled from the merged ports, clarifications P1 … P12, forty-two divergences with eleven follow-ups F-59-01 … F-59-11) 2026-10-09 (contract 1.59) — no wire change, `CONTRACT.md` the only artefact to re-sync; the answers to the sixteen questions of #588 (§34.4: a fallible replay store, so a store that cannot answer leaves a SET unjudged and Rust's `ReplayStore` changes incompatibly; a successful cold-cache key fill not counted against the refetch limit, a failed one counted; a fresh connection per never-retried write in C#, C and C++; one validation error for every local refusal; event types carried as strings; an input type built for submission, not decoded; `unjudged`; the §21.3.1 vector A pin and the §21.9 DPoP-decline reason; SDK rows assigned to each of the eleven) and the additions of the 1.0.0 platform release (§31's optional `expected_updated_at`, `notification_rules`' optional `window_minutes`, the `403` on the device approval routes, §15.2 rule 9 on the actor token, §8's minimal-profile note, informative notes on client removal, tenant deletion, the `email_config` address policy, the CIBA pending list and `ValidateCredentials`, and the new informative §35 on certificate revocation lists) 2026-10-10 (contract 1.60) — clarifications and two optional fields, `openapi.json` and `management-registry.json` regenerated by the same release, `CONTRACT.md` re-synced with them in all eleven SDK repositories*
*Binding since: 2026-06-30*
*Reference: D-09, D-10 in `.planning/phases/15-sdk-foundation/15-CONTEXT.md`*
