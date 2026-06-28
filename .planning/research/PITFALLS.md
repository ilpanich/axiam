# Pitfalls Research — AXIAM Client SDKs (v1.1)

**Domain:** IAM client SDK — multi-language wrappers for an existing hardened IAM server
**Researched:** 2026-06-28
**Confidence:** HIGH (auth model grounded in AXIAM server source; OAuth2 pitfalls grounded in RFCs + documented CVEs)

---

## Critical Pitfalls

### Pitfall 1: Double-Refresh Race Destroys the Token Family

**What goes wrong:**
AXIAM uses single-use rotating refresh tokens (RFC 6749 §10.4 / RFC 6819 §5.2.2.3). If an SDK fires two requests concurrently and both detect a 401, both attempt a refresh with the same token. The server detects reuse of a consumed token and **revokes the entire token family**. The user is logged out and cannot silently recover — they must re-authenticate. This is not a theoretical issue; it is a documented pattern in the MCP TypeScript SDK (issue #1760) and any OAuth library that lacks a single-flight refresh guard.

**Why it happens:**
SDK authors model the refresh as a simple "if 401 → refresh → retry" interceptor without considering parallelism. In a modern async environment (browser SPA, Go goroutines, asyncio, Spring WebFlux) multiple requests easily race.

**How to avoid:**
- Implement a **single-flight refresh guard**: when a refresh is in flight, all subsequent 401 responses must wait on the same in-flight promise/future and reuse the resulting token. Never issue a second refresh while one is pending.
- Use a language-appropriate primitive: `Promise` chain with shared state (TS), `asyncio.Lock` (Python), `sync.Once`/channel (Go), `Mutex` + `Condvar` (Rust/Java/C#).
- After a successful refresh, update the shared token store atomically before releasing waiters.
- Treat a 401 response to a refresh request as **credential compromise** (not a retriable error) — surface it as an `AuthenticationError` requiring re-login, do not retry.

**Warning signs:**
- "User randomly logged out after a burst of requests" in production logs.
- `401` response to `/api/v1/auth/refresh` when the user just logged in.
- Two refresh requests in flight at the same timestamp in access logs.

**Phase to address:** T17.x (each SDK) — build the guard into the base `HttpClient` or `AuthManager` class before any other feature. Test with a fixture that fires 5 concurrent requests on an expired token.

---

### Pitfall 2: Tokens Leaked into Logs, Error Objects, or Debug Output

**What goes wrong:**
Bearer tokens, refresh tokens, or AXIAM's opaque refresh values appear in:
- Structured log lines (e.g., logging the full `Authorization` header or HTTP response body containing the token).
- Error messages surfaced to the caller (e.g., wrapping the raw HTTP 401 response body in an exception message).
- Debug/trace output from underlying HTTP libraries (reqwest, axios, requests, okhttp) that is enabled by default.
- Example code in the SDK repository that embeds real tokens in comments or fixtures.

AWS CLI's LeakyCLI vulnerability (CVE-2023-36052, CVSS 8.6) showed that credential leakage through logging is a systemic IAM SDK failure mode.

**Why it happens:**
Logging frameworks eagerly serialize request/response objects. Error wrapping captures the raw response body. Developers paste tokens into examples "to show it working".

**How to avoid:**
- Never log `Authorization` headers or `Set-Cookie` values. Scrub them before passing to any logger.
- Error types must redact token values — wrap only the HTTP status code and a non-sensitive error string, never the raw response body containing a token.
- Implement a `Sensitive<T>` wrapper (or equivalent) that suppresses `Debug`/`Display`/`toString`/`__repr__` for token fields across all languages.
- Provide a canonical `TokenStore` type that never derives/implements `Debug` / `Serializable` / `Encodable`.
- All examples must use placeholder strings (`<your-access-token>`, env var lookups) — never real tokens.

**Warning signs:**
- `grep -r 'Bearer ' ./logs` returns results.
- Exception stack traces include `Authorization: Bearer eyJ...`.
- `cargo clippy`/`mypy`/`golangci-lint` passes but example code contains hardcoded tokens.

**Phase to address:** T17.x — establish `Sensitive<T>` / redacted error types as the first PR per SDK; enforce via CI linting rule (`grep -r 'eyJ' examples/` fails the build).

---

### Pitfall 3: PKCE Downgrade — `plain` Method or Missing Verifier

**What goes wrong:**
AXIAM enforces S256 PKCE for all public clients. An SDK that:
(a) sends `code_challenge_method=plain` (which AXIAM's server rejects for public clients — see Phase 11 enforcement),
(b) omits the `code_challenge` entirely, or
(c) generates a verifier but sends the verifier itself as the challenge (plain in disguise)

…will fail or, if the server is ever misconfigured, silently allow authorization code interception attacks.

**Why it happens:**
Developers copy-paste OAuth2 examples that predate PKCE or use libraries that default to `plain`. Some `state`-machine OAuth2 libs require explicit opt-in to S256 that is easy to miss.

**How to avoid:**
- Hard-code `code_challenge_method=S256` in the SDK. Do not accept `plain` as a parameter.
- Generate the `code_verifier` as 43–128 cryptographically random URL-safe base64 characters (use the platform CSPRNG — `OsRng` in Rust, `secrets.token_urlsafe` in Python, `crypto.randomBytes` in Node, `SecureRandom` in Java, `RandomNumberGenerator` in C#).
- Compute `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))` without padding.
- Store the verifier in-memory (never on disk or in a cookie) between authorization redirect and callback.
- Reject any configuration attempt to set `plain` at compile time (type-level enum, not a string).

**Warning signs:**
- Server returns `400 invalid_request` with `code_challenge_method not supported`.
- The authorization URL emitted by the SDK contains `code_challenge_method=plain` or no `code_challenge` at all.
- Unit tests pass against a mock that does not enforce S256.

**Phase to address:** T17.x — PKCE is required from day 1 of the OAuth2 flow; do not add it as a "todo" after the flow works.

---

### Pitfall 4: Missing CSRF Token on State-Changing REST Calls

**What goes wrong:**
AXIAM enforces CSRF double-submit on all `/api/v1` CRUD endpoints (Phase 11, REQ-15). An SDK that omits the `X-CSRF-Token` header on `POST`/`PUT`/`PATCH`/`DELETE` will receive `403 Forbidden`. Worse: a non-browser SDK that disables CSRF "because it's a server-to-server call" creates a pathway for CSRF attacks if the same token is reused in a browser context.

**Why it happens:**
CSRF is mentally associated with browsers. Server-side SDK authors assume it doesn't apply to them. In practice, the server cannot distinguish SDK callers from browser callers.

**How to avoid:**
- SDK's HTTP client interceptor must: (a) fetch the CSRF token from the `X-CSRF-Token` response header or a dedicated endpoint on first request, (b) attach it to all subsequent state-changing requests, (c) refresh it after a 403 due to CSRF failure.
- For machine-to-machine (service accounts using Client Credentials), confirm whether CSRF enforcement applies to that grant type; if the server exempts it, document the distinction.
- Non-browser SDKs must never skip CSRF even if they "know" it's server-to-server — the server decides policy.

**Warning signs:**
- `403` on `POST`/`PUT`/`DELETE` with a body like `{"error": "csrf_token_missing"}`.
- Developers monkey-patch the SDK to add a hardcoded CSRF token value in tests.

**Phase to address:** T17.x — include CSRF header management in the base HTTP client from the start, alongside cookie jar management.

---

### Pitfall 5: httpOnly Cookie Mishandling in Non-Browser Clients

**What goes wrong:**
AXIAM delivers the access token as an `httpOnly; Secure; SameSite=Strict` cookie. Browsers handle this transparently. Non-browser clients (server-side Java, Python, Go, C#, Rust) must explicitly:
- Maintain a cookie jar across requests.
- NOT copy the cookie value into an `Authorization` header (the server does not accept Bearer tokens on cookie-auth endpoints).
- NOT store the cookie value in a log, file, or serializable object (it is equivalent to a plaintext access token).
- Respect `Path=/` for the access cookie and `Path=/api/v1/auth/refresh` for the refresh cookie — requests outside these paths must not send the wrong cookie.

**Why it happens:**
HTTP client libraries default to no cookie jar (reqwest, okhttp in some modes, Go's net/http). Developers unfamiliar with httpOnly semantics try to extract the cookie value and use it as a Bearer token.

**How to avoid:**
- Configure the HTTP client with a **persistent cookie store** on construction. This is mandatory, not optional.
- Use `cookie_store(true)` in reqwest, `CookieManager` in Java OkHttp, `requests.Session` in Python, `http.CookieJar` in Go.
- Never expose the cookie value through a public `get_access_token()` method. If callers need to know "am I authenticated?", expose only a `is_authenticated() -> bool` or a decoded claims struct with non-sensitive fields.
- For SDK consumers who need the token for a third-party call (e.g., passing it to another microservice), document that they should use the AXIAM gRPC authz endpoint instead of forwarding the cookie.

**Warning signs:**
- `401 Unauthorized` on every request after login (cookie jar not persisted between requests).
- SDK exposes `get_cookie_value()` or `get_access_token_string()`.
- Developers ask "how do I get the Bearer token?" — they should not need it.

**Phase to address:** T17.x — cookie jar must be instantiated in the SDK constructor; test that a login followed by a profile fetch succeeds without any manual token handling by the caller.

---

### Pitfall 6: Missing or Hardcoded Tenant Context

**What goes wrong:**
Every AXIAM endpoint is tenant-scoped. The JWT contains `tenant_id` and `org_id` claims; the server enforces them. But SDK callers can forget to set tenant context (e.g., when constructing a client against the wrong base URL), or the SDK silently sends requests without the tenant slug resolved. The result is a cross-tenant data exposure if the server's RBAC check has a gap, or a silent 404/403 that is hard to diagnose.

**Why it happens:**
Multi-tenancy is an AXIAM-specific requirement that is not obvious from REST API surface inspection. Developers copying from a "standard OAuth2 client" example miss the tenant routing layer (e.g., the `/t/{tenant_slug}/` path prefix or the `X-Tenant-ID` header).

**How to avoid:**
- The SDK `Client` constructor MUST require a `tenant_slug` or `tenant_id` parameter — it must not be optional.
- Tenant context must be embedded in the base URL or injected as a header on every request by the SDK internals — never left to the caller to remember per-request.
- If the server returns a tenant mismatch error, the SDK must surface a clear `TenantMismatchError`, not a generic `403`.
- Integration tests must include a two-tenant fixture that asserts tenant A cannot read tenant B's resources.

**Warning signs:**
- SDK examples show `AxiamClient::new("https://axiam.example.com")` without a tenant parameter.
- `404 Not Found` on a resource the caller just created (wrong tenant in the URL).
- Test suite only uses a single tenant.

**Phase to address:** T17.x — enforce at construction time; reject a no-tenant constructor at compile time if the language's type system permits (Rust, TypeScript).

---

### Pitfall 7: TLS Verification Disabled "For Convenience"

**What goes wrong:**
All AXIAM channels require TLS 1.3 minimum. An SDK that ships with `verify=False` (Python requests), `InsecureSkipVerify: true` (Go), or `TrustManager` that accepts all certs (Java) allows man-in-the-middle attacks — an attacker can steal credentials and tokens in transit. This pattern appears frequently in "getting started quickly" examples and then ships to production.

Datadog's static analysis rules for Go explicitly flag `grpc.WithInsecure()` as a security defect.

**Why it happens:**
Self-signed certificates in development environments are painful. Developers disable verification to unblock themselves and forget to re-enable it.

**How to avoid:**
- Default to strict TLS verification in all SDK HTTP and gRPC clients. No exceptions.
- Provide a `with_custom_ca(path_to_pem)` option for self-signed dev certificates — never `skip_tls_verification()`.
- For gRPC: use `SslCredentials` (not `InsecureChannelCredentials`); allow injecting a custom root CA bundle.
- For mTLS (IoT/service accounts): the SDK must load client certificate + private key and present them in the TLS handshake; do not silently fall back to no client cert.
- CI integration tests must run against a TLS-enabled test server (self-signed CA in test fixtures).

**Warning signs:**
- SDK README shows `verify=False` or `insecure=true` in any example.
- `InsecureSkipVerify`, `WithInsecure`, `TrustAllCerts`, or equivalent identifiers appear in SDK source.
- gRPC channel constructed with `grpc.insecure_channel()`.

**Phase to address:** T17.x — no insecure transport flag in SDK API surface; blocked by linting rule in CI from day 1.

---

### Pitfall 8: gRPC Channel Leak and Missing Keepalive

**What goes wrong:**
The AXIAM gRPC authz service is designed for low-latency in-process mesh calls. An SDK that:
(a) opens a new channel per request — leaks connections and exhausts server-side connection slots.
(b) reuses a single global channel without keepalive — the channel goes idle and TCP/TLS state is torn down silently; the next request fails or hangs.
(c) does not cap concurrent streams per channel — a burst creates backpressure that the server's concurrency limits (set in Phase 11) will reject with `RESOURCE_EXHAUSTED`.

**Why it happens:**
gRPC channel lifecycle is non-obvious. HTTP/1.1 SDK authors treat each connection as disposable; this is wrong for HTTP/2.

**How to avoid:**
- Maintain a single shared `Channel` per `AxiamClient` instance (not per call).
- Configure keepalive: `keepalive_time=30s`, `keepalive_timeout=10s`, `keepalive_permit_without_calls=true`.
- Set a deadline on every unary RPC call (e.g., 5s default); never use a no-timeout call.
- Cap max concurrent streams (match the server's setting from Phase 11).
- Provide an explicit `close()` / `shutdown()` method on the SDK client; document that it must be called on application shutdown.
- In tests, assert that creating 100 clients and calling them does not exhaust file descriptors (integration test with `ulimit -n 64`).

**Warning signs:**
- Server logs show thousands of new TLS handshakes per minute.
- `RESOURCE_EXHAUSTED` gRPC status codes under moderate load.
- SDK client object does not have a `close()` method.

**Phase to address:** T17.1 (Rust, first SDK) establishes the channel management pattern; T17.3+ (Python, Go, Java) adapt to language idioms.

---

### Pitfall 9: AMQP HMAC Signature Verification Skipped

**What goes wrong:**
AXIAM AMQP messages are HMAC-SHA256 signed (Phase 11, REQ-15). An SDK that consumes AMQP messages without verifying the signature accepts any message injected into the queue — including forged authz decisions or audit events. This is particularly dangerous for authz consumers that act on the message payload.

**Why it happens:**
AMQP client libraries (pika, lapin, amqplib) deliver messages without built-in payload authentication. HMAC verification is the application's responsibility; it is invisible unless the SDK author reads the AXIAM server code or documentation.

**How to avoid:**
- Every AMQP message consumer in the SDK must verify `HMAC-SHA256(shared_secret, message_body) == message_header['X-AXIAM-Signature']` before processing the payload.
- Treat HMAC verification failure as a **security event**: log it, reject the message (nack without requeue), and increment a metric. Do not silently ignore it.
- The shared secret must be loaded from an environment variable or a secret store — never hardcoded.
- AMQP message producers in the SDK must sign every outgoing message using the same shared secret.
- Integration test: deliver a message with a tampered body and assert the consumer rejects it.

**Warning signs:**
- SDK AMQP consumer does not read a `X-AXIAM-Signature` header.
- AMQP example code processes the message payload without a verification step.
- Shared secret is hardcoded in SDK source or test fixtures committed to the repo.

**Phase to address:** T17.x (any SDK with AMQP support: Rust T17.1, Python T17.3, Java T17.4, C# T17.5, Go T17.7) — verification must be in the base consumer, not optional.

---

### Pitfall 10: Clock Skew Causes Spurious Token Expiry on 15-Minute Tokens

**What goes wrong:**
AXIAM access tokens have a 15-minute lifetime. A 2-minute clock drift between the SDK host and the AXIAM server can silently expire 13% of the token lifetime. Worse: an SDK that pre-checks `exp` client-side (to decide whether to proactively refresh) may reject a still-valid token if the SDK host's clock is behind the server's.

**Why it happens:**
Server-side: the server stamps `exp = now + 900s`. SDK host: `now` is 120s behind. SDK sees `exp - now_local = -120s` and discards the token before it is actually expired server-side.

**How to avoid:**
- Do not pre-check `exp` client-side as the sole trigger for refresh. Let the server's 401 be the authoritative signal; treat a 401 as "refresh now".
- If proactive refresh is desired (to avoid latency on expiry): use `exp - now_local - 60s` as the threshold, where `60s` is a clock-skew buffer. Never use a zero-second buffer.
- Do not reject a token on the client side solely because `exp < now_local`. The server enforces the actual expiry.
- Document: SDK users must synchronize their host clock (NTP). Warn in the README that clock drift > 60s will cause authentication failures.

**Warning signs:**
- Repeated refresh calls even when the access token was just issued.
- `401` on the first request after a fresh login in test environments (host clock is wrong).
- SDK pre-validates JWT signature + `exp` client-side without a skew tolerance.

**Phase to address:** T17.x — establish clock-skew handling policy in the auth manager before any proactive-refresh logic; test with a fixture that sets `exp` to `now + 10s` and fires a request at `now + 5s`.

---

### Pitfall 11: Retry Storms on 401 / No Backoff

**What goes wrong:**
An SDK that retries immediately on a 401 without backoff can cause a thundering herd against the AXIAM token endpoint, triggering the server's rate limiting (10 req/min per IP from REQ-3) and locking out the SDK caller. In a multi-instance deployment, all instances refreshing simultaneously amplifies this.

**Why it happens:**
Retry logic is often copy-pasted from non-auth contexts where retrying immediately is fine. Token refresh has O(n_instances) fanout that is not present in idempotent GET retries.

**How to avoid:**
- After a failed refresh (not 401 on a resource endpoint, but 401 on the refresh endpoint), apply exponential backoff: 1s, 2s, 4s, max 30s, with jitter.
- Cap retry attempts at 3 before surfacing `AuthenticationError` to the caller.
- Emit a metric on refresh failure so operators can detect cascading logout events.
- Document: a 429 from the token endpoint means the caller is retrying too aggressively.

**Warning signs:**
- Log shows "refreshing token" 10+ times per minute for a single SDK instance.
- `429 Too Many Requests` from `/api/v1/auth/refresh` under normal load.
- SDK retry logic does not distinguish between retryable (network timeout) and non-retryable (401 on refresh) errors.

**Phase to address:** T17.x — retry policy must be defined in the base HTTP client before any endpoint-specific code.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Skip CSRF header in non-browser SDK | Fewer lines of code | Server returns 403 on all mutations; security gap if client-side rendering ever involved | Never |
| Hardcode `tenant_id` in SDK config | Simpler first example | Breaks multi-tenant deployments; creates cross-tenant data risk | Only in a test-only example with a comment |
| Use `plain` PKCE for easier debugging | Simpler code_challenge computation | PKCE protection nullified; AXIAM server rejects it anyway | Never |
| Disable TLS in CI tests | Avoids certificate setup | Production habit bleeds in; AXIAM TLS stack untested | Only with explicit `#[cfg(test)]` guard and a comment |
| Single-use token without single-flight refresh guard | Works for single-threaded tests | Token family revoked on concurrent access; silent user logout | Never |
| Log full HTTP response in debug mode | Easy debugging | Tokens appear in log files, CI output, crash reports | Never for auth responses; gate behind `if cfg!(debug_assert)` AND sanitize |
| No `close()` / shutdown on gRPC channel | Simpler API | File descriptor leak in long-running processes | Never in production SDKs |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| AXIAM REST (cookie auth) | HTTP client without cookie jar: every request after login returns 401 | Construct HTTP client with a persistent, cross-request cookie store |
| AXIAM gRPC | `grpc.insecure_channel()` for local dev, committed to repo | `grpc.secure_channel()` with a dev CA bundle; never insecure in committed code |
| AXIAM AMQP | Process message before verifying HMAC-SHA256 signature | Always verify signature first; nack without requeue on failure |
| OAuth2 PKCE flow | Store `code_verifier` in localStorage / a cookie | Store in memory only (function scope or short-lived session variable); wipe after token exchange |
| mTLS IoT clients | Load client cert but skip chain verification to tenant/org CA | Verify the full chain: client cert → intermediate CA → org CA; reject if chain breaks |
| Token refresh | Parallel requests each trigger independent refresh | Single-flight mutex: first caller refreshes, rest await and reuse result |
| Tenant routing | Forget tenant slug in base URL construction | Enforce tenant parameter in SDK constructor; embed in every request |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Exposing `get_access_token() -> String` in public SDK API | Token exfiltration via application code | Expose only decoded claims struct; never the raw token string |
| Caching AMQP shared secret in a public field | Secret exposed via reflection or debug output | Store in a `Sensitive<String>` / opaque type with no `Debug` impl |
| Treating `401` on refresh as retryable | Replay of a revoked token | Surface `AuthenticationError` immediately; require re-login |
| Allowing `S256` to be downgraded to `plain` via SDK config | PKCE protection bypass | Enum with only `S256` variant; no `plain` option exposed |
| Not validating `iss` / `aud` in SDK-side JWT decode | JWT from a different AXIAM tenant accepted | Always validate `iss` (matches expected server URL) and `aud` (matches client_id) |
| Serializing SDK client state (tokens) to disk for "session persistence" | Token persistence across process restarts creates plaintext secrets on disk | Require re-authentication on SDK client construction; do not persist tokens to disk |
| Secrets in SDK example code | Real credentials committed to public repo | All examples use `std::env::var` / `os.getenv` / `os.Getenv` / `Environment.GetEnvironmentVariable` |

---

## "Looks Done But Isn't" Checklist

- [ ] **Single-flight refresh guard:** Does the test suite fire 5 concurrent authenticated requests on an expired token and assert only ONE refresh call is made?
- [ ] **HMAC verification:** Does the AMQP consumer have a test that delivers a message with a tampered body and asserts it is rejected?
- [ ] **CSRF header:** Does every `POST`/`PUT`/`PATCH`/`DELETE` integration test assert the `X-CSRF-Token` header is present?
- [ ] **Tenant isolation:** Is there a test with two tenants asserting tenant A cannot read tenant B's resources?
- [ ] **TLS enforcement:** Does the CI test server use TLS (even a self-signed dev CA)? Does the SDK fail to connect when TLS verification is disabled in the server but not in the SDK?
- [ ] **No token in logs:** Does CI run `grep -r 'eyJ' logs/` and `grep -r 'Bearer ' logs/` and fail if results are found?
- [ ] **gRPC channel close:** Is there a test that creates a client, calls an endpoint, and then asserts `close()` releases the connection (no leaked goroutines / threads)?
- [ ] **PKCE S256 only:** Does the test suite assert that a request with `code_challenge_method=plain` is rejected by the SDK before it reaches the server?
- [ ] **Clock skew buffer:** Is there a test that sets token `exp` to `now + 30s` and confirms the SDK does NOT attempt a refresh until the 401 arrives from the server?
- [ ] **mTLS chain verification:** Is there a test that presents a client cert signed by a different CA and asserts the SDK (or server via mTLS) rejects it?

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| New gRPC channel per authz call | Connection exhaustion; high latency from repeated TLS handshakes | Single shared channel per SDK client instance | At ~50 calls/s with 10 SDK instances |
| Proactive token refresh on every request | Unnecessary refresh calls; token family thrash | Refresh only on 401 or when `exp - now < 60s` | At >1 req/s in a multi-instance deployment |
| Synchronous AMQP blocking call in async context | Event loop starvation (Python asyncio, Node.js) | Use async AMQP library (aio-pika for Python, amqplib for TS) | At >10 concurrent consumers per process |
| No connection pooling for REST client | TLS handshake per request; latency spikes | HTTP/1.1 keep-alive or HTTP/2; reuse the client instance | At >5 req/s per SDK instance |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Double-refresh race (single-use token family revocation) | T17.x — all SDKs at initial auth manager design | Integration test: 5 concurrent requests on expired token → exactly 1 refresh call |
| Token leakage in logs | T17.x — day-1 `Sensitive<T>` / redacted error types | CI: `grep -r 'eyJ' logs/` must return empty |
| PKCE downgrade | T17.x — hardcoded S256, no `plain` option | Test: SDK rejects `plain` at call site; server also rejects if it slips through |
| Missing CSRF header | T17.x — base HTTP client interceptor | Test: mutation without CSRF header returns 403; SDK surfaces `CsrfError` |
| httpOnly cookie mishandling | T17.x — persistent cookie jar in client constructor | Test: login → profile fetch → token refresh without manual token extraction |
| Missing tenant context | T17.x — required constructor parameter | Compile-time (Rust/TS) or runtime (Python/Java/Go/PHP) rejection if no tenant |
| TLS disabled | T17.x — no insecure transport option in SDK API | Linting rule blocks `InsecureSkipVerify` / `verify=False` from merging |
| gRPC channel leak | T17.1 (Rust, sets pattern); T17.3/4/5/7 (others) | Integration test: 100 auth checks do not leak file descriptors |
| AMQP HMAC skipped | T17.1/3/4/5/7 (AMQP-capable SDKs) | Integration test: tampered message rejected; no-sig message rejected |
| Clock skew / premature expiry | T17.x — clock-skew buffer in proactive refresh | Test: token with `exp = now+10s` not eagerly refreshed before 401 from server |
| Retry storms | T17.x — backoff in base HTTP client | Test: refresh endpoint returns 401; SDK waits with backoff before retry |

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Double-refresh race shipped to consumers | HIGH — requires SDK patch + consumer upgrade + user re-auth | Patch single-flight guard; release patch; document that all affected users must re-login |
| Token in published logs | HIGH — token exposure is immediate | Rotate all tokens (server-side session invalidation); patch SDK; audit logs for exfiltration |
| PKCE plain shipped | HIGH — retroactive code injection window; re-audit all authorization codes issued | Patch SDK to S256 only; notify consumers to rotate OAuth2 clients; audit server-side for plain-issued grants |
| TLS disabled in SDK release | HIGH — all traffic sniffable until patched | Emergency patch; re-issue any credentials that transited insecure connections |
| Missing tenant context | MEDIUM — data visible to wrong tenant (if server RBAC has gap) | Patch SDK constructor; audit server-side for cross-tenant access in logs |
| AMQP HMAC skipped | MEDIUM — fake authz messages possible if queue is accessible | Patch consumer; rotate AMQP shared secret; audit queue for injected messages |
| gRPC channel leak | LOW-MEDIUM — process OOM or FD exhaustion | Patch with shared channel; no credential rotation required |

---

## Sources

- MCP TypeScript SDK issue #1760 — refresh token race condition in concurrent auth — <https://github.com/modelcontextprotocol/typescript-sdk/issues/1760>
- OWASP OAuth2 Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html>
- OWASP Multi-Tenant Security Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html>
- RFC 6819 §5.2.2.3 — refresh token replay detection — <https://datatracker.ietf.org/doc/html/rfc6819>
- RFC 7636 — PKCE S256 mandatory — <https://datatracker.ietf.org/doc/html/rfc7636>
- Azure CLI CVE-2023-36052 (CVSS 8.6) — credential leak through environment variable logging — <https://orca.security/resources/blog/leakycli-aws-google-cloud-command-line-tools-can-expose-sensitive-credentials-build-logs/>
- Datadog Go static analysis — `grpc.WithInsecure()` flagged as security defect — <https://docs.datadoghq.com/code_analysis/static_analysis_rules/go-security/grpc-client-insecure/>
- Dana Epp — Cross-Tenant Data Leaks (CTDL) — <https://danaepp.com/cross-tenant-data-leaks-ctdl-why-api-hackers-should-be-on-the-lookout>
- Microsoft Vulnerable SDK components in IoT supply chain — <https://www.microsoft.com/en-us/security/blog/2022/11/22/vulnerable-sdk-components-lead-to-supply-chain-risks-in-iot-and-ot-environments/>
- AXIAM CLAUDE.md — security standards (EdDSA JWT 15 min, single-use rotating refresh, HMAC-AMQP, mTLS, CSRF)
- AXIAM .planning/REQUIREMENTS.md — REQ-1 (cookie auth), REQ-3 (rate limiting), REQ-15 (CSRF + PKCE + HMAC enforcement)

---
*Pitfalls research for: AXIAM client SDKs (v1.1, Phase 17)*
*Researched: 2026-06-28*
