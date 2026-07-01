---
phase: 17
slug: typescript-sdk
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-01
---

# Phase 17 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| SDK code → log / console / serializer | Token values could leak into diagnostic output; `Sensitive<T>` is the redaction boundary. | Access/refresh tokens, HMAC keys (secret) |
| consumer bundler → `/rest` entry | Node-only transports must not cross into a browser bundle (SC#1); enforced by a dependency-free core. | Module graph (build-time) |
| browser JS → AXIAM server (REST) | Untrusted state-changing requests cross here; CSRF double-submit is the mitigation. | Request bodies, CSRF token (semi-trusted) |
| SDK → server auth endpoints | 401 responses can trigger refresh storms; single-flight guard bounds them. | Refresh cookies (secret) |
| Node SDK → gRPC AuthorizationService | Bearer token + tenant metadata cross here; must be current and correctly scoped. | Bearer token, tenant id (secret) |
| server JWKS → local verification | JWT signature/exp verified locally; algorithm confusion is the risk. | Public keys, JWT claims |
| token cache → logs / metadata | Token values must stay `Sensitive`; only `expose()` at the metadata-injection point. | Access tokens (secret) |
| RabbitMQ message → consumer handler | Messages may be forged/tampered/replayed; HMAC verify-before-handler is the boundary. | AMQP payloads, HMAC signature (untrusted until verified) |
| signing key → logs | The per-tenant AMQP secret must never appear in logs; `Sensitive<Buffer>` + §8.4 event rules. | HMAC signing key (secret) |
| incoming HTTP request → protected route | Untrusted session token crosses here; middleware verifies before the handler runs. | Session JWT (untrusted until verified) |
| JWKS cache → middleware decision | Stale/forged keys would allow forged sessions; explicit EdDSA + exp check mitigates. | Public keys, verified claims |
| CI publish job → npm registry | A side-effecting release; `NPM_TOKEN` must never be exposed to PR-triggered runs. | `NPM_TOKEN` (secret) |
| consumer bundler → published `/rest` tarball | Node-only transports must be absent from a browser bundle; bundle-grep gate proves it pre-publish. | Module graph (build-time) |
| published tarball → npm consumers | Consumers must not need buf; compiled stubs must be bundled. | Compiled artifacts |
| independent `AxiamClient` instances in one Node process | Each holds its own session/tenant; a shared process-global refresh state crosses this boundary. | Per-session refresh state (secret) |
| resource-server middleware ← client-presented access token | Untrusted JWT crosses here; org-wide JWKS signature validity does NOT imply tenant authorization. | Access JWT, tenant id (untrusted until scoped) |
| Node cookie jar → outgoing REST request | `axiam_csrf` must cross into the `X-CSRF-Token` header; absence silently disables CSRF protection server-side. | CSRF token (semi-trusted) |
| thrown `AxiamError` → consumer logging (console.log / JSON.stringify / util.inspect) | Raw `Set-Cookie` token material must NOT cross this boundary. | Set-Cookie tokens (secret) |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-17-01 | Information Disclosure | `Sensitive<T>` (core/sensitive.ts) | high | mitigate | Redacts `[SENSITIVE]` across toString/toJSON/util.inspect.custom; raw only via `expose()`. Verified: `src/core/sensitive.ts`, `test/core/sensitive.test.ts` (all 3 surfaces). | closed |
| T-17-02 | Information Disclosure | error classes (core/errors.ts) | high | mitigate | Error classes never embed raw token strings; `AuthzError` carries only action/resourceId. Verified: `src/core/errors.ts`. | closed |
| T-17-03 | Tampering | error taxonomy drift REST vs gRPC | medium | mitigate | Single central `errorMapper` (core/errorMapper.ts) is the sole source both transports import. Verified: `src/core/index.ts` re-export, `test/core/errorMapper.test.ts`. | closed |
| T-17-04 | Tampering | tree-shaking leak of Node transports | high | mitigate | Dependency-free core (no grpc-js/amqplib import) + `splitting:false` + `sideEffects:false`. Verified: `src/core/*` clean, `tsup.config.ts:29`, `package.json:7`. E2E proof at T-17-23. | closed |
| T-17-05 | Spoofing / Tampering | CSRF on state-changing REST calls | high | mitigate | Interceptor forwards `axiam_csrf` as `X-CSRF-Token` on POST/PUT/PATCH/DELETE only. Verified: `src/rest/interceptors.ts:33-38`, `test/rest/csrf.test.ts` (present on POST, absent on GET). | closed |
| T-17-06 | Denial of Service (self-inflicted) | thundering-herd refresh | high | mitigate | Reactive single-flight guard. Verified: `src/core/singleFlightRefresh.ts`, `test/rest/singleFlightRefresh.test.ts` (exactly 1 refresh for 5 concurrent 401s). | closed |
| T-17-07 | Information Disclosure | token in login/refresh result | high | mitigate | Public API exposes no `access_token` field (tokens via Set-Cookie only). Verified: no exposed `access_token` field in `src/`; eyJ leak gate (T-17-24). | closed |
| T-17-08 | Tampering | TLS bypass via `customCa` misuse | high | mitigate | `customCa` only ADDS a PEM CA, never disables verification; no insecure surface. Verified: `src/core/config.ts`, TLS-lint gate (T-17-25). | closed |
| T-17-09 | Tampering | AMQP message forgery/tampering | high | mitigate | HMAC-SHA256 verify-before-handler with constant-time compare (`timingSafeEqual`); mismatch → nack-no-requeue + security event. Verified: `src/amqp/hmac.ts:38-50`, `src/amqp/consumer.ts`, `test/amqp/hmac.test.ts`. | closed |
| T-17-10 | Spoofing | missing-signature message | high | mitigate | Strict mode (default) nacks unsigned messages without requeue; lenient mode opt-in only. Verified: `src/amqp/consumer.ts`, `test/amqp/consumer.test.ts`. | closed |
| T-17-11 | Information Disclosure | signing key / signature in logs | high | mitigate | Key is `Sensitive<Buffer>`; security event logs only timestamp/exchange/routingKey/tenant. Verified: `src/amqp/consumer.ts` (Sensitive import), test asserts absence. | closed |
| T-17-12 | Tampering | nack argument transposition | medium | mitigate | Explicit `nack(msg, allUpTo=false, requeue=false)` positional booleans + test asserting `requeue===false` on every failure path. Verified: `src/amqp/consumer.ts:34`. | closed |
| T-17-13 | Tampering | pre-verify schema reordering | medium | mitigate | Canonical JSON via plain parse; no schema validator before HMAC verify. Verified: `src/amqp/hmac.ts`, key-order test. | closed |
| T-17-14 | Spoofing | JWT algorithm confusion (alg:none / HS-with-pubkey) | high | mitigate | `jose` jwtVerify with explicit `algorithms:['EdDSA']`; token's own alg never trusted. Verified: `src/node/jwks.ts:75`, `test/node/jwks.test.ts`. | closed |
| T-17-15 | Information Disclosure | token in gRPC metadata logs / cache | high | mitigate | Tokens wrapped in `Sensitive<T>`; `expose()` only at `metadata.add`. Verified: `src/grpc/interceptor.ts:32`. | closed |
| T-17-16 | Denial of Service | UNAUTHENTICATED refresh storm across gRPC | high | mitigate | `callWithRefresh` shares the per-session single-flight guard; retry exactly once. Verified: `src/grpc/callWithRefresh.ts:37`. | closed |
| T-17-17 | Tampering | TLS bypass in gRPC channel | high | mitigate | Default TLS ChannelCredentials; `customCa` builds SSL creds from PEM only; `createInsecure()` scheme-gated to explicit plaintext http/grpc (no TLS to bypass). Verified: `src/grpc/client.ts:123-136`, TLS-lint gate (T-17-25). | closed |
| T-17-18 | Spoofing | stale token injected because `start()` cannot await | medium | mitigate | Interceptor reads only the sync cached token; refresh handled at `callWithRefresh`; `syncFromJar` keeps cache current. Verified: `src/grpc/interceptor.ts:29-30`. | closed |
| T-17-19 | Spoofing | forged/expired session at middleware | high | mitigate | Local `jose` verify (EdDSA + exp) before handler; 401 on failure; roles from verified scope claim only. Verified: `src/middleware/verifyCore.ts`, `src/middleware/express.ts:57`. | closed |
| T-17-20 | Elevation of Privilege | missing 403 on authz failure | medium | mitigate | `AuthError`→401, `AuthzError`→403 standardized bodies. Verified: `src/middleware/express.ts:53-58`. | closed |
| T-17-21 | Information Disclosure | token echoed in middleware error body | medium | mitigate | Standardized JSON error bodies contain no token value; identity injection carries only userId/tenantId/roles. Verified: `src/middleware/express.ts` (standardized body helpers). | closed |
| T-17-22 | Tampering | stale JWKS cached beyond token TTL | low | accept | `jose`'s exp enforcement bounds acceptance to the token's own lifetime; no extra caching layer added. Below `high` block threshold; see Accepted Risks Log. | closed |
| T-17-23 | Tampering | Node transports leaking into browser bundle | high | mitigate | SC#1 bundle-and-grep gate (esbuild `platform:'browser'`; fail on `@grpc/grpc-js\|amqplib`). Verified: `scripts/bundle-grep.mjs`, `.github/workflows/sdk-ci-typescript.yml:69`. | closed |
| T-17-24 | Information Disclosure | JWT-shaped string in built artifacts | high | mitigate | Token-leak gate greps `eyJ` in `dist/`. Verified: `.github/workflows/sdk-ci-typescript.yml:92`. | closed |
| T-17-25 | Tampering | TLS-bypass pattern creeping into SDK source | high | mitigate | TLS-lint gate greps `rejectUnauthorized:false` / `NODE_TLS_REJECT_UNAUTHORIZED` / `insecureSkipVerify` in `src/`. Verified: `.github/workflows/sdk-ci-typescript.yml:105`. | closed |
| T-17-26 | Elevation of Privilege | `NPM_TOKEN` exposed to PR runs | high | mitigate | Publish job gated on tag ref only (`push` + `refs/tags/sdks/typescript/v`), never `pull_request`; `id-token:write` + `--provenance`. Verified: `.github/workflows/sdk-ci-typescript.yml:122-164`. | closed |
| T-17-27 | Denial of Service | CJS consumers crash with ERR_REQUIRE_ESM (jose-loading entries) | medium | mitigate | Post-build CJS-require smoke gate on grpc + middleware entries proves the dynamic `import('jose')` guard works. Verified: `.github/workflows/sdk-ci-typescript.yml:78,82`. | closed |
| T-17-SC (17-06) | Tampering | npm / buf package installs | high | mitigate | RESEARCH Package Legitimacy Audit approved all deps; no `[SLOP]` package retained; buf/GitHub Actions SHA-pinned (SEC-057). Verified: SHA-pinned actions in release/CI workflows. | closed |
| T-17-CR02 | Tampering / Information Disclosure | module-level `refreshPromise` shared across sessions | high | mitigate | Per-session `createRefreshGuard()` with private `refreshPromise`; session A cannot satisfy session B. Verified: `src/core/singleFlightRefresh.ts:29-34`, `test/rest/multiSessionRefresh.test.ts`. | closed |
| T-17-CR03 | Spoofing / Elevation of Privilege | presence-only tenant_id check with org-wide JWKS | high | mitigate | Enforces `claims.tenant_id === session.tenantHeaderValue`; Tenant-A token rejected against Tenant-B server. Verified: `src/middleware/verifyCore.ts:62`, `test/middleware/tenantIsolation.test.ts` (401 on mismatch). | closed |
| T-17-SC (17-07) | Tampering | npm installs during gap closure | high | mitigate | No new dependencies added (existing jose/tough-cookie/msw only); no package-legitimacy checkpoint required. | closed |
| T-17-CR01 | Spoofing / Tampering (CSRF) | `csrfToken` never written in Node path | high | mitigate | `NodeSession.onAuthenticated` + `doRefresh` sync `session.csrfToken` from the jar's `axiam_csrf` cookie. Verified: `src/node/session.ts:56,66-72`, `test/node/csrf.test.ts`. | closed |
| T-17-CR04 | Information Disclosure | `NetworkError.cause` carries raw axios error with Set-Cookie headers | high | mitigate | `sanitizeAxiosError` strips set-cookie before it becomes `NetworkError.cause` at every call site. Verified: `src/rest/auth.ts:89,116,138,158`, `test/core/errorRedaction.test.ts`. | closed |
| T-17-SC (17-08) | Tampering | npm installs during gap closure | high | mitigate | No new runtime dependencies added; `node:util` (test-only) and existing tough-cookie/msw suffice. | closed |

*Status: open · closed · open — below `high` threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| R-17-01 | T-17-22 | Stale JWKS cached beyond token TTL is bounded by `jose`'s `exp` enforcement — acceptance is capped at the token's own lifetime. Severity `low`, below the `high` block threshold; no extra caching-invalidation layer added. | Phase 17 plan (17-05), verified by security audit | 2026-07-01 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-01 | 34 | 34 | 0 | gsd-secure-phase (L1 grep-depth, register authored at plan time) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-01
