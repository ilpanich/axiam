# Project Research Summary

**Project:** AXIAM v1.1 — Client SDKs (Phase 17)
**Domain:** Multi-language IAM client SDK layer over a frozen v1.0 REST/gRPC/AMQP server
**Researched:** 2026-06-28
**Confidence:** HIGH

---

## Executive Summary

AXIAM v1.1 ships 7 language-native client SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go)
wrapping a frozen v1.0 IAM server. The fundamental insight from research is that these SDKs
are NOT thin HTTP wrapper codegen outputs — they are stateful auth clients that must manage
token lifecycles, enforce tenant context, implement concurrency-safe refresh guards, and
integrate with each language's idiomatic framework middleware. The reference implementation
pattern (TokenManager + AuthClient + TenantContext + AuthzClient) is consistent across all 7
languages; only the idioms change.

The recommended build approach starts with shared foundation artifacts (exported
`sdks/openapi.json`, a root `buf.gen.yaml` over `proto/axiam/v1/`, and a written cross-SDK
behavioral contract) before any per-language work begins. The Rust SDK is the reference
implementation and validates the full pattern. TypeScript, Go, Python, Java, C#, and PHP
follow in that order, each reusing the shared contract document and codegen pipeline. This
ordering is driven by ecosystem maturity, protocol viability, and publisher value (Rust
validates correctness; TypeScript captures the broadest audience; Go/Python serve
microservices; Java/C#/PHP serve enterprise).

The primary risk in SDK development is security regression — not implementation complexity.
Single-use rotating refresh tokens (AXIAM's design) cause cascading user logouts if an SDK
fires parallel refresh requests. TLS disabled "for convenience" in CI becomes a production
habit. Tokens leaking into logs are an IAM-specific CVE class (AWS LeakyCLI, CVE-2023-36052).
All 7 of the identified critical pitfalls must be addressed at construction-time in each SDK,
not retrofitted. Security is day-1 scope.

---

## Key Findings

### Recommended Stack

All 7 SDK language stacks are confirmed viable. Each uses the idiomatic HTTP client, gRPC
client, and AMQP library for its ecosystem — no exotic dependencies. Protocol viability is
language-specific and must be documented clearly per SDK. See STACK.md for full dependency
tables, version pins, and rationale.

**Core technologies (cross-cutting):**
- `buf` CLI — single codegen driver for all gRPC stubs across all 7 languages; eliminates
  per-language `protoc` installs in CI. Exception: C# uses `Grpc.Tools` MSBuild integration.
- `openapi-generator-cli` — generates typed model/schema classes only; NOT full client logic
  (auth orchestration, token management, and tenant injection are hand-written per SDK).
- EdDSA (Ed25519) JWT — all 7 recommended JWT libs support it; resource-server SDKs must
  verify via JWKS at `/.well-known/jwks.json` with `kid` matching.
- HMAC-SHA256 — all 7 standard libraries support it natively; required for AMQP message
  signature verification (no additional dependency needed).

**Protocol viability matrix (carry verbatim into requirements):**

| SDK | REST | gRPC | AMQP |
|-----|------|------|------|
| Rust | ✓ | ✓ | ✓ |
| TypeScript | ✓ (browser+Node) | ✓ Node.js only | ✓ Node.js only |
| Python | ✓ | ✓ | ✓ |
| Java | ✓ | ✓ | ✓ |
| C# | ✓ | ✓ | ✓ |
| PHP | ✓ | ⚠ long-running runtimes only (Swoole/RoadRunner/CLI) | ✓ |
| Go | ✓ | ✓ | ✓ |

TypeScript browser persona: REST only (gRPC and AMQP are Node.js server-side only, exported
via separate entry points that browser bundlers tree-shake).

**Key version constraints:**
- Rust: `reqwest 0.12`, `tonic 0.14` (matches server workspace), `lapin 4`, `jsonwebtoken 10`
- TypeScript: Node 18+; `axios 1.7`, `@grpc/grpc-js 1.14`, `jose 5.x`, `ts-proto 2.x`
- Python: Python 3.10+; `httpx 0.27`, `grpcio 1.78`, `aio-pika 9.6`, `PyJWT 2.x`
- Java: Java 11+; `grpc-netty-shaded 1.82`, `nimbus-jose-jwt 10.x` + `tink 1.16` for EdDSA
- C#: .NET 8+; `Grpc.Net.Client 2.80`, `RabbitMQ.Client 7.2`, `Microsoft.IdentityModel.JsonWebTokens 8.x`
- PHP: PHP 8.1+; `guzzlehttp/guzzle 7.x`, `firebase/php-jwt 6.11`, `php-amqplib 3.7`
- Go: Go 1.22+; `google.golang.org/grpc 1.81`, `amqp091-go 1.10`, `lestrrat-go/jwx/v3`

### Expected Features

**Must have (v1.1 — P1, each SDK):**
- Password login → typed `LoginResult` with `mfa_required` field
- MFA step-up — two-phase: `login()` then `verify_mfa(code)` when `mfa_required == true`
- OAuth2 Client Credentials — service-to-service M2M; Bearer token (not cookie)
- Token refresh — concurrency-safe, single-flight guard (single-use rotating refresh token)
- Logout — clears cookies (server), CSRF token, local state
- Single authorization check — gRPC for server SDKs (Rust/Go/Java/C#/Python); browser TS has NO client-side check (see Open Question 1 — server enforces 403)
- Tenant context binding — required constructor parameter, injected on every request
- Framework middleware / route guard — per-language framework integration
- Typed error model — `AuthError`, `AuthzError`, `NetworkError` per language conventions
- CSRF token forwarding — TypeScript browser SDK (all SDKs need it for REST CRUD mutations)

**Should have (v1.1.x — P2):**
- OAuth2 Authorization Code + PKCE (S256 hardcoded, no `plain`)
- Batch authorization check (`BatchCheckAccess` gRPC)
- Authorization decision cache (TTL-based, invalidated on logout)
- Proactive token refresh at `exp - 60s` for server-side SDKs (Persona B)
- OIDC discovery auto-configuration from `/.well-known/openid-configuration`
- WebAuthn helpers (TypeScript browser SDK)

**Defer (v1.2+ — P3):**
- AMQP event consumer / async authz
- Device Authorization Flow
- Federation login helpers
- Certificate / mTLS auth client

**Two SDK personas govern feature behavior:**
- **Persona A (Browser/SPA):** httpOnly cookies, CSRF forwarding, REST-only, cannot read JWT `exp` claim. TypeScript browser entry point.
- **Persona B (Server/Service):** Bearer token, gRPC preferred, AMQP-capable, can read `exp` for proactive refresh. All server-side SDKs.

### Architecture Approach

All 7 SDKs share a five-layer conceptual architecture: AuthClient (login/MFA/OAuth2),
TokenManager (in-memory token + proactive refresh + 401 retry queue), TenantContext (org/tenant
scope injected on every request), AuthzClient (gRPC `CheckAccess`/`BatchCheckAccess`), and
TypedModels (generated from OpenAPI spec + proto IDL). OpenAPI-generator generates model/schema
stubs only; auth orchestration is hand-written. Monorepo under `sdks/` enables atomic cross-SDK
updates when server API changes; per-SDK GitHub Actions `paths:` filters keep CI cost O(1) per
change.

**Major components:**
1. **`sdks/openapi.json`** — exported from server's `--dump-openapi` flag; source of truth for REST model codegen; re-exported on every release tag.
2. **`sdks/buf.gen.yaml` + `sdks/buf.yaml`** — multi-language proto codegen config pointing at `proto/axiam/v1/`; generates stubs for all gRPC-capable SDKs in one pass.
3. **SDK contract document** — written spec for naming/behavior parity across all 7 languages.
4. **Per-SDK package** (`sdks/{rust,typescript,python,java,csharp,php,go}/`) — idiomatic implementation of the shared five-layer architecture.
5. **CI: `export-openapi` workflow** — builds server binary with `--dump-openapi`, diffs against committed `sdks/openapi.json`; fails on drift.
6. **CI: per-SDK build/test workflow** — one file per language, triggered by `paths:` filter.

**One server-side change required:** Add `--dump-openapi` flag to `crates/axiam-server/src/main.rs` that prints `api_doc().to_pretty_json()` and exits without starting SurrealDB or AMQP.

### Critical Pitfalls

1. **Double-refresh race destroys the token family** — AXIAM uses single-use rotating refresh tokens (RFC 6819 §5.2.2.3). Two concurrent 401s both attempting refresh invalidate the entire family and log the user out. Prevention: implement a single-flight refresh guard as the FIRST thing in every SDK's `TokenManager`. Test: 5 concurrent requests on expired token → assert exactly 1 refresh call.

2. **Token leakage into logs / error objects** — IAM-specific CVE class (AWS LeakyCLI, CVE-2023-36052). All token fields must use a `Sensitive<T>` wrapper suppressing `Debug`/`Display`/`toString`/`__repr__`. CI gate: `grep -r 'eyJ' logs/` must return empty.

3. **TLS disabled "for convenience"** — Default to strict TLS verification with no `skip_tls_verification()` option. Provide `with_custom_ca(pem_path)` for dev self-signed certs. Block `InsecureSkipVerify` / `verify=False` via CI lint rule from day 1.

4. **Missing tenant context** — SDK constructor MUST require `tenant_slug` / `tenant_id` as non-optional. Enforce at compile time (Rust, TypeScript); throw at runtime otherwise.

5. **AMQP HMAC signature verification skipped** — SDK AMQP consumers must verify `HMAC-SHA256(secret, body)` against the message `hmac_signature` field before processing. Mandatory, not optional. Treat failure as a security event (nack without requeue).

6. **gRPC channel leak and missing keepalive** — One shared `Channel` per `AxiamClient` instance. Configure `keepalive_time=30s`, deadline on every unary RPC, explicit `close()` method.

7. **httpOnly cookie mishandling in non-browser clients** — Persistent cookie jar mandatory in HTTP client constructor. Never expose `get_access_token() -> String`.

---

## Resolved Open Questions (verified against codebase 2026-06-28)

### Q1 — REST authorization-check endpoint: CONFIRMED ABSENT
Authorization is enforced server-side via `AuthzMiddleware` + `RequirePermission` per-route
guards (`crates/axiam-api-rest/src/server.rs`, `authz.rs`). There is **no standalone REST
"can user X do action Y?" query endpoint**. The only authz **query** surface is gRPC
`AuthorizationService.CheckAccess` / `BatchCheckAccess` (`proto/axiam/v1/authorization.proto`).

**Implication:** Server SDKs (Rust/Go/Python/Java/C#) perform authz checks via gRPC. The
**browser TypeScript SDK (REST-only) has no client-side authz-check path** — it must rely on
the server returning 403 on the actual request. This is a milestone scope decision:
(a) document the limitation (browser SDK has no `can()`), or (b) add a small REST authz-check
endpoint to the server (touches the otherwise-frozen v1.0 surface).

### Q2 — AMQP auth-event message schema: RESOLVED (source of truth `crates/axiam-amqp/src/messages.rs`)
SDK AMQP producers/consumers mirror these structs (JSON-serialized, `hmac_signature` is
HMAC-SHA256 over the body with that field nulled):
- `AuthzRequest { correlation_id, tenant_id, subject_id, action, resource_id, scope?, hmac_signature? }`
- `AuthzResponse { correlation_id, allowed, reason? }`
- `AuditEventMessage { tenant_id, actor_id, actor_type, action, resource_id?, outcome, ip_address?, metadata?, hmac_signature? }`
- `NotificationEvent { event_type, tenant_id, actor_id, resource_id?, timestamp, data? }`

Not a blocker — the schema exists and is stable.

---

## Implications for Roadmap

Suggested structure: 8 phases (foundation + 7 per-language SDKs). Per the milestone's
continued GSD numbering, these map to **GSD Phases 15–22**.

### GSD Phase 15 — SDK Foundation (prerequisite to all per-language work)

**Rationale:** All 7 SDKs depend on three shared artifacts that do not exist yet. Unlocks all
subsequent phases.

**Delivers:**
- `--dump-openapi` flag on server binary; `sdks/openapi.json` committed (first export)
- `sdks/buf.yaml` + `sdks/buf.gen.yaml` (multi-language proto codegen)
- CI workflow: `sdk-export-openapi.yml` (re-export on release, diff gate)
- CI addition: `buf lint` + `buf breaking` gate on `proto/**` changes
- Written SDK contract document: method signatures, error taxonomy, CSRF behavior, cookie jar requirement, tenant context contract, middleware interface per language

### GSD Phase 16 — Rust SDK (reference implementation)
`sdks/rust/` — reqwest 0.12 REST + tonic 0.14 gRPC + lapin 4 AMQP; Actix-Web middleware;
crates.io-ready. Establishes gRPC channel management + `Sensitive<T>` pattern for all others.
Security day-1: single-flight refresh guard, `reqwest::cookie::Jar`, TLS-strict, mandatory
`tenant_slug`, HMAC-SHA256 AMQP verification.

### GSD Phase 17 — TypeScript SDK
`sdks/typescript/` — axios 1.7 REST + @grpc/grpc-js (Node only) + amqplib (Node only); CSRF
interceptor; Express + Fastify middleware; ts-proto 2.x stubs; separate `rest`/`grpc`/`amqp`
entry points. Browser persona: no authz `can()` (Q1). Security day-1: promise-dedup refresh
guard, CSRF interceptor, S256 PKCE, TLS-strict, mandatory `tenant_slug`.

### GSD Phase 18 — Go SDK
`sdks/go/` — net/http REST + grpc-go 1.81 + amqp091-go 1.10; net/http middleware;
lestrrat-go/jwx/v3 for EdDSA + JWKS. Second server-side reference.

### GSD Phase 19 — Python SDK
`sdks/python/` — httpx 0.27 (sync+async) + grpcio 1.78 + aio-pika 9.6; FastAPI dependency +
Django middleware; Pydantic v2 models.

### GSD Phase 20 — Java SDK
`sdks/java/` — OkHttp 4.12 + grpc-netty-shaded 1.82 + amqp-client 5.22; Spring Security
filter; Maven Central (`io.axiam:axiam-sdk`).

### GSD Phase 21 — C# SDK
`sdks/csharp/` — HttpClient + Grpc.Net.Client 2.80 + RabbitMQ.Client 7.2; ASP.NET Core
middleware; NuGet (`Axiam.Sdk`). `Grpc.Tools` MSBuild avoids buf step.

### GSD Phase 22 — PHP SDK
`sdks/php/` — Guzzle 7.x REST + optional grpc PECL + php-amqplib 3.7; Laravel + Symfony
middleware; Packagist (`axiam/axiam-sdk`); runtime `extension_loaded('grpc')` guard. REST-only
starter; validates codegen end-to-end.

### Phase Ordering Rationale
- Foundation (15) is a hard prerequisite — no per-language SDK can begin without `sdks/openapi.json` and the buf codegen pipeline.
- Rust (16) before TypeScript (17): Rust validates the complete auth/gRPC/AMQP pattern in the most type-safe language.
- Go (18) before Python/Java/C#: Go idioms are close to Rust's in clarity; reduces design drift in verbose enterprise languages.
- PHP (22) last: REST-only, lowest risk, validates codegen end-to-end.
- Phases 17–22 can run in parallel after 15+16 establish the contract, if multiple contributors are available.

### Research Flags
**Standard patterns (skip phase-research):** all 8 phases use well-documented libraries and
established patterns; the two prior open questions are now resolved.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All versions verified via official package registries |
| Features | HIGH | Grounded in AXIAM server source (server.rs route registrations + proto files) + Auth0/Keycloak pattern research |
| Architecture | HIGH | Based on direct codebase inspection (utoipa ApiDoc, proto files, CI workflows) |
| Pitfalls | HIGH | Auth model grounded in AXIAM server source; OAuth2 pitfalls grounded in RFCs + documented CVEs |

**Overall confidence:** HIGH

### Remaining Decision for Requirements
- **Browser SDK authz (from Q1):** document the no-`can()` limitation, OR add a REST
  authz-check endpoint to the server. User decision required at requirements scoping.

---

## Sources

### Primary (HIGH confidence)
- AXIAM codebase: `crates/axiam-api-rest/src/{openapi.rs,server.rs,authz.rs}`
- AXIAM codebase: `proto/axiam/v1/{authorization,token,user}.proto`
- AXIAM codebase: `crates/axiam-amqp/src/messages.rs` (AMQP schema)
- AXIAM codebase: `.github/workflows/ci.yml`, `release.yml`
- crates.io: reqwest 0.12, tonic 0.14, lapin 4, jsonwebtoken 10 — workspace Cargo.toml verified
- RFC 6749 / RFC 7636 / RFC 6819
- OWASP OAuth2 Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
- OWASP Multi-Tenant Security Cheat Sheet

### Secondary (MEDIUM confidence)
- Auth0 Docs — refresh token rotation, SPA token storage patterns
- Keycloak Node.js adapter — middleware pattern reference
- buf.build — multi-language proto codegen config
- openapi-generator.tech — model stub generation (7.x)

### Tertiary (LOW confidence — needs validation)
- MCP TypeScript SDK issue #1760 — refresh token race condition (confirms pitfall is real)
- Datadog Go static analysis — `grpc.WithInsecure()` as security defect

---
*Research completed: 2026-06-28. Both open questions resolved against the codebase. Ready for roadmap.*
