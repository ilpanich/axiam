# Stack Research — AXIAM Client SDKs (v1.1)

**Domain:** Client SDK libraries wrapping REST + gRPC + AMQP for an IAM server
**Researched:** 2026-06-28
**Confidence:** HIGH (versions verified via crates.io, npm, PyPI, NuGet, pkg.go.dev, WebSearch)

---

## AXIAM Server API Contract (Read-Only — Do Not Change)

| Protocol | Transport | Auth | Notes |
|----------|-----------|------|-------|
| REST | HTTPS, Actix-Web, `/api/v1` | httpOnly Secure cookie (EdDSA JWT access token 15m + opaque refresh) | CSRF protection on all `/api/v1` CRUD |
| OAuth2/OIDC | HTTPS, `/oauth2/*`, `/.well-known/*` | Bearer token or PKCE flow | JWKS at `/.well-known/jwks.json` |
| gRPC | HTTP/2, Tonic 0.14 | — | 3 services: AuthorizationService, TokenService, UserService |
| AMQP | RabbitMQ 3.x | — | HMAC-SHA256 signed messages; async authz, audit, events |

**JWT signature algorithm:** EdDSA (Ed25519). SDKs acting as resource servers must verify with Ed25519 public key.

**Proto package:** `axiam.v1`; services: `AuthorizationService`, `TokenService`, `UserService`; files: `proto/axiam/v1/{authorization,token,user}.proto`

---

## Codegen Toolchain — Unified Proto Approach

**Recommendation: use `buf` CLI as the single codegen driver across all languages.**

```
buf generate --template sdks/<lang>/buf.gen.yaml
```

Each SDK ships a `buf.gen.yaml` pointing at the shared `proto/` tree. This avoids per-language `protoc` binary installation in CI and lets each SDK pin its own plugin versions.

| Language | buf plugin | Output |
|----------|-----------|--------|
| Rust | `buf.build/community/neoeinstein-prost` + `buf.build/community/neoeinstein-tonic` | `src/proto/` |
| TypeScript | `ts-proto` (local npm binary) | `src/generated/` |
| Python | `buf.build/grpc/python` + `buf.build/protocolbuffers/python` | `axiam_sdk/proto/` |
| Java | `buf.build/grpc/java` + `buf.build/protocolbuffers/java` | `src/main/java/` |
| C# | `Grpc.Tools` (MSBuild, no buf needed) | auto via .csproj |
| PHP | `buf.build/grpc/php` + `buf.build/protocolbuffers/php` | `src/Generated/` |
| Go | `buf.build/grpc/go` + `buf.build/protocolbuffers/go` | `proto/` |

C# is the exception: `Grpc.Tools` integrates with MSBuild — just add `<Protobuf>` items to `.csproj`.

---

## Language Stacks

### Rust SDK (`sdks/rust/`)

**Publish target:** crates.io

| Role | Crate | Version | Why |
|------|-------|---------|-----|
| HTTP client | `reqwest` | 0.12 | Matches server workspace; `rustls-tls` feature avoids OpenSSL dep |
| Async runtime | `tokio` | 1 | Standard; `reqwest` + `tonic` + `lapin` all require it |
| gRPC client | `tonic` + `tonic-prost` | 0.14 | Matches server — ensures wire compat; client-only features: no tonic-build dep in published lib |
| gRPC codegen (build) | `tonic-build` + `prost-build` | 0.14 | `build.rs` compiles proto → Rust stubs at build time |
| AMQP client | `lapin` | 4 | Matches server workspace; tokio executor feature |
| JWT verification | `jsonwebtoken` | 10 | Already in server workspace; EdDSA/Ed25519 via `ed` feature |
| Serialization | `serde` + `serde_json` | 1 | Deserialize REST responses |
| Error handling | `thiserror` | 2 | Idiomatic crate-level error types |
| Tracing | `tracing` | 0.1 | Optional; downstream consumers can instrument |

**Viability:** REST ✓ gRPC ✓ AMQP ✓ — fully viable, no caveats.

**Notes:**
- Pin `tonic` and `lapin` to the same semver range as the server to avoid duplicate dep trees for consumers who also run AXIAM server code.
- `tonic-prost` replaces `tonic` feature `prost` in 0.14; use `tonic-prost-build` for codegen.
- The published crate should have `tonic-build` only in `[build-dependencies]`, not `[dependencies]`.

---

### TypeScript SDK (`sdks/typescript/`)

**Publish target:** npm (`axiam-sdk`)

| Role | Package | Version | Why |
|------|---------|---------|-----|
| HTTP client | `axios` | 1.7 | Request/response interceptors for token refresh + cookie handling; mature, typed |
| gRPC client | `@grpc/grpc-js` | 1.14 | Pure JS, no native bindings; official Google-maintained gRPC for Node |
| gRPC proto loader | `@grpc/proto-loader` | 0.8 | Dynamic loading fallback; ts-proto is preferred for static types |
| gRPC codegen | `ts-proto` | 2.x | Generates idiomatic TS interfaces + `@grpc/grpc-js` client stubs; uses `@bufbuild/protobuf` |
| AMQP client | `amqplib` | 2.0 | Node.js only; official RabbitMQ-community maintained; includes TS types via `@types/amqplib` |
| JWT/JOSE | `jose` | 5.x | EdDSA/Ed25519 supported; JWKS URI fetch + verification; by panva (security-focused) |
| Types | `typescript` | 5.x | Dev dep |

**Viability:**
- REST ✓ — browser + Node
- gRPC ✓ Node.js only — `@grpc/grpc-js` does NOT work in browsers; browser use requires a grpc-web proxy (Envoy). AXIAM SDK targets Node.js server-side; document this constraint explicitly.
- AMQP ✓ Node.js only — `amqplib` is Node.js only. Not viable in browser. Document explicitly.

**Notes:**
- Export separate entry points: `axiam-sdk/rest`, `axiam-sdk/grpc`, `axiam-sdk/amqp` so browser bundlers tree-shake Node-only deps.
- `axios` beats `node-fetch`/`cross-fetch` here because interceptors are the cleanest pattern for cookie rotation (refresh on 401).
- `jose` 5.x preferred over `jsonwebtoken` because `jsonwebtoken` has minimal EdDSA support and is in maintenance mode.
- `ts-proto` 2.x migrated from `protobufjs` to `@bufbuild/protobuf` — use it, not the older 1.x.

---

### Python SDK (`sdks/python/`)

**Publish target:** PyPI (`axiam-sdk`)

| Role | Package | Version | Why |
|------|---------|---------|-----|
| HTTP client | `httpx` | 0.27+ | Async-first (asyncio); sync interface also available; cookie jar support |
| gRPC client | `grpcio` | 1.78+ | Official Google gRPC Python; `grpcio-status` for status codes |
| gRPC codegen | `grpcio-tools` | 1.78+ | Bundles `protoc` + Python gRPC plugin; `python -m grpc_tools.protoc` |
| AMQP client | `aio-pika` | 9.6 | asyncio-native; cleaner API than `pika` for async codebases |
| JWT verification | `PyJWT` | 2.x | EdDSA/Ed25519 support via `cryptography` package |
| EdDSA support | `cryptography` | 43+ | Required by PyJWT for EdDSA; also provides TLS utilities |
| Middleware helpers | `fastapi` / `django` | — | Dev/test deps only; SDK provides integration helpers, not hard dep |

**Viability:** REST ✓ gRPC ✓ AMQP ✓ — fully viable.

**Notes:**
- Offer both sync (`httpx.Client`) and async (`httpx.AsyncClient`) interfaces; FastAPI users expect `async`, Django users may use sync.
- `aio-pika` over bare `pika` because AXIAM's async patterns are asyncio-first.
- `grpcio-tools` is a build-time / dev dep; the published package only needs `grpcio` + pre-generated stubs.
- Use `betterproto` as an optional codegen alternative for cleaner Pythonic dataclasses, but default to official `grpcio-tools` to minimize risk.

---

### Java SDK (`sdks/java/`)

**Publish target:** Maven Central (`io.axiam:axiam-sdk`)

| Role | Library | Version | Why |
|------|---------|---------|-----|
| HTTP client | `OkHttp` | 4.12 | Modern, efficient, cookie jar built-in; fewer transitives than Apache HttpClient 5 |
| gRPC client | `io.grpc:grpc-netty-shaded` | 1.82.0 | Shaded Netty avoids version conflicts; grpc-stub + grpc-protobuf required too |
| gRPC codegen | `protobuf-maven-plugin` + `protoc-gen-grpc-java` | 1.82.0 | Hooks into Maven `compile` phase; no manual protoc needed |
| AMQP client | `com.rabbitmq:amqp-client` | 5.22 | Official RabbitMQ Java client; widely used |
| JWT verification | `com.nimbusds:nimbus-jose-jwt` | 10.x | Best EdDSA/Ed25519 support in Java; used by Spring Security OAuth2 internally |
| EdDSA support | `com.google.crypto.tink:tink` | 1.16 | Required by nimbus-jose-jwt for Ed25519 operations |
| Spring integration | `spring-boot-starter-security` + `spring-security-oauth2-resource-server` | 3.x | Optional; SDK provides a `BearerTokenAuthenticationFilter` helper |

**Viability:** REST ✓ gRPC ✓ AMQP ✓ — fully viable.

**Notes:**
- `grpc-netty-shaded` avoids the common Netty version conflict pain; prefer it over `grpc-netty`.
- For Gradle users: `id 'com.google.protobuf' version '0.9.4'` plugin (protobuf-gradle-plugin) replaces Maven plugin.
- `nimbus-jose-jwt 10.x` requires Tink for Ed25519; add `com.google.crypto.tink:tink` explicitly.
- Spring Security's `spring-security-oauth2-resource-server` handles JWKS auto-fetch from `/.well-known/jwks.json` — wire to AXIAM's OIDC URL for zero-boilerplate JWT verification.

---

### C# SDK (`sdks/csharp/`)

**Publish target:** NuGet (`Axiam.Sdk`)

| Role | Package | Version | Why |
|------|---------|---------|-----|
| HTTP client | `System.Net.Http.HttpClient` (stdlib) | .NET 8+ | No external dep; `IHttpClientFactory` for DI + resilience |
| gRPC client | `Grpc.Net.Client` | 2.80.0 | Official .NET gRPC client; HTTP/2 via .NET's Kestrel stack |
| gRPC codegen | `Grpc.Tools` + `Google.Protobuf` | 2.80.0 / 3.29 | MSBuild integration — add `<Protobuf Include="**/*.proto" GrpcServices="Client" />` to .csproj; no manual protoc |
| AMQP client | `RabbitMQ.Client` | 7.2.x | Official RabbitMQ .NET client; v7 is fully async (TAP); targets .NET 8 + Standard 2.0 |
| JWT verification | `Microsoft.IdentityModel.JsonWebTokens` | 8.x | Official MS JWT library; EdDSA/Ed25519 supported in .NET 8+ |
| ASP.NET integration | `Microsoft.AspNetCore.Authentication.JwtBearer` | 8.x | Auto-validates tokens via OIDC discovery; wire to AXIAM `/.well-known/openid-configuration` |

**Viability:** REST ✓ gRPC ✓ AMQP ✓ — fully viable.

**Notes:**
- `Grpc.Tools` is a build-time NuGet dependency; mark `PrivateAssets="All"` so consumers don't inherit it.
- EdDSA in .NET: `Microsoft.IdentityModel.JsonWebTokens` 8.x supports Ed25519 natively on .NET 8+. For .NET Standard 2.0 targets, use `BouncyCastle.Cryptography` (2.4.x) as EdDSA provider.
- `RabbitMQ.Client` 7.x is a breaking API change from 6.x — v7 is the correct target (fully async, no sync wrappers).
- Use `IHttpClientFactory` via DI so consumers get connection pooling and `HttpMessageHandler` lifecycle management.

---

### PHP SDK (`sdks/php/`)

**Publish target:** Packagist (`axiam/axiam-sdk`)

| Role | Package | Version | Why |
|------|---------|---------|-----|
| HTTP client | `guzzlehttp/guzzle` | 7.x | De facto standard; PSR-7/PSR-18 compatible; cookie jar |
| gRPC client | `grpc/grpc` (PECL ext) + Composer package | 1.72.x | C extension required; Composer package provides generated stub base classes |
| gRPC codegen | `protoc` + `grpc_php_plugin` | 1.72.x | Build-time only; `grpc_php_plugin` is compiled alongside the PECL extension |
| AMQP client | `php-amqplib/php-amqplib` | 3.7 | Pure PHP; no C extension needed; de facto RabbitMQ PHP client |
| JWT verification | `firebase/php-jwt` | 6.11 | EdDSA/Ed25519 supported (`EdDSA` algorithm); 400M+ downloads |
| Laravel integration | `illuminate/http` | — | Optional dev dep; SDK provides `AximMiddleware` as `Middleware` interface |
| Symfony integration | `symfony/http-kernel` | — | Optional dev dep; SDK provides `HttpKernel` event listener |

**Viability:**
- REST ✓ — fully viable, standard PHP
- gRPC ⚠ VIABLE WITH CAVEATS — requires the C PECL extension (`pecl install grpc`). Works in long-running PHP processes (Swoole, FrankenPHP, RoadRunner, CLI daemons). **NOT recommended for standard PHP-FPM** — gRPC channel initialization cost per request is prohibitive. Mark as "long-running PHP only" in SDK docs.
- AMQP ✓ — `php-amqplib` is pure PHP, no extension needed; works everywhere

**Notes:**
- Provide `GrpcClient` behind a conditional class that checks `extension_loaded('grpc')` and throws `\RuntimeException` with clear instructions if missing.
- AMQP in PHP is synchronous (blocking IO); mark as "not recommended for web request handlers". Use in CLI consumers / queue workers only.
- `firebase/php-jwt` 6.x requires PHP 8.0+. Minimum supported PHP version for the SDK: 8.1 (LTS, in security support).
- Guzzle 7.x: use `HandlerStack` for middleware (retry on 401, attach cookies).

---

### Go SDK (`sdks/go/`)

**Publish target:** Go modules (`github.com/axiam/axiam-go-sdk`)

| Role | Package | Version | Why |
|------|---------|---------|-----|
| HTTP client | `net/http` (stdlib) | Go 1.22+ | Idiomatic Go; no external dep; `http.CookieJar` for cookie handling |
| gRPC client | `google.golang.org/grpc` | 1.81 | Official Google gRPC-Go; HTTP/2 |
| gRPC codegen | `protoc-gen-go` + `protoc-gen-go-grpc` | latest | `go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest` |
| gRPC runtime | `google.golang.org/protobuf` | 1.35+ | Required runtime for generated stubs |
| AMQP client | `github.com/rabbitmq/amqp091-go` | 1.10 | Official RabbitMQ-maintained Go client; successor to `streadway/amqp` |
| JWT verification | `github.com/lestrrat-go/jwx/v3` | v3.x | EdDSA/Ed25519 (`jwa.EdDSAEd25519()`); JWKS URI fetching + auto key rotation |
| HTTP middleware | `net/http` handler wrapping | stdlib | No dep; `func Middleware(next http.Handler) http.Handler` pattern |

**Viability:** REST ✓ gRPC ✓ AMQP ✓ — fully viable.

**Notes:**
- `lestrrat-go/jwx/v3` is the current major; v2 is still maintained but v3 has RFC 9864 EdDSA support and `jwa.EdDSAEd25519()` accessor. Use v3.
- `amqp091-go` is maintained by RabbitMQ team directly; do NOT use the archived `streadway/amqp`.
- Go module path must match the GitHub repo: `module github.com/axiam/axiam-go-sdk` (or the actual org name). Semantic versioning required for Go modules.
- buf alternative for codegen: `buf.gen.yaml` with `buf.build/grpc/go` and `buf.build/protocolbuffers/go` remote plugins; avoids local tool installation in CI.

---

## Cross-Cutting Notes

### EdDSA JWT Verification — All Languages

AXIAM signs JWTs with Ed25519 (EdDSA). SDKs deployed as **resource servers** (microservices validating incoming AXIAM tokens) must verify signatures locally using the JWKS from `/.well-known/jwks.json`. All 7 recommended JWT libs support this. Steps:
1. Fetch JWKS from `/.well-known/jwks.json`
2. Select key by `kid` header
3. Verify signature with Ed25519 public key
4. Validate `exp`, `iss`, `tenant_id` claims

### Cookie Handling

AXIAM uses httpOnly Secure cookies (not Authorization headers) for REST. SDKs must:
- Store cookies received from login/refresh responses
- Attach cookies on every subsequent request
- Handle `Set-Cookie` on 401 responses (refresh flow)

| Language | Cookie storage |
|----------|---------------|
| Rust | `reqwest::cookie::Jar` |
| TypeScript | `axios` cookie interceptor + `tough-cookie` |
| Python | `httpx.Cookies` (built-in) |
| Java | `OkHttp.CookieJar` impl |
| C# | `HttpClientHandler.CookieContainer` |
| PHP | `Guzzle CookieJar` |
| Go | `net/http.CookieJar` (`cookiejar.New`) |

### AMQP Message Verification

AXIAM signs AMQP messages with HMAC-SHA256. SDKs consuming events must verify:
1. Extract `X-Axiam-Signature` header from AMQP delivery
2. Compute `HMAC-SHA256(secret, body)`
3. Compare (constant-time)

All 7 language standard libraries provide HMAC-SHA256 — no additional dep needed.

### Browser vs Node (TypeScript)

The TypeScript SDK targets **Node.js** for gRPC + AMQP. Browser bundles get REST-only. Export condition in `package.json`:
```json
"exports": {
  ".": "./dist/index.js",
  "./rest": "./dist/rest.js",
  "./grpc": { "node": "./dist/grpc.js", "default": null },
  "./amqp": { "node": "./dist/amqp.js", "default": null }
}
```

### PHP gRPC — Deployment Gate

The PHP gRPC C extension must be explicitly enabled by the consumer. SDK must detect at runtime and fail loudly:
```php
if (!extension_loaded('grpc')) {
    throw new \RuntimeException(
        'The grpc PHP extension is required for gRPC support. Install with: pecl install grpc'
    );
}
```

---

## Version Compatibility Matrix

| SDK | Min Runtime | Key constraint |
|-----|------------|----------------|
| Rust | Rust 1.82+ (MSRV tonic 0.14) | tonic 0.14 requires `async_fn_in_trait` stable (1.75+) |
| TypeScript | Node 18+ | `amqplib` 2.0.1 requires Node 18+; `@grpc/grpc-js` requires Node 16+ |
| Python | Python 3.10+ | `httpx` 0.27 drops Python 3.8; `aio-pika` 9.6 requires 3.9+ |
| Java | Java 11+ | grpc-java 1.82 supports Java 8+ but netty-shaded requires Java 11 for HTTP/2 |
| C# | .NET 8+ | EdDSA in `Microsoft.IdentityModel` works without BouncyCastle only on .NET 8+ |
| PHP | PHP 8.1+ | `firebase/php-jwt` 6.x drops PHP 7.x |
| Go | Go 1.22+ | grpc-go 1.81 minimum Go 1.22 |

---

## Sources

- crates.io: reqwest 0.12, tonic 0.14, lapin 4, jsonwebtoken 10 — verified from workspace Cargo.toml
- crates.io: tonic 0.14.6 — WebSearch via generalistprogrammer.com
- npm: `@grpc/grpc-js` 1.14.x — npmjs.com WebSearch (published 1 month ago as of 2026-06)
- npm: `amqplib` 2.0.1 — WebSearch (last published June 2026)
- npm: `ts-proto` 2.x — WebSearch, GitHub stephenh/ts-proto
- PyPI: `grpcio` 1.78.0 — WebSearch (released Feb 2026)
- PyPI: `aio-pika` 9.6.x — WebSearch pypi.org
- NuGet: `Grpc.Net.Client` 2.80.0 — NuGet Gallery WebSearch
- NuGet: `RabbitMQ.Client` 7.2.1 — NuGet Gallery WebSearch
- Maven: `grpc-java` 1.82.0 — WebSearch, grpc/grpc-java GitHub
- Maven: `nimbus-jose-jwt` 10.x — mvnrepository.com WebSearch
- Packagist: `firebase/php-jwt` 6.11.1 — WebSearch packagist.org
- Packagist: `php-amqplib` 3.7 — WebSearch php-amqplib/php-amqplib GitHub
- Go: `google.golang.org/grpc` 1.81 — pkg.go.dev WebSearch
- Go: `amqp091-go` 1.10.0 — rabbitmq/amqp091-go GitHub WebSearch
- Go: `lestrrat-go/jwx/v3` — WebSearch lestrrat.medium.com + GitHub

---

*Stack research for: AXIAM v1.1 Client SDKs*
*Researched: 2026-06-28*
