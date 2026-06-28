# Architecture Research: AXIAM Client SDKs (v1.1)

**Domain:** Multi-language IAM client SDK layer over frozen v1.0 REST/gRPC/AMQP server
**Researched:** 2026-06-28
**Confidence:** HIGH — based on codebase inspection + current tooling verification

---

## 1. Shared Conceptual Core

Every SDK — regardless of language — exposes the same five logical layers realized
idiomatically per language.

```
┌────────────────────────────────────────────────────────────────────┐
│                      SDK Consumer (user code)                       │
├────────────────────────────────────────────────────────────────────┤
│  AuthClient    TenantContext    AuthzClient    AdminClient           │
│  (login/MFA/   (org+tenant      (gRPC check   (REST CRUD            │
│   OAuth2/OIDC)  scope header)   /batch)        endpoints)           │
├────────────────────────────────────────────────────────────────────┤
│                       TokenManager                                   │
│  (in-memory access token, proactive refresh, 401-retry, queue)      │
├────────────────────────────────────────────────────────────────────┤
│         Transport layer (REST HTTP)  |  gRPC channel  |  AMQP conn  │
│         (HttpClient / reqwest /       (tonic / grpc-   (lapin /     │
│          requests / fetch / Guzzle)   java / grpc-go)  amqplib)     │
├────────────────────────────────────────────────────────────────────┤
│   TypedModels (generated or hand-maintained — Organization, Tenant, │
│   User, Role, Permission, Token, CheckAccessRequest …)              │
└────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Notes |
|-----------|---------------|-------|
| **AuthClient** | Login, MFA confirm, OAuth2 Code+PKCE, Client Credentials, refresh, logout, WebAuthn | Produces `TokenSet`; delegates storage to TokenManager |
| **TokenManager** | In-memory access token; proactive background refresh (at 80% lifetime); 401-triggered reactive refresh with request queue to avoid thundering herd | httpOnly cookie refresh flow: backend sets the cookie, SDK just calls `/auth/refresh` with `credentials: include` |
| **TenantContext** | Holds `org_slug` + `tenant_slug`; injects `X-Tenant-ID` header (or path prefix) on every request | Built once, passed to every client constructor |
| **AuthzClient** | Wraps gRPC `AuthorizationService` (`CheckAccess`, `BatchCheckAccess`) and `TokenService` (`ValidateToken`, `IntrospectToken`) | Falls back to REST introspect endpoint for languages where gRPC is not viable |
| **AdminClient** | Typed methods for every REST CRUD resource (org, tenant, user, group, role, permission, resource, scope, cert, PGP, webhook, audit, service-account, oauth2-client, federation, settings) | Generated from OpenAPI spec where tooling is reliable; hand-written otherwise |
| **TypedModels** | Request/response types matching the OpenAPI components schema and proto messages | Source of truth: OpenAPI spec (`/api/docs/openapi.json`) + proto files in `proto/axiam/v1/` |

---

## 2. Contract Source of Truth and Codegen Strategy

### OpenAPI Spec (REST)

**Source of truth:** utoipa annotations in `crates/axiam-api-rest/src/` compiled into
`ApiDoc`. The spec is served live at `GET /api/docs/openapi.json`.

**Export strategy for codegen:** Add a CI step that starts the server (or a minimal
binary that calls `api_doc().to_pretty_json()` without spinning up Actix) and writes
`artifacts/openapi.json`. This artifact is committed to `sdks/openapi.json` (or
published as a CI artifact) and consumed by codegen tools. The file must be re-exported
on every release tag; stale codegen is a maintenance trap.

**Codegen tool recommendation:** Use `openapi-generator-cli` (openapi-generator 7.x,
JVM-based, `docker run --rm openapitools/openapi-generator-cli`) for typed model
stubs only (data classes / structs / interfaces). Do NOT use it to generate full client
logic — the auth/token/tenant layers require hand-written orchestration that codegen
tools produce poorly (non-idiomatic, missing retry queues, OAuth2 not wired). Generate:
- TypeScript: `typescript-fetch` generator → type stubs + raw fetch calls; replace HTTP
  layer with hand-written `AuthClient` + `TokenManager`.
- Python: `python` generator (or `python-pydantic-v1`) → Pydantic models only.
- Java: `java` generator with `okhttp-gson` library → model POJOs only.
- C#: `csharp` generator → model classes only.
- PHP: `php` generator → model classes only.
- Go: `go` generator → type structs only.
- Rust: Do NOT use codegen for Rust — hand-write `reqwest`-based client; the generated
  Rust code from openapi-generator is low quality and conflicts with Rust idioms.

### Proto (gRPC)

**Source of truth:** `proto/axiam/v1/` — three services:
- `AuthorizationService` (CheckAccess, BatchCheckAccess) — `authorization.proto`
- `TokenService` (ValidateToken, IntrospectToken) — `token.proto`
- `UserService` (GetUser, ValidateCredentials) — `user.proto`

**Codegen tool:** Use [buf](https://buf.build/) (`buf.gen.yaml`) to generate stubs
for all gRPC-capable languages in one pass. Buf provides: linting, breaking-change
detection in CI, remote plugins (no local `protoc` install required), and a single
`buf.gen.yaml` that outputs to each SDK's generated directory.

Sample `buf.gen.yaml` at repo root:
```yaml
version: v2
plugins:
  - remote: buf.build/grpc/go
    out: sdks/go/internal/gen/grpc
  - remote: buf.build/grpc/java
    out: sdks/java/src/main/java/gen/grpc
  - remote: buf.build/community/neoeinstein-prost  # Rust
    out: sdks/rust/src/gen
  - remote: buf.build/grpc/python
    out: sdks/python/axiam_sdk/gen/grpc
  - remote: buf.build/grpc/csharp
    out: sdks/csharp/Axiam.Sdk/Gen/Grpc
```
TypeScript gRPC: use `buf.build/community/stephenh-ts-proto` for Node.js environments;
browser gRPC requires `grpc-web` (not in scope for v1.1 starter SDKs).
PHP gRPC: use the official `grpc/grpc` PHP extension + `protoc-gen-php-grpc`; viable
but complex to set up — treat as optional for PHP SDK starter.

**Buf CI gate:** Add `buf lint` + `buf breaking --against '.git#branch=main'` to
the existing `ci.yml` whenever protos change. Prevents accidental wire-breaking changes.

---

## 3. Monorepo vs. Polyrepo Decision

**Decision: Monorepo (sdks/ subtree in the existing repo)**

Rationale:
- SDKs track the frozen v1.0 API. They version together: an API fix in the server
  that changes a response field must update ALL SDKs atomically. Polyrepos make this
  coordination expensive.
- The OpenAPI spec and proto files are the shared contract. With a monorepo, a
  codegen regeneration step can update all 7 SDKs in a single PR, with a single CI run
  verifying they still compile.
- AXIAM is open-source. GitHub Actions path filters (`paths:`) make it cheap to run
  only the affected SDK's CI job on a per-change basis, removing the main monorepo
  downside (slow CI).
- Polyrepo is better when SDK teams are independent and need divergent release cadences.
  AXIAM has one maintainer team and wants coordinated v1.1 releases. Polyrepo is wrong
  here.

**Monorepo layout:**
```
sdks/
├── openapi.json              # exported spec (source of truth for codegen)
├── buf.gen.yaml              # multi-language proto codegen config
├── buf.yaml                  # buf workspace pointing at proto/
├── rust/
│   ├── Cargo.toml            # [package] axiam-client; publishes to crates.io
│   ├── src/
│   │   ├── lib.rs
│   │   ├── auth.rs           # AuthClient
│   │   ├── authz.rs          # AuthzClient (gRPC via tonic)
│   │   ├── admin.rs          # AdminClient (reqwest REST)
│   │   ├── token.rs          # TokenManager
│   │   ├── tenant.rs         # TenantContext
│   │   ├── models/           # hand-written or generated model types
│   │   └── gen/              # buf-generated proto stubs (gitignored or committed)
│   └── examples/
├── typescript/
│   ├── package.json          # name: @axiam/sdk; publishes to npm
│   ├── src/
│   │   ├── index.ts
│   │   ├── auth.ts
│   │   ├── authz.ts          # gRPC via @grpc/grpc-js (Node.js only)
│   │   ├── admin.ts
│   │   ├── token-manager.ts
│   │   ├── tenant.ts
│   │   ├── models/           # generated from openapi-generator typescript-fetch
│   │   └── gen/              # buf-generated ts-proto stubs
│   ├── middleware/
│   │   ├── express.ts
│   │   └── fastify.ts
│   └── examples/
├── python/
│   ├── pyproject.toml        # name: axiam-sdk; publishes to PyPI
│   ├── axiam_sdk/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── authz.py          # gRPC via grpcio
│   │   ├── admin.py
│   │   ├── token_manager.py
│   │   ├── tenant.py
│   │   ├── models/           # Pydantic v2 models (generated stubs, then customized)
│   │   └── gen/              # buf-generated proto stubs
│   ├── middleware/
│   │   ├── fastapi.py
│   │   └── django.py
│   └── examples/
├── java/
│   ├── pom.xml               # group: io.axiam; publishes to Maven Central
│   ├── src/main/java/io/axiam/sdk/
│   │   ├── AximClient.java
│   │   ├── AuthClient.java
│   │   ├── AuthzClient.java  # gRPC via grpc-java
│   │   ├── AdminClient.java
│   │   ├── TokenManager.java
│   │   ├── TenantContext.java
│   │   ├── models/
│   │   └── gen/grpc/
│   ├── spring/               # Spring Security integration
│   └── examples/
├── csharp/
│   ├── Axiam.Sdk.csproj      # publishes to NuGet
│   ├── Axiam.Sdk/
│   │   ├── AuthClient.cs
│   │   ├── AuthzClient.cs    # gRPC via Grpc.Net.Client
│   │   ├── AdminClient.cs
│   │   ├── TokenManager.cs
│   │   ├── TenantContext.cs
│   │   ├── Models/
│   │   └── Gen/Grpc/
│   ├── Axiam.Sdk.AspNetCore/ # ASP.NET Core middleware
│   └── examples/
├── php/
│   ├── composer.json         # name: axiam/sdk; publishes to Packagist
│   ├── src/
│   │   ├── AuthClient.php
│   │   ├── AdminClient.php
│   │   ├── TokenManager.php
│   │   ├── TenantContext.php
│   │   ├── Models/
│   │   └── Middleware/
│   │       ├── LaravelMiddleware.php
│   │       └── SymfonyMiddleware.php
│   └── examples/
└── go/
    ├── go.mod                # module github.com/axiamhq/axiam-go; publishes to pkg.go.dev
    ├── auth.go
    ├── authz.go              # gRPC via google.golang.org/grpc
    ├── admin.go
    ├── token_manager.go
    ├── tenant.go
    ├── models/               # generated Go structs + hand-written
    ├── gen/grpc/             # buf-generated stubs
    ├── middleware/
    │   └── http.go           # net/http middleware
    └── examples/
```

---

## 4. Versioning Strategy

### SDK Versions vs. Server API Version

- Server API is versioned by URL prefix: `/api/v1/`. This prefix is stable for all
  of v1.x. A breaking REST change would introduce `/api/v2/`.
- SDKs use **semver independently** from the server: `axiam-client 0.1.0` targets
  `server v1.0`. SDK patch releases fix SDK bugs without server changes. SDK minor
  releases add convenience wrappers for existing endpoints. SDK major releases track
  server API major versions or their own breaking API surface changes.
- **Compatibility contract:** Each SDK's README declares a compatibility matrix:
  `axiam-client >= 0.1 requires axiam-server >= 1.0`. A `[package.metadata.axiam]`
  section in each manifest pins the minimum server version.
- **Proto stability:** buf `breaking` checks enforce proto wire compatibility. Any
  proto field removal or renaming is a breaking change requiring a new SDK major.
- **OpenAPI drift detection:** CI re-exports `openapi.json` from the server binary and
  diffs it against `sdks/openapi.json`. A mismatch (field added/removed) fails the
  SDK CI gate and forces a codegen + SDK update cycle.

### Release Tagging

Tags are per-SDK to trigger only the relevant publish workflow:
- `sdk/rust/v0.1.0` → triggers `publish-sdk-rust.yml`
- `sdk/typescript/v0.1.0` → triggers `publish-sdk-typescript.yml`
- etc.

Server releases (`v1.x.y`) do NOT automatically trigger SDK publishes — a human
bumps SDK versions after verifying compatibility.

---

## 5. Build Order Across 7 SDKs

**Rationale for ordering:** The Rust SDK is the reference implementation because:
1. The server is Rust — the maintainer understands the type system and auth flows best.
2. Rust SDK can share proto-generated types from `buf` without fighting the toolchain.
3. TypeScript is the second most likely consumer (frontend/BFF) and has the richest
   codegen ecosystem; it validates the OpenAPI export pipeline.
4. Go and Python have mature gRPC ecosystems and serve microservice use cases.
5. Java and C# are enterprise targets; their codegen output is predictable but verbose.
6. PHP is REST-only (gRPC optional); it's lowest complexity and serves as a smoke-test
   that the OpenAPI codegen models are correct.

**Shared artifacts that must exist before per-language work:**
- `sdks/openapi.json` — exported from server, committed
- `buf.gen.yaml` + `buf.yaml` — proto codegen config
- CI job `export-openapi` — runs on every release, updates `sdks/openapi.json`

**Suggested phase order:**

| Phase | SDK | Rationale | Depends On |
|-------|-----|-----------|------------|
| T17.1 | **Rust** | Reference impl; proves transport + TokenManager pattern | openapi.json, proto |
| T17.2 | **TypeScript** | Validates OpenAPI export + npm publish pipeline; broadest immediate user base | openapi.json (codegen), proto (ts-proto) |
| T17.7 | **Go** | gRPC ecosystem matures alongside Rust; microservice use case | proto (buf go), openapi.json |
| T17.3 | **Python** | gRPC via grpcio; FastAPI/Django middleware needed for Python IAM consumers | proto (buf python), openapi.json |
| T17.4 | **Java** | Enterprise; grpc-java codegen well understood; Spring Security integration | proto (buf java), openapi.json |
| T17.5 | **C#** | Grpc.Net.Client is .NET-native; ASP.NET Core middleware; similar to Java effort | proto (buf csharp), openapi.json |
| T17.6 | **PHP** | REST-only starter; no gRPC complexity; validates Packagist publish pipeline | openapi.json only |

---

## 6. Integration Points with Existing Monorepo

### New Components (net-new, nothing modified in server)

| Component | Location | Purpose |
|-----------|----------|---------|
| `sdks/openapi.json` | `sdks/openapi.json` | Exported spec; codegen source of truth |
| `sdks/buf.yaml` | `sdks/buf.yaml` | Buf workspace config pointing at `proto/axiam/v1/` |
| `sdks/buf.gen.yaml` | `sdks/buf.gen.yaml` | Multi-language proto codegen output config |
| Per-SDK packages | `sdks/{rust,typescript,…}/` | SDK source trees |
| CI workflow: export-openapi | `.github/workflows/sdk-export-openapi.yml` | Builds server binary, dumps spec, diffs vs committed |
| CI workflow per SDK | `.github/workflows/sdk-ci-{lang}.yml` | Build + test each SDK on `sdks/{lang}/**` path filter |
| CI workflow publish | `.github/workflows/publish-sdk-{lang}.yml` | Triggered by `sdk/{lang}/v*` tag; pushes to registry |

### Modified Components (existing, minimal changes)

| Component | Change | Why |
|-----------|--------|-----|
| `crates/axiam-server/src/main.rs` (or new binary) | Add `--dump-openapi` flag that prints `api_doc().to_pretty_json()` and exits | Enables CI spec export without starting SurrealDB/AMQP |
| `.github/workflows/ci.yml` | Add buf lint + buf breaking gate on `proto/**` changes | Prevents accidental wire breaks |
| `Cargo.toml` (workspace) | Add `members = ["sdks/rust"]` if Rust SDK uses workspace | Optional — SDK may be standalone to decouple release |

### Data Flow for Auth in SDKs

```
SDK user calls client.auth.login(email, password, tenant)
    -> POST /api/v1/auth/login with X-Tenant-ID header
    -> Server sets httpOnly cookie (refresh_token) + returns access_token in body
    -> TokenManager stores access_token in memory
    -> TokenManager schedules refresh at (exp - 15s)

On subsequent API call:
    -> TokenManager injects Authorization: Bearer <access_token>
    -> On 401: pause queue, POST /api/v1/auth/refresh (cookie auto-sent)
    -> New access_token stored, queue drained

For gRPC (AuthzClient):
    -> TokenManager provides access_token as gRPC metadata: authorization: Bearer <token>
    -> Same refresh path — REST refresh, then retry gRPC call

For AMQP (Rust/Go/Python/Java/C# only):
    -> AMQP client connects with service-account credentials (Client Credentials flow)
    -> Publishes authz request messages; consumes response messages
    -> SDK wraps publish/consume with typed message structs from proto
```

---

## 7. Architectural Patterns

### Pattern 1: In-Memory Token + Proactive Refresh

**What:** Access token stored in process memory. A background task (tokio task / asyncio
task / goroutine / ExecutorService thread) wakes at `(exp_at - 30s)` and calls
`/auth/refresh` before the token expires, eliminating 401s in steady-state.
**When to use:** All SDKs. Avoids the "thundering herd" 401 problem when multiple
concurrent calls hit an expired token simultaneously.
**Trade-off:** In-process token means token is lost on process restart (expected for
short-lived access tokens). Refresh token is in httpOnly cookie — browser manages it
automatically; server-side SDK must store it explicitly (in a secure server-side store,
not in-process for long-running services).

### Pattern 2: TenantContext Injection via Header

**What:** All REST requests include `X-Tenant-ID: <tenant_uuid>` (server uses this to
scope DB queries). TenantContext is constructed once with org/tenant identifiers and
injected into every HTTP client call via a middleware/interceptor.
**When to use:** All SDKs. Don't pass tenant on every method call — that's error-prone.
**Trade-off:** The tenant UUID must be resolved from the org+tenant slug before SDK
initialization. The SDK should expose a `resolve_tenant(org_slug, tenant_slug) -> uuid`
helper that calls `GET /api/v1/tenants?slug=…`.

### Pattern 3: gRPC Fallback for AuthzClient

**What:** gRPC `CheckAccess` is the primary path. If gRPC is not available (PHP, or
environments where port 50051 is blocked), fall back to REST `POST /oauth2/introspect`
for token validation and a REST authz-check stub.
**When to use:** PHP SDK (gRPC optional); any SDK where the deployment blocks gRPC.
**Trade-off:** REST fallback is ~2-5x higher latency than gRPC for high-frequency authz
checks. Document clearly in SDK README.

---

## 8. Anti-Patterns

### Anti-Pattern 1: Using openapi-generator for Full Client Logic

**What people do:** Run `openapi-generator generate -g typescript-fetch` and ship the
output as the SDK.
**Why it's wrong:** Auth flows (cookie refresh, MFA branching, PKCE), the TokenManager
retry queue, and tenant context injection are not expressible in OpenAPI spec — the
generated client has none of them. The output is also non-idiomatic in most target
languages.
**Do this instead:** Use openapi-generator for typed model/schema classes only. Write
the AuthClient, TokenManager, and TenantContext by hand.

### Anti-Pattern 2: Storing Access Tokens in Persistent Storage

**What people do:** Store the access token in localStorage, a file, or a DB row.
**Why it's wrong:** AXIAM access tokens expire in 15 minutes. Persisting them creates
a false cache. More critically, localStorage is XSS-readable; file storage leaks on
shared systems.
**Do this instead:** Keep access token in memory. Persist only the refresh token (httpOnly
cookie in browser; encrypted file/keychain for CLI/desktop SDK consumers).

### Anti-Pattern 3: Per-Request Tenant Resolution

**What people do:** Look up the tenant UUID on every API call from the org/tenant slug.
**Why it's wrong:** Adds a DB round-trip on every request; tenants don't change during
a session.
**Do this instead:** Resolve and cache tenant UUID at SDK initialization in TenantContext.

### Anti-Pattern 4: One Giant CI Job for All SDKs

**What people do:** A single CI workflow builds and tests all 7 SDKs on every commit.
**Why it's wrong:** A Rust change shouldn't trigger Java CI. Adds minutes to unrelated
PRs and wastes CI minutes.
**Do this instead:** Use GitHub Actions `paths:` filters — one workflow file per SDK,
triggered only when `sdks/{lang}/**` or `sdks/openapi.json` changes.

---

## Sources

- AXIAM codebase: `crates/axiam-api-rest/src/openapi.rs` (utoipa ApiDoc, spec at `/api/docs/openapi.json`)
- AXIAM codebase: `proto/axiam/v1/{authorization,token,user}.proto` (gRPC IDL)
- AXIAM codebase: `.github/workflows/ci.yml` + `release.yml` (existing CI patterns)
- [buf.build — Modern Protobuf toolchain](https://buf.build/)
- [openapi-generator: 50+ language targets, best for model stubs](https://openapi-generator.tech/)
- [Buf GitHub — buf.gen.yaml multi-language config](https://github.com/bufbuild/buf)
- [Parser Digital: Managing Multi-Language Open Source SDKs on GitHub](https://parserdigital.com/2025/02/18/how-to-manage-multi-language-open-source-sdks-on-githug-best-practices-tools/)
- [utoipa OpenAPI export issue #214](https://github.com/juhaku/utoipa/issues/214)

---
*Architecture research for: AXIAM Client SDK layer (v1.1)*
*Researched: 2026-06-28*
