# Architecture

**Analysis Date:** 2026-03-28

## Pattern Overview

**Overall:** Layered Modular Monolith (Cargo workspace with clean layer separation)

**Key Characteristics:**
- 13 workspace crates with strict dependency direction: core -> db -> services -> api -> server
- Repository trait pattern: traits defined in `axiam-core`, implemented in `axiam-db`
- Multi-tenant by design: all domain operations are scoped by `tenant_id`
- Three API surfaces (REST, gRPC, AMQP) sharing the same domain/service layer
- Single binary (`axiam-server`) composes all crates at startup

## Layers

**Domain Layer (`axiam-core`):**
- Purpose: Domain models, repository traits, error types. Zero external dependencies beyond serde/uuid/chrono.
- Location: `crates/axiam-core/src/`
- Contains: 25 model modules, repository trait definitions, `AxiamError` enum
- Depends on: serde, uuid, chrono, thiserror, utoipa (for schema derive)
- Used by: Every other crate in the workspace

**Persistence Layer (`axiam-db`):**
- Purpose: SurrealDB repository implementations, schema migrations, connection management
- Location: `crates/axiam-db/src/`
- Contains: 28 repository implementations (`SurrealXxxRepository`), migration runner, `DbManager`
- Depends on: `axiam-core`, surrealdb, surrealdb-types, argon2
- Used by: `axiam-auth`, `axiam-authz`, `axiam-api-rest`, `axiam-oauth2`, `axiam-federation`, `axiam-server`

**Service Layer (multiple crates):**

| Crate | Purpose | Location |
|-------|---------|----------|
| `axiam-auth` | Authentication: password, JWT, MFA (TOTP, WebAuthn), password reset, email verification | `crates/axiam-auth/src/` |
| `axiam-authz` | RBAC engine with resource hierarchy and scope evaluation | `crates/axiam-authz/src/` |
| `axiam-oauth2` | OAuth2 authorization server + OIDC provider (authorize, token, PKCE) | `crates/axiam-oauth2/src/` |
| `axiam-pki` | X.509 CA management, leaf certificate lifecycle, mTLS device auth, PGP keys | `crates/axiam-pki/src/` |
| `axiam-federation` | SAML SP and OIDC external IdP integration | `crates/axiam-federation/src/` |
| `axiam-audit` | Audit logging middleware and notification dispatch | `crates/axiam-audit/src/` |
| `axiam-email` | Pluggable email delivery (SMTP, SendGrid, Postmark, Resend, Brevo) | `crates/axiam-email/src/` |

**API Layer:**

| Crate | Purpose | Location |
|-------|---------|----------|
| `axiam-api-rest` | Actix-Web REST API: handlers, extractors, authorization guards, OpenAPI | `crates/axiam-api-rest/src/` |
| `axiam-api-grpc` | Tonic gRPC server: authorization, user, and token services | `crates/axiam-api-grpc/src/` |
| `axiam-amqp` | RabbitMQ: async authz consumer, audit consumer, notification publisher | `crates/axiam-amqp/src/` |

**Composition Layer (`axiam-server`):**
- Purpose: Binary entry point. Wires all crates together, starts HTTP + gRPC + AMQP.
- Location: `crates/axiam-server/src/main.rs`
- Depends on: All other crates
- Used by: Nothing (final binary)

## Crate Dependency Graph

```
                         axiam-server (binary)
                        /    |    |    \
                       /     |    |     \
              axiam-api-rest  |  axiam-api-grpc  axiam-amqp
              /  |  |  \      |       |    \        |   \
             /   |  |   \     |       |     \       |    \
    axiam-auth   |  |  axiam-pki   axiam-authz   axiam-audit
        |        |  |     |           |              |
        |   axiam-oauth2  |     axiam-federation     |
        |        |        |           |              |
        v        v        v           v              v
              axiam-db  (all service crates depend on axiam-core)
                 |
                 v
             axiam-core
```

**Dependency rules:**
- `axiam-core` has ZERO internal dependencies (leaf crate)
- `axiam-db` depends only on `axiam-core`
- Service crates depend on `axiam-core` and optionally `axiam-db`
- API crates depend on service crates and `axiam-core`
- `axiam-server` depends on everything

## Data Flow

**REST API Request:**

1. HTTP request arrives at Actix-Web (`crates/axiam-server/src/main.rs` lines 247-285)
2. `AuditMiddleware` intercepts: validates JWT (if present), caches identity, queues audit entry (`crates/axiam-audit/src/middleware.rs`)
3. CORS middleware applies (`crates/axiam-api-rest/src/server.rs` `build_cors()`)
4. Route dispatches to handler in `crates/axiam-api-rest/src/handlers/`
5. `AuthenticatedUser` extractor validates JWT from `Authorization: Bearer` header (`crates/axiam-api-rest/src/extractors/auth.rs`)
6. `TenantContext` extractor derives tenant_id/org_id from JWT claims (`crates/axiam-api-rest/src/extractors/tenant.rs`)
7. Handler calls repository (injected via `web::Data<SurrealXxxRepository>`)
8. Repository executes SurrealQL, returns domain model
9. Handler serializes response as JSON

**gRPC Authorization Check:**

1. gRPC request arrives at Tonic server (spawned on separate port)
2. `AuthorizationServiceImpl` receives `CheckAccessRequest` (`crates/axiam-api-grpc/src/services/authorization.rs`)
3. Delegates to `AuthorizationEngine::check_access()` (`crates/axiam-authz/src/engine.rs`)
4. Engine fetches user roles (direct + group), filters by resource hierarchy, checks permissions and scopes
5. Returns `AccessDecision` (Allow/Deny with reason)

**AMQP Async Authorization:**

1. Message published to `axiam.authz.request` queue
2. `start_authz_consumer()` receives message (`crates/axiam-amqp/src/authz_consumer.rs`)
3. Deserializes `AuthzRequest`, calls `AuthorizationEngine::check_access()`
4. Publishes `AuthzResponse` to `axiam.authz.response` queue

**AMQP Audit Event Flow:**

1. Audit middleware sends `CreateAuditLogEntry` to bounded channel (capacity 4096)
2. Background worker reads from channel, writes to `AuditLogRepository`
3. Separate AMQP audit consumer handles async audit events from `axiam.audit.event` queue

**State Management:**
- No in-process state beyond connection pools and config
- All state lives in SurrealDB (users, roles, sessions, etc.) and RabbitMQ (message queues)
- JWT tokens are stateless (Ed25519 signed, 15-min expiry)
- Refresh tokens are server-stored, single-use with rotation

## Key Abstractions

**Repository Traits (`crates/axiam-core/src/repository.rs`):**
- Purpose: Define all data access contracts independent of database implementation
- 25+ traits: `OrganizationRepository`, `TenantRepository`, `UserRepository`, `RoleRepository`, `PermissionRepository`, `ResourceRepository`, `ScopeRepository`, `GroupRepository`, `SessionRepository`, `AuditLogRepository`, `CaCertificateRepository`, `CertificateRepository`, `PgpKeyRepository`, `WebhookRepository`, `OAuth2ClientRepository`, `AuthorizationCodeRepository`, `RefreshTokenRepository`, `FederationConfigRepository`, `FederationLinkRepository`, `ServiceAccountRepository`, `WebauthnCredentialRepository`, `SettingsRepository`, `NotificationRuleRepository`, `EmailTemplateRepository`, `PasswordHistoryRepository`, `PasswordResetTokenRepository`, `EmailVerificationTokenRepository`
- Pattern: All async, tenant-scoped operations require `tenant_id: Uuid` parameter
- Pagination: `Pagination` struct (offset/limit) returns `PaginatedResult<T>`

**Domain Models (`crates/axiam-core/src/models/`):**
- 25 model modules, each with Create/Update DTOs and main entity struct
- All use serde `Serialize`/`Deserialize`
- UUIDs used for all identifiers

**AuthorizationEngine (`crates/axiam-authz/src/engine.rs`):**
- Purpose: RBAC permission evaluation with resource hierarchy inheritance
- Generic over 5 repository types: `<R: RoleRepository, P: PermissionRepository, Res: ResourceRepository, S: ScopeRepository, G: GroupRepository>`
- Algorithm: fetch roles (direct + group) -> filter by resource scope (global, direct, ancestor) -> collect permissions -> match action -> validate scopes -> default deny
- Type-erased via `AuthzChecker` trait in `crates/axiam-api-rest/src/authz.rs` for handler use

**AuthenticatedUser Extractor (`crates/axiam-api-rest/src/extractors/auth.rs`):**
- Purpose: Actix-Web `FromRequest` implementation for JWT-based authentication
- Extracts `user_id`, `tenant_id`, `org_id` from JWT claims
- Reuses cached identity from audit middleware when available

**AuthService (`crates/axiam-auth/src/service.rs`):**
- Purpose: Login flow orchestration (password verify, MFA challenge, JWT issuance, session creation)
- Handles: login, logout, refresh, MFA enroll/verify

## Entry Points

**Binary (`axiam-server`):**
- Location: `crates/axiam-server/src/main.rs`
- Triggers: `cargo run --bin axiam-server` or `just run`
- Responsibilities: Load config, connect to SurrealDB, run migrations, connect to RabbitMQ, instantiate all repositories and services, spawn gRPC server and AMQP consumers as background tasks, start Actix-Web HTTP server

**REST API:**
- Location: `crates/axiam-api-rest/src/server.rs`
- Routes registered in: `register_api_v1_routes()`, `health_routes()`, `openapi_routes()`
- Base paths: `/auth/*`, `/oauth2/*`, `/api/v1/*`, `/.well-known/openid-configuration`, `/health`, `/ready`, `/api/docs/*`

**gRPC Server:**
- Location: `crates/axiam-api-grpc/src/server.rs`
- Services: `AuthorizationService`, `UserService`, `TokenService`
- Proto definitions: `proto/axiam/v1/authorization.proto`, `proto/axiam/v1/user.proto`, `proto/axiam/v1/token.proto`

**AMQP Consumers:**
- Authorization: `crates/axiam-amqp/src/authz_consumer.rs` (queue: `axiam.authz.request`)
- Audit: `crates/axiam-amqp/src/audit_consumer.rs` (queue: `axiam.audit.event`)
- Notification publisher: `crates/axiam-amqp/src/notification_publisher.rs`

## Error Handling

**Strategy:** Layered error types with conversion at boundaries

**Patterns:**
- `AxiamError` (`crates/axiam-core/src/error.rs`): Central domain error enum (NotFound, AlreadyExists, AuthenticationFailed, AuthorizationDenied, Validation, Database, Certificate, Crypto, EmailDelivery, WebhookDelivery, TenantContext, RateLimited, Internal)
- `AxiamResult<T>` = `Result<T, AxiamError>`: Used throughout domain and service layers
- `DbError` (`crates/axiam-db/src/error.rs`): Database-specific errors, converted to `AxiamError::Database`
- `AuthError` (`crates/axiam-auth/src/error.rs`): Auth-specific errors
- `AxiamApiError` (`crates/axiam-api-rest/src/error.rs`): HTTP error responses, converts from `AxiamError` to appropriate status codes
- `AmqpError` (`crates/axiam-amqp/src/error.rs`): AMQP-specific errors
- `FederationError` (`crates/axiam-federation/src/error.rs`): Federation-specific errors

## Cross-Cutting Concerns

**Logging:**
- Framework: `tracing` + `tracing-subscriber` with JSON output and env-filter
- HTTP: `TracingLogger` middleware (tracing-actix-web)
- Default level: `axiam=info`, overridable via `RUST_LOG`

**Validation:**
- Config validation at startup with `assert!` macros (fail-fast)
- JWT issuer URL validation (HTTPS required, no path/query/fragment)
- Encryption key validation (must be exactly 32 bytes hex-encoded)
- SSRF mitigation: `reqwest::redirect::Policy::none()` + 10s timeout on HTTP client

**Authentication:**
- JWT (Ed25519/EdDSA) with 15-min access tokens
- Refresh tokens: server-stored, single-use rotation
- MFA: TOTP + WebAuthn, secrets encrypted with AES-256-GCM
- Certificate-based: mTLS for IoT devices (`CertificateAuthenticated` extractor)
- Federation: OIDC + SAML external IdP login

**Multi-tenancy:**
- Every tenant-scoped repository method requires `tenant_id: Uuid`
- JWT claims carry `tenant_id` and `org_id`
- `TenantContext` extractor provides scoping in every handler

**Audit:**
- Actix-Web middleware captures all requests to bounded async channel
- Background worker persists to SurrealDB (append-only, no UPDATE/DELETE)
- AMQP consumer handles async audit events
- PGP signing available for audit batch verification

---

*Architecture analysis: 2026-03-28*
