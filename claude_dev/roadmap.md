# AXIAM — Development Roadmap

Each task is sized to be completable in a single Claude Code session (Opus 4.6, medium effort). Each task ends with a signed commit. Tasks within a phase are sequential; phases build on previous ones.

---

## Phase 0: Project Foundation

### T0.1 — Cargo Workspace Scaffolding
Create the Cargo workspace with all planned crates (`axiam-core`, `axiam-db`, `axiam-auth`, `axiam-authz`, `axiam-api-rest`, `axiam-api-grpc`, `axiam-amqp`, `axiam-oauth2`, `axiam-federation`, `axiam-audit`, `axiam-server`). Each crate gets a minimal `lib.rs` or `main.rs`. Add workspace-level dependencies in `Cargo.toml`.

**Commit**: `feat: scaffold Cargo workspace with all crates`

### T0.2 — CI Pipeline (GitHub Actions)
Set up GitHub Actions workflows: `ci.yml` (build + test + clippy + fmt check on every push/PR), `release.yml` (placeholder for Docker build). Add `.rustfmt.toml` and `clippy.toml` with project conventions.

**Commit**: `ci: add GitHub Actions build/test/lint pipeline`

### T0.3 — Dev Environment (Docker Compose)
Create `docker/docker-compose.dev.yml` with SurrealDB and RabbitMQ services. Add a `Makefile` or `justfile` with common dev commands (`dev-up`, `dev-down`, `build`, `test`, `lint`).

**Commit**: `chore: add Docker Compose dev environment and Makefile`

---

## Phase 1: Core Domain & Database

### T1.1 — Core Domain Types (`axiam-core`)
Define core domain types: `User`, `Role`, `Permission`, `Resource`, `Scope`, `ServiceAccount`, `Session`, `AuditLogEntry`, `OAuth2Client`, `FederationConfig`. Define error types (`AxiamError`). Define repository traits (`UserRepository`, `RoleRepository`, etc.).

**Commit**: `feat(core): define domain types, error types, and repository traits`

### T1.2 — SurrealDB Connection & Migrations (`axiam-db`)
Implement SurrealDB connection pool/manager. Create schema initialization (table definitions, indexes, graph edge definitions). Write a migration runner that applies schema on startup. Add integration test with Docker-based SurrealDB.

**Commit**: `feat(db): SurrealDB connection manager and schema initialization`

### T1.3 — User Repository Implementation
Implement `UserRepository` trait for SurrealDB: create, get by ID, get by username/email, update, delete (soft-delete), list with pagination. Include password hash storage. Add unit/integration tests.

**Commit**: `feat(db): implement User repository with CRUD operations`

### T1.4 — Role & Permission Repository Implementation
Implement `RoleRepository` and `PermissionRepository` for SurrealDB: CRUD operations, role-permission assignment (`grants` edge), global vs resource-scoped roles. Add tests.

**Commit**: `feat(db): implement Role and Permission repositories`

### T1.5 — Resource & Scope Repository Implementation
Implement `ResourceRepository` for SurrealDB: CRUD with hierarchical parent-child relationships (`child_of` edge), tree traversal queries. Implement `ScopeRepository`. Add tests.

**Commit**: `feat(db): implement Resource hierarchy and Scope repositories`

### T1.6 — Service Account & Session Repositories
Implement `ServiceAccountRepository` (CRUD, client credential management) and `SessionRepository` (create, validate, invalidate, cleanup expired). Add tests.

**Commit**: `feat(db): implement ServiceAccount and Session repositories`

---

## Phase 2: Authentication

### T2.1 — Password Authentication (`axiam-auth`)
Implement password hashing (Argon2id) and verification. Implement login flow: credential validation, session creation, JWT (EdDSA/Ed25519) access token + opaque refresh token generation. Add configuration for password policy (min length, complexity). Add unit tests.

**Commit**: `feat(auth): password authentication with Argon2id and JWT issuance`

### T2.2 — JWT Validation & Token Refresh
Implement JWT validation middleware (signature verification, expiry check, claims extraction). Implement refresh token rotation endpoint. Handle token revocation (blacklist via session invalidation). Add tests.

**Commit**: `feat(auth): JWT validation middleware and token refresh`

### T2.3 — MFA (TOTP)
Implement TOTP enrollment (secret generation, QR code URI), TOTP verification, MFA challenge flow during login. Encrypt TOTP secrets at rest (AES-256-GCM). Add tests.

**Commit**: `feat(auth): TOTP multi-factor authentication`

### T2.4 — Brute Force Protection & Security Controls
Implement failed login tracking, account lockout with exponential backoff, rate limiting per IP/user on auth endpoints. Add tests.

**Commit**: `feat(auth): brute force protection and rate limiting`

---

## Phase 3: Authorization Engine

### T3.1 — Permission Evaluation Engine (`axiam-authz`)
Implement the core authorization check: given (subject, action, resource), resolve roles, collect permissions, evaluate against resource hierarchy with inheritance. Default-deny policy. Add unit tests with various hierarchy scenarios.

**Commit**: `feat(authz): permission evaluation engine with hierarchy inheritance`

### T3.2 — Scope-Based Authorization
Extend the engine to support scope-level checks. Implement scope validation within permission grants. Add tests for scope-based access control.

**Commit**: `feat(authz): scope-based fine-grained authorization`

### T3.3 — Authorization Middleware
Create Actix-Web middleware/extractor that runs authorization checks on incoming requests. Support attribute-based annotations (e.g., required permission and resource extracted from path). Add integration tests.

**Commit**: `feat(authz): HTTP authorization middleware for Actix-Web`

---

## Phase 4: REST API

### T4.1 — REST API Server Bootstrap (`axiam-api-rest`)
Set up Actix-Web server with configuration loading, middleware pipeline (CORS, logging, error handling), health/readiness endpoints. Wire up to `axiam-server` binary. Add basic integration test.

**Commit**: `feat(api-rest): Actix-Web server bootstrap with health endpoints`

### T4.2 — Auth Endpoints (REST)
Implement `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `POST /auth/mfa/enroll`, `POST /auth/mfa/verify`. Wire to auth service. Add integration tests.

**Commit**: `feat(api-rest): authentication endpoints`

### T4.3 — User Management Endpoints (REST)
Implement `GET/POST/PUT/DELETE /api/v1/users` with pagination, filtering, input validation. Protected by authorization middleware. Add integration tests.

**Commit**: `feat(api-rest): user management CRUD endpoints`

### T4.4 — Role & Permission Endpoints (REST)
Implement CRUD for roles, permissions, and role-permission assignments. Implement role assignment to users (`has_role` edge management). Add tests.

**Commit**: `feat(api-rest): role and permission management endpoints`

### T4.5 — Resource & Service Account Endpoints (REST)
Implement CRUD for resources (including hierarchy), scopes, and service accounts. Add tests.

**Commit**: `feat(api-rest): resource, scope, and service account endpoints`

### T4.6 — OpenAPI Documentation
Add `utoipa` annotations to all REST endpoints. Generate and serve OpenAPI spec at `/api/docs`. Add Swagger UI integration. Verify spec completeness.

**Commit**: `feat(api-rest): OpenAPI documentation with Swagger UI`

---

## Phase 5: gRPC API

### T5.1 — Proto Definitions & gRPC Server Bootstrap
Define `.proto` files for `AuthorizationService`, `UserService`, `TokenService`. Set up Tonic server alongside Actix-Web in `axiam-server`. Add build script for proto compilation.

**Commit**: `feat(api-grpc): proto definitions and Tonic server bootstrap`

### T5.2 — gRPC Service Implementations
Implement `CheckAccess`, `BatchCheckAccess`, `GetUser`, `ValidateCredentials`, `ValidateToken`, `IntrospectToken`. Wire to existing services. Add integration tests.

**Commit**: `feat(api-grpc): implement authorization, user, and token gRPC services`

---

## Phase 6: AMQP Integration

### T6.1 — AMQP Connection & Queue Setup (`axiam-amqp`)
Implement RabbitMQ connection management using Lapin. Declare queues (`authz.request`, `authz.response`, `audit.events`, `notifications`). Add reconnection logic.

**Commit**: `feat(amqp): RabbitMQ connection manager and queue declarations`

### T6.2 — Async Authorization via AMQP
Implement consumer for `authz.request` queue: deserialize request, run authorization engine, publish result to `authz.response`. Add integration test with RabbitMQ.

**Commit**: `feat(amqp): async authorization request/response via AMQP`

### T6.3 — Audit Event Ingestion & Notifications
Implement consumer for `audit.events` queue (external audit events). Implement publisher for `notifications` queue (role changes, user events). Add tests.

**Commit**: `feat(amqp): audit event ingestion and notification publishing`

---

## Phase 7: Audit Logging

### T7.1 — Audit Service (`axiam-audit`)
Implement audit logging service: structured log entries for authentication, authorization, CRUD operations, admin actions. Ensure append-only semantics. Add middleware that automatically logs API requests. Add tests.

**Commit**: `feat(audit): audit logging service with append-only storage`

### T7.2 — Audit Query API
Implement `GET /api/v1/audit-logs` with filtering (by actor, action, resource, date range), pagination, and sorting. Admin-only access. Add tests.

**Commit**: `feat(audit): audit log query API with filtering and pagination`

---

## Phase 8: OAuth2 & OpenID Connect

### T8.1 — OAuth2 Authorization Server (`axiam-oauth2`)
Implement OAuth2 client registration (CRUD for `OAuth2Client`). Implement Authorization Code Grant flow: `/oauth2/authorize` (consent screen), `/oauth2/token` (code exchange). Add PKCE support. Add tests.

**Commit**: `feat(oauth2): authorization server with Authorization Code + PKCE`

### T8.2 — Additional OAuth2 Grant Types
Implement Client Credentials Grant (for service accounts) and Refresh Token Grant. Implement `/oauth2/revoke` and `/oauth2/introspect`. Add tests.

**Commit**: `feat(oauth2): client credentials, refresh, revocation, and introspection`

### T8.3 — OpenID Connect Provider
Implement OIDC discovery (`/.well-known/openid-configuration`), ID token issuance with standard claims, `/oauth2/userinfo`, `/oauth2/jwks`. Add tests.

**Commit**: `feat(oauth2): OpenID Connect provider with discovery and userinfo`

---

## Phase 9: Federation

### T9.1 — OIDC Federation (`axiam-federation`)
Implement external OIDC IdP integration: configuration management, authorization redirect, callback handling, user provisioning/linking from external IdP claims. Add tests.

**Commit**: `feat(federation): external OIDC identity provider integration`

### T9.2 — SAML Service Provider
Implement SAML SP: metadata generation, AuthnRequest creation, SAML Response parsing/validation, assertion extraction, user provisioning/linking. Add tests.

**Commit**: `feat(federation): SAML service provider integration`

---

## Phase 10: Admin Frontend

### T10.1 — React Project Scaffold
Initialize React project (`frontend/`) with TypeScript, Vite, React Router, and a component library (e.g., Mantine or Ant Design). Set up API client (axios/fetch with auth interceptors). Add login page.

**Commit**: `feat(frontend): React project scaffold with login page`

### T10.2 — User Management UI
Implement user list (paginated, searchable), user detail/edit page, user creation form, role assignment UI. Connect to REST API.

**Commit**: `feat(frontend): user management pages`

### T10.3 — Role & Permission Management UI
Implement role list, role editor (permission assignment), permission list. Implement resource hierarchy viewer/editor.

**Commit**: `feat(frontend): role, permission, and resource management pages`

### T10.4 — Dashboard & Audit Viewer
Implement admin dashboard (user count, active sessions, recent activity). Implement audit log viewer with filters. Add OAuth2 client management page.

**Commit**: `feat(frontend): admin dashboard, audit viewer, and OAuth2 client management`

---

## Phase 11: Deployment & Infrastructure

### T11.1 — Dockerfile & Multi-Stage Build
Create optimized multi-stage Dockerfile for the AXIAM server binary. Create Dockerfile for the frontend (nginx-based). Add `.dockerignore`. Test images locally.

**Commit**: `feat(docker): multi-stage Dockerfiles for server and frontend`

### T11.2 — Kubernetes Manifests
Create K8s manifests: Deployment, Service, Ingress, ConfigMap, Secrets for AXIAM server. StatefulSet for SurrealDB and RabbitMQ. HPA configuration. Readiness/liveness probes.

**Commit**: `feat(k8s): Kubernetes deployment manifests with HPA`

### T11.3 — CD Pipeline (GitHub Actions)
Extend GitHub Actions: build and push Docker images on tag, deploy to K8s (or push Helm chart). Add release workflow with CHANGELOG generation.

**Commit**: `ci: add CD pipeline for Docker build and release`

---

## Phase 12: SDKs (Starters)

### T12.1 — Rust SDK
Create `sdks/rust/` with a client library wrapping REST and gRPC APIs. Auth helper, token management, authorization check helper. Add usage examples. Publish-ready with `Cargo.toml`.

**Commit**: `feat(sdk): Rust SDK with REST and gRPC client`

### T12.2 — TypeScript SDK
Create `sdks/typescript/` with a TypeScript/Node.js client library wrapping REST API. Auth flows, token refresh, middleware helper for Express/Fastify. Add usage examples.

**Commit**: `feat(sdk): TypeScript SDK with REST client`

### T12.3 — Python SDK
Create `sdks/python/` with a Python client library wrapping REST API. Auth flows, token management, FastAPI/Django middleware helper. Add usage examples.

**Commit**: `feat(sdk): Python SDK with REST client`

---

## Phase 13: Hardening & Compliance

### T13.1 — Security Audit Checklist
Create security audit checklist based on OWASP ASVS. Verify all authentication, session, access control, and cryptography requirements. Document findings and remediations in `claude_dev/security-audit.md`.

**Commit**: `docs: OWASP ASVS security audit checklist and findings`

### T13.2 — GDPR Compliance Features
Implement user data export (`GET /api/v1/users/:id/export`), account deletion (right to be forgotten), consent tracking. Document GDPR compliance measures.

**Commit**: `feat: GDPR compliance features (data export, deletion, consent)`

### T13.3 — Performance Testing & Optimization
Set up load testing (e.g., using `k6` or `criterion` benchmarks). Profile and optimize critical paths (auth, authz checks). Document results in `claude_dev/performance-report.md`.

**Commit**: `perf: load testing setup and critical path optimization`

### T13.4 — Comprehensive Documentation
Write API documentation (REST, gRPC, AMQP), deployment guide, admin guide, SDK getting-started guides. Consolidate in `docs/` directory.

**Commit**: `docs: comprehensive API, deployment, and admin documentation`

---

## Summary

| Phase | Tasks | Focus |
|-------|-------|-------|
| Phase 0 | 3 | Project foundation, CI, dev environment |
| Phase 1 | 6 | Core domain types and DB repositories |
| Phase 2 | 4 | Authentication (password, JWT, MFA, brute-force) |
| Phase 3 | 3 | Authorization engine |
| Phase 4 | 6 | REST API |
| Phase 5 | 2 | gRPC API |
| Phase 6 | 3 | AMQP integration |
| Phase 7 | 2 | Audit logging |
| Phase 8 | 3 | OAuth2 & OIDC |
| Phase 9 | 2 | Federation (OIDC + SAML) |
| Phase 10 | 4 | Admin frontend |
| Phase 11 | 3 | Docker, K8s, CD pipeline |
| Phase 12 | 3 | SDKs (Rust, TypeScript, Python) |
| Phase 13 | 4 | Security, compliance, performance, docs |

**Total: 48 tasks across 14 phases**

Each task is designed to be a self-contained unit of work with a clear deliverable and a signed commit, fitting within a single Claude Code session.
