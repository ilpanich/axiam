# AXIAM — Development Roadmap

Each task is sized to be completable in a single Claude Code session (Opus 4.6, medium effort). Each task ends with a signed commit. Tasks within a phase are sequential; phases build on previous ones.

---

## Phase 0: Project Foundation

### T0.1 — Cargo Workspace Scaffolding
Create the Cargo workspace with all planned crates (`axiam-core`, `axiam-db`, `axiam-auth`, `axiam-authz`, `axiam-api-rest`, `axiam-api-grpc`, `axiam-amqp`, `axiam-oauth2`, `axiam-federation`, `axiam-audit`, `axiam-pki`, `axiam-server`). Each crate gets a minimal `lib.rs` or `main.rs`. Add workspace-level dependencies in `Cargo.toml`.

**Commit**: `feat: scaffold Cargo workspace with all crates`

### T0.2 — CI Pipeline (GitHub Actions)
Set up GitHub Actions workflows: `ci.yml` (build + test + clippy + fmt check on every push/PR), `release.yml` (placeholder for Docker build). Add `.rustfmt.toml` and `clippy.toml` with project conventions.

**Commit**: `ci: add GitHub Actions build/test/lint pipeline`

### T0.3 — Dev Environment (Docker Compose)
Create `docker/docker-compose.dev.yml` with SurrealDB and RabbitMQ services. Add a `justfile` with common dev commands (`dev-up`, `dev-down`, `build`, `test`, `lint`).

**Commit**: `chore: add Docker Compose dev environment and justfile`

### T0.4 — Design Document & Roadmap Review
Review and update design document and roadmap to incorporate multi-tenancy (Tenant/Organization), certificate/PKI management, GnuPG integration, IoT device authentication, and webhooks from INSTRUCTION.md. Fix CI SurrealDB container issue.

**Commit**: `docs: update design document and roadmap with multi-tenancy, PKI, GnuPG, webhooks`

---

## Phase 1: Core Domain & Database

### T1.1 — Core Domain Types (`axiam-core`)
Define core domain types: `Organization`, `Tenant`, `User`, `Group`, `Role`, `Permission`, `Resource`, `Scope`, `ServiceAccount`, `Session`, `AuditLogEntry`, `OAuth2Client`, `FederationConfig`, `Certificate`, `CaCertificate`, `Webhook`. All tenant-scoped types include a `tenant_id` field. Define error types (`AxiamError`). Define repository traits (`UserRepository`, `GroupRepository`, `RoleRepository`, `OrganizationRepository`, `TenantRepository`, `CertificateRepository`, `WebhookRepository`, etc.).

**Commit**: `feat(core): define domain types, error types, and repository traits`

### T1.2 — SurrealDB Connection & Migrations (`axiam-db`)
Implement SurrealDB connection pool/manager. Create schema initialization (table definitions, indexes, graph edge definitions) including `organization`, `tenant`, `group`, `ca_certificate`, `certificate`, and `webhook` tables plus `member_of` edge. Write a migration runner that applies schema on startup. Add integration test with in-memory SurrealDB.

**Commit**: `feat(db): SurrealDB connection manager and schema initialization`

### T1.3 — Organization & Tenant Repositories
Implement `OrganizationRepository` (CRUD, slug-based lookup) and `TenantRepository` (CRUD scoped to organization, slug-based lookup, `has_tenant` edge). All subsequent repository operations will require tenant context. Add tests.

**Commit**: `feat(db): implement Organization and Tenant repositories`

### T1.4 — User Repository Implementation
Implement `UserRepository` trait for SurrealDB: create, get by ID, get by username/email, update, delete (soft-delete), list with pagination. All operations scoped to tenant. Include password hash storage. Add unit/integration tests.

**Commit**: `feat(db): implement User repository with CRUD operations`

### T1.5 — Group Repository Implementation
Implement `GroupRepository` for SurrealDB: CRUD operations, user-group membership via `member_of` edge (add/remove members, list members, list user groups). All tenant-scoped. Add tests.

**Commit**: `feat(db): implement Group repository with membership management`

### T1.6 — Role & Permission Repository Implementation
Implement `RoleRepository` and `PermissionRepository` for SurrealDB: CRUD operations, role-permission assignment (`grants` edge), role assignment to users/groups/service accounts via `has_role` edge, global vs resource-scoped roles. All tenant-scoped. Add tests.

**Commit**: `feat(db): implement Role and Permission repositories`

### T1.7 — Resource & Scope Repository Implementation
Implement `ResourceRepository` for SurrealDB: CRUD with hierarchical parent-child relationships (`child_of` edge), tree traversal queries. Implement `ScopeRepository`. All tenant-scoped. Add tests.

**Commit**: `feat(db): implement Resource hierarchy and Scope repositories`

### T1.8 — Service Account & Session Repositories
Implement `ServiceAccountRepository` (CRUD, client credential management) and `SessionRepository` (create, validate, invalidate, cleanup expired). All tenant-scoped. Add tests.

**Commit**: `feat(db): implement ServiceAccount and Session repositories`

---

## Phase 2: Authentication

### T2.1 — Password Authentication (`axiam-auth`)
Implement password hashing (Argon2id) and verification. Implement login flow: credential validation, session creation, JWT (EdDSA/Ed25519) access token + opaque refresh token generation. JWT claims include `tenant_id` and `org_id`. Add configuration for password policy (min length, complexity). Add unit tests.

**Commit**: `feat(auth): password authentication with Argon2id and JWT issuance`

### T2.2 — JWT Validation & Token Refresh
Implement JWT validation middleware (signature verification, expiry check, claims extraction including tenant context). Implement refresh token rotation endpoint. Handle token revocation (blacklist via session invalidation). Add tests.

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
Implement the core authorization check: given (subject, action, resource), resolve roles (direct + via group membership), collect permissions, evaluate against resource hierarchy with inheritance. Default-deny policy. All evaluations scoped to tenant. Add unit tests with various hierarchy scenarios.

**Commit**: `feat(authz): permission evaluation engine with hierarchy inheritance`

### T3.2 — Scope-Based Authorization
Extend the engine to support scope-level checks. Implement scope validation within permission grants. Add tests for scope-based access control.

**Commit**: `feat(authz): scope-based fine-grained authorization`

### T3.3 — Authorization Middleware
Create Actix-Web middleware/extractor that runs authorization checks on incoming requests. Extract tenant context from JWT claims or request path. Support attribute-based annotations (e.g., required permission and resource extracted from path). Add integration tests.

**Commit**: `feat(authz): HTTP authorization middleware for Actix-Web`

---

## Phase 4: REST API

### T4.1 — REST API Server Bootstrap (`axiam-api-rest`)
Set up Actix-Web server with configuration loading, middleware pipeline (CORS, logging, error handling, tenant context extraction), health/readiness endpoints. Wire up to `axiam-server` binary. Add basic integration test.

**Commit**: `feat(api-rest): Actix-Web server bootstrap with health endpoints`

### T4.2 — Organization & Tenant Endpoints (REST)
Implement `GET/POST/PUT/DELETE /api/v1/organizations` and `GET/POST/PUT/DELETE /api/v1/organizations/:org_id/tenants`. Super-admin access control. Add integration tests.

**Commit**: `feat(api-rest): organization and tenant management endpoints`

### T4.3 — Auth Endpoints (REST)
Implement `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `POST /auth/mfa/enroll`, `POST /auth/mfa/verify`. Wire to auth service. Add integration tests.

**Commit**: `feat(api-rest): authentication endpoints`

### T4.4 — User Management Endpoints (REST)
Implement `GET/POST/PUT/DELETE /api/v1/users` with pagination, filtering, input validation. Protected by authorization middleware. Tenant-scoped. Add integration tests.

**Commit**: `feat(api-rest): user management CRUD endpoints`

### T4.5 — Group Management Endpoints (REST)
Implement `GET/POST/PUT/DELETE /api/v1/groups` and `POST/DELETE /api/v1/groups/:id/members` for group membership management. Protected by authorization middleware. Tenant-scoped. Add integration tests.

**Commit**: `feat(api-rest): group management and membership endpoints`

### T4.6 — Role & Permission Endpoints (REST)
Implement CRUD for roles, permissions, and role-permission assignments. Implement role assignment to users and groups (`has_role` edge management). Add tests.

**Commit**: `feat(api-rest): role and permission management endpoints`

### T4.7 — Resource & Service Account Endpoints (REST)
Implement CRUD for resources (including hierarchy), scopes, and service accounts. Add tests.

**Commit**: `feat(api-rest): resource, scope, and service account endpoints`

### T4.8 — OpenAPI Documentation
Add `utoipa` annotations to all REST endpoints. Generate and serve OpenAPI spec at `/api/docs`. Add Swagger UI integration. Verify spec completeness.

**Commit**: `feat(api-rest): OpenAPI documentation with Swagger UI`

---

## Phase 5: gRPC API

### T5.1 — Proto Definitions & gRPC Server Bootstrap
Define `.proto` files for `AuthorizationService`, `UserService`, `TokenService`. Set up Tonic server alongside Actix-Web in `axiam-server`. Add build script for proto compilation.

**Commit**: `feat(api-grpc): proto definitions and Tonic server bootstrap`

### T5.2 — gRPC Service Implementations
Implement `CheckAccess`, `BatchCheckAccess`, `GetUser`, `ValidateCredentials`, `ValidateToken`, `IntrospectToken`. All calls include tenant context. Wire to existing services. Add integration tests.

**Commit**: `feat(api-grpc): implement authorization, user, and token gRPC services`

---

## Phase 6: AMQP Integration

### T6.1 — AMQP Connection & Queue Setup (`axiam-amqp`)
Implement RabbitMQ connection management using Lapin. Declare queues (`authz.request`, `authz.response`, `audit.events`, `notifications`). Add reconnection logic.

**Commit**: `feat(amqp): RabbitMQ connection manager and queue declarations`

### T6.2 — Async Authorization via AMQP
Implement consumer for `authz.request` queue: deserialize request (including tenant context), run authorization engine, publish result to `authz.response`. Add integration test with RabbitMQ.

**Commit**: `feat(amqp): async authorization request/response via AMQP`

### T6.3 — Audit Event Ingestion & Notifications
Implement consumer for `audit.events` queue (external audit events). Implement publisher for `notifications` queue (role changes, user events). Add tests.

**Commit**: `feat(amqp): audit event ingestion and notification publishing`

---

## Phase 7: Audit Logging

### T7.1 — Audit Service (`axiam-audit`)
Implement audit logging service: structured log entries for authentication, authorization, CRUD operations, admin actions. Ensure append-only semantics. Tenant-scoped. Add middleware that automatically logs API requests. Add tests.

**Commit**: `feat(audit): audit logging service with append-only storage`

### T7.2 — Audit Query API
Implement `GET /api/v1/audit-logs` with filtering (by actor, action, resource, date range), pagination, and sorting. Admin-only access, tenant-scoped. Add tests.

**Commit**: `feat(audit): audit log query API with filtering and pagination`

---

## Phase 8: Certificate Management & PKI

### T8.1 — CA Certificate Management (`axiam-pki`)
Implement CA certificate generation (RSA-4096 / Ed25519), upload, listing, and revocation at the organization level. Private key encryption with AES-256-GCM for signing CAs. Implement `CaCertificateRepository`. Add REST endpoints (`/api/v1/organizations/:org_id/ca-certificates`). Add tests.

**Commit**: `feat(pki): CA certificate management at organization level`

### T8.2 — Tenant Certificate Lifecycle
Implement certificate generation signed by organization CA, certificate upload, revocation, and rotation at the tenant level. Private key returned once on generation, never stored. Implement `CertificateRepository`. Add REST endpoints (`/api/v1/certificates`). Implement `signed_by` graph edge. Add tests.

**Commit**: `feat(pki): tenant certificate lifecycle with CA signing`

### T8.3 — IoT Device Certificate Authentication
Implement mTLS support for device authentication. Allow binding device certificates to service accounts for RBAC. Certificate validation against tenant CA chain. Add tests.

**Commit**: `feat(pki): IoT device certificate authentication via mTLS`

### T8.4 — GnuPG Key Management
Implement OpenPGP keypair generation, public key storage, key revocation. Integrate with audit logging for batch signing of audit entries. Support PGP-encrypted data exports. Add tests.

**Commit**: `feat(pki): GnuPG/OpenPGP key management and audit signing`

---

## Phase 9: Webhook System

### T9.1 — Webhook Registration & Delivery
Implement webhook endpoint CRUD (`/api/v1/webhooks`): URL, subscribed event types, HMAC-SHA256 shared secret, enable/disable. Implement async webhook delivery with HTTPS POST, signature headers, and exponential backoff retry. Delivery status logged in audit trail. Add tests.

**Commit**: `feat(webhooks): webhook registration and event delivery system`

---

## Phase 10: OAuth2 & OpenID Connect

### T10.1 — OAuth2 Authorization Server (`axiam-oauth2`)
Implement OAuth2 client registration (CRUD for `OAuth2Client`, tenant-scoped). Implement Authorization Code Grant flow: `/oauth2/authorize` (consent screen), `/oauth2/token` (code exchange). Add PKCE support. Add tests.

**Commit**: `feat(oauth2): authorization server with Authorization Code + PKCE`

### T10.2 — Additional OAuth2 Grant Types
Implement Client Credentials Grant (for service accounts) and Refresh Token Grant. Implement `/oauth2/revoke` and `/oauth2/introspect`. Add tests.

**Commit**: `feat(oauth2): client credentials, refresh, revocation, and introspection`

### T10.3 — OpenID Connect Provider
Implement OIDC discovery (`/.well-known/openid-configuration`), ID token issuance with standard claims (including tenant context), `/oauth2/userinfo`, `/oauth2/jwks`. Add tests.

**Commit**: `feat(oauth2): OpenID Connect provider with discovery and userinfo`

---

## Phase 11: Federation

### T11.1 — OIDC Federation (`axiam-federation`)
Implement external OIDC IdP integration (including social login providers): configuration management, authorization redirect, callback handling, user provisioning/linking from external IdP claims. Tenant-scoped. Add tests.

**Commit**: `feat(federation): external OIDC identity provider integration`

### T11.2 — SAML Service Provider
Implement SAML SP: metadata generation, AuthnRequest creation, SAML Response parsing/validation, assertion extraction, user provisioning/linking. Tenant-scoped. Add tests.

**Commit**: `feat(federation): SAML service provider integration`

---

## Phase 12: Admin Frontend

### T12.1 — React Project Scaffold
Initialize React project (`frontend/`) with TypeScript, Vite, React Router, and a component library (e.g., Mantine or Ant Design). Set up API client (axios/fetch with auth interceptors). Add login page with tenant selection.

**Commit**: `feat(frontend): React project scaffold with login page`

### T12.2 — Organization & Tenant Management UI
Implement organization list/detail pages, tenant list/creation/edit within organizations. CA certificate upload/generation UI.

**Commit**: `feat(frontend): organization and tenant management pages`

### T12.3 — User & Group Management UI
Implement user list (paginated, searchable), user detail/edit page, user creation form, role assignment UI. Implement group list, group detail with member management. Connect to REST API.

**Commit**: `feat(frontend): user and group management pages`

### T12.4 — Role & Permission Management UI
Implement role list, role editor (permission assignment), permission list. Implement resource hierarchy viewer/editor. Support role assignment to both users and groups.

**Commit**: `feat(frontend): role, permission, and resource management pages`

### T12.5 — Certificate & Webhook Management UI
Implement certificate list, generation/upload forms, revocation. Webhook endpoint management with delivery status.

**Commit**: `feat(frontend): certificate and webhook management pages`

### T12.6 — Dashboard & Audit Viewer
Implement admin dashboard (user count, active sessions, recent activity, certificate expiry warnings). Implement audit log viewer with filters. Add OAuth2 client management page.

**Commit**: `feat(frontend): admin dashboard, audit viewer, and OAuth2 client management`

---

## Phase 13: Deployment & Infrastructure

### T13.1 — Dockerfile & Multi-Stage Build
Create optimized multi-stage Dockerfile for the AXIAM server binary. Create Dockerfile for the frontend (nginx-based). Add `.dockerignore`. Test images locally.

**Commit**: `feat(docker): multi-stage Dockerfiles for server and frontend`

### T13.2 — Kubernetes Manifests
Create K8s manifests: Deployment, Service, Ingress, ConfigMap, Secrets for AXIAM server. StatefulSet for SurrealDB and RabbitMQ. HPA configuration. Readiness/liveness probes.

**Commit**: `feat(k8s): Kubernetes deployment manifests with HPA`

### T13.3 — CD Pipeline (GitHub Actions)
Extend GitHub Actions: build and push Docker images on tag, deploy to K8s (or push Helm chart). Add release workflow with CHANGELOG generation.

**Commit**: `ci: add CD pipeline for Docker build and release`

---

## Phase 14: SDKs (Starters)

### T14.1 — Rust SDK
Create `sdks/rust/` with a client library wrapping REST and gRPC APIs. Auth helper, token management, authorization check helper, tenant context. Add usage examples. Publish-ready with `Cargo.toml`.

**Commit**: `feat(sdk): Rust SDK with REST and gRPC client`

### T14.2 — TypeScript SDK
Create `sdks/typescript/` with a TypeScript/Node.js client library wrapping REST API. Auth flows, token refresh, tenant context, middleware helper for Express/Fastify. Add usage examples.

**Commit**: `feat(sdk): TypeScript SDK with REST client`

### T14.3 — Python SDK
Create `sdks/python/` with a Python client library wrapping REST API. Auth flows, token management, tenant context, FastAPI/Django middleware helper. Add usage examples.

**Commit**: `feat(sdk): Python SDK with REST client`

### T14.4 — Java SDK
Create `sdks/java/` with a Java client library wrapping REST API. Auth flows, token management, tenant context, Spring Security integration helper. Add usage examples.

**Commit**: `feat(sdk): Java SDK with REST client`

### T14.5 — C# SDK
Create `sdks/csharp/` with a C# client library wrapping REST API. Auth flows, token management, tenant context, ASP.NET Core middleware helper. Add usage examples.

**Commit**: `feat(sdk): C# SDK with REST client`

### T14.6 — PHP SDK
Create `sdks/php/` with a PHP client library wrapping REST API. Auth flows, token management, tenant context, Laravel/Symfony middleware helper. Add usage examples.

**Commit**: `feat(sdk): PHP SDK with REST client`

### T14.7 — Go SDK
Create `sdks/go/` with a Go client library wrapping REST and gRPC APIs. Auth flows, token management, tenant context, HTTP middleware helper. Add usage examples.

**Commit**: `feat(sdk): Go SDK with REST and gRPC client`

---

## Phase 15: Hardening & Compliance

### T15.1 — Security Audit Checklist
Create security audit checklist based on OWASP ASVS, ISO 27001, and CyberSecurity Act. Verify all authentication, session, access control, cryptography, and PKI requirements. Document findings and remediations in `claude_dev/security-audit.md`.

**Commit**: `docs: security audit checklist and findings (OWASP ASVS, ISO 27001)`

### T15.2 — GDPR Compliance Features
Implement user data export (`GET /api/v1/users/:id/export` with optional PGP encryption), account deletion (right to be forgotten), consent tracking. Document GDPR compliance measures.

**Commit**: `feat: GDPR compliance features (data export, deletion, consent)`

### T15.3 — Performance Testing & Optimization
Set up load testing (e.g., using `k6` or `criterion` benchmarks). Profile and optimize critical paths (auth, authz checks, certificate validation). Document results in `claude_dev/performance-report.md`.

**Commit**: `perf: load testing setup and critical path optimization`

### T15.4 — Comprehensive Documentation
Write API documentation (REST, gRPC, AMQP), deployment guide, admin guide, PKI/certificate guide, SDK getting-started guides. Consolidate in `docs/` directory.

**Commit**: `docs: comprehensive API, deployment, and admin documentation`

---

## Summary

| Phase | Tasks | Focus |
|-------|-------|-------|
| Phase 0 | 4 | Project foundation, CI, dev environment, design review |
| Phase 1 | 8 | Core domain types (with multi-tenancy, groups) and DB repositories |
| Phase 2 | 4 | Authentication (password, JWT, MFA, brute-force) |
| Phase 3 | 3 | Authorization engine (with group role inheritance) |
| Phase 4 | 8 | REST API (including org/tenant/group endpoints) |
| Phase 5 | 2 | gRPC API |
| Phase 6 | 3 | AMQP integration |
| Phase 7 | 2 | Audit logging |
| Phase 8 | 4 | Certificate management, PKI, IoT device auth, GnuPG |
| Phase 9 | 1 | Webhook system |
| Phase 10 | 3 | OAuth2 & OIDC |
| Phase 11 | 2 | Federation (OIDC + SAML) |
| Phase 12 | 6 | Admin frontend (with org/tenant/group/cert/webhook UI) |
| Phase 13 | 3 | Docker, K8s, CD pipeline |
| Phase 14 | 7 | SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) |
| Phase 15 | 4 | Security, compliance, performance, docs |

**Total: 64 tasks across 16 phases**

Each task is designed to be a self-contained unit of work with a clear deliverable and a signed commit, fitting within a single Claude Code session.
