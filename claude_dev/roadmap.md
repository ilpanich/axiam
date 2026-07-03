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
Implement `UserRepository` trait for SurrealDB: create, get by ID, get by username/email, update, delete (soft-delete), list with pagination. All operations scoped to tenant. Include password hash storage (according to OWASP guidelines, argon2id with salt and pepper must be used). Add unit/integration tests.

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

## Phase 12: Hierarchical Settings & Password Policy

### T12.1 — Org/Tenant Settings Model & Inheritance Engine
Define the `SecuritySettings` domain model with all configurable fields (password policy, MFA enforcement, email verification, certificate validity, notifications). Implement the inheritance engine: org settings are the baseline; tenant overrides are validated to be **more restrictive only** (higher minimums, enabled-only booleans, lower maximums). Add `settings` table to DB schema with migration v4. Implement `SettingsRepository` trait and SurrealDB implementation. Add unit tests for inheritance validation logic.

**Commit**: `feat(core): hierarchical org/tenant security settings with inheritance engine`

### T12.2 — Password Policy Engine
Implement password policy evaluation: minimum length, complexity rules (uppercase, lowercase, digits, symbols), password history check (reject reuse of last N passwords), and optional Have I Been Pwned (HIBP) breach detection via k-Anonymity API (only 5-char SHA-1 prefix sent). Add `password_history` table to DB schema. Policy is resolved from effective settings (org + tenant override). Not applicable for federated/social login users. Add unit tests.

**Commit**: `feat(auth): password policy engine with complexity rules and HIBP breach check`

### T12.3 — Settings REST API
Implement `GET/PUT /api/v1/organizations/:org_id/settings` (org-level) and `GET/PUT /api/v1/settings` (tenant-level, from JWT context). PUT validates inheritance constraints (tenant can only be more restrictive). Add OpenAPI annotations. Add integration tests.

**Commit**: `feat(api-rest): org/tenant security settings endpoints`

---

## Phase 13: Email Service & Account Flows

### T13.1 — Email Service Abstraction
Implement a pluggable email service with provider trait (`EmailProvider`): SMTP/TLS (via `lettre`), SendGrid, Postmark, Resend, Brevo (via `reqwest` REST calls if specific and maintained crates are not available). Provider is configured at org level; tenants can override. Add email configuration section. Add unit tests with mock provider.

**Commit**: `feat(email): pluggable email service with SMTP and REST provider support`

### T13.2 — Email Templates Engine
Implement an email template engine with standard placeholders (`{{username}}`, `{{email}}`, `{{tenant_name}}`, `{{org_name}}`, `{{action_url}}`, `{{expiry_time}}`). Default templates for: activation, password reset, MFA setup reminder, admin notification. Templates customizable at org/tenant level and stored in DB. HTML + plaintext variants. Add tests.

**Commit**: `feat(email): customizable email templates with org/tenant overrides`

### T13.3 — Mail Verification Flow
Implement email verification: on user creation (when enforced), send activation email with confirmation token (24h expiry). Grace period allows login for 24h. After grace period, account is locked until confirmed. Locked users can request new confirmation email (max 2/day). Add `email_verification_token` table, `POST /auth/verify-email`, `POST /auth/resend-verification` endpoints. Not applicable for federated/social login. Add integration tests.

**Commit**: `feat(auth): email verification flow with grace period and resend limits`

### T13.4 — Password Reset Flow
Implement email-based password reset: `POST /auth/reset` generates a time-limited token and sends reset email. `POST /auth/reset/confirm` validates token, applies password policy on new password, resets fail2ban counter (allowing immediate login). Not applicable for federated/social login. Add integration tests.

**Commit**: `feat(auth): email-based password reset with fail2ban counter reset`

### T13.5 — Admin Notification Service
Implement admin notification subscriptions: org/tenant admins configure rules for critical events (security incidents, privilege changes, certificate expiry, user lifecycle events). Notifications are delivered via the email service. Add `notification_rule` table, `GET/POST/PUT/DELETE /api/v1/notification-rules` endpoints. Wire into audit event pipeline. Add integration tests.

**Commit**: `feat(notifications): admin email notifications for critical events`

---

## Phase 14: Advanced MFA

### T14.1 — MFA Enforcement & First-Login Flow
Implement org/tenant-level MFA enforcement via settings. When enforced: on first login, redirect user to MFA setup (choose TOTP, passkey, or hardware key). User cannot access any resource until MFA is configured. On setup failure, only org/tenant admins can reset MFA state (via `POST /api/v1/users/:id/reset-mfa`), allowing the user to retry. Not applicable for federated/social login. Add integration tests.

**Commit**: `feat(auth): MFA enforcement with first-login setup and admin unlock`

### T14.2 — WebAuthn / FIDO2 Support
Implement WebAuthn registration and authentication using `webauthn-rs`. Support passkeys (1Password, Bitwarden, Android, iCloud Keychain) and hardware security keys (YubiKey, NitroKey). Add `webauthn_credential` table to DB schema. Implement `POST /auth/webauthn/register/start`, `POST /auth/webauthn/register/finish`, `POST /auth/webauthn/authenticate/start`, `POST /auth/webauthn/authenticate/finish` endpoints. Add integration tests.

**Commit**: `feat(auth): WebAuthn/FIDO2 support for passkeys and hardware security keys`

### T14.3 — Multi-MFA Method Management
Allow users to register multiple MFA methods (TOTP + passkey + hardware key). Any registered method can be used for login verification. Add `GET /api/v1/users/:id/mfa-methods` (list methods, no secrets), `DELETE /api/v1/users/:id/mfa-methods/:method_id` (remove a method). Update login flow to present available method options. Add integration tests.

**Commit**: `feat(auth): multi-MFA method registration and management`

---

## Phase 15: Admin Frontend

### T15.1 — React Project Scaffold
Initialize React project (`frontend/`) with TypeScript, Vite, React Router, and a component library (e.g., Mantine or Ant Design). Set up API client (axios/fetch with auth interceptors). Add login page with tenant selection. **Design must be fully responsive** for mobile and desktop usage.

**Commit**: `feat(frontend): React project scaffold with responsive login page`

### T15.2 — Organization & Tenant Management UI
Implement organization list/detail pages, tenant list/creation/edit within organizations. CA certificate upload/generation UI. Organization and tenant security settings management UI.

**Commit**: `feat(frontend): organization and tenant management pages`

### T15.3 — User & Group Management UI
Implement user list (paginated, searchable), user detail/edit page, user creation form, role assignment UI. Implement group list, group detail with member management. MFA method viewer for admins. Connect to REST API.

**Commit**: `feat(frontend): user and group management pages`

### T15.4 — Role & Permission Management UI
Implement role list, role editor (permission assignment), permission list. Implement resource hierarchy viewer/editor. Support role assignment to both users and groups.

**Commit**: `feat(frontend): role, permission, and resource management pages`

### T15.5 — Certificate & Webhook Management UI
Implement certificate list, generation/upload forms, revocation. Webhook endpoint management with delivery status. PGP key management UI.

**Commit**: `feat(frontend): certificate and webhook management pages`

### T15.6 — Dashboard & Audit Viewer
Implement admin dashboard (user count, active sessions, recent activity, certificate expiry warnings). Implement audit log viewer with filters. Add OAuth2 client management page. Admin notification rules management.

**Commit**: `feat(frontend): admin dashboard, audit viewer, and OAuth2 client management`

### T15.7 — User Identity Pages
Implement user-facing identity management pages: change password (with policy feedback), manage MFA methods (add/remove TOTP, passkeys, hardware keys), view profile, email verification status. These pages are accessible to social/federated login users in read-only mode. Add password reset page (public, no auth required).

**Commit**: `feat(frontend): user identity management and password reset pages`

---

## Phase 16: Deployment & Infrastructure

### T16.1 — Dockerfile & Multi-Stage Build
Create optimized multi-stage Dockerfile for the AXIAM server binary. Create Dockerfile for the frontend (nginx-based). Add `.dockerignore`. Test images locally.

**Commit**: `feat(docker): multi-stage Dockerfiles for server and frontend`

### T16.2 — Kubernetes Manifests
Create K8s manifests: Deployment, Service, Ingress, ConfigMap, Secrets for AXIAM server. StatefulSet for SurrealDB and RabbitMQ. HPA configuration. Readiness/liveness probes.

**Commit**: `feat(k8s): Kubernetes deployment manifests with HPA`

### T16.3 — CD Pipeline (GitHub Actions)
Extend GitHub Actions: build, sign (using ([sigstore](https://www.sigstore.dev/)) and push Docker images on tag, deploy to K8s (or push Helm chart). Add release workflow with CHANGELOG generation. Produce github attestation of the generated binary.

**Commit**: `ci: add CD pipeline for Docker build and release`

---

## Phase 17: SDKs (Starters)

### T17.1 — Rust SDK
Create `sdks/rust/` with a client library wrapping REST,AMQP and gRPC APIs. Auth helper, token management, authorization check helper, tenant context. Add usage examples. Publish-ready with `Cargo.toml`.

**Commit**: `feat(sdk): Rust SDK with REST and gRPC client`

### T17.2 — TypeScript SDK
Create `sdks/typescript/` with a TypeScript/Node.js client library wrapping REST API. Auth flows, token refresh, tenant context, middleware helper for Express/Fastify. Add usage examples.

**Commit**: `feat(sdk): TypeScript SDK with REST client`

### T17.3 — Python SDK
Create `sdks/python/` with a Python client library wrapping REST API,AMQP and gRPC. Auth flows, token management, tenant context, FastAPI/Django middleware helper. Add usage examples.

**Commit**: `feat(sdk): Python SDK with REST client`

### T17.4 — Java SDK
Create `sdks/java/` with a Java client library wrapping REST API, AMQP and gRPC. Auth flows, token management, tenant context, Spring Security integration helper. Add usage examples.

**Commit**: `feat(sdk): Java SDK with REST client`

### T17.5 — C# SDK
Create `sdks/csharp/` with a C# client library wrapping REST API, AMQP and gRPC. Auth flows, token management, tenant context, ASP.NET Core middleware helper. Add usage examples.

**Commit**: `feat(sdk): C# SDK with REST client`

### T17.6 — PHP SDK
Create `sdks/php/` with a PHP client library wrapping REST API. Auth flows, token management, tenant context, Laravel/Symfony middleware helper. Add usage examples.

**Commit**: `feat(sdk): PHP SDK with REST client`

### T17.7 — Go SDK
Create `sdks/go/` with a Go client library wrapping REST, AMQP and gRPC APIs. Auth flows, token management, tenant context, HTTP middleware helper. Add usage examples.

**Commit**: `feat(sdk): Go SDK with REST and gRPC client`

---

## Phase 18: Hardening & Compliance

### T18.1 — Security Audit Checklist
Create security audit checklist based on OWASP ASVS, ISO 27001, and CyberSecurity Act. Verify all authentication, session, access control, cryptography, and PKI requirements. Document findings and remediations in `claude_dev/security-audit.md`.

**Commit**: `docs: security audit checklist and findings (OWASP ASVS, ISO 27001)`

### T18.2 — GDPR Compliance Features
Implement user data export (`GET /api/v1/users/:id/export` with optional PGP encryption), account deletion (right to be forgotten), consent tracking. Document GDPR compliance measures.

**Commit**: `feat: GDPR compliance features (data export, deletion, consent)`

### T18.3 — Performance Testing & Optimization
Set up load testing (e.g., using `k6` or `criterion` benchmarks). Profile and optimize critical paths (auth, authz checks, certificate validation). Document results in `claude_dev/performance-report.md`.

**Commit**: `perf: load testing setup and critical path optimization`

### T18.4 — Comprehensive Documentation
Write API documentation (REST, gRPC, AMQP), deployment guide, admin guide, PKI/certificate guide, SDK getting-started guides. Consolidate in `docs/` directory.

**Commit**: `docs: comprehensive API, deployment, and admin documentation`

---

## Phase 19: Deferred Improvements & Optimizations

Items identified during development and PR reviews (PRs #70, #71) that were intentionally deferred to keep each phase focused.

### T19.1 — gRPC Integration Tests
Add integration tests for `axiam-api-grpc`: spin up a Tonic server with mock/in-memory repositories, use a generated gRPC client to test UUID parsing, error mapping, credential validation policy, token validation, and authorization checks. Ensure parity with existing REST integration tests.

**Commit**: `test(api-grpc): integration tests for gRPC services`

### T19.2 — Concurrent BatchCheckAccess
Refactor `BatchCheckAccess` to evaluate requests concurrently using `futures::stream::FuturesUnordered` or `buffer_unordered` with bounded concurrency. Preserve result order. Benchmark against sequential implementation to validate improvement.

**Commit**: `perf(api-grpc): concurrent batch authorization checks`

### T19.3 — REST Endpoint Authorization Enforcement
Wire the `RequirePermission` middleware and `AuthorizationEngine` to all REST CRUD endpoints (users, groups, roles, permissions, resources, scopes, service accounts, organizations, tenants). Define authorization policies and implement an admin bootstrap flow (initial super-admin creation). Currently only JWT authentication is enforced via `AuthenticatedUser`.

**Commit**: `feat(api-rest): enforce per-endpoint authorization on all CRUD routes`

### T19.4 — OpenAPI Login Response Schema
Fix the OpenAPI annotation for `POST /auth/login` to accurately document both `LoginSuccessResponse` and `MfaRequiredResponse` as possible 200 response bodies (using `oneOf` or separate status codes). Ensures generated client SDKs correctly model the login response.

**Commit**: `fix(api-rest): OpenAPI login response documents both success and MFA schemas`

### T19.5 — ValidateCredentials Brute-Force Side Effects
The gRPC `ValidateCredentials` RPC is intentionally side-effect-free (it checks lockout state but does not increment `failed_login_attempts` or set `locked_until` on failure). If this RPC is exposed to untrusted callers, add an option to record failed attempts — either by calling into `AuthService` failure-tracking logic or by factoring the lockout counter update into a shared helper used by both REST login and gRPC credential validation.

**Commit**: `feat(api-grpc): track failed login attempts in ValidateCredentials`

### T19.6 — OIDC ID Token JWKS Signature Verification
Implement JWT signature verification for OIDC federation ID tokens using the JWKS endpoint from the discovery document. Integrate `jsonwebtoken` with JWK fetching and caching. Fail closed by default — reject unverified tokens unless an explicit `insecure_federation` dev/test flag is enabled in configuration.

**Commit**: `feat(federation): JWKS-based JWT signature verification for OIDC ID tokens`

### T19.7 — SAML Response XML Signature Verification
Implement XML signature verification for SAML responses using the IdP's X.509 certificate from metadata. Fail closed by default — reject unsigned or unverified assertions unless an explicit `insecure_federation` dev/test flag is enabled. Also set `WantAssertionsSigned="true"` in SP metadata once verification is enforced.

**Commit**: `feat(federation): XML signature verification for SAML responses`

### T19.8 — Federation Client Secret Encryption at Rest
Encrypt `client_secret` in the `federation_config` table using AES-256-GCM before storage, mirroring the pattern used for MFA secrets and CA private keys. Decrypt only at runtime when performing token exchange. Apply consistently on both `create()` and `update()` paths.

**Commit**: `security(federation): encrypt client_secret at rest with AES-256-GCM`

### T19.9 — Unauthenticated Federation Login Endpoints
Add separate unauthenticated federation login endpoints (`/auth/federation/oidc/login`, `/auth/federation/saml/login`) that complete the external OIDC/SAML flow and return AXIAM access/refresh tokens — enabling first-time login via federation without requiring an existing local account. The current authenticated endpoints remain for account-linking (linking an external identity to an already-authenticated user).

**Commit**: `feat(federation): unauthenticated federation login endpoints for first-time SSO`

### T19.10 — Session Invalidation on Password Reset
After a successful password reset (`confirm_reset`), invalidate all active sessions for the user. Currently deferred because it would expand the `PasswordResetService` signature to include a `SessionRepository` dependency.

**Commit**: `security(auth): invalidate sessions on password reset`

### ~~T19.11 — Wire Email Sending for Password Reset and Verification~~ ✓ RESOLVED (Phase 05-04)
~~Connect the `EmailService` to the `/auth/reset` and `/auth/resend-verification` handlers so that reset/verification emails are actually delivered. Currently the handlers generate and store tokens but do not send emails (marked with `TODO(T19)` comments).~~

Resolved in Phase 05 Plan 04: handlers now enqueue `OutboundMailMessage(PasswordReset/EmailVerification)` to `axiam.mail.outbound`; responses are enumeration-safe (D-15). The `TODO(T19)` stubs in `password_reset.rs` and `email_verification.rs` are wired.

**Commit**: `feat(05-04): wire password-reset and email-verify handlers to enqueue mail (D-14/D-15)`

### ~~T19.12 — Wire NotificationDispatcher Email Delivery~~ ✓ RESOLVED (Phase 05-04)
~~Connect `NotificationDispatcher` to `EmailService` with template resolution and org_id lookup so that matched notification rules actually send emails. Currently the dispatcher returns matched rules/recipients but does not send (marked with `TODO(T19)` in `crates/axiam-audit/src/notification.rs`).~~

Resolved in Phase 05 Plan 04: `NotificationDispatcher::dispatch` now accepts a `&impl MailPublisher` and enqueues one `OutboundMailMessage(Notification)` per matched recipient. The `TODO(T19)` stub in `notification.rs` is wired.

**Commit**: `feat(05-04): notification dispatcher enqueues mail messages (T19.12/T19.13)`

### T19.20 — Admin Email-Config CRUD API
Add admin-facing REST endpoints to create/read/update/delete `email_config` rows (org- and tenant-scoped), guarded by an appropriate RBAC permission (e.g. `email_config:write`). Phase 5 builds the DB-backed `SurrealEmailConfigRepository` (encrypt-at-rest, all five providers) and resolves the effective provider per org/tenant, but provider rows are seeded/written via the repository only — there is no admin UI/API in Phase 5. This task exposes that configuration surface. Deferred from Phase 5 (see `.planning/phases/05-email-delivery-gdpr-compliance/05-CONTEXT.md` Claude's Discretion).

**Commit**: `feat(api-rest): admin email-config CRUD endpoints (org/tenant scoped)`

### T19.21 — Per-Org/Tenant Custom Template Lookup in Mail Consumer
The mail consumer (`axiam-amqp/src/mail_consumer.rs`) currently uses the built-in default template only (`resolve_template(kind, None, None)`). Wire the `SurrealEmailTemplateRepository` to fetch per-org and per-tenant custom templates and pass them to `resolve_template`, so custom templates are applied at delivery time.

**Commit**: `feat(amqp): wire custom template resolution in mail consumer`

### T19.22 — Email Config Secrets Backfill UPDATE Path
`SurrealEmailConfigRepository::backfill_plaintext_secrets` counts unencrypted rows but does not yet UPDATE them (returns the pending count and logs a warning). Implement the UPDATE path: for each row where `smtp_password_ciphertext IS NULL AND smtp_password IS NOT NULL` (or API-key equivalent), encrypt via `encrypt_field` and UPDATE the row. This path is needed only if pre-Phase-5 tooling wrote plaintext rows before schema v15 was deployed.

**Commit**: `feat(db): implement email config secrets backfill UPDATE path (T19.22)`

---

### Items deferred from PR #126 review (SDKs — phases 15–22)

Findings from the Gemini review and CI triage on PR #126 that are **out of scope for the SDK PR** (they touch already-merged backend code, or are cross-cutting hardening best done as a focused pass). In-scope PR items (rustfmt, Python 3.10 `datetime.UTC`, mypy-strict config, D-04 Python stub drift, Rust-SDK protoc, CSRF header origin-gating in the Python SDK) were fixed directly in the PR.

**Follow-up review rounds (PR #126, two further Gemini passes + CI triage) resolved several of these in-PR** — see the ✓ RESOLVED entries below: cross-SDK header origin-gating (T19.29), Security-Scan remediation (cargo-audit + Trivy, T19.31), and GitHub Actions SHA-pinning (T19.32). Least-privilege workflow permissions (Gemini R2 §1.B) were verified already-clean (every SDK workflow declares top-level `permissions: contents: read`, with `id-token: write` scoped to publish jobs only) — no change needed. The remaining backend items (T19.23–T19.28, T19.33–T19.34) stay deferred.

### T19.23 — Password-reset timing side-channel (user enumeration)
`crates/axiam-auth/src/password_reset.rs::initiate_reset` returns early for unknown/federated users, so response time distinguishes valid from invalid emails. Add a constant-time fallback: perform a dummy Argon2/hash + equivalent async DB wait on the ineligible path so overall duration matches a real token generation. (Gemini review §1.A.)

**Commit**: `security(auth): constant-time password-reset to close user-enumeration side-channel`

### T19.24 — Zeroize peppered-password buffer
`crates/axiam-auth/src/password.rs::hash_password` builds `format!("{p}{password}")`, leaving plaintext password + secret pepper in heap memory until reallocated. Wrap the peppered buffer with `zeroize` (and consider `secrecy` for the pepper) so it is wiped before the function returns. (Gemini review §1.B.)

**Commit**: `security(auth): zeroize peppered-password buffer after hashing`

### T19.25 — Public-path prefix-match hardening
`crates/axiam-api-rest/src/middleware/authz.rs` matches public paths with a wildcard prefix, so an entry like `/api/v1/auth*` would also match `/api/v1/authz/...`. Require a path-segment boundary (trailing slash before the wildcard, e.g. `/api/v1/auth/*`) to prevent accidental namespace exposure. (Gemini review §1.D; R2 §3.A.) A second review pass added: also normalize the path **before** the exclusion check — collapse double slashes (`//`) and reject/resolve `..` traversal segments — so a crafted route can't slip past the allowlist via a non-canonical form. (Current state: `is_public_path` already exact-matches by default and only prefix-matches explicit `*` entries; the segment-boundary + normalization hardening is the deferred delta.)

**Commit**: `fix(api-rest): require segment boundary in public-path wildcard matching`

### T19.26 — HIBP circuit breaker + micro-opt
`crates/axiam-auth/src/policy.rs::check_hibp` makes a 5s-timeout network call to the Pwned Passwords API; under a credential-stuffing burst thousands of tasks could block, starving legitimate flows. Wrap the call in a circuit breaker that trips on repeated failure/timeout and fails open (`Ok(None)`) for a cooldown window. Also pre-size `check_complexity`'s `violations` vec with `Vec::with_capacity(5)`. (Gemini review §2.A, §2.C.) Both follow-up passes reiterated the pre-allocation point and broadened it (R1 §2.C, R2 §3.B) to any hot-path collection that gathers rule violations / path segments in the authorization middleware, and to SDK serialization paths building multi-tenant object maps / long list contracts — pre-size with `Vec::with_capacity(n)` to avoid heap reallocation churn under load.

**Commit**: `perf(auth): circuit-breaker HIBP checks and pre-size complexity violations`

### T19.27 — GDPR audit durability (DLQ fallback)
`crates/axiam-api-rest/src/handlers/gdpr.rs::append_gdpr_audit` is fire-and-forget; if the SurrealDB insert fails, the legally-significant Art. 15/17 event is only in a tracing log. On DB-insert failure, fall back to a persistent local dead-letter file / dedicated audit syslog for 100% durability. (Gemini review §3.A.)

**Commit**: `feat(api-rest): dead-letter fallback for GDPR audit-write failures`

### T19.28 — JWKS single-flight across SDKs
Under a burst of invalid-`kid` tokens with an empty cache, per-SDK JWKS clients may each fetch concurrently (e.g. Python `PyJWKClient` does not coalesce), causing a fetch storm to the JWKS endpoint. Wrap the fetch in a single-flight promise/future so N concurrent misses await one network request. Apply consistently across Python, Go, Rust, Java, C#, TypeScript. (Gemini review §2.B; the once/60s forced-refetch rate-limit already caps *invalidation* but not the initial cache-fill.)

**Commit**: `perf(sdks): single-flight JWKS fetch to prevent cache-stampede`

### T19.29 — CSRF/tenant header origin-gating across all SDKs ✓ RESOLVED (PR #126)
The Python SDK already withheld `X-Tenant-ID`/`X-CSRF-Token` from cross-origin requests. **Resolved in a follow-up review round (Gemini R1 §3.A):** the same host-isolation guard was extended to the remaining six SDKs so the tenant id, CSRF token, and (where applicable) bearer token are attached only to same-origin requests — an absolute third-party URL or a followed cross-host redirect gets nothing. Per-SDK implementation:
- **Go** — host guard in `decorateRequest` **plus** a `CheckRedirect` that strips the headers on any cross-host redirect hop (net/http otherwise forwards custom headers across hosts). +2 tests.
- **TypeScript** — `SharedSession.isForeignHost()` gates the tenant + CSRF request interceptors. +test.
- **Java** — `SessionState.isBaseHost()` gates tenant/bearer/CSRF in the OkHttp interceptor. +test.
- **C#** — `IsForeignHost()` short-circuits `ApplyHeaders` in the message handler.
- **PHP** — base-host check in the Guzzle `AuthMiddleware`.
- **Rust** — reqwest redirect policy refuses cross-host redirects (capped at 10, matching the default).

**Commit**: `fix(sdks): host-isolation guard for tenant/CSRF/bearer headers (Gemini 3A)`

### T19.30 — Unify PHP/Python codegen under buf ✓ PARTIALLY RESOLVED (PR #126)
The buf workspace break was **fixed in PR #126** once buf became available locally: `buf.yaml`/`buf.gen.yaml` relocated to the repo root (`modules: [{path: proto}]`), managed mode added for Go's `go_package`, `php_namespace` made consistent across all three protos, Go stubs regenerated (authorization drift + new token/user), and all buf invocations moved to the repo root. `buf lint + breaking`, `buf drift-check (D-01)`, and TS codegen now pass (validated locally).

**Residual:** buf currently drives only Rust/TS/Go. Python (`grpc_tools`, D-04) and PHP (manual `protoc --php_out`, D-03) keep separate toolchains because buf's output layout/paths conflict with their committed stubs. Unify all six languages under a single buf pipeline (reconcile the PHP flat-vs-nested `Gen/` layout and the Python output path) so there is one source of truth for codegen.

**Commit**: `ci(sdks): unify PHP/Python gRPC codegen under the buf pipeline`

### T19.31 — Security Scan remediation (cargo-audit + Trivy) ✓ RESOLVED (PR #126)
The `Security Scan` job failed on advisories published **after** the last green `main` run (not introduced by PR #126). Both scanners were remediated in-PR:

**cargo-audit** (RUSTSEC, published 2026-06-29/30):
- `RUSTSEC-2026-0193` — `ammonia` 4.1.2 mXSS: **real fix**, bumped to `ammonia 4.1.3` via `cargo update` (also modernizes its parser stack, dropping the phf/futf/mac chain).
- `RUSTSEC-2026-0194` / `RUSTSEC-2026-0195` — `quick-xml` 0.37.5 two HIGH DoS: **unfixable transitively** (only fix is quick-xml ≥0.41, but the latest `samael` 0.0.21 still pins `quick-xml ^0.37.2`). Added both to `deny.toml` **and** the CI `cargo-audit` ignore list with justification (SAML/samael is opt-in and off by default; DoS-only; review date 2026-07-03), keeping the two ignore lists in sync.

**Trivy filesystem scan** (Go SDK, surfaced once cargo-audit passed and the job progressed): `golang.org/x/net v0.51.0` carried five HIGH CVEs (CVE-2026-25681/-27136/-33814/-39821/-42502). **Real fix**, bumped `golang.org/x/net` → `0.55.0` (pulling `x/sys 0.45.0`, `x/text 0.37.0`) via `go get` + `go mod tidy`; all Go SDK tests pass.

**Commits**: `fix(security): resolve cargo audit failures blocking PR #126` · `fix(security): bump golang.org/x/net to 0.55.0 in Go SDK (Trivy HIGH CVEs)`

### T19.32 — Pin third-party GitHub Actions to commit SHAs ✓ RESOLVED (PR #126)
The new SDK CI workflows referenced third-party actions by mutable tag rather than full commit SHA, while the repo's own `ci.yml` already pins to SHAs. **Resolved in a follow-up review round (Gemini R2 §1.A):** all 19 occurrences across the seven SDK workflows pinned to full commit SHAs (resolved via `git ls-remote`) with the concrete version in a trailing comment, matching the `ci.yml` convention:
- `actions/setup-python` `@v5` → `@a26af69…` (v5.6.0)
- `actions/setup-java` `@v4` → `@c1e3236…` (v4.8.0)
- `actions/setup-dotnet` `@v4` → `@67a3573…` (v4.3.1)
- `shivammathur/setup-php` `@v2` → `@f3e473d…` (v2.37.2, annotated-tag deref)
- `bufbuild/buf-action` `@v1.4.0` → `@fd21066…` (v1.4.0)

**Commit**: `ci(sdks): pin SDK workflow actions to commit SHAs (Gemini 1A)`

### T19.33 — SurrealDB reconnect exponential backoff + full jitter
The SurrealDB connection layer's reconnection path should defend against connection stampedes when a cluster recovers or re-elects a leader. Verify the disconnect-mitigation loop uses **exponential backoff with randomized full jitter** (not flat retry intervals), a `max_backoff` ceiling, and a bounded retry count that surfaces a critical error rather than spinning — so competing workers desynchronize instead of hammering the DB port and exhausting async executor threads. (Gemini review R1 §2.A, R2 §2.A. Pre-existing `axiam-db`; out of scope for the SDK PR.)

**Commit**: `perf(db): exponential-backoff-with-jitter reconnect for SurrealDB`

### T19.34 — Poisoned connection-pool purging
On a critical network-topology anomaly or an authentication-handshake timeout, the SurrealDB pool manager should explicitly **drop and regenerate** the affected connection instances instead of returning stale/poisoned handles to concurrent callers. Ensure failed connections are evicted (not recycled) so a partition or handshake failure can't leak a broken handle into the healthy pool. (Gemini review R2 §2.B. Pre-existing `axiam-db`; out of scope for the SDK PR.)

**Commit**: `fix(db): evict and regenerate poisoned connections from the pool`

---

## Phase 20: Axiam website

### 20.1 - Generate Axiam website - Showcase
Generate the website to be deployed on github.io to describe and showcase axiam

**Commit**`feat(website): Axiam showcase website`

### 20.1 - Generate Axiam website - Docs
Generate the website to be deployed on github.io for the documentation. Produce the docs according to standard docs formats (OpenAPI v3, AsyncAPI, docs.rs, JavaDocs, ...).

**Commit**`feat(website): Axiam docs website`

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
| Phase 12 | 3 | Hierarchical settings, password policy engine |
| Phase 13 | 5 | Email service, mail verification, password reset, admin notifications |
| Phase 14 | 3 | MFA enforcement, WebAuthn/FIDO2, multi-MFA management |
| Phase 15 | 7 | Admin frontend (responsive, user identity pages) |
| Phase 16 | 3 | Docker, K8s, CD pipeline |
| Phase 17 | 7 | SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) |
| Phase 18 | 4 | Security, compliance, performance, docs |
| Phase 19 | 24 | Deferred improvements & optimizations from PR reviews (incl. PR #126; 3 resolved in-PR) |

**Total: 101 tasks across 21 phases**

Each task is designed to be a self-contained unit of work with a clear deliverable and a signed commit, fitting within a single Claude Code session.
