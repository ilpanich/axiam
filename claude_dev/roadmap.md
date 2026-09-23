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
  - **Update (2026-09-04, T19.36):** no longer suppressed. `samael` 0.0.22 moved to `quick-xml` 0.41.0, which is the patched release for both advisories, so the pair was dropped from `deny.toml` and from the CI ignore list.

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

### T19.35 — "Sign in with X": working federated login, end to end
The backend implemented first-time SSO completely and the SPA had no way to reach it — no button, no callback route, and a federation service that only did CRUD (`claude_dev/rpi5-prod-google-federation-guide.md` §0). Close that, and the gaps that block the providers people actually ask for: a public providers-listing endpoint so a login page knows what to render; `FederationProtocol::OAuth2` for GitHub and Facebook, which issue no ID token; per-config scopes (Apple rejects the hard-coded `openid email profile`); server-minted Apple client secrets; templated-issuer support for Entra's `common` authority; organization→tenant inheritance of a federation config; a form-encoded SAML ACS a real IdP can post to; and single-use handoff codes so a cross-site SAML or Apple return can issue a session without weakening `SameSite=Strict`. Fix the two standing defects while in there: `attribute_map` was stored and read by nothing, and `allowed_algorithms` was hidden from OIDC in the admin UI. Design: `claude_dev/federation-sso-login-design.md`.

**Commit**: `feat(federation): working "Sign in with X" login providers`

### T19.36 — Security Scan: npm-registry outages and stale advisory suppressions ✓ RESOLVED
Run 1118 on `main` turned red without a vulnerability anywhere in the tree: `npm audit` got HTTP 503 from `registry.npmjs.org`'s audit endpoint for seven minutes and exited 1, and because that step precedes the SARIF producers, four `Path does not exist` upload errors landed on top of the one line that said what had happened. Three fixes, plus one dependency bump:

- **npm audit no longer fails on someone else's outage.** The step retries three times with backoff and tells "found advisories" apart from "could not reach the endpoint" by the *shape* of the output — npm exits 1 for both, but only a completed audit parses as JSON without an `error` key. A real HIGH/CRITICAL finding still fails the job; a sustained outage ends in a `::warning::` that says explicitly it is not a clean bill of health. `--fetch-retries`/`--fetch-timeout` bound npm's own retry loop, which is what burned the seven minutes.
- **Four suppressions had gone stale** and were emitting `advisory-not-detected` on every run: `RUSTSEC-2026-0194`/`-0195` (fixed upstream — `samael` 0.0.22 moved to `quick-xml` 0.41.0) and `RUSTSEC-2023-0089`/`RUSTSEC-2026-0235` (not in the resolved feature graph at all). Removed from `deny.toml`, and the job now runs `-D advisory-not-detected` so the next one fails CI instead of scrolling past — an ignore is keyed by advisory ID, so one left behind after its crate leaves the graph silently re-suppresses that advisory if the crate ever returns.
- **`check-audit-ignore-sync.py` demanded set equality, which had become unsatisfiable.** cargo-deny resolves the feature graph while cargo-audit reads `Cargo.lock`, so an optional dependency nothing enables is invisible to one and reported by the other. The gate now checks containment plus an explicit `# audit-only: <ID> — <reason>` declaration in `deny.toml`, which is what keeps "the lists differ" distinguishable from "the lists drifted".
- **`chacha20` 0.10.1 was yanked** (reached via `rand` 0.10.2 ← actix-http/totp-rs); bumped to 0.10.2.

Also guarded the four SARIF uploads on `hashFiles(…) != ''` so a failed producer no longer adds four errors of its own to a job that already has one.

**Commit**: `fix(ci): survive npm-registry outages and drop stale advisory suppressions`

---

## Phase 20: Axiam website

### 20.1 - Generate Axiam website - Showcase
Generate the website to be deployed on github.io to describe and showcase axiam

**Commit**`feat(website): Axiam showcase website`

### 20.1 - Generate Axiam website - Docs
Generate the website to be deployed on github.io for the documentation. Produce the docs according to standard docs formats (OpenAPI v3, AsyncAPI, docs.rs, JavaDocs, ...).

**Commit**`feat(website): Axiam docs website`

---

## Phase 21: MCP authorization-server support — ✓ COMPLETE (2026-09-17)

Make AXIAM usable as the OAuth 2.0 authorization server for Model Context
Protocol servers, at parity with or ahead of Keycloak's published support.
Full specification, invariants, model assignment per task and the regression
gate: [`mcp-authorization-server-plan.md`](mcp-authorization-server-plan.md).
Every task is additive and opt-in; existing flows must stay byte-identical.

**All nine tasks executed.** T21.1 and T21.2 are on `main`; T21.3 through
T21.6 and T21.9a are on the accumulation branch; T21.7, T21.8 and T21.9d are
in PRs #467, #473 and #468. The eleven SDK ports (T21.9b/c) are merged in
their own repositories. Two things are deliberately left open and are not
defects of execution: the four security findings filed as #469–#472, and
**F-28-01**, the single re-sync of the eleven vendored contract copies that
must happen from `main` after this phase merges.

### T21.1 — RFC 8414 well-known alias — Sonnet 5 ✓ LANDED
Serve `/.well-known/oauth-authorization-server` from the existing discovery handler; public-path and OpenAPI parity.

**Commit** `573373a` `feat(oauth2): serve RFC 8414 discovery alongside OIDC discovery (T21.1)`

### T21.2 — Public clients and loopback redirects — Opus 5 (server), Sonnet 5 (admin UI) ✓ LANDED
`token_endpoint_auth_method: none`, PKCE required at the token endpoint, RFC 8252 §7.3 port-agnostic loopback matching for registered loopback URIs only.

**Commits** `0534af6` "feat(oauth2): public clients (`none`) and RFC 8252 loopback redirects (T21.2)" · `ed9e9f0` `feat(frontend): admin UI for public OAuth2 clients (T21.2)`

### T21.3 — RFC 8707 resource indicators end to end — Opus 5 ✓ LANDED
`allowed_resources` on clients; `resource` honoured on authorize, PAR, device and token; `aud` minted from it; AXIAM's own APIs keep refusing foreign audiences.

**Commit** `ffec785` `feat(oauth2): RFC 8707 resource indicators, end to end (T21.3)`

### T21.4 — RFC 7591 dynamic client registration — Opus 5 (endpoint), Sonnet 5 (admin UI) ✓ LANDED
Per-tenant policy (disabled by default), `POST /oauth2/register`, abuse controls, forced consent for externally registered clients.

**Commits** `ff1919b` `feat(oauth2): RFC 7591 dynamic client registration (T21.4)` · `e1540b5` `Add admin UI for dynamic client registration (T21.4b)`

T21.7 recorded the admin UI as "not found on this branch" and was right about
its branch: `claude/t21-4b-dcr-admin-ui` merged into the accumulation branch
(PR #465) twelve minutes before T21.5 branched from elsewhere, so it is absent
from `claude/t21-7-mcp-docs` and from everything cut after it. It is present
here.

### T21.5 — OAuth Client ID Metadata Document — Opus 5 ✓ LANDED
URL-shaped `client_id` resolved through an SSRF-guarded, cache-bounded fetch; per-tenant trust policy; VS Code and Claude Code flows.

**Commits** `0213087` `feat(oauth2): resolve a URL-shaped client_id from its metadata document (T21.5)` · `ddc1d2a` `docs(oauth2): client ID metadata documents — operator page, spec, contract (T21.5)`

### T21.6 — Per-tenant path-based issuers — Opus 5 ✓ LANDED
Opt-in `{root}/t/{tenant}` issuer with RFC 8414 and OIDC Discovery path forms; no `tenant_id` query in the advertised endpoints.

**Commit** `41aa36f` `feat(oauth2): per-tenant path issuers, opt-in (T21.6)`

### T21.7 — Documentation, contract, website — Sonnet 5 ✓ LANDED
`docs/api/mcp.md`, CONTRACT §10.1 audience note, token-exchange audience rewrite, website block.

**Commit** `abdb3b6` `docs(mcp): fronting an MCP server with AXIAM, and the b7-mcp-server example` — `docs/api/mcp.md`, `examples/b7-mcp-server/`, the CONTRACT §10.1 row 6 sentence, the `oauth2.ts` website block; `docs/api/token-exchange.md#audience` was already rewritten by T21.3. PR #467.

### T21.8 — End-to-end MCP harness and security review — Opus 5 ✓ LANDED
Integration test driving the MCP client sequence in both issuer modes; security review of the new surfaces; STRIDE model update.

**Commits** `f154d24` `test(mcp): the MCP client sequence end to end, in both issuer modes (T21.8)` · `1ab4e7a` `test(mcp): the adversarial half of the T21.8 harness` · `013903d` `fix(oauth2): reserve the axiam scheme against use as a resource (MCP-02)` · `0233742` `docs(security): the MCP security review, and nine STRIDE entries for it (T21.8)` · `2350ae2` `docs: discharge the I1 conformance condition, and link the filed findings`. PR #473.

The harness drives the MCP client sequence four times — `{DCR, CIMD}` ×
`{?tenant_id=, /t/{tenant}}`. One finding (**MCP-02**, AXIAM's own audiences
were valid RFC 8707 resource indicators) was fixed in the same task; four are
filed as #469–#472 and one is accepted. Evidence:
[`claude_dev/security-review-mcp-2026-09-17.md`](security-review-mcp-2026-09-17.md).

### T21.9 — SDK fan-out: MCP resource-server helpers — Opus 5 (contract §28, TypeScript reference, review), Sonnet 5 (ten ports) — complete
CONTRACT §28 (RFC 9728 document builder and route, `WWW-Authenticate` challenge, `resource_metadata_url` middleware option); TypeScript reference; ports in the other ten SDK repositories; cross-SDK conformance review. Every task also ships docs, the `examples/b7-mcp-server` entry and tests per the plan's §4.0.

**Commit** `63a19af` `docs(sdk-contract): §28 MCP resource-server helpers, contract 1.48 (T21.9)` — the contract text only, ahead of every port (T9a)

**T9b / T9c — all eleven ports merged.** TypeScript is the reference
(`axiam-typescript-sdk` #110); the ten ports are `axiam-rust-sdk` #109,
`axiam-python-sdk` #83, `axiam-java-sdk` #98, `axiam-kotlin-sdk` #65,
`axiam-csharp-sdk` #91, `axiam-php-sdk` #70, `axiam-go-sdk` #81,
`axiam-swift-sdk` #63, `axiam-c-sdk` #62 and `axiam-cplusplus-sdk` #63.

**Commits** `8bdd062` `docs(sdk-contract): §28 cross-SDK conformance review, contract 1.49 (T21.9 T9d)` · `b1aedc8` `docs(sdk-contract): correct §28.10/§28.11 R-2's count of unrecorded posture rows`. PR #468 — all eleven ports read against §28 and against the reference; thirteen divergences recorded in §28.11 with no open row; six contract defects fixed; §28.10's posture table filled in from the merged code and moved to upstream maintenance. Evidence: [`claude_dev/sdk-mcp-helpers-conformance-review.md`](sdk-mcp-helpers-conformance-review.md). One follow-up, **F-28-01**, is open by design and blocked on Phase 21 merging: the eleven vendored `CONTRACT.md`/`openapi.json` copies are re-synced from `main` in one step afterwards, and the review explains why doing it from a phase branch is what left the eleven holding five distinct files.

## Phase 22: Dogfooding remediation (`axiam-domo-demo` DF-001 … DF-027) — IN PROGRESS

Fix what the `axiam-domo-demo` integration found, as re-read against `main`
rather than as filed. Full verdict per finding, the model assignment, the
pull-request split and the verification gates:
[`dogfooding-findings-fix-plan.md`](dogfooding-findings-fix-plan.md). Seventeen
fixes, four documentation-only items, four recorded declines and two defects the
findings did not contain (§1.7, §1.8). Every task ships its I1, its negative
tests' I4 twins, and the §9 records in the same commit.

### T22.1 — A signing CA issues only for the tenant it signs for — Opus 5 ✓ LANDED
DF-017 / DF-025. `prepare_leaf_issuance` reads `ca_certificate.tenant_id` and
matches it against the tenant being acted on, ahead of the status and window
checks; an organization-level CA additionally requires a principal whose record
lives in the organization scope. `404`, following the cross-organization
precedent. Nine unit tests plus the end-to-end twin; threat **T-281**, and
**T-98** corrected where it claimed this was already enforced. PR A.

### T22.2 — The device mTLS login gets a rate limiter — Sonnet 5 ✓ LANDED
DF-028 (new, from §1.7 of the plan). `POST /api/v1/auth/device` was a bare route
while every neighbouring auth resource carried a governor and a shared store.
`AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN`, default 60 per IP, in the machine
family so a posture preset scales it (300 / 3 000) for a fleet behind one NAT.
No existing default moves. Six tests against the real route wiring; threat
**T-282**. PR A.

### T22.3 — Device tokens are bound to their certificate — Opus 5 ✓ LANDED
DF-014. `POST /api/v1/auth/device` handed back a plain bearer token although
the device had just proved possession of a private key. It now carries
`cnf.x5t#S256` over the certificate rustls verified for the connection. **No
enforcement code changed:** both REST and gRPC already refuse a `cnf`-bearing
token whose evidence does not match, so the claim was the only missing half.
The trusted-proxy header path mints no claim, deliberately. Three unit tests;
threat **T-283**. PR A.

### T22.4 — An unbound certificate is a 401 — Sonnet 5 ✓ LANDED
DF-027. The device-auth path reached `403` for one refusal by matching the text
of an `axiam-pki` error message. A certificate bound to no principal identifies
nobody, so it is unauthenticated like its three siblings; and a status that
depends on a lower crate's wording is one nobody can change safely. The string
match goes with it. OpenAPI and the management registry regenerated. PR A.

### T22.5 — Messages and docs name the variable the env provider reads — Sonnet 5 ✓ LANDED
DF-018 / DF-022. `AXIAM__PKI__ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`,
`AXIAM__GDPR_PSEUDONYM_PEPPER` and `AXIAM__FEDERATION_ENCRYPTION_KEY` were
documented, printed in a dozen error messages, and set by `just dev-up`, `just
prod-up`, the benchmark compose file and the conformance harness — and read by
nothing. Every secret resolves through the provider to `AXIAM__AUTH__<KEY>`,
with three grandfathered exceptions. Renamed everywhere, with the rule itself
stated on both the deployment guide and the configuration page; no aliases
(D-1). A startup `WARN` names both spellings for a deployment that still sets
an old one, computed from an *is-set* predicate so it can never touch a value.
`AXIAM__AMQP__SIGNING_KEY` is excluded — it is genuinely honoured. Seven unit
tests; records: none. PR B.

### T22.6 — `subject` is a common name, and `CN=` is understood once — Sonnet 5 ✓ LANDED
DF-023. Every AXIAM certificate has one DN component, but `subject` was pushed
into rcgen whole, so a documented `CN=device-001` produced a DN of
`CN=CN=device-001` while the row stored the prefix. `subject_common_name` in
`axiam-pki` normalises once, at the top of the three paths that accept a
caller-supplied subject, so the certificate and the row agree. A distinguished
name is refused with `400` rather than silently reduced to its CN (D-2): no RFC
4514 parser for a field with one consumer. Paths whose subject is parsed out of
a certificate or CSR are untouched. Eleven tests across `subject.rs`,
`ca_test.rs`, `intermediate_ca_test.rs` and `cert_test.rs`, each with its I4
twin; the e2e matrix fixture's idempotency lookup, which matches on the stored
subject, moved to the bare form with it. OpenAPI regenerated. Records: none.
PR B.

### T22.7 — `axiam-server setup-token --remint` — Sonnet 5 ✓ LANDED
DF-019. The bootstrap setup token is stored as a hash and minted only on a
never-bootstrapped database, so an operator who lost it had one recovery: wipe
the volume. The subcommand replaces it and prints the new token to stdout only.
It refuses with exit 2, writing nothing, once a `user` row or a redeemed token
exists — before bootstrap there is nothing to take over, after it there is an
authenticated way in. The "delete then mint" is one function shared with the
first-boot path. Argv parsing moved to a unit-tested `cli` module so
`setup-token` with a mistyped flag cannot start a server. Eight tests; threat
**T-284**. PR B.

### T22.8 — `healthcheck` can probe a TLS listener — Sonnet 5 ✓ LANDED
DF-016. The probe was a hardcoded plaintext GET, so a deployment terminating TLS
in-process — the shipped Kubernetes ConfigMap — failed its container healthcheck
forever. The scheme now follows the listener (`ENABLED` **and** a certificate
path, not the path alone, which `docker-compose.prod.yml` sets unconditionally)
and the port follows `AXIAM__SERVER__PORT`. `AXIAM_HEALTHCHECK_CA_FILE` names
trust anchors; with none set an `https` self-probe trusts the server's own chain
file. No insecure switch. Nineteen tests, including the empirical answer to the
plan's open question — an end-entity certificate that is its own issuer **is** a
usable trust anchor, a CA-issued leaf without its issuer is not. Records: none.
PR B.

### T22.9 — The documentation bundle — Sonnet 5 ✓ LANDED
DF-002, DF-015, DF-007/DF-020. Prose only. DF-002 was the dangerous one: the PKI
guide and the website both said a `Device` certificate needs no bind, while
`authenticate_device` refuses an unbound certificate with `401` — a commissioned
fleet failing every login with nothing to say why. Both now give the order, the
permission and the bind-time requirements. DF-015: RSA-4096 CA generation works
under every custodian; the two sentences claiming otherwise are replaced by the
trade-off that does apply, keygen time on small hardware. DF-007/DF-020: a new
broker section on the client certificate AXIAM cannot issue for itself, and on
why AXIAM tokens are not consumable by `rabbitmq_auth_backend_oauth2`. Records:
none. Also in PR B, deliberately outside the plan: the latent CodeQL
`rust/insecure-cookie` alert in `users_rate_limit_split_test.rs`, and the
tenant-B half of `frontend/e2e/matrix/tenancy.spec.ts` snapshotting the users
table with no wait. PR B.

### T22.10 — The console resolves its upstream at request time — Sonnet 5 ✓ LANDED
DF-026. A literal host in `proxy_pass` is resolved once, at config load, so a
console started before `axiam-server` exited with `host not found in upstream`,
and one whose backend moved kept the dead address. The three proxy blocks now
go through `set $axiam_backend` and a `resolver ... valid=30s`, once per
`server`. The resolver comes from the container's `resolv.conf`, through an
entrypoint hook, unless `AXIAM_BACKEND_RESOLVER` is set: the plan's fixed
`127.0.0.11` would have been right on Docker only. Routing was proved unchanged
across sixteen request shapes on a real nginx. The image build now runs
`nginx -t` on the rendered template, and a new path-filtered workflow runs the
start-order scenario against the built image (console first, `502`, `200`, the
backend moved, `200`). Records: none, verified. PR C.

### T22.11 — A role assignment can be non-inheritable — Opus 5 ✓ LANDED
DF-021. A resource-scoped assignment always cascaded to every descendant, so
"this building and not its apartments" needed a deny at every apartment.
`inherit: bool` on the `has_role` edge, default `true` (schema v66,
`option<bool>`, no backfill): `false` applies the assignment at its resource
only, for allows and denies alike. One clause in `applicable_role_ids`, shared
by `evaluate` and `evaluate_batch`; read in both the direct and the
group-inherited SELECT. The three assign routes take `inherit`, refuse `false`
with `400` on a tenant-wide assignment and on a global role, and every listing
shows it; changing it is unassign-and-assign (`UNIQUE(in, out)`), both of which
invalidate. Precedence rows 9–11 in the design document, proved end to end
through both engine paths and over gRPC; three property tests; the clause
broken on purpose twice to watch the new tests fail. OpenAPI and the management
registry regenerated. Threat **T-285**; **T-16** and **T-87** amended. PR D.

### T22.11b — Non-inheritable assignments in the admin console — Sonnet 5 ✓ LANDED
S-10b, the console half of T22.11 (PR G2). Every assign dialog — role → user,
group, service account; user → role; group → role — offers `inherit` only
with a resource on a non-global role, and sends it only as `false`. Listings
badge a non-inheritable row; *Stop here* / *Include descendants* changes the
flag as unassign-then-assign with a restore on failure and a loud message if
the restore fails too. T-285's "console does not offer the flag" residual
amended. Saving a role as global while it has non-inheritable assignments asks
first, naming them (the T-285 residual: a confirmation, not a refusal), on both
the role list and the role page.
(Numbered after T22.11, the task it completes; the brief called it T22.10b,
but T22.10 in this roadmap is the console resolver, S-11.)

### T22.12 — Client-certificate verification on the gRPC listener — Opus 5 ✓ LANDED
DF-005. The gRPC listener's rustls configuration called `with_no_client_auth()`,
a deployment decision deferred from T-234, while `ReactorAdminService` joined
`CheckAccess` on it. `AXIAM__GRPC_TLS_CLIENT_AUTH` (`off` default | `optional`
| `required`) and `AXIAM__GRPC_TLS_CLIENT_CA_PATH`. `off` keeps
`with_no_client_auth()`, and the handshake is proved unchanged against the
pre-change configuration. The verifying modes install a second
`ReloadableClientCertVerifier`, registered with `reload_trust_anchors`, which
re-reads its own bundle on each reload. Seven misconfigurations refuse to boot,
including client auth on a plaintext listener. The verified certificate reaches
the interceptor through tonic's `TlsConnectInfo`, which the custom accept loop
already produced. So S-3's certificate-bound device tokens now work over gRPC,
proved end to end with the right certificate, another device's certificate,
and none. Three mutations were made to confirm the new tests can fail.
Threat **T-286**; **T-234** and **T-283** amended. PR E.

### T22.13 — Service accounts on the management routes — Opus 5 ✓ LANDED
DF-013. Every management handler took `AuthenticatedUser`, so automation that
provisions a tenant needed a human administrator's credential. D-5 admits a
service-account token on eight families — resources, scopes, permissions, roles
(assignments included), groups, service accounts, certificates, webhooks — whose
66 handlers now take `AuthenticatedPrincipal` and `RequirePermission::check`
over a `Caller` trait; every other route still refuses `axiam:m2m` with `401`.
The boundary is `M2M_MANAGEMENT_FAMILIES` / `HUMAN_ONLY_FAMILIES`, checked
against the permission registry, and a sweep drives all 146 mapped routes plus
every other non-public `/api/v1` operation with real tokens. The machine branch
admits `sub_kind = service_account` only (an exchanged user token is not a
machine); the user branch is `AuthenticatedUser`'s own code, which fixes a `sid`
misread; `X-Axiam-Tenant` resolves as for a user; no service account issues
under the organization CA. The audit log records the actor type from
`sub_kind`. OpenAPI gains a `service_account` security scheme on the admitted
operations; spec and management registry regenerated. Threat **T-287**. PR F.

### T22.14 — Server certificates, the name fence and the leaf usage profile — Opus 5 ✓ LANDED
DF-001. AXIAM could not issue a certificate a TLS server presents: leaves
carried no SAN, KU or EKU, and neither request body had a field for them.
`CertificateType::Server` is the only type with SANs, taken from an explicit
`subject_alt_names` field on `generate` and `sign-csr`. A CSR's own
`subjectAltName` is still refused. Every SAN and the CN must match the
effective `server_cert_allowed_names`: DNS suffixes (strictly below, on label
boundaries), exact hosts and CIDRs. The list is empty by default, which
refuses every `Server` request. It uses the existing tighten-only interlock:
widening is a `400`, and a shrinking baseline intersects. Every leaf gets a
per-type, per-algorithm KU/EKU profile on both paths and both custodians. Under
`vault_pki` the names go in AXIAM's own CSR, because `sign-verbatim` ignores
`alt_names` (measured on a real Vault 1.18.3). A caller-CSR `Server` request is
refused there. `bind` and device login refuse `Server`. Schema **v67**
(`cert_type` assertion + baseline column). A browser-shaped rustls↔actix
acceptance test passes. Nine mutations were made to confirm the new tests can
fail. OpenAPI and the management registry regenerated. Threat **T-288**;
**T-268** amended. Decision D-7 (`nameConstraints` in tenant CAs) deferred. The
admin UI is S-7b, next. PR G.

### T22.14b — Server certificates in the admin console — Sonnet 5 ✓ LANDED
S-7b, the console half of T22.14 (PR G2). The certificate dialogs offer
`Server` with a SAN list editor, `{dns}` or `{ip}` per row, required for
`Server` and absent for every other type; the form checks shape only and shows
the server's `400` verbatim, the `vault_pki` sign-CSR refusal included. A
**Server Certificate Names** card edits `server_cert_allowed_names` on the
organization Settings tab (baseline), the tenant Settings page (effective list,
read back) and the tenant Security Overrides panel (its own group: absent
follows the organization, empty issues none). Fixes three console paths that
silently dropped the list on an unrelated save since #495. Records: none,
verified.

### T22.15 — SDK contract 1.51 — Opus 5 ✓ LANDED
C-0 (PR H), DF-008 … DF-012. `sdks/CONTRACT.md` describes what T22.1 … T22.14b
shipped. `authenticate_device`, `validate_token` and `introspect_token` join §1
(new §1.1.1, §6.1 rules 6–10). The acting-tenant helper becomes SHOULD: REST-only,
with the UUID checked client-side (§5.2 rule 1). §27.0 lists all five registry
exclusions, `/admin/bootstrap` with its outcomes and no helper. The manifest gains
`metadata`, resource-scoped bindings with `inherit`, and `service_accounts`, with the
one-time secret returned as `create` returns it (§27.5 rule 5, §27.6.1). §27.10 records
the two manifest tiers and three SDK defects. New §27.13 covers the DTO notes, and §27's
figures are re-rendered at 162 operations. Numbered **1.51**, since 1.50 was already
taken (`d5a6811`), so C-12 becomes 1.52. Threat **T-210** amended, no new entry. The
eleven SDK ports (C-1 … C-11) follow, one PR per SDK repository, Rust first.

---

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
| Phase 19 | 26 | Deferred improvements & optimizations from PR reviews (incl. PR #126; 3 resolved in-PR) |
| Phase 20 | 2 | Public website and documentation site |
| Phase 21 | 9 | MCP authorization-server support (RFC 8414 path, public clients, RFC 8707, RFC 7591, CIMD, per-tenant issuers, SDK fan-out) |
| Phase 22 | 4+ | Dogfooding remediation from `axiam-domo-demo` (PKI tenant scope, device-login rate limit, certificate-bound device tokens, status codes, server certificates) |

**Total: 112 tasks across 22 complete phases, plus Phase 22 in progress**

Each task is designed to be a self-contained unit of work with a clear deliverable and a signed commit, fitting within a single Claude Code session.
