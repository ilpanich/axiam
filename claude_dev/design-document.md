# AXIAM — Design Document

## 1. Overview

AXIAM (Access eXtended Identity and Authorization Management) is an open-source IAM platform built with Rust and SurrealDB. It targets microservices and IoT environments, providing authentication, authorization, user management, federation, and audit capabilities while maintaining compliance with GDPR, CyberSecurity Act, ISO 27001, OWASP ASVS, and OWASP Cumulus.

---

## 2. System Architecture

AXIAM follows a **layered, modular architecture** with clear separation of concerns. Each layer communicates only with its immediate neighbors.

```
┌──────────────────────────────────────────────────────────┐
│                      Clients                             │
│  (Browser, Mobile, IoT devices, Service accounts, SDKs)  │
└──────────┬──────────────┬──────────────┬─────────────────┘
           │ REST/HTTPS   │ gRPC/TLS     │ AMQP
           ▼              ▼              ▼
┌──────────────────────────────────────────────────────────┐
│                   API Gateway Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌────────────────────┐ │
│  │  REST API    │ │  gRPC API   │ │  AMQP Consumer     │ │
│  │  (Actix-Web) │ │  (Tonic)    │ │  (Lapin)           │ │
│  └──────┬──────┘ └──────┬──────┘ └────────┬───────────┘ │
│         └───────────┬───┘                  │             │
│                     ▼                      ▼             │
│           ┌─────────────────────────────────┐            │
│           │       Middleware Pipeline        │            │
│           │  (Auth, Rate Limit, CORS, Audit) │            │
│           └──────────────┬──────────────────┘            │
└──────────────────────────┼───────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   Service Layer                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │
│  │ AuthN    │ │ AuthZ    │ │ User     │ │ Federation │  │
│  │ Service  │ │ Engine   │ │ Service  │ │ Service    │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │
│  │ Role     │ │ Resource │ │ Audit    │ │ OAuth2/    │  │
│  │ Service  │ │ Service  │ │ Service  │ │ OIDC       │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │
└──────────────────────────┬───────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   Data Access Layer                       │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Repository Trait Abstractions             │  │
│  │  (UserRepo, RoleRepo, ResourceRepo, AuditRepo...)  │  │
│  └───────────────────────┬────────────────────────────┘  │
└──────────────────────────┼───────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   SurrealDB Cluster                       │
│  (Users, Roles, Permissions, Resources, Audit Logs,      │
│   Sessions, OAuth2 Clients, Federation Configs)           │
└──────────────────────────────────────────────────────────┘
```

### 2.1 Communication Protocols

| Protocol | Use Case | Rust Crate |
|----------|----------|------------|
| **REST/HTTP** | Admin UI, public API, OAuth2/OIDC endpoints | `actix-web` |
| **gRPC** | Inter-service authz checks, SDK communication, IoT devices | `tonic` + `prost` |
| **AMQP** | Async authz requests, audit log ingestion, event notifications | `lapin` |

### 2.2 Crate Organization

The project is organized as a Cargo workspace with the following crates:

```
axiam/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── axiam-core/             # Domain types, traits, error types
│   ├── axiam-db/               # SurrealDB repository implementations
│   ├── axiam-auth/             # Authentication logic (password, MFA, JWT)
│   ├── axiam-authz/            # Authorization engine (RBAC, hierarchy, scopes)
│   ├── axiam-api-rest/         # REST API handlers (Actix-Web)
│   ├── axiam-api-grpc/         # gRPC service implementations (Tonic)
│   ├── axiam-amqp/             # AMQP consumer/producer (Lapin)
│   ├── axiam-oauth2/           # OAuth2 authorization server + OIDC provider
│   ├── axiam-federation/       # SAML SP + OIDC federation
│   ├── axiam-audit/            # Audit logging service
│   └── axiam-server/           # Binary — composes all crates, starts server
├── proto/                      # Protocol Buffer definitions for gRPC
├── frontend/                   # React admin UI
├── docker/                     # Dockerfiles and compose configs
├── k8s/                        # Kubernetes manifests
└── sdks/                       # SDK projects (rust, python, typescript, etc.)
```

---

## 3. Data Model

SurrealDB's document/graph hybrid model is leveraged for both entity storage and relationship traversal (e.g., resource hierarchies, role assignments).

### 3.1 Entity-Relationship Diagram

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│    User      │──N:M──│    Role      │──N:M──│  Permission  │
│              │       │              │       │              │
│ id           │       │ id           │       │ id           │
│ username     │       │ name         │       │ action       │
│ email        │       │ description  │       │ description  │
│ password_hash│       │ is_global    │       └──────┬───────┘
│ mfa_secret   │       │ created_at   │              │
│ status       │       │ updated_at   │              │ N:M
│ metadata     │       └──────────────┘              │
│ created_at   │                              ┌──────┴───────┐
│ updated_at   │                              │   Resource   │
└──────┬───────┘                              │              │
       │                                      │ id           │
       │ 1:N                                  │ name         │
       ▼                                      │ type         │
┌──────────────┐                              │ parent_id    │
│   Session    │                              │ metadata     │
│              │                              └──────┬───────┘
│ id           │                                     │
│ user_id      │                                     │ 1:N
│ token_hash   │                              ┌──────┴───────┐
│ ip_address   │                              │    Scope     │
│ user_agent   │                              │              │
│ expires_at   │                              │ id           │
│ created_at   │                              │ resource_id  │
└──────────────┘                              │ name         │
                                              │ description  │
┌──────────────┐       ┌──────────────┐       └──────────────┘
│ServiceAccount│       │  AuditLog    │
│              │       │              │
│ id           │       │ id           │
│ name         │       │ actor_id     │
│ client_id    │       │ actor_type   │
│ client_secret│       │ action       │
│ roles[]      │       │ resource_id  │
│ status       │       │ outcome      │
│ created_at   │       │ ip_address   │
└──────────────┘       │ metadata     │
                       │ timestamp    │
┌──────────────┐       └──────────────┘
│ OAuth2Client │
│              │       ┌──────────────┐
│ id           │       │ FederationCfg│
│ client_id    │       │              │
│ client_secret│       │ id           │
│ name         │       │ provider     │
│ redirect_uris│       │ protocol     │
│ grant_types  │       │ metadata_url │
│ scopes       │       │ client_id    │
│ created_at   │       │ client_secret│
└──────────────┘       │ attribute_map│
                       │ enabled      │
                       └──────────────┘
```

### 3.2 SurrealDB Tables

| Table | Description |
|-------|-------------|
| `user` | User accounts with credentials and profile data |
| `service_account` | Machine-to-machine accounts |
| `role` | Named collections of permissions |
| `permission` | Action definitions (e.g., `read`, `write`, `delete`) |
| `resource` | Hierarchical resources (self-referencing `parent_id`) |
| `scope` | Fine-grained sub-resource permissions |
| `session` | Active user sessions |
| `audit_log` | Immutable audit trail |
| `oauth2_client` | Registered OAuth2/OIDC clients |
| `federation_config` | External IdP configurations (SAML, OIDC) |

### 3.3 SurrealDB Graph Edges (Relations)

| Edge | From | To | Description |
|------|------|----|-------------|
| `has_role` | `user` / `service_account` | `role` | Role assignment, optionally scoped to a resource |
| `grants` | `role` | `permission` | Permissions included in a role |
| `on_resource` | `permission` | `resource` | Which resource a permission applies to |
| `child_of` | `resource` | `resource` | Resource hierarchy |

Using graph edges allows efficient traversal queries such as:
```surql
SELECT ->has_role->role->grants->permission->on_resource->resource
FROM user:$uid;
```

### 3.4 Key Design Decisions

- **Password hashing**: Argon2id (OWASP-recommended parameters)
- **JWT signing**: EdDSA (Ed25519) for access tokens; opaque refresh tokens stored server-side
- **MFA**: TOTP (RFC 6238) with encrypted secret storage; extensible for WebAuthn later
- **Audit logs**: Append-only table, no UPDATE/DELETE allowed (enforced at SurrealDB permission level)
- **Resource hierarchy**: Computed at query time via graph traversal, not materialized, to keep writes simple and consistent

---

## 4. Authentication Flows

### 4.1 Username/Password Login

```
Client                    AXIAM REST API              SurrealDB
  │                            │                         │
  │── POST /auth/login ───────▶│                         │
  │   {username, password}     │── Fetch user ──────────▶│
  │                            │◀── user record ─────────│
  │                            │── Verify Argon2id       │
  │                            │── Check MFA required?   │
  │                            │                         │
  │ (if MFA not required)      │                         │
  │◀── {access_token,          │── Create session ──────▶│
  │     refresh_token} ────────│── Write audit log ─────▶│
  │                            │                         │
  │ (if MFA required)          │                         │
  │◀── {mfa_challenge_token} ──│                         │
  │                            │                         │
  │── POST /auth/mfa/verify ──▶│                         │
  │   {challenge_token, code}  │── Verify TOTP           │
  │◀── {access_token,          │── Create session ──────▶│
  │     refresh_token} ────────│── Write audit log ─────▶│
```

### 4.2 OAuth2 Authorization Code Flow

```
Client        AXIAM (AuthZ Server)       Resource Server
  │                │                          │
  │── GET /oauth2/authorize ──▶│              │
  │   (client_id, scope,       │              │
  │    redirect_uri, state)    │              │
  │                            │              │
  │◀── Login page ─────────────│              │
  │── Authenticate ───────────▶│              │
  │◀── Consent screen ────────│              │
  │── Approve ────────────────▶│              │
  │◀── Redirect with code ─────│              │
  │                            │              │
  │── POST /oauth2/token ─────▶│              │
  │   (code, client_secret)    │              │
  │◀── {access_token, id_token}│              │
  │                            │              │
  │── API call + Bearer token ─┼─────────────▶│
  │                            │              │── Validate JWT
  │◀── Response ───────────────┼──────────────│
```

### 4.3 gRPC Authorization Check

For low-latency authorization decisions in microservice architectures:

```protobuf
service AuthorizationService {
  rpc CheckAccess(CheckAccessRequest) returns (CheckAccessResponse);
  rpc BatchCheckAccess(BatchCheckAccessRequest) returns (BatchCheckAccessResponse);
}

message CheckAccessRequest {
  string subject_id = 1;    // user or service account
  string action = 2;        // permission action
  string resource_id = 3;   // target resource
  repeated string scopes = 4;
}

message CheckAccessResponse {
  bool allowed = 1;
  string reason = 2;
}
```

### 4.4 AMQP Async Authorization

For scenarios where authorization decisions can be deferred:

```
Producer                    AMQP Broker              AXIAM Consumer
  │                            │                         │
  │── Publish to               │                         │
  │   authz.request queue ────▶│                         │
  │                            │── Deliver ─────────────▶│
  │                            │                         │── Evaluate authz
  │                            │                         │── Write audit log
  │                            │◀── Publish to           │
  │◀── Consume from            │    authz.response ──────│
  │    authz.response ─────────│                         │
```

---

## 5. Authorization Engine

### 5.1 Permission Resolution Algorithm

When evaluating whether a subject can perform an action on a resource:

1. **Fetch direct roles**: Get all roles assigned to the subject
2. **Filter by resource scope**: Keep global roles + roles assigned on the target resource or any ancestor in the hierarchy
3. **Collect permissions**: Union of all permissions from the matching roles
4. **Check scopes**: If the permission requires specific scopes, verify they are present
5. **Apply inheritance**: Walk up the resource tree — a role on a parent grants access to children unless an explicit deny exists at a lower level
6. **Return decision**: `Allow` if a matching permission is found, `Deny` otherwise (default deny)

### 5.2 Resource Hierarchy Traversal

```
Organization (global roles apply here)
├── Project A
│   ├── Service X (inherits Project A roles)
│   │   ├── Endpoint /users
│   │   └── Endpoint /orders
│   └── Service Y
└── Project B
    └── Service Z
```

A user with role `admin` on `Project A` automatically has `admin` on `Service X`, `Service Y`, and all their children — unless overridden.

---

## 6. API Design

### 6.1 REST API Endpoints (Summary)

| Group | Endpoints | Description |
|-------|-----------|-------------|
| **Auth** | `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `POST /auth/mfa/*` | Authentication flows |
| **Users** | `GET/POST/PUT/DELETE /api/v1/users` | User CRUD |
| **Roles** | `GET/POST/PUT/DELETE /api/v1/roles` | Role management |
| **Permissions** | `GET/POST/PUT/DELETE /api/v1/permissions` | Permission definitions |
| **Resources** | `GET/POST/PUT/DELETE /api/v1/resources` | Resource hierarchy management |
| **Service Accounts** | `GET/POST/PUT/DELETE /api/v1/service-accounts` | Service account management |
| **OAuth2** | `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect` | OAuth2 endpoints |
| **OIDC** | `/.well-known/openid-configuration`, `/oauth2/userinfo`, `/oauth2/jwks` | OpenID Connect discovery and endpoints |
| **Federation** | `GET/POST/PUT/DELETE /api/v1/federation` | IdP configuration management |
| **Audit** | `GET /api/v1/audit-logs` | Audit log query (read-only) |
| **Health** | `GET /health`, `GET /ready` | Health and readiness probes |

### 6.2 gRPC Services

| Service | Methods | Description |
|---------|---------|-------------|
| `AuthorizationService` | `CheckAccess`, `BatchCheckAccess` | Real-time authz decisions |
| `UserService` | `GetUser`, `ValidateCredentials` | User lookups for inter-service use |
| `TokenService` | `ValidateToken`, `IntrospectToken` | Token validation for service mesh |

### 6.3 AMQP Queues

| Queue | Direction | Description |
|-------|-----------|-------------|
| `axiam.authz.request` | Inbound | Async authorization check requests |
| `axiam.authz.response` | Outbound | Authorization decision responses |
| `axiam.audit.events` | Inbound | Audit events from external services |
| `axiam.notifications` | Outbound | Real-time event notifications (role changes, user creation, etc.) |

---

## 7. Security Measures

### 7.1 Cryptography

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Password hashing | Argon2id | OWASP-recommended params (memory: 19 MiB, iterations: 2, parallelism: 1) |
| JWT signing | EdDSA (Ed25519) | Short-lived access tokens (15 min default) |
| Refresh tokens | Opaque, server-stored | Rotation on use, single-use |
| MFA secrets | AES-256-GCM encrypted at rest | TOTP per RFC 6238 |
| TLS | TLS 1.3 minimum | For all external communication |
| Client secrets | HMAC-SHA256 hashed | Never stored in plaintext |

### 7.2 Security Controls

- **Rate limiting**: Per-IP and per-user on authentication endpoints
- **CSRF protection**: Double-submit cookie pattern for browser-based flows
- **CORS**: Configurable allowed origins, strict defaults
- **Input validation**: All inputs validated and sanitized at the API boundary
- **SQL injection**: Parameterized queries only (SurrealDB prepared statements)
- **XSS**: Content-Security-Policy headers; React handles output encoding
- **Brute force protection**: Account lockout after N failed attempts, with exponential backoff
- **Session security**: Secure, HttpOnly, SameSite cookies; session invalidation on password change
- **Audit immutability**: Audit log table has no UPDATE/DELETE permissions

### 7.3 Compliance Mapping

| Standard | Relevant AXIAM Features |
|----------|------------------------|
| GDPR | User data export/deletion, consent tracking, audit logs, data minimization |
| ISO 27001 | Access control (A.9), cryptography (A.10), audit logging (A.12) |
| OWASP ASVS | Password requirements (V2), session management (V3), access control (V4) |
| CyberSecurity Act | Secure by design, vulnerability management, incident logging |

---

## 8. Deployment Architecture

### 8.1 Development (Docker Compose)

```
┌─────────────────────────────────────────┐
│              docker-compose              │
│  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │  AXIAM   │  │ SurrealDB│  │ RabbitMQ│ │
│  │  Server  │──│  (single)│  │        │ │
│  │  :8080   │  │  :8000   │  │  :5672 │ │
│  └──────────┘  └──────────┘  └────────┘ │
└─────────────────────────────────────────┘
```

### 8.2 Production (Kubernetes)

```
┌─────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                  │
│                                                      │
│  ┌──────────┐   ┌──────────────────┐                │
│  │ Ingress  │──▶│ AXIAM Deployment │                │
│  │ (TLS)    │   │ (N replicas, HPA)│                │
│  └──────────┘   └────────┬─────────┘                │
│                          │                           │
│         ┌────────────────┼────────────────┐          │
│         ▼                ▼                ▼          │
│  ┌──────────┐   ┌──────────────┐  ┌───────────┐    │
│  │ SurrealDB│   │   RabbitMQ   │  │ ConfigMap │    │
│  │ StatefulSet│  │  StatefulSet │  │ + Secrets │    │
│  │ (cluster) │  │  (cluster)   │  └───────────┘    │
│  └──────────┘   └──────────────┘                    │
│                                                      │
│  ┌─────────────────────────────────────┐            │
│  │ Monitoring: Prometheus + Grafana    │            │
│  └─────────────────────────────────────┘            │
└─────────────────────────────────────────────────────┘
```

---

## 9. Rust Crate Dependencies (Planned)

| Crate | Purpose |
|-------|---------|
| `actix-web` | HTTP server and REST API framework |
| `tonic` / `prost` | gRPC server and Protocol Buffers |
| `lapin` | AMQP client (RabbitMQ) |
| `surrealdb` | SurrealDB Rust SDK |
| `jsonwebtoken` | JWT creation and validation |
| `argon2` | Password hashing |
| `totp-rs` | TOTP generation and verification |
| `serde` / `serde_json` | Serialization |
| `utoipa` | OpenAPI spec generation from code |
| `tracing` | Structured logging and instrumentation |
| `config` | Configuration management |
| `thiserror` / `anyhow` | Error handling |
| `uuid` | Unique identifiers |
| `chrono` | Date/time handling |
| `rustls` | TLS support |

---

## 10. Configuration

AXIAM uses a layered configuration approach:

1. **Default values** compiled into the binary
2. **Configuration file** (`axiam.toml` or `axiam.yaml`)
3. **Environment variables** (`AXIAM_*` prefix) — override file values
4. **CLI arguments** — highest priority

Key configuration sections:
- `server` — bind address, ports (HTTP, gRPC), TLS settings
- `database` — SurrealDB connection URI, namespace, database name, credentials
- `amqp` — RabbitMQ connection URI, queue names, prefetch settings
- `auth` — JWT key paths, token lifetimes, password policy, MFA settings
- `oauth2` — issuer URL, supported grant types, default scopes
- `security` — rate limits, CORS origins, session settings
- `logging` — log level, format, output targets
