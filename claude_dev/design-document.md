# AXIAM — Design Document

## 1. Overview

AXIAM (Access eXtended Identity and Authorization Management) is an open-source IAM platform built with Rust and SurrealDB. It targets microservices and IoT environments, providing authentication, authorization, user management, federation, certificate/PKI management, and audit capabilities while maintaining compliance with GDPR, CyberSecurity Act, ISO 27001, OWASP ASVS, and OWASP Cumulus.

AXIAM is designed as a **multi-tenant** system. Organizations are the top-level entities, each containing one or more tenants. Tenants provide full data isolation — each tenant has its own users, roles, permissions, resources, and certificates. Organizations hold CA certificates that can sign tenant-level certificates, enabling a hierarchical trust model.

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
│                   API Gateway Layer                      │
│  ┌─────────────┐ ┌─────────────┐ ┌────────────────────┐  │
│  │  REST API   │ │  gRPC API   │ │  AMQP Consumer     │  │
│  │  (Actix-Web)│ │  (Tonic)    │ │  (Lapin)           │  │
│  └──────┬──────┘ └──────┬──────┘ └────────┬───────────┘  │
│         └───────────┬───┘                  │             │
│                     ▼                      ▼             │
│           ┌─────────────────────────────────┐            │
│           │      Middleware Pipeline        │            │
│           │ (Auth, Rate Limit, CORS, Audit) │            │
│           └──────────────┬──────────────────┘            │
└──────────────────────────┼───────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   Service Layer                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │
│  │ AuthN    │ │ AuthZ    │ │ User     │ │ Federation │   │
│  │ Service  │ │ Engine   │ │ Service  │ │ Service    │   │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │
│  │ Role     │ │ Resource │ │ Audit    │ │ OAuth2/    │   │
│  │ Service  │ │ Service  │ │ Service  │ │ OIDC       │   │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │
│  │ Tenant   │ │ PKI /    │ │ Webhook  │ │ GnuPG      │   │
│  │ Service  │ │ Cert Svc │ │ Service  │ │ Service    │   │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘   │
└──────────────────────────┬───────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────┐
│                   Data Access Layer                      │
│  ┌────────────────────────────────────────────────────┐  │
│  │           Repository Trait Abstractions            │  │
│  │  (UserRepo, RoleRepo, ResourceRepo, AuditRepo...)  │  │
│  └───────────────────────┬────────────────────────────┘  │
└──────────────────────────┼───────────────────────────────┘
                           ▼
┌───────────────────────────────────────────────────────────┐
│                   SurrealDB Cluster                       │
│  (Organizations, Tenants, Users, Groups, Roles,           │
│   Permissions, Resources, Certificates, Audit Logs,       │
│   Sessions, OAuth2 Clients, Federation Configs, Webhooks) │
└───────────────────────────────────────────────────────────┘
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
│   ├── axiam-pki/              # Certificate management, CA, GnuPG integration
│   └── axiam-server/           # Binary — composes all crates, starts server
├── proto/                      # Protocol Buffer definitions for gRPC
├── frontend/                   # React admin UI
├── docker/                     # Dockerfiles and compose configs
├── k8s/                        # Kubernetes manifests
└── sdks/                       # SDK projects (Rust, Python, TypeScript, Java, C#, PHP, Go)
```

---

## 3. Data Model

SurrealDB's document/graph hybrid model is leveraged for both entity storage and relationship traversal (e.g., resource hierarchies, role assignments).

### 3.1 Multi-Tenancy Model

AXIAM uses a two-level hierarchy for multi-tenancy:

```
┌──────────────────┐
│   Organization   │       ┌──────────────────┐
│                  │──1:N──│     Tenant       │
│ id               │       │                  │
│ name             │       │ id               │
│ slug             │       │ name             │
│ metadata         │       │ slug             │
│ created_at       │       │ organization_id  │
│ updated_at       │       │ metadata         │
└────────┬─────────┘       │ created_at       │
         │                 │ updated_at       │
         │ 1:N             └────────┬─────────┘
         ▼                          │
┌──────────────────┐                │ Scopes all entities below
│  CA Certificate  │                ▼
│ (org-level only) │     Users, Groups, Roles, Permissions,
│                  │     Resources, Service Accounts,
│ id               │     Sessions, OAuth2 Clients,
│ organization_id  │     Federation Configs, Certificates,
│ subject          │     Webhooks — all scoped to a tenant
│ public_cert (PEM)│
│ not_before       │
│ not_after        │
│ fingerprint      │
│ status           │
│ created_at       │
└──────────────────┘
```

- **Organization**: Top-level entity for centralized administration. Holds CA certificates used to sign tenant certificates. Represents a company, department, or business unit.
- **Tenant**: Provides full data isolation. All domain entities (users, roles, resources, etc.) belong to exactly one tenant. Tenants can represent environments (dev/staging/prod) or separate business contexts within an organization.
- **Tenant scoping**: Every tenant-scoped table includes a `tenant_id` field. All queries are filtered by tenant context, enforced at the repository layer. SurrealDB namespaces may additionally be leveraged for physical isolation in high-security deployments.

### 3.2 Entity-Relationship Diagram

```
┌──────────────┐       ┌──────────────┐        ┌──────────────┐
│    User      │──N:M──│    Role      │──N:M───│  Permission  │
│              │       │              │        │              │
│ id           │       │ id           │        │ id           │
│ tenant_id    │       │ tenant_id    │        │ tenant_id    │
│ username     │       │ name         │        │ action       │
│ email        │       │ description  │        │ description  │
│ password_hash│       │ is_global    │        └──────┬───────┘
│ mfa_secret   │       │ created_at   │               │
│ status       │       │ updated_at   │               │ N:M
│ metadata     │       └──────┬───────┘               │
│ created_at   │              │ N:M            ┌──────┴───────┐
│ updated_at   │              │                │   Resource   │
└──────┬───────┘       ┌──────┴───────┐        │              │
       │               │    Group     │        │ id           │
       │ N:M           │              │        │ tenant_id    │
       ├─────────────▶│ id           │        │ name         │
       │               │ tenant_id    │        │ type         │
       │ 1:N           │ name         │        │ parent_id    │
       ▼               │ description  │        │ metadata     │
┌──────────────┐       │ metadata     │        └──────┬───────┘
│   Session    │       │ created_at   │               │
│              │       │ updated_at   │               │ 1:N
│ id           │       └──────────────┘        ┌──────┴───────┐
│ tenant_id    │                               │    Scope     │
│ user_id      │                               │              │
│ token_hash   │                               │ id           │
│ ip_address   │                               │ tenant_id    │
│ user_agent   │                               │ resource_id  │
│ expires_at   │                               │ name         │
│ created_at   │                               │ description  │
└──────────────┘                               └──────────────┘

┌──────────────┐       ┌──────────────┐
│ServiceAccount│       │  AuditLog    │
│              │       │              │
│ id           │       │ id           │
│ tenant_id    │       │ tenant_id    │
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
│ tenant_id    │       │              │
│ client_id    │       │ id           │
│ client_secret│       │ tenant_id    │
│ name         │       │ provider     │
│ redirect_uris│       │ protocol     │
│ grant_types  │       │ metadata_url │
│ scopes       │       │ client_id    │
│ created_at   │       │ client_secret│
└──────────────┘       │ attribute_map│
                       │ enabled      │
┌──────────────┐       └──────────────┘
│ Certificate  │
│              │       ┌──────────────┐
│ id           │       │  Webhook     │
│ tenant_id    │       │              │
│ subject      │       │ id           │
│ public_cert  │       │ tenant_id    │
│ cert_type    │       │ url          │
│ issuer_ca_id │       │ events[]     │
│ not_before   │       │ secret       │
│ not_after    │       │ enabled      │
│ fingerprint  │       │ retry_policy │
│ status       │       │ created_at   │
│ metadata     │       └──────────────┘
│ created_at   │
└──────────────┘
```

### 3.3 SurrealDB Tables

| Table | Scope | Description |
|-------|-------|-------------|
| `organization` | Global | Top-level organizational entities |
| `tenant` | Global | Isolated tenant contexts within an organization |
| `ca_certificate` | Organization | CA certificates for signing tenant certificates |
| `user` | Tenant | User accounts with credentials and profile data |
| `group` | Tenant | Named collections of users for simplified role management |
| `service_account` | Tenant | Machine-to-machine accounts |
| `role` | Tenant | Named collections of permissions |
| `permission` | Tenant | Action definitions (e.g., `read`, `write`, `delete`) |
| `resource` | Tenant | Hierarchical resources (self-referencing `parent_id`) |
| `scope` | Tenant | Fine-grained sub-resource permissions |
| `session` | Tenant | Active user sessions |
| `audit_log` | Tenant | Immutable audit trail |
| `oauth2_client` | Tenant | Registered OAuth2/OIDC clients |
| `federation_config` | Tenant | External IdP configurations (SAML, OIDC) |
| `certificate` | Tenant | X.509 certificates for users, services, IoT devices |
| `webhook` | Tenant | Webhook endpoint registrations for event delivery |

### 3.4 SurrealDB Graph Edges (Relations)

| Edge | From | To | Description |
|------|------|----|-------------|
| `has_tenant` | `organization` | `tenant` | Organization-tenant membership |
| `member_of` | `user` | `group` | User-group membership |
| `has_role` | `user` / `service_account` / `group` | `role` | Role assignment, optionally scoped to a resource |
| `grants` | `role` | `permission` | Permissions included in a role |
| `on_resource` | `permission` | `resource` | Which resource a permission applies to |
| `child_of` | `resource` | `resource` | Resource hierarchy |
| `signed_by` | `certificate` | `ca_certificate` | Certificate chain of trust |

Using graph edges allows efficient traversal queries such as:
```surql
-- Direct role assignments
SELECT ->has_role->role->grants->permission->on_resource->resource
FROM user:$uid;

-- Roles inherited via group membership
SELECT ->member_of->group->has_role->role->grants->permission
FROM user:$uid;
```

### 3.5 Key Design Decisions

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
  │── POST /auth/login ──────▶│                         │
  │   {username, password}     │── Fetch user ─────────▶│
  │                            │◀── user record ────────│
  │                            │── Verify Argon2id       │
  │                            │── Check MFA required?   │
  │                            │                         │
  │ (if MFA not required)      │                         │
  │◀── {access_token,         │── Create session ─────▶│
  │     refresh_token} ────────│── Write audit log ────▶│
  │                            │                         │
  │ (if MFA required)          │                         │
  │◀── {mfa_challenge_token} ─│                         │
  │                            │                         │
  │─ POST /auth/mfa/verify ──▶│                         │
  │   {challenge_token, code}  │── Verify TOTP           │
  │◀── {access_token,         │── Create session ─────▶│
  │     refresh_token} ────────│── Write audit log ────▶│
```

### 4.2 OAuth2 Authorization Code Flow

```
Client              AXIAM (AuthZ Server)       Resource Server
  │                              │                     │
  │── GET /oauth2/authorize ───▶│                     │
  │   (client_id, scope,         │                     │
  │    redirect_uri, state)      │                     │
  │                              │                     │
  │◀── Login page ──────────────│                     │
  │── Authenticate ────────────▶│                     │
  │◀── Consent screen ──────────│                     │
  │── Approve ─────────────────▶│                     │
  │◀── Redirect with code ──────│                     │
  │                              │                     │
  │── POST /oauth2/token ──────▶│                     │
  │   (code, client_secret)      │                     │
  │◀── {access_token, id_token}─│                     │
  │                              │                     │
  │── API call + Bearer token ───┼───────────────────▶│
  │                              │                     │── Validate JWT
  │◀── Response ────────────────┼─────────────────────│
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
  │  authz.request queue ────▶│                         │
  │                            │── Deliver ────────────▶│
  │                            │                         │── Evaluate authz
  │                            │                         │── Write audit log
  │                            │◀── Publish to          │
  │◀── Consume from           │    authz.response ──────│
  │    authz.response ─────────│                         │
```

---

## 5. Authorization Engine

### 5.1 Permission Resolution Algorithm

When evaluating whether a subject can perform an action on a resource:

1. **Fetch direct roles**: Get all roles assigned directly to the subject
1b. **Fetch group roles**: Get roles from all groups the subject belongs to
2. **Filter by resource scope**: Keep global roles + roles assigned on the target resource or any ancestor in the hierarchy
3. **Collect permissions**: Union of all permissions from the matching roles
4. **Check scopes**: If the permission requires specific scopes, verify they are present
5. **Apply inheritance**: Walk up the resource tree — a role on a parent grants access to children (additive-only, allow-wins; there is no explicit deny-override mechanism in v1.0-beta; deny-override cascade is deferred to post-v1.0-beta)
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

## 6. Certificate Management & PKI

AXIAM provides a hierarchical PKI (Public Key Infrastructure) for secure authentication, identity signing, and encrypted communication.

### 6.1 Certificate Hierarchy

```
Organization CA Certificate (root of trust)
├── Tenant Certificate A (signed by Org CA)
│   ├── User Certificate (signed by Tenant A cert)
│   ├── Service Certificate (signed by Tenant A cert)
│   └── IoT Device Certificate (signed by Tenant A cert)
└── Tenant Certificate B (signed by Org CA)
    └── ...
```

### 6.2 Certificate Lifecycle

| Operation | Level | Description |
|-----------|-------|-------------|
| **Generate CA** | Organization | Create a new CA keypair; private key returned once for download, never stored |
| **Upload CA** | Organization | Import an existing CA certificate (public cert only) |
| **Generate Cert** | Tenant | Create a certificate signed by the organization CA; private key returned once |
| **Upload Cert** | Tenant | Import an externally-issued certificate |
| **Revoke** | Any | Mark a certificate as revoked; propagates to CRL |
| **Rotate** | Any | Issue a new certificate and revoke the old one |

### 6.3 Private Key Handling

AXIAM follows a **zero-knowledge** approach to private keys:
- On certificate generation, the private key is returned **once** in the API response
- AXIAM **never stores** private keys — only public certificates and metadata
- Exception: CA certificates used for signing identity tokens require the private key to be available. In this case, the key is encrypted with AES-256-GCM and stored in a separate, access-controlled table

### 6.4 IoT Device Identity

For IoT platforms, AXIAM supports certificate-based device authentication:
- Devices are provisioned with a certificate signed by the tenant's CA
- mTLS (mutual TLS) is used for device-to-AXIAM communication
- Device certificates can be bound to service accounts for RBAC
- Certificate revocation immediately invalidates device access

---

## 7. GnuPG Integration

AXIAM integrates with GnuPG (GNU Privacy Guard) for data encryption and signing based on the OpenPGP standard.

### 7.1 Use Cases

| Use Case | Description |
|----------|-------------|
| **Audit log signing** | Each audit log batch is signed with the tenant's GnuPG key, providing tamper-evidence |
| **Data export encryption** | GDPR data exports can be encrypted with the requesting user's PGP public key |
| **Credential encryption** | Sensitive configuration values (e.g., federation secrets) encrypted at rest |
| **Identity attestation** | Users and service accounts can register PGP public keys for signed identity assertions |

### 7.2 Key Management

- GnuPG keys are managed per-tenant
- Public keys are stored in AXIAM; private keys follow the same zero-knowledge approach as X.509
- Key generation produces an OpenPGP keypair; the private key is returned once for download
- Key revocation is supported via revocation certificates

---

## 8. Webhook System

AXIAM supports webhook delivery for real-time event notifications to external systems.

### 8.1 Webhook Events

| Event Category | Events |
|---------------|--------|
| **User** | `user.created`, `user.updated`, `user.deleted`, `user.locked` |
| **Auth** | `auth.login`, `auth.logout`, `auth.mfa_enrolled`, `auth.failed` |
| **Group** | `group.created`, `group.updated`, `group.deleted`, `group.member_added`, `group.member_removed` |
| **Role** | `role.created`, `role.updated`, `role.deleted`, `role.assigned`, `role.unassigned` |
| **Resource** | `resource.created`, `resource.updated`, `resource.deleted` |
| **Certificate** | `cert.issued`, `cert.revoked`, `cert.expiring` |
| **OAuth2** | `oauth2.client_created`, `oauth2.token_issued`, `oauth2.token_revoked` |

### 8.2 Delivery Mechanism

- Webhooks are delivered via HTTPS POST with HMAC-SHA256 signature in headers
- Failed deliveries are retried with exponential backoff (configurable per webhook)
- Delivery status is logged in the audit trail
- Webhook payloads include event type, timestamp, tenant context, and event-specific data

---

## 8a. Hierarchical Settings & Policy Engine

AXIAM supports configurable security settings at both organization and tenant levels with a hierarchical inheritance model.

### 8a.1 Hierarchical Inheritance Model

Settings follow a strict inheritance rule: **tenants can only override organization-level settings with more restrictive values**. This applies recursively along the hierarchy.

```
Organization Settings (baseline)
├── Tenant A Settings (can only be MORE restrictive)
├── Tenant B Settings (can only be MORE restrictive)
└── Tenant C (inherits org defaults — no overrides)
```

Examples:
- If the org requires minimum password length 10, a tenant can set 12 but not 8
- If the org requires MFA, a tenant cannot disable it
- If the org sets password history to 5, a tenant can set 10 but not 3

### 8a.2 Configurable Settings

| Setting | Type | Scope | Default |
|---------|------|-------|---------|
| `password_min_length` | u32 | Org/Tenant | 12 |
| `password_require_uppercase` | bool | Org/Tenant | true |
| `password_require_lowercase` | bool | Org/Tenant | true |
| `password_require_digits` | bool | Org/Tenant | true |
| `password_require_symbols` | bool | Org/Tenant | false |
| `password_history_count` | u32 | Org/Tenant | 5 |
| `password_hibp_check` | bool | Org/Tenant | false |
| `mfa_required` | bool | Org/Tenant | false |
| `email_verification_required` | bool | Org/Tenant | false |
| `email_verification_grace_hours` | u32 | Org/Tenant | 24 |
| `max_certificate_validity_days` | u32 | Org/Tenant | 365 |
| `admin_notifications_enabled` | bool | Org/Tenant | false |

### 8a.3 Password Policy

Password policies are enforced at org/tenant level and are **not applicable** for federated or social login users.

- **Complexity rules**: Configurable requirements for uppercase, lowercase, digits, and symbols
- **Password history**: New passwords must differ from the last N passwords (configurable)
- **Breach detection**: Optional integration with the Have I Been Pwned (HIBP) API to reject passwords found in known breaches (k-Anonymity model — only a 5-character SHA-1 prefix is sent, preserving privacy)
- **Minimum length**: OWASP ASVS recommends minimum 8, NIST SP 800-63B recommends minimum 8 with no maximum; AXIAM defaults to 12

---

## 8b. Email Service

AXIAM provides a pluggable email delivery service for transactional emails (verification, password reset, admin notifications).

### 8b.1 Supported Providers

| Provider | Protocol | Notes |
|----------|----------|-------|
| **SMTP** | SMTP over TLS | Private SMTP server, TLS required |
| **SendGrid** | REST API | API key authentication |
| **Postmark** | REST API | Server token authentication |
| **Resend** | REST API | API key authentication |
| **Brevo** | REST API | API key authentication |

Provider configuration is set at org level; tenants inherit but can override with their own provider.

### 8b.2 Email Templates

- Templates are customizable at organization or tenant level
- Standard placeholders available: `{{username}}`, `{{email}}`, `{{tenant_name}}`, `{{org_name}}`, `{{action_url}}`, `{{expiry_time}}`
- Default templates provided for: activation, password reset, MFA setup reminder, admin notification
- Templates support HTML and plaintext variants

### 8b.3 Mail Verification Flow

When email verification is enforced (org/tenant setting), the following flow applies:

```
User Registration
  │
  ├── Send activation email with confirmation token (24h expiry)
  │
  ├── Grace period: 24 hours to confirm
  │   └── User can log in during grace period
  │
  ├── After 24h without confirmation:
  │   └── Account is LOCKED
  │       └── Locked user can request new confirmation email (max 2/day)
  │
  └── On confirmation:
      └── Account status set to ACTIVE
```

**Not applicable** for federated or social login users.

### 8b.4 Password Reset Flow

```
User                      AXIAM                    Email Provider
  │                         │                           │
  │── POST /auth/reset ───▶│                           │
  │   {email}               │── Generate reset token    │
  │                         │── Send reset email ─────▶│
  │◀── 200 OK               │                           │
  │                         │                           │
  │── (click link) ────────▶│                           │
  │── POST /auth/reset/     │                           │
  │   confirm               │                           │
  │   {token, new_password} │── Validate token          │
  │                         │── Apply password policy   │
  │                         │── Reset fail2ban counter  │
  │                         │── Update password hash    │
  │◀── 200 OK               │                           │
```

Password reset **resets the fail2ban login counter**, allowing the user to log in again. **Not applicable** for federated or social login users.

---

## 8c. Advanced MFA

AXIAM extends its MFA capabilities with organizational enforcement, WebAuthn/FIDO2 support, and multi-method management.

### 8c.1 MFA Enforcement

When MFA is enforced at org/tenant level:
- On first login, the user is redirected to MFA setup (TOTP, passkey, or hardware key)
- The user cannot access any resource until MFA is configured
- If MFA setup fails (e.g., device issue), only org/tenant admins can reset the user's MFA state, allowing them to retry the first-login MFA registration
- **Not applicable** for federated or social login users

### 8c.2 WebAuthn / FIDO2

AXIAM supports passkeys and hardware security keys via the WebAuthn standard:

| Type | Examples | Use Case |
|------|----------|----------|
| **Passkeys** | 1Password, Bitwarden, Android device, iCloud Keychain | Passwordless or second-factor authentication from any synced device |
| **Hardware Keys** | YubiKey, NitroKey, SoloKeys | Physical second-factor for high-security environments |

WebAuthn registration and authentication flow:
```
Registration:
  Client ──▶ navigator.credentials.create() ──▶ AXIAM verifies attestation ──▶ Store credential

Authentication:
  Client ──▶ navigator.credentials.get() ──▶ AXIAM verifies assertion ──▶ Login success
```

### 8c.3 Multi-MFA Management

- A user can register **multiple MFA methods** (e.g., TOTP + YubiKey + passkey)
- Any registered method can be used for authentication
- Admins can view which methods a user has configured (but not secrets)
- Users manage their MFA methods via the user identity page

### 8c.4 Admin Notifications

Organizations and tenant admins can subscribe to email notifications for critical or suspicious events:

| Event Category | Examples |
|---------------|----------|
| **Security** | Repeated login failures, account lockouts, brute-force attempts |
| **Access** | Privilege escalation, role changes on sensitive resources |
| **Compliance** | Certificate expiry warnings, audit log signing failures |
| **User Lifecycle** | User creation/deletion, MFA enrollment/reset, password changes |

Notification rules are configurable per org/tenant. Notifications are delivered via the email service (Section 8b).

---

## 9. API Design

### 9.1 REST API Endpoints (Summary)

All tenant-scoped endpoints are prefixed with `/api/v1/tenants/:tenant_id/` or use tenant context from the authenticated session.

| Group | Endpoints | Description |
|-------|-----------|-------------|
| **Organizations** | `GET/POST/PUT/DELETE /api/v1/organizations` | Organization CRUD |
| **Tenants** | `GET/POST/PUT/DELETE /api/v1/organizations/:org_id/tenants` | Tenant management |
| **Auth** | `POST /auth/login`, `POST /auth/logout`, `POST /auth/refresh`, `POST /auth/mfa/*` | Authentication flows |
| **Users** | `GET/POST/PUT/DELETE /api/v1/users` | User CRUD |
| **Groups** | `GET/POST/PUT/DELETE /api/v1/groups`, `POST/DELETE /api/v1/groups/:id/members` | Group management and membership |
| **Roles** | `GET/POST/PUT/DELETE /api/v1/roles` | Role management |
| **Permissions** | `GET/POST/PUT/DELETE /api/v1/permissions` | Permission definitions |
| **Resources** | `GET/POST/PUT/DELETE /api/v1/resources` | Resource hierarchy management |
| **Service Accounts** | `GET/POST/PUT/DELETE /api/v1/service-accounts` | Service account management |
| **Certificates** | `GET/POST/DELETE /api/v1/certificates`, `POST /api/v1/certificates/:id/revoke` | Certificate lifecycle management |
| **CA Certificates** | `GET/POST/DELETE /api/v1/organizations/:org_id/ca-certificates` | Organization CA management |
| **Webhooks** | `GET/POST/PUT/DELETE /api/v1/webhooks` | Webhook endpoint management |
| **OAuth2** | `/oauth2/authorize`, `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect` | OAuth2 endpoints |
| **OIDC** | `/.well-known/openid-configuration`, `/oauth2/userinfo`, `/oauth2/jwks` | OpenID Connect discovery and endpoints |
| **Federation** | `GET/POST/PUT/DELETE /api/v1/federation` | IdP configuration management |
| **Audit** | `GET /api/v1/audit-logs` | Audit log query (read-only) |
| **Settings** | `GET/PUT /api/v1/organizations/:org_id/settings`, `GET/PUT /api/v1/settings` | Org/tenant security settings |
| **Password Reset** | `POST /auth/reset`, `POST /auth/reset/confirm` | Email-based password reset flow |
| **Mail Verification** | `POST /auth/verify-email`, `POST /auth/resend-verification` | Email confirmation flow |
| **WebAuthn** | `POST /auth/webauthn/register`, `POST /auth/webauthn/authenticate` | Passkey and hardware key flows |
| **MFA Management** | `GET/DELETE /api/v1/users/:id/mfa-methods` | Multi-MFA method management |
| **Admin Notifications** | `GET/POST/PUT/DELETE /api/v1/notification-rules` | Admin notification subscriptions |
| **Health** | `GET /health`, `GET /ready` | Health and readiness probes |

### 9.2 gRPC Services

| Service | Methods | Description |
|---------|---------|-------------|
| `AuthorizationService` | `CheckAccess`, `BatchCheckAccess` | Real-time authz decisions |
| `UserService` | `GetUser`, `ValidateCredentials` | User lookups for inter-service use |
| `TokenService` | `ValidateToken`, `IntrospectToken` | Token validation for service mesh |

### 9.3 AMQP Queues

| Queue | Direction | Description |
|-------|-----------|-------------|
| `axiam.authz.request` | Inbound | Async authorization check requests |
| `axiam.authz.response` | Outbound | Authorization decision responses |
| `axiam.audit.events` | Inbound | Audit events from external services |
| `axiam.notifications` | Outbound | Real-time event notifications (role changes, user creation, etc.) |

---

## 10. Security Measures

### 10.1 Cryptography

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Password hashing | Argon2id | OWASP-recommended params (memory: 19 MiB, iterations: 2, parallelism: 1) |
| JWT signing | EdDSA (Ed25519) | Short-lived access tokens (15 min default) |
| Refresh tokens | Opaque, server-stored | Rotation on use, single-use |
| MFA secrets | AES-256-GCM encrypted at rest | TOTP per RFC 6238 |
| TLS | TLS 1.3 minimum | For all external communication |
| Client secrets | HMAC-SHA256 hashed | Never stored in plaintext |
| CA private keys | AES-256-GCM encrypted at rest | Only stored for signing CAs; user-generated CAs not stored |
| X.509 certificates | RSA-4096 or Ed25519 | Configurable key type per tenant |
| GnuPG keys | OpenPGP (Ed25519/RSA-4096) | Public keys stored; private keys returned once on generation |
| Webhook signatures | HMAC-SHA256 | Shared secret per webhook endpoint |

### 10.2 Security Controls

- **Rate limiting**: Per-IP and per-user on authentication endpoints
- **CSRF protection**: Double-submit cookie pattern for browser-based flows
- **CORS**: Configurable allowed origins, strict defaults
- **Input validation**: All inputs validated and sanitized at the API boundary
- **SQL injection**: Parameterized queries only (SurrealDB prepared statements)
- **XSS**: Content-Security-Policy headers; React handles output encoding
- **Brute force protection**: Account lockout after N failed attempts, with exponential backoff
- **Session security**: Secure, HttpOnly, SameSite cookies; session invalidation on password change
- **Audit immutability**: Audit log table has no UPDATE/DELETE permissions
- **Password policy**: Configurable complexity, history, and breach detection (HIBP) at org/tenant level
- **MFA enforcement**: Org/tenant-level mandatory MFA with first-login setup flow
- **WebAuthn/FIDO2**: Passkeys and hardware security keys for phishing-resistant authentication
- **Email verification**: Confirmation tokens with 24h grace period and resend limits
- **Hierarchical settings**: Tenant settings can only be more restrictive than organization settings

### 10.3 Compliance Mapping

| Standard | Relevant AXIAM Features |
|----------|------------------------|
| GDPR | User data export/deletion, consent tracking, audit logs, data minimization |
| ISO 27001 | Access control (A.9), cryptography (A.10), audit logging (A.12) |
| OWASP ASVS | Password requirements (V2), session management (V3), access control (V4) |
| CyberSecurity Act | Secure by design, vulnerability management, incident logging |

---

## 11. Deployment Architecture

### 11.1 Development (Docker Compose)

```
┌──────────────────────────────────────────┐
│              docker-compose              │
│  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │  AXIAM   │  │ SurrealDB│  │ RabbitMQ│ │
│  │  Server  │──│  (single)│  │         │ │
│  │  :8080   │  │  :8000   │  │  :5672  │ │
│  └──────────┘  └──────────┘  └─────────┘ │
└──────────────────────────────────────────┘
```

### 11.2 Production (Kubernetes)

```
┌──────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                 │
│                                                      │
│  ┌──────────┐   ┌───────────────────┐                │
│  │ Ingress  │──▶│ AXIAM Deployment │                │
│  │ (TLS)    │   │ (N replicas, HPA) │                │
│  └──────────┘   └────────┬──────────┘                │
│                          │                           │
│         ┌────────────────┼────────────────┐          │
│         ▼                ▼                ▼          │
│  ┌─────────────┐ ┌──────────────┐  ┌───────────┐     │
│  │ SurrealDB   │ │   RabbitMQ   │  │ ConfigMap │     │
│  │ StatefulSet │ │  StatefulSet │  │ + Secrets │     │
│  │ (cluster)   │ │  (cluster)   │  └───────────┘     │
│  └─────────────┘ └──────────────┘                    │
│                                                      │
│  ┌─────────────────────────────────────┐             │
│  │ Monitoring: Prometheus + Grafana    │             │
│  └─────────────────────────────────────┘             │
└──────────────────────────────────────────────────────┘
```

---

## 12. Rust Crate Dependencies (Planned)

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
| `rcgen` | X.509 certificate generation |
| `x509-parser` | X.509 certificate parsing and validation |
| `pgp` / `sequoia-openpgp` | GnuPG/OpenPGP key management and signing |
| `reqwest` | HTTP client for webhook delivery and HIBP API |
| `webauthn-rs` | WebAuthn/FIDO2 server implementation |
| `lettre` | SMTP email sending |
| `tera` / `handlebars` | Email template rendering |

---

## 13. Configuration

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
- `pki` — CA key encryption settings, certificate defaults (validity, key size), CRL configuration
- `webhooks` — delivery timeout, retry policy, max concurrent deliveries
- `gnupg` — key storage settings, signing algorithm preferences
- `email` — provider (smtp/sendgrid/postmark/resend/brevo), SMTP host/port/TLS, API keys, from address
- `notifications` — admin notification defaults, delivery batch size
- `logging` — log level, format, output targets
