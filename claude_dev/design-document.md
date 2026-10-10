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
- **Record identifiers**: UUIDv7 (`axiam_core::id::new_id`) for every persisted entity id. Record ids are the primary key in SurrealDB's ordered KV engine (`surrealkv:`/`file:`), so v7's leading 48-bit millisecond timestamp keeps time-adjacent inserts physically adjacent instead of scattering them across the keyspace as v4 does. Ids are stored as hyphenated strings, whose lexicographic order matches the byte order, so the locality survives the encoding. **Secrets never use v7**: session/download/reset/cancel tokens and generated passwords stay on a CSPRNG, because v7 spends 48 bits on a timestamp and its per-millisecond monotonic counter leaves same-millisecond ids sharing a long common prefix — ample for uniqueness, useless for secrecy.

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

### 4.5 Logout

What ships (B5; the discovery fields below are advertised by
`crates/axiam-oauth2/src/oidc.rs`):

- **RP-Initiated Logout 1.0** — `GET`/`POST /oauth2/end_session`, advertised as
  `end_session_endpoint`. It ends the session named by `id_token_hint` (or the
  browser's own AXIAM cookie when there is no verifiable hint) and redirects
  only to an exact match against the client's `post_logout_redirect_uris`.
- **Back-Channel Logout 1.0** — on logout AXIAM POSTs a signed logout token to
  each participating client's registered `backchannel_logout_uri` (one token per
  client, `sid` always present, 120 s lifetime). Discovery advertises
  `backchannel_logout_supported` and `backchannel_logout_session_supported`,
  both `true`.
- **Revocation feed** — `GET /oauth2/revocations` (opt-in via
  `AXIAM__AUTH__REVOCATION_FEED_ENABLED`) lets a resource server or SDK route
  guard reject a revoked session within one poll interval. It narrows a
  residual window; it is not a control.

#### Front-channel logout — declined (D-6, 2026-10-02)

**Decision.** AXIAM does not implement OIDC Front-Channel Logout 1.0 (gap G-12,
[remediation plan](competitor-gap-remediation-plan-2026-10-02.md)). Discovery
does not advertise `frontchannel_logout_supported` or
`frontchannel_logout_session_supported`, and the client model has no
`frontchannel_logout_uri`.

**What it is.** On logout the OP renders a page containing one iframe per
participating RP, each pointing at that RP's `frontchannel_logout_uri`, and
relies on the browser sending the RP's session cookie with the iframe request so
the RP can clear its own session.

**Why it is declined.** The mechanism needs the RP's cookie to travel in a
third-party iframe request. Safari (Intelligent Tracking Prevention), Firefox
(Total Cookie Protection) and Chrome's third-party cookie restrictions block or
partition exactly that, so the RP does not see its session cookie and the logout
silently does nothing. The OP cannot observe the failure: the iframe loads, the
OP shows "logged out", and the RP session survives. That is a false sense of
logout, which is worse than no feature.

**What to use instead.** Back-channel logout: a server-to-server signed logout
token that does not depend on the browser, cookies or iframes, and whose
delivery the OP performs itself rather than delegating to the user agent. For resource servers and route guards that
need a bounded revocation window, poll `GET /oauth2/revocations`.

**Reopen condition.** A concrete adopter request. Not a competitor comparison:
Keycloak and authentik offer the feature, and that alone does not reopen it.

#### SAML single logout

AXIAM as a SAML identity provider has its own logout, through the browser and signed at both ends; it ends the AXIAM session first and then the SAML service providers that hold it, and is described in [§8e.5](#8e5-single-logout). The OIDC endpoints above do not run it.

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
| **Revoke** | Any | Mark a certificate as revoked: its status in AXIAM's store, checked when AXIAM authenticates a device by its certificate (not at the TLS handshake, nor for OAuth2 `tls_client_auth`) |
| **Rotate** | Any | Issue a new certificate and revoke the old one |

**Revocation reaches only AXIAM's device sign-in.** AXIAM publishes no
certificate revocation list and runs no OCSP responder: its CAs carry the
`cRLSign` key-usage bit, and nothing serves a list. `DeviceAuthService`
reads a certificate's status, and every CA's on its chain, on each
authentication, so a revocation takes effect at once for device sign-in by
certificate. Nothing else reads it: neither listener's TLS handshake checks
revocation, and OAuth2 `tls_client_auth` matches the client's registered subject
DN or SAN, so a revoked AXIAM-issued leaf keeps authenticating its OAuth2 client
until it expires or the registration changes (corrected by the W6 F4 review). A
relying party that validates AXIAM-issued certificates itself — a
FreeRADIUS server doing EAP-TLS, a VPN gateway, a peer service terminating its
own mTLS — has no revocation channel, and honours a revoked certificate until it
expires; the bound is the tenant's `max_cert_validity_days`. Earlier revisions of
this table said revocation "propagates to CRL"; there has never been one.
Publishing a CRL per issuing CA is tracked by
[ilpanich/axiam#565](https://github.com/ilpanich/axiam/issues/565) (item D1 of
[`radius-eap-tls-spike-2026-10-06.md`](radius-eap-tls-spike-2026-10-06.md));
threat T-102 in [`threat-model-stride.md`](threat-model-stride.md) stays open
until it is.

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

**One mail per rule, event and window** (`1.0.0`, #551, T-117). Each rule has a window, `window_minutes` (1 to 1440, 15 by default; the API refuses a value outside the bounds). `NotificationDispatcher` claims the window of (tenant, rule, event) before it publishes: the first event of a window mails each of the rule's recipients, every later one inside it is counted and not mailed, and the first mail after the window carries the count (`suppressed_count`, with a sentence in `window_note`, both rendered by the built-in template). The claim is one conditional `UPSERT` on `notification_window` (schema v85; one row per triple, deleted with its rule), retried on a write conflict, so every replica sees the same window; a claim that fails mails nobody. A background process's event — today `scim_delivery_failed` — keeps the `NotificationGate` its producer applies (one per target per hour, D-73) and is not windowed again. The count of a burst is reported when that event next occurs; the audit log keeps every row.

---

## Federation, Provisioning and Signals (Phase 23)

Chapters 8d … 8j record what Phase 23, the competitor-gap closure of [`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md), built, one chapter per item:

- [8d](#8d-directory-identity-source-ldap--active-directory) — LDAP / Active Directory as an identity source (G-3)
- [8e](#8e-saml-20-identity-provider) — the SAML 2.0 identity provider (G-2)
- [8f](#8f-rfc-7592-client-configuration) — RFC 7592 client configuration (G-4)
- [8g](#8g-shared-signals-framework-transmitter) — the Shared Signals Framework transmitter, and the outbound dispatcher it shares with webhooks, SCIM and CIBA (G-5)
- [8h](#8h-outbound-scim-provisioning) — outbound SCIM provisioning (G-6)
- [8i](#8i-ciba-client-initiated-backchannel-authentication) — CIBA (G-7)
- [8j](#8j-the-minimal-deployment-profile-no-broker) — the minimal deployment profile, without a broker (G-8)

Two items have a document and no chapter, because nothing was built:

- G-9, verifiable credentials (OID4VCI issuer, OID4VP verifier) — design only; building waits for its go/no-go criterion, specification stability and one concrete adopter: [`verifiable-credentials-design.md`](verifiable-credentials-design.md)
- G-11, RADIUS and EAP-TLS — the spike and its decision (D-77: native front end declined): [`radius-eap-tls-spike-2026-10-06.md`](radius-eap-tls-spike-2026-10-06.md)

---

## 8d. Directory Identity Source (LDAP / Active Directory)

A tenant can federate an existing LDAP or Active Directory server (competitor-gap item **G-3**, Phase 23): users sign in with their directory password, accounts are provisioned just in time, and directory groups map onto AXIAM groups, so roles and permissions keep working. AXIAM is **read-only** against the directory and has no Kerberos / SPNEGO path. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8), the wire contract in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §30, the operator's view in [`docs/deployment/README.md`](../docs/deployment/README.md), the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-291 … T-303, T-331 … T-355).

### 8d.1 Placement

`axiam-directory` is a layer-3 crate beside `axiam-federation` (a federation protocol with the same dependency shape), placed in the layering table and [`crate-layering.md`](crate-layering.md) in the commit that created it, and opted into `missing_docs` from its first commit. It uses `ldap3` over `rustls` (no OpenSSL) and has no feature flag. The sign-in path, which lives in `axiam-auth` (layer 1), reaches it through ports declared in `axiam-core` (`DirectoryAuthenticator`, `DirectoryGroupMapper`, `DirectoryAuditSink`) that `axiam-server` implements and injects, so no production dependency points outward. `axiam-api-rest` (layer 6) depends on the crate only to call its validation and address guard on a write.

### 8d.2 Configuration and the bind secret

One `directory_config` row per tenant (schema v70, group mappings v74): URL (`ldaps://`, or `ldap://` with StartTLS — plaintext is refused), bind DN, base DN, the user-filter template (one `{username}`, in value position), the attribute map, group search base, filter and member attribute, nesting depth, the mapping table, sync interval, `jit_provisioning` and per-tenant trust anchors. `kind` (`open_ldap` | `active_directory`) chooses **defaults only**.

The bind secret is encrypted at rest in the row with AES-256-GCM, a fresh nonce per write, under the optional deployment key `directory_encryption_key`, exactly as the per-tenant SMTP password is ([D-15](competitor-gap-remediation-plan-2026-10-02.md)). It is **write-only through every interface**: no read returns it, no response type has a member for it, a flag that says one is set, or a hash of it, request bodies `Debug`-print `[REDACTED]`, and only `decrypt_bind_secret` — called at bind time — yields the plaintext. Without the key the feature is unavailable: a write that carries a secret is `503`, while reads, `DELETE` and the sync status still work.

### 8d.3 Sign-in: the bind path

```
POST /auth/login ──▶ AXIAM lockout (brute-force counters, in front of the directory)
                      │  account carries directory_external_id?
                      ▼
                    service bind (bind_dn, pooled, bounded per tenant)
                      │  search base_dn with the RFC 4515-escaped login name → exactly one entry
                      ▼
                    bind AS that entry with the typed password (fresh connection, never pooled)
                      │  success only if the entry's id equals the account's marker
                      ▼
                    group mapping (D-30) → session / MFA proceed as for any user, amr = [pwd]
```

A directory account is marked by one column, `user.directory_external_id` (`entryUUID` or `objectGUID`, schema v71, unique per tenant; [D-18](competitor-gap-remediation-plan-2026-10-02.md), amended by D-29): the directory is then the **only** authority for its password. There is **no fallback to a local hash**; every local password door (change, reset request and confirm, OPAQUE login and enrolment, the SCIM password write, gRPC `ValidateCredentials`) refuses such an account. Only an invalid-credentials answer moves the AXIAM counter, a locked account never reaches the directory (AXIAM cannot be used to lock accounts in AD), every failure is the generic sign-in failure at the cost of the dummy Argon2id verify, and an empty password is refused before any packet is sent. Filters are built through one escape function and never by formatting; referrals are neither followed nor matched; TLS is mandatory, verified against the tenant's anchors (or the public roots, never both) with the URL's host as the name.

### 8d.4 Just-in-time provisioning

With `jit_provisioning` on, a first successful sign-in for a name that matches **no local account** creates one in a single write: `Active` (the directory vouches for it), marked, holding an unusable password hash. Profile values from the entry are cleaned, not repaired (control and bidirectional characters, length), and an entry **without a usable e-mail address is refused** with the generic failure and a `directory.jit_refused` audit row, because a placeholder would be released as a `NameID` and as the OIDC `email` ([D-29](competitor-gap-remediation-plan-2026-10-02.md)). JIT **never links** a colliding local account ([D-28](competitor-gap-remediation-plan-2026-10-02.md)): a directory administrator cannot take over `admin` by creating a matching entry.

### 8d.5 Linking an existing account

Linking is the explicit administrator act (`POST …/directory/links`, permission `directory:link`): the directory resolves the entry from the account's own username, the account is marked, and everything it held that authenticates without the directory deciding is retired — passkeys deleted, federation links deleted (F4 P23W3-01), `User`-type certificates revoked (by the D-29 convention, since no certificate is bound to a user), then all sessions and OAuth2 refresh tokens, last, so anything issued before the mark is swept. TOTP is kept. The order is safe to stop in and to retry; a repeat on an account already linked to that entry is `200` with `was_already_linked`. There is no unlink.

### 8d.6 Group mapping

An explicit table only: `{ directory_group_dn, group_id }`, at most 500, every group of the same tenant, DNs compared after RFC 4514 normalisation ([D-30](competitor-gap-remediation-plan-2026-10-02.md)). No match by name, no AXIAM group created from a directory one. The mapping **owns only the memberships it made** (`member_of.source = directory`, schema v74) and never touches one added by hand. Resolution is `memberOf` (AD) or a reverse `member` search (OpenLDAP), nested to `group_nesting_depth` with cycle detection and a hard cap of 1 000 groups, over the service connection. It runs on every successful directory sign-in before the session is issued, and by the sync job; a lookup that fails or hits a cap **refuses the sign-in** rather than keep memberships that may have been revoked. A change flushes the authorization decision cache for the user.

### 8d.7 The sync job

A job on the cleanup scheduler (`directory_sync` in job health), one tenant at a time, only for enabled directories ([D-31](competitor-gap-remediation-plan-2026-10-02.md)). A **full run** (first, every 24 h, and after any skipped account) looks up every marked account by its immutable id and is the only run that concludes "vanished"; an **incremental run** reads `modifyTimestamp` / `uSNChanged` from a watermark (AD: `highestCommittedUSN`, with a fall-back to full on a `dsServiceName` change). A vanished or directory-disabled account becomes **`Inactive`** — never `Deleted`, never a hard delete — with its sessions revoked and its directory-sourced memberships removed. Sync **never re-enables, creates or links**. A full run that would deactivate more than 10 % of the tenant's directory accounts (and at least 5) applies nothing and reports `safety_valve`. State (watermark, server, last result) is the per-tenant `directory_sync_state` row (schema v75), deleted with its configuration and its tenant.

### 8d.8 The connector: address guard and frame cap

A tenant administrator chooses the host, so the connector holds it to a deployment rule before it opens a socket ([D-19, D-32](competitor-gap-remediation-plan-2026-10-02.md); T-300, T-295, T-331). The host is resolved **once**; loopback, unspecified, link-local (the metadata address included), multicast, special-purpose and IPv4-mapped forms are always refused, as are AXIAM's own listeners and IPv6-literal URLs; a private address needs `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`. The socket is connected to the vetted address while TLS checks the host name, so a rebinding name cannot reach loopback. Because `ldap3` does its own TLS, a frame cap beneath it would see ciphertext: AXIAM performs StartTLS and the handshake itself and hands `ldap3` one end of a Unix socket pair, a **relay** that checks each directory message (declared length against `AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`, well-formed, bounded depth) before forwarding it.

### 8d.9 The management surface

Six routes under `/api/v1/tenants/{tenant_id}/directory` (contract §30, OpenAPI tag `directory`, the §27 namespace `directory`): `GET`, `PUT` (replace), `PATCH` (sparse), `DELETE`, `POST …/links`, `GET …/sync-status`; permissions `directory:read`, `directory:write` and `directory:link`; a human administrator only (no service-account token); the caller's own tenant only. **Every write**, in order: `503` if it carries a secret and there is no key; `axiam_directory::config::validate`; the address guard on the URL as written, for a write whose resulting configuration is enabled (so a re-pointed name is caught by an unrelated write, while a directory can always be switched off — D-33); the **P23W2-01 rule** — moving the URL, StartTLS, bind DN or trust anchors without the secret is a `400`, checked against the stored row in the same statement as the write; and a `409` if an enabled directory would sit under an effective `opaque_mode = required` (the settings writes refuse the other direction). The four writes share a per-IP rate-limit bucket (`AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN`, 30). Audit rows `directory.config_created` / `_updated` / `_deleted` record the actor, the **names** of the changed fields, `connection_moved`, `secret_replaced` and, on a disable or delete, the count of live directory accounts — never the secret nor an anchor's content. Disabling or deleting stops the directory and only that: sessions, refresh tokens and passkeys already held keep working until they expire or an administrator deactivates the accounts. The console's **Directory** page and the website's *LDAP / Active Directory* page are the readable front doors; the normative text stays in §30 and the deployment guide.

---

## 8e. SAML 2.0 Identity Provider

AXIAM issues SAML 2.0 assertions, per tenant, to the service providers (SPs) a tenant administrator registered (competitor-gap item **G-2**, Phase 23): IdP metadata, the Web Browser SSO profile on the HTTP-Redirect and HTTP-POST bindings, SP- and IdP-initiated sign-on, signed assertions (and optionally signed responses), attributes mapped from AXIAM's own data, and single logout wired into session revocation. AXIAM's side as a SAML **service provider** — consuming an external IdP's assertions — is the older `saml.rs` and is not this chapter. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8, D-2, D-3, D-20 … D-27, D-34, D-37 … D-42), the wire contract for the management surface in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §29, and the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-304 … T-330, T-357 … T-384). The registry routes, the metadata endpoint and single logout were specified here ahead of their code and are built (W4: T23.2.5, then T23.2.4).

### 8e.1 Placement

No new crate; the layering table is unchanged. The plain data — `SamlServiceProvider` and the credential types — is in `axiam-core` (`models::saml_sp`, `models::saml_idp_credential`), the repositories in `axiam-db`, the write-time validator in `axiam_federation::saml_sp` (outside the `saml` feature: it parses URLs and X.509, no XML), the protocol in `axiam_federation::saml_idp` (behind `saml`, on `samael` and `libxml`/xmlsec), the credential's issuance in `axiam_pki::saml_signing`, and the routes in `axiam-api-rest`: the browser routes `/saml/v2/{tenant}/metadata`, `/sso` and `/slo` (behind `saml`, out of `openapi.json`) and the management routes `/api/v1/tenants/{tenant_id}/saml/…` (in every build, so in the spec — [D-42](competitor-gap-remediation-plan-2026-10-02.md)). The browser routes answer one indistinguishable empty `404` when the build lacks `saml` or the tenant's layered, disable-only setting `saml_idp_enabled` is off ([D-20](competitor-gap-remediation-plan-2026-10-02.md)); the entity id and every endpoint URL are one function of the deployment's public base URL and the path tenant.

### 8e.2 The signing credential

One RSA-4096 key per tenant signs with `rsa-sha256`/`sha256`; its leaf is issued by a signing CA of the tenant's organization with the `SamlSigning` profile (`digitalSignature`, `id-kp-documentSigning`, no SAN), an internal-only certificate type every certificate API refuses ([D-21](competitor-gap-remediation-plan-2026-10-02.md)). It lives in a `saml_idp_credential` row, never a `certificate` row, with the key sealed under `pki_encryption_key` through the database custodian; only the signer's lookup selects the ciphertext, and retiring destroys it. At most one `active` and one `next` credential per tenant, enforced by a unique index. **Rotation** is: issue into `next`, which the metadata publishes beside `active`; wait until the SPs have refreshed; **promote**, which in one transaction retires the old `active` and activates `next` ([D-42](competitor-gap-remediation-plan-2026-10-02.md), T-309). Retiring the `active` credential without a successor stops sign-on at once — the incident response to a leaked key, which SPs keep trusting until their administrators remove it (T-306).

### 8e.3 Issuance

`SamlIdpIssuer::issue` builds one assertion — bearer confirmation and `Conditions` of five minutes, audience the SP's entity id, `Recipient`/`Destination` the ACS URL used, `InResponseTo` only when SP-initiated, `AuthnInstant` the session's authentication time, an `AuthnContextClassRef` from the session's `amr` only (T-314) — and signs it always, then the response by policy (T23.2.2). It refuses unless the SP, user, session, groups, roles and credential all carry the path tenant (T-307), never signs a failure response (T-316), and re-verifies its own output. The `NameID` is a persistent pairwise HMAC under the dedicated `saml_pairwise_key` by default ([D-22](competitor-gap-remediation-plan-2026-10-02.md)), or an email address only when something vouched for it ([D-25](competitor-gap-remediation-plan-2026-10-02.md)). The `SessionIndex` is **per SP and random**, recorded with the `NameID` in `saml_sp_session` before the assertion is signed, so SLO can map it back while SPs cannot correlate it ([D-37](competitor-gap-remediation-plan-2026-10-02.md), T-312). Encryption (D-2) is refused rather than downgraded: an SP that asks for it gets `Responder`, and the registry refuses the flag until it is implemented.

### 8e.4 Single sign-on

`/saml/v2/{tenant}/sso` takes an `AuthnRequest` on either binding in two legs ([D-24](competitor-gap-remediation-plan-2026-10-02.md)): the first refuses everything decidable without a principal — size, DTDs, encodings, staleness, the issuer, any signature (Redirect over the exact octets, POST as the root's one enveloped signature), `Destination`, the ACS URL or index against the registration, the binding, a replayed `ID` — and holds the checked request under an opaque, browser-bound handle; the second resolves the OP cookie through the tenant-keyed lookup, applies `account_may_act`, hops to `/login` when it must (`ForceAuthn` bound to the request, `IsPassive` never hopping), consumes the handle on the X6 arbiter, records the participant and issues. Refusals before the ACS is known post nowhere; policy refusals after it are posted unsigned ([D-26](competitor-gap-remediation-plan-2026-10-02.md)). IdP-initiated sign-on is a per-SP opt-in, triggered by a same-site `GET …/sso/idp-initiated` (D-3, D-26). The auto-post page carries the one handler-set content-security policy ([D-27](competitor-gap-remediation-plan-2026-10-02.md)).

### 8e.5 Single logout

`/saml/v2/{tenant}/slo` receives `LogoutRequest`s and `LogoutResponse`s on both bindings with the SSO endpoint's receiver, and requires **every** SP message to be signed by the SP's registered certificate, verified on its own node, SHA-2 only ([D-38](competitor-gap-remediation-plan-2026-10-02.md)). A verified request ends the AXIAM sessions it names through `saml_sp_session` — OIDC back-channel logout to their clients, then `SessionRepository::invalidate`, which feeds the revocation feed — and only then tells the session's other SPs, one at a time through the browser, in a `saml_logout_run` chain that ends with a response to the initiating SP ([D-39](competitor-gap-remediation-plan-2026-10-02.md)). AXIAM signs its own logout messages only for a session's holder or a verified SP, with the detached query signature on the Redirect binding, so the tenant key mints no XML wrapping gadget (T-373). `/slo` never reads the OP cookie; it clears every copy. IdP-initiated logout is the same-site `GET …/sso/logout`, under the SSO path so the cookie reaches it. Sessions ended any other way — `/oauth2/end_session`, an administrator, a password reset — do not run a SAML chain, so SPs' own sessions outlive them (T-380, accepted; §4.5 for OIDC logout).

### 8e.6 The SP registry and its management surface

`SamlServiceProvider` rows (schema v72) hold the entity id (unique per tenant, immutable after create), the ACS allow-list (exact strings, the OAuth2 redirect-URI registration rule plus no `*`), the SLO endpoint, the `NameID` policy, response signing (there is no field to turn assertion signing off), the SP's certificates, attribute mappings and allowed groups. Eleven routes under `/api/v1/tenants/{tenant_id}/saml` ([`CONTRACT.md` §29](../sdks/CONTRACT.md), the §27 namespace `saml`): `get_idp`; the SP CRUD (`update` a replacement) through `validate_saml_service_provider` and four further refusals; `parse_sp_metadata`, which fetches an SP's metadata only through `guarded_fetch`, refuses any DTD on the bytes and returns a **draft** an administrator submits — nothing from an unsigned document is trusted or stored on its own ([D-41](competitor-gap-remediation-plan-2026-10-02.md)); and the credential's `list`, `issue`, `promote` and `retire`. Permissions `saml_sp:read`, `saml_sp:write` and `saml_idp:credential`; human administrators only, their own tenant only; writes rate-limited by `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN`; every change audited ([D-42](competitor-gap-remediation-plan-2026-10-02.md)). The routes work whatever `saml_idp_enabled` says, so a tenant is prepared before the IdP is switched on. The console's *SAML Service Providers* page (T23.2.6) is built on them.

### 8e.7 IdP metadata

`GET /saml/v2/{tenant}/metadata` publishes one unsigned `EntityDescriptor` from a fixed template: the signing certificates of the `active` and `next` credentials, the SSO and SLO locations for both bindings, the two `NameID` formats, no encryption key ([D-40](competitor-gap-remediation-plan-2026-10-02.md)). It answers the D-20 `404` when SAML is unavailable or off **and** when the tenant has no publishable credential, so the endpoint is no tenant oracle; it is cached for an hour with an `ETag` and rate-limited like the other browser routes.

---

## 8f. RFC 7592 Client Configuration

A client that registered itself through `POST /oauth2/register` (RFC 7591) can read, replace and delete its own registration (competitor-gap item **G-4**, Phase 23, task T23.4.1), authenticated by a per-client `registration_access_token` the registration returns once — never by a user or a service account. It is what an MCP client, or any other dynamically registered client, needs to keep its redirect URIs current and to remove itself. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's G-4 item ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §4), the wire contract in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §28.12, the operator's view in [`docs/admin/dynamic-client-registration.md`](../docs/admin/dynamic-client-registration.md#the-client-configuration-endpoint-rfc-7592), the threat in [`threat-model-stride.md`](threat-model-stride.md) (T-289).

### 8f.1 Placement

No new crate; the layering table is unchanged. Minting the token, its digest, the `registration_client_uri` builder and what a replacement may change are in `axiam_oauth2::dcr` (`mint_registration_access_token`, `registration_access_token_digest`, `validate`); the three routes `GET`, `PUT` and `DELETE /oauth2/register/{client_id}`, in both issuer forms, are in `axiam-api-rest`'s `handlers::dcr`; the repository verbs (`create_with_registration_access_token`, `get_by_registration_access_token`, `delete_by_registration_access_token`) are declared in `axiam-core` and implemented in `axiam-db`'s `oauth2_client` repository. Schema v69 adds one optional column to `oauth2_client`, the token's SHA-256.

### 8f.2 The token, and what it opens

32 CSPRNG bytes, base64url, returned in the registration's `201` and, rotated, in each `PUT`'s `200`; only the digest is stored, so `GET` never returns the token again although RFC 7592 §3 calls it REQUIRED in the response. Only a `managed_by = 'dcr'` client registered after v69 holds one — an administrator's client, a CIMD client and an older self-registered client have none. It is read from the `Authorization` header only (in the query string it is `400`) and compared as a digest in one `WHERE` with the tenant, the path's `client_id` and `managed_by = 'dcr'`, so an unknown client, a wrong token, another tenant's client and a client without a token are one indistinguishable `401 invalid_token`. `PUT` is RFC 7592's full replacement, re-validated by the same `dcr::validate` under the tenant's current policy and written through a type that holds only what a registration may set (the profile, the X7 flags, the provenance and the tenant are out of reach by construction); it rotates the token as one compare-and-swap on X6's two layers, so of racing `PUT`s one wins. `DELETE` revokes the client's refresh tokens and frees its `dcr_max_clients` slot; it does **not** end its users' AXIAM sessions, which belong to the users, and access tokens already issued live to their 15-minute `exp`. The administrator's `DELETE /api/v1/oauth2-clients/{id}` revokes nothing, so the self-service path does strictly more than the admin one (W1 F4 finding, [ilpanich/axiam#517](https://github.com/ilpanich/axiam/issues/517)). The three routes share one per-IP bucket at the registration preset, and every call is audited (`oauth2.client_configuration_*`) without the token or its digest. What an SDK must and must not do with the token — the URI used verbatim and only at the configured AXIAM, no retry of `PUT` or `DELETE` — is §28.12.2's and is not repeated here. CIBA metadata is registrable here only in initial-access-token mode ([§8i.2](#8i2-initiation)).

---

## 8g. Shared Signals Framework Transmitter

AXIAM transmits security events about a tenant's users to the relying parties a tenant administrator registered (competitor-gap item **G-5**, Phase 23, W4): CAEP `session-revoked`, `credential-change` and `assurance-level-change`, and RISC `account-disabled`, `account-enabled` and `account-purged`, each as one Security Event Token (RFC 8417), delivered by push (RFC 8935) or poll (RFC 8936), with a stream registry for the administrator, the SSF stream API for the receiver and transmitter metadata at `/.well-known/ssf-configuration`. The specification followed is OpenID Shared Signals Framework 1.0 (final), with CAEP 1.0, RISC 1.0 and RFC 9493 subject identifiers ([D-44](competitor-gap-remediation-plan-2026-10-02.md)). AXIAM transmits only; a receiver is later (D-4). This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8, D-36, D-44 … D-53, D-55), the wire contract in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §32 (the registry §32.1 – §32.5, the receiver protocol §32.6, the receiver helper §32.7), the operator's view in the website's *Integrate* page **Shared Signals (SSF) transmitter**, the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-385 … T-406).

### 8g.1 The shared outbound dispatcher

Before SSF, webhook delivery was a topology of its own inside `axiam-api-rest` (layer 6), which `axiam-oauth2` (layer 4) cannot reach. T23.5.1 extracted it into a shared outbound dispatcher, with no behaviour change, per **[D-36](competitor-gap-remediation-plan-2026-10-02.md)**: ports in `axiam-core`, machinery in `axiam-amqp`, deliverers where their protocol lives, wiring in `axiam-server`; the layering table did not change. `axiam_core::outbound` holds the envelope `OutboundMessage`, `OutboundKind` — one line per kind in a macro whose slug fixes the kind's queue names, its `AXIAM__<SLUG>__*` retry variables and its audit prefix — and two object-safe ports, `OutboundPublisher` (enqueue) and `OutboundDeliverer` (one attempt, classified as delivered, retry or dead-letter). `axiam_amqp::outbound` holds each kind's sibling topology (`axiam.<slug>`, `.retry`, `.dlq`, its declare arguments pinned byte for byte, since RabbitMQ refuses to redeclare a queue with other arguments), the publisher, the retry policy, one consumer supervisor for every kind (`spawn_outbound_consumer`, folded in T23.6.1) and the outcome table `outbound::outcome`, which the minimal profile's in-process dispatcher shares ([§8j.2](#8j2-what-the-broker-carried-and-what-replaces-it)). The webhook kind kept its queues, its environment variables and the exact `WebhookMessage` wire bytes through a per-kind codec (`outbound::wire`), so in-flight messages and a rolling upgrade survive; its deliverer stays in `axiam-api-rest` (`webhook.rs`). Four kinds ride it: `webhook`, `ssf_push`, `scim_push` ([§8h](#8h-outbound-scim-provisioning)) and `ciba_ping` ([§8i](#8i-ciba-client-initiated-backchannel-authentication)). Each new kind's dead-letter queue carries a seven-day `x-message-ttl`; the webhook DLQ keeps the arguments a running broker already holds.

### 8g.2 Placement

No new crate. The plain data and the ports are in `axiam-core` (`models::ssf`: the unsigned `SsfPendingEvent`, the `SsfOutbox` and `SessionRevocationSink` ports), the repositories in `axiam-db` (`ssf_stream`, `ssf_event_buffer`, `ssf_step_up`; schema v77 and v78), the protocol in `axiam_oauth2::ssf` (the event shapes, `prepare_event`, `sign_set`, `validate_push_endpoint` and the shared-issuer gate `SsfIssuerGate`) and `axiam_oauth2::ssf_delivery` (`SsfPushDeliverer` and the outbox), and in `axiam-api-rest` the emitter (`ssf_emitter::SsfEmitter`), the receiver's protocol surface and discovery (`handlers::ssf`: `/ssf/v1/stream`, `/status`, `/verify`, `/poll/{stream_id}`) and the administrator's registry (`handlers::ssf_admin`, five routes under `/api/v1/tenants/{tenant_id}/ssf/streams`, the §27 namespace `ssf`). Push leaves only through `axiam_pki::ssrf::guarded_fetch_no_redirect`. The tenant's layered, disable-only setting `ssf_enabled`, default off, stops discovery, the receiver API and every producer; the registry works regardless, so streams are registered before the switch ([D-45](competitor-gap-remediation-plan-2026-10-02.md)).

### 8g.3 Streams

A stream is registered by an administrator, never by a receiver ([D-50](competitor-gap-remediation-plan-2026-10-02.md)): it names the receiver's OAuth2 client (`receiver_client_id`, a client of the tenant registered for `client_credentials` with the scope `ssf.manage`), an audience unique across the deployment (`idx_ssf_stream_audience`, D-47), the events allowed, the subject format and the delivery method. The receiver manages its own streams at `/ssf/v1/*` with an `ssf.manage` client-credentials token and sees only streams bound to its `client_id` in its token's tenant — anything else is the same `404`. It may narrow its events within the allowance and, for push, move its endpoint and replace its header; it may not change the method, the audience, the subject format or the allowance. Verification runs at most once every 60 s, claimed in the datastore. `enabled` transmits, `paused` holds events in the buffer, `disabled` drops them where they are produced, and a receiver cannot restart what an administrator stopped ([D-51](competitor-gap-remediation-plan-2026-10-02.md)). The push `Authorization` header the receiver supplies is sealed with AES-256-GCM under `pki_encryption_key`, never projected, write-only, and never follows the endpoint to another origin ([D-49](competitor-gap-remediation-plan-2026-10-02.md)). The rules an SDK observes are §32.3's.

### 8g.4 Event sources, the step-up record and SET issuance

Events are emitted where the change happens, through one emitter, with a `txn` per originating operation ([D-52 as amended by D-53](competitor-gap-remediation-plan-2026-10-02.md)): `session-revoked` from the three session-repository paths that also publish to the revocation feed, through a core port; `credential-change` and the three account events from the call sites D-52 and D-53 name, SCIM `DELETE` and a directory deactivation included. Production is best effort — a failure is a `WARN` and never fails the logout, reset or erasure that caused it (T-405, Open, accepted). **The step-up record.** `assurance-level-change` must link a step-up's two browser legs, and nothing that links them travels with the browser: when the honour lane interacts for a step-up and the request carries a valid OP session, the authorization endpoint writes an `ssf_step_up` row `{tenant, user, previous_session_id, previous_acr}` (schema v78, ten minutes, one per user, swept on `/health/jobs`), and the return leg that arrives with a new session of the same user consumes it once and emits only when the `acr` changed (D-53 (1), T-404). The subject is resolved per stream when the event is produced — `iss_sub`, or `email` only for an address D-25's rule vouches for, and otherwise the event is not sent on that stream ([D-46](competitor-gap-remediation-plan-2026-10-02.md)). What travels and waits is the **unsigned** `SsfPendingEvent`; `sign_set` signs at delivery, against the stream as it then is — EdDSA with the deployment key, `typ: secevent+jwt`, one event, a 128-bit CSPRNG `jti`, no `exp` and no `sub` — so no queue or table holds a signed token, a stream disabled or narrowed meanwhile delivers nothing, and a retry carries the byte-identical SET ([D-45, D-48](competitor-gap-remediation-plan-2026-10-02.md); T-389, T-398).

### 8g.5 Push and poll

**Push** (RFC 8935): `SsfPushDeliverer`, on the dispatcher's `ssf_push` kind, re-reads the stream and signs at each attempt and posts `application/secevent+jwt` with the stored header through `guarded_fetch_no_redirect` with `allow_private = false` — a `3xx` is returned, never followed, so the header never reaches another origin (T-391, T-392). The receiver's answer is mapped per D-49 and D-53: any `2xx` is delivered; a `400` carrying an RFC 8935 `err`, a `401` or `403` and any other `4xx` are dead-lettered; `404`, `408`, `429`, `5xx`, `3xx` and transport failures retry on the dispatcher's schedule. **`axiam.ssf_push.dlq` drops a message seven days after it arrives** — D-48's bound for held events, because a dead-lettered event still names a person (D-53 (10), T-402). **Poll** (RFC 8936): `POST /ssf/v1/poll/{stream_id}` over `ssf_event_buffer` — at most 1 000 events per stream with the oldest dropped, seven days at most, swept on `/health/jobs` — at-least-once, `ack` deleting exactly the named rows, a long poll of at most 30 s and at most one waiting long poll per stream per instance (T-395, T-403). Resuming a paused push stream releases its held events oldest first. A receiver de-duplicates by `jti`; the §32.7 receiver helper, which remembers every `jti` for at least seven days, shipped in all eleven SDKs and closed T-388 at model 2.37.0.

### 8g.6 Per-tenant issuers

Without tenant issuer paths every tenant's SETs carry the same `iss` and the same key, so a tenant administrator who squatted another receiver's audience could produce SETs that receiver accepts. The maintainer's decision **[D-55](competitor-gap-remediation-plan-2026-10-02.md)** (option (b) of [ilpanich/axiam#539](https://github.com/ilpanich/axiam/issues/539), W4 F4 P23W4-11): **SSF requires per-tenant issuers in a deployment that holds more than one tenant.** While `AXIAM__AUTH__TENANT_ISSUER_PATHS` is off and the deployment holds more than one tenant, counted across every organization, `SsfIssuerGate` makes SSF behave for every tenant as with `ssf_enabled` off — checked where an event is produced, where a SET is signed and at discovery, never only at write time — and turning SSF on is `400` naming the cause; the change is logged once and audited as `ssf.inactive_shared_issuer`. A single-tenant deployment keeps the root issuer. The tenant count may be reused for up to 60 s, so a second tenant created on another replica stops SSF there within a minute (T-390's residual; contract §32.3 rule 13).

---

## 8h. Outbound SCIM Provisioning

AXIAM acts as a SCIM 2.0 client (RFC 7643, RFC 7644) for a tenant (competitor-gap item **G-6**, Phase 23, W5): a tenant administrator registers downstream SCIM service providers — **targets** — and AXIAM pushes the tenant's user and group lifecycle to them, repairs drift by reconciliation and propagates an erasure as `DELETE`. Nothing is needed from an SDK for that to happen; what the contract adds is the target registry, a §27 namespace. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8, D-57, D-58, D-73), the wire contract in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §31, the operator's view in the website's *Integrate* page **Outbound SCIM provisioning** and the deployment guide's `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN` entry ([`docs/deployment/README.md`](../docs/deployment/README.md#rate-limiting)), the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-407 … T-420).

### 8h.1 Placement

No new crate; the layering table is unchanged. The plain data is in `axiam_core::models::scim_target` (`ScimTarget`, which has no credential member, `ScimTargetLink`, `ScimTargetState`) and the source port in `axiam_core::provisioning` (`ProvisioningSink`); the repositories are in `axiam-db` (`scim_target`; schema v79: `scim_target`, `scim_target_link`, `scim_target_state`; v84: the notification claim); the client is `axiam_scim::outbound` in `axiam-scim` (layer 7, where SCIM already lives) — `provisioner` (`ScimProvisioner`), `deliverer` (`ScimPushDeliverer`), `client`, `wire` and `reconcile`; the six management routes are `axiam-api-rest`'s `handlers::scim_targets` under `/api/v1/scim-targets`; the notification gate is `axiam-server`'s `scim_notification`; the console page is *SCIM targets* (`frontend/src/pages/scim-targets`).

### 8h.2 The target and its credential

A target holds `base_url`, `enabled`, its authentication — `bearer`, or `oauth2_client_credentials` with `token_url`, `client_id`, an optional `scope` and a secret — its scope (`all_users`, or `groups`: the direct members of up to 100 listed groups of the tenant), `push_groups`, `user_name_from` and `deprovision` (`deactivate`, the default, or `delete`): a fixed attribute set, no mapping language ([D-57](competitor-gap-remediation-plan-2026-10-02.md); T-412). Both URLs are held to `validate_push_endpoint`, the webhook outbound address policy, at write time. The credential is sealed with AES-256-GCM under `pki_encryption_key` in columns of its own, write-only through every interface, and a write that carries one fails closed without the key. **It is bound to its URL.** A write that moves `base_url` on a bearer target, moves either URL on a client-credentials target, or switches the authentication kind without supplying the credential in the same write is `400` naming the field. D-57 first bound a client-credentials secret to `token_url` only, which let an administrator who never held the secret move `base_url` alone and collect the next freshly minted access token; the W5 F4 review bound it to `base_url` as well (P23W5-01, **T-409**, contract §31.3 rule 2 amended in place). The administrator's update is conditional on the `updated_at` it read (`409` when overtaken); the deliverer never writes the target row — delivery state lives in `scim_target_state`, written only by atomic statements (T-416). The management family `scim_targets:read` / `:write` is human-only; the rules an SDK observes are §31.3's.

### 8h.3 Lifecycle translation on the dispatcher

The source is the repositories, not the handlers: the SurrealDB user, group and account-deletion repositories call `ProvisioningSink` after every successful mutating write, so REST, inbound SCIM, directory JIT and sync, OIDC and SAML JIT and erasure are covered without a call site each; a user `update` notifies only when a provisioned field changes, so a login's bookkeeping enqueues nothing. `ScimProvisioner` enqueues, on the dispatcher's `scim_push` kind ([§8g.1](#8g1-the-shared-outbound-dispatcher)), one reference `{resource_type, axiam_id}` per enabled target of the tenant — nothing about a person travels. `ScimPushDeliverer` is **level-triggered**: each attempt re-reads the target, the resource and its link and computes the downstream state now, so retries, reordering and duplicates converge. An in-scope `Active` user is present and `active`; one out of scope or in another live status is deprovisioned per `deprovision`; a `Deleted`, `Anonymized` or absent one is `DELETE`d whatever the policy. Without a link AXIAM sends `POST` with `externalId` set to the AXIAM id, and a `409` adopts exactly one downstream resource carrying that `externalId`, or dead-letters `conflict`; with a link it sends a `PATCH` replacing the mapped attributes only, skipped when the digest of the last representation is unchanged, and a `404` on `PATCH` drops the link and re-creates. Groups follow the same rules; a group of more than 10 000 members dead-letters. Every request, the token request included, goes through `guarded_fetch_no_redirect` with `allow_private = false`, and the target is re-read and its version compared before any credential leaves; client-credentials access tokens are cached in memory per target version, for at most an hour (T-408, T-410).

### 8h.4 Reconciliation

A cleanup job, `scim_reconcile` in `SWEEP_JOBS`, runs each enabled target at most once every 24 h, claimed by a conditional write on `scim_target_state` so replicas do not run it twice; `POST …/reconcile` runs it on demand under the same claim (`202`, or `409` while claimed), and enabling a target starts one ([D-58](competitor-gap-remediation-plan-2026-10-02.md); T-419). A run enqueues a reference per in-scope and per linked resource; pages the downstream `/Users` and `/Groups` (100 per page, at most 100 pages and five minutes) through the deliverer's own client; clears the digest of a resource whose downstream copy drifted; drops links whose downstream resource is gone; deprovisions a downstream resource whose `externalId` names an out-of-scope, disabled or erased resource of this tenant; and retries pending erasures. It **never touches** a downstream resource whose `externalId` is not an AXIAM id of this tenant — accounts the application created itself (T-413, T-414).

### 8h.5 Dead letters, notification and erasure

A dead letter is recorded by the dispatcher's `scim_push.delivery_failed` audit row and by counters and a fixed-vocabulary reason on `scim_target_state`, which the target's `GET` projects. The audit log the consumer writes through is a `NotifyingAuditLog` (`axiam-audit`), so a row written outside any HTTP request still reaches the tenant's notification rules as the event `scim_delivery_failed`. **One notification per target per hour** ([D-73](competitor-gap-remediation-plan-2026-10-02.md), W5 F4 P23W5-02, T-418): the gate claims `scim_target_state.failure_notified_at` with a conditional write (schema v84), so replicas agree, and every dead letter keeps its audit row and its count. **Erasure** (GDPR Art. 17, T-415): `anonymize_user` reports to the sink like every other write and the deliverer sends `DELETE` through the link row, which survives the erasure cascade — it holds ids and a digest only — until that `DELETE` succeeds; an erasure that dead-letters leaves the link `deprovisioned` with `erase_pending`, which reconciliation retries until it lands. `axiam.scim_push.dlq` drops a reference seven days after it arrives. Deleting a target removes its links and state and deprovisions nothing downstream (§31.3 rule 8).

### 8h.6 One consumer per replica, and the per-target breaker

Each replica runs one `scim_push` consumer with one delivery in flight, for every tenant, and the in-process dispatcher of [§8j](#8j-the-minimal-deployment-profile-no-broker) does the same. A request may wait ten seconds, twenty with a token request, so without a guard one unresponsive downstream would stall every tenant's provisioning on that replica: a reconciliation that queues 10 000 references for a target that never answers would hold the others for more than a day. The W5 F4 review reported it (P23W5-07, T-414), and [ilpanich/axiam#550](https://github.com/ilpanich/axiam/issues/550) decided it for `1.0.0` with a **per-target breaker** in the deliverer:

- Before it reads the resource, an attempt reads the target's `scim_target_state`. With `consecutive_failures` at or above **5** (`BREAKER_THRESHOLD`) and `last_failure_at` inside the window, the attempt is a retry, reason `target is failing; backing off`, with **no request** and no write to the state.
- The window is the consumer's own backoff (`AXIAM__SCIM_PUSH__BACKOFF_BASE_MS`, `__BACKOFF_CEILING_MS`, told to the deliverer by the composition root) applied to the failures past the threshold: the base at five, doubling with each further failure, never above the ceiling (5 s, 10 s, 20 s … one hour by default).
- Once the window has passed, the next reference is attempted: a success zeroes `consecutive_failures` and closes the breaker, a failure stamps `last_failure_at` and doubles the window.
- A refused delivery on the consumer's last attempt is counted as the dead letter it becomes (`count_dead_letter`: `dead_lettered_total` only), without stamping `last_failure_at`, so a stream of refused references cannot hold the breaker open.

A tarpit therefore costs the consumer five request timeouts to open its breaker and one per window after, instead of one per queued reference. Still true: a downstream that answers just inside ten seconds and succeeds now and then never opens it, and references queued while a breaker is open spend their attempts without a request and dead-letter on the schedule (reconciliation queues again what is in scope). Webhooks, SSF and sign-ins are unaffected, being separate kinds. The issue's second option, a **per-target concurrency budget** (more than one delivery in flight per consumer), is deferred to `1.0.x`.

---

## 8i. CIBA (Client-Initiated Backchannel Authentication)

AXIAM is an OpenID Connect CIBA authorization server (CIBA Core 1.0) in **poll** and **ping** mode, the two modes FAPI-CIBA allows (competitor-gap item **G-7**, Phase 23, W5). A client that already knows whom it wants to authenticate calls `POST /oauth2/bc-authorize`; AXIAM stores a pending request and mails the user a link to the console's approval page; the user signs in, completes any step-up the request asks for, and approves or denies; the client collects the tokens at the token endpoint with the grant `urn:openid:params:grant-type:ciba`, by polling or once it is pinged. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8, D-5, D-61 … D-70, D-74), the wire contract in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md) §33 (the server rules an SDK observes are §33.3's), the operator's view in the website's *Integrate* page **CIBA (backchannel authentication)**, the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-421 … T-447).

### 8i.1 Placement

No new crate. The plain data is in `axiam_core::models::ciba` (`CibaRequest`, `CibaRequestStatus`), the request store in `axiam-db` (`ciba_request`; schema v80, the signing column and replay kind v81, the mail template kind v82), the protocol in `axiam-oauth2` — `ciba` (`CibaService`, the client-registration rules, `auth_req_id` generation), `ciba_signed_request`, `token_ciba` (the grant, a child of `token`, so it issues through the same machinery as the other user grants), `ciba_notifier` (`CibaMailNotifier`) and `ciba_ping` (`CibaPingDeliverer`) — the routes in `axiam-api-rest`'s `handlers::ciba` (`bc-authorize`, both issuer forms) and `handlers::ciba_approval` (the approval API), and the console page `/ciba/approve` (`frontend/src/pages/ciba`). The `ciba_request` sweep is in `SWEEP_JOBS`.

### 8i.2 Initiation

A CIBA client is confidential and registered for poll or ping, through the admin API or RFC 7591/7592 — the latter in initial-access-token mode only, so a stranger cannot obtain a notification channel to every user ([D-62](competitor-gap-remediation-plan-2026-10-02.md); T-438). `bc-authorize` authenticates the client as the token endpoint does and takes exactly one hint: `login_hint` (username, then e-mail, within the tenant) or `id_token_hint`. **No `user_code`**: it is refused at registration and on the request and discovery says `false`, because a user code checked against the password is a password oracle; `login_hint_token` is refused too ([D-64](competitor-gap-remediation-plan-2026-10-02.md)). `binding_message` (at most 64 printable characters, no bidirectional overrides), `requested_expiry` (30 – 600 s, default 300) and `acr_values` are bounded ([D-66](competitor-gap-remediation-plan-2026-10-02.md); T-437). `unknown_user_id` is never sent: a hint that names nobody, a user who may not sign in or one under lockout gets a stored request with no subject and the same response, and it expires ([D-63](competitor-gap-remediation-plan-2026-10-02.md); T-422). The endpoint has its own bucket in the machine presets, `bc_authorize_per_min`, a per-client bucket after authentication, and a fixed three notifications per user per minute ([D-70](competitor-gap-remediation-plan-2026-10-02.md); T-424, T-428).

### 8i.3 The `auth_req_id` lifecycle

The `auth_req_id` is 256 bits from the CSPRNG, base64url, returned once and stored only as its SHA-256. A request moves from `Pending` to `Approved` or `Denied`, from `Approved` to `Redeemed`, or to `Expired`; every transition is conditional on the version read, only a status change bumps the version, and a poll is a compare-and-set on `last_polled_at` that never moves it ([D-68](competitor-gap-remediation-plan-2026-10-02.md); T-427). The token endpoint answers `authorization_pending`; `slow_down`, the interval starting at 5 s and growing by 5 s per early poll to 60 s; `access_denied`; `expired_token`; and `invalid_grant` for another client's or another tenant's identifier. Redemption is single-use on the device grant's two-layer arbiter (T-425, T-426). An expired request is marked and deleted ten minutes later, so a late poll still reads `expired_token`. The ID token is always issued, carrying the approval's `auth_time`, `amr` and `acr`, and the access token's `sid` is the approving session, so ending that session ends the tokens ([D-67](competitor-gap-remediation-plan-2026-10-02.md); T-439). Lockout is checked at request, at approval and at redemption ([D-69](competitor-gap-remediation-plan-2026-10-02.md), the class of defect Keycloak 26.7.x had; T-429).

### 8i.4 Poll and ping, and no push

**Poll and ping; no push** ([D-65](competitor-gap-remediation-plan-2026-10-02.md)). A ping is sent after approval **and** after denial: `POST {"auth_req_id"}` with `Authorization: Bearer <client_notification_token>`, on the dispatcher's `ciba_ping` kind ([§8g.1](#8g1-the-shared-outbound-dispatcher)), whose queue carries only the request's record id and whose DLQ has the seven-day TTL. `CibaPingDeliverer` is level-triggered — it re-reads the request and the client — and sends through `guarded_fetch_no_redirect` with `allow_private = false` (T-433). The notification endpoint and token are sealed together under `pki_encryption_key`, and ping mode is refused on a deployment without the key (T-432). Push mode, and with it the `urn:openid:params:jwt:claim:auth_req_id` claim, is not offered; CIBA push and `user_code` are among Phase 23's declined items.

### 8i.5 Signed requests and the `fapi2` client

[D-61](competitor-gap-remediation-plan-2026-10-02.md) serves FAPI-CIBA. A client that registered `backchannel_authentication_request_signing_alg` (PS256, ES256 or EdDSA, with exactly one of `jwks` or `jwks_uri`) must send every request as a `request` JWT under exactly that algorithm, verified only against its registered keys; `iss` (the `client_id`), `aud` (the issuer, in either form), `exp`, `nbf`, `iat` and `jti` are required, `exp − nbf` is at most 60 minutes, the `jti` is single-use (`oauth2_proof_replay`, kind `ciba_request_object`), the parameters come from the JWT only, and `request_uri` is refused because AXIAM never fetches a request (T-440 … T-443). The **`fapi2` CIBA client** holds the grant only with an algorithm registered — through the admin API, since dynamic registration is never `fapi2` — and under the profile's rules: `tls_client_auth`, `self_signed_tls_client_auth` or `private_key_jwt`, sender-constrained tokens, a mandatory `binding_message` and, in ping mode, a notification token of at least 22 characters (T-434). `backchannel_authentication_endpoint` is the seventh member of `mtls_endpoint_aliases` (contract §21.3.1, amended in place by contract 1.58).

### 8i.6 Approval: a console sign-in only

The user decides on the console page `/ciba/approve`, through `GET /api/v1/ciba/requests?status=pending` (the signed-in user's own pending requests, each carrying the page's `request_id` and `version`; D-74, #566), `GET /api/v1/ciba/requests/{id}` and `POST …/approve` and `…/deny`: a human session and CSRF; one indistinguishable `404` for a request that is unknown, another user's, expired, decided or changed since it was read; `403 step_up_required` naming the class the request needs, the step-up going through the login hop; the decision conditional on the version read; `ciba.approved` and `ciba.denied` audited with the deciding session and never the binding message (T-430, T-431, T-435). **Only a console sign-in decides.** The W5 F4 review found that an access token AXIAM minted for an OAuth2 client — through the code, refresh or CIBA grant — names the user and a live session and was admitted, so a CIBA client holding one from an earlier redemption could open and approve its next request in the user's name; the approval routes now refuse any token that carries a `client_id` (P23W5-04, contract §33 amended in place). T-447 stays Open for the device grant, whose `/api/v1/device/decide` admits the same token, pre-existing since B2 ([ilpanich/axiam#549](https://github.com/ilpanich/axiam/issues/549)).

### 8i.7 The approval mail

`CibaMailNotifier` sends the `ciba_approval` template — the client, the binding message and the link, never the `auth_req_id` — only to an account that may sign in, behind the three-per-minute throttle, and **only to an address D-25's rule vouches for**: `email_verified_at` set, or the account `Active` ([D-74](competitor-gap-remediation-plan-2026-10-02.md), W5 F4 P23W5-03, T-446). An unvouched address is the same quiet no-op as an account that may not sign in; the request is stored and answered as usual, because mailing an unproven address would make AXIAM a phishing relay quoting client-chosen text. **As amended by the W6 F4 review (P23W6-07), and resolved for 1.0.0 (#566):** the console had no list of a user's pending requests and the record id travelled only in the mail, so an unmailed request could not be opened and ran to expiry, the client seeing `expired_token`; a federated account, `PendingVerification` for life, with no verified address could not approve a CIBA request at all. The decision stands, and the remedy shipped: `GET /api/v1/ciba/requests?status=pending` lists the signed-in user's own pending requests (client name, binding message, scopes, requested `acr`, expiry, the page's `request_id` and `version`, never the `auth_req_id`), under the approval surface's rules — a console sign-in only (a token with a `client_id` is `403`), a rate-limit bucket of its own in `ciba_approval_per_min`, and no oracle (another user's, a decided and an expired request are absent). The console's user menu carries a badge with the count and lists the requests, each opening the existing approval page; the decisions stay behind CSRF, the version read and the session-audited decision.

---

## 8j. The Minimal Deployment Profile (No Broker)

`AXIAM__AMQP__ENABLED=false` runs AXIAM with **SurrealDB only** — no RabbitMQ, no `AXIAM__AMQP__URL`, no AMQP signing key — for a single node, an edge site or a small deployment where a broker is more infrastructure than the workload justifies (competitor-gap item **G-8**, Phase 23, W5). The default is `true`. The profile is **single-instance by definition**: without a broker nothing tells a second replica about the first one's mutations, so a second instance would serve stale authorization decisions. This chapter says where each part lives and links to the decisions that bind it; the reasoning is in the plan's decision table ([`competitor-gap-remediation-plan-2026-10-02.md`](competitor-gap-remediation-plan-2026-10-02.md) §8, D-59, D-72), the operator's view in [`docs/deployment/README.md` — *Minimal profile (no broker)*](../docs/deployment/README.md#minimal-profile-no-broker), the audit review in [`audit-durability-review-minimal-profile-2026-10-05.md`](audit-durability-review-minimal-profile-2026-10-05.md), the threats in [`threat-model-stride.md`](threat-model-stride.md) (T-444, T-445). There is no contract change.

### 8j.1 Placement

No new crate. The composition root moved out of `main.rs` into `axiam_server::boot::serve`, so that a test boots it without a broker (`crates/axiam-server/tests/minimal_profile_boot.rs`); `axiam_server::profile` holds the boot guards, the singleton lease and its timings (`LeaseTiming`); `axiam_server::messaging` chooses the transport for outbound delivery and mail once, at start-up, so no producer or deliverer branches on the profile. The in-process transports are `axiam_amqp::outbound::inprocess` and `axiam_amqp::mail_inprocess`; the lease row's repository is `axiam-db`'s `minimal_profile_lease` (schema v83). `docker/docker-compose.minimal.yml`, with `just minimal-up`, `-down` and `-clean`, runs one server beside SurrealDB.

### 8j.2 What the broker carried, and what replaces it

| The broker carried | In the minimal profile |
|---|---|
| Webhooks, SSF push, outbound SCIM, CIBA ping | One **in-process dispatcher** implementing the same `OutboundPublisher` port: a bounded channel of 1 024 per kind, the same deliverers, the same retry policy and variables, the same outcome table and audit vocabulary as the AMQP loop ([§8g.1](#8g1-the-shared-outbound-dispatcher)); retries are bounded sleeping tasks, and a dead letter is its audit row only — there is no DLQ |
| Transactional mail | An in-process bounded channel around the same send path, with the consumer's retry count and the same `email.delivery_failed` row |
| Asynchronous authorization requests | Not started; REST and gRPC authorization checks are unaffected |
| Audit events published by *other* services | Not started. AXIAM's own audit rows never rode the broker: the middleware writes SurrealDB directly, in both profiles |
| Reactor transport | `UnavailableReactorTransport` is composed; a write that would enable a registration is `409` naming the profile, gRPC reactor administration `FAILED_PRECONDITION`, and boot refuses while any registration is enabled |
| Cross-replica decision-cache invalidation | Nothing to invalidate across; boot refuses `decision_cache_broadcast_enabled = true`, and the cache works process-locally |

`/health` reports `profile` (`full` or `minimal`) and, in the minimal profile, what is `unavailable` ([D-59](competitor-gap-remediation-plan-2026-10-02.md)). The deployment guide's *What it does not provide* table is the operator's version of this one.

### 8j.3 The singleton lease and the orderly stop

A replica count is the orchestrator's knowledge, not the process's, so the profile holds a **singleton lease** in the datastore: the row `minimal_profile_lease:instance`, claimed with a conditional write at start-up, valid for 30 s and renewed every 10 s. A boot that finds another instance's live lease waits up to 45 s for it to expire — a rolling update's old pod — and then refuses; an orderly stop releases it. An instance that loses its lease does not run beside the new holder, and since T23.8.2 it does not die mid-flight either (**[D-72](competitor-gap-remediation-plan-2026-10-02.md)**, T-444): the loss raises a flag and the instance stops through the path a `SIGTERM` takes — no new connections, in-flight requests finished, the cleanup task's current tick finished so an erasure and its audit row stay together, the audit queue drained by `AuditMiddleware::drain` (a FIFO barrier bounded at 5 s) — and then exits non-zero. `std::process::exit(1)` remains only as a backstop after 15 s (`LeaseTiming::lost_stop_deadline`). The drain applies to every orderly stop, the full profile's `SIGTERM` included. The same stop now answers the full profile's other fatal exits — a dead AMQP consumer or gRPC server used to be a `std::process::exit(1)` too — and the gRPC listener stops with the REST one and is awaited before the drain (#554). The dead-component stop has its own 35 s backstop (the lease's 15 s is shorter than the REST shutdown timeout). A `SIGKILL`, an OOM kill and the backstop still lose the queue (T-444's residuals).

### 8j.4 What is lost on restart, and why that is accepted

There is no durable queue. A delivery or a mail queued, or sleeping before a retry, when the process stops is gone. Since P23W5-A4 an *orderly* stop gives each lost outbound delivery (webhook, SSF push, outbound SCIM, CIBA ping) a terminal `<kind>.delivery_abandoned` audit row with a fixed reason, and so does an enqueue refused because a queue is full (or closed); a kill still leaves the trail ending at a `<kind>.delivery_attempt`, or holding nothing for a message never attempted. `delivery_abandoned` is deliberately not `delivery_failed`, so a stop does not trigger the `scim_delivery_failed` notification mail. A lost `ExportReady` mail strands a ready GDPR export; and external services' audit events have no ingestion path. **T-445 is Open and accepted under [D-59](competitor-gap-remediation-plan-2026-10-02.md)**: the profile exists to run without a broker, and a SurrealDB-backed durable queue was rejected as a second dispatcher. What bounds the loss: the profile is opt-in and says what it lacks — a `WARN` at boot, `/health`, the deployment guide; AXIAM's own audit rows are written directly in both profiles and drained by every orderly stop; the GDPR erasure records keep their dead-letter fallback (T19.27); a delivery that exhausts its attempts still writes `<kind>.delivery_failed`; and outbound SCIM is repaired by the next reconciliation ([§8h.4](#8h4-reconciliation)). An SSF push queued at a restart is lost the same way (T-405).

### 8j.5 The audit-path review

T23.8.2 reviewed every path by which an audit record is written in the profile against T19.27 ([`audit-durability-review-minimal-profile-2026-10-05.md`](audit-durability-review-minimal-profile-2026-10-05.md), findings A1 … A12). **T19.27 holds**: the profile does not touch `write_erasure_audit_with_dlq` or its callers. **One regression, fixed** with failing-first tests: the first build's reaction to a lost lease killed the process wherever it was, dropping up to 4 096 queued audit rows and a purge between its erasure and its audit row (A1); the orderly stop of §8j.3 replaced it, and closed a pre-existing gap with it — a `SIGTERM` never waited for the queue (A2). The audit middleware, the in-process dispatcher, mail and the export notice, external ingestion (refused loudly) and the SSF and SCIM dead-letter rows hold (A3, A4, A5, A6, A9). The pre-existing gaps it found are filed: the GDPR dead-letter file configured in no shipped deployment and GDPR request audits that are fire-and-forget (A7, A8; [ilpanich/axiam#552](https://github.com/ilpanich/axiam/issues/552)), T-108's claimed controls absent (A10; [#553](https://github.com/ilpanich/axiam/issues/553)), and the gRPC listener outside the orderly stop and the full profile's abrupt exits (A11, A12; [#554](https://github.com/ilpanich/axiam/issues/554)). T23.8.3's compose file puts the GDPR dead-letter file on a named volume and gives the server a stop grace period (30 s when written; 40 s since #569, to cover the REST listener's 20 s shutdown timeout, gRPC's 5 s and the 5 s drain). Its measured resting footprint, at rest and not under load, is 207 MiB for the minimal stack against 331 MiB for the full one (`benchmarks/PUBLIC_BENCH_ANALYSIS.md` §5).

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
| **SAML IdP** | `GET/POST/PUT/DELETE /api/v1/tenants/:tenant_id/saml/…`; browser routes `/saml/v2/:tenant_id/metadata`, `/sso`, `/slo` | SP registry, metadata import, signing-credential lifecycle (CONTRACT §29); the IdP itself ([§8e](#8e-saml-20-identity-provider)) |
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
- `pki` — CA signing-key custody (`AXIAM__PKI__CA_KEY_STORE`: `database`, `vault` or `vault_pki`, with the Vault address, token and mounts) and FIDO MDS3 metadata ingestion (`AXIAM__PKI__MDS_*`). The key that seals CA rows is a secret from the secret provider (`AXIAM__AUTH__PKI_ENCRYPTION_KEY`), not a `pki` setting; certificate validity defaults and ceilings are per-tenant settings (`default_cert_validity_days`, `max_cert_validity_days`); there is no CRL to configure (§6.2)
- `webhooks` — delivery timeout, retry policy, max concurrent deliveries
- `gnupg` — key storage settings, signing algorithm preferences
- `email` — provider (smtp/sendgrid/postmark/resend/brevo), SMTP host/port/TLS, API keys, from address
- `notifications` — admin notification defaults, delivery batch size
- `logging` — log level, format, output targets
