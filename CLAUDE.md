# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AXIAM (Access eXtended Identity and Authorization Management) is an open-source IAM solution built with **Rust** and **SurrealDB**, targeting microservices and IoT environments. It aims to compete with Keycloak, Okta, and Auth0, with a focus on security compliance (GDPR, CyberSecurity Act, ISO27001, OWASP ASVS, OWASP Cumulus).

AXIAM is a **multi-tenant** system. Organizations are top-level entities containing one or more tenants. Tenants provide full data isolation — each tenant has its own users, roles, permissions, resources, certificates, and configuration.

## Technology Stack

- **Backend**: Rust (Actix-Web for REST, Tonic for gRPC, Lapin for AMQP)
- **Database**: SurrealDB (distributed, document/graph hybrid)
- **Message Broker**: RabbitMQ (AMQP) for async authz, audit ingestion, event notifications
- **Frontend**: React + TypeScript (Vite)
- **API Protocols**: REST (OpenAPI documented), gRPC (Protocol Buffers), AMQP
- **Deployment**: Docker, Kubernetes
- **SDKs**: Planned for Rust, Python, TypeScript, Java, C#, PHP, Go

## Core Domain Model

- **Organizations** are top-level entities that hold CA certificates and contain tenants
- **Tenants** provide data isolation; all domain entities are scoped to a tenant
- **Users** authenticate via username/password, social login, MFA, or certificates
- **Groups** are named collections of users; roles assigned to a group are inherited by all members
- **Roles** are collections of permissions, can be global or resource-specific, and support inheritance through resource hierarchies
- **Permissions** define actions on resources; **scopes** provide sub-resource granularity
- **Resources** are organized hierarchically; role assignments on parent resources cascade to children unless overridden
- **Service accounts** are used for automated/machine-to-machine authentication
- **Certificates** (X.509) are managed per-tenant, signed by organization CA; used for users, services, and IoT devices
- **Webhooks** deliver real-time event notifications to external systems
- **Federation** via SAML and OpenID Connect enables cross-domain SSO

## Authentication & Authorization Protocols

- OAuth2 for authorization (Authorization Code + PKCE, Client Credentials, Refresh Token)
- OpenID Connect for authentication/identity
- MFA support (TOTP, extensible to WebAuthn)
- Certificate-based authentication (mTLS for IoT devices)
- gRPC for low-latency authz checks in service mesh
- AMQP for async/deferred authz decisions

## Project Structure (Cargo Workspace)

```
axiam/
├── crates/
│   ├── axiam-core/         # Domain types, traits, error types
│   ├── axiam-db/           # SurrealDB repository implementations
│   ├── axiam-auth/         # Authentication (password, MFA, JWT)
│   ├── axiam-authz/        # Authorization engine (RBAC, hierarchy, scopes)
│   ├── axiam-api-rest/     # REST API (Actix-Web)
│   ├── axiam-api-grpc/     # gRPC services (Tonic)
│   ├── axiam-amqp/         # AMQP consumer/producer (Lapin)
│   ├── axiam-oauth2/       # OAuth2 authorization server + OIDC provider
│   ├── axiam-federation/   # SAML SP + OIDC federation
│   ├── axiam-audit/        # Audit logging service
│   ├── axiam-pki/          # Certificate management, CA, GnuPG integration
│   └── axiam-server/       # Binary — composes all crates
├── proto/                  # Protocol Buffer definitions
├── frontend/               # React admin UI
├── docker/                 # Dockerfiles and compose configs
├── k8s/                    # Kubernetes manifests
└── sdks/                   # SDK projects
```

## Development Artifacts

All design/planning documents live in `claude_dev/`:
- [`claude_dev/design-document.md`](claude_dev/design-document.md) — Architecture, data model, flows, security
- [`claude_dev/roadmap.md`](claude_dev/roadmap.md) — 64 tasks across 16 phases

## Development Process

- Each roadmap task requires a **signed commit** before proceeding to the next
- Use **feature branches** for different stages; keep main clean
- Development artifacts go in the `claude_dev/` directory as Markdown files
- CI/CD via GitHub Actions (build, test, deploy pipelines)
- Refer to `claude_dev/roadmap.md` for current task to work on

## Build & Run (once scaffolded)

```bash
just build             # Build the project
just test              # Run all tests
just test-one <name>   # Run a single test
just run               # Run the application
just dev-up            # Start SurrealDB + RabbitMQ
just dev-down          # Stop containers
just check             # fmt + lint + test
```

## Security Standards

- Passwords: Argon2id (OWASP-recommended parameters)
- JWT: EdDSA (Ed25519), short-lived access tokens (15 min)
- Refresh tokens: Opaque, server-stored, single-use with rotation
- MFA secrets: AES-256-GCM encrypted at rest
- CA private keys: AES-256-GCM encrypted at rest (only for signing CAs)
- Certificates: X.509 with RSA-4096 or Ed25519; private keys never stored (returned once)
- GnuPG: OpenPGP keys for audit signing and encrypted data exports
- Webhook signatures: HMAC-SHA256
- Audit logs: Append-only (no UPDATE/DELETE)
- TLS 1.3 minimum for all external communication
