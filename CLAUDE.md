# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AXIAM (Access eXtended Identity and Authorization Management) is an open-source IAM solution built with **Rust** and **SurrealDB**, targeting microservices and IoT environments. It aims to compete with Keycloak, Okta, and Auth0, with a focus on security compliance (GDPR, CyberSecurity Act, ISO27001, OWASP ASVS, OWASP Cumulus).

## Technology Stack

- **Backend**: Rust (Actix-Web for REST, Tonic for gRPC, Lapin for AMQP)
- **Database**: SurrealDB (distributed, document/graph hybrid)
- **Message Broker**: RabbitMQ (AMQP) for async authz, audit ingestion, event notifications
- **Frontend**: React + TypeScript (Vite)
- **API Protocols**: REST (OpenAPI documented), gRPC (Protocol Buffers), AMQP
- **Deployment**: Docker, Kubernetes
- **SDKs**: Planned for Rust, Python, TypeScript, Java, C#, Go

## Core Domain Model

- **Users** authenticate via username/password, social login, or MFA
- **Roles** are collections of permissions, can be global or resource-specific, and support inheritance through resource hierarchies
- **Permissions** define actions on resources; **scopes** provide sub-resource granularity
- **Resources** are organized hierarchically; role assignments on parent resources cascade to children unless overridden
- **Service accounts** are used for automated/machine-to-machine authentication
- **Federation** via SAML and OpenID Connect enables cross-domain SSO

## Authentication & Authorization Protocols

- OAuth2 for authorization (Authorization Code + PKCE, Client Credentials, Refresh Token)
- OpenID Connect for authentication/identity
- MFA support (TOTP, extensible to WebAuthn)
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
- [`claude_dev/roadmap.md`](claude_dev/roadmap.md) — 48 tasks across 14 phases

## Development Process

- Each roadmap task requires a **signed commit** before proceeding to the next
- Use **feature branches** for different stages; keep main clean
- Development artifacts go in the `claude_dev/` directory as Markdown files
- CI/CD via GitHub Actions (build, test, deploy pipelines)
- Refer to `claude_dev/roadmap.md` for current task to work on

## Build & Run (once scaffolded)

```bash
cargo build            # Build the project
cargo test             # Run all tests
cargo test <test_name> # Run a single test
cargo run              # Run the application
```

## Security Standards

- Passwords: Argon2id (OWASP-recommended parameters)
- JWT: EdDSA (Ed25519), short-lived access tokens (15 min)
- Refresh tokens: Opaque, server-stored, single-use with rotation
- MFA secrets: AES-256-GCM encrypted at rest
- Audit logs: Append-only (no UPDATE/DELETE)
- TLS 1.3 minimum for all external communication
