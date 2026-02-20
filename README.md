```
     ___      ___  ___  ___      ___      ___     ___
    /   \     \  \/  / |   |    /   \    /   \   /   \
   / /\  \     \    /  |   |   / /\  \  / /\ \ / /\ \
  / /__\  \    /    \  |   |  / /__\  \/ /  \ \  /  \ \
 /  ____\  \  / /\ \ \ |   | /  ____\  /    \ \/    \ \
/_/      \__\/_/  \_\_\|___|/_/      \__\     \_\     \_\
```

# AXIAM

**Access eXtended Identity and Authorization Management**

---

## What is AXIAM?

AXIAM is a full **vibe-coding experiment** — an enterprise-grade, open-source Identity and Access Management (IAM) platform designed from scratch by a human software architect and built entirely through AI-assisted development with [Claude Code](https://claude.ai/code) (Opus 4.6).

The goal: prove that a single architect, collaborating with an AI coding agent, can produce a production-quality IAM system that competes with Keycloak, Okta, and Auth0 — built in Rust for maximum performance, safety, and security.

Every line of code, every test, every commit in this repository has been produced through human-AI pair programming — the architect provides vision, constraints, and review; the AI provides implementation at scale.

## Key Features

- **Multi-tenant architecture** — Organizations contain tenants; tenants provide full data isolation
- **RBAC with resource hierarchy** — Roles, permissions, groups, and scoped access that cascades through resource trees
- **Multiple auth protocols** — REST, gRPC, and AMQP for sync and async authorization
- **OAuth2 & OpenID Connect** — Full authorization server with PKCE, client credentials, and refresh token rotation
- **Federation** — SAML and OIDC for cross-domain SSO
- **PKI & Certificate Management** — Hierarchical X.509 certificates, mTLS for IoT devices
- **GnuPG Integration** — Audit log signing, encrypted data exports, identity attestation
- **Webhooks** — Real-time event delivery with HMAC-SHA256 signatures
- **Comprehensive audit trail** — Append-only, tamper-evident logging

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Rust (edition 2024) |
| **Database** | SurrealDB (document/graph hybrid) |
| **REST API** | Actix-Web |
| **gRPC** | Tonic + Protocol Buffers |
| **Message Broker** | RabbitMQ (via Lapin) |
| **Frontend** | React + TypeScript (Vite) |
| **Auth Crypto** | Argon2id, EdDSA (Ed25519), AES-256-GCM |
| **Deployment** | Docker, Kubernetes |

## Architecture

```
Clients (Browser, Mobile, IoT, Services, SDKs)
    |           |           |
    REST/HTTPS  gRPC/TLS    AMQP
    |           |           |
    v           v           v
+--------------------------------------+
|          API Gateway Layer           |
|  Actix-Web  |  Tonic  |  Lapin     |
+--------------------------------------+
                |
+--------------------------------------+
|          Service Layer               |
|  AuthN | AuthZ | Users | Federation |
|  Roles | PKI   | Audit | OAuth2     |
+--------------------------------------+
                |
+--------------------------------------+
|        Repository Abstractions       |
+--------------------------------------+
                |
+--------------------------------------+
|          SurrealDB Cluster           |
+--------------------------------------+
```

## Security & Compliance

AXIAM targets compliance with:

- **OWASP ASVS** — Password requirements, session management, access control
- **GDPR** — Data export/deletion, consent tracking, audit logs
- **ISO 27001** — Access control, cryptography, audit logging
- **CyberSecurity Act** — Secure by design, vulnerability management

## Development Progress

The project follows a structured roadmap of **64 tasks across 16 phases**:

| Phase | Focus | Status |
|-------|-------|--------|
| Phase 0 | Project foundation, CI, dev environment | Done |
| Phase 1 | Core domain types & DB repositories | Done |
| Phase 2 | Authentication (password, JWT, MFA) | Next |
| Phase 3 | Authorization engine | Planned |
| Phase 4 | REST API | Planned |
| Phase 5 | gRPC API | Planned |
| Phase 6 | AMQP integration | Planned |
| Phase 7 | Audit logging | Planned |
| Phase 8 | PKI & certificates | Planned |
| Phase 9 | Webhook system | Planned |
| Phase 10 | OAuth2 & OIDC | Planned |
| Phase 11 | Federation (SAML + OIDC) | Planned |
| Phase 12 | Admin frontend | Planned |
| Phase 13 | Docker & Kubernetes | Planned |
| Phase 14 | SDKs (Rust, TS, Python, Java, C#, PHP, Go) | Planned |
| Phase 15 | Security audit, compliance, docs | Planned |

## Quick Start

```bash
# Prerequisites: Rust 1.93+, Docker

# Start dev infrastructure (SurrealDB + RabbitMQ)
just dev-up

# Build the project
just build

# Run all tests
just test

# Format + lint + test
just check
```

## Project Structure

```
axiam/
├── crates/
│   ├── axiam-core/         # Domain types, traits, error types
│   ├── axiam-db/           # SurrealDB repository implementations
│   ├── axiam-auth/         # Authentication (password, MFA, JWT)
│   ├── axiam-authz/        # Authorization engine (RBAC, hierarchy)
│   ├── axiam-api-rest/     # REST API (Actix-Web)
│   ├── axiam-api-grpc/     # gRPC services (Tonic)
│   ├── axiam-amqp/         # AMQP consumer/producer (Lapin)
│   ├── axiam-oauth2/       # OAuth2 + OIDC provider
│   ├── axiam-federation/   # SAML + OIDC federation
│   ├── axiam-audit/        # Audit logging service
│   ├── axiam-pki/          # Certificate management & GnuPG
│   └── axiam-server/       # Binary — composes all crates
├── proto/                  # Protocol Buffer definitions
├── frontend/               # React admin UI
├── claude_dev/             # Design document & roadmap
├── docker/                 # Docker Compose configs
├── k8s/                    # Kubernetes manifests
└── sdks/                   # SDK projects
```

## License

AGPL-3.0-or-later
