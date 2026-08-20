<p align="center">
  <img src="axiam_logo.png" alt="AXIAM" width="600" />
</p>

# AXIAM

[![CI](https://github.com/ilpanich/axiam/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam?branch=main)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Access eXtended Identity and Authorization Management**

---

## What is AXIAM?

AXIAM is a full **vibe-coding experiment** — an enterprise-grade, open-source Identity and Access Management (IAM) platform designed from scratch by a human software architect and built entirely through AI-assisted development with [Claude Code](https://claude.ai/code) (Opus 4.6).

The goal: prove that a single architect, collaborating with an AI coding agent, can produce a production-quality IAM system that competes with Keycloak, Okta, and Auth0 — built in Rust for maximum performance, safety, and security.

Every line of code, every test, every commit in this repository has been produced through human-AI pair programming — the architect provides vision, constraints, and review; the AI provides implementation at scale.

While the aim is to build a fully functional IAM system, the deeper goal is to explore the future of software development itself — where human creativity and AI's generative capabilities combine to create software that neither could produce alone. AXIAM is a case study in this new paradigm, pushing the boundaries of what's possible with AI-assisted software engineering.

**Note: AXIAM is a work in progress and should not be used in production environments until it reaches a stable release. The project is currently in active development, with core features being implemented and tested.**

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
|  Actix-Web  |  Tonic  |  Lapin       |
+--------------------------------------+
                |
+--------------------------------------+
|          Service Layer               |
|  AuthN | AuthZ | Users | Federation  |
|  Roles | PKI   | Audit | OAuth2      |
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

### OPAQUE (optional)

AXIAM can authenticate with **OPAQUE** ([RFC 9807](https://datatracker.ietf.org/doc/rfc9807/)),
the CFRG's augmented PAKE, in which the password never reaches the server —
only a registration record whose envelope is sealed under a key the client
derives through the server's oblivious PRF. This closes the exposure TLS does
not: a TLS-terminating proxy, an accidentally verbose request log, or a heap
dump can no longer capture a plaintext password, because the server never has
one.

It also means a **stolen record database is not offline-crackable on its own**.
Recovering a password additionally requires the tenant's OPRF seed, which is
encrypted at rest separately — so unlike a stolen password-hash database, there
is no dictionary attack to mount at any cost.

It does **not** defend against a compromised AXIAM server, and for browser
clients it does not defend against AXIAM serving malicious JavaScript. The
strong case is native SDK clients, IoT devices, and deployments sitting behind
infrastructure the tenant does not control.

It is **off by default** and enabled per organization or tenant
(`opaque_mode: disabled | optional | required`). `required` cannot be turned on
safely until every user has enrolled, because a record needs the plaintext
password and a stored Argon2id hash is not invertible — so nobody can be
enrolled retroactively. See
[`claude_dev/opaque-design.md`](claude_dev/opaque-design.md) for the migration
runbook, and `sdks/CONTRACT.md` §23 for the cross-language protocol.

Every AXIAM client — the eleven SDKs and the admin UI — binds one audited
implementation (`crates/axiam-opaque`), compiled directly, through WebAssembly,
or through its C ABI. OPAQUE is not a protocol it is reasonable to hand-write
once per language.

```bash
# Both required whenever any org or tenant has opaque_mode != disabled.
# Seals in-flight exchange state; cheap to rotate.
export AXIAM__AUTH__OPAQUE_SESSION_KEY="$(openssl rand -hex 32)"
# Encrypts per-tenant OPRF seeds at rest. Back this up: losing it means every
# user in every tenant needs a password reset.
export AXIAM__AUTH__OPAQUE_SETUP_KEY="$(openssl rand -hex 32)"
```

The per-tenant OPRF seeds are stored in the database as AES-256-GCM ciphertext;
the key is not, which is what keeps a stolen credential database
non-crackable. Where that key comes from is pluggable — environment (default),
a mounted `file` for Docker/Kubernetes secret volumes, or HashiCorp `vault`:

```bash
export AXIAM__AUTH__SECRET_PROVIDER=vault
export AXIAM__AUTH__VAULT_ADDR=https://vault.internal:8200
export AXIAM__AUTH__VAULT_TOKEN=...
```

See [`claude_dev/opaque-design.md`](claude_dev/opaque-design.md) for the threat
model behind each, including why moving the *seeds* to a file on the server
volume would weaken rather than strengthen the separation.

## Development Progress

The project follows a structured roadmap of **64 tasks across 19 phases**:

| Phase | Focus | Status |
|-------|-------|--------|
| Phase 0 | Project foundation, CI, dev environment | Done |
| Phase 1 | Core domain types & DB repositories | Done |
| Phase 2 | Authentication (password, JWT, MFA) | Done |
| Phase 3 | Authorization engine | Done |
| Phase 4 | REST API | Done |
| Phase 5 | gRPC API | Done |
| Phase 6 | AMQP integration | Done |
| Phase 7 | Audit logging | Done |
| Phase 8 | PKI & certificates | Done |
| Phase 9 | Webhook system | Done |
| Phase 10 | OAuth2 & OIDC | Done |
| Phase 11 | Federation (SAML + OIDC) | Done |
| Phase 12 | Hierarchical Settings & Password Policy | Done |
| Phase 13 | Email Service & Account Flows | Done |
| Phase 14 | Advanced MFA | Done |
| Phase 15 | Admin frontend | Done |
| Phase 16 | Docker & Kubernetes | Done |
| Phase 17 | SDKs (Rust, TS, Python, Java, Kotlin, C#, PHP, Go, Swift, C, C++) | Done |
| Phase 18 | Security audit, compliance, docs | Done |

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
│   ├── axiam-email/          # Certificate management & GnuPG
│   └── axiam-server/       # Binary — composes all crates
├── proto/                  # Protocol Buffer definitions
├── frontend/               # React admin UI
├── benchmarks/             # Performance/efficiency/security benchmark framework
├── claude_dev/             # Design document & roadmap
├── docker/                 # Docker Compose configs
├── k8s/                    # Kubernetes manifests
└── sdks/                   # SDK contract + OpenAPI spec (the SDKs themselves
                        #   live in ilpanich/axiam-<lang>-sdk repositories)
```

## Client SDKs

The eleven client SDKs live in their own repositories. Each one vendors a copy of
[`sdks/CONTRACT.md`](sdks/CONTRACT.md) (the binding cross-language behavioral contract),
[`sdks/openapi.json`](sdks/openapi.json) and [`proto/`](proto/), which are maintained here:

| Language | Repository | Package |
|----------|------------|---------|
| Rust | [axiam-rust-sdk](https://github.com/ilpanich/axiam-rust-sdk) | [crates.io](https://crates.io/crates/axiam-sdk) |
| TypeScript | [axiam-typescript-sdk](https://github.com/ilpanich/axiam-typescript-sdk) | [npm](https://www.npmjs.com/package/axiam-sdk) |
| Python | [axiam-python-sdk](https://github.com/ilpanich/axiam-python-sdk) | [PyPI](https://pypi.org/project/axiam-sdk/) |
| Java | [axiam-java-sdk](https://github.com/ilpanich/axiam-java-sdk) | Maven Central (`io.github.ilpanich:axiam-sdk`) |
| Kotlin | [axiam-kotlin-sdk](https://github.com/ilpanich/axiam-kotlin-sdk) | Maven Central (`io.github.ilpanich:axiam-sdk-kotlin`) |
| C# | [axiam-csharp-sdk](https://github.com/ilpanich/axiam-csharp-sdk) | [NuGet](https://www.nuget.org/packages/Axiam.Sdk) |
| PHP | [axiam-php-sdk](https://github.com/ilpanich/axiam-php-sdk) | [Packagist](https://packagist.org/packages/axiam/axiam-sdk) |
| Go | [axiam-go-sdk](https://github.com/ilpanich/axiam-go-sdk) | [pkg.go.dev](https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk) |
| Swift | [axiam-swift-sdk](https://github.com/ilpanich/axiam-swift-sdk) | Swift Package Manager (`github.com/ilpanich/axiam-swift-sdk`) |
| C | [axiam-c-sdk](https://github.com/ilpanich/axiam-c-sdk) | CMake (FetchContent / `find_package`) |
| C++ | [axiam-cplusplus-sdk](https://github.com/ilpanich/axiam-cplusplus-sdk) | CMake (FetchContent / vcpkg) |

## Benchmarking

AXIAM ships a vendor-neutral benchmark framework in [`benchmarks/`](benchmarks/README.md)
for comparing it against other open-source IAM systems (Keycloak, Zitadel, …)
across three axes: **performance** (throughput / latency), **resource efficiency**
(throughput per CPU core and per GiB — *competitor-level performance at a smaller
footprint?*), and **security posture** (the same workload replayed from plaintext
HTTP up to mTLS with client-certificate auth, quantifying what each tier costs).

It drives standard OAuth2/OIDC flows through a per-target adapter so every system
is measured on equal footing, and includes scaffolded per-SDK client-overhead
benchmarks that consume each SDK from its published package. See
[`benchmarks/README.md`](benchmarks/README.md) and
[`benchmarks/docs/methodology.md`](benchmarks/docs/methodology.md).

## License

Apache License v2.0
