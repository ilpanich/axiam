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
- **SDKs**: Rust, Python, TypeScript, Java, C#, PHP, Go — each in its own `axiam-<lang>-sdk` repository

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
- RBAC engine is default-deny with **deny-override**: an explicit `effect: "deny"` grant overrides every allow, at any depth of the resource hierarchy and at equal specificity (SEC-040 closed; see `claude_dev/deny-override-design.md` for the precedence table and why deny-override rather than most-specific-wins)

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
└── sdks/                   # SDK contract (CONTRACT.md) + OpenAPI spec only
```

### Documentation lint (ratcheting)

`[workspace.lints.rust] missing_docs = "warn"` is defined in the root
`Cargo.toml` and opted into **per crate** with `[lints] workspace = true`. It is
a warning locally and an error in CI, where clippy runs `-D warnings`.

Opted in today: **`axiam-authz`**. Next target: **`axiam-core`, 993 sites** —
`missing_docs` fires on struct and enum *fields*, so the count is roughly four
times the number of public types. Do not add the `[lints]` key to a crate you
have not documented first; a lint that fires on every build is one everybody
learns to scroll past.

### Crate layering (enforced)

Dependencies point **inward**: a crate may depend only on crates in a strictly
lower layer. `axiam-core` (layer 0) has no internal dependencies at all; the
composition root `axiam-server` (layer 8) may reach everything and nothing may
reach back.

`scripts/check-crate-layering.py` enforces this in CI (job **Architecture Invariants**);
`--graph` prints the table with every crate's edges resolved against it. Adding a
crate to the workspace without placing it in that table is itself a failure.
Test-only outward edges are allowed but must be declared in
`TEST_ONLY_INVERSIONS` with a reason. See
[`claude_dev/crate-layering.md`](claude_dev/crate-layering.md) for the rationale
behind each placement.

The seven client SDKs are **not** in this repository — each lives in its own
`ilpanich/axiam-<lang>-sdk` repo (rust, typescript, python, java, csharp, php, go) and
vendors a copy of `sdks/CONTRACT.md`, `sdks/openapi.json` and `proto/`, which are
maintained here and must be re-synced downstream when they change.

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

## Build & Disk Hygiene (sandbox / CI environments)

This applies to every orchestrator run and every spawned executor, on **every wave and phase**.

- **`cargo clean` between plan steps.** The sandbox disk is quota-limited (~38 GB) and Rust
  `target/` build artifacts accumulate fast (a full `cargo test` builds ~15 integration-test
  binaries per crate, each hundreds of MB). Run `cargo clean` in the gap **between** each plan
  that involves Rust compilation — never *during* an executor run (it would wipe an in-progress
  build). If the disk fills, Bash and all write tools fail with `ENOSPC`; recover by deleting
  `target/` (`/dev/shm` is a separate writable tmpfs usable as an escape hatch).
- **Prefer narrowly-scoped cargo commands** to keep `target/` small: `cargo test -p <crate> --lib`
  or `-p <crate> --test <specific>`, `cargo clippy -p <crate> --lib`, `cargo fmt -p <crate> -- --check`.
  Avoid unscoped `cargo test` / `cargo build` across the whole workspace unless required
  (e.g. the end-of-phase regression gate).
- **swagger-ui GitHub-egress workaround (required after any `target/` wipe).** `utoipa-swagger-ui`
  downloads `swagger-ui-5.17.14.zip` from `github.com` at build time, which this environment's
  proxy blocks (403). Generate the placeholder zip and point the build script at it:
  ```bash
  export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
  ```
  The cache lives OUTSIDE the repo (`~/.axiam-build-cache/`) and therefore does **not** survive a
  fresh container — earlier revisions of this file described it as durable, and a session that
  trusted that failed in `utoipa-swagger-ui`'s build script with
  `swagger ui download path should exists`. Run the script; it takes a second and is idempotent.
  This is a local-only build input substitution — it touches no tracked file, `Cargo.toml`, or CI config.
- **`--no-default-features` when libxml2 is unavailable.** `axiam-api-rest`'s default `saml`
  feature pulls `libxml`, whose build script needs system libxml2 headers. Where those are absent,
  build and test with `--no-default-features` — the same thing CI's "Build (SAML off)" job does.

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

## PR and issues guidelines
- GitHub issues will be closed only after a PR merge
- After a phase is completed, the corresponding issues will be included in the PR description and closed after the PR merge
- PRs must reference the issue(s) they address and include a detailed description of the changes
- PRs must be made by claude agents on behalf of the human developer

## SAGE — Persistent Memory

Your brain is powered by SAGE MCP. You have persistent institutional memory.

### Boot Sequence (MANDATORY)
1. Call `sage_inception` as your VERY FIRST action in every new conversation
2. Do NOT respond to the user before booting — your memories must load first
3. Follow the instructions returned by inception (they adapt to the user's settings)

### If SAGE MCP is not connected
Start the node: `sage-gui serve`
MCP config is in `.mcp.json` at project root. Restart your session after starting.
