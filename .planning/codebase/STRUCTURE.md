# Project Structure

> Generated: 2026-03-30

## Directory Layout

```
axiam/
├── crates/                    # Rust workspace crates (13 members)
│   ├── axiam-core/            # Domain types, traits, error types, repository traits
│   ├── axiam-db/              # SurrealDB repository implementations, migrations
│   ├── axiam-auth/            # Authentication (password, MFA, JWT, TOTP, WebAuthn)
│   ├── axiam-authz/           # Authorization engine (RBAC, hierarchy, scopes)
│   ├── axiam-api-rest/        # REST API handlers (Actix-Web), middleware, routes
│   ├── axiam-api-grpc/        # gRPC services (Tonic)
│   ├── axiam-amqp/            # AMQP consumer/producer (Lapin)
│   ├── axiam-oauth2/          # OAuth2 authorization server + OIDC provider
│   ├── axiam-federation/      # SAML SP + OIDC federation
│   ├── axiam-audit/           # Audit logging, notification rules
│   ├── axiam-pki/             # Certificate management, CA, mTLS, GnuPG/PGP
│   ├── axiam-email/           # Email templates, email service
│   └── axiam-server/          # Binary — composes all crates into server
├── proto/                     # Protocol Buffer definitions
│   └── axiam/v1/              # v1 API protos
│       ├── authorization.proto
│       ├── token.proto
│       └── user.proto
├── frontend/                  # React + TypeScript admin UI (Vite)
│   ├── src/
│   │   ├── components/        # Shared UI components (DataTable, FormDialog, etc.)
│   │   ├── pages/             # Route-level pages (20+ modules)
│   │   ├── services/          # API client services
│   │   ├── stores/            # Zustand state stores
│   │   ├── lib/               # Utilities
│   │   └── assets/            # Static assets
│   ├── e2e/                   # Playwright E2E tests
│   └── dist/                  # Build output
├── docker/                    # Docker configuration
│   ├── Dockerfile.server      # Rust backend multi-stage build
│   ├── Dockerfile.frontend    # Frontend nginx build
│   ├── docker-compose.dev.yml # Dev environment (SurrealDB + RabbitMQ)
│   ├── docker-compose.prod.yml
│   └── nginx.conf
├── k8s/                       # Kubernetes manifests
│   ├── server/                # Backend deployment
│   ├── frontend/              # Frontend deployment
│   ├── surrealdb/             # SurrealDB StatefulSet
│   ├── rabbitmq/              # RabbitMQ deployment
│   ├── ingress.yml
│   ├── namespace.yml
│   └── kustomization.yml
├── claude_dev/                # Design docs and roadmap
├── ThreatDragonModels/        # Threat model (OWASP Threat Dragon)
├── .codegraph/                # CodeGraph index
├── Cargo.toml                 # Workspace root
├── justfile                   # Task runner (just commands)
└── .github/                   # CI/CD workflows
```

## Crate Dependency Graph

```
                    axiam-core (foundation — no internal deps)
                   /    |    \      \       \        \
                  /     |     \      \       \        \
            axiam-db  axiam-pki  axiam-email  \        \
              / |  \                           \        \
             /  |   \                           \        \
      axiam-auth  axiam-authz  axiam-federation  \        \
         / |  \        |            |             \        \
        /  |   \       |            |              \        \
  axiam-oauth2  axiam-audit                         \        \
        |          |                                 \        \
        |          |                                  \        \
  axiam-api-rest (depends on: core, auth, authz, db,  \        \
   |              audit, oauth2, federation, pki)       \        \
   |                                                     |        |
  axiam-api-grpc (depends on: core, authz, auth)         |        |
   |                                                     |        |
  axiam-amqp (depends on: core, authz, audit)            |        |
   |                                                     |        |
   +-----------------------------------------------------+--------+
   |
  axiam-server (composes ALL crates into binary)
```

### Dependency Details

| Crate | Internal Dependencies |
|-------|----------------------|
| `axiam-core` | (none — leaf crate) |
| `axiam-db` | core |
| `axiam-auth` | core, db |
| `axiam-authz` | core, db |
| `axiam-pki` | core |
| `axiam-email` | core |
| `axiam-federation` | core, db |
| `axiam-oauth2` | core, auth, db |
| `axiam-audit` | core, auth |
| `axiam-api-rest` | core, auth, authz, db, audit, oauth2, federation, pki |
| `axiam-api-grpc` | core, authz, auth |
| `axiam-amqp` | core, authz, audit |
| `axiam-server` | ALL crates (composition root) |

## Entry Points

### Backend Binary
- `crates/axiam-server/src/main.rs` — Single binary that composes all services
  - Connects to SurrealDB, runs migrations
  - Connects to RabbitMQ, declares queues
  - Configures Actix-Web with all REST routes
  - Starts gRPC server (Tonic)
  - Launches AMQP consumers

### Frontend
- `frontend/src/main.tsx` — React app entry point
- `frontend/vite.config.ts` — Vite build configuration

## Key Files by Crate

### axiam-core
- `src/models/` — All domain types (User, Organization, Tenant, Role, Permission, etc.)
- `src/repository.rs` — Repository trait definitions
- `src/error.rs` — Unified error types (`AxiamError`)

### axiam-db
- `src/schema.rs` — SurrealDB migration/schema definitions
- `src/repository/` — One file per entity (e.g., `user.rs`, `tenant.rs`)

### axiam-api-rest
- `src/handlers/` — One handler module per domain entity
- `src/middleware/` — JWT auth middleware, RBAC middleware
- `src/lib.rs` — Route registration (`register_api_v1_routes`)
- `tests/` — Integration tests (one per domain)

### axiam-auth
- `src/token.rs` — JWT issuance and validation
- `src/password.rs` — Argon2id password hashing
- `src/totp.rs` — TOTP MFA
- `src/policy.rs` — Password and MFA policy enforcement
- `src/config.rs` — Auth configuration

### axiam-pki
- `src/ca.rs` — Certificate Authority operations
- `src/cert.rs` — X.509 certificate generation
- `src/mtls.rs` — mTLS helpers
- `src/pgp.rs` — GnuPG/PGP key management

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace definition, shared dependencies |
| `justfile` | Task runner commands (build, test, run, dev-up/down) |
| `rustfmt.toml` | Rust formatting (max_width=100) |
| `.github/workflows/` | CI/CD pipelines |
| `docker/docker-compose.dev.yml` | Local dev environment |
| `k8s/kustomization.yml` | Kubernetes deployment |

## Frontend Structure

```
frontend/src/
├── components/
│   ├── ui/                    # shadcn/ui primitives
│   ├── layout/                # App shell, sidebar, header
│   ├── DataTable.tsx          # Reusable data table
│   ├── FormDialog.tsx         # Modal form component
│   ├── ConfirmDialog.tsx      # Confirmation dialogs
│   ├── PageHeader.tsx         # Page title/actions
│   └── SearchInput.tsx        # Search with debounce
├── pages/                     # ~20 route modules
│   ├── LoginPage.tsx
│   ├── DashboardPage.tsx
│   ├── users/
│   ├── groups/
│   ├── roles/
│   ├── permissions/
│   ├── organizations/
│   ├── tenants/
│   ├── certificates/
│   ├── oauth2/
│   ├── federation/
│   ├── audit/
│   ├── webhooks/
│   ├── settings/
│   └── ...
├── services/                  # Axios API clients
├── stores/                    # Zustand state management
└── lib/                       # Shared utilities
```
