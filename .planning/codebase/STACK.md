# Technology Stack

**Analysis Date:** 2026-03-28

## Languages

**Primary:**
- Rust (edition 2024, MSRV 1.93) - Backend, all server-side logic across 13 workspace crates
- TypeScript (~5.9.3) - Frontend admin UI

**Secondary:**
- Protocol Buffers - gRPC service definitions (`proto/axiam/v1/`)
- SQL (SurrealQL) - Database queries embedded in Rust code

## Runtime

**Environment:**
- Rust stable (1.93+), async via Tokio 1.x
- Node.js 22 (Docker build uses `node:22-alpine`)
- Nginx 1.27 (frontend static serving in production)

**Package Manager:**
- Cargo (Rust) - Lockfile: `Cargo.lock` present
- npm (frontend) - Lockfile: `frontend/package-lock.json` present

**Task Runner:**
- `just` (justfile at project root) - Build, test, dev-up/down, prod-up/down commands

## Frameworks

**Core:**
- Actix-Web 4 - REST API (`crates/axiam-api-rest/`)
- Tonic 0.14 - gRPC services (`crates/axiam-api-grpc/`)
- Lapin 4 - AMQP consumer/producer (`crates/axiam-amqp/`)
- React 19.2 - Frontend admin UI (`frontend/`)
- Vite 8.0 - Frontend build tooling

**Testing:**
- `cargo test` - Rust unit/integration tests
- `tokio-test 0.4` - Async test utilities
- SurrealDB `kv-mem` feature - In-memory DB for repository tests
- Playwright 1.58 - Frontend E2E tests (`frontend/playwright.config.ts`)

**Build/Dev:**
- `tonic-build 0.14` / `tonic-prost-build 0.14` - Protobuf codegen (build dependency of `axiam-api-grpc`)
- `protobuf-compiler` (apt) - Required system dependency for gRPC builds
- Docker multi-stage builds - `docker/Dockerfile.server`, `docker/Dockerfile.frontend`

## Key Dependencies

**Critical (Backend):**
- `surrealdb 3` + `surrealdb-types 3` - Database client and derive macros (`crates/axiam-db/`)
- `jsonwebtoken 10` - JWT creation/validation (`crates/axiam-auth/`)
- `argon2 0.5` - Password hashing (`crates/axiam-auth/`, `crates/axiam-db/`)
- `totp-rs 5` (features: gen_secret, otpauth) - TOTP MFA (`crates/axiam-auth/`)
- `webauthn-rs 0.5` - WebAuthn/FIDO2 support (`crates/axiam-auth/`)
- `rcgen 0.13` - X.509 certificate generation (`crates/axiam-pki/`)
- `x509-parser 0.17` - Certificate parsing (`crates/axiam-pki/`)
- `pgp 0.19` - OpenPGP key management and signing (`crates/axiam-pki/`)
- `aes-gcm 0.10` - AES-256-GCM encryption for secrets at rest (`crates/axiam-auth/`, `crates/axiam-pki/`)
- `samael 0.0.19` - SAML SP implementation (`crates/axiam-federation/`)
- `lettre 0.11` (features: tokio1-rustls-tls, smtp-transport) - Email delivery (`crates/axiam-email/`)
- `reqwest 0.12` (features: json, rustls-tls) - HTTP client for federation, webhooks

**Critical (Frontend):**
- `react 19.2` / `react-dom 19.2` - UI framework
- `react-router-dom 7.13` - Client-side routing
- `@tanstack/react-query 5.95` - Server state management
- `zustand 5.0` - Client state management
- `axios 1.13` - HTTP client
- `@radix-ui/*` - Accessible UI primitives (dialog, dropdown-menu, label, select, separator, slot, toast)
- `tailwindcss 3.4` + `tailwind-merge 3.5` - Styling
- `lucide-react 1.7` - Icon library
- `class-variance-authority 0.7` + `clsx 2.1` - CSS class utilities

**Infrastructure:**
- `tokio 1` (features: full) - Async runtime
- `tracing 0.1` + `tracing-subscriber 0.3` (features: env-filter, json) - Structured logging
- `tracing-actix-web 0.7` - Request tracing middleware
- `config 0.15` - Configuration management (env vars, files)
- `utoipa 5` + `utoipa-swagger-ui 9` - OpenAPI documentation with Swagger UI
- `actix-cors 0.7` - CORS middleware
- `rustls 0.23` - TLS implementation (no OpenSSL dependency in Rust layer)

**Crypto/Security:**
- `hmac 0.12` + `sha2 0.10` - HMAC-SHA256 for webhook signatures
- `sha1 0.10` - Legacy hash support
- `rand 0.9` - Random number generation
- `rand_core 0.6` (in `axiam-pki` only) - Compatibility with `pgp` crate's rand 0.8 dependency
- `base64 0.22` - Base64 encoding/decoding
- `hex 0.4` - Hex encoding
- `subtle 2` - Constant-time comparisons (`crates/axiam-oauth2/`)
- `uuid 1` (features: v4, v5, serde) - UUID generation throughout

**Utility:**
- `serde 1` (features: derive) + `serde_json 1` - Serialization (workspace-wide)
- `chrono 0.4` (features: serde) - Date/time handling
- `thiserror 2` - Error type derivation
- `anyhow 1` - Error propagation
- `url 2` - URL parsing
- `flate2 1` - Compression (SAML deflate encoding)
- `prost 0.14` + `tonic-prost 0.14` - Protobuf serialization
- `futures-lite 2` - Lightweight futures utilities (AMQP)
- `smallvec 1` - Stack-allocated vectors (`crates/axiam-pki/`)
- `time 0.3` - Time library (required by `rcgen 0.13` for certificate dates)

## Configuration

**Environment Variables (server):**
- `AXIAM_DB__URL` - SurrealDB WebSocket URL (e.g., `ws://surrealdb:8000`)
- `AXIAM_DB__USERNAME` / `AXIAM_DB__PASSWORD` - SurrealDB credentials
- `AXIAM_DB__NAMESPACE` / `AXIAM_DB__DATABASE` - SurrealDB namespace/database
- `AXIAM_AMQP__URL` - RabbitMQ AMQP URL (e.g., `amqp://rabbitmq:5672`)
- `AXIAM_SERVER__HOST` / `AXIAM_GRPC__HOST` - Bind addresses
- `RUST_LOG` - Log level configuration (e.g., `axiam=info`)
- Configuration loaded via `config 0.15` crate (supports env vars, config files)

**Build Configuration:**
- `Cargo.toml` - Workspace root with all dependency versions centralized
- `rustfmt.toml` - Formatter config: edition 2024, max_width 100, use_field_init_shorthand, use_try_shorthand
- `frontend/tsconfig.json` - TypeScript configuration
- `frontend/vite.config.ts` - Vite build config
- `frontend/tailwind.config.js` - Tailwind CSS config
- `frontend/postcss.config.js` - PostCSS config
- `frontend/playwright.config.ts` - E2E test config

## Workspace Crate Structure

| Crate | Type | Purpose |
|-------|------|---------|
| `axiam-core` | lib | Domain types, traits, error definitions |
| `axiam-db` | lib | SurrealDB repository implementations |
| `axiam-auth` | lib | Authentication (password, JWT, MFA, WebAuthn) |
| `axiam-authz` | lib | Authorization engine (RBAC, hierarchy, scopes) |
| `axiam-api-rest` | lib | REST API endpoints (Actix-Web) |
| `axiam-api-grpc` | lib | gRPC service implementations (Tonic) |
| `axiam-amqp` | lib | AMQP consumer/producer (Lapin) |
| `axiam-oauth2` | lib | OAuth2 authorization server + OIDC provider |
| `axiam-federation` | lib | SAML SP + OIDC external IdP federation |
| `axiam-audit` | lib | Audit logging service |
| `axiam-pki` | lib | Certificate management, CA, GnuPG |
| `axiam-email` | lib | Email delivery (SMTP via Lettre) |
| `axiam-server` | bin | Binary entry point, composes all crates |

## Platform Requirements

**Development:**
- Rust 1.93+ (edition 2024 features: native async fn in traits)
- Node.js 22+ (frontend)
- `protobuf-compiler` system package (for gRPC codegen)
- Docker + Docker Compose (for SurrealDB and RabbitMQ dev services)
- `just` task runner

**Production:**
- Docker images: `rust:1.86-bookworm` (build), `debian:bookworm-slim` (runtime)
- Frontend: `node:22-alpine` (build), `nginxinc/nginx-unprivileged:1.27-alpine` (runtime)
- Runtime deps: `ca-certificates`, `libssl3`, `curl` (health checks)
- Kubernetes (k8s manifests provided via Kustomize)
- Container registry: GitHub Container Registry (ghcr.io)

**Compatibility Notes:**
- `pgp 0.19` uses `rand 0.8` / `rand_core 0.6` while workspace uses `rand 0.9` - bridged via explicit `rand_core 0.6` dep in `axiam-pki`
- `rcgen 0.13` requires `time 0.3` crate (not `chrono`) for certificate date parameters
- SurrealDB SDK v3 uses `SurrealValue` derive macro (from `surrealdb-types` crate) instead of serde `Deserialize` for query results
- `samael 0.0.19` used with `default-features = false` to avoid pulling in unnecessary XML dependencies

---

*Stack analysis: 2026-03-28*
