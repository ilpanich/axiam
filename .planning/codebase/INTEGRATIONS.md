# External Integrations

**Analysis Date:** 2026-03-28

## APIs & External Services

**gRPC Services (self-hosted):**
- Protocol Buffers defined in `proto/axiam/v1/`
  - `authorization.proto` - Authorization check service
  - `token.proto` - Token validation/introspection service
  - `user.proto` - User lookup service
- Server: Tonic 0.14 (`crates/axiam-api-grpc/`)
- Build codegen: `tonic-build 0.14` + `tonic-prost-build 0.14` (in `build.rs`)
- Port: 50051

**REST API (self-hosted):**
- Actix-Web 4 (`crates/axiam-api-rest/`)
- OpenAPI docs: utoipa 5 + Swagger UI at `/swagger-ui`
- Port: 8080
- Health endpoint: `GET /health`
- CORS: `actix-cors 0.7`

**OAuth2 / OpenID Connect Provider (self-hosted):**
- Implementation: `crates/axiam-oauth2/`
- Flows: Authorization Code + PKCE, Client Credentials, Refresh Token
- OIDC discovery, JWKS endpoints

**Federation (outbound):**
- SAML SP: `crates/axiam-federation/` via `samael 0.0.19`
- OIDC external IdP: `crates/axiam-federation/` via `reqwest 0.12`
- HTTP client for metadata discovery and token exchange

**Webhook Delivery (outbound):**
- HMAC-SHA256 signed payloads (`hmac 0.12` + `sha2 0.10`)
- HTTP delivery via `reqwest 0.12`
- Configured per-tenant

**Email Delivery (outbound):**
- SMTP via `lettre 0.11` (`crates/axiam-email/`)
- TLS: rustls (tokio1-rustls-tls feature)
- Pluggable provider architecture

## Data Storage

**Database:**
- SurrealDB v2 (server image: `surrealdb/surrealdb:v2`)
  - Connection: WebSocket (`ws://surrealdb:8000`)
  - Env var: `AXIAM_DB__URL`
  - Credentials: `AXIAM_DB__USERNAME`, `AXIAM_DB__PASSWORD`
  - Namespace: `AXIAM_DB__NAMESPACE` (default: `axiam`)
  - Database: `AXIAM_DB__DATABASE` (default: `axiam`)
  - Client: `surrealdb 3` Rust SDK with `surrealdb-types 3` for derive macros
  - Repository layer: `crates/axiam-db/`
  - Test mode: In-memory engine via `kv-mem` feature (no server needed)
  - Deployment: StatefulSet in Kubernetes (`k8s/surrealdb/statefulset.yml`)

**File Storage:**
- Not applicable (no external file storage integration)
- Certificates and keys handled in-memory or stored in SurrealDB

**Caching:**
- None detected (no Redis, Memcached, or in-process cache integration)

## Message Broker

**RabbitMQ (AMQP):**
- Image: `rabbitmq:3-management-alpine`
- Connection: `amqp://rabbitmq:5672`
- Env var: `AXIAM_AMQP__URL`
- Client: `lapin 4` (`crates/axiam-amqp/`)
- Management UI: port 15672 (dev only)
- Use cases:
  - Async/deferred authorization decisions
  - Audit log ingestion
  - Event notifications
- Deployment: StatefulSet in Kubernetes (`k8s/rabbitmq/statefulset.yml`)

## Authentication & Identity

**Self-hosted (AXIAM IS the auth provider):**
- Password authentication: Argon2id via `argon2 0.5` (`crates/axiam-auth/`)
- JWT tokens: EdDSA (Ed25519) via `jsonwebtoken 10`
- MFA: TOTP via `totp-rs 5`, WebAuthn via `webauthn-rs 0.5`
- Certificate auth: mTLS for IoT devices via `rcgen 0.13`, `x509-parser 0.17`
- OAuth2/OIDC provider: `crates/axiam-oauth2/`

**Federation (external IdPs):**
- SAML SP via `samael 0.0.19` (`crates/axiam-federation/`)
- OIDC external IdP via `reqwest` + standard OIDC discovery (`crates/axiam-federation/`)

## PKI & Certificate Management

**X.509 Certificates:**
- Generation: `rcgen 0.13` (`crates/axiam-pki/`)
- Parsing/validation: `x509-parser 0.17`
- Key types: RSA-4096, Ed25519
- CA private keys: AES-256-GCM encrypted at rest (`aes-gcm 0.10`)
- Per-organization CA, per-tenant certificate issuance

**OpenPGP:**
- Key management: `pgp 0.19` (`crates/axiam-pki/`)
- Use cases: Audit log signing, encrypted data exports
- Key types: Ed25519Legacy (signing), RSA-4096 (encryption)

## Monitoring & Observability

**Structured Logging:**
- `tracing 0.1` + `tracing-subscriber 0.3` with env-filter and JSON output
- `tracing-actix-web 0.7` for HTTP request tracing
- Log level: `RUST_LOG` env var (default: `info,axiam=debug` in k8s)

**Error Tracking:**
- None detected (no Sentry, Datadog, etc.)

**Metrics:**
- None detected (no Prometheus metrics endpoint)

**Health Checks:**
- REST: `GET /health` (used by Docker HEALTHCHECK and k8s probes)

## CI/CD & Deployment

**CI Pipeline (GitHub Actions):**
- Config: `.github/workflows/ci.yml`
- Triggers: Push to `main`, PRs to `main`
- Jobs:
  1. **Rustfmt** - `cargo fmt --all -- --check`
  2. **Clippy** - `cargo clippy --workspace --all-targets -- -D warnings`
  3. **Build** - `cargo build --workspace`
  4. **Test** - `cargo test --workspace` (with SurrealDB v2 + RabbitMQ services)
- Rust toolchain: `dtolnay/rust-toolchain@stable`
- Caching: `Swatinem/rust-cache@v2`
- System dep: `protobuf-compiler` installed in clippy, build, test jobs

**CD Pipeline (GitHub Actions):**
- Config: `.github/workflows/release.yml`
- Trigger: Push tags matching `v*`
- Jobs:
  1. **Build Server Image** - Docker build + push to ghcr.io + cosign signing + SLSA provenance attestation
  2. **Build Frontend Image** - Same as server
  3. **Build Release Binary** - `cargo build --release -p axiam-server`, strip, create tarball
  4. **Create GitHub Release** - Changelog via `git-cliff`, attach binary tarball
- Image signing: `sigstore/cosign-installer@v3`
- Provenance: `actions/attest-build-provenance@v2`
- Changelog: `orhun/git-cliff-action@v4`

**Container Registry:**
- GitHub Container Registry (`ghcr.io`)
- Images: `ghcr.io/{repo}/server`, `ghcr.io/{repo}/frontend`
- Tags: semver (`{{version}}`, `{{major}}.{{minor}}`), SHA

**Docker:**
- `docker/Dockerfile.server` - Multi-stage Rust build (rust:1.86-bookworm -> debian:bookworm-slim)
- `docker/Dockerfile.frontend` - Multi-stage Node build (node:22-alpine -> nginxinc/nginx-unprivileged:1.27-alpine)
- `docker/docker-compose.dev.yml` - Dev services (SurrealDB + RabbitMQ)
- `docker/docker-compose.prod.yml` - Full stack (server + frontend + SurrealDB + RabbitMQ)
- `docker/nginx.conf` - Frontend nginx config with SPA fallback, gzip, security headers, API proxy

**Kubernetes:**
- Namespace: `axiam` (`k8s/namespace.yml`)
- Orchestration: Kustomize (`k8s/kustomization.yml`)
- Components:
  - **Server**: Deployment + Service + HPA (2-10 replicas, CPU 70% / Memory 80%) + ConfigMap + Secret
  - **Frontend**: Deployment + Service
  - **SurrealDB**: StatefulSet + Service + Secret
  - **RabbitMQ**: StatefulSet + Service + Secret
  - **Ingress**: nginx ingress controller, TLS termination
    - `axiam.example.com/api` -> server:8080
    - `axiam.example.com/` -> frontend:80
    - `grpc.axiam.example.com/` -> server:50051 (GRPC backend protocol)

## Environment Configuration

**Required env vars (server):**
- `AXIAM_DB__URL` - SurrealDB connection URL
- `AXIAM_DB__USERNAME` - SurrealDB username
- `AXIAM_DB__PASSWORD` - SurrealDB password
- `AXIAM_DB__NAMESPACE` - SurrealDB namespace
- `AXIAM_DB__DATABASE` - SurrealDB database name
- `AXIAM_AMQP__URL` - RabbitMQ AMQP connection URL
- `AXIAM_SERVER__HOST` - REST API bind address
- `AXIAM_GRPC__HOST` - gRPC bind address
- `RUST_LOG` - Log level

**Secrets location:**
- Kubernetes: `k8s/server/secret.yml`, `k8s/surrealdb/secret.yml`, `k8s/rabbitmq/secret.yml`
- Docker Compose: Inline environment variables (dev/test only)
- No `.env` file committed (none detected in repo)

## Webhooks & Callbacks

**Incoming:**
- SAML ACS (Assertion Consumer Service) endpoint - receives SAML responses from external IdPs
- OAuth2 redirect URI - receives authorization codes from external OIDC providers

**Outgoing:**
- Webhook delivery to tenant-configured URLs
- HMAC-SHA256 signed payloads
- Event-driven (user creation, role changes, auth events, etc.)

---

*Integration audit: 2026-03-28*
