# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Require organization context for login/refresh (#204)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Added

- Add --changelog to summarize commits into CHANGELOG.md

### Changed

- Wire org context into the TypeScript bench; list all 11 SDKs in README (#199)

### Fixed

- Wire Keycloak TLS via entrypoint; stop passing empty KC_HTTPS_*
- Correct image labeling metadata for GHCR
- Drop --optimized from Keycloak first start
- Dial gRPC plaintext regardless of HTTP TLS profile
- Merge tlsOptions() into gRPC scenarios so cert-skip applies
- Skip k6 server-cert verify for private-CA TLS profiles
- Neutralize rate limits so p0 measures endpoint capacity
- Apply the configured password pepper when hashing the admin (#200)
- Don't set AXIAM__AUTH__PEPPER (breaks bootstrap-admin login)
- Write resource CSV rows; configure OAuth2/optional secrets; skip OAuth2 when unset
- Supply org context on login; make bench-down work without secrets
- Provide mandatory AMQP signing key for the AXIAM target
- Bootstrap AXIAM secrets in bench-up; auto-track image tag
- Correct just variable-override ordering so bench-matrix works

## [1.0.0-alpha3] - 2026-07-16

Third alpha. Build/release tuning and project-infrastructure changes only. No
server runtime or API behavior changes — the OpenAPI specification is
byte-for-byte identical apart from its `info.version` string.

### Added

- **Public marketing & documentation website**, deployed to GitHub Pages.

### Changed

- **Release build profile** — added `[profile.release]` to the workspace-root
  `Cargo.toml`, tuned for execution speed first and footprint second:
  `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`.
  Cargo only honors profiles at the workspace root, so this single section
  covers `axiam-server` and every crate it links. `panic = "abort"` is
  intentionally omitted to preserve per-request panic isolation on the
  long-running REST/gRPC/AMQP server. Release builds are slower in exchange for
  faster runtime.

## [1.0.0-alpha2] - 2026-07-16

Second alpha. Adds the SDK declarative-authorization contract and release-prep
polish; no server runtime/API behavior changes.

### Added

- **CONTRACT.md §11 — Declarative Authorization Helpers**: the canonical
  `require_auth` / `require_access(action, resource[, scope])` / `require_role`
  vocabulary layered on the §10 guard, with the per-language naming map and
  normative semantics (subject propagation, 401/403/400/503 error mapping,
  fail-closed on transport error, no decision caching). Marked SHOULD-level and
  recorded as non-breaking/additive; contract version bumped to 1.1.
- README build/coverage/license badges.

### Changed

- Roadmap "Development Progress": Phase 17 (SDKs) and Phase 18 (security audit)
  marked Done.

### Fixed / CI

- Added a free-disk-space step to the heavy Rust `test` and `cargo-llvm-cov`
  jobs to prevent the RabbitMQ disk-space alarm that intermittently failed CI.

## [1.0.0-alpha1] - 2026-07-16

Patch release over `1.0.0-alpha` that fixes the release pipeline so the
aarch64 server binary and the OpenAPI drift gate build cleanly. There are no
functional or API changes — the OpenAPI specification is byte-for-byte
identical apart from its `info.version` string.

### Fixed

- **aarch64 release build** — the *Build Release Binary (aarch64)* job failed
  at "Install build dependencies" because the native `ubuntu-24.04-arm` runner
  intermittently could not reach `ports.ubuntu.com` (IPv6 unreachable, IPv4
  timeouts). The apt step now forces IPv4, prefers Azure's in-network ports
  mirror, and retries with backoff, without changing the installed package set.
- **OpenAPI version drift** — the REST spec's `info.version` was a hardcoded
  literal that fell out of sync with the crate version and failed the OpenAPI
  drift gate. It is now bound to `CARGO_PKG_VERSION`, so it always tracks the
  workspace version and cannot drift on a future version bump.

[1.0.0-alpha1]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha1

## [1.0.0-alpha] - 2026-07-15

First alpha release of AXIAM (Access eXtended Identity and Authorization
Management). This is an early, pre-production preview intended for evaluation
and feedback — APIs and data models may still change before the beta and
stable releases.

### Added

- **Multi-tenancy** — organizations as top-level entities containing fully
  data-isolated tenants; all domain entities (users, groups, roles,
  permissions, resources, certificates) are tenant-scoped.
- **Authentication** — username/password (Argon2id), MFA (TOTP), social login
  and certificate-based (mTLS) authentication; EdDSA (Ed25519) JWT access
  tokens with opaque, single-use, rotating refresh tokens.
- **Authorization** — additive, default-deny RBAC engine with role
  inheritance through hierarchical resources, scopes for sub-resource
  granularity, and group-inherited role assignments.
- **OAuth2 / OpenID Connect** — authorization server and OIDC provider
  (Authorization Code + PKCE, Client Credentials, Refresh Token).
- **Federation** — SAML SP and OpenID Connect federation for cross-domain SSO.
- **APIs** — REST (Actix-Web, OpenAPI-documented), gRPC (Tonic) for
  low-latency authz checks, and AMQP (Lapin) for async/deferred authz, audit
  ingestion and event notifications.
- **PKI** — per-tenant X.509 certificate management signed by an organization
  CA, with CA private keys encrypted at rest (AES-256-GCM); GnuPG/OpenPGP
  integration for audit signing and encrypted data exports.
- **Auditing** — append-only audit logging.
- **Webhooks** — real-time event notifications to external systems, signed
  with HMAC-SHA256.
- **Admin frontend** — React + TypeScript administration UI.
- **Packaging & deployment** — multi-arch (amd64/arm64) container images and
  standalone server binaries, Docker Compose and Kubernetes manifests.
- **Client SDKs** — Rust, TypeScript, Python, Java, C#, PHP and Go SDKs, each
  released in its own repository against the shared API contract.

[1.0.0-alpha]: https://github.com/ilpanich/axiam/releases/tag/axiam-server/v1.0.0-alpha
