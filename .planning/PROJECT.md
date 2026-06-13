# AXIAM — MVP Hardening & Security Compliance

## What This Is

AXIAM is an open-source Identity and Access Management (IAM) system built with Rust and SurrealDB, targeting microservices and IoT environments. It provides multi-tenant authentication, authorization, OAuth2/OIDC, federation (SAML/OIDC), certificate management, and an admin UI. This milestone focuses on hardening AXIAM for community beta release — closing all security gaps, resolving deferred TODOs, and ensuring compliance with OAuth2, OIDC, OWASP ASVS, and GDPR standards.

## Core Value

AXIAM must be secure enough for production use as an IAM system — any security vulnerability in an identity provider is a vulnerability in every system that depends on it. **No beta user should be at risk.**

## Requirements

### Validated

- ✓ Multi-tenant organization/tenant model with data isolation — Phase 1
- ✓ User CRUD with Argon2id password hashing — Phases 1-2
- ✓ Group, Role, Permission, Resource, Scope management — Phases 2-3
- ✓ JWT authentication (EdDSA/Ed25519) with access/refresh tokens — Phase 2
- ✓ TOTP MFA enrollment and verification — Phase 3
- ✓ WebAuthn/passkey support — Phase 14
- ✓ OAuth2 Authorization Code + PKCE flow — Phase 4
- ✓ OAuth2 Client Credentials flow — Phase 4
- ✓ OIDC Provider (discovery, JWKS, userinfo) — Phase 4
- ✓ RBAC authorization engine with resource hierarchy — Phase 5
- ✓ REST API (Actix-Web) with all CRUD endpoints — Phases 6-7
- ✓ gRPC authorization service (Tonic) — Phase 8
- ✓ AMQP async authorization and audit (Lapin/RabbitMQ) — Phase 9
- ✓ SAML SP and OIDC federation — Phase 10
- ✓ X.509 PKI (CA, cert generation, mTLS) — Phase 11
- ✓ GnuPG/PGP key management — Phase 11
- ✓ Audit logging with notification rules — Phase 12
- ✓ Service accounts with credential rotation — Phase 13
- ✓ Email service with pluggable providers (SMTP, SendGrid, Postmark, Resend, Brevo) — Phase 13
- ✓ Email templates with Handlebars rendering — Phase 13
- ✓ React admin UI (dashboard, CRUD pages for all entities) — Phase 15
- ✓ Docker multi-stage builds (server + frontend) — Phase 16
- ✓ Kubernetes manifests with HPA, probes, security contexts — Phase 16
- ✓ CI/CD pipeline (GitHub Actions: fmt, clippy, build, test, Docker, cosign) — Phase 16

### Active

See `.planning/REQUIREMENTS.md` for detailed REQ-IDs.

**Security — Critical:**
- [ ] Federation token signature verification (OIDC JWKS + SAML XML sig)
- [ ] Per-endpoint RBAC enforcement with admin bootstrap
- [ ] Federation client secret encryption at rest (AES-256-GCM)
- [ ] Session invalidation on password reset
- [x] Migrate JWT from sessionStorage to httpOnly secure cookies — Validated in Phase 1: Cookie-Based Authentication
- [x] CSP, HSTS, Permissions-Policy headers — Validated in Phase 2: Security Headers & Rate Limiting

**Functional — Required for MVP:**
- [ ] Wire email delivery to password reset and verification endpoints
- [ ] Wire notification dispatcher to email service
- [ ] Unauthenticated federation login endpoints (first-time SSO)
- [ ] Service-account dedicated token type
- [ ] Admin user listing endpoint (requires RBAC)
- [ ] Admin MFA management for other users (requires RBAC)

**Compliance:**
- [x] OWASP ASVS audit checklist and remediation — Validated in Phase 7: Compliance Verification & Test Closure
- [x] OAuth2 RFC compliance verification — Validated in Phase 7: Compliance Verification & Test Closure
- [x] OIDC conformance verification — Validated in Phase 7: Compliance Verification & Test Closure
- [ ] GDPR data export and right-to-deletion

**Infrastructure:**
- [ ] CI hardening (security scanning, dependency audit, frontend tests)
- [ ] K8s NetworkPolicy, pod security standards
- [ ] Docker image hardening (non-root, minimal base, health checks)
- [x] gRPC brute-force protection (T19.5) — Validated in Phase 2: Security Headers & Rate Limiting
- [ ] OpenAPI schema accuracy (T19.4)

**Testing:**
- [x] gRPC integration tests (T19.1) — Validated in Phase 7: Compliance Verification & Test Closure
- [x] Concurrent batch authorization (T19.2) — Validated in Phase 7: Compliance Verification & Test Closure
- [x] PKI/certificate tests — Validated in Phase 7: Compliance Verification & Test Closure
- [x] Federation flow tests — Validated in Phase 7 (pre-existing OIDC/SAML e2e suites cited in SC#4)

### Out of Scope

- SDK development (Rust, TypeScript, Python, Java, C#, PHP, Go) — deferred to Phase 17 after hardening
- Performance benchmarking and load testing — separate phase after MVP
- Mobile app — web-first
- Multi-region deployment — single-cluster for beta
- Real-time WebSocket features — not needed for MVP

## Context

AXIAM has completed 16 development phases with a working backend and frontend. However, several security-critical features were deferred to Phase 19 during development to keep phases focused. Before releasing to beta users, all deferred security items must be resolved. The existing Phase 18 (Hardening & Compliance) and Phase 19 (Deferred Improvements) from the original roadmap are being consolidated into this focused hardening milestone.

**Current state:**
- Audit-remediation phases 8–11 complete. Phase 11 (REQ-15, Medium severity) landed: shared repo helpers + typed request DTOs with `DbError::AlreadyExists`→HTTP 409 mapping and unique edge indexes; webhook SSRF re-resolve+pin-at-delivery with AES-256-GCM secret-at-rest; mTLS chain verification to the tenant/org CA; gRPC message-size/timeout/concurrency limits + env-gated TLS + rate-limit bug fix; rate limits on `/auth/mfa/*` and `/oauth2/introspect|revoke`; S256 PKCE enforced for public clients; HMAC-signed AMQP messages; JWKS body cap; dummy-Argon2 on user-not-found, atomic failed-login increment, reset-to-current block, CSRF on `/api/v1` CRUD, `ROUTE_PERMISSION_MAP` enforcement, transactional+gated bootstrap, self-update status-strip + email gate, logout session-ownership; k8s `AXIAM__` ConfigMap fix + secrets + PSA restricted + receiver NetworkPolicies + nginx `/oauth2`+`/.well-known` proxy + prod-compose creds removed; and the frontend Medium items (getApiErrorMessage + Toaster, route guards/ForbiddenPage, login MFA branches, form validation, pagination placeholderData, shared components). 5/5 plans, 24/25 must-haves verified in code; 4 live/browser items (route-guard render, login MFA routing, tenant slug restore, dummy-Argon2 timing) tracked in 11-HUMAN-UAT.md. One deviation: gRPC uses tonic 0.14 `max_frame_size` (no builder `max_decoding_message_size`), tracked for Phase 19.
- Phase 10 (REQ-14, High severity) landed: single Argon2id password-hashing path with pepper, async-safe crypto (spawn_blocking + bounding semaphore), tenant-isolated transactional role/permission edges + resource-hierarchy integrity, sparse tenant settings, idempotent/transactional migrations, AMQP DLQ parity, GDPR purge re-selectability + complete/paginated export, pagination clamp, generic 5xx bodies, TOTP replay rejection, SAML protocol checks, PKI fail-fast (no zero-key fallback), and 8 frontend High items + a frontend lint/tsc CI gate. 3 live/CI-only items (SAML-ON, AMQP DLQ routing, GDPR export completeness) tracked in 10-HUMAN-UAT.md.
- 13 Rust workspace crates, ~139 tests (heavy REST integration bias)
- React 19 + Vite + Tailwind frontend with ~20 admin pages
- Zero tests for: axiam-pki, axiam-authz, axiam-federation, axiam-api-grpc
- 14 TODO comments in code, all tracked with T19.x references
- Authorization engine built but not wired to any endpoint
- Email service built but not connected to auth flows
- Federation accepts tokens without cryptographic verification

## Constraints

- **Security**: Must pass OWASP ASVS Level 2 verification for IAM-relevant controls
- **Compliance**: OAuth2 (RFC 6749/7636), OIDC Core 1.0, GDPR Articles 15/17
- **Tech stack**: Rust edition 2024 (MSRV 1.93), SurrealDB v3 SDK, React 19
- **Build**: Per-crate builds only (`cargo check/test -p <crate>`), never full workspace
- **Code quality**: `cargo fmt` + `cargo clippy -D warnings` on all changes before commit

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Migrate JWT from sessionStorage to httpOnly cookies | IAM products must protect tokens from XSS; sessionStorage is accessible to JS | ✓ Phase 1 |
| OWASP security headers + brute-force rate limiting | IAM endpoints are high-value targets; must resist automated attacks | ✓ Phase 2 |
| Defer lockout UI human testing to Phase 3 | Frontend login requires slug resolution + admin bootstrap (Phase 3 scope) before UI can be manually tested | — Deferred |
| Full per-endpoint RBAC (not simplified admin/user check) | MVP users will expect granular permissions; simplification would need rework later | — Pending |
| Consolidate Phase 18 + 19 into single hardening milestone | Security items span both phases; treating as one prevents gaps | — Pending |
| SMTP + external provider support for email | User wants configurable email delivery, not just logging | — Pending |
| Defer SDKs until after hardening | Security must come before API consumption libraries | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-06-13 after Phase 11 completion — REQ-15 medium-severity remediation (5/5 plans, 24/25 must-haves verified in code); 4 live-verification items tracked in 11-HUMAN-UAT.md.*
