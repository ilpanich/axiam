# Roadmap — MVP Hardening & Security Compliance

> Milestone: v1.0-beta
> Phases: 14 | Granularity: standard
> Created: 2026-03-30

## Overview

AXIAM has completed 16 development phases with a working backend and frontend. This milestone closes all security gaps, wires deferred features, and verifies compliance before community beta release. The work proceeds from foundational auth changes (cookie migration) through security hardening (headers, rate limiting, RBAC), feature completion (federation, email, GDPR), infrastructure hardening, and final compliance verification.

## Phases

- [x] **Phase 1: Cookie-Based Authentication** - Migrate JWT delivery from sessionStorage to httpOnly secure cookies with CSRF protection (completed 2026-04-04)
- [x] **Phase 2: Security Headers & Rate Limiting** - Add OWASP-recommended security headers and brute-force protection to all endpoints (completed 2026-05-29)
- [x] **Phase 3: RBAC Enforcement** - Wire authorization engine to every endpoint with default-deny and admin bootstrap (completed 2026-05-29)
- [x] **Phase 4: Federation Verification & Session Security** - Cryptographically verify federation tokens and enforce session lifecycle (completed 2026-05-29)
- [x] **Phase 5: Email Delivery & GDPR Compliance** - Wire email service to auth flows and implement data subject rights (completed 2026-06-02)
- [x] **Phase 6: CI/CD & Infrastructure Hardening** - Add security scanning to CI and harden Docker/K8s configurations (completed 2026-06-07)
- [x] **Phase 7: Compliance Verification & Test Closure** - Verify OWASP ASVS, OAuth2 RFC, OIDC conformance and close remaining test gaps (completed 2026-06-07)
- [x] **Phase 8: Build Unblock (Wave 0)** - Make `axiam-server` compile and pass CI `-D warnings` (completed 2026-06-10)
- [x] **Phase 9: Critical Remediation (Wave 1)** - Close cross-tenant IDOR, gRPC auth, frontend auth flows, silent refresh, federation secret encryption (completed 2026-06-12)
- [x] **Phase 10: High Remediation (Wave 2)** - Hashing/pepper, async-safe crypto, tenant isolation, GDPR/SAML/TOTP correctness, frontend High items (completed 2026-06-13)
- [x] **Phase 11: Medium Remediation (Wave 3)** - Repo/DTO consolidation, transport limits, auth/infra hardening, frontend Medium items (completed 2026-06-13)
- [x] **Phase 12: Low / Trivial Remediation (Wave 4)** - Cleanup, dead-code, dep pruning, i18n, security polish + whole-effort verification (completed 2026-06-19)
- [x] **Phase 13: SurrealDB Connection Resilience** - Reconnect-safe ns/db selection + ns/db-asserting health check; first-run seed repair; unblocks deferred Phase-12 smoke (completed 2026-06-19)

- [x] **Phase 14: Frontend List-Contract Alignment** - Unwrap backend PaginatedResult ({items}) in all frontend list services via a shared defensive helper; fixes the dashboard crash + list-page empties (completed 2026-06-19)

> Audit-remediation tranche (Phases 8–12) added 2026-06-10 from `claude_dev/remediation-plan.md`; sequential with a green-build gate between waves.
> Phase 13 added 2026-06-19 — durable fix for the SurrealDB stale-connection bug found during the Phase-12 manual smoke.
> Phase 14 added 2026-06-19 — systemic frontend list-contract mismatch found during the Phase-12/13 smoke.

## Phase Details

### Phase 1: Cookie-Based Authentication

**Goal**: Users authenticate via httpOnly secure cookies instead of XSS-vulnerable sessionStorage tokens
**Depends on**: Nothing (foundational change)
**Requirements**: REQ-1
**Success Criteria** (what must be TRUE):

  1. Browser never exposes JWT tokens to JavaScript (no sessionStorage, no Authorization header)
  2. Login returns Set-Cookie headers with httpOnly, Secure, SameSite=Strict flags
  3. Refresh token cookie is path-scoped to the refresh endpoint only
  4. State-changing API requests are protected against CSRF via double-submit cookie pattern
  5. Frontend login/logout/refresh flows work end-to-end with cookie auth

**Plans**: 3 plans

Plans:

- [x] 01-01-PLAN.md — Backend cookie middleware, CSRF, auth handlers, extractor, /me endpoint
- [x] 01-02-PLAN.md — Frontend auth refactor (Zustand store, Axios client, auth init hook)
- [x] 01-03-PLAN.md — Integration tests rewritten for cookie-based auth flow

**UI hint**: yes

### Scope

- Backend cookie middleware (Set-Cookie on login/refresh, clear on logout)
- CSRF double-submit cookie implementation
- Frontend refactor: remove sessionStorage handling, remove Authorization header, switch to credentials: "include"
- Update all existing integration tests for cookie-based auth
- Docker compose dev environment updated for cookie auth (REQ-10 AC item, moved here as dependency)

---

### Phase 2: Security Headers & Rate Limiting

**Goal**: All HTTP responses include security headers and authentication endpoints resist brute-force attacks
**Depends on**: Phase 1
**Requirements**: REQ-2, REQ-3
**Success Criteria** (what must be TRUE):

  1. Security audit tools (e.g., securityheaders.com) report no missing headers on API responses
  2. Nginx frontend config includes CSP, HSTS, and Permissions-Policy headers
  3. Repeated login attempts from the same IP are throttled after 10 requests per minute
  4. Account locks out after 5 consecutive failed logins with a 15-minute cooldown
  5. gRPC authorization endpoint has brute-force protection

**Plans**: 5 plans

Plans:

- [x] 02-01-PLAN.md — Security headers middleware (backend + nginx) + tests
- [x] 02-02-PLAN.md — REST rate limiting (actix-governor, config, per-endpoint wiring)
- [x] 02-03-PLAN.md — gRPC rate limiting (tower-governor layer)
- [x] 02-04-PLAN.md — Unlock endpoint + UserResponse extension + frontend lockout UI
- [x] 02-05-PLAN.md — Gap closure: wire register rate limit + fix lockout cooldown default

**UI hint**: yes

### Scope

- Actix-Web middleware for X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- Nginx config for CSP, HSTS, Permissions-Policy
- actix-governor rate limiting on /auth/login, /auth/register, /oauth2/token, /auth/password-reset
- Account lockout logic (5 failures, 15-min cooldown)
- Lockout status visible in admin UI
- gRPC brute-force protection (T19.5)

---

### Phase 3: RBAC Enforcement

**Goal**: Every API endpoint enforces authorization with default-deny, and the first admin can bootstrap the system
**Depends on**: Phase 1, Phase 2
**Requirements**: REQ-4
**Success Criteria** (what must be TRUE):

  1. An unauthenticated request to any non-public endpoint returns 401
  2. An authenticated user without the required permission gets 403
  3. Self-service endpoints (profile, own MFA) work for the resource owner but reject other users
  4. Admin bootstrap creates the first admin user when no admins exist, then disables itself
  5. Admin can list users and manage MFA for other users

**Plans**: 5 plans

Plans:

- [x] 03-01-PLAN.md — Permission registry, seeder, AuthzMiddleware, AuthzChecker wiring
- [x] 03-02-PLAN.md — Handler-level RequirePermission checks + self-service ownership
- [x] 03-03-PLAN.md — Admin bootstrap endpoint + default role seeding
- [x] 03-04-PLAN.md — Frontend RBAC sidebar gating + /me permissions response
- [x] 03-05-PLAN.md — Integration tests + bootstrap page UI

**UI hint**: yes

### Scope

- Default-deny authorization middleware
- Public endpoint allowlist (login, register, health, OIDC discovery, JWKS, federation callbacks)
- Permission-per-endpoint mapping (e.g., users:read, users:write, roles:read)
- Self-service caller_user_id == target_user_id checks
- Admin bootstrap endpoint with AXIAM_BOOTSTRAP_ADMIN_EMAIL env var
- Admin user listing endpoint (T19.3)
- Admin MFA management for other users (T19.3)
- Integration test: every registered route has an authorization check

---

### Phase 4: Federation Verification & Session Security

**Goal**: Federation tokens are cryptographically verified and session lifecycle is properly managed
**Depends on**: Phase 1
**Requirements**: REQ-5, REQ-7
**Success Criteria** (what must be TRUE):

  1. OIDC login rejects tokens with invalid signatures, expired claims, or wrong audience
  2. SAML login rejects responses with invalid XML signatures or expired conditions
  3. Changing or resetting a password immediately invalidates all other active sessions
  4. Federation client secrets are encrypted at rest in the database
  5. Service accounts receive a dedicated token type distinguishable from user tokens

**Plans**: 5 plans

### Scope

- OIDC JWKS fetching, caching (1h TTL), and ID token signature verification
- OIDC claim validation (iss, aud, exp, nonce) with algorithm pinning (reject "none")
- SAML XML signature verification and condition validation (NotOnOrAfter, NotBefore, Audience)
- SAML assertion ID replay tracking
- Clock skew tolerance (60 seconds)
- Federation client secret encryption with AES-256-GCM (T19.8)
- Password change/reset invalidates all refresh tokens and sessions (T19.10)
- MFA reset session invalidation
- Service-account dedicated token type with sub_kind: "ServiceAccount"
- Unauthenticated federation login endpoints for first-time SSO

### Phase 19 follow-ups raised during Phase 4 execution

- Per-FederationConfig registered redirect_uri allowlist for first-time SSO endpoints (currently only a scheme/host HTTPS guard; needs a schema column) (T19.14)
- Resolve real org_id from tenant in SSO callback session/token creation (currently `Uuid::nil()`; SSO access tokens carry an empty org_id claim) (T19.15)

---

### Phase 5: Email Delivery & GDPR Compliance

**Goal**: Auth flows send real emails and users can exercise GDPR data rights
**Depends on**: Phase 3
**Requirements**: REQ-6, REQ-8
**Success Criteria** (what must be TRUE):

  1. Password reset flow sends an email with a reset link to the user's address
  2. Email verification flow sends a verification email after registration
  3. A user can export all their personal data as a single JSON download
  4. A user can request account deletion, which removes PII and pseudonymizes audit logs
  5. Audit log entries for deleted users show DELETED_USER_<hash> instead of PII

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 05-01-PLAN.md — Schema v15 + EmailConfigRepository (encrypted secrets) + gdpr_pseudonym + user anonymization + GDPR support repos
- [x] 05-02-PLAN.md — AMQP mail transport: OutboundMailMessage/MailType + mail.outbound queue + dead-letter queue

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 05-03-PLAN.md — Mail consumer (retry + delivery_failed audit) + key loading + email-secret backfill + consumer spawn
- [x] 05-04-PLAN.md — Wire reset/verify/notification stubs to enqueue mail (enumeration-safe) + consent at registration

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 05-05-PLAN.md — GDPR Art. 15 export + Art. 17 erasure (purge/export sweeps, pseudonymization, cancel) + gdpr_test.rs

### Scope

- Wire password reset handler to EmailService (T19.11)
- Wire email verification handler to EmailService (T19.12)
- Wire notification dispatcher to EmailService (T19.13)
- Email provider configuration (SMTP, SendGrid, Postmark, Resend, Brevo)
- Email delivery failure audit logging with retry info
- Template escaping audit (no triple-stash {{{ }}})
- Reset/verification URLs use server-generated tokens only
- GDPR data export endpoint (Art. 15) — all user data as JSON
- GDPR data deletion endpoint (Art. 17) — remove user, pseudonymize audit logs
- Consent tracking (record when user accepted terms)
- Integration tests for export completeness and deletion/pseudonymization

---

### Phase 6: CI/CD & Infrastructure Hardening

**Goal**: CI pipeline catches vulnerabilities automatically and deployment configs follow security best practices
**Depends on**: Phase 1 (cookie auth changes affect Docker compose and K8s configs)
**Requirements**: REQ-9, REQ-10
**Success Criteria** (what must be TRUE):

  1. A PR with a known vulnerable dependency fails CI
  2. Docker images run as non-root with a minimal base image
  3. K8s NetworkPolicy restricts pod-to-pod traffic to only required paths
  4. Container image scan runs on every Docker build in CI
  5. OpenAPI schema matches actual endpoint signatures

**Plans**: 5 plans

Plans:
**Wave 1**

- [x] 06-01-PLAN.md — Dependency/license scanning + remediation: deny.toml, dependabot, ci.yml security-scan, license fix, 36-vuln burndown (D-01..D-04, D-16)
- [x] 06-03-PLAN.md — Distroless server image + healthcheck subcommand + frontend digest pins + license labels (D-08, D-09, D-10, D-04)
- [x] 06-05-PLAN.md — K8s NetworkPolicy + Pod Security Standards + secret hygiene (D-11, D-12, D-13, D-14)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 06-02-PLAN.md — release.yml build→scan→push→sign reorder with trivy image gate (D-06, D-07) — depends on 06-03
- [x] 06-04-PLAN.md — Frontend build hardening (sourcemap/SRI) + route↔openapi parity test + dev cookie Secure flag (D-15, D-17, D-18) — depends on 06-01

### Scope

- cargo-audit step in CI (fail on known vulnerabilities with patches)
- cargo-deny step in CI (license + vulnerability + duplicate checking)
- npm audit step in CI for frontend
- trivy container image scan after Docker build
- hadolint Dockerfile linting
- Frontend production build: sourcemap: false, SRI for assets
- OpenAPI schema accuracy verification (T19.4)
- Docker images: non-root user, distroless/alpine base
- K8s NetworkPolicy (server-surrealdb, server-rabbitmq, ingress-frontend, ingress-server)
- K8s pod security standards (restricted profile)
- All K8s secrets use secretKeyRef
- Health check endpoint validation in K8s probes

---

### Phase 7: Compliance Verification & Test Closure

**Goal**: AXIAM passes security compliance audits and all critical test gaps are closed
**Depends on**: Phase 1, Phase 2, Phase 3, Phase 4, Phase 5, Phase 6
**Requirements**: REQ-11
**Success Criteria** (what must be TRUE):

  1. OWASP ASVS Level 2 checklist for IAM-relevant controls has no open items
  2. OAuth2 RFC 6749/7636 compliance verification passes (all required parameters, error codes, PKCE)
  3. OIDC Core 1.0 conformance verification passes (discovery, JWKS, userinfo, token validation)
  4. All previously untested crates (axiam-pki, axiam-authz, axiam-federation, axiam-api-grpc) have integration tests
  5. Frontend E2E tests cover login, RBAC-gated navigation, and federation flows

**Plans**: 5 plans
**UI hint**: yes

Plans:

**Wave 1**

- [x] 07-01-PLAN.md — axiam-pki critical-path tests (CA, leaf cert, mTLS reject, PGP sign+verify)
- [x] 07-02-PLAN.md — OAuth2 RFC 6749/7636 + OIDC Core conformance tests + MUST-matrix docs + FINDINGS seed
- [x] 07-03-PLAN.md — gRPC in-process tonic harness + authz (T19.1) + concurrent batch (T19.2)
- [x] 07-04-PLAN.md — Frontend E2E rewrite (11 specs, cookie-auth) + live-backend seeded-DB CI job

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 07-05-PLAN.md — ASVS L2 checklist (V2-V14) + finalized FINDINGS register (Wave 2)

### Scope

- gRPC authorization integration tests (T19.1)
- Concurrent batch authorization tests (T19.2)
- PKI/certificate generation tests (axiam-pki)
- Federation OIDC flow integration tests (with mocked IdP)
- Federation SAML flow integration tests (with mocked IdP)
- RBAC enforcement integration tests (every endpoint)
- Cookie auth flow integration tests
- GDPR export/deletion integration tests
- Frontend E2E tests (login, RBAC, federation flows)
- OWASP ASVS Level 2 audit checklist and remediation
- OAuth2 RFC compliance verification
- OIDC conformance verification

---

### Phase 8: Build Unblock (Wave 0)

**Goal**: `axiam-server` compiles and the CI build job passes under `-D warnings`, unblocking every subsequent remediation wave
**Depends on**: Phase 7 (foundational — BLOCKS all of Waves 1–4)
**Requirements**: REQ-12
**Success Criteria** (what must be TRUE):

  1. `cargo build -p axiam-server` succeeds (uuid/chrono/serde_json moved from `[dev-dependencies]` to `[dependencies]` with `workspace = true`; direct `sha2 = { workspace = true }` added)
  2. `cleanup.rs:260,399` import `sha2::{Digest, Sha256}` instead of `rsa::sha2::{...}`; `rsa` dropped from binary deps if now unused
  3. The CI `build` job fails on `-p axiam-server` at the current tip and goes green after the fix
  4. The 12 warnings in `req5_*/req7_*/cleanup_task` tests are cleared so `-D warnings` passes

**Plans**: TBD (run `/gsd:plan-phase 8`)

### Scope

- `crates/axiam-server/Cargo.toml` dependency relocation + `sha2` direct dep
- `crates/axiam-server/src/cleanup.rs` import fix
- Warning cleanup in server test modules

---

### Phase 9: Critical Remediation (Wave 1)

**Goal**: Close cross-tenant data exposure and broken authentication lifecycle defects (SEC-002, SEC-003, SEC-044/CQ-F27, CQ-F28, SEC-045/SEC-017)
**Depends on**: Phase 8 (green-build gate — Wave 0 must pass before Wave 1)
**Requirements**: REQ-13
**Success Criteria** (what must be TRUE):

  1. Cross-org IDOR closed: org-nested routes (orgs/tenants/CA certs) return 403 when `org_id != user.org_id`; org create/list restricted to system-admin; cross-org negative tests pass
  2. gRPC authenticated: Tonic interceptor validates bearer JWT / mTLS identity; tenant_id/subject_id derived from verified claims; public gRPC ingress removed; interceptor accept/reject tests added
  3. All six frontend auth flows call real backend endpoints via a typed `auth.ts` service (reset, reset-confirm, verify-email, resend, change-password, MFA enroll/confirm); frontend↔OpenAPI contract test gates in CI
  4. Silent refresh succeeds (CSRF token attached, skip-list narrowed); boot refresh attempted once before declaring unauthenticated
  5. Federation client secrets decrypted at use and encrypted on create/update; secret never serialized; OIDC login succeeds after restart/backfill

**Plans**: 5 plans

Plans:
**Wave 1**

- [x] 09-01-PLAN.md — Cross-org IDOR guards (orgs/tenants/CA certs) + system-admin restriction + cross-org 403 tests (SEC-002)
- [x] 09-02-PLAN.md — gRPC Tonic auth interceptor + remove public gRPC ingress + accept/reject tests (SEC-003)
- [x] 09-03-PLAN.md — Typed auth.ts service + rewire 6 auth pages + Playwright contract test (SEC-044/CQ-F27)
- [x] 09-05-PLAN.md — Federation secret decrypt-at-use/encrypt-on-write/never-serialize + post-restart login test (SEC-045/SEC-017)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 09-04-PLAN.md — Silent/boot refresh CSRF fix + narrowed skip-list + CSRF contract test (CQ-F28)

### Scope

- `handlers/organizations.rs`, `tenants.rs`, `ca_certificates.rs` — org-ownership checks (reuse `settings.rs:43` pattern) + cross-org negative tests
- `axiam-api-grpc` — Tonic auth interceptor; `k8s/ingress.yml` remove public gRPC exposure
- `frontend/src/services/auth.ts` + 6 auth pages rewired to real routes; frontend↔OpenAPI contract test
- `lib/api.ts`, `hooks/useAuthInit.ts`, `lib/fetchCurrentUser.ts` — silent/boot refresh fix
- `OidcFederationService`/`SamlFederationService`, `repository/federation_config.rs`, `models/federation.rs` — secret decrypt-at-use + encrypt-at-rest

---

### Phase 10: High Remediation (Wave 2)

**Goal**: Resolve high-severity correctness, async-safety, tenant-isolation, and protocol-hardening defects. *Foundational first:* single hashing path + pepper (CQ-B09/B01) and `load_key_from_env` extraction (CQ-B43, enables SEC-012)
**Depends on**: Phase 9 (green-build gate)
**Requirements**: REQ-14
**Success Criteria** (what must be TRUE):

  1. One password-hashing path with pepper (repo-layer hasher deleted); REST-created user logs in with pepper set
  2. Argon2 hash/verify and PKI keygen/sign run in `spawn_blocking` behind a bounding semaphore
  3. Tenant settings persist sparse overrides merged against org baseline at read time; baseline change propagates
  4. Tenant-scoped edge mutations (role/permission) verify both endpoints belong to tenant and run in transactions; resource hierarchy rejects cycles/orphans and drops depth-50 truncation
  5. GDPR purge/export correctness (re-selectable on failure, complete export, paginated audit, Failed status); SAML protocol checks (InResponseTo/Destination/Conditions/XSW); TOTP replay rejected; pagination clamped; 5xx errors generic; PKI fails fast on missing key; AMQP DLQ parity; migration idempotent/transactional
  6. Frontend High items fixed (real `user.id`, ConfirmDialog label, debounce cleanup, useQuery search, logout clears store, eslint+`tsc -b` in CI, org settings save, no fabricated tenant status)

**Plans**: 6 plans in 4 waves

- [x] 10-01-PLAN.md — single password-hashing path + pepper wiring (CQ-B09/B01) [wave 1]
- [x] 10-02-PLAN.md — load_key_from_env extraction + PKI fail-fast (CQ-B43, SEC-012) [wave 2]
- [x] 10-03-PLAN.md — async-safe crypto + tenant edge isolation + resource hierarchy (CQ-B02/B07/B08) [wave 3]
- [x] 10-04-PLAN.md — sparse settings, migrations, AMQP DLQ, GDPR correctness (CQ-B03/B05/B06/B38) [wave 3]
- [x] 10-05-PLAN.md — pagination clamp, generic 5xx, TOTP replay, SAML hardening, federation API (SEC-005/008/010/011, CQ-B30/B33/B40) [wave 4]
- [x] 10-06-PLAN.md — frontend High items + CI lint/tsc gate (CQ-F01..F08) [wave 1]

### Scope

- `axiam-auth/password.rs`, `db/repository/user.rs`, `main.rs` — single hashing path + pepper
- `auth/service.rs`, `policy.rs`, `axiam-pki/*` — `spawn_blocking` + semaphore for Argon2/PKI
- `repository/settings.rs`, `role.rs`, `permission.rs`, `resource.rs` — tenant isolation + hierarchy
- `cleanup.rs`, `handlers/gdpr.rs`, `axiam-federation/saml.rs`, `totp.rs`, `core/repository.rs`, `api-rest/error.rs`, `axiam-pki`, `amqp/*`, `schema.rs` — correctness + hardening
- Frontend High: `PgpKeysPage`, `ConfirmDialog`, `AuditLogsPage`, `RoleDetailPage`/`GroupDetailPage`, `Topbar`, `ci.yml`, `OrganizationDetailPage`, `TenantsPage`

---

### Phase 11: Medium Remediation (Wave 3)

**Goal**: Consolidate repo/DTO patterns, add transport limits, and harden auth/infra surfaces (CQ-B10..B26/B39/B41/B43, CQ-F09..F19/F29..F31, SEC-016/019/020/022..026/028/031/032/046..055)
**Depends on**: Phase 10 (green-build gate)
**Requirements**: REQ-15
**Success Criteria** (what must be TRUE):

  1. Shared repo helpers + request DTOs; index/duplicate violations map to 409; OAuth2/gRPC error mapping + message-size/timeout/concurrency/TLS limits correct
  2. Webhook SSRF re-resolves and pins IP at delivery; rate limits on `/auth/mfa/*` + `/oauth2/introspect|revoke`; AMQP authz/mail messages authenticated/scoped; mTLS verifies chain to tenant/org CA; S256 PKCE enforced
  3. Auth hardening: dummy-Argon2 on user-not-found, atomic failed-login increment, reset-to-current blocked, CSRF on `/api/v1` CRUD, permission enforcement keyed off `ROUTE_PERMISSION_MAP`, bootstrap transactional + gated, self-update strips `status` + gates email change, logout revokes caller's own session
  4. k8s/nginx hardened: `AXIAM__` env keys + secrets, receiver-side NetworkPolicies + PSA restricted, `/oauth2/*` + `/.well-known` proxy locations, backend ports unpublished, prod compose default creds removed
  5. Frontend medium items: toast + `getApiErrorMessage` on all mutations, form validation, resource parent picker excludes descendants, federation edit locks type, pagination `placeholderData`, shared components/hooks, route guards + friendly 403, login handles `mfa_setup_required`/`mfa_required`

**Plans**: 5 plans

Plans:
**Wave 1**

- [x] 11-01-PLAN.md — Shared repo helpers + AlreadyExists→409 + edge indexes + email_config UPSERT + GDPR handler cleanup + request DTOs (CQ-B10/B11/B12/B17/B25/B26/B39/B41)
- [x] 11-04-PLAN.md — k8s AXIAM__ env keys + PSA restricted + receiver NetworkPolicies + nginx/ingress oauth2/.well-known proxy + prod compose creds (SEC-016/023/052/053)
- [x] 11-05-PLAN.md — Frontend medium: toast/getApiErrorMessage, validation, resource picker, federation edit lock, pagination, shared components/hooks/types, route guards+403, login MFA branches, slug restore (CQ-F09..F18/F29/F30/F31)

**Wave 2** *(after 11-01)*

- [x] 11-02-PLAN.md — Webhook SSRF+secret encrypt, mTLS chain, CertService dedup, gRPC/OAuth2 limits, MFA/oauth2 rate limits, XFF hop, Ed25519 parse-once, AMQP HMAC, JWKS cap (SEC-019/020/022/024/025/031/048/054/055, CQ-B14/B15/B18/B19/B20/B44)

**Wave 3** *(after 11-02 — shares server.rs)*

- [x] 11-03-PLAN.md — Dummy-Argon2, atomic failed-login, reset-to-current block, CSRF on /api/v1, permission map + register gating, transactional bootstrap, self-update strip, logout ownership (SEC-026/028/032/046/047/049/050/051, CQ-B12)

> Deferred to Phase 12 (surfaced during planning, developer-confirmed): CQ-B13 (AuthZ N+1 batching), CQ-B16 (org/tenant delete cascade), CQ-B23 OIDC discovery-cache portion (JWKS body cap done here), CQ-B24 broad pki/grpc test backfill (mtls_chain done here), CQ-F19 (verify-email StrictMode single-fire — folds into Phase 9 SEC-044). CQ-B43 AppState refactor deferred to Phase 12 per research.

### Scope

- Backend Medium (CQ-B10..B26/B39/B41/B43): shared repo helpers, DTOs, OAuth2/gRPC limits, JSON body limits, webhook AMQP, federation discovery cache, tests, `load_key_from_env`/`AppState` extraction
- Security Medium (SEC-016..055): nginx/k8s hardening, webhook SSRF, rate limits, AMQP auth, mTLS chain, S256 PKCE, dummy-Argon2, CSRF scope, permission middleware, bootstrap, self-update, logout, JWKS caps, compose creds
- Frontend Medium (CQ-F09..F19/F29..F31): toast/error handling, validation, resource picker, federation edit, pagination, shared components, route guards, login MFA states

---

### Phase 12: Low / Trivial Remediation (Wave 4)

**Goal**: Close remaining cleanup, dead-code, dependency, i18n, and minor security-polish findings, then run whole-effort verification (CQ-B27..B36/B42, CQ-F20..F35, SEC-036/037/040/041/043/057)
**Depends on**: Phase 11 (green-build gate)
**Requirements**: REQ-16
**Success Criteria** (what must be TRUE):

  1. Backend cleanup: shared `client_ip`/`user_agent` helper, NotificationDispatcher wired or removed, logged error handling (no silent `let _ =`/`.ok()`), typed errors, `cargo machete` dep pruning + `rand` consolidation, HIBP on sync change-password, audit-drop metric, seeder version/hash skip
  2. SEC-040 deny-overrides cascade implemented or CLAUDE.md wording corrected; encrypted blobs no longer `Debug`-derived/hydrated on list paths; GitHub Actions pinned by commit SHA
  3. Frontend trivial items: dead `Placeholder.tsx` removed, unused radix deps removed, password-policy checker on admin-create+bootstrap, safe DataTable row key, i18n / no hardcoded `en-US`, `CSS.escape` in ResourceTree, `_retry` guard + escaped cookie regex, bootstrap 404 handling, StrictMode double-fetch fixed
  4. Secrets cleared from React state on modal close; reset/verify tokens stripped from URL via `history.replaceState`; no full Axios error/email logging on ForgotPasswordPage
  5. Final whole-effort verification green: `cargo build/clippy -D warnings/test --workspace`, `cargo audit`/`cargo-deny`, `npm audit`, frontend `lint && tsc -b && vitest`, Playwright e2e gating in CI; manual smoke (login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds rejected)

**Plans**: 5 plans

Plans:
**Wave 1**

- [x] 12-01-PLAN.md — Backend cleanup: shared client_ip/user_agent, NotificationDispatcher, logged errors, typed errors, dep pruning, HIBP on change-password, audit-drop metric, seeder hash-skip (CQ-B28/29/31/33/34/35/36/42)
- [x] 12-02-PLAN.md — Backend security polish: mfa_secret Debug-redact + list projection, RBAC additive-only doc fix, GitHub Actions SHA-pinning (SEC-043/040/057)
- [x] 12-03-PLAN.md — Frontend trivial: dead Placeholder.tsx, radix dep prune, password-policy checker, DataTable key, i18n, CSS.escape, _retry guard, bootstrap 404, StrictMode (CQ-F20..F35)
- [x] 12-04-PLAN.md — Frontend security: clear revealed secrets on modal close, strip URL tokens, redact ForgotPassword log (SEC-036/037/041)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 12-05-PLAN.md — Final whole-effort verification gate: workspace build/clippy/test + audit/deny/npm-audit + frontend + Playwright e2e (CI) + manual smoke

### Scope

- Backend Low (CQ-B27..B36/B42, SEC-040/043/057): service composition, shared helpers, dead-code removal, typed errors, dep pruning, HIBP, metrics, seeder, deny-overrides, Debug-derive removal, Actions SHA-pinning
- Frontend Low (CQ-F20..F35, SEC-036/037/041): dead-code/dep removal, password-policy checker, DataTable key, i18n, `CSS.escape`, refresh `_retry` guard, bootstrap 404, StrictMode fix, secret clearing, URL token stripping, log redaction
- Final whole-effort verification + manual smoke

---

### Phase 13: SurrealDB Connection Resilience

**Goal**: Eliminate the silent stale-connection failure mode where the server's SurrealDB WebSocket connection loses its `use_ns`/`use_db` selection after an idle reconnect and then queries the empty default namespace — surfacing as confusing "not found" on records that exist. Also repair the documented first-run seed path so local bootstrap works end-to-end.
**Depends on**: Phase 12 (found during the Phase-12 manual smoke)
**Requirements**: REQ-17
**Success Criteria** (what must be TRUE):

  1. After a forced/simulated WebSocket reconnect, the connection still operates against `ns=axiam`/`db=main` (no silent fallback to the default `main`/`main` namespace); a regression test reproduces the reconnect and asserts post-reconnect reads succeed.
  2. `DbManager` re-establishes ns/db selection on reconnect (re-select guard, reconnect hook, or health-check that re-issues `USE NS … DB …`), and `health_check` verifies the active namespace/database rather than just liveness.
  3. `scripts/e2e-bootstrap.sh` seeds into the same database the server reads (correct the hardcoded `surreal-db: axiam` vs server `db=main` mismatch), so the documented first-run flow produces a working admin end-to-end; tenant CREATE no longer sets the removed `is_active` field.
  4. A repeatable local first-run path exists (e.g. `just bootstrap-local`) that seeds org+tenant+admin against the `run-local` server.
  5. The deferred Phase-12 manual smoke (`12-HUMAN-UAT.md`, 11 items) is unblocked and can be executed.

**Plans**: 2 plans (Wave 1, parallel — no file overlap)

- [x] 13-01-PLAN.md — DbManager reconnect resilience: ns/db keepalive guard + asserting health_check + regression test
- [x] 13-02-PLAN.md — First-run seed repair: e2e-bootstrap.sh db-name/is_active fix + `just bootstrap-local`

### Scope

- DB connection resilience in `crates/axiam-db` (`connection.rs` `DbManager`): reconnect-safe ns/db selection + health verification
- Regression test reproducing the idle-reconnect → wrong-namespace failure
- First-run seed repair: `scripts/e2e-bootstrap.sh` db-name + schema drift; optional `just bootstrap-local` helper
- Unblock and (optionally) execute the deferred Phase-12 smoke (`12-HUMAN-UAT.md`)

---

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12
Note: Phases 4 and 6 can run in parallel with Phase 3 and Phase 5 respectively (see dependency map).
Audit-remediation tranche (Phases 8–12) is strictly sequential with a green-build gate between waves.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Cookie-Based Authentication | 3/3 | Complete   | 2026-04-04 |
| 2. Security Headers & Rate Limiting | 5/5 | Complete   | 2026-05-29 |
| 3. RBAC Enforcement | 5/5 | Complete   | 2026-05-29 |
| 4. Federation Verification & Session Security | 6/6 | Complete   | 2026-05-29 |
| 5. Email Delivery & GDPR Compliance | 5/5 | Complete   | 2026-06-02 |
| 6. CI/CD & Infrastructure Hardening | 5/5 | Complete   | 2026-06-07 |
| 7. Compliance Verification & Test Closure | 5/5 | Complete   | 2026-06-07 |
| 8. Build Unblock (Wave 0) | 1/1 | Complete   | 2026-06-10 |
| 9. Critical Remediation (Wave 1) | 5/5 | Complete   | 2026-06-12 |
| 10. High Remediation (Wave 2) | 6/6 | Complete    | 2026-06-13 |
| 11. Medium Remediation (Wave 3) | 5/5 | Complete    | 2026-06-13 |
| 12. Low / Trivial Remediation (Wave 4) | 5/5 | Complete   | 2026-06-19 |
| 13. SurrealDB Connection Resilience | 2/2 | Complete   | 2026-06-19 |
| 14. Frontend List-Contract Alignment | 1/1 | Complete   | 2026-06-19 |

---

## Coverage Matrix

| Requirement | Phase | Description |
|-------------|-------|-------------|
| REQ-1 | Phase 1 | Cookie-Based Authentication |
| REQ-2 | Phase 2 | Security Headers |
| REQ-3 | Phase 2 | Rate Limiting & Brute-Force Protection |
| REQ-4 | Phase 3 | RBAC Enforcement |
| REQ-5 | Phase 4 | Federation Token Verification |
| REQ-6 | Phase 5 | Email Delivery |
| REQ-7 | Phase 4 | Session Security |
| REQ-8 | Phase 5 | GDPR Compliance |
| REQ-9 | Phase 6 | CI/CD Security Hardening |
| REQ-10 | Phase 6 | Infrastructure Hardening |
| REQ-11 | Phase 7 | Testing Gaps |
| REQ-12 | Phase 8 | Build Integrity (Wave 0) |
| REQ-13 | Phase 9 | Critical Security Remediation (Wave 1) |
| REQ-14 | Phase 10 | High Security Remediation (Wave 2) |
| REQ-15 | Phase 11 | Medium Security Remediation (Wave 3) |
| REQ-16 | Phase 12 | Low / Trivial Remediation (Wave 4) |
| REQ-17 | Phase 13 | SurrealDB Connection Resilience (post-remediation bug fix) |
| REQ-18 | Phase 14 | Frontend List-Contract Alignment (post-remediation bug fix) |

**Coverage: 18/18 requirements mapped (100%)**

---

## Dependency Graph

```
Phase 1 (Cookie Auth) -----> Phase 2 (Headers/Rate Limit) -----> Phase 3 (RBAC) -----> Phase 5 (Email/GDPR)
      |                                                                                        |
      +-----> Phase 4 (Federation/Session)                                                     |
      |                                                                                        |
      +-----> Phase 6 (CI/Infra) [can parallel with 3-5]                                      |
                                                                                               v
                                                                                  Phase 7 (Compliance/Tests)
                                                                                  [depends on ALL phases]
                                                                                               |
                                                                                               v
              Audit-remediation tranche (sequential, green-build gate between waves):
              Phase 8 (Build Unblock / W0) -> Phase 9 (Critical / W1) -> Phase 10 (High / W2)
                  -> Phase 11 (Medium / W3) -> Phase 12 (Low / W4)
```

---

## Milestone v1.1 — Client SDKs

> Milestone: v1.1
> Phase range: 15–22 | Granularity: standard
> Created: 2026-06-28

### Overview (v1.1)

This milestone ships 7 language-native client SDKs (Rust, TypeScript, Python, Java, C#, PHP, Go) wrapping the frozen v1.0 REST / gRPC / AMQP APIs. SDKs are stateful auth clients — not thin codegen wrappers — managing token lifecycles, tenant context, concurrency-safe refresh guards, and framework middleware per language. Phase 15 (foundation) is a hard prerequisite for all per-language work; Phase 16 (Rust reference implementation) must precede Phases 17–22, which can then parallelize.

### Phases (v1.1)

- [x] **Phase 15: SDK Foundation** - Export OpenAPI spec, establish buf proto codegen pipeline, add REST authz-check endpoint, author cross-language contract, scaffold `sdks/` monorepo with per-SDK path-filtered CI (completed 2026-06-30)
- [x] **Phase 16: Rust SDK** - Reference implementation (REST + gRPC + AMQP); establishes `Sensitive<T>` and gRPC-channel patterns reused by all later SDKs (completed 2026-07-01)
- [x] **Phase 17: TypeScript SDK** - Browser (REST-only) and Node (REST + gRPC + AMQP) personas; browser authz via FND-04 REST endpoint; Express + Fastify middleware; npm publish (6/6 plans executed 2026-07-01; verification found 4 critical security gaps CR-01..CR-04 — gap-closure plan 17-07 executed 2026-07-01 closing CR-02/CR-03; 17-08 pending for CR-01/CR-04) (completed 2026-07-01)
- [x] **Phase 18: Go SDK** - Full REST + gRPC + AMQP; idiomatic `net/http` middleware; Go module publish (completed 2026-07-01)
- [x] **Phase 19: Python SDK** - Sync + async interfaces via httpx; FastAPI dependency + Django middleware; PyPI publish (completed 2026-07-01)
- [x] **Phase 20: Java SDK** - OkHttp + grpc-netty; Spring Security filter; Maven Central publish with GPG signing (completed 2026-07-02)
- [x] **Phase 21: C# SDK** - HttpClient + Grpc.Net.Client; Grpc.Tools MSBuild codegen; ASP.NET Core middleware; NuGet publish (completed 2026-07-02)
- [x] **Phase 22: PHP SDK** - REST-first; gRPC guarded by runtime `extension_loaded('grpc')`; Laravel + Symfony middleware; Packagist publish (completed 2026-07-02)

### Phase Details (v1.1)

### Phase 15: SDK Foundation

**Goal**: All shared SDK artifacts exist and CI gates prevent spec drift or breaking proto changes before any per-language SDK begins
**Depends on**: Phase 14 (v1.0 complete; v1.1 opens)
**Requirements**: FND-01, FND-02, FND-03, FND-04, FND-05
**Success Criteria** (what must be TRUE):

  1. `axiam-server --dump-openapi` exits without starting SurrealDB or AMQP; `sdks/openapi.json` is committed; a CI drift gate fails the build if the spec diverges from code on a release tag.
  2. `buf lint` and `buf breaking` pass in CI on every `proto/**` change; proto stubs for all gRPC-capable SDKs generate reproducibly from a clean checkout via a single documented command.
  3. `POST /api/v1/authz/check` returns `{ allowed, reason? }` using the same `AuthorizationEngine` as gRPC; the route↔OpenAPI parity test includes the new endpoint and it is rate-limited.
  4. `sdks/CONTRACT.md` documents method naming map, error taxonomy, CSRF/cookie-jar behavior, TLS policy, `Sensitive<T>` token-redaction requirement, AMQP HMAC contract, and middleware interface — and is referenced in every SDK README stub.
  5. `sdks/{rust,typescript,python,java,csharp,php,go}/` directories exist with Apache-2.0 LICENSE and per-SDK path-filtered CI workflows that trigger only on per-SDK path changes.

**Plans**: 6/6 plans complete

  - [x] 15-01-PLAN.md — FND-04 REST authz-check endpoint (single + batch, authz:check_as, dedicated rate-limit tier)
  - [x] 15-02-PLAN.md — FND-01 --dump-openapi flag + committed sdks/openapi.json + drift gate
  - [x] 15-03-PLAN.md — FND-03 sdks/CONTRACT.md (§1-§10) + D-13 ROADMAP Go fixup
  - [x] 15-04-PLAN.md — FND-02 buf codegen pipeline (buf.yaml/buf.gen.yaml + lint/breaking CI)
  - [x] 15-05-PLAN.md — FND-05 sdks/ monorepo scaffold (7 languages) + per-SDK path-filtered CI
  - [x] 15-06-PLAN.md — FND-05 registry/org name availability verification (human-verify)

---

### Phase 16: Rust SDK

**Goal**: A Rust developer can `cargo add axiam-sdk`, authenticate against AXIAM with full REST + gRPC + AMQP coverage, and token safety + concurrency correctness are proven by test
**Depends on**: Phase 15
**Requirements**: RUST-01
**Success Criteria** (what must be TRUE):

  1. A client constructed with a non-optional `tenant_slug` calls `login(email, password)` and receives a typed `LoginResult { mfa_required }`; if MFA required, `verify_mfa(code)` completes the two-phase flow.
  2. A concurrency test fires 5 simultaneous requests against an expired token and asserts exactly 1 refresh call was made (single-flight `tokio::sync::Mutex` guard).
  3. `grep -r 'eyJ' target/debug/` returns empty in CI — `Sensitive<T>` prevents token values from appearing in any debug output or test logs.
  4. gRPC `CheckAccess` and `BatchCheckAccess` succeed via `tonic 0.14`; AMQP consumer verifies HMAC-SHA256 before processing and nacks without requeue on signature failure.
  5. `cargo publish --dry-run` succeeds; crates.io publish CI pipeline runs on release tag.

**Plans**: 6/6 plans complete

Plans:
**Wave 1**

- [x] 16-01-PLAN.md — Foundation: crate manifest + Cargo features (rest/grpc/amqp/observability) + MSRV 1.88 + `Sensitive<T>` + `AxiamError` + build.rs gRPC codegen + redaction test

**Wave 2** *(parallel; depend on 16-01)*

- [x] 16-02-PLAN.md — REST core: AxiamClient builder + cookie jar + TokenManager + single-flight refresh + local JWKS verify + login/verify_mfa/refresh/logout + check_access/can/batch_check (SC#1, SC#2)
- [x] 16-04-PLAN.md — AMQP: byte-identical HMAC sign/verify + server-identical message DTOs + closure-handler consumer (verify-before-handler, nack-no-requeue) (SC#4 AMQP half)

**Wave 3** *(parallel; depend on 16-01 + 16-02)*

- [x] 16-03-PLAN.md — gRPC: shared lazy tonic Channel + sync-safe auth/tenant interceptor + check_access/batch_check + UNAUTHENTICATED single-flight retry + in-process test server (SC#4 gRPC half)
- [x] 16-05-PLAN.md — Actix middleware: `AxiamUser` FromRequest extractor (cookie/Bearer → local JWKS verify → identity inject → 401/403), feature-gated

**Wave 4** *(depends on all transports)*

- [x] 16-06-PLAN.md — Examples (login+MFA / REST / gRPC / AMQP / Actix) + README conformance + crates.io publish CI (leak gate, TLS-lint gate, dry-run gate, tag-triggered publish + buf bundle) (SC#3, SC#5)

---

### Phase 17: TypeScript SDK

**Goal**: A TypeScript developer can use the SDK in a browser (REST-only) or Node.js (REST + gRPC + AMQP) context with correct per-persona behavior and framework middleware for Express and Fastify
**Depends on**: Phase 15, Phase 16
**Requirements**: TS-01
**Success Criteria** (what must be TRUE):

  1. A browser bundler (Vite/webpack) importing `axiam-sdk/rest` tree-shakes all Node-only exports — zero Node-only modules (`@grpc/grpc-js`, `amqplib`) appear in the browser bundle.
  2. In browser persona, `client.can(action, resource)` calls `POST /api/v1/authz/check` (FND-04 REST endpoint); in Node persona it calls gRPC `CheckAccess` — each persona uses only its viable transport.
  3. 5 parallel fetch calls on an expired token trigger exactly 1 refresh (promise-dedup guard); the CSRF token is auto-forwarded on all state-changing requests via the axios interceptor.
  4. Express and Fastify middleware examples compile under TypeScript strict mode and protect a sample route; the package publishes as `axiam-sdk` on npm.
  5. `npm publish --dry-run` succeeds; npm publish CI pipeline runs on release tag.

**Plans**: 8/8 plans complete

Plans:
**Wave 1**

- [x] 17-01-PLAN.md — Foundation: tsup dual ESM+CJS multi-entry + gitignored buf codegen + dependency-free `core` (error taxonomy, status mapper, Sensitive<T>, CSRF, single-flight) + AxiamClient rename (D-01..D-04/D-14/D-16/D-17/D-19/D-20/D-26/CF-03)

**Wave 2** *(parallel; depend on 17-01)*

- [x] 17-02-PLAN.md — REST/browser persona: AxiamClient + CSRF interceptor + reactive single-flight refresh + login/MFA discriminated union + can/checkAccess/batchCheck over FND-04 REST + CF-01 retry + SharedSession (D-05..D-08/D-13/D-18/D-25, SC#2 browser, SC#3)
- [x] 17-04-PLAN.md — AMQP: byte-identical HMAC sign/verify + server-identical DTOs + verify-before-handler closure consumer (nack-no-requeue + security event) (D-12/§8)

**Wave 3** *(depends on 17-01 + 17-02)*

- [x] 17-03-PLAN.md — Node persona: tough-cookie jar + jar-read tokens (Sensitive) + local EdDSA JWKS via jose + reused gRPC channel + sync interceptor + UNAUTHENTICATED call-wrapper refresh; checkAccess/batchCheck over gRPC (D-09/D-10/D-11/D-13/D-15/D-26, SC#2 Node)

**Wave 4** *(depends on 17-02 + 17-03)*

- [x] 17-05-PLAN.md — Express + Fastify middleware (shared local-JWKS verify core, inject req.axiamUser) + five strict-compiling examples (D-27/§10, SC#4)

**Wave 5** *(depends on all transports + middleware)*

- [x] 17-06-PLAN.md — SC#1 bundle-and-grep gate + leak/TLS-lint gates + TS CI workflow (dry-run PR gate + tag-triggered provenance publish) + README + scoped CONTRACT.md §3/naming update (D-02/D-20/D-21/D-28/D-14, SC#1, SC#5)

**Wave 6** *(gap closure — CR-01..CR-04 from 17-VERIFICATION.md; sequential: 17-08 depends on 17-07 via shared session files)*

- [x] 17-07-PLAN.md — Gap closure: per-session single-flight refresh guard (CR-02) + middleware tenant_id enforcement (CR-03) + regression tests
- [x] 17-08-PLAN.md — Gap closure: Node persona CSRF token population (CR-01) + NetworkError.cause Set-Cookie redaction (CR-04) + regression tests

**UI hint**: yes

---

### Phase 18: Go SDK

**Goal**: A Go developer can import the SDK and authenticate, authorize, and consume AMQP events using idiomatic Go patterns, with no TLS bypass paths possible in the SDK
**Depends on**: Phase 15, Phase 16
**Requirements**: GO-01
**Success Criteria** (what must be TRUE):

  1. `go get github.com/ilpanich/axiam/sdks/go` installs; a `net/http` middleware example compiles and protects a sample route; `tenantSlug` is a required constructor parameter enforced at call time.
  2. `sync.Mutex` single-flight refresh: 5 concurrent goroutines firing against an expired token trigger exactly 1 refresh call (verified by table-driven test).
  3. CI lint gate: `grep -rn 'InsecureSkipVerify' sdks/go/` returns empty — no TLS bypass paths exist anywhere in the SDK source tree.
  4. AMQP consumer verifies HMAC-SHA256 of each message body; nacks without requeue on signature mismatch.
  5. `go test ./...` passes; Go module publish pipeline tags `sdks/go/vX.Y.Z` on release.

**Plans**: 6/6 plans complete

Plans:
**Wave 1**

- [x] 18-01-PLAN.md — Foundation: buf out-path fix + committed internal/gen stubs + go.sum deps + Sensitive type + error taxonomy (redact-before-wrap) + GO-01 doc reconciliation

**Wave 2** *(parallel; depend on 18-01)*

- [x] 18-02-PLAN.md — REST core: NewClient functional options + cookie jar/TLS override safety + sync.Mutex single-flight + Login/VerifyMfa/Refresh/Logout (LoginResult, org_id) + CheckAccess/Can/BatchCheck (SC#1, SC#2)
- [x] 18-03-PLAN.md — AMQP: byte-identical HMAC verify + closure-handler Consume (verify-before-handler, nack-no-requeue, ErrDrop) (SC#4)
- [x] 18-04-PLAN.md — Local JWKS verifier (jwx/v3, EdDSA allowlist, org-wide /oauth2/jwks) + gRPC client (grpc.NewClient, strict TLS, sync-safe interceptor) (SC#3 gRPC half)

**Wave 3** *(depends on 18-01 + 18-04)*

- [x] 18-05-PLAN.md — net/http middleware: local verify + cross-tenant claim check + context identity injection + 401/403 JSON

**Wave 4** *(depends on all transports + middleware)*

- [x] 18-06-PLAN.md — Five per-capability examples + README conformance + sdk-ci-go.yml (test/vet + TLS-bypass grep gate + buf drift-check + tag-triggered publish) (SC#1, SC#3, SC#5)

---

### Phase 19: Python SDK

**Goal**: A Python developer using sync or async patterns can authenticate and make authorized requests, with FastAPI dependency injection and Django middleware as first-class integrations
**Depends on**: Phase 15, Phase 16
**Requirements**: PY-01
**Success Criteria** (what must be TRUE):

  1. `pip install axiam-sdk` installs; both `client.login(email, password)` (sync via httpx) and `await client.async_login(email, password)` (async) return a typed `LoginResult` with a `mfa_required` field.
  2. `asyncio.Lock` single-flight refresh: 5 concurrent asyncio tasks on an expired token trigger exactly 1 refresh call (verified by pytest-asyncio test).
  3. `httpx` client is constructed with `verify=True` (hardcoded); a CI grep gate confirms `verify=False` does not appear anywhere in SDK source or examples.
  4. A FastAPI dependency-injection helper and a Django middleware class are both provided and demonstrated in runnable example scripts.
  5. `python -m build && twine check dist/*` succeeds; PyPI publish CI pipeline runs on release tag.

**Plans**: 2/7 plans executed

Plans:
**Wave 1**

- [x] 19-01-PLAN.md — Foundation: pyproject fix (build_meta/>=3.10/src-layout/py.typed/package-data) + committed gRPC stubs (grpc_tools.protoc + import fixup) + conftest + **AMQP HMAC cross-language fixture test** (Assumption A2 / Pitfall 2)

**Wave 2** *(depends on 19-01)*

- [x] 19-02-PLAN.md — Core primitives: error taxonomy + redact-before-wrap (D-08/CR-04), Pydantic models + SecretStr (D-06/D-07/D-21), local JWKS EdDSA-only verifier (D-16), dual-lock single-flight refresh guard (SC#2)

**Wave 3** *(parallel; depend on 19-01 + 19-02; zero file overlap)*

- [x] 19-03-PLAN.md — REST core: shared _Session (cookie jar/CSRF/lazy sync+async httpx) + AxiamClient sync+async login/verify_mfa/refresh/logout + check_access/can/batch (SC#1, org_id, path-scoped refresh)
- [x] 19-04-PLAN.md — gRPC: sync (grpcio) + async (grpc.aio) AuthzGrpcClient + non-blocking interceptor + strict TLS + UNAUTHENTICATED retry-once (D-12)
- [x] 19-05-PLAN.md — AMQP: async closure-handler consumer, HMAC verify-before-handler + full §8 ack/nack matrix (D-02)

**Wave 4** *(depends on 19-02)*

- [x] 19-06-PLAN.md — FastAPI dependency + Django middleware (local JWKS verify + cross-tenant claim check + identity injection), import-safe optional extras (D-09/D-10, SC#4)

**Wave 5** *(depends on all transports + integrations)*

- [x] 19-07-PLAN.md — Six examples (login+MFA/REST/gRPC/AMQP/FastAPI/Django) + README §1–§10 conformance + Python SDK CI (matrix 3.10–3.13, verify=False gate, gRPC drift-check, mypy/ruff, build/twine, tag-triggered PyPI Trusted Publishing) (SC#3/SC#5/D-13/D-18/D-20)

---

### Phase 20: Java SDK

**Goal**: A Java developer using Spring Security can authenticate and authorize via the SDK with the artifact available on Maven Central, GPG-signed
**Depends on**: Phase 15, Phase 16
**Requirements**: JAVA-01
**Success Criteria** (what must be TRUE):

  1. `io.axiam:axiam-sdk` added to a Maven POM; `tenantId` is a required builder parameter (compiler-enforced via no-arg builder absence); `login(email, password)` returns a typed `LoginResult`.
  2. `ReentrantLock` single-flight refresh: 5 concurrent threads on an expired token trigger exactly 1 refresh call (verified by JUnit 5 test).
  3. A Spring Security `Filter` using the SDK protects a sample endpoint and compiles against Spring Boot 3.x; the example includes a complete working application context.
  4. `OkHttpClient` uses `CookieManager` for cookie persistence; no `hostnameVerifier` or `sslSocketFactory` bypass is present anywhere in SDK source.
  5. Maven Central publish pipeline with GPG signing is documented and operational; `mvn verify` passes including signing.

**Plans**: 9/9 plans complete

Plans:
**Wave 1**

- [x] 20-01-PLAN.md — Maven scaffold: pom Java 11→21 + deps + plugin chain, protobuf-maven-plugin codegen, buf.gen.yaml demote, TLS grep gate, JAVA-01↔BOM reconcile

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 20-02-PLAN.md — AMQP HMAC foundation: Hmac.verify (wire-order canonicalization) + ErrDrop + real cross-language fixture + HmacVerifyTest
- [x] 20-03-PLAN.md — Token safety & error taxonomy: Sensitive (D-17) + AuthError/AuthzError/NetworkError + ErrorMapper redact-before-wrap (D-18/CR-04) + records
- [x] 20-04-PLAN.md — Verification & concurrency core: RefreshGuard single-flight (SC#2) + JwksVerifier EdDSA-pinned + cross-tenant helper (D-19)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 20-05-PLAN.md — REST core: SessionState + interceptors + AxiamClient builder (SC#1, D-27) + auth (login/verifyMfa/refresh/logout) + authz (checkAccess/can/batchCheck)
- [x] 20-06-PLAN.md — Spring Security: AxiamAuthenticationFilter (cross-tenant check) + @AutoConfiguration (SC#3 core)
- [x] 20-07-PLAN.md — AMQP consumer: verify-before-handler + §8 ack/nack matrix + built-in recovery (D-13)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 20-08-PLAN.md — gRPC transport: GrpcAuthzClient (shared guard, strict-TLS channel, deadline) + AuthClientInterceptor

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 20-09-PLAN.md — Deliverables: examples + complete Spring Boot app (SC#3) + README + BOM + GPG-signed Central Portal CI/publish (SC#5)

**Waves**: W1: 20-01 · W2: 20-02, 20-03, 20-04 · W3: 20-05, 20-06, 20-07 · W4: 20-08 · W5: 20-09

---

### Phase 21: C# SDK

**Goal**: An ASP.NET Core developer can use the SDK for auth and authorization via NuGet, with `Grpc.Tools` MSBuild providing gRPC codegen at build time (C# exception to the buf pipeline)
**Depends on**: Phase 15, Phase 16
**Requirements**: CS-01
**Success Criteria** (what must be TRUE):

  1. `dotnet add package Axiam.Sdk` installs; `await client.LoginAsync(email, password)` returns a typed `LoginResult`; tenant context is a required constructor parameter with no default.
  2. `SemaphoreSlim(1,1)` single-flight refresh: 5 concurrent tasks on an expired token trigger exactly 1 refresh call (verified by xUnit test).
  3. `Axiam.Sdk.AspNetCore` sub-package provides middleware that protects a sample ASP.NET Core 8+ endpoint and is demonstrated in a runnable example.
  4. `Grpc.Tools` MSBuild integration generates gRPC stubs at build time (documented as the C# exception to the repo-wide buf pipeline); no `ServerCertificateCustomValidationCallback` bypass present in SDK source.
  5. `dotnet pack` succeeds and produces a valid `.nupkg`; NuGet publish pipeline with credential setup is documented and operational.

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 21-01-PLAN.md — Foundation: two-package solution (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`) + `Grpc.Tools` codegen + `Sensitive<T>`/error taxonomy (redact-before-wrap) + xUnit scaffold + HMAC/JWKS fixtures (D-01/D-03/D-05/D-12, SC#4 codegen, CR-04)

**Wave 2** *(parallel; depend on 21-01)*

- [x] 21-02-PLAN.md — AMQP: wire-order HMAC verify + `RabbitMQ.Client` 7.2 `AsyncEventingBasicConsumer` verify-before-handler + ack/nack matrix (D-11, §8)
- [x] 21-03-PLAN.md — Auth utilities: `SemaphoreSlim(1,1)` single-flight `RefreshGuard` (SC#2) + BouncyCastle Ed25519 `JwksVerifier` (alg-pin + cross-tenant check) (D-02/D-10)

**Wave 3** *(depends on 21-01 + 21-03)*

- [x] 21-04-PLAN.md — REST transport + `AxiamClient` facade: cookie jar + client-override safety + no-TLS-bypass + tenant-required ctor + async auth flow + FND-04 authz (SC#1, D-09/D-10, §3/§4/§5/§6)

**Wave 4** *(parallel; depend on 21-04)*

- [x] 21-05-PLAN.md — gRPC: long-lived channel + sync-safe interceptor sharing the single guard + `CheckAccess`/`BatchCheckAccess` (D-10, §6)
- [x] 21-06-PLAN.md — `Axiam.Sdk.AspNetCore`: middleware → `ClaimsPrincipal` + DI extensions + policy-based authz + WebApplicationFactory test (SC#3, D-06/D-07/D-08, §10)

**Wave 5** *(depends on 21-02 + 21-05 + 21-06)*

- [x] 21-07-PLAN.md — Examples (AspNetCore sample + quickstart) + SourceLink/snupkg packaging + TLS-bypass gate + CI build/test/pack + tag-triggered NuGet publish (SC#3/SC#4/SC#5, D-04/D-05)

---

### Phase 22: PHP SDK

**Goal**: A PHP developer using Laravel or Symfony can authenticate via REST and AMQP, with gRPC available on long-running runtimes, and the package published to Packagist
**Depends on**: Phase 15, Phase 16
**Requirements**: PHP-01
**Success Criteria** (what must be TRUE):

  1. `composer require axiam/axiam-sdk` installs; `$client->login($email, $password)` returns a typed `LoginResult`; tenant slug is a required constructor parameter with no nullable default.
  2. Guzzle `HandlerStack` single-refresh middleware: concurrent Guzzle requests on an expired token trigger exactly 1 refresh call (verified by PHPUnit test).
  3. gRPC usage is guarded by `extension_loaded('grpc')` — when absent, the SDK operates in REST-only mode; the Swoole/RoadRunner long-running runtime requirement is documented prominently.
  4. Laravel and Symfony middleware helpers are provided as runnable examples; AMQP consumer verifies HMAC-SHA256 and calls `nack` (no requeue) on signature failure.
  5. `composer test` passes; Packagist automation (`axiam/axiam-sdk`) runs on release tag.

**Plans**: 9/9 plans complete

Plans:
**Wave 1**

- [x] 22-01-PLAN.md — Wave 1: scaffold + pinned deps + PHPUnit + Sensitive/error taxonomy (D-10/D-11, CR-04)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 22-02-PLAN.md — Wave 2: JWKS EdDSA verifier (alg-pin + tenant_id) + LoginResult DTO + crypto fixtures (D-08/D-09)
- [x] 22-03-PLAN.md — Wave 2: AMQP Hmac verify-before-handler + Consumer + CLI worker (D-04, SC#4-AMQP)
- [x] 22-04-PLAN.md — Wave 2: Session + shared-promise single-flight refresh middleware (D-06, SC#2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 22-05-PLAN.md — Wave 3: AuthzRestClient + gRPC guard/dispatcher + committed stubs + buf.gen.yaml (D-03, SC#3)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 22-06-PLAN.md — Wave 4: AxiamClient facade + auth flows (login/verifyMfa/refresh/logout) (SC#1, D-13)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 22-07-PLAN.md — Wave 5: Laravel bridge (ServiceProvider + Middleware + Gate) + example (D-01/D-02, SC#4)
- [x] 22-08-PLAN.md — Wave 5: Symfony bridge (Bundle + Subscriber + Voter) + example (D-01/D-02, SC#4)

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 22-09-PLAN.md — Wave 6: CI (test + TLS gate + subtree-split Packagist) + README (D-05/D-12, SC#5)

---

### Progress (v1.1)

**Execution Order:**
Phase 15 (SDK Foundation) is a hard prerequisite — no per-language SDK can begin without `sdks/openapi.json` and the buf codegen pipeline.
Phase 16 (Rust SDK) establishes the reference implementation patterns; Phases 17–22 can parallelize once 15 + 16 are complete.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 15. SDK Foundation | 6/6 | Complete    | 2026-06-30 |
| 16. Rust SDK | 6/6 | Complete   | 2026-07-01 |
| 17. TypeScript SDK | 8/8 | Complete    | 2026-07-01 |
| 18. Go SDK | 6/6 | Complete    | 2026-07-01 |
| 19. Python SDK | 7/7 | Complete   | 2026-07-01 |
| 20. Java SDK | 9/9 | Complete    | 2026-07-02 |
| 21. C# SDK | 7/7 | Complete   | 2026-07-02 |
| 22. PHP SDK | 9/9 | Complete    | 2026-07-02 |

---

### Coverage Matrix (v1.1)

| Requirement | Phase | Description |
|-------------|-------|-------------|
| FND-01 | Phase 15 | OpenAPI Spec Export (`--dump-openapi` flag + `sdks/openapi.json` + drift gate) |
| FND-02 | Phase 15 | Multi-Language Proto Codegen (buf pipeline + lint/breaking gate) |
| FND-03 | Phase 15 | Cross-Language SDK Contract Document (`sdks/CONTRACT.md`) |
| FND-04 | Phase 15 | REST Authorization-Check Endpoint (`POST /api/v1/authz/check`) |
| FND-05 | Phase 15 | SDK Monorepo Scaffold & per-SDK path-filtered CI |
| RUST-01 | Phase 16 | Rust SDK — REST + gRPC + AMQP (reference implementation) |
| TS-01 | Phase 17 | TypeScript SDK — browser (REST) + Node (REST + gRPC + AMQP) |
| GO-01 | Phase 18 | Go SDK — REST + gRPC + AMQP |
| PY-01 | Phase 19 | Python SDK — REST + gRPC + AMQP (sync + async) |
| JAVA-01 | Phase 20 | Java SDK — REST + gRPC + AMQP + Maven Central |
| CS-01 | Phase 21 | C# SDK — REST + gRPC + AMQP + NuGet |
| PHP-01 | Phase 22 | PHP SDK — REST + AMQP; gRPC long-running runtimes only |

**Coverage: 12/12 v1.1 requirements mapped (100%)**

---

### Dependency Graph (v1.1)

```
Phase 15: SDK Foundation (hard prerequisite)
    ├── FND-01: --dump-openapi -> sdks/openapi.json + CI drift gate
    ├── FND-02: buf codegen pipeline (proto stubs for Rust/TS/Go/Python/Java)
    ├── FND-03: sdks/CONTRACT.md (cross-language behavioral spec)
    ├── FND-04: POST /api/v1/authz/check (REST authz query endpoint)
    └── FND-05: sdks/ monorepo + per-SDK path-filtered CI
          |
          v
Phase 16: Rust SDK (reference implementation — validates full pattern)
          |
          +------+------+------+------+------+------+
          v      v      v      v      v      v      v
        Ph.17  Ph.18  Ph.19  Ph.20  Ph.21  Ph.22
        (TS)   (Go)   (Py)  (Java) (C#)   (PHP)
        [phases 17-22 can parallelize after 15+16 complete]
```

---

## Milestone v1.2 — MVP Release Hardening (final milestone)

> Milestone: v1.2
> Phase range: 23–30 | Granularity: standard
> Created: 2026-07-03
> Source: `claude_dev/roadmap.md` Phases 18–19 + `security-review-postremediation.md` + `code-review-postremediation.md`

### Overview (v1.2)

The final push to a production-credible MVP. This milestone remediates every open security regression,
correctness bug, performance gap, and compliance/documentation item from the two post-remediation reviews
(2026-07-01) plus the outstanding roadmap Phases 18–19 — with **no new domain features**. Phases are
priority-banded per Core Value: **security > correctness > performance > compliance > structural quality > docs.**
The critical/HIGH security regressions (SECFIX-*) land first (Phase 23), medium/low security hardening
follows (Phases 24–25), then correctness+resilience (Phase 26), performance (Phase 27), functional
completeness (Phase 28), structural-quality refactors *after* the security/correctness work so refactors
never churn unreviewed security code (Phase 29), and finally compliance + documentation which certify the
*finished, hardened* state (Phase 30). Every security phase's success criteria include the relevant
NEGATIVE test passing.

> Coverage note: the enumerated v1.2 REQ-ID set is **44** IDs (SECFIX 6 + SECHRD 12 + CORR 6 + PERF 5 +
> FUNC 5 + QUAL 7 + CMPL 2 + DOCS 1). The earlier "42" summary in REQUIREMENTS.md undercounted by 2;
> all 44 are mapped below (100%).

### Phases (v1.2)

- [x] **Phase 23: Security Regressions & HIGH Findings** - Close the critical/HIGH SEC regressions (gRPC service auth, live-grant tenant guard, webhook fail-closed encrypt-at-rest, SAML XSW binding, logout revocation, reset/resend tenant_id) — each proven by a negative test (completed 2026-07-03)
- [x] **Phase 24: Security Hardening I — Authentication & Access-Control Surfaces** - Harden the auth front door: TOTP atomic replay, XFF rate-limit keying, bootstrap atomicity+gate, public-path allowlist, reset/crypto side-channels (completed 2026-07-04)
- [x] **Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra** - Fail-closed trust boundaries: SSRF address pinning, mTLS CA status, GDPR erasure durability, federation nonce+secret handling, AMQP per-tenant signing, cluster egress/secret completeness (completed 2026-07-04)
- [x] **Phase 26: Correctness & Resilience** - gRPC governor throughput, SurrealDB token renewal, durable webhook delivery, Playwright-in-CI with body assertions, frontend tenant/MFA/residual flows (completed 2026-07-05)
- [x] **Phase 27: Performance & Load Hardening** - HIBP circuit breaker + hot-path pre-sizing, concurrent bounded BatchCheckAccess, JWKS single-flight across SDKs, SurrealDB reconnect backoff-with-jitter, load-test + profiling report (completed 2026-07-05)
- [x] **Phase 28: Functional Completeness** - Unauthenticated first-time federation login, session invalidation on reset, admin email-config API + templates, admin user/MFA endpoints + service-account token type, OpenAPI login schema (completed 2026-07-05)
- [x] **Phase 29: Structural Quality** - AppState extraction, generic paginate + shared repo helpers, error-taxonomy correctness, transactional multi-statement mutations, PKI/frontend dedup, dead-code cleanup — no behavior change (completed 2026-07-06)
- [ ] **Phase 30: Compliance & Documentation** - OWASP ASVS/ISO 27001/CyberSecurity Act audit checklist, GDPR export/deletion/consent completeness, consolidated REST/gRPC/AMQP + deployment + admin + PKI + SDK docs

> v1.2 roadmap created 2026-07-03. Phase numbering continues from Phase 22 (v1.1). Sequential execution with
> a green-build gate between phases; Phases 24 and 25 are parallel-capable once Phase 23 lands. `gsd-sdk
> phase.add` sentinel bug still present — author phase dirs `23`–`30` directly.

### Phase Details (v1.2)

### Phase 23: Security Regressions & HIGH Findings

**Goal**: Every critical/HIGH security regression surfaced by the two post-remediation reviews is closed and fail-closed, each proven by a negative test — no known exploitable defect remains in the gRPC, grant, webhook, SAML, logout, or reset control paths
**Depends on**: Phase 22 (v1.1 complete; v1.2 opens) — first phase of the milestone
**Requirements**: SECFIX-01, SECFIX-02, SECFIX-03, SECFIX-04, SECFIX-05, SECFIX-06
**Success Criteria** (what must be TRUE):

  1. A gRPC `GetUser`/`ValidateCredentials`/`IntrospectToken` call with no bearer token / mTLS identity is rejected, and a cross-tenant `GetUser` (tenant-A caller, tenant-B target) returns permission-denied (SECFIX-01)
  2. A caller holding `permissions:grant` in tenant A cannot attach tenant B's permission or scope to a tenant-A role via `POST /api/v1/roles/{id}/permissions` — the scoped `grant_to_role_with_scopes` path rejects it (SECFIX-02)
  3. Webhook registration fails closed when `AXIAM__PKI__ENCRYPTION_KEY` is unset (no all-zero key), and a stored webhook secret is ciphertext (≠ plaintext) that still decrypts correctly at delivery (SECFIX-03)
  4. A SAML response with a wrapped/duplicated assertion, a wrong `Destination`, or a missing `InResponseTo` on the authenticated ACS path is rejected (SECFIX-04)
  5. After `POST /api/v1/auth/logout` a request replaying the old cookies is unauthenticated (frontend logout returns no 400), and password-reset/resend requests carry `tenant_id`/`email`, succeed, and stay enumeration-safe with a constant response (SECFIX-05, SECFIX-06)

**Plans**: 6/6 plans complete

Plans:

- [x] 23-01-PLAN.md — SECFIX-01: gRPC UserService/TokenService auth + tenant cross-validation + shared always-on lockout helper
- [x] 23-02-PLAN.md — SECFIX-02: tenant + scope-ownership guard on the live grant_to_role_with_scopes path
- [x] 23-03-PLAN.md — SECFIX-03: webhook fail-closed encryption key + encrypt-at-rest on create/update
- [x] 23-04-PLAN.md — SECFIX-04: SAML XSW signature↔assertion binding (samael 0.0.21) + authenticated-path Destination/InResponseTo
- [x] 23-05-PLAN.md — SECFIX-05: logout revokes the caller's session from the JWT jti (no body)
- [x] 23-06-PLAN.md — SECFIX-06: reset/resend flows thread tenant_id/email, stay enumeration-safe

**UI hint**: yes

---

### Phase 24: Security Hardening I — Authentication & Access-Control Surfaces

**Goal**: The authentication and access-control front door resists replay, IP-spoofing, race, path-smuggling, and timing attacks — every fix fails closed and ships with a negative test
**Depends on**: Phase 23
**Requirements**: SECHRD-01, SECHRD-03, SECHRD-04, SECHRD-11, SECHRD-12
**Success Criteria** (what must be TRUE):

  1. N parallel submissions of one valid TOTP code succeed at most once (DB compare-and-set), and a code accepted via the −1 skew window cannot be replayed in a later wall-clock step (SECHRD-01)
  2. Rotating `X-Forwarded-For` per request no longer yields a fresh rate-limit bucket — when `trusted_hops >= hops.len()` the limiter keys off `peer_addr()`, not the client-controlled leftmost hop (SECHRD-03)
  3. Two concurrent first-run bootstrap requests create at most one super-admin, and bootstrap is refused when `AXIAM_BOOTSTRAP_ADMIN_EMAIL` / setup token is unset (no unconditional bootstrap) (SECHRD-04)
  4. A non-canonical or wrong-segment request path (e.g. `/api/v1/authz/...` must not match a `/api/v1/auth/*` entry; `//` and `..` variants are collapsed/rejected) cannot slip past the public-path allowlist (SECHRD-11)
  5. A password-reset request for an ineligible/unknown/federated account is time-indistinguishable from a valid one (dummy hash + async wait), the peppered password buffer is zeroized, and the unauthenticated reset path blocks reuse of the current password (SECHRD-12)

**Plans**: 9/9 plans complete

Plans:
**Wave 1**

- [x] 24-01-PLAN.md — SECHRD-01 TOTP atomic replay CAS + skew-step recording + enrollment seed (wave 1)
- [x] 24-02-PLAN.md — SECHRD-11 public-path allowlist segment-boundary + normalization (wave 1)
- [x] 24-03-PLAN.md — SECHRD-03 XFF client-IP keying fix (peer_addr fallback) (wave 1)
- [x] 24-04-PLAN.md — SECHRD-03 shared SurrealDB rate-limit store, fail-open (REST) (wave 1)
- [x] 24-05-PLAN.md — SECHRD-12 secret hygiene: zeroize buffer + secrecy pepper (wave 1)
- [x] 24-06-PLAN.md — SECHRD-12 GDPR audit-write dead-letter (file + structured event) (wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 24-07-PLAN.md — SECHRD-03 gRPC rate-limit parity (store + key extractor) (wave 2)
- [x] 24-08-PLAN.md — SECHRD-04 bootstrap atomicity + mandatory gate + setup token (wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 24-09-PLAN.md — SECHRD-12 constant-time reset + current-password block + history seed (wave 3)

---

### Phase 25: Security Hardening II — Federation, PKI, Data-Protection & Infra

**Goal**: The outbound-fetch, federation, mTLS, GDPR-erasure, AMQP, and cluster-egress trust boundaries all fail closed and never leak, strand, or cross-contaminate tenant data — proven by negative tests
**Depends on**: Phase 23 (parallel-capable with Phase 24)
**Requirements**: SECHRD-02, SECHRD-05, SECHRD-06, SECHRD-07, SECHRD-08, SECHRD-09, SECHRD-10
**Success Criteria** (what must be TRUE):

  1. A discovery document whose `token_endpoint` resolves to a loopback/internal/link-local/ULA address is rejected, and the validated `IpAddr` is pinned into the connection for webhook + OIDC/SAML fetches (no DNS-rebind between check and send) (SECHRD-02)
  2. Device-cert (mTLS) auth against an issuing CA that is not Active or is outside its validity window fails closed (SECHRD-05)
  3. A GDPR purge whose `pseudonymize_actor` step fails leaves the user re-selectable and writes NO erasure proof; a duplicate export request (queued/ready-undownloaded/failed) is rejected; export contains real `sessions` data (SECHRD-06)
  4. An account-linking OIDC callback ignores a request-supplied nonce and validates against server-side login state (replay rejected), and federation/PKI secrets are never serialized or printed in Debug/list paths (SECHRD-07, SECHRD-09)
  5. AMQP message signing is mandatory in production and per-tenant (a tenant-A signature cannot validate a tenant-B message), ExportReady mail is deliverable end-to-end (real `org_id`, backoff retry), and SMTP egress + the completed k8s secret set work under the tightened default-deny NetworkPolicy (SECHRD-08, SECHRD-10)

**Plans**: 10/10 plans complete

Plans:
**Wave 1** *(8 parallel — disjoint files/crates)*

- [x] 25-01-PLAN.md — SECHRD-02: shared SSRF resolve-and-pin guard (axiam-federation) + JWKS/OIDC/SAML call sites
- [x] 25-03-PLAN.md — SECHRD-05: mTLS issuing-CA status/validity gate before verify_signature (axiam-pki)
- [x] 25-04-PLAN.md — SECHRD-06: DB layer — SessionRepository::list_by_user + export dedup widen + erasure_proof UNIQUE index
- [x] 25-06-PLAN.md — SECHRD-07: account-linking OIDC callback nonce-from-server-state + replay test
- [x] 25-07-PLAN.md — SECHRD-08: per-tenant HKDF AMQP signing (mandatory, no fail-open) + cross-tenant/unsigned tests
- [x] 25-08-PLAN.md — SECHRD-08: mail-consumer backoff + ExportReady end-to-end deliverability test
- [x] 25-09-PLAN.md — SECHRD-09: FederationConfig + CaCertificate secret non-serialization/Debug-redaction + narrowed list()
- [x] 25-10-PLAN.md — SECHRD-10: SMTP egress + 443 CIDR exclusions + k8s secret set + CI AXIAM__ prefix (human-verify)

**Wave 2** *(depend on Wave 1)*

- [x] 25-02-PLAN.md — SECHRD-02: webhook delivery IP-pinning via the shared guard + pin test (depends 25-01)
- [x] 25-05-PLAN.md — SECHRD-06/08: proof-last erasure pipeline (fatal pseudonymize) + real-sessions export + ExportReady org_id (depends 25-04)

---

### Phase 26: Correctness & Resilience

**Goal**: Control-plane throughput, database/token resilience, durable webhook delivery, and the frontend auth/tenant flows behave correctly under real conditions and are gated by CI that actually runs
**Depends on**: Phase 23 (SECFIX-03 must precede CORR-03 webhook decrypt; SECFIX-06 is verified by CORR-04 body assertions) — recommended after Phases 24–25
**Requirements**: CORR-01, CORR-02, CORR-03, CORR-04, CORR-05, CORR-06
**Success Criteria** (what must be TRUE):

  1. Raising `grpc_authz_per_sec` increases sustained gRPC throughput (governor no longer inverted to ~1 token/100 s); a test asserts sustained throughput ≈ configured rate (CORR-01)
  2. The SurrealDB client recovers after root-token expiry without a process restart (periodic re-signin or reconnect-on-auth-error), and `health_check` surfaces auth-expiry as unhealthy (CORR-02)
  3. A registered webhook receives an HMAC-SHA256-signed delivery driven from a durable AMQP queue that survives restart, and a failed delivery retries with exponential backoff while writing status to the audit trail (CORR-03)
  4. The CI e2e job runs `npx playwright test` against the seeded backend (vitest kept separate), the auth/login/contract specs gate the build, and the contract spec asserts request **bodies** — catching a SECFIX-06 regression (CORR-04)
  5. After a hard reload the Topbar restores the tenant from `/auth/me` slugs, an MFA-mandated user reaches the setup landing via `setup_token` (no dead end), and VerifyEmail/Dashboard/Org-settings no longer misfire under StrictMode/query-key-collision/refocus (CORR-05, CORR-06)

**Plans**: 8/8 plans complete

Plans:
**Wave 1**

- [x] 26-01-PLAN.md — CORR-01: gRPC governor throughput fix (Quota::per_second) + sustained-throughput test [wave 1]
- [x] 26-02-PLAN.md — CORR-02: SurrealDB proactive re-signin + reactive reconnect + auth-aware health_check [wave 1]
- [x] 26-03-PLAN.md — CORR-03a: webhook emit/deliver_once split + Stripe-style signature + AMQP topology/publisher [wave 1]
- [x] 26-04-PLAN.md — CORR-04: Playwright in CI (blocking) + spec triage + contract body assertions [wave 1]
- [x] 26-05-PLAN.md — CORR-05a: backend /auth/me tenant_slug/org_slug emission (graceful degrade) [wave 1]
- [x] 26-06-PLAN.md — CORR-06: VerifyEmail useRef guard + Dashboard query key + org-settings dirty-tracking [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 26-07-PLAN.md — CORR-03b: webhook consumer + retry/DLQ config + main.rs wiring + integration test [wave 2, depends 26-03]
- [x] 26-08-PLAN.md — CORR-05b: MFA-setup landing route + TotpSetupPanel + tenant-restore e2e [wave 2, depends 26-05]

**UI hint**: yes

---

### Phase 27: Performance & Load Hardening

**Goal**: Hot paths withstand load — HIBP failures degrade gracefully, batch authz parallelizes, JWKS fetches coalesce, DB reconnects back off with jitter, and critical paths are profiled with documented numbers
**Depends on**: Phase 26 (PERF-04 reconnect resilience builds on CORR-02 token-renewal/reconnect work in `connection.rs`)
**Requirements**: PERF-01, PERF-02, PERF-03, PERF-04, PERF-05
**Success Criteria** (what must be TRUE):

  1. A credential-stuffing burst trips the `check_hibp` circuit breaker, which fails open (`Ok(None)`) for a cooldown window and does not starve legitimate auth flows; hot-path vectors are pre-sized (PERF-01)
  2. `BatchCheckAccess` evaluates requests with bounded concurrency, preserves result order, matches per-item `CheckAccess` results, and benchmarks faster than the sequential baseline (PERF-02)
  3. A burst of concurrent cache-miss JWKS lookups (invalid-`kid` tokens) triggers exactly one network fetch, consistently across the Python/Go/Rust/Java/C#/TypeScript SDKs (PERF-03)
  4. A failed SurrealDB handshake / poisoned connection is dropped and never recycled into the healthy pool, and the reconnect loop uses full-jitter exponential backoff with a `max_backoff` ceiling and bounded retry (PERF-04)
  5. `claude_dev/performance-report.md` records baseline-vs-optimized numbers from the load-test harness (k6/criterion) for auth, authz-check, and certificate validation (PERF-05)

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 27-01-PLAN.md — PERF-01 HIBP circuit breaker (fail-open + cooldown) + hot-path pre-sizing (axiam-auth)
- [x] 27-02-PLAN.md — PERF-03 JWKS single-flight: Rust + Python SDKs
- [x] 27-03-PLAN.md — PERF-03 JWKS single-flight: Go + Java + C# SDKs
- [x] 27-04-PLAN.md — PERF-03 JWKS single-flight: TypeScript + PHP SDKs

**Wave 2** *(depends on 27-01 — shared main.rs)*

- [x] 27-05-PLAN.md — PERF-02 concurrent bounded BatchCheckAccess (new AuthzConfig + gRPC + REST + futures dep)

**Wave 3** *(depends on 27-05 — shared main.rs)*

- [x] 27-06-PLAN.md — PERF-04 SurrealDB reconnect resilience (full-jitter backoff + poisoned-handle eviction)
- [x] 27-07-PLAN.md — PERF-05 criterion benches (auth/authz/cert) + performance-report.md

---

### Phase 28: Functional Completeness

**Goal**: The remaining MVP feature gaps are complete and RBAC-gated — first-time federation SSO, session invalidation on reset, admin email-config/user/MFA management, service-account token type, and an SDK-accurate login response schema
**Depends on**: Phase 23 (per-endpoint RBAC re-verified; FUNC-02 session invalidation aligns with the SECFIX-05 session work)
**Requirements**: FUNC-01, FUNC-02, FUNC-03, FUNC-04, FUNC-05
**Success Criteria** (what must be TRUE):

  1. A first-time SSO user with no pre-existing local account completes `POST /auth/federation/oidc/login` (or `/saml/login`) and receives AXIAM access/refresh tokens; the federation metadata endpoint is public (FUNC-01)
  2. After a password reset, all prior sessions/refresh tokens for that user are rejected (`SessionRepository` threaded into `PasswordResetService`) (FUNC-02)
  3. An admin can CRUD org/tenant `email_config` (gated by `email_config:write`), the mail consumer renders a per-tenant custom template, and `backfill_plaintext_secrets` is honestly closed as a documented, tested no-op — `email_config` is ciphertext-only by schema so there is no plaintext to encrypt (see CONTEXT.md D-07); a NULL-ciphertext row surfaces a clear misconfiguration error at send time (D-08) (FUNC-03)
  4. An admin can list users and list/delete another user's MFA methods (RBAC-gated), and service-account tokens carry `sub_kind: "ServiceAccount"` (FUNC-04)
  5. `POST /auth/login` OpenAPI documents both the success and MFA-required responses (via `oneOf`/distinct status) so generated SDKs model them correctly (FUNC-05)

**Plans**: 5/5 plans complete

Plans:
**Wave 1**

- [x] 28-01-PLAN.md — FUNC-03 foundation: email-provider secret hygiene (D-01/D-02), repository delete_org_config + NULL-ciphertext error (D-08) + honest backfill closure (D-07)
- [x] 28-02-PLAN.md — FUNC-04: SubjectKind + sub_kind claim + issue_service_account_token (D-09/D-10/D-11); verify admin user/MFA RBAC gating
- [x] 28-03-PLAN.md — FUNC-03 custom email-template delivery: thread EmailTemplateRepository into the mail consumer with fail-safe fallback (D-05/D-06)
- [x] 28-05-PLAN.md — FUNC-01 first-time OIDC SSO e2e (closes CQ-B40) + FUNC-02 / FUNC-05 verification-and-close

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 28-04-PLAN.md — FUNC-03 email-config admin API (6 scope-nested handlers, route↔OpenAPI↔permission triangle, D-13) + FUNC-01 public-SSO OpenAPI docs (D-12)

---

### Phase 29: Structural Quality

**Goal**: Clear the structural-quality debt at GA — AppState, generic pagination, error taxonomy, transactional mutations, PKI/frontend dedup, dead-code — with no behavior change (tests stay green). Sequenced AFTER security/correctness so refactors never churn unreviewed security code; within the phase, error-taxonomy (QUAL-03) and transaction (QUAL-04) work on security-adjacent paths lands before/with the AppState extraction (QUAL-01)
**Depends on**: Phase 26 (security + correctness complete before structural refactors)
**Requirements**: QUAL-01, QUAL-02, QUAL-03, QUAL-04, QUAL-05, QUAL-06, QUAL-07
**Success Criteria** (what must be TRUE):

  1. `main.rs` composes a single `AppState` instead of ~45 inline `app_data` registrations, and the full existing test suite stays green (no behavior change) (QUAL-01)
  2. Index/unique violations on mainstream create paths return HTTP 409 (`AlreadyExists`, not `Migration`→500), OAuth2 handlers distinguish a DB outage from `invalid_client`, and `helpers::parse_uuid` no longer mislabels a corrupt read as "Migration failed" (QUAL-03)
  3. Role/permission edge deletes and `resource::delete` child-guard run in a single tenant-predicated transaction (no cross-tenant strip, no TOCTOU), and GDPR deletion setup is transactional so a mid-setup failure cannot strand an uncancellable purge (QUAL-04)
  4. The 24 duplicated `CountRow` definitions collapse to `helpers::CountRow`, repos adopt a generic `paginate<T>` + `helpers::parse_uuid`/`take_first_or_not_found`, and `CertService` reconstructs the CA via `from_ca_cert_pem` with shared keypair/fingerprint/encrypt helpers (QUAL-02, QUAL-05)
  5. Frontend pages import the extracted shared components/hooks (`ToggleField`/`SectionCard`/`useCrudMutations`/…) or the dead modules are deleted and profile/MFA pages call a typed users service; the pepper-less second `verify_password` impl and per-request federation/reset/verification service construction are removed (QUAL-06, QUAL-07)

**Plans**: 7/7 plans complete

Plans:
**Wave 1**

- [x] 29-01-PLAN.md — QUAL-03 error taxonomy: classify_write_error + DbError::Serialization, 409 create/edge paths, OAuth2 DB-outage vs invalid_client (Wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 29-02-PLAN.md — QUAL-04 transactional mutations: tenant-predicated role/resource deletes + child-guard TOCTOU + GDPR deletion-setup atomicity (Wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 29-03-PLAN.md — QUAL-01 AppState<C> full migration + QUAL-07 per-request service hoisting (Wave 3)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 29-04-PLAN.md — QUAL-02 paginate<T> + shared-helper dedup (group A) + QUAL-07 pepper-less verify_password deletion (Wave 4)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 29-05-PLAN.md — QUAL-02 CountRow/take_first dedup (group B) + federation_link parse_uuid removal (Wave 5)

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 29-06-PLAN.md — QUAL-05 PKI dedup: from_ca_cert_pem CA reconstruction + shared crypto module + phase-end workspace regression gate (Wave 6)

**Wave 7** *(blocked on Wave 6 completion)*

- [x] 29-07-PLAN.md — QUAL-06 frontend shared components/services adoption + manual smoke checkpoint (Wave 7)

**UI hint**: yes

---

### Phase 30: Compliance & Documentation

**Goal**: Document and certify the finished, hardened MVP — a security-audit checklist mapped to the compliance frameworks, GDPR export/deletion/consent completeness, and consolidated API/deployment/admin/PKI/SDK documentation covering the final state
**Depends on**: Phases 23–29 (documents the completed hardened state; CMPL-02 ties to SECHRD-06 GDPR erasure durability from Phase 25)
**Requirements**: CMPL-01, CMPL-02, DOCS-01
**Success Criteria** (what must be TRUE):

  1. `claude_dev/security-audit.md` maps every authentication, session, access-control, cryptography, and PKI control to a pass/fail with an evidence pointer against OWASP ASVS L2, ISO 27001, and the CyberSecurity Act, with open items cross-referenced to v1.2 REQ-IDs (CMPL-01)
  2. `GET /api/v1/users/:id/export` covers every table incl. real sessions (optional PGP encryption), account deletion durably pseudonymizes audit PII (ties to SECHRD-06), and consent is recorded and exportable (CMPL-02)
  3. `docs/` consolidates REST (OpenAPI) / gRPC (proto) / AMQP (AsyncAPI) API docs, a Docker/K8s deployment guide (env/secrets/NetworkPolicies), admin + PKI/certificate guides, and links to the 7 SDK getting-started READMEs (DOCS-01)

**Plans**: 1/6 plans executed

Plans:
**Wave 1**

- [x] 30-01-PLAN.md — CMPL-01 security-audit.md master doc (ASVS L2 + ISO 27001 family + CyberSecurity Act theme mapping, cite existing evidence) [wave 1]
- [ ] 30-02-PLAN.md — CMPL-02 GDPR verify (re-run gdpr_test.rs) + docs/compliance/gdpr-compliance.md (D-05 async reconciliation, D-06 consent scope) [wave 1]
- [ ] 30-03-PLAN.md — DOCS-01 API contracts: net-new docs/api/asyncapi.yml + openapi.json symlink + grpc.md + api/README.md [wave 1]
- [ ] 30-04-PLAN.md — DOCS-01 operator guides: docs/{deployment,admin,pki}/README.md [wave 1]

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 30-05-PLAN.md — DOCS-01 docs/README.md index + scripts/check-doc-links.sh (zero-dependency link-check) [wave 2]

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 30-06-PLAN.md — DOCS-01 .github/workflows/docs-ci.yml (spec-validate + link-check; @asyncapi/cli legitimacy checkpoint) [wave 3]

---

### Progress (v1.2)

**Execution Order:**
Phases execute in numeric order 23 → 24 → 25 → 26 → 27 → 28 → 29 → 30 with a green-build gate between phases.
Phases 24 and 25 (SECHRD hardening) are parallel-capable once Phase 23 lands. Structural-quality (Phase 29)
is intentionally sequenced after security (23–25) and correctness (26) so refactors never churn unreviewed
security code. Compliance + docs (Phase 30) run last to certify/document the finished, hardened state.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 23. Security Regressions & HIGH Findings | 6/6 | Complete   | 2026-07-03 |
| 24. Security Hardening I — Auth & Access-Control | 9/9 | Complete    | 2026-07-04 |
| 25. Security Hardening II — Federation/PKI/Data/Infra | 10/10 | Complete    | 2026-07-04 |
| 26. Correctness & Resilience | 8/8 | Complete   | 2026-07-05 |
| 27. Performance & Load Hardening | 7/7 | Complete    | 2026-07-05 |
| 28. Functional Completeness | 5/5 | Complete    | 2026-07-05 |
| 29. Structural Quality | 7/7 | Complete    | 2026-07-06 |
| 30. Compliance & Documentation | 1/6 | In Progress|  |

---

### Coverage Matrix (v1.2)

| Requirement | Phase | Description |
|-------------|-------|-------------|
| SECFIX-01 | Phase 23 | gRPC UserService/TokenService authentication (SEC-003) |
| SECFIX-02 | Phase 23 | Tenant guard on live REST grant path (SEC-058) |
| SECFIX-03 | Phase 23 | Webhook fail-closed key + encrypt-at-rest (SEC-059/031) |
| SECFIX-04 | Phase 23 | SAML signature↔assertion binding / XSW (SEC-005) |
| SECFIX-05 | Phase 23 | Logout revokes caller's session (SEC-015) |
| SECFIX-06 | Phase 23 | Reset/resend flows threaded with tenant_id (SEC-044) |
| SECHRD-01 | Phase 24 | TOTP atomic replay protection (SEC-008) |
| SECHRD-03 | Phase 24 | Rate-limit client-IP keying / XFF (SEC-048/060) |
| SECHRD-04 | Phase 24 | Bootstrap atomicity + mandatory gate (SEC-049) |
| SECHRD-11 | Phase 24 | Public-path allowlist hardening (T19.25) |
| SECHRD-12 | Phase 24 | Auth crypto & recovery side-channels (T19.23/24/27) |
| SECHRD-02 | Phase 25 | SSRF address pinning — webhook + federation (SEC-019/064) |
| SECHRD-05 | Phase 25 | mTLS CA status & validity enforcement (SEC-061) |
| SECHRD-06 | Phase 25 | GDPR erasure durability & ledger integrity (SEC-063/065/066) |
| SECHRD-07 | Phase 25 | Federation nonce from server state (SEC-004) |
| SECHRD-08 | Phase 25 | AMQP signing key + ExportReady delivery (SEC-022/055) |
| SECHRD-09 | Phase 25 | Federation secret non-serialization (SEC-017) |
| SECHRD-10 | Phase 25 | Network egress + k8s secret completeness (SEC-053/052) |
| CORR-01 | Phase 26 | gRPC governor throughput semantics (CQ-B44) |
| CORR-02 | Phase 26 | SurrealDB token renewal / reconnect (CQ-B45) |
| CORR-03 | Phase 26 | Webhook delivery wiring via AMQP (CQ-B22) |
| CORR-04 | Phase 26 | Playwright in CI + body assertions (CQ-F36) |
| CORR-05 | Phase 26 | Frontend tenant context + MFA-setup landing (CQ-F29/F31) |
| CORR-06 | Phase 26 | Frontend residual correctness (CQ-F19/37/38) |
| PERF-01 | Phase 27 | HIBP circuit breaker + hot-path pre-sizing (T19.26) |
| PERF-02 | Phase 27 | Concurrent bounded BatchCheckAccess (T19.2/CQ-B20) |
| PERF-03 | Phase 27 | JWKS single-flight across SDKs (T19.28) |
| PERF-04 | Phase 27 | SurrealDB reconnect resilience (T19.33/34) |
| PERF-05 | Phase 27 | Load testing & critical-path profiling (T18.3) |
| FUNC-01 | Phase 28 | Unauthenticated first-time federation login (T19.9) |
| FUNC-02 | Phase 28 | Session invalidation on password reset (T19.10) |
| FUNC-03 | Phase 28 | Admin email-config API & template delivery (T19.20/21/22) |
| FUNC-04 | Phase 28 | Admin user & MFA management + SA token type |
| FUNC-05 | Phase 28 | OpenAPI login response schema (T19.4) |
| QUAL-01 | Phase 29 | AppState extraction (CQ-B43) |
| QUAL-02 | Phase 29 | Generic pagination & shared repo helpers (CQ-B10) |
| QUAL-03 | Phase 29 | Error taxonomy correctness (CQ-B11/17/18) |
| QUAL-04 | Phase 29 | Transactional multi-statement mutations (CQ-B07/46) |
| QUAL-05 | Phase 29 | PKI helper deduplication (CQ-B15) |
| QUAL-06 | Phase 29 | Frontend shared components & services (CQ-F15/17/39) |
| QUAL-07 | Phase 29 | Dead-code & per-request-construction cleanup (CQ-B47/27) |
| CMPL-01 | Phase 30 | Security audit checklist (T18.1) |
| CMPL-02 | Phase 30 | GDPR completeness (T18.2) |
| DOCS-01 | Phase 30 | Comprehensive documentation (T18.4) |

**Coverage: 44/44 v1.2 requirement IDs mapped (100%).** (The enumerated set totals 44 — SECFIX 6 + SECHRD 12 + CORR 6 + PERF 5 + FUNC 5 + QUAL 7 + CMPL 2 + DOCS 1; the earlier "42" label undercounted by 2.)

---

### Dependency Graph (v1.2)

```
Priority band ordering (Core Value): security > correctness > performance > compliance > structural quality > docs

Phase 23: SECFIX critical/HIGH regressions  (first — highest priority)
    |
    +--> Phase 24: SECHRD auth/access-control hardening  ┐ (24 & 25 parallel-capable after 23)
    +--> Phase 25: SECHRD federation/PKI/data/infra       ┘
    |
    v
Phase 26: CORR correctness + resilience
    (SECFIX-03 -> CORR-03 webhook decrypt; SECFIX-06 -> CORR-04 body assertions; CORR-05 backend /auth/me before frontend restore)
    |
    v
Phase 27: PERF  (PERF-04 reconnect builds on CORR-02)
    |
    v
Phase 28: FUNC completeness  (depends on per-endpoint RBAC from Phase 23)
    |
    v
Phase 29: QUAL structural refactors  (AFTER security/correctness; QUAL-03/04 security-adjacent, before/with QUAL-01)
    |
    v
Phase 30: CMPL + DOCS  (certifies/documents the finished hardened state; CMPL-02 <- SECHRD-06)
```
