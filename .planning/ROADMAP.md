# Roadmap — MVP Hardening & Security Compliance

> Milestone: v1.0-beta
> Phases: 13 | Granularity: standard
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
- [ ] **Phase 13: SurrealDB Connection Resilience** - Reconnect-safe ns/db selection + ns/db-asserting health check; first-run seed repair; unblocks deferred Phase-12 smoke

> Audit-remediation tranche (Phases 8–12) added 2026-06-10 from `claude_dev/remediation-plan.md`; sequential with a green-build gate between waves.
> Phase 13 added 2026-06-19 — durable fix for the SurrealDB stale-connection bug found during the Phase-12 manual smoke.

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

**Plans**: 5 plans

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
- [ ] 13-01-PLAN.md — DbManager reconnect resilience: ns/db keepalive guard + asserting health_check + regression test
- [ ] 13-02-PLAN.md — First-run seed repair: e2e-bootstrap.sh db-name/is_active fix + `just bootstrap-local`

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
| 13. SurrealDB Connection Resilience | 0/? | Planned | |

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

**Coverage: 17/17 requirements mapped (100%)**

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
