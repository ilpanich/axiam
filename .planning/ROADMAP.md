# Roadmap — MVP Hardening & Security Compliance

> Milestone: v1.0-beta
> Phases: 7 | Granularity: standard
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
- [ ] **Phase 7: Compliance Verification & Test Closure** - Verify OWASP ASVS, OAuth2 RFC, OIDC conformance and close remaining test gaps

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

- [ ] 07-05-PLAN.md — ASVS L2 checklist (V2-V14) + finalized FINDINGS register (Wave 2)

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

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7
Note: Phases 4 and 6 can run in parallel with Phase 3 and Phase 5 respectively (see dependency map).

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Cookie-Based Authentication | 3/3 | Complete   | 2026-04-04 |
| 2. Security Headers & Rate Limiting | 5/5 | Complete   | 2026-05-29 |
| 3. RBAC Enforcement | 5/5 | Complete   | 2026-05-29 |
| 4. Federation Verification & Session Security | 6/6 | Complete   | 2026-05-29 |
| 5. Email Delivery & GDPR Compliance | 5/5 | Complete   | 2026-06-02 |
| 6. CI/CD & Infrastructure Hardening | 5/5 | Complete   | 2026-06-07 |
| 7. Compliance Verification & Test Closure | 4/5 | In Progress|  |

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

**Coverage: 11/11 requirements mapped (100%)**

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
```
