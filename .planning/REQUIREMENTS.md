# Requirements — MVP Hardening & Security Compliance

> Milestone: v1.0-beta
> Created: 2026-03-30

## REQ-1: Cookie-Based Authentication

**Priority:** Critical | **Source:** OWASP ASVS 3.4.2-3.4.5, user decision

Migrate JWT token delivery from sessionStorage (XSS-vulnerable) to httpOnly secure cookies with proper CSRF protection.

### Acceptance Criteria
- [ ] Access token delivered via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/`
- [ ] Refresh token delivered via `Set-Cookie` with `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh`
- [ ] Frontend removes all sessionStorage token handling
- [ ] Frontend API client sends credentials via cookies (no Authorization header)
- [ ] CSRF double-submit cookie pattern implemented for state-changing requests
- [ ] Logout endpoint clears cookies server-side (`Max-Age=0`)
- [ ] Refresh endpoint uses refresh cookie, returns new access cookie
- [ ] Existing integration tests updated for cookie-based auth

---

## REQ-2: Security Headers

**Priority:** High | **Source:** OWASP ASVS 14.4

Add comprehensive security headers to both backend API and frontend nginx.

### Acceptance Criteria
- [ ] Backend middleware adds: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] Nginx config adds: `Content-Security-Policy`, `Strict-Transport-Security`, `Permissions-Policy`
- [ ] CSP policy restricts scripts to self-origin (no inline, no eval)
- [ ] HSTS with `max-age=31536000; includeSubDomains`

---

## REQ-3: Rate Limiting & Brute-Force Protection

**Priority:** High | **Source:** OWASP ASVS 2.2.1

Protect authentication endpoints from brute-force and credential stuffing attacks.

### Acceptance Criteria
- [ ] Rate limiting on `/auth/login` (10 req/min per IP)
- [ ] Rate limiting on `/auth/register` (5 req/min per IP)
- [ ] Rate limiting on `/oauth2/token` (20 req/min per client)
- [ ] Rate limiting on `/auth/password-reset` (3 req/min per IP)
- [ ] Account lockout after 5 consecutive failed login attempts (15-min cooldown)
- [ ] Lockout status visible in admin UI
- [ ] gRPC brute-force protection (T19.5)

---

## REQ-4: RBAC Enforcement

**Priority:** Critical | **Source:** OWASP ASVS 4.1.1-4.1.5, user decision

Wire the existing authorization engine to ALL REST API endpoints with default-deny.

### Acceptance Criteria
- [ ] Default-deny middleware: all routes require authorization unless explicitly public
- [ ] Public endpoint allowlist: login, register, health, OIDC discovery, JWKS, federation callbacks
- [ ] Every CRUD endpoint requires the appropriate permission (e.g., `users:read`, `users:write`)
- [ ] Self-service endpoints verify `caller_user_id == target_user_id`
- [ ] Admin bootstrap endpoint: creates first admin when zero admins exist, disabled after
- [ ] Admin bootstrap configurable via `AXIAM_BOOTSTRAP_ADMIN_EMAIL` env var
- [ ] Integration test verifying every registered route has an authorization check
- [ ] Admin user listing endpoint enabled (T19.3)
- [ ] Admin MFA management for other users enabled (T19.3)

---

## REQ-5: Federation Token Verification

**Priority:** Critical | **Source:** OIDC Core §3.1.3.7, SAML Core §5

Cryptographically verify all federation tokens before accepting them.

### Acceptance Criteria
- [ ] OIDC: Fetch and cache JWKS from IdP discovery endpoint
- [ ] OIDC: Verify ID token signature using JWKS public keys
- [ ] OIDC: Validate `iss`, `aud`, `exp`, `nonce` claims
- [ ] OIDC: Pin expected algorithm per federation config (reject `none`)
- [ ] OIDC: JWKS cache with TTL (1 hour) + retry-on-failure
- [ ] SAML: Verify XML signature on SAML response
- [ ] SAML: Validate `NotOnOrAfter`, `NotBefore`, `Audience` conditions
- [ ] SAML: Track consumed assertion IDs (prevent replay)
- [ ] Clock skew tolerance: 60 seconds
- [ ] Federation client secrets encrypted at rest with AES-256-GCM (T19.8)

---

## REQ-6: Email Delivery

**Priority:** High | **Source:** T19.11, T19.12, user decision

Wire the existing EmailService to authentication flows with configurable SMTP/provider backend.

### Acceptance Criteria
- [ ] Password reset handler sends reset email via EmailService (T19.11)
- [ ] Email verification handler sends verification email via EmailService (T19.12)
- [ ] Notification dispatcher sends alerts via EmailService (T19.13)
- [ ] Email provider configurable via settings: SMTP, SendGrid, Postmark, Resend, Brevo
- [ ] Email delivery failures logged to audit with retry info
- [ ] Email templates use proper escaping (no triple-stash `{{{}}}`)
- [ ] Reset/verification URLs use server-generated tokens only

---

## REQ-7: Session Security

**Priority:** High | **Source:** OWASP ASVS 3.3.1, T19.10

Ensure session lifecycle is properly managed.

### Acceptance Criteria
- [ ] All active sessions/refresh tokens invalidated on password change
- [ ] All active sessions/refresh tokens invalidated on password reset
- [ ] Session invalidation on MFA reset
- [ ] Service-account dedicated token type with `sub_kind: "ServiceAccount"` (T15 TODO)

---

## REQ-8: GDPR Compliance

**Priority:** High | **Source:** GDPR Articles 15, 17

Implement minimum viable GDPR data subject rights.

### Acceptance Criteria
- [ ] Data export endpoint: returns all user data across all tables as JSON (Art. 15)
- [ ] Data deletion endpoint: removes user and pseudonymizes PII in audit logs (Art. 17)
- [ ] Pseudonymization replaces user identifiers with `DELETED_USER_<hash>` in audit entries
- [ ] Audit log entries preserved (immutability maintained) with PII stripped
- [ ] Consent tracking: record when user accepted terms
- [ ] Integration test: create user with data in every table, export, verify completeness
- [ ] Integration test: delete user, verify PII removed from all tables and audit pseudonymized

---

## REQ-9: CI/CD Security Hardening

**Priority:** High | **Source:** Best practice

Add security scanning to CI pipeline and harden build process.

### Acceptance Criteria
- [ ] `cargo-audit` step in CI (fail on known vulnerabilities with patches)
- [ ] `cargo-deny` step in CI (license + vulnerability + duplicate checking)
- [ ] `npm audit` step in CI for frontend
- [ ] `trivy` container image scan after Docker build
- [ ] `hadolint` Dockerfile linting
- [ ] Frontend build with `sourcemap: false` in production
- [ ] Vite SRI (Subresource Integrity) for production assets
- [ ] OpenAPI schema accuracy verification (T19.4)

---

## REQ-10: Infrastructure Hardening

**Priority:** Medium | **Source:** K8s security best practices

Harden Docker and Kubernetes deployment configurations.

### Acceptance Criteria
- [ ] Docker images run as non-root user
- [ ] Docker images use minimal base (distroless or alpine)
- [ ] K8s NetworkPolicy: server→surrealdb, server→rabbitmq, ingress→frontend, ingress→server
- [ ] K8s pod security standards verified (restricted profile)
- [ ] All K8s secrets use `secretKeyRef` (no inline values)
- [ ] Health check endpoints validated in K8s probes
- [ ] Docker compose dev environment updated for cookie auth

---

## REQ-11: Testing Gaps

**Priority:** High | **Source:** Codebase analysis

Close critical testing gaps in security-sensitive crates.

### Acceptance Criteria
- [ ] gRPC authorization integration tests (T19.1)
- [ ] Concurrent batch authorization tests (T19.2)
- [ ] PKI/certificate generation tests (axiam-pki)
- [ ] Federation OIDC flow integration tests (with mocked IdP)
- [ ] Federation SAML flow integration tests (with mocked IdP)
- [ ] RBAC enforcement integration tests (every endpoint)
- [ ] Cookie auth flow integration tests
- [ ] GDPR export/deletion integration tests
- [ ] Frontend E2E tests for login, RBAC, federation flows

---

## Dependency Map

```
REQ-1 (Cookie Auth) ──────┐
                           ├──→ REQ-4 (RBAC) ──→ REQ-6 (Email) ──→ REQ-8 (GDPR)
REQ-2 (Security Headers) ─┘          │
REQ-3 (Rate Limiting) ───────────────┘
REQ-5 (Federation Verify) ─── independent
REQ-7 (Session Security) ──── depends on REQ-1
REQ-9 (CI Hardening) ──────── independent (can run in parallel)
REQ-10 (Infra Hardening) ──── independent (can run in parallel)
REQ-11 (Testing) ──────────── runs after each REQ as verification
```

---

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| REQ-1 | Phase 1 | Complete |
| REQ-2 | Phase 2 | Complete |
| REQ-3 | Phase 2 | Complete |
| REQ-4 | Phase 3 | Complete |
| REQ-5 | Phase 4 | Pending |
| REQ-6 | Phase 5 | Complete |
| REQ-7 | Phase 4 | Pending |
| REQ-8 | Phase 5 | Complete |
| REQ-9 | Phase 6 | Pending |
| REQ-10 | Phase 6 | Pending |
| REQ-11 | Phase 7 | Pending |

---
*Last updated: 2026-03-30*
