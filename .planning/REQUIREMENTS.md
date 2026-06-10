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

## Audit Remediation (post-beta tranche)

> Source: `claude_dev/remediation-plan.md`, derived from `claude_dev/code-review.md`
> (`CQ-B01..B44`, `CQ-F01..F35`) and `claude_dev/security-review.md` (`SEC-002..SEC-057`),
> both at commit `d69323b`. These requirements open after the v1.0-beta milestone and are
> executed wave-by-wave with a green-build gate between waves.

## REQ-12: Build Integrity (Wave 0)

**Priority:** Blocker | **Source:** code-review CQ-B37

`axiam-server` must compile and the CI build must pass under `-D warnings`. Blocks all
subsequent remediation waves.

### Acceptance Criteria
- [ ] `cargo build -p axiam-server` succeeds (uuid/chrono/serde_json moved to `[dependencies]`, direct `sha2` dep added)
- [ ] `cleanup.rs` imports `sha2::{Digest, Sha256}` (not `rsa::sha2::{...}`); unused `rsa` dep dropped if now unused
- [ ] CI `build` job passes `-p axiam-server` including `-D warnings` (12 warnings in `req5_*/req7_*/cleanup_task` tests cleared)

---

## REQ-13: Critical Security Remediation (Wave 1)

**Priority:** Critical | **Source:** SEC-002, SEC-003, SEC-044/CQ-F27, CQ-F28, SEC-045/SEC-017

Close cross-tenant data exposure and broken authentication lifecycle defects.

### Acceptance Criteria
- [ ] Cross-org IDOR closed: org-nested routes (orgs/tenants/CA certs) return 403 when `org_id != user.org_id`; org create/list restricted to system-admin; cross-org negative tests pass
- [ ] gRPC authenticated: Tonic interceptor validates bearer JWT / mTLS identity; tenant_id/subject_id derived from verified claims; public gRPC ingress removed; interceptor accept/reject tests added
- [ ] All six frontend auth flows call real backend endpoints via a typed `auth.ts` service (reset, reset-confirm, verify-email, resend, change-password, MFA enroll/confirm); frontend↔OpenAPI contract test gates in CI
- [ ] Silent refresh succeeds (CSRF token attached, skip-list narrowed); boot refresh attempted once before declaring unauthenticated
- [ ] Federation client secrets decrypted at use and encrypted on create/update; secret never serialized; OIDC login succeeds after restart/backfill

---

## REQ-14: High Security Remediation (Wave 2)

**Priority:** High | **Source:** CQ-B01/B02/B03/B04/B05/B06/B07/B08/B09/B30/B38/B40, CQ-F01..F08, SEC-005/007/008/010/011/012/017/033/039/056

Resolve high-severity correctness, async-safety, tenant-isolation, and protocol-hardening defects. *Foundational first:* single hashing path + pepper (CQ-B09/B01) and `load_key_from_env` extraction (CQ-B43, enables SEC-012).

### Acceptance Criteria
- [ ] One password-hashing path with pepper (repo-layer hasher deleted); REST-created user logs in with pepper set
- [ ] Argon2 hash/verify and PKI keygen/sign run in `spawn_blocking` behind a bounding semaphore
- [ ] Tenant settings persist sparse overrides merged against org baseline at read time; baseline change propagates
- [ ] Tenant-scoped edge mutations (role/permission) verify both endpoints belong to tenant and run in transactions; resource hierarchy rejects cycles/orphans and drops depth-50 truncation
- [ ] GDPR purge/export correctness (re-selectable on failure, complete export, paginated audit, Failed status); SAML protocol checks (InResponseTo/Destination/Conditions/XSW); TOTP replay rejected; pagination clamped; 5xx errors generic; PKI fails fast on missing key; AMQP DLQ parity; migration idempotent/transactional
- [ ] Frontend High items fixed (real `user.id`, ConfirmDialog label, debounce cleanup, useQuery search, logout clears store, eslint+`tsc -b` in CI, org settings save, no fabricated tenant status)

---

## REQ-15: Medium Security Remediation (Wave 3)

**Priority:** Medium | **Source:** CQ-B10..B26/B39/B41/B43, CQ-F09..F19/F29/F30/F31, SEC-016/019/020/022/023/024/025/026/028/031/032/046/047/048/049/050/051/052/053/054/055

Consolidate repo/DTO patterns, add transport limits, and harden auth/infra surfaces.

### Acceptance Criteria
- [ ] Shared repo helpers + request DTOs; index/duplicate violations map to 409; OAuth2/gRPC error mapping + message-size/timeout/concurrency/TLS limits correct
- [ ] Webhook SSRF re-resolves and pins IP at delivery; rate limits on `/auth/mfa/*` + `/oauth2/introspect|revoke`; AMQP authz/mail messages authenticated/scoped; mTLS verifies chain to tenant/org CA; S256 PKCE enforced
- [ ] Auth hardening: dummy-Argon2 on user-not-found, atomic failed-login increment, reset-to-current blocked, CSRF on `/api/v1` CRUD, permission enforcement keyed off `ROUTE_PERMISSION_MAP`, bootstrap transactional + gated, self-update strips `status` + gates email change, logout revokes caller's own session
- [ ] k8s/nginx hardened: `AXIAM__` env keys + secrets, receiver-side NetworkPolicies + PSA restricted, `/oauth2/*` + `/.well-known` proxy locations, backend ports unpublished, prod compose default creds removed
- [ ] Frontend medium items: toast + `getApiErrorMessage` on all mutations, form validation, resource parent picker excludes descendants, federation edit locks type, pagination `placeholderData`, shared components/hooks, route guards + friendly 403, login handles `mfa_setup_required`/`mfa_required`

---

## REQ-16: Low / Trivial Remediation (Wave 4)

**Priority:** Low | **Source:** CQ-B27..B36/B42, CQ-F20..F35, SEC-036/037/040/041/043/057

Close remaining cleanup, dead-code, dependency, i18n, and minor security-polish findings.

### Acceptance Criteria
- [ ] Backend cleanup: shared `client_ip`/`user_agent` helper, NotificationDispatcher wired or removed, logged error handling (no silent `let _ =`/`.ok()`), typed errors, `cargo machete` dep pruning + `rand` consolidation, HIBP on sync change-password, audit-drop metric, seeder version/hash skip
- [ ] SEC-040 deny-overrides cascade implemented or CLAUDE.md wording corrected; encrypted blobs no longer `Debug`-derived/hydrated on list paths; GitHub Actions pinned by commit SHA
- [ ] Frontend trivial items: dead `Placeholder.tsx` removed, unused radix deps removed, password-policy checker on admin-create+bootstrap, safe DataTable row key, i18n / no hardcoded `en-US`, `CSS.escape` in ResourceTree, `_retry` guard + escaped cookie regex, bootstrap 404 handling, StrictMode double-fetch fixed
- [ ] Secrets cleared from React state on modal close; reset/verify tokens stripped from URL via `history.replaceState`; no full Axios error/email logging on ForgotPasswordPage
- [ ] Final whole-effort verification green: `cargo build/clippy -D warnings/test --workspace`, `cargo audit`/`cargo-deny`, `npm audit`, frontend `lint && tsc -b && vitest`, Playwright e2e gating in CI; manual smoke (login→MFA→reset/verify/change-pw→GDPR→federation-after-restart→cross-org 403→gRPC-no-creds rejected)

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
| REQ-9 | Phase 6 | Complete |
| REQ-10 | Phase 6 | Complete |
| REQ-11 | Phase 7 | Complete |
| REQ-12 | Phase 8 | Pending |
| REQ-13 | Phase 9 | Pending |
| REQ-14 | Phase 10 | Pending |
| REQ-15 | Phase 11 | Pending |
| REQ-16 | Phase 12 | Pending |

---
*Last updated: 2026-06-10 (audit-remediation tranche REQ-12..16 added)*
