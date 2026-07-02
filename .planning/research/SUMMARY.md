# Research Summary — AXIAM MVP Hardening

> Synthesized: 2026-03-30

## Key Findings

### Critical Security Gaps (Must Fix Before Beta)

1. **Federation tokens unverified** — OIDC ID tokens and SAML responses accepted without cryptographic signature verification. Any forged token from a configured IdP would be accepted. (STACK, FEATURES, PITFALLS)

2. **No authorization on endpoints** — RBAC engine exists but zero endpoints enforce it. Any authenticated user has full admin access. No admin bootstrap mechanism exists. (FEATURES, PITFALLS)

3. **JWT in sessionStorage** — Accessible to any XSS. IAM products must use httpOnly secure cookies. Migration requires backend cookie handling + frontend refactor + CSRF protection. (FEATURES, ARCHITECTURE, PITFALLS)

4. **Federation secrets in plaintext** — OAuth2 client_secret stored unencrypted in SurrealDB. AES-256-GCM encryption already available (used for MFA secrets). (FEATURES)

5. **No security headers** — Missing CSP, HSTS, X-Content-Type-Options, Permissions-Policy, Referrer-Policy on both backend API and frontend nginx. (FEATURES)

### High Priority Gaps

6. **Email delivery not wired** — EmailService exists with SMTP + 4 provider support, but auth handlers don't call it. Password reset and email verification flows are incomplete.

7. **No rate limiting** — Login, token, and registration endpoints have no brute-force protection. Need `actix-governor` or similar.

8. **No GDPR data operations** — No data export (Art. 15) or right-to-erasure (Art. 17) with audit log pseudonymization.

9. **Session invalidation missing** — Password change/reset doesn't invalidate existing sessions/tokens.

10. **CI lacks security scanning** — No cargo-audit, cargo-deny, trivy, or npm audit in pipeline.

### Architecture Implications

- **Cookie migration is foundational** — Must happen first since it changes how the frontend authenticates (removes Bearer header, adds cookie handling, needs CSRF protection). All subsequent features depend on the auth mechanism being stable.

- **RBAC wiring is the largest task** — Every REST endpoint needs a permission check. Requires: admin bootstrap flow, default-deny middleware, public endpoint allowlist, integration tests.

- **Build order matters:**
  1. Cookie auth migration (backend + frontend)
  2. Security headers + rate limiting
  3. RBAC wiring + admin bootstrap
  4. Federation verification (JWKS + SAML sig)
  5. Email delivery wiring
  6. GDPR data operations
  7. CI/infrastructure hardening
  8. Testing + compliance verification

### Tooling Decisions

| Need | Solution | New Dependency? |
|------|----------|----------------|
| Cookie auth | Actix-Web native | No |
| CSRF protection | Double-submit cookie pattern | No |
| Security headers | Custom middleware (20 lines) | No |
| Rate limiting | `actix-governor` + `governor` | Yes |
| OIDC JWKS verify | `jsonwebtoken` (already present) | No |
| SAML sig verify | `samael` (already present) | No |
| Secret encryption | `aes-gcm` (already present) | No |
| CI scanning | cargo-audit, cargo-deny, trivy, npm audit | CI tools only |
| Container scanning | trivy | CI tool only |

### Key Pitfalls to Watch

1. **Admin bootstrap chicken-and-egg** — Need a bootstrap-only endpoint for first admin
2. **JWKS algorithm confusion attacks** — Must pin expected algorithms per federation provider
3. **Cookie path scoping** — Refresh token cookie must be path-restricted to `/api/v1/auth/refresh`
4. **Audit log vs GDPR erasure conflict** — Pseudonymize PII in audit logs, don't delete entries
5. **Missing endpoint authorization** — Need default-deny middleware + exhaustive test
