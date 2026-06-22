# Features Research — IAM MVP Security Requirements

> Generated: 2026-03-30

## Table Stakes (Must Have for Beta)

### 1. Authentication Security

| Feature | Standard | Current State | Gap |
|---------|----------|--------------|-----|
| Password hashing (Argon2id) | OWASP ASVS 2.4.1 | Done | None |
| JWT short-lived access tokens (15min) | OWASP ASVS 3.5.1 | Done | None |
| Refresh token rotation (single-use) | OWASP ASVS 3.5.2 | Done | None |
| httpOnly secure cookie for tokens | OWASP ASVS 3.4.2-3.4.5 | **Missing** — using sessionStorage | Critical |
| Session invalidation on password change | OWASP ASVS 3.3.1 | **Missing** (T19.10) | Critical |
| MFA enforcement policy | OWASP ASVS 2.8 | Done | None |
| Brute-force protection (rate limiting) | OWASP ASVS 2.2.1 | **Missing** on login/token endpoints | High |
| Account lockout after failed attempts | OWASP ASVS 2.2.3 | **Missing** | High |

### 2. Authorization (RBAC)

| Feature | Standard | Current State | Gap |
|---------|----------|--------------|-----|
| Per-endpoint authorization checks | OWASP ASVS 4.1.1-4.1.5 | **Missing** — engine exists, not wired | Critical |
| Default-deny authorization | OWASP ASVS 4.1.1 | **Missing** — all endpoints open to any authenticated user | Critical |
| Admin bootstrap flow | N/A | **Missing** — no way to create first admin | High |
| Privilege escalation prevention | OWASP ASVS 4.2 | Partially done (MFA reset fixed) | Medium |

### 3. OAuth2 Compliance (RFC 6749 / RFC 7636)

| Requirement | RFC Section | Current State | Gap |
|-------------|------------|--------------|-----|
| Authorization Code + PKCE | RFC 7636 | Done | None |
| Client authentication | RFC 6749 §2.3 | Done | None |
| Redirect URI exact match | RFC 6749 §3.1.2.3 | Done | None |
| Token endpoint HTTPS only | RFC 6749 §3.2 | Infrastructure concern | Verify in K8s |
| Refresh token binding | RFC 6749 §10.4 | Done (single-use rotation) | None |
| Error response format | RFC 6749 §5.2 | Done | Verify completeness |
| State parameter validation | RFC 6749 §10.12 | Done | None |

### 4. OIDC Compliance (Core 1.0)

| Requirement | Spec Section | Current State | Gap |
|-------------|-------------|--------------|-----|
| Discovery endpoint | §4 | Done (/.well-known/openid-configuration) | None |
| JWKS endpoint | §10 | Done | None |
| ID Token signing (EdDSA) | §2 | Done | None |
| ID Token validation at RP | §3.1.3.7 | **Missing** — federation accepts without verify (T19.6) | Critical |
| Userinfo endpoint | §5.3 | Done | None |
| Nonce validation | §3.1.2.1 | Verify implementation | Medium |
| at_hash claim | §3.1.3.6 | Verify implementation | Medium |

### 5. Federation Security

| Feature | Standard | Current State | Gap |
|---------|----------|--------------|-----|
| OIDC token JWKS verification | OIDC Core §3.1.3.7 | **Missing** (T19.6) | Critical |
| SAML XML signature verification | SAML Core §5 | **Missing** (T19.7) | Critical |
| Federation client secret encryption | OWASP ASVS 6.4.1 | **Missing** (T19.8) | Critical |
| Redirect URI validation in federation | OWASP ASVS 4.3 | Done (HTTPS-only) | None |

### 6. Email Delivery

| Feature | Purpose | Current State | Gap |
|---------|---------|--------------|-----|
| Password reset email | Auth flow | **Stubbed** (T19.11) | High |
| Email verification | Auth flow | **Stubbed** (T19.12) | High |
| Notification dispatch | Audit alerts | **Stubbed** (T19.13) | Medium |
| SMTP + provider config | Settings | Service exists, not wired to handlers | High |

### 7. Security Headers

| Header | Value | Current State | Gap |
|--------|-------|--------------|-----|
| Content-Security-Policy | Strict policy | **Missing** | High |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | **Missing** | High |
| X-Content-Type-Options | nosniff | **Missing** | Medium |
| X-Frame-Options | DENY | **Missing** | Medium |
| Permissions-Policy | Restrictive | **Missing** | Medium |
| Referrer-Policy | strict-origin-when-cross-origin | **Missing** | Medium |

### 8. GDPR Minimum Viable Compliance

| Requirement | GDPR Article | Current State | Gap |
|-------------|-------------|--------------|-----|
| Right of access (data export) | Art. 15 | **Missing** | High |
| Right to erasure | Art. 17 | **Missing** | High |
| Data processing records | Art. 30 | Audit logs exist (partial) | Medium |
| Privacy policy acknowledgment | Art. 7 | **Missing** (consent tracking) | Medium |
| Data breach notification capability | Art. 33 | **Missing** | Low (operational) |

**Note on audit logs vs erasure:** Audit logs are append-only by design. GDPR right-to-erasure conflicts with audit immutability. Standard approach: pseudonymize user data in audit logs (replace PII with anonymized IDs) rather than deleting entries.

### 9. Infrastructure Security

| Feature | Current State | Gap |
|---------|--------------|-----|
| K8s NetworkPolicy | **Missing** | High |
| Pod security standards (restricted) | SecurityContext exists | Verify completeness |
| Docker non-root user | **Check** Dockerfile | Medium |
| Image signing (cosign) | CI has cosign step | Verify |
| TLS termination | Ingress configured | Verify cert management |
| Secrets management | K8s Secrets | Consider sealed-secrets for GitOps |

## Differentiators (Not Blocking Beta)

- Hardware security module (HSM) integration for CA keys
- WebAuthn attestation verification (beyond basic)
- Adaptive MFA (risk-based)
- IP reputation scoring
- Anomaly detection on login patterns
- SCIM provisioning
- OpenPolicyAgent integration

## Anti-Features (Do NOT Build for MVP)

- Custom WAF rules — use infrastructure-level WAF (nginx/ingress)
- Multi-region replication — single cluster for beta
- Real-time event streaming (WebSocket) — REST polling is sufficient
- Social login providers (Google, GitHub) — OIDC federation covers this generically
- Self-service organization creation — admin-provisioned for beta
- Password-less only auth — keep password + MFA as primary
