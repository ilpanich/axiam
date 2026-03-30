# Stack Research — IAM Security Hardening

> Generated: 2026-03-30

## Security Crates to Add

### Cookie Auth
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| `actix-web` (built-in Cookie) | 4.x | `Cookie::build()` with httpOnly, Secure, SameSite=Strict | High — native, no extra dep |
| `tower-cookies` | N/A | Not needed — Actix-Web has native cookie support | Skip |

**Why:** Actix-Web's built-in cookie API supports all required attributes. No new crate needed.

### CSRF Protection
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| Double-submit cookie pattern | N/A | Custom implementation — CSRF token in cookie + header | High |

**Why:** With SameSite=Strict cookies, CSRF risk is minimal for same-origin API calls. For cross-origin (federation callbacks), use state parameter validation. A custom double-submit pattern is simpler than adding a crate.

### Security Headers
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| Actix-Web middleware (custom) | N/A | Add CSP, HSTS, X-Content-Type-Options, Permissions-Policy | High |

**Why:** Security headers are static strings set in middleware. A 20-line middleware is simpler than a crate dependency.

### Rate Limiting
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| `actix-governor` | 0.6+ | Token bucket rate limiting per IP/endpoint | High |
| `governor` | 0.8+ | Underlying rate limiter (used by actix-governor) | High |

**Why:** `actix-governor` wraps `governor` for Actix-Web. Essential for brute-force protection on login, token, and registration endpoints.

### Federation Token Verification
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| `jsonwebtoken` | 9.x | Already in workspace — JWKS key decoding for OIDC verification | High |
| `reqwest` | Already present | Fetch JWKS endpoints | High |
| `samael` | 0.0.19 | Already present — has XML signature verification support | Medium |

**Why:** OIDC JWKS verification uses `jsonwebtoken` to decode with fetched public keys. SAML uses `samael`'s built-in XML sig verification (needs enabling).

### Encryption at Rest
| Crate | Version | Purpose | Confidence |
|-------|---------|---------|------------|
| `aes-gcm` | Already present | AES-256-GCM for client secrets, MFA secrets | High |

**Why:** Already in workspace for MFA secret encryption. Reuse for federation client secrets.

## CI Security Tooling

| Tool | Purpose | Integration |
|------|---------|-------------|
| `cargo-audit` | Known vulnerability scanning (RustSec DB) | GitHub Actions step |
| `cargo-deny` | License + vulnerability + duplicate dep checking | GitHub Actions step |
| `trivy` | Container image vulnerability scanning | GitHub Actions after Docker build |
| `hadolint` | Dockerfile linting | GitHub Actions step |
| `npm audit` | Frontend dependency vulnerabilities | GitHub Actions step |
| `eslint-plugin-security` | Frontend security linting | Add to ESLint config |
| GitHub CodeQL | SAST (already partially configured) | Enhance existing workflow |

## OAuth2/OIDC Conformance Testing

| Tool | Purpose |
|------|---------|
| `oidc-conformance-suite` (OpenID Foundation) | Official OIDC provider conformance tests |
| Manual checklist against RFC 6749/7636 | Authorization Code + PKCE flow verification |

**Note:** Full OIDC conformance suite requires a running instance. For MVP, manual checklist + integration tests against RFC requirements is sufficient.

## Frontend Security

| Package | Purpose |
|---------|---------|
| `helmet` (via nginx) | Security headers (CSP, HSTS) — configured in nginx.conf, not React |
| Vite `build.sourcemap: false` | Disable source maps in production |
| SRI (Subresource Integrity) | Vite plugin `vite-plugin-sri` for script/style integrity hashes |

## What NOT to Add

| Don't Use | Why |
|-----------|-----|
| `actix-cors` wildcard | Already present but must be restrictive in production |
| `jsonwebtoken` for SAML | SAML uses XML signatures, not JWT |
| External WAF crate | Nginx/K8s ingress handles WAF at infrastructure level |
| `bcrypt` | Already using Argon2id which is superior (OWASP recommended) |
| Session crate (actix-session) | JWT-in-cookie is stateless; server-side sessions add complexity |
