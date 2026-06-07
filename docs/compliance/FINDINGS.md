# Compliance Findings Register

**Purpose:** Inline-fix-vs-defer decision register (D-05). Records every compliance gap
found during Phase 7 verification, its disposition, and remediation outcome.

**Schema:** Each row is one finding. Status is either Fixed (with commit) or Deferred
(with rationale and tracking issue).

---

## Findings

| # | Finding | Severity | ASVS / RFC Ref | Status | Disposition |
|---|---------|----------|---------------|--------|-------------|
| F-01 | WWW-Authenticate header absent on 401 invalid_client responses from /oauth2/token | Low | RFC 6749 §5.2 | **Fixed** | Inline fix (D-04) in `build_oauth2_error_response` — added `WWW-Authenticate: Bearer realm="axiam"` on all 401 responses. Phase 7 Plan 02 commit 20c8174. |
| F-02 | Playwright e2e/ files not covered by any tsconfig include | Info | N/A (IDE-only) | **Deferred** | `frontend/e2e/*.ts` and `playwright.config.ts` use `process.env` but are not in `tsconfig.app.json` or `tsconfig.node.json`. `@types/node` IS installed. Runtime unaffected (Playwright uses esbuild; `process` exists under Node). CI unaffected. IDE shows "Cannot find name 'process'". Suggested fix: add `frontend/e2e/tsconfig.json` extending root with `"types": ["node"]`. Non-blocking. Issue: https://github.com/ilpanich/axiam/issues/98 |
| F-03 | Breach-password check (HIBP) not implemented | Low | ASVS V2.1.7 | **Deferred** | `crates/axiam-auth/src/policy.rs:289` — comment notes HIBP as deferred. Argon2id verification is the primary defense; HIBP is defense-in-depth for known-breached passwords. To be implemented in a future security hardening phase. Issue: https://github.com/ilpanich/axiam/issues/99 |
| F-04 | TLS 1.3 minimum not explicitly enforced in Actix-Web / rustls config | Low | ASVS V9.1.2, V9.1.3 | **Deferred** | TLS termination is handled at the proxy layer (load balancer / Nginx/Caddy in production). Actix-Web with rustls supports TLS 1.3 by default. Enforcing TLS 1.3 minimum in code requires explicit rustls `ServerConfig` with `versions` filter. Low-priority for beta; acceptable to enforce at proxy. Issue: https://github.com/ilpanich/axiam/issues/100 |
| F-05 | Content-Security-Policy (CSP) header not set | Medium | ASVS V14.4.4 | **Deferred** | `SecurityHeadersMiddleware` in `crates/axiam-api-rest/src/middleware/security_headers.rs` sets `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` but not `Content-Security-Policy`. The REST API serves JSON only (no HTML from Rust); the frontend React SPA is served separately. XSS risk is limited because the admin UI does not render untrusted user content. Medium severity: should be added in a future phase. Issue: https://github.com/ilpanich/axiam/issues/101 |

---

## Deferred Findings Summary

| # | Severity | Blocker for Beta? | Note |
|---|----------|-------------------|------|
| F-02 | Info | No | IDE cosmetic only |
| F-03 | Low | No | Defense-in-depth; Argon2id is primary defense |
| F-04 | Low | No | Proxy-layer enforcement acceptable |
| F-05 | Medium | No | No untrusted HTML rendering in admin UI scope |

**No High or Critical deferred finding. Beta ships with no known High security holes (D-04).**

---

## Tracking Issues (Created Phase 7 Plan 05 — after human sign-off)

| # | GitHub Issue |
|---|--------------|
| F-02 | https://github.com/ilpanich/axiam/issues/98 |
| F-03 | https://github.com/ilpanich/axiam/issues/99 |
| F-04 | https://github.com/ilpanich/axiam/issues/100 |
| F-05 | https://github.com/ilpanich/axiam/issues/101 |

All four `compliance`-labeled tracking issues were created only after the auditor approved
the deferred-findings set at the Task 2 checkpoint (T-07-18 mitigation).

---

## Schema Reference

| Column | Description |
|--------|-------------|
| # | Sequential finding ID (F-NN) |
| Finding | Short description of the gap |
| Severity | Critical / High / Medium / Low / Info |
| ASVS / RFC Ref | Controlling standard reference (ASVS control ID or RFC section) |
| Status | Fixed / Deferred |
| Disposition | For Fixed: what was done + commit. For Deferred: rationale + issue link |

**Severity guidance:**
- **Critical** — active exploitation path; blocks release
- **High** — significant security gap; must fix before production
- **Medium** — RFC non-compliance or defense-in-depth gap
- **Low** — cosmetic non-compliance; no security impact
- **Info** — observation only; no action required

---

*Last updated: Phase 7, Plan 05 — 2026-06-07*
