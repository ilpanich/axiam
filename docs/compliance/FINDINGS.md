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
| F-02 | Playwright e2e/ files not covered by any tsconfig include | Info | N/A (IDE-only) | **Deferred** | `frontend/e2e/*.ts` and `playwright.config.ts` use `process.env` but are not in `tsconfig.app.json` or `tsconfig.node.json`. `@types/node` IS installed. Runtime unaffected (Playwright uses esbuild; `process` exists under Node). CI unaffected. IDE shows "Cannot find name 'process'". Suggested fix: add `frontend/e2e/tsconfig.json` extending root with `"types": ["node"]`. Non-blocking. PENDING (staged — create in Task 2) |
| F-03 | Breach-password check (HIBP) not implemented | Low | ASVS V2.1.7 | **Deferred** | `crates/axiam-auth/src/policy.rs:289` — comment notes HIBP as deferred. Argon2id verification is the primary defense; HIBP is defense-in-depth for known-breached passwords. To be implemented in a future security hardening phase. PENDING (staged — create in Task 2) |
| F-04 | TLS 1.3 minimum not explicitly enforced in Actix-Web / rustls config | Low | ASVS V9.1.2, V9.1.3 | **Deferred** | TLS termination is handled at the proxy layer (load balancer / Nginx/Caddy in production). Actix-Web with rustls supports TLS 1.3 by default. Enforcing TLS 1.3 minimum in code requires explicit rustls `ServerConfig` with `versions` filter. Low-priority for beta; acceptable to enforce at proxy. PENDING (staged — create in Task 2) |
| F-05 | Content-Security-Policy (CSP) header not set | Medium | ASVS V14.4.4 | **Deferred** | `SecurityHeadersMiddleware` in `crates/axiam-api-rest/src/middleware/security_headers.rs` sets `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` but not `Content-Security-Policy`. The REST API serves JSON only (no HTML from Rust); the frontend React SPA is served separately. XSS risk is limited because the admin UI does not render untrusted user content. Medium severity: should be added in a future phase. PENDING (staged — create in Task 2) |

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

## Proposed Issues (Staged for Task 2 Approval)

The following `gh issue create` commands are STAGED and must NOT be executed until the
human auditor approves at the Task 2 compliance checkpoint. Executing these is irreversible
(outward-facing GitHub issues cannot be un-created cleanly).

```bash
# F-02: Playwright tsconfig IDE issue
gh issue create \
  --title "[Compliance] Playwright e2e/ files not in tsconfig includes (IDE type error)" \
  --label "compliance,frontend,low" \
  --body "## Finding: F-02

**Severity:** Info (IDE-only, no CI/runtime impact)

**ASVS/RFC Ref:** N/A

**Description:**
frontend/e2e/*.ts and playwright.config.ts use process.env but the e2e/ directory
is not included in tsconfig.app.json or tsconfig.node.json. @types/node IS installed.

**Impact:** IDE shows \"Cannot find name 'process'\". No CI failure. No runtime failure.
Playwright uses esbuild which resolves process under Node.

**Suggested Fix:**
Add frontend/e2e/tsconfig.json extending the root tsconfig with \"types\": [\"node\"].

**Found during:** Phase 7, Plan 05 (2026-06-07)"

# F-03: HIBP breach-password check
gh issue create \
  --title "[Compliance] ASVS V2.1.7: HIBP breach-password check not implemented" \
  --label "compliance,security,low" \
  --body "## Finding: F-03

**Severity:** Low

**ASVS Ref:** V2.1.7

**Description:**
crates/axiam-auth/src/policy.rs:289 notes HIBP integration as deferred.
Users can set passwords that match known-breached credential lists.

**Impact:** Defense-in-depth gap only. Argon2id (primary protection) is implemented
per OWASP parameters. HIBP adds a secondary layer.

**Suggested Fix:**
Implement optional HIBP k-anonymity check in policy.rs password evaluation path.
Can be made opt-in via AuthConfig.

**Found during:** Phase 7, Plan 05 (2026-06-07)"

# F-04: TLS 1.3 minimum
gh issue create \
  --title "[Compliance] ASVS V9.1.2: TLS 1.3 minimum not enforced in rustls config" \
  --label "compliance,security,low" \
  --body "## Finding: F-04

**Severity:** Low

**ASVS Ref:** V9.1.2 (TLS 1.2+ minimum), V9.1.3 (approved cipher suites)

**Description:**
Actix-Web with rustls defaults to TLS 1.2+. The AXIAM server does not explicitly set
rustls::ServerConfig to restrict TLS versions to 1.3 minimum. TLS termination is
currently handled at the proxy layer (recommended deployment pattern).

**Impact:** In proxy-terminated deployments: no impact. In direct TLS: TLS 1.2 accepted.

**Suggested Fix:**
For the production TLS path in crates/axiam-server/src/main.rs, add explicit rustls
ServerConfig configured with TLS 1.3 only. Document proxy enforcement as supported pattern.

**Found during:** Phase 7, Plan 05 (2026-06-07)"

# F-05: Content-Security-Policy header
gh issue create \
  --title "[Compliance] ASVS V14.4.4: Content-Security-Policy header not set" \
  --label "compliance,security,medium" \
  --body "## Finding: F-05

**Severity:** Medium

**ASVS Ref:** V14.4.4

**Description:**
SecurityHeadersMiddleware (crates/axiam-api-rest/src/middleware/security_headers.rs)
sets X-Content-Type-Options, X-Frame-Options, and Referrer-Policy but not
Content-Security-Policy. The CSP header is a key defense against XSS.

**Impact:** REST API serves JSON only (no HTML); admin SPA is served separately.
XSS risk limited because admin UI does not render untrusted user content.
Medium-priority defense-in-depth gap.

**Suggested Fix:**
Add Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; to
SecurityHeadersMiddleware. For the frontend, configure a stricter CSP in Nginx or
via Vite build output headers.

**Found during:** Phase 7, Plan 05 (2026-06-07)"
```

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
