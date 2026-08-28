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
| F-02 | Playwright e2e/ files not covered by any tsconfig include | Info | N/A (IDE-only) | **Fixed** | Added `frontend/e2e/tsconfig.json` (`"types": ["node"]`, DOM lib) covering `e2e/**/*.ts` and `../playwright.config.ts`, so the IDE resolves `process` and Playwright/DOM types. It is not referenced by the root `tsconfig.json`, so `tsc -b`/CI behavior is unchanged. Issue: https://github.com/ilpanich/axiam/issues/98 |
| F-03 | Breach-password check (HIBP) not implemented | Low | ASVS V2.1.7 | **Fixed** | Implemented in a later hardening phase (this row was stale until 2026-08-28): `check_hibp` in `crates/axiam-auth/src/policy.rs` performs the k-anonymity range query (only a five-character SHA-1 prefix leaves the server), behind opt-in `hibp_*` configuration, with a circuit breaker (`crates/axiam-auth/src/hibp_breaker.rs`) so a HIBP outage can never block sign-up or password change. Issue #99 closed. |
| F-04 | TLS 1.3 minimum not explicitly enforced in Actix-Web / rustls config | Low | ASVS V9.1.2, V9.1.3 | **Fixed** | Proxy-terminated TLS remains the recommended pattern, now documented with a TLS 1.3-minimum proxy snippet (`docs/deployment/README.md`). Added an opt-in direct-TLS path: `server.tls.{enabled,cert_path,key_path}` (`crates/axiam-api-rest/src/config/mod.rs`) drives `axiam_server::tls::build_rustls_server_config`, which builds a rustls `ServerConfig` restricted to `TLS13` only (V9.1.3 satisfied — all TLS 1.3 suites are approved) and is bound via `bind_rustls_0_23`. Fails fast on cert/key misconfiguration (no insecure fallback). Issue: https://github.com/ilpanich/axiam/issues/100 |
| F-05 | Content-Security-Policy (CSP) header not set | Medium | ASVS V14.4.4 | **Fixed** | `SecurityHeadersMiddleware` (`crates/axiam-api-rest/src/middleware/security_headers.rs`) now sets `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'`, mirroring the frontend Nginx policy and covering both JSON responses and the same-origin Swagger UI (CSP-friendly in swagger-ui 5.x). Asserted in `crates/axiam-api-rest/tests/security_headers_test.rs`. Issue: https://github.com/ilpanich/axiam/issues/101 |
| SBOM-01 | No Software Bill of Materials (SBOM) generated for the Rust workspace or the frontend npm dependency tree | Info | CRA SBOM theme (net-new item raised by `claude_dev/security-audit.md` §7, not an ASVS 4.0.3 control) | **Fixed** | `.github/workflows/release.yml` gained a `sbom` job that runs on every `v*` release tag: `cargo cyclonedx` (pinned `0.5.9`, installed via `cargo install --locked`) emits one CycloneDX 1.5 JSON SBOM per Cargo workspace member, and `@cyclonedx/cyclonedx-npm` (pinned `1.20.0`, run via `npx`) emits one CycloneDX 1.5 JSON SBOM for `frontend/`'s npm dependency tree. Both are uploaded as the `sboms` build artifact and then attached as files on the GitHub Release created by the `release` job, alongside the existing binary tarballs — so every tagged release ships its SBOMs as downloadable, versioned artifacts. CycloneDX was chosen over SPDX because both ecosystems already have actively maintained, OWASP-native generators that install from the public crates.io/npm registries with no paid registry or license key, keeping the two SBOMs in one consistent format. No GitHub tracking issue was opened — the finding was fixed inline in the same pass it was raised (R5.10), not deferred. |

---

## Deferred Findings Summary

| # | Severity | Blocker for Beta? | Note |
|---|----------|-------------------|------|
| — | — | — | No deferred finding remains open |

F-02, F-04, and F-05 were resolved (see the Findings table above), and F-03
(HIBP breach-password check, issue #99) was subsequently implemented and its
issue closed — every finding in this register is now Fixed.

**No open deferred finding of any severity. Beta ships with no known High security holes (D-04).**

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
