# AXIAM Security Audit — v1.2 Beta

**Standard:** OWASP ASVS v4.0.3 (Level 2), ISO/IEC 27001:2022 Annex A, EU Cyber
Resilience Act (CRA) essential requirements — see §4 for the framework choice.

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Date:** 2026-07-06
**Commit reviewed:** `c79b66e`
**Last verified:** 2026-07-06
**Scope:** Authentication, session management, access control, cryptography, and PKI
controls across `crates/axiam-auth`, `crates/axiam-authz`, `crates/axiam-pki`,
`crates/axiam-federation`, `crates/axiam-api-rest`, `crates/axiam-api-grpc`,
`crates/axiam-amqp`, and the deployment surface (`docker/`, `k8s/`).

**Out of scope:** A control-by-control (93-control) ISO 27001 ISMS certification
audit, a formal external CyberSecurity Act conformity assessment, and re-running
tests that Phases 7 and 23–29 already prove (see §1). This document performs a
spot-verification pass (D-03), not a fresh full re-audit.

**Status values:** Pass / N/A / Partial / Deferred — every applicable row below
carries one of these plus an evidence pointer.

**Compliance assertion:** All in-scope control families and themes below have an
explicit status. No High or Critical severity item is open (see §7).

---

## 1. How to Read This Document

This document is a **master citation index**, not a second copy of the detailed
evidence. It maps AXIAM's authentication, session, access-control, cryptography,
and PKI controls to OWASP ASVS L2, ISO 27001 Annex A, and the CyberSecurity Act,
with pass/fail status and an evidence **pointer** — a link into
`docs/compliance/`, a `REQUIREMENTS.md` requirement ID, or a source/test file
path. It does not re-run tests or re-transcribe control text; it cites where the
proof already lives (D-01, D-03).

**This is an internal self-assessment at control-family granularity, not a
certified ISO 27001 ISMS audit and not a CyberSecurity Act conformity
assessment.** AXIAM has not engaged an accredited external auditor or
certification body. The ASVS section (§2) is the one part of this document
backed by a control-by-control checklist (`docs/compliance/asvs-l2-checklist.md`,
produced in Phase 7); the ISO 27001 and CyberSecurity Act sections (§3, §4) are
this project's own interpretive mapping at control-family / theme altitude,
appropriate for an IAM MVP beta and explicitly **not** equivalent to a
certifiable ISMS audit (D-02). Interpretive rows are flagged `[ASSUMED]` and
require human confirmation before being treated as final (see the Task 3
checkpoint in `.planning/phases/30-compliance-documentation/30-01-PLAN.md`).

The evidence trail this document cites is:
- `docs/compliance/asvs-l2-checklist.md`, `FINDINGS.md`, `oauth2-rfc-compliance.md`,
  `oidc-conformance.md`, `sc4-coverage.md` — Phase 7 compliance-verification
  artifacts.
- `.planning/REQUIREMENTS.md` — the v1.2 SECFIX/SECHRD/CORR/PERF/FUNC/QUAL
  requirement register (44 REQ-IDs), each with acceptance criteria checked off
  against a regression test.
- Phase 23–29 validation/verification artifacts (`.planning/phases/2{3..9}-*/`)
  — each phase's Success Criteria were proven in-code with a negative test where
  security-relevant (D-03).

Where this audit's spot-verification (D-03) found that cited evidence had gone
stale since Phase 7, the discrepancy is called out explicitly in §7 rather than
silently repeated — see F-03 and F-05 corrections.

---

## 2. OWASP ASVS Level 2 — Status Summary

Full control-by-control checklist: [`docs/compliance/asvs-l2-checklist.md`](../docs/compliance/asvs-l2-checklist.md).

| Category | Total | Pass | N/A | Deferred | Section |
|----------|------:|-----:|----:|---------:|---------|
| V2 (Authentication) | 23 | 20 | 2 | 1 | [`asvs-l2-checklist.md#v2--authentication-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v2--authentication-verification-requirements) |
| V3 (Session Management) | 15 | 15 | 0 | 0 | [`asvs-l2-checklist.md#v3--session-management-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v3--session-management-verification-requirements) |
| V4 (Access Control) | 9 | 8 | 1 | 0 | [`asvs-l2-checklist.md#v4--access-control-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v4--access-control-verification-requirements) |
| V6 (Stored Cryptography) | 14 | 14 | 0 | 0 | [`asvs-l2-checklist.md#v6--stored-cryptography-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v6--stored-cryptography-verification-requirements) |
| V7 (Error Handling / Logging) | 7 | 7 | 0 | 0 | [`asvs-l2-checklist.md#v7--error-handling-and-logging-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v7--error-handling-and-logging-verification-requirements) |
| V8 (Data Protection) | 8 | 8 | 0 | 0 | [`asvs-l2-checklist.md#v8--data-protection-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v8--data-protection-verification-requirements) |
| V9 (Communications) | 6 | 4 | 0 | 2 | [`asvs-l2-checklist.md#v9--communications-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v9--communications-verification-requirements) |
| V10 (Malicious Code) | 8 | 7 | 1 | 0 | [`asvs-l2-checklist.md#v10--malicious-code-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v10--malicious-code-verification-requirements) |
| V14 (Configuration) | 13 | 11 | 0 | 2 | [`asvs-l2-checklist.md#v14--configuration-verification-requirements`](../docs/compliance/asvs-l2-checklist.md#v14--configuration-verification-requirements) |
| **Total** | **103** | **94** | **4** | **5** | — |

**No Deferred row has High or Critical severity** (`asvs-l2-checklist.md` Summary).
All Deferred rows are cross-referenced to `FINDINGS.md` and re-examined in §7 of
this document, including one correction found during this audit's spot-verify pass.

### v1.2 Regression & Hardening Cross-Reference

The Phase-7 checklist above predates the v1.2 milestone (Phases 23–29). The
following v1.2 requirements touched ASVS-relevant control families; each was
closed with an acceptance-criteria checklist and a regression/negative test
(see `.planning/REQUIREMENTS.md` for full text and file:line evidence):

| REQ-ID | ASVS Family Touched | Summary | Evidence |
|--------|---------------------|---------|----------|
| SECFIX-01 | V4 (Access Control) | gRPC `UserService`/`TokenService` now enforce `AuthInterceptor`; identity derived from verified JWT claims, not request body | `.planning/REQUIREMENTS.md#secfix-01-grpc-userservice--tokenservice-authentication` |
| SECFIX-02 | V4 (Access Control) | Tenant guard applied to the live REST scoped-permission-grant path (`grant_to_role_with_scopes`) | `.planning/REQUIREMENTS.md#secfix-02-tenant-guard-on-live-rest-grant-path` |
| SECFIX-03 | V6 (Stored Cryptography) | Removed all-zero webhook-secret encryption-key fallback; fail-closed + encrypt-at-rest | `.planning/REQUIREMENTS.md#secfix-03-webhook-secret--fail-closed-key--encrypt-at-rest` |
| SECFIX-04 | V2 (Authentication) | SAML XML Signature Wrapping closed — signature bound to the consumed assertion; `Destination`/`InResponseTo` validated on the authenticated ACS path | `.planning/REQUIREMENTS.md#secfix-04-saml-signature-to-assertion-binding` |
| SECFIX-05 | V3 (Session Management) | Logout derives session from JWT `jti`; all cookies cleared server-side | `.planning/REQUIREMENTS.md#secfix-05-logout-revokes-the-callers-session` |
| SECFIX-06 | V2 (Authentication) | Password-reset/resend flows correctly threaded with `tenant_id`; enumeration-safe | `.planning/REQUIREMENTS.md#secfix-06-password-reset--resend-flows-threaded-with-tenant_id` |
| SECHRD-01 | V2 (Authentication) | TOTP step check-and-update made atomic (CAS); replay window closed | `.planning/REQUIREMENTS.md#sechrd-01-totp-atomic-replay-protection` |
| SECHRD-02 | V9 (Communications) | SSRF address pinning extended to all federation outbound fetches (discovery, token, SAML metadata), not just JWKS | `.planning/REQUIREMENTS.md#sechrd-02-ssrf-address-pinning-webhook--federation-fetches` |
| SECHRD-03 | V2 (Authentication) | XFF client-IP-keying fix; multi-replica shared rate-limit store | `.planning/REQUIREMENTS.md#sechrd-03-rate-limit-client-ip-keying` |
| SECHRD-04 | V2 (Authentication) | Bootstrap TOCTOU closed; single-admin invariant proven under concurrency | `.planning/REQUIREMENTS.md#sechrd-04-bootstrap-atomicity--mandatory-gate` |
| SECHRD-05 | V2/V6 (mTLS/PKI) | Issuing CA `Active` + validity-window check added before trusting a device cert | `.planning/REQUIREMENTS.md#sechrd-05-mtls-ca-status-and-validity-enforcement` |
| SECHRD-06 | V8 (Data Protection) | GDPR erasure durability + ledger integrity — see §7 CMPL-02 cross-reference below | `.planning/REQUIREMENTS.md#sechrd-06-gdpr-erasure-durability--ledger-integrity` |
| SECHRD-07 | V2 (Authentication) | Account-linking OIDC nonce derived from server-side state, not request body | `.planning/REQUIREMENTS.md#sechrd-07-federation-nonce-from-server-state-authenticated-path` |
| SECHRD-08 | V6 (Stored Cryptography) | AMQP signing key mandatory + per-tenant HKDF-derived subkey in production | `.planning/REQUIREMENTS.md#sechrd-08-amqp-signing-key--exportready-delivery` |
| SECHRD-09 | V6/V8 | Federation/PKI secrets excluded from `serde`/`Debug` serialization | `.planning/REQUIREMENTS.md#sechrd-09-federation-secret-non-serialization` |
| SECHRD-11 | V4 (Access Control) | Public-path allowlist requires a segment boundary; path normalized before the check | `.planning/REQUIREMENTS.md#sechrd-11-public-path-allowlist-hardening` |
| SECHRD-12 | V2/V6 | Constant-time password-reset path; peppered-password buffer zeroized; GDPR audit-write dead-letter fallback | `.planning/REQUIREMENTS.md#sechrd-12-auth-crypto--recovery-side-channels` |

All items above are marked complete (`[x]`) in `.planning/REQUIREMENTS.md` with
file:line evidence and a regression/negative test per requirement; this audit
spot-verified a representative sample (SECFIX-04 SAML XSW test, SECHRD-01 TOTP
CAS test, SECHRD-06 erasure-pipeline test — see §6) rather than re-running the
full v1.2 suite (D-03).

---

## 3. ISO 27001 Annex A — Control-Family Mapping

**[ASSUMED]** No canonical OWASP ASVS ↔ ISO 27001 crosswalk document exists;
the family groupings below are this project's own interpretive mapping at
control-family altitude (D-02), built from the ISO 27001:2022 Annex A structure
(4 themes, 93 controls: A.5 Organizational (37), A.6 People (8), A.7 Physical
(14), A.8 Technological (34)) cross-referenced against AXIAM's actual control
surface. **A human reviewer must confirm this mapping before it is treated as
final** (see the Task 3 checkpoint).

| Annex A Family | Theme | Applies to AXIAM | Status | Evidence Pointer |
|-----------------|-------|-------------------|--------|-------------------|
| A.5.15–5.18 (access control, identity mgmt, authn info, access rights) | Organizational | Yes | Pass | `crates/axiam-authz` RBAC engine; ASVS V4 rows (§2); `.planning/REQUIREMENTS.md#req-4-rbac-enforcement` |
| A.5 (remaining: supplier/asset mgmt, incident mgmt process) | Organizational | Partial | Partial | No formal supplier-risk or incident-response *process* documentation exists yet beyond `FINDINGS.md`'s ad-hoc tracking-issue workflow; code-level controls (A.5.15–5.18) are covered above |
| A.6 (screening, responsibilities, training, disciplinary process) | People | N/A `[ASSUMED]` | N/A | Organizational/HR controls outside the codebase's verifiable scope for a self-assessment — not code-verifiable; human reviewer should confirm this is an acceptable N/A for a beta-stage self-assessment |
| A.7 (physical/environmental security) | Physical | N/A `[ASSUMED]` | N/A | AXIAM is a containerized/Kubernetes-deployed application; physical facility security is the cloud/infrastructure provider's responsibility, not AXIAM's codebase |
| A.8.2–8.3 (privileged access rights, information access restriction) | Technological | Yes | Pass | RBAC default-deny (`axiam-authz`); admin bootstrap gate (SECHRD-04); ASVS V4.1.1/V4.3.1 (§2) |
| A.8.5 (secure authentication) | Technological | Yes | Pass | Argon2id (V2.4.1), MFA/TOTP (V2.8.1), mTLS device auth (V2.9.1/V2.9.2) — see §2 V2 rows |
| A.8.9–8.11 (configuration management, information deletion, data masking) | Technological | Yes | Pass | GDPR erasure/pseudonymization (SECHRD-06, §7); K8s `ConfigMap`/`Secret` separation (`k8s/server/secret.yml`) |
| A.8.12 (data leakage prevention) | Technological | Yes | Pass | Encrypted-at-rest secrets (MFA/federation/PKI/webhook keys — SECFIX-03, SECHRD-08/09); no secrets in `Debug`/serialized output (SECHRD-09) |
| A.8.15–8.16 (logging, monitoring) | Technological | Yes | Pass | `crates/axiam-audit` append-only audit log; ASVS V7 rows (§2) |
| A.8.20–8.23 (network security, segregation, secure coding) | Technological | Yes | Pass | K8s default-deny NetworkPolicies (`k8s/network-policy/`, SECHRD-10); TLS at ingress; ASVS V9/V14 rows (§2) |
| A.8.24 (cryptography) | Technological | Yes | Pass | Argon2id, AES-256-GCM, Ed25519/EdDSA JWT, X.509 PKI — ASVS V6/V8 rows (§2) |
| A.8.25–8.29 (secure development lifecycle, security testing) | Technological | Yes | Pass | CI security-scan job — `cargo audit`, `cargo deny`, Trivy fs/config scan, `npm audit` (`.github/workflows/ci.yml`); ASVS V10 rows (§2) |
| A.8.32–8.34 (change management, capacity management, audit testing) | Technological | Partial | Partial | CI/CD pipeline (`ci.yml`, `release.yml`, SHA-pinned actions) covers change control; capacity management is out of scope for MVP beta; audit testing = this document + `docs/compliance/` |
| A.5 SBOM / asset inventory | Organizational/Technological | Deferred `[ASSUMED]` | Deferred | No SBOM is currently generated. Tracked as an open item in §7 (cross-referenced to a v1.2 REQ-ID) |

**A human reviewer must confirm:** the A.6/A.7 N/A dispositions, the A.8.5 vs
A.8.24 sub-control groupings, and the SBOM deferral, before this table is
treated as a final self-assessment (RESEARCH.md Assumption A1).

---

## 4. CyberSecurity Act — Essential-Requirement Theme Mapping

**[ASSUMED — requires human confirmation]** "CyberSecurity Act" is interpreted
here as the **EU Cyber Resilience Act (CRA)** — the current EU framework
setting essential cybersecurity requirements for products with digital elements
(Annex I) — rather than EU Regulation 2019/881 (the ENISA Cybersecurity Act,
which establishes the EU cybersecurity certification framework/agency mandate
but does not itself impose product-level essential requirements). AXIAM, as a
product with digital elements, is more directly addressed by the CRA's Annex I
essential requirements. **If this interpretation is incorrect for AXIAM's
intended regulatory context, the theme table below must be re-anchored against
Regulation 2019/881 instead** (RESEARCH.md Assumption A2).

| CRA/CSA Theme | Applies to AXIAM | Status | Evidence Pointer |
|---------------|-------------------|--------|--------------------|
| Secure-by-design & default configuration | Yes | Pass | Default-deny RBAC (`axiam-authz`); fail-closed encryption-key handling (SECFIX-03, no `unwrap_or([0u8;32])` fallback); cookie-based auth secure defaults (§2 V3) |
| No known exploitable vulnerabilities | Yes | Pass | `cargo audit` + `cargo deny` + Trivy (fs/config, HIGH/CRITICAL gate) + `npm audit` — `.github/workflows/ci.yml`; ASVS V10.3 rows (§2) |
| Confidentiality of stored/transmitted data | Yes | Pass | AES-256-GCM at rest (MFA/CA/webhook secrets); TLS at ingress; GDPR export encryption (§7 CMPL-02) |
| Data minimization | Yes | Pass | GDPR export excludes `password_hash`/`mfa_secret`/token hashes/`passkey_json` — `crates/axiam-server/src/cleanup.rs::aggregate_export_data` |
| Access control / authentication | Yes | Pass | Same evidence as ASVS V2/V4 (§2) and A.5.15–5.18 (§3) |
| Vulnerability handling process | Yes | Pass | `docs/compliance/FINDINGS.md` inline-fix-vs-defer register with GitHub tracking issues (#98–#101); each Deferred finding has a rationale and an issue link |
| Security updates | Yes | Pass | `.github/dependabot.yml` — weekly automated dependency updates across 3 ecosystems (cargo, npm, github-actions), grouped minor/patch. This resolves the "Partial" status carried in earlier research; dependabot is confirmed present and configured. |
| SBOM | Deferred `[ASSUMED]` | Deferred | No SBOM currently generated for AXIAM's dependency tree. Cross-referenced as an open item in §7 |

**A human reviewer must confirm** the CRA-vs-2019/881 framework interpretation
above before this table is treated as final.

---

## 5. OAuth2 / OIDC Conformance

Full RFC MUST-matrices: [`docs/compliance/oauth2-rfc-compliance.md`](../docs/compliance/oauth2-rfc-compliance.md)
and [`docs/compliance/oidc-conformance.md`](../docs/compliance/oidc-conformance.md).

AXIAM's OAuth2 authorization server and OIDC provider pass all 30 tracked MUST
requirements across RFC 6749 (Authorization Framework), RFC 7636 (PKCE), RFC
7009 (Token Revocation), and RFC 7662 (Token Introspection) — including PKCE
S256-only enforcement, single-use authorization codes, refresh-token rotation
with client binding, and `WWW-Authenticate` on 401 responses (F-01, Fixed in
Phase 7). OIDC Core 1.0 and Discovery 1.0 conformance (22 tracked MUST
requirements) includes `alg:none` rejection at both the token-endpoint and
service layer, `id_token` issuer/audience/nonce validation, and Ed25519/EdDSA
signing exclusively — no HS256/RS256 downgrade path exists. Both matrices are
backed by dedicated conformance test suites
(`crates/axiam-api-rest/tests/oauth2_conformance.rs`,
`crates/axiam-api-rest/tests/oidc_conformance.rs`) plus the broader
`oauth2_flow_test.rs` (37 tests) and `req5_oidc_e2e.rs` service-layer suite.
No open findings in this area.

---

## 6. Federation / Test-Coverage Cross-Reference

Full citation table: [`docs/compliance/sc4-coverage.md`](../docs/compliance/sc4-coverage.md).

REQ-11 (Testing Gaps) is satisfied for every security-sensitive crate area:
the RBAC engine (14 tests, `axiam-authz/tests/authz_engine_test.rs`), OIDC
federation (12 tests, `req5_oidc_e2e.rs`), SAML federation (6 tests,
`req5_saml_e2e.rs`), RBAC middleware enforcement (7 tests, `rbac_test.rs`),
cookie-based auth (16 tests, `auth_test.rs`), and GDPR data lifecycle (4 tests,
`gdpr_test.rs`) — all cited with file:line evidence in `sc4-coverage.md`. Phase
7 added PKI (`ca_test.rs`, `cert_test.rs`, `mtls_test.rs`, `pgp_test.rs`), gRPC
authz (`grpc_authz_test.rs`), and Playwright e2e coverage (11 specs).

Phase 23–29 validation/verification artifacts extend this trail for the v1.2
regression and hardening work summarized in §2's cross-reference table:

| Phase | Scope | Artifact |
|-------|-------|----------|
| 23 | Security regressions (SECFIX-01..06) | `.planning/phases/23-security-regressions-high-findings/23-VALIDATION.md` |
| 24 | Auth/access-control hardening (SECHRD-01,03,04,07,11,12) | `.planning/phases/24-security-hardening-i-authentication-access-control-surfaces/24-VERIFICATION.md` |
| 25 | Federation/PKI/data/infra hardening (SECHRD-02,05,06,08,09,10) | `.planning/phases/25-security-hardening-ii-federation-pki-data-protection-infra/25-VERIFICATION.md` |
| 26 | Correctness & resilience | `.planning/phases/26-correctness-resilience/26-VERIFICATION.md` |
| 27 | Performance/load hardening (incl. PERF-01 HIBP breaker) | `.planning/phases/27-performance-load-hardening/27-VERIFICATION.md` |
| 28 | Functional completeness | `.planning/phases/28-functional-completeness/28-VERIFICATION.md` |
| 29 | Structural quality | `.planning/phases/29-structural-quality/29-VERIFICATION.md` |

This audit spot-verified (D-03) the following representative sample rather than
re-running the full suite: `req5_saml_e2e.rs::saml_rejects_xsw_wrapped_assertion`
(SECFIX-04), `totp_step_cas_test.rs::totp_step_cas_concurrent` (SECHRD-01), and
`gdpr_test.rs::deletion_pseudonymization` / the erasure-pipeline fatal-failure
test (SECHRD-06) — all present in the codebase at the cited paths with the
described assertions.

---

## 7. Open Items / Deferred Findings

Reuses the `docs/compliance/FINDINGS.md` row shape, adding a v1.2 REQ-ID column
so every open/deferred item is cross-referenced to this milestone's
requirement register (or its originating pre-v1.2 requirement where no v1.2
work touched it).

| # | Finding | Severity | Ref | Status | v1.2 REQ-ID | Disposition |
|---|---------|----------|-----|--------|-------------|-------------|
| F-02 | Playwright `e2e/` files not covered by any `tsconfig` include | Info | N/A (IDE-only) | Deferred | REQ-11 (origin) | Re-verified 2026-07-06: `frontend/tsconfig.app.json`/`tsconfig.node.json` still do not include `frontend/e2e/`. Cosmetic IDE-only issue; CI unaffected (Playwright runs via esbuild). Issue #98 still open. |
| F-03 | Breach-password check (HIBP) not implemented | Low | ASVS V2.1.7 | **Fixed (correction)** | REQ-16 (Phase 12), hardened by PERF-01 (Phase 27) | **This audit's spot-verification (D-03) found F-03 is stale.** `crates/axiam-auth/src/policy.rs::check_hibp` implements the k-Anonymity HIBP API check, gated by `PasswordPolicy.hibp_check_enabled` and wired into `evaluate_password` (called from the sync change-password path, `handlers/users.rs`, per REQ-16 acceptance criterion "HIBP on sync change-password"). PERF-01 (Phase 27) added `HibpBreaker`, a process-wide circuit breaker around the outbound HTTP call (9/9 unit tests, `hibp_breaker.rs`). `docs/compliance/asvs-l2-checklist.md` (V2.1.7) and `FINDINGS.md` (#F-03) still show this as Deferred and should be updated by a documentation-maintenance follow-up — tracked here rather than silently re-asserted (CMPL-01 self-reference). Issue #99 should be closed. |
| F-04 | TLS 1.3 minimum / cipher suite not explicitly enforced in Actix-Web/rustls config | Low | ASVS V9.1.2, V9.1.3 | Deferred | REQ-11 (origin); no v1.2 REQ-ID remediates this | Re-verified 2026-07-06: `docker/nginx.conf` (frontend edge) sets no `ssl_protocols`/`ssl_ciphers` directives; TLS termination remains a proxy/ingress-layer responsibility (k8s ingress, out of AXIAM's application code). Still low severity, still acceptable for beta. Issue #100 still open. |
| F-05 | Content-Security-Policy (CSP) header not set by the backend | Medium | ASVS V14.4.4 | **Partially mitigated** | REQ-2 (origin, Phase 2); no v1.2 REQ-ID | Re-verified 2026-07-06: `crates/axiam-api-rest/src/middleware/security_headers.rs` still does not set `Content-Security-Policy` (REST API is JSON-only — FINDINGS.md's original rationale holds for this layer). However, **CSP IS enforced at the frontend edge**: `docker/nginx.conf` sets `Content-Security-Policy: default-src 'self'; script-src 'self'; ...` (self-origin only, no inline/eval scripts for the SPA shell), wired into production via `docker/Dockerfile.frontend` (`COPY docker/nginx.conf /etc/nginx/conf.d/default.conf`) — this satisfies REQ-2's "CSP policy restricts scripts to self-origin" acceptance criterion for the browser-facing surface where XSS actually matters. The backend-JSON-API residual gap remains open at Medium severity for a future phase. Issue #101 should be re-scoped, not closed. |
| SBOM-01 | No Software Bill of Materials generated | Info | CRA SBOM theme (§4) | Deferred | Not tracked under any existing v1.2 REQ-ID; net-new open item raised by this audit (CMPL-01 self-reference) | `cargo-deny`/`cargo-audit`/Trivy (§2 V10, §4 "no known exploitable vulnerabilities") cover dependency vulnerability scanning but do not emit a distributable SBOM artifact (e.g., CycloneDX/SPDX). Recommended for a future documentation/compliance phase; no beta-blocking impact. |

**No open item carries High or Critical severity.** All four inherited Phase-7
findings (F-02, F-03, F-04, F-05) were re-examined against current code as part
of this audit's spot-verification pass rather than re-asserted verbatim — one
(F-03) is corrected to Fixed, one (F-05) is corrected to Partially Mitigated,
and two (F-02, F-04) are confirmed still accurately Deferred. One new item
(SBOM-01) is raised directly by this audit's §3/§4 mapping work.

---

## 8. Version & Provenance

- **Milestone:** v1.2 (MVP Release Hardening) — **Beta**. This document
  describes the beta state of AXIAM as of the commit below; it is not a
  point-in-time-frozen certification and should be re-verified at the next
  milestone or whenever a control cited above materially changes.
- **Date:** 2026-07-06
- **Commit reviewed:** `c79b66e`
- **Last verified:** 2026-07-06
- **Method:** Citation-index aggregation over `docs/compliance/` (Phase 7) and
  `.planning/REQUIREMENTS.md` (v1.2, Phases 23–29), with a representative
  spot-verification sample (D-03) re-read against current source — not a full
  fresh re-audit.
- **Author:** GSD executor agent, Phase 30 Plan 01 (CMPL-01), per
  `.planning/phases/30-compliance-documentation/30-01-PLAN.md`.
- **Pending human confirmation:** the §3 ISO 27001 Annex A family groupings,
  the §4 CyberSecurity Act = EU CRA framework interpretation, and the §1
  self-assessment framing (no over-claiming) — see the blocking
  `checkpoint:human-verify` gate in the owning plan.
