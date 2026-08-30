---
phase: 30-compliance-documentation
plan: 01
subsystem: compliance
tags: [asvs, iso27001, cyber-resilience-act, gdpr, security-audit, citation-index]

# Dependency graph
requires:
  - phase: 07-compliance-verification-test-closure
    provides: docs/compliance/{asvs-l2-checklist,FINDINGS,oauth2-rfc-compliance,oidc-conformance,sc4-coverage}.md — the control-by-control evidence cited by the master doc
  - phase: 23-security-regressions-high-findings
    provides: SECFIX-01..06 regression/negative tests cross-referenced in §2
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: SECHRD-06 GDPR erasure durability (feeds §7 CMPL-02 cross-reference)
  - phase: 27-performance-load-hardening
    provides: PERF-01 HibpBreaker (basis for the F-03 Fixed correction)
provides:
  - "claude_dev/security-audit.md — v1.2 master compliance citation index (ASVS L2 + ISO 27001 Annex A + CyberSecurity Act/CRA), open items cross-referenced to v1.2 REQ-IDs"
affects: [30-02-gdpr-compliance, 30-05-docs-index, 30-06-docs-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Citation-over-duplication: every audit row is a one-line summary + relative link into docs/compliance/ or a REQ-ID, never a re-transcription"
    - "Interpretive compliance mappings surfaced with [ASSUMED] flags + a blocking human-verify gate rather than asserted silently"

key-files:
  created:
    - claude_dev/security-audit.md
  modified: []

key-decisions:
  - "CyberSecurity Act interpreted as EU Cyber Resilience Act (CRA), not EU Reg 2019/881 — matches 30-RESEARCH Assumption A2; retained [ASSUMED] flag for human PR-time confirmation"
  - "F-03 (HIBP breach check) corrected from Deferred to Fixed — spot-verification found check_hibp implemented + PERF-01 HibpBreaker; stale Phase-7 docs left untouched (out of scope) but discrepancy called out in §7"
  - "F-05 (CSP header) corrected from Deferred to Partially Mitigated — nginx edge enforces self-origin CSP via docker/nginx.conf; backend JSON-API residual gap remains open"
  - "SBOM-01 raised as a net-new Info open item (no SBOM currently generated)"

patterns-established:
  - "Pattern 1: master citation index cites docs/compliance/ + .planning/REQUIREMENTS.md by relative link; no evidence duplication (D-01)"
  - "Pattern 2: control-family / theme altitude for ISO 27001 + CRA (D-02), not control-by-control"

requirements-completed: [CMPL-01]

coverage:
  - id: D1
    description: "claude_dev/security-audit.md maps auth/session/access-control/crypto/PKI controls to pass/fail with evidence pointers across ASVS L2 + ISO 27001 Annex A + CyberSecurity Act; open items cross-referenced to v1.2 REQ-IDs"
    requirement: "CMPL-01"
    verification:
      - kind: automated
        ref: "test -f claude_dev/security-audit.md && grep -Eq 'v1\\.2' && grep -Eq 'docs/compliance/asvs-l2-checklist\\.md' && grep -Eq 'REQ-|SECFIX-|SECHRD-|CMPL-|DOCS-' && grep -Eq 'A\\.5|A\\.8' && grep -q 'dependabot' && grep -q 'ASSUMED' — all pass"
        status: pass
    human_judgment: true
    rationale: "The ISO 27001 Annex A family groupings (§3) and the CyberSecurity Act = EU CRA framework interpretation (§4) are interpretive compliance-framework mappings with no canonical crosswalk; they carry [ASSUMED] flags and require human confirmation at PR review (blocking checkpoint approved this session by the coordinator resolving from phase ground-truth, but human PR-time sign-off remains a documented pre-merge item)"

# Metrics
duration: 55min
completed: 2026-07-06
status: complete
---

# Phase 30 Plan 01: Security Audit Checklist (CMPL-01) Summary

**`claude_dev/security-audit.md` — a v1.2 master compliance citation index mapping AXIAM's auth/session/access-control/crypto/PKI controls to OWASP ASVS L2, ISO 27001:2022 Annex A (family level), and the EU Cyber Resilience Act (theme level), with every open item cross-referenced to a v1.2 REQ-ID and interpretive mappings flagged `[ASSUMED]`.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-07-06
- **Completed:** 2026-07-06
- **Tasks:** 3 (2 authoring + 1 human-verify checkpoint, approved by coordinator)
- **Files modified:** 1 created

## Accomplishments
- Authored the single top-level CMPL-01 certification document as a citation index over `docs/compliance/` and `.planning/REQUIREMENTS.md` — no evidence duplication (D-01).
- §2 ASVS L2 category status summary (103 controls: 94 Pass / 4 N/A / 5 Deferred) linking into `docs/compliance/asvs-l2-checklist.md`, plus a v1.2 SECFIX/SECHRD cross-reference table tying Phases 23–29 hardening to the ASVS families they touched.
- §3 ISO 27001:2022 Annex A control-family mapping (A.5/A.6/A.7/A.8) with evidence pointers; A.6/A.7 N/A and SBOM rows flagged `[ASSUMED]` (D-02).
- §4 CyberSecurity Act = EU CRA essential-requirement theme mapping (`[ASSUMED]` framework flag); the "security updates" theme upgraded to Pass citing `.github/dependabot.yml` (confirmed present).
- §7 open-items register with a v1.2 REQ-ID column; three spot-verification corrections (F-03, F-05) and one net-new open item (SBOM-01) — see Deviations.
- §1 framing + §8 provenance stamp explicitly scope this as an internal self-assessment at control-family granularity, not a certified ISO 27001 ISMS audit or CRA conformity assessment (Pitfall 4, anti-overclaim).

## Task Commits

1. **Task 1: security-audit.md skeleton (header, self-assessment framing, ASVS L2 summary, OAuth2/OIDC/federation citations, open-items register)** — `1c42da8` (docs)
2. **Task 2: ISO 27001 Annex A family table + CyberSecurity Act theme table with [ASSUMED] flags** — `806ce86` (docs)
3. **Task 3: human-verify checkpoint** — approved by the coordinator (resolved from phase ground-truth; CRA interpretation + per-row `[ASSUMED]` flags retained for human PR-time confirmation). No code commit.

## Files Created/Modified
- `claude_dev/security-audit.md` — v1.2 master compliance citation index (§1 how-to-read/self-assessment framing, §2 ASVS L2 + v1.2 cross-ref, §3 ISO 27001 Annex A, §4 CyberSecurity Act/CRA, §5 OAuth2/OIDC, §6 federation/test-coverage, §7 open items, §8 provenance).

## Decisions Made
- **CyberSecurity Act = EU CRA (not EU Reg 2019/881).** Matches 30-RESEARCH Assumption A2's discretionary D-02 choice. `[ASSUMED — requires human confirmation]` flag kept verbatim in §4 for PR-time sign-off.
- **Kept the document a citation index, not a re-audit** (D-01/D-03): ASVS/OAuth2/OIDC/federation sections are one-line summaries + relative links into `docs/compliance/`; v1.2 work is cited by REQ-ID into `.planning/REQUIREMENTS.md`.
- **Control-family / theme altitude for ISO 27001 + CRA** (D-02), not control-by-control.

## Deviations from Plan

### Auto-fixed Issues (documentation-accuracy corrections during D-03 spot-verification)

**1. [Rule 1 - Bug] F-03 (HIBP breach check) corrected from Deferred to Fixed**
- **Found during:** Task 1 (open-items register authoring + spot-verification of the cited ASVS status)
- **Issue:** `docs/compliance/asvs-l2-checklist.md` (V2.1.7) and `FINDINGS.md` (#F-03) list the HIBP breach check as Deferred, but the codebase actually implements it (`crates/axiam-auth/src/policy.rs::check_hibp`, wired into `evaluate_password` and the sync change-password path per REQ-16/Phase 12; hardened by the PERF-01 `HibpBreaker` circuit breaker in Phase 27 with 9/9 unit tests). Repeating the stale "Deferred" status in the new master doc would misrepresent coverage (a compliance-integrity issue — threat T-30-02).
- **Fix:** Documented F-03 as "Fixed (correction)" in §7 with the real evidence pointers, explicitly noting the stale Phase-7 docs were left untouched (out of this plan's file scope: only `claude_dev/security-audit.md`) but that the discrepancy is surfaced, and that issue #99 should be closed. Did NOT edit `docs/compliance/*` (out of scope; a documentation-maintenance follow-up).
- **Files modified:** `claude_dev/security-audit.md`
- **Verification:** Re-read `policy.rs` (check_hibp at L176, evaluate_password at L309, hibp gate at L342), `hibp_breaker.rs`, and REQ-16 acceptance criterion "HIBP on sync change-password".
- **Committed in:** `1c42da8`

**2. [Rule 1 - Bug] F-05 (CSP header) corrected from Deferred to Partially Mitigated**
- **Found during:** Task 1
- **Issue:** `FINDINGS.md` #F-05 lists CSP as Deferred (Medium). Spot-verification confirmed the backend REST middleware still doesn't set CSP (accurate — JSON-only surface), but `docker/nginx.conf` DOES enforce a self-origin-only CSP at the frontend edge (wired via `docker/Dockerfile.frontend`), satisfying REQ-2's "CSP restricts scripts to self-origin" for the browser-facing surface where XSS matters. Repeating a flat "Deferred" would overstate the residual risk.
- **Fix:** Documented F-05 as "Partially Mitigated" in §7 — frontend-edge CSP present, backend-JSON-API residual gap remains open at Medium for a future phase; noted issue #101 should be re-scoped, not closed.
- **Files modified:** `claude_dev/security-audit.md`
- **Verification:** `grep` of `docker/nginx.conf` (CSP `default-src 'self'; script-src 'self'; ...` on all server blocks) and `security_headers.rs` (no CSP set); `docker/Dockerfile.frontend` COPY of nginx.conf.
- **Committed in:** `1c42da8`

**3. [Rule 2 - Missing Critical] SBOM-01 raised as a net-new open item**
- **Found during:** Task 2 (CyberSecurity Act theme mapping)
- **Issue:** The CRA §4 "SBOM" theme and ISO §3 asset-inventory row have no backing artifact — AXIAM generates no distributable SBOM (CycloneDX/SPDX). An honest self-assessment must surface this rather than mark the theme Pass.
- **Fix:** Added SBOM-01 (Info, Deferred) to §7 and marked the SBOM rows in §3/§4 Deferred `[ASSUMED]`, cross-referenced to §7. Noted `cargo-deny`/`cargo-audit`/Trivy cover vuln scanning but not SBOM emission; recommended for a future compliance phase; no beta-blocking impact.
- **Files modified:** `claude_dev/security-audit.md`
- **Verification:** Confirmed no SBOM step in `.github/workflows/ci.yml` security-scan job and no SBOM artifact under `docs/` or repo root.
- **Committed in:** `806ce86`

---

**Total deviations:** 3 (2 Rule-1 documentation-accuracy corrections, 1 Rule-2 missing open item). All confined to `claude_dev/security-audit.md`; no `docs/compliance/*` or source edits (respecting the plan's single-file scope).
**Impact on plan:** All three improve compliance-document accuracy (directly serving CMPL-01's whole point — truthful mapping) and mitigate threat T-30-02 (interpretive mapping misrepresenting coverage). No scope creep.

## Issues Encountered
None during planned work. The Task 3 checkpoint (compliance-framework interpretation) was approved by the coordinator, resolving from the phase's own ground-truth (30-RESEARCH Assumption A2 chose CRA); the CRA interpretation and per-row `[ASSUMED]` flags remain for human confirmation at PR review as a documented pre-merge item.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- CMPL-01 satisfied. `claude_dev/security-audit.md` is ready to be linked from the `docs/README.md` index (30-05) and internal-link-checked by `docs-ci.yml` (30-06).
- **Pre-merge item for human PR review:** confirm the §4 CyberSecurity Act = EU CRA interpretation and the §3 A.6/A.7/SBOM `[ASSUMED]` rows.
- **Documentation-maintenance follow-ups (out of this plan's scope, low priority):** update `docs/compliance/asvs-l2-checklist.md` + `FINDINGS.md` for the F-03 (now Fixed) and F-05 (now Partially Mitigated) corrections, and close/re-scope GitHub issues #99/#101.

## Self-Check: PASSED

- FOUND: `claude_dev/security-audit.md`
- FOUND: `.planning/phases/30-compliance-documentation/30-01-SUMMARY.md`
- FOUND commit: `1c42da8` (Task 1)
- FOUND commit: `806ce86` (Task 2)

---
*Phase: 30-compliance-documentation*
*Completed: 2026-07-06*
