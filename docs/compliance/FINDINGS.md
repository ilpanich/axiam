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

---

## Deferred Findings

No deferred findings from Phase 7 Plan 02.

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

*Last updated: Phase 7, Plan 02 — 2026-06-07*
