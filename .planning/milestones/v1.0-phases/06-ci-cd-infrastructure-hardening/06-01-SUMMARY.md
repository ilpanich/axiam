---
phase: 06-ci-cd-infrastructure-hardening
plan: 01
subsystem: infra
tags: [cargo-deny, cargo-audit, npm-audit, trivy, hadolint, codeql, sarif, dependabot, ci-cd, license, security-scan]

# Dependency graph
requires:
  - phase: 05-email-delivery-gdpr-compliance
    provides: stable codebase with clean build; no regression baseline

provides:
  - deny.toml cargo-deny policy (advisories/licenses/bans/sources)
  - .github/dependabot.yml (cargo + npm + github-actions weekly grouped updates)
  - security-scan CI job (cargo-audit, cargo-deny, npm audit, hadolint, trivy fs/config + SARIF upload)
  - .hadolint.yaml Dockerfile lint config
  - Apache-2.0 license metadata in Cargo.toml and frontend/package.json
  - Remediated Cargo.lock (hickory-proto, rustls-webpki, lettre, rustls patched)
  - Remediated frontend/package-lock.json (react-router-dom, vite patched)

affects: [06-02, 06-03, 06-04, 06-05, ci-cd, release, all future plans touching deps]

# Tech tracking
tech-stack:
  added:
    - cargo-deny (workspace advisory/license/bans/sources policy via deny.toml)
    - EmbarkStudios/cargo-deny-action@v2 (CI)
    - actions-rust-lang/audit@v1 (CI cargo-audit)
    - hadolint/hadolint-action@v3.1.0 (CI Dockerfile lint)
    - aquasecurity/trivy-action@v0.36.0 (CI fs + config scan)
    - github/codeql-action/upload-sarif@v4 (SARIF → GitHub Security tab)
  patterns:
    - SARIF-upload pattern for every scan tool (distinct category per tool)
    - Documented deny.toml ignore entries (id + reason + review date) for no-fix advisories
    - License exceptions with rationale for BUSL-1.1 (surrealdb), GPL-3.0 (actix-governor), bzip2 (libbz2-rs-sys)

key-files:
  created:
    - deny.toml
    - .hadolint.yaml
    - .github/dependabot.yml
  modified:
    - Cargo.toml (license AGPL-3.0-or-later → Apache-2.0)
    - frontend/package.json (added "license": "Apache-2.0")
    - .github/workflows/ci.yml (security-scan job added)
    - Cargo.lock (vuln remediation updates)
    - frontend/package-lock.json (npm audit fix)

key-decisions:
  - "deny.toml advisories.ignore: RUSTSEC-2023-0071 (rsa Marvin attack, no upstream fix, RSA not used as decryption oracle)"
  - "deny.toml advisories.ignore: RUSTSEC-2025-0141 (bincode unmaintained via surrealdb-core, no CVE)"
  - "deny.toml advisories.ignore: RUSTSEC-2023-0089 (atomic-polyfill unmaintained via surrealdb, no CVE)"
  - "BUSL-1.1 license exception added for surrealdb family (core DB dependency, BUSL converts to Apache-2.0 after 4 years)"
  - "GPL-3.0-or-later exception for actix-governor (rate limiter; reviewed acceptable for server binary)"
  - "trivy-action v0.36.0 confirmed as latest release before pinning"
  - "security-scan job has no needs: — runs in parallel with existing CI jobs"
  - "hadolint no-fail:true with SARIF output — findings advisory, not blocking (separate from cargo/npm which block)"

patterns-established:
  - "SARIF pattern: every scan tool uploads SARIF with distinct category: to GitHub Security tab"
  - "deny.toml ignore pattern: id + reason + review date mandatory for every exception (D-02)"

requirements-completed: [REQ-9]

# Metrics
duration: 45min
completed: 2026-06-04
---

# Phase 6 Plan 01: Security Scan CI + Vuln Remediation Summary

**cargo-audit, cargo-deny, npm audit, hadolint, and trivy fs/config wired into PR-time CI with SARIF upload; 36 Dependabot vulns remediated (Cargo + npm); license metadata corrected to Apache-2.0**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-06-04T12:00:00Z
- **Completed:** 2026-06-04T13:00:00Z
- **Tasks:** 3 of 4 (Task 4 is checkpoint:human-verify — awaiting human)
- **Files modified:** 8

## Accomplishments

- Created `deny.toml` cargo-deny workspace policy with permissive license allowlist, documented advisory ignores for 3 no-fix advisories (RUSTSEC-2023-0071, RUSTSEC-2025-0141, RUSTSEC-2023-0089), and license exceptions for surrealdb (BUSL-1.1), actix-governor (GPL-3.0), libbz2-rs-sys (bzip2-1.0.6)
- Added `security-scan` CI job to ci.yml (parallel, no needs:) with 5 scan tools and 4 SARIF uploads to GitHub Security tab via codeql-action/upload-sarif@v4 with distinct categories
- Remediated Cargo.lock: updated hickory-proto 0.25→0.26, rustls-webpki 0.103.10→0.103.13, lettre 0.11.19→0.11.22, rustls 0.23→0.23.40 (fixes 6 vulns); npm audit fix → 0 vulnerabilities
- Fixed license metadata: Cargo.toml:23 AGPL-3.0-or-later → Apache-2.0; added "license": "Apache-2.0" to frontend/package.json
- Created `.github/dependabot.yml` with weekly grouped updates for cargo, npm, and github-actions

## Task Commits

1. **Task 1: Fix license metadata + create deny.toml + dependabot.yml** — `f9fccd4` (chore)
2. **Task 2: Remediate 36 Dependabot vulns and reconcile deny.toml** — `a1bbb7b` (fix)
3. **Task 3: Add security-scan job to ci.yml** — `40b1555` (feat)

## Files Created/Modified

- `deny.toml` — cargo-deny workspace policy (advisories/licenses/bans/sources)
- `.hadolint.yaml` — Hadolint config suppressing only DL3008 (intentional design)
- `.github/dependabot.yml` — weekly grouped updates for cargo/npm/github-actions
- `Cargo.toml` — license field corrected to Apache-2.0
- `frontend/package.json` — license field added (Apache-2.0)
- `.github/workflows/ci.yml` — security-scan job added (cargo-audit, cargo-deny, npm audit, hadolint×2, trivy fs/config, 4× SARIF upload)
- `Cargo.lock` — updated to remediate hickory-proto, rustls-webpki, lettre, rustls vulnerabilities
- `frontend/package-lock.json` — npm audit fix applied (react-router-dom, vite patched)

## Decisions Made

- **deny.toml schema**: Used cargo-deny 0.18.9/0.19.x compatible schema (no `vulnerability`/`unmaintained`/`yanked` top-level fields — those don't exist in the installed version; `ignore = [...]` is the correct mechanism)
- **License exceptions**: Added BUSL-1.1 for surrealdb family (production database dependency), GPL-3.0 for actix-governor (server-side rate limiter), bzip2-1.0.6 for libbz2-rs-sys — all reviewed and documented
- **Permissive allowlist additions**: Added `Unlicense`, `0BSD`, `CDLA-Permissive-2.0` to the allow list (verified as permissive); these were not in the RESEARCH template but found in the actual dependency graph
- **trivy-action@v0.36.0**: Confirmed as latest via GitHub API before pinning

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] deny.toml `[advisories]` schema incompatibility**
- **Found during:** Task 2 (running cargo deny check advisories)
- **Issue:** RESEARCH template included `version = 2`, `vulnerability = "deny"`, `unmaintained = "warn"`, `yanked = "warn"`, `notice = "warn"` fields which are NOT valid in cargo-deny 0.18.9/0.19.x — schema error `unexpected-value: expected ["all", "workspace", "transitive", "none"]`
- **Fix:** Removed the unsupported top-level fields; used only `ignore = [...]` which is the correct advisory configuration
- **Files modified:** deny.toml
- **Verification:** `cargo deny check advisories` → `advisories ok`
- **Committed in:** a1bbb7b (Task 2 commit)

**2. [Rule 2 - Missing Critical] Additional license exceptions required**
- **Found during:** Task 2 (running cargo deny check licenses)
- **Issue:** The RESEARCH allowlist (`MIT`, `Apache-2.0`, etc.) was missing licenses actually present in the dependency graph: `BUSL-1.1` (surrealdb), `GPL-3.0-or-later` (actix-governor), `Unlicense` (ext-sort), `0BSD` (quoted_printable), `CDLA-Permissive-2.0` (webpki-roots), `bzip2-1.0.6` (libbz2-rs-sys)
- **Fix:** Added `Unlicense`, `0BSD`, `CDLA-Permissive-2.0` to global allowlist; added per-crate exceptions for BUSL-1.1 (surrealdb family), GPL-3.0-or-later (actix-governor), bzip2-1.0.6 (libbz2-rs-sys) with documented rationale
- **Files modified:** deny.toml
- **Verification:** `cargo deny check licenses` → `licenses ok`
- **Committed in:** a1bbb7b (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 Rule 1 schema bug, 1 Rule 2 missing license policy)
**Impact on plan:** Both fixes necessary for correctness. No scope creep.

## Issues Encountered

- `cargo audit` advisory DB was in a corrupt state at `~/.cargo/advisory-db` — removed and re-fetched. No functional impact.
- RUSTSEC-2023-0071 (rsa Marvin attack) has no upstream fix available. Documented in deny.toml with justification: RSA used only in PGP encryption path (not a decryption oracle), JWT uses Ed25519.
- `bincode` (RUSTSEC-2025-0141) and `atomic-polyfill` (RUSTSEC-2023-0089) are unmaintained with no upstream fix — both deep transitive deps via surrealdb. Documented ignores added.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are CI/tooling/config only.

## Known Stubs

None — no UI-rendering stubs or placeholder data introduced in this plan.

## User Setup Required

**Human verification required.** See Task 4 checkpoint:
- Push a throwaway branch with a known-vulnerable dep, open a PR, confirm `security-scan` goes RED
- Confirm SARIF results appear in GitHub Security tab
- Confirm a clean PR shows `security-scan` GREEN

## Next Phase Readiness

- Plan 06-02 can proceed: `release.yml` trivy image scan reorder (D-06) and image signing
- Plan 06-03 can proceed: distroless runtime migration (D-08), healthcheck subcommand (D-09)
- All scan tooling is wired; human checkpoint verifies CI triggers correctly on GitHub

---

*Phase: 06-ci-cd-infrastructure-hardening*
*Completed: 2026-06-04*
