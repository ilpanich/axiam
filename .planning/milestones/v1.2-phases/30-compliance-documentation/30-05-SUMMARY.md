---
phase: 30-compliance-documentation
plan: 05
subsystem: docs
tags: [markdown, bash, docs-index, link-checker, ci-tooling]

# Dependency graph
requires:
  - phase: 30-compliance-documentation
    provides: "Wave 1 docs artifacts (30-01..30-04): docs/api/*, docs/deployment/README.md, docs/admin/README.md, docs/pki/README.md, docs/compliance/gdpr-compliance.md, claude_dev/security-audit.md"
provides:
  - "docs/README.md — top-level documentation index linking out to every doc section, all 7 SDK READMEs, sdks/CONTRACT.md, and claude_dev/security-audit.md (no duplication)"
  - "scripts/check-doc-links.sh — zero-dependency bash internal-link checker for docs/**/*.md + claude_dev/security-audit.md, fails closed on any broken relative link"
affects: [30-06]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Zero-dependency internal-link validation: grep -oE '\\]\\([^) ]+\\)' + sed to extract markdown link targets, filtered to relative paths, resolved against the containing file's directory, existence-checked with `[ -e ]` (covers both files and directories)"
    - "docs/README.md as a pure link-out index (D-09) — no content duplication, single source of truth per linked page"

key-files:
  created:
    - scripts/check-doc-links.sh
    - docs/README.md
  modified: []

key-decisions:
  - "check-doc-links.sh written in bash (not Python) to match all 4 existing scripts/*.sh siblings' convention"
  - "Link existence check uses `[ -e ]` rather than `[ -f ]` so directory-target links (e.g. ../../sdks/, ../../k8s/) also resolve correctly, not just file links"
  - "docs/README.md additionally links sdks/CONTRACT.md and dev-environment.md/CLAUDE.md/roadmap.md beyond the plan's minimum required set, since they were natural additions already present in the doc tree and improve discoverability without duplicating content"

patterns-established:
  - "scripts/check-doc-links.sh is the canonical pre-merge/CI gate for internal doc-link integrity; run it after adding or moving any docs/**/*.md file"

requirements-completed: [DOCS-01]

coverage:
  - id: D1
    description: "scripts/check-doc-links.sh: zero-dependency bash link checker that resolves every relative markdown link in docs/**/*.md + claude_dev/security-audit.md and fails closed on a missing target"
    requirement: "DOCS-01"
    verification:
      - kind: other
        ref: "test -x scripts/check-doc-links.sh && bash -n scripts/check-doc-links.sh"
        status: pass
      - kind: other
        ref: "bash scripts/check-doc-links.sh (isolated sandbox self-test: exit 0 with all-resolving links, exit 1 with an injected broken link)"
        status: pass
    human_judgment: false
  - id: D2
    description: "docs/README.md top-level index linking out to docs/api, docs/deployment, docs/admin, docs/pki, docs/compliance, all 7 sdks/*/README.md, and claude_dev/security-audit.md, stamped v1.2 Beta"
    requirement: "DOCS-01"
    verification:
      - kind: other
        ref: "grep -Eq 'v1\\.2' docs/README.md && grep -q 'security-audit.md' docs/README.md && grep -q 'api/' docs/README.md && grep -q 'deployment/' docs/README.md && grep -q 'admin/' docs/README.md && grep -q 'pki/' docs/README.md && grep -q 'compliance/' docs/README.md"
        status: pass
      - kind: other
        ref: "bash scripts/check-doc-links.sh (109 relative links resolved across all 14 docs/**/*.md + claude_dev/security-audit.md files, exit 0)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-06
status: complete
---

# Phase 30 Plan 05: Docs Index + Link Checker Summary

**Top-level docs/README.md link-out index over all 5 doc sections, 7 SDK READMEs, and the security-audit master doc, validated end-to-end by a new zero-dependency scripts/check-doc-links.sh that fails closed on broken links.**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-06T17:47:00Z
- **Completed:** 2026-07-06T17:48:39Z
- **Tasks:** 2 completed
- **Files modified:** 2 (both created)

## Accomplishments
- `scripts/check-doc-links.sh` — stdlib-only bash script that scans `docs/**/*.md` + `claude_dev/security-audit.md`, extracts relative markdown link targets, resolves each against its source file's directory (handles `../` and `../../`), and exits non-zero with a per-link report on any broken target. Self-tested in an isolated sandbox: confirmed exit 0 when all links resolve and exit 1 with a correctly-reported broken link when one is injected.
- `docs/README.md` — single landing page linking out (no duplication, D-09) to `docs/api/`, `docs/deployment/`, `docs/admin/`, `docs/pki/`, `docs/compliance/` (including the new `gdpr-compliance.md`), all 7 `sdks/{rust,typescript,python,java,csharp,php,go}/README.md`, `sdks/CONTRACT.md`, and `../claude_dev/security-audit.md`. Stamped v1.2 Beta + last-verified date (D-12).
- Ran `scripts/check-doc-links.sh` over the full real doc set as the plan's gate: **109 relative links resolved across all 14 scanned files, exit 0** — this simultaneously validates every Wave 1 (30-01..30-04) doc's internal links, not just the new index.

## Task Commits

Each task was committed atomically:

1. **Task 1: Author scripts/check-doc-links.sh** - `5421600` (feat)
2. **Task 2: Author docs/README.md top-level index and validate all links** - `918c975` (docs)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified
- `scripts/check-doc-links.sh` - zero-dependency bash internal-link checker (executable, `set -euo pipefail`)
- `docs/README.md` - top-level documentation index, link-out only

## Decisions Made
- Wrote the checker in bash rather than Python to match the existing `scripts/*.sh` convention (all 4 sibling scripts are bash).
- Used `[ -e ]` (exists, file-or-directory) rather than `[ -f ]` for the existence check, since several docs link to directories (e.g. `../../sdks/`, `../../k8s/`, `../../proto/axiam/v1/`) not just files.
- Included a couple of link targets beyond the plan's literal minimum (`sdks/CONTRACT.md`, `dev-environment.md`, `CLAUDE.md`, `claude_dev/roadmap.md`) since they were already-existing, relevant docs that improve the index's usefulness without duplicating any content — pure link-outs, consistent with D-09.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None. The link checker's first real run against the actual repo (before `docs/README.md` existed) correctly flagged `docs/api/README.md -> ../README.md` as broken, which was expected (docs/README.md is the exact deliverable created in Task 2) and served as an additional live confirmation of fail-closed behavior beyond the isolated sandbox self-test.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

DOCS-01's index requirement is fully satisfied: a single discoverable `docs/README.md` links to every doc section, all 7 SDK READMEs, and the compliance master doc, and `scripts/check-doc-links.sh` is now available as a reusable CI/pre-merge gate for internal doc-link integrity across the whole `docs/` tree plus `claude_dev/security-audit.md`. Ready for plan 30-06 (light docs CI wiring), which can invoke this script directly as its link-check step without adding any new dependency.

## Self-Check: PASSED

- FOUND: scripts/check-doc-links.sh
- FOUND: docs/README.md
- FOUND commit: 5421600
- FOUND commit: 918c975

---
*Phase: 30-compliance-documentation*
*Completed: 2026-07-06*
