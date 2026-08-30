---
phase: 13-surrealdb-connection-resilience
plan: 02
subsystem: infra
tags: [surrealdb, bash, justfile, seed, bootstrap, e2e]

requires:
  - phase: 13-surrealdb-connection-resilience
    provides: research identifying two confirmed seed bugs (RESEARCH Q6)

provides:
  - e2e-bootstrap.sh seeds into db=main (matching server DbConfig), without rejected is_active field
  - just bootstrap-local provides one-command local first-run seed unblocking 12-HUMAN-UAT

affects:
  - 12-HUMAN-UAT smoke test (now unblocked)
  - any CI job invoking scripts/e2e-bootstrap.sh

tech-stack:
  added: []
  patterns:
    - "Env-driven DB targeting: AXIAM__DB__DATABASE env var drives surreal-db header (default: main)"
    - "just recipe delegates to shell script rather than duplicating seed logic"

key-files:
  created: []
  modified:
    - scripts/e2e-bootstrap.sh
    - justfile

key-decisions:
  - "AXIAM_DB driven by AXIAM__DB__DATABASE env var defaulting to 'main' — matches server DbConfig, env-overridable for non-default deployments"
  - "bootstrap-local delegates entirely to e2e-bootstrap.sh — no logic duplication; env vars override-able"
  - "is_active field removed from tenant CREATE; SCHEMAFULL table rejects unknown fields silently (statement ERR)"

patterns-established:
  - "Seed scripts must target the database the server reads, verified via grep assertion on surreal-db header"

requirements-completed: [REQ-17]

duration: 10min
completed: 2026-06-19
---

# Phase 13 Plan 02: First-Run Seed Repair Summary

**Fixed two silent seed failures in e2e-bootstrap.sh (wrong db + rejected field) and added `just bootstrap-local` for repeatable one-command local first-run, unblocking the deferred 12-HUMAN-UAT smoke.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-06-19T13:20:00Z
- **Completed:** 2026-06-19T13:30:22Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- e2e-bootstrap.sh now targets `db=main` (server's DbConfig default) via `AXIAM__DB__DATABASE`-driven header — seed no longer writes to wrong db
- Removed `is_active = true` from tenant CREATE — SCHEMAFULL table no longer rejects statement 2 with ERR
- `just bootstrap-local` recipe added; delegates to e2e-bootstrap.sh with correct local-dev defaults; appears in `just --list` with clean one-line description

## Task Commits

1. **Task 1: Fix e2e-bootstrap.sh db-name mismatch + drop is_active** - `6ca8351` (fix)
2. **Task 2: Add just bootstrap-local recipe** - `360f6fc` (feat)

## Files Created/Modified
- `/home/emanuele/git/priv/axiam/scripts/e2e-bootstrap.sh` - Added AXIAM_DB var, changed surreal-db header to `${AXIAM_DB}`, removed is_active field
- `/home/emanuele/git/priv/axiam/justfile` - Added bootstrap-local recipe delegating to e2e-bootstrap.sh

## Decisions Made
- `AXIAM_DB` driven by `AXIAM__DB__DATABASE` (default `main`) rather than hardcoded string — matches server DbConfig, env-overridable for CI/staging overrides
- `bootstrap-local` sets all three env vars explicitly (`AXIAM_URL`, `SURREAL_URL`, `AXIAM__DB__DATABASE`) before delegating to the script — no logic duplication, all overridable
- Kept `surreal-ns: axiam` unchanged — namespace is correct; only the database name was wrong

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered
None.

## Known Stubs
None.

## Threat Flags
None. Both threat mitigations applied as planned: T-13-04 (env-driven db header) and T-13-05 (per-statement ERR check preserved).

## User Setup Required
None — no external service configuration required.

## Next Phase Readiness
- 12-HUMAN-UAT smoke test unblocked: `just dev-up && just run-local` in one terminal, then `just bootstrap-local` in another
- Verify bootstrap-local end-to-end against a live local stack to confirm full path works

---
*Phase: 13-surrealdb-connection-resilience*
*Completed: 2026-06-19*
