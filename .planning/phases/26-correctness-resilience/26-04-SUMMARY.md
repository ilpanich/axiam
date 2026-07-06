---
phase: 26-correctness-resilience
plan: 04
subsystem: testing
tags: [ci, playwright, vitest, e2e, github-actions, contract-testing]

# Dependency graph
requires:
  - phase: 23-secfix-critical-high
    provides: auth-contract.spec.ts already authored asserting SECFIX-06 request bodies (23-06)
provides:
  - CI e2e job that actually runs Playwright as a blocking step against the served build + seeded backend
  - vitest run kept as its own separate blocking step in the same job
  - Confirmation that all 13 present frontend/e2e/*.spec.ts specs are discoverable/compilable and gate the build (no test.skip needed)
  - Confirmation that auth-contract.spec.ts asserts request BODIES (tenant_id/email/token/new_password/org_slug/tenant_slug), not just paths
affects: [ci-cd-infrastructure-hardening, compliance-verification]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "CI e2e job runs two independently-blocking test steps in the same job (Playwright test:e2e + vitest test), rather than conflating them into one run invocation"

key-files:
  created: []
  modified:
    - .github/workflows/ci.yml

key-decisions:
  - "No changes needed to frontend/e2e/auth-contract.spec.ts — it already asserts request bodies (tenant_id, email, token, new_password, org_slug, tenant_slug) via request().postDataJSON(), authored in Phase 23-06. Task 2 was a verification-only task."
  - "No specs required test.skip: `npx playwright test --list` enumerated all 13 spec files / 105 tests cleanly, and `npx tsc -b --noEmit` + `npm run lint` are both green — nothing is broken or covering an unfinished feature."

patterns-established:
  - "D-11: CI e2e job runs `npm run test:e2e` (Playwright) as a distinct blocking step, with `npm test` (vitest) as its own separate blocking step in the same job."

requirements-completed: [CORR-04]

coverage:
  - id: D1
    description: "CI e2e job's 'Serve frontend and run E2E tests' step now runs `npm run test:e2e` (Playwright) against the served build + seeded backend as a blocking step, with `npm test` (vitest run) added as its own separate blocking step; playwright install/report-upload steps unchanged"
    requirement: "CORR-04"
    verification:
      - kind: other
        ref: "python3 -c \"import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))\" — exits 0"
        status: pass
      - kind: other
        ref: "grep -q 'npm run test:e2e' .github/workflows/ci.yml && grep -Eq 'vitest run|npm test' .github/workflows/ci.yml — both PASS"
        status: pass
    human_judgment: true
    rationale: "The load-bearing GREEN (Playwright specs actually passing against the seeded backend in CI) cannot be reproduced in this sandbox — the proxy blocks the Chromium browser-binary download (see 23-06-SUMMARY.md). Structural verification (YAML parses, correct step wiring, browser-install/report-upload steps retained) is complete and passing, but the live CI run itself is the true gate per the plan's <manual_ci_only_verifications>."
  - id: D2
    description: "All 13 present frontend/e2e/*.spec.ts specs are discoverable, compile clean, and gate the build (none silently skipped); auth-contract.spec.ts confirmed to assert request BODIES for SECFIX-06 reset/resend/verify flows, not just paths"
    requirement: "CORR-04"
    verification:
      - kind: other
        ref: "npx playwright test --list (frontend/) — Total: 105 tests in 13 files, zero compile/discovery errors"
        status: pass
      - kind: other
        ref: "npx tsc -b --noEmit (frontend/) — exits 0, no output"
        status: pass
      - kind: other
        ref: "npm run lint (frontend/) — exits 0, no output"
        status: pass
      - kind: other
        ref: "grep -Eq 'tenant_id' e2e/auth-contract.spec.ts && grep -Eq 'postData|request\\(\\)|\\.body|JSON.parse' e2e/auth-contract.spec.ts — PASS"
        status: pass
    human_judgment: false

# Metrics
duration: 12min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 04: CI Playwright Wiring + Contract Body Assertion Summary

**Fixed CORR-04: the CI "e2e" job now actually runs `npx playwright test` (via `npm run test:e2e`) as a distinct blocking step against the seeded backend, with `vitest run` kept as its own separate blocking step, so all 13 `frontend/e2e/*.spec.ts` specs — including the SECFIX-06 body-asserting `auth-contract.spec.ts` — finally gate the build.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-07-05T08:57:00Z
- **Completed:** 2026-07-05T09:09:00Z
- **Tasks:** 2 completed
- **Files modified:** 1

## Accomplishments
- CI `e2e` job's "Serve frontend and run E2E tests" step was renamed to "Serve frontend and run Playwright E2E tests" and now runs `npm run test:e2e` (Playwright) instead of `npm test` (vitest) — the actual regression that let 13 e2e specs never gate the build (CORR-04).
- Added a new, separate blocking "Run frontend unit tests" step (`npm test` / vitest run) in the same `e2e` job, so both suites independently gate merges per D-11.
- Confirmed (no code change required) that `auth-contract.spec.ts` already asserts request BODIES — `tenant_id`, `email`, `token`, `new_password`, `org_slug`, `tenant_slug` via `request().postDataJSON()` — for all SECFIX-06 reset/resend/verify flows, not merely request paths.
- Confirmed all 13 present `frontend/e2e/*.spec.ts` files (105 tests) are discoverable via `npx playwright test --list`, and both `npx tsc -b --noEmit` and `npm run lint` pass clean — nothing needed `test.skip`-ing per D-12.
- `npx playwright install chromium` and the `playwright-report` artifact upload (`if: always()`) steps were left unchanged and retained.

## Task Commits

Each task was committed atomically:

1. **Task 1: Run Playwright in the CI e2e job as a blocking step; keep vitest separate (D-11)** - `16842b6` (fix)
2. **Task 2: Triage e2e specs / verify contract spec asserts bodies (D-12/SECFIX-06)** - no commit (verification-only; no file changes were required — see Decisions Made)

**Plan metadata:** (recorded below in final commit)

## Files Created/Modified
- `.github/workflows/ci.yml` - `e2e` job's test-runner step now runs `npm run test:e2e` (Playwright) as a blocking step, with a new separate blocking `npm test` (vitest) step added; browser-install and playwright-report upload steps unchanged.

## Decisions Made
- No changes needed to `frontend/e2e/auth-contract.spec.ts` — reading it confirmed it already asserts request bodies (`tenant_id`, `email`, `token`, `new_password`, `org_slug`, `tenant_slug`) via `request().postDataJSON()`, per work done in Phase 23-06 (SECFIX-06). Task 2's action items ("confirm/strengthen") resolved to "confirm; no strengthening required."
- No spec required `test.skip`: `npx playwright test --list` cleanly enumerated all 13 files / 105 tests with zero compile or discovery errors, and both `npx tsc -b --noEmit` and `npm run lint` passed with no output. No spec covers a genuinely unfinished feature that would need to be skipped-with-note per D-12.
- Kept the existing action SHA pins, `npx playwright install chromium` step, and `playwright-report` (`if: always()`) upload step completely unchanged, per the plan's constraint.

## Deviations from Plan

None — plan executed exactly as written. Task 2 required no source changes because the artifact it targeted (`auth-contract.spec.ts`) already satisfied the acceptance criteria from prior work (23-06); this was confirmed via structural verification, not assumed.

## Issues Encountered
None. `npx playwright test --list` worked directly in this sandbox (no browser binary is required to list/discover tests), so Task 2's discovery/triage step did not need the documented tsc+lint fallback — both were still run anyway per the plan's verification requirements and passed clean.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- The CI e2e job is now correctly wired; the load-bearing verification (Playwright specs passing against a live seeded backend, including the SECFIX-06 auth-contract regression guard) is CI-gated per this plan's `<manual_ci_only_verifications>` — it will run automatically on the next push/PR to this branch and should be checked in the Actions run before merge.
- No blockers for subsequent Phase 26 plans.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED

- FOUND: .github/workflows/ci.yml
- FOUND: frontend/e2e/auth-contract.spec.ts
- FOUND: commit 16842b6
- FOUND: .planning/phases/26-correctness-resilience/26-04-SUMMARY.md
