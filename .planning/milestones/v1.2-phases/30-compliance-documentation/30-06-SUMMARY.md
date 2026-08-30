---
phase: 30-compliance-documentation
plan: 06
subsystem: infra
tags: [github-actions, ci, docs, openapi, asyncapi, link-check, supply-chain]

# Dependency graph
requires:
  - phase: 30-compliance-documentation (30-03)
    provides: docs/api/openapi.json (symlink) + docs/api/asyncapi.yml specs validated by the docs CI
  - phase: 30-compliance-documentation (30-05)
    provides: scripts/check-doc-links.sh + docs/README.md index consumed by the link-check step
provides:
  - .github/workflows/docs-ci.yml — path-filtered, SHA-pinned, least-privilege docs CI job
  - Enforced internal doc link-check (scripts/check-doc-links.sh) on docs/spec changes
  - Enforced OpenAPI JSON parse-check (docs/api/openapi.json) on docs/spec changes
  - Documented local-only AsyncAPI validation fallback (docs/api/README.md)
affects: [docs, ci, compliance, release-gate]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Docs CI mirrors sdk-openapi-drift.yml conventions: SHA-pinned actions, permissions: contents: read, dual pull_request + push:[main] path-filtered triggers"
    - "Egress-conscious CI: zero-dependency stdlib checks (bash + python3) only; no new npm/pip supply-chain dependency introduced"

key-files:
  created:
    - .github/workflows/docs-ci.yml
  modified:
    - docs/api/README.md

key-decisions:
  - "Coordinator resolved the T-30-SC blocking-human checkpoint as FALLBACK: omit npx @asyncapi/cli validate from CI (SUS verdict = sandbox telemetry gap, but a SUS-flagged supply-chain dep is not an autonomous 'approve'). Keep OpenAPI-parse + link-check enforced."
  - "OpenAPI parse-check validates the committed docs/api/openapi.json directly via python3 stdlib json.load rather than building axiam-server --dump-openapi — lighter (D-11), no Rust toolchain / SWAGGER_UI egress needed in this job; drift is already covered by sdk-openapi-drift.yml."

patterns-established:
  - "Package-legitimacy fallback is documented in-repo (docs/api/README.md + workflow header comment) as a maintainer follow-up, not silently dropped"

requirements-completed: [DOCS-01]

coverage:
  - id: D1
    description: ".github/workflows/docs-ci.yml is valid YAML, path-filtered on docs+spec sources, SHA-pinned checkout, permissions: contents: read (no write/secrets)"
    requirement: "DOCS-01"
    verification:
      - kind: automated
        ref: "python3 -c \"import yaml; yaml.safe_load(open('.github/workflows/docs-ci.yml'))\" && grep -Eq 'contents: *read' && grep -q 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683'"
        status: pass
    human_judgment: false
  - id: D2
    description: "Docs CI enforces the internal link-check (scripts/check-doc-links.sh) and the OpenAPI JSON parse-check"
    requirement: "DOCS-01"
    verification:
      - kind: automated
        ref: "bash scripts/check-doc-links.sh (110 links resolved) && python3 -c \"import json; json.load(open('docs/api/openapi.json'))\""
        status: pass
    human_judgment: false
  - id: D3
    description: "AsyncAPI-validate step omitted with a documented fallback note (docs/api/README.md) per the blocking-human package-legitimacy checkpoint outcome"
    requirement: "DOCS-01"
    verification:
      - kind: manual_procedural
        ref: "docs/api/README.md § AMQP — AsyncAPI: local `npx @asyncapi/cli validate` note + maintainer wire-in follow-up"
        status: pass
    human_judgment: true
    rationale: "The AsyncAPI CI enforcement is a deferred maintainer decision (confirm @asyncapi/cli legitimacy at npmjs.com then wire the step in); a human must sign off on introducing the SUS-flagged dependency before it becomes CI-enforced."

# Metrics
duration: 8min
completed: 2026-07-06
status: complete
---

# Phase 30 Plan 06: Light Docs CI (DOCS-01) Summary

**Path-filtered, SHA-pinned, least-privilege `.github/workflows/docs-ci.yml` that enforces the zero-dependency internal link-check plus an OpenAPI JSON parse-check; the `@asyncapi/cli` validation step was omitted via the documented supply-chain fallback.**

## Performance

- **Duration:** ~8 min
- **Completed:** 2026-07-06T17:55:28Z
- **Tasks:** 2 (1 checkpoint resolved by coordinator, 1 auto)
- **Files modified:** 2 (1 created, 1 modified)

## Accomplishments
- Authored `.github/workflows/docs-ci.yml` mirroring `sdk-openapi-drift.yml` conventions: `name:` header, `on.pull_request` + `on.push` both `branches: [main]` with a `paths:` filter (`docs/**`, `claude_dev/security-audit.md`, `crates/axiam-amqp/**`, `crates/axiam-api-rest/src/openapi.rs`), `permissions: contents: read`, single `ubuntu-latest` job, SHA-pinned `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`.
- Enforced Step 1: `bash scripts/check-doc-links.sh` (zero-dependency, egress-free; 110 links resolved across 14 files).
- Enforced Step 2: OpenAPI parse-check — `python3 -c "import json; json.load(open('docs/api/openapi.json'))"` (stdlib, no new dependency, follows the symlink to `sdks/openapi.json`).
- Omitted the `npx @asyncapi/cli validate` step per the blocking-human package-legitimacy checkpoint fallback, with an explanatory workflow header comment and a maintainer follow-up note added to `docs/api/README.md`.

## Task Commits

1. **Task 1: Blocking-human package-legitimacy checkpoint for @asyncapi/cli** — resolved by coordinator as `fallback` (no commit; gate outcome fed Task 2).
2. **Task 2: Author .github/workflows/docs-ci.yml (spec-validate + link-check)** — `f8bb0f7` (ci)

**Plan metadata:** (this commit)

## Files Created/Modified
- `.github/workflows/docs-ci.yml` — new light docs CI: link-check + OpenAPI-parse enforced; AsyncAPI-validate omitted (fallback comment).
- `docs/api/README.md` — added a "Validation is local-only (not CI-enforced yet)" note under § AMQP — AsyncAPI explaining the omission and the maintainer wire-in path.

## Decisions Made
- **Checkpoint outcome = FALLBACK (coordinator).** The `@asyncapi/cli` `[SUS]` verdict is a sandbox download-telemetry gap (official AsyncAPI Initiative CLI, benign postinstall), but introducing a SUS-flagged supply-chain dependency into CI is not an autonomous "approve" without interactive human confirmation. The plan explicitly supports this fallback (30-RESEARCH § "Environment Availability"); little is lost because `asyncapi.yml` is hand-authored and validatable locally.
- **OpenAPI parse-check runs against the committed `docs/api/openapi.json` via python3 stdlib**, not a fresh `--dump-openapi` build. Lighter per D-11 (no Rust toolchain, no `protobuf-compiler`, no `SWAGGER_UI_DOWNLOAD_URL` egress workaround in this job), and JSON validity is the only thing this job needs to guard — Rust-source drift is already covered by `sdk-openapi-drift.yml`.

## Deviations from Plan

The plan's Task 2 described building `axiam-server --no-default-features` + `--dump-openapi` + `jq empty` for the OpenAPI step. Per the coordinator's explicit direction (keep it light, add NO new external dependency, validate the committed JSON), the OpenAPI step instead parses `docs/api/openapi.json` directly with `python3` stdlib. This is a lighter, dependency-free realization of the same acceptance criterion ("OpenAPI parse step present"), fully consistent with D-11 and the fallback framing. Not a Rule 1–4 auto-fix — it is a coordinator-directed refinement of the checkpoint outcome.

## Issues Encountered
None.

## User Setup Required
None required for CI to pass. **Maintainer follow-up (optional, non-blocking):** confirm `@asyncapi/cli` legitimacy at npmjs.com/package/@asyncapi/cli, then optionally wire `npx @asyncapi/cli validate docs/api/asyncapi.yml` into `docs-ci.yml` to CI-enforce AsyncAPI meta-schema validation. Until then, run it locally before commit (documented in `docs/api/README.md`).

## Next Phase Readiness
- DOCS-01 CI portion satisfied: docs CI is a path-filtered, SHA-pinned, least-privilege guard that link-checks the docs and parse-validates the OpenAPI spec.
- This is the final plan (30-06) of the final phase (30) of the v1.2 milestone. Phase 30 plans are all complete.

## Self-Check: PASSED

- FOUND: `.github/workflows/docs-ci.yml`
- FOUND commit: `f8bb0f7`

---
*Phase: 30-compliance-documentation*
*Completed: 2026-07-06*
