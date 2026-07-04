---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 02
subsystem: auth
tags: [access-control, authz-middleware, path-normalization, actix-web, rust]

# Dependency graph
requires:
  - phase: 24-security-hardening-i-authentication-access-control-surfaces (plan 01)
    provides: TOTP replay-window closure (prior plan in this phase; no functional dependency, same crate)
provides:
  - Segment-boundary-aware wildcard matching in the public-path allowlist gate (is_public_path)
  - Path normalization (collapse `//`, reject `..`) applied before the allowlist check, fail-closed on ambiguity
  - matches_public_allowlist(path, entries) — a pure, directly-testable matcher extracted from is_public_path
affects: [phase-25-security-hardening-federation-pki-data-infra, any future work touching PUBLIC_PATHS or AuthzMiddleware]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Direct-call unit tests for pure matchers — test the matching function itself with a synthetic allowlist, not just the live registry, to prove properties the current registry contents don't happen to exercise"

key-files:
  created: []
  modified:
    - crates/axiam-api-rest/src/middleware/authz.rs

key-decisions:
  - "Normalization failure (a `..` segment) returns None/false — fail-closed, never an implicit allow; the request falls through to the normal 401/403 credential check"
  - "Wildcard match requires the remainder after the stripped prefix to be empty or start with `/`, closing the /api/v1/auth/* vs /api/v1/authz/... prefix-confusion class of bug"
  - "matches_public_allowlist extracted as a standalone function so tests can assert the property against a synthetic allowlist (the real PUBLIC_PATHS has only one wildcard entry today with no adjacent-prefix collision to exploit — Pitfall 6)"

patterns-established:
  - "Pure matcher extraction + synthetic-allowlist unit tests for security-critical string-matching logic"

requirements-completed: [SECHRD-11]

coverage:
  - id: D1
    description: "is_public_path rejects wildcard prefix-confusion (/api/v1/auth/* does not match /api/v1/authz/...) while preserving legitimate wildcard matches"
    requirement: "SECHRD-11"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#wildcard_prefix_confusion_is_rejected"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#real_wildcard_entry_still_matches_legitimate_paths"
        status: pass
    human_judgment: false
  - id: D2
    description: "Path normalization collapses `//` and rejects `..` segments before the allowlist check, fail-closed"
    requirement: "SECHRD-11"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#double_slash_is_collapsed_before_matching"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#dot_dot_segment_is_rejected_fail_closed"
        status: pass
    human_judgment: false
  - id: D3
    description: "Exact-match allowlist entries still match their canonical path (no regression)"
    requirement: "SECHRD-11"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#exact_match_entry_still_matches_canonical_path"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/middleware/authz.rs#public_paths_are_recognized"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 02: Public-Path Allowlist Hardening Summary

**Segment-boundary-aware wildcard matching + `//`/`..` path normalization closes the `/api/v1/auth/*` vs `/api/v1/authz/...` access-control-bypass gap in `is_public_path`, proven by direct-call negative unit tests.**

## Performance

- **Duration:** ~20 min (resumed session; original code+tests were authored in a prior interrupted session that could not build/test/commit due to disk exhaustion — this session reviewed, verified, fixed a clippy lint, and committed)
- **Started:** 2026-07-04T08:46:00Z (this session)
- **Completed:** 2026-07-04T08:54:58Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments
- `is_public_path` now normalizes the incoming path (collapses `//`, rejects any `..` segment) before running the allowlist check, and normalization failures fail closed (return `false`, never an implicit allow)
- Wildcard (`*`-suffixed) allowlist entries now require a segment boundary: `/api/v1/auth/*` no longer matches `/api/v1/authz/check` (prefix confusion), while `/api/v1/auth/login` and the bare `/api/v1/auth` prefix still match correctly
- Extracted `matches_public_allowlist(path, entries)` as a standalone, directly-testable pure function so the matching property is proven against a synthetic allowlist (the real `PUBLIC_PATHS` registry has only one wildcard entry, `/api/docs/*`, with no adjacent-prefix collision to exploit today — RESEARCH.md Pitfall 6)
- Added 5 new negative/regression unit tests in the existing inline `mod tests`: `wildcard_prefix_confusion_is_rejected`, `real_wildcard_entry_still_matches_legitimate_paths`, `double_slash_is_collapsed_before_matching`, `dot_dot_segment_is_rejected_fail_closed`, `exact_match_entry_still_matches_canonical_path`

## Task Commits

Each task was committed atomically:

1. **Task 1: Segment-boundary wildcard matching + path normalization in is_public_path, with negative tests** - `1b92f5f` (feat)

**Plan metadata:** committed alongside this SUMMARY per the state-update workflow.

_Note: Task was authored with `tdd="true"` but code and tests were written together in the prior interrupted session (see TDD Gate Compliance below); this session's single commit is the atomic task commit._

## Files Created/Modified
- `crates/axiam-api-rest/src/middleware/authz.rs` - Added `normalize_for_public_check` (collapse `//`, reject `..`, fail-closed `Option<String>`), extracted `matches_public_allowlist(path, entries)` (segment-boundary-aware wildcard matcher), made `is_public_path` a thin wrapper over it, and extended the inline `mod tests` with 5 new negative-case tests

## Decisions Made
- Normalization failure returns `false`/`None` (deny), never an implicit allow — the request continues to the normal 401/403 credential check path, preserving default-deny (matches plan's explicit fail-closed requirement)
- Wildcard match rule: strip the trailing `*` (and one `/` before it) to get the prefix, then require the remainder of the path after that prefix to be empty or start with `/` — this is the minimal rule that both closes the prefix-confusion bug and preserves the existing `/api/docs/*` behavior
- Kept `is_public_path` as the sole public entry point used by `AuthzMiddleware`; `matches_public_allowlist` is only exposed to the inline test module (`pub(super)`-free, referenced via `super::` import) so production callers are unaffected

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed `clippy::collapsible_if` warning in `matches_public_allowlist`**
- **Found during:** Task 1 verification (`cargo clippy -p axiam-api-rest --lib -- -D warnings`)
- **Issue:** The nested `if let Some(remainder) = path.strip_prefix(prefix) { if remainder.is_empty() || remainder.starts_with('/') { return true; } }` structure trips `clippy::collapsible_if`, which is denied by the project's `-D warnings` clippy gate (CLAUDE.md "Code quality" constraint)
- **Fix:** Collapsed into a single `if let ... && (...)` using Rust 2024's `let`-chain syntax, matching clippy's own suggested rewrite; behavior is unchanged (same short-circuit logic)
- **Files modified:** `crates/axiam-api-rest/src/middleware/authz.rs`
- **Verification:** `cargo clippy -p axiam-api-rest --lib -- -D warnings` passes; re-ran `cargo test -p axiam-api-rest --lib middleware::authz::tests` (8/8 pass) after the change
- **Committed in:** `1b92f5f` (part of the single task commit)

---

**Total deviations:** 1 auto-fixed (1 bug — lint violation)
**Impact on plan:** No scope change; fix was required to satisfy the project's mandatory `-D warnings` clippy gate before commit. No behavior change.

## Issues Encountered

- **Recovery context:** This plan resumed a prior interrupted execution. The prior session had already written the full task implementation (normalization function, extracted matcher, 5 new tests) directly in the working tree, but could not run `cargo test`/`cargo clippy`/commit because the sandbox disk had filled up (Bash was non-functional). This session started with the disk cleared (`target/` build cache deleted, ~23GB free) and Bash restored.
- **GitHub egress blocked for `utoipa-swagger-ui` build script:** With `target/` wiped, `cargo test -p axiam-api-rest --lib` needed to rebuild `utoipa-swagger-ui`'s build script, which downloads `swagger-ui-5.17.14.zip` from `github.com` at build time. This sandbox's outbound proxy returns 403 for `github.com` (a known, pre-existing environment limitation — see STATE.md's Phase 16/18 notes: "GitHub unreachable from this environment's egress policy"). Worked around it purely at the environment level (no repo change): built a minimal placeholder zip with the `swagger-ui-{version}/dist/{index.html,swagger-ui.css,swagger-ui-bundle.js,swagger-ui-standalone-preset.js,swagger-initializer.js}` structure the build script expects in this session's scratchpad, and pointed `SWAGGER_UI_DOWNLOAD_URL=file://<scratchpad>/v5.17.14.zip` at it for the verification commands only. This does not touch any tracked file, `Cargo.toml`, or CI config — it is a local-only build input substitution to unblock verification in this sandboxed environment; real builds (CI, developer machines with GitHub access) are unaffected.
- After the clippy fix, re-verified with `cargo test -p axiam-api-rest --lib middleware::authz::tests` (8/8 pass), `cargo clippy -p axiam-api-rest --lib -- -D warnings` (clean), and `cargo fmt -p axiam-api-rest -- --check` (clean) before committing.

## TDD Gate Compliance

This task's frontmatter declares `tdd="true"`, but the RED (failing test) → GREEN (passing implementation) commit sequence was not separately preserved: the prior interrupted session wrote the hardening logic and its tests together in the working tree before the disk-exhaustion failure prevented any commit at all. Per the recovery instructions for this plan, the verified code+tests were committed as a single atomic `feat` commit (`1b92f5f`) rather than reconstructed into synthetic RED/GREEN commits, since the implementation was already confirmed correct against the plan's acceptance criteria and reverting-then-redoing it would not add verification value. No RED-phase failing-test commit exists in git history for this task.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SECHRD-11 / T-24-11 / T-24-12 closed: a non-canonical or wrong-segment request path can no longer be classified public by `is_public_path`, proven by direct-call negative tests against the matching function itself.
- No blockers for the remaining Phase 24 plans (auth/access-control-surfaces track) or the parallel Phase 25 (federation/PKI/data/infra) track.
- Environment note for future executors in this sandbox: if `target/` is ever wiped again, `axiam-api-rest` (and anything depending on it) will need the `utoipa-swagger-ui` GitHub-download workaround described above (or genuine GitHub egress) to build/test.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

- FOUND: crates/axiam-api-rest/src/middleware/authz.rs
- FOUND: commit 1b92f5f
