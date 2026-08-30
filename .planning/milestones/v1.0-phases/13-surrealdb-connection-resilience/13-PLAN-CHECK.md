# Phase 13 Plan Check

**Phase:** 13-surrealdb-connection-resilience
**Plans verified:** 13-01-PLAN.md, 13-02-PLAN.md
**Date:** 2026-06-19
**Verdict:** CONCERNS (1 blocker, 2 warnings)

---

## Verdict Summary

| Finding | Severity | Dimension |
|---------|----------|-----------|
| VALIDATION.md missing — Nyquist gate 8e blocked | BLOCKER | Dimension 8 |
| tokio `time` feature not explicitly listed in axiam-db dep | WARNING | Dimension 2 / CLAUDE.md |
| RESEARCH Q4 sample code uses `.is_none()` / `.is_some()` but actual repo returns `AxiamResult<T>` (Err, not None) — PLAN action already corrects this but test must not copy the RESEARCH snippet verbatim | WARNING | Dimension 4 |

1 blocker requires resolution before execution. The 2 warnings will not prevent execution but risk a compile/test failure if the executor follows the RESEARCH sample code rather than the PLAN action.

---

## Success Criteria Coverage

| # | Roadmap Success Criterion | Covering Plan/Task | Status |
|---|---------------------------|--------------------|--------|
| SC-1 | After forced/simulated WS reconnect, connection operates against ns=axiam/db=main; regression test asserts post-reconnect reads succeed | 13-01 Task 2 | COVERED |
| SC-2 | DbManager re-establishes ns/db on reconnect; health_check verifies active ns/db not just liveness | 13-01 Tasks 1+3 | COVERED |
| SC-3 | e2e-bootstrap.sh seeds into the server's db (main), no is_active | 13-02 Task 1 | COVERED |
| SC-4 | Repeatable local first-run path (`just bootstrap-local`) | 13-02 Task 2 | COVERED |
| SC-5 | Deferred 12-HUMAN-UAT smoke is unblocked | 13-02 (both tasks) | COVERED (plan correctly defers execution of the smoke per CONTEXT.md Deferred) |

---

## Dimension 1: Requirement Coverage — PASS

Phase has a single requirement: REQ-17. Both plans declare `requirements: [REQ-17]` in frontmatter.
REQ-17 = "SurrealDB Connection Resilience (post-remediation bug fix)". All five success criteria map to tasks.

---

## Dimension 2: Task Completeness — PASS with warning

| Plan | Task | Files | Action | Verify | Done | Notes |
|------|------|-------|--------|--------|------|-------|
| 13-01 | 1 | error.rs | Specific | `cargo check` command | grep + no-errors | OK |
| 13-01 | 2 | reconnect_regression.rs | Specific | `cargo test` command | output text criteria | OK |
| 13-01 | 3 | connection.rs | Specific | `cargo test` + grep | measurable | OK |
| 13-02 | 1 | e2e-bootstrap.sh | Specific | `bash -n` + grep counts | counts + block intact | OK |
| 13-02 | 2 | justfile | Specific | `just --list` grep | count + delegate check | OK |

All tasks have Files, Action, Verify (automated), and Done. Action steps are concrete (exact function names, line numbers, env var names).

WARNING: Task 3 `<verify>` runs the full `cargo test -p axiam-db --no-default-features` suite. If existing tests in axiam-db have live-DB dependencies, this could fail unrelated to the change. The task notes disk constraints and per-crate scope — acceptable, but the executor should be aware.

WARNING: Task 3 action says "Verify `tokio` `time` feature is available" but the axiam-db `Cargo.toml` lists `tokio = { workspace = true }` (no explicit features) and the workspace root has `tokio = { version = "1", features = ["full"] }`. The `full` feature includes `time`. Since axiam-db inherits workspace features, `tokio::time` should compile. However: when running `--no-default-features`, workspace feature inheritance is unaffected (features are different from crate features). This is fine. No action needed, but executor should verify if `interval` fails to resolve.

---

## Dimension 3: Dependency Correctness — PASS

Both plans: `depends_on: []`, `wave: 1`. Files modified are disjoint:
- 13-01: `crates/axiam-db/src/connection.rs`, `crates/axiam-db/src/error.rs`, `crates/axiam-db/tests/reconnect_regression.rs`
- 13-02: `scripts/e2e-bootstrap.sh`, `justfile`

Zero overlap. Genuinely parallel. No cycles. No forward references.

---

## Dimension 4: Key Links Planned — PASS with warning

13-01 key links:
- guard task → config.namespace/config.database via `session::ns()` comparison: PLANNED in Task 3 action.
- health_check → config.namespace/config.database via `DbError::SessionMismatch`: PLANNED in Tasks 1+3, wired via `connection.rs` storing `config: DbConfig`.

13-02 key links:
- e2e-bootstrap.sh → server db `main` via `AXIAM__DB__DATABASE` env default: PLANNED in Task 1 action.
- justfile `bootstrap-local` → e2e-bootstrap.sh: PLANNED in Task 2 action (delegates, does not duplicate).

WARNING on test correctness: RESEARCH.md Q4 sample code (lines 321-328) uses `get_by_id(org.id.clone()).await.unwrap()` and asserts `.is_none()` / `.is_some()`. The actual `SurrealOrganizationRepository::get_by_id` returns `AxiamResult<Organization>` — not `Option`. `NotFound` is returned as `Err(...)`, not `Ok(None)`. Plan Task 2 `<action>` explicitly and correctly overrides this: "Use `assert!(result.is_err())` for the wrong-ns read and `assert!(result.is_ok())` for the re-selected read (get_by_id returns AxiamResult, NOT Option — NotFound is an Err)." The PLAN is correct. If the executor reads RESEARCH Q4 code and copies it verbatim, the test will fail to compile (calling `.is_none()` on a `Result`). The plan action must be followed, not the RESEARCH snippet.

---

## Dimension 5: Scope Sanity — PASS

| Plan | Tasks | Files | Status |
|------|-------|-------|--------|
| 13-01 | 3 | 3 | Within budget (3 tasks, 3 files) |
| 13-02 | 2 | 2 | Well within budget |

No scope concerns.

---

## Dimension 6: Verification Derivation — PASS

13-01 truths are user-observable behavior:
- "A reconnected session no longer silently reads the empty default ns/db" — observable via test.
- "health_check fails when active session points at wrong ns/db" — observable via test.
- "A regression test reproduces the wrong-namespace failure" — verifiable outcome.

Artifacts map to truths with concrete `contains` checks (`session::ns`, `SessionMismatch`).
Key links connect guard→config and health_check→config with exact mechanism stated.

13-02 truths are user-observable:
- Seed ends up in the right db — observable by running bootstrap.
- No `is_active` ERR — observable from bootstrap output.
- `just bootstrap-local` exists — observable via `just --list`.

---

## Dimension 7: Context Compliance — PASS

Locked decisions (CONTEXT.md `<decisions>`):

| Decision | Task(s) | Compliant |
|----------|---------|-----------|
| Root cause confirmed: SDK does not replay use_ns/use_db on reconnect | 13-01 T3 | YES — guard task pattern |
| health_check MUST verify actual ns/db selection | 13-01 T3 | YES — session::ns/db assertion |
| Regression test MUST reproduce failure | 13-01 T2 | YES |
| e2e-bootstrap.sh: surreal-db axiam → main, remove is_active | 13-02 T1 | YES |
| Add `just bootstrap-local` recipe | 13-02 T2 | YES |
| Disk near-full: build/test per-crate -p --no-default-features | Both plans | YES — every verify command uses -p axiam-db --no-default-features |

Deferred ideas check:
- "Executing the 11-item manual smoke" — 13-02 success_criteria explicitly excludes this. PASS.
- "Broader SDK upgrade or connection-pool changes" — not present in any task. PASS.

No contradictions. No deferred ideas included.

---

## Dimension 7b: Scope Reduction — PASS

No v1/v2 versioning language. No "static for now", "hardcoded", "future enhancement" qualifiers on any locked decision. All decisions are implemented fully. The smoke execution deferral is explicit per CONTEXT.md Deferred, not a silent reduction.

---

## Dimension 7c: Architectural Tier Compliance — PASS

Architectural Responsibility Map (RESEARCH.md):

| Capability | Expected Tier | Plan Tier | Status |
|------------|---------------|-----------|--------|
| WS ns/db selection | DB client layer (axiam-db) | 13-01 targets connection.rs in axiam-db | CORRECT |
| Reconnect detection | DB client layer (axiam-db) | 13-01 T3 guard in connection.rs | CORRECT |
| Health verification | DB client layer (axiam-db) | 13-01 T3 health_check in connection.rs | CORRECT |
| Seed correctness | Scripts (e2e-bootstrap.sh) + justfile | 13-02 targets exactly these files | CORRECT |

No tier mismatches. No security capability placed in wrong tier.

---

## Dimension 8: Nyquist Compliance — FAIL (BLOCKER)

### Check 8e — VALIDATION.md Existence

```
ls /home/emanuele/git/priv/axiam/.planning/phases/13-surrealdb-connection-resilience/*-VALIDATION.md
# Result: no files found
```

**VALIDATION.md does not exist for Phase 13.** `nyquist_validation` is `true` in `config.json`. RESEARCH.md contains a `## Validation Architecture` section (confirmed present, lines 519-533). Gate 8e requires VALIDATION.md to exist before proceeding.

```yaml
issue:
  plan: null
  dimension: dimension_8_nyquist
  severity: blocker
  description: "13-VALIDATION.md missing. nyquist_validation=true and RESEARCH.md has a Validation Architecture section. Gate 8e requires this file before execution."
  fix_hint: "Re-run `/gsd:plan-phase 13 --research` to regenerate, or manually create 13-VALIDATION.md from the RESEARCH.md Validation Architecture section before execution."
```

---

## Dimension 9: Cross-Plan Data Contracts — PASS

Plans are file-disjoint. 13-01 touches axiam-db Rust source; 13-02 touches shell script and justfile. No shared data pipelines. No conflicting transforms.

---

## Dimension 10: CLAUDE.md Compliance — PASS

Checked against `/home/emanuele/git/priv/axiam/CLAUDE.md`:

| Rule | Status |
|------|--------|
| NEVER create files unless absolutely necessary | Tests and new script section are necessary by requirement — OK |
| Files under 500 lines | Tasks 1 and 3 both note "Keep file under 500 lines" — OK |
| ALWAYS read a file before editing it | Plans reference `@crates/axiam-db/src/connection.rs` etc. in context block — OK |
| Build: `just check` / per-crate scope | Every verify uses `-p axiam-db --no-default-features` — OK |
| No whole-workspace build/test (disk near-full) | Plans explicitly prohibit this — OK |
| Signed commits | Out of scope for plan check; note from project memory: subagents may not sign; re-sign needed at phase end |

No CLAUDE.md violations in either plan.

---

## Dimension 11: Research Resolution — PASS

RESEARCH.md has `## Open Questions` section. Checking status:

1. **Clone session state independence** — plan acknowledges this in Task 2 behavior: "This settles RESEARCH A4 / Open Question 1: if use_ns on the handle does NOT flip the read result, the clone/handle does not share session state and Task 3 must use the Arc fallback." Resolution deferred to test execution with explicit branch condition. This is acceptable — the plan handles both outcomes (Task 2 proves empirically, Task 3 adapts). The questions are operationally resolved: the test settles them at execution time.

2. **`surrealdb::Error` variant for health_check mismatch** — resolved in Task 1 by choosing `DbError::SessionMismatch` over unstable surrealdb::Error internals, as explicitly noted in the plan action.

No unresolved blocker questions. PASS.

---

## Dimension 12: Pattern Compliance — SKIPPED

No `13-PATTERNS.md` found in phase directory.

---

## Structured Issues

```yaml
issues:
  - plan: null
    dimension: dimension_8_nyquist
    severity: blocker
    description: "13-VALIDATION.md missing. nyquist_validation=true in config.json and RESEARCH.md has a Validation Architecture section. Gate 8e requires VALIDATION.md to exist before execution."
    fix_hint: "Create 13-VALIDATION.md from RESEARCH.md ## Validation Architecture section (lines 519-533 map REQ-17 behaviors to test commands). Minimum content: the Phase Requirements -> Test Map table and Wave 0 test file gaps."

  - plan: 13-01
    task: 2
    dimension: key_links_planned
    severity: warning
    description: "RESEARCH.md Q4 sample code uses get_by_id().await.unwrap().is_none() but actual return type is AxiamResult<Organization> — not Option. Plan action already corrects this, but the RESEARCH snippet will cause a compile error if copied verbatim."
    fix_hint: "Plan action is correct: assert!(result.is_err()) for wrong-ns, assert!(result.is_ok()) for re-selected. Executor must follow Task 2 <action>, not the RESEARCH Q4 code block. Consider adding a note in the task to explicitly warn against copying the RESEARCH snippet."

  - plan: 13-01
    task: 3
    dimension: task_completeness
    severity: warning
    description: "health_check return type change: current health_check returns Result<(), surrealdb::Error> but Task 3 switches it to return DbError::SessionMismatch. Callers in axiam-server (health route) call health_check — a type change may require a trivial update in main.rs. Task 3 <done> acknowledges this ('flag it in the SUMMARY') but the file is not listed in files_modified. If the caller breaks, execution fails at the verify step."
    fix_hint: "Add axiam-server/src/main.rs (or the health route file) to files_modified with a note that only the error type in the match arm needs updating. Alternatively, keep health_check returning Result<(), surrealdb::Error> and map DbError::SessionMismatch to a surrealdb error at the boundary."
```

---

## Recommendation

**1 blocker** requires resolution before execution:

- Create `13-VALIDATION.md` (content available in RESEARCH.md lines 519-533).

After the blocker is resolved, the plans are structurally sound and will achieve the phase goal. The 2 warnings are low-risk: one is a documentation clarification (RESEARCH vs PLAN discrepancy the executor should follow the plan action on), one is a possible minor ripple to a health-route caller in axiam-server.

