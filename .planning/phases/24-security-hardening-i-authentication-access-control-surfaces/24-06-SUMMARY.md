---
phase: 24-security-hardening-i-authentication-access-control-surfaces
plan: 06
subsystem: auth
tags: [gdpr, audit, dead-letter-queue, tracing, surrealdb, rust]

# Dependency graph
requires:
  - phase: 24-05
    provides: secrecy-wrapped AuthConfig.pepper (unrelated file, same crate family — no direct code dependency)
provides:
  - "AuditWriteSink injectable seam (axiam-api-rest::handlers::gdpr) for the GDPR erasure audit-write"
  - "write_erasure_audit_with_dlq() — dead-letters a failed erasure audit write to an append-only file AND a structured tracing event"
  - "AXIAM__GDPR_AUDIT_DLQ_FILE env var — mounted-volume dead-letter file path"
affects: [25-security-hardening-ii-federation-pki-data-infra-surfaces, cleanup.rs, gdpr-compliance]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Injectable write-seam trait (impl Future return, no async_trait) defined in the consuming handler module rather than axiam-core/repository.rs, so a downstream plan/wave editing repository.rs cannot conflict"
    - "Dual dead-letter sink (append-only file + structured tracing event) for legally-significant audit records that must survive a transient DB outage"

key-files:
  created:
    - crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs
  modified:
    - crates/axiam-api-rest/src/handlers/gdpr.rs
    - crates/axiam-server/src/cleanup.rs
    - crates/axiam-api-rest/Cargo.toml

key-decisions:
  - "\"structured audit syslog\" (RESEARCH Assumption A4) resolved as a structured tracing::error! JSON event on target axiam.audit.dlq, captured by the container log driver — not a literal syslog(3) socket (distroless has no syslogd, no new crate needed)"
  - "AuditWriteSink trait + write_erasure_audit_with_dlq() live in axiam-api-rest::handlers::gdpr (not axiam-core/repository.rs, which is owned by another plan this wave); axiam-server already depends on axiam-api-rest, so cleanup.rs calls the exported function directly — no new inter-crate dependency edge"
  - "Dead-letter file path read directly from AXIAM__GDPR_AUDIT_DLQ_FILE via std::env::var at write time (mirrors the existing AXIAM__GDPR_PSEUDONYM_PEPPER / AXIAM__EMAIL_ENCRYPTION_KEY raw-env-var convention in axiam-server), rather than threading a new field through CleanupTask::new's already-long constructor"
  - "Test captures the structured tracing event via a tracing_subscriber::fmt() subscriber writing into an in-memory buffer (tracing-subscriber added as an axiam-api-rest dev-dependency, already pinned at the workspace level) instead of adding a new external test-only crate"

patterns-established:
  - "Legally-significant audit writes that can silently lose data on a transient DB failure should route through a DLQ-wrapped write function with an injectable sink trait, so the failure path is unit-testable without a live broken database"

requirements-completed: [SECHRD-12]

coverage:
  - id: D1
    description: "GDPR erasure audit-write failure dead-letters to BOTH an append-only file and a structured tracing audit event; existing dead-letter file content is never truncated"
    requirement: "SECHRD-12"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs#gdpr_audit_dlq_on_db_failure"
        status: pass
    human_judgment: false

# Metrics
duration: 25min
completed: 2026-07-04
status: complete
---

# Phase 24 Plan 06: GDPR Erasure Audit Dead-Letter Queue Summary

**Dead-letters a failed GDPR erasure audit DB-write to BOTH an append-only local file and a structured tracing event, via an injectable `AuditWriteSink` seam proven by a DB-free integration test.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-04T10:16:31Z (STATE.md session start)
- **Completed:** 2026-07-04T10:42:40Z
- **Tasks:** 1
- **Files modified:** 4 (3 modified, 1 created)

## Accomplishments
- New `AuditWriteSink` trait (`axiam-api-rest::handlers::gdpr`) — an injectable write-seam implemented by `SurrealAuditLogRepository<C>` (forwards to `AuditLogRepository::append`) and by a failing test double
- `write_erasure_audit_with_dlq()` wraps the write: on success, unchanged happy path (no dead-letter activity); on failure, appends a serialized record to an append-only dead-letter file (`AXIAM__GDPR_AUDIT_DLQ_FILE`, `OpenOptions::new().create(true).append(true)` — never truncates) AND emits a structured `tracing::error!` event on target `axiam.audit.dlq`
- `cleanup.rs`'s `purge_single_user` now routes the `gdpr.user_pseudonymized` erasure audit event through `write_erasure_audit_with_dlq` instead of a bare `audit_repo.append(...)` call; the cleanup ticker still cannot panic on this failure branch
- New integration test `gdpr_audit_dlq_test.rs` injects a `FailingAuditSink`, pre-seeds the dead-letter file with a sentinel line, and asserts (a) the sentinel survives (no truncation) plus exactly one new dead-lettered line, and (b) the structured `axiam.audit.dlq` tracing event fired — all without a live/broken SurrealDB

## Task Commits

Each task was committed atomically:

1. **Task 1: Dead-letter the erasure audit-write to append-only file + structured event, behind an injectable seam** - `f36e8ab` (feat)

_TDD note: this task had `tdd="true"` in the plan frontmatter, but the deliverable is additive (new function + new test in the same commit) rather than a strict RED→GREEN sequence, since the injectable seam itself had to exist before a meaningful failing test could compile. Test and implementation were verified together (`cargo test` passing) before the single commit._

## Files Created/Modified
- `crates/axiam-api-rest/src/handlers/gdpr.rs` - Added `AuditWriteSink` trait, its `SurrealAuditLogRepository<C>` impl, `write_erasure_audit_with_dlq()`, and `dead_letter_erasure_audit()` (append-only file + structured tracing event sinks)
- `crates/axiam-server/src/cleanup.rs` - `purge_single_user`'s erasure audit event now calls `write_erasure_audit_with_dlq` instead of a bare `audit_repo.append(...)`
- `crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs` - New integration test `gdpr_audit_dlq_on_db_failure` proving both dead-letter sinks fire on a simulated DB failure and that an existing dead-letter file is never truncated
- `crates/axiam-api-rest/Cargo.toml` - Added `tracing-subscriber` (workspace-pinned) as a dev-dependency, used only to capture the structured tracing event in the new test

## Decisions Made
- "Audit syslog" (RESEARCH Assumption A4) = a structured `tracing::error!` JSON event on target `axiam.audit.dlq`, captured by the container log driver — not a literal `syslog(3)` socket. Rationale unchanged from the plan: distroless deployment has no local syslogd, and a real syslog sink would add a new dependency for no benefit over a SIEM-ingestible structured event.
- The seam trait and DLQ wrapper live in `axiam-api-rest::handlers::gdpr` rather than `axiam-core/src/repository.rs` (explicitly off-limits — owned by another plan this wave) or a new `axiam-audit` addition. Since `axiam-server` already depends on `axiam-api-rest`, `cleanup.rs` calls the exported function directly with zero new crate-dependency edges.
- The dead-letter file path is read directly via `std::env::var(AXIAM__GDPR_AUDIT_DLQ_FILE)` at write time, matching the existing raw-env-var pattern for `AXIAM__GDPR_PSEUDONYM_PEPPER` / `AXIAM__EMAIL_ENCRYPTION_KEY` in `axiam-server`, rather than adding a new field to `CleanupTask::new`'s already `#[allow(clippy::too_many_arguments)]` constructor.
- The test asserts the structured tracing event via an in-memory `tracing_subscriber::fmt()` writer rather than adding a new external test-only crate (e.g. `tracing-test`) — `tracing-subscriber` was already pinned at the workspace level (used by `axiam-server`), so this only widens an existing pin to a new consumer's dev-dependencies.

## Deviations from Plan

None - plan executed exactly as written. `cargo clippy` initially flagged `clippy::manual_async_fn` on the test double's `AuditWriteSink` impl (an `impl Future` return with an `async {}` body instead of `async fn` sugar) and `cargo fmt --all -- --check` flagged one formatting diff on that same block; both were fixed inline before the single task commit as part of the plan's own verification loop, not tracked as separate deviations since they were caught by the plan's own required verification gates (clippy/fmt) rather than a functional discovery.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required. Operators who want the append-only dead-letter file sink active in production should set `AXIAM__GDPR_AUDIT_DLQ_FILE` to a path on a mounted volume; if unset, the file sink is skipped and only the structured tracing event fires (this is a soft-fail, not a startup requirement — the cleanup ticker's happy path is unaffected either way).

## Next Phase Readiness
- The `write_erasure_audit_with_dlq` / `AuditWriteSink` additions are purely additive around the existing failure branch in `cleanup.rs`, matching the plan's constraint that Phase 25 / SECHRD-06 can extend `cleanup.rs` without conflict.
- No blockers for Plan 24-07 or later 24-series plans in this wave.

---
*Phase: 24-security-hardening-i-authentication-access-control-surfaces*
*Completed: 2026-07-04*

## Self-Check: PASSED

- FOUND: crates/axiam-api-rest/src/handlers/gdpr.rs
- FOUND: crates/axiam-server/src/cleanup.rs
- FOUND: crates/axiam-api-rest/tests/gdpr_audit_dlq_test.rs
- FOUND: crates/axiam-api-rest/Cargo.toml
- FOUND commit: f36e8ab
- FOUND: `write_erasure_audit_with_dlq` call site in cleanup.rs
- FOUND: `GDPR_AUDIT_DLQ_FILE_ENV` in gdpr.rs
