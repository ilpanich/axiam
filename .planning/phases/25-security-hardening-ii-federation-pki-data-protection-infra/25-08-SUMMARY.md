---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 08
subsystem: infra
tags: [amqp, lapin, tokio, mail, backoff, retry, gdpr-export, surrealdb]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra (25-07)
    provides: axiam-amqp per-tenant HMAC signing conventions (unrelated subsystem, same crate)
provides:
  - In-process exponential backoff before mail RetryNeeded republish (SECHRD-08 / D-05d)
  - Hermetic end-to-end deliverability proof that a real org_id gates email-config resolution, template rendering, and the delivery attempt
affects: [25-05 (producer-side org_id resolution in cleanup.rs, still pending), 25-09, 25-10]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "In-process tokio::time::sleep backoff scaled by attempt_count before AMQP republish, mirroring webhook.rs's initial_delay * multiplier.powi(attempt - 1) shape — no broker delayed-exchange plugin"
    - "Config-resolution-as-gate test pattern: prove a value 'reaches' internal rendering logic by asserting the value's presence/absence changes whether config resolution (and therefore render+send) is reachable at all, without requiring the private render internals to be pub"

key-files:
  created: []
  modified:
    - crates/axiam-amqp/src/mail_consumer.rs
    - crates/axiam-amqp/tests/mail_consumer_test.rs

key-decisions:
  - "Backoff constants (MAIL_RETRY_INITIAL_DELAY_SECS=10.0, MAIL_RETRY_BACKOFF_MULTIPLIER=2.0, MAIL_RETRY_MAX_DELAY_SECS=3600.0) defined locally in mail_consumer.rs rather than added to a shared/config-driven RetryPolicy, since the mail path (unlike webhooks) has no per-message configurable retry policy today and MAX_RETRIES=3 is already a fixed const in the same module"
  - "backoff_delay_secs(attempt_count) takes the POST-increment retry attempt number (1 for the first retry) so the shape exactly mirrors webhook.rs's attempt-1 exponent convention"
  - "export_ready_resolves_real_org_id proves org_id reaches the rendered template context indirectly via the config-resolution gate (get_effective_config looks up by org_id first, returning None/SendError for an unseeded org_id before any rendering happens), rather than by making the private build_template_context/render_email internals pub — keeps the plan's file scope to the test file only, as specified"
  - "Test uses the existing seed_failing_email_config (127.0.0.1:1 fake SMTP sink) fixture rather than MockProvider, since send_with_retry_and_audit always builds its EmailService via EmailService::from_config (real provider), and MockProvider can only be injected via EmailService::with_provider, bypassing the config-resolution path entirely"

requirements-completed: [SECHRD-08]

coverage:
  - id: D1
    description: "Mail RetryNeeded republish waits an in-process exponential backoff (scaled by attempt_count) before basic_publish — no zero-delay hot-retry loop"
    requirement: "SECHRD-08"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/src/mail_consumer.rs#mail_retry_backoff_tests::mail_retry_backoff_is_nonzero_and_increasing"
        status: pass
      - kind: unit
        ref: "crates/axiam-amqp/src/mail_consumer.rs#mail_retry_backoff_tests::mail_retry_backoff_is_clamped"
        status: pass
    human_judgment: false
  - id: D2
    description: "ExportReady mail carrying a real org_id is deliverable end-to-end — org_id resolution gates email-config lookup, template render, and the delivery attempt (consumer half of D-05d)"
    requirement: "SECHRD-08"
    verification:
      - kind: integration
        ref: "crates/axiam-amqp/tests/mail_consumer_test.rs#export_ready_resolves_real_org_id"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 08: Mail Retry Backoff + ExportReady Deliverability Summary

**In-process exponential backoff before mail retry republish, plus a hermetic test proving a real org_id (not `Uuid::nil()`) is required to reach email-config resolution, template rendering, and delivery attempt for ExportReady mail**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-04T17:50:17Z
- **Completed:** 2026-07-04T18:15:00Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Fixed the zero-delay hot-retry loop in `mail_consumer.rs`'s `SendOutcome::RetryNeeded` branch: an in-process `tokio::time::sleep` (scaled exponentially by the retry's `attempt_count`, mirroring `webhook.rs`'s backoff shape) now runs before `basic_publish` — no broker delayed-exchange plugin, per the "no new infra" constraint
- Added `export_ready_resolves_real_org_id`, a hermetic integration test proving the consumer-side half of D-05d: a real `org_id` resolves an org-level email config and reaches a delivery attempt (`RetryNeeded` against a fake/unreachable SMTP sink), while `Uuid::nil()` (the pre-fix producer placeholder) fails closed with `SendError` before any rendering happens
- Existing nack/requeue/DLQ semantics preserved unchanged; `cargo clippy -p axiam-amqp --lib -- -D warnings` and `cargo fmt -p axiam-amqp -- --check` both clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Insert exponential backoff before the RetryNeeded republish** - `9972d7b` (fix)
2. **Task 2: End-to-end ExportReady deliverability test (real org_id reaches the template)** - `5d69372` (test)

**Plan metadata:** committed as part of this SUMMARY (see final commit)

## Files Created/Modified
- `crates/axiam-amqp/src/mail_consumer.rs` - Added `backoff_delay_secs()` pure function + 3 local backoff constants; inserted `tokio::time::sleep` before `basic_publish` in the `RetryNeeded` branch; added 3 unit tests covering nonzero/increasing/clamped backoff
- `crates/axiam-amqp/tests/mail_consumer_test.rs` - Added `export_ready_resolves_real_org_id` integration test (real-org_id positive case + `Uuid::nil()` negative control)

## Decisions Made
- Backoff constants defined locally in `mail_consumer.rs` (initial delay 10s, multiplier 2.0, cap 3600s) rather than threaded through a config struct — the mail path has no existing per-message `RetryPolicy` analog to webhook's, and `MAX_RETRIES` is already a fixed module-level const
- `backoff_delay_secs` takes the post-increment retry attempt number so the exponent shape (`attempt - 1`) matches `webhook.rs` exactly
- The deliverability test proves "org_id reaches the rendered template context" via the config-resolution gate (`get_effective_config` looks up by `org_id` first and returns `None` for an unseeded id, short-circuiting before `render_email` ever runs) rather than exposing the private `build_template_context`/`render_email` internals as `pub` — this keeps the plan's file-modification scope to the test file only, as specified in the plan frontmatter
- Reused the existing `seed_failing_email_config` fixture (SMTP pointed at `127.0.0.1:1`, an address nothing listens on) instead of `MockProvider`, since `send_with_retry_and_audit` always builds its `EmailService` via `EmailService::from_config` (the real provider path) — `MockProvider` can only be injected via `EmailService::with_provider`, which bypasses config resolution entirely and would not prove the org_id-gates-config-gates-render chain

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched their `<action>` and `<acceptance_criteria>` blocks precisely; no Rule 1-4 auto-fixes were needed.

## Issues Encountered

None. The build/test loop was slow the first time due to a cold `target/` (axiam-amqp pulls in axiam-auth/axiam-email/axiam-db/lapin/actix-web transitively — ~4 min initial compile), but all scoped `cargo test -p axiam-amqp` / `cargo clippy -p axiam-amqp --lib` / `cargo fmt -p axiam-amqp -- --check` commands completed cleanly with no ENOSPC pressure (19GB free before and after).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The consumer-side half of SECHRD-08 / D-05d is complete: the mail consumer backs off before retrying, and a real `org_id` is proven necessary for ExportReady mail to reach delivery.
- **Still outstanding (owned by plan 25-05, not this plan):** the producer-side fix — `crates/axiam-server/src/cleanup.rs:509` still enqueues `org_id: Uuid::nil()` for ExportReady mail. Until 25-05 lands, real-world ExportReady mail sent via `cleanup.rs`'s export sweep will still hit the `SendError` fail-closed path this plan's negative-control test reproduces (i.e., GDPR export-ready notifications are currently NOT deliverable in production — this plan only proves the mechanism and the fix's shape; it does not itself unblock ExportReady mail delivery end-to-end).
- No blockers for plans 25-09/25-10.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*
