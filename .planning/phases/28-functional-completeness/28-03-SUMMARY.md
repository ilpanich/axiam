---
phase: 28-functional-completeness
plan: 03
subsystem: email
tags: [amqp, email-templates, surrealdb, rust, mail-consumer]

# Dependency graph
requires:
  - phase: 28-functional-completeness (plan 01/02)
    provides: baseline mail_consumer.rs / axiam-server boot wiring conventions
provides:
  - "send_with_retry_and_audit and start_mail_consumer thread a T: EmailTemplateRepository generic, fetching org/tenant custom templates by kind and resolving via the existing tenant-precedence resolve_template"
  - "Fail-safe (D-06) fallback to built-in template on any template fetch Err, mirroring the SEC-055 recipient-resolution defensive shape"
  - "axiam-server main.rs constructs SurrealEmailTemplateRepository and wires it into the live mail consumer"
affects: [email-templates-crud, tenant-branding]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fetch-then-resolve with unwrap_or_else(|e| { warn!(...); None }) defensive shape (same pattern as SEC-055 recipient resolution) applied to EmailTemplateRepository fetches"
    - "Tracing-capture test technique (BufWriter + tracing_subscriber::fmt with tracing::subscriber::set_default) reused from axiam-api-rest/tests/gdpr_audit_dlq_test.rs to assert on log content when the function under test doesn't expose an inspectable return value"

key-files:
  created: []
  modified:
    - crates/axiam-amqp/src/mail_consumer.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-amqp/tests/mail_consumer_test.rs
    - crates/axiam-amqp/Cargo.toml

key-decisions:
  - "D-06 fail-safe implemented only around the two fetch calls (get_org_template/get_tenant_template) per the plan's D-06-fetch-only-fallback decision — no render-error branch added since render/render_html are infallible"
  - "Test verification for custom-template resolution/fallback captures the EmailService::send debug log (subject field) rather than intercepting the EmailMessage directly, since send_with_retry_and_audit delivers via a real provider and returns no inspectable rendered artifact"
  - "tracing-subscriber added as a axiam-amqp dev-dependency (was not previously present) to support the log-capture test technique"

requirements-completed: [FUNC-03]

coverage:
  - id: D1
    description: "send_with_retry_and_audit/start_mail_consumer thread EmailTemplateRepository and resolve tenant/org/built-in templates via the existing resolve_template precedence (D-05)"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/tests/mail_consumer_test.rs#custom_tenant_template_is_used_when_present"
        status: pass
    human_judgment: false
  - id: D2
    description: "A template fetch Err (org or tenant) logs a warning and falls back to the built-in template instead of stranding the mail send (D-06)"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/tests/mail_consumer_test.rs#template_fetch_error_falls_back_to_builtin_and_still_attempts_delivery"
        status: pass
    human_judgment: false
  - id: D3
    description: "Live server boot wires SurrealEmailTemplateRepository into the mail consumer"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "cargo build -p axiam-server (SWAGGER_UI_DOWNLOAD_URL exported)"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-05
status: complete
---

# Phase 28 Plan 03: Wire per-org/per-tenant custom email templates into the mail consumer Summary

**`send_with_retry_and_audit`/`start_mail_consumer` now fetch org+tenant custom email templates (D-05 tenant precedence via the existing `resolve_template`) with a fail-safe fallback to the built-in on any DB fetch error (D-06), and the live server wires `SurrealEmailTemplateRepository` into the consumer at boot.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-05
- **Tasks:** 3
- **Files modified:** 4 (mail_consumer.rs, main.rs, mail_consumer_test.rs, Cargo.toml) + Cargo.lock

## Accomplishments
- `send_with_retry_and_audit` gained a fourth generic `T: EmailTemplateRepository` parameter; it now fetches `template_repo.get_org_template(msg.org_id, kind)` and `template_repo.get_tenant_template(msg.tenant_id, kind)`, each fail-safe to `None` on `Err` (logging a `warn!` with a "D-06" marker), then calls the existing (unmodified) `resolve_template(kind, org.as_ref(), tenant.as_ref())`.
- `start_mail_consumer` threads the same generic and passes `template_repo` through to `send_with_retry_and_audit` on each delivery.
- `axiam-server/src/main.rs` constructs `SurrealEmailTemplateRepository::new(db_handle.clone())` alongside the other mail-consumer repositories and passes it into `start_mail_consumer(...)`.
- Two new tests prove the behavior: a seeded tenant custom template reaches the render/send path (captured via the `EmailService::send` debug log, since the function delivers directly and returns no inspectable message), and a template-repo double that always errors on both fetches still proceeds to delivery using the built-in template (no hard `SendError`), with exactly two D-06 fallback warnings logged.

## Task Commits

Each task was committed atomically:

1. **Task 1: Thread EmailTemplateRepository into the consumer with fail-safe fetch (D-05/D-06)** - `8fa82b6` (feat)
2. **Task 2: Wire SurrealEmailTemplateRepository into main.rs** - `4d6bc25` (feat)
3. **Task 3: Test custom-template resolution + fetch-error fallback** - `c9a237e` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-amqp/src/mail_consumer.rs` - `send_with_retry_and_audit`/`start_mail_consumer` thread `T: EmailTemplateRepository`; fetch-then-resolve replaces the old `resolve_template(kind, None, None)` call, with fail-safe fallback to `None` on fetch `Err`
- `crates/axiam-server/src/main.rs` - constructs `SurrealEmailTemplateRepository` and passes it into `start_mail_consumer`
- `crates/axiam-amqp/tests/mail_consumer_test.rs` - all existing `send_with_retry_and_audit` call sites updated for the new parameter; two new tests added (custom-template-used, fetch-error-fallback) plus a local `BufWriter`/`FailingTemplateRepo` test-only helper
- `crates/axiam-amqp/Cargo.toml` - added `tracing-subscriber` as a dev-dependency (needed for the log-capture test technique)

## Decisions Made
- D-06's fail-safe scope is fetch-only (per the plan's pre-baked `D-06-fetch-only-fallback` decision) — `resolve_template`/`render`/`render_html` are infallible and untouched.
- Because `send_with_retry_and_audit` delivers via a real `EmailService`/provider and returns no inspectable rendered message, the new tests verify template-content resolution indirectly by capturing the `EmailService::send` debug log line (`subject = ...`) emitted just before the (always-failing, broker-free) SMTP attempt — the same tracing-capture technique already established in `axiam-api-rest/tests/gdpr_audit_dlq_test.rs`. This is documented in the test file's module comment.
- "Still delivers" in the D-06 fallback test is scoped to "does not surface a hard `SendError`" and "still reaches/attempts the send call" (`SendOutcome::RetryNeeded` against the fixture's unreachable fake SMTP sink) — genuine end-to-end delivery success isn't verifiable in this broker-free harness since there is no injectable mock-provider seam through the `EmailConfig` → `EmailService::from_config` path.

## Deviations from Plan

None — plan executed as written. One self-caught bug during test authoring (not a plan deviation, since it never reached a commit): the `FailingTemplateRepo` test double's error strings originally embedded the literal substring "D-06 test", which double-counted against the `warn!` log's own "D-06:" prefix in the fallback test's assertion. Fixed before any commit by rewording the test double's error messages to avoid the collision; verified via a clean 7/7 test pass afterward.

## Issues Encountered
None beyond the self-caught test-string collision above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- FUNC-03 (per-org/per-tenant email template branding) is now fully wired end-to-end: fetch → resolve → render → deliver, with a graceful fallback path.
- No template-authoring CRUD API was added in this plan (explicitly deferred per the plan's objective) — a future plan would need to add REST endpoints for tenants/orgs to actually create/manage `EmailTemplate` rows via `SurrealEmailTemplateRepository::set_org_template`/`set_tenant_template`, which already exist in the repository layer but have no HTTP surface yet.

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*
