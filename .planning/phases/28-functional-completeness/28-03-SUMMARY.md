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
  created:
    - crates/axiam-amqp/tests/mail_consumer_template_test.rs
  modified:
    - crates/axiam-amqp/src/mail_consumer.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-amqp/tests/mail_consumer_test.rs
    - crates/axiam-amqp/Cargo.toml

key-decisions:
  - "D-06 fail-safe implemented only around the two fetch calls (get_org_template/get_tenant_template) per the plan's D-06-fetch-only-fallback decision — no render-error branch added since render/render_html are infallible"
  - "Test verification for custom-template resolution/fallback captures the EmailService::send debug log (subject field) rather than intercepting the EmailMessage directly, since send_with_retry_and_audit delivers via a real provider and returns no inspectable rendered artifact"
  - "tracing-subscriber added as a axiam-amqp dev-dependency (was not previously present) to support the log-capture test technique"
  - "The two tracing-capturing tests were moved into their own test binary (mail_consumer_template_test.rs) after an empirically-confirmed process-global tracing::Interest-cache race with mail_consumer_test.rs's other five tests caused ~50% intermittent failures under cargo test's default parallel runner; isolated into its own process (mirroring gdpr_audit_dlq_test.rs) plus a tokio::sync::Mutex serializing the two tests against each other end-to-end (async-aware, safe across .await, unlike std::sync::Mutex which clippy::await_holding_lock flags)"

requirements-completed: [FUNC-03]

coverage:
  - id: D1
    description: "send_with_retry_and_audit/start_mail_consumer thread EmailTemplateRepository and resolve tenant/org/built-in templates via the existing resolve_template precedence (D-05)"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/tests/mail_consumer_template_test.rs#custom_tenant_template_is_used_when_present"
        status: pass
    human_judgment: false
  - id: D2
    description: "A template fetch Err (org or tenant) logs a warning and falls back to the built-in template instead of stranding the mail send (D-06)"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/tests/mail_consumer_template_test.rs#template_fetch_error_falls_back_to_builtin_and_still_attempts_delivery"
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

duration: 35min
completed: 2026-07-05
status: complete
---

# Phase 28 Plan 03: Wire per-org/per-tenant custom email templates into the mail consumer Summary

**`send_with_retry_and_audit`/`start_mail_consumer` now fetch org+tenant custom email templates (D-05 tenant precedence via the existing `resolve_template`) with a fail-safe fallback to the built-in on any DB fetch error (D-06), and the live server wires `SurrealEmailTemplateRepository` into the consumer at boot.**

## Performance

- **Duration:** ~35 min (includes diagnosing and fixing an intermittent test flake)
- **Completed:** 2026-07-05
- **Tasks:** 3
- **Files modified:** 5 (mail_consumer.rs, main.rs, mail_consumer_test.rs, mail_consumer_template_test.rs [new], Cargo.toml) + Cargo.lock

## Accomplishments
- `send_with_retry_and_audit` gained a fourth generic `T: EmailTemplateRepository` parameter; it now fetches `template_repo.get_org_template(msg.org_id, kind)` and `template_repo.get_tenant_template(msg.tenant_id, kind)`, each fail-safe to `None` on `Err` (logging a `warn!` with a "D-06" marker), then calls the existing (unmodified) `resolve_template(kind, org.as_ref(), tenant.as_ref())`.
- `start_mail_consumer` threads the same generic and passes `template_repo` through to `send_with_retry_and_audit` on each delivery.
- `axiam-server/src/main.rs` constructs `SurrealEmailTemplateRepository::new(db_handle.clone())` alongside the other mail-consumer repositories and passes it into `start_mail_consumer(...)`.
- Two new tests prove the behavior: a seeded tenant custom template reaches the render/send path (captured via the `EmailService::send` debug log, since the function delivers directly and returns no inspectable message), and a template-repo double that always errors on both fetches still proceeds to delivery using the built-in template (no hard `SendError`), with exactly two D-06 fallback warnings logged. These two tests live in their own test binary (`mail_consumer_template_test.rs`) after a flaky-test investigation — see Deviations.

## Task Commits

Each task was committed atomically:

1. **Task 1: Thread EmailTemplateRepository into the consumer with fail-safe fetch (D-05/D-06)** - `8fa82b6` (feat)
2. **Task 2: Wire SurrealEmailTemplateRepository into main.rs** - `4d6bc25` (feat)
3. **Task 3: Test custom-template resolution + fetch-error fallback** - `c9a237e` (test)
4. **Flaky-test fix (Rule 1 — discovered after Task 3's initial commit): isolate tracing-capturing tests into their own binary** - `08837e9` (fix)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-amqp/src/mail_consumer.rs` - `send_with_retry_and_audit`/`start_mail_consumer` thread `T: EmailTemplateRepository`; fetch-then-resolve replaces the old `resolve_template(kind, None, None)` call, with fail-safe fallback to `None` on fetch `Err`
- `crates/axiam-server/src/main.rs` - constructs `SurrealEmailTemplateRepository` and passes it into `start_mail_consumer`
- `crates/axiam-amqp/tests/mail_consumer_test.rs` - all existing `send_with_retry_and_audit` call sites updated for the new parameter; the two new template tests were moved OUT of this file (see below)
- `crates/axiam-amqp/tests/mail_consumer_template_test.rs` (new) - the two new tests (custom-template-used, fetch-error-fallback) plus file-local `BufWriter`/`FailingTemplateRepo`/test-fixture helpers, isolated into their own cargo test binary/process
- `crates/axiam-amqp/Cargo.toml` - added `tracing-subscriber` as a dev-dependency (needed for the log-capture test technique)

## Decisions Made
- D-06's fail-safe scope is fetch-only (per the plan's pre-baked `D-06-fetch-only-fallback` decision) — `resolve_template`/`render`/`render_html` are infallible and untouched.
- Because `send_with_retry_and_audit` delivers via a real `EmailService`/provider and returns no inspectable rendered message, the new tests verify template-content resolution indirectly by capturing the `EmailService::send` debug log line (`subject = ...`) emitted just before the (always-failing, broker-free) SMTP attempt — the same tracing-capture technique already established in `axiam-api-rest/tests/gdpr_audit_dlq_test.rs`. This is documented in the test file's module comment.
- "Still delivers" in the D-06 fallback test is scoped to "does not surface a hard `SendError`" and "still reaches/attempts the send call" (`SendOutcome::RetryNeeded` against the fixture's unreachable fake SMTP sink) — genuine end-to-end delivery success isn't verifiable in this broker-free harness since there is no injectable mock-provider seam through the `EmailConfig` → `EmailService::from_config` path.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Intermittent tracing-capture test flake from a process-global Interest-cache race**
- **Found during:** Task 3 (post-commit `c9a237e` stability re-check — running `cargo test -p axiam-amqp --test mail_consumer_test` repeatedly surfaced an intermittent failure not seen in the initial single run)
- **Issue:** `custom_tenant_template_is_used_when_present` and `template_fetch_error_falls_back_to_builtin_and_still_attempts_delivery` (both added in Task 3) capture `tracing` debug/warn output via a thread-local `tracing::subscriber::set_default` override. `tracing`'s per-callsite `Interest` cache that a `set_default`/guard-drop invalidates via `rebuild_interest_cache()` is **process-global**, not per-thread. Sharing `mail_consumer_test.rs`'s process with the other five (unrelated, non-tracing) tests running concurrently under cargo test's default parallel runner caused an intermittent race (~50% failure rate empirically) where a concurrent test's SurrealDB/tokio-runtime lifecycle transition silently re-cached these two tests' callsites as "never enabled," dropping the captured log content the assertions depended on. Confirmed via diagnostic markers: a `tracing::error!` fired immediately after `set_default` was reliably captured, but every event fired deeper in `send_with_retry_and_audit` (after intervening `.await` points) was intermittently lost — 100% reproducible under default parallel scheduling, 100% passing under `--test-threads=1`.
- **Fix:** Moved both tests (+ their `BufWriter`/`FailingTemplateRepo` helpers) into a new file `crates/axiam-amqp/tests/mail_consumer_template_test.rs` — a separate cargo test binary/process, completely isolating them from `mail_consumer_test.rs`'s other five tests. This mirrors the existing `axiam-api-rest/tests/gdpr_audit_dlq_test.rs` precedent (the sole test in its file, for the identical reason, per that file's own doc comment). As defense in depth, the two tests in the new file also serialize against each other end-to-end (from before `setup_db()` through the final log assertion) via a `tokio::sync::Mutex` held across `.await` — chosen over `std::sync::Mutex` because the latter trips `clippy::await_holding_lock` when a guard is held across an await point.
- **Files modified:** `crates/axiam-amqp/tests/mail_consumer_test.rs` (tests removed, helpers/imports trimmed), `crates/axiam-amqp/tests/mail_consumer_template_test.rs` (new)
- **Verification:** `cargo test -p axiam-amqp --test mail_consumer_test --test mail_consumer_template_test` run 15 consecutive times under default parallel scheduling — 0 failures (vs. the prior ~50% flake rate). `cargo clippy -p axiam-amqp --tests` clean (no `await_holding_lock` or other new warnings).
- **Committed in:** `08837e9`

---

**Total deviations:** 1 auto-fixed (Rule 1 — flaky test introduced by this plan's own Task 3, caught and fixed before plan completion)
**Impact on plan:** No scope creep — the fix is entirely test-infrastructure (no production code touched) and makes the plan's own Task 3 verification criterion (`cargo test -p axiam-amqp --test mail_consumer_test` exits 0) actually reliable rather than nondeterministic.

## Issues Encountered
- `gsd-tools query requirements.mark-complete FUNC-03` returned `not_found`. Pre-existing structural mismatch between this project's `REQUIREMENTS.md` format (heading-per-requirement `## FUNC-03: ...`, plain unlabeled acceptance-criteria checkboxes, and a 4-column traceability table) and the tool's expected `- [ ] **REQ-ID**` bold-checkbox / 3-column-table conventions — not something introduced by this plan (28-01's SUMMARY also lists `requirements-completed: [FUNC-03]` yet the traceability row is still `Pending`, so this gap predates this plan). Not fixed here: rewriting REQUIREMENTS.md's format is out of this plan's scope. FUNC-03 has three ACs (T19.20/21/22); this plan closes only the T19.21 (custom-template resolution) AC, so the requirement row should stay `Pending` until the other two ACs are also verified regardless.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- FUNC-03 (per-org/per-tenant email template branding) is now fully wired end-to-end: fetch → resolve → render → deliver, with a graceful fallback path.
- No template-authoring CRUD API was added in this plan (explicitly deferred per the plan's objective) — a future plan would need to add REST endpoints for tenants/orgs to actually create/manage `EmailTemplate` rows via `SurrealEmailTemplateRepository::set_org_template`/`set_tenant_template`, which already exist in the repository layer but have no HTTP surface yet.

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*

## Self-Check: PASSED

All modified files confirmed present on disk and all task/summary commit hashes confirmed present in git log.
