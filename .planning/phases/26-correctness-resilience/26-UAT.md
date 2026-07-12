---
status: testing
phase: 26-correctness-resilience
source: [26-VERIFICATION.md]
started: 2026-07-05T11:15:00Z
updated: 2026-07-05T11:15:00Z
---

## Current Test

number: 1
name: SurrealDB recovers from root-token expiry without a process restart (CORR-02)
expected: |
  With a live SurrealDB up (`just dev-up`), running
  `cargo test -p axiam-db --test connection_resilience_test -- --ignored`
  (recovers_from_token_expiry_without_restart) shows the DbManager
  reconnects/re-signs and health_check returns healthy again after a
  short-TTL token expiry, without restarting the process.
awaiting: user response

## Tests

### 1. SurrealDB recovers from root-token expiry without a process restart (CORR-02)
expected: With a live SurrealDB (`just dev-up`), `cargo test -p axiam-db --test connection_resilience_test -- --ignored` (recovers_from_token_expiry_without_restart) passes — DbManager reconnects/re-signs and health_check returns healthy again after a short-TTL token expiry, no process restart. (Pure-logic interval-math + health-classification tests already pass in-sandbox; only the live state-transition needs a broker.)
result: [pending]

### 2. Webhook durable delivery retries → DLQ → audit against a live RabbitMQ (CORR-03)
expected: With a live RabbitMQ (`just dev-up`), `cargo test -p axiam-api-rest --test webhook_consumer_test -- --ignored` (webhook_consumer_retries_then_dlqs_and_audits_end_to_end) passes — a queued WebhookMessage is dequeued, deliver_once runs, a failure republishes to WEBHOOK_RETRY with the computed backoff TTL, exhaustion dead-letters to WEBHOOK_DLQ, per-attempt/terminal audit records are written, and delivery resumes after a broker restart. (All consumer/topology/backoff logic is unit-tested and compiles in-sandbox; only durable-queue restart-survival + DLX routing need a live broker.)
result: [pending]

### 3. Scope decision — wire a domain-event trigger to WebhookDeliveryService::emit() (CORR-03 follow-up)
expected: Acknowledge that CORR-03's durable pipeline is proven at the mechanism level only — `grep -rn "\.emit(" crates/` confirms zero production call sites outside tests. A registered webhook will not actually receive any delivery until a follow-up wires a real domain event (e.g. user.created) to emit(). This is documented as explicitly out of CORR-03's locked scope in 26-07-SUMMARY.md (not a phase gap). Decide whether to open a follow-up FUNC requirement before relying on webhooks in production.
result: [pending]

### 4. CI E2E job runs Playwright green against the seeded backend + live Chromium (CORR-04/05/06)
expected: After pushing this branch, the CI `E2E Tests` job's `npm run test:e2e` (Playwright) step executes — not just discovers — all 14 spec files / 108 tests against a live seeded backend and Chromium, including auth-contract.spec.ts (request-body assertions), mfa-setup.spec.ts (no dead end), and the Topbar tenant-restore-after-reload assertion, and blocks the build on failure. (Specs already compile, lint, and are discoverable in-sandbox via `playwright test --list`; the sandbox proxy blocks the Chromium binary download, so the live run is CI-only.)
result: [pending]

## Summary

total: 4
passed: 0
issues: 0
pending: 4
skipped: 0
blocked: 0

## Gaps
