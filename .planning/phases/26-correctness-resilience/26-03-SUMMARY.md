---
phase: 26-correctness-resilience
plan: 03
subsystem: api
tags: [webhook, amqp, rabbitmq, hmac, stripe-signature, rust, lapin]

# Dependency graph
requires:
  - phase: 26-correctness-resilience (plan 01/02)
    provides: phase scaffolding and CORR-01/CORR-02 resilience fixes (unrelated subsystems, no direct code dependency)
provides:
  - "WebhookDeliveryService::emit()/deliver_once() split (D-06) — publish-only emit, single-attempt deliver_once"
  - "compute_signature_v2 Stripe-style signed-timestamp signature (D-10)"
  - "axiam-amqp WebhookMessage DTO + queues::WEBHOOK/WEBHOOK_RETRY/WEBHOOK_DLQ + declare_webhook_topology() (D-07)"
  - "axiam-amqp WebhookPublisher (publish/publish_retry)"
affects: [26-07-webhook-consumer-wiring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Stripe-style signed-timestamp webhook signature (t=<unix>,v1=<hex hmac-sha256>) replacing body-only HMAC"
    - "AMQP-native delayed retry via per-message TTL + default-exchange DLX (no in-process sleep tying up a consumer slot)"

key-files:
  created:
    - crates/axiam-amqp/src/webhook_publisher.rs
  modified:
    - crates/axiam-api-rest/src/webhook.rs
    - crates/axiam-amqp/src/messages.rs
    - crates/axiam-amqp/src/connection.rs
    - crates/axiam-amqp/src/lib.rs

key-decisions:
  - "Added tenant_id to WebhookMessage DTO and deliver_once's parameter list — not in the plan's literal DTO/signature sketch, but required for the tenant-scoped WebhookRepository::get_by_id lookup (AXIAM's multi-tenant data-isolation model); omitting it would make deliver_once uncompilable or require an unscoped cross-tenant lookup"
  - "Removed the old deliver() method entirely rather than keeping a deprecated stub — confirmed via grep zero call sites exist anywhere in the codebase"
  - "WEBHOOK primary queue (not just WEBHOOK_RETRY) also declared with a default-exchange + x-dead-letter-routing-key DLX pointing at WEBHOOK_DLQ, so a consumer's terminal nack(requeue=false) on exhaustion actually routes to the DLQ rather than being silently dropped — inferred from PATTERNS.md's 'nack'ing to WEBHOOK_DLQ' phrasing and the truths block's 'terminal failures are replayable' requirement"
  - "Added WebhookError::WebhookLookupFailed variant (mapped to AxiamError::WebhookDelivery) to distinguish a repo-fetch failure from the existing crypto-flavored error variants"

patterns-established:
  - "compute_signature_v2(secret, timestamp, body) -> \"t={timestamp},v1={hex}\" — the canonical webhook signature helper for any future signed-webhook work"

requirements-completed: [CORR-03]

coverage:
  - id: D1
    description: "WebhookDeliveryService::deliver() split into publish-only emit() and single-attempt deliver_once(), removing the in-process retry loop and detached tokio::spawn"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/webhook.rs::tests (signature_v2_*, ssrf_*, webhook_secret_encrypt_decrypt_round_trip) — cargo test -p axiam-api-rest --lib webhook"
        status: pass
    human_judgment: false
  - id: D2
    description: "Stripe-style signed-timestamp signature (X-Axiam-Timestamp + X-Axiam-Signature: t=<unix>,v1=<hex>) replacing the body-only HMAC"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/webhook.rs::tests::signature_v2_matches_stripe_style_format, signature_v2_different_timestamps_produce_different_signatures"
        status: pass
    human_judgment: false
  - id: D3
    description: "Correctly-DLX-wired webhook AMQP topology (primary/retry/DLQ), WebhookMessage DTO, and WebhookPublisher — using the default-exchange + x-dead-letter-routing-key form (Pitfall 4), never a bare undeclared exchange name"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "crates/axiam-amqp/src/webhook_publisher.rs::tests + crates/axiam-amqp/src/messages.rs::tests — cargo test -p axiam-amqp --lib"
        status: pass
      - kind: other
        ref: "grep -n 'x-dead-letter-exchange|x-dead-letter-routing-key' crates/axiam-amqp/src/connection.rs — confirms only the empty-string default-exchange form is used for WEBHOOK/WEBHOOK_RETRY"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 03: Webhook Durable-Delivery Primitives Summary

**Split webhook delivery into publish-only emit() + single-attempt deliver_once(), upgraded signatures to Stripe-style t=/v1= HMAC, and built a correctly-DLX-wired primary/retry/DLQ AMQP topology + publisher — the transport primitives 26-07's consumer will assemble into a durable retrying delivery path.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-05T08:30:20Z
- **Completed:** 2026-07-05T08:55:00Z
- **Tasks:** 2
- **Files modified:** 4 modified, 1 created

## Accomplishments
- `WebhookDeliveryService::deliver()` (a detached `tokio::spawn` with an in-process sleep retry loop and ZERO call sites) removed entirely and replaced with:
  - `emit()` — fetches matching webhooks and publishes one `WebhookMessage` per webhook onto the durable `axiam.webhook` queue; no HTTP call, no spawn.
  - `deliver_once()` — single SSRF-guarded HTTP attempt (decrypt secret, sign, POST); returns `Result<StatusCode, WebhookError>` for the caller to decide ack/nack; no retry loop, no sleep.
- `compute_signature_v2(secret, timestamp, body)` implements the Stripe-style signed-timestamp scheme (D-10): `X-Axiam-Timestamp` + `X-Axiam-Signature: t=<unix>,v1=<hex hmac-sha256>`, replacing the old body-only signature. `X-Axiam-Event`/`X-Axiam-Delivery` unchanged.
- New `axiam-amqp` webhook AMQP topology (D-07): `queues::WEBHOOK`/`WEBHOOK_RETRY`/`WEBHOOK_DLQ` consts and `AmqpManager::declare_webhook_topology()`. WEBHOOK_RETRY's TTL-expired messages dead-letter back to WEBHOOK (native delayed retry, no in-process sleep tying up a consumer slot); WEBHOOK's terminal nacks dead-letter to WEBHOOK_DLQ. Both use the default exchange (`""`) + explicit `x-dead-letter-routing-key`, deliberately NOT copying the existing `MAIL_OUTBOUND`/`AUDIT_EVENTS`/`AUTHZ_REQUEST` pattern that names an undeclared exchange (Pitfall 4 — RabbitMQ silently drops those).
- New `WebhookMessage` DTO and `WebhookPublisher` (mirrors `MailOutboundPublisher`): `publish()` to the primary queue (persistent), `publish_retry(msg, ttl_ms)` to the retry queue with a per-message expiration.

## Task Commits

Each task was committed atomically:

1. **Task 1: Split deliver() into emit()/deliver_once() + Stripe-style signature (D-06/D-10)** - `c6b4e99` (feat)
2. **Task 2: Webhook AMQP topology, WebhookMessage DTO, and WebhookPublisher (D-07)** - `c33a708` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-api-rest/src/webhook.rs` - `deliver()` removed; `emit()`/`deliver_once()`/`compute_signature_v2()` added; `WebhookError::WebhookLookupFailed` added
- `crates/axiam-amqp/src/messages.rs` - `WebhookMessage` DTO added
- `crates/axiam-amqp/src/connection.rs` - `queues::WEBHOOK`/`WEBHOOK_RETRY`/`WEBHOOK_DLQ` + `declare_webhook_topology()` added
- `crates/axiam-amqp/src/webhook_publisher.rs` - new `WebhookPublisher` (publish/publish_retry)
- `crates/axiam-amqp/src/lib.rs` - registers `webhook_publisher` module, re-exports `WebhookMessage`/`WebhookPublisher`

## Decisions Made
- Added `tenant_id` to the `WebhookMessage` DTO and to `deliver_once`'s parameter list, beyond the plan's literal sketch (which omitted it) — `WebhookRepository::get_by_id` is tenant-scoped per AXIAM's multi-tenant data-isolation model, so `deliver_once` cannot resolve a webhook by ID alone without either an unscoped lookup (a cross-tenant data-isolation risk) or this additional field. 26-07's consumer will read `tenant_id` off the `WebhookMessage` it dequeues.
- Removed `deliver()` entirely rather than keeping a deprecated stub — `grep -rn "\.deliver("` across the repo confirmed zero call sites, matching the RESEARCH.md finding, so there was nothing to keep working during a transition window.
- Wired the primary `WEBHOOK` queue's DLX to `WEBHOOK_DLQ` (default-exchange form) in addition to `WEBHOOK_RETRY`'s DLX to `WEBHOOK` — the plan's `<behavior>` block explicitly described only the retry→primary hop, but PATTERNS.md's "nack'ing to WEBHOOK_DLQ" phrasing and the plan's own truths ("terminal failures are replayable") require the primary queue's own DLX to be correctly wired too, or a consumer's terminal `nack(requeue=false)` would have nowhere to route.
- Added `WebhookError::WebhookLookupFailed(String)`, mapped to `AxiamError::WebhookDelivery`, to distinguish a repository-fetch failure (e.g. a deleted webhook) from the existing crypto-flavored `WebhookError` variants.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added `tenant_id` to `WebhookMessage`/`deliver_once` for tenant-scoped webhook lookup**
- **Found during:** Task 1/2 (while implementing `deliver_once`'s `repo.get_by_id` call)
- **Issue:** The plan's `WebhookMessage` DTO sketch (5 fields) and `deliver_once` signature omitted `tenant_id`, but `WebhookRepository::get_by_id(tenant_id, id)` requires it to enforce AXIAM's per-tenant data isolation — without it, `deliver_once` either wouldn't compile against the trait or would need an unscoped (cross-tenant) lookup.
- **Fix:** Added `tenant_id: Uuid` as a 6th field to `WebhookMessage` and as a parameter to `deliver_once`; `emit()` populates it from its own `tenant_id` argument.
- **Files modified:** `crates/axiam-amqp/src/messages.rs`, `crates/axiam-api-rest/src/webhook.rs`
- **Verification:** `cargo test -p axiam-amqp --lib` and `cargo test -p axiam-api-rest --lib webhook` both green
- **Committed in:** `c6b4e99` (Task 1), `c33a708` (Task 2)

**2. [Rule 2 - Missing Critical] Wired WEBHOOK primary queue's own DLX to WEBHOOK_DLQ**
- **Found during:** Task 2 (declaring the webhook AMQP topology)
- **Issue:** The plan's `<behavior>` block only explicitly specified WEBHOOK_RETRY's DLX (→ WEBHOOK); without the primary WEBHOOK queue also having a correctly-wired DLX to WEBHOOK_DLQ, a consumer's terminal `nack(requeue=false)` on exhaustion would have no dead-letter target, silently dropping the message instead of the plan's stated "terminal failures are replayable" guarantee.
- **Fix:** Declared WEBHOOK with `x-dead-letter-exchange=""` and `x-dead-letter-routing-key=WEBHOOK_DLQ`, using the same correct default-exchange form as WEBHOOK_RETRY.
- **Files modified:** `crates/axiam-amqp/src/connection.rs`
- **Verification:** `grep -n "x-dead-letter-exchange|x-dead-letter-routing-key" crates/axiam-amqp/src/connection.rs` confirms only the empty-string default-exchange form for the new topology; `cargo test -p axiam-amqp --lib` green
- **Committed in:** `c33a708` (Task 2)

---

**Total deviations:** 2 auto-fixed (both Rule 2 — missing critical functionality for correctness/data-isolation)
**Impact on plan:** Both additions are structurally necessary for the primitives to compile against existing trait bounds and to satisfy the plan's own stated truths (tenant-scoped lookups, replayable terminal failures). No scope creep — no consumer or main.rs wiring was added (correctly deferred to 26-07 per this plan's explicit scope note).

## Issues Encountered
None — `SWAGGER_UI_DOWNLOAD_URL` build-env workaround applied per CLAUDE.md before every `axiam-api-rest` build/test, as instructed.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- 26-07 (Wave 2) can now wire the webhook AMQP consumer against `WebhookDeliveryService::deliver_once`, `axiam_amqp::WebhookPublisher`, `axiam_amqp::WebhookMessage`, and `AmqpManager::declare_webhook_topology` — all unit-tested without a live broker.
- Deferred to 26-07 (explicitly out of this plan's scope): the consumer itself (`webhook_consumer.rs` in `axiam-api-rest`, per this plan's architecture note), backoff-to-TTL math wiring `publish_retry`, attempt-count increment/exhaustion check against `AXIAM__WEBHOOK__MAX_ATTEMPTS`, and `main.rs` wiring (calling `declare_webhook_topology`, constructing `WebhookPublisher`, registering the consumer). A live-broker integration test proving the DLX/TTL wiring actually routes (RESEARCH's recommended `webhook_consumer_test.rs`) is also deferred to 26-07, since the consumer doesn't exist yet in this plan.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED

All created/modified files verified present on disk; both task commits (`c6b4e99`, `c33a708`) verified present in `git log --oneline --all`.
