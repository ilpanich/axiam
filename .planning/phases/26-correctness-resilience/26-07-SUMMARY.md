---
phase: 26-correctness-resilience
plan: 07
subsystem: api
tags: [webhook, amqp, rabbitmq, lapin, retry, backoff, audit, rust]

# Dependency graph
requires:
  - phase: 26-correctness-resilience (plan 03)
    provides: "WebhookDeliveryService::emit()/deliver_once() split, Stripe-style signature, axiam-amqp WebhookMessage/WebhookPublisher/declare_webhook_topology (the primitives this plan assembles into a running delivery path)"
provides:
  - "crates/axiam-api-rest/src/webhook_consumer.rs: WebhookRetryConfig (AXIAM__WEBHOOK__* env knobs, D-20), backoff_ttl_ms (bounded exponential backoff, D-08), start_webhook_consumer (the durable AMQP consumer, D-06/D-07/D-09)"
  - "axiam-server main.rs wiring: declare_webhook_topology + WebhookPublisher construction + start_webhook_consumer spawn, publisher registered as app_data"
  - "crates/axiam-api-rest/tests/webhook_consumer_test.rs: broker-free attempt-increment/backoff assertions + an #[ignore]d live-RabbitMQ end-to-end retry/DLQ/audit integration test"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "AMQP consumer with native TTL+DLX retry scheduling (no in-process sleep tying up a consumer slot) — mirrors mail_consumer.rs's consume/ack/nack/republish shape but diverges on the retry mechanism per D-07/Pitfall 5"
    - "Uuid::nil() + ActorType::System for audit records with no human/service-account actor (mirrors axiam-federation::secrets and mail_consumer's existing convention)"

key-files:
  created:
    - crates/axiam-api-rest/src/webhook_consumer.rs
    - crates/axiam-api-rest/tests/webhook_consumer_test.rs
  modified:
    - crates/axiam-api-rest/src/lib.rs
    - crates/axiam-api-rest/Cargo.toml
    - crates/axiam-server/src/main.rs

key-decisions:
  - "Added lapin + futures-lite as direct axiam-api-rest dependencies (workspace-pinned versions already resolved via axiam-amqp's existing use — no new external package) so webhook_consumer.rs can drive lapin::Channel directly, mirroring mail_consumer.rs's shape, per the plan's architecture note that the consumer cannot live in axiam-amqp"
  - "The live-broker integration test's webhook target is deliberately a loopback URL (https://127.0.0.1:9/...) rather than a local HTTP sink the test process stands up — deliver_once's ssrf::guarded_fetch hardcodes allow_private=false in the production path (26-03/T-26-07-01), so ANY local target is deterministically SSRF-blocked regardless of broker presence; this proves the guard survives being driven from AMQP and exercises the full retry->backoff->DLQ->audit pipeline via that deterministic failure, rather than claiming to prove a successful signed HTTP delivery the current architecture cannot exercise locally"
  - "actor_id: Uuid::nil() / ActorType::System for all three webhook.delivery_* audit records — no human or service-account initiates an AMQP-driven delivery attempt, matching the existing convention in mail_consumer.rs and axiam-federation::secrets.rs"

patterns-established:
  - "backoff_ttl_ms(attempt, cfg) — bounded exponential backoff expressed directly as an AMQP retry-queue TTL (milliseconds), not an in-process sleep duration; the canonical shape for any future AMQP-consumer retry policy in this codebase"

requirements-completed: [CORR-03]

coverage:
  - id: D1
    description: "WebhookRetryConfig reads AXIAM__WEBHOOK__MAX_ATTEMPTS/BACKOFF_BASE_MS/BACKOFF_CEILING_MS with safe defaults; backoff_ttl_ms computes a nonzero, increasing, ceiling-clamped retry-queue TTL (D-08/D-20)"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/webhook_consumer.rs::webhook_consumer_tests (backoff_ttl_ms_nonzero_at_attempt_1, backoff_ttl_ms_increases_until_ceiling, backoff_ttl_ms_clamped_to_ceiling, backoff_ttl_ms_never_negative_defensively, webhook_retry_config_defaults_resolve_when_env_unset) — cargo test -p axiam-api-rest --lib webhook_consumer"
        status: pass
    human_judgment: false
  - id: D2
    description: "start_webhook_consumer drives deliver_once once per (re)delivery, retries via WEBHOOK_RETRY TTL+DLX with attempt-count increment and per-attempt audit, dead-letters exhausted deliveries to WEBHOOK_DLQ with a terminal audit record, and performs zero in-process wait"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "cargo build -p axiam-api-rest --lib (compiles against WebhookDeliveryService/WebhookPublisher/AuditLogRepository trait bounds) + grep -c tokio::time::sleep crates/axiam-api-rest/src/webhook_consumer.rs == 0 + grep publish_retry/webhook.delivery_* action strings present"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/tests/webhook_consumer_test.rs::simulated_first_failure_computes_expected_retry_ttl, simulated_second_failure_computes_larger_retry_ttl_than_first, webhook_message_round_trips_with_incremented_attempt"
        status: pass
    human_judgment: false
  - id: D3
    description: "main.rs declares the webhook topology, constructs a WebhookPublisher, and spawns start_webhook_consumer on startup; zero remaining .deliver( call sites reconfirmed"
    requirement: CORR-03
    verification:
      - kind: unit
        ref: "cargo build -p axiam-server --bin axiam-server + grep declare_webhook_topology/WebhookPublisher::new/start_webhook_consumer crates/axiam-server/src/main.rs + grep -rn '\\.deliver(' (zero hits)"
        status: pass
    human_judgment: false
  - id: D4
    description: "End-to-end proof against a live RabbitMQ broker: queued delivery dequeued -> deliver_once invoked -> failure retried via TTL+DLX -> exhaustion dead-letters to WEBHOOK_DLQ -> per-attempt + terminal audit records written"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/webhook_consumer_test.rs::webhook_consumer_retries_then_dlqs_and_audits_end_to_end (#[ignore]d — run via `just dev-up` then `cargo test -p axiam-api-rest --test webhook_consumer_test -- --ignored`)"
        status: unknown
    human_judgment: true
    rationale: "This sandbox has no live RabbitMQ broker (documented constraint of this execution environment), so the #[ignore]d test could not actually be run here — it was only verified to compile cleanly (cargo test -p axiam-api-rest --test webhook_consumer_test, non-ignored subset green). A human (or a CI job with `just dev-up`) must run it with --ignored to confirm the real TTL+DLX/DLQ/audit behavior against a live broker before this is considered fully proven end-to-end."

# Metrics
duration: 35min
completed: 2026-07-05
status: complete
---

# Phase 26 Plan 07: Webhook Durable-Delivery Consumer Summary

**Assembled the durable, retrying, auditable webhook delivery path (CORR-03 part 2/2): a lapin-driven AMQP consumer in axiam-api-rest that calls `deliver_once` once per (re)delivery, schedules retries via the retry-queue's native TTL+DLX (bounded exponential backoff read from `AXIAM__WEBHOOK__*`), writes per-attempt/terminal audit records, routes exhausted deliveries to the replayable DLQ, and is wired into `main.rs` on startup.**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-07-05T09:50:00Z
- **Completed:** 2026-07-05T10:20:00Z
- **Tasks:** 3
- **Files modified:** 3 modified, 2 created

## Accomplishments
- `crates/axiam-api-rest/src/webhook_consumer.rs` (new): `WebhookRetryConfig` reads `AXIAM__WEBHOOK__MAX_ATTEMPTS` (default 5), `AXIAM__WEBHOOK__BACKOFF_BASE_MS` (default 5s), `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` (default 1h) with `.unwrap_or(default)` safe defaults (mirrors the `trusted_hops_from_env` precedent). `backoff_ttl_ms(attempt, cfg)` computes `base*multiplier^(attempt-1)` clamped to the ceiling — the value becomes the retry-queue's per-message TTL, never an in-process sleep.
- `start_webhook_consumer` consumes `queues::WEBHOOK`, deserializes `WebhookMessage` (bad payload -> nack requeue:false), and calls `WebhookDeliveryService::deliver_once` exactly once per delivery — the same SSRF-guarded, secret-decrypting path from 26-03, unbypassed (T-26-07-01). On 2xx: ack + terminal `webhook.delivery_succeeded` audit. On failure with retries remaining: `publisher.publish_retry` to `WEBHOOK_RETRY` with `expiration = backoff_ttl_ms(...)`, per-attempt `webhook.delivery_attempt` audit, then ack the original — the retry re-enters `WEBHOOK` via TTL+DLX with zero consumer-slot-holding wait (D-07). On exhaustion: nack requeue:false -> `WEBHOOK_DLQ` (replayable) + terminal `webhook.delivery_failed` audit.
- `main.rs`: `amqp.declare_webhook_topology()` alongside `declare_queues()`; a `WebhookPublisher` built on a dedicated publisher channel; `start_webhook_consumer` spawned on its own consumer channel with `WebhookRetryConfig::from_env()`; the publisher registered as `app_data` so a future `emit()` REST call site can extract it (no such call site exists yet — out of this plan's locked scope, see Residual Scope Notes below).
- `crates/axiam-api-rest/tests/webhook_consumer_test.rs` (new): 3 non-ignored broker-free assertions (attempt-increment round-trip, simulated-failure backoff-TTL math) plus an `#[ignore]`d live-RabbitMQ integration test proving the full dequeue -> retry -> DLQ -> audit pipeline end-to-end.

## Task Commits

Each task was committed atomically:

1. **Task 1: Webhook retry config knobs + bounded exponential backoff (D-08/D-20)** - `4014655` (feat)
2. **Task 2: Webhook consumer loop — deliver_once + TTL/DLX retry + audit (D-06/D-07/D-09)** - `f3dbb6d` (feat)
3. **Task 3: Wire topology/publisher/consumer into main.rs + integration test (D-06)** - `405ea29` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified
- `crates/axiam-api-rest/src/webhook_consumer.rs` - `WebhookRetryConfig`, `backoff_ttl_ms`, `start_webhook_consumer`, `handle_delivery_failure`, `build_audit_entry`
- `crates/axiam-api-rest/src/lib.rs` - `pub mod webhook_consumer;`
- `crates/axiam-api-rest/Cargo.toml` - added `lapin`/`futures-lite` (workspace-pinned, no new external package)
- `crates/axiam-server/src/main.rs` - `declare_webhook_topology()` call, `WebhookPublisher` construction, `start_webhook_consumer` spawn, publisher registered as `app_data`
- `crates/axiam-api-rest/tests/webhook_consumer_test.rs` - broker-free unit assertions + `#[ignore]`d live-broker integration test

## Decisions Made
- Added `lapin` + `futures-lite` as direct `axiam-api-rest` dependencies (workspace-pinned versions already resolved in `Cargo.lock` via `axiam-amqp`'s existing use — not a new external package fetch) since `webhook_consumer.rs` drives `lapin::Channel` directly, per the plan's architecture note placing the consumer in `axiam-api-rest` rather than `axiam-amqp`.
- The live-broker integration test targets a loopback URL rather than a local HTTP sink the test process stands up. `deliver_once`'s `ssrf::guarded_fetch` call hardcodes `allow_private=false` in the production path (established in 26-03 for T-26-07-01), so any local delivery target is deterministically `SsrfBlocked` regardless of whether a live broker is available. The test uses this deterministic failure to exercise the full retry -> backoff -> DLQ -> audit pipeline, and documents in-file why it cannot instead claim to prove a successful signed HTTP delivery to a local sink — the current architecture's fail-closed SSRF guard makes that impossible to test locally by design, and weakening the guard to make it testable was correctly out of scope.
- All three `webhook.delivery_*` audit records use `actor_id: Uuid::nil()` + `ActorType::System` — no human or service-account initiates an AMQP-driven delivery attempt, matching the existing convention already used by `mail_consumer.rs` and `axiam-federation::secrets.rs`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `lapin`/`futures-lite` to `axiam-api-rest`'s `Cargo.toml`**
- **Found during:** Task 1 (creating `webhook_consumer.rs`)
- **Issue:** The plan requires `webhook_consumer.rs` to drive `lapin::Channel` directly (mirroring `mail_consumer.rs`'s shape), but `axiam-api-rest` did not previously depend on `lapin`/`futures-lite` directly (only transitively via `axiam-amqp`) — without adding them, the crate would not compile.
- **Fix:** Added `lapin = { workspace = true }` and `futures-lite = { workspace = true }` to `crates/axiam-api-rest/Cargo.toml`. Both versions are already pinned in the workspace root `Cargo.toml` and already resolved in `Cargo.lock` (via `axiam-amqp`'s existing dependency) — this is a workspace-internal dependency-graph correction, not a new external package fetch, so it does not fall under the package-manager-install exclusion (Rule 3's carve-out is for installing a *new, unverified* package name).
- **Verification:** `cargo build -p axiam-api-rest --lib` and `cargo test -p axiam-api-rest --lib webhook_consumer` both green.
- **Committed in:** `4014655` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking dependency-graph gap, workspace-pinned versions only)
**Impact on plan:** Structurally necessary for Task 1-3 to compile against the plan's own architecture note (consumer lives in `axiam-api-rest`, drives `lapin::Channel` directly). No scope creep, no new external package.

## Issues Encountered
None — `SWAGGER_UI_DOWNLOAD_URL` build-env workaround applied per CLAUDE.md before every `axiam-api-rest`/`axiam-server` build/test, as instructed. `cargo clean` run after all builds/tests completed (disk hygiene, between-plan gap per CLAUDE.md).

## User Setup Required
None - no external service configuration required for the code to build/run. The `#[ignore]`d live-broker integration test (`webhook_consumer_retries_then_dlqs_and_audits_end_to_end`) requires `just dev-up` (a live RabbitMQ instance) to actually execute — see coverage item D4.

## Next Phase Readiness
- CORR-03 is now fully implemented: durable AMQP-driven webhook delivery with native TTL+DLX retry, replayable DLQ, and full audit trail, matching the phase's success criteria (ROADMAP SC #3).
- Residual scope notes carried forward from the plan (both explicitly out of CORR-03's locked scope, not gaps in this plan):
  1. `emit()` is wired for durable delivery (publisher registered as `app_data`) but no REST-handler/domain-event call site invokes it on a real event yet (e.g. `user.created`) — a follow-up FUNC requirement would add that wiring.
  2. The pre-existing DLX gap on `AUDIT_EVENTS`/`AUTHZ_REQUEST`/`MAIL_OUTBOUND` (RESEARCH Pitfall 4/A1) remains a known, separately-tracked follow-up; the new webhook topology deliberately avoids the same mistake.
- The `#[ignore]`d live-broker integration test (D4) should be run with `just dev-up` + `--ignored` by a human or CI job with broker access before CORR-03 is considered fully proven end-to-end against a real RabbitMQ instance.

---
*Phase: 26-correctness-resilience*
*Completed: 2026-07-05*

## Self-Check: PASSED

All created/modified files verified present on disk; all three task commits (`4014655`, `f3dbb6d`, `405ea29`) verified present in `git log --oneline --all`.
