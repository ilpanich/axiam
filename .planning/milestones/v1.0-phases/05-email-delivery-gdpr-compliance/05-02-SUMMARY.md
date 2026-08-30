---
phase: 05-email-delivery-gdpr-compliance
plan: "02"
subsystem: amqp
tags: [amqp, lapin, rabbitmq, serde, dead-letter-queue, gdpr, mail]

requires:
  - phase: 05-email-delivery-gdpr-compliance
    provides: Phase 5 context, D-14 async mail decision, queue declaration patterns

provides:
  - OutboundMailMessage struct with five MailType variants (serde round-trip tested)
  - axiam.mail.outbound queue declared with x-dead-letter-exchange to DLQ (D-14)
  - axiam.mail.outbound.dlq plain-durable dead-letter queue
  - MAIL_OUTBOUND / MAIL_OUTBOUND_DLQ constants in queues module
  - Types re-exported from axiam-amqp crate public API for Plans 03/04 consumption

affects:
  - 05-03-PLAN (mail consumer reads OutboundMailMessage from axiam.mail.outbound)
  - 05-04-PLAN (handlers enqueue OutboundMailMessage via MAIL_OUTBOUND constant)
  - axiam-amqp (queue topology updated)

tech-stack:
  added: []
  patterns:
    - "DLQ-wired AMQP queue: declare DLQ first (plain durable), then main queue with FieldTable x-dead-letter-exchange pointing at DLQ"
    - "AMQP message type: derive Debug+Clone+Serialize+Deserialize; snake_case enum variant names via serde(rename_all)"

key-files:
  created: []
  modified:
    - crates/axiam-amqp/src/messages.rs
    - crates/axiam-amqp/src/connection.rs
    - crates/axiam-amqp/src/lib.rs

key-decisions:
  - "MAIL_OUTBOUND_DLQ added to ALL_QUEUES plain-durable loop; MAIL_OUTBOUND declared separately with FieldTable to preserve DLQ-first ordering required by broker"
  - "to_address field documented delivery-only with MUST NOT log warning (D-16) inline in struct definition and field doc comment"
  - "MailType uses serde(rename_all = snake_case) for wire format stability across consumer versions"

patterns-established:
  - "DLQ declaration: declare DLQ in ALL_QUEUES loop first, then declare main queue separately with x-dead-letter-exchange FieldTable arg"
  - "Mail message type: OutboundMailMessage carries attempt_count for consumer retry tracking without external state"

requirements-completed: [REQ-6]

duration: 8min
completed: 2026-06-02
---

# Phase 05 Plan 02: AMQP Mail Transport Summary

**OutboundMailMessage (five MailType variants) + axiam.mail.outbound queue with explicit x-dead-letter-exchange DLQ wiring (D-14) added to axiam-amqp**

## Performance

- **Duration:** 8 min
- **Started:** 2026-06-02T14:30:00Z
- **Completed:** 2026-06-02T14:38:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Added `OutboundMailMessage` and `MailType` enum (PasswordReset, EmailVerification, Notification, DeletionCancel, ExportReady) with serde round-trip + snake_case serialization tests
- Declared `axiam.mail.outbound.dlq` as plain-durable and `axiam.mail.outbound` with `x-dead-letter-exchange` FieldTable arg pointing at the DLQ — explicit broker-side dead-letter routing (D-14, no reliance on broker defaults)
- Re-exported `OutboundMailMessage`, `MailType`, and `queues` from `axiam_amqp` public API for Plans 03/04

## Task Commits

1. **Task 1: OutboundMailMessage + MailType in messages.rs** - `cc98f8f` (feat)
2. **Task 2: mail.outbound queue + DLQ declaration in connection.rs** - `ec63ca7` (feat)

**Plan metadata:** (docs commit below)

## Files Created/Modified

- `crates/axiam-amqp/src/messages.rs` - OutboundMailMessage + MailType enum + serde tests
- `crates/axiam-amqp/src/connection.rs` - MAIL_OUTBOUND/MAIL_OUTBOUND_DLQ constants + DLQ-wired queue declaration
- `crates/axiam-amqp/src/lib.rs` - Re-exports OutboundMailMessage, MailType, queues

## Decisions Made

- MAIL_OUTBOUND_DLQ placed in ALL_QUEUES loop (declared first) and MAIL_OUTBOUND declared after via separate explicit call — ensures DLQ exists before the main queue references it
- `to_address` documented in-struct as "delivery only — MUST NOT be logged in audit" to surface D-16 constraint at the definition site, not only in docs

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Queue declarations match plan threat model (T-5-mail-drop mitigated by x-dead-letter-exchange; T-5-addr-leak mitigated by field documentation; T-5-SC accepted per plan).

## Known Stubs

None.

## Self-Check: PASSED

- `crates/axiam-amqp/src/messages.rs` — exists, contains OutboundMailMessage
- `crates/axiam-amqp/src/connection.rs` — exists, contains x-dead-letter-exchange, MAIL_OUTBOUND, MAIL_OUTBOUND_DLQ
- Commits cc98f8f and ec63ca7 verified in git log
- `cargo check -p axiam-amqp --tests` output: no errors

## Next Phase Readiness

- Plan 03 (mail consumer) can import `OutboundMailMessage`, `MailType`, `queues::MAIL_OUTBOUND` from `axiam_amqp`
- Plan 04 (handler enqueue stubs) can use same imports to publish to `MAIL_OUTBOUND`
- Queue topology is broker-ready; no further AMQP infrastructure work needed for this feature

---
*Phase: 05-email-delivery-gdpr-compliance*
*Completed: 2026-06-02*
