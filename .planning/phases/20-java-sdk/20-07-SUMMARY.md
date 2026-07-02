---
phase: 20-java-sdk
plan: 07
subsystem: sdk
tags: [java, amqp, rabbitmq, hmac, security, ack-nack]

# Dependency graph
requires:
  - phase: 20-java-sdk (20-02)
    provides: "Hmac.verify(signingKey, body) and ErrDrop sentinel — the proven HMAC-SHA256 canonicalize+constant-time-compare primitive and poison-message signal this plan wires into the consumer's ack/nack decision"
  - phase: 20-java-sdk (20-03)
    provides: "sdks/java module conventions (package layout, javadoc style) this plan's amqp package follows"
provides:
  - "io.axiam.sdk.amqp.AmqpConsumer — static consume(Channel, String, byte[], Consumer<byte[]>, Logger) implementing CONTRACT.md §8 verify-before-handler + the full ack/nack matrix"
  - "AmqpConsumer.configureAutomaticRecovery(ConnectionFactory, Duration) — documented, overridable automatic-recovery helper (setAutomaticRecoveryEnabled(true) + setNetworkRecoveryInterval), never disabling recovery"
  - "AmqpConsumerTest — Proxy-based fake Channel/Logger proving all four ack/nack matrix branches against 20-02's real Rust-signed fixture, without a live broker"
affects: [20-08, 20-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "DeliverCallback built by a package-private static factory (AmqpConsumer.deliverCallback) so tests can invoke it directly against synthesized Delivery objects without going through basicConsume/a live broker"
    - "java.lang.reflect.Proxy-based test doubles for com.rabbitmq.client.Channel and org.slf4j.Logger (no mocking framework dependency in this SDK's test scope) — records basicAck/basicNack(tag,multiple,requeue) and formats SLF4J {} placeholders for log-content assertions"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java
    - sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java
  modified: []

key-decisions:
  - "AmqpConsumer.deliverCallback is package-private (not private) specifically so AmqpConsumerTest can construct and invoke the DeliverCallback directly with synthesized Delivery objects, per the plan's explicit test-shape requirement — avoids needing a live broker or a full basicConsume round-trip in tests"
  - "Fake Channel/Logger implemented via java.lang.reflect.Proxy rather than adding a mocking framework dependency — com.rabbitmq.client.Channel has ~90 methods; a Proxy InvocationHandler only needs to special-case basicAck/basicNack (and warn(...) for Logger), returning safe defaults for everything else"
  - "logger.warn uses the two-arg (String, Object, Object) SLF4J overload with {} placeholders for exchange/routingKey context — never formats the HMAC value into the message, satisfying §8.4"
  - "catch (Exception transientFailure) after catch (ErrDrop drop) in the handler try/catch, matching the plan's literal ack/nack matrix wording and the RESEARCH.md Pattern 5 reference exactly (ErrDrop is a RuntimeException subtype, ordered first)"

patterns-established:
  - "AMQP consumer test doubles for future AMQP-adjacent Java SDK plans (e.g. producer-side work in 20-08/20-09) should reuse the same Proxy-based fake-Channel pattern rather than introducing Mockito, keeping the SDK's own test dependency footprint minimal"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "AmqpConsumer verifies every delivery's HMAC-SHA256 signature via Hmac.verify BEFORE the handler ever runs — the handler is structurally unreachable for an unverified message"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java#invalidSignatureNacksWithoutRequeueAndNeverInvokesHandler"
        status: pass
    human_judgment: false
  - id: D2
    description: "Full §8 ack/nack matrix: handler success -> ack; ErrDrop -> nack without requeue; other handler exception -> nack with requeue; HMAC-fail -> nack without requeue + security log"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java#validSignatureAndSuccessfulHandlerAcks"
        status: pass
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java#errDropFromHandlerNacksWithoutRequeue"
        status: pass
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java#transientHandlerExceptionNacksWithRequeue"
        status: pass
    human_judgment: false
  - id: D3
    description: "Security log entry on HMAC verification failure never contains the received or expected HMAC hex value"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java#securityLogNeverContainsAnHmacHexValue"
        status: pass
    human_judgment: false
  - id: D4
    description: "Built-in RabbitMQ Java client automatic recovery is left enabled with a documented, overridable network-recovery-interval helper"
    requirement: "JAVA-01"
    verification:
      - kind: other
        ref: "grep -n setAutomaticRecoveryEnabled sdks/java/src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java (only ever called with true)"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 07: AMQP Consumer — Verify-Before-Handler + Ack/Nack Matrix Summary

**`AmqpConsumer.consume(...)` verifies every AMQP delivery's HMAC-SHA256 signature via 20-02's `Hmac.verify` before the caller's handler ever runs, then applies the exact CONTRACT.md §8 ack/nack matrix, on top of the RabbitMQ Java client's built-in automatic recovery.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-02T08:15:25Z
- **Completed:** 2026-07-02T08:21:38Z
- **Tasks:** 2
- **Files modified:** 2 (both new)

## Accomplishments
- `AmqpConsumer.consume(Channel, String, byte[], Consumer<byte[]>, Logger)` sets `basicQos(10)` and registers a manual-ack `DeliverCallback` that verifies HMAC before ever calling the handler — the handler call site is structurally unreachable for an unverified message.
- Full §8 ack/nack matrix implemented 1:1 with `sdks/go/amqp/consumer.go`'s `verifyAndDispatch`: success → `basicAck`; `ErrDrop` → `basicNack(tag,false,false)`; other handler exception → `basicNack(tag,false,true)`; HMAC-fail → `basicNack(tag,false,false)` + a security-event log line that never contains the HMAC value.
- `AmqpConsumer.configureAutomaticRecovery(ConnectionFactory, Duration)` documents and applies `setAutomaticRecoveryEnabled(true)` (never disabled) plus an overridable `setNetworkRecoveryInterval` (default 5s, CF-03), so the SDK relies on the client's built-in reconnect rather than porting Go's manual `NotifyClose` loop.
- `AmqpConsumerTest` proves all four ack/nack branches — including the non-vacuous "handler never invoked on HMAC failure" assertion and a dedicated "no HMAC value in the log" assertion — against 20-02's real, Rust-signer-produced fixture vectors, using `java.lang.reflect.Proxy`-based fake `Channel`/`Logger` test doubles (no live broker, no mocking framework dependency).

## Task Commits

Each task was committed atomically:

1. **Task 1: AmqpConsumer verify-before-handler + ack/nack matrix + built-in recovery (D-13, §8)** - `871cb87` (feat)
2. **Task 2: AmqpConsumerTest — ack/nack matrix across all branches (§8)** - `4172a84` (test)

## Files Created/Modified
- `sdks/java/src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java` - verify-before-handler `consume`/`deliverCallback` + `configureAutomaticRecovery` helper
- `sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java` - ack/nack matrix + verify-before-handler + no-HMAC-in-logs tests

## Decisions Made
- `deliverCallback` is package-private (not `private`) so the test can invoke it directly against synthesized `Delivery` objects, matching the plan's explicit test shape without needing a live broker.
- Fake `Channel`/`Logger` implemented via `java.lang.reflect.Proxy` instead of adding a mocking framework — `Channel` has ~90 methods; the `InvocationHandler` only special-cases `basicAck`/`basicNack` (and `warn(...)` for `Logger`), defaulting everything else safely.
- `logger.warn` uses the `(String, Object, Object)` SLF4J overload with `{}` placeholders for exchange/routing-key context, never formatting the HMAC value into the message (§8.4).
- Exception ordering in the handler `try`/`catch` is `ErrDrop` (subtype) before `Exception` (supertype, transient/retryable), matching RESEARCH.md Pattern 5's reference exactly.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `AmqpConsumer` is ready for use by any downstream example/integration plan (20-08/20-09) that wires a real `ConnectionFactory`/`Channel` against a live RabbitMQ broker.
- `mvn -f sdks/java/pom.xml test` is green (49/49 tests) after this plan; no regressions in prior Phase 20 plans' test suites.

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

- FOUND: sdks/java/src/main/java/io/axiam/sdk/amqp/AmqpConsumer.java
- FOUND: sdks/java/src/test/java/io/axiam/sdk/amqp/AmqpConsumerTest.java
- FOUND: .planning/phases/20-java-sdk/20-07-SUMMARY.md
- FOUND commit: 871cb87
- FOUND commit: 4172a84
