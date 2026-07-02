---
phase: 19-python-sdk
plan: 05
subsystem: sdk
tags: [python, aio-pika, amqp, hmac, security, asyncio, pytest]

# Dependency graph
requires:
  - phase: 19-python-sdk
    plan: "01"
    provides: "verify_hmac() AMQP HMAC-SHA256 verifier proven byte-for-byte against crates/axiam-amqp/src/messages.rs::sign_payload via a real cross-language fixture; tests/fixtures/amqp_hmac_vectors.json"
  - phase: 19-python-sdk
    plan: "02"
    provides: "_errors.py taxonomy pattern precedent (not directly imported here, but the redact-before-wrap/verify-before-handler security posture this plan follows)"
provides:
  - "amqp/_consumer.py: async closure-handler consume() on aio-pika with mandatory HMAC verify-before-handler and the full §8 ack/nack decision matrix"
  - "amqp/__init__.py: public exports consume, ErrDrop, verify_hmac (re-exported from 19-01)"
  - "ErrDrop exception sentinel mirroring Go's exported ErrDrop for poison-message handling"
affects: [19-06, 19-07]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "SDK-owned ack/nack via message.process(ignore_processed=True) — aio-pika's automatic context-manager auto-ack/requeue is never used; every outcome is an explicit decision"
    - "HMAC verify-before-handler: verify_hmac(signing_key, message.body) is the first thing _on_message does, before any JSON parsing of message content the handler would see"
    - "Injectable logging.Logger with NullHandler default (D-15 observability off-by-default) mirrored from 19-02's pattern"

key-files:
  created:
    - sdks/python/src/axiam_sdk/amqp/_consumer.py
    - sdks/python/tests/test_amqp_consumer.py
  modified:
    - sdks/python/src/axiam_sdk/amqp/__init__.py

key-decisions:
  - "Reused 19-01's verify_hmac() exactly (no reimplementation) — _consumer.py imports it directly from axiam_sdk.amqp._hmac"
  - "Post-verify parse-failure path is structurally only reachable when message.body's second json.loads() call fails independently of the first (inside verify_hmac) — both Python's and Go's reference verifyHMAC require a JSON-object body to succeed at all, so a non-JSON-object body fails HMAC verification first in both languages. The test isolates this branch via a monkeypatched json.loads that fails only on its second invocation, proving nack-without-requeue/no-signature-in-log/handler-never-invoked behavior identically to the HMAC-fail path."
  - "consumer_tag='axiam-sdk-consumer' passed to queue.consume() mirrors Go's const consumerTag for operational parity across SDKs"

patterns-established:
  - "amqp/_consumer.py's _on_message is a standalone, directly-testable unit (mirrors Go's separately-tested verifyAndDispatch) — consume() itself is a thin aio-pika wiring wrapper around it"

requirements-completed: [PY-01]

coverage:
  - id: D1
    description: "Async closure-handler consume() verifies HMAC-SHA256 via 19-01's verify_hmac() BEFORE the handler is ever invoked; an unverified message never reaches the handler"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_amqp_consumer.py::test_invalid_hmac_nacks_without_requeue_and_handler_never_called"
        status: pass
      - kind: unit
        ref: "sdks/python/tests/test_amqp_consumer.py::test_valid_hmac_and_none_handler_acks"
        status: pass
    human_judgment: false
  - id: D2
    description: "Full §8 ack/nack decision matrix: HMAC-fail/parse-fail/ErrDrop all nack WITHOUT requeue + security log (never includes signature); other handler exception nacks WITH requeue; None return acks"
    requirement: "PY-01"
    verification:
      - kind: unit
        ref: "sdks/python/tests/test_amqp_consumer.py (5 tests: valid+None, invalid-HMAC, ErrDrop, other-exception, post-verify-parse-fail)"
        status: pass
      - kind: other
        ref: "grep -c 'requeue=False' sdks/python/src/axiam_sdk/amqp/_consumer.py == 6 (>=3 required)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Consumer reuses the 19-01 verify_hmac primitive rather than reimplementing canonicalization; public surface (consume, ErrDrop) importable from axiam_sdk.amqp"
    requirement: "PY-01"
    verification:
      - kind: other
        ref: "grep -c 'verify_hmac' sdks/python/src/axiam_sdk/amqp/_consumer.py == 4 (>=1 required); python -c \"from axiam_sdk.amqp import consume, ErrDrop\""
        status: pass
      - kind: other
        ref: "mypy --strict sdks/python/src/axiam_sdk/amqp (No issues found)"
        status: pass
    human_judgment: false

# Metrics
duration: 15min
completed: 2026-07-01
status: complete
---

# Phase 19 Plan 05: AMQP Async Consumer Summary

**Async `aio-pika` closure-handler `consume()` with mandatory HMAC-SHA256 verify-before-handler, reusing 19-01's proven `verify_hmac`, enforcing the full CONTRACT.md §8 ack/nack decision matrix (nack-without-requeue on HMAC-fail/parse-fail/`ErrDrop`; nack-with-requeue on transient handler errors), proven hermetically via a recording delivery double.**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-07-01T20:48:00Z
- **Completed:** 2026-07-01T21:03:00Z
- **Tasks:** 1
- **Files modified:** 3 (1 commit)

## Accomplishments

- `amqp/_consumer.py`: `consume(channel, queue_name, signing_key, handler, *, prefetch=10, logger=None)` sets QoS prefetch, passively declares the queue, and registers an async per-message callback with `no_ack=False`. The internal `_on_message` unit calls `verify_hmac()` (from 19-01) **first**, before any JSON parsing the handler could observe — an unverified message never reaches the handler (T-19-16). SDK owns ack/nack via `message.process(ignore_processed=True)`, never aio-pika's automatic context-manager auto-ack.
- Full §8 ack/nack matrix implemented and tested: HMAC-fail → `nack(requeue=False)` + security log (no signature value); post-verify parse-fail → same; handler returns `None` → `ack()`; handler raises `ErrDrop` → `nack(requeue=False)`; handler raises any other exception → `nack(requeue=True)`.
- `ErrDrop(Exception)` sentinel exported from `amqp/__init__.py` alongside `consume` and a re-export of `verify_hmac`, mirroring Go's exported `ErrDrop` (`sdks/go/amqp/errdrop.go`).
- `tests/test_amqp_consumer.py`: a recording fake `AbstractIncomingMessage` double (`.body`, async `.process()` context manager, recording `.ack()`/`.nack(requeue=...)`) proves all five ack/nack paths with no live broker, reusing the real server-signed HMAC fixture from 19-01 (`tests/fixtures/amqp_hmac_vectors.json`) for the valid-signature case.

## Task Commits

Each task was committed atomically:

1. **Task 1: Async closure-handler consumer with verify-before-handler + ack/nack matrix (D-02, §8)** - `7813445` (feat)

**Plan metadata:** committed alongside this SUMMARY (see final commit below)

## Files Created/Modified

- `sdks/python/src/axiam_sdk/amqp/_consumer.py` - `consume()`, `ErrDrop`, internal `_on_message` dispatch; the full §8 verify-before-handler ack/nack matrix
- `sdks/python/src/axiam_sdk/amqp/__init__.py` - Public exports: `consume`, `ErrDrop`, `verify_hmac` (re-export from `_hmac`)
- `sdks/python/tests/test_amqp_consumer.py` - 5 tests covering all ack/nack paths against a recording `AbstractIncomingMessage` double

## Decisions Made

- Reused 19-01's `verify_hmac()` exactly — no reimplementation of the HMAC canonicalization logic. `_consumer.py` imports it directly from `axiam_sdk.amqp._hmac`.
- The plan's "path 5: valid HMAC but non-object body" scenario is structurally only reachable as an *independent* branch when the post-verify `json.loads()` call fails on a call distinct from the one inside `verify_hmac()` — both the Python and Go reference implementations require the body to already parse as a JSON object for HMAC verification to succeed at all (a non-JSON-object body fails HMAC first in both languages, converging on identical externally observable behavior: nack-without-requeue, handler never invoked, no signature logged). The test isolates the parse-failure branch specifically via a monkeypatched `json.loads` that fails only on its second invocation within a single `_on_message` call, proving the branch's independent nack/logging/no-handler-invocation behavior rather than re-testing the HMAC-fail path under a different name.
- `consumer_tag="axiam-sdk-consumer"` passed to `queue.consume()`, matching Go's `const consumerTag` for cross-SDK operational parity (identifiable in RabbitMQ's management UI).

## Deviations from Plan

None — plan executed exactly as written. The HMAC-fail/parse-fail convergence noted above is a design clarification (documented in Decisions Made), not a deviation: the plan's five specified paths are all implemented and independently tested; the parse-failure test isolates the branch via targeted monkeypatching rather than relying on an unreachable "non-object body passes HMAC" input shape.

## Issues Encountered

None beyond the design clarification documented above — no unresolved issues.

## User Setup Required

None — no external service configuration required. `mypy`, `ruff`, and `aio-pika` were already available/installed in this execution environment from prior Phase 19 plans' `dev` optional-dependency group.

## Next Phase Readiness

- The AMQP transport is complete: `_hmac.py` (19-01) + `_consumer.py`/`__init__.py` (this plan) together deliver PY-01's full AMQP capability with the security-critical verify-before-handler invariant proven hermetically.
- 19-06 (FastAPI/Django integrations) and 19-07 (examples/CI/publish) can now reference `axiam_sdk.amqp.consume`/`ErrDrop` for the AMQP consumer example script.
- No blockers.

## Self-Check: PASSED

- `sdks/python/src/axiam_sdk/amqp/_consumer.py` — FOUND
- `sdks/python/src/axiam_sdk/amqp/__init__.py` — FOUND (modified)
- `sdks/python/tests/test_amqp_consumer.py` — FOUND
- Commit `7813445` — FOUND in `git log --oneline --all`
- `pytest sdks/python/tests/test_amqp_consumer.py -x -q` — 5 passed
- `pytest sdks/python` (full suite) — 97 passed
- `mypy --strict sdks/python/src/axiam_sdk/amqp` — No issues found
- `grep -c 'requeue=False' sdks/python/src/axiam_sdk/amqp/_consumer.py` — 6 (≥3 required)
- `grep -c 'verify_hmac' sdks/python/src/axiam_sdk/amqp/_consumer.py` — 4 (≥1 required)
- `python -c "from axiam_sdk.amqp import consume, ErrDrop"` — succeeds

---
*Phase: 19-python-sdk*
*Completed: 2026-07-01*
