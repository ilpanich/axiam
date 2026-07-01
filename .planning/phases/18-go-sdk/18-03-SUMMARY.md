---
phase: 18-go-sdk
plan: 03
subsystem: go-sdk-amqp
tags: [go, sdk, amqp, hmac, security, rabbitmq, consumer]

requires:
  - phase: 18-go-sdk (18-01)
    provides: "go.mod/go.sum with amqp091-go v1.10.0 pinned; module scaffold"
provides:
  - "sdks/go/amqp package: byte-identical HMAC-SHA256 verify (verifyHMAC), ErrDrop sentinel, Event/parseEvent, closure-handler Consume with verify-before-handler ordering"
  - "AckableDelivery seam (interface over amqp091.Delivery Ack/Nack) proven hermetically via recordingDelivery fake — no live broker in the default go test ./... suite"
affects: ["18-04", "18-05", "18-06 (examples/middleware may reference the amqp package for the AMQP consumer example)"]

tech-stack:
  added: []
  patterns:
    - "verifyHMAC: json.Unmarshal into map[string]json.RawMessage, extract+delete hmac_signature, re-marshal (Go sorts map keys, matching serde_json's BTreeMap-backed default ordering), HMAC-SHA256 + hmac.Equal constant-time compare"
    - "AckableDelivery interface seam (Data/Ack/Nack) — amqp091.Delivery in prod via deliveryAdapter, recordingDelivery fake in tests"
    - "verifyAndDispatch as the load-bearing, separately-testable unit: HMAC-verify BEFORE handler, D-07 ack/nack matrix (nil->Ack, ErrDrop->Nack(false), other err->Nack(true), verify-fail->Nack(false)+security log)"
    - "securityLogger narrow one-method interface (SecurityWarn) with a noopLogger default — CF-02 observability off by default"

key-files:
  created:
    - sdks/go/amqp/hmac.go
    - sdks/go/amqp/hmac_test.go
    - sdks/go/amqp/errdrop.go
    - sdks/go/amqp/consumer.go
    - sdks/go/amqp/consumer_test.go
    - sdks/go/amqp/event.go
  modified:
    - sdks/go/go.mod
    - sdks/go/go.sum

key-decisions:
  - "amqp091-go promoted from // indirect to a direct go.mod requirement via go mod tidy, since the new amqp package is the first code that actually imports it (18-01 pinned it but nothing used it yet, so go mod tidy had dropped the direct marker)"
  - "amqp package cannot reuse the root axiam package's unexported newNetworkError/NetworkError (separate Go package per D-02 sub-package partitioning) — Consume's own connection-level failures (Qos/Consume/NotifyClose errors) use plain fmt.Errorf wrapping instead of a NetworkError value; this only affects Consume's own setup/teardown errors, not the verify-and-dispatch security path"
  - "securityLogger defined as a narrow package-local one-method interface (SecurityWarn) rather than requiring slog.Logger directly, so callers can adapt any logger with a one-line closure and tests can supply a zero-dependency recording fake"

requirements-completed: [GO-01]

coverage:
  - id: D1
    description: "verifyHMAC reproduces the server's canonical HMAC-SHA256 protocol byte-for-byte: extract hmac_signature, remove it, canonical-JSON re-serialize, HMAC-SHA256 + constant-time hmac.Equal compare; missing/malformed/tampered signatures all fail closed without panic"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/amqp/hmac_test.go#TestVerifyHMAC_MatchesServerProtocol"
        status: pass
    human_judgment: false
  - id: D2
    description: "Consume verifies HMAC before invoking the handler; D-07 ack/nack matrix (nil->Ack, plain error->Nack+requeue, ErrDrop->Nack-no-requeue, HMAC failure->Nack-no-requeue+security log, handler never invoked) proven via the AckableDelivery seam and recordingDelivery fake, no live broker"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/amqp/consumer_test.go#TestVerifyAndDispatch"
        status: pass
    human_judgment: false
  - id: D3
    description: "Consumer sets a configurable QoS prefetch (default 10, WithPrefetch override) and allocates NotifyClose with buffer capacity >= 1 (Pitfall 4 avoidance)"
    requirement: "GO-01"
    verification:
      - kind: unit
        ref: "sdks/go/amqp/consumer.go#Consume (ch.NotifyClose(make(chan *amqp091.Error, 1)))"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-01
status: complete
---

# Phase 18 Plan 03: Go SDK AMQP Consumer Summary

**Byte-identical HMAC-SHA256 AMQP consumer verifying every delivery before the handler runs, with a D-07 ack/nack matrix proven hermetically against a recording fake — no live broker.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-01T15:38:50Z
- **Completed:** 2026-07-01T15:45:09Z
- **Tasks:** 2
- **Files modified:** 8 (6 created, 2 modified)

## Accomplishments
- `verifyHMAC` mirrors `crates/axiam-amqp/src/messages.rs`'s canonical protocol byte-for-byte: unmarshal into `map[string]json.RawMessage`, extract+delete `hmac_signature`, re-serialize (Go's `encoding/json` sorts map keys, matching serde_json's default `BTreeMap`-backed ordering), HMAC-SHA256, hex-decode, compare via `hmac.Equal` (constant-time — verified byte-identical against a fixture cross-checked in both Go and Python before hardcoding).
- `ErrDrop` sentinel and the `AckableDelivery` interface seam (`Data`/`Ack`/`Nack`) let the security-sensitive nack-without-requeue contract be proven with a `recordingDelivery` test fake, with zero live-broker dependency in `go test ./...`.
- `verifyAndDispatch` implements the D-07 ack/nack matrix exactly: HMAC verification runs strictly before the handler; on failure (missing/malformed/mismatched signature, or a body that fails to parse post-verification) the delivery is nacked without requeue, a security event fires via the injected `securityLogger` (never containing the HMAC value), and the handler is never invoked.
- `Consume` wires the full loop against `*amqp091.Channel`: configurable QoS prefetch (default 10, `WithPrefetch` override), a buffered `NotifyClose(make(chan *amqp091.Error, 1))` (Pitfall 4 — deadlock avoidance), and a `ctx`-cancellation-aware `select` loop.

## Task Commits

Each task was committed atomically:

1. **Task 1: Byte-identical HMAC-SHA256 verify (§8) + ErrDrop sentinel** - `051e72e` (feat, TDD RED→GREEN)
2. **Task 2: Closure-handler Consume — verify-before-handler, ack/nack semantics, QoS, buffered NotifyClose (D-07, SC#4)** - `7aa4795` (feat, TDD RED→GREEN)

_Note: both tasks are TDD; RED (compile failure via `go vet`, confirmed before implementing) and GREEN commits are combined into a single commit per task since the plan's TDD flow for this Go SDK phase writes the test file and implementation together before the first commit point, matching 18-01/18-02's established per-task commit granularity for this phase._

## Files Created/Modified
- `sdks/go/amqp/hmac.go` - `verifyHMAC(signingKey, body []byte) bool` — byte-identical HMAC-SHA256 verify
- `sdks/go/amqp/hmac_test.go` - `TestVerifyHMAC_MatchesServerProtocol` (9 subtests: valid, flipped-signature, flipped-key, flipped-body, missing-signature, non-hex, wrong-length, malformed-JSON)
- `sdks/go/amqp/errdrop.go` - `var ErrDrop` sentinel
- `sdks/go/amqp/event.go` - `Event` type + `parseEvent`
- `sdks/go/amqp/consumer.go` - `AckableDelivery`, `deliveryAdapter`, `Handler`, `ConsumeOption`/`WithPrefetch`/`WithSecurityLogger`, `verifyAndDispatch`, `Consume`
- `sdks/go/amqp/consumer_test.go` - `TestVerifyAndDispatch` (5 subtests: ack-on-nil, nack-requeue-on-error, nack-no-requeue-on-ErrDrop, nack-no-requeue-on-HMAC-fail-with-handler-not-invoked, security-log-omits-HMAC-value) + `recordingDelivery`/`recordingLogger` test fakes
- `sdks/go/go.mod` - promoted `github.com/rabbitmq/amqp091-go` from indirect to direct requirement
- `sdks/go/go.sum` - amqp091-go hash entries (already present from 18-01 pinning; regenerated by `go mod tidy` for the direct-requirement move)

## Decisions Made
- `amqp091-go` promoted from `// indirect` to a direct `go.mod` requirement via `go mod tidy` — 18-01 pinned it in `go.sum` but nothing imported it yet, so Go's tooling had marked it indirect; this plan's `amqp` package is the first consumer.
- The `amqp` package is a separate Go package from the root `axiam` package (per Phase 18 D-02 sub-package partitioning), so it cannot reach the root package's unexported `newNetworkError`/`NetworkError`. `Consume`'s own connection-level setup errors (`Qos`/`Consume`/`NotifyClose` failures) use plain `fmt.Errorf` wrapping instead — this only affects `Consume`'s own transport-setup error returns, not the verify-and-dispatch security path, which is the surface this plan's must-haves and threat model actually cover.
- `securityLogger` is a narrow, package-local one-method interface (`SecurityWarn(msg string, args ...any)`) rather than a hard dependency on `slog.Logger`, so callers can adapt any logger with a one-line closure and tests supply a zero-dependency `recordingLogger` fake — consistent with CF-02 (observability injectable, off by default via `noopLogger`).

## Deviations from Plan

None — plan executed exactly as written. All four `must_haves.truths`, all four `must_haves.artifacts`, and all four `must_haves.prohibitions` are satisfied as specified.

## Issues Encountered

`amqp091-go` was pinned in `go.sum` (per the environment note) but not yet a direct `go.mod` requirement, since no code imported it before this plan. Resolved with `go get github.com/rabbitmq/amqp091-go@v1.10.0` followed by `go mod tidy`, which cleanly promoted it to a direct dependency with a minimal diff (no unexpected transitive additions beyond `go.uber.org/goleak`, a test-only transitive dependency harmless in `go.sum`).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `sdks/go/amqp` package is complete and independently testable; 18-04/18-05/18-06 can reference `amqp.Consume`/`amqp.ErrDrop`/`amqp.Event` (e.g. for an AMQP consumer example per 18-CONTEXT.md D-10) without further AMQP-layer work.
- No blockers. `go build ./...`, `go vet ./...`, `go test ./...` (72 tests across 4 packages), `gofmt -l .`, and the TLS-bypass grep gate all pass clean at the full-module level, not just this plan's package.

---
*Phase: 18-go-sdk*
*Completed: 2026-07-01*
