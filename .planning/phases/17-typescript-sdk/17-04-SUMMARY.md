---
phase: 17-typescript-sdk
plan: 04
subsystem: sdk
tags: [typescript, sdk, amqp, hmac, security, node-crypto, amqplib]

# Dependency graph
requires:
  - phase: 17-typescript-sdk
    provides: "17-01: dependency-free core module (Sensitive<T>), build/test tooling, /amqp entry stub"
provides:
  - "signPayload/verifyPayload HMAC-SHA256 sign/verify pair (src/amqp/hmac.ts), byte-identical to the server/Rust-SDK protocol"
  - "Server-identical AMQP message DTOs (src/amqp/messages.ts): AuthzRequest, AuditEventMessage, AuthzResponse, NotificationEvent"
  - "verifyAndDispatch/consume closure-handler consumer (src/amqp/consumer.ts): verify-before-handler, nack-without-requeue on any failure, security event that never logs the signature or key"
  - "axiam-sdk/amqp entry filled in (src/amqp/index.ts re-exports hmac/messages/consumer)"
affects: [17-05-middleware, 17-06-publish-ci]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Mirror, never import: hmac.ts and messages.ts reproduce crates/axiam-amqp/src/messages.rs and sdks/rust/src/amqp/{hmac,messages}.rs byte-for-byte using only node:crypto, with no dependency on the Rust crates"
    - "ConsumeChannel seam (mirroring Rust's AckableDelivery pub(crate) trait): consumer.test.ts exercises the full verify-before-handler/nack-no-requeue contract against a RecordingChannel fake with zero live broker (D-24)"
    - "Canonical JSON via plain JSON.parse + delete + JSON.stringify only — no schema-validator reconstruction before HMAC verification (Pitfall 5)"

key-files:
  created:
    - sdks/typescript/src/amqp/hmac.ts
    - sdks/typescript/src/amqp/messages.ts
    - sdks/typescript/src/amqp/consumer.ts
    - sdks/typescript/test/amqp/hmac.test.ts
    - sdks/typescript/test/amqp/consumer.test.ts
  modified:
    - sdks/typescript/src/amqp/index.ts
    - sdks/typescript/package.json
    - sdks/typescript/tsconfig.json

key-decisions:
  - "verifyPayload never throws: malformed hex, odd-length hex, and length-mismatched-but-valid hex all return false via a try/catch around Buffer.from(hex) plus a pre-timingSafeEqual length check"
  - "Fixed-vector HMAC test cross-checked independently against `openssl dgst -sha256 -hmac` for the same key+canonical-JSON bytes, locking byte-identity against any future serialization/HMAC regression"
  - "consumer.ts exposes verifyAndDispatch (not just consume) as a separately-exported, separately-testable unit, mirroring the Rust SDK's verify_and_dispatch/consume split"
  - "ConsumeOptions.strict defaults to true (CONTRACT.md §8.3); a present signature is always verified regardless of strict/lenient — lenient mode only changes the outcome for a MISSING signature"
  - "Handler exceptions are caught and treated as a nack-without-requeue failure path (not left to propagate) to avoid re-queuing a handler-crashing message into a hot loop, matching the plan's explicit guidance"

patterns-established:
  - "AMQP entry (axiam-sdk/amqp) is now fully implemented: hmac + messages + consumer, all Node-only, re-exported from src/amqp/index.ts"

requirements-completed: [TS-01]

coverage:
  - id: D1
    description: "signPayload/verifyPayload reproduce the server's HMAC-SHA256 hex protocol byte-for-byte via node:crypto, with a fixed-vector test cross-checked against openssl"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/amqp/hmac.test.ts#fixed-vector byte-identity (4 tests: sign, verify-accept, flipped-byte-reject, tampered-payload-reject)"
        status: pass
      - kind: unit
        ref: "test/amqp/hmac.test.ts#verifyPayload never throws (4 tests: malformed hex, odd-length hex, length-mismatch, empty string)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Canonical JSON key-order preservation: JSON.stringify after delete obj.hmac_signature preserves original insertion order (no alphabetical reordering)"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/amqp/hmac.test.ts#key-order preservation (Pitfall 5)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Message DTOs (AuthzRequest, AuditEventMessage, AuthzResponse, NotificationEvent) with field order matching the Rust structs; only AuthzRequest/AuditEventMessage marked as HMAC-signed via HMAC_SIGNED_MESSAGE_TYPES"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/src/amqp/messages.ts (interfaces used directly by hmac.test.ts and consumer.test.ts fixtures; field order manually verified against crates/axiam-amqp/src/messages.rs during authoring)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Consumer verifies HMAC before invoking the handler; a verified message reaches the handler and is acked; the handler never sees an unverified message"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/amqp/consumer.test.ts#valid signature: handler is called once (signature stripped) and message is acked"
        status: pass
    human_judgment: false
  - id: D5
    description: "On mismatch, missing-signature (strict default), or JSON parse failure, the consumer nacks WITHOUT requeue (msg, false, false) and never invokes the handler; a security event is emitted that never contains the signature hex or signing key"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "test/amqp/consumer.test.ts#mismatched signature / missing signature (strict default) / unparseable JSON body / every failure path (mismatch, missing, parse-fail) records requeue===false exactly"
        status: pass
      - kind: unit
        ref: "sdks/typescript/src/amqp/consumer.ts grep for '/* requeue */ false' comment on all three nack call sites (Pitfall 4 guard)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Signing key is a required, caller-supplied Sensitive<Buffer> parameter to consume() — the SDK does not fetch it from the server"
    requirement: "TS-01"
    verification:
      - kind: unit
        ref: "sdks/typescript/src/amqp/consumer.ts (consume signature: signingKey: Sensitive<Buffer>, non-optional); typecheck (tsc --noEmit) enforces this at call sites"
        status: pass
    human_judgment: false

# Metrics
duration: 10min
completed: 2026-07-01
status: complete
---

# Phase 17 Plan 04: TypeScript SDK AMQP HMAC Consumer Summary

**Node-only AMQP consumer with byte-identical HMAC-SHA256 sign/verify (node:crypto), server-matching message DTOs, and a closure-handler consumer that verifies every delivery before the handler ever runs and nacks-without-requeue on any failure — direct TS port of the already-tested Rust `verify_and_dispatch`/`consume`.**

## Performance

- **Duration:** 10 min
- **Started:** 2026-07-01T12:05:00Z
- **Completed:** 2026-07-01T12:15:01Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Implemented `signPayload`/`verifyPayload` in `src/amqp/hmac.ts` using Node's built-in `crypto.createHmac`/`timingSafeEqual`, matching `crates/axiam-amqp/src/messages.rs:35-50` and `sdks/rust/src/amqp/hmac.rs` byte-for-byte; the fixed-vector test's expected hex was independently cross-checked against `openssl dgst -sha256 -hmac`
- Added `src/amqp/messages.ts` with `AuthzRequest`/`AuditEventMessage`/`AuthzResponse`/`NotificationEvent` interfaces whose field declaration order matches the Rust structs, plus `HMAC_SIGNED_MESSAGE_TYPES` documenting which two carry `hmac_signature`
- Built `src/amqp/consumer.ts`: `verifyAndDispatch` (the separately-testable per-message unit) and `consume` (the connect/channel/queue-declare/consume loop) — parses JSON, strips `hmac_signature`, re-serializes to canonical JSON via plain `JSON.stringify` (no schema-validator reconstruction, Pitfall 5), verifies BEFORE the handler runs, and nacks-without-requeue with an explicit `channel.nack(msg, /* allUpTo */ false, /* requeue */ false)` comment (Pitfall 4) on every failure path: parse failure, signature mismatch, missing signature (strict default), and handler exceptions
- Security events on verification failure carry only timestamp/exchange/routingKey/tenant-context — a dedicated test (`security event omits the signature hex`) asserts the serialized event log never contains the tampered signature hex or the raw signing key
- 17 new unit tests (9 hmac + 8 consumer) pass; a `ConsumeChannel` seam (mirroring Rust's `AckableDelivery` trait) lets `consumer.test.ts` exercise the full contract with a `RecordingChannel` fake and zero live RabbitMQ broker
- `src/amqp/index.ts` now re-exports `hmac`/`messages`/`consumer`, completing the `axiam-sdk/amqp` entry left as a stub by 17-01

## Task Commits

Each task was committed atomically:

1. **Task 1: Byte-identical HMAC sign/verify + server-identical message DTOs (§8 / D-12)** - `2d30b28` (feat)
2. **Task 2: Closure-handler consumer — verify-before-handler, nack-no-requeue, security event (D-12 / §8.3g/§8.4)** - `62892d1` (feat)

**Plan metadata:** (pending — final docs commit follows this summary)

_Note: `tdd="true"` was declared on both tasks; tests were authored alongside implementation in a single commit per task (matching the pattern established in 17-01) rather than separate RED/GREEN commits — the plan's `<behavior>` spec was implemented and its tests written and passed together within each task's atomic commit._

## Files Created/Modified
- `sdks/typescript/src/amqp/hmac.ts` - `signPayload`/`verifyPayload`, byte-identical to the Rust/server HMAC-SHA256 hex protocol
- `sdks/typescript/src/amqp/messages.ts` - `AuthzRequest`/`AuditEventMessage`/`AuthzResponse`/`NotificationEvent` DTOs + `HMAC_SIGNED_MESSAGE_TYPES`
- `sdks/typescript/src/amqp/consumer.ts` - `verifyAndDispatch`/`consume`, `ConsumeChannel`/`ConsumeLogger`/`ConsumeOptions` types
- `sdks/typescript/src/amqp/index.ts` - now re-exports hmac/messages/consumer (was an `export {}` stub from 17-01)
- `sdks/typescript/test/amqp/hmac.test.ts` - 9 tests: fixed-vector byte-identity, key-order preservation, never-throws on malformed/short/empty hex
- `sdks/typescript/test/amqp/consumer.test.ts` - 8 tests: valid-signature/ack, mismatch/nack+security-event, missing-signature strict default, parse-fail, handler-throw, lenient mode, requeue===false on every failure path, Pitfall 4 source-comment guard
- `sdks/typescript/package.json` - added `@types/node` devDependency
- `sdks/typescript/tsconfig.json` - added `"types": ["node"]`

## Decisions Made
- `verifyPayload` returns `false` (never throws) for malformed hex, odd-length hex, and length-mismatched-but-valid hex, matching the plan's acceptance criteria and Rust's `hmac` crate `verify_slice` semantics.
- `consumer.ts` exports `verifyAndDispatch` as a standalone, directly-testable function (not just used internally by `consume`), mirroring the Rust SDK's `verify_and_dispatch`/`consume` split and enabling `consumer.test.ts` to assert the full contract without amqplib's `consume` callback plumbing.
- `ConsumeOptions.strict` defaults to `true`; a present signature is always cryptographically verified regardless of strict/lenient mode — lenient mode (opt-in only, per CONTRACT.md §8.3) changes only the outcome for a **missing** signature.
- Handler exceptions are caught inside `verifyAndDispatch` and treated as a nack-without-requeue failure path (with a security-event log), rather than left to propagate out of `consume`'s per-message callback — this matches the plan's action text ("if the handler throws, nack-no-requeue and log — do not requeue a handler-crashing message into a hot loop").

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `@types/node` devDependency + `tsconfig.json` `types: ["node"]`**
- **Found during:** Task 1, running `npx tsc --noEmit` per the plan's implicit typecheck gate
- **Issue:** `tsc --noEmit` failed with 16 pre-existing errors (`Cannot find name 'Buffer'/'process'/'node:crypto'/'node:util'/'require'`) across `src/amqp/hmac.ts` (this plan's new file), `src/rest/session.ts` (17-02), and `test/core/sensitive.test.ts` (17-01) — `@types/node` was never declared as a devDependency in 17-01's scaffold, and `tsconfig.json` had no `"types"` array, so ambient Node globals were invisible to the compiler even though `@types/node` happened to be present transitively in `node_modules`
- **Fix:** Added `"@types/node": "^22.0.0"` to `devDependencies` and `"types": ["node"]` to `tsconfig.json compilerOptions`
- **Files modified:** `sdks/typescript/package.json`, `sdks/typescript/tsconfig.json`
- **Verification:** `npx tsc --noEmit` now exits clean (0 errors) across the whole package, including the previously-broken 17-01/17-02 files
- **Committed in:** `2d30b28` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary to satisfy this plan's own typecheck-clean requirement and unblocks a latent gap from 17-01/17-02 that would otherwise have surfaced in every subsequent plan touching `src/rest/` or Node-only code. No scope creep — scoped to the minimal fix (declare the already-present transitive dependency, enable its types).

## Issues Encountered
None beyond the `@types/node` gap documented above.

## User Setup Required

None - no external service configuration required. (Note: the AMQP signing key remains a caller-supplied `Sensitive<Buffer>` per CONTRACT.md §8.1 — no AXIAM server endpoint currently returns it; this is an existing, documented gap tracked in the Phase 17 RESEARCH.md, not something this plan needed to resolve.)

## Next Phase Readiness
- `axiam-sdk/amqp` entry is fully implemented (hmac + messages + consumer) and typecheck-clean; 17 new unit tests pass with zero live-broker dependency
- `npm run build` (tsup) still cannot be verified end-to-end in this sandbox because the `buf` CLI is unavailable (pre-existing gap from 17-01, unrelated to this plan's `src/amqp/` scope) — `npm test` and `npm run typecheck` are the verification surface used here, per the environment notes
- The real-broker exercise (live RabbitMQ smoke test) is deferred to the optional testcontainers job referenced in 17-03/17-06, consistent with D-24
- Ready for 17-05 (middleware) and 17-06 (publish/CI), which can now assume a complete `/amqp` entry alongside the existing `/rest` persona

---
*Phase: 17-typescript-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED
All 6 created/modified source and test files verified present on disk; all 3 commits (2d30b28, 62892d1, 71f07c0) verified in git log.
