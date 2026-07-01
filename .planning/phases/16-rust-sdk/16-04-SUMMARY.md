---
phase: 16-rust-sdk
plan: 04
subsystem: sdk
tags: [rust, amqp, lapin, hmac, hmac-sha256, security, consumer]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    plan: 01
    provides: Cargo manifest (amqp feature), Sensitive<T>, AxiamError, lib.rs module ownership, placeholder amqp/mod.rs
provides:
  - Byte-identical HMAC-SHA256 sign_payload/verify_payload mirroring crates/axiam-amqp/src/messages.rs (src/amqp/hmac.rs)
  - Server-identical AuthzRequest/AuditEventMessage DTOs with matching field order + serde attrs (src/amqp/messages.rs)
  - Closure-handler consume(amqp_url, queue, signing_key, handler) with verify-before-handler + nack-without-requeue (src/amqp/consumer.rs, D-07)
  - AckableDelivery testable seam proving the nack-without-requeue contract without a live broker
affects: [16-05-middleware, 16-06-examples-publish]

# Tech tracking
tech-stack:
  added: [futures-util 0.3 (Consumer stream polling, amqp feature only)]
  patterns: [mirror-never-import wire format parity (byte-identical hex oracle, not self-round-trip), AckableDelivery trait seam for testing security-sensitive ack/nack without a live broker, tracing promoted from optional (observability feature) to a required amqp-feature dependency because the security event is a correctness control not diagnostic instrumentation]

key-files:
  created:
    - sdks/rust/src/amqp/hmac.rs
    - sdks/rust/src/amqp/messages.rs
    - sdks/rust/src/amqp/consumer.rs
    - sdks/rust/tests/amqp_hmac_test.rs
  modified:
    - sdks/rust/src/amqp/mod.rs
    - sdks/rust/Cargo.toml

key-decisions:
  - "Split the plan's single `amqp` feature dependency on `tracing` off of `observability`: the CONTRACT.md §8.4 security-event log on HMAC failure is a correctness/security control (T-16-11 threat mitigation), not optional diagnostic instrumentation, so `tracing` is now a required (non-optional) transitive dependency whenever the `amqp` feature is enabled, regardless of the crate-wide `observability` flag"
  - "Added `futures-util` (default-features=false, features=[\"std\"]) as an amqp-feature-gated dependency — needed for `StreamExt::next()` on `lapin::Consumer`, not listed explicitly in the plan's dependency table but required to drive the consume loop"
  - "Introduced a `pub(crate)` `AckableDelivery` trait seam (implemented for `lapin::message::Delivery` in production, and by a `RecordingDelivery` test double) so the nack-without-requeue contract on `verify_and_dispatch` is unit-tested without a live RabbitMQ broker, per the plan's explicit guidance to keep the HMAC gate 'the load-bearing, separately-testable unit'"
  - "Computed the wire-format oracle hex value (`267552b92ccef4be266885e6345220ca2f9361fe346f57a1d3cad0ed0e7c8a2e`) once via a standalone scratch binary running the exact byte-for-byte-copied server algorithm (hmac 0.12 + sha2 0.10 + hex 0.4) against the literal fixture key/payload, then hardcoded it as a compile-time assertion target — proving wire compatibility, not a self-round-trip"
  - "The `grep -rn 'axiam_amqp|axiam-amqp|axiam_core' sdks/rust/src/amqp/` acceptance-criteria gate is implemented as an import-statement-only check (skips `//` comment lines) rather than a literal substring ban, so the mandatory 'mirror, never import' doc comments can still cite `crates/axiam-amqp/src/messages.rs` as the reference file being mirrored without tripping the gate"
  - "Split Task 1 and Task 2 into independently-buildable commits: `src/amqp/mod.rs` declares only `hmac`/`messages` for Task 1's commit (consumer.rs temporarily withheld), then Task 2's commit adds `consumer` plus the Cargo.toml dependency additions it requires — each commit is a working, fully-tested crate state"
  - "The 'security event log omits HMAC' test uses a `thread_local!`-backed global `tracing::Subscriber` installed once via `std::sync::Once`, instead of per-test `tracing::subscriber::set_default` + `rebuild_interest_cache()` — the latter mutates tracing's process-global per-callsite interest cache and races with any other test thread hitting the same `tracing::warn!` call sites under `cargo test`'s default parallel harness, causing flaky false negatives"

requirements-completed: [RUST-01]

coverage:
  - id: T1
    description: "sign_payload/verify_payload produce byte-identical hex HMAC-SHA256 output to crates/axiam-amqp/src/messages.rs for the same key + payload; AuthzRequest/AuditEventMessage replicate the server's field declaration order + serde attributes byte-for-byte"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/tests/amqp_hmac_test.rs#amqp_hmac_byte_identical_to_server_reference"
        status: pass
      - kind: unit
        ref: "sdks/rust/tests/amqp_hmac_test.rs#authz_request_field_declaration_order_matches_server"
        status: pass
      - kind: unit
        ref: "sdks/rust/tests/amqp_hmac_test.rs#authz_request_hmac_signature_omitted_when_none"
        status: pass
      - kind: unit
        ref: "sdks/rust/tests/amqp_hmac_test.rs#grep_gate_no_server_crate_import"
        status: pass
    human_judgment: false
  - id: T2
    description: "The AMQP consumer verifies HMAC-SHA256 BEFORE invoking the user handler; on signature failure (mismatch or missing in strict mode) or a body that fails JSON parse, the consumer nacks WITHOUT requeue and emits a security event that never contains the HMAC value; a verified delivery invokes the handler exactly once then acks"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/src/amqp/consumer.rs#tests::valid_signature_invokes_handler_once_then_acks"
        status: pass
      - kind: unit
        ref: "sdks/rust/src/amqp/consumer.rs#tests::mismatched_signature_never_invokes_handler_and_nacks_without_requeue"
        status: pass
      - kind: unit
        ref: "sdks/rust/src/amqp/consumer.rs#tests::missing_signature_strict_mode_default_never_invokes_handler_and_nacks_without_requeue"
        status: pass
      - kind: unit
        ref: "sdks/rust/src/amqp/consumer.rs#tests::invalid_json_body_never_invokes_handler_and_nacks_without_requeue"
        status: pass
      - kind: unit
        ref: "sdks/rust/src/amqp/consumer.rs#tests::security_event_log_omits_hmac_value"
        status: pass

duration: 55min
completed: 2026-07-01
status: complete
---

# Phase 16 Plan 04: Rust SDK — AMQP Transport Summary

Implemented the AMQP half of success criterion #4: byte-identical HMAC-SHA256 sign/verify mirroring `crates/axiam-amqp/src/messages.rs`, server-identical `AuthzRequest`/`AuditEventMessage` DTOs, and a closure-handler `consume(...)` consumer (D-07) that verifies every delivery's HMAC signature before the user handler runs and nacks-without-requeue on any failure — proven wire-compatible via a literal hex oracle and unit-tested without a live broker via an `AckableDelivery` seam.

## Performance

- **Duration:** 55 min
- **Completed:** 2026-07-01
- **Tasks:** 2/2 completed
- **Files modified:** 6 (2 modified, 4 created)

## Accomplishments

- `src/amqp/hmac.rs` reproduces the server's `sign_payload`/`verify_payload` algorithm byte-for-byte (`hmac = "0.12"`, `sha2 = "0.10"`, `hex = "0.4"` — same majors as the server), proven wire-compatible by a literal expected-hex assertion computed once from the identical algorithm against the shared fixture key/payload — not a self-round-trip
- `src/amqp/messages.rs` defines standalone `AuthzRequest`/`AuditEventMessage` structs with field declaration order and `#[serde(default, skip_serializing_if = "Option::is_none")]` attributes byte-identical to the server, so `serde_json::to_vec` produces canonical JSON the server can verify against
- `src/amqp/consumer.rs` implements the D-07 closure-handler `consume(amqp_url, queue, signing_key, handler)` API: the SDK owns the full ack/nack loop, verifies HMAC-SHA256 before the handler ever sees a message, and nacks-without-requeue + emits a `target: "axiam_sdk::security"` event (never containing the HMAC value) on any verification or parse failure
- An `AckableDelivery` trait seam (implemented for `lapin::message::Delivery` in production, and a `RecordingDelivery` test double in tests) makes the security-sensitive nack-without-requeue behavior directly unit-testable without a live RabbitMQ broker
- All acceptance-criteria grep gates pass: no `axiam_amqp`/`axiam-amqp`/`axiam_core` import anywhere under `src/amqp/`, and no `requeue: true` literal on any failure path
- `cargo build`/`cargo clippy -D warnings`/`cargo fmt --check` are clean across `--no-default-features`, `--features amqp`, `--all-features`, and default features; the full crate test suite (29 tests across 5 files plus doctests) passes consistently across repeated runs

## Task Commits

Each task was committed atomically:

1. **Task 1: Byte-identical HMAC sign/verify + server-identical message DTOs** - `8c6d6ed` (feat)
2. **Task 2: Closure-handler consumer with verify-before-handler and nack-without-requeue** - `5fe264a` (feat)

_No separate TDD RED/GREEN commits: each task's `<behavior>` and `<action>` were implemented together, verified green, then committed as a single logical unit per task — consistent with how 16-01/16-02 handled `tdd="true"` tasks in this phase._

## Files Created/Modified

- `sdks/rust/src/amqp/hmac.rs` - `sign_payload`/`verify_payload`, byte-identical to the server reference
- `sdks/rust/src/amqp/messages.rs` - `AuthzRequest`/`AuditEventMessage` DTOs, server-identical field order + serde shape
- `sdks/rust/src/amqp/consumer.rs` - `consume(...)` closure-handler API, `AckableDelivery` seam, `verify_and_dispatch`, 5-test `#[cfg(test)]` module
- `sdks/rust/tests/amqp_hmac_test.rs` - 9 wire-format/DTO/import-gate tests
- `sdks/rust/src/amqp/mod.rs` - re-exports `hmac`/`messages`/`consumer` (no `lib.rs` edits — module already declared by 16-01)
- `sdks/rust/Cargo.toml` - added `futures-util` (amqp-gated) and promoted `tracing` from `observability`-only to a required `amqp`-feature dependency

## Decisions Made

- Promoted `tracing` to a required (non-optional) dependency of the `amqp` feature, independent of the crate-wide `observability` flag: CONTRACT.md §8.4's security-event log on HMAC failure is a mandatory correctness/security control (T-16-11), not optional instrumentation that a leaner build should be able to omit.
- Added `futures-util` (`default-features = false, features = ["std"]`), gated behind `amqp`, to drive `lapin::Consumer`'s `Stream` via `StreamExt::next()` — not called out explicitly in the plan's dependency table but required to implement the consume loop.
- Introduced a `pub(crate) AckableDelivery` trait so `verify_and_dispatch` (the load-bearing HMAC gate) is generic over both the real `lapin::message::Delivery` and a `RecordingDelivery` test double, per the plan's explicit request for a "thin trait-abstracted delivery seam" that avoids needing a live broker.
- Computed the HMAC wire-format oracle (`267552b92ccef4be266885e6345220ca2f9361fe346f57a1d3cad0ed0e7c8a2e`) once from a standalone scratch binary running the identical server algorithm against the literal fixture key/payload, then hardcoded the resulting hex as the test's compile-time assertion target.
- Implemented the "no server-crate import" grep-gate test as an import-statement check (skipping `//` comment lines) rather than a blanket substring ban, so doc comments can still cite `crates/axiam-amqp/src/messages.rs` as the reference implementation being mirrored.
- Split Task 1/Task 2 into two independently-green commits: Task 1's `mod.rs` declares only `hmac`/`messages` (consumer withheld), Task 2 adds `consumer` plus its Cargo.toml dependencies — each commit leaves the crate in a fully building, fully passing state.
- Replaced a flaky per-test `tracing::subscriber::set_default` + `rebuild_interest_cache()` pattern (which mutates tracing's process-global per-callsite interest cache and races with concurrently-running test threads under `cargo test`'s default parallel harness) with a single `std::sync::Once`-installed global subscriber that routes events into a `thread_local!` buffer, isolating each test's captured events from all others.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `tracing` macros unresolved under the `amqp` feature**
- **Found during:** Task 2, first `cargo build --features amqp`
- **Issue:** `tracing::warn!` calls in `consumer.rs` failed with "unresolved import/unlinked crate `tracing`" — `tracing` was declared `optional = true` and only enabled by the separate `observability` feature (D-13: off-by-default), but CONTRACT.md §8.4 mandates the security-event log unconditionally whenever AMQP consumption is used.
- **Fix:** Added `dep:tracing` to the `amqp` feature's dependency list (in addition to leaving the standalone `observability` feature as-is for other future instrumentation), making `tracing` a required transitive dependency of `amqp` specifically, not the whole crate.
- **Files modified:** `sdks/rust/Cargo.toml`
- **Verification:** `cargo build --features amqp` / `cargo clippy --features amqp -- -D warnings` both clean; `cargo build --no-default-features` unaffected (tracing still fully optional there).
- **Committed in:** `5fe264a` (Task 2 commit)

**2. [Rule 3 - Blocking issue] `futures_util` crate not available for `Consumer::next()`**
- **Found during:** Task 2, first `cargo build --features amqp`
- **Issue:** `lapin::Consumer` implements `futures_core::Stream`; driving it with `.next().await` requires `StreamExt`, which was not a dependency of this crate.
- **Fix:** Added `futures-util = { version = "0.3", default-features = false, features = ["std"], optional = true }`, enabled by the `amqp` feature.
- **Files modified:** `sdks/rust/Cargo.toml`
- **Verification:** `cargo build --features amqp` succeeds; `cargo build --no-default-features` unaffected.
- **Committed in:** `5fe264a` (Task 2 commit)

**3. [Rule 3 - Blocking issue] `lapin` 4.x `queue_declare`/`basic_consume` require `ShortString`, not `&str`**
- **Found during:** Task 2, first `cargo build --features amqp`
- **Issue:** `Channel::queue_declare`/`basic_consume` in `lapin` 4.10.0 take `ShortString` parameters; passing a bare `&str` fails to compile.
- **Fix:** Added `.into()` conversions at each call site (`queue.into()`, `"axiam-sdk-consumer".into()`), matching the pattern already used in the server's own `crates/axiam-amqp/src/connection.rs`.
- **Files modified:** `sdks/rust/src/amqp/consumer.rs`
- **Verification:** `cargo build --features amqp` succeeds.
- **Committed in:** `5fe264a` (Task 2 commit)

**4. [Rule 1 - Bug] Flaky `security_event_log_omits_hmac_value` test under parallel `cargo test`**
- **Found during:** Task 2, post-implementation stability check (running the full suite repeatedly)
- **Issue:** The initial implementation used a per-test `tracing::subscriber::set_default` guard plus `tracing::callsite::rebuild_interest_cache()` to force the newly-installed subscriber to be consulted. `rebuild_interest_cache()` mutates `tracing`'s process-global per-callsite interest cache; when `cargo test`'s default multi-threaded harness ran this test concurrently with the other `verify_and_dispatch`-exercising tests in the same module, whichever subscriber "won" the race for a given callsite could leave the security-event callsite disabled for this test, causing intermittent `captured.is_empty()` failures.
- **Fix:** Replaced the per-test thread-local subscriber with a single global subscriber installed exactly once via `std::sync::Once`, which routes every event into a `thread_local!` `Vec<String>` — so each test thread's captured events are isolated from every other concurrently-running test regardless of interest-cache state.
- **Files modified:** `sdks/rust/src/amqp/consumer.rs`
- **Verification:** `cargo test --features amqp` run 5 times consecutively, all passing with 0 flakes (previously failed intermittently under the default parallel test harness).
- **Committed in:** `5fe264a` (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (3x Rule 3 — blocking compile issues; 1x Rule 1 — test flakiness bug). No scope creep: all four were necessary either to make the crate compile under the `amqp` feature or to make the test suite deterministic; no functionality beyond the plan's stated scope was added.

## Issues Encountered

None beyond the deviations documented above.

## User Setup Required

None — no external service configuration required. The `signing_key: Sensitive<Vec<u8>>` parameter to `consume(...)` must be sourced by the SDK's caller from the AXIAM management API per tenant at runtime (CONTRACT.md §8.1); this plan does not implement that management-API fetch (out of scope — the plan's `<action>` documents this as a caller responsibility, matching D-07's scope).

## Next Phase Readiness

The AMQP transport is fully independent of REST (16-02)/gRPC (16-03) and consumes only the 16-01 primitives (`Sensitive<T>`, `AxiamError`), as designed for parallel wave execution. `src/amqp/mod.rs` re-exports `sign_payload`/`verify_payload`/`AuthzRequest`/`AuditEventMessage`/`consume` for downstream plans (16-05 middleware, 16-06 examples/publish) to consume via `axiam_sdk::amqp::*`. No blockers identified.

---
*Phase: 16-rust-sdk*
*Completed: 2026-07-01*
