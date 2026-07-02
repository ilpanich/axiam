---
phase: 20-java-sdk
plan: 02
subsystem: auth
tags: [amqp, hmac, hmac-sha256, jackson, junit5, java, cross-language-fixture]

requires:
  - phase: 20-java-sdk (20-01)
    provides: Maven scaffold with jackson-databind, amqp-client, junit-jupiter dependencies already declared in pom.xml
  - phase: 19-python-sdk
    provides: the proven Rust-signer-produced amqp_hmac_vectors.json fixture and the empirical wire-order-preservation finding
provides:
  - io.axiam.sdk.amqp.Hmac.verify(byte[], byte[]) — wire-order-preserving HMAC-SHA256 verification, never throws
  - io.axiam.sdk.amqp.ErrDrop — poison-message sentinel RuntimeException for the 20-07 AMQP consumer
  - sdks/java/src/test/resources/amqp_hmac_vectors.json — real cross-language fixture, byte-identical to the Phase-19 source
  - a non-vacuous, data-driven JUnit 5 regression test proving Hmac.verify against every fixture vector
affects: [20-07-amqp-consumer]

tech-stack:
  added: []
  patterns:
    - "Jackson ObjectNode (LinkedHashMap-backed) parse -> node.remove(field) -> re-serialize preserves wire/insertion key order for HMAC canonicalization; never TreeMap or key-sort features"
    - "constant-time signature comparison via java.security.MessageDigest.isEqual"

key-files:
  created:
    - sdks/java/src/main/java/io/axiam/sdk/amqp/Hmac.java
    - sdks/java/src/main/java/io/axiam/sdk/amqp/ErrDrop.java
    - sdks/java/src/main/java/io/axiam/sdk/amqp/package-info.java
    - sdks/java/src/test/resources/amqp_hmac_vectors.json
    - sdks/java/src/test/java/io/axiam/sdk/amqp/HmacVerifyTest.java
  modified: []

key-decisions:
  - "Hmac.verify canonicalizes via ObjectNode.remove(\"hmac_signature\") in place (never a TreeMap/sorted copy), preserving Rust struct-declaration field order — re-confirms the Phase-19 (Python) empirical finding, now proven against the same fixture in Java"
  - "Manually verified (then reverted, not committed) that swapping the canonicalization to a TreeMap/alphabetical-sort breaks authz_request_valid and audit_event_valid in HmacVerifyTest, confirming the ordering invariant is load-bearing and test-enforced"

patterns-established:
  - "amqp/Hmac.java — the canonical wire-order-preserving HMAC verify primitive other AMQP-consuming Java SDK code (20-07) must call, never reimplement"

requirements-completed: [JAVA-01]

coverage:
  - id: D1
    description: "Hmac.verify(signingKey, body) returns true for real Rust-signed vectors and false for tampered/wrong-key/missing/non-hex/wrong-length vectors"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/HmacVerifyTest.java#verifyMatchesExpectedValidity (7 fixture vectors)"
        status: pass
      - kind: unit
        ref: "sdks/java/src/test/java/io/axiam/sdk/amqp/HmacVerifyTest.java#atLeastOneTrueAndOneFalseVectorExist"
        status: pass
    human_judgment: false
  - id: D2
    description: "Canonicalization preserves wire/insertion key order (never alphabetized) and comparison is constant-time"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "mvn -f sdks/java/pom.xml test -Dtest=HmacVerifyTest (all 8 tests green); manually verified test fails when Hmac.java is patched to alphabetize keys via TreeMap"
        status: pass
    human_judgment: false
  - id: D3
    description: "ErrDrop poison-message sentinel exists as a RuntimeException for the 20-07 AMQP consumer to use"
    requirement: "JAVA-01"
    verification:
      - kind: unit
        ref: "mvn -f sdks/java/pom.xml -q test-compile (compiles); grep confirms ErrDrop extends RuntimeException"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-02
status: complete
---

# Phase 20 Plan 02: AMQP HMAC Canonicalization Summary

**Wire-order-preserving `Hmac.verify` (Jackson `ObjectNode.remove`, constant-time `MessageDigest.isEqual`) proven byte-for-byte against the real Rust-signed fixture, plus the `ErrDrop` poison-message sentinel.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-07-02T07:09:48Z
- **Completed:** 2026-07-02T07:14:15Z
- **Tasks:** 2
- **Files modified:** 5 (all new)

## Accomplishments
- `io.axiam.sdk.amqp.Hmac.verify(byte[], byte[])` implemented per RESEARCH.md Pattern 5: parses body into a Jackson `ObjectNode`, removes `hmac_signature` in place (preserving remaining key insertion order — never sorted), re-serializes, and compares via `MessageDigest.isEqual`; never throws on malformed input
- `io.axiam.sdk.amqp.ErrDrop extends RuntimeException` — poison-message sentinel for the 20-07 AMQP consumer's ack/nack loop
- `amqp/package-info.java` created, `@NullMarked`
- Vendored `sdks/python/tests/fixtures/amqp_hmac_vectors.json` verbatim (byte-identical) into `sdks/java/src/test/resources/`
- `HmacVerifyTest` — JUnit 5 `@ParameterizedTest` driven by all 7 fixture vectors, plus a guard test asserting at least one true and one false vector exist (non-vacuous)
- Manually confirmed (not committed) that swapping the canonicalization to a `TreeMap`/alphabetical-sort approach breaks `authz_request_valid` and `audit_event_valid` — proving the ordering invariant is load-bearing and actually caught by the test, not incidental

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement Hmac.verify with wire-order-preserving canonicalization + ErrDrop sentinel (§8, D-13)** - `580807a` (feat)
2. **Task 2: Vendor the real cross-language fixture + data-driven HmacVerifyTest (proves §8 byte-for-byte)** - `94af2f4` (test)

**Plan metadata:** (this commit, docs)

## Files Created/Modified
- `sdks/java/src/main/java/io/axiam/sdk/amqp/Hmac.java` - HMAC-SHA256 verify-before-handler primitive with wire-order-preserving canonicalization
- `sdks/java/src/main/java/io/axiam/sdk/amqp/ErrDrop.java` - poison-message sentinel `RuntimeException` for 20-07
- `sdks/java/src/main/java/io/axiam/sdk/amqp/package-info.java` - `@NullMarked` package anchor
- `sdks/java/src/test/resources/amqp_hmac_vectors.json` - real Rust-signer-produced fixture, vendored verbatim from Phase 19
- `sdks/java/src/test/java/io/axiam/sdk/amqp/HmacVerifyTest.java` - data-driven JUnit 5 test proving `Hmac.verify` against every fixture vector

## Decisions Made
- Confirmed and re-proved the Phase-19 (Python) empirical finding in Java: canonicalization must preserve Rust struct-declaration field order (via `ObjectNode.remove` in place), not alphabetize — Go's stale comment in `sdks/go/amqp/hmac.go` was deliberately NOT used as a reference per 20-PATTERNS.md's explicit divergence callout.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- `io.axiam.sdk.amqp.Hmac.verify` and `ErrDrop` are ready for the 20-07 AMQP consumer's ack/nack loop (verify-before-handler, `ErrDrop` -> nack-without-requeue) to build on directly.
- The §8 canonicalization ordering gap flagged in 20-VALIDATION.md's Wave-0 requirements is now closed for Java, matching the Python/Go/TypeScript/Rust SDKs' cross-language byte-fidelity.

---
*Phase: 20-java-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All created files verified present on disk; both task commits (`580807a`, `94af2f4`) verified in git log.
