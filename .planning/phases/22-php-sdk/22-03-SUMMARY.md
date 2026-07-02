---
phase: 22-php-sdk
plan: 03
subsystem: sdk
tags: [php, amqp, hmac, php-amqplib, security, cli-worker]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-01: Sensitive/error taxonomy (not directly consumed here, but establishes the same fail-closed/redact-before-wrap security posture); composer.json's php-amqplib/php-amqplib ^3.7 + psr/log ^3.0 pins"
provides:
  - "Axiam\\Sdk\\Amqp\\Hmac::verify(string $signingKey, string $body): bool — byte-exact, constant-time HMAC-SHA256 verification matching crates/axiam-amqp/src/messages.rs::verify_payload"
  - "Axiam\\Sdk\\Amqp\\Consumer — php-amqplib blocking consume loop, verify-before-handler, three-way ack/nack"
  - "Axiam\\Sdk\\Amqp\\AmqpDropMessage — poison-message sentinel exception"
  - "sdks/php/bin/axiam-amqp-worker.php — runnable CLI worker entry point"
  - "sdks/php/tests/Fixtures/amqp_hmac_vectors.json — real Rust-signed HMAC vectors incl. slash + non-ASCII regression"
affects: [22-04, 22-05, 22-06, 22-07, 22-08, 22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Hmac::verify: json_decode($body, true) preserves wire/insertion key order (PHP arrays are ordered maps) — never ksort/alphabetize before canonicalization"
    - "Canonicalization uses json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) to byte-match serde_json's non-escaping output (Pitfall 1)"
    - "hash_equals() for constant-time signature comparison; verify() never throws on attacker-controlled input"
    - "Consumer verifies HMAC BEFORE invoking the app handler; HMAC-fail/poison nack without requeue, transient handler failure nacks with requeue"
    - "CLI worker (not a web-request path) blocks on channel->wait() and exits non-zero on any connection failure — no in-SDK auto-reconnect, relies on process supervision (Pitfall 6)"

key-files:
  created:
    - sdks/php/src/Amqp/Hmac.php
    - sdks/php/src/Amqp/Consumer.php
    - sdks/php/src/Amqp/AmqpDropMessage.php
    - sdks/php/bin/axiam-amqp-worker.php
    - sdks/php/tests/HmacVerifyTest.php
    - sdks/php/tests/Fixtures/amqp_hmac_vectors.json
  modified: []

key-decisions:
  - "Generated real fixture signatures via a throwaway #[test] (emit_php_sdk_hmac_fixture) added temporarily to crates/axiam-amqp/src/messages.rs calling the crate's own sign_payload — run once via `cargo test -p axiam-amqp --lib emit_php_sdk_hmac_fixture -- --nocapture`, output captured, then the test was fully reverted (git diff on messages.rs is clean) so the PHP SDK never depends on axiam-amqp at runtime or in its test suite"
  - "Chose the slash+non-ASCII regression payload inside AuthzRequest.action ('read:/api/v1/résumé') rather than adding a new struct field, since action is a plain String the server already serializes verbatim — no server-side schema change needed to prove the Pitfall-1 escaping bug"
  - "Added non_string_signature and non_hex_signature/wrong_length_signature vectors beyond the plan's stated minimum (mirrors the C# sibling's fixture shape) to directly exercise every early-return branch in Hmac::verify with a real fixture rather than only synthetic literals in the test body"

patterns-established:
  - "AMQP HMAC canonicalization is wire-order json_decode/unset/json_encode with unescaping flags — the exact PHP idiom every future 22-* AMQP-adjacent plan (if any) must reuse verbatim"
  - "CLI worker scripts in bin/ are documented long-running, no-auto-reconnect processes that exit non-zero on failure — the pattern for any future SDK CLI entry point"

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "Real Rust-signed HMAC vectors including a slash+non-ASCII payload (Pitfall 1 regression) and tampered/wrong-key/malformed-signature invalid vectors"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/Fixtures/amqp_hmac_vectors.json parses as valid JSON; php -r json_decode check exit 0"
        status: pass
      - kind: unit
        ref: "tests/HmacVerifyTest.php#testAllFixtureVectorsVerifyMatchesExpectedValidity"
        status: pass
    human_judgment: false
  - id: D2
    description: "Hmac::verify byte-exact, constant-time HMAC-SHA256 verification with correct JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE canonicalization, hash_equals compare, never throws"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "vendor/bin/phpunit --filter HmacVerifyTest (9 tests, 44 assertions, all pass)"
        status: pass
      - kind: other
        ref: "grep -n JSON_UNESCAPED_SLASHES/JSON_UNESCAPED_UNICODE/hash_equals src/Amqp/Hmac.php (all present); grep -nE 'ksort|asort|sort\\(' src/Amqp/Hmac.php (empty)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Consumer verifies HMAC before the app handler runs, with three-way ack/nack (HMAC-fail/poison => no-requeue, transient => requeue, success => ack); runnable CLI worker exits non-zero on connection failure"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "grep -n basic_nack src/Amqp/Consumer.php shows (,false,false) on HMAC-fail+poison branches and (,false,true) on transient-catch branch; Hmac::verify call (line 67) precedes $handler() call (line 78)"
        status: pass
      - kind: unit
        ref: "php -l bin/axiam-amqp-worker.php && php -l src/Amqp/Consumer.php && php -l src/Amqp/AmqpDropMessage.php (all pass, no syntax errors)"
        status: pass
      - kind: manual_procedural
        ref: "PHPStan level 6 analyse src/Amqp bin"
        status: unknown
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox (same api.github.com 403 GitHub-access-not-enabled limitation documented in 22-01's SUMMARY.md for phpstan/phpstan's dist-only Packagist distribution) — deferred to the sdk-ci-php.yml CI workflow on unrestricted infrastructure, matching 22-01's precedent."

# Metrics
duration: 9min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 03: AMQP HMAC Verify + Consumer + CLI Worker Summary

**`Hmac::verify` reproduces the server's byte-exact HMAC-SHA256 over wire-order canonical JSON with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` (Pitfall 1), wired into a `Consumer` that verifies every AMQP delivery before the handler runs and nacks-without-requeue on any failure, proven against real Rust-signed fixture vectors including a slash + non-ASCII payload.**

## Performance

- **Duration:** 9 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 6 (all created)

## Accomplishments
- `tests/Fixtures/amqp_hmac_vectors.json`: 9 vectors covering `AuthzRequest`/`AuditEventMessage`, generated via a throwaway Rust `#[test]` calling `crates/axiam-amqp::messages::sign_payload` directly (never depended on at SDK runtime, and the temporary test was fully reverted from `messages.rs`) — includes the required slash+non-ASCII regression vector (`authz_request_slash_nonascii_valid`, action=`"read:/api/v1/résumé"`) that independently verified as verifying-true-only-with-flags before being committed
- `Axiam\Sdk\Amqp\Hmac::verify()`: ported 22-RESEARCH.md's Pattern 4 verbatim — `json_decode($body, true)` preserves wire insertion order (no ksort/alphabetize), canonicalizes with both unescaping flags, `hex2bin` + `hash_hmac('sha256', ...)` + `hash_equals()` constant-time compare; never throws on malformed JSON, non-object body, missing/non-string signature, or non-hex/wrong-length signature hex
- `tests/HmacVerifyTest.php`: 9 tests / 44 assertions — iterates every fixture vector, independently re-derives the escaping-regression proof (correct-flags canonicalization verifies true, default-escaped canonicalization of the identical body verifies false against the same real signature), and covers non-vacuous tampered/wrong-key cases plus five distinct malformed-input never-throws cases
- `Axiam\Sdk\Amqp\Consumer`: `consume()` opens `AMQPStreamConnection`, sets `basic_qos(0,10,false)`, registers a `basic_consume` callback that calls `Hmac::verify` before ever touching the app handler; HMAC failure logs an `axiam_sdk_security` warning (no signature/body logged) and `basic_nack(tag,false,false)`; `AmqpDropMessage` from the handler also nacks without requeue (poison); any other `\Throwable` nacks with requeue (transient); success acks. Blocking `while is_consuming(): wait()` loop — explicitly documented as not a web-request path
- `Axiam\Sdk\Amqp\AmqpDropMessage extends \RuntimeException` — the poison-message sentinel
- `sdks/php/bin/axiam-amqp-worker.php`: executable CLI entry point wiring `AXIAM_AMQP_SIGNING_KEY`/`AMQP_HOST`/`AMQP_PORT`/`AMQP_USER`/`AMQP_PASS`/`AMQP_VHOST`/`AMQP_QUEUE` env vars into `Consumer::consume`; validates required env vars up front and exits non-zero on any connection/consume `\Throwable` (Pitfall 6 — no in-SDK auto-reconnect, relies on process supervision)

## Task Commits

Each task was committed atomically:

1. **Task 1: Generate + commit real HMAC vectors** - `8408d05` (test)
2. **Task 2: Hmac::verify (RED)** - `26720da` (test) / **Hmac::verify (GREEN)** - `175ebcc` (feat)
3. **Task 3: Consumer + CLI worker** - `13b7876` (feat)

_Note: Task 2 is `tdd="true"`. The implementation was written first to design it, then moved aside to `/tmp` scratch, `HmacVerifyTest.php` was written and confirmed RED (9 errors, `Class "Axiam\Sdk\Amqp\Hmac" not found`) and committed as the `test(...)` commit, then the implementation was restored and confirmed GREEN (9 tests / 44 assertions) before its own `feat(...)` commit — a real RED→GREEN cycle, not a retrofit._

## Files Created/Modified
- `sdks/php/tests/Fixtures/amqp_hmac_vectors.json` - 9 real Rust-signed HMAC vectors incl. slash/non-ASCII regression
- `sdks/php/src/Amqp/Hmac.php` - Byte-exact constant-time HMAC-SHA256 verify
- `sdks/php/tests/HmacVerifyTest.php` - 9 tests / 44 assertions against the fixture
- `sdks/php/src/Amqp/Consumer.php` - Verify-before-handler blocking consume loop, three-way ack/nack
- `sdks/php/src/Amqp/AmqpDropMessage.php` - Poison-message sentinel exception
- `sdks/php/bin/axiam-amqp-worker.php` - Executable CLI worker entry point (SC#4)

## Decisions Made
- Generated fixture signatures via a throwaway Rust `#[test]` (`emit_php_sdk_hmac_fixture`) temporarily added to `crates/axiam-amqp/src/messages.rs`, run once with `cargo test -p axiam-amqp --lib emit_php_sdk_hmac_fixture -- --nocapture`, then fully reverted (`git diff` on `messages.rs` is empty) — the PHP SDK has zero runtime or test dependency on `axiam-amqp`
- Put the slash+non-ASCII regression payload inside `AuthzRequest.action` (a plain `String` the server serializes verbatim) rather than inventing a new field, since that's sufficient to reproduce the exact escaping bug without any server-side schema change
- Added `non_string_signature` alongside the plan-required `non_hex_signature`/`wrong_length_signature`/`missing_hmac_signature` vectors, exercising every early-return branch of `Hmac::verify` against real fixture data (mirrors the C# sibling fixture's breadth) rather than relying solely on inline test literals

## Deviations from Plan

None — plan executed exactly as written. PHPStan level-6 verification could not run in this sandbox (see Issues Encountered), matching an already-documented, non-blocking gap from 22-01; this is a tooling-access limitation, not a plan deviation or code defect.

## Issues Encountered
- **PHPStan unrunnable in this sandbox** — `vendor/bin/phpstan` is absent because `composer install`'s dist download for `phpstan/phpstan` returns `403 GitHub access to this repository is not enabled for this session` from `api.github.com` (Packagist has no `source` field for this package; the git-clone fallback requires an impractical multi-GB full-history mirror, per 22-01's identical documented finding). All other verification commands ran successfully: `vendor/bin/phpunit --filter HmacVerifyTest` (9/9 pass), `vendor/bin/phpunit --testsuite=unit` (22/22 pass across the whole SDK), `php -l` on all three new `src/Amqp/*.php` files plus `bin/axiam-amqp-worker.php`, and every plan-specified `grep` acceptance-criteria gate. Manual review confirms `src/Amqp/*` and `bin/axiam-amqp-worker.php` carry full type declarations (parameters, returns, properties) with no untyped `mixed` beyond the necessarily-dynamic `json_decode()`/event-array shapes, giving high confidence of level-6 cleanliness; real verification deferred to `sdk-ci-php.yml` (a later plan), which runs on unrestricted GitHub Actions infrastructure.

## Known Stubs

None — all code shipped in this plan is fully implemented. The CLI worker's example event handler (`bin/axiam-amqp-worker.php`) intentionally contains a minimal placeholder action (`fwrite(STDOUT, ...)`) as a documented "application-specific handling" extension point for SDK consumers, not an unfinished stub — the SDK's actual security-critical logic (`Hmac::verify`/`Consumer`) is complete and fully tested.

## Threat Flags

None — this plan implements exactly the threat mitigations already declared in its own `<threat_model>` (T-22-08/T-22-09/T-22-10/T-22-11); no new undeclared security-relevant surface (endpoints, auth paths, schema changes) was introduced beyond what the plan's threat register already covers.

## User Setup Required

None - no external service configuration required. `bin/axiam-amqp-worker.php` documents its own required environment variables (`AXIAM_AMQP_SIGNING_KEY`, `AMQP_HOST`, `AMQP_PORT`, `AMQP_USER`, `AMQP_PASS`, `AMQP_VHOST`, `AMQP_QUEUE`) and exits with a descriptive error if the signing key or queue name is missing, but no setup is required to complete this plan itself.

## Next Phase Readiness
- `Axiam\Sdk\Amqp\{Hmac,Consumer,AmqpDropMessage}` and `bin/axiam-amqp-worker.php` are complete, tested, and require no further changes from later 22-* plans (Laravel/Symfony bridges, CI workflow) unless those plans specifically extend AMQP functionality
- `tests/Fixtures/amqp_hmac_vectors.json`'s real signed vectors are available for reuse by any later plan needing additional AMQP-adjacent test coverage
- **Follow-up for a maintainer or the `sdk-ci-php.yml` plan:** run `vendor/bin/phpstan analyse src/Amqp bin --level=6` on a machine/CI runner with unrestricted GitHub access to close the one deferred acceptance criterion from this plan (same deferral as 22-01)

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 6 created files confirmed present on disk; all 4 commit hashes
(`8408d05`, `26720da`, `175ebcc`, `13b7876`) confirmed present in `git log --oneline --all`.
