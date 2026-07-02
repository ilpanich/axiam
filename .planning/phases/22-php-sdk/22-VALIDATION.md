---
phase: 22
slug: php-sdk
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-07-02
---

# Phase 22 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `22-RESEARCH.md` § Validation Architecture. Task IDs are bound
> to plans during planning/execution; the SC-level behaviors below are the
> fixed acceptance targets.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | PHPUnit ^9.6 (PHP ≥8.1 LTS-compatible line) |
| **Config file** | `sdks/php/phpunit.xml.dist` — created in Wave 0 (unit/integration testsuite split) |
| **Quick run command** | `vendor/bin/phpunit --testsuite=unit` |
| **Full suite command** | `composer test` (wraps `vendor/bin/phpunit`; incl. SC#2 single-flight + AMQP HMAC fixture + Laravel/Symfony bridge tests) |
| **Estimated runtime** | ~30 seconds (unit), ~90 seconds (full incl. framework integration) |

---

## Sampling Rate

- **After every task commit:** Run `vendor/bin/phpunit --testsuite=unit` (fast unit tests: `Sensitive` redaction, HMAC fixture vectors incl. the slash/unicode escaping regression, JWKS `kid` lookup, single-flight refresh logic)
- **After every plan wave:** Run `composer test` (full suite incl. Laravel/Symfony integration tests)
- **Before `/gsd-verify-work`:** Full suite green + `composer validate` + TLS-bypass grep gate empty
- **Max feedback latency:** ~30 seconds (unit tier)

---

## Per-Task Verification Map

> Task IDs bind during planning. Rows are the fixed SC-level acceptance targets.

| Behavior (SC / decision) | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|--------------------------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| SC#1 — `composer require` installs; `tenant` required ctor param (no nullable default); `login()` returns typed `LoginResult` | 1 | PHP-01 | — | Constructor rejects missing tenant | unit | `vendor/bin/phpunit --filter ClientConstructionTest` | ❌ W0 | ⬜ pending |
| SC#2 — N concurrent Guzzle async promises on expired token ⇒ exactly 1 refresh | 2 | PHP-01 | T-thundering-herd | Shared-`Promise` single-flight guard | unit (`MockHandler` + `Middleware::history`, deliberately-ordered 401 queue) | `vendor/bin/phpunit --filter SingleFlightRefreshTest` | ❌ W0 | ⬜ pending |
| SC#3 — gRPC guarded by `extension_loaded('grpc')`; REST-only fallback; runtime requirement documented | 3 | PHP-01 | T-grpc-fatal | Guard at every gRPC class reference | unit (fallback via indirection) + doc-presence check | `vendor/bin/phpunit --filter AuthzDispatcherFallbackTest` | ❌ W0 | ⬜ pending |
| SC#4 — Laravel + Symfony helpers protect a sample endpoint; AMQP HMAC-verify + nack-no-requeue on failure | 3 | PHP-01 | T-amqp-tamper | HMAC verify-before-handler, fail-closed, `hash_equals` | integration (Laravel `TestCase` / Symfony `KernelTestCase`) + unit (HMAC fixture) | `vendor/bin/phpunit --filter "LaravelMiddlewareTest\|SymfonyAuthSubscriberTest\|HmacVerifyTest"` | ❌ W0 | ⬜ pending |
| SC#5 — `composer test` passes; Packagist automation runs on release tag | 4 | PHP-01 | — | CI publish on tag | build/CI | `composer validate && composer test` | ❌ W0 | ⬜ pending |
| D-11/CR-04 — raw token never in `Sensitive`/`NetworkError` `__toString`/JSON/log | 1 | PHP-01 | T-token-leak | Redact-before-wrap (carried-forward real bug class) | unit (non-vacuous control case) | `vendor/bin/phpunit --filter SensitiveRedactionTest` | ❌ W0 | ⬜ pending |
| D-12 — no `verify => false` anywhere in `sdks/php/` | 4 | PHP-01 | T-tls-bypass | Absolute TLS-verify prohibition; only `customCa` escape | static (CI grep gate) | `grep -rn "verify.*=>.*false" sdks/php --include=*.php \| grep -v customCa` (expect empty) | ❌ W0 | ⬜ pending |
| Pitfall 1 — AMQP HMAC canonicalization uses `JSON_UNESCAPED_SLASHES\|JSON_UNESCAPED_UNICODE` | 2 | PHP-01 | T-amqp-tamper | Byte-exact parity with server `serde_json` | unit (slash + non-ASCII fixture vector) | `vendor/bin/phpunit --filter HmacVerifyTest` | ❌ W0 | ⬜ pending |
| Pitfall 5 — JWT `alg` pinned to `EdDSA` before key lookup | 1 | PHP-01 | T-alg-confusion | Reject non-EdDSA header pre-verification | unit | `vendor/bin/phpunit --filter JwtVerifyTest` | ❌ W0 | ⬜ pending |
| Pitfall 3 — post-signature `tenant_id` claim check | 1 | PHP-01 | T-cross-tenant | Fail closed on tenant mismatch | unit | `vendor/bin/phpunit --filter JwtVerifyTest` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `sdks/php/composer.json` — package `axiam/axiam-sdk`, PSR-4 autoload, `scripts.test` wiring `phpunit` (so `composer test` works per SC#5)
- [ ] `sdks/php/phpunit.xml.dist` — test suite config (unit/integration split)
- [ ] `composer require --dev phpunit/phpunit:^9.6 phpstan/phpstan:^2.2` — framework install
- [ ] `sdks/php/tests/Fixtures/` — real Rust-signed HMAC byte-vector fixture **including** a slash-containing and non-ASCII payload variant (generate once from `crates/axiam-amqp` `sign_payload`; commit the fixed byte array + expected hex signature — do NOT depend on `axiam-amqp` at runtime)
- [ ] `sdks/php/tests/Fixtures/` — real Ed25519 keypair + AXIAM-shaped JWKS document + matching signed JWT fixture (mirrors Java/C# "confirm empirically before committing" approach)

*Wave 0 gaps above; no existing PHP test infrastructure — scaffold created this phase.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Packagist publish on release tag | PHP-01 (SC#5) | Requires external Packagist registry + real release tag; not exercisable in CI unit run | On tag `sdks/php/vX.Y.Z`, confirm CI publish job succeeds and `composer require axiam/axiam-sdk` resolves the new version from Packagist |
| gRPC over Swoole/RoadRunner long-running runtime | PHP-01 (SC#3) | Requires `ext-grpc` PECL + long-running runtime not present in default CI image | Documented runtime requirement; optional CI matrix leg with `ext-grpc` installed verifies the gRPC path when available |

---

## Validation Sign-Off

- [x] All SC-level behaviors have an `<automated>` verify target or Wave 0 dependency
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (composer/phpunit config + crypto fixtures)
- [x] No watch-mode flags
- [x] Feedback latency < 30s (unit tier)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-02
