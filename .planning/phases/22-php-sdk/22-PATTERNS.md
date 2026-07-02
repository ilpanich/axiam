# Phase 22: PHP SDK - Pattern Map

**Mapped:** 2026-07-02
**Files analyzed:** 27 (core `src/`, bridges, AMQP worker, CI, examples, tests)
**Analogs found:** 27 / 27 (all files have at least a role-match sibling-SDK analog)

> **Note:** RESEARCH.md (`22-RESEARCH.md`, Architecture Patterns 1–5) already contains
> complete, source-grounded PHP code for the hardest patterns (single-flight refresh,
> gRPC guard, Laravel/Symfony bridges, AMQP HMAC worker, JWKS verifier) — that PHP code
> IS the primary pattern source for those files; this document adds the sibling-SDK
> structural analogs (C#/Python/Go) and the server-side byte-exact contract
> (`crates/axiam-amqp/src/messages.rs`) that the RESEARCH.md code was itself derived
> from, plus CI/composer/buf wiring not covered in RESEARCH.md's code samples.

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `sdks/php/src/AxiamClient.php` | service (client facade) | request-response | `sdks/csharp/Axiam.Sdk/AxiamClient.cs` (or Python `_client.py`) | role-match |
| `sdks/php/src/Session.php` | service (session/state) | request-response | `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` + Python `_session.py` | role-match; PHP code already in RESEARCH.md Pattern 1 |
| `sdks/php/src/Auth/LoginResult.php` | model (DTO) | CRUD (response mapping) | Python `_models.py` (`LoginResult`) / C# DTO records | exact (readonly DTO idiom, D-09) |
| `sdks/php/src/Auth/RefreshGuard.php` | service (concurrency guard) | event-driven (single-flight) | `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs`, `sdks/csharp/tests/Axiam.Sdk.Tests/RefreshGuardSingleFlightTests.cs` | exact (same D-06 mechanism, promise instead of lock) |
| `sdks/php/src/Auth/JwksVerifier.php` | service (crypto/verification) | request-response | `sdks/python/src/axiam_sdk/_jwks.py` | role-match; PHP code in RESEARCH.md Pattern 5 |
| `sdks/php/src/Rest/AuthMiddleware.php` | middleware | request-response | `sdks/python/src/axiam_sdk/_session.py` (header injection) / Guzzle `HandlerStack` idiom | role-match; PHP code in RESEARCH.md Pattern 1 |
| `sdks/php/src/Rest/RefreshMiddleware.php` | middleware | event-driven (401-retry) | `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` (`DelegatingHandler` equivalent) | role-match; PHP code in RESEARCH.md Pattern 1 |
| `sdks/php/src/Rest/AuthzRestClient.php` | service (CRUD over REST) | request-response | `crates/axiam-api-rest/src/handlers/authz_check.rs` (server contract) + Python REST authz client | role-match |
| `sdks/php/src/Grpc/AuthzGrpcClient.php` | service (gRPC client) | request-response | `sdks/python/src/axiam_sdk/grpc/client.py` + `sdks/python/src/axiam_sdk/grpc/_interceptor.py` | role-match; guard pattern in RESEARCH.md Pattern 2 |
| `sdks/php/src/Grpc/Gen/*.php` | generated stub | request-response | Go/Python committed `gen/`/`internal/gen` stub dirs (source-distributed, D-03) | role-match (codegen output, no hand-write) |
| `sdks/php/src/Amqp/Consumer.php` | service (consumer, CLI) | event-driven | `sdks/python/src/axiam_sdk/amqp/_consumer.py` | role-match; PHP code in RESEARCH.md Pattern 4 |
| `sdks/php/src/Amqp/Hmac.php` | utility (crypto verify) | transform | `crates/axiam-amqp/src/messages.rs` (`sign_payload`/`verify_payload`, lines 30–50) — **byte-exact contract, server side** + `sdks/python/src/axiam_sdk/amqp/_hmac.py` | exact (server = ground truth); PHP code in RESEARCH.md Pattern 4 |
| `sdks/php/src/Core/Sensitive.php` | utility (redaction wrapper) | transform | `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs` | exact |
| `sdks/php/src/Core/AxiamException.php` | utility (error base) | transform | `sdks/csharp/Axiam.Sdk/Core/AuthError.cs` (base pattern) | role-match |
| `sdks/php/src/Core/AuthError.php` | utility (typed error) | transform | `sdks/csharp/Axiam.Sdk/Core/AuthError.cs` | exact |
| `sdks/php/src/Core/AuthzError.php` | utility (typed error) | transform | `sdks/csharp/Axiam.Sdk/Core/AuthzError.cs` | exact |
| `sdks/php/src/Core/NetworkError.php` | utility (typed error, redact-before-wrap) | transform | `sdks/csharp/Axiam.Sdk/Core/NetworkError.cs` + `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`, CR-04 origin) | exact |
| `sdks/php/src/Core/ErrorMapper.php` | utility (status→error mapper) | transform | `sdks/csharp/Axiam.Sdk/Core/ErrorMapper.cs` | exact |
| `sdks/php/src/Laravel/AxiamServiceProvider.php` | provider | event-driven (bootstrap) | none in siblings (PHP-only concept) — nearest is Python `django/middleware.py` app-registration idiom | role-match (novel to PHP); PHP code in RESEARCH.md Pattern 3 |
| `sdks/php/src/Laravel/AxiamMiddleware.php` | middleware | request-response | `sdks/python/src/axiam_sdk/django/middleware.py` | role-match; PHP code in RESEARCH.md Pattern 3 |
| `sdks/php/src/Laravel/AxiamGate.php` | provider (authz gate) | request-response | `sdks/python/src/axiam_sdk/fastapi/__init__.py` (dependency-based authz helper) | role-match |
| `sdks/php/src/Symfony/AxiamBundle.php` | provider | event-driven (bootstrap) | none in siblings — see Laravel ServiceProvider as nearest structural sibling | role-match (novel to PHP) |
| `sdks/php/src/Symfony/AxiamAuthSubscriber.php` | middleware (event subscriber) | request-response | `sdks/python/src/axiam_sdk/django/middleware.py` | role-match; PHP code in RESEARCH.md Pattern 3 |
| `sdks/php/src/Symfony/AxiamVoter.php` | middleware (authz voter) | request-response | `sdks/php/src/Laravel/AxiamGate.php` (sibling-in-package) / Python FastAPI dependency authz | role-match |
| `sdks/php/bin/axiam-amqp-worker.php` | utility (CLI entrypoint) | event-driven | `sdks/python/examples/amqp_consumer.py` | role-match; PHP code in RESEARCH.md Pattern 4 |
| `sdks/php/tests/SingleFlightRefreshTest.php` | test | event-driven | `sdks/csharp/tests/Axiam.Sdk.Tests/RefreshGuardSingleFlightTests.cs` + `sdks/python/tests/test_single_flight.py` | exact; PHPUnit code in RESEARCH.md Pattern 1 |
| `sdks/php/tests/SensitiveRedactionTest.php` | test | transform | `sdks/csharp/tests/Axiam.Sdk.Tests/SensitiveRedactionTests.cs` + `sdks/python/tests/test_error_redaction.py` | exact |
| `.github/workflows/sdk-ci-php.yml` | config (CI) | batch | `.github/workflows/sdk-ci-csharp.yml` (full build/test/gate/pack/publish lifecycle) + `.github/workflows/sdk-ci-python.yml` (structural template, closer language ecosystem) | role-match — see Shared Patterns below |
| `sdks/buf.gen.yaml` (PHP plugin entry, modified) | config (codegen) | batch | existing `go`/`python` plugin blocks (lines 28–42) | exact (same remote-plugin idiom) |

## Pattern Assignments

### `sdks/php/src/Session.php` + `sdks/php/src/Rest/RefreshMiddleware.php` (service/middleware, event-driven single-flight)

**Analog:** `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` (mutex/lock-based single-flight) and its test `sdks/csharp/tests/Axiam.Sdk.Tests/RefreshGuardSingleFlightTests.cs`. The PHP mechanism is a **shared `PromiseInterface`** rather than a lock (Fiber-cooperative, no true parallelism) — the concrete PHP implementation is already written out in `22-RESEARCH.md` Pattern 1 (lines ~298–476): `Session::refreshIfNeeded()`, `RefreshMiddleware::__invoke()`, and the SC#2 PHPUnit `MockHandler`-counted test. Use that code verbatim as the starting point; do not re-derive from C# since C#'s `SemaphoreSlim`/lock idiom does not translate — only the **guard semantics** (check-and-store once, all concurrent callers await the same in-flight operation, clear on both success and failure, retry exactly once with no loop) transfer.

**Core pattern to copy (guard-clear-on-both-paths):**
```csharp
// sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs — semantics to mirror (see file for full lock code)
// clears the in-flight guard on BOTH success and failure so the NEXT 401 starts a fresh attempt,
// and callers awaiting the in-flight task all receive the same result (single network call).
```
Mirror this guard-clear-on-both-paths behavior in PHP's `Session::refreshIfNeeded()` (RESEARCH.md already does this via `->then(onSuccess, onFailure)` both setting `$this->refreshPromise = null`).

---

### `sdks/php/src/Amqp/Hmac.php` (utility, transform — HMAC verify)

**Analog (byte-exact contract, must match):** `crates/axiam-amqp/src/messages.rs`

**Server signing/verify reference** (lines 30–50):
```rust
pub fn sign_payload(key: &[u8], payload_json: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_payload(key: &[u8], payload_json: &[u8], signature_hex: &str) -> bool {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload_json);
    let expected = hex::decode(signature_hex).unwrap_or_default();
    mac.verify_slice(&expected).is_ok()
}
```
Key contract facts the PHP port MUST preserve: (1) canonical bytes = the message JSON with `hmac_signature` removed, in **original wire/insertion order** (not alphabetized — the field-order pitfall every prior SDK hit); (2) hex-encoded HMAC-SHA256; (3) constant-time compare on the verify side.

**PHP port (already written, use directly):** `22-RESEARCH.md` Pattern 4, `Hmac::verify()` — uses `hash_hmac('sha256', $canonical, $signingKey, true)` + `hash_equals()`, and **critically** `json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)` (PHP-specific pitfall #1 — omitting these flags silently breaks verification for any `/`-containing or non-ASCII payload). Also mirror `sdks/python/src/axiam_sdk/amqp/_hmac.py` for the sibling structural shape (verify-then-strip-field idiom) but treat the Rust file as the normative byte contract.

**Test analog:** build `HmacVerifyTest.php` against `sdks/python/tests/test_amqp_hmac.py`'s fixture-based approach (real signed vectors), and add a payload with `/` + non-ASCII text per RESEARCH.md Pitfall 1's explicit warning that ASCII/UUID-only fixtures hide the bug.

---

### `sdks/php/src/Amqp/Consumer.php` + `sdks/php/bin/axiam-amqp-worker.php` (service/CLI, event-driven)

**Analog:** `sdks/python/src/axiam_sdk/amqp/_consumer.py` (structural: verify-before-handler, ack/nack-no-requeue on HMAC/parse failure, nack-with-requeue on transient handler failure) and `sdks/python/examples/amqp_consumer.py` (CLI worker shape). PHP-specific: `php-amqplib` has **no built-in reconnection** (unlike Go/C#) — the worker must exit non-zero on connection loss and rely on process supervision (RESEARCH.md Pitfall 6). Concrete PHP code (Consumer class + CLI worker script) is already written in `22-RESEARCH.md` Pattern 4 (lines ~751–811) — use directly; the `AmqpDropMessage` poison-message exception and the three-way ack/nack-requeue/nack-no-requeue branching should mirror `crates/axiam-amqp/src/messages.rs`'s consumer-side semantics described in the AMQP HMAC doc comment (server owns the signing key distribution; PHP takes the signing key as a caller-supplied constructor parameter, same as every sibling SDK — no `GET .../amqp-signing-key` endpoint exists).

---

### `sdks/php/src/Auth/JwksVerifier.php` (service, request-response — JWKS/EdDSA verification)

**Analog:** `sdks/python/src/axiam_sdk/_jwks.py` (OIDC-discovery + TTL-cache + rotate-on-unknown-kid shape) and `sdks/python/tests/test_jwks.py`. PHP-specific: use `firebase/php-jwt`'s `JWK::parseKeySet()` + a hand-rolled ~15-line TTL cache — **do NOT use `CachedKeySet`** (pulls in PSR-18/PSR-17/PSR-6 chain, RESEARCH.md Pitfall 2). Concrete PHP code already written in `22-RESEARCH.md` Pattern 5 (lines ~822–911): `JwksVerifier::verify()` pins `alg === 'EdDSA'` before key lookup, guards `extension_loaded('sodium')`, and — critically — checks `tenant_id` claim after signature verification succeeds (JWKS is org-wide not tenant-scoped, Pitfall 3, same finding every sibling SDK made independently). Use this code directly.

---

### `sdks/php/src/Core/{Sensitive,AxiamException,AuthError,AuthzError,NetworkError,ErrorMapper}.php` (utility, transform — error taxonomy + redaction)

**Analog:** `sdks/csharp/Axiam.Sdk/Core/Sensitive.cs`, `AuthError.cs`, `AuthzError.cs`, `NetworkError.cs`, `ErrorMapper.cs` — read these five files directly for the exact class-hierarchy shape (`AxiamException` base, three typed subclasses, one central status→error mapper) since D-10 explicitly rejects "a flat enum-of-codes" and requires this hierarchy. Also read `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`) — this is the **CR-04 origin fix** (token-leak-via-error finding from TS Phase 17 Review) that `NetworkError`'s redact-before-wrap logic must replicate: strip `Set-Cookie`/`Authorization`/`Cookie` from any wrapped response/exception **before** constructing the exception, never after.

**PHP idiom differences to apply on top of the C# structure:**
- `Sensitive::__toString()` → `"[SENSITIVE]"` (§7) + implement `JsonSerializable` returning `"[SENSITIVE]"` (D-11's PHP-specific JSON hardening — C# has no equivalent `JsonSerializable` interface concern, this is new PHP-specific work).
- Redaction must happen in `NetworkError`'s constructor/factory (`NetworkError::fromResponse()`) **before** any property assignment — mirror the C# `NetworkError.cs` constructor-time redaction pattern exactly.

**Test analog:** `sdks/csharp/tests/Axiam.Sdk.Tests/SensitiveRedactionTests.cs` + `sdks/python/tests/test_error_redaction.py` — both include a **non-vacuous control case** (a test that would fail if redaction were removed); D-11 requires the same discipline in `SensitiveRedactionTest.php`.

---

### `sdks/php/src/Grpc/AuthzGrpcClient.php` + `AuthzDispatcher` guard (service, request-response — gRPC guarded fallback)

**Analog:** `sdks/python/src/axiam_sdk/grpc/client.py` + `sdks/python/src/axiam_sdk/grpc/_interceptor.py` (metadata injection: `Authorization`/`X-Tenant-Id` on every RPC) and `sdks/python/src/axiam_sdk/grpc/_tls.py` (channel credentials / no-bypass TLS). PHP's guard mechanism (`extension_loaded('grpc')`, never referencing `\Grpc\BaseStub` outside the guard) is PHP-specific — the concrete `AuthzDispatcher` dispatcher class is already written in `22-RESEARCH.md` Pattern 2 (lines ~489–539). Server-side semantics to match: `crates/axiam-api-grpc/src/services/authorization.rs` (`CheckAccess`/`BatchCheckAccess`) and the REST fallback target `crates/axiam-api-rest/src/handlers/authz_check.rs` (`POST /api/v1/authz/check[/batch]`, FND-04).

---

### `sdks/php/src/Laravel/*` and `sdks/php/src/Symfony/*` (provider/middleware, request-response — framework bridges)

**Analog:** No sibling SDK has a Laravel/Symfony equivalent (Go/Rust/Java/C# have no PHP-framework concept; the nearest structural sibling is `sdks/python/src/axiam_sdk/django/middleware.py` for the auth-middleware half, and `sdks/python/src/axiam_sdk/fastapi/__init__.py` for the dependency-injection/authz-gate half). The concrete PHP code for both bridges (ServiceProvider, Middleware, Gate for Laravel; EventSubscriber, Voter for Symfony) is fully written in `22-RESEARCH.md` Pattern 3 (lines ~541–683) — use directly. Two structural facts from RESEARCH.md are load-bearing and must not be lost in planning:
1. Laravel gets **true zero-config auto-discovery** via `composer.json`'s `extra.laravel.providers` (no manual wiring).
2. Symfony has **no equivalent** — `config/bundles.php` + `config/services.yaml` registration is manual (Pitfall 5); do not describe both as "auto-discovered" in docs/README.

Both bridges call into the *same* core `AxiamClient::verifyLocallyOrFallback()` / `AxiamClient::can()` methods — never duplicate JWKS-verify or refresh logic inside the bridge classes (D-02).

---

## Shared Patterns

### CI workflow lifecycle (build/test/gate/publish)
**Source:** `.github/workflows/sdk-ci-csharp.yml` (full lifecycle: scaffold-check → build-test [restore/build/test/TLS-grep-gate/pack] → publish-on-tag with graceful no-op if the registry credential secret is absent).
**Apply to:** `.github/workflows/sdk-ci-php.yml`, which currently is **only a scaffold-check stub** (verifies `LICENSE` exists) and must be extended with:
- `composer validate` + `composer install` + `composer test` (PHPUnit, incl. SC#2 single-flight and the redaction/HMAC regression tests)
- The TLS-bypass grep gate (D-12/SC#4) — adapt the C# grep step's shape but search for `verify.*=>.*false` / `'verify'\s*=>\s*false` patterns across `sdks/php/` (source, examples, tests) instead of `ServerCertificateCustomValidationCallback`.
- A **subtree-split → mirror-repo push → tag-triggered Packagist update** step (D-05) — this has **no C# analog** (NuGet publishes the monorepo subdirectory directly via `dotnet pack`/`dotnet nuget push`); model this new step on the described `git subtree split` (or `splitsh-lite`) + push-to-mirror-repo + re-tag flow in CONTEXT.md D-05, gated `if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/sdks/php/v')`, with the same graceful "credential/mirror absent → warning, not failure" posture C#'s `NUGET_API_KEY`-absent branch uses (lines 170–174 of `sdk-ci-csharp.yml`).
- Reference `sdk-ci-python.yml` for the ecosystem-appropriate ordering (install deps before lint/test) since Python and PHP are both interpreted/Composer-or-pip ecosystems, unlike C#'s compile-first model.

### `sdks/buf.gen.yaml` PHP plugin entry
**Source:** existing `go`/`python` plugin blocks (lines 28–42 of `sdks/buf.gen.yaml`):
```yaml
  - remote: buf.build/protocolbuffers/go
    out: go/internal/gen
  - remote: buf.build/grpc/go
    out: go/internal/gen
  ...
  - remote: buf.build/protocolbuffers/python
    out: python/axiam_sdk/gen
  - remote: buf.build/grpc/python
    out: python/axiam_sdk/gen
```
**Apply to:** add a PHP block using `buf.build/protocolbuffers/php` + `buf.build/grpc/php` remote plugins, `out: php/src/Grpc/Gen` (matching the RESEARCH.md structure `sdks/php/src/Grpc/Gen/`) — same two-plugin-pair idiom as Go/Python, since PHP (like Go/Python) is source-distributed and commits generated stubs (D-03), unlike C#'s build-time-only exception.

### Typed exception hierarchy + redaction (D-10/D-11, CR-04 carry-forward)
**Source:** `sdks/csharp/Axiam.Sdk/Core/{AuthError,AuthzError,NetworkError,ErrorMapper,Sensitive}.cs` + `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`).
**Apply to:** all `Core/`, `Rest/`, `Grpc/` files that throw/catch AXIAM errors — one central `ErrorMapper` is the only place that converts HTTP status / gRPC status into a typed exception; nothing else hand-rolls status-code branching.

### Single-flight refresh guard (D-06)
**Source:** `sdks/csharp/Axiam.Sdk/Auth/RefreshGuard.cs` (semantics) + `22-RESEARCH.md` Pattern 1 (concrete PHP `Promise`-based implementation).
**Apply to:** `Session.php`, `Rest/RefreshMiddleware.php`, and (per D-06) the gRPC path must share the *same* `Session::refreshIfNeeded()` instance/promise — do not build a second independent refresh mechanism in `Grpc/AuthzGrpcClient.php`.

## No Analog Found

None — every planned file has at least a role-match analog (either a sibling SDK file or, for the two PHP-only framework-bridge bootstrap files `AxiamServiceProvider.php`/`AxiamBundle.php`, the nearest cross-language structural analog plus fully-written PHP code already present in RESEARCH.md).

## Metadata

**Analog search scope:** `sdks/csharp/`, `sdks/python/`, `sdks/go/` (referenced), `sdks/typescript/src/core/`, `crates/axiam-amqp/src/messages.rs`, `crates/axiam-api-grpc/src/services/authorization.rs`, `crates/axiam-api-rest/src/handlers/authz_check.rs`, `.github/workflows/sdk-ci-{csharp,python}.yml`, `sdks/buf.gen.yaml`, `sdks/php/` (existing scaffold: `composer.json`, `LICENSE`, `README.md`).
**Files scanned:** ~45 (directory listings + targeted reads of Rust HMAC module, C# Core/Auth directories, Python SDK tree, both CI workflow files, buf.gen.yaml plugin blocks, existing PHP scaffold).
**Pattern extraction date:** 2026-07-02

---

*Phase: 22-php-sdk*
