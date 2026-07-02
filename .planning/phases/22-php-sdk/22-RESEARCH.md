# Phase 22: PHP SDK - Research

**Researched:** 2026-07-02
**Domain:** PHP 8.1+ client SDK (Guzzle REST + php-amqplib AMQP + optional grpc PECL), Laravel/Symfony framework bridges, Packagist monorepo-subtree publishing
**Confidence:** HIGH (Guzzle/php-amqplib/firebase-php-jwt APIs and versions confirmed against official docs/source and the Packagist registry directly; AMQP-signing-key acquisition and buf PHP plugin resolution carry MEDIUM/LOW sub-findings, logged in Assumptions)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Package Structure & Framework Bridges**
- **D-01 [LOCKED]:** Single package + first-class, auto-discovered bridges. One `axiam/axiam-sdk` Composer package contains the REST/gRPC/AMQP core **plus** a first-class Laravel ServiceProvider (auto-discovered via `extra.laravel.providers`) and a Symfony Bundle/EventSubscriber, each guarded by framework class presence so the **core has zero framework deps at runtime**. NOT separate `axiam/axiam-laravel` + `axiam/axiam-symfony` packages.
- **D-02:** Bridges do auth + authz. Authentication: middleware verifies the token (local JWKS) and populates framework identity (Laravel: `$request->user()`/guard; Symfony: security token) with `user_id`/`tenant_id`/`roles`, 401 on failure. Authorization: framework-native gate calls `$client->can(resource, action)` → 403 — Laravel route middleware + Gate; Symfony a Voter. Runnable example demonstrates both.

**gRPC Posture & Guard**
- **D-03 [LOCKED]:** Committed stubs + transparent REST fallback. buf-generates PHP gRPC stubs in CI, **committed** into `sdks/php/src/` (source-distributed — PHP consumers lack `protoc`+`grpc_php_plugin`). Usage guarded by `extension_loaded('grpc')`; absent extension OR REST-only config → `checkAccess`/`can` transparently route over `POST /api/v1/authz/check`. `grpc` PECL is `suggest`/optional, **never hard-required**.
- **D-04 [LOCKED]:** AMQP = CLI-worker consumer, verify-before-handler. php-amqplib 3.7 blocking consume loop as a standalone CLI-oriented consumer class (worker script / RoadRunner worker) — **not a web-request path**. Verify HMAC-SHA256 (constant-time) BEFORE handler; success → ack; retryable failure → nack WITH requeue; HMAC-fail/parse-fail/drop-sentinel → nack WITHOUT requeue + security log. README documents prominently that gRPC channel reuse + AMQP consumer require Swoole/RoadRunner/CLI, not standard FPM (SC#3).

**Packagist Publishing**
- **D-05 [LOCKED]:** Subtree-split to a read-only mirror repo, tag-triggered. CI runs `git subtree split` (or splitsh-lite) of `sdks/php/` on tag `sdks/php/vX.Y.Z`, pushes to a read-only mirror repo re-tagged `vX.Y.Z`; Packagist points at the mirror via webhook/API. Pipeline + `composer validate` + `composer test` must pass in-phase (SC#5); live mirror/Packagist registration may be a maintainer action.

**Concurrency & Single-Flight Refresh**
- **D-06 [LOCKED]:** Shared refresh-promise single-flight in the `HandlerStack`, no extra dep. Holds a single shared refresh `Promise`: first request synchronously checks-and-stores the promise; concurrent async requests await the SAME promise → exactly 1 refresh call. Fiber-safe by construction (PHP Fibers are cooperative/non-preemptive). **No `revolt/event-loop` mutex needed on the base path.** SC#2 PHPUnit test: N concurrent Guzzle async promises against an expired token with a `MockHandler` counting refresh hits → assert == 1.

**PHP Baseline & PSR Interop**
- **D-07 [LOCKED]:** PHP 8.1 floor + PSR-3/PSR-7; Guzzle pinned. Fibers, enums, readonly properties, first-class callable syntax. PSR-3 `LoggerInterface` (silent `NullLogger` default, redaction-aware). PSR-7 messages (Guzzle-native). **Guzzle 7.x is a hard, pinned dep — no PSR-18 swappability.** PSR-11 not required.

**JWKS Acquisition & Rotation**
- **D-08 [LOCKED]:** OIDC discovery + TTL cache + rotate-on-unknown-`kid`. Resolve `jwks_uri` via `/.well-known/openid-configuration`, fetch JWKS, cache with TTL, refetch once on unknown `kid` before failing. Exact TTL + discovery/jwks paths delegated to research (confirm against server — **resolved below**).

**DTO & Error-Model Idiom**
- **D-09 [LOCKED]:** Readonly DTOs — `readonly` classes for `LoginResult` (+ `mfaRequired` + optional fields) and other responses.
- **D-10 [LOCKED]:** Typed exception hierarchy for the §2 taxonomy. `AuthError`/`AuthzError`/`NetworkError` extending `AxiamException`, thrown from one central status→error mapper. `NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie` from any wrapped PSR-7 response/exception BEFORE storing it (CR-04 carry-forward target). NOT a flat enum-of-codes.

**Token Safety & Verification (carried forward)**
- **D-11:** `Sensitive` — `__toString()` → `"[SENSITIVE]"` + redact-before-wrap on `NetworkError` + `JsonSerializable` hardening. Regression test proves raw `axiam_access`/`axiam_refresh` never appears in `__toString`/JSON/log, with a non-vacuous control case.
- **D-12:** TLS no-bypass. Guzzle `verify: true` always; no `verify => false` anywhere; only a `customCa` escape hatch; CI grep gate over `sdks/php/` must return empty.
- **D-13:** Tenant required — `tenant` (slug) is a required constructor parameter with no nullable default.

### Claude's Discretion
- Internal namespace/folder/file layout under `sdks/php/src/`.
- Exact numeric timeout/backoff/retry values and gRPC per-call deadline (idempotent-only bounded exponential backoff + jitter, honor `Retry-After`; state-changing requests never auto-retry).
- JWKS cache-TTL value and exact OIDC discovery/jwks endpoint paths (confirmed below).
- gRPC channel construction, metadata injection (`Authorization`/`X-Tenant-Id`/`X-CSRF-Token`); one long-lived channel reused across authz RPCs on long-running runtimes.
- `LoginResult` optional-field set beyond `mfaRequired`.
- composer/CI plugin + tool versions; buf PHP plugin config; PHPUnit/PHPStan/coding-standard tooling choice.
- PSR-3 logging facade specifics (default `NullLogger`, redaction-aware).

### Deferred Ideas (OUT OF SCOPE)
- Separate `axiam/axiam-laravel` + `axiam/axiam-symfony` bridge packages — revisit if bundled-bridge footprint becomes a concern.
- Framework Artisan/Console command wrappers for the AMQP worker — deferred to v1.1 starter SDK follow-up.
- `revolt/event-loop` fiber mutex on the base single-flight path — revisit only for a true-parallel (Swoole preemptive coroutine) runtime.
- A first-class persistent-connection story under standard PHP-FPM — gRPC channel reuse + AMQP consumer are long-running-runtime concerns (documented as SC#3 requirement, not solved for FPM).
- PSR-18 HTTP-client swappability — rejected; CONTRACT §4/§9 pin Guzzle `CookieJar`+`HandlerStack`.
- Live Packagist first publish + mirror-repo creation — may be a maintainer action if creds are absent in CI.
- Automated cross-language conformance harness.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PHP-01 | Deliver `sdks/php/` (`axiam/axiam-sdk`, PSR-4 `Axiam\Sdk\`, PHP ≥8.1): Guzzle REST + single-flight refresh, php-amqplib AMQP worker, optional grpc-PECL-guarded gRPC, Laravel + Symfony bridges (auth+authz), Packagist publish via monorepo subtree-split | Standard Stack (verified registry versions), Architecture Patterns (single-flight `HandlerStack` middleware, `extension_loaded('grpc')` guard + lazy-autoload interaction, CLI AMQP worker, Laravel/Symfony bridges, JWKS-via-discovery), Package Legitimacy Audit, Common Pitfalls (JSON escaping byte-mismatch, CachedKeySet's PSR-6/17/18 dependency chain, Symfony's lack of true auto-discovery), Validation Architecture |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Stack:** Rust workspace + SurrealDB backend; this phase is a pure external PHP client — MUST NOT depend on server crates (`axiam-*`). JWKS shape, HMAC protocol, and error taxonomy are *reimplemented* from `sdks/CONTRACT.md`/`crates/axiam-amqp/src/messages.rs`, never imported.
- **Security standards:** JWT = EdDSA (Ed25519), short-lived access tokens (15 min); TLS 1.3 minimum; webhook/AMQP signatures = HMAC-SHA256 — directly relevant to JWKS verification (Pattern 5) and the AMQP consumer (Pattern 4).
- **RBAC is additive-only (allow-wins, default-deny)** — the Laravel Gate / Symfony Voter (D-02) must call `checkAccess`/`can` on every check; no client-side deny-override or long-lived authz caching beyond the token's own TTL.
- **License:** Apache-2.0 repo-wide — `sdks/php/LICENSE` + `composer.json` `"license": "Apache-2.0"` already match; keep them.
- **No project-specific `.claude/skills/` or `rules/*.md`** found for this repository beyond CLAUDE.md itself.

## Summary

Phase 22 is the seventh and final SDK, and the first one that is a pure **share-nothing, per-request runtime** by default (classic PHP-FPM) with an *optional* long-running mode (Swoole/RoadRunner) for gRPC/AMQP. This reframes "concurrency" for §9's single-flight guard: it is not about OS threads but about **Guzzle's own async/promise model within one PHP process** — concurrent `Pool`/`Promise\Utils::all()` calls sharing one `AxiamClient`, or multiple coroutines on a long-running worker sharing one client instance. D-06 already resolves the mechanism (a single shared `PromiseInterface` stored on the session object, checked-and-stored synchronously before any `await`/`wait()`), which this research confirms is sound: PHP Fibers (and Guzzle's own promise resolution, which is itself cooperative — `Promise::wait()` synchronously drains the curl multi-handle) never preempt mid-statement, so the check-and-store step cannot race.

Three PHP-ecosystem-specific findings materially shape implementation beyond what CONTRACT.md's abstract description implies:

1. **firebase/php-jwt 6.11 natively supports OKP/Ed25519** (via `sodium_crypto_sign_verify_detached`, using PHP's bundled `ext-sodium` — compiled into PHP core by default since 7.2, not a separate PECL install) — unlike the C#/Java siblings, which each hit a real EdDSA gap in their mainstream JWT/crypto libraries. PHP does **not** need a BouncyCastle-style workaround. The one operational risk is that some minimal/stripped PHP builds (certain Alpine/distroless images) compile PHP `--without-sodium`; the SDK should defensively check `extension_loaded('sodium')` at JWKS-verification time and raise a clear `AxiamException` rather than a cryptic fatal error.
2. **firebase/php-jwt's `CachedKeySet` convenience class requires PSR-18 (`Psr\Http\Client\ClientInterface`) + PSR-17 (`RequestFactoryInterface`) + PSR-6 (`CacheItemPoolInterface`)** in its constructor — a dependency chain that conflicts with D-07's "Guzzle 7.x hard pinned, no PSR-18 swappability" framing (adding `CachedKeySet` would pull in `psr/http-client`, a PSR-17 factory implementation, and a PSR-6 cache backend just for JWKS caching). **Recommendation: do NOT use `CachedKeySet`.** Use the lower-level `JWK::parseKeySet()` static method (zero extra interface requirements) fetched through the SDK's own Guzzle client, wrapped in a small hand-rolled TTL cache — the same shape every sibling SDK (Rust/Go/Python/Java/C#) already implements for its own JWKS cache.
3. **The AMQP HMAC "canonical JSON" pitfall recurs in PHP with a PHP-specific twist.** Every prior SDK (Python 19, Java 20, C# 21) independently discovered that the canonical bytes are the server's exact **wire/insertion key order** (Rust struct-declaration order), not alphabetized — PHP's `json_decode($body, true)` into an associative array already preserves insertion order (PHP arrays are ordered maps), so the fix pattern (`unset($msg['hmac_signature']); json_encode($msg)`) is structurally correct with almost no code. **The PHP-specific trap is different:** PHP's `json_encode()` **escapes forward slashes and non-ASCII characters by default** (`/` → `\/`, non-ASCII → `\uXXXX`), while Rust's `serde_json::to_vec` does neither. Every payload containing a `/` (nothing here, since fields are UUIDs/strings/enums without slashes today, but a defensive requirement regardless) or non-ASCII tenant/action data will silently produce a **different byte sequence** than what the server signed unless `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` is passed to `json_encode()`. This is the single highest-risk, PHP-specific correctness bug in this phase.

**Primary recommendation:** Build `AxiamClient` around one `Session` object holding a Guzzle `CookieJar`, the shared single-flight refresh `Promise`, CSRF-token capture, and a `JwksVerifier` (firebase/php-jwt `JWK::parseKeySet` + hand-rolled TTL cache, sourced via `/.well-known/openid-configuration`). REST goes through a `HandlerStack` middleware stack (auth-header injection → CSRF injection → single-flight-refresh-on-401). gRPC is a separate `AuthzGrpcClient` class that is **never autoloaded/instantiated** unless `extension_loaded('grpc')` is true, sharing the same `Session`/refresh mechanism via a constructor-injected token accessor (mirrors Go/C#'s "no import cycle" pattern). AMQP ships a standalone `bin/axiam-amqp-worker` CLI script wrapping a `Consumer` class built on `php-amqplib` 3.7. Laravel and Symfony bridges are thin, framework-class-guarded classes inside the same package (`src/Laravel/`, `src/Symfony/`) that call into the core client's `checkAccess`/local-verify methods — never duplicating auth logic.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Login/MFA/refresh/logout (REST) | SDK Client (non-browser, PHP process) | API/Backend (AXIAM server) | SDK is a pure external Guzzle-based HTTP client; the server issues/verifies credentials and owns session state. |
| Single-flight refresh guard | SDK Client | — | Client-side concurrency control (§9) scoped to Guzzle's promise model within one PHP process (or one long-running worker); the server has no visibility into concurrent SDK callers. |
| Authz check (REST `checkAccess`/`can`/`batchCheck`) | SDK Client (REST transport, default) | API/Backend (`FND-04` `/api/v1/authz/check[/batch]`) | Always-available path; used directly on FPM and as the transparent fallback when gRPC is absent (D-03). |
| Authz check (gRPC `CheckAccess`/`BatchCheckAccess`) | SDK Client (gRPC transport, opt-in) | API/Backend (`axiam-api-grpc`) | Same authorization engine, different transport; gated behind `extension_loaded('grpc')` and a long-running runtime (Swoole/RoadRunner/CLI) — never assumed available. |
| AMQP event consumption + HMAC verify | SDK Client (CLI worker, long-running) | Message Broker (RabbitMQ) / API-Backend (server-side publisher) | Not a web-request path; a standalone worker process verifies signatures the server produced — verification logic is reimplemented, not imported, per the "no server-crate dependency" constraint. |
| Local JWKS / Ed25519 verification | SDK Client | API/Backend (`/oauth2/jwks` issuer, discovered via `/.well-known/openid-configuration`) | Performance optimization to avoid a server round trip per request; server remains the key-rotation source of truth; reactive 401-driven refresh is the fallback regardless. |
| Laravel middleware + Gate | SDK (framework integration layer, guarded by `class_exists('Illuminate\...')`) | — | Runs inside the consuming Laravel app's own process; local-verify + `checkAccess` calls, no new server endpoint. |
| Symfony EventSubscriber + Voter | SDK (framework integration layer, guarded by `class_exists('Symfony\...')`) | — | Runs inside the consuming Symfony app's own process; same local-verify + `checkAccess` pattern, manually registered (Symfony has no Laravel-style zero-config auto-discovery without a separate Flex recipe — see Pitfall 5). |
| Token/session redaction (`Sensitive`) | SDK Client (data model) | — | Class-level concern; must hold regardless of transport. |
| Packagist packaging / subtree-split / CI | SDK repo tooling (monorepo → mirror repo) | — | Build/release concern; Packagist requires a real top-level repository, forcing the subtree-split step that no other sibling SDK needed (crates.io/npm/PyPI/Maven/NuGet/Go-modules all support subdirectory or per-directory publishing natively). |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `guzzlehttp/guzzle` | **7.13.1** (7.x line pinned by PHP-01/D-07; latest confirmed on Packagist) | REST transport, `HandlerStack`, `CookieJar` | Contract-mandated (`sdks/CONTRACT.md` §4 PHP row: "Guzzle `CookieJar` with `cookies: true` handler option"). De facto standard PHP HTTP client; only mainstream library offering `HandlerStack` middleware + native async `Promise`/`Pool` needed for D-06's single-flight design. `[VERIFIED: packagist.org/packages/guzzlehttp/guzzle.json registry query, 2026-07-02 — 185 published versions, 1.04B total downloads, github.com/guzzle/guzzle official repo]` |
| `php-amqplib/php-amqplib` | **3.7.4** (3.7 line pinned by PHP-01; latest patch on Packagist) | AMQP 0.9.1 client, blocking consume loop for the CLI worker | PHP-01 pinned dep; the long-standing, most widely used pure-PHP AMQP client (no native extension required, unlike `ext-amqp`), matching `bunny`'s async-only ReactPHP model being unnecessary for a blocking CLI worker. `[VERIFIED: packagist.org/packages/php-amqplib/php-amqplib.json registry query, 2026-07-02 — 84 published versions, 132M total downloads, github.com/php-amqplib/php-amqplib official repo]` |
| `firebase/php-jwt` | **6.11.1** (6.11 line pinned by PHP-01; a newer 7.x major exists but PHP-01 explicitly pins 6.11) | `JWK::parseKeySet()` + `JWT::decode()`/`JWT::encode()`, native EdDSA/Ed25519 support | PHP-01 pinned dep. Confirmed native OKP/Ed25519 handling via `sodium_crypto_sign_verify_detached` (Pattern 5) — no crypto workaround needed, unlike the C#/Java siblings. `[VERIFIED: packagist.org/packages/firebase/php-jwt.json registry query, 2026-07-02 — v6.11.1 confirmed present; repository now redirects to github.com/googleapis/php-jwt (renamed, same Packagist name) — cosmetic, not a legitimacy concern]` |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `guzzlehttp/promises` | bundled transitive dep of `guzzlehttp/guzzle` 7.x (no separate version pin needed) | `PromiseInterface`, `Promise\Utils::all()`/`Coroutine`, the shared refresh promise (D-06) | Already a hard transitive dependency of Guzzle 7 — no new composer entry required, just `use GuzzleHttp\Promise\...`. |
| `guzzlehttp/psr7` | bundled transitive dep of `guzzlehttp/guzzle` 7.x (currently 2.9.x) | PSR-7 request/response/URI implementation (D-07's PSR-7 requirement) | Already transitive; the SDK's own PSR-7-typed method signatures (e.g. `NetworkError::fromResponse(ResponseInterface $response)`) rely on this without a new dependency. |
| `psr/log` | `^3.0` | PSR-3 `LoggerInterface` interface-only dependency (D-07) | Depend on the interface package only (`psr/log`), never a concrete logger — consumer wires their own PSR-3 implementation; SDK defaults to `Psr\Log\NullLogger` (ships in `psr/log` itself). |
| `grpc/grpc` | latest 1.x (**suggest-only**, never `require`) | `Grpc\BaseStub`, `Grpc\ChannelCredentials` — pure-PHP wrapper classes the generated stubs extend | D-03: PECL `ext-grpc` is optional; `grpc/grpc` composer package is safe to leave uninstalled since PHP's PSR-4 autoloading is lazy — the gRPC transport class is never loaded unless `extension_loaded('grpc')` gates its instantiation first (see Pitfall 4). |
| `phpunit/phpunit` | **9.6.9** (matches PHP 8.1 floor's supported PHPUnit line; PHPUnit 11/12 require PHP 8.2+) | Test framework, incl. the SC#2 concurrent-`MockHandler` single-flight test | PHPUnit 10+ dropped PHP 8.1 support; pin the 9.6.x LTS line to stay compatible with the D-07 PHP ≥8.1 floor. `[VERIFIED: packagist.org registry, 2026-07-02]` |
| `phpstan/phpstan` | **2.2.3** | Static analysis (discretion: tooling choice) | Standard modern PHP static-analysis gate; catches the `extension_loaded('grpc')`-guard-bypass class of bug at analysis time if a stub file for `Grpc\BaseStub` is provided. `[VERIFIED: packagist.org registry, 2026-07-02]` |
| `friendsofphp/php-cs-fixer` | **v3.95.9** | Code style enforcement (discretion: tooling choice) | De facto standard PHP formatter/linter, PSR-12-compatible ruleset. `[VERIFIED: packagist.org registry, 2026-07-02]` |
| `illuminate/support`, `illuminate/contracts` | dev-only, version-range matched to the Laravel LTS the example targets (e.g. `^11.0\|^12.0`) | Laravel `ServiceProvider`/`Middleware`/`Gate` base classes for the bridge + its tests | **`require-dev` only** — the core package's `composer.json` `require` block must stay framework-free (D-01); Laravel classes are referenced behind `class_exists('Illuminate\Support\ServiceProvider')` guards so a non-Laravel consumer never needs these installed. |
| `symfony/security-core`, `symfony/http-kernel`, `symfony/event-dispatcher-contracts` | dev-only, `^7.0\|^8.0` | Symfony `Voter`/`EventSubscriberInterface`/`RequestEvent` base classes for the bridge + its tests | Same rationale as above — `require-dev` only, guarded by `interface_exists`/`class_exists` checks at runtime. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `guzzlehttp/guzzle` (locked, D-07) | `symfony/http-client` (also supports PSR-18 + async) | CONTRACT.md's own per-language table names Guzzle `CookieJar`/`HandlerStack` explicitly (§4/§9); Symfony's client has a different (though also capable) async model (`ResponseInterface::getInfo()` chunked streaming vs Guzzle's `Promise`) that would require re-deriving the single-flight pattern from scratch with no CONTRACT.md precedent. |
| `php-amqplib/php-amqplib` (locked, D-04) | `bunny/bunny` (ReactPHP-based, non-blocking) | `bunny` targets an event-loop (ReactPHP) execution model; D-04's CLI-worker consumer is explicitly a **blocking** consume loop — `php-amqplib`'s synchronous `wait()` loop is the simpler, directly-matching fit with zero extra event-loop dependency. `ext-amqp` (PECL, wraps `librabbitmq` in C) is faster but requires a native extension most hosting/CI images don't ship by default — `php-amqplib`'s pure-PHP nature avoids that operational friction, matching PHP-01's explicit pin. |
| `firebase/php-jwt` `JWK::parseKeySet()` + hand-rolled TTL cache | `firebase/php-jwt`'s own `CachedKeySet` class | `CachedKeySet` requires PSR-18 `ClientInterface` + PSR-17 `RequestFactoryInterface` + PSR-6 `CacheItemPoolInterface` in its constructor — three additional interface dependencies (and at least one concrete PSR-6 cache implementation, e.g. `symfony/cache`) just to get TTL caching that every sibling SDK already hand-rolls in ~20 lines. Rejected to keep the dependency surface matching D-07's "no PSR-18/PSR-6 swappability needed" framing. |
| Hand-rolled TTL JWKS cache | `lcobucci/jwt` (alternative general-purpose JWT library) | `lcobucci/jwt` is a fine, well-maintained library, but PHP-01 explicitly pins `firebase/php-jwt` 6.11 as a locked dependency (CONTEXT.md D-08/PHP-01) — not re-litigated here. |
| `grpc/grpc` + native stubs (D-03, committed) | `spiral/roadrunner-grpc` or a pure-userland gRPC-over-HTTP/2 client | Both are far less mature/standard than the official `grpc/grpc` + PECL `ext-grpc` combination that every gRPC-PHP tutorial and the `grpc.io` official quickstart use; D-03 already locks "committed stubs + `extension_loaded('grpc')` guard" as the approach. |

**Installation:**
```bash
# Core (required)
composer require guzzlehttp/guzzle:^7.13 php-amqplib/php-amqplib:^3.7 firebase/php-jwt:^6.11 psr/log:^3.0

# Optional gRPC transport (never required — suggest only)
composer suggest ext-grpc "Enables the gRPC transport for checkAccess/batchCheck on long-running runtimes (Swoole/RoadRunner). Falls back to REST when absent."
# grpc/grpc itself may be listed in `suggest` too, or required unconditionally since it is
# pure PHP and safe to install without the PECL extension present (see Pattern 2 / Pitfall 4).

# Dev/test tooling
composer require --dev phpunit/phpunit:^9.6 phpstan/phpstan:^2.2 friendsofphp/php-cs-fixer:^3.95

# Framework bridge dev/test deps (require-dev only — never a runtime dependency of the core package)
composer require --dev "illuminate/support:^11.0 || ^12.0" "illuminate/contracts:^11.0 || ^12.0"
composer require --dev "symfony/security-core:^7.0 || ^8.0" "symfony/http-kernel:^7.0 || ^8.0"
```

**Version verification:** All Core-table versions were checked directly against the Packagist v2 registry API (`packagist.org/packages/<vendor>/<pkg>.json`) on 2026-07-02, reading the full `versions` map (not a cached "latest" field) to avoid the lexicographic-sort trap where tag-prefix inconsistency (`v3.8.1` vs bare `7.13.1`) can make an old major version appear "greater" under naive string sorting — confirmed the actual latest stable Guzzle 7.x tag is **`7.13.1`** (unprefixed), not the `v3.8.x` legacy major that also exists in the same tag list. `firebase/php-jwt` is deliberately pinned to the `6.11.x` line per PHP-01/D-08 even though `7.1.0` is the latest major — do not silently bump without a follow-up decision.

## Package Legitimacy Audit

| Package | Registry | Age (version-history depth) | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `guzzlehttp/guzzle` | Packagist | 185 published versions, spans 3.x→7.x majors over ~14 years | 1.046B total / 18.6M monthly | github.com/guzzle/guzzle (23.4k stars) | OK | Approved |
| `php-amqplib/php-amqplib` | Packagist | 84 published versions | 132.4M total / 2.3M monthly | github.com/php-amqplib/php-amqplib (4.6k stars) | OK | Approved |
| `firebase/php-jwt` | Packagist | 44 published versions | 479.3M total / 11.1M monthly | github.com/googleapis/php-jwt (repo renamed from firebase/php-jwt, same Packagist package identity; 9.8k stars) | OK | Approved |
| `psr/log` | Packagist | Official PHP-FIG interface package, extremely long-lived | Not independently re-queried — PHP-FIG interface packages are near-universal | github.com/php-fig/log | OK | Approved |
| `grpc/grpc` | Packagist | Official `grpc/grpc` monorepo PHP artifact | Not independently re-queried — official first-party gRPC project package | github.com/grpc/grpc (`src/php`) | OK | Approved (suggest-only, see Pattern 2) |
| `phpunit/phpunit` | Packagist | Long-established de facto standard PHP test framework | Not independently re-queried — canonical PHP testing tool | github.com/sebastianbergmann/phpunit | OK | Approved |
| `phpstan/phpstan` | Packagist | Widely-adopted static analysis tool, multi-year history | Not independently re-queried | github.com/phpstan/phpstan | OK | Approved |
| `friendsofphp/php-cs-fixer` | Packagist | Long-established PHP formatter | Not independently re-queried | github.com/PHP-CS-Fixer/PHP-CS-Fixer | OK | Approved |

**Packages removed due to `[SLOP]` verdict:** none.
**Packages flagged as suspicious `[SUS]`:** none. All packages above are official-project, high-download, long-history artifacts independently confirmed via direct Packagist registry queries (`packagist.org/packages/<pkg>.json`) cross-referenced against each project's GitHub org. The `gsd-tools package-legitimacy check` seam in this environment only accepts `--ecosystem npm|pypi|crates` (no `packagist` ecosystem support) — the checks above were performed manually via direct Packagist API queries, an authoritative registry source.

*Package **names** for `guzzlehttp/guzzle`, `php-amqplib/php-amqplib`, and `firebase/php-jwt` are locked, user-confirmed pinned dependencies from `.planning/REQUIREMENTS.md` PHP-01 / `22-CONTEXT.md`, not researcher-discovered — registry-verified above but not subject to the WebSearch-provenance `[ASSUMED]` downgrade rule (they were not discovered by this research session; they were supplied as a locked constraint and then verified).*

## Architecture Patterns

### System Architecture Diagram

```
                    Consuming PHP application (FPM request OR Swoole/RoadRunner worker)
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │                          new AxiamClient(baseUrl, tenant: 'acme', ...)            │
   │                                                                                     │
   │  ┌───────────────────────┐   ┌─────────────────────┐   ┌───────────────────────┐  │
   │  │      REST path         │   │   gRPC path (opt-in) │   │   AMQP path (CLI only) │  │
   │  │ Guzzle Client +        │   │ AuthzGrpcClient       │   │  php-amqplib Consumer  │  │
   │  │ HandlerStack + Cookie  │   │ extends Grpc\BaseStub │   │  (bin/axiam-amqp-      │  │
   │  │ Jar (cookies:true)     │   │ guarded by            │   │   worker.php)          │  │
   │  │                        │   │ extension_loaded(     │   │                        │  │
   │  │                        │   │  'grpc')              │   │                        │  │
   │  └───────────┬────────────┘   └──────────┬────────────┘   └───────────┬────────────┘  │
   │              │  every request: inject Authorization + X-Tenant-ID     │                │
   │              │  (+X-CSRF-Token on state-changing REST calls)          │                │
   │              ▼                            ▼                          │ HMAC verify     │
   │  ┌──────────────────────────────────────────────────────────┐        │ BEFORE handler  │
   │  │      Session (shared refresh Promise, single-flight)      │        ▼                │
   │  │  on 401 / REST — first caller stores $this->refreshPromise │  ┌──────────────────┐  │
   │  │  synchronously; concurrent Guzzle async callers await the │  │ ack / nack(requeue│  │
   │  │  SAME promise (D-06) — exactly 1 refresh call             │  │  = false on fail)  │  │
   │  └───────────────────────┬────────────────────────────────────┘  └──────────────────┘  │
   │                          │ POST /api/v1/auth/refresh                                     │
   │                          ▼                                                               │
   │  ┌────────────────────────────────────┐                                                 │
   │  │   JwksVerifier (firebase/php-jwt)   │                                                 │
   │  │   JWK::parseKeySet() + hand-rolled  │                                                 │
   │  │   TTL cache; alg pinned to EdDSA    │                                                 │
   │  └───────────────────┬────────────────┘                                                 │
   └──────────────────────┼──────────────────────────────────────────────────────────────────┘
                          │ GET jwks_uri (resolved via OIDC discovery, cached)
                          │ POST /api/v1/auth/{login,mfa/verify,refresh,logout},
                          │ POST /api/v1/authz/check[/batch]
                          ▼
        ┌────────────────────────────────────────────┐        ┌───────────────────────────┐
        │        AXIAM Server (frozen v1.0 API)       │        │      RabbitMQ Broker       │
        │  GET /.well-known/openid-configuration       │◄───────┤  axiam.audit.events, etc.  │
        │  GET /oauth2/jwks · REST (Actix-Web) ·       │        │  HMAC-SHA256 signed by     │
        │  gRPC (Tonic) · additive-only RBAC engine    │        │  server before publish      │
        └──────────────────────────────────────────────┘        └───────────────────────────┘

  ── Laravel/Symfony bridges (same package, guarded by class_exists) ───────────────────────
  Incoming HTTP request
    → Laravel Middleware / Symfony EventSubscriber (reads Authorization/cookie, calls
      JwksVerifier locally, falls back to Session's reactive refresh path)
    → success: populate $request->user() (Laravel) / security token (Symfony) with
      user_id/tenant_id/roles
    → downstream: Laravel Gate::before / Symfony Voter → $client->can($resource, $action)
      → 403 (AuthzError) on deny
    → failure: 401 (AuthError), standardized JSON error body
```

Trace the primary use case (SC#1/SC#2): `$client->login($email, $password)` → Guzzle `HandlerStack`
POSTs `/api/v1/auth/login` → server sets `axiam_access`/`axiam_refresh`/`axiam_csrf` cookies via the
Guzzle `CookieJar` → typed `LoginResult` returned. Later, `$client->checkAccess(...)` fires with an
expired access token → server returns 401 → the `HandlerStack`'s refresh middleware calls into
`Session::refreshIfNeeded()` → under N concurrent Guzzle async promises this resolves to exactly one
shared `Promise` → `/api/v1/auth/refresh` is called once → all N original requests retry with the new
token. Independently, `JwksVerifier` performs local EdDSA verification for the Laravel/Symfony
middleware's fast path without touching the refresh guard (resource-server side, not client side).

### Recommended Project Structure

```
sdks/php/
├── composer.json                 # axiam/axiam-sdk, PSR-4 Axiam\Sdk\, php>=8.1 (existing scaffold)
├── README.md                     # states "This SDK conforms to CONTRACT.md §1-§10."
├── LICENSE                       # Apache-2.0 (existing scaffold)
├── src/
│   ├── AxiamClient.php            # public entry point; tenant required ctor param (D-13)
│   ├── Session.php                # cookie jar + CSRF capture + shared refresh Promise (D-06)
│   ├── Auth/
│   │   ├── LoginResult.php        # readonly class (D-09)
│   │   ├── RefreshGuard.php       # shared-Promise single-flight helper used by Session
│   │   └── JwksVerifier.php       # firebase/php-jwt JWK::parseKeySet + TTL cache (D-08)
│   ├── Rest/
│   │   ├── AuthMiddleware.php     # HandlerStack middleware: inject auth+tenant+CSRF headers
│   │   ├── RefreshMiddleware.php  # HandlerStack middleware: on 401, single-flight refresh+retry
│   │   └── AuthzRestClient.php    # checkAccess()/can()/batchCheck() over REST (FND-04)
│   ├── Grpc/
│   │   ├── AuthzGrpcClient.php    # extends Grpc\BaseStub; ONLY referenced behind
│   │   │                           # extension_loaded('grpc') guards (Pitfall 4)
│   │   └── Gen/                    # COMMITTED generated stubs (D-03) — buf generate output
│   ├── Amqp/
│   │   ├── Consumer.php           # php-amqplib blocking consume loop, verify-before-handler (D-04)
│   │   └── Hmac.php                # verifyPayload() — JSON_UNESCAPED_SLASHES|UNICODE (Pitfall 1)
│   ├── Core/
│   │   ├── Sensitive.php          # __toString() -> "[SENSITIVE]", JsonSerializable (D-11)
│   │   ├── AxiamException.php     # base exception
│   │   ├── AuthError.php / AuthzError.php / NetworkError.php  # D-10 taxonomy
│   │   └── ErrorMapper.php        # one central HTTP/gRPC status -> error mapper
│   ├── Laravel/                    # guarded by class_exists('Illuminate\...') at call sites
│   │   ├── AxiamServiceProvider.php
│   │   ├── AxiamMiddleware.php
│   │   └── AxiamGate.php           # registers Gate::before / a named ability
│   └── Symfony/                    # guarded by class_exists('Symfony\...') at call sites
│       ├── AxiamBundle.php
│       ├── AxiamAuthSubscriber.php # kernel.request EventSubscriber
│       └── AxiamVoter.php
├── bin/
│   └── axiam-amqp-worker.php      # standalone CLI entry point wrapping Amqp\Consumer (D-04)
├── examples/
│   ├── login_mfa.php
│   ├── rest_authz.php
│   ├── grpc_checkaccess.php        # documents Swoole/RoadRunner requirement prominently (SC#3)
│   ├── amqp_worker_example.php
│   ├── laravel_app/                # runnable example: middleware + Gate -> 403 (SC#4)
│   └── symfony_app/                # runnable example: subscriber + Voter -> 403 (SC#4)
├── tests/
│   ├── SingleFlightRefreshTest.php # SC#2, MockHandler-counted
│   ├── TlsBypassGrepGateTest.php   # or a standalone CI grep step (SC#4 belt-and-suspenders)
│   ├── SensitiveRedactionTest.php  # CR-04 carry-forward, non-vacuous control case
│   ├── HmacVerifyTest.php          # fixture-based, real Rust-signed vectors, escaping regression
│   ├── JwksVerifierTest.php
│   ├── LaravelMiddlewareTest.php
│   └── SymfonyAuthSubscriberTest.php
└── extra/extra.laravel.providers    # composer.json `extra` block, not a real path — see Pattern 3
```

### Pattern 1: Guzzle `HandlerStack` Single-Flight Refresh Middleware (D-06, §9, SC#2)

**What:** Two `HandlerStack` middlewares, pushed in order: (1) an auth/tenant/CSRF header
injector, (2) a 401-response interceptor that triggers the shared single-flight refresh and
retries the original request. The single-flight guard itself lives on the `Session` object (not
inside the middleware closure) so REST and, when active, gRPC share the exact same in-flight
refresh (D-06's "§9 single-flight guard is one shared promise across REST and gRPC").

**When to use:** Every outgoing REST call; the retry-after-refresh middleware specifically on 401
responses when a refresh token/cookie is present.

**Example:**
```php
<?php
// Source: Guzzle official docs (docs.guzzlephp.org/en/stable/handlers-and-middleware.html) —
// handler signature `function (RequestInterface $request, array $options): PromiseInterface`,
// middleware-as-higher-order-function shape — applied to CONTRACT.md §9 (locked PHP mechanism:
// "Fiber-safe Mutex from revolt/event-loop or equivalent" -> D-06 resolves this to a shared
// Promise, no extra dependency) + D-13 (tenant required ctor param).

namespace Axiam\Sdk;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;

final class Session
{
    private ?PromiseInterface $refreshPromise = null;

    public function __construct(
        private readonly string $baseUrl,
        private readonly string $tenant,          // D-13: no nullable default anywhere in this class
        private \GuzzleHttp\Client $http,
        private ?string $csrfToken = null,
    ) {}

    /**
     * Returns the SAME PromiseInterface to every concurrent caller until it
     * resolves. The check-and-store below executes synchronously (PHP has no
     * preemption point between the null-check and the assignment — Fibers are
     * cooperative, and nothing here calls ->wait() or yields), so it is safe
     * without a mutex even under N concurrent async callers sharing one
     * Session instance (D-06's "fiber-safe by construction" claim).
     */
    public function refreshIfNeeded(): PromiseInterface
    {
        if ($this->refreshPromise !== null) {
            return $this->refreshPromise;
        }

        $this->refreshPromise = $this->http
            ->postAsync('/api/v1/auth/refresh', [
                'json' => ['tenant_id' => $this->tenantId, 'org_id' => $this->orgId],
            ])
            ->then(
                function (\Psr\Http\Message\ResponseInterface $response) {
                    $this->refreshPromise = null;   // clear on success so the NEXT 401 starts fresh
                    $this->captureCsrfToken($response);
                    return $response;
                },
                function (\Throwable $reason) {
                    $this->refreshPromise = null;   // clear on failure too — §9.3: no retry loop
                    throw AuthError::fromRefreshFailure($reason);
                }
            );

        return $this->refreshPromise;
    }

    private function captureCsrfToken(\Psr\Http\Message\ResponseInterface $response): void
    {
        // §3 non-browser CSRF: capture X-CSRF-Token response header, echo on mutating requests.
        if ($token = $response->getHeaderLine('X-CSRF-Token')) {
            $this->csrfToken = $token;
        }
    }
}
```

**The retry-on-401 middleware (registered on the `HandlerStack`):**
```php
<?php
// Source: docs.guzzlephp.org/en/stable/handlers-and-middleware.html middleware pattern +
// github.com/guzzle/guzzle/issues/1740 (community precedent for refresh-and-retry middleware).
namespace Axiam\Sdk\Rest;

use Psr\Http\Message\RequestInterface;
use Axiam\Sdk\Session;

final class RefreshMiddleware
{
    public function __construct(private readonly Session $session) {}

    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            return $handler($request, $options)->then(
                function (\Psr\Http\Message\ResponseInterface $response) use ($request, $options, $handler) {
                    if ($response->getStatusCode() !== 401) {
                        return $response;
                    }
                    // Single-flight: ALL concurrent 401-triggering requests call
                    // refreshIfNeeded() and get back the SAME Promise (D-06).
                    return $this->session->refreshIfNeeded()->then(
                        fn () => $handler($request, $options)   // retry exactly once, no loop
                    );
                }
            );
        };
    }
}

// Wiring (in AxiamClient's constructor):
$stack = \GuzzleHttp\HandlerStack::create();
$stack->push(new \Axiam\Sdk\Rest\AuthMiddleware($session), 'axiam_auth');
$stack->push(new \Axiam\Sdk\Rest\RefreshMiddleware($session), 'axiam_refresh');
$httpClient = new \GuzzleHttp\Client([
    'base_uri' => $baseUrl,
    'handler'  => $stack,
    'cookies'  => $session->cookieJar(),   // §4: GuzzleHttp\Cookie\CookieJar, cookies:true handler option
    'verify'   => true,                     // §6/D-12: NEVER false; only `customCa` escape hatch
]);
```

**SC#2 PHPUnit test — N concurrent Guzzle async promises, exactly 1 refresh call, `MockHandler`-counted:**
```php
<?php
// Source: docs.guzzlephp.org/en/stable/testing.html (MockHandler + Middleware::history) +
// CONTRACT.md §9 "Test requirement": fire N (>=5) concurrent requests against an expired
// token, assert exactly 1 refresh call.
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class SingleFlightRefreshTest extends TestCase
{
    public function testExactlyOneRefreshUnderFiveConcurrentRequests(): void
    {
        $container = [];
        $mock = new MockHandler([
            new Response(401), new Response(401), new Response(401),
            new Response(401), new Response(401),          // 5 initial calls, all expired
            new Response(200, ['Set-Cookie' => 'axiam_access=new-token'], '{}'), // the ONE refresh
            new Response(200), new Response(200), new Response(200),
            new Response(200), new Response(200),            // 5 retries, now succeed
        ]);
        $history = Middleware::history($container);
        $stack = HandlerStack::create($mock);
        $stack->push($history);

        $session = new Axiam\Sdk\Session('https://api.test', 'acme', new Client(['handler' => $stack]));
        $stack->push(new Axiam\Sdk\Rest\RefreshMiddleware($session), 'axiam_refresh');
        $client = new Client(['handler' => $stack]);

        $promises = [];
        for ($i = 0; $i < 5; $i++) {
            $promises[] = $client->getAsync('/api/v1/authz/check');
        }
        \GuzzleHttp\Promise\Utils::all($promises)->wait();

        $refreshCalls = array_filter(
            $container,
            fn (array $t) => $t['request']->getUri()->getPath() === '/api/v1/auth/refresh'
        );
        self::assertCount(1, $refreshCalls, 'expected exactly one refresh call across 5 concurrent requests');
    }
}
```
**Critical test-design note:** `Utils::all($promises)->wait()` only proves single-flight if the
underlying handler genuinely interleaves resolution before any one promise fully settles — a
`MockHandler` resolves synchronously by default (no real I/O latency), so the queued-response
ordering above (all five 401s before the one refresh 200) is what actually forces every one of the
five requests to observe "no refresh yet" before the guard resolves. If `MockHandler` responses were
queued 401→refresh→200→401→refresh→200..., the test would trivially pass without exercising
single-flight at all — the queued-401-first shape is load-bearing for a meaningful assertion.

### Pattern 2: gRPC `extension_loaded('grpc')` Guard + Lazy-Autoload Interaction (D-03)

**What:** The gRPC transport class (`AuthzGrpcClient extends \Grpc\BaseStub`) must never be
autoloaded unless `extension_loaded('grpc')` is true — PHP resolves an `extends` clause's parent
class at the moment the subclass's defining file is *executed* (which PSR-4 autoloading triggers
lazily, only when the class name is first referenced), so gating **instantiation** behind the
extension check is sufficient and correct, as long as no other code path unconditionally
`use`s/instantiates/type-hints the class at the top of an eagerly-loaded file.

**When to use:** Every place `checkAccess`/`can`/`batchCheck` decide REST vs. gRPC transport.

**Example:**
```php
<?php
// Source: sdks/CONTRACT.md §1 (checkAccess/can/batchCheck) + D-03 (transparent REST fallback,
// grpc PECL never hard-required) + PHP's own lazy-class-resolution semantics (a `class X extends
// Y` declaration only triggers Y's autoload when the file defining X is included/executed, which
// PSR-4 autoloading defers until X is first referenced by name).
namespace Axiam\Sdk;

final class AuthzDispatcher
{
    private ?\Axiam\Sdk\Grpc\AuthzGrpcClient $grpcClient = null;

    public function __construct(
        private readonly \Axiam\Sdk\Rest\AuthzRestClient $restClient,
        private readonly bool $restOnly = false,       // explicit REST-only config opt-out
    ) {}

    public function checkAccess(string $action, string $resourceId, ?string $scope = null): bool
    {
        if (!$this->restOnly && extension_loaded('grpc')) {
            // Class is referenced ONLY inside this branch — on a runtime without the
            // grpc PECL extension, this line never executes, so AuthzGrpcClient.php
            // (which `extends \Grpc\BaseStub`) is never autoloaded, and no fatal
            // "Class Grpc\BaseStub not found" error occurs even if grpc/grpc's
            // composer package (or the extension) is entirely absent.
            $this->grpcClient ??= new \Axiam\Sdk\Grpc\AuthzGrpcClient(/* ... */);
            return $this->grpcClient->checkAccess($action, $resourceId, $scope);
        }

        // D-03: authz ALWAYS works — transparent fallback, not a degraded mode.
        return $this->restClient->checkAccess($action, $resourceId, $scope);
    }
}
```

**`composer.json` fragment:**
```json
{
    "require": {
        "php": ">=8.1",
        "guzzlehttp/guzzle": "^7.13",
        "php-amqplib/php-amqplib": "^3.7",
        "firebase/php-jwt": "^6.11",
        "psr/log": "^3.0"
    },
    "suggest": {
        "ext-grpc": "Enables the gRPC transport for checkAccess/batchCheck on long-running runtimes (Swoole/RoadRunner). REST-only fallback is used automatically when absent.",
        "grpc/grpc": "Required alongside ext-grpc for gRPC support; the SDK never fatals without it as long as extension_loaded('grpc') gates every gRPC class reference."
    }
}
```

### Pattern 3: Laravel ServiceProvider (true auto-discovery) + Symfony Bundle (manual registration)

**What:** Laravel's package auto-discovery (`extra.laravel.providers` in `composer.json`) means a
Laravel consumer gets the `AxiamServiceProvider` registered with **zero** manual wiring beyond
`composer require`. Symfony has **no equivalent zero-config mechanism** for a plain
`composer require` — Symfony Flex's "recipes" auto-configure bundles, but that requires a separate
PR to the `symfony/recipes-contrib` repository (out of scope for this phase); without a published
Flex recipe, a Symfony consumer must manually add the bundle to `config/bundles.php`. **Do not let
a plan or README imply Symfony gets the same "auto-discovered" experience Laravel does** — D-01's
"first-class, auto-discovered bridges" phrasing is accurate for Laravel and aspirational-but-manual
for Symfony; document both honestly.

**Laravel `composer.json` fragment (true zero-config discovery):**
```json
{
    "extra": {
        "laravel": {
            "providers": ["Axiam\\Sdk\\Laravel\\AxiamServiceProvider"]
        }
    }
}
```

**Laravel middleware + Gate (auth + authz, SC#4's Laravel half):**
```php
<?php
// Source: laravel.com/docs middleware + Gate authoring conventions +
// sdks/CONTRACT.md §10 (locked PHP row: "Middleware (Laravel) / EventSubscriber (Symfony)") + D-02.
namespace Axiam\Sdk\Laravel;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

final class AxiamMiddleware
{
    public function __construct(private readonly \Axiam\Sdk\AxiamClient $client) {}

    public function handle(Request $request, Closure $next)
    {
        $token = $request->bearerToken() ?? $request->cookie('axiam_access');
        if ($token === null) {
            return response()->json(['error' => 'AuthError', 'message' => 'missing credentials'], 401);
        }

        $claims = $this->client->verifyLocallyOrFallback($token, $request->header('X-Tenant-ID'));
        if ($claims === null) {
            return response()->json(['error' => 'AuthError', 'message' => 'invalid or expired token'], 401);
        }

        $request->attributes->set('axiam_user', [
            'user_id'   => $claims['sub'],
            'tenant_id' => $claims['tenant_id'],
            'roles'     => $claims['roles'] ?? [],
        ]);
        return $next($request);
    }
}

final class AxiamServiceProvider extends \Illuminate\Support\ServiceProvider
{
    public function boot(): void
    {
        // D-02: Gate::before + a named ability call the real checkAccess() — no client-side
        // deny-override, no caching beyond the token's own remaining TTL (project constraint).
        Gate::define('axiam', function ($user, string $resource, string $action) {
            return app(\Axiam\Sdk\AxiamClient::class)->can($resource, $action);
        });
    }
}

// Route usage (SC#4 runnable example):
// Route::get('/documents/{id}', Handler::class)
//     ->middleware(['axiam.auth', 'can:axiam,documents,read']);
```

**Symfony EventSubscriber + Voter (auth + authz, SC#4's Symfony half — manually registered):**
```php
<?php
// Source: symfony.com/doc event-dispatcher + security/voters conventions + CONTRACT.md §10
// (locked PHP row: "EventSubscriber (Symfony)") + D-02.
namespace Axiam\Sdk\Symfony;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class AxiamAuthSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly \Axiam\Sdk\AxiamClient $client) {}

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => 'onKernelRequest'];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $token = $request->cookies->get('axiam_access')
            ?? str_replace('Bearer ', '', (string) $request->headers->get('Authorization'));
        if ($token === '') {
            $event->setResponse(new \Symfony\Component\HttpFoundation\JsonResponse(
                ['error' => 'AuthError', 'message' => 'missing credentials'], 401
            ));
            return;
        }
        $claims = $this->client->verifyLocallyOrFallback($token, $request->headers->get('X-Tenant-ID'));
        if ($claims === null) {
            $event->setResponse(new \Symfony\Component\HttpFoundation\JsonResponse(
                ['error' => 'AuthError', 'message' => 'invalid or expired token'], 401
            ));
            return;
        }
        $request->attributes->set('axiam_user', $claims);
    }
}

final class AxiamVoter extends \Symfony\Component\Security\Core\Authorization\Voter\Voter
{
    public function __construct(private readonly \Axiam\Sdk\AxiamClient $client) {}

    protected function supports(string $attribute, mixed $subject): bool
    {
        return str_contains($attribute, ':');   // e.g. "documents:read"
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, \Symfony\Component\Security\Core\Authorization\Voter\Vote|null $vote = null): bool
    {
        [$resource, $action] = explode(':', $attribute, 2);
        return $this->client->can($resource, $action);   // server's additive-only RBAC is authoritative
    }
}

// config/bundles.php — MANUAL registration required (no Flex recipe published in this phase):
// return [
//     Axiam\Sdk\Symfony\AxiamBundle::class => ['all' => true],
// ];
// config/services.yaml:
// services:
//   Axiam\Sdk\Symfony\AxiamAuthSubscriber: { tags: ['kernel.event_subscriber'] }
//   Axiam\Sdk\Symfony\AxiamVoter: { tags: ['security.voter'] }
```

### Pattern 4: php-amqplib CLI Worker, Verify-Before-Handler, `JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE` (D-04, §8)

**What:** A standalone CLI script (`bin/axiam-amqp-worker.php`) constructs an
`AMQPStreamConnection`, declares a channel, and runs `Consumer::consume()` — a blocking loop using
`$channel->basic_consume(...)` + `$channel->wait()`. Every delivered message is HMAC-verified
BEFORE the caller-supplied handler runs. **The signing key is a caller-supplied constructor
parameter (per-tenant AMQP signing secret), not fetched via any documented REST endpoint** — every
sibling SDK (Go/Python/Java/C#) takes it the same way; there is no `GET
/api/v1/.../amqp-signing-key`-style endpoint in `sdks/openapi.json` (confirmed by search — the
management/provisioning of this secret is out-of-band/operational, matching every prior phase).

**Example:**
```php
<?php
// Source: HMAC protocol confirmed from crates/axiam-amqp/src/messages.rs (sign_payload/
// verify_payload: hex(HMAC-SHA256) over the message body with hmac_signature omitted) +
// sdks/CONTRACT.md §8 + php-amqplib official docs/demo scripts
// (github.com/php-amqplib/php-amqplib/blob/master/demo/basic_nack.php) for basic_consume/
// ack/nack(requeue) signatures, confirmed 2026-07-02.
namespace Axiam\Sdk\Amqp;

final class Hmac
{
    /**
     * Byte-for-byte port of crates/axiam-amqp/src/messages.rs::verify_payload.
     * Never throws — malformed input verifies as false (strict-mode default, §8.3).
     *
     * CRITICAL: json_decode($body, true) into a PHP associative array preserves the
     * EXACT insertion/wire order the message arrived in (PHP arrays are ordered maps) —
     * this matches the server's serde_json struct-field-declaration order WITHOUT any
     * extra sorting logic (same fix class as the Python/Java/C# siblings' discovery that
     * the canonical bytes are wire order, not alphabetical).
     *
     * THE PHP-SPECIFIC TRAP: json_encode() escapes forward slashes ("/" -> "\/") and
     * non-ASCII characters (-> "\uXXXX") BY DEFAULT. serde_json::to_vec does neither.
     * Omitting JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE produces a byte sequence
     * that will NEVER match the server's signature for any payload containing a slash
     * or non-ASCII text (see Pitfall 1).
     */
    public static function verify(string $signingKey, string $body): bool
    {
        $msg = json_decode($body, true);
        if (!is_array($msg)) {
            return false;                       // malformed JSON -> reject
        }
        if (!isset($msg['hmac_signature']) || !is_string($msg['hmac_signature'])) {
            return false;                       // §8.3 strict mode: missing signature = reject
        }
        $sigHex = $msg['hmac_signature'];
        unset($msg['hmac_signature']);           // remaining array keeps its original insertion order

        $canonical = json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($canonical === false) {
            return false;
        }

        $expected = @hex2bin($sigHex);
        if ($expected === false) {
            return false;                        // non-hex signature -> reject, never throw
        }
        $computed = hash_hmac('sha256', $canonical, $signingKey, true);

        return hash_equals($expected, $computed); // hash_equals() is PHP's constant-time compare
    }
}

final class Consumer
{
    private ?\PhpAmqpLib\Connection\AMQPStreamConnection $connection = null;
    private ?\PhpAmqpLib\Channel\AMQPChannel $channel = null;

    public function __construct(
        private readonly string $signingKey,           // per-tenant AMQP signing secret, caller-supplied
        private readonly \Psr\Log\LoggerInterface $logger = new \Psr\Log\NullLogger(),
    ) {}

    /** @param callable(array):void $handler Throws AmqpDropMessage for poison messages. */
    public function consume(string $host, int $port, string $user, string $pass, string $vhost, string $queue, callable $handler): void
    {
        $this->connection = new \PhpAmqpLib\Connection\AMQPStreamConnection($host, $port, $user, $pass, $vhost);
        $this->channel = $this->connection->channel();
        $this->channel->basic_qos(0, 10, false);

        $this->channel->basic_consume($queue, '', false, false, false, false,
            function (\PhpAmqpLib\Message\AMQPMessage $msg) use ($handler) {
                if (!Hmac::verify($this->signingKey, $msg->getBody())) {
                    $this->logger->warning('axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue');
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, false); // requeue=false
                    return;
                }
                $event = json_decode($msg->getBody(), true);
                unset($event['hmac_signature']);
                try {
                    $handler($event);
                    $msg->getChannel()->basic_ack($msg->getDeliveryTag());
                } catch (AmqpDropMessage) {
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, false); // poison -> no requeue
                } catch (\Throwable) {
                    $msg->getChannel()->basic_nack($msg->getDeliveryTag(), false, true);  // transient -> requeue
                }
            }
        );

        while ($this->channel->is_consuming()) {
            $this->channel->wait();   // blocking loop — this is the "not a web-request path" (D-04)
        }
    }
}

final class AmqpDropMessage extends \RuntimeException {}
```

**`bin/axiam-amqp-worker.php` (the runnable example, SC#4):**
```php
#!/usr/bin/env php
<?php
require __DIR__ . '/../vendor/autoload.php';

$consumer = new \Axiam\Sdk\Amqp\Consumer(signingKey: getenv('AXIAM_AMQP_SIGNING_KEY'));
$consumer->consume(
    host: getenv('AMQP_HOST'), port: 5672, user: getenv('AMQP_USER'),
    pass: getenv('AMQP_PASS'), vhost: '/', queue: 'axiam.audit.events',
    handler: function (array $event): void {
        // application-specific handling of the verified event
    }
);
```

### Pattern 5: JWKS via OIDC Discovery + `JWK::parseKeySet()` + Hand-Rolled TTL Cache (D-08)

**What:** `GET /.well-known/openid-configuration` returns an `OidcDiscoveryDocument` whose
`jwks_uri` field resolves to `GET /oauth2/jwks` (confirmed directly from `sdks/openapi.json` —
both routes exist and are wired to real handlers, not placeholders). The `JwksDocument` schema's
`Jwk` shape requires `kty`/`crv`/`x`/`kid`/`use`/`alg`, matching RFC 7517 OKP/Ed25519 exactly.
`firebase\JWT\JWK::parseKeySet($jwksArray)` returns `array<string,Key>` keyed by `kid`, ready to
pass straight into `JWT::decode()`.

**Example:**
```php
<?php
// Source: sdks/openapi.json (paths "/.well-known/openid-configuration" -> OidcDiscoveryDocument
// with required "jwks_uri" field; "/oauth2/jwks" -> JwksDocument{keys: Jwk[]}) confirmed 2026-07-02
// + firebase/php-jwt official JWK::parseKeySet/JWT::decode usage
// (github.com/firebase/php-jwt, packagist.org/packages/firebase/php-jwt).
namespace Axiam\Sdk\Auth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

final class JwksVerifier
{
    private ?array $keysByKid = null;    // array<string, Key>
    private int $fetchedAt = 0;
    private readonly int $cacheTtlSeconds;   // discretion: sane default e.g. 300

    public function __construct(
        private readonly \GuzzleHttp\Client $http,
        private readonly string $baseUrl,
        int $cacheTtlSeconds = 300,
    ) {
        $this->cacheTtlSeconds = $cacheTtlSeconds;
    }

    /** @return array<string,mixed>|null verified claims, or null on any failure (never throws on attacker input). */
    public function verify(string $jwt, string $expectedTenantId): ?array
    {
        if (!extension_loaded('sodium')) {
            // ext-sodium is compiled into PHP core by default since 7.2, but a small subset
            // of minimal/distroless builds compile --without-sodium. Fail with a clear,
            // actionable error rather than a cryptic "Call to undefined function" fatal
            // inside firebase/php-jwt's EdDSA branch.
            throw new \Axiam\Sdk\Core\AxiamException(
                'ext-sodium is required for EdDSA JWT verification but is not loaded'
            );
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        if (!is_array($header) || ($header['alg'] ?? null) !== 'EdDSA') {
            return null;   // alg-pin BEFORE key lookup — never trust the token to select its own verifier
        }
        $kid = $header['kid'] ?? null;

        $this->ensureFresh($kid);
        if ($kid === null || !isset($this->keysByKid[$kid])) {
            return null;   // unknown kid even after a forced refetch
        }

        try {
            $decoded = JWT::decode($jwt, $this->keysByKid);   // firebase/php-jwt resolves by kid internally
        } catch (\Throwable) {
            return null;
        }
        $claims = (array) $decoded;

        // JWKS is organization-wide, not tenant-scoped — signature validity alone does NOT
        // imply tenant authorization (same finding independently made by every sibling SDK).
        if (($claims['tenant_id'] ?? null) !== $expectedTenantId) {
            return null;
        }
        return $claims;
    }

    private function ensureFresh(?string$unknownKid): void
    {
        $expired = (time() - $this->fetchedAt) > $this->cacheTtlSeconds;
        $unknown = $unknownKid !== null && !isset($this->keysByKid[$unknownKid]);
        if ($this->keysByKid !== null && !$expired && !$unknown) {
            return;
        }

        // Resolve jwks_uri fresh via OIDC discovery every refetch (cheap, avoids a second
        // hardcoded path constant drifting from the server's actual configuration).
        $discovery = json_decode(
            (string) $this->http->get('/.well-known/openid-configuration')->getBody(), true
        );
        $jwksUri = $discovery['jwks_uri'] ?? ($this->baseUrl . '/oauth2/jwks');

        $jwksJson = json_decode((string) $this->http->get($jwksUri)->getBody(), true);
        $this->keysByKid = JWK::parseKeySet($jwksJson);   // firebase/php-jwt: array<kid, Key>
        $this->fetchedAt = time();
    }
}
```
**Why not `CachedKeySet`:** firebase/php-jwt's own `CachedKeySet` convenience class requires a
PSR-18 `Psr\Http\Client\ClientInterface`, a PSR-17 `RequestFactoryInterface`, and a PSR-6
`CacheItemPoolInterface` in its constructor — adding all three just to get TTL caching duplicates
what the ~15-line `ensureFresh()` above already does, and would pull in dependencies D-07 does not
otherwise need (Guzzle 7's `Client` *does* implement PSR-18, so that part is "free," but PSR-17
request-factory glue and a concrete PSR-6 cache backend are not). Every sibling SDK independently
hand-rolls this same small TTL-cache shape rather than reaching for a heavier library convenience
class.

### Anti-Patterns to Avoid

- **Alphabetizing or `ksort()`-ing the AMQP message array before HMAC verification:** breaks
  100% of verifications — the canonical order is wire/insertion order, not alphabetical (mirrors
  the Python/Java/C# siblings' proven pitfall).
- **Omitting `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` from the HMAC `json_encode()` call:**
  a PHP-specific variant of the same class of bug — silently produces different bytes than
  `serde_json` for any slash or non-ASCII content.
- **Using `firebase/php-jwt`'s `CachedKeySet`:** pulls in a PSR-18/PSR-17/PSR-6 dependency chain
  for no benefit over a ~15-line hand-rolled TTL cache (see Pattern 5).
- **Describing the Symfony bridge as "auto-discovered" in README/marketing copy:** Symfony has no
  Laravel-style zero-config discovery without a published Flex recipe (out of scope this phase) —
  document manual `config/bundles.php` registration honestly (Pitfall 5).
- **Referencing `\Grpc\BaseStub`/`AuthzGrpcClient` outside an `extension_loaded('grpc')` guard:**
  causes a fatal "Class not found" error the instant that code path executes on a REST-only runtime,
  defeating D-03's entire purpose (Pitfall 4).
- **Treating Guzzle's `MockHandler` as inherently async/concurrent:** it resolves synchronously by
  default; a naive test can pass without ever exercising the single-flight code path unless the
  queued-response ordering is deliberately constructed to force overlap (see Pattern 1's test note).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Ed25519/EdDSA signature verification | A hand-rolled Edwards-curve implementation, or reaching for a third-party crypto wrapper (the C#/Java path) | `firebase/php-jwt` 6.11's native `JWT::decode()` (internally calls `sodium_crypto_sign_verify_detached`, using PHP core's bundled `ext-sodium`) | PHP is uniquely well-positioned here versus the C#/Java siblings — no crypto workaround needed; the risk is purely operational (`extension_loaded('sodium')` on stripped builds), not a missing-capability gap. |
| HMAC-SHA256 + constant-time comparison | A hand-rolled `==`/`===` byte comparison | `hash_hmac('sha256', ..., true)` + `hash_equals()` — both native PHP functions, side-channel-resistant | Both are core-language, zero-dependency, and specifically designed to prevent the exact timing-side-channel class of bug a naive comparison introduces. |
| Cookie jar / session persistence | A custom cookie parser/store | Guzzle `GuzzleHttp\Cookie\CookieJar` with `'cookies' => true` client option (§4) | Cookie attribute parsing (domain/path/secure/`SameSite`) is exactly the "looks simple, isn't" class of problem Guzzle already solves correctly; contract-mandated regardless. |
| AMQP connection recovery / reconnect loop | A hand-rolled retry-and-redeclare loop around raw sockets | `php-amqplib`'s `AMQPStreamConnection` + standard `basic_consume`/`wait()` loop, restarted at the process level (e.g. `systemd`/RoadRunner worker respawn) on connection loss | `php-amqplib` does not have RabbitMQ.Client-style built-in automatic recovery; the idiomatic PHP-worker pattern is process-level restart-on-crash (documented explicitly in the worker script/README) rather than reimplementing reconnect logic inside the SDK — this is a real, worth-documenting difference from the Go/C#/Java siblings, not an oversight. |
| gRPC/protobuf code generation | Hand-written protobuf message classes for PHP | `buf generate` with the `buf.build/protocolbuffers/php` + `buf.build/grpc/php` remote plugins, committed stub output (D-03) | Hand-writing protobuf wire-format (de)serialization is exactly the class of bug-prone, high-maintenance code generation exists to eliminate. |
| JWT/JWKS full-spec parsing | A general-purpose "parse any JWT" library pulled in for extra safety | The minimal `JwksVerifier` in Pattern 5, scoped ONLY to EdDSA + the two claims (`tenant_id`, `exp`) the SDK actually checks | The SDK only ever verifies AXIAM's own EdDSA-signed tokens against AXIAM's own JWKS — unused algorithm/claim surface area is unnecessary attack surface, not a safety margin. |

**Key insight:** unlike the C#/Java siblings (which each hit a real native-crypto gap forcing a new
dependency), PHP's "don't hand-roll" list is short precisely because `ext-sodium` (bundled by
default) + `firebase/php-jwt` + Guzzle + `hash_hmac`/`hash_equals` already cover every
security-sensitive primitive this phase needs — the discipline here is almost entirely about
**not adding unnecessary dependencies** (`CachedKeySet`'s PSR chain, a general JWT library) rather
than filling capability gaps.

## Common Pitfalls

### Pitfall 1: PHP's default `json_encode()` escaping breaks the AMQP HMAC byte-for-byte match

**What goes wrong:** 100% HMAC verification failure rate for any message payload containing a `/`
character or non-ASCII text, indistinguishable in testing from a wrong-key or connectivity issue —
the exact same failure class the Python (Phase 19), Java (Phase 20), and C# (Phase 21) siblings
each independently hit and documented for the field-ORDER half of this problem, but PHP adds a
second, escaping-specific trap on top.

**Why it happens:** Rust's `serde_json::to_vec` neither escapes forward slashes nor non-ASCII
UTF-8 bytes. PHP's `json_encode()` escapes both **by default** (`/` → `\/`, non-ASCII → `\uXXXX`)
unless `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` is explicitly passed.

**How to avoid:** Always call `json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`
in the HMAC canonicalization path (Pattern 4). Add a fixture-based regression test using a real
signature computed via `crates/axiam-amqp/src/messages.rs::sign_payload` (or a captured live
signature) over a payload that deliberately includes a `/`-containing string and non-ASCII text —
a test that only uses plain ASCII/UUID fields will pass even with the flags omitted, silently
hiding the bug until a real payload with slashes/unicode arrives in production.

**Warning signs:** Any `json_encode()` call in the HMAC path without both flags; a passing HMAC
test suite that only exercises UUID/enum/boolean fields (no free-text strings).

### Pitfall 2: `CachedKeySet`'s PSR-18/PSR-17/PSR-6 dependency chain

**What goes wrong:** Reaching for `firebase/php-jwt`'s `CachedKeySet` "for convenience" silently
pulls three new interface dependencies into scope, at least one of which (PSR-6 cache) needs a
concrete implementation the SDK doesn't otherwise ship, conflicting with D-07's minimal-dependency
framing.

**Why it happens:** `CachedKeySet` is the library's own "batteries included" JWKS-caching helper
and is the first thing most tutorials/AI-assisted code reach for.

**How to avoid:** Use `JWK::parseKeySet()` directly with the hand-rolled TTL wrapper in Pattern 5.

**Warning signs:** Any `use Firebase\JWT\CachedKeySet;` import, or a new `psr/cache`/concrete cache
package appearing in `composer.json` for JWKS purposes only.

### Pitfall 3: JWKS is organization-wide, not tenant-scoped

**What goes wrong:** A token signed with a valid, currently-active key verifies successfully even
if it was issued for a different tenant under the same AXIAM organization — a client that stops at
"signature valid" without checking `tenant_id` risks cross-tenant token replay.

**Why it happens:** `GET /oauth2/jwks` is registered at the top server scope, outside any tenant
path segment (confirmed via `sdks/openapi.json`'s path listing — the route carries no `{tenant}`
segment) — the same document serves every tenant in the organization. Every sibling SDK
(Rust/Go/Python/Java/C#) independently confirmed and mitigated this identical finding.

**How to avoid:** Always check the `tenant_id` claim against the configured tenant AFTER signature
verification succeeds (Pattern 5's `verify()` already does this).

**Warning signs:** Any `JwksVerifier::verify()`-equivalent method that returns claims without a
`tenant_id` comparison.

### Pitfall 4: gRPC class referenced outside the `extension_loaded('grpc')` guard

**What goes wrong:** A fatal "Class 'Grpc\BaseStub' not found" error the instant any code path
(even a type-hint on an eagerly-loaded file, or an unconditional `use` inside a class that itself
gets autoloaded) references the gRPC transport class on a runtime without the `grpc` PECL extension
— completely defeating D-03's "authz always works, gRPC is opt-in" guarantee, turning an intended
graceful fallback into a hard crash.

**Why it happens:** PHP resolves an `extends`/`implements` clause's target at the moment the
declaring file executes, which happens the first time any code references that class by name —
easy to accidentally trigger from an eagerly-loaded factory/registry class that lists all transport
classes up front.

**How to avoid:** Gate every reference to `AuthzGrpcClient` (construction, type-hints in method
signatures that get called, `instanceof` checks against the class) behind an
`extension_loaded('grpc')` check at the call site, as in Pattern 2. Consider a PHPStan stub file for
`Grpc\BaseStub` so static analysis doesn't itself force-resolve the class outside the guard.

**Warning signs:** Any file outside `src/Grpc/` that imports (`use Axiam\Sdk\Grpc\...`) a gRPC class
without a preceding runtime guard.

### Pitfall 5: Symfony "auto-discovery" is not the same guarantee as Laravel's

**What goes wrong:** A plan or README that promises Symfony consumers the same
zero-config-after-`composer require` experience Laravel gets — Symfony developers file confused
bug reports when the bundle "doesn't do anything" after installation.

**Why it happens:** Laravel's package auto-discovery (`extra.laravel.providers` +
`Illuminate\Foundation\PackageManifest`) is a first-party Composer-plugin-independent mechanism.
Symfony's equivalent (Flex recipes) requires publishing a recipe to a curated, PR-reviewed registry
(`symfony/recipes-contrib`) — a separate, out-of-scope process this phase does not undertake.

**How to avoid:** Document the Symfony bridge's manual registration steps (`config/bundles.php` +
`config/services.yaml` tags) explicitly and prominently in the README and the runnable example,
rather than implying parity with Laravel's discovery.

**Warning signs:** README language like "works automatically in both Laravel and Symfony" without
a manual-registration caveat for Symfony.

### Pitfall 6: `php-amqplib` has no built-in automatic reconnection (unlike RabbitMQ.Client/amqp091-go)

**What goes wrong:** A worker that assumes the AMQP connection self-heals after a broker restart or
network blip silently stops consuming forever once `AMQPStreamConnection` drops, with no automatic
recovery — a materially different operational model from the C#/Go siblings' libraries, which both
default to automatic recovery.

**Why it happens:** `php-amqplib` is a relatively low-level, synchronous client; connection
recovery is explicitly the caller's responsibility (a documented, long-standing characteristic of
the library, not a bug).

**How to avoid:** Design the worker script to exit non-zero on a caught connection exception and
rely on process supervision (systemd `Restart=on-failure`, a RoadRunner worker pool respawn, or a
Docker `restart: unless-stopped` policy) to relaunch it — document this operational requirement
prominently alongside the Swoole/RoadRunner runtime note (SC#3), since both are "the process
manager handles what the library does not" concerns.

**Warning signs:** A worker script with no non-zero exit path on connection failure, or
documentation that doesn't mention process supervision.

## Code Examples

See **Architecture Patterns** above (Patterns 1–5) — all include complete, source-grounded code
with inline provenance comments. No additional standalone examples beyond what is already embedded
there.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `firebase/php-jwt` hosted under `firebase/php-jwt` GitHub org | Repository moved to `googleapis/php-jwt` (Packagist package name `firebase/php-jwt` unchanged) | Ongoing (confirmed live as of this research) | Cosmetic only — `composer require firebase/php-jwt` still resolves correctly; do not be confused by GitHub links resolving to a different org than the Packagist vendor prefix. |
| Guzzle 6.x-era `Client::request()` synchronous-only usage patterns common in older tutorials | Guzzle 7.x's `HandlerStack`/`Promise`-based async model (`getAsync`, `Pool`, `Promise\Utils::all`) — the mechanism D-06's single-flight design depends on | Guzzle 6→7 (2019) | Any training-data-era or tutorial-derived Guzzle code that assumes only synchronous `->request()` calls needs the async-aware `HandlerStack` middleware pattern shown in Pattern 1 to implement single-flight refresh at all. |

**Deprecated/outdated:**
- `firebase/php-jwt` 5.x/early-6.x versions predating OKP/Ed25519 support — PHP-01's 6.11 pin is
  well past that point, but do not assume an arbitrary `^6.0` range without floor-checking OKP
  support if this pin is ever revisited.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The `buf.build/protocolbuffers/php` and `buf.build/grpc/php` remote plugins exist on the BSR and produce stubs compatible with `ext-grpc`'s runtime expectations — confirmed via WebSearch of buf.build's own documentation examples, not by directly querying the BSR plugin registry or running `buf generate` in this environment (no `buf` CLI available here, consistent with every prior SDK phase's documented environment gap) | Architecture Patterns (`Don't Hand-Roll`), Package Legitimacy, `sdks/buf.gen.yaml` update guidance | Medium — if either plugin doesn't exist or produces incompatible output, the planner falls back to the `protoc` + `grpc_php_plugin` local-generation path (same fallback every prior SDK phase used for its own language when `buf` was unavailable locally) — this is a documented, low-severity contingency, not a phase blocker. |
| A2 | The per-tenant AMQP signing secret is a caller-supplied constructor/config parameter, not fetched via any documented REST endpoint — confirmed by the absence of a matching path in `sdks/openapi.json` and by mirroring every sibling SDK's (Go/Python/Java/C#) identical treatment (all take it as a plain constructor argument, sourced operationally/out-of-band) | Pattern 4 (AMQP), Common Pitfalls | Low — this is a strong cross-language precedent (5 of 5 prior AMQP-capable SDKs agree), not a novel PHP-specific guess. |
| A3 | `ext-sodium` is compiled into PHP core by default since PHP 7.2 and therefore virtually always present on a PHP ≥8.1 runtime, with the exception of some minimal/distroless-style builds compiled `--without-sodium` — based on general PHP ecosystem knowledge (php.net manual: sodium is a core extension, "there is no need to install it" on default builds), not independently verified against a specific distroless PHP Docker image in this session | Pattern 5 (JWKS), Summary | Low — the defensive `extension_loaded('sodium')` check in Pattern 5 fails closed with a clear error message regardless of whether this assumption holds on any given deployment target. |
| A4 | Sample download-count/star figures in the Package Legitimacy Audit table for `psr/log`, `grpc/grpc`, `phpunit/phpunit`, `phpstan/phpstan`, and `friendsofphp/php-cs-fixer` were not independently re-queried against the Packagist API this session (time-boxed to the three PHP-01-pinned core packages) — qualitative "well-known official project" judgment only | Package Legitimacy Audit | Low — all five are unambiguously long-established, official-project, high-adoption PHP-ecosystem staples; no `[SUS]`/`[SLOP]` risk profile is plausible for any of them. |

## Open Questions

1. **Exact `buf.gen.yaml` PHP plugin config and committed-stub directory layout (D-03 research flag).**
   - What we know: `buf.build/protocolbuffers/php` (message codegen) and `buf.build/grpc/php`
     (service stub codegen) are the documented remote-plugin names per buf.build's own docs; the
     repo's `sdks/buf.gen.yaml` currently has no PHP entry (only Rust/TypeScript/Go/Python, with
     Java commented out as drift-check-only).
   - What's unclear: The exact plugin version pin to use, and whether the generated output needs a
     post-generation namespace/autoload fixup (PHP protobuf codegen has historically needed an
     `option php_namespace`/`php_metadata_namespace` in the `.proto` files or a `--php_opt` flag to
     land in a PSR-4-friendly namespace — `proto/axiam/v1/*.proto` may need a small addition here,
     similar to how Go's codegen needed `paths=source_relative`).
   - Recommendation: Planner adds a Wave-0 task to add the PHP plugin entries to
     `sdks/buf.gen.yaml` (mirroring the existing Go/Python entries' `remote:`/`out:` shape) and
     verify the generated namespace matches `Axiam\Sdk\Grpc\Gen\...`; if `buf` CLI is unavailable in
     the execution environment (as it has been for every prior SDK phase), fall back to a local
     `protoc --php_out=... --grpc_out=... --plugin=protoc-gen-grpc=$(which grpc_php_plugin)`
     invocation documented as a reproducible Makefile/composer-script target, matching the
     Go/Python precedent.

2. **Whether `grpc/grpc` should be `require` or `suggest` in `composer.json`.**
   - What we know: The composer package itself is pure PHP (safe to install without the PECL
     extension present) and only the native extension's classes (`Grpc\Channel`, etc.) require
     `ext-grpc` to actually exist at runtime.
   - What's unclear: Whether leaving `grpc/grpc` entirely out of `require`/`require-dev` (pure
     `suggest`) means the generated stub files (which `use Grpc\BaseStub;`) are still syntactically
     loadable by PHPStan/CI static analysis without a stub definition file, or whether CI needs a
     `grpc/grpc`-as-`require-dev` + `ext-grpc` skip-if-absent test annotation.
   - Recommendation: Planner decides based on how strict the CI static-analysis gate needs to be;
     a pragmatic middle ground is `require-dev` (so tests/PHPStan always have the classes available)
     while keeping the true `require` block extension-free, with the `suggest` entry documenting the
     end-user-facing story.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| PHP CLI | Building/testing `sdks/php/` | Not verified in this research session (no local `php --version` probe run against the actual execution environment) | — | Planner/executor MUST verify `php --version` reports ≥8.1 before Wave 0. |
| `composer` | Dependency installation, `composer test`/`composer validate` (SC#5) | Not verified this session | — | Standard Composer install if absent; out of scope for this research doc. |
| `buf` CLI | gRPC PHP stub generation (D-03) | Not verified this session; every prior SDK phase (16–21) documented `buf` as unavailable in their execution environments | — | Local `protoc` + `protoc-gen-php` + `grpc_php_plugin` invocation (same fallback pattern used by Go/Python/Java in prior phases). |
| `ext-grpc` PECL | gRPC transport (opt-in, D-03) | Not verified; assumed typically absent on standard PHP-FPM images | — | REST-only fallback is the SDK's own designed behavior (D-03) — not a phase blocker. |
| `ext-sodium` | EdDSA JWKS verification (Pattern 5) | Assumed present (PHP core default since 7.2) but not independently verified this session | — | `extension_loaded('sodium')` runtime guard fails closed with a clear `AxiamException` (Pattern 5). |
| RabbitMQ broker (for AMQP integration testing) | AMQP consumer/HMAC integration tests | Not verified | — | Fixture-based unit tests (canned Rust-signed byte payloads, mirroring the Python/Java/C# siblings' approach) instead of a live broker for CI. |
| A running/reachable AXIAM server instance | End-to-end SC#1/JWKS live verification | Not verified; server-side APIs are frozen/pre-existing (Phases 1–14) | — | `MockHandler`-seeded Guzzle fixtures (login responses, JWKS documents) rather than a live server dependency for automated tests. |
| Packagist mirror repo + credentials | SC#5 live publish | Not verified — operational/maintainer concern, per D-05 explicitly allowed to be deferred | — | Pipeline + `composer validate`/`composer test` must pass in-phase; live first publish may be a maintainer action if the mirror repo/Packagist webhook aren't provisioned. |

**Missing dependencies with no fallback:** none identified — every dependency above has a
documented fallback (fixture/mock-based testing, REST-only transport, deferred live-publish action)
that does not block phase completion.

**Missing dependencies with fallback:** all rows above.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | PHPUnit 9.6.9 (PHP ≥8.1-compatible LTS line) |
| Config file | none yet — `sdks/php/phpunit.xml.dist` to be created in Wave 0 |
| Quick run command | `vendor/bin/phpunit --testsuite=unit` |
| Full suite command | `composer test` (wraps `vendor/bin/phpunit`, incl. SC#2 single-flight + AMQP HMAC fixture + Laravel/Symfony bridge tests) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PHP-01 (SC#1) | `composer require axiam/axiam-sdk` installs; `tenant` required ctor param (no default); `login()` returns typed `LoginResult` | unit | `vendor/bin/phpunit --filter ClientConstructionTest` | ❌ Wave 0 |
| PHP-01 (SC#2) | N concurrent Guzzle async promises on expired token ⇒ exactly 1 refresh | unit (`MockHandler` + `Middleware::history`, deliberately-ordered response queue) | `vendor/bin/phpunit --filter SingleFlightRefreshTest` | ❌ Wave 0 |
| PHP-01 (SC#3) | gRPC guarded by `extension_loaded('grpc')`; REST-only fallback verified; Swoole/RoadRunner requirement documented | unit (mock `extension_loaded` via a testable indirection layer, or CI matrix run without `ext-grpc` installed) + doc-presence check | `vendor/bin/phpunit --filter AuthzDispatcherFallbackTest` | ❌ Wave 0 |
| PHP-01 (SC#4) | Laravel + Symfony middleware/subscriber protect a sample endpoint; auth + `can()`→403 in runnable examples; AMQP HMAC-verify + nack-no-requeue on failure | integration (Laravel `TestCase` + `Illuminate\Foundation\Testing`, Symfony `KernelTestCase`) + unit (HMAC fixture) | `vendor/bin/phpunit --filter "LaravelMiddlewareTest|SymfonyAuthSubscriberTest|HmacVerifyTest"` | ❌ Wave 0 |
| PHP-01 (SC#5) | `composer test` passes; Packagist automation runs on release tag | build/CI pipeline | `composer validate && composer test` | ❌ Wave 0 |
| PHP-01 (D-11/CR-04) | Raw token never appears in `Sensitive`/`NetworkError`'s `__toString`/JSON/log | unit (regression, non-vacuous control case) | `vendor/bin/phpunit --filter SensitiveRedactionTest` | ❌ Wave 0 |
| PHP-01 (D-12/SC#4 gate) | No `verify => false` anywhere in `sdks/php/` | static (CI grep gate) | `grep -rn "verify.*=>.*false" sdks/php --include=*.php \| grep -v customCa` (expect empty) | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `vendor/bin/phpunit --testsuite=unit` (fast unit tests: `Sensitive` redaction,
  HMAC fixture vectors incl. the slash/unicode escaping regression, JWKS `kid` lookup, single-flight
  refresh logic)
- **Per wave merge:** `composer test` (full suite incl. Laravel/Symfony integration tests)
- **Phase gate:** Full suite green + `composer validate` + TLS-bypass grep gate empty, before
  `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `sdks/php/phpunit.xml.dist` — test suite config (unit/integration split)
- [ ] `sdks/php/tests/Fixtures/` — a real Rust-signed HMAC byte-vector fixture INCLUDING a
      slash-containing and non-ASCII-containing payload variant (generate once via a throwaway
      call into `crates/axiam-amqp`'s `sign_payload`, or a small standalone Rust binary; commit the
      fixed byte array + expected hex signature as test data — do NOT depend on `axiam-amqp` at
      runtime, only to *generate* the fixture)
- [ ] `sdks/php/tests/Fixtures/` — a real Ed25519 keypair + AXIAM-shaped JWKS document + a matching
      signed JWT fixture (mirrors the Java/C# siblings' "confirm empirically before committing"
      approach)
- [ ] Framework install: `composer require --dev phpunit/phpunit:^9.6 phpstan/phpstan:^2.2` (Wave 0,
      alongside the main package scaffold)
- [ ] `sdks/php/composer.json` `scripts.test` entry wiring `phpunit` (so `composer test` works per
      SC#5)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | EdDSA/Ed25519 JWT verification via `firebase/php-jwt` (native `ext-sodium`); reactive 401-driven refresh via the shared single-flight `Promise` (Pattern 1); never a client-side credential store beyond the Guzzle `CookieJar`. |
| V3 Session Management | yes | Guzzle `CookieJar` with `cookies: true` (§4); single-flight refresh with no retry-loop on refresh failure (§9.3); Laravel/Symfony middleware never caches verification beyond the token's remaining TTL. |
| V4 Access Control | yes | Server-side additive-only, allow-wins, default-deny RBAC is the sole source of truth (`checkAccess`/`can`/gRPC `CheckAccess`); Laravel Gate / Symfony Voter never implement client-side deny-override or long-lived authz caching; JWKS org-wide-not-tenant-scoped requires the explicit post-verification `tenant_id` claim check (Pitfall 3). |
| V5 Input Validation | yes | PSR-7 messages for all REST (de)serialization; JWT header `alg` pinned to `EdDSA` BEFORE key lookup (never trusts a token's self-declared algorithm — classic "alg confusion" defense); AMQP HMAC verification (Pattern 4) never throws on malformed attacker-controlled input, always fails closed (`false`/nack-without-requeue). |
| V6 Cryptography | yes | `firebase/php-jwt`'s native EdDSA path (via `ext-sodium`, never hand-rolled) for JWT/JWKS; native `hash_hmac('sha256', ...)` + `hash_equals()` (both PHP core, side-channel-resistant) for AMQP HMAC — no cryptographic primitive in this SDK is hand-implemented. |

### Known Threat Patterns for PHP/Laravel/Symfony SDK

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| JWT "alg confusion" (attacker crafts a token with a different/`none` algorithm) | Spoofing | Pin `alg=="EdDSA"` from the token header BEFORE any key lookup or verification attempt (Pattern 5) — never branch verifier selection on untrusted input beyond this single explicit check. |
| Cross-tenant token replay (valid signature, wrong tenant) | Elevation of Privilege | Mandatory post-signature `tenant_id` claim check against the configured tenant (Pitfall 3). |
| AMQP message tampering / forged events | Tampering | HMAC-SHA256 verify-before-handler (Pattern 4), constant-time compare via `hash_equals()`, fail-closed (nack without requeue) on any verification failure, security-event logging without leaking the HMAC value itself. |
| Token leakage via exception/log message (`NetworkError` wrapping a raw PSR-7 response carrying `Set-Cookie`) | Information Disclosure | Redact-before-wrap `NetworkError` (D-10/D-11) — this is a **carried-forward, previously-confirmed real bug class** (Phase 17 CR-04), not hypothetical. |
| TLS downgrade / certificate-validation bypass | Tampering / Information Disclosure | Absolute prohibition on `verify => false` anywhere in Guzzle client construction (§6/D-12); CI grep gate; the only escape hatch is `customCa` (a CA bundle path passed to Guzzle's `verify` option). |
| Fatal-error-as-availability-failure from an unguarded gRPC class reference | Denial of Service (self-inflicted) | `extension_loaded('grpc')` guard at every gRPC class reference (Pattern 2/Pitfall 4) — a missing guard turns an intended graceful REST fallback into a hard crash. |
| Thundering-herd token refresh (many concurrent 401s triggering many refresh calls) | Denial of Service (self-inflicted) | Shared-`Promise` single-flight guard (Pattern 1), proven by the SC#2 concurrency test. |

## Sources

### Primary (HIGH confidence)
- `sdks/CONTRACT.md` §1–§10 (this repository, binding) — read in full.
- `sdks/openapi.json` (this repository) — read directly for `/.well-known/openid-configuration`,
  `/api/v1/auth/{login,logout,refresh,mfa/verify}`, `/api/v1/authz/check[/batch]`, `/oauth2/jwks`
  paths and the `LoginRequest`/`LoginSuccessResponse`/`RefreshRequest`/`OidcDiscoveryDocument`/`Jwk`/
  `JwksDocument` schemas — confirmed 2026-07-02.
- `crates/axiam-amqp/src/messages.rs` (this repository) — read in full to confirm the AMQP HMAC
  sign/verify protocol and message field shapes.
- `packagist.org/packages/{guzzlehttp/guzzle,php-amqplib/php-amqplib,firebase/php-jwt,phpunit/phpunit,phpstan/phpstan,friendsofphp/php-cs-fixer,guzzlehttp/psr7,symfony/http-kernel}.json`
  — direct registry queries, 2026-07-02.
- `github.com/firebase/php-jwt` (`JWK.php`, `JWT.php`, `CachedKeySet.php` fetched directly via
  WebFetch, main branch) — confirmed OKP/Ed25519 support, `sodium_crypto_sign_verify_detached`
  usage, and `CachedKeySet`'s PSR-18/17/6 constructor signature, 2026-07-02.
- `github.com/php-amqplib/php-amqplib` (`demo/basic_nack.php`, official docs) — confirmed
  `basic_consume`/`basic_ack`/`basic_nack(deliveryTag, multiple, requeue)` signatures.
- `.planning/STATE.md`, `.planning/phases/{15,16,18,19,20,21}-*/{CONTEXT,RESEARCH}.md` (this
  repository) — sibling-phase precedent, especially Phase 19's proven wire-order HMAC fix and
  Phase 20/21's independent EdDSA-gap findings (which PHP does NOT share).
- `.github/workflows/sdk-ci-php.yml`, `sdk-ci-csharp.yml`, `sdk-ci-python.yml` (this repository) —
  confirmed existing scaffold CI structure and the `sdks/php/vX.Y.Z` tag convention.
- `sdks/buf.gen.yaml` (this repository) — confirmed no PHP entry exists yet; Go/Python entries used
  as the structural template for the new PHP entry.

### Secondary (MEDIUM confidence)
- Guzzle official documentation (`docs.guzzlephp.org/en/stable/handlers-and-middleware.html`,
  `.../testing.html`) — WebSearch-surfaced, cross-checked against multiple independent queries and
  matching well-known Guzzle API shapes.
- `grpc.io/docs/languages/php/quickstart/` and `grpc.github.io/grpc/php/` — WebSearch-surfaced
  confirmation of `grpc_php_plugin` + `ext-grpc` + `grpc/grpc` composer package requirements.
- `buf.build/docs/bsr/remote-plugins/` — WebSearch-surfaced confirmation of the
  `buf.build/protocolbuffers/php` / `buf.build/grpc/php` remote plugin names (not independently
  queried against the live BSR registry in this session — see Assumption A1).

### Tertiary (LOW confidence)
- General community blog/tutorial content on Guzzle refresh-token middleware patterns
  (`kamermans/guzzle-oauth2-subscriber`, Medium articles) — used only to confirm the middleware
  *shape* is a well-established community pattern, not as a source of any specific claim in this
  document.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all three PHP-01-pinned core packages verified directly against the
  Packagist registry (full version-history JSON, not a cached "latest" field); firebase/php-jwt's
  EdDSA support and `CachedKeySet` constructor confirmed directly from GitHub source.
- Architecture: HIGH — every pattern (single-flight refresh, gRPC guard, Laravel/Symfony bridges,
  AMQP worker, JWKS verification) is grounded in either a direct source/registry check or a proven
  mirror of an already-shipped sibling SDK pattern (Rust/Go/Python/Java/C#).
- Pitfalls: HIGH — Pitfalls 1–3 and 6 are empirically-confirmed or directly-source-derived; Pitfalls
  4–5 are PHP-language/ecosystem-semantics findings independently reasoned through and cross-checked
  against official Composer/Symfony documentation conventions, not speculative.

**Research date:** 2026-07-02
**Valid until:** 2026-08-01 (30 days) — shorten specifically for the buf PHP remote-plugin finding
(Assumption A1) if a `buf` CLI becomes available in this environment and the plugins can be
directly test-run, since that is the one finding not verified against a live tool invocation.
</content>
