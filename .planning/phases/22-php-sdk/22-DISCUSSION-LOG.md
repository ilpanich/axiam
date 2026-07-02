# Phase 22: PHP SDK - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-02
**Phase:** 22-php-sdk
**Areas discussed:** Package & framework bridges, gRPC posture & guard, Packagist publishing, Concurrency & refresh, PHP baseline & PSR interop, OIDC discovery & JWKS rotation, DTO & error-model style

---

## Area selection (round 1)

| Option | Selected |
|--------|----------|
| Package & framework bridges | ✓ |
| gRPC posture & guard | ✓ |
| Packagist publishing | ✓ |
| Concurrency & refresh | ✓ |

**User's choice:** All four.

---

## Package & framework bridges — structure

| Option | Description | Selected |
|--------|-------------|----------|
| Single package + first-class bridges | One `axiam/axiam-sdk` with Laravel ServiceProvider + Symfony Bundle bundled & auto-discovered, framework-guarded; core has zero framework deps | ✓ |
| Separate bridge packages | `axiam/axiam-sdk` + `axiam/axiam-laravel` + `axiam/axiam-symfony` as distinct Packagist packages | |
| Single package + examples only | Framework integration as runnable copy-paste examples only | |

**User's choice:** Single package + first-class bridges (Recommended).
**Notes:** Avoids tripling the monorepo subtree-split/Packagist cost; keeps SC#1's one-line install true. → D-01.

## Package & framework bridges — integration surface

| Option | Description | Selected |
|--------|-------------|----------|
| Auth + authz helpers | Middleware verifies token + populates identity (401); plus a gate calling `can()`→403 (Laravel route middleware + Gate; Symfony Voter). Example demonstrates both | ✓ |
| Authentication only | Bridges verify token + populate identity + 401; authz left for the app to wire manually | |

**User's choice:** Auth + authz helpers (Recommended).
**Notes:** Mirrors C# D-06+D-08 / Java Spring SecurityContext. → D-02.

---

## gRPC posture & guard — packaging + fallback

| Option | Description | Selected |
|--------|-------------|----------|
| Commit stubs + transparent REST fallback | buf-gen stubs committed; `extension_loaded('grpc')` guard; `can()`/`checkAccess()` fall back to FND-04 REST when absent/configured; grpc PECL optional | ✓ |
| Commit stubs + hard error when absent | Same stubs, but throw when gRPC method called without the extension (no silent fallback) | |
| Generate stubs on install | Run protoc + grpc_php_plugin at install time (heavy toolchain requirement) | |

**User's choice:** Commit stubs + transparent REST fallback (Recommended).
**Notes:** Source-distributed like Go/Python; authz always works, gRPC is a perf opt-in. → D-03.

## gRPC posture & guard — AMQP consumer shape

| Option | Description | Selected |
|--------|-------------|----------|
| CLI worker + callback, verify-before-handler | php-amqplib blocking consumer as a standalone CLI worker; HMAC verify before handler; ack/nack(no-requeue); Swoole/RoadRunner documented | ✓ |
| Also add a framework command wrapper | Same core + Laravel Artisan / Symfony Console wrappers | |

**User's choice:** CLI worker + callback, verify-before-handler (Recommended).
**Notes:** Direct Go/C# analog; framework command wrappers deferred. → D-04.

---

## Packagist publishing

| Option | Description | Selected |
|--------|-------------|----------|
| Subtree-split to a read-only mirror repo | CI `git subtree split` on `sdks/php/vX.Y.Z` → push to mirror repo re-tagged `vX.Y.Z` → Packagist auto-updates. Pipeline proven in-phase; live publish deferrable to maintainer | ✓ |
| Manual/maintainer publish only | Documented manual release runbook, no subtree-split automation | |

**User's choice:** Subtree-split to a read-only mirror repo (Recommended).
**Notes:** Standard Symfony/Laravel monorepo→Packagist pattern; Packagist has no subdirectory support and repo root is a Rust workspace. → D-05.

---

## Concurrency & refresh

| Option | Description | Selected |
|--------|-------------|----------|
| Shared refresh-promise in HandlerStack, no extra dep | First request synchronously checks-and-stores a shared refresh Promise; concurrent async requests await it → 1 refresh. Fiber-safe by construction; no revolt dep | ✓ |
| Promise + explicit revolt/event-loop mutex | Same, but always wrap the guard in a revolt/event-loop Fiber-safe mutex (extra runtime dep) | |

**User's choice:** Shared refresh-promise in HandlerStack, no extra dep (Recommended).
**Notes:** SC#2 tested via N concurrent Guzzle async promises + counting MockHandler == 1. → D-06.

---

## Area selection (round 2 — "explore more")

| Option | Selected |
|--------|----------|
| PHP baseline & PSR interop | ✓ |
| OIDC discovery & JWKS rotation | ✓ |
| DTO & error-model style | ✓ |

**User's choice:** All three.

---

## PHP baseline & PSR interop

| Option | Description | Selected |
|--------|-------------|----------|
| PHP 8.1 floor + PSR-3/PSR-7, Guzzle pinned | Keep `php: >=8.1` (Fibers/enums/readonly); PSR-3 logger + PSR-7 messages; Guzzle pinned (no PSR-18 swap) | ✓ |
| PHP 8.2 floor | Raise floor to 8.2 for readonly classes + DNF types | |

**User's choice:** PHP 8.1 floor + PSR-3/PSR-7, Guzzle pinned (Recommended).
**Notes:** Matches scaffold + firebase/php-jwt 6.11 + php-amqplib 3.7; Guzzle pinned per CONTRACT §4/§9. → D-07.

## OIDC discovery & JWKS rotation

| Option | Description | Selected |
|--------|-------------|----------|
| OIDC discovery + TTL cache + rotate-on-unknown-kid | Resolve `jwks_uri` via `/.well-known/openid-configuration`; cache with TTL; refetch once on unknown `kid` | ✓ |
| Fixed jwks.json path + TTL cache | Skip discovery; fetch fixed `/.well-known/jwks.json`; cache + rotate on unknown `kid` | |

**User's choice:** OIDC discovery + TTL cache + rotate-on-unknown-kid (Recommended).
**Notes:** Rotation pattern from Rust/C# siblings; exact TTL/paths delegated to research. → D-08.

## DTO & error-model style

| Option | Description | Selected |
|--------|-------------|----------|
| Readonly DTOs + exception hierarchy | `readonly` DTOs for `LoginResult` etc.; `AuthError`/`AuthzError`/`NetworkError` extending `AxiamException` from a central status→error mapper; `NetworkError` redacts before wrap (CR-04) | ✓ |
| Readonly DTOs + enum error codes | Same DTOs, but error taxonomy as a PHP enum on a single exception type | |

**User's choice:** Readonly DTOs + exception hierarchy (Recommended).
**Notes:** Idiomatic catch-by-type; aligns with sibling SDKs' typed errors; CR-04 regression-test target. → D-09/D-10.

---

## Claude's Discretion

- Internal namespace/folder/file layout under `sdks/php/src/`.
- Exact timeout/backoff/retry values, gRPC per-call deadline.
- JWKS cache-TTL value + exact OIDC discovery/jwks endpoint paths (confirm against server).
- gRPC channel construction + metadata injection.
- `LoginResult` optional-field set beyond `mfaRequired`.
- composer/CI plugin + tool versions; buf PHP plugin config; PHPUnit/PHPStan/coding-standard tooling.
- PSR-3 logging facade specifics (default `NullLogger`, redaction-aware).

## Deferred Ideas

- Separate `axiam/axiam-laravel` + `axiam/axiam-symfony` bridge packages.
- Framework Artisan/Console command wrappers for the AMQP worker.
- `revolt/event-loop` fiber mutex on the base single-flight path.
- Broad-runtime / persistent-connection support under standard PHP-FPM.
- PSR-18 HTTP-client swappability.
- Live Packagist first publish + mirror-repo creation (maintainer action if creds absent).
- Automated cross-language conformance harness (inherited from Phase 15–21 deferred list).
