# Phase 22: PHP SDK - Context

**Gathered:** 2026-07-02
**Status:** Ready for planning

> **Discussion note:** Interactive discuss session. The user selected all four
> originally-presented PHP-specific gray areas (Package & framework bridges,
> gRPC posture & guard, Packagist publishing, Concurrency & refresh), then chose
> "explore more" once to cover PHP baseline & PSR interop, OIDC/JWKS rotation,
> and the DTO/error-model idiom — **10 PHP-specific decisions across 2 rounds**.
> Every choice is grounded in the binding `sdks/CONTRACT.md` §1–§10, the `PHP-01`
> pinned deps, and the **six** sibling reference SDKs (Rust 16, TypeScript 17,
> Go 18, Python 19, Java 20, C# 21). All decisions below are **user-confirmed**.
> Low-level items (exact timeout/deadline/backoff numbers, JWKS cache TTL, exact
> OIDC discovery/jwks paths, internal namespace/file layout, PSR-3 facade
> specifics, plugin/tool versions) are explicitly delegated to research/planner.

<domain>
## Phase Boundary

Phase 22 delivers `sdks/php/` — the Composer package **`axiam/axiam-sdk`**
(PSR-4 namespace `Axiam\Sdk`, PHP **≥8.1**) — the **seventh and final SDK**
(after Rust ref Phase 16, TypeScript Phase 17, Go Phase 18, Python Phase 19,
Java Phase 20, C# Phase 21). It implements the full client capability baseline
against the frozen v1.0 APIs in idiomatic PHP 8.1+:

- **REST** (Guzzle **7.x** + `HandlerStack` single-refresh middleware +
  `CookieJar` with `cookies: true`, `verify: true`) — auth flow (`login` →
  `verifyMfa`), `refresh`, `logout`, `checkAccess`/`can`, `batchCheck`. JSON
  over PSR-7 messages.
- **AMQP** (php-amqplib **3.7**) — a CLI-worker consumer with HMAC-SHA256
  verify-before-handler and ack/nack semantics.
- **Local JWKS** (firebase/php-jwt **6.11**, EdDSA/Ed25519) for proactive
  refresh + middleware local verification, sourced via OIDC discovery.
- **gRPC guarded by `extension_loaded('grpc')`** (optional grpc PECL) — when
  absent OR configured REST-only, `checkAccess`/`can` transparently route over
  the FND-04 REST endpoint. gRPC is a performance opt-in requiring a
  long-running runtime (Swoole/RoadRunner/CLI), documented prominently (SC#3).
- A first-class **Laravel** (ServiceProvider + Middleware) and **Symfony**
  (Bundle + EventSubscriber/Voter) integration providing authentication
  (identity population) **and** authorization (`can()` → 403) helpers.

Public method names follow **camelCase** (CONTRACT §1 PHP row). PHP is a
**non-browser** SDK, so §3 CSRF = capture `X-CSRF-Token` from the response
header (not the browser cookie double-submit). It conforms to `sdks/CONTRACT.md`
§1–§10 in full and **inherits the Rust/TS/Go/Python/Java/C# reference patterns**
wherever a PHP analog exists. The novel work this phase resolves is everything
PHP's ecosystem forces — the Guzzle `HandlerStack` promise-based single-flight,
the `extension_loaded('grpc')` REST-fallback posture, the CLI-worker AMQP
consumer, the Laravel ServiceProvider + Symfony Bundle auto-discovery, and the
**monorepo→Packagist subtree-split publish** problem.

**In scope (PHP-01):** the `sdks/php/` package + REST + AMQP + gRPC (guarded) +
Laravel/Symfony bridges (auth + authz) + committed gRPC stubs + `Sensitive` +
JWKS + examples + Packagist publish automation, with promise-based single-flight
refresh, HMAC verify, and the no-TLS-bypass gate proven by test.

**Out of scope:** any change to the AXIAM server (v1.0 APIs are frozen; the SDK
is a pure external client and MUST NOT depend on server crates); the shared
foundation already delivered in Phase 15 (`buf.gen.yaml`, `CONTRACT.md`, FND-04
endpoint, scaffold); a persistent-connection story for standard PHP-FPM (gRPC
channel reuse + AMQP consumer are long-running-runtime concerns — see Deferred).

</domain>

<decisions>
## Implementation Decisions

> **Note:** The SDK's *behavioral* surface is already locked by the binding
> `sdks/CONTRACT.md` §1–§10 and by `PHP-01` (pinned deps: Guzzle 7.x,
> php-amqplib 3.7, firebase/php-jwt 6.11, optional grpc PECL behind
> `extension_loaded('grpc')`; Guzzle `CookieJar`/`HandlerStack`; `verify: true`;
> `tenant` required constructor param; Laravel+Symfony middleware; Packagist
> `axiam/axiam-sdk`). The decisions below are the **HOW choices** — all
> **user-confirmed** in the 2026-07-02 discuss session. They do not restate the
> contract — downstream agents MUST read CONTRACT.md.

### Package Structure & Framework Bridges
- **D-01 [LOCKED]:** **Single package + first-class, auto-discovered bridges.**
  One `axiam/axiam-sdk` Composer package contains the REST/gRPC/AMQP core **plus**
  a first-class Laravel ServiceProvider (auto-discovered via
  `extra.laravel.providers`) and a Symfony Bundle/EventSubscriber, each guarded by
  framework class presence so the **core has zero framework deps at runtime**.
  NOT separate `axiam/axiam-laravel` + `axiam/axiam-symfony` packages — that would
  triple the monorepo subtree-split/Packagist cost (D-06). Keeps SC#1's one-line
  `composer require axiam/axiam-sdk` true and still delivers first-class
  integration beyond bare examples. Mirrors the C#/Java single-artifact +
  optional-framework model (C# D-03, Java single-jar).
- **D-02 [LOCKED]:** **Bridges do auth + authz.** Authentication: middleware
  verifies the token (local JWKS) and populates framework identity (Laravel:
  resolve `$request->user()` / bind a guard; Symfony: security token) with
  `user_id`/`tenant_id`/`roles`, 401 on failure per §10. Authorization: a
  framework-native gate calls `$client->can(resource, action)` → 403 — Laravel
  route middleware (e.g. `axiam.can:doc,read`) + a Gate; Symfony a Voter. The
  runnable example (SC#4) demonstrates **both**. Direct analog of C# D-06+D-08 /
  Java Spring `SecurityContext`. Within the framework-integration domain (helper),
  not a new capability.

### gRPC Posture & Guard
- **D-03 [LOCKED]:** **Committed stubs + transparent REST fallback.**
  buf-generates PHP gRPC stubs in CI, **committed** into `sdks/php/src/`
  (source-distributed like Go/Python — PHP consumers lack `protoc` +
  `grpc_php_plugin`). Usage guarded by `extension_loaded('grpc')`; when the PECL
  extension is absent **OR** the client is configured REST-only, `checkAccess`/
  `can` transparently route over the FND-04 REST endpoint
  (`POST /api/v1/authz/check`). Authz therefore **always works**; gRPC is a
  performance opt-in. The `grpc` PECL is a `suggest`/optional dep, **never
  hard-required** in `composer.json`.
- **D-04 [LOCKED]:** **AMQP = CLI-worker consumer, verify-before-handler.**
  php-amqplib 3.7 blocking consume loop exposed as a standalone CLI-oriented
  consumer class (run via a worker script / RoadRunner worker) — **not a
  web-request path**. On each delivery: verify HMAC-SHA256 (constant-time compare)
  **BEFORE** invoking the app handler; handler success → `ack`; retryable failure
  → `nack` **WITH** requeue; HMAC-fail / parse-fail / drop-sentinel → `nack`
  **WITHOUT** requeue + security log. Handler never sees an unverified message.
  Ships a runnable worker example. README documents **prominently** that gRPC
  channel reuse + the AMQP consumer require Swoole/RoadRunner/CLI, not standard
  FPM (SC#3). Direct Go/C# analog. (Optional thin Laravel Artisan / Symfony
  Console command wrappers considered — deferred; see Deferred.)

### Packagist Publishing
- **D-05 [LOCKED]:** **Subtree-split to a read-only mirror repo, tag-triggered.**
  Packagist has no native subdirectory support and the repo root is a Rust
  workspace, so `sdks/php/` cannot be published directly. CI runs `git subtree
  split` (or splitsh-lite) of `sdks/php/` on the `sdks/php/vX.Y.Z` release tag
  (Phase 15 D-13), pushes to a **read-only mirror repo** (e.g.
  `ilpanich/axiam-php-sdk`) re-tagged `vX.Y.Z`; Packagist points at the mirror and
  auto-updates via its GitHub webhook/API. The proven monorepo→Packagist pattern
  (Symfony/Laravel components). **Pipeline + `composer validate` + `composer test`
  must pass in-phase (SC#5)**; live mirror-repo creation + Packagist registration
  + first publish may be a **maintainer action** if the mirror/creds aren't
  provisioned in CI — same posture as C# D-04's deferred live first-publish.

### Concurrency & Single-Flight Refresh
- **D-06 [LOCKED]:** **Shared refresh-promise single-flight in the HandlerStack,
  no extra dep.** The Guzzle `HandlerStack` middleware holds a single shared
  refresh `Promise`: on expired/401, the first request **synchronously**
  checks-and-stores the refresh promise; concurrent async requests await that
  **same** promise → exactly 1 refresh call. **Fiber-safe by construction** (PHP
  Fibers are cooperative/non-preemptive; the check-and-store completes before any
  `await`), so **no `revolt/event-loop` mutex is needed on the base path**. §9
  single-flight guard is one shared promise across REST (and, when active, the
  gRPC path shares the same token/refresh). SC#2 PHPUnit test: fire N concurrent
  Guzzle async promises against an expired token with a `MockHandler` counting
  refresh hits → assert **== 1**. Planner may add a fiber/coroutine mutex **only**
  if a true-parallel runtime demands it (§9 PHP row leaves this open).

### PHP Baseline & PSR Interop
- **D-07 [LOCKED]:** **PHP 8.1 floor + PSR-3/PSR-7; Guzzle pinned.** Keep the
  scaffold's `php: >=8.1` — gives Fibers (D-06), enums (D-10), readonly
  properties, first-class callable syntax; matches firebase/php-jwt 6.11 +
  php-amqplib 3.7. Depend on **PSR-3** `LoggerInterface` (silent `NullLogger`
  default, redaction-aware — never logs `Sensitive`) and use **PSR-7** messages
  (Guzzle-native). **Guzzle 7.x stays a hard, pinned dep** — CONTRACT §4/§9
  require `CookieJar` + `HandlerStack`, so **no PSR-18 swappability**. PSR-11
  container not required.

### JWKS Acquisition & Rotation
- **D-08 [LOCKED]:** **OIDC discovery + TTL cache + rotate-on-unknown-`kid`.**
  Resolve `jwks_uri` via OIDC discovery (`/.well-known/openid-configuration`),
  fetch JWKS, cache with a TTL, and refetch **once** on an unknown `kid` before
  failing — the rotation pattern from the Rust/C# siblings. Enables proactive
  local EdDSA verification for the middleware (D-02); reactive 401-driven refresh
  remains the fallback. Exact TTL + discovery/jwks paths delegated to research
  (**confirm the server's discovery + jwks paths** — see research flag).

### DTO & Error-Model Idiom
- **D-09 [LOCKED]:** **Readonly DTOs.** `readonly` DTO classes for `LoginResult`
  (+ `mfaRequired` and optional fields) and other responses. DTO style (record-like
  readonly classes) is the idiom downstream code targets.
- **D-10 [LOCKED]:** **Typed exception hierarchy for the §2 taxonomy.**
  `AuthError` / `AuthzError` / `NetworkError` extending a base `AxiamException`,
  thrown from **one central status→error mapper** (HTTP §2 table + gRPC status
  codes). **`NetworkError` MUST redact `Set-Cookie`/`Authorization`/`Cookie`**
  from any wrapped PSR-7 response/exception **before** storing it — never let a raw
  token enter the exception chain, `__toString`, or logs. This exception hierarchy
  is the target of the **CR-04 redaction regression test** (D-11). NOT a flat
  enum-of-codes on a single exception type (diverges from siblings' catch-by-type).

### Token Safety & Verification (carried forward from siblings — locked, not re-asked)
- **D-11:** **`Sensitive` — `__toString()` → `"[SENSITIVE]"` (§7 PHP row floor)
  + redact-before-wrap on `NetworkError` (CR-04 carry-forward).** Additionally
  harden JSON serialization (`JsonSerializable`) to emit `[SENSITIVE]`. Add a PHP
  regression test analogous to the sibling error-redaction tests (assert the raw
  `axiam_access`/`axiam_refresh` value never appears in `__toString`/JSON/log of a
  thrown error, with a **non-vacuous control case**). Direct TS Phase 17 CR-04
  carry-forward.
- **D-12:** **TLS no-bypass (§6 / SC#4).** Guzzle `verify: true` always; **no
  `verify => false` anywhere** in source, examples, or tests. Only a `customCa`
  escape hatch (path to a CA bundle). A CI grep gate over `sdks/php/` MUST return
  empty for TLS-disable patterns.
- **D-13:** **Tenant required (§5 / SC#1).** `tenant` (slug) is a **required
  constructor parameter with no nullable default**.

### Claude's Discretion (delegated to research/planner)
- Internal namespace/folder/file layout under `sdks/php/src/`.
- Exact numeric timeout/backoff/retry values and gRPC per-call deadline (sane
  defaults, options-overridable; idempotent-only bounded exponential backoff +
  jitter, honor `Retry-After`; state-changing requests never auto-retry — Java
  D-26 / Go analog).
- JWKS cache-TTL value and exact OIDC discovery/jwks endpoint paths (confirm
  against server).
- gRPC channel construction, metadata injection (`Authorization`/`X-Tenant-Id`/
  `X-CSRF-Token`); one long-lived channel reused across authz RPCs on
  long-running runtimes.
- `LoginResult` optional-field set beyond `mfaRequired`.
- composer/CI plugin + tool versions; buf PHP plugin config for stub generation;
  PHPUnit/PHPStan/coding-standard tooling choice.
- PSR-3 logging facade specifics (default `NullLogger`, redaction-aware).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Binding contract & phase definition (read FIRST)
- `sdks/CONTRACT.md` §1–§10 — **normative/binding** cross-language behavioral
  contract. The PHP SDK *implements* this. Relevant §: §1 camelCase method map
  (row: PHP), §2 error taxonomy + status mapping (D-10), §3 CSRF (**PHP =
  non-browser → `X-CSRF-Token` response header**), §4 cookie jar (**"Guzzle
  `CookieJar` with `cookies: true` handler option"** → D-01/D-06), §5 tenant
  (required constructor param, SC#1 → D-13), §6 TLS no-bypass (D-12; SC#4 gate),
  §7 `Sensitive` (**"`__toString()` returns `\"[SENSITIVE]\"`"** → D-11), §8 AMQP
  HMAC protocol (D-04), §9 single-flight (**"Fiber-safe `Mutex` from
  `revolt/event-loop` or equivalent"** → D-06 resolves this to a shared promise;
  §9 concurrency-safety across fibers), §10 Laravel/Symfony middleware
  (**"`Middleware` (Laravel) / `EventSubscriber` (Symfony)"** → D-01/D-02). The
  closing "C# `Grpc.Tools` Exception" note confirms **PHP runs `buf generate`**
  for codegen (→ D-03).
- `.planning/ROADMAP.md` — Phase 22 goal + 5 success criteria; the
  `sdks/<lang>/vX.Y.Z` tag convention (Phase 15 D-13) the publish CI follows
  (→ D-05).
- `.planning/REQUIREMENTS.md` §PHP-01 — acceptance criteria + pinned deps (Guzzle
  7.x + php-amqplib 3.7 + firebase/php-jwt 6.11; optional grpc PECL behind
  `extension_loaded('grpc')` + Swoole/RoadRunner requirement; Guzzle
  `CookieJar`/`HandlerStack`; `verify: true`; Laravel+Symfony middleware;
  Packagist `axiam/axiam-sdk`).

### ⚠ Research flags (must resolve before planning)
- **OIDC discovery + JWKS endpoint paths (D-08).** Confirm the AXIAM server's
  actual `/.well-known/openid-configuration` and `jwks_uri`/`jwks.json` paths, and
  the EdDSA `alg`/`kid` shape firebase/php-jwt 6.11 must verify.
- **buf PHP gRPC codegen (D-03).** Confirm the `buf.gen.yaml` PHP plugin
  (`protocolbuffers/php` + `grpc/php`) produces committable stubs compatible with
  the `grpc` PECL runtime; determine the committed-stubs directory + gitignore
  posture (source-distributed, unlike compiled SDKs).
- **php-amqplib 3.7 consumer API (D-04).** Confirm blocking-consume + ack/nack
  (no-requeue) signatures and reconnection handling for the CLI worker.

### Prior-phase decisions this phase inherits
- `.planning/phases/21-c-sdk/21-CONTEXT.md` — **most recent sibling.** Two-artifact
  core + optional-framework split (→ D-01), full-idiom auth + policy authz (→ D-02),
  transparent transport selection (→ D-03), verify-before-handler AMQP (→ D-04),
  deferred live first-publish posture (→ D-05), single-flight guard framing
  (→ D-06), redact-before-wrap `NetworkError` (→ D-10/D-11), bounded-backoff/
  timeouts/logging discretion.
- `.planning/phases/19-python-sdk/19-CONTEXT.md` — **dynamic-language analog.**
  Source-distributed committed stubs (→ D-03), `Sensitive` multi-surface redaction
  (→ D-11), publish/signing framing (→ D-05).
- `.planning/phases/18-go-sdk/18-CONTEXT.md` — non-browser reference. Callback AMQP
  consumer + nack-no-requeue (→ D-04), typed error + redact-before-wrap (→ D-10),
  identity-injection middleware (→ D-02), client override safety (→ D-12).
- `.planning/phases/17-typescript-sdk/17-CONTEXT.md` + `17-REVIEW.md` §CR-04 +
  `17-VERIFICATION.md` — the **token-leak-via-error** finding + `sanitizeAxiosError()`
  fix; **D-10/D-11's redact-before-wrap is the direct PHP carry-forward.** Read
  CR-04 before implementing `NetworkError`. Also the closest REST-first + guarded
  higher-transport posture analog.
- `.planning/phases/16-rust-sdk/16-CONTEXT.md` — first reference (local JWKS + OIDC
  discovery/rotation → D-08, shared-session single-flight → D-06, closure-handler
  AMQP → D-04, regenerate-and-distribute codegen → D-03).
- `.planning/phases/15-sdk-foundation/15-CONTEXT.md` — D-01 (C# is the ONLY buf
  exception → PHP uses `buf generate`, D-03), D-05 (FND-04 `/authz/check` +
  `/batch`), D-09/D-10 (binding contract + locked vocabulary), D-11/D-12/D-13
  (package identities + monorepo tag scheme `sdks/php/vX.Y.Z`).

### SDK domain research (read for rationale)
- `.planning/research/ARCHITECTURE.md` — codegen source-of-truth, monorepo +
  path-filtered CI.
- `.planning/research/STACK.md` — toolchain + plugin set.
- `.planning/research/PITFALLS.md` — cross-language divergence trap + the
  **TLS-bypass pitfall** (→ SC#4 gate; PHP = Guzzle `verify => false`).
- `.planning/research/FEATURES.md` — per-SDK feature matrix.
- `.planning/research/SUMMARY.md` — consolidated research synthesis
  (TLS-disabled anti-pattern).

### Code the SDK consumes / mirrors (reuse semantics; do NOT depend on server crates)
- `crates/axiam-amqp/src/messages.rs` — **AMQP HMAC reference impl** (§8):
  canonical-JSON + hex-HMAC-SHA256 protocol the PHP verify (D-04) must match
  byte-for-byte (use `hash_hmac('sha256', ...)` + `hash_equals()` for constant-time
  compare).
- `sdks/typescript/src/core/errorMapper.ts` (`sanitizeAxiosError`), plus the
  Go/Python/Java/C# error + sensitive modules — the redaction implementations
  D-10/D-11 mirror in PHP.
- `sdks/rust/src/`, `sdks/go/`, `sdks/python/src/axiam_sdk/`, `sdks/java/src/`,
  `sdks/csharp/` — reference trees (session/single-flight, grpc interceptor/
  metadata, amqp consumer, middleware, sensitive) — structural analogs for the PHP
  classes.
- `proto/axiam/v1/authorization.proto`, `user.proto`, `token.proto` — proto surface
  the PHP stubs cover; `CheckAccess`/`BatchCheckAccess` request/response shapes.
- `crates/axiam-api-grpc/src/services/authorization.rs` — gRPC
  `check_access`/`batch_check_access` semantics the PHP gRPC client targets.
- REST `POST /api/v1/authz/check` + `/api/v1/authz/check/batch` (Phase 15 FND-04,
  `crates/axiam-api-rest/src/handlers/authz_check.rs`) — the endpoints `checkAccess`/
  `can`/`batchCheck` call (and the transparent gRPC-absent fallback target, D-03).
- `sdks/buf.gen.yaml` — buf codegen config; PHP **adds** a plugin entry here (unlike
  the C# `Grpc.Tools` exception) to generate committable stubs (D-03).
- `sdks/php/{composer.json,README.md,LICENSE}` — existing scaffold
  (`axiam/axiam-sdk`, PSR-4 `Axiam\Sdk\`, `php: >=8.1`, Apache-2.0) — Phase 22
  fills it in.
- OIDC `/.well-known/openid-configuration` + `jwks_uri` (exact paths to confirm in
  research) — JWKS source for D-08.

### Project-wide constraints
- License is **Apache-2.0** repo-wide — `sdks/php/LICENSE` + `composer.json`
  `"license": "Apache-2.0"` already match; keep them. See project memory
  `project_license_apache.md`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `sdks/rust/`, `sdks/typescript/`, `sdks/go/`, `sdks/python/`, `sdks/java/`,
  `sdks/csharp/` — **six** complete reference implementations of the same
  contract; the PHP SDK ports their structure (shared session + single-flight
  guard, gRPC metadata injection, callback AMQP consumer, JWKS cache, middleware)
  into idiomatic PHP 8.1.
- The sibling error-redaction + `Sensitive` implementations — the exact behavior
  PHP's `NetworkError` (D-10) and `Sensitive` class (D-11) mirror (CR-04
  carry-forward).
- `crates/axiam-amqp/src/messages.rs` — canonical HMAC sign/verify; the PHP
  consumer reimplements *verification* (cannot depend on the crate) but the
  canonical-JSON + hex-HMAC-SHA256 protocol must be byte-identical (§8 / D-04);
  use `hash_hmac` + `hash_equals`.
- `proto/axiam/v1/*.proto` — the proto surface; D-03 generates PHP stubs via
  `buf generate`, committed into `sdks/php/src/`.
- `sdks/php/` scaffold (`composer.json` with `axiam/axiam-sdk` + Apache-2.0 +
  PSR-4 `Axiam\Sdk\`, LICENSE, README) — Phase 22 fills it in; `php: >=8.1`
  already set (D-07).

### Established Patterns
- **CONTRACT.md is binding (Phase 15 D-09):** "CONTRACT.md §1–§10 conformance
  verified" is a required acceptance checklist item for this phase.
- **No TLS bypass (§6 / SC#4):** no Guzzle `verify => false` anywhere in
  `sdks/php/` (source + examples + tests); a CI grep gate MUST return empty. Only
  a `customCa` escape hatch.
- **PHP runs `buf generate` (§ / Phase 15 D-01):** C# is the ONLY documented buf
  exception; PHP uses the repo-wide `buf` pipeline and **commits** the generated
  stubs (source-distributed, D-03).
- **Additive-only / allow-wins / default-deny RBAC** constrains how the SDK
  surfaces authz `reason` semantics (mirrors gRPC), and how the Laravel Gate /
  Symfony Voter maps authz results to 403 (D-02).
- **Monorepo tag release** (`sdks/php/vX.Y.Z`, Phase 15 D-13) — the publish CI
  follows it, then subtree-splits to a mirror for Packagist (D-05).
- **Codegen distribution differs by ecosystem:** PHP (like Go/Python) is
  source-distributed via Composer, so D-03 **commits** generated stubs — unlike
  compiled Rust/TS/Java/C# which ship compiled artifacts.

### Integration Points
- New `sdks/php/` package: `src/` (REST core + gRPC + AMQP + auth/JWKS +
  `Sensitive` + exception hierarchy + generated stubs), Laravel ServiceProvider +
  Middleware + Gate, Symfony Bundle + EventSubscriber + Voter (all guarded by
  framework class presence), plus `examples/` including a runnable Laravel and
  Symfony app demonstrating auth middleware + `can()`→403 (SC#4) and a standalone
  AMQP worker script (D-04).
- New per-SDK GitHub Actions workflow under `.github/workflows/` with
  `paths: sdks/php/**` filter: `composer validate` + `composer test` (incl. the
  PHPUnit concurrent-single-flight test SC#2) + the TLS-bypass grep gate +
  subtree-split → mirror push + tag-triggered Packagist update (`sdks/php/vX.Y.Z`,
  SC#5).
- gRPC stubs generated from `proto/axiam/v1/` via `buf generate`, committed into
  `sdks/php/src/` (D-03).

</code_context>

<specifics>
## Specific Ideas

- The PHP SDK is the **Laravel/Symfony + Composer SDK** — decisions favor what PHP
  developers expect (Guzzle `HandlerStack` middleware, auto-discovered
  ServiceProvider/Bundle, readonly DTOs, typed exception hierarchy, PSR-3 logging,
  Packagist) while staying byte-faithful to the shared contract.
- Success-criterion proof points to preserve as concrete tests: (#1) `composer
  require axiam/axiam-sdk` installs + `tenant` required constructor param (no
  default) + `$client->login($email, $password)` returns a typed `LoginResult`;
  (#2) N concurrent Guzzle async requests on an expired token ⇒ **exactly 1
  refresh** (PHPUnit shared-promise single-flight test, MockHandler-counted);
  (#3) gRPC guarded by `extension_loaded('grpc')` → REST-only fallback when absent
  + Swoole/RoadRunner requirement documented prominently; (#4) Laravel and Symfony
  middleware protect a sample endpoint in **runnable examples** (demonstrating auth
  + `can()`→403 per D-02) + AMQP consumer HMAC-verify + nack-no-requeue on failure;
  (#5) `composer test` passes + Packagist automation (`axiam/axiam-sdk`) runs on
  release tag.
- **CR-04 must not recur in PHP:** never wrap a raw PSR-7 response/exception
  carrying `Set-Cookie`/`Authorization` into `NetworkError` without redacting first
  (D-10/D-11). Add a PHP regression test analogous to the sibling error-redaction
  tests (assert the raw `axiam_access`/`axiam_refresh` value never appears in
  `__toString`/JSON/log of a thrown error, with a non-vacuous control case).

</specifics>

<deferred>
## Deferred Ideas

- **Separate `axiam/axiam-laravel` + `axiam/axiam-symfony` bridge packages** —
  the strict PHP-ecosystem norm, considered (D-01); rejected for this phase because
  it triples the monorepo subtree-split/Packagist cost. **Do not lose** — if the
  bundled-bridge footprint becomes a concern, revisit splitting the bridges into
  their own Packagist packages (each with its own subtree split).
- **Framework Artisan/Console command wrappers for the AMQP worker** — considered
  (D-04); thin Laravel Artisan + Symfony Console wrappers around the consumer core
  would integrate with each framework's process manager. Deferred as extra surface
  for a v1.1 starter SDK; the standalone worker script ships now.
- **`revolt/event-loop` fiber mutex on the base single-flight path** — considered
  (D-06 / CONTRACT §9 PHP row's literal suggestion); rejected as an unneeded runtime
  dep because PHP Fibers are cooperative and the shared-promise check-and-store is
  atomic. Revisit only if a true-parallel (Swoole preemptive coroutine) runtime
  needs it.
- **netstandard-style broad-runtime / persistent-connection support under
  standard PHP-FPM** — gRPC channel reuse + the AMQP consumer are long-running
  runtime concerns (Swoole/RoadRunner/CLI). A first-class FPM persistent story is
  out of scope; documented as a runtime requirement (SC#3) instead.
- **PSR-18 HTTP-client swappability** — considered (D-07); rejected because
  CONTRACT §4/§9 pin Guzzle `CookieJar` + `HandlerStack`. Revisit only if a
  Guzzle-independent transport becomes a requirement.
- **Live Packagist first publish + mirror-repo creation** — the pipeline +
  `composer validate`/`composer test` must pass in-phase, but the first real
  publish + read-only mirror repo may be a maintainer action if the mirror/creds
  are absent in CI (D-05).
- **Automated cross-language conformance harness** — inherited from Phase 15–21
  deferred list; Phase 22 verifies conformance via its own §1–§10 checklist, not a
  mechanical suite.

### Reviewed Todos (not folded)
None — no pending todos matched this phase.

</deferred>

---

*Phase: 22-php-sdk*
*Context gathered: 2026-07-02*
