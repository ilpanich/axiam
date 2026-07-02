---
phase: 22-php-sdk
plan: 05
subsystem: sdk
tags: [php, guzzle, grpc, protoc, authz, dispatcher, fnd-04, extension-guard]

# Dependency graph
requires:
  - phase: 22-php-sdk
    provides: "22-01: Axiam\\Sdk\\Core\\{AxiamException,AuthError,AuthzError,NetworkError,ErrorMapper} — error taxonomy AuthzRestClient/AuthzGrpcClient throw into"
  - phase: 22-php-sdk
    provides: "22-04: Axiam\\Sdk\\Session — Guzzle CookieJar + HandlerStack (AuthMiddleware/RefreshMiddleware) — AuthzRestClient reuses the Session-configured Guzzle client directly"
provides:
  - "Axiam\\Sdk\\Rest\\AuthzRestClient — checkAccess()/can()/batchCheck() over POST /api/v1/authz/check[/batch] (FND-04), wire fields verified byte-exact against authz_check.rs"
  - "Axiam\\Sdk\\Grpc\\AuthzGrpcClient — extends \\Grpc\\BaseStub, hand-implements CheckAccess/BatchCheckAccess via _simpleRequest(), strict-TLS-only channel, Authorization+x-tenant-id metadata"
  - "Axiam\\Sdk\\Grpc\\Gen\\* — protoc-generated (buf unavailable) CheckAccessRequest/Response, BatchCheckAccessRequest/Response message classes + GPBMetadata registrar, namespaced Axiam\\Sdk\\Grpc\\Gen via new PHP-only proto file options"
  - "Axiam\\Sdk\\AuthzDispatcher — transparent REST/gRPC transport selection, extension_loaded('grpc') guard (Pitfall 4 / T-22-16), REST-only fallback proven non-vacuously"
  - "sdks/buf.gen.yaml PHP plugin entry (protocolbuffers/php + grpc/php, out: php/src/Grpc/Gen)"
  - "sdks/php/phpstan.neon.dist + stubs/grpc.stub.php — PHPStan-only Grpc\\BaseStub/Google\\Protobuf\\Internal\\Message signature stubs"
  - "tests/AuthzDispatcherFallbackTest.php (5 tests) — SC#3 proof, non-vacuous (verified RED when the guard is removed)"
  - "examples/grpc_checkaccess.php — documents the Swoole/RoadRunner/long-running-CLI requirement prominently"
affects: [22-06, 22-07, 22-08, 22-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "extension_loaded('grpc') guard: AuthzDispatcher is the ONLY call site referencing AuthzGrpcClient by name in the whole SDK, and only inside the guarded branches — the typed property/return-type declarations naming AuthzGrpcClient are safe because PHP resolves class names used only in type declarations lazily (confirmed empirically with a throwaway script: a typed property/return-type naming a nonexistent class does not fatal a class that never assigns/invokes it)"
    - "protoc-generate-then-flatten: protoc's --php_out always nests output under out_dir/<namespace-as-path>/ (confirmed empirically); since the namespace declaration inside each generated file is correct regardless of which directory it physically sits in, generating into a scratch dir and copying (flattening) the .php files directly into the PSR-4 target directory is a safe, standard workaround for the directory-nesting mismatch — no buf CLI required"
    - "PHPStan-only stub files (never autoloaded): stubs/grpc.stub.php declares Grpc\\BaseStub/ChannelCredentials/status constants and Google\\Protobuf\\Internal\\Message purely for PHPStan's reflection layer (referenced via phpstan.neon.dist's stubFiles) — kept outside src/ and outside composer.json's autoload map so it can never be included/executed by the real autoloader"

key-files:
  created:
    - sdks/php/src/Rest/AuthzRestClient.php
    - sdks/php/src/Grpc/AuthzGrpcClient.php
    - sdks/php/src/Grpc/Gen/CheckAccessRequest.php
    - sdks/php/src/Grpc/Gen/CheckAccessResponse.php
    - sdks/php/src/Grpc/Gen/BatchCheckAccessRequest.php
    - sdks/php/src/Grpc/Gen/BatchCheckAccessResponse.php
    - sdks/php/src/Grpc/Gen/Metadata/Authorization.php
    - sdks/php/src/AuthzDispatcher.php
    - sdks/php/phpstan.neon.dist
    - sdks/php/stubs/grpc.stub.php
    - sdks/php/tests/AuthzDispatcherFallbackTest.php
    - sdks/php/examples/grpc_checkaccess.php
  modified:
    - sdks/buf.gen.yaml
    - sdks/php/composer.json
    - proto/axiam/v1/authorization.proto

key-decisions:
  - "Added php_namespace/php_metadata_namespace FileOptions to proto/axiam/v1/authorization.proto (a shared cross-SDK proto file) rather than leaving it untouched — these are standard, PHP-codegen-only protobuf FileOptions fields (not a custom extension), confirmed empirically to have zero effect on Rust codegen (`cargo check -p axiam-api-grpc` still compiles cleanly, recompiling the proto via tonic_prost_build's build.rs) — without them, protoc's --php_out would derive the namespace Axiam\\V1 from the proto package, which does not match this SDK's PSR-4 root Axiam\\Sdk\\ -> src/"
  - "protoc (3.21.12, present in this sandbox) natively supports --php_out message codegen, but no grpc_php_plugin was available to generate a *ServiceClient stub — rather than leaving the service-client class entirely hand-authored-and-undocumented, AuthzGrpcClient.php hand-implements CheckAccess/BatchCheckAccess directly via the same Grpc\\BaseStub::_simpleRequest() primitive grpc_php_plugin's own generated code uses internally; this was already the plan's own architecture (Pattern 2's AuthzDispatcher constructs AuthzGrpcClient directly, not a wrapped generated *Client), so no deviation from plan was needed here"
  - "AuthzDispatcher's constructor takes tokenAccessor/subjectIdAccessor as caller-supplied closures rather than depending on Session directly — avoids an import cycle (Session lives in the Axiam\\Sdk root namespace, AuthzDispatcher also does) and matches the Go/Python siblings' RefreshFunc/token_fn decoupling pattern (22-RESEARCH.md); full wiring of these closures to the real Session instance is AxiamClient's job (22-06, per 22-04-SUMMARY's own 'Next Phase Readiness' note)"
  - "google/protobuf added to composer.json's suggest block (not require-dev) alongside grpc/grpc — the Grpc\\Gen\\* message classes extend Google\\Protobuf\\Internal\\Message, but that runtime is only ever loaded behind the same extension_loaded('grpc') guard as the gRPC extension itself, so it follows the identical D-03 never-hard-required posture"

patterns-established:
  - "Generate-to-scratch-then-flatten for protoc PHP output: documented as the reproducible regeneration command in sdks/buf.gen.yaml's PHP entry's own comment block, for the next maintainer/CI run that has buf available"

requirements-completed: [PHP-01]

coverage:
  - id: D1
    description: "AuthzRestClient::checkAccess()/can()/batchCheck() call POST /api/v1/authz/check[/batch] with wire field names (action, resource_id, scope) matching crates/axiam-api-rest/src/handlers/authz_check.rs exactly, reusing the caller-supplied Guzzle client (Session's auth/tenant/CSRF/refresh middleware apply automatically)"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "uncommitted MockHandler smoke script (scratchpad) — confirmed exact wire body shape for checkAccess/can/batchCheck and 403 -> AuthzError; full existing suite green (23/23) after adding the file"
        status: pass
      - kind: other
        ref: "grep -n 'authz/check' src/Rest/AuthzRestClient.php (both /api/v1/authz/check and /batch present)"
        status: pass
    human_judgment: false
  - id: D2
    description: "AuthzGrpcClient extends \\Grpc\\BaseStub, referenced ONLY inside AuthzDispatcher's extension_loaded('grpc')-guarded branches (Pitfall 4 / T-22-16); a REST-only runtime (this sandbox — no ext-grpc) never autoloads it, never fatals"
    requirement: "PHP-01"
    verification:
      - kind: unit
        ref: "tests/AuthzDispatcherFallbackTest.php (5 tests, 12 assertions) — checkAccess/can/batchCheck over REST with grpc absent, explicit restOnly=true, and class_exists(AuthzGrpcClient::class, false) === false"
        status: pass
      - kind: other
        ref: "manual RED/GREEN proof: forced both guarded branches to `if (true)`, re-ran the suite — genuinely failed with 'Error: Class \"Grpc\\BaseStub\" not found' (and a second failure surfacing 'Google\\Protobuf\\Internal\\Message not found' on the batch path); restored and re-verified green (5/5, full suite 28/28)"
        status: pass
      - kind: other
        ref: "grep -rn 'Grpc\\\\BaseStub|AuthzGrpcClient' src --include=*.php | grep -v 'src/Grpc/' -> all matches confined to src/AuthzDispatcher.php, either doc comments or the guarded branches/lazy-typed declarations"
        status: pass
    human_judgment: false
  - id: D3
    description: "sdks/buf.gen.yaml carries a PHP plugin entry (protocolbuffers/php + grpc/php, out: php/src/Grpc/Gen); committed stubs exist under sdks/php/src/Grpc/Gen/ generated via protoc (buf CLI unavailable, consistent with every prior SDK phase)"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "cd sdks && grep -A2 'protocolbuffers/php' buf.gen.yaml | grep 'php/src/Grpc/Gen' (matches)"
        status: pass
      - kind: other
        ref: "ls sdks/php/src/Grpc/Gen/*.php sdks/php/src/Grpc/Gen/Metadata/*.php (5 files present); php -l on all 5 (no syntax errors)"
        status: pass
    human_judgment: false
  - id: D4
    description: "grpc/grpc and google/protobuf remain suggest-only in composer.json — never a runtime require; no insecure gRPC channel construction anywhere in src/"
    requirement: "PHP-01"
    verification:
      - kind: other
        ref: "grep -n grpc composer.json (both entries only under 'suggest'); grep -rn 'verify.*=>.*false|insecure|InsecureSkipVerify|createInsecure' src/ (only a negative-sense doc-comment match, no real pattern)"
        status: pass
    human_judgment: false
  - id: D5
    description: "PHPStan level 6 static analysis clean on src/Grpc + src/AuthzDispatcher.php + src/Rest/AuthzRestClient.php, with phpstan.neon.dist's Grpc\\BaseStub/Google\\Protobuf\\Internal\\Message stub"
    verification: []
    human_judgment: true
    rationale: "PHPStan could not be installed in this sandbox — identical root cause documented in every prior 22-* SUMMARY (composer's dist download for phpstan/phpstan returns 'Could not authenticate against github.com' via this sandbox's egress proxy; the package ships no Packagist 'source' field for a git-clone fallback). Re-attempted via `composer install` (phpstan/phpstan is already declared in composer.json/composer.lock from the original scaffold) — failed identically. composer.json/composer.lock were left untouched (confirmed via git status). phpstan.neon.dist + stubs/grpc.stub.php were authored to close this gap once CI (sdk-ci-php.yml, unrestricted GitHub access) can install phpstan/phpstan; code was manually reviewed for level-6 compliance (full type declarations, declare(strict_types=1) everywhere, generated src/Grpc/Gen/* excluded from analysis as machine output)."

# Metrics
duration: 40min
completed: 2026-07-02
status: complete
---

# Phase 22 Plan 05: AuthzRestClient + Guarded gRPC AuthzDispatcher Summary

**REST-default authz (`AuthzRestClient` over `POST /api/v1/authz/check[/batch]`, FND-04) with a transparently-upgrading, `extension_loaded('grpc')`-guarded `AuthzDispatcher`/`AuthzGrpcClient` gRPC opt-in — proven never to fatal on this sandbox's actual REST-only runtime via a non-vacuous fallback test, backed by protoc-generated (buf unavailable) committed gRPC message stubs and a new `buf.gen.yaml` PHP plugin entry.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-07-02
- **Tasks:** 3
- **Files modified:** 15 (3 modified, 12 created)

## Accomplishments

- `Axiam\Sdk\Rest\AuthzRestClient::checkAccess()`/`can()`/`batchCheck()` call `POST /api/v1/authz/check[/batch]` with wire fields (`action`, `resource_id`, optional `scope`) verified byte-exact against `crates/axiam-api-rest/src/handlers/authz_check.rs` via an uncommitted MockHandler smoke script; reuses the caller-supplied Guzzle client directly so `Session`'s auth/tenant/CSRF header injection and single-flight refresh-on-401 (D-06) apply automatically — this class never re-implements any of that.
- `proto/axiam/v1/authorization.proto` gained PHP-only `php_namespace`/`php_metadata_namespace` file options (standard protobuf FileOptions, not a custom extension) so generated PHP classes land under `Axiam\Sdk\Grpc\Gen` matching this SDK's PSR-4 root — confirmed to have zero effect on Rust codegen (`cargo check -p axiam-api-grpc` recompiles the proto via `build.rs`/`tonic_prost_build` and still builds cleanly).
- `sdks/buf.gen.yaml` gained a PHP plugin entry (`buf.build/protocolbuffers/php` + `buf.build/grpc/php`, `out: php/src/Grpc/Gen`) mirroring the Go/Python two-plugin idiom. `buf` itself is unavailable in this sandbox (consistent with every prior SDK phase); the four message classes (`CheckAccessRequest`/`Response`, `BatchCheckAccessRequest`/`Response`) plus the `GPBMetadata` registrar were generated via a local `protoc --php_out` invocation (protoc 3.21.12 ships native PHP message codegen) into a scratch directory, then flattened directly into `sdks/php/src/Grpc/Gen/` — protoc always nests output under `<out_dir>/<namespace-as-path>/`, but the namespace declaration baked into each generated file is correct regardless of which directory it physically sits in, so flattening is safe. No `grpc_php_plugin` was available to generate a `*ServiceClient` stub.
- `Axiam\Sdk\Grpc\AuthzGrpcClient extends \Grpc\BaseStub`, hand-implementing `CheckAccess`/`BatchCheckAccess` directly via `_simpleRequest()` — the same primitive `grpc_php_plugin`'s own generated client classes use internally, exactly matching the plan's own Pattern 2 architecture (`AuthzDispatcher` constructs `AuthzGrpcClient` directly, never a wrapped generated `*Client`). Injects `authorization`/`x-tenant-id` metadata on every RPC (§5); channel credentials always go through `\Grpc\ChannelCredentials::createSsl()` (§6/D-12 — no insecure-channel path exists); never re-implements refresh — takes a `tokenAccessor` closure read live on every call (D-06).
- `Axiam\Sdk\AuthzDispatcher` ports `22-RESEARCH.md` Pattern 2 verbatim: `checkAccess`/`can`/`batchCheck` branch on `!$this->restOnly && extension_loaded('grpc')`, referencing `AuthzGrpcClient` ONLY inside that guard (lazy `??=` construction) — Pitfall 4 / T-22-16. Otherwise delegates to `AuthzRestClient` (D-03: authz ALWAYS works, transparent fallback, not a degraded mode).
- `tests/AuthzDispatcherFallbackTest.php` (5 tests, 12 assertions): proves the REST-only fallback for all three public methods with `extension_loaded('grpc')` genuinely `false` in this sandbox, the explicit `restOnly: true` opt-out, and `class_exists(AuthzGrpcClient::class, false) === false` after the REST round-trips — i.e. the class was never autoloaded. **Non-vacuousness proven manually:** temporarily forced both guarded branches to `if (true)` and re-ran the suite — it genuinely failed RED with `Error: Class "Grpc\BaseStub" not found` (and, on the batch path, a second real failure `Class "Google\Protobuf\Internal\Message" not found`); restored the guard and re-verified GREEN (5/5, full suite 28/28).
- `sdks/php/phpstan.neon.dist` (level 6, excludes machine-generated `src/Grpc/Gen/*`) + `sdks/php/stubs/grpc.stub.php`: PHPStan-only (never autoloaded/executed — kept outside `src/` and outside `composer.json`'s autoload map) signature stubs for `Grpc\BaseStub`/`Grpc\ChannelCredentials`/gRPC status constants and `Google\Protobuf\Internal\Message`, so static analysis can type-check `AuthzGrpcClient`/`AuthzDispatcher` without `ext-grpc`/`grpc/grpc`/`google/protobuf` actually installed.
- `examples/grpc_checkaccess.php`: a runnable CLI example whose header comment prominently documents the Swoole/RoadRunner/long-running-CLI requirement (SC#3) and the automatic REST fallback; actually run in this sandbox — it correctly selects the REST transport (extension absent) and fails only at the expected point (no live AXIAM server reachable at `localhost:8443`), never at a missing-extension fatal.

## Task Commits

Each task was committed atomically:

1. **Task 1: buf.gen.yaml PHP entry + generate/commit gRPC stubs** - `a6070fa` (feat)
2. **Task 2: AuthzRestClient (FND-04) + REST-default dispatch path** - `4ed05c8` (feat)
3. **Task 3: AuthzGrpcClient + AuthzDispatcher guard + PHPStan stub + fallback test + example** - `e160bb2` (feat)

_Note: Task 3 is `tdd="true"`. The fallback test and implementation were authored together and verified via a manual RED/GREEN proof (forcing the guarded branches to `if (true)`, confirming the suite genuinely fails, then restoring and re-verifying green) rather than a separate `test(...)`-then-`feat(...)` commit pair — the same "manual RED/GREEN proof, single commit" precedent 22-01/22-04 used for their `tdd="true"` tasks, documented in full in this task's commit message and the coverage entries above._

## Files Created/Modified

- `sdks/php/src/Rest/AuthzRestClient.php` - `checkAccess`/`can`/`batchCheck` over REST (FND-04)
- `sdks/php/src/Grpc/AuthzGrpcClient.php` - `extends \Grpc\BaseStub`, guarded gRPC transport
- `sdks/php/src/Grpc/Gen/{CheckAccessRequest,CheckAccessResponse,BatchCheckAccessRequest,BatchCheckAccessResponse}.php` - protoc-generated message stubs
- `sdks/php/src/Grpc/Gen/Metadata/Authorization.php` - protoc-generated `GPBMetadata` registrar
- `sdks/php/src/AuthzDispatcher.php` - transparent REST/gRPC transport selection, `extension_loaded('grpc')` guard
- `sdks/php/phpstan.neon.dist` - level 6, excludes generated `Grpc/Gen`, references the stub file
- `sdks/php/stubs/grpc.stub.php` - PHPStan-only `Grpc\BaseStub`/`Google\Protobuf\Internal\Message` signature stubs
- `sdks/php/tests/AuthzDispatcherFallbackTest.php` - SC#3 fallback proof, non-vacuous
- `sdks/php/examples/grpc_checkaccess.php` - runnable example, documents the long-running-runtime requirement
- `sdks/buf.gen.yaml` - PHP plugin entry (protocolbuffers/php + grpc/php)
- `sdks/php/composer.json` - `google/protobuf` added to `suggest` (alongside existing `ext-grpc`/`grpc/grpc`)
- `proto/axiam/v1/authorization.proto` - PHP-only `php_namespace`/`php_metadata_namespace` file options

## Decisions Made

- Added `php_namespace`/`php_metadata_namespace` to the shared `proto/axiam/v1/authorization.proto` rather than leaving PHP with the package-derived default namespace — these are standard protobuf FileOptions (part of `descriptor.proto`), ignored by every non-PHP codegen; confirmed empirically via `cargo check -p axiam-api-grpc` (which recompiles this exact proto through `tonic_prost_build` in `build.rs`) that the Rust build is byte-for-byte unaffected.
- protoc's `--php_out` always nests generated files under `<out_dir>/<namespace-as-path>/` (confirmed empirically: `Axiam\Sdk\Grpc\Gen` namespace produces `<out>/Axiam/Sdk/Grpc/Gen/*.php`), which cannot be made to directly equal the desired `sdks/php/src/Grpc/Gen/` path via `out_dir` manipulation alone (the namespace path and the desired path share a `Grpc/Gen` suffix but differ in prefix, so no simple relative-path trick collapses them). Resolved by generating into a scratch directory and copying (flattening) the four message files + the `GPBMetadata` file directly into `sdks/php/src/Grpc/Gen/` — each file's own `namespace` declaration is what PHP's autoloader actually cares about, not the directory protoc happened to write it to.
- `AuthzGrpcClient` hand-implements `CheckAccess`/`BatchCheckAccess` via `Grpc\BaseStub::_simpleRequest()` directly (no `grpc_php_plugin`-generated `*ServiceClient` wrapper) — this was already the plan's intended architecture (Pattern 2 constructs `AuthzGrpcClient` directly), not a workaround improvised due to the missing plugin.
- `AuthzDispatcher`'s gRPC-path parameters (`tokenAccessor`, `subjectIdAccessor`, `tenantId`, `grpcTarget`, `customCaPem`) are plain caller-supplied closures/strings rather than a `Session` dependency — avoids an import cycle and matches the Go/Python siblings' `RefreshFunc`/`token_fn` decoupling pattern from `22-RESEARCH.md`; full wiring to a real `Session` instance is `AxiamClient`'s responsibility in 22-06 (per 22-04-SUMMARY's own "Next Phase Readiness" note).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Added gRPC status -> error-type mapping inside AuthzGrpcClient**
- **Found during:** Task 3 (writing `AuthzGrpcClient`)
- **Issue:** The plan's `<action>` describes metadata injection and TLS but does not explicitly call out gRPC status code -> SDK error type translation; without it, every gRPC failure would surface as an unhandled/untyped exception, contradicting CONTRACT.md §2's gRPC Status Code -> Error Type table (`UNAUTHENTICATED` -> `AuthError`, `PERMISSION_DENIED` -> `AuthzError`, else -> `NetworkError`).
- **Fix:** Added a private `mapStatus()` method inside `AuthzGrpcClient` (kept local to the file rather than extending the shared `Core\ErrorMapper`, since that class's public contract is HTTP-status-shaped and modifying it was out of this task's file scope) implementing the CONTRACT.md §2 gRPC mapping using the existing `AuthError`/`AuthzError`/`NetworkError` classes.
- **Files modified:** `sdks/php/src/Grpc/AuthzGrpcClient.php`
- **Verification:** `php -l` clean; logic follows the same three-class taxonomy `ErrorMapper::fromStatus()` already establishes for REST.
- **Committed in:** `e160bb2` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 missing-critical-functionality addition)
**Impact on plan:** Necessary for `AuthzGrpcClient` to conform to the already-locked CONTRACT.md §2 error taxonomy; no architectural change, no scope creep beyond the file the plan already listed.

## Issues Encountered

- **PHPStan level-6 verification could not run in this sandbox** — identical root cause documented in every prior 22-* SUMMARY (`phpstan/phpstan`'s dist download fails GitHub authentication via this sandbox's egress proxy; the package ships no Packagist `source` field for a git-clone fallback). Re-attempted via `composer install` (phpstan/phpstan is already declared in `composer.json`/`composer.lock` from the original scaffold, so no `composer.json` mutation was needed) — failed identically with `Could not authenticate against github.com`. `composer.json`/`composer.lock` confirmed unchanged via `git status`. `phpstan.neon.dist` + `stubs/grpc.stub.php` were authored so this deferred check can pass cleanly once `sdk-ci-php.yml` (unrestricted GitHub Actions infrastructure) runs it.
- All other verification commands ran successfully — see the `coverage` block above and "Verification" notes throughout "Accomplishments".

## Known Stubs

- `sdks/php/src/Grpc/Gen/*.php` are genuine machine-generated protobuf message classes (not placeholder/mock stand-ins) — "stub" here means protoc-generated code, not an incomplete/TODO implementation. They are fully functional as long as `google/protobuf`'s runtime classes are present (guarded, D-03).
- `sdks/php/stubs/grpc.stub.php` is a PHPStan-only signature file (documented at length in its own header) — never autoloaded/executed in production; not a functional code stub.
- No functional/placeholder stubs exist in the shipped SDK code itself.

## Threat Flags

None — this plan's new surface (`POST /api/v1/authz/check[/batch]` client calls, the gRPC `CheckAccess`/`BatchCheckAccess` client calls) is exactly the surface the plan's own `<threat_model>` (T-22-16 through T-22-19) already covers; no new endpoint/auth-path/schema surface was introduced beyond what was planned and mitigated. T-22-16 (unguarded gRPC reference) was empirically disproven via the manual RED/GREEN proof; T-22-17 (TLS) confirmed via grep (no insecure-channel pattern present); T-22-18 (client-side authz decision) — the dispatcher never caches or overrides a decision, both transports simply relay the server's `allowed`/`deny_reason`; T-22-19 (gRPC metadata spoofing) — `authorization`/`x-tenant-id` are injected from the caller-supplied `tokenAccessor`/`tenantId`, sourced from the shared `Session` in the eventual `AxiamClient` wiring (22-06).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `Axiam\Sdk\{Rest\AuthzRestClient, Grpc\AuthzGrpcClient, AuthzDispatcher}` are ready for 22-06 (`AxiamClient` facade), which is expected to: (1) construct `AuthzRestClient` with the same Guzzle client `Session` wires with `AuthMiddleware`/`RefreshMiddleware`, (2) construct `AuthzDispatcher` with `tokenAccessor: fn() => $session->accessToken()` and a `subjectIdAccessor` sourced from decoded JWT claims (via `JwksVerifier` or a login-response DTO), and (3) expose `checkAccess`/`can`/`batchCheck` on the public `AxiamClient` surface by delegating to `AuthzDispatcher`.
- `sdks/php/src/Grpc/Gen/*` and the `buf.gen.yaml` PHP entry are ready for a real `buf generate` run once `buf` is available in CI — the entry's own comment documents the exact fallback `protoc --php_out` command used here for reproducibility.
- **Follow-up for a maintainer or the `sdk-ci-php.yml` plan:** run `vendor/bin/phpstan analyse` (config already points at `src`, excludes `src/Grpc/Gen`, and loads `stubs/grpc.stub.php`) on a machine/CI runner with unrestricted GitHub access to close the one deferred acceptance criterion from this plan (same deferral pattern as every prior 22-* plan).

---
*Phase: 22-php-sdk*
*Completed: 2026-07-02*

## Self-Check: PASSED

All 16 created/modified files confirmed present on disk; all 3 task commit hashes
(`a6070fa`, `4ed05c8`, `e160bb2`) confirmed present in `git log --oneline --all`.
