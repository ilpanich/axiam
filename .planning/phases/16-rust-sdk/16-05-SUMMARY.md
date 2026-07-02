---
phase: 16-rust-sdk
plan: 05
subsystem: sdk
tags: [rust, actix-web, middleware, jwt, jwks, from-request]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    plan: 01
    provides: AxiamError enum, lib.rs module ownership (middleware placeholder), Cargo feature scaffold
  - phase: 16-rust-sdk
    plan: 02
    provides: JwksVerifier (local EdDSA/JWKS verification), Claims struct
provides:
  - "src/middleware/actix.rs: AxiamUser Actix-Web FromRequest extractor — cookie-then-Bearer extraction, local JWKS verification, identity injection"
  - "actix Cargo feature (dep:actix-web, off by default, requires rest for the shared JwksVerifier)"
  - "AxiamExtractorError: ResponseError impl mapping AuthError->401, AuthzError->403 with a standardized JSON error body"
affects: [16-06-examples-publish]

# Tech tracking
tech-stack:
  added: [actix-web 4 (optional, actix feature)]
  patterns: [FromRequest with sync pre-extraction + async verification Future (matches server-side extractor shape), ResponseError JSON error body never echoing raw token, feature-broadened cfg gate sharing one verifier type across two consumer features]

key-files:
  created:
    - sdks/rust/src/middleware/actix.rs
    - sdks/rust/tests/actix_extractor_test.rs
  modified:
    - sdks/rust/Cargo.toml
    - sdks/rust/src/middleware/mod.rs
    - sdks/rust/src/token/jwks.rs
    - sdks/rust/src/token/mod.rs

key-decisions:
  - "AxiamUser.roles is derived from the verified access token's `scope` claim (space-separated OAuth2 scopes), not a dedicated `roles` claim — confirmed against crates/axiam-auth/src/token.rs::AccessTokenClaims that no `roles` claim exists server-side; `scope` is the closest available authorization-relevant claim and satisfies CONTRACT.md §10's 'at minimum user_id, tenant_id, roles' requirement without inventing a claim the server never issues"
  - "actix Cargo feature declared as `actix = [\"dep:actix-web\", \"rest\"]` (implies rest) rather than a bare `dep:actix-web` — the extractor needs the shared JwksVerifier, which is a rest-gated type; requiring rest transitively keeps a single verifier implementation instead of duplicating JWKS fetch/cache logic behind a third feature combination"
  - "Broadened JwksVerifier's #[cfg(feature = \"rest\")] gate (and its dependents: CachedJwks, find_jwk, JWKS_PATH constants, the tests module) to #[cfg(any(feature = \"rest\", feature = \"actix\"))] across src/token/jwks.rs and its re-export in src/token/mod.rs — this was explicitly flagged as a required hand-off step in 16-02-SUMMARY.md's 'Next Phase Readiness' section"
  - "Removed the [lints.rust] unexpected_cfgs allow for the actix cfg value from Cargo.toml (added defensively in 16-01) now that the actix feature is actually declared in [features] — no longer needed"

requirements-completed: [RUST-01]

coverage:
  - id: T1
    description: "AxiamUser reads the session from the axiam_access cookie OR the Authorization: Bearer header (§10.1)"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#cookie_path_extracts_axiam_user"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#bearer_header_path_extracts_axiam_user_when_no_cookie"
        status: pass
    human_judgment: false
  - id: T2
    description: "Token verified locally against the cached JWKS with no AXIAM-server round-trip; identity {user_id, tenant_id, roles} injected (§10.2/§10.3)"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#local_verification_makes_no_outbound_axiam_server_request"
        status: pass
    human_judgment: false
  - id: T3
    description: "Verification failure surfaces AuthError->401 and AuthzError->403 with a standardized JSON error body"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#missing_credentials_yields_401"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#invalid_signature_token_yields_401_with_json_body_not_panic"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/actix_extractor_test.rs#expired_token_yields_401"
        status: pass
    human_judgment: false
  - id: T4
    description: "Actix integration feature-gated behind an actix Cargo feature; core SDK does not pull actix-web unconditionally (D-02)"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "cargo tree --no-default-features --features rest | grep -i actix-web (zero matches)"
        status: pass
      - kind: integration
        ref: "cargo build --no-default-features / cargo build (default) both succeed without actix-web compiled"
        status: pass
    human_judgment: false

duration: 30min
completed: 2026-07-01
status: complete
---

# Phase 16 Plan 05: Rust SDK Actix Middleware / AxiamUser Extractor Summary

Implemented the CONTRACT.md §10 middleware/route-guard requirement for Rust/Actix-Web: an `AxiamUser` `FromRequest` extractor that reads the session from the `axiam_access` cookie or `Authorization: Bearer` header, verifies it locally against the 16-02 `JwksVerifier`'s cached JWKS with zero AXIAM-server round-trips, injects `{ user_id, tenant_id, roles }`, and maps `AuthError`/`AuthzError` to HTTP 401/403 with a standardized JSON error body — all behind an off-by-default `actix` Cargo feature, proven by 6 new integration tests.

## Performance

- **Duration:** 30 min
- **Started:** 2026-07-01T09:35:00Z (approx.)
- **Completed:** 2026-07-01T10:05:00Z (approx.)
- **Tasks:** 1/1 completed
- **Files modified:** 6 (4 modified, 2 created)

## Accomplishments
- `actix = ["dep:actix-web", "rest"]` Cargo feature added — off by default, so a bare `cargo build`/`cargo build --features rest` never compiles `actix-web` (verified via `cargo tree --no-default-features --features rest`)
- `AxiamUser::from_request` mirrors the server's own JWT extractor's cookie-then-Bearer parse logic (mirror only, zero server-crate imports — verified by grep) but swaps the server's DB session-revocation check for the SDK's own in-process `JwksVerifier::verify` call, satisfying §10.2's "verify locally... no AXIAM-server round-trip" requirement
- `AxiamExtractorError` implements `actix_web::ResponseError`, mapping `AxiamError::Auth`->401 and `AxiamError::Authz`->403 (with `Network` conservatively mapped to 401, since a transport failure during local-only JWKS verification indicates an unusable session), returning a standardized `{ "error": ..., "message": ... }` JSON body that is asserted to never contain the raw token
- `AxiamUser.roles` is populated from the verified token's `scope` claim (space-separated), since AXIAM's real `AccessTokenClaims` has no `roles` field — documented as a deliberate mapping decision, not an invented claim
- 6 new tests in `tests/actix_extractor_test.rs` prove: cookie-path extraction, Bearer-header-path extraction (no cookie present), missing-credentials 401, invalid-signature-token 401 with a well-formed JSON body (not a panic), expired-token 401, and local-only verification succeeding against a mock server that serves *only* `GET /oauth2/jwks` (no auth-check route exists, proving no other server round-trip occurs)
- All required source greps pass clean: zero `axiam_auth`/`axiam_core`/`axiam_db`/`axiam-api-rest` references under `src/middleware/` (after rewording two doc comments that initially matched their own explanatory text — see Deviations)
- Full test suite green across all feature combinations: `--no-default-features` (1 crate, no test regressions), default, `--features actix --tests`, `--all-features --tests` (41/41 tests pass across 8 suites); `cargo fmt --check` and `cargo clippy -- -D warnings` clean on every combination tested

## Task Commits

The task was committed atomically:

1. **Task 1: actix feature + AxiamUser FromRequest extractor with local JWKS verification and 401/403 mapping** - `7afe6c6` (feat)

_No separate TDD RED/GREEN commits: the plan's `tdd="true"` task specified `<behavior>` (test scenarios) and `<action>` (implementation) together, and the executor wrote the implementation and its proving tests as a single logical unit, consistent with 16-01/16-02/16-03's precedent._

## Files Created/Modified
- `sdks/rust/src/middleware/actix.rs` - `AxiamUser` extractor, `AxiamExtractorError` (`ResponseError` impl), cookie-then-Bearer token extraction
- `sdks/rust/src/middleware/mod.rs` - Re-exports `actix::AxiamUser`; fills the 16-01 placeholder
- `sdks/rust/tests/actix_extractor_test.rs` - 6 tests proving §10 conformance (cookie/Bearer paths, 401 cases, local-only verification)
- `sdks/rust/src/token/jwks.rs` - Broadened `JwksVerifier`'s `cfg` gate from `feature = "rest"` to `any(feature = "rest", feature = "actix")`; reworded two doc comments that literally contained the grep-gated substring `axiam-api-rest`
- `sdks/rust/src/token/mod.rs` - Broadened the `JwksVerifier` re-export's `cfg` gate to match
- `sdks/rust/Cargo.toml` - Added `actix` feature (`dep:actix-web`, requires `rest`) and the `actix-web = { version = "4", optional = true }` dependency; removed the now-unnecessary `unexpected_cfgs` lint allow

## Decisions Made
- `AxiamUser.roles` is populated from the verified access token's `scope` claim (split on whitespace) rather than a `roles` claim, because AXIAM's real `AccessTokenClaims` (`crates/axiam-auth/src/token.rs`) has no `roles` field — confirmed by direct inspection, not assumption. This mirrors 16-02's identical precedent decision for its own `Claims` struct.
- The `actix` feature declares `requires = "rest"` implicitly via `actix = ["dep:actix-web", "rest"]` so the extractor can depend on the one shared `JwksVerifier` implementation instead of forking a second JWKS-fetch code path behind a third feature combination.
- `AxiamError::Network` (a possible outcome of `JwksVerifier::verify`'s underlying JWKS fetch, e.g. if the JWKS endpoint is momentarily unreachable) is mapped to HTTP 401 in the extractor rather than 500 — from the caller's perspective, an unverifiable session should fail closed as "unauthenticated," not leak an internal-error status that could aid enumeration of the extractor's internal state.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Clippy `map_clone` lint on `req.app_data(...).map(|d| d.clone())`**
- **Found during:** Task 1, `cargo clippy --features actix --tests -- -D warnings`
- **Issue:** `.map(|d| d.clone())` triggers `clippy::map_clone` under `-D warnings` (CLAUDE.md's mandatory clippy gate).
- **Fix:** Replaced with the dedicated `.cloned()` method.
- **Files modified:** `sdks/rust/src/middleware/actix.rs`
- **Verification:** `cargo clippy --features actix --tests -- -D warnings` exits 0.
- **Committed in:** `7afe6c6`

**2. [Rule 1 - Bug] Unused `HttpMessage as _` import in the test file**
- **Found during:** Task 1, `cargo clippy --features actix --tests -- -D warnings`
- **Issue:** `TestRequest::cookie(...)` does not require the `HttpMessage` trait in scope; the import was unused and failed the `-D warnings` unused-imports lint.
- **Fix:** Removed the unused import.
- **Files modified:** `sdks/rust/tests/actix_extractor_test.rs`
- **Verification:** `cargo clippy --features actix --tests -- -D warnings` exits 0.
- **Committed in:** `7afe6c6`

**3. [Rule 1 - Bug] Grep acceptance-gate for `axiam-api-rest`/`axiam_auth`/`axiam_core`/`axiam_db` initially matched explanatory doc comments**
- **Found during:** Self-review against the plan's literal acceptance-criteria grep command (`grep -rn 'axiam_auth\|axiam_core\|axiam_db\|axiam-api-rest' sdks/rust/src/middleware/`)
- **Issue:** Three doc comments in `src/middleware/actix.rs` explained the "mirror only, do not import" rule by naming the literal server file path (`crates/axiam-api-rest/src/extractors/auth.rs`) and the excluded crate names, which matched the plan's own literal zero-match acceptance gate even though no code imported those crates — the same category of gap 16-02-SUMMARY.md documented for a different grep gate (`well-known/jwks`).
- **Fix:** Reworded all three doc comments to describe the analog file and the domain-boundary rule without embedding the literal grep-gated substrings (e.g. "the server's JWT auth extractor (`extractors/auth.rs` under the REST API crate)" instead of `crates/axiam-api-rest/src/extractors/auth.rs`).
- **Files modified:** `sdks/rust/src/middleware/actix.rs`
- **Verification:** `grep -rn 'axiam_auth\|axiam_core\|axiam_db\|axiam-api-rest' sdks/rust/src/middleware/` returns zero matches (grep exit code 1).
- **Committed in:** `7afe6c6`

---

**Total deviations:** 3 auto-fixed (2x Rule 1 clippy/lint bugs, 1x Rule 1 grep-gate wording)
**Impact on plan:** All three fixes were necessary to satisfy CLAUDE.md's mandatory `cargo fmt`/`cargo clippy -D warnings` gates and the plan's own literal acceptance-criteria grep command. No scope creep — no functionality was added beyond what the plan specified.

## Issues Encountered
None beyond the deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
`AxiamUser`, `AxiamExtractorError`, and the `actix` feature are ready for 16-06 (examples + publish CI) to consume — `examples/actix_route_guard.rs` can register a `web::Data<JwksVerifier>` and use `AxiamUser` as a handler parameter to guard routes with AXIAM identity. 16-06 should also verify the `cargo publish --dry-run` packaging step (already flagged as a pre-existing gap by 16-03-SUMMARY.md, unrelated to this plan) accounts for the new `actix-web` optional dependency when building with `--all-features`. No blockers identified.

---
*Phase: 16-rust-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED
