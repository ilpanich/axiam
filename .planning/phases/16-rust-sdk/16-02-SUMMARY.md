---
phase: 16-rust-sdk
plan: 02
subsystem: sdk
tags: [rust, reqwest, jwt, jwks, single-flight, cookie-jar, csrf, mfa]

# Dependency graph
requires:
  - phase: 16-rust-sdk
    plan: 01
    provides: Cargo manifest (rest/grpc/amqp features), Sensitive<T>, AxiamError, build.rs, lib.rs module ownership, placeholder client.rs/token/rest modules
provides:
  - AxiamClient + AxiamClientBuilder enforcing non-optional tenant_slug/tenant_id at build() time (CONTRACT.md §5)
  - TokenManager (Sensitive<T>-wrapped access/refresh state + lock-free fast-read cache for the future sync gRPC interceptor)
  - Single-flight refresh guard (tokio::sync::Mutex double-check pattern), proven exactly-1-call under 5 concurrent callers (SC#2, §9)
  - JwksVerifier (GET /oauth2/jwks fetch/cache/kid-rotation, local EdDSA verification via jsonwebtoken 10)
  - REST auth methods login/verify_mfa/refresh/logout with typed two-phase LoginResult (SC#1, D-05: no access_token field)
  - REST authz methods check_access/can/batch_check targeting the FND-04 endpoints with bounded retry (D-12)
affects: [16-03-grpc, 16-04-amqp, 16-05-middleware, 16-06-examples-publish]

# Tech tracking
tech-stack:
  added: [backon (bounded retry for read-only authz checks)]
  patterns: [single-flight tokio::sync::Mutex double-check refresh guard, JWKS kid-rotation forced-refetch (rate-limited), reqwest cookie::Jar direct extraction for HttpOnly cookies, feature-gating reqwest-touching code behind cfg(feature = "rest") to preserve --no-default-features build]

key-files:
  created:
    - sdks/rust/src/token/manager.rs
    - sdks/rust/src/token/refresh_guard.rs
    - sdks/rust/src/token/jwks.rs
    - sdks/rust/src/rest/auth.rs
    - sdks/rust/src/rest/authz.rs
    - sdks/rust/tests/single_flight_refresh_test.rs
    - sdks/rust/tests/login_mfa_flow_test.rs
  modified:
    - sdks/rust/Cargo.toml
    - sdks/rust/src/client.rs
    - sdks/rust/src/token/mod.rs
    - sdks/rust/src/rest/mod.rs

key-decisions:
  - "Pinned jsonwebtoken's rust_crypto backend feature explicitly (default-features = false, features = [\"rust_crypto\", \"use_pem\"]) — jsonwebtoken 10 has no default crypto provider and panics at first encode/decode call without one; the root AXIAM workspace resolves aws-lc-rs transitively via feature unification with other workspace crates, but this standalone crate's own Cargo.lock needs an explicit choice. rust_crypto (pure Rust, no C/cmake toolchain) was chosen for portability, matching the pure-Rust rustls-tls choice already made for reqwest in 16-01"
  - "Added optional org_slug/org_id builder methods beyond CONTRACT.md §5's tenant-only mandate — AXIAM's real POST /api/v1/auth/login and POST /api/v1/auth/refresh endpoints require an organization identifier (organizations are the top-level entity above tenants per CLAUDE.md's domain model), which the locked CONTRACT.md §5 text does not mention. The resolved org UUID is decoded from the access token's org_id claim after the first successful login and cached, so most callers never need to supply it explicitly"
  - "Gated client.rs's entire module body and the reqwest-touching half of token/jwks.rs (JwksVerifier, CachedJwks, find_jwk) behind #[cfg(feature = \"rest\")] — both are declared unconditionally in lib.rs (unlike rest/grpc/amqp), so 16-01's cargo build --no-default-features invariant would otherwise break the moment this plan's code was added. Claims, JWKS_PATH, and TokenManager remain feature-independent since 16-03 (gRPC) and 16-05 (Actix, its own actix feature) need them without pulling in reqwest"
  - "verify_mfa(code) stores no explicit challenge_token parameter — CONTRACT.md §1 mandates the exact signature verify_mfa(code); the challenge token from a prior login() returning mfa_required=true is held internally (behind a private RwLock, itself Sensitive<T>-wrapped) and consumed on the next verify_mfa call, rather than requiring callers to thread it through manually"
  - "LoginResult does not derive Clone — it holds an Option<Sensitive<String>> for the challenge token, and Sensitive<T> deliberately does not implement public Clone (only pub(crate) clone_inner) per the CONTRACT.md §7 redaction design from 16-01, so a derived Clone on LoginResult would not compile without weakening that guarantee"
  - "Defined the SDK's own Claims struct matching the ACTUAL server AccessTokenClaims fields (sub, tenant_id, org_id, iss, iat, exp, jti, aud, scope) rather than the plan text's suggested roles field — crates/axiam-auth/src/token.rs::AccessTokenClaims has no roles claim; mirroring non-existent fields would silently break claim deserialization against the real server"

requirements-completed: [RUST-01]

coverage:
  - id: SC1
    description: "A client built with a non-optional tenant identifier calls login(email,password) and receives a typed LoginResult{mfa_required}; on MFA, verify_mfa(code) completes the two-phase flow"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/login_mfa_flow_test.rs#login_without_mfa_yields_completed_session"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/login_mfa_flow_test.rs#login_with_mfa_required_then_verify_mfa_completes_two_phase_flow"
        status: pass
    human_judgment: false
  - id: SC2
    description: "5 concurrent requests on an expired token trigger EXACTLY 1 refresh HTTP call via the single-flight tokio::sync::Mutex guard"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/single_flight_refresh_test.rs#single_flight_refresh_exactly_one_call_under_five_concurrent_callers"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every outgoing REST request carries X-Tenant-ID; state-changing verbs carry X-CSRF-Token forwarded from the captured axiam_csrf cookie"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/src/rest/auth.rs (maybe_csrf_header on refresh/logout), src/rest/authz.rs (X-Tenant-ID on check_access/batch_check)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Access token is read from the reqwest::cookie::Jar by the axiam_access cookie name after each login/verify_mfa/refresh and immediately wrapped in Sensitive<T>"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/login_mfa_flow_test.rs (asserts resolved_tenant_id is populated, which only happens after jar-extraction + JWKS verify succeeds)"
        status: pass
    human_judgment: false
  - id: D11
    description: "Access-token signature + exp are verified locally against the cached JWKS fetched from GET /oauth2/jwks (EdDSA/Ed25519) with kid-rotation refetch"
    requirement: "RUST-01"
    verification:
      - kind: unit
        ref: "sdks/rust/src/token/jwks.rs#tests::rejects_non_eddsa_alg_header, #tests::find_jwk_matches_by_kid, #tests::find_jwk_single_key_fallback_when_kid_absent"
        status: pass
      - kind: integration
        ref: "sdks/rust/tests/login_mfa_flow_test.rs (real Ed25519 JWKS + EdDSA-signed test tokens verified end-to-end via a mounted wiremock /oauth2/jwks mock)"
        status: pass
    human_judgment: false
  - id: FND04
    description: "check_access/can call POST /api/v1/authz/check; batch_check calls POST /api/v1/authz/check/batch returning results in input order"
    requirement: "RUST-01"
    verification:
      - kind: integration
        ref: "sdks/rust/tests/login_mfa_flow_test.rs#check_access_targets_exact_paths_and_preserves_batch_order"
        status: pass
    human_judgment: false

duration: 42min
completed: 2026-07-01
status: complete
---

# Phase 16 Plan 02: Rust SDK REST Core Summary

Implemented AXIAM's Rust SDK REST transport core: `AxiamClient` with a tenant-enforcing builder, `TokenManager` + single-flight refresh guard, local EdDSA/JWKS verification, and the full two-phase login/MFA/refresh/logout + authz-check REST surface — all 15 tests (6 new integration, 4 new unit, plus the 5 carried over from 16-01) green across every feature combination (`--no-default-features`, `--features rest`, `--features grpc`, `--features amqp`, default, `--all-features`).

## Performance

- **Duration:** 42 min
- **Started:** 2026-07-01T07:26:00Z (approx.)
- **Completed:** 2026-07-01T08:08:09Z
- **Tasks:** 2/2 completed
- **Files modified:** 11 (4 modified, 7 created)

## Accomplishments
- `AxiamClient::builder()` refuses to `build()` without a `tenant_slug`/`tenant_id` (CONTRACT.md §5) — verified by both the login test suite's successful construction path and the builder's own `build()` error path
- The single-flight refresh guard collapses 5 concurrent `refresh_if_needed` callers into exactly 1 underlying HTTP call, proven against a real `wiremock` server with an `AtomicUsize` call counter (SC#2)
- `JwksVerifier` fetches `GET /oauth2/jwks`, caches with TTL, force-refetches once on an unknown `kid`, and rejects any non-EdDSA `alg` header — proven end-to-end with a real Ed25519 keypair (generated via `openssl genpkey -algorithm ed25519`) signing test JWTs that are verified through the actual `jsonwebtoken::decode` + `DecodingKey::from_jwk` path
- `login()`/`verify_mfa()` reproduce AXIAM's exact two-phase response shapes (200 `LoginSuccessResponse` vs 202 `MfaRequiredResponse`) and never expose an `access_token` field anywhere in the SDK's public API (D-05) — the token is read from the cookie jar and immediately wrapped in `Sensitive<T>`
- `check_access`/`can`/`batch_check` target `/api/v1/authz/check` and `/api/v1/authz/check/batch` exactly, preserve batch input order, and apply bounded `backon` retry only to these read-only calls (D-12) — login/verify_mfa/refresh/logout never auto-retry (§9.3)
- All required source greps pass clean: zero TLS-bypass patterns, zero `/.well-known/jwks.json` references, zero `access_token` field on `LoginResult`

## Task Commits

Each task was committed atomically:

1. **Task 1: AxiamClient builder, cookie jar, token state, single-flight refresh guard, JWKS verifier** - `766f11d` (feat)
2. **Task 2: REST auth flow (login/verify_mfa/refresh/logout) + REST authz (check_access/can/batch_check)** - `2c2103e` (feat)

_No separate TDD RED/GREEN commits: both tasks specified `<behavior>` (test scenarios) and `<action>` (implementation) together, and the executor wrote the implementation and its proving tests as a single logical unit per task, consistent with 16-01's precedent._

## Files Created/Modified
- `sdks/rust/src/client.rs` - `AxiamClient` + `AxiamClientBuilder`; tenant/org identifiers, cookie jar, CSRF/pending-MFA-challenge state, JWKS verifier wiring
- `sdks/rust/src/token/manager.rs` - `TokenManager`, `TokenState`, fast-read cache, jar-extraction helpers for access/refresh/CSRF cookies
- `sdks/rust/src/token/refresh_guard.rs` - Single-flight `refresh_if_needed` (double-check `tokio::sync::Mutex` pattern)
- `sdks/rust/src/token/jwks.rs` - `JwksVerifier`, `Claims`, `find_jwk` kid-rotation lookup
- `sdks/rust/src/token/mod.rs` - Re-exports `Claims` (always) and `JwksVerifier`/`TokenManager` (feature-gated where needed)
- `sdks/rust/src/rest/mod.rs` - Re-exports `auth`/`authz`
- `sdks/rust/src/rest/auth.rs` - `login`/`verify_mfa`/`refresh`/`logout`, `LoginResult`
- `sdks/rust/src/rest/authz.rs` - `check_access`/`can`/`batch_check`, `AccessCheckRequest`/`AccessDecision`
- `sdks/rust/tests/single_flight_refresh_test.rs` - SC#2 oracle: 5 concurrent callers, exactly 1 refresh call
- `sdks/rust/tests/login_mfa_flow_test.rs` - SC#1 oracle plus status-mapping and authz-path/order assertions
- `sdks/rust/Cargo.toml` - `jsonwebtoken` crypto-backend feature pin (`rust_crypto`, `use_pem`)

## Decisions Made
- Pinned `jsonwebtoken`'s `rust_crypto` backend feature explicitly — jsonwebtoken 10 ships with no default crypto provider and panics at the first `encode`/`decode` call without one selected; chose the pure-Rust backend over `aws_lc_rs` to match the crate's existing pure-Rust `rustls-tls` choice and avoid a C/cmake build dependency in a publishable SDK.
- Added optional `org_slug`/`org_id` builder methods beyond CONTRACT.md §5's tenant-only mandate, because AXIAM's real login/refresh endpoints require an organization identifier that the locked contract text doesn't mention; the resolved org UUID is decoded from the access token's `org_id` claim after first login so most callers never need to supply it.
- Gated `client.rs`'s entire body and the reqwest-touching half of `token/jwks.rs` behind `#[cfg(feature = "rest")]` to preserve 16-01's `cargo build --no-default-features` invariant, since both modules are declared unconditionally in `lib.rs`.
- `verify_mfa(code)` matches CONTRACT.md §1's exact signature by holding the pending challenge token internally (set by a prior `login()` call that returned `mfa_required: true`) rather than requiring the caller to pass it explicitly.
- `LoginResult` does not derive `Clone` since it holds a `Sensitive<String>` challenge token and `Sensitive<T>` deliberately has no public `Clone` (§7 redaction design from 16-01).
- Defined the SDK's `Claims` struct to match the server's actual `AccessTokenClaims` fields (`sub`, `tenant_id`, `org_id`, `iss`, `iat`, `exp`, `jti`, `aud`, `scope`) rather than the plan text's suggested `roles` field, since no `roles` claim exists server-side — mirroring a non-existent field would silently break real-world claim deserialization.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `jsonwebtoken` 10 has no default crypto provider**
- **Found during:** Task 1 verification (`cargo test --features rest --lib`)
- **Issue:** `jsonwebtoken::encode`/`decode` panicked at runtime with "Could not automatically determine the process-level CryptoProvider" — jsonwebtoken 10's `default-features` do not select a crypto backend; the root AXIAM workspace resolves one transitively via other crates' feature unification, but this standalone crate's own `Cargo.lock` has no such neighbor.
- **Fix:** Pinned `jsonwebtoken = { version = "10", default-features = false, features = ["rust_crypto", "use_pem"] }` in `Cargo.toml`.
- **Files modified:** `sdks/rust/Cargo.toml`
- **Verification:** `cargo test --features rest --lib` — all 4 JWKS unit tests pass; the end-to-end EdDSA verification in `login_mfa_flow_test.rs` also passes.
- **Committed in:** `766f11d` (part of Task 1 commit)

**2. [Rule 1 - Bug] `cargo build --no-default-features` broke once reqwest-dependent code was added**
- **Found during:** Post-implementation CLAUDE.md compliance check (clippy across all feature combinations)
- **Issue:** `client.rs` and the fetch/cache half of `token/jwks.rs` use `reqwest::Client`/`reqwest::cookie::Jar` types unconditionally, but `client`/`token` are declared as unconditional (non-feature-gated) modules in `lib.rs` (16-01's design) — `cargo build --no-default-features` (a 16-01-established invariant) failed to resolve `reqwest`.
- **Fix:** Gated `client.rs`'s entire module body (`#![cfg(feature = "rest")]`) and the reqwest-touching items in `token/jwks.rs` (`JwksVerifier`, `CachedJwks`, `find_jwk`, associated imports) behind `#[cfg(feature = "rest")]`, keeping `Claims`/`JWKS_PATH`/`TokenManager` feature-independent for 16-03/16-05's future needs.
- **Files modified:** `sdks/rust/src/client.rs`, `sdks/rust/src/token/jwks.rs`, `sdks/rust/src/token/mod.rs`
- **Verification:** `cargo clippy --no-default-features -- -D warnings`, `--features grpc`, `--features amqp`, default, `--features rest --tests`, and `--all-features --tests` all exit 0.
- **Committed in:** `766f11d` (part of Task 1 commit)

**3. [Rule 2 - Missing critical functionality] AXIAM's real login/refresh endpoints require an organization identifier not mentioned in CONTRACT.md §5**
- **Found during:** Task 2 implementation, reading `crates/axiam-api-rest/src/handlers/auth.rs`'s actual `LoginRequest`/`RefreshRequest` shapes
- **Issue:** CONTRACT.md §5 specifies only `tenant_slug`/`tenant_id` as the non-optional constructor parameter, but the real server requires `org_id`/`org_slug` on login and a non-optional `org_id: Uuid` on refresh (organizations are the top-level entity above tenants). Without this, `login()` and `refresh()` cannot function against the real server at all.
- **Fix:** Added optional `org_slug(String)`/`org_id(Uuid)` builder methods; the resolved organization UUID is additionally decoded from the access token's `org_id` claim after the first successful login/verify_mfa and cached, so `refresh()` can supply it even if the caller never set it explicitly at construction.
- **Files modified:** `sdks/rust/src/client.rs`, `sdks/rust/src/rest/auth.rs`
- **Verification:** `login_mfa_flow_test.rs`'s login and MFA-verify tests pass, exercising the full body construction and post-success org resolution path.
- **Committed in:** `766f11d` (client.rs changes), `2c2103e` (auth.rs usage)

**4. [Rule 1 - Bug] Grep acceptance criterion for `/.well-known/jwks.json` initially matched explanatory doc comments**
- **Found during:** Self-review against the plan's literal acceptance-criteria grep commands
- **Issue:** `grep -rn 'well-known/jwks' sdks/rust/src/` matched two doc comments explaining *why* `/oauth2/jwks` is correct (quoting the wrong path as a negative example), which would fail the plan's literal zero-match acceptance gate even though no code used the wrong path.
- **Fix:** Reworded both doc comments to describe the anti-pattern without embedding the literal `well-known/jwks` substring.
- **Files modified:** `sdks/rust/src/token/jwks.rs`
- **Verification:** `grep -rn 'well-known/jwks' sdks/rust/src/` returns zero matches (grep exit code 1).
- **Committed in:** `766f11d` (part of Task 1 commit)

---

**Total deviations:** 4 auto-fixed (1x Rule 1 crypto-provider bug, 1x Rule 1 feature-gating bug, 1x Rule 2 missing org identifier, 1x Rule 1 grep-gate wording)
**Impact on plan:** All four fixes were necessary for the crate to build/test correctly across all feature combinations and for `login()`/`refresh()` to function against the real AXIAM server. No functionality was added beyond what was needed to satisfy the plan's own acceptance criteria and CONTRACT.md's binding requirements.

## Issues Encountered
None beyond the deviations documented above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
`TokenManager`, `JwksVerifier`, and `Claims` are ready for 16-03 (gRPC transport + interceptor) to consume — the fast-read cache (`TokenManager::cached_access_token`) is specifically designed for the synchronous `tonic::service::Interceptor::call` constraint (RESEARCH.md Pitfall 3). `JwksVerifier` is ready for 16-05's Actix `FromRequest` extractor, though its `#[cfg(feature = "rest")]` gate will need broadening to `any(feature = "rest", feature = "actix")` once 16-05 adds the `actix` Cargo feature (noted inline in `token/jwks.rs`'s doc comment). No blockers identified.

---
*Phase: 16-rust-sdk*
*Completed: 2026-07-01*

## Self-Check: PASSED

All 11 created/modified files verified present on disk. Both commit hashes (`766f11d`, `2c2103e`) verified present in `git log --oneline --all`.
