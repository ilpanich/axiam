---
phase: 28-functional-completeness
plan: 05
subsystem: federation-sso
tags: [oidc, federation, csrf, ssrf, testing, openapi, rust]

# Dependency graph
requires:
  - phase: 28-functional-completeness (plan 04, in progress)
    provides: openapi.rs registration of the four public SSO handlers (not touched by this plan)
provides:
  - "federation_first_time_sso_test.rs — real HTTP e2e proving a first-time OIDC SSO user (no pre-existing local account) completes start->callback and receives AXIAM cookies, closing CQ-B40"
  - "OidcFederationService::discover()/exchange_code() now honor JwksCache's pre-existing allow_private_networks test seam, enabling loopback wiremock IdP testing of the public SSO handlers"
  - "The four public first-time-SSO endpoints (oidc/start, oidc/callback, saml/login, saml/acs) are now CSRF-exempt, matching their PUBLIC_PATHS/no-JWT status — a genuine pre-existing production bug fixed"
  - "FUNC-02 (session revocation on password reset) and FUNC-05 (login OpenAPI 200/202/403/401) verified green"
affects: [federation-sso, csrf-middleware, oidc-federation-service, jwks-cache]

# Tech tracking
tech-stack:
  added:
    - "wiremock 0.6, rsa 0.9 (feature sha2), rand_core 0.6 (feature getrandom) as axiam-api-rest dev-dependencies, mirroring axiam-server's existing req5_oidc_e2e.rs pins exactly"
  patterns:
    - "Reused JwksCache's existing `allow_private_networks` SEC-054 test seam (already used for JWKS loopback fetches in req5_oidc_e2e.rs) inside OidcFederationService::discover()/exchange_code() instead of inventing a second, independent SSRF bypass — zero production behavior change since JwksCache::new() (the only production constructor) always yields false"
    - "Extract the server-generated OIDC nonce (never returned in the /oidc/start JSON body, per T-04-31) from the authorize_url's query string instead of expecting it in the response body — required to sign a matching mock-IdP ID token"

key-files:
  created:
    - crates/axiam-api-rest/tests/federation_first_time_sso_test.rs
  modified:
    - crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs
    - crates/axiam-api-rest/src/extractors/auth.rs
    - crates/axiam-api-rest/src/tests/authz_check_test.rs
    - crates/axiam-federation/src/oidc.rs
    - crates/axiam-federation/src/jwks_cache.rs
    - crates/axiam-api-rest/src/middleware/csrf.rs
    - crates/axiam-api-rest/Cargo.toml
    - Cargo.lock

key-decisions:
  - "Deferred (Rule 4 — architectural, needs human sign-off): the federation metadata endpoint (GET /api/v1/federation/saml/metadata) is listed in PUBLIC_PATHS but its handler (saml_metadata) unconditionally requires a valid JWT via the AuthenticatedUser extractor — empirically confirmed a bare no-auth GET returns 401, not the reachable/success status the plan's truth expected. NOT fixed in this plan; see Deviations for the full finding and proposed remediation."
  - "Reused JwksCache's cache.1 allow-private-networks bit inside OidcFederationService::discover()/exchange_code() rather than adding a new constructor parameter or touching handlers/federation.rs — keeps the fix to a single crate/file and zero blast radius on production call sites"
  - "Test file omits any assertion of the metadata-endpoint truth (would fail against current code) rather than committing a failing/misleading test"

requirements-completed: [FUNC-02, FUNC-05]
---

# Phase 28 Plan 05: Federation First-Time SSO E2E + FUNC-02/FUNC-05 Verification Summary

Added a real end-to-end HTTP test proving first-time OIDC SSO issues AXIAM cookies for a brand-new user (closing CQ-B40), fixed two genuine pre-existing production bugs discovered while writing it (a hardcoded SSRF/HTTPS-only guard with no test seam, and a missing CSRF exemption that 403'd the public SSO endpoints), fixed a broken test fixture and a broken lib-test compile from earlier phases, and verified FUNC-02/FUNC-05 are already correctly implemented.

## What Was Built

- **`federation_first_time_sso_test.rs`** (new): creates an OIDC federation config via the authenticated API, drives the real public `POST /api/v1/auth/federation/oidc/start` → `POST /api/v1/auth/federation/oidc/callback` handlers against a wiremock mock IdP (RS256-signed ID token for a subject with no pre-existing local account or federation link), and asserts `axiam_access`/`axiam_refresh`/`axiam_csrf` cookies are set (never JSON tokens) and that a subsequent `GET /api/v1/auth/me` returns 200 with the provisioned user's email sourced from the ID token's `email` claim.
- **`OidcFederationService::discover()`/`exchange_code()`** (axiam-federation): now read `self.cache.allow_private_networks()` instead of a hardcoded `false`, and `discover()` skips its HTTPS-only URL/endpoint validation when that bit is set — reusing the exact `JwksCache::new_allow_private_networks()` test seam `req5_oidc_e2e.rs` already relies on for JWKS fetches. Production is unaffected (`JwksCache::new()` always yields `false`).
- **`CSRF_EXEMPT_SUFFIXES`** (axiam-api-rest): added the four public first-time-SSO paths (`/api/v1/auth/federation/{oidc,saml}/{start,callback,login,acs}` as applicable), fixing a real production bug where these routes 403'd on CSRF despite being listed in `PUBLIC_PATHS`.
- **Test-fixture/compile fixes** (see Deviations): `password_reset_revokes_sessions.rs` was missing a `crypto_semaphore` app_data registration (500 on every call); `extractors/auth.rs` and `authz_check_test.rs` had two `AccessTokenClaims` struct literals missing the `sub_kind` field added by 28-02, breaking `cargo test -p axiam-api-rest --lib` entirely.

## Task Commits

1. **Task 2 pre-req fix: register missing `crypto_semaphore` app_data (FUNC-02 blocker)** — `1708083` (fix)
2. **Task 3 pre-req fix: add missing `sub_kind` field to test-only `AccessTokenClaims` literals** — `b7f4b84` (fix)
3. **Task 1 pre-req fix: thread `JwksCache`'s allow-private seam through `discover()`/`exchange_code()`** — `965da7b` (feat)
4. **Task 1 pre-req fix: exempt the four public SSO endpoints from CSRF** — `89748b8` (fix)
5. **Task 1: first-time OIDC SSO e2e against a mock IdP** — `9d9fb26` (test)

**Plan metadata:** (this commit)

## Verification Evidence

- **FUNC-01 (partial — see Deviations):** `cargo test -p axiam-api-rest --test federation_first_time_sso_test` → 1/1 pass. No regression in `federation_test.rs` (20/20), `req5_oidc_e2e.rs` (13/13 — axiam-server), `axiam-federation --lib` (21/21), `auth_test.rs` (19/19, including CSRF tests), or `axiam-api-rest --lib` (60/60).
- **FUNC-02:** `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` → 1/1 pass (`password_reset_confirm_revokes_existing_sessions`: the original session cookie is rejected 401 after `POST /api/v1/auth/reset/confirm`).
- **FUNC-05:** `crates/axiam-api-rest/src/handlers/auth.rs:254-265` — the `login` handler's `#[utoipa::path]` documents `200 → LoginSuccessResponse`, `202 → MfaRequiredResponse`, `403 → MfaSetupRequiredResponse`, `401` (no body) as four distinct responses. `crates/axiam-api-rest/src/openapi.rs` registers `handlers::auth::login` (line 20) as a path and all three response body schemas (`LoginSuccessResponse` line 189, `MfaRequiredResponse` line 190, `MfaSetupRequiredResponse` line 196) as components. `cargo test -p axiam-api-rest --lib route_openapi_parity` → 2/2 pass. No `openapi.rs` edits were made (per plan's explicit instruction — 28-04 owns that file this phase).

## Decisions Made

- Reused `JwksCache`'s already-existing `allow_private_networks` bit for `OidcFederationService::discover()`/`exchange_code()` instead of inventing a new bypass mechanism — see Deviations for full rationale.
- Left the federation-metadata "reachable with no auth" truth unimplemented rather than unilaterally changing `saml_metadata`'s authentication model — flagged as a Rule 4 architectural decision requiring human sign-off (see below).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `password_reset_revokes_sessions.rs`'s `test_app!` macro missing `crypto_semaphore` app_data**
- **Found during:** Task 2 verify-only run — `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` failed with a 500 (expected 200) on `POST /api/v1/auth/reset/confirm`.
- **Issue:** `confirm_reset`/`request_reset` gate their CPU-bound Argon2 work behind a shared `web::Data<Arc<Semaphore>>` (the "A3" crypto-isolation pattern, mirroring `axiam-server`'s production `main.rs` wiring). The test's `test_app!` macro predates this and never registered it, so the `Data` extractor failed (confirmed via a debug run with `tracing_subscriber` enabled: `Failed to extract Data<Arc<Semaphore>>`), surfacing as a 500 instead of exercising the FUNC-02 assertion. HIBP breaker network failure was ruled out as a red herring — `check_hibp` is already fail-open by design and logged only a `WARN`.
- **Fix:** Registered `web::Data::new(Arc::new(Semaphore::new(4)))` in the macro.
- **Files modified:** `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs`
- **Commit:** `1708083`

**2. [Rule 3 - Blocking issue] `cargo test -p axiam-api-rest --lib` fails to compile (E0063, missing `sub_kind`)**
- **Found during:** Task 3 verify — `route_openapi_parity` requires `--lib`, which failed with `missing field sub_kind in initializer of AccessTokenClaims` at two call sites.
- **Issue:** 28-02 (already committed, `e02499d`) added the `sub_kind` claim to `AccessTokenClaims` and updated every construction site inside `axiam-auth`, but two test-only cross-crate literals in `axiam-api-rest` (`extractors/auth.rs`'s no-aud-token test helper, `authz_check_test.rs`'s `make_user` helper) were missed — breaking the whole crate's `--lib` test target.
- **Fix:** Added `sub_kind: SubjectKind::User` to both struct literals (matching D-11's "missing sub_kind defaults to User" convention for user-facing fixtures).
- **Files modified:** `crates/axiam-api-rest/src/extractors/auth.rs`, `crates/axiam-api-rest/src/tests/authz_check_test.rs`
- **Commit:** `b7f4b84`

**3. [Rule 3 - Blocking issue] `OidcFederationService::discover()`/`exchange_code()` hardcode SSRF `allow_private=false` + HTTPS-only validation, with no test seam**
- **Found during:** Task 1 design — realized `discover()` calls `validate_metadata_url()` (rejects non-HTTPS URLs outright) and both `discover()`/`exchange_code()` call `crate::ssrf::guarded_fetch(url, false, ..)` (hardcoded, unconditionally rejects loopback/private IPs). `wiremock` (0.6.5, vendored in this workspace) serves plain HTTP only — no TLS support. This meant literally NO test could drive the public `oidc_start_public`/`oidc_callback_public` handlers end-to-end against a loopback mock IdP, in any environment, by design (confirmed against `req5_oidc_e2e.rs`'s own file-header documentation of this exact limitation for the authenticated flow).
- **Fix:** `discover()`/`exchange_code()` now read `self.cache.allow_private_networks()` (a new `pub(crate)` accessor on `JwksCache`) instead of a hardcoded `false`; `discover()` also skips its HTTPS-only checks under the same bit. This reuses the `JwksCache::new_allow_private_networks()` seam ALREADY injected into `OidcFederationService` via its `cache: Arc<JwksCache>` field and ALREADY used by `req5_oidc_e2e.rs` for JWKS fetches on this exact flow — no new bypass mechanism, no changes to `OidcFederationService::new()`'s signature, no changes to `handlers/federation.rs` (production always constructs `JwksCache::new()`, so `cache.1` is always `false` there).
- **Files modified:** `crates/axiam-federation/src/oidc.rs`, `crates/axiam-federation/src/jwks_cache.rs`
- **Verification:** `axiam-federation --lib` (21/21), `req5_oidc_e2e.rs` (13/13), `federation_test.rs` (20/20) — all green, no behavior change on the production (`allow_private=false`) path.
- **Commit:** `965da7b`

**4. [Rule 1 - Bug] The four public first-time-SSO endpoints were missing from `CSRF_EXEMPT_SUFFIXES`**
- **Found during:** Task 1 — the e2e test's `POST /api/v1/auth/federation/oidc/start` call returned 403 even with a fully valid, correctly-configured request.
- **Issue:** `oidc_start_public`/`oidc_callback_public`/`saml_login_public`/`saml_acs_public` are correctly listed in `PUBLIC_PATHS` (AuthzMiddleware bypass), but `CsrfMiddleware` consults a SEPARATE registry (`CSRF_EXEMPT_SUFFIXES`) that never gained matching entries. A first-time SSO caller has no prior session and therefore no `axiam_csrf` cookie to echo back — exactly the same "CSRF-blocked" failure mode the codebase's own comments already document (and had already fixed) for `/api/v1/auth/reset`/`reset/confirm`. This is a genuine, pre-existing PRODUCTION bug (not a test-environment artifact): any real first-time SSO login attempt today gets 403'd before the handler ever runs.
- **Fix:** Added all four public SSO paths to `CSRF_EXEMPT_SUFFIXES`.
- **Files modified:** `crates/axiam-api-rest/src/middleware/csrf.rs`
- **Verification:** `auth_test.rs` (19/19, including the existing CSRF-specific tests), `federation_test.rs` (20/20), `axiam-api-rest --lib` (60/60) — no regressions.
- **Commit:** `89748b8`

### Deferred — Requires Human Decision (Rule 4)

**5. [Rule 4 - Architectural] Federation metadata endpoint requires a JWT despite being listed as public**

- **What was found:** The plan's truth "The federation metadata endpoint is reachable with no auth header" does NOT hold against current code. `GET /api/v1/federation/saml/metadata` is listed in `PUBLIC_PATHS` (so `AuthzMiddleware` bypasses its own JWT/permission check) and the phase's threat model explicitly states "Metadata is public by design... matching the established PUBLIC_PATHS posture" — but the handler (`saml_metadata`, `handlers/federation.rs:952`) takes `user: AuthenticatedUser` as its first extractor parameter, which unconditionally requires a valid JWT (cookie or `Authorization: Bearer`) with no bypass for public paths. **Empirically confirmed**: a bare `GET` with zero credentials returns 401 (verified with a throwaway probe test against the real handler/routes before writing any fix). `AuthzMiddleware`'s "public paths pass through without any credential check" only bypasses its OWN check — it does not, and cannot, make a handler's own `AuthenticatedUser` extractor succeed with no token.
- **Root cause:** `AuthzMiddleware`'s allowlist (`PUBLIC_PATHS`) and `saml_metadata`'s per-handler auth requirement are two independent mechanisms that were never reconciled for this route — the SAME class of gap already found and fixed for CSRF in this same plan (item 4 above), but for a DIFFERENT middleware boundary that removing the extractor cannot be done as a narrow, zero-risk change.
- **Why NOT auto-fixed:** Making this route genuinely reachable with no JWT means removing its `AuthenticatedUser` requirement and resolving tenant identity some other way (e.g. accepting `org_id`/`org_slug` + `tenant_id`/`tenant_slug` query params and looking up the tenant, mirroring `oidc_start_public`'s exact pattern in the same file) — a "changing auth approach" change to an existing, shipped, currently-authenticated endpoint (explicitly listed as a Rule 4 trigger example). This also changes the endpoint's data-isolation semantics (currently: only the caller's own tenant's configs are visible via `user.tenant_id`; a query-param-based version would need its own IDOR consideration, even though metadata itself is non-secret per T-28-16's "accept" disposition). This is out of the plan's declared `files_modified` scope (only the test file was declared) and touches a live authentication boundary, so it was NOT changed unilaterally.
- **Proposed remediation (for a follow-up plan/decision):** Add `org_id`/`org_slug` + `tenant_id`/`tenant_slug` fields to `SamlMetadataQuery` (mirroring `OidcStartRequest`), resolve `tenant_id` from them instead of `AuthenticatedUser.tenant_id`, and drop the `AuthenticatedUser` parameter from `saml_metadata`. Update its `#[utoipa::path]` doc (remove `security(("bearer" = []))`, document the new query params) — this touches `handlers/federation.rs` only, not `openapi.rs` directly (utoipa reads the handler's own macro).
- **Impact on this plan:** FUNC-01's core truth (first-time SSO token issuance) is fully proven; this ONE sub-assertion of Task 1's acceptance criteria (the metadata reachability test case) is not implemented. No test asserting the current (incorrect) 401 behavior was committed, to avoid a misleading "passing" test that documents a bug as intended behavior.
- **Alternatives considered:** (a) fix it now under Rule 1/2 reasoning (rejected — "changing auth approach" is an explicit Rule 4 trigger regardless of how narrow the fix looks); (b) write a test asserting the current 401 (rejected — contradicts the plan's stated truth and the threat model's stated intent, would read as "intentional" to future readers); (c) leave undocumented (rejected — silently marking FUNC-01 "done" would hide a real, currently-exploitable-by-nobody-but-still-incorrect production gap).

---

**Total deviations:** 4 auto-fixed (2 blocking test/compile issues from earlier phases, 2 genuine production bugs discovered while building this plan's e2e), 1 deferred pending human decision.
**Impact on plan:** FUNC-02 and FUNC-05 fully verified. FUNC-01's CQ-B40-closing truth (first-time SSO → AXIAM cookies → `/auth/me` 200) is fully proven end-to-end. FUNC-01's metadata-reachability truth is NOT met by current code and requires a follow-up decision per item 5 above.

## Known Stubs

None.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: auth_bypass_incomplete | `crates/axiam-api-rest/src/handlers/federation.rs` (`saml_metadata`) | Route is listed in `PUBLIC_PATHS` (intended public) but the handler's `AuthenticatedUser` extractor still requires a valid JWT — the route is effectively still authenticated, contradicting its documented/intended public posture. See Deviations item 5. |

## Issues Encountered

- Sandbox disk filled to 100% mid-build (`rustc-LLVM ERROR: IO failure on output stream: No space left on device`) while compiling the new `wiremock`/`rsa` dev-dependencies. Recovered per CLAUDE.md's documented ENOSPC procedure (`cargo clean`, freeing ~20 GiB) before continuing.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The two production bugs fixed here (CSRF exemption gap, SSRF/HTTPS test-seam gap) were both blocking issues that would otherwise silently fail any real first-time SSO login attempt in production (the CSRF one) or any future test coverage of this flow (the SSRF one) — both are now closed.
- **Follow-up required:** a human decision on Deviations item 5 (federation metadata auth model). Recommend either a small follow-up plan implementing the proposed remediation, or an explicit decision to keep the endpoint authenticated and correct `PUBLIC_PATHS`/the threat model/FUNC-01's AC to match (i.e. treat the "public metadata" framing itself as the error, not the code).
- Plan 28-04 still owns `openapi.rs` for the four public SSO handlers' OpenAPI documentation (D-12) — untouched by this plan as instructed.

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*

## Self-Check: PASSED

All created/modified files confirmed present on disk and all five task commit hashes
(`1708083`, `b7f4b84`, `965da7b`, `89748b8`, `9d9fb26`) confirmed present in git log.
