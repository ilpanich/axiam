---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 06
subsystem: federation
tags: [oidc, nonce, replay, federation-login-state, actix-web]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: "plan 25-01 (SECHRD-02): axiam_federation::ssrf shared SSRF guard used by discover()/exchange_code() — the reason handle_callback cannot be driven end-to-end against a local wiremock server (documented in this plan's test as a structural constraint, not a bug)"
provides:
  - "handlers/federation.rs::oidc_authorize persists a server-generated nonce in FederationLoginState keyed by req.state (mirrors oidc_start_public)"
  - "handlers/federation.rs::oidc_callback consumes the state row and derives expected_nonce from login_state.nonce; req.nonce is never read for verification"
  - "OidcCallbackRequest gains a required `state` field"
  - "req5_oidc_e2e.rs::oidc_linking_ignores_client_supplied_nonce — replay/negative test proving a client/attacker-supplied nonce cannot satisfy verification"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Authenticated account-linking OIDC flow now mirrors the public first-time-SSO flow's nonce-from-server-state plumbing (FederationLoginState insert on authorize, consume_by_state on callback)"

key-files:
  created: []
  modified:
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-server/tests/req5_oidc_e2e.rs

key-decisions:
  - "OidcCallbackRequest gained a required `state` field (previously absent) so the authenticated callback can look up its FederationLoginState row, mirroring the public path's OidcPublicCallbackRequest.state — this is a wire-contract change, not just an internal one, since existing callers must now send `state`"
  - "req.nonce field is kept on OidcCallbackRequest/OidcAuthorizeRequest for backward-compatible wire shape but is structurally never read for verification anymore — documented in-line as ignored"
  - "Negative test (oidc_linking_ignores_client_supplied_nonce) proves the fix at two levels instead of one full wiremock HTTP round-trip: (1) real HTTP call to the actual oidc_callback handler proving the new state-gate rejects an unknown/attacker-fabricated state with 401 before any nonce is even considered; (2) real SurrealFederationLoginStateRepository + real JWKS-verified OidcFederationService::verify_id_token proving an attacker-controlled ID-token nonce claim that differs from the server-stored nonce is rejected, with a positive companion (matching nonce succeeds) and a single-use check. This split was necessary because OidcFederationService::discover/exchange_code (used inside handle_callback) route through ssrf::guarded_fetch(url, false, ..) — SECHRD-02/plan 25-01 — which hardcodes allow_private=false with no test seam, so a full network round-trip against a loopback wiremock server is rejected by the SSRF guard in every environment (not a local-only limitation). Every other test in req5_oidc_e2e.rs already tests at the same verify_id_token boundary for the identical reason (see file header, dating to 04-06-SUMMARY.md)."

requirements-completed: [SECHRD-07]

coverage:
  - id: D1
    description: "oidc_authorize persists a server-generated nonce in FederationLoginState keyed by req.state, passing the server nonce (not req.nonce) into build_authorization_url"
    requirement: "SECHRD-07"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/federation_test.rs (regression — 20/20 pass, unaffected federation-config/link/SAML flows)"
        status: pass
      - kind: unit
        ref: "cargo clippy -p axiam-api-rest --lib -- -D warnings (clean)"
        status: pass
    human_judgment: false
  - id: D2
    description: "oidc_callback derives expected_nonce from consume_by_state(req.state) and never reads req.nonce for verification; missing/expired state -> 401"
    requirement: "SECHRD-07"
    verification:
      - kind: integration
        ref: "crates/axiam-server/tests/req5_oidc_e2e.rs#oidc_linking_ignores_client_supplied_nonce (HTTP-level: unknown state -> 401)"
        status: pass
    human_judgment: false
  - id: D3
    description: "A client/attacker-supplied nonce (in the ID token's nonce claim and in req.nonce) cannot satisfy verification; only the server-stored FederationLoginState nonce does — replay negative test with positive companion"
    requirement: "SECHRD-07"
    verification:
      - kind: integration
        ref: "crates/axiam-server/tests/req5_oidc_e2e.rs#oidc_linking_ignores_client_supplied_nonce"
        status: pass
    human_judgment: false

duration: ~20min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 06: Federation Account-Linking OIDC Nonce From Server State Summary

**Account-linking OIDC callback (`oidc_authorize`/`oidc_callback`) now derives its nonce exclusively from a server-side `FederationLoginState` row keyed by `state`, mirroring the already-correct public first-time-SSO path — a request-supplied nonce can no longer satisfy verification.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-04T17:27:00Z
- **Tasks:** 2/2 completed
- **Files modified:** 2

## Accomplishments

- `oidc_authorize` generates a server-side nonce (`random_base64url()`) and persists it in `FederationLoginState` (keyed by `req.state`, `tenant_id` from the authenticated user, 10-minute TTL) before returning the authorization URL — the server nonce (not `req.nonce`) is what's actually embedded in the IdP redirect.
- `oidc_callback` now requires a `state` field, atomically consumes the matching `FederationLoginState` row (`consume_by_state`), and derives `expected_nonce` from the stored row. `req.nonce` is retained on the wire for backward compatibility but is structurally never read for verification. A missing/expired/already-consumed state row returns 401 "state not found or expired" before any nonce logic runs.
- No `main.rs` changes were needed — `SurrealFederationLoginStateRepository` was already registered as `app_data` for the public path, so adding it as a handler parameter to `oidc_authorize`/`oidc_callback` was a drop-in change.
- Negative test `oidc_linking_ignores_client_supplied_nonce` proves the fix at both the HTTP-handler level (unknown state -> 401, regardless of attacker-supplied code/nonce) and the cryptographic nonce-comparison level (an attacker-controlled ID-token nonce claim, differing from the server-stored nonce, is rejected; a matching nonce succeeds as a positive companion; the state row is proven single-use).

## Task Commits

Each task was committed atomically:

1. **Task 1: Replicate the public-path nonce-from-state plumbing on the authenticated account-linking path** - `9b471e9` (fix)
2. **Task 2: Replay negative test — a client-supplied nonce cannot satisfy verification** - `2784817` (test)

**Plan metadata:** (this commit, following SUMMARY.md creation)

## Files Created/Modified

- `crates/axiam-api-rest/src/handlers/federation.rs` - `OidcCallbackRequest` gains a required `state` field; `oidc_authorize` persists a server-generated nonce in `FederationLoginState`; `oidc_callback` consumes the state row and derives `expected_nonce` from it, ignoring `req.nonce`
- `crates/axiam-server/tests/req5_oidc_e2e.rs` - Added `oidc_linking_ignores_client_supplied_nonce`: HTTP-level state-gate proof (real `oidc_callback` handler, no network) + cryptographic nonce-comparison proof (real `SurrealFederationLoginStateRepository` + real `verify_id_token`) with a positive companion and single-use check

## Decisions Made

- **`OidcCallbackRequest.state` is a new required wire field.** The authenticated callback previously had no `state` concept at all; adding it (mirroring the public path's `OidcPublicCallbackRequest.state`) is the mechanism the server-side nonce lookup depends on. Any existing caller of `POST /api/v1/federation/oidc/callback` must now send `state` (the same value it received back from `oidc_authorize`'s underlying flow) — this is a breaking wire-contract change but is exactly what SECHRD-07 requires (no lower-risk mechanism exists to bind the callback to its own `oidc_authorize` invocation).
- **`req.nonce` retained but functionally dead for verification.** Kept on both `OidcAuthorizeRequest` and `OidcCallbackRequest` for backward-compatible request shapes (older/generated clients may still send it), but neither handler reads it when computing the value used for cryptographic nonce comparison.
- **Negative test split across two levels instead of one full wiremock HTTP round-trip.** `OidcFederationService::discover`/`exchange_code` (both invoked inside `handle_callback`) route through `ssrf::guarded_fetch(url, false, ..)` (SECHRD-02, already shipped in plan 25-01), which hardcodes `allow_private=false` with no test seam — a genuine, environment-independent constraint (not a local-compile quirk) that makes a full network round-trip against a loopback wiremock server structurally impossible to test, in this sandbox or in CI. Every other test in `req5_oidc_e2e.rs` already tests at the `verify_id_token` boundary for the identical reason (documented in the file's own header, tracing back to `04-06-SUMMARY.md`'s "local-compile constraint" note). The new test instead: (1) calls the real, unmodified `oidc_callback` HTTP handler with no matching `FederationLoginState` row and asserts 401 — genuinely differentiates from pre-fix behavior, since old code lacked a `state` field/gate entirely and would have hit a different failure mode (`ConfigNotFound` → 404) for the same bogus-config request; (2) uses the real `SurrealFederationLoginStateRepository` (the identical type wired into production) plus the real, JWKS-verified `verify_id_token` to prove the nonce comparison itself rejects an attacker-controlled ID-token nonce claim and accepts only the server-stored one, mirroring `handle_callback`'s own comparison logic at `oidc.rs:329-334`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Test design change for the negative test's network boundary**
- **Found during:** Task 2 (writing `oidc_linking_ignores_client_supplied_nonce`)
- **Issue:** The plan's task text describes driving the flow "through the mock IdP" via a full HTTP round-trip (`oidc_authorize` → mock IdP → `oidc_callback`). Investigation showed `OidcFederationService::discover`/`exchange_code` (both required for `handle_callback` to reach its nonce comparison) call `ssrf::guarded_fetch(url, false, ..)` with `allow_private` hardcoded `false` — a deliberate, already-shipped SECHRD-02 security control (plan 25-01) with no test seam. A wiremock server always binds to loopback, so any attempt at a full round-trip is unconditionally rejected by the SSRF guard before reaching token exchange or the nonce check, in every environment (this is not the samael/libxml "local-compile" issue documented elsewhere in this phase — it reproduces in CI too).
- **Fix:** Split the negative test into two levels that together cover the same contract without requiring the blocked network hops: (1) a real HTTP call to the actual `oidc_callback` handler proving the new state-gate (unknown state → 401); (2) a real-repo + real-crypto test of the nonce comparison itself (attacker-chosen ID-token nonce claim rejected; matching nonce accepted; state single-use). See "Decisions Made" above for the full technical justification.
- **Files modified:** `crates/axiam-server/tests/req5_oidc_e2e.rs`
- **Verification:** `cargo test -p axiam-server --test req5_oidc_e2e oidc_linking_ignores_client_supplied_nonce` passes; the HTTP-level assertion is confirmed to genuinely differentiate from pre-fix behavior (old code would 404 on the same bogus-config-id request, since it had no state field/gate to hit a 401 on).
- **Committed in:** `2784817` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking test-infrastructure constraint from a prior, already-shipped security control)
**Impact on plan:** No production-code scope creep — `crates/axiam-federation/src/oidc.rs`/`ssrf.rs` were NOT touched (out of this plan's `files_modified`, and weakening `allow_private` there would regress SECHRD-02). The negative test's coverage of the SECHRD-07 property is equivalent, just split across the two boundaries that are actually reachable without a live network call.

## Issues Encountered

None beyond the network-boundary test-design issue documented above. `cargo fmt -p axiam-server` applied two line-wrap formatting fixes to the new test (auto-applied, no logic change).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SECHRD-07 closed: the account-linking OIDC callback is now consistent with the public first-time-SSO path's server-side nonce handling.
- `axiam-api-rest`/`axiam-server` both compile locally in this sandbox (xmlsec1 1.2.39 matches samael's expected version — the Arch-host `04-06-SUMMARY.md` local-compile limitation does not apply here), so `cargo test -p axiam-server --test req5_oidc_e2e` and `cargo test -p axiam-api-rest --test federation_test` are both locally runnable and green (13/13 and 20/20 respectively).
- No blockers for subsequent Phase 25 plans (SECHRD-08/09/10 — independent file surfaces).

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*

## Self-Check: PASSED
