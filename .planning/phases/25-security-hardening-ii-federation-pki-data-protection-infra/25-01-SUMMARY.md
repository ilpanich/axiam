---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 01
subsystem: federation
tags: [ssrf, dns-rebind, oidc, saml, jwks, reqwest]

# Dependency graph
requires: []
provides:
  - "axiam_federation::ssrf — shared IP-pinning SSRF guard module (is_disallowed_ip, resolve_and_pick, pinned_client, guarded_fetch, SsrfError)"
  - "JWKS/OIDC discovery/OIDC token-exchange/SAML metadata fetches all pin the validated IpAddr and fail closed against internal-address redirects"
affects: [25-02-webhook-ssrf-mtls-pki]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Resolve-once-and-pin outbound fetch: resolve host -> reject disallowed IPs -> pin exact IpAddr via ClientBuilder::resolve() -> fresh single-use client per request -> manual bounded redirect re-validation (Policy::none() + Url::join)"

key-files:
  created:
    - crates/axiam-federation/src/ssrf.rs
  modified:
    - crates/axiam-federation/src/lib.rs
    - crates/axiam-federation/src/jwks_cache.rs
    - crates/axiam-federation/src/oidc.rs
    - crates/axiam-federation/src/saml.rs

key-decisions:
  - "allow_private test seam (loopback mock-server integration seam) is honored ONLY on the first hop of guarded_fetch — every redirect hop is always strictly validated regardless of the caller's seam opt-in, otherwise the redirect-bypass negative test could never distinguish a real block from a seam bypass"
  - "SamlFederationService.http_client field is now unused by fetch_idp_metadata (guarded_fetch builds its own fresh pinned client) but is retained with #[allow(dead_code)] rather than removed, since removing it would require touching ~9 out-of-scope call sites in axiam-api-rest::handlers::federation and axiam-server test files not listed in this plan's files_modified"
  - "fetch_jwks's http parameter renamed to _http (unused) rather than removing it from get_or_fetch/force_refetch_if_allowed's public signatures, preserving those methods' existing call sites in oidc.rs and jwks_cache.rs's own tests unchanged"

patterns-established:
  - "Every outbound fetch to an admin/IdP-supplied URL (JWKS, OIDC discovery, OIDC token exchange, SAML metadata) routes through ssrf::guarded_fetch(url, allow_private, |c,u| ...) instead of building/sending via an injected reqwest::Client directly"

requirements-completed: [SECHRD-02]

coverage:
  - id: D1
    description: "Shared axiam-federation::ssrf module pins the validated resolved IP into the connection (no DNS-rebind TOCTOU window) and disables auto-redirects in favor of bounded, re-validated manual redirect handling"
    requirement: "SECHRD-02"
    verification:
      - kind: unit
        ref: "crates/axiam-federation/src/ssrf.rs#ssrf_rejects_loopback_token_endpoint"
        status: pass
      - kind: unit
        ref: "crates/axiam-federation/src/ssrf.rs#ssrf_rejects_redirect_to_internal"
        status: pass
    human_judgment: false
  - id: D2
    description: "JWKS fetch (jwks_cache::fetch_jwks), OIDC discovery (oidc::discover), OIDC token exchange (oidc::exchange_code), and SAML metadata fetch (saml::fetch_idp_metadata) all route through the shared guard; no direct reqwest::Client construction remains for these production fetch paths"
    requirement: "SECHRD-02"
    verification:
      - kind: unit
        ref: "cargo test -p axiam-federation --lib (21/21 pass, includes pre-existing jwks_cache/oidc/saml suites)"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 01: Federation SSRF Address-Pinning Summary

**Shared `axiam-federation::ssrf` module generalizes the pre-existing JWKS-only SSRF guard into an IP-pinning, redirect-re-validating fetch helper now used by JWKS, OIDC discovery/token-exchange, and SAML metadata — closing the DNS-rebind TOCTOU window none of the prior per-crate guards actually closed.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-04T16:16:41Z
- **Tasks:** 2/2 completed
- **Files modified:** 4 modified, 1 created

## Accomplishments

- New `axiam-federation::ssrf` module: `is_disallowed_ip`, `resolve_and_pick`, `pinned_client`, `guarded_fetch`, `SsrfError` — the exact validated `IpAddr` is pinned into the socket via `reqwest::ClientBuilder::resolve()`, and a fresh single-use client is built per request (no cross-request DNS caching or pooled-client reuse).
- `reqwest::redirect::Policy::none()` disables automatic redirect-following; `guarded_fetch` manually re-runs the full resolve→validate→pin→send guard against each `Location` target (bounded to 3 hops, using `Url::join` for relative redirects) — a redirect to an internal address is rejected, not silently followed.
- `jwks_cache::fetch_jwks`, `oidc::discover`, `oidc::exchange_code`, and `saml::fetch_idp_metadata` all now route through `ssrf::guarded_fetch` instead of building/sending via a raw or injected `reqwest::Client`. OIDC and SAML previously had **no** SSRF guard at all on these paths; JWKS previously had validate-then-independently-resolve (the pinning gap this plan closes).
- The byte-identical duplicate IP-classification logic (`jwks_cache::is_private_jwks_ip` / `validate_jwks_url`) is deleted and forwarded to the shared `ssrf` module (D-01a dedup).
- Two negative tests prove the fix: `ssrf_rejects_loopback_token_endpoint` (a loopback host/IP is blocked before any request is sent) and `ssrf_rejects_redirect_to_internal` (a real loopback TCP mock server returns a 302 to `10.0.0.5`; the redirect hop is rejected, proving it is re-validated rather than followed).

## Task Commits

Each task was committed atomically:

1. **Task 1: Create the shared ssrf.rs guard module with resolve-and-pin + bounded redirect re-validation** - `c82cc28` (feat)
2. **Task 2: Route JWKS, OIDC discovery/token-exchange, and SAML-metadata fetches through the shared guard** - `bcc2922` (fix)

**Plan metadata:** (this commit, following SUMMARY.md creation)

## Files Created/Modified

- `crates/axiam-federation/src/ssrf.rs` - Shared SSRF guard: IP classification, resolve-and-pin, fresh pinned client builder, guarded fetch orchestration with bounded manual redirect re-validation
- `crates/axiam-federation/src/lib.rs` - `pub mod ssrf;` (feature-independent — not gated behind `saml`, since plan 25-02's webhook SSRF work in `axiam-api-rest` depends on it regardless of SAML)
- `crates/axiam-federation/src/jwks_cache.rs` - `fetch_jwks` routes through `ssrf::guarded_fetch`; duplicate `is_private_jwks_ip`/`validate_jwks_url` removed
- `crates/axiam-federation/src/oidc.rs` - `discover` (GET) and `exchange_code` (POST form) route through `ssrf::guarded_fetch`
- `crates/axiam-federation/src/saml.rs` - `fetch_idp_metadata` routes through `ssrf::guarded_fetch`

## Decisions Made

- **`allow_private` test seam scoped to the first hop only:** The plan's task text describes a single `allow_private` bool threaded through `guarded_fetch`'s entire call, but if that flag disabled the disallow check for every hop (including a redirect target), the `ssrf_rejects_redirect_to_internal` test could never distinguish a genuine block from an accidental seam bypass — a redirect to `10.0.0.5` would pass unchecked whenever the test needed `allow_private=true` to reach its own loopback mock server. I resolved this by applying `allow_private` only to hop 0; every subsequent redirect hop is always held to the strict (production) check regardless of the caller's seam opt-in. This is consistent with — and arguably required by — D-01b's "re-run the **full** SSRF guard against the redirect target," since a `Location` header is attacker-influenced response data, not the admin-configured URL the caller explicitly opted to trust.
- **`SamlFederationService.http_client` retained with `#[allow(dead_code)]` rather than removed:** after routing `fetch_idp_metadata` through `guarded_fetch` (which builds its own fresh pinned client per D-01c), `http_client` becomes genuinely unread within `saml.rs`. Removing the field would require changing the constructor signature and touching ~9 call sites in `axiam-api-rest::handlers::federation` plus `axiam-server` integration tests — none of which are in this plan's `files_modified` list and several of which belong to plan 25-02's scope. Keeping the field (documented, with an explanation of why) avoids scope creep and merge risk while still closing the actual security gap.
- **`fetch_jwks`'s now-unused `http` parameter renamed `_http`** rather than removing it from `get_or_fetch`/`force_refetch_if_allowed`'s public signatures — preserves every existing call site (oidc.rs's production code and both files' own test suites) unchanged.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug/ambiguity in test design] Scoped `allow_private` to the first hop only**
- **Found during:** Task 1 (writing `ssrf_rejects_redirect_to_internal`)
- **Issue:** A literal single-flag-for-the-whole-call design (as implied by the task's prose) would let a redirect target inherit the caller's `allow_private=true` test seam, making it impossible for the redirect-bypass negative test to prove anything — the very address it's supposed to reject (`10.0.0.5`) would also be exempted from the check.
- **Fix:** `guarded_fetch` applies `allow_private` only when `hop == 0`; every redirect hop always runs the strict check.
- **Files modified:** `crates/axiam-federation/src/ssrf.rs`
- **Verification:** `ssrf_rejects_redirect_to_internal` passes and genuinely fails if the hop-scoping is removed (verified via reasoning through the guard's IP-classification logic — `10.0.0.5` is RFC1918 private, and without hop-scoping `resolve_and_pick` would skip the check for allow_private=true).
- **Committed in:** `c82cc28` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — closing an ambiguity that would have produced a vacuous test)
**Impact on plan:** Necessary for the negative test to actually prove the redirect-bypass defense; no scope creep — the fix lives entirely inside the new `ssrf.rs` module already in scope for Task 1.

## Issues Encountered

None — both tasks completed on the first pass with no build/test failures beyond the fmt-formatting auto-fix applied by `cargo fmt`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `axiam-federation::ssrf::guarded_fetch` is public and ready for plan 25-02 to reuse for `axiam-api-rest`'s webhook delivery path (`webhook.rs`'s `resolve_and_validate_host` has the same validate-but-don't-pin gap this plan closed for federation).
- No blockers for 25-02 (mTLS CA status/validity) — independent file surface (`axiam-pki::mtls`).

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*
