---
phase: 25-security-hardening-ii-federation-pki-data-protection-infra
plan: 02
subsystem: api
tags: [ssrf, dns-rebind, webhook, reqwest, axiam-federation]

# Dependency graph
requires:
  - phase: 25-security-hardening-ii-federation-pki-data-protection-infra
    provides: "axiam_federation::ssrf — shared IP-pinning SSRF guard (25-01)"
provides:
  - "axiam-api-rest webhook delivery routes per-attempt sends through axiam_federation::ssrf::guarded_fetch, pinning the validated IpAddr into a fresh single-use client"
  - "From<SsrfError> for WebhookError bridge, so blocked/unresolvable webhook targets fail closed through the existing AxiamApiError mapping"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "webhook per-attempt delivery: ssrf::guarded_fetch(url, false, |c,u| c.post(u)...) replaces resolve-then-independently-send, closing the DNS-rebind pin gap"

key-files:
  created: []
  modified:
    - crates/axiam-api-rest/src/webhook.rs
    - crates/axiam-api-rest/tests/webhook_test.rs

key-decisions:
  - "Removed the WebhookDeliveryService's pooled reqwest::Client field entirely (rather than keeping it #[allow(dead_code)] as 25-01 did for SamlFederationService::http_client), since the field is fully private with no external call sites — guarded_fetch builds its own fresh pinned client per attempt, so the pooled client would be genuine dead weight and a clippy dead_code hazard under -D warnings"
  - "SsrfError variants beyond Blocked/InvalidUrl/ResolveFailed (ClientBuildFailed, RequestFailed, TooManyRedirects) map to WebhookError::ResolveFailed rather than a new variant — these are transport-level failures, not SSRF verdicts, and the existing WebhookError enum has no generic 'transport error' variant; reusing ResolveFailed keeps the fail-closed AxiamApiError mapping intact without expanding public API surface"
  - "Delivery loop distinguishes SSRF-verdict errors (Blocked/InvalidUrl/ResolveFailed — abort all retries, matching pre-existing behavior) from transport-level errors (ClientBuildFailed/RequestFailed/TooManyRedirects — allow the exponential-backoff loop to retry), since guarded_fetch merges what used to be two separately-handled steps (resolve-check then send) into one call"

patterns-established:
  - "Every server-initiated fetch to a tenant/admin-supplied URL (JWKS, OIDC, SAML metadata from 25-01; webhook delivery from 25-02) now uses the same axiam_federation::ssrf::guarded_fetch guard — no crate has its own duplicate IP-classification or pinning logic"

requirements-completed: [SECHRD-02]

coverage:
  - id: D1
    description: "Webhook delivery's per-attempt send is routed through axiam_federation::ssrf::guarded_fetch, pinning the validated IpAddr into a fresh single-use client instead of independently re-resolving DNS at send time"
    requirement: "SECHRD-02"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/webhook.rs#tests::ssrf_error_blocked_maps_to_webhook_error_ssrf_blocked"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/webhook_test.rs#webhook_pins_resolved_ip"
        status: pass
    human_judgment: false
  - id: D2
    description: "Local duplicate is_private_ip/resolve_and_validate_host guard logic in webhook.rs is retired; webhook.rs's own SSRF unit tests now exercise the shared ssrf module directly, proving no byte-identical copy remains"
    requirement: "SECHRD-02"
    verification:
      - kind: unit
        ref: "cargo test -p axiam-api-rest --lib webhook (17/17 pass)"
        status: pass
    human_judgment: false

duration: ~35min
completed: 2026-07-04
status: complete
---

# Phase 25 Plan 02: Webhook SSRF Address-Pinning Summary

**Webhook delivery now routes its per-attempt POST through `axiam_federation::ssrf::guarded_fetch`, pinning the validated `IpAddr` into a fresh single-use client so `reqwest` cannot independently re-resolve DNS between the SSRF check and the actual send — closing the DNS-rebind TOCTOU window `webhook.rs` previously left open (RESEARCH Pitfall 1).**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-07-04
- **Tasks:** 2/2 completed
- **Files modified:** 2

## Accomplishments

- `webhook.rs`'s delivery loop replaces `resolve_and_validate_host(url).await?` + a separate, independently-resolving `client.post(&webhook.url)...send()` with a single `ssrf::guarded_fetch(&webhook.url, false, |c, u| c.post(u)...)` call per attempt — the exact validated `IpAddr` is pinned into the connection via a fresh single-use `reqwest::Client`, so no second DNS lookup can occur between the check and the send.
- The exponential-backoff retry loop (delay scaled by attempt count via `multiplier.powi`) is unchanged; only the per-attempt send mechanics changed. SSRF-verdict errors (`Blocked`/`InvalidUrl`/`ResolveFailed`) still abort all remaining retries immediately (unchanged behavior — retrying a blocked target is pointless); transport-level errors (`ClientBuildFailed`/`RequestFailed`/`TooManyRedirects`) fall through to the existing per-attempt retry path, matching how a plain `reqwest::Error` was previously handled.
- The local duplicate `is_private_ip`/`resolve_and_validate_host` guard logic is deleted; webhook.rs's own SSRF unit tests were rewritten to call `ssrf::is_disallowed_ip`/`ssrf::resolve_and_pick` directly, proving the module genuinely forwards to the shared guard rather than keeping a byte-identical copy (D-01a dedup, mirroring what 25-01 did for JWKS/OIDC/SAML).
- Added `impl From<SsrfError> for WebhookError` so a blocked/unresolvable target flows through the pre-existing fail-closed `From<WebhookError> for AxiamApiError` mapping — never a panic or a raw 500.
- Removed `WebhookDeliveryService`'s pooled `reqwest::Client` field: `guarded_fetch` builds its own pinned client per attempt, so the old field was genuinely dead weight (private, no external call sites) rather than something worth preserving with `#[allow(dead_code)]`.
- New integration test `webhook_pins_resolved_ip` proves the anti-rebind property with a hermetic, loopback-only construction: a client pinned (via `ssrf::pinned_client`, the exact mechanism `guarded_fetch` uses) to `127.0.0.2` for host `"localhost"` fails even though `"localhost"` genuinely resolves to `127.0.0.1` where a real mock server listens — proving the pin, not a fresh independent resolution, determines where the connection lands. A positive control (pin to the correct `127.0.0.1`) and an end-to-end `guarded_fetch` call (the exact shape `webhook.rs` uses) both succeed, ruling out "the test always fails" and confirming the production wiring works.

## Task Commits

Each task was committed atomically:

1. **Task 1: Route webhook per-attempt delivery through the shared ssrf guard, preserving the backoff loop** - `aca89f4` (fix)
2. **Task 2: Add the webhook_pins_resolved_ip integration test (no second DNS resolution at send)** - `01b2e1c` (test)

**Plan metadata:** (this commit, following SUMMARY.md creation)

## Files Created/Modified

- `crates/axiam-api-rest/src/webhook.rs` - Delivery loop routes per-attempt POST through `ssrf::guarded_fetch`; local `is_private_ip`/`resolve_and_validate_host` duplicates removed; `From<SsrfError> for WebhookError` bridge added; pooled `reqwest::Client` field removed; SSRF unit tests updated to exercise the shared `ssrf` module directly
- `crates/axiam-api-rest/tests/webhook_test.rs` - New `webhook_pins_resolved_ip` integration test proving IP pinning closes the DNS-rebind TOCTOU window

## Decisions Made

- Removed the `WebhookDeliveryService`'s pooled `reqwest::Client` field entirely rather than retaining it with `#[allow(dead_code)]` (the pattern 25-01 used for `SamlFederationService::http_client`) — this field was fully private with zero external call sites, so keeping it would have been genuine dead code flagged by `clippy -D warnings`, unlike the SAML case where the field was referenced across ~9 out-of-scope call sites.
- `SsrfError` variants that aren't SSRF verdicts (`ClientBuildFailed`, `RequestFailed`, `TooManyRedirects`) map to `WebhookError::ResolveFailed` rather than introducing a new "transport error" variant, keeping the fail-closed `AxiamApiError` mapping intact without expanding public API surface for this plan's scope.
- The delivery loop explicitly distinguishes SSRF-verdict errors (abort all retries) from transport-level errors (allow retry) at the match-arm level, since `guarded_fetch` merges what used to be two separately-handled steps (a resolve-and-check step, then an independent send step) into a single call whose `Err` can now originate from either phase.

## Deviations from Plan

None - plan executed exactly as written. The only additions beyond the plan's literal task text were (a) rewriting webhook.rs's pre-existing SSRF unit tests to call the shared module directly instead of leaving them broken by the removal of the local duplicate functions they tested, and (b) removing the now-genuinely-dead pooled `reqwest::Client` field — both are direct, necessary consequences of Task 1's instruction to "remove the now-redundant local `is_private_ip` and `resolve_and_validate_host`" and are covered by Rule 1 (fixing what would otherwise be a compile break) rather than scope creep.

## Issues Encountered

None — both tasks completed on the first pass. `cargo fmt` made minor formatting adjustments (match-arm wrapping, a long line split) after each task, applied via `cargo fmt -p axiam-api-rest`.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both webhook and federation (JWKS/OIDC/SAML) outbound fetch paths now share one guard (`axiam_federation::ssrf`) — no per-crate duplicate SSRF logic remains anywhere in the codebase (D-01a fully realized across both consumers).
- Wave 2's other plan, 25-05 (mTLS CA status/validity), is independent (`axiam-pki::mtls` file surface) and unaffected by this plan's changes.
- No blockers identified.

---
*Phase: 25-security-hardening-ii-federation-pki-data-protection-infra*
*Completed: 2026-07-04*

## Self-Check: PASSED

All created/modified files verified present on disk; task commit hashes (`aca89f4`, `01b2e1c`) verified present in `git log --oneline --all`.
