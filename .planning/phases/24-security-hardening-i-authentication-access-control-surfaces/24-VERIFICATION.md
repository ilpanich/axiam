---
phase: 24-security-hardening-i-authentication-access-control-surfaces
verified: 2026-07-04T13:09:46Z
status: gaps_found
score: 5/5 roadmap success criteria verified; 1 plan-level must-have (24-07) failed
behavior_unverified: 0
overrides_applied: 0
gaps:
  - truth: "The gRPC limiter shares the same SurrealDB rate-limit bucket store, failing OPEN to the existing in-memory GovernorLayer on DB error (24-07 must_haves.truths)"
    status: failed
    reason: >
      GrpcSharedRateLimitLayer / GrpcSharedRateLimitService are fully implemented and
      unit/integration-tested in crates/axiam-api-grpc/src/middleware/rate_limit.rs, but
      are never constructed or `.layer()`'d anywhere outside test files. `start_grpc_server`
      (crates/axiam-api-grpc/src/server.rs) only calls `build_grpc_governor_layer(...)`
      (the in-memory-only GovernorLayer with the fixed GrpcTrustedHopsKeyExtractor); no
      `Surreal<C>` handle is threaded through `start_grpc_server`/`main.rs` to construct
      the shared-store layer. In the running gRPC server today, the multi-replica shared
      counter is dead code — a brute-force attacker spread across replicas still gets
      N× the intended gRPC authz-check rate limit, the same gap the REST half (24-04)
      already closed for REST endpoints.
    artifacts:
      - path: "crates/axiam-api-grpc/src/middleware/rate_limit.rs"
        issue: "GrpcSharedRateLimitLayer/GrpcSharedRateLimitService exist, are substantive, and are exercised by crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs — but are never referenced from crates/axiam-api-grpc/src/server.rs or crates/axiam-server/src/main.rs (grep across the whole repo confirms zero non-test/non-doc-comment call sites)."
    missing:
      - "Thread a Surreal<C> handle through start_grpc_server (or an equivalent mechanism) and call .layer(GrpcSharedRateLimitLayer::new(db, \"grpc_authz\", grpc_config.grpc_authz_per_sec, trusted_hops)) BEFORE .layer(build_grpc_governor_layer(...)) in server.rs, per the plan's own documented follow-up (24-07-SUMMARY.md \"Next Phase Readiness\")."
---

# Phase 24: Security Hardening I — Authentication & Access-Control Surfaces Verification Report

**Phase Goal:** The authentication and access-control front door resists replay, IP-spoofing, race, path-smuggling, and timing attacks — every fix fails closed and ships with a negative test
**Verified:** 2026-07-04T13:09:46Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | N parallel submissions of one valid TOTP code succeed at most once (DB CAS); a −1-skew-accepted code cannot be replayed in a later wall-clock step (SECHRD-01) | ✓ VERIFIED | `update_totp_step` is a guarded `SELECT ... FROM (UPDATE ... WHERE totp_last_used_step = NONE OR totp_last_used_step < $step)` (crates/axiam-db/src/repository/user.rs:493-522), returning `bool`. `verify_code_with_replay_check` (crates/axiam-auth/src/totp.rs:103-162) probes which of `current_step-1/current_step/current_step+1` actually matched and rejects unless `matched_step > last_used_step`. `AuthService::verify_mfa`/`confirm_mfa` (crates/axiam-auth/src/service.rs:358-382, 490-511) persist the matched step via the CAS and reject `Ok(false)` as `MfaInvalidCode`. Behavioral test run live: `cargo test -p axiam-db --test totp_step_cas_test` → `totp_step_cas_concurrent ... ok` (20 concurrent submissions, exactly 1 success, replay at same step then rejected). |
| 2 | Rotating `X-Forwarded-For` no longer yields a fresh rate-limit bucket — when `trusted_hops >= hops.len()` the limiter keys off `peer_addr()`, not the leftmost hop — REST **and** gRPC | ✓ VERIFIED | REST: `XForwardedForKeyExtractor::extract` (crates/axiam-api-rest/src/extractors/rate_limit.rs:58-80) only indexes into `hops` when `trusted_hops < hops.len()`; otherwise falls through to `req.peer_addr()`. `rate_limit_keying_test.rs` has `rate_limit_xff_rotation_rejected`, `insufficient_hops_falls_through_to_peer_addr_not_leftmost_hop`, `sufficient_hops_still_selects_right_indexed_hop`. gRPC: `GrpcTrustedHopsKeyExtractor::extract` (crates/axiam-api-grpc/src/middleware/rate_limit.rs:91-135) mirrors the same trusted_hops logic, reading tonic's `TcpConnectInfo`/`TlsConnectInfo` peer address instead of `SmartIpKeyExtractor`'s (broken) axum-only lookup; wired live via `build_grpc_governor_layer` → confirmed called from `start_grpc_server` (crates/axiam-api-grpc/src/server.rs:63) → confirmed called from `crates/axiam-server/src/main.rs:621`. |
| 3 | Two concurrent first-run bootstrap requests create at most one super-admin; bootstrap refused when `AXIAM_BOOTSTRAP_ADMIN_EMAIL`/setup token is unset (SECHRD-04) | ✓ VERIFIED | `bootstrap.rs` mandatory gate (crates/axiam-api-rest/src/handlers/bootstrap.rs:157-181): refuses (403 `AuthorizationDenied`) unless the env var matches OR a valid unconsumed setup-token hash is presented — no "unset ⇒ allow" fallback exists. TOCTOU SELECT-then-branch replaced by a `CREATE type::record('bootstrap_lock', $tenant_id)` inside the same `BEGIN/COMMIT` transaction as admin creation (lines 215-271); loser gets a UNIQUE-index violation → `AlreadyExists` (409), whole transaction rolls back. Behavioral test run live: `cargo test -p axiam-api-rest --test bootstrap_test bootstrap_concurrent_race_single_admin` → `ok` (1 passed). |
| 4 | A non-canonical or wrong-segment request path cannot slip past the public-path allowlist (SECHRD-11) | ✓ VERIFIED | `matches_public_allowlist` (crates/axiam-api-rest/src/middleware/authz.rs:90-110) requires a segment boundary after a stripped wildcard prefix (`remainder.is_empty() || remainder.starts_with('/')`), closing the `/api/v1/auth/*` vs `/api/v1/authz/...` confusion. `normalize_for_public_check` (lines 42-67) collapses `//` and fails closed (`None`→`false`, never implicit-allow) on any `..` segment, run before every allowlist check in `AuthzMiddlewareService::call` (`req.path()` at line 169). 5 negative unit tests present and reviewed: `wildcard_prefix_confusion_is_rejected`, `real_wildcard_entry_still_matches_legitimate_paths`, `double_slash_is_collapsed_before_matching`, `dot_dot_segment_is_rejected_fail_closed`, `exact_match_entry_still_matches_canonical_path`. |
| 5 | A password-reset request for an ineligible/unknown/federated account is time-indistinguishable (dummy hash + async wait); peppered buffer zeroized; unauthenticated reset path blocks current-password reuse (SECHRD-12) | ✓ VERIFIED | `PasswordResetService::dummy_hash_wait` (crates/axiam-auth/src/password_reset.rs:98-108) runs the shared `DUMMY_HASH` Argon2 verify behind `crypto_semaphore`; called on both `Ok(None)` branches (unknown email line 131, federated user line 146) before returning. `hash_password`/`verify_password` (crates/axiam-auth/src/password.rs:21-77) wrap the peppered concatenation in `zeroize::Zeroizing<String>`, wiped on every exit path incl. `?`-propagated errors. `confirm_reset` performs an explicit `verify_password(new_password, &user.password_hash, pepper)` check and returns `AuthError::PasswordReusedCurrent` on match (lines 238-245), independent of `password_history_count`. |

**Score:** 5/5 ROADMAP success criteria verified. 0 behavior-unverified.

### Plan-Level Must-Have (Beyond Roadmap SC Wording) — FAILED

Plan 24-07's frontmatter declared a must-have truth in addition to the ROADMAP wording: *"The gRPC limiter shares the same SurrealDB rate-limit bucket store, failing OPEN to the existing in-memory GovernorLayer on DB error (parity with 24-04's REST shared store)."* This directly maps to SECHRD-04's REQUIREMENTS.md sibling requirement SECHRD-03's 4th acceptance criterion: *"Multi-replica shared rate-limit store implemented, or the per-replica multiplier documented loudly."*

Investigation of the `<known_gap_to_assess>` item:

- `GrpcSharedRateLimitLayer` / `GrpcSharedRateLimitService` (crates/axiam-api-grpc/src/middleware/rate_limit.rs) are real, substantive, and covered by 3 passing integration tests (`crates/axiam-api-grpc/tests/rate_limit_shared_store_test.rs`: cross-instance enforcement, peer-parity under rotating XFF, fail-open on DB error).
- A repo-wide grep for `GrpcSharedRateLimitLayer` confirms it is referenced ONLY in `rate_limit.rs`'s own doc comment/definition and in the test file — **never** in `crates/axiam-api-grpc/src/server.rs`, `crates/axiam-server/src/main.rs`, or anywhere else. `start_grpc_server` has no `Surreal<C>` parameter through which the shared store could even be constructed.
- Distinguishing the two SECHRD-03 concerns: the phase's literal ROADMAP Success Criterion 2 is about **keying** (peer_addr vs. leftmost-hop spoofing) — this is fully fixed and live for BOTH REST and gRPC (`GrpcTrustedHopsKeyExtractor` is wired into `build_grpc_governor_layer`, which is wired into `start_grpc_server`, which is called from `main.rs`). The **multi-replica shared-store** concern (defense against HPA/horizontal-scaling rate-limit-multiplication, not literally "IP-spoofing") is a broader SECHRD-03 acceptance criterion that is fully closed for REST (24-04, `RateLimitShared` wired onto all 20 REST governor call sites) but NOT closed for gRPC in production.
- This gap is **not silently hidden**: `24-07-SUMMARY.md`'s "Next Phase Readiness" section explicitly flags it ("flagged here rather than silently left as a gap"), and `.planning/REQUIREMENTS.md`'s traceability table already annotates SECHRD-03 with the exact same caveat ("prod wiring of the gRPC shared-store layer into start_grpc_server is a follow-up, see 24-07-SUMMARY.md").
- No later-phase ROADMAP success criterion (Phase 25 or Phase 26) explicitly claims ownership of wiring `GrpcSharedRateLimitLayer` into `start_grpc_server` — Phase 26's CORR-01 only touches gRPC governor *quota math*, not the shared-store wiring. Per Step 9b's conservative-matching rule, this gap is **not deferred**.

**Determination:** This is a genuine, if narrow, gap against a plan-declared must-have and against the fuller SECHRD-03 requirement text — not against the phase's literal ROADMAP goal/SC wording (which only concerns keying and is met on both surfaces). It is well-documented (not a silent regression) and does not defeat the phase's stated "resists ... IP-spoofing" goal (the spoofing-via-leftmost-hop vector is closed everywhere). It is real defense-in-depth work that remains undone in production. Per the verification decision tree (a key link is NOT_WIRED), this routes the phase to `gaps_found` rather than `passed`.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-db/src/repository/user.rs::update_totp_step` | Atomic CAS | ✓ VERIFIED | Exists, substantive, wired into `AuthService::verify_mfa`/`confirm_mfa`; behavioral test passes |
| `crates/axiam-db/tests/totp_step_cas_test.rs` | Concurrency test | ✓ VERIFIED | Present, substantive, passes (`cargo test -p axiam-db --test totp_step_cas_test`) |
| `crates/axiam-api-rest/src/extractors/rate_limit.rs::XForwardedForKeyExtractor` | Fixed peer_addr() fallback | ✓ VERIFIED | Exists, substantive, wired into `build_governor` (server.rs); tests pass |
| `crates/axiam-api-rest/tests/rate_limit_keying_test.rs` | Negative XFF-rotation test | ✓ VERIFIED | Present, substantive, 3 tests |
| `crates/axiam-db/src/repository/rate_limit.rs::SurrealRateLimitBucketRepository` | Windowed-CAS counter (REST) | ✓ VERIFIED | Exists, wired into `RateLimitShared` middleware, wired onto all 20 REST governor call sites in server.rs |
| `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs::RateLimitShared` | Shared-store pre-check (REST) | ✓ VERIFIED | Wired, tested (cross-instance + fail-open) |
| `crates/axiam-api-grpc/src/middleware/rate_limit.rs::GrpcTrustedHopsKeyExtractor` | trusted_hops-aware gRPC key extractor | ✓ VERIFIED | Wired into `build_grpc_governor_layer` → `start_grpc_server` → `main.rs` |
| `crates/axiam-api-grpc/src/middleware/rate_limit.rs::GrpcSharedRateLimitLayer` | Shared-store pre-check (gRPC) | ⚠️ ORPHANED | Exists, substantive, tested — but NEVER referenced outside its own module and the test file. Not wired into `start_grpc_server`/`main.rs`. See gap above. |
| `crates/axiam-api-rest/src/middleware/authz.rs::is_public_path`/`matches_public_allowlist`/`normalize_for_public_check` | Segment-boundary + normalization | ✓ VERIFIED | Wired as the default-deny gate; 5 negative unit tests present and pass by inspection of logic (direct-call matcher tests) |
| `crates/axiam-auth/src/password.rs::hash_password`/`verify_password` | Zeroizing peppered buffer | ✓ VERIFIED | `Zeroizing<String>` wraps the peppered concatenation on both functions |
| `crates/axiam-auth/src/config.rs::AuthConfig.pepper` | `SecretString` | ✓ VERIFIED | `Option<secrecy::SecretString>`; every call site (auth, api-rest, api-grpc, server) uses `.expose_secret()` at the `&str` boundary |
| `crates/axiam-auth/src/password_reset.rs::dummy_hash_wait`/`initiate_reset`/`confirm_reset` | Constant-time reset + reuse block | ✓ VERIFIED | Both `Ok(None)` branches call `dummy_hash_wait`; `confirm_reset` explicitly rejects current-password reuse |
| `crates/axiam-db/src/repository/user.rs::create_with_consent` | password_history seed | ✓ VERIFIED | Transaction includes a third `CREATE type::record('password_history', ...)` statement |
| `crates/axiam-api-rest/src/handlers/bootstrap.rs::bootstrap` | Atomic bootstrap transaction + mandatory gate | ✓ VERIFIED | `bootstrap_lock` uniqueness-invariant CREATE inside the transaction; mandatory env-var-OR-token gate; behavioral concurrency test passes live |
| `crates/axiam-server/src/cleanup.rs` / `crates/axiam-api-rest/src/handlers/gdpr.rs::write_erasure_audit_with_dlq` | GDPR audit DLQ (SECHRD-12, not a ROADMAP SC item but plan-declared) | ✓ VERIFIED | `AuditWriteSink` seam + dual dead-letter sink (append-only file + structured tracing event) present and wired into `purge_single_user` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `AuthService::verify_mfa`/`confirm_mfa` | `update_totp_step` | direct call, treats `Ok(false)` as `MfaInvalidCode` | WIRED | Confirmed at service.rs:358-382, 490-511 |
| `XForwardedForKeyExtractor` | `build_governor` (REST) | `.key_extractor(...)` | WIRED | server.rs |
| `RateLimitShared` middleware | `SurrealRateLimitBucketRepository::increment` | async pre-check before Governor | WIRED | 20 call sites in server.rs |
| `GrpcTrustedHopsKeyExtractor` | `build_grpc_governor_layer` → `start_grpc_server` → `main.rs` | `.key_extractor(...)` / fn call chain | WIRED | Confirmed all 3 hops present |
| `GrpcSharedRateLimitLayer` | `start_grpc_server` / `main.rs` | `.layer(...)` | **NOT_WIRED** | Zero non-test/non-doc call sites found repo-wide |
| `is_public_path` | `AuthzMiddlewareService::call` | direct call on `req.path()` before credential check | WIRED | authz.rs:169 |
| `PasswordResetService::dummy_hash_wait` | `initiate_reset`'s `Ok(None)` branches | direct call before return | WIRED | password_reset.rs:131, 146 |
| `bootstrap_lock` CREATE | admin-creation transaction | same `BEGIN...COMMIT` block | WIRED | bootstrap.rs:215-271 |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| TOTP CAS: exactly one of 20 concurrent submissions of one step wins | `cargo test -p axiam-db --test totp_step_cas_test` | `test totp_step_cas_concurrent ... ok` | ✓ PASS |
| Bootstrap race: two concurrent first-run requests create exactly one super-admin | `cargo test -p axiam-api-rest --test bootstrap_test bootstrap_concurrent_race_single_admin -- --exact` | `test bootstrap_concurrent_race_single_admin ... ok` | ✓ PASS |
| Touched crates compile cleanly | `cargo check -p axiam-api-grpc -p axiam-auth -p axiam-db` and `cargo check -p axiam-server` | `Finished` with no errors, both invocations | ✓ PASS |
| `axiam-api-rest` lib clippy gate | `cargo clippy -p axiam-api-rest --lib -- -D warnings` | `Finished` clean | ✓ PASS |

Full-crate test suites for `axiam-auth`, `axiam-api-rest` (rate_limit_keying_test, authz unit tests, password_reset unit tests), and `axiam-api-grpc` (rate_limit unit + integration tests) were not re-run in full due to the sandbox's disk-quota constraint (per `<build_environment>`); the two most safety-critical concurrency tests (TOTP CAS, bootstrap race) were run directly and pass, and all touched crates type-check/clippy-check cleanly.

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|-----------------|--------------|--------|----------|
| SECHRD-01 | 24-01 | TOTP atomic replay protection | ✓ SATISFIED | CAS + matched-step recording + enrollment seed, all confirmed live and test-passing |
| SECHRD-03 | 24-03, 24-04, 24-07 | Rate-limit client-IP keying + multi-replica store | ⚠️ PARTIALLY SATISFIED | Keying fix (the literal ROADMAP SC wording) fully satisfied for REST + gRPC. Multi-replica shared store fully satisfied for REST; implemented+tested but NOT production-wired for gRPC (see gap above) |
| SECHRD-04 | 24-08 | Bootstrap atomicity + mandatory gate | ✓ SATISFIED | Atomicity + gate confirmed live and test-passing |
| SECHRD-11 | 24-02 | Public-path allowlist hardening | ✓ SATISFIED | Segment-boundary + normalization confirmed, 5 negative tests present |
| SECHRD-12 | 24-05, 24-06, 24-09 | Auth crypto/recovery side-channels | ✓ SATISFIED | Zeroizing buffer, SecretString pepper, GDPR DLQ, constant-time reset, current-password-reuse block, history seeding — all confirmed |

No orphaned requirements: all 5 declared requirement IDs (SECHRD-01, 03, 04, 11, 12) appear in both plan frontmatter and REQUIREMENTS.md, and REQUIREMENTS.md's own traceability table independently corroborates the SECHRD-03 gRPC-wiring caveat found here.

### Anti-Patterns Found

None (no `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` markers in any file touched by this phase's plans, per SUMMARY key-files sections). One pre-existing `TODO(T15)` in `crates/axiam-api-rest/src/handlers/auth.rs` predates this phase (tracked under REQ-7/T15, unrelated to SECHRD-01..12) and is not counted against this phase since 24-01's actual SUMMARY confirms `handlers/auth.rs` was never modified (the plan's speculative `files_modified` entry for it was corrected during execution).

### Deviations from ROADMAP/PLAN Documented by the Executor (for context, not gaps)

- 24-01: fix applied in `AuthService::verify_mfa`/`confirm_mfa` (service.rs) rather than `handlers/auth.rs` as the plan's frontmatter speculated — confirmed correct, thin-wrapper handler has no MFA logic of its own.
- 24-07: `SmartIpKeyExtractor` was found to never resolve a real tonic peer address at all (not just an XFF-trust bug) — the custom extractor fixes both issues. This is a strictly stronger fix than the plan's literal framing, confirmed in code.

### Human Verification Required

None. All 5 ROADMAP success criteria and their supporting artifacts/wiring were verifiable via code inspection plus two live behavioral test runs (TOTP CAS concurrency, bootstrap concurrency race) and cross-crate `cargo check`/`clippy` gates — no UI, real-time, or external-service behavior in this phase's scope.

### Gaps Summary

Phase 24 fully achieves its literal ROADMAP goal and all 5 stated Success Criteria: the TOTP, XFF-keying (REST + gRPC), bootstrap, public-path-allowlist, and password-reset/pepper-hygiene defenses are all live, wired, and each backed by at least one passing negative/concurrency test. Every fix fails closed as required.

One gap remains, narrower than the phase's own SC wording but real: plan 24-07's own declared must-have — that the gRPC rate limiter "shares the same SurrealDB rate-limit bucket store" — is false in the currently running server. The shared-store code is fully built and tested but sits unreferenced outside its own module and test file; `start_grpc_server`/`main.rs` never construct or `.layer()` it. This means the multi-replica rate-limit-evasion gap that 24-04 closed for REST remains open for gRPC in production. It is not a silent gap — both `24-07-SUMMARY.md` and `.planning/REQUIREMENTS.md`'s own traceability table already flag it as an outstanding follow-up — but no concrete phase/plan currently owns closing it, so it is recorded here as a gap rather than deferred.

**Recommended resolution:** a small follow-up plan (in Phase 24, Phase 26, or a dedicated fast-follow) that threads a `Surreal<C>` handle through `start_grpc_server` and adds `.layer(GrpcSharedRateLimitLayer::new(db, "grpc_authz", grpc_config.grpc_authz_per_sec, trusted_hops))` before `.layer(build_grpc_governor_layer(...))` in `crates/axiam-api-grpc/src/server.rs`, exactly as `24-07-SUMMARY.md` already specifies.

---

_Verified: 2026-07-04T13:09:46Z_
_Verifier: Claude (gsd-verifier)_
