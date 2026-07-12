---
phase: 28-functional-completeness
verified: 2026-07-05T21:42:53Z
status: passed
resolved: 2026-07-05T22:10:00Z
score: 11/11 must-haves verified (after human scope decision D-15)
behavior_unverified: 0
overrides_applied: 1
human_resolution: "Both gaps resolved via human scope decision D-15 (2026-07-05). GAP 1 (metadata 'public'): decided to keep the SAML SP metadata endpoint intentionally admin-authenticated (JWT via AuthenticatedUser), NOT public — removed the stale /api/v1/federation/saml/metadata entry from permissions.rs::PUBLIC_PATHS so the middleware allowlist matches the handler, and reworded FUNC-01's AC. Authenticated behavior is covered by federation_test::saml_metadata_returns_xml (20/20 pass, re-run after the fix). GAP 2 (SAML first-time-login e2e): accepted documented deferral — ROADMAP SC1 is satisfied by the proven OIDC path ('oidc/login OR saml/login') and the shared downstream provisioning (provision_new_user) is exercised by the OIDC e2e; a dedicated SAML e2e test is deferred to a future phase. Recorded in REQUIREMENTS.md FUNC-01."
gaps_resolved:
  - truth: "The federation metadata endpoint is reachable with no auth header (ROADMAP SC1 / FUNC-01)"
    status: failed
    reason: >
      GET /api/v1/federation/saml/metadata is listed in permissions.rs::PUBLIC_PATHS (line ~239),
      so AuthzMiddleware bypasses its own JWT/permission check for this path. But the handler
      `saml_metadata` (handlers/federation.rs:952) takes `user: AuthenticatedUser` as its first
      extractor parameter. AuthenticatedUser::from_request (extractors/auth.rs:87-119) calls
      extract_user -> parse_validated_claims, which requires a present, valid JWT and returns
      AxiamError::AuthenticationFailed (401) when absent. A bare unauthenticated GET therefore
      returns 401, not the public/reachable response the roadmap success criterion and FUNC-01's
      AC require. Confirmed by direct source read (not just SUMMARY narrative) and by the fact
      that the ONLY existing test touching this endpoint (federation_test.rs::saml_metadata_returns_xml)
      always sends an Authorization header — no passing or even attempted no-auth test exists.
      This is self-flagged and logged: 28-05-SUMMARY.md Deviations item 5 (Rule 4, deferred
      pending human architectural decision) and STATE.md "Blockers/Concerns" (28-05 entry).
    artifacts:
      - path: "crates/axiam-api-rest/src/handlers/federation.rs"
        issue: "saml_metadata (~line 952) requires AuthenticatedUser, making the PUBLIC_PATHS listing ineffective against the handler's own auth requirement"
    missing:
      - "A human decision on remediation: (a) resolve org/tenant identity from query params (mirroring OidcStartRequest's org_id/org_slug + tenant_id/tenant_slug pattern) and drop the AuthenticatedUser requirement from saml_metadata, reconsidering the resulting data-isolation/IDOR posture for a query-param-driven lookup, OR (b) accept the endpoint is intentionally authenticated and correct FUNC-01's AC / PUBLIC_PATHS / the phase's threat-model wording instead of the code"
      - "After the decision: implement the fix (if (a)) plus a test asserting a bare unauthenticated GET returns a 200/success status, not 401"
  - truth: "POST /auth/federation/saml/login completes the external flow and returns AXIAM tokens for a first-time user with no pre-existing local account (REQUIREMENTS.md FUNC-01 AC1, 'and ... saml/login')"
    status: partial
    reason: >
      saml_login_public/saml_acs_public (handlers/federation.rs ~1407/~1523) exist, are listed in
      PUBLIC_PATHS, and were added to CSRF_EXEMPT_SUFFIXES in this same phase (28-05) alongside the
      OIDC public handlers, and structurally mirror the OIDC first-time-provisioning pattern
      (provision_or_link_user / provision_new_user in axiam-federation's SamlFederationService).
      However, NO test in the codebase drives them end-to-end over HTTP with a first-time
      (no-pre-existing-account) subject: grep across crates/*/tests/*.rs for
      "auth/federation/saml/login" or "auth/federation/saml/acs" (the public paths, distinct from
      the authenticated `/api/v1/federation/saml/acs` account-linking path exercised by
      federation_test.rs) returns zero matches. req5_saml_e2e.rs's saml_happy_path exercises
      SamlFederationService::handle_saml_response directly (service-layer unit test), not the
      public HTTP handler/route/CSRF-exemption pipeline. 28-05's plan explicitly scoped its new
      e2e test to "First-time OIDC SSO" only; the SAML half of REQUIREMENTS.md's FUNC-01 AC1 was
      silently left unexercised and its REQUIREMENTS.md checkbox remains unchecked. This does not
      block ROADMAP.md's own Success Criterion 1, which is phrased as "oidc/login (or /saml/login)"
      and is satisfied by the OIDC proof alone, but it is a real gap against the stricter
      REQUIREMENTS.md wording and leaves this phase's own CSRF-exemption fix for the two SAML paths
      unverified by any automated test.
    artifacts:
      - path: "crates/axiam-api-rest/tests/federation_first_time_sso_test.rs"
        issue: "Covers OIDC start->callback only; no equivalent SAML first-time-login test exists anywhere in the test suite"
    missing:
      - "A SAML-equivalent e2e HTTP test (create SAML federation config -> POST saml/login -> POST saml/acs with a first-time subject -> assert cookies + /auth/me 200), OR an explicit written decision that ROADMAP SC1's 'oidc (or saml)' wording makes this genuinely out of scope, with REQUIREMENTS.md's FUNC-01 AC1 updated/split to reflect that decision"
---

# Phase 28: Functional Completeness Verification Report

**Phase Goal:** The remaining MVP feature gaps are complete and RBAC-gated — first-time federation SSO, session invalidation on reset, admin email-config/user/MFA management, service-account token type, and an SDK-accurate login response schema.
**Verified:** 2026-07-05T21:42:53Z
**Status:** gaps_found
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A first-time OIDC SSO user with no pre-existing local account completes start→callback and receives AXIAM access/refresh cookies; `/auth/me` succeeds (FUNC-01, ROADMAP SC1, closes CQ-B40) | ✓ VERIFIED | `cargo test -p axiam-api-rest --test federation_first_time_sso_test` → 1/1 pass (`first_time_oidc_sso_sets_cookies_and_me_succeeds`). Confirmed real HTTP-level test (not unit-level): drives `POST /api/v1/auth/federation/oidc/start` → `POST /api/v1/auth/federation/oidc/callback` against a wiremock mock IdP, then `GET /api/v1/auth/me`. |
| 2 | The federation metadata endpoint is reachable with no auth header (FUNC-01, ROADMAP SC1) | ✗ FAILED | Source-confirmed: `saml_metadata` (`handlers/federation.rs:952`) requires `AuthenticatedUser`, which 401s with no JWT, despite the path being listed in `PUBLIC_PATHS`. No passing or even attempted no-auth test exists. See gaps. |
| 3 | `POST /auth/federation/saml/login` completes the external flow and returns AXIAM tokens for a first-time user (REQUIREMENTS.md FUNC-01 AC1, "and saml/login") | ⚠ PARTIAL (not blocker per ROADMAP's "or" wording, but a real REQUIREMENTS.md gap) | No e2e/HTTP test exists for the public SAML first-time path; handlers exist structurally but are unexercised end-to-end. See gaps. |
| 4 | Existing authenticated federation endpoints remain for account-linking (FUNC-01 AC2) | ✓ VERIFIED | `handlers/federation.rs` retains the authenticated `oidc_callback`/`saml_acs` (non-public) handlers unchanged; `federation_test.rs` (existing suite, reported 20/20 pass by 28-05-SUMMARY, unaffected by this phase's diffs) exercises the authenticated `/api/v1/federation/saml/acs` linking path. |
| 5 | After a password reset, all prior sessions/refresh tokens for that user are rejected (FUNC-02, ROADMAP SC2) | ✓ VERIFIED | `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` → 1/1 pass (`password_reset_confirm_revokes_existing_sessions`: original cookie → 401 after `POST /api/v1/auth/reset/confirm`). `confirm_reset` (`axiam-auth/src/password_reset.rs:293-302`) calls both `invalidate_user_sessions` and `revoke_all_for_user`. |
| 6 | An admin can CRUD org/tenant `email_config`, gated by `email_config:read`/`email_config:write`, IDOR-blocked, secret-omitting (FUNC-03, ROADMAP SC3) | ✓ VERIFIED | `cargo test -p axiam-api-rest --test email_config_test` → 6/6 pass (round-trip, secret-omission, cross-org/cross-tenant 403, delete→404, D-02 preserve-on-omit). `permissions.rs` has `email_config:read`/`email_config:write` in `PERMISSION_REGISTRY` + 6 `ROUTE_PERMISSION_MAP` entries; `server.rs` registers the 6 routes. `cargo test -p axiam-api-rest --lib route_openapi_parity` → 2/2 pass. |
| 7 | The mail consumer renders a per-org/per-tenant custom template with a fail-safe fallback to built-in on fetch error (FUNC-03, ROADMAP SC3) | ✓ VERIFIED | `cargo test -p axiam-amqp --test mail_consumer_template_test` → 2/2 pass (`custom_tenant_template_is_used_when_present`, `template_fetch_error_falls_back_to_builtin_and_still_attempts_delivery`). `cargo test -p axiam-amqp --test mail_consumer_test` → 5/5 pass (unaffected). |
| 8 | `backfill_plaintext_secrets` is honestly closed as a documented, tested no-op; a NULL-ciphertext row surfaces a clear error at read/send time (FUNC-03, ROADMAP SC3, D-07/D-08) | ✓ VERIFIED | `cargo test -p axiam-db --lib email_config` → 13/13 pass, including `backfill_plaintext_secrets_is_a_noop_on_v15_schema_with_data_present`, `backfill_plaintext_secrets_is_a_noop_on_empty_table`, and `read_path_errors_on_null_ciphertext_row`. `cargo test -p axiam-core --lib models::email` → 36/36 pass (secret skip/redact + omit-preserve tests). |
| 9 | An admin can list users (RBAC-gated) and list/delete another user's MFA methods (RBAC-gated) (FUNC-04, ROADMAP SC4) | ✓ VERIFIED | `cargo test -p axiam-api-rest --test user_test` → 9/9 pass, including `list_users_non_privileged_caller_returns_403` (real-RBAC harness, not `AllowAllAuthzChecker`). MFA cross-user gating (`mfa_methods.rs` `users:admin` at list~66-83/delete~107-124) confirmed by direct code read per the plan's explicit verify-only scope; no new automated test was added for that half (documented in 28-02-SUMMARY as `human_judgment: true`). |
| 10 | Service-account tokens carry `sub_kind: "service_account"`; the claim is informational-only and backward-compatible (FUNC-04, ROADMAP SC4) | ✓ VERIFIED | `cargo test -p axiam-auth --lib token` → 24/24 pass, incl. `issue_service_account_token_stamps_service_account_sub_kind`, `missing_sub_kind_defaults_to_user`, `validate_access_token_accepts_service_account_token`. `cargo test -p axiam-api-rest --test device_auth_test` → 6/6 pass, incl. `device_auth_mints_service_account_sub_kind`. `TODO(T15)` confirmed removed from `auth.rs`; `device_auth` now calls `issue_service_account_token`. |
| 11 | `POST /auth/login` OpenAPI documents 200/202/403/401 as distinct responses (FUNC-05, ROADMAP SC5) | ✓ VERIFIED | `crates/axiam-api-rest/src/handlers/auth.rs:254-265` `#[utoipa::path]` documents 200→`LoginSuccessResponse`, 202→`MfaRequiredResponse`, 403→`MfaSetupRequiredResponse`, 401. `openapi.rs` registers all three schemas. `cargo test -p axiam-api-rest --lib route_openapi_parity` → 2/2 pass. |

**Score:** 9/11 truths verified (1 failed / blocker, 1 partial / non-blocking-but-real requirements gap)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/axiam-core/src/models/email.rs` | Secret skip_serializing + redacting Debug, omit-preserve input semantics | ✓ VERIFIED | `cargo test -p axiam-core --lib models::email` 36/36 pass |
| `crates/axiam-db/src/repository/email_config.rs` | `delete_org_config`, preserve-on-omit `set_org_config`, NULL-ciphertext error, honest backfill | ✓ VERIFIED | `cargo test -p axiam-db --lib email_config` 13/13 pass |
| `crates/axiam-amqp/src/mail_consumer.rs` | `T: EmailTemplateRepository` threaded, fetch-then-resolve with fail-safe fallback | ✓ VERIFIED | `mail_consumer_test.rs` (5/5) + `mail_consumer_template_test.rs` (2/2) pass |
| `crates/axiam-auth/src/token.rs` | `SubjectKind` enum, `sub_kind` claim, `issue_service_account_token` | ✓ VERIFIED | `cargo test -p axiam-auth --lib token` 24/24 pass; grep confirms enum/field/fn present |
| `crates/axiam-api-rest/src/handlers/email_config.rs` | 6 scope-nested singleton handlers | ✓ VERIFIED | File exists, registered in `handlers/mod.rs`, routes wired in `server.rs`, exercised by 6 passing integration tests |
| `crates/axiam-api-rest/src/openapi.rs` | Email-config paths/schemas + 4 public SSO handlers/DTOs documented | ✓ VERIFIED | `route_openapi_parity_test` 2/2 pass; grep confirms `handlers::email_config::*` and the 4 public SSO handlers referenced |
| `crates/axiam-api-rest/tests/federation_first_time_sso_test.rs` | New e2e for first-time OIDC SSO + public metadata assertion | ⚠ PARTIAL | File exists and its one test (`first_time_oidc_sso_sets_cookies_and_me_succeeds`) passes, but the metadata-reachability assertion described in the plan's own acceptance criteria was NOT implemented (deliberately omitted rather than asserting the current, incorrect 401 — see gap 1) |
| `crates/axiam-api-rest/src/handlers/federation.rs` (`saml_metadata`) | Public metadata endpoint reachable with no auth | ✗ NOT MET | Handler requires `AuthenticatedUser`; PUBLIC_PATHS listing does not override the handler's own extractor requirement |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `server.rs` routes | `permissions.rs::ROUTE_PERMISSION_MAP` | email-config triangle | ✓ WIRED | `route_openapi_parity_test` passes both directions |
| `permissions.rs::PUBLIC_PATHS` | `middleware/authz.rs::AuthzMiddleware` | public-path bypass | ✓ WIRED (for the 4 SSO handlers) / ✗ NOT EFFECTIVE (for `saml_metadata`, whose own `AuthenticatedUser` extractor still gates it) | Confirmed via source read of both `authz.rs` and `extractors/auth.rs` |
| `middleware/csrf.rs::CSRF_EXEMPT_SUFFIXES` | 4 public SSO paths | CSRF bypass for unauthenticated first-time login | ✓ WIRED (OIDC, proven by e2e test) / ⚠ UNVERIFIED (SAML — same code change applied, but no test exercises the SAML paths through the real HTTP pipeline) | `federation_first_time_sso_test.rs` proves the OIDC POST succeeds despite no CSRF cookie; no equivalent SAML test exists |
| `mail_consumer.rs::send_with_retry_and_audit` | `EmailTemplateRepository::get_org_template`/`get_tenant_template` → `resolve_template` | template threading | ✓ WIRED | `mail_consumer_template_test.rs` 2/2 pass |
| `main.rs` | `SurrealEmailTemplateRepository` / `SurrealEmailConfigRepository` (REST app_data) | boot wiring | ✓ WIRED | `cargo build -p axiam-server` reported green by 28-03/28-04 SUMMARYs; `main.rs` grep confirms conditional registration |
| `auth.rs::device_auth` (SA cert-auth path) | `issue_service_account_token` | mint-path swap | ✓ WIRED | `TODO(T15)` gone; `device_auth_test.rs` asserts `sub_kind == service_account` |

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|-----------------|--------------|--------|----------|
| FUNC-01 | 28-04, 28-05 | Unauthenticated first-time federation login (OIDC+SAML), public metadata | ✗ BLOCKED (partial) | OIDC first-time flow fully proven (e2e green); public-metadata AC demonstrably false (401 without JWT); SAML first-time flow structurally present but never exercised end-to-end. REQUIREMENTS.md checkboxes remain unchecked for this requirement — consistent with actual state. |
| FUNC-02 | 28-05 | Session invalidation on password reset | ✓ SATISFIED | `password_reset_revokes_sessions` e2e passes; `confirm_reset` unchanged and correct. REQUIREMENTS.md checkboxes remain unchecked (stale bookkeeping — the tool `requirements.mark-complete` doesn't match this file's heading-per-requirement format per 28-03-SUMMARY's "Issues Encountered"; functionally satisfied). |
| FUNC-03 | 28-01, 28-03, 28-04 | Admin email-config API & template delivery | ✓ SATISFIED | All three sub-ACs (T19.20 admin CRUD, T19.21 template resolution, T19.22 backfill honesty) verified by passing tests; REQUIREMENTS.md checkboxes are correctly marked `[x]` for this one. |
| FUNC-04 | 28-02 | Admin user/MFA management + SA token type | ✓ SATISFIED | User-listing RBAC 403 test passes; MFA admin-gating confirmed by code read (plan-scoped verify-only); `sub_kind` claim proven on all three mint paths + backward compat. REQUIREMENTS.md checkboxes remain unchecked (stale bookkeeping, same tool-format gap as FUNC-02/05). |
| FUNC-05 | 28-05 | OpenAPI login response schema | ✓ SATISFIED | `route_openapi_parity_test` passes; `openapi.rs`/`auth.rs` confirmed to document 200/202/403/401 distinctly. REQUIREMENTS.md checkbox remains unchecked (stale bookkeeping). |

**Orphaned requirements:** None found — FUNC-01 through FUNC-05 are exactly the 5 IDs declared across the 5 plans' `requirements:` frontmatter, matching REQUIREMENTS.md's phase-28 mapping table.

**Note on REQUIREMENTS.md bookkeeping:** Acceptance-criteria checkboxes for FUNC-01/02/04/05 remain `[ ]` even though FUNC-02/04/05 are functionally verified complete and FUNC-01 is majority-complete. This is a documented, pre-existing tooling gap (28-03-SUMMARY: `gsd-tools query requirements.mark-complete` doesn't match this file's heading-per-requirement / unlabeled-checkbox format), not a functional defect — but it should be corrected by hand in the phase's closure/gap-fix pass so REQUIREMENTS.md accurately reflects ground truth (checked where true, left unchecked/annotated where FUNC-01's two open items remain).

### Anti-Patterns Found

Scanned all 24 files touched across the 5 plans (models/email.rs, repository.rs, email_config.rs [repo+handler], token.rs, auth.rs, device_auth_test.rs, user_test.rs, mail_consumer.rs + its 2 test files, main.rs, handlers/mod.rs, server.rs, permissions.rs, openapi.rs, email_config_test.rs, federation_first_time_sso_test.rs, password_reset_revokes_sessions.rs, extractors/auth.rs, authz_check_test.rs, oidc.rs, jwks_cache.rs, csrf.rs, schema.rs) for `TBD`/`FIXME`/`XXX` debt markers.

**None found.** No blocker-class debt markers in any phase-modified file. (A pre-existing `TODO(T19.15)` in `federation.rs` — SSO tokens carry `org_id: Uuid::nil()` — predates this phase, is explicitly out of FUNC-01's AC per CONTEXT.md's `FUNC-01-org-id-nil` decision, and is a `TODO` not `TBD`/`FIXME`/`XXX`, so it does not trigger the debt-marker gate.)

### Behavioral Spot-Checks / Test Execution

All automated verification commands were independently re-run by this verifier (not taken from SUMMARY claims):

| Command | Result | Status |
|---------|--------|--------|
| `cargo test -p axiam-core --lib models::email` | 36/36 pass | ✓ PASS |
| `cargo test -p axiam-db --lib email_config` | 13/13 pass | ✓ PASS |
| `cargo test -p axiam-auth --lib token` | 24/24 pass | ✓ PASS |
| `cargo test -p axiam-amqp --test mail_consumer_test` | 5/5 pass | ✓ PASS |
| `cargo test -p axiam-amqp --test mail_consumer_template_test` | 2/2 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --test device_auth_test` | 6/6 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --test user_test` | 9/9 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --test email_config_test` | 6/6 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --lib route_openapi_parity` | 2/2 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` | 1/1 pass | ✓ PASS |
| `cargo test -p axiam-api-rest --test federation_first_time_sso_test` | 1/1 pass | ✓ PASS |
| Source read: `saml_metadata` handler signature + `AuthenticatedUser::from_request` | Confirms unconditional JWT requirement | ✗ CONFIRMS GAP 1 |
| Grep: any test invoking `/api/v1/auth/federation/saml/{login,acs}` (public paths) | Zero matches | ✗ CONFIRMS GAP 2 (partial) |

All commands run with `SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` exported where the crate depends on `axiam-api-rest`. No full-workspace `cargo test` was run (per build-hygiene note); each command was scoped to the specific crate/test binary named in each plan's own `<verify>` block.

### Human Verification Required

None required beyond the architectural decision already captured as gap 1 (which is a code/design decision, not a subjective UX judgment) and the SAML e2e coverage decision in gap 2. Both are structured as gaps (not human-verification items) because they are resolvable by further planning/implementation work, not by a human manually testing running software.

### Gaps Summary

Phase 28 delivers the large majority of its goal correctly and verifiably: FUNC-02, FUNC-03, FUNC-04, and FUNC-05 are fully implemented, RBAC-gated where required, and proven by passing automated tests that this verifier independently re-ran (not just SUMMARY claims). FUNC-01's core deliverable — a first-time OIDC SSO user receiving AXIAM tokens end-to-end — is also genuinely proven by a real HTTP-level e2e test.

However, FUNC-01 is not fully closed:

1. **Blocker:** The federation metadata endpoint (`GET /api/v1/federation/saml/metadata`) is claimed public (listed in `PUBLIC_PATHS`, asserted "public by design" in the phase's own threat model) but empirically requires a valid JWT and 401s without one. This was honestly discovered and self-flagged by the executor (28-05-SUMMARY.md Deviations item 5, STATE.md Blockers/Concerns) as a Rule-4 architectural decision needing human sign-off — this verification independently confirms the finding is accurate via direct source inspection, not merely trusting the SUMMARY's narrative.
2. **Secondary gap (does not block ROADMAP.md's own success-criterion wording, but is real):** REQUIREMENTS.md's FUNC-01 AC1 requires both the OIDC and SAML first-time-login paths to be proven; only OIDC was exercised end-to-end in this phase. The SAML public handlers exist and were touched by this phase's CSRF-exemption fix, but no automated test proves they work for a first-time user over HTTP.

Both gaps require a follow-up planning/implementation pass before FUNC-01 — and therefore the phase — can be marked fully complete. Neither is a "silent" failure: both are traceable to honest, self-documented findings in the executor's own SUMMARY/STATE.md trail, which this verification corroborates against the actual source rather than rubber-stamping.
