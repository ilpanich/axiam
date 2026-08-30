# Phase 23: Security Regressions & HIGH Findings - Context

**Gathered:** 2026-07-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the six critical/HIGH security regressions surfaced by the two post-remediation reviews (2026-07-01), each fail-closed and each proven by a NEGATIVE test that demonstrates the attack is now rejected. Scope is exactly SECFIX-01..06 — no other findings, no refactors beyond what a given fix strictly requires.

- **SECFIX-01 / SEC-003** — attach auth to gRPC `UserService` + `TokenService`
- **SECFIX-02 / SEC-058** — tenant guard on the live `grant_to_role_with_scopes` path
- **SECFIX-03 / SEC-059+031** — webhook encryption key fail-closed + encrypt-at-rest
- **SECFIX-04 / SEC-005** — SAML signature↔assertion binding (XSW) + Destination/InResponseTo
- **SECFIX-05 / SEC-015** — logout actually revokes the session
- **SECFIX-06 / SEC-044** — reset/resend flows carry `tenant_id`, stay enumeration-safe

Out of scope for Phase 23 (tracked elsewhere in v1.2): webhook *delivery* wiring (CORR-03, Phase 26 — depends on SECFIX-03), Playwright-in-CI (CORR-04, Phase 26), the SECHRD-* medium hardening (Phases 24–25).
</domain>

<decisions>
## Implementation Decisions

> These four were confirmed as the recommended security defaults during discuss-phase (the interactive picker was unavailable; defaults were locked and may be edited here before planning). The rest are Claude's discretion.

### Webhook encryption-key posture (SECFIX-03)
- **D-01:** **Graceful degrade.** The server boots when `AXIAM__PKI__ENCRYPTION_KEY` is unset; webhook **registration and delivery are refused** (explicit error + `warn!`) until a key is present. NEVER substitute an all-zero (or any constant) key. This mirrors PKI's lazy fail-closed on the same env var — an optional subsystem must not block whole-server boot, but must never operate under a bogus key.
- **D-02:** On create AND update, the webhook secret is encrypted with AES-256-GCM before storage (call `encrypt_webhook_secret` on both write paths); the response continues to exclude the secret (`skip_serializing`); the update DTO exposes secret rotation.

### Logout revocation (SECFIX-05)
- **D-03:** **Server-side revocation from the authenticated JWT `jti`, no request body.** The logout handler revokes the caller's own session using `jti` from the validated token; the frontend posts nothing. No client-supplied `session_id`, no IDOR surface. All three auth cookies are cleared server-side. Frontend `handleLogout` must stop sending `{}`/`{session_id}` and must no longer 400.

### Reset/verify tenant resolution (SECFIX-06)
- **D-04:** **Tenant slug carried in the page URL + tenant-bound server token.** The public reset/verify pages carry the tenant slug in their URL (consistent with how login already establishes tenant selection); the emailed confirm link carries the server-generated, tenant-scoped token. The frontend threads `tenant_id`/`email` into `requestPasswordReset`, `confirmPasswordReset`, `resendVerification` to match the backend DTOs. No user-typed tenant field, no email-domain inference.
- **D-05:** Responses stay **enumeration-safe** — a constant response (and constant-ish timing) regardless of whether the account exists or is federated. (Deeper constant-time work is SECHRD-12/Phase 24; Phase 23 must not regress the existing enumeration-safety.)

### gRPC ValidateCredentials lockout (SECFIX-01 / SEC-026b)
- **D-06:** **Always-on lockout accrual via a shared helper.** Factor the REST-login failed-attempt/lockout counter into a shared helper that BOTH the REST login path and gRPC `ValidateCredentials` call, so there is no unmetered credential-check path even for an authenticated mesh peer. Not behind a config flag.

### Claude's Discretion
- **gRPC auth wiring (SECFIX-01):** apply the existing `AuthInterceptor` to `UserService` and `TokenService` — prefer a single shared tower `Layer` across all three gRPC services over per-service duplication if clean. Derive `tenant_id`/`user_id` from `ValidatedClaims` and reject any mismatched body field, exactly as `AuthorizationService` already does. Add reject-without-token tests for both services.
- **SECFIX-02 mechanics:** apply the same `LET … IF array::len = 0 { THROW }` tenant predicate to BOTH branches (empty-scope and scoped) of `grant_to_role_with_scopes`; additionally validate every scope id belongs to the caller's tenant. Repoint the existing tenant-isolation test at the REST-reachable `grant_to_role_with_scopes` path (not the already-guarded `grant_to_role`).
- **SECFIX-04 mechanics:** bind the verified XML-signature reference ID to the assertion actually consumed by `handle_saml_response` (reject when they differ); pass the real ACS URL to the `Destination` check (stop passing `None`); require `InResponseTo` on the authenticated ACS path; add an XSW negative test (wrapped/duplicated assertion rejected).
- **Test placement:** Rust negative tests in the owning crate's `tests/` (`axiam-api-grpc/tests/`, `axiam-db` isolation test, `axiam-federation`/server SAML tests); frontend logout/reset behavior is validated by Playwright specs (execution gated in CI under CORR-04, Phase 26). Per-crate builds only.
- **Per-PLAN `<threat_model>`:** the security capability is active — each PLAN.md carries a threat-model block (ASVS-aligned) for the control it touches.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Authoritative finding descriptions
- `claude_dev/security-review-postremediation.md` — SEC-003 (§High), SEC-058, SEC-059, SEC-005, SEC-015, SEC-044 — the exact issue + suggested fix per finding
- `claude_dev/code-review-postremediation.md` — CQ-B22 (webhook delivery, deferred to Phase 26), CQ-B44, CQ-F05 (logout frontend), CQ-F27 (reset/resend frontend)

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` — v1.2 section, SECFIX-01..06 acceptance criteria + verification baseline
- `.planning/ROADMAP.md` §"Phase 23" — goal + 5 success criteria (each includes a negative test)
- `CLAUDE.md` — security standards: Argon2id, EdDSA/Ed25519 JWT, AES-256-GCM at rest, additive-only RBAC, fail-closed, per-crate build discipline

### Code surfaces (verify current file:line — drifted since review commit ea85872)
- `crates/axiam-api-grpc/src/server.rs`, `middleware/auth.rs`, `services/{authorization,user,token}.rs` — SECFIX-01
- `crates/axiam-db/src/repository/permission.rs`, `crates/axiam-api-rest/src/handlers/permissions.rs` — SECFIX-02
- `crates/axiam-server/src/main.rs`, `crates/axiam-api-rest/src/webhook.rs`, `handlers/webhooks.rs`, `crates/axiam-db/src/repository/webhook.rs` — SECFIX-03 (mirror the PKI `Option<[u8;32]>` fail-closed pattern)
- `crates/axiam-federation/src/saml.rs`, `crates/axiam-api-rest/src/handlers/federation.rs` — SECFIX-04
- `crates/axiam-api-rest/src/handlers/auth.rs`, `frontend/src/components/layout/Topbar.tsx` — SECFIX-05
- `crates/axiam-api-rest/src/handlers/{password_reset,email_verification}.rs`, `frontend/src/services/auth.ts` — SECFIX-06
- `.planning/phases/23-security-regressions-high-findings/23-RESEARCH.md` — phase researcher's current-code location map (if present)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **gRPC `AuthorizationService` interceptor pattern** (`services/authorization.rs:73-99`) — the working chokepoint: identity from verified JWT, every body field cross-validated and rejected on mismatch. Replicate for User/Token services.
- **PKI fail-closed `Option<[u8;32]>`** — the SEC-012 remediation pattern to mirror for the webhook key (never a constant fallback).
- **`grant_to_role` tenant guard** (`permission.rs`) — the `LET/THROW` predicate to lift into `grant_to_role_with_scopes`.
- **REST login lockout counter** — the atomic failed-login/backoff logic (SEC-032) to factor into a shared helper for D-06.
- **CSRF double-submit + cookie auth** — logout must clear all three cookies (access/refresh/csrf) consistently with the existing cookie scheme.

### Established Patterns
- Trait-in-core / impl-in-db / thin-handler; per-crate `cargo check/test -p <crate>` (never full workspace); `cargo fmt` + `clippy -D warnings` before commit.
- Fail-closed is the default posture for every auth/authz/crypto/federation control.
- Existing negative-test suites: `crates/axiam-api-grpc/tests/{grpc_auth,grpc_authz}_test.rs`, `req14_tenant_isolation_test.rs`, federation e2e (oidc/saml/clock-skew), frontend Playwright `e2e/`.

### Integration Points
- SECFIX-03 encrypt-on-write is a **hard prerequisite** for CORR-03 webhook delivery (Phase 26) — the delivery path decrypts, so it must be able to.
- SECFIX-05/06 frontend behavior is verified by Playwright specs whose CI execution is fixed in CORR-04 (Phase 26).
- D-06 shared lockout helper is reused by any future credential-check path (keep it the single source of truth).

</code_context>

<specifics>
## Specific Ideas

Every fix ships with a regression test that fails before / passes after; security fixes additionally ship a negative test proving the attack is rejected (this is the phase's defining success signal, not optional). No new `unwrap()`/`expect()`/constant-key fallbacks on security paths; secrets never serialized, logged, or defaulted.

</specifics>

<deferred>
## Deferred Ideas

- Webhook **delivery** wiring (durable AMQP queue + retry + audit status) — CORR-03, Phase 26 (depends on SECFIX-03).
- Deeper **constant-time** reset side-channel + zeroize + GDPR-audit DLQ — SECHRD-12, Phase 24.
- Running Playwright in CI with request-**body** assertions — CORR-04, Phase 26 (this is what actually gates SECFIX-06 in CI).
- SAML `Recipient`/`SubjectConfirmationData` full validation beyond the XSW-binding + Destination/InResponseTo minimum — remainder tracked under SEC-005 residual if not fully closed here.

None of these expand Phase 23 scope — they are the correct home for adjacent work.

</deferred>

---

*Phase: 23-security-regressions-high-findings*
*Context gathered: 2026-07-03*
