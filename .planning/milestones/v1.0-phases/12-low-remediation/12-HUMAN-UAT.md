---
status: blocked
phase: 12-low-remediation
source: [12-05-PLAN.md, 12-VALIDATION.md]
started: 2026-06-19T12:10:00Z
updated: 2026-06-19T12:10:00Z
blocked_on: Phase 13 (SurrealDB connection resilience) — local first-run bootstrap could not produce a working admin login due to the stale-connection bug
---

## Current Test

[awaiting human testing — run after Phase 13 lands the connection fix and `just dev-up` + `just run-local` + `scripts/e2e-bootstrap.sh` reliably produces a working admin login]

## Tests

### 1. Login → MFA enroll → MFA verify → dashboard
expected: Log in as the seeded admin; enroll MFA (TOTP), verify the code, and land on the dashboard. No spinner hang (regression `ba709b8` fixed `useAuthInit` StrictMode deadlock).
result: [pending]

### 2. Password reset — token stripped from URL after use (SEC-037)
expected: Request reset → email link → set new password → log in with it. After the token is consumed, the URL no longer contains it (`history.replaceState`). Source: `frontend/src/pages/auth/ResetPasswordPage.tsx` (`replaceState`).
result: [pending]

### 3. Email verify — token stripped from URL (SEC-037)
expected: Click the verify link → success page; the token is stripped from the URL after the call. Source: `frontend/src/pages/auth/VerifyEmailPage.tsx` (`replaceState`).
result: [pending]

### 4. Change password — HIBP check on compromised password (CQ-B35)
expected: Changing to a known-breached password is rejected by the HIBP k-anonymity check on the sync change-password path. Source: `crates/axiam-auth/src/service.rs` (`change_password` with `http_client`).
result: [pending]

### 5. GDPR export → download JSON
expected: Request a GDPR Art.15 export and download the resulting JSON for the tenant.
result: [pending]

### 6. Federation OIDC login survives server restart (secret decrypt-at-use)
expected: Complete an OIDC federation login; restart the server; OIDC login succeeds again (the federation client secret is decrypted at use, not cached only in memory). Requires `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` set.
result: [pending]

### 7. Cross-org isolation → 403
expected: As an Org A user, requesting an Org B resource returns 403 (tenant data isolation enforced).
result: [pending]

### 8. gRPC without credentials → UNAUTHENTICATED
expected: A gRPC authz call with no credentials is rejected with `UNAUTHENTICATED`. gRPC on `127.0.0.1:50051`.
result: [pending]

### 9. Bootstrap page after admin exists → 404 → "already initialized" (CQ-F34)
expected: With an admin already created, the bootstrap flow returns 404 and the UI shows the friendly "Already Initialized / Sign in" state — not a confusing error. Source: `frontend/src/pages/BootstrapPage.tsx` (404 → `alreadyInitialized`).
result: [pending]

### 10. Admin user create — password-policy checker gates submit (CQ-F23)
expected: On the admin "create user" form, the `PasswordPolicyChecker` is visible and `checkPasswordPolicy` blocks submit until the password meets policy. Source: `frontend/src/pages/users/UsersPage.tsx`.
result: [pending]

### 11. Reveal a secret then close the modal → cleared from React state (SEC-036)
expected: Reveal a secret (certificate / OAuth2 client / PGP key), then close the modal via any path (cancel, ESC/overlay, or after submit); the revealed secret is no longer in React state (verify via React DevTools). Source: 5 pages — certificates / oauth2 / service-accounts / webhooks / pgp.
result: [pending]

## Summary

total: 11
passed: 0
issues: 0
pending: 11
skipped: 0
blocked: 11

## Gaps

- All 11 items are blocked on a reproducible local admin login. The local first-run
  flow is broken by the SurrealDB stale-connection bug (server silently queries the
  empty default namespace after an idle WebSocket reconnect). Tracked as **Phase 13:
  SurrealDB Connection Resilience**. Re-run this UAT once Phase 13 is complete.
- Setup prerequisites once Phase 13 lands: `just dev-up` (deps only) → `just run-local`
  (server, no-saml, keygen) → seed org+tenant+admin (`scripts/e2e-bootstrap.sh` after
  its `surreal-db` is corrected to `main`, or the documented manual seed).
