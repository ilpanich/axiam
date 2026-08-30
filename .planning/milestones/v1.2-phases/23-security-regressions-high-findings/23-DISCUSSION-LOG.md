# Phase 23 — Discussion Log

**Date:** 2026-07-03
**Mode:** discuss (default)

Human reference only — not consumed by downstream agents (see 23-CONTEXT.md for the canonical decisions).

## Gray areas presented
User selected all four to lock down:
1. Webhook key posture (SECFIX-03)
2. Logout revocation (SECFIX-05)
3. Reset-page tenant resolution (SECFIX-06)
4. gRPC ValidateCredentials lockout (SECFIX-01)

Implementation details (gRPC interceptor as shared Layer, SAML XSW binding technique, negative-test placement) were left to Claude's discretion.

## Decisions
| Area | Decision | Rationale |
|------|----------|-----------|
| Webhook key (D-01/02) | Graceful degrade — boot OK, refuse webhook register/deliver until key set; encrypt secret on create+update | Optional subsystem shouldn't block boot; never a zero key; mirrors PKI lazy fail-closed on the same env var |
| Logout (D-03) | Server-side revoke from JWT `jti`, no request body | Simplest robust client, no IDOR; matches review's preferred fix |
| Reset tenant (D-04/05) | Tenant slug in page URL + tenant-bound server token; responses stay enumeration-safe | No user-typed tenant, no email-domain inference; consistent with login's tenant selection |
| gRPC lockout (D-06) | Always-on accrual via shared helper (REST + gRPC) | No unmetered credential-check path even for authenticated mesh peers |

## Interaction note
The interactive question picker (AskUserQuestion) was unavailable due to a permission-stream error across two attempts. The four areas were confirmed for discussion in the first (successful) multiSelect; the per-area decisions were then locked to the recommended security defaults. Decisions are recorded in 23-CONTEXT.md and may be edited there before planning if any default should change.

## Deferred
- Webhook delivery wiring → CORR-03 (Phase 26)
- Constant-time reset / zeroize / GDPR-audit DLQ → SECHRD-12 (Phase 24)
- Playwright-in-CI with body assertions → CORR-04 (Phase 26)
- SAML Recipient/SubjectConfirmation full validation beyond XSW+Destination+InResponseTo → SEC-005 residual

*Phase: 23-security-regressions-high-findings*
