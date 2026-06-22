---
status: partial
phase: 10-high-remediation
source: [10-VERIFICATION.md]
started: 2026-06-13T11:30:00Z
updated: 2026-06-13T11:30:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. SAML protocol checks (SAML-ON path)
expected: Under `--features saml` in CI/Docker (real xmlsec), the new protocol checks in `saml.rs` (InResponseTo / Destination / Conditions time-window / WantAssertionsSigned / XSW defense) reject malformed/forged assertions, and the `axiam-api-rest` federation_test baseline is still exactly 3 failures (saml_acs/saml_authn/saml_metadata) — not 4+. These cannot be exercised on the local Arch off-path (`--no-default-features`).
result: [pending]

### 2. AMQP dead-letter routing (live broker)
expected: With a real RabbitMQ broker, poison/rejected messages in both the audit and authz consumers land on their `.dlq` queues (DLX declared with `requeue:false`), with parity between the two consumers — no silent message drop.
result: [pending]

### 3. GDPR export completeness (live data)
expected: Against a populated database, a GDPR export blob contains all user-linked data — sessions, role/permission assignments, group memberships, webauthn credentials — and a failed purge is re-selectable (marked `Failed`) and re-runnable; paginated audit export returns the complete set.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
