---
status: partial
phase: 05-email-delivery-gdpr-compliance
source: [05-VERIFICATION.md]
started: 2026-06-02
updated: 2026-06-02
---

## Current Test

[awaiting human testing]

## Tests

### 1. Real email delivery end-to-end (live provider)
expected: With a real SMTP/provider configured (`just dev-up`, set an `email_config` row or provider env), triggering a password reset for a real address results in an email arriving in the inbox containing a working reset link. Triggering registration results in a verification email. (All in-process behavior is covered by automated tests; this verifies the actual outbound send + link round-trip against a live mailbox.)
result: [pending]

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
