---
status: partial
phase: 01-cookie-based-authentication
source: [01-VERIFICATION.md]
started: 2026-04-04T18:00:00Z
updated: 2026-04-04T18:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Cookie Secure flag over HTTPS
expected: axiam_access, axiam_refresh, axiam_csrf all have Secure flag when served over HTTPS
result: [pending]

### 2. CSRF cookie readable by JavaScript
expected: document.cookie shows axiam_csrf but NOT axiam_access or axiam_refresh (httpOnly)
result: [pending]

### 3. Auth initialization flow
expected: App shows spinner, then redirects to login (no session) or loads dashboard (valid session)
result: [pending]

### 4. Silent refresh on token expiry
expected: After access token expires, next API call triggers transparent refresh without user interaction
result: [pending]

### 5. Cross-tab logout detection
expected: Logging out in one tab causes other tabs to detect unauthenticated state on next API call
result: [pending]

## Summary

total: 5
passed: 0
issues: 0
pending: 5
skipped: 0
blocked: 0

## Gaps
