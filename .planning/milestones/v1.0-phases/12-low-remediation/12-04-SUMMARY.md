---
phase: 12-low-remediation
plan: "04"
subsystem: ui
tags: [react, typescript, security, information-disclosure, browser-history, pii]

requires:
  - phase: 12-low-remediation
    provides: "Plans 01-03 closed prior LOW findings; this plan closes SEC-036/037/041"

provides:
  - "Secret-reveal modal onClose clears revealed secret from React state (5 pages)"
  - "Reset/verify tokens stripped from browser URL via history.replaceState after use"
  - "ForgotPasswordPage catch clause no longer logs AxiosError carrying user email"

affects: [12-05]

tech-stack:
  added: []
  patterns:
    - "onClose handler clears both the open-flag state AND the secret-bearing state in a single arrow function"
    - "history.replaceState called immediately after the awaited API call in both success and catch branches"
    - "Bare catch clause (no binding) when the caught value is intentionally discarded"

key-files:
  created: []
  modified:
    - frontend/src/pages/webhooks/WebhooksPage.tsx
    - frontend/src/pages/certificates/CertificatesPage.tsx
    - frontend/src/pages/oauth2/OAuth2ClientsPage.tsx
    - frontend/src/pages/service-accounts/ServiceAccountsPage.tsx
    - frontend/src/pages/pgp/PgpKeysPage.tsx
    - frontend/src/pages/auth/ResetPasswordPage.tsx
    - frontend/src/pages/auth/VerifyEmailPage.tsx
    - frontend/src/pages/auth/ForgotPasswordPage.tsx

key-decisions:
  - "Used bare catch clause in ForgotPasswordPage to eliminate the unused-vars lint error introduced by removing the err arg"
  - "Cleared all derived secret context (title, desc) in ServiceAccountsPage onClose — removes lingering modal label that identifies the revealed credential"
  - "replaceState placed after the awaited API call in both success and error branches per Pitfall 5 (would break re-read of searchParams if placed before)"

patterns-established:
  - "Secret-modal clear pattern: onClose={() => { setOpen(false); setRevealedValue(''); }}"
  - "URL-token strip pattern: window.history.replaceState({}, document.title, window.location.pathname) after the awaited token-consuming call"

requirements-completed: [REQ-16]

duration: 15min
completed: 2026-06-19
---

# Phase 12 Plan 04: Frontend Security LOW Findings (SEC-036/037/041) Summary

**Revealed secrets cleared from React state on modal close (5 pages), reset/verify tokens stripped from URL after use (2 auth pages), and ForgotPasswordPage PII log eliminated**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-06-19T00:00:00Z
- **Completed:** 2026-06-19T00:15:00Z
- **Tasks:** 3
- **Files modified:** 8

## Accomplishments

- SEC-036: All 5 secret-reveal modals (WebhooksPage, CertificatesPage, OAuth2ClientsPage, ServiceAccountsPage, PgpKeysPage) now clear the revealed secret value from React state when closed — prevents credentials from lingering in the JS heap/devtools after the one-time-show modal closes
- SEC-037: ResetPasswordPage and VerifyEmailPage both call `window.history.replaceState` after the token-consuming API call in both success and catch branches — token no longer persists in browser history or referrer headers
- SEC-041: ForgotPasswordPage catch clause changed to bare `catch` (no `err` binding), `console.warn` no longer receives the AxiosError whose `config.data` carries the submitted email — eliminates PII leak to devtools and error-tracking sinks

## Task Commits

1. **Task 1: SEC-036 clear revealed secret on modal close (5 pages)** - `e6d9565` (fix)
2. **Task 2: SEC-037 strip reset/verify tokens from URL** - `002f13d` (fix)
3. **Task 3: SEC-041 redact email from ForgotPasswordPage failure log** - `d75142a` (fix)

## Files Created/Modified

- `frontend/src/pages/webhooks/WebhooksPage.tsx` - `onClose` clears `revealedSecret`
- `frontend/src/pages/certificates/CertificatesPage.tsx` - `onClose` clears `privateKeyPem`
- `frontend/src/pages/oauth2/OAuth2ClientsPage.tsx` - `onClose` clears `revealedClientId` + `revealedSecret`
- `frontend/src/pages/service-accounts/ServiceAccountsPage.tsx` - `onClose` clears `revealedClientId`, `revealedSecret`, `secretModalTitle`, `secretModalDesc`
- `frontend/src/pages/pgp/PgpKeysPage.tsx` - `onClose` clears `privateKeyArmor`
- `frontend/src/pages/auth/ResetPasswordPage.tsx` - `replaceState` after `confirmPasswordReset` in both success and catch
- `frontend/src/pages/auth/VerifyEmailPage.tsx` - `replaceState` after `verifyEmail` in both success and catch
- `frontend/src/pages/auth/ForgotPasswordPage.tsx` - bare `catch`, no `err` in `console.warn`

## Decisions Made

- Bare catch clause preferred over `catch (_err)` — clearer intent (the error is intentionally discarded for anti-enumeration) and eliminates the lint issue without a suppression comment
- ServiceAccountsPage onClose also resets `secretModalTitle` and `secretModalDesc` since they carry derived secret context (labels like "Service Account Created" / "Secret Rotated")
- `replaceState` placed AFTER the awaited call per plan Pitfall 5 note — placing it before would break searchParams re-read if the component re-renders during the async window

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed unused `err` catch binding in ForgotPasswordPage**
- **Found during:** Task 3 final lint gate (`npm run lint`)
- **Issue:** Removing `err` from `console.warn` left the catch binding unused, triggering `@typescript-eslint/no-unused-vars` ESLint error
- **Fix:** Changed `catch (err) {` to `catch {` (bare catch clause — valid TypeScript)
- **Files modified:** `frontend/src/pages/auth/ForgotPasswordPage.tsx`
- **Verification:** `npm run lint` reports zero issues
- **Committed in:** `d75142a` (Task 3 commit, amended)

---

**Total deviations:** 1 auto-fixed (Rule 1 - lint/compiler error)
**Impact on plan:** Minor follow-through on the SEC-041 fix; no scope creep.

## Issues Encountered

None beyond the unused-var lint fix documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All SEC-036/037/041 LOW findings resolved
- Ready for plan 12-05

---
*Phase: 12-low-remediation*
*Completed: 2026-06-19*
