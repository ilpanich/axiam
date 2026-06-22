---
phase: 1
slug: cookie-based-authentication
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-01
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `#[actix_rt::test]` (actix-rt 2.x) + in-memory SurrealDB |
| **Config file** | `crates/axiam-api-rest/Cargo.toml` dev-dependencies |
| **Quick run command** | `cargo test -p axiam-api-rest --test auth_test` |
| **Full suite command** | `cargo test -p axiam-api-rest` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-api-rest --test auth_test`
- **After every plan wave:** Run `cargo test -p axiam-api-rest`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | REQ-1 AC1 | integration | `cargo test -p axiam-api-rest --test auth_test -- login_sets_httponly_access_cookie` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | REQ-1 AC2 | integration | `cargo test -p axiam-api-rest --test auth_test -- login_sets_pathscoped_refresh_cookie` | ❌ W0 | ⬜ pending |
| 01-01-03 | 01 | 1 | REQ-1 AC5 | integration | `cargo test -p axiam-api-rest --test auth_test -- csrf_missing_header_returns_401` | ❌ W0 | ⬜ pending |
| 01-01-04 | 01 | 1 | REQ-1 AC6 | integration | `cargo test -p axiam-api-rest --test auth_test -- logout_clears_cookies` | ❌ W0 | ⬜ pending |
| 01-01-05 | 01 | 1 | REQ-1 AC7 | integration | `cargo test -p axiam-api-rest --test auth_test -- refresh_uses_cookie_returns_new_access_cookie` | ❌ W0 | ⬜ pending |
| 01-01-06 | 01 | 1 | REQ-1 AC8 | integration (suite) | `cargo test -p axiam-api-rest` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] New test functions in `crates/axiam-api-rest/tests/auth_test.rs` — stubs for REQ-1 ACs 1, 2, 5, 6, 7
- [ ] Rewrite existing tests: `login_with_valid_credentials_returns_200`, `logout_returns_204`, `refresh_returns_new_tokens`, `mfa_setup_full_flow_returns_tokens`
- [ ] CSRF test helpers — cookie jar extraction utility function

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Frontend: no sessionStorage reads in auth flow | REQ-1 AC3 | Browser-side behavior, no Rust integration test | Grep `frontend/src/` for `sessionStorage` — must return 0 matches in auth code |
| Frontend: Axios uses `withCredentials: true`, no Authorization header | REQ-1 AC4 | Frontend TypeScript, not backend testable | Grep `frontend/src/lib/api.ts` for `withCredentials: true` present, `Authorization` absent |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
