---
phase: 2
slug: security-headers-rate-limiting
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-04
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | actix-web test (`actix_web::test`) + `#[actix_web::test]` macro |
| **Config file** | None — tests are integration tests in `crates/axiam-api-rest/tests/` |
| **Quick run command** | `cargo test -p axiam-api-rest --test security_headers_test 2>&1 \| tail -5` |
| **Full suite command** | `cargo test -p axiam-api-rest 2>&1 \| tail -20` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-api-rest 2>&1 | tail -10`
- **After every plan wave:** Run `cargo test -p axiam-api-rest && cargo test -p axiam-api-grpc`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | REQ-2 | integration | `cargo test -p axiam-api-rest --test security_headers_test test_security_headers_present` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | REQ-2 | integration | `cargo test -p axiam-api-rest --test security_headers_test test_x_frame_options_deny` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | REQ-2 | integration | `cargo test -p axiam-api-rest --test security_headers_test test_referrer_policy` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 1 | REQ-2 | manual | `curl -I http://localhost:8080` | manual-only | ⬜ pending |
| 02-03-01 | 03 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_login_rate_limit` | ❌ W0 | ⬜ pending |
| 02-03-02 | 03 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_register_rate_limit` | ❌ W0 | ⬜ pending |
| 02-03-03 | 03 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_token_rate_limit` | ❌ W0 | ⬜ pending |
| 02-03-04 | 03 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_password_reset_rate_limit` | ❌ W0 | ⬜ pending |
| 02-03-05 | 03 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test rate_limit_test test_429_response_format` | ❌ W0 | ⬜ pending |
| 02-04-01 | 04 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test auth_test` | ✅ | ⬜ pending |
| 02-04-02 | 04 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test user_test test_user_response_includes_lock_fields` | ❌ W0 | ⬜ pending |
| 02-04-03 | 04 | 2 | REQ-3 | integration | `cargo test -p axiam-api-rest --test user_test test_unlock_user` | ❌ W0 | ⬜ pending |
| 02-05-01 | 05 | 3 | REQ-3 | manual | gRPC rate limit — Tower layer inspection + manual test | manual-only | ⬜ pending |
| 02-06-01 | 06 | 3 | REQ-3 | manual | Frontend lockout badge/filter/unlock — visual inspection | manual-only | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-api-rest/tests/security_headers_test.rs` — stubs for REQ-2 header verification
- [ ] `crates/axiam-api-rest/tests/rate_limit_test.rs` — stubs for REQ-3 rate limiting (actix test client sends N requests)
- [ ] actix-governor and tower-governor added to Cargo.toml (workspace + crate-level)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Nginx CSP/HSTS/Permissions-Policy headers | REQ-2 | Nginx config is not testable in Rust integration tests | `curl -I http://localhost:8080` and verify headers present |
| gRPC brute-force protection | REQ-3 | Tower layer requires running gRPC server; no test harness | Manual gRPC call repetition or inspection of Tower layer code |
| Frontend lockout badge/filter/unlock | REQ-3 | No frontend test framework configured | Visual inspection in browser |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
