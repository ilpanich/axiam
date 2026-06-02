---
phase: 5
slug: email-delivery-gdpr-compliance
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-02
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `05-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[cfg(test)]` + actix-web test + SurrealDB in-memory (`kv-mem`) |
| **Config file** | None — inline test module pattern |
| **Quick run command** | `cargo test -p axiam-api-rest -p axiam-amqp -p axiam-audit --lib` |
| **Full suite command** | `cargo test -p axiam-api-rest` |
| **Estimated runtime** | ~30–60 seconds (per-crate; RabbitMQ required for mail-consumer integration tests) |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p axiam-api-rest -p axiam-amqp -p axiam-audit --lib`
- **After every plan wave:** Run `cargo test -p axiam-api-rest`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

> Requirement-level map seeded from research. Task IDs ({N}-PP-TT) are filled in by the
> planner per plan/wave; rows below map each phase behavior to its automated proof.

| Behavior | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|----------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| Password reset handler enqueues mail (mock AMQP) | REQ-6 (T19.11) | — | Token never returned in response body | unit | `cargo test -p axiam-api-rest password_reset` | ⚠️ partial (handler exists) | ⬜ pending |
| Email verification handler enqueues mail | REQ-6 (T19.12) | — | Token never returned in response body | unit | `cargo test -p axiam-api-rest email_verification` | ⚠️ partial | ⬜ pending |
| Notification dispatcher enqueues instead of returning list | REQ-6 (T19.13) | — | Dispatch is fire-and-forget via AMQP | unit | `cargo test -p axiam-audit notification` | ❌ W0 | ⬜ pending |
| `email.delivery_failed` audit event on exhausted retries | REQ-6 | T-5-delivery | Failure recorded with retry count | unit | `cargo test -p axiam-amqp mail_consumer` | ❌ W0 | ⬜ pending |
| Reset/verify returns `{"sent": true}` for unknown emails | REQ-6 | T-5-enum (V2) | Uniform 200 regardless of address existence (D-15) | unit | `cargo test -p axiam-api-rest password_reset::unknown_email` | ⚠️ partial | ⬜ pending |
| Export contains all user data (every table) | REQ-8 | T-5-export | Single-use 24h opaque download token (D-13) | integration | `cargo test -p axiam-api-rest gdpr_test::export_completeness` | ❌ W0 | ⬜ pending |
| Deletion removes PII from all tables | REQ-8 | T-5-delete | Tenant-scoped purge; sessions revoked | integration | `cargo test -p axiam-api-rest gdpr_test::deletion_pseudonymization` | ❌ W0 | ⬜ pending |
| Deleted-user audit entries show `DELETED_USER_<hash>` | REQ-8 | T-5-pseudonym (V6) | Keyed HMAC-SHA256 pepper; no UUID leak (D-02) | integration | part of `gdpr_test::deletion_pseudonymization` | ❌ W0 | ⬜ pending |
| Registration inserts consent record | REQ-8 | — | Consent timestamp recorded | integration | `cargo test -p axiam-api-rest gdpr_test::consent_on_registration` | ❌ W0 | ⬜ pending |
| Cancel link aborts deletion, re-enables account | REQ-8 | T-5-cancel | Single-use cancel token (hash-stored) | integration | `cargo test -p axiam-api-rest gdpr_test::deletion_cancel` | ❌ W0 | ⬜ pending |
| Export file encrypted at rest | REQ-8 | T-5-export-rest (V6) | AES-256-GCM; deleted on download/TTL (D-12) | integration | part of `gdpr_test::export_completeness` | ❌ W0 | ⬜ pending |
| Template values HTML-escaped | REQ-6 | T-5-template (V5) | `render_html` escapes context (D-18) | unit | `cargo test -p axiam-email render_html` | ⚠️ partial | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/axiam-api-rest/tests/gdpr_test.rs` — REQ-8 export completeness + deletion/pseudonymization + consent + cancel
- [ ] `crates/axiam-amqp/tests/mail_consumer_test.rs` — REQ-6 delivery-failure audit (new test file)
- [ ] Mock `EmailService` / `MockProvider` wiring for mail-consumer tests — reuse `crates/axiam-email/src/providers/mock.rs` via `with_provider(Box::new(MockProvider::new()))`

*Existing infrastructure (inline `#[cfg(test)]` + SurrealDB `kv-mem`) covers everything else.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real email arrives in inbox (end-to-end SMTP/provider) | REQ-6 | Requires live provider + real mailbox; not deterministic in CI | `just dev-up`, configure a real provider, trigger reset, confirm receipt + working link |

*All other phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (gdpr_test.rs, mail_consumer_test.rs, mock wiring)
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
