---
phase: 5
slug: email-delivery-gdpr-compliance
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-02
validated: 2026-06-04
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

| Behavior | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command (test fn) | File Exists | Status |
|----------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| Password reset handler enqueues mail (mock AMQP) + never returns token | REQ-6 (T19.11) | T-5-token-leak | Token never returned in response body | unit | `cargo test -p axiam-api-rest --lib password_reset` (`unknown_email_enqueues_and_returns_sent`, `known_email_never_returns_token`) | ✅ `password_reset.rs` | ✅ green |
| Email verification handler enqueues mail + never returns token | REQ-6 (T19.12) | T-5-token-leak | Token never returned in response body | unit | `cargo test -p axiam-api-rest --lib email_verification` (`unknown_email_enqueues_and_returns_sent`, `known_email_never_returns_token`) | ✅ `email_verification.rs` | ✅ green |
| Notification dispatcher enqueues instead of returning list | REQ-6 (T19.13) | — | Dispatch is fire-and-forget via AMQP | unit | `cargo test -p axiam-audit notification` (`notification_enqueues_per_recipient`) | ✅ `axiam-audit/notification.rs` | ✅ green |
| `email.delivery_failed` audit event on exhausted retries (no recipient) | REQ-6 | T-5-mail-drop / T-5-addr-leak | Failure recorded with retry count; `to_address` excluded | integration | `cargo test -p axiam-amqp --test mail_consumer_test` (`exhausted_retries_writes_delivery_failed_audit_without_recipient`) | ✅ `mail_consumer_test.rs` | ✅ green |
| Reset/verify returns `{"sent": true}` for unknown emails | REQ-6 | T-5-enum | Uniform 200 regardless of address existence (D-15) | unit | `cargo test -p axiam-api-rest --lib unknown_email_enqueues_and_returns_sent` | ✅ `password_reset.rs` / `email_verification.rs` | ✅ green |
| Export contains all user data (every Art.15 section) + single-use token | REQ-8 | T-5-export-token | Single-use 24h opaque download token, SHA-256 hash (D-13) | integration | `cargo test -p axiam-api-rest --test gdpr_test export_completeness` | ✅ `gdpr_test.rs` | ✅ green |
| Deletion removes PII / pseudonymizes across tables | REQ-8 | T-5-delete | Tenant-scoped purge + anonymize-in-place | integration | `cargo test -p axiam-api-rest --test gdpr_test deletion_pseudonymization` | ✅ `gdpr_test.rs` | ✅ green |
| Deleted-user audit entries show `DELETED_USER_<hash>` | REQ-8 | T-5-pseudonym | Keyed HMAC-SHA256 pepper; no UUID leak (D-02) | integration | part of `gdpr_test::deletion_pseudonymization` (asserts `pseudonym.starts_with("DELETED_USER_")`) | ✅ `gdpr_test.rs` | ✅ green |
| Registration inserts consent record (atomic with user) | REQ-8 | T-5-consent-gap | Consent committed in same transaction as user | integration + unit | `gdpr_test::consent_on_registration` + `users::consent_tests::registration_creates_consent_row` | ✅ `gdpr_test.rs` / `users.rs` | ✅ green |
| Cancel link aborts deletion, re-enables account | REQ-8 | T-5-cancel | Single-use cancel token (hash-stored) | integration | `cargo test -p axiam-api-rest --test gdpr_test deletion_cancel` | ✅ `gdpr_test.rs` | ✅ green |
| Export file encrypted at rest | REQ-8 | T-5-export-rest | AES-256-GCM round-trip; `encrypted_blob` set (D-12) | integration | part of `gdpr_test::export_completeness` (asserts `encrypt_separate`/`decrypt_separate` + `encrypted_blob.is_some()`) | ✅ `gdpr_test.rs` | ✅ green |
| Template values HTML-escaped | REQ-6 | T-5-template | `render_html` escapes `&<>"'` (D-18) | unit | `cargo test -p axiam-email render_html` (asserts `<script>` → `&lt;script&gt;`) | ✅ `axiam-email/template.rs` | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `crates/axiam-api-rest/tests/gdpr_test.rs` — REQ-8 export completeness + deletion/pseudonymization + consent + cancel (4 tests green)
- [x] `crates/axiam-amqp/tests/mail_consumer_test.rs` — REQ-6 delivery-failure audit (4 tests green)
- [x] Mock `EmailService` / `MockProvider` wiring for mail-consumer tests — `seed_failing_email_config` + mock-config send path

*Existing infrastructure (inline `#[cfg(test)]` + SurrealDB `kv-mem`) covers everything else.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Real email arrives in inbox (end-to-end SMTP/provider) | REQ-6 | Requires live provider + real mailbox; not deterministic in CI | `just dev-up`, configure a real provider, trigger reset, confirm receipt + working link |

*All other phase behaviors have automated verification.*

---

## Validation Audit 2026-06-04

| Metric | Count |
|--------|-------|
| Behaviors mapped | 12 |
| COVERED (green) | 12 |
| PARTIAL | 0 |
| MISSING | 0 |
| Gaps found | 0 |
| Tests generated | 0 (full coverage already present) |

**Audit method:** State-A audit. Each mapped behavior cross-referenced to its real
test function and assertions, then the Phase 5 suites were run to confirm green:

| Suite | Result |
|-------|--------|
| `axiam-api-rest --lib` (password_reset, email_verification, consent_tests) | 17 passed |
| `axiam-api-rest --test gdpr_test` | 4 passed |
| `axiam-amqp` lib + `mail_consumer_test` | 2 + 4 passed |
| `axiam-audit` (notification) | 4 passed |
| `axiam-email` (template/render_html) | 35 passed |
| **Total** | **66 passed, 0 failed** |

Run under `--no-default-features` (local SAML-off path). The 3 known pre-existing
`federation_test` SAML failures are out of Phase 5 scope and were excluded by
targeting `--lib --test gdpr_test`.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (gdpr_test.rs, mail_consumer_test.rs, mock wiring)
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** verified 2026-06-04 — Nyquist-compliant, all 12 behaviors green.
