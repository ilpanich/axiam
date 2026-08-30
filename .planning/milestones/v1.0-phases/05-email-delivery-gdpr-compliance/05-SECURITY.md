---
phase: 05
slug: email-delivery-gdpr-compliance
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-04
---

# Phase 05 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Register authored at plan time across 05-01..05-05; mitigations independently
> verified against the implementation by `gsd-security-auditor` on 2026-06-04.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| application connection → `audit_log` table | Append-only invariant; only the GDPR pseudonymization path may UPDATE; never DELETE | Audit events (actor, action, outcome) |
| DB at rest → provider secrets | SMTP password / API key must never be stored plaintext | `email_config` credentials |
| pepper key → audit pseudonym | Re-identification resistance depends on pepper secrecy | Pseudonymized actor id |
| AMQP message payload → mail consumer | `to_address` travels in the message but must never reach the audit log (D-16) | Recipient email address |
| public reset / verify / cancel endpoint → client | Response must not leak account existence or token | Auth status, opaque tokens |
| client → export / delete endpoint | Only the owner or a privileged admin may act | User PII, deletion intent |
| export file at rest → disk/DB | Must be encrypted; deleted on download or expiry | Full user data export |
| registration input → consent record | Captured atomically with the user; ip/user_agent recorded for Art. 7 proof | Consent proof (ip, user_agent) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation (evidence) | Status |
|-----------|----------|-----------|-------------|------------------------|--------|
| T-5-secret-rest | Information Disclosure | `email_config` provider secrets (D-17) | mitigate | AES-256-GCM `encrypt_field`/`decrypt_field` (`email_config.rs:32-58`); ciphertext+nonce+`secret_key_version` columns in SCHEMA_V15 (`schema.rs:854-864`); dedicated key from env (`main.rs:212`) | closed |
| T-5-pseudonym | Information Disclosure | `gdpr_pseudonym` (D-02) | mitigate | Keyed HMAC-SHA256 on pepper + tenant_id + user_id, 64-bit truncation `DELETED_USER_{hex}` (`crypto.rs:158-164`) | closed |
| T-5-audit-update | Elevation of Privilege / Tampering | `audit_log` UPDATE relaxation (D-04) | mitigate | `FOR update WHERE $auth.role='gdpr_pseudonymizer'`, `FOR delete NONE` (`schema.rs:955-960`); `pseudonymize_actor` is the sole UPDATE, action/outcome/timestamp untouched (`audit.rs:342-432`) | closed |
| T-5-token-store | Spoofing | account_deletion + export_job tokens (D-09/D-13) | mitigate | `sha256_hex` helper; only hashes persisted (`gdpr.rs:95-99,311-312`; `export_job.rs:25`); raw token returned once | closed |
| T-5-mail-drop | Denial of Service | `mail.outbound` delivery failures | mitigate | `x-dead-letter-exchange` → DLQ (`connection.rs:131-139`); persistent `delivery_mode(2)` (`mail_publisher.rs:47`); `nack(requeue:false)` + `email.delivery_failed` audit (`mail_consumer.rs:328-337,163`) | closed |
| T-5-addr-leak | Information Disclosure | `to_address` in AMQP message (D-16) | mitigate | Audit metadata limited to provider/error_class/attempt_count/next_retry_at/mail_type; `to_address` absent (`mail_consumer.rs:150-157`) | closed |
| T-5-template | Tampering | username in HTML email body (D-18) | mitigate | `render_email` → `render_html` HTML-escapes all 5 dangerous chars (`template.rs:84-98,116-123`) | closed |
| T-5-key-absent | Denial of Service | missing email encryption key | accept | Consumer spawn guarded: `if let Some(email_key) … else warn!` (`main.rs:457-474`) — see Accepted Risks | closed |
| T-5-enum | Information Disclosure | reset / verify response | mitigate | Uniform `{"sent": true}` regardless of account existence or delivery (`password_reset.rs:148-149`; `email_verification.rs`) (D-15) | closed |
| T-5-token-leak | Information Disclosure | reset / verify response body | mitigate | Server token enqueued in `template_context` only; never serialized to HTTP response (`password_reset.rs:106-149`) | closed |
| T-5-consent-gap | Repudiation | registration without consent | mitigate | **Atomic** user+consent `BEGIN..COMMIT` transaction `create_with_consent` (`user.rs:508-585`); handler propagates failure (`users.rs:98-135`); verified by unit test `registration_creates_consent_row` | closed |
| T-5-export-token | Spoofing | export download link (D-13) | mitigate | Single-use SHA-256 hash, 24h TTL (`cleanup.rs:397-404`); status/expiry check + `mark_downloaded`+`delete` on use (`gdpr.rs:214-246`) | closed |
| T-5-export-rest | Information Disclosure | export file at rest (D-12) | mitigate | AES-256-GCM `encrypt_separate` with `export_encryption_key` (`cleanup.rs:393-394`); `decrypt_separate` only on download (`gdpr.rs:241`) | closed |
| T-5-delete | Elevation of Privilege | account delete authorization (D-07) | mitigate | `is_own_resource` OR `RequirePermission("users:erase")`; tenant-scoped purge (`gdpr.rs:289-294`) | closed |
| T-5-cancel | Elevation of Privilege | public cancel-deletion endpoint | mitigate | Single-use SHA-256 token, Pending+window check, `mark_cancelled` clears only deletion flags (`gdpr.rs:397-423`) | closed |
| T-5-purge-tenant | Elevation of Privilege | purge sweep cross-tenant leakage | mitigate | Each purged row carries its own `tenant_id`, passed to all downstream scoped ops (`cleanup.rs:210`) | closed |
| T-5-SC | Tampering | cargo dependency installs | accept | No new external crates; only `aes-gcm`/`base64` (already workspace deps) added to axiam-db (`git diff` Cargo.toml) — see Accepted Risks | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-05-01 | T-5-key-absent | If `AXIAM__EMAIL_ENCRYPTION_KEY` is absent the mail consumer is not spawned and a warning is logged; no secret decryption is attempted. Email delivery is degraded (not started), never insecure. Operational/config concern, not an exploitable flaw. | gsd-security-auditor + maintainer | 2026-06-04 |
| AR-05-02 | T-5-SC | Phase 5 adds no new external packages. The only Cargo.toml additions (`aes-gcm`, `base64` to axiam-db) are pre-existing workspace dependencies. Supply-chain surface unchanged. | gsd-security-auditor + maintainer | 2026-06-04 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-04 | 17 | 16 | 1 | gsd-security-auditor (initial verification — T-5-consent-gap OPEN) |
| 2026-06-04 | 17 | 17 | 0 | maintainer — fixed T-5-consent-gap (atomic `create_with_consent`), re-verified |

### Remediation note — T-5-consent-gap

Initial audit found registration created the user first, then recorded consent in a
non-fatal `if let Err(e) { warn! }` block (`users.rs`), so a consent-DB failure could
leave a user with no proof-of-consent — violating the plan invariant. Because AXIAM
never physically deletes user rows (anonymize-in-place for FK integrity), a compensating
delete could not restore the invariant. Fixed by introducing `create_with_consent`, a
single SurrealDB `BEGIN..COMMIT` transaction that commits the user and its
`terms_of_service` consent together (or neither). Verified by `registration_creates_consent_row`.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-04
