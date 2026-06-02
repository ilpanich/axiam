# Phase 5: Email Delivery & GDPR Compliance - Context

**Gathered:** 2026-06-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire the already-built `axiam-email` `EmailService` into the three flows that currently stub it — password reset (`password_reset.rs:88`), email verification (`email_verification.rs:105`), and the audit notification dispatcher (`axiam-audit/notification.rs:68`) — with a per-org/tenant configurable provider whose secrets are encrypted at rest. Deliver all outbound mail asynchronously through the existing AMQP infrastructure with retry. Implement the minimum-viable GDPR data-subject rights: an Article 15 data export (async, emailed download link) and an Article 17 right-to-erasure (grace-period scheduled purge that anonymizes the user in place and pseudonymizes audit-log PII), plus consent tracking.

**Not in this phase:** new email providers beyond the five already built; a generic template-management UI; OAuth2/OIDC compliance verification (Phase 6); broad integration-test closure (Phase 6). Discussion clarifies HOW to wire and implement what REQ-6/REQ-8 already scope — no new capabilities.

</domain>

<decisions>
## Implementation Decisions

### Audit Pseudonymization (Art. 17 ↔ append-only invariant)
- **D-01:** Reconcile the append-only audit invariant with Art. 17 via **controlled in-place PII overwrite**. The invariant is redefined as: *event facts (action, outcome, timestamp) are immutable; identifier/PII fields may be pseudonymized exactly once.* This genuinely **erases** PII (vs merely hiding it), which a tombstone/read-time-mask approach does not.
- **D-02:** The `<hash>` in `DELETED_USER_<hash>` is a **keyed HMAC-SHA256(pepper, tenant_id ‖ user_id)**, truncated. The pepper is a dedicated env-loaded key following the Phase 4 D-10 pattern (separate blast radius). Deterministic by design: the same deleted user maps to the same pseudonym across all their entries, so forensics can still group "what did this now-anonymous account do?" without re-identifying who it was. The keyed pepper blocks brute-force re-identification from candidate user_ids.
- **D-03:** **Full PII scrub** of a deleted user's audit entries: `actor_id` → nil UUID **and** `metadata.actor_pseudonym = "DELETED_USER_<hash>"`; `ip_address` → NULL; `metadata` scanned for known PII keys (email, username, name, …) and redacted; `resource_id` → nil where it equals the deleted `user_id` (catches entries where someone acted **on** this user). `actor_id` is a typed `Uuid` column and cannot hold the pseudonym string — hence the pseudonym lives in `metadata` and the HMAC string becomes the new correlation key.
- **D-04:** Expose exactly **one** privileged repository method, e.g. `pseudonymize_actor(tenant_id, user_id, hash)` — the **only** non-INSERT write the audit repo permits. It runs **inside the purge transaction** (PII scrub + user anonymization commit together or not at all) and itself emits a fresh audit event `action: gdpr.user_pseudonymized` (actor = whoever triggered erasure). The trail proves *that* erasure ran without retaining *who* was erased. The schema-level no-UPDATE guard must be relaxed for this single path only — planner to document the mechanism (DB permission scoping vs application-level guard).

### Deletion Semantics (Art. 17)
- **D-05:** "Remove user" = **anonymize the user row in place**, not hard-delete: keep the row and its `id` (preserves referential integrity for `created_by`/owner references), and scrub **every** PII column (email, username, display name → hash/null; `password_hash` → null so login is impossible; status → `anonymized`). ⚠ **Exhaustive PII-column inventory of the user entity (and any denormalized copies) is a first-class research/planning deliverable** — a single missed column means retained PII after an erasure request.
- **D-06:** **Hard-delete** all user-owned auth artifacts: sessions, refresh tokens, MFA secret, password-reset/verify tokens, federation identity links, WebAuthn credentials. **Retain** a minimal **PII-free erasure-proof record** (timestamp + pseudonym, no identifying data) to satisfy the GDPR accountability principle ("prove you erased user X on date Y").
- **D-07:** Trigger authorization: **self-service + admin**. An authenticated user may erase their **own** account (ownership check, mirroring the Phase 3 `/users/{own_id}` self-service pattern); admins holding a dedicated permission (e.g. `users:erase` / `gdpr:erase`) may erase any user in their tenant (covers written requests for users who cannot log in).
- **D-08:** Erasure uses a **30-day grace period with a scheduled purge job**, not immediate execution. On request: the account is **immediately disabled** (login blocked) and marked `deletion_pending` with `scheduled_purge_at = now + 30d`. The destructive work (anonymize-in-place D-05, audit pseudonymization D-01..D-04, auth-artifact deletion D-06) runs **at purge time** via a background job.
- **D-09:** Cancellation is via an **emailed one-time cancel link**: on the deletion request a server-generated token (consistent with "server-generated tokens only") is emailed to the user; clicking it within the window aborts the deletion and re-enables the account. This is a **new email template type** (deletion-scheduled / cancel-link) and a fourth+fifth consumer of the email path.

### GDPR Data Export (Art. 15)
- **D-10:** Export scope = **comprehensive personal data**: profile + consent records + sessions (metadata only, NOT token values) + MFA enrollment status (NOT the secret) + federation identities + role/group/permission assignments + audit entries where `actor_id = user`. **Secrets excluded** unconditionally (password hash, MFA secret, opaque token values).
- **D-11:** Format = **single sectioned-by-entity JSON object**: a top-level `export_metadata` block (`generated_at`, `tenant`, `subject_id`, `schema_version`) plus named sections (`profile`, `consents`, `sessions`, `mfa`, `federation_identities`, `assignments`, `audit_entries`). One file satisfies the "single JSON download" success criterion.
- **D-12:** Generation is **asynchronous**: the request endpoint enqueues a job; a background worker aggregates across tables, writes the JSON file **encrypted at rest** (AES-256-GCM, existing pattern), and **emails a download link**. (Another consumer of both the background-job pattern and the email path.)
- **D-13:** The download link is a server-generated opaque token, **single-use, 24h TTL**; the export file is **deleted on download or expiry** (auto-purge). Triggers: self-service + admin-permission (same model as D-07). Every export emits a `gdpr.data_exported` audit event recording actor + subject.

### Email Delivery & Failure Handling (REQ-6)
- **D-14:** **All outbound mail is sent asynchronously via AMQP with retry.** Each of the five mail types (password reset, email verification, audit notifications, deletion-cancel link, export-ready link) is enqueued to a mail queue; a consumer sends via `EmailService` with retry/backoff; after N exhausted retries the message dead-letters and an `email.delivery_failed` audit event is written. Decouples request latency from provider latency and unifies retry.
- **D-15:** The public **password-reset and email-verification request endpoints return a uniform, enumeration-safe response** ("if an account exists, an email has been sent") regardless of whether the address exists or whether delivery later succeeds. They merely enqueue; account existence and delivery outcome never leak to the client (OWASP anti-enumeration). Async delivery makes this the natural shape.
- **D-16:** The `email.delivery_failed` audit event is **keyed on `user_id`** (resolvable to the address only via the user row), with `metadata = { provider, error_class, attempt_count, next_retry_at, mail_type }` and **no raw recipient email**. This keeps the audit log PII-minimal *by construction* — nothing extra for the D-01..D-04 pseudonymizer to scrub.
- **D-17:** Provider secrets (`SmtpConfig.password`, `ApiProviderConfig.api_key`) are **encrypted at rest mirroring the Phase 4 federation-secret pattern**: a dedicated `AXIAM_EMAIL_ENCRYPTION_KEY` (32-byte base64), AES-256-GCM, with `ciphertext` + `nonce` + `key_version` storage and a separate blast radius from MFA/PKI/federation keys. The model doc-comments *claim* "stored encrypted by the DB layer" — **research must verify whether this is actually implemented or an aspirational stub** (cf. federation D-12). If currently plaintext, the planner adds an **idempotent startup backfill migration** using the federation D-12 heuristic (ciphertext column NULL while legacy column non-NULL).

### Template escaping (scope item — largely already satisfied)
- **D-18:** The "template escaping audit (no triple-stash `{{{}}}`)" roadmap item is **moot as written**: `axiam-email` does **not** use Handlebars. `template.rs` is a custom single-pass `{{placeholder}}` renderer that already HTML-escapes substituted values (`render_html`), prevents re-processing of inserted values (injection-safe), and strips CR/LF from headers (`sanitize_header`). The remaining work is to **ensure the new wiring renders HTML bodies via `render_html`** (not the plain `render`) for any user-controlled context value (e.g. username), per the existing engine contract.

### Claude's Discretion
- Exact background-job/queue mechanism — but see the **strong recommendation** in `<specifics>` to unify the purge job, export job, and mail consumer onto **one** hardened primitive rather than three ad-hoc tasks.
- Truncation length of the HMAC pseudonym; precise list of metadata PII keys to redact (D-03) and how they are detected.
- Storage backend for the encrypted export file (DB blob vs object store) within the "encrypted + auditable + expiring" guardrail (D-12/D-13).
- AMQP exchange/queue topology and dead-letter configuration for the mail queue (D-14); retry count and backoff schedule.
- **Consent tracking model (REQ-6/REQ-8 in scope, not deep-dived):** what events/granularity count as "consent" (terms acceptance at registration at minimum), the consent record shape, and whether withdrawal is tracked. Planner to propose a minimal model (record `accepted_terms` with version + timestamp at registration) unless research surfaces a richer requirement; surface for confirmation if non-trivial.
- New email templates for the deletion-cancel (D-09) and export-ready (D-12) link flows; reuse of the existing template-resolution order (tenant → org → built-in default).
- Endpoint paths for export/erase/cancel (suggest `/api/v1/account/export`, `/account/delete`, public `/auth/account/delete/cancel`); admin variants under the RBAC-gated user routes.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §REQ-6 — Email Delivery acceptance criteria (7 items: wire reset/verify/notification, configurable provider, failure audit, escaping, server-generated tokens)
- `.planning/REQUIREMENTS.md` §REQ-8 — GDPR Compliance acceptance criteria (7 items: export, deletion+pseudonymization, consent, two integration tests)
- `.planning/ROADMAP.md` Phase 5 — Scope, 5 success criteria
- `claude_dev/design-document.md` — Master architecture (email, audit, encryption-at-rest, multi-tenant data model sections)

### Email Wiring Targets (currently stubbed)
- `crates/axiam-api-rest/src/handlers/password_reset.rs` — `:88` `TODO(T19): wire up actual email sending via EmailService` (REQ-6 / T19.11)
- `crates/axiam-api-rest/src/handlers/email_verification.rs` — `:105` `TODO(T19): wire up actual email sending via EmailService` (REQ-6 / T19.12); `:108` notes composition layer wires EmailService
- `crates/axiam-audit/src/notification.rs` — `:68` `TODO(T19): Send actual emails via EmailService with template resolution and org_id lookup` (REQ-6 / T19.13). `NotificationDispatcher::dispatch` currently returns `Vec<(event_name, recipient_emails)>` for the caller to send.

### Email Service (built — Phase 13 of original roadmap)
- `crates/axiam-email/src/service.rs` — `EmailService::from_config` / `with_provider` / `send`; resolves provider, sends `EmailMessage`
- `crates/axiam-email/src/template.rs` — custom `{{placeholder}}` engine; `render`, `render_html` (HTML-escapes), `render_email`, `sanitize_header`; resolution order tenant → org → built-in
- `crates/axiam-email/src/provider.rs`, `src/providers/` — `EmailProvider` trait + smtp / sendgrid / postmark / resend / brevo / mock impls
- `crates/axiam-email/src/message.rs` — `EmailMessage` (`has_body`, `to`, `subject`)
- `crates/axiam-core/src/models/email.rs` — `EmailConfig`, `ProviderConfig` (Smtp/SendGrid/Postmark/Resend/Brevo), `SmtpConfig.password` / `ApiProviderConfig.api_key` (doc-commented "encrypted at rest" — VERIFY), org→tenant inheritance via `effective_email_config`, `validate_email_config`
- `crates/axiam-core/src/models/email_template.rs` — `EmailTemplate`, `TemplateKind`

### Audit (GDPR pseudonymization target)
- `crates/axiam-core/src/models/audit.rs` — `AuditLogEntry { id, tenant_id, actor_id: Uuid, actor_type, action, resource_id: Option<Uuid>, outcome, ip_address: Option<String>, metadata: serde_json::Value, timestamp }`; module doc states **"append-only — no UPDATE or DELETE operations are permitted"**
- `crates/axiam-core/src/models/notification_rule.rs` — `NotificationEventType::from_audit_action`, `to_db_string`
- `crates/axiam-audit/` — audit repository + dispatcher (pseudonymization write path lands here)

### Encryption-at-rest Patterns to Mirror (Phase 4 lineage)
- `.planning/phases/04-federation-verification-session-security/04-CONTEXT.md` §D-10..D-13 — dedicated env key, AES-256-GCM, ciphertext/nonce/key_version columns, idempotent startup backfill migration (the exact template for D-17)
- `crates/axiam-auth/src/config.rs` — 32-byte base64 env-key loading (`mfa_encryption_key` etc.)
- `crates/axiam-auth/src/totp.rs` — AES-256-GCM `encrypt_secret`/`decrypt_secret` helpers

### Session/Token Plumbing (deletion cascade — Phase 4 already wired some)
- `crates/axiam-auth/src/service.rs` — `AuthService::revoke_all_sessions`; session/refresh invalidation chokepoint (Phase 4 D-16/D-18) — reuse for deletion cascade
- `crates/axiam-auth/src/password_reset.rs` — reset token model + `confirm_reset` (session-invalidation already wired in Phase 4)
- `crates/axiam-api-rest/src/server.rs` — route registration + `PUBLIC_ALLOWLIST` (extend for the public cancel-link endpoint)
- `crates/axiam-api-rest/src/extractors/auth.rs` — `AuthenticatedUser` (self-service ownership checks for export/erase)

### AMQP (async delivery)
- `crates/axiam-amqp/` — Lapin consumer/producer; the mail queue + consumer (D-14) live here or extend it
- `.planning/codebase/INTEGRATIONS.md` — external-integration inventory (AMQP, email providers)

### Codebase Maps
- `.planning/codebase/ARCHITECTURE.md` — crate dependency graph
- `.planning/codebase/CONVENTIONS.md` — naming, middleware, repository patterns
- `.planning/codebase/STACK.md` — tech-stack inventory
- `.planning/codebase/CONCERNS.md` — known debt
- `.planning/codebase/TESTING.md` — test layout (REQ-8 requires export-completeness + deletion/pseudonymization integration tests)

### Prior Phase Context
- `.planning/phases/03-rbac-enforcement/03-CONTEXT.md` — `PUBLIC_ALLOWLIST` (D-04), self-service ownership pattern (export/erase authorization)
- `.planning/phases/02-security-headers-rate-limiting/02-CONTEXT.md` — rate limiting (apply to new export/erase/cancel endpoints), security headers
- `.planning/phases/01-cookie-based-authentication/01-CONTEXT.md` — cookie JWT, server-generated token conventions

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `EmailService` (`service.rs`) — fully built; `from_config(&EmailConfig)` builds the provider, `send(&EmailMessage)` delivers. The wiring just needs to resolve the effective `EmailConfig` per tenant and call it (from the AMQP consumer per D-14).
- `template.rs` renderer — already injection-safe (`render_html` HTML-escapes, single-pass, CR/LF header sanitization). New mail types add templates; rendering of HTML bodies must use `render_html` (D-18).
- `effective_email_config(org, tenant_override, …)` (`models/email.rs`) — org→tenant inheritance already implemented; resolution at send time merges then builds the provider.
- `NotificationDispatcher::dispatch` (`notification.rs`) — already returns matched `(event, recipients)`; T19.13 is to actually send those via `EmailService` (now: enqueue to the mail queue).
- `AuthService::revoke_all_sessions` + the session-invalidation chokepoint (Phase 4) — reuse for the deletion auth-artifact cascade (D-06).
- AES-256-GCM helpers (`totp.rs`) + Phase 4 federation-secret machinery — the model for D-17 provider-secret encryption and D-12 export-file encryption.
- `AuthenticatedUser` extractor — self-service ownership for export/erase (D-07/D-13).

### Established Patterns
- Repository trait pattern: `web::Data<SurrealXxxRepository<C>>` injected as app data; `XxxRow` / `XxxRowWithId` row structs; `SurrealValue` derive in `axiam-db`.
- Public-endpoint registration via `PUBLIC_ALLOWLIST` (Phase 3) — the public deletion-cancel link endpoint extends it.
- Env-key loading: 32-byte base64 → `[u8; 32]` (`config.rs`).
- Schema migrations: `DEFINE FIELD ... TYPE option<...>` for new nullable columns; new tables `DEFINE TABLE ... SCHEMAFULL` + `DEFINE FIELD`/`DEFINE INDEX`.
- **Background jobs**: Phase 4 introduced the first (replay/state cleanup, likely a tokio task spawned at startup). Phase 5 adds the **purge job** and **export job** — planner should treat these + the **mail consumer** as one unified, hardened primitive (see Specifics).
- Audit immutability: enforced at the model/repo layer; D-04 introduces the single sanctioned exception.

### Integration Points
- `crates/axiam-api-rest/src/handlers/password_reset.rs` / `email_verification.rs` — replace the TODO stubs with enqueue-to-mail-queue calls; keep responses uniform (D-15).
- `crates/axiam-audit/src/notification.rs` — dispatcher enqueues instead of returning recipient lists (or caller enqueues).
- `crates/axiam-amqp/` — new mail queue + consumer that calls `EmailService` with retry/dead-letter (D-14).
- `crates/axiam-server/src/main.rs` — load `AXIAM_EMAIL_ENCRYPTION_KEY` (D-17) + HMAC pepper key (D-02); spawn the purge + export jobs; (if needed) run the email-secret backfill migration (D-17).
- `crates/axiam-db/src/schema.rs` — migrations: encrypted-secret columns on email config (D-17); user `deletion_pending` + `scheduled_purge_at` + cancel-token storage (D-08/D-09); export-job/file tracking (D-12/D-13); consent records (REQ-8); erasure-proof record (D-06).
- New REST handlers: account export, account delete (self + admin), public delete-cancel; all RBAC/ownership gated and rate-limited (Phase 2 carry-forward).

</code_context>

<specifics>
## Specific Ideas

- **Architectural through-line — one background primitive.** Every "more robust" choice in this phase (AMQP delivery D-14, async export D-12, scheduled purge D-08) leans on a **reliable background-job/queue mechanism** that Phase 4 only just introduced (replay/state cleanup). The single biggest planning risk is implementing purge-job, export-job, and mail-consumer as three separate ad-hoc tasks. **Strong recommendation:** the planner unify them onto one hardened pattern (retry, failure visibility, idempotency, graceful shutdown).
- The user consistently preferred the **infrastructure-backed, emailed-link** option (async export with emailed link, emailed deletion-cancel link) over simpler synchronous/in-app alternatives — a coherent, queue-centric architecture.
- Pseudonymization must be **genuine erasure, not concealment** — the in-place-overwrite choice (D-01) was explicitly preferred over a tombstone+read-time-mask because regulators want PII erased, not merely hidden.
- The pseudonym is **deterministic and correlatable** (keyed HMAC, D-02), explicitly trading absolute unlinkability for retained forensic value in the security audit log.
- Audit must stay **PII-minimal by construction** (D-16): the failure-event design avoids raw recipient emails specifically so it doesn't create new PII for the Art-17 scrubber to chase.

</specifics>

<deferred>
## Deferred Ideas

- **Grace-window edge cases** — exact semantics of "disabled" for already-issued access/refresh tokens during the window; whether admin-initiated erasure also uses the 30-day grace or purges sooner; cancel-link re-issue/expiry behavior. Surface during planning; default to "disable = revoke all sessions + block new login," admin path also uses the grace window.
- **Synchronous-download export fallback** — if per-user export volume turns out small, a synchronous download endpoint could supplement the async path; not built now (async chosen for scale and link-security).
- **Login-allowed-during-window cancellation UX** — the friendlier in-app cancel model (vs emailed link) is a possible later UX improvement.
- **Consent richness** — withdrawal tracking, per-purpose consent granularity, and consent-version history beyond the minimal "accepted terms at registration" model belong in a dedicated consent/privacy phase if requirements grow.
- **Export Art. 15(1) processing metadata** — including processing purposes / legal basis alongside the data dump is a fuller Art-15 implementation; MVP ships the data sections only.
- **Email i18n / localized templates** for the new link flows — out of scope for MVP.

### Reviewed Todos (not folded)
None — `gsd-sdk todo.match-phase 5` returned 0 matches.

</deferred>

---

*Phase: 05-email-delivery-gdpr-compliance*
*Context gathered: 2026-06-02*
