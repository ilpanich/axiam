# Phase 5: Email Delivery & GDPR Compliance - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-02
**Phase:** 05-email-delivery-gdpr-compliance
**Areas discussed:** Audit Pseudonymization, Deletion semantics, Export scope & format, Email failure & delivery path

---

## Audit Pseudonymization

### Reconcile append-only audit with Art.17 PII rewrite
| Option | Description | Selected |
|--------|-------------|----------|
| In-place PII overwrite | One-time audited UPDATE of identifier fields only; erases PII; relaxes no-UPDATE for one path | ✓ |
| Tombstone + read-time mask | Never touch rows; mask at query time; PII physically retained (hides, not erases) | |
| Actor-indirection only | Audit stores only actor_id; clean only if logs never denormalize PII | |

**User's choice:** In-place PII overwrite
**Notes:** Chosen because it genuinely erases PII (regulators want erasure, not concealment). Invariant redefined: event facts immutable, identifiers pseudonymizable once.

### What is `<hash>` in DELETED_USER_<hash>
| Option | Description | Selected |
|--------|-------------|----------|
| Keyed HMAC of user_id | HMAC-SHA256(pepper, tenant+user); deterministic; correlatable; brute-force resistant | ✓ |
| Random token per user | Correlatable but requires a stored, re-identifying mapping | |
| Random per entry | Fully unlinkable (anonymization); destroys forensic value | |

**User's choice:** Keyed HMAC of user_id
**Notes:** Dedicated pepper env key (Phase 4 D-10 pattern). Trades absolute unlinkability for retained audit correlation.

### Which fields get overwritten
| Option | Description | Selected |
|--------|-------------|----------|
| Full PII scrub | actor_id→nil + metadata.actor_pseudonym; ip→NULL; metadata PII keys redacted; resource_id→nil when self | ✓ |
| Actor + IP only | Pseudonymize actor + null IP; leave metadata/resource_id | |
| Actor identity only | Only actor; leaves IP (personal data) and metadata | |

**User's choice:** Full PII scrub
**Notes:** actor_id is a typed Uuid → pseudonym string lives in metadata; HMAC becomes the new correlation key.

### Keep no-UPDATE invariant meaningful
| Option | Description | Selected |
|--------|-------------|----------|
| Single guarded method + meta-event | One privileged pseudonymize_actor(); transactional; emits gdpr.user_pseudonymized | ✓ |
| Guarded method, no meta-event | Same path, no self-documenting event | |
| Best-effort, post-commit | Separate step after delete; crash leaves orphaned PII | |

**User's choice:** Single guarded method + meta-event
**Notes:** Runs inside the purge transaction (D-08); proves erasure ran without retaining who.

---

## Deletion semantics

### User row treatment
| Option | Description | Selected |
|--------|-------------|----------|
| Hard delete + cascade | Physically delete row + cascade; genuine erasure; dangling FK references | |
| Anonymize in place | Keep row+id (FK integrity); scrub every PII column | ✓ |
| Soft-delete flag | deleted=true, retain PII — rejected (Art.17 violation) | |

**User's choice:** Anonymize in place
**Notes:** Exhaustive PII-column inventory of the user entity is now a first-class research deliverable.

### Owned-data treatment
| Option | Description | Selected |
|--------|-------------|----------|
| Delete auth, keep erasure proof | Hard-delete sessions/refresh/MFA/tokens/links; retain PII-free proof record | ✓ |
| Delete everything owned | Also delete consent/proof; loses accountability evidence | |
| Anonymize owned rows too | Keep security artifacts stripped — harmful, should be destroyed | |

**User's choice:** Delete auth, keep erasure proof
**Notes:** Accountability principle — must be able to prove erasure of user X on date Y.

### Who can trigger
| Option | Description | Selected |
|--------|-------------|----------|
| Self-service + admin | User erases own (ownership check) + admin with users:erase/gdpr:erase | ✓ |
| Admin-only | Only admins; data subject can't act directly | |
| Self-service only | No admin path for inaccessible accounts | |

**User's choice:** Self-service + admin

### Irreversibility safeguard
| Option | Description | Selected |
|--------|-------------|----------|
| Immediate + step-up confirm | Synchronous; re-auth + confirm flag | |
| Grace period + purge job | Immediate disable, scheduled purge after window | ✓ |
| Immediate, no extra confirm | Execute on request — dangerous | |

**User's choice:** Grace period + purge job
**Notes:** Destructive work deferred to purge time; extends the Phase 4 background-task pattern.

### Cancellation model + window
| Option | Description | Selected |
|--------|-------------|----------|
| Login allowed + in-app cancel | deletion_pending, still authenticates, in-app cancel | |
| Disabled + emailed cancel link | Login blocked immediately; one-time emailed cancel token | ✓ |
| Disabled + admin reactivation | Only admin can cancel | |

**User's choice:** Disabled + emailed cancel link (30-day window)
**Notes:** Server-generated token (consistent with reset/verify). Adds a new email template type; rides the email path being wired this phase.

---

## Export scope & format

### What the export includes
| Option | Description | Selected |
|--------|-------------|----------|
| Comprehensive personal data | Profile + consent + sessions + MFA-status + federation + assignments + own audit entries; secrets excluded | ✓ |
| Profile + direct records | Omits audit history/assignments — under-delivers Art.15 | |
| Everything incl. secrets | Dumps hashes/secrets — rejected | |

**User's choice:** Comprehensive personal data

### Structure
| Option | Description | Selected |
|--------|-------------|----------|
| Sectioned by entity | export_metadata + named sections; single self-describing file | ✓ |
| Flat merged object | Field-name collisions, lost structure | |
| Bundle of per-entity files | Zip — conflicts with "single JSON download" | |

**User's choice:** Sectioned by entity

### Generation & delivery
| Option | Description | Selected |
|--------|-------------|----------|
| Synchronous download | In-request aggregation, attachment response | |
| Async job + emailed link | Enqueue → build → email time-limited link | ✓ |
| You decide | Defer to planner | |

**User's choice:** Async job + emailed link
**Notes:** Third emailed-link flow; pulls in job + storage + signed-link infra.

### Link security & retention
| Option | Description | Selected |
|--------|-------------|----------|
| Single-use, 24h, encrypted, auto-purge | Opaque token, single-use, 24h, file encrypted + deleted on download/expiry; export audited | ✓ |
| Multi-use, 7-day TTL | Reusable week-long link — larger exposure | |
| You decide | Defer TTL/backend to planner | |

**User's choice:** Single-use, 24h, encrypted, auto-purge
**Notes:** Trigger = self + admin permission; gdpr.data_exported audited (actor + subject).

---

## Email failure & delivery path

### Send mechanism
| Option | Description | Selected |
|--------|-------------|----------|
| Async via AMQP + retry | Enqueue all 5 mail types; consumer sends with retry/dead-letter | ✓ |
| Sync transactional, async notifications | Two paths; request blocks on provider | |
| Sync everywhere | No queue, no retry; provider issues become user errors | |

**User's choice:** Async via AMQP + retry

### Request-endpoint response shape
| Option | Description | Selected |
|--------|-------------|----------|
| Uniform response, outcome in audit | Generic 200/202 regardless of account existence/delivery; enumeration-safe | ✓ |
| Reveal send status | Distinct responses — leaks account existence | |
| Uniform for reset, explicit for verify | Nuance only if a logged-in resend exists | |

**User's choice:** Uniform response, outcome in audit

### Failure-event contents
| Option | Description | Selected |
|--------|-------------|----------|
| user_id + provider + error + attempts | Keyed on user_id; no raw recipient; PII-minimal | ✓ |
| Include raw recipient | Easier debug but injects PII into audit | |
| Minimal flag only | Not actionable; defeats "with retry info" | |

**User's choice:** user_id + provider + error + attempts
**Notes:** PII-minimal by construction — avoids creating PII the Art-17 scrubber must chase.

### Provider-secret encryption at rest
| Option | Description | Selected |
|--------|-------------|----------|
| Mirror Phase 4, dedicated key | AXIAM_EMAIL_ENCRYPTION_KEY, AES-256-GCM, ciphertext/nonce/key_version; backfill if plaintext | ✓ |
| Reuse an existing key | Fewer keys, larger blast radius | |
| Research-first, then decide | Verify before locking | |

**User's choice:** Mirror Phase 4, dedicated key
**Notes:** "Encrypted by DB layer" doc-comment must be verified — may be an aspirational stub (cf. federation D-12).

---

## Claude's Discretion

- Background-job/queue mechanism (with strong recommendation to unify purge + export + mail-consumer onto one primitive)
- HMAC truncation length; metadata PII-key detection list
- Export file storage backend (DB blob vs object store) within the encrypted/expiring guardrail
- AMQP mail-queue topology, retry count, backoff, dead-letter config
- Consent-tracking model (minimal "accepted terms at registration" default unless research surfaces more)
- New email templates for deletion-cancel and export-ready flows
- Endpoint paths for export/erase/cancel

## Deferred Ideas

- Grace-window edge cases (already-issued token semantics, admin grace vs immediate, cancel-link re-issue)
- Synchronous-download export fallback if volumes are small
- Login-allowed-during-window cancellation UX
- Consent richness (withdrawal, per-purpose granularity, version history)
- Export Art.15(1) processing-metadata (purposes/legal basis)
- Email i18n / localized templates
