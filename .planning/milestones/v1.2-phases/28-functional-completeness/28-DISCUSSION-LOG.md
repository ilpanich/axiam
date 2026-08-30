# Phase 28: Functional Completeness - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-05
**Phase:** 28-functional-completeness
**Areas discussed:** Email-config API (secrets & RBAC), Custom email templates (resolution & fallback), backfill_plaintext_secrets, Service-account token sub_kind, FUNC-01/05 verification depth, Email-config endpoint shape, GET effective vs raw, Provider-secret validation on write

---

## Email-config API — secrets & RBAC

| Question | Option | Selected |
|----------|--------|----------|
| Secret read-back on GET | Write-only, never returned | ✓ |
| | Masked / presence flag | |
| | Full to authorized admins | |
| Secret update semantics | Omit preserves, value replaces | ✓ |
| | Full replace every write | |
| RBAC shape | `email_config:write` + `email_config:read` | ✓ |
| | Per-verb (like federation) | |
| | `email_config:write` for read+write | |
| Scoping | One handler set, both scopes | ✓ |
| | Separate org vs tenant permissions | |

**Notes:** Write-only mirrors the SECHRD-09 federation-secret posture. The `email_config:write`
choice deliberately deviates from the codebase's per-verb convention to match the AC wording.

---

## Custom email templates — resolution & fallback

| Question | Option | Selected |
|----------|--------|----------|
| Template scope | Wire consumer resolution only | ✓ |
| | Also add template-authoring CRUD | |
| | Consumer + seed/migration only | |
| Failure behavior | Fall back to built-in + log | ✓ |
| | Fail the send → AMQP retry/DLQ | |

**Notes:** `resolve_template` already implements tenant→org→built-in precedence; only the
consumer's `None, None` call needs fixing. Authoring CRUD deferred to avoid scope creep.

---

## backfill_plaintext_secrets — implement vs no-op

| Question | Option | Selected |
|----------|--------|----------|
| Close the backfill AC | Accept no-op, close honestly | ✓ |
| | Defensive UPDATE (quarantine) | |
| | Full federation-style parity | |
| NULL-ciphertext at runtime | Treat as misconfiguration — clear error | ✓ |
| | Fall back to lower-scope / built-in config | |
| | Leave current behavior | |

**Notes:** Unlike `federation_config`, `email_config` has no legacy plaintext column — a genuine
encrypt-backfill is impossible. Honest closure (remove TODO, document, test 0 rows) chosen over
inventing a fake backfill, consistent with the no-over-engineering stance (cf. SECHRD-05).

---

## Service-account token sub_kind

| Question | Option | Selected |
|----------|--------|----------|
| Scope of sub_kind | All mint paths, explicit kind | ✓ |
| | Only SA tokens carry it | |
| | SA + User only | |
| Authz impact | Informational only | ✓ |
| | Enforce at endpoints | |
| Backward compat | Missing ⇒ User (accept) | ✓ |
| | Missing ⇒ reject | |

**Notes:** Three subject types today (User/ServiceAccount/OAuth2Client) are indistinguishable;
an explicit claim on all paths avoids a second inference path. Informational-only + accept-missing
keeps in-flight tokens working through their TTL.

---

## FUNC-01/05 verification depth

| Question | Option | Selected |
|----------|--------|----------|
| OIDC endpoint shape | Accept start/callback; document contract | ✓ |
| | Add /oidc/login alias for parity | |
| | Rename SAML to match OIDC | |

**Notes:** FUNC-05 found already complete (200/202/403/401 documented) — verify-only. OIDC is
inherently a two-step redirect flow; a single POST can't complete it, so the contract is documented
rather than reshaped.

---

## Email-config endpoint shape & paths

| Question | Option | Selected |
|----------|--------|----------|
| Endpoint shape | Scope-nested singleton | ✓ |
| | Flat /email-configs like federation | |
| | Unified /email-config?scope=&scope_id= | |

**Notes:** `email_config` is a singleton per scope, so `/organizations/{id}/email-config` +
`/tenants/{id}/email-config` (GET/PUT/DELETE, no POST/list) reads more naturally than a flat collection.

---

## GET returns effective vs raw config

| Question | Option | Selected |
|----------|--------|----------|
| Tenant GET view | Raw own-scope row | ✓ |
| | Effective merged config | |
| | Raw by default, ?effective=true | |

**Notes:** An edit form should show the values being edited, not inherited ones. Merged view deferred.

---

## Provider-secret validation on write

| Question | Option | Selected |
|----------|--------|----------|
| Validate credential on write | Accept blindly, no live test | ✓ |
| | Live connectivity test | |
| | (structural validation only implied) | |

**Notes:** Avoids an outbound call (and SSRF/egress surface) at write time; the first send surfaces
bad credentials. Consistent with not doing live validation elsewhere.

---

## Claude's Discretion

- Exact `SubjectKind` serde representation (`#[serde(default)]` + naming per existing claim conventions).
- Seam for threading `EmailTemplateRepository` into `send_with_retry_and_audit` and its wiring in `main.rs`.
- Email-config DTO shapes, validation messages, error→status mapping (reuse existing `email.rs` model).
- New `email_config:read`/`email_config:write` permission seeding.
- Test structure/harness for e2e and unit tests (follow Phase 26 CORR-04 conventions).
- Whether the SA token needs any claim beyond `sub_kind` (default: `sub_kind` alone).

## Deferred Ideas

- Email-template authoring CRUD API (set/delete org/tenant custom templates) — its own phase.
- `sub_kind`-based authz enforcement (gating endpoints by subject kind) — its own phase.
- Live provider-credential validation on write — deferred by D-15; revisit on operator pain.
- Merged/effective email-config GET view (`?effective=true`) — add later if the admin UI needs it.
