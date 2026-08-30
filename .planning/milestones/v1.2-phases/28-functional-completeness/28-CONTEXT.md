# Phase 28: Functional Completeness - Context

**Gathered:** 2026-07-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the remaining MVP feature gaps and make them RBAC-gated. Requirements
**FUNC-01…FUNC-05 are locked** by ROADMAP.md / REQUIREMENTS.md — this discussion
clarifies HOW to implement/close them, not WHAT to build. No new capabilities.

- **FUNC-01** — Unauthenticated first-time federation login (OIDC + SAML), public federation metadata
- **FUNC-02** — Session invalidation on password reset (`SessionRepository` in `PasswordResetService`)
- **FUNC-03** — Admin email-config CRUD API + per-tenant custom template resolution + plaintext-secret backfill
- **FUNC-04** — Admin user/MFA management endpoints + service-account token type (`sub_kind`)
- **FUNC-05** — OpenAPI login response schema (success + MFA-required)

**Critical scouting finding (2026-07-05): most of this phase is already
implemented in the codebase from prior work.** The genuinely-open work is
narrower than the roadmap implies. The researcher MUST verify current state
before planning rather than assuming greenfield. Per-requirement status found
during discuss-phase scouting:

| Req | Status found during scout | Remaining work |
|---|---|---|
| FUNC-01 | SAML public `saml_login_public` + `saml_acs_public` exist; OIDC public `/oidc/start` + `/oidc/callback` exist ("D-22" first-time SSO) | **Verify + gap-fill:** confirm federation metadata endpoint is public (AC + `handlers/federation.rs:377`); add first-time-login e2e (create config via API → login → assert AXIAM tokens; closes CQ-B40). Document OIDC two-step contract (D-12). |
| FUNC-02 | **Done** — `confirm_reset` (`password_reset.rs:296`) already invalidates all sessions AND revokes refresh tokens ("D-16/D-18") | **Verify-only:** ensure a test asserts prior sessions/refresh tokens are rejected after reset. |
| FUNC-03 | `backfill_plaintext_secrets` exists (a no-op stub, `email_config.rs:353`) and is called in `main.rs:279`; `SurrealEmailTemplateRepository` exists | **Real gaps:** no email-config admin handler/route/permission; mail consumer uses built-in templates only; backfill is a stub. |
| FUNC-04 | Admin user-listing (`GET /api/v1/users`) + admin MFA list/delete gated by `users:admin` already exist | **Real gap:** no `sub_kind` claim on tokens (`TODO(T15)` at `auth.rs:556`). Verify user-listing/MFA gating. |
| FUNC-05 | **Done** — login OpenAPI documents `200`/`202`/`403 MfaSetupRequired`/`401` as distinct statuses (`auth.rs:261`, `openapi.rs:196`) | **Verify-only.** |

</domain>

<decisions>
## Implementation Decisions

> Captured interactively during discuss-phase (2026-07-05). Consistent with the
> Phase 23–27 posture: fail-closed / graceful-degrade, reuse existing
> conventions and shared helpers, no over-engineering, honest closure.

### FUNC-03 — Email-config admin API (secrets & RBAC)
- **D-01 — Write-only secrets.** SMTP password / API key are `#[serde(skip_serializing)]` and never returned on GET (config metadata + provider kind only). Consistent with the SECHRD-09 federation-secret posture.
- **D-02 — Update: omit preserves, value replaces.** PATCH/PUT where an omitted secret field keeps the stored ciphertext; an explicit value re-encrypts (AES-256-GCM) and replaces. Pairs with write-only read-back.
- **D-03 — RBAC: `email_config:write` + `email_config:read`.** A single `email_config:write` gates all mutations (matches the AC wording exactly); a separate `email_config:read` gates GET. (Note: diverges from the codebase's per-verb convention, e.g. `federation:create/update/…`, deliberately to honor the AC — flag for the researcher.)
- **D-04 — One handler set, both scopes.** The same endpoints/permission cover org- and tenant-scoped rows (scope + scope_id from the path); tenant config overrides org via the existing `effective_email_config` merge.
- **D-13 — Scope-nested singleton endpoints.** `GET/PUT/DELETE /api/v1/organizations/{org_id}/email-config` and `GET/PUT/DELETE /api/v1/tenants/{tenant_id}/email-config`. `email_config` is a singleton per scope (not a collection), so no POST/list; scope + scope_id resolve from the path for the RBAC check.
- **D-14 — GET returns the raw own-scope row.** At tenant scope, GET returns only that tenant's own override row (the values an admin edits), NOT the merged effective config. (A merged view is not in scope for this phase.)
- **D-15 — Accept credentials blindly.** On write, validate structure only (required fields/format); do NOT perform a live SMTP/API connectivity test. The first real send surfaces bad credentials. Avoids an outbound call at write time and its SSRF/egress surface — consistent with not doing live validation elsewhere.

### FUNC-03 — Custom email-template resolution
- **D-05 — Wire consumer resolution only.** Thread `EmailTemplateRepository` (`SurrealEmailTemplateRepository`) into the mail send path (`mail_consumer.rs::send_with_retry_and_audit`, currently calls `resolve_template(kind, None, None)` at line ~154). Fetch org + tenant templates by `msg.org_id`/`msg.tenant_id` + kind and pass them to the **existing** `resolve_template(kind, org, tenant)`, which already implements the tenant→org→built-in precedence. A **template-authoring CRUD API is OUT OF SCOPE** (deferred — see Deferred Ideas); the AC (T19.21) only requires the consumer to *resolve* custom templates.
- **D-06 — Fail-safe fallback to built-in.** On any custom-template **fetch** error (DB blip) OR **render** error (bad Handlebars), log a warning and fall back to the built-in template so the email still delivers. A broken custom template must never strand a password-reset/verification email. (Contrast with config-fetch failure, which still errors the send — a missing email config means no delivery is possible at all.)

### FUNC-03 — Plaintext-secret backfill
- **D-07 — Accept the honest no-op; close the AC properly.** Unlike `federation_config` (which has a legacy plaintext `client_secret` column that `list_with_legacy_plaintext_secret` + `set_encrypted_secret` migrate), `email_config` was born in Phase 5 with **ciphertext-only columns** — there is no plaintext `smtp_password`/`api_key` source to encrypt, so a genuine encrypt-backfill is impossible and meaningless. Remove the `TODO(T19.22)`, document the email_config-vs-federation difference in the function, and add a test asserting the detection SELECT returns 0 rows and the function is a safe no-op. This satisfies the intent (no unencrypted secrets at rest) honestly rather than inventing a fake backfill. Matches the no-over-engineering stance (cf. SECHRD-05 rejecting a full-chain walk).
- **D-08 — NULL-ciphertext at runtime ⇒ clear misconfiguration error.** If an `email_config` row exists but its secret ciphertext is NULL/missing, `get_effective_config`/the send path returns a clear error ("email config has no usable credential"), consistent with the existing "no email config for org/tenant" failure. Mail visibly won't send until fixed.

### FUNC-04 — Service-account token `sub_kind`
- **D-09 — Stamp an explicit `sub_kind` on ALL mint paths.** Add a `SubjectKind` enum (`User` / `ServiceAccount` / `OAuth2Client`) to `AccessTokenClaims` (`token.rs`). Every mint path sets it explicitly: `issue_access_token` → `User`, the SA cert-auth path (`auth.rs:556`, resolving `TODO(T15)`) → `ServiceAccount`, `issue_client_credentials_token` → `OAuth2Client`. Tokens self-describe their subject — cleanest for SDK modeling and audit attribution, avoids a second inference path.
- **D-10 — Informational only.** `sub_kind` does NOT change validation or authz gating. Validators accept tokens regardless of `sub_kind`; the claim exists for SDK modeling, audit, and future use. Endpoint gating by subject kind is out of scope (would be its own phase).
- **D-11 — Missing `sub_kind` ⇒ treated as `User` (accept).** Tokens issued before this change (no `sub_kind` claim) validate and are treated as `User`/unspecified — no forced re-auth; in-flight tokens keep working through their 15-min TTL. Implementation hint: `#[serde(default)]` with a `User` default on deserialize, always serialized on issue.

### FUNC-01 — Federation first-time login
- **D-12 — Accept the OIDC two-step contract; document it.** OIDC is implemented as public `/oidc/start` + `/oidc/callback` (a redirect-based flow cannot complete in a single `POST /oidc/login` as the AC verbatim names). Keep the two-step flow and update the AC/API docs so generated SDKs model `start → callback`. Do NOT invent a `/oidc/login` facade and do NOT rename the already-shipped SAML `/saml/login`. The verify-and-close work is: confirm the metadata endpoint is public, add the first-time-login e2e, document the contract.

### Verify-and-close scope (FUNC-01 / FUNC-02 / FUNC-05)
- These items appear already implemented (see the domain-boundary table). Phase 28's job for them is **verification + narrow gap-fill** (public-metadata confirmation, first-time-login e2e closing CQ-B40, a session-rejection-after-reset test), **not reimplementation.** The planner should scope them as verification tasks and only implement a genuine missing piece if the researcher finds one.

### Claude's Discretion
Prescriptive enough for the researcher/planner to nail directly — no user decision needed:
- Exact `SubjectKind` serde representation (`#[serde(default)]` + `rename`/lowercase per existing claim conventions).
- The precise seam for threading `EmailTemplateRepository` into `send_with_retry_and_audit` and its callers/wiring in `mail_consumer.rs` / `main.rs`.
- Email-config request/response DTO shapes, validation messages, and error→status mapping (reuse the existing `email.rs` model + `validate_email_config`).
- New permission seeding (`email_config:read`/`email_config:write`) alongside the existing bootstrap permission set.
- Test structure/harness choice for the e2e and unit tests (follow the established Phase 26 CORR-04 / prior-phase testing conventions).
- Whether the SA cert-auth token needs any additional claim beyond `sub_kind` to be a "dedicated token type" (default: `sub_kind` alone satisfies the AC).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

The roadmap lists no external ADR/spec refs for this phase; the authoritative
references are REQUIREMENTS.md and the existing implementation seams below.

### Requirements & roadmap
- `.planning/REQUIREMENTS.md` §FUNC-01…FUNC-05 (lines ~919–957) — locked acceptance criteria
- `.planning/ROADMAP.md` §"Phase 28: Functional Completeness" (line ~1183) — goal + success criteria + dependency (Phase 23 per-endpoint RBAC)

### FUNC-01 — Federation first-time login
- `crates/axiam-api-rest/src/handlers/federation.rs` — `saml_login_public`/`saml_acs_public` (~1407/1507), OIDC `/oidc/start` (~1139) + `/oidc/callback` (~1268), metadata endpoints (SAML ~933, and the metadata handler at ~377 that must be public)
- `crates/axiam-api-rest/src/server.rs` §public `auth_scope` (line ~65) and `api_scope` (line ~269) — where public vs bearer-gated routes are registered

### FUNC-02 — Session invalidation on reset
- `crates/axiam-auth/src/password_reset.rs` — `confirm_reset` (line 184; invalidation at ~296, `invalidate_user_sessions` + `revoke_all_for_user`)

### FUNC-03 — Email-config API, templates, backfill
- `crates/axiam-core/src/models/email.rs` — `EmailConfig` (`scope`/`scope_id`, `SmtpConfig.password`, `ApiProviderConfig.api_key`), `effective_email_config` (line ~190), `validate_email_config` (~139)
- `crates/axiam-db/src/repository/email_config.rs` — `backfill_plaintext_secrets` (line 353, the no-op stub to close), ciphertext/nonce columns
- `crates/axiam-db/src/repository/federation_config.rs` — `list_with_legacy_plaintext_secret` (~446) + `set_encrypted_secret` (~471): the federation backfill analogy that DOESN'T apply to email_config (has a real plaintext column; email_config doesn't)
- `crates/axiam-db/src/repository/email_template.rs` — `SurrealEmailTemplateRepository` (impl at ~235) to thread into the consumer
- `crates/axiam-core/src/repository.rs` §`EmailTemplateRepository` trait (line ~1203) — `get_org_template`/`get_tenant_template`
- `crates/axiam-amqp/src/mail_consumer.rs` — `send_with_retry_and_audit` (line ~127); the `resolve_template(kind, None, None)` gap (~154)
- `crates/axiam-email/src/template.rs` — `resolve_template` (line 130, tenant→org→built-in) + `builtin_template`; `render_email` (~109)

### FUNC-04 — Admin endpoints + SA token
- `crates/axiam-auth/src/token.rs` — `AccessTokenClaims` (line 25), `issue_access_token` (69), `issue_client_credentials_token` (119)
- `crates/axiam-api-rest/src/handlers/auth.rs` — SA cert-auth token `TODO(T15)` (line ~556)
- `crates/axiam-api-rest/src/handlers/users.rs` — `GET /api/v1/users` list (~131/186), `users:admin` gating (~352)
- `crates/axiam-api-rest/src/handlers/mfa_methods.rs` — `list_mfa_methods`/`delete_mfa_method` with `users:admin` gating (~72/116)

### FUNC-05 — Login OpenAPI
- `crates/axiam-api-rest/src/handlers/auth.rs` — login `#[utoipa::path]` responses (line ~259: 200/202/403/401), `LoginSuccessResponse` (93), `MfaRequiredResponse` (100), `MfaSetupRequiredResponse`
- `crates/axiam-api-rest/src/openapi.rs` — schema registrations (line ~189/196)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `resolve_template(kind, org, tenant)` (`template.rs:130`) — already implements the full tenant→org→built-in precedence; the consumer just needs to pass real templates instead of `None, None`.
- `effective_email_config` (`email.rs:190`) + `get_effective_config` (repo) — existing org→tenant merge for the send path; reuse for D-04/D-08.
- SECHRD-09 federation-secret pattern (`#[serde(skip_serializing)]` + AES-256-GCM at rest + Debug scrubbing) — the template for D-01/D-02 email-config secret handling.
- `federation_config.rs` backfill (`list_with_legacy_plaintext_secret` + `set_encrypted_secret`) — the analogy the current email backfill cites (D-17), documented as NOT applicable to email_config in D-07.
- SECHRD-02 shared SSRF-guarded HTTP client — the client any live credential test would have to route through (relevant only if D-15 is ever revisited).

### Established Patterns
- Per-verb RBAC permission strings (`resource:verb`) via `RequirePermission::new("perm", Uuid::nil())` — D-03 deliberately deviates (single `:write`) to honor the AC.
- Flat top-level resource scopes for config resources (`/api/v1/federation-configs/{id}`); D-13 uses scope-nested singletons instead because email_config is one-per-scope.
- Public vs bearer routes split between `auth_scope` and `api_scope` in `server.rs` — where FUNC-01 public endpoints and new bearer-gated email-config endpoints register.
- `#[serde(default)]` claim tolerance for backward-compatible token evolution — D-11.

### Integration Points
- New email-config handlers → `server.rs` `api_scope` under org/tenant paths (bearer + RBAC).
- `EmailTemplateRepository` → injected into the mail consumer's `send_with_retry_and_audit` and wired in `main.rs`.
- `SubjectKind` claim → `AccessTokenClaims` (all three mint paths) + tolerant deserialize in the validator.
- New `email_config:read`/`email_config:write` permissions → bootstrap permission seeding.

</code_context>

<specifics>
## Specific Ideas

- FUNC-05 is already complete (200/202/403/401 documented) — treat as a pure verification checkbox, no code.
- The OIDC first-time flow is `start → callback`, not a single POST — SDK docs/contract must reflect this (D-12).
- Backfill closure should read as an honest "N/A by schema" with a passing test, not a silent stub (D-07).

</specifics>

<deferred>
## Deferred Ideas

- **Email-template authoring CRUD API** (set/delete org/tenant custom templates) — the `EmailTemplateRepository` already has the methods, but exposing them via admin REST is a new capability beyond FUNC-03's "consumer resolves templates" AC. Its own phase.
- **`sub_kind`-based authz enforcement** — gating endpoints by subject kind (e.g., reject ServiceAccount tokens on interactive routes). Beyond FUNC-04's "the claim exists" AC. Its own phase.
- **Live provider-credential validation on write** (SMTP/API connectivity test through the SSRF-guarded client) — deliberately deferred by D-15; revisit if operators report silent misconfig pain.
- **Merged/effective email-config GET view** (`?effective=true`) — D-14 returns raw own-scope only; a merged read view can be added later if the admin UI needs it.

</deferred>

---

*Phase: 28-functional-completeness*
*Context gathered: 2026-07-05*
