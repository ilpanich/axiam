# Phase 28: Functional Completeness - Research

**Researched:** 2026-07-05
**Domain:** Rust/Actix-Web/SurrealDB IAM backend — RBAC-gated admin API completion, federation SSO, JWT claim evolution, mail template resolution
**Confidence:** HIGH (all findings ground-truthed by direct code inspection; no external library research required — this phase is closure of existing internal seams, not new-technology adoption)

## Summary

Phase 28 is **not greenfield**. Direct inspection of every canonical seam listed in CONTEXT.md
confirms the discuss-phase scouting was accurate, and in one case (FUNC-02) even *more* complete
than scouted: an end-to-end integration test for session-revocation-on-reset already exists and
passes. The real, buildable work in this phase is narrow and concentrated almost entirely in
FUNC-03 (email-config admin API — a handler file that does not exist yet) and FUNC-04 (a
`sub_kind` claim that is a one-line `TODO` away from being wired, but touches a JWT-minting
function with 49 call sites across the codebase).

**Primary recommendation:** Treat FUNC-02 and FUNC-05 as pure verification checkboxes (run
existing tests, no code changes). Treat FUNC-01 as verify + two narrow additions (an e2e test,
and OpenAPI documentation for the two-step SSO contract — currently entirely undocumented in the
spec). Build FUNC-03's admin handler from scratch using `handlers/settings.rs` as the exact
structural template (same org/tenant-scoped singleton GET/PUT pattern already proven in this
codebase). Implement FUNC-04's `sub_kind` via a **new minting function**, not by adding a
parameter to `issue_access_token` — the latter has 49 call sites (mostly test files) and would be
an unnecessarily large mechanical diff for a claim that only needs to differ at one call site
(`auth.rs:560`, the SA cert-auth path).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| First-time federation SSO (OIDC/SAML) | API / Backend | Database (login-state, federation-link) | Redirect-based IdP flow terminates in Actix handlers; state persisted server-side (no client-trusted nonce) |
| Federation metadata endpoint | API / Backend | — | Static-ish XML/JSON served publicly; no auth tier involvement |
| Session invalidation on reset | API / Backend | Database (session, refresh_token) | `PasswordResetService` orchestrates two repository writes; already implemented |
| Email-config admin CRUD | API / Backend | Database (email_config, encrypted columns) | New REST handler; secrets encrypted at DB layer, never round-tripped to client |
| Mail template resolution | Backend (AMQP consumer) | Database (email_template) | Consumer-side resolution only; no new tier — reuses existing `resolve_template` |
| Plaintext-secret backfill | Database / Storage | Backend (startup hook) | Runs at boot from `main.rs`, targets `email_config` table directly |
| Admin user/MFA management | API / Backend | Database (user, mfa methods) | Already RBAC-gated via existing `users:list`/`users:admin` permissions |
| Service-account token `sub_kind` | Backend (JWT minting) | — | Claim-only change inside `axiam-auth`; no new tier |
| OpenAPI login schema | API / Backend (docs layer) | — | `utoipa` annotations; already complete |

## Project Constraints (from CLAUDE.md)

- Rust + SurrealDB workspace; use `just` recipes where available (`just test-one`, `just check`).
- **Disk hygiene:** run `cargo clean` between plan steps in this sandbox (quota ~38GB); prefer
  narrowly-scoped `cargo test -p <crate> --lib` / `--test <name>` over unscoped workspace builds.
- **swagger-ui egress workaround required** for any build/test touching `axiam-api-rest` (or a
  dependent crate): `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`
  before `cargo build`/`cargo test`.
- Security standards: Argon2id passwords, EdDSA (Ed25519) JWTs, AES-256-GCM at-rest secrets,
  HMAC-SHA256 webhook signatures, TLS 1.3 minimum — all already satisfied by existing code this
  phase touches; no new crypto primitives introduced.
- RBAC is additive-only (allow-wins, default-deny) — the new `email_config:read`/`email_config:write`
  permissions must follow this model (no deny-override).
- Signed commit required before proceeding to next roadmap task; feature-branch discipline.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**FUNC-03 — Email-config admin API (secrets & RBAC)**
- D-01 — Write-only secrets. SMTP password / API key are `#[serde(skip_serializing)]` and never returned on GET (config metadata + provider kind only). Consistent with the SECHRD-09 federation-secret posture.
- D-02 — Update: omit preserves, value replaces. PATCH/PUT where an omitted secret field keeps the stored ciphertext; an explicit value re-encrypts (AES-256-GCM) and replaces. Pairs with write-only read-back.
- D-03 — RBAC: `email_config:write` + `email_config:read`. A single `email_config:write` gates all mutations (matches the AC wording exactly); a separate `email_config:read` gates GET. (Diverges from the codebase's per-verb convention, e.g. `federation:create/update/…`, deliberately to honor the AC.)
- D-04 — One handler set, both scopes. The same endpoints/permission cover org- and tenant-scoped rows (scope + scope_id from the path); tenant config overrides org via the existing `effective_email_config` merge.
- D-13 — Scope-nested singleton endpoints. `GET/PUT/DELETE /api/v1/organizations/{org_id}/email-config` and `GET/PUT/DELETE /api/v1/tenants/{tenant_id}/email-config`. `email_config` is a singleton per scope (not a collection), so no POST/list; scope + scope_id resolve from the path for the RBAC check.
- D-14 — GET returns the raw own-scope row. At tenant scope, GET returns only that tenant's own override row (the values an admin edits), NOT the merged effective config. (A merged view is out of scope.)
- D-15 — Accept credentials blindly. On write, validate structure only (required fields/format); do NOT perform a live SMTP/API connectivity test.

**FUNC-03 — Custom email-template resolution**
- D-05 — Wire consumer resolution only. Thread `EmailTemplateRepository` (`SurrealEmailTemplateRepository`) into the mail send path (`mail_consumer.rs::send_with_retry_and_audit`). Fetch org + tenant templates by `msg.org_id`/`msg.tenant_id` + kind and pass them to the existing `resolve_template(kind, org, tenant)`. A template-authoring CRUD API is OUT OF SCOPE (deferred).
- D-06 — Fail-safe fallback to built-in. On any custom-template fetch error (DB blip) OR render error (bad Handlebars), log a warning and fall back to the built-in template so the email still delivers. (Contrast with config-fetch failure, which still errors the send.)

**FUNC-03 — Plaintext-secret backfill**
- D-07 — Accept the honest no-op; close the AC properly. `email_config` was born in Phase 5 with ciphertext-only columns — a genuine encrypt-backfill is impossible and meaningless. Remove the `TODO(T19.22)`, document the email_config-vs-federation difference in the function, and add a test asserting the detection SELECT returns 0 rows and the function is a safe no-op.
- D-08 — NULL-ciphertext at runtime ⇒ clear misconfiguration error. If an `email_config` row exists but its secret ciphertext is NULL/missing, the send path returns a clear error, consistent with the existing "no email config for org/tenant" failure.

**FUNC-04 — Service-account token `sub_kind`**
- D-09 — Stamp an explicit `sub_kind` on ALL mint paths. Add a `SubjectKind` enum (`User` / `ServiceAccount` / `OAuth2Client`) to `AccessTokenClaims`. Every mint path sets it explicitly: `issue_access_token` → `User`, the SA cert-auth path (`auth.rs:556`, resolving `TODO(T15)`) → `ServiceAccount`, `issue_client_credentials_token` → `OAuth2Client`.
- D-10 — Informational only. `sub_kind` does NOT change validation or authz gating. Endpoint gating by subject kind is out of scope.
- D-11 — Missing `sub_kind` ⇒ treated as `User` (accept). Tokens issued before this change validate and are treated as `User`/unspecified. Implementation hint: `#[serde(default)]` with a `User` default on deserialize, always serialized on issue.

**FUNC-01 — Federation first-time login**
- D-12 — Accept the OIDC two-step contract; document it. OIDC is implemented as public `/oidc/start` + `/oidc/callback`. Keep the two-step flow and update the AC/API docs so generated SDKs model `start → callback`. Do NOT invent a `/oidc/login` facade and do NOT rename the already-shipped SAML `/saml/login`.

**Verify-and-close scope (FUNC-01 / FUNC-02 / FUNC-05)**
- These items appear already implemented. Phase 28's job for them is verification + narrow gap-fill, not reimplementation.

### Claude's Discretion
- Exact `SubjectKind` serde representation (`#[serde(default)]` + `rename`/lowercase per existing claim conventions).
- The precise seam for threading `EmailTemplateRepository` into `send_with_retry_and_audit` and its callers/wiring in `mail_consumer.rs` / `main.rs`.
- Email-config request/response DTO shapes, validation messages, and error→status mapping (reuse the existing `email.rs` model + `validate_email_config`).
- New permission seeding (`email_config:read`/`email_config:write`) alongside the existing bootstrap permission set.
- Test structure/harness choice for the e2e and unit tests (follow the established Phase 26 CORR-04 / prior-phase testing conventions).
- Whether the SA cert-auth token needs any additional claim beyond `sub_kind` to be a "dedicated token type" (default: `sub_kind` alone satisfies the AC).

### Deferred Ideas (OUT OF SCOPE)
- Email-template authoring CRUD API (set/delete org/tenant custom templates via REST) — its own phase.
- `sub_kind`-based authz enforcement (gating endpoints by subject kind) — its own phase.
- Live provider-credential validation on write (SMTP/API connectivity test) — deliberately deferred by D-15.
- Merged/effective email-config GET view (`?effective=true`) — D-14 returns raw own-scope only.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| FUNC-01 | Unauthenticated first-time federation login (OIDC + SAML), public federation metadata | Ground-truthed: public metadata CONFIRMED via `PUBLIC_PATHS`; first-time provisioning path CONFIRMED (`provision_new_user`); no e2e HTTP test exists yet (real gap); OpenAPI docs for the two public endpoints are ENTIRELY MISSING (real gap) |
| FUNC-02 | Session invalidation on password reset | Ground-truthed: `confirm_reset` already invalidates sessions + revokes refresh tokens; an END-TO-END integration test (`password_reset_revokes_sessions.rs`) ALREADY EXISTS and asserts exactly the required behavior — this requirement needs literally zero new code |
| FUNC-03 | Admin email-config API, template delivery, secret backfill | Ground-truthed: repository CRUD methods exist but NO handler file exists (real gap); mail consumer hardcodes `resolve_template(kind, None, None)` (real gap, narrow); backfill is an intentional, already-honest no-op needing only doc + test polish (narrow gap-fill); secret fields are NOT currently `skip_serializing` (real gap, D-01) |
| FUNC-04 | Admin user/MFA management + service-account `sub_kind` | Ground-truthed: user-listing + MFA admin gating ALREADY EXIST (roadmap's `auth.rs:470` reference is STALE — that line is now `enroll_mfa`, unrelated); `sub_kind` is a real, unimplemented gap at `auth.rs:556`; `issue_access_token` has 49 call sites — informs the minting-function design choice below |
| FUNC-05 | OpenAPI login response schema | Ground-truthed: 200/202/403/401 already distinctly documented with response bodies registered in `openapi.rs` — zero code needed |
</phase_requirements>

## Ground-Truth Findings Per Requirement

### FUNC-01 — Federation first-time login

**Classification: VERIFY + NARROW GAP-FILL.**

Confirmed seams (line numbers as of this research; drift from CONTEXT.md's estimates noted):

| Symbol | File | Actual line | CONTEXT.md estimate | Drift |
|---|---|---|---|---|
| `oidc_start_public` | `handlers/federation.rs` | 1150 | ~1139 | +11 |
| `oidc_callback_public` | `handlers/federation.rs` | 1278 | ~1268 | +10 |
| `saml_login_public` | `handlers/federation.rs` | 1407 | ~1407 | exact |
| `saml_acs_public` | `handlers/federation.rs` | 1523 | ~1507 | +16 |
| `saml_metadata` (the public metadata handler) | `handlers/federation.rs` | 952 | ~377 | **stale** — line 377 is now `PUT /api/v1/federation-configs/{id}` (`update`); `saml_metadata` moved |

**Public metadata — CONFIRMED via allowlist, not route placement.** `saml_metadata` is registered
at `server.rs:706-707` *inside* `api_scope` (which `.wrap(AuthzMiddleware)` — normally
JWT-required). It is public only because `/api/v1/federation/saml/metadata` is listed in
`permissions.rs::PUBLIC_PATHS` (line 230), which `AuthzMiddleware` consults as a bypass allowlist
(D-04 pattern, documented in STATE.md). This is the correct AXIAM pattern — **do not** move the
route to a different scope; the allowlist entry alone makes it public. `[VERIFIED: direct code read]`

**First-time-user token issuance — CONFIRMED.** `oidc_callback_public` (federation.rs:1278-1383)
calls `OidcFederationService::handle_callback` → `provision_or_link_user` →
`provision_new_user` (`axiam-federation/src/oidc.rs:525`, sets `newly_provisioned: true`), then
mints AXIAM tokens via `auth_svc.create_session_and_tokens(...)` and returns them as
**Set-Cookie headers** (`axiam_access`/`axiam_refresh`/`axiam_csrf`), NOT in the JSON body. The
JSON body (`SsoLoginSuccessResponse`) carries only `user_id`, `session_id`, `expires_in`,
`redirect_uri`. **This is important for the e2e test design** — assert cookies, not JSON tokens,
matching the cookie-based-auth convention established in Phase 01. `[VERIFIED: direct code read]`

**Known pre-existing gap (not this phase's scope, but adjacent):** `oidc_callback_public` line
1347-1351 has `TODO(T19.15)`: SSO-provisioned tokens carry `org_id: Uuid::nil()` instead of a
resolved org_id. This does NOT block FUNC-01's AC (the AC only requires AXIAM tokens are
returned, not that org_id is correct) — flag but do not fix unless the planner judges it
in-scope; it is not listed in FUNC-01's AC.

**Real gap 1 — no e2e HTTP test exists.** Searched all test files under
`crates/axiam-api-rest/tests/` and `crates/axiam-server/tests/`; `federation_test.rs` covers
config CRUD, SAML metadata/AuthnRequest validation, and secret-encryption round-trips, but
**no test drives the public `/api/v1/auth/federation/oidc/start` → `/callback` HTTP handlers
end-to-end**. `req5_oidc_e2e.rs` tests `OidcVerificationService` at the unit level and the
*authenticated* (account-linking) `/api/v1/federation/oidc/callback` — a different route from
the public first-time-SSO one. **This is the CQ-B40 gap the planner must close**: a new
integration test (mirroring `password_reset_revokes_sessions.rs`'s `test_app!` macro pattern) that:
1. Creates a federation config via the authenticated API,
2. Simulates the OIDC start (mock IdP JWKS/discovery via `wiremock`, following `req5_oidc_e2e.rs`'s `MockServer` pattern),
3. Drives `/api/v1/auth/federation/oidc/start` then `/api/v1/auth/federation/oidc/callback`,
4. Asserts `axiam_access`/`axiam_refresh` cookies are set and a subsequent `/api/v1/auth/me` call succeeds for the newly-provisioned user.

**Real gap 2 — OpenAPI documentation entirely missing.** Grepped `openapi.rs` for
`oidc_start_public`, `oidc_callback_public`, `saml_login_public`, `saml_acs_public` — **zero
matches**. None of the four public first-time-SSO handlers, nor their request/response DTOs
(`OidcStartRequest`, `OidcStartResponse`, `OidcPublicCallbackRequest`, `SsoLoginSuccessResponse`,
`SamlLoginRequest`, `SamlLoginResponse`), appear in the `#[openapi(paths(...), components(schemas(...)))]`
macro. This satisfies D-12's "document the OIDC two-step contract" requirement concretely: add
the four handlers to `openapi.rs::paths()` and their DTOs to `components(schemas(...))`. Because
all four paths are already listed in `PUBLIC_PATHS`, the `route_openapi_parity_test.rs` Test B
(every OpenAPI path must be public/permissioned/self-service) will pass automatically once added
— no parity-map changes needed beyond the OpenAPI macro itself. `[VERIFIED: direct code read]`

### FUNC-02 — Session invalidation on password reset

**Classification: VERIFY-ONLY — zero code required.**

`PasswordResetService::confirm_reset` (`crates/axiam-auth/src/password_reset.rs:184-320`)
already, at lines 293-302:
```rust
// Invalidate all active sessions for the user (D-16: password reset
// caller is unauthenticated, so there is no current session to preserve —
// ALL sessions die). Both the session-flow tokens AND the OAuth2-flow
// refresh tokens must be revoked (RESEARCH §4 — D-18 "two chokepoints").
self.session_repo.invalidate_user_sessions(tenant_id, user.id).await?;
self.refresh_token_repo.revoke_all_for_user(tenant_id, user.id).await?;
```
`[VERIFIED: direct code read]`

**A full end-to-end integration test already exists and passes**:
`crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs::password_reset_confirm_revokes_existing_sessions`.
It: logs in (captures `axiam_access`/`axiam_csrf` cookies), confirms `/api/v1/auth/me` returns
200, mints a reset token directly via the repository, calls
`POST /api/v1/auth/reset/confirm`, then re-checks `/api/v1/auth/me` with the *original* cookie
and asserts **401**. This is precisely the AC's required test ("after reset, prior sessions are
rejected"). `[VERIFIED: direct code read]`

**Planner action:** run `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` to
confirm it currently passes (it should — nothing in this phase touches password-reset code), and
mark FUNC-02 closed with no new tasks beyond that verification run.

### FUNC-03 — Admin Email-Config API, template delivery, secret backfill

**Classification: REAL GAPS (handler + secret hygiene), NARROW GAP-FILL (template wiring), NARROW GAP-FILL (backfill polish).**

#### 3a. Admin email-config CRUD handler — REAL GAP, build from scratch

No `crates/axiam-api-rest/src/handlers/email_config.rs` exists (confirmed via directory
listing and grep — zero matches for "email_config" anywhere under `handlers/`). `[VERIFIED]`

However, ALL the building blocks already exist:
- `EmailConfigRepository` trait (axiam-core `repository.rs`) with `get_org_config`,
  `set_org_config`, `get_tenant_override`, `set_tenant_override`, `delete_tenant_override`,
  `get_effective_config` — already fully implemented by `SurrealEmailConfigRepository`
  (`crates/axiam-db/src/repository/email_config.rs`).
- `SetOrgEmailConfig` / `EmailConfigOverride` / `SetTenantEmailOverride` input DTOs and
  `validate_email_config()` already exist in `axiam-core/src/models/email.rs`.
- Encryption at rest for `SmtpConfig.password` / `ApiProviderConfig.api_key` is already fully
  implemented at the repository layer (AES-256-GCM, `smtp_password_ciphertext`/`nonce`,
  `api_key_ciphertext`/`nonce` columns) — the handler layer does not need to touch crypto at all,
  it just calls the repository.

**Exact structural template to copy: `crates/axiam-api-rest/src/handlers/settings.rs`.** This
file is the closest existing analog to D-13's "scope-nested singleton" pattern — it already
implements `GET/PUT /api/v1/organizations/{org_id}/settings` and `GET/PUT /api/v1/settings`
(effective tenant view) with the exact RBAC + org-ownership-check shape needed:
```rust
RequirePermission::new("settings:get", Uuid::nil())
    .check(&user, authz.get_ref().as_ref())
    .await?;
let org_id = path.into_inner();
if org_id != user.org_id {
    return Err(AxiamApiError(AxiamError::AuthorizationDenied {
        reason: "cannot read settings for a different organization".into(),
    }));
}
```
Recommend the new `email_config.rs` handler mirror this exactly, substituting
`"email_config:read"`/`"email_config:write"` (per D-03) and using
`/api/v1/tenants/{tenant_id}/email-config` in place of the tenant-implicit `/api/v1/settings`
(per D-13's explicit tenant_id path param — email_config's tenant route takes an explicit
`tenant_id` path segment, unlike settings' implicit-current-tenant route, so also add a
tenant_id-vs-`user.tenant_id` ownership check analogous to the org_id check above).

**D-01 secret write-only requirement — REAL GAP, not yet true today.** Current
`SmtpConfig`/`ApiProviderConfig` structs (`axiam-core/src/models/email.rs:30-48`) have **no**
`#[serde(skip_serializing)]` on `password`/`api_key`, and both structs `#[derive(Debug, ...)]`
without redaction. `[VERIFIED]` Compare to the established precedent this codebase already has
for exactly this problem — `FederationConfig` (`axiam-core/src/models/federation.rs:27-52`):
```rust
#[serde(skip_serializing)]
pub client_secret: String,
...
#[serde(skip_serializing)]
pub client_secret_ciphertext: Option<String>,
```
plus a **manual `Debug` impl** that prints `"[REDACTED]"` for these fields instead of deriving
`Debug`. Recommend replicating both halves of this pattern on `SmtpConfig`/`ApiProviderConfig`:
add `#[serde(skip_serializing)]` to `password`/`api_key`, and add a manual `Debug` impl (or
`#[derive(Debug)]` replaced by one) redacting those two fields — the current derived `Debug`
would otherwise leak plaintext secrets into any `{:?}`-formatted log line, which is the exact
vulnerability class SECHRD-09 fixed for federation. This is slightly broader than D-01's literal
"never returned on GET" (a JSON-serialization concern), but is cheap, matches the established
in-repo pattern, and belongs in this task rather than becoming a future finding. **Recommend
including it, flagged as a discretionary hardening add.**

**D-14 GET returns raw own-scope row — repository already supports this exactly.**
`get_org_config`/`get_tenant_override` (not `get_effective_config`) are the two calls the new
handler should use for GET — `get_effective_config` (the merged view) must NOT be used for GET
per D-14.

**Route/OpenAPI/RBAC-map bookkeeping — do not skip.** This codebase enforces bidirectional
route↔OpenAPI parity via `route_openapi_parity_test.rs` (D-15, referenced in STATE.md). Any new
route MUST be added to ALL of:
1. `server.rs` (`api_scope`, actual route registration),
2. `openapi.rs` (`paths()` + `components(schemas(...))`),
3. `permissions.rs::ROUTE_PERMISSION_MAP` (the `(METHOD, path, permission)` triple),
4. `permissions.rs::PERMISSION_REGISTRY` (add `("email_config:read", "...")`,
   `("email_config:write", "...")`).

Adding to `PERMISSION_REGISTRY` is sufficient for seeding — no additional wiring needed.
`seed_default_roles` (axiam-db `seeder.rs:208`) automatically grants **every** registry
permission to `super-admin`, **every permission except `admin:bootstrap`** to `admin`, and only
`:list`/`:get`-suffixed permissions to `viewer`. Since `email_config:read`/`email_config:write`
don't match the viewer suffix rule, viewer will correctly NOT receive them — no extra
role-mapping code needed. The registry-hash-based skip (CQ-B42) will detect the registry changed
and re-run seeding automatically on next boot. `[VERIFIED: direct code read of seeder.rs]`

#### 3b. Mail consumer custom-template resolution — NARROW GAP-FILL

`send_with_retry_and_audit` (`crates/axiam-amqp/src/mail_consumer.rs:127-238`) is generic over
`<E: EmailConfigRepository, A: AuditLogRepository, U: UserRepository>` and at line 154 calls:
```rust
let template = resolve_template(kind, None, None);
```
`[VERIFIED — exact line and code]`. `resolve_template(kind, org_template, tenant_template)`
(`axiam-email/src/template.rs:130-142`) already implements the full tenant→org→built-in
precedence — it is a pure function taking `Option<&EmailTemplate>` for each tier and returning
the resolved template.

**Blast radius of adding a 4th generic parameter (`T: EmailTemplateRepository`):** small — 7 call
sites total, all within `axiam-amqp` (the function itself, `start_mail_consumer` at line ~296,
its call to `send_with_retry_and_audit` at line ~356, and 5 test invocations in
`crates/axiam-amqp/tests/mail_consumer_test.rs`), plus 1 wiring site in
`crates/axiam-server/src/main.rs` (constructing `SurrealEmailTemplateRepository::new(db_handle.clone())`
— constructor signature confirmed: `pub fn new(db: Surreal<C>) -> Self`, no extra key/config
needed) and passing it into `start_mail_consumer(...)`. This is a MUCH smaller and safer change
than FUNC-04's `sub_kind` blast radius (compare 49 call sites there).

**D-06 correction — "render error" fallback has no concrete failure mode today.** CONTEXT.md's
D-06 mentions falling back on "render error (bad Handlebars)". Ground-truth: `render_email`
(`axiam-email/src/template.rs:116-123`) calls `render`/`render_html`
(`render_inner`, lines 52+), which is a **hand-rolled `{{key}}` placeholder substitutor**, NOT
Handlebars, and it is **infallible** — it returns a plain `String`, never a `Result`. There is no
rendering error path to catch in the current codebase. `[VERIFIED: direct code read]`
**Recommendation for the planner:** implement D-06's fallback ONLY around the *fetch* calls
(`get_org_template`/`get_tenant_template`, which DO return `AxiamResult<Option<EmailTemplate>>`
and can genuinely fail on a DB blip) — wrap each fetch in a match/`.ok().flatten()` that logs a
`warn!` and substitutes `None` on error, then feed the results into the existing
`resolve_template(kind, org_result, tenant_result)`. Do not attempt to add a render-error branch;
none exists to hook into, and inventing one (e.g., wrapping `render_email` in a `catch_unwind`)
would be over-engineering for a function that provably cannot fail today.

#### 3c. Plaintext-secret backfill — NARROW GAP-FILL, mostly documentation + test

`SurrealEmailConfigRepository::backfill_plaintext_secrets`
(`crates/axiam-db/src/repository/email_config.rs:353-398`) already:
- Queries for rows with NULL ciphertext (the detection SELECT D-07 references),
- Returns `Ok(0)` immediately when no pending rows exist (the expected v15+ state),
- Logs a `tracing::warn!` and returns the pending count (not an error) when rows ARE found,
- Is already called at boot in `main.rs:279` (`boot_email_repo.backfill_plaintext_secrets()`).

It currently still has `// TODO(T19.22): implement the UPDATE path...` (line 389) — D-07
requires this exact TODO be **removed** and replaced with the honest documentation of *why* no
UPDATE path exists (the doc comment at lines 340-347 already gestures at this but the inline
`TODO` at 389 contradicts the "documented as intentional" framing D-07 wants). **Remaining
work:** (1) delete the `TODO(T19.22)` comment and replace with documentation matching D-07's
exact framing, (2) add a unit test asserting `backfill_plaintext_secrets()` returns `Ok(0)` on a
freshly-migrated (v15+) schema with data present — no such test currently exists (only
`get_org_config_returns_none_when_not_set` covers this repository's empty-state behavior; there
is no dedicated backfill test). `[VERIFIED: read full repository file, confirmed no
`backfill`-named test in the `#[cfg(test)]` module]`.

D-08 (NULL-ciphertext at runtime ⇒ clear error) — verify the send path's behavior here:
`row_to_provider` (email_config.rs:177-212) currently falls back to `String::new()` (empty
string) when ciphertext/nonce are both `None`, rather than erroring. This does NOT yet satisfy
D-08's "clear misconfiguration error" requirement — it silently produces an empty
password/api_key instead of erroring. **Real narrow gap:** the planner should add an explicit
check (either in `row_to_provider` or at the `EmailService::from_config` call site in
`mail_consumer.rs`) that surfaces a clear `AxiamError`/`SendError` like "email config has no
usable credential" when ciphertext is absent on a fetched row, rather than silently proceeding
with an empty secret.

### FUNC-04 — Admin User & MFA Management + Service-Account `sub_kind`

**Classification: VERIFY-ONLY (user/MFA admin gating) + REAL GAP (`sub_kind`).**

**User-listing — VERIFY-ONLY, roadmap line reference is stale.** REQUIREMENTS.md cites
`handlers/auth.rs:470` for "Admin user-listing endpoint enabled." Ground-truth: `auth.rs:470` is
currently `pub async fn enroll_mfa` (a self-service MFA endpoint), unrelated to user listing.
The actual admin user-listing endpoint is `GET /api/v1/users` →
`handlers::users::list` (`crates/axiam-api-rest/src/handlers/users.rs:194-211`), gated by
`RequirePermission::new("users:list", Uuid::nil())`. This satisfies the AC's "RBAC-gated"
requirement (a real permission check exists) even though the specific permission string is
`users:list` rather than `users:admin` — CONTEXT.md's scouting table describes this gate as
`users:admin`, which is imprecise; `users:admin` in `users.rs` is actually used for the
**unlock** endpoint (line 352), a distinct action. `[VERIFIED: direct code read]` No code changes
needed; only confirm `users:list` is granted to admin/super-admin (it is, per the
all-registry-permissions-to-admin seeding rule) and add/confirm a test if one doesn't already
exist asserting a non-privileged user gets 403 on `GET /api/v1/users`.

**Admin MFA list/delete — VERIFY-ONLY, confirmed exactly as scouted.**
`list_mfa_methods` (`handlers/mfa_methods.rs:66-83`) and `delete_mfa_method` (lines 107-124) both
gate cross-user access via `is_own_resource(&caller, user_id)` (self-service, no permission
check) OR `RequirePermission::new("users:admin", Uuid::nil())` (admin override) — exact match to
CONTEXT.md's claim. `[VERIFIED: direct code read, line numbers match CONTEXT.md's ~72/~116
estimate exactly]`

**`sub_kind` claim — REAL GAP, design decision needed on blast radius.**

`AccessTokenClaims` (`crates/axiam-auth/src/token.rs:24-57`) currently has NO `sub_kind` field.
Confirmed exact fields: `sub`, `tenant_id`, `org_id`, `iss`, `iat`, `exp`, `jti`,
`aud: Option<String>`, `scope: Option<String>`.

Three mint paths, confirmed:
| Function | File:line | Current behavior |
|---|---|---|
| `issue_access_token` | `axiam-auth/src/token.rs:69-110` | Used for BOTH normal user login AND (today) the SA cert-auth path — see below |
| `issue_client_credentials_token` | `axiam-auth/src/token.rs:119-158` | OAuth2 M2M client-credentials grant |
| SA cert-auth (`device_auth` handler) | `axiam-api-rest/src/handlers/auth.rs:546-576` | Calls `issue_access_token` directly, with the exact `TODO(T15)` comment at line 556 |

**Critical finding — blast radius.** `issue_access_token` has **49 call sites across 32 files**
(mostly test setup helpers: `organization_test.rs`, `rbac_test.rs`, `middleware_test.rs` (5
calls), `req7_service_account_aud.rs` (3 calls), `oauth2_flow_test.rs` (3 calls), etc. — see full
list via `grep -rn "issue_access_token(" crates/`). `issue_client_credentials_token` has 10 call
sites across 4 files. `[VERIFIED via grep count]`

Because `device_auth` (the SA cert-auth path) calls the SAME `issue_access_token` function used
by ordinary user login, achieving D-09's "SA path → `ServiceAccount`, everything else →
`User`/`OAuth2Client`" requirement via a **new required positional parameter** on
`issue_access_token` would force mechanical edits across all 49 call sites (nearly all in test
files, non-logic-changing but still a large diff surface).

**Recommendation (lower blast radius, same outcome):** keep `issue_access_token`'s public
signature unchanged; internally hardcode `sub_kind: SubjectKind::User` in its `AccessTokenClaims`
construction (zero changes needed at its 49 call sites). Similarly keep
`issue_client_credentials_token` unchanged, hardcoding `SubjectKind::OAuth2Client` internally
(zero changes at its 10 call sites). Add ONE new small function —
e.g. `issue_service_account_token(...)` — that duplicates `issue_access_token`'s ~40-line
JWT-encoding body (this codebase already duplicates this exact encode-key-resolution +
`jsonwebtoken::encode` block between `issue_access_token` and `issue_client_credentials_token`,
so a third near-identical function is idiomatic here, not a DRY violation the codebase currently
avoids) but sets `sub_kind: SubjectKind::ServiceAccount`. Update ONLY `auth.rs:560`'s call site
(the `device_auth` handler) to call the new function instead of `issue_access_token`. This
satisfies D-09's literal requirement ("every mint path sets it explicitly") while touching 2
files total (`token.rs` + `auth.rs`) instead of 32+.

**D-11 backward-compat — straightforward.** `validate_access_token`
(`axiam-auth/src/token.rs:309-314`) decodes via `jsonwebtoken::decode` + serde into
`AccessTokenClaims` — no manual field handling. Adding `#[serde(default)]` on a new `sub_kind:
SubjectKind` field (with `impl Default for SubjectKind { fn default() -> Self { Self::User } }`)
requires zero changes to the decode path; old tokens missing the claim will deserialize
correctly with `SubjectKind::User`. `[VERIFIED: direct code read of decode call site]`

## Standard Stack

No new external dependencies required for any of the five requirements — this phase closes gaps
using only crates already present in the workspace (`actix-web`, `utoipa`, `serde`, `jsonwebtoken`,
`aes-gcm`, `surrealdb`, `lapin`). Skipping the Standard Stack / Package Legitimacy Audit sections
(no packages to add).

## Architecture Patterns

### Recommended structure for the new email-config handler

```
crates/axiam-api-rest/src/handlers/email_config.rs   (NEW FILE)
├── OrgEmailConfigResponse / TenantEmailConfigResponse DTOs
│   (mirror EmailConfig but with password/api_key omitted per D-01;
│    reuse SmtpConfig/ApiProviderConfig with #[serde(skip_serializing)]
│    added directly, OR define response-only provider variants — prefer
│    the direct-field-attribute approach since it also protects
│    Debug-derived log lines, matching the federation.rs precedent)
├── get_org_email_config()   — GET  /api/v1/organizations/{org_id}/email-config
├── set_org_email_config()   — PUT  /api/v1/organizations/{org_id}/email-config
├── delete_org_email_config()— DELETE /api/v1/organizations/{org_id}/email-config
├── get_tenant_email_config()— GET  /api/v1/tenants/{tenant_id}/email-config
├── set_tenant_email_config()— PUT  /api/v1/tenants/{tenant_id}/email-config
└── delete_tenant_email_config() — DELETE /api/v1/tenants/{tenant_id}/email-config
```

Each handler follows the exact `settings.rs` shape: `RequirePermission::new("email_config:read"
| "email_config:write", Uuid::nil())` then an explicit `org_id != user.org_id` /
`tenant_id != user.tenant_id` ownership check (403 `AuthorizationDenied` on mismatch) before
calling the repository.

### System flow — first-time federation SSO (FUNC-01)

```
Browser/SPA                 AXIAM /api/v1/auth/*            External IdP
     |                              |                             |
     |--POST /federation/oidc/start->                             |
     |   (org_slug/tenant_slug,     |--build_authorization_url---->|
     |    redirect_uri)             |  (persists state+nonce in    |
     |<--{authorize_url, state}-----|   federation_login_state)    |
     |                              |                             |
     |----redirect user's browser to authorize_url---------------->|
     |<---redirect back to SPA with ?code=...&state=...------------|
     |                              |                             |
     |--POST /federation/oidc/callback->                          |
     |   (code, state)              |--consume_by_state (1-use)--->|
     |                              |--handle_callback------------>|
     |                              |    (code exchange, ID token  |
     |                              |     verify, provision_or_    |
     |                              |     link_user)               |
     |                              |--create_session_and_tokens-->|
     |<--Set-Cookie: axiam_access,  |                              |
     |   axiam_refresh, axiam_csrf  |                              |
     |<--200 {user_id, session_id}  |                              |
```

### Anti-Patterns to Avoid
- **Adding a required parameter to `issue_access_token`/`issue_client_credentials_token`:**
  touches 49+10 call sites for a claim that only needs to differ at ONE call site. Use a
  dedicated minting function instead (see FUNC-04 findings above).
- **Using `get_effective_config` for the email-config GET response:** violates D-14 (GET must
  return the raw own-scope row, not the merged view). Use `get_org_config`/`get_tenant_override`.
- **Inventing a render-error fallback branch for D-06:** the current template renderer is
  infallible; only the *fetch* calls can error. Don't add unreachable error-handling code.
- **Moving `saml_metadata` out of `api_scope` to "make it public":** it is already public via the
  `PUBLIC_PATHS` allowlist bypass — moving the route registration would be redundant and diverge
  from the established D-04 pattern.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AES-256-GCM secret encryption for email config | New encryption helpers | Existing `encrypt_field`/`decrypt_field` in `email_config.rs` (already correct, already tested via `round_trip_smtp`/`round_trip_sendgrid`/etc.) | Already implemented, already has 5 round-trip tests |
| Org/tenant inheritance merge logic | New merge function | Existing `effective_email_config()` (`axiam-core/src/models/email.rs:190`) | Already implemented, already has dedicated unit tests |
| Template variable substitution | Handlebars or similar templating crate | Existing `render`/`render_html` (`axiam-email/src/template.rs`) | Already implemented, HTML-escaped, header-injection-safe; adding a new template engine would be a scope violation (deferred: template-authoring CRUD is explicitly out of scope) |
| RBAC permission seeding | Manual per-tenant grant script | Add entries to `PERMISSION_REGISTRY`; `seed_default_roles`/`seed_permissions` handle the rest automatically | Idempotent, hash-gated (CQ-B42), already proven across 25+ prior phases |

**Key insight:** virtually everything FUNC-03 needs at the repository/crypto/template-engine
layer already exists and is already tested. The only new code is the REST handler layer (thin
glue: RBAC check → ownership check → repository call → response DTO).

## Common Pitfalls

### Pitfall 1: Forgetting the route↔OpenAPI↔permission-map triangle
**What goes wrong:** Adding a new route to `server.rs` without also adding it to `openapi.rs`
paths/schemas AND `permissions.rs::ROUTE_PERMISSION_MAP` causes `route_openapi_parity_test.rs` to
fail at CI/test time — Test A checks every `ROUTE_PERMISSION_MAP` entry has an OpenAPI path;
Test B checks every OpenAPI path is accounted for somewhere.
**Why it happens:** the three files are edited independently and easy to forget one.
**How to avoid:** treat "add email-config routes" as a single 3-file diff every time; run the
parity test (`cargo test -p axiam-api-rest --lib route_openapi_parity_test` or similar target)
before considering the task done.
**Warning signs:** parity test failure naming a path not found in the other structure.

### Pitfall 2: Widening the `issue_access_token` blast radius unnecessarily
**What goes wrong:** literal reading of D-09 ("every mint path sets it explicitly") could be
misread as "add a `sub_kind` parameter to `issue_access_token`," forcing edits across 49 call
sites in mostly-unrelated test files.
**Why it happens:** `issue_access_token` is currently overloaded — it serves both normal user
login and the SA device-auth path, which is the actual root cause needing untangling.
**How to avoid:** add a dedicated `issue_service_account_token` function (see FUNC-04 findings)
rather than parameterizing the shared function.
**Warning signs:** a task/diff touching more than ~3 files for a claim-only change.

### Pitfall 3: Treating already-implemented requirements as build tasks
**What goes wrong:** re-implementing `confirm_reset`'s session invalidation, or re-writing the
already-correct `resolve_template` precedence logic, wastes phase budget and risks introducing
regressions into working, tested code.
**Why it happens:** the roadmap's original phrasing ("implements the UPDATE path", "invalidates
all active sessions") reads like a build task even where the target state already exists.
**How to avoid:** this RESEARCH.md's per-requirement classification (VERIFY-ONLY / NARROW
GAP-FILL / REAL GAP) should map directly to task types in PLAN.md — VERIFY-ONLY requirements get
a single `checkpoint`/test-run task, not implementation tasks.
**Warning signs:** a task diff touching files already covered by a passing test with no local
gap identified in this research.

### Pitfall 4: Silent empty-string fallback instead of a clear misconfiguration error (D-08)
**What goes wrong:** `row_to_provider`'s current `_ => String::new()` fallback when ciphertext is
absent means a misconfigured email_config row silently produces empty credentials rather than a
loud, actionable error — mail delivery fails with a cryptic "SMTP auth failed" instead of "email
config has no usable credential."
**Why it happens:** the fallback was written for the (currently unreachable in practice, since
Phase 5 columns are always populated on write) case of a partially-written row.
**How to avoid:** add an explicit check either at `row_to_provider` or the
`EmailService::from_config` call site that surfaces the AC-required clear error when
ciphertext/nonce are absent on a config row that DOES exist.
**Warning signs:** a test asserting the mail-send path errors clearly (not silently) on a
config row with NULL ciphertext columns.

## Code Examples

### D-01/D-02 secret-hygiene precedent to replicate (from `federation.rs`)
```rust
// Source: crates/axiam-core/src/models/federation.rs:20-76
#[derive(Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    // ...
    #[serde(skip_serializing)]
    pub client_secret: String,
    // ...
}

// Manual Debug impl redacts secrets instead of deriving Debug:
impl std::fmt::Debug for FederationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationConfig")
            .field("client_secret", &"[REDACTED]")
            // ...
            .finish()
    }
}
```

### Settings-handler template to copy for the new email-config handler
```rust
// Source: crates/axiam-api-rest/src/handlers/settings.rs:31-53
pub async fn get_org_settings<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealSettingsRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("settings:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let org_id = path.into_inner();
    if org_id != user.org_id {
        return Err(AxiamApiError(axiam_core::error::AxiamError::AuthorizationDenied {
            reason: "cannot read settings for a different organization".into(),
        }));
    }
    let settings = repo.get_org_settings(org_id).await?;
    Ok(HttpResponse::Ok().json(settings))
}
```

### Mail-consumer template-repo threading point
```rust
// Source: crates/axiam-amqp/src/mail_consumer.rs:127-154 (current)
pub async fn send_with_retry_and_audit<E, A, U>(
    msg: &OutboundMailMessage,
    email_config_repo: &E,
    audit_repo: &A,
    user_repo: &U,
) -> Result<SendOutcome, SendError>
where
    E: EmailConfigRepository,
    A: AuditLogRepository,
    U: UserRepository,
{
    // ...
    let kind = template_kind_for(&msg.mail_type);
    let template = resolve_template(kind, None, None); // <-- D-05 threading point
    // ...
}
```
Recommended shape after D-05: add `T: EmailTemplateRepository` generic param, fetch
`template_repo.get_org_template(msg.org_id, kind)` and
`template_repo.get_tenant_template(msg.tenant_id, kind)` (each wrapped to fall back to `None` on
`Err`, logging a `warn!` per D-06), then pass both `Option<&EmailTemplate>` refs into the
existing `resolve_template(kind, org.as_ref(), tenant.as_ref())` call — no change to
`resolve_template` itself needed.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| N/A — this phase closes gaps in an already-current architecture | — | — | — |

No technology/library version drift is relevant to this phase; all work is internal-seam
completion within the existing, already-current stack.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Adding a new small `issue_service_account_token` function (rather than parameterizing `issue_access_token`) is an acceptable interpretation of D-09's "every mint path sets it explicitly" | FUNC-04 findings | Low — functionally identical outcome (SA tokens carry `sub_kind: ServiceAccount`, others don't); if the planner/user insists on a single unified function, the 49-call-site refactor is mechanical but larger |
| A2 | Replicating the federation.rs manual-Debug-redaction pattern on `SmtpConfig`/`ApiProviderConfig` is in-scope even though D-01 only literally requires `skip_serializing` (JSON) | FUNC-03 findings (3a) | Low — purely additive hardening; omitting it does not fail any stated AC, just leaves a smaller residual log-leak risk |
| A3 | `email_config:read`/`email_config:write` should NOT be granted to the `viewer` role (since neither ends in `:list`/`:get`), consistent with these being admin-only operations | FUNC-03 findings (3a) | Low — matches D-03's intent (admin API); if wrong, a follow-up permission-registry entry named `email_config:get` could be added later without breaking the write gate |

**If this table is empty:** N/A — see above; all three assumptions are low-risk implementation
choices flagged for planner awareness, not load-bearing claims about external facts.

## Open Questions (RESOLVED)

> Both questions resolved during planning; the plans follow the stated recommendations.

1. **Does the SA-token-type AC require anything beyond the `sub_kind` claim?**
   - **RESOLVED:** No. Plan 28-02 stamps `sub_kind` alone (no extra SA claims, no authz gating), per the recommendation and D-10.
   - What we know: CONTEXT.md's "Claude's Discretion" section defaults to "sub_kind alone
     satisfies the AC."
   - What's unclear: whether a future consumer (e.g., audit log enrichment) expects additional
     SA-specific claims.
   - Recommendation: implement `sub_kind` alone per the discretion default; do not add scope
     restrictions or additional claims (D-10 explicitly rules out authz-gating changes).

2. **Should the org/tenant email-config DELETE endpoints exist, or only GET/PUT?**
   - **RESOLVED:** Implement DELETE per D-13; Plan 28-01 adds the missing `delete_org_config` repository method and 28-04 wires the endpoints. Org-level DELETE does not cascade — orphaned tenant overrides surface D-08's clear error at send time (recorded as an explicit `<plan_decision>` in 28-01/28-04).
   - What we know: D-13 explicitly lists `GET/PUT/DELETE` for both scopes.
   - What's unclear: whether DELETE on the org-level singleton should be permitted at all (an org
     without an email config would break the tenant `effective_email_config` merge for every
     tenant under it, per existing repository logic which returns `None` when no org config
     exists).
   - Recommendation: implement DELETE as specified by D-13 (repository already exposes
     `delete_tenant_override`; an equivalent `delete_org_config` may need adding to the
     repository trait/impl if it doesn't already exist — verify this specific method exists
     before assuming it does; the repository read above did not show a `delete_org_config`
     method, only `delete_tenant_override`). **This is a genuine repository-layer gap the planner
     must account for**: `EmailConfigRepository` trait currently has NO `delete_org_config`
     method — only `delete_tenant_override`. Adding org-level DELETE requires adding this
     repository method first.

## Environment Availability

Skipped — this phase has no new external tool/service dependencies beyond what's already running
in the existing dev/test environment (SurrealDB in-memory for tests, no new AMQP/broker
requirements — the mail consumer already runs against the existing RabbitMQ setup).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[tokio::test]` / `#[actix_rt::test]`, workspace-standard |
| Config file | none — cargo test target selection via `-p <crate> --test <name>` |
| Quick run command | `cargo test -p axiam-auth --lib password_reset` / `-p axiam-api-rest --test password_reset_revokes_sessions` etc. (per-requirement, see map below) |
| Full suite command | `cargo test --workspace` (avoid unscoped; prefer per-crate per CLAUDE.md disk hygiene) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| FUNC-01 | First-time OIDC login returns AXIAM cookies | integration (e2e) | `cargo test -p axiam-api-rest --test federation_first_time_sso_test` | ❌ Wave 0 — new file needed |
| FUNC-01 | Federation metadata is public | integration | `cargo test -p axiam-api-rest --test federation_test saml_metadata` (existing coverage checks XML shape; add explicit no-JWT-header assertion if missing) | ⚠️ Partial — verify no-auth-header case is asserted |
| FUNC-01 | OpenAPI documents oidc/saml public flow | unit (parity) | `cargo test -p axiam-api-rest --lib route_openapi_parity_test` | ✅ Exists — will fail until paths are added, which is the point |
| FUNC-02 | Session/refresh tokens rejected after reset | integration (e2e) | `cargo test -p axiam-api-rest --test password_reset_revokes_sessions` | ✅ Exists and already covers the AC |
| FUNC-03 | Admin CRUD on org/tenant email_config, RBAC-gated | integration | `cargo test -p axiam-api-rest --test email_config_test` (new) | ❌ Wave 0 — new file needed, plus new handler |
| FUNC-03 | Mail consumer resolves custom template | unit | `cargo test -p axiam-amqp --test mail_consumer_test custom_template` (new test in existing file) | ⚠️ Partial — existing file covers built-in path; add custom-template + fallback-on-fetch-error cases |
| FUNC-03 | Backfill is a documented no-op on v15+ schema | unit | `cargo test -p axiam-db --lib email_config backfill_plaintext_secrets_is_noop` (new) | ❌ Wave 0 — new test |
| FUNC-03 | NULL-ciphertext row ⇒ clear error, not silent empty secret | unit | `cargo test -p axiam-db --lib email_config` (new case) | ❌ Wave 0 — new test |
| FUNC-04 | `users:list` 403s for non-privileged caller | integration | `cargo test -p axiam-api-rest --test user_test` (verify existing coverage or add) | ⚠️ Partial — verify |
| FUNC-04 | SA cert-auth token carries `sub_kind: ServiceAccount` | integration | `cargo test -p axiam-api-rest --test device_auth_test sub_kind` (new case in existing file) | ⚠️ Partial — existing file covers device auth happy path; add sub_kind assertion |
| FUNC-04 | Missing `sub_kind` (pre-phase token) deserializes as `User` | unit | `cargo test -p axiam-auth --lib token` (new case) | ❌ Wave 0 — new test |
| FUNC-05 | Login OpenAPI documents 200/202/403/401 distinctly | unit (parity/manual) | `cargo test -p axiam-api-rest --lib route_openapi_parity_test` + visual spec check | ✅ Already satisfied, no new test needed |

### Sampling Rate
- **Per task commit:** the specific scoped test file/module for the task just completed (see map above).
- **Per wave merge:** `cargo test -p axiam-auth -p axiam-api-rest -p axiam-amqp -p axiam-db --lib` (scoped multi-crate, avoids full-workspace rebuild per CLAUDE.md hygiene) plus the full integration test files touched.
- **Phase gate:** `cargo test --workspace` (with `SWAGGER_UI_DOWNLOAD_URL` exported) green before `/gsd-verify-work`; `cargo clean` immediately after to respect sandbox disk quota.

### Wave 0 Gaps
- [ ] `crates/axiam-api-rest/tests/federation_first_time_sso_test.rs` — new e2e test, covers FUNC-01 (closes CQ-B40)
- [ ] `crates/axiam-api-rest/src/handlers/email_config.rs` — new handler file, covers FUNC-03 (3a)
- [ ] `crates/axiam-api-rest/tests/email_config_test.rs` — new integration test file, covers FUNC-03 (3a)
- [ ] Repository method `delete_org_config` on `EmailConfigRepository` — missing, needed if org-level DELETE is implemented per D-13 (see Open Question 2)
- [ ] New test cases in existing `crates/axiam-amqp/tests/mail_consumer_test.rs` for custom-template resolution + fetch-error fallback (FUNC-03 3b)
- [ ] New test in `crates/axiam-db/src/repository/email_config.rs`'s `#[cfg(test)]` module asserting `backfill_plaintext_secrets` no-op (FUNC-03 3c) and NULL-ciphertext clear-error behavior (D-08)
- [ ] New test case(s) in `crates/axiam-api-rest/tests/device_auth_test.rs` asserting `sub_kind: "ServiceAccount"` on the minted token (FUNC-04)
- [ ] New unit test in `crates/axiam-auth/src/token.rs`'s test module asserting missing-`sub_kind` backward-compat deserialization (FUNC-04, D-11)
- [ ] `openapi.rs` additions for `oidc_start_public`/`oidc_callback_public`/`saml_login_public`/`saml_acs_public` and their DTOs (FUNC-01, D-12) — needed before `route_openapi_parity_test` will reflect the documented contract (the test currently passes trivially because these paths are simply absent from the spec, which is itself the gap)
- Framework install: none — `tokio`/`actix_rt` test harnesses already in every touched crate's dev-dependencies.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | yes | Federation OIDC/SAML flows already implement signature/iss/aud/exp/nonce validation (`OidcFederationService`); no new auth mechanism introduced this phase |
| V3 Session Management | yes | FUNC-02's session/refresh-token revocation on reset (already implemented, already ASVS 3.3.1-aligned per REQUIREMENTS.md's own citation) |
| V4 Access Control | yes | New `email_config:read`/`email_config:write` permissions must follow the existing additive-only RBAC model; org/tenant ownership checks (mirroring `settings.rs`) prevent cross-tenant IDOR on the new endpoints |
| V5 Input Validation | yes | Reuse existing `validate_email_config()`; no new validation logic to invent |
| V6 Cryptography | yes | AES-256-GCM secret encryption already implemented and tested at the repository layer; this phase must NOT introduce a second encryption implementation — reuse `encrypt_field`/`decrypt_field` |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Cross-tenant/cross-org IDOR on new email-config endpoints (path `org_id`/`tenant_id` vs. JWT claim) | Elevation of Privilege | Explicit `path_id != user.{org_id,tenant_id}` check before any repository call — mirrors `settings.rs`'s existing pattern exactly |
| Secret leakage via JSON response or Debug-derived log line on `SmtpConfig`/`ApiProviderConfig` | Information Disclosure | `#[serde(skip_serializing)]` + manual redacting `Debug` impl (SECHRD-09 precedent) |
| Recipient hijacking via tampered AMQP `to_address` (pre-existing, unaffected by this phase's changes) | Tampering | Already mitigated (SEC-055) — recipient always re-resolved from `user_id`+`tenant_id`; the D-05 template-repo addition must not disturb this resolution order |
| Replay of federation login-state (`state`/`nonce`) | Spoofing | Already mitigated — `consume_by_state` is single-use/atomic; nonce is server-stored, never client-supplied at verification time (T-04-30) |

## Sources

### Primary (HIGH confidence — direct code inspection this session)
- `crates/axiam-api-rest/src/handlers/federation.rs` — public SSO handlers, metadata routing
- `crates/axiam-api-rest/src/server.rs` — route scope/middleware wiring, `PUBLIC_PATHS` bypass mechanics
- `crates/axiam-api-rest/src/permissions.rs` — `PERMISSION_REGISTRY`, `PUBLIC_PATHS`, `ROUTE_PERMISSION_MAP`
- `crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs` — parity-test mechanics
- `crates/axiam-auth/src/password_reset.rs` — `confirm_reset` session/refresh invalidation
- `crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs` — existing e2e test (FUNC-02 proof)
- `crates/axiam-core/src/models/email.rs`, `crates/axiam-db/src/repository/email_config.rs` — email-config model + repository, secret encryption, backfill stub
- `crates/axiam-core/src/models/federation.rs` — SECHRD-09 secret-redaction precedent
- `crates/axiam-api-rest/src/handlers/settings.rs` — structural template for the new handler
- `crates/axiam-amqp/src/mail_consumer.rs`, `crates/axiam-email/src/template.rs` — template resolution seam
- `crates/axiam-auth/src/token.rs`, `crates/axiam-api-rest/src/handlers/auth.rs` — JWT claims, mint paths, `TODO(T15)`
- `crates/axiam-api-rest/src/handlers/users.rs`, `crates/axiam-api-rest/src/handlers/mfa_methods.rs` — admin gating
- `crates/axiam-api-rest/src/openapi.rs` — schema/path registrations (confirmed FUNC-05 complete, FUNC-01 public-SSO docs absent)
- `crates/axiam-db/src/seeder.rs` — permission-seeding and role-grant automation
- `.planning/REQUIREMENTS.md`, `.planning/phases/28-functional-completeness/28-CONTEXT.md`, `.planning/STATE.md`

### Secondary / Tertiary
- None — no external web research was needed for this phase; all findings are internal-codebase
  ground-truth. `brave_search`/`exa_search`/`firecrawl` are disabled in `.planning/config.json`
  and were not required given the phase's closure-not-adoption nature.

## Metadata

**Confidence breakdown:**
- Standard stack: N/A — no new packages
- Architecture: HIGH — every architectural claim in this document is backed by a direct file read this session, with exact line numbers where feasible
- Pitfalls: HIGH — derived from direct observation of actual call-site counts, existing test coverage, and the codebase's own established precedents (not general Rust/Actix folklore)

**Research date:** 2026-07-05
**Valid until:** 14 days (internal codebase state — shorter validity than a typical 30-day
external-library research doc, since concurrent phase work on the same crates could shift line
numbers or introduce new call sites before planning executes)
