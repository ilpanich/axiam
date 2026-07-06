---
phase: 28-functional-completeness
plan: 04
subsystem: api
tags: [rest, actix-web, rbac, openapi, email-config, federation-sso, surrealdb]

# Dependency graph
requires:
  - phase: 28-functional-completeness (plan 01)
    provides: "Write-only/redacted email-provider secrets (D-01), omit-preserve write semantics (D-02), delete_org_config (D-13), NULL-ciphertext read error (D-08)"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Scope-nested singleton REST resource with an explicit ownership check before any repository call — path org_id/tenant_id vs. AuthenticatedUser.org_id/tenant_id, mirroring settings.rs's precedent (T-28-01 IDOR mitigation)"
    - "Single shared permission (email_config:read/write) across both org and tenant scopes, not per-verb-per-scope (D-03)"
    - "Conditional actix app_data registration: App::app_data() returns Self (does not change App's generic type parameter), so a repository requiring an optional runtime key can be registered only when the key is present, composing cleanly with a single-expression App builder chain"

key-files:
  created:
    - crates/axiam-api-rest/src/handlers/email_config.rs
    - crates/axiam-api-rest/tests/email_config_test.rs
  modified:
    - crates/axiam-api-rest/src/handlers/mod.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/permissions.rs
    - crates/axiam-api-rest/src/openapi.rs
    - crates/axiam-server/src/main.rs
    - crates/axiam-db/src/schema.rs

key-decisions:
  - "email_config:read/write is a single permission pair shared across org and tenant scopes and across GET (read) / PUT+DELETE (write) verbs — not four separate permissions — per D-03, mirroring the existing /api/v1/settings pattern."
  - "GET always calls get_org_config/get_tenant_override (the raw own-scope row), never get_effective_config, per D-14 — admins editing a tenant override must see exactly what they set, not the org-merged view."
  - "email_config_repo is registered as REST app_data only when AXIAM__EMAIL_ENCRYPTION_KEY is present (fail-closed, no zero-key fallback) — mirrors the existing mail-consumer conditional-spawn pattern in main.rs."
  - "Schema v23 (DEFINE FIELD OVERWRITE) extends email_config.provider_kind's ASSERT to accept the empty-string sentinel, fixing a latent write/read asymmetry bug in set_tenant_override that this plan's PUT tenant handler was the first caller to exercise."

patterns-established:
  - "utoipa OpenAPI doc split: paths not behind #[cfg(feature = \"saml\")] go in the main ApiDoc; SAML-feature-gated paths (and only those) go in the separate SamlApiDoc merged in by api_doc() — verified against each handler's own cfg attribute rather than assumed from co-location."

requirements-completed: [FUNC-03, FUNC-01]

coverage:
  - id: D1
    description: "Six scope-nested singleton handlers (GET/PUT/DELETE org+tenant) for admin email-config, RBAC-gated by email_config:read/write, secret-omitting responses"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#org_email_config_put_get_round_trip_omits_secrets"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#tenant_email_config_put_get_delete_round_trip"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#org_email_config_delete_then_get_returns_404"
        status: pass
    human_judgment: false
  - id: D2
    description: "Cross-org/cross-tenant callers are blocked with 403 (T-28-01 IDOR mitigation) before any repository call"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#org_email_config_cross_org_returns_403"
        status: pass
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#tenant_email_config_cross_tenant_returns_403"
        status: pass
    human_judgment: false
  - id: D3
    description: "D-02 omit-preserve semantics hold end-to-end through the REST layer: a PUT that omits the secret preserves the previously stored one"
    requirement: "FUNC-03"
    verification:
      - kind: integration
        ref: "crates/axiam-api-rest/tests/email_config_test.rs#org_email_config_omitted_secret_preserves_stored_password"
        status: pass
    human_judgment: false
  - id: D4
    description: "The route↔OpenAPI↔permission triangle is complete for email-config and the parity test passes"
    requirement: "FUNC-03"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs#every_authed_route_is_in_openapi"
        status: pass
      - kind: unit
        ref: "crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs#every_openapi_path_is_registered"
        status: pass
    human_judgment: false
  - id: D5
    description: "The four public first-time-SSO handlers (oidc_start_public, oidc_callback_public, saml_login_public, saml_acs_public) and their DTOs are documented in the OpenAPI spec (FUNC-01/D-12)"
    requirement: "FUNC-01"
    verification:
      - kind: unit
        ref: "crates/axiam-api-rest/src/tests/route_openapi_parity_test.rs#every_openapi_path_is_registered"
        status: pass
    human_judgment: false

duration: ~35min
completed: 2026-07-05
status: complete
---

# Phase 28 Plan 04: Admin Email-Config REST API + Public-SSO OpenAPI Docs Summary

**Six RBAC-gated, IDOR-safe, secret-omitting REST handlers for org/tenant email-config CRUD (closing FUNC-03), plus OpenAPI documentation for the four already-shipped public first-time-SSO endpoints (closing the FUNC-01 doc gap) — with a schema fix for a latent set_tenant_override write bug the new PUT handler was the first caller to exercise.**

## Performance

- **Duration:** ~35 min
- **Completed:** 2026-07-05T21:03:17Z
- **Tasks:** 3 completed
- **Files modified:** 8 (2 created, 6 modified)

## Accomplishments

- `handlers/email_config.rs`: six handlers (`get_org_email_config`, `set_org_email_config`, `delete_org_email_config`, `get_tenant_email_config`, `set_tenant_email_config`, `delete_tenant_email_config`), each performing the `email_config:read`/`email_config:write` RBAC check first, then an explicit `path org_id/tenant_id == user.org_id/user.tenant_id` ownership check, before any repository call (T-28-01 IDOR mitigation, mirrors `settings.rs`'s precedent). GET always calls `get_org_config`/`get_tenant_override` — never `get_effective_config` (D-14). A new `validate_email_config_override` helper performs D-15 structural-only validation on the tenant override's `Option`-wrapped fields.
- Route↔OpenAPI↔permission triangle completed: 6 routes registered in `server.rs` (`/organizations/{org_id}/email-config`, `/tenants/{tenant_id}/email-config`, each GET/PUT/DELETE); `email_config:read`/`email_config:write` added to `PERMISSION_REGISTRY`; 6 `ROUTE_PERMISSION_MAP` entries (GET→read, PUT/DELETE→write, single permission shared across scopes per D-03); 6 paths + 7 schemas added to `openapi.rs`. `route_openapi_parity_test` (both directions) passes.
- FUNC-01 OpenAPI gap closed: `oidc_start_public`/`oidc_callback_public` (not feature-gated) added to the main `ApiDoc`; `saml_login_public`/`saml_acs_public` (`#[cfg(feature = "saml")]`) added to the feature-gated `SamlApiDoc`, matching each handler's own cfg attribute. All 7 associated DTOs (`OidcStartRequest`, `OidcStartResponse`, `OidcPublicCallbackRequest`, `SsoLoginSuccessResponse`, `SamlLoginRequest`, `SamlLoginResponse`, `SamlAcsPublicRequest`) documented.
- `tests/email_config_test.rs`: 6 integration tests using a real-RBAC harness (mirrors `rbac_test.rs`, not `AllowAllAuthzChecker`) proving PUT/GET round trip with secrets always omitted, cross-org/cross-tenant 403, DELETE→404, and D-02 preserve-on-omit (verified directly via the repository since GET never re-exposes secrets).

## Task Commits

Each task was committed atomically:

1. **Task 1: New email_config.rs handler — 6 scope-nested singleton handlers (D-01/D-03/D-04/D-13/D-14)** — `3c51e77` (feat)
2. **Task 2: Complete the route↔OpenAPI↔permission triangle (email-config + FUNC-01 public SSO docs)** — `ca701ca` (feat) — includes the main.rs app_data wiring deviation
3. **Task 3: Integration test — email-config CRUD, secret omission, cross-scope 403 IDOR** — `4560f2d` (test) — includes the schema v23 fix deviation

**Plan metadata:** (this commit)

## Files Created/Modified

- `crates/axiam-api-rest/src/handlers/email_config.rs` — 6 handlers + `validate_email_config_override` + 9 unit tests for the override validator.
- `crates/axiam-api-rest/src/handlers/mod.rs` — registered `pub mod email_config;`.
- `crates/axiam-api-rest/src/server.rs` — 2 new `web::resource` blocks (org + tenant email-config), 6 routes.
- `crates/axiam-api-rest/src/permissions.rs` — 2 new `PERMISSION_REGISTRY` entries, 6 new `ROUTE_PERMISSION_MAP` entries.
- `crates/axiam-api-rest/src/openapi.rs` — 6 email-config paths + 7 email-config schemas; 2 public-SSO paths + 4 DTOs in the main `ApiDoc`; 2 public-SSO SAML paths + 3 DTOs in `SamlApiDoc`; 2 new tags (`email-config`, `federation-sso`).
- `crates/axiam-api-rest/tests/email_config_test.rs` (NEW) — 6 integration tests, real-RBAC harness.
- `crates/axiam-server/src/main.rs` — conditional `email_config_repo` construction + app_data registration (deviation, see below).
- `crates/axiam-db/src/schema.rs` — schema migration v23 fixing `provider_kind`'s ASSERT clause (deviation, see below).

## Decisions Made

- **email_config:read/write is shared across org+tenant scopes and GET/PUT+DELETE** (not four separate permissions) — explicit plan requirement (D-03), matching the existing `/api/v1/settings` pattern rather than the org-settings pattern (`organizations:get_settings`/`organizations:update_settings`) which uses per-scope names.
- **GET never calls `get_effective_config`** — always the raw own-scope row (`get_org_config`/`get_tenant_override`), per D-14, so an admin editing a tenant override sees exactly what is stored for that tenant, not the org-merged view.
- **Response DTOs reused directly from 28-01's models** (`EmailConfig`, `EmailConfigOverride`) rather than defining new REST-layer DTOs — their `#[serde(skip_serializing)]` secret fields already guarantee D-01 at the serialization boundary regardless of caller.
- **`validate_email_config_override` kept local to the handler file** (not added to `axiam-core`'s email model) since this plan's declared file scope is `axiam-api-rest` only; it mirrors `validate_email_config`'s checks but adapted for the override's `Option`-wrapped fields.
- **`oidc_start_public`/`oidc_callback_public` documented in the main `ApiDoc`; `saml_login_public`/`saml_acs_public` in the feature-gated `SamlApiDoc`** — verified against each handler's actual `#[cfg(feature = "saml")]` attribute in `federation.rs` rather than assuming all four public-SSO handlers belong together; `SsoLoginSuccessResponse` (used by both the OIDC and SAML success responses) is declared only once, in the main `ApiDoc`'s schema list — `merge_from` combines both documents at generation time, matching the pre-existing precedent where `saml_acs`'s `OidcCallbackResponse` schema is likewise declared only in the main doc.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Wired `SurrealEmailConfigRepository` as REST app_data in `axiam-server/src/main.rs`**
- **Found during:** Task 2 (route registration)
- **Issue:** The plan's declared `files_modified` covers only `axiam-api-rest`, but the new handlers extract `web::Data<SurrealEmailConfigRepository<C>>`. The production `App::new()` builder in `main.rs` never registered this app_data (it only constructs a `SurrealEmailConfigRepository` for the boot-time secrets backfill and the AMQP mail consumer, both of which are separate, narrowly-scoped uses) — every one of the 6 new routes would 500 with "app data not configured" in production, the same failure class the pre-existing `notification_rule_repo` comment in that file warns about.
- **Fix:** Constructed `email_config_repo: Option<SurrealEmailConfigRepository<axiam_db::DbClient>>` before `HttpServer::new`, `Some` only when `AXIAM__EMAIL_ENCRYPTION_KEY` is present (fail-closed, no zero-key fallback — mirrors the mail consumer's existing conditional-spawn pattern in the same file). Registered conditionally inside the `HttpServer::new(move || ...)` closure: `App::app_data()` returns `Self` (verified against `actix-web` 4.14.0 source — it does not alter `App`'s generic type parameter), so `let app = match &email_config_repo { Some(repo) => app.app_data(...), None => app };` composes cleanly with the existing single-expression builder chain without restructuring it.
- **Files modified:** `crates/axiam-server/src/main.rs`
- **Verification:** `cargo check -p axiam-server` succeeds with zero new warnings.
- **Committed in:** `ca701ca` (Task 2 commit)

**2. [Rule 1/3 - Pre-existing blocking bug] Fixed `set_tenant_override`'s `provider_kind = ''` schema violation (schema v23)**
- **Found during:** Task 3 (integration test — tenant PUT without a provider)
- **Issue:** `SurrealEmailConfigRepository::set_tenant_override` has always written `provider_kind = ''` when the caller's override does not touch the provider (a legitimate partial override — e.g. a tenant setting only `from_name`, leaving the provider inherited from the org baseline). The v15 schema's `ASSERT $value IN ['smtp', 'send_grid', 'postmark', 'resend', 'brevo']` only permitted the five real provider-kind values, so this write path has always thrown a `Migration failed: ... field must conform to` DB error — a write/read asymmetry, since `get_tenant_override` already special-cases an empty `provider_kind` as "no provider override" on the read side. No prior code path ever called `set_tenant_override` with `provider: None`, so this was never caught until this plan's PUT tenant handler became the first caller to exercise it.
- **Fix:** Added schema migration v23 (`email_config_provider_kind_optional`) using `DEFINE FIELD OVERWRITE provider_kind ON TABLE email_config TYPE string ASSERT $value IN ['', 'smtp', 'send_grid', 'postmark', 'resend', 'brevo'];` — the same `OVERWRITE`-to-extend-an-ASSERT pattern already used by the v15/v16 migrations (e.g. `user.status`, `export_job.status`). Org-scope rows are unaffected (`set_org_config` always supplies a real provider).
- **Files modified:** `crates/axiam-db/src/schema.rs`
- **Verification:** `cargo test -p axiam-db --lib email_config` (13/13 pass, unaffected) and `cargo test -p axiam-db --lib schema` (2/2 pass, including `migrations_are_ordered`); the new `tenant_email_config_put_get_delete_round_trip` integration test now passes end-to-end.
- **Committed in:** `4560f2d` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (1 missing-critical-functionality, 1 pre-existing blocking bug newly exercised)
**Impact on plan:** Both fixes were necessary for the plan's own handlers to function correctly in production and to pass its own required verification (Task 3's test suite). No scope creep beyond what was required to make the declared deliverable actually work end-to-end.

## Issues Encountered

- Full-rebuild `cargo build -p axiam-api-rest` from a clean `target/` (~4m37s) and `cargo check -p axiam-server` (~3m51s) were unavoidable given the sandbox's prior `cargo clean`; both were run once each and reused via incremental compilation for all subsequent scoped test/clippy invocations. `SWAGGER_UI_DOWNLOAD_URL` was exported in every cargo invocation per CLAUDE.md's build-hygiene note.
- `cargo clippy -p axiam-api-rest --lib -D warnings` surfaced one pre-existing, unrelated `clippy::derivable_impls` warning in `axiam-auth::token::SubjectKind` — out of this plan's scope (not a file this plan touches); confirmed via a non-`-D warnings` clippy run scoped to the touched files/crates (`axiam-api-rest`, `axiam-db`, `axiam-server`) that no new warnings were introduced.

## User Setup Required

None — no new external service configuration. Existing `AXIAM__EMAIL_ENCRYPTION_KEY` operational requirement (already documented for the mail consumer) now also gates the admin email-config REST endpoints; no new environment variable was introduced.

## Next Phase Readiness

- FUNC-03's admin email-config REST surface is complete: RBAC-gated, IDOR-safe, secret-omitting CRUD at both org and tenant scope, with D-02 preserve-on-omit semantics proven end-to-end through the HTTP layer.
- FUNC-01's OpenAPI documentation gap is closed — the four public first-time-SSO handlers and their DTOs are now discoverable in the generated spec, unblocking accurate SDK generation for the OIDC/SAML start→callback contract.
- This is the final plan (Wave 2) of Phase 28 (functional-completeness); no further plans are pending in this phase.

---
*Phase: 28-functional-completeness*
*Completed: 2026-07-05*

## Self-Check: PASSED

All 9 modified/created files verified present on disk; all 3 task commit hashes (`3c51e77`, `ca701ca`, `4560f2d`) verified present in git history.
