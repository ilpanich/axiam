# Phase 29: Structural Quality - Research

**Researched:** 2026-07-06
**Domain:** Rust/Actix-Web/SurrealDB structural refactor (AppState composition, generic pagination/dedup, error taxonomy, transactional mutations, PKI dedup, React/TS frontend dedup)
**Confidence:** HIGH — every claim below was verified directly against the live codebase (`grep`/`Read`), not training knowledge. Package-API claims (rcgen) were verified against the vendored crate source, not web search.

This research is **primarily a verification pass**, per the phase's own critical scouting
finding: most shared assets already exist and are simply unadopted. Every count/claim in
CONTEXT.md was re-verified below; several numbers are corrected with exact evidence.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01 — Full migration.** `main.rs` composes a single `AppState<C>` and every handler
  extracts `web::Data<AppState<C>>`, accessing dependencies as fields (e.g. `state.user_repo`).
  Replaces the inline `app_data` registrations in `crates/axiam-server/src/main.rs`. `AppState`
  is generic over the DB connection `C` because the repos are `Surreal…Repository<C>`.
- **D-02 — Optional deps are `Option<>` fields.** Conditionally-registered deps (e.g.
  `email_config_repo`, fail-closed when `AXIAM__EMAIL_ENCRYPTION_KEY` is present) become
  `Option<…>` fields on `AppState`. Handlers get `None` when unconfigured, preserving fail-closed
  behavior. Single composition root holds everything; no dep registered outside AppState.
- **D-03 — "No behavior change" scopes the pure refactors only.** QUAL-01, QUAL-02, QUAL-05,
  QUAL-06, QUAL-07 must be behavior-preserving — existing tests pass unchanged.
- **D-04 — QUAL-03/04 are INTENTIONAL in-scope behavior changes.** 500→409 error-taxonomy fixes
  (QUAL-03) and transactional/tenant-predicated mutation fixes (QUAL-04) deliberately change
  observable behavior. Update tests asserting old behavior; add tests locking the fix.
- **D-06 — Green gate = per-crate during dev + full-workspace regression at phase end.**
  Narrowly-scoped tests during dev (`-p <crate> --lib`/`--test <name>`), full workspace test
  suite once as end-of-phase regression gate.
- **D-07 — Exhaustive adoption.** Collapse ALL duplicated `struct CountRow` into
  `helpers::CountRow`; remove the duplicate `parse_uuid` (`federation_link.rs:44`); add a
  generic `paginate<T>` helper and adopt it in every list repo; route single-record reads
  through `helpers::take_first_or_not_found`. "Mainstream-only" rejected.
- **D-08 — PKI: real-PEM CA reconstruction + shared crypto helpers.** Implement
  `from_ca_cert_pem` so `CertService` reconstructs the signing CA by parsing the stored CA cert
  PEM (+ decrypted key) with its true issuer DN/serial/key — not from subject CN / "minimal CA
  params" (`cert.rs:224`). Prove behavior-equivalence: a cert signed via the new path verifies
  against the CA chain and carries the identical issuer DN. Move keypair/fingerprint/encrypt
  helpers into one shared `axiam-pki` module used by `ca`/`cert`/`pgp`.
- **D-09 — One centralized detection helper.** Add a shared mapper (db error layer / helpers)
  that inspects the SurrealDB error for specific index-violation markers and maps those to
  `DbError::AlreadyExists` (→ 409). Everything else falls through to `Migration`/`Database`
  (→ 5xx). Mainstream create paths (user create, edge-uniqueness) call this helper instead of
  the blanket `.map_err(|e| DbError::Migration(e.to_string()))`. DB outage must still return
  5xx — never a false 409. Tests: one genuine duplicate (→409), one non-index DB error (→5xx).
  Per-site inline matching rejected.
- **D-10 — `parse_uuid` stops mislabeling corrupt reads.** `helpers::parse_uuid` must not label
  a corrupt-data read as "Migration failed" (its own error variant, not `Migration`).
- **D-11 — OAuth2 distinguishes DB outage from `invalid_client`.** OAuth2 handlers return an
  appropriate server error on DB outage rather than collapsing it into `invalid_client`.
- **D-12 — Follow the existing inline `BEGIN/COMMIT` idiom.** No new Rust transaction
  abstraction (rejected as over-engineering).
- **D-13 — Predicate every statement on tenant (defense-in-depth).** Role/permission edge
  deletes and `resource::delete` child-guard: every DELETE/guard statement inside the
  transaction carries an explicit tenant predicate; child-guard SELECT + delete run in the
  SAME transaction (no TOCTOU). Add tests for cross-tenant and concurrent-child cases.
- **D-14 — GDPR deletion setup is transactional.** A `create` failure after
  `mark_deletion_pending` cannot strand an uncancellable purge.
- **D-15 — Adopt canonical, delete orphans (per module).** For each shared frontend module: if
  the shared version is canonical, wire pages to it and remove local duplicates; if genuinely
  orphaned/inferior, delete it. "Prefer deletion (minimal churn)" rejected.
- **D-16 — Profile/MFA pages → typed users service.** Call `services/users.ts` instead of
  inline `api.*` calls.
- **D-17 — Delete the pepper-less `verify_password`.** Remove `user.rs:872`'s Argon2
  `verify_password` (re-exported). Keep canonical `axiam-auth::password::verify_password`.
  Confirm no live caller depends on the deleted impl.
- **D-18 — Per-request services become singleton AppState fields.** Federation/reset/
  verification services (13 sites) hoisted into AppState as shared singletons. Guard: confirm
  none carry per-request state; if one does, it stays per-request (document exception).
- **D-19 — Security-adjacent → AppState → dedup → frontend.** Plan order: (1) QUAL-03+QUAL-04,
  (2) QUAL-01+QUAL-07 service hoisting, (3) QUAL-02+QUAL-05 backend dedup, (4) QUAL-06 frontend
  (own plan/diff). Each plan independently green-gated. "Fewer, larger plans" rejected.

### Claude's Discretion (resolved below with evidence)
- Exact `AppState` field naming/grouping and how generic `C` threads through handlers.
- The precise `paginate<T>` signature/bounds and which repos it lands in first.
- Exact SurrealDB index-violation marker strings for D-09.
- Test harness/structure choices (follow Phase 26 CORR-04 / prior-phase conventions).
- Where the shared `axiam-pki` crypto-helper module lives and its API.

### Deferred Ideas (OUT OF SCOPE)
- A generic Rust transaction-wrapper abstraction for axiam-db (D-12 rejected it).
- `sub_kind`-based / subject-kind authz enforcement (its own phase).
- Broader error-taxonomy sweep beyond mainstream create paths (full audit of every
  `Migration`-mapped site across all repos is out of scope for GA).
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| QUAL-01 | AppState extraction | § QUAL-01 below: exact main.rs/handler/test counts, generic-`C` threading, SAML feature-gate landmine |
| QUAL-02 | Generic pagination & shared repo helpers | § QUAL-02 below: reconciled CountRow count (24, not 27), `take_first_or_not_found` 0%-adopted (79 sites!), `paginate<T>` signature |
| QUAL-03 | Error taxonomy correctness | § QUAL-03 below: exact marker strings already in use elsewhere in the codebase, exact create-path sites, `DbError::Serialization` fix for D-10 |
| QUAL-04 | Transactional multi-statement mutations | § QUAL-04 below: exact SQL for role.rs/resource.rs/GDPR fixes with tenant predicates |
| QUAL-05 | PKI helper deduplication | § QUAL-05 below: rcgen 0.13.2 `from_ca_cert_pem` API (verified against vendored source), Cargo feature-flag requirement, exact helper triplication inventory |
| QUAL-06 | Frontend shared components & services adoption | § QUAL-06 below: per-module adopt/delete verdicts with exact consumer files |
| QUAL-07 | Dead-code & per-request-construction cleanup | § QUAL-01/QUAL-06 below (spans both): `verify_password` deletion confirmed dead outside one test; 13 per-request service sites confirmed safe to hoist |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **Signed commits** required before proceeding to the next roadmap task.
- **Build/disk hygiene:** `cargo clean` between plan steps (Rust `target/` fills the sandbox's
  ~38GB quota fast); prefer narrowly-scoped `cargo test -p <crate> --lib` / `--test <name>` over
  unscoped workspace builds; `/dev/shm` is the ENOSPC escape hatch.
- **swagger-ui workaround required** for any build/test touching `axiam-api-rest` (or its
  dependents, which includes `axiam-server`): `export
  SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip`. This
  phase's full-workspace regression gate (D-06) touches `axiam-api-rest`/`axiam-server` directly
  — every plan that runs `cargo test -p axiam-api-rest` or `cargo test --workspace` MUST set this
  env var first.
- **Security standards** (Argon2id, EdDSA JWT, AES-256-GCM at rest, TLS 1.3) are unaffected by
  this phase — QUAL-05's PKI change reuses the existing AES-256-GCM scheme; QUAL-07's password
  verify deletion keeps the canonical Argon2id path.
- **RBAC is additive-only** (allow-wins, default-deny, no deny-override in v1.0-beta) — QUAL-04's
  tenant-predicate hardening is defense-in-depth on top of this model, not a change to it.

## Summary

Phase 29 is overwhelmingly an **adoption and hardening** phase, not a design phase. Every
locked decision (D-01…D-19) maps to a concrete, already-located code site. The three most
important corrections/findings from this research, beyond what CONTEXT.md already knew:

1. **QUAL-01's true migration surface is larger than "283 handler extractions."** Beyond the
   283 sites across 28 handler files (confirmed exact), there are **7 more `web::Data<T>`
   extraction/lookup sites outside `handlers/`** (`extractors/auth.rs` ×4, `extractors/cert_auth.rs`
   ×1, `middleware/rate_limit_shared.rs` ×1, `health.rs::ready` ×1) that run on *every*
   authenticated request and will silently break if the individual registrations they depend on
   are removed without updating these sites too. Separately, **32 axiam-api-rest test files +
   3 axiam-server test files (35 files, ~333 individual `app_data` calls)** build their own
   test-harness `App` independently of `main.rs` — but the good news is these are almost all
   consolidated behind a single `macro_rules! test_app { … }` (or equivalent builder) per file,
   so the real edit surface is ~35 builder definitions, not 333 line-by-line edits.
2. **QUAL-02's `take_first_or_not_found` helper has ZERO current adopters** (not partially
   adopted — literally never called outside its own unit tests), while the manual
   `.into_iter().next().ok_or_else(|| DbError::NotFound {...})` pattern it was designed to
   replace appears **79 times across 30 files**. This is the single largest mechanical-adoption
   surface in the phase — larger than the CountRow dedup. The `CountRow` count itself
   reconciles to **24** (not CONTEXT's estimated 27) — matching the ROADMAP's AC exactly; two of
   the "previously duplicated" sites (`user.rs`, `role.rs`) were **already migrated** in a prior
   phase, confirming the "unadopted assets" scouting finding precisely.
3. **D-13's cross-tenant edge-strip bug is real and exactly as described**, with zero tenant
   predicate on the edge-delete statements in both `role.rs:delete` and `resource.rs:delete`
   (only the final record-delete statement is tenant-scoped today), and `resource.rs:delete`'s
   child-count guard runs as a genuinely separate, non-transactional query — a real TOCTOU.
   D-14's GDPR strand bug is also real: `mark_deletion_pending` and `account_deletion_repo.create`
   are two independent, non-transactional calls in `gdpr.rs` handler.

**Primary recommendation:** Execute in the D-19 order. Do QUAL-03/04 first (small, surgical,
security-adjacent, already-idiomatic SQL patterns to mirror). Do QUAL-01 next but budget for the
**full surface** (main.rs + 28 handler files + 7 non-handler extraction sites + ~35 test-harness
builders), not just the handler count. Do QUAL-02/05 as the largest pure-mechanical pass (24
CountRow + 79 take_first_or_not_found + 7 parse_uuid call sites + paginate<T> in 26 repos + PKI
dedup). Do QUAL-06 last, as its own plan, after fixing one pre-existing behavior inconsistency in
`ActionBadge` (see § QUAL-06).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| AppState composition (QUAL-01) | API/Backend (Actix app-data layer) | — | Actix's `web::Data` extractor is a backend-only composition-root concept; no client/CDN tier involvement |
| Generic pagination/repo helpers (QUAL-02) | Database/Storage (repository layer) | API/Backend (consumes `PaginatedResult<T>`) | Helpers live in `axiam-db`; handlers just pass through the already-shaped result |
| Error taxonomy (QUAL-03) | Database/Storage (`DbError`) → API/Backend (`AxiamError`→HTTP) | — | Two-hop mapping already exists (`DbError`→`AxiamError`→`ResponseError`); this phase only changes what `DbError` variant is chosen at the DB layer |
| Transactional mutations (QUAL-04) | Database/Storage (SurrealQL transactions) | — | All fixes are inline SQL in the repository layer; no API-layer orchestration change |
| PKI dedup (QUAL-05) | Backend service layer (`axiam-pki`) | — | Standalone crate, no HTTP/DB coupling beyond existing repo calls |
| Frontend shared components/services (QUAL-06) | Browser/Client (React pages) | — | Pure client-side refactor; no backend contract change |
| Dead-code/service hoisting (QUAL-07) | API/Backend (AppState composition) + Database/Storage (dead fn removal) | — | Splits across QUAL-01 (hoisting) and QUAL-02/05-adjacent (dead code) |

## QUAL-01: AppState Extraction

### Verified current state

**main.rs registrations — 48 total, not ~56.** Exact count via
`grep -n "^\s*\.app_data(" crates/axiam-server/src/main.rs`: **47 unconditional**
`.app_data(web::Data::new(...))` calls (lines 772–832) **+ 1 conditional** (the
`email_config_repo` `Some`/`None` match at line 838) = **48**. CONTEXT.md's "~56" was an
overcount (some of the 56 raw `app_data` grep hits were comment lines, e.g. `:360`, `:465`,
`:584-585`, `:790/793`, `:834-838` — not actual registrations).

Distinct dependency types registered (48 total, one per line): `rest_authz` (`Arc<dyn
AuthzChecker>`), `config.authz`, `auth_config`, `db_handle` (`Surreal<C>`), `health_checker`
(`Arc<dyn HealthChecker>`), `audit_repo`, `org_repo`, `tenant_repo`, `user_repo`, `group_repo`,
`role_repo`, `permission_repo`, `resource_repo`, `scope_repo`, `service_account_repo`,
`auth_service`, `webauthn_service`, `mfa_method_service`, `mail_outbound_publisher`,
`session_repo`, `session_validator`, `handler_refresh_token_repo`, `password_history_repo`,
`consent_repo`, `account_deletion_repo`, `export_job_repo`, `erasure_proof_repo`,
`config.email_encryption_key` (raw `Option<[u8;32]>`, not a repo), `ca_service`, `cert_service`,
`cert_repo`, `device_auth_service`, `pgp_service`, `webhook_repo`, `webhook_delivery`,
`webhook_publisher`, `notification_rule_repo`, `oauth2_client_repo`, `authorize_service`,
`token_service`, `settings_repo`, `federation_config_repo`, `federation_link_repo`,
`assertion_replay_repo`, `federation_login_state_repo`, `http_client`, `jwks_cache`,
`crypto_semaphore` (`Arc<Semaphore>`), and the conditional `email_config_repo`.

**Handler extraction sites — 283 across 28 files, exactly matching CONTEXT.** Per-file
breakdown (files with 0 extractions, e.g. `mod.rs`, excluded from the "28" count):

| File | Count | File | Count |
|---|---|---|---|
| federation.rs | 71 | tenants.rs | 6 |
| auth.rs | 36 | service_accounts.rs | 6 |
| password_reset.rs | 22 | email_config.rs | 6 |
| roles.rs | 13 | scopes.rs | 5 |
| gdpr.rs | 12 | oauth2_clients.rs | 5 |
| permissions.rs | 8 | notification_rules.rs | 5 |
| groups.rs | 8 | settings.rs | 4 |
| email_verification.rs | 8 | ca_certificates.rs | 4 |
| webhooks.rs | 7 | bootstrap.rs | 3 |
| resources.rs | 7 | authz_check.rs | 3 |
| pgp_keys.rs | 7 | mfa_methods.rs | 2 |
| organizations.rs | 7 | audit.rs | 2 |
| oauth2.rs | 7 | | |
| certificates.rs | 7 | | |
| webauthn.rs | 6 | | |
| users.rs | 6 | | |

**LANDMINE — 7 more `web::Data<T>` sites outside `handlers/` (not in the 283 count), all on
every-request code paths:**
- `crates/axiam-api-rest/src/extractors/auth.rs`: `.app_data::<web::Data<Arc<dyn
  SessionValidator>>>()` (:97), `.app_data::<web::Data<AuthConfig>>()` (:150, :193, :207) — 4
  sites, part of the `AuthenticatedUser` `FromRequest` impl that runs on nearly every
  authenticated route.
- `crates/axiam-api-rest/src/extractors/cert_auth.rs:36`: `.app_data::<web::Data<
  DeviceAuthService<SurrealCertificateRepository<C>, SurrealCaCertificateRepository<C>>>>()` —
  manual extraction (not `FromRequest`) because the concrete type depends on generic `C`.
- `crates/axiam-api-rest/src/middleware/rate_limit_shared.rs:192`:
  `.app_data::<web::Data<Surreal<C>>>()` inside the rate-limiter middleware's `poll_ready`/`call`.
- `crates/axiam-api-rest/src/health.rs:61`: `ready(checker: web::Data<Arc<dyn
  HealthChecker>>)` — ordinary function-param extraction, but the file lives outside
  `handlers/` so it wasn't counted in the 283.

If `AppState<C>` fully replaces the individual registrations (per D-01/D-02: "no dep is
registered outside AppState"), these 7 sites must be updated too — e.g.
`req.app_data::<web::Data<AppState<C>>>().map(|s| s.session_validator.clone())` — or they will
return `None` at runtime (auth extraction failing on every request is a severe regression, not
a compile error, since `.app_data::<T>()` returns `Option<T>`).

**LANDMINE — test harness surface: 35 files, ~333 registrations, but consolidated behind
per-file builder macros.** `grep -rl "app_data(web::Data::new(" crates/axiam-api-rest/tests/*.rs`
→ 32 files (webhook_test.rs, ca_certificate_test.rs, etc. — full per-file counts range 1–28,
e.g. `email_config_test.rs`=28, `bootstrap_test.rs`=28, `rbac_test.rs`=27). Plus 3 files in
`crates/axiam-server/tests/` (`req5_oidc_e2e.rs`=8, `req7_service_account_aud.rs`=13,
`req7_session_lifecycle.rs`=17). Each test file builds its own `App::new()...app_data(...)...`
chain independently of `main.rs` (there is no shared test-harness helper crate). **Good news:**
almost every file consolidates this into ONE `macro_rules! test_app { ... }` (or 2–4 variants in
a few files like `certificate_test.rs`, `device_auth_test.rs`, `user_test.rs`) invoked by many
`#[actix_web::test]` functions — e.g. `auth_test.rs` defines `test_app!` once (line 134) and
calls it 19+ times. Two files (`health_test.rs`, `middleware_test.rs`) build inline without a
macro (few calls). **Net scope: update ~35 builder definitions to construct and register one
`AppState<C>`, not 333 individual call sites.** This is the single most important planning fact
for QUAL-01 — the AC's "no behavior change" gate (D-06) depends on every one of these 35 files
compiling and passing after the handler signature change.

**Generic `C` threading (discretion, resolved):** `crates/axiam-api-rest/src/server.rs:61`
already declares `pub fn register_api_v1_routes<C: surrealdb::Connection + Clone>(cfg: &mut
web::ServiceConfig, rate_limit_cfg: &RateLimitConfig)` — generic over `C: surrealdb::Connection +
Clone`, used identically by production (`DbClient`) and tests (`surrealdb::engine::local::Db`).
`AppState<C>` should mirror this exact bound: `pub struct AppState<C: surrealdb::Connection +
Clone> { ... }`, and every handler signature becomes `state: web::Data<AppState<C>>` matching
the existing `<C: Connection>` generic parameter already on every handler fn.

**D-18 per-request service hoisting — all 13 sites confirmed safe (no per-request state).**
Exact count reconciles: `PasswordResetService::new` at `password_reset.rs:162`/`:292` (2),
`EmailVerificationService::new` at `email_verification.rs:67`/`:102` (2),
`OidcFederationService::new` at `federation.rs:565`/`:667`/`:1217`/`:1322` (4),
`SamlFederationService::new` at `federation.rs:849`/`:905`/`:961`/`:1465`/`:1558` (5) = **13**,
exactly matching CONTEXT. Inspected every constructor call: all arguments are already
app-wide singletons cloned from `web::Data` (repos, `http_client`, `jwks_cache`,
`crypto_semaphore`, `enc_key` read from shared `AuthConfig`) — `tenant_id` is always passed to
the *method* call (`initiate_reset(tenant_id, ...)`, `build_authorization_url(user.tenant_id,
...)`), never baked into the constructor. **No exception needed — all 13 hoist cleanly.**
`federation.rs:563` already has a `TODO(T19): AppState refactor — CQ-B27/CQ-B43 deferred
(per-request service rebuild; OidcFederationService constructed here instead of once at
startup)` comment confirming this was already flagged as future work.

**LANDMINE — SAML feature gate.** 5 of the 9 federation-service constructions
(`saml_authn_request`, `saml_acs`, `saml_metadata`, `saml_login_public`, `saml_acs_public` — fns
at `federation.rs:834/887/952/1407/1523`) are behind `#[cfg(feature = "saml")]` (default-on,
disable via `--no-default-features` for hosts with incompatible libxml2 per
`axiam-api-rest/Cargo.toml:55-60`). The 4 OIDC constructions are NOT gated. If
`SamlFederationService` becomes an `AppState` field, it must be either (a) present unconditionally
(built even under `--no-default-features`, since `SamlFederationService::new`'s dependencies
don't actually require the `saml` feature — only the *handlers* are cfg-gated) or (b) itself
`#[cfg(feature = "saml")]`-gated on the `AppState` struct, requiring conditional-compilation
attributes on the struct field and its construction in `main.rs`. Recommend (a) — construct the
service unconditionally in `main.rs` (cheap, no I/O) and let only the *handlers* stay
feature-gated, avoiding cfg-attribute sprawl inside `AppState<C>`'s field list.

### Approach

1. Define `pub struct AppState<C: surrealdb::Connection + Clone> { ... }` (new module, e.g.
   `crates/axiam-api-rest/src/state.rs`) with one field per current `main.rs` registration (48
   fields, `email_config_repo: Option<SurrealEmailConfigRepository<C>>`), plus the two hoisted
   singleton services (`password_reset_service`, `email_verification_service`) and the 9
   federation services collapsed to 2 fields (`oidc_federation_service`,
   `saml_federation_service`) since each is constructed identically at every call site today.
2. `main.rs` builds one `AppState` instance, registers it once via
   `.app_data(web::Data::new(app_state.clone()))`, replacing the 48 individual `.app_data()`
   calls.
3. Update the 28 handler files (283 sites): replace each `dep: web::Data<SurrealXRepository<C>>`
   parameter with `state: web::Data<AppState<C>>` and rewrite body references from `dep.` to
   `state.dep_field.` (mechanical, IDE-assisted or scripted).
4. Update the 7 non-handler extraction sites (`extractors/auth.rs`, `extractors/cert_auth.rs`,
   `middleware/rate_limit_shared.rs`, `health.rs`) to pull their dependency out of `AppState<C>`
   instead of looking up the individual type.
5. Update the ~35 test-harness builder macros/functions to construct one `AppState` and register
   it, replacing their internal per-dependency `.app_data()` chains.
6. Replace the 13 per-request `XService::new(...)` call sites with `state.x_service.method(...)`.

### Landmines / ordering constraints
- Do QUAL-03/04 (D-19 step 1) **before** this, so the transactional/error-taxonomy repository
  method signatures are already final when AppState wires them in — avoids re-touching the same
  handler bodies twice.
- Budget the non-handler 7 sites and the ~35 test builders as their own review-sized chunk —
  they're easy to miss if scoping only from "handlers/" and "283."
- The SAML cfg-gate (above) needs a decision recorded before writing `AppState`'s field list.

## QUAL-02: Generic Pagination & Shared Repo Helpers

### Verified current state

**`helpers.rs` already defines all three target helpers** (`crates/axiam-db/src/helpers.rs`):
`CountRow` (`:18`, `#[derive(Debug, SurrealValue)] pub struct CountRow { pub total: u64 }`),
`parse_uuid(s: &str, field: &str) -> Result<Uuid, DbError>` (`:33`), `take_first_or_not_found<T>
(items: Vec<T>, entity: &str, id: &str) -> Result<T, DbError>` (`:46`).

**`CountRow` duplicates: exactly 24, not 27.** `grep -rln "struct CountRow"
crates/axiam-db/src/repository/*.rs` → 24 files: `audit.rs`, `ca_certificate.rs`,
`certificate.rs`, `email_config.rs`, `email_verification_token.rs`, `export_job.rs`,
`federation_config.rs`, `federation_login_state.rs`, `group.rs`, `notification_rule.rs`,
`oauth2_auth_code.rs`, `oauth2_client.rs`, `oauth2_refresh_token.rs`, `organization.rs`,
`password_reset_token.rs`, `permission.rs`, `pgp_key.rs`, `resource.rs`, `saml_replay.rs`,
`service_account.rs`, `session.rs`, `tenant.rs`, `webauthn_credential.rs`, `webhook.rs`. This
**reconciles exactly with the ROADMAP.md AC ("24")**, not CONTEXT.md's "27" estimate.
`helpers.rs`'s own doc comment ("Previously duplicated privately in every repository module
(user.rs:148, role.rs:53, …)") confirms `user.rs` and `role.rs` were **already migrated** in a
prior phase — both now `use crate::helpers::{CountRow, parse_uuid};` and construct
`PaginatedResult` using the shared type. This is direct evidence for CONTEXT's "unadopted
assets" scouting finding: adoption is real but partial.

**`parse_uuid` duplicate: exactly 1, at `federation_link.rs:44`.**
`fn parse_uuid(s: &str) -> Result<Uuid, DbError> { Uuid::parse_str(s).map_err(|e|
DbError::Migration(e.to_string()))? }` — note the **different signature** (1 arg, no field
name) vs. `helpers::parse_uuid(s, field)` (2 args). 7 call sites in the same file need updating
to pass a field-name string: `record_id` (:65), `tenant_id` (:52, :68), `user_id` (:53, :69),
`federation_config_id` (:54, :70). Note ~25 *other* repos still do fully-inline
`Uuid::parse_str(...).map_err(|e| DbError::Migration(format!("invalid ... UUID: {e}")))` without
even a locally-named helper function — D-07's mandate is scoped narrowly to the literal
`federation_link.rs:44` duplicate function per CONTEXT's canonical refs, **not** a sweep of all
inline UUID-parse call sites (that would be a much larger, unbounded surface — correctly out of
scope per the "broader error-taxonomy sweep... out of scope" deferred item, which the same
principle extends to).

**LANDMINE — `take_first_or_not_found` has ZERO current adopters**, a bigger finding than
CONTEXT called out. `grep -rn "take_first_or_not_found" crates/axiam-db/src/repository/*.rs` →
0 hits outside `helpers.rs` itself (its own unit tests). Meanwhile the manual pattern it exists
to replace — `items.into_iter().next().ok_or_else(|| DbError::NotFound { entity: ..., id: ...
})?` — appears **79 times across 30 files** (verified:
`grep -rn "into_iter().next().ok_or_else(|| DbError::NotFound" crates/axiam-db/src/repository/*.rs
| wc -l` → 79). Spot-checked `tenant.rs:126` and `:145` — both are a direct, mechanical
1:1 substitution: `helpers::take_first_or_not_found(rows, "tenant", &id_str)?`. **This is the
single largest mechanical-adoption surface in the phase** (79 sites vs. 24 for CountRow) and
should be explicitly budgeted as its own task/wave, not folded silently into "adopt CountRow."

**`paginate<T>` — no such helper exists yet; signature derived from the uniform list-repo shape.**
26 repos share the identical count+list+construct pattern (verified:
`grep -rln "SELECT count() AS total" crates/axiam-db/src/repository/*.rs` → 26 files, and
`grep -n "let total = count_rows" crates/axiam-db/src/repository/*.rs` → 20+ literal matches of
`let total = count_rows.first().map(|r| r.total).unwrap_or(0);`, followed in every case by an
identical `PaginatedResult { items, total, offset: pagination.offset, limit: pagination.limit }`
construction — confirmed byte-identical in `user.rs:574`, `role.rs:324`, `oauth2_client.rs:352`,
`webhook.rs:318`). Recommended signature (adopt in `helpers.rs`):

```rust
/// Assemble a `PaginatedResult<T>` from an already-fetched item page and its
/// count-query result. Collapses the identical 5-line "extract total +
/// construct PaginatedResult" boilerplate repeated in every list-repo method.
pub fn paginate<T>(
    items: Vec<T>,
    count_rows: Vec<CountRow>,
    pagination: &Pagination,
) -> PaginatedResult<T> {
    let total = count_rows.first().map(|r| r.total).unwrap_or(0);
    PaginatedResult {
        items,
        total,
        offset: pagination.offset,
        limit: pagination.limit,
    }
}
```

This intentionally does **not** try to also execute the two underlying SurrealDB queries
generically — each repo's count/list SQL differs in WHERE-clause shape (some filter by
`tenant_id` only, others by `tenant_id + resource_id`, etc.), and `surrealdb::method::Query`'s
builder API doesn't lend itself to a single generic "run both queries" wrapper without a closure
parameter that would add more complexity than it removes (consistent with the project's
stated aversion to over-engineering — see D-12's rejection of a transaction abstraction for the
same reason). Land it in **all 26 repos with the count+list shape** — it's uniformly applicable
and mechanical; there's no reason to phase the adoption order since every site is independent.
`Pagination`/`PaginatedResult<T>` themselves are defined in `axiam-core/src/repository.rs:63/80`
and need no changes.

### PKI dedup is covered under QUAL-05 below (separate section per phase requirement numbering).

### Approach
1. Add `paginate<T>` to `helpers.rs` (with unit tests mirroring the existing `parse_uuid`/
   `take_first_or_not_found` test style).
2. Collapse the 24 `struct CountRow` duplicates: delete each local definition, add `use
   crate::helpers::CountRow;` (or extend an existing `use crate::helpers::{...}` line), replace
   the local `let total = ...; PaginatedResult { ... }` with `helpers::paginate(items,
   count_rows, &pagination)`.
3. Route the 79 `take_first_or_not_found` sites through the helper (mechanical; import already
   present in some files, e.g. `federation_link.rs` already imports `parse_uuid` — check per file).
4. Fix `federation_link.rs`'s 7 call sites + delete its local `parse_uuid` fn.

### Landmines / ordering constraints
- The 79-site `take_first_or_not_found` sweep and the 24-site `CountRow` sweep touch **the same
  25–26 files** in most cases (both are per-list-repo patterns) — do them together per file in
  one pass rather than two separate global sweeps, to avoid re-diffing the same files twice.
- Because this is the largest pure-mechanical surface in the phase (103+ call sites across
  ~30 files), consider splitting into 2–3 waves of ~10 files each for reviewability, per D-19's
  "fewer, larger plans rejected" principle already established for this phase.

## QUAL-03: Error Taxonomy Correctness

### Verified current state

**The centralized-detection pattern already exists in 3 places — reuse it, don't invent a new
one.** `grep -rn "already contains\|already exists"` across `axiam-db/src/` surfaces the *exact*
marker strings this codebase's SurrealDB 3.1.5 (`Cargo.lock:6775`, `version = "3.1.5"`) index
violations produce, already discovered and matched by prior work:
- `saml_replay.rs:81-87`: `if msg.contains("already contains") || msg.contains("already exists")
  || msg.contains("unique") { AxiamError::ReplayDetected } else { AxiamError::Database(msg) }`,
  with the comment: *"SurrealDB v3 UNIQUE index violation message contains 'already contains'
  (e.g. 'Database index `idx_replay_uniq` already contains [...]'). Also match 'already exists'
  and 'unique' as fallback patterns."*
- `federation_login_state.rs:86-87`: same `"already contains"` check, comment: *"UNIQUE index
  violation on `state` — duplicate state value."*
- `seeder.rs:385`, `:458`: same `msg.contains("already contains")` check for idempotent seeding.

**Resolved discretion item (D-09 marker strings):** the exact, empirically-confirmed marker set
for SurrealDB 3.1.5 is **`"already contains"`** (primary/confirmed pattern) with **`"already
exists"`** and **`"unique"`** as documented fallbacks. The centralized helper (new, e.g.
`helpers::classify_db_error` or a method on `DbError`) should reuse this exact 3-string set —
do **not** invent new markers; this is already load-bearing, verified-in-production text.
Proposed shared helper (in `helpers.rs`, alongside `parse_uuid`/`take_first_or_not_found`):

```rust
/// Classify a checked SurrealDB query-execution error: genuine unique/index
/// violations map to `DbError::AlreadyExists`; everything else (including DB
/// outages) falls through unchanged so it still maps to a 5xx (CQ-B11/17).
pub fn classify_write_error(err: surrealdb::Error, entity: &str) -> DbError {
    let msg = err.to_string();
    if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique") {
        DbError::AlreadyExists { entity: entity.to_string() }
    } else {
        DbError::Migration(msg)
    }
}
```

Callers replace `.map_err(|e| DbError::Migration(e.to_string()))?` with
`.map_err(|e| helpers::classify_write_error(e, "user"))?` (entity name varies per call site).

**Exact create-path sites in `user.rs` — CONTEXT's 9-site list is accurate, but only 4 are
literal CREATEs; the other 5 are UPDATEs where a unique-violation is structurally impossible.**
Verified via `awk` mapping each of the 9 cited lines to its enclosing fn:

| Line | Enclosing fn | Statement type | Needs `classify_write_error`? |
|---|---|---|---|
| 252, 285 | `create` | `CREATE` | **Yes — required** (this is literally the unique-username/email violation path) |
| 463 | `update` | `UPDATE` | No unique field touched; optional (harmless if applied) |
| 518 | `update_totp_step` | `UPDATE` | No unique field touched; optional |
| 631 | `increment_failed_logins` | `UPDATE` | No unique field touched; optional |
| 682 | `anonymize_user` | `UPDATE` | No unique field touched; optional |
| 725, 780 | `create_with_consent` | `CREATE` (3-statement transaction) | **Yes — required** |
| 817 | `mark_deletion_pending` | `UPDATE` | No unique field touched; optional |

Two additional `.map_err(|e| DbError::Migration(e.to_string()))?` sites exist in `user.rs` that
CONTEXT's list did **not** include — `:841` (`clear_deletion_pending`, an UPDATE) and `:860`
(`find_due_for_purge`, a SELECT) — correctly excluded since neither is a create path. **Minimum
required scope to satisfy the AC:** apply `classify_write_error` at the 4 true CREATE sites
(252, 285, 725, 780). **Recommended (lower-risk, matches D-09's "per-site inline matching
rejected — drift risk" reasoning):** apply uniformly to all `.map_err(|e|
DbError::Migration(e.to_string()))?` sites in `user.rs` for consistency — since UPDATE-path
error text will never contain the unique markers, this is a no-op behavior-wise for those sites
but eliminates the risk of a future UPDATE gaining a unique-constrained field and silently
missing the routing.

**Edge-uniqueness sites (D-09's second target):** `schema.rs`'s Schema v19 comment (CQ-B17)
confirms **7 edge tables already have `UNIQUE (in, out)` composite indexes**: `has_tenant`,
`member_of`, `has_role`, `grants`, `on_resource`, `child_of`, `signed_by` (all defined
`crates/axiam-db/src/schema.rs`, "Schema v19 — unique (in, out) indexes on edge tables"). Any
`RELATE ... -> has_role -> ...` / `RELATE ... -> grants -> ...` etc. that can violate these
(e.g. `role.rs:550`'s `RELATE group:... -> has_role -> role:...`, `group.rs:392`'s `RELATE
user:... -> member_of -> group:...`) is a candidate for the same `classify_write_error` routing
— currently these RELATE calls still map to blanket `Migration`. Scope this to the create-time
RELATE call sites that a user-facing "assign role"/"add group member" endpoint invokes (a
handful, not all 79 QUAL-02 sites) — verify at plan time which RELATE sites are reachable from a
mutating REST endpoint vs. internal-only (e.g. seeder-only paths already handled by `seeder.rs`'s
own existing check).

**D-10 fix — `helpers::parse_uuid` already anticipates its own fix.** The current impl (`:33-36`)
literally says in its own doc comment (`:29-32`): *"Unlike the inline `Uuid::parse_str(..).
map_err(|e| DbError::Migration(…))` pattern scattered across ~25 repos, this function uses
`DbError::Migration` consistently... **A future refactor can switch the variant to
`DbError::Serialization` if that variant is added.**"* This is exactly D-10's ask, already
flagged as anticipated future work by a prior phase author. **Recommended fix:** add
`DbError::Serialization(String)` to `crates/axiam-db/src/error.rs`'s enum, update `parse_uuid` to
construct it instead of `Migration`. The `impl From<DbError> for AxiamError`'s existing catch-all
arm (`other => AxiamError::Database(other.to_string())`) requires **zero changes** — the new
variant falls through it automatically, so **HTTP status is unaffected (still 500)** — this is a
pure error-taxonomy/log-clarity fix, not an observable-behavior change, and stays correctly
within the "no behavior change" bucket (D-03) even though it's discussed under the QUAL-03
umbrella. No test asserts the literal string "Migration failed" (verified: `grep -rn "Migration
failed" crates/*/tests/*.rs` → 0 hits) so this is a safe, isolated rename.

**D-11 — OAuth2 DB-outage-vs-`invalid_client`: exactly 5 sites, all identical pattern.** Verified
via `grep -n "InvalidClient(\"client not found\"" crates/axiam-oauth2/src/*.rs`:
`authorize.rs:67`, `token.rs:175`, `token.rs:346`, `token.rs:454`, `token.rs:745`
(`authenticate_client` fn). All 5 do `.get_by_client_id(tenant_id, client_id).await.map_err(|_|
OAuth2Error::InvalidClient("client not found".into()))?` — the `|_|` **discards the underlying
`AxiamError` entirely**, so a genuine DB outage (`AxiamError::Database(_)`) collapses to the same
`invalid_client` response as an actually-nonexistent client. `crates/axiam-oauth2/src/error.rs`
already has a `ServerError(String)` variant (`:26`) that maps to `StatusCode::INTERNAL_SERVER_ERROR`
(confirmed in `crates/axiam-api-rest/src/handlers/oauth2.rs:435`) — **no new error variant or
HTTP-status wiring needed**, only the 5 call sites need to distinguish the error:

```rust
.map_err(|e| match e {
    AxiamError::NotFound { .. } => OAuth2Error::InvalidClient("client not found".into()),
    other => OAuth2Error::ServerError(other.to_string()),
})?
```

`get_by_client_id`'s trait signature (`axiam-core/src/repository.rs`) already returns
`AxiamResult<OAuth2Client>` (i.e. `Result<_, AxiamError>`), so this match is a direct, available
distinction — no upstream repo change needed.

### Approach
1. Add `DbError::Serialization(String)` variant + update `parse_uuid` (D-10) — smallest,
   isolated change, do first.
2. Add `helpers::classify_write_error` + route the 4 required `user.rs` CREATE sites (D-09) +
   the reachable edge-uniqueness RELATE sites.
3. Fix the 5 OAuth2 sites (D-11) with the match-based error mapping above.
4. Tests: one genuine-duplicate-409 test per CREATE path fixed (user create, edge RELATE), one
   non-index-DB-error-still-5xx test (can reuse a mocked/`Unhealthy` DB error or a malformed
   query), one OAuth2 DB-outage-returns-5xx test (simulate a `Database` error from a mock repo).

### Landmines / ordering constraints
- Do this section **first** in the phase (D-19 step 1) — small, surgical, and the fixed
  `user.rs`/`role.rs` method bodies will be touched again by QUAL-01's AppState pass; landing
  QUAL-03 first avoids re-diffing the same lines twice.
- `classify_write_error`'s marker-string match (`"already contains"`/`"already exists"`/
  `"unique"`) is a **substring** match on the full SurrealDB error `Display` text — verify no
  legitimate non-uniqueness error message happens to contain these substrings for the specific
  operations being routed (spot-check against a live/in-memory SurrealDB error in the new test,
  don't just trust the string pattern blind).

## QUAL-04: Transactional Multi-Statement Mutations

### Verified current state

**The `BEGIN TRANSACTION; ...; COMMIT TRANSACTION` idiom is well-established — 2 canonical
examples to mirror exactly.**
- `user.rs:736-760` (`create_with_consent`): 3-statement transaction (CREATE user, CREATE
  consent, CREATE password_history), with an explicit "Result slots: BEGIN=0, CREATE user=1,
  CREATE consent=2, CREATE password_history=3, COMMIT=4" comment documenting the `.take(N)`
  index convention.
- `federation_login_state.rs:86-127` (`consume_by_state`): atomic SELECT+DELETE using `LET $row
  = (SELECT ...); DELETE ... WHERE state = $state; RETURN $row;` inside BEGIN/COMMIT — this is
  the **exact pattern to mirror for `resource.rs`'s child-guard fix** (capture-then-mutate
  atomically).

**`role.rs::delete` (`:264-282`) — confirmed exact bug, matches D-13 precisely.**
```rust
// CURRENT (buggy):
let query = format!(
    "DELETE has_role WHERE out = role:`{id_str}`; \
     DELETE grants WHERE in = role:`{id_str}`; \
     DELETE type::record('role', $id) WHERE tenant_id = $tenant_id;"
);
```
Only the **third** statement has a `WHERE tenant_id = $tenant_id` predicate. The first two
(`DELETE has_role`, `DELETE grants`) have **zero tenant scoping** — they match purely on the
role's UUID regardless of which tenant "owns" that ID in the query's context. There is also
**no `BEGIN TRANSACTION`/`COMMIT TRANSACTION` wrapper at all** — three DELETE statements are
sent as one semicolon-joined string to a single `.query()` call, but per this codebase's own
established idiom (explicit `BEGIN`/`COMMIT` used everywhere else for multi-statement atomicity),
this is the "non-transactional multi-statement mutation" CQ-B46/D-13 targets.

**`resource.rs::delete` (`:275-310`) — confirmed exact TOCTOU + missing predicates.** The
child-count guard (`:278-294`) runs as a **fully separate `.query()` call** (its own DB
round-trip) before the deferred cleanup query — a concurrent request creating a new `child_of`
edge between the guard-check and the delete would let the delete proceed and orphan the new
child. The subsequent cleanup query (`:297-302`) also lacks tenant predicates on 2 of its 4
statements:
```rust
"DELETE child_of WHERE in = resource:`{id_str}` OR out = resource:`{id_str}`; \   // no tenant predicate
 DELETE on_resource WHERE out = resource:`{id_str}`; \                            // no tenant predicate
 DELETE scope WHERE resource_id = $resource_id AND tenant_id = $tenant_id; \      // has predicate
 DELETE type::record('resource', $id) WHERE tenant_id = $tenant_id;"             // has predicate
```

**Recommended fix for both**, mirroring `federation_login_state.rs`'s `LET $row = (...)` capture
pattern for the child-guard (child-count now happens *inside* the same transaction as the
delete, closing the TOCTOU), with tenant predicates added to every statement:

```sql
-- resource::delete, single transaction, tenant-predicated throughout:
BEGIN TRANSACTION;
LET $child_count = (SELECT count() AS total FROM child_of
                    WHERE out = resource:`{id_str}` GROUP ALL);
-- (application layer aborts with Validation error if child_count > 0 — see note below)
DELETE child_of WHERE (in = resource:`{id_str}` OR out = resource:`{id_str}`)
    AND tenant_id = $tenant_id;
DELETE on_resource WHERE out = resource:`{id_str}` AND tenant_id = $tenant_id;
DELETE scope WHERE resource_id = $resource_id AND tenant_id = $tenant_id;
DELETE type::record('resource', $id) WHERE tenant_id = $tenant_id;
COMMIT TRANSACTION;
```

**Note on `child_of` edges having no `tenant_id` field of their own:** verify at plan time
whether the `child_of` edge table schema carries a `tenant_id` field directly (schema.rs) — if
it does not (edges may only reference `resource:` record IDs, deriving tenant scope
transitively through the resource), the tenant predicate must instead be expressed as a subquery
guard (`in.tenant_id = $tenant_id` via graph traversal) or enforced by ensuring `id_str`/
`new_parent_str` are only ever resolved from within the correct tenant upstream (defense-in-depth
via the *record ID itself* being tenant-checked before this method is called) — **check
`schema.rs`'s `child_of`/`has_role`/`grants` field definitions before finalizing the exact SQL**;
this research did not exhaustively confirm whether edge tables carry their own `tenant_id`
field vs. relying on the endpoint record's tenant_id. Since SurrealDB edge records DO support
custom fields, and `schema.rs` Schema v19's edge indexes are on `in, out` (not `tenant_id`), it
is likely these edge tables have **no own `tenant_id` field** — in which case the tenant
predicate must be re-expressed against the *node's* tenant_id (e.g. `WHERE (SELECT tenant_id
FROM $this.out) = $tenant_id` or equivalent), not a flat `WHERE tenant_id = $tenant_id` clause.
**Flag this as an open question for the planner to resolve with a schema.rs read before writing
the exact SQL** (see Open Questions).

**Same TOCTOU/predicate issue applies to `role.rs`'s `has_role`/`grants` edges** — same
open-question caveat about whether these edge tables carry their own `tenant_id` field.

**D-14 GDPR deletion setup — confirmed exact strand bug.** In
`crates/axiam-api-rest/src/handlers/gdpr.rs::request_account_delete` (`:451-495`):
```rust
user_repo.mark_deletion_pending(auth_user.tenant_id, target_id, scheduled_purge_at).await?;  // :477-479
auth_service.revoke_all_sessions(auth_user.tenant_id, target_id).await?;                     // :482-484
// ... generate cancel token ...
account_deletion_repo.create(CreateAccountDeletion { ... }).await?;                           // :490-496
```
`mark_deletion_pending` (`user.rs:796-818`, a plain `UPDATE ... WHERE tenant_id = $tenant_id`,
no transaction) and `account_deletion_repo.create` (`account_deletion.rs:148-176`, a plain
`CREATE`, no transaction) are **two fully independent DB round-trips issued from the handler**.
If `account_deletion_repo.create` fails (e.g. a duplicate-pending-deletion unique-constraint hit,
or a transient DB error) **after** `mark_deletion_pending` already succeeded, the user is left
with `deletion_pending = true` / `status = 'Inactive'` but **no `account_deletion` row exists to
hold the `cancel_token_hash`** — the user has no way to look up a valid cancel token, yet
`find_due_for_purge` (`user.rs:844-860`) purges strictly on `user.deletion_pending = true AND
scheduled_purge_at <= now`, independent of whether an `account_deletion` row exists. This is
exactly D-14's "uncancellable purge" scenario.

**Recommended fix:** add a new repository method — e.g. `AccountDeletionRepository::
create_with_pending_flag(tenant_id, user_id, scheduled_purge_at, cancel_token_hash) ->
AxiamResult<AccountDeletion>` on `SurrealAccountDeletionRepository` — that issues ONE compound
transaction touching both `user` and `account_deletion` tables:
```sql
BEGIN TRANSACTION;
UPDATE type::record('user', $user_id) SET
    deletion_pending = true, scheduled_purge_at = $purge_at,
    status = 'Inactive', updated_at = time::now()
    WHERE tenant_id = $tenant_id;
CREATE type::record('account_deletion', $ad_id) SET
    tenant_id = $tenant_id, user_id = $user_id,
    cancel_token_hash = $hash, scheduled_purge_at = $purge_at,
    status = 'pending', created_at = time::now();
COMMIT TRANSACTION;
```
The handler (`gdpr.rs`) replaces its two separate calls
(`user_repo.mark_deletion_pending(...)` + `account_deletion_repo.create(...)`) with this one new
method call. `revoke_all_sessions` can stay a separate, subsequent call (not part of the strand
risk — a failure there doesn't leave an uncancellable purge, just an unrevoked session, a lesser
and pre-existing concern out of D-14's scope).

### Approach
1. `role.rs::delete`: wrap in `BEGIN`/`COMMIT`, add tenant predicates to `has_role`/`grants`
   deletes (pending the edge-table `tenant_id`-field verification above).
2. `resource.rs::delete`: fold the child-count guard into the same transaction via `LET
   $child_count = (...)`, add tenant predicates to `child_of`/`on_resource` deletes.
3. Add `create_with_pending_flag` (or similarly-named) method for D-14, update `gdpr.rs` handler.
4. Tests (D-04 mandates both updating old-behavior tests AND adding lock-in tests): cross-tenant
   edge-strip test (attempt delete of a role/resource whose edges reference a different tenant's
   node — assert the foreign edge survives), concurrent-child test (spawn a child-create
   concurrently with the parent delete — assert either the delete fails with the existing
   "cannot delete resource with children" error OR the child never gets orphaned, never both a
   successful delete AND a surviving orphaned child), GDPR strand test (force
   `account_deletion_repo.create` to fail post-`mark_deletion_pending` — e.g. via a duplicate
   pending-deletion row — assert `user.deletion_pending` rolls back to `false`).

### Landmines / ordering constraints
- **Resolve the edge-table `tenant_id`-field question before writing final SQL** (see Open
  Questions) — this determines whether the tenant predicate is a flat `WHERE tenant_id = ...`
  or a subquery/join guard.
- Land this section alongside/before QUAL-03 per D-19 (both are "security-adjacent, land first").
- These are the **only** sections with new/updated tests asserting different responses than
  today (D-04) — make sure the plan explicitly calls out which existing tests need updating
  (`resource_scope_test.rs::delete_resource`, `role_permission_test.rs::delete_role` — verify
  neither currently asserts on the vulnerable cross-tenant edge behavior in a way that would
  need updating vs. just needs a new adjacent test).

## QUAL-05: PKI Helper Deduplication

### Verified current state

**The "minimal CA params" bug (`cert.rs:224-231`) is real, but currently latent (no observable
divergence today) because CA subjects are CN-only in this codebase — still worth fixing per
D-08's defensive/future-proofing rationale.** `CertService::generate` (`cert.rs:142-146`)
reconstructs the signing CA by calling `build_ca_params(&ca_subject)` — which builds a **brand
new** `CertificateParams` from scratch, pushing only `DnType::CommonName` (`cert.rs:224-230`),
setting `is_ca = Ca(Unconstrained)`, and leaving `not_before`/`not_after`/serial as rcgen
defaults — then `.self_signed(&ca_key_pair)` to get an in-memory `Certificate` used purely as the
`issuer` parameter to `ee_params.signed_by(&ee_key_pair, &ca_certificate, &ca_key_pair)`.
Verified `ca.rs::generate` (`:75-77`) also only ever sets `DnType::CommonName` when originally
creating a CA cert — so **today**, the reconstructed CA's DN matches the real one (both are
CN-only), meaning the "identical issuer DN" equivalence test D-08 requires would currently pass
either way. The real risk is **latent DN drift**: if a CA subject ever gained additional RDN
components (O=, OU=, C=) — which `CaCertificate.subject`'s own doc comment example ("e.g.,
`CN=ACME Corp Root CA`") suggests is a plausible future format — `build_ca_params`'s CN-only
reconstruction would silently produce leaf certs with a **different issuer DN** than the real CA
cert's actual subject. There is no "upload external CA" path in this codebase today (`ca.rs` only
has `generate`, no import/upload method) — so this drift vector isn't reachable in the current
build, but D-08's fix removes it permanently rather than leaving it latent.

**rcgen 0.13.2 API — verified against the vendored crate source at
`/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rcgen-0.13.2/src/certificate.rs`**
(not web search — this is a stronger source, the actual compiled dependency):
```rust
// certificate.rs:198 (feature-gated: pem + x509-parser)
pub fn from_ca_cert_pem(pem_str: &str) -> Result<Self, Error>
// certificate.rs:225 (feature-gated: x509-parser)
pub fn from_ca_cert_der(ca_cert: &CertificateDer<'_>) -> Result<Self, Error>
```
`from_ca_cert_der`'s doc comment (`:203-223`) confirms exactly the D-08 use case: *"This function
is only of use if you have an existing CA certificate you would like to use to sign a certificate
generated by rcgen. By providing the constructed `CertificateParams` and the `KeyPair` associated
with your existing `ca_cert` you can use `CertificateParams::signed_by()`... In general this
function only extracts the information needed for signing."* It parses the real subject DN
(`DistinguishedName::from_name(&x509.tbs_certificate.subject)`), `is_ca`, validity window,
SAN/key-usage/name-constraint extensions, **and the real serial number**
(`x509.serial.to_bytes_be()`) via `x509_parser::parse_x509_certificate`. The crate's own test
suite (`certificate.rs:1466`) demonstrates the exact pattern: `CertificateParams::
from_ca_cert_pem(ca_cert_pem)` → `.self_signed(&ca_key_pair)` → use the resulting `Certificate`
as the `issuer` for `signed_by`.

**LANDMINE — Cargo feature flag required, not currently enabled.** rcgen's `x509-parser` optional
dependency (`rcgen-0.13.2/Cargo.toml:114-117`, `version = "0.16"`) auto-generates an implicit
Cargo feature also named `x509-parser`. rcgen's `default` features are `["crypto", "pem",
"ring"]` (`Cargo.toml:165-169`) — **`x509-parser` is NOT a default feature**. Verified
`crates/axiam-pki/Cargo.toml:19`: `rcgen = { workspace = true }` — no extra features requested,
so `from_ca_cert_pem`/`from_ca_cert_der` are **currently uncompilable** (the `#[cfg(feature =
"x509-parser")]` gate on rcgen's own definitions is not satisfied). **Required fix:** change to
`rcgen = { workspace = true, features = ["x509-parser"] }` in `crates/axiam-pki/Cargo.toml`
before writing any code that calls `from_ca_cert_pem`. Note this is a *separate* Cargo feature
namespace from axiam-pki's own **direct** dependency on the `x509-parser` crate (`crates/
axiam-pki/Cargo.toml:20`, `x509-parser = { workspace = true }`, workspace pins `0.17` with
`features = ["verify"]`) — enabling `rcgen/x509-parser` will pull in `x509-parser 0.16.x` as
rcgen's own internal dependency alongside axiam-pki's direct `0.17.x` use; Cargo resolves both
independently with no conflict (confirmed 3 versions of `x509-parser` — 0.16.0, 0.17.0, 0.18.1
— already coexist in `Cargo.lock`, so this is a benign, already-normal situation for this
dependency graph, not a new problem).

**Triplication inventory — precise, not "3x everything."** `grep -n "fn generate_keypair|fn
compute_fingerprint|fn encrypt_private_key|fn decrypt_private_key" crates/axiam-pki/src/*.rs`:

| Helper | ca.rs | cert.rs | pgp.rs | Verdict |
|---|---|---|---|---|
| `generate_keypair` (X.509 `KeyAlgorithm` → `KeyPair`) | `:151` | `:234` | — (pgp.rs has its own, `PgpKeyAlgorithm`+`user_id` → `SignedSecretKey`, genuinely different type, NOT mergeable) | **Byte-identical** between ca.rs/cert.rs — unify these 2, leave pgp.rs's distinct impl alone |
| `compute_fingerprint` (DER → SHA-256 hex) | `:161` | `:247` | — (pgp fingerprints come from the `pgp` crate itself) | **Byte-identical** between ca.rs/cert.rs — unify these 2 |
| `encrypt_private_key`/`decrypt_private_key` (AES-256-GCM, 12-byte nonce prepend) | `encrypt` only, `:168` | `decrypt` only, `:253` (returns `String` via extra `from_utf8`) | **both**, `:277`/`:291` (return `Vec<u8>`) | Logic is functionally identical AES-256-GCM scheme across all 3 (verified byte-for-byte: same nonce-generation, same 12-byte split, same error messages) — genuinely triplicated (well, 2.5×) |

**Recommended shared module location:** new `crates/axiam-pki/src/crypto.rs`, exporting
`generate_keypair(algorithm: &KeyAlgorithm) -> AxiamResult<KeyPair>`, `compute_fingerprint(der:
&[u8]) -> String`, `encrypt_secret(plaintext: &[u8], key: &[u8;32]) -> AxiamResult<Vec<u8>>`,
`decrypt_secret(ciphertext: &[u8], key: &[u8;32]) -> AxiamResult<Vec<u8>>` (renamed from
`_private_key` to `_secret` since PGP keys aren't literally "private key" PEM strings the same
way X.509 keys are — generic naming reflects the 3-way reuse). `ca.rs`/`cert.rs` import
`generate_keypair`/`compute_fingerprint`/`encrypt_secret`/`decrypt_secret` directly; `cert.rs`'s
`decrypt_private_key` wrapper keeps its local `String::from_utf8` conversion (X.509-specific,
PGP doesn't need it) calling the shared `decrypt_secret`; `pgp.rs` imports only
`encrypt_secret`/`decrypt_secret` (keeps its own distinct `generate_keypair`). Declared in
`lib.rs` as `mod crypto;` (not `pub mod` — internal implementation detail, no external
consumers needed per the existing `pub use` re-export list).

### Approach
1. Add `rcgen/x509-parser` feature flag to `axiam-pki/Cargo.toml`.
2. Create `crypto.rs`, move the 2 identical `generate_keypair`/`compute_fingerprint` fns and the
   AES-256-GCM encrypt/decrypt pair into it; update `ca.rs`/`cert.rs`/`pgp.rs` imports.
3. Implement `CertService::generate`'s CA reconstruction via `CertificateParams::
   from_ca_cert_pem(&ca_cert.public_cert_pem)?` + `.self_signed(&ca_key_pair)` instead of
   `build_ca_params(&ca_subject)` + `.self_signed(&ca_key_pair)`. Delete `build_ca_params`.
4. Add the identical-issuer-DN equivalence test (D-08): generate a CA, sign a leaf cert via the
   new path, parse the resulting leaf's Issuer DN (via `x509-parser`, already a direct
   dependency), assert it equals the CA's own stored `subject` (or the CA cert's parsed Subject
   DN) — plus a control assertion that chain verification against the CA still succeeds.

### Landmines / ordering constraints
- `from_ca_cert_pem` requires the `pem` feature too, but that's already a **default** rcgen
  feature (on already) — only `x509-parser` needs adding.
- This section has zero dependency on QUAL-01/02/03/04 — safe to schedule anywhere in the
  D-19 order after the security-adjacent work, as CONTEXT already places it (step 3, alongside
  QUAL-02).

## QUAL-06: Frontend Shared Components & Services Adoption

### Verified current state

**`components/shared.tsx` and `hooks/useCrudMutations.ts` have ZERO current consumers — fully
unadopted, confirming CONTEXT's scouting finding exactly.** `grep -rln "from ['\"].*components/
shared['\"]" frontend/src/pages/` → 0 results. `grep -rln "from ['\"].*hooks/useCrudMutations['\"]"
frontend/src/pages/` → 0 results. Meanwhile **11 page files have their own local
re-implementations** of `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`:

| Component | Duplicated in (local fn, not importing shared.tsx) |
|---|---|
| `ToggleField` | `UserDetailPage.tsx`, `UsersPage.tsx`, `FederationPage.tsx`, `NotificationRulesPage.tsx`, `SettingsPage.tsx`, `RolesPage.tsx`, `WebhooksPage.tsx`, `ServiceAccountsPage.tsx` (8 files) |
| `SectionCard` | `UserDetailPage.tsx`, `RoleDetailPage.tsx`, `GroupDetailPage.tsx` (3 files) |
| `InfoRow` | `UserDetailPage.tsx`, `RoleDetailPage.tsx`, `GroupDetailPage.tsx` (3 files) |
| `ActionBadge` | `PermissionsPage.tsx`, `RoleDetailPage.tsx` (2 files, `RoleDetailPage`'s copy is `export`ed but has zero external importers — dead export) |

**Verdict: ADOPT (canonical, migrate all 11 pages), per D-15's "reduce duplication" mandate.**
`SectionCard`/`InfoRow` are structurally byte-identical between `shared.tsx` and every local copy
(same JSX/classes) — safe direct swap. `ToggleField` likewise identical across all 8 local
copies and `shared.tsx`.

**LANDMINE — `ActionBadge` has a real behavioral difference that must be fixed before adoption
to preserve D-03's "no behavior change."** `shared.tsx`'s `ActionBadge` (`:76-97`) looks up
`ACTION_COLOR_MAP[action]` **without lowercasing** `action` first. `RoleDetailPage.tsx`'s local
copy (`:76-97`) does `colorMap[action.toLowerCase()] ?? "bg-white/10 text-foreground/70
border-white/20"` (also a **different fallback class** than shared.tsx's `"bg-white/5
text-muted-foreground border-white/10"`). In practice, `action` values come from
`permission.action` server-side, which per the RBAC permission model are always lowercase
literals (`read`/`write`/`delete`/`admin` — confirmed no mixed-case action strings exist in the
schema/seeder), so this difference is currently unobservable — but **fix `shared.tsx`'s
`ActionBadge` to add `.toLowerCase()` before the map lookup as part of the adoption pass**
(cheap, removes a latent inconsistency, keeps true behavior-parity guaranteed rather than
"probably fine because current data happens to be lowercase").

**`lib/utils.ts`'s `slugify` — genuine duplicate, safe adopt.** 2 files
(`OrganizationsPage.tsx:21`, `OrganizationDetailPage.tsx:36`) have local `slugify` fns,
functionally equivalent to `lib/utils.ts:59`'s exported version (trivial regex difference:
local versions strip only one leading/trailing hyphen `/^-|-$/g` vs. shared's `/^-+|-+$/g`
which strips runs — since the preceding `.replace(/[^a-z0-9]+/g, "-")` already collapses runs of
non-alphanumerics to a single hyphen, there's no practical input where these two differ).
Both other 2 files already import `formatDate` from `lib/utils.ts` (partial adoption already
present) — just missing the `slugify` import. Safe direct swap.

**`services/users.ts`'s `userService`/`groupService` — already broadly adopted, contradicting
CONTEXT's framing that "pages don't uniformly import them."** `grep -rln "from ['\"].*services/
users['\"]" frontend/src/` → 10 consumer files already: `UserSearchDialog.tsx`, `services/
roles.ts`, `UserDetailPage.tsx`, `UsersPage.tsx`, `ProfilePage.tsx`, `MfaManagementPage.tsx`,
`RoleDetailPage.tsx`, `DashboardPage.tsx`, `GroupsPage.tsx`, `GroupDetailPage.tsx`. **However,
D-16's specific claim about `ProfilePage.tsx`/`MfaManagementPage.tsx` is precisely confirmed**:
both files import `services/users.ts` **type-only** (`import type { MfaMethod } from
"@/services/users"`) while making their **actual data calls** via raw `api.get`/`api.put`/
`api.delete` imported from `@/lib/api`:
- `ProfilePage.tsx:5` (`import api from "@/lib/api"`), `:63` (`api.get<UserResponse>(\`/api/v1/
  users/${userId}\`)`), `:81` (`api.put<UserResponse>(...)`), `:86` (`api.get<MfaMethod[] | {
  items: MfaMethod[] }>(...)`).
- `MfaManagementPage.tsx:4` (`import api from "@/lib/api"`), `:36` (`api.get<MfaMethod[] | {
  items: MfaMethod[] }>(...)`), `:43` (`api.delete(\`/api/v1/users/${userId}/mfa-methods/${id}\`)`).

`services/users.ts`'s `userService` object (`:92-175`) already exports the equivalent typed
methods (`getById`, `update`, MFA-method list/delete per the interfaces at `:41-56`) — the fix
is a straightforward call-site swap from `api.get(...)`/`api.put(...)`/`api.delete(...)` to
`userService.get(...)`/`userService.update(...)`/`userService.deleteMfaMethod(...)` (exact method
names to confirm against `userService`'s object literal at plan time).

**`useCrudMutations` adoption — real fit confirmed on `RolesPage.tsx`, with one non-trivial
UX-behavior nuance to flag.** `RolesPage.tsx`'s existing `createMutation`/`editMutation`/
`deleteMutation` (`:146-236`) map almost exactly onto `useCrudMutations`'s shape
(`queryKey: ["roles"]`, `createFn: roleService.create`, `updateFn: roleService.update`,
`deleteFn: roleService.remove`, `onCreateSuccess`/`onCreateError` callbacks matching the hook's
options). **LANDMINE:** `useCrudMutations`'s `onError` handlers **always** call `toast({...,
variant: "destructive" })` in addition to any optional callback — `RolesPage.tsx`'s current
`createMutation`/`editMutation` `onError` only set local inline form-error state (`setCreateError`/
`setEditError`), **no toast today**; its `deleteMutation` has **no `onError` handler at all**
(silent failure today). Adopting `useCrudMutations` as-is would **add** a toast notification on
every create/update/delete error across every migrated page — a genuine, if minor, additive UI
behavior change (arguably a bug fix for the silent-delete-failure case, but still not strictly
"zero behavior change" per D-03's letter). Flag this for the planner/tester to accept explicitly
(recommend accepting it — it's a net UX improvement and D-15 already rejects "prefer deletion,
minimal churn" in favor of real adoption) rather than silently shipping it unflagged.

### Approach
1. Fix `shared.tsx`'s `ActionBadge` to `.toLowerCase()` before the map lookup (small, first).
2. Migrate the 11 pages off their local `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge` to
   `shared.tsx` imports; delete the local fns.
3. Migrate `OrganizationsPage.tsx`/`OrganizationDetailPage.tsx` to `lib/utils.ts`'s `slugify`.
4. Migrate `ProfilePage.tsx`/`MfaManagementPage.tsx`'s inline `api.*` calls to `userService`
   methods (D-16).
5. Migrate `RolesPage.tsx` (and any other page with the same inline useMutation pattern found at
   plan time — check `GroupsPage.tsx`, `PermissionsPage.tsx`, `WebhooksPage.tsx`,
   `ServiceAccountsPage.tsx`, `NotificationRulesPage.tsx` for the same shape) to
   `useCrudMutations`, accepting the toast-on-error UX addition.

### Landmines / ordering constraints
- Do this as its own plan/diff, last (D-19 step 4) — keeps backend/frontend reviewable
  separately, as already decided.
- Frontend automated test coverage is thin (`vitest`: only 3 `*.test.*` files exist in
  `frontend/src/`; the real regression net is 13 Playwright `frontend/e2e/*.spec.ts` specs per
  Phase 26's CORR-04 fix, which gate CI). Rely on `tsc -b` (type-check) + the existing e2e specs
  + manual smoke-check for pages without direct e2e coverage — don't expect fine-grained
  automated coverage of these specific components.

## QUAL-07: Dead-Code & Per-Request-Construction Cleanup

*(Spans QUAL-01's service-hoisting — see § QUAL-01 above for the 13-site inventory — and the
dead `verify_password` — detailed here.)*

### Verified current state

**`user.rs:872`'s `verify_password` — confirmed dead outside exactly one test file.**
`pub fn verify_password(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool,
DbError>` (`user.rs:872-889`), re-exported at `crates/axiam-db/src/repository/mod.rs:71` (`pub
use user::{SurrealUserRepository, verify_password};`) and again at the crate root
`crates/axiam-db/src/lib.rs:34`. Despite the "pepper-less" framing in REQUIREMENTS.md's
historical wording, the **current** function signature already accepts an `Option<&str>` pepper
— the "trap" is that it's a fully independent Argon2 impl parallel to
`axiam-auth::password::verify_password` (`password.rs:53`, functionally identical logic), and a
caller could import either. **Grepped every call site in the workspace**
(`grep -rn "verify_password" crates/*/src/**/*.rs`): every live caller
(`axiam-api-grpc/src/services/user.rs:164`, `axiam-auth/src/password_reset.rs`,
`axiam-auth/src/policy.rs`, `axiam-auth/src/service.rs`) already calls `axiam_auth::password::
verify_password` (via `use crate::password::{...}` or `password::verify_password` where
`password` resolves to `axiam_auth::password`). The **only** consumer of `axiam_db::
verify_password` in the entire workspace is `crates/axiam-db/tests/user_repository_test.rs:12`
(`use axiam_db::verify_password;`), with 4 call sites (`:98`, `:101`, `:122`, `:125`) — all
simple `.unwrap()` assertions on hash round-trips. **D-17 confirmed: no live (non-test) caller
depends on the deleted impl.** `axiam-auth` is already a normal (non-dev) dependency of
`axiam-db` (`axiam-db/Cargo.toml:12`), so the test file can be updated with a one-line import
swap (`use axiam_auth::password::verify_password;`) — signatures match
(`(password: &str, hash: &str, pepper: Option<&str>) -> Result<bool, _>`), only the error type
differs (`AuthError` vs `DbError`), irrelevant since the test just calls `.unwrap()`.

### Approach
1. Delete `user.rs:872-889`'s `verify_password` fn and its two re-exports (`mod.rs:71`,
   `lib.rs:34`).
2. Update `user_repository_test.rs`'s import + the 4 call sites to
   `axiam_auth::password::verify_password`.
3. (See § QUAL-01 for the 13-site per-request-service hoisting — no additional work here beyond
   what's already covered there.)

### Landmines / ordering constraints
- Trivial, isolated, no ordering dependency on any other section — safe to do any time, but
  natural to bundle with the QUAL-02 dedup pass since it's in the same file family
  (`axiam-db/src/repository/`).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| CA-cert reconstruction for signing | A custom PEM/DN parser | `rcgen::CertificateParams::from_ca_cert_pem` (feature `x509-parser`, already vetted, already a workspace dependency via `x509-parser` crate) | Already ships exactly this use case per its own doc comment; hand-rolling X.509 DN parsing is a well-known source of subtle security bugs |
| SurrealDB error classification | Per-site inline `if e.to_string().contains(...)` | The centralized `helpers::classify_write_error` (D-09) reusing the exact marker strings already proven correct in `saml_replay.rs`/`federation_login_state.rs`/`seeder.rs` | D-09 explicitly rejected per-site inline matching for drift risk; 3 independent prior implementations already converged on the same 3-string marker set — treat that convergence as ground truth |
| Multi-statement atomicity | A new Rust transaction-wrapper type (`async fn with_transaction(...)`) | Inline `BEGIN TRANSACTION; ...; COMMIT TRANSACTION` SurrealQL, exactly as `user.rs:736`/`federation_login_state.rs:110` already do | D-12 explicitly rejected this as over-engineering for the phase's actual needs (a handful of call sites, not a systemic pattern needing an abstraction) |
| Generic CRUD mutation boilerplate (frontend) | New per-page bespoke mutation/toast plumbing | `hooks/useCrudMutations.ts` (already exists, well-designed, zero current adopters) | Exists, tested-in-design (typed generics over `TCreate`/`TUpdate`), just unwired |

**Key insight:** almost nothing in this phase requires new abstractions — CONTEXT's scouting
finding holds up under verification: the shared assets exist, the fixes are template-following
(mirror an existing 2-3-site pattern across the remaining N sites), and the two places a truly
new helper is warranted (`paginate<T>`, `classify_write_error`) are both simple compositions of
already-existing pieces (`CountRow` + `Pagination`/`PaginatedResult`; the 3 marker strings 3
other files already discovered independently).

## Runtime State Inventory

**Not applicable to this phase.** Phase 29 is a pure internal code-structure refactor (AppState
composition, function/struct extraction, SQL statement hardening, dead-code removal) — it does
not rename, rebrand, or relocate any domain concept, database table/column, config key, secret
name, or OS-registered identifier. Verified explicitly per category:
- **Stored data:** No table/column renames; QUAL-04's transactional fixes wrap *existing*
  statements against *existing* schema fields (verified against `schema.rs` — no `DEFINE FIELD`/
  `DEFINE TABLE` changes required). QUAL-03's new `DbError::Serialization` variant is
  Rust-internal, never persisted.
- **Live service config:** No n8n/Datadog/Tailscale/Cloudflare-style external service config
  exists in this project's stack; not applicable.
- **OS-registered state:** No Task Scheduler/pm2/launchd/systemd entries reference any
  identifier this phase touches.
- **Secrets/env vars:** `AXIAM__EMAIL_ENCRYPTION_KEY` (D-02's conditional dep) and
  `AXIAM__PKI__ENCRYPTION_KEY` (QUAL-05) are read, not renamed — no env var name changes.
- **Build artifacts:** The `rcgen/x509-parser` Cargo feature addition (QUAL-05) changes the
  dependency graph slightly (pulls in `x509-parser 0.16.x` as rcgen's internal dep alongside the
  existing direct `0.17.x` use) but requires no artifact cleanup beyond the standard `cargo
  clean` already mandated by CLAUDE.md's build-hygiene rule between plan steps.

## Code Examples

### Existing transaction idiom to mirror (federation_login_state.rs:110-127)
```rust
// Source: crates/axiam-db/src/repository/federation_login_state.rs (verified in this session)
let mut result = self
    .db
    .query(
        "BEGIN TRANSACTION; \
         LET $row = (SELECT state, nonce, tenant_id, federation_config_id, \
                       redirect_uri, expires_at, request_id \
                     FROM federation_login_state \
                     WHERE state = $state LIMIT 1); \
         DELETE federation_login_state WHERE state = $state; \
         RETURN $row; \
         COMMIT TRANSACTION",
    )
    .bind(("state", state_owned))
    .await
    .map_err(DbError::from)?;
// Result slots: BEGIN=0, LET=1, DELETE=2, RETURN=3
let rows: Vec<FederationLoginStateRow> = result.take(3).map_err(|e| AxiamError::Database(e.to_string()))?;
```

### Existing centralized-error-detection precedent to reuse (saml_replay.rs:76-93)
```rust
// Source: crates/axiam-db/src/repository/saml_replay.rs (verified in this session)
result
    .check()
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("already contains") || msg.contains("already exists") || msg.contains("unique") {
            AxiamError::ReplayDetected
        } else {
            AxiamError::Database(msg)
        }
    })
    .map(|_| ())
```

### rcgen 0.13.2 from_ca_cert_pem usage pattern (from the crate's own test suite)
```rust
// Source: rcgen-0.13.2/src/certificate.rs:1466 (vendored source, verified in this session)
let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)?;
let ca_kp = KeyPair::from_pem(ca_key_pem)?;
let ca_cert = params.self_signed(&ca_kp)?; // now use `ca_cert` as the issuer in signed_by()
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| Per-repo local `struct CountRow` | Shared `helpers::CountRow` | Started in a prior phase (user.rs/role.rs already migrated) | This phase finishes the remaining 24 sites |
| `build_ca_params` (subject-CN-only synthetic CA) | `rcgen::CertificateParams::from_ca_cert_pem` (real PEM parse) | This phase (QUAL-05) | Removes latent DN-drift risk; requires new Cargo feature |
| Blanket `DbError::Migration` on write-path errors | Centralized `classify_write_error` (409 for genuine uniqueness, 5xx otherwise) | This phase (QUAL-03), pattern already proven in 3 other files | Correct HTTP semantics on create-path errors |

**Deprecated/outdated:** `crates/axiam-pki/src/cert.rs::build_ca_params` — removed entirely once
`from_ca_cert_pem` lands (QUAL-05). `crates/axiam-db/src/repository/user.rs::verify_password`
(second Argon2 impl) — removed entirely (QUAL-07/D-17).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `child_of`/`has_role`/`grants` edge tables do **not** carry their own `tenant_id` field (based on Schema v19's index being on `in, out` only, not `tenant_id`) — meaning D-13's tenant predicate on edge deletes must be expressed as a subquery/join guard against the endpoint node's tenant, not a flat `WHERE tenant_id = ...` clause | QUAL-04 | If wrong (edge tables DO have a flat `tenant_id` field), the fix is actually simpler than described (flat predicate works) — low risk either way, but the exact SQL text in this doc would need adjusting. **Planner must grep `schema.rs`'s `DEFINE FIELD ... ON TABLE has_role`/`grants`/`child_of` before finalizing SQL.** |
| A2 | Adopting `useCrudMutations` (always-toast `onError`) on pages that currently show only inline form errors (or no error UI at all, e.g. `RolesPage`'s delete) is an acceptable additive UX change, not a blocking "behavior change" violation of D-03 | QUAL-06 | If the user/reviewer considers any new toast a D-03 violation, the plan needs an explicit carve-out or a modified `useCrudMutations` that supports toast-suppression per call site |
| A3 | Applying `classify_write_error` only to the 4 true CREATE sites in `user.rs` (not the 5 UPDATE sites CONTEXT also listed) still satisfies the QUAL-03 AC, since UPDATE paths there don't touch unique-constrained fields | QUAL-03 | If a listed UPDATE site *does* touch a unique field (not verified per-field in this pass), skipping it would miss a genuine 500-should-be-409 case — low risk (recommended approach applies the helper to all 9 sites uniformly anyway, which is harmless) |

**Overall confidence is HIGH** — every non-assumption claim above was verified with a tool
(grep/Read) against the live repository or the vendored rcgen source, not recalled from training
data.

## Open Questions

1. **Do `child_of`/`has_role`/`grants` edge tables carry their own `tenant_id` field?**
   - What we know: Schema v19 (`schema.rs`) defines `UNIQUE (in, out)` indexes on these edge
     tables but the index definition alone doesn't confirm whether a `tenant_id` field also
     exists on the edge record.
   - What's unclear: the exact `DEFINE FIELD` list for these edge tables (not read in this
     research pass — time-boxed to the higher-priority verification items above).
   - Recommendation: planner greps `schema.rs` for `ON TABLE has_role`/`ON TABLE grants`/`ON
     TABLE child_of` before finalizing the exact tenant-predicate SQL in QUAL-04's plan; if no
     `tenant_id` field exists, express the predicate via a subquery against the node's tenant_id
     (e.g. resolve `out`'s owning tenant) rather than a flat WHERE clause.

2. **Which other pages beyond `RolesPage.tsx` have the same inline `useMutation` + local-toast
   pattern that would benefit from `useCrudMutations` adoption?**
   - What we know: `RolesPage.tsx` was spot-checked as a clean fit; `GroupsPage.tsx`,
     `PermissionsPage.tsx`, `WebhooksPage.tsx`, `ServiceAccountsPage.tsx`,
     `NotificationRulesPage.tsx` all have similar CRUD-page shapes (confirmed they exist among
     the 11 files with local `ToggleField`/etc. duplicates) but their individual
     `useMutation` call shapes weren't diffed against `useCrudMutations`'s options interface in
     this pass.
   - What's unclear: whether each page's `onSuccess`/`onError` callback needs match
     `UseCrudOptions`'s shape exactly, or needs a per-page adjustment.
   - Recommendation: planner does a per-page diff at plan time (mechanical, ~10 minutes per
     page) rather than assuming uniform fit from the one verified example.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|---|---|---|---|---|
| Rust/cargo toolchain | All QUAL-01…05/07 | ✓ | — (workspace-managed) | — |
| SurrealDB (surrealdb crate, embedded `kv-mem` for tests) | QUAL-02/03/04 tests | ✓ | 3.1.5 (Cargo.lock) | — |
| `rcgen` w/ `x509-parser` feature | QUAL-05 | ✓ (feature flag not yet enabled — code change, not an environment gap) | 0.13.2 | — |
| Node/npm + vitest + Playwright | QUAL-06 | ✓ (per Phase 26 CORR-04 CI wiring) | — | — |
| `SWAGGER_UI_DOWNLOAD_URL` local cache | Any build/test touching `axiam-api-rest`/`axiam-server` | ✓ | cached zip at `/home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` | — |

**Missing dependencies with no fallback:** none identified.

**Missing dependencies with fallback:** none — the only "gap" (`rcgen/x509-parser` feature not
yet enabled) is a one-line Cargo.toml change within this phase's own scope, not an environment
limitation.

## Validation Architecture

### Test Framework

| Property | Value |
|---|---|
| Backend framework | Rust built-in `#[tokio::test]`/`#[actix_web::test]` via `cargo test`, per-crate `tests/*.rs` integration tests + inline `#[cfg(test)] mod tests` unit tests |
| Backend config | Cargo workspace, no separate test-framework config file |
| Frontend framework | Vitest (unit, `frontend/src/**/*.test.ts`, only 3 files exist today) + Playwright (`frontend/e2e/*.spec.ts`, 13 specs, CI-gated per Phase 26 CORR-04) |
| Quick run command (per-crate, dev-loop) | `cargo test -p axiam-db --lib` / `-p axiam-db --test <name>`; for `axiam-api-rest`/`axiam-server`: `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip && cargo test -p axiam-api-rest --test <name>` |
| Full suite command (phase-end gate, D-06) | `export SWAGGER_UI_DOWNLOAD_URL=file:///home/user/.axiam-build-cache/swagger-ui-5.17.14.zip && cargo test --workspace` (default features, i.e. `saml` on) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|---|---|---|---|---|
| QUAL-01 | `AppState<C>` composition replaces individual `app_data`; all 35 test-harness files still compile/pass | integration (compile-gate + existing suite) | `cargo test --workspace` (full regression, no new test needed — behavior-preserving) | ✅ (existing 35 test files ARE the gate) |
| QUAL-01/D-18 | Hoisted services (`password_reset_service` etc.) behave identically to per-request construction | integration | `cargo test -p axiam-api-rest --test password_reset_revokes_sessions`, `--test federation_first_time_sso_test` | ✅ Wave 0 (existing) |
| QUAL-02 | `paginate<T>`/`CountRow`/`take_first_or_not_found` adoption is behavior-preserving | unit + integration | `cargo test -p axiam-db --lib` (new `paginate` unit test) + full existing repo test suite | ⚠️ new unit test for `paginate` — Wave 0 gap |
| QUAL-03 (409) | Genuine duplicate username/email/edge → `DbError::AlreadyExists` → HTTP 409 | integration | New test asserting `POST /users` (dup username) → 409; new test asserting dup role-assignment RELATE → 409 | ⚠️ Wave 0 gap — new test |
| QUAL-03 (5xx) | Non-uniqueness DB error (e.g. simulated outage) still → 5xx, never a false 409 | unit | New unit test on `classify_write_error` with a synthetic non-marker error string | ⚠️ Wave 0 gap — new test |
| QUAL-03 (D-10) | `parse_uuid` on corrupt data returns `DbError::Serialization`, not `Migration` | unit | Extend existing `helpers.rs` `#[cfg(test)] mod tests` (already has `parse_uuid_invalid_contains_field_name`) | ✅ existing test file, ⚠️ new assertion needed |
| QUAL-03 (D-11) | OAuth2 DB outage → `ServerError`/5xx, not `invalid_client`/401 | integration | New test on `authenticate_client`/`token.rs` with a mocked DB-outage repo | ⚠️ Wave 0 gap — new test |
| QUAL-04 (cross-tenant) | Deleting a role/resource never strips another tenant's edge, even with a spoofed/foreign ID | integration | New test: create role/resource in tenant A, edge in tenant B referencing same-ID collision scenario (or direct repo-level cross-tenant delete attempt), assert tenant B's edge survives | ⚠️ Wave 0 gap — new test, extends `role_permission_test.rs`/`resource_scope_test.rs` |
| QUAL-04 (concurrent-child) | Concurrent child-create during resource delete never results in both a successful delete AND a surviving orphan | integration | New test: spawn concurrent `create` (child) + `delete` (parent), assert invariant holds | ⚠️ Wave 0 gap — new test |
| QUAL-04 (D-14 GDPR) | `create_with_pending_flag` failure rolls back `deletion_pending` | integration | New test forcing a duplicate-pending-deletion conflict, assert `user.deletion_pending == false` after | ⚠️ Wave 0 gap — new test |
| QUAL-05 | Leaf cert signed via `from_ca_cert_pem` path carries identical issuer DN to the old path + still verifies against CA chain | unit/integration (`axiam-pki` crate tests) | New test in `cert.rs`'s `#[cfg(test)]` module | ⚠️ Wave 0 gap — new test |
| QUAL-06 | Pages render/function identically after shared-component/service adoption | manual + existing e2e | `npx playwright test` (existing 13 specs) + manual smoke-check of the 11 migrated pages | ✅ existing e2e gate; ⚠️ manual smoke-check needed for pages without direct e2e coverage |
| QUAL-07 | Deleted `verify_password` — no live caller broken | unit | `cargo test -p axiam-db --test user_repository_test` (updated import) | ✅ existing test file, needs import swap |

### Sampling Rate
- **Per task commit:** narrowly-scoped `cargo test -p <crate> --lib`/`--test <name>` (per D-06,
  per CLAUDE.md build-hygiene).
- **Per wave merge:** the relevant crate's full `--test` suite (e.g. all of `axiam-db/tests/`,
  all of `axiam-api-rest/tests/`).
- **Phase gate:** `cargo test --workspace` (full regression, D-06) — this is the primary proof
  that QUAL-01/02/05/06/07's "no behavior change" holds; QUAL-03/04's intentionally-changed
  tests must be updated in the SAME commit that changes the behavior (D-04), never left red.

### Wave 0 Gaps
- [ ] `crates/axiam-db/src/helpers.rs` — add `paginate<T>` unit tests (mirrors existing
      `parse_uuid`/`take_first_or_not_found` test style already in the file)
- [ ] `crates/axiam-db/src/helpers.rs` or a new test module — `classify_write_error` unit tests
      (genuine-duplicate → `AlreadyExists`, non-marker error → falls through unchanged)
- [ ] `crates/axiam-api-rest/tests/` — new integration test(s) for the user-create 409 path and
      an edge-uniqueness 409 path
- [ ] `crates/axiam-oauth2/` or `axiam-api-rest/tests/oauth2_*` — new DB-outage-vs-invalid_client
      test (needs a mockable repo error injection point — verify one exists or add a test-only
      seam)
- [ ] `crates/axiam-db/tests/role_permission_test.rs` — cross-tenant edge-strip test
- [ ] `crates/axiam-db/tests/resource_scope_test.rs` — concurrent-child TOCTOU test
- [ ] `crates/axiam-api-rest/tests/gdpr_test.rs` — GDPR deletion-setup atomicity test
- [ ] `crates/axiam-pki/src/cert.rs` (or a new `crates/axiam-pki/tests/`) — identical-issuer-DN
      signing-equivalence test

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V2 Authentication | No (out of scope — no auth-mechanism change) | — |
| V3 Session Management | No | — |
| V4 Access Control | **Yes** | QUAL-04's tenant-predicate hardening (D-13) is a direct ASVS V4 (Access Control) / multi-tenancy isolation control — every mutating statement inside a transaction must independently re-assert the tenant boundary, not rely on a single upstream check |
| V5 Input Validation | Marginal | QUAL-03's error-taxonomy work doesn't validate new input, but correctly reflects validation-adjacent outcomes (uniqueness) as 409 rather than leaking internal 500s |
| V6 Cryptography | **Yes** | QUAL-05's PKI dedup reuses the existing AES-256-GCM (already ASVS-compliant per this project's `CLAUDE.md` security standards) — the refactor must not change nonce/key handling, only consolidate duplicate implementations byte-for-byte |
| V9 Communications | No | — |
| V12 Files and Resources | No | — |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---|---|---|
| Cross-tenant edge deletion via spoofed/foreign resource ID (CQ-B07/SEC-058 family) | Tampering / Elevation of Privilege | Tenant-predicated DELETE on every statement inside the transaction (D-13) — this phase's core QUAL-04 fix |
| TOCTOU on child-guard-then-delete (CQ-B46) | Tampering | Same-transaction SELECT+DELETE (LET-capture pattern already established in `federation_login_state.rs`) |
| Error-oracle leaking DB-outage-vs-not-found distinction to attacker (OAuth2 D-11) | Information Disclosure (minor) | Route DB outages to a distinct `ServerError`/5xx rather than silently reusing `invalid_client`, which also happens to fix operational blindness (an outage masquerading as bad credentials would be invisible to monitoring) |
| Silent uncancellable GDPR purge strand (D-14, CQ-B39 residual) | Denial of Service (against the data subject's own erasure/cancel right) | Single-transaction `mark_deletion_pending` + `account_deletion` create |
| CA-reconstruction DN drift silently changing certificate issuer identity (D-08) | Tampering / Repudiation (a leaf cert's issuer field could silently diverge from the real CA's subject) | Parse the real stored PEM (`from_ca_cert_pem`) instead of reconstructing from a partial field |

## Sources

### Primary (HIGH confidence — verified this session via tool)
- Live codebase reads (`Read`/`Grep`/`Bash grep`) across `crates/axiam-server/src/main.rs`,
  `crates/axiam-api-rest/src/{handlers,extractors,middleware,server.rs,health.rs}`,
  `crates/axiam-db/src/{helpers.rs,error.rs,repository/*.rs,schema.rs}`,
  `crates/axiam-pki/src/{ca.rs,cert.rs,pgp.rs,lib.rs}`, `crates/axiam-oauth2/src/{error.rs,
  authorize.rs,token.rs}`, `crates/axiam-core/src/{error.rs,repository.rs}`,
  `frontend/src/{components/shared.tsx,hooks/useCrudMutations.ts,lib/utils.ts,services/users.ts,
  pages/**}` — all counts/line-numbers in this document were produced by grep/read against these
  files in this session, not recalled.
- `/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rcgen-0.13.2/src/certificate.rs`
  and `Cargo.toml` — vendored dependency source, read directly (stronger than a web search for
  API-exactness against the pinned version).
- `Cargo.lock` — exact pinned versions (`surrealdb 3.1.5`, `rcgen 0.13.2`, `x509-parser`
  0.16.0/0.17.0/0.18.1 coexisting).
- `.planning/REQUIREMENTS.md` §QUAL-01…07, `.planning/phases/29-structural-quality/29-CONTEXT.md`,
  `.planning/STATE.md`, `./CLAUDE.md`.

### Secondary (MEDIUM confidence)
- None — this research relied entirely on direct codebase/vendored-source verification; no
  external web search or Context7 lookup was needed since the phase is pure internal-codebase
  archaeology, not new-library adoption.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new libraries introduced; the one Cargo feature-flag change
  (`rcgen/x509-parser`) was verified against the vendored source, not assumed.
- Architecture: HIGH — every file/line reference was grepped/read this session.
- Pitfalls: HIGH — the landmines (non-handler `web::Data` sites, test-harness surface, SAML
  cfg-gate, edge-table tenant-field open question, `ActionBadge`/`useCrudMutations` UX nuances)
  were all discovered via direct code reading, not inferred from CONTEXT.md's summary alone.

**Research date:** 2026-07-06
**Valid until:** 30 days (stable, internal-refactor phase; no external API/library drift risk
except the noted rcgen feature-flag requirement, which is fixed by pinned `Cargo.lock` version).

## RESEARCH COMPLETE
