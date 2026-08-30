---
phase: 29-structural-quality
plan: 03
type: execute
completed: 2026-07-06
requirements: [QUAL-01, QUAL-07]
status: complete
---

# 29-03 SUMMARY — AppState extraction (full migration) + per-request service hoisting

## What was built

**QUAL-01 — AppState<C> composition root.** `crates/axiam-api-rest/src/state.rs`
(new, 452 lines) defines `AppState<C: surrealdb::Connection + Clone>` holding every
REST handler dependency as a field. `axiam-server/src/main.rs` now builds ONE
`AppState<C>` and registers it once, replacing ~48 individual
`.app_data(web::Data::new(...))` calls. Every handler extracts
`web::Data<AppState<C>>` and reads deps as fields (`state.user_repo`,
`state.auth_service`, …). The 7 non-handler extraction sites (auth + cert_auth
extractors, `rate_limit_shared` middleware, `health`) pull their deps from
`AppState<C>` as well.

**QUAL-07 — per-request service hoisting.** The federation/reset/verification
services (13 per-request construction sites) are now shared singletons built once
at startup and stored on `AppState`: `password_reset_service`,
`email_verification_service`, `oidc_federation_service`, `saml_federation_service`.

Behavior-preserving composition only — no repository method signatures changed.
`email_config_repo` stays an `Option<>` field (fail-closed `None` when unconfigured).

## Deviations

- **Rule 2 (documented in `state.rs` module docs):** Three dependencies —
  `AuthConfig`, `Arc<dyn SessionValidator>`, `Arc<dyn AuthzChecker>` — remain
  registered as standalone `web::Data<T>` in `main.rs` *in addition to* being
  `AppState` fields. The non-generic `AuthenticatedUser` `FromRequest` impl and the
  cross-crate `AuditMiddleware` cannot resolve a generic `AppState<C>` (no `C` in
  scope), so they must keep looking up the connection-agnostic types directly. The
  118 `AuthzData` call sites are out of this plan's migration scope. This is a
  deliberate, documented exception to prohibition "no dependency registered outside
  AppState," not an oversight.

## Execution note — recovered from an interrupted executor

The original executor completed the full migration and reached its commit step but
stalled: verifying a 65-file change across two crates builds dozens of
integration-test binaries, which repeatedly exhausted the ~38 GB sandbox disk quota
(CLAUDE.md's documented failure mode), forcing full `rm -rf target/` rebuilds — an
hour of thrash with nothing committed. The orchestrator killed it and recovered the
work: compiled it, then ran the entire existing test suite in disk-safe batches
(`cargo clean -p` between batches to keep deps cached), fixed the one failure, and
committed.

## Verification (behavior-preservation gate — all green post-recovery)

- Compiles: `axiam-api-rest` lib + `axiam-server` bin (4m17s, exit 0).
- `axiam-api-rest --lib`: **69/69**.
- All ~39 `axiam-api-rest` integration test binaries: green (auth, rbac, federation,
  health, middleware, rate_limit ×2, service_account, device_auth, password_reset,
  mfa, csrf, bootstrap, audit, certificates ×2, email_config, group, gdpr ×2,
  oauth2 ×3, oidc_conformance, organization, pgp, qual03, req14 ×2, resource_scope,
  role_permission, security_headers, settings, tenant, user, webhook ×2).
- All 9 `axiam-server` integration tests green, incl. `req5_oidc_e2e` and
  `req5_saml_e2e` (`--features saml`, validates the hoisted `SamlFederationService`).
- **~400 tests total, 0 failures.**

## One failure found + fixed (separate commit, pre-existing)

`route_openapi_parity_test::every_openapi_path_is_registered` failed because
`/api/v1/federation/saml/metadata` was orphaned by the Phase 28 D-15 change (removed
from `PUBLIC_PATHS`, never reclassified). Fixed by adding it to
`AUTHENTICATED_SELF_SERVICE_PATHS` (JWT-authenticated, no named permission).
Committed separately as `fix(28): classify saml/metadata …` — latent since Phase 28,
not caused by this migration.

## Key files

- `crates/axiam-api-rest/src/state.rs` — new `AppState<C>` composition root
- `crates/axiam-api-rest/src/lib.rs` — `pub mod state; pub use state::AppState;`
- `crates/axiam-server/src/main.rs` — single `AppState<C>` registration
- `crates/axiam-api-rest/src/handlers/*` — every handler migrated to `web::Data<AppState<C>>`
- `crates/axiam-api-rest/src/extractors/{auth,cert_auth}.rs`, `middleware/rate_limit_shared.rs`, `health.rs` — non-handler extraction sites
- `crates/axiam-api-rest/tests/*`, `crates/axiam-server/tests/*` — test-harness builders construct one `AppState<C>` (the no-behavior-change gate)

## Commits

- `20658c0` feat(29-03): extract AppState<C> composition root + hoist per-request services
- `818b645` fix(28): classify saml/metadata as authenticated-self-service (D-15 follow-up)
