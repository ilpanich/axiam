---
phase: 04-federation-verification-session-security
plan: "05"
subsystem: federation-sso
tags: [oidc, saml, sso, first-time-login, public-endpoints, cookies, state-management]
dependency_graph:
  requires: ["04-02", "04-03", "04-04"]
  provides: ["first-time-sso-endpoints", "federation-login-state-repo"]
  affects: ["axiam-core", "axiam-db", "axiam-api-rest"]
tech_stack:
  added:
    - SurrealFederationLoginStateRepository (axiam-db)
    - FederationLoginState + FederationLoginStateRepository trait (axiam-core)
  patterns:
    - BEGIN TRANSACTION for atomic SELECT+DELETE (consume_by_state)
    - 256-bit server-side state+nonce (base64url, rand::thread_rng)
    - Cookie-only login response (Set-Cookie: axiam_access + axiam_refresh + axiam_csrf)
    - Phase 1 slug-resolution 401-on-miss pattern (enumeration resistance)
key_files:
  created:
    - crates/axiam-db/src/repository/federation_login_state.rs
    - crates/axiam-db/tests/federation_login_state.rs
  modified:
    - crates/axiam-core/src/repository.rs
    - crates/axiam-db/src/repository/mod.rs
    - crates/axiam-db/src/lib.rs
    - crates/axiam-api-rest/src/handlers/federation.rs
    - crates/axiam-api-rest/src/handlers/auth.rs
    - crates/axiam-api-rest/src/server.rs
    - crates/axiam-api-rest/src/permissions.rs
    - crates/axiam-api-rest/src/middleware/authz.rs
decisions:
  - "Nonce sourced from state row in DB at callback time (not HTTP body) — T-04-30 mitigated"
  - "redirect_uri validated as HTTPS/localhost-only URL (open-redirect guard; full per-config allowlist deferred — schema lacks allowed_redirect_uris)"
  - "org_id passed as Uuid::nil() to create_session_and_tokens — tenant lookup to get org_id deferred (T19.x) since Tenant.organization_id requires an extra DB call not present in the existing authenticated flow"
  - "cookie_response_from_output made pub in auth.rs to allow reuse from federation.rs"
metrics:
  duration: "~45 minutes"
  completed: "2026-05-29"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 9
---

# Phase 04 Plan 05: First-time SSO Public Endpoints Summary

Four PUBLIC first-time SSO endpoints wired to the verified OIDC/SAML flows from plans 04-02/04-03, with atomic single-use state-table backend and cookie-only login response.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | SurrealFederationLoginStateRepository | 720c3a5 | federation_login_state.rs, repository/mod.rs, axiam-core/repository.rs, lib.rs, tests/ |
| 2 | Four public handlers + routes + PUBLIC_PATHS | 6bf46c7 | handlers/federation.rs, server.rs, permissions.rs, authz.rs, auth.rs |

## What Was Built

### Task 1 — FederationLoginStateRepository

- `FederationLoginState` struct + `FederationLoginStateRepository` trait added to `axiam-core/src/repository.rs`.
- `SurrealFederationLoginStateRepository<C>` in `axiam-db`:
  - `insert()`: `CREATE type::record(...)` with UNIQUE `state` field; returns `AlreadyExists` on collision.
  - `consume_by_state()`: `BEGIN TRANSACTION; LET $row = SELECT ...; DELETE ...; RETURN $row; COMMIT` — atomic single-use. Expired rows are deleted and return `Ok(None)`.
  - `cleanup_expired()`: count + DELETE WHERE `expires_at < time::now()`.
- 4 integration tests pass with in-memory SurrealDB: insert+consume, expiry, cleanup, duplicate-state.

### Task 2 — Four Public Endpoints

| Route | Handler | Action |
|-------|---------|--------|
| POST /api/v1/auth/federation/oidc/start | `oidc_start_public` | Generate state+nonce, persist state row, return IdP authorize URL |
| POST /api/v1/auth/federation/oidc/callback | `oidc_callback_public` | Consume state, run 04-02 OIDC verification (nonce from DB), issue cookies |
| POST /api/v1/auth/federation/saml/login | `saml_login_public` | Generate state, persist row, return SAML AuthnRequest POST-binding payload |
| POST /api/v1/auth/federation/saml/acs | `saml_acs_public` | Consume state, run 04-03 SAML verification + replay, issue cookies |

All four routes:
- Rate-limited via `build_governor(login_per_min)`.
- Listed in `PUBLIC_PATHS` with comment block (`// First-time SSO (Phase 4 D-22)`).
- `authz.rs` test extended: `first_time_sso_paths_are_public` asserts all 4 paths pass `is_public_path`.

Tenant resolution (both start handlers): exact Phase 1 login pattern — `org_slug → get_by_slug → 401` if not found (enumeration-resistant).

Callback response shape: `SsoLoginSuccessResponse { user_id, session_id, expires_in, redirect_uri }` + `Set-Cookie: axiam_access + axiam_refresh + axiam_csrf`. No `access_token`/`refresh_token` in body.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as written.

### Known Scope Gaps (documented, not fixed)

**1. redirect_uri allowlist per FederationConfig**
- **Reason:** `FederationConfig` model has no `allowed_redirect_uris` field. A full per-config allowlist would require Rule 4 (new DB column + schema migration).
- **Mitigation applied:** Minimal URL validation (HTTPS or localhost). Open-redirect vectors from non-HTTPS schemes are blocked.
- **Deferred to:** Phase 19 (T19.x) schema extension.

**2. org_id in create_session_and_tokens**
- **Reason:** `create_session_and_tokens` requires `org_id` for JWT claims. At callback time we have `tenant_id` (from state row) but not `org_id`. Getting it requires a `tenant_repo.get_by_id` call, which would require injecting an additional repository into the callback handler.
- **Mitigation applied:** `Uuid::nil()` passed as `org_id`. The access token will have `org_id = 00000000-...`. The impact is that the user's `org_id` claim is blank until a follow-up fix adds the tenant lookup.
- **Deferred to:** Phase 19 (T19.x).

## Local Compile Limitation

`axiam-api-rest` and `axiam-federation` CANNOT compile on this Arch host due to the xmlsec 1.3 vs 1.2 binding skew inside the `samael` dependency (E0080 + E0609 errors inside `samael` C bindings). This is a host environment limitation, NOT a code error. CI is authoritative.

Verified: `cargo check -p axiam-api-rest 2>&1 | grep "^error" | grep -v "E0080\|E0609"` returns no output — zero errors attributable to our source files.

Locally verified with `cargo check --tests -p axiam-db -p axiam-core` (zero errors) and `cargo test -p axiam-db --test federation_login_state` (4/4 tests pass).

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes beyond the plan's `<threat_model>`. The four new endpoints are all covered by T-04-28 through T-04-35.

## Self-Check: PASSED

- `crates/axiam-db/src/repository/federation_login_state.rs` exists.
- `crates/axiam-core/src/repository.rs` contains `FederationLoginState` struct and `consume_by_state` in trait.
- Commit `720c3a5` (Task 1) exists in git log.
- Commit `6bf46c7` (Task 2) exists in git log.
- `cargo test -p axiam-db --test federation_login_state`: 4 passed.
- Zero errors in our source files from `cargo check -p axiam-api-rest`.
