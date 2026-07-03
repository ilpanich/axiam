# Phase 23: Security Regressions & HIGH Findings - Research

**Researched:** 2026-07-03
**Domain:** Rust/Actix-Web/Tonic security remediation — gRPC auth, tenant-isolation SurrealQL guards, AES-256-GCM fail-closed key handling, SAML XML-Signature-Wrapping defense, session revocation, enumeration-safe multi-tenant reset flows
**Confidence:** HIGH (every code location below was read from the live `main` branch, not assumed from the review commit)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

> These four were confirmed as the recommended security defaults during discuss-phase (the interactive picker was unavailable; defaults were locked and may be edited here before planning). The rest are Claude's discretion.

**Webhook encryption-key posture (SECFIX-03)**
- **D-01:** **Graceful degrade.** The server boots when `AXIAM__PKI__ENCRYPTION_KEY` is unset; webhook **registration and delivery are refused** (explicit error + `warn!`) until a key is present. NEVER substitute an all-zero (or any constant) key. This mirrors PKI's lazy fail-closed on the same env var — an optional subsystem must not block whole-server boot, but must never operate under a bogus key.
- **D-02:** On create AND update, the webhook secret is encrypted with AES-256-GCM before storage (call `encrypt_webhook_secret` on both write paths); the response continues to exclude the secret (`skip_serializing`); the update DTO exposes secret rotation.

**Logout revocation (SECFIX-05)**
- **D-03:** **Server-side revocation from the authenticated JWT `jti`, no request body.** The logout handler revokes the caller's own session using `jti` from the validated token; the frontend posts nothing. No client-supplied `session_id`, no IDOR surface. All three auth cookies are cleared server-side. Frontend `handleLogout` must stop sending `{}`/`{session_id}` and must no longer 400.

**Reset/verify tenant resolution (SECFIX-06)**
- **D-04:** **Tenant slug carried in the page URL + tenant-bound server token.** The public reset/verify pages carry the tenant slug in their URL (consistent with how login already establishes tenant selection); the emailed confirm link carries the server-generated, tenant-scoped token. The frontend threads `tenant_id`/`email` into `requestPasswordReset`, `confirmPasswordReset`, `resendVerification` to match the backend DTOs. No user-typed tenant field, no email-domain inference.
- **D-05:** Responses stay **enumeration-safe** — a constant response (and constant-ish timing) regardless of whether the account exists or is federated. (Deeper constant-time work is SECHRD-12/Phase 24; Phase 23 must not regress the existing enumeration-safety.)

**gRPC ValidateCredentials lockout (SECFIX-01 / SEC-026b)**
- **D-06:** **Always-on lockout accrual via a shared helper.** Factor the REST-login failed-attempt/lockout counter into a shared helper that BOTH the REST login path and gRPC `ValidateCredentials` call, so there is no unmetered credential-check path even for an authenticated mesh peer. Not behind a config flag.

### Claude's Discretion

- **gRPC auth wiring (SECFIX-01):** apply the existing `AuthInterceptor` to `UserService` and `TokenService` — prefer a single shared tower `Layer` across all three gRPC services over per-service duplication if clean. Derive `tenant_id`/`user_id` from `ValidatedClaims` and reject any mismatched body field, exactly as `AuthorizationService` already does. Add reject-without-token tests for both services.
- **SECFIX-02 mechanics:** apply the same `LET … IF array::len = 0 { THROW }` tenant predicate to BOTH branches (empty-scope and scoped) of `grant_to_role_with_scopes`; additionally validate every scope id belongs to the caller's tenant. Repoint the existing tenant-isolation test at the REST-reachable `grant_to_role_with_scopes` path (not the already-guarded `grant_to_role`).
- **SECFIX-04 mechanics:** bind the verified XML-signature reference ID to the assertion actually consumed by `handle_saml_response` (reject when they differ); pass the real ACS URL to the `Destination` check (stop passing `None`); require `InResponseTo` on the authenticated ACS path; add an XSW negative test (wrapped/duplicated assertion rejected).
- **Test placement:** Rust negative tests in the owning crate's `tests/` (`axiam-api-grpc/tests/`, `axiam-db` isolation test, `axiam-federation`/server SAML tests); frontend logout/reset behavior is validated by Playwright specs (execution gated in CI under CORR-04, Phase 26). Per-crate builds only.
- **Per-PLAN `<threat_model>`:** the security capability is active — each PLAN.md carries a threat-model block (ASVS-aligned) for the control it touches.

### Deferred Ideas (OUT OF SCOPE)

- Webhook **delivery** wiring (durable AMQP queue + retry + audit status) — CORR-03, Phase 26 (depends on SECFIX-03).
- Deeper **constant-time** reset side-channel + zeroize + GDPR-audit DLQ — SECHRD-12, Phase 24.
- Running Playwright in CI with request-**body** assertions — CORR-04, Phase 26 (this is what actually gates SECFIX-06 in CI).
- SAML `Recipient`/`SubjectConfirmationData` full validation beyond the XSW-binding + Destination/InResponseTo minimum — remainder tracked under SEC-005 residual if not fully closed here.

None of these expand Phase 23 scope — they are the correct home for adjacent work.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| SECFIX-01 | gRPC `UserService`/`TokenService` authentication + tenant cross-validation + always-on lockout (SEC-003, SEC-026b) | Current-code location map (server.rs:65-70, services/{user,token}.rs, middleware/auth.rs); reusable `authorization.rs:73-99` pattern; open design question on `ValidateCredentials.tenant_id` scoping; D-06 lockout-helper location guidance; test harness extension plan (`grpc_auth_test.rs`) |
| SECFIX-02 | Tenant guard on `grant_to_role_with_scopes` (SEC-058) | Confirmed unguarded at `permission.rs:428-459` (no drift from REQUIREMENTS.md); exact SurrealQL fix mirroring `grant_to_role:314-352`; scope-ownership validation against `scope` table schema; existing test to repoint (`req14_tenant_isolation_test.rs:160-199`) |
| SECFIX-03 | Webhook encryption key fail-closed + encrypt-at-rest (SEC-059, SEC-031) | Corrected location (`main.rs:405-406`, not 389-390 as REQUIREMENTS.md states); PKI `Option<[u8;32]>` template (`main.rs:378-380`); already-implemented-but-unwired `encrypt_webhook_secret`; critical `web::Data` type-collision landmine + recommended `WebhookDeliveryService.encrypt_secret()` avoidance pattern; `UpdateWebhook` DTO gap for secret rotation |
| SECFIX-04 | SAML signature↔assertion binding (XSW) + Destination/InResponseTo (SEC-005) | Full `handle_saml_response` flow read; root-cause identification (verify_signed_xml returns no reference binding at pinned samael 0.0.19); required `samael` version bump to 0.0.20/0.0.21 with exact migration steps; both Destination call sites verified (869, 1524 — exact REQUIREMENTS.md match); public-path schema gap (no acs_url anywhere) flagged as a scope-boundary decision |
| SECFIX-05 | Logout revokes caller's session (SEC-015) | Confirmed `SessionValidator`/session-liveness re-check already implemented and wired; root cause isolated to the handler's redundant required body; exact minimal fix; existing test to update (`auth_test.rs:521-570`) |
| SECFIX-06 | Reset/resend flows carry tenant_id, stay enumeration-safe (SEC-044) | Confirmed backend DTOs already correct except missing update-DTO/frontend threading; `verifyEmail`'s already-correct call as the literal template; login's slug-resolution pattern (`auth.rs:252-285`) as the reusable mechanism; enumeration-safety regression pitfall; contract test location (`auth-contract.spec.ts`) |
</phase_requirements>

## Summary

The codebase has drifted since the review commit `ea85872`, but **not in ways that closed any of the six findings** — every SECFIX-01..06 defect is still present, at the locations below (mostly matching REQUIREMENTS.md's cited lines; two corrections are called out explicitly). This research is primarily a **current-code location map** plus the exact mechanics each fix requires, because the domain (Rust security hardening) needs no new framework research — it needs precise diffs against real code.

The most consequential finding from this session: **SECFIX-04 (SAML XSW) cannot be correctly closed with the currently pinned `samael = "0.0.19"`.** The crate's XSW-safe primitive (`CryptoProvider::reduce_xml_to_signed` with `ReduceMode::ValidateAndMarkNoAncestors`) was added in `samael 0.0.20` and is not present in 0.0.19. Closing SECFIX-04 correctly (binding the verified signature to the assertion actually consumed, not hand-rolling reference-ID matching) requires bumping to `samael 0.0.20` or `0.0.21` (both confirmed published on crates.io) and migrating the one call site in `saml.rs:591` to the new trait-based API (breaking change: `&[u8]` → `&CertificateDer`, free function → trait method via the `Crypto` type alias).

The second most consequential finding: **SECFIX-05's hard part is already done.** The `SessionValidator` trait (`axiam-api-rest/src/extractors/auth.rs:36-56`) already re-checks session liveness in SurrealDB on every authenticated request, and `AuthService::logout` already does a hard `DELETE` on the session row. The ONLY defect is that the `logout` handler requires a JSON body (`LogoutRequest { session_id: Uuid }`) that the frontend doesn't send correctly, causing a 400 before the (already-correct) revocation logic ever runs. This is a much smaller fix than the ROADMAP wording suggests — do not over-build session plumbing that already exists.

Third: **a real landmine for SECFIX-03.** `axiam-server/src/main.rs:681` already registers `web::Data::new(config.email_encryption_key)` where `email_encryption_key: Option<[u8; 32]>`. Actix's `web::Data<T>` is keyed by type, not by variable name — registering a second, distinct `Option<[u8; 32]>` (the webhook key) via `web::Data::new(...)` would **silently overwrite or collide with** the email key's app_data slot. The webhook key must NOT be registered as a bare `web::Data<Option<[u8;32]>>`; either wrap it in a distinct newtype or (preferred) expose an `encrypt_secret`/`is_configured` method on the already-distinctly-typed `WebhookDeliveryService<W>` (already registered at `main.rs:688`) and have the `create`/`update` handlers take that as an extra parameter.

**Primary recommendation:** Fix each SECFIX at the exact locations below; for SECFIX-04, budget for a `samael` dependency bump (0.0.19 → 0.0.21) as part of "what the fix strictly requires," not scope creep — there is no correct fix at 0.0.19.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| gRPC service authentication (SECFIX-01) | API / Backend (gRPC mesh) | — | Tonic interceptor is a transport-layer concern owned entirely by `axiam-api-grpc` |
| Tenant-scoped grant mutation (SECFIX-02) | Database / Storage (SurrealQL guard) | API / Backend (handler) | The authoritative guard is a DB-layer `LET…IF…THROW` predicate; REST handler only routes |
| Webhook secret encryption (SECFIX-03) | API / Backend (encrypt-on-write) | Database / Storage (ciphertext column) | Encryption/decryption happens in Rust before/after the DB boundary; DB only stores opaque ciphertext |
| SAML signature/assertion binding (SECFIX-04) | API / Backend (federation library) | — | `axiam-federation` is a pure library crate; REST handlers only pass through IdP-supplied bytes |
| Logout/session revocation (SECFIX-05) | API / Backend (REST handler + DB) | Browser/Client (cookie clear + local state clear) | Server owns the source of truth (session row); browser only reflects it |
| Password-reset/verify tenant threading (SECFIX-06) | Browser/Client (SPA routing + form state) | API / Backend (DTO + slug resolution) | The missing piece is almost entirely in the SPA (unthreaded `tenant_id`); backend DTOs are already correct except where noted |

## Standard Stack

This phase introduces **no new libraries or frameworks**. Every fix uses tooling already established in the codebase:

### Core (already in use, unchanged)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `tonic` | workspace-pinned (0.14) | gRPC transport + `Interceptor` trait | Already the project's gRPC framework; `AuthInterceptor` is an existing, working implementation |
| `actix-web` | workspace-pinned | REST transport, `web::Data` DI, `FromRequest` extractors | Already the project's REST framework |
| `axiam_auth::crypto` (AES-256-GCM via `aes-gcm`) | internal crate, already vendored | Webhook secret encrypt/decrypt | Already used for federation secrets, MFA secrets, PKI private keys — one hashing/crypto path per CLAUDE.md |
| `samael` | **bump 0.0.19 → 0.0.20 or 0.0.21** | SAML XML parsing + XML-DSig verification | Only viable Rust SAML2 + xmlsec1-binding crate already integrated; the version bump is required to reach the XSW-safe `reduce_xml_to_signed` primitive (see SECFIX-04) |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `hex` | workspace-pinned | Decoding `AXIAM__*_KEY` env vars | Already used by `load_key_from_env` — no change needed |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `samael::crypto::reduce_xml_to_signed` (0.0.20+) | Hand-rolled reference-ID matching against the parsed DOM | Rejected — re-implementing XML-DSig reference resolution is exactly the class of mistake that causes XSW bugs; see Don't Hand-Roll |

**Installation:**
```bash
# Cargo.toml (workspace root) — single line change
# samael = { version = "0.0.19", features = ["xmlsec"] }
# becomes:
# samael = { version = "0.0.21", features = ["xmlsec"] }
cargo update -p samael --precise 0.0.21
cargo check -p axiam-federation --features saml
```

**Version verification [VERIFIED: crates.io sparse index]:** confirmed via `curl https://index.crates.io/sa/ma/samael`, published versions through `0.0.21` exist; tarballs for `0.0.19`/`0.0.20`/`0.0.21` downloaded and inspected directly (see Package Legitimacy Audit and SECFIX-04 sections for the exact API diff this bump unlocks).

## Package Legitimacy Audit

No **new** external packages are introduced by this phase. One existing, already-vetted dependency requires a **version bump**:

| Package | Registry | Age | Current pin | Target | Verdict | Disposition |
|---------|----------|-----|--------------|--------|---------|-------------|
| `samael` | crates.io | in use since Phase 4 (federation) | `0.0.19` | `0.0.21` (latest) or `0.0.20` (minimum for the needed API) | OK | Approved — version bump only, not a new dependency |

**Verification performed [VERIFIED: crates.io sparse index]:** `curl https://index.crates.io/sa/ma/samael` confirms published versions `0.0.1`..`0.0.21` exist, with `0.0.20`/`0.0.21` as the two most recent. Source tarballs for `0.0.19`, `0.0.20`, and `0.0.21` were downloaded directly from `static.crates.io` and inspected: `0.0.19`'s `src/crypto.rs` (single file, free functions, `&[u8]` cert param) predates the `src/crypto/{mod,xmlsec,...}.rs` restructuring that ships `ReduceMode`/`CryptoProvider::reduce_xml_to_signed` starting at `0.0.20`.

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────────┐
                         │   External callers          │
                         │ (gRPC mesh peer / IdP POST / │
                         │  browser SPA)                │
                         └───────────┬─────────────────┘
                                     │
             ┌───────────────────────┼────────────────────────┐
             │ gRPC (SECFIX-01)      │ REST (SECFIX-02/03/05/06)│ SAML POST (SECFIX-04)
             ▼                       ▼                          ▼
   ┌──────────────────┐   ┌────────────────────┐     ┌───────────────────────┐
   │ tonic Server      │   │ Actix-Web App       │     │ axiam-federation       │
   │ server.rs:65-70   │   │ (RequirePermission, │     │ SamlFederationService  │
   │  authz_svc: HAS   │   │  AuthenticatedUser) │     │  .handle_saml_response │
   │  interceptor      │   │                      │     │   1. verify_signature  │
   │  user_svc: NO     │───┼─▶ handlers/*.rs ────┼────▶│   2. parse assertion   │
   │  token_svc: NO    │   │  (permissions.rs,    │     │      from RAW xml      │
   │  interceptor      │   │   webhooks.rs,       │     │      (NOT bound to the │
   │  (SEC-003 gap)    │   │   auth.rs,           │     │      verified sig ref) │
   └──────────┬────────┘   │   password_reset.rs, │     │   3. Conditions/replay │
              │            │   email_verification │     └───────────┬───────────┘
              ▼            │   .rs)               │                 │
   ┌──────────────────┐   └──────────┬───────────┘                 ▼
   │ services/{user,   │              │                   provision_or_link_user
   │  token}.rs        │              ▼
   │ (trusts body       │   ┌────────────────────┐
   │  tenant_id/user_id │   │ axiam-db repos      │
   │  — no interceptor  │   │  permission.rs:     │
   │  to derive from)   │   │   grant_to_role_     │
   └────────────────────┘   │   with_scopes: NO    │
                             │   tenant guard        │
                             │  webhook.rs: secret   │
                             │   stored PLAINTEXT     │
                             └────────────────────┘
```

A reader can trace: an unauthenticated gRPC caller hits `UserServiceServer`/`TokenServiceServer` with zero interceptor (SECFIX-01); an authenticated REST caller with `permissions:grant` in tenant A reaches `grant_to_role_with_scopes` with no tenant predicate (SECFIX-02); a webhook `POST`/`PUT` reaches the DB with the secret un-encrypted (SECFIX-03); a SAML POST is parsed and its (unbound) `response.assertion` field is trusted downstream of signature verification (SECFIX-04).

### Recommended Project Structure (no new directories — fixes are localized edits)

```
crates/axiam-api-grpc/src/
├── server.rs                 # wrap user_svc/token_svc with AuthInterceptor (or shared Layer)
├── middleware/auth.rs         # AuthInterceptor — unchanged, just applied more broadly
└── services/{user,token}.rs   # derive tenant_id/user_id from ValidatedClaims, cross-validate body

crates/axiam-db/src/repository/
└── permission.rs              # grant_to_role_with_scopes:428-459 — add LET/IF/THROW guard

crates/axiam-server/src/main.rs        # webhook_enc_key: Option<[u8;32]>, no unwrap_or fallback
crates/axiam-api-rest/src/webhook.rs   # WebhookDeliveryService.encryption_key -> Option<[u8;32]>
crates/axiam-api-rest/src/handlers/webhooks.rs  # call encrypt_webhook_secret on create+update

crates/axiam-federation/src/saml.rs    # bind reduce_xml_to_signed output to consumed assertion
crates/axiam-api-rest/src/handlers/federation.rs  # pass real acs_url; add InResponseTo requirement

crates/axiam-api-rest/src/handlers/auth.rs  # logout: drop body param, use user.session_id
frontend/src/components/layout/Topbar.tsx    # handleLogout: stop sending {}

crates/axiam-api-rest/src/handlers/{password_reset,email_verification}.rs  # accept slug OR id
frontend/src/services/auth.ts   # thread tenant_id/org_slug through reset/resend calls
frontend/src/pages/auth/{ForgotPasswordPage,ResetPasswordPage,VerifyEmailPage}.tsx
frontend/src/router.tsx         # add slug path segments/query params to the 3 public routes
```

---

## SECFIX-01 — gRPC UserService & TokenService Authentication

### Current-code location map (verified against live `main`)

| Item | File:Lines | Current state |
|------|-----------|----------------|
| `AuthInterceptor` (reusable) | `crates/axiam-api-grpc/src/middleware/auth.rs:1-48` | Complete, working. Extracts `authorization` metadata, strips `Bearer `, calls `validate_access_token`, inserts `ValidatedClaims` into request extensions. **Unchanged from CONTEXT.md's description — no drift.** |
| Server wiring — the gap | `crates/axiam-api-grpc/src/server.rs:65-70` | `authz_svc` (line 65-68) is built with `AuthorizationServiceServer::with_interceptor(..., AuthInterceptor::new(...))`. `user_svc` (line 69) and `token_svc` (line 70) are built with plain `::new(...)` — **zero interceptor, zero auth, confirmed live.** |
| `AuthorizationService` reference pattern | `crates/axiam-api-grpc/src/services/authorization.rs:69-116` (check_access), `118-169` (batch_check_access) | Confirmed exact pattern: reads `ValidatedClaims` from `request.extensions()`, parses `claims.0.tenant_id`/`claims.0.sub`, then cross-validates body `tenant_id`/`subject_id` against claims, returning `Status::permission_denied` on mismatch. **This is the literal template to replicate — no drift from CONTEXT.md.** |
| `UserService::get_user` | `crates/axiam-api-grpc/src/services/user.rs:57-80` | Trusts `req.tenant_id`/`req.user_id` from the request body verbatim — no claims check at all (can't, since no interceptor runs). Proto: `GetUserRequest { tenant_id, user_id }` — both fields present, so the `authorization.rs` cross-validation pattern applies directly. |
| `UserService::validate_credentials` | `crates/axiam-api-grpc/src/services/user.rs:82-143` | Proto: `ValidateCredentialsRequest { tenant_id, username_or_email, password }`. Already has lockout/status/Argon2 checks (lines 115-133) — solid. `tenant_id` is trusted from the body. |
| `TokenService::validate_token` / `introspect_token` | `crates/axiam-api-grpc/src/services/token.rs:23-90` | Proto: both requests carry **only** `access_token` — no `tenant_id`/`user_id` fields at all (`token.proto:20-38`). There is nothing to cross-validate here; the fix is auth-gating only (caller must present a valid bearer token to call the service at all), not body/claims cross-validation. |

### Proto shapes (verified)

```protobuf
// user.proto
message GetUserRequest { string tenant_id = 1; string user_id = 2; }
message ValidateCredentialsRequest { string tenant_id = 1; string username_or_email = 2; string password = 3; }

// token.proto
message ValidateTokenRequest { string access_token = 1; }
message IntrospectTokenRequest { string access_token = 1; }
```

### Open design question the planner must resolve

`ValidateCredentials` has a `tenant_id` body field. Two valid interpretations:
1. **Cross-validate** it against the caller's own claims (mirror `GetUser`/`authorization.rs` exactly) — an authenticated mesh peer can only credential-check within its own tenant.
2. **Trust it as-is** (only require *some* valid bearer token) — a mesh peer (e.g. an API gateway) might legitimately validate credentials on behalf of many tenants it doesn't itself belong to.

ROADMAP SC#1 only explicitly requires cross-tenant rejection for `GetUser` ("cross-tenant GetUser (tenant-A caller, tenant-B target) returns permission-denied"); it says nothing about `ValidateCredentials` tenant scoping. CONTEXT.md's discretion text says "reject any mismatched body field, exactly as AuthorizationService already does" for **all three** RPCs, which reads as intent to cross-validate `ValidateCredentials.tenant_id` too. **Recommendation: cross-validate `ValidateCredentials.tenant_id` against claims as well (interpretation 1)** — it's the conservative, fail-closed choice and matches the literal CONTEXT.md instruction; document this as a locked decision in the PLAN so it isn't re-litigated at execute time.

### D-06 — shared lockout helper (SEC-026b)

**Location of the REST lockout logic to factor out:** search confirms failed-login/lockout accrual lives in the REST login path (SEC-032 atomic failed-login increment, referenced in STATE.md as landed in Phase 11 `11-03-PLAN.md`). `UserService::validate_credentials` (grpc) currently does NOT increment any failed-attempt counter on a wrong password — it only *checks* `user.locked_until` (line 116-120) but never *writes* a failure on invalid credentials. This is the literal "unmetered credential-check path" SEC-026b refers to. The planner must locate the exact REST failed-login increment call (in `axiam-auth`'s login service, called from `handlers/auth.rs` login handler) and extract it into a helper both paths call. **Do not duplicate the increment logic — it must be the single source of truth per CONTEXT.md's Integration Points note.**

### Test harness (existing, to extend)

`crates/axiam-api-grpc/tests/grpc_auth_test.rs:172-195` — `start_test_server()` currently only registers `AuthorizationServiceServer::with_interceptor(...)`. It must be extended (or a sibling harness added) to also register `UserServiceServer`/`TokenServiceServer` wrapped identically, plus corresponding `bare_client`-style helpers for `UserServiceClient`/`TokenServiceClient` (generated stubs already exist since the services are wired, just unauthenticated). `grpc_authz_test.rs` (21KB) is the sibling file for authz-specific cases; new User/Token tests can live in `grpc_auth_test.rs` alongside the existing `grpc_rejects_call_without_bearer_token` pattern (lines 212-237) which is the literal template for the new reject-without-token tests.

---

## SECFIX-02 — Tenant Guard on Live REST Grant Path

### Current-code location map

| Item | File:Lines | Current state |
|------|-----------|----------------|
| **The gap** | `crates/axiam-db/src/repository/permission.rs:428-459` | `grant_to_role_with_scopes` — **matches REQUIREMENTS.md's cited lines exactly, no drift.** Signature takes `_tenant_id: Uuid` (underscore-prefixed — literally unused). Neither the empty-scope branch (438-444) nor the scoped branch (445-456) runs any tenant predicate. Both branches `RELATE` directly. |
| Guarded sibling (the template) | `crates/axiam-db/src/repository/permission.rs:314-352` | `grant_to_role` — the exact `LET $ro = (...); LET $pe = (...); IF array::len($ro) = 0 OR array::len($pe) = 0 { THROW 'cross-tenant edge denied'; }` pattern (CQ-B07 remediation) to replicate. |
| REST handler | `crates/axiam-api-rest/src/handlers/permissions.rs:196-227` | `POST /api/v1/roles/{role_id}/permissions` → fn `grant_to_role` (handler name, NOT the repo method name — don't conflate) → calls `repo.grant_to_role_with_scopes(user.tenant_id, path.into_inner(), req.permission_id, req.scope_ids)`. `user.tenant_id` IS available and passed — the bug is entirely in the repo method ignoring it. |
| Request DTO | `crates/axiam-api-rest/src/handlers/permissions.rs:33-38` | `GrantPermissionRequest { permission_id: Uuid, #[serde(default)] scope_ids: Vec<Uuid> }` — no changes needed here. |
| Scope table schema | `crates/axiam-db/src/schema.rs:275-284` | `DEFINE TABLE scope SCHEMAFULL; DEFINE FIELD tenant_id ON TABLE scope TYPE string;` — confirms scopes are tenant-scoped records, so a per-scope tenant check is meaningful. |
| Existing test to repoint | `crates/axiam-db/tests/req14_tenant_isolation_test.rs:160-199` | `permission_grant_cross_tenant_rejected` currently calls `perm_repo.grant_to_role(tenant_a, role_a.id, perm_b.id)` (line 191) — **the already-guarded path**, not the vulnerable one. CONTEXT.md's instruction to repoint this test is exactly correct and this is the file/function to edit. |

### Exact fix shape (SurrealQL)

```sql
-- both branches need the guard; scoped branch additionally validates every scope_id
LET $ro = (SELECT id FROM role:`{role_id}` WHERE tenant_id = $tid);
LET $pe = (SELECT id FROM permission:`{perm_id}` WHERE tenant_id = $tid);
LET $sc = (SELECT id FROM scope WHERE meta::id(id) IN $scope_ids AND tenant_id = $tid);
IF array::len($ro) = 0 OR array::len($pe) = 0 OR array::len($sc) != array::len($scope_ids) {
    THROW 'cross-tenant edge denied';
};
RELATE role:`{role_id}` -> grants -> permission:`{perm_id}` SET scope_ids = $scope_ids;
```

For the empty-scope (wildcard) branch, omit the `$sc` check entirely (mirrors `grant_to_role`'s structure exactly since there are no scope_ids to validate).

**Repository layer has no `ScopeRepository` dependency injected** (`SurrealPermissionRepository<C>` only holds `db: Surreal<C>`) — do the scope-ownership check inline in the SurrealQL above rather than adding a new constructor dependency (which would be a refactor beyond what the fix strictly requires).

**Error mapping:** reuse the exact pattern at `permission.rs:341-348` (`result.check()` → match `"cross-tenant edge denied"` in the error string → `AxiamError::AuthorizationDenied`).

---

## SECFIX-03 — Webhook Secret Fail-Closed Key & Encrypt-at-Rest

### Current-code location map (one correction vs REQUIREMENTS.md)

| Item | File:Lines | Current state |
|------|-----------|----------------|
| **The all-zero fallback** | `crates/axiam-server/src/main.rs:405-406` | **CORRECTION: REQUIREMENTS.md cites `main.rs:389-390`; the actual current line is 406** (`let webhook_enc_key: [u8; 32] = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY").unwrap_or([0u8; 32]);`). Drifted by ~16 lines, same bug, same file. |
| PKI's already-correct sibling pattern (the template) | `crates/axiam-server/src/main.rs:378-380` | `let pki_config = PkiConfig { encryption_key: load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY") };` — `Option<[u8;32]>`, no fallback. **This exact 2-line pattern is what the webhook key assignment must become.** |
| `load_key_from_env` (reusable, no changes needed) | `crates/axiam-server/src/main.rs:52-68` | Already returns `Option<[u8;32]>`, already logs `warn!` on absence (line 64), already panics on malformed-but-present values. Nothing to change here. |
| `WebhookDeliveryService` struct | `crates/axiam-api-rest/src/webhook.rs:83-104` | `encryption_key: [u8; 32]` (non-optional field, line 89) — must become `Option<[u8; 32]>`. Constructor `new(repo, encryption_key: [u8;32])` (line 93) signature changes accordingly. |
| Delivery decrypt call site | `crates/axiam-api-rest/src/webhook.rs:112,136-155` | `deliver()` captures `encryption_key` at line 112, decrypts at 136. With `Option`, must check `None` up front and `tracing::error!` + return (refuse delivery) — mirrors the PKI `Option<[u8;32]>` "fails fast with a clear error" posture, but since `deliver()` is fire-and-forget (`tokio::spawn`, no caller to propagate an error to), "fail fast" here means "log and skip," not `Result`. |
| **`encrypt_webhook_secret` — already exists, zero call sites** | `crates/axiam-api-rest/src/webhook.rs:250-255` | `pub fn encrypt_webhook_secret(key: &[u8;32], plaintext_secret: &str) -> Result<String, AuthError>` calls `aes256gcm_encrypt`. Fully implemented and unit-tested (`webhook_secret_encrypt_decrypt_round_trip`, line 372-385) — **but is called from NOWHERE outside its own test.** This is the function to wire into both handlers. |
| `create` handler — stores plaintext | `crates/axiam-api-rest/src/handlers/webhooks.rs:86-116` | `CreateWebhook { ..., secret: req.secret, ... }` — `req.secret` (raw user input) passed straight through, never encrypted. |
| `update` handler — has no secret field at all | `crates/axiam-api-rest/src/handlers/webhooks.rs:34-40,192-227` | `UpdateWebhookRequest` has NO `secret` field. D-02 ("update DTO exposes secret rotation") requires **adding** `pub secret: Option<String>` to both `UpdateWebhookRequest` (REST DTO) and `UpdateWebhook` (core model, `axiam-core/src/models/webhook.rs:63-69`), then wiring the repo's `update()` (`axiam-db/src/repository/webhook.rs:177-`) to `SET secret = $secret` when present. |
| `Webhook.secret` already redacted | `crates/axiam-core/src/models/webhook.rs:41-44` | `#[serde(skip_serializing)] pub secret: String` — already correct, no change needed. |
| DB write of plaintext secret | `crates/axiam-db/src/repository/webhook.rs:114-152` (create), `177-` (update) | `create()` binds `("secret", input.secret)` verbatim (line 136) — stores whatever the caller passed. No repo-layer change needed IF encryption happens in the REST handler before calling `repo.create`/`repo.update` (repo stays encryption-agnostic, matches how federation secrets are handled elsewhere per STATE.md's Phase 9 decision). |

### The Actix `web::Data` type-collision landmine

`main.rs:681` already does `.app_data(web::Data::new(config.email_encryption_key))` where `email_encryption_key: Option<[u8; 32]>`. **Actix's `web::Data<T>` extractor is looked up by the concrete type `T`, not by variable name.** If the webhook key is also plumbed through as a bare `Option<[u8; 32]>` via a second `.app_data(web::Data::new(webhook_enc_key))` call, one registration will shadow the other — whichever handler asks for `web::Data<Option<[u8;32]>>` will nondeterministically get the wrong key (or Actix may simply keep only the last-registered value; either way it is silently wrong, not a compile error).

**Recommended fix (avoids the collision entirely):** don't register the raw key as app_data for the create/update handlers at all. Instead add a method to the already-distinctly-typed `WebhookDeliveryService<W>` (already registered at `main.rs:688` as `web::Data<WebhookDeliveryService<SurrealWebhookRepository<C>>>>`, a unique generic type — no collision risk):

```rust
// crates/axiam-api-rest/src/webhook.rs — new method on WebhookDeliveryService<W>
impl<W: WebhookRepository + Clone + 'static> WebhookDeliveryService<W> {
    /// Encrypt a webhook secret for storage. Returns an error (not a panic,
    /// not a silent no-op) when no encryption key is configured (D-01).
    pub fn encrypt_secret(&self, plaintext: &str) -> Result<String, WebhookError> {
        let key = self.encryption_key.ok_or(WebhookError::EncryptionKeyMissing)?;
        encrypt_webhook_secret(&key, plaintext)
            .map_err(|e| WebhookError::SecretDecrypt(e.to_string())) // or a new variant
    }
}
```

Then `create`/`update` handlers add `webhook_delivery: web::Data<WebhookDeliveryService<SurrealWebhookRepository<C>>>` as a parameter (the same instance already registered, no new app_data needed) and call `webhook_delivery.encrypt_secret(&req.secret)?`, mapping the error to a 503-style "webhook subsystem unavailable" `AxiamApiError` — this is D-01's "registration ... refused (explicit error + warn!) until a key is present" made concrete.

### Package/version note

No new crates needed — `aes256gcm_encrypt`/`aes256gcm_decrypt` already live in `axiam-auth::crypto` and are already imported in `webhook.rs:9`.

---

## SECFIX-04 — SAML Signature-to-Assertion Binding (XSW)

This is the most involved fix in the phase — it requires a dependency version bump, not just a code edit.

### Current-code location map

| Item | File:Lines | Current state |
|------|-----------|----------------|
| `handle_saml_response` | `crates/axiam-federation/src/saml.rs:332-519` | Full flow read end-to-end. Signature verify (378) → InResponseTo check (383-401, skipped entirely if `expected_request_id` is `None`) → Destination check (403-421, skipped if `expected_destination` is `None`) → status (424-433) → **assertion extracted from the raw, independently-parsed `response.assertion`** (436-438) → Conditions (440-479) → replay insert (481-496) → claims extraction (499). |
| **The XSW gap itself** | `crates/axiam-federation/src/saml.rs:378,436` | `self.verify_signature(xml.as_bytes(), &config)?` (378) returns `Result<(), FederationError>` — **it does not return which element/reference was verified.** `response.assertion.as_ref()` (436) is read from the same, already-parsed `samael::schema::Response` struct — there is no code path that binds "the assertion the signature covered" to "the assertion `handle_saml_response` consumes." This is the literal XSW hole: an attacker can wrap a legitimate signed assertion elsewhere in the document and inject an unsigned sibling that `response.assertion` picks up instead (or vice versa, depending on how the parser resolves the field), and `verify_signature` still returns `Ok(())` because *a* valid signature exists *somewhere*. |
| `verify_signature` | `crates/axiam-federation/src/saml.rs:579-593` | Calls `samael::crypto::verify_signed_xml(xml_bytes, &der, Some("ID"))`. At the **pinned `samael = "0.0.19"`**, this free function's signature is `fn verify_signed_xml<Bytes: AsRef<[u8]>>(xml: Bytes, x509_cert_der: &[u8], id_attribute: Option<&str>) -> Result<(), Error>` [VERIFIED: samael 0.0.19 source, `src/crypto.rs:90-109`, downloaded from static.crates.io] — confirms it truly cannot report which reference/ID was signed. There is no way to close this gap correctly by only changing call-site code at 0.0.19. |
| Destination call site 1 (authenticated ACS) | `crates/axiam-api-rest/src/handlers/federation.rs:862-870` | `saml_acs` handler — `handle_saml_response(..., None, None)` (line 868-869: "no request ID available"/"no expected destination available"). **Matches REQUIREMENTS.md's cited line 869 exactly, no drift.** The handler's own `SamlAcsRequest` DTO (line 745-752) has **no `acs_url` field**, unlike the sibling `SamlAuthnRequestRequest` (line 717-725) which does. |
| Destination call site 2 (public/unauthenticated ACS) | `crates/axiam-api-rest/src/handlers/federation.rs:1514-1525` | `saml_acs_public` handler — `handle_saml_response(..., Some(login_state.request_id.as_str()), None)` (line 1521,1524). **Matches REQUIREMENTS.md's cited line 1524 exactly.** InResponseTo is already correctly threaded here (via `FederationLoginState.request_id`); only Destination is still `None`. |
| Outgoing AuthnRequest — public flow has no ACS URL at all | `crates/axiam-api-rest/src/handlers/federation.rs:1423` | `build_authn_request(tenant_id, b.federation_config_id, "", Some(state.clone()))` — the SP's own outgoing AuthnRequest is built with an **empty-string ACS URL**. There is no canonical ACS URL configured anywhere for the public flow (confirmed: no `base_url`/`public_url` config exists in the codebase outside one test file). This means fully closing Destination validation for the *public* path requires introducing a real ACS URL somewhere, not just flipping `None` to `Some`. |
| `FederationLoginState` — no `acs_url` field | `crates/axiam-core/src/repository.rs:799-814` | Schemafull table (`axiam-db/src/schema.rs:435-444`, migration v18 is the precedent at `schema.rs:1039-1043` for exactly this kind of additive field). Adding `acs_url: String` here is the minimal viable way to thread a real Destination through the public flow's round trip. |
| InResponseTo requirement scope | ROADMAP SC#4 + REQUIREMENTS.md SECFIX-04 AC | "Authenticated ACS path rejects unsolicited responses (InResponseTo required)" — scoped to the **authenticated** path (`saml_acs`, line 839) only; the public path already passes a real `expected_request_id`. The authenticated (account-linking) flow has **no stored server-side state at all** — `build_authn_request`'s returned `request_id` (line 313-319, `SamlAuthnRequestResult.request_id`) is discarded and never returned to the caller (`SamlAuthnRequestResponse`, line 728-740, has no `request_id` field) and never persisted. Genuinely closing "require InResponseTo" for this path without a bigger refactor means: **require `response.in_response_to` to be present** (reject `None` = unsolicited), without comparing to a specific stored value — decouple "must be present" from "must equal X" in `handle_saml_response`'s logic. |

### The correct fix: use `samael`'s XSW-safe reduction primitive (requires version bump)

[VERIFIED: samael 0.0.20/0.0.21 source, `src/crypto/mod.rs`, downloaded from static.crates.io] `samael` ships exactly the primitive needed, starting at 0.0.20:

```rust
pub enum ReduceMode {
    PreDigest,
    ValidateAndMark,               // legacy, NOT recommended (unsigned ancestors can survive)
    ValidateAndMarkNoAncestors,    // DEFAULT — rooted doc containing ONLY verified content
}

pub trait CryptoProvider {
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(xml: Bytes, x509_cert_der: &CertificateDer, id_attribute: Option<&str>) -> Result<(), CryptoError>;
    fn reduce_xml_to_signed(xml_str: &str, certs_der: &[CertificateDer], reduce_mode: ReduceMode) -> Result<String, CryptoError>;
    // ...
}
pub type Crypto = XmlSec; // when feature = "xmlsec" (already enabled)
```

`reduce_xml_to_signed` with the default `ValidateAndMarkNoAncestors` mode "returns a rooted XML document containing only xmlsec-verified content" — i.e., it strips everything that was NOT covered by a valid signature, including XSW-wrapped duplicate/sibling assertions. The fix is: **parse the assertion from the *reduced* document, not the raw one.**

```rust
// New call site pattern (samael >= 0.0.20), replacing saml.rs:591's free-function call:
use samael::crypto::{CertificateDer, Crypto, CryptoProvider, ReduceMode};

fn verify_and_extract_trusted_xml(
    xml: &str,
    cert_der: Vec<u8>, // from crate::cert::pem_cert_to_der (unchanged return type)
) -> Result<String, FederationError> {
    let cert = CertificateDer::from(cert_der);
    Crypto::reduce_xml_to_signed(xml, &[cert], ReduceMode::default())
        .map_err(|e| FederationError::SamlSignatureInvalid(e.to_string()))
}
```

Then re-parse `samael::schema::Response` (or extract just the `Assertion`) from **this reduced string**, not from the original `xml` variable — that is what "binds the verified signature to the assertion actually consumed" means concretely. This replaces both the `verify_signature` call (line 378) and the `response.assertion` read (line 436) with a single trusted-content extraction step. `verify_signature`'s existing `ConfigIncomplete`/cert-missing behavior (lines 583-587) is preserved unchanged — only the verification mechanism inside changes.

**Cargo.toml change:** `samael = { version = "0.0.19", features = ["xmlsec"] }` → `samael = { version = "0.0.21", features = ["xmlsec"] }` (root workspace `Cargo.toml:105`).

**Breaking-change checklist for the one call site (`saml.rs:591`):**
- `verify_signed_xml`/new reduce call now takes `&CertificateDer` instead of `&[u8]` — wrap with `CertificateDer::from(der_vec)`.
- The crate's error type is `samael::crypto::CryptoError` in 0.0.20+ (was a plain `Error` in 0.0.19) — update the `.map_err(|e| FederationError::SamlSignatureInvalid(e.to_string()))` type inference (should still compile unchanged since it only calls `.to_string()`, but confirm no explicit `samael::crypto::Error` type annotation exists elsewhere — none found in a repo-wide grep).
- Import path changes from a free function (`samael::crypto::verify_signed_xml`) to a trait method reached via the `Crypto` type alias — must `use samael::crypto::CryptoProvider;` to bring the trait method into scope, plus `use samael::crypto::{Crypto, ReduceMode, CertificateDer};`.

### Recommended scope boundary for the two Destination call sites

- **Authenticated path (`federation.rs:868-869`):** minimal fix — the DTO already has `req.acs_url` (line 762) sitting **unused**. Change `None` → `Some(&req.acs_url)` (after validating non-empty, mirroring the existing `validate_webhook_url`-style guard already used for the sibling `build_authn_request` handler at line 797-798).
- **Public path (`federation.rs:1521-1524`):** requires the `FederationLoginState.acs_url` schema addition described above, threaded from a new `acs_url` field on `SamlLoginRequest` (`federation.rs:996-1004`, currently missing one) through to `build_authn_request` (replacing the `""` literal at line 1423) and back out at consume time. **This is schema + DTO work, not a one-line call-site fix — budget accordingly.** If the planner judges this too large for "no refactors beyond what a fix strictly requires," it is acceptable to close ONLY the authenticated-path Destination check in Phase 23 and record the public-path Destination gap explicitly in the PLAN's residual/deferred notes (CONTEXT.md's own Deferred section already anticipates a SAML residual: "SAML Recipient/SubjectConfirmationData full validation beyond the XSW-binding + Destination/InResponseTo minimum — remainder tracked under SEC-005 residual if not fully closed here"). **Recommendation: attempt both; if the public-path schema work threatens scope, defer only that half with an explicit note, since REQUIREMENTS.md's AC literally names both line numbers.**

### Test locations

`crates/axiam-federation/src/saml.rs:1064-1157` — existing unit tests including `verify_accepts_well_signed_response`, `verify_rejects_tampered_body`, `verify_rejects_missing_signature`, `verify_rejects_when_no_cert_configured`, and `acs_rejects_replayed_assertion_via_replay_repo` (async, using a mock `insert_assertion`). New XSW negative test (wrapped/duplicated assertion) belongs alongside these in the same `#[cfg(test)] mod tests` block, or in a new `crates/axiam-federation/tests/` integration test if constructing a full wrapped-assertion XML fixture is easier outside the unit-test module. Look for any existing SAML e2e test file under `axiam-server/tests/` (none found matching "saml" in this session's grep — the SAML e2e coverage referenced in CONTEXT.md's "federation e2e (oidc/saml/clock-skew)" line may need to be located precisely by the planner via `find crates/axiam-server/tests -iname "*saml*"`).

---

## SECFIX-05 — Logout Revokes the Caller's Session

### Current-code location map

| Item | File:Lines | Current state |
|------|-----------|----------------|
| `logout` handler | `crates/axiam-api-rest/src/handlers/auth.rs:348-367` | Takes `body: web::Json<LogoutRequest>` (**required**, no `Option`). Compares `body.session_id != user.session_id` (line 356) and returns `AuthorizationDenied` on mismatch (SEC-051 IDOR guard) — but `user.session_id` (from `AuthenticatedUser`, already the JWT `jti`) makes the body parameter **entirely redundant**. Cookies are already cleared correctly (lines 362-366: `clear_access_cookie()`, `clear_refresh_cookie()`, `clear_csrf_cookie()`). |
| `LogoutRequest` DTO | `crates/axiam-api-rest/src/handlers/auth.rs:104-106` | `pub struct LogoutRequest { pub session_id: Uuid }` — to be deleted once the handler no longer needs it (confirm no other call sites use this struct before removing). |
| `AuthenticatedUser.session_id` (already == jti) | `crates/axiam-api-rest/src/extractors/auth.rs:76-85` | Doc comment confirms: "equals the JWT `jti` claim which is set to `session.id` for user-facing tokens (D-15)." Everything `logout` needs is already on `user` — no body required. |
| `AuthService::logout` (already correct) | `crates/axiam-auth/src/service.rs:580-582` | `pub async fn logout(&self, tenant_id: Uuid, session_id: Uuid) -> AxiamResult<()> { self.session_repo.invalidate(tenant_id, session_id).await }` — no changes needed. |
| Session invalidation (already a hard delete) | `crates/axiam-db/src/repository/session.rs:186-198` | `invalidate()` does `DELETE type::record('session', $id) WHERE tenant_id = $tenant_id` — a real delete, not a soft flag. |
| **Why replay-after-logout already works (once logout itself stops 400ing)** | `crates/axiam-api-rest/src/extractors/auth.rs:25-60` | `SessionValidator` trait + `impl<C: Connection> SessionValidator for SurrealSessionRepository<C>` — `is_session_active()` does a real per-request DB lookup (`get_by_id`) and returns `false` if the session row is gone or expired. **This is wired into `AuthenticatedUser::from_request` and registered as app_data at `crates/axiam-server/src/main.rs:342`** (`let session_validator: Arc<dyn axiam_api_rest::SessionValidator> = ...`). Once the session row is deleted, the very next request presenting the old access cookie is rejected by this check — no additional plumbing needed for "replaying old cookies is unauthenticated." |
| Frontend bug | `frontend/src/components/layout/Topbar.tsx:89-98` | `handleLogout` does `await api.post("/api/v1/auth/logout", {})` — sends an empty object where the backend (currently) requires `{session_id: Uuid}`, so this 400s today. Errors are swallowed (`catch {}`) so the user doesn't see the 400, but the server-side session is **never actually revoked** — this is the real defect: logout is currently a client-side-only no-op with respect to session state. |
| Existing test to update | `crates/axiam-api-rest/tests/auth_test.rs:521-570+` (`logout_clears_cookies`) | Currently sends `.set_json(serde_json::json!({ "session_id": session_id }))` (line 555) — update to send no body once the handler drops the parameter. This is also the right home for the new negative test (replay old access cookie post-logout → 401). |

### Fix shape

```rust
// handlers/auth.rs — drop the body parameter entirely
pub async fn logout<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<AuthSvc<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    svc.logout(user.tenant_id, user.session_id).await?;
    Ok(HttpResponse::NoContent()
        .cookie(clear_access_cookie())
        .cookie(clear_refresh_cookie())
        .cookie(clear_csrf_cookie())
        .finish())
}
```

```typescript
// Topbar.tsx
await api.post("/api/v1/auth/logout"); // no body
```

**Scope note:** this is intentionally a small fix. The revocation and cookie-clearing machinery is already correct; do not add new session-tracking infrastructure.

---

## SECFIX-06 — Password-Reset / Resend Flows Threaded with tenant_id

### Current-code location map

| Item | File:Lines | Current state |
|------|-----------|----------------|
| `RequestResetBody` (backend, already correct) | `crates/axiam-api-rest/src/handlers/password_reset.rs:30-33` | `{ tenant_id: Uuid, email: String }` — already requires both. |
| `ConfirmResetBody` (backend, already correct) | `crates/axiam-api-rest/src/handlers/password_reset.rs:37-41` | `{ tenant_id: Uuid, token: String, new_password: String }` — `tenant_id` is genuinely used (line 188: resolves tenant for org password-policy settings; line 205: scopes the token lookup) — **not removable without a larger refactor.** |
| `VerifyEmailRequest` (backend, already correct) | `crates/axiam-api-rest/src/handlers/email_verification.rs:29-33` | `{ tenant_id: Uuid, token: String }`. |
| `ResendVerificationRequest` (backend, already correct) | `crates/axiam-api-rest/src/handlers/email_verification.rs:36-40` | `{ tenant_id: Uuid, email: String }` — unauthenticated handler (`resend_verification`, line 93-99, no `AuthenticatedUser` param despite a stale frontend doc-comment calling it "authenticated"). |
| **`requestPasswordReset` — missing tenant_id entirely** | `frontend/src/services/auth.ts:39-42` | `requestPasswordReset: (email) => api.post("/api/v1/auth/reset", { email })` — posts `{email}` only. Will 400 against the real backend DTO today. |
| **`confirmPasswordReset` — missing tenant_id entirely** | `frontend/src/services/auth.ts:48-51` | `confirmPasswordReset: (token, new_password) => api.post("/api/v1/auth/reset/confirm", { token, new_password })` — same gap. |
| `verifyEmail` — already fixed as precedent | `frontend/src/services/auth.ts:62-65` | `verifyEmail: (tenantId, token) => api.post(..., { tenant_id: tenantId, token })` — **this one is already correct** and is the literal template for the other two. Its own doc comment (lines 57-60) explains the constraint precisely. |
| **`resendVerification` — sends NO body at all** | `frontend/src/services/auth.ts:71-74` | `resendVerification: () => api.post("/api/v1/auth/resend-verification")` — zero params, zero body. Backend requires `{tenant_id, email}`. |
| `ForgotPasswordPage` — no tenant concept | `frontend/src/pages/auth/ForgotPasswordPage.tsx:25-41` | Form collects only `email` (line 28); calls `authService.requestPasswordReset(email)`. No tenant slug field, no URL param read at all. |
| `ResetPasswordPage` — reads only `token` | `frontend/src/pages/auth/ResetPasswordPage.tsx:34-36` | `useSearchParams()` → `token = searchParams.get("token")`. No tenant param read. |
| `router.tsx` — flat routes, no slug segments | `frontend/src/router.tsx:45-56` | `/auth/forgot-password`, `/auth/reset-password`, `/auth/verify-email` are all bare paths with no `:orgSlug`/`:tenantSlug` params and no documented query-param convention. |
| Login's "Forgot password?" link — the wiring gap | `frontend/src/pages/LoginPage.tsx:333-338` | `<Link to="/auth/forgot-password">` — does **not** carry `orgTenantData.orgSlug`/`tenantSlug` (already collected in component state at this point in the 2-step login wizard, `LoginPage.tsx:57-93`), even though the slug values are sitting right there in scope. |
| Login's existing slug→id resolution pattern (the template) | `crates/axiam-api-rest/src/handlers/auth.rs:50-61,252-285` | `LoginRequest` has `Option<Uuid>` + `Option<String>` pairs for both org and tenant (`org_id`/`org_slug`, `tenant_id`/`tenant_slug`, lines 50-58). Resolution: `match (b.org_id, b.org_slug.as_deref()) { (Some(id), _) => id, (None, Some(slug)) => org_repo.get_by_slug(...)?.id, (None, None) => return Err(validation_err) }` (lines 252-268), same shape for tenant (269-285). **This is the exact reusable resolution pattern to replicate on the 4 reset/verify DTOs.** Per STATE.md's recorded decision, slug-resolution failures on login map to `AuthenticationFailed (401)` specifically to avoid enumeration — the reset/resend flows have a *different* existing enumeration-safety mechanism (always return `{"sent": true}` / `200` regardless of outcome, D-15) that a failed slug resolution must not bypass. |
| Enumeration-safety mechanism already in place (do not regress) | `crates/axiam-api-rest/src/handlers/password_reset.rs:130-149` | `Ok(None)` (user not found/federated) and `Err(AxiamError::RateLimited)` both fall through to the same `Ok(HttpResponse::Ok().json({"sent": true}))` at line 149 — **a slug-resolution failure must be funneled into this same uniform-response path, not surfaced as a distinct 400/404**, or the enumeration-safety guarantee (D-05) regresses. |
| Reset-email URL construction — not in this repo's Rust source | `axiam-amqp/src/mail_consumer.rs`, DB-seeded `email_template` rows | `template_context` sent to the mail queue currently only carries `{token, expiry_time}` (`password_reset.rs:112-115`, `email_verification.rs` equivalent) — no `tenant_id`. The actual reset-link URL text lives in DB-seeded email templates, not in Rust source (repo-wide grep for "reset-password"/"verify-email" literal strings found no template file). **Adding `tenant_id` (and/or `org_slug`/`tenant_slug`) to `template_context` is the correct, small, code-level fix** so whatever template an operator configures has the value available to interpolate into the link — the template content itself is outside this phase's code surface. |

### Recommended fix shape

1. **Backend:** add optional `org_slug: Option<String>` / `tenant_slug: Option<String>` fields to `RequestResetBody`, `ConfirmResetBody`, `ResendVerificationRequest` (and confirm `VerifyEmailRequest` needs no change — already `tenant_id`-only and already correctly called). Resolve using the exact `(Option<Uuid>, Option<&str>)` match pattern from `auth.rs:252-285`, but route resolution failures into the SAME enumeration-safe response path each handler already uses (do not `?`-propagate a `NotFound` from slug resolution — catch it and fall through to the uniform 200/`{"sent":true}`).
2. **Backend:** add `tenant_id` (the resolved UUID) into each `template_context` so email templates can build a tenant-aware link.
3. **Frontend `auth.ts`:** update `requestPasswordReset`, `confirmPasswordReset`, `resendVerification` to accept and send `tenant_id`/`org_slug`/`tenant_slug` matching the (extended) backend DTOs — mirror `verifyEmail`'s already-correct shape.
4. **Frontend routing:** add slug carriage to the 3 public routes (`router.tsx`) — either path segments (`/auth/forgot-password/:orgSlug/:tenantSlug`) or query params (`?org=...&tenant=...`); query params are less invasive to the router config and match how `ResetPasswordPage` already reads `?token=` via `useSearchParams`.
5. **Frontend `LoginPage.tsx:334`:** thread `orgTenantData.orgSlug`/`tenantSlug` into the "Forgot password?" link's URL, since that data is already in component state at that point in the flow.
6. **Frontend pages:** `ForgotPasswordPage`/`ResetPasswordPage`/`VerifyEmailPage` read the new slug/tenant param(s) from the URL and pass them through to the (updated) `auth.ts` functions. `VerifyEmailPage` may already do something close to this correctly given `verifyEmail(tenantId, token)` already expects a `tenantId` argument — check it for the existing pattern before designing a new one.

### Contract test to update (existing, already scoped for this)

`frontend/e2e/auth-contract.spec.ts:82-207` — `ForgotPasswordPage`/`ResetPasswordPage`/`VerifyEmailPage`/`ProfilePage` (resend) `describe` blocks currently assert **only the request URL path**, never the body content (confirmed via full read of the assertions — every `expect()` in this range checks `capturedUrl`, none check a captured request body). CONTEXT.md's Deferred section defers "running Playwright in CI with body assertions" to CORR-04/Phase 26, but **adding the body assertions themselves is in-scope for SECFIX-06** per REQUIREMENTS.md's literal AC ("Contract test asserts request bodies... and runs in CI (ties to CORR-04)") — Phase 23 should update the assertions; Phase 26 only needs to make CI actually execute Playwright.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| XSW-safe SAML assertion extraction | A custom reference-ID-to-element matcher against the parsed XML tree | `samael::crypto::{Crypto, CryptoProvider, ReduceMode}::reduce_xml_to_signed` (0.0.20+) | XML canonicalization, reference resolution, and multi-signature edge cases are exactly what caused the original XSW class of bugs across the industry (2012 Duo Security research); xmlsec1 (which `samael`'s `xmlsec` feature wraps) is the battle-tested reference implementation |
| Webhook secret encryption | A bespoke AES wrapper | `aes256gcm_encrypt`/`aes256gcm_decrypt` from `axiam_auth::crypto` (already used, already tested) via the existing but unwired `encrypt_webhook_secret` helper | Already exists, already round-trip tested; the only defect is missing call sites, not missing crypto |
| gRPC bearer-token auth | A second interceptor implementation per service | The existing `AuthInterceptor` (`middleware/auth.rs`), applied to all three services (optionally via one shared tower `Layer`) | One chokepoint = one place to audit; duplicated interceptors drift (this exact drift is why SECFIX-01 exists) |
| Tenant-scoped SurrealQL guards | An application-layer "fetch both records, compare tenant_id in Rust" check | The `LET…IF…THROW` in-query pattern (`grant_to_role`) | Keeps the check atomic with the mutation (no TOCTOU window between the read-check and the `RELATE`) |

**Key insight:** every fix in this phase has a working, already-tested sibling pattern elsewhere in the codebase (SECFIX-01 → `authorization.rs`; SECFIX-02 → `grant_to_role`; SECFIX-03 → PKI's `Option<[u8;32]>` + the already-written `encrypt_webhook_secret`; SECFIX-06 → login's slug resolution + `verifyEmail`'s already-correct call). The dominant risk in this phase is under-using these siblings and re-deriving worse versions, not a lack of applicable patterns.

## Common Pitfalls

### Pitfall 1: Actix `web::Data<T>` type collisions on repeated primitive types
**What goes wrong:** Registering two different `Option<[u8;32]>` (or any other bare primitive/newtype-free) values as separate `web::Data::new(...)` calls silently collides — Actix keys app_data by type, not by call site or variable name.
**Why it happens:** `email_encryption_key` (already registered) and a naively-added `webhook_enc_key` are both exactly `Option<[u8; 32]>`.
**How to avoid:** Route webhook-key access through the already-uniquely-typed `WebhookDeliveryService<W>` (see SECFIX-03 section) instead of registering the raw `Option<[u8;32]>` a second time.
**Warning signs:** A handler correctly compiles and correctly extracts `web::Data<Option<[u8;32]>>` but gets the *wrong* key at runtime (email key instead of webhook key or vice versa) — this would NOT fail any test that only exercises one of the two key-consuming paths in isolation, making it a genuinely dangerous silent bug.

### Pitfall 2: Assuming `samael 0.0.19` can be patched in place for SECFIX-04
**What goes wrong:** Attempting to bind the verified signature to the consumed assertion using only `verify_signed_xml`'s `Result<(), Error>` return value (0.0.19) — there is no reference/ID information to bind to.
**Why it happens:** The function signature looks like it should be extendable, but the underlying xmlsec1 binding genuinely does not surface which element was verified at this API version.
**How to avoid:** Bump to `samael >= 0.0.20` and use `reduce_xml_to_signed`.
**Warning signs:** A "fix" that re-parses `response.assertion` from the SAME original XML string after calling `verify_signature` has not actually closed the XSW gap, no matter how the code is refactored around it — the binding must happen at the XML-content level (verified-subset extraction), not at the Rust-struct level.

### Pitfall 3: Treating SECFIX-05 as requiring new session-tracking work
**What goes wrong:** Building new session-invalidation propagation, a token-blocklist, or JWT-side revocation checks, believing the "stateless access token" architecture means logout can't actually revoke anything.
**Why it happens:** Access tokens ARE stateless JWTs (per-request DB check would seem redundant with that architecture) — but `SessionValidator` already does a per-request DB liveness check specifically to close this gap (D-15/REQ-7, already shipped in an earlier phase).
**How to avoid:** Verify `SessionValidator`/`is_session_active` and its `main.rs:342` wiring are intact before designing any new revocation mechanism — the only defect is the handler's now-redundant required request body causing the endpoint to 400 before revocation ever runs.
**Warning signs:** A PLAN.md for SECFIX-05 that proposes JWT blocklisting, token versioning, or similar heavyweight mechanisms is almost certainly solving an already-solved problem.

### Pitfall 4: Regressing enumeration-safety while fixing SECFIX-06
**What goes wrong:** Adding slug resolution to `request_reset`/`confirm_reset`/`resend_verification` such that an invalid/unknown org or tenant slug produces a different HTTP status or timing than a valid one.
**Why it happens:** The natural Rust idiom (`repo.get_by_slug(...)?`) propagates a `NotFound` error that would surface as a distinct 4xx, breaking the existing "always 200/`{sent:true}`" contract (D-15, D-05).
**How to avoid:** Catch slug-resolution failure explicitly and route it into the same code path as "user not found" (`Ok(None)` branch, e.g. `password_reset.rs:130-136`) rather than using `?` to propagate.
**Warning signs:** Any new `match`/`?` in these handlers that can return early with a status code the pre-existing enumeration-safety tests didn't already exercise.

## Code Examples

### SECFIX-01 — cross-tenant `GetUser` guard (mirrors `authorization.rs:73-99`)
```rust
// crates/axiam-api-grpc/src/services/user.rs — get_user, after adding the interceptor to server.rs
async fn get_user(&self, request: Request<GetUserRequest>) -> Result<Response<UserResponse>, Status> {
    let claims = request.extensions().get::<ValidatedClaims>()
        .ok_or_else(|| Status::unauthenticated("missing validated claims"))?
        .clone();
    let claims_tenant_id = parse_uuid(&claims.0.tenant_id, "claims.tenant_id")?;

    let req = request.into_inner();
    let body_tenant_id = parse_uuid(&req.tenant_id, "tenant_id")?;
    if body_tenant_id != claims_tenant_id {
        return Err(Status::permission_denied("tenant_id mismatch: body does not match token claims"));
    }
    // proceed with req.user_id lookup using claims_tenant_id (authoritative), not req.tenant_id
    let user_id = parse_uuid(&req.user_id, "user_id")?;
    let user = self.user_repo.get_by_id(claims_tenant_id, user_id).await.map_err(axiam_err_to_status)?;
    // ... unchanged response construction
}
```

### SECFIX-02 — extended tenant guard (source: `permission.rs:314-352`, generalized)
See the full SurrealQL block in the SECFIX-02 section above.

### SECFIX-03 — fail-closed key assignment (source: the existing PKI pattern, `main.rs:378-380`)
```rust
// main.rs — replaces the unwrap_or([0u8;32]) fallback at line 405-406
// SEC-031/SECFIX-03: fail-closed, no all-zero fallback (mirrors PKI's SEC-012 pattern).
let webhook_enc_key: Option<[u8; 32]> = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY");
let webhook_delivery = axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
```

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `ValidateCredentials.tenant_id` should be cross-validated against caller claims (interpretation 1, not 2) | SECFIX-01 open design question | If the intended mesh topology actually needs a gateway to validate credentials across tenants it doesn't belong to, this fix would break that legitimate use case — confirm with the user/CONTEXT before locking the PLAN |
| A2 | The public SAML flow's Destination-check gap (requiring a schema addition) can be deferred if it threatens scope, per CONTEXT's own residual-tracking precedent | SECFIX-04 | REQUIREMENTS.md's AC literally names both `federation.rs:869` and `:1524` as in-scope; deferring the public-path half without explicit sign-off could be read as silently dropping an acceptance criterion, which CONTEXT.md's phase boundary explicitly disallows ("MUST NOT silently drop a criterion without recording why") |
| A3 | `samael 0.0.21` (vs the minimum-sufficient `0.0.20`) is safe to adopt without other breaking changes to the SP flow (`AuthnRequest` building, metadata generation, `ToXml` trait usage) | SECFIX-04 | Only the `crypto` module's public API was diffed in this session; `schema`/`metadata`/`traits` modules (used elsewhere in `saml.rs` for `AuthnRequest`/`Issuer`/`NameIdPolicy`/`ToXml`) were not diffed between 0.0.19 and 0.0.21 — a full `cargo build -p axiam-federation --features saml` after the bump is mandatory before assuming zero other breakage |
| A4 | Adding `acs_url: String` to the schemafull `federation_login_state` table (migration v21) is an acceptable "what the fix strictly requires" addition, not an out-of-scope refactor | SECFIX-04 | If judged out of scope, the public-path Destination check cannot be meaningfully closed at all (there is currently no real ACS URL anywhere in that flow) — see A2 |

**If this table is empty:** N/A — see entries above; all four concern narrow design/scope-boundary calls, not unverified technical facts (every technical claim in this document was verified by reading live source or downloading and inspecting the actual crate tarballs).

## Open Questions

1. **SECFIX-01: Does `ValidateCredentials.tenant_id` need cross-tenant rejection, or is cross-tenant credential validation a legitimate mesh use case?**
   - What we know: `GetUser` definitely needs it (ROADMAP SC#1 is explicit). `IntrospectToken`/`ValidateToken` have no tenant field to check. `ValidateCredentials` is the ambiguous middle case.
   - What's unclear: whether any current or planned mesh consumer needs to validate credentials for a tenant other than its own.
   - Recommendation: default to cross-validating (fail-closed), and record it as a locked decision in the PLAN rather than leaving it to the executor's judgment.

2. **SECFIX-04: Is the public-path SAML Destination gap (requiring a login_state schema change) in scope for Phase 23, or should it be explicitly deferred?**
   - What we know: REQUIREMENTS.md cites both call sites; the authenticated-path fix is a one-line change (unused field already exists), the public-path fix requires a new schema field + DTO threading.
   - What's unclear: whether "no refactors beyond what a given fix strictly requires" extends to a small, additive schema migration (this research treats it as in-scope, since it's additive and narrowly targeted, not a refactor of existing behavior).
   - Recommendation: attempt both in the PLAN; if wave/time-boxing forces a choice, close the authenticated path unconditionally (it's cited by ROADMAP SC#4's literal wording — "on the authenticated ACS path") and treat the public-path Destination check as the one item eligible for an explicit, recorded deferral.

3. **SECFIX-06: exact frontend routing shape (path segments vs query params) for tenant slug carriage.**
   - What we know: D-04 mandates URL-carried tenant slug, forbids user-typed tenant fields and email-domain inference.
   - What's unclear: whether the planner should introduce path-segment routes (`/auth/forgot-password/:org/:tenant`) or query params (`?org=...&tenant=...`) — both satisfy D-04's letter.
   - Recommendation: query params (lower blast radius on `router.tsx`, consistent with `ResetPasswordPage`'s existing `?token=` convention) unless the planner has a reason to prefer path segments.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|--------------|-----------|---------|----------|
| crates.io registry access (network) | SECFIX-04 `samael` version bump | Confirmed reachable this session (sparse index + tarball downloads succeeded) | n/a | If registry access is unavailable at execute time, SECFIX-04 cannot be correctly closed at `samael 0.0.19` — see Common Pitfalls #2; this would block the phase gate, not degrade gracefully |
| SurrealDB (local/dev instance) | SECFIX-02, SECFIX-04 (new migration v21 if public-path fix attempted) | Assumed available per existing `just dev-up` workflow | n/a | none needed — already a hard project dependency |
| `xmlsec1` system library (via samael's `xmlsec` feature) | SECFIX-04 (all SAML work, not just the version bump) | Already a build-time dependency today (feature already enabled at 0.0.19) | n/a | Already working; the version bump does not add a new system dependency |

**Missing dependencies with no fallback:** none identified — this phase's only new environmental requirement (crates.io reachability for the `samael` bump) is the same class of dependency `cargo build` already requires for every other crate.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Backend framework | `cargo test` (per-crate, `#[tokio::test]`/`#[actix_rt::test]`) — no new framework |
| Frontend unit/contract framework | `vitest` (`npm run test`) |
| Frontend e2e framework | `playwright` (`npm run test:e2e`) — specs exist under `frontend/e2e/`; CI execution wiring is CORR-04/Phase 26, but the specs themselves run locally today |
| Config files | `crates/*/Cargo.toml` (workspace test targets), `frontend/playwright.config.ts`, `frontend/vitest.config.ts` (paths not modified by this phase) |
| Quick run command (per touched crate) | `cargo test -p <crate>` (NEVER `--workspace`, per CLAUDE.md) |
| Frontend quick run | `npm run test` (vitest) / `npx playwright test <file>` for a single e2e spec |

### Phase Requirements → Test Map

| Req ID | Behavior (the attack / negative case) | Test Type | Automated Command | File Exists? |
|--------|----------------------------------------|-----------|--------------------|--------------|
| SECFIX-01 | gRPC `GetUser`/`ValidateCredentials`/`IntrospectToken` with no bearer token → `UNAUTHENTICATED` | integration | `cargo test -p axiam-api-grpc --test grpc_auth_test` | ✅ file exists (`grpc_auth_test.rs`), ❌ new test functions for User/Token services needed |
| SECFIX-01 | Cross-tenant `GetUser` (tenant-A caller token, tenant-B `user_id`/`tenant_id` in body) → `PERMISSION_DENIED` | integration | `cargo test -p axiam-api-grpc --test grpc_auth_test` | ❌ new test needed (template: `grpc_rejects_call_without_bearer_token`, `grpc_auth_test.rs:212-237`) |
| SECFIX-01 | gRPC `ValidateCredentials` accrues lockout state on repeated bad passwords (SEC-026b) | integration | `cargo test -p axiam-api-grpc --test grpc_auth_test` (or `axiam-auth` unit test on the shared helper) | ❌ new test needed |
| SECFIX-02 | Tenant-A `permissions:grant` caller cannot attach tenant-B permission/scope to a tenant-A role via `grant_to_role_with_scopes` | integration | `cargo test -p axiam-db --test req14_tenant_isolation_test` | ✅ file exists; ❌ existing `permission_grant_cross_tenant_rejected` (line 160-199) currently tests the wrong (already-guarded) method — must be repointed, not just added-to |
| SECFIX-03 | Webhook create/update fails closed (explicit error, not silent success) when `AXIAM__PKI__ENCRYPTION_KEY` is unset | integration | `cargo test -p axiam-api-rest --test webhook_test` | ✅ file exists (`crates/axiam-api-rest/tests/webhook_test.rs`) — has `create_webhook_returns_201` (line 128), `create_webhook_omits_secret` (line 159, already asserts response excludes secret), `create_webhook_validates_empty_url`/`_events` (187, 211); ❌ no existing test constructs the app with a `None` encryption key or asserts stored-ciphertext ≠ plaintext — both need to be added here |
| SECFIX-03 | Stored webhook secret ciphertext ≠ plaintext; decrypts correctly at delivery | unit (already partially covered) | `cargo test -p axiam-api-rest webhook_secret_encrypt_decrypt_round_trip` | ✅ exists (`webhook.rs:372-385`) but only tests the standalone `encrypt_webhook_secret` function, not that the `create`/`update` handlers actually call it — new integration-level test needed asserting the DB-stored value differs from the submitted plaintext |
| SECFIX-04 | SAML response with a wrapped/duplicated assertion (XSW) is rejected | unit or integration | `cargo test -p axiam-federation` (unit) or `cargo test -p axiam-server --test req5_saml_e2e` (e2e, has full fixture infra) | ❌ new test needed; templates confirmed: `axiam-federation/src/saml.rs:1074-1110` (`verify_rejects_tampered_body`/`verify_rejects_missing_signature`) AND `axiam-server/tests/req5_saml_e2e.rs` which already has a real signed-fixture harness (`fixture()`/`fixture_b64()` at lines 46-52, `signing_cert_pem()` at 57, `saml_rejects_tampered_response` at 191, `saml_rejects_expired_not_on_or_after` at 238 building a raw XML assertion string inline at lines 253-276) — the e2e file's pattern of hand-building assertion XML is the more direct template for a wrapped/duplicated-assertion fixture than the unit-test module |
| SECFIX-04 | SAML response with wrong `Destination` is rejected on the authenticated ACS path | unit or integration | `cargo test -p axiam-server --test req5_saml_e2e` | ❌ new test needed — `insert_saml_config`/`make_saml_svc` helpers (lines 74, 130) already exist to build the harness |
| SECFIX-04 | SAML response missing `InResponseTo` is rejected on the authenticated ACS path | unit or integration | `cargo test -p axiam-server --test req5_saml_e2e` | ❌ new test needed |
| SECFIX-05 | Replaying old cookies after `POST /api/v1/auth/logout` is unauthenticated | integration | `cargo test -p axiam-api-rest --test auth_test` | ✅ file exists (`auth_test.rs`, `logout_clears_cookies` at line 521-570+) — extend with a post-logout replay assertion (expect 401 on `/api/v1/auth/me` using the old access cookie) |
| SECFIX-05 | Frontend logout no longer 400s | e2e (Playwright) | `npx playwright test <logout spec>` | ❌ no existing logout coverage found in `frontend/e2e/*.spec.ts` — new spec or addition to `login.spec.ts` needed |
| SECFIX-06 | Reset/confirm/resend requests carry `tenant_id`/`email` and succeed | e2e contract (body assertion) | `npx playwright test auth-contract.spec.ts` | ✅ file exists but only asserts URL path today (lines 82-207) — must add body-content assertions |
| SECFIX-06 | Reset/resend responses stay enumeration-safe (constant response) including for unresolvable tenant slugs | integration | `cargo test -p axiam-api-rest --test <password_reset/email_verification test module>` | ✅ partial — `password_reset.rs:221-` already has a `#[cfg(test)] mod tests` (D-15 enumeration-safe gate); extend with a slug-resolution-failure case |

### Sampling Rate

- **Per task commit:** `cargo test -p <touched crate>` (backend); `npm run test` (frontend unit) for any touched frontend file
- **Per wave merge:** full per-crate test suites for every crate touched in the wave, plus `npx playwright test <touched specs>` for SECFIX-05/06 frontend changes
- **Phase gate:** all six SECFIX negative tests green, `cargo fmt` + `cargo clippy -D warnings` clean per touched crate, `eslint .` + `tsc -b` clean for touched frontend files, before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `crates/axiam-api-rest/tests/webhook_test.rs` — add a fail-closed-on-missing-key test and a stored-ciphertext-≠-plaintext test (file exists with a working app harness; no code changes needed to the harness itself)
- [ ] `crates/axiam-server/tests/req5_saml_e2e.rs` — add XSW wrapped-assertion, wrong-Destination, and missing-InResponseTo negative tests (file exists with `insert_saml_config`/`make_saml_svc`/`fixture()` helpers already built for exactly this purpose — confirmed via direct read, corrects an earlier assumption in this research that no such file existed)
- [ ] New Playwright spec (or extension of `frontend/e2e/login.spec.ts`) for logout replay-after-cookie-clear behavior — confirmed no existing spec covers this (`grep -i logout` across all `frontend/e2e/*.spec.ts` returned nothing)

*(Not "None" — three gaps exist and are listed above with confirmed target files; both backend test harnesses already exist and only need new test functions added, not new infrastructure.)*

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | Yes (SECFIX-01, SECFIX-05) | Bearer JWT validation on every gRPC service (Tonic interceptor); session-liveness re-check on every REST request (`SessionValidator`, already implemented) |
| V3 Session Management | Yes (SECFIX-05) | Server-side session invalidation on logout, all-cookie clearing, no client-supplied session identifier |
| V4 Access Control | Yes (SECFIX-01, SECFIX-02) | Tenant-scoped authorization derived from verified claims, never from request body; SurrealQL-level tenant predicates on every cross-record edge mutation |
| V5 Input Validation | Yes (all six) | Existing `AxiamError::Validation` pattern; UUID parsing via `parse_uuid` helpers already used consistently |
| V6 Cryptography | Yes (SECFIX-03) | AES-256-GCM via `axiam_auth::crypto` (never hand-rolled); fail-closed `Option<[u8;32]>` key handling, no constant/zero-key fallback |
| V7 Error Handling / Logging | Yes (SECFIX-03, SECFIX-06) | Secrets never logged (`#[serde(skip_serializing)]` already on `Webhook.secret`); enumeration-safe uniform responses on reset/verify (D-15, must not regress) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| Unauthenticated gRPC service call (SECFIX-01) | Spoofing | Tonic `Interceptor` requiring a verified bearer JWT on every service, no exceptions |
| Cross-tenant IDOR via unguarded DB mutation (SECFIX-02) | Elevation of Privilege | In-query `LET…IF…THROW` tenant predicate, atomic with the mutation |
| Encryption key defaulting to a constant/zero value (SECFIX-03) | Information Disclosure / Tampering | `Option<[u8;32]>` fail-closed pattern — absence of a key disables the feature, never silently weakens it |
| XML Signature Wrapping (SECFIX-04) | Spoofing / Tampering | Extract and parse only the xmlsec-verified content subset (`reduce_xml_to_signed`), never trust a structurally-independent read of the same document post-verification |
| Stale-session replay after logout (SECFIX-05) | Repudiation / Spoofing | Server-authoritative session invalidation + per-request liveness re-check (already implemented; just needs to actually be invoked) |
| Account/tenant enumeration via differential responses (SECFIX-06) | Information Disclosure | Uniform response body/status/timing regardless of account existence, federation status, or (newly) slug-resolution success |

## Sources

### Primary (HIGH confidence — read directly from live repository source)
- `crates/axiam-api-grpc/src/{server.rs, middleware/auth.rs, services/{authorization,user,token}.rs}`
- `crates/axiam-db/src/repository/permission.rs`, `crates/axiam-db/tests/req14_tenant_isolation_test.rs`
- `crates/axiam-server/src/main.rs`, `crates/axiam-api-rest/src/webhook.rs`, `crates/axiam-api-rest/src/handlers/webhooks.rs`, `crates/axiam-db/src/repository/webhook.rs`, `crates/axiam-core/src/models/webhook.rs`
- `crates/axiam-federation/src/{saml.rs, cert.rs}`, `crates/axiam-api-rest/src/handlers/federation.rs`, `crates/axiam-core/src/repository.rs` (FederationLoginState), `crates/axiam-db/src/schema.rs`
- `crates/axiam-api-rest/src/handlers/auth.rs`, `crates/axiam-api-rest/src/extractors/auth.rs`, `crates/axiam-auth/src/service.rs`, `crates/axiam-db/src/repository/session.rs`, `frontend/src/components/layout/Topbar.tsx`
- `crates/axiam-api-rest/src/handlers/{password_reset,email_verification}.rs`, `frontend/src/services/auth.ts`, `frontend/src/pages/{LoginPage.tsx, auth/{ForgotPasswordPage,ResetPasswordPage}.tsx}`, `frontend/src/router.tsx`
- `frontend/e2e/auth-contract.spec.ts`, `crates/axiam-api-rest/tests/auth_test.rs`

### Primary (HIGH confidence — verified via authoritative registry + downloaded source)
- crates.io sparse index (`index.crates.io/sa/ma/samael`) — confirms published versions `0.0.1`–`0.0.21`
- `static.crates.io/crates/samael/samael-{0.0.19,0.0.20,0.0.21}.crate` — full tarball download and direct source inspection of `src/crypto.rs` (0.0.19) vs `src/crypto/mod.rs` (0.0.20/0.0.21), confirming the exact API diff (`ReduceMode`, `CryptoProvider::reduce_xml_to_signed`, `CertificateDer` newtype)

### Secondary (MEDIUM confidence)
- `github.com/njaremko/samael` master-branch source (fetched via raw.githubusercontent.com) — used only to locate the crypto module's file layout before pinpointing exact released-version source via the tarballs above; the tarball inspection is the actual evidentiary basis for every samael claim in this document

## Metadata

**Confidence breakdown:**
- Current-code location map (all 6 SECFIXes): HIGH — every cited file:line was read from live `main`, not assumed from the review commit or REQUIREMENTS.md's (occasionally stale) citations
- samael version/API facts: HIGH — verified via direct tarball download and source inspection, not training-data recall
- SECFIX-04 public-path scope boundary (schema addition): MEDIUM — a legitimate design judgment call flagged in Open Questions, not a verified fact
- SECFIX-01 `ValidateCredentials` tenant cross-validation: MEDIUM — a defensible interpretation of ambiguous requirements, flagged in Assumptions Log

**Research date:** 2026-07-03
**Valid until:** Effectively indefinite for the codebase-location claims (they will only go stale if more commits land on `main` before Phase 23 executes — re-verify line numbers immediately before planning if any commits have landed since this research). The samael version facts are stable (published crate versions don't change).
