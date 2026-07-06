# Phase 23: Security Regressions & HIGH Findings - Research

**Researched:** 2026-07-03
**Domain:** Rust/Actix-Web/Tonic security remediation — gRPC service authentication, tenant-isolation SurrealQL guards, AES-256-GCM fail-closed key handling, SAML XML-Signature-Wrapping (XSW) defense, JWT-`jti`-based session revocation, enumeration-safe multi-tenant password-reset/verification flows.
**Confidence:** HIGH — every file:line cited below was read directly from the live `main` branch in this session (not assumed from the 2026-07-01 review commit `ea85872`), and drift from the review was confirmed/re-confirmed for every finding.

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
- Extracting `record_failed_login`/`reset_failed_logins` into a *crate-shared* module is in-scope only to the extent D-06 requires it (gRPC must call the same logic REST calls) — do not otherwise refactor `AuthService`.
- Adding a `tenant_slug`-alternative field to `RequestResetBody`/`ConfirmResetBody`/`ResendVerificationRequest` mirroring `handlers/auth.rs`'s `(tenant_id, tenant_slug)` pattern is **plausible but not mandated** — see Open Questions. Do not introduce a new "frontend base URL" config; reuse the existing relative-path `action_url` precedent (`handlers/gdpr.rs`).

None of these expand Phase 23 scope — they are the correct home for adjacent work.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| SECFIX-01 | gRPC `UserService`/`TokenService` authentication + gRPC lockout accrual | §SECFIX-01 below: exact `server.rs`/`services/{user,token}.rs` gaps, shared-Layer design, shared lockout helper location |
| SECFIX-02 | Tenant guard on live `grant_to_role_with_scopes` path | §SECFIX-02 below: exact SurrealQL pattern to lift from `grant_to_role`, scope-id tenant check, test repoint |
| SECFIX-03 | Webhook fail-closed key + encrypt-at-rest | §SECFIX-03 below: `main.rs` fallback removal, `PkiConfig` `Option<[u8;32]>` pattern to mirror, create/update write-path wiring |
| SECFIX-04 | SAML signature↔assertion binding (XSW) + Destination/InResponseTo | §SECFIX-04 below: `samael` library internals proving the exact gap, both `handle_saml_response` call sites, fixture reuse plan |
| SECFIX-05 | Logout revokes session from `jti`, no body | §SECFIX-05 below: `AuthenticatedUser.session_id` already equals `jti` — trivial, low-risk fix confirmed |
| SECFIX-06 | Reset/resend flows carry `tenant_id`, stay enumeration-safe | §SECFIX-06 below: DTOs, missing `action_url` construction (broken today, not just an SPA problem), `VerifyEmailPage` as the working reference pattern |

</phase_requirements>

## Summary

All six SECFIX findings were re-verified against the current `main` branch (post v1.1 SDK merge) and every one is **still present exactly as described**, though several have more moving parts than the review commit hinted at. Two findings deserve extra planner attention because they are subtler than a single-line fix:

1. **SECFIX-04 (SAML XSW)** is not fixable by changing a function argument. `samael::crypto::verify_signed_xml` (via `xmlsec1`'s `xmlSecFindNode`) finds and verifies the **first** `<ds:Signature>` element anywhere under the document root and returns only `Ok(true)/Ok(false)` — it never tells the caller **which element ID** it verified. `handle_saml_response` then **independently** re-parses the document via `samael::schema::Response` and consumes `response.assertion` (a scalar `Option<Assertion>`, not a `Vec`). These two facts together are the exact precondition for XML Signature Wrapping: nothing today binds "the element that was cryptographically verified" to "the element whose claims get trusted." Closing this requires the fix to independently walk the raw XML (via `libxml`, already a transitive dependency) to (a) assert exactly one `<Assertion>` element exists in the document and (b) confirm the verified `<Reference URI="#...">` equals that assertion's `ID`.
2. **SECFIX-06 (reset/resend `tenant_id`)** is not purely a frontend bug. The backend's `request_reset`/`email_verification` handlers **never build an `action_url` at all** — `template_context` only carries `{token, expiry_time}`, while the email templates (`axiam-email/src/template.rs`) render `{{action_url}}`. Today's reset/verification emails ship a template placeholder, not a working link, independent of the SPA-side `tenant_id` omission. The fix must add `action_url` construction (mirroring the existing relative-path precedent in `handlers/gdpr.rs`'s `cancel_url`) **and** thread `tenant_id`/`email` through the three frontend calls. `VerifyEmailPage.tsx`'s existing `?token=…&tenant_id=…` pattern is the proven, already-shipped reference to replicate for `ResetPasswordPage.tsx`.

The remaining four (SECFIX-01, 02, 03, 05) are straightforward, well-precedented fixes: SECFIX-01 and SECFIX-02 both have a working guarded sibling in the same file to copy (`AuthorizationServiceImpl`/`grant_to_role`); SECFIX-03 has a working sibling pattern in `axiam-pki` (`Option<[u8;32]>` + `.ok_or_else`); SECFIX-05 turns out to require **zero new plumbing** — `AuthenticatedUser.session_id` already equals the JWT `jti` (comment confirms this at `extractors/auth.rs:80-82`), so the fix is deleting the body-comparison branch and calling `svc.logout(user.tenant_id, user.session_id)` directly.

**Primary recommendation:** Fix SECFIX-01/02/03/05 first (mechanical, low-ambiguity, each mirrors an existing in-file pattern); budget the most implementation time for SECFIX-04 (requires new raw-XML introspection code, no library API shortcut) and SECFIX-06 (requires both a backend `action_url`-construction fix and a frontend URL-param fix, not just a body-shape fix).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| gRPC service authentication (SECFIX-01) | API / Backend (gRPC) | — | Tonic interceptor/layer operates purely at the transport/service boundary; no DB or frontend involvement |
| Credential lockout accrual (SECFIX-01/D-06) | API / Backend | Database / Storage | Business logic lives in `axiam-auth`/`axiam-core` trait methods; the counter itself persists in `user.failed_login_attempts`/`locked_until` |
| Tenant-scoped permission grant (SECFIX-02) | Database / Storage | API / Backend | The guard is a SurrealQL `LET/THROW` predicate inside the repository query; the REST handler is a thin pass-through with no additional logic needed |
| Webhook secret encryption (SECFIX-03) | API / Backend | Database / Storage | Encrypt-before-store logic lives in `axiam-api-rest::webhook`/handlers; the DB layer stores/returns ciphertext opaquely |
| SAML XSW binding (SECFIX-04) | API / Backend (federation) | — | Pure server-side XML/crypto validation in `axiam-federation`; no client involvement, no persistence beyond existing replay-ID tracking |
| Logout session revocation (SECFIX-05) | API / Backend | Browser / Client | Server derives session solely from its own verified JWT; the browser's only job is to stop sending a body and clear local state |
| Reset/verify tenant threading (SECFIX-06) | Browser / Client | API / Backend | Frontend must carry `tenant_id` in the URL/state (client-tier fix); backend must additionally start building `action_url` in the mail `template_context` (a currently-missing backend behavior, not purely a frontend contract mismatch) |

## Package Legitimacy Audit

No new external packages are introduced by this phase. All fixes reuse existing workspace dependencies (`samael` 0.0.19, `tonic` 0.14.6, `libxml` — transitively via `samael`'s `xmlsec` feature — `axiam_auth::crypto::aes256gcm_encrypt`). If the planner elects to add `libxml` as a **direct** dependency of `axiam-federation` (recommended for SECFIX-04, see below), verify it against the same major/minor version `samael` 0.0.19 already pins, to avoid two copies of the FFI bindings in the dependency tree.

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `libxml` (new direct dep, optional) | crates.io | mature (samael already vendors it transitively; used since ≥2019) | — (transitive today) | github.com/KWARC/rust-libxml | OK | Approved if added — pin to the version samael 0.0.19 already resolves in `Cargo.lock` to avoid duplicate FFI bindings |

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.

## Standard Stack

### Core (already in workspace — no new pins required)
| Library | Version (verified via `Cargo.lock`) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `tonic` | 0.14.6 [VERIFIED: Cargo.lock] | gRPC server/client, `Interceptor`/`tower::Layer` composition | Already the workspace gRPC stack; `Server::builder().layer(...)` is the documented mechanism for cross-cutting request middleware |
| `samael` | 0.0.19, `xmlsec` feature [VERIFIED: Cargo.lock, source inspected] | SAML XML parsing + XML-DSig verification | Only maintained pure-Rust SAML2 library with `xmlsec1` FFI bindings; already wired in `axiam-federation` |
| `libxml` | transitively resolved by `samael` 0.0.19 [VERIFIED: source inspected — `samael/Cargo.toml:68`] | Raw XML DOM/XPath walking needed for the XSW element-count + reference-binding check | `samael` already depends on and re-uses this crate internally for its own signing helpers; no new supply-chain surface if pinned to the same resolved version |
| `axiam_auth::crypto::{aes256gcm_encrypt, aes256gcm_decrypt}` | in-repo | AES-256-GCM encrypt/decrypt already used for PKI private keys, federation client secrets, and (partially) webhook secrets | Single hashing/crypto helper module per CLAUDE.md security standards — reuse, don't reintroduce a second AEAD call site |
| `tower_governor` | 0.8.0 [VERIFIED: Cargo.lock] | Already-applied gRPC rate limiting (`build_grpc_governor_layer`) — proves the `.layer(...)` composition point already exists on `Server::builder()`, useful precedent for the shared auth `Layer` | Existing pattern in `server.rs:82` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tonic::service::Interceptor` / `tonic::service::interceptor` | in `tonic` 0.14.6 | Wraps a service in `InterceptedService<S, F>` | Use when building the shared cross-service auth `Layer` for SECFIX-01 (see Architecture Patterns below) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Raw-XML walk (`libxml`) for XSW reference-binding (SECFIX-04) | Regex-based extraction of `Reference URI=` / `Assertion ID=` | **Rejected** — XML cannot be safely parsed with regex (comments, CDATA, namespace-prefix aliasing, and entity tricks are exactly how real-world XSW bypasses defeat naive string checks); use a real XML parser |
| Extending `RequestResetBody`/`ConfirmResetBody` with `tenant_slug: Option<String>` (SECFIX-06) | Requiring the frontend to already have a resolved `tenant_id` UUID in scope (from a prior login attempt, stored tenant context, or the emailed link) | Either is defensible; see Open Questions — the mechanics are Claude's discretion per CONTEXT.md, but the **DTOs and enumeration-safety must not regress** |

**Installation:** No new `cargo add`/`npm install` commands required — every fix uses libraries already resolved in `Cargo.lock`/`package-lock.json`. If `libxml` is added as a direct `axiam-federation` dependency, pin to the exact version resolved in `Cargo.lock` (fetch confirmed working: `~/.cargo/registry/src/.../samael-0.0.19` present after `cargo fetch`).

## Architecture Patterns

### System Architecture Diagram (SECFIX-01: gRPC auth chokepoint)

```
                     ┌─────────────────────────────────────────┐
                     │   Server::builder()                      │
                     │     .layer(governor_layer)   (existing)  │
                     │     .layer(auth_layer)       (NEW)        │
                     └───────────────┬───────────────────────────┘
                                     │  every inbound gRPC frame passes
                                     │  through both layers BEFORE routing
                     ┌───────────────▼───────────────────────────┐
                     │  auth_layer: wraps AuthInterceptor as a    │
                     │  tower::Layer via InterceptedService       │
                     │  (rejects: missing/invalid bearer JWT)     │
                     └───────────────┬───────────────────────────┘
                                     │ ValidatedClaims inserted into
                                     │ request.extensions()
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
   AuthorizationServiceImpl   UserServiceImpl (NEW)   TokenServiceImpl (NEW)
   (already reads claims,     MUST read claims for    MUST require caller auth;
    cross-validates body)     GetUser/ValidateCreds    ValidateToken/Introspect
                                                        operate on an arbitrary
                                                        `access_token` body field
                                                        (no tenant_id to cross-
                                                        validate — caller auth
                                                        is the whole fix here)
```

### Recommended Project Structure (no new files strictly required; optional additions noted)
```
crates/axiam-api-grpc/src/
├── middleware/
│   ├── auth.rs          # existing AuthInterceptor — reused, not duplicated
│   └── rate_limit.rs    # existing governor layer — proves the .layer() composition point
├── server.rs            # MODIFY: register one shared auth layer instead of a single with_interceptor call
└── services/
    ├── authorization.rs # reference pattern — copy the claims-cross-validate block
    ├── user.rs           # MODIFY: GetUser + ValidateCredentials read ValidatedClaims
    └── token.rs          # MODIFY: no body cross-validation needed (see Pattern 2 below) — just needs to sit behind the layer
```

### Pattern 1: Shared tower `Layer` instead of three `with_interceptor` calls (SECFIX-01)
**What:** Wrap the whole `Server::builder()` router in one `Layer` that applies `AuthInterceptor` to every inbound request, instead of calling `XxxServiceServer::with_interceptor(...)` three times.
**When to use:** All three gRPC services now require the same authentication precondition (per D-06/discretion note), so a per-service `with_interceptor` is pure duplication once `UserService`/`TokenService` also need it.
**Example:**
```rust
// Source: tonic::service::Interceptor docs (docs.rs/tonic/latest/tonic/service/trait.Interceptor.html)
// and existing in-repo precedent at server.rs:82 (`.layer(governor_layer)`).
use tonic::service::interceptor;

let auth_layer = interceptor(AuthInterceptor::new(auth_config.clone()));

let mut builder = Server::builder()
    .max_frame_size(4 * 1024 * 1024)
    .timeout(Duration::from_secs(30))
    .concurrency_limit_per_connection(256)
    .layer(governor_layer)
    .layer(auth_layer); // NEW — replaces per-service with_interceptor

// Register services WITHOUT with_interceptor — the layer above already
// authenticates every request before it reaches routing.
let authz_svc = AuthorizationServiceServer::new(AuthorizationServiceImpl::new(engine));
let user_svc = UserServiceServer::new(UserServiceImpl::new(user_repo, auth_config.clone()));
let token_svc = TokenServiceServer::new(TokenServiceImpl::new(auth_config));
```
[ASSUMED — the `tonic::service::interceptor(...)` free function producing a `Layer` was confirmed to exist via web search of `tonic::service::interceptor` docs, but the exact 0.14.6 signature was not independently re-verified against the vendored source in this session. **Verify** `tonic::service::interceptor` compiles against 0.14.6 before committing to this exact call shape; the fallback if it doesn't exist as a free function is `tower::layer::layer_fn(|inner| InterceptedService::new(inner, AuthInterceptor::new(auth_config.clone())))`, which is guaranteed to work because `InterceptedService::new` is the primitive `with_interceptor` already calls internally.]

### Pattern 2: `TokenService`'s two RPCs need caller-authentication only, not body cross-validation
**What:** `ValidateTokenRequest`/`IntrospectTokenRequest` (`proto/axiam/v1/token.proto:20-38`) carry only `access_token: String` — no `tenant_id`/`user_id` field exists to cross-validate against `ValidatedClaims`.
**When to use:** When wiring the shared auth layer onto `TokenService`, do NOT add a claims-cross-validate block to `validate_token`/`introspect_token` (there is nothing in the request body to compare). The security fix for these two RPCs is purely "the caller itself must present a valid bearer token" (closing the "any mesh peer on :50051 can introspect arbitrary tokens" gap) — the *token being introspected* is a separate value by design (this RPC is meant to let one authenticated service introspect a token issued to a different subject, e.g. for cross-service authorization checks).
[VERIFIED: proto/axiam/v1/token.proto read directly]

### Pattern 3: Tenant-guard SurrealQL predicate to lift into `grant_to_role_with_scopes` (SECFIX-02)
**What:** `grant_to_role` (`permission.rs:314-352`) already has the exact guard needed; `grant_to_role_with_scopes` (`permission.rs:428-459`) has none and ignores its own `_tenant_id` parameter.
**Example:**
```rust
// Source: crates/axiam-db/src/repository/permission.rs:323-332 (existing grant_to_role — COPY this pattern)
async fn grant_to_role_with_scopes(
    &self,
    tenant_id: Uuid,   // rename from `_tenant_id` — now used
    role_id: Uuid,
    permission_id: Uuid,
    scope_ids: Vec<Uuid>,
) -> AxiamResult<()> {
    let role_id_str = role_id.to_string();
    let perm_id_str = permission_id.to_string();

    if scope_ids.is_empty() {
        let query = format!(
            "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
             IF array::len($ro) = 0 OR array::len($pe) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             RELATE role:`{role_id_str}` -> grants -> \
             permission:`{perm_id_str}` SET scope_ids = NONE;"
        );
        // .bind(("tid", tenant_id.to_string())) + same result.check() error-mapping as grant_to_role
    } else {
        // ADDITIONAL scope-id tenant check (discretion note: "validate every
        // scope id belongs to the caller's tenant"). `scope` table already has
        // a `tenant_id` field (schema.rs:276). Extend the LET/THROW predicate:
        let query = format!(
            "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
             LET $sc = (SELECT id FROM scope WHERE tenant_id = $tid AND meta::id(id) IN $scope_ids);\
             IF array::len($ro) = 0 OR array::len($pe) = 0 \
                OR array::len($sc) != array::len($scope_ids) {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             RELATE role:`{role_id_str}` -> grants -> \
             permission:`{perm_id_str}` SET scope_ids = $scope_ids;"
        );
        // .bind(("tid", tenant_id.to_string())).bind(("scope_ids", scope_strs))
    }
    // ... same result.check() → AuthorizationDenied mapping as grant_to_role
}
```
[VERIFIED: permission.rs:314-459 and schema.rs:275-284 read directly; the `$sc` scope-tenant sub-query is a direct extension of the existing pattern, not independently tested in this session — planner must add the negative test proving it]

### Pattern 4: `Option<[u8;32]>` fail-closed key (mirror PKI, SECFIX-03)
**What:** PKI (`axiam-pki/src/config.rs:10-11`, `ca.rs:105-108`) already fixed the exact same class of bug for CA/cert keys; webhook must mirror it exactly, not reinvent a new posture.
**Example:**
```rust
// Source: crates/axiam-pki/src/ca.rs:105-108 (existing, working pattern — mirror this)
let enc_key = self.config.encryption_key.ok_or_else(|| {
    AxiamError::Internal(
        "AXIAM__PKI__ENCRYPTION_KEY not set — CA/cert key encryption unavailable".into(),
    )
})?;
```
```rust
// main.rs — BEFORE (the SEC-059 bug):
let webhook_enc_key: [u8; 32] =
    load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY").unwrap_or([0u8; 32]);
let webhook_delivery =
    axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);

// main.rs — AFTER (D-01: graceful degrade, no server-boot failure):
let webhook_enc_key: Option<[u8; 32]> = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY");
let webhook_delivery =
    axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
// WebhookDeliveryService::new signature changes: encryption_key: Option<[u8; 32]>
// WebhookDeliveryService::deliver(...) and the create/update handlers each do:
//   let key = self.encryption_key.ok_or_else(|| WebhookError::EncryptionKeyUnset)?;
// (or the handler-level equivalent — refuse registration with a 4xx, not a panic)
```
[VERIFIED: `axiam-pki/src/config.rs:10-11`, `ca.rs:105-108`, `main.rs:405-408` all read directly this session; `load_key_from_env` (`main.rs:52-68`) already returns `Option<[u8;32]>` with a `warn!` on absence — no change needed to that function]

### Pattern 5: XSW binding — raw-XML introspection to close the gap `samael` doesn't cover (SECFIX-04)
**What:** `samael::crypto::verify_signed_xml` (`samael-0.0.19/src/crypto.rs:90-109`) calls `XmlSecSignatureContext::verify_document`, which calls `find_signode` (`samael-0.0.19/src/xmlsec/xmldsig.rs:211-225`) — a thin wrapper over the C function `xmlSecFindNode`, which performs a **depth-first search from the document root and returns the FIRST `<dsig:Signature>` element found**, then verifies only that one node. The function's public return type is `Result<(), Error>` — **it never surfaces which element ID the verified Signature's `<Reference URI="#...">` pointed to.** Meanwhile `samael::schema::Response.assertion` is declared as `#[serde(rename = "Assertion")] pub assertion: Option<Assertion>` (`response.rs:35`) — a scalar, not `Vec<Assertion>` — so if an attacker's payload contains two sibling `<Assertion>` elements (the textbook XSW shape: keep the original signed one intact somewhere in the tree so the lone-signature check still passes, and add a second, forged, unsigned `<Assertion>` that `quick_xml`'s deserializer happens to bind to the `assertion` field), nothing in the current code detects the duplication or confirms the *consumed* assertion is the *signed* one.
**When to use:** This is the core SECFIX-04 fix. It CANNOT be solved by changing `verify_signature`'s call-site arguments alone — it requires new code in `saml.rs` that runs after `verify_signature()` succeeds and before `extract_assertion_claims(assertion)` is trusted.
**Example (recommended shape — no ready-made samael API exists for this):**
```rust
// NEW helper in axiam-federation/src/saml.rs, run between verify_signature()
// and the existing `let assertion = response.assertion...` extraction.
// Requires `libxml` as a direct dependency (already transitively resolved
// by samael 0.0.19 — pin to the same version).
fn bind_signature_to_assertion(xml_bytes: &[u8], claimed_assertion_id: &str)
    -> Result<(), FederationError>
{
    let parser = libxml::parser::Parser::default();
    let doc = parser.parse_string(xml_bytes)
        .map_err(|e| FederationError::SamlResponseFailed(format!("re-parse failed: {e}")))?;
    let context = libxml::xpath::Context::new(&doc)
        .map_err(|_| FederationError::SamlResponseFailed("xpath context failed".into()))?;

    // 1. Exactly one Assertion element must exist anywhere in the document.
    //    (Closes the duplicate/wrapped-assertion XSW payload shape.)
    let assertions = context.findnodes("//*[local-name()='Assertion']", None)
        .map_err(|_| FederationError::SamlResponseFailed("xpath eval failed".into()))?;
    if assertions.len() != 1 {
        return Err(FederationError::SamlResponseFailed(format!(
            "expected exactly 1 Assertion element, found {} (possible XSW)",
            assertions.len()
        )));
    }

    // 2. Every <Signature>'s Reference URI must resolve to the consumed
    //    assertion's ID (or the Response's own ID, for response-level signing).
    //    Reject if NO signature references the consumed assertion.
    let references = context.findnodes(
        "//*[local-name()='Signature']//*[local-name()='Reference']/@URI", None
    ).map_err(|_| FederationError::SamlResponseFailed("xpath eval failed".into()))?;
    let expected = format!("#{claimed_assertion_id}");
    let bound = references.iter().any(|n| n.get_content() == expected);
    if !bound {
        return Err(FederationError::SamlResponseFailed(
            "no verified Signature references the consumed Assertion (XSW rejected)".into(),
        ));
    }
    Ok(())
}
```
[VERIFIED (library internals): `verify_signed_xml`/`verify_document`/`find_signode` source read directly from `~/.cargo/registry/.../samael-0.0.19/src/crypto.rs` and `src/xmlsec/xmldsig.rs`; `Response.assertion` field declaration read directly from `response.rs:35` and confirmed scalar via `quick_xml::de::from_str`. [ASSUMED] the specific `bind_signature_to_assertion` code shape above (XPath queries, `libxml::xpath::Context` API surface) is my own security-engineering design based on reading `libxml`'s presence as a `samael` dependency, NOT verified against `libxml` crate's actual public API docs in this session — **the planner/implementer must confirm the exact `libxml::xpath::Context`/`findnodes` method names and signatures against the resolved `libxml` version before writing this code** (docs.rs was inaccessible via WebFetch during this research session — 403).]

### Pattern 6: Reset-link `action_url` construction (mirror the GDPR precedent, SECFIX-06)
**What:** `handlers/gdpr.rs:394-408` already builds a relative-path `action_url` and puts it in `template_context` for the `DeletionScheduled`/`ExportReady` mail types. `password_reset.rs`/`email_verification.rs` do NOT do this today — they only pass `{token, expiry_time}` while the templates (`axiam-email/src/template.rs:161,178`) expect `{{action_url}}`.
**Example:**
```rust
// Source: crates/axiam-api-rest/src/handlers/gdpr.rs:394-398 (existing pattern to mirror)
let cancel_url = format!(
    "/api/v1/auth/account/delete/cancel?token={}",
    raw_cancel_token
);
// password_reset.rs — analogous fix (frontend PAGE route, not a backend API route,
// since a human must land on the SPA form):
let reset_url = format!(
    "/auth/reset-password?token={}&tenant_id={}",
    raw_token, req.tenant_id
);
// then: template_context: serde_json::json!({
//     "action_url": reset_url,
//     "expiry_time": expires_at.to_rfc3339(),
// }),
```
[VERIFIED: `gdpr.rs:394-408`, `template.rs:161,178`, `password_reset.rs:106-118` all read directly; confirmed via grep that `MailType::PasswordReset`/`MailType::EmailVerification` are produced ONLY by these two handlers, so there is no other code path already building this URL]

### Anti-Patterns to Avoid
- **Per-service `with_interceptor` triplication (SECFIX-01):** copy-pasting the same `AuthInterceptor::new(auth_config.clone())` three times is what the discretion note explicitly asks to avoid — prefer the single `.layer(...)` at `Server::builder()`.
- **Regex/string-search XML validation (SECFIX-04):** never use string matching to find `Assertion`/`Signature`/`Reference` elements — use a real XML parser with namespace-aware XPath (`local-name()='X'` to be namespace-prefix-agnostic, since IdPs vary `saml:`/`saml2:`/no-prefix conventions).
- **Constant-key fallback of any kind (SECFIX-03):** `unwrap_or([0u8;32])` was already flagged once (SEC-012 on PKI) and reappeared verbatim on webhook (SEC-059) — this is a **pattern class**, not a one-off; grep the whole workspace for `unwrap_or(\[0u8` / `unwrap_or_default()` on any `[u8; N]` key type before closing this phase.
- **Trusting client-supplied `session_id`/`tenant_id`/`user_id` on any authenticated route** — every SECFIX in this phase reinforces the same rule already established by `authorization.rs`: identity comes from verified JWT claims, body fields are cross-validated and rejected on mismatch, never trusted outright.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| gRPC bearer-token auth | A second interceptor implementation for User/Token services | The existing `AuthInterceptor` (`middleware/auth.rs`), applied via `.layer(...)` | Already implements token extraction, `validate_access_token`, and claims-injection correctly; duplicating it risks subtle divergence (e.g., different error messages leaking info) |
| AES-256-GCM encrypt/decrypt | A second crypto helper for webhook secrets | `axiam_auth::crypto::{aes256gcm_encrypt, aes256gcm_decrypt}` (already imported in `webhook.rs`) | Already used for PKI and federation secrets; one reviewed AEAD implementation reduces the crypto attack surface |
| XML signature verification | A hand-rolled XML-DSig verifier | `samael::crypto::verify_signed_xml` (keep using it — it correctly rejects unsigned/tampered documents) | XML-DSig is notoriously easy to get wrong (that's precisely what XSW exploits); do NOT try to replace `samael`'s verification, only **supplement** it with the missing binding check |
| Failed-login lockout counter | A second lockout implementation inside `axiam-api-grpc` | `UserRepository::increment_failed_logins` (already a trait method used by `AuthService::record_failed_login`, `axiam-db/src/repository/user.rs`) | The gRPC `UserServiceImpl<U: UserRepository>` already holds a `U: UserRepository` — it can call the same trait method directly; extract `record_failed_login`/`reset_failed_logins` as free functions (or a small trait-extension) usable from both `axiam-auth::AuthService` and `axiam-api-grpc::services::user` rather than reimplementing the SEC-032 atomic-increment logic a second time |

**Key insight:** every SECFIX in this phase has either (a) an exact working sibling implementation already in the codebase to copy verbatim (SECFIX-01's `authorization.rs`, SECFIX-02's `grant_to_role`, SECFIX-03's `axiam-pki`), or (b) a `#[serde(skip_serializing)]`/existing-cookie-clearing mechanism already doing 90% of the work (SECFIX-05). The only finding requiring genuinely new logic is SECFIX-04's raw-XML binding check — everything else is "find the guarded pattern already in this file and apply it to the unguarded twin."

## Common Pitfalls

### Pitfall 1: Assuming `TokenService`'s RPCs need the same body cross-validation as `AuthorizationService`
**What goes wrong:** A planner/implementer copy-pastes the `body_tenant_id != claims_tenant_id` check from `authorization.rs` onto `validate_token`/`introspect_token` and it fails to compile (no `tenant_id` field on `ValidateTokenRequest`/`IntrospectTokenRequest`).
**Why it happens:** REQUIREMENTS.md's SECFIX-01 acceptance criteria text groups `GetUser, ValidateCredentials, IntrospectToken` together as "read tenant_id/user_id from ValidatedClaims and reject any mismatched body field" — but `IntrospectTokenRequest` has no such body field (see Pattern 2 above).
**How to avoid:** For `TokenService`, the fix is caller-authentication only (require the layer to reject unauthenticated calls); no body-vs-claims comparison is possible or needed.
**Warning signs:** Compile error referencing a nonexistent `req.tenant_id` on a `TokenService` RPC.

### Pitfall 2: Believing `verify_signature()` passing means the consumed assertion is trustworthy (SECFIX-04)
**What goes wrong:** Treating `self.verify_signature(xml.as_bytes(), &config)?;` (line 378) as sufficient and only adding the `Destination`/`InResponseTo` checks, leaving the actual XSW hole (signature↔assertion binding) open — this is EXACTLY what the 2026-07-01 review already found ("Destination validation exists but every call site passes None... there is still no XSW binding").
**Why it happens:** The existing code structure makes it look like signature verification already "protects" everything that follows, since it runs first and returns an `Err` on failure. But `Ok(())` from `verify_signed_xml` only proves *some* valid signature exists somewhere in the document — not that it covers the specific data being trusted.
**How to avoid:** Add the `bind_signature_to_assertion`-style check (Pattern 5) as a mandatory step between `verify_signature()` and `extract_assertion_claims(assertion)`.
**Warning signs:** A test that duplicates the well-signed assertion fixture and adds a second forged `<Assertion>` sibling still gets provisioned/logged in.

### Pitfall 3: Fixing the frontend body shape for reset/resend without checking the backend actually builds a usable link (SECFIX-06)
**What goes wrong:** Threading `tenant_id`/`email` into `requestPasswordReset`/`confirmPasswordReset`/`resendVerification` makes the REQUEST calls succeed (no more 400s), but the emailed reset/verification link is still `{{action_url}}` (unsubstituted) or empty, because `password_reset.rs`/`email_verification.rs` never populate `action_url` in `template_context` today.
**Why it happens:** CQ-F27/SEC-044 were both scoped by the reviewers as "frontend sends wrong body" — neither review commit inspected whether the SERVER-SIDE email link construction was even wired, because they were testing the JSON contract, not the actual email content.
**How to avoid:** Verify (ideally with a test asserting `template_context["action_url"]` is present and well-formed) that both `request_reset` and `resend_verification` build and enqueue an `action_url`, mirroring Pattern 6.
**Warning signs:** `render_email` output (or a test snapshot of it) still contains the literal string `{{action_url}}`.

### Pitfall 4: Forgetting `resend_verification`'s body also needs `email`, not just `tenant_id`
**What goes wrong:** `resendVerification` in `auth.ts` currently sends NO body at all (`api.post<void>("/api/v1/auth/resend-verification")`), but `ResendVerificationRequest` (`email_verification.rs:37-40`) requires BOTH `tenant_id: Uuid` AND `email: String`. Adding only `tenant_id` still 400s.
**Why it happens:** `resendVerification`'s current TSDoc comment mislabels it as "authenticated endpoint" — it is not; the backend handler takes no `AuthenticatedUser` extractor and is registered as a public/unauthenticated route.
**How to avoid:** The frontend needs BOTH tenant context AND the user's email address at the point `resendVerification()` is called — check `ProfilePage.tsx`'s current call site (only other consumer) to see whether it currently has the user's email in scope (it should, since it's an authenticated page — the frontend auth store has the current user's email even though the backend RPC itself doesn't require auth).
**Warning signs:** `resend_verification` still returns 400 after the `tenant_id`-only fix.

## Runtime State Inventory

> Not applicable — Phase 23 is bug-fix/hardening work, not a rename/refactor/migration phase. No table names, IDs, or external service registrations are being renamed.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `protoc` | `axiam-api-grpc` build.rs (`tonic_prost_build::configure().compile_protos(...)`) | ✗ (not on PATH in this research sandbox) | — | Must be installed in the actual dev/CI environment; verify with `protoc --version` before `cargo build -p axiam-api-grpc`. Not a Phase-23-specific requirement — this crate already builds today, so the dev environment presumably already has it; only flag if planning to run `cargo check -p axiam-api-grpc` in a fresh sandbox |
| `libxml2` / `libxmlsec1` (system libs, `xmlsec` feature) | `samael` (SAML support in `axiam-federation`) | Not probed directly (headers, not a CLI) | — | If unavailable on a build host, the workspace already documents a fallback: `--no-default-features` on `axiam-federation` disables SAML (OIDC federation unaffected) — see `Cargo.toml:31-39` comments. SECFIX-04 work requires these libs to be present; there is no code-only fallback for this specific phase's SAML fix |
| `cargo fetch` / crates.io registry access | Confirming `samael`/`tonic`/`libxml` source during research and before implementation | ✓ (confirmed working via the pre-configured agent proxy) | `samael` 0.0.19, `tonic` 0.14.6, `libxml` (transitive) all present in `~/.cargo/registry/src/` after `cargo fetch --manifest-path Cargo.toml` | — |
| `docs.rs` / raw GitHub source browsing | Verifying `libxml` crate's public `xpath::Context`/`findnodes` API surface for Pattern 5 | ✗ (WebFetch returned 403 on docs.rs; GitHub raw/API access to `njaremko/samael` and `KWARC/rust-libxml` blocked in this session) | — | Planner/implementer must locally run `cargo doc -p libxml --open` (or read the vendored source directly, as done for `samael` in this session) to confirm exact API names before writing Pattern 5's XPath code |

**Missing dependencies with no fallback:** none block *research* completion; `libxml2`/`libxmlsec1` block *implementation* of SECFIX-04 specifically if absent from the actual build host (verify separately from this research session, which could not shell out to a real dev container).

**Missing dependencies with fallback:** `protoc` absence would block SECFIX-01 changes to `axiam-api-grpc` — but this crate already compiles in the existing CI/dev setup (proven by pre-existing `grpc_auth_test.rs`/`grpc_authz_test.rs`), so this is very unlikely to be a real blocker, just an artifact of this sandboxed research environment lacking it.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` (per-crate, `#[tokio::test]` for async) + Playwright (`frontend/e2e/`, execution gated in CI under CORR-04/Phase 26 — not gating in Phase 23) |
| Config file | Workspace `Cargo.toml`; no dedicated per-crate test config beyond standard `tests/` directories |
| Quick run command | `cargo test -p <crate> <test_name>` (e.g. `cargo test -p axiam-api-grpc grpc_reject_without_token`) |
| Full suite command | `cargo test -p <crate>` per touched crate (NEVER `cargo test --workspace` per CLAUDE.md/CONTEXT.md discipline) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SECFIX-01 | `UserService`/`TokenService` reject calls with no bearer token | integration (negative) | `cargo test -p axiam-api-grpc --test grpc_auth_test` | ✅ file exists (`grpc_auth_test.rs`) — add new test fns for User/Token services |
| SECFIX-01 | Cross-tenant `GetUser` read denied | integration (negative) | `cargo test -p axiam-api-grpc --test grpc_authz_test` (or a new `grpc_user_test.rs`) | ✅ `grpc_authz_test.rs` exists as a pattern reference; new file/fn needed |
| SECFIX-01 | gRPC `ValidateCredentials` accrues lockout via shared helper | unit/integration | `cargo test -p axiam-auth` (shared helper) + `cargo test -p axiam-api-grpc` (call-site) | ❌ Wave 0 — no existing lockout test at the gRPC layer |
| SECFIX-02 | Cross-tenant grant via `grant_to_role_with_scopes` rejected | integration (negative) | `cargo test -p axiam-db --test req14_tenant_isolation_test permission_grant_with_scopes_cross_tenant_rejected` | ❌ Wave 0 — repoint/extend `req14_tenant_isolation_test.rs:162-199` |
| SECFIX-03 | Server boots with key unset; webhook create refused | integration | `cargo test -p axiam-server` (or `-p axiam-api-rest`) | ❌ Wave 0 |
| SECFIX-03 | Round-trip: stored ciphertext ≠ plaintext | unit | `cargo test -p axiam-api-rest webhook_secret_encrypt_decrypt_round_trip` | ✅ round-trip helper test exists (`webhook.rs` `#[cfg(test)]`) but is NOT wired to the create/update handler path — need a new handler-level test |
| SECFIX-04 | XSW: wrapped/duplicated assertion rejected | integration (negative) | `cargo test -p axiam-federation` or `-p axiam-server --test req5_saml_e2e` | ❌ Wave 0 — new fixture (`xsw_wrapped_response.xml`) needed via `tests/fixtures/saml/generate.sh` |
| SECFIX-04 | Destination/InResponseTo mismatch rejected | integration (negative) | same as above | ❌ Wave 0 |
| SECFIX-05 | Logout revokes session; reload doesn't re-authenticate | integration | `cargo test -p axiam-api-rest` (existing auth test module, extend) | ❌ Wave 0 — extend existing auth handler tests |
| SECFIX-06 | Reset/resend request bodies match backend DTOs | contract (frontend) | Playwright spec update (not CI-gated until CORR-04) | Partial — existing contract spec asserts paths only, per CQ-F36/CQ-F27; body-assertion extension is this phase's job even though CI execution isn't |
| SECFIX-06 | Enumeration-safety preserved | unit | `cargo test -p axiam-api-rest` (existing D-15 tests in `password_reset.rs`/`email_verification.rs` — extend, don't regress) | ✅ existing tests present (`password_reset.rs:221-373`) |

### Sampling Rate
- **Per task commit:** the single most relevant `cargo test -p <crate> <test_name>` for the file just touched
- **Per wave merge:** `cargo test -p <crate>` (full crate suite) for every crate touched in that wave
- **Phase gate:** full per-crate suites green across all six touched crates before `/gsd-verify-work`; frontend `eslint . && tsc -b` clean if `frontend/` touched (Playwright itself is not CI-gating per CORR-04, but SHOULD be run locally by the implementer to sanity-check SECFIX-05/06)

### Wave 0 Gaps
- [ ] `crates/axiam-api-grpc/tests/grpc_auth_test.rs` — add `user_service_rejects_without_token`, `token_service_rejects_without_token`
- [ ] `crates/axiam-api-grpc/tests/` — new or extended file for cross-tenant `GetUser` negative test
- [ ] `crates/axiam-db/tests/req14_tenant_isolation_test.rs` — repoint/add `grant_to_role_with_scopes` cross-tenant test (both empty-scope and scoped branches)
- [ ] `crates/axiam-federation/tests/fixtures/saml/generate.sh` — extend to emit an `xsw_wrapped_response.xml` fixture (duplicate/wrapped assertion, original signature intact)
- [ ] `crates/axiam-server/tests/req5_saml_e2e.rs` (or a new `axiam-federation` integration test) — XSW negative test + Destination/InResponseTo negative tests
- [ ] `crates/axiam-api-rest/src/handlers/auth.rs` test module — logout-then-reload-doesn't-reauthenticate test
- [ ] `crates/axiam-api-rest/src/handlers/webhooks.rs` — new handler-level test proving `create`/`update` actually encrypt (not just the existing standalone round-trip unit test)
- [ ] `frontend/e2e/` contract spec — extend to assert request **bodies** for reset/confirm/resend (even though not CI-gated until Phase 26, write it now per REQUIREMENTS.md's phase 23 verification baseline: "Security fixes additionally get a negative test")

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Argon2id password hashing (existing, unchanged); gRPC bearer-JWT via `AuthInterceptor` (SECFIX-01) |
| V3 Session Management | yes | JWT `jti` = session ID; server-side revocation on logout (SECFIX-05); session-active check already at `extractors/auth.rs:106-115` |
| V4 Access Control | yes | Tenant-isolation `LET/THROW` SurrealQL guards (SECFIX-02); claims-derived identity, never body-trusted (SECFIX-01) |
| V5 Input Validation | yes | DTO field validation already present (`validation_err` helpers); reset/verify DTOs need `tenant_id` threading (SECFIX-06) without weakening validation |
| V6 Cryptography | yes | AES-256-GCM via `axiam_auth::crypto` (never hand-roll — reuse for webhook secret, SECFIX-03); XML-DSig via `samael`/`xmlsec1` (never hand-roll — SECFIX-04 only supplements with binding logic, does not replace verification) |
| V13 API and Web Service | yes | gRPC service-level auth chokepoint (SECFIX-01); REST tenant-scoped endpoints (SECFIX-02, 03, 05, 06) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Unauthenticated gRPC service (mesh peer reads/brute-forces cross-tenant) | Spoofing, Information Disclosure | `AuthInterceptor` on every service (SECFIX-01) |
| Cross-tenant RELATE via unguarded repository method | Elevation of Privilege | `LET/THROW` tenant predicate at the query layer, not just the handler layer (SECFIX-02) |
| Constant/all-zero encryption key fallback | Tampering, Information Disclosure | `Option<[u8;32]>` + fail-closed at point-of-use, never a constant default (SECFIX-03) |
| XML Signature Wrapping (XSW) | Tampering, Spoofing | Bind the verified signature `Reference` to the consumed data element; reject on cardinality mismatch (SECFIX-04) |
| Session fixation / stale-cookie reuse after logout | Spoofing | Server-derived session revocation from verified JWT `jti`, cookies cleared server-side (SECFIX-05) |
| Account/tenant enumeration via differential responses | Information Disclosure | Uniform response body + timing regardless of account existence/federation status (SECFIX-06/D-05 — already implemented, must not regress) |

## Sources

### Primary (HIGH confidence — read directly from live code/dependency source this session)
- `crates/axiam-api-grpc/src/{server.rs, middleware/auth.rs, services/{authorization,user,token}.rs}` — SECFIX-01 exact gaps
- `proto/axiam/v1/{user,token}.proto` — confirms `IntrospectTokenRequest`/`ValidateTokenRequest` body shape (no tenant_id field)
- `crates/axiam-db/src/repository/permission.rs:314-459`, `crates/axiam-db/src/schema.rs:275-284` — SECFIX-02 exact guard pattern + scope table schema
- `crates/axiam-db/tests/req14_tenant_isolation_test.rs:160-199` — confirms the misdirected test
- `crates/axiam-server/src/main.rs:52-68,375-408` — SECFIX-03 exact fallback + `load_key_from_env` behavior
- `crates/axiam-pki/src/config.rs:10-11`, `crates/axiam-pki/src/ca.rs:105-108` — SECFIX-03 pattern to mirror
- `crates/axiam-api-rest/src/webhook.rs`, `crates/axiam-api-rest/src/handlers/webhooks.rs`, `crates/axiam-db/src/repository/webhook.rs`, `crates/axiam-core/src/models/webhook.rs` — SECFIX-03 write-path gap (create/update never call `encrypt_webhook_secret`; `UpdateWebhook` has no `secret` field)
- `crates/axiam-federation/src/saml.rs:322-593` — SECFIX-04 `handle_saml_response`/`verify_signature` full flow
- `~/.cargo/registry/.../samael-0.0.19/src/crypto.rs:90-109`, `src/xmlsec/xmldsig.rs:105-225`, `src/schema/response.rs:1-35` — [VERIFIED: source inspected] the exact library-internal cause of the XSW gap
- `crates/axiam-api-rest/src/handlers/federation.rs:839-879,1449-1535` — both `handle_saml_response` call sites, confirms `None` passed for Destination/InResponseTo on the authenticated path and empty-string ACS URL on the public path's `build_authn_request` call
- `crates/axiam-federation/tests/fixtures/saml/{README.md,generate.sh}` — existing fixture generation infra to extend for the XSW negative test
- `crates/axiam-api-rest/src/handlers/auth.rs:97-106,336-367`, `crates/axiam-api-rest/src/extractors/auth.rs:76-119` — SECFIX-05 confirms `session_id` already equals `jti`
- `frontend/src/components/layout/Topbar.tsx:89-98` — SECFIX-05 frontend gap
- `crates/axiam-api-rest/src/handlers/{password_reset,email_verification}.rs` — SECFIX-06 DTOs + missing `action_url` construction
- `crates/axiam-email/src/template.rs:161,178` — confirms templates expect `{{action_url}}`
- `crates/axiam-api-rest/src/handlers/gdpr.rs:394-408` — SECFIX-06 existing `action_url` construction pattern to mirror
- `frontend/src/services/auth.ts`, `frontend/src/pages/auth/{ForgotPasswordPage,ResetPasswordPage,VerifyEmailPage}.tsx` — SECFIX-06 frontend gaps; `VerifyEmailPage.tsx` is the proven working reference pattern (`?token=…&tenant_id=…`)
- `crates/axiam-auth/src/service.rs:202-266,1035-1069` — D-06 shared lockout helper source (`record_failed_login`/`reset_failed_logins`)
- `.planning/REQUIREMENTS.md` (v1.2 SECFIX-01..06 section, lines 572-663) — acceptance criteria
- `claude_dev/security-review-postremediation.md` (lines 40-84) — SEC-003/058/059/005/015/044 authoritative descriptions
- `claude_dev/code-review-postremediation.md` (lines 82-176) — CQ-B44 (out of scope for Phase 23, confirmed by REQUIREMENTS.md traceability), CQ-F05/F27/F36 cross-refs

### Secondary (MEDIUM confidence)
- WebSearch: "tonic grpc rust apply single tower Layer with Interceptor across multiple services" — confirmed `Server::builder().layer(...)` is the documented cross-service pattern; exact 0.14.6 free-function name (`tonic::service::interceptor`) not independently re-verified against vendored source (flagged [ASSUMED] in Pattern 1)
- WebSearch: "samael rust SAML XSW verify_signature assertion id reference binding" — general XSW background confirmed against public security literature (Hackmanit, HackTricks); the AXIAM-specific mechanism was independently confirmed via direct source reading (promoted to Primary for the code-specific claims)

### Tertiary (LOW confidence)
- `libxml` crate's public `xpath::Context`/`findnodes` API surface (Pattern 5) — NOT independently verified in this session (docs.rs returned 403, GitHub raw/API access blocked). Implementer must confirm exact method names before writing this code.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `tonic::service::interceptor(...)` exists as a free function producing a `tower::Layer` in tonic 0.14.6, usable at `Server::builder().layer(...)` | Architecture Patterns, Pattern 1 | If it doesn't exist under that name, the fallback (`tower::layer::layer_fn` wrapping `InterceptedService::new`) is guaranteed to compile since `with_interceptor` already uses `InterceptedService` internally — low risk, just extra implementer verification step |
| A2 | `libxml::xpath::Context::new`/`findnodes` (or equivalently-named methods) exist with a signature usable for the XSW binding check in Pattern 5 | Architecture Patterns, Pattern 5 | If the API differs, the *design* (exactly-one-Assertion + Reference-URI-matches-consumed-ID) still holds; only the specific Rust call syntax needs adjustment — implementer should run `cargo doc -p libxml --open` locally before writing this code |
| A3 | The correct fix for `saml_acs`'s (authenticated flow) missing `InResponseTo`/`Destination` context is to add a stored-state row analogous to `FederationLoginState` (used by the public flow), rather than trusting client-supplied values | SECFIX-04 discussion (see Open Questions) | If wrong, an alternative (e.g., deriving ACS URL from a per-tenant `FederationConfig` field) may be preferred — this is a design decision, not a verified fact, and is called out explicitly in Open Questions for planner/human resolution |
| A4 | Extending `RequestResetBody`/`ConfirmResetBody`/`ResendVerificationRequest` with a `tenant_slug: Option<String>` alternative (mirroring `handlers/auth.rs:269-285`) is an acceptable, in-scope way to satisfy "tenant slug carried in the page URL" (D-04) for the *initial* request pages that have no token yet | SECFIX-06 discussion (see Open Questions) | If the human intends "tenant slug" literally only for display/routing (not as an alternative DTO field), the alternative is to resolve slug→id via the already-working `handlers/auth.rs`/`handlers/federation.rs` pattern in the frontend indirectly (e.g., reusing the login flow's resolved tenant context) — needs discuss-phase or planner judgment call |

**If this table is empty:** N/A — see rows above.

## Open Questions

1. **How does `ForgotPasswordPage` (no token yet) learn the tenant slug/id, concretely?**
   - What we know: D-04 says the URL carries the tenant slug; `LoginPage.tsx`'s "Forgot password?" link (`LoginPage.tsx:334`) currently has no query params; `LoginPage` itself only has a locally-typed `tenantSlug` in component state (not yet resolved to a `tenant_id` UUID) at the point a user might click through.
   - What's unclear: whether the fix should (a) thread the LoginPage's locally-typed slug into the `/auth/forgot-password?tenant=<slug>` link and have the backend `RequestResetBody` accept an optional `tenant_slug` (mirroring the existing `handlers/auth.rs`/`federation.rs` either-or pattern), or (b) some other mechanism.
   - Recommendation: (a) is the most consistent with an already-proven, already-reviewed codebase pattern (3 other handlers already do exactly this slug/id resolution) and requires the least net-new code. Flag to the planner as the default; confirm with human if scope concerns arise (adding an optional field to 2-3 DTOs plus their handler resolution logic is a small, mechanical, well-precedented change, not a "refactor").

2. **Does the confirm-reset/verify-email link need `tenant_slug` in the URL, or is a raw `tenant_id` (UUID) sufficient, given `VerifyEmailPage.tsx` already works with a raw `tenant_id` query param?**
   - What we know: `VerifyEmailPage.tsx` (an ALREADY-SHIPPED, working page per CQ-F27's "verify-email... hits real endpoint") reads `?token=…&tenant_id=…` directly as a UUID string, with no slug involved. The backend never needs the "slug" for the confirm/verify step — it only needs `tenant_id` to validate the token belongs to that tenant.
   - What's unclear: D-04's phrase "tenant slug carried in the page URL" may be describing the INITIAL-request pages only (see Open Question 1) rather than a hard requirement that confirm/verify links use a human-readable slug too.
   - Recommendation: mirror `VerifyEmailPage.tsx` exactly for `ResetPasswordPage.tsx` (raw `tenant_id` UUID in the URL, server-generated since the server already knows the UUID when building the email) — this is lower-risk than introducing slug resolution on the confirm path, and is consistent with the already-shipped, reviewed pattern.

3. **Is a shared crate-level "lockout helper" (D-06) expected to be a formal refactor (e.g., a new `axiam-auth::lockout` module) or is calling the existing `UserRepository::increment_failed_logins` trait method directly from `axiam-api-grpc::services::user` (bypassing `AuthService` entirely) sufficient?**
   - What we know: `AuthService::record_failed_login`/`reset_failed_logins` (`service.rs:1035-1069`) are thin private wrappers around `UserRepository::increment_failed_logins`/`.update(...)`, already generic over the repository trait. `UserServiceImpl<U: UserRepository>` already holds the same trait bound.
   - What's unclear: whether extracting these two methods into a small public shared function (in `axiam-auth`, since both `axiam-auth` and `axiam-api-grpc` already depend on it) is required by D-06's wording ("Factor... into a shared helper"), or whether directly calling the already-public `UserRepository::increment_failed_logins` trait method from both call sites (without extracting `AuthService`'s private wrapper) already satisfies "no unmetered credential-check path."
   - Recommendation: extract a small shared function (e.g. `axiam_auth::lockout::{record_failed_login, reset_failed_logins}`) so the LOCKOUT-THRESHOLD-CHECK-AND-INCREMENT sequencing logic (not just the raw repository call) is identical on both paths — this is the more literal reading of "shared helper" and avoids two independently-maintained copies of the sequencing logic (lockout check → verify → increment-on-failure/reset-on-success) even though today it's a thin wrapper.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new libraries; every existing dependency version confirmed via `Cargo.lock` and successful `cargo fetch`
- Architecture (SECFIX-01, 02, 03, 05): HIGH — exact working sibling patterns exist in the same files; verified by direct source reading
- Architecture (SECFIX-04): MEDIUM — the *diagnosis* is HIGH confidence (library-internal source read directly proves the exact gap), but the *specific remediation code* (Pattern 5) uses an unverified `libxml` API surface — implementer must confirm method names before coding
- Architecture (SECFIX-06): MEDIUM-HIGH — the diagnosis (missing `action_url`, DTO shape mismatches) is HIGH confidence; the exact tenant-slug-vs-tenant-id URL mechanics for the *initial* request pages is a design decision flagged in Open Questions
- Pitfalls: HIGH — every pitfall traces to a specific, re-verified code location or library-internal fact, not general security folklore

**Research date:** 2026-07-03
**Valid until:** Re-verify file:line references if any of `crates/axiam-api-grpc`, `crates/axiam-db/src/repository/permission.rs`, `crates/axiam-server/src/main.rs`, `crates/axiam-federation/src/saml.rs`, `crates/axiam-api-rest/src/handlers/{auth,federation,password_reset,email_verification,webhooks}.rs`, or `frontend/src/{services/auth.ts,pages/auth/*,components/layout/Topbar.tsx}` receive further commits before this phase is planned/executed (30-day validity is generous for a codebase under active multi-phase development; re-grep before planning if more than a few days have passed).
