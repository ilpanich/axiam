# AXIAM — Full Security Review (updated re-assessment)

- **Date**: 2026-06-09 (update of the 2026-06-09 review done at `6f2676d`)
- **Scope**: Entire repository at commit `d69323b` (merge of the Phase 01–06 remediation work: cookie-based auth, RBAC enforcement, federation signature verification, GDPR/email delivery, deployment hardening — 51 commits, ~52k insertions since the previous review).
- **Method**: Per-finding re-verification of all 43 previous findings (`SEC-001`…`SEC-043`) against the current code, line-level review of all security-relevant new code (extractors/auth.rs cookie auth, middleware/csrf.rs, middleware/authz.rs + permissions.rs, handlers/bootstrap.rs, handlers/gdpr.rs + GDPR repos, federation oidc/saml/jwks_cache/secrets, email_config, mail consumer, cleanup task, docker/k8s/CI), plus `cargo audit`-equivalent lockfile checks, `npm audit`, and full route-table inspection.
- **Companion document**: [`code-review.md`](code-review.md). The top blocking item — **the server binary does not compile at this commit** — is tracked there as **CQ-B37** and gates every fix below.

Finding IDs are stable. Statuses: ✅ FIXED (verified), 🔶 PARTIAL (core improved, residual risk listed), ❌ OPEN (unchanged or equivalent). New findings continue the sequence at SEC-044.

---

## Executive summary

The remediation wave was real and well-aimed: **RBAC is now enforced on every REST handler** (SEC-001 fixed, with negative tests), **OIDC/SAML federation now verifies signatures** (JWKS + xmlsec, fail-closed, with tampered-fixture tests), the **MFA-challenge-as-access-token bypass is closed**, **WebAuthn fails closed**, **password reset revokes sessions**, tokens moved out of `sessionStorage` into **httpOnly SameSite=Strict cookies with CSRF double-submit on the auth scope**, security headers + CSP/HSTS landed in nginx and middleware, dependency advisories were cleared and **CI now gates audit/deny/trivy/npm-audit**.

What remains, in order of severity:

1. **Two of the original criticals are still exploitable.** Organizations/tenants/CA endpoints check *permissions* but never that the caller belongs to the path `org_id` — cross-organization IDOR stands (SEC-002). gRPC still has **no authentication** and is still publicly ingressed (SEC-003).
2. **A new class of "wired-but-broken" issues.** The frontend's password-reset/forgot/verify-email/change-password/MFA-setup flows call endpoints that don't exist (SEC-044); silent token refresh is blocked by the CSRF middleware it doesn't know about (CQ-F28); the federation secret-at-rest pipeline encrypts on backfill but **never decrypts at use and blanks the plaintext**, breaking OIDC login after the first restart (SEC-045); the k8s manifests set env vars with the wrong prefix so production config is silently ignored (SEC-052).
3. **Tenant-isolation gaps below the handler layer** — role/permission edge mutations still ignore `tenant_id` (SEC-007).
4. Unfinished hygiene: zero-key PKI fallback (SEC-012), unbounded pagination (SEC-010), error-detail leakage (SEC-011), TOTP replay (SEC-008), webhook SSRF (SEC-019), frontend logout still client-side (SEC-015).

### Current finding counts (active = OPEN + PARTIAL)

| Severity | Active | Of which new this round |
|---|---|---|
| Critical | 2 | 0 |
| High | 10 | 2 |
| Medium | 24 | 11 |
| Low | 7 | 1 |

14 previous findings verified **fixed** (see the Resolved table at the end).

### Top remediation priorities (suggested order)

1. **CQ-B37** — make the server compile again (dev-deps vs cleanup.rs); nothing ships until this is green.
2. **SEC-002** — add the `path.org_id == user.org_id` check (the settings.rs pattern) to organizations/tenants/ca_certificates; **SEC-003** — gRPC auth interceptor + remove public ingress.
3. **SEC-044 / CQ-F27 / CQ-F28** — repair the broken frontend auth flows and the CSRF-blocked refresh (auth lifecycle is currently non-functional past the happy path).
4. **SEC-045** — wire federation secret decryption into the OIDC callback and encrypt on create/update.
5. **SEC-007** (tenant-scope edge mutations), **SEC-012** (zero-key), **SEC-010/SEC-011** (clamp pagination, generic 5xx bodies).
6. **SEC-052 / SEC-053** — fix k8s env prefixes/secrets and NetworkPolicy receiver rules (the k8s deployment cannot work as committed).

---

## Critical findings (active)

### SEC-002 [CRITICAL] 🔶 PARTIAL — Cross-organization IDOR on organizations / tenants / CA-certificates endpoints
- **File**: `crates/axiam-api-rest/src/handlers/organizations.rs:74-137`, `tenants.rs:143-220`, `ca_certificates.rs:28-128`
- **What changed**: Handlers now run `RequirePermission` checks (`organizations:get/update/delete`, etc.) and tenants verifies `tenant.organization_id == path.org_id`.
- **What remains**: **No handler compares the caller's `org_id` (JWT) to the path `org_id`** — grep for `user.org_id` in all three modules returns nothing. A user with `organizations:get`/`tenants:*` in org A can read/update/delete org B, manage org B's tenants, and manage org B's CA certificates. The correct pattern already exists in `settings.rs:38`.
- **Fix**: `if path.org_id != user.org_id { return 403/404 }` on every org-nested route (or scope the authz resource to the org). Restrict org create/list to system admins. Add cross-org negative tests.

### SEC-003 [CRITICAL] ❌ OPEN — gRPC services have no authentication and are exposed via public ingress
- **File**: `crates/axiam-api-grpc/src/server.rs:51-57` (only a rate-limit layer was added — `middleware/rate_limit.rs`); `k8s/ingress.yml` still exposes `grpc.axiam.example.com → :50051`
- **Issue**: No JWT/mTLS interceptor; `CheckAccess`/`BatchCheckAccess`/`UserService` still trust request-supplied `tenant_id`/`subject_id`. Anyone reaching the endpoint reads any user, brute-forces `ValidateCredentials` (which still never increments lockout — SEC-026b), and queries authz decisions for any tenant.
- **Fix**: Tonic interceptor validating bearer JWT or mTLS identity; derive `tenant_id` from verified claims; remove from public ingress (mesh-internal + mTLS).

---

## High findings (active)

### SEC-005 [HIGH→ was CRITICAL] 🔶 PARTIAL — SAML: signature verification landed; protocol checks still missing
- **File**: `crates/axiam-federation/src/saml.rs`
- **Fixed**: `verify_signature` (saml.rs:513-527) fails closed via `samael::crypto::verify_signed_xml` against the configured IdP cert; missing cert → `ConfigIncomplete`; Conditions NotBefore/NotOnOrAfter (383-398) and AudienceRestriction (401-412) validated; **assertion-ID replay protection** with UNIQUE index (`saml_assertion_replay`, schema.rs:392-400, repo + cleanup sweep); tampered/unsigned fixture tests + `req5_saml_e2e.rs`.
- **Still missing**: `InResponseTo` never checked (unsolicited responses accepted); `Destination`/`Recipient`/`SubjectConfirmationData` not validated; SP metadata still advertises `WantAssertionsSigned="false"` / `AuthnRequestsSigned="false"` (saml.rs:487-488); no explicit XSW defense — the code verifies *a* signature in the document then consumes `response.assertion` without binding the signed element to the consumed one; assertions with no `Conditions` block are accepted.
- **Fix**: Validate InResponseTo against issued request IDs; check Destination/Recipient/SubjectConfirmation; require Conditions; set `WantAssertionsSigned="true"`; bind the verified signature reference to the consumed assertion (XSW).

### SEC-007 [HIGH] ❌ OPEN — Cross-tenant role assignment & permission grants: edge methods still ignore `tenant_id`
- **File**: `crates/axiam-db/src/repository/role.rs:320,345,477,502`; `permission.rs:314,333` (+ `grant_to_role_with_scopes`)
- **Issue**: All still take `_tenant_id` (unused) and `RELATE`/`DELETE` edges by raw UUIDs; handlers do no pre-flight ownership check on path/body IDs. A caller with `roles:assign`/`permissions:grant` can create or destroy cross-tenant edges. The correct pattern exists in `group.rs::add_member` and `certificate.rs::bind_to_service_account`.
- **Fix**: Verify both sides belong to the tenant (subquery/`THROW`) in every edge mutation; add tenant-isolation tests per method.

### SEC-008 [HIGH] ❌ OPEN — No replay protection on TOTP codes
- **File**: `crates/axiam-auth/src/totp.rs:70`; `service.rs:316,425`
- **Issue**: `check_current` with skew 1 (~90 s window); no consumed-step persistence anywhere (user model unchanged). Codes are replayable within the window.
- **Fix**: Persist last-used TOTP step per user; reject same-or-earlier steps (RFC 6238 §5.2).

### SEC-010 [HIGH] ❌ OPEN — Unbounded pagination `limit` — DoS on every list endpoint
- **File**: `crates/axiam-core/src/repository.rs:49-63` (`limit: u64`, default 50, **no clamp**); flows to `LIMIT $limit` in every repo
- **Fix**: Clamp centrally (max ~200, reject 0) in `Pagination` deserialization. Unchanged since last review.

### SEC-011 [HIGH] ❌ OPEN — Internal error details leaked in HTTP responses
- **File**: `crates/axiam-api-rest/src/error.rs:72-75` — the `error` code is now genericized to `"internal_error"`, but `message: self.0.to_string()` still serializes full `Database/Crypto/Internal/Certificate` detail into 5xx bodies.
- **Fix**: Generic message for 5xx; `tracing` for detail. Also closes SEC-039.

### SEC-012 [HIGH] ❌ OPEN — PKI encryption key still silently falls back to an all-zero key
- **File**: `crates/axiam-server/src/main.rs:335-353` (still substitutes `[0u8; 32]` with only a warning); no zero-key guard in axiam-pki (`ca.rs:147`)
- **Fix**: Fail at startup when unset; never substitute a constant key. (Note: federation/MFA/email keys got proper `Option<[u8;32]>` handling — apply the same pattern.)

### SEC-015 [HIGH] 🔶 PARTIAL — Logout: backend complete, frontend never calls it
- **Fixed**: `POST /api/v1/auth/logout` (handlers/auth.rs:364-375) invalidates the session and clears all three cookies; refresh-token revocation is complete server-side.
- **Open**: `frontend/src/components/layout/Topbar.tsx:86-89` still only does `clearAuth(); navigate("/login")`. With cookie auth this is now **worse than before**: the httpOnly cookies survive, so a page reload re-authenticates via `useAuthInit` — logout is effectively a no-op on shared machines. react-query cache also survives (CQ-F05).
- **Fix**: Call the logout endpoint + `queryClient.clear()` in `handleLogout` and on the 401-refresh-failure path. (Also see SEC-051 for the logout body `session_id` IDOR.)

### SEC-017 [HIGH] 🔶 PARTIAL — Federation IdP `client_secret`: backfill encryption landed, but create/update still plaintext and responses fixed
- **Fixed**: Boot-time backfill encrypts legacy rows (secrets.rs:108-188, AES-256-GCM, key version, audit trail; tests `federation_secret_backfill.rs`, `req5_secret_at_rest.rs`); API responses now use `FederationConfigResponse` which omits the secret.
- **Open**: `federation_config.rs:184-186,248-251` (`TODO T19.8`) — **create/update still write plaintext**, so every new/edited config is plaintext at rest until the next restart's backfill; core model still has no `#[serde(skip_serializing)]` (models/federation.rs:26-27); frontend still declares/pre-fills `client_secret` (services/federation.ts:15, FederationPage.tsx:334) — currently inert only because it calls a non-existent endpoint (CQ-F27).
- **Fix**: Encrypt at create/update; `skip_serializing` on the model; make the UI field write-only. **And see SEC-045 — the decrypt side is unwired.**

### SEC-044 [HIGH] 🆕 — Frontend security flows call endpoints that do not exist (reset / forgot / verify-email / change-password / MFA setup / resend-verification)
- **File**: `frontend/src/pages/auth/ForgotPasswordPage.tsx:15`, `ResetPasswordPage.tsx:22`, `VerifyEmailPage.tsx:20`, `profile/ChangePasswordPage.tsx:22`, `profile/MfaManagementPage.tsx:44,49`, `profile/ProfilePage.tsx:52`; backend routes live under `/api/v1/auth/*` (`server.rs:58-140`) with different names/methods/shapes (`/auth/forgot-password` vs `/api/v1/auth/reset`, GET `/auth/verify-email` vs POST `/api/v1/auth/verify-email` requiring `tenant_id`, `{code}` vs `{totp_code}`, …). Neither the vite proxy nor nginx forwards the legacy `/auth/*` XHR paths (vite.config.ts deliberately lists some as "SPA routes").
- **Impact**: Password reset, email verification, password change, MFA enrollment and resend-verification are all silently dead; verify-email shows a **false "Email verified!" success** from the SPA fallback (subsumes **SEC-030**, still open). In an IAM product these are security-recovery paths.
- **Fix**: Move all of these into the typed services layer with the real `/api/v1/auth/*` paths/methods/bodies; add a CI contract test against the OpenAPI document (the backend already has route↔OpenAPI parity tests — mirror that on the frontend).

### SEC-045 [HIGH] 🆕 — Federation secret-at-rest pipeline is never decrypted at use; backfill blanks the plaintext → OIDC federation breaks after first restart
- **File**: `crates/axiam-federation/src/secrets.rs:75-91` (`decrypt_client_secret_or_legacy` has **zero non-test call sites**); `oidc.rs:286-294` passes `&config.client_secret` (legacy plaintext column) to the token exchange; backfill sets `client_secret = ''` after encrypting (`federation_config.rs:401-411`)
- **Impact**: After the first restart with `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` set, every backfilled OIDC config sends an empty `client_secret` to the IdP — federation login fails; the only *working* state is plaintext-at-rest. Security control that disables the feature it protects.
- **Fix**: Plumb the federation key into the OIDC/SAML services and resolve the secret via `decrypt_client_secret_or_legacy` in `handle_callback`; encrypt on create/update (closes the SEC-017 remainder); add an e2e test that exercises login *after* backfill.

---

## Medium findings (active)

### SEC-016 [MEDIUM→ was HIGH] 🔶 PARTIAL — nginx: `/api` proxied; `/oauth2` + discovery still not; backend ports still published
- **Fixed**: Auth now lives under `/api/v1/auth`, which nginx proxies (`docker/nginx.conf:61-67`); prod compose requires JWT keys from env and documents itself as local-testing-only.
- **Open**: `/oauth2/*` and `/.well-known/openid-configuration` still hit the SPA fallback; `docker-compose.prod.yml:17-19` still publishes 8090/50051 plain-HTTP on the host.
- **Fix**: Add `/oauth2` + `/.well-known` proxy locations; stop publishing backend ports.

### SEC-019 [MEDIUM] ❌ OPEN — Webhook SSRF protection bypassable via DNS-resolved hostnames
- **File**: `handlers/webhooks.rs:264-296` (literal-IP + hostname denylist at registration only); delivery (`webhook.rs:75-83`) does no resolution-time check. Redirects now disabled (good).
- **Fix**: Resolve at delivery time, re-check every IP against the private-range list, pin the validated address.

### SEC-020 [MEDIUM] 🔶 PARTIAL — IP rate limiting added, but with coverage and keying gaps (see SEC-048)
- **Fixed**: actix-governor on `/auth/login`, `/auth/reset`, `/auth/password/change`, `/oauth2/token`, user register, federation public, GDPR endpoints (`server.rs:64-247`).
- **Open**: `/auth/mfa/*` (TOTP brute-force unthrottled — pairs with SEC-008), `/oauth2/introspect`, `/oauth2/revoke` uncovered; keying/distribution weaknesses are SEC-048.

### SEC-022 [MEDIUM] ❌ OPEN — AMQP authz consumer fully trusts queue messages
- **File**: `authz_consumer.rs:62-92` — unchanged; any broker client gets authz decisions for any tenant. The same trust model was **repeated** in the new mail consumer (SEC-055).
- **Fix**: Signed payloads or per-tenant queues + broker ACLs; document the broker trust boundary.

### SEC-023 [MEDIUM] 🔶 PARTIAL — Deployment credentials/logging
- **Fixed**: k8s secrets are blank placeholders; prod compose `RUST_LOG` now `axiam=info`; JWT keys env-required.
- **Open**: prod compose still ships SurrealDB `root/root` and RabbitMQ `axiam/axiam` (`docker-compose.prod.yml:30-32,102,121-122`); `k8s/server/configmap.yml` still sets `RUST_LOG: "info,axiam=debug"`.

### SEC-024 [MEDIUM] ❌ OPEN — mTLS device auth: global fingerprint lookup, no tenant/CA chain binding
- **File**: `axiam-pki/src/mtls.rs:35-77` — unchanged in substance. (`org_id` resolution by the caller is now documented and done at `handlers/auth.rs:532-542`.)
- **Fix**: Verify the presented cert chains to the tenant/org CA, not just fingerprint match; document the proxy trust dependency.

### SEC-025 [MEDIUM] ❌ OPEN — PKCE still not enforced for the authorization-code grant
- **File**: `authorize.rs:106-125`, `token.rs:217` — verified only if volunteered; all clients are confidential (secret-authenticated), which mitigates today, but OAuth 2.1 and any future public client require mandatory S256.

### SEC-026 [MEDIUM] ❌ OPEN — (a) login timing oracle; (b) gRPC `ValidateCredentials` never increments lockout
- **File**: `service.rs:188-201` (no dummy Argon2 on user-not-found); `axiam-api-grpc/src/services/user.rs:140-141` (reads `locked_until`, never records failures — unmetered brute force, compounded by SEC-003).

### SEC-028 [MEDIUM] ❌ OPEN — Reset to the same current password still passes; initial password never enters history
- **File**: `password_reset.rs:182-209` (history check excludes the live `password_hash`, which is appended after); user creation seeds no history. Reuse of *rotated* passwords is correctly blocked.

### SEC-030 [MEDIUM] ❌ OPEN — Verify-email false success (now an endpoint/method mismatch; subsumed by SEC-044)
- Backend is now `POST /api/v1/auth/verify-email` (good), but the page still GETs the unproxied legacy path → SPA 200 → false success in dev **and** prod. Tokens are never consumed.

### SEC-031 [MEDIUM] ❌ OPEN — Webhook HMAC `secret` plaintext at rest, exclusion from responses only conventional
- **File**: core `Webhook.secret` still plain `Serialize`; `WebhookResponse` convention only.

### SEC-032 [MEDIUM] ❌ OPEN — Failed-login counter still non-atomic read-modify-write
- **File**: `service.rs` `record_failed_login` writes an absolute value computed from the login-start read; no atomic `+= 1` repo method exists.

### SEC-033 [MEDIUM] ❌ OPEN — Tenant settings snapshot still freezes org security baselines
- **File**: `settings.rs` handler stores the merged row (`repository/settings.rs:482-491`); `get_effective_settings` (:524-542) re-merges by diffing the stored row against the **current** org baseline — so a field whose snapshot equals the *old* org value becomes a phantom override the moment the org changes it. Org policy changes (MFA enforcement included) still don't propagate. Storage must become sparse overrides (`Option` fields) merged at read time.

### SEC-046 [MEDIUM] 🆕 — CSRF double-submit middleware not applied to the main `/api/v1` scope
- **File**: `server.rs:58-60` (CsrfMiddleware on `/api/v1/auth` and `/oauth2` only); the `/api/v1` CRUD scope (:197-198) has only AuthzMiddleware.
- **Impact**: All cookie-authenticated state-changing CRUD relies solely on `SameSite=Strict`. The frontend already sends `X-CSRF-Token` on all mutations — enforcing it API-wide is a free defense-in-depth win.

### SEC-047 [MEDIUM] 🆕 — Authorization is fail-open by construction; stale PUBLIC_PATHS entry
- **File**: `middleware/authz.rs:102-136` checks only credential *presence*; the real check is the per-handler `RequirePermission` call — a forgotten line = silent bypass with no compile/test failure. Nothing verifies the permission **literal a handler checks** matches `ROUTE_PERMISSION_MAP` (the parity tests check route coverage, not handler behavior). `permissions.rs:197` lists `"/api/v1/auth/register"` as public though no such route exists — a latent unauthenticated route if ever added.
- **Fix**: Enforce permissions in middleware keyed off `ROUTE_PERMISSION_MAP` (single chokepoint), or add a test that exercises every mapped route with a zero-permission user and asserts 403; remove the stale public path.

### SEC-048 [MEDIUM] 🆕 — Rate limiting keyed on client-controlled `X-Forwarded-For`, per-replica in-memory
- **File**: `extractors/rate_limit.rs:23-29` — takes the **leftmost** XFF value with no trusted-proxy validation → spoofable per request unless the ingress overwrites XFF; counters are per-process (multiply by replicas, reset on restart).
- **Fix**: Rightmost-untrusted-hop extraction (configurable trusted-proxy count); shared store for multi-replica; document the ingress XFF requirement loudly.

### SEC-049 [MEDIUM] 🆕 — Bootstrap endpoint: TOCTOU race and ungated when env var unset
- **File**: `handlers/bootstrap.rs:77-171` — the "already initialized" check and admin creation are not atomic (two concurrent first-run requests can both create admins); the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` gate applies only if set — if unset, **any** caller can create the first super-admin on a fresh deployment.
- **Fix**: Single conditional/transactional create; require the env gate (or one-time setup token) unconditionally.

### SEC-050 [MEDIUM] 🆕 — Self-service user update can set own `status` → email-verification bypass
- **File**: `handlers/users.rs:209-231` — `is_own_resource` skips the `users:update` permission check, but `UpdateUserRequest` includes `status`; a `PendingVerification` user (24 h login grace) can PUT `status: "Active"` and bypass verification permanently; email change requires no re-verification.
- **Fix**: Strip `status` (and gate email changes behind re-verification) on the self-service path.

### SEC-051 [MEDIUM] 🆕 — Logout accepts an arbitrary `session_id` from the request body (same-tenant session revocation IDOR)
- **File**: `handlers/auth.rs:364-369` — revokes `body.session_id` scoped to tenant but not to `user.user_id`.
- **Fix**: Revoke the caller's own session (JWT `jti`), or verify the target session belongs to the caller.

### SEC-052 [MEDIUM] 🆕 — k8s manifests use the wrong env prefix; config silently ignored; no JWT keys in any manifest
- **File**: `k8s/server/configmap.yml` + `secret.yml` ship `AXIAM_DB__URL`-style keys (single underscore); the server reads `Environment::with_prefix("AXIAM").separator("__")` → `AXIAM__DB__URL` (`main.rs:628`). All values are silently ignored and in-code defaults win; no `AXIAM__AUTH__JWT_*` entries exist anywhere in k8s.
- **Fix**: Rename to `AXIAM__…`; add JWT/encryption key entries to the secret; add a startup log of the effective (redacted) config so this class of failure is visible.

### SEC-053 [MEDIUM] 🆕 — NetworkPolicies internally inconsistent; PSA not enforced
- **File**: `k8s/network-policy/*` — default-deny covers all pods, `server-egress.yml` allows server→DB/MQ, but **no policy allows ingress to the SurrealDB/RabbitMQ pods** and there is **no egress policy for the frontend** — the policies as committed break the deployment (inviting wholesale deletion of default-deny). `0.0.0.0/0:443` egress leaves cluster CIDR exclusions as TODOs; no SMTP egress. `k8s/namespace.yml` sets PSA `warn`/`audit` only, no `enforce`.
- **Fix**: Add receiver-side ingress policies for DB/MQ and a frontend egress policy; test with a kind/minikube e2e; enable `enforce: restricted` once green.

### SEC-054 [MEDIUM] 🆕 — JWKS fetch: no body-size cap, no private-IP guard
- **File**: `crates/axiam-federation/src/jwks_cache.rs:198-212` — `.json::<JwkSet>()` buffers unbounded (discovery enforces 256 KiB; JWKS enforces nothing); SSRF posture rests on redirects-disabled + HTTPS-scheme check only — an admin-supplied discovery document can point JWKS at internal HTTPS hosts.
- **Fix**: Cap the body before parse; consider resolving + filtering private ranges (same work as SEC-019).

### SEC-055 [MEDIUM] 🆕 — Mail consumer trusts queue messages; GDPR ExportReady mail can never deliver
- **File**: `crates/axiam-amqp/src/mail_consumer.rs:96-120` — `org_id`/`tenant_id`/`to_address`/`template_context` straight from the queue: broker access = relay arbitrary mail through any org's SMTP credentials (SEC-022 pattern repeated). Separately, `cleanup.rs:417-431` enqueues ExportReady with `org_id: Uuid::nil()` and `to_address: ""` claiming the consumer resolves them — it doesn't (mail_consumer.rs:97,117), so export-ready notifications are undeliverable.
- **Fix**: Authenticate/scope queue messages; make the consumer resolve recipient/org from `user_id`+`tenant_id` (or fix the producer); add a delay to the "backoff" republish (currently immediate).

### SEC-056 [MEDIUM] 🆕 — GDPR pipeline gaps: download race, missed tables, unrecoverable partial purge, silently incomplete exports
- **File**: `handlers/gdpr.rs:214-246` — export download is check-then-act (two concurrent requests with the same single-use token can both receive plaintext; needs an atomic conditional UPDATE). `cleanup.rs:228-334` — the Art. 17 purge never deletes `webauthn_credential` or `password_history` rows; `anonymize_user` clears the purge flags *before* the erasure proof is written, so a failure there permanently strands the deletion (never re-selected). `cleanup.rs:462-549` — export aggregation swallows section failures with `unwrap_or_default()` and hardcodes `sessions/assignments/group_memberships/webauthn_credentials: []` while attesting `schema_version: "1.0"` — legally attested Art. 15 exports can be silently incomplete.
- **Fix**: Atomic download consumption; add the missed tables to the purge; order purge steps so failure is re-selectable (or transactional); fail (or mark) exports when a section query fails; include the placeholder sections for real.
- (Positive: authz on GDPR endpoints is sound — self-or-permission checks, tenant-scoped single-use download tokens, INSERT-only audit pseudonymization resolving the deletion-vs-retention conflict.)

---

## Low findings (active)

### SEC-036 [LOW] ❌ OPEN — Revealed secrets retained in React state after modal close
- `CertificatesPage.tsx:347`, OAuth2ClientsPage:564, ServiceAccountsPage:519, WebhooksPage:550, PgpKeysPage:471 — close handlers never clear the secret.

### SEC-037 [LOW] ❌ OPEN — Reset/verification tokens persist in URL history
- No `history.replaceState` anywhere in `frontend/src`; `ResetPasswordPage.tsx:40`, `VerifyEmailPage.tsx:34-35`.

### SEC-039 [LOW] ❌ OPEN — Crypto error detail propagates toward clients
- `axiam-auth/src/error.rs:104`; closes with SEC-011.

### SEC-040 [LOW] ❌ OPEN — AuthZ engine additive-only vs documented "override" cascade
- `engine.rs` purely additive / default-deny; CLAUDE.md wording unchanged. Implement deny-overrides or fix the docs.

### SEC-041 [LOW] ❌ OPEN — Full Axios error logged on the enumeration-sensitive forgot-password page
- `ForgotPasswordPage.tsx:43` (logs config + submitted email).

### SEC-043 [LOW] 🔶 PARTIAL — CA/PGP encrypted blobs
- `skip_serializing` added on both models (fixed the JSON exposure). Remaining: derived `Debug` still prints blobs; list paths still hydrate the encrypted column.

### SEC-057 [LOW] 🆕 — GitHub Actions pinned by mutable tags, not SHAs
- `ci.yml`/`release.yml` use `@v4`/`@v0.36.0`/`@stable` refs. Otherwise both workflows are strong (least-privilege permissions, scan-before-push, cosign + provenance). Pin by SHA; note hadolint `no-fail: true` and Trivy config-scan `exit-code: 0` are advisory-only by choice.

---

## Resolved findings (verified this round)

| ID | Was | Verified fix |
|---|---|---|
| SEC-001 | CRITICAL — no RBAC on REST | `RequirePermission` called in every handler; `AuthzData` wired (`main.rs:563`); route↔permission map asserted complete (`rbac_test.rs:493`); negative tests (401/403/self-service). Residual architecture risk → SEC-047. |
| SEC-004 | CRITICAL — OIDC no signature verification | Full JWKS verification: raw-header `alg=none` rejection, per-config alg allow-list (HS*/none unmappable), `set_issuer`/`set_audience`, required claims, kid-miss refetch, mandatory nonce from server-side login state (public flow). Tests incl. wiremock e2e + clock-skew. Residuals: legacy authenticated callback takes nonce from body (handlers/federation.rs:510-529); JWKS size cap → SEC-054; API can't set `allowed_algorithms` → CQ-B40 (fail-closed). |
| SEC-006 | CRITICAL — MFA-challenge token = access token | Separate claim structs (challenge/setup/webauthn lack `jti`, carry `purpose`; access requires `jti` + audience narrowing in `extractors/auth.rs:256-294`). Recommend: explicit regression test + retire the `allow_missing_aud_as_user` back-compat flag after rollout. |
| SEC-009 | HIGH — WebAuthn cross-credential Ok | Ceremony state built only from the user's own passkeys; library rejects foreign assertions; no silent-Ok path (webauthn.rs:206-247). |
| SEC-013 | HIGH — cargo audit advisories | lettre 0.11.22, hickory-proto 0.26.1, rustls-webpki 0.103.13 upgraded; residuals (rsa Marvin, bincode, atomic-polyfill) explicitly ignored with reasons + review dates in `deny.toml:7-26`; CI gates `cargo audit` + `cargo-deny`. Three `rand` majors remain (warn-only) → CQ-B34. |
| SEC-014 | HIGH — token in sessionStorage, no CSP | Access token now httpOnly `axiam_access` cookie (Secure, SameSite=Strict); store holds no tokens, no `persist`; nginx ships CSP/HSTS/nosniff/Referrer-Policy/Permissions-Policy, X-XSS-Protection dropped; backend `SecurityHeadersMiddleware` + tests. Nit: middleware itself lacks HSTS — relevant where the k8s ingress routes `/api` straight to the server. |
| SEC-018 | HIGH — SMTP/API-key secrets | `email_config.rs` encrypts (AES-256-GCM, split nonce/ciphertext, key version); no handler exposes EmailConfig. Residual: model fields still lack `skip_serializing` (one future handler from a leak); plaintext backfill is detect-and-warn only (TODO T19.22). |
| SEC-021 | MEDIUM — no API security headers | `SecurityHeadersMiddleware` app-wide + integration tests; nginx inherits. |
| SEC-027 | MEDIUM — reset didn't revoke sessions | `confirm_reset` invalidates sessions + revokes refresh tokens; regression test `password_reset_revokes_sessions.rs`. |
| SEC-029 | MEDIUM — npm vulnerabilities | `npm audit`: **0 vulnerabilities** (axios 1.17.0, react-router 7.16.0, vite 8.0.16); CI gates `npm audit --audit-level=high`. |
| SEC-034 | LOW — audit logs world-readable | Non-admins auto-scoped to own entries; `list_system` requires `audit_logs:list_system`. |
| SEC-035 | LOW — tenant mass-assignment | `UpdateTenant` reduced to name/slug/metadata; users use a dedicated DTO (`password_hash` skip-deserialized). Residual `status` exposure → SEC-050. |
| SEC-038 | LOW — refresh CSRF posture | Refresh accepted only from httpOnly cookie, `SameSite=Strict`, `Path=/api/v1/auth/refresh`, CSRF double-submit enforced + rotated, constant-time compare. Functional regression: the SPA's silent refresh doesn't send the CSRF header → CQ-F28. |
| SEC-042 | LOW — client-side-only route protection | Acceptable now that backend RBAC enforces (SEC-001); residual depends on SEC-002/007. UI-side permission gating is sidebar-only → CQ-F30. |

---

## Positive observations (verified this round)

- Previous positives re-confirmed: parameterized SurrealQL everywhere (no injection found in new code either, including GDPR/email/federation repos), Argon2id at OWASP parameters, EdDSA-only JWTs, AES-256-GCM with fresh nonces (now also: federation secrets, email secrets, GDPR export blobs), hashed single-use tokens, constant-time comparisons.
- New: CSRF double-submit implementation is textbook (32-byte CSPRNG, constant-time compare, rotation on login/refresh); cookie attributes correct incl. scoped refresh path; `crypto.rs` (AES-GCM + HMAC pseudonym) is clean; SAML replay store uses a UNIQUE index with transactional consume; federation login state is server-side and single-use; GDPR endpoints have correct authz and single-use tenant-scoped download tokens; seeder ships **no credentials**; CI: fmt + clippy `-D warnings` + tests against real SurrealDB/RabbitMQ + cargo audit/deny + npm audit + hadolint + trivy, release does scan-before-push with cosign signing and provenance; Dockerfiles distroless/digest-pinned/non-root; deployment securityContexts restricted-profile.

## Coverage notes

All 43 prior findings re-verified against `d69323b` with file:line evidence; all new security-relevant code read (auth extractors, csrf/authz middleware, permissions map, bootstrap, gdpr + repos, federation oidc/saml/jwks/secrets/cert, email_config, mail consumer/publisher, cleanup, seeder, main.rs composition, docker/, k8s/, CI workflows). Lower-confidence areas for a future pass: samael's xmlsec verification internals (XSW), SurrealDB transaction-isolation assumptions in `federation_login_state::consume_by_state`, and the OAuth2 handlers' fine detail (unchanged since last round). Build prerequisites for local verification: `protoc`, `libxml2-dev`, `libxmlsec1-dev` (samael), or `--no-default-features` to drop SAML.
