# AXIAM — Full Security Review

- **Date**: 2026-06-09
- **Scope**: Entire repository at commit `6f2676d` — all 13 Rust crates, React frontend, proto definitions, docker/, k8s/, dependency audit (`cargo audit`, `npm audit`).
- **Method**: Manual line-level review of all security-relevant code (auth, oauth2, federation, pki, authz, db layer, REST/gRPC/AMQP surface, frontend auth/token handling), full route-table enumeration of the REST API, plus automated dependency scanning. Each finding was verified against the actual code; file:line references point at the evidence.
- **Companion document**: [`code-review.md`](code-review.md) — code-quality findings. Items that are both quality and security issues are cross-referenced.

Finding IDs (`SEC-NNN`) are stable — use them to drive and track remediation.

---

## Executive summary

The codebase shows strong security *primitives* (Argon2id at OWASP parameters, EdDSA JWTs with no alg-confusion, AES-256-GCM with fresh nonces, hashed single-use refresh tokens, constant-time secret comparisons, parameterized SurrealQL everywhere — **no injection found**), but the *enforcement layer is not wired up*. The most severe theme: the authorization engine exists and is tested, yet **no REST handler calls it**, organizations/tenants endpoints don't even check ownership, and gRPC has no authentication at all while being publicly ingressed. Federation (SAML + OIDC) currently performs **no signature verification**, and an MFA-challenge JWT is accepted as a full access token. Until SEC-001…SEC-006 are fixed, any authenticated user is effectively a global administrator, and federation is an authentication bypass.

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 12 |
| Medium | 15 |
| Low | 10 |

### Top remediation priorities (suggested order)

1. **SEC-001 / SEC-002 / SEC-003** — wire RBAC into REST, fix org/tenant IDOR, authenticate gRPC (the management plane is currently open to any token holder).
2. **SEC-004 / SEC-005** — implement OIDC JWKS + SAML XML-signature verification, or hard-disable federation endpoints until done.
3. **SEC-006** — add `token_use`/`aud` claims and enforce them in `decode_access_token` (MFA bypass).
4. **SEC-007** — tenant-scope the role/permission RELATE repository methods.
5. **SEC-012 / SEC-017 / SEC-018** — stop the zero-key fallback and plaintext secrets at rest / in API responses.
6. **SEC-013 / SEC-029** — dependency upgrades (`lettre`, `axios`, `react-router`, `vite`).

---

## Critical findings

### SEC-001 [CRITICAL] No authorization (RBAC) enforced on any REST handler
- **File**: `crates/axiam-api-rest/src/handlers/*.rs` (all of users.rs, roles.rs, groups.rs, permissions.rs, resources.rs, certificates.rs, service_accounts.rs, webhooks.rs, …); unused guard at `crates/axiam-api-rest/src/authz.rs:67-113`
- **Category**: AuthZ / Privilege escalation
- **Issue**: Every handler requires only `AuthenticatedUser` (a valid JWT). The `RequirePermission`/`AuthzChecker` infrastructure exists and is unit-tested, but a grep across `handlers/` shows it is never invoked; `AuthorizationEngine` is built in `main.rs` but only wired to gRPC/AMQP — `AuthzData` is never inserted into the REST app.
- **Impact**: Any user with a valid JWT can create/delete users, create roles, **assign any role (including admin roles) to themselves** via `POST /api/v1/roles/{role_id}/users {user_id: <self>}`, grant permissions, mint certificates, read audit logs, manage webhooks — complete privilege escalation within the tenant.
- **Fix**: Insert `web::Data<Arc<dyn AuthzChecker>>` into the REST app and call `RequirePermission::new(action, resource).check(&user, authz).await?` at the top of every state-changing/sensitive handler. Add negative tests asserting a non-privileged user is denied. Re-enable `reset_mfa` (auth.rs:465) once done.

### SEC-002 [CRITICAL] Cross-organization / cross-tenant IDOR on organizations & tenants endpoints
- **File**: `crates/axiam-api-rest/src/handlers/organizations.rs:24-116`, `crates/axiam-api-rest/src/handlers/tenants.rs:49-187`; same pattern in `ca_certificates.rs` (no `org_id` comparison)
- **Category**: IDOR / Broken object-level authorization
- **Issue**: Both modules bind the caller as `_user: AuthenticatedUser` (extracted then **ignored**) and operate purely on path IDs. Tenants only validate `tenant.organization_id == path.org_id`, never that the caller belongs to `org_id`. Contrast with `settings.rs:38`, which does the check correctly.
- **Impact**: Any authenticated user from any tenant can list **all organizations**, read/update/delete **any organization**, create/read/update/delete **any tenant in any org**, and manage other orgs' CA certificates — full multi-tenant isolation breach.
- **Fix**: Enforce `path.org_id == user.org_id` (as settings.rs does) plus an org-admin permission check (depends on SEC-001). Restrict org creation/listing to system administrators.

### SEC-003 [CRITICAL] gRPC services have no authentication and are exposed via public ingress
- **File**: `crates/axiam-api-grpc/src/server.rs:39-44` (no interceptor); `k8s/ingress.yml:36-62` (public `grpc.axiam.example.com`)
- **Category**: AuthN / Authorization bypass
- **Issue**: `Server::builder().add_service(...).serve(addr)` with no JWT/mTLS interceptor. `UserServiceImpl::get_user` and `validate_credentials` take `tenant_id` straight from the request with no caller identity; `CheckAccess`/`BatchCheckAccess` trust request-supplied `tenant_id`/`subject_id`.
- **Impact**: Anyone who can reach the gRPC endpoint can read any user in any tenant, brute-force passwords via `ValidateCredentials` (which checks lockout but never increments it — see SEC-026/CQ cross-ref), and query authorization decisions for any tenant/subject.
- **Fix**: Add a Tonic auth interceptor that validates the bearer JWT (or mTLS identity) and derives `tenant_id` from verified claims. Remove gRPC from the public ingress; keep it mesh-internal with mTLS.

### SEC-004 [CRITICAL] OIDC federation accepts ID tokens with NO signature verification
- **File**: `crates/axiam-federation/src/oidc.rs:284-295, 398-425`
- **Category**: AuthN / Federation
- **Evidence**: `// TODO(T19.6): Implement JWKS-based JWT signature verification` followed by `decode_id_token_claims`, which just base64-decodes the payload. nonce/exp/aud are checked; the signature is not.
- **Impact**: Full authentication bypass via federation — anyone who can reach the callback can forge a token with any `sub`/`email` (matching `aud=client_id` and the expected `nonce`) and AXIAM will provision/link a local user as that identity.
- **Fix**: Fetch JWKS from `discovery.jwks_uri`, verify the JWT signature (RS256/ES256/EdDSA per IdP) with `jsonwebtoken` using `set_issuer`/`set_audience`, validate `iss` against the discovery `issuer`. Fail closed; gate any insecure decode behind an explicit dev-only flag. Until then, disable the federation login endpoints.

### SEC-005 [CRITICAL] SAML assertions accepted with NO XML signature verification
- **File**: `crates/axiam-federation/src/saml.rs:354-362`; SP metadata advertises `WantAssertionsSigned="false"` at saml.rs:468
- **Category**: AuthN / Federation
- **Issue**: After a `TODO(T19.7)` warning, the code checks only `Status == Success`, `Conditions` (NotBefore/NotOnOrAfter), and audience, then provisions the user. No verification that the Response/Assertion is signed by the configured IdP.
- **Impact**: Anyone who can POST to the ACS endpoint can craft a SAML Response with an arbitrary `NameID` and matching `AudienceRestriction` (the SP entity ID is the public `client_id`) and be authenticated as any user.
- **Fix**: Validate the enveloped XML signature against the IdP's X.509 cert from metadata (samael supports this); reject unsigned assertions; validate `InResponseTo`, `Recipient`, `Destination`, and `SubjectConfirmation` NotOnOrAfter; set `WantAssertionsSigned="true"`.

### SEC-006 [CRITICAL] MFA-challenge token is accepted as a full access token (MFA bypass)
- **File**: `crates/axiam-auth/src/service.rs:666-689, 720-761`; `crates/axiam-auth/src/token.rs:192-208`; `crates/axiam-auth/src/webauthn.rs:320-339`
- **Category**: Token handling / AuthN
- **Issue**: All internal JWTs (access, MFA challenge, MFA setup, WebAuthn state) are signed with the same Ed25519 key and share `iss`. Purpose separation relies on a manual `purpose` claim check — but `decode_access_token` does not check it. The MFA challenge token carries `sub`/`tenant_id`/`org_id`/`exp`/`iat`/`iss`, so it deserializes cleanly into `AccessTokenClaims` (the extra `purpose` field is ignored; `scope` is optional) and passes `validate_access_token`.
- **Impact**: A user who passes only the password step (before TOTP/WebAuthn) receives a challenge token that the API auth middleware accepts as a full access token → MFA bypass.
- **Fix**: Add a `token_use` (or `aud`) claim to **every** token type and enforce it on decode: `decode_access_token` must require `token_use == "access"`; challenge/setup/webauthn decoders must require theirs. Add regression tests that each non-access token is rejected by the REST auth extractor.

---

## High findings

### SEC-007 [HIGH] Cross-tenant role assignment & permission grants — repository methods ignore `tenant_id`
- **File**: `crates/axiam-db/src/repository/role.rs:320-376, 477-532`; `crates/axiam-db/src/repository/permission.rs:314-417`
- **Category**: Tenant isolation
- **Issue**: `assign_to_user`, `assign_to_group`, `grant_to_role`, `grant_to_role_with_scopes`, `revoke_from_role`, `unassign_*` all take `_tenant_id` (unused) and `RELATE`/`DELETE` edges by raw UUIDs with no verification that the user/group/role/permission/scope belong to the calling tenant. The REST handler passes `user.tenant_id`, but role_id (path) and user_id (body) are attacker-controlled. Contrast: `group.rs::add_member` (350-383) **does** verify both sides; `certificate.rs::bind_to_service_account` verifies via `THROW`.
- **Impact**: A tenant-A admin can create or delete role-assignment/permission-grant edges involving tenant-B entities — cross-tenant privilege manipulation and denial of access.
- **Fix**: Apply the `add_member` verification pattern (or a tenant-guarded subquery / `THROW` inside the statement) to every edge-mutating method. Add tenant-isolation tests for each.

### SEC-008 [HIGH] No replay protection on TOTP codes
- **File**: `crates/axiam-auth/src/totp.rs:76-95`; `crates/axiam-auth/src/service.rs:287-296`
- **Category**: AuthN / MFA
- **Issue**: `check_current` with skew=1 (~90 s window); nothing records that a code/step was consumed.
- **Impact**: A code observed in transit (phishing proxy, shoulder-surf, replayed request) can be reused within the window — MFA bypass.
- **Fix**: Persist the last successfully used TOTP step (or code hash) per user and reject same-or-earlier steps (RFC 6238 §5.2).

### SEC-009 [HIGH] WebAuthn `finish_authentication` does not bind the asserting credential to the user
- **File**: `crates/axiam-auth/src/webauthn.rs:230-268`
- **Category**: AuthN / MFA
- **Issue**: After `finish_passkey_authentication`, the code looks up the credential in the user's list only to update `last_used_at`; when no credential matches, the function **still returns `Ok((user_id, org_id))`** — the identity comes from the state token, not the matched credential.
- **Impact**: Violates fail-closed; if any caller ever starts a ceremony with a broader credential set (or on future refactors), an assertion from one user's key could authenticate as another.
- **Fix**: Require the matched credential to exist and belong to `user_id`; return an error on `None`. Derive the authenticated identity from the stored credential.

### SEC-010 [HIGH] Unbounded pagination `limit` — DoS on every list endpoint
- **File**: `crates/axiam-core/src/repository.rs:44-58`; used unclamped in all repos (e.g. `user.rs:455-459`, `role.rs:297`, `audit.rs:308`)
- **Category**: DoS / Input validation
- **Issue**: `limit: u64` from the query string flows straight to `LIMIT $limit` with no maximum.
- **Impact**: `GET /api/v1/users?limit=100000000` forces the DB to materialize huge result sets — memory/CPU exhaustion, repeatable by any authenticated user on every list endpoint.
- **Fix**: Clamp `limit` (e.g. max 200, reject 0) centrally in `Pagination` deserialization/constructor.

### SEC-011 [HIGH] Internal error details leaked in HTTP responses
- **File**: `crates/axiam-api-rest/src/error.rs:53-69`; feeding from `crates/axiam-db/src/error.rs` and `crates/axiam-auth/src/error.rs:104`
- **Category**: Info disclosure
- **Issue**: `message: self.0.to_string()` serializes the full error `Display` for `Database(_)`, `Crypto(_)`, `Internal(_)`, `Certificate(_)` — SurrealDB engine/query text, crypto library detail, internal messages all reach the client.
- **Impact**: Leaks schema/query internals and crypto state, aiding attackers.
- **Fix**: For 5xx categories return a generic message; log details server-side with `tracing` only.

### SEC-012 [HIGH] PKI encryption key silently falls back to an all-zero key
- **File**: `crates/axiam-server/src/main.rs:129-134`; `crates/axiam-pki/src/ca.rs:84`
- **Category**: Crypto / Secrets at rest
- **Issue**: When `AXIAM__PKI__ENCRYPTION_KEY` is unset, the server logs a warning claiming "CA certificate generation will fail" and substitutes `[0u8; 32]`. axiam-pki has no zero-key guard — generation succeeds, and CA/PGP private keys are AES-256-GCM-encrypted with a publicly known constant key.
- **Impact**: All CA/PGP private keys "encrypted at rest" are trivially decryptable by anyone with DB access; the operator was told the feature would fail, so the misconfiguration goes unnoticed.
- **Fix**: Make `PkiConfig.encryption_key` an `Option` and **fail at startup** (or at the service call) when unset. Never substitute a constant key.

### SEC-013 [HIGH] Rust dependency vulnerabilities (`cargo audit`: 7 advisories)
- **File**: `Cargo.lock`
- **Category**: Supply chain
- **Issue / inventory**:
  - `lettre 0.11.19` — **RUSTSEC-2026-0141 (critical 9.1)**: TLS hostname verification disabled with Boring TLS backend → upgrade to ≥0.11.22. (Verify which TLS backend AXIAM compiles; upgrade regardless.)
  - `hickory-proto 0.25.2` — RUSTSEC-2026-0119 (O(n²) CPU exhaustion, fix ≥0.26.1) and RUSTSEC-2026-0118 (unbounded loop, no fix yet).
  - `rustls-webpki 0.103.10` — RUSTSEC-2026-0098/0099 (name-constraint bypasses), RUSTSEC-2026-0104 (panic in CRL parsing) → upgrade ≥0.103.13.
  - `rsa 0.9.10` — RUSTSEC-2023-0071 Marvin timing side-channel (no fix; document residual risk where RSA-4096 certs are used).
  - Warnings: `atomic-polyfill`, `bincode 2.0.1` unmaintained; `rand` 0.8/0.9/0.10 RUSTSEC-2026-0097 unsoundness with custom loggers (three duplicate `rand` majors in tree — consolidate).
- **Fix**: Bump `lettre`, `hickory-proto`, `rustls-webpki`; add `cargo audit`/`cargo deny` to CI so this is gated continuously.

### SEC-014 [HIGH] Frontend: access token persisted in `sessionStorage` with no CSP anywhere
- **File**: `frontend/src/stores/auth.ts:52-61`; `frontend/index.html`; `docker/nginx.conf:20-24`
- **Category**: Token storage / XSS defense-in-depth
- **Issue**: The bearer token is persisted via zustand `persist` into `sessionStorage` (`axiam-auth` key). Neither index.html nor nginx sets `Content-Security-Policy`; nginx ships the deprecated `X-XSS-Protection` and no HSTS.
- **Impact**: Any XSS foothold (including a compromised npm dependency) exfiltrates a valid **IAM admin** bearer token with one line of JS; there is no compensating CSP layer.
- **Fix**: Keep the access token in memory only and re-establish sessions via the httpOnly refresh cookie + silent `/auth/refresh` on load. Regardless, add a strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'`), `Strict-Transport-Security`, and `Permissions-Policy` in nginx; drop `X-XSS-Protection`.

### SEC-015 [HIGH] Logout is client-side only — refresh token never revoked
- **File**: `frontend/src/components/layout/Topbar.tsx:86-89`; `frontend/src/lib/api.ts:111`
- **Category**: Session management
- **Issue**: "Sign out" only clears the zustand store; `POST /auth/logout` is never called anywhere (grep: zero references). The server-stored refresh token and the httpOnly cookie remain valid.
- **Impact**: On a shared machine, anyone after "logout" can hit `POST /auth/refresh` (cookie sent automatically) and obtain a fresh access token — logout does not terminate the session.
- **Fix**: Call `/auth/logout` (revoke + clear cookie) in `handleLogout` and in the 401-refresh-failure path; also clear the react-query cache (see code review FE-005).

### SEC-016 [HIGH] Production nginx does not proxy `/auth/*` or `/oauth2*` — invites insecure workarounds
- **File**: `docker/nginx.conf:50-61`; compare `frontend/vite.config.ts:13-27`; `docker/docker-compose.prod.yml` publishes `8080:8080`
- **Category**: Deployment
- **Issue**: The SPA calls `/auth/login`, `/auth/refresh`, `/auth/mfa/*`, `/oauth2/*` same-origin; production nginx proxies only `/api`. Auth flows are broken in the shipped image, and the prod compose already exposes the backend directly on plain-HTTP :8080 — the natural "fix" operators will reach for, which breaks cookie same-origin assumptions and bypasses nginx security headers.
- **Fix**: Add `location ^~ /auth/ { proxy_pass ...; }` and `location ^~ /oauth2 { ... }` blocks mirroring the Vite proxy rules (keeping the SPA-only `/auth/...` pages served by the SPA); stop publishing the backend port in prod compose.

### SEC-017 [HIGH] Federation IdP `client_secret` stored in plaintext, serialized into API responses, and pre-filled in the UI
- **File**: `crates/axiam-db/src/repository/federation_config.rs:162-164, 226-229` (`TODO(T19.8)`); `crates/axiam-core` federation model (`client_secret: String`, plain `Serialize`); `frontend/src/services/federation.ts:12-17`; `frontend/src/pages/federation/FederationPage.tsx:331-336`
- **Category**: Secrets at rest / Info disclosure
- **Issue**: The upstream IdP OAuth client secret is written to SurrealDB as cleartext and the domain type has no `#[serde(skip_serializing)]`, so GET/list endpoints return it; the frontend then pre-fills it into an `<input type="password">` (readable via devtools, present in every list response and the React Query cache). This contradicts the write-only/reveal-once pattern used for service accounts/OAuth2 clients/webhooks.
- **Impact**: Harvesting these secrets enables impersonation of AXIAM against upstream IdPs — cross-domain SSO compromise.
- **Fix**: Encrypt at rest (planned AES-256-GCM), add `#[serde(skip_serializing)]`, never return the secret on GET (masked placeholder), make the frontend field write-only ("leave blank to keep current").

### SEC-018 [HIGH] SMTP/email-provider secrets serialize into API responses; promised at-rest encryption not implemented
- **File**: `crates/axiam-core/src/models/email.rs:30-48, 78-91`
- **Category**: Secrets at rest / Info disclosure
- **Issue**: `SmtpConfig.password` and `ApiProviderConfig.api_key` are plain `String`s with plain `Serialize` and comments claiming "stored encrypted at rest by the DB layer" — but no `EmailConfigRepository` implementation exists in axiam-db, and `EmailConfig` (which embeds the provider) derives full `Serialize`, so any endpoint returning it exposes the credentials in cleartext JSON.
- **Fix**: `#[serde(skip_serializing)]` on both fields; implement the at-rest encryption the comments promise before persisting.

---

## Medium findings

### SEC-019 [MEDIUM] Webhook SSRF protection bypassable via DNS-resolved hostnames
- **File**: `crates/axiam-api-rest/src/handlers/webhooks.rs:244-329`
- **Issue**: Private-range checks only apply to literal IPs; a hostname resolving to `169.254.169.254`/`10.x` passes validation, and resolution happens later at delivery time (DNS rebinding unguarded). Partially mitigated by `redirect::Policy::none()` + 10 s timeout.
- **Fix**: Resolve at delivery time and re-check every resolved IP against `is_global_ip`; pin the validated address for the actual connection.

### SEC-020 [MEDIUM] No IP-level rate limiting on auth/MFA/token endpoints
- **File**: `crates/axiam-server/src/main.rs:247-285`
- **Issue**: Per-account lockout exists (5 attempts, exponential backoff), but `/auth/login`, `/auth/mfa/verify`, `/oauth2/token`, `/oauth2/introspect` have no per-IP throttling — credential stuffing across many accounts and MFA guessing are unbounded.
- **Fix**: Add `actix-governor` (or similar) on `/auth/*` and `/oauth2/token|introspect`; confirm MFA verify attempts count toward lockout.

### SEC-021 [MEDIUM] REST API responses lack security headers
- **File**: `crates/axiam-api-rest/src/server.rs:495-509`; `docker/nginx.conf:55` (`/api` location adds none)
- **Fix**: `DefaultHeaders` middleware with HSTS, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` on sensitive responses; replicate on the nginx `/api` location.

### SEC-022 [MEDIUM] AMQP authz consumer fully trusts queue messages
- **File**: `crates/axiam-amqp/src/authz_consumer.rs:62-90`
- **Issue**: Any producer with broker access can request authz decisions for any tenant/subject; no signature/claims binding. Dev/prod compose ships `axiam:axiam` broker creds (SEC-023).
- **Fix**: Authenticate/authorize messages (signed payloads or per-tenant queues with broker ACLs); document the broker trust boundary.

### SEC-023 [MEDIUM] Deployment: hardcoded weak credentials; debug logging in production configmap
- **File**: `docker/docker-compose.prod.yml:24-29, 70-71` (SurrealDB `root/root`, RabbitMQ `axiam/axiam`); `docker/docker-compose.dev.yml:8, 22-23`; `k8s/server/configmap.yml:16` (`RUST_LOG: "info,axiam=debug"`)
- **Fix**: Inject credentials via secrets/env; set `RUST_LOG=info` (or `warn`) in production.

### SEC-024 [MEDIUM] mTLS device auth: global fingerprint lookup with no tenant/CA binding
- **File**: `crates/axiam-pki/src/mtls.rs:35-77`; `crates/axiam-db/src/repository/certificate.rs:382-403, 440-460`
- **Issue**: Identity is keyed purely on a global fingerprint match; tenant comes from whatever row matches; chain validation is delegated entirely to the proxy; no check that the cert was issued by the tenant's own CA. `get_bound_service_account`/`get_by_fingerprint_global` are deliberately cross-tenant — callers must re-scope.
- **Fix**: Verify issuer chains to the tenant/org CA in addition to fingerprint; scope lookups by expected tenant where possible; document the proxy trust dependency loudly.

### SEC-025 [MEDIUM] PKCE not enforced for the authorization-code grant
- **File**: `crates/axiam-oauth2/src/authorize.rs:105-126`; `crates/axiam-oauth2/src/token.rs:184-224`
- **Issue**: PKCE is validated only when the client volunteers it; there is no public-client concept. Stated standard is "Authorization Code + PKCE"; OAuth 2.1 mandates PKCE.
- **Fix**: Require `code_challenge` (S256) for the authorization_code grant — at minimum for public clients, ideally for all.

### SEC-026 [MEDIUM] Username enumeration via login timing; gRPC path never increments lockout
- **File**: `crates/axiam-auth/src/service.rs:159-193`; `crates/axiam-api-grpc/src/services/user.rs:113-131`
- **Issue**: (a) Unknown users return immediately while existing users incur an Argon2 verification (~tens of ms) — a timing oracle. (b) gRPC `ValidateCredentials` checks `locked_until` but never records failed attempts — an unmetered brute-force path (compounded by SEC-003).
- **Fix**: Dummy Argon2 verification on user-not-found; route gRPC credential checks through the same failed-login accounting as REST.

### SEC-027 [MEDIUM] Password reset does not invalidate existing sessions
- **File**: `crates/axiam-auth/src/password_reset.rs:190` (`TODO(T19)`)
- **Issue**: After a successful reset (the recovery path for a compromised account), all existing sessions/refresh tokens remain valid — the attacker keeps access.
- **Fix**: Invalidate all sessions and revoke refresh tokens on reset completion.

### SEC-028 [MEDIUM] Password reset allows reusing the current password; initial password never enters history
- **File**: `crates/axiam-auth/src/password_reset.rs:160-187`; `crates/axiam-auth/src/policy.rs:231-266`
- **Issue**: `check_history` compares only `password_history` rows; the current `password_hash` is appended only after the check, and the signup password is never recorded — "reset to the same password" always passes.
- **Fix**: Include `user.password_hash` in the candidate set; record the initial hash at user creation.

### SEC-029 [MEDIUM] Frontend dependency vulnerabilities (`npm audit`: 4 high, 3 moderate)
- **File**: `frontend/package.json` / `package-lock.json`
- **Issue / inventory**: `axios` (large advisory set incl. prototype-pollution credential-injection chains), `react-router 7.x < 7.14.2` (**high** — vendored turbo-stream deserialization RCE GHSA-49rj-9fvp-4h2h, open redirect), `vite 8.0.0-8.0.4` (high — dev-server file read/path traversal), `follow-redirects`, `postcss`, `brace-expansion`. All have fixes via `npm audit fix`.
- **Fix**: Run `npm audit fix`, commit the lockfile, and add `npm audit --audit-level=high` to CI.

### SEC-030 [MEDIUM] Email verification shows a false "Email verified!" success
- **File**: `frontend/src/pages/auth/VerifyEmailPage.tsx:19-21, 49-50`; `frontend/vite.config.ts:18`; `docker/nginx.conf`
- **Issue**: The page GETs `/auth/verify-email?token=...`, but that path is excluded from the dev proxy and not proxied by prod nginx — the SPA fallback returns `index.html` with HTTP 200, so the UI claims success while the backend never saw the token.
- **Impact**: False security state in an identity product; verification-gated controls remain ineffective while the UI says otherwise.
- **Fix**: Route the call through a proxied path (prefer `POST`), and validate response content, not just status.

### SEC-031 [MEDIUM] Webhook HMAC `secret` plaintext at rest and only conventionally excluded from responses
- **File**: `crates/axiam-db/src/repository/webhook.rs:18-44, 120-128`; core `Webhook.secret` derives `Serialize` (doc comment promises "never returned" but nothing enforces it)
- **Fix**: `#[serde(skip_serializing)]` on `Webhook::secret`; consider envelope encryption at rest.

### SEC-032 [MEDIUM] Failed-login counter uses non-atomic read-modify-write — lockout weakened under concurrency
- **File**: `crates/axiam-auth/src/service.rs:763-793`
- **Issue**: Counter read at login start, written back as an absolute value — concurrent failed attempts (exactly the brute-force scenario) lose increments.
- **Fix**: Atomic `UPDATE user SET failed_login_attempts += 1 ... RETURN AFTER` repository method; compute lockout from the returned value.

### SEC-033 [MEDIUM] Tenant settings snapshot freezes org security baselines (MFA enforcement included)
- **File**: `crates/axiam-api-rest/src/handlers/settings.rs:134-149`; `crates/axiam-db/src/repository/settings.rs:524-542`
- **Issue**: `PUT /settings` persists the *merged* org-baseline+overrides row. When the org later tightens its baseline (e.g. enforces MFA — consumed by `login` via auth.rs:155-160), tenants that ever saved settings keep the stale values: the diff-based re-merge logic cannot distinguish overrides from stale baseline copies.
- **Impact**: Org-level security policy changes silently fail to propagate to tenants.
- **Fix**: Persist only the sparse override set (`Option` fields) and merge against the live org baseline at read time. (Cross-ref: code review CQ-003.)

---

## Low findings

### SEC-034 [LOW] Audit logs readable by any authenticated tenant user; system audit log readable by everyone
- **File**: `crates/axiam-api-rest/src/handlers/audit.rs:22-59`
- **Fix**: Gate behind an `audit:read` permission (depends on SEC-001); restrict `list_system` to system admins.

### SEC-035 [LOW] Tenant update mass-assignment surface
- **File**: `crates/axiam-api-rest/src/handlers/tenants.rs:139-155` (raw `UpdateTenant` body); pattern repeated where core domain `Update*` structs bind directly to JSON (certificates, groups, etc.)
- **Fix**: Explicit request DTOs; never deserialize ownership fields (org/tenant ids) from bodies. (Cross-ref CQ-024.)

### SEC-036 [LOW] Revealed secrets/private keys retained in React state after modal close
- **File**: `frontend/src/pages/certificates/CertificatesPage.tsx:345-351` (same in PgpKeysPage, ServiceAccountsPage, OAuth2ClientsPage, WebhooksPage)
- **Fix**: Clear secret state in `onClose` (the `EncryptDataModal` in PgpKeysPage already does this correctly).

### SEC-037 [LOW] Reset/verification tokens persist in URL history and server logs
- **File**: `frontend/src/pages/auth/ResetPasswordPage.tsx:39-40`; `VerifyEmailPage.tsx:34-35`
- **Fix**: `history.replaceState` to strip `?token=` after capture; submit the verify token via POST body.

### SEC-038 [LOW] CSRF posture of `/auth/refresh` depends on unverified cookie attributes
- **File**: `frontend/src/lib/api.ts:87-91`
- **Issue**: Bearer-token APIs are CSRF-safe; the only ambient-credential endpoint is `POST /auth/refresh`, which a cross-site page can trigger blind (rotation → session desync/DoS at worst).
- **Fix**: Confirm the backend sets `SameSite=Lax/Strict`, `Path=/auth/refresh`, and add an `Origin` check on the refresh endpoint.

### SEC-039 [LOW] Crypto library error detail propagates toward clients
- **File**: `crates/axiam-auth/src/error.rs:104` (`AuthError::Crypto(msg)` → `AxiamError::Crypto(msg)`), e.g. token.rs:69, totp.rs:23/46
- **Fix**: Subsumed by SEC-011's generic-5xx-message fix; log detail server-side only.

### SEC-040 [LOW] AuthZ engine is additive-only — documented "override" cascade absent
- **File**: `crates/axiam-authz/src/engine.rs:81-171`
- **Issue**: CLAUDE.md says parent role assignments cascade "unless overridden", but no deny/override mechanism exists — purely additive allow with default deny. Not an escalation bug; operators expecting deny-overrides will mis-model permissions.
- **Fix**: Implement explicit deny/override precedence or update the documented model to "purely additive".

### SEC-041 [LOW] Full Axios error object logged to console on the enumeration-sensitive forgot-password page
- **File**: `frontend/src/pages/auth/ForgotPasswordPage.tsx:43`
- **Fix**: Log nothing or only `err.message`/status.

### SEC-042 [LOW] Route protection is client-side only with no role gating in the UI
- **File**: `frontend/src/components/layout/AppLayout.tsx:21-23`
- **Issue**: A forged `sessionStorage` entry renders the full admin shell. Acceptable **only** once the backend enforces authz on every endpoint (SEC-001); currently the backend does not, making this consequential.
- **Fix**: Fix SEC-001 first; longer-term fetch the user's permissions to gate UI sections.

### SEC-043 [LOW] CA/PGP encrypted key blobs hydrated on reads and exposed in `Debug`
- **File**: `crates/axiam-db/src/repository/ca_certificate.rs:97-137`; `pgp_key.rs:110-145`
- **Issue**: Ciphertext only (and `skip_serializing` is present), but `Debug` derives could put blobs into logs; list endpoints don't need the field at all.
- **Fix**: Redacting `Debug` impl; skip hydration on list paths.

---

## Positive observations (verified)

- **No SurrealQL injection found**: every query binds user-controlled values via `$param`; `format!` interpolation is limited to server-generated `Uuid`s in `RELATE` and compile-time column-name constants.
- Argon2id at OWASP parameters (m=19456 KiB, t=2, p=1) with per-hash salts and optional pepper; password reset flow is enumeration-safe and rate-limited.
- EdDSA-only JWT encode/decode (no alg confusion, no `none`), issuer + required-claims enforcement.
- AES-256-GCM used correctly (fresh random 12-byte nonce per encryption, nonce prepended) for TOTP secrets, CA keys, PGP keys, WebAuthn state.
- Refresh/auth/reset/verification tokens: 32-byte CSPRNG, stored as SHA-256 hashes, single-use with rotation; atomic `UPDATE ... WHERE used=false` consumption (race-safe).
- OAuth2: constant-time client-secret and PKCE comparisons; redirect_uri validated against the registered set before any redirectable error; PKCE verified before code consumption; introspection enforces tenant + client ownership.
- Tenant-scoped entities (users/roles/groups/webhooks/certs/audit) consistently take `tenant_id` from the validated JWT, never from the request.
- Audit table is append-only via schema permissions; email templating HTML-escapes and strips CR/LF from headers (no header injection); SMTP enforces TLS.
- Frontend: zero XSS sinks (no `dangerouslySetInnerHTML`/`eval`/`innerHTML`/`target="_blank"` issues); refresh token httpOnly; solid 401-refresh queueing; reveal-once secret UX; no `VITE_` secret baking; unprivileged nginx image.
- Containers: non-root user, `readOnlyRootFilesystem`, resource limits, TLS ingress with ssl-redirect; k8s secret manifests intentionally blank.

## Coverage notes

Fully read: all of axiam-auth, axiam-oauth2, axiam-federation, axiam-pki, axiam-authz, axiam-db (all 27 repositories + schema), axiam-core models/errors, axiam-email, axiam-amqp consumers, axiam-audit middleware, axiam-server main.rs, REST route table + extractors + the majority of handlers, gRPC server + services, all of docker/ and k8s/, and 100 % of frontend/src auth/secret-handling code (remaining CRUD pages exhaustively pattern-scanned for sink classes). Follow-up deep-dives recommended (lower-confidence areas): `handlers/oauth2.rs`/`oauth2_clients.rs` fine detail, `webauthn.rs` REST handlers, CI workflows in `.github/`.
