# AXIAM — Post-Remediation Security Review

- **Date**: 2026-07-01
- **Commit reviewed**: `ea85872` (HEAD of `claude/post-remediation-review-994pto`)
- **Baseline**: the previous review at `d69323b` ([`security-review.md`](security-review.md)) and the [`remediation-plan.md`](remediation-plan.md) it produced. 246 commits / ~40k insertions since `d69323b` (Phases 07–14: build-unblock, compliance verification, critical/high/medium/low remediation waves, SurrealDB connection resilience, frontend list contract).
- **Method**: per-finding re-verification of every active `SEC-*` finding against current code with file:line evidence, plus a fresh line-level review of all remediation-touched security surface (gRPC auth interceptor, cookie/CSRF/authz middleware, extractors, federation OIDC/SAML/JWKS/secrets, GDPR cleanup + repos, AMQP HMAC signing, mail consumer, PKI mTLS chain verification, lockout/backoff, bootstrap, k8s/docker/CI). Ten parallel review agents; high-impact items independently re-verified by hand.
- **Build/lint state**: frontend `eslint` clean (0 errors, was 9), `tsc -b` clean, `npm audit` 0 vulnerabilities. All 12 Rust **library** crates pass `cargo clippy` (the workspace binary build was exercised separately; `utoipa-swagger-ui` needs a network-fetched asset in this sandbox). CI now gates fmt/clippy/build/audit/deny/trivy + frontend lint/tsc.
- **Companion**: [`code-review-postremediation.md`](code-review-postremediation.md).

Statuses: ✅ FIXED (verified), 🔶 PARTIAL (core improved, residual risk), ❌ OPEN. New findings this round continue the sequence at **SEC-058**.

---

## Executive summary

The remediation is substantial and mostly real. Both original criticals from the last round are resolved at the layer they were reported: **cross-organization IDOR is closed** (org/tenant/CA handlers now compare the caller's JWT `org_id` to the path, with cross-org negative tests — SEC-002 ✅), and **the broken auth lifecycle is largely repaired** (silent refresh no longer self-blocks on CSRF, federation secrets now decrypt at use — SEC-045 ✅). Password lockout with exponential backoff was genuinely broken and is now fixed and tested (SEC-032 ✅). Pagination is clamped, 5xx bodies are generic, PKCE is enforced for public clients, CSRF now covers the whole API, self-service status escalation and the logout IDOR are closed, k8s config prefixes are corrected, and CI is pinned by SHA with real gates.

But the wave also **reintroduced the same class of bug it was closing**, and left several controls wired only halfway:

1. **gRPC is still partly unauthenticated (SEC-003, HIGH).** The new interceptor guards `AuthorizationService` correctly but was never attached to `UserService` or `TokenService`; both still trust body-supplied `tenant_id`/`user_id`. Cross-tenant user read and unmetered credential brute-force remain reachable by any mesh peer.
2. **A tenant guard was applied to the wrong function (SEC-058, HIGH, new).** The per-tenant edge check landed on `grant_to_role`, but the live REST grant path calls the *unguarded* `grant_to_role_with_scopes`. Cross-tenant privilege grants are still possible, and the isolation test exercises the guarded variant, masking it.
3. **The zero-key anti-pattern was relocated, not eliminated (SEC-059, HIGH, new).** PKI now fails closed when its encryption key is absent — but the webhook subsystem re-added `load_key_from_env(...).unwrap_or([0u8; 32])`, so webhook HMAC secrets are "encrypted" at rest under an all-zero key when the env var is unset.
4. **Enforcement-by-convention persists.** RBAC (per-handler `RequirePermission`), authz middleware (presence-only, fail-open), rate-limiting (spoofable XFF fallback — SEC-048/SEC-060), and secret encryption (webhook plaintext-at-rest — SEC-031) are all correct where wired and silently absent where not.
5. **Several recovery/notification paths are wired but non-functional**: password-reset request/confirm and resend-verification still omit the backend-required `tenant_id` (SEC-044); logout POSTs an empty body against a handler that now requires `{session_id}`, so it 400s and never revokes the server session (SEC-015); GDPR ExportReady mail is still undeliverable (SEC-055).

Nothing here is a newly-opened *critical*, but SEC-003, SEC-058, and SEC-059 are exploitable HIGHs, and two of them are regressions introduced by the remediation itself.

### Active finding counts (OPEN + PARTIAL)

| Severity | Active | New this round |
|---|---|---|
| Critical | 0 | 0 |
| High | 6 | 2 |
| Medium | 20 | 6 |
| Low | 9 | 2 |

**19 previously-active findings verified fully FIXED** this round (see the Resolved table).

### Top priorities (suggested order)

1. **SEC-003** — attach the interceptor to `UserService`/`TokenService`; derive identity from verified claims (the `AuthorizationService` pattern already exists).
2. **SEC-058** — move the tenant guard into `grant_to_role_with_scopes` (the method the REST endpoint actually calls); fix the isolation test to hit the live path.
3. **SEC-059** — make the webhook key fail closed like PKI now does.
4. **SEC-044 / SEC-015** — thread `tenant_id` into the reset/resend calls; make logout revoke the caller's own session without a client-supplied body.
5. **SEC-048/SEC-060** — fix the XFF fallback (use `peer_addr()`, not the leftmost hop) and reconcile the `trusted_hops` guidance with nginx's append behaviour.
6. **SEC-031 / SEC-055 / SEC-047** — wire webhook secret encryption; fix ExportReady producer; enforce permissions at a chokepoint.

---

## High findings (active)

### SEC-003 [HIGH ← was CRITICAL] 🔶 PARTIAL — gRPC UserService / TokenService still unauthenticated
- **File**: `crates/axiam-api-grpc/src/server.rs:65-70`; `services/user.rs:56-142`; `services/token.rs`
- **Fixed**: `AuthInterceptor` (`middleware/auth.rs:33-47`) validates a bearer JWT and stashes `ValidatedClaims`; it is attached to `AuthorizationServiceServer` (`server.rs:65`). `CheckAccess`/`BatchCheckAccess` derive `tenant_id`/`subject_id` from claims and reject any mismatched body field (`services/authorization.rs:73-99,122-149`). Public gRPC ingress was removed (`k8s/ingress.yml`). Message-size/timeout/concurrency limits and env-gated TLS were added (`server.rs:78-120`). First gRPC tests exist (`grpc_auth_test.rs`, `grpc_authz_test.rs`).
- **Open**: `UserServiceServer::new(...)` and `TokenServiceServer::new(...)` are registered **without** the interceptor, and neither handler reads `ValidatedClaims` — `GetUser`, `ValidateCredentials`, and `IntrospectToken` still trust `tenant_id`/`user_id` from the request body. Any mesh peer that reaches `:50051` (TLS is off by default) reads any user cross-tenant (PII) and brute-forces `ValidateCredentials` with no lockout accrual (compounds SEC-026b). Independently confirmed by three reviewers.
- **Fix**: wrap all three services with the interceptor (or a shared layer); derive identity from claims + cross-validate the body as `authorization.rs` already does; add reject-without-token tests for `UserService`/`TokenService`.

### SEC-058 [HIGH] 🆕 — Live REST permission-grant path bypasses the SEC-007 tenant guard
- **File**: `crates/axiam-db/src/repository/permission.rs:428-459` (`grant_to_role_with_scopes`, `_tenant_id` unused, raw `RELATE` by UUID); reached from `crates/axiam-api-rest/src/handlers/permissions.rs:219` (`POST /api/v1/roles/{role_id}/permissions`)
- **Issue**: The SEC-007 remediation added `LET … IF array::len = 0 { THROW }` tenant checks to `grant_to_role`/`revoke_from_role`/`assign_to_user`/… and added tenant-isolation tests — but the REST handler calls the **scoped** variant `grant_to_role_with_scopes`, which was left unguarded (both the empty-scope and scoped branches `RELATE` by raw UUID with no tenant predicate). A caller with `permissions:grant` in tenant A can attach tenant B's permission to a tenant A role, or grant across tenants entirely. `req14_tenant_isolation_test.rs:191` exercises the guarded `grant_to_role`, so the suite is green while production traffic flows through the hole.
- **Fix**: apply the same `LET/THROW` tenant guard inside `grant_to_role_with_scopes` (both branches, and validate every scope id belongs to the tenant); repoint the isolation test at the REST-reachable path.

### SEC-059 [HIGH] 🆕 — Webhook HMAC secret encryption falls back to an all-zero key
- **File**: `crates/axiam-server/src/main.rs:389-390` — `load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY").unwrap_or([0u8; 32])`
- **Issue**: This is the exact SEC-012 anti-pattern the PKI crate was just hardened against (PKI now fails closed with `Option<[u8;32]>`), relocated to the webhook subsystem. Because PKI now fails *lazily*, deploying without `AXIAM__PKI__ENCRYPTION_KEY` is a fully supported boot state — and in that state every webhook signing secret is AES-256-GCM "encrypted" under a hardcoded all-zero key, i.e. trivially recoverable by anyone with DB read access, with only a generic `warn!`.
- **Fix**: fail fast (as PKI now does) or gate webhook registration off when the key is absent; never substitute a constant key. (See also SEC-031 — the encryption is not even wired on the write path today.)

### SEC-005 [HIGH] 🔶 PARTIAL — SAML: signature + several protocol checks landed; binding gaps remain
- **File**: `crates/axiam-federation/src/saml.rs`
- **Fixed**: a `Conditions` block is now mandatory (`saml.rs:443`); NotBefore/NotOnOrAfter + AudienceRestriction validated (`:451-478`); SP metadata now advertises `WantAssertionsSigned="true"` and `AuthnRequestsSigned="true"` (`:553-554`); `InResponseTo` is validated when a stored request id is available (public SSO passes it from `federation_login_state`); assertion-ID replay store intact.
- **Open**: `Destination` validation exists but **every call site passes `None`** (`handlers/federation.rs:869,1524`), so it never runs; `Recipient`/`SubjectConfirmationData` are never checked; there is still **no XSW binding** — `verify_signature` validates *a* signature over the document, then `handle_saml_response` independently consumes `response.assertion` with no check that the signed element's ID equals the consumed assertion's; the authenticated ACS path still accepts unsolicited responses. Protocol-check parameters are untested (all e2e calls pass `None`).
- **Fix**: pass the real ACS URL to the Destination check; validate Recipient/SubjectConfirmation; bind the verified signature reference to the consumed assertion; add InResponseTo/Destination negative tests.

### SEC-015 [HIGH] 🔶 PARTIAL — Logout endpoint sound, but the SPA call 400s and never revokes
- **File**: `frontend/src/components/layout/Topbar.tsx:89-98`; backend `handlers/auth.rs:348-367`
- **Fixed (backend)**: `POST /api/v1/auth/logout` invalidates the session and clears all three cookies, and now enforces `body.session_id == user.session_id` (the SEC-051 IDOR fix).
- **Open (frontend, regression interaction)**: `handleLogout` posts `{}`, but the handler requires `web::Json<LogoutRequest>{ session_id: Uuid }`. The body fails to deserialize → **400**, the `catch` swallows it, and the server session + cookies are never invalidated. On a shared machine a reload re-authenticates via `useAuthInit` from the surviving httpOnly cookies — the SEC-015 objective is still unmet, and the fix made it worse by pairing a stricter server contract with a client that cannot satisfy it.
- **Fix**: make the server revoke the caller's own session from the JWT `jti` with no required body (preferred), or expose `session_id` to the client so it can send it.

### SEC-044 [HIGH] 🔶 PARTIAL — Frontend auth flows: most wired to real routes; reset/resend still dead
- **File**: `frontend/src/services/auth.ts:39-74`; backend `handlers/password_reset.rs:30-41`, `email_verification.rs:37-40`
- **Fixed**: change-password, verify-email, and MFA enroll/confirm now call the real `/api/v1/auth/*` routes with correct methods/bodies; a `services/auth.ts` layer and an e2e contract spec were added; verify-email false-success is gone (SEC-030 ✅).
- **Open**: `requestPasswordReset` sends `{email}` but `RequestResetBody` requires `{tenant_id, email}`; `confirmPasswordReset` sends `{token, new_password}` but `ConfirmResetBody` requires `{tenant_id, …}`; `resendVerification` sends an empty body but the handler requires `{tenant_id, email}`. All three deserialize-fail → 400, so password-reset request, reset-confirm, and resend-verification remain non-functional in an IAM product, and the reset link carries no `tenant_id` for the page to forward. **The contract test does not catch this** — it asserts only URL/path, never the JSON body (and the CI job never runs Playwright anyway — see CQ-F36 in the companion).
- **Fix**: thread `tenant_id`/`email` into the three calls and carry `tenant_id` on the reset/verify links; make the contract test assert request bodies and actually run in CI.

---

## Medium findings (active)

### SEC-008 [MEDIUM ← was HIGH] 🔶 PARTIAL — TOTP replay: guard added, but non-atomic and skew-boundary-leaky
- **File**: `crates/axiam-auth/src/totp.rs:85-126`, `service.rs:337-370`, `crates/axiam-db/src/repository/user.rs:484-497`
- **Fixed**: `verify_code_with_replay_check` rejects a valid code when `current_step <= last_used_step`, the step is persisted per user, and `/auth/mfa/*` is now rate-limited (`mfa_per_min`, default 5).
- **Open**: (a) the read-check-write is **not atomic** — the UPDATE has no `WHERE totp_last_used_step < $step` guard, so N concurrent submissions of one code all read the stale step and all succeed; (b) `check_current` uses `skew=1`, so a code accepted via the −1 window is replayable in its later wall-clock steps; (c) the enrollment-confirm code is untracked, replayable once at first login.
- **Fix**: make the step update a conditional compare-and-set in the DB; record the step the presented code actually matched; seed `totp_last_used_step` at confirm time.

### SEC-017 [MEDIUM ← was HIGH] 🔶 PARTIAL — Federation secret: encrypted on write, but model still serializes
- **File**: `handlers/federation.rs:269-299,447-468` (encrypt on create/update ✅); `crates/axiam-core/src/models/federation.rs:27,43-48`
- **Open**: the core `FederationConfig` model still has no `#[serde(skip_serializing)]` on `client_secret` / `client_secret_ciphertext` / `_nonce` / `_key_version`. Responses go through `FederationConfigResponse` (which omits them) today, so protection is convention-only — any future handler serializing the model directly leaks ciphertext+nonce.
- **Fix**: `skip_serializing` on the model secret fields.

### SEC-019 [MEDIUM] 🔶 PARTIAL — Webhook SSRF: re-resolved at delivery, but address not pinned
- **File**: `crates/axiam-api-rest/src/webhook.rs:62-77,173-186`
- **Fixed**: each delivery attempt calls `resolve_and_validate_host`, re-resolving and rejecting private/loopback/link-local/ULA IPs; redirects disabled.
- **Open**: the validated address is not pinned — `client.post(&webhook.url)` lets reqwest re-resolve independently, so a DNS rebind between check and send still reaches an internal IP.
- **Fix**: pin the validated `IpAddr` into the connection (custom resolver / `resolve()`).

### SEC-022 / SEC-055 [MEDIUM] 🔶 PARTIAL — AMQP message trust: HMAC added (fail-open, global key); ExportReady still undeliverable
- **File**: `crates/axiam-amqp/src/messages.rs:8-49`, `authz_consumer.rs:88-118`, `mail_consumer.rs:96-137`, `crates/axiam-server/src/cleanup.rs:507-522`, `main.rs:471-485`
- **Fixed**: HMAC-SHA256 signing/verification with constant-time compare, fail-closed on bad hex; consumers nack unverified messages. Mail recipient hijacking is closed — `to_address` is advisory and the real recipient is resolved from `user_id`+`tenant_id`.
- **Open**: (a) verification is **fail-open** when `AXIAM__AMQP__SIGNING_KEY` is unset (warn + process); (b) it is a single **global** key, not the per-tenant secret the doc claims, so a signature for tenant A validates a message asserting tenant B; (c) **ExportReady mail is still undeliverable** — `cleanup.rs:510` enqueues `org_id: Uuid::nil()`, the consumer passes it straight to `get_effective_config`, which returns `None` on the org miss → `SendError` → nack; (d) retry republish has no delay.
- **Fix**: make the key mandatory in production; key per tenant (or per-tenant queues + broker ACLs); resolve org from tenant in the consumer (or fix the producer); add retry backoff.

### SEC-024 [MEDIUM] 🔶 PARTIAL — mTLS now chain-verifies, but ignores CA status/validity
- **File**: `crates/axiam-pki/src/mtls.rs:72-103`
- **Fixed**: after the fingerprint lookup, the client cert is cryptographically verified against the issuing CA fetched by `issuer_ca_id` (fail-closed if absent) — closes the fingerprint-only bypass.
- **Open** (new sub-finding): the CA's own `status` (Active/Revoked) and validity window are not checked before it is trusted, while the client cert is. A revoked or expired org CA still authenticates device certs it previously signed.
- **Fix**: assert the CA is Active and within its validity window before `verify_signature`.

### SEC-031 [MEDIUM] 🔶 PARTIAL — Webhook HMAC secret: response-excluded, but still plaintext at rest
- **File**: `crates/axiam-core/src/models/webhook.rs:43` (`#[serde(skip_serializing)]` ✅); `crates/axiam-db/src/repository/webhook.rs:136` (binds `input.secret` verbatim); `handlers/webhooks.rs:111` (passes `req.secret` plaintext)
- **Open**: `encrypt_webhook_secret` has **zero non-test call sites** — secrets are persisted in cleartext despite the module's "stored AES-256-GCM encrypted" claim. Latent correctness trap: the delivery path unconditionally `aes256gcm_decrypt`s the stored value, so if CQ-B22 (delivery) is ever wired without also encrypting on write, 100% of deliveries fail at the decrypt step. (Encryption key also has the SEC-059 zero-key fallback.)
- **Fix**: encrypt on create/update; keep the response exclusion; wire the key fail-closed.

### SEC-047 [MEDIUM] 🔶 PARTIAL — Authorization still fail-open by construction; stale public path removed
- **File**: `crates/axiam-api-rest/src/middleware/authz.rs:114-135`; `permissions.rs:197`; `tests/rbac_test.rs:329,506`
- **Fixed**: the stale `/api/v1/auth/register` public-path entry is gone.
- **Open**: the middleware checks only credential *presence*; the real check remains the per-handler `RequirePermission` call, so a forgotten line is a silent bypass. The parity test asserts map↔registry coverage, not handler behaviour, and `no_permission_returns_403` exercises exactly one route.
- **Fix**: enforce permissions in middleware keyed off `ROUTE_PERMISSION_MAP` (single chokepoint), or add a test that drives every mapped route with a zero-permission user and asserts 403.

### SEC-048 [MEDIUM] 🔶 PARTIAL — Rate-limit key spoofable via XFF fallback; keying contradicts the documented deployment
- **File**: `crates/axiam-api-rest/src/extractors/rate_limit.rs:54-75`
- **Fixed**: rewritten to select the rightmost-untrusted hop with configurable `trusted_hops`; per-replica limitation documented.
- **Open (SEC-060, new)**: two compounding bugs. (1) When `trusted_hops >= hops.len()`, the code sets `idx = 0` and returns `hops[0]` — the **leftmost, client-controlled** value — instead of falling through to `peer_addr()` as its comment claims. (2) The docs tell operators to set `trusted_hops = 1` behind a single nginx, but nginx's `proxy_add_x_forwarded_for` appends the real client as the *rightmost* entry, so the correct value is `trusted_hops = 0`; following the docs makes `idx = 0` select the attacker-controlled hop. Either way, rotating `X-Forwarded-For` per request gives each request its own bucket, defeating the login/reset/OAuth throttles. Multi-replica shared store still not implemented.
- **Fix**: in the underflow branch ignore XFF and use `peer_addr()`; reconcile the `trusted_hops` guidance with nginx's append semantics; add a shared store (or document the per-replica multiplier loudly).

### SEC-049 [MEDIUM] 🔶 PARTIAL — Bootstrap: create is now atomic; initialized-check TOCTOU and unset-gate remain
- **File**: `crates/axiam-api-rest/src/handlers/bootstrap.rs:77-83,100-140,171-201`
- **Fixed**: user-create + role-assign is a single `BEGIN/COMMIT`.
- **Open**: the "already initialized" read precedes and is not atomic with the create transaction — two concurrent first-run requests can both create super-admins; and the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` gate is still conditional, so an unset var lets **any** caller create the first super-admin.
- **Fix**: single conditional/transactional create keyed on a uniqueness invariant; require the env gate (or a one-time setup token) unconditionally.

### SEC-053 [MEDIUM] 🔶 PARTIAL — NetworkPolicies/PSA mostly coherent now; no SMTP egress
- **File**: `k8s/network-policy/*`, `k8s/namespace.yml`
- **Fixed**: receiver-side ingress policies for SurrealDB (`:8000`) and RabbitMQ (`:5672`) now exist, server egress to DB/MQ/DNS/443 present, and `namespace.yml` sets PSA `enforce: restricted` with matching restricted securityContexts — the deployment no longer breaks under default-deny.
- **Open**: no SMTP egress rule (ports 25/465/587), so under default-deny the server cannot reach an external relay and verification/GDPR-export mail silently fails in-cluster; pod/service cluster-CIDR exclusions on the `0.0.0.0/0:443` rule are still operator TODOs.
- **Fix**: add an SMTP egress policy; tighten the CIDR exclusions.

### SEC-054 [MEDIUM] ✅ FIXED — JWKS body cap + private-IP guard (residual SSRF elsewhere)
- **File**: `crates/axiam-federation/src/jwks_cache.rs:220-307`
- **Fixed**: 512 KiB body cap before parse; resolves and rejects private/loopback/link-local/ULA IPs; the opt-in test flag is `#[doc(hidden)]` and defaults off in production.
- **Residual → SEC-064 (new, MEDIUM)**: the IP guard is JWKS-only. Discovery, the token exchange (which POSTs the decrypted `client_secret`), and SAML-metadata fetches are scheme-only, so an internal/loopback `token_endpoint` from a discovery document passes and can exfiltrate the client secret. Also a DNS-rebinding TOCTOU: `validate_jwks_url` resolves once, then reqwest re-resolves at fetch. **Fix**: apply the IP filter to discovery/token/metadata hosts and pin the resolved address.

### SEC-063 [MEDIUM] 🆕 — GDPR erasure certified while audit PII survives
- **File**: `crates/axiam-server/src/cleanup.rs:327-344`
- **Issue**: in `purge_single_user`, an `audit_repo.pseudonymize_actor` failure is only logged (`warn`), then the erasure proof is written and `anonymize_user` clears the re-selection flags. A transient failure (DB contention during the sweep) leaves the real `actor_id` (subject PII) in audit rows indefinitely while an Art. 17 erasure proof attests completion — a legally-attested-but-incomplete erasure.
- **Fix**: treat audit-pseudonymization failure as fatal to the purge (leave flags set so the user is re-selected), or write the proof only after every PII-bearing step succeeds.

### SEC-004 residual [MEDIUM] ❌ OPEN — Authenticated OIDC callback still takes the nonce from the request body
- **File**: `handlers/federation.rs:595-648` (reads `req.nonce`, passes it as `expected_nonce`)
- **Issue**: the account-linking callback lets the caller supply both the nonce and (via the IdP) the token, defeating replay protection on that path. The public first-time-SSO path is correct (server-side nonce from login state).
- **Fix**: derive the expected nonce from server-side state for the authenticated path too.

### Carried-forward mediums (unchanged or lightly touched)
- **SEC-016** ✅ FIXED — nginx now proxies `/oauth2/*` and `/.well-known`; prod compose documents itself as local-only (host still publishes 8090/50051 in the dev-only compose — k8s exposes neither).
- **SEC-023** ✅ FIXED — prod compose creds env-required (no `root/root` / `axiam/axiam`); configmap `RUST_LOG: info`.
- **SEC-025** ✅ FIXED — S256 PKCE enforced for public clients at `/authorize` and verified at token exchange, with tests.
- **SEC-026a** ✅ FIXED — dummy Argon2 on user-not-found. **SEC-026b** ❌ OPEN — gRPC `ValidateCredentials` still never increments lockout (compounds SEC-003).
- **SEC-028** 🔶 PARTIAL — self-service change-password blocks current-password reuse; the unauthenticated reset path does not, and initial passwords are still never seeded into history.
- **SEC-032** ✅ FIXED — atomic `+= 1` failed-login increment; lockout + exponential backoff repaired and tested (commit `e07323f`).
- **SEC-033** ✅ FIXED — tenant settings now stored as a sparse `Option` override mask merged against the live org baseline; org policy changes propagate (secondary write path has a minor residual).
- **SEC-046** ✅ FIXED — `CsrfMiddleware` now wraps the `/api/v1` CRUD scope.
- **SEC-050** ✅ FIXED — self-update strips `status`; a self email change clears `email_verified_at` (forces re-verification).
- **SEC-051** ✅ FIXED — logout rejects a `session_id` that isn't the caller's JWT `jti`.
- **SEC-052** ✅ FIXED — k8s env keys renamed to the `AXIAM__…` double-underscore schema; JWT/MFA/PKI keys added to the secret. Residual (LOW): the CI `test` job still sets `AXIAM_DATABASE__*` (wrong prefix, silently ignored — tests pass only because the DB defaults coincide); the k8s secret omits federation/email/GDPR/pepper keys (features silently degrade).
- **SEC-057** ✅ FIXED — all GitHub Actions pinned by commit SHA.

---

## Low findings (active)

- **SEC-036** ✅ FIXED — revealed secrets cleared on modal close (shared `SecretRevealModal`).
- **SEC-037** ✅ FIXED — `history.replaceState` strips reset/verify tokens from the URL.
- **SEC-039** ✅ FIXED — crypto error detail no longer reaches clients (folded into the generic 5xx body).
- **SEC-040** ✅ FIXED (docs) — additive-only RBAC now accurately documented in CLAUDE.md/design-document.
- **SEC-041** ✅ FIXED — forgot-password no longer logs the Axios error/email.
- **SEC-043** 🔶 PARTIAL — `skip_serializing` added on CA/PGP blobs; derived `Debug` still prints them and list queries still hydrate the encrypted column.
- **SEC-057** — see above (fixed).
- **SEC-065 [LOW] 🆕** — duplicate erasure-proof rows: if `anonymize_user` fails after the proof is written, the user is re-selected and a second proof is appended (no uniqueness guard), corrupting the erasure ledger (`cleanup.rs:337-380`).
- **SEC-066 [LOW] 🆕** — export dedup only filters `status IN ['queued']`, so a `ready`-but-undownloaded or `failed` job doesn't block a duplicate export request (`export_job.rs:102-126`).

---

## New findings summary (this round)

| ID | Sev | Summary |
|---|---|---|
| SEC-058 | High | `grant_to_role_with_scopes` (live REST grant path) bypasses the SEC-007 tenant guard |
| SEC-059 | High | Webhook secret encryption falls back to an all-zero key when `AXIAM__PKI__ENCRYPTION_KEY` unset |
| SEC-060 | Medium | XFF rate-limit fallback returns the client-controlled leftmost hop; keying contradicts the documented nginx setup (SEC-048 regression) |
| SEC-061 | Medium | mTLS chain verify trusts a CA without checking its status/validity (SEC-024 residual) |
| SEC-063 | Medium | GDPR erasure certified while audit-actor PII survives a swallowed pseudonymize failure |
| SEC-064 | Medium | SSRF/secret-exfil guard missing on discovery/token/metadata fetches; JWKS DNS-rebind TOCTOU |
| SEC-065 | Low | Duplicate erasure-proof rows on late-stage purge retry |
| SEC-066 | Low | Export dedup misses `ready`/`failed` in-flight jobs |

(SEC-003's gRPC `UserService`/`TokenService` gap and SEC-055's undeliverable ExportReady are tracked under their existing IDs above rather than as new numbers.)

---

## Resolved this round (verified with file:line)

| ID | Was | Verified fix |
|---|---|---|
| SEC-002 | CRITICAL — cross-org IDOR | `path.org_id == user.org_id` on every org/tenant/CA route; org create/list gated to super-admin; cross-org 403 tests. |
| SEC-010 | HIGH — unbounded pagination | `Pagination.limit` clamped to `1..=200` in serde (`core/repository.rs:52-67`). |
| SEC-011 | HIGH — error-detail leak | 5xx bodies genericized to `internal_error` + fixed message; detail logged via `tracing` (`error.rs:60-98`). |
| SEC-012 | HIGH — PKI zero-key | `PkiConfig.encryption_key: Option<[u8;32]>`, fail-closed at every use site. (But re-added for webhooks — SEC-059.) |
| SEC-020 | MEDIUM — rate-limit gaps | `/auth/mfa/*`, `/oauth2/introspect`, `/oauth2/revoke` now throttled. |
| SEC-025 | MEDIUM — PKCE optional | S256 enforced for public clients, verified at token exchange, tested. |
| SEC-030 | MEDIUM — verify-email false success | page POSTs the real endpoint with `token`+`tenant_id`; no SPA-fallback GET. |
| SEC-032 | MEDIUM — non-atomic lockout | atomic `+= 1`; lockout + exponential backoff repaired and tested. |
| SEC-033 | MEDIUM — settings snapshot | sparse `Option` override mask merged against live org baseline. |
| SEC-045 | HIGH — fed secret never decrypted | `decrypt_client_secret_or_legacy` wired into the OIDC callback; key plumbed everywhere; tested. |
| SEC-046 | MEDIUM — CSRF not on `/api/v1` | `CsrfMiddleware` wraps the CRUD scope. |
| SEC-050 | MEDIUM — self-status escalation | `status` stripped on self-update; email change forces re-verification. |
| SEC-051 | MEDIUM — logout IDOR | rejects a non-caller `session_id`. |
| SEC-052 | MEDIUM — k8s env prefix | keys renamed to `AXIAM__…`; JWT/MFA/PKI secrets added. |
| SEC-054 | MEDIUM — JWKS unbounded/SSRF | body cap + private-IP guard (residual on other fetches — SEC-064). |
| SEC-016 | MEDIUM — nginx/oauth2 | `/oauth2` + `/.well-known` proxied. |
| SEC-023 | MEDIUM — deploy creds/logging | env-required creds; `RUST_LOG` sane. |
| SEC-036 / SEC-037 / SEC-041 | LOW — frontend leaks | secrets cleared on close; tokens stripped from URL; forgot-password logging removed. |
| SEC-039 / SEC-040 / SEC-057 | LOW | crypto detail hidden; docs corrected; actions SHA-pinned. |

---

## Positive observations

- The `AuthorizationService` gRPC interceptor is a clean chokepoint: identity from the verified JWT, every body field cross-validated and rejected on mismatch (`authorization.rs:73-99`). The gap is only that it wasn't extended to the other two services.
- CSRF double-submit is textbook: 32-byte CSPRNG, constant-time compare (`csrf.rs:154`), rotation on login and refresh, refresh cookie path-scoped to `/api/v1/auth/refresh`, correct `HttpOnly`/`Secure`/`SameSite=Strict`.
- The frontend refresh interceptor rewrite is correct — refresh goes through the `api` instance (CSRF header attached), `_retry` set before the single-flight queue, one boot-time refresh before declaring unauthenticated (CQ-F28 genuinely closed).
- Lockout/backoff fix (`e07323f`) corrected three real defects (SurrealDB v3 `duration::from_secs`, an off-by-one, and wiring the exponential backoff) with regression tests.
- GDPR purge now hard-deletes `webauthn_credential` + `password_history` + `member_of`/`has_role` edges, runs `anonymize_user` last (re-selectable on failure), paginates the audit export, and consumes the download token atomically.
- PKCE, PKI fail-closed, mTLS chain verification, JWKS hardening, AMQP HMAC (constant-time), and the sparse-override settings rework are all real, well-implemented improvements.
- CI is genuinely stronger: SHA-pinned actions, fmt + clippy `-D warnings` + build + real-service tests + cargo-audit/deny + npm-audit + trivy, with a first-class gRPC-auth test lane.

## Coverage notes

All active `SEC-*` findings re-verified against `ea85872` with file:line evidence; all remediation-touched security code read. Independently corroborated high-impact items: gRPC service gap (3 reviewers), XFF fallback (2), webhook secret at rest (2). Lower-confidence areas for a future pass: samael xmlsec XSW internals, SurrealDB SET-evaluation-order assumption underpinning the lockout off-by-one (encoded only in a comment — pin with a version-locked test), and live boundary behaviour of the backoff `math::pow`/cast under extreme multipliers.
