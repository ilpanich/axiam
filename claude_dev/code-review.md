# AXIAM — Full Code Review (Quality & Correctness, updated re-assessment)

- **Date**: 2026-06-09 (update of the 2026-06-09 review done at `6f2676d`)
- **Scope**: Entire repository at commit `d69323b` — all 13 Rust crates, React/TypeScript frontend, workspace config, build tooling, CI. 51 commits / ~52k insertions since the previous review (Phases 01–06: cookie auth, locked accounts, RBAC, federation hardening, GDPR + email delivery, deployment hardening).
- **Method**: Per-finding re-verification of all 62 previous findings (`CQ-B01`–`B36`, `CQ-F01`–`F26`) with file:line evidence, line-level review of the major new modules (cleanup.rs, gdpr.rs + repos, email_config.rs, seeder.rs, crypto.rs, permissions.rs, middleware/*, mail consumer, frontend auth rewrite), verified with `cargo clippy --workspace --all-targets`, `tsc -b`, `eslint .`, `npm audit`.
- **Companion document**: [`security-review.md`](security-review.md). Security-primary items live there (`SEC-NNN`).

Finding IDs are stable. Statuses: ✅ FIXED, 🔶 PARTIAL, ❌ OPEN. New findings continue at CQ-B37 / CQ-F27.

---

## Executive summary

The remediation wave focused on **new security features** (RBAC enforcement, cookie auth + CSRF, federation verification, GDPR, mail pipeline with a real DLQ) and largely **did not touch the structural backlog**: of the 62 previous quality findings, **1 is partially-superseded, 14 are partial, 47 are still open, and 0 are fully fixed**. Test coverage grew enormously (~500 test fns; rbac/gdpr/bootstrap/federation-e2e/session-lifecycle suites), CI now gates fmt/clippy/test/audit — but the frontend has **no CI gate at all** (no eslint/tsc/test step) and eslint still fails with the same 9 errors.

Headline items this round:

1. **CQ-B37 (new): the server binary does not compile at `d69323b`** — `cleanup.rs` imports `uuid`/`chrono`/`serde_json`/`rsa` that are only declared in `[dev-dependencies]`. 14 hard errors; the CI clippy/build gates cannot be green on this merge. Everything else queues behind this.
2. **The wired-but-broken class**: six frontend auth flows call endpoints that don't exist (CQ-F27/SEC-044); silent token refresh is CSRF-blocked so sessions die every 15 minutes (CQ-F28); the federation secret pipeline never decrypts (SEC-045); notification rules still match-but-never-send (CQ-B29); webhook delivery is still dead code (CQ-B22).
3. The original systemic debts stand: composition bugs in `main.rs` (pepper CQ-B01), blocking crypto on the async executor (CQ-B02 — still zero `spawn_blocking`), repository boilerplate ~25× (CQ-B10), no transactions around multi-statement graph mutations (CQ-B07), non-idempotent migrations (CQ-B06), the 9-of-everything CRUD-page duplication (CQ-F15 — `ToggleField` is now defined **9×**, up from 6).

### Current finding counts (active)

| Priority | Backend | Frontend |
|---|---|---|
| High | 12 | 10 |
| Medium | 20 | 14 |
| Low | 12 | 11 |

### Suggested fix order

1. **CQ-B37** — restore compilation (move the four deps to `[dependencies]`); then keep CI red/green honest.
2. **CQ-F27/CQ-F28** — repair the frontend auth flows and the refresh interceptor (the app is unusable past 15 min / for any recovery flow).
3. **CQ-B01** (pepper), **CQ-B02** (spawn_blocking), **CQ-B05** (audit-queue DLQ parity), **CQ-B06** (migrations) — production-breaking / data-loss class, all unchanged from last round.
4. **CQ-B38/SEC-056** — GDPR purge/export correctness while the feature is young.
5. Structural: **CQ-B10** (repo helpers), **CQ-B09** (single hashing path), **CQ-F15** (CRUD abstraction + shared `ToggleField`/`SectionCard`), **CQ-B43** (AppState/bootstrap module) — every new feature copy-pastes these again.
6. Frontend gate: wire **eslint + tsc + playwright into CI** (CQ-F06) so the 9 standing errors stop being decorative.

---

# Backend findings

## High

### CQ-B37 [HIGH] 🆕 — axiam-server does not compile: bin-code imports live only in `[dev-dependencies]`
- **File**: `crates/axiam-server/Cargo.toml:52-58` (uuid, chrono, serde_json, rsa under `[dev-dependencies]`); `crates/axiam-server/src/cleanup.rs:33,36,260,399,534` imports them from the binary target
- **Issue**: `cargo check -p axiam-server` fails with 14 errors (E0432/E0433/E0282). Tests compile (dev-deps apply), so test-only CI lanes can look green while the shippable binary is broken. Also a smell: `cleanup.rs:260,399` reaches SHA-256 through `rsa::sha2::` instead of a direct `sha2` dependency.
- **Fix**: Move `uuid`/`chrono`/`serde_json` to `[dependencies]` (workspace = true); replace `rsa::sha2` with the workspace `sha2`; confirm `cargo build --workspace` is green in CI (the `build` job should already catch this — verify why it didn't).

### CQ-B01 [HIGH] ❌ OPEN — REST-created users can never log in when a password pepper is configured
- **File**: `crates/axiam-server/src/main.rs:296` still constructs `SurrealUserRepository::new(...)` (pepper `None`); login verifies with `AuthConfig::pepper` (`service.rs:212-216`). `with_pepper` is called only from a test.
- **Fix**: Construct with the configured pepper — but the durable fix is CQ-B09 (one hashing path). Note the new `axiam-auth/src/crypto.rs` is AES-GCM/HMAC only; password hashing was **not** centralized.

### CQ-B02 [HIGH] ❌ OPEN — Blocking CPU-heavy crypto on async executor threads
- **File**: still zero `spawn_blocking` in `crates/`; Argon2 inline at `service.rs:212-217`, policy history loop `policy.rs:247`, gRPC `services/user.rs:128-133`; RSA-4096/Ed25519/PGP keygen inline in `axiam-pki/src/ca.rs:44,125-130`, cert.rs, pgp.rs.
- **Fix**: Wrap hash/verify/keygen/sign in `tokio::task::spawn_blocking` + a bounding semaphore. Still untested whether rcgen's backend supports the `Rsa4096` path (axiam-pki still has zero tests, CQ-B24).

### CQ-B03 [HIGH] ❌ OPEN — Tenant settings still store a merged snapshot; org baseline changes still don't propagate
- **File**: `repository/settings.rs:482-491` (upsert merged row), `:524-542` (read-time re-merge added)
- **Issue**: The new read-time `diff_against_org` infers overrides by inequality with the **current** org baseline, so a field whose snapshot equals the *old* org value becomes a phantom override the moment the org changes it — the original failure mode (SEC-033) survives the rework.
- **Fix**: Persist the sparse `TenantSettingsOverride` (`Option` fields); merge at read time.

### CQ-B04 [HIGH] ❌ OPEN — "Clear field" double-`Option` semantics still unreachable from JSON
- **File**: `models/resource.rs:37` (`parent_id`), `handlers/federation.rs:72` (`metadata_url`); also `models/user.rs:64-69`, `models/email.rs:105` (`reply_to`). No `serde_with`/`double_option` anywhere.
- **Fix**: `#[serde(default, with = "serde_with::rust::double_option")]`; test that JSON `null` clears.

### CQ-B05 [HIGH] 🔶 PARTIAL — AMQP reliability: mail pipeline done right; audit/authz consumers unchanged
- **Fixed**: `MAIL_OUTBOUND` declares a real DLX (`connection.rs:129-142`); mail consumer does bounded retries then dead-letters.
- **Open**: audit/authz queues still have no DLX; `audit_consumer.rs:140` still nacks `requeue: false` on transient DB failure (audit events permanently lost); `authz_consumer.rs:177-181` still `requeue: true` hot-loop on publish failure. Mail "backoff" republish has no actual delay (`mail_consumer.rs:296-326`).
- **Fix**: Bring audit/authz queues up to the mail pipeline's standard; add delay to retries.

### CQ-B06 [HIGH] ❌ OPEN — Migration runner not idempotent, not transactional, no concurrency guard
- **File**: `schema.rs` — runner unchanged; v1 body still plain `DEFINE` (errors on re-run), apply+record not transactional, two replicas still race. Mitigation: new migrations (v12+, v15) use `IF NOT EXISTS` per statement.
- **Fix**: `IF NOT EXISTS`/`OVERWRITE` on legacy DDL; transaction around apply+record; startup lock record.

### CQ-B07 [HIGH] ❌ OPEN — Multi-statement graph deletes unguarded by tenant, no transactions
- **File**: `role.rs:252-270`, `permission.rs:247ff`, `resource.rs:257ff`, `group.rs:281ff`, `service_account.rs:298ff` — edge deletes still precede the tenant-guarded record delete, unguarded and untransacted. (Isolation angle: SEC-007.)

### CQ-B08 [HIGH] ❌ OPEN — Resource hierarchy: cycles, silent ancestor truncation, orphaned children
- **File**: `resource.rs:202-215` (no cycle check on re-parent), `:350-393` (depth-50 truncation with duplicates), `:257-277` (children's `parent_id` dangles on delete). Frontend pair: CQ-F12.

### CQ-B09 [HIGH] 🔶 PARTIAL — Password hashing still duplicated; gRPC now uses the auth copy
- **Fixed**: gRPC routes through `axiam_auth::password` with the configured pepper (`services/user.rs:4,128-132`).
- **Open**: the axiam-db copy still exists and is the one used by **create/update** paths (`repository/user.rs:152-172,210,521,713`) with its own (None) pepper — which is exactly the CQ-B01 bug. Delete the db copy; hash in the service layer.

### CQ-B38 [HIGH] 🆕 — cleanup.rs GDPR pipeline: unrecoverable partial purge, silently incomplete exports
- **File**: `crates/axiam-server/src/cleanup.rs`
- **Issues**: (a) `anonymize_user` clears `deletion_pending`/`scheduled_purge_at` (user.rs:645-646) *before* the erasure proof is written (cleanup.rs:282-288) — a failure there permanently strands the deletion (never re-selected by `find_due_for_purge`); (b) export aggregation swallows section failures with `unwrap_or_default()` (cleanup.rs:462-503) and hardcodes `sessions/assignments/group_memberships/webauthn_credentials: []` (:543-549) while attesting completeness; the purge also never deletes `webauthn_credential`/`password_history` rows; (c) audit export capped at 10k entries with no pagination loop (:480-496); (d) failed export jobs are never marked failed → retried every sweep forever (:359-375); (e) shutdown only observed between sweeps. Cross-ref SEC-056.
- **Fix**: Reorder purge steps (clear flags last) or transact; propagate/mark section failures; add the missing tables; add a `Failed` job status; per-item shutdown checks.
- **Positives**: `MissedTickBehavior::Skip`, watch-channel shutdown joined in main, interval clamped.

### CQ-B40 [HIGH] 🆕 — Federation is not operable via the API: signing certs and algorithms cannot be set
- **File**: `handlers/federation.rs:53-77` (`Create/UpdateFederationConfigRequest` have no `idp_signing_cert_pem` or `allowed_algorithms` fields; repo create/update never write those columns); `cert.rs:36-41` `validate_pem_cert` has zero call sites; schema defaults `allowed_algorithms = []`
- **Issue**: API-created SAML configs always fail `ConfigIncomplete`; API-created OIDC configs always fail `AlgorithmNotAllowed`. Fail-closed (good for security) but the flagship federation feature only works via direct DB writes. Also `cert.rs:18-27` PEM parsing concatenates all non-dash lines (multi-cert bundles → garbage DER; any `-----BEGIN X-----` block accepted).
- **Fix**: Add both fields to the DTOs (validated via `validate_pem_cert`); proper PEM parsing (pem crate); e2e test that creates a config via API and completes a login.

## Medium

### CQ-B10 [MEDIUM] ❌ OPEN — ~25 repositories still duplicate Row/CountRow/UUID-parse/pagination boilerplate
- 25 files still define their own `CountRow`; the +263 lines in `axiam-core/src/repository.rs` are new GDPR/email trait definitions, not shared helpers. The new GDPR repos (export_job.rs:17-42 etc.) copy the same pattern. Fix as before: `parse_uuid`, generic `paginate<T>`, one `CountRow`, `take_first_or_not_found`.

### CQ-B11 [MEDIUM] ❌ OPEN — `DbError::Migration` catch-all; duplicate-username create still a 500
- `db/src/error.rs:7-16` unchanged; `AxiamError::AlreadyExists` now exists and maps to 409 (`error.rs:38`) but is produced in exactly one place (`federation_login_state.rs:86`). Index-violation mapping still missing. The new GDPR repos misuse `Migration` in ~10 more places (`export_job.rs:126-240`, `account_deletion.rs:110-207`).

### CQ-B12 [MEDIUM] 🔶 PARTIAL — login email-fallback still swallows DB errors
- Username branch now propagates real errors (`service.rs:196-201`); the email fallback still does `.map_err(|_| InvalidCredentials)` (:200) — outage reads as 401.

### CQ-B13 [MEDIUM] 🔶 PARTIAL — AuthZ engine: assignments batched; grants/ancestors still N+1
- **Fixed**: one combined `get_user_role_assignments` round-trip (role.rs:422-461).
- **Open**: one grant query per applicable role (engine.rs:129-136); sequential per-level ancestor walk; dead `group_repo` generic now merely `#[allow(dead_code)]` (engine.rs:34-35).

### CQ-B14 [MEDIUM] ❌ OPEN — Ed25519 PEM keys re-parsed on every token issue/validate
- `token.rs:97,138,215,234` — `from_ed_pem` per call on the hottest path; three near-identical issue helpers. Parse once at construction; fail fast.

### CQ-B15 [MEDIUM] ❌ OPEN — CertService still reconstructs the CA instead of `from_ca_cert_pem`; helpers triplicated
- `cert.rs:103-107` rebuilds the issuer from the subject CN; `generate_keypair`/`compute_fingerprint`/`encrypt|decrypt_private_key` now live in **three** copies (ca.rs:125-147, cert.rs:195-219, pgp.rs:204-245).

### CQ-B16 [MEDIUM] ❌ OPEN — Org/tenant delete: no cascade; deletes succeed for missing records
- `organization.rs:210-218`, `tenant.rs:221-229` unchanged (org REST delete → 204 for missing). Handler-level mitigation only: tenants handler now `get_by_id`-first (handlers/tenants.rs:215-220). `user.rs:425-441` is now a soft-delete (status=Inactive) that still silently succeeds for missing ids.

### CQ-B17 [MEDIUM] ❌ OPEN — Duplicate graph edges: no unique indexes, false dedup comment intact
- `schema.rs:470-484` defines the five edge tables with no unique `(in, out)` index; plain RELATEs at `group.rs:390` (false "IF NOT EXISTS" comment still there), `role.rs:332,489`, `permission.rs:324,399`; `get_members` total/items drift persists.

### CQ-B18 [MEDIUM] ❌ OPEN — OAuth2: repo errors still collapse to `invalid_client`/`invalid_grant`; client-auth still inlined 3×
- `oauth2/token.rs:175,346,454` + auth-code lookups :210-234; `authenticate_client()` (:729) still used only by revoke/introspect. Minor: tenant lookup now distinguishes NotFound from ServerError (:241-244).

### CQ-B19 [MEDIUM] 🔶 PARTIAL — OIDC discovery cleaned up; `?tenant_id=` requirement and plain-text extractor 400s remain
- **Fixed**: discovery emits clean URLs; issuer validated at startup (`main.rs:649-689`) and per request; handler errors now RFC 6749-shaped with correct redirect semantics (`handlers/oauth2.rs:48-53,132-147,400-444`).
- **Open**: `/oauth2/token|revoke|introspect` still hard-require `?tenant_id=` (oauth2.rs:43-46,172-177) which discovery now *silently omits* — a discovery-following client fails; missing param still yields actix's plain-text 400 (no `QueryConfig` handler in the workspace).

### CQ-B20 [MEDIUM] 🔶 PARTIAL — gRPC server: rate limit added; shutdown/limits/batch semantics unchanged
- New per-IP tower-governor layer (`middleware/rate_limit.rs:34-47`). Still `.serve()` (no graceful shutdown), no message-size/timeout/concurrency limits, no TLS; `batch_check_access` unbounded/serial/all-or-nothing (authorization.rs:91-117). New nit → CQ-B44.

### CQ-B21 [MEDIUM] ❌ OPEN — Body limits / error envelopes / extractor configs
- Only `/api/v1/auth` has the 64 KiB `JsonConfig` (server.rs:61); `/api/v1` still 2 MiB default; no Query/Path/Form configs; three envelope shapes (`{"error","message"}`, `{"error","retry_after"}`, RFC 6749).

### CQ-B22 [MEDIUM] ❌ OPEN — Webhook delivery: still fire-and-forget, still dead code
- `webhook.rs` deliveries still detached `tokio::spawn`s with no persistence; **zero `.deliver(` call sites** — no handler emits events; `UpdateWebhookRequest` still can't rotate the secret. Improvements: backoff clamp, retry-policy bounds + SSRF URL validation on create/update. Route through the AMQP infra (the mail pipeline shows how) or remove until wired.

### CQ-B23 [MEDIUM] 🔶 PARTIAL — Federation: SAML attribute_map applied; discovery cache / streaming cap / 4xx mapping still missing
- **Fixed**: `apply_attribute_map` on the SAML path (saml.rs:445,714-731).
- **Open**: discovery fetched twice per login uncached (oidc.rs:218,283 — JWKS is cached, discovery isn't); 256 KiB cap still applied after full buffering (oidc.rs:146-155, saml.rs:145-154); IdP 4xx still → HTTP 500; `attribute_map` still ignored on the OIDC provisioning path.

### CQ-B24 [MEDIUM] 🔶 PARTIAL — Test coverage: huge improvement; axiam-pki and axiam-api-grpc still at zero
- See the updated coverage table below. Remaining zero/near-zero areas: **axiam-pki (0 tests)**, **axiam-api-grpc (0, incl. the new rate-limit middleware)**, webauthn REST handlers, notification_rules (0 anywhere), audit middleware drop paths.

### CQ-B25 [MEDIUM] ❌ OPEN — DTO strategy drift; server-set fields still accepted in bodies then overwritten
- `certificates.rs:40-46` (`CreateCertificate.tenant_id`), `CreateCaCertificate`, `CreateOrganization`, `UpdatePermission/Resource/Role/Scope`, `CreatePgpKey` still bind domain structs; users/groups/webhooks/service-accounts have DTOs — drift persists.

### CQ-B26 [MEDIUM] ❌ OPEN — `users::create` still does zero validation (no email format, no password policy)
- `handlers/users.rs:98-135` — straight to the repo, while reset/change flows enforce the full policy; `notification_rules.rs:289` still validates emails with `contains('@')`. New positive: atomic user+consent creation (`create_with_consent`).

### CQ-B39 [MEDIUM] 🆕 — gdpr.rs handler quality
- **File**: `handlers/gdpr.rs` — non-transactional deletion setup (`mark_deletion_pending` → sessions → `account_deletion_repo.create`; a create failure leaves a scheduled purge with **no cancel token**, :300-322); no dedup on export requests (every POST queues a job, :142-147 — unbounded backlog with the never-fail sweep, CQ-B38d); copy-pasted `let _ = audit_repo.append(...)` blocks (:150-163 vs :356-370); `sha256_hex` re-implemented in cleanup.rs via `rsa::sha2`; cancel token is UUIDv4 rather than a 256-bit token (:311). Cross-ref SEC-056 for the download race.

### CQ-B41 [MEDIUM] 🆕 — email_config repository: `set_*` always CREATE, never upsert
- **File**: `email_config.rs:437-460,595-617` — repeated saves accumulate rows; reads take "first row" with no ORDER BY (nondeterministic config!); superseded secret ciphertexts linger. `get_effective_config` passes a random `Uuid::new_v4()` into `effective_email_config` (:669-674). Plaintext backfill is detect-and-warn only (:389-397, TODO T19.22).
- **Fix**: UPSERT keyed on (scope, scope_id); deterministic read; delete superseded ciphertext rows.

### CQ-B43 [MEDIUM] 🆕 — main.rs composition: still one 545-line main(), no AppState; ~45 app_data registrations
- **File**: `main.rs:106-170` (four near-identical hex-key loader blocks — extract `load_key_from_env(name)`), `:551-611` (HttpServer closure registering ~45 entries), duplicated repo instances worked around with comments (:312-314,382-384). Extends CQ-B27 — every new repo touches 3+ places. Positives: background consumers now `exit(1)` instead of zombie-running; cleanup task has ordered shutdown.

## Low

### CQ-B27 [LOW] ❌ OPEN — Federation/email/reset services still rebuilt per request
- `OidcFederationService::new`/`SamlFederationService::new` at 9 handler sites (`handlers/federation.rs:455-1376`); `PasswordResetService` ×2; `EmailVerificationService` ×2. Compose once (see CQ-B43).

### CQ-B28 [LOW] ❌ OPEN — `client_ip`/`user_agent` helpers now copy-pasted 4× with drift
- `auth.rs:169-180` (uncapped), `webauthn.rs:95-106` (capped), inline in `users.rs:118-126` (uncapped), `axiam-audit/src/middleware.rs:110-113`.

### CQ-B29 [LOW] ❌ OPEN — Notification path rewritten but still unwired; AuditService still dead
- The new `NotificationDispatcher` is well-built (batched `get_by_events`, unit tests) but `dispatch()` has **zero production call sites** — rules still match-but-never-send; `NotificationPublisher` registered but unconsumed (main.rs:447,580); `AuditService` exported, used nowhere.

### CQ-B30 [LOW] ❌ OPEN — Pagination unclamped; count+data non-transactional
- `repository.rs:48-63`; `limit=u64::MAX` accepted (security angle: SEC-010).

### CQ-B31 [LOW] ❌ OPEN — Silently dropped errors (and new instances added)
- `webauthn.rs:101,202` (`.ok()` on passkey decrypt), `service.rs:469` (`let _ =` invalidate); new: `gdpr.rs:150,356` and `cleanup.rs:247,297,311` (`let _ =` on audit/federation-link/mark_completed).

### CQ-B32 [LOW] 🔶 PARTIAL — `DeviceIdentity.org_id` nil placeholder now documented; caller resolves it
- `mtls.rs:33-34,74` documents the contract and `handlers/auth.rs:532-542` resolves the real org. Still a footgun — make it `Option<Uuid>` or split the type.

### CQ-B33 [LOW] 🔶 PARTIAL — Error taxonomy / API-shape inconsistencies
- **Fixed**: revoke endpoints now uniform; `AxiamError` gained typed variants (PasswordPolicy, RateLimited, ReplayDetected, …).
- **Open**: `Database/Crypto/Internal/Certificate` still stringly; PUT-with-PATCH semantics everywhere; `GET /oauth2/authorize` still 401-JSONs unauthenticated browsers despite the doc comment promising a redirect (oauth2.rs:73,86-87).

### CQ-B34 [LOW] 🔶 PARTIAL — Dependency hygiene: versions unified; unused deps and three rand majors remain
- **Fixed**: single `[workspace.dependencies]` table, all crates `workspace = true`.
- **Open**: axiam-authz declares serde/tokio/tracing/thiserror unused; axiam-pki declares tokio/tracing/thiserror/base64/rand unused + non-workspace `rand_core 0.6`; axiam-auth's `webauthn-rs-proto` unused; axiam-db's tokio is test-only; rand 0.8.6 + 0.9.4 + 0.10.1 all in tree (deny.toml `multiple-versions = "warn"`). Run `cargo machete` and consolidate.

### CQ-B35 [LOW] ❌ OPEN — `check_hibp` vestigial Result; HIBP skippable by call-site omission
- `policy.rs:173-220,310-315` unchanged; the sync change-password path passes `None, // no HIBP client` (`service.rs:642`) — policy silently skipped exactly as predicted.

### CQ-B36 [LOW] ❌ OPEN — Audit middleware drops entries with only a `warn!`, no metric
- `middleware.rs:54-56,161-163`; channel still 4096.

### CQ-B42 [LOW] 🆕 — Seeder: per-boot O(tenants × ~95 permissions) UPSERT storm; ignored parameter
- `seeder.rs:42-66,86,96-107,184-221` — fine at small scale; add a version/hash check to skip unchanged seeds, get-role-by-name instead of list-1000-and-scan. (No security issue: no credentials seeded, deterministic v5 UUIDs.)

### CQ-B44 [LOW] 🆕 — gRPC governor refill misconfigured: 1 req/s sustained
- `middleware/rate_limit.rs:39-40` — `per_second(1)` with burst = `grpc_authz_per_sec`; the doc comment claims "100 tokens/sec". A mesh caller throttles hard after the initial burst. Use `per_second(cfg)` with a separate burst.

---

# Frontend findings

## High

### CQ-F27 [HIGH] 🆕 — Six auth flows call endpoints the backend does not serve
- **File**: `ForgotPasswordPage.tsx:15`, `ResetPasswordPage.tsx:22`, `VerifyEmailPage.tsx:20`, `ChangePasswordPage.tsx:22`, `MfaManagementPage.tsx:44,49`, `ProfilePage.tsx:52` — legacy `/auth/*` paths, sometimes wrong method (GET vs POST) and wrong body shape (`{code}` vs `{totp_code}`, missing `tenant_id`), vs the real `/api/v1/auth/*` routes (`server.rs:58-140`). Neither vite nor nginx proxies the legacy paths; verify-email false-succeeds via SPA fallback.
- **Fix**: Move all into the typed services layer with correct paths/shapes; add a frontend↔OpenAPI contract test in CI. (Security framing: SEC-044.)

### CQ-F28 [HIGH] 🆕 — Silent token refresh is CSRF-blocked; `/auth/` skip-list also kills boot-time refresh
- **File**: `lib/api.ts:92-96` — refresh uses the **raw axios** import, bypassing the interceptor that injects `X-CSRF-Token`; the backend enforces CSRF on `/api/v1/auth/refresh` → every silent refresh 403s → users dumped to login at access-token expiry (15 min). Additionally `api.ts:72` skips the 401-refresh handler for any URL containing `/auth/` — which includes `GET /api/v1/auth/me`, so a returning visitor with a valid refresh cookie is treated as logged out (`fetchCurrentUser.ts:26-28` swallows the 401).
- **Fix**: Send the refresh via the `api` instance (or attach the header manually); narrow the skip-list to login/refresh/logout; attempt one explicit refresh in `useAuthInit` before declaring unauthenticated.

### CQ-F01 [HIGH] ❌ OPEN — PgpKeysPage still sends `"current-user"` as the user ID
- `PgpKeysPage.tsx:267-268,314` — even though the rewritten auth store now exposes a real `user.id`.

### CQ-F02 [HIGH] ❌ OPEN — ConfirmDialog still hardcodes "Delete"
- `ConfirmDialog.tsx:106`; consumers still mislabeled (PgpKeysPage:498-507 "Revoke PGP Key" → Delete). UsersPage worked *around* it with a bespoke 57-line unlock dialog (UsersPage.tsx:605-661) instead of adding `confirmLabel`.

### CQ-F03 [HIGH] ❌ OPEN — Audit "Clear" still doesn't cancel pending debounce timers
- `AuditLogsPage.tsx:203-204,241-250` — timers in `useState`, no clearTimeout, no unmount cleanup.

### CQ-F04 [HIGH] 🔶 PARTIAL — User-search debounce moved to `useRef`; race and duplication remain
- `RoleDetailPage.tsx:285`, `GroupDetailPage.tsx:83` — re-render churn fixed; still no AbortController/sequence guard (stale responses overwrite newer), no cleanup on close/unmount, dialog still copy-pasted across both files. Use `useQuery({queryKey:["user-search", term]})`.

### CQ-F05 [HIGH] ❌ OPEN — Logout doesn't call the backend or clear the query cache (now effectively a no-op)
- `Topbar.tsx:86-89`. With cookie auth, the httpOnly cookies survive `clearAuth()` — a reload re-authenticates via `useAuthInit`. Security framing: SEC-015.

### CQ-F06 [HIGH] ❌ OPEN — `npm run lint` still fails with the same 9 errors; lint/tsc/tests still not in CI
- Verified this round: 9 errors unchanged (OrganizationDetailPage refs ×2, MfaManagementPage + ResourceTree set-state-in-effect, button/badge/PasswordPolicyChecker react-refresh, input/textarea empty interfaces). `ci.yml`'s only frontend steps are `npm audit` + hadolint. `tsc -b` is clean; `npm audit` is clean.
- **Fix**: Fix the two hook-rule errors, split non-component exports, then add `npm run lint && tsc -b` (and Playwright) to CI.

### CQ-F07 [HIGH] ❌ OPEN — Org Settings dead "sync" block + display/save drift
- `OrganizationDetailPage.tsx:632-635` (plain-object `syncedRef`, recreated per render, fully dead — also 2 of the 9 lint errors); inputs display `?? 12` defaults that `handleSubmit` (:653-667) never saves.

### CQ-F08 [HIGH] ❌ OPEN — Tenants table still fabricates "Status: Active"
- `TenantsPage.tsx:377-381`.

## Medium

### CQ-F09 [MEDIUM] ❌ OPEN — Mutation errors: raw Axios messages or nothing
- No toast system (radix toast still unused), no `getApiErrorMessage`; delete/revoke/unlock mutations still have no `onError` (PgpKeysPage:323-329, UsersPage:343-360, TenantsPage:341-348, RoleDetailPage:674-683, FederationPage:549-557).

### CQ-F10 [MEDIUM] ❌ OPEN — Dashboard still uses parallel `["dashboard-*"]` query keys
- `DashboardPage.tsx:182-199` — CRUD invalidations never reach it.

### CQ-F11 [MEDIUM] ❌ OPEN — `noValidate` everywhere; no email/URL validation
- `FormDialog.tsx:99`; now also LoginPage (:236,:293,:374) and BootstrapPage (:136). Only NotificationRulesPage validates email.

### CQ-F12 [MEDIUM] ❌ OPEN — Resource parent picker cycles; de-parenting impossible
- `ResourcesPage.tsx:70` (only self excluded), `:293` (`parent_id: editParentId || undefined`). Pairs with CQ-B04/CQ-B08.

### CQ-F13 [MEDIUM] ❌ OPEN — Federation edit dialog stale state; type switch sends mismatched config
- `FederationPage.tsx:320-338,520-540,778-803` — type select editable in edit mode; payload omits `type` but switches which config block is sent (can submit `oidc_config` for a SAML provider).

### CQ-F14 [MEDIUM] ❌ OPEN — Users pagination: no `placeholderData`; stranded empty page after delete
- `UsersPage.tsx:228-231,343-349` (the ~133-line diff was the lock/unlock feature).

### CQ-F15 [MEDIUM] ❌ OPEN (worse) — CRUD duplication grew: `ToggleField` now defined 9×
- UsersPage:59, RolesPage:40, UserDetailPage:57, SettingsPage:55, NotificationRulesPage:54, FederationPage:48, WebhooksPage:82, ServiceAccountsPage:32, OAuth2ClientsPage:107. `SectionCard`/`InfoRow` 3×, `ActionBadge` 2×, `slugify` 2×. Still no `useCrudMutations`/shared components — every fix in this document must currently be applied N times.

### CQ-F16 [MEDIUM] 🔶 PARTIAL/SUPERSEDED — Whole-store zustand subscriptions remain; original symptom gone by architecture
- AppLayout.tsx:9, Topbar.tsx:20, DashboardPage.tsx:177 still subscribe to the whole store, but the store no longer holds tokens so refresh no longer re-renders the tree. Switch to selectors anyway.

### CQ-F17 [MEDIUM] ❌ OPEN — `MfaMethod` still defined 3× with diverging types; profile pages bypass services
- services/users.ts:21 vs MfaManagementPage.tsx:17 vs ProfilePage.tsx:24; inline `api.*` calls in ProfilePage:42-56, MfaManagementPage:34-49, ChangePasswordPage:22.

### CQ-F18 [MEDIUM] ❌ OPEN — Role/group assignments write-only; unassign methods dead
- `services/roles.ts:66,78` zero call sites; RoleDetailPage:851-871 placeholder text unchanged.

### CQ-F19 [MEDIUM] ❌ OPEN — VerifyEmailPage double-fires under StrictMode (and is now wholly broken)
- The `cancelled` flag only suppresses the duplicate setState; the GET still fires twice and targets a non-existent endpoint (CQ-F27/SEC-044).

### CQ-F29 [MEDIUM] 🆕 — Tenant context lost on reload
- `stores/auth.ts` `tenantSlug/orgSlug` set only by LoginPage; `useAuthInit`/`fetchCurrentUser` never restore them — after F5 the Topbar shows "Select tenant" while logged in.

### CQ-F30 [MEDIUM] 🆕 — Permission gating is sidebar-only; no route guards; silent empty-permission fallback
- `Sidebar.tsx:233-257` fails closed (good), but any authenticated user can deep-link to any page (requests 403 with no friendly state); `LoginPage.tsx:110,157` falls back to `permissions: []` when `/auth/me` transiently fails — fully disabled UI with no retry/notice; sidebar ignores `isLoading` and flashes disabled at boot.

### CQ-F31 [MEDIUM] 🆕 — LoginPage ignores `mfa_setup_required`
- `LoginPage.tsx:32-33` types the fields; neither submit handler checks them — users with mandated MFA enrollment land on "Authentication error. Please sign in again."

## Low

### CQ-F20 [LOW] ❌ OPEN — TenantsPage "No tenants found" while orgs load; N+1 fan-out
- `TenantsPage.tsx:194-211,456-461`.

### CQ-F21 [LOW] ❌ OPEN — Dead `Placeholder.tsx` (124 lines); stray icon re-exports
- `pages/placeholders/Placeholder.tsx` (zero imports); `RoleDetailPage.tsx:937`.

### CQ-F22 [LOW] ❌ OPEN — Five unused @radix-ui dependencies
- dialog/dropdown-menu/select/separator/toast still installed, zero imports.

### CQ-F23 [LOW] ❌ OPEN — Client password policy hardcoded; absent on admin user creation and bootstrap
- `PasswordPolicyChecker.tsx:46-48`; not used by UsersPage create (:130-141) nor BootstrapPage.

### CQ-F24 [LOW] ❌ OPEN — DataTable fallback row key unchecked double cast
- `DataTable.tsx:79` (optional `getRowKey` exists; fallback unchanged).

### CQ-F25 [LOW] ❌ OPEN — No i18n; `en-US` hardcoded
- `lib/utils.ts:40,49`.

### CQ-F26 [LOW] ❌ OPEN — ResourceTree DOM selector without `CSS.escape`
- `ResourceTree.tsx:80-83`.

### CQ-F32 [LOW] 🆕 — Refresh queue replays without `_retry`; `getCookie` regex unescaped
- `api.ts:81-84` — a replayed request that 401s again can trigger a second refresh cycle (bounded but wasteful); `getCookie` builds a RegExp from the name unescaped (safe today, fragile).

### CQ-F33 [LOW] 🆕 — `usePermissions` allocates a fresh array per render while logged out
- `usePermissions.ts:15` — `?? []` defeats `Object.is`; use a module-level constant.

### CQ-F34 [LOW] 🆕 — BootstrapPage: 404 treated as "Already Initialized"; `noValidate`; no policy checker on the inaugural admin password
- `BootstrapPage.tsx:80-81,136` — a proxy misconfig reads as "already initialized".

### CQ-F35 [LOW] 🆕 — `useAuthInit` double-fetches under StrictMode; dead dependency
- `useAuthInit.ts:16-31` — `cancelled` flag only stops the setState; `setInitializing` in the dep array is never called in the body.

---

## Architecture observations

**Backend.** The layering held up well under the remediation wave: new features (GDPR, mail, federation verification) follow the trait-in-core / impl-in-db / thin-handler shape, and the permission map is guarded by genuinely good parity tests (route↔OpenAPI bi-directional, map↔registry). Three structural weaknesses persist and one was added: (1) repository boilerplate keeps metastasizing — the new GDPR/email repos copy the same Row/CountRow/Migration-error patterns (CQ-B10/B11); (2) still no transactions around multi-statement mutations, now including the GDPR purge pipeline where partial failure strands legal records (CQ-B07/B38); (3) `main.rs` composition keeps growing without an AppState abstraction — 545 lines, 45 app_data registrations, per-request service construction (CQ-B43/B27/B01); (4) **new**: enforcement-by-convention — RBAC (per-handler `RequirePermission`), CSRF (per-scope wrap), and secret encryption (encrypt-on-backfill but plaintext-on-create) are all correct where wired and silently absent where not. Prefer chokepoints: middleware-enforced permissions (SEC-047), app-wide CSRF (SEC-046), encrypt-in-repository (SEC-017/045).

**Frontend.** The cookie-auth rewrite is architecturally right (no tokens in JS, store holds only user/permissions, CSRF header injection in one interceptor) but shipped without integration verification: the refresh path 403s on its own CSRF middleware, six auth flows target dead endpoints, and tenant context doesn't survive reload (CQ-F27/28/29). The services layer is still bypassed by exactly the pages that were bypassing it last round, and the CRUD-template duplication grew (ToggleField 6×→9×). The single highest-leverage frontend investment remains: shared CRUD/mutation/toast plumbing + a frontend↔OpenAPI contract test in CI.

## Test coverage summary (updated)

| Area | State |
|---|---|
| axiam-api-rest | **Strong**: 27 integration files / ~222 test fns + 21 in-src (incl. route↔OpenAPI parity). New: rbac (6), gdpr (4), bootstrap (4), password_change (5), security_headers (4), auth_test grown to 19. Remaining gaps: webauthn handlers, notification_rules (0 anywhere), mfa_methods handlers. |
| axiam-server | **New**: 9 files / 44 fns — federation e2e (oidc 12, saml 6, clock-skew 4, secret-at-rest 2, backfill 1), session lifecycle (7), service-account aud (6), cleanup (4), healthcheck (2). |
| axiam-db | 12 files / 91 fns + 14 inline (saml_replay, session_invalidate_except, webauthn creds; GDPR repos tested inline). |
| axiam-auth | 2 files / 40 fns + 70 inline — best covered. |
| axiam-authz | 1 file / 14 fns. Still missing: cycles/depth-limit, duplicate assignments, ancestor scopes, concurrency. |
| axiam-amqp | mail_consumer_test (4). audit/authz consumers still untested. |
| axiam-federation | 19 inline unit tests + signed/tampered fixtures (was zero). |
| axiam-email / axiam-core / axiam-oauth2 / axiam-audit | 35 / 58 / 9 / 4 inline fns respectively; audit middleware drop-path untested. |
| **axiam-pki** | **Still zero tests** (ca/cert/mtls/pgp) — most urgent given key material + the unverified rcgen-RSA path. |
| **axiam-api-grpc** | **Still zero tests** (incl. new rate-limit middleware). |
| Frontend | 11 Playwright specs (~2,166 lines, mocked APIs). **Still zero unit tests** (no vitest); the concurrency-sensitive refresh interceptor and `buildTree`/policy/parsers remain untested — and the interceptor demonstrably has bugs (CQ-F28). Nothing frontend runs in CI. |

## Static analysis results (this round)

- `cargo clippy --workspace --all-targets`: **axiam-server fails to compile (14 errors — CQ-B37)**; all 12 library crates clean; 12 warnings in axiam-server *tests* (unused imports/vars in req5_*/req7_*/cleanup_task). The CI gate (`-D warnings`) cannot be green at this commit.
- `tsc -b`: clean. `eslint .`: **9 errors** (identical to last round — CQ-F06). `npm audit`: **0 vulnerabilities** (was 7).
- `cargo audit`/`cargo-deny`: gated in CI; residual advisories (rsa Marvin, bincode, atomic-polyfill) explicitly ignored with reasons in `deny.toml`.
- Build prerequisites grew: `protoc` (gRPC) plus `libxml2-dev` + `libxmlsec1-dev` (samael/SAML; `--no-default-features` drops it). Document these in the README/justfile — fresh environments fail three different native builds before succeeding.
