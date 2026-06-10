# AXIAM — Remediation Plan (from Code & Security Audits)

- **Source audits**: [`code-review.md`](code-review.md) (`CQ-B01..B44`, `CQ-F01..F35`)
  and [`security-review.md`](security-review.md) (`SEC-002..SEC-057`), both at commit
  `d69323b`.
- **Purpose**: A single, wave-ordered plan to close every active finding, from the
  critical fixes to the trivial ones, with the concrete operations per fix.
- **Execution model**: To be executed by the `sonnet` model on branch
  `claude/stoic-dirac-12opcw`. **One signed commit per finding** (or per tightly
  coupled group), the message referencing the finding ID(s). Waves are ordered: do
  **not** start a wave until the previous one builds green. Within a wave, do the
  *Foundational* items first — later fixes depend on them.
- **Per-wave gate**: `cargo build --workspace && cargo clippy --workspace
  --all-targets -- -D warnings && cargo test --workspace`; for frontend waves also
  `npm run lint && npx tsc -b && npm test`. Add/extend tests for every behavioural
  fix. Do **not** open a PR unless explicitly asked.

### Reuse these existing patterns (verified) instead of re-inventing
- Org/tenant ownership check: `handlers/settings.rs:43` (`if org_id != user.org_id`).
- Tenant-scoped edge mutation: `repository/group.rs:349-378` (count subquery),
  `repository/certificate.rs:405-437` (`LET … IF … THROW`).
- Centralized crypto: `axiam-auth/src/crypto.rs` (AES-256-GCM + HMAC-SHA256).
- Canonical password hashing: `axiam-auth/src/password.rs:12` (`hash_password`).
- Federation secret decrypt helper: `secrets.rs:75` (`decrypt_client_secret_or_legacy`).
- DLX template: `connection.rs:129-142` (`MAIL_OUTBOUND`) + mail-consumer retry shape.
- Parity test pattern: backend route↔OpenAPI tests (mirror for the frontend contract test).

---

## Wave 0 — Unblock the build (BLOCKS EVERYTHING)

### CQ-B37 — `axiam-server` does not compile
- `crates/axiam-server/Cargo.toml`: move `uuid`, `chrono`, `serde_json` from
  `[dev-dependencies]` to `[dependencies]` (`workspace = true`); add a direct
  `sha2 = { workspace = true }`.
- `crates/axiam-server/src/cleanup.rs:260,399`: replace `use rsa::sha2::{...}` with
  `use sha2::{Digest, Sha256}`; drop `rsa` from the binary deps if now unused.
- Confirm the CI `build` job fails on `-p axiam-server` today and goes green after;
  clear the 12 warnings in `req5_*/req7_*/cleanup_task` tests so `-D warnings` passes.

---

## Wave 1 — Critical (cross-tenant exposure, broken auth lifecycle)

### SEC-002 — Cross-organization IDOR (orgs / tenants / CA certs)
- Add `if path.org_id != user.org_id { return 403 }` to every org-nested route in
  `handlers/organizations.rs:74-137`, `tenants.rs:143-220`, `ca_certificates.rs:28-128`
  (reuse the `settings.rs:43` pattern).
- Restrict org create/list to a system-admin permission. Add cross-org negative tests
  (mirror `rbac_test.rs`).

### SEC-003 — gRPC unauthenticated + public ingress
- Add a Tonic interceptor in `axiam-api-grpc` validating bearer JWT (reuse
  `axiam-auth` token validation) or mTLS identity; derive `tenant_id`/`subject_id`
  from verified claims, never the request body, in `CheckAccess`, `BatchCheckAccess`,
  `UserService`.
- `k8s/ingress.yml`: remove the public `grpc.axiam.example.com → :50051` exposure
  (mesh-internal + mTLS only).
- `ValidateCredentials` must increment lockout (ties to SEC-026b). Add interceptor
  accept/reject tests (first gRPC tests).

### SEC-044 / CQ-F27 — Six frontend auth flows call non-existent endpoints
- Create `frontend/src/services/auth.ts` with typed functions hitting the real routes
  (from `server.rs:58-156`): `request_reset` `POST /api/v1/auth/reset` `{tenant_id,
  email}`; `confirm_reset` `POST /api/v1/auth/reset/confirm` `{tenant_id,token,
  new_password}`; `verify_email` `POST /api/v1/auth/verify-email` `{tenant_id,token}`;
  `resend_verification` `POST /api/v1/auth/resend-verification`; `change_password`
  `POST /api/v1/auth/password/change`; MFA enroll/confirm via `/api/v1/auth/mfa/enroll`
  + `/mfa/confirm` (`{totp_code}`), setup via `/mfa/setup/enroll` + `/mfa/setup/confirm`.
- Rewrite `pages/auth/ForgotPasswordPage.tsx:15`, `ResetPasswordPage.tsx:22`,
  `VerifyEmailPage.tsx:20`, `profile/ChangePasswordPage.tsx:22`,
  `profile/MfaManagementPage.tsx:44,49`, `profile/ProfilePage.tsx:52` to call the
  service (correct method/body, include `tenant_id`).
- Add a frontend↔OpenAPI contract test in CI.

### CQ-F28 — Silent refresh CSRF-blocked; boot refresh killed
- `lib/api.ts:92-96`: send refresh through the `api` instance (or attach
  `X-CSRF-Token` manually).
- `lib/api.ts:72`: narrow the refresh skip-list to `login`/`refresh`/`logout` only
  (stop skipping `/api/v1/auth/me`).
- `hooks/useAuthInit.ts`: attempt one explicit refresh before declaring the user
  unauthenticated; surface 401 in `lib/fetchCurrentUser.ts:14-29` on the boot path.

### SEC-045 (+ SEC-017 remainder) — Federation secret never decrypted; plaintext on create/update
- Plumb the federation encryption key into `OidcFederationService`/
  `SamlFederationService`; in `oidc.rs:286-294` (and the SAML callback) resolve the
  secret via `secrets.rs:75 decrypt_client_secret_or_legacy` instead of raw
  `config.client_secret`.
- Encrypt on create/update in `repository/federation_config.rs:184-186,248-251`
  (remove `TODO T19.8`); add `#[serde(skip_serializing)]` on
  `models/federation.rs:26-27`; make the UI field write-only (`services/federation.ts`,
  `FederationPage.tsx:334`).
- e2e: create config via API → restart/backfill → OIDC login still succeeds.

---

## Wave 2 — High

> **Foundational first:** **CQ-B09/CQ-B01** (single hashing path + pepper) and
> **CQ-B43**'s `load_key_from_env` extraction (enables SEC-012).

### CQ-B09 + CQ-B01 — One password-hashing path, with pepper
- Delete the duplicate hasher in `db/repository/user.rs:152-173`; hash/verify in the
  service layer via `axiam_auth::password` with the configured pepper for
  create/update/reset (`user.rs:192-194,210,521,713`).
- `main.rs:296`: construct the user repo with the configured pepper (or remove the
  responsibility once hashing leaves the repo). Test: REST-created user logs in with a
  pepper set.

### CQ-B02 — Blocking crypto on the async executor
- Wrap Argon2 hash/verify (`auth/service.rs:212-217`, `policy.rs:247`, `grpc
  services/user.rs:128-133`) and PKI keygen/sign (`axiam-pki/ca.rs:44,125-130`,
  `cert.rs`, `pgp.rs`) in `tokio::task::spawn_blocking` behind a bounding semaphore.
  Confirm the rcgen RSA-4096 path (adds first axiam-pki test).

### CQ-B03 / SEC-033 — Tenant settings store a merged snapshot
- Persist a sparse `TenantSettingsOverride` (`Option` fields) at
  `repository/settings.rs:482-491`; merge against the current org baseline at read time
  (`:524-542`). Test that an org baseline change propagates.

### CQ-B04 — "Clear field" unreachable from JSON
- `#[serde(default, with = "serde_with::rust::double_option")]` on
  `models/resource.rs:37`, `handlers/federation.rs:72`, `models/user.rs:64-69`,
  `models/email.rs:105`. Test JSON `null` clears.

### CQ-B05 — AMQP DLQ parity for audit/authz
- Give audit/authz queues a real DLX like `MAIL_OUTBOUND` (`connection.rs:129-142`);
  fix permanent-loss `nack requeue:false` (`audit_consumer.rs:140`) and the hot-loop
  `requeue:true` (`authz_consumer.rs:177-181`); add real delay to retry republish
  (`mail_consumer.rs:296-326`).

### CQ-B06 — Migration runner not idempotent/transactional
- Add `IF NOT EXISTS`/`OVERWRITE` to legacy v1 DDL in `schema.rs`; wrap apply+record in
  a transaction; add a startup lock record against replica races.

### CQ-B07 / SEC-007 — Edge mutations ignore tenant; no transactions
- In `repository/role.rs:320,345,477,502` and `permission.rs:314,333` verify both
  endpoints belong to `tenant_id` (reuse `certificate.rs:405-437` or
  `group.rs:349-378`) and wrap multi-statement delete+edge ops in a transaction.
  Per-method tenant-isolation tests.

### CQ-B08 — Resource hierarchy: cycles / truncation / orphans
- `resource.rs:202-215` reject cycle-creating re-parent; `:350-393` remove the depth-50
  truncation/dup behaviour; `:257-277` re-home or block delete of resources with
  children. Pairs with CQ-F12.

### CQ-B38 / SEC-056 — GDPR purge/export correctness
- Reorder `anonymize_user` so purge flags clear **last** (or transact) so failures stay
  re-selectable; add missing `webauthn_credential`/`password_history` deletes.
- Stop `unwrap_or_default()` swallowing in export aggregation (`cleanup.rs:462-503`);
  populate hardcoded `sessions/assignments/group_memberships/webauthn_credentials`
  (`:543-549`); paginate audit export beyond 10k (`:480-496`); add a `Failed` job status
  (`:359-375`); per-item shutdown checks.
- Atomic single-use download consumption (`handlers/gdpr.rs:214-246`).

### CQ-B40 — Federation not operable via API
- Add `idp_signing_cert_pem` + `allowed_algorithms` to create/update DTOs
  (`handlers/federation.rs:53-77`), validate the PEM via `cert.rs:36-41`
  `validate_pem_cert`, persist them. Replace the line-concatenation PEM parser
  (`cert.rs:18-27`) with the `pem` crate. e2e: API-created config completes a login.

### SEC-005 — SAML protocol checks
- In `axiam-federation/src/saml.rs`: validate `InResponseTo` against issued request IDs;
  check `Destination`/`Recipient`/`SubjectConfirmationData`; require a `Conditions`
  block; set `WantAssertionsSigned="true"`/`AuthnRequestsSigned="true"` (`:487-488`);
  bind the verified signature reference to the consumed assertion (XSW).

### SEC-008 — TOTP replay
- Persist last-used TOTP step per user; reject same-or-earlier steps (`totp.rs:70`,
  `service.rs:316,425`). Add a `/auth/mfa/*` rate limit (SEC-020).

### SEC-010 / CQ-B30 — Unbounded pagination
- Clamp `limit` (max ~200, reject 0) centrally in `Pagination` deserialization
  (`core/repository.rs:48-63`).

### SEC-011 / SEC-039 / CQ-B33 — Internal error detail leaked
- `api-rest/error.rs:72-75`: generic message for 5xx, log detail via `tracing`; stop
  stringly `Database/Crypto/Internal/Certificate` (`db/error.rs`, `auth/error.rs:104`).

### SEC-012 — PKI zero-key fallback
- `main.rs:335-353`: fail fast when `AXIAM__PKI__ENCRYPTION_KEY` unset; never substitute
  `[0u8;32]`. Reuse `load_key_from_env` (CQ-B43) + the `Option<[u8;32]>` pattern.

### Frontend High
- **CQ-F01** `PgpKeysPage.tsx:267-268,314`: use real `user.id`, not `"current-user"`.
- **CQ-F02** `ConfirmDialog.tsx`: add `confirmLabel?: string` (default "Delete"); fix
  consumers; retire the bespoke UsersPage unlock dialog.
- **CQ-F03** `AuditLogsPage.tsx:203-204,241-250`: clear debounce timers on
  Clear/unmount.
- **CQ-F04** `RoleDetailPage.tsx:285`, `GroupDetailPage.tsx:83`: replace manual debounce
  with `useQuery({queryKey:["user-search",term]})`; extract the shared search dialog.
- **CQ-F05 / SEC-015** `Topbar.tsx:86-89`: call `POST /api/v1/auth/logout` and
  `queryClient.clear()` in logout and on refresh-failure.
- **CQ-F06** Fix the 9 eslint errors; add `npm run lint && tsc -b` (+ Playwright) to
  `ci.yml`.
- **CQ-F07** `OrganizationDetailPage.tsx:632-635`: remove the dead `syncedRef`; make
  `handleSubmit:653-667` save the displayed settings.
- **CQ-F08** `TenantsPage.tsx:377-381`: stop fabricating "Status: Active".

---

## Wave 3 — Medium

### Backend
- **CQ-B10** Shared repo helpers (`parse_uuid`, generic `paginate<T>`, one `CountRow`,
  `take_first_or_not_found`); retrofit ~25 repos + GDPR/email repos.
- **CQ-B11** Map index/duplicate violations to `AlreadyExists`→409; stop misusing
  `DbError::Migration` (`export_job.rs`, `account_deletion.rs`).
- **CQ-B12** `auth/service.rs:200`: propagate real DB errors on the email fallback.
- **CQ-B13** AuthZ N+1: batch grant queries / ancestor walk (`engine.rs:129-136`);
  remove the dead `group_repo`.
- **CQ-B14** Parse Ed25519 PEM once at `TokenService` construction
  (`token.rs:97,138,215,234`); collapse the three issue helpers.
- **CQ-B15** `CertService` use `from_ca_cert_pem` (`cert.rs:103-107`); dedupe the
  triplicated keypair/fingerprint/encrypt helpers.
- **CQ-B16** Org/tenant delete: existence check + cascade (or block) instead of silent
  204; report missing user-delete ids.
- **CQ-B17** Unique `(in,out)` indexes on the five edge tables (`schema.rs:470-484`);
  remove false "IF NOT EXISTS" comments; fix `get_members` total/items drift.
- **CQ-B18** OAuth2: stop collapsing repo errors to `invalid_client`/`invalid_grant`;
  route all client-auth through `authenticate_client()`.
- **CQ-B19** `/oauth2/token|revoke|introspect`: stop hard-requiring `?tenant_id=`;
  add `QueryConfig` for RFC-shaped 400s.
- **CQ-B20 (+B44)** gRPC: graceful shutdown, message-size/timeout/concurrency limits,
  TLS; bound `batch_check_access`; fix governor `per_second(cfg)` + separate burst.
- **CQ-B21** `JsonConfig` body limits + Query/Path/Form configs across `/api/v1`; unify
  the three error-envelope shapes.
- **CQ-B22** Webhook delivery via AMQP with persistence + emit events from handlers (or
  remove until wired); allow secret rotation in `UpdateWebhookRequest`.
- **CQ-B23** Federation: cache OIDC discovery; enforce the 256 KiB cap before buffering;
  map IdP 4xx→4xx; apply `attribute_map` on the OIDC provisioning path.
- **CQ-B24** Tests for axiam-pki (ca/cert/mtls/pgp), axiam-api-grpc (incl. interceptor +
  rate-limit), webauthn handlers, notification_rules.
- **CQ-B25** Request DTOs for certificates/ca/organization/permission/resource/role/
  scope/pgp.
- **CQ-B26** `handlers/users.rs:98-135`: validate email + password policy on create;
  replace `contains('@')` (`notification_rules.rs:289`).
- **CQ-B39** GDPR handler: transactional deletion setup; dedupe export requests; factor
  repeated audit-append blocks; 256-bit cancel token.
- **CQ-B41** `email_config.rs`: UPSERT keyed on `(scope, scope_id)`; deterministic
  ordered reads; delete superseded ciphertext; fix the `Uuid::new_v4()` passed to
  `effective_email_config`.
- **CQ-B43** Extract `load_key_from_env(name)` (4 blocks `main.rs:106-170`) and an
  `AppState`/bootstrap module to replace ~45 `app_data` registrations.

### Security
- **SEC-016** nginx: add `/oauth2/*` + `/.well-known` proxy locations; stop publishing
  backend ports 8090/50051.
- **SEC-019** Webhook SSRF: resolve + re-check every IP at delivery (`webhook.rs:75-83`);
  pin the validated address.
- **SEC-020** Rate-limit `/auth/mfa/*`, `/oauth2/introspect`, `/oauth2/revoke`.
- **SEC-022 / SEC-055** Authenticate/scope AMQP authz + mail messages (signed payloads
  or per-tenant queues + broker ACLs); make the mail consumer resolve recipient/org from
  `user_id`+`tenant_id`; fix the `cleanup.rs:417-431` ExportReady producer; add retry
  delay.
- **SEC-024** mTLS: verify the cert chains to the tenant/org CA, not just fingerprint
  (`mtls.rs:35-77`).
- **SEC-025** Enforce S256 PKCE for the auth-code grant (`authorize.rs`, `token.rs:217`).
- **SEC-026** Dummy-Argon2 on user-not-found; gRPC `ValidateCredentials` increments
  lockout.
- **SEC-028** Block reset to the current password; seed initial password into history.
- **SEC-031** Webhook HMAC secret: encrypt at rest + `skip_serializing` on the model.
- **SEC-032** Atomic `+= 1` failed-login increment (new repo method).
- **SEC-046** Apply `CsrfMiddleware` to the `/api/v1` CRUD scope (`server.rs:197-198`).
- **SEC-047** Enforce permissions in middleware keyed off `ROUTE_PERMISSION_MAP` (or add
  a zero-permission-per-route 403 test); remove the stale `/api/v1/auth/register` public
  path (`permissions.rs:197`).
- **SEC-048** Rate-limit key: rightmost-untrusted-hop XFF (configurable trusted-proxy
  count); shared store for multi-replica; document the ingress requirement.
- **SEC-049** Bootstrap: single transactional conditional create; require the env gate
  (or one-time token) unconditionally (`handlers/bootstrap.rs:77-171`).
- **SEC-050** Self-service user update: strip `status`; gate email change behind
  re-verification (`handlers/users.rs:209-231`).
- **SEC-051** Logout: revoke the caller's own session (JWT `jti`) or verify ownership of
  `body.session_id` (`handlers/auth.rs:364-369`).
- **SEC-052** k8s: rename env keys to `AXIAM__…`; add `AXIAM__AUTH__JWT_*`/encryption
  keys to the secret; log redacted effective config.
- **SEC-053** k8s: receiver-side ingress NetworkPolicies for DB/MQ + a frontend egress
  policy; tighten CIDR exclusions/SMTP egress; PSA `enforce: restricted`.
- **SEC-054** JWKS fetch: cap body before parse; filter private ranges
  (`jwks_cache.rs:198-212`).
- **SEC-023** prod compose: remove `root/root` + `axiam/axiam` defaults; fix
  `configmap.yml` `RUST_LOG`.

### Frontend
- **CQ-F09** Toast system + `getApiErrorMessage`; `onError` on all delete/revoke/unlock
  mutations.
- **CQ-F10** Dashboard: align query keys with CRUD invalidations (`DashboardPage.tsx:
  182-199`).
- **CQ-F11** Remove blanket `noValidate`; add email/URL validation (`FormDialog.tsx:99`,
  LoginPage, BootstrapPage).
- **CQ-F12** Resource parent picker: exclude descendants; allow de-parenting
  (`ResourcesPage.tsx:70,293`). Pairs with CQ-B08.
- **CQ-F13** Federation edit: lock the type select in edit mode; send the config block
  matching the type (`FederationPage.tsx:320-338,520-540,778-803`).
- **CQ-F14** Users pagination: `placeholderData`; redirect off a stranded empty page
  after delete.
- **CQ-F15** Extract shared `ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`/
  `slugify` + a `useCrudMutations` hook into `components/`; replace the 9 copies.
- **CQ-F16** Whole-store zustand subscriptions → selectors.
- **CQ-F17** Single `MfaMethod` type in services; route profile/MFA/change-password
  pages through the services layer (folds into SEC-044 auth service).
- **CQ-F18** Wire role/group unassign methods (`services/roles.ts:66,78`) to the UI.
- **CQ-F19** VerifyEmailPage: single fire under StrictMode against the real endpoint
  (folds into SEC-044).
- **CQ-F29** Restore `tenantSlug/orgSlug` on reload from `/auth/me` (`stores/auth.ts`,
  `useAuthInit`, `fetchCurrentUser`).
- **CQ-F30** Route guards + friendly 403 state; retry/notice on transient `/auth/me`
  failure instead of `permissions:[]`; respect `isLoading` in Sidebar.
- **CQ-F31** LoginPage: handle `mfa_setup_required`/`mfa_required` (`LoginPage.tsx:32-33`).

---

## Wave 4 — Low / Trivial

### Backend
- **CQ-B27** Compose federation/reset/verification services once (see CQ-B43).
- **CQ-B28** Single shared `client_ip`/`user_agent` helper (currently 4× with drift).
- **CQ-B29** Wire `NotificationDispatcher.dispatch()` to real call sites (or remove the
  dead `AuditService`/`NotificationPublisher`).
- **CQ-B30** (remainder) make list count+data transactional.
- **CQ-B31** Replace `let _ =`/`.ok()` silent drops with logged handling.
- **CQ-B32** `DeviceIdentity.org_id` → `Option<Uuid>` (or split the type).
- **CQ-B33** (remainder) typed `Database/Crypto/Internal/Certificate`; fix PUT/PATCH
  semantics; redirect unauthenticated `GET /oauth2/authorize` (`oauth2.rs:73,86-87`).
- **CQ-B34** `cargo machete`: drop unused deps; consolidate the three `rand` majors +
  non-workspace `rand_core`.
- **CQ-B35** Remove vestigial `check_hibp` Result; run HIBP on the sync change-password
  path (`service.rs:642`).
- **CQ-B36** Audit-drop: add a metric (not just `warn!`); revisit the 4096 channel.
- **CQ-B42** Seeder: version/hash skip for unchanged seeds; get-role-by-name.
- **SEC-040** Implement deny-overrides cascade or correct the CLAUDE.md wording.
- **SEC-043** Stop deriving `Debug` over encrypted blobs; don't hydrate encrypted columns
  on list paths.
- **SEC-057** Pin GitHub Actions by commit SHA.

### Frontend
- **CQ-F20** TenantsPage: gate "No tenants found" on orgs loading; remove the N+1
  fan-out.
- **CQ-F21** Delete dead `Placeholder.tsx`; remove stray icon re-exports.
- **CQ-F22** Remove the 5 unused `@radix-ui` deps (or use them).
- **CQ-F23** Use `PasswordPolicyChecker` on admin user-create + bootstrap; source the
  policy from the server.
- **CQ-F24** DataTable: safe fallback row key (`DataTable.tsx:79`).
- **CQ-F25** Introduce i18n / stop hardcoding `en-US` (`lib/utils.ts:40,49`).
- **CQ-F26** `CSS.escape` in the ResourceTree DOM selector (`ResourceTree.tsx:80-83`).
- **CQ-F32** `_retry` guard on the refresh replay; escape the `getCookie` regex.
- **CQ-F33** Module-level empty-permissions constant (`usePermissions.ts:15`).
- **CQ-F34** BootstrapPage: distinguish 404 from "already initialized"; drop
  `noValidate`; add the policy checker.
- **CQ-F35** Fix `useAuthInit` StrictMode double-fetch + dead dep.
- **SEC-036** Clear revealed secrets from React state on modal close (5 pages).
- **SEC-037** `history.replaceState` to strip reset/verify tokens from the URL.
- **SEC-041** Stop logging full Axios error/email on ForgotPasswordPage.

---

## Final verification (whole effort)
- `cargo build --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` green.
- `cargo audit` / `cargo-deny`, `npm audit`, frontend `npm run lint && tsc -b && vitest`,
  Playwright e2e green and **gating in CI** (the frontend gate is new).
- Manual smoke against `just dev-up`: login → MFA → reset/verify/change-password → GDPR
  export+purge → federation login after restart → cross-org request returns 403 → gRPC
  call without credentials rejected.
- Each finding ID closed by a signed commit on `claude/stoic-dirac-12opcw`.
