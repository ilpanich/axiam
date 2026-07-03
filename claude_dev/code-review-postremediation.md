# AXIAM — Post-Remediation Code Review (Quality & Correctness)

- **Date**: 2026-07-01
- **Commit reviewed**: `ea85872` (HEAD of `claude/post-remediation-review-994pto`)
- **Baseline**: the previous review at `d69323b` ([`code-review.md`](code-review.md)) and the [`remediation-plan.md`](remediation-plan.md). 246 commits / ~40k insertions since `d69323b`.
- **Method**: per-finding re-verification of every active `CQ-*` finding with file:line evidence; fresh line-level review of remediation-touched modules (cleanup/GDPR, email_config, seeder, mtls chain verify, schema migrations, AMQP DLX/HMAC, gRPC interceptor + governor, frontend services/hooks/api/shared-components, SurrealDB connection resilience).
- **Verification run in this environment**:
  - `cargo build --workspace` → **green** (4m27s; `axiam-server` binary produced — **CQ-B37 fixed**).
  - `cargo clippy` → all 12 library crates clean.
  - Frontend `eslint .` → **0 errors** (was 9 — **CQ-F06 source fixed**); `tsc -b` → clean; `npm audit` → 0 vulnerabilities.
- **Companion**: [`security-review-postremediation.md`](security-review-postremediation.md). Security-primary items live there (`SEC-*`).

Statuses: ✅ FIXED, 🔶 PARTIAL, ❌ OPEN. New findings continue at **CQ-B45 / CQ-F36**.

---

## Executive summary

Unlike the previous wave (which the last review found "did not touch the structural backlog"), this round closed a meaningful slice of it. The build compiles and the frontend lints clean — both were red at `d69323b`. Concrete correctness fixes landed across the stack: resource-hierarchy cycle/orphan protection (CQ-B08 ✅), a single hashing path with the configured pepper so REST-created users can log in (CQ-B01 ✅), `spawn_blocking` around most crypto (CQ-B02 partial), atomic lockout (SEC-032), migration transactionality (CQ-B06 partial), unique edge indexes (CQ-B17 partial), a seeder that skips unchanged work (CQ-B42 ✅), PKI/gRPC test suites where there were zero (CQ-B24 partial), and a genuinely well-built cookie-auth + refresh-interceptor rewrite on the frontend.

Three themes remain:

1. **The "wired-but-broken" class persists in new places.** Webhook delivery is still dead code that would now *fail 100% of the time* if wired (it decrypts a secret that is stored in plaintext — CQ-B22/SEC-031); the notification dispatcher still has zero call sites (CQ-B29); the frontend's extracted shared components ship as dead code with the duplication they were meant to remove still intact (CQ-F15); and the CI "e2e" job runs vitest, not Playwright, so all 12 Playwright specs — including the auth contract test — never execute (**CQ-F36, new**).
2. **Structural debt is dented, not cleared.** `main.rs` still has no `AppState` and ~45 inline `app_data` registrations (CQ-B43 partial); 24 repos still define their own `CountRow` and there's still no generic `paginate<T>` (CQ-B10 partial); the GDPR/email repos institutionalized the `DbError::Migration` misuse into the shared helper (CQ-B11, CQ-B44-adjacent); OAuth2 still collapses repo errors to `invalid_client` (CQ-B18).
3. **A few remediations are incorrect.** The gRPC governor was "fixed" into `per_second(100)` semantics that throttle to ~1 token/100s — worse than the original bug (CQ-B44). The XFF rate-limit fallback returns the client-controlled hop (SEC-060). The SurrealDB token-expiry fix deferred a 1-hour failure to a 4-week one with no renewal loop (**CQ-B45, new**).

### Active finding counts

| Priority | Backend | Frontend |
|---|---|---|
| High | 6 | 6 |
| Medium | 17 | 9 |
| Low | 11 | 9 |

**Fully fixed this round**: 11 backend + 12 frontend previously-active findings (see per-finding verdicts).

### Suggested fix order

1. **CQ-B44** (gRPC governor semantics — currently throttles the mesh to a crawl) and **CQ-F36** (run Playwright in CI so the contract/auth specs actually gate).
2. **CQ-B22 + SEC-031** (webhook: wire delivery via AMQP *and* encrypt the secret, or the first delivery fails on decrypt).
3. **CQ-B45** (SurrealDB token renewal loop — a 4-week uptime ceiling on an IAM control plane).
4. Structural leverage: **CQ-B10** (repo helpers + generic paginate), **CQ-B43** (AppState), **CQ-F15** (actually adopt the shared components), **CQ-B11** (error taxonomy).
5. **CQ-F27/F29/F31** (frontend auth-flow bodies, tenant-context-on-reload, MFA-setup landing).

---

# Backend findings

## High

### CQ-B37 [HIGH] ✅ FIXED — axiam-server compiles
`crates/axiam-server/Cargo.toml:37-40` moves `uuid`/`chrono`/`serde_json` to `[dependencies]` and adds `sha2`; `cleanup.rs` uses `sha2::{Digest, Sha256}` (no `rsa::sha2`), with `rsa` correctly dev-only. Verified: `cargo build --workspace` is green and produces the `axiam-server` binary.

### CQ-B45 [HIGH] 🆕 — SurrealDB root token given a fixed 4-week TTL with no renewal or reconnect
- **File**: `crates/axiam-db/src/connection.rs:23,104-136` (`ROOT_TOKEN_DURATION = "4w"`, `extend_root_token_duration` — one call site, in `connect`)
- **Issue**: the Phase-13 "connection resilience" work fixed a 1-hour token expiry by `DEFINE USER OVERWRITE … DURATION FOR TOKEN 4w` at startup, but added no renewal task and no reconnect-on-auth-failure path (the code itself notes re-`signin` on the live handle is rejected). `health_check` only runs `RETURN 1`. A process with >~4 weeks of uptime (routine for an IAM control plane) hits the cached-JWT expiry and every DB request begins to 401 — login, audit, cleanup — until an operator restarts. This defers the exact failure mode the phase set out to eliminate rather than removing it.
- **Fix**: a periodic re-`signin`/handle-refresh well inside the TTL, or reconnect-on-auth-error; failing that, document the hard uptime ceiling and add a readiness alarm.

### CQ-B01 [HIGH] ✅ FIXED — pepper wired into the user repo
`main.rs:312-314` builds `SurrealUserRepository::with_pepper(db, config.auth.pepper…)`; create hashes with `self.pepper` (`user.rs:242`), login verifies with the same pepper (`service.rs:250-252`). `hash_password(Some(""))` equals `hash_password(None)`, so the `unwrap_or_default()` case is consistent. REST-created users log in with or without a pepper set.

### CQ-B02 [HIGH] 🔶 PARTIAL — spawn_blocking around most, not all, crypto
Login verify + dummy verify, both change-password verifies, the history-check loop, and all PKI keygen/sign now run in `spawn_blocking` behind a bounding `crypto_semaphore`. Remaining inline Argon2 on executor threads: db-repo `create`/`update_password` hashes (`user.rs:242,639`), the **new-password hash** in `change_password` (`service.rs:728` — the verifies around it are wrapped, the hash isn't), and gRPC `ValidateCredentials` verify (`services/user.rs:128`).

### CQ-B08 [HIGH] ✅ FIXED — resource hierarchy cycles/truncation/orphans
`resource.rs:205-221` rejects self-parent and cycle-creating re-parents (`Validation("cycle detected")`); `delete` blocks when `child_of` edges exist (`:275-294`); `get_ancestors` now errors past `MAX_ANCESTOR_DEPTH` instead of silently truncating (`:386-401`). (The delete edge-cleanup is still non-transactional — that's CQ-B07; and the guard+delete is a TOCTOU — see CQ-B46.)

### CQ-B40 [HIGH] ✅ FIXED — federation operable via API
`handlers/federation.rs:68-88` adds `idp_signing_cert_pem` + `allowed_algorithms` to the create/update DTOs; `validate_pem_cert` runs before persistence; the repo persists both columns; PEM parsing uses the `pem` crate + `x509_parser` (line-concatenation parser gone). SAML configs can reach a complete state and OIDC configs get a working allow-list via the API. Gap: the specifically-requested *create-via-API-then-complete-a-login* e2e is still absent.

### CQ-B38 [HIGH] 🔶 PARTIAL — GDPR purge/export correctness
Fixed: purge flags cleared last (re-selectable on failure), missing `webauthn_credential`/`password_history` deletes added, `unwrap_or_default()` swallowing replaced with `?`, audit export paginated past 10k, and a `Failed` job status added. Open: per-item shutdown checks still absent (only between sweeps); `sessions` is still hardcoded `[]` in the export while attesting `schema_version "1.0"`; a swallowed audit-pseudonymize failure certifies erasure with residual PII (SEC-063).

### CQ-B03 / CQ-B05 / CQ-B06 / CQ-B07 — see per-topic notes
- **CQ-B03** ✅ FIXED — sparse `Option` override mask (see SEC-033).
- **CQ-B05** 🔶 PARTIAL — audit/authz queues now declare real DLXs matching `MAIL_OUTBOUND`; the audit permanent-drop and authz hot-loop nacks are fixed. Remaining: mail retry republish still has no backoff delay.
- **CQ-B06** 🔶 PARTIAL — apply+record is now one `BEGIN/COMMIT` and a `_migration_lock` record is written, but the legacy v1 DDL is still plain `DEFINE` (non-idempotent on bare re-run) and the "lock" is a plain `UPSERT` that provides no mutual exclusion (double-apply is prevented only by the version UNIQUE index + per-migration transaction).
- **CQ-B07** ❌ OPEN — role/permission edge deletes are still non-transactional and keyed by UUID without a tenant predicate (cross-tenant edge-strip; see SEC-007/SEC-058 in the security report).

## Medium

### CQ-B44 [MEDIUM] ❌ OPEN (remediation is wrong — now worse) — gRPC governor throttles to ~1 token / 100 s
- **File**: `crates/axiam-api-grpc/src/middleware/rate_limit.rs:40-47`
- **Issue**: the code now calls `.per_second(authz_per_sec as u64).burst_size(authz_per_sec * 2)`, but tower_governor 0.8's `per_second(n)` sets the *replenish period* to `n` seconds ("one token every n seconds"). With the default `grpc_authz_per_sec = 100`, this becomes "1 token every 100 s, burst 200" — sustained ~0.01 req/s, and *raising* the config makes the limiter slower. The original `per_second(1)` bug was 1 req/s; this is 100× worse and inverted.
- **Fix**: use `per_millisecond(1000 / authz_per_sec)` (or `Quota::per_second`) with a separate burst; add a test asserting sustained throughput.

### CQ-B10 [MEDIUM] 🔶 PARTIAL — shared repo helpers exist but adoption is thin
A `helpers` module now offers `CountRow`, `parse_uuid`, `take_first_or_not_found`, adopted by ~4 repos. But **24 repositories still define their own `CountRow`**, there is still **no generic `paginate<T>`**, and unconverted repos still inline `Uuid::parse_str(...).map_err(DbError::Migration)`.

### CQ-B11 [MEDIUM] ❌ OPEN — duplicate-create still 500; `Migration` catch-all institutionalized
`AlreadyExists`→409 is produced only in `federation_login_state.rs`/`saml_replay.rs`; mainstream create paths (e.g. user create's `.check()` at `user.rs:275-276`) still map index violations to `DbError::Migration`→500. The new GDPR repos add ~18 more `Migration` misuses, and `helpers::parse_uuid:33-36` bakes the same mapping into the shared path — a corrupt-data read now surfaces as a 500 labeled "Migration failed".

### CQ-B17 [MEDIUM] 🔶 PARTIAL — unique edge indexes added; error mapping + drift remain
Migration v19 adds UNIQUE `(in,out)` indexes on the edge tables (`schema.rs:1057-1070`), so duplicate edges now error instead of silently inserting. Remaining: the false "IF NOT EXISTS avoids duplicates" comment is still above a plain `RELATE` (`group.rs:391`); a unique-violation maps to `Database`→500, not `AlreadyExists`→409; and `get_members` total/items still drift (count over edges vs selected rows).

### CQ-B24 [MEDIUM] 🔶 PARTIAL — big test-coverage gains; two gaps remain
`axiam-pki/tests/` (ca/cert/mtls/mtls_chain/pgp/failfast) and `axiam-api-grpc/tests/` (grpc_auth/grpc_authz) now exist where there were zero. Still missing: dedicated webauthn REST-handler tests and any `notification_rules` test.

### Carried-forward mediums (verdicts)
- **CQ-B13** 🔶 PARTIAL — assignments batched; grant queries + ancestor walk still N+1; dead `group_repo` still `#[allow(dead_code)]`.
- **CQ-B15** ❌ OPEN — `CertService` still rebuilds the CA from the subject CN (no `from_ca_cert_pem`); keypair/fingerprint/encrypt helpers still triplicated across ca/cert/pgp.
- **CQ-B16** ❌ OPEN — org/user delete still silently succeeds for missing ids; no cascade (tenant handler has a `get_by_id`-first mitigation only).
- **CQ-B18** ❌ OPEN — OAuth2 grant handlers still inline the client lookup and collapse DB outages to `invalid_client`; `authenticate_client()` used only by revoke/introspect.
- **CQ-B19** 🔶 PARTIAL — discovery cleaned up, but token/revoke/introspect still hard-require `?tenant_id=` (which discovery omits) and there's still no `QueryConfig` for RFC-shaped 400s.
- **CQ-B20** 🔶 PARTIAL — gRPC now sets frame-size/timeout/concurrency limits + env-gated TLS; still no graceful shutdown, and `batch_check_access` is unbounded/serial.
- **CQ-B21** 🔶 PARTIAL — 64 KiB `JsonConfig` now on both scopes; no Query/Path/Form configs; three envelope shapes unremediated.
- **CQ-B22** ❌ OPEN — webhook delivery still detached `tokio::spawn`, no persistence, **zero `.deliver(` call sites**, no secret rotation in the update DTO; and it decrypts a secret stored in plaintext, so wiring it as-is fails every delivery.
- **CQ-B23** 🔶 PARTIAL — SAML attribute_map applied; OIDC discovery still uncached, cap still after buffering, IdP 4xx still → 500, OIDC provisioning still ignores `attribute_map`.
- **CQ-B25** 🔶 PARTIAL — create paths use DTOs; role/group/tenant/service-account *update* handlers still bind domain structs.
- **CQ-B26** ✅ FIXED — `users::create` now validates email format + password policy; `notification_rules`/`email` still use `contains('@')`.
- **CQ-B39** 🔶 PARTIAL — export dedup + factored audit-append + 256-bit cancel token landed; deletion setup still non-transactional (a `create` failure after `mark_deletion_pending` strands an unrecoverable purge with no cancel token — cross-ref SEC-063).
- **CQ-B41** 🔶 PARTIAL — `set_*` now UPSERTs a deterministic `(scope, scope_id)` record (no row accumulation, deterministic reads); the flagged `Uuid::new_v4()` into `effective_email_config`/`email_config_from_org_input` is unchanged (now cosmetic).
- **CQ-B43** 🔶 PARTIAL — `load_key_from_env` extracted; still no `AppState`, `main()` still registers ~45 `app_data` inline.

## Low
- **CQ-B27** ❌ OPEN — federation/reset/verification services still constructed per request (9+ sites).
- **CQ-B28** ✅ FIXED — single capped `client_ip`/`user_agent` helper module, used uniformly in api-rest.
- **CQ-B29** ❌ OPEN — `NotificationDispatcher.dispatch()` still has zero production call sites; `NotificationPublisher` constructed but unconsumed; `AuditService` dead.
- **CQ-B31** 🔶 PARTIAL — impactful silent drops (gdpr/cleanup/webauthn) gone; one benign `let _ = invalidate(...)` remains.
- **CQ-B32** 🔶 PARTIAL — `DeviceIdentity.org_id` documented + caller-resolved; still `Uuid::nil()` not `Option<Uuid>`.
- **CQ-B33** 🔶 PARTIAL — revoke endpoints uniform, typed error variants added; `Database/Crypto/Internal/Certificate` still stringly, PUT-with-PATCH everywhere, `GET /oauth2/authorize` still 401-JSONs unauthenticated browsers.
- **CQ-B34** 🔶 PARTIAL — workspace deps unified; three `rand` majors + non-workspace `rand_core 0.6` in axiam-pki remain; unused deps not pruned.
- **CQ-B35** 🔶 PARTIAL — HIBP now runs on the sync change-password path; the vestigial `Result` on `check_hibp` is not removed.
- **CQ-B36** ❌ OPEN — audit-drop still `warn!`-only (no metric); channel still 4096.
- **CQ-B42** ✅ FIXED — seeder hashes the permission registry and skips the UPSERT loop when unchanged (migration v20 adds `seeder_state`).
- **CQ-B46 [LOW] 🆕** — `resource::delete` child-guard is a non-atomic TOCTOU: a concurrent create/re-parent between the child-count and the delete reintroduces the orphan state CQ-B08 closes (`resource.rs:278-312`). Wrap guard+delete in a transaction (ties to CQ-B07).
- **CQ-B47 [LOW] 🆕** — `axiam-db` still publicly exports a second `verify_password` Argon2 implementation (`user.rs:829-852`, re-exported at `mod.rs:69`/`lib.rs:34`), dead in production but inviting a pepper-less caller — delete it now that hashing is centralized.

---

# Frontend findings

## High

### CQ-F36 [HIGH] 🆕 — CI "e2e" job runs vitest, not Playwright; all 12 e2e specs never execute
- **File**: `.github/workflows/ci.yml:342` runs `npm test` = `vitest run` (`package.json:12`); `vitest.config.ts` includes only `src/**/*.test.ts` (one file). The 12 Playwright specs live in `e2e/` and run via `test:e2e` (`playwright test`), which CI never invokes — even though the job boots a backend, seeds a fixture, installs Chromium, and uploads a `playwright-report`.
- **Impact**: the auth-flow, login, and frontend↔OpenAPI *contract* specs — the very tests meant to catch the SEC-044/CQ-F27 regressions — are dead in CI. The "contract test in CI" the plan required is not running.
- **Fix**: change the step to `npx playwright test` (keep vitest as its own step).

### CQ-F27 [HIGH] 🔶 PARTIAL — auth flows: most wired; reset/resend still send wrong bodies
Change-password, verify-email, and MFA enroll/confirm now hit real `/api/v1/auth/*` routes via `services/auth.ts`. But `requestPasswordReset`/`confirmPasswordReset`/`resendVerification` omit the backend-required `tenant_id` (and resend omits `email`), so all three 400 and stay dead (security framing: SEC-044). The contract spec asserts only paths, not bodies, so it can't catch this even if it ran (CQ-F36).

### CQ-F28 [HIGH] ✅ FIXED — silent refresh + boot refresh
`lib/api.ts` sends refresh through the `api` instance (CSRF header attached), narrows `SKIP_REFRESH` to login/refresh/logout (no longer skips `/auth/me`), and `useAuthInit` performs one explicit boot refresh before declaring unauthenticated. `_retry` is set before the single-flight queue check. Confirmed by two reviewers.

### CQ-F05 [HIGH] 🔶 PARTIAL — logout calls the endpoint but 400s
`Topbar.tsx` now posts `/api/v1/auth/logout` and clears the query cache + auth on both logout and refresh-failure. But it posts `{}` while the handler requires `{session_id}` (the SEC-051 fix), so the request 400s and the server session/cookies survive (security framing: SEC-015). Fix requires a server change (revoke from JWT `jti`) or exposing `session_id`.

### CQ-F06 [HIGH] ✅ FIXED — lint clean + CI gates
`eslint .` reports 0 errors (was 9); `tsc -b` clean. `ci.yml` adds a `frontend-quality` job running `npm run lint && npx tsc -b`. (Caveat: the *e2e* gate is miswired — CQ-F36.)

### CQ-F01 / CQ-F07 / CQ-F08 ✅ FIXED
`"current-user"` gone (real `user.id`); OrganizationDetailPage dead `syncedRef` removed and the settings form now saves the displayed values; TenantsPage no longer fabricates "Status: Active".

### CQ-F02 [HIGH] 🔶 PARTIAL — `ConfirmDialog.confirmLabel` added, but the bespoke unlock dialog wasn't retired
`confirmLabel` prop exists and PgpKeysPage uses it, but the ~57-line inline UsersPage unlock dialog remains, and cert-revoke ConfirmDialogs still show the default "Delete".

### CQ-F03 / CQ-F04 ✅ FIXED
AuditLogsPage clears debounce timers on Clear/unmount/retrigger; user-search moved to a shared `UserSearchDialog` using `useQuery` keyed by term (stale-response race gone).

## Medium
- **CQ-F09** 🔶 PARTIAL — toast system + `getApiErrorMessage` + `onError` adopted on most pages; TenantsPage delete has no `onError` (silent), and a few create/edit mutations still surface raw `err.message`.
- **CQ-F10** ✅ FIXED (with a caveat) — dashboard query keys aligned with CRUD invalidations; but `["users",1,""]` now collides with UsersPage at a different page size (**CQ-F37**).
- **CQ-F11** 🔶 PARTIAL — `noValidate` removed from `FormDialog`; still present on LoginPage (×3) and BootstrapPage.
- **CQ-F12** ✅ FIXED — resource parent picker excludes descendants (BFS); de-parenting sends explicit `null`.
- **CQ-F13** ✅ FIXED — federation type select `disabled` in edit mode; payload matches the (now immutable) protocol.
- **CQ-F14** 🔶 PARTIAL — `placeholderData` added; stranded-empty-page-after-delete still unhandled.
- **CQ-F15** 🔶 PARTIAL (adoption ~zero) — `components/shared.tsx` (`ToggleField`/`SectionCard`/`InfoRow`/`ActionBadge`), `lib/utils.slugify`, and `hooks/useCrudMutations` were extracted, but **nothing imports them** — `ToggleField` is still defined locally 8×, `SectionCard`/`InfoRow` 3×, `ActionBadge`/`slugify` 2×. The shared module is dead code; the duplication it targets is intact.
- **CQ-F16** 🔶 PARTIAL — Dashboard/usePermissions use selectors; AppLayout/Topbar still subscribe to the whole store.
- **CQ-F17** 🔶 PARTIAL — single `MfaMethod` type; profile/MFA pages still make inline `api.*` calls instead of a typed users service.
- **CQ-F18** ✅ FIXED — role/group unassign methods now have call sites.
- **CQ-F19** 🔶 PARTIAL — VerifyEmailPage hits the real endpoint, but still relies on a `cancelled` flag (no `useRef` once-guard), so it double-fires under StrictMode and can flip to "failed" after success (dev only).
- **CQ-F20** 🔶 PARTIAL — TenantsPage loading gate fixed; the N+1 `Promise.all(orgs.map(list))` fan-out remains.
- **CQ-F29** 🔶 PARTIAL (behaviorally broken) — frontend reads `tenant_slug`/`org_slug` on reload, but `/auth/me`'s `MeResponse`/`LoginUserInfo` never emit them, so the Topbar reverts to "Select tenant" after any hard reload. **Backend fix needed**: add the slugs to `/auth/me`.
- **CQ-F30** 🔶 PARTIAL — `ProtectedRoute`/`ForbiddenPage` added but wired to only 3 of ~14 gated sections; LoginPage still falls back to `permissions: []` on a transient `/auth/me` failure; Sidebar still ignores `isLoading` and flashes disabled at boot.
- **CQ-F31** 🔶 PARTIAL — LoginPage routes `mfa_setup_required` to `/profile/mfa`, but that page never reads the `setup_token` and enrolls via the full-session endpoint, so MFA-mandated users hit a dead end.

## Low
- **CQ-F21** ✅ FIXED — `Placeholder.tsx` deleted.
- **CQ-F22** ✅ FIXED — unused `@radix-ui` deps removed; the three remaining are all imported.
- **CQ-F23** ✅ FIXED — `PasswordPolicyChecker` on admin create + bootstrap (policy still client-hardcoded, a separate sub-item).
- **CQ-F24** ✅ FIXED — safe `getRowKey` fallback in DataTable.
- **CQ-F25** ✅ FIXED — locale-aware `Intl.DateTimeFormat(undefined, …)` (no hardcoded `en-US`).
- **CQ-F26** ✅ FIXED — `CSS.escape` in the ResourceTree selector.
- **CQ-F32** ✅ FIXED — `_retry` guard on the refresh replay; `getCookie` uses a static regex.
- **CQ-F33** ✅ FIXED — module-level empty-permissions constant.
- **CQ-F34** 🔶 PARTIAL — BootstrapPage has the policy checker; 404 still maps to "Already Initialized" (now matches the backend contract but a proxy-404 is indistinguishable); `noValidate` remains.
- **CQ-F35** ✅ FIXED — `useAuthInit` `useRef` once-guard survives StrictMode; dead dep removed.
- **CQ-F37 [LOW] 🆕** — Dashboard and UsersPage share the query key `["users",1,""]` but request different page sizes (`list(1,1,"")` vs `list(page,20,search)`); whichever refetches last wins the cache, so navigating Dashboard→Users can render a 1-row user list until refetch. Introduced by the CQ-F10 key alignment. Give the dashboard a distinct key.
- **CQ-F38 [LOW] 🆕** — `OrganizationDetailPage` settings form re-initializes from server data on every background refetch (`useEffect([settings])` with the lint suppressed), silently discarding an admin's in-progress edits on window refocus. Guard the init on first load or track dirtiness.
- **CQ-F39 [LOW] 🆕** — `components/shared.tsx` + `hooks/useCrudMutations.ts` shipped with zero importers — pure maintenance overhead until CQ-F15 adoption happens (or delete them).

---

## Architecture observations

**Backend.** The remediation followed the established trait-in-core / impl-in-db / thin-handler shape and added real tests where there were none (PKI, gRPC). Four structural weaknesses persist: (1) repository boilerplate still metastasizes and the shared helper even institutionalized the `Migration`-error misuse (CQ-B10/B11); (2) still no transactions around multi-statement mutations (CQ-B07/B38/B46), now including the GDPR purge and resource-delete guard; (3) `main.rs` still has no `AppState` and ~45 inline registrations (CQ-B43); (4) enforcement-by-convention — RBAC, CSRF, secret-encryption, and now the tenant-edge guard (applied to `grant_to_role` but not the REST-reachable `grant_to_role_with_scopes`) — is correct where wired and silently absent where not. The connection-resilience work traded a 1-hour bug for a 4-week one (CQ-B45), and two "fixes" are numerically wrong (CQ-B44 governor, SEC-060 XFF).

**Frontend.** The cookie-auth + refresh-interceptor rewrite is the strongest piece of the wave — correct single-flight, CSRF injection, boot refresh. But the same anti-pattern as last round repeats: the pages that bypassed the services layer still do; the extracted shared components ship unused; the auth-recovery flows send bodies the backend rejects; and the tests meant to catch all of this don't run in CI. The single highest-leverage move remains adopting the shared CRUD/mutation plumbing and running Playwright (with body assertions) as a real gate.

## Test coverage (updated)

| Area | State |
|---|---|
| axiam-api-rest | Strong: rbac/gdpr/bootstrap/password-change/security-headers/route-parity suites. Gaps: webauthn handlers, notification_rules (0). |
| axiam-server | federation e2e (oidc/saml/clock-skew/secret-at-rest/backfill), session lifecycle, service-account aud, cleanup, healthcheck. Missing: create-config-via-API-then-login e2e (CQ-B40). |
| axiam-pki | **New** — ca/cert/mtls/mtls_chain/pgp/failfast (was zero). |
| axiam-api-grpc | **New** — grpc_auth/grpc_authz (was zero); covers only AuthorizationService, not UserService/TokenService (SEC-003). |
| axiam-db | tenant-isolation tests added — but exercise the guarded `grant_to_role`, not the REST-reachable `grant_to_role_with_scopes` (SEC-058). |
| Frontend | 1 vitest file runs in CI; the 12 Playwright specs **do not run** (CQ-F36). |

## Static analysis (this round)
- `cargo build --workspace`: **green** (axiam-server binary produced).
- `cargo clippy`: all 12 library crates clean.
- `eslint .`: **0 errors** (was 9). `tsc -b`: clean. `npm audit`: 0 vulnerabilities.
- Build prerequisites remain `protoc` + `libxml2-dev` + `libxmlsec1-dev` (samael); `utoipa-swagger-ui` fetches an asset at build time (needs network or a pre-seeded `SWAGGER_UI_DOWNLOAD_URL`).
