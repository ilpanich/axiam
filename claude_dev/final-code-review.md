# AXIAM — Final Pre-MVP Code-Quality & Correctness Review

- **Date**: 2026-07-06
- **Commit reviewed**: `031abfe` (HEAD of `claude/final-security-code-review-j0fzni`)
- **Baseline**: [`code-review-postremediation.md`](code-review-postremediation.md) (reviewed `ea85872`). **111 commits / ~123k insertions** since: v1.2 hardening (phases 23–29), phase 30 docs, and **7 new client SDKs (~63k lines)**.
- **Method**: independent re-verification of every active `CQ-B*`/`CQ-F*` finding against current code with file:line evidence, a fresh correctness scan of v1.2-touched backend modules, the **first quality review of the 7 SDKs** (structure, error handling, contract conformance, tests, packaging), the frontend, and a build/CI/lint pass (scoped `cargo clippy`, `eslint`, `tsc`, `cargo audit`). Multi-agent fan-out.
- **Companion**: [`final-security-review.md`](final-security-review.md) — security-primary items (`SEC-*`, SDK `X-*`/`SDK-NN`) live there.

Statuses: ✅ FIXED · 🔶 PARTIAL · ❌ OPEN · ⚠️ REGRESSION. New findings continue at **CQ-B48 / CQ-F40 / SDK-Q01 / CI-01**.

> **Written for an Opus 4.8 planner + Sonnet 5 executor.** Every open item has an exact anchor, an impact statement, and a concrete fix. Prioritized order in §6.

---

## 1. Executive summary

This wave closed the structural backlog far more than either prior round. The two headline architectural debts the last two reviews kept re-flagging are **done**: `main.rs` now has a real `AppState` composition root (**CQ-B43 ✅**, ~45 inline registrations → 4), and the repository layer has a shared `helpers` module with a canonical `CountRow` and a generic `paginate<T>` (**CQ-B10 ✅**, 26 repos migrated). The gRPC governor math is correct and test-backed (**CQ-B44 ✅**), OAuth2 error collapse is fixed (**CQ-B18 ✅**), GDPR export/deletion are complete and atomic (**CQ-B38/B39 ✅**), and on the frontend **6 of 8 headline items are fully fixed** (auth-flow bodies, logout, tenant-context-on-reload, MFA-setup landing, Playwright-in-CI with body-asserting contract tests, and shared-component adoption).

Three themes remain, and they concentrate the risk:

1. **A partially-applied resilience fix is now *masked*, not just incomplete.** The SurrealDB token-renewal loop (CQ-B45) refreshes only the *manager's* handle; the ~30 request-serving repositories hold independent auth snapshots that still expire ~4 weeks after startup — and `health_check` probes only the renewed handle, so `/ready` stays green while every DB request 401s (**CQ-B48, High**). The readiness alarm the phase promised cannot fire.
2. **The "wired-but-broken" class persists in webhooks.** Delivery machinery (durable RabbitMQ retry, encrypt-on-write) is now correct, but `emit()` still has **zero call sites** and the publisher isn't in `AppState` (**CQ-B22**), so no domain event dispatches; and on a retry-publish failure the consumer **acks the original** — losing the delivery entirely while writing an audit record that claims a retry was scheduled (**CQ-B49, High**).
3. **The cross-tenant graph-edge strip (CQ-B07) is only half-fixed.** `role.delete`/`resource.delete` are now transactional + tenant-guarded, but `permission.delete`, `group.delete`, `service_account.delete`, `group.remove_member`, and the `resource.update` re-parent path still `DELETE` edges by raw UUID with no tenant predicate (three of them without `.check()`). This has a security dimension — see the companion.

The SDKs are a genuinely high-quality, contract-disciplined set (all 7 expose exactly the canonical surface + single-flight guard + `Sensitive` redaction, each with a concurrency test). Their issues are consistency/idiom polish plus a handful of real bugs (the Rust/Go AMQP-HMAC ordering, TS Node-REST wiring, a broken TS dependency pin).

### Active finding counts

| Priority | Backend | Frontend | SDK | Build/CI |
|---|---|---|---|---|
| High | 2 (B48, B49) | 0 | 2 (Q01, Q04/Q05) | 1 (CI-01) |
| Medium | 4 (B50–B53) | 1 (F40) | ~7 | 1 (CI-03) |
| Low | ~6 | ~3 | ~8 | 1 (CI-05) |

---

## 2. Backend — verification of prior findings + new bugs

### Fixed and verified ✅
| ID | What | Evidence |
|---|---|---|
| **CQ-B44** | gRPC governor throughput | Constructs `Quota::per_second` directly, feeds `replenish_interval()`/`burst_size()` into `const_period`/`const_burst_size` (`axiam-api-grpc/src/middleware/rate_limit.rs:183-193`) → ~100 req/s sustained at `authz_per_sec=100`. Test drains the burst *then* counts replenished tokens over a 1 s fake clock (`:477-557`) — asserts sustained rate, not just a burst pass. Wired live (`server.rs:86,122`). |
| **CQ-B43** | main.rs `AppState` | `AppState` in `state.rs`, single composition root (`main.rs:825-879`), registered once (`:908`); only 4 real `.app_data` calls remain. |
| **CQ-B10** | repo helpers | Exactly one `struct CountRow` (`helpers.rs:19`), imported by 26 repos; generic `paginate<T>` (`helpers.rs:103`, unit-tested) adopted by ~20 repos. |
| **CQ-B18** | OAuth2 error collapse | All grant handlers discriminate `NotFound`→`invalid_client` vs everything-else→`ServerError` (`oauth2/src/token.rs:175-184,355-364,472-481,768-781`). |
| **CQ-B38** | GDPR export completeness | `sessions` populated from `session_repo.list_by_user` (metadata only, token_hash excluded) (`cleanup.rs:706-718,792`); `schema_version:"1.0"` now truthful; all sections `?`-propagate. |
| **CQ-B39** | GDPR deletion atomicity | Single `create_with_pending_flag` → `BEGIN…UPDATE…IF dup THROW…CREATE…COMMIT` (`account_deletion.rs:184-204`); rollback test `gdpr_test.rs:532-593`. |
| **CQ-B15** | CertService rebuilds CA | Now `CertificateParams::from_ca_cert_pem(&ca_cert_pem)` (`pki/src/cert.rs:128,143`), not CN reconstruction. |
| **CQ-B46** | resource-delete TOCTOU | Guard+delete folded into one `BEGIN…IF len>0 THROW…DELETE…COMMIT` (`resource.rs:293-305`). |
| **CQ-B47** | dead `verify_password` export | Removed — 0 matches in `axiam-db`. |

### CQ-B45 [HIGH] 🔶 PARTIAL → escalates to CQ-B48 — SurrealDB token renewal reaches only the manager handle
- **File**: `crates/axiam-db/src/connection.rs:333-339` (re-signin), `:398-476` (reconnect), `:508-517` (health probe); repo clones at `crates/axiam-server/src/main.rs:259-388`
- **Verified**: the proactive re-signin *does* refresh the manager's own live handle in place (surrealdb 3.2.0 mutates the session auth on `signin`), the cadence (≈2.4 wk of a 4 wk TTL) is safely inside the token TTL, and reconnect-on-auth-error rebuilds-and-swaps under the write guard. Good.
- **Open**: repositories are built from `db.client_cloned().await`, and cloning a `Surreal<Client>` produces an **independent auth snapshot** (new session id, `RwLock`-copied auth). The manager's re-signin/reconnect never propagates to these clones → every request-serving repo holds a JWT expiring ~4 weeks after startup. See **CQ-B48**.

### CQ-B48 [HIGH] 🆕 — Repo-handle token expiry is undetectable (health check masks it)
- **File**: `crates/axiam-db/src/connection.rs:508-517` + repo clones (`main.rs:259-388`)
- **Issue**: after ~4 weeks of uptime all repository DB handles 401, but `health_check` probes only the manager's (renewed) handle, so `/ready` reports healthy while every API DB request fails — an *undetectable* outage, arguably worse than a visible one.
- **Fix**: thread the manager's swappable `Arc<RwLock<Surreal>>` into repositories (so re-signin/reconnect reaches request-serving handles), **or** make `health_check` exercise a freshly-cloned handle / real record read so the probe detects repo-token expiry; add a hard-uptime alarm regardless.

### CQ-B22 [MEDIUM] 🔶 PARTIAL — Webhook delivery: machinery fixed, still non-delivering end-to-end
- **File**: `crates/axiam-api-rest/src/webhook.rs:159` (`emit()`), `state.rs` (no publisher field), `main.rs:685`
- **Fixed**: durable RabbitMQ retry topology (per-message TTL + DLQ, `axiam-amqp/src/webhook_publisher.rs:87-97`, `connection.rs:230-281`), encrypt-on-write/decrypt-on-delivery consistent (no more 100%-fail decrypt), update DTO rotates the secret (`webhooks.rs:43,228-234`), consumer wired (`main.rs:701`).
- **Open**: `WebhookDeliveryService::emit()` has **zero call sites**, and the `WebhookPublisher` built at `main.rs:685` is **not stored in `AppState`**, so handlers physically cannot emit. A registered webhook receives nothing on any domain event.
- **Fix**: add `webhook_publisher` to `AppState`; call `state.webhook_delivery.emit(&publisher, tenant_id, "user.created", payload)` from event sites (mirror `mail_outbound_publisher.publish`).

### CQ-B49 [HIGH] 🆕 — Webhook consumer acks the original on retry-publish failure → delivery lost + lying audit record
- **File**: `crates/axiam-api-rest/src/webhook_consumer.rs:306-335`
- **Issue**: in `handle_delivery_failure`, if `publish_retry(...)` returns `Err`, the code logs, then still writes a "delivery_attempt" audit record claiming `next_retry_in_ms` **and acks the original** (`acker.ack`, `:333`). The retry copy was never enqueued and the original is gone → delivery lost with no retry and no DLQ, while the audit trail asserts a retry is pending.
- **Fix**: on `publish_retry` failure, `nack` (requeue:false → DLQ, or requeue:true) instead of acking; do not write a retry-scheduled audit record when the enqueue failed.

### CQ-B07 cluster [MEDIUM] 🔶 PARTIAL — Non-transactional, tenant-unguarded graph-edge deletes
`role.delete` (`role.rs:288-304`) and `resource.delete` (`resource.rs:293-306`) are now transactional with `out.tenant_id=$tenant_id`/`in.tenant_id=$tenant_id` edge guards. The rest are not:

| # | Method | Anchor | Transactional | Tenant-scoped edge delete |
|---|---|---|---|---|
| **CQ-B50** | `permission.delete` | `permission.rs:238-248` | ❌ | ❌ `DELETE grants WHERE out=permission:UUID` |
| **CQ-B51** | `resource.update` re-parent | `resource.rs:214-222` | ❌ | ❌ `DELETE child_of WHERE in=resource:UUID` |
| **CQ-B50** | `group.delete` | `group.rs:274-284` | ❌ | ❌ `DELETE member_of WHERE out=group:UUID` |
| **CQ-B52** | `group.remove_member` | `group.rs:389-410` | N/A | ❌ `_tenant_id` param ignored (`:391`) |
| **CQ-B50** | `service_account.delete` | `service_account.rs:289-300` | ❌ | ❌ `DELETE has_role WHERE in=service_account:UUID` |

- **CQ-B50 [MED]**: `permission.delete`/`group.delete`/`service_account.delete` also fire the query and drop the response **without `.check()`** (unlike the two fixed paths), so per-statement failures — including the cross-tenant no-op and real DB errors — are silently returned as `Ok(())`.
- **CQ-B51 [MED]**: the re-parent's `DELETE child_of → UPDATE → RELATE` is three non-transactional statements; a failure after the DELETE (e.g. RELATE hits a UNIQUE violation) leaves the resource **parentless/orphaned** with no rollback — the exact class `resource.delete`'s txn fix closed, not applied here.
- **CQ-B52 [MED]**: `group.remove_member` discards its `tenant_id`, so any caller with a user+group UUID pair can sever a membership cross-tenant.
- **Fix (all)**: wrap each in `BEGIN/COMMIT`, add `AND {endpoint}.tenant_id=$tenant_id` to every edge DELETE (mirror `role.delete`), restore `.check()`, and use the `tenant_id` param in `group.remove_member`. (Security dimension: companion §3.)

### CQ-B53 [MEDIUM] 🆕 — Webhook consumer `process::exit(1)` on AMQP stream end takes down the whole server
- **File**: `crates/axiam-server/src/main.rs:710-711`
- **Issue**: if the webhook consumer's AMQP stream ends (a transient broker disconnect), it calls `std::process::exit(1)` — killing the entire API server (auth, authz, everything), not just webhook delivery.
- **Fix**: reconnect the consumer with backoff instead of exiting the process.

### CQ-B11 [MEDIUM] 🔶 PARTIAL — Error taxonomy: 409 plumbing done, most create paths still 500 on duplicate
- **Fixed**: `DbError::AlreadyExists{entity}` → 409 (`error.rs:26,42`; `api-rest/src/error.rs:39`); `classify_write_error` (`helpers.rs:65`) centralizes 409 detection; user-create returns 409 (`user.rs:285`, test `qual03_error_taxonomy_test.rs:176`); **`parse_uuid` no longer mis-maps to `Migration`** (uses `Serialization`, `helpers.rs:35-38`) — that prior sub-claim is stale.
- **Open**: role create still 500s on duplicate (`role.rs:145` `.map_err(DbError::Migration)`; also inline `Uuid::parse_str` at `:153-154` despite `parse_uuid` imported); permission-grant edge (`permission.rs:329`) and cert→service-account binding (`certificate.rs:419`) fall through to `Migration`→500. ~319 `DbError::Migration` occurrences across 37 files; most `.check()` write sites unconverted. Inline `contains("already exists")` triplets in `seeder.rs`/`saml_replay.rs`/`federation_login_state.rs` bypass the single-source `classify_write_error`.
- **Fix**: route remaining create/RELATE `.check()` sites through `classify_write_error`; collapse the inline triplets.

### Quick verdicts (carried-forward)
- **CQ-B13 (authz N+1) — ❌ OPEN**: per-role grant lookup loops one query/role (`authz/src/engine.rs:129-136`); ancestor walk one SELECT/level (`resource.rs:418-461`). Fix: `WHERE role_id IN $ids` + a single recursive/graph query.
- **CQ-B16 (delete missing-id silent success) — ❌ OPEN**: `user.rs:474-491`, `organization.rs:193-201` return `Ok(())` with no affected-row check; handler 204s for a nonexistent id (`organizations.rs:230`). Fix: `RETURN AFTER`/`meta::id`, map empty → `NotFound`.
- **CQ-B23 (OIDC discovery) — ❌ OPEN (all three)**: uncached, fetched per login (`federation/src/oidc.rs:131-155,241,306`); body cap applied *after* full buffering (`:167,170`); IdP non-2xx → `AxiamError::Internal` 500 (`federation/src/error.rs:132`).
- **CQ-B18 residual — DRY**: the three grant handlers inline byte-identical client-auth copies instead of calling `authenticate_client()` (used only by revoke/introspect). Maintainability, not a bug.

---

## 3. Frontend — verification + new bugs

### Fixed and verified ✅ (6 of 8 headline items)
- **CQ-F36** — CI runs Playwright `npm run test:e2e` in a dedicated `e2e` job (`ci.yml:349`) + vitest as a separate step (`:364`); **the contract spec now asserts request bodies** (`e2e/auth-contract.spec.ts:127-290`), so a SEC-044-style body regression fails CI.
- **CQ-F27/SEC-044** — `services/auth.ts` threads `tenant_id`/slugs on reset/confirm/resend (`:61-65,83-87,115-118`), proven by the contract spec.
- **CQ-F05/SEC-015** — bodyless logout (`Topbar.tsx:93`); backend revokes from JWT `jti` (`handlers/auth.rs:371-376`).
- **CQ-F29** — `MeResponse` emits `tenant_slug`/`org_slug` from the session (`auth.rs:702-725`); `useAuthInit`/`MfaSetupPage` restore context on reload.
- **CQ-F31** — `mfa_setup_required` routes to `/auth/mfa-setup?setup_token=…` (`LoginPage.tsx:111-113`); `MfaSetupPage` reads the token, enrolls via the setup endpoint with a `useRef` once-guard (`:42,54-59,64,83`).
- **CQ-F15/F39** — shared components adopted by ~9 pages; `useCrudMutations` in `RolesPage.tsx:133`; `slugify` centralized (`lib/utils.ts:59`). One residual: `SettingsPage.tsx:124` keeps a local `ToggleField` because it's a **superset** (adds `description`/`disabled`); migration requires extending the shared component first.
- Also ✅: CQ-F37 (dashboard uses distinct `["users","dashboard-count"]` key, test-asserted), CQ-F38 (settings form seeds once via `initializedRef`, no edit-loss on refocus), CQ-F19 (VerifyEmailPage `useRef` once-guard).

### Still partial / new
- **CQ-F30 [MED] 🔶 PARTIAL** — `ProtectedRoute` wraps only **3 of ~15 gated groups** (`organizations:list`, `users:list`, `audit_logs:list` in `router.tsx:78,104,168`); groups/roles/permissions/resources/certificates/webhooks/pgp-keys/oauth2-clients/notification-rules/service-accounts/federation/settings render for **any** authenticated user (403 with no friendly state). And `LoginPage` still falls back to `permissions: []` on a transient `/auth/me` failure (`LoginPage.tsx:122,169`). **Fix**: wrap all gated groups in `ProtectedRoute`; treat a null `/auth/me` after login as a hard failure, not empty-permissions.
- **CQ-F40 [MED] 🆕** — `AuditLogsPage` stores debounce timers in `useState` with a single cleanup effect keyed `[actorTimer, actionTimer]` (`pages/audit/AuditLogsPage.tsx:205-236`): typing in the "action" filter re-runs the effect and its cleanup **clears the pending actor-debounce timer** (and vice-versa), cancelling the sibling search. **Fix**: store each timer in a `useRef` (the pattern in `components/SearchInput.tsx:23,34,41-45`), or reuse `SearchInput`.
- **CQ-F09 [MED] 🔶 PARTIAL** — `TenantsPage` `deleteMutation` still has no `onError` (`TenantsPage.tsx:344-351`) — delete failures are silent (create/edit have `onError`).
- **CQ-F41 [LOW] 🆕** — divergent query keys for MFA-methods (`["user-mfa",userId]` vs `["mfaMethods"]` vs `["mfaMethods",userId]`) and `["currentUser"]` vs `["currentUser",userId]` — self-consistent today but a latent invalidation-miss trap. Standardize on a key factory.
- **CQ-F20 [LOW] 🔶** — TenantsPage N+1 `Promise.all(orgs.map(list))` fan-out remains (`TenantsPage.tsx:197-207`).
- **CQ-F11 [LOW] 🔶** — `noValidate` still on LoginPage forms (`LoginPage.tsx:248,305,396`).

### Clean (do not touch)
No `dangerouslySetInnerHTML` anywhere; no `localStorage`/`sessionStorage` token handling (tokens stay in httpOnly cookies); `lib/api.ts` single-flight refresh is sound (`_retry` before the queue check, static CSRF regex, `SKIP_REFRESH` list).

---

## 4. SDK code quality (first review)

**Nature**: focused auth/authz client libraries implementing `CONTRACT.md` §1–§10 (7 canonical methods, 3-type error taxonomy, CSRF forwarding, cookie jar, `Sensitive` redaction, AMQP-HMAC consumer, single-flight refresh, per-framework middleware) — **not** full-CRUD clients over `openapi.json`. gRPC stubs are generated; auth/http/token layers are hand-written and broadly parallel across languages. All 7 ship the canonical surface + a single-flight guard with an N≥5 concurrency test + `Sensitive` redaction — a strong, disciplined baseline.

### High
- **SDK-Q01 [HIGH]** — AMQP-HMAC canonicalization: **Rust & Go recompute over sorted keys**, server signs in struct declaration order → verification fails for every real message, message dropped. Masked by pre-sorted toy fixtures. (Full detail + fix in the security companion X-1; it's a correctness bug with a security-control impact.)
- **SDK-Q04 [HIGH, Rust]** — REST authz POSTs omit `X-CSRF-Token`: `send_authz_post` sets only `X-Tenant-ID` (`sdks/rust/src/rest/authz.rs:145-150`), unlike Rust's own `refresh`/`logout` and unlike Go. If the server enforces CSRF on the authz endpoints, `checkAccess`/`can`/`batchCheck` fail. **Fix**: add `.maybe_csrf_header()`.
- **SDK-Q05 [HIGH, TypeScript]** — Node REST persona not wired: `AxiamClient` always builds a browser-style `SharedSession` with no cookie jar (`sdks/typescript/src/rest/client.ts:20-23`); there's no path to inject `NodeSession`, so `onAuthenticated` is a production no-op and Node REST `login()`/`refresh()` can't persist the httpOnly cookies → every post-login call fails. **Fix**: expose a Node-session construction path (jar + CSRF/refresh interceptors). `NodeSession` today is exercised only by tests.

### Medium
- **SDK-Q06 [MED, TypeScript]** — broken dependency pin: `amqplib: "^2.0.0"` (`package.json:94`) — the real line is `0.10.x`, and `@types/amqplib: "^0.10.0"` contradicts a `^2` runtime major; likely fails clean install. `jsdom ^29`/`vitest ^4` also look ahead of their real majors. **Fix**: correct pins against the registry.
- **SDK-Q02 [MED, all 7]** — `AuthzError` never surfaces the server's denied `action`/`resource_id` from the response body (§2 SHOULD): fields exist but are dead; no mapper parses the error body (TS sets them only from client call-args, and only for single `checkAccess`). **Fix**: parse the JSON error body in each mapper. (Also drops `NetworkError` cause chaining across C#/PHP/Java — §2 MUST — deliberate for leak-safety but violates the contract; chain a *sanitized* cause.)
- **SDK-Q03 [MED]** — CONTRACT §8 drift: server added `key_version` + per-tenant HKDF (`derive_tenant_key`); §8 and the SDK mirror structs predate it and have no `key_version`. **Fix**: update §8 + mirror structs.
- **SDK-Q08 [MED]** — async method-name twins vs §1's "no additional names": Python `async_login`/… on the same class (most flagrant — idiomatic would be a separate `AsyncAxiamClient`), Java `loginAsync`/…, C# `…Async`-only (defensible TAP). **Fix**: contract-conformance ruling; prefer a separate async client for Python.
- **SDK-Q09 [MED, PHP]** — `can(resource, action)` argument order is reversed vs every other SDK's `can(action, resource)` (`sdks/php/src/AxiamClient.php:289`) — silent foot-gun when porting. **Fix**: align or document prominently.
- **SDK-Q10 [MED]** — inconsistent authz request/decision models: TS has two same-named `AccessDecision` shapes (REST `{allowed,reason}` vs gRPC `{allowed,denyReason}`) and declares-but-never-serializes `resourceType`/`subjectId`; Rust gRPC `subject_id` required vs REST `Option`. **Fix**: normalize.
- **SDK-Q13 [MED, TypeScript]** — gRPC ships a JSON-codec stand-in (`grpc/client.ts:143`) because `buf generate` output is absent in-repo → not wire-compatible with a real Tonic server until a buf build swaps the factory. Documented, but a shipping footgun.

### Low / consistency
- **SDK-Q07 [LOW, TS]** dead GET-only `withRetry` (no call sites; all methods POST). **SDK-Q11 [LOW, Go]** retry over-broadens (retries 400 NetworkErrors; bare type assertion vs `errors.As`). **SDK-Q12 [LOW, Go]** gRPC interceptor omits `x-tenant-id` pre-login (§5 requires it on every RPC). **SDK-Q14 [LOW, TS]** AMQP consumer has no shutdown/close path. **SDK-Q15 [LOW]** version split (0.1.0 vs 0.0.0 vs none) and lockfiles committed only for Go/TS. **SDK-Q16 [LOW, PHP]** README missing the mandatory "conforms to CONTRACT.md §1–§10" statement. **SDK-Q17 [LOW, Go]** duplicated `Sensitive` type (import-cycle workaround). **SDK-Q18 [LOW]** inconsistent committed-vs-generated codegen posture across SDKs.
- **Per-SDK test gaps** (from the language reviews): C# `VerifyMfaAsync` has **zero tests**; several SDKs lack a direct `ErrorMapper` status→type unit test and a `logout()` test; PHP/C# single-flight guards **fan out to N refreshes on the *failure* path** (asserted by their own tests) — satisfies §9.1 literally but defeats thundering-herd protection when the server is rejecting refreshes. Worth a design decision (cache-the-failure briefly).

### Cross-SDK consistency (quick map)
| Dimension | Rust | Go | TS | Py | Java | C# | PHP |
|---|---|---|---|---|---|---|---|
| AMQP-HMAC matches server | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| REST authz sends CSRF | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `AuthzError` surfaces body action/resource | ❌ | ❌ | 🔶 | ❌ | ❌ | ❌ | ❌ |
| `can()` arg order | act,res | act,res | act,res | act,res | act,res | act,res | **res,act** |
| README conformance stmt | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | **❌** |
| Lockfile committed | ❌ | ✅ | ✅ | ❌ | n/a | ❌ | ❌ |

---

## 5. Build / CI / dependency findings

- **CI-01 [HIGH — verify against CI toolchain] 🆕** — clippy gate likely red: `crates/axiam-auth/src/token.rs:42-46` has a manual `impl Default for SubjectKind` that clippy flags as `derivable_impls` (confirmed present). Under `ci.yml`'s `cargo clippy --workspace --all-targets -- -D warnings`, a warning is a hard error → the **clippy gate would fail**. Observed on clippy 1.94.0; CI pins stable @ 2026-03-27 — `derivable_impls` has linted enum `Default` since ~1.62 so it very likely fires there too, but **confirm against the pinned toolchain**. **Fix**: `#[derive(Default)]` + `#[default] User`.
- **CI-03 [MEDIUM] 🆕** — no SDK dependency scanning: dependabot covers only cargo(`/`)/npm(`/frontend`)/actions — **none of the 7 SDK ecosystems** — and no `sdk-ci-*.yml` runs a dependency vuln scan. (Security framing + fix: companion CI-03/CI-04, which also covers the absent CodeQL/SAST.)
- **CI-05 [LOW] 🆕** — doc nit: `REQUIREMENTS.md` PERF-01 places `check_complexity` in "authz middleware"; it's in `axiam-auth/src/policy.rs`.
- **Green today**: frontend `eslint`/`tsc`/`npm audit` all **0**; `cargo audit` has no active advisory (the 5 flagged are all documented ignores in `deny.toml`); CI is otherwise strong (fmt, build, build-no-saml, security-scan with cargo-deny+Trivy, real-service tests, frontend-quality, e2e). The five spot-checked compliance REQ test files all exist with the described assertions.
- **Environment note (not a code defect)**: the swagger-ui build placeholder `/home/user/.axiam-build-cache/swagger-ui-5.17.14.zip` referenced by `CLAUDE.md` is **missing** in this sandbox, so `axiam-api-rest`/`axiam-server`/full-workspace clippy can't be built locally (CI downloads the real asset from github). The server binary's compilation at HEAD relies on CI evidence; it could not be reproduced here. Restore the cache for local reproducibility.

---

## 6. Prioritized remediation order (for the Opus 4.8 planner)

**Tier 1 — correctness bugs that break a control or a core flow:**
1. **CI-01** — fix the `derivable_impls` warning so the clippy `-D warnings` gate is green (2-line change; confirm against CI's toolchain first). Nothing else merges cleanly until CI is green.
2. **CQ-B48** (+ finish **CQ-B45**) — repo handles must renew, or `health_check` must detect their expiry. A 4-week undetectable outage on an IAM control plane is release-blocking.
3. **CQ-B49** — webhook consumer must `nack` (not `ack`) on retry-publish failure.
4. **SDK-Q01** — Rust/Go AMQP-HMAC declaration-order serialization + real-server-signed fixture test.
5. **CQ-B07 cluster (CQ-B50/B51/B52)** — tenant predicates + transactions + `.check()` on the five unguarded edge mutations (also security — companion §3).

**Tier 2 — wired-but-broken + user-visible correctness:**
6. **CQ-B22** — put the webhook publisher in `AppState` and call `emit()` from domain-event sites (or explicitly defer webhooks from the MVP and mark them experimental).
7. **CQ-B53** — reconnect the webhook consumer instead of `process::exit(1)`.
8. **SDK-Q04** (Rust authz CSRF), **SDK-Q05** (TS Node-REST wiring), **SDK-Q06** (TS `amqplib` pin) — each makes an SDK path actually usable.
9. **CQ-F30** — wrap all gated frontend routes in `ProtectedRoute`; stop the `permissions:[]` fallback.
10. **CQ-F40** — AuditLogsPage debounce timers → `useRef`.

**Tier 3 — taxonomy, consistency, polish:**
11. **CQ-B11** (route create paths through `classify_write_error`), **CQ-B16** (delete missing-id → 404), **CQ-B13/B23** (N+1 / discovery cache).
12. **SDK-Q02/Q03/Q08/Q09/Q10** (contract conformance + model normalization), **SDK-Q16** (PHP README), the SDK test gaps (C# `VerifyMfa`, single-flight failure-path fan-out).
13. **CI-03** (SDK dependabot + vuln scans — pairs with the companion's CodeQL/SAST recommendation), **CQ-F09/F20/F41/F11**, remaining SDK LOWs.

**Executor note (Sonnet 5):** Tier 1 items are localized and have same-repo precedents to copy — `role.delete` (`role.rs:288-304`) for the edge guards, the 5 correct SDKs for the HMAC ordering, the manager's swappable `Arc<RwLock<Surreal>>` for the handle plumbing. Add a regression test with each fix; **SDK-Q01's test must use server-signed bytes**, not self-generated ones, or it re-masks the bug. Don't refactor the SDK `Sensitive`/TLS/JWKS code — it's correct and defensive.

---

## 7. Coverage note

All active `CQ-B*`/`CQ-F*` findings re-verified against `031abfe` with file:line evidence; all v1.2-touched backend modules, the frontend, and all 7 SDKs read. High-impact items independently corroborated by ≥2 readers (repo-handle expiry, webhook ack-on-failure, AMQP-HMAC ordering, edge-strip cluster). Not reproducible in this sandbox (rely on CI): the `axiam-server` binary build and full-workspace clippy (missing swagger-ui asset). Lower-confidence, worth a follow-up: exact behavior of CI-01 on the pinned toolchain; SurrealDB clone-auth-snapshot semantics under a future surrealdb bump (pin with a version-locked integration test).
