# AXIAM — Final Code-Quality & Security Review (2026-07-08)

- **Date**: 2026-07-08
- **Commit reviewed**: `a8e40b3` (HEAD of `claude/code-quality-security-review-1r6bln`; merge of the prior final-review branch into the `feature/final-phases` line)
- **Baseline**: [`final-security-review.md`](final-security-review.md) and [`final-code-review.md`](final-code-review.md), both reviewed at `031abfe`. **No source code has changed since `031abfe`** — the only commits since are the two review documents themselves (`7e6d2d9`, `a8e40b3`). Therefore every open finding from the prior final review is, by construction, still present; this pass re-verifies them and adds a **fresh, independent vulnerability scan** of the auth/OAuth2/authz cores and the REST/PKI/audit surface that turned up **four new findings the prior reviews missed** — including two cross-boundary escalation issues.
- **Method**: independent multi-agent fan-out. (1) Re-verification of all 17 carried-forward backend/SDK/CI findings against current code with file:line evidence. (2) A from-scratch data-flow scan of `axiam-auth`/`axiam-oauth2`/`axiam-authz` and of the full REST route table (auth/permission-guard/tenant-scoping completeness), PKI, audit, and AMQP/email. (3) Local build gates: `cargo fmt --all --check`, scoped `cargo clippy -D warnings`, frontend `tsc`/`eslint`/`npm audit`. Every HIGH re-derived from source and corroborated by ≥2 reads; the two new escalation findings were independently re-verified by hand (evidence inline below).

Statuses: ✅ FIXED · 🔶 PARTIAL · ❌ OPEN · 🆕 NEW.

---

## 1. Executive summary

**Verdict: not release-ready as-is.** The codebase remains fundamentally strong — the v1.2 hardening wave (14/15 security remediations verified fixed, no regressions) holds, the OAuth2/OIDC token machinery is disciplined, and the frontend is clean (`tsc`, `eslint`, `npm audit` all zero). But this pass found **two things the three prior review rounds did not**, and both are top-of-tree isolation breaks:

1. **The organization `org_id` in an access token is forged from unvalidated client input** → a legitimate tenant user who holds an org-scoped permission and knows a target organization's UUID can mint a token scoped to *another* organization and act inside it (CA-certificate issuance, org settings, tenant enumeration). **NEW-1, HIGH.** This is the single most serious finding in any review round.
2. **The organization-baseline settings endpoints enforce the wrong (tenant-level) permission**, collapsing the tenant↔org privilege boundary the permission model was designed to keep separate — a tenant-scoped grant can weaken the org security baseline that cascades to every sibling tenant. **NEW-2, HIGH/MED.**

Alongside those, **CI is currently red on two gates** at this HEAD: `cargo fmt --all --check` fails on 6 files and `cargo clippy -D warnings` fails on the known `derivable_impls` lint (CI-01) — nothing merges cleanly until both are green.

The prior final review's release-blocking backlog is entirely unremediated (no code moved), so it all carries forward: the 4-week undetectable DB-token outage (CQ-B48), the webhook consumer that acks-and-loses on retry-publish failure (CQ-B49), the broken SDK AMQP-HMAC in Go/Rust (SDK-Q01), and the cross-tenant graph-edge strip cluster (CQ-B50/B51/B52).

### Finding counts

| Severity | New this pass | Carried-forward (still open) | Total open |
|---|---|---|---|
| **CI-red (blocker)** | 1 (fmt gate) | 1 (CI-01 clippy) | 2 |
| High | 2 (NEW-1, NEW-2*) | 5 (CQ-B48, CQ-B49, SDK-Q01, SDK-Q04, SDK-Q05) | 7 |
| Medium | 1 (NEW-3) | 8 (CQ-B22, B50/51/52, B53, SEC-067, SDK-Q06, SDK-19, X-2) | 9 |
| Low | 1 (NEW-4) + 1 nit | ~5 (SEC-068/069/070, X-4, SDK-04) | ~6 |

\* NEW-2 is HIGH by boundary-collapse impact, MED by exploit precondition (attacker already holds `settings:update`).

---

## 2. New findings (this pass) — not in any prior review

### NEW-1 [HIGH] 🆕 — `org_id` access-token claim is forged from unvalidated client input → cross-organization escalation

- **Files**: `crates/axiam-api-rest/src/handlers/auth.rs:262-297` (login `org_id`/`tenant_id` resolution) and `:416-418` (refresh); `crates/axiam-auth/src/service.rs:310-314` (login → `create_session_and_tokens`) and `:588-597` (refresh → `issue_access_token`); `crates/axiam-auth/src/token.rs:120` (stamped into the signed `org_id` claim). Downstream gate (the boundary this defeats): `handlers/ca_certificates.rs:55,102,143,181`, `organizations.rs`, `tenants.rs`, `email_config.rs`, `settings.rs:43,83`.
- **Defect**: the `(tenant_id, org_id)` pair is accepted from the client and **never validated against the tenant's real `organization_id`**. Credentials authenticate the user purely against `tenant_id` (`service.rs:197-232`, `get_by_username`/`get_by_email` scoped to `tenant_id`); `org_id` merely rides along into token issuance. On `/login`, the tenant∈org binding is checked *only* in the slug-resolution branch (`get_by_slug(org_id, slug)`); the **direct-UUID branch skips it** (`auth.rs:262-263, 280-281`). On `/refresh`, `AuthService::refresh` reads `org_id` straight from the request body (`RefreshInput.org_id`) and stamps it into the new token (`service.rs:592`) — `org_id` is not stored on the session and never re-derived, so it is fully attacker-controlled. `get_effective_settings(org_id, tenant_id)` fetches the two rows independently and does not enforce the pairing, so a mismatched pair does not fail closed.
- **Exploit**: a legitimate user of tenant T (organization A) who holds an org-scoped permission in their own tenant (e.g. `ca_certificates:generate`) logs in normally but supplies `org_id = B` (another real org's UUID) — via `/login` with UUIDs, or on `/refresh`. They receive a validly-signed token `{sub: self, tenant_id: T, org_id: B}`. `RequirePermission` passes (evaluated against their real `tenant_id` T); the org-isolation gate `org_id == user.org_id` passes (the claim now reads B); `ca_service.generate({organization_id: B})` / `list(B)` then issues or enumerates **organization B's** signing-CA certificates. Same lever opens org B's settings, email config, and tenant list — a breach of the system's top-level isolation boundary. Precondition: hold an org-scoped permission in your own tenant + know/guess a target org UUID.
- **Fix**: never accept `org_id` from the client for token minting. In both login and refresh, resolve `org_id = tenant_repo.get_by_id(tenant_id).organization_id` server-side (exactly as `axiam-oauth2::token` already does), or persist `org_id` on the `session` row and re-derive it on refresh. Reject any request whose supplied `org_id` disagrees with the resolved value. `AuthService::refresh` has no `TenantRepository` today — thread one in or store `org_id` on the session.

### NEW-2 [HIGH / MED] 🆕 — Org-baseline settings endpoints enforce the tenant-level permission → tenant↔org boundary collapse

- **Files**: `crates/axiam-api-rest/src/handlers/settings.rs:37` (`get_org_settings` checks `settings:get`) and `:77` (`set_org_settings` checks `settings:update`) — identical to the *tenant* endpoints `GET/PUT /api/v1/settings` (`:116`, `:149`). The route map declares these routes require the **org-level** permissions `organizations:get_settings` / `organizations:update_settings` (`permissions.rs:286-295`), and those two permissions are **registered but referenced by no handler** — dead (`permissions.rs:167-171`; grep confirms zero handler uses).
- **Defect**: the permission model deliberately created separate `organizations:*_settings` permissions to keep org-baseline control distinct from tenant self-management. Both org handlers instead enforce the tenant permission `settings:update`, so any principal granted `settings:update` (a routine tenant-management grant, needed for `PUT /api/v1/settings`) can also call `PUT /api/v1/organizations/{their_org_id}/settings`. The only additional gate is `org_id == user.org_id` — no higher permission.
- **Exploit**: a tenant-admin role in tenant T1 holding `settings:update` sends `PUT /api/v1/organizations/{org_id}/settings` lowering `min_password_length` / disabling HIBP / raising lockout thresholds in the **org baseline**. `get_effective_settings(org_id, tenant_id)` merges org baseline + tenant override, so sibling tenants T2…Tn that inherit the baseline (no override) now run under the weakened policy — a cross-tenant security-posture downgrade driven by a tenant-scoped permission.
- **Fix**: change `get_org_settings` → `RequirePermission::new("organizations:get_settings", …)` and `set_org_settings` → `"organizations:update_settings"`, matching the route map. Strengthen the route↔OpenAPI parity test (`src/tests/route_openapi_parity_test.rs`) to assert each handler's *enforced* permission string equals its `ROUTE_PERMISSION_MAP` entry — the current test checks only path existence, which is why this drift went undetected.

### NEW-3 [MEDIUM] 🆕 — Session refresh-token single-use is not atomic (TOCTOU)

- **Files**: `crates/axiam-auth/src/service.rs:531-586` (`AuthService::refresh`); `crates/axiam-db/src/repository/session.rs:177-189` (`invalidate`).
- **Defect**: `refresh` is three separate statements — `get_by_token_hash` (SELECT) → `invalidate` (unconditional `DELETE … WHERE tenant_id=$tid`, returns `Ok(())` regardless of whether a row was deleted) → `create` new session. Nothing ties rotation to *this* request winning the delete.
- **Exploit (race)**: two concurrent `/refresh` calls with the same refresh token both pass the SELECT before either DELETE runs; both DELETEs "succeed" (idempotent, no row-count feedback); both `create` a fresh session and mint an access token. One refresh token thus yields two independent, separately-rotating session lineages — violating single-use rotation and, critically, **defeating stolen-token reuse detection**: when a thief races the legitimate client, neither errors, so the compromise is silent. `/refresh` (`server.rs:79`) also has no per-route rate limit, making the race easy to drive. The OAuth2 refresh path gets this right (`oauth2_refresh_token.rs::revoke` is an atomic `UPDATE … WHERE revoked=false` returning `NotFound` to the loser); the session flow lacks the equivalent.
- **Fix**: make the delete the atomic gate — `SessionRepository::invalidate` returns whether it deleted the specific row (`DELETE … RETURN BEFORE`, check non-empty); `refresh` treats an empty result as "already consumed" and errors *before* creating the new session.

### NEW-4 [LOW] 🆕 — No replay/nonce/timestamp protection on signed AMQP messages

- **Files**: `crates/axiam-amqp/src/messages.rs` (`AuthzRequest`, `AuditEventMessage`); `crates/axiam-amqp/src/audit_consumer.rs:91-119`.
- **Defect**: the HMAC design (per-tenant HKDF subkey, constant-time verify, reject-when-absent) proves integrity/authenticity but not freshness — no message carries a nonce or timestamp, and no consumer keeps a replay window or dedup set. A previously-captured, validly-signed message replayed onto the queue (broker access, or an at-least-once transport redelivery) is accepted and processed again: duplicate audit rows (append-only, so pollution not tampering) or a re-run authz decision. Attacker cannot forge new content without the master key → Low.
- **Fix**: add `nonce: Uuid` + `issued_at: DateTime<Utc>` inside the HMAC'd body; reject outside a bounded clock-skew window; dedup recently-seen nonces per tenant (short-TTL/LRU set).

### Minor (hardening nit, not a vuln)
Decrypted CA and PGP private-key material lives in `String`/`Vec<u8>` and is not zeroized after use (`pki/src/cert.rs:136`, `pki/src/pgp.rs:153`). Consider `zeroize` on those buffers.

---

## 3. Build / CI gate status (local, this HEAD)

| Gate | Result | Note |
|---|---|---|
| `cargo fmt --all --check` | ❌ **RED** | 6 files need formatting: `axiam-api-grpc/src/services/authorization.rs`, `axiam-core/src/models/email.rs`, `axiam-db/src/repository/email_config.rs`, `axiam-db/src/repository/session.rs`, `axiam-db/tests/user_repository_test.rs`, `axiam-pki/src/cert.rs`. CI's Rustfmt job (`ci.yml:26`) runs the same command → fails. Fix: `cargo fmt --all`. |
| `cargo clippy -D warnings` (CI-01) | ❌ **RED** | Reproduced locally on `axiam-auth`: `derivable_impls` on the manual `impl Default for SubjectKind` (`token.rs:42-46`). CI's clippy job runs `--workspace --all-targets -D warnings`. Fix: `#[derive(Default)]` + `#[default]` on `SubjectKind::User`. |
| Frontend `tsc --noEmit` | ✅ green | 0 errors. |
| Frontend `eslint .` | ✅ green | 0 problems. |
| Frontend `npm ci` + `npm audit` | ✅ green | Clean install; 0 vulnerabilities. |
| `cargo audit` / full-workspace `clippy` / `axiam-server` build | ⚠️ not run locally | `cargo-audit` not installed here; `axiam-api-rest`/`axiam-server` need the `SWAGGER_UI_DOWNLOAD_URL` file placeholder (per `CLAUDE.md`) to build offline. Rely on CI for these. |

**Both Rust gates are red at this HEAD** — that alone blocks a clean merge independent of the security findings.

---

## 4. Carried-forward findings — re-verified CONFIRMED-OPEN at `a8e40b3`

No source changed since `031abfe`, so all prior open items persist. Independently re-derived from code this pass:

**Backend (release-blocking):**
- **CQ-B48 / CQ-B45 [HIGH]** — repository DB handles are `client_cloned()` snapshots whose auth is never renewed by the manager's re-signin/reconnect; `health_check` probes only the manager handle → after ~4wk uptime every DB request 401s while `/ready` stays green. Undetectable outage. (`connection.rs:316-352,489-517`; `main.rs:259-388`.)
- **CQ-B49 [HIGH]** — `webhook_consumer.rs:306-335`: on `publish_retry` `Err`, no early return — it still writes a "retry scheduled" audit record **and acks the original**, losing the delivery. Fix: `nack` on enqueue failure.
- **CQ-B50/B51/B52 [MED, security dimension]** — graph-edge `DELETE`s keyed by raw UUID with **no tenant predicate** (and three with no `.check()`): `permission.delete` (`permission.rs:234-251`), `group.delete` (`group.rs:269-287`), `service_account.delete` (`service_account.rs:286-303`), `group.remove_member` (ignores its `_tenant_id`, `group.rs:389-410`), `resource.update` re-parent (3 non-transactional statements, `resource.rs:213-222`). Fix: mirror the fixed `role.delete`/`resource.delete` (txn + `in/out.tenant_id=$tenant_id` + `.check()`).
- **CQ-B22 [MED]** — `WebhookDeliveryService::emit()` (`webhook.rs:159`) has zero call sites and the publisher isn't in `AppState` (`state.rs:215-252`) → no domain event ever dispatches a webhook.
- **CQ-B53 [MED]** — `main.rs:710-711`: webhook consumer stream-end calls `std::process::exit(1)`, killing the whole server on a transient broker disconnect.
- **SEC-067 [MED]** — `Webhook`/`CreateWebhook` derive `Debug` over the secret (encrypted, and *plaintext* for `CreateWebhook`) with no redaction (`models/webhook.rs:32-60`); federation's redacting `Debug` (`models/federation.rs:57-81`) was not mirrored.
- **SEC-068/069/070 [LOW]** — gRPC introspection not tenant-scoped (`services/token.rs:55-89`); `guarded_fetch` no https-only + no body cap (`ssrf.rs:148-189`); XFF `trusted_hops` doc/code mismatch.

**SDKs:**
- **SDK-Q01 / X-1 [HIGH]** — AMQP-HMAC verification broken in **Go** (`amqp/hmac.go:34,51-52`, map-key sort) and **Rust** (`amqp/consumer.rs:82,104`, `serde_json::Value`/BTreeMap sort; no `preserve_order` in `Cargo.toml`): both recompute the HMAC over alphabetically-sorted bytes while the server signs in struct-declaration order → every real multi-field message fails and is dropped. Masked by pre-sorted toy fixtures. The other 5 SDKs are correct.
- **SDK-Q04 [HIGH]** — Rust `send_authz_post` omits `X-CSRF-Token` (`rest/authz.rs:145-155`), unlike its own `refresh`/`logout`.
- **SDK-Q05 [HIGH]** — TS `AxiamClient` hardwires a browser `SharedSession` with no cookie jar and no path to inject `NodeSession` into the REST client → Node REST login/refresh can't persist httpOnly cookies (`rest/client.ts:20-23`).
- **SDK-Q06 [MED]** — TS `package.json:93` pins `amqplib: "^2.0.0"` (real major 0.10.x, unsatisfiable) contradicting `@types/amqplib: "^0.10.0"`; `jsdom ^29`/`vitest ^4` also implausible.
- **SDK-19 [MED]** — PHP JWKS `jwks_uri` from OIDC discovery used with no scheme/host validation (`JwksVerifier.php:219-231,188,115`) → key-substitution if discovery is attacker-influenced.
- **X-2 [MED]** — no SDK rejects a plaintext base URL; TS gRPC actively `createInsecure()` for non-`https`/`grpcs` with no warning (`grpc/client.ts:123-130`); Rust accepts `http://` (`client.rs:98-105`).
- **X-4 / SDK-04 [LOW]** — Rust `LoginRequestBody`/`MfaVerifyRequestBody` derive `Debug` over password/OTP (`rest/auth.rs:27-45`) and Java `TokenPair` record `toString()` prints raw tokens (`internal/TokenPair.java:14`); Rust redirect policy compares host but not scheme → follows `https→http` downgrade re-sending tenant/CSRF headers (`client.rs:187-196`).

**Also confirmed genuinely fixed (do not re-touch):** all 14 v1.2 security remediations, PKCE S256-only, OAuth2 auth-code/refresh atomic single-use, exact `redirect_uri` match, constant-time client-secret compare, JWT audience narrowing + type-confusion blocks, parameterized SurrealQL (no injection), authz default-deny with `tenant_id` predicates throughout, PKI AES-GCM-at-rest + tenant-scoped CA signing + fingerprint-based mTLS identity, in-process rPGP (no shell-out), audit HMAC verify + dead-letter on persist failure, email template/header-injection safety.

---

## 5. Prioritized remediation order

**Tier 0 — unblock CI (nothing merges until green):**
1. `cargo fmt --all` (6 files).
2. **CI-01** — derive `Default` for `SubjectKind`.

**Tier 1 — new isolation breaks + carried release-blockers:**
3. **NEW-1** — server-derive `org_id` from the tenant in login + refresh; reject client/tenant mismatch. *(Highest priority — top-level org isolation.)*
4. **NEW-2** — org-settings handlers must enforce `organizations:*_settings`; add the enforced-permission parity assertion.
5. **CQ-B48** (+ finish B45) — renew repo handles or make `health_check` detect their expiry; add a hard-uptime alarm.
6. **CQ-B49** — `nack` (not `ack`) on webhook retry-publish failure.
7. **SDK-Q01** — declaration-order serialization in Go + Rust SDKs; regression test against **real server-signed bytes**.
8. **CQ-B50/B51/B52** — tenant predicates + transactions + `.check()` on the five unguarded edge mutations.

**Tier 2 — meaningful hardening:**
9. **NEW-3** — atomic delete-gate for session refresh single-use.
10. **CQ-B22 / CQ-B53** — wire webhook `emit()` into `AppState` + event sites (or mark webhooks experimental); reconnect the consumer instead of `process::exit`.
11. **SEC-067** — redacting `Debug` on webhook models. **SDK-Q04/Q05/Q06** — Rust authz CSRF, TS Node-REST wiring, TS `amqplib` pin. **SDK-19 / X-2** — PHP JWKS pin, reject plaintext SDK base URLs.

**Tier 3 — polish:**
12. **NEW-4** (AMQP replay nonce), **SEC-068/069/070**, **X-4/SDK-04**, key-material zeroization, `cargo audit`/full-workspace clippy on CI, SDK dependabot + vuln scans (CI-03), committed CodeQL/SAST (CI-04).

---

## 6. Coverage & confidence

Every carried-forward finding was re-derived from source at `a8e40b3`; the two new escalation findings (NEW-1, NEW-2) and the non-atomic refresh (NEW-3) were each verified by hand end-to-end (handler → service → token claim → downstream gate). CI gate results (fmt red, clippy red, frontend green) were reproduced locally. Not reproduced locally (rely on CI): the `axiam-server` binary build and full-workspace clippy (swagger-ui offline placeholder absent in this sandbox), and `cargo audit` (tool not installed). Lower-confidence residual: CQ-B48 hinges on `Surreal<Client>` clone-auth-snapshot semantics, which the connection module documents as a known residual and which should be pinned with a version-locked integration test against a future surrealdb bump.
