# Phase 12: Low / Trivial Remediation (Wave 4) — Research

**Researched:** 2026-06-19
**Domain:** Rust/Actix-Web/Lapin/React+TS — dead-code removal, dep pruning, i18n, minor security polish, whole-effort final verification
**Confidence:** HIGH (all findings verified by direct codebase inspection against post-Phase-11 state)

---

## Summary

Phase 12 is the final wave of the audit-remediation tranche. It closes ~30 LOW/TRIVIAL findings that were deferred from Waves 1–3, then runs a whole-effort final verification gate. The work splits into four cohesive plan clusters: (1) backend cleanup / shared helpers / dead-code; (2) backend security polish (SEC-040, SEC-043, SEC-057); (3) frontend trivial items; (4) frontend security (SEC-036, SEC-037, SEC-041) plus final verification.

Key facts from direct inspection (post-Phase-11 codebase):

- **CQ-B28 — `client_ip`/`user_agent` helpers**: Three separate private function definitions at `auth.rs:169-180`, `webauthn.rs:95-106`, and inline in `users.rs:118-126`. No shared extractor module.
- **CQ-B29 — NotificationDispatcher**: `NotificationPublisher` is created in `main.rs:477` and registered as `app_data` at line 611, but ZERO handler files extract or call it. The `NotificationDispatcher` struct exists in `axiam-audit/src/notification.rs` with unit tests but no production call sites.
- **CQ-B31 — Silent errors**: `let _ =` present at `cleanup.rs:247,294,314`; `gdpr.rs:124`; `oauth2/token.rs:555`; `audit/service.rs (via repo):388,401`. AMQP consumer `let _ = delivery.acker.*` calls are correct fire-and-forget ack patterns, not hiding errors.
- **CQ-B33 — Typed errors**: `Database/Crypto/Internal/Certificate` variants still stringly-typed in `axiam-auth/src/error.rs:104`. PUT-vs-PATCH semantics inconsistency persists but is cosmetic.
- **CQ-B34 — Dep hygiene**: Confirmed three `rand` majors: workspace uses `rand = "0.9"` (Cargo.toml:66); `axiam-pki/Cargo.toml:25` pins `rand_core = "0.6"`; `axiam-server/Cargo.toml:65` also pins `rand_core = "0.6"`. `cargo machete` would flag `webauthn-rs-proto` in axiam-auth, `tokio` test-only in axiam-db, and `rand` in axiam-db and axiam-authz (declared but usage via re-exports).
- **CQ-B35 — HIBP on sync change-password**: Confirmed at `service.rs:642`: `None, // no HIBP client in the sync change-password path`. The `check_hibp` function in `policy.rs:173-220` accepts an `Option<&reqwest::Client>` — adding HIBP to sync `change_password` requires passing an HTTP client through. This is the only outstanding item.
- **CQ-B36 — Audit-drop metric**: `axiam-audit/src/middleware.rs:161-162`: `tx.try_send(entry).is_err()` followed by `warn!("Audit channel full — dropping audit entry…")`. No counter metric (Prometheus/tracing counter). Channel capacity 4096.
- **CQ-B42 — Seeder storm**: `seeder.rs:37-66` — runs ~95 UPSERT statements per tenant per boot with no version/hash guard. For a system with many tenants this is a startup O(n×95) UPSERT storm. Fix: compute a hash of the registry slice, persist it in a `seeder_version` record, skip UPSERT if hash matches. `seed_default_roles` also uses `list` + linear scan instead of `get_by_name`.
- **SEC-040 — deny-overrides vs docs**: `engine.rs` is purely additive (`Allow` wins, default-deny). `claude_dev/design-document.md:385` says "role on a parent grants access to children unless an explicit deny exists at a lower level" — the "explicit deny" branch is not implemented. The fix options are: (a) add a `DenyPermission` model and denial cascade, or (b) update CLAUDE.md and design-document.md to say the current engine is additive-only / default-deny with no explicit deny mechanism (simpler and consistent with what ships). Option (b) is appropriate for a LOW finding.
- **SEC-043 — CA/PGP Debug + list hydration**: `axiam-db/src/repository/user.rs` inner `UserRow`/`UserRowWithId` derive `#[derive(Debug, SurrealValue)]` and include `mfa_secret: Option<String>`. The `list` method at line 458 uses `SELECT meta::id(id) AS record_id, * FROM user` which hydrates `mfa_secret` into the row struct. The mfa_secret is the AES-256-GCM encrypted blob. Fix: (1) replace `Debug` derive with a custom `impl` that redacts `mfa_secret`; (2) for the list path, use a projection that excludes `mfa_secret` (e.g., `SELECT meta::id(id) AS record_id, id, username, email, status, ...` without `mfa_secret`).
- **SEC-057 — GitHub Actions SHAs**: `ci.yml` and `release.yml` use mutable version tags (`@v4`, `@v2`, `@v3`, `@v0.36.0`, `@stable`). Must pin each `uses:` line to `@<sha>` from the official repository's release page. Both workflows are otherwise well-hardened (least-privilege, scan-before-push, cosign).
- **CQ-F21 — Dead Placeholder.tsx**: `frontend/src/pages/placeholders/Placeholder.tsx` exists (3.5K) with zero import sites. Safe to delete.
- **CQ-F22 — Unused radix deps**: Only three `@radix-ui` packages are imported in source: `react-label`, `react-slot`, `react-toast`. The `package.json` also lists `react-dialog`, `react-dropdown-menu`, `react-select`, `react-separator` — these have zero direct `import from "@radix-ui/react-{dialog,dropdown-menu,select,separator}"` in `src/`. They are likely transitive deps of shadcn/ui component wrappers in `src/components/ui/`. Remove only after verifying shadcn ui components do not re-export them directly.
- **CQ-F23 — Password policy checker absent on admin-create/bootstrap**: `UsersPage.tsx` and `BootstrapPage.tsx` do not import or render `PasswordPolicyChecker`. It is used in `ResetPasswordPage.tsx` and `ChangePasswordPage.tsx`. Missing from admin-create user form and bootstrap page inaugural admin password.
- **CQ-F24 — DataTable row key**: `DataTable.tsx:79` — fallback uses `(row as Record<string, unknown>).id as string ?? rowIdx`. The double-cast is unsafe if `id` is a number or UUID. Use `String(...)` conversion with `?? rowIdx` as index fallback.
- **CQ-F25 — Hardcoded `en-US`**: `frontend/src/lib/utils.ts:40,49` — `new Intl.DateTimeFormat("en-US", ...)`. Replace with `undefined` (browser locale) or a configurable locale constant.
- **CQ-F26 — CSS.escape missing**: `ResourceTree.tsx:81` — `document.querySelector('[data-tree-node-id="${id}"]')` where `id` is a UUID string (safe in practice for UUID format but semantically wrong). Fix: `document.querySelector('[data-tree-node-id="${CSS.escape(id)}"]')`.
- **CQ-F32 — Refresh `_retry` guard and cookie regex**: `api.ts:88-98` — `_retry` is set AFTER the retry attempt (`originalRequest._retry = true` at line 98), not before. A queued 401 that replays and 401s again could trigger a second refresh. The `getCookie` regex at line 21 is a static literal (`AXIAM_CSRF_RE`) — already safe (hardcoded string, not dynamic RegExp from user input). The `_retry` set-after-retry ordering is the real gap.
- **CQ-F33 — usePermissions empty array**: `usePermissions.ts:15` — `?? []` creates a new array reference on every render when the user has no permissions, defeating React.memo and useMemo equality checks. Fix: `const EMPTY: string[] = []` module-level constant.
- **CQ-F34 — BootstrapPage 404 handling**: `BootstrapPage.tsx:80` — `status === 404` is mapped to `alreadyInitialized = true`. A 404 could be a proxy misconfiguration rather than "already initialized". The endpoint should return 409 for "already initialized" and 200 for success. Verify backend returns 409 (bootstrap already done) and map 409 → already-initialized, 404 → proxy/network error.
- **CQ-F35 — useAuthInit StrictMode double-fetch**: `useAuthInit.ts:58` — `setInitializing` is in the `useEffect` dependency array but never called inside the effect body. In StrictMode, the effect fires twice; the `cancelled` flag suppresses the duplicate `setState` but the HTTP request itself fires twice. Fix: remove `setInitializing` from the dep array; use `useRef` to gate the effect to one execution.
- **SEC-036 — Secrets in React state after modal close**: `CertificatesPage.tsx`, `OAuth2ClientsPage.tsx`, `ServiceAccountsPage.tsx`, `WebhooksPage.tsx`, `PgpKeysPage.tsx` — all set a revealed secret in state but never clear it when the modal closes (`onClose` callbacks do not call `setRevealedSecret(null)` or equivalent).
- **SEC-037 — Tokens in URL history**: `ResetPasswordPage.tsx:36` reads `token` from `searchParams` but never calls `window.history.replaceState` to strip it. `VerifyEmailPage.tsx:31` same. After success/failure, the token remains in the browser history.
- **SEC-041 — ForgotPasswordPage email logging**: `ForgotPasswordPage.tsx:35` — `console.warn("[ForgotPassword] request failed:", err)`. The `err` object is an AxiosError which includes `config.data` containing the submitted email address. Replace with a redacted log: `console.warn("[ForgotPassword] request failed (email redacted)")`.

**Primary recommendation:** Implement in four sequential plan files: (1) backend cleanup + dead-code (CQ-B27..B36/B42); (2) backend security polish (SEC-040/043/057); (3) frontend trivial (CQ-F20..F35); (4) frontend security + whole-effort final verification (SEC-036/037/041 + verification gate).

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-16 AC-1 | Backend cleanup: shared `client_ip`/`user_agent`, NotificationDispatcher wired/removed, logged errors, typed errors, dep pruning, rand consolidation, HIBP on sync change-password, audit-drop metric, seeder version/hash skip | CQ-B27..B36/B42: all confirmed open in post-Phase-11 code. `client_ip` defined 3×; NotificationDispatcher has 0 call sites; `let _ =` at 5+ locations; HIBP explicitly `None` in change_password; audit middleware uses `warn!` only; seeder runs full UPSERT per boot. |
| REQ-16 AC-2 | SEC-040 deny-overrides cascade or doc correction; encrypted blobs not Debug-derived/hydrated on list; GH Actions pinned by SHA | SEC-040: engine.rs additive-only; SEC-043: UserRow derives Debug with mfa_secret included; SEC-057: ci.yml/release.yml use mutable tags (@v4 etc.) |
| REQ-16 AC-3 | Frontend trivial: dead Placeholder.tsx, unused radix deps, password-policy on admin-create/bootstrap, safe DataTable key, i18n, CSS.escape, `_retry` guard, bootstrap 404 handling, StrictMode double-fetch | CQ-F20..F35: all confirmed in source. Placeholder.tsx has 0 imports; radix dialog/dropdown/select/separator not imported directly; policy checker missing from UsersPage+BootstrapPage; `_retry` set after retry; useAuthInit dep array includes `setInitializing` never called in body. |
| REQ-16 AC-4 | Secrets cleared from React state on modal close; reset/verify tokens stripped via `history.replaceState`; no full Axios error/email logging on ForgotPasswordPage | SEC-036: 5 pages confirmed; SEC-037: ResetPasswordPage and VerifyEmailPage confirmed; SEC-041: `console.warn(err)` at ForgotPasswordPage:35 confirmed |
| REQ-16 AC-5 | Final whole-effort verification green: cargo build/clippy -D warnings/test --workspace, cargo audit/deny, npm audit, frontend lint+tsc+vitest, Playwright e2e in CI; manual smoke | Must run as a dedicated plan after all fixes land. Note: `cargo test --workspace` may hit ENOSPC; use per-crate targeted tests plus `cargo check --workspace`. |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| `client_ip`/`user_agent` extractor | API / Backend (axiam-api-rest) | — | Belongs in `handlers/extractors.rs` or `src/extractors/`; consumed by auth/webauthn handlers |
| NotificationDispatcher wiring | API / Backend (axiam-api-rest) | axiam-audit | Handlers call `dispatcher.dispatch()` after audit writes; or remove if deferred |
| Silent error logging | API / Backend (axiam-server + axiam-api-rest) | — | `cleanup.rs`, `gdpr.rs`, `oauth2/token.rs` — change `let _ =` to `if let Err(e) = ... { tracing::warn! }` |
| Typed error variants | API / Backend (axiam-auth) | — | `error.rs` crypto error variants; not surfaced to clients |
| Dep pruning (cargo machete) | Build / Cross-cutting | — | Workspace Cargo.toml + per-crate Cargo.toml edits |
| rand consolidation | Build / Cross-cutting | — | axiam-pki and axiam-server pin rand_core 0.6; evaluate if needed or can use workspace rand 0.9 |
| HIBP on sync change-password | API / Backend (axiam-auth) | — | `service.rs::change_password` — pass a `reqwest::Client` or accept `Option<&reqwest::Client>` |
| Audit-drop metric | API / Backend (axiam-audit) | — | `middleware.rs` — add `tracing::counter!` or Prometheus counter on `try_send` failure |
| Seeder version/hash skip | Database / Storage (axiam-db) | — | `seeder.rs` — hash registry, persist in `seeder_state` table, skip if unchanged |
| SEC-040 doc correction | API / Backend (axiam-authz) | Documentation | Update `claude_dev/design-document.md` and CLAUDE.md to reflect additive-only engine |
| SEC-043 mfa_secret exclusion from list | Database / Storage (axiam-db) | — | `repository/user.rs` list query: explicit column list excluding `mfa_secret` |
| SEC-043 Debug redaction | API / Backend (axiam-core) | — | `models/user.rs`: custom `Debug` impl or `#[debug_stub]` on mfa_secret field |
| GitHub Actions SHA pinning | CI / CDN | — | `.github/workflows/ci.yml` and `release.yml` |
| Frontend dead-code removal | Browser / Client | — | Delete files, remove package.json entries |
| Password policy on admin-create/bootstrap | Browser / Client | — | `UsersPage.tsx` and `BootstrapPage.tsx` — add `<PasswordPolicyChecker>` |
| DataTable safe row key | Browser / Client | — | `DataTable.tsx:79` — `String(...)` cast |
| i18n locale | Browser / Client | — | `utils.ts:40,49` — `undefined` locale |
| CSS.escape | Browser / Client | — | `ResourceTree.tsx:81` |
| `_retry` ordering | Browser / Client | — | `api.ts` — set `_retry = true` before the retry call |
| StrictMode double-fetch | Browser / Client | — | `useAuthInit.ts` dep array |
| Secrets state clear | Browser / Client | — | 5 pages close handlers |
| URL token strip | Browser / Client | — | `ResetPasswordPage.tsx`, `VerifyEmailPage.tsx` |
| ForgotPassword log redaction | Browser / Client | — | `ForgotPasswordPage.tsx:35` |
| Final verification gate | CI / CDN + API / Backend + Browser | — | Runs all toolchain checks; manual smoke |

---

## Standard Stack

### Core (no new dependencies needed)

| Library / Tool | Version | Purpose | Status |
|----------------|---------|---------|--------|
| `tracing` | workspace | Replace `warn!`-only audit drop with structured counter | Already used everywhere |
| `reqwest::Client` | workspace | Pass to HIBP check in change_password | Already in axiam-auth via policy.rs |
| `cargo machete` | CLI | Detect unused Rust deps | Install as one-shot: `cargo install cargo-machete` |
| `cargo audit` | CLI | CVE scan | Already in CI (ci.yml step) |
| `cargo deny` | CLI | License + dep graph check | Already in CI |
| `npm audit` | npm built-in | Frontend CVE scan | Already in CI |
| `vitest` | workspace | Frontend unit tests | Already in package.json |
| `playwright` | workspace | E2E tests | Already in package.json |

### No New External Dependencies

This phase has zero new external package introductions. All fixes reuse existing crates, patterns, and tools.

---

## Package Legitimacy Audit

> No new external packages introduced in Phase 12. All changes use existing workspace crates and existing frontend packages. No package legitimacy check required.

| Package | Registry | Status | Note |
|---------|----------|--------|------|
| (none) | — | N/A | Phase 12 adds no new dependencies |

---

## Architecture Patterns

### System Architecture Diagram

No architectural changes. Phase 12 is cleanup within the existing architecture.

```
Final verification flow:

cargo check --workspace
    ↓
cargo clippy -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-authz -p axiam-amqp -p axiam-pki -p axiam-oauth2 -p axiam-audit -p axiam-federation -p axiam-server -- -D warnings
    ↓
Targeted cargo test (per-crate, avoiding ENOSPC)
    ↓
cargo audit / cargo deny
    ↓
cd frontend && npm run lint && npx tsc -b && npx vitest run
    ↓
npm audit
    ↓
Playwright e2e smoke
    ↓
Manual smoke checklist
```

### Recommended Project Structure (all edits to existing files)

Key files per cluster:

**Cluster 1 — Backend cleanup:**
- NEW: `crates/axiam-api-rest/src/extractors/client_info.rs` — shared `client_ip(req)` + `user_agent(req)` functions, exported from `extractors/mod.rs`
- EDIT: `crates/axiam-api-rest/src/handlers/auth.rs` — remove local `client_ip`/`user_agent` defs; import from `extractors::client_info`
- EDIT: `crates/axiam-api-rest/src/handlers/webauthn.rs` — same
- EDIT: `crates/axiam-api-rest/src/handlers/users.rs` — same (currently inline, not even a private fn)
- EDIT: `crates/axiam-audit/src/middleware.rs` — wrap notify handler: `axiam-audit/src/notification.rs` dispatch called from audit write worker, OR add `web::Data<NotificationPublisher>` extraction in each handler that needs it
- EDIT: `crates/axiam-server/src/cleanup.rs:247,294,314` — `let _ =` → `if let Err(e) = ... { tracing::warn!(...) }`
- EDIT: `crates/axiam-api-rest/src/handlers/gdpr.rs:124` — same
- EDIT: `crates/axiam-oauth2/src/token.rs:555` — same
- EDIT: `crates/axiam-auth/src/error.rs` — promote `Crypto(String)` to typed variants if applicable; low-priority
- EDIT: `Cargo.toml` workspace + per-crate `Cargo.toml` — remove flagged unused deps after `cargo machete`
- EDIT: `crates/axiam-auth/src/service.rs::change_password` — accept and pass `Option<&reqwest::Client>` to `evaluate_password`
- EDIT: `crates/axiam-api-rest/src/handlers/auth.rs` — extract `reqwest::Client` from `app_data` and pass to `change_password`
- EDIT: `crates/axiam-audit/src/middleware.rs:161-162` — add structured counter/metric on audit drop
- EDIT: `crates/axiam-db/src/seeder.rs` — add `seeder_state` table; hash registry; skip unchanged

**Cluster 2 — Backend security polish:**
- EDIT: `claude_dev/design-document.md:385` — correct "unless an explicit deny exists" wording to reflect additive-only engine (SEC-040 option b)
- EDIT: `CLAUDE.md` — add note on additive-only RBAC engine
- EDIT: `crates/axiam-db/src/repository/user.rs` — list query: explicit column projection excluding `mfa_secret`; UserRow: remove `mfa_secret` from the list-path row struct or add custom `Debug` impl
- EDIT: `.github/workflows/ci.yml` — pin all `uses:` lines to commit SHAs
- EDIT: `.github/workflows/release.yml` — same

**Cluster 3 — Frontend trivial:**
- DELETE: `frontend/src/pages/placeholders/Placeholder.tsx`
- EDIT: `frontend/package.json` — remove `@radix-ui/react-dialog`, `@radix-ui/react-dropdown-menu`, `@radix-ui/react-select`, `@radix-ui/react-separator` (verify not used by shadcn ui wrappers first)
- EDIT: `frontend/src/pages/users/UsersPage.tsx` — add `<PasswordPolicyChecker>` on password field
- EDIT: `frontend/src/pages/BootstrapPage.tsx` — add `<PasswordPolicyChecker>` on password field
- EDIT: `frontend/src/components/DataTable.tsx:79` — `String(...)` safe key
- EDIT: `frontend/src/lib/utils.ts:40,49` — `"en-US"` → `undefined`
- EDIT: `frontend/src/components/ResourceTree.tsx:81` — `CSS.escape(id)` in selector
- EDIT: `frontend/src/lib/api.ts:88-98` — set `_retry = true` BEFORE the retry call
- EDIT: `frontend/src/hooks/usePermissions.ts:15` — `const EMPTY: string[] = []` module constant
- EDIT: `frontend/src/pages/tenants/TenantsPage.tsx` — add `isLoading` guard on initial org fetch to prevent "No tenants" flash; note N+1 is by design for now (org count typically small)
- EDIT: `frontend/src/hooks/useAuthInit.ts:58` — remove `setInitializing` from dep array; use `useRef` executed-once guard

**Cluster 4 — Frontend security + final verification:**
- EDIT: `frontend/src/pages/certificates/CertificatesPage.tsx` — `onClose` clears `revealedSecret`
- EDIT: `frontend/src/pages/oauth2/OAuth2ClientsPage.tsx` — same
- EDIT: `frontend/src/pages/service-accounts/ServiceAccountsPage.tsx` — same
- EDIT: `frontend/src/pages/webhooks/WebhooksPage.tsx` — same
- EDIT: `frontend/src/pages/pgp/PgpKeysPage.tsx` — same
- EDIT: `frontend/src/pages/auth/ResetPasswordPage.tsx` — after successful confirm/error display: `window.history.replaceState({}, document.title, window.location.pathname)`
- EDIT: `frontend/src/pages/auth/VerifyEmailPage.tsx` — same
- EDIT: `frontend/src/pages/auth/ForgotPasswordPage.tsx:35` — redact email from log
- EDIT: `.github/workflows/ci.yml` — add Playwright e2e job (or verify existing coverage)
- VERIFY: `cargo check --workspace` green
- VERIFY: `cargo clippy` per-crate green
- VERIFY: targeted `cargo test` per affected crate green
- VERIFY: `cargo audit` / `cargo deny` green
- VERIFY: `cd frontend && npm run lint && npx tsc -b && npx vitest run` green
- VERIFY: `npm audit` green
- MANUAL SMOKE: login → MFA → reset/verify/change-pw → GDPR → federation-after-restart → cross-org 403 → gRPC-no-creds rejected

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| SHA-pinning GH Actions | Manual SHA lookup | `pin-github-action` CLI or GitHub security advisory advisories | Tedious but straightforward; use the current SHA for each action version |
| Audit drop counter | Custom global counter | `tracing::event!` with `level = ERROR` + a structured field `audit_dropped = true` | Already in the tracing ecosystem; Prometheus can scrape via opentelemetry if needed later |
| Registry hash for seeder | Serialize whole registry | `sha2::Digest` over concatenated `format!("{action}:{desc}")` strings | Already have `sha2` in workspace |
| Debug redaction | Custom proc macro | Manual `impl std::fmt::Debug for UserRow` | Trivial to write; avoids new dep |

**Key insight:** Phase 12 is almost entirely "apply existing patterns in new locations" — the same philosophy as Phase 11. No new architectural decisions or dependencies are required.

---

## Finding-by-Finding Code State

### CQ-B27 — Service composition (per-request rebuild)
**File:** `crates/axiam-api-rest/src/handlers/federation.rs` — `OidcFederationService::new` called ~9 times per-request; `PasswordResetService` ×2; `EmailVerificationService` ×2.
**Status:** OPEN. The Phase 11 ROADMAP deferred `CQ-B43` (AppState refactor) to Phase 12 but noted it as a refactor, not security finding. Given disk constraints and scope, this is LOW priority; address if time permits after Cluster 1/2 fixes are green.
**Recommendation:** Defer AppState refactor to Phase 19 (follow-ups). Mention in commit message only.

### CQ-B28 — `client_ip`/`user_agent` copy-pasted
**Files:**
- `crates/axiam-api-rest/src/handlers/auth.rs:169-180` (uncapped `ConnectionInfo::realip_remote_addr()`)
- `crates/axiam-api-rest/src/handlers/webauthn.rs:95-106` (capped — uses `peer_addr`)
- `crates/axiam-api-rest/src/handlers/users.rs:172` (inline `http_req.headers().get("user-agent")`)
**Fix:** Create `crates/axiam-api-rest/src/extractors/client_info.rs` with two `pub fn client_ip(req: &HttpRequest) -> Option<String>` and `user_agent(req: &HttpRequest) -> Option<String>`. Use `auth.rs` logic (the one that uses `ConnectionInfo`) as canonical. Add `pub mod client_info;` to `extractors/mod.rs`.

### CQ-B29 — NotificationDispatcher unwired
**Files:** `crates/axiam-audit/src/notification.rs` (struct + tests, no production call sites); `crates/axiam-server/src/main.rs:477,611` (publisher created and registered but never extracted in handlers).
**Fix options:** (A) Wire: after each audit write, call `notification_dispatcher.dispatch(event)` inside the audit middleware worker loop — this is the cleanest integration point since audit events flow through the worker. (B) Remove `NotificationPublisher` from `app_data` registration if not wiring in this phase.
**Recommendation:** Option A if feasible. The dispatcher is tested and ready; wiring it into the audit worker (`middleware.rs` async loop) adds < 20 lines. If the handlers need `reqwest` for email delivery, verify `reqwest::Client` is accessible from the audit worker context.

### CQ-B31 — Silent dropped errors
**Files and lines:**
- `crates/axiam-server/src/cleanup.rs:247` — `let _ = self.federation_link_repo.delete(...)` — deletion during expired-link cleanup; if fails, link is silently left
- `crates/axiam-server/src/cleanup.rs:294,314` — similar cleanup audit writes
- `crates/axiam-api-rest/src/handlers/gdpr.rs:124` — `let _ = audit_repo...` (comment at :114 calls it "fire-and-forget" but it's actually a correctness concern for GDPR audit trails)
- `crates/axiam-oauth2/src/token.rs:555` — `let _ = self...` (token revocation failure silently swallowed)
**Fix pattern:**
```rust
// Replace: let _ = self.some_repo.delete(tenant_id, id).await;
// With:
if let Err(e) = self.some_repo.delete(tenant_id, id).await {
    tracing::warn!(error = %e, entity_id = %id, "cleanup: failed to delete expired entity");
}
```
For gdpr.rs audit write: promote to `Err` propagation or at minimum log at `error!` level since GDPR audit trails are legally significant.

### CQ-B33 — Typed error variants (partial)
**File:** `crates/axiam-auth/src/error.rs` — `Crypto(String)` variant. The finding notes this is already partially fixed (new typed variants added in earlier phases). Remaining: `AuthError::Crypto(String)` could be split into `KeyParse`, `HmacInvalid`, `AesDecrypt`. Low impact; cosmetic cleanup only.
**Fix:** Add two or three typed sub-variants to `AuthError` for the most common crypto failure modes. Not worth deep effort.

### CQ-B34 — Dep pruning + rand consolidation
**Current state:**
- Workspace `rand = "0.9"` in Cargo.toml:66
- `axiam-pki/Cargo.toml:25` — `rand_core = { version = "0.6", features = ["getrandom"] }` (needed by pgp crate which uses rand 0.8 API)
- `axiam-server/Cargo.toml:65` — `rand_core = { version = "0.6", features = ["getrandom"] }` (comment says "rsa 0.9 requires rand_core 0.6 CryptoRng")
- Likely unused direct deps: `webauthn-rs-proto` in axiam-auth, `tokio` as non-dev-dep in axiam-db, `rand` direct dep in axiam-authz and axiam-db (used only via imports from other crates)
**Fix protocol:**
1. Run `cargo machete --fix` (or `cargo machete` then manually remove flagged deps)
2. For rand_core 0.6 pins: keep them — they are necessary for pgp and rsa crates compatibility as documented in MEMORY.md. Add a comment in each Cargo.toml: `# Required: pgp/rsa crate uses rand_core 0.6 API; cannot upgrade until upstream`.
3. Verify `cargo check -p axiam-pki -p axiam-server` passes after changes.

### CQ-B35 — HIBP on sync change-password
**File:** `crates/axiam-auth/src/service.rs:642` — `None, // no HIBP client in the sync change-password path`
**Root cause:** `change_password` is a generic async fn that takes `&H: PasswordHistoryRepository` but no HTTP client.
**Fix:** Add `http_client: Option<&reqwest::Client>` parameter to `change_password`. In the call site at `crates/axiam-api-rest/src/handlers/auth.rs`, extract the `reqwest::Client` from `app_data` (it should be registered; if not, register it in `main.rs`). Pass it through.
**Note:** `check_hibp` in `policy.rs:173-220` already accepts `Option<&reqwest::Client>`. The wiring is a two-step: add param to `change_password`, pass in from handler.

### CQ-B36 — Audit-drop metric
**File:** `crates/axiam-audit/src/middleware.rs:161-162`
**Current:**
```rust
if tx.try_send(entry).is_err() {
    warn!("Audit channel full — dropping audit entry for {method} {path}");
}
```
**Fix:** Add a structured `tracing::event!` at ERROR level with a stable field name `audit_dropped = true` so Prometheus/Loki can alert on it. Optionally use `std::sync::atomic::AtomicU64` counter exposed via a health endpoint or metrics path.

```rust
// Simple: escalate to error + structured field
if tx.try_send(entry).is_err() {
    tracing::error!(
        audit_dropped = true,
        method = %method,
        path = %path,
        "Audit channel full — entry dropped; investigate channel capacity"
    );
}
```

### CQ-B42 — Seeder version/hash skip
**File:** `crates/axiam-db/src/seeder.rs:37-66`
**Fix:** Before running UPSERT loop, compute a deterministic hash of the registry slice:
```rust
use sha2::{Digest, Sha256};
let registry_hash = {
    let mut h = Sha256::new();
    for (action, desc) in registry {
        h.update(action.as_bytes());
        h.update(b"|");
        h.update(desc.as_bytes());
    }
    hex::encode(h.finalize())
};
// Try to read seeder_state record for this tenant; if hash matches, skip.
// UPSERT seeder_state after successful seed.
```
Add a `seeder_state` table to `schema.rs`: `DEFINE TABLE IF NOT EXISTS seeder_state SCHEMAFULL TYPE NORMAL`.
For `seed_default_roles`: replace `list(tenant_id, Pagination::default())` + linear scan with `get_by_name(tenant_id, "super-admin")` — add `get_by_name` method to `SurrealRoleRepository`.

### SEC-040 — AuthZ engine additive-only vs docs
**Current engine behavior:** Purely additive. `check_access` in `engine.rs` returns `Allow` if any applicable role has a permission grant matching the action. No deny mechanism exists.
**Design-document.md:385** says "unless an explicit deny exists at a lower level" — this implies a deny-override cascade that is NOT implemented.
**Recommendation (option b — doc correction):**
- Edit `claude_dev/design-document.md:385` to remove "unless an explicit deny exists" phrasing
- Add a note: "The current engine is additive-only (allow-wins) with default-deny for missing grants. Explicit deny permissions are not implemented in v1.0-beta."
- Edit CLAUDE.md to add: "RBAC engine is additive-only; there is no explicit deny override mechanism."
**Risk of option a (implementing deny overrides):** Significant scope — requires new `DenyPermission` model, schema migration, engine changes, and tests. Not appropriate for a LOW finding.

### SEC-043 — Debug derive on mfa_secret; list hydration
**Files:**
- `crates/axiam-db/src/repository/user.rs` — `UserRow` at line 20 and `UserRowWithId` at line 45 both derive `Debug` and include `mfa_secret: Option<String>`
- List query at line 458: `SELECT meta::id(id) AS record_id, * FROM user` — `*` hydrates `mfa_secret`

**Fix 1 — Debug redaction:** Replace `#[derive(Debug, SurrealValue)]` on `UserRow` with:
```rust
#[derive(SurrealValue)]
struct UserRow { ... }

impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("record_id", &self.record_id)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(|_| "[REDACTED]"))
            // ... other non-sensitive fields
            .finish()
    }
}
```

**Fix 2 — List projection:** Replace `SELECT meta::id(id) AS record_id, * FROM user` with an explicit column list that excludes `mfa_secret` and `totp_last_used_step`:
```sql
SELECT meta::id(id) AS record_id, username, email, status, tenant_id,
       email_verified_at, failed_login_attempts, locked_until,
       last_login_at, metadata, created_at, updated_at
FROM user WHERE tenant_id = $tenant_id ...
```
The list endpoint (`GET /users`) must never return MFA secret blobs.

### SEC-057 — GitHub Actions SHA pinning
**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`
**Current:** Uses `@v4`, `@v2`, `@v3`, `@stable`, `@v0.36.0`, etc. (all mutable tags).
**Fix:** Replace each `uses: org/action@vX` with `uses: org/action@<sha>  # vX`. SHAs obtained from the action's release page (GitHub: repo → releases → copy full SHA).
**Actions to pin (from ci.yml and release.yml):**
- `actions/checkout@v4`
- `dtolnay/rust-toolchain@stable`
- `Swatinem/rust-cache@v2`
- `actions-rust-lang/audit@v1`
- `EmbarkStudios/cargo-deny-action@v2`
- `hadolint/hadolint-action@v3.1.0`
- `aquasecurity/trivy-action@v0.36.0`
- `docker/setup-buildx-action@v3`
- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@v6`
- `github/codeql-action/upload-sarif@v4`
- `sigstore/cosign-installer@v3`
- `actions/attest-build-provenance@v2`

**Note:** SHA lookup is manual or via `pin-github-action` tool. The `hadolint no-fail: true` and `trivy exit-code: 0` are advisory-by-design per security review comment — do not change these, just pin the SHAs.

### CQ-F20 — TenantsPage N+1 loading flash
**File:** `frontend/src/pages/tenants/TenantsPage.tsx:194-211`
**Current:** `useQuery` has `enabled: organizations.length > 0`. While `organizations` loads, `enabled` is false so tenants query doesn't run — but `tenants = []` is shown as "No tenants found" before orgs resolve.
**Fix:** Add `isLoading` from the orgs query to the tenants query's `isLoading` composite, or render a skeleton/spinner while `organizations.length === 0 && isLoadingOrgs`. The `Promise.all` fan-out (one request per org) is acceptable at small org count; no N+1 fix needed architecturally.

### CQ-F21 — Dead Placeholder.tsx
**File:** `frontend/src/pages/placeholders/Placeholder.tsx` — 3.5K, zero import sites confirmed.
**Fix:** Delete the file. Check if the `placeholders/` directory should also be removed (if empty after deletion).
**Note:** Also check `RoleDetailPage.tsx:937` for stray icon re-exports mentioned in the finding — verify if still present.

### CQ-F22 — Unused radix deps
**Verification:** Direct imports of `@radix-ui/react-{dialog,dropdown-menu,select,separator}` found: ZERO in `frontend/src/`. However, shadcn/ui component wrappers in `frontend/src/components/ui/` may wrap these packages. Before removing from `package.json`, run:
```bash
grep -r "@radix-ui/react-dialog\|@radix-ui/react-dropdown-menu\|@radix-ui/react-select\|@radix-ui/react-separator" frontend/src/components/ui/
```
If the shadcn ui wrappers import them, they cannot be removed (they are direct peer deps of shadcn, not truly unused). If not found in `ui/` either, remove from `package.json` and run `npm install --save-exact` to update lock file.

### CQ-F23 — Password policy checker absent on admin-create and bootstrap
**Files:**
- `frontend/src/pages/users/UsersPage.tsx` — admin user create form at line 133-141 has a password field with no `<PasswordPolicyChecker>`
- `frontend/src/pages/BootstrapPage.tsx` — inaugural admin password at line 202-209, no checker
**Fix:** Import `{ PasswordPolicyChecker, checkPasswordPolicy }` from `@/components/PasswordPolicyChecker` and add below the password `<Input>`. Gate form submission on `checkPasswordPolicy(password)` result.

### CQ-F24 — DataTable unsafe row key
**File:** `frontend/src/components/DataTable.tsx:79`
**Current:** `(row as Record<string, unknown>).id as string ?? rowIdx`
**Issue:** Double cast — if `id` is a number (e.g., integer primary key from another system), `as string` silently yields `"[object Object]"` or loses type info.
**Fix:**
```typescript
key={getRowKey ? getRowKey(row, rowIdx) : String((row as Record<string, unknown>).id ?? rowIdx)}
```

### CQ-F25 — Hardcoded en-US locale
**File:** `frontend/src/lib/utils.ts:40,49`
**Current:**
```typescript
new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(...)
new Intl.DateTimeFormat("en-US", { dateStyle: "short", timeStyle: "short" }).format(...)
```
**Fix:**
```typescript
new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(...)
new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "short" }).format(...)
```
`undefined` uses the browser's preferred locale. AXIAM targets enterprise/IoT environments globally — locale-agnostic formatting is required.

### CQ-F26 — ResourceTree CSS.escape
**File:** `frontend/src/components/ResourceTree.tsx:81`
**Current:** `document.querySelector('[data-tree-node-id="${id}"]')`
**Issue:** `id` is a UUID (safe in practice for the CSS attribute selector since UUIDs contain only hex + hyphens), but semantically wrong if IDs ever contain CSS special chars.
**Fix:**
```typescript
const el = document.querySelector<HTMLElement>(`[data-tree-node-id="${CSS.escape(id)}"]`);
```
`CSS.escape` is available in all modern browsers and Node >= 12.

### CQ-F32 — `_retry` set after retry
**File:** `frontend/src/lib/api.ts:88-98`
**Current order:**
```typescript
if (!originalRequest._retry && ...) {
    // ... refresh call ...
    return api(originalRequest);  // line 106
    // ...
    originalRequest._retry = true;  // line 98 — set AFTER the retry
}
```
**Issue:** If the retry itself 401s, `_retry` is still false (set only after successful return), potentially causing a second refresh loop.
**Fix:** Set `_retry = true` immediately before the refresh attempt:
```typescript
originalRequest._retry = true;  // SET BEFORE
await api.post("/api/v1/auth/refresh", {});
return api(originalRequest);
```
The `getCookie` regex at line 21 is already a static literal — no fix needed there.

### CQ-F33 — usePermissions empty array allocation
**File:** `frontend/src/hooks/usePermissions.ts:15`
**Current:** `const permissions = useAuthStore((s) => s.user?.permissions ?? []);`
**Fix:**
```typescript
const EMPTY_PERMISSIONS: string[] = [];
// ...
const permissions = useAuthStore((s) => s.user?.permissions ?? EMPTY_PERMISSIONS);
```

### CQ-F34 — BootstrapPage 404 vs "already initialized"
**File:** `frontend/src/pages/BootstrapPage.tsx:80`
**Current:** `status === 404` → `setAlreadyInitialized(true)`
**Issue:** The bootstrap endpoint returns 409 (Conflict) when already initialized (per the handler logic from Phase 3/11), not 404. A genuine 404 means the endpoint is not routed — proxy misconfiguration.
**Verify in backend:** `handlers/bootstrap.rs` — what does it return when admin already exists? If it returns 409, update the frontend to map 409 → already-initialized; remap 404 → network/proxy error with a friendly message.
**Fix:**
```typescript
} else if (status === 409) {
    setAlreadyInitialized(true);
} else if (status === 404) {
    setError("Bootstrap endpoint not found. Check your proxy configuration.");
}
```

### CQ-F35 — useAuthInit StrictMode double-fetch
**File:** `frontend/src/hooks/useAuthInit.ts`
**Current:** `setInitializing` is in the useEffect dep array (line 58) but never called inside the effect body.
**Fix:** Remove `setInitializing` from the dep array. The `cancelled` flag handles concurrency. To prevent the double-HTTP-request under StrictMode, add a `useRef` guard:
```typescript
const initialized = useRef(false);
useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    // ... rest of init
}, [setUser, clearAuth, setTenantContext]);  // setInitializing removed
```

### SEC-036 — Secrets retained in React state
**Files and state vars:**
- `CertificatesPage.tsx:146,157` — `const [secretOpen, setSecretOpen] = useState(false)` + `revealedKey` state. `onClose={() => setSecretOpen(false)}` does not clear `revealedKey`.
- `OAuth2ClientsPage.tsx:283,297` — `secretModalOpen` + `revealedSecret` state. `onClose` does not clear `revealedSecret`.
- `ServiceAccountsPage.tsx:202-206` — `secretModalOpen`, `secretModalTitle`, `secretModalDesc`, `revealedSecret`. `onClose` does not clear `revealedSecret`.
- `WebhooksPage.tsx:287,297-298` — `secretOpen` + `revealedSecret`. `onClose` does not clear `revealedSecret`.
- `PgpKeysPage.tsx:287,298` — `secretOpen` + `revealedKey`. `onClose` does not clear `revealedKey`.
**Fix pattern (apply to all 5):**
```typescript
// Change onClose callback:
onClose={() => {
    setSecretOpen(false);
    setRevealedSecret(null);  // or setRevealedKey(null)
}}
```

### SEC-037 — Tokens in URL history
**Files:**
- `ResetPasswordPage.tsx:36` — reads `token` from `searchParams`; after confirm or error, token stays in URL
- `VerifyEmailPage.tsx:31` — same

**Fix (add after the async action completes, before state update or navigate):**
```typescript
// Strip token from URL after first use — prevents it from appearing in browser history
window.history.replaceState({}, document.title, window.location.pathname);
```
For `ResetPasswordPage`: call in the `useActionState` action after `await authService.confirmPasswordReset(token, newPw)`.
For `VerifyEmailPage`: call inside `doVerify()` after `await authService.verifyEmail(token!)`.

### SEC-041 — ForgotPasswordPage email in error log
**File:** `frontend/src/pages/auth/ForgotPasswordPage.tsx:35`
**Current:**
```typescript
console.warn("[ForgotPassword] request failed:", err);
```
**Issue:** `err` is an AxiosError; its `config.data` contains the request body (the submitted email address). This is logged to the browser console — visible in browser devtools and potentially in any error tracking service.
**Fix:**
```typescript
console.warn("[ForgotPassword] reset request failed (details redacted for privacy)");
```

---

## Common Pitfalls

### Pitfall 1: radix-ui `@radix-ui/react-{dialog,dropdown-menu,select,separator}` are shadcn/ui peer deps

**What goes wrong:** Removing these from `package.json` breaks shadcn/ui components that depend on them even if your source files don't directly `import from "@radix-ui/..."`.
**Why it happens:** shadcn/ui components in `src/components/ui/` (e.g., `dialog.tsx`, `dropdown-menu.tsx`) re-export from these radix packages.
**How to avoid:** Before removing, run: `grep -r "@radix-ui/react-dialog\|react-dropdown-menu\|react-select\|react-separator" frontend/src/components/ui/`. If found, keep those packages. Only remove packages that are not imported anywhere in `frontend/src/`.
**Warning signs:** `npm install` succeeds but `tsc -b` or runtime fails with "module not found @radix-ui/...".

### Pitfall 2: `cargo machete` flags packages that ARE needed indirectly

**What goes wrong:** `cargo machete` may flag `rand` in axiam-db even though it is transitively re-exported by a dependency. Removing it breaks compile.
**Why it happens:** Machete does static analysis on `Cargo.toml` — it cannot always trace transitive re-exports.
**How to avoid:** After removing a dep flagged by machete, run `cargo check -p <crate>` immediately. If it fails with "unresolved import", revert that specific removal and add a comment: `# used via <dep> re-export`.

### Pitfall 3: `rand_core 0.6` pins are intentional — don't remove them

**What goes wrong:** The `rand_core = "0.6"` explicit deps in `axiam-pki` and `axiam-server` look like they could be removed (workspace uses rand 0.9). Removing them causes compile errors in pgp.rs and pkcs#1 RSA code.
**Why it happens:** `pgp 0.19` uses `rand_core 0.6` APIs. The workspace `rand 0.9` re-exports `rand_core 0.9`. These are incompatible ABI-wise.
**How to avoid:** Keep both pins. Add a comment in Cargo.toml: `# Required: pgp/rsa 0.9 uses rand_core 0.6 CryptoRng; removing breaks pgp.rs`.

### Pitfall 4: BootstrapPage status code mismatch

**What goes wrong:** If the backend returns 409 for "already initialized" but the frontend maps 404, the fix is incomplete and the user sees a confusing "already initialized" message for genuine 404s (proxy misconfiguration, route removed).
**How to avoid:** Verify the actual HTTP status code returned by `handlers/bootstrap.rs` when the admin already exists before touching the frontend. Check the integration test in `bootstrap_test.rs` for the expected status code.

### Pitfall 5: history.replaceState timing for token strip

**What goes wrong:** Calling `window.history.replaceState` before the token is validated causes the page to lose the token mid-verification, breaking any mid-flight async call that reads `searchParams.get("token")` again.
**Why it happens:** React re-renders or effect re-runs may re-read `searchParams` after replaceState strips the query.
**How to avoid:** Call `replaceState` only after the async verification is complete (success OR terminal failure), not at the start of the effect. The token is already captured in a local variable by then.

### Pitfall 6: disk constraint — no full workspace cargo test

**What goes wrong:** `cargo test --workspace` on this machine fails with `error: os error 28 (No space left on device)` during linking due to ~46 GiB `target/` directory.
**Why it happens:** Disk near-full; whole-workspace test builds generate large link artifacts simultaneously.
**How to avoid:** Use `cargo check --workspace` for compilation verification, then `cargo test -p <crate>` targeted per affected crate. The final verification step must document this constraint and substitute targeted tests for the "cargo test --workspace" criterion. Reclaim space first if possible: `rm -rf target/debug/incremental`.

### Pitfall 7: SEC-040 — implementing deny-override cascade is Phase 12 out-of-scope

**What goes wrong:** A developer decides to implement the deny-override cascade (option a) since it's documented in the design-doc. This is large scope (new model, migration, engine rewrite, tests) that will block the whole phase.
**How to avoid:** Fix the docs (option b) only. The finding severity is LOW. Document in commit: "SEC-040: correct design-document and CLAUDE.md to reflect additive-only RBAC engine; explicit deny cascade deferred to post-v1.0-beta (Phase 19)."

---

## Code Examples

### Shared client_ip/user_agent extractor (CQ-B28)

```rust
// Source: consolidation of auth.rs:169-180 (canonical version uses ConnectionInfo)
// New file: crates/axiam-api-rest/src/extractors/client_info.rs

use actix_web::HttpRequest;

/// Extract the real client IP from ConnectionInfo (respects X-Forwarded-For via
/// trusted proxy configuration set on the Actix server).
pub fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string())
}

/// Extract the User-Agent header value.
pub fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}
```

### Logged error handling (CQ-B31)

```rust
// Replace let _ = self.some_repo.delete(tenant_id, id).await;
// With:
if let Err(e) = self.some_repo.delete(tenant_id, id).await {
    tracing::warn!(
        error = %e,
        entity_id = %id,
        "cleanup: failed to delete expired federation link; will retry next cycle"
    );
}
```

### Audit-drop metric (CQ-B36)

```rust
// crates/axiam-audit/src/middleware.rs:161-163
if tx.try_send(entry).is_err() {
    tracing::error!(
        audit_dropped = true,
        method = %method,
        path = %path,
        "Audit channel full — entry dropped. Investigate CHANNEL_CAPACITY (currently {CHANNEL_CAPACITY})."
    );
}
```

### Seeder hash guard (CQ-B42)

```rust
// crates/axiam-db/src/seeder.rs — add before the UPSERT loop
use sha2::{Digest, Sha256};
use hex;

async fn compute_registry_hash(registry: &[(&str, &str)]) -> String {
    let mut h = Sha256::new();
    for (action, desc) in registry {
        h.update(action.as_bytes());
        h.update(b"|");
        h.update(desc.as_bytes());
    }
    hex::encode(h.finalize())
}
// Then: check seeder_state table; if hash matches, return Ok(()) early.
// After successful UPSERT loop: UPSERT seeder_state with new hash.
```

### HIBP wiring in change_password (CQ-B35)

```rust
// crates/axiam-auth/src/service.rs — change_password signature
pub async fn change_password<H: PasswordHistoryRepository>(
    &self,
    tenant_id: Uuid,
    user_id: Uuid,
    current_session_id: Uuid,
    current_password: &str,
    new_password: &str,
    policy: &PasswordPolicy,
    history_repo: &H,
    http_client: Option<&reqwest::Client>,  // ADD: for HIBP check
) -> AxiamResult<()> {
    // ... existing code ...
    // In the evaluate_password call at line ~642:
    let check = crate::policy::evaluate_password(
        new_password,
        self.config.pepper.as_deref(),
        policy,
        tenant_id,
        user_id,
        history_repo,
        http_client,  // PASS THROUGH (was None)
    ).await?;
    // ...
}
```

### Custom Debug for mfa_secret redaction (SEC-043)

```rust
// crates/axiam-db/src/repository/user.rs
// Remove Debug from derive, add manual impl:
#[derive(SurrealValue)]
struct UserRow {
    // ...
    mfa_secret: Option<String>,
    // ...
}

impl std::fmt::Debug for UserRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserRow")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("status", &self.status)
            .field("mfa_secret", &self.mfa_secret.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}
```

### URL token strip after verification (SEC-037)

```typescript
// frontend/src/pages/auth/VerifyEmailPage.tsx
// Inside doVerify(), after success or terminal error:
async function doVerify() {
    try {
        await authService.verifyEmail(token!);
        // Strip token from URL before state update (SEC-037)
        window.history.replaceState({}, document.title, window.location.pathname);
        if (!cancelled) setVerifyState("success");
    } catch (err) {
        // Strip even on failure — token is now consumed/invalid
        window.history.replaceState({}, document.title, window.location.pathname);
        if (cancelled) return;
        // ...error handling...
    }
}
```

### Secret state clear on modal close (SEC-036)

```typescript
// Pattern for all 5 affected pages — example WebhooksPage.tsx:
onClose={() => {
    setSecretOpen(false);
    setRevealedSecret(null);  // SEC-036: clear secret from memory
}}
```

---

## State of the Art

| Old Approach | Current Approach | Phase | Impact |
|--------------|------------------|-------|--------|
| client_ip/user_agent private helpers per-file | Shared extractor in extractors/client_info.rs | Phase 12 | Consistent IP capping/parsing across all auth events |
| `warn!` only on audit drop | `error!` with `audit_dropped = true` structured field | Phase 12 | Alertable on drop events via Loki/Prometheus |
| Full UPSERT per boot × tenants | Hash-guarded seeder skip | Phase 12 | O(1) on restarts when registry unchanged |
| Implicit deny-override claim in docs | Explicit additive-only documentation | Phase 12 | No false security assurance from docs |
| GitHub Actions on mutable tags | Pinned to commit SHAs | Phase 12 | Eliminates supply-chain attack vector on CI |

**Deprecated/outdated:**
- `pages/placeholders/Placeholder.tsx`: no longer referenced, delete
- Hardcoded `en-US` in `utils.ts`: replace with `undefined` for browser locale

---

## Pre-Phase Status of Each Finding

| ID | Status at Phase 12 start | Evidence |
|----|--------------------------|----------|
| CQ-B27 | OPEN (descoped to Ph19) | Per ROADMAP deferred list; AppState refactor out of scope |
| CQ-B28 | OPEN | 3 separate `client_ip`/`user_agent` private defs confirmed |
| CQ-B29 | OPEN | NotificationPublisher in app_data; 0 handler call sites |
| CQ-B30 | FIXED in Phase 10 | `clamp_pagination_limit` at repository.rs:52 confirmed |
| CQ-B31 | OPEN | `let _ =` at cleanup.rs:247,294,314; gdpr.rs:124; token.rs:555 |
| CQ-B32 | PARTIAL (Phases 9-10 addressed org_id resolution) | Cosmetic split-type improvement deferred |
| CQ-B33 | PARTIAL | Typed variants added but `Crypto(String)` remains stringly |
| CQ-B34 | PARTIAL | Three rand majors remain; unused deps not yet macheted |
| CQ-B35 | OPEN | `None` passed to HIBP in `change_password` confirmed |
| CQ-B36 | OPEN | `warn!` only at middleware.rs:162 confirmed |
| CQ-B42 | OPEN | Seeder runs full UPSERT per boot confirmed |
| CQ-B44 | FIXED in Phase 11 | gRPC rate-limit `.per_second` fix done in 11-02 |
| SEC-040 | OPEN | engine.rs additive-only confirmed; docs unchanged |
| SEC-043 | PARTIAL | `skip_serializing` added (Phase 11); Debug redaction + list projection not done |
| SEC-057 | OPEN | ci.yml/release.yml confirmed using mutable tags |
| CQ-F20 | OPEN | TenantsPage `enabled: organizations.length > 0` confirmed |
| CQ-F21 | OPEN | Placeholder.tsx: 0 import sites confirmed |
| CQ-F22 | OPEN (pending shadcn/ui verification) | dialog/dropdown/select/separator: 0 direct imports in src/ |
| CQ-F23 | OPEN | UsersPage + BootstrapPage: no PasswordPolicyChecker confirmed |
| CQ-F24 | OPEN | DataTable.tsx:79 unsafe cast confirmed |
| CQ-F25 | OPEN | utils.ts:40,49 hardcoded `en-US` confirmed |
| CQ-F26 | OPEN | ResourceTree.tsx:81 no CSS.escape confirmed |
| CQ-F32 | OPEN | `_retry` set after retry at api.ts:98 confirmed |
| CQ-F33 | OPEN | `?? []` at usePermissions.ts:15 confirmed |
| CQ-F34 | OPEN | BootstrapPage:80 maps 404 → already-initialized |
| CQ-F35 | OPEN | `setInitializing` in dep array but not called in body confirmed |
| SEC-036 | OPEN | 5 pages confirmed: secrets not cleared on modal close |
| SEC-037 | OPEN | No `history.replaceState` in ResetPasswordPage or VerifyEmailPage |
| SEC-041 | OPEN | `console.warn("[ForgotPassword] request failed:", err)` at :35 confirmed |

---

## Runtime State Inventory

> Not a rename/migration phase. No runtime state inventory required.

None — all changes are code/config edits with no stored key renames or data migrations.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| cargo check/clippy | All Rust fixes | ✓ | workspace | — |
| cargo machete | CQ-B34 dep pruning | Install on-demand (`cargo install cargo-machete`) | latest | Manual grep for unused deps |
| node/npm | Frontend fixes | ✓ | workspace | — |
| playwright | Final e2e verification | ✓ | in package.json | Manual smoke only |

**Missing dependencies with no fallback:** None.

**Disk constraint (critical):** `/home` is near-full (~100%, target/ ~46 GiB). Do NOT run `cargo build --workspace` or `cargo test --workspace`. Use `cargo check -p <crate>` and `cargo test -p <crate> --test <test_name>`. Reclaim space before the final verification gate: `rm -rf target/debug/incremental`.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust framework | Built-in `#[tokio::test]` + actix-web test helpers |
| Frontend framework | vitest (unit) + Playwright (e2e) |
| Config file | `vitest.config.ts` (frontend) |
| Quick Rust check | `cargo check -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-audit -p axiam-amqp -p axiam-server` |
| Targeted test run | `cargo test -p <crate> --test <test_name>` OR `cargo test -p <crate> --lib` |
| Frontend check | `cd frontend && npm run lint && npx tsc -b --noEmit` |
| Frontend unit test | `cd frontend && npx vitest run` |
| Final gate | See Phase Requirements AC-5 |

### Phase Requirements → Test Map

| AC | Behavior | Test Type | Command | Proof |
|----|----------|-----------|---------|-------|
| AC-1: client_ip shared | All three handlers use same extractor | Compilation | `cargo check -p axiam-api-rest` | No compile error; single definition |
| AC-1: NotificationDispatcher | Dispatcher call sites exist or removed | Source assertion | grep for `dispatcher.dispatch` | Either present in audit worker or `NotificationPublisher` removed from app_data |
| AC-1: logged errors | `let _ =` removed at targeted sites | Source assertion | `grep -n "let _ = " crates/axiam-server/src/cleanup.rs` | Zero results (or only intentional ones) |
| AC-1: HIBP on change-password | change_password accepts HTTP client | Unit test | `cargo test -p axiam-auth -- change_password` | Existing test + new test: `change_password(..., Some(&reqwest_client))` |
| AC-1: audit-drop metric | `audit_dropped = true` event on full channel | Source assertion + unit | `cargo test -p axiam-audit --lib` | Verify `error!` emitted; write a unit test that fills channel and checks counter |
| AC-1: seeder hash skip | Second boot skips UPSERT when registry unchanged | Unit test | `cargo test -p axiam-db --lib -- seeder` | Add `test_seeder_skip_on_unchanged_hash` |
| AC-2: SEC-040 doc fix | Design-doc no longer claims deny-override | Source assertion | Read `claude_dev/design-document.md:385` | "explicit deny" wording removed |
| AC-2: SEC-043 mfa_secret | List query excludes mfa_secret; Debug redacted | Source assertion + unit | `cargo test -p axiam-db --lib -- user_list` | `UserRow::fmt` prints "[REDACTED]"; list SELECT has explicit column list |
| AC-2: SEC-057 SHA pins | All `uses:` lines have `@sha` format | Source assertion | `grep "uses:" .github/workflows/*.yml` | No `@v\d` or `@stable` refs remain |
| AC-3: dead Placeholder.tsx | File deleted | Source assertion | `ls frontend/src/pages/placeholders/Placeholder.tsx` | File not found (or directory empty) |
| AC-3: radix unused deps | Package.json cleaned | Source assertion | `grep "react-dialog\|react-select\|react-separator\|react-dropdown" frontend/package.json` | Zero results (if shadcn doesn't need them) |
| AC-3: password policy on admin-create | PasswordPolicyChecker present | Source assertion | `grep PasswordPolicyChecker frontend/src/pages/users/UsersPage.tsx` | Present |
| AC-3: password policy on bootstrap | PasswordPolicyChecker present | Source assertion | `grep PasswordPolicyChecker frontend/src/pages/BootstrapPage.tsx` | Present |
| AC-3: DataTable safe key | `String(...)` conversion used | Source assertion | Read `DataTable.tsx:79` | `String(...)` present |
| AC-3: i18n locale | No `en-US` hardcoded in utils.ts | Source assertion | `grep "en-US" frontend/src/lib/utils.ts` | Zero results |
| AC-3: CSS.escape | Present in ResourceTree | Source assertion | `grep "CSS.escape" frontend/src/components/ResourceTree.tsx` | Present |
| AC-3: _retry ordering | `_retry = true` set before retry | Source assertion | Read `api.ts` around line 98 | `_retry = true` before `api.post(...)` |
| AC-3: StrictMode double-fetch | `setInitializing` removed from dep array; useRef guard | Source assertion | Read `useAuthInit.ts:58` | `setInitializing` absent from deps |
| AC-4: secrets cleared | All 5 pages clear on modal close | Source assertion | grep each page for `setRevealedSecret(null)` or equivalent in `onClose` | Present in each |
| AC-4: URL token strip | `history.replaceState` present | Source assertion | `grep replaceState frontend/src/pages/auth/ResetPasswordPage.tsx frontend/src/pages/auth/VerifyEmailPage.tsx` | Present in both |
| AC-4: log redaction | No `err` in ForgotPassword warn | Source assertion | Read `ForgotPasswordPage.tsx:35` | No `err` arg in console.warn |
| AC-5: final gate — cargo check | All crates compile | `cargo check --workspace` | See disk note | Zero errors |
| AC-5: final gate — clippy | No warnings in affected crates | `cargo clippy -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-audit -p axiam-amqp -p axiam-server -- -D warnings` | Zero warnings |
| AC-5: final gate — cargo test | Affected crates' tests pass | `cargo test -p axiam-db -p axiam-api-rest -p axiam-auth -p axiam-audit` | All pass |
| AC-5: final gate — cargo audit | No unaddressed CVEs | `cargo audit` | Zero new advisories |
| AC-5: final gate — frontend | lint + tsc + vitest green | `cd frontend && npm run lint && npx tsc -b && npx vitest run` | All pass |
| AC-5: manual smoke | Core flows work end-to-end | Manual | Browser smoke checklist below | All flows pass |

### Manual Smoke Checklist (AC-5)

1. Login → MFA enroll → MFA verify → dashboard visible
2. Password reset (email sent → link opened → password changed → login with new password)
3. Email verify (link clicked → token stripped from URL → success page shown)
4. Change password (HIBP check triggers on known compromised password)
5. GDPR export → download JSON
6. Federation OIDC login → restart server → OIDC login succeeds again (secret decrypt-at-use working)
7. Cross-org request: as Org A user, access Org B resource → 403
8. gRPC call without credentials → UNAUTHENTICATED response
9. Bootstrap page: visit `/bootstrap` after admin exists → 409 → "already initialized" message (not 404 confused)
10. Admin user create: password policy checker visible and gates submission

### Sampling Rate

- **Per task commit:** `cargo check -p <affected-crate>` (disk-safe)
- **Per plan cluster:** targeted `cargo test -p <crate>` for behaviors changed in that cluster + `cd frontend && npx tsc -b`
- **Phase gate (Plan 12-04):** full AC-5 verification sequence as documented above

### Wave 0 Gaps (test infrastructure)

- `crates/axiam-db/tests/seeder_skip_test.rs` — does not exist; needed for seeder hash-skip behavior (CQ-B42)
- `crates/axiam-audit/tests/audit_drop_test.rs` — does not exist; needed for audit-drop metric verification (CQ-B36)
- `frontend/src/hooks/useAuthInit.test.ts` — does not exist; needed to prove StrictMode double-fetch fixed (CQ-F35)

*(All other verifications are source assertions or extensions of existing test files.)*

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | HIBP on sync change-password path (CQ-B35) |
| V3 Session Management | yes | Secrets cleared from state on close (SEC-036); URL tokens stripped (SEC-037) |
| V4 Access Control | yes | SEC-040 doc correction (additive-only RBAC clarified) |
| V5 Input Validation | yes | Password policy checker on admin-create + bootstrap (CQ-F23) |
| V6 Cryptography | yes | Debug redaction of mfa_secret encrypted blob (SEC-043) |
| V7 Error Handling | yes | Logged errors replace silent `let _ =`; ForgotPassword redaction (SEC-041) |
| V14 Config | yes | GitHub Actions SHA pinning (SEC-057); remove dead Placeholder.tsx; dep pruning |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| GH Actions supply chain via mutable tag | Tampering / Spoofing | Pin by commit SHA (SEC-057) |
| MFA secret in debug log / error log | Information Disclosure | Custom Debug impl redacting mfa_secret (SEC-043) |
| Reset token persists in browser history | Information Disclosure | `history.replaceState` after token use (SEC-037) |
| Secret (API key, cert priv key) visible in JS memory after modal close | Information Disclosure | Clear state in `onClose` (SEC-036) |
| Email address logged on password-reset request | Information Disclosure | Remove `err` from console.warn (SEC-041) |
| HIBP bypass on sync change-password | Elevation of Privilege | Pass `reqwest::Client` to `change_password` (CQ-B35) |
| Forged RBAC denial claims (additive-only doc gap) | Spoofing / Elevation of Privilege | Document engine limitations accurately (SEC-040) |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Bootstrap endpoint returns HTTP 409 (not 404) when admin already exists | CQ-F34 | If it returns 404, frontend status code mapping stays as-is; verify in `bootstrap_test.rs` during implementation |
| A2 | radix-ui packages `react-dialog`/`react-dropdown-menu`/`react-select`/`react-separator` are not used in `frontend/src/components/ui/` shadcn wrappers | CQ-F22 | If shadcn ui components import them, cannot remove from package.json; must verify with grep before removal |
| A3 | `reqwest::Client` is already available as `app_data` in `main.rs` (or can be easily registered) | CQ-B35 | If not registered, requires adding `web::Data::new(reqwest::Client::new())` to `main.rs` and extracting it in the change-password handler |
| A4 | `cargo machete` is not installed and must be installed during Plan 12-01 | CQ-B34 | If `cargo install cargo-machete` is slow due to compile time, run it off-critical-path; alternatively do manual dep audit |
| A5 | NotificationDispatcher can be called from the audit middleware worker loop (which has access to its internal components) | CQ-B29 | If the dispatcher needs `reqwest::Client` or other components not in the worker context, wiring to the audit loop requires adding those components; may need to fall back to "remove from app_data" option |

---

## Open Questions

1. **CQ-B27 — AppState refactor scope:** The ROADMAP deferred `CQ-B43` (AppState with ~45 app_data registrations) to Phase 12. Is this intended to be implemented in Phase 12 or fully deferred to Phase 19?
   - What we know: Phase 11 research says "deferred to Phase 12 per ROADMAP deferred list"
   - What's unclear: implementing AppState is significant scope (refactor `main.rs`, update all handler signatures) vs the other LOW findings which are 2-5 line fixes
   - Recommendation: Defer to Phase 19. CQ-B27 is the per-request service rebuild issue (not AppState itself) — fix the worst offenders (federation services) in a targeted way if time permits, but do not block Phase 12 on a full AppState refactor.

2. **BootstrapPage HTTP status:** The frontend maps `status === 404` to "already initialized" but the backend handler should be returning 409.
   - What we know: Phase 3 (`bootstrap.rs`) was implemented to create admin once; the test file `bootstrap_test.rs` exists and likely validates the status code
   - What's unclear: exact status code when `admin already exists` — need to check `bootstrap_test.rs` during implementation
   - Recommendation: Verify `bootstrap_test.rs` before changing frontend mapping.

3. **NotificationDispatcher wiring scope:** Wiring the dispatcher into the audit middleware worker vs. calling it from handlers are different scope sizes.
   - What we know: The dispatcher is well-tested, NotificationPublisher is registered
   - What's unclear: Does the audit worker have access to `reqwest::Client` or similar delivery mechanism?
   - Recommendation: Check `notification.rs:dispatch()` signature. If it just calls an AMQP publisher (which it likely does via `NotificationPublisher`), wiring into the audit worker is 10-15 lines. If it requires HTTP delivery itself, option B (remove from app_data, document as Phase 19) is safer.

---

## Sources

### Primary (HIGH confidence — direct codebase inspection at post-Phase-11 HEAD)

- `crates/axiam-api-rest/src/handlers/auth.rs:169-180` — confirmed `client_ip`/`user_agent` private defs
- `crates/axiam-api-rest/src/handlers/webauthn.rs:95-106` — confirmed third private def
- `crates/axiam-server/src/main.rs:477,611` — NotificationPublisher created + registered, no handler extraction
- `crates/axiam-server/src/cleanup.rs:247,294,314` — `let _ =` confirmed
- `crates/axiam-auth/src/service.rs:642` — `None, // no HIBP client` confirmed
- `crates/axiam-audit/src/middleware.rs:161-162` — `warn!` only, no metric
- `crates/axiam-db/src/seeder.rs:37-66` — full UPSERT per boot, no hash guard
- `crates/axiam-authz/src/engine.rs` — additive-only, no deny mechanism
- `crates/axiam-db/src/repository/user.rs:20,45,254,277,446,458` — `Debug` derive with mfa_secret + SELECT * in list
- `.github/workflows/ci.yml` and `release.yml` — mutable tags confirmed
- `frontend/src/pages/placeholders/Placeholder.tsx` — 0 import sites confirmed
- `frontend/package.json` — 4 radix packages with 0 direct imports in `src/`
- `frontend/src/pages/users/UsersPage.tsx`, `BootstrapPage.tsx` — no PasswordPolicyChecker confirmed
- `frontend/src/components/DataTable.tsx:79` — unsafe cast confirmed
- `frontend/src/lib/utils.ts:40,49` — `en-US` hardcoded confirmed
- `frontend/src/components/ResourceTree.tsx:81` — no CSS.escape confirmed
- `frontend/src/lib/api.ts:88-98` — `_retry` set after retry confirmed
- `frontend/src/hooks/usePermissions.ts:15` — `?? []` confirmed
- `frontend/src/pages/BootstrapPage.tsx:80` — 404 → alreadyInitialized confirmed
- `frontend/src/hooks/useAuthInit.ts:58` — `setInitializing` in dep array, not called in body
- `frontend/src/pages/{Certificates,OAuth2Clients,ServiceAccounts,Webhooks,PgpKeys}Page.tsx` — 5 pages confirmed: secrets not cleared on close
- `frontend/src/pages/auth/ResetPasswordPage.tsx`, `VerifyEmailPage.tsx` — no `replaceState`
- `frontend/src/pages/auth/ForgotPasswordPage.tsx:35` — `console.warn(err)` with Axios error object
- `claude_dev/code-review.md` — finding definitions CQ-B27..B36/B42/F20..F35
- `claude_dev/security-review.md` — finding definitions SEC-036/037/040/041/043/057

### Secondary (MEDIUM confidence — prior phase research + ROADMAP)

- `.planning/phases/11-medium-remediation/11-RESEARCH.md` — structural exemplar
- `.planning/ROADMAP.md` Phase 12 scope + deferred items list
- `MEMORY.md` — SurrealDB v3 quirks (no changes relevant to Phase 12 findings)

---

## Metadata

**Confidence breakdown:**
- Standard Stack: HIGH — no new deps; all existing
- Architecture: HIGH — all "apply existing pattern" changes; no new structural decisions
- Pitfalls: HIGH — verified against actual post-Phase-11 code state
- Validation: HIGH — commands derived from established crate structure

**Research date:** 2026-06-19
**Valid until:** 2026-07-19 (stable Rust + React ecosystem; no fast-moving dependencies in this phase)
