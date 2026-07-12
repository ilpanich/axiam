# AXIAM — Final Pre-MVP Security Review

- **Date**: 2026-07-06
- **Commit reviewed**: `031abfe` (HEAD of `claude/final-security-code-review-j0fzni`; `feature/final-phases` line)
- **Baseline**: [`security-review-postremediation.md`](security-review-postremediation.md) (reviewed `ea85872`) and [`security-audit.md`](security-audit.md) (compliance index at `c79b66e`). **111 commits / ~123k insertions** since `ea85872`: v1.2 hardening (phases 23–29 — the SECFIX/SECHRD requirement register), phase 30 docs, and **7 new client SDKs (~63k lines across 377 files)**.
- **Method**: independent re-verification of every claimed v1.2 security remediation against current code with file:line evidence (not trusting `.planning/REQUIREMENTS.md`), a fresh vulnerability scan of all v1.2-touched security surface (gRPC auth, RBAC/CSRF middleware, federation OIDC/SAML/JWKS/SSRF, PKI/mTLS, AMQP HMAC, GDPR erasure, bootstrap, rate-limiting), the **first-ever security review of the 7 SDKs**, and a supply-chain/CI review (dependabot, SAST, cargo-audit/deny). Multi-agent fan-out; every HIGH independently corroborated by ≥2 readers.
- **Companion**: [`final-code-review.md`](final-code-review.md) — quality/correctness (`CQ-*`) items live there.

Statuses: ✅ FIXED · 🔶 PARTIAL · ❌ OPEN · ⚠️ REGRESSION. New findings continue at **SEC-067**.

> **This document is written to be consumed by an Opus 4.8 planner + Sonnet 5 executor.** Each open finding carries an exact anchor, an exploit/impact statement, and a concrete fix. A prioritized remediation order is in §7.

---

## 1. Executive summary

**The v1.2 hardening wave is real and thorough.** Of the 15 HIGH/MEDIUM security remediations claimed by the SECFIX/SECHRD register, **14 verified fully FIXED against current code and 1 is PARTIAL**, with **no regressions** of previously-closed findings and **no open Critical or (backend-server) High**. The two regressions the last review flagged (webhook zero-key, `grant_to_role_with_scopes` bypass) are both genuinely closed now, verified at the source. Password/session/crypto/federation/PKI controls are in strong shape: gRPC is fully authenticated at a single interceptor chokepoint, the SAML XSW binding is closed, SSRF address-pinning covers all four federation fetch types, TOTP replay is an atomic compare-and-set, mTLS checks issuing-CA status and validity, and GDPR erasure is now fatal-on-failure and re-selectable.

**The frontier of remaining risk has moved to two places the last review did not cover:**

1. **The 7 new SDKs** (never previously reviewed — this is where dependabot/CodeQL alerts cluster). No Critical and **no classic auth bypass** was found (TLS-bypass APIs, `alg:none`/HS-confusion, unsafe deserialization, weak RNG, tokens-in-URLs all verified *absent* — the SDKs are unusually disciplined). But there is one HIGH reliability-class defect that renders a security control inoperative (**SDK AMQP HMAC verification is broken in Go and Rust**), one MEDIUM key-substitution exposure (**PHP JWKS discovery is unvalidated**), and a systemic hardening gap (**no SDK rejects a plaintext `http://` base URL**).
2. **Supply-chain / CI security coverage.** dependabot covers only 3 ecosystems (**none of the 7 SDK package managers**), no SDK CI job runs a dependency vulnerability scan, and **there is no CodeQL/SAST analysis anywhere** in `.github/` — the `codeql-action` usage only uploads Trivy/Hadolint SARIF. `security-audit.md` currently marks "Security updates" and "no known exploitable vulnerabilities" as full Pass; that is accurate for the Rust workspace + frontend but overstated for the SDK tree.

**Enforcement-by-convention** remains the one architectural theme to watch: RBAC (`RequirePermission` per handler), CSRF (per-scope wrap), and secret redaction are correct where wired and silent where not — the webhook secret got `serde(skip_serializing)` but not the `Debug` redaction its federation sibling received (SEC-067).

### Active finding counts (this review)

| Severity | Backend | SDK | Supply-chain/CI | Total new |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 1 (X-1, fail-closed) | 0 | 1 |
| Medium | 1 (SEC-067) | 1 (SDK-19) + 1 (X-2 family) | 2 (CI-03, CI-04) | 5 |
| Low | 3 (SEC-068/069/070) | ~6 (X-3/X-4/SDK-04/10/11/17) | 0 | ~9 |

Plus **CQ-B50/B52** (cross-tenant graph-edge strip) carried from the companion for its security dimension — see §4.

---

## 2. v1.2 remediation verification — all claims re-checked against `031abfe`

Every remediation the register claims. Independently verified with file:line; exploit noted where residual.

| Prior ID (→ v1.2 REQ) | Verdict | Evidence & residual |
|---|---|---|
| **SEC-003** gRPC UserService/TokenService unauth (→ SECFIX-01) | ✅ FIXED | All three services `with_interceptor(AuthInterceptor)` (`axiam-api-grpc/src/server.rs:88-102`); `GetUser`/`ValidateCredentials` read `ValidatedClaims`, reject body/claims tenant mismatch, and look up scoped to the *claims* tenant (`services/user.rs:66-90,117-122`). `ValidateCredentials` now accrues lockout (`services/user.rs:180-190`), closing SEC-026b. Residual → **SEC-068** (introspection not tenant-scoped, Low). |
| **SEC-058** live grant path bypasses tenant guard (→ SECFIX-02) | ✅ FIXED | `grant_to_role_with_scopes` now guards **both** branches: `LET…WHERE tenant_id=$tid; IF array::len=0 {THROW}` and validates every scope id belongs to the tenant (`axiam-db/src/repository/permission.rs:409-472`). Isolation test targets this method (`req14_tenant_isolation_test.rs:161-168`). |
| **SEC-059** webhook all-zero key (→ SECFIX-03) | ✅ FIXED | No `[0u8;32]` fallback anywhere; key is `Option<[u8;32]>`, fail-closed (`axiam-server/src/main.rs:62-79,459-461`; `webhook.rs:145-152` → `EncryptionKeyMissing`). |
| **SEC-031** webhook secret plaintext-at-rest (→ SECFIX-03) | ✅ FIXED | `encrypt_secret` now called on **create** (`handlers/webhooks.rs:113`) and **update/rotation** (`:232`) before persist; delivery decrypts before HMAC (`webhook.rs:237,244`). The 100%-fail decrypt trap is gone. |
| **SEC-005** SAML XSW / binding gaps (→ SECFIX-04) | ✅ FIXED | Signature bound to the consumed assertion: `bind_signature_to_assertion(xml, &assertion.id)` (`axiam-federation/src/saml.rs:474`), enforcing exactly one `<Assertion>` and a signed `Reference URI=#<id>` (`:792-851`). Authenticated ACS passes real `Destination`/`InResponseTo` (`handlers/federation.rs:876-884`), not `None`. Disclosed deferrals: `Recipient`/`SubjectConfirmationData` still unchecked (register-acknowledged). |
| **SEC-015** logout never revokes (→ SECFIX-05) | ✅ FIXED | `logout(user, state)` takes **no body**, revokes `user.session_id` derived from the verified JWT `jti` (`handlers/auth.rs:371-385`). Frontend posts bodyless (`Topbar.tsx:93`). |
| **SEC-044** reset/resend missing tenant_id (→ SECFIX-06) | ✅ FIXED | `services/auth.ts` threads `tenant_id`/slugs on all three flows (`:61-65,83-87,115-118`); backend resolves + is enumeration-safe (`handlers/password_reset.rs:64-99,131-139`). The e2e contract spec now asserts request **bodies** (`e2e/auth-contract.spec.ts:127-290`), so a body regression fails CI. |
| **SEC-008** TOTP replay non-atomic (→ SECHRD-01) | ✅ FIXED | Atomic CAS: `UPDATE…WHERE totp_last_used_step = NONE OR < $step` wrapped in `SELECT FROM (UPDATE…)` (`repository/user.rs:493-508`); caller treats lost CAS as invalid (`service.rs:378-382`); enrollment-confirm seeds the step (`service.rs:485-514`). Test `totp_step_cas_concurrent`. |
| **SEC-064** SSRF guard JWKS-only (→ SECHRD-02) | ✅ FIXED | `ssrf.rs` resolve-once-and-pin (`resolve_and_pick:99-115`, `pinned_client:129-131`) applied to **all four** IdP fetches: discovery (`oidc.rs:153`), token exchange (`oidc.rs:474`), JWKS (`jwks_cache.rs:255`), SAML metadata (`saml.rs:145`); redirects re-validated per hop. DNS-rebind TOCTOU closed. Residual → **SEC-069** (no https-only/size cap in `guarded_fetch`, Low). |
| **SEC-048/060** XFF rate-limit keying (→ SECHRD-03) | ✅ FIXED | Underflow branch falls through to `peer_addr()` instead of the client-controlled hop (`extractors/rate_limit.rs:66-77`); nginx right-append semantics documented; gRPC has a SurrealDB-backed shared store. Residual → **SEC-070** (stale doc comment, Info). |
| **SEC-049** bootstrap TOCTOU / unset gate (→ SECHRD-04) | ✅ FIXED | Mandatory fail-closed gate (`handlers/bootstrap.rs:153-184`) + atomic `CREATE bootstrap_lock` uniqueness inside one `BEGIN…COMMIT` (`:243-273`); concurrent second request hits the UNIQUE violation and rolls back. |
| **SEC-024/061** mTLS ignores CA status (→ SECHRD-05) | ✅ FIXED | Device cert Active+validity, **then** issuing CA `status==Active` (`mtls.rs:90`) + CA validity window (`:93-95`) + chain verify (`:112-115`). |
| **SEC-004** OIDC nonce from request body (→ SECHRD-07) | ✅ FIXED | Authenticated callback derives `expected_nonce` from server-side `federation_login_state`; `req.nonce` ignored (`handlers/federation.rs:642-660`). |
| **SEC-063/065/066** GDPR erasure durability (→ SECHRD-06) | ✅ FIXED | Audit-pseudonymize is now fatal (`cleanup.rs:132-135` `?`), flags cleared last (re-selectable), proof written last, export dedup covers `queued`/`ready`/`failed` (`export_job.rs:99-111`). |
| **SEC-022/055** AMQP signing + ExportReady (→ SECHRD-08) | ✅ FIXED | Signing mandatory in release builds (fail-closed, `axiam-amqp/src/config.rs`), per-tenant HKDF subkey (`messages.rs:59-63`), consumers nack unsigned; ExportReady resolves real `org_id` from tenant (`cleanup.rs:586-603`). |
| **SEC-017** secret non-serialization (→ SECHRD-09) | 🔶 **PARTIAL** | Federation fully fixed: `skip_serializing` + redacting `Debug` (`models/federation.rs:27,44,48,52,60-77`). **Webhook gap** → **SEC-067** below. |

**Verdict: 14 ✅ / 1 🔶. No regressions.** The compliance-audit deferrals (SAML `Recipient`, PERF-01 load test, SBOM) are honestly disclosed in `security-audit.md`, not hidden.

---

## 3. New backend security findings

### SEC-067 [MEDIUM] 🆕 — Webhook secret leaks via derived `Debug` (SECHRD-09 applied to federation, not mirrored to webhook)
- **File**: `crates/axiam-core/src/models/webhook.rs:31-44` (`Webhook`), `:51-60` (`CreateWebhook`)
- **Issue**: `Webhook` has `#[serde(skip_serializing)]` on `secret` but **still `#[derive(Debug)]`** with no manual redaction, so `{:?}` prints the AES-GCM-encrypted secret. Worse, `CreateWebhook` derives `Debug` over a **plaintext** `secret: String` with no skip and no redaction. The federation model got exactly this fix (redacting `Debug` impl at `federation.rs:60-77`); it was not carried to webhooks.
- **Exploit**: any `tracing::debug!(?webhook)` / `{:?}` of a `Webhook` (encrypted secret + nonce) or `CreateWebhook` (plaintext HMAC secret) writes the secret to logs — the SECHRD-09 "kept out of Debug" requirement half-applied.
- **Fix**: add a manual redacting `Debug` impl to both structs, mirroring `FederationConfig::fmt` (`federation.rs:60-77`).

### SEC-068 [LOW] 🆕 — gRPC token introspection not scoped to the caller's tenant
- **File**: `crates/axiam-api-grpc/src/services/token.rs:56-98`
- **Issue**: `IntrospectToken`/`ValidateToken` validate the *supplied* token but never cross-check it against the caller's `ValidatedClaims` tenant (unlike `GetUser`/`CheckAccess`, which do). Access is gated (interceptor requires *a* valid JWT), so the SEC-003 hole stays closed, but any authenticated mesh peer in tenant A can introspect a tenant-B access token and read its `sub`/`tenant_id`/`org_id`/`jti` claims — cross-tenant info disclosure inside the mesh.
- **Fix**: read `ValidatedClaims` and reject when the introspected token's `tenant_id` ≠ caller's, or restrict introspection to service-account callers.

### SEC-069 [LOW] 🆕 — Federation `guarded_fetch` has no https-only check and no response-body size cap
- **File**: `crates/axiam-federation/src/ssrf.rs:148-186`
- **Issue**: The SSRF guard pins the resolved IP but does not enforce `https` (an admin-configured `http://` IdP endpoint is fetched silently) and imposes no body-size limit on discovery/token/metadata responses (JWKS has a 512 KiB cap; the others do not).
- **Exploit**: a malicious/compromised admin-configured IdP (or a redirect) serves a multi-GB metadata/JWKS body → memory-exhaustion DoS; or a plaintext IdP endpoint carries the decrypted `client_secret` in cleartext.
- **Fix**: reject non-`https` (allow `http` only behind the private-network test seam); stream with a few-MB read cap.

### SEC-070 [LOW/INFO] 🆕 — XFF `trusted_hops` doc comment contradicts the (safer) code
- **File**: `crates/axiam-api-rest/src/extractors/rate_limit.rs:34,42`
- **Issue**: comments say `trusted_hops=0` uses the "leftmost" entry, but the code computes `idx = len-1-hops` → selects the **rightmost** (correct for single-hop nginx). The code is safe; the stale comment can mislead an operator, and the default of 0 still trusts XFF-when-present, so a directly-exposed server (no proxy) lets an attacker rotate `X-Forwarded-For` to mint fresh buckets.
- **Fix**: correct the comments; consider defaulting to `peer_addr()`-only unless `trusted_hops > 0` is explicitly set.

### Cross-tenant graph-edge strip (security dimension of CQ-B07 / CQ-B50 / CQ-B52)
- **File**: `permission.delete` (`permission.rs:238-248`), `group.delete` (`group.rs:274-284`), `service_account.delete` (`service_account.rs:289-300`), `group.remove_member` (`group.rs:389-410`, ignores its `_tenant_id`), `resource.update` re-parent (`resource.rs:214-222`)
- **Issue**: This is the same class as SEC-007/SEC-058 — the *edge* `DELETE`s are keyed by raw record UUID with **no tenant predicate** (only the trailing node delete carries a flat `tenant_id`). A caller with the relevant permission in tenant A who supplies a foreign-tenant entity UUID strips another tenant's role/membership/permission edges; three of these also omit `.check()`, so the failure is swallowed as `Ok(())`.
- **Impact**: cross-tenant integrity/isolation violation (deauthorize another tenant's users/service-accounts). Requires a valid permission in the attacker's tenant + knowledge/guess of a foreign record id.
- **Fix**: mirror the already-correct `role.delete`/`resource.delete` pattern — wrap each mutation in `BEGIN/COMMIT` and add `AND {endpoint}.tenant_id = $tenant_id` to every edge `DELETE`; use the ignored `tenant_id` in `group.remove_member`; restore `.check()`. (Full correctness detail in the companion under CQ-B07/B50/B51/B52.)

---

## 4. SDK security review (first pass — the dependabot/CodeQL frontier)

**Provenance**: all security-relevant SDK code (auth, token, HMAC, JWKS, TLS, transport) is **hand-written**; only the gRPC protobuf stubs are generated (and clean). **General posture is unusually strong**: strict-TLS-by-default everywhere, CI grep-gates against TLS-bypass idioms, `Sensitive<T>` redaction newtypes, constant-time HMAC compares in every language, and alg-pinned EdDSA JWKS verification that rejects `alg` confusion *before* key lookup.

**Verified absent (no findings):** TLS-verification bypass APIs, `alg:none`/HS-confusion, non-constant-time secret compares, unsafe deserialization (pickle/`readObject`/`BinaryFormatter`/`unserialize`/`TypeNameHandling`), XXE, weak RNG for security values, hardcoded keys/IVs, tokens in URLs/query strings. (There is no OAuth2 authorization-code/PKCE/state/nonce surface in the SDKs — they are password+MFA+cookie clients, so that class is N/A.)

### X-1 / SDK-01 / SDK-05 [HIGH] — AMQP HMAC verification is broken in Go and Rust (a security control is inoperative)
- **File**: Go `sdks/go/amqp/hmac.go:34,51-52`; Rust `sdks/rust/src/amqp/consumer.rs:104` (+ `Cargo.toml:68`, no `preserve_order`)
- **Issue**: The server signs the HMAC over `serde_json` **struct-declaration-order** bytes (`crates/axiam-amqp/src/messages.rs`; `AuthzRequest` order = `correlation_id, tenant_id, subject_id, action, resource_id, scope, key_version` — *not* alphabetical). Go re-canonicalizes via a `map[string]json.RawMessage` (Go sorts map keys); Rust re-serializes a `serde_json::Value` backed by a sorted `BTreeMap`. Both recompute the HMAC over **different bytes than the server signed**.
- **Impact**: `hmac.Equal`/`verify_slice` fails for every real multi-field message → the delivery is nacked-without-requeue (**dropped**). The entire async-authz / audit-ingestion consumer path is **non-functional** in the two "reference" SDKs. This **fails closed** (a reliability/DoS defect, not a forgery bypass — which is why it slipped through), but it means a security control (AMQP message authentication) does not operate.
- **Masked by tautological tests**: `go/amqp/hmac_test.go:5-17` hardcodes a fixture whose 2 keys happen to be pre-sorted and whose comment *falsely* claims the server serializes alphabetically; Rust signs and verifies over the same `Value`. The 5 correct SDKs (Python/PHP/Java/C#/TS) preserve insertion order and their comments **explicitly cite "the key-order divergence from Go"** — the bug was known downstream and never fixed at source.
- **Fix**: deserialize into the concrete declaration-ordered struct (or enable `serde_json/preserve_order` in Rust; use the typed struct or an order-preserving decoder in Go). Add a fixture test using **real server-signed bytes** with ≥3 out-of-order fields. (Companion: CQ-related, cross-referenced as SDK-Q01.)

### SDK-19 [MEDIUM] — PHP JWKS `jwks_uri` from OIDC discovery is unvalidated (key substitution / SSRF)
- **File**: `sdks/php/src/Auth/JwksVerifier.php:224` (returns `jwks_uri` verbatim), `:188` (fetches it), `:115` (`JWT::decode` trusts the fetched keys)
- **Issue**: PHP is the **only** SDK that performs OIDC discovery (all others hardcode `/oauth2/jwks`). The discovered `jwks_uri` is used with no scheme/host validation, so a `jwks_uri` of `http://evil/jwks` is fetched off-host and its keys become the trust anchor for token verification. `alg` is pinned to EdDSA, so this is **key substitution, not alg confusion** → a full auth bypass *if* the discovery response is ever attacker-influenced (compromised/malicious server, SSRF/open-redirect on discovery, or MITM if TLS is relaxed). Gated today behind enforced `verify=true`, so it is defense-in-depth, not an active break.
- **Fix**: require the `jwks_uri` be `https` and same-host as `baseUrl`, else fall back to `{baseUrl}/oauth2/jwks`.

### X-2 (family) [MEDIUM/LOW] — No transport-scheme enforcement: plaintext base URLs silently accepted
- **File**: Rust `client.rs:98-105`, gRPC `channel.rs:61`; Go `login.go`/`client.go`; **TS gRPC `grpc/client.ts:124-130` (actively calls `createInsecure()` for non-https/grpcs)**; Python `_client.py:70-101`; Java `AxiamClient.java:94,113-116,517-520`; C# `AxiamClient.cs:63,82-85`, gRPC `AxiamGrpcChannel.cs:36-54` (h2c), AMQP `AxiamAmqpConsumer.cs:77`
- **Issue**: Every SDK validates the CA/cert path but **never rejects a non-TLS base URL**. A misconfigured `http://`/`amqp://`/`grpc://` target sends login username+password, `Authorization: Bearer`, session cookies, CSRF and tenant headers in cleartext — defeating the "TLS 1.3 minimum" mandate without touching a bypass API. The TS gRPC path is the sharpest: it *chooses* `createInsecure()` with no opt-in or warning.
- **Fix**: reject non-`https`/`amqps`/`grpcs` targets at construction (allow-list loopback for dev only). One fix per SDK; the TS gRPC `buildCredentials` is the priority.

### Lower-severity SDK findings

| ID | SDK(s) | Sev | Issue | Fix |
|---|---|---|---|---|
| X-4 / SDK-13, SDK-03 | Java, Rust | LOW/MED | Secret-bearing structs use default `Debug`/`toString`: Java `TokenPair` (`internal/TokenPair.java:14`) prints both raw tokens; Rust `LoginRequestBody`/`MfaVerifyRequestBody` derive `Debug` over password/OTP (`rest/auth.rs:27-45`). | Wrap in `Sensitive`/redact `toString`/drop the `Debug` derive. |
| SDK-04 | Rust | LOW/MED | Redirect policy compares host only, not scheme (`client.rs:187-196`) → follows a same-host `https→http` downgrade, re-sending `X-Tenant-ID`/`X-CSRF-Token` in cleartext. | `attempt.stop()` on scheme downgrade too. |
| SDK-17 | C# | LOW | `AllowAutoRedirect` left `true` (`Rest/AxiamHttpClientFactory.cs:34-40`); .NET strips `Authorization` on cross-origin redirect but **not** the SDK's `X-Tenant-Id`/`X-CSRF-Token`. | `AllowAutoRedirect=false`. |
| SDK-11 | Python | LOW | Signature-valid token with non-numeric `exp` → unhandled 500 (denies, but breaks the "malformed→401" invariant) (`fastapi/__init__.py:117-118`, `django/middleware.py:176-177`). | Parse `exp` inside the verify try/except. |
| SDK-10 | Python | LOW | JSON-decode error interpolates the decoded JWT payload segment into `AuthError` message (`_client.py:49-50`) — leaks (non-secret) claims into logs, contradicts the SDK's own rule. | Static message. |
| X-3 / SDK-08,12,18 | TS, Py, C#, Java (+Go) | LOW | Error/cause header redaction uses a 3-entry **denylist** (`set-cookie`/`authorization`/`cookie`), so a custom `X-Auth-Token` survives into exceptions/logs. | Switch to an allowlist of known-safe headers. |
| SDK-15 | Java | INFO | AMQP generic-exception path requeues a poison message infinitely; an `Error` (vs `Exception`) leaves the delivery neither acked nor nacked (`amqp/AmqpConsumer.java:119-121`). | Bound requeues / dead-letter after N. |
| SDK-20 | PHP | INFO | Effective tenant taken from client-supplied `X-Tenant-ID`, but `JwksVerifier.verify` enforces `token.tenant_id === header` (`:124`) — not a bypass; document that consuming apps must still confirm the route's tenant. | Doc note. |

---

## 5. Supply-chain & CI security coverage

The Rust-workspace + frontend security tooling is genuinely strong (SHA-pinned actions, `cargo audit` + `cargo deny` + Trivy fs/config + `npm audit` + Hadolint, all gating). **The gap is the SDK tree and the absence of first-party SAST.**

### CI-03 [MEDIUM] — SDK dependencies are entirely unscanned and un-updated
- **dependabot** (`.github/dependabot.yml`) covers exactly 3 ecosystems: `cargo` (`/`), `npm` (`/frontend`), `github-actions` (`/`). **None** of the 7 SDK package managers are covered — no `sdks/rust` (cargo), `sdks/typescript` (npm), `sdks/python` (pip), `sdks/go` (gomod), `sdks/java` + `sdks/java-bom` (maven), `sdks/csharp` (nuget), `sdks/php` (composer).
- **SDK CI** (7 `sdk-ci-*.yml`): every one runs build/test/lint + grep-based TLS-bypass/token-leak gates, but **none runs a dependency vulnerability scan** (no `pip-audit`/`npm audit`/`govulncheck`/`cargo audit`/`composer audit`/OWASP-dependency-check).
- **Impact**: this is precisely why the dependabot/CodeQL alerts the user references cluster in the SDKs — the SDK dependency trees receive neither automated update PRs nor a CI vuln gate. `security-audit.md` §4 "Security updates → Pass (dependabot across 3 ecosystems)" and CRA "no known exploitable vulnerabilities → Pass" are accurate for the workspace but **overstated for the SDKs**.
- **Fix**: add a dependabot entry per SDK ecosystem/directory; add a vuln-scan step to each `sdk-ci-*.yml` (`pip-audit`, `npm audit --audit-level=high`, `govulncheck`, `cargo audit`, `dotnet list package --vulnerable`, `composer audit`).

### CI-04 [MEDIUM] — No CodeQL / SAST anywhere in the repo
- **File**: `.github/workflows/*` — `github/codeql-action/upload-sarif` appears (ci.yml, release.yml) but only to upload **Trivy/Hadolint** SARIF. There is **no `codeql-action/init` + `analyze`**, and no Semgrep/Snyk/Sonar. First-party static code analysis is absent across both the Rust workspace and all 7 SDKs.
- **Impact**: the CodeQL alerts the user sees come from GitHub's repo-level *default setup* (configured in the UI, not reproducible in-repo) rather than a committed workflow — so scanning coverage isn't portable, versioned, or enforced on forks/self-hosted runners, and there is no in-repo record of what is scanned.
- **Fix**: add a committed `codeql.yml` (languages: `javascript-typescript`, `python`, `go`, `java`, `csharp`; Rust via community action or accept cargo-audit/clippy as the Rust substitute) so SAST is versioned and gating.

### Compliance-doc accuracy (positive, with one nit)
Spot-checking `security-audit.md`'s cited evidence against code: **all five sampled REQ-IDs (SECFIX-01/02, SECHRD-01/06, PERF-01) resolve to test files that exist and contain the described assertions** (`grpc_auth_test.rs`, `permission.rs:409+`, `totp_step_cas_test.rs`, `cleanup_task.rs` + `export_job.rs:376`, `hibp_breaker.rs`). The `[ASSUMED]`/`DEFERRED` flags and the F-03/F-05 self-corrections are honest. Only nit: PERF-01 attributes `check_complexity` pre-sizing to "authz middleware" but it lives in `axiam-auth/src/policy.rs` (cosmetic).

---

## 6. What is genuinely solid (so the executor doesn't "fix" it)

- gRPC identity chokepoint — claims-derived, body cross-validated, all three services wrapped.
- CSRF double-submit — 32-byte CSPRNG, constant-time compare, rotation on login/refresh, path-scoped refresh cookie, `HttpOnly`/`Secure`/`SameSite=Strict`.
- Frontend token handling — tokens never touch JS/`localStorage`; single-flight refresh with `_retry`-before-queue; ReDoS-safe CSRF cookie regex; no `dangerouslySetInnerHTML`.
- SAML XSW binding, SSRF pinning (4 fetches), TOTP CAS, mTLS CA-status, bootstrap uniqueness, GDPR fatal-on-failure erasure, per-tenant HKDF AMQP signing — all real and tested.
- SDK crypto discipline — constant-time HMAC in all 7 languages, alg-pinned EdDSA JWKS, `Sensitive<T>` redaction, strict-TLS-by-default, CI grep-gates. Do **not** weaken these.

---

## 7. Prioritized remediation order (for the Opus 4.8 planner)

**Tier 1 — correctness of a security control / cross-tenant integrity (do first):**
1. **X-1 (SDK AMQP HMAC, Go+Rust)** — serialize in declaration order; re-test against real server-signed fixtures. The control is currently inoperative in the two reference SDKs.
2. **CQ-B07 cross-tenant edge-strip cluster** (SEC §3 / companion CQ-B50/B52) — add tenant predicates + transactions + `.check()` to `permission.delete`, `group.delete`, `service_account.delete`, `group.remove_member`, `resource.update`.

**Tier 2 — meaningful hardening:**
3. **SEC-067** — redacting `Debug` on `Webhook`/`CreateWebhook` (mirror the federation fix).
4. **SDK-19** — pin PHP `jwks_uri` to https+same-host.
5. **X-2 family** — reject plaintext base URLs across all SDKs (start with TS gRPC `createInsecure`).
6. **CI-03 + CI-04** — dependabot entries + a vuln-scan step per SDK ecosystem; add a committed CodeQL workflow. (Pairs with the user's own dependabot/CodeQL cleanup.)

**Tier 3 — low-risk polish:**
7. SEC-068 (tenant-scope gRPC introspection), SEC-069 (https-only + body cap in `guarded_fetch`), SEC-070 (XFF doc), X-3/X-4/SDK-04/10/11/17 (SDK redaction/redirect/exp-parse hardening).

**Executor note (Sonnet 5):** Tiers 1–2 are localized, test-backed changes — each has an exact anchor and a same-file precedent to copy (`role.delete` for the edge guards, `FederationConfig::fmt` for the Debug redaction, the 5 correct SDKs for the HMAC ordering). Add a regression test with each fix; for X-1 the test **must** use server-signed bytes, not self-generated ones, or it will re-mask the bug.
