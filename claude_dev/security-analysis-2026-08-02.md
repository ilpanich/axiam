# AXIAM — Security Analysis (2026-08-02)

- **Date**: 2026-08-02
- **Server commit**: `7ee7df1` (HEAD of `main`; release `1.0.0-alpha23`). SDKs reviewed at each repo's `1.0.0-alpha23` HEAD.
- **Baseline**: [`final-review-2026-07-08.md`](final-review-2026-07-08.md) + [`remediation-2026-07-08.md`](remediation-2026-07-08.md) (last full code-level review, at `a8e40b3`), the [`security-audit.md`](security-audit.md) compliance index (`c79b66e`), and the [`threat-model-stride.md`](threat-model-stride.md) STRIDE model. Companion public write-up: [`threat-modeling-and-security.md`](threat-modeling-and-security.md).
- **Scope**: (1) re-verification at current HEAD of the security controls that landed *after* the 2026-07-08 review — none of which had a prior code-level review — namely write-behind rate limiting, in-process TLS termination, the authz decision cache, AMQP v2 replay protection, the signed-timestamp webhook scheme, and the org-scope/refresh escalation fixes; (2) the **first-ever security review of the four newest SDKs** — Kotlin, Swift, C and C++ (REST-only, contract §1–§7/§9–§11); (3) confirmation that the 2026-07-08 SDK remediations still hold in the original seven SDKs, plus the two open SDK items (webhook helper, per-SDK dependency hygiene).
- **Method**: multi-agent fan-out with per-item file:line evidence, followed by hand re-verification of both new HIGH-class findings and the two headline backend controls (org_id derivation, atomic refresh). Statuses: ✅ verified sound · 🔶 residual/partial · ❌ finding. New findings continue the review sequence at **SEC-071**.

---

## 1. Executive summary

**The AXIAM server's security posture continues to hold, and the controls added since the last review are correctly implemented.** All eight post-2026-07-08 backend controls verified sound at HEAD, each with a real fail-closed design rather than a comment claiming one. The server's own request path — authentication, session, authorization/tenant-isolation, OAuth2/OIDC, federation, PKI, audit, messaging — carries **no open Critical or High finding**, consistent with the 2026-07-08 conclusion and the STRIDE model. One HIGH release-blocker from the last review, the stale-DB-handle outage (CQ-B48/B45), is **confirmed fixed** in `alpha22` ("hold a live pool reference in repositories, not a boot-time clone").

**The frontier of risk has moved, as expected, to the newest client SDKs.** The four SDKs added since the last review — Kotlin, Swift, C, C++ — had never been security-reviewed. They are disciplined in the ways the original seven are (EdDSA `alg`-pinning before key lookup with `alg:none`/HS-confusion rejected, strict TLS with only a custom-CA dev seam and no verify-disable API, mTLS keys wrapped and never logged, no weak RNG or hardcoded key material, clean C/C++ parsing paths). But the review found **one HIGH** — the C SDK's route-guard helpers accept expired *and* cross-tenant tokens because local verification checks only the signature — and a **cross-tenant acceptance gap in the Swift authenticator**, plus a systemic **plaintext-base-URL gap across all four** (the `X-2` hardening that reached the original seven was never carried to the new ones). These are client-side/relying-party controls, but in an IAM SDK a guard that trusts an expired or foreign-tenant token is precisely the class that matters.

**Two SDK-hygiene items round it out**: the TypeScript SDK's `amqplib` dependency is mis-pinned to a nonexistent major (`^2.0.1`) — a regression of the 2026-07-08 `SDK-Q06` fix that leaves the AMQP dependency unsatisfiable — and **no SDK ships a webhook-signature verifier** (threat-model `T-145`), so every integrator still hand-rolls or skips webhook verification.

### Finding counts (this analysis)

| Severity | Backend | SDK | Total new |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 0 | 1 (SEC-071) | 1 |
| Medium | 0 | 3 (SEC-072, SEC-073, SEC-074) | 3 |
| Low | 0 | 4 (SEC-075, SEC-076, SEC-077, SEC-078) | 4 |

Plus three **backend residual concerns** (§4) — all documented and accepted, none a new finding — and one **still-open** SDK gap (`T-145`, webhook verifier).

### Top remediation priorities

1. **SEC-071** — C SDK: validate `exp` (and bind `tenant_id`) in the route-guard verification path; a guard that accepts expired tokens defeats the 15-minute access-token bound for any resource server using it.
2. **SEC-072** — Swift SDK: assert the configured tenant on every verified session, as the Kotlin SDK's `assertTenant` already does.
3. **SEC-073** — Kotlin/Swift/C/C++: reject a non-`https` base URL at construction (loopback dev exception), matching the original-seven `X-2` fix.
4. **SEC-074 / SEC-075** — ship a safe-by-default exp+tenant authenticator in the C++ SDK; origin-pin the Kotlin discovery `jwks_uri`.
5. **SEC-078** — repin TypeScript `amqplib` to a real `^0.10.x`.
6. **T-145** — add a `verify_webhook(...)` helper with a freshness window to every SDK and state it in `CONTRACT.md`.

---

## 2. Backend controls added since 2026-07-08 — verified at HEAD

Each of these shipped after the last code-level review and had no prior file:line verification. All are sound; evidence is quoted at current-HEAD lines.

| Control | Verdict | Evidence |
|---|---|---|
| **Org-scope escalation fix (NEW-1)** | ✅ | Login derives the authoritative `org_id` from the tenant record and rejects a mismatched client value before minting (`handlers/auth.rs:317-327`); refresh reads `org_id` from `tenant.get_by_id(tenant_id).organization_id`, never the request body (`auth.rs:451-462`); `token::issue_access_token` only ever stamps the server-derived value (`token.rs:96-138`). MFA challenge/setup tokens embed the same derived `org_id`. |
| **Refresh single-use atomicity (NEW-3)** | ✅ | `SessionRepository::consume` is an atomic `DELETE … WHERE tenant_id=$tid RETURN BEFORE` returning whether *this* call won (`repository/session.rs:195-214`); `AuthService::refresh` aborts on a lost race **before** minting the new session/tokens (`service.rs:582-590`). No forked lineage, stolen-token reuse stays detectable. |
| **Write-behind shared rate limiter** | ✅ | Synchronous in-memory decision with a background coalescing flush, no DB write on the request path (`rate_limit_counter.rs:500-527,740-761`). XFF uses rightmost-untrusted with `peer_addr()` fallback when `trusted_hops ≥ hops` (`extractors/rate_limit.rs:71-93`). **`limit=0` denies regardless of store reachability** (fail-closed, `:522`). The one deliberate fail-open (no derivable key / `SHARED=off`) is isolated and documented (`middleware/rate_limit_shared.rs:334-353`). |
| **In-process TLS listener** | ✅ | rustls **TLS 1.3-only** via `with_protocol_versions(&[&TLS13])` (`tls.rs:391-393`); fails startup on missing/unreadable/mismatched cert or key (`tls.rs:331-413`) and **never falls back to plaintext** — the plaintext `bind` is only reached in the TLS-disabled branch (`main.rs:1239-1256`). Native mTLS terminates in-process with no trusted proxy-header identity. |
| **AMQP v2 replay protection** | ✅ | Per-message `nonce`+`issued_at` are always inside the signed body (`messages.rs:186-192,234-240`); freshness window (`is_fresh`, `:86-88`) + per-tenant nonce dedup (`authz_consumer.rs:129-154`) with a store error failing closed to `NackDrop`; `key_version ≥ 2` hard-required (`messages.rs:52`, no v1 grace); per-tenant HKDF-SHA256 subkey (`derive_tenant_key`, `:101-111`); signing mandatory in release (`config.rs:77-97`, `main.rs:840-843`). |
| **Signed-timestamp webhooks** | ✅ | `X-Axiam-Signature: t=<unix>,v1=<hex>` = HMAC-SHA256 over `<timestamp>.<body>` (`webhook.rs:308-317`); delivery through resolve-and-pin `guarded_fetch(allow_private=false)` (`:264`); secret AES-256-GCM at rest (`:151-157`, encrypted on create/rotate, fail-closed on missing key); redacting `Debug` on `Webhook`/`CreateWebhook`/`UpdateWebhook` plus `skip_serializing` and a response DTO (`models/webhook.rs:43,53-118`). |
| **Federation SSRF guard (four fetches)** | ✅ | `guarded_fetch` enforces `https` on every hop incl. redirects (`ssrf.rs:180-182`, redirect hops never get the private allowance), resolve-and-pin (`:110-147`), body caps by `Content-Length` + streaming cap (`:210-254`), `MAX_HOPS=3`. Applied to JWKS (`jwks_cache.rs:255`), token exchange (`oidc.rs:448`), SAML metadata (`saml.rs:145`), discovery (`discovery_cache.rs:206`). |
| **Authz decision-cache invalidation** | ✅ | Key = tenant + subject + resource + action + scope (`decision_cache.rs:163-180,387-391`); access-narrowing mutations call `invalidate_subject`/`invalidate_tenant` across roles/groups/permissions/scopes/resources handlers (not just TTL); 5 s TTL is a backstop only. |

**Also confirmed fixed since the last review:** the stale-DB-handle undetectable-outage HIGH (`CQ-B48`/`CQ-B45`) — repositories now hold a live `DbHandle` over the pool slot and resolve the current connection per query (`alpha22` changelog; connection module).

---

## 3. New findings — client SDKs

The four newest SDKs are REST-only relying-party clients. The findings below are in their **local token-verification and transport-construction** paths — the client-side face of controls the server enforces correctly.

### SEC-071 [HIGH] ❌ — C SDK route guards accept expired and cross-tenant tokens

- **File**: `axiam-c-sdk/src/guard.c:41-63` (`verify_and_claims` → `axiam_require_auth`/`require_access`/`require_role`), `src/jwks.c:100-194` (`axiam_jwt_verify`).
- **Defect**: `axiam_jwt_verify` correctly pins `alg=EdDSA` before key lookup (`jwks.c:126-137`) and verifies the Ed25519 signature (`:161-179`), then returns the raw claims JSON — but performs **no `exp`/`nbf` check and no `tenant_id` assertion** (verified by hand: there is no expiry or tenant logic anywhere in `jwks.c` or `guard.c`). The shipped guards call this and treat any signature-valid token as authenticated: `require_auth` returns `ALLOW`, `require_role` matches roles from the unvalidated claims, and `require_access` runs its server-side authz check only *after* admitting the token.
- **Impact**: a resource server that protects its endpoints with the C SDK guards accepts (a) an **expired** AXIAM access token — defeating the 15-minute lifetime that bounds stolen-token exposure, indefinitely — and (b) a token minted for a **different tenant in the same organization**, because the JWKS trust anchor is org-wide and nothing binds the token's `tenant_id` to the client's configured tenant. This is the exact `exp`/tenant discipline the Kotlin SDK enforces (`assertTenant`; Swift enforces `exp` at least).
- **Fix**: in the guard's verification path (or in `axiam_jwt_verify` behind a strict flag used by the guards), reject when `exp ≤ now` (small skew) and when the token's `tenant_id` claim ≠ the client's configured tenant. Add negative tests for an expired token and a foreign-tenant token.

### SEC-072 [MEDIUM] ❌ — Swift `AxiamRequestAuthenticator` does not bind the session to the configured tenant

- **File**: `axiam-swift-sdk/Sources/AxiamSDK/Guard/AxiamRequestAuthenticator.swift:64-73`.
- **Defect**: `exp` *is* enforced (`:54`), and the JWKS URL is origin-derived from the configured base — both good. But the tenant check only fires when the request carries an `X-Tenant-ID` header **and** the token has a `tenant_id` claim **and** they differ; the client's configured `tenantID` is used only as a fallback field value (`:73`), never as an assertion. With an org-wide JWKS, a validly-signed token from another tenant is accepted whenever the request omits `X-Tenant-ID` (or presents a matching pair).
- **Impact**: cross-tenant token acceptance on a Swift-guarded resource server — a narrower version of SEC-071 (bounded by the enforced `exp`).
- **Fix**: assert `token.tenant_id == configured tenantID` on every verified session, mirroring the Kotlin SDK's `assertTenant` (`JwksVerifier.kt:258-267`). Add a cross-tenant negative test.

### SEC-073 [MEDIUM] ❌ — All four new SDKs accept a plaintext `http://` base URL at construction

- **File**: Kotlin `AxiamClient.kt:546-556`, Swift `AxiamConfig.swift:37-65`, C `config.c:86-89`, C++ `client.cpp:272-303`.
- **Defect**: each validates non-empty `base_url`/tenant but never checks the URL scheme, and the base URL is used verbatim to build requests. TLS is strict *when `https` is used*, but a misconfigured `http://` (or `grpc://`/`amqp://` where applicable) base sends login credentials, bearer cookies, CSRF and tenant headers in cleartext with no error. This is the `X-2` finding that was fixed in the Rust/TS SDKs (`ensure_secure_scheme`, gRPC `allowInsecure` opt-in) but never carried to the four new ones.
- **Impact**: silent transport downgrade — threat-model `T-23` on the new SDKs. Contract §6 requires rejecting non-`https` at construction (loopback dev exception).
- **Fix**: reject a non-`https` base URL at construction in all four (allow-list loopback for dev), one small change per SDK.

### SEC-074 [MEDIUM] ❌ — C++ SDK ships a signature-only `verify()` with no safe-default exp/tenant authenticator

- **File**: `axiam-cplusplus-sdk/src/jwks.cpp:140-178`, `include/axiam/guard.hpp`.
- **Defect**: `verify()` pins EdDSA and checks the signature but returns the payload with **no `exp`/`iss`/`aud`/`tenant` checks** (documented in `jwks.hpp:5-6,43`), and the SDK ships no §10 authenticator that adds them — `guard.hpp` operates on an already-built `AxiamUser` and never verifies a token. So the only bundled primitive is signature-only, and an integrator wiring it into a request guard will accept expired/cross-tenant tokens unless they hand-add the checks. Same underlying gap as SEC-071 but presented as a documented primitive rather than a shipped guard.
- **Fix**: add a safe-by-default authenticator that verifies signature **and** `exp` **and** the configured tenant, and make it the documented entry point; keep the raw primitive clearly labelled.

### SEC-075 [LOW/MEDIUM] ❌ — Kotlin discovery `jwks_uri` not constrained to the issuer origin

- **File**: `axiam-kotlin-sdk/src/main/kotlin/io/axiam/sdk/oidc/OidcSupport.kt:565,595-597`; `JwksVerifier.forJwksUri`.
- **Defect**: Kotlin is the one new SDK doing OIDC discovery; the discovered `jwks_uri` is followed without constraining it to the configured issuer/base-URL origin. Mitigated because discovery is fetched over strict TLS from the configured base URL, so it is defense-in-depth rather than an active break — but it is the `SDK-19` class (first seen in the PHP SDK, since fixed there with a same-origin-https check).
- **Fix**: require the discovered `jwks_uri` be `https` and same-origin as the base URL, else fall back to `{baseUrl}/oauth2/jwks` — exactly the PHP SDK's fix.

### SEC-076 [LOW] ❌ — C and C++ SDKs store MFA challenge/setup tokens as plain strings

- **File**: C `include/axiam/client.h:44-45` (`challenge_token`/`setup_token`), C++ `include/axiam/types.hpp:36` (`LoginResult.challenge_token`).
- **Defect**: contract §7 classes the MFA challenge token as a secret; the Kotlin and Swift SDKs wrap it in `Sensitive`, but C/C++ leave it as a plain `char*`/`std::string`. No auto-logging path exists today, so severity is low, but it is an inconsistency that removes the redaction safety-net the other SDKs have.
- **Fix**: wrap the challenge/setup tokens in the SDK's `Sensitive` type (and zeroize on free in C, as the SDK already does for the mTLS key).

### SEC-077 [LOW] ❌ — Swift `Sensitive` uses a non-constant-time equality

- **File**: `axiam-swift-sdk/Sources/AxiamSDK/Sensitive.swift:28-32` — `Equatable` via plain `lhs.value == rhs.value` over secret material. The Kotlin SDK deliberately does *not* override equality for exactly this reason. Low severity (few call sites compare secrets), but worth a constant-time compare.

### SEC-078 [LOW] ❌ — TypeScript SDK `amqplib` pinned to a nonexistent major (SDK-Q06 regression)

- **File**: `axiam-typescript-sdk/package.json:118` — `"amqplib": "^2.0.1"`, while `@types/amqplib` is `^0.10.8` (`:150`). amqplib has no 2.x line (real releases top out at 0.10.x), so the runtime dependency is **unsatisfiable** as pinned. The 2026-07-08 remediation claimed this was corrected to `^0.10.x`; it is not, at HEAD.
- **Impact**: the AMQP transport can't install cleanly; a resolver that ignores the bad range could pull an unexpected artifact. Reliability/supply-chain hygiene rather than an exploit.
- **Fix**: repin to a real `^0.10.x` matching `@types/amqplib`; add a `postinstall`/CI lockfile-resolve gate so an unsatisfiable pin fails the build.

---

## 4. Backend residual concerns (documented / accepted — not new findings)

These surfaced during verification of recently-added code. All are already documented or are accepted trade-offs; none is a new finding, and all are noted here for completeness and future scheduling.

1. **Pre-auth `client_id` rate-limit keying** (`middleware/rate_limit_shared.rs:301-318`, `extractors/rate_limit.rs:150-155`). In `AXIAM__RATE_LIMIT__KEY=client_id` mode the bucket key is read from the raw form body **before** the credential check, so a caller rotating `client_id` values mints fresh buckets on `/oauth2/{token,introspect,revoke}`. This is documented in the Configuration guide's security caveat (the shipped default is `ip`, which an attacker cannot mint), mitigated by `ip_client_id` and the per-replica governor, and intended only where an edge (mTLS/gateway/WAF) already authenticates callers. Config-dependent, low–medium; no change recommended beyond the existing loud documentation.

2. **Multi-replica decision-cache stale-allow window** (`decision_cache.rs:47-74`). Invalidation is process-local with no cross-replica channel, so on a replica that did not handle the mutation a revoked grant can remain `Allow` for up to `decision_cache_ttl_secs` (default 5 s). This is the documented, accepted bounded-staleness trade-off of the cache (threat-model `T-88`), enabled opt-in; the TTL bounds it. Deployments needing immediate cross-replica revocation should use gRPC introspection.

3. **Access-token audience narrowing — confirm downstream** (`token.rs:343-351`). `decode_access_token` accepts both `axiam:user` and `axiam:m2m` audiences and does not require `aud` at the token layer, deferring per-route audience separation to the REST extractor (`extractors/auth.rs`, per the SEC-006 resolution). This is by design *provided* the extractor narrows audience per route; it predates this review window and was not re-derived end-to-end here. **Recommendation**: add/keep a regression test asserting an `axiam:m2m` token is rejected on a user route (and vice-versa) so this intentional token-layer permissiveness stays backed by an enforced downstream check.

---

## 5. Original-seven SDKs — 2026-07-08 remediations still hold

Re-verified at `alpha23`; the fixes from [`remediation-2026-07-08.md`](remediation-2026-07-08.md) are present:

- **AMQP HMAC declaration-order (SDK-Q01/X-1)** ✅ — Go canonicalises via declaration-order structs; Rust uses `serde_json` `preserve_order` + `shift_remove`. Field order matches the server (`correlation_id, tenant_id, subject_id, action, resource_id, scope, key_version, nonce, issued_at`).
- **AMQP §8 v2 replay fields** ✅ — nonce + `issued_at` + `key_version ≥ 2` supported in **all seven** consumers (Rust/Go/Python/TS/Java/C#/PHP), each with a freshness skew and a nonce store.
- **Rust authz CSRF (SDK-Q04)** ✅ — `send_authz_post` forwards `X-CSRF-Token` (`rest/authz.rs:195`).
- **TS Node client (SDK-Q05)** ✅ — `createNodeClient` + injectable tough-cookie jar. **SDK-Q06** ❌ — `amqplib` mis-pin persists → **SEC-078** above.
- **PHP JWKS pin (SDK-19)** ✅ — discovered `jwks_uri` honoured only when same-origin https, else fallback to `{baseUrl}/oauth2/jwks`.
- **Plaintext base URL rejection (X-2)** ✅ — Rust (`ensure_secure_scheme`, + redirect scheme-downgrade guard) and TS gRPC (`allowInsecure` opt-in). *(Not carried to the four new SDKs → SEC-073.)*
- **Header redaction allowlist (X-3)** ✅ — TS/Python/Go/Java/C# all use a safe-header allowlist, not the old 3-entry denylist.

**Still open — `T-145` (webhook-signature verifier).** No SDK — original seven or new four — ships a `verify_webhook(secret, timestamp_header, signature_header, body)` helper for the server's signed-timestamp scheme. Every integrator hand-rolls or skips verification. The server-side control is complete; the gap is purely on the client side. **Fix**: add the helper (HMAC-SHA256 over `<timestamp>.<body>`, constant-time compare, freshness window on `t`, dedup on `X-Axiam-Delivery`) to each SDK and state the expectation in `CONTRACT.md`.

---

## 6. Alignment with the STRIDE threat model

The threat model ([`threat-model-stride.md`](threat-model-stride.md)) records 149 threats, 22 open. This analysis is consistent with it and refines two SDK-surface items:

- The model marks `T-23` (SDK transport downgrade) and the SDK-integration diagram broadly **mitigated** via CONTRACT §6. That holds for the original seven; **SEC-073** shows the four new SDKs do not yet reject a plaintext base URL, so `T-23` is **partial** for them until fixed.
- `T-142` (SDK JWKS-from-discovery) is mitigated per §12; **SEC-075** is the same class re-appearing in the Kotlin SDK (defense-in-depth, TLS-mitigated).
- `T-145` (no SDK webhook verifier) is confirmed **still open**, unchanged.
- SEC-071/072/074 are new **local relying-party verification** items on the REST-guard surface (`T-143` neighbourhood — local verification vs. server truth); they do not change the server-side threat verdicts, which remain sound.

The model's 22 open items are otherwise unchanged and correctly characterised: accepted design trade-offs (no deny-override `T-16`/`T-87`, 15-min token revocation lag `T-39`, append-only audit vs. erasure `T-110`/`T-118`), deployment responsibilities (`T-9`, `T-18`, `T-124`, `T-125`, `T-131`, `T-132`, `T-133`, `T-134`, `T-129`, `T-119`), and SDK/distribution gaps (`T-135`, `T-146`, `T-148`, `T-145`, `T-143`).

---

## 7. Prioritized remediation order

**Tier 1 — SDK auth-verification correctness (do first):**
1. **SEC-071** — C SDK guards: enforce `exp` + tenant binding in local verification. (HIGH.)
2. **SEC-072** — Swift authenticator: assert the configured tenant on every session.
3. **SEC-074** — C++ SDK: ship a safe-by-default exp+tenant authenticator, not just a signature primitive.

**Tier 2 — transport & discovery hardening:**
4. **SEC-073** — reject non-`https` base URLs across Kotlin/Swift/C/C++ (loopback exception).
5. **SEC-075** — origin-pin the Kotlin discovery `jwks_uri`.
6. **T-145** — add `verify_webhook(...)` to every SDK + a `CONTRACT.md` clause.

**Tier 3 — hygiene & polish:**
7. **SEC-078** — repin TS `amqplib` to `^0.10.x` + a lockfile-resolve CI gate.
8. **SEC-076** — wrap C/C++ MFA tokens in `Sensitive`. **SEC-077** — constant-time compare in Swift `Sensitive`.
9. Backend residual §4.3 — add the audience-narrowing regression test if not already present.

**Executor note.** Every Tier 1–2 item has a same-family precedent to copy: the Kotlin SDK's `assertTenant` and `exp` enforcement for SEC-071/072/074, the Rust/TS `ensure_secure_scheme`/`allowInsecure` for SEC-073, and the PHP SDK's same-origin-https `jwks_uri` check for SEC-075. Land each fix with a negative test (expired token, foreign-tenant token, `http://` base URL).

---

## 8. Coverage & confidence

- **Backend**: the eight post-2026-07-08 controls were each verified with current-HEAD file:line evidence; the two headline items (org_id derivation, atomic refresh) were re-derived by hand end-to-end. Not re-run locally: the full `axiam-server` binary build and `cargo audit` (swagger-ui offline placeholder + tool availability in this sandbox — rely on CI, which gates both). The earlier reviews' sound controls (PKCE S256-only, OAuth2 atomic single-use, JWT audience blocks, parameterised SurrealQL, PKI/mTLS, GDPR erasure durability) were not re-audited this round and are assumed to hold, no source having regressed them per the changelog.
- **SDKs**: the four new SDKs were reviewed across strict-TLS/no-bypass, plaintext-URL rejection, secret redaction, JWKS/token verification, weak-crypto/RNG, mTLS handling and (C/C++) memory safety. SEC-071 was confirmed by directly reading `guard.c` and `jwks.c` (no `exp`/tenant logic present). The original seven were spot-verified against the 2026-07-08 remediation list; the `amqplib` mis-pin (SEC-078) was confirmed firsthand.
- **Lower-confidence residual**: the backend §4.3 audience-narrowing path was not traced into the extractor this round; the multi-replica cache-staleness bound rests on the documented single-process invalidation model. Both are flagged for a future targeted pass rather than asserted closed.
