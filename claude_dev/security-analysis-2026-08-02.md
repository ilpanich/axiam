# AXIAM — Security Analysis (2026-08-02)

- **Date**: 2026-08-02
- **Server commit**: `7ee7df1` (HEAD of `main`; release `1.0.0-alpha23`). SDKs reviewed at each repo's `1.0.0-alpha23` HEAD.
- **Baseline**: [`final-review-2026-07-08.md`](final-review-2026-07-08.md) + [`remediation-2026-07-08.md`](remediation-2026-07-08.md) (last full code-level review, at `a8e40b3`), the [`security-audit.md`](security-audit.md) compliance index (`c79b66e`), and the [`threat-model-stride.md`](threat-model-stride.md) STRIDE model. Companion public write-up: [`threat-modeling-and-security.md`](threat-modeling-and-security.md).
- **Scope**: (1) re-verification at current HEAD of the security controls that landed *after* the 2026-07-08 review — none of which had a prior code-level review — namely write-behind rate limiting, in-process TLS termination, the authz decision cache, AMQP v2 replay protection, the signed-timestamp webhook scheme, and the org-scope/refresh escalation fixes; (2) the **first-ever security review of the four newest SDKs** — Kotlin, Swift, C and C++ (REST-only, contract §1–§7/§9–§11); (3) confirmation that the 2026-07-08 SDK remediations still hold in the original seven SDKs, plus the two open SDK items (webhook helper, per-SDK dependency hygiene).
- **Method**: multi-agent fan-out with per-item file:line evidence, followed by hand re-verification of both new HIGH-class findings and the two headline backend controls (org_id derivation, atomic refresh). Statuses: ✅ verified sound · 🔶 residual/partial · ❌ finding. New findings continue the review sequence at **SEC-071**.
- **Remediation status**: every finding in this document has since been fixed. See **[§9 Remediation status](#9-remediation-status-2026-08-02)** for the per-finding record, the commits, the two deliberate fail-closed breaking changes, and a correction to the SEC-078 premise below.
- **Independent re-verification (2026-08-03)**: §9 was written by the remediation itself, so every claim was re-derived from source by an independent reviewer at `f77ad2a9` — **8/8 findings and `T-145` confirmed**, one partial (SEC-072's expiry half → **SEC-080**). That pass also reviewed two commits that landed after §9 and had never been security-reviewed (authz query rewrites + session-validation cache; rate-limit units/defaults), yielding **SEC-079**. See **[§10](#10-independent-re-verification-pass-2026-08-03)**.

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

> **Status as of 2026-08-02: all eight findings fixed and `T-145` closed across all eleven SDKs.** The §4.3 residual is now traced and pinned by regression tests. Two of the fixes are deliberately **fail-closed in a way that rejects previously-accepted tokens** — see [§9.3](#93--two-deliberate-fail-closed-breaking-changes). The SEC-078 premise as originally written was **incorrect** and is corrected in place in §3.
>
> **Re-verified independently on 2026-08-03 (§10): confirmed, with one partial and two new findings.** SEC-071/073/074/075/076/077/078 and `T-145` (11/11 SDKs) hold up against source. SEC-072's tenant binding is solid but its expiry check still admits a token carrying **no** `exp` claim (**SEC-080**, Low). Reviewing the two commits that landed *after* §9 found the authz query rewrites and the new session-validation cache sound, and one new **Medium** — the gRPC rate-limit units fix raised the effective per-IP ceiling on the Argon2id `ValidateCredentials` RPC by **60×** (**SEC-079**).

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

### SEC-078 [LOW] ❌ — TypeScript SDK `amqplib` mis-pinned across a major line (SDK-Q06 regression)

> **⚠ Premise corrected during remediation (2026-08-02).** As originally written this
> finding stated that "amqplib has no 2.x line (real releases top out at 0.10.x), so the
> runtime dependency is **unsatisfiable** as pinned." **That is false.** The registry was
> checked directly during remediation (`npm view amqplib versions`): amqplib published
> 1.x and 2.x releases between 2026-03 and 2026-05, and `^2.0.1` resolves cleanly — a
> clean `npm ci` on the unmodified tree installed and typechecked without error. The
> finding is still real, but the defect is a different one; the corrected statement is
> below. The original text is preserved above the fold for audit continuity.

- **File**: `axiam-typescript-sdk/package.json:118` — `"amqplib": "^2.0.1"`, while `@types/amqplib` is `^0.10.8` (`:150`).
- **Actual defect**: `amqplib@2.x` is a rewrite that ships its own bundled `index.d.ts` (zero dependencies), whereas `@types/amqplib` was never updated past `0.10.8`. Pinning the runtime package to 2.x therefore **silently orphans the vendored types package**: the two describe different APIs, and nothing fails loudly. This is a type/runtime divergence, not an install failure.
- **Impact**: type checking validates against an API the installed runtime may not implement. Reliability/supply-chain hygiene rather than an exploit — but the *silent* nature makes it worse than the unsatisfiable pin originally described, which would at least have failed the install.
- **Fix**: repin to a real `^0.10.x` matching `@types/amqplib`; add a CI lockfile-resolve gate so a future divergence fails the build.

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

**~~Still open~~ → ✅ CLOSED 2026-08-02 — `T-145` (webhook-signature verifier).** *As reviewed:* no SDK — original seven or new four — shipped a `verify_webhook(secret, timestamp_header, signature_header, body)` helper for the server's signed-timestamp scheme, so every integrator hand-rolled or skipped verification. The server-side control was complete; the gap was purely client-side. **Now fixed in all eleven SDKs**, with `CONTRACT.md` §13 made normative — see [§9.2](#92-t-145--webhook-verifier-all-eleven-sdks) for commits and the cross-SDK vector check.

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

> **✅ All tiers below were completed on 2026-08-02** on branch
> `claude/axiam-fixes-optimization-4qymzu`. This section is retained as the plan of record;
> [§9](#9-remediation-status-2026-08-02) is the outcome of record.

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
- **Lower-confidence residual**: the backend §4.3 audience-narrowing path was not traced into the extractor this round; the multi-replica cache-staleness bound rests on the documented single-process invalidation model. Both are flagged for a future targeted pass rather than asserted closed. *(§4.3 has since been traced and pinned — see §9.)*

---

## 9. Remediation status (2026-08-02)

All eight findings (SEC-071 … SEC-078) and the standing `T-145` gap were remediated on
branch `claude/axiam-fixes-optimization-4qymzu` across the server repo and all eleven SDK
repos. Every fix landed with the negative tests the §7 executor note required.

### 9.1 Per-finding record

| ID | Severity | Repo | Status | Commit | What landed |
|---|---|---|---|---|---|
| **SEC-071** | HIGH | `axiam-c-sdk` | ✅ Fixed | `6698c48` | `axiam_jwt_verify` became `axiam_jwt_verify_ex(..., AXIAM_JWT_VERIFY_STRICT, ...)` — **safe by default**, with opt-out flags (`SIGNATURE_ONLY`/`EXPIRY`/`TENANT`) and `AXIAM_JWT_CLOCK_SKEW_SECS 60`. `exp` is mandatory and numeric, `nbf` honoured when present, `tenant_id` must equal the configured tenant. Every failure returns `AXIAM_ERR_AUTH` → 401 and the authz server is **never consulted**. 15 new claim tests. |
| **SEC-072** | MEDIUM | `axiam-swift-sdk` | ✅ Fixed | `41b05f2` | `AxiamRequestAuthenticator` now asserts the configured tenant on **every** verified session (matching against `tenantID` or `tenantSlug`), not only when an `X-Tenant-ID` header is present. Cross-tenant negative test added; `exp` enforcement unchanged. |
| **SEC-073** | MEDIUM | Kotlin, Swift, C, C++ | ✅ Fixed | `8018b93`, `41b05f2`, `6698c48`, `e28874e` | Non-`https` base URL rejected at construction in all four, with a loopback dev exception (`localhost`/`127.0.0.1`/`::1`). Matched on **string literals, never DNS-resolved**, so a hostile name resolving to loopback cannot slip through. The C implementation also parses URL userinfo, so `http://localhost@evil.example` is refused. Negative + positive tests in each. |
| **SEC-074** | MEDIUM | `axiam-cplusplus-sdk` | ✅ Fixed | `e28874e` | New safe-by-default authenticator verifying signature **and** `exp` (named skew, `nbf` honoured) **and** configured tenant; it is now the documented guard entry point. The raw primitive was renamed `verify_signature_only_unchecked()` so it cannot be reached by accident. |
| **SEC-075** | LOW/MED | `axiam-kotlin-sdk` | ✅ Fixed | `8018b93` | Discovered `jwks_uri` must be absolute `https` and same host+port as the configured base URL; anything else (cross-origin, relative, plaintext) falls back to `{baseUrl}/oauth2/jwks` — the PHP `SDK-19` fix. The test points the cross-origin URI at an **unreachable** host, so it fails if the pin ever stops working rather than passing by coincidence. |
| **SEC-076** | LOW | C, C++ | ✅ Fixed | `6698c48`, `e28874e` | MFA `challenge_token`/`setup_token` wrapped in the SDK `Sensitive` type. C additionally scrubs the plaintext out of parsed JSON and request bodies before free, and replaces an elidable `memset` with a volatile-write `axiam_secure_zero()`. |
| **SEC-077** | LOW | `axiam-swift-sdk` | ✅ Fixed | `41b05f2` | `Sensitive` equality is now constant-time. Went further than the finding asked: `Equatable` is constrained to a new `ConstantTimeComparable` protocol (`String`, `Data`, `[UInt8]`) so no wrapped type can silently fall back to a short-circuiting compare. `Hashable` was deliberately **not** added — hashing secret material invites `Set`/dictionary use, whose lookup is hash-bucketed and not constant time. |
| **SEC-078** | LOW | `axiam-typescript-sdk` | ✅ Fixed | `cd2402f` | `amqplib` repinned `^2.0.1` → `^0.10.9` (verified against the live registry), lockfile regenerated, and an `npm ls amqplib` gate added to `sdk-ci-typescript.yml` after `npm ci`. **See the corrected premise in §3** — the original "unsatisfiable pin" diagnosis was wrong. |
| **T-145** | Gap | all 11 SDKs | ✅ Closed | see §9.2 | `verify_webhook(...)` shipped in every SDK against one canonical spec, plus **CONTRACT.md §13** normative in all twelve repos. |
| **§4.3 residual** | Residual | `axiam` | ✅ Pinned | `a15b78d` | The audience-narrowing regression tests already existed (`rejects_axiam_m2m_audience_on_user_route`, `service_account_extractor_rejects_user_token`). Rather than duplicate them, two tests were added that pin the whole §4.3 contract in one place: `token_layer_accepts_both_audiences_but_routes_narrow_in_both_directions` and `missing_aud_is_never_accepted_on_an_m2m_route` (the latter proves the `allow_missing_aud_as_user` back-compat window cannot leak onto an m2m route, for both flag values). The residual noted in §8 is now traced and closed. |

### 9.2 T-145 — webhook verifier, all eleven SDKs

To keep every implementation byte-compatible with the server signer
(`crates/axiam-api-rest/src/webhook.rs`, `compute_signature_v2`), one canonical spec was
derived from that code and handed to every implementation, and **CONTRACT.md §13** was
made normative: HMAC-SHA256 over `<timestamp>.<raw_body>`; `t=` taken verbatim from the
header (not reformatted from a parsed integer); constant-time comparison on **decoded**
MAC bytes; a header carrying no `v1` is always a failure, never a silent pass; multiple
`v1` values accepted for secret rotation; a **two-sided** freshness window defaulting to
300 s so future-dated timestamps are rejected like stale ones; fail-closed on malformed
hex; and an error surface that never carries the secret or the expected MAC.

| SDK | Commit | | SDK | Commit |
|---|---|---|---|---|
| Rust | `415961e` | | Kotlin | `8018b93` |
| TypeScript | `cd2402f` | | Swift | `41b05f2` |
| Python | `b00d78c` | | C | `6698c48` |
| Java | `47c9879` | | C++ | `e28874e` |
| C# | `3ae1205` | | PHP | `bbe09ec` |
| Go | `2ee34ba` | | | |

**Cross-SDK pin verified, not assumed.** The §13.4 shared vector (`whsec_test_0123456789abcdef`,
`t=1785700000`) produces `a642d9201b6f99c4e4e86f03cdedf1592a277f97c14ba936d78f37cb14c5d720`,
confirmed identical between independent PHP and Python computations. Each SDK computes the
vector in test setup rather than hardcoding the hex, so the pin cannot drift into a
tautology.

### 9.3 ⚠ Two deliberate fail-closed breaking changes

Both fall directly out of the tenant-binding fixes and **will reject tokens that previously
succeeded**. This is the vulnerability being closed, not a regression — but it warrants
release-note prominence rather than a CHANGELOG line, because it can break working
deployments on upgrade.

1. **A guard-side C or Swift client must now be configured with the tenant UUID.** Access
   tokens carry the tenant **UUID** in `tenant_id`; a client configured only with a tenant
   **slug** has nothing to compare against, so it now refuses *every* token. C falls back to
   the UUID resolved at login (D-14) when available and fails closed otherwise; Swift accepts
   a match against either configured identifier. Deployments relying on a guard that admitted
   tokens without tenant configuration were relying on SEC-071/SEC-072.
2. **Source-breaking type changes.** C: `challenge_token`/`setup_token` are now
   `axiam_sensitive_t *` (new `axiam_verify_mfa_sensitive()`). C++: `LoginResult::challenge_token`
   is `Sensitive<std::string>` and `JwksVerifier::verify()` is renamed
   `verify_signature_only_unchecked()`. Swift: `Sensitive`'s `Equatable` conformance narrowed
   to `ConstantTimeComparable`.

### 9.4 New observations from the remediation pass

Neither is a finding against this review's scope; both were discovered while fixing the above
and are recorded so they are not lost.

- **OBS-1 — client-secret hashing is unsalted single-round SHA-256** (`crates/axiam-db/src/repository/service_account.rs:36-40`, consumed at `crates/axiam-oauth2/src/token.rs:199,408,551,851`). Found while establishing that the client-credentials path is *not* Argon2-bound. **Severity: informational, not a finding.** Every client secret is 32 CSPRNG bytes (256-bit) from `generate_client_secret()` at both creation and rotation, and there is no operator-supplied-secret path — so brute-force and rainbow-table attacks are infeasible and the missing salt has no practical consequence, the same posture GitHub and Stripe use for API tokens. The comparison is already constant-time (`ct_eq`). **It would become a real finding the moment an operator-supplied or low-entropy client secret is accepted anywhere**; if that is ever added, this must move to a salted KDF at the same time. Worth an explicit code comment recording the entropy assumption.
- **OBS-2 — C++ SDK `CURLOPT_CUSTOMREQUEST` was sticky across reused handles** (fixed in `e28874e`). After any POST, every subsequent GET on the same easy handle inherited the previous verb, silently turning the JWKS fetch into `POST /oauth2/jwks` — which a conformant server answers `405`. This is a reliability bug rather than a vulnerability, but it is recorded here because the **SEC-074 authenticator depends on that fetch**: the security fix would have failed in production against a real server had this not been caught. Now reset per request, with a regression test.

### 9.5 Verification depth

Fixes were verified with each repo's own CI gates, run locally where the toolchain permitted:

- **C** — 23/23 tests under gcc *and* clang, clean under ASan+UBSan, **valgrind across all 22 binaries: 0 errors, 0 definite leaks**, coverage 98.7% line / 82.7% branch (gates: 96/80).
- **C++** — 103 test cases / 359 checks under g++ and clang++, clean under ASan+UBSan with leak detection, 98.81% line coverage. Transport fixes were **falsification-tested**: each fix was reverted to confirm its test fails, then restored.
- **Swift** — a real Swift 5.10.1 toolchain matching CI was downloaded; `swift build` clean, 92 tests / 0 failures (up from 63), 96.32% line coverage vs a 92% floor.
- **Kotlin** — `./gradlew build` green at 247/247, `koverVerify` clearing the 98% line floor.
- **Java** — `mvn verify` BUILD SUCCESS at 373 tests, JaCoCo floor met, D-22 doclint gate passing.
- **Go** — `build`/`vet`/`test` green, webhook package 98.3% coverage, `golangci-lint` clean. *`govulncheck` could not be installed (module-proxy timeout) and did not run.*
- **TypeScript** — typecheck clean, 495 tests passing, build + publish dry-run OK, `npm audit` 0 high.
- **Python** — `mypy --strict` clean, 480 tests, 98.94% coverage (webhook module 100%).
- **Rust SDK** — `fmt`, `clippy --all-targets --all-features -D warnings`, `cargo doc -D warnings` all pass; 33/34 suites, 0 failures (the exception, `tests/trybuild.rs`, fails byte-identically on unmodified `HEAD` — a trybuild/rustc toolchain interaction, not a regression).
- **C#** — repo CI gates run locally.
- **PHP** — ⚠ **PHPUnit and PHPStan could not be run**: `composer install` cannot authenticate to github.com through this environment's proxy. Compensating verification: `php -l` clean on all files, and the real classes were driven directly through every §13.4 required case (**20/20**, including tampered body, wrong secret, stale/future timestamps, tolerance boundary, all malformed-header shapes, secret rotation, and an assertion that error messages leak neither secret nor MAC), plus the cross-SDK vector cross-checked against Python. Repository CI is the first execution of PHPUnit and PHPStan level 6 for this change.

---

## 10. Independent re-verification pass (2026-08-03)

- **Server commit**: `f77ad2a9` (HEAD of `main`, PR #255). SDKs at their latest merged HEADs (`6e9e9bd` C, `705fff0` Swift, `4620a35` C++, `ec71d98` Kotlin, `babf8d2` TS, `80287ac` Rust, `d236f9f` Go, `07d7ba0` Python, `d0b7ed5` Java, `26629c5` C#, `741649d` PHP).
- **Why this pass exists**: §9 was written by the remediation work itself. A self-reported "all fixed" is a claim, not evidence, so every item was re-derived from source by an independent reviewer. Separately, two commits landed after §9 that **change security behaviour and had never been security-reviewed** — `421e3e2a` (authorization hot-path query rewrites + a new session-validation cache) and `a15b78d0` (rate-limit units/scoping/defaults).
- **Result**: the §9 remediation claims hold — **8 of 8 findings and `T-145` confirmed fixed**, with **one partial** (SEC-072's expiry half). The backend review found the authz rewrites and the session cache sound, and surfaced **one new MEDIUM** in the rate-limit commit. New findings continue at **SEC-079**.

### 10.1 Verification of the §9 remediation claims

| ID | Claim | Independent verdict |
|---|---|---|
| **SEC-071** | C guards verify `exp` + tenant, safe by default | ✅ **CONFIRMED** (verified by hand). `guard.c:54` calls `axiam_jwt_verify_ex(..., AXIAM_JWT_VERIFY_STRICT, ...)` — strictness is hardcoded at the call site, not a weakenable default. `jwks.c:130-176`: `exp` mandatory and numeric (absent ⇒ refused), `nbf` honoured, `tenant_id` compared to the configured tenant, fail-closed when no comparand exists. |
| **SEC-072** | Swift asserts the configured tenant on every session | 🔶 **PARTIAL** — tenant half confirmed, expiry half incomplete → **SEC-080** below. `assertTenant` runs unconditionally outside any header guard (`AxiamRequestAuthenticator.swift:80`) and fails closed on absent claim / no configured tenant / mismatch; all three guard entry points route through it. No path admits a foreign-tenant token. |
| **SEC-073** | https-only base URL, literal loopback exception | ✅ **CONFIRMED** in Kotlin, Swift, C++ (and C, verified by hand). All match string literals, none resolves DNS. The three abuse shapes — `http://localhost@evil.example`, `http://evil.com#localhost`, `http://localhost.evil.com` — are rejected by all four; the C++ hand parser strips path/query/fragment first, then userinfo via `rfind`, so a smuggled `@` cannot re-expose an attacker host. Enforced at the only construction path in each SDK, with no bypass flag. |
| **SEC-074** | C++ safe-by-default authenticator; primitive renamed | ✅ **CONFIRMED**. `TokenAuthenticator` (`authenticator.cpp:70-139`) checks signature → `exp` (absent **and** malformed both hard-fail) → `nbf` → tenant → optional `iss`/`aud`; empty `expected_tenant_id` is rejected at construction so the tenant check cannot be silently disabled. `verify_signature_only_unchecked` has exactly two call sites (its definition and the safe authenticator). |
| **SEC-075** | Kotlin `jwks_uri` pinned to issuer origin | ✅ **CONFIRMED** (`OidcSupport.kt:619-627`): absolute + https + host (case-insensitive) + exact port, else fallback to `{baseUrl}/oauth2/jwks`. It sits on the only verifier path and the cache is keyed on the **resolved** URI, so a hostile `jwks_uri` cannot even poison the cache key. |
| **SEC-076** | C/C++ MFA tokens wrapped in `Sensitive` | ✅ **CONFIRMED** (C++ `types.hpp:39`, populated wrapped, `verify_mfa` accepts the wrapper so callers never unwrap; C likewise with volatile-write scrubbing). |
| **SEC-077** | Swift `Sensitive` equality constant-time | ✅ **CONFIRMED** (`Sensitive.swift:40-44`, `ConstantTime.swift:35-49`). Length difference is seeded into the accumulator rather than short-circuited, the loop runs `max(len)` iterations, and the verdict is read only after the full walk. Conformance is constrained to `ConstantTimeComparable`, and `Hashable` is deliberately absent. |
| **SEC-078** | TS `amqplib` repinned + CI gate | ✅ **CONFIRMED**: `package.json:118` `^0.10.9`, lockfile resolves `0.10.9`, `@types/amqplib ^0.10.8` consistent, and `npm ls amqplib` runs immediately after `npm ci` in `sdk-ci-typescript.yml:43-44`. |
| **T-145** | Webhook verifier in all eleven SDKs | ✅ **CONFIRMED 11/11**. Every SDK HMACs `<timestamp>.<raw_body>`, compares constant-time on **decoded** MAC bytes, hard-fails a header with no `v1`, accepts multiple `v1` for rotation, and applies a **two-sided** 300 s window. In all eleven the freshness check runs *after* the MAC check, so a forged signature is never reported as merely stale. No SDK compares hex strings; none has a one-sided window; none can silently pass a `v1`-less header. |

**Two conformance notes (not defects).** Rust, Swift, C++ and C never `break` out of the multi-`v1` candidate loop, so not even the position of the matching key is observable; Go/Java/C#/PHP/TS break on match, leaking only which rotation-era key matched — standard practice, and each per-candidate compare is itself constant-time. Python and Kotlin re-render the timestamp from the parsed integer rather than using the raw header bytes: identical for canonical server output, and fail-closed (never a bypass) for a non-canonical `t`.

### 10.2 New backend code reviewed for the first time

Both commits landed after §9 and change security-relevant behaviour.

| Area | Verdict | Evidence |
|---|---|---|
| **Authz hot-path query rewrites** (`permission.rs:599-627`, `role.rs:551-586`) | ✅ **SOUND** — the highest-value check this pass | The `grants` rewrite keeps `AND out.tenant_id = $tenant_id` **byte-identically**; the `in` side is tenant-safe upstream because `role_ids` comes from `get_user_role_assignments(tenant_id, …)`. The rewrite is strictly **narrower**: the old `meta::id(in) IN $role_ids` compared only the key portion and would match `group:<same-uuid>`, while `in IN $role_records` requires table `role`. The `has_role` `LET` hoist is character-for-character the removed sub-select, both halves keep `out.tenant_id = $tenant_id`, and the `take(1)→take(2)` index shift is correct (a `LET` consumes a result slot) and pinned by a functional test. **No cross-tenant traversal is newly permitted** — no SEC-007/SEC-058/CQ-B50-class regression. |
| **Session-validation cache** (`session_validation_cache.rs`, new) | ✅ **SOUND on all six claims** | Positive-only (the sole `Some(true)` return; only written inside the `expires_at > now` arm). Entries expire at **min(TTL, session.expires_at)**, re-checked on every read, so a cached entry cannot outlive its session. Key is `(tenant_id, session_id)` — tenant-scoped. Default TTL `0` = off, triple-enforced (config default, wiring branch, and short-circuits in both `get` and `insert_valid`), and enabling it emits a startup `warn!`. Invalidation verified **exhaustive**: all five `DELETE …session` sites invalidate (`invalidate`, `consume`, `invalidate_user_sessions`, `invalidate_user_sessions_except`, `cleanup_expired`), the production wiring shares one cached instance across every consumer, and GDPR/account-deletion never touches the `session` table. |
| **OAuth2 client-credentials stage timings** | ✅ **SOUND** | `#[tracing::instrument(skip(self, req))]` keeps the secret-bearing request out of the span; emitted fields are durations plus `access_token_len` — no secret, no token, no `client_id`. `ct_eq` retained over fixed-length hex digests. The timing event fires **only on the success path**, so the instrumentation creates no new remotely-observable discriminator between "client not found" and "bad secret". |
| **Rate limiting** (`a15b78d0`) | ❌ **SEC-079** (below) | Human/brute-force knobs (`login 10`, `register 5`, `password_reset 3`, `mfa 5`) are unchanged and structurally protected — `apply_profile` asserts the presets cannot touch them. Per-method classification is fail-closed (unknown paths → strictest family). The finding is the gRPC units change. |
| **New config knobs** | ✅ **SOUND** | `AXIAM__SERVER__TCP_NODELAY` defaults `true` (no security surface); `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` defaults `0` = off, with the risky mode opt-in and loudly announced. |

### 10.3 New findings

#### SEC-079 [MEDIUM] ❌ — gRPC rate-limit "units fix" raises the effective ceiling 60× on an Argon2id RPC

- **File**: `crates/axiam-api-grpc/src/middleware/rate_limit.rs:284` (`admin_per_sec: authz_per_sec`), `:514-515` (`per_sec_to_window_limit`), `:490` (`WINDOW_SECS = 60`); `crates/axiam-api-grpc/src/config.rs` (`default_grpc_authz_per_sec() = 100`); `crates/axiam-api-grpc/src/services/user.rs:164` (Argon2id `verify_password`).
- **Verified by hand.** Before `a15b78d0`, the per-second ceiling was handed to the shared cross-replica limiter's 60-second window **verbatim** — the commit's own doc comment says so — making the *effective* deployed ceiling `N` per **minute**. After the fix it is `N` per **second**: the crate's own test asserts `per_sec_to_window_limit(100) == 6_000`. `axiam.v1.UserService` classifies into the `Admin` family, whose ceiling is `admin_per_sec = authz_per_sec` (default 100/s), and that family contains `ValidateCredentials` — an **Argon2id password verification**.
- **Impact**: on upgrade, the per-IP ceiling on the Argon2id credential-check RPC goes from ~100/min to ~6,000/min — a 60× increase in online password-guessing throughput and in the Argon2id CPU/memory (~19 MiB arena each) an authenticated caller can conscript. The units bug was accidentally providing 60× more protection than configured, and fixing it silently removed that.
- **Mitigating factors** (why MEDIUM, not HIGH): per-account lockout is checked *before* hashing (`user.rs:152-156`), every failure is metered through the shared lockout helper (`:180`), the RPC requires a valid tenant-scoped JWT, and the process-wide crypto semaphore bounds concurrent Argon2 work. Single-account guessing stays lockout-bound; the 60× buys password-spraying **breadth** and CPU headroom.
- **Fix**: stop deriving `admin_per_sec` from the read-sized authz ceiling. The code comment at `:277-279` already states the correct rationale — *"`ValidateCredentials` is an Argon2id verification, so its ceiling is a CPU guard and must not inherit a read-sized multiplier"* — and then assigns the read-sized base anyway. Default it to a small absolute value (≈5–10/s). At minimum, call the 60× effective-limit change out in the CHANGELOG/upgrade notes as a **posture change**, not only as a units bug: an operator reading "correct gRPC units" will not realise their deployed gRPC ceiling just rose 60×.

#### SEC-080 [LOW] ❌ — Swift authenticator accepts a token with no `exp` claim (SEC-072 residual)

- **File**: `axiam-swift-sdk/Sources/AxiamSDK/Guard/AxiamRequestAuthenticator.swift:68`; `JWKS/JwksVerifier.swift:31` (`let exp: Double?`).
- **Verified by hand**: the check is `if let exp = claims.exp, exp < Date().timeIntervalSince1970 { throw }`. A token carrying **no** `exp` decodes to `nil`, the `if let` never fires, and the token is accepted — and never expires. A *malformed* non-numeric `exp` does fail closed (JSON decode error), so only the absent case leaks. `GuardTests.swift` covers expired and cross-tenant but has no missing-`exp` case.
- **Impact**: bounded by an invariant rather than a control — the AXIAM server always mints `exp`, so this is not directly exploitable today. It matters because the guard's job is to *not* rely on that invariant: the JWKS is organization-wide, and if any signer sharing it ever issues an `exp`-less token, that token becomes a permanent credential. The C and C++ SDKs already treat an absent `exp` as a hard failure (*"an unbounded token is refused"*), so this is also a cross-SDK inconsistency.
- **Fix**: one line — replace the `if let` with a `guard let exp = claims.exp else { throw AuthError(...) }` followed by the comparison, mirroring C/C++. Add a missing-`exp` negative test.

### 10.4 Residuals recorded (not findings)

1. **`member_of` is never tenant-filtered at read time** (`role.rs:551-586`) — pre-existing, not introduced by the rewrite. Currently unreachable because `group.rs:355-389` validates both endpoints against the tenant at write time, and the outer `out.tenant_id` predicate still confines the resulting role. But it leaves group-inherited roles as the one authz edge with no read-time tenant check, so a migration or bulk-import that writes `member_of` directly would bypass it. Adding `AND out.tenant_id = $tenant_id` inside the `LET` is index-served and free.
2. **Session-cache invalidation ordering** — in `consume` (`session.rs:284-286`) and `invalidate_user_sessions_except` (`:330-336`) invalidation happens *after* `result.take(0)?`; a `DELETE` that succeeds but whose row fails to deserialize returns early and leaves a positive entry live for up to TTL. Cheap fix: invalidate immediately after the `.await`.
3. **Session cache does not re-check user status** — a user disabled or locked without a session sweep stays authenticated for up to TTL. Same semantics as the pre-cache inline check, so not a regression, but enabling the cache widens the window from "next request" to "TTL".
4. **`Unlimited` gRPC family is a prefix test on the attacker-controlled path** (`rate_limit.rs:151`) — `/grpc.reflection.` and `/grpc.health.` bypass **both** limiter layers. Neither service is registered today (requests terminate `Unimplemented`), so the effect is unmetered HTTP/2 stream churn, not DB work. If a health service is ever registered this becomes a genuinely unmetered endpoint; cap the family with a generous-but-finite bucket instead of a pass-through.
5. **Unauthenticated work factor on `/oauth2/introspect` rose 60×** (10→600/min) — the endpoint *does* authenticate the client before any lookup, so it is not a token oracle; the residual is that a pre-auth caller can now drive 600 client lookups + SHA-256 per minute per IP instead of 10.
6. **OBS-1 carried forward** — client secrets remain unsalted single-round SHA-256. Acceptable only while every secret is 32 CSPRNG bytes with no operator-supplied path; `421e3e2a`'s doc comment now enshrines it as a design property, which is the moment it deserves a tracking ticket rather than a code comment.

### 10.5 Threat-model synchronisation

`T-145` was still recorded **Open** in the STRIDE model and its generated document although the control shipped. Now that the verifier is confirmed in all eleven SDKs, the model has been updated at source and the document regenerated to match:

- `ThreatDragonModels/Axiam/Axiam.json` — T-145 `status: Open → Mitigated`, retitled *"Receiver acts on an unverified webhook delivery"* (the threat is the receiver's behaviour; the absence of a helper was only the reason it was unmitigated), with the §13 mitigation text; the diagram element `Webhook receiver helper (absent)` renamed to `… (§13)`.
- `claude_dev/threat-model-stride.md` — header count `127 / 22 → 128 / 21`, the §5.9 diagram header `5 open → 4 open`, the threat row and detail block, removal of the open-risk-register row, the §6 header, and the by-severity / by-diagram coverage tables. All three independent count views (register rows, by-severity, by-diagram) reconcile at **21**.

`T-143` (local JWT verification misses a revoked entitlement) stays **open** and is the right home for SEC-080's class: the SDK guards verify locally, so their correctness *is* the control.

### 10.6 Remaining priorities

1. **SEC-079** — decouple `admin_per_sec` from the authz ceiling; document the 60× posture change in the upgrade notes.
2. **SEC-080** — one-line `guard let` for the Swift `exp` check, plus the negative test.
3. **Residual 1** — add the `member_of` tenant predicate (free, closes the last read-time gap in the authz graph).
4. **Residuals 2 and 4** — reorder the two cache invalidations; bound the `Unlimited` gRPC family.
5. **OBS-1** — open a ticket recording the client-secret entropy assumption.
