# AXIAM — Security Analysis (2026-08-02)

- **Date**: 2026-08-02
- **Server commit**: `7ee7df1` (HEAD of `main`; release `1.0.0-alpha23`). SDKs reviewed at each repo's `1.0.0-alpha23` HEAD.
- **Baseline**: [`final-review-2026-07-08.md`](final-review-2026-07-08.md) + [`remediation-2026-07-08.md`](remediation-2026-07-08.md) (last full code-level review, at `a8e40b3`), the [`security-audit.md`](security-audit.md) compliance index (`c79b66e`), and the [`threat-model-stride.md`](threat-model-stride.md) STRIDE model. Companion public write-up: [`threat-modeling-and-security.md`](threat-modeling-and-security.md).
- **Scope**: (1) re-verification at current HEAD of the security controls that landed *after* the 2026-07-08 review — none of which had a prior code-level review — namely write-behind rate limiting, in-process TLS termination, the authz decision cache, AMQP v2 replay protection, the signed-timestamp webhook scheme, and the org-scope/refresh escalation fixes; (2) the **first-ever security review of the four newest SDKs** — Kotlin, Swift, C and C++ (REST-only, contract §1–§7/§9–§11); (3) confirmation that the 2026-07-08 SDK remediations still hold in the original seven SDKs, plus the two open SDK items (webhook helper, per-SDK dependency hygiene).
- **Method**: multi-agent fan-out with per-item file:line evidence, followed by hand re-verification of both new HIGH-class findings and the two headline backend controls (org_id derivation, atomic refresh). Statuses: ✅ verified sound · 🔶 residual/partial · ❌ finding. New findings continue the review sequence at **SEC-071**.
- **Remediation status**: every finding in this document has since been fixed. See **[§9 Remediation status](#9-remediation-status-2026-08-02)** for the per-finding record, the commits, the two deliberate fail-closed breaking changes, and a correction to the SEC-078 premise below.
- **Independent re-verification (2026-08-03)**: §9 was written by the remediation itself, so every claim was re-derived from source by an independent reviewer at `f77ad2a9` — **8/8 findings and `T-145` confirmed**, one partial (SEC-072's expiry half → **SEC-080**). That pass also reviewed two commits that landed after §9 and had never been security-reviewed (authz query rewrites + session-validation cache; rate-limit units/defaults), yielding **SEC-079**. See **[§10](#10-independent-re-verification-pass-2026-08-03)**.
- **Second re-verification (2026-08-03, `1b416c72`)**: the §10.7 remediation recorded its own statuses as *claims pending verification*; all six are now **CONFIRMED FIXED** from source, with a clean regression scan of the remediation diff. See **[§11](#11-second-independent-re-verification-pass-2026-08-03)** — including a process finding (§11.2) on citing authoring commits rather than merges.
- **CONTRACT §10.1 sweep (§12)**: §11's carried recommendation was actioned — a normative minimum local-verification set, audited across all eleven SDKs. It surfaced **five findings three prior passes had missed** (SEC-081 … SEC-084, OBS-4), including two HIGH cross-tenant bypasses.
- **Final verification (2026-08-03, `8c2a5f87`)**: every §12 claim **CONFIRMED**, all eleven SDK repos merged, and the new cross-replica cache-invalidation surface reviewed and found authenticated and fail-safe. One new **HIGH** was raised — **SEC-085**, the PHP framework guards authenticating a failed request as the application's own service account. See **[§13](#13-final-verification-pass-2026-08-03)**, which also records two corrections to my own earlier conclusions.
- **Verification of §14 (2026-08-03, `f0a750ff`)**: **SEC-085 is closed**, CONTRACT §10.1 gained a **rule 8** (the guard must decide on the caller's credential and no other), and rule-8 conformance is confirmed across all eleven SDKs. **This document now has no open finding.** Two §14 claims are PARTIAL — the service-account upgrade seam has no production caller, and the invalidation heartbeat leaves the decision-cache TTL unclamped — plus seven open observations. See **[§15](#15-independent-verification-of-14-2026-08-03)**.

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
>
> **Closed out on 2026-08-03 (§11): SEC-079 and SEC-080 fixed and verified; every finding in this document is now closed.** The admin gRPC ceiling is decoupled from the authz ceiling at an absolute 10/s (600/min), immune to posture presets and pinned by tests; the Swift guard rejects a token with no `exp`; the `member_of` tenant predicate, the cache-invalidation ordering and the bounded infra family are all confirmed from source, with no regressions in the remediation diff. What remains is accepted residuals plus one structural recommendation: **`CONTRACT.md` §10 should state the minimum local-verification set every SDK guard must enforce** — the drift between C, C++ and Swift is the class both SEC-071 and SEC-080 came from.

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
3. **~~Session cache does not re-check user status~~ — ✅ CLOSED 2026-08-03: misdescribed, and subsumed by `T-39`.** *As written*, this said a disabled user "stays authenticated for up to TTL" and that enabling the cache "widens the window from *next request* to *TTL*". Tracing the path shows the premise is wrong in the SDK-favourable direction: `AuthenticatedUser::from_request` (`extractors/auth.rs:105-115`) calls only `is_session_active`, which resolves to `is_session_active_checked` (`session.rs:144-160`) — and that checks **only the session row's `expires_at`**. There is no user-status check anywhere on the session-authenticated request path, cached or uncached. So the pre-cache path never caught a disabled user either, and **the cache widens nothing**. What actually bounds the exposure is `AuthService::refresh`, which reloads the user and calls `check_user_status` before minting — so a disabled user loses access when their current access token expires. That is the already-accepted 15-minute revocation lag, threat-model **`T-39`**, not a property of the session-validation cache. Carrying it as a separate cache residual overstated the cache's risk. Closed here; `T-39` remains the correct home.
4. **`Unlimited` gRPC family is a prefix test on the attacker-controlled path** (`rate_limit.rs:151`) — `/grpc.reflection.` and `/grpc.health.` bypass **both** limiter layers. Neither service is registered today (requests terminate `Unimplemented`), so the effect is unmetered HTTP/2 stream churn, not DB work. If a health service is ever registered this becomes a genuinely unmetered endpoint; cap the family with a generous-but-finite bucket instead of a pass-through.
5. **Unauthenticated work factor on `/oauth2/introspect` rose 60×** (10→600/min) — the endpoint *does* authenticate the client before any lookup, so it is not a token oracle; the residual is that a pre-auth caller can now drive 600 client lookups + SHA-256 per minute per IP instead of 10.
6. **OBS-1 carried forward** — client secrets remain unsalted single-round SHA-256. Acceptable only while every secret is 32 CSPRNG bytes with no operator-supplied path; `421e3e2a`'s doc comment now enshrines it as a design property, which is the moment it deserves a tracking ticket rather than a code comment.

### 10.5 Threat-model synchronisation

`T-145` was still recorded **Open** in the STRIDE model and its generated document although the control shipped. Now that the verifier is confirmed in all eleven SDKs, the model has been updated at source and the document regenerated to match:

- `ThreatDragonModels/Axiam/Axiam.json` — T-145 `status: Open → Mitigated`, retitled *"Receiver acts on an unverified webhook delivery"* (the threat is the receiver's behaviour; the absence of a helper was only the reason it was unmitigated), with the §13 mitigation text; the diagram element `Webhook receiver helper (absent)` renamed to `… (§13)`.
- `claude_dev/threat-model-stride.md` — header count `127 / 22 → 128 / 21`, the §5.9 diagram header `5 open → 4 open`, the threat row and detail block, removal of the open-risk-register row, the §6 header, and the by-severity / by-diagram coverage tables. All three independent count views (register rows, by-severity, by-diagram) reconcile at **21**.

`T-143` (local JWT verification misses a revoked entitlement) stays **open** and is the right home for SEC-080's class: the SDK guards verify locally, so their correctness *is* the control.

### 10.6 Remaining priorities

> **Superseded by [§11](#11-second-independent-re-verification-pass-2026-08-03).** Items 1–4 below were remediated and independently verified on 2026-08-03; item 5 (OBS-1) remains a tracked assumption with its trigger condition recorded. Kept unedited as the record of what this pass asked for.

1. **SEC-079** — decouple `admin_per_sec` from the authz ceiling; document the 60× posture change in the upgrade notes.
2. **SEC-080** — one-line `guard let` for the Swift `exp` check, plus the negative test.
3. **Residual 1** — add the `member_of` tenant predicate (free, closes the last read-time gap in the authz graph).
4. **Residuals 2 and 4** — reorder the two cache invalidations; bound the `Unlimited` gRPC family.
5. **OBS-1** — open a ticket recording the client-secret entropy assumption.

### 10.7 Remediation of §10 — status (2026-08-03)

> ⚠️ **This subsection was written by the remediation work, not by a reviewer.**
> §9 is the cautionary precedent: it asserted "all fixed", and the independent
> pass in §10 found one of its claims partial (SEC-072 → SEC-080) plus two
> further findings in code the remediation itself had introduced. So the
> statuses below are **claims pending verification**, deliberately *not* marked
> ✅ CONFIRMED. Only an independent pass may promote them. Treat §10.1's table
> as the model: re-derive each from source.

| Item | Claimed status | Where |
|---|---|---|
| **SEC-079** | Remediated — pending verification | `axiam` `04dc674` |
| **SEC-080** | Remediated — pending verification | `axiam-swift-sdk` `bc7c48d` |
| **Residual 1** (`member_of` tenant predicate) | Remediated — pending verification | `axiam` `04dc674` |
| **Residual 2** (cache invalidation ordering) | Remediated — pending verification, **no regression test** | `axiam` `04dc674` |
| **Residual 4** (`Unlimited` family bounded) | Remediated — pending verification | `axiam` `04dc674` |
| **Residual 3** (cache does not re-check user status) | **Not addressed** — accepted, documented | — |
| **Residual 5** (introspect work factor rose 60×) | **Not addressed** — accepted, documented | — |
| **OBS-1** (client-secret hashing) | Tracked, see below | — |

**What was done.**

- **SEC-079.** `admin_per_sec` no longer derives from `authz_per_sec` at all: a new absolute `ADMIN_PER_SEC_DEFAULT = 10` (600/min per IP) governs the family that holds the Argon2id `ValidateCredentials`. Only `identity_per_sec` still scales with authz, so a `gateway`/`mesh` preset raising mesh capacity can no longer widen credential-guessing breadth as a side effect. `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` still overrides. The CHANGELOG entry leads with *"This is a posture change — read it even if you skipped the units fix above"*, because the hazard SEC-079 identified is precisely an operator reading "corrected gRPC units" and not realising their deployed ceiling rose 60×. The pre-existing doc-drift test `documented_per_family_rows_match_the_derivation` failed as predicted (`left: 100, right: 10`) before the docs were updated — the guard worked.
- **Residual 1.** `AND out.tenant_id = $tenant_id` added inside the `LET $group_records` sub-select. Query-plan pins re-run: still `IndexScan idx_member_of_unique`, and the `TableScan` witness test was updated to the same shape so it still witnesses a scan rather than going vacuous.
- **Residual 2.** Cache invalidation moved above `result.take(0)?` in `consume` and `invalidate_user_sessions_except`. The other three session-deleting methods were audited and have no fallible step between the `.await` and the invalidation, so they were already correct. **No regression test was added, deliberately**: reaching the bug requires the database to commit the `DELETE … RETURN BEFORE` and then return a BEFORE image that fails to deserialize into `SessionRow`. With the real embedded SurrealDB the returned row is by construction the row it stored, and the repository takes a concrete `Surreal<C>` rather than a mockable trait, so there is no seam. An instrumented-cache call-order assertion would test the assertion, not the behaviour. **This is the weakest item in the set and the one most worth an independent look.**
- **Residual 4.** `Unlimited` became `Infra` with an absolute `INFRA_PER_SEC = 100`. Rationale: a k8s liveness/readiness probe runs on the order of once per few seconds per prober, so even a large sidecar fleet behind one NAT egress IP stays orders of magnitude below 100/s — the ceiling can never be what breaks a probe during an incident (the property that motivated the original pass-through), while the surface stops being unbounded. The old `reflection_and_health_are_never_throttled` test was split into two that pin *both* halves: probes survive a fully saturated server, **and** a sustained flood is eventually rejected. New shared-counter endpoint `grpc_infra`; the other three bucket names are byte-identical, so an in-flight upgrade keeps counting against the same rows.

**Not addressed, and why.** Residual 3 (the cache does not re-check user status, so a disabled user stays authenticated for up to the TTL) and residual 5 (a pre-auth caller can drive 600 introspect client-lookups per minute per IP instead of 10) are both **accepted trade-offs of features that are opt-in or already reviewed**, not defects introduced here. Residual 3 has the same semantics as the pre-cache inline check — the cache widens the window from "next request" to "TTL", which is the documented bounded-staleness contract the cache is opt-in for. Changing either is a posture decision, not a fix.

**OBS-1 — client-secret hashing.** Client secrets are hashed with unsalted single-round SHA-256 (`repository/service_account.rs:36-40`). This is acceptable **only** while every secret is 32 CSPRNG bytes with no operator-supplied path — verified true at both creation and rotation, with no API accepting a caller-chosen secret. §10.4 makes the right point: `421e3e2a`'s doc comment now enshrines that as a design property, which is exactly when it stops being an implementation detail and needs a tracking item rather than a comment. **The trigger condition, stated so it cannot be missed: if any code path is ever added that accepts an operator-supplied, imported, or otherwise non-CSPRNG client secret, this must move to a salted KDF in the same change.** Until then it is not a finding.

**Cross-SDK observation from the SEC-080 fix (new, not previously recorded).** While fixing the absent-`exp` case, every other optional claim in the Swift authenticator was audited. `tenant_id` and `sub` already use `guard let` and fail closed. But `JwtClaims` in `JwksVerifier.swift` **has no `nbf`, `iss` or `aud` fields at all** — the Swift SDK does not model them, so it cannot check them. That is not an `if let` leak (there is nothing to leak), but it is the same family as SEC-080: the three newest SDKs now enforce three different subsets of the same token contract — C honours `nbf`, the C++ `TokenAuthenticator` checks optional `iss`/`aud`, Swift checks neither. Recorded as an observation rather than fixed: adding `nbf` enforcement changes acceptance behaviour, and `iss`/`aud` need a decision about expected values. Worth a deliberate cross-SDK decision on what the minimum local-verification set is, ideally stated in `CONTRACT.md` §10 so it stops drifting per SDK.

---

## 11. Second independent re-verification pass (2026-08-03)

- **Server commit**: `1b416c72` (HEAD of `main`, PR #256), reviewing the fixes in `04dc6744`. SDKs re-checked at their default-branch HEADs; Swift at `53e7915` (PR #10).
- **Why this pass exists**: §10.7 was again written by the remediation work, and — correctly — recorded its own statuses as *"claims pending verification"* rather than as fixes. This pass promotes them (or not) by re-deriving each from source, and re-scans the remediation diff for anything it might have weakened.
- **Result**: **all six claimed items CONFIRMED FIXED**, no regressions found in the diff. `SEC-079` and `SEC-080` are closed. One new low-severity observation (§11.3) and one process finding worth more than its severity (§11.2).

### 11.1 Verification of the §10.7 claims

| Item | Claimed | Independent verdict |
|---|---|---|
| **SEC-079** — gRPC admin ceiling decoupled | Pending verification | ✅ **CONFIRMED FIXED**. `ADMIN_PER_SEC_DEFAULT = 10` (`rate_limit.rs:325`) is an absolute constant, and `from_authz_per_sec` (`:353-359`) no longer references `authz_per_sec` for admin. Effective ceiling on `ValidateCredentials` is now **600/min per IP** (shared window `per_sec_to_window_limit(10) = 600`, governor 10/s burst 10), down from ~6,000/min. `apply_rate_limit_preset` (`config.rs:139-147`) writes **only** `grpc_authz_per_sec`, so no posture preset can widen credential-guessing breadth as a side effect — the exact coupling the finding objected to. `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` still overrides (`config.rs:167`). `UserService → Admin` classification unchanged (`:243-247`), Argon2id path intact (`services/user.rs:164`). Pinned by five tests, including one looping `[1, 100, 1_000, 5_000, 60_000, u32::MAX]` to assert admin never tracks authz, and an end-to-end case with `authz = 5000`. |
| **SEC-080** — Swift absent-`exp` fails closed | Pending verification | ✅ **CONFIRMED FIXED** and **now merged** (`bc7c48d`, merged to Swift `main` via PR #10 as `53e7915`). `guard let exp = claims.exp else { throw }` replaces the `if let`, with the rationale recorded inline and a regression test asserting rejection of a token with no `exp`. Verified against merged `main`, not the feature branch — see §11.2. |
| **Residual 1** — `member_of` tenant predicate | Pending verification | ✅ **CONFIRMED FIXED**. `AND out.tenant_id = $tenant_id` now inside the `LET $group_records` sub-select (`role.rs:578`), and the outer inherited query keeps its own predicate (`:589`). Statement count is still 3 and the `take(0)`/`take(2)` indices are unchanged and correct. Crucially **not over-filtered**: `role_repository_gaps_test.rs:152-204` still proves a group-inherited role is returned, so the added predicate did not silently drop legitimate inheritance. Query-plan pins re-run as `IndexScan`. |
| **Residual 2** — cache invalidation ordering | Pending verification, no regression test | ✅ **CONFIRMED FIXED across all five methods**. In `consume` (`session.rs:292-296`) and `invalidate_user_sessions_except` (`:349-353`) invalidation now precedes `result.take(0)?`. The other three were audited and have no fallible step between the `.await` and the invalidation — `invalidate` and `invalidate_user_sessions` never call `take()` at all, and `cleanup_expired`'s only `take()` is on the *count* query before the DELETE. The one remaining `?` is on the `.await` itself, which is the correct boundary (nothing committed). Cache methods are infallible. **The remediation's decision not to add a regression test is sound**: reaching the bug requires the database to commit a `DELETE … RETURN BEFORE` and then return a BEFORE image that fails to deserialize, which the real embedded SurrealDB cannot produce, and the repository takes a concrete `Surreal<C>` rather than a mockable trait. A call-order assertion would test the assertion, not the behaviour. Verified by reading all five methods rather than by trusting that reasoning. |
| **Residual 4** — `Unlimited` family bounded | Pending verification | ✅ **CONFIRMED FIXED**. `Unlimited` → `Infra` with `INFRA_PER_SEC = 100` (`rate_limit.rs:224,342`). The pass-through is genuinely gone, not merely renamed: `per_sec` returns a plain `u32`, `shared_endpoint` a `&'static str`, `SharedScope::resolve` an unconditional `(endpoint, limit)`, and the service `call` has no `None => allow` branch left. Both layers now cover the family. Fail-closed classification for unknown paths preserved (`_ => Self::AuthzCheck`), pinned over `"/"`, `"/nonsense"`, `"/some.other.Service/Method"`. Tests assert *both* halves — probes survive a saturated server **and** a sustained flood is eventually rejected. |
| **Residuals 3 & 5** — not addressed | Accepted, documented | ✅ **Correctly characterised.** Both are properties of opt-in or previously-reviewed features, not defects introduced by the remediation; leaving them is a posture decision, and both remain recorded in §10.4. |

**Regression scan of the full `04dc6744` diff: clean.** `per_sec_to_window_limit` semantics are untouched (`WINDOW_SECS = 60`); the only numeric movements are tightenings (admin 6,000→600/min; infra unbounded→finite); no tenant predicate was dropped anywhere (`role.rs` only *adds* one, `session.rs` changes are pure reordering with both `WHERE tenant_id` clauses intact); unknown-path classification is unchanged; and the removed `Option` branches are not silent allow-paths — the surviving `None => true` (no extractable client IP) is pre-existing, documented, and still backstopped by the in-memory governor. `poll_ready` was tightened to require all four governors.

### 11.2 Process finding — a correct fix sat unmerged

For part of this pass the Swift SEC-080 fix existed only on `origin/claude/axiam-fixes-optimization-4qymzu`, one commit ahead of that repo's `main`, while §10.7 already recorded it as remediated against commit `bc7c48d`. It has since merged (PR #10). No action is needed on this instance — but the mechanism is worth naming, because it is invisible to exactly the checks that would otherwise catch it:

- A remediation record that cites a **commit hash** is not evidence the fix **shipped**. A hash exists the moment the commit is authored, on any branch.
- Verification that reads a **feature branch** will confirm a fix that users never receive; verification that reads **`main`** will refute a fix that is merely awaiting merge. Both are wrong in opposite directions, and neither is detectable from the diff.
- A sweep across all eleven SDK repositories showed the other ten fully merged, so the gap was a single stranded PR rather than a systemic pattern.

**Recommendation**: record the **merge commit on the default branch** (not the authoring commit) as the evidence pointer for a remediated finding, and treat "authored but unmerged" as its own status — it is materially different from "fixed" for anyone consuming a released SDK. Cheap enforcement: a CI check that every finding ID referenced in a remediation table resolves to a commit reachable from `origin/main` in the repository it claims.

### 11.3 New observation (low)

**OBS-3 — `invalidate` and `invalidate_user_sessions` swallow statement-level DELETE failures.** Neither calls `.check()` nor `.take()` on the DELETE result (`session.rs:243-263`, `:300-315`), so a statement-level SurrealDB error is discarded and the method returns `Ok(())`. Cache invalidation still runs, so the *cache* fails in the safe direction, but the caller — logout, password-reset session revocation, MFA reset — is told sessions were revoked when the statement may have failed. Pre-existing, not introduced by `04dc6744`, and not a finding against this review's scope; recorded so it is not lost. Fix: `.check()` the result and propagate, mirroring the other repositories' error taxonomy.

### 11.4 Standing status

- **All findings from this document are now closed**: SEC-071 … SEC-078 (§10.1), SEC-079 and SEC-080 (§11.1), and `T-145` (11/11 SDKs).
- **Open residuals, all accepted and documented**: §10.4 residuals 3 and 5, OBS-1 (client-secret hashing — with its trigger condition stated), OBS-2, and OBS-3 above.
- **Carried recommendation, unresolved**: the cross-SDK local-verification set still drifts — C honours `nbf`, C++ checks optional `iss`/`aud`, Swift models neither. `CONTRACT.md` §10 should state the minimum set every guard must enforce so this stops being decided per SDK. This is the class both SEC-071 and SEC-080 came from, and it is the one structural gap in the SDK guard surface that no individual fix closes.

---

## 12. CONTRACT §10.1 sweep — five new findings across the SDK guard surface (2026-08-03)

> ⚠️ **Written by the remediation work, not by a reviewer.** Per the §10.7
> precedent, every status below is a **claim pending verification**. The two
> preceding independent passes each found something the remediation's own
> report had missed, so this section is deliberately not self-certified.

### 12.1 Why this pass happened

§11.4 carried one unresolved recommendation: *"the cross-SDK local-verification
set still drifts — C honours `nbf`, C++ checks optional `iss`/`aud`, Swift
models neither. `CONTRACT.md` §10 should state the minimum set every guard must
enforce so this stops being decided per SDK. This is the class both SEC-071 and
SEC-080 came from, and it is the one structural gap in the SDK guard surface
that no individual fix closes."*

That recommendation was actioned: **`sdks/CONTRACT.md` §10.1 — Minimum
local-verification set (normative)** now states the seven rules once, and all
eleven SDKs were audited against it rule by rule.

**The audit found substantially more than drift.** Stating the complete set and
checking every SDK against it surfaced five findings that three prior security
passes had not — not because those passes were careless, but because **there
was no complete set to check against**. Each SDK's subset looked complete in
isolation, and the reference implementation's blind spot propagated as the
standard.

### 12.2 New findings

#### SEC-081 [HIGH] ❌ — `X-Tenant-ID` header selected the tenant a token was verified against (C#, PHP)

- **Files**: C# `AspNetCore/AxiamAuthMiddleware.cs:103-107`; PHP `Laravel/AxiamMiddleware.php:98`, `Symfony/AxiamAuthSubscriber.php:104`.
- **Defect**: both guards computed the expected tenant as `header ?: configured` — PHP literally `$request->headers->get('X-Tenant-ID') ?: $this->tenant` — and then verified the token against **that**. The header is attacker-controlled, so presenting a token minted for tenant B alongside `X-Tenant-ID: B` compared the token **against itself**.
- **Impact**: the tenant assertion was not incomplete, it was **vacuous** — a cross-tenant authentication bypass on any ASP.NET Core, Laravel or Symfony app using the bridge. C# then injected the attacker's tenant into `HttpContext.User`, so downstream authorization also ran under the wrong tenant. This is strictly worse than SEC-072, which merely *skipped* the check when the header was absent.
- **Bounded by inspection**: Python, Java, Rust, TypeScript, Kotlin and Swift use `X-Tenant-ID` only as an **outbound** client header. Go already had it right (`middleware/nethttp.go:151` — `h != "" && h != claims.TenantID`, narrowing only). Confined to C# and PHP.
- **Fix**: the configured tenant is authoritative; an inbound header may only **narrow** (when present it must agree with the verified claim) and can never select the expectation. C# `1d2e077`, PHP `8587418`.

#### SEC-082 [HIGH] ❌ — Rust SDK required `tenant_id` but never compared it

- **File**: `axiam-rust-sdk` `src/token/jwks.rs` (pre-fix), `src/middleware/actix.rs:303`.
- **Defect**: `Claims::tenant_id` is a non-`Option` field, so serde enforced its **presence** — and nothing ever compared it to a configured tenant. The middleware merely parsed it into the injected identity.
- **Impact**: the JWKS trust anchor is organization-wide, so a validly-signed token from **any sibling tenant** was accepted by an Actix guard configured for a different one, then injected as that tenant's identity. Same class as SEC-071 and SEC-072.
- **Why it was missed**: requiring a claim *reads* as handling it. The token could not decode without a `tenant_id`, so nothing looked absent — the gap was that presence was never followed by comparison.
- **Fix**: `expect_tenant_id` + `assert_tenant`, failing closed on absent claim, unparseable claim, **and** unconfigured verifier. `84b7c7a`.

#### SEC-083 [MEDIUM] ❌ — the SEC-080 defect was present in eight of eleven SDKs

`exp` checked only when present — "the claim was missing so there was nothing to check" — making a token with no `exp` a permanent credential.

| SDK | Shape | Commit |
|---|---|---|
| Swift | `if let exp = claims.exp` | `bc7c48d` (SEC-080) |
| Kotlin | `if (exp != null && …)` | `0f06a53` |
| Python | `exp_ts = float(exp) if exp is not None else None` | `b762870` |
| Java | `if (expiration != null && expiration.before(…))` | `e4bada0` |
| Go | `if claims.Exp != 0 && …` — absent decoded to the **zero value** | `f749b1f` |
| C# | `TryGetProperty("exp",…) && TryGetInt64(…) && expired` | `1d2e077` |
| PHP | inherited from `firebase/php-jwt`'s `isset($payload->exp) && …` | `8587418` |
| TypeScript | inherited from `jose`'s `if (payload.exp !== undefined)` | `e99cb2b` |

Only C, C++ and Rust rejected an absent `exp`. **The same rule failed for a different reason in each language** — a nil check, an `Option`, a zero value, a `TryGet` conjunct, and two library defaults that validate a claim only when present. No single code-review pattern catches all of those, which is the argument for a stated contract rather than eleven independent fixes.

Three SDKs additionally accepted a **numeric-string** `exp` (`"1700000000"`), coerced rather than rejected as the wrong JSON type: Python (`float()`), Go, PHP (`is_numeric()`).

#### SEC-084 [LOW] ❌ — unbounded, operator-settable clock skew

C++ used an inline literal with no ceiling; PHP delegated to `firebase/php-jwt`'s `JWT::$leeway`, a **public mutable static** any code in the process can set to an unbounded value. Rust and TypeScript had zero leeway with no named constant. All now use a named constant; C++ enforces a 60 s ceiling and PHP pins `JWT::$leeway` for the duration of each decode. `46a9636`, `8587418`, `84b7c7a`, `e99cb2b`.

#### OBS-4 — signed-integer overflow (UB) in the C++ base64url decoder

`axiam-cplusplus-sdk/src/jwks.cpp` accumulated into a never-truncated `int`, overflowing on any token longer than a few characters — undefined behaviour on the **token-decode path**. Pre-existing, unrelated to §10.1, and surfaced only because the ASan+UBSan leg was run manually: **neither the C nor the C++ repository has a sanitizer or valgrind job in CI**. Fixed in `46a9636`; the missing CI gate is the more durable issue and is not addressed here.

### 12.3 What the libraries actually do — recorded because two gaps came from defaults

| Library | Behaviour vs §10.1 |
|---|---|
| `jsonwebtoken` (Rust) | `validate_nbf` defaults to **`false`**. Configuring an expected `aud` still accepts a token with **no** `aud` unless it is also added to `required_spec_claims` — an absent claim never trips the comparison. |
| `jose` (TS) | `exp` checked **only if present**; `requiredClaims` is the fix and is not a default. But supplying `issuer`/`audience` **does** add a presence check — the opposite of `jsonwebtoken` on the same rule. |
| PyJWT | Its own docstring states the gap. A wrong-typed `exp` raises `TypeError`, **not** a `PyJWTError`, so it escaped the handler and would have surfaced as a 500 rather than a 401. |
| nimbus (Java) | Applies **no** claim policy at all — pure getters. The natural `exp != null &&` idiom is therefore the path of least resistance, which is exactly how the defect arose. |
| `firebase/php-jwt` | Validates `exp`/`nbf`/`iat` **only when present**; `is_numeric()` accepts numeric strings; `JWT::$leeway` is a public mutable static. |
| `lestrrat-go/jwx` (Go) | JWS parse/verify only — no claim validation whatsoever, so every rule was the SDK's own responsibility. |
| C# | **No JWT library at all.** `TokenValidationParameters` is absent from the dependency graph — .NET has no Ed25519 primitive, so JOSE is hand-rolled over BouncyCastle. Every gap was hand-written, not inherited. |

The lesson worth keeping: **"the library validates `exp`" is not a control.** Four of these validate `exp` in some sense and still accept a token that has none.

### 12.4 Corrections to earlier sections of this document

1. **§10.7's claim that residual 2 had no test seam was wrong.** It stated that reaching the invalidation-ordering bug "requires the database to commit a `DELETE … RETURN BEFORE` and then return a BEFORE image that fails to deserialize, which the real embedded SurrealDB cannot produce, and the repository takes a concrete `Surreal<C>` rather than a mockable trait." The premise about the *connection* is right; the conclusion is not. SurrealDB provides a seam **inside the database**: `DEFINE EVENT … WHEN $event = 'DELETE' THEN { THROW … }` makes the real engine fail the statement. The regression test §10.7 called impossible now exists and covers all five delete paths, proving both that the error propagates *and* that the cache is invalidated first. Recorded in `1f498ec`.

2. **§11.4's carried recommendation is actioned**, not merely noted — `CONTRACT.md` §10.1 is normative and all eleven SDKs are aligned.

### 12.5 Status

| Item | Status | Evidence |
|---|---|---|
| **SEC-081** (tenant-header override) | Remediated — pending verification | C# `1d2e077`, PHP `8587418` |
| **SEC-082** (Rust tenant never compared) | Remediated — pending verification | `84b7c7a` |
| **SEC-083** (absent `exp`, 8 SDKs) | Remediated — pending verification | see the table in §12.2 |
| **SEC-084** (unbounded skew) | Remediated — pending verification | `46a9636`, `8587418`, `84b7c7a`, `e99cb2b` |
| **OBS-4** (C++ base64url UB) | Fixed — pending verification | `46a9636` |
| **OBS-1** (client-secret hashing) | Remediated — pending verification | `2fa25c1` + startup gate `8162f00` |
| **OBS-3** (swallowed revocation errors) | Remediated — pending verification, **now with a regression test** | `1f498ec` |
| §4 residual 1 (mintable rate-limit key) | Advisory added | `1f498ec` |
| §11.2 (evidence must resolve on main) | CI gate added | `1f498ec` |
| §4 residual 2 (multi-replica cache staleness) | **Closed** — remediated, pending verification | `e5b2a26` |

**§4 residual 2 — closed rather than accepted.** The ≤ `decision_cache_ttl_secs`
stale-allow window (threat-model `T-88`) is now closable with
`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true`: invalidations fan out
over the existing RabbitMQ transport to a per-replica exclusive queue, carrying
the §8 signed envelope. Default off and inert when off, so a single-replica
deployment that enables the cache acquires no AMQP dependency and the previously
documented behaviour is unchanged.

Two design points are worth recording, because both are traps the obvious
implementation falls into:

1. **Trust follows the consumer's connection liveness only.** A replica that
   cannot hear invalidations stops serving from its cache (correct, slower)
   rather than serving allows it can no longer invalidate. But a stale — though
   validly signed — *message* is rejected and logged **without** revoking trust.
   Tying trust to message freshness would turn a single captured broadcast into
   an on-demand lever for disabling every replica's cache fleet-wide.
2. **Nonce dedup is per-replica and in-memory, never the shared durable store.**
   On a fanout every replica sees the same nonce; a shared store would let
   exactly one replica record it first and make all the others reject the
   invalidation as a replay — reinstating the very hole this closes, everywhere
   but one node.

Publish-side failure fails the *mutation* (503) rather than reporting a
revocation that did not fully take effect; the local cache is dropped before the
publish is attempted, so the mutating replica is never the stale one. Both are
operator-visible behaviour changes and are documented as such.

### 12.6 Recommendations that remain open

1. **Add sanitizer/valgrind gates to the C and C++ CI.** OBS-4 was undefined behaviour on the token-decode path that survived because the only jobs are gcc/clang builds plus coverage. Both repos' suites pass cleanly under ASan+UBSan today — wiring them in is cheap and would have caught it.
2. **`AXIAM__AUTH__PEPPER` is now mandatory in release builds** (OBS-1). This is an operator-visible breaking change; it needs release-note prominence, and the pepper must not be rotated without re-issuing every client secret.
3. **Go's `govulncheck` reports 26 stdlib advisories** from the go1.25.0 toolchain, fixed in go1.25.3. A toolchain bump, not a code change, but real.
4. **Kotlin's coverage margin is 0.19 points** above its 98% floor, because of pre-existing untested webhook lines. The next unrelated addition will trip the gate.

---

## 13. Final verification pass (2026-08-03)

- **Server commit**: `8c2a5f87` (HEAD of `main`, PR #257). SDKs verified at each repo's **`origin/main`**, not at working-tree HEAD — 8 of 11 working trees were sitting on an older commit than `origin/main`, so a tree-based audit would have read pre-fix code.
- **Scope**: (1) verification of the §12 claims (SEC-081 … SEC-084, OBS-4) and the §12.5 backend items (OBS-1, OBS-3); (2) first security review of the **cross-replica decision-cache invalidation over RabbitMQ** (`e5b2a261`), which is new inbound attack surface; (3) a regression scan of the whole `b46997ce..8c2a5f87` diff; (4) a §10.1 conformance matrix across all eleven SDKs.
- **Result**: every §12 claim **CONFIRMED**, all eleven SDK repositories merged, and the new invalidation surface is authenticated and fails safe. The §10.1 matrix — the point of stating the contract — surfaced **one new HIGH**: the PHP framework guards admit a request whose token fails verification by falling back to the application's *own* session. New findings continue at **SEC-085**.

### 13.1 Verification of the §12 and §12.5 claims

| Item | Independent verdict |
|---|---|
| **SEC-081** — `X-Tenant-ID` selected the expected tenant (C#, PHP) | ✅ **CONFIRMED FIXED** (by hand). C# takes the expectation from `optionsAccessor.Value.DefaultTenantId` and lets the header only *narrow* (`AxiamAuthMiddleware.cs:110,160-166`); PHP Laravel and Symfony both verify against the configured `$this->tenant` and reject a differing header (`AxiamMiddleware.php:103,108`, `AxiamAuthSubscriber.php:110,117-118`). The vacuous self-comparison is gone. |
| **SEC-082** — Rust required `tenant_id` but never compared it | ✅ **CONFIRMED FIXED** (by hand). `assert_tenant` is called inside `verify` (`token/jwks.rs:348`) and fails closed on an absent claim, an unparseable claim, **and** a verifier with no configured tenant (`:516-534`) — the last being the case that would otherwise re-open the hole silently. |
| **SEC-083** — absent `exp` accepted (8 of 11 SDKs) | ✅ **CONFIRMED FIXED in all eleven.** Each language's specific trap is closed at the root rather than patched: Go retyped the claim `Exp *int64` so an absent value cannot decode to `0`; TypeScript adds `requiredClaims: ['exp']` over `jose`; PHP enforces `exp` itself instead of inheriting php-jwt's present-only check; Python sets `options={"require": [...]}` **and** re-asserts the raw claim type; Java requires presence explicitly over nimbus; Rust carries both a non-`Option` field and `set_required_spec_claims`. The numeric-string coercion is also fixed in all three affected SDKs (Go rejects a leading `"`, PHP requires `is_int`/`is_float`, Python excludes `bool` explicitly — `isinstance(True, int)` is `True`). |
| **SEC-084** — unbounded/operator-settable skew | ✅ **CONFIRMED FIXED.** C++ has a 30 s default with a **60 s hard ceiling** enforced by a throwing constructor; PHP saves, pins and restores `JWT::$leeway` around each decode in a `finally`, so a global set by unrelated code cannot leak in; Rust and TypeScript use named 60 s constants. Nine of eleven are fixed and non-configurable. |
| **OBS-4** — C++ base64url signed-integer overflow (UB) | ✅ **CONFIRMED FIXED.** The accumulator is now `std::uint32_t` **and** truncated every iteration (`& 0xFFFFFFu`) — both halves matter, since unsigned alone would only make the wraparound well-defined rather than correct (`jwks.cpp:31-38`). No other accumulation in the file has that shape. |
| **OBS-1** — client-secret hashing keyed with the pepper | ✅ **CONFIRMED.** Keyed HMAC-SHA256 under a domain-separated subkey, stored as `v2.hs256$…` (`client_secret.rs:169-176,225-242`); the unkeyed function is removed from the public API rather than merely bypassed; comparison remains constant-time over the whole stored string and candidates are zeroized. The release startup gate is genuinely fail-closed (`main.rs:281-282`), and — better than an assertion — it was *proved* by the release-mode E2E stack panicking on a missing pepper, which is why `3c06ab58` exists. **Migration is handled properly**: length-self-identifying dual-read plus a lazy CAS upgrade that only fires on a successful match and carries a `tenant_id` predicate, so a wrong secret can never trigger a write and a racing rotation cannot be clobbered. |
| **OBS-3** — revocation failures propagate | ✅ **CONFIRMED**, with all five delete paths covered and cache invalidation still ordered before the fallible step. |
| **Merge status (§11.2 lesson applied)** | ✅ **All eleven SDK repositories at 0 unmerged commits** on the fixes branch. Last round's stranded-PR failure did not recur, and the CI gate `scripts/check-remediation-evidence.py` now enforces it — every `(finding, repo, commit)` triple must resolve to a commit reachable from the default branch. |

### 13.2 Cross-replica cache invalidation — first review of new attack surface

The transport lives in `crates/axiam-amqp/src/cache_invalidation.rs` (new, ~773 lines); `crates/axiam-authz/src/invalidation.rs` is only the transport-agnostic seam.

**Authenticated — confirmed.** Invalidation reuses the *same* §8 envelope as the rest of the AMQP surface rather than inventing a parallel one: per-tenant HKDF subkey, `key_version >= 2`, nonce, `issued_at`, constant-time verify, with **no accept-when-absent branch**. A party with broker publish access but no signing key can do nothing — every forged message is nack'd without requeue. Even a validly-signed message is structurally bounded: `InvalidationEvent` is a closed two-variant enum whose `apply` only ever calls `cache.invalidate_*` and takes `&DecisionCache`, not the engine, so there is no path from a received message back to a publish. Loop-freedom is structural, not conventional.

**Fails safe — confirmed.** The cache starts **untrusted** when broadcast is enabled and only becomes trusted after `basic_consume` succeeds; while untrusted, `get()` returns `None` and `insert()` discards, so it degrades to uncached evaluation rather than serving stale allows. Publish failure fails the *mutation* (503) rather than silently leaving replicas stale, and the local cache is dropped before the broadcast is attempted. Both switches default **off**. Tenant scoping holds — a tenant-A signature cannot verify as tenant B, and a subkey holder can only flush their own tenant (self-DoS). Flood resistance is bounded by channel prefetch and a hard-capped nonce guard.

**Two residuals** (§13.4 items 1–2): trust tracks *consumer liveness only*, so a party with broker **configure** rights can `queue.unbind` a replica and silently suppress its invalidations — bounded by the TTL, which is exactly why the TTL must not be relaxed now that fan-out exists; and the publisher holds a single unsupervised channel, so one channel exception makes every narrowing mutation 503 for the process lifetime.

### 13.3 New finding

#### SEC-085 [HIGH] ❌ — PHP framework guards authenticate a failed request as the application's own service account

- **Files**: `axiam-php-sdk` `src/AxiamClient.php:784-803` (`verifyLocallyOrFallback`), reached from `src/Laravel/AxiamMiddleware.php:103` and `src/Symfony/AxiamAuthSubscriber.php:110`.
- **Verified by hand.** The guard calls `verifyLocallyOrFallback($token, $this->tenant)`. If the caller's token fails verification for **any** reason — expired, absent `exp`, wrong tenant, bad signature, garbage — the method does not return `null`. It refreshes **the client's own session** (`$this->session->refreshIfNeeded()`) and verifies **that** token instead, returning its claims. The middleware then injects `$claims['sub']` as `axiam_user`.
- **Impact**: a request bearing an invalid or foreign token is admitted, authenticated as the application's own AXIAM principal — typically a **service account**, which in an IAM integration is usually more privileged than the end user whose request it replaced. Every downstream authorization decision then runs under that identity. This is an authentication bypass in the two PHP framework bridges, and it is not caught by the §10.1 rules because both verification calls are individually complete — the defect is *which token* the decision is about.
- **Why the sweep found it and three prior passes did not**: §10.1 audits ask "does this guard enforce rule N?" for each rule. The answer here is yes for all seven. The gap is one level up, in the guard's control flow, and only became visible when every SDK's guard was read side by side — C#, Go, Java, Kotlin, Rust, Swift, TS, C and C++ all return 401 at this point; PHP is the only one that substitutes a different credential.
- **Fix**: the framework guards must call `JwksVerifier::verify()` (or a `verifyLocally()` that has no fallback) directly. `verifyLocallyOrFallback` is a reasonable *client-side* helper for the SDK's own outbound calls — it is only wrong as a request guard. Add a negative test asserting that an expired caller token yields 401 even while the client session is healthy.

### 13.4 New observations

1. **Invalidation suppression by unbinding** — trust follows consumer liveness, not delivery. A broker-configure attacker can unbind a replica's queue: its consumer stays subscribed, trust stays `true`, and it keeps serving cached decisions while the publisher's `mandatory`-off publish still gets acked. Bounded by the TTL, which makes the TTL load-bearing again — **do not raise `decision_cache_ttl_secs` on the theory that fan-out makes it moot.** A liveness heartbeat over the channel would close it.
2. **Publisher channel has no recovery** — one unsupervised `Channel` created at startup, versus a fully supervised consumer with backoff. A single channel exception makes every access-narrowing mutation return 503 for the process lifetime. Fail-closed, so not a security hole, but a durable availability defect that the docs do not mention.
3. **Pepper rotation is an unversioned hard break** — the `v2.hs256$` tag versions the *algorithm*, not the *key*, so there is no dual-pepper read. Rotating `AXIAM__AUTH__PEPPER` permanently invalidates every client secret. The AMQP path carries a `key_version` on the wire for exactly this reason; the client-secret format should too.
4. **Service-account secrets have no v1 upgrade path** — `service_account.rs` writes v2 on create/rotate but has no `upgrade_*` method, so legacy rows never migrate. The v1 arm therefore cannot be retired on the strength of "no v1 `oauth2_client` rows remain".
5. **Python and Java permit a 300 s operator-set clock skew** — rule 7 is satisfied (named and bounded), but this is 5× the recommended 60 s and 5× every sibling's fixed value. Consider lowering the ceiling to 60 s to match C++.
6. **Tenant comparand is a slug in three SDKs** (TypeScript, PHP, Django) while the `tenant_id` claim is always a UUID — a slug-configured guard rejects 100% of traffic. Fail-closed, so not a vulnerability, but a deployment footgun with no diagnostic, diverging from the six SDKs that compare UUIDs.
7. **Swift accepts a token with no `kid`**, falling back to the sole EdDSA key when unambiguous. Not a §10.1 rule and low risk with one org key, but Kotlin, PHP and Java reject it, and it is fragile under key rotation.
8. **C SDK's §10.1 negative-test set looks incomplete** — ten of eleven carry the full mandated set; `tests/test_jwt_claims.c` covers the `exp` cases but not evidently the rest. Worth closing before §10.1's testing clause is treated as satisfied.
9. **`users.rs` delete/update do not invalidate cached decisions** for the affected subject, so a deleted or disabled user's cached allows survive until TTL. Pre-existing and unrelated to the fan-out work, but now the one gap left in an otherwise complete invalidation surface.
10. **No sanitizer/valgrind job in the C or C++ CI** (carried from §12.6). OBS-4 was undefined behaviour on the token-decode path that survived because the only jobs are builds plus coverage. Both suites pass under ASan+UBSan today; wiring them in is cheap.

### 13.5 Corrections to my own earlier conclusions

Recorded plainly, because both were cases where I endorsed a claim rather than testing it:

1. **§11.1 was wrong to endorse "there is no test seam" for the invalidation-ordering fix.** I accepted the reasoning that a concrete `Surreal<C>` offers no mocking seam and verified the five methods by reading them. The premise about the *connection* is right, but the conclusion is not: SurrealDB provides a seam **inside the database** — `DEFINE EVENT … WHEN $event = 'DELETE' THEN { THROW … }` makes the real engine fail the statement. That test now exists (`session.rs:557` helper; `every_delete_path_propagates_a_statement_level_failure:591`, `cache_is_invalidated_before_the_fallible_step_on_every_path:668`, `delete_paths_still_succeed_and_clear_the_cache:774`) and covers all five paths against the real embedded engine. Verified present. The lesson is narrow and worth keeping: *"there is no seam"* is a claim about imagination, not about the system.
2. **§10.4 residual 3 overstated the session cache's risk.** I wrote that the cache "widens the window from *next request* to *TTL*" for a disabled user. Verified against code: `AuthenticatedUser::from_request` calls only `is_session_active`, which checks **only the session row's `expires_at`** (`session.rs:144-160`) — there is no user-status check on the session-authenticated path, cached or uncached. So the pre-cache path never caught a disabled user either and the cache widens nothing. The real bound is `AuthService::refresh` reloading the user before minting, i.e. the already-accepted 15-minute lag — threat-model **`T-39`**, not a cache property. Correctly closed as misdescribed.

### 13.6 Standing status

- **Closed and independently verified**: SEC-071 … SEC-084, `T-145`, OBS-1, OBS-3, OBS-4, and §10.4 residuals 1, 2, 3 and 4.
- **Open**: **SEC-085** (HIGH, PHP guard fallback) — the only open finding in this document.
- **Open observations**: §13.4 items 1–10, plus §10.4 residual 5 (introspect pre-auth work factor) and the carried recommendations from §12.6 (C/C++ sanitizer CI, pepper release-note prominence, Go toolchain advisories, Kotlin coverage margin).
- **Structural note**: the §10.1 contract did what it was introduced to do. Stating the rules once and auditing eleven implementations against them surfaced two HIGH cross-tenant bypasses, an eight-SDK expiry gap and a UB defect that three prior passes had missed — *"there was no complete set to check against"* is the correct diagnosis. SEC-085 is the argument for extending that discipline one level up: §10.1 constrains what a guard must *check*, and should also state that a guard must fail closed on the **caller's** credential and never substitute another.

---

## 14. Remediation of §13 (2026-08-03)

> ⚠️ **Written by the remediation work, not by a reviewer.** Per the §10.7 and
> §12 precedent, every status below is a **claim pending verification**. Three
> prior independent passes each found something the remediation's own report had
> missed, so this section is deliberately not self-certified. §13.1's table is
> the model: re-derive each from source, at `origin/main`, not at a working-tree
> HEAD or a feature branch (§11.2).

### 14.1 Scope

§13.6 left exactly one open finding and a list of open observations. All of them
were actioned — the required item (SEC-085) and every optional one — with the
single deliberate exception recorded in §14.4.

### 14.2 The open finding

| Item | Severity | Repo | Claimed status | What landed |
|---|---|---|---|---|
| **SEC-085** | HIGH | `axiam-php-sdk` | Remediated — pending verification | New `AxiamClient::verifyLocally()` applies the full §10.1 set to the caller's token with **no fallback**, and is what both framework bridges now call. `verifyLocallyOrFallback()` is retained for the SDK's own outbound calls — the context where refreshing the client's own token is the intended recovery — and now carries an explicit warning against guard use. |

**On the regression tests.** The finding's own fix note asked for "a negative
test asserting that an expired caller token yields 401 even while the client
session is healthy". Writing that test naively produces a **vacuous pass**, and
this is worth recording because the trap is not obvious: the natural fixture
token carries no `org_id`, so `Session::buildRefreshCall()` rejects locally and
the fallback never reaches the transport. The test then passes against the
*vulnerable* code, for a reason that has nothing to do with the fix.

The harness therefore primes a session whose refresh genuinely succeeds and
whose token genuinely verifies, and **asserts that precondition explicitly**
before each case. Verified by falsification: reverting either guard to
`verifyLocallyOrFallback()` fails 8 of the 9 new cases, each admitting the
rejected caller as `app-service-account`. Four caller shapes are covered
(expired, garbage, `alg:none`, foreign tenant) across both Laravel and Symfony.
Full suite: 507 tests / 1302 assertions green.

### 14.3 CONTRACT.md §10.1 rule 8 — the structural note actioned

§13.6 closed with: *"§10.1 constrains what a guard must check, and should also
state that a guard must fail closed on the caller's credential and never
substitute another."* That is now **rule 8 — subject of the decision**, normative
in `sdks/CONTRACT.md` and re-synced to all eleven vendored copies.

Rule 8 is deliberately framed as being about **control flow, not claims**, because
that is what made SEC-085 invisible to three prior passes and to the §10.1 audit
itself: rules 1–7 ask *"is this token good?"* and the PHP guard satisfied all
seven. Rule 8 asks *"is this the token the decision is about?"*. The rule also
states the legitimate shape — a reactive-refresh helper is correct for an SDK's
**outbound** calls — and requires the two to be separate methods with the
no-fallback one as the documented guard entry point.

The testing clause carries the §14.2 lesson forward: a rule-8 test whose client
session is unusable passes vacuously and does not satisfy the clause.

### 14.4 Observations from §13.4 and §12.6

> **No commit hashes are cited in this section, deliberately.** §11.2's rule is
> that a remediation record citing a hash must resolve to a commit reachable from
> the default branch, and `scripts/check-remediation-evidence.py` enforces it. A
> hash authored on the remediation branch cannot satisfy that until the branch
> merges, so citing one here would either fail the gate or — worse — invite
> relaxing it. The rows below name the **repository** and what landed; the
> merge-commit evidence belongs in the verification pass that promotes these
> claims, which is the only point at which it can be true.

| Item | Claimed status | Repo and what landed |
|---|---|---|
| **1** — invalidation suppression by unbinding | Remediated — pending verification | `axiam`: self-addressed liveness heartbeat; watchdog is a **one-way revoker** |
| **2** — publisher channel has no recovery | Remediated — pending verification | `axiam`: channel opened lazily and reopened after any failure |
| **3** — pepper rotation is an unversioned hard break | Remediated — pending verification | `axiam`: `AXIAM__AUTH__PEPPER_PREVIOUS` dual-read + lazy rewrite |
| **4** — service-account secrets have no upgrade path | Remediated — pending verification | `axiam`: tenant-scoped CAS `upgrade_client_secret_hash` |
| **5** — Python/Java permit a 300 s operator-set skew | Remediated — pending verification | `axiam-python-sdk`, `axiam-java-sdk`: ceiling lowered to 60 s |
| **6** — tenant comparand is a slug in three SDKs | Remediated — pending verification | TS/PHP/Python: one-time diagnostic naming the cause |
| **7** — Swift accepts a token with no `kid` | Remediated — pending verification | `axiam-swift-sdk` |
| **8** — C SDK's §10.1 negative-test set incomplete | Remediated — pending verification | `axiam-c-sdk` |
| **9** — `users.rs` does not invalidate cached decisions | Remediated — pending verification | `axiam` |
| **10 / §12.6.1** — no sanitizer job in C/C++ CI | Remediated — pending verification | `axiam-c-sdk`, `axiam-cplusplus-sdk`: ASan+UBSan+valgrind |
| **§12.6.2** — pepper release-note prominence | Remediated — pending verification | `axiam`: CHANGELOG + a rotation procedure in `docs/deployment/` |
| **§12.6.3** — Go stdlib advisories | Remediated — pending verification | `axiam-go-sdk`: toolchain bump |
| **§12.6.4** — Kotlin coverage margin 0.19 pts | Remediated — pending verification | `axiam-kotlin-sdk`: webhook lines covered |
| **§10.4 residual 5** — introspect pre-auth work factor | **Not addressed** — accepted, unchanged | — |
| **OBS-1** — client-secret entropy assumption | Superseded by the keyed hash (§13.1) | — |

**Two design points worth recording**, because both are traps the obvious
implementation falls into:

1. **The heartbeat watchdog can only revoke trust, never grant it.** Trust is
   still granted in exactly one place — the consumer, on a successful
   `basic_consume`. A watchdog able to grant it could resurrect trust on a
   replica whose consumer had died, converting a fail-safe into a fail-open.
   Only the replica's *own* heartbeat counts: another replica's proves that
   replica can publish, which says nothing about our binding. And heartbeats are
   separated out before any `InvalidationEvent` exists, so they have no path to
   `apply` and cannot consume the bounded nonce-guard capacity that real
   invalidations depend on.

2. **Pepper rotation uses a dual read, not a stored key id.** The obvious design
   — derive a kid from the pepper and store it beside the hash — would hand
   anyone holding a table dump an **offline oracle for testing pepper guesses**,
   which does not exist today: testing a guess currently requires a known
   (secret, hash) pair, and no secret is ever stored. Trying both keys costs one
   extra HMAC on rotation-era rows and adds no new verifier for an attacker.
   Both candidates are computed unconditionally while a rotation is configured,
   so response time does not reveal which pepper era a row is in.

**Not addressed, and why.** §10.4 residual 5 (a pre-auth caller can drive 600
introspect client-lookups per minute per IP instead of 10) remains accepted: the
endpoint authenticates the client before any lookup, so it is not a token oracle,
and changing the ceiling is a posture decision rather than a fix. It stays
recorded in §10.4.

### 14.5 What a verifier should look at hardest

Stated plainly, so the next pass spends its effort where this one is weakest:

1. **The rule-8 regression harness.** Its value rests entirely on the fallback
   being genuinely reachable. The precondition is asserted in-test, but a future
   edit to the mock transport could make it vacuous again without failing
   anything. Re-run the falsification rather than trusting the assertion.
2. **The heartbeat's one-way-revoker property.** It is a claim about the *whole*
   wiring, not one function: confirm by source that no path other than the
   consumer's post-subscribe call reaches `set_trusted(true)`.
3. **The pepper dual-read's timing behaviour.** Both candidates are computed
   unconditionally, but only when a previous pepper is configured. Confirm that
   the no-rotation path is unchanged and that neither path branches on the
   presented secret.
4. **§14.4 items 5–8 across SDKs.** Per-SDK changes are where every previous pass
   found drift, and each language closed its own rule for its own reason.

---

## 15. Independent verification of §14 (2026-08-03)

- **Commits**: server `f0a750ff` (PR #258); SDKs at each repo's `origin/main` (`d2f99a2` PHP, `e182736` C, `715bfd5` C++, `a7f8b0c` Swift, `d524050` TS, `3f177c9` Python, `a6bb698` Java, `b6aea31` Go, `103adee` Kotlin, `418c20b` Rust, `6fe89ce` C#).
- **Method**: §14 again recorded its statuses as *claims pending verification*, and §14.5 named its own three weakest points — a genuinely useful hand-off. Each claim was re-derived from source; the two §14.5 items that are structural (the one-way-revoker property, the sole `set_trusted(true)`) were checked by hand.
- **Result**: **SEC-085 is closed** and rule 8 holds across all eleven SDKs, so **this document has no open finding**. Two §14 claims are **PARTIAL**, and the residuals below are all observations rather than findings.

### 15.1 Verification of the §14 claims

| Item | Verdict |
|---|---|
| **SEC-085** — PHP guard credential substitution | ✅ **CONFIRMED FIXED** (by hand). Both bridges now call `AxiamClient::verifyLocally()`, which delegates straight to `JwksVerifier::verify()` and returns `null` on any failure with no fallback (`AxiamClient.php:786-789`, `AxiamMiddleware.php:112`, `AxiamAuthSubscriber.php:120`). `verifyLocallyOrFallback()` is retained for the SDK's own outbound calls — the correct home for it — and carries an explicit warning against guard use. |
| **Rule 8 across the other ten SDKs** | ✅ **CONFIRMED**. Every guard threads the caller's token into exactly one verification call and rejects on failure; none references the client session, token manager or refresh path. Go narrows its verifier interface to `VerifyAccessToken` so the signature-only primitive is not even reachable from the guard. No SDK can admit a request under a credential other than the one presented. |
| **Obs 5** — clock-skew ceiling 300→60 s | ✅ **CONFIRMED**. Python `MAX_CLOCK_SKEW_SECONDS = 60` enforced by **rejection** (`_jwks.py:92,153`); Java the same in a record compact constructor (`JwksVerifier.java:145,233-237`), so an out-of-range Spring property fails context startup rather than silently widening. All eleven SDKs now sit at 60 s. |
| **Obs 7** — Swift requires `kid` | ✅ **CONFIRMED**. `guard let kid else { return nil }` (`JwksVerifier.swift:209-212`); the sole-key fallback is gone, and `alg` is still pinned before key lookup. |
| **Obs 8** — C §10.1 negative-test set | ✅ **CONFIRMED**, all eight mandated cases present and registered in CTest. The HS-confusion case is a real attack, not a straw man: the fixture HMACs with the org's published Ed25519 **public key**, so the MAC genuinely verifies for any implementation that trusts the header. |
| **Obs 10** — C/C++ sanitizer CI | ✅ **CONFIRMED gating**, not advisory. `-fno-sanitize-recover=all` plus `halt_on_error`/`abort_on_error` is the load-bearing detail — without it UBSan prints and continues, which is exactly the advisory failure mode. Valgrind runs with `--error-exitcode=9`. (Whether these are *required checks* in branch protection is a GitHub setting, not visible in-tree.) |
| **Go stdlib advisories** | ✅ **CONFIRMED** — `go 1.25.12` directive with all three CI pins matching, and `govulncheck` gating. The *count* of 26 was not re-executed here; the bump and the gate are what hold the claim over time. |
| **Obs 9** — user delete/update invalidation | ✅ **CONFIRMED**. Both paths invalidate the **target** subject scoped to the tenant, and update invalidates *unconditionally* rather than gating on which field moved — the stronger choice, and reasoned in-code. Fail-closed is genuine end to end (`?` → `ServiceUnavailable` → 503), matching the other narrowing mutations. The test asserts the recorded `(tenant, subject)` pairs and pins the target-vs-caller inversion, not merely a 200. |
| **Obs 2** — publisher channel recovery | ✅ **CONFIRMED**. Lazy open plus discard-on-any-failure, with the error still returned on the failing attempt, so recovery did not cost the fail-closed property. Publisher confirms survive the refactor (`confirm_select` on every new channel). Pinned by a test asserting both reopen *and* `is_err()`. |
| **Obs 3** — pepper rotation | ✅ **CONFIRMED** as a dual-pepper verify-only read with lazy rewrite under the current key. Both candidates are computed before any branch on the result, kept as `subtle::Choice`, so timing does not reveal the pepper era; a wrong secret never triggers a write. **No key-version marker, deliberately** — a stored kid would give a table-dump holder an offline oracle for pepper guesses. That is a coherent trade, but it means the "key-version marker" half of the observation is answered with *intentionally not done*, not *done*. |
| **Obs 1** — suppression by queue unbind | 🔶 **PARTIAL** — see §15.2. |
| **Obs 4** — service-account v1 upgrade path | 🔶 **PARTIAL** — see §15.2. |
| **Regression scan** (both sides) | ✅ **Clean.** No tenant predicate dropped (the one new query *adds* one and is tested against cross-tenant abuse), no limit loosened, no new fail-open path, no new unauthenticated surface, no secret reaching a log line. |

### 15.2 The two partials

**Obs 4 — the service-account upgrade seam has no production caller.** The trait method, the tenant-scoped CAS implementation and four good tests all exist (`repository.rs:506-512`, `service_account.rs:434-463`, `uncovered_repos_test.rs:679-772`). But grepping the workspace, `ServiceAccountRepository::upgrade_client_secret_hash` is referenced only by the trait, its impl and that test — the only live upgrade call site is the OAuth2 client one. Nothing outside `axiam-db` verifies `service_account.client_secret_hash` at all. So the *capability* landed and the *defect* did not close: a legacy v1 service-account row still never migrates in a running server, and the v1 arm still cannot be retired. The same applies to the pepper rotation rewrite in Obs 3, which drains `oauth2_client` rows only.

**Obs 1 — the heartbeat is real, but three gaps remain.** The mechanism is well built: a self-addressed signed heartbeat on the same exchange, separated out *after* signature/key-version/freshness checks but *before* the nonce guard and before any event is constructed, so a heartbeat provably cannot reach `apply`. Only a replica's *own* heartbeat counts. Detection is ≤ ~30 s (10 s interval × 3 misses). I verified the one-way-revoker property by hand: production contains exactly **one** `set_trusted(true)`, in the consumer after `basic_consume` succeeds, and the watchdog only ever revokes. Remaining:

1. **No TTL ceiling clamp.** `decision_cache_ttl_secs` is still an unbounded `u64` consumed verbatim, with no clamp — unlike `cleanup_interval_secs`, which is clamped to `60..=3600`. An operator can still configure a multi-hour staleness window. §13.4 warned the TTL is load-bearing; it is still unbounded.
2. **The mitigation is operator-disableable.** Setting the heartbeat interval to `0` skips the watchdog with only a warning, restoring the pre-fix hole.
3. **Heartbeats bypass the replay guard** (deliberately, to protect bounded nonce capacity). A party with broker rights who replays a captured signed heartbeat within the 30 s skew can keep a replica's watchdog satisfied while its queue is unbound — the precise adversary model of Obs 1 retains a narrow suppression path. The trade-off is reasoned in-code but not named as a residual.

### 15.3 Observations carried or newly recorded

1. **Rule-8 regression test exists only in PHP** *(new, MEDIUM-ish process gap)*. CONTRACT §10.1's own test clause requires that a failing caller token still yield 401 **while the client's own session is healthy and verifiable** — a test whose client session is unusable passes vacuously. Only `axiam-php-sdk` ships that test. The other ten are structurally correct today with no guardrail against regression, which is exactly how SEC-085 survived three passes.
2. **Slug-vs-UUID diagnostic is log-only** *(Obs 6, PARTIAL)*. TS and Python now emit a genuinely well-written warning — it names the cause, the fix, and is keyed on the operator-configured value's shape rather than caller input, so it cannot be attacker-flooded. But it is a `console.warn`/`_LOGGER.warning`, latched once, emitted *after* the rejection is decided; the 401 body and error message are unchanged, and Python's warning is dropped under Django's default `LOGGING`. A slug-configured guard still starts cleanly and rejects 100% of traffic. **PHP was named in the original observation and still has no equivalent.**
3. **Kotlin's Ktor plugin does not itself reject** *(new, LOW)*. It swallows `AuthError` and leaves the user attribute absent, so a route that forgets `requireAuth()` runs unauthenticated. Java and C# make the same choice deliberately, but they sit behind Spring Security / ASP.NET authorization; Kotlin has no equivalent layer behind it. Not credential substitution — a fail-open-by-omission shape.
4. **Publisher mutex serialises narrowing mutations** *(new, availability)*. The channel slot's `Mutex` is held across the broker confirm await, so every narrowing mutation in the process now queues on one lock across a network round-trip, and the heartbeat task contends on the same lock. Previously the channel was shared without a lock. Not a security defect; a throughput cliff under a slow broker.
5. **Fail-closed 503 also suppresses the webhook** for a user row that *was* written, since the `?` precedes `emit_webhook`. Consistent with the pre-existing pattern in `groups.rs`, so not a regression, but it means a broadcast outage silently drops `user.updated`/`user.deleted` events.
6. **`AppState::for_test` is `pub` and not `#[cfg(test)]`-gated** — pre-existing, now with a second consumer.
7. **Carried, unchanged**: §10.4 residual 5 (introspect pre-auth work factor), and `with_previous_pepper` not carrying `from_pepper`'s weak-pepper warning (low impact — a previous key can only verify existing hashes, never produce one).

### 15.4 Standing status

- **Findings: none open.** SEC-071 … SEC-085 are all closed and independently verified, as are `T-145`, OBS-1 … OBS-4 and §10.4 residuals 1–4.
- **Observations open**: §15.3 items 1–7, plus the two partials in §15.2. None is an exploitable defect in AXIAM's own request path; the two worth scheduling are the **unclamped decision-cache TTL** (a one-line clamp that makes the Obs 1 mitigation robust rather than advisory) and the **rule-8 regression test in the ten SDKs that lack it**.
- **Assessment**: five successive passes have now each found something the preceding remediation's self-report missed — SEC-080 after §9, SEC-079 after §10, SEC-085 after §12, and the two partials here. That the count is falling and the severity has dropped from HIGH to *partial/observation* is the meaningful signal. The practice worth keeping is the one §14.5 adopted voluntarily: **a remediation naming its own weakest points is the cheapest possible input to the next verification.**

---

## 16. Remediation of §15 (2026-08-03)

> ⚠️ **Written by the remediation work, not by a reviewer.** Per the precedent
> §14.5 set and §15 endorsed, this section names its own weakest points (§16.5)
> rather than self-certifying. Statuses are **claims pending verification**, and
> — following §16.1 — no commit hashes are cited, for the reason §14.4 records.

### 16.1 Scope

§15 confirmed **no open finding**. What remained were two partials (§15.2) and
seven observations (§15.3). All are actioned below except the three recorded in
§16.4 as deliberately not actioned.

**A check for new findings was requested and performed.** Re-reading the merged
§14 diff against the current tree surfaced **no new finding** — the one thing it
did surface was a factual error in §15 itself (§16.3).

### 16.2 The two partials

**Obs 1 — the heartbeat's three remaining gaps, all closed.**

| Gap | What landed |
|---|---|
| **1. Unclamped TTL** | `decision_cache_ttl_secs` is now clamped to `MAX_DECISION_CACHE_TTL_SECS` (300 s). Clamped in `AuthzConfig::decision_cache_ttl_secs()` — the accessor `build_decision_cache` calls — **not** in `main.rs` where `cleanup_interval_secs` is clamped, so every construction path is covered including tests and any embedder. A bound one binary happens to apply is not a bound. |
| **2. Operator-disableable** | An interval of `0` no longer means "off". Heartbeats **cannot be disabled** while broadcast is on; out-of-range values clamp to `1..=60` with a warning. This was free to change: the `0` escape hatch was introduced in the same unreleased change, so nothing depends on it. |
| **3. Replayable heartbeat** | Acceptance is now bound to nonces *this replica published and has not yet seen back*. `build_signed_heartbeat` returns its nonce, the publisher registers it **before** publishing (the fanout can deliver the echo before the confirm returns), and the consumer consumes it once. A replayed heartbeat carries a nonce already consumed, so it cannot refresh the liveness clock — closing the path without spending the shared `NonceGuard`'s bounded capacity, which is why heartbeats bypassed it in the first place. |

Gaps 1 and 2 together are the substantive change: **neither half of the
staleness bound is operator-removable any more.** Previously an operator could
set the TTL to hours *and* switch off the mechanism that shortens the window.

**Obs 4 — service-account hashes: the diagnosis was incomplete, and the fix
follows the corrected one.** §15.2 said the seam has no production caller. That
is right, and the reason is stronger than "a caller was forgotten": **nothing in
the running server verifies a service-account secret at all.** Service accounts
are CRUD plus certificate binding; the secret is issued at create/rotate and
never presented back. So no lazy upgrade can ever fire here, and adding a caller
would mean inventing a whole authentication path — a feature, not a remediation.

What actually blocks progress is the *decision* the observation names: the v1
arm cannot be retired on the strength of "no v1 `oauth2_client` rows remain",
because this table is invisible to that reasoning. So:

- `ServiceAccountRepository::count_legacy_secret_hashes(tenant)` makes the
  backlog answerable, testing the same self-identifying prefix the verifier uses
  rather than inventing a second definition of the format;
- startup emits a warning naming the count **and the only migration route that
  exists here — rotation**, which writes the current scheme under the current
  pepper;
- the trait doc states plainly that these rows do not drain lazily and why.

The same limitation applies to the Obs 3 pepper-rotation rewrite, which drains
`oauth2_client` rows only — now covered by the same count and the same route.

### 16.3 A correction to §15

**§15.3.2 is factually wrong where it says PHP "still has no equivalent"**
slug-vs-UUID diagnostic. The PHP SDK has shipped one since the SEC-085 change
and it is on `main`: `JwksVerifier::warnOnceIfTenantComparandLooksLikeASlug()`,
called from the rule-4 rejection path, latched once per process, keyed on the
operator-configured value's shape, with `looksLikeUuid()` beside it — the same
design as the TS and Python ones §15.3.2 credits. All three named SDKs have it.

The rest of §15.3.2 stands: the diagnostic **is** log-only in all three, the 401
body is unchanged, and Python's warning is dropped under Django's default
`LOGGING`. That is a real limitation and is left as-is deliberately — see §16.4.

### 16.3a §15.3.1 — rule-8 regression tests, and a refinement to the observation

§15.3.1 recorded that the rule-8 test exists only in PHP and that "the other ten
are structurally correct today with no guardrail against regression". Auditing
the guards to write those tests refined *why* they are correct, and that changes
what the guardrail should be.

**PHP was uniquely exposed, structurally.** `AxiamClient` bundles a stateful
`Session`, and the guard called a helper that reached into it. In the other
SDKs the guard's inputs are a **verifier plus configuration** — TypeScript's
`VerifiableSession` is a config object (verifier + tenant), Python's
`_authenticate` takes `(request, verifier, configured_tenant)`, Go's middleware
holds a verifier. There is no second credential in scope for those guards to
substitute, so the literal §10.1 test — "a failing caller token yields 401 while
the client's own session is healthy and verifiable" — **cannot be written for
them**: there is no session to make healthy, and a test that stubs one in would
be testing the stub.

The guardrail that actually protects them is therefore a different one: pin that
the property stays true. Two tests per SDK — the verifier is invoked with the
caller's token and nothing else, and the guard's input surface exposes no
`session`/`client`/`refresh`/`accessToken`. Both fail the moment someone threads
a stateful client session into the guard's inputs, which is exactly how the PHP
bug became reachable.

**Status: partially actioned.** Landed in **TypeScript** and **Python**. **Not
done in Go, Java, C#, Rust, Swift, C, C++ and Kotlin** — the same two tests
apply, and the argument above says what they should assert. This is the one item
of §15 left incomplete, and it is a process gap rather than a defect: §15.1
confirmed by hand that all eleven guards reject correctly today.

### 16.4 Deliberately not actioned

1. **§15.3.2's remaining substance — the diagnostic is log-only.** Making a
   misconfigured guard *fail loudly at startup* rather than warn on first
   rejection would mean an SDK refusing to construct against a
   slug-shaped tenant. That is a breaking change to construction semantics for
   a condition that is already fail-closed, and it would fire on any deployment
   whose tenant identifier legitimately is not a UUID. A posture decision for
   the SDK owners, not a defect to patch.
2. **§15.3.5 — a 503 also suppresses the webhook** for a row that was written.
   §15 already records this as consistent with the pre-existing `groups.rs`
   pattern and not a regression. Reordering would emit an event for a change
   that has not fully taken effect, which is worse.
3. **§15.3.6 — `AppState::for_test` is `pub` and not `#[cfg(test)]`-gated.**
   Pre-existing; gating it would break the integration tests that legitimately
   construct state across crate boundaries. Worth a follow-up that introduces a
   `test-util` feature, not a change to smuggle into a security remediation.
4. **§10.4 residual 5** (introspect pre-auth work factor) — carried unchanged,
   as it has been since §10.

### 16.5 What a verifier should look at hardest

1. **The heartbeat nonce lifecycle.** The registration happens before the
   publish deliberately, to avoid losing a race with the echo. Confirm there is
   no path that registers a nonce and then fails to publish in a way that lets
   the outstanding set fill with nonces that can never be answered — the ring is
   bounded at 8, which is the backstop, but the reasoning is worth re-deriving.
2. **The publisher lock change.** The guard is now released before the confirm
   await, and the failure path re-acquires and clears **only if the slot still
   holds the same channel**. Confirm that compare-before-clear is correct under
   a concurrent reopen, and that the fail-closed property (an unconfirmed
   broadcast still returns `Err`) is genuinely unchanged.
3. **The TTL clamp's placement.** It is on the accessor, not the field. Confirm
   no caller reads `decision_cache_ttl_secs` directly and bypasses it.
