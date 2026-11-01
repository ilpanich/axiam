# CONTRACT 1.65 — cross-SDK conformance review (the 1.2.0 release)

**Date:** 2026-10-31
**Plan item:** W4.13 of [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md) §4 (W4 row
W4.13); the decisions read are §5 D-N1 … D-N35, D-N16, D-N21 … D-N24, D-N30 and D-N32 … D-N34 in particular.
**Scope:** the eleven `claude/bold-mayer-wpd3kv` branches, each a draft PR against its repository's `main`, vendoring
`sdks/CONTRACT.md`, `sdks/openapi.json`, `sdks/management-registry.json` and `proto/` from axiam `76d35d9`
(contract 1.65, §34.9 (a) … (j)). The rules read are §37 (§37.1 … §37.9), §12.1 (rule 5's amendment, the `idp_hint`
paragraph, note 12), §26.2 rule 8 and §26.6, §9 (the refresh-reuse paragraph and its confirmation test), §15.2
rule 10, §21.2, §8 and the record §34.9.

| SDK | Repo | Head read | PR |
|---|---|---|---|
| Rust | `axiam-rust-sdk` | `3ce575d` | #145 |
| TypeScript | `axiam-typescript-sdk` | `df17b53` | #157 |
| Python | `axiam-python-sdk` | `51eb8d3` | #107 |
| Java | `axiam-java-sdk` | `e2ece70` | #127 |
| Kotlin | `axiam-kotlin-sdk` | `97e3706` | #82 |
| C# | `axiam-csharp-sdk` | `2e056b0` | #115 |
| PHP | `axiam-php-sdk` | `f47a8a4` | #89 |
| Go | `axiam-go-sdk` | `cf1128c` | #107 |
| Swift | `axiam-swift-sdk` | `4b10728` | #80 |
| C | `axiam-c-sdk` | `c29f78e` | #79 |
| C++ | `axiam-cplusplus-sdk` | `999888a` | #82 |

**Outcome.** All eleven ports of (a) and (b) are present, every vendored file is byte-identical to `76d35d9`, every
§37.9 / `idp_hint` / §9-confirmation suite that could be run here is green, and the core of §37 is right
everywhere: the exact form-key set with empties omitted, the **raw** nonce byte for byte, `provider` verbatim, no
`openid` and no empty `scope=`, local refusals before any request (discovery included), `client_id` alone for a
public client, one request with no SDK or transport replay, ID-token validation under §12.4 with the raw nonce, and
no adoption beyond each SDK's existing posture. Every `native_nonce` passes the fixed vector and draws 32 CSPRNG
bytes. Swift's new `oidcRefresh` single-flight guard (D-N34) is correct (§3, Swift row 7).

**Three findings are Medium**, and all three are about what happens outside the mocks:

- **Python maps AXIAM's own route-level 429 to `NetworkError` (C165-01).** `/oauth2/token` sits behind two route
  limiters whose `429` bodies are `{"error":"rate_limit_exceeded"}` and `{"error":"rate_limit_exceeded","retry_after":N}`
  — no `error_description` (`crates/axiam-api-rest/src/middleware/rate_limit_shared.rs:105-110`,
  `extractors/rate_limit.rs:209-224`, mounted at `server.rs:2312-2322`). Python's token-response mapper requires a
  description, so that body is a `NetworkError`, which breaks the §37.3 429 row and is exactly §37.9 test 9's mock.
  The Python test passes only because its mock adds `"error_description":"slow down"`. Probed: both bodies give
  `NetworkError('network error: token request failed')`, sync and async. This is C164-01 again, on a second call site.
- **C grows its generated structs by inserting members mid-struct and keeps SOVERSION 2 (C165-02).** D-N32 asked
  this review to decide; the answer is a bump. The members are not appended: `native_login` lands between
  `metadata_url` and `protocol`, `default_idp` between `created_at`/`browser_sso` and `dpop_*`, `oauth2` inside
  `axiam_mgmt_security_settings`, `refresh_reuse_response` inside `set_org_settings` and
  `tenant_settings_override`. Request structs are caller-allocated (`= {0}` in the SDK's own tests, positional
  initialisers in its examples), and every offset after the insertion point moves in the library-allocated response
  structs too. A binary built against 1.1.x and loaded against this `libaxiam.so.2` reads and writes the wrong
  members. The CHANGELOG says "an appended member, so nothing is source-breaking", which is not what the header does.
- **C++ changes the layout of generated model structs and keeps SOVERSION 4 (C165-03).** The overloads keep the
  *function* ABI, as the PR says, but `FederationConfigResponse` gains a `NativeLoginTrustResponse native_login`
  member mid-struct and eight other model structs gain `std::optional` members. The CHANGELOG's "so the ABI is too"
  is false; the 1.1.1 precedent (SOVERSION 3 → 4 for two types that gained members) applies.

Twelve Low and nine Informational findings follow (§4). **Six are contract text** (C165-09 … -13, -19). One
question goes to the maintainer (§5): whether `oidc_par` should carry a hint that `oidc_begin` already put on the
URL, where the SDKs split 9 / 1 / 1.

## 1. Method

The method is the [1.64 review](sdk-contract-1.64-conformance-review.md)'s (its §1), re-cut for 1.65:

- **One reviewer pass per SDK,** reading `git diff origin/main...HEAD` and the files it calls into (the token POST,
  the OAuth2 error mapper, the transport's retry, redirect and refresh layers), against §37 and the brief's list.
  Every cell carries a `path:line` on the head read. **The code was read, not the tests**; a test was read only to
  see what its mock sends.
- **Claims were checked, not trusted.** CHANGELOGs, PR bodies (read through the GitHub tools: every PR has a "Notes
  for the cross-SDK conformance review" section, consolidated in §3 and §4) and doc comments were treated as claims.
  Where the code disagreed, the code won (C165-02, -03, -08).
- **Probed against AXIAM's real bodies, not the mocks** (the 1.64 lesson). The server's wire shapes for this grant,
  read from `crates/axiam-api-rest/src/handlers/oauth2.rs` (`handle_provider_id_token`, `:5170-5372`;
  `build_oauth2_error_response`, `:5716-5734`), `crates/axiam-oauth2/src/provider_id_token.rs:96-116`,
  `:297-310` and `crates/axiam-api-rest/tests/provider_id_token_test.rs`:

  | Case | Status | Body | Headers |
  |---|---|---|---|
  | every refusal of the provider token | 400 | `{"error":"invalid_grant","error_description":"the provider ID token is not acceptable"}` | `Cache-Control: no-store` |
  | the grant's own bucket (`oauth2_provider_id_token:{tenant}:{addr}`) | 429 | `{"error":"rate_limit_exceeded","error_description":"too many native sign-in attempts from this address"}` | `Retry-After: 60` |
  | the route limiters in front of `/oauth2/token` (`token_per_min`) | 429 | `{"error":"rate_limit_exceeded"}` or `{"error":"rate_limit_exceeded","retry_after":N}` | `Retry-After: N` |
  | datastore / `login.post_auth` user read | 500 | `{"error":"server_error","error_description":"the sign-in could not be completed; retry shortly"}` | — |
  | client authentication | 401 | `{"error":"invalid_client",…}` | `WWW-Authenticate: Bearer realm="axiam"` |
  | no caller address | 400 | `{"error":"invalid_request","error_description":"the caller's network address could not be determined"}` | — |

  Each SDK's mapper was traced (or probed) on the description-less 429 and the 500 `server_error` body. The
  description-less 429 is the one that matters: §37.3's row says the bucket's body, but a caller meets the route
  limiter's body first under load, and §37.9 test 9 mocks that shape.
- **Transport replay.** For each SDK: the client the native POST rides, whether a §16 retry layer, a 401→refresh
  interceptor, OkHttp's `retryOnConnectionFailure`, .NET's pooled-connection re-send, or a redirect follower can
  send the body a second time.
- **Runs.** Wherever a toolchain existed, the touched-area tests ran in a throw-away worktree under the session
  scratchpad (removed afterwards); one probe test was added to Python's copy (C165-01). No SDK repository was
  modified.

| Repo | Run by the reviewer (scratch worktree at the head read) |
|---|---|
| rust | `cargo test --no-default-features --features rest --test contract_165_test`: 20 passed |
| typescript | `npm ci`; `vitest run test/node/nativeSignIn.test.ts test/node/idpHint.test.ts test/node/oidcTokenOps.test.ts` (proxy variables unset): 3 files, 59 passed |
| python | venv, `pip install -e .[dev]`; `pytest tests/test_native_sign_in.py tests/test_idp_hint.py tests/test_oidc_refresh_single_flight_invariants.py`: 89 passed; C165-01 probe: 4 cases fail as described |
| java | `./mvnw -Dtest=NativeSignInTest,IdpHintTest,RefreshReuseInvalidGrantTest test` (JDK 21): 14 + 5 + 1 passed |
| kotlin | `./gradlew test --tests '*NativeSignInTest' '*IdpHintTest' '*OidcRefreshReuseTest'`: 14 + 5 + 1 passed |
| csharp | `dotnet test --filter NativeLogin|IdpHint|OidcRefreshAndCredentials` (.NET 10): 46 passed |
| php | **none**: `composer install` could not fetch the dev dependencies (GitHub zipballs and `git clone` blocked: "Could not authenticate against github.com"). Read only; the PR reports phpunit 2119 tests green |
| go | `go test -count=1 .` (root package, includes `contract_165_test.go`): ok |
| swift | **none**: no Swift toolchain here. Read only; the single-flight guard was traced by hand (§3) |
| c | cmake Debug build with tests; `ctest -R 'native|idp|singleflight|abi|version'`: 6/6 passed (`test_native_sign_in`, `test_idp_hint`, `test_oidc_singleflight`, `test_singleflight`, `test_version_policy`, `abi_soname` — the last passes because it still pins `libaxiam.so.2`, C165-02) |
| cplusplus | cmake Debug build (g++, tests on); `ctest`: 1/1 (`axiam_cpp_tests`: 1667 cases, 6555 checks, 0 failed). Not run: sanitizer, valgrind, clang legs |

**Severity** follows the 1.64 scale: **Medium** (a normative rule broken in a way a caller meets, or a release
defect), **Low** (a deviation with a narrow trigger and no data loss, an incomplete required test, or a required
document statement missing), **Informational** (posture, text or test strength that hides no defect). **High** and
**Critical** are reserved for an exploitable security defect or data loss; none was found. A defect in several SDKs
is one finding.

## 2. Vendoring

`sha256` of the four artifacts at `76d35d9` and at each head:

| Artifact | `76d35d9` | Result |
|---|---|---|
| `sdks/CONTRACT.md` | `e1d17fc91e1874ac…` | identical in all eleven |
| `sdks/openapi.json` | `c23676a3cade910b…` | identical in all eleven |
| `sdks/management-registry.json` | `d0d588cb95e0279e…` | identical in all eleven |
| `proto/axiam/v1/*.proto` (5 files) | `cmp` | identical in the nine that vendor them; C and C++ vendor none (`REST_ONLY_REPOS`) |

`scripts/check-sdk-artifact-drift.py --local-root` over bare clones whose `origin/main` was pointed at each head:
**11 repos, 0 artifact problems** (10 artifacts in Rust with `vendor/axiam-opaque/src/lib.rs`, 9 in each other gRPC
SDK, 5 in C and C++). Against the real `origin/main` it reports every repository stale, which is expected until the
eleven PRs merge. Each PR's regeneration check (`gen_management.py --check`, Go's `genmanagement -check`, TS's
`gen-management.mjs --check`) is reported clean in its PR body; the reviewer re-ran the Rust, Go, Python, Java,
Kotlin and C# suites that include the regenerated-surface tests, all green.

## 3. Per-SDK reports

`path:line` is on the head read. A cross-SDK finding is listed in every report it touches and described once, in §4.
Rows that conform in every SDK and need no evidence beyond the summary (form-key set, raw nonce, `provider`
verbatim, no `openid`, the fixed vector, 32 CSPRNG bytes, lower-case hex) are collapsed into row 1.

---

### Report — rust — `3ce575d` (PR #145)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `ProviderIdTokenForm` has exactly `grant_type`, `client_id`, `provider`, `id_token`, `nonce`, optional `scope`/`resource`/`client_secret` with `skip_serializing_if`; nonce `expose()`d byte for byte; `scope` only when `Some`. `Some(vec![])` would send `scope=` empty (C165-20). | `src/oidc/native.rs:113-126`, `:199-210` |
| 2 | rule 4 and order | Empty inputs → `local_refusal` (`ValidationError`) before `oidc_client_id_or_err`, the tenant and discovery. | `native.rs:176-197` |
| 3 | rule 5 | `client_secret` only when configured; no Basic. No `private_key_jwt` (PR note), so such a client meets `invalid_client` — conformant under rule 5 ("only when its caller configured one"). | `native.rs:198` |
| 4 | rule 10 / transport | `post_token` → `idp_form_post` on `http_bare`: no §16 layer, no 401 interceptor. Same-host redirects followed (C165-14). | `src/oidc/exchange.rs:614-640`; `src/client.rs:1123-1128`, `:522-560` |
| 5 | §37.3 mapping | `oauth2_error_or_fallback` dispatches on a non-empty `error` at any status; `error_description` is `#[serde(default)]`, so the route-limiter 429 maps. 500 `server_error` → `OAuthProtocolError`; body-less 5xx → `from_http_status`. `Retry-After` not exposed (C165-17). | `exchange.rs:97-101`, `:347-359` |
| 6 | rule 8, §12.4 | `to_token_set(wire, …, Some(raw nonce))`. | `native.rs:215` |
| 7 | rule 9 | Not adopted (same as `login_client_credentials`, `device_login`). | `native.rs:25-26` |
| 8 | rule 12, §37.6 | `id_token`/`nonce` are `Sensitive<String>`; the form is deliberately not `Debug`; `ProviderNonce.raw` `Sensitive`, test asserts the `Debug` rendering redacts it. | `native.rs:52-61`, `:111-113`, `:232-238` |
| 9 | `native_nonce` | `random_url_safe_token(CSPRNG_BYTES)` (32), `hex::encode(Sha256)`; vector unit test. | `native.rs:63-89`, `:224-230` |
| 10 | `idp_hint` | Emitted once after the eight; option drops a same-named extra, else the first extra passes once; bounds by `len()` bytes. PAR carries the hint from the begin URL (`idp_hint_of`) into the body; redirect stays `client_id`+`request_uri`. An empty `axiam_idp_hint` *extra* accepted by `oidc_begin` is refused at `oidc_par` (C165-20). | `src/oidc/authorize.rs:55-85`, `:314-356`; `src/oidc/par.rs:165-172`, `:224-245` |
| 11 | §9 confirmation | 8-caller `invalid_grant` burst, one wire call (`tests/contract_165_test.rs`). | — |
| 12 | Source compatibility | `OidcBeginParams` gains a pub field (listed). Generated request structs without `Default` (e.g. `CreateFederationConfigRequest`) gain pub fields; listed generically ("the generated request types named above"). | `CHANGELOG.md:39-45` |
| 13 | D-N33 | **Missing** (C165-04). `FederationConfigResponse.native_login` is a required, non-defaulted field, so an older server's response fails to decode. | `src/management/models.rs:2217` |

---

### Report — typescript — `df17b53` (PR #157)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `URLSearchParams` built key by key; `scope` only when `scopes` is non-empty; `resource` only when set; `#appendClientSecret`. | `src/node/oidc.ts:1249-1262` |
| 2 | rule 4 and order | `ValidationError` for empty `provider`/`idToken`/`nonce`, then `#resolveTenantId` before discovery. | `oidc.ts:1229-1247` |
| 3 | rule 10 / transport | `#postCibaForm` (`validateStatus: () => true`, no `withRetry`); a transport failure is a `NetworkError` built without the axios cause (whose `config` holds the form). `session.axios` has no `maxRedirects` override, so Node's follow-redirects re-sends a 307/308 body, cross-host included (C165-14). | `oidc.ts:2772-2785`; `src/rest/session.ts:536` |
| 4 | §37.3 mapping | `cibaError` → `oauth2ErrorFromBody` first (description optional), then `mapHttpStatusToError`: route-limiter 429 and 500 `server_error` both `OAuthProtocolError`. `Retry-After` not exposed (C165-17). | `oidc.ts:902-907`; `src/core/errorMapper.ts:137-147` |
| 5 | rules 8, 9 | `#toTokenSet(…, nonceValue)`; not adopted — PR note: "follows `deviceLogin`", while `loginClientCredentials` offers an opt-in `adoptAsCredential` (C165-12). | `oidc.ts:1272`; `src/node/oidcTypes.ts:477` |
| 6 | rule 12, §37.6 | `idToken`/`nonce` accept `Sensitive` or a bare string (§15.5 allows it); `ProviderNonce.raw` is `Sensitive`. | `oidc.ts:1229-1241`; `src/node/oidcPkce.ts:85-88` |
| 7 | `idp_hint` | `checkIdpHint` (`Buffer.byteLength`), emitted once, extra dropped when set. `oidcPar` takes `idpHint` as an argument and **does not read the begin URL's hint** — documented at `oidcTypes.ts:316-320` (C165-11, §5 Q1). | `oidc.ts:403-431`, `:1029-1059`, `:1754`, `:1787-1791` |
| 8 | Source compatibility | Additive except `FederationConfigResponse.native_login`, a new **required** interface member (a type-level break for code that builds that object, e.g. test fixtures); not listed (C165-08). | `src/management/models.ts` |
| 9 | D-N33 | **Missing** (C165-04). TS does not validate responses at runtime, so an older server's response decodes with `native_login` `undefined` despite the type; the CHANGELOG should say both. | — |

---

### Report — python — `51eb8d3` (PR #107)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `_provider_id_token_form`: the five, `client_secret` via `_append_client_secret`, `scope` only when `scopes` truthy, `resource` when not `None`. | `src/axiam_sdk/_oidc.py:1012-1065` |
| 2 | rule 4 | `ValueError` (the language's programming-error type; rule 4 allows it) for empties and for a nonce over 512 bytes (MAY), before the tenant and discovery. | `_oidc.py:1037-1052`; `_client.py:1964-1968` |
| 3 | rule 10 / transport | `_rest_send_sync` → `_session._send_sync`: no 401 interceptor, no httpx transport retries, httpx does not follow redirects by default. Transport failures → `network_error_from_transport` without chaining the request. | `src/axiam_sdk/_session.py:447-482`; `_errors.py:375-386` |
| 4 | §37.3 mapping | **Fails on the route-limiter 429** (C165-01): `_handle_token_response` → `error_from_oauth2_response(…)` with `description_optional=False`. The 500 `server_error` body carries a description and maps correctly; a 429 *with* a description gets `retry_after_ms`. | `_oidc.py:1316-1317`; `_errors.py:283-313`, `:341-372` |
| 5 | rules 8, 9 | Raw nonce to `_handle_token_response`; returned, not adopted. | `_client.py:1975-1977`; `_async_client.py:740-…` |
| 6 | rule 12, §37.6 | `SecretStr` accepted; `ProviderNonce.raw: SecretStr`. | `src/axiam_sdk/_models.py:551-571` |
| 7 | `native_nonce` | 32 bytes, `hashlib.sha256(raw.encode("utf-8")).hexdigest()`; method on both clients, sync. | `src/axiam_sdk/_oidc_pkce.py:79-95`; `_oidc.py:1067-1079` |
| 8 | `idp_hint` | `_validate_idp_hint` (UTF-8 bytes; `ValueError`); dropped extra; PAR takes `idp_hint` as a keyword and does not read the begin URL (C165-11). | `_oidc.py:448-470`, `:938-964`, `:1152-1156` |
| 9 | Tests | §37.9 test 9's mock adds `error_description` (`tests/test_native_sign_in.py:463`; `_oauth_error` always adds one, `:114-117`), so test 9 and test 12's rate-limit case do not exercise the server's shape (C165-01). | — |
| 10 | Source compatibility / D-N33 | New required `native_login` on `FederationConfigResponse` (fixture adjusted); not listed (C165-08). D-N33 **missing** (C165-04). | — |

---

### Report — java — `e2ece70` (PR #127)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `FormBody.Builder` with the five; `scope` only when non-empty; `resource` only when non-empty; `appendOidcClientSecret`. | `src/main/java/io/axiam/sdk/AxiamClient.java:2675-2689` |
| 2 | rule 4 | `LocalRefusal` (`ValidationError`) for empties, then client id, tenant, discovery. | `AxiamClient.java:2656-2674` |
| 3 | rule 10 / transport | `sessionlessHttpClient`: interceptors cleared, no cookie jar, `Authenticator.NONE`, no redirects, `retryOnConnectionFailure(false)`. `X-Tenant-ID` set by hand. `IOException` → `NetworkError` naming only the class. | `AxiamClient.java:2691-2708`; `src/main/java/io/axiam/sdk/internal/Sessionless.java:37-49` |
| 4 | §37.3 mapping | `fromOAuth2ErrorAtAnyStatus`: description optional, any status; 429 carries `retryAfterSeconds`. Route 429 and 500 both map. | `errors/ErrorMapper.java:164-177`, `:226-246` |
| 5 | rules 8, 9, 12 | `buildTokenSet(…, nonce.expose())`; not adopted; `ProviderNonce(Sensitive raw, String hashed)` record (accessor returns the wrapper). | `AxiamClient.java:2710`; `oidc/ProviderNonce.java:32-63` |
| 6 | `idp_hint` | New overloads; bytes bound; extra dropped; PAR argument (C165-11). | `AxiamClient.java:2405-2468`, `:5346-5386` |
| 7 | Source compatibility | Record components inserted alphabetically into nine records; the CHANGELOG says so under *Changed* ("a caller using a record's canonical constructor … must add the new argument"). Adequate; a `### Breaking` heading would match Rust's. | `CHANGELOG.md:30-35` |
| 8 | D-N33 | **Missing** (C165-04). | — |

---

### Report — kotlin — `97e3706` (PR #82)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `buildForm` drops `null` pairs; `scope` only for a non-empty list. | `src/main/kotlin/io/axiam/sdk/oidc/OidcSupport.kt` (`loginWithProviderIdToken`) |
| 2 | rule 4 | `ValidationError` (a `NetworkError` subtype, the `cibaInitiate` precedent) before `resolveTenantId` and discovery; `requireClientId` first. | same |
| 3 | rule 10 / transport | `OneShotBody` on the shared `httpClient`, so OkHttp neither retries on connection failure nor follows a 307/308 with it; the client has no 401-reactive interceptor (`OidcSupport.kt:2085-2106`). | `internal/OneShotBody.kt:21-26` |
| 4 | §37.3 mapping | `fromOAuth2ResponseAtAnyStatus` (description optional) + `retryAfter` on a 429. | `errors/ErrorMapper.kt:68-96` |
| 5 | rules 8, 9, 12 | Raw nonce expected; not adopted; `ProviderNonce(raw: Sensitive<String>, hashed)`. The canonical signature is a params object (`ProviderIdTokenLoginParams`) rather than three positionals — the SDK's convention for §12, accepted (Info, not raised). | `oidc/OidcTypes.kt` |
| 6 | `idp_hint` | Trailing defaulted field on both params types; map semantics give one value; PAR argument (C165-11). | `OidcSupport.kt:451` |
| 7 | Source compatibility | **Not listed** (C165-08): generated data classes gain constructor parameters inserted alphabetically (`nativeLogin` before `protocol` in `CreateFederationConfigRequest`; a required `nativeLogin` with no default in `FederationConfigResponse`), which breaks positional calls, `componentN`/`copy` and JVM binary compatibility. | `management/models/CreateFederationConfigRequest.kt`, `FederationConfigResponse.kt` |
| 8 | D-N33 | **Missing** in CHANGELOG/README (the PR body states it) (C165-04). | — |

---

### Report — csharp — `2e056b0` (PR #115)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** Dictionary of the five, secret if configured, `scope` for `Count > 0`, `resource` when non-empty. | `Axiam.Sdk/AxiamClient.NativeLogin.cs:56-72` |
| 2 | rule 4 | `ArgumentException` (programming-error type) for empties, then client id, tenant, configuration. | `NativeLogin.cs:34-53` |
| 3 | rule 10 / transport | `PostOAuth2FormAsync(…, retryEligible: false)`: not marked retry-eligible, so the §34.2 P11 fresh-connection policy applies (no pooled re-send); `AllowAutoRedirect = false` on the factory's handlers. | `AxiamClient.Oidc.cs:1306-1335`; `Rest/AxiamHttpClientFactory.cs:98`, `:193` |
| 4 | §37.3 mapping | `MapOAuth2ErrorAnyStatusAsync` (`TryReadOAuth2Error`, description optional) then `HttpStatus`/`RetryAfter` on the 429. Both are `internal`, so `Retry-After` is not exposed to callers (C165-17). | `NativeLogin.cs:93-103`; `AxiamClient.ClientRegistration.cs:336-355` |
| 5 | rule 9 | Not adopted; an `adoptAsCredential` parameter exists and always throws `NotSupportedException`, copying `LoginClientCredentialsAsync` (C165-18). | `NativeLogin.cs:24-31` |
| 6 | rules 8, 12 | `IdTokenExpectations(…, rawNonce, …)`; `Sensitive<string>` inputs; `sealed record ProviderNonce(Sensitive<string> Raw, string Hashed)`. | `NativeLogin.cs:88-90`; `Auth/Oidc/OidcTypes.cs` |
| 7 | `idp_hint` | `ValidateIdpHint` (`ArgumentException`, UTF-8 byte count); extra dropped; PAR argument (C165-11). | `AxiamClient.Oidc.cs`; `AxiamClient.Par.cs:45-…` |
| 8 | Source compatibility | `init` properties; additive. The response's required `NativeLogin` is noted. | `CHANGELOG.md:41` |
| 9 | D-N33 | **Partial** (C165-04): "a required response member, as the server always sends it" — the floor (server ≥ 1.2.0) is not stated. | `CHANGELOG.md:41` |

---

### Report — php — `f47a8a4` (PR #89)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** Five keys, `scope` for a non-empty array, `resource` when not null, `appendClientSecret`. | `src/Oidc/OidcClient.php:768-830` |
| 2 | rule 4 | Empties and the 512-byte nonce refused **with `AuthError`** — the §2 taxonomy type, neither `ValidationError` (which this SDK has: `src/Management/ValidationError.php:18`) nor the programming-error type; `idpHint` uses `\InvalidArgumentException` (C165-05). | `OidcClient.php:786-797` |
| 3 | rule 10 / transport | `postToken` → `postForm` on `plainHttp` (no `RefreshMiddleware`, by the documented invariant; no retry middleware). Guzzle's default `allow_redirects` is on for `plainHttp` (only `bareHttp` sets `false`), so a 307/308 re-sends the form cross-host (C165-14). `NetworkError::fromException` chains a sanitised stand-in, not the Guzzle exception (which holds the request). | `OidcClient.php:2620-2633`, `:2932-2944`; `src/AxiamClient.php:434`, `:445`, `:514-535`; `src/Core/NetworkError.php:153-165` |
| 4 | §37.3 mapping | `ErrorMapper::fromOAuth2Response`: any status, description optional, `retryAfterMs` and status carried. | `src/Core/ErrorMapper.php:88-103` |
| 5 | rule 9 | Opt-in `adoptAsCredential`, the same flag as `loginClientCredentials` (`OidcClient.php:677-705`). Conformant (C165-12). | `OidcClient.php:823-825` |
| 6 | `idp_hint` | `assertIdpHint` (`strlen` bytes); `AuthorizationRequest` gains `?string $idpHint` (trailing, defaulted) and `oidcPar` falls back to it (`$idpHint ??= $request->idpHint`) — the only SDK that serves both sources (C165-11). | `OidcClient.php:441`; `src/Oidc/AuthorizationRequest.php` |
| 7 | Source compatibility | Constructor parameters inserted alphabetically; README and CHANGELOG tell callers to use named arguments. Adequate. | `CHANGELOG.md` (Unreleased) |
| 8 | D-N33 | **Substantially met** ("a response without `native_login` (an older server) fails to decode"); the exact floor sentence is still worth adding (C165-04). | `CHANGELOG.md:54-56` |

---

### Report — go — `cf1128c` (PR #107)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms** on the keys; `scope` for `len > 0`, `resource` when non-empty. **But `client_id` is sent even when empty** (C165-06). | `oidc_native.go:150-162` |
| 2 | rule 4 | Empties refused with plain `errors.New` before the tenant and discovery; no client-id check at all (C165-06). The package has `*ValidationError` / `localRefusal` (`management_errors.go:101`, `oidc_registration.go:309`) (C165-07). | `oidc_native.go:128-145` |
| 3 | rule 10 / transport | `postOAuth2FormMapped` → `doRequest`: jar suppressed for `/oauth2/*`; `net/http` does not replay a POST. `CheckRedirect` follows up to 10 hops, cross-host included, stripping only three headers, so a 307/308 re-sends the form (C165-14). | `oidc_wire.go:246-270`; `client.go:726-737`, `:885-917` |
| 4 | §37.3 mapping | Grant-local `mapNativeSignInError`: a 5xx with an `error` body → `*OAuthProtocolError`; below 500 the shared `mapOAuth2ErrorResponse` maps 400/401 with a body and the 429 `rate_limit_exceeded` (with `RetryAfter`). Route 429 and 500 map. The PR asks the contract to say a grant-local mapper is allowed (C165-19). | `oidc_native.go:205-227`; `oidc_wire.go:287-313` |
| 5 | rules 8, 9, 12 | Raw nonce; opt-in `AdoptAsCredential` as `LoginClientCredentials`; `ProviderNonce{Raw Sensitive, Hashed}`. | `oidc_native.go:170-188` |
| 6 | `idp_hint` | `*string`, bytes bound, extra dropped; PAR argument (C165-11). Errors are `fmt.Errorf` (C165-07). | `oidc.go` (`validateIdpHint`, `OidcBegin` `:357-…`); `oidc_par.go:128-…` |
| 7 | Source compatibility | CHANGELOG: "Nothing here is source-breaking". Generated structs gain fields, which breaks only unkeyed composite literals (Go's compatibility convention tolerates this); one sentence would say so (C165-08). | `CHANGELOG.md` (Unreleased) |
| 8 | D-N33 | **Missing** (C165-04). `encoding/json` does not enforce required members, so an older server's response decodes with `NativeLogin` zero; state that. | — |

---

### Report — swift — `4b10728` (PR #80)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** | `Sources/AxiamSDK/Oidc/NativeSignIn.swift:163-178` |
| 2 | rule 4 | `ManagementChecks.refusal` (validation `NetworkError`) for empties; `requireOidcClientID` and the new `requireOidcTenantUUID` before discovery. | `NativeSignIn.swift:149-160`; `Oidc/OidcInternals.swift:233-245` |
| 3 | rule 10 / transport | `bareSend(…, retry: .never)`. The transport sets no redirect delegate, so `URLSession` follows redirects (C165-14; not verified on Linux FoundationNetworking). | `NativeSignIn.swift:180-191` |
| 4 | §37.3 mapping | `oidcMapGrantError`: a non-empty `error` at any status → `AxiamError.auth(AuthError(oauthError:…))`; `error_description` optional. `Retry-After` not exposed (C165-17). | `OidcInternals.swift:425-434` |
| 5 | rules 8, 9, 12 | Raw nonce; not adopted; `ProviderNonce` with a redacting `description`/`debugDescription`. | `NativeSignIn.swift:28-38`, `:198` |
| 6 | `native_nonce` | 32 bytes via `UInt8.random(in:)` (`SystemRandomNumberGenerator`, a CSPRNG on every supported platform; the same source `OidcPkce` uses), base64url without padding, `%02x`. | `NativeSignIn.swift:64-76`; `Oidc/OidcPkce.swift:19` |
| 7 | **§9 single-flight (D-N34)** | **Correct.** The guard lives on the `AxiamClient` actor: lookup and insert of `oidcRefreshFlights[key]` happen with no suspension between them, so the first caller of a burst creates the one `Task` and every later caller awaits the same `task.value` (one wire call, one shared outcome, including the error). The leader vacates with an identity check (`id`), so a stale leader cannot clear a newer slot (rule 6c). No deadlock: the task body runs on the actor while the leader is suspended in `await task.value`, and actor re-entrancy lets joiners in. Cancellation of a caller does not cancel the unstructured task, so the burst still gets the outcome. The key is SHA-256(tenant ‖ "\n" ‖ token) in hex: the map never holds the token, and the token lives only in the task's capture while in flight. One edge, conformant: a call arriving after the task finished but before the leader resumed joins the settled outcome (rule 6b's "just-settled"), never a second wire call with the spent token. | `Oidc/Oidc.swift:189-232`; `AxiamClient.swift:99-102` |
| 8 | `idp_hint` | `checkIdpHint` (utf8 count); removes an `axiam_idp_hint` already on the discovery endpoint when set; PAR argument (C165-11). | `Oidc.swift:83-112`; `Oidc/Par.swift:60`, `:102` |
| 9 | Source compatibility | `oidcBegin` gains a defaulted labelled parameter (source-compatible). Generated `FederationConfigResponse` gains a non-defaulted `nativeLogin` init parameter; not listed (C165-08). | `Management/Generated/ManagementModels.swift` |
| 10 | D-N33 | **Missing** in CHANGELOG/README (the PR body states it) (C165-04). | — |

---

### Report — c — `c29f78e` (PR #79)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `oidc_form_add` drops `NULL` and empty values, so `scope=""` is omitted; the signature takes a space-joined `scope` string. | `src/oidc_native.c` (`axiam_login_with_provider_id_token`); `src/oidc.c:85-101` |
| 2 | rule 4 | `refuse_empty` → `AXIAM_ERR_NETWORK` with `transport_cause` 400, C's local-refusal convention (§34.4 C-16), before client id, tenant and discovery. | `oidc_native.c` (`refuse_empty`) |
| 3 | rule 10 / transport | `oidc_token_grant(…, retryable 0, …)`; libcurl `FOLLOWLOCATION 0`. The form buffer is scrubbed (`oidc_form_dispose`) and the response body zeroed. | `src/oidc.c:926-982`; `src/transport_curl.c:127` |
| 4 | §37.3 mapping | `oidc_map_grant_error`: a non-empty `error` at any status → `AXIAM_ERR_AUTH` with `oauth_error`; message `"<error>: <description>"`. `error_description` has no field of its own (message only) and `Retry-After` is not exposed (C165-17, C165-21). | `src/oidc.c:495-532`; `include/axiam/error.h:48` |
| 5 | rules 8, 9, 12 | Raw nonce to `oidc_parse_token_set`; not adopted; `axiam_provider_nonce_t.raw` is a `Sensitive` handle. | — |
| 6 | `native_nonce` | `RAND_bytes` 32, `axiam_b64url_encode`, EVP SHA-256, lower-case hex. | `oidc_native.c` (`axiam_native_nonce`, `oidc_nonce_hash_hex`) |
| 7 | `idp_hint` | New `_with_hint` functions; the old ones unchanged. | `include/axiam/oidc.h`; `src/oidc_par.c:127` |
| 8 | **ABI (D-N32)** | **SOVERSION must move to 3** (C165-02). Members inserted mid-struct in `axiam_mgmt_create_federation_config_request` (`native_login` at `:2860`), `axiam_mgmt_federation_config_response` (`:4168`), `axiam_mgmt_update_federation_config_request` (`:9259`), the three OAuth2 client structs (`default_idp`), `axiam_mgmt_security_settings` (`oauth2`), `axiam_mgmt_set_org_settings` and `axiam_mgmt_tenant_settings_override` (`refresh_reuse_response`). Requests are caller-allocated. | `include/axiam/management_models.h`; `CMakeLists.txt:136`; `tests/CMakeLists.txt:487-490`; `CHANGELOG.md:11-12` |
| 9 | D-N35 | `AXIAM_VERSION_PATCH 3` and the version test, as decided. | `include/axiam/axiam.h` |
| 10 | D-N33 | **Missing** (C165-04). | — |

---

### Report — cplusplus — `999888a` (PR #82)

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | §37.1 form, rules 2, 3, 7 | **Conforms.** `Form::add` skips empty values, so an empty joined `scope` is omitted. | `src/oidc.cpp:62-75`; `login_with_provider_id_token` |
| 2 | rule 4 | `std::invalid_argument` for empties (programming-error type), then client id, tenant, discovery. | same |
| 3 | rule 10 / transport | `token_grant(…, retryable=false, …)`; `CURLOPT_FOLLOWLOCATION 0`. | `src/http_curl.cpp:480` |
| 4 | §37.3 mapping | Body-first mapper (the C164-03 reading): route 429 and 500 `server_error` → `OAuthProtocolError`; `retry_after()` populated (test 9 asserts 7000 ms). | `tests/test_native_signin.cpp:584-600` |
| 5 | rules 8, 9, 12 | Raw nonce; not adopted; `ProviderNonce{Sensitive<std::string> raw; std::string hashed;}`. | `include/axiam/oidc.hpp` |
| 6 | `native_nonce` | `random_b64url()` (32 `RAND_bytes`), `digest_hex`. | `src/oidc.cpp:364-372` |
| 7 | `idp_hint` | New overloads (function ABI kept); `oidc_begin` takes no extras, so the duplicate rule is trivially met; PAR argument (C165-11). | `include/axiam/client.hpp`; `src/oidc.cpp:2155` |
| 8 | **ABI (D-N32)** | **SOVERSION must move to 5** (C165-03). `FederationConfigResponse` gains `NativeLoginTrustResponse native_login` after `mints_client_secret` (`management_models.hpp:2929`); `CreateFederationConfigRequest`, `UpdateFederationConfigRequest`, the three OAuth2 client structs, `SecuritySettings` (`std::optional<OAuth2Policy> oauth2`), `SetOrgSettings` and `TenantSettingsOverride` gain `std::optional` members mid-struct. The CHANGELOG's "the ABI is too" is false. | `CMakeLists.txt:116`; `CHANGELOG.md:24` |
| 9 | D-N33 | **Missing** (C165-04). | — |

## 4. Findings index

`path:line` is on the head read (§1). "Contract" rows are text in `sdks/CONTRACT.md` at `76d35d9`.

| ID | Severity | SDK | `path:line` | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C165-01 | **Medium** | python | `src/axiam_sdk/_oidc.py:1316-1317`; `_errors.py:283-313`; test `tests/test_native_sign_in.py:114-117`, `:461-472`, `:603` | §37.3 429 row; §37.9 test 9 | `_handle_token_response` maps with `description_optional=False`. AXIAM's route limiters on `/oauth2/token` answer `429 {"error":"rate_limit_exceeded"}` (or with `"retry_after":N`), no description, so `login_with_provider_id_token` raises `NetworkError` instead of `OAuthProtocolError(rate_limit_exceeded)` and drops `Retry-After`. Probed sync and async, both bodies. The same mapper serves `oidc_exchange`, `oidc_refresh` and `login_client_credentials`. | In `_handle_token_response`: `raise error_from_oauth2_response(response.status_code, response, "token request failed", description_optional=True)` (every `error` member at any status is the §12.3 rule 3 reading; at minimum `response.status_code == 429`). Tests: make `_oauth_error` omit `error_description` when none is passed; test 9 mocks exactly `{"error":"rate_limit_exceeded"}` + `Retry-After: 7` and is parametrised with the `"retry_after":7` body; assert `retry_after_ms == 7000`. |
| C165-02 | **Medium** | c | `include/axiam/management_models.h:2860`, `:4168`, `:9259` (and the OAuth2 client, security-settings, set-org and tenant-override structs); `CMakeLists.txt:136`; `tests/CMakeLists.txt:489`; `CHANGELOG.md:11-12` | D-N32; the SDK's own SOVERSION rule (`README.md:32-35`, `CHANGELOG.md:323-325`) | Regeneration inserts members mid-struct, so offsets move in caller-allocated request structs and in library-allocated response structs. SOVERSION stays 2, so an old binary loads the new library and misreads every member after the insertion point. Positional aggregate initialisers of those structs also stop compiling correctly. The CHANGELOG calls it "an appended member, so nothing is source-breaking". | `set(AXIAM_SOVERSION 3)`; `abi_soname` `-DEXPECTED=libaxiam.so.3`. CHANGELOG: a `### Breaking changes` entry "Rebuild against the new headers: these structs gained members **inside** the struct (offsets move): … (list the nine); the shared library's ABI version is now 3 (`libaxiam.so.3`); designated initialisers are unaffected, positional ones must be updated." Delete "appended member … nothing is source-breaking". README `:32-35`: the SONAME example becomes `libaxiam.so.3`. If C165-21 adds a field to `axiam_error_t`, do it in the same bump. |
| C165-03 | **Medium** | cplusplus | `include/axiam/management_models.hpp:2929` and the eight structs in §3 row 8; `CMakeLists.txt:116`; `tests/CMakeLists.txt:200-205`; `CHANGELOG.md:24` | D-N32; the SDK's 1.1.1 precedent (SOVERSION 3 → 4 for types that gained members) | Generated model structs change size and layout; SOVERSION stays 4. The overloads keep the *function* ABI only. | `set(AXIAM_SOVERSION 5)`; the `abi_soname` expectation `libaxiam_cpp.so.5`. CHANGELOG: replace "so the ABI is too" with "the `oidc_begin`/`oidc_par` signatures are unchanged; the regenerated model structs (list) gained members, so the ABI version is now 5 — rebuild. Aggregate initialisation by position must name the new members." Add the `### Binary compatibility` section the 1.1.1 entry has. |
| C165-04 | Low | rust, typescript, python, java, kotlin, csharp (partial), go, swift, c, cplusplus; php (wording) | each `CHANGELOG.md` `[Unreleased]` (`:7`/`:8`) and the README's contract-1.65 paragraph | D-N33 | No SDK states the floor D-N33 decided. PHP says an older server's response fails to decode; C# says the member is required. TypeScript and Go do not fail at all (no runtime check / `encoding/json`), and get a zero value instead. | Add to each CHANGELOG `### Changed` and to the README's 1.65 paragraph: "**Server floor:** federation-config admin calls (`federation.create_config`, `get_config`, `list_configs`, `update_config`) of this 1.2-line SDK need an AXIAM server **1.2.0 or later**: `FederationConfigResponse.native_login` is required from 1.2.0, and a response from an older server <fails to decode with … / decodes with `native_login` absent (TS: `undefined`; Go: the zero value)>." |
| C165-05 | Low | php | `src/Oidc/OidcClient.php:786-797` | §37.2 rule 4; §34.4 ("one validation error for every local refusal") | Empty `provider`/`idToken`/`nonce` and the over-long nonce raise `AuthError`, the taxonomy type for authentication failures, while `idpHint` raises `\InvalidArgumentException`. Rule 4 allows the §2 `ValidationError` or the programming-error type, not `AuthError`. | Throw `\Axiam\Sdk\Management\ValidationError` (what the SDK's other local refusals raise) for all four, or `\InvalidArgumentException` to match `assertIdpHint`; pick one for both helpers. Update `tests/Contract165/NativeSignInTest.php`'s test 5 and the docblock. A slug-only client stays `AuthError` (§12.3 rule 4). |
| C165-06 | Low | go | `oidc_native.go:128-151` | §37.2 rule 4/5; §12.1 (missing `client_id` refused locally) | No `client_id` check: a `Client` built without `WithOidcClientID` sends `client_id=` (empty) and spends a request. `cibaClientAuth` refuses the same case (`oidc_ciba.go:350-352`). | Before the tenant check: `if c.session.oidc.clientID == "" { return OidcTokenSet{}, &AuthError{Message: "LoginWithProviderIdToken requires a client_id: construct the Client with WithOidcClientID (CONTRACT.md §37.2 rule 5)"} }`. Test: no client id → error, zero requests. |
| C165-07 | Info | go | `oidc_native.go:129-137`; `oidc.go` (`validateIdpHint`) | §37.2 rule 4; §34.4 | Refusals are untyped `errors.New`/`fmt.Errorf` while the package's local refusals elsewhere are `*ValidationError` (`localRefusal`, `oidc_registration.go:309`). Allowed by rule 4 (Go's programming-error idiom), but `errors.As(err, &*ValidationError)` does not catch them. | Return `localRefusal("LoginWithProviderIdToken", "provider", …)` etc. and the same for `IdpHint`; the tests assert `errors.As`. |
| C165-08 | Low | kotlin, go, swift, typescript, python | Kotlin `management/models/CreateFederationConfigRequest.kt`, `FederationConfigResponse.kt`; Go `CHANGELOG.md` ("Nothing here is source-breaking"); Swift `ManagementModels.swift` (`FederationConfigResponse.init`); TS `src/management/models.ts`; Python `management/models.py` | D-N32 ("the breaks listed in each CHANGELOG") | The regenerated surface breaks some source and the CHANGELOG does not list it. **Kotlin** is the real one: constructor parameters inserted mid-list break positional calls, `copy`/`componentN`, and JVM binary compatibility; `FederationConfigResponse.nativeLogin` has no default. **Go**: unkeyed literals. **Swift, TS, Python**: the new required `FederationConfigResponse` member breaks code that constructs the response (fixtures, mocks). Rust, Java, PHP list theirs; C and C++ are C165-02/-03. | One `### Source compatibility` bullet each. Kotlin: "the generated data classes gained constructor parameters in alphabetical position (… list) — use named arguments; the change is binary-incompatible for code compiled against 1.1.x, rebuild". Go: "unkeyed composite literals of the regenerated structs (list) must add the new fields". Swift/TS/Python: "`FederationConfigResponse` gained the required `native_login`; code that builds one must supply it". |
| C165-09 | Low | contract | `sdks/CONTRACT.md` §37.9 test 5 (`:15054`ff.) vs §37.1 (`:14803-14805`) | consistency | Test 5 says a slug-only client "raises the SDK's validation error"; §37.1 says it "raises its taxonomy error" (§12.3 rule 4), and all eleven SDKs raise `AuthError` (correctly, by §12.3). | Test 5: "… raises the SDK's validation error with **zero** requests; a slug-only client raises the §12.3 rule 4 taxonomy error (`AuthError`), also with zero requests." |
| C165-10 | Low | contract | §37.9 test 3 ("no discovery fetch"); §37.8 last sentence | consistency with every implementation | The token endpoint comes from discovery in all eleven (§12.1 forbids hard-coding it); every suite warms the cache or passes a configuration and counts from there. §37.8 forbids discovery *to decide support*, not to find `token_endpoint`. | Test 3: "the test records **one** request to the token endpoint and no `sso_providers` lookup; a discovery fetch made to find `token_endpoint` (cold cache, no configuration passed) is not counted, and the test may pre-warm or pass the configuration." Add to §37.8: "Reading `token_endpoint` from the discovery document, as every §12 operation does, is not that." |
| C165-11 | Low | contract (+ typescript, python, java, kotlin, csharp, go, swift, c, cplusplus docs) | §26.2 rule 8 (`:8326-8338`); TS `src/node/oidcTypes.ts:316-320`; Python `_oidc.py:1152`; Java `AxiamClient.java:5351`; Kotlin `OidcSupport.kt:451`; C# `AxiamClient.Par.cs:45`; Go `oidc_par.go:128`; Swift `Oidc/Par.swift:102`; C `src/oidc_par.c:127`; C++ `src/oidc.cpp:2155`; Rust `src/oidc/par.rs:228`; PHP `src/Oidc/OidcClient.php:441` | §26.2 rule 8 | Every `oidc_par` takes the `oidc_begin` *request* (state, nonce, verifier) **and** arguments (redirect URI, scope). Rule 8 lets an "arguments" SDK take the hint as an argument, so nine SDKs ignore the hint the begin URL already carries: `oidc_begin(idp_hint="x")` followed by `oidc_par(request)` pushes no hint, silently. Rust reads it from the URL; PHP does both (argument, falling back to the request). Only TS documents the trap. | Contract (after §5 Q1): either (a) "when the `idp_hint` argument is unset, an `axiam_idp_hint` the begin URL carries is pushed (the argument wins when both are set)", or (b) "an SDK whose `oidc_par` does not read the begin URL MUST document that the hint is passed to `oidc_par`, not to `oidc_begin`". Code under (a): the PHP pattern in the nine (TS/Java/Kotlin/C#/Go/Swift: read `axiam_idp_hint` from `request.url`; Python the same; C/C++ parse the URL). Under (b): one doc sentence on each `oidc_par`. |
| C165-12 | Info | contract (typescript, go, php, csharp observed) | §37.2 rule 9 (`:14882-14888`) | clarity | "Follow whichever posture it already took" assumes one posture; TS has two (`loginClientCredentials` opt-in `adoptAsCredential`, `deviceLogin` none) and followed `deviceLogin`. Result across SDKs: none (8), opt-in flag (Go, PHP), a flag that always throws (C#). All conformant. | Rule 9: "Where the SDK's two precedents differ, it MAY offer the opt-in either one offers, off by default; it MUST NOT adopt by default." |
| C165-13 | Low | contract | §12.1 rule 3 (the 1.63 paragraph); §37.2 rule 12 | gap | No rule says an `/oauth2/*` POST must not follow a redirect. C165-14 shows four SDKs re-send the form — the provider ID token, the raw nonce, `client_secret` — to a 307/308 target, cross-host included. AXIAM never redirects these endpoints, so only an intermediary or a wrong base URL triggers it. | §12.1 rule 3, new sentence: "An SDK MUST NOT follow an HTTP redirect from a `POST` to an `/oauth2/*` endpoint; a `3xx` is surfaced as `NetworkError` (§2). A 307/308 would re-send the form, and its credentials, to the redirect target." §37.2 rule 12: "… nor sent anywhere but the token endpoint (no redirect is followed, §12.1 rule 3)." |
| C165-14 | Low | go, php, typescript (Node), swift; rust (same-host only) | Go `client.go:726-737`; PHP `src/AxiamClient.php:434` (`plainHttp`, Guzzle `allow_redirects` default); TS `src/rest/session.ts:536` (`axios.create`, no `maxRedirects`); Swift transport (no redirect delegate); Rust `src/client.rs:522-560` | §37.2 rule 12 (spirit); C165-13 | The native POST (and every pre-existing `/oauth2/token` POST) follows a 307/308 and re-sends the form; Go, PHP and TS also cross hosts. Java, Kotlin (`OneShotBody`), C# (`AllowAutoRedirect=false`), Python (httpx default), C and C++ (`FOLLOWLOCATION 0`) do not. Pre-existing, narrow trigger. | Refuse redirects on `/oauth2/*` POSTs: Go `if req.Method == http.MethodPost && c.isOAuth2Path(via[0]) { return http.ErrUseLastResponse }` in `CheckRedirect`; PHP `'allow_redirects' => false` in `postForm`'s options; TS `maxRedirects: 0` in `#postCibaForm`'s (and the token POSTs') config; Swift a `URLSessionTaskDelegate` returning `nil` from `willPerformHTTPRedirection` for `/oauth2/*`; Rust `redirect::Policy::none()` on `http_bare` for `/oauth2/*`. Test: a mock answering `307 Location: http://other/…` → `NetworkError`, and the other host sees no request. |
| C165-15 | Info | all | — | §37.9 test 12 | Rust, C# and C report (PR notes) that an OAuth2 form POST emits no §19 event, Java's session-free transport clears its interceptors, and Swift's `bareSend` reports the operation and the path template only; so the telemetry half of test 12 checks little or nothing. Not a defect. | None; the contract could say "where the SDK emits §19 events for the call". |
| C165-16 | Info | swift | `Oidc/Oidc.swift:189-232` | §9 rule 6b | The D-N34 guard is correct (§3 Swift row 7). Recorded for the review D-N34 asked for. No toolchain here, so it was traced, not run. | None. CI's Swift legs run `testRefreshInvalidGrantIsOneWireCallSharedByEveryWaiter` and `testSequentialRefreshesEachMakeTheirOwnWireCall`. |
| C165-17 | Info | rust, typescript, swift, c (and csharp: `internal`) | Rust `src/error.rs:498-513`; TS `src/core/errors.ts`; Swift `AuthError`; C `include/axiam/error.h`; C# `NativeLogin.cs:97-101` | §37.3 429 row ("wherever the SDK exposes it on that error") | `Retry-After` is not reachable on the 429's `OAuthProtocolError`. Conformant as written; a caller cannot honour the server's 60 s. | Optional: expose it as Java, Kotlin, Python, PHP, Go and C++ do (C#: make `RetryAfter` public). C: with C165-02's bump, an `oauth_retry_after_ms` member is free to add. |
| C165-18 | Info | csharp | `Axiam.Sdk/AxiamClient.NativeLogin.cs:24-31` | §37.2 rule 9 | `adoptAsCredential` is a public parameter whose only behaviour is `NotSupportedException`. It mirrors `LoginClientCredentialsAsync`, but a new method need not carry it, and removing it after release is a break. | Drop the parameter (keep the doc sentence "not adopted"), or implement it as Go/PHP do. |
| C165-19 | Info | contract | §37.3 (`:14942-14944`); §14.2 rule 6; §26.3 ("No grant-local mapper is permitted here") | clarity | §37.3 dispatches a 5xx-with-body on the body, while §14.2 rule 6 makes a device poll's 5xx a `NetworkError` whatever its body. Go's shared mapper encodes the device reading, so it added a grant-local mapper; §26.3's "no grant-local mapper" (written for PAR) reads as forbidding that. | §37.3, after the table: "This deliberately differs from §14.2 rule 6, which governs a poll; an SDK whose shared `/oauth2/*` mapper implements rule 6 may map this grant with its own, provided it dispatches on `error` at any status." |
| C165-20 | Info | rust | `src/oidc/native.rs:199`; `src/oidc/par.rs:228-231` | §37.2 rule 7; §12.1 idp_hint rule 2 | `scopes: Some(vec![])` sends `scope=` (empty), which rule 7 forbids. Every other SDK treats an empty list as none. Separately, an empty `axiam_idp_hint` passed as an `extra_params` entry is accepted by `oidc_begin` and then refused by `oidc_par`. | `let scope = options.scopes.as_ref().filter(|s| !s.is_empty()).map(|s| s.join(" "));` and a test. For the hint: refuse an empty `axiam_idp_hint` extra in `oidc_begin` too, or skip validation in PAR for a URL-carried value. |
| C165-21 | Info | c | `src/oidc.c:514-521`; `include/axiam/error.h:48` | §37.9 test 6 ("`error` and `error_description` exposed") | `error_description` is reachable only inside the message (`"invalid_grant: the provider ID token is not acceptable"`); `axiam_error_t` has `oauth_error` and no description field. Pre-existing §12.3 surface. | With C165-02's SOVERSION bump: add `char oauth_error_description[256]` to `axiam_error_t`, fill it in `oidc_map_grant_error`, and assert it in test 6. |

**Counts:** Medium 3 (C165-01, -02, -03) · Low 9 (C165-04, -05, -06, -08, -09, -10, -11, -13, -14) · Informational 9
(C165-07, -12, -15 … -21). **Contract text:** C165-09, -10, -11, -12, -13, -19 (C165-11 and -13 also carry SDK
work). There is no High or Critical.

**Per SDK** (the fix list for each SDK's session):

| SDK | Findings |
|---|---|
| rust | C165-04, (-14 same-host), -17, -20 |
| typescript | C165-04, -08, -11 (doc / Q1), -14, -17 |
| python | **C165-01**, -04, -08, -11 (Q1) |
| java | C165-04, -11 (Q1) |
| kotlin | C165-04, -08, -11 (Q1) |
| csharp | C165-04, -11 (Q1), -17, -18 |
| php | C165-04 (wording), -05, -14 |
| go | C165-04, -06, -07, -08, -11 (Q1), -14 |
| swift | C165-04, -08, -11 (Q1), -14, -17 |
| c | **C165-02**, -04, -11 (Q1), -17, -21 |
| cplusplus | **C165-03**, -04, -11 (Q1) |
| contract (a 1.65 text pass) | C165-09, -10, -11, -12, -13, -19 |

**What each SDK did right, for the record.**
- (a) is ported in all eleven with the thirteen §37.9 tests and the fixed vector; (b) with the five `idp_hint`
  tests; the §9 confirmation test exists in all eleven, and Swift's new guard is correct.
- No SDK hashes the nonce, reads the token's claim, generates a nonce inside the call, adds `openid`, trims or
  resolves `provider`, calls `sso_providers`, routes through `token_exchange`, or falls back to another grant.
- No SDK retries the call through §16, a 401→refresh interceptor or a connection-level re-send: Java and Kotlin
  switched OkHttp's silent retry off for it, C# gave it a fresh connection, PHP kept it off the refresh stack.
- Ten of eleven map AXIAM's real 429 and 500 bodies correctly (Python is C165-01).
- No secret reaches an error: each transport-failure path drops or sanitises the library exception that holds the
  request (TS, Python, PHP, Java explicitly), and C scrubs the form buffer.

## 5. Questions for the maintainer

Only what the plan's decisions (D-N1 … D-N35) and the contract do not answer.

**Q1. Under PAR, should `oidc_par` carry a hint that `oidc_begin` already put on the authorization URL (C165-11)?**
- **What is open.** §26.2 rule 8 permits both sources, and the SDKs split: nine read only an `idp_hint` argument
  (so `oidc_begin(idp_hint=…)` then `oidc_par(request)` pushes no hint, with no error), Rust reads only the URL, PHP
  reads the argument and falls back to the request. D-N23 settled the server's side (the pushed hint is
  authoritative), not this.
- **Options.**
  - **(a)** Make carry-over normative: "when `idp_hint` is unset, a hint the begin URL carries is pushed; when both
    are set, the argument wins." Nine SDKs add a few lines (the PHP pattern); Rust adds the argument or keeps the
    URL as its single source.
  - **(b)** Keep rule 8 permissive and require each argument-only SDK to document, on `oidc_par`, that the hint must
    be passed there.
- **Recommendation: (a).** The begin-then-push sequence is the documented way to use PAR in every SDK, and a hint
  lost without an error is the failure mode `idp_hint` rule 3 already guards against for duplicates. The redirect
  rule (`client_id` + `request_uri` only) is unaffected.

C165-01 … -10 and -12 … -21 need no decision: the rules they cite are explicit, D-N32 and D-N33 decide the ABI and
floor findings, and the contract-text fixes clarify text every SDK already meets.

## 6. What this review could not verify

- **Swift** was read, not run (no toolchain); its suite ran under Swift 6.2.4 per the PR.
- **CI** of the eleven repositories was not read; the PR bodies' gate lists were taken as claims and the suites in §1
  were re-run where possible.
- **The redirect behaviour of Swift's transport on Linux FoundationNetworking** (C165-14) was inferred from the
  absence of a redirect delegate, not observed.

---

## Addendum 1 — fix-round re-check (2026-10-31)

**Scope.** The eleven fix commits on `claude/bold-mayer-wpd3kv` (all signed, all equal to their pushed
`origin/claude/bold-mayer-wpd3kv`), each diffed against the head this review read; the contract at axiam
`d93976b` (§12.1 rule 3 "No redirect is followed", §26.2 rule 8 + §26.6 `par_idp_hint_from_begin_url_pushed` /
`par_idp_hint_argument_wins` (D-N36), §37.2 rules 9 and 12, §37.3 last paragraph, §37.8, §37.9 tests 3, 5 and
12, §34.9 "Amended 2026-10-31" with the D-N33 floor); plan §5 D-N32 … D-N37.

| SDK | previous head | fix head | CI on the fix head (`gh run list`) |
|---|---|---|---|
| Rust | `3ce575d` | `9d5ca23` | SDK CI, Coverage, clippy: success |
| TypeScript | `df17b53` | `4586681` | SDK CI, Coverage, CodeQL: success |
| Python | `51eb8d3` | `4ccc75a` | SDK CI, Coverage: success |
| Java | `e2ece70` | `ae12455` | SDK CI, Coverage: success |
| Kotlin | `97e3706` | `54871aa` | SDK CI, Coverage: success |
| C# | `2e056b0` | `c06bbf3` | SDK CI, Coverage: success |
| PHP | `f47a8a4` | `114810f` | SDK CI, Coverage: success |
| Go | `cf1128c` | `e4235e7` | SDK CI, Coverage: success |
| Swift | `4b10728` | `139198d` | sdk-ci-swift, coverage: success |
| C | `c29f78e` | `3476b7d` | coverage: success; sdk-ci-c still running when read |
| C++ | `999888a` | `7e45f76` | sdk-ci-cpp and coverage still running when read |

### A1.1 Vendoring

`CONTRACT.md` at each fix head (`git show <head>:CONTRACT.md | sha256sum`) is
`95ee87ba128afb5a198b5364983b5a725e9a75b775840f87259c896ce3359529`, identical to axiam `d93976b`, in **all eleven**.
No fix commit touches `openapi.json`, `management-registry.json` or `proto/`, so those stay as §2 recorded them
(`76d35d9`). Each repository holds exactly one tracked `CONTRACT.md`.

### A1.2 Runs (scratch worktrees at the fix heads, removed afterwards)

| Repo | Run | Result |
|---|---|---|
| rust | `cargo test --no-default-features --features rest --test contract_165_test` | 24 passed |
| typescript | `npm ci`; `vitest run` nativeSignIn, idpHint, oidcTokenOps, deviceFlow, ciba, oidcExchange (proxy unset) | 6 files, 171 passed |
| python | focused (native, idp_hint, coverage-gaps, single-flight, device): 196 passed; full `pytest tests`: 2061 passed, 11 collection errors (django/flask/fastapi extras not installed, environmental) | green |
| java | `mvnw -Dtest=NativeSignInTest,IdpHintTest,RefreshReuseInvalidGrantTest` + a reviewer probe | 14 + 7 + 1 passed; probe: C165-23 |
| kotlin | `gradlew test --tests` NativeSignIn, IdpHint, OidcRefreshReuse + probe; `OidcRefreshTest` ×5 isolated | 14 + 7 + 1 passed; probe: C165-23; `OidcRefreshTest` 5/5 |
| csharp | `dotnet test --filter NativeLogin\|IdpHint\|OidcRefreshAndCredentials` | 48 passed |
| php | **none**: `composer install` still blocked ("Could not authenticate against github.com"); read only | — |
| go | `go test -count=1 .`; `go vet .` | ok; clean |
| swift | **none** (no toolchain); read only | — |
| c | cmake Debug, `AXIAM_BUILD_TESTS=ON`; full `ctest` 83/83; valgrind `test_idp_hint`, `test_native_sign_in` clean; `readelf` SONAME `libaxiam.so.3` | green |
| cplusplus | cmake Debug, tests on, shared; `ctest` 2/2 (`axiam_cpp_tests` 1669 cases, 6564 checks, 0 failed; `abi_soname`); `readelf` SONAME `libaxiam_cpp.so.5` | green |

The two probes (a `307 Location: <second MockWebServer>/oauth2/token` answer to `oidcRefresh`) lived only in the
scratch worktrees.

### A1.3 Status of C165-01 … C165-21

| ID | SDK(s) | Status | Evidence on the fix head |
|---|---|---|---|
| C165-01 | python | **Closed** | `_handle_token_response` maps with `description_optional=True` (`src/axiam_sdk/_oidc.py:1333-1342`); `_oauth_error` omits the description unless given; test 9 mocks exactly `429 {"error":"rate_limit_exceeded"}` and the `"retry_after":7` variant with `Retry-After: 7`. See point 3 (A1.5). |
| C165-02 | c | **Closed** | `AXIAM_SOVERSION 3` (`CMakeLists.txt:135-137`); `abi_soname` expects `libaxiam.so.3` and passes; CHANGELOG `### Breaking changes` names the nine structs, the moved offsets and positional initialisers; the "appended member, nothing source-breaking" sentence is gone. One wording defect left in the README (C165-27). |
| C165-03 | cplusplus | **Closed** | `AXIAM_SOVERSION 5`; `abi_soname` updated and passing; CHANGELOG "so the ABI is too" replaced, `### Binary compatibility` added. |
| C165-04 | all eleven | **Closed** | The D-N33 floor sentence is in every CHANGELOG and README, with each SDK's actual behaviour: decode failure (Rust, Python, Java, Kotlin, C#, PHP, Swift, C++), `undefined` (TS), zero value (Go), NULL member (C). |
| C165-05 | php | **Closed** | Empty inputs and the 513-byte nonce throw `\InvalidArgumentException` (`src/Oidc/OidcClient.php:786-798`), the type `assertIdpHint` uses; the slug-only client stays `AuthError`; tests and docblocks updated. See point 4. |
| C165-06 | go | **Closed** | `*AuthError` before any request when `clientID == ""` (`oidc_native.go:128-132`); `TestNativeSignIn_MissingClientIDRefusedLocally`. |
| C165-07 | go | **Closed** | `localRefusal(...)` for `Provider`/`IDToken`/`Nonce` and in `validateIdpHint` (`oidc.go:84-92`); the tests assert `errors.As(err, &*ValidationError)`. |
| C165-08 | kotlin, go, swift, typescript, python | **Closed** | A `### Source compatibility` section in each CHANGELOG; Kotlin lists the nine classes, the parameter positions, the missing default and the JVM binary break. |
| C165-09 | contract | **Closed** | §37.9 test 5 at `d93976b`. |
| C165-10 | contract | **Closed** | §37.9 test 3 and the last sentence of §37.8. |
| C165-11 | contract + nine SDKs | **Closed** (contract, D-N36); **Closed** in TypeScript, Python, Java, Kotlin, C#, Go, Swift, C and C++; PHP already conformed and added both §26.6 tests; Rust **Closed as decided** (point 1). | Each `oidc_par` now falls back to the begin URL's `axiam_idp_hint` when its argument is unset, and each of the nine (and PHP) carries `par_idp_hint_from_begin_url_pushed` and `par_idp_hint_argument_wins` by name. |
| C165-12 | contract | **Closed** | §37.2 rule 9. |
| C165-13 | contract | **Closed** | §12.1 rule 3 "No redirect is followed"; §37.2 rule 12. |
| C165-14 | go, typescript (Node), swift; php; rust | Go **Closed**; TypeScript **Closed** (Node; browser persona C165-26); Swift **Closed**; PHP **Partially** (C165-22); Rust **Closed — no defect** (point 1). Java and Kotlin were wrongly cleared by this review and are **Open** as C165-23. | Go: `CheckRedirect` returns `http.ErrUseLastResponse` for an `/oauth2/*` POST and `doRequest` makes the `3xx` a `*NetworkError` without the `Location` (`client.go:428-434`, `:927-933`). TS: `maxRedirects: 0` on the four `/oauth2/*` form-POST sites (`src/node/oidc.ts:2247`, `:2811`, `:2840`, `:3112`) plus a `3xx` → `NetworkError` branch in `mapOidcError`, `cibaError` and the §16 runner; tests for native, `oidcExchange` and CIBA with a second host that sees nothing. Swift: point 2. |
| C165-15 | contract | **Closed** | §37.9 test 12's parenthetical. |
| C165-16 | swift | **Closed** (no action) | Swift CI green on `139198d`. |
| C165-17 | rust, typescript, swift, c, csharp | **Closed** | Rust `AxiamError::retry_after()` on `Auth` (point 1); TS `OAuthProtocolError.retryAfterMs` (test asserts 7000); Swift `AuthError.retryAfter` (trailing defaulted init parameter, test asserts 7); C `axiam_error_t.oauth_retry_after_ms` (test asserts 7000); C# `RetryAfter` public. |
| C165-18 | csharp | **Closed** | The parameter is gone; the only remaining `adoptAsCredential` mentions are the docs saying there is none, and `README.md:961`, which is `DeviceLoginAsync`'s. The test asserts by reflection that the parameter does not exist and that nothing is adopted. |
| C165-19 | contract | **Closed** | §37.3 last paragraph. |
| C165-20 | rust | **Closed** | `scopes: Some(vec![])` sends no `scope` (`src/oidc/native.rs:199-203`, `empty_scopes_send_no_scope`); an empty `axiam_idp_hint` extra is refused at `oidc_begin` (`src/oidc/authorize.rs:316-324`, `empty_idp_hint_extra_refused_at_begin`). |
| C165-21 | c | **Closed** | `axiam_error_t.oauth_error_description[256]`, filled in `oidc_map_grant_error` and cleared by `axiam_error_reset`/`_set`; test 6 asserts it. |

### A1.4 New findings

| ID | Severity | SDK | `path:line` (fix head) | Rule | What | Fix (size) |
|---|---|---|---|---|---|---|
| C165-22 | Low | php | `src/Oidc/OidcClient.php:2674` (`postTokenAsync`, used by `oidcRefresh`), `:1110` (`devicePollWithin`), `:2527` (`cibaPollTracked`) | §12.1 rule 3 (amended); §37.2 rule 12 | `allow_redirects => false` went into `postForm` (`:2942`), which carries PAR, device authorization, token exchange, introspect, revoke, the UMA ticket, `ciba_initiate` and `postToken` (exchange, client credentials, native sign-in). Three `/oauth2/token` POSTs call `$this->http` directly on `plainHttp`, whose Guzzle default follows a 307/308 and re-sends the body to the `Location` host. Guzzle strips only `Authorization`/`Cookie` across hosts, so `oidcRefresh` re-sends `refresh_token` and `client_secret`, the device poll `device_code`, the CIBA poll `auth_req_id` and the secret. Found by reading; not run (no composer). | Add `'allow_redirects' => false` to the three option arrays. Map a `3xx` to `NetworkError` before the existing status handling: in `postTokenAsync`'s fulfilled callback, and as a `$status >= 300 && < 400` branch in the two polls. That is the poll's decided answer and not §16-retried. Add one test: `oidcRefresh` against a `307` → `NetworkError`, `assertCount(1, $this->sent)`. Small (~15 lines + 1 test). |
| C165-23 | Low | java, kotlin | Java `src/main/java/io/axiam/sdk/AxiamClient.java:736` (`httpClient`, OkHttp default `followRedirects(true)`), `:739` (`pollHttpClient`), `:4334-4345` (`executeFormPost`); Kotlin `src/main/kotlin/io/axiam/sdk/AxiamClient.kt:270-283` (shared `httpClient`), `oidc/OidcSupport.kt:2058-2079` (`postOAuth2Form`), `:2111-2120` (`executeRequest`) | §12.1 rule 3 (amended); §37.2 rule 12 | §3's "Java and Kotlin do not follow" was wrong: it read only the native POST's transport (Java `sessionlessHttpClient`, Kotlin `OneShotBody`). Every other `/oauth2/*` form POST rides an OkHttp client that follows redirects, with a `FormBody` that is not one-shot. OkHttp re-POSTs that body on a 307/308 to any host and drops only `Authorization`. The affected calls are `oidcExchange`, `oidcRefresh`, client credentials, PAR, introspect, revoke, token exchange, the UMA ticket and device authorization, plus Java's device and CIBA polls. Kotlin's one-shot polls and CIBA are protected from 307/308 only, and still follow 301–303 as a `GET`. **Probed in both:** `oidcRefresh` answered `307 Location: http://<second server>/oauth2/token` sent `grant_type=refresh_token&refresh_token=the-refresh-token&client_id=app&client_secret=s3cret` to the second server (one request there) and returned *its* answer. | Java: build an `/oauth2/*` client once, `httpClient.newBuilder().followRedirects(false).followSslRedirects(false)`, and use it for `executeFormPost`, with `pollHttpClient` derived from it. Map a `3xx` to `NetworkError` ahead of `ErrorMapper.fromOAuth2…`. Kotlin: the same, with `executeRequest(…, client = oauth2Client)` for every `/oauth2/*` POST (`Sessionless.kt:49-50` already does it for its client), and a `3xx` → `NetworkError` branch in `mapOAuth2ErrorResponse`. Tests: the probe above, asserting `NetworkError` and zero requests at the second server, for `oidcRefresh` and one poll. Small (~20 lines + 2 tests each). |
| C165-24 | Info | contract | `sdks/CONTRACT.md` §34.9 "Amended 2026-10-31" item (5) | record accuracy | The *SDK code* list for C165-14 repeats this review's error twice. It names Rust "(same-host only; Rust for `/oauth2/*` on `http_bare`)", but `http_bare` was always `redirect::Policy::none()` and `idp_form_post` is the only `/oauth2/*` POST path (`src/client.rs:579-581`, `:1126-1131`). It also omits Java and Kotlin (C165-23). §12.1 rule 3 binds every SDK whatever the record lists, so nothing normative is wrong. | Optional text fix: "Go, PHP, TypeScript (Node), Swift, Java and Kotlin (C165-23); Rust needed none (its `/oauth2/*` transport follows no redirect) and added the test". Fold it into the next contract text pass. A separate re-vendor of all eleven only for this is not worth it. |
| C165-25 | Info | rust, java, kotlin, csharp, python, c, cplusplus | Rust `src/oidc/exchange.rs:347-373`; Python `_oidc.py:1332-1342`; Java/Kotlin/C#/C/C++ the "any status" OAuth2 mappers §3 cites | §12.1 rule 3 ("a `3xx` is surfaced as `NetworkError`") | None of these follows a redirect. But their `/oauth2/*` mappers read the body before the status, so a `3xx` whose body is `{"error":…}` surfaces as `OAuthProtocolError`, not `NetworkError`. Nothing leaks; the type is wrong only for a contrived intermediary answer. TS, Go, PHP and Swift check the status first. | A `300..399` → `NetworkError` guard ahead of the body dispatch, the TS/Go/Swift pattern. Trivial; not blocking. |
| C165-26 | Info | typescript (browser persona) | `src/rest/session.ts:322-324` (`oauth2RequestConfig`); `src/rest/bareTransport.ts:56-60` | §12.1 rule 3 | The browser persona's `/oauth2/*` config is the axios `fetch` adapter with `credentials: 'omit'` and no `redirect` option. That adapter does not honour `maxRedirects`, so the RFC 7592 `/oauth2/register*` calls made through `bareRequest` in a browser follow a 307/308 under the browser's fetch rules. The §12 form POSTs are Node-only (`src/node/oidc.ts`). Found by reading; not probed. | `fetchOptions: { credentials: 'omit', redirect: 'error' }` in `oauth2RequestConfig` (or `'manual'` plus a status check). One line. |
| C165-27 | Info | c | `README.md:33-37` | doc accuracy | "a 1.1.x release is `libaxiam.so.1.1.x` with SONAME `libaxiam.so.3` …, one built against 1.1.x keeps loading `libaxiam.so.2`" contradicts itself: 1.1.x shipped `.so.2`, and `.so.3` is the contract-1.65 release (the 1.2 line, D-N32). | "the contract-1.65 release has SONAME `libaxiam.so.3` (1.1.x was `.so.2`, 1.0.x `.so.1`), so a binary built against an earlier line keeps loading its own SONAME and the loader refuses to run it against this library until it is rebuilt." One sentence. |
| C165-28 | Info | kotlin | `src/test/kotlin/io/axiam/sdk/oidc/OidcRefreshTest.kt:124-141` | test stability | `the refresh response's scope replaces the grant's` failed once in the fixer's full gate (`AssertionFailedError at OidcRefreshTest.kt:124`) and passed on re-run. The fix commit does not touch `oidcRefresh` or this test, which is unchanged since the C164-33 fix (`08825e8`). The reviewer ran `OidcRefreshTest` 5/5 green in isolation. So the flake is pre-existing and load-dependent, and C164-33's distinct-token change did not remove it. | Record and track; not blocking. Next step: run the full gate with `--info` until it reproduces, and log which assertion fails (the scope or the absent `idClaims`). |

Also noted, below a finding. With D-N36 the begin URL's hint is pushed. An `axiam_idp_hint` passed as a begin
*extra* over 256 bytes is now refused at PAR in TypeScript, Java, Swift, C and C++, and pushed as given in C#, Go,
Python and Kotlin. Java and C++ also refuse an empty URL value that the others ignore. Only a hand-built request or an
extra reaches this, and the server bounds the value. That is the C165-20 asymmetry Rust fixed at begin; aligning it is
optional.

**Counts (new):** Low 2 (C165-22, -23) · Informational 5 (C165-24 … -28). No Medium, High or Critical.

### A1.5 Verdicts on the fixers' ten points

1. **Rust.** Conformant on all three counts.
   - *No `idp_hint` argument on `oidc_par`.* Amended rule 8 says that when the argument is unset, `oidc_par` pushes the
     URL's hint. Rust's argument is always unset (the URL is its single source), so the rule reduces to what Rust does.
     §34.9 item (3) itself lists Rust as needing no code. `par_idp_hint_argument_wins` is not applicable: it needs an
     argument. Adding one would be a new public field on the exhaustive `OidcParParams`, a break for no gain. The
     comment in `tests/contract_165_test.rs` saying so is the right record; the PR's review notes should say it too.
     Rust's `par_idp_hint_from_begin_url_pushed` injects the hint through `with_extra_param`. The `with_idp_hint` path
     the contract names is covered by the existing `par_idp_hint_in_pushed_body`.
   - *`retry_after` on `AxiamError::Auth`.* Acceptable. §37.3 asks for it "wherever the SDK exposes it on that
     error", and in Rust *that error* is the `Auth` variant carrying `oauth: Some(OAuthProtocolError)`. The variant is
     `#[non_exhaustive]` (`src/error.rs:87`), so the field is additive. `OAuthProtocolError` has all-public fields and is
     not `non_exhaustive`, so a field there would break every downstream struct literal. It is surfaced on a 429 only.
   - *C165-14.* The claim is true and this review was wrong. `http_bare` is `redirect::Policy::none()`
     (`src/client.rs:579-581`), and every `/oauth2/*` POST goes through `idp_form_post` on it
     (`par`, `exchange`, `token_exchange`, `ciba`, `device`, `uma`). §3 cited the session transport's same-host
     policy (`:547-563`), which `/oauth2/*` never rides. `token_post_does_not_follow_redirect` now pins it. See C165-24
     for the record text.
2. **Swift.** Verified by reading.
   - `HTTPTransport` is an internal protocol (`HTTP/HTTPTransport.swift:47`), so no caller can inject another
     transport. Its one production implementation sets `redirectConfiguration = .disallow` (`:63`). `URLSession`
     appears in `Sources/` only in comments.
   - Every OIDC, CIBA, registration and UMA call reaches `umaSendAbsolute`, where `refuseOAuth2Redirect` now runs
     (`AxiamClient.swift:1175-1176`, `:1189-1198`). `bareSend` does not retry that refusal (`BareRequest.swift:85-94`).
     Nothing in Swift can follow a redirect.
   - Residual: the path match is under `config.baseURL.path` only. With a non-empty base path, a discovery-given root
     `/oauth2/*` endpoint gets the generic `3xx` mapping instead of the named `NetworkError`. It is still not followed.
     Negligible.
   - The new `testRedirectToOtherHostIsNotFollowedOverTheWire` uses real sockets. CI is green.
3. **Python.** The change is correct, and the test is still meaningful.
   - §12.3 rule 3, §37.3 (dispatch on a non-empty `error` at any status) and RFC 6749 §5.2 (`error_description`
     optional) all make a 4xx/5xx `{"error":…}` an `OAuthProtocolError`. A 5xx *with* a description already was one
     before the change, so this only removes a description-presence distinction the contract never drew.
     `oidc_exchange`, `oidc_refresh` and `login_client_credentials` take no §16 retry, so no retry behaviour changes.
   - The edited single-flight tests still assert what they exist for: one wire call, and every waiter gets the same
     `NetworkError`. They do it with a body-less 500, which is still a `NetworkError`.
   - No device-poll regression. `_handle_device_poll_response` maps a 5xx (whatever its body) and any 429 *before*
     calling `_handle_token_response` (`_oidc.py:1871-1901`), so §14.2 rules 6 and 9 are untouched. A body-only 400
     poll answer (`authorization_pending` without a description) now dispatches on `error` instead of reading as a
     transport failure, which is rule 5's reading.
   - The full suite is green (2061).
4. **PHP.**
   - *`\InvalidArgumentException`.* Conformant: rule 4 allows "the §2 `ValidationError` **or** the programming-error
     type". `\InvalidArgumentException` is PHP's programming-error type and the one `assertIdpHint` already throws, so
     the two helpers now agree, which was what C165-05 asked. PHP's `ValidationError` extends `NetworkError` and would
     also have been allowed; the choice is the fixer's.
   - *`allow_redirects => false` in `postForm`.* It does **not** cover every `/oauth2/*` POST. Three bypass it; see
     C165-22.
5. **TypeScript.** Still asserting the right thing. `recordSleeps` records a `setTimeout` only when the synchronous
   stack includes `src/node/oidc` and now excludes any stack that also includes `/node_modules/axios/`. The loop's own
   sleep is armed from `oidc.ts` after the POST's `await` has resolved, so no axios frame is on its stack. The timer
   excluded is the request timeout axios's native `http` path arms from inside the POST (`maxRedirects: 0` bypasses
   `follow-redirects`). `deviceFlow.test.ts` passes, and its delay assertions still see the loop's waits.
6. **Java.** Fine. Under D-N36, a begin URL that carries a hint *must* be pushed, so the old no-hint assertion against
   such a request contradicted the amended rule. A hint-less begin is the right fixture for "absent when unset". CI
   (SDK CI — Java, Coverage) is green on `ae12455`, and the reviewer re-ran the three suites (14 + 7 + 1). The
   redirect probe is C165-23, unrelated to this edit.
7. **C.**
   - *Caller-allocated.* Yes. There is no constructor, the SDK's tests and examples declare it on the stack, it is
     embedded in no other public struct, and nothing asserts on its size.
   - *Layout.* `oauth_error_description[256]` and `long oauth_retry_after_ms` are appended at the end. Both are
     cleared by `axiam_error_reset`/`axiam_error_set` and filled only in `oidc_map_grant_error`.
   - *Bump.* Riding the same SOVERSION 3 as C165-02 is consistent with the SDK's rule ("bumped whenever a
     caller-allocated public struct changes size"). `readelf` shows `libaxiam.so.3`.
   - *Percent-decoding* (`src/oidc_par.c:116-149`) is safe:
     - a `%` is decoded only with two hex digits inside the segment;
     - `o + 1 >= cap` is checked before every write, with `cap` = 257 into a 257-byte stack buffer, so at most 256
       bytes plus NUL;
     - an over-bound value is a local refusal before any request;
     - `%00` only truncates.

     Valgrind is clean on `test_idp_hint` and `test_native_sign_in`, and the percent-encoded test value round-trips.
   - *Remarks.* `oauth_retry_after_ms` is filled at any status that carries `Retry-After`, not only 429. That is
     harmless and documented as "of the OAuth2 error response". The README sentence on the SONAME is C165-27.
8. **C++.** SOVERSION 5 is consistent with the D-N37 decision and the 1.1.1 precedent. `readelf` shows
   `libaxiam_cpp.so.5`, and `abi_soname` passes. The URL-hint fallback (`src/oidc.cpp:251-280`, `:2133`) decodes into
   a `std::string`. It is bounds-checked (`i + 2 < size`), deliberately does no `+` decoding (begin emits `%20`), and
   the result goes through `check_idp_hint`, so an over-256-byte value is `std::invalid_argument` before any request.
   1669 cases pass.
9. **Kotlin.** Pre-existing flake, recorded as Informational C165-28, not attributed to the fix round: the fix
   touched only `oidcPar`, and the test is unchanged since `08825e8`. Not blocking.
10. **C#.** Confirmed. No code references the removed parameter; the remaining mentions are the "there is none"
    sentences and `DeviceLoginAsync`'s README paragraph. The test asserts its absence by reflection.
    `OAuthProtocolError.RetryAfter` is `public … { get; init; }` (`Core/OAuthProtocolError.cs:48`) and set on a 429
    only. Making a getter public is additive.

### A1.6 Before W5

- **Must fix** (the amended §12.1 rule 3 is a MUST, and the 1.2.0 SDKs should not ship breaking their own contract):
  - **C165-22** (PHP, three call sites);
  - **C165-23** (Java and Kotlin, one redirect-free OkHttp client each).

  Both are small and need no contract change. Once each lands, the SDK's C165-14 row reads Closed.
- **Should, cheap:** C165-27 (one C README sentence) and C165-26 (one TS line). Both can ride the same fix commits.
- **May defer:** C165-24 (record text; next contract text pass), C165-25 (mapper ordering), C165-28 (tracked
  flake), and the extra-hint asymmetry note.
- **Still to confirm:** the C and C++ CI runs on `3476b7d` / `7e45f76` were in progress when read; the local C and
  C++ runs above are green.

Everything else from the fix list (C165-01 … -21) is closed.

## Addendum 2 — sweep 2 re-check (2026-11-01)

**Scope.** The nine sweep-2 commits on `claude/bold-mayer-wpd3kv` (plus Kotlin's follow-up `320cefa`), each
diffed against its Addendum 1 head, against §12.1 rule 3 "No redirect is followed" (no redirect followed from a
`POST` to `/oauth2/*`; a `3xx` is `NetworkError`) and its 1.63 paragraph (no session cookie or `X-CSRF-Token` on
`/oauth2/*`). Go (`e4235e7`) and Swift (`139198d`) had no sweep-2 findings and were not re-read. No sweep commit
touches `CONTRACT.md`, `openapi.json`, `management-registry.json` or `proto/`, so A1.1's vendoring stands.

| SDK | A1 head | sweep-2 head | Findings addressed | CI on the sweep-2 head (check runs) |
|---|---|---|---|---|
| PHP | `114810f` | `2b2809b` | C165-22 | 7 success, 2 skipped (publish, tag) |
| Java | `ae12455` | `b54a3bb` | C165-23, -25 | 20 success, 2 skipped |
| Kotlin | `54871aa` | `62d0e47` → `320cefa` | C165-23, -25 | `320cefa`: 9 success (JDK 17 / Kotlin 2.1.0 and JDK 27 / Kotlin 2.4.21), 2 skipped |
| TypeScript | `4586681` | `34db3dc` | C165-26 | 7 success, 2 skipped |
| C | `3476b7d` | `00cced0` | C165-25, -27 | 26 success, 4 skipped |
| C++ | `7e45f76` | `c37f016` | C165-25 | 10 success, 2 skipped; llvm-cov → Coveralls still running when read |
| Rust | `9d5ca23` | `f047710` | C165-25 | 16 success, 2 skipped |
| C# | `c06bbf3` | `620b987` | C165-25 | 10 success, 2 skipped |
| Python | `4ccc75a` | `ff8a2a9` | C165-25 | 13 success, 2 skipped |

Kotlin `62d0e47` failed to compile its own test under Kotlin 2.4.21 (`OAuth2NoRedirectTest.kt:104`,
`assertFalse(e is OAuthProtocolError)` on a `NetworkError` is `IMPOSSIBLE_IS_CHECK_ERROR`). `320cefa` changes that
one test line to `assertFalse(OAuthProtocolError::class.java.isInstance(e))`. That is test-only and changes no
behaviour. The assertion is vacuous (the two types are unrelated, which is what the compiler said). The real check
is `assertThrows(NetworkError::class.java)` on the line above. Accepted.

### A2.1 Runs (scratch worktrees at the sweep-2 heads, removed afterwards)

| Repo | Run | Result |
|---|---|---|
| php | **none**: `composer install` still fails ("Could not authenticate against github.com"; dist zipballs come from `api.github.com`, and `--prefer-source` fails the same way). `php -l` on `OidcClient.php` and the new test: clean. Read only | — |
| java | `mvnw -o -Dtest=Oauth2NoRedirectTest,NativeSignInTest,RefreshReuseInvalidGrantTest,Ciba*` + reviewer probes (`devicePoll` 307, `cibaPoll` 308) | 6 + 14 + 1 + 24 passed; probes: `NetworkError`, second host 0 requests, one token POST |
| kotlin (`62d0e47` sources) | `gradlew --offline --no-daemon test` OAuth2NoRedirect, Ciba, NativeSignIn, IdpHint, OidcRefreshReuse + two reviewer probes in `CibaTest` | 4 + 29 + 14 + 7 + 1 passed; probes: C165-29 |
| typescript | `npm ci`; `vitest run` oauth2BrowserCredentials, nativeSignIn, idpHint, oidcTokenOps, clientRegistration (proxy unset); `tsc --noEmit` | 5 files, 91 passed; tsc clean |
| python | venv `pip install -e .[dev]`; pytest token_grants, native_sign_in, idp_hint, ciba, uma, device_flow, refresh single-flight | 229 passed |
| rust | `cargo test --no-default-features --features rest --test contract_165_test` | 25 passed (was 24) |
| csharp | `dotnet test --filter NativeLogin\|IdpHint\|OidcRefreshAndCredentials\|ClientRegistration` | 63 passed |
| c | cmake Debug, tests on; full `ctest`; `readelf` | 83/83; SONAME `libaxiam.so.3` |
| cplusplus | cmake Debug, tests on, shared; `ctest` | 2/2 (`axiam_cpp_tests` 1672 cases, 6579 checks, 0 failed) |

The probes lived only in the scratch worktrees. Peak scratch use was about 1.5 GB (the Rust target dir).

### A2.2 Status of the findings this sweep addressed

| ID | SDK | Status | Evidence on the sweep-2 head |
|---|---|---|---|
| C165-22 | php | **Closed** (read; not run) | `oauth2PostOptions()` (`src/Oidc/OidcClient.php:2940-2958`) adds `allow_redirects => false` to every `/oauth2/*` form POST: `postForm` (`:2985`), the device poll (`:1116`), the CIBA poll (`:2534`) and `postTokenAsync` (`:2684`). A `3xx` becomes `NetworkError` before the 5xx branch in both polls (`:1123-1126`, `:2539-2542`). The polls' retry predicates do not retry it: the device predicate refuses any status `< 500`, and the CIBA predicate only accepts null/5xx/408/429. The `Location` is neither followed nor echoed (`redirectRefused`, status only). The test (`tests/Contract165/Oauth2RedirectRefusalTest.php`) runs through `HandlerStack::create`, so Guzzle's redirect middleware is really in the path. It covers 307 and 308 for `oidcRefresh` and both polls, with retry on, and asserts one request and no request to the other host. See A2.4 point 1 on the fulfilled-value choice. |
| C165-23 | java | **Closed** | `oauth2HttpClient = httpClient.newBuilder().followRedirects(false).followSslRedirects(false)` (`AxiamClient.java:745`). `executeFormPost(url, form)` uses it (`:4342-4343`), and `pollHttpClient` is derived from it (`:746`), so the device poll (`:3765`) and the CIBA poll (`:5018`) follow nothing either. The other `/oauth2/*` POSTs already rode redirect-free clients: native sign-in on `Sessionless` (`followRedirects(false)`) and `cibaInitiate` on `sendOnceHttpClient` (`:747-749`). No other `/oauth2/*` POST exists. The shipped tests cover `oidcRefresh` (307, 308) and client credentials (307, 302). The reviewer's poll probes passed. Deriving from `httpClient` keeps its interceptors, which is the 1.63 posture it already had. |
| C165-23 | kotlin | **Closed except `cibaInitiate`** → C165-29 | `oauth2Client` (lazy, `followRedirects(false)`/`followSslRedirects(false)`) and `executeOAuth2Post` (`oidc/OidcSupport.kt:2110-2134`) now carry native sign-in (`:701`), revoke (`:806`), the CIBA poll (`:1494`), the UMA ticket (`:1773`) and `postOAuth2Form` (`:2073`). `postOAuth2Form` serves PAR, introspect, device authorization, token exchange, the token grants and the device poll. `cibaInitiate` (`:1408`) still calls `httpClient.newCall` directly. Probed: see C165-29. |
| C165-25 | java | **Closed** | `isRedirect` → `fromHttpResponse` (a `NetworkError`) at the top of `fromOAuth2Response` and `fromOAuth2ErrorAtAnyStatus` (`errors/ErrorMapper.java:136-138`, `:169-172`). `fromDevicePollResponse` delegates to the first. Unit test on both mappers. |
| C165-25 | kotlin | **Closed except `cibaInitiate`** → C165-29 | The check sits in the transport (`executeOAuth2Post`, `3xx` → `NetworkError` before any mapper runs), not in `ErrorMapper`. So every path through it is covered. `cibaInitiate` maps with `fromOAuth2ResponseAtAnyStatus` (`:1414`), which is unchanged. Probed: a `307` with an `error` body there is `OAuthProtocolError`. |
| C165-25 | rust | **Closed** | `oauth2_error_or_fallback` returns `AxiamError::Network` for `300..400` before reading the body (`src/oidc/exchange.rs:349-360`). It is the only `OAuth2ErrorResponseWire` reader (15 call sites). New test in `contract_165_test`. |
| C165-25 | csharp | **Closed** | `MapOAuth2ErrorAnyStatusAsync` checks the status first (`AxiamClient.ClientRegistration.cs:339-345`). The other two readers (`MapOAuth2ErrorAsync`, `MapUmaGrantErrorAsync`) already gate on 400/401/403, so a `3xx` falls to `ErrorMapper`'s `NetworkError`. |
| C165-25 | python | **Closed** | `error_from_oauth2_response` returns `error_from_http_status(...)` for 300–399 before `_oauth2_error_body` (`_errors.py:366-370`). For a 3xx that is `NetworkError` (only 401/403/409 map otherwise). It is the only reader. Tests in `tests/test_oidc_token_grants.py`. |
| C165-25 | c | **Closed except the UMA ticket exchange** → C165-30 | `oidc_map_grant_error` sets `AXIAM_ERR_NETWORK` for 300–399 before parsing (`src/oidc.c:497-503`). It serves the token grants, native sign-in, `ciba_initiate` and `ciba_poll` (`oidc_ciba.c:440`, `:569`). `uma.c`'s own `map_oauth2_error` (`:85-110`, called at `:825` for any non-2xx) still dispatches on the body first. |
| C165-25 | cplusplus | **Closed** | `raise_grant_error` throws `NetworkError("… (HTTP 3xx)", "http_3xx")` before the body (`src/oidc.cpp:474-480`). The CIBA poll's terminal path ends in it, and the poll does not retry a 3xx. The UMA ticket exchange guards separately with `raise_for_status` for a 3xx (`src/client.cpp:1516-1517`), whose fall-through is `NetworkError("unexpected HTTP status (3xx)")`. Three new cases in `tests/test_oidc_errors.cpp`. |
| C165-26 | typescript | **Closed** | `oauth2RequestConfig` sets `fetchOptions: { credentials: 'omit', redirect: 'error' }` (`src/rest/session.ts:329`). `bareRequest` maps status 0 or 300–399 to `NetworkError` without the `Location` (`src/rest/bareTransport.ts:72-78`). Both are needed. axios 1.21's fetch adapter overrides `redirect` to `'manual'` when `maxRedirects === 0` (`lib/adapters/fetch.js:521-527`), and `bareRequest` sets `maxRedirects: 0`. So on the RFC 7592 path a browser hands back an opaque-redirect (status 0), and the new guard catches it. On the main client's `/oauth2/*` requests (no `maxRedirects`), `'error'` makes `fetch` reject. One comment is inaccurate: C165-32. |
| C165-27 | c | **Closed** | `README.md:33-37` now says 1.1.x ships `libaxiam.so.2` and the contract-1.65 (1.2) release ships `libaxiam.so.3`, which matches `CMakeLists.txt` and `readelf`. |

### A2.3 New findings (sweep 2)

| ID | Severity | SDK | `path:line` | Rule | What | Fix |
|---|---|---|---|---|---|---|
| C165-29 | Low | kotlin | `src/main/kotlin/io/axiam/sdk/oidc/OidcSupport.kt:1405-1416` (`cibaInitiate`) | §12.1 rule 3; C165-23/-25 residual | `cibaInitiate` (`POST /oauth2/bc-authorize`) was not moved to `executeOAuth2Post`. It still runs `httpClient.newCall` on the redirect-following client. Its `OneShotBody` stops OkHttp from following a 307/308, but a 301–303 is followed as a body-less `GET` to any host, and that host's answer is accepted. **Probed:** `302 Location: <second MockWebServer>` returned `Success(CibaInitiateResponse(...))` built from the second host's `auth_req_id`, one `GET` there. A `307` with an `{"error":…}` body surfaced as `OAuthProtocolError`. No secret leaks (the `GET` carries no form), but the rule's MUST is broken. The CHANGELOG list omits `cibaInitiate`, which is how it was missed. | Keep the existing `IOException` catch (its message carries only the exception's class name), but run the call on `oauth2Client` and add `if (response.code in 300..399) { response.close(); throw NetworkError("cibaInitiate: redirect (HTTP ${response.code}) not followed") }` before the mapper. Tests in `CibaTest`: 302 and 307 (with an error body) → `NetworkError`, zero requests at the second host. Add `cibaInitiate` to the CHANGELOG list. About 5 lines + 2 tests. |
| C165-30 | Info | c | `src/uma.c:85-110` (`map_oauth2_error`), `:824-825` | §12.1 rule 3; C165-25 residual | The UMA ticket exchange (`POST` to the token endpoint) maps any non-2xx through its own mapper, which reads the body first. So a `3xx` carrying `{"error":…}` is `AXIAM_ERR_AUTH` with `oauth_error` set, not `AXIAM_ERR_NETWORK`. No redirect is followed (libcurl `FOLLOWLOCATION` is off). The C++ fixer guarded the same path (`client.cpp:1516`); C did not. Found by reading. | First statement of `map_oauth2_error`: `if (resp->status >= 300 && resp->status < 400) { axiam_error_set(err, AXIAM_ERR_NETWORK, resp->status, "uma ticket exchange failed"); return AXIAM_ERR_NETWORK; }`, plus one test. Trivial. |
| C165-31 | Info | kotlin | `src/main/kotlin/io/axiam/sdk/oidc/OidcSupport.kt:2087-2116` | doc accuracy | The new KDoc for `oauth2Client` was inserted between `executeRequest`'s existing KDoc (the §12.3 rule 3 "structural guarantee" paragraph) and `executeRequest`. Two KDoc blocks now precede `oauth2Client`, so Dokka attaches the second one, the first is orphaned, and `executeRequest` loses its documentation. The orphaned paragraph is the regression note for the 401-never-refreshes invariant. | Move `executeRequest`'s KDoc back down to directly above `private suspend fun executeRequest`. Doc-only. |
| C165-32 | Info | typescript | `src/rest/session.ts:318-323` | doc accuracy | The comment says the fetch adapter "ignores `maxRedirects`" and that with `redirect: 'error'` "`fetch` then rejects". In axios 1.21 a `maxRedirects` of 0 overrides `redirect` to `'manual'`, so on the `bareRequest` path the browser returns an opaque-redirect rather than rejecting. The code is right, because the guard in `bareTransport.ts:72-78` exists for exactly this case. Only the explanation is wrong. C165-26's own wording ("does not honour `maxRedirects`") made the same error. | Reword: "`redirect: 'error'` makes `fetch` reject on the main client; where `maxRedirects: 0` is set (the bare transport) axios substitutes `'manual'`, and `bareRequest` maps the opaque-redirect (status 0) or `3xx` to `NetworkError`." |

**Counts (new):** Low 1 (C165-29) · Informational 3 (C165-30, -31, -32). No Medium, High or Critical.

### A2.4 Verdicts on the points the orchestrator asked about

1. **PHP: `postTokenAsync` fulfils with the `NetworkError` as a value.** Correct, and it is the smallest choice
   that works. `RefreshGuard::settle` turns every rejection that is not an `AuthError` into
   `AuthError('token refresh failed: …')` (`src/Auth/RefreshGuard.php`, `settle`), and `join` does the same.
   A rejected `NetworkError` would therefore reach the caller as `AuthError`, which contradicts §12.1 rule 3. As a
   fulfilled value it passes through `settle`'s success path. That path runs `onClear` (the slot is cleared, so
   the outcome is not cached for the next caller, §9.3), and the OIDC kind passes no `onSuccess`. The leader
   (`$guarded['promise']->wait()`) and every same-kind joiner (`RefreshGuard::join`) receive the **same**
   `NetworkError` instance and throw it (`OidcClient.php:632-636`, `:650-653`). So the single flight still shares
   one wire call and one outcome. A different-kind waiter (the cookie-session path) only joins in order to retry
   the acquire, and ignores the value. The only cost is that the one exception object is thrown from several
   stacks, so its trace shows where it was built, not each throw site. That is harmless.
2. **Java: `pollHttpClient` derived from `oauth2HttpClient`.** Correct. The poll client keeps
   `retryOnConnectionFailure(false)` (the §16.1 attempt count) and gains the redirect refusal. Both clients come
   from `httpClient` through `newBuilder()`, so they share its connection pool and its interceptors, as the poll
   client always did.
3. **Kotlin: a cookie jar on `oauth2Client`.** This does not contradict the 1.63 paragraph. The rule forbids
   *attaching* `axiam_*` cookies or `X-CSRF-Token` to `/oauth2/*`, not having a jar. `newBuilder()` copies
   `AuthHeaderInterceptor`, which tags every `/oauth2/*` request with `NO_SESSION_CREDENTIALS_HEADER` (and adds
   no CSRF header). It also copies `NoSessionCredentialsNetworkInterceptor`, which strips `Cookie` after
   `BridgeInterceptor` has applied the jar (`internal/AuthHeaderInterceptor.kt:110-135`; `AxiamClient.kt:275-285`).
   These requests rode the same jar and interceptors before the sweep. The only change is that they no longer
   follow redirects, which also removes the one way a jar could have mattered: a followed hop to another path.
4. **Kotlin: native sign-in through `executeOAuth2Post`.** The one-shot body is intact. The request is still
   built as `post(OneShotBody(form))` (`OidcSupport.kt:700`). The helper only changes the client and adds the
   `3xx` check, and it closes the response before throwing. `NativeSignInTest` passed 14/14. With redirects off,
   the one-shot body now guards only OkHttp's silent retry, which is its §37.2 rule 10 job.
5. **TypeScript: `redirect: 'error'` plus the status-0/3xx guard.** Both are needed, and the fixer's reading of
   axios is right (see A2.2, C165-26). The guard covers the RFC 7592 path, where `maxRedirects: 0` makes axios
   choose `'manual'`. `'error'` covers the main client's `/oauth2/*` calls. The comment is C165-32.
6. **C++: the UMA ticket exchange guard in `client.cpp`.** Correct and needed. That path dispatches on the
   body's `error` at any status (§20.4) before it reaches `raise_grant_error`, so without the guard it would have
   been the C++ twin of C165-30. `raise_for_status` gives `NetworkError` for any 3xx.

### A2.5 Records left as they were

- **C165-24** (Info, contract record text in §34.9 "Amended 2026-10-31" item (5)) is **Open**, as recorded. The
  sentence at `sdks/CONTRACT.md:14271` still reads "(same-host only; Rust for `/oauth2/*` on `http_bare`)" and
  still omits Java and Kotlin. `CONTRACT.md` is unchanged since `d93976b`. It belongs in the next contract text
  pass. A re-vendor only for this is not worth it.
- **C165-28** (Info, Kotlin `OidcRefreshTest` flake) is **Open**, as recorded. Neither `62d0e47` nor `320cefa`
  touches `oidcRefresh`'s logic beyond the transport swap or the test. Both CI legs on `320cefa` are green, and
  no reproduction was attempted this round.

### A2.6 Before W5

- **Should fix before the 1.2.0 tags:** C165-29 (Kotlin `cibaInitiate`). It is the one remaining breach of the
  §12.1 rule 3 MUST in the eleven SDKs, and it is about 5 lines and 2 tests.
- **Cheap, may ride the same commits:** C165-30 (C UMA guard, one `if`), C165-31 (move a KDoc), C165-32 (one
  comment).
- **May defer:** C165-24 (next contract text pass) and C165-28 (tracked flake).
- **Still to confirm:** C++ `llvm-cov coverage → Coveralls` on `c37f016` was still running when read. Every other
  check run on the nine heads concluded success or skipped (publish and tag gates).

**Final status, C165-01 … C165-32:** 01 Closed · 02 Closed · 03 Closed · 04 Closed · 05 Closed · 06 Closed ·
07 Closed · 08 Closed · 09 Closed · 10 Closed · 11 Closed (Rust closed as decided) · 12 Closed · 13 Closed ·
14 Closed · 15 Closed · 16 Closed · 17 Closed · 18 Closed · 19 Closed · 20 Closed · 21 Closed · 22 Closed ·
23 Closed (Kotlin `cibaInitiate` residual → 29) · **24 Open (Info)** · 25 Closed (Kotlin `cibaInitiate` → 29,
C UMA → 30) · 26 Closed · 27 Closed · **28 Open (Info)** · **29 Open (Low)** · **30 Open (Info)** ·
**31 Open (Info)** · **32 Open (Info)**.
