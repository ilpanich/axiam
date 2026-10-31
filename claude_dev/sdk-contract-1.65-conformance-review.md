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
