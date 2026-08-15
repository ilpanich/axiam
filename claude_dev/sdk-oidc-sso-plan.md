# SDK OIDC / SSO Relying-Party Helpers — Implementation Plan

> **Status: SHIPPED.** The helpers below are specified as CONTRACT §12
> ("OIDC/SSO Relying-Party Helpers") in [`sdks/CONTRACT.md`](../sdks/CONTRACT.md)
> and are implemented across the SDK fleet. Cross-SDK conformance was reviewed
> in [`sdk-oidc-sso-conformance-review.md`](sdk-oidc-sso-conformance-review.md)
> (18 of 19 follow-up findings are still open and untracked — see
> `remediation-plan-2026-08-15.md` R5.7). The plan below is kept as the
> original design record; it is not being rewritten to past tense.
>
> Scope: the eight **backend-capable** client SDKs (`axiam-rust-sdk`, `axiam-typescript-sdk`,
> `axiam-python-sdk`, `axiam-java-sdk`, `axiam-kotlin-sdk`, `axiam-csharp-sdk`,
> `axiam-php-sdk`, `axiam-go-sdk`) plus a contract amendment in this repository
> (`sdks/CONTRACT.md`). The device/client-oriented SDKs (`axiam-swift-sdk`,
> `axiam-c-sdk`, `axiam-cplusplus-sdk`) are **explicitly deferred** — see §8.
> Each task below is sized to be one executable task for a developer agent in a
> follow-up run, and carries the **recommended model** (cheapest adequate choice
> between Opus 5 and Sonnet 5) to drive that agent.

## 1. Problem statement — what is missing today (surveyed 2026-07-27)

The AXIAM server already ships a complete OIDC provider + federation surface
(`sdks/openapi.json`):

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery |
| `GET /oauth2/authorize` | Authorization endpoint (code flow, PKCE, `state`, `nonce`) |
| `POST /oauth2/token?tenant_id=<uuid>` | Token endpoint — `authorization_code`, `client_credentials`, `refresh_token` grants (form-encoded `TokenRequest`, returns `TokenResponse` with optional `id_token`) |
| `GET /oauth2/jwks` | Signing keys (EdDSA/Ed25519) |
| `POST /oauth2/introspect`, `POST /oauth2/revoke` | RFC 7662 / RFC 7009 |
| `POST /api/v1/auth/federation/oidc/start` | First-time SSO against an upstream IdP: returns IdP authorize URL, server persists state+nonce (10-min TTL, D-22) |
| `POST /api/v1/auth/federation/oidc/callback` | Single-use state consumption, user provisioning/linking, returns **Set-Cookie** session (no token in body) |

The SDKs, however, only implement the CONTRACT §1 vocabulary: `login`
(direct password `POST /api/v1/auth/login`), `verify_mfa`, `refresh`, `logout`,
`check_access`/`can`/`batch_check`, and gRPC `get_user_info`, plus the §10/§11
resource-server middleware (local JWKS verification of inbound bearer tokens).

**A backend developer today cannot implement "Login with AXIAM" (OIDC/SSO) using
any SDK.** Specifically, no SDK has:

- OIDC discovery-document fetch/cache;
- authorization-URL construction with CSPRNG `state`, `nonce`, and PKCE S256
  verifier/challenge generation;
- authorization-code → token exchange against `POST /oauth2/token`;
- ID-token validation as a *relying party* (`iss`/`aud`/`exp`/`nonce`/signature);
- `client_credentials` grant for service-account M2M auth;
- token introspection/revocation calls;
- helpers for the federation SSO endpoints (`/federation/oidc/start|callback`).

(Verified by grep across all SDK repos: zero non-test source hits for
`authorization_code`, `client_credentials`, `code_verifier`, `/oauth2/token`,
or `/oauth2/authorize`.)

What each backend SDK *does* already have, and the new work must reuse:

| SDK | JWKS/EdDSA verification to reuse | HTTP core to reuse | Framework surface |
|---|---|---|---|
| Rust | `src/token/jwks.rs` | existing reqwest-based client | Actix extractor (`src/middleware/actix.rs`) |
| TypeScript | `src/node/jwks.ts` (+ `src/node/session.ts`) | `src/rest/` core | Express/Fastify middleware, NestJS module |
| Python | `src/axiam_sdk/_jwks.py`, `token/` | `_client.py` / `_async_client.py` | FastAPI deps, Django middleware |
| Java | JWKS logic reachable from `io/axiam/sdk/AxiamClient.java` | `AxiamClient` HTTP core | Spring filter/auto-config (`spring/`) |
| Kotlin | `src/main/kotlin/io/axiam/sdk/internal/JwksVerifier.kt` | `AxiamClient.kt` | Ktor plugin (`ktor/AxiamAuthentication.kt`) — JVM-only SDK, Ktor `compileOnly` |
| C# | `Axiam.Sdk/Auth/Jwk.cs` | `Axiam.Sdk` core | `Axiam.Sdk.AspNetCore` middleware + policies |
| PHP | `src/Auth/JwksVerifier.php` | `src/AxiamClient.php` | Laravel provider, Symfony bundle |
| Go | `internal/jwks/verifier.go` | `client.go` | `middleware/nethttp.go` |

## 2. Design — canonical operation set (to be locked in CONTRACT §12)

CONTRACT §1 forbids any SDK method names outside the naming map, so the contract
amendment (Task T0) is a **hard prerequisite** for every SDK task. The proposed
canonical vocabulary (final casing per language follows the existing §1 casing
rules):

| Canonical operation | Endpoint | Semantics |
|---|---|---|
| `oidc_discover` | `GET /.well-known/openid-configuration` | Fetch + cache discovery doc (TTL ≥ 5 min, single-flight, per-base-URL). Returns typed `OidcConfiguration`. |
| `oidc_begin` | *(no wire call, uses discovery)* | Build authorization request: CSPRNG `state` (≥128-bit) and `nonce`, PKCE verifier (43–128 chars) + **S256** challenge (never `plain`). Returns `AuthorizationRequest { url, state, nonce, code_verifier }`. Caller stores `state`/`nonce`/`code_verifier` in its own session and redirects the browser to `url`. |
| `oidc_exchange` | `POST /oauth2/token` (`grant_type=authorization_code`) | Exchange `code` + `code_verifier` + `redirect_uri` (+ `client_id`, optional `client_secret` for confidential clients; `tenant_id` as query param). Validates the returned `id_token` (checklist in §3) before returning `OidcTokenSet { access_token, id_token, id_claims, refresh_token?, expires_in, scope? }`. |
| `oidc_refresh` | `POST /oauth2/token` (`grant_type=refresh_token`) | Refreshes an `OidcTokenSet`. MUST run under the existing §9 single-flight refresh guard. Distinct from session `refresh` (cookie/opaque-token path) — do not merge the two. |
| `login_client_credentials` | `POST /oauth2/token` (`grant_type=client_credentials`) | Service-account M2M login: `client_id` + `client_secret` (+ optional `scope`). Returns the token set; the SDK may then use it as its bearer credential exactly like a `login()` result. |
| `introspect` | `POST /oauth2/introspect` | RFC 7662; returns typed `IntrospectionResult { active, ... }`. |
| `revoke` | `POST /oauth2/revoke` | RFC 7009; returns void; treat HTTP 200 as success even for unknown tokens. |
| `sso_start` | `POST /api/v1/auth/federation/oidc/start` | Upstream-IdP SSO step 1 (`OidcStartRequest` → `OidcStartResponse.authorize_url`). No JWT required. |
| `sso_complete` | `POST /api/v1/auth/federation/oidc/callback` | Step 2: posts `OidcPublicCallbackRequest`; session arrives as **Set-Cookie**, so the §4 cookie-jar requirement applies verbatim; returns `SsoLoginSuccessResponse`. |

Cross-cutting rules (normative, identical in all SDKs — the amendment text must
state them):

1. **Stateless by default.** `oidc_begin`/`oidc_exchange` never store
   `state`/`nonce`/`code_verifier` inside the SDK; the caller owns that storage.
   Framework integrations MAY add an optional `OidcStateStore` interface with an
   in-memory reference implementation (TTL 10 min, single-use consume — mirrors
   the server's `federation_login_state` semantics).
2. **Sensitive wrapping (§7).** `access_token`, `refresh_token`, `id_token`,
   `client_secret`, and `code_verifier` are `Sensitive<T>` in every SDK; never
   logged, never in `Debug`/`toString` output.
3. **Error taxonomy (§2).** `OAuth2ErrorResponse` bodies map to a new
   `OAuthProtocolError` subtype of the existing taxonomy carrying `error` +
   `error_description`; HTTP 400 from the token endpoint MUST NOT surface as a
   generic validation error. ID-token validation failures raise
   `AuthenticationError` with a machine-readable reason code.
4. **Tenant context (§5).** `tenant_id` is a required argument (or client-level
   config) for `oidc_exchange`, `oidc_refresh`, and `login_client_credentials`
   (query param on the token endpoint); org/tenant slugs for `sso_start` follow
   the §5.1 rules.
5. **REST `/oauth2/userinfo` stays out** of the SDK vocabulary (existing closing
   note): RP claims come from the validated ID token; identity lookups use gRPC
   `get_user_info`.
6. **TLS (§6)** applies; the discovery cache key includes the scheme+host+port to
   prevent cross-issuer poisoning.

## 3. ID-token validation checklist (normative for `oidc_exchange`)

Reuse each SDK's existing JWKS verifier; validation per OIDC Core §3.1.3.7:

1. `alg` MUST be `EdDSA` — reject `none` and anything else outright.
2. Signature via `GET /oauth2/jwks`, keyed by `kid`; on unknown `kid`, one JWKS
   re-fetch then fail (same rule the §10 middleware already implements).
3. `iss` equals the discovery document's `issuer` (exact string match).
4. `aud` contains our `client_id`; if multiple audiences, `azp` must equal it.
5. `exp`/`iat`/`nbf` with clock skew ≤ 60 s.
6. `nonce` claim equals the caller-supplied nonce from `oidc_begin` (mandatory
   when the request scope included `openid`; the helper always includes it).
7. On any failure: `AuthenticationError`, and the token set is discarded (no
   partial success).

## 4. Task list, ordering, and model assignment

Execution order: **T0 → T1 → {T2…T8 in parallel} → T9.** T1 is the reference
implementation; T2–T8 are ports of a fully-specified design and can run as one
parallel wave.

Model-choice rule used below (best-but-cheapest): **Opus 5** only where the task
*creates* normative text or reference patterns that every other task copies, or
performs cross-repo adversarial review (design ambiguity → cheaper models drift);
**Sonnet 5** for everything that is a well-specified port with strong local
feedback (compilers, existing test harnesses, a reference implementation to
imitate). This mirrors the cost outcome of the sdk-auth-helpers run.

| # | Task | Repo | Model | Why this model |
|---|---|---|---|---|
| T0 | CONTRACT §12 amendment + naming-map rows + openapi/proto re-sync note | `axiam` | **Opus 5** | Normative spec text; every downstream task inherits its mistakes |
| T1 | TypeScript reference implementation | `axiam-typescript-sdk` | **Opus 5** | Establishes the file/test/doc patterns T2–T8 imitate |
| T2 | Rust port | `axiam-rust-sdk` | Sonnet 5 | Spec + reference exist; rustc/clippy give strong feedback |
| T3 | Python port | `axiam-python-sdk` | Sonnet 5 | Straight port; sync+async mirroring is mechanical |
| T4 | Go port | `axiam-go-sdk` | Sonnet 5 | Straight port; small API surface |
| T5 | Java port | `axiam-java-sdk` | Sonnet 5 | Straight port onto existing Spring surface |
| T6 | Kotlin port | `axiam-kotlin-sdk` | Sonnet 5 | Straight port onto existing Ktor plugin |
| T7 | C# port | `axiam-csharp-sdk` | Sonnet 5 | Straight port; ASP.NET Core patterns already in repo |
| T8 | PHP port | `axiam-php-sdk` | Sonnet 5 | Straight port onto Laravel/Symfony surfaces |
| T9 | Cross-SDK conformance review + contract conformance-statement update | all + `axiam` | **Opus 5** | Adversarial cross-repo review; catches semantic drift Sonnet ports may introduce |

Every task ends with a **signed commit** (project rule), a `CHANGELOG.md` entry,
and — for T1–T8 — a re-synced vendored `CONTRACT.md` copied from this repo after
T0 merges.

### T0 — Contract amendment (`axiam` repo) — **Opus 5**

1. Append **§12 "OIDC / SSO Relying-Party Helpers"** to `sdks/CONTRACT.md`
   containing: the §2 operation table above rendered as a naming map for all
   twelve languages (casing per existing §1 rules: Go/C# PascalCase, C
   `axiam_`-prefixed snake_case, C++ snake_case, others camel/snake as per
   language); the six cross-cutting rules; the §3 ID-token checklist; the
   stateless-state rule; and a deferral paragraph for Swift/C/C++ (§8 below).
2. Amend the §1 note "No SDK is permitted to expose additional login/auth/authz
   method names…" to reference §12 as part of the locked vocabulary.
3. Add the `OAuthProtocolError` row to the §2 error taxonomy and the
   HTTP-status mapping (`400` from `/oauth2/*` → `OAuthProtocolError`).
4. Log the addition in "Breaking Changes Log" as a **non-breaking, additive**
   contract 1.4 change.
5. Verify `sdks/openapi.json` already describes every §12 endpoint (it does as
   of 2026-07-27 — this step is a check, not an edit).
6. Deliverable check: `grep -c "oidc_" sdks/CONTRACT.md` > 0; markdown renders;
   no server code touched.

### T1 — TypeScript reference implementation — **Opus 5**

Repo: `axiam-typescript-sdk` (npm `axiam-sdk`, TS ~5.9, tsup build, vitest).

1. New module `src/node/oidc.ts` (+ re-exports from `src/node/index.ts` and a
   subpath export if the existing `package.json` `exports` map is per-area):
   `discover()`, `oidcBegin()`, `oidcExchange()`, `oidcRefresh()`,
   `loginClientCredentials()`, `introspect()`, `revoke()`, `ssoStart()`,
   `ssoComplete()` — Node-only (uses `node:crypto` for CSPRNG + SHA-256/base64url
   PKCE; no WebCrypto fallback needed since this lives under `src/node/`).
2. Reuse: `src/node/jwks.ts` for ID-token verification (extend, don't fork);
   `src/rest/` request core for transport + §2 error mapping; `Sensitive`
   wrapper wherever the repo defines it; the §9 single-flight guard for
   `oidcRefresh`.
3. Types in the same file or `src/node/oidcTypes.ts`: `OidcConfiguration`,
   `AuthorizationRequest`, `OidcTokenSet`, `IntrospectionResult`,
   `OidcStateStore` (interface) + `MemoryOidcStateStore` (10-min TTL,
   single-use `consume(state)`).
4. Framework glue: `oidcLoginHandlers(client, store, opts)` in
   `src/middleware/` returning `{ login, callback }` Express-compatible
   handlers (redirect to `url` / consume state + exchange + establish session
   via the existing `src/node/session.ts` machinery). Fastify variant mirrors
   the existing plugin pattern.
5. Tests (vitest, mock the HTTP layer the way existing rest tests do):
   discovery caching + single-flight; PKCE S256 vector (RFC 7636 Appendix B);
   state/nonce entropy and uniqueness; full happy-path exchange; each ID-token
   validation failure from §3 (wrong iss/aud/exp/nonce/alg/`kid`);
   `OAuth2ErrorResponse` → `OAuthProtocolError` mapping; client-credentials
   happy path; revoke-is-idempotent; `MemoryOidcStateStore` single-use + TTL.
6. Example under `examples/` (Express "Login with AXIAM"), README section,
   CHANGELOG, vendored `CONTRACT.md` re-sync. `npm test` + `npm run build`
   green.

### T2 — Rust port — **Sonnet 5**

Repo: `axiam-rust-sdk` (single crate `axiam-sdk`, edition 2021, MSRV 1.88).

1. New module `src/oidc/mod.rs` (submodules `discovery.rs`, `authorize.rs`,
   `exchange.rs`, `state.rs`); methods on the existing client(s): `oidc_discover`,
   `oidc_begin`, `oidc_exchange`, `oidc_refresh`, `login_client_credentials`,
   `introspect`, `revoke`, `sso_start`, `sso_complete`.
2. PKCE/state/nonce via the crate's existing CSPRNG dependency (`rand`/`getrandom`
   — whichever is already in `Cargo.toml`; add `sha2` + `base64` only if absent).
   ID-token validation reuses `src/token/jwks.rs`.
3. Wrap secrets in the crate's existing `Sensitive` type; `Debug` must redact.
4. Actix glue (feature `actix`): a small `oidc_login_scope()` helper mirroring
   the existing extractor module's style is optional — implement only if it fits
   in the task budget; core primitives are the deliverable.
5. Tests under `tests/` following the repo's existing mock-server pattern
   (same coverage list as T1 item 5). RFC 7636 Appendix B test vector included.
6. Example in `examples/`, README, CHANGELOG, vendored contract re-sync.
   `cargo fmt --check`, `cargo clippy --lib`, `cargo test` green.

### T3 — Python port — **Sonnet 5**

Repo: `axiam-python-sdk` (PyPI `axiam-sdk`, ≥3.10, sync `_client.py` + async
`_async_client.py`, extras `fastapi`/`django`).

1. New `src/axiam_sdk/_oidc.py` with shared pure logic (PKCE via `secrets` +
   `hashlib`, URL building, ID-token checks reusing `_jwks.py`); sync methods on
   `AxiamClient` and async twins on the async client (`oidc_discover`,
   `oidc_begin`, `oidc_exchange`, `oidc_refresh`, `login_client_credentials`,
   `introspect`, `revoke`, `sso_start`, `sso_complete`) — respect the SDK-Q08
   async-naming rule.
2. Models in `_models.py` (dataclasses/pydantic — match whatever `_models.py`
   already uses); secrets use the repo's existing sensitive-value pattern.
3. Framework glue: FastAPI `oidc_login_router(...)` factory in
   `fastapi/__init__.py` (two routes: login-redirect + callback) and a Django
   view-pair helper in `django/`; both delegate to the shared core and the
   existing session-cookie machinery in `_session.py`.
4. Tests mirroring the repo's existing transport-mock style; same coverage list
   as T1; both sync and async paths. `pytest` + type check (whatever
   `pyproject.toml` gates) green.
5. Example, README, CHANGELOG, vendored contract re-sync.

### T4 — Go port — **Sonnet 5**

Repo: `axiam-go-sdk` (module `github.com/ilpanich/axiam-go-sdk`, go 1.25,
flat root package + `middleware/`, `internal/jwks/`).

1. New root-package file `oidc.go` (+ `oidc_types.go`): `OidcDiscover`,
   `OidcBegin`, `OidcExchange`, `OidcRefresh`, `LoginClientCredentials`,
   `Introspect`, `Revoke`, `SsoStart`, `SsoComplete` on the existing `*Client`.
   PKCE via `crypto/rand` + `crypto/sha256`; ID-token checks via
   `internal/jwks/verifier.go`.
2. `OidcStateStore` interface + in-memory impl (mutex + TTL) in the root
   package; `middleware.OidcLoginHandler`/`middleware.OidcCallbackHandler`
   `http.Handler` helpers in `middleware/` following `nethttp.go` conventions.
3. Secrets: match the SDK's existing sensitive-string handling (§7 row for Go).
4. Table-driven tests next to `oidc.go` using the same `httptest` patterns as
   `client_test.go`; same coverage list as T1; run with `-race`.
5. Example in `examples/`, README, CHANGELOG, vendored contract re-sync.
   `go vet ./...`, `go test -race ./...` green.

### T5 — Java port — **Sonnet 5**

Repo: `axiam-java-sdk` (`io.github.ilpanich:axiam-sdk`, Java 21, Maven,
Spring optional/provided).

1. New package `io.axiam.sdk.oidc`: `OidcOperations` implemented by
   `AxiamClient` (`oidcDiscover`, `oidcBegin`, `oidcExchange`, `oidcRefresh`,
   `loginClientCredentials`, `introspect`, `revoke`, `ssoStart`, `ssoComplete`),
   records for the §2 types, `SecureRandom` + `MessageDigest` for PKCE,
   ID-token checks via the client's existing JWKS path.
2. Spring glue in `io.axiam.sdk.spring`: an `AxiamOidcLoginController`-style
   registrar (or a pair of `HandlerFunction`s) auto-configured only when the
   consumer opts in via properties — same conditional-on-class pattern as
   `AxiamAutoConfiguration`.
3. Tests with the repo's existing HTTP-mock approach (WireMock/MockWebServer —
   use what's already a test dependency; add nothing new unless absent); same
   coverage list as T1. `mvn -q verify` green.
4. Example under `examples/`, README, CHANGELOG, vendored contract re-sync, BOM
   untouched (no new runtime deps).

### T6 — Kotlin port — **Sonnet 5**

Repo: `axiam-kotlin-sdk` (JVM-only, Kotlin 2.1, Ktor 2.x `compileOnly`).

1. New `src/main/kotlin/io/axiam/sdk/oidc/` mirroring T5's shape with suspend
   functions on `AxiamClient` (camelCase names per contract); PKCE via
   `java.security.SecureRandom`/`MessageDigest`; ID-token checks via
   `internal/JwksVerifier.kt`.
2. Ktor glue in `ktor/`: `Route.axiamOidcLogin(client, store, opts)` extension
   installing the login-redirect and callback routes — kept `compileOnly`-safe
   exactly like `AxiamAuthentication.kt` (core must compile without Ktor).
3. Tests with ktor-server-test-host + the repo's existing HTTP-mock style; same
   coverage list as T1. `./gradlew check` green.
4. Example, README, CHANGELOG, vendored contract re-sync.

### T7 — C# port — **Sonnet 5**

Repo: `axiam-csharp-sdk` (`Axiam.Sdk` + `Axiam.Sdk.AspNetCore`, net8.0).

1. In `Axiam.Sdk`: `Auth/Oidc/` folder — `OidcDiscoverAsync`, `OidcBegin`
   (sync, no I/O beyond cached discovery), `OidcExchangeAsync`,
   `OidcRefreshAsync`, `LoginClientCredentialsAsync`, `IntrospectAsync`,
   `RevokeAsync`, `SsoStartAsync`, `SsoCompleteAsync` (PascalCase +
   `Async` suffix per §1/SDK-Q08); `RandomNumberGenerator` + `SHA256` for PKCE;
   ID-token checks via `Auth/Jwk.cs` machinery.
2. In `Axiam.Sdk.AspNetCore`: minimal-API extension
   `MapAxiamOidcLogin(this IEndpointRouteBuilder, ...)` wiring the
   redirect + callback endpoints into the existing middleware/session pipeline;
   `IOidcStateStore` + `MemoryOidcStateStore` registered via DI.
3. Tests in the existing `tests/` projects (same mock style as current
   HTTP tests); same coverage list as T1. `dotnet test` green.
4. Example under `examples/`, README/docfx page, CHANGELOG, vendored contract
   re-sync.

### T8 — PHP port — **Sonnet 5**

Repo: `axiam-php-sdk` (`axiam/axiam-sdk`, PHP ≥8.1, Laravel provider +
Symfony bundle, PHPStan).

1. New `src/Oidc/` (e.g. `OidcClient.php`, `AuthorizationRequest.php`,
   `OidcTokenSet.php`, `OidcStateStoreInterface.php`, `MemoryOidcStateStore.php`)
   with camelCase methods surfaced on `AxiamClient`: `oidcDiscover`, `oidcBegin`,
   `oidcExchange`, `oidcRefresh`, `loginClientCredentials`, `introspect`,
   `revoke`, `ssoStart`, `ssoComplete`. PKCE via `random_bytes` + `hash('sha256')`
   with base64url; ID-token checks via `src/Auth/JwksVerifier.php`.
2. Framework glue: Laravel — two invokable controllers + route macro in the
   existing provider; Symfony — controller pair registered by the bundle,
   both optional and off by default.
3. Secrets use the repo's existing sensitive-value class (§7 row for PHP).
4. PHPUnit tests with the repo's existing HTTP-mock approach; same coverage
   list as T1. `composer test` + PHPStan at the configured level green.
5. Example, README, CHANGELOG, vendored contract re-sync.

### T9 — Cross-SDK conformance review — **Opus 5**

After T1–T8 land:

1. Diff every SDK's §12 surface against the contract: names, argument order,
   error mapping, Sensitive coverage, single-flight `oidc_refresh`, S256-only,
   stateless-state rule, cookie-jar on `sso_complete`. Produce a
   pass/fail matrix per SDK per rule (same format as prior conformance docs in
   `claude_dev/`).
2. Verify the RFC 7636 Appendix B vector test exists in all eight repos.
3. Update each repo's Conformance Statement section in the vendored contract,
   and the master `sdks/CONTRACT.md` conformance table here.
4. File follow-up issues for any drift instead of hot-fixing inside the review
   task (keeps the review adversarial and cheap to re-run).

## 5. What is explicitly out of scope

- Server-side changes — the provider endpoints already exist and are contract-
  stable; any server bug found becomes an issue, not a scope expansion.
- Implicit/hybrid flows and non-S256 PKCE — rejected by design.
- Device-authorization grant (RFC 8628) — server doesn't expose it yet.
- REST `/oauth2/userinfo` in the SDK vocabulary — stays excluded (existing
  contract closing note); ID-token claims + gRPC `get_user_info` cover it.
- Browser/SPA-side helpers — these SDKs are backend SDKs; the frontend flow is
  the consuming app's redirect + AXIAM's hosted login.

## 6. Acceptance criteria (applies to every SDK task)

1. All §12 operations implemented with contract-mandated names and semantics.
2. Full test coverage of the §3 ID-token checklist (one failing test per rule).
3. RFC 7636 Appendix B PKCE vector test present and passing.
4. No new runtime dependency unless the language stdlib lacks CSPRNG/SHA-256
   (none of the eight needs one).
5. Secrets `Sensitive`-wrapped; no token material in logs, exceptions, or
   `Debug`/`toString`.
6. Example + README + CHANGELOG + vendored CONTRACT re-sync committed.
7. Repo's full check pipeline green; signed commit per project rules.

## 7. Suggested execution schedule

| Wave | Tasks | Parallelism |
|---|---|---|
| 1 | T0 | solo (blocks everything) |
| 2 | T1 | solo (reference) |
| 3 | T2–T8 | 7 agents in parallel, one repo each |
| 4 | T9 | solo |

Cost note: only 3 of 10 tasks run on Opus 5; the seven parallel ports — the bulk
of the token spend — run on Sonnet 5 against a locked spec and a working
reference implementation, which is where Sonnet is reliably as good and several
times cheaper.

## 8. Deferred SDKs (Swift, C, C++)

These are device/IoT-oriented SDKs (Swift ships NIOSSL specifically for
client-cert mTLS; C/C++ target embedded consumers). The browser-redirect OIDC
RP flow has no natural home there, and their auth story (mTLS, password,
service credentials) is already covered. Defer §12 with the same
carve-out pattern the contract already uses for their gRPC deferral. If
server-side Swift (Vapor) demand materializes, a T-Swift port can be cloned
from T6's shape; `login_client_credentials` alone may be worth adding to C/C++
for machine-to-machine use — file as a separate follow-up decision.
