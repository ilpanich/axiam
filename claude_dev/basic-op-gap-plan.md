# OpenID Connect **Basic OP** — gap-closure plan, coexisting with FAPI 2.0

**Status: plan only.** No crate source changes accompany this document. It
designs the work needed for AXIAM to pass the OpenID Foundation's
`oidcc-basic-certification-test-plan` (certification profile **"Basic OP"**)
without loosening any security property the FAPI 2.0 Security Profile (Final)
posture already has, and without changing the behaviour of any client that
exists today.

Verified against `main` at `113bb9c` (which contains `e54df40`, the revision the
established facts were confirmed against; the two commits in between only add
`mtls_endpoint_aliases` to discovery). Every "verified" claim below names the
file and line it was read from.

> **Provenance note.** The task pointed at `claude_dev/openid-certification-strategy.md`
> as the decision this plan follows from. That file does not exist on `main`,
> on any remote branch, or anywhere in git history (`git log --all -- …` is
> empty). This plan therefore takes the task's *established facts* as the
> decision record, re-verifies each of them, and records where it had to
> decide something that document would presumably have settled. Those are
> collected in §11 so the maintainer can reconcile them with the strategy
> document if it exists outside the repository.

---

## 0. Executive summary

1. **RS256 is not required** for a static-client Basic OP run. Keep EdDSA-only.
   The one module that asserts RS256 is annotated not-applicable when
   `client_registration=static_client`, and the suite's generic signature check
   verifies Ed25519 keys. Details and citations in §1. **Say it loudly: no RSA
   key enters the JWKS, no SDK changes its `alg` pin, and the sharpest edge in
   this project disappears.**
2. **The gap list omitted the item everything else depends on.** AXIAM's
   authorization endpoint has **no browser login hop**: `/oauth2/authorize`
   requires an already-authenticated principal via the `axiam_access` cookie
   (`SameSite=Strict`, 15-minute lifetime) or a Bearer header, and answers an
   unauthenticated request with a 401 JSON body. A cross-site redirect from a
   relying party therefore *never* carries a session. `prompt=none`,
   `prompt=login`, `max_age`, `id_token_hint` and the "expect a login page"
   modules are all unreachable until this exists. It is **Gap 0** below and is
   the critical path.
3. **`client_secret_basic` is not one module of the Basic plan; it is the
   plan's default variant.** 37 of 38 modules run with
   `ClientAuthType = client_secret_basic`; exactly one runs `client_secret_post`.
   Without it there is no Basic OP badge. This was escalated (§10, decision A)
   and **decided yes by the maintainer on 2026-09-07**; W8 is unblocked
   because it touches a documented SDK-contract commitment — but see §10 for
   why the fan-out can be **zero**: the server can accept it while every SDK
   keeps sending `client_secret_post`.
4. Everything else fits the existing per-client, two-layer gate in
   `crates/axiam-oauth2/src/fapi.rs` with **one new per-client field**
   (`authn_request_params: ignore | honour`, default `ignore`), one new
   per-client field for the login hop (`browser_sso`, default off), one new
   `ClientAuthMethod` variant, and a set of tenant-level switches for the
   GDPR-sensitive scopes. Nothing is server-wide.
5. **Request objects are rejected, not implemented.** `request` →
   `request_not_supported`; a `request_uri` that is not a PAR URN →
   `request_uri_not_supported`. Both pass the plan. §9 says why nobody should
   "helpfully" implement them later.

---

## 1. Task 0 — does Basic OP certification require RS256?

### 1.1 What the specification says

OpenID Connect Core 1.0 §15.1 *Mandatory to Implement Features for All OpenID
Providers*:

> OPs MUST support signing ID Tokens with the RSA SHA-256 algorithm (an `alg`
> value of `RS256`), **unless the OP only supports returning ID Tokens from the
> Token Endpoint** (as is the case for the Authorization Code Flow) and only
> allows Clients to register specifying `none` as the requested ID Token
> signing algorithm.

(Text as quoted in the conformance suite's own issue tracker,
<https://gitlab.com/openid/conformance-suite/-/issues/1054>; `openid.net` is
not reachable from this environment's egress proxy, so the spec was not fetched
directly — the wording above is the errata-set-2 wording, cross-checked against
the search index of `openid-connect-core-1_0.html`.)

AXIAM is exactly that OP: `response_type=code` only, globally
(`crates/axiam-oauth2/src/authorize.rs:129`), so ID tokens are only ever
returned from the token endpoint. The clause's second half ("only allows
Clients to register specifying `none`") is about Dynamic Registration, which
AXIAM does not implement (no `registration_endpoint`, no `/oauth2/register`
route; verified by grep). The spec's exemption is written for the
signed-or-nothing code-flow OP and AXIAM sits inside it.

### 1.2 What the conformance suite actually asserts (the empirical answer)

Source: `OIDCCBasicTestPlan.java` and the modules it lists, read from
`https://gitlab.com/openid/conformance-suite/-/raw/master/src/main/java/net/openid/conformance/openid/`.

- The plan (`testPlanName = "oidcc-basic-certification-test-plan"`,
  `certificationProfileName → List.of("Basic OP")`) lists 38 modules, in three
  `ModuleListEntry` groups: 28 under `variantCodeBasic`
  (`ResponseType=code`, `ClientAuthType=client_secret_basic`,
  `ResponseMode=default`), **one** (`OIDCCServerTestClientSecretPost`) under
  `ClientAuthType=client_secret_post`, and 9 more under `variantCodeBasic`.
- **Exactly one module asserts RS256:** `OIDCCIdTokenSignature`
  (`oidcc-idtoken-signature`, summary "This test requests an ID token without
  specifying an algorithm (which should default to RS256)") calls
  `EnsureIdTokenContainsKid` and `EnsureIdTokenSignatureIsRS256`. Its class is
  annotated

  ```java
  @VariantNotApplicable(parameter = ClientRegistration.class, values = { "static_client" })
  ```

  so it **does not run** in the
  `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`
  configuration — the only configuration available to an OP without Dynamic
  Registration. Its sibling `OIDCCIdTokenUnsigned` (alg `none`) carries the
  same annotation.
- **Every other module validates the ID token through the generic path:**
  `AbstractOIDCCServerTest.performIdTokenValidation()` → sequence
  `PerformStandardIdTokenChecks` → `ValidateIdToken`,
  `ValidateIdTokenStandardClaims`, `ValidateIdTokenNonce`,
  `ValidateIdTokenACRClaimAgainstRequest`, **`ValidateIdTokenSignature`**,
  `CheckForSubjectInIdToken`, `EnsureIdTokenUpdatedAtValid`,
  `ValidateEncryptedIdTokenHasKid`. `ValidateIdTokenSignature` extends
  `AbstractVerifyJwsSignature`, whose verifier selection contains

  ```java
  if (jwkKey instanceof OctetKeyPair) {
      OctetKeyPair publicKey = OctetKeyPair.parse(jwkKey.toPublicJWK().toString());
      if (Curve.Ed25519.equals(publicKey.getCurve())) {
          verifier = new Ed25519Verifier(publicKey);
      }
  }
  ```

  and whose only algorithm gate is `JWAUtil.isJwsAlgorithm(headerAlg)`. There
  is no allow-list that excludes `EdDSA`, and no discovery-level condition in
  `AbstractOIDCCServerTest` inspects `id_token_signing_alg_values_supported`
  for `RS256`.
- Issue #1054 confirms the suite's one hard precondition on keys: it refuses to
  start without a `jwks_uri`. AXIAM publishes one
  (`crates/axiam-oauth2/src/oidc.rs:324`, `build_jwks`), with a deterministic
  `kid` (`oidc.rs:346`).

### 1.3 Finding and consequence

**Basic OP certification of AXIAM does not require RS256.** Keep the
EdDSA-only posture: `Algorithm::EdDSA` hard-coded at encode
(`crates/axiam-auth/src/token.rs:367`) and decode (`:1164`),
`id_token_signing_alg_values_supported: ["EdDSA"]` (`oidc.rs:243`), and the
contract's pin (`sdks/CONTRACT.md:1082` rule 1, `:2063` requirement 1)
unchanged in all eleven SDKs.

Consequences, stated so they are not re-derived:

| Consequence | Effect on this plan |
|---|---|
| No RSA key in the JWKS | Escalation B (§10) is answered **"no"** — by this analysis and, on 2026-09-07, by the maintainer. Nothing in the plan needs it; it is recorded only because the task asked that it never happen as a side effect |
| No SDK `alg` relaxation | Zero SDK fan-out from the ID-token side; `CONTRACT.md` §10 rule 1 and the `oidc_exchange` requirement 1 stay verbatim |
| FAPI 2.0 unaffected | FAPI 2.0 §5.3.1.1 permits `EdDSA`; nothing changes on that lane |
| Dynamic OP is foreclosed | The moment `client_registration=dynamic_client` is attempted, `OIDCCIdTokenSignature` becomes applicable and requires RS256. That is one of the reasons Dynamic OP is in §9 ("not doing") |
| Optional tightening: `kid` in the JWT header | `sign_claims` builds `Header::new(Algorithm::EdDSA)` with no `kid`, while the JWKS publishes one. Adding the JWKS `kid` to every header is additive, helps every RP's key selection, and lets the (skipped) `EnsureIdTokenContainsKid` pass if a dynamic run is ever attempted. Recommended as a W1 one-liner; it reaches the FAPI lane but only tightens (a header field that names the verifying key). SDK impact: none — CONTRACT §10 rule 1 already selects "by the header's `kid`" and today copes with its absence |

Residual risk worth naming: the module list is read from `master` of the
suite, not from the pinned version in `conformance/suite.env`. Before the
first Basic run, re-read `OIDCCBasicTestPlan.java` at the pinned tag and
re-confirm the `@VariantNotApplicable` annotation on `OIDCCIdTokenSignature`.
The certification programme has run static-client Basic OP certifications for
years (Dex and others hold them), so a reversal is unlikely, but the check
costs a minute and the plan's headline rests on it.

---

## 2. The tree as it is (verified), and the two things the gap list missed

### 2.1 Established facts, re-verified

| Fact | Where | Verified |
|---|---|---|
| Per-client `profile: standard \| fapi2`; serde default `standard`; pre-v38 rows decode to it | `crates/axiam-core/src/models/oauth2_client.rs:22`, `:178` | ✅ |
| Two-layer gate: `validate_registration` (registration) + `enforce_authorization_request` / `enforce_token_request` (request time, "defence in depth" against a DB-edited row); all no-ops for `standard` | `crates/axiam-oauth2/src/fapi.rs` | ✅ |
| Registration validation is called on create **and** update | `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:402`, `:589` | ✅ |
| Client auth dispatches on the **registered** method only (SEC-093) | `crates/axiam-oauth2/src/token.rs:585` `authenticate_client_credential`; rationale at `:1821` | ✅ |
| `ClientAuthMethod` = `ClientSecretPost` (default) \| `TlsClientAuth` \| `SelfSignedTlsClientAuth` \| `PrivateKeyJwt`; `client_secret_basic` is **explicitly refused** by `from_wire` and pinned by a test | `oauth2_client.rs:67`, test at `:861-865` | ✅ |
| `redirect_uri` exact + global | `authorize.rs:105` | ✅ |
| `response_type=code` only, global | `authorize.rs:129` | ✅ |
| `auth_time`, `acr`, `amr`, `prompt`, `max_age`, `login_hint`, `ui_locales`, `display`, `claims_locales` — **absent** from every crate | tree-wide grep | ✅ |
| EdDSA only for everything AXIAM mints; `RS256` appears only in `axiam-federation` for *verifying* upstream IdPs | `axiam-auth/src/token.rs:367`; `axiam-federation/src/oidc.rs:981` | ✅ |
| SDK contract pins ID-token `alg` to exactly `EdDSA` before key lookup; forbids `Authorization: Basic` to `/oauth2/*` | `sdks/CONTRACT.md:1082`, `:2063`, `:1590` (contract 1.40) | ✅ |
| Unknown authorization-request parameters are already ignored (serde drops them from `AuthorizeQuery`) | `crates/axiam-api-rest/src/handlers/oauth2.rs:67` | ✅ — `OIDCCEnsureRequestWithUnknownParameterSucceeds` passes today |

### 2.2 Facts the gap list did not carry, and which shape the design

| # | Fact | Why it matters |
|---|---|---|
| F1 | `/oauth2/authorize` takes `user: AuthenticatedUser` as an extractor (`oauth2.rs:115`). The extractor reads the `axiam_access` cookie, then `Authorization: Bearer/DPoP` (`extractors/auth.rs:361-387`); it never redirects. The handler's doc comment "(redirected to login first if not)" describes nothing in the code | There is **no login hop**. An unauthenticated authorize is a 401 JSON dead end |
| F2 | `axiam_access` is `HttpOnly; Secure; SameSite=Strict; Path=/`, `Max-Age` = access-token lifetime (`middleware/csrf.rs:295-316`, 15 min per the security standards) | A cross-site top-level navigation (which is what an RP redirect is) **never** sends a Strict cookie. Even a logged-in user arrives at authorize anonymous. This is why the FAPI harness's interactive modules are finished by hand in a tab that already holds the admin-UI session, and why `prompt=none` cannot work today even in principle |
| F3 | `Session` has `created_at`, `expires_at`, no authentication timestamp and no method evidence (`crates/axiam-core/src/models/session.rs:8`; schema `session` at `axiam-db/src/schema.rs:488`). Refresh rotation **creates a new session row** (`axiam-auth/src/service.rs:914`) | `created_at` cannot stand in for `auth_time`; it resets every refresh. `auth_time` must be a new column, copied across rotation |
| F4 | All browser logins funnel through `AuthService::create_session_and_tokens` (`service.rs:1285`) — password (`:434`), TOTP (`:671`), MFA-setup confirm (`:1202`), WebAuthn (`handlers/webauthn.rs:707`, `:756`), federation (`handlers/federation.rs:1759`) | One choke point to record the authentication event (`authenticated_at`, `amr`) |
| F5 | ID token minted in two places: code exchange (`axiam-oauth2/src/token.rs:1129`) and refresh (`:1619`, no nonce, same `sid`) via `issue_id_token` (`axiam-auth/src/token.rs:1103`) | `auth_time`/`acr`/`amr` must flow through both, consistently (OIDC §12.2: refreshed `auth_time` must equal the original) |
| F6 | `/oauth2/userinfo` is registered **GET-only** (`server.rs:653`); the extractor reads no `access_token` form field | `OIDCCUserInfoPostHeader` and `OIDCCUserInfoPostBody` **fail** today (they require HTTP 200). Not in the gap list; added below as G10 |
| F7 | `/oauth2/authorize` is GET-only | `OIDCCEnsurePostRequestSucceeds` only *warns* (`ExpectRedirectUriHasBeenCalled`, WARNING after 30 s). Optional item G11 |
| F8 | `User` has `username`, `email`, `metadata: serde_json::Value` — no phone, no address (`crates/axiam-core/src/models/user.rs`) | `address`/`phone` scopes need a data source, not just a claim mapper |
| F9 | A GDPR consent store exists: `Consent { consent_type, version, accepted_at, ip, ua }` + `ConsentRepository::{create, list_by_user}` (`models/gdpr.rs`, `repository.rs:2775`). AXIAM has **no OAuth consent screen** (the threat model labels the process "/oauth2/authorize (+ consent)" but nothing renders one) | The consent primitive for the GDPR-sensitive scopes already exists; only the screen and the release check are missing |
| F10 | PAR `request_uri` lifetime is **60 s** (`par.rs:55`); `PushedAuthParams` carries exactly the same seven fields as the inline query (`oauth2_client.rs:741`) | Every new authorization-request parameter must be added to **both** carriers or PAR requests silently lose it. A 60 s window also bounds how long a login hop may take for a PAR client |
| F11 | `id_token_hint` decoding already exists for end-session (`logout.rs:137`, `decode_id_token_hint`: signature-checked, expiry tolerated) | Reuse for `prompt=none` + `id_token_hint` (`OIDCCIdTokenHint`) |
| F12 | The FAPI plans run with `openid: plain_oauth` (`conformance/plans/*.json`, `variant` block) | The FAPI run exercises **no** OIDC authentication-request parameter. Every change on the honour lane is therefore invisible to it by construction — which is what lets §8 promise it stays green |
| F13 | Discovery is tenant-scoped (`?tenant_id=`), built by one pure function (`oidc.rs:221`) | Advertising is per tenant; behaviour is per client. The two must not be confused (§6) |

---

## 3. The coexistence mechanism, extended (not duplicated)

The pattern in `fapi.rs` is: **a field on the client row is the policy; the
registration handler validates the row before it is written; the request path
re-derives the same decision from the row it loaded.** Every addition below is
one of three things:

1. a new field on `OAuth2Client` / `CreateOAuth2Client` / `UpdateOAuth2Client`
   with a serde default equal to today's behaviour;
2. a new arm in `validate_registration` (typed `FapiRegistrationError`
   variant) that refuses the field on a `fapi2` row;
3. a new check in `enforce_authorization_request` / `enforce_token_request`
   that refuses the *mechanism* at request time when the row says `fapi2`.

### 3.1 New client fields

| Field | Type / wire | Default | Lane | Refused on `fapi2`? |
|---|---|---|---|---|
| `authn_request_params` | enum `ignore` \| `honour` | `ignore` | Basic | **yes**, both layers (`FapiRegistrationError::AuthnParamsOnFapiClient`) |
| `browser_sso` | bool | `false` | shared (Gap 0) | **no** — see §4.0; it is not a relaxation |
| `token_endpoint_auth_method: client_secret_basic` | new `ClientAuthMethod` variant, `is_strong() == false` | (unchanged default `client_secret_post`) | Basic | **yes**, both layers — *already*: `WeakClientAuth` at registration, `is_strong()` re-check in `enforce_token_request` |
| `scopes` containing `address` / `phone` | existing `Vec<String>` | — | Basic | yes at both layers (see G8) |

`authn_request_params = honour` is one field and one bundle, deliberately, for
the same reason `profile = fapi2` is one field: a client that honours `max_age`
but ignores `prompt=none` is not "mostly conformant", it is a client an RP
cannot reason about. The bundle covers: `prompt`, `max_age`, `acr_values`,
`claims` (only its `id_token.acr` member — see G4), `id_token_hint`,
`login_hint`, `display`, `ui_locales`, `claims_locales`.

### 3.2 `RegistrationView` grows, the function signature does not

`RegistrationView<'a>` gains `authn_request_params` and `browser_sso`; both
`From` impls fill them; `validate_registration` gains, after the existing
profile bundle:

```text
if profile.is_fapi2() && authn_request_params == Honour  → Err(AuthnParamsOnFapiClient)
if profile.is_fapi2() && scopes ∩ {address, phone} ≠ ∅   → Err(SensitiveScopesOnFapiClient)
```

(`client_secret_basic` needs no new arm: `is_strong()` returns `false` for it
and the existing `WeakClientAuth` arm fires.)

### 3.3 Request-time: one new argument, two rules

`enforce_authorization_request(client, code_challenge)` becomes
`enforce_authorization_request(client, code_challenge, params: &AuthnRequestParams)`
where `AuthnRequestParams` is the typed, already-parsed bundle (§4.1). Rules,
in order, all before any redirectable error:

1. **`fapi2` + any *security-bearing* parameter present** (`prompt`,
   `max_age`, `acr_values`, `claims`, `id_token_hint`) → `invalid_request`
   ("not supported for clients on the fapi2 profile"). Silently ignoring them
   is the downgrade this plan exists to prevent, and refusing is the stricter
   of the two lanes' behaviours. A conforming FAPI 2.0 RP sends none of these
   (F12), so no client that passes the FAPI plan today observes this.
2. **`fapi2` row edited to `honour`** (the DB-bypass case the existing gate
   guards against) → `invalid_request` + `tracing::error!` naming the row,
   mirroring `enforce_token_request`'s existing wording.
3. **`standard` + `ignore`** (every client that exists today): the cosmetic
   four are ignored exactly as today; the security-bearing five are **also
   ignored exactly as today** — this is invariant 4 — but logged at `warn`
   (rate-limited per client) so an operator can see which clients would
   benefit from `honour`. This is the one place invariants 3 and 4 pull in
   opposite directions, and 4 wins because it is the stated non-negotiable;
   §11 records it as a decision.
4. **`standard` + `honour`** → the honour lane (§4).

The cosmetic four (`login_hint`, `display`, `ui_locales`, `claims_locales`)
are never *refused* on `fapi2` when the row honestly says `ignore` — refusing
`login_hint`, which many RP libraries send by reflex, would break existing
FAPI clients for no security gain. Their mechanism (pre-filling, locale
selection, layout hint) is refused on `fapi2` by rules 1–2 above: the SPA only
ever receives them from a server redirect the server only builds on the honour
lane.

---

## 4. Per-item design

Each item states how it satisfies the five invariants:
**I1** opt-in per client · **I2** refused on `fapi2` at both layers ·
**I3** stricter default when unspecified · **I4** zero change for today's
clients · **I5** shared code only tightens, every touchpoint named.

### 4.0 Gap 0 — the browser login hop and the OP session cookie

**Mechanism.**

- New per-client `browser_sso: bool` (default `false`).
- New cookie `axiam_op_session`: `HttpOnly; Secure; SameSite=Lax; Path=/oauth2/authorize`,
  `Max-Age` = session lifetime (`refresh_token_lifetime_secs`). Value: 256 random
  bits; SHA-256 stored on the session row as `browser_token_hash` (schema
  v50). Set by `cookie_response_from_output` (`handlers/auth.rs:285`) on every
  browser login — issuing a cookie no client reads is not a client-visible
  change. Cleared by logout alongside the other three.
- `authorize` resolves the principal in this order: (a) existing
  `AuthenticatedUser` path (Strict cookie / Bearer) — unchanged; (b) **only if
  the client row says `browser_sso`**, the `axiam_op_session` cookie, hashed
  and looked up on `session` (existing `get_by_token_hash`-style read, plus
  expiry). Note that the client must be loaded *before* the principal is
  resolved, which is a reordering inside the handler: client lookup already
  precedes every redirectable error in the service, so this is moving the
  lookup one step earlier in the handler, not a new trust decision.
- Unauthenticated + `browser_sso`: if `prompt=none` → redirect error
  `login_required` (redirect only after `redirect_uri` exact-match, as every
  redirectable error already is; `state` echoed; `iss` appended); else HTTP 302
  to the admin SPA `/login?return_to=<path>` where `return_to` is a **same-origin
  path** that begins with `/oauth2/authorize?` (server builds it; SPA
  re-validates: no scheme, no host, no `//`, prefix-checked; navigation via
  `location.assign` of the path only). After login the SPA navigates to
  `return_to`; the browser now carries `axiam_op_session` (same-site
  navigation) and `authorize` runs through **every existing gate again** —
  PAR-required, exact `redirect_uri`, PKCE, FAPI gate. Nothing is cached across
  the hop.
- Unauthenticated + `!browser_sso`: 401 JSON exactly as today.

**Why `Lax`, why path-scoped, why a second cookie.** `Lax` is sent on top-level
GET navigations and nothing else — that is precisely the OIDC redirect and
precisely not an `<iframe>`, an `<img>`, or a cross-site `fetch`. Scoping to
`/oauth2/authorize` means the cookie can produce **only** an authorization code
for a registered exact `redirect_uri`, never an API call; the API surface keeps
its Strict cookies and CSRF double-submit untouched. A second cookie rather than
relaxing `axiam_access` keeps the API cookie's threat model exactly as SEC-046
documented it.

**Invariants.** I1: `browser_sso` per client. I2: *not applicable, by
argument* — the hop is not a relaxation FAPI forbids; FAPI 2.0 requires user
authentication and says nothing about how the user agent reaches the login
page. It is permitted on `fapi2` so that the FAPI harness's interactive
modules can eventually be run without the manual same-tab trick, and the
negative test that matters is that the return leg cannot skip PAR/PKCE (test
T0.4). I3: default off. I4: for `browser_sso=false` clients, byte-identical
behaviour; the new cookie is not consulted for them. I5 touchpoints:
`session` model + schema (additive column), `cookie_response_from_output`
(adds one cookie), logout (clears one more cookie), `authorize` handler
(principal resolution order), SPA login page (`return_to`, `reauth`).

**Threats.** Login CSRF at authorize (attacker navigates victim to
`/oauth2/authorize?client_id=attacker-rp…`): only a *registered* client with an
exact `redirect_uri` can receive the code, and the RP's `state`/PKCE bind the
code to the RP's own initiated request — the standard OIDC posture; recorded,
not new. Open redirect via `return_to`: prevented by same-origin-path
construction and re-validation on both sides (test T0.3). Cookie theft: the
cookie is HttpOnly and reaches only one path; a stolen value yields codes for
registered RPs only, and the session can be revoked like any other (it *is* the
session). PAR TTL: a `browser_sso` PAR client whose user takes longer than 60 s
to log in gets `invalid_request_uri` on return and the RP re-pushes — RFC 9126
§2.2's own design; documented, not worked around.

**Tests.** T0.1 unauthenticated + `browser_sso=false` → 401 JSON unchanged
(pins I4). T0.2 unauthenticated + `browser_sso=true` → 302 to `/login` with
path-only `return_to`. T0.3 `return_to` with a scheme/host/`//` is refused by
both builder and SPA. T0.4 return leg re-runs PAR-required and PKCE gates (a
`require_par` client cannot smuggle inline params through the hop). T0.5
`axiam_op_session` is not honoured for a `browser_sso=false` client even when
present. T0.6 cookie attributes pinned (Lax, HttpOnly, Secure, path).

### 4.1 Parsing: `AuthnRequestParams` (shared, tightening only)

`AuthorizeQuery` (`oauth2.rs:67`), `PushedRequest` (`par.rs:80`) and
`PushedAuthParams` (`oauth2_client.rs:741`) all gain the same optional fields:
`prompt`, `max_age`, `acr_values`, `claims`, `id_token_hint`, `login_hint`,
`display`, `ui_locales`, `claims_locales`. A pure `AuthnRequestParams::parse`
produces the typed bundle:

- `prompt`: space-separated set of `{none, login, consent, select_account}`;
  `none` combined with anything else → `invalid_request` (OIDC §3.1.2.1);
  unknown value → `invalid_request`.
- `max_age`: non-negative integer; `0` is `Some(0)`, **never** `None`
  (test T2.1); non-numeric or negative → `invalid_request`.
- `acr_values`: space-separated list, kept in RP-preference order.
- `claims`: JSON; only `id_token.acr` is read (`value`, `values`,
  `essential`); everything else is ignored *and said to be ignored* in
  discovery (`claims_parameter_supported: false`).
- `id_token_hint`: opaque string until decoded on the honour lane.
- `login_hint`, `display`, `ui_locales`, `claims_locales`: bounded-length
  strings (256 bytes), treated as data.

Parsing errors are raised **only on the honour lane**; on `ignore` rows the
fields are dropped as today (I4). The parse is total and typed so that no
handler ever reads a raw string for these.

Both carriers: the PAR endpoint stores the new fields alongside the existing
seven, and `consume` returns them; the inline path reads them from the query.
The "request_uri must not be combined with inline parameters" refusal extends
to the new fields (test T1.3) so a browser cannot add `prompt=none` to a pushed
request.

### 4.2 G1 — `prompt` (`none` / `login` / `consent` / `select_account`)

**Mechanism (honour lane only).**

- `none`: requires a resolved principal whose session satisfies `max_age` (if
  sent) and, when `id_token_hint` is sent, whose `sub` equals the hint's
  (`aud` must equal `client_id`; signature verified with
  `decode_id_token_hint`; expiry tolerated as end-session does). Any
  interaction need → redirect error, choosing the most specific of
  `login_required` (no session / hint mismatch / `max_age` unmet),
  `consent_required` (a consent-gated scope without a recorded consent — G8),
  `interaction_required` (anything else). All four are accepted by the suite's
  `CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface`.
- `login`: always redirect to `/login?reauth=1&return_to=…`. The SPA in
  `reauth` mode **always** performs a credential check (password/OPAQUE +
  MFA as policy requires, or passkey); success creates a *new* session with a
  fresh `authenticated_at` and a new `axiam_op_session`. The return leg then
  satisfies the request. Loop guard: each iteration requires a user action, so
  no automatic loop is possible; still, the SPA refuses a `reauth` `return_to`
  more than N=3 times per minute and shows an error instead (test T1.6).
- `consent`: redirect to `/login?consent=1&return_to=…` where the SPA renders
  the first-party consent screen (G8). If the client requests no consent-gated
  scope, the screen still shows (the RP asked for it) and records nothing.
- `select_account`: handled as `login` (a fresh sign-in *is* the account
  picker in a single-account SPA); for `none` combined semantics it yields
  `account_selection_required` only if a hint mismatch is the cause — in
  practice `login_required`.

**Invariants.** I1/I2/I3/I4 by the bundle field (§3). I5: `authorize` handler
gains the redirect-error branch; `AuthorizeService::authorize` gains the
`prompt` evaluation *after* client lookup, PAR check, `redirect_uri` match, and
the FAPI gate, and *before* code issuance — i.e. inside the existing "safe to
redirect" region.

**Threats and what remains.** Silent-authentication oracle: a registered RP
learns "logged in or not" — inherent to `prompt=none`, bounded to tenant-
registered clients with exact redirect URIs; recorded in the audit log per
outcome (`oauth2.prompt_none.{code,login_required,consent_required}` with
`client_id`) so abuse is visible. Login-status probing via iframe from a
third-party site: **fails closed** — `axiam_op_session` is `Lax` and an iframe
navigation is not top-level, so the OP sees no session and answers
`login_required`. This is stated as a functional limitation too: hidden-iframe
silent renew works only for RPs on the same site as AXIAM; cross-site RPs must
use a top-level navigation or the refresh token. Cross-site tracking: no
identifier is issued on the error path (the error carries only `state`, `iss`
and the code), and the success path issues a code only to the registered RP.
What global exact `redirect_uri` matching removes is the *exfiltration* of the
code to a third party; what remains is the one-bit login-status signal to a
registered client, which is accepted and audited.

**Tests.** T1.1 `prompt=none` + no session → 302 `error=login_required` with
`state` and `iss`, **no** code. T1.2 `prompt=none` + session → code, no
interaction, `auth_time` unchanged. T1.3 `prompt=none` in the query with a
`request_uri` → `invalid_request`. T1.4 `prompt=none login` →
`invalid_request`. T1.5 `prompt=login` → 302 to `/login?reauth=1`; after
re-login the second ID token's `auth_time` is strictly later (mirrors
`OIDCCPromptLogin`). T1.6 reauth loop guard. T1.7 `prompt=none` from an
iframe-shaped request (no cookie) → `login_required`.

### 4.3 G2 — `max_age` and `auth_time`

**Session evidence (shared, tightening).** Schema v50 adds to `session`:
`authenticated_at: datetime`, `amr: array<string>` (RFC 8176 values),
`browser_token_hash: option<string>`. `CreateSession` gains
`authenticated_at` and `amr`; `create_session_and_tokens` gains an `amr`
argument its five callers pass: `["pwd"]` (password), `["pwd","otp","mfa"]`
(TOTP), `["pwd","hwk","mfa"]` / `["hwk","user"]` (WebAuthn; `user` when UV
was performed), `["fed"]` plus whatever the upstream assertion carried
(federation — see below). **Refresh rotation copies `authenticated_at` and
`amr` from the old session** (`service.rs:914`) instead of stamping now: a
refresh is not an authentication event. Pre-v50 rows decode with
`authenticated_at = created_at` and `amr = []`; the plan notes that such a
session can never satisfy an ACR above the floor (G4) and never presents as
"fresh" beyond its creation, which is the strict direction.

Federated logins: `authenticated_at` is the upstream `auth_time` when the
upstream ID token carries one, else the moment AXIAM verified the assertion.
Using "now" would overstate freshness for an IdP with a long SSO session.

**Carrying it to the token.** `CreateAuthorizationCode` / `AuthorizationCode`
gain `auth_time: Option<DateTime>`, `acr: Option<String>`, `amr: Vec<String>`,
snapshotted at code issuance from the session. `issue_id_token` gains the three
optional claims; the refresh path (`token.rs:1619`) reads the session behind
`stored.session_id` so `auth_time` on a refreshed token equals the original
(OIDC §12.2; `OIDCCRefreshToken` compares).

**When the claims are emitted.** `auth_time` (and `acr`/`amr`) are emitted
when the client is on the honour lane, or when the request carried `max_age`
or an essential `acr` (which can only happen on the honour lane). For every
`ignore` client the ID token is byte-for-byte what it is today (I4). Turning
`auth_time` on for everyone is a one-line follow-up the maintainer may choose;
it is additive and truthful, but it is a visible change and this plan does not
make it.

**`max_age` evaluation.** `elapsed = floor(now − authenticated_at)` in whole
seconds; reauthenticate iff `elapsed >= max_age`. Hence `max_age=0` ⇒
`0 >= 0` ⇒ **always** reauthenticate — no special case, no `None` (test
T2.1). Server clock only; no leeway in the RP's disfavour. After reauth, the
second evaluation runs on the new session; if it still fails (clock went
backwards) the answer is `login_required`, never a code.

**Invariants.** I1–I4 via the bundle. I5 touchpoints: `session` model/schema,
`CreateSession`, `create_session_and_tokens` and its five callers, refresh
rotation, `AuthorizationCode` model/schema, `issue_id_token` signature (both
call sites), `IdTokenClaims` (three `skip_serializing_if` fields). All
additive; none changes an emitted byte for an `ignore` client (test T2.6 pins
the ID token of an `ignore` client against a golden claim set).

**Tests.** T2.1 `max_age=0` with a 1-second-old session → reauth (302
`/login?reauth=1`), never a code. T2.2 `max_age=1`, wait 2 s → reauth; second
token has `auth_time` present, later, and within 300 s (mirrors
`OIDCCMaxAge1`). T2.3 `max_age=15000` then `max_age=10000` → no reauth,
`auth_time` present in both and equal, `sub` equal (mirrors
`OIDCCMaxAge10000`). T2.4 refreshed ID token `auth_time` == original. T2.5
refresh rotation preserves `authenticated_at`/`amr`. T2.6 golden ID token for
an `ignore` client (no `auth_time`, `acr`, `amr`). T2.7 `max_age=-1` /
`max_age=abc` → `invalid_request` on honour, ignored on `ignore`.

### 4.4 G3/G4 — `acr_values`, `claims.id_token.acr`, and the `acr` claim

**ACR vocabulary.** Two AXIAM-defined values, published in
`acr_values_supported`:

| ACR | Satisfied when `session.amr` contains |
|---|---|
| `urn:axiam:acr:1fa` | anything (floor) — a session with `amr = []` (pre-v50) satisfies only this |
| `urn:axiam:acr:mfa` | `mfa`, or `hwk`/`swk` with `user` (passkey with UV), or `x509` (mTLS user login) |

Federated sessions map through the federation config's claim mapping
(`federation_claims.rs`) when the operator has mapped the upstream `acr`/`amr`;
unmapped upstream evidence yields `1fa`. Strict by default.

**Derivation is a pure function of the session, never of the request.**
`acr_for(amr: &[Amr]) -> Acr` takes only the session's evidence. The request's
`acr_values` are used for exactly two things: to decide whether a *step-up* is
needed, and to choose which satisfied value to *report*. Reporting rule: return
the most-preferred requested value that the session satisfies (a session that
did MFA satisfies `1fa`'s class too; OIDC §3.1.2.1 says the class *satisfied*
is returned); if none requested is satisfied, and the request was voluntary
(`acr_values`), return the **achieved** ACR truthfully after a step-up attempt
was offered (redirect to `/login?reauth=1&acr=…`) and declined/failed. If the
request was **essential** (`claims.id_token.acr.essential = true`) and cannot be
satisfied after step-up → redirect error `unmet_authentication_requirements`
(OpenID Connect Core Error Code `unmet_authentication_requirements` 1.0),
**never** a token. The suite's `ValidateIdTokenACRClaimAgainstRequest` fails
only on essential mismatch; `OIDCCEnsureRequestWithAcrValuesSucceeds` warns on
voluntary mismatch; the plan config sets `server.acr_values` to the two AXIAM
values so the test user (password) yields `1fa` ∈ requested.

The classic ACR-deception bug — echoing `acr_values[0]` into `acr` — is
designed out at the type level: the function that produces the claim cannot see
the request (test T3.1 is a compile-time-shaped unit test: `acr_for` is called
with evidence only, and an integration test sends `acr_values=urn:axiam:acr:mfa`
with a password-only session and asserts the token says `1fa`).

**Invariants.** I1–I4 via the bundle. I5: `claims` parsing touches the shared
parser (§4.1) only; `acr_for` is new code; the step-up redirect reuses G1's
`reauth` path with an `acr` requirement the SPA turns into "MFA required" (the
SPA never chooses the ACR; it only knows which factor to demand, from an
allow-list of two).

**Tests.** T3.1 as above (never echoed). T3.2 essential `mfa` + user without
MFA enrolled → `unmet_authentication_requirements`, no code. T3.3 voluntary
`mfa` + password session → step-up offered; declined → token with `1fa`. T3.4
voluntary `[1fa, mfa]` + MFA session → `acr = 1fa`: the rule is **most-preferred
satisfied in RP order**, not highest achieved — pinned so it stays explicit.
T3.5 `acr_values` on an `ignore` client → ignored, no `acr` claim (I4).

### 4.5 G5 — `login_hint`

**Mechanism (honour lane).** Forwarded to the SPA login page as
`/login?…&login_hint=<value>` only when a login page is being shown anyway.
The SPA pre-fills the username input (React value binding — escaped by
construction). **The server performs no lookup on the hint**, on any path:
it is never compared to a user, never used to select a session, and ignored
entirely when a session already exists. That makes every response *uniform by
construction* with respect to whether the hinted account exists (there is no
branch that could differ), which is the enumeration mitigation the task asks
for. Length-bounded (256 bytes) and dropped if it fails to parse as UTF-8.

**Threats.** Reflected XSS in the SPA: no `dangerouslySetInnerHTML`; value
binding only; test T5.2 mounts the login page with
`login_hint=<script>alert(1)</script>` and asserts the string appears in the
DOM only as the input's `value`. Enumeration: T5.1 asserts the server's
response for an existing and a non-existing hint is byte-identical apart from
the echoed parameter.

I1–I4 via the bundle. I5: SPA login page only.

### 4.6 G6/G7 — `display`, `ui_locales`, `claims_locales`

**Mechanism (honour lane).** `display ∈ {page, popup, touch, wap}` else
dropped; forwarded to the SPA as `display=` and mapped to a CSS class from a
**fixed allow-list** (`popup` → compact layout; others → default). Never
rendered as text. `ui_locales`: split, each matched against the SPA's bundled
locale list; first match wins; no match → tenant default; the raw value is
never rendered (test T6.2 with `ui_locales=<img onerror>` asserts the string
is absent from the DOM). `claims_locales`: accepted and ignored (AXIAM has no
localised claims); it must merely not error (`OIDCCClaimsLocales`).

I1–I4 via the bundle. I5: SPA only; server forwards allow-listed tokens.

#### W5 amendment — the widened scope, and what shipped (2026-09-07)

§8's W5 row is one line: the four cosmetic parameters in the SPA. **W5
deliberately went further, at the maintainer's request**, and this section is
amended in the same commit so that plan and code agree afterwards rather than
leaving a reader to work out which one is current.

The widening is the second sentence of the mechanism above. It said `ui_locales`
is *"matched against the SPA's bundled locale list"* — and no such list existed:
before W5 the SPA had no i18n framework, no locale bundles and no locale list,
so the paragraph described matching against the empty set, which would have
selected nothing for every relying party for ever. W5 therefore builds the
layer as well as the parameter.

**What shipped, beyond the row:**

| Item | Where |
|---|---|
| Five complete locales — `en` (default), `it`, `fr`, `de`, `es` | `frontend/src/i18n/messages.ts` |
| A typed catalogue: `MessageKey` derived from the English bundle, every other bundle `Record<MessageKey, string>`, so a missing string is a **compile error** | same |
| A `useMessages()` hook that also sets `<html lang>` and restores it on unmount | `frontend/src/i18n/index.ts` |
| A typed `Locale` enum and an RFC 4647 §3.4 lookup on the **server**, so the raw `ui_locales` never crosses into the SPA | `crates/axiam-oauth2/src/locale.rs` |
| A CI gate asserting the Rust allow-list and the SPA catalogue agree in both directions | `scripts/check-locale-bundle-sync.py`, Architecture Invariants |

**What the layer deliberately does not cover.** The **admin console is out of
scope**. `ui_locales` is an authentication-request parameter, so the only pages
it can reach are the sign-in page, W3/W4's reauthentication and step-up
prompts, their error and validation messages, and (in W7) the consent screen.
Those are translated completely; the console is not translated at all. The
layer is built so the console can adopt it later — nothing in `useMessages()`
knows what kind of page is using it — but a half-translated console would be
the "stub bundle" failure this section warns about, one screen up.

**No sixth language as a stub.** A locale added to the enum without a complete
bundle would make `ui_locales=pt` *succeed* and then deliver English, which is
worse than answering "no match" and delivering English: the relying party is
told its request was honoured. The sync gate refuses that in both directions.

**The matching rule, made explicit.** RFC 4647 §3.4 lookup, applied to each
requested tag **in the relying party's order**: the first *requested* tag that
matches anything wins, not the best match found anywhere in the list. So
`ui_locales=zz it fr` selects Italian. That mirrors the "most-preferred
satisfied, in RP order" rule §4.4 pinned for `acr_values`, so the authorization
request has one preference rule rather than one per parameter.

**`claims_locales` must not reach the UI-locale selection.** Now that
`ui_locales` does something real, the adjacency is a hazard: the two names
differ by a prefix, carry the same BCP 47 syntax, and one of them is a no-op.
There is exactly one call site of `select_ui_locale`, inside
`login_hop::Cosmetic::from_params`, and `claims_locales` is neither a field of
`Cosmetic` nor a parameter of that function. Pinned by
`claims_locales_never_reaches_the_ui_locale_selection` and by an HTTP test that
`claims_locales=it` alone leaves the page in the default locale.

**Tenant default — deferred to W7, and this is the decision, not an omission.**
The paragraph above says "no match → tenant default". W5 implements the
*chain*: `select_ui_locale(requested, tenant_default)` takes the tenant's
locale as an argument and is unit-tested through all three steps
(`ui_locales` → tenant default → deployment default `en`). What W5 does **not**
add is a place for an operator to set it, and the callers therefore pass
`None`, which lands every deployment on `en` exactly as before.

Two reasons, and the first is the one that would still hold in a different
environment:

1. **A per-tenant switch belongs in `TenantSettingsOverride`**, which is where
   every other one already lives — `mfa_enforced`, `opaque_mode`,
   `webauthn_user_verification`, `deletion_grace_period_days`. A
   `default_locale` column on the `tenant` table would be the first per-tenant
   switch not to live there, and it would be reachable only by a DB edit until
   somebody built the API for it. The plan's own §4.8 (G8) puts the sensitive-
   scopes switch in the settings surface for the same reason; W7 touches that
   surface anyway.
2. **The settings surface is `utoipa`-generated**, so adding a field there
   regenerates `sdks/openapi.json` — and `axiam-server --dump-openapi` cannot
   be built in the environment this wave was developed in (`protoc` is absent,
   so `axiam-api-grpc`'s build script fails). A hand-edited spec whose digest
   CI re-derives from a fresh dump is exactly the kind of guess that ships red.

So schema **v57 was not added**, and §8's W5 row does not carry a migration.
When W7 adds `default_locale: Option<String>` to `TenantSettingsOverride`, the
change here is one argument at two call sites in
`crates/axiam-api-rest/src/handlers/oauth2.rs`, parsed with
`Locale::from_tag` — which is already written and already tested as "the parser
for a stored tenant default", exact rather than a lookup, so a stored `fr-CA`
reads as "somebody wrote something this binary does not ship" rather than as a
guess at French.

**Accessibility.** `<html lang>` is set to the selected locale and restored on
unmount. All five languages are left-to-right, so **no `dir` handling was
added**: untested RTL support would only make a future reviewer believe the
question had been settled.

### 4.7 G9 — `client_secret_basic` (**gated on escalation A, §10**)

**Mechanism.**

- `ClientAuthMethod::ClientSecretBasic` (`"client_secret_basic"` on the wire);
  `is_strong() == false`, `is_mtls() == false`. The existing test
  `an_unrecognised_auth_method_is_refused` moves `client_secret_basic` from the
  refused list to the accepted list — a deliberate, reviewed reversal.
- `TokenRequestContext` gains `basic_credentials: Option<BasicCredentials>`
  parsed **by the REST layer** from `Authorization: Basic`: base64-decode; split
  on the **first** `:`; then `application/x-www-form-urlencoded`-decode each
  half (RFC 6749 §2.3.1 — the classic bug is skipping this step; test T9.1 uses
  a secret containing `%`, `+` and `:`). Malformed header → `invalid_client`
  with `WWW-Authenticate: Basic realm="axiam"` (RFC 6749 §5.2 requires the
  header when the client used the `Authorization` header; the existing test
  `invalid_client_returns_www_authenticate_header` is extended for the scheme).
- `authenticate_client_credential` dispatches, as it already does, **on the
  registered method**: `ClientSecretBasic` → the secret from the header, and the
  header's `client_id` must equal the registered one; a `client_secret` in the
  **body** of a `client_secret_basic` client → `invalid_request` ("more than one
  authentication method", RFC 6749 §2.3). For a `client_secret_post` client an
  `Authorization: Basic` header is **ignored** as it is today (I4) and logged
  at `warn`. This is SEC-093's rule applied to a fourth method: the
  registration decides which credential is read, and the other channel can
  never authenticate.
- Same `verify_client_secret` path (peppered hash, SEC-086 uniform
  `invalid_client`), same rate-limit buckets.
- **Redaction.** The `Authorization` header must never reach a log: (1) the
  request-logging layer's header allow-list is asserted not to include it
  (test T9.4 greps the tracing output of a failed Basic attempt for the secret
  and the base64 blob); (2) `tracing` spans on the token endpoint carry
  `client_id` only; (3) the operator guide states that reverse proxies
  commonly log `Authorization` and that `client_secret_post` remains the
  recommended and SDK-default method — which is why the SDK rule stays.
- Discovery: `token_endpoint_auth_methods_supported` gains
  `client_secret_basic` (tenant-scoped document; a capability statement).
- FAPI gate: **no new code.** `validate_registration` refuses it on `fapi2`
  through `WeakClientAuth` (`is_strong()` is asked, not the variants
  enumerated — the module docs anticipated "a future third strong method";
  this is a future *weak* one and the same question answers it), and
  `enforce_token_request` re-checks `is_strong()` at request time. Tests T9.5
  and T9.6 add the variant to both existing matrices.

I1: per client by registration. I2: both layers, existing arms. I3: default
stays `client_secret_post`. I4: no existing client is affected; a Basic header
on a post client is ignored as before. I5 touchpoints: `ClientAuthMethod`
(new variant), `TokenRequestContext` (new field), the token/revoke/introspect/
PAR handlers (parse the header), `authenticate_client_credential` (one new
branch), discovery.

**Contract.** `CONTRACT.md:1590` rule 3 says SDKs MUST NOT send Basic *because
the server documents no such alternative*. The rule can stay verbatim with its
rationale amended ("the server accepts it for third-party RPs; SDKs keep the
form-body method because it is not logged by intermediaries"). That is a
contract minor bump (1.41) with **no SDK code change** and no downstream
re-sync beyond the text. The escalation in §10 is about whether the maintainer
accepts the header-leakage surface at all, not about SDK work.

### 4.8 G8 — `address` and `phone` scopes (GDPR item)

**Mechanism.**

- Data: schema v51 adds optional user fields `phone_number`,
  `phone_number_verified_at`, and `address` (the OIDC §5.1.1 structured claim,
  stored as a typed record). Written by the admin API and by SCIM (`axiam-scim`
  already speaks SCIM Core's `phoneNumbers`/`addresses`; today it drops them).
  Purpose limitation is documented in `docs/compliance/gdpr-compliance.md`:
  "identity claims released to relying parties the user has consented to".
  Covered by the existing erasure and export paths because they are user-row
  fields.
- Tenant switch `oidc.sensitive_scopes_enabled` (default **off**): when off,
  `address`/`phone` are not in `scopes_supported`, cannot be registered on a
  client (registration refuses), and are refused at authorize as unregistered
  scopes exactly as today.
- Per-client: the client must have the scope in its registered `scopes`
  (`authorize.rs` step 5 already refuses unregistered scopes) — I1 for free.
- **Consent.** These two scopes are *consent-gated*: the first authorization
  for `(user, client, scope-set)` renders the SPA consent screen (G1
  `consent`) and records `Consent { consent_type: "oidc_scope_release:<client_id>",
  version: "<sorted scopes>" }` via the existing `ConsentRepository`. Without a
  record: interactive flow → consent screen; `prompt=none` → `consent_required`.
  Consent is per client and per scope-set; a client that later adds a scope
  re-prompts. Withdrawal: an entry on the user's GDPR self-service page (the
  existing consent list) — deleting the record; the next authorization
  re-prompts.
- **Release.** Claims are returned from **userinfo only** (data minimisation;
  OIDC §5.4 puts scope claims in userinfo for the code flow), never in the ID
  token, and only when the access token's `scope` carries the scope *and* a
  consent record exists at the time of the userinfo call (revocation takes
  effect immediately). Absent data → claim omitted (the suite *warns*, it does
  not fail: `AbstractOIDCCReturnedClaimsServerTest` uses WARNING for
  `VerifyScopesReturnedInUserInfoClaims`). Audit event per release
  (`userinfo.sensitive_claims_released`, `client_id`, claim names — not
  values).

I1: registered scopes. I2: `validate_registration` refuses `address`/`phone`
in a `fapi2` client's `scopes` (new arm `SensitiveScopesOnFapiClient`); at
request time `enforce_authorization_request` refuses a `fapi2` request whose
scope set contains them — even if the row was edited (a FAPI deployment's
data-minimisation posture should not depend on a row). I3: tenant switch off,
consent required. I4: no existing client has these scopes (they were never
registrable). I5: `User` model/schema (additive), userinfo handler (new
optional fields), SCIM mapping (additive), discovery (`scopes_supported`,
`claims_supported` gated by the tenant switch).

Not a protocol threat; the risks are lawful-basis and over-collection. The
design answers them with: an explicit tenant switch, per-client registration,
per-user per-client consent with a record, userinfo-only release, immediate
withdrawal, and audit — the GDPR Art. 5(1)(c)/Art. 7 shape the existing
`create_with_consent` path already implements for terms of service.

**Tests.** T8.1 tenant switch off → scope unregistrable and refused at
authorize. T8.2 first authorization → consent screen; `prompt=none` →
`consent_required`. T8.3 after consent → userinfo returns `phone_number` /
`address`; ID token does not. T8.4 consent withdrawn → userinfo omits the
claims on the next call with the same access token. T8.5 `fapi2` client with
`address` in `scopes` refused at registration; DB-edited row refused at
request time. T8.6 audit event emitted, without claim values.

### 4.9 G10/G11 — `POST /oauth2/userinfo` and `POST /oauth2/authorize` (found, not listed)

- **G10 (required — the suite FAILS without it).** Register `POST` on
  `/oauth2/userinfo` with the same handler; accept the access token from the
  `Authorization` header (RFC 6750 §2.1) **or**, for POST only, from an
  `access_token` form field (§2.2) — and refuse a request that carries both
  (§2 "MUST NOT use more than one method"). The extractor change is
  additive and scoped to that route; GET behaviour is untouched.
  Not per-client (it is the resource-server side of the token, the same for
  every lane) and it tightens nothing on the FAPI lane: a FAPI client's
  sender-constrained token is verified identically on POST. Tests T10.1–T10.3.
- **G11 (optional — warning-only).** Register `POST` (form-encoded) on
  `/oauth2/authorize` with the same parameter set. With `SameSite=Lax` a
  cross-site POST carries no cookie, so the user sees the login page — which
  is exactly what the module then does. Cheap; recommended; not required.

### 4.10 G12 — request objects: **reject, cleanly**

- `request` present → redirect error `request_not_supported` when a registered
  exact `redirect_uri` and `client_id` accompany it inline (the suite sends
  them), otherwise a 400 with that error code. Passes
  `OIDCCUnsignedRequestObjectSupportedCorrectlyOrRejectedAsUnsupported` and
  `OIDCCEnsureRequestObjectWithRedirectUri` (both also skip if discovery lacks
  `none` in `request_object_signing_alg_values_supported`, which AXIAM omits).
- `request_uri` that does not start with `urn:ietf:params:oauth:request_uri:`
  → `request_uri_not_supported` by the same rule. Today such a value falls
  into `par_service.consume` and fails with a less specific error; classifying
  it first is a tightening and gives the suite the code it looks for
  (`OIDCCRequestUriUnsignedSupportedCorrectlyOrRejectedAsUnsupported` passes on
  that error and the discovery check is WARNING-level).
- Discovery: `request_parameter_supported: false` (global, truthful);
  `request_uri_parameter_supported` **omitted** (default `true`, truthful for
  PAR URNs, unchanged from today); `request_object_signing_alg_values_supported`
  omitted.
- These are **global**, not per client, because they refuse rather than
  permit: a refusal cannot loosen any lane, and there is no client for whom a
  request object works today. I5 satisfied by construction.

Why reject rather than implement, said once so it is not re-litigated: JAR
(RFC 9101) by value duplicates PAR's purpose with a weaker integrity story
(unsigned objects are exactly the variant the Basic plan probes); `request_uri`
by reference is an **SSRF primitive** — the OP fetches an attacker-chosen URL —
which AXIAM's whole `jwks_uri`/SEC-054 machinery exists to contain and which
PAR made unnecessary (RFC 9126 §1 says as much). FAPI 2.0 requires PAR and
does not require JAR. A future "let's support signed request objects" proposal
must start from this paragraph.

---

## 5. Per-item table

| Gap | Mechanism | Where the `fapi2` gate refuses it | Shared code touched | Threats | Mitigation | Test that proves it |
|---|---|---|---|---|---|---|
| **G0** login hop / OP cookie | `browser_sso` per client; `axiam_op_session` Lax, path-scoped; SPA `return_to` | not a relaxation — permitted; return leg re-runs PAR/PKCE/FAPI gates | `session` (+3 cols), `cookie_response_from_output`, logout, `authorize` handler, SPA login | login CSRF, open redirect, cookie theft, iframe probing | registered exact `redirect_uri` + RP `state`/PKCE; path-only `return_to` validated twice; HttpOnly + single path; Lax ⇒ iframes fail closed | T0.1–T0.6 |
| **G1** `prompt` | bundle `authn_request_params=honour` | `validate_registration` (`AuthnParamsOnFapiClient`); `enforce_authorization_request` rule 1 (param present) + rule 2 (edited row) | parser (§4.1), `AuthorizeService::authorize`, handler redirect-error branch, SPA `reauth`/`consent` | silent-auth oracle, iframe probing, tracking, reauth loop | audit per outcome; Lax cookie; no identifier on error path; user-action-bound loop + SPA guard | T1.1–T1.7, M1 |
| **G2** `max_age` / `auth_time` | same bundle; session `authenticated_at`/`amr`; code snapshot; claim on honour lane | same as G1 | `session` model/schema, `CreateSession`, `create_session_and_tokens` (+5 callers), refresh rotation, `AuthorizationCode`, `issue_id_token` ×2, `IdTokenClaims` | `max_age=0` treated as absent; freshness overstated on refresh/federation | `Some(0)` by type; `elapsed >= max_age`; rotation copies; federated uses upstream `auth_time` | T2.1–T2.7, M2 |
| **G3/G4** `acr_values` / `claims.acr` / `acr` | same bundle; `acr_for(session.amr)`; step-up via `reauth&acr=` | same as G1 (`acr_values` and `claims` are security-bearing ⇒ refused on `fapi2` when present) | parser; step-up path; discovery `acr_values_supported` | ACR deception (echo), silent downgrade of essential | claim derived from evidence only (type-level); essential unmet ⇒ `unmet_authentication_requirements`; voluntary ⇒ truthful achieved value | T3.1–T3.5, M3 |
| **G5** `login_hint` | same bundle; SPA prefill only | registration + edited-row rules (mechanism refused); parameter itself ignored on honest `fapi2` rows | SPA | enumeration, reflected XSS | no server lookup ⇒ uniform by construction; React value binding | T5.1–T5.2, M5 |
| **G6/G7** `display` / `ui_locales` / `claims_locales` | same bundle; allow-listed tokens to SPA | as G5 | SPA | reflected XSS | allow-lists; raw value never rendered | T6.1–T6.2, M6 |
| **G8** `address` / `phone` | tenant switch + registered scopes + consent record; userinfo-only release | `validate_registration` (`SensitiveScopesOnFapiClient`); `enforce_authorization_request` refuses the scopes on `fapi2` | `User` model/schema, userinfo, SCIM, discovery (tenant-gated), consent SPA | over-collection, no lawful basis, release after withdrawal | switch off by default; per-client; per-user consent record; immediate withdrawal; audit | T8.1–T8.6, M8 |
| **G9** `client_secret_basic` | new `ClientAuthMethod` variant; header parsed by REST layer; registration decides | **existing** `WeakClientAuth` + `enforce_token_request` `is_strong()` re-check | `ClientAuthMethod`, `TokenRequestContext`, four handlers, `authenticate_client_credential`, discovery | RFC 6749 §2.3.1 encoding bug; header leakage in logs/proxies; two-method confusion | form-urlencode before base64 (test with `%`, `+`, `:`); redaction test; body secret on a basic client ⇒ `invalid_request`; SDKs keep post | T9.1–T9.6, M9 |
| **G10** POST userinfo | route + RFC 6750 §2.2 body token (POST only) | n/a (resource-server side; same for all lanes) | userinfo route/extractor | token in body logged | POST body only; both-methods ⇒ refuse | T10.1–T10.3 |
| **G12** request objects | explicit `request_not_supported` / `request_uri_not_supported`; discovery says so | n/a — a refusal | `authorize` handler (classification before PAR consume), discovery | SSRF (if ever implemented), parameter confusion | **not implemented**, and §9 says why | T12.1–T12.3 |

---

## 6. Discovery changes (tenant-scoped document; capability, not behaviour)

| Field | Change | Gate |
|---|---|---|
| `request_parameter_supported` | add, `false` | global (truthful today) |
| `claims_parameter_supported` | add, `false` | global (only `id_token.acr` is read; the RP is told not to rely on `claims`) |
| `acr_values_supported` | add, `["urn:axiam:acr:1fa", "urn:axiam:acr:mfa"]` | global capability statement |
| `claims_supported` | add `auth_time`, `acr`, `amr`; add `phone_number`, `phone_number_verified`, `address` | first three global; last three only when `oidc.sensitive_scopes_enabled` |
| `scopes_supported` | add `address`, `phone` | tenant switch |
| `token_endpoint_auth_methods_supported` | add `client_secret_basic` | after escalation A |
| `id_token_signing_alg_values_supported` | **unchanged** `["EdDSA"]` | — |

All additive. `sdks/CONTRACT.md:1744` lists the fields every SDK's
`OidcConfiguration` requires; new members are ignored by the SDKs' lenient
decoders (the same way `dpop_signing_alg_values_supported` and
`mtls_endpoint_aliases` arrived). The contract's §21 discovery row (`:3909`)
gets the new methods/fields in the 1.41 text bump; `openapi.json` is
regenerated. The existing test `discovery_doc_excludes_alg_none` and the
matrix row 16 in `docs/compliance/oidc-conformance.md` continue to pin EdDSA.

---

## 7. Profile-confusion negative-test matrix

For each Basic-lane mechanism, the test that a `fapi2` client is refused it at
**both** layers. Registration tests live in `fapi.rs`'s test module next to
the existing bundle tests; request-time tests live next to
`enforce_authorization_request` / `enforce_token_request` and in
`crates/axiam-api-rest/tests/oauth2_conformance.rs` for the HTTP shape. Each
row also carries the **I4 twin**: the same input against a `standard`/`ignore`
client behaves exactly as today.

| # | Mechanism | Layer 1 — registration (`validate_registration`) | Layer 2 — request time | I4 twin |
|---|---|---|---|---|
| M1 | `authn_request_params = honour` | `fapi2` + `honour` ⇒ `Err(AuthnParamsOnFapiClient)`, on create **and** on update (the merged `UpdateOAuth2Client` path at `oauth2_clients.rs:589`) | row edited to `fapi2`+`honour` ⇒ `enforce_authorization_request` returns `invalid_request` and logs `error!`; `fapi2`+`ignore` + `prompt=none` ⇒ `invalid_request` (rule 1) | `standard`+`ignore` + `prompt=none` ⇒ ignored, code issued as today |
| M2 | `max_age` honouring | as M1 | `fapi2` + `max_age=0` ⇒ `invalid_request`; no reauth redirect ever built for a `fapi2` row | `standard`+`ignore` + `max_age=0` ⇒ ignored (warn logged), code issued |
| M3 | `acr_values` / `claims.acr` | as M1 | `fapi2` + `acr_values=…` ⇒ `invalid_request`; `fapi2` + `claims={"id_token":{"acr":{"essential":true}}}` ⇒ `invalid_request`; ID token for a `fapi2` client **never** carries `acr`/`amr`/`auth_time` (golden test) | `standard`+`ignore` ⇒ ignored, no claims |
| M4 | `id_token_hint` at authorize | as M1 | `fapi2` + `id_token_hint` ⇒ `invalid_request` | ignored |
| M5 | `login_hint` prefill | as M1 | `fapi2` row edited to `honour` + `login_hint` ⇒ `invalid_request`; honest `fapi2` row ⇒ parameter ignored, **no** redirect to `/login?login_hint=` is ever built | ignored |
| M6 | `display` / `ui_locales` / `claims_locales` | as M1 | as M5 | ignored |
| M7 | `browser_sso` | **permitted** — negative test is different in kind: `fapi2` + `browser_sso` + return leg with inline params on a `require_par` client ⇒ `ParRequired`; without `code_challenge` ⇒ FAPI PKCE refusal | `standard` + `browser_sso=false` ⇒ 401 JSON as today |
| M8 | `address` / `phone` scopes | `fapi2` + `scopes ∋ address` ⇒ `Err(SensitiveScopesOnFapiClient)` (create + update) | row edited ⇒ `enforce_authorization_request` refuses `scope=openid address` with `invalid_scope`; userinfo for a `fapi2` token never releases them even if the tenant switch is on | `standard` client without the scope registered ⇒ `invalid_scope` as today |
| M9 | `client_secret_basic` | `fapi2` + `client_secret_basic` ⇒ `Err(WeakClientAuth { method: ClientSecretBasic })` (existing arm, new variant added to the existing parametrised test) | row edited ⇒ `enforce_token_request` refuses with `MTLS_AUTH_FAILED` and logs `error!` (existing branch); additionally a `fapi2` client presenting `Authorization: Basic` is refused *before* profile evaluation because the registered method is strong and the header is not its credential (SEC-093) | `standard`/`client_secret_post` client presenting `Authorization: Basic` ⇒ header ignored, body secret verified as today |
| M10 | sensitive-claims release | — | `fapi2`-issued access token at userinfo ⇒ `phone_number`/`address` absent regardless of scope | — |

Two cross-cutting pins:

- **P1 — the `standard`/`ignore` golden path.** One integration test creates a
  client exactly as `oauth2_flow_test::full_authorization_code_flow` does,
  sends *every* new parameter at once, and asserts the redirect, the token
  response and the decoded ID token are byte-identical (modulo randomness) to
  the same flow without the parameters. This is invariant 4 as a test rather
  than an aspiration, in the words of `fapi.rs`'s module docs.
- **P2 — the `fapi2` golden path.** The same for a `fapi2` client with none of
  the new parameters: identical to today, including the ID token claim set.

---

## 8. Sequencing — nothing lands before the test that contains it, FAPI stays green

Ordering principle: each wave lands the **gate and its negative tests
first**, then the capability, so that at no commit does a `fapi2` client
have access to a mechanism that a test does not already prove refused. The FAPI
2.0 conformance workflow (`.github/workflows/fapi-conformance.yml`, manual) is
run at the three marked points; because the FAPI plans run `openid:
plain_oauth` (F12) and every change here is either per-client-opt-in or a
refusal, the expected result at each point is *identical* to the baseline run,
and a diff in the report is a stop-the-line signal.

| Wave | Content | Gate/tests that must be green first | FAPI run |
|---|---|---|---|
| **W0** | Baseline: execute the FAPI plans on `main` once (the runbook notes no run has yet happened); commit the report to `docs/conformance/`. Decisions A and B (§10) are **taken** (A yes, B no, 2026-09-07); nothing gates W8 any more | — | **#0 baseline** |
| **W1** | Model + gates + parsing, **honouring nothing**: `authn_request_params` (default `ignore`), `browser_sso` (default off), `AuthnRequestParams::parse` wired into query and PAR carriers, `validate_registration` new arms, `enforce_authorization_request` rules 1–3, discovery statics (`request_parameter_supported`, `claims_parameter_supported`), G12 request-object classification, optional `kid` header. Matrix M1–M6, M8 registration halves, P1, P2, T12.* | none (first wave) | **#1** — must equal #0 |
| **W2** | Session evidence: schema v50, `authenticated_at`/`amr`/`browser_token_hash`, `create_session_and_tokens` + callers, rotation copy, `AuthorizationCode` snapshot, `issue_id_token` optional claims (emitted for nobody yet). T2.5, T2.6 golden, P2 re-run | W1 | — |
| **W3** | Gap 0: `axiam_op_session`, principal resolution behind `browser_sso`, SPA `/login?return_to`, `reauth`, loop guard. T0.1–T0.6, M7 | W1, W2 | **#2** — must equal #0 |
| **W4** | Honour lane, security-bearing: `prompt`, `max_age`, `id_token_hint`, `acr`/`claims.acr`, step-up. T1.*, T2.1–T2.4, T2.7, T3.*, M1–M4 request halves | W3 | — |
| **W5** | Honour lane, cosmetic: `login_hint`, `display`, `ui_locales`, `claims_locales` in the SPA — **plus the SPA i18n layer and five shipped locales** the row's `ui_locales` needs in order to select anything at all (§4.6's W5 amendment: widened at the maintainer's request; no v57 migration, tenant default deferred to W7). T5.*, T6.*, M5–M6 request halves | W4 | — |
| **W6** | G10 POST userinfo (+ G11 optional). T10.* | W1 | — |
| **W7** | G8 sensitive scopes: schema v51, tenant switch, consent screen, userinfo release, SCIM mapping, GDPR doc. T8.*, M8, M10 | W3 (consent screen rides the login hop) | — |
| **W8** | G9 `client_secret_basic` — decision A is **yes**, so this wave is in scope. T9.*, M9; contract 1.41 text; `openapi.json` | W1 | — |
| **W9** | Basic OP harness: `conformance/plans/oidcc-basic-static.json` (plan `oidcc-basic-certification-test-plan`, variants `server_metadata=discovery`, `client_registration=static_client`; config `server.acr_values`, `server.login_hint`, `server.ui_locales`; two static clients, one `client_secret_basic`, one `client_secret_post`, both `standard`/`honour`/`browser_sso`, scopes `openid profile email address phone`, `grant_types` incl. `refresh_token`); `register-clients.sh` variant; test user with phone/address; run; `docs/conformance/` report; `docs/compliance/oidc-conformance.md` rows for the new modules | W1–W8 | **#3 final** — FAPI and Basic both green, on a digest-pinned image, per `fapi-certification-submission.md` |

Rollback story per wave: every wave is additive with defaults equal to today,
so reverting a wave is reverting a PR; schema v50/v51 columns are optional and
the pre-migration decode path is specified (§4.3), so a rolled-back binary
reads a migrated database.

Model split (as X5): the gate arms, the session evidence, `acr_for`, the
`client_secret_basic` parser and the cookie/principal resolution are
token-security mechanisms where a plausible-but-wrong answer mints something
it should not — **Opus 5**. SPA changes, harness, docs, discovery statics —
Sonnet 5.

---

## 9. What we are **not** doing, and why

| Item | Decision | Why |
|---|---|---|
| **Request objects** (`request`, `request_uri` by reference, JAR/RFC 9101) | **Reject, never implement** | The plan's modules are support-or-reject and reject passes. `request_uri` is an SSRF primitive; PAR supersedes it (RFC 9126 §1) and FAPI 2.0 requires PAR. Unsigned objects are the weak variant the suite probes. See §4.10; a future proposal starts there |
| **RS256 / any RSA key in the JWKS** | **No** (Task 0) | Not required for static-client Basic OP; would force a weaker `alg` pin across eleven SDKs; hard to withdraw once RPs pin the key; FAPI 2.0 forbids `RS256`, so it would be the first *per-client* signing algorithm and a new confusion surface. If ever reconsidered, PS256 (permitted by FAPI 2.0) is the lesser evil — but the answer is still no unless a certification that *requires* it is chosen |
| **Dynamic OP** (`client_registration=dynamic_client`, RFC 7591 endpoint) | **No** | Turns `OIDCCIdTokenSignature` on ⇒ RS256 required; open registration is a self-service attack surface (SSRF via `jwks_uri`, resource exhaustion) AXIAM has deliberately kept behind the admin API and SCIM |
| **Implicit OP / Hybrid OP** (`id_token`, `code id_token`, … response types) | **No** | Tokens in URLs; `response_type=code` only is a FAPI 2.0 requirement AXIAM already enforces globally (`authorize.rs:129`) and a global relaxation is exactly what invariant 5 forbids. OAuth 2.1 removes implicit |
| **Config OP / Form Post OP / 3rd-party-init OP / Session/Front-channel logout OP** | Not in scope | Not asked; each is a separate profile. Back-channel logout already exists; a later plan may add the RP-initiated/session profiles |
| **`claims` parameter beyond `id_token.acr`** | Ignored, advertised as unsupported | Reading only the member whose silent-ignore is a security downgrade (§4.4); full support is a separate feature with its own data-minimisation questions |
| **`amr` as a first-class per-client policy** | Emitted alongside `acr` on the honour lane only | Evidence, not policy; the ACR mapping is the policy |
| **Emitting `auth_time` for every client** | Not in this plan | Visible change to every ID token; recorded as a one-line follow-up for the maintainer |
| **Cross-site hidden-iframe silent renew** | Not supported (fails closed) | Consequence of the `Lax` cookie chosen to defeat iframe probing; RPs use top-level `prompt=none` or refresh tokens |
| **Refusing `Authorization: Basic` on `client_secret_post` clients** | Ignore + warn, not refuse | Invariant 4; refusing would be spec-correct (RFC 6749 §2.3) but could break a client that sends both today |
| **Refusing security-bearing parameters on `standard`/`ignore` clients** | Ignore + warn | Invariant 4 (§3.3 rule 3, §11 decision D3) |

---

## 10. Decisions escalated to the maintainer — **both answered 2026-09-07**

Neither should happen as a side effect of chasing a badge. Both reverse a
documented commitment, so they were put to the maintainer rather than
assumed. The answers are recorded here with the reasoning that was in front
of the maintainer when they were given.

| Decision | Answer | Consequence for the plan |
|---|---|---|
| **A.** Accept `client_secret_basic` server-side | **Yes** | W8 is in scope; the Basic OP badge is reachable. SDKs keep `client_secret_post`; only the rationale sentence of `CONTRACT.md` rule 3 changes (contract 1.41 text) |
| **B.** Publish an RSA key in the JWKS | **No** | EdDSA-only stays, in the server and in all eleven SDK pins. §9 lists it under "not doing" |

### A. Accept `client_secret_basic` server-side

**What it reverses.** `sdks/CONTRACT.md:1590` rule 3: "The server documents
no HTTP Basic (`client_secret_basic`) alternative, so SDKs MUST NOT send an
`Authorization: Basic` header to `/oauth2/*`." And
`oauth2_client.rs:861-865`, a test that pins the refusal with the comment
"accepting it as anything would claim support that does not exist".

**Why it is on the table.** The Basic plan's default variant is
`client_secret_basic` for 37 of 38 modules (§1.2). There is no Basic OP badge
without it.

**Cost.** A shared secret in a request header: proxies, load balancers and
APM agents log `Authorization` far more often than they log form bodies; the
redaction obligations in §4.7 are real work and a permanent audit item. One
more weak method in the enum (correctly `is_strong() == false`, so the FAPI
gate handles it with no new code).

**What it does *not* cost.** Zero SDK code: the rule can stay — SDKs keep
`client_secret_post`; only its rationale sentence changes (contract 1.41
text). The "reversal across eleven SDKs" the task feared is avoidable; the
reversal is of the *server's* documented stance, not of SDK behaviour.

**Decision (2026-09-07): yes.** The recommendation below was the one on the
table, and it was accepted as written.

**Recommendation.** Accept, **if** Basic OP certification is wanted at all;
keep SDKs on `client_secret_post`; keep the operator guide's recommendation
that first-party integrations use `client_secret_post` or a strong method. If
the answer is no, Basic OP certification is off the table and W1–W7 remain
worth doing for interoperability with third-party RPs (`prompt`, `max_age`,
`auth_time`, `acr` are what real RPs send), just without the badge.

### B. Publish an RSA key in the JWKS

**What it reverses.** EdDSA-only, hard-coded at encode and decode; the SDK
`alg` pin in `CONTRACT.md:1082` and `:2063`; the discovery test
`discovery_doc_excludes_alg_none`'s sibling assumption that the list is
`["EdDSA"]`.

**Why it is recorded.** The task required it be a decision rather than a
consequence. Task 0 found it **is not needed** for static-client Basic OP.

**Cost if ever done.** A per-client signing algorithm (FAPI 2.0 forbids RS256,
so `fapi2` rows must be refused it at both layers — a third gate row); a
strictly weaker SDK invariant ("pin to the registered alg") re-implemented in
eleven repositories, each a chance to get key confusion wrong; an RSA key
that RPs pin and that cannot be withdrawn without a coordinated rotation.

**Decision (2026-09-07): no.** As recommended.

**Recommendation.** **No.** Do not publish an RSA key. If a future
certification target requires an RSA-family algorithm, prefer PS256 over RS256
(FAPI 2.0 permits PS256, so it would not need to be refused on the `fapi2`
lane), and treat the SDK fan-out as a contract major bump, not a minor one.

---

## 11. Decisions this plan made that a strategy document would normally settle

Recorded so they can be reconciled with `openid-certification-strategy.md` if
it exists outside the repository.

| # | Decision | Alternative rejected |
|---|---|---|
| D1 | One bundle field (`authn_request_params`) rather than one boolean per parameter | Per-parameter flags let a client be "mostly conformant", which `fapi.rs`'s module docs already argue against for FAPI |
| D2 | `browser_sso` is permitted on `fapi2` clients | Refusing it would keep the FAPI harness's interactive modules manual forever, for no security property |
| D3 | On `standard`/`ignore` clients, `max_age`/`prompt` etc. keep being ignored (with a warn log) rather than refused | Refusing is stricter but violates invariant 4, which the task made absolute |
| D4 | Security-bearing parameters are **refused** on honest `fapi2` rows; cosmetic ones are ignored | Refusing `login_hint` would break real FAPI RPs; ignoring `max_age` is the downgrade the task forbids |
| D5 | `auth_time`/`acr`/`amr` emitted only on the honour lane | Global emission is additive and truthful but a visible change; left to the maintainer |
| D6 | ACR vocabulary is two AXIAM URNs, not operator-defined strings | Free-form ACRs invite the echo bug back through configuration |
| D7 | `address`/`phone` released from userinfo only, never the ID token | Data minimisation; the suite only warns either way |
| D8 | `request_uri_parameter_supported` left at its default rather than set `false` | AXIAM does accept the parameter, for PAR URNs |
| D9 | The Basic harness registers its clients with `browser_sso` so the interactive modules can complete from the suite's own redirect; the FAPI harness clients are left untouched until #3 is green | Changing the FAPI clients earlier would make run #1/#2 non-comparable to the baseline |

---

## 12. Documentation and contract follow-through (in-scope, not code)

- `docs/compliance/oidc-conformance.md`: rows for `auth_time`, `acr`, `prompt`,
  `max_age`, userinfo POST, request-object rejection, and the Basic plan's
  module→test mapping (the format the file already uses).
- `docs/compliance/gdpr-compliance.md`: purpose, lawful basis and consent
  record for the sensitive scopes.
- Operator guide section "Standard-lane OIDC parameters" next to the FAPI
  profile guide: what `authn_request_params=honour` and `browser_sso` do, the
  Lax-cookie iframe limitation, the PAR 60 s window, the `Authorization`
  header logging caveat.
- `sdks/CONTRACT.md` 1.41: rule 3 rationale, §21 discovery row, and a
  sentence in §oidc_exchange that `auth_time`/`acr`/`amr` may be present and
  are informational to SDKs (no new validation obligation). `openapi.json`
  regenerated. Downstream re-sync is text-only.
- `claude_dev/fapi-conformance-runbook.md`: a "Basic OP" section pointing at
  the new plan file and the cookie note; the runbook's "No run has been
  performed yet" entry closes with run #0.
