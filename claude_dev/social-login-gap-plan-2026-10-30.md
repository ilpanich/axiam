# Native social sign-in, IdP hint and the refresh-reuse response — assessment and plan

> Written 2026-10-30 against `v1.1.3` (`8b264a8`), in answer to an external,
> read-only analysis of AXIAM produced while comparing identity servers for
> another project. The analysis is reproduced in §1 claim by claim, each claim
> checked against the tree with the evidence named, so that what this plan
> builds rests on what the code does rather than on what a reader inferred.
>
> Companion documents this plan extends rather than replaces:
> [`token-exchange-design.md`](token-exchange-design.md) (B3),
> [`external-token-exchange-design.md`](external-token-exchange-design.md) (X4),
> [`t254-refresh-grace-decision.md`](t254-refresh-grace-decision.md) (T-254),
> [`federation-sso-login-design.md`](federation-sso-login-design.md) (the
> browser "Sign in with X" path), and the competitor comparison
> [`competitor-comparison-keycloak.md`](competitor-comparison-keycloak.md).

---

## 0. Verdict in one paragraph

The analysis is **right on five of its seven factual claims, wrong on one, and
mis-framed on one**. It is wrong that there is no Facebook preset
(`ProviderKind::Facebook` has existed since schema v52). It is factually right
about RFC 8693 — ID tokens are refused, no refresh token is issued, and the
issued token carries no `client_id` claim — but it reads those as *gaps in a
social-login feature*, when X4 was designed as a **partner-API** token exchange
and refuses ID tokens *on purpose* (the analysis itself quotes the reason and
adopts it). The right response is therefore **not** to loosen X4 but to add the
feature AXIAM genuinely lacks: a **native sign-in with a provider's ID token**,
the Auth0 "native social" / Keycloak V1 "external-to-internal" shape, as its own
grant with its own trust switch. Two further points stand on their own merits:
an **IdP hint** on the authorization endpoint (Keycloak's `kc_idp_hint`, Auth0's
`connection`, Okta's `idp` — AXIAM has none, so a relying party can never skip
the chooser), and the **response to a refresh-token replay**, which today is
*refuse, mark, audit* and never revokes anything, while RFC 9700 §4.14.2 and
every compared product revoke the family. A fourth, small item falls out of the
verification: exchanged tokens omit the `client_id` claim RFC 9068 §2.2
requires. **Recommendation: plan all four as a 1.2.0 minor** (§4), with the
seven decisions in §5 taken by the maintainer first.

---

## 1. The analysis, verified

The analysis "only read the code; it didn't run anything". So did this
verification — but against the tree at `8b264a8`, with the lines named.

| # | Claim in the analysis | Verdict | Evidence |
|---|---|---|---|
| 1a | RFC 8693 exchange "refuses ID tokens on purpose, even ones labelled as plain JWTs" | **True, and correct behaviour** | `axiam-oauth2/src/token_exchange.rs:554-581` refuses `…:id_token` by name; `axiam-federation/src/token_exchange.rs:230-270` (`reject_wrong_token_kind`) refuses by *shape* — `nonce`, `at_hash`, `c_hash`, `s_hash`, or a `typ` of `id_token`/`id+jwt` in header or claim — exactly so that an ID token relabelled `…:jwt` cannot slip through. The rationale is the one the analysis quotes and adopts: an ID token is addressed to the client that requested the login, not to an API. |
| 1b | "The new token isn't tied to the requesting app's client ID" | **True as a claim set; mitigated otherwise** | `axiam-auth/src/token.rs:1059-1082` — `issue_exchanged_token` takes no client and `AccessTokenSpec::exchanged` stamps no `client_id`. The audit record names the exchanging client, the `aud` is bounded by what that client may address (`client_may_address`, `token_exchange.rs:741`), and `cnf` is the exchanging client's own binding (SEC-096). What is missing is the **claim**, which RFC 9068 §2.2 makes REQUIRED and which every code/refresh/CIBA/device token of AXIAM carries (`docs/api/token-exchange.md:110-116`). Item G-D. |
| 1c | "It issues no refresh token" | **True, by design** | `token_exchange.rs:825-827`: "No refresh token, ever. One would let the holder outlive the subject token indefinitely — the lifetime cap above, defeated." For a *partner-API* exchange that is the right rule and this plan keeps it. For a *sign-in* it is the wrong shape — which is why sign-in gets its own grant (G-A), not a switch on X4. |
| 2a | Browser social login exists; "no provider-hint parameter like `kc_idp_hint`, so the user always sees a provider chooser" | **True** | `axiam-oauth2/src/authn_params.rs` parses `login_hint`, `display`, `ui_locales`, `prompt`, `max_age`, `id_token_hint`, `acr_values`, `claims` — nothing selects a provider. `login_hop.rs:480-525` (`Cosmetic`) forwards three presentation values to the SPA; none names an IdP. `frontend/src/pages/LoginPage.tsx:270-445` loads the public provider list and renders one button per provider. `OAuth2Client` has no default-provider field. Item G-B. |
| 2b | "It handles OIDC, OAuth2, SAML and Apple; I found no Facebook preset" | **False** | `axiam-core/src/models/federation.rs:85-87, 108, 122, 175, 215, 292` — `ProviderKind::Facebook`, slug `facebook`, default protocol `OAuth2` (because Facebook's web code flow returns no ID token), default scopes `email public_profile`, and the one kind that admits both protocols (`facebook_admits_both_protocols_and_nothing_else_does`). Documented in `federation-sso-login-design.md:76`. Nothing to do. |
| 3 | "Direct 'social login with ID token' API: absent. Only browser redirect flows exist." | **True** | `axiam-api-rest/src/handlers/federation_login.rs` exposes `list_providers_public`, `sso_handoff_public`, `oauth2_start_public`, `oauth2_callback_public`, `oidc_form_callback_public`, `saml_acs_form_public` — every one a browser leg. No endpoint accepts a provider-issued ID token from a native app. Item G-A. |
| 4 | "Refresh tokens tied to their client: implemented" | **True** | The refresh grant checks the presenting client against the row's client; `oauth2_refresh_token.rs` and `client_grants.rs:113` (`revoke_all_for_client`). Nothing to do. |
| 5 | "Refresh token rotation: implemented, but reusing an old refresh token only flags and logs it. It doesn't revoke the token family." | **True — and a deliberate decision, revisited below** | T-254 (`t254-refresh-grace-decision.md` §2) weighed "revoke the family on reuse" (option a) against "confine the grace window to `fapi2`" (option b) and chose (b) *plus* marking. `token.rs:975-1070` (`record_refresh_replay`) warns, increments per-outcome counters on the session (`mark_refresh_replay`, `session.rs:948`) and appends `oauth2.refresh_token_replayed`; it revokes nothing. The authorization-**code** replay path does the opposite (`token.rs:1873-1930`: `replayed_session` → `SessionRepository::invalidate`, RFC 6749 §10.5). Item G-C. |
| 6 | "PKCE (S256 only), PAR, client credentials, device code, introspection, revocation, discovery, dynamic client registration: all implemented" | **True** | Phases 10, 21, 23; Basic OP and FAPI 2.0 certification (`fapi-certification-submission.md`). Nothing to do. |
| — | "Single-maintainer project with most commits made by Claude, at v1.1.3, last updated 2026-10-29" | True | `Cargo.toml:62`, `git log`. |

### 1.1 Where the analysis and this plan part ways

The analysis groups 1a–1c under "RFC 8693 token exchange, social token in,
local tokens out (option 2)" and scores AXIAM *partial*. That is the Keycloak
V1 reading of token exchange, in which an external IdP's token — including an
ID token — can be swapped for a local session. Keycloak itself has moved away
from it: V2 (standard token exchange, Keycloak 26) covers internal tokens
only, and the external-to-internal variant remains preview/legacy. AXIAM's X4
is the V2 posture with one extension — a partner's **access** token, under a
per-provider, off-by-default trust block with a deny-by-default scope map.

The analysis' own closing paragraph gets the distinction right: accepting an
ID token is safe **only** when the acceptor checks that the token was addressed
to *its own* registered client IDs at that provider, because then the acceptor
is the party the token was issued to. That is a **sign-in** property, enforced
by the federation provider's registration, not a **token-exchange** property.
So this plan keeps X4 exactly as it is — the ID-token refusal is a security
invariant, pinned by `every_id_token_marker_is_refused` and
`refresh_and_id_subject_token_types_are_refused_by_name` — and adds the
sign-in as a separate grant whose *first* check is that `aud` names one of the
provider's registered native client IDs (§3.1).

### 1.2 Is it worth doing?

Yes, for three reasons, in order of weight.

1. **Mobile apps are the gap.** Every iOS app that offers a third-party login
   must offer Sign in with Apple, and the native Apple and Google SDKs hand the
   app an **ID token**, not a browser redirect. Today the only way such an app
   can sign into AXIAM is to open a system browser for the hosted login page.
   That is a legitimate pattern (RFC 8252) and AXIAM does it well — but it is
   the one pattern, and the one Auth0 and Firebase customers are used to
   *not* being forced into. Keycloak V1 and Auth0 both have the native path;
   Cognito user pools do not (identity pools accept provider tokens for AWS
   credentials, which is a different thing). Shipping G-A puts AXIAM level
   with the first two.
2. **The IdP hint is cheap and asked for constantly.** A B2B relying party
   that knows its user is an `acme.example` employee wants to send them to
   Acme's Entra tenant, not to a chooser. Keycloak (`kc_idp_hint` and a
   per-client default IdP), Auth0 (`connection`) and Okta (`idp`) all do it.
   The login hop already carries `login_hint`; the hint rides the same lane.
3. **The refresh-reuse response is the one security row where AXIAM is
   behind the BCP.** RFC 9700 §4.14.2 (the OAuth 2.0 Security BCP, published
   January 2025): when a rotated refresh token is presented, "the authorization
   server cannot determine which party submitted the invalid refresh token,
   but it will revoke the active refresh token." Auth0 revokes the family on
   reuse detection; Keycloak with *Revoke Refresh Token* on treats reuse beyond
   the allowed count as a compromise; Okta's rotation does the same outside its
   grace period. AXIAM refuses the replayed token and leaves the live chain —
   and the session — intact. T-254 chose that knowingly, for the `fapi2` grace
   window's false-positive mode; but on the `standard` lane, where the
   predecessor is revoked at rotation, the false-positive argument does not
   apply (§3.3), and AXIAM already revokes the *session* on an
   authorization-code replay. The asymmetry is hard to defend.

Not worth doing, and this plan declines: a Facebook preset (exists); a refresh
token from X4 (correctly refused); accepting ID tokens at the RFC 8693 endpoint
(correctly refused; see §1.1).

---

## 2. Scope — four items

| Item | Issue | What | Kind | Size | Core model |
|---|---|---|---|---|---|
| **G-A** | [#816](https://github.com/ilpanich/axiam/issues/816) | Native sign-in with a provider ID token — a new grant at `/oauth2/token`, per-provider trust block, replay guard, admin UI, docs, contract, SDK helper | feature | L | Opus 5.5 |
| **G-B** | [#817](https://github.com/ilpanich/axiam/issues/817) | `axiam_idp_hint` on the authorization endpoint + per-client `default_idp`; SPA auto-redirect; SDK authorize-URL builders learn the hint | feature | M | Opus 5.5 (server) / Sonnet 5.5 (SPA, SDKs) |
| **G-C** | [#818](https://github.com/ilpanich/axiam/issues/818) | Refresh-token replay revokes the session (T-254 amendment), per-tenant policy, default `revoke_session` | security hardening, **behaviour change** | M | Opus 5.5 |
| **G-D** | [#819](https://github.com/ilpanich/axiam/issues/819) | `client_id` claim on exchanged tokens (RFC 9068 §2.2) | conformance | S | Opus 5.5 |

Per `CLAUDE.md`'s PR rules the issues close only when the release PR merges:
each wave PR references the issues it advances, and the 1.2.0 PR body lists
all four as *Closes*.

**Repositories the plan touches.** W1 … W3 and W5 live in `ilpanich/axiam`
alone. **W4 needs the eleven SDK repositories** (`ilpanich/axiam-<lang>-sdk`:
rust, typescript, python, java, kotlin, csharp, php, go, swift, c,
cplusplus) — each re-vendors `sdks/CONTRACT.md` 1.65, `sdks/openapi.json`
and gains the native sign-in helper and the `idp_hint` option on its
authorize-URL builder. An orchestrating session that does not have them
attached stops at the end of W3 and hands W4 to one that does.

Semantic versioning: G-A and G-B add surface, G-C changes default behaviour
(with a setting that restores today's) — a **minor**, 1.2.0 (D-N7).

---

## 3. Design

### 3.1 G-A — Native sign-in with a provider ID token

**The rule.** *An ID token is accepted as a sign-in only when it was issued to
us.* "Us" is a client ID the operator registered on the federation provider
for exactly this purpose; nothing else — not the web `client_id` by default,
not "any audience" — is admissible. Everything below is that rule applied one
dimension at a time, which is also why the result is a **grant** and not a
widening of X4: the output is a sign-in's token set (access + refresh + AXIAM
ID token, client-bound, consent-ruled, rotated), and the input is a token X4
must keep refusing.

**Trust block**, per OIDC-protocol federation provider, beside the X4 block
and shaped like it (`TokenExchangeTrust`, `federation.rs:506`):

```
native_login {
  enabled: bool                 // default FALSE — opt-in per provider
  client_ids: [string]          // non-empty REQUIRED when enabled; the
                                // iOS bundle id / Android client id / Apple
                                // app id the native SDK was configured with
  max_token_age_secs: int       // default 300, 1..=3600, bound on now - iat
  subject_mapping reused from the provider (linked_only | jit_provision)
}
```

Decisions, not defaults: `enabled` is off because configuring Google for
*browser* login is not agreement to accept Google ID tokens *from apps*;
`client_ids` is deny-by-default because Google issues ID tokens with `aud` =
the platform client ID, Apple with `aud` = the bundle ID, and neither equals
the web client ID — an operator who wants the web ID accepted lists it.
SAML providers cannot have the block (no issuer, no JWKS); OAuth2-protocol
providers (GitHub; Facebook's default) cannot either — they issue no ID token
(D-N5 on the access-token alternative).

**The grant.** `POST /oauth2/token` with
`grant_type=urn:axiam:params:oauth:grant-type:provider-id-token` (final URN per
the executor, matched against the vendor URNs already in the tree), parameters
`provider` (the provider's `provider_slug` or UUID), `id_token`, `nonce` (the
raw nonce the app generated), optional `scope` and RFC 8707 `resource`, and the
client's usual authentication — public clients (mobile) with `client_id` only.
The client's registration must list the grant in `grant_types`, exactly as
X4 requires for token exchange (`token_exchange.rs:536`).

**Validation order** — the order is the design; a plausible-but-wrong order is
an account takeover that looks like a successful request:

1. Client authenticated/identified; grant registered on the client; rate
   limiter (new bucket `oauth2_provider_id_token`, login preset, both mounts).
2. `provider` resolves to an enabled OIDC provider **of the request's tenant**
   (or inherited from its organization, as `list_providers_public` resolves)
   with `native_login.enabled`. Anything else: `invalid_grant`, generic.
3. Header: `alg` within the provider's `allowed_algorithms`; `none` refused
   raw (`reject_alg_none_raw`); `kid` resolved through the existing JWKS cache
   with its rollover behaviour — **no new fetch surface**.
4. Claims, through `OidcFederationService::verify_id_token_full`
   (`oidc.rs:630`) with the audience set to `native_login.client_ids`:
   `iss` equals the provider's discovered issuer, exactly; `aud` ∈
   `client_ids` (array or string per OIDC Core §3.1.3.7; `azp` checked when
   present and `aud` has several members); `exp` in the future with the
   D-05 leeway; `iat` within `max_token_age_secs`.
5. **Shape**: this endpoint *requires* ID-token shape. `nonce` claim present
   and equal to the request `nonce`, or to its SHA-256 hex (Apple's documented
   pattern); an access-token-shaped JWT (no `nonce`) is `invalid_grant`. The
   X4 shape test runs in reverse here, and the two modules share the marker
   list so they cannot drift.
6. **Replay**: `ProofReplayRepository::insert_proof_jti(tenant, kind =
   "provider_id_token", scope = provider_id, jti = SHA-256(token))`, kept
   until `exp` + skew (Google tokens carry no `jti`). `ReplayDetected` is
   `invalid_grant`; a guard that cannot record refuses (the CIBA rule,
   `ciba_signed_request.rs:538`).
7. Subject resolution through **the same**
   `OidcFederationService::provision_or_link_user` (`oidc.rs:834`) the browser
   login and X4 use, under the provider's `subject_mapping`, with the same
   `email_verified` and JIT rules. Account state through `account_may_act`.
   Federated sign-ins carry no local MFA obligation today (roadmap T12/T14:
   "not applicable for federated/social login"); unchanged.
8. **Issue** the client's ordinary sign-in token set — access token with
   `client_id`, `aud` per the client's rules, `cnf` if DPoP; refresh token
   under rotation and client binding; AXIAM ID token with the request `nonce`
   when `openid` was asked. Scopes: the client's registered set intersected
   with the request; a scope that would need a consent ceremony is
   `consent_required` (D-N6).
9. Audit `federation.native_login` (provider, client, outcome, newly
   provisioned, **never the token**); on failure the generic `invalid_grant`
   description for everything past step 2 — the X4 rule that a wrong token
   and a wrong configuration are told apart only in the server log.

**Where it lives.** Verification and subject resolution in
`axiam-federation/src/native_login.rs` (returning a `NativeSubject`, sibling
of `ExternalSubject`); the grant in `axiam-oauth2/src/provider_id_token.rs`;
dispatch at the token endpoint; the trust block on the federation config model
and admin API (`PATCH /api/v1/federation/configs/{id}`, replaced wholesale like
`token_exchange`); a card in the admin UI's federation page; OpenAPI regenerated
through the exporter. `axiam-oauth2 → axiam-federation` is an existing edge
(X4), so `check-crate-layering.py` needs no change.

**Apple specifics** the executor must honour: `aud` is the bundle ID for
native; the first sign-in is the only time Apple sends name and email (the
existing `apple.rs` rules apply unchanged); `nonce_supported` is true. Facebook
*Limited Login* mints an OIDC ID token (`iss https://www.facebook.com`) and
works through this grant when the provider is configured as the OIDC variant.

### 3.2 G-B — IdP hint and per-client default provider

**Parameter.** `axiam_idp_hint`, following the vendor-namespace rule stated at
`login_hop.rs:112-118` for `axiam_login_hop` (D-N3 offers an alias). Value: a
provider's `provider_slug` (schema v52, operator-chosen) or its UUID. Bounded
by `MAX_HINT_LEN`, dropped if not UTF-8, exactly as `login_hint`.

**Resolution happens on the server, and an unknown hint is a no-op.** The hint
is resolved against the tenant's *effective, enabled, public* provider list —
the same resolver `list_providers_public` uses, inheritance included — and
what crosses into the login-hop URL is a **type** (`idp=<uuid>`), never the
string. A hint that names nothing, a disabled provider, or a provider of
another tenant is **silently ignored**: the response is byte-identical to the
no-hint case (hint semantics, and what Keycloak does). This *is* a lookup,
unlike `login_hint`'s no-lookup rule — permissible because the provider list
is already public for the tenant, so nothing is enumerable that was not. The
test states that property.

**Per-client default.** `OAuth2Client.default_idp: Option<Uuid>` (additive
schema version), validated at create and on the merged update path to name a
provider the client's tenant can see; applied when the request carries no
hint. *The registration decides, the request may only choose among what the
tenant offers.*

**Lane.** Presentational, like `login_hint`: `Cosmetic` gains `idp:
Option<Uuid>`; no `fapi2` interaction (a hint never changes what is issued).
With a live OP session the authorization endpoint does not hop to login and
the hint is moot — documented, and the same as Keycloak.

**SPA.** `LoginPage` reads `idp`; when it matches a loaded provider it
auto-starts `handleSsoSelect(provider)` once, rendering "Redirecting to
{display_name}…" with a visible "Choose another way to sign in" that cancels
the redirect. **No loop**: a return from a failed SSO leg (error param on
`/login`) never auto-redirects again. Works for OIDC, OAuth2, SAML and Apple
providers alike, because the start operation is protocol-generic.

**SDKs.** The OIDC-SSO helpers' authorize-URL builders (contract §… from
`sdk-oidc-sso-plan.md`) gain an optional `idp_hint`. Additive; one small change
per SDK, folded into W4.

### 3.3 G-C — A refused refresh-token replay revokes the session

**What changes.** On the `standard` lane a presentation of a rotated token is
today refused and marked. It will, in addition, do what the authorization-code
replay path does (`token.rs:1873-1930`): invalidate the session the replayed
token names (`SessionRepository::invalidate` — which publishes to the
revocation feed) and revoke every refresh token of that session through a new
`RefreshTokenRepository::revoke_all_for_session(tenant_id, session_id)`
(`revoke_all_for_user` is too wide: every client, every device). The audit row
gains `response: "revoked_session" | "refused"`; the per-outcome session
counters stay.

**Why the T-254 false-positive argument does not reach this lane.** The
decision rejected family revocation because "a client whose rotation response
was lost retries with the old token, having never received the successor".
On `standard` that client holds a dead token and no successor: it cannot
continue *either way*, so revoking the session costs it nothing it still had
and costs the attacker — who may hold the successor — everything. The only
remaining false positive is a client that issues two refreshes with the same
token concurrently, which is a client defect the BCP explicitly declines to
accommodate. On `fapi2` the window stays exactly as decided (D-N4): inside it
the presentation is accepted, outside it (the row expired by `supersede`,
still found by `find_rotated`) it is refused **and now revokes**, as on
`standard`. A token revoked at logout and re-presented is not a replay
(`find_rotated` requires `rotated_at`) and revokes nothing — the test pins it.

**Policy.** Tenant setting `oauth2.refresh_reuse_response` ∈ `revoke_session`
(default, D-N2) | `refuse` (today's behaviour), resolved through the
hierarchical settings like the rest. The default is a behaviour change for
every `standard` client: CHANGELOG *Changed*, an upgrade note, and T-254
re-amended — "detectable and invalidates the family" (threat model §…, line
605) becomes true again for the first time since 1.0.0-beta13.

### 3.4 G-D — `client_id` on exchanged tokens

RFC 9068 §2.2 makes `client_id` REQUIRED in a JWT access token; AXIAM's code,
refresh, CIBA and device tokens carry it and exchanged tokens (B3 and X4) do
not. Add the exchanging client's `client_id` to `AccessTokenSpec::exchanged`
in both paths. One consequence to confirm by test rather than assume: an
exchanged token presented later as an `actor_token` becomes attributable to
its exchanging client (`actor_token_client`, `token_exchange.rs:89`), which is
exactly the #518 rule — "a party the exchanging client can show the token was
issued to" — and therefore allowed where it was previously refused for want of
evidence. Introspection shows the claim. `docs/api/token-exchange.md:110-116`
updated. Small, but it touches an authorization rule, hence Opus.

---

## 4. Waves

> **Execution**, as the 1.0.1 … 1.1.2 plans: one Opus 5.5 orchestrator runs
> the plan; each wave is a branch cut from the plan branch, merged after its
> F4 security review (Opus 5.5). Model selection per
> [`release-1.1.2-plan.md` §1.1](release-1.1.2-plan.md): **Opus 5.5** where
> the task *defines* behaviour under adversarial input, **Sonnet 5.5** where
> the design above already states the fix and names the precedent at a
> `file:line`.

### 4.0 Model per activity — the suggestion, in one table

The rule (release-1.1.2 plan §1.1) is "the cheapest model that can be
trusted with the row's *definition*, not with its typing". Applied here:

| Activity | Model | Why this one |
|---|---|---|
| **Orchestrator** — runs the plan, cuts branches, writes §4.1 wave results, takes the D-N decisions back to the maintainer | **Opus 5.5** | Holds the whole plan and every cross-wave invariant (X4 untouched, T-254 lanes, layering) |
| W1.1 refresh-reuse response (G-C) | **Opus 5.5** | Defines behaviour under adversarial input and concurrency (two rotations racing, replay vs. lost response); changes a default |
| W1.2 `client_id` on exchanged tokens (G-D) | **Opus 5.5** | Small, but it changes an authorization rule (`actor_token_client`) and the executor must judge the consequence on the evidence |
| W1.3 threat model + F4 review of W1 | **Opus 5.5** | Every F4 review is Opus |
| W2.1 `NativeLoginTrust` model, validation, admin API | **Opus 5.5** | Validation rules are the security boundary (non-empty `client_ids`, refusals on SAML/OAuth2 kinds, replace-wholesale) |
| W2.2 `native_login.rs` verification + replay guard | **Opus 5.5** | The long pole and the one place an ordering mistake is an account takeover |
| W2.3 the grant at the token endpoint | **Opus 5.5** | Issues a sign-in token set from a non-browser input; consent, rotation, DPoP and the `grant_types` gate must compose correctly |
| W2.4 admin UI trust card | Sonnet 5.5 | Precedent exists: the X4 `token_exchange` card on the same page |
| W2.5 OpenAPI regen, `docs/api/native-sign-in.md`, website block | Sonnet 5.5 | Text and a scripted regen; the design in §3.1 is the source |
| W2.5 F4 review of W2 | **Opus 5.5** | Review |
| W3.1 `axiam_idp_hint` parsing, server-side resolution, `Cosmetic.idp`, `default_idp` validation | **Opus 5.5** | Tenant isolation of the resolver and the byte-identical no-hint property are defined here |
| W3.2 SPA auto-redirect/cancel/no-loop; `default_idp` field in the console | Sonnet 5.5 | Precedent: `handleSsoSelect` and the `login_hint` handling in `LoginPage.tsx` |
| W3.3 docs (authorize parameters, website) | Sonnet 5.5 | Text |
| W3.3 F4 review of W3 | **Opus 5.5** | Review |
| W4.1 contract 1.65 text, `sdks/openapi.json` re-vendor | Sonnet 5.5 | The contract's shape is fixed by §3; the task is stating it in the contract's register |
| W4.2 … W4.12 the eleven SDK ports | Sonnet 5.5 ×11, in parallel | Each follows the Rust reference and the contract; the W7 pattern of the 1.1.2 plan |
| W4.13 cross-SDK conformance review | **Opus 5.5** | Review across eleven codebases against one contract |
| W5 CHANGELOG, upgrade notes, competitor rows, roadmap row | Sonnet 5.5 | Text, with the wave results as source |
| W5 combined F4 security review before the tag | **Opus 5.5** | Review |

Haiku 5.5 is not suggested for any row: every task here either touches a
security boundary or must read a long design faithfully, and the SDK ports
need language-specific judgement the contract does not spell out.

### W1 — the security core (branch `claude/social-gap-w1`)

| Task | Item | Model | Size | Acceptance |
|---|---|---|---|---|
| W1.1 | G-C: `revoke_all_for_session`; the `standard` lane and the post-window `fapi2` lane revoke; setting `oauth2.refresh_reuse_response`; audit `response` field | **Opus 5.5** | M | New tests beside the T-254 ones: standard replay → session invalidated, sibling refresh tokens refused, feed entry; `fapi2` in-window unchanged (the OIDF module `fapi2-security-profile-final-refresh-token` still passes); `fapi2` post-window revokes; setting `refuse` restores today's; logout-revoked token re-presented revokes nothing; concurrent rotations still lose cleanly (T-37 untouched) |
| W1.2 | G-D: `client_id` on exchanged tokens, B3 and X4 | **Opus 5.5** | S | Claim present in both paths; introspection shows it; the actor-token attribution test added and the existing exchange tests green; `docs/api/token-exchange.md` |
| W1.3 | Threat model: T-254 re-amended; `threat-model-stride.md` line 605 restored to "invalidates the family"; model version bump; F4 review of W1 | **Opus 5.5** | S | — |

### W2 — native sign-in (branch `claude/social-gap-w2`)

| Task | Item | Model | Size | Acceptance |
|---|---|---|---|---|
| W2.1 | `NativeLoginTrust` block on the federation model (schema vNext, additive), validation (non-empty `client_ids` when enabled; refused on SAML and OAuth2-protocol providers), admin API replace-wholesale | **Opus 5.5** | M | Model tests mirror `TokenExchangeTrust`'s |
| W2.2 | `axiam-federation/src/native_login.rs`: §3.1 steps 3–7, shape markers shared with X4, replay guard | **Opus 5.5** | L | Every refusal has a test named after it: wrong `aud`, web client id not listed, stale `iat`, missing/mismatched `nonce` (raw and SHA-256), access-token shape, replayed token, provider of another tenant, disabled provider, SAML provider, `alg none`, unknown `kid` after rollover |
| W2.3 | `axiam-oauth2/src/provider_id_token.rs` grant + token-endpoint dispatch + limiter bucket + audit | **Opus 5.5** | M | Issues the client's ordinary token set; refresh under rotation and client binding; `consent_required` path; `grant_types` gate; public client allowed; REST integration test end-to-end with a stub IdP (the pattern of `token_exchange_test.rs`) |
| W2.4 | Admin UI: the trust card on the federation provider page | Sonnet 5.5 | S | Frontend tests; `frontend-coverage-matrix.md` row |
| W2.5 | OpenAPI regenerated (`--dump-openapi`, digest), `docs/api/native-sign-in.md`, website block, threat-model entries (§7), F4 review of W2 | **Opus 5.5** (review) / Sonnet 5.5 (text) | M | `check-spec-digest.py` green; `docSectionsAreComplete()` |

### W3 — IdP hint (branch `claude/social-gap-w3`)

| Task | Item | Model | Size | Acceptance |
|---|---|---|---|---|
| W3.1 | `authn_params`: `axiam_idp_hint` parsed and bounded; server-side resolution to a typed provider id; `Cosmetic.idp`; `OAuth2Client.default_idp` (schema, validation on create and merged update) | **Opus 5.5** | M | Unknown/disabled/foreign-tenant hint → byte-identical response (the T5.1 shape); known hint → `Location` carries `idp=<uuid>`; client default applied when no hint; hint overrides default; a client default naming a foreign provider is `400` at registration |
| W3.2 | SPA: auto-redirect with cancel, no-loop; admin UI field for `default_idp` | Sonnet 5.5 | S | Frontend tests for redirect, cancel, no-loop after an SSO error |
| W3.3 | Docs (authorize parameters page, website), F4 review of W3 | Sonnet 5.5 / **Opus 5.5** | S | — |

### W4 — contract 1.65 and the eleven SDKs (cut after W1–W3 merge)

| Task | Model | Size |
|---|---|---|
| W4.1 contract text: new § for the native sign-in helper (`loginWithProviderIdToken(provider, idToken, nonce, scopes?)` in each language's idiom), `idp_hint` on the authorize-URL builder, the refresh-reuse behaviour note; `sdks/openapi.json` re-vendored | Sonnet 5.5 | M |
| W4.2 … W4.12 the eleven SDK sessions, in parallel, per the W7 pattern of the 1.1.2 plan (REST-only SDKs — Kotlin, Swift, C, C++ — implement both helpers; they are REST) | Sonnet 5.5 ×11 | S each |
| W4.13 conformance review | **Opus 5.5** | M |

### W5 — release readiness 1.2.0 (on the plan branch)

| Task | Model | Size |
|---|---|---|
| W5.1 CHANGELOG (`Added` G-A, G-B, G-D; `Changed` G-C with the setting that restores 1.1.x behaviour); upgrade notes | Sonnet 5.5 | S |
| W5.2 `competitor-comparison-keycloak.md` rows (native social, IdP hint, reuse detection) flipped with the date; roadmap table row; `CLAUDE.md` protocol line | Sonnet 5.5 | S |
| W5.3 combined F4 security review of the plan branch before the tag | **Opus 5.5** | M |

The maintainer merges and tags `v1.2.0`.

### 4.1 Wave results (written by the orchestrator as each wave lands)

*Empty until W1 lands. One subsection per wave: base commit, PR, what
changed against §4, test counts before/after, issues filed under §1.4-style
"arises while the plan runs".*

**Expected cost**, in executor sessions: W1 3 (3 Opus), W2 6 (4 Opus), W3 4
(2 Opus), W4 13 (1 Opus), W5 3 (1 Opus) — roughly **29 sessions, 11 Opus**,
plus the orchestrator. W2.2 is the long pole; W4's eleven run in parallel.

---

## 5. Decisions requested from the maintainer

| # | Question | Recommendation |
|---|---|---|
| D-N1 | Where does native sign-in live: a grant at `/oauth2/token` (OAuth2 token set, client-bound, consent-ruled); a session-world `POST /api/v1/auth/federation/native` (the SDK login shape, cookies/handoff); or both? | **The grant.** It answers the analysis' two complaints (client binding, refresh) in the OAuth2 world where mobile apps live, and reuses rotation, DPoP and consent as they stand. The SDK helper wraps it. A session-world variant can follow if the console or an SDK needs it. |
| D-N2 | Default for `oauth2.refresh_reuse_response` | **`revoke_session`.** The BCP's behaviour, what the compared products do, and what AXIAM already does for an authorization-code replay. `refuse` stays available per tenant. |
| D-N3 | Hint parameter name | **`axiam_idp_hint`** alone, by the vendor-namespace rule already written at `login_hop.rs`. A `kc_idp_hint` alias would make a Keycloak client "just work" but puts a competitor's prefix in AXIAM's API; decline unless a migration asks for it. |
| D-N4 | On `fapi2`, revoke inside the grace window when the *successor* has already been rotated (the BCP's definitive breach signal)? | **Not in this plan.** T-254's reasoning stands for that lane; the window is sender-constrained; certification was obtained with it. Record as the residual it already is. |
| D-N5 | Accept a provider **access token** (plus a userinfo call) for OAuth2-protocol providers — GitHub, classic Facebook — as Auth0 does? | **No.** An access token's audience cannot be verified generically (Google's `tokeninfo` is provider-specific), which is the one check §3.1 rests on. Facebook has Limited Login (OIDC) for apps; GitHub has no native SDK sign-in to begin with. |
| D-N6 | Consent for the native grant | **Refuse with `consent_required`** any scope that would need a ceremony; the client's registration decides what needs none, as it does today. An "implicit consent for first-party clients" switch is a separate decision with its own threat entry. |
| D-N7 | Version | **1.2.0.** New grant, new parameter, one default behaviour change with an opt-out. |

---

## 6. The gate before every commit

Unchanged from the 1.1.2 plan §10, restated so an executor can re-derive it:
`cargo fmt --check`, `cargo clippy -p <crate> --lib -- -D warnings` (the
`missing_docs` ratchet on `axiam-authz` and `axiam-directory`), the crate's
tests (`--no-default-features` where libxml2 is absent), `scripts/check-crate-layering.py`,
`scripts/check-spec-digest.py` after any handler change (the server binary
needs `protobuf-compiler` and the swagger-ui placeholder — `CLAUDE.md`
"Build & Disk Hygiene"), the frontend suite for W2.4/W3.2, and a signed
commit per task. No test is skipped or quarantined to go green. Behaviour
changes (G-C) are not merged without the CHANGELOG line and the upgrade note
in the same wave.

---

## 7. Threat-model and documentation deltas

New entries (ids after T-488; model version 2.45.0), each Mitigated by a
named test on landing:

| Id | Threat | Element | Mitigation |
|---|---|---|---|
| T-489 | A provider ID token minted for **another app** (another operator's client ID at the same provider) is presented to the native grant | `/oauth2/token` | `aud` ∈ `native_login.client_ids`, deny-by-default, no web-client fallback (§3.1 step 4) |
| T-490 | A captured provider ID token is **replayed** within its lifetime | `/oauth2/token` | SHA-256(token) in the proof-replay table until `exp` + skew; a guard that cannot record refuses (step 6) |
| T-491 | A stale or **nonce-less** ID token, or an access-token-shaped JWT, is presented as a sign-in | `/oauth2/token` | `iat` ≤ `max_token_age_secs`; `nonce` required and bound to the request; shape markers shared with X4 (step 5) |
| T-492 | A provider configured for **browser** login is used for native sign-in without the operator's agreement | federation config | `native_login.enabled` off by default; separate switch from `token_exchange` (the X4 argument) |
| T-493 | An `axiam_idp_hint` steers a user to a provider of **another tenant**, or carries a URL | `/oauth2/authorize` | Resolved server-side against the request tenant's effective list to a typed id; anything else ignored; the SPA receives a UUID, never a string (§3.2) |
| T-494 | A client's `default_idp` names a provider the tenant cannot see | OAuth2 client registration | Validated on create and on the merged update path (the T-241 lesson: a gate that only runs on create is a gate with a PATCH around it) |
| T-254 | re-amended | `/oauth2/token` | §3.3 — the `standard` and post-window `fapi2` lanes revoke the session; the in-window `fapi2` residual stays recorded |

Documentation: `docs/api/native-sign-in.md` (new), `docs/api/token-exchange.md`
(the `client_id` claim; a cross-link saying *this is not how you sign a user
in — see native-sign-in*), the authorize-parameters page (`axiam_idp_hint`,
`default_idp`), `docs/deployment` upgrade notes (G-C), `sdks/CONTRACT.md` 1.65,
the website's OAuth2 and federation blocks, `competitor-comparison-keycloak.md`.
`CLAUDE.md`'s protocol list gains one line for the native grant.

---

## 8. Rejected, and why — so nobody reopens them by accident

- **Accepting `…:id_token` at the RFC 8693 endpoint.** The analysis' closing
  paragraph is the argument against: an ID token is safe to accept only as a
  sign-in by the party it was issued to. That is G-A, with its own trust
  switch. X4's refusal by name and by shape stays, and its tests stay red if
  anyone changes it.
- **A refresh token from token exchange.** It would defeat the lifetime cap
  X4 exists to enforce; a service that needs long-lived access re-runs the
  exchange.
- **A Facebook preset.** Exists (`ProviderKind::Facebook`).
- **Family revocation inside the `fapi2` grace window.** D-N4.
- **Native sign-in with provider access tokens.** D-N5.
- **A `kc_idp_hint` alias.** D-N3.
