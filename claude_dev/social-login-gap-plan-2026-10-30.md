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

> **Correction 2026-10-31 (W2.2, D-N10/D-N11):** step 6 does not use
> `ProofReplayRepository`; the replay record lives in the additive table
> `federation_id_token_replay` (v112) behind its own
> `ProviderIdTokenReplayRepository`, keyed on the provider's owning tenant.
> Step 7 has no `subject_mapping`: resolution is the browser path
> (`map_identity` → `provision_or_link_identity`), then `account_may_act`.

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

> **Correction, 2026-10-30 (W1.2).** The consequence stated above is wrong,
> and the executor showed it by test before committing. With the claim,
> client A holding user U's token issued to client B can exchange it as a
> `subject_token` (result: `sub = U`, `client_id = A`) and then present the
> result as its own `actor_token`, obtaining `act.sub = U` — "U acts for A",
> the false attribution #518 / D-5 exists to refuse. Holding a token the
> client itself exchanged is not evidence that U consented to the client.
> **Maintainer decision D-N9 (option A):** exchanged tokens carry
> `client_id` *and* an exchange marker (`axiam_exchanged`), and
> `actor_token_client` refuses any token carrying the marker, `act` or
> `ext_exchange` — actor behaviour is exactly as before. Pinned by
> `an_exchanged_token_is_refused_as_an_actor_even_by_its_own_client` and
> `an_x4_token_names_its_client_and_is_never_that_clients_actor`.

---

## 4. Waves

> **Execution**, as the 1.0.1 … 1.1.2 plans: one Opus 5.5 orchestrator runs
> the plan; each wave is a branch cut from the plan branch, merged after its
> F4 security review (Opus 5.5). Model selection per
> [`release-1.1.2-plan.md` §1.1](release-1.1.2-plan.md): **Opus 5.5** where
> the task *defines* behaviour under adversarial input, **Sonnet 5.5** where
> the design above already states the fix and names the precedent at a
> `file:line`.
>
> **Amended 2026-10-30 by the maintainer:** no PR per wave. When a wave's
> F4 and sweeps are clean, the orchestrator fast-forwards the plan branch
> `claude/social-gap-1.2.0` to the wave branch (linear history, no merge
> commit) and cuts the next wave from it. A **single PR**, plan branch →
> `main`, is opened after W5; the maintainer merges it and tags.

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

*One subsection per wave: base commit, PR, what changed against §4, test
counts before/after, issues filed under §1.4-style "arises while the plan
runs".*

#### W1 — the security core (`claude/social-gap-w1`, closed 2026-10-30)

**Base** `85721de` (the plan branch after the D-N1…D-N7 record). **PR:** none
per the 2026-10-30 amendment above; the plan branch was fast-forwarded to the
wave head. **Commits**, each signed:

| Commit | Task | What |
|---|---|---|
| `f978dff` | W1.1 G-C (#818) | `revoke_all_for_session`; refused replay on `standard`, post-window `fapi2` and superseded-off-`fapi2` invalidates the session and revokes its refresh tokens; setting `oauth2.refresh_reuse_response` (`revoke_session` default \| `refuse`), tighten-only; audit `response`; schema **v110** (column + `idx_refresh_token_session`); CHANGELOG *Changed* + deployment upgrade note; OpenAPI regenerated |
| `9f1c855` | W1.2 G-D (#819) | `client_id` on B3 and X4 tokens **plus** the `axiam_exchanged` marker; `actor_token_client` refuses marked / `act` / `ext_exchange` tokens (D-N9); introspection (REST and gRPC) echoes the `client_id` claim |
| `9e761ad` | orchestrator | D-N8, D-N9, §3.4 correction |
| `3c7d031` | W1.3 | T-37, T-254, T-471 amended; model **2.45.0**; T-254 decision §7 |
| `dc5e4f5` | F4 | `security-review-social-gap-w1-2026-10-30.md`: 0 C/H/M, 2 Low, 4 Info |
| `4241409` `e398312` `09242b6` | sweep 1 | #821, #822, #823 |
| `fe5de4e` | F4 addendum 1 | all six closed; 2 Info → #824 |
| `4119629` | sweep 2 | #824 |
| `ed33742` | F4 addendum 2 | both closed; F4-W1-09 (Info, docs wording) left open by the two-sweep rule |

**Deltas against §4.**
- **W1.2 stopped before committing.** The consequence §3.4 predicted was a
  #518 regression (actor-token laundering), shown by a probe test; the
  maintainer chose option A (D-N9). The probe is now the regression test
  `an_exchanged_token_is_refused_as_an_actor_even_by_its_own_client`.
- **G-D needed no new threat id**: T-471 (#518 / D-5) already covered it and
  was amended; T-489…T-494 stay reserved for W2/W3.
- **G-C is narrower than §3.3 stated** after #821: only the token's own client,
  passing the same binding checks a live refresh runs, triggers revocation;
  any other presentation is refused, marked and audited
  (`refused_unverified_presenter`) — the authorization-code replay precedent.
  Audit `response` values: `revoked_session` \| `refused` \|
  `refused_unverified_presenter` \| `revocation_failed` (with `failed_writes`);
  `token_client_id` recorded beside the presenting client.
- **Beyond scope, accepted:** introspection now returns `client_id` for every
  JWT access token (code, refresh, CIBA, device too — RFC 7662 conformant,
  F4-checked); `website/src/docs/oauth2.ts` and the agents guide corrected.
- **OpenAPI** regenerated three times in-wave (`RefreshReuseResponse`
  component); `sdks/openapi.json` and `management-registry.json` must be
  re-vendored by W4.

**Tests**, before → after on the binaries the wave touched: `axiam-oauth2`
`token_service` 149 → 166, lib 630 → 636; `axiam-api-rest`
`oauth2_flow_test` 44 → 46, `token_exchange_test` 29 → 31,
`external_token_exchange_test` 27 → 28; `axiam-auth` lib 278 → 280;
`grpc_units` 47 → 48; plus new `axiam-db` (3) and `axiam-core` (4) tests. Full
binaries of every touched crate green at each commit; none skipped or
ignored beyond the pre-existing live-service ignores.

**Issues filed:** [#821](https://github.com/ilpanich/axiam/issues/821),
[#822](https://github.com/ilpanich/axiam/issues/822),
[#823](https://github.com/ilpanich/axiam/issues/823),
[#824](https://github.com/ilpanich/axiam/issues/824) — all fixed in-wave,
close with the 1.2.0 PR. **Open after two sweeps:** F4-W1-09 (Info) — the docs
say a cross-client presentation is always audited
`refused_unverified_presenter`; under `refuse` or a session-less row it is
`refused`. Text only; proposed for W5.1.

**Not run:** OIDF conformance suite (no Docker); the full workspace suite in
one invocation (per-crate binaries instead); the frontend suite (no console
change in W1).

#### W2 — native sign-in (`claude/social-gap-w2`, closed 2026-10-31)

**Base** `fc8f888` (the plan branch after W1). **PR:** none (single PR after
W5); the plan branch was fast-forwarded to the wave head. **Commits**, each
signed:

| Commit | Task | What |
|---|---|---|
| `0349f3c` | W2.1 | `NativeLoginTrust` on OIDC federation configs (off by default; 1–64 client IDs ≤ 512 bytes, no duplicates; `max_token_age_secs` 1..=3600, default 300; OIDC only); schema **v111**; admin `PUT /api/v1/federation-configs/{id}` (not the PATCH §3.1 named); never on the public provider listing |
| `9b733e4` | W2.2 | `axiam-federation::native_login` (steps 2–7); `token_shape` marker list shared with X4; `provider_resolution` moved from axiam-api-rest; a crate-private multi-audience core behind `verify_id_token_full` (browser behaviour unchanged); `federation_id_token_replay` (schema **v112**, own trait, sweep, write-conflict retry) |
| `8157a17` | orchestrator | D-N10, D-N11; §3.1 steps 6–7 corrected |
| `9c24a61` | W2.3 | grant `urn:axiam:params:oauth:grant-type:provider-id-token`; dispatch; limiter bucket; audit `federation.native_login`; session + `sid` |
| `2811532` | orchestrator | D-N12…D-N15 |
| `75f79e6` | W2.4 | admin UI trust card; grant option in the client editor; coverage matrix |
| `c4e7e18` | W2.5 | discovery lists the grant (D-N15); OpenAPI + management registry regenerated; `docs/api/native-sign-in.md`; website page and blocks; T-489…T-492 (model 2.45.0, 492 threats); `CLAUDE.md` protocol line |
| `6346fd3` | F4 | `security-review-social-gap-w2-2026-10-31.md`: **1 High**, 1 Medium, 3 Low, 5 Info |
| `e2c0be9` | orchestrator | D-N16…D-N19 |
| `81d0dee` `34f2e14` `a12dbe5` | sweep 1 | #828, #829, #830 |
| `2ba70c7` | orchestrator | D-N18 wording: the per-client binding is not part of 1.2.0 |
| `94f3483` | F4 addendum 1 | 9 of 10 closed, F4-W2-10 partly; 1 Low + 4 Info new → #831 |
| `ace76a9` | orchestrator | D-N20, D-N21 |
| `24f6929` | sweep 2 | #831 |
| `64380ae` | F4 addendum 2 | all closed or closed as decided; no new finding; F4-W2-15 is a PR-description note |

**Deltas against §4 and §3.1.**
- **Replay store (D-N10, then D-N19, then F4-W2-11):** a dedicated table, not
  `oauth2_proof_replay`; keyed deployment-wide on (issuer, SHA-256 of the JWS
  signing input), kept to `exp` + 2 × leeway, left out of the tenant purge
  (deleting early would re-enable a token elsewhere).
- **Subject resolution (D-N11):** the browser path (`map_identity` →
  `provision_or_link_identity`); there is no `subject_mapping` setting.
- **Nonce (D-N16, D-N21):** hashed form only — SHA-256(request nonce) hex,
  either case, must equal the claim. §3.1 step 5's raw form is withdrawn: it
  bound nothing.
- **Audience (D-N17):** azp-first; Google Android tokens (`aud` = web,
  `azp` = Android) sign in with only the app IDs listed.
- **Grant (D-N12…D-N14):** a session per sign-in; `fapi2` clients under FAPI
  rules; `consent_required` spends the token, every user-independent check
  (including the sensitive-scope switch and the nonce bound) runs before it.
  An omitted `scope` is the empty set. The `login.post_auth` gate runs before
  issuance (#828; CONTRACT §22 lists the grant, version not bumped — W4).
- **Limiter:** `oauth2_provider_id_token:{tenant}:{ip}`; no address is refused.
- **Residuals recorded:** per-tenant (not per-client) trust, T-489 (D-N18);
  the first-sign-in account-existence signal shared with browser login, T-491
  (D-N20); JWKS refetch reachable by caller-chosen `kid`, T-491.
- **Beyond scope, accepted:** `website/src/docs/operate.ts` sweep list was two
  short (`oauth2_refresh_token` also missing) — fixed.
- **OpenAPI** regenerated in W2.5 and sweep 1; `TokenRequest` gains
  `provider`, `id_token`, `nonce`. W4 re-vendors `openapi.json`,
  `management-registry.json` and CONTRACT §22.

**Tests**, before → after: `axiam-federation` lib 349 → 404; `axiam-oauth2`
lib 636 → 648; new `provider_id_token_test` 21, `federation_id_token_replay_test`
4; `oauth2_client_test` 45 → 46; `axiam-db` schema tests +1 (v112); frontend
+29 (2416 total, line coverage 96.61 %). Unchanged and green:
`external_token_exchange_test` 28, `token_exchange_test` 31, `oauth2_flow_test`
46, `token_service` 166, `rate_limit_bucket_names_test` 21,
`sec095_federated_login_gate_test` 4, `axiam-server` lib 175, `cleanup_task` 65.

**Issues filed:** [#828](https://github.com/ilpanich/axiam/issues/828),
[#829](https://github.com/ilpanich/axiam/issues/829),
[#830](https://github.com/ilpanich/axiam/issues/830),
[#831](https://github.com/ilpanich/axiam/issues/831) — all fixed in-wave, close
with the 1.2.0 PR. **Open after two sweeps:** F4-W2-15 (Info, PR note): a dev
database that ran the pre-sweep v112 keeps the old required fields and fails
closed on native sign-in — drop `federation_id_token_replay` and the v112
stamp; no release affected. **Optional, not filed:** a non-base64 or DER
signature segment is audited `claim_rejected` rather than `bad_signature`
(same wire answer); the OpenAPI text says "lower-case SHA-256 hex" (accurate
guidance; say "either case" at the next regeneration).

**Not run:** OIDF conformance suite; a real Google/Apple token (the stub IdP
mints the shapes); `npm run test:a11y` (CI step).

#### W3 — IdP hint (`claude/social-gap-w3`, closed 2026-10-31)

**Base** `ad1430f` (the plan branch after W2). **PR:** none (single PR after
W5); the plan branch was fast-forwarded to the wave head. **Commits**, each
signed:

| Commit | Task | What |
|---|---|---|
| `01b4f43` | W3.1 | `axiam_idp_hint` on `/oauth2/authorize` and the PAR body, resolved server-side to `idp=<uuid>` on the login hop, unresolvable ⇒ byte-identical to no hint; `OAuth2Client.default_idp` (schema **v113**), validated on create/update, stale default ignored, not settable by DCR/CIMD |
| `787836d` | orchestrator | D-N22…D-N24 |
| `3b4b0bd` | W3.1b | kind name (`google`, `github`, `facebook`, `apple`, `microsoft`) as a third hint form (D-N24); slug beats kind; ambiguous ignored; generic kinds refused |
| `d78a6f9` | W3.2 | SPA auto-redirect (1.5 s; 3 s with reduced motion) with cancel and loop guards; admin "Default identity provider" select |
| `bd520e6` | W3.3 | OpenAPI + management registry regenerated (also the deferred W2 "either case" nonce wording); `docs/admin/oidc-authn-parameters.md`, `browser-login-hop.md`; website block; T-493, T-494 (494 threats); `CLAUDE.md` line |
| `19490dd` | F4 | `security-review-social-gap-w3-2026-10-31.md`: 1 Medium, 4 Low, 6 Info; server half holds |
| `a151491` | orchestrator | D-N25…D-N27 |
| `b42318c` `30f5b84` `d1c6f40` | sweep 1 | #832, #833, #834 |
| `2e13c33` | F4 addendum 1 | 01–11 closed; 1 Low + 4 Info new → #835 |
| `a15573e` | orchestrator | D-N28, D-N29 |
| `4588b12` | sweep 2 | #835 |
| `6d095e3` | F4 addendum 2 | 12–16 closed; 17–19 open → #836 |

**Deltas against §4 and §3.2.**
- **Hint forms (D-N24):** UUID, slug and branded kind name; §3.2 named only
  the first two.
- **Lanes (D-N22):** the hint and `default_idp` apply on every
  `authn_request_params` lane; **PAR (D-N23):** the pushed hint is
  authoritative, read through a narrow `ParService::peek`.
- **The SSO round trip (D-N25, #832):** an SSO leg started from a login hop
  now returns to the relying party — pre-existing gap, made the main path by
  G-B. The stored hop is bound to its start's `state` (D-N29); SAML and Apple
  handoff redirects now carry the spent start `state` (server change).
- **Re-authentication (D-N26, D-N28):** no auto-start on a re-authentication
  hop; the server marks a first-leg hop that demands a fresh authentication
  with `fresh=1` (honour lane, query and PAR), using the predicate the honour
  lane already decides with.
- **Beyond scope, decided by the maintainer (D-N27, #834):** admin OAuth2
  client create/update/delete are now audited (`oauth2.client_created`,
  `_updated` with `changed_fields`, `_deleted`); an audit-write failure is
  logged and the write stands, as every REST admin audit does.
- **OpenAPI** regenerated in W3.3; W4 re-vendors `openapi.json` and
  `management-registry.json`.

**Tests**, before → after: `axiam-oauth2` lib 648 → 659; `axiam-api-rest` lib
315 → 324; new `oauth2_idp_hint_test` 19; `oauth2_honour_lane_test` 39 → 42;
`par_test` 30 → 31; `axiam-db` schema +1 (v113); frontend 2416 → 2486 (line
coverage 96.64 %). Unchanged and green: `oauth2_flow_test`,
`oauth2_client_test`, `oauth2_login_hop_test`, `oauth2_cosmetic_params_test`,
`federation_login_providers_test`, `provider_id_token_test`,
`token_exchange_test`, `external_token_exchange_test`, `axiam-server` lib.

**Issues filed:** [#832](https://github.com/ilpanich/axiam/issues/832),
[#833](https://github.com/ilpanich/axiam/issues/833),
[#834](https://github.com/ilpanich/axiam/issues/834),
[#835](https://github.com/ilpanich/axiam/issues/835) — fixed in-wave, close
with the 1.2.0 PR. **Open after two sweeps:**
[#836](https://github.com/ilpanich/axiam/issues/836) — F4-W3-17 (Low: a
reload of a stripped interaction hop auto-starts the provider; proposed as the
first W4 item), F4-W3-18 (Info: CONTRACT §12 note on the handoff `state`;
W4.1), F4-W3-19 (Info: `Referrer-Policy` on the form-post error redirect; with
F4-W3-17). **Outside the plan, filed:**
[#837](https://github.com/ilpanich/axiam/issues/837) (federated state not
bound to the browser — pre-existing login CSRF),
[#838](https://github.com/ilpanich/axiam/issues/838) (forward
`prompt=login`/`max_age`/`ForceAuthn` upstream — the later item of D-N26).

**Not run:** OIDF conformance suite; a real upstream IdP;
`npm run test:a11y` (CI step).

#### W4 — contract 1.65 and the eleven SDKs (`claude/social-gap-w4`, closed 2026-11-01)

**Base** `a29ede0` (the plan branch after W3). **PR:** none in this repository
(single PR after W5); the plan branch was fast-forwarded to the wave head. The
SDK work is **one draft PR per SDK** (D-N30), each on `claude/bold-mayer-wpd3kv`.
**Commits** in this repository, each signed:

| Commit | Task | What |
|---|---|---|
| `c3a2043` | orchestrator | D-N30, D-N31 |
| `eecd4df` | W4.0 | #836: F4-W3-17 (`fresh=1` written when the page strips `reauth`/`acr`) and F4-W3-19 (`Referrer-Policy: no-referrer` on the form-post error 303) |
| `b1283a7` | W4.1 | version **1.2.0** ahead of the re-vendor (the 1.1.2 W8.4a precedent); OpenAPI and management registry regenerated |
| `76d35d9` | W4.1 | contract **1.65**: §37 native sign-in helper (`login_with_provider_id_token`, `native_nonce`, 13 conformance tests), `idp_hint` on `oidc_begin`/`oidc_par`, the §9 refresh-reuse note, §15.2 rule 10, F4-W3-18 (§12.1 note 12), §34.9 record |
| `73c2532` | orchestrator | D-N32 … D-N35 |
| `294cdd9` | W4.13 | `sdk-contract-1.65-conformance-review.md`: 21 findings, 3 Medium |
| `8c0241f` | orchestrator | D-N36, D-N37 |
| `d93976b` | W4.13a | contract 1.65 amended in place: C165-09 … -13, -19; D-N36 (PAR carries the begin URL's hint); §12.1 rule 3 "no redirect is followed" |
| `a59ef55` | review addendum 1 | fix round re-checked; C165-22 … -28 |
| `e6890c0` | review addendum 2 | sweep 2 re-checked; C165-29 … -32 |
| `365b106` | orchestrator | D-N38 |
| *(this commit)* | review addendum 3 + results | the targeted pass; W4 results |

**SDK draft PRs** (all green on CI at their final heads unless noted):

| SDK | PR | Final head | Notes |
|---|---|---|---|
| Rust | [ilpanich/axiam-rust-sdk#145](https://github.com/ilpanich/axiam-rust-sdk/pull/145) | `f047710` | `OidcBeginParams.idp_hint` is a source-breaking public field (listed, D-N32); `retry_after` on the `#[non_exhaustive]` `Auth` variant |
| TypeScript | [ilpanich/axiam-typescript-sdk#157](https://github.com/ilpanich/axiam-typescript-sdk/pull/157) | `b199c0a` | `retryAfterMs` additive; browser `/oauth2/*` `redirect: 'error'` |
| Python | [ilpanich/axiam-python-sdk#107](https://github.com/ilpanich/axiam-python-sdk/pull/107) | `ff8a2a9` | C165-01 (Medium): AXIAM's description-less 429 now maps to `OAuthProtocolError` |
| Java | [ilpanich/axiam-java-sdk#127](https://github.com/ilpanich/axiam-java-sdk/pull/127) | `b54a3bb` | record constructors source-breaking (D-N32); one redirect-free `oauth2HttpClient` |
| Kotlin | [ilpanich/axiam-kotlin-sdk#82](https://github.com/ilpanich/axiam-kotlin-sdk/pull/82) | `08c4b07` | data-class constructors source/binary-breaking (D-N32); C165-28 flake tracked |
| C# | [ilpanich/axiam-csharp-sdk#115](https://github.com/ilpanich/axiam-csharp-sdk/pull/115) | `620b987` | `adoptAsCredential` dropped (C165-18); `RetryAfter` public |
| PHP | [ilpanich/axiam-php-sdk#89](https://github.com/ilpanich/axiam-php-sdk/pull/89) | `2b2809b` | positional constructors source-breaking (D-N32); one `oauth2PostOptions()` for every `/oauth2/*` POST |
| Go | [ilpanich/axiam-go-sdk#107](https://github.com/ilpanich/axiam-go-sdk/pull/107) | `e4235e7` | pre-existing `-race` data race in a UMA test (CI runs without `-race`) |
| Swift | [ilpanich/axiam-swift-sdk#80](https://github.com/ilpanich/axiam-swift-sdk/pull/80) | `139198d` | `oidcRefresh` single-flight guard added (D-N34) |
| C | [ilpanich/axiam-c-sdk#79](https://github.com/ilpanich/axiam-c-sdk/pull/79) | `02aa474` | **SOVERSION 3** (C165-02); 1.1.3's `AXIAM_VERSION_PATCH` fixed (D-N35); `oauth_error_description`, `oauth_retry_after_ms` |
| C++ | [ilpanich/axiam-cplusplus-sdk#82](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/82) | `c37f016` | **SOVERSION 5** (D-N37); an intermittent g++-16/C++23 crash after the new tests, in pre-existing curl tests (re-run green; a diagnostic is proposed on the PR) |

**Deltas against §4.**
- **W4.0 added** (D-N31): #836's F4-W3-17/-19 in this repository; F4-W3-18 in the contract.
- **Version bump moved forward** to W4.1, so every SDK vendors the final spec once.
- **Decisions in-wave:** D-N30 … D-N38 — release level minor with breaks listed (D-N32); server floor documented, every SDK states it (D-N33); C SOVERSION 3 and C++ 5 (D-N32, D-N37); PAR carries the begin URL's hint (D-N36); no redirect is followed on an `/oauth2/*` POST (the C165-13 amendment).
- **Beyond scope, accepted:** the redirect hardening reached every `/oauth2/*` POST in nine SDKs, not only the new grant (C165-14, -22, -23, -26, -29); C's 1.1.3 version macro was wrong on `main` (D-N35).
- **The conformance review ran three rounds** (fix round, sweep 2, the D-N38 targeted pass).

**Tests** (suite before → after, each SDK): Rust 1202 → 1229; TypeScript 1781 → 1810;
Python 2175 → 2260; Java 1534 → 1562; Kotlin 1327 → 1357; C# 1514 → 1558 (+72
ASP.NET Core); PHP 2084 → 2125; Go 986 → ~1010; Swift 1498 → 1530; C 81 → 83 ctest
suites (Unity cases +~30); C++ 1667 → 1672 cases. This repository: frontend 2486 →
2490 (W4.0); `federation_login_providers_test` 54 → 55.

**Open after the review:** C165-24 (Info, §34.9 record text; next contract text
pass), C165-28 (Info, Kotlin flake, tracked).

**Not run locally** (CI covered): the Swift 6.4, JDK 25/27, PHP 8.2/8.5, Python
3.11/3.15, clang/C23 matrix legs; PHPStan; sanitizer/valgrind cells beyond those noted.

#### W5 — release readiness 1.2.0 (`claude/social-gap-1.2.0`, closed 2026-11-01)

| Commit | Task | What |
|---|---|---|
| `e8de849` | W5.1, W5.2 | CHANGELOG `[1.2.0] - 2026-11-01`; `release-1.2.0-upgrade-notes.md`; F4-W1-09 wording; Keycloak comparison rows; roadmap row; threat-model copies reconciled to 2.45.0 (494 / 463 / 21 / 10); website refresh-rotation text |
| `5ae4c02` | W5.3 | combined F4 review: 0 High/Medium, 3 Low, 3 Info; invariants hold; regression gate green |
| `a377893` `0274ad2` `e32a835` | orchestrator | D-N39 … D-N44 |
| `d6083b2` `2da13a6` | sweep 1 | #839 (logout revokes the session's refresh tokens; native client is a session participant), #840 |
| `60f0cdf` `9c040db` `92bf8d3` | sweep 2 | #841 (admin MFA reset revokes refresh tokens), #842 (code replay revokes the session's refresh tokens), D-N42 (`end_session` 500 declared) |
| `22acf19` | review addendum 1 | sweeps re-checked; F4-R12-07 … -11 |
| `c442c7c` `c6819a4` `54fe63f` | targeted pass (D-N43, D-N44) | #843: logout revokes before it deletes; the D-N39 limit documented; logout/reset-mfa 500s declared |
| *(this commit)* | review addendum 2 + results | |

**Deltas against §4.** Beyond the plan, decided by the maintainer: logout revokes the session's refresh tokens (D-N39), admin MFA reset revokes the user's (D-N40, a pre-existing regression), code replay revokes the session's (D-N41), three 500s declared in the spec with two re-vendors of `openapi.json` into the eleven SDK PRs (D-N42, D-N44).

**Issues filed:** #839 … #843 (fixed, close with the PR); #844 (session lineage key, later); ilpanich/axiam-cplusplus-sdk#83 (intermittent g++-16 CI crash, pre-existing code).

**Open:** F4-R12-09, F4-R12-11 (SSF part), the F4-R12-01 residual (Info); #844; C165-24, C165-28 (Info, W4).

**Expected cost**, in executor sessions: W1 3 (3 Opus), W2 6 (4 Opus), W3 4
(2 Opus), W4 13 (1 Opus), W5 3 (1 Opus) — roughly **29 sessions, 11 Opus**,
plus the orchestrator. W2.2 is the long pole; W4's eleven run in parallel.

---

## 5. Decisions requested from the maintainer

All seven were put to the maintainer on 2026-10-30, before W1 was cut, and
each was answered explicitly (none applied by default). Every answer is the
recommendation.

| # | Question | Recommendation | Answer |
|---|---|---|---|
| D-N1 | Where does native sign-in live: a grant at `/oauth2/token` (OAuth2 token set, client-bound, consent-ruled); a session-world `POST /api/v1/auth/federation/native` (the SDK login shape, cookies/handoff); or both? | **The grant.** It answers the analysis' two complaints (client binding, refresh) in the OAuth2 world where mobile apps live, and reuses rotation, DPoP and consent as they stand. The SDK helper wraps it. A session-world variant can follow if the console or an SDK needs it. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N2 | Default for `oauth2.refresh_reuse_response` | **`revoke_session`.** The BCP's behaviour, what the compared products do, and what AXIAM already does for an authorization-code replay. `refuse` stays available per tenant. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N3 | Hint parameter name | **`axiam_idp_hint`** alone, by the vendor-namespace rule already written at `login_hop.rs`. A `kc_idp_hint` alias would make a Keycloak client "just work" but puts a competitor's prefix in AXIAM's API; decline unless a migration asks for it. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N4 | On `fapi2`, revoke inside the grace window when the *successor* has already been rotated (the BCP's definitive breach signal)? | **Not in this plan.** T-254's reasoning stands for that lane; the window is sender-constrained; certification was obtained with it. Record as the residual it already is. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N5 | Accept a provider **access token** (plus a userinfo call) for OAuth2-protocol providers — GitHub, classic Facebook — as Auth0 does? | **No.** An access token's audience cannot be verified generically (Google's `tokeninfo` is provider-specific), which is the one check §3.1 rests on. Facebook has Limited Login (OIDC) for apps; GitHub has no native SDK sign-in to begin with. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N6 | Consent for the native grant | **Refuse with `consent_required`** any scope that would need a ceremony; the client's registration decides what needs none, as it does today. An "implicit consent for first-party clients" switch is a separate decision with its own threat entry. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N7 | Version | **1.2.0.** New grant, new parameter, one default behaviour change with an opt-out. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N8 | *(arose in W1.1)* Is `oauth2.refresh_reuse_response` tighten-only like the other security settings (a tenant may choose `refuse` only when its organization is on `refuse`), or may a tenant relax it alone? | **Tighten-only**, as every other hierarchical security setting; "available per tenant" in D-N2 is met through the organization. | **Answered by the maintainer 2026-10-30: as recommended.** |
| D-N9 | *(arose in W1.2)* The `client_id` claim on exchanged tokens re-opens #518 (an exchanged token becomes an acceptable `actor_token` for its exchanging client — laundering). A: claim + exchange marker, exchanged tokens never actors; B: accept; C: defer G-D | **A** | **Answered by the maintainer 2026-10-30: A.** See the §3.4 correction. |
| D-N10 | *(arose in W2.2)* Where is the provider-ID-token replay record kept? `oauth2_proof_replay.kind` is an ASSERT allow-list; widening it is a non-additive redefinition (#729). (a) widen the ASSERT; (b) a new additive table | **(b)** — `federation_id_token_replay`, schema v112, UNIQUE (tenant_id, provider_id, token_hash), written after signature and nonce checks, kept until `exp` + 60 s, a failed write refuses | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N11 | *(arose in W2.2)* §3.1 step 7 names a provider `subject_mapping` (linked_only / jit_provision) that does not exist. (a) resolve exactly as browser OIDC login (`map_identity` → `provision_or_link_identity`); (b) add a new per-provider mapping setting | **(a)** — native and browser sign-in land on the same user; no `email_verified` refusal; an unverified email is never marked verified | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N12 | *(arose in W2.3)* Does a native sign-in create an AXIAM session (tokens carry `sid`), or follow the device-grant precedent (no session)? | **Create a session**, as federated browser login does: upstream auth evidence, `amr = [fed]`; UserInfo and session-validated APIs accept the tokens and logout/session revocation ends them | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N13 | *(arose in W2.3)* May `fapi2`-profile clients use the grant? | **Allow**, under `fapi::enforce_token_request` and sender binding, as X4, CIBA and the device grant | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N14 | *(arose in W2.3)* Consent is decided after verification (it needs the resolved user), so `consent_required` has already spent the provider token and may have provisioned a first-time user | **Accept and document**: every user-independent check (parameters, scope registration, `resource`, grant, binding) runs first and spends nothing; after consent the app obtains a fresh provider ID token | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N15 | *(arose in W2.3)* List the grant URN in discovery `grant_types_supported`? | **List it** (W2.5, with the OpenAPI regen) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N16 | *(F4-W2-02, #829)* The raw-nonce form binds nothing (a stolen token's own claim passes). Hashed only; per-provider opt-in raw; or keep both as a residual? | **Hashed only**: SHA-256(request `nonce`) must equal the token's `nonce` claim; the app gives the provider SDK SHA-256(raw) and AXIAM the raw value | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N17 | *(F4-W2-03, #829)* Google Android tokens: `aud` = web client ID, `azp` = Android client ID. Change the audience rule or only the docs? | **azp-first**: the issued-to party is `azp` when present, else the single `aud`, and must be listed; with a listed `azp`, `aud` may be listed or the provider's web `client_id`; browser-flow tokens stay refused | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N18 | *(F4-W2-04, #830)* Bind provider app IDs to specific AXIAM clients? | **Residual for 1.2.0**, recorded under T-489 and documented | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N19 | *(F4-W2-06, #830)* Single use per provider config or deployment-wide? | **Deployment-wide**: the replay row is keyed on (issuer, SHA-256(token)); v112 is unreleased, so its definition changes in-wave | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N20 | *(F4-W2-12, #831)* First-sign-in provisioning still tells a caller whether an email/username is taken, as browser login does. Record a residual or change provisioning now? | **Residual** shared with browser login; correct the text that claims otherwise; a provisioning change can be planned later | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N21 | *(F4-W2-14, #831)* Upper-case hex nonce hashes are refused. Accept either case or document lower-case only? | **Accept either case**: normalise before the constant-time compare | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N22 | *(arose in W3.1)* Do `axiam_idp_hint` and `default_idp` apply on every `authn_request_params` lane or only on `honour`? | **Every lane**: the lanes govern the nine OIDC parameters; this is AXIAM's presentational parameter and never changes what is issued; honour-only would make `default_idp` inert for most clients | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N23 | *(arose in W3.1)* Under PAR, read the pushed hint (widening `ParService::peek` to return only `axiam_idp_hint`) or only a query copy? | **The pushed hint, via the narrow peek** (RFC 9126: pushed parameters are authoritative); a query copy beside `request_uri` is ignored | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N24 | *(arose in W3.1)* Also accept the provider kind name (`google`, `apple`, …) as a hint value, for branded providers without a slug? | **Recommended: not in 1.2.0.** | **Answered by the maintainer 2026-10-31: accept the kind name now** (a third form beside slug and UUID; a name matching more than one effective provider is ignored as ambiguous). |
| D-N25 | *(F4-W3-01, #832)* An SSO sign-in started from a login hop never returns to the relying party (pre-existing; G-B makes it the main path). Fix in W3 or document and defer? | **Fix in W3**: `return_to` carried in the pending-SSO record, the hop resumed on success, kept on the failure link | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N26 | *(F4-W3-03, #833)* The re-authentication hop auto-starts the provider while `prompt=login`/`max_age`/`ForceAuthn` are not forwarded upstream. No auto-start on re-auth, or forward upstream now? | **No auto-start on a re-authentication hop**; forwarding upstream is a later issue | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N27 | *(F4-W3-05, #834)* Admin OAuth2 client create/update/delete are not audited (pre-existing), so `default_idp` changes leave no record. Residual with its own issue, or audit in this wave? | **Recommended: residual + own issue.** | **Answered by the maintainer 2026-10-31: audit in this wave.** |
| D-N28 | *(F4-W3-12, #835)* Under PAR the sign-in page cannot see `prompt=login`/`max_age=0` and auto-starts the provider. Server marks the hop, or residual? | **The server marks the hop** as a re-authentication (query and PAR alike); the SPA stops parsing `return_to` (also settles F4-W3-13/-14) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N29 | *(F4-W3-16, #835)* Bind the remembered login hop to the SSO start that created it? | **Yes**: resume only on a callback whose `state` matches the one recorded at start | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N30 | *(W4 start)* How are the eleven SDK changes delivered? | **One draft PR per SDK**, each on `claude/bold-mayer-wpd3kv` in its own repository, referencing contract 1.65 and listed in the final axiam PR; the maintainer merges and tags | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N31 | *(W4 start)* #836 (F4-W3-17/-18/-19, open after W3's two sweeps): fix inside the plan? | **Yes**: F4-W3-17 and -19 as the first W4 commit (W4.0); F4-W3-18 folded into the contract 1.65 text (W4.1) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N32 | *(arose in W4)* Regenerating from openapi 1.2.0 is source-breaking in some SDKs (Java records and PHP constructors gain positional parameters; Rust `OidcBeginParams` gains a public field; C generated structs grow). Release level? | **Minor**, with the breaks listed in each CHANGELOG (the 1.1.0 and contract 1.42 precedent); C keeps SOVERSION 2 unless W4.13 finds a grown struct is caller-allocated | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N33 | *(arose in W4)* `native_login` is required in federation-config responses, so 1.2-line SDKs cannot decode them from servers older than 1.2.0. Document or make it optional? | **Document the floor**: the spec stays truthful; the SDK CHANGELOGs and the 1.2.0 upgrade notes state that federation-config admin calls of 1.2-line SDKs need a server of 1.2.0 or later | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N34 | *(arose in W4.10)* The Swift `oidcRefresh` lacked the single-flight guard §12.1 requires; the session added it. Keep it in the contract 1.65 PR? | **Keep it** (with D-N2, an unguarded concurrent refresh would end the session); W4.13 reviews it | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N35 | *(arose in W4.11)* The C SDK's CI was red on `main` because the 1.1.3 release left `AXIAM_VERSION_PATCH` at 2 and the version test at "1.1.2". Carry the fix in the contract 1.65 PR? | **Carry it** (ilpanich/axiam-c-sdk `c29f78e`) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N36 | *(W4.13 Q1, C165-11)* Under PAR, should `oidc_par` carry over a hint `oidc_begin` put on the authorization URL (9 SDKs drop it silently)? | **Yes, normative**: the URL's hint is pushed; an explicit `oidc_par` argument wins when both are set (the PHP pattern) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N37 | *(W4.13, C165-03)* The C++ model structs change layout while SOVERSION stays 4. Bump? | **Yes: SOVERSION 5**, `abi_soname` and the CHANGELOG corrected; the release stays minor (D-N32). C goes to SOVERSION 3 under D-N32 (C165-02) | **Answered by the maintainer 2026-10-31: as recommended.** |
| D-N38 | *(contract 1.65 review, after two sweeps)* C165-29 (Low, Kotlin `cibaInitiate` follows redirects), C165-30/-31/-32 (Info: C UMA mapper, Kotlin KDoc, TS comment): fix now or leave open? | **One targeted pass** (the D-N31 precedent); only C165-24 and C165-28 stay on the final PR's open list | **Answered by the maintainer 2026-11-01: as recommended.** |
| D-N39 | *(W5.3, F4-R12-01, #839)* Logout does not end a session's refresh tokens, so a native sign-in keeps minting tokens after logout. (A) revoke on logout and record the native client as a session participant; (B) correct the docs and CONTRACT; (A) for cookie-less sessions only | **(A)**: single-session logout and RP `end_session` revoke that session's refresh tokens (`revoke_all_for_session`); the docs and CONTRACT §37.2 rule 8 become true, no contract change | **Answered by the maintainer 2026-11-01: as recommended.** |
| D-N40 | *(W5.3 sweep 1)* Admin MFA reset ends the user's sessions but revokes no OAuth2 refresh tokens (a likely regression). Fix in 1.2.0? | **Fix in 1.2.0** (`revoke_all_for_user`) | **Answered by the maintainer 2026-11-01: as recommended.** |
| D-N41 | *(W5.3 sweep 1)* An authorization-code replay revokes the code's tokens (RFC 6749 §10.5) and the session, not the session's other refresh tokens. Match D-N39? | **Recommended: leave as is and file it.** | **Answered by the maintainer 2026-11-01: match D-N39 now** (`revoke_all_for_session` on code replay). |
| D-N42 | *(W5.3 sweep 1)* D-N39's failed-logout path answers a 500 on `end_session` that the OpenAPI spec does not declare; declaring it changes `sdks/openapi.json` (eleven SDK re-vendors). Declare it? | **Recommended: not now** (a browser redirect endpoint no SDK reads). | **Answered by the maintainer 2026-11-01: declare it and re-vendor `openapi.json` in all eleven SDK PRs.** |
| D-N43 | *(release review addendum 1)* F4-R12-07 (a half-failed logout cannot be retried with its own credential) and F4-R12-08 (the D-N39 limit after a console refresh is the common case, documented only in the upgrade notes): fix now? | **Targeted pass**: revoke the refresh tokens first and delete the session only on success; state the limit in the CHANGELOG, `docs/api/logout.md` and the deployment guide; file a session-lineage-key issue; also F4-R12-11's `logout.md` gap | **Answered by the maintainer 2026-11-01: as recommended.** |
| D-N44 | *(F4-R12-10)* Declare the 500 of `POST /api/v1/auth/logout` and `POST /api/v1/users/{id}/reset-mfa` in the spec (another re-vendor in eleven SDKs)? | **Declare and re-vendor**, consistent with D-N42 | **Answered by the maintainer 2026-11-01: as recommended.** |

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
