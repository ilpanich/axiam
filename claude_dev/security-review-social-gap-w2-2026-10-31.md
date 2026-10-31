# Security review — social-login gap plan, wave W2 (F4)

**Date:** 2026-10-31.
**Against:** `claude/social-gap-w2`, the wave diff `fc8f888..c4e7e18` (73 files,
about 8 340 lines added). Commits: `0349f3c` (W2.1 — the `native_login` trust
block on OIDC federation configs, schema v111, the admin `PUT`), `9b733e4`
(W2.2 — `axiam-federation::native_login`, `token_shape`, `provider_resolution`,
the multi-audience verification core, the `federation_id_token_replay` table
v112 with its repository, sweep and purge step), `9c24a61` (W2.3 — the
`urn:axiam:params:oauth:grant-type:provider-id-token` grant, token-endpoint
dispatch, limiter bucket, `federation.native_login` audit, session creation),
`75f79e6` (W2.4 — admin UI card and grant option), `c4e7e18` (W2.5 — discovery,
OpenAPI, `docs/api/native-sign-in.md`, website, threat model T-489…T-492),
`8157a17` / `2811532` (plan text: D-N10…D-N15). Issue #816.
**Scope:** G-A of [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md)
— §3.1 with its "Correction 2026-10-31", the decisions D-N1, D-N5, D-N6 and
D-N10…D-N15 (§5), the commit gate (§6), the threat-model and documentation
deltas (§7) and the rejections (§8); read against `sdks/CONTRACT.md` §22 (the
`login.post_auth` coverage clarification of SEC-095), the browser OIDC login it
claims parity with (`crates/axiam-federation/src/oidc.rs`,
`crates/axiam-api-rest/src/handlers/federation.rs`), X4
(`crates/axiam-federation/src/token_exchange.rs`), and `CLAUDE.md` *Security
Standards*.
**Method:** adversarial reading of the code, not of the commit messages: every
step of `verify_native_id_token` and the grant, the sibling paths each one
claims to mirror (the OIDC callback and `sso_login_post_auth`, the CIBA/device
grants for binding and FAPI, DCR and CIMD for the grant gate, X4 for the shape
markers), the replay repository and its error classification, the v111/v112
DDL, the sweep and purge registration, the admin handler's create and update
paths, the UI's validation, the OpenAPI delta, and the four threat-model
entries against the code and the tests they cite (every cited test name was
checked to exist). One suspicion was confirmed by a throw-away probe test
(F4-W2-02), kept out of the tree. `cargo test -p axiam-federation --lib --
native_login token_shape token_exchange`: 64 passed (65 with the probe);
`scripts/check-crate-layering.py` and `scripts/check-spec-digest.py`: green.
This review fixes nothing; every finding is a recommendation.

---

## 0. Summary

The verification core is sound. The audience is a deny-by-default list with no
web-client fallback, the issuer match is exact, `alg=none` is refused raw, no
new fetch surface is opened, the replay record is atomic, fails closed and sits
after the signature, the provider resolution cannot cross a tenant or
organization boundary, subject resolution is byte-for-byte the browser path's
(no email linking, so no account takeover through an unverified email), and
the grant cannot be obtained through DCR or CIMD. X4's refusals by name and by
shape are untouched and still pass.

One **High**: the native grant is a new interactive sign-in that never fires
the `login.post_auth` reactor gate, which `sdks/CONTRACT.md` §22 says covers
*every* interactive sign-in — the SEC-095 hole re-opened on a fifth path
(F4-W2-01). One **Medium**: the nonce "binding" binds nothing — the token
carries its own nonce, and because the raw form is accepted, whoever holds the
token passes the check by copying the claim, in the Apple hashed pattern too;
the "only the app that holds both can spend it" claim in the code, the docs,
the website and T-490/T-491 does not hold (F4-W2-02, probe-confirmed). Three
**Lows** and five **Informational** items follow.

| ID | Severity | Where | Finding |
|---|---|---|---|
| **F4-W2-01** | **High** | `crates/axiam-api-rest/src/handlers/oauth2.rs:4974-5030`; `crates/axiam-oauth2/src/provider_id_token.rs:442-499` | The native grant creates a session and issues tokens without `intercept_federated_login_post_auth`; an operator's `login.post_auth` veto (the embargoed-region example) is bypassed by native sign-in. CONTRACT §22 says the event covers every interactive sign-in. |
| **F4-W2-02** | **Medium** | `crates/axiam-federation/src/native_login.rs:422-449`, `:50-65` | The nonce check accepts the claim value itself as the request nonce, so it proves nothing a token holder lacks; a stolen token signs in and turns the victim's own presentation into a "replay". The stated binding (code comments, docs, website, T-490, T-491) does not exist. |
| **F4-W2-03** | Low | `crates/axiam-federation/src/native_login.rs:378-399`; `docs/api/native-sign-in.md:99` | Google's Android ID tokens carry `aud` = the *server (web)* client ID and `azp` = the Android client; the docs say the reverse. An operator who follows them sees refusals and lists the web client ID, and `issued_to` ignores `azp` for a single `aud`, so web-flow tokens become acceptable — T-489's "no web-client fallback" collapses in exactly the Android case. |
| **F4-W2-04** | Low | `crates/axiam-oauth2/src/provider_id_token.rs:346-391`; `crates/axiam-federation/src/native_login.rs:546-561` | Trust is per provider, not per AXIAM client: a token issued to native app X redeems through *any* grant-holding client of the tenant, with that client's scopes and resources. "Issued to us" means "to this tenant". Needs a maintainer decision. |
| **F4-W2-05** | Low | `docs/api/native-sign-in.md:167`, `:254-255`, `:334-335`; `claude_dev/threat-model-stride.md` T-490/T-491 | Docs promise what the code does not do: an omitted `scope` is the *empty* set (no `openid`, so no ID token), not "the client's registered set"; "the claims only access tokens carry" are not refused (only `typ`); the tenant's sensitive-scope switch is user-independent but is decided after the token is spent. |
| **F4-W2-06** | Informational | `crates/axiam-db/src/repository/federation_id_token_replay.rs`; `native_login.rs:583-602` | Single use is per provider *config*: two configs (two tenants of different organizations, or two providers in one tenant) listing the same client ID each accept the same token once. The sweep compares against the database clock, the decoder against the node's. |
| **F4-W2-07** | Informational | `crates/axiam-api-rest/src/handlers/oauth2.rs:4922-4926` | The bucket is deployment-wide per address at the login preset (10/min): mobile-carrier CGNAT puts many users of many tenants behind one key, and a missing address collapses everyone into `oauth2_provider_id_token:unknown`. |
| **F4-W2-08** | Informational | `crates/axiam-federation/src/oidc.rs:750-763`; `jwks_cache.rs:168` | An attacker-chosen `kid` now reaches the forced JWKS refetch from an unauthenticated (public-client) request. Bounded at one fetch per minute per provider, as intended, but the cooldown is shared with browser login and a caller can keep it armed. |
| **F4-W2-09** | Informational | `crates/axiam-oauth2/src/provider_id_token.rs:127-143`, `:575-584` | `nonce` has no length bound and is echoed into the signed AXIAM ID token. |
| **F4-W2-10** | Informational | `crates/axiam-federation/src/native_login.rs:611-614`; `oidc.rs:1053` | A JIT provisioning collision (email/username already taken) is `server_error` 500 rather than `invalid_grant` — an account-existence oracle for anyone holding a token for an identity whose (possibly unverified) email they chose. Same as the browser path; native gives it a machine-readable endpoint. |

---

## 1. Invariant verdicts

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 refuses ID tokens by name and by shape; its tests untouched | **Holds** | `crates/axiam-oauth2/src/token_exchange.rs` (the name refusals) is not in the diff. In `crates/axiam-federation/src/token_exchange.rs` only `reject_wrong_token_kind`'s body changed, to read `token_shape::ID_TOKEN_ONLY_CLAIMS`, and an unknown marker refuses (`_ => true`) — fail-closed. `an_access_token_shape_passes` (`:821`) and `every_id_token_marker_is_refused` (`:828`) are not in the diff and pass. `refused_as_subject_token` keeps the old six `typ` values exactly. |
| 2 | No refresh token from token exchange | **Holds** | No exchange code is in the diff; the native grant is its own arm (`oauth2.rs` `token_inner`, dispatched after the exchange arm) and is the only new issuer of refresh tokens. |
| 3 | fapi2 grace unchanged | **Holds** | `crates/axiam-oauth2/src/fapi.rs` untouched; the grant runs `fapi::enforce_token_request` and `certificate_binding_for` like CIBA and the device grant (D-N13). |
| 4 | Crate layering | **Holds** | "Crate layering OK: 19 crates, 62 internal production edge(s)". `axiam-federation` gained `subtle` (already a workspace dependency) and calls `axiam_auth::service::account_may_act` over an existing edge. |
| 5 | `missing_docs` on axiam-authz / axiam-directory | **Holds (untouched)** | Neither crate is in the diff. |
| 6 | Schema v111/v112 additive (#729) | **Holds** | Every statement `DEFINE … IF NOT EXISTS`, no `DEFAULT`/backfill on v111, no `OVERWRITE`; pinned by `v111_adds_only_the_native_login_columns`, `v112_adds_only_the_native_sign_in_replay_table`. Absent columns hydrate to `enabled: false` (`native_login_from_columns`). |

---

## 2. F4-W2-01 (High) — native sign-in skips the `login.post_auth` gate

**Where.** `handle_provider_id_token` (`crates/axiam-api-rest/src/handlers/oauth2.rs:4874`)
goes from `verify_native_id_token` (`:4974`) to consent (`:4991`) to
`issue_provider_id_token_grant` (`:5003`), which writes a session
(`provider_id_token.rs:481`) and mints the token set. Nothing on the path calls
`AuthService::intercept_federated_login_post_auth` (`crates/axiam-auth/src/service.rs:894`).
The only hook that runs is `token.pre_issue` (`provider_id_token.rs:466`), a
different event with a different payload and contract.

**Why it matters.** `sdks/CONTRACT.md:6313` is normative: "`login.post_auth`
covers every interactive sign-in, not only password login (clarified 2026-08,
SEC-095)… in every case after the credentials verify and before any session or
token is issued". SEC-095 (F4bis, 2026-08-15) was graded HIGH and blocking for
exactly this shape on SAML and OIDC; the webauthn discoverable path was added
to the list later for the same reason ("could be sidestepped by choosing 'sign
in with a passkey'"). Every other federated sign-in reaches the gate through
`sso_login_post_auth` (`federation.rs:2150`); the native grant is a fifth
interactive sign-in that does not. The browser-parity claim in D-N11/D-N12 and
in the docs ("the browser login's, unchanged") is true of subject resolution
and false of the sign-in gate.

**Exploit.** A tenant runs the §22.5 worked example — a reactor that vetoes
`login.post_auth` for sign-ins from an embargoed region, or a risk engine that
denies a user under investigation — and enables native sign-in for its mobile
app. A user (or a holder of a user's provider ID token, see F4-W2-02) in the
vetoed situation calls the grant instead of the browser flow and receives a
session, an access token and a refresh token that rotates for thirty days. The
operator's control fires on every path but this one, and nothing says so.

**Recommendation.** Fix size **S**. After `verify_native_id_token` succeeds and
before consent and issuance, call
`state.auth_service.intercept_federated_login_post_auth(tenant_id,
organization_id, &user, client_ip, user_agent)` — the existing adapter refuses
`require_mfa`, which is the right answer for a one-round-trip grant. Map a veto
to the same generic `invalid_grant` with an audit `reason_code` such as
`reactor_denied`, and a reactor transport failure to whatever
`fail_closed` resolves to on the other federated paths. The token is already
spent at that point, which is the D-N14 rule and acceptable. Add the native
grant to the CONTRACT §22 list, and a REST test with a denying reactor (the
pattern of the SEC-095 tests). Treat as blocking for the W2 merge, as SEC-095
was.

---

## 3. F4-W2-02 (Medium) — the nonce binding is not a binding

**Where.** `check_shape` (`crates/axiam-federation/src/native_login.rs:422-449`):

```rust
let hashed = sha256_hex(request_nonce);
let raw_match = token_nonce.as_bytes().ct_eq(request_nonce.as_bytes());
let hashed_match = token_nonce.as_bytes().ct_eq(hashed.as_bytes());
if bool::from(raw_match | hashed_match) { Ok(()) } else { Err(NonceMismatch) }
```

**The flaw.** The token's `nonce` claim is readable by anyone who holds the
token: a JWT payload is base64url. Because equality with the raw request value
is accepted, a presenter who copies the claim into the `nonce` parameter always
passes. That holds for the raw pattern (Google: the claim *is* the raw nonce)
and for Apple's hashed pattern too — the claim is `sha256(raw)`, and sending
that value as "the raw nonce" matches the raw arm. So the check verifies that a
`nonce` claim exists. It does not verify that the presenter is the party that
started the attempt.

**Confirmed by probe.** A throw-away test in `native_login/tests.rs` minted a
token with `nonce = sha256_hex(fx.nonce)`, decoded the payload, presented the
token with `nonce` = the copied claim (never using `fx.nonce`) and was signed
in; the genuine app's own presentation then failed with
`NativeLoginError::Replayed`. The probe is not in the tree.

**What is claimed instead.** The module doc (`native_login.rs:60-65`): "Recorded
after step 5, only a presenter holding both the token and its nonce — the app
that started the sign-in — can spend it." `docs/api/native-sign-in.md:272-276`:
"Someone who obtained a victim's token from a log or a proxy cannot burn it by
presenting it without the nonce." The website's oauth2 block: "only the app
that holds both can spend it". T-490 ("only a presenter who holds the token
*and* its nonce … can spend it"; residual 2 presumes the nonce is a secret) and
T-491 ("A nonce, bound to this request"). The test
`a_refused_presentation_does_not_spend_the_token` passes only because the
attacker it models guesses `"guess"` instead of reading the claim. The
OpenAPI text for `/oauth2/token` (`oauth2.rs:2102`) describes the parameter as
"the raw nonce or its SHA-256 hex", which invites clients to send the claim
value.

**Exploit.** An ID token leaks before the app redeems it — a crash report, an
analytics SDK, a debugging proxy, a log line in the app's own backend. The
holder reads the claim, calls the grant first, gets a session and a 30-day
refresh token for the victim, and the victim's app sees a generic
`invalid_grant`. This is the threat T-490 says is mitigated.

**Recommendation.** Fix size **S–M**, with a maintainer decision on
compatibility. The binding becomes real only when the value in the token is
not the value the presenter must send:

1. Accept **only** `sha256_hex(request.nonce) == claim` — the app gives the
   provider SDK `sha256(raw)` and sends `raw` to AXIAM. Apple requires this
   already; Google's SDKs (Credential Manager `setNonce`, `GIDSignIn` with a
   nonce) take any string, so the app can pass the hash there too. A thief
   then needs a SHA-256 preimage.
2. If raw equality must stay for a provider whose SDK cannot take an arbitrary
   nonce, make it a per-provider opt-in (`native_login.nonce_form: "sha256" |
   "raw"`, default `"sha256"`) and say plainly in T-490 that on `"raw"` the
   nonce is a shape requirement and the token is a bearer credential until
   spent.
3. Either way, correct the module doc, the docs page, the website block, the
   OpenAPI description and T-490/T-491, and add a test named after the attack
   (`a_presenter_who_copies_the_nonce_claim_is_refused`) next to the existing
   guess-based one.

---

## 4. F4-W2-03 (Low) — Google Android tokens and the single-`aud` rule

**Where.** `issued_to` (`native_login.rs:378-399`): with one `aud` member that
member must be listed, and `azp` is not read. `docs/api/native-sign-in.md:99`:
"The **iOS client ID** and the **Android client ID** … Google mints the ID token
with *that* client as `aud`."

**The issue.** On Android, Google Sign-In / Credential Manager issues the ID
token for the *server* client ID the app requests it for
(`requestIdToken(serverClientId)` / `setServerClientId`): `aud` is the web
client ID and `azp` is the Android client ID. (iOS without a server client ID
uses the iOS client ID as `aud`.) An operator who lists only the Android
client ID, as the page says, gets `wrong_audience` on every Android sign-in.
The fix they will reach for is listing the web client ID, and once listed,
`issued_to` accepts any single-`aud` token for the web client regardless of
`azp` — including tokens from the browser flow, which T-489 and the docs say
are not accepted "unless listed". The rule holds in letter and fails in the
configuration every Android deployment needs.

**Recommendation.** Fix size **S**, plus a doc correction. Treat `azp`, when
present, as the party the token was issued to for a single `aud` as well:
require `azp ∈ client_ids` whenever `azp` is present and differs from `aud`,
and let `aud` be either a listed ID or the provider's web `client_id` when
`azp` is listed. The operator then lists the Android and iOS client IDs only,
and a web-flow token (`azp` = web client) is refused. Correct the Google row of
the docs. Confirm against a captured Android token before changing the rule.

---

## 5. F4-W2-04 (Low) — the trust is per tenant, not per client

**Where.** The grant authenticates *some* client holding the grant
(`authenticate_provider_id_token_client`, `provider_id_token.rs:346`) and then
verifies the token against the *provider's* `client_ids`
(`native_login.rs:546`). Nothing ties the provider audience to the AXIAM client
the request names.

**The issue.** With two public clients in a tenant — a consumer app ("Shop")
and a staff app with wider scopes and `allowed_resources` — a Google token
minted for the Shop app's client ID redeems through the staff client's
`client_id`, because public clients authenticate by naming themselves and both
hold the grant. "Issued to us" means "issued to any app this tenant lists".
The user gains nothing they could not get through `/authorize` for a
first-party client, but a holder of a stolen Shop token (F4-W2-02) gets the
staff client's scope set, and the audit row attributes the sign-in to the
staff client.

**Recommendation.** Maintainer decision; fix size **M** if taken. Either an
optional per-OAuth2-client list of accepted provider audiences (the native
client's registration names the platform client IDs it is), or a map in the
`native_login` block from listed client ID to the AXIAM `client_id`(s) allowed
to redeem it. If declined, add the residual to T-489.

---

## 6. F4-W2-05 (Low) — docs and threat model promise what the code does not do

1. `docs/api/native-sign-in.md:167`: "`scope` … Omitted: the client's registered
   set." `requested_scopes` (`provider_id_token.rs:161-183`) makes an absent
   `scope` the **empty** set, which its own test pins
   (`scopes_are_the_request_within_the_registration`). An app that follows the
   page gets an access token with no scopes and no ID token.
2. Docs step 6 and T-491: "`typ: at+jwt`, or the claims only access tokens
   carry" are refused. `check_shape` refuses by `typ` only; no claim-based
   access-token marker exists in `token_shape`. Either add one (e.g. `scope`,
   `client_id` per RFC 9068 §2.2) or drop the clause. The `aud` check already
   blocks most access tokens, so this is a text fix unless a provider is found
   that mints ID-shaped access tokens for a native client ID.
3. D-N14, the docs (Consent) and T-490 residual 1: "Everything that does not
   depend on the user … is checked first and spends nothing." The tenant's
   sensitive-scope switch (`ConsentState::sensitive_switch_off`) is
   user-independent but is decided inside `decide_consent`
   (`provider_id_token.rs:452`), after the token is spent. Move the switch
   check into `prepare_provider_id_token_grant`, or name it in the exception
   list.
4. The CONTRACT §22 list of `login.post_auth` firing points must gain the
   native grant when F4-W2-01 is fixed.

Fix size **XS** (text), **S** for item 3 in code.

---

## 7. Informational

**F4-W2-06 — replay scope.** The UNIQUE key is `(owning tenant, provider_id,
token_hash)`. That makes a token single-use across tenants inheriting one
organization provider (tested), but not across *configs*: a multi-workspace
SaaS whose one mobile app is configured separately in each customer
organization's tenant accepts a stolen token once per tenant. Keying on
`(iss, token_hash)` deployment-wide would close it at the cost of tenant
isolation of the table and of purge semantics; recording the residual in T-490
is the cheaper answer. Separately, `cleanup_expired_rows` deletes by the
database's `time::now()` while `exp` is checked by the node's clock with 60 s
leeway; a node lagging the database by *d* seconds reopens a *d*-second window
at the end of a token's life if the sweep runs in it. Keeping rows to
`exp + 2 × leeway` removes the dependency.

**F4-W2-07 — limiter keying.** `oauth2_provider_id_token:{client_ip}` is one
bucket per address for the whole deployment at the password-login preset.
Correct for brute force, but mobile carrier NAT puts many unrelated users of
many tenants behind one address, and `client_ip == None` collapses every such
request into a single `…:unknown` bucket. Consider keying on
`{tenant_id}:{client_ip}` and refusing (or using the peer) instead of
`"unknown"`, and say in `rate-limit-sizing.md` that mobile traffic may need a
higher preset.

**F4-W2-08 — attacker-chosen `kid`.** Before G-A, the browser path only ever
verified ID tokens fetched by AXIAM from the provider's token endpoint; now a
public-client caller chooses the `kid`. The forced refetch stays at one per
60 s per `(tenant, provider)` cache key, so the plan's "no new fetch surface"
holds in volume. The cooldown is shared with browser login, though, and a
caller who sends one unknown `kid` a minute keeps it armed, so a genuine
rollover token presented in the minute after a key is first used waits for the
cache TTL. Providers publish keys ahead of use, so the effect is small; noted
so nobody shortens the TTL assumption later.

**F4-W2-09 — unbounded `nonce`.** `native_request` requires the three
parameters to be non-blank but bounds none; `nonce` is hashed and echoed into
the signed AXIAM ID token (`issue_id_token(..., Some(nonce), ...)`). Only the
form extractor's body limit applies. A 512-byte cap, refused as
`invalid_request` before anything else, is the house style.

**F4-W2-10 — provisioning collisions answer 500.** `provision_or_link_identity`
links by `(tenant, config, sub)` only, never by email — so an unverified email
cannot attach to an existing local account (no takeover; native does not widen
the browser path). But a first sign-in whose mapped username or email collides
with an existing user fails `user_repo.create`, becomes
`NativeLoginError::Server`, and answers `server_error` 500 instead of
`invalid_grant`. With a provider that releases unverified emails (generic OIDC,
some Limited Login accounts), a token for an attacker-controlled identity
carrying a chosen email tells the attacker whether that email has an account in
the tenant. Mapping a provisioning conflict to `invalid_grant` with
`reason_code: "provisioning_conflict"` closes the oracle on this path; the
browser path has the same behaviour and could take the same change.

**Test gaps** (no separate id): no test fires a denying `login.post_auth`
reactor at the grant (F4-W2-01); the nonce tests model a guessing attacker,
not a copying one (F4-W2-02); no REST test asserts that `consent_required`
leaves the token spent (T-490 says so); no test covers a provider ID token
redeemed through a second grant-holding client (F4-W2-04).

---

## 8. What holds

- **Audience.** `verify_id_token_core` is given `native_login.client_ids` and
  nothing else; the browser path still passes exactly `[config.client_id]`
  through the unchanged `verify_id_token_full` wrapper. An empty audience set
  is refused at the core (`oidc.rs:723`) so the decoder can never skip the
  check. Multi-`aud` requires a listed `azp` (`issued_to`), `aud` matching is
  exact (no trim, no case fold).
- **Issuer.** `set_issuer(&[expected_issuer])` against the discovered issuer,
  with Entra's templated issuer resolved only against
  `allowed_issuer_tenants` — the browser rule, shared.
- **Provider resolution.** `effective_providers` moved to `axiam-federation`
  verbatim (own enabled + organization's enabled, inheritable, unshadowed; a
  disabled own config still shadows). The native filter adds enabled, OIDC,
  `native_login.enabled` and a valid block, matches UUID **or** slug (a
  UUID-shaped string is only ever compared as an id), refuses an ambiguous
  slug instead of picking by list order, and re-reads the row from its owning
  tenant before trusting it. A provider of another tenant or organization is
  unreachable.
- **Header.** `reject_alg_none_raw` before `decode_header`; the algorithm
  allow-list before any key lookup; JWKS through the existing cache.
- **Freshness and shape.** `iat` required, bounded inclusively by
  `max_token_age_secs` (1…3600) and by the 60 s future leeway; `exp` by the
  decoder with the same leeway; `at+jwt` and refresh/logout `typ`s refused;
  the marker list is shared with X4 and the partition is pinned by
  `no_named_type_is_accepted_by_both_paths`. The nonce comparison is constant
  time and both arms always run (its weakness is F4-W2-02, not timing).
- **Replay.** One `CREATE` against a UNIQUE index, no read; inserted after
  signature, claims and nonce and before subject resolution; keyed on the
  provider's owning tenant. The retry loop retries only
  `is_transaction_conflict` errors, at most four attempts, and a conflict that
  outlasts it becomes `AxiamError::Database` → `ReplayGuardUnavailable` →
  `server_error`: no error can be read as success, and a UNIQUE violation is
  `ReplayDetected` on any attempt. Rows live to `exp + 60 s`, swept by a
  required (not builder-optional) `CleanupTask` argument registered in job
  health, and removed by the tenant purge in the `Grants` phase.
- **Subject.** `map_identity` → `provision_or_link_identity`, the browser's
  functions; no linking by email; an unverified email is provisioned as
  unverified; `account_may_act` before anything is issued; the issuing side
  re-checks `subject.tenant_id == tenant_id`.
- **Grant gate.** `KNOWN_GRANT_TYPES` lists the URN for administrator
  registration only; DCR's `grant_refusal` and CIMD's allow-list are
  `{authorization_code, refresh_token}` (+ CIBA with an initial access token),
  so neither can register it; no default set contains it (admin UI included).
  Client authentication follows SEC-093/SEC-086 ordering
  (`authenticate_client_credential`, then `enforce_token_request`, then the
  grant check, so `unauthorized_client` is learnt only by a credential holder).
- **Request checks before spend.** Parameters, registered scopes (refused, not
  narrowed), `resource` against `allowed_resources`, the grant and the
  DPoP/mTLS binding all run before the provider token is touched.
- **Issuance.** Access token with `client_id`, `sid`, `cnf` when bound, the
  real `organization_id`; refresh token only when the client holds
  `refresh_token`, stored with `client_id`, `session_id`, `resource`,
  `auth_time`/`acr`/`amr` and the #681 DPoP key binding; ID token only with
  `openid`, echoing the request nonce, with evidence only on the emitting lane;
  `amr = [fed]`, `auth_time` clamped to now. The session row has no browser
  token and an unusable console refresh hash, so `/auth/refresh` can never
  rotate it; session revocation and logout end the refresh tokens through
  `session_id` (the W1 machinery).
- **Error oracle.** Every `NativeLoginError` but the two datastore variants is
  one `invalid_grant` with one description (pinned by
  `every_token_refusal_is_one_generic_invalid_grant`); `AccountRefused` is
  among them. The residuals are F4-W2-10 (500 on a collision) and a timing
  difference between "provider not found" (no crypto) and later refusals,
  which reveals only whether a provider has native sign-in on.
- **Audit and logs.** `federation.native_login` on every attempt past client
  authentication, with `reason_code`; the caller-supplied provider name is
  truncated; neither the record nor any `tracing` line carries the token or
  the nonce; `NativeIdTokenRequest`'s `Debug` prints neither
  (`a_request_debug_prints_neither_token_nor_nonce`).
- **Admin API and UI.** `federation:update` on the `PUT`; the block is
  validated whether or not enabled (bounds 64 × 512 bytes, no blank, no
  duplicate, age 1…3600), and the protocol rule is applied on create and to the
  block the row *will* hold after an update, against the immutable stored
  protocol (the T-241 lesson). `PublicFederationProvider` has no
  `native_login` field. The UI mirrors the server's checks and sends the block
  wholesale; it does not weaken anything the server enforces.
- **Docs/threat model.** Every test name T-489…T-492 cites exists. Apart from
  the items in F4-W2-02, -03 and -05, the page and the entries describe the
  code; the discovery listing (D-N15) and the OpenAPI schema
  (`TokenRequest.provider/id_token/nonce`, `NativeLoginTrust*`) match, and the
  spec digest is current.

---

## 9. Needs a maintainer decision

- **F4-W2-02:** hashed-nonce-only (breaks any app that passes the raw nonce to
  its provider SDK) versus a per-provider `nonce_form` with `raw` documented as
  bearer-only.
- **F4-W2-04:** whether a provider audience should be bound to the AXIAM
  client(s) allowed to redeem it, or the per-tenant scope recorded as a
  residual of T-489.
- **F4-W2-06:** whether single use should span configs (deployment-wide key)
  or the per-config scope recorded as a residual of T-490.
- **F4-W2-01** is a fix, not a decision — but whether it blocks the W2 merge
  should be stated, given SEC-095 was graded blocking.
