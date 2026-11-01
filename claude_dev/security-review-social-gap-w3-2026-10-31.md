# Security review — social-login gap plan, wave W3 (F4)

**Date:** 2026-10-31.
**Against:** `claude/social-gap-w3`, the wave diff `ad1430f..bd520e6` (75 files,
about 3 300 lines added). Commits: `01b4f43` (W3.1 — `axiam_idp_hint` on the
query and the PAR body, `resolve_login_idp`, `Cosmetic.idp`, `&idp=<uuid>` on
the login hop, `OAuth2Client.default_idp` with schema v113 and the
create/update validation, the narrow `ParService::peek`), `787836d` (plan text
D-N22…D-N24), `3b4b0bd` (W3.1b — the branded kind-name form, D-N24), `d78a6f9`
(W3.2 — the SPA auto-redirect, cancel and loop guards; the admin
"Default identity provider" select), `bd520e6` (W3.3 — OpenAPI,
`docs/admin/oidc-authn-parameters.md`, `docs/admin/browser-login-hop.md`,
website, threat model T-493/T-494). Issue #817.
**Scope:** G-B of [`social-login-gap-plan-2026-10-30.md`](social-login-gap-plan-2026-10-30.md)
— §3.2, the decisions D-N3 and D-N22…D-N24 (§5), the commit gate (§6), the
threat-model and documentation deltas (§7) and the rejections (§8); read
against the login hop it extends (`crates/axiam-oauth2/src/login_hop.rs`,
`docs/admin/browser-login-hop.md`), PAR (`crates/axiam-oauth2/src/par.rs`),
the public provider resolver (`crates/axiam-federation/src/provider_resolution.rs`,
`crates/axiam-api-rest/src/handlers/federation_login.rs`), the SPA sign-in
and SSO-callback pages, and `CLAUDE.md` *Security Standards*.
**Method:** adversarial reading of the code, not the commit messages: the
query and PAR carriers through `authn_params`, both arms that build a sign-in
URL (the anonymous first leg in `resolve_authorize_principal` and the
re-authentication hop in `authorize`), `match_idp_hint` tier by tier, the
effective-provider resolver's shadowing, every write path of `OAuth2Client`
(admin create/update, DCR, RFC 7592, CIMD; no gRPC or AMQP management surface
for clients exists — `sdks/management-registry.json` lists only the REST
`/api/v1/oauth2-clients` operations), the SPA's `LoginPage`,
`SsoCallbackPage` and `ssoLogin.ts` end to end, the admin form, the OpenAPI
delta and the two threat-model entries against the code and the tests they
cite (all 29 cited Rust test names and all seven cited frontend test titles
exist in the tree).

Throw-away probes, kept out of the tree:

- *Server* (appended to `oauth2_idp_hint_test.rs`, then reverted): `%FF`,
  `corp%FFokta`, `%20%20`, `%00`, `corp-okta%00`, a zero-width-space prefix,
  `javascript:alert(1)`, `//evil.example`, an embedded tab, and an
  organization provider's UUID once the tenant shadows it — each
  byte-identical to the unhinted response bar the echo; an ignored hint on a
  client with a `default_idp` leaves the default applied byte-identically; a
  `default_idp` naming a shadowed organization provider is `400` on create;
  ` corp-okta `, `%09corp-okta`, `urn:uuid:<id>` and `{<id>}` resolve; a
  repeated `axiam_idp_hint` is answered exactly as a repeated `login_hint`.
- *SPA* (a temporary `F4Probe.test.tsx`, then deleted): with
  `sessionStorage.getItem`/`setItem` throwing, the page still starts the
  provider exactly once and does not crash; `/login?idp=<listed id>&org=acme`
  loads no providers and starts nothing; cancelling does not write the guard.

Test runs (all exit 0): `cargo test -p axiam-api-rest --no-default-features
--test oauth2_idp_hint_test` 17 passed (19 with the probes);
`--lib idp_hint_tests` 8 passed; `cargo test -p axiam-oauth2 --lib --
authn_params login_hop par::` 69 passed; `cargo test -p axiam-db --lib schema`
96 passed; `npx vitest run LoginPageIdpHint.test.tsx OAuth2ClientsPage.test.tsx`
green (70 with the probe file); `scripts/check-crate-layering.py` and
`scripts/check-spec-digest.py` green. This review fixes nothing; every
finding is a recommendation.

---

## 0. Summary

The server half is sound. The hint is resolved against exactly the list the
unauthenticated providers endpoint already returns for the request tenant, the
datastore access pattern does not depend on the hint's value (so nothing about
another tenant's providers is measurable), only a `Uuid` crosses into the
redirect, every unresolvable form tried is byte-identical to no hint (bar the
query echo in `return_to`, which every unknown parameter has always had), the
precedence rules cannot route a word to a provider the operator did not mean,
`peek` stays a read that hands back nothing that authorizes, `default_idp` is
validated on both write paths against the same resolver and is unreachable
from DCR, RFC 7592 and CIMD, and nothing that is issued changes on any lane.

The findings are on the **browser half**, and the first is the important one:
the SSO leg the auto-redirect starts **never returns to the relying party** —
`SsoCallbackPage` always ends on `/dashboard`, and its failure link drops
`return_to` — so G-B's headline flow ("send the user straight there") lands
the user in the AXIAM console instead (F4-W3-01, Medium; a pre-existing gap in
the federated-from-hop path that G-B makes the primary path). The `idp`
parameter is also inert until the user types their workspace, which the
docs do not say — and that typing is, today, the only thing standing between
`/login?idp=…` and a cross-tenant redirector (F4-W3-02). Auto-starting on the
re-authentication hop lets an upstream SSO session satisfy `prompt=login` /
`max_age` with no user action (F4-W3-03). Two more Lows and six
Informational items follow. No High.

| ID | Severity | Where | Finding | Fix |
|---|---|---|---|---|
| **F4-W3-01** | **Medium** | `frontend/src/pages/auth/SsoCallbackPage.tsx:109`, `:144`; `frontend/src/pages/LoginPage.tsx:484-500`; `frontend/src/services/ssoLogin.ts:105-124` | A federated sign-in started from a login hop (by the new auto-redirect or a button) never resumes the authorization request: success navigates to `/dashboard`, failure links to a bare `/login`. The RP's request is abandoned; the user lands in the console. Docs, website, CHANGELOG and the admin help text describe the opposite. | S |
| **F4-W3-02** | Low | `LoginPage.tsx:457-470`, `:569`; `crates/axiam-oauth2/src/login_hop.rs:616-659` | The hop carries no workspace and providers load only on the workspace step's submit (not even from `?org=`), so `idp` does nothing until the user types their organization. Undocumented, and load-bearing for T-493's residual: a "fix" that loads providers from URL parameters turns `/login` into a 1.5-second redirector to any tenant operator's IdP. | XS (test + docs) |
| **F4-W3-03** | Low | `crates/axiam-api-rest/src/handlers/oauth2.rs:2226-2242`; `LoginPage.tsx:528-552`; federation start (no `prompt`/`max_age`/`ForceAuthn` forwarded upstream) | The re-authentication hop (`prompt=login`, `max_age`, `acr_values`) carries `idp`, and the page starts the provider unattended; an upstream SSO session answers silently, so a fresh `authenticated_at` is minted with no credential presented and no click. | S, needs a decision |
| **F4-W3-04** | Low | `LoginPage.tsx:101`, `:210-214`; `SsoCallbackPage.tsx:65-69`, `:144`; T-493; `docs/admin/oidc-authn-parameters.md` "No loop" | The error-parameter loop guard models a path production never produces: nothing in the tree puts `error`, `error_description` or `sso_error` on `/login`. There is no loop (the real failure path drops `idp`, and every start needs a typed workspace), but the documented mitigation is not the one that operates, and the cited test exercises a synthetic URL. | XS |
| **F4-W3-05** | Low | `crates/axiam-api-rest/src/handlers/oauth2_clients.rs:1039`, `:1463` (and `create`/`update` generally) | Setting or clearing `default_idp` — which steers every sign-in of a client to one provider — writes no audit row; admin client create/update are not audited at all (pre-existing; only the #675 public conversion is). | S |
| F4-W3-06 | Info | `docs/admin/oidc-authn-parameters.md`; T-493; CHANGELOG | "Byte-identical" is byte-identical *apart from the hint's own echo inside `return_to`*; the raw RP string does reach the SPA, as an opaque part of `return_to`. A hint long enough to push `return_to` past 4096 bytes turns the hop into the no-`browser_sso` refusal — as any long unknown parameter always has. | XS (wording) |
| F4-W3-07 | Info | `crates/axiam-oauth2/src/authn_params.rs:525-527`, `:466-470` | Trimming is `str::trim` (Unicode whitespace): `corp-okta%0A`, `%09corp-okta` resolve. Harmless — only a UUID crosses — and "trimmed" is documented; noted so a reader of the T-493 "control characters" claim knows CR/LF/TAB at the ends are folded, not refused. | — |
| F4-W3-08 | Info | `oauth2.rs` `authorize_query_error` (`:6049`) | A repeated `axiam_idp_hint` makes the request an error (`401 authentication_failed`), identical to a repeated `login_hint`: the one way a hint changes the outcome. Pre-existing extractor behaviour, and RFC 6749 §3.1 forbids repeats. | — |
| F4-W3-09 | Info | `crates/axiam-oauth2/src/par.rs:379-409`; `oauth2.rs` PAR handler | The pushed hint is stored unbounded (form limit only) and bounded at use, as `login_hint` is. `peek` now returns a value: the provider a pushed request chose becomes visible in the front channel as `idp=<uuid>` to whoever holds the `request_uri` — a public, tenant-listed id. Single use and expiry unchanged. | — |
| F4-W3-10 | Info | `frontend/src/pages/oauth2/OAuth2ClientsPage.tsx:1274-1301` | The admin select is fed from the public listing keyed on the auth store's slugs, falling back to the tenant's own enabled configs (inherited providers then missing). The server is the judge (a wrong option is a `400`), so this is UX only. | — |
| F4-W3-11 | Info | `LoginPage.tsx` cancel button | Cancel does not record the guard, so a reload re-arms the redirect; a successful password sign-in clears it. UX only. | — |

---

## 1. Invariant verdicts

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 refuses ID tokens by name and by shape | **Holds** | `crates/axiam-oauth2/src/token_exchange.rs` and `fapi.rs` gained only `default_idp: None` / `axiam_idp_hint: None` struct fields in test fixtures; no refusal logic is in the diff. |
| 2 | No refresh token from token exchange | **Holds** | No exchange code path is in the diff. `token.rs` changed one doc comment (the D-N21 nonce case). |
| 3 | `fapi2` grace unchanged; the hint changes nothing issued | **Holds** | `fapi.rs` untouched bar a fixture field. `Cosmetic.idp` is read only by `build_login_redirect_for`; nothing in `AuthorizeService`, the code row, the session or the token claims reads `idp_hint`, `default_idp` or `PeekedRequest`. A `fapi2` client is PAR-only, so its hint is the pushed one. |
| 4 | Crate layering | **Holds** | "Crate layering OK: 19 crates, 62 internal production edge(s), all pointing inward; 4 declared test-only inversion(s)." |
| 5 | `missing_docs` on axiam-authz / axiam-directory | **Holds (untouched)** | Neither crate is in the diff. |
| 6 | Schema v113 additive (#729) | **Holds** | One `DEFINE FIELD IF NOT EXISTS default_idp ON TABLE oauth2_client TYPE option<string>`; no `DEFAULT`, backfill, `OVERWRITE` or index; pinned by `v113_adds_only_the_client_default_idp_column` and `is_additive`; the pushed hint needs no DDL (`params` is `FLEXIBLE`). A non-UUID stored value is refused on read (`decode_default_idp`), never guessed. |
| 7 | Spec and registry in sync | **Holds** | `check-spec-digest.py` matches; `axiam_idp_hint` is on `GET /oauth2/authorize` and `PushedAuthorizationRequest`; `default_idp` on the create, update (nullable, three-state) and response schemas; the registry digest moved with it. |

---

## 2. F4-W3-01 (Medium) — the SSO leg never returns to the relying party

**Where.** `handleSsoSelect` (`LoginPage.tsx:484-500`) posts
`{org_slug, tenant_slug?, federation_config_id, redirect_uri: ssoCallbackUrl()}`
and records only `{protocol, displayName}` (`rememberPendingSso`,
`ssoLogin.ts:105`). Nothing carries `returnTo`. `SsoCallbackPage` then, on
success, `clearAutoRedirect(); setUser(…); navigate("/dashboard")` (`:107-109`);
on any failure it renders the message and a `<Link to="/login">Back to sign in`
(`:144`) — bare, without `return_to`. The new test pins the first half
("return_to is untouched (the page never rewrites it for SSO)", `navigate` not
called) and nothing tests where the browser ends up.

**Why it matters.** G-B exists for exactly this flow: an RP sends the user to
`/oauth2/authorize?…&axiam_idp_hint=google`; AXIAM hops to
`/login?return_to=…&idp=<uuid>`; the page starts Google; Google returns to
`/auth/sso/callback`; and then the user is in the AXIAM admin console, with an
OP session (the federated completion does set `axiam_op_session`,
`handlers/federation.rs:2313`), while the RP's tab waits for a redirect that
never comes. The user must go back to the RP and start again (that second
request then finds the session and issues a code). The docs ("send the user
straight there instead of through AXIAM's provider chooser"), the website
("Sending the user straight to one identity provider"), the CHANGELOG and the
admin help text ("the login page goes straight to this provider") all describe
an end-to-end flow that does not complete. The gap predates W3 for the manual
SSO buttons on a hop page, but W3 turns it from a corner into the primary path,
and every `default_idp` client now walks into it on every sign-in.

Security-wise it is not an escalation — the user only gets a session they
could have got by clicking — but a non-admin end user of an RP is now routinely
dropped into the console UI, and after a *failed* leg the authorization request
is unrecoverable from the page.

**Recommendation.** Fix size **S**. Store the already-sanitized `returnTo`
in the pending-SSO record (it is a same-origin path, validated by
`sanitizeReturnTo`), and in `SsoCallbackPage`'s success branch call
`resumeLoginHop(pending.returnTo, navigate)` — which re-validates at the moment
it navigates, the T23.1.3 rule — falling back to `/dashboard` only when there
is none. On failure, make "Back to sign in" carry `return_to` (and deliberately
**not** `idp`, which keeps the failure path quiet; see F4-W3-04). Add a test of
each end. Until it lands, correct the four texts above to say the hint picks
the provider and the user then restarts from the RP. Needs a maintainer call on
whether this blocks the W3 merge; this review recommends it does, because the
feature's acceptance (plan §4 W3.1/W3.2) is met in isolation and not end to end.

---

## 3. F4-W3-02 (Low) — `idp` is inert until the user types a workspace, and that is load-bearing

**Where.** `build_login_redirect_for` (`login_hop.rs:616-659`) emits
`return_to`, `reauth`, `acr`, the cosmetic three and `idp` — no organization or
tenant. `loadProviders` is called from exactly one place, the workspace step's
submit (`LoginPage.tsx:569`); `?org=`/`?tenant=` pre-fill the fields and jump to
the credentials step but load nothing (probe: `/login?idp=<listed>&org=acme`
issues no providers request and starts nothing). `autoProvider` requires a
loaded list (`:528`).

**Why it matters.** Two ways.

1. *Functional/docs.* Every hinted sign-in still asks the user for their
   organization slug first; the redirect fires 1.5 s after they press Continue.
   No text says so.
2. *Security.* T-493's accepted residual ("a person who reaches
   `/login?idp=<uuid>` by hand can at worst start a provider the tenant already
   offers as a button") is true only because the **tenant is the one the user
   typed**. The SPA cannot tell a server-built `/login` URL from a hand-made
   one, and any tenant operator on a shared deployment controls their own
   provider's `authorization_endpoint`/SAML SSO URL. If the obvious fix for (1)
   is made — load providers from `?org=`/`?tenant=`, or from the `tenant_id` in
   `return_to` (which an attacker can also forge, pointing at their own client)
   — then `https://axiam.example/login?org=evil&idp=<evil provider>` becomes a
   link on the AXIAM origin that navigates to an attacker-chosen URL after 1.5
   seconds with no click: an open redirect and a phishing launchpad carrying
   AXIAM's origin.

**Recommendation.** Fix size **XS** now: a frontend test pinning "a workspace
taken from the URL never auto-starts a provider; only a submitted workspace
step does" (the probe, kept), and a sentence in
`oidc-authn-parameters.md` and T-493 saying the user enters the workspace
first and why that matters. If (1) is to be fixed later, bind the workspace to
the hop server-side (e.g. a short-lived, single-use, server-minted handle that
the SPA exchanges for `{tenant, idp}`), never to a URL parameter, and make it a
plan item with its own threat entry.

---

## 4. F4-W3-03 (Low) — unattended re-authentication through an upstream SSO session

**Where.** The re-authentication arm (`oauth2.rs:2226-2242`) resolves the hint
or `default_idp` and puts `idp` on the `reauth=1` hop (as §3.2 asks and the
docs state). The page auto-starts it like any other (`LoginPage.tsx:528-552`;
the `reauth` effect only ends the AXIAM session). The federation start
forwards neither `prompt=login` nor `max_age` to an OIDC provider, nor
`ForceAuthn` to a SAML IdP (no occurrence in `axiam-federation/src/oidc.rs` or
`federation_login.rs`).

**Scenario.** An RP sends `prompt=login` (or `max_age=0`) before a sensitive
operation. AXIAM ends its session and hops to `/login?reauth=1&…&idp=<google>`;
after the workspace step the page goes to Google, Google still holds a session
and answers immediately, and AXIAM mints a session with a fresh
`authenticated_at` and `amr: [fed]`. Nobody re-entered anything and, unlike the
manual button, nobody clicked. With F4-W3-01 fixed the return leg also
completes automatically, so the RP receives a "just re-authenticated" `auth_time`
for a person who may have walked away from the keyboard. (`acr_values` asking
for MFA is not satisfiable this way, and the return-leg marker bounds the
chain, so this is about `prompt=login`/`max_age`, not about the factor.)

**Recommendation.** Needs a maintainer decision; either is size **S**:
(a) never auto-start on `reauth=1` — show the provider preselected and
focused, one click away; or (b) when the hop is `reauth=1`, forward
`prompt=login`/`max_age=0` to OIDC providers and `ForceAuthn="true"` to SAML
IdPs on the federation start, and say in the docs that a provider which ignores
them (several social providers do) cannot give a real re-authentication. (a) is
the smaller change and the safer default; (b) is the more correct one and
helps the manual button too.

---

## 5. F4-W3-04 (Low) — the documented loop guard is not the one that operates

**Where.** `SSO_ERROR_PARAMS = ["error", "error_description", "sso_error"]`
(`LoginPage.tsx:101`) vetoes the redirect when `/login` carries one. Nothing
in the tree puts any of them on `/login`: `sso_error` appears nowhere else, and
the real failure path — a provider error or a completion failure — ends on
`SsoCallbackPage`, which renders the message in place (`:65-69`) and links to
a bare `/login` (`:144`). The test "never redirects when the page carries %s
(a failed SSO leg)" loads a synthetic `/login?error=access_denied&idp=…`, and
T-493 and the docs cite it as "the return from a failed leg".

**What actually holds.** There is no loop, verified end to end: the failure
link drops `idp` (so the next `/login` has nothing to start); an RP that
restarts the request produces a fresh `/login?…&idp=` that the
`sessionStorage` guard suppresses for ten minutes; where storage throws
(probe), the page still starts at most once per load, and every start needs
the user to submit the workspace step, so nothing repeats unattended; the
browser Back button lands on a page whose `autoStarted` ref (or a fresh load
under the guard) is quiet.

**Recommendation.** Size **XS**. Reword T-493 and the docs' "No loop" bullet to
name the operative guards (the failure page does not carry `idp`; the
`sessionStorage` guard; one start per load; the typed workspace). Keep the
error-param check as defence in depth, drop `sso_error` or have something set
it, and add a `SsoCallbackPage` test that the failure link carries no `idp`
(and, after F4-W3-01, that it carries `return_to`).

---

## 6. F4-W3-05 (Low) — a `default_idp` change is not audited

**Where.** `create` and `update` in `oauth2_clients.rs` validate
`default_idp` (`:1039`, `:1463`) and write it, and append no audit entry; the
only audit row in the module is the #675 conversion to public (`:1587`). This
predates W3 — no client create/update is audited — but `default_idp` is a new
field whose whole effect is to steer every user of a client to one provider
(including an inherited organization provider the tenant does not administer).

**Recommendation.** Size **S**, and probably its own issue rather than W3:
an `oauth2_client.created` / `oauth2_client.updated` audit row with the actor,
the client id and the *names* of the changed fields (and the new
`default_idp` value, which is a public provider id, not a secret). If deferred,
record it as a residual under T-494.

---

## 7. Informational

**F4-W3-06 — "byte-identical" has one stated exception.** The response to an
ignored hint equals the unhinted response *apart from the hint's own echo in
`return_to`* — which is how the tests are written (`without_echo`) and is the
T5.1 shape every unknown parameter already has, but the docs, the website, the
CHANGELOG and T-493 say "byte-identical" unqualified, and T-493 says "the SPA
receives a UUID, never a string" while the raw hint is inside `return_to`
(opaque to the page, never parsed; the SPA navigates back to it, and the
server re-resolves it). Separately, a hint long enough to push `return_to` past
`MAX_RETURN_TO_LEN` (4096) makes `build_return_to_at` fail and the request get
the no-`browser_sso` refusal instead of a hop — the one size-dependent error,
shared with any long unknown parameter, unchanged by W3. Add "apart from its
own echo in `return_to`" where the claim is made.

**F4-W3-07 — Unicode trimming.** `present()` is `str::trim`, so leading and
trailing Unicode whitespace including CR, LF and TAB is removed before
matching (`corp-okta%0A` and `%09corp-okta` resolve; probe). Interior control
characters, NUL, zero-width characters and anything the query decoder repaired
to U+FFFD are not folded and the hint is ignored. `Uuid::parse_str` accepts
hyphenated, simple, braced and `urn:uuid:` spellings (probe), as the docs say.
Nothing here reaches a URL; only the matched id does.

**F4-W3-08 — a repeated parameter is the one hint-driven error.**
`?axiam_idp_hint=a&axiam_idp_hint=b` is refused by the query extractor before
any handler code (`401 authentication_failed`), byte-for-byte as a repeated
`login_hint` is (probe). RFC 6749 §3.1 says parameters MUST NOT repeat, the
behaviour predates W3, and no value of a single hint changes the outcome; the
odd status for a malformed query is a separate, pre-existing matter.

**F4-W3-09 — PAR.** `PushedAuthorizationRequest.axiam_idp_hint` is stored as
pushed (bounded by the form limit, not `MAX_HINT_LEN`), like `login_hint`;
both are bounded at use. `peek` still reads through `find_unconsumed`, checks
the client binding, consumes nothing (`consumes == 0` in
`peek_returns_the_pushed_idp_hint_and_nothing_else`), and returns only the raw
hint, which the caller bounds and resolves exactly as the inline one. The
observable change: the provider a pushed request chose now appears in the
front channel as `idp=<uuid>` to anyone holding that `request_uri` with its
`client_id` — a tenant-public id, and the user's browser shows it anyway.
JAR stays refused (`classify_request_object` gates the peek; a `request_uri`
beside a `request` skips it, so no pushed hint is read and the query copy is
still ignored because `request_uri` is present).

**F4-W3-10 — the admin select's source.** `OAuth2ClientsPage` lists providers
from `GET /api/v1/auth/federation/providers` for the auth store's
`orgSlug`/`tenantSlug`, or, without an organization slug, from the tenant's own
enabled configs (inherited providers then absent). If the store's workspace
ever differs from the JWT's tenant, the options are another workspace's and the
server refuses the save with its `400`. Safe; a stale or "Unavailable provider
(<id>)" option is rendered as text by React.

**F4-W3-11 — cancel and the guard.** Cancelling does not call
`markAutoRedirect`, so reloading the page re-arms the redirect; a successful
password sign-in (`completeSignIn`) and a successful SSO completion clear the
guard. Consider recording the cancel for the same ten minutes — a person who
said "choose another way" once is unlikely to mean it less on reload.

---

## 8. What holds

- **Resolution is confined to the public list.** `resolve_login_idp`
  (`oauth2.rs:1199`) reads the request tenant, then `effective_providers` — the
  function `list_providers_public` maps to its response — and nothing else.
  Disabled own configs, non-inheritable organization configs and organization
  configs the tenant shadows (`override_key`, computed over *all* own configs,
  disabled included, as the listing does) are absent from the candidate list,
  so they are unnamable by UUID, slug or kind. Another tenant's provider is
  never read. Probe-confirmed for a shadowed organization UUID; pinned by
  `t493_a_hint_resolves_exactly_when_the_public_listing_shows_the_provider`
  (the "if and only if" property).
- **No cross-tenant timing signal.** With a hint or a default, the reads are
  the same four whatever the value (tenant row, own configs, organization
  tenant, organization configs); without either there are none. Matching is an
  in-memory scan of the tenant's own public list. The endpoint is rate-limited
  under its own `oauth2_authorize` bucket.
- **Only a type crosses.** `Cosmetic.idp` is `Option<Uuid>`, set only by the
  caller from a matched config's `id`; `Cosmetic::from_params` never reads
  `idp_hint`; `build_login_redirect_for` is still the only `/login` builder;
  `build_interaction_redirect` drops `idp` for `/consent`
  (`the_consent_page_never_receives_an_idp`).
- **Unresolvable is no hint, on every axis tried.** Unknown, disabled,
  non-inheritable, shadowed, foreign (slug and UUID), random UUID, URL,
  over-long, blank, non-UTF-8, NUL, zero-width, embedded control characters,
  ambiguous slug-vs-UUID, ambiguous kind, generic kind, case-folded slug — all
  byte-identical bar the echo (tests plus probes). An ignored hint never turns a
  302 into an error and never suppresses the client default; a datastore
  failure degrades to the chooser.
- **Precedence cannot surprise an operator.** UUID and slug are one tier and a
  collision is ambiguous, not settled by order; a slug beats a kind name in
  every ASCII case; the kind tier accepts only the five branded kinds
  (`!uses_slug()`), never `generic_*`; ambiguity in the kind tier is ignored;
  only effective slugs veto the kind tier, so the outcome reveals nothing the
  listing does not. Slugs are validated lower-case, and the fold is
  ASCII-only (`\u{ff47}oogle` is refused).
- **Lanes.** The hint is read on `ignore`, `honour` and `fapi2` alike (D-N22);
  `axiam_idp_hint` is not in `present`, so it can neither make a `fapi2`
  request refusable nor count as an inline parameter beside `request_uri`, and
  it never sets a parse error on the honour lane.
  `prompt=none` is answered before any hop is built, so it never hops; a live
  session issues without a sign-in URL (`with_a_live_session_the_hint_is_moot`).
- **PAR.** Pushed copy authoritative, query copy beside `request_uri` ignored
  (`a_pushed_hint_is_honoured_and_a_query_copy_beside_it_is_not`); `peek`
  remains a non-consuming read bound to tenant and client (F4-W3-09).
- **`default_idp`.** One validator, `validate_default_idp`, on create and on
  every update that sets an id (`Some(Some(_))`); `Some(None)` clears;
  omitted leaves the stored value (the field has no cross-field interaction,
  so the patch value *is* the merged value). Foreign, disabled,
  non-inheritable, shadowed (probe) and nonexistent ids are one indistinct
  `400`, so the admin API is not a cross-tenant provider oracle either. The
  write is under `oauth2_clients:create` / `:update`. DCR (`dcr.rs:641`) and
  CIMD (`cimd.rs:579`) construct `default_idp: None` and have no member for
  it; RFC 7592 has no path that writes it. A stale default is ignored
  byte-identically (`a_default_whose_provider_was_disabled_is_ignored_byte_identically`).
  The admin form sends the field only when changed, so an unrelated edit is
  never blocked by a stale default.
- **The SPA cannot be steered off the list.** `idp` passes a strict UUID regex,
  is only ever compared with ids from the loaded listing, and never builds a
  URL; the start call is the same protocol-generic one the buttons use; the
  delay is behind a focused, labelled cancel in a polite live region; StrictMode
  starts once (`autoStarted` ref); `sessionStorage` failures are caught on every
  access and degrade to "no guard" without breaking the page (probe).
  `return_to` handling is unchanged.
- **Docs and threat model.** Every test name T-493 and T-494 cite exists and
  asserts what it is cited for; the OpenAPI matches the handlers; the website
  links out for the normative detail. The inaccuracies are F4-W3-01, -02, -04
  and -06.

---

## 9. Needs a maintainer decision

1. **F4-W3-01** — fix the SSO leg's return to `return_to` inside W3 (this
   review's recommendation: the headline flow does not complete without it), or
   merge W3 with the four texts corrected and track the fix separately.
2. **F4-W3-03** — on a `reauth=1` hop: (a) do not auto-start, or (b) forward
   `prompt=login`/`max_age=0`/`ForceAuthn` upstream. Recommendation: (a) now,
   (b) as a follow-up that also benefits the manual button.
3. **F4-W3-05** — audit client create/update (with `default_idp`) in this
   plan, or record the gap as a T-494 residual and open an issue.

---

## Addendum 1 — sweep 1 re-check (2026-10-31)

**Against:** `a151491..d1c6f40` on `claude/social-gap-w3`. The commits are
`b42318c` (#832, F4-W3-01; D-N25), `30f5b84` (#833, F4-W3-02 … 04 and 06 … 11;
D-N26) and `d1c6f40` (#834, F4-W3-05; D-N27). The range touches 21 files and
adds about 1 240 lines. I re-checked each finding against the code, not
against the commit messages, and read the new code for what it adds. Two
throw-away probes ran and were kept out of the tree (below). The following
were run and were green (exit 0):

- `cargo test -p axiam-oauth2 --lib -- authn_params par:: login_hop`: 70 passed,
  including `the_shared_idp_hint_bound_trims_unicode_whitespace_and_matches_the_parse`.
- `cargo test -p axiam-api-rest --no-default-features --test oauth2_idp_hint_test`:
  19 passed (20 with the probe), including
  `t494_client_writes_are_audited_by_field_name_and_never_carry_a_secret` and
  `a_repeated_hint_is_refused_like_a_repeated_login_hint`.
- `cargo test -p axiam-api-rest --no-default-features --test par_test`: 31 passed,
  including `a_pushed_idp_hint_is_bounded_at_push_time_and_never_refused`.
- `npx vitest run LoginPageIdpHint.test.tsx SsoCallbackPage.test.tsx ssoLogin.test.ts OAuth2ClientsPage.test.tsx`:
  4 files, 121 passed.
- `scripts/check-crate-layering.py`: OK, 19 crates, 62 edges.
- `scripts/check-spec-digest.py`: OK. The range changes no OpenAPI-visible
  shape (the handlers gained an `HttpRequest` extractor only).
- `cargo fmt -p axiam-oauth2 -p axiam-api-rest -- --check`: clean.

**Probes.** (1) REST, appended to `oauth2_idp_hint_test.rs` and then removed:
a `PUT` of `grant_types` alone is audited as `["grant_types"]`; one of
`redirect_uris` alone as `["redirect_uris"]`; re-sending the same redirect
URIs in another order also lists `redirect_uris` (a false *positive*, harmless);
re-setting `default_idp` to its current value lists nothing and does not
restate the value. (2) SPA, a temporary `F4Probe.test.tsx`, then deleted: with
`return_to` carrying `max_age=00`, `max_age=%2B0`, `max_age=%200`,
`prompt=consent%09login` or `prompt=consent%0Alogin`, the page **auto-starts**
the provider; with `prompt=login` it does not (F4-W3-14).

### A.1 Verdicts

| ID | Verdict | Evidence |
|---|---|---|
| **F4-W3-01** | **Closed** | `handleSsoSelect` (`LoginPage.tsx:552`) stores the hop only when `sanitizeReturnTo(returnTo)` accepts it, together with the sanitised `acr`, requested locale, `display` and `login_hint`, and never `idp` or `reauth`. `takePendingSso` (`ssoLogin.ts:180`) removes the record before parsing and runs every field back through its own sanitiser (`revalidateHop`, `:161`); a `returnTo` that fails discards the whole hop. On success `SsoCallbackPage` calls `resumeLoginHop(pending?.hop?.returnTo, …)` (`:126`), which sanitises a third time immediately before `window.location.assign`, and falls back to `/dashboard`. On failure the link is `loginHopRetryPath(hop)` (`:163`), which sanitises a fourth time and builds `/login?return_to=…` without `idp`/`reauth`; `LoginPage` sanitises again on load. So `return_to` passes the same sanitiser at every read and right before every navigation. All four completions (OIDC and OAuth2 redirects, SAML and Apple handoff) share the one success tail. Tests: `resumes the hop after %s`, `goes to the dashboard when the sign-in was not started from a hop`, `rejects a tampered stored return_to and goes to the dashboard`, `after %s, Back to sign in keeps return_to and drops idp`, `drops the whole hop when the stored return_to is %s`. **Planting** — see A.3 below. |
| **F4-W3-02** | **Closed** | `loads no providers and starts nothing from ?%s=` pins `?org=`, `?org=&tenant=` and `?tenant=` (no providers request, no start, no `assign`). The `LoginPage` comment, `docs/admin/oidc-authn-parameters.md` ("The person names the workspace first") and T-493 state the rule and why it is load-bearing, and say any future binding must be server-side. |
| **F4-W3-03** | **Closed as decided (D-N26 (a))**, with a gap on PAR (F4-W3-12) | `freshAuthRequired` (`LoginPage.tsx:251`) is `reauth=1`, a sanitised `acr`, or `demandsFreshLogin(returnTo)`. When true, `autoProvider` is `null` and the hinted provider is only `suggested` (a ring on the button); the start needs a click. Forwarding upstream stays a later item, as decided and as the docs say. The SPA-side detection of `prompt`/`max_age` is the executor's extension (verdict in A.2). It cannot see a pushed request (F4-W3-12), and it reads spellings differently from the server (F4-W3-14). |
| **F4-W3-04** | **Closed** | `sso_error` is gone (no occurrence in code); `error`/`error_description` remain, labelled defence in depth, and the test is renamed to say so. `follows SsoCallbackPage's own failure link and does not start again` exercises the real path. T-493, the docs' "No loop" bullet and the `ssoLogin.ts` guard comment name the operative guards. One stale copy remains in `claude_dev/frontend-coverage-matrix.md` (F4-W3-15). |
| **F4-W3-05** | **Closed (D-N27: audit in this wave)** | `oauth2.client_created` / `_updated` / `_deleted` (`oauth2_clients.rs:1071`, `:1569`, `:1843`) through `audit_client_write` (`:1685`), after the write and only on success. Every early return in `update` (`?` and the `422` paths) is before `update_if_unchanged`, and nothing between the write and the audit can return, so no successful write escapes the row. `changed_client_fields` (`:1719`) compares the stored row (the one the conditional write was keyed on) with the row the repository returned; I checked it against every field of `OAuth2Client` (`axiam-core/src/models/oauth2_client.rs`): all 23 mutable registration members are compared, and only the immutable ones, the bookkeeping timestamps and `client_secret_hash` are not. No false negative: `default_idp` set→other, set→`null` (recorded as `null`), grant types and redirect URIs are all listed (test plus probe). **Metadata**: create records `client_id`, `name`, `grant_types`, auth method, profile and `default_idp`; update records names only plus `default_idp`'s new value when it moved; delete records `client_id`, `name`, `managed_by`. No secret, no hash, no redirect URI, key set or DN. The test asserts that neither the one-time secret nor the stored hash appears in any row. Only DCR, RFC 7592 and CIMD stay on their own rows, as stated. |
| **F4-W3-06** | **Closed** | "apart from the hint's own echo inside `return_to`" is in T-493, the docs, the website and the CHANGELOG; the 4096-byte case is stated. |
| **F4-W3-07** | **Closed** | `bound_idp_hint` (`authn_params.rs:530`) documents `str::trim` and is pinned by `the_shared_idp_hint_bound_trims_unicode_whitespace_and_matches_the_parse`, which also proves that the query parse and the push-time bound agree on every case. |
| **F4-W3-08** | **Closed** | `a_repeated_hint_is_refused_like_a_repeated_login_hint` compares full snapshots, including a repeat of two listed providers. Documented. |
| **F4-W3-09** | **Closed** | The push bound is applied before storage (`par.rs:293`), and the use-time bound is unchanged (the authorize handler still parses the peeked value through `authn_params`), so the bound is applied twice and agrees. `peek` still consumes nothing. Its rustdoc now says what reaches the front channel, and the claim is right: a PAR `return_to` carries only `client_id`, `request_uri` and the marker, so the pushed string is never echoed. |
| **F4-W3-10** | **Closed** | The admin help text says the list is a convenience and the server decides; T-494 says the same. |
| **F4-W3-11** | **Closed** | The cancel calls `markAutoRedirect` (`LoginPage.tsx:919`) before hiding the countdown; `records the cancel, so a reload does not restart the countdown`. The ten-minute TTL keeps it a convenience, never a lockout. |

### A.2 The executor's choices beyond the brief

1. **Re-authentication detection also covers a step-up `acr` and a `return_to`
   with `prompt=login` or `max_age=0`; an ordinary `max_age` still
   auto-starts.** **Accepted.** Reading the server's own request to suppress an
   automatic action can only make the page *more* conservative: a wrong reading
   costs a click and never a token, and the server stays the judge of
   freshness. Excluding an ordinary `max_age=N` is right: with no AXIAM
   session, any sign-in is "fresh" by AXIAM's clock. The residual (upstream
   `auth_time` is not propagated, so `auth_time` is AXIAM's) is the same
   later forwarding item, and every auto-start already needs the workspace
   step, which shows someone is present. Two limits. On PAR the page cannot see
   the request (F4-W3-12). The page's parse differs from the server's
   (F4-W3-14). A third side effect: a **stale-cookie** first leg also carries
   `reauth=1`, so it no longer auto-starts either (F4-W3-13).
2. **The failure link drops `reauth`.** **Accepted.** The `reauth` effect ends
   the AXIAM session and counts an attempt against the `@/lib/reauth` loop
   guard. The first visit already ended the session, and no session was made
   by the failed leg. Re-sending `reauth` would only make a person's retries
   trip the three-in-a-minute guard. The server's freshness check does not
   depend on the SPA's flag: the resumed `return_to` keeps its hop marker, so
   the return leg is answered rather than redirected again, and it is judged
   on the new session. The retry page still carries `acr` (so a step-up still
   demands its factor) and carries no `idp` (so nothing auto-starts whatever
   `freshAuthRequired` reads).
3. **`sso_error` removed from the error-parameter check.** **Accepted.** Nothing
   set it. Keeping a dead name in a guard list suggests a code path that does
   not exist, which is how F4-W3-04 arose. `error`/`error_description` stay as
   defence in depth for a hand-made link.
4. **An over-long pushed hint is stored as no hint.** **Accepted, with one
   wording nit.** The outcome is identical to the query carrier and to an
   over-long pushed `login_hint` (dropped, never refused). The *storage* is
   not identical: `login_hint` is still stored as pushed and dropped at use
   (`par.rs:283`), while the hint is now dropped before storage. That is
   stricter, and harmless. The phrases "as for an over-long pushed
   `login_hint`" (T-493) and "just as the push never refuses an over-long
   `login_hint`" (the docs) are true of the refusal. T-493's sentence order
   reads as if `login_hint` were also stored as none; that is optional to fix.
5. **Audit: only successful writes, and an audit-append failure is logged
   while the request still succeeds.** **Accepted, and consistent.** Every
   administrator audit row in `crates/axiam-api-rest/src/handlers` is written
   the same way: `if let Err(e) = audit_repo.append(..) { tracing::error!(..) }`
   after the durable write. That covers `saml_admin.rs`, `scim_targets.rs`,
   `ssf_admin.rs`, `directory.rs`, `federation.rs` (the SHA-1 opt-in, itself a
   security downgrade), `users.rs` (certificate revocation on delete),
   `ca_certificates.rs` and the #675 conversion in this same module. No REST
   admin write fails closed on audit. Failing *this* one closed would be
   worse than the precedent: the write is already committed, so a `5xx` would
   be retried as a no-op, misreport the state, and still leave no row. Real
   fail-closed auditing needs the row in the same transaction as the write.
   That is a deployment-wide design decision (ASVS V7 and ISO 27001 A.8.15 lean
   that way), not a W3 item. The `tracing::error!` carries `client_id` and the
   action only. Not auditing refused writes also matches the other
   registries. A refused write changed nothing, and the authorization layer,
   not the registry, is where denied attempts belong.

### A.3 Can the pending-SSO record be planted or steered?

The question was whether an attacker can land a victim's fresh session on an
attacker-chosen `/oauth2/authorize` request. **No new capability.** Path by
path:

- **Another tab or another origin.** The record is in `sessionStorage`, so it
  is per origin *and* per tab. Another origin cannot read or write it. Another
  AXIAM tab has its own copy. A tab opened from this one gets a snapshot at
  open time and never writes back.
- **A crafted `/login?return_to=<attacker request>&idp=…`.** The record is
  written only by `handleSsoSelect`, that is, by a click or by the auto-start
  after the person submits the workspace step. The victim then signs in, and
  the request resumed is the attacker's. That is *exactly* what the same URL
  does on the password path, where `resumeLoginHop` has resumed `return_to`
  since T23.1.3. `sanitizeReturnTo` confines the value to the four
  authorization-continuation shapes on this origin. The resumed request still
  needs a registered `redirect_uri`, a session in that client's tenant, and
  consent where the client requires it. This is the standard OAuth
  consent-phishing residual of every login hop, not something #832 adds.
- **A login CSRF into `/auth/sso/callback`.** The federated state is not bound
  to the browser: the handoff code, or `code`+`state`, of the attacker's own
  sign-in completes in any browser. So an attacker who drives the victim's tab
  there logs it in as the attacker. That is pre-existing and outside this
  range. If the tab still holds a stale hop (a provider leg the victim
  abandoned earlier in that tab), that hop is resumed under the attacker's
  session. But an attacker who already holds a session in the victim's
  browser can navigate it to *any* `/oauth2/authorize` request directly, so
  the stale hop adds nothing. Binding the hop to its start would also catch
  this case cheaply (F4-W3-16, optional).
- **One-time semantics.** `takePendingSso` removes the record before it parses
  it, so a hop is consumed by the first callback. The resume navigates to
  the server-built `return_to`, hop marker included, so the return leg is
  answered and not re-hopped, exactly as on the password path. Under PAR,
  `peek` on the anonymous leg consumes nothing, and the `request_uri` is
  consumed once, by the return leg. A retry after a failed leg resumes the same
  unconsumed `request_uri` if it has not expired, and otherwise gets the
  ordinary `invalid_request_uri`. Back-navigation to a spent request is
  refused as before. `resumeLoginHop` clears the `@/lib/reauth` counter for
  the destination exactly as the password path does, and the counter still
  counts every `reauth=1` load.

### A.4 Invariants

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 refuses ID tokens by name and by shape; its tests unchanged | **Holds** | Neither `token_exchange.rs` (`axiam-oauth2`, `axiam-federation`) nor any of their tests is in the range. |
| 2 | No refresh token from token exchange | **Holds** | No exchange code in the range. |
| 3 | `fapi2` grace unchanged | **Holds** | `fapi.rs` is not in the range. The push-time bound is silent on every lane, so it cannot make a `fapi2` push refusable. |
| 4 | Crate layering | **Holds** | "19 crates, 62 internal production edge(s), all pointing inward; 4 declared test-only inversion(s)". |
| 5 | `missing_docs` on `axiam-authz` / `axiam-directory` | **Holds (untouched)** | Neither crate is in the range. The new public items (`bound_idp_hint`, the three action constants) are documented anyway. |
| 6 | Spec current | **Holds** | Digest matches; no schema-visible change. |
| 7 | Threat model and docs cite real tests | **Holds** | Every name in the T-493 and T-494 amendments was looked up in the tree (`grep`) and its assertions read: the four Rust tests, the six `LoginPageIdpHint` cases, the four `SsoCallbackPage` cases and the two `ssoLogin` cases. |

### A.5 New findings

| ID | Severity | Where | Finding | Fix |
|---|---|---|---|---|
| **F4-W3-12** | Low | `LoginPage.tsx:122`, `:251`; `oauth2.rs:1127` (the anonymous leg passes `acr = None`); `ParService::peek` | Under PAR, the anonymous first leg carries no sign that the pushed request asks for `prompt=login`/`max_age=0`, so the page auto-starts and an upstream session answers silently. That is the F4-W3-03 shape on exactly the clients most likely to ask for it (`fapi2` is PAR-only). | S |
| F4-W3-13 | Info | `oauth2.rs:1127` (`stale` → `reauth=1`); `docs/admin/oidc-authn-parameters.md` ("Not on a re-authentication") | `reauth=1` also means "a stale session cookie was presented" on the first leg. The page now treats that as a re-authentication and does not auto-start, so a returning user whose cookie outlived the server session loses the headline redirect. The docs list only `prompt=login`/`max_age`/`acr_values` as sources. Fails safe. | XS–S |
| F4-W3-14 | Info | `LoginPage.tsx:122` | The page's `prompt`/`max_age` reading is not the server's. The server splits `prompt` on ASCII whitespace and parses `max_age` as a trimmed `u64` (`00`, `+0`, ` 0` are all `0`); the page splits on a space and compares with `"0"`. Probe: `max_age=00`, `%2B0`, `%200`, `prompt=consent%09login`, `consent%0Alogin` all auto-start. Only the relying party chooses the spelling, so nobody gains from it. | XS |
| F4-W3-15 | Info | `claude_dev/frontend-coverage-matrix.md:38` | Still describes the guard as `error`, `error_description`, `sso_error` "on a failed SSO leg" — the description F4-W3-04 corrected everywhere else. | XS |
| F4-W3-16 | Info | `ssoLogin.ts` (`PendingSso`); `SsoCallbackPage.tsx` | The stored hop is not bound to the start it belongs to, so any callback in the tab consumes it, including a login-CSRF one (A.3). Optional hardening. | XS |

**F4-W3-12 (Low) — PAR hides the fresh-login demand from the page.**
*Scenario.* A `fapi2` (PAR-only) relying party pushes `prompt=login` (or
`max_age=0`) with `axiam_idp_hint`, or it has a `default_idp`. The browser has
no AXIAM session. `resolve_authorize_principal` builds the first-leg hop with
`reauth` false (no stale cookie) and `acr = None`. The `return_to` is
`/oauth2/authorize?client_id=…&request_uri=…` plus the marker, so
`demandsFreshLogin` has nothing to read. The page auto-starts the provider
1.5 s after the workspace step. The provider still holds a session, so it
answers at once. AXIAM mints a session with `authenticated_at = now`, and
the return leg satisfies `prompt=login`/`max_age=0`: the relying party gets
an `auth_time` for a sign-in at which nobody presented a credential. The docs
state the PAR limitation ("only `reauth` and `acr` mark the hop"). T-493's
"No unattended re-authentication" sentence does not.

*Recommendation.* Fix size **S**: have the **server** mark the hop. The
server is the only party that can see both carriers. Add a typed flag to
`Cosmetic` (or a third value of `reauth`), set on the anonymous leg when the
effective request asks for `prompt=login` or `max_age=0`. For PAR, widen
`PeekedRequest` by one `bool`, which keeps `peek`'s "nothing that
authorizes" property. Drop `demandsFreshLogin`'s parsing of `return_to`, and
F4-W3-14 goes with it. If deferred, add the PAR caveat to T-493 as a
residual.

**F4-W3-13 (Info) — a stale cookie now suppresses the auto-redirect.** The
first leg sets `reauth=1` when a presented `axiam_op_session` resolves to no
session (`oauth2.rs:1127`). Since #833, `reauth=1` means "never auto-start".
That is safe, but it drops G-B's flow for every user whose cookie outlived
the server session: idle expiry, revocation, a server-side logout that did
not reach this browser. The relying party asked for nothing here, so nothing
in D-N26 calls for the suppression. *Recommendation.* XS if the page keys
suppression on the server's own fresh-authentication marker from F4-W3-12 and
not on `reauth`. Otherwise, accept it and add "or a stale session cookie" to
the docs' list of what `reauth=1` means.

**F4-W3-14 (Info) — two parsers of one value.** See the table. The divergence
only ever makes the page *start* where the server would demand fresh
authentication, never the reverse. *Recommendation.* XS: mirror the server
(split on `/[\t\n\f\r ]+/`; trim, then `/^\+?0+$/`), or remove the parse
through F4-W3-12.

**F4-W3-15 (Info) — stale coverage matrix.** Reword the `auth` row to match
T-493: the failure link carries no `idp`; the `sessionStorage` guard, now
also written on cancel; one start per load; the workspace step; `error` and
`error_description` as defence in depth.

**F4-W3-16 (Info, optional) — bind the stored hop to its start.**
`oidc/start` and `oauth2/start` return the `state`, so the record could keep
it, and `SsoCallbackPage` could resume the hop only when the callback's
`state` equals it. For a handoff, it could resume only when the record's
`federation_config_id` matches the provider the completion reports, or it
could accept the handoff case as is. When they differ, complete the sign-in
but land on the dashboard. This stops a foreign or stale callback from
consuming a hop. It costs nothing on the normal path, and it leaves a browser
whose storage is disabled exactly where it is today. It does not fix the
underlying unbound-state login CSRF, which is a pre-existing, separate matter.

### A.6 Needs a maintainer decision

- **F4-W3-12:** fix it in W3 by having the server mark the anonymous hop when
  the inline *or pushed* request demands fresh authentication (recommended;
  it also settles F4-W3-13 and F4-W3-14), or record the PAR gap as a T-493
  residual next to the upstream-forwarding item.
- **Audit failure policy (A.2 item 5):** no change recommended for W3. Whether
  any administrator write should fail closed on audit (which needs the row
  written in the write's transaction) is a deployment-wide question. If it is
  wanted, it belongs on the roadmap, not in this wave.

F4-W3-01 … 11 are closed. Nothing here is High or Medium.

## Addendum 2 — sweep 2 re-check (2026-10-31)

**Against:** `a15573e..4588b12` on `claude/social-gap-w3`, the one commit
`4588b12` (#835; F4-W3-12 … 16; D-N28, D-N29). The range touches 21 files and
adds about 920 lines. As before, every finding was re-checked against the code,
not the commit message, and the new code was read for what it adds. Two
throw-away probes ran and were kept out of the tree (below). The following
were run and were green (exit 0):

- `cargo test -p axiam-oauth2 --lib`: 659 passed, including every `honour::`
  test, `fresh_authentication_is_prompt_login_or_max_age_zero_in_any_spelling`,
  `peek_reports_a_pushed_fresh_authentication_demand_as_a_bool`,
  `the_fresh_authentication_marker_is_appended_last_and_only_when_set` and
  `the_fresh_authentication_marker_never_reaches_the_consent_page`.
- `cargo test -p axiam-api-rest --no-default-features --test oauth2_honour_lane_test --test oauth2_idp_hint_test --test par_test`:
  42 + 19 + 31 passed, including the three `d_n28_*` tests.
- `cargo test -p axiam-api-rest --no-default-features --test oauth2_cosmetic_params_test --test federation_login_providers_test`:
  10 + 54 passed (55 with the probe), including `a_handoff_code_buys_exactly_one_session`.
- `cargo test -p axiam-api-rest --no-default-features --lib federation_login`:
  11 passed, including `a_cross_site_return_carries_the_start_state`.
- `npx vitest run LoginPageIdpHint.test.tsx SsoCallbackPage.test.tsx ssoLogin.test.ts`:
  3 files, 87 passed (89 with the probe).
- `scripts/check-crate-layering.py`: OK, 19 crates, 62 edges.
  `scripts/check-spec-digest.py`: OK (no OpenAPI-visible change).
  `cargo fmt -p axiam-oauth2 -p axiam-api-rest -- --check`: clean.

**Probes.** (1) REST, appended to `federation_login_providers_test.rs` and then
removed: start a plain-OAuth2 sign-in with
`redirect_uri=…/auth/sso/callback?keep=1`, then post the form callback with
that `state` and `error=access_denied"<x`. The answer is `303` to
`…/callback?keep=1&error=provider_error&state=<the start state>` (the error is
sanitised, the URI's own query is kept, the value is encoded). Replaying the
same `state` afterwards is `401` on the form callback with an `error`, `401`
with a `code`, and `401` on the SPA's JSON `oauth2/callback`: the echoed value
is spent everywhere it could be redeemed. The `303` carries
`Cache-Control: no-store` but **no** `Referrer-Policy` (F4-W3-19). (2) SPA, a
temporary `describe` in `LoginPageIdpHint.test.tsx`, then removed: an
interaction hop `/login?return_to=…prompt=login…&reauth=1&idp=<id>` (and the
same with `acr=urn:axiam:acr:mfa` in place of `reauth=1`) starts nothing. But
the page rewrites its URL to `?return_to=…&idp=<id>`, and rendering that URL
again (a reload) **auto-starts** the provider after the workspace step
(F4-W3-17).

### B.1 Verdicts

| ID | Verdict | Evidence |
|---|---|---|
| **F4-W3-12** | **Closed as decided (D-N28)** | The server marks the hop. `AuthnRequestParams::demands_fresh_authentication` (`authn_params.rs:504`) is `max_age == Some(0) \|\| prompt ∋ Login`. It is applied to the query copy on the anonymous leg (`oauth2.rs:1149`, which now also parses `max_age`; `parse` records an error and carries on, and this arm reads no `parse_error`, so the extra field changes nothing else on the leg). For the pushed copy it is applied inside `ParService::peek` (`par.rs:436`), which returns one `bool` and still consumes nothing (the test asserts `consumes == 0` for every case). Carrier selection follows RFC 9126 §4: beside a `request_uri` only the pushed copy counts, and a query `prompt=login` next to it does not mark (tested). The marker is set on the honour lane only, on the first leg only (`oauth2.rs:2275` sets `false` on the interaction hop), never on `/consent` (`build_interaction_redirect` drops it), and appended last, so an unmarked URL is the G-B URL byte for byte. The page holds the start on `fresh=1` and keeps it in the address bar. **Lane rule, gap check.** A `fapi2` client can never be on the honour lane (`fapi.rs`, `m1_m6_fapi_plus_honour_is_refused_at_creation` / `_on_update`), and its `prompt`/`max_age` are refused, so no `fapi2` token ever answers a fresh-login demand. On `ignore`, `prompt=login`/`max_age` are dropped: even a live AXIAM session would be reused silently, so an auto-start there asserts nothing the lane promised. The docs' table says exactly this ("Not set on the `ignore` lane or for `fapi2` clients"). One behaviour moved: sweep 1's SPA parse held the start for an *inline* `prompt=login` on any lane, and now an `ignore`-lane client's inline `prompt=login` auto-starts. That is consistent with the lane and documented. **Accepted.** Correction to Addendum 1: F4-W3-12's scenario named `fapi2`. The real exposure was an honour-lane client using PAR (optional or `require_par`), because a `fapi2` request carrying `prompt`/`max_age` is refused. The fix covers exactly that client. Residual: F4-W3-17. |
| **F4-W3-13** | **Closed (accepted and documented)** | `docs/admin/oidc-authn-parameters.md` now has a table of marks. `reauth=1` is (a) the stale-cookie first leg, (b) every honour-lane interaction hop (checked against `Reason::requires_reauthentication`, which is everything but `ConsentRequired`), and (c) the CIBA step-up link (`ciba.ts:112`). The table states that case (a) also gets click-to-start, and why the page cannot tell (a) from (b). The `LoginPage` comment says the same. Fails safe. |
| **F4-W3-14** | **Closed** | `demandsFreshLogin` is gone (no occurrence under `frontend/src`). There is one parser, the honour lane's own. `honour::evaluate` now calls the shared predicate (`honour.rs:320`): `A \|\| (L \|\| C \|\| S)` became `(A \|\| L) \|\| (C \|\| S)`, with `A` the unchanged `max_age_is_login` (`== Some(0)`, `:287`). That is the same boolean, `max_age_is_login` keeps its other use (the `prompt=none` refusal), and every honour, lane and cosmetic test is green. F4-W3-14's probe spellings (`00`, `+0`, ` 0`, tab, newline) now mark the hop at the REST level (`d_n28_an_inline_fresh_authentication_demand_marks_the_first_leg`). The page auto-starts on them only when the server did not mark the hop (`auto-starts when only return_to says %s`). |
| **F4-W3-15** | **Closed** | The coverage-matrix `auth` row now describes the operative guards (no `idp` on the failure link, the guard written on start and cancel, one start per load, the workspace step, `error`/`error_description` as defence in depth), the three marks, and the D-N29 binding. `sso_error` has no occurrence in code or docs outside this review. |
| **F4-W3-16** | **Closed as decided (D-N29)** | The record is written only after the start answers (`LoginPage.tsx:558`), with `start.state` or SAML's `relay_state`. A failed start leaves no record (tested). `takePendingSso` bounds the stored value (non-empty string, ≤ 512 characters) and removes the record before parsing. `hopForCallback` (`ssoLogin.ts:229`) returns the hop only if both values are present and equal. Otherwise the sign-in still completes and lands on `/dashboard`, and the failure link is a bare `/login`. All four arrivals carry the value: the OIDC/OAuth2 provider redirect, and on the server's side the SAML and Apple handoff and Apple's form-post error (`spa_return_target`, `federation_login.rs:73`). A login CSRF or stale callback can therefore no longer resume a hop the person left behind. The underlying unbound federated state is open item (3). |

### B.2 The new `state` on the cross-site returns

I scrutinised the server change on its own, because it is the only part of
#835 that puts a new value into a URL.

- **Never live when echoed.** There are exactly three call sites, and each
  runs after the atomic `consume_login_state`, which does SELECT + DELETE in one
  transaction (`federation_login_state.rs:100`). The Apple success path calls
  `mint_handoff_and_redirect` with `&f.state` after `:898`. The Apple error path
  calls `redirect_with_error` with `&f.state` after the same consume ("consumed
  whatever the outcome"). SAML calls `mint_handoff_and_redirect` with
  `relay_state` after `:1040`. Every failure *after* the consume (workspace,
  config, assertion or code verification, origin check, reactor veto) returns
  an API error, not a redirect, so it echoes nothing. The echoed string is the
  form's own value, which matched the row byte for byte. Probe (1) confirms
  that a replay is `401` on all three redemption endpoints. The value keys no
  other table: the nonce and PKCE verifier are separate fields of the row, and
  SAML replay protection keys on the assertion.
- **Leakage.** The value is not new to the browser. While it *was* live, it
  already sat in the provider URL (Apple's `state`, SAML's `RelayState`), in
  history, and at the provider. Now it reappears spent, beside a handoff code
  that *is* live and is protected as before: `SsoCallbackPage` calls
  `replaceState(…, pathname)` before redeeming, which removes `state` with it.
  The success `303` sends `Referrer-Policy: no-referrer`. The error `303` does
  not (pre-existing, F4-W3-19); there the URL holds only a sanitised error code
  and the spent value. Server logs: the `info!` line logs no URL. An access log
  of the SPA route records the same query that already held the handoff code.
  The value is a random 256-bit correlator with nothing behind it.
- **Replay or completion.** It can complete nothing (see above). The SPA uses
  it only for an equality test that can *withhold* a hop and never grant one.
  An attacker's own handoff URL carries the attacker's `state`, which does not
  match the victim's record, so the hop is withheld. That is the intended
  effect.
- **The handoff exchange.** It is unchanged. `sso_handoff_public` takes the code
  alone. Its single use, 60-second TTL, hash-only storage and redirect-origin
  confinement are untouched (`a_handoff_code_buys_exactly_one_session`
  passes). The exchange is not bound to `state`, so its security is neither
  better nor worse (open item 3).
- **Dispatch on the callback.** The page checks `error` first, then
  `axiam_handoff`, then `code && state`. A handoff URL now has `state` but no
  `code`, so it can never be misrouted to `completeOidc`/`completeOauth2`.

**Verdict:** sound. It leaks nothing that was not already exposed while live,
and it changes no credential's security. It needs one parity fix (F4-W3-19)
and one contract note (F4-W3-18).

### B.3 The executor's open items

1. **A reload after `reauth=1`/`acr` is stripped can auto-start.** The
   finding is **confirmed** by probe (2) and filed as **F4-W3-17 (Low)**. The
   *interaction* hop carries `idp` (`oauth2.rs`, the G-B arm) and never
   `fresh`. `LoginPage`'s strip effect deletes `reauth` and `acr`
   (`LoginPage.tsx:294`) and keeps `idp`, so the reloaded URL has no mark.
   After the workspace step the page auto-starts. An upstream session answers,
   and the return leg is judged on a session dated now. For `prompt=login`,
   `max_age=0` and an unmet `max_age`, that is the D-N26 outcome (a fresh
   authentication nobody performed) behind one reload. For a step-up `acr` it
   only loops back to another hop, because the federated session does not
   carry the factor. Severity matches F4-W3-03 (Low): it needs the person to
   reload and re-enter the workspace, and it yields presence at AXIAM but no
   credential. It is not pre-W3: it entered with #833 in this wave. The
   existing test `stays quiet on reload: the page strips reauth but keeps fresh=1`
   covers only a URL carrying both marks, which the server never builds (the
   interaction hop never has `fresh`). **Should be fixed. Size XS.**
   Preferred: when the strip effect removes `reauth` or `acr`, set `fresh=1` in
   their place. The page keeps its own "hold the start" state across a reload,
   the provider stays highlighted, and `fresh` already has exactly this meaning
   for the page. The alternative, deleting `idp` along with them, also closes
   it but loses the highlight. Either way, add `reauth=1`-only and `acr`-only
   cases to the reload test.
2. **CONTRACT §12 does not mention `state` on the handoff redirect.** Filed
   as **F4-W3-18 (Info)**. The change is additive. An SDK that reads
   `axiam_handoff` keeps working. An SDK that binds its callback to its own
   start (the right thing to do) now *can* on SAML and Apple. No reasonable
   SDK reads `state` on a handoff URL in a way this breaks. It **should** be
   a CONTRACT change in W4, but it is not a blocker for W3. Add a sentence to
   §12.3 rule 12: "the redirect also carries `state`, the value the start
   operation returned (`state`, or SAML's `relay_state`), already spent; an
   SDK MAY compare it with the value it stored to bind the return to its own
   start, and MUST NOT redeem or forward it". State the same for the
   form-post `error` redirect. Bump the contract minor version and re-sync
   the eleven SDKs with the next contract sync. Optionally say it in the two
   `303` response descriptions in OpenAPI too, which changes the spec digest.
3. **Federated state is not bound to the browser (login CSRF).** It
   **predates W3 and is outside it. Severity Low.** An attacker who drives a
   victim's tab to the callback with the attacker's own handoff code or
   `code`+`state` signs that tab in as the attacker. D-N29 removed the one
   way W3 made this worse (resuming the victim's stale hop under the
   attacker's session). What remains is the classic login CSRF, at the same
   level as before W3. **It needs its own issue, not a W3 change.** Suggested
   shape: set a `__Host-` cookie at the start endpoint that binds to the
   login-state row (the start is a same-origin `POST`). Check it where the
   browser comes back same-origin: at `oidc/callback`, `oauth2/callback` and
   handoff redemption. Do not check it at the cross-site form endpoints, where
   a `SameSite=Strict` or `Lax` cookie is not sent.

### B.4 Invariants

| # | Invariant | Verdict | Evidence |
|---|---|---|---|
| 1 | X4 refuses ID tokens by name and by shape; its tests unchanged | **Holds** | No `token_exchange.rs` (`axiam-oauth2`, `axiam-federation`) or test of it is in the range; `axiam-oauth2 --lib` (659) green. |
| 2 | No refresh token from token exchange | **Holds** | No exchange code in the range. |
| 3 | `fapi2` grace unchanged | **Holds** | `fapi.rs` not in the range. The marker is honour-only, and a `fapi2` client can never be on the honour lane. `peek`'s new `bool` is computed silently and refuses nothing. |
| 4 | Crate layering | **Holds** | "19 crates, 62 internal production edge(s), all pointing inward; 4 declared test-only inversion(s)". `axiam-oauth2` gained no dependency. |
| 5 | `missing_docs` on `axiam-authz` / `axiam-directory` | **Holds (untouched)** | Neither crate is in the range. The new public items are documented anyway: `demands_fresh_authentication`, `Cosmetic::fresh_authentication`, `FRESH_LOGIN_PARAM` and `PeekedRequest::fresh_authentication`. |
| 6 | Spec current | **Holds** | The digest matches. The new handler parameter is internal, and the `303` descriptions are unchanged (see F4-W3-18 for the optional wording). |
| 7 | Threat model and docs cite real tests | **Holds** | Every test name in the T-493 amendment, `docs/admin/*`, the coverage matrix and the CHANGELOG delta was looked up in the tree: 9 Rust and 18 frontend titles. The other back-ticked identifiers are module or parameter names, not tests. The docs match the code on the carrier, the lane, first-leg-only, no `/consent`, appended last, and the `reauth=1` sources. One statement is incomplete: "keeps `fresh` in the address bar so a reload stays quiet" is true of a `fresh` hop but not of a `reauth`/`acr` hop (F4-W3-17). |

### B.5 New findings

| ID | Severity | Where | Finding | Fix |
|---|---|---|---|---|
| **F4-W3-17** | Low | `LoginPage.tsx:276–296` (strip effect), `:247` (`freshAuthRequired`) | A reload of an interaction hop (`reauth=1` or a step-up `acr`, which carries `idp`) loses the mark, because the page strips it from the URL and keeps `idp`. The reloaded page auto-starts the provider (probe 2), which is D-N26's unattended re-authentication behind one reload. | XS: when the strip effect removes `reauth`/`acr`, write `fresh=1` (or drop `idp`); add the two single-mark reload cases; amend the T-493 sentence. |
| F4-W3-18 | Info | `sdks/CONTRACT.md` §12.3 rule 12 | The SAML/Apple handoff redirect and the form-post error redirect now carry the spent start `state`. The contract does not say so, and SDKs cannot rely on it for binding. | XS, W4: one paragraph and a minor contract bump; downstream re-sync. |
| F4-W3-19 | Info | `federation_login.rs:1165` (`redirect_with_error`) | The form-post error `303` sends `Cache-Control: no-store` but not `Referrer-Policy: no-referrer`, which the success `303` sends. It is pre-existing. The URL now also holds the spent `state`, so nothing live leaks, but the two exits of one endpoint should match. | XS: add the header. |

### B.6 Final status of every W3 finding

F4-W3-01 … 16 are **closed**:

- 01, 02, 04, 06 … 11, 14, 15 and 16 are fixed.
- 03 and 12 are closed as decided (D-N26, D-N28). The upstream forwarding of
  `prompt`/`max_age`/`ForceAuthn` remains a later item, as decided.
- 05 is fixed by auditing in this wave (D-N27).
- 13 is accepted and documented.

Open: **F4-W3-17 (Low, XS)**, which should be fixed before the merge or as the
first W4 item. **F4-W3-18 (Info)** is a W4 contract note. **F4-W3-19 (Info,
XS)** can be fixed in any later commit. Outside W3, the browser-unbound
federated state (login CSRF, pre-existing, Low) needs its own issue. Nothing
in this review is High or Medium.
