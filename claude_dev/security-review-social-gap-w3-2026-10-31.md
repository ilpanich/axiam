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
