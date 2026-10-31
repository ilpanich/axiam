# Standard-lane OpenID Connect parameters (`authn_request_params`)

**Waves W4 and W5 of [`claude_dev/basic-op-gap-plan.md`](../../claude_dev/basic-op-gap-plan.md)
§4.2–§4.6.** Sits beside [the browser login hop](browser-login-hop.md) and
[FAPI 2.0 profile and mTLS](fapi2-profile.md): three per-client switches on the
same registration, each defaulting to what an AXIAM client already was.

---

## What problem this solves

OpenID Connect Core §3.1.2.1 lets a relying party ask for five things that
change what a token *means*:

| Parameter | What the relying party is asking |
|---|---|
| `prompt=none` | answer without showing the end user anything |
| `prompt=login` | authenticate them again, whatever session exists |
| `max_age` | do not hand me a token minted from an authentication older than this |
| `acr_values` / `claims.id_token.acr` | tell me which class of authentication this was, and prefer this one |
| `id_token_hint` / `claims.id_token.sub` with a `value` | I believe *this* end user is present; confirm or correct me — and never give me a token for anybody else |

Until W4, AXIAM accepted all five and acted on none. That is a conformant
answer to nothing: a relying party that sent `max_age=60` and received a code
minted from a week-old login had been told a freshness guarantee it did not
get, and could not tell.

`authn_request_params: honour` makes them mean what they say. It is per client,
and the default stays `ignore`.

It also lets a relying party ask for four things that change only how the
sign-in page *looks*. W5 honours these on the same switch:

| Parameter | What the relying party is asking | What AXIAM does |
|---|---|---|
| `login_hint` | pre-fill the username field with this | fills the field; **never looks the value up** |
| `display` | lay the page out for `page`, `popup`, `touch` or `wap` | `popup` gets a compact card; everything else the default; anything outside the four is dropped |
| `ui_locales` | render the page in one of these languages | matches the list against the five AXIAM ships and renders the first requested tag that matches |
| `claims_locales` | return claim *values* in this language | accepted and ignored — AXIAM has no localised claims |

These four are never *refused*, on any lane, including `fapi2`: relying-party
libraries send `login_hint` by reflex and refusing it would break working
clients for no security gain. What they get on a lane other than `honour` is
what they have always got — nothing.

---

## Turning it on

One field on the client registration:

```bash
curl -sS -X POST https://iam.example.com/api/v1/oauth2-clients \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "Partner Portal",
        "redirect_uris": ["https://portal.example.com/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile", "email"],
        "authn_request_params": "honour",
        "browser_sso": true
      }'
```

`browser_sso` is not required, but without it the only interaction AXIAM can
perform is for a browser that already holds an `axiam_access` cookie on this
origin — i.e. a first-party application. A third-party relying party needs
both. See [the login hop guide](browser-login-hop.md).

**It cannot be set on a `fapi2` client**, on create or on update. The
registration is refused with a message naming the profile. The two settings are
two answers to the same question — *what does an authorization request from
this client mean* — and a row may hold at most one of them.

---

## What changes for a client that opts in

### The ID token grows three claims

`auth_time`, `acr` and `amr`. All three are optional members that were absent
before, so a relying party that ignores them is unaffected; a relying party
that reads them gets:

```json
{
  "auth_time": 1757238000,
  "acr": "urn:axiam:acr:1fa",
  "amr": ["pwd"]
}
```

`amr` is RFC 8176 (`pwd`, `otp`, `mfa`, `hwk`, `swk`, `user`, `x509`, `fed`).
`acr` is one of exactly two AXIAM URNs, published in the discovery document's
`acr_values_supported`:

| ACR | Means |
|---|---|
| `urn:axiam:acr:1fa` | one factor — a password, a federated assertion, a presence-only passkey |
| `urn:axiam:acr:mfa` | two distinct factors, or one possession factor the authenticator verified a human for (`mfa`; `hwk`/`swk` with `user`; `x509`) |

The vocabulary is **not configurable**, deliberately. An operator who could
configure the string could configure it to say `mfa` for a password login, and
an `acr` a relying party cannot trust is worse than none.

A client that stays on `ignore` receives none of the three, exactly as before.

### The authorization endpoint may now redirect to the sign-in page

Where the request cannot be satisfied by the session it arrives with, AXIAM
sends the browser to `/login?return_to=…&reauth=1` (and `&acr=…` when a
particular factor is needed), the user authenticates, and the authorization
request resumes. That redirect is the same hop `browser_sso` uses, with the
same `return_to` validation on both sides and the same loop guard.

### The sign-in page may be pre-filled, laid out and translated

The same redirect carries the presentation the relying party asked for:
`/login?return_to=…&login_hint=…&display=popup&ui_locale=it`.

Three things are worth an operator's attention.

**Nothing is looked up.** AXIAM never compares a `login_hint` to a user, never
uses it to select a tenant or a session, and ignores it entirely when a session
already exists. The response to a hint naming a real account and one naming
nobody is byte-identical apart from the echoed value — not because two branches
were carefully equalised, but because there is only one branch. A relying party
therefore cannot use `login_hint` to discover who has an account here.

**The raw values do not reach the browser.** `ui_locales` and `display` are
matched on the server; what travels in the redirect is a validated tag from a
list this build knows (`ui_locale=it`) or nothing at all. A `ui_locales` value
that matches nothing produces no parameter, and the page renders English.

**Five languages, translated completely:** English (default), Italian, French,
German and Spanish. The **admin console is not translated** — `ui_locales` is
an authentication-request parameter and cannot reach it. A language is either
complete or absent: a stub bundle would make `ui_locales=pt` succeed and then
deliver English, which tells the relying party its request was honoured when it
was not. There is no per-tenant default language yet; every deployment falls
back to English.

### The authorization endpoint may now refuse

| Answer | When |
|---|---|
| `login_required` | `prompt=none` with no usable session, a `max_age` an authentication cannot meet, an `id_token_hint` or a `claims.id_token.sub` value naming somebody else |
| `account_selection_required` | as above, when `prompt=select_account` was asked |
| `unmet_authentication_requirements` | an **essential** `claims.id_token.acr` the end user cannot reach — typically a request for MFA from a user with no second factor enrolled |
| `invalid_request` | a value AXIAM cannot parse (`max_age=abc`), `prompt=none` combined with another value, an authentication-request parameter on the query string beside a `request_uri` |

All of these are redirected to the relying party's registered `redirect_uri`
with `state` and `iss`. On the `ignore` lane none of them can occur: a value
AXIAM cannot parse is dropped, as it always was.

---

## Things worth knowing before you turn it on

**`max_age=0` is handled as `prompt=login`.** OIDC Core §3.1.2.1 says
`max_age=0` is equivalent to `prompt=login`, so that is what AXIAM does: the
browser is always sent to sign in again, and when it comes back the
authorization request is answered with a code whose ID token carries the new
`auth_time`. (Before D-14 it was answered `login_required`, because
the fresh sign-in was itself "zero seconds old" and failed the comparison, so a
relying party sending `max_age=0` could never sign in.) `max_age=0` together
with `prompt=none` is `login_required`: it cannot be satisfied without the
interaction `prompt=none` forbids. A positive `max_age` is unchanged: the
comparison is `elapsed >= max_age` with no leeway in the relying party's favour,
and a sign-in that still does not meet it is answered `login_required`.

**`prompt=none` is a login-status oracle, and it is audited.** A registered
relying party learns, without interaction, whether this browser is signed in.
That is inherent to the parameter; it is bounded to clients registered in the
tenant with exact `redirect_uri` matching, and every outcome is written to the
audit log as `oauth2.prompt_none.code` or `oauth2.prompt_none.login_required`
with the `client_id`. A relying party polling it every few seconds is visible
in that log:

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://iam.example.com/api/v1/audit-logs?action=oauth2.prompt_none.login_required" | \
  jq '[.items[] | .metadata.client_id] | group_by(.) | map({client: .[0], count: length})'
```

**Silent renew in a hidden iframe does not work cross-site**, and fails closed.
The `axiam_op_session` cookie is `SameSite=Lax`, so it is not sent on a
sub-frame navigation and the OP answers `login_required`. That is the same
property that defeats cross-site login-status probing. Relying parties renew
with a top-level `prompt=none` navigation or with a refresh token.

**`prompt=consent` is treated as `prompt=login` for now.** AXIAM has no consent
screen until wave W7; ignoring the parameter would be the silent downgrade this
whole lane exists to prevent, so an authentication is performed instead. No
claim asserts that consent was collected. When W7 lands, the same redirect
renders the consent screen and no relying party has to change.

**Pushed requests and the sign-in page do not combine well.** A `request_uri`
lives 60 seconds (RFC 9126 §2.2). A relying party that uses PAR *and* needs its
end users to sign in at AXIAM will see `invalid_request_uri` whenever a user
takes longer than a minute to type a password; the recovery is to push again.
A `prompt=none` inside a pushed request cannot be read before the hop is built,
so an anonymous browser is sent to sign in first and the request is then
refused rather than converted into a code — no token is ever issued behind an
interaction the relying party forbade, but the failure is not the tidy
`login_required` the inline form produces.

**`claims.id_token.sub` is answered like `id_token_hint`** (OIDC Core §5.5.1;
#520). A `claims` parameter whose `id_token.sub` carries a `value` (or
`values`) is compared, as the exact string, with the `sub` AXIAM would put in
the ID token — the user's id. A match changes nothing. A mismatch sends the
browser to sign in again, because the request can be satisfied by signing in
*as* the named user; if the sign-in still produces somebody else, or the
request carried `prompt=none`, the answer is `login_required`
(`account_selection_required` under `prompt=select_account`) and no code is
issued. An anonymous browser is sent to sign in before the value is read, so
it steers nothing until somebody has authenticated. A `sub` member that is not
`null` or an object, or whose `value` is not a string, is `invalid_request`.
`"sub": null` asks for nothing beyond the `sub` every ID token carries. A
`fapi2` client, which this lane never serves, is refused a `claims` carrying a
`sub` value with `invalid_request` — the same answer it gets for
`id_token_hint` — rather than having the constraint dropped.

**A federated sign-in is `1fa`.** AXIAM records `amr = ["fed"]` and nothing
else: what the upstream provider did to produce its assertion is the
provider's claim, not AXIAM's evidence. There is no attribute mapping for an
upstream `acr`, and adding one is deliberately not on the roadmap — it would be
the same "configure the string" problem as a configurable vocabulary.

**Sessions created before schema v55** have no recorded `amr` and are dated by
their creation. They satisfy the `1fa` floor and nothing above it, and they
never present as fresher than the row is. There is no backfill; the affected
sessions age out.

---

## Auditing what is on

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  https://iam.example.com/api/v1/oauth2-clients | \
  jq '[.items[] | select(.authn_request_params == "honour")
       | {client_id, name, browser_sso}]'
```

Any client not in that list drops all nine parameters exactly as AXIAM always
has. Those clients also produce a rate-limited `warn` when they send one, so
the server log names the relying parties that would benefit from `honour`:

```
authorization request carried OpenID Connect authentication-request parameters
that this client is registered to ignore (authn_request_params: ignore); the
request was served exactly as before. Set authn_request_params: honour to act
on them
```

---

## Choosing the provider: `axiam_idp_hint` and `default_idp`

**Wave G-B of [`claude_dev/social-login-gap-plan-2026-10-30.md`](../../claude_dev/social-login-gap-plan-2026-10-30.md)
§3.2 (#817).** Not one of the nine OpenID Connect parameters above, and not
behind the `authn_request_params` switch: it is AXIAM's own presentational
parameter, so it works for every client that sends the browser to the sign-in
page (`browser_sso: true`, or `authn_request_params: honour`). It never changes
what is issued.

A relying party that already knows which identity provider its user should use
— "Sign in with Google" in its own UI — can send the user straight there instead
of through AXIAM's provider chooser:

```
GET /oauth2/authorize?response_type=code&client_id=…&redirect_uri=…
    &code_challenge=…&code_challenge_method=S256&state=…
    &axiam_idp_hint=google
```

### What the value may be

The hint is resolved **on the server**, against the request tenant's *effective,
enabled, public* provider list: the tenant's own providers plus the
organization's inheritable ones, minus anything the tenant shadows — exactly the
list `GET /api/v1/auth/federation/providers` already shows that tenant's
sign-in page. Three forms are accepted and are tried **in this order**; the
first form that matches anything decides, and a later form never breaks an
earlier form's tie.

| Order | Form | Matching |
|---|---|---|
| 1 | The provider's **UUID** or its **`provider_slug`** (schema v52, chosen by the operator) | A UUID is compared as a UUID, so any spelling `Uuid::parse_str` accepts names the same provider. A slug is compared exactly (slugs are lower-case `[a-z0-9-]`). The two are one tier. |
| 2 | A **branded kind name**: `google`, `github`, `facebook`, `apple`, `microsoft` | ASCII case-insensitive (`Google` is `google`); nothing else is folded. Matches when **exactly one** offered provider is of that kind. |

Rules that follow from that:

- **A slug beats a kind name, in every spelling.** If an operator gave a generic
  provider the slug `google`, the hint `google` — and `Google` — name *that*
  provider, never the branded Google. A hint that equals any offered provider's
  slug ignoring ASCII case is never read as a kind name.
- **The generic kinds are not hint names** (`generic_oidc`, `generic_oauth2`,
  `generic_saml`). They name a protocol family, not a provider; name such a
  provider by its slug or id.
- **Ambiguous means ignored.** A kind two offered providers share, or a slug
  that is also another provider's id, matches nothing.
- The value is trimmed and bounded to 256 bytes (`MAX_HINT_LEN`, as
  `login_hint`); a longer value, or one that is not valid UTF-8, is dropped, not
  truncated. Trimming is Rust's `str::trim`: leading and trailing **Unicode**
  whitespace is removed, CR, LF and TAB included, so `corp-okta%0A` and
  `%09corp-okta` name `corp-okta`. Control characters, NUL or zero-width
  characters *inside* the value are not folded; such a hint matches nothing and
  is ignored. Nothing of the value reaches a URL either way — only a matched
  provider's id does.
- **A repeated `axiam_idp_hint` is refused like a repeated `login_hint`.**
  `?axiam_idp_hint=a&axiam_idp_hint=b` is rejected by the query parser before
  any hint is read, with the same response a repeated `login_hint` gets (RFC
  6749 §3.1: parameters must not repeat). It is the one way the hint parameter
  changes the outcome, and it depends on the repetition, not on any value.

### A hint that names nothing is a no-op

An unknown hint, a disabled provider, a provider that exists only in another
tenant, a URL, an ambiguous name: all are **silently ignored**, and the response
is **byte-identical** to the request without a hint *apart from the hint's own
echo inside `return_to`* — the client's `default_idp`
(below) then applies as it would have, or the ordinary chooser is shown. There is
no error and no distinguishable status, so the hint cannot be used to probe
which providers exist. This is a lookup, unlike `login_hint`'s no-lookup rule,
and that is permissible only because the list it consults is already public for
the tenant (T-493).

The echo is the one exception, and it is not new: `return_to` carries the
relying party's query string verbatim, as it carries every unknown parameter,
so the raw hint is inside it — opaque to the sign-in page, which never parses
it and only navigates back to it, after which the server resolves the hint
again. A hint long enough to push `return_to` past its 4096-byte limit turns
the hop into the ordinary refusal for a request with nothing safe to come back
to, exactly as any long unknown parameter always has.

What the sign-in page *acts on* is a type, never the string: the redirect gains
`&idp=<uuid>` (see [the browser login hop](browser-login-hop.md#the-idp-parameter)).
`idp` is never sent to `/consent`.

### Where it applies

- **Every `authn_request_params` lane** (D-N22): `ignore` and `honour` alike, and
  `fapi2` clients too, because the hint changes nothing that is issued.
- **Pushed authorization requests** (D-N23): `axiam_idp_hint` is accepted in the
  body of `POST /oauth2/par` and is **authoritative**; the authorization
  endpoint reads it from the stored request. A copy on the query string beside a
  `request_uri` is ignored (RFC 9126 §4). The push itself never refuses a hint:
  it is bounded **at push time** by the same rule as the query string (trimmed,
  `MAX_HINT_LEN`, valid UTF-8), so an over-long pushed hint is stored as no hint
  — just as the push never refuses an over-long `login_hint` — and one that
  names nothing is answered as no hint when the browser arrives. The only thing
  of the pushed hint the front channel ever sees is the id it resolved to, on
  the `/login` redirect.
- **A live session means no hop and no hint.** When the browser already holds an
  OP session the authorization endpoint answers with a code and never builds a
  sign-in URL; the hint selects nothing (the same as Keycloak).
- **Re-authentication.** The `reauth=1` hop (`prompt=login`, `max_age`, `acr_values`)
  carries the resolved `idp` like the first hop does, but the sign-in page
  **does not start it by itself** (D-N26): see below.

### `default_idp` — a per-client default

`OAuth2Client.default_idp` is the registration's answer to "which provider by
default": the sign-in page starts with it when a request carries **no
resolvable hint**. *The registration decides; the request may only choose among
what the tenant offers.*

| | |
|---|---|
| **Precedence** | A hint that resolves beats `default_idp`; `default_idp` beats the chooser. |
| **Set with** | `POST /api/v1/oauth2-clients` (`default_idp`: a federation config id) and `PUT /api/v1/oauth2-clients/{id}` (omit to leave, `null` to clear, an id to set). The admin console has a **Default identity provider** select on the client form; its options are a convenience drawn from the sign-in page's provider listing, and the server's validation below is what decides. |
| **Validation** | Must name a provider the client's tenant can sign in with — its own enabled configs or the organization's enabled, inheritable, unshadowed ones — or the request is refused with `400 validation_error` naming `default_idp`. The rule runs on **create and on the merged update path**, so a PATCH cannot set what a POST could not. |
| **A stale default** | If the provider is later disabled or deleted, the default is **ignored at the authorization endpoint** — the chooser is shown — and is never an error. The stored value is still echoed by the admin API. |
| **Dynamic registration** | Neither RFC 7591 (`dcr`) nor client ID metadata documents (`cimd`) can set it: a self-registering client does not get to choose what an operator's sign-in page does. Only the administrator API sets it. |

### What the sign-in page does with `idp`

**The person names the workspace first.** The login hop carries no organization
or tenant, so the sign-in page loads its providers only when the person submits
the workspace step — never from `?org=`/`?tenant=` and never from anything in
`return_to` — and `idp` does nothing until then. Every hinted sign-in therefore
asks for the organization first, and the redirect below begins after
**Continue**. This is load-bearing, not an omission: the page cannot tell a
server-built `/login` URL from a hand-made one, and any tenant operator on a
shared deployment controls their own provider's endpoint, so a page that loaded
providers from URL parameters would make `/login?org=<theirs>&idp=<theirs>` a
link on AXIAM's origin that sends a visitor to an operator-chosen URL with no
click (T-493). Binding the workspace to the hop, if it is ever wanted, has to be
done server-side, not through a URL parameter.

When `/login?idp=<uuid>` matches a provider the page has loaded, it starts that
provider **by itself**, for OIDC, OAuth2, SAML and Apple providers alike:

- It first shows "Redirecting to *{provider}*…" with a visible **Choose another
  way to sign in** button, and waits **1.5 seconds** (**3 seconds** when the
  person's system asks for reduced motion). Cancelling shows the ordinary
  chooser and the redirect never fires; the cancel is remembered in the tab
  like a start (below), so reloading the page does not restart the countdown.
- **Not on a re-authentication** (D-N26). When the hop asks for a fresh
  authentication — `reauth=1` (from `prompt=login`, `max_age` or
  `acr_values`), a step-up `acr`, or a `return_to` whose request carries
  `prompt=login` or `max_age=0` — the page does not start the provider: it
  highlights that provider's button and the person has to click it. AXIAM does
  not yet forward `prompt=login`/`max_age` to an OIDC provider or `ForceAuthn`
  to a SAML identity provider, so a provider that still holds a session would
  answer at once, and an unattended start would record a fresh authentication
  nobody performed. Forwarding them upstream is a later item; a provider that
  ignores them (several social providers do) cannot give a real
  re-authentication even then. Under PAR the request's `prompt`/`max_age` are
  in the pushed request rather than in `return_to`, so there only `reauth` and
  `acr` mark the hop.
- **No loop.** What stops a loop on a real failure: the failed leg ends on the
  SSO callback page, whose **Back to sign in** link carries no `idp`, so the
  page it opens has nothing to start; a relying party that restarts the request
  produces a fresh `/login?…&idp=`, which a `sessionStorage` guard suppresses
  for a provider already started (or declined) in this tab within the last 10
  minutes — recorded *before* navigating away, so Back from the provider is
  quiet, and cleared on a successful sign-in; the page starts at most once per
  load; and every start needs the person to submit the workspace step, so
  nothing repeats unattended even where storage is unavailable. The page also
  declines when `/login` carries an `error` or `error_description` parameter,
  as defence in depth only — nothing AXIAM builds puts one there. When the `idp`
  value is not a UUID matching a loaded provider, nothing starts. A start that
  fails shows the ordinary page and its error.
- **Back to the relying party** (#832). A provider sign-in started from the
  login hop — by this redirect or by a provider button on the hop page —
  carries the hop's `return_to` with it (in the tab's `sessionStorage`, as the
  value the page's own `return_to` check accepted). When the provider returns
  and AXIAM completes the sign-in (OIDC and OAuth2 redirects, and the SAML and
  Apple handoff code alike), the page resumes the authorization request, which
  then issues the code to the relying party; `return_to` is checked again
  before the browser is sent there, and a value that fails the check sends the
  user to the console instead. If the provider leg fails, **Back to sign in**
  returns to the hop's sign-in page with `return_to` (and `acr`, `login_hint`,
  `display`, `ui_locale`) but **never** `idp` and never `reauth`, so it starts
  nothing by itself and the person can choose another way.
- A hand-written `/login?idp=…` can at worst start a provider the tenant already
  shows as a button.

### Migrating from Keycloak's `kc_idp_hint`

AXIAM deliberately has **no `kc_idp_hint` alias** (D-N3): the vendor-namespace
rule that names `axiam_login_hop` applies, and a competitor's prefix does not
belong in AXIAM's API. To migrate a relying party, rename the parameter to
`axiam_idp_hint` and check the value:

- Keycloak's value is an identity provider *alias*. Give the equivalent AXIAM
  provider the same string as its `provider_slug` and the value works unchanged
  (it is matched in the first tier).
- A client that only ever hints one branded provider can send the kind name
  (`google`) and needs no slug.
- A client that always wants the same provider can drop the parameter and take
  `default_idp` instead.
- Keycloak ignores a hint it cannot resolve and so does AXIAM; there is no error
  to handle in either direction. `kc_idp_hint` sent to AXIAM is just an unknown
  query parameter and is ignored.
