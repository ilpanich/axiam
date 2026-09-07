# Standard-lane OpenID Connect parameters (`authn_request_params`)

**Wave W4 of [`claude_dev/basic-op-gap-plan.md`](../../claude_dev/basic-op-gap-plan.md)
§4.2–§4.4.** Sits beside [the browser login hop](browser-login-hop.md) and
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
| `id_token_hint` | I believe *this* end user is present; confirm or correct me |

Until W4, AXIAM accepted all five and acted on none. That is a conformant
answer to nothing: a relying party that sent `max_age=60` and received a code
minted from a week-old login had been told a freshness guarantee it did not
get, and could not tell.

`authn_request_params: honour` makes them mean what they say. It is per client,
and the default stays `ignore`.

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

### The authorization endpoint may now refuse

| Answer | When |
|---|---|
| `login_required` | `prompt=none` with no usable session, a `max_age` an authentication cannot meet, an `id_token_hint` naming somebody else |
| `account_selection_required` | as above, when `prompt=select_account` was asked |
| `unmet_authentication_requirements` | an **essential** `claims.id_token.acr` the end user cannot reach — typically a request for MFA from a user with no second factor enrolled |
| `invalid_request` | a value AXIAM cannot parse (`max_age=abc`), `prompt=none` combined with another value, an authentication-request parameter on the query string beside a `request_uri` |

All of these are redirected to the relying party's registered `redirect_uri`
with `state` and `iss`. On the `ignore` lane none of them can occur: a value
AXIAM cannot parse is dropped, as it always was.

---

## Things worth knowing before you turn it on

**`max_age=0` can never succeed.** The comparison is
`elapsed >= max_age` with no leeway in the relying party's favour, and an
authentication is never zero seconds old — so `max_age=0` always demands a
reauthentication, and the reauthentication fails the same comparison. The
relying party is sent to sign in and then answered `login_required`. If a
relying party in your deployment sends `max_age=0` meaning "authenticate them
now", it wants `prompt=login`.

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
