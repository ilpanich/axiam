# Dynamic client registration (RFC 7591)

AXIAM can let a client **register itself** at `POST /oauth2/register`, without
an administrator creating it first. This is what MCP Inspector, Claude Code and
VS Code expect from an authorization server: they are handed a URL, they
discover the registration endpoint, and they create their own `client_id`.

It is **off by default, on every tenant**. A deployment that changes nothing
registers no client it did not create, and `POST /oauth2/register` answers
`403` on every tenant — the path exists and the feature does not, so nothing a
scanner can reach tells it which tenants have turned it on.

Turning it on is three decisions, and one of them is a security control rather
than a convenience. Read [The D3 warning](#the-d3-warning-audiences) before
enabling `anonymous`.

---

## The three modes

`dynamic_registration` takes one of three values.

| Mode | Who may register | Use it when |
| --- | --- | --- |
| `disabled` (default) | Nobody. `403` for every request. | Always, unless you have decided otherwise. |
| `initial_access_token` | A caller presenting a single-use token an administrator minted. | You want self-registration but not from strangers — a controlled rollout, a demonstration, a customer you are onboarding. |
| `anonymous` | Anybody who can reach the endpoint. | You are fronting MCP servers for end users whose desktop clients register themselves. |

RFC 7591 §1.2 calls the second and third the *protected* and *open* profiles.
The difference is whether an administrator has already decided that a
particular registration should happen.

**The reason to prefer `initial_access_token` that matters most:** its
`dcr_max_clients` allowance cannot be spent by somebody with no credential.
In `anonymous` mode the ceiling is a storage bound *and* an availability
budget, and one stranger can spend all of it — twenty registrations at five
requests a minute is about four minutes' work, after which a legitimate
client's registration is refused. Every attempt is rate-limited and audited,
so the flood is noisy and attributable, and AXIAM reclaims the slots within
the hour ([the sweeper](#the-sweeper)) rather than within the month. But a
mode where the caller has to hold a handle an administrator minted has no
such exposure at all, and if quota exhaustion is a risk you are carrying,
switching modes removes it rather than bounding it.

---

## Every policy field

All six live on the tenant's OIDC policy, resolved through the ordinary
organization-baseline-plus-tenant-override chain (see
[`docs/admin/organization-scope.md`](organization-scope.md)).

| Field | Default | What it does |
| --- | --- | --- |
| `dynamic_registration` | `disabled` | The mode, above. |
| `dcr_allowed_scopes` | `[]` | The scopes a self-registered client may ask for. A `scope` outside this list is `invalid_client_metadata`. An empty list means a self-registered client gets no scopes at all. |
| `dcr_allowed_redirect_hosts` | `[]` | Hosts a self-registered `redirect_uri` may point at, as globs. The loopback hosts are **always** allowed — see [Redirect hosts](#redirect-hosts). |
| `external_client_allowed_resources` | `[]` | **D3.** The audiences a self-registered client may address (RFC 8707 `resource`). See the warning below. |
| `dcr_max_clients` | `20` | How many self-registered clients this tenant may hold. The 21st registration is `403`. |
| `dcr_unused_client_ttl_days` | `30` | How long a self-registered client survives without being *used*. `0` disables the sweep for this tenant. A registration that was never authorized at all, in `anonymous` mode, is on a much shorter clock — see [the sweeper](#the-sweeper). |

Three of them are **ordered** against the organization baseline, so a tenant
may be stricter than its organization and never more permissive:
`dynamic_registration` (a tenant may move `anonymous` → `initial_access_token`
→ `disabled`, never the other way), `dcr_max_clients` (a tenant's value must be
no larger) and `dcr_unused_client_ttl_days` (a tenant's window must be no
longer — and `0`, "never sweep", counts as the longest value of all).

The three **lists** are not ordered and are not validated against the
baseline. They name per-tenant resources — *this* tenant's MCP servers, *this*
tenant's callback hosts — and there is no sense in which one such list is
stricter than another. A tenant override replaces the organization's list
whole; it does not add to it.

### The D3 warning: audiences

> **A self-registered client cannot choose its own audiences.** It inherits
> `external_client_allowed_resources` verbatim, and there is no request member
> that changes that.

This is the control that makes open registration safe to offer at all. Without
it, a stranger who registered a client could name any `resource` they liked and
obtain a token addressed at any service the deployment fronts.

An **empty** list is therefore not a safe default for `anonymous` mode. It does
not mean "this client can get nothing": it means the client can obtain only
today's `axiam:user` tokens, which are the tokens **AXIAM's own APIs accept**.
So AXIAM refuses to store a policy that combines `anonymous` with an empty
list:

```
400 Bad Request
Invalid org settings: dynamic_registration: anonymous registration cannot be
enabled while external_client_allowed_resources is empty (D3). A client
registered by an unrelated party inherits that list as its allowed_resources,
and an empty list leaves it able to obtain only the axiam:user tokens AXIAM's
own APIs accept. Name the MCP servers this tenant fronts first
```

Name the MCP servers first. `initial_access_token` mode is deliberately not
interlocked — there an administrator has already vetted the registration by
handing out the credential.

### Sensitive scopes are refused

`dcr_allowed_scopes` may not contain `address` or `phone`. Those two release
personal data under a per-client consent record
([`docs/admin/oidc-authn-parameters.md`](oidc-authn-parameters.md) and the
`sensitive_scopes_enabled` switch), and a self-registered client already
carries a forced consent record of its own — see
[Consent is forced](#consent-is-forced). A client that needs them is a client
an administrator should create through `POST /api/v1/oauth2-clients`.

---

## Enabling it

```bash
curl -X PUT "https://id.example.com/api/v1/organizations/$ORG_ID/settings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "…": "every existing field, unchanged",
        "dynamic_registration": "anonymous",
        "dcr_allowed_scopes": ["openid", "profile", "email"],
        "dcr_allowed_redirect_hosts": [],
        "external_client_allowed_resources": ["https://mcp.example.com/mcp"],
        "dcr_max_clients": 20,
        "dcr_unused_client_ttl_days": 30
      }'
```

A tenant can then tighten, but not loosen:

```bash
curl -X PUT "https://id.example.com/api/v1/tenants/$TENANT_ID/settings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"dynamic_registration": "initial_access_token", "dcr_max_clients": 5}'
```

Once a tenant is not `disabled`, its discovery document gains one member:

```bash
curl "https://id.example.com/.well-known/oauth-authorization-server?tenant_id=$TENANT_ID"
```

```jsonc
{
  "issuer": "https://id.example.com",
  "registration_endpoint": "https://id.example.com/oauth2/register?tenant_id=…",
  // …everything else, unchanged
}
```

A tenant on `disabled` — and any caller that names no tenant — receives a
document with no `registration_endpoint` at all. The member is omitted rather
than sent empty, because RFC 8414 defines no default for it and a present value
is one a conforming client will try.

---

## Registering a client

### Anonymous mode

```bash
curl -X POST "https://id.example.com/oauth2/register?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/json" \
  -d '{
        "client_name": "MCP Inspector",
        "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile"
      }'
```

```jsonc
201 Created
{
  "client_id": "…",
  "client_id_issued_at": 1789200000,
  "client_name": "MCP Inspector",
  "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile"
}
```

No `client_secret`, and no `client_secret_expires_at`: a `none` registration
mints no secret at all, so the members are **absent** rather than empty. A
confidential registration (`client_secret_basic`, `client_secret_post`,
`private_key_jwt` with a key) carries both, with
`"client_secret_expires_at": 0` — AXIAM does not expire client secrets.

### Initial-access-token mode

An administrator mints a token:

```bash
curl -X POST "https://id.example.com/api/v1/oauth2-clients/registration-tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "mcp-inspector-demo", "expires_in_hours": 24}'
```

```jsonc
201 Created
{
  "token": { "id": "…", "name": "mcp-inspector-demo", "expires_at": "…" },
  "initial_access_token": "axiam_dcr_…"
}
```

The handle is shown **once**. It is single-use — the registration that succeeds
spends it — and it expires after at most a week (168 hours; 24 by default). It
carries no identity: what the registration may ask for is the tenant's policy
at the moment it is spent, never the minting administrator's own authority.

The registering client presents it as an ordinary bearer:

```bash
curl -X POST "https://id.example.com/oauth2/register?tenant_id=$TENANT_ID" \
  -H "Authorization: Bearer axiam_dcr_…" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "MCP Inspector", "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"], "token_endpoint_auth_method": "none"}'
```

Outstanding and spent tokens are listed — metadata only, never a handle — at
`GET /api/v1/oauth2-clients/registration-tokens`.

The mint endpoint refuses while the tenant is not in `initial_access_token`
mode, rather than issuing a credential that would authorise nothing.

---

## What a registration may and may not say

| Member | Answer |
| --- | --- |
| `redirect_uris` | Required. `https`, or `http` on a loopback host. No fragment. Host must pass `dcr_allowed_redirect_hosts`. |
| `grant_types` | `authorization_code` and optionally `refresh_token`. Must include `authorization_code`. Defaults to `["authorization_code"]`. |
| `response_types` | `["code"]`, which is the RFC 7591 default and the only value AXIAM implements. |
| `token_endpoint_auth_method` | `none`, `client_secret_basic`, `client_secret_post`, `private_key_jwt`. Defaults to `client_secret_basic` (RFC 7591 §2's default, not AXIAM's). |
| `jwks` / `jwks_uri` | At most one, and required for `private_key_jwt`. A `jwks_uri` must be absolute `https`. |
| `scope` | Space-delimited, within `dcr_allowed_scopes`. Omitted means no scopes. |
| `client_name` | Optional. Shown on the consent screen, so give it one. |
| `software_statement` | **Refused** with `invalid_software_statement`. |
| everything else | Ignored, per RFC 7591 §2. `client_uri`, `logo_uri`, `contacts`, `tos_uri`, `policy_uri` and the localised `client_name#xx` forms all arrive from real clients and are dropped. |

Four things the request does not decide at all. They are not validated, they
are **overwritten**, and the response echoes what was stored:

- `allowed_resources` — the tenant's `external_client_allowed_resources` (D3);
- `profile` — always `standard`; a self-registered client can never carry the
  FAPI 2.0 profile ([`docs/admin/fapi2-profile.md`](fapi2-profile.md));
- `managed_by` — always `dcr`;
- the consent requirement — always on.

`software_statement` is refused rather than ignored because it is a *signed*
assertion about the client: a server that dropped it would be treating an
unverified request as though it had been verified, which is the one failure the
member exists to prevent.

### Redirect hosts

`dcr_allowed_redirect_hosts` takes two forms and nothing else:

| Pattern | Matches |
| --- | --- |
| `mcp.example.com` | exactly that host |
| `*.example.com` | `mcp.example.com`, `a.b.example.com` — **not** `example.com`, and **not** `evil-example.com` |
| `*` | any host |

A pattern with `*` anywhere else (`mcp*.example.com`, `*.*.com`) matches
nothing. Refusing to guess is deliberate: a host allow-list in front of a
redirect is a security check, and a general-purpose glob in front of a security
check is where a matching bug becomes an open redirect.

`127.0.0.1` and `localhost` are always allowed, whatever the list says —
including when it is empty, which is the default. Every desktop MCP client
receives its callback on the loopback interface under RFC 8252 §7.3, so a
tenant whose glob excluded them would have enabled registration for nobody.
Allowing them adds no reach: a loopback URI is reachable only from the machine
the user is sitting at. The [public-clients](public-clients.md) page has the
port rule.

> **`http://[::1]/…` cannot be registered today**, through this endpoint or
> through `POST /api/v1/oauth2-clients`. The redirect-URI matcher treats
> `[::1]` as a loopback host, but the structural validator both endpoints share
> compares the parsed host against `::1` while a URL parser returns an IPv6
> literal *with* its brackets — so the IPv6 arm is unreachable. This is a
> pre-existing gap rather than a dynamic-registration one, and it is left alone
> here because closing it would make a registration that is refused today
> succeed. Nothing in MCP depends on it: Claude Code registers `localhost` and
> VS Code registers `127.0.0.1`.

### Error codes

Per RFC 7591 §3.2.2, with the status AXIAM answers:

| Code | Status | When |
| --- | --- | --- |
| `invalid_request` | `403` | Registration is `disabled`; the initial access token was missing, malformed, expired, spent or another tenant's; the tenant is at `dcr_max_clients`. |
| `invalid_redirect_uri` | `400` | A `redirect_uris` entry is unusable or outside the host glob. |
| `invalid_client_metadata` | `400` | Anything else the server will not register. |
| `invalid_software_statement` | `400` | `software_statement` was present. |

The three `403`s are deliberately indistinguishable from each other in the
response: a caller holding nothing must not be able to learn which mode a
tenant is in, or whether a handle it guessed names a real token.

---

## Consent is forced

A client an administrator did not create is an unrelated party, so **the first
authorization per end user goes through the consent screen**, whatever scopes
the client asked for. Nobody at your deployment decided this application should
exist; the only person who can decide whether it may act as somebody is that
somebody.

The grant is recorded through the existing OIDC-scope consent records, so the
end user withdraws it from the account page exactly as they withdraw any other:

```bash
curl -X DELETE "https://id.example.com/api/v1/account/consents/oidc-scopes/$CLIENT_ID" \
  -H "Authorization: Bearer $USER_TOKEN"
```

The record covers the **scope set** the user was shown, so a client that later
asks for more re-prompts rather than inheriting. A client that has been
declined — the user reached the consent screen and came back without granting —
receives `access_denied`; a `prompt=none` request that would need the screen
receives `consent_required`.

---

## Abuse controls

Everything an unrelated party can reach without a credential is bounded:

| Control | Default | Configure with |
| --- | --- | --- |
| Per-IP rate limit | 5 requests/minute | `AXIAM__RATE_LIMIT__DCR_PER_MIN` |
| Clients per tenant | 20 | `dcr_max_clients` |
| Unused-client sweep | 30 days | `dcr_unused_client_ttl_days` |
| Never-authorized sweep (`anonymous` only) | 1 hour | not configurable — see [the sweeper](#the-sweeper) |
| Audit | every attempt | — |

**Both numbers govern client ID metadata documents too**, counted separately
and against the same value: a tenant running both mechanisms gets
`dcr_max_clients` self-registered clients *and* `dcr_max_clients` shadow rows,
so neither can exhaust the other's allowance, and each is swept on
`dcr_unused_client_ttl_days` under its own clock. They keep their `dcr_` names
because dynamic registration defined them, which is the same convention
`dcr_allowed_scopes` follows. See
[client ID metadata documents](client-id-metadata-documents.md#cleaning-up).

Five per minute is the smallest limit in AXIAM, and the reasoning is the
sharpest: this is the only endpoint that writes on behalf of a caller holding
no credential, and each accepted request allocates a row. The honest traffic it
has to accommodate is one person registering one MCP client once.

Every registration attempt, successful or not, is an audit event —
`oauth2.client_registered` or `oauth2.client_registration_refused`. The
metadata carries the `client_id` AXIAM minted and the refusal code, and
deliberately carries no client-supplied string: a refused registration's
`client_name` and `redirect_uris` are attacker-controlled, and an audit viewer
is a place where strings are read by people.

### The sweeper

A background sweep, registered with the job runner behind
[`GET /health/jobs`](../deployment/README.md), deletes `managed_by: dcr`
clients that have not been authorized within their tenant's
`dcr_unused_client_ttl_days`. A sibling sweep does the same for
`managed_by: cimd` rows on its own counter, and a third drops expired initial
access tokens.

```bash
curl https://id.example.com/health/jobs | jq '.jobs.dcr_unused_clients'
curl https://id.example.com/health/jobs | jq '.jobs.cimd_unused_clients'
```

What it will not touch:

- **`admin` clients.** An administrator's client is never swept, however long
  it sits unused. Somebody decided it should exist.
- **A tenant whose TTL is `0`.** That is the explicit opt-out for a deployment
  that prunes out of band.
- **A tenant whose settings cannot be read.** The fail-closed direction for a
  sweep that deletes is to delete nothing.

The clock it reads is `last_authorized_at` — stamped when the client is issued
an authorization code — falling back to `created_at` for a client that has
never been authorized.

### The second clock: never authorized, in `anonymous` mode

A registration that has **never** been authorized, in a tenant whose effective
mode is `anonymous`, is measured against **one hour** from `created_at`
instead of against `dcr_unused_client_ttl_days`.

The thirty-day default is sized for a client somebody uses monthly. A client
registered and never authorized is not that client: every MCP client this
exists to serve — Inspector, Claude Code, VS Code — authorizes within seconds
of registering, because registration is the first step of the same flow. One
TTL was serving two situations with nothing in common, and that is what made
`dcr_max_clients` an availability budget a stranger could hold for a month.
An hour-old registration nobody has authorized is either abandoned or hostile,
and AXIAM can tell it apart from a quiet-but-real client with no extra
bookkeeping, because the row carries no `last_authorized_at`.

Three things it deliberately does not do.

- **It does not apply in `initial_access_token` mode.** There the row exists
  because an administrator minted a handle and somebody redeemed it; there is
  no unauthenticated exposure to bound, and an operator who hands somebody a
  registration token on Friday should not find the registration gone on
  Monday. Nor in `disabled` mode, where such rows are leftovers from a mode
  the tenant has since turned off.
- **It does not read a client that completed a flow.** Authorize once and the
  client is on the thirty-day window like any other, whatever mode the tenant
  is in.
- **It is not switched off by `dcr_unused_client_ttl_days: 0`.** That value is
  a decision about how long a client somebody *uses* is kept, and a
  registration nobody has ever authorized is not that client. An operator who
  prunes out of band still gets the hour on the one sweep that deletes rows
  strangers created.

The hour is a constant rather than a tenant setting, which is the one place
this file describes a sweep window an operator cannot change. The reasoning,
and what changing it would cost, is on
`axiam_core::models::settings::DCR_UNAUTHORIZED_CLIENT_TTL_SECS`.

A swept client's users see their MCP client ask to register again, which it
does automatically. If that is disruptive, raise the TTL — and note that a
client reaching the second clock has not completed an authorization, so there
are no users to disrupt.

---

## MCP Inspector, translated from Keycloak's guide

Keycloak's MCP guide configures its realm for MCP Inspector with client
registration open, a redirect URI on `http://localhost:6274`, and an audience
mapper for the MCP server. The AXIAM settings that mean the same thing:

| Keycloak | AXIAM |
| --- | --- |
| Client registration policy: anonymous | `dynamic_registration: "anonymous"` |
| Allowed scopes on registered clients | `dcr_allowed_scopes: ["openid", "profile"]` |
| Redirect URI `http://localhost:6274/*` | nothing — loopback is always allowed; the client registers its own URI and AXIAM accepts any port on it |
| Audience mapper adding the MCP server to `aud` | `external_client_allowed_resources: ["https://mcp.example.com/mcp"]`, and the client sends `resource=` — [RFC 8707 proper](../api/resource-indicators.md), not a mapper |
| — | `dcr_max_clients`, `dcr_unused_client_ttl_days`: no Keycloak equivalent |

The last two rows are where AXIAM differs on purpose. Keycloak's audience
mapper is a workaround for not implementing RFC 8707; AXIAM mints the audience
from the `resource` parameter the client actually sends, so a token is
addressed at one MCP server rather than at whatever the mapper was configured
to add. And Keycloak's open registration has no ceiling and no sweep.

---

## See also

- [Public clients and loopback redirects](public-clients.md) — the `none` auth
  method and the RFC 8252 §7.3 port rule these clients rely on.
- [Resource indicators](../api/resource-indicators.md) — what
  `external_client_allowed_resources` feeds, and what `aud` a registered client
  can obtain.
- [The FAPI 2.0 profile](fapi2-profile.md) — why a self-registered client can
  never carry it.
