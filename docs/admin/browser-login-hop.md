# The browser login hop (`browser_sso`)

**Wave W3 of [`claude_dev/basic-op-gap-plan.md`](../../claude_dev/basic-op-gap-plan.md)
§4.0.** Sits beside [FAPI 2.0 profile and mTLS](fapi2-profile.md): both are
per-client switches on the same registration, and both default to what an AXIAM
client already was.

---

## What problem this solves

Before this, `/oauth2/authorize` could serve only relying parties that already
held an AXIAM access token — in practice, first-party applications on AXIAM's
own origin.

The reason is the `axiam_access` cookie. It is `SameSite=Strict`, which is
right for an API cookie and fatal for an authorization endpoint: a browser does
not send a Strict cookie on a **cross-site top-level navigation**, and that is
exactly what an OpenID Connect redirect from a relying party is. A user who had
signed in five seconds earlier arrived at `/oauth2/authorize` anonymous, and an
anonymous request was answered with a `401` JSON body. There was no sign-in
page to be sent to.

`browser_sso` adds one.

---

## Turning it on

One field on the client registration. It defaults to `false`, which is what
every client registered before this wave is.

```jsonc
POST /api/v1/oauth2-clients
{
  "name": "third-party-rp",
  "redirect_uris": ["https://rp.example/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"],

  "browser_sso": true          // <- the switch
}
```

With it on, an authorization request that carries no access token is answered
in one of three ways:

| The browser | The answer |
|---|---|
| carries a valid `axiam_op_session` cookie for this tenant | authorized as that user; the ordinary code redirect follows |
| carries none | `302` to `/login?return_to=…`, and back here afterwards |
| carries one that names no live session | `302` to `/login?return_to=…&reauth=1`; the dead cookie is cleared |

With it off — the default — the answer is the `401` it has always been, and the
`axiam_op_session` cookie is **not read at all**. That is the property to hold
on to when reasoning about a deployment: turning nothing on changes nothing.

### It is permitted on a `fapi2` client

Unlike every other lane switch, `browser_sso` is *not* refused on the FAPI 2.0
profile. It relaxes nothing: it decides how a request with **no principal** is
answered, and every gate — PAR, exact `redirect_uri`, PKCE, the profile bundle
— runs on the return leg exactly as it runs on a request that never hopped.

### It honours no authentication-request parameter

`prompt`, `max_age`, `acr_values`, `claims` and `id_token_hint` are still
ignored on the standard lane and still refused on `fapi2`, `browser_sso` or
not. The hop makes them *reachable* — there is finally a browser session for
them to be about — but reading them is a later wave. See
[`docs/compliance/oidc-conformance.md`](../compliance/oidc-conformance.md)
rows 23–25.

---

## The `tenant_id` parameter

Every session, client and authorization code in AXIAM is tenant-scoped, and
until this wave the tenant came exclusively from the caller's own access token.
An anonymous browser has none, so an anonymous authorization request must name
its tenant:

```
GET /oauth2/authorize?response_type=code&client_id=oa_…&redirect_uri=…
                     &scope=openid&state=…&tenant_id=<uuid>
```

It is the same parameter `/oauth2/end_session`, `/oauth2/token` and the
tenant-scoped discovery document already take. Two properties worth knowing:

- It is **ignored** whenever a principal was resolved from an access token. The
  token's tenant is the tenant it acts in, and a query parameter does not move
  that.
- Omitting it on an anonymous request gives today's `401`, `browser_sso` or
  not. That is why adding the parameter cannot have changed anything for a
  client registered today: none of them has ever sent it.

The published `authorization_endpoint` in the discovery document does not carry
it. A relying party on the hop appends it.

---

## The `axiam_op_session` cookie

A **second** cookie, set on every browser sign-in beside the three that already
exist. The first three are unchanged — that is the reason there is a second one.

```
Set-Cookie: axiam_op_session=<256 random bits>;
            HttpOnly; Secure; SameSite=Lax; Path=/oauth2/authorize;
            Max-Age=<session lifetime>
```

Only its SHA-256 is stored (`session.browser_token_hash`), the way a refresh
token is. Every attribute is doing a job:

- **`SameSite=Lax`** — sent on top-level GET navigations and nothing else. That
  is precisely the relying party's redirect, and precisely *not* an `<iframe>`,
  an `<img>` or a cross-site `fetch`.
- **`Path=/oauth2/authorize`** — a browser that sends this cookie cross-site can
  obtain exactly one thing: an authorization code, for a registered client, at
  a `redirect_uri` that matched exactly, bound to the relying party's own PKCE
  and `state`. It reaches no API endpoint.
- **`HttpOnly`** — not readable from script.
- **`Secure`** — **always**, and unlike the other three it does *not* follow
  `AXIAM__AUTH__COOKIE_SECURE` (D-18). It is the only `SameSite=Lax` cookie
  AXIAM sets, i.e. the only one a browser sends on a *cross-site* top-level
  navigation, and the endpoint it is scoped to must be TLS-protected anyway
  (RFC 6749 §3.1). Loopback development is unaffected — browsers store `Secure`
  cookies set from `http://localhost` and `http://127.0.0.1`. What it refuses
  is a browser login hop over plaintext to a non-loopback host: there,
  `browser_sso` clients will see the `login_required` described below, and the
  fix is TLS, not a flag.
- **`Max-Age`** — the session's lifetime (`refresh_token_lifetime_secs`), not
  the access token's: the value names the session row.

### The limitation this buys, stated plainly

**Cross-site hidden-iframe silent renew does not work, and fails closed.** The
pattern of loading `/oauth2/authorize?prompt=none` in an invisible frame to
refresh a session without a page navigation depends on the OP's session cookie
being sent inside a frame — which is the same thing that lets any site on the
internet frame the endpoint and observe whether a visitor has a session here.

AXIAM takes the other side. Relying parties renew with a **top-level**
`prompt=none` navigation, or with a refresh token.

Setting the cookie to `SameSite=None` would buy the iframe pattern back and
sell the probe with it. It is a deliberate decision (plan §9), not an
oversight, and it should not be changed without replacing the property it
protects.

### Same-origin SPA is a requirement, not a preference

The sign-in page is redirected to as a **path** (`/login?return_to=…`), and
`return_to` is a path on the API's origin. Both are deliberate: the cookie is
scoped to `/oauth2/authorize` on that origin, so a browser signing in somewhere
else would come back without it. This is the topology `docker/nginx.conf` and
the deployment guides describe, and the one the admin UI is built for
(`baseURL: "/"`).

A deployment serving the admin UI from a different host than the API cannot
complete the hop. `AXIAM__AUTH__SSO_SPA_ORIGINS`, which governs where a
federation SSO handoff code may be sent, does not change that — the cookie is
the binding constraint, not the redirect check.

---

## The PAR window bounds the hop

A pushed authorization request's `request_uri` lives **60 seconds** (RFC 9126
§2.2). A user who takes longer than that to type a password comes back to a
handle that no longer exists.

That is not worked around, because RFC 9126 §2.2 intends it. It is reported so
the relying party can act:

```json
{
  "error": "invalid_request_uri",
  "error_description": "the pushed authorization request expired while signing in
                        (a request_uri lives 60 seconds); push it again and
                        restart the authorization request"
}
```

The relying party pushes again and restarts. Two operational consequences:

- A `require_par` client whose users routinely take longer than a minute to
  sign in will see this. Either the relying party retries on
  `invalid_request_uri` (the correct fix), or that client does not use PAR.
- An **already signed-in** user never sees it: the cookie resolves on the first
  leg and there is no hop to outlive the window.

---

## The loop guard

`authorize → /login → authorize` would be a loop if the second `authorize`
could produce a third — a browser refusing cookies, a user signing into a
different tenant, a session expiring between the legs.

It cannot. Every login redirect the server builds carries `axiam_login_hop=1`
inside its `return_to`, and an authorization request that **arrives** carrying
that marker is never redirected again. If it still has no principal it is
answered:

```json
{
  "error": "login_required",
  "error_description": "the sign-in did not establish a session for this tenant
                        at this origin; sign in again from the relying party,
                        and check that the browser accepts the axiam_op_session
                        cookie"
}
```

So a chain is at most two authorization requests and one sign-in page.

**Seeing this in production means something is wrong**, and the message names
the two candidates: the browser is refusing the cookie (a third-party-cookie
blocker with an over-broad rule, a `Secure` cookie on a plaintext origin), or
the user signed into a tenant other than the `tenant_id` the request named.
It is logged at `warn` with the tenant and client id.

---

## What logging out does

Both `POST /api/v1/auth/logout` and RP-initiated `GET /oauth2/end_session`
clear `axiam_op_session` alongside the other three cookies, and the session row
it named is gone either way. A user who signs out through one relying party is
not silently recognised by the next.

Refresh-token rotation is the opposite case and is handled the other way: the
cookie in the browser is not reissued by a refresh, so the digest is **copied**
to the rotated session row. A signed-in user is never quietly signed out of the
authorization endpoint alone.

---

## Auditing what is on

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  https://iam.example.com/api/v1/oauth2-clients | \
  jq '[.items[] | select(.browser_sso) | {client_id, name, profile, require_par}]'
```

Any client not in that list is on the pre-W3 behaviour exactly.
