# OIDC session completion — RP-initiated logout, back-channel logout, PAR — design

> B5 of [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md).
> Three features that share one theme: AXIAM currently knows how a session
> *starts* and has no vocabulary for how it *ends* anywhere but on AXIAM itself.

## Why these three together

A federation deployment has AXIAM plus N relying parties. Today:

- A user who logs out of an RP stays logged in at AXIAM, so the next "Login
  with AXIAM" silently re-authenticates them. From the user's point of view
  they did not log out.
- A user who logs out **of AXIAM** stays logged in at every RP, indefinitely,
  because nothing tells the RPs. This is the one that matters: an admin
  revoking a compromised account leaves N live sessions behind.

RP-initiated logout fixes the first, back-channel logout fixes the second, and
they are specified as a pair because either alone leaves a hole a deployment
will discover in an incident.

PAR is here because it is the same surface (client registration, the authorize
endpoint) and because X5 needs it — FAPI 2.0 requires PAR — so building it
alongside costs one migration instead of two.

## Client registration gains three fields

All three are additive and optional; every existing client keeps working
untouched.

| Field | Type | Purpose |
|---|---|---|
| `post_logout_redirect_uris` | `array<string>` | Allow-list for RP-initiated logout's `post_logout_redirect_uri` |
| `backchannel_logout_uri` | `option<string>` | Where logout tokens are POSTed |
| `require_par` | `bool`, default `false` | Refuse a direct authorize request from this client |

**`post_logout_redirect_uris` is a separate list from `redirect_uris`, not a
reuse of it.** They are allow-lists for different things: one receives an
authorization code, the other receives a browser after a session has ended.
Deployments routinely want the second to be a marketing page that must never
be a code destination. Conflating them would silently widen the code
allow-list the first time someone added a post-logout landing page.

## 1. RP-initiated logout (OIDC RP-Initiated Logout 1.0)

```
GET /oauth2/end_session?id_token_hint=<jwt>
                       &post_logout_redirect_uri=<uri>
                       &state=<opaque>
                       &client_id=<id>
                       &tenant_id=<uuid>
```

### The redirect is the whole security surface

An unvalidated `post_logout_redirect_uri` is an open redirect on an endpoint
that is, by design, reachable without authentication. So:

1. **A `post_logout_redirect_uri` is honoured only when it exactly matches an
   entry in the identified client's `post_logout_redirect_uris`.** Exact
   string match — no prefix matching, no wildcard, no scheme/host
   normalisation, the same discipline `redirect_uris` already uses.
2. **The client is identified from `id_token_hint` first, `client_id`
   second.** The hint is a signed statement of which client the session
   belongs to; `client_id` is an unauthenticated parameter. When both are
   present and disagree, the request is refused rather than resolved in favour
   of either.
3. **A non-matching or unresolvable redirect does not redirect.** The session
   is still ended — refusing to log the user out because their RP sent a bad
   parameter is the wrong failure — and the response is AXIAM's own
   logged-out page. It is not an error page: the user asked to log out and
   they are logged out.
4. **`state` is echoed only on a redirect that actually happens**, verbatim,
   and never interpreted.

### What "end the session" means

`id_token_hint` names a `sid`. The endpoint terminates *that* session, not
every session the user has. A user with a phone and a laptop who logs out on
the laptop expects the phone to stay signed in, and RP-Initiated Logout 1.0
§2 agrees.

**A missing or unverifiable `id_token_hint` cannot end a session.** Without it
there is nothing to identify but the browser's own AXIAM cookie, so the
endpoint ends the cookie session if there is one and does nothing otherwise.
It MUST NOT fall back to "end all sessions for the subject named in an
unverified parameter" — that is a denial-of-service primitive handed to
anyone who knows a user id.

**No confirmation prompt in v1.** The spec permits one (§2, "the OP SHOULD
ask the End-User whether to log out"), and a prompt is the mitigation for a
logout CSRF. We take the other side deliberately: forced logout is a nuisance,
not a privilege escalation, and a prompt that appears on every logout is
trained away in a week. This is written down so the choice is visible rather
than accidental.

## 2. Back-channel logout (OIDC Back-Channel Logout 1.0)

When a session ends — by RP-initiated logout, by `/api/v1/auth/logout`, by
admin revocation, by user deletion — every client that participated in that
session and has a `backchannel_logout_uri` receives:

```
POST <backchannel_logout_uri>
Content-Type: application/x-www-form-urlencoded

logout_token=<jwt>
```

### The logout token

Signed EdDSA like every other AXIAM token, with:

```json
{
  "iss": "<issuer>",
  "aud": "<client_id>",
  "iat": 1785700000,
  "exp": 1785700120,
  "jti": "<uuid>",
  "sid": "<session id>",
  "sub": "<user id>",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
}
```

Four constraints the spec states and implementations skip:

1. **`events` must contain exactly that URI as a key**, with an empty object
   value. It is what distinguishes a logout token from an ID token, and the
   receiving RP is required to check it.
2. **A logout token MUST NOT contain `nonce`.** Its presence is how an
   attacker replays an ID token as a logout token; the check is trivial and
   omitting it is the documented failure.
3. **At least one of `sid` and `sub` is required.** AXIAM always sends `sid`,
   because that is what makes the logout precise — `sub` alone would tell an
   RP to end every session it holds for that user, which is not what happened.
4. **Short-lived.** `exp = iat + 120s`. A logout token is delivered
   immediately or not at all; a long-lived one is a replayable
   session-termination command.

### Delivery reuses the webhook machinery

The webhook delivery path already has bounded retry, a DLQ, and per-delivery
audit. Back-channel logout has the same shape — an outbound POST to a
per-tenant registered URL that may be down — so it rides on that rather than
growing a second delivery system with its own half-implemented retry.

Two differences from a webhook, both deliberate:

- **No HMAC header.** The signed JWT *is* the authentication; adding
  `X-Axiam-Signature` would invite an RP to check the cheaper one.
- **Delivery is best-effort and never blocks the logout.** The user's session
  is gone from AXIAM the moment the request returns, whether or not any RP
  acknowledged. An RP that is down stays logged in until its own session
  expires — that is the spec's model, and making logout synchronous on N
  external HTTP calls would make the feature a hostage to the least reliable
  RP.

### Which clients get told

Only clients that actually participated in the session. AXIAM records the
`client_id` on each session created through the authorization-code flow;
back-channel logout iterates those, not every client in the tenant.
Broadcasting to every registered client would leak the existence of a session
to clients that were never part of it.

## 3. PAR (RFC 9126)

```
POST /oauth2/par?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

response_type=code&client_id=…&client_secret=…&redirect_uri=…
&scope=…&state=…&code_challenge=…&code_challenge_method=S256
```

→ `201 { "request_uri": "urn:ietf:params:oauth:request_uri:<64 hex>", "expires_in": 60 }`

The authorize endpoint then accepts `?request_uri=…&client_id=…` in place of
the parameters.

Rules:

1. **The client authenticates at `/oauth2/par`.** That is the point of the
   endpoint — the request parameters stop travelling through the browser, and
   the ones that arrive are attributable.
2. **`request_uri` is single-use.** Consumed atomically on the authorize
   request, the same `consume`-returns-bool pattern refresh rotation uses. A
   replayable `request_uri` is a replayable authorization request.
3. **Short expiry — 60 s, and no configuration knob in v1.** RFC 9126 §2.2
   suggests "in the order of seconds to a few minutes". The window only has to
   cover one browser redirect.
4. **`request_uri` and inline parameters do not mix.** An authorize request
   carrying both is refused rather than merged; merging is where parameter
   confusion lives.
5. **`require_par` on the client makes a direct authorize request an error**
   (`invalid_request`), which is the FAPI posture X5 will switch on.
6. **The stored request is opaque to the browser.** The `request_uri` is a
   256-bit CSPRNG value; the parameters are stored server-side and never
   re-serialised into the redirect.

## Discovery

```json
{
  "end_session_endpoint": "<issuer>/oauth2/end_session",
  "pushed_authorization_request_endpoint": "<issuer>/oauth2/par",
  "require_pushed_authorization_requests": false,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

`backchannel_logout_session_supported: true` is the claim that AXIAM puts
`sid` in its logout tokens — which it does, unconditionally, per §2 above.
`require_pushed_authorization_requests` is the *server-wide* default (false);
per-client enforcement is `require_par` on the registration and is not
discoverable, which matches RFC 9126 §5.

## Rejections

| Condition | Endpoint | Answer |
|---|---|---|
| `post_logout_redirect_uri` not in the client's allow-list | end_session | log out, render AXIAM's page, no redirect |
| `id_token_hint` and `client_id` name different clients | end_session | `400 invalid_request`, no logout |
| `id_token_hint` unverifiable | end_session | treated as absent |
| unknown/expired/consumed `request_uri` | authorize | `400 invalid_request` |
| `request_uri` plus inline parameters | authorize | `400 invalid_request` |
| direct authorize from a `require_par` client | authorize | `400 invalid_request` |
| client authentication fails | par | `401 invalid_client` |

## Rate limiting

- `/oauth2/end_session` — unauthenticated and it terminates state, the same
  abuse profile as `/oauth2/device_authorization`. Its own bucket.
- `/oauth2/par` — authenticated and it allocates state. Its own bucket, sized
  like the token endpoint's since one PAR precedes one authorize.

## Tests

- Logout-token vectors: `events` key exact; `nonce` present ⇒ invalid; neither
  `sid` nor `sub` ⇒ invalid; expired ⇒ invalid; wrong `aud` ⇒ invalid.
- Redirect allow-list: exact match honoured; prefix match refused;
  scheme-differing match refused; absent list ⇒ no redirect but still logged
  out; `state` echoed only on a real redirect.
- Session precision: logging out one session leaves the user's other sessions
  alive.
- Back-channel fan-out: only participating clients are notified; a failing RP
  does not fail the logout; a client without `backchannel_logout_uri` is
  skipped.
- PAR: expiry; single-use (second use refused); mixed inline parameters
  refused; `require_par` client refused on direct authorize; unauthenticated
  PAR refused.

## What this unblocks

- **X5 (FAPI 2.0)** — PAR is a hard requirement of the profile, and
  `require_par` is the per-client switch its conformance run needs.
- **D4 §12 logout** — the SDK contract's RP-side helpers: `logout_url()` and a
  `verify_logout_token()` the RP's back-channel endpoint calls. Through D6,
  eleven implementations.
