# Logout — RP-Initiated and Back-Channel

AXIAM implements [OIDC RP-Initiated Logout 1.0][rp] and
[OIDC Back-Channel Logout 1.0][bc]. Together they answer a question a plain
OIDC deployment cannot: *when a session ends, who else needs to know?*

[rp]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
[bc]: https://openid.net/specs/openid-connect-backchannel-1_0.html

A federation deployment is AXIAM plus N relying parties, and each half closes a
hole the other leaves:

- Without RP-initiated logout, a user who logs out of an RP stays logged in at
  AXIAM, so the next "Login with AXIAM" silently signs them back in. From the
  user's point of view they did not log out.
- Without back-channel logout, a user who logs out **of AXIAM** stays logged in
  at every RP indefinitely, because nothing tells them. This is the one that
  matters in an incident: revoking a compromised account otherwise leaves N
  live sessions behind.

## Sessions, not users

Both operate on a **session**. A user with a phone and a laptop who logs out on
the laptop expects the phone to stay signed in, and RP-Initiated Logout 1.0 §2
agrees.

That is why AXIAM's ID tokens carry `sid` and why every logout token names it.
An ID token identifying only the user would force both halves to be
all-or-nothing.

`sid` is stable across refresh: a token minted by the refresh grant carries the
same `sid` as the one issued at login, so an RP that stored it can still match
a logout token to its own session.

## RP-initiated logout

```
GET  /oauth2/end_session?tenant_id=<uuid>
POST /oauth2/end_session?tenant_id=<uuid>
```

| Parameter | Required | Meaning |
|---|---|---|
| `id_token_hint` | SHOULD | A previously-issued ID token. The only *authenticated* statement of which session and client this is about. |
| `post_logout_redirect_uri` | no | Where to send the browser afterwards. Honoured only on the client's allow-list. |
| `state` | no | Echoed verbatim on a redirect that actually happens. Never interpreted. |
| `client_id` | no | Fallback identification when no hint is supplied. |

Both methods are accepted because §2 permits either and browsers reach the
endpoint by navigation.

### The endpoint is unauthenticated, deliberately

A user whose session has already expired must still be able to complete a
logout; demanding a live session in order to end a session is a contradiction.
What identifies the target is the *signature* on `id_token_hint`, not an
ambient credential.

**Expiry on the hint is not checked.** A logging-out user's ID token has
routinely expired already — logout commonly happens long after a 15-minute
token was minted — so rejecting expired hints would make the hint useless
exactly when it is needed. The signature *is* checked, because that is what
makes the hint a statement rather than a suggestion.

**An unverifiable hint ends nothing.** There is no fallback to "end every
session for the subject named in an unverified parameter": that would be a
denial-of-service primitive handed to anyone who knows a user id. An
unverifiable or malformed hint is treated as absent, not as an error — the user
asked to log out.

**A hint and a `client_id` that disagree are refused** (`400 invalid_request`)
rather than resolved in favour of either. Preferring the signed one silently
ignores what the caller asked; preferring the parameter lets an unauthenticated
value override a signature.

### The redirect allow-list

`post_logout_redirect_uri` is honoured only on **exact string match** against
the identified client's `post_logout_redirect_uris` — no prefix matching, no
wildcards, no scheme or host normalisation. The endpoint is reachable without
authentication by design, so a loose match here is an open redirect on an
unauthenticated endpoint.

`post_logout_redirect_uris` is a **separate list** from `redirect_uris`. They
allow-list different things — one receives an authorization code, the other
receives a browser after a session ended — and deployments routinely want the
second to be a marketing page that must never be a code destination.

A non-matching URI **still logs the user out** and renders AXIAM's own page.
Refusing to log someone out because their RP sent a bad parameter is the wrong
failure. That page carries no RP-supplied content — not the `state`, not the
rejected URI — because echoing either would put an attacker-controlled string
in a page served from AXIAM's own origin.

### No confirmation prompt

§2 permits one ("the OP SHOULD ask the End-User whether to log out"), and a
prompt is the mitigation for logout CSRF. AXIAM takes the other side
deliberately: a forced logout is a nuisance, not a privilege escalation, and a
prompt shown on every logout is trained away within a week.

## Back-channel logout

When a session ends, every client that **participated** in it and registered a
`backchannel_logout_uri` receives:

```
POST <backchannel_logout_uri>
Content-Type: application/x-www-form-urlencoded

logout_token=<jwt>
```

### The logout token

EdDSA-signed, like every other AXIAM token:

```json
{
  "iss": "https://id.example.com",
  "aud": "<client_id>",
  "iat": 1785700000,
  "exp": 1785700120,
  "jti": "<uuid>",
  "sid": "<session id>",
  "sub": "<user id>",
  "events": { "http://schemas.openid.net/event/backchannel-logout": {} }
}
```

Four properties an RP must check, each because skipping it has a name:

1. **`events` contains exactly that key**, with an object value. It is what
   distinguishes a logout token from an ID token.
2. **No `nonce`.** Its presence is the documented signature of an ID token
   being replayed as a logout token. AXIAM's issuer takes no `nonce` parameter
   at all, so it cannot emit one by accident.
3. **`sid` is always present.** `sub` alone would tell an RP to end every
   session it holds for that user, which is not what happened.
4. **120-second lifetime.** A logout token is delivered immediately or not at
   all; a long-lived one is a replayable session-termination command.

`jti` is the dedup key. Delivery is at-least-once, so a valid token can arrive
twice — that is a retry, not an attack.

### Who gets told

Only clients that participated in the session. Participation is recorded when
an authorization code is issued, which is the moment a client actually joins.

This is tracked in a `session_client` table rather than a column on the
session, because one AXIAM session serves many RPs — that is what SSO is. A
single `client_id` on the session would record only whichever RP authorized
last, and the fan-out would silently skip every other RP the user was signed
into: precisely the failure the feature exists to prevent.

Broadcasting to every registered client instead would tell clients that were
never part of the session that one just ended, which leaks its existence.

### Delivery

Best-effort, and it **never blocks the logout**. The session is gone from AXIAM
the moment the request returns, whether or not any RP acknowledged; making
logout synchronous on N external HTTP calls would make it a hostage to the
least reliable RP.

Each client is POSTed its own token (`aud` names one client, so tokens are not
interchangeable), with up to 3 attempts, 500 ms then 2 s backoff, 5 s per
attempt. That covers a restart or a blip. It deliberately does not cover a
sustained outage: such an RP keeps its own session until it expires, and
queueing indefinitely would mean holding a session-termination command for an
unbounded time.

There is **no HMAC signature header**. The signed JWT is the authentication;
adding a second, cheaper check would invite an RP to verify that one instead.
This is the one deliberate difference from AXIAM's webhook deliveries, which
*are* HMAC-signed (see CONTRACT.md §13).

### The URI is resolved from AXIAM's network position

`backchannel_logout_uri` is the only URL in either half of logout that **AXIAM
dials itself**. `redirect_uris` and `post_logout_redirect_uris` are dialled by
the user's browser; this one is dialled by the server, from wherever the server
runs.

That distinction matters whenever those are different places — AXIAM in a
container or a pod, the RP outside it, or the reverse. `http://localhost:9000`
registered by an RP running next to your browser names *AXIAM's* loopback, not
the RP's, and every delivery to it is refused. The registration succeeds and the
logout succeeds; only the notification is lost.

There is **no error surfaced to anyone** when this happens, by design: delivery
is best-effort and never blocks the logout. The only evidence is in AXIAM's own
log, one line per attempt:

```
WARN back-channel logout delivery failed  client_id=… error=… attempt=1
WARN back-channel logout rejected by RP   client_id=… status=…  attempt=1
```

The first is "we could not reach it"; the second is "we reached it and it said
no". If an RP reports that it is never told about logouts, that pair of lines is
the first thing to look at — and if *neither* appears, the fan-out never
selected the client, which `back-channel logout fan-out computed` (DEBUG) breaks
down by stage.

## Discovery

```json
{
  "end_session_endpoint": "https://id.example.com/oauth2/end_session",
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

`backchannel_logout_session_supported: true` is the claim that AXIAM puts `sid`
in its logout tokens — which it does, unconditionally. An RP reads it to know
it can end one session rather than every session it holds for the subject.

## Client registration

| Field | Default | Meaning |
|---|---|---|
| `post_logout_redirect_uris` | `[]` | Allow-list for `post_logout_redirect_uri`. Empty means no redirect is permitted. |
| `backchannel_logout_uri` | unset | Where logout tokens go. Unset means the client does not participate and is skipped, not retried. |

Both are settable through `POST`/`PATCH /api/v1/oauth2-clients`. Pass an empty
string for `backchannel_logout_uri` on update to clear it — the edit an
operator makes when an RP is decommissioned.

## Rate limiting

`AXIAM__RATE_LIMIT__END_SESSION_PER_MIN` (default 30, per IP). The endpoint is
unauthenticated and it *terminates* state, so the thing being limited is
forced-logout abuse rather than throughput. The real defence against mass
logout is upstream of the limit: an unverifiable `id_token_hint` ends nothing.

## SDK support

`CONTRACT.md` §12.7 specifies the RP side: `logout_url` builds the redirect,
`verify_logout_token` validates what the OP pushed.

## Errors

| Condition | Answer |
|---|---|
| `id_token_hint` and `client_id` name different clients | `400 invalid_request` |
| `id_token_hint` unverifiable or malformed | treated as absent; session untouched; `200` |
| `post_logout_redirect_uri` not allow-listed | logged out; `200` with AXIAM's page; no redirect |
| allow-listed URI present and valid | `302` to it, with `state` appended when supplied |
| nothing identifiable supplied | `200` with AXIAM's page |
