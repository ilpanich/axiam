# Device Authorization Grant (RFC 8628)

For clients that cannot show a browser or accept typed input: a television, a
set-top box, a CLI on a headless machine, an IoT sensor being commissioned.
The device shows a short code; the user types it on a phone or laptop; the
device polls until they approve.

AXIAM implements the non-interactive path of RFC 8628 in full.

## The flow

```
  device                          AXIAM                        user's phone
    |                               |                                |
    |-- POST /oauth2/device_authorization ->                         |
    |<- device_code, user_code, verification_uri --                  |
    |                               |                                |
  shows "go to id.example.com/device and enter WXYZ-1234"            |
    |                               |<--- GET /api/v1/device/verify -|
    |                               |---- client + scopes ---------->|
    |                               |<--- POST /api/v1/device/decide-|
    |-- POST /oauth2/token (device_code) ->                          |
    |<- authorization_pending ------|   (repeatedly, at `interval`)   |
    |-- POST /oauth2/token (device_code) ->                          |
    |<- access_token + refresh_token                                 |
```

## 1. Start — `POST /oauth2/device_authorization`

```http
POST /oauth2/device_authorization?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

client_id=oa_...&scope=openid
```

```json
{
  "device_code": "…",
  "user_code": "WXYZ-1234",
  "verification_uri": "https://id.example.com/device",
  "verification_uri_complete": "https://id.example.com/device?user_code=WXYZ-1234",
  "expires_in": 600,
  "interval": 5
}
```

**No client authentication.** RFC 8628 exists for public clients, and a
television cannot keep a secret. `client_id` is still checked against the
tenant's registered clients and its grant list — without that, any string
could mint pending grants and exhaust the user-code space, which is a denial
of service against every legitimate device at once.

`verification_uri_complete` is the pre-filled variant; render it as a QR code
and the user scans instead of typing eight characters.

## 2. Poll — `POST /oauth2/token`

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…
```

**Most of these requests return an error, and that is normal.** RFC 8628 §3.5:

| Server answer | HTTP | What the device should do |
|---|---|---|
| `authorization_pending` | 400 | Keep polling at `interval`. |
| `slow_down` | 400 | **Raise its interval by 5s**, then keep polling. |
| tokens | 200 | Stop. |
| `access_denied` | 400 | **Stop.** The user refused. |
| `expired_token` | 400 | Restart the flow with a new code. |
| `invalid_grant` | 400 | Stop. Unknown or already-redeemed code. |

Two of those deserve emphasis:

- **`access_denied` is distinct from `authorization_pending` on purpose.** A
  device that has been refused stops immediately rather than polling out the
  full ten minutes.
- **`slow_down` is self-correcting, not punitive.** The interval is raised and
  polling continues; a device that ignores the interval is progressively
  slowed rather than cut off. Interval enforcement happens *before* the
  grant's state is examined, so a device cannot outrun the signal by being in
  a lucky state.

The device code is the credential — a 256-bit CSPRNG value, stored only as a
SHA-256 hash. An approved grant mints tokens **exactly once**: redemption is a
single atomic statement, so two concurrent polls cannot both collect a token
set from one human approval.

## 3. Approve — the `/device` page

Two endpoints back the page, both under `/api/v1`:

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/device/verify?user_code=…` | What is this code asking for? Returns `client_id` and `scopes`. |
| `POST /api/v1/device/decide` | `{"user_code": "…", "approved": true\|false}` |

They are **authenticated and CSRF-protected**, which is why they live under
`/api/v1` rather than `/oauth2`:

- Approval records the approver as the subject the token is minted for, so the
  caller must be a known human.
- A user code is short and typed, so another origin can plausibly know one.
  Double-submit CSRF is what stops an attacker's page silently POSTing an
  approval on a victim's session — the device-code phishing shape RFC 8628
  §5.4 warns about, seen from the other side.

Codes are normalized before lookup: `WXYZ-1234`, `wxyz 1234` and `WXYZ1234`
are the same code.

**Unknown, expired and already-decided codes all answer identically**
(`found: false` / `ok: false`). Distinguishing them would turn the page into
an oracle for which codes are live, and the code space is small by
construction — 8 characters from a 20-letter alphabet, because a human has to
read them off a screen.

## Rate limits

Three buckets, none of them sized from benchmark capacity:

| Endpoint | Default | Env var |
|---|---|---|
| `/oauth2/device_authorization` | 12/min per IP | `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` |
| `/api/v1/device/verify`, `/api/v1/device/decide` | 10/min per IP | `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` |
| `/oauth2/token` (polling) | shares the token bucket | `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` |

`device_authorization` gets its own bucket because it is unauthenticated *and*
every accepted request allocates state; sharing the token bucket would let
ordinary traffic pay for — or mask — an attempt to exhaust the user-code
space. Both are keyed per-IP, never per-client: RFC 8628 clients are public,
so `client_id` is caller-supplied and worthless as a bucket key.

`device_verify_per_min` is the brute-force bound on user codes, and the server
**refuses to start** if it is raised past the point where guessing becomes
feasible. `RateLimitConfig::validate` asserts the OWASP condition
(`charset^len / (rate × lifetime) > 10⁶`) rather than trusting a comment — an
operator who turns a typed 8-character code into a guessable one finds out at
startup, not in an incident review.

## Discovery

Advertised unconditionally at `/.well-known/openid-configuration`:

```json
{
  "device_authorization_endpoint": "https://id.example.com/oauth2/device_authorization",
  "grant_types_supported": ["…", "urn:ietf:params:oauth:grant-type:device_code"]
}
```

A device that can read discovery is exactly the client that cannot be told the
URL out of band.

## Registering a device client

```http
POST /api/v1/oauth2-clients
{
  "name": "living-room-tv",
  "redirect_uris": [],
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
  "scopes": ["openid"]
}
```

No redirect URI is needed — the device never handles one.

## Not implemented

Interactive claims-gathering and the `verification_uri` *page itself* (the
HTML) are outside this API surface; the endpoints above are what a frontend
or a custom page calls. The frontend page ships with the C4 admin-UI work.
