# Native sign-in with a provider ID token

A mobile or desktop app that uses Google, Apple or Facebook's *native* SDK ends
up holding an **ID token** the provider signed for that app. There is no
browser redirect, so nothing can complete the authorization-code flow. The app
presents the ID token to AXIAM's token endpoint, AXIAM verifies it, resolves
the AXIAM user it belongs to and returns the client's ordinary sign-in token
set.

This is the **native sign-in grant**:

```
grant_type=urn:axiam:params:oauth:grant-type:provider-id-token
```

**The one rule everything below serves: an ID token is accepted as a sign-in
only when it was issued to us.** "Us" is a client ID the operator listed on the
provider for exactly this purpose. Not the provider's web client ID unless it
is listed, and never "any audience".

Design rationale and the decisions behind it:
[`claude_dev/social-login-gap-plan-2026-10-30.md`](../../claude_dev/social-login-gap-plan-2026-10-30.md)
(section 3.1, D-N1 and D-N10 to D-N15).

---

## What it is, and what it is not

| | Native sign-in (this page) | [Token exchange](token-exchange.md) / [X4](federated-token-exchange.md) |
|---|---|---|
| Who calls | An **app** signing a person in | A **service** that already holds a token |
| Presents | The provider's **ID token** | An access token (X4: a partner IdP's access token) |
| Result | A new **session** and the client's full token set, refresh token included | A narrower access token; **never** a refresh token, no session |
| ID tokens | Required (the token is refused without a `nonce`) | **Refused** (X4 rejects anything shaped like an ID token) |

This is not token exchange, and it does not loosen it. X4 still refuses ID
tokens, and the two paths share one list of ID-token markers so they cannot
drift apart. If you hold a partner's *access* token and want an AXIAM token,
that is X4. If a person is signing in on a device, this is the page.

It is also not the browser flow. A browser-based social login still goes
through `/oauth2/authorize` and the provider's redirect; a native sign-in and a
browser sign-in through the same provider land on **the same AXIAM user**,
because both resolve the subject the same way (see
[Who the user is](#who-the-user-is)).

---

## Before you start: it is off

Native sign-in is **disabled by default, per federation provider.**
Configuring a provider for *browser* login is not agreement to accept its ID
tokens *from apps*, and it is a separate switch from `token_exchange`. Upgrading
AXIAM never turns it on.

You need, in order:

1. An **OIDC** federation provider (protocol `oidc_connect`). SAML providers and
   OAuth2-protocol providers cannot do this, and AXIAM refuses the
   configuration: there is no ID token to verify. Google, Apple, Microsoft,
   generic OIDC and Facebook's **OIDC variant** (Facebook *Limited Login*, issuer
   `https://www.facebook.com`) qualify. Facebook's default OAuth2 variant and
   GitHub do not.
2. A `native_login` block on that provider with `enabled: true` and at least one
   `client_ids` entry.
3. An AXIAM OAuth2 client that holds the native sign-in grant.
4. Optionally, a `provider_slug` on the provider, so the app can name it without a UUID.

### Trust configuration

`PUT /api/v1/federation-configs/{id}` (admin, `federation:update`). The
`native_login` block is replaced wholesale, as `token_exchange` is; a request
that omits it leaves the stored block as it was.

```json
{
  "native_login": {
    "enabled": true,
    "client_ids": [
      "1234567890-abcdefg.apps.googleusercontent.com",
      "1234567890-hijklmn.apps.googleusercontent.com",
      "com.example.myapp"
    ],
    "max_token_age_secs": 300
  }
}
```

| Field | Meaning |
|---|---|
| `enabled` | Off unless you say otherwise. |
| `client_ids` | The audiences a presented ID token may carry. Non-empty when `enabled`; at most 64 entries, each at most 512 bytes, no blanks, no duplicates. Matching is exact. |
| `max_token_age_secs` | How old `iat` may be, independent of `exp`. Default 300, range 1 to 3600. |

What to list, by provider:

| Provider | What goes in `client_ids` |
|---|---|
| Google | The **iOS client ID** and the **Android client ID** the app's Google Sign-In SDK is configured with. These differ from the web client ID, and Google mints the ID token with *that* client as `aud`. |
| Apple | The app's **bundle ID** (the "App ID"). For the web flow `aud` is the Services ID instead; list it only if you want that token accepted here. |
| Facebook | Limited Login only, on a provider configured as the **OIDC variant**: the Facebook app ID. Classic Facebook Login produces an access token, not an ID token, and cannot use this grant. |
| Microsoft / generic OIDC | The application (client) IDs your native app registered. |

The provider's own `allowed_algorithms`, issuer and JWKS are the ones its
browser login uses; nothing new is fetched.

The block is never returned on the public provider listing the login page reads.

### Register the grant on the client

The client's `grant_types` must include the URN. A client that does not hold it
gets `unauthorized_client`.

```json
POST /api/v1/oauth2-clients
{
  "name": "Example mobile app",
  "redirect_uris": [],
  "grant_types": [
    "urn:axiam:params:oauth:grant-type:provider-id-token",
    "refresh_token"
  ],
  "scopes": ["openid", "profile", "email", "offline_access"],
  "token_endpoint_auth_method": "none"
}
```

- A **public** client (`token_endpoint_auth_method: none`, the normal case for
  a mobile app) sends `client_id` only. A confidential client authenticates by
  its registered method.
- A refresh token is issued **only** if the client also holds `refresh_token`.
- An ID token from AXIAM is issued **only** if `openid` is among the granted
  scopes.
- The admin console's OAuth2 client form lists the grant, and the provider page
  has a *Native sign-in* card that edits the `native_login` block.
- The grant is listed in `grant_types_supported` of the OIDC discovery document
  (`/.well-known/openid-configuration`), so an SDK can find it without being
  told out of band. Listing it says AXIAM supports the grant; whether a given
  client may use it is still that client's registration.

---

## Request

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:axiam:params:oauth:grant-type:provider-id-token
&client_id=<client id>
&provider=<provider UUID or slug>
&id_token=<the provider's ID token>
&nonce=<the nonce the app generated>
&scope=openid profile              # optional
&resource=https://api.example.com  # optional (RFC 8707)
```

The tenant-path form `POST /t/{tenant_id}/oauth2/token` is served too, and
shares the same rate-limit bucket.

| Parameter | Required | Notes |
|---|---|---|
| `grant_type` | yes | The URN above. |
| `provider` | yes | The federation provider's UUID, or its `provider_slug`. It must be a provider of this tenant, or one inherited from its organization. |
| `id_token` | yes | The compact JWT the provider's SDK returned. |
| `nonce` | yes | See [Nonce rules](#nonce-rules). |
| `scope` | no | Within the client's registered scopes. Omitted: the client's registered set. |
| `resource` | no | An RFC 8707 resource the client may address. |
| client authentication | per client | Public client: `client_id`. Confidential: its registered method. A client registered for DPoP or mTLS sender binding must present the proof, and gets a bound token. |

### Response

The ordinary token response of the client's registration:

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "…",
  "id_token": "eyJ...",
  "scope": "openid profile"
}
```

`refresh_token` appears only when the client holds `refresh_token`; `id_token`
only when `openid` was granted, and it carries the request's `nonce`. The
access token carries `client_id` and `sid` (see [Session](#the-session-it-creates)).

### Errors

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | `provider`, `id_token` or `nonce` is missing or empty. |
| 400 | `unauthorized_client` | The client is not registered for this grant. |
| 401 | `invalid_client` | Client authentication failed, or a required DPoP or mTLS proof is missing. Carries a `WWW-Authenticate` challenge. |
| 400 | `invalid_scope` | A scope outside the client's registration. |
| 400 | `invalid_target` | A `resource` the client may not address. |
| 400 | `invalid_grant` | **Every refusal of the provider token**, with the single description `the provider ID token is not acceptable`. |
| 400 | `consent_required` | A requested scope needs a consent ceremony, and nobody can be asked on this request. See [Consent](#consent). |
| 429 | `rate_limit_exceeded` | See [Rate limit](#rate-limit). Carries `Retry-After`. |
| 500 | `server_error` | An internal failure, for example the datastore. The body always carries `error_description`. |

**One answer for every refusal.** A wrong audience, a bad signature, an expired
or replayed token, a provider that is switched off, a provider that does not
exist, an account that may not sign in and a `login.post_auth` veto are all the
same `invalid_grant` with the same description. A caller cannot tell a wrong token from a wrong
configuration. The reason is in the server log and the audit record
(`reason_code`), where an operator can read it.

---

## Nonce rules

The app generates a random nonce, hands the provider the nonce (or a hash of
it) when it starts the sign-in, and sends **the same raw nonce** to AXIAM. The
ID token must carry a `nonce` claim that equals either:

- the request's `nonce`, **or**
- the **lower-case SHA-256 hex** of the request's `nonce`.

The second form is Apple's documented pattern: the app passes `sha256(raw)` to
Apple and keeps `raw`. Both comparisons are constant time. A token with no
`nonce` claim, or with one that matches neither, is refused. AXIAM generates no
nonce for you; the app must, and must make it unguessable and new for each
attempt.

---

## What is checked, and in what order

The order is the design. Each step runs before the next.

1. **Client.** It authenticates by its registered method, the profile's request
   rules run (`fapi2` clients included, see [FAPI 2.0](#fapi-20)), the
   registration must list the grant, and the sender binding it asks for is
   decided. The rate-limit bucket is charged. Nothing has been written.
2. **Request.** The three parameters are present, `scope` is within the
   registration and `resource` is addressable. Still nothing written, so a
   malformed request does not spend the token.
3. **Provider.** `provider` names an effective provider of this tenant that is
   enabled, speaks OIDC and has `native_login.enabled`. A provider of another
   tenant is "not found".
4. **Header.** `alg: none` is refused on the raw header, `alg` must be within the
   provider's `allowed_algorithms`, and `kid` is resolved through the provider's
   JWKS cache (including its rate-limited refetch after a key rollover). No new
   outbound fetch surface.
5. **Signature and claims.** `iss` is exactly the provider's discovered issuer.
   `aud` names a listed client ID; if `aud` has several members `azp` must be
   present and listed (OIDC Core 3.1.3.7), and the sign-in is attributed to the
   `azp`. `exp` is in the future (60 seconds of clock leeway). `iat` is no older
   than `max_token_age_secs` and not in the future beyond the leeway.
6. **Shape and nonce.** The token has ID-token shape: `nonce` present and
   matching, and not an access token (`typ: at+jwt`, or the claims only access
   tokens carry). This is X4's test run in reverse, from the same marker list.
7. **Replay.** The token's SHA-256 is recorded; a second presentation is refused
   (see [Single use](#single-use-and-replay)).
8. **User.** The subject is resolved (see [Who the user is](#who-the-user-is))
   and the account must be allowed to act (active, not locked). Then the
   `login.post_auth` reactor event fires for that user, as it does on every
   interactive sign-in ([`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §22): a
   veto, a `require_mfa` (this grant has no step-up to perform) or a
   `fail_closed` reactor failure refuses the sign-in as the same generic
   `invalid_grant`, before any session or token exists.
9. **Consent**, then **issue**: the session, the access token, the optional
   refresh token and the optional ID token.

---

## Single use and replay

An ID token is accepted **once**. Its SHA-256 is written to a dedicated table
(`federation_id_token_replay`) under a unique key of tenant, provider and token
hash, and kept until the token's `exp` plus 60 seconds. Google tokens carry no
`jti`, so the hash of the exact bytes is the identity.

- The record is written only after the signature, the claims and the nonce have
  been checked, so only a presenter who holds the token **and** its nonce can
  spend it. Someone who obtained a victim's token from a log or a proxy cannot
  burn it by presenting it without the nonce.
- It is written before anything acts on the presentation, and the insert is one
  atomic decision, so two concurrent presentations produce exactly one winner.
- A write conflict is retried; a record that cannot be written **refuses** the
  sign-in. Failing open would make replay protection optional.
- Expired rows are removed by the replay-record cleanup sweep.

For an inherited provider, the record is keyed on the tenant that owns the
provider, so a token cannot be replayed once per inheriting tenant.

---

## Who the user is

Subject resolution is **the browser login's, unchanged**: the provider's
attribute map turns the token's claims into an identity, then the identity is
linked to an existing AXIAM user or provisioned on first sight, by the same code
path. So:

- a native sign-in and a browser sign-in through the same provider land on the
  same AXIAM user;
- there is no extra `email_verified` refusal, and an unverified email is
  provisioned as unverified, never marked verified;
- Apple's rules apply as they do for the browser: name and email arrive only on
  the first sign-in;
- an account that may not act (for example disabled or locked) is refused as every
  other refusal is.

Federated sign-ins carry no local MFA obligation today; that is unchanged.

---

## The session it creates

A native sign-in creates an AXIAM **session**, as a federated browser sign-in
does (D-N12). It records the provider's authentication time and
`amr = ["fed"]`, with no browser cookie. The access token names it in `sid`, so:

- UserInfo and the session-validated APIs accept the token;
- logging out, a password reset or an administrator's revocation ends the
  session and so the tokens;
- the user's session list shows the device.

The refresh token, when issued, rotates and is bound to the client as every
other refresh token is.

---

## Consent

A scope that would need a consent ceremony cannot be granted by this grant,
because there is nobody to ask on this request. It is answered as `prompt=none`
is at `/oauth2/authorize`: `400 consent_required`.

Consent is decided after the user is known, so by then the provider token has
been verified and **spent**, and a first-time user may already have been
provisioned (D-N14). The app does not retry with the same token: it completes
consent (for example by an authorization-code sign-in for that scope), then
obtains a **fresh** ID token from the provider SDK and calls the grant again.
Everything that does not depend on the user (parameters, scope registration,
`resource`, the grant, the sender binding) is checked first and spends nothing.

---

## FAPI 2.0

A client under the `fapi2` profile may use the grant (D-N13), under the same
rules as the token-exchange, CIBA and device grants: the profile's token-request
enforcement runs first and the token is sender-bound as the client's
registration requires. The profile's refresh-token grace window is unchanged.

---

## Rate limit

The grant has its own bucket, `oauth2_provider_id_token:{client_ip}`, using the
**login** preset (`AXIAM__RATE_LIMIT__LOGIN_PER_MIN`, default 10 per minute; see
[`docs/deployment/rate-limit-sizing.md`](../deployment/rate-limit-sizing.md)). Both
the `/oauth2/token` and the `/t/{tenant_id}/oauth2/token` mounts charge the same
bucket. It is charged after the client is authenticated and before the token is
looked at, and an exceeded bucket answers `429 rate_limit_exceeded` with
`Retry-After`.

A guessing attacker holds nothing worth guessing here (a forged token fails the
signature), but verification costs a JWKS lookup and a database write, so the
limit bounds that cost per address.

---

## Audit

Every attempt that reached the grant writes one audit row, accepted or refused,
with `action = federation.native_login`. The metadata carries:

`client_id`, `outcome` (`accepted` or `refused`), `reason_code`, `provider`,
`provider_name`, `provider_kind`, `provider_inherited`, `user_id`,
`external_subject`, `newly_provisioned`, `granted_scopes`.

The `reason_code` is where a refusal is told apart: `provider_not_found`,
`provider_unavailable`, `algorithm_refused`, `unknown_key`, `keys_unavailable`,
`bad_signature`, `wrong_issuer`, `wrong_audience`, `azp_refused`, `expired`,
`too_old`, `issued_in_future`, `claim_rejected`, `wrong_token_shape`,
`nonce_missing`, `nonce_mismatch`, `replayed`, `replay_guard_unavailable`,
`subject_unmapped`, `account_refused`, `reactor_denied` (the `login.post_auth`
gate refused), `server_error`, and `accepted`.

**The record never carries the ID token or the nonce.** Until a provider
resolves, `provider` is what the request named (bounded in length).

---

## Example

Operator side, once:

```bash
# Enable native sign-in on the Google provider
curl -sS -X PUT "$AXIAM/api/v1/federation-configs/$PROVIDER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "native_login": {
          "enabled": true,
          "client_ids": ["1234567890-abcdefg.apps.googleusercontent.com"],
          "max_token_age_secs": 300
        }
      }'
```

App side, after the Google SDK returned `$GOOGLE_ID_TOKEN` for the nonce
`$NONCE`:

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT_ID" \
  --data-urlencode "grant_type=urn:axiam:params:oauth:grant-type:provider-id-token" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "provider=google" \
  --data-urlencode "id_token=$GOOGLE_ID_TOKEN" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "scope=openid profile"
```

A second identical call is refused:

```json
{
  "error": "invalid_grant",
  "error_description": "the provider ID token is not acceptable"
}
```

---

## See also

- [`token-exchange.md`](token-exchange.md) and
  [`federated-token-exchange.md`](federated-token-exchange.md): what this is
  not.
- [`resource-indicators.md`](resource-indicators.md): the `resource` parameter.
- [`../admin/fapi2-profile.md`](../admin/fapi2-profile.md): the profile rules.
- Threat model entries T-489 to T-492 in
  [`claude_dev/threat-model-stride.md`](../../claude_dev/threat-model-stride.md).
