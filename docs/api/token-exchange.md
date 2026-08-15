# OAuth2 Token Exchange (RFC 8693)

A service in a mesh receives a request carrying a user's access token. To call
a second service on that user's behalf it should present a token that is
*narrower* than the one it holds — fewer scopes, a specific audience, and a
record of who acted for whom.

Token exchange is how it gets one. The alternatives are forwarding the user's
token verbatim (over-privileged, and the second service cannot tell the caller
from the user) or using the service's own credentials (right privileges, no
user context).

**The one rule everything below serves: an exchange may only ever narrow.**
There is no parameter, no configuration and no client grant that makes the
issued token permit something the subject token did not already permit. Each
section is that rule restated for one dimension.

The design rationale — including the alternatives rejected and the threat each
check answers — is in
[`claude_dev/token-exchange-design.md`](../../claude_dev/token-exchange-design.md).

## Request

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<jwt>                    # optional — presence selects delegation
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&scope=read:orders write:orders       # optional — defaults to the subject's scopes
&audience=https://orders.internal     # optional
&resource=https://orders.internal/v1  # optional
&client_id=oa_...&client_secret=...
```

| Parameter | Required | Notes |
|---|---|---|
| `grant_type` | yes | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | yes | The token being exchanged. v1 accepts **AXIAM-issued access tokens only** |
| `subject_token_type` | yes | `urn:ietf:params:oauth:token-type:access_token` |
| `actor_token` | no | Present ⇒ delegation. Absent ⇒ impersonation |
| `actor_token_type` | with `actor_token` | Same value as above |
| `scope` | no | Space-delimited. Defaults to the subject token's own scopes |
| `audience` | no | Must be registered to the exchanging client |
| `resource` | no | RFC 8707. Must agree with `audience` when both are given |
| `requested_token_type` | no | Defaults to `access_token`; naming anything else is refused rather than silently substituted |

**The exchanging client authenticates.** Unlike the device grant, this is a
confidential service, not a television — and the exchange is exactly the
operation that should be attributable. Client authentication uses the same
`client_id`/`client_secret` path as every other confidential grant, and an
unknown client is indistinguishable from a wrong secret.

The client must also be registered for the grant
(`grant_types` includes `urn:ietf:params:oauth:grant-type:token-exchange`);
otherwise `unauthorized_client`.

## Delegation vs impersonation

RFC 8693 distinguishes them by whether an `actor_token` is present. They carry
very different risk.

**Delegation** — *"service S is acting for user U, and the token says so."*
The issued token keeps `sub` = the user and gains an `act` claim naming the
actor:

```json
{ "sub": "user-uuid", "act": { "sub": "service-uuid" } }
```

A downstream service can see both parties and log both. Re-exchanging nests
the claim (`act.act`); the chain is **capped at depth 3** — beyond that nobody
reads it, and an uncapped chain is an unbounded field inside a signed token.
Exceeding the cap is `invalid_request`.

**Impersonation** — *"service S is now U, and nothing in the token records
that."* The issued token is indistinguishable from one the user obtained
directly. Useful for support tooling and admin "view as", and the single most
dangerous operation in this document, because the audit record is the only
remaining evidence it happened.

So:

- **Impersonation is off by default.** A client gets it only by holding the
  explicit grant
  `urn:axiam:params:oauth:grant-type:may-impersonate` in its registration.
- A client without that grant asking for impersonation receives
  `unauthorized_client` — never a silently-downgraded delegation.
- **Every impersonation is audited** with client, subject, granted scopes and
  audience, *before* the token is returned.

Because the impersonation gate runs before the scope, audience and lifetime
checks, a request that omits `actor_token` by accident is refused there and
never reaches them. If you mean delegation, send the actor token.

## Scope narrowing

```
granted = requested ∩ subject_scopes ∩ client_allowed_scopes
```

with `requested` defaulting to `subject_scopes` when `scope` is absent.

Two behaviours worth stating explicitly:

1. **A requested scope the subject token does not hold is refused, not
   dropped** (`invalid_scope`). Silent narrowing yields a token that works for
   some calls and not others, and the caller finds out at the second service
   instead of at the exchange.
2. **The client's own registered scopes bound the result even when the subject
   token is broader.** A compromised low-privilege service holding an admin's
   token cannot mint an admin token; the intersection with the *client's*
   registration is what prevents it.

An empty intersection fails the exchange. A token with no scopes is not a
narrowing, it is a mistake best diagnosed here.

## Audience

`audience` and `resource` both narrow the issued token's `aud`. An
unconstrained `aud` would let a service mint tokens addressed at systems it has
no relationship with. When both are supplied they must agree.

**The allow-list is the client's `redirect_uris`** (SEC-089). There is no
separate audience field in v1: a target is accepted if it appears in the
client's registered redirect URIs, or is one of AXIAM's own audiences below.

> **Operators:** this means **adding a redirect URI also authorises it as a
> token audience.** A redirect URI is normally reviewed as *"where may this
> client send a user's browser"* — a routine, low-privilege edit. Here it also
> answers *"for whom may this client mint tokens"*. The two lists also drift
> for ordinary reasons: prune the redirect URIs of a client that stopped using
> the browser flow and it silently loses exchange targets. Review redirect-URI
> changes on clients holding the exchange grant with that second question in
> mind. A dedicated `allowed_token_targets` registration field is the intended
> fix and is not in v1.

AXIAM's own audiences (`axiam:user`, `axiam:m2m`) are always addressable.
When neither parameter is supplied the issued token keeps the subject token's
audience.

## Lifetime

```
exp = now + min(subject_token_remaining, configured_max_exchange_lifetime)
```

**The exchanged token never outlives its subject token.** Without this cap an
exchange launders lifetime: hold a token for its last 30 seconds, exchange it,
hold the result for a further 15 minutes.

Revoking the subject's session does **not** retroactively revoke tokens
exchanged from it — they are separate tokens. That is why the cap matters and
why it is documented rather than left to be discovered.

### Revocation is not consulted at exchange time (SEC-091)

The subject token is validated for signature, issuer, audience and expiry. It
is **not** checked against session revocation, which is the standing posture
for access tokens across AXIAM (see
[Session-revocation posture](../security-profiles.md#session-revocation-posture-rest-vs-grpc-a4j10)).
A logged-out-but-unexpired access token can therefore still be exchanged.

Two properties bound what that costs, and both are enforced in code rather than
by convention:

- **Lifetime cannot be laundered** — the cap above means the exchanged token
  dies no later than its subject would have.
- **Privilege cannot be widened** — the scope intersection refuses anything the
  subject or the client does not already hold.

So the window is *at most the subject's remaining lifetime, at no more than the
subject's privilege* — the same window a revoked access token already has
everywhere else in the product. This is not a new exposure introduced by token
exchange; it is the existing one, unchanged. If you need sign-out to be
immediate, shorten `AXIAM__AUTH__ACCESS_TOKEN_LIFETIME_SECS` — that is the knob
that bounds this posture, here as elsewhere.

## Response

```json
{
  "access_token": "…",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read:orders"
}
```

`issued_token_type` is mandatory (RFC 8693 §2.2.1), not decoration: a client
that requested one type and received another must be able to tell.

**No refresh token is issued.** A refresh token would let the holder outlive
the subject token indefinitely — the lifetime cap above, defeated. Re-run the
exchange instead.

## Errors

All errors use the standard OAuth2 error response shape.

| Condition | Error |
|---|---|
| `subject_token` missing | `invalid_request` |
| `subject_token` unparseable, invalid signature, or expired | `invalid_grant` |
| `subject_token_type` unsupported | `invalid_request` |
| `requested_token_type` names anything but `access_token` | `invalid_request` |
| Subject token issued for another tenant | `invalid_grant` |
| Subject token not issued by this AXIAM (v1) | `invalid_request` |
| Requested scope not held by the subject | `invalid_scope` |
| Scope intersection empty | `invalid_scope` |
| `audience`/`resource` not registered to the client | `invalid_target` |
| `audience` and `resource` disagree | `invalid_request` |
| Impersonation without the `may_impersonate` grant | `unauthorized_client` |
| Client not registered for the exchange grant | `unauthorized_client` |
| Client authentication fails / unknown client | `invalid_client` |
| `act` chain already at depth 3 | `invalid_request` |

A cross-tenant subject token is `invalid_grant` rather than a distinct error on
purpose: a caller learning that a token is valid *somewhere else* is a
tenant-enumeration signal.

## Rate limiting

Its own bucket, `AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN` (default 120).
An exchange costs more than an ordinary token request — it verifies an inbound
JWT, consults the client registration and writes an audit record — and it is
the endpoint an attacker holding one stolen token would hammer looking for a
widening path.

## Audit

Every exchange, successful or not, records the exchanging client, the subject,
the actor (if any), whether it was delegation or impersonation, the requested
and granted scopes, the audience, and the outcome.

This is not optional telemetry. For impersonation it is the *only* record that
the acting party was not the subject, because the token deliberately does not
say so.

## Discovery

The grant is advertised in `grant_types_supported` at
`/.well-known/openid-configuration`.

## Not in v1

- **External subject tokens.** Accepting a token from another IdP means
  accepting whatever that IdP asserts about the subject; the trust
  configuration that makes it safe is its own feature (X4). v1 hard-wires the
  issuer check to "us".
- **`refresh_token`, `id_token` and SAML assertions** as requested or subject
  token types.

## See also

- [`device-flow.md`](device-flow.md) — the other new OAuth2 grant
- [`examples/b3-mesh-delegation-grpc`](../../examples/b3-mesh-delegation-grpc/README.md) — worked gRPC mesh-delegation example
- [`claude_dev/token-exchange-design.md`](../../claude_dev/token-exchange-design.md) — design rationale and threat model
- [`README.md`](README.md) — API documentation index
