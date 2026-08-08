# OAuth2 Token Exchange (RFC 8693) — design

> B3 of [`improvement-after-run5-benchmark.md`](improvement-after-run5-benchmark.md).
> Written before the code, because every mistake this feature can make is a
> privilege escalation that looks like a successful request.

## What it is for

A service in a mesh receives a request carrying a user's access token. To call
a second service on that user's behalf it should present a token that is
*narrower* than the one it holds — fewer scopes, a specific audience, and a
record of who acted for whom. Today it either forwards the user's token
verbatim (over-privileged, and now indistinguishable from the user) or uses
its own service credentials (correct privileges, no user context).

Token exchange is the third option, and it is the one Keycloak and Zitadel
both ship.

## The one rule everything else serves

**An exchange may only ever narrow.** There is no input, no configuration and
no client grant that causes the issued token to permit something the subject
token did not already permit. Every check below is a restatement of that rule
for a particular dimension, and every test named in §Tests exists to prove one
of them cannot be bypassed.

## v1 scope

| Dimension | v1 | Deferred |
|---|---|---|
| Subject token types | AXIAM-issued access tokens (`urn:ietf:params:oauth:token-type:access_token`) | External IdP tokens — that is X4, gated on this |
| Actor token types | AXIAM-issued access tokens | External |
| Requested token type | `access_token` only | `refresh_token`, `id_token`, SAML assertions |
| Delegation (`act` chain) | yes | — |
| Impersonation | opt-in per client, **off by default** | — |

Refusing external subject tokens in v1 is deliberate: accepting a token means
accepting whatever the issuing IdP asserts about the subject, and the trust
configuration that makes that safe is a feature of its own (X4). Shipping the
easy half first, with the issuer check hard-wired to "us", means the exchange
grant exists and is small enough to review.

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
&client_id=…&client_secret=…          # the exchanging client authenticates normally
```

Unlike the device grant, **the exchanging client authenticates**. It is a
confidential service, not a television, and the exchange is exactly the
operation that should be attributable.

## Delegation vs impersonation

These are different operations with different risk, and RFC 8693 distinguishes
them by whether an `actor_token` is present.

**Delegation** (`actor_token` present) — "service S is acting for user U, and
the token says so." The issued token keeps `sub` = the user and gains an `act`
claim naming the actor:

```json
{ "sub": "user-uuid", "act": { "sub": "service-uuid" } }
```

A downstream service can therefore see both parties and log both. Nested
chains nest the claim (`act.act`), and the chain is **capped at depth 3** —
beyond that nobody is reading it, and an uncapped chain is an unbounded field
in a signed token.

**Impersonation** (no `actor_token`) — "service S is now U, and nothing in the
token records that." The issued token is indistinguishable from one the user
obtained directly. This is genuinely useful (support tooling, admin
"view as"), and it is the single most dangerous thing in this document,
because the audit trail is the only remaining evidence that it happened.

Therefore:

- **Impersonation is off by default.** A client gets it only via an explicit
  `may_impersonate` grant on its registration.
- **Every impersonation is audited** with the client, the subject, the granted
  scopes and the audience — before the token is returned, not after.
- A client without the grant asking for impersonation gets
  `unauthorized_client`, not a silently-downgraded delegation.

## Scope narrowing

```
granted = requested ∩ subject_scopes ∩ client_allowed_scopes
```

with `requested` defaulting to `subject_scopes` when the parameter is absent.

Two consequences worth stating because they are where implementations go
wrong:

1. **A requested scope the subject token does not hold is not silently
   dropped — it is `invalid_scope`.** Silently narrowing produces a token that
   works for some calls and not others, and the caller finds out at the second
   service. Refusing is the answer a caller can act on.
2. **The client's own allowed scopes bound the result even when the subject
   token is broader.** A compromised low-privilege service holding an admin's
   token must not be able to mint an admin token; the intersection with the
   *client's* registration is what stops it.

If the intersection is empty the exchange fails. A token with no scopes is not
a useful narrowing, it is a mistake that will be diagnosed somewhere less
convenient.

## Audience

`audience` and `resource` (RFC 8707) both narrow the issued token's `aud`.
When either is supplied it must match one of the exchanging client's
registered audiences — an unconstrained `aud` would let a service mint tokens
addressed at systems it has no relationship with, which is the mesh
equivalent of an open redirect.

When neither is supplied the issued token keeps the subject token's audience.

## Lifetime

```
exp = now + min(subject_token_remaining, configured_max_exchange_lifetime)
```

The exchanged token **never outlives its subject token**. Without this, an
exchange is a privilege-lifetime laundering step: hold a token for 30 seconds,
exchange it, and hold the result for the full 15 minutes. The configured max
(default: the ordinary access-token lifetime) is a second, independent cap.

Revoking the subject's session does not retroactively revoke tokens exchanged
from it — they are separate tokens — which is why the lifetime cap matters and
why it is written down here rather than left to be discovered.

## Rejections

| Condition | Error |
|---|---|
| `subject_token` missing/unparseable/expired | `invalid_grant` |
| `subject_token_type` unsupported | `invalid_request` |
| Subject token issued by another tenant | `invalid_grant` |
| Subject token not issued by us (v1) | `invalid_request` (X4 relaxes this) |
| Requested scope not held by the subject | `invalid_scope` |
| Scope intersection empty | `invalid_scope` |
| `audience`/`resource` not registered to the client | `invalid_target` |
| Impersonation without `may_impersonate` | `unauthorized_client` |
| Client not registered for this grant | `unauthorized_client` |
| `act` chain already at depth 3 | `invalid_request` |

Cross-tenant is `invalid_grant` rather than a distinct error on purpose: a
caller learning that a token is valid *somewhere else* is a tenant-enumeration
signal.

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

`issued_token_type` is mandatory per RFC 8693 §2.2.1 and is not optional
decoration — a client that requested one type and received another must be
able to tell.

**No refresh token is issued.** A refresh token would let the holder outlive
the subject token indefinitely, which is precisely the lifetime cap above,
defeated. Re-run the exchange.

## Rate limiting

Its own bucket, keyed like the other machine endpoints
(`AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN`). Exchange is more expensive than
an ordinary token request (it verifies an inbound JWT, consults the client
registration, and audits) and it is the endpoint an attacker with one stolen
token would hammer looking for a widening path.

## Audit

Every exchange, successful or not, records: exchanging client, subject, actor
(if any), delegation-or-impersonation, requested scopes, granted scopes,
audience, and outcome. This is not optional telemetry — for impersonation it
is the *only* record that the acting party was not the subject, since the
token itself deliberately does not say so.

## Tests

Named here because each maps to one narrowing rule:

- **Property: `granted ⊆ requested ∩ subject ∩ client`** over generated scope
  sets. The single most valuable test in the feature.
- Impersonation refused by default; permitted only with the grant; audited in
  both directions.
- `act` chain: built correctly on delegation, nested on re-exchange, refused
  at depth 3.
- Lifetime: exchanged `exp` never exceeds the subject's, with the subject
  seconds from expiry.
- Audience: unregistered target is `invalid_target`; absent target inherits.
- Cross-tenant subject token is `invalid_grant`.
- Externally-issued subject token is refused in v1 (the test X4 will later
  invert, deliberately, so the change of posture is visible in the diff).
- No refresh token in any response.

## What this unblocks

- **X4** — the same grant, extended to subject tokens from trusted external
  IdPs. Its additional invariants (no transitive exchange, deny-by-default
  scope maps) build directly on the rules above.
- **D4 §15** — the SDK contract's `oauth2_token_exchange(subject, actor?,
  scopes?, audience?)` helper, and through D6 its eleven implementations.
