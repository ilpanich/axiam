# External-IdP token exchange (RFC 8693, cross-domain) — design

> X4 of [`extra-B-track-features.md`](extra-B-track-features.md). Companion to
> [`token-exchange-design.md`](token-exchange-design.md), which this extends
> rather than replaces: **every B3 rule still applies**, and X4 only widens
> *which subject tokens are admissible* — never what an exchange may produce.
>
> Written before the code, for the same reason B3's was: on this path a
> plausible-but-wrong validation order is a cross-domain privilege escalation
> that looks like a successful request.

## What it is for

A partner, or a sibling business unit, runs its own IdP — Entra, Okta,
Keycloak. Their service calls ours. Today the only options are to provision
partner credentials in AXIAM (a second identity to keep in sync) or to let the
partner's token in unverified (no).

X4 is the third option and the enterprise pattern the plan names: **accept a
trusted partner's token at the mesh edge, emit a scoped AXIAM token.** The
partner's IdP stays the authority on *who authenticated*; AXIAM stays the
authority on *what they may do here*.

## The rule B3 states, restated for a foreign issuer

B3: *an exchange may only ever narrow.* With an external subject token there
is nothing to narrow *from* — the partner's scopes are not AXIAM's scopes and
carry no authority in this tenant. So the rule becomes:

> **An external subject token is evidence of authentication, never a grant of
> authorization.** What the resulting AXIAM token may do is decided entirely
> by AXIAM state: the admin's `scope_map`, the exchanging client's
> registration, and the RBAC engine's answer for the resolved user. The
> partner's token can only ever *reduce* that set, never add to it.

Everything below is that sentence applied to one dimension at a time.

## Trust configuration

Per **OIDC federation provider** (the rows `axiam-federation` already owns —
same `discovery_cache` / `jwks_cache` / SSRF paths, no new fetch surface), a
new `token_exchange` block:

```
token_exchange {
  enabled: bool                       // default FALSE — X4 is opt-in per provider
  accepted_audiences: [string]        // non-empty REQUIRED when enabled
  subject_mapping: "linked_only" | "jit_provision"   // default linked_only
  scope_map: { external value -> [AXIAM scopes] }    // deny-by-default
  max_token_age_secs: int             // default 300, 1..=3600
  max_lifetime_secs: option<int>      // per-provider ceiling on the issued token
}
```

Notes that are decisions, not defaults:

- **`enabled` defaults to false.** An operator who configured Okta for
  *login* did not thereby agree to accept Okta tokens as API credentials.
  Those are different trust statements and they get different switches.
- **`accepted_audiences` must be non-empty.** A token that was not addressed
  to us is a token we captured, not a token we were given. Accepting any
  audience turns every partner-issued token anywhere in their estate into an
  AXIAM credential — including ones minted for a third party who is not us.
  There is no "accept all" value; refusing to configure one is the point.
- **`scope_map` is deny-by-default.** An external value with no entry
  contributes nothing. There is no passthrough mode, and no identity mapping,
  because an identity mapping makes the *partner's* admin able to name AXIAM
  scopes.
- **`max_token_age_secs`** bounds `now - iat` independently of `exp`. A
  partner IdP that issues 24-hour access tokens should not thereby be handing
  out 24-hour-replayable AXIAM entry.

## Which path a subject token takes

The grant reads `iss` from the subject token **without verifying it**, purely
to route:

| unverified `iss` | path |
|---|---|
| equals AXIAM's own issuer | B3 internal path — signature checked against our key |
| anything else | X4 external path — issuer must match a trusted, exchange-enabled provider |

Routing on an unauthenticated claim is safe **because neither destination
trusts it**. Claiming to be us lands in a branch that verifies against our
signing key and fails. Claiming to be a partner lands in a branch that
verifies against that partner's JWKS and fails. The claim selects which key
the token is checked against; it never selects *whether* it is checked.

A provider whose discovery document advertises AXIAM's own issuer is refused
at resolution time, so the two branches can never overlap.

## Validation pipeline (order is normative)

1. **Client**: registered for the exchange grant (B3, unchanged).
2. **Types**: `subject_token_type` ∈ {`…:access_token`, `…:jwt`}.
   `…:refresh_token` and `…:id_token` are refused *by name* — a distinct
   error, because a caller passing one has made a specific mistake.
3. **`actor_token` is refused on the external path.** Delegation across a
   trust boundary needs a second trust decision X4 does not make (v1).
4. **Issuer → provider.** Enabled OIDC providers of this tenant whose
   `token_exchange.enabled` is true; each one's issuer resolved from its
   cached discovery document; **exact string match**, no normalisation, no
   trailing-slash forgiveness. No match ⇒ refuse.
5. **Signature.** `alg` allow-list from the provider's `allowed_algorithms`
   (`none` refused twice, raw and parsed — same code path OIDC login uses),
   JWKS from the cache, unknown-`kid` forced refetch (existing rollover
   behaviour).
6. **Claims.** `iss` bound to the discovery issuer; `exp`, `iat` required;
   `nbf` honoured when present; 60 s skew. Then `now - iat ≤
   max_token_age_secs`, and an `iat` in the future beyond skew is refused.
7. **Audience.** `aud` (string or array) ∩ `accepted_audiences` ≠ ∅.
8. **Shape.** ID tokens and refresh tokens are refused even when correctly
   signed: an ID token is an assertion *to a client about a login*, not a
   credential for an API, and OIDC deliberately gives it a longer-lived,
   more widely-distributed life. Detected by `nonce` / `at_hash` / `c_hash` /
   `s_hash` claims and by a `typ` header naming an ID or refresh token.
9. **No transitivity.** A token carrying `ext_exchange` is refused —
   here *and* on the internal path. See below.
10. **Subject.** `(provider, sub)` → federation link → AXIAM user. Unlinked
    ⇒ refuse under `linked_only`, or provision via the existing federation
    JIT path under `jit_provision`, audited as such. The resolved user must
    be **active**; a suspended user is not resurrected by a partner token.
11. **Scopes** (below).
12. **Audience of the issued token** — B3's rule, with one change: when the
    request names no `audience`/`resource`, the issued token gets
    `axiam:user`. It **never inherits the external token's `aud`**, which
    names the partner's resource server and would be meaningless — or worse,
    coincidentally meaningful — here.
13. **Lifetime** = min(subject token remaining, provider `max_lifetime_secs`,
    B3's configured exchange maximum).

## Scopes: three gates, in this order

```
candidate = ⋃ scope_map[v]  for each v the external token asserts
granted   = requested ∩ candidate ∩ client.scopes ∩ engine(user)
```

The external token's assertions are read from the `scope`/`scp` string claims
and the `roles`/`groups` array claims — the four shapes Entra, Okta and
Keycloak actually emit. Anything else is invisible to the map, which is the
conservative direction.

`engine(user)` is the RBAC engine consulted at mint time, using the mapping
X2 already pinned: **an AXIAM scope name is an action**. A scope survives
only if the user holds an `allow` grant for that action and **no `deny` grant
for it anywhere in their applicable roles** — deny-override (B1) at its
broadest reading, deliberately: this is a cross-domain path, and the cheap
conservative answer is the right one.

**Explicit requests refuse; the default drops.** If the caller names `scope`,
a value it cannot have is `invalid_scope` naming the offender (B3's rule — a
silently-narrowed token fails at the second service instead of at the
exchange). If the caller names nothing, the result is whatever survives all
four gates. This *is* a divergence from B3, and it is deliberate: B3's
default is the subject token's own scopes, which pass the subject gate by
construction, whereas `scope_map` output is admin-configured for a provider
and routinely exceeds what any individual user holds. Refusing there would
make the no-`scope` call fail for everyone but the most privileged user.

An empty result is `invalid_scope`, never a scopeless token.

## No transitive exchange

Every token minted from an external subject token carries

```json
{ "ext_exchange": { "iss": "https://partner.example/" } }
```

alongside B3's `act`, and **both exchange paths refuse a subject token that
carries it**. So:

- an AXIAM token minted from a partner token cannot be exchanged again, and
- a partner token that itself carries the claim (because the partner runs
  AXIAM, or copied the convention) cannot be exchanged here.

Without this, trust composes silently: A trusts B, B trusts C, therefore A
trusts C — which nobody configured and nobody can see in either config.

The claim is also the audit trail's anchor and is visible via introspection,
so a resource server can tell a cross-domain token from a locally-issued one
without asking us.

## Why `may_impersonate` is *not* required here

An external exchange emits no `act` claim, which in B3 terms looks like
impersonation. It is not. Impersonation is "this client asserts it may be the
user, on its own authority". An external exchange is "a trusted IdP asserts
the user authenticated, and the token was addressed to us". The evidence is
different in kind, so the gate is different: the per-provider `enabled` flag
plus `accepted_audiences`, not a per-client impersonation grant.

What is the same is the audit obligation — see below.

## Rejections

| Condition | Error | Description says |
|---|---|---|
| Issuer matches no exchange-enabled provider | `invalid_grant` | "…issuer is not configured for token exchange" |
| Signature / claim / age / audience failure | `invalid_grant` | generic |
| `subject_token_type` is a refresh or ID token type | `invalid_request` | names the type |
| Token is shaped like an ID/refresh token | `invalid_grant` | generic |
| `actor_token` present on the external path | `invalid_request` | v1 unsupported |
| Subject token carries `ext_exchange` | `invalid_request` | "already the product of an exchange" |
| Unlinked subject under `linked_only` | `invalid_grant` | generic |
| Resolved user not active | `invalid_grant` | generic |
| Requested scope outside the map / client / engine | `invalid_scope` | names the scope |
| Empty scope result | `invalid_scope` | generic |

Untrusted-issuer is the one failure given a *distinguishable* description,
because the exchanging client is an authenticated confidential client of this
tenant, not an anonymous prober — telling it that a partner it named is not
configured leaks nothing it could not get from the admin, and without it the
SDK cannot tell "fix your config" from "fix your token".

## Audit

Every external exchange, successful or refused, records: exchanging client,
external issuer, external subject, provider config id, resolved AXIAM user,
whether the user was JIT-provisioned, granted scopes, audience, and outcome.
For a JIT provision this is the only record that a partner's IdP created an
AXIAM user.

## Tests, mapped to rules

- Validation matrix: each invariant violated **in isolation** produces its
  own error — untrusted issuer, bad signature, expired, `iat` too old,
  audience disjoint, ID-token shape, refresh-token type, `actor_token`
  present, unlinked, inactive user.
- JWKS rollover mid-flight (unknown `kid` → forced refetch → success).
- JIT on and off against the same unlinked subject.
- Transitive rejection **both directions**: our `ext_exchange` token refused
  on the internal path; a foreign token carrying it refused on the external
  path.
- Scope-map property test: output ⊆ map range ∩ client scopes ∩ engine
  answer, over generated inputs.
- `aud` never inherited from the external token.
- Lifetime never exceeds the external token's remaining life.
- Cross-vendor proof: fixtures minted by a real Keycloak container in the
  e2e suite.
