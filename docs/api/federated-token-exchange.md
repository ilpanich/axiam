# Federated token exchange — accepting a partner IdP's token

A partner, or a sibling business unit, runs their own identity provider —
Microsoft Entra ID, Okta, Keycloak. Their service calls yours, carrying *their*
token. You need an AXIAM token to do anything with it.

X4 is how you get one: present the partner's token at the ordinary
[token-exchange](token-exchange.md) endpoint and receive an AXIAM access token
scoped to what the resolved AXIAM user may actually do.

This extends [`token-exchange.md`](token-exchange.md); **every rule there still
applies.** What is new is which subject tokens are admissible, and the trust
configuration that decides.

> **The rule this page exists to make concrete.**
> An external subject token is **evidence of authentication, never a grant of
> authorization.** The partner's IdP stays the authority on *who
> authenticated*. AXIAM stays the authority on *what they may do here*. Nothing
> in a partner's token can widen what the resulting AXIAM token permits.

Design rationale, including the alternatives rejected and the threat each check
answers:
[`claude_dev/external-token-exchange-design.md`](../../claude_dev/external-token-exchange-design.md).

---

## Before you start: it is off

External token exchange is **disabled by default, per federation provider.**
Configuring Okta for *login* is not agreement to accept Okta tokens as API
credentials — those are different trust statements, so they get different
switches. Upgrading AXIAM never turns this on.

You need, in order:

1. An **OIDC** federation provider (SAML providers cannot do this — there is no
   issuer to match and no JWKS to verify against; AXIAM refuses the
   configuration outright).
2. A `token_exchange` block on that provider with `enabled: true` and at least
   one `accepted_audiences` entry.
3. A `scope_map` saying which of the partner's assertions may map onto which
   AXIAM scopes.
4. An AXIAM user each partner subject resolves to — either pre-linked, or
   JIT-provisioned if you opt in.
5. That user actually holding the permissions, in AXIAM's own RBAC.

Miss any one and the exchange is refused. That is the design.

---

## Trust configuration

`PATCH /api/v1/federation/configs/{id}` (admin, `federation:update`):

```json
{
  "token_exchange": {
    "enabled": true,
    "accepted_audiences": ["https://api.example.com"],
    "subject_mapping": "linked_only",
    "scope_map": {
      "partner.orders.read":  ["read:orders"],
      "Orders.ReadWrite.All": ["read:orders", "write:orders"]
    },
    "max_token_age_secs": 300,
    "max_lifetime_secs": 600
  }
}
```

The block is **replaced wholesale**, never merged field by field — a partial
merge of a trust configuration is how you end up keeping an
`accepted_audiences` entry you believed you had removed.

| Field | Default | What it does |
|---|---|---|
| `enabled` | `false` | Master switch for this provider. |
| `accepted_audiences` | — | Audiences an incoming token may name. **Required, non-empty, when enabled.** |
| `subject_mapping` | `linked_only` | `linked_only` or `jit_provision` — see below. |
| `scope_map` | `{}` | Partner assertion → AXIAM scopes. Deny-by-default. |
| `max_token_age_secs` | `300` | Bound on `now - iat`, independent of `exp`. 1…3600. |
| `max_lifetime_secs` | unset | Per-provider ceiling on the *issued* token's life. |

### Why there is no "accept any audience"

A token that was not addressed to you is a token you **captured**, not a token
you were **given**. Accepting any audience turns every token the partner mints
anywhere in their estate into an AXIAM credential — including ones minted for a
third party who is not you, and including ones a different relying party could
replay at your door.

So `accepted_audiences` must name at least one value, and matching is **exact
string equality**: no trailing-slash forgiveness, no case folding, no
normalisation. "Close enough" comparisons at a trust boundary are how a token
minted for `https://api.example.com.attacker.test` gets accepted as
`https://api.example.com`.

Put your own API's audience identifier here — the value the partner configures
on their side when they mint a token *for you*.

### The scope map is deny-by-default

An assertion with no entry in `scope_map` contributes **nothing**. There is no
passthrough mode and no identity mapping, because an identity mapping would let
the *partner's* administrator name AXIAM scopes.

AXIAM reads four claim shapes — the ones the target IdPs actually emit:

| Claim | Shape | Emitted by |
|---|---|---|
| `scope` | space-separated string | Okta, Keycloak, Auth0, RFC 9068 |
| `scp` | string **or** array | Entra ID (string), some Okta configs (array) |
| `roles` | array | Entra ID app roles |
| `groups` | array | Okta, Entra group claims |

Nested shapes (Keycloak's `realm_access.roles`) are **not** read in v1. If your
partner's authority lives there, add a protocol mapper on their side that
projects it into `scope` or `roles` — a claim AXIAM does not read cannot grant
anything, which is the safe direction, but it also means it silently grants
nothing.

### `linked_only` vs `jit_provision`

`linked_only` (the default): the partner subject must already resolve to an
AXIAM user — because they logged in through this provider's browser flow at
least once, or because an admin created the link. Unknown subject ⇒ refused.

`jit_provision`: AXIAM creates the user on first sight, through the same
provisioning path a browser SSO login uses, audited as such.

**A JIT-provisioned user holds no roles, so their first exchange still yields
nothing.** Provisioning an identity is not granting it anything — the user
appears in AXIAM so an admin can grant them something, and until that happens
every exchange for them fails with `invalid_scope`. This is worth knowing
before you conclude the feature is broken.

---

## Making a request

```http
POST /oauth2/token?tenant_id=<uuid>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the partner's JWT>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read:orders                  # optional
&audience=https://orders.internal   # optional
&client_id=oa_...&client_secret=...
```

`subject_token_type` may be `…:jwt` or `…:access_token`; both are accepted for
an external issuer. `…:refresh_token` and `…:id_token` are refused **by name**.

**`actor_token` is not supported.** Delegation across a trust boundary needs a
second trust decision — "may this actor act for a subject *that IdP* vouched
for" — which v1 does not make. Sending one is `invalid_request`.

The exchanging client authenticates normally and must be registered for the
token-exchange grant. It does **not** need `may_impersonate`: the evidence here
is a trusted IdP's signed assertion that the user authenticated, not the
client's own say-so that it may be them.

### What comes back

An ordinary AXIAM access token, plus one claim:

```json
{
  "sub": "<the AXIAM user's id>",
  "scope": "read:orders",
  "aud": "axiam:user",
  "ext_exchange": { "iss": "https://partner.example/" }
}
```

`ext_exchange` is the token's provenance. A resource server can read it to tell
a cross-domain token from a locally-issued one without asking AXIAM anything.

Note what is **not** there: the partner's `aud` is never inherited (it names
*their* resource server), there is no `act` claim (nobody acted *for* the user),
and there is no refresh token (re-run the exchange).

---

## How a scope is decided

```
candidate = ⋃ scope_map[v]   for each assertion v in the partner's token
granted   = requested ∩ candidate ∩ client registration ∩ RBAC engine
```

Four gates, and the partner's token is only the first. In particular the **RBAC
engine is consulted at mint time**: a scope survives only if the resolved user
holds an `allow` grant for that action and **no `deny` grant for it anywhere**
in their applicable roles.

That last clause is deliberately broader than a live access check. A deny scoped
to one resource withholds the *scope* entirely, even though the same deny would
only veto that one resource in a live check. A bearer scope cannot express
"except on resource X" — it travels in a token with no resource attached — so
the only two honest answers are "grant it everywhere" or "do not grant it", and
on a cross-domain path AXIAM takes the narrower one. The live check still
governs every actual request.

**Explicit requests refuse; the default drops.** If you name `scope`, a value
you cannot have is `invalid_scope` naming the offender. If you name nothing, you
get whatever survives all four gates. (This differs from a same-domain exchange,
where the default also refuses — there the default is the subject token's own
scopes, which pass by construction, whereas a `scope_map` is written for a
provider and routinely exceeds what any individual user holds.)

---

## No transitive trust

Every token minted from an external subject token carries `ext_exchange`, and
**both exchange paths refuse a subject token that carries it.** So:

- a token you got from an external exchange cannot be exchanged again, and
- a partner token that itself carries the claim cannot be exchanged here.

Without this, trust composes silently: A trusts B, B trusts C, therefore A
trusts C — which nobody configured, and which nobody can see by reading either
configuration.

---

## Refusals

| Condition | `error` | Description |
|---|---|---|
| Issuer matches no exchange-enabled provider | `invalid_grant` | **`the subject token's issuer is not configured for token exchange`** |
| Signature, claims, age, audience, token shape, unlinked subject, inactive user | `invalid_grant` | `subject token is not valid` |
| `subject_token_type` is a refresh or ID token type | `invalid_request` | names the type |
| `actor_token` supplied | `invalid_request` | v1 unsupported |
| Subject token already the product of an exchange | `invalid_request` | "exchanges do not compose" |
| Requested scope outside the map / client / engine | `invalid_scope` | names the scope |
| Nothing survives the four gates | `invalid_scope` | generic |
| `audience`/`resource` not registered to the client | `invalid_target` | names the target |

**Untrusted-issuer is the one failure given a distinguishable message.** The
exchanging client is an authenticated confidential client of your tenant, not an
anonymous prober, so telling it that an issuer is not configured leaks nothing
it could not learn by asking you — and without it, an integrator cannot tell
"fix the AXIAM trust configuration" from "fix your token". Everything else is
generic on purpose: which of a dozen checks refused a token is a map of the
validation order, drawn one request at a time.

The precise reason is always in the audit record.

---

## Audit

Every external exchange — successful or refused — records the exchanging
client, the external issuer, the external subject, the federation provider, the
resolved AXIAM user, whether that user was JIT-provisioned, the granted scopes,
the audience, and the outcome. All in one entry: a reader correlating two lines
by timestamp is a reader who can be made to correlate the wrong two.

For a JIT provision this is the **only** record that a partner's IdP created an
AXIAM user.

---

## Operational notes

- **JWKS and discovery reuse the login path's caches.** Key rotation is handled
  by the same unknown-`kid` forced refetch (rate-limited to one per minute per
  provider) that federated login uses. There are no new outbound fetch paths and
  no new SSRF surface.
- **Rate limiting**: the exchange's existing per-client bucket
  (`AXIAM__RATE_LIMIT__TOKEN_EXCHANGE_PER_MIN`) covers this path too.
- **Requires `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY`.** Without it AXIAM has no
  OIDC federation service, so there is nothing to read provider trust *with*,
  and every external issuer resolves to "not configured". The startup log says
  which posture is live.
- **`max_token_age_secs` is not `exp`.** A partner IdP issuing 24-hour access
  tokens should not thereby hand out a 24-hour replay window into AXIAM. Set it
  to the shortest value your integration tolerates; the default of 5 minutes
  suits a gateway that exchanges on receipt.

## See also

- [`token-exchange.md`](token-exchange.md) — the same-domain grant this extends
- [SDK contract §15.7](../../sdks/CONTRACT.md) — what SDKs must and must not do
- [`claude_dev/external-token-exchange-design.md`](../../claude_dev/external-token-exchange-design.md) — the rationale
